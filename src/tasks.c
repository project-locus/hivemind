#pragma once
#include "recv.c"
#ifndef _WIN32
	#include <signal.h>
#endif

// Acquire semantics
static inline void _hv_hazard_wait(void* target){
	struct _hv_thread* t = atomic_load_explicit(&_hv_meta.threads, memory_order_acquire);
	while(t){
		retry: {}
		void* h = atomic_load_explicit(&t->hazard, memory_order_relaxed);
		if(h == target || h == (void*)-1ull){
			thread_sleep(1); // Very strong yield
			goto retry;
		}
		t = atomic_load_explicit(&t->next, memory_order_acquire);
	}
}

#define GC_FREQ (3600*SECOND_US)

// Listener thread autoscaling
#define _HV_SCALE_SAMPLE (250*MILLISECOND_US) // How often each thread flushes its CPU time
#define _HV_SCALE_PERIOD SECOND_US // How often the load is evaluated
#define _HV_SCALE_WINDOW (30*SECOND_US) // Time constant of the load moving average
#define _HV_SCALE_COOLDOWN (5*SECOND_US) // Minimum time between spawning/retiring threads
#define _HV_SCALE_HIGH .75f // Spawn a thread above this per-thread load
#define _HV_SCALE_LOW .40f // Retire a thread if the load would stay below this without it

static void _hv_remove_unused(hivemind_server_t* s, uint64_t t){
	array_buffer_t candidates = {0};
	shared_lock_acquire(&s->state_lock);
	size_t buckets = (1<<s->buckets_exp & -2ull)>>1;
	struct _hv_remote** l = s->remote_buckets;
	if(buckets < 2) l = (struct _hv_remote**)&s->remote_buckets;
	for(size_t b = 0; b < buckets; b++){
		struct _hv_remote* state = l[b];
		while(state){
			if(state->bypass_type&2){
				struct _hv_remote_vq* state_vq = (struct _hv_remote_vq*)state;
				uint64_t last_used = atomic_load_explicit(&state_vq->vq_last_used, memory_order_relaxed);
				if(last_used-t > _HV_STATE_LIFETIME) array_buffer_push(&candidates, &state, sizeof(struct _hv_remote*));
			}else{
				uint64_t r = atomic_load_explicit(&state->recv_last_used, memory_order_relaxed);
				uint64_t s = atomic_load_explicit(&state->send_last_used, memory_order_relaxed);
				if(r && s && (r-t+1)>>1 > _HV_STATE_LIFETIME && s-t > _HV_STATE_LIFETIME){
					array_buffer_push(&candidates, &state, sizeof(struct _hv_remote*));
				}
			}
			assert(state != state->next);
			state = state->next;
		}
	}
	if(!array_buffer_size(&candidates)){
		shared_lock_release(&s->state_lock);
		return;
	}
	shared_lock_upgrade(&s->state_lock);
	array_iterator_t it = array_buffer_iterator(&candidates, 0, SIZE_MAX);
	struct _hv_remote* state, **prevp;
	while(array_iterator_next(&it, &state, sizeof(struct _hv_remote*))){
		if(state->bypass_type&2){
			struct _hv_remote_vq* state_vq = (struct _hv_remote_vq*)state;
			uint32_t ref = atomic_load_explicit(&state_vq->ref, memory_order_acquire);
			if(ref) continue;
			uint64_t last_used = atomic_load_explicit(&state_vq->vq_last_used, memory_order_relaxed);
			if(last_used-t <= _HV_STATE_LIFETIME) continue;
			vqueue_close(&state_vq->q);
			prevp = state_vq->prevp;
		}else{
			uint64_t r = _hv_time_lock_acq(&state->recv_last_used);
			uint64_t s = _hv_time_lock_acq(&state->send_last_used);
			t = _hv_internal_clock();
			if(state->send_unlocked_ref || state->recv_unlocked_ref || atomic_load_explicit(&state->undrained_next, memory_order_relaxed) || atomic_load_explicit(&state->unsent_ack_next, memory_order_relaxed) || (r-t+1)>>1 <= _HV_STATE_LIFETIME || s-t <= _HV_STATE_LIFETIME){
				_hv_time_lock_rel(&state->recv_last_used, r);
				_hv_time_lock_rel(&state->send_last_used, s);
				continue;
			}
			// FREE!!!
			_hv_remote_cleanup_recv(state, state->bypass_type);
			_hv_remote_cleanup_send(state);
			prevp = state->prevp;
		}
		*prevp = state->next;
		struct _hv_remote* next = state->next;
		if(next){
			if(next->bypass_type&2) ((struct _hv_remote_vq*)next)->prevp = prevp;
			else next->prevp = prevp;
		}
		_hv_free(state, state->bypass_type&2 ? sizeof(struct _hv_remote_vq) : _HV_REMOTE_SIZE);
	}
	array_buffer_destroy(&candidates);
	exclusive_lock_release(&s->state_lock);
}

static void* _hv_listen(void* _);

// Update the load average and spawn/retire a listener thread if needed. Expects the scale_at lock held
// Returns -1 if the calling thread should retire, otherwise 0
static int _hv_autoscale(uint64_t now, uint64_t dt){
	lock_acquire(&_hv_meta.threads_lock, 1);
	uint32_t n = _hv_meta.threads_cur, max = _hv_meta.threads_max;
	lock_release(&_hv_meta.threads_lock, 1);
	if(!n) return 0;
	float u = (float)atomic_exchange_explicit(&_hv_meta.busy_us, 0, memory_order_relaxed) / ((float)dt * n);
	if(u > 1.f) u = 1.f;
	float load = _hv_meta.load;
	load += (u - load) * ((float)dt / (float)(dt + _HV_SCALE_WINDOW));
	_hv_meta.load = load;
	if(now - _hv_meta.scale_changed < _HV_SCALE_COOLDOWN) return 0;
	uint32_t cap = max > 1 ? max-1 : 1;
	if(load > _HV_SCALE_HIGH && n < cap){
		lock_acquire(&_hv_meta.threads_lock, 1);
		_hv_meta.threads_cur++;
		lock_release(&_hv_meta.threads_lock, 1);
		thread_t t = thread_create(_hv_listen, 0, 0);
		if(!t){
			lock_acquire(&_hv_meta.threads_lock, 1);
			_hv_meta.threads_cur--;
			lock_release(&_hv_meta.threads_lock, 1);
			return 0;
		}
		thread_detach(t);
		// Same total work, spread over one more thread
		_hv_meta.load = load * n / (n+1);
		_hv_meta.scale_changed = now;
	}else if(n > 1 && load * n / (n-1) < _HV_SCALE_LOW){
		lock_acquire(&_hv_meta.threads_lock, 1);
		_hv_meta.threads_cur--;
		lock_release(&_hv_meta.threads_lock, 1);
		_hv_meta.load = load * n / (n-1);
		_hv_meta.scale_changed = now;
		return -1;
	}
	return 0;
}

static void* _hv_listen(void* _){
#ifdef _POSIX_THREADS
	sigset_t set; sigfillset(&set);
	pthread_sigmask(SIG_BLOCK, &set, 0);
#endif

	struct _hv_thread self = {.hazard = 0};
	self.prevp = &_hv_meta.threads;
	lock_acquire(&_hv_meta.threads_lock, 1);
	struct _hv_thread* next = atomic_load_explicit(&_hv_meta.threads, memory_order_relaxed);
	atomic_init(&self.next, next);
	if(next) next->prevp = &self.next;
	atomic_store_explicit(&_hv_meta.threads, &self, memory_order_release);
	lock_release(&_hv_meta.threads_lock, 1);

	uint8_t* packet = 0; unsigned packetsz = 0;
	uint64_t cpu0 = thread_now(), flush_at = _hv_internal_clock();
	for(;;){
		// Nothing is held here, so this is where we measure our CPU usage and may retire
		uint64_t now = _hv_internal_clock();
		if unlikely(now - flush_at >= _HV_SCALE_SAMPLE){
			uint64_t cpu = thread_now();
			atomic_fetch_add_explicit(&_hv_meta.busy_us, cpu - cpu0, memory_order_relaxed);
			cpu0 = cpu; flush_at = now;
			uint64_t scale_at = atomic_load_explicit(&_hv_meta.scale_at, memory_order_relaxed);
			if(scale_at != -1ull && now - scale_at >= _HV_SCALE_PERIOD && atomic_compare_exchange_strong_explicit(&_hv_meta.scale_at, &scale_at, -1ull, memory_order_acquire, memory_order_relaxed)){
				int r = _hv_autoscale(now, now - scale_at);
				atomic_store_explicit(&_hv_meta.scale_at, now, memory_order_release);
				if(r < 0) break;
			}
		}
		x_event_t ev = x_event_queue_wait(&_hv_meta.queue, -1ull);
		tsan_fence(memory_order_acquire);
		if(ev.type & X_EVENT_READABLE)
			atomic_store_explicit(&self.hazard, ev.data.ptr, memory_order_relaxed);
		x_event_queue_unlock(&_hv_meta.queue);
		if(ev.type == X_EVENT_WAKE){
			hivemind_server_t* s_s = atomic_load_explicit(&_hv_meta.servers, memory_order_relaxed);
			if unlikely(!s_s){
				x_event_queue_wake(&_hv_meta.queue, 0);
				lock_acquire(&_hv_meta.threads_lock, 1);
				_hv_meta.threads_cur--;
				lock_release(&_hv_meta.threads_lock, 1);
				break;
			}
			hivemind_server_t* help = atomic_load_explicit(&_hv_meta.read_help_requested, memory_order_relaxed);
			if(help){
				atomic_store_explicit(&self.hazard, help, memory_order_relaxed);
				// No barrier needed here, order is protected by the `acq_rel` xchg
				if(help == atomic_exchange_explicit(&_hv_meta.read_help_requested, 0, memory_order_acq_rel)){
					x_event_queue_wake(&_hv_meta.queue, 0); // someone else deal with any wakes
					ev.data.ptr = help;
					goto recv_packet;
				} // if changed, another wakeup will handle it
			}
			uint64_t wake = GC_FREQ;
			// early test
			if((uintptr_t)atomic_load_explicit(&_hv_meta.unsent_ack, memory_order_relaxed) > 1){
				struct _hv_remote* state = atomic_exchange_explicit(&_hv_meta.unsent_ack, 0, memory_order_acquire), *head = state;
				atomic(struct _hv_remote*) *prev = (atomic(struct _hv_remote*)*)&head;
				new_unsent_acks:
				while((uintptr_t)state > 1){
					_hv_time_lock_acq(&state->recv_last_used);
					uint64_t tim = _hv_internal_clock();
					struct _hv_remote* n = atomic_load_explicit(&state->unsent_ack_next, memory_order_relaxed);
					if(!state->ack_coal_i) goto rem;
					if((((tim<<8) - (state->ack_coal_tim0<<8)) >> 8) >= _HV_SEND_TICK){
						_hv_queue_ack(state, state->recv_seq_lo, state->recv_seq_hi, 0, true, state->bypass_type == 1);
						rem:
						atomic_store_explicit(prev, n, memory_order_relaxed);
						atomic_store_explicit(&state->unsent_ack_next, 0, memory_order_relaxed);
						if unlikely(!state->prevp){
							uint64_t l = _hv_time_lock_try_acq(&state->send_last_used);
							if(l){
								if(!atomic_load_explicit(&state->undrained_next, memory_order_relaxed)){ _hv_free(state, _HV_REMOTE_SIZE); goto next_a; }
								else _hv_time_lock_rel(&state->send_last_used, l);
							}
						}
					}else{ prev = &state->unsent_ack_next; }
					_hv_time_lock_rel(&state->recv_last_used, tim);
					next_a: state = n;
				}
				state = 0;
				if(!atomic_compare_exchange_strong_explicit(&_hv_meta.unsent_ack, &state, head, memory_order_relaxed, memory_order_acquire)){
					atomic_store_explicit(prev, state, memory_order_relaxed);
					goto new_unsent_acks;
				}
				if((uintptr_t)head > 1) wake = _HV_SEND_TICK;
			}
			// early test
			if((uintptr_t)atomic_load_explicit(&_hv_meta.undrained, memory_order_relaxed) > 1){
				struct _hv_remote* state = atomic_exchange_explicit(&_hv_meta.undrained, 0, memory_order_acquire), *head = state;
				atomic(struct _hv_remote*) *prev = (atomic(struct _hv_remote*)*)&head;
				new_undraineds:
				while((uintptr_t)state > 1){
					_hv_time_lock_acq(&state->send_last_used);
					uint64_t tim = _hv_internal_clock();
					struct _hv_remote* n = atomic_load_explicit(&state->undrained_next, memory_order_relaxed);
					if(!ring_buffer_size(&state->send_queue)){
						atomic_store_explicit(prev, n, memory_order_relaxed);
						atomic_store_explicit(&state->undrained_next, 0, memory_order_relaxed);
						if unlikely(!state->prevp){
							uint64_t l = _hv_time_lock_try_acq(&state->recv_last_used);
							if(l){
								if(!atomic_load_explicit(&state->unsent_ack_next, memory_order_relaxed)){ _hv_free(state, _HV_REMOTE_SIZE); goto next_u; }
								else _hv_time_lock_rel(&state->recv_last_used, l);
							}
						}
					}else{
						tim = _hv_drain_writes(state, tim, state->bypass_type&1);
						prev = &state->undrained_next;
					}
					_hv_time_lock_rel(&state->send_last_used, tim);
					next_u: state = n;
				}
				state = 0;
				if(!atomic_compare_exchange_strong_explicit(&_hv_meta.undrained, &state, head, memory_order_relaxed, memory_order_acquire)){
					atomic_store_explicit(prev, state, memory_order_relaxed);
					goto new_undraineds;
				}
				if((uintptr_t)head > 1) wake = _HV_SEND_TICK;
			}
			uint64_t last_gc = atomic_load_explicit(&_hv_meta.last_gc, memory_order_relaxed);
			uint64_t tim = _hv_internal_clock();
			if unlikely(s_s && last_gc != -1ull && tim - last_gc > GC_FREQ && atomic_compare_exchange_strong_explicit(&_hv_meta.last_gc, &last_gc, -1ull, memory_order_acquire, memory_order_relaxed)){
				for(;;){
					atomic_store_explicit(&self.hazard, s_s, memory_order_relaxed);
					thread_memory_barrier(mb_co_acquire);
					hivemind_server_t* s2 = atomic_load_explicit(&_hv_meta.servers, memory_order_acquire);
					if(s2 == s_s) break;
				}
				while(s_s){
					_hv_remove_unused(s_s, tim);
					atomic_store_explicit(&self.hazard, (void*)-1ull, memory_order_relaxed);
					thread_memory_barrier(mb_co_acquire);
					s_s = atomic_load_explicit(&s_s->next, memory_order_acquire);
					atomic_store_explicit(&self.hazard, s_s, memory_order_release);
					thread_memory_barrier(mb_co_acquire);
				}
				atomic_store_explicit(&_hv_meta.last_gc, _hv_internal_clock(), memory_order_release);
			}
			x_event_queue_wake(&_hv_meta.queue, wake);
			continue;
		}
		if(ev.type & X_EVENT_READABLE) recv_packet: {
			hivemind_server_t* s = (hivemind_server_t*)ev.data.ptr;
			atomic_thread_fence(memory_order_acquire);
			uint16_t mtu = le16toh(s->mtu_le);
			if(packetsz < mtu){
				_hv_free(packet, packetsz);
				packet = (uint8_t*)_hv_alloc(packetsz = mtu);
			}
			packet = _hv_drain_reads(s, packet, packetsz, ev.type == X_EVENT_READABLE);
			atomic_store_explicit(&self.hazard, 0, memory_order_release);
		}
		if(ev.type & X_EVENT_CLOSE){
			hivemind_server_t* s = (hivemind_server_t*)ev.data.ptr;
			hivemind_server_t* expected = s;
			atomic_compare_exchange_strong_explicit(&_hv_meta.read_help_requested, &expected, 0, memory_order_relaxed, memory_order_relaxed);
			lock_acquire(&_hv_meta.threads_lock, 1);
			hivemind_server_t* next = atomic_load_explicit(&s->next, memory_order_relaxed);
			atomic_store_explicit(s->prevp, next, memory_order_relaxed);
			if(next) next->prevp = s->prevp;
			else if(s->prevp == &_hv_meta.servers)
				x_event_queue_wake(&_hv_meta.queue, 0);
			lock_release(&_hv_meta.threads_lock, 1);

			_hv_hazard_wait(s);
			while(atomic_load_explicit(&s->vq_flag, memory_order_relaxed)){
				atomic_wait(&s->vq_flag, 1);
			}
			exclusive_lock_wait(&s->state_lock);
			// Server should be unreachable after this

			// Fearless freeing!
			_hv_finish(s);

			// Safe to teardown
			x_socket_free(s->handle);
			s->handle = X_SOCKET_INVALID;
			if(s->open_close_cb) s->open_close_cb(s->udata);
		}
	}
	_hv_free(packet, packetsz);
	lock_acquire(&_hv_meta.threads_lock, 1);
	next = atomic_load_explicit(&self.next, memory_order_relaxed);
	if(next) next->prevp = self.prevp;
	atomic_store_explicit(self.prevp, next, memory_order_release);
	lock_release(&_hv_meta.threads_lock, 1);
	return 0;
}

static void* _hv_vq_loop(hivemind_server_t* s){
	struct _hv_vq* b = s->vq_block;
	for(;;){
		vqueue_block_t msg = vqueue_wait(&b->q);
		if(msg.size >= 20){
			struct _hv_tls_packet_detach d = {.packet_on_heap = msg.size, .vq_block = b};
			_hv_fire_pipe(s, (uint32_t*)msg.data, msg.data+20, msg.size-20, &d);
			if(d.packet_on_heap == SIZE_MAX)
				continue;
		}
		vqueue_free(&b->q, msg);
		if(!msg.size) break;
	}
	if(atomic_fetch_sub_explicit(&b->ref, 1, memory_order_acquire) == 1){
		vqueue_close(&b->q);
		_hv_free(b, sizeof(struct _hv_vq));
	}
	atomic_store_explicit(&s->vq_flag, 0, memory_order_release);
	atomic_wake(&s->vq_flag, 1);
	return 0;
}