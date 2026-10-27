#include "plumbing.c"
#include <stdint.h>
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
	size_t buckets = (1<<s->buckets_exp&-2ull)>>1;
	struct _hv_remote** l = s->remote_buckets;
	if(buckets < 2) l = (struct _hv_remote**) &s->remote_buckets;
	for(size_t b = 0; b < buckets; b++){
		struct _hv_remote* state = l[b];
		while(state){
			if(state->bypass_type&2){
				struct _hv_remote_vq* state_vq = (struct _hv_remote_vq*) state;
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
			struct _hv_remote_vq* state_vq = (struct _hv_remote_vq*) state;
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
		free(state);
	}
	array_buffer_destroy(&candidates);
	exclusive_lock_release(&s->state_lock);
}

static void _hv_send_packet(struct _hv_remote* state, struct _hv_send_packet* packet, uint64_t now, bool bypass){
	//printf("send %zu i=%zu\n", _hv_lseqof(packet), i);
	unsigned len = packet->len4<<2;
	if(bypass && packet->first) len -= packet->kex ? 2 : 1;
	bool send_success = x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet->payload4, len);
	soft_assert(send_success);
	packet->time_lo = now;
}

// Undo the encryption of a sent (non bypass) packet with full sequence number [hi,lo], restoring the plaintext hivemind_send built.
// Header words (tag/seq) are left as they are, the caller rewrites them
static void _hv_unencrypt_packet(uint32_t chacha_in[16], uint64_t lo, uint32_t hi, struct _hv_send_packet* p){
	chacha_in[13] = (uint32_t)lo; chacha_in[14] = (uint32_t)(lo>>32); chacha_in[15] = hi;
	unsigned plen = p->len4, j = 5, tail = 0;
	if(p->first){
		uint32_t d[16]; memcpy(d, chacha_in, 64);
		d[12] = 0xffffffff;
		ChaCha20_block(d);
		p->payload4[plen-1] ^= d[15];
		if(p->kex){
			p->payload4[plen-2] ^= d[14];
			j = 9; tail = 2;
		}else if(le32toh(p->payload4[plen-1])>>16 == 0xffff){
			// Long encoding
			p->payload4[plen-2] ^= d[14];
			p->payload4[plen-3] ^= d[13];
			tail = 3;
		}else tail = 1;
		for(unsigned i = 8; i < 13; i++, j++) p->payload4[j] ^= d[i];
	}
	unsigned blocks = plen > j+tail ? (plen-j-tail)>>4 : 0;
	chacha_in[12] = 0;
	if(blocks) ChaCha20_block_xor(chacha_in, (uint8_t*)(p->payload4+j), blocks);
}

// Header size (in dwords, including the pipe id) of a message's first packet
#define _hv_first_header(p, bypass) ((p)->kex ? ((bypass) ? 9 : 14) : ((bypass) ? 8 : 10))

// Message length and trailer size (in dwords) of a plaintext first packet, as encoded by hivemind_send
static inline size_t _hv_first_len(struct _hv_send_packet* p, bool bypass, unsigned* tail){
	const uint32_t* t = p->payload4 + p->len4;
	if(p->kex){
		*tail = 2;
		return (size_t)le32toh(t[-2])<<16 | (le32toh(t[-1])&0xffff);
	}
	uint32_t x = le32toh(t[-1]);
	if(x>>16 == 0xffff){
		*tail = 3;
		return (size_t)le32toh(t[-2])<<16 | (x&0xffff);
	}
	*tail = 1;
	return bypass ? x&0xffff : x>>16;
}

// Rewrite the dependency of a (non kEX) first packet now sitting at sequence `self`
static inline void _hv_set_pipe_last(struct _hv_send_packet* p, uint32_t self, uint32_t pipe_last, bool bypass){
	uint32_t* t = p->payload4 + p->len4;
	uint32_t x = le32toh(t[-1]);
	if(x>>16 == 0xffff){
		t[-3] = htole32(pipe_last);
		return;
	}
	uint32_t diff = self - pipe_last;
	// Doesn't fit the short encoding and we can't grow the packet, drop the dependency instead
	if(diff > (bypass ? 0xfe : 0xffff)) diff = 0;
	t[-1] = htole32(bypass ? (x&0xffff) | diff<<16 : (x&0xFFFF0000) | diff);
}

// QoS of a pipe in a (detached) pipes_with_unsent table, 0 if it isn't there
static unsigned _hv_unsent_qos(const hash_table_t* b, array_buffer_t* pipes, const uint32_t id[5]){
	char* data = array_buffer_data(pipes);
	for(size_t pos = (size_t)hash_table_find(b, _hv_send_pipe_hash(id)); pos;){
		struct _hv_send_pipe* ps = (struct _hv_send_pipe*)(data + pos) - 1;
		if(!memcmp(ps->id, id, 20)) return (unsigned)(ps->queued >> (sizeof(size_t)*CHAR_BIT-2));
		pos = (size_t)ps->next;
	}
	return 0;
}

// Turn the first message of the queue (chain starting at f, plaintext) into a kEX message, the same way hivemind_send starts a new connection
// A non kEX first packet's data is moved into a new continuation packet so neither packet grows past the original's size (and therefore the MTU)
static struct _hv_send_packet* _hv_kexify(hivemind_server_t* s, struct _hv_remote* state, struct _hv_send_packet* f, const uint32_t pipeid[5], bool bypass){
	unsigned khdr = bypass ? 9 : 14;
	unsigned hdr = _hv_first_header(f, bypass), chdr = bypass ? 3 : 5, tail;
	size_t len = _hv_first_len(f, bypass, &tail);
	unsigned data = f->len4 > hdr+tail ? f->len4-hdr-tail : 0;
	size_t fb = f->has_err_fb ? 20+sizeof(uintptr_t) : 0;
	struct _hv_send_packet* k = (struct _hv_send_packet*)_hv_alloc(sizeof(struct _hv_send_packet) + 4 * (khdr+2) + (data ? 0 : fb));
	k->len4 = khdr+2; k->first = k->kex = 1; k->resent = 0; k->time_lo = 0;
	k->has_err_fb = !data && f->has_err_fb;
	memcpy(k->payload4+khdr-5, pipeid, 20);
	k->payload4[khdr+1] = htole32(len&0xffff);
	k->payload4[khdr] = htole32(len>>16);
	struct _hv_send_packet* tail_p = k;
	if(data){
		struct _hv_send_packet* c = (struct _hv_send_packet*)_hv_alloc(sizeof(struct _hv_send_packet) + 4 * (chdr+data) + fb);
		c->len4 = chdr+data; c->first = c->kex = 0; c->resent = 0; c->time_lo = 0;
		c->has_err_fb = f->has_err_fb;
		memcpy(c->payload4+chdr, f->payload4+hdr, data<<2);
		k->next = c; tail_p = c;
	}
	// Error feedback lives after the last packet's payload
	if(fb) memcpy(tail_p->payload4+tail_p->len4, f->payload4+f->len4, fb);
	tail_p->next = 0;
	_hv_free(f, _hv_packet_allocsz(f));
	f = k;
	// Fresh kEX, the old one is either rejected or too old
	if(bypass){
		uint64_t shash = _hv_mix64_addr(s->addr, le16toh(s->port_le)), dhash = _hv_mix64_addr(state->addr, state->port);
		f->payload4[0] = htole32(shash); f->payload4[1] = htole32(shash>>32);
		f->payload4[2] = htole32(dhash); f->payload4[3] = htole32(dhash>>32);
		_hv_nalloc_id(s, state->send_key+3);
		state->send_key[2] = 0;
		state->send_crcinit = _hv_alloc_id_short(s);
	}else _hv_ram_packed_kex(s, state, f->payload4+4);
	return f;
}

static inline void _hv_fire_dropped(hivemind_server_t* s, uint32_t* dropped, size_t count, unsigned reason){
	while(count -= 20+sizeof(uintptr_t)){
		struct _hv_tls_packet_detach d = {.packet_on_heap = SIZE_MAX};
		uintptr_t udata = dropped[5];
	#if UINTPTR_MAX > UINT32_MAX
		udata |= (uintptr_t)dropped[6] << 32;
	#endif
		_hv_fire_pipe(s, dropped, (uint8_t*)udata, (SIZE_MAX-63) | reason, &d);
		dropped += 6 + (UINTPTR_MAX > UINT32_MAX);
	}
}

// ACK ERR: the remote has no state for us. Requeue (as unsent, renumbered from a new kEX) every complete message whose pipe is in [pipe0, pipe1]
// Messages out of that range, or with any packet already acked, are dropped into `dropped`. The caller must pass it to _hv_fire_dropped once the send lock is released
// Expects the send lock held exclusively (no unlocked refs). Returns true if nothing was requeued and the next hivemind_send should start a new kEX
static bool _hv_filter_send_queue(hivemind_server_t* s, struct _hv_remote* state, uint32_t pipe0[5], uint32_t pipe1[5], bool first, bool bypass, array_buffer_t* dropped){
	size_t rsz = ring_buffer_size(&state->send_queue) / sizeof(struct _hv_send_packet*);
	uint64_t lo = state->send_seq_lo - rsz; uint32_t hi = state->send_seq_hi;
	if(lo > state->send_seq_lo) hi--;
	// An ack err for the kEX is only meaningful while the kEX is still at the front of the queue
	if(first && (lo || hi)) return false;

	uint32_t chacha_in[16] = CHACHA20_INIT;
	if(!bypass) memcpy(chacha_in+4, state->send_key, 32);

	// Pass 1: collect the packets of the messages to keep (plaintext, in order), drop everything else
	array_buffer_t kept = {0};
	size_t need = 0, mstart = 0;
	// 0 while the message being walked is kept, otherwise why it's being dropped. Leading continuations belong to a message whose start was already acked
	ring_iterator_t it = ring_buffer_iterator(&state->send_queue, 0, SIZE_MAX);
	uintptr_t v;
	ring_buffer_t old_send_queue = state->send_queue;
	state->send_queue = (ring_buffer_t){};
	state->send_order_start = 0;
	state->send_order_end = &state->send_order_start;
	array_buffer_t old_pipes = state->pipes_with_unsent;
	hash_table_t old_b = state->pipes_with_unsent_b;
	state->pipes_with_unsent = (array_buffer_t){};
	state->pipes_with_unsent_b = (hash_table_t){};
	state->qd_bytes4 = 0;
	
	array_buffer_t to_free = {};
	uint32_t new_seq = 0;
	if(first){
		ring_iterator_skip(&it, sizeof(v), true);
		assert(!lo && !hi);
		lo = 1;
		bool keep = false;
		struct _hv_send_packet_placeholder plch;
		struct _hv_send_packet* f, **pp = &f;
		uint32_t* pipeid;
		size_t dwords = 0;
		while(ring_iterator_next(&it, &v, sizeof(v), true)){
			assert(v > 1);
			struct _hv_send_packet* p = v&1 ? *(struct _hv_send_packet**)v : (struct _hv_send_packet*)v;
			assert((uint32_t)lo == _hv_lseqof(p, bypass));
			if(p->first){
				if(keep){
					_hv_add_to_send_pipe(state, pipeid, f, pp, dwords, &plch);
					state->qd_bytes4 += dwords;
					dwords = 0;
				}
				pipeid = p->payload4+_hv_first_header(p, bypass)-5;
				keep = _hv_pipeid_in_range(pipeid, pipe0, pipe1);
			}
			if(keep){
				if(v&1) _hv_unencrypt_packet(chacha_in, lo, hi, p);
				if(first){
					uint32_t pipe_last = _hv_find_pipe_last(state, pipeid, _hv_unsent_qos(&old_b, &old_pipes, pipeid), new_seq, &plch);
					_hv_set_pipe_last(p, new_seq, pipe_last, bypass);
					p->payload4[bypass ? 2 : 4] = new_seq;
					p->payload4[0] = 0;
					p->payload4[1] = 0;
					if(!new_seq){
						p = _hv_kexify(s, state, p, pipeid, bypass);
						if(p->next){
							*pp = p; pp = &p->next;
							dwords += p->len4;
							ring_buffer_push(&state->send_queue, &p, sizeof(struct _hv_send_packet*), true);
							p = p->next;
						}
					}
				}
				*pp = p; pp = &p->next;
				dwords += p->len4;
				p->resent = 0; p->time_lo = 0;
				ring_buffer_push(&state->send_queue, &p, sizeof(struct _hv_send_packet*), true);
				new_seq++;
			}else{
				if(p->has_err_fb)
					array_buffer_push(dropped, p->payload4 + p->len4, 20 + sizeof(uintptr_t));
				array_buffer_push(&to_free, &p, sizeof(struct _hv_send_packet*));
			}
			if(!++lo) hi++;
		}
		if(keep){
			_hv_add_to_send_pipe(state, pipeid, f, pp, dwords, &plch);
		}
	}else while(ring_iterator_next(&it, &v, sizeof(v), true)){
		if(v < 2) continue;
		struct _hv_send_packet* p = v&1 ? *(struct _hv_send_packet**)(v-1) : (struct _hv_send_packet*)v;
		if(p->has_err_fb)
			array_buffer_push(dropped, p->payload4 + p->len4, 20 + sizeof(uintptr_t));
		array_buffer_push(&to_free, &p, sizeof(struct _hv_send_packet*));
	}
	ring_buffer_destroy(&old_send_queue);
	array_buffer_destroy(&old_pipes);
	hash_table_set_rank(&old_b, 0);

	array_iterator_t it2 = array_buffer_iterator(&to_free, 0, SIZE_MAX);
	struct _hv_send_packet* to_free_p;
	while(array_iterator_next(&it2, &to_free_p, sizeof(struct _hv_send_packet*))) free(to_free_p);
	array_buffer_destroy(&to_free);

	state->send_seq_lo = new_seq; state->send_seq_hi = 0;
	state->rtt_gate_hi = 0;
	state->rtt_gate_lo = new_seq ? 8 : 0;

	// If nothing was requeued, force a kEX next time
	return !new_seq;
}

static uint64_t _hv_drain_writes(struct _hv_remote* state, uint64_t now, bool bypass){
	if unlikely((state->rtt_gate_lo&5)==4){
		// network partition
		uint32_t rtt_gate = (uint32_t)state->rtt_gate_lo|(uint32_t)state->rtt_gate_hi<<16;
		if(rtt_gate < 256){
			// Timer expired, send a probe packet
			uint8_t packet[40];
			remote_t to = {.addr = state->addr, .port = state->port};
			if(bypass) _hv_crcinitless_packet_finish(state->server, &to, packet, 0, 0);
			else _hv_keyless_packet_finish(state->server, &to, packet, 0, 0);
			unsigned gen = rtt_gate>>3&31;
			if(gen<24) gen++;
			rtt_gate = 4 | gen<<3 | ((1u<<(gen>>1))-1)<<8;
		}else rtt_gate -= 256;
		state->rtt_gate_lo = rtt_gate; state->rtt_gate_hi = rtt_gate>>16;
		return now;
	}
	float left = now-state->send_window;
	if(left > _HV_SEND_BURST){
		left = _HV_SEND_BURST;
		state->send_window = now-_HV_SEND_BURST;
	}
	if(left <= 0) return now;
	size_t sendable_now = /*floor*/ (size_t)(left / state->us_per_byte), sent = 0;
	if(!sendable_now) return now;

	// find unacked
	struct _hv_send_packet *packet = state->send_order_start, *packet0 = packet, *fpacket;
	uint64_t cutoff = (uint64_t)(state->min_latency + (state->avg_latency-state->min_latency)*4.);
	if(cutoff < _HV_SEND_TICK*2) cutoff = _HV_SEND_TICK*2;
	cutoff = (now - cutoff) << 21;
	struct _hv_send_packet** replace = 0;
	uint32_t base = _hv_send_base(state);
	if(packet){
		if unlikely(packet->resent /* short-circuit */ && now - state->last_ack > state->server->message_timeout){
			uint32_t pipe0[5] = {};
			array_buffer_t dropped = {};
			_hv_filter_send_queue(state->server, state, pipe0, pipe0, false, bypass, &dropped);
			state->send_unlocked_ref++;
			_hv_time_lock_rel(&state->send_last_used, 1);
			_hv_fire_dropped(state->server, array_buffer_data(&dropped), array_buffer_size(&dropped), HIVEMIND_CLOSED_TIMEOUT);
			array_buffer_destroy(&dropped);
			uint64_t l = _hv_time_lock_acq(&state->send_last_used);
			state->send_unlocked_ref--;
			return l;
		}
		for(;;){
			if((int64_t)((packet->time_lo<<21) - cutoff) >= 0){
				if(packet == packet0) packet0 = 0;
				state->send_order_start = packet;
				break;
			}
			packet->resent = 1;
			sent += (packet->len4<<2)+48;
			// Not in send order while being resent, acks for it are ignored until it's relinked
			uintptr_t tagged = (uintptr_t)replace | 1;
			ring_buffer_set(&state->send_queue, _hv_send_slot(state, packet, bypass, base), &tagged, sizeof(tagged), true);
			packet = packet->next;
			if(!packet || sent >= sendable_now){
				if(!packet) state->send_order_end = &state->send_order_start;
				state->send_order_start = packet;
				break;
			}
		}
	}
	if(packet){
		replace = &state->send_order_start;
		uintptr_t tagged = (uintptr_t)replace | 1;
		ring_buffer_set(&state->send_queue, _hv_send_slot(state, packet, bypass, base), &tagged, sizeof(tagged), true);
	}
	state->send_unlocked_ref++;
	fpacket = packet;
	if((packet = packet0)){
		state->send_window += (uint64_t)((double)sent*(double)state->us_per_byte);
		sendable_now = sent > sendable_now ? 0 : sendable_now-sent; sent = 0;
		_hv_time_lock_rel(&state->send_last_used, now);

		// This outside of critical section
		for(;;){
			// Resent lost packet
			struct _hv_send_packet* next = packet->next;
			_hv_send_packet(state, packet, now, bypass);
			if(next == fpacket){ packet->next = 0; break; }
			packet = next;
		}

		now = _hv_time_lock_acq(&state->send_last_used);
		packet = packet0;
		if(!state->prevp){ // server shutdown
			while(packet){
				struct _hv_send_packet* next = packet->next;
				_hv_free(packet, _hv_packet_allocsz(packet));
				packet = next;
			}
			goto end;
		}
		float left = now-state->send_window;
		if(left > _HV_SEND_BURST){
			left = _HV_SEND_BURST;
			state->send_window = now-_HV_SEND_BURST;
		}
		sendable_now = /*floor*/ left >= 0 ? (size_t)(left / state->us_per_byte) : 0;

		*state->send_order_end = packet0;
		replace = state->send_order_end;
		base = _hv_send_base(state); // Acks may have shifted the queue while we were unlocked
		while(packet){
			uintptr_t tagged = (uintptr_t)replace | 1;
			ring_buffer_set(&state->send_queue, _hv_send_slot(state, packet, bypass, base), &tagged, sizeof(tagged), true);
			replace = &packet->next;
			packet = *replace;
		}
		state->send_order_end = replace;
	}

	// drain unsent
	again: {}
	size_t sz = array_buffer_size(&state->pipes_with_unsent);
	if(!sz){
		// Don't measure throughput for a gap where we're not even trying
		state->rtt_gate_lo = 0;
		state->rtt_gate_hi = 0;
		goto end;
	}
	if(sendable_now){
		uint32_t chacha_in[16] = CHACHA20_INIT;
		if(!bypass) memcpy(chacha_in+4, state->send_key, 32);
		else chacha_in[4] = state->send_crcinit, chacha_in[5] = state->send_crcinit>>32;
		char* unsent_data = array_buffer_data(&state->pipes_with_unsent);
		size_t iter_i = state->unsent_iter_i;
		while(!iter_i) find: {
			size_t best = 0, best_i = SIZE_MAX;
			for(size_t i = 0; i < sz; i += sizeof(struct _hv_send_pipe)){
				struct _hv_send_pipe* ps = (struct _hv_send_pipe*)(unsent_data+i);
				// Skip pipes whose next message is still being built by hivemind_send
				if(!ps->start || ((uintptr_t)ps->start & 1)) continue;
				if(best_i == SIZE_MAX || ps->queued < best) best = ps->queued, best_i = i;
			}
			// Every pipe is blocked, whoever is building the message will drain it
			if(best_i == SIZE_MAX) goto end;
			iter_i = state->unsent_iter_i = best_i + sizeof(struct _hv_send_pipe);
		}
		struct _hv_send_pipe* pipe_state = (struct _hv_send_pipe*)(unsent_data+iter_i) - 1;
		struct _hv_send_packet *packet = pipe_state->start;
		if((uintptr_t)packet & 1)
			goto find;
		size_t i = _hv_send_slot(state, packet, bypass);
		if(!(pipe_state->start = packet->next)){
			// remove, moving the last pipe into its place
			struct _hv_send_pipe* last = (struct _hv_send_pipe*)(unsent_data + sz) - 1;
			unsigned cur_rank = hash_table_rank(&state->pipes_with_unsent_b);
			bool rehash = sz <= ((sizeof(struct _hv_send_pipe)>>1) << cur_rank);
			if(!rehash){
				_hv_unsent_unlink(state, pipe_state, iter_i);
				if(pipe_state != last) _hv_unsent_unlink(state, last, sz);
			}
			if(pipe_state != last){
				*pipe_state = *last;
				if(!rehash){
					uint64_t hash = _hv_send_pipe_hash(pipe_state->id);
					pipe_state->next = hash_table_find(&state->pipes_with_unsent_b, hash);
					hash_table_put(&state->pipes_with_unsent_b, hash, (void*)iter_i);
				}
			}
			array_buffer_pop_discard(&state->pipes_with_unsent, sizeof(struct _hv_send_pipe));
			sz -= sizeof(struct _hv_send_pipe);
			// The array may have been moved by the shrink (or the last pipe moved within it)
			unsent_data = array_buffer_data(&state->pipes_with_unsent);
			_hv_unsent_fix_placeholders(state);
			if(rehash){
				hash_table_set_rank(&state->pipes_with_unsent_b, --cur_rank);
				for(unsigned i = 0; i < sz; i += sizeof(struct _hv_send_pipe)){
					struct _hv_send_pipe* ps = (struct _hv_send_pipe*)(unsent_data+i);
					uint64_t hash2 = _hv_send_pipe_hash(ps->id);
					ps->next = hash_table_find(&state->pipes_with_unsent_b, hash2);
					hash_table_put(&state->pipes_with_unsent_b, hash2, (void*)(i + sizeof(struct _hv_send_pipe)));
				}
			}
			state->unsent_iter_i = 0;
		}else if((uintptr_t)pipe_state->start & 1){
			struct _hv_send_packet_placeholder* p2 = (struct _hv_send_packet_placeholder*)((uintptr_t)pipe_state->start-1);
			p2->prevp = &pipe_state->start;
		}
		// Out of the pipe and not in send order yet. Clear its slot so an ack arriving while we're unlocked doesn't touch it
		packet->next = 0;
		uintptr_t cleared = 0;
		ring_buffer_set(&state->send_queue, i, &cleared, sizeof(cleared), true);
		size_t sending = (packet->len4<<2)+48;
		sendable_now = sending < sendable_now ? sendable_now-sending : 0;
		state->send_window += (uint64_t)(sending*state->us_per_byte);
		_hv_time_lock_rel(&state->send_last_used, now);

		// This outside of critical section
		if(bypass){
			uint64_t crcinit = /*state->send_crcinit*/ chacha_in[4] | (uint64_t)chacha_in[5]<<32, crc;
			if(packet->kex){
				crc = crc64(crcinit, (uint8_t*)packet->payload4, (packet->len4<<2)+2);
				packet->payload4[2] = htole32(crcinit); packet->payload4[3] = htole32(crcinit>>32);
			}else{
				crc = crc64(crcinit, (uint8_t*)packet->payload4, (packet->len4<<2)+(packet->first?3:0));
			}
			packet->payload4[0] = htole32(crc); packet->payload4[1] = htole32(crc>>32);
		}else _hv_encrypt_packet(chacha_in, packet);
		_hv_send_packet(state, packet, now, bypass);

		now = _hv_time_lock_acq(&state->send_last_used);
		if(!state->prevp){ // server shutdown
			_hv_free(packet, _hv_packet_allocsz(packet));
			goto end;
		}
		// The slot is still there: it holds 0, and acks only shift leading 1s off the front
		uintptr_t tagged = (uintptr_t)&state->send_order_end | 1;
		ring_buffer_set(&state->send_queue, _hv_send_slot(state, packet, bypass), &tagged, sizeof(tagged), true);
		*state->send_order_end = packet;
		state->send_order_end = &packet->next;
		goto again;
	}
	end:
	state->send_unlocked_ref--;
	return now;
}

static inline void _hv_update_throughput(struct _hv_remote* state, struct _hv_send_packet* p, float ithr, float a){
	ithr /= (1 + fast_exp2f(state->growth)) * ((p->len4<<2)+48);
	state->us_per_byte += (ithr-state->us_per_byte)*a;
	assert(state->us_per_byte > 0.f);
}

// Take the packet in send_queue slot i (which holds its send order link `spacket`) out of send order, mark the slot acked and shift acked slots off the front
// rsz, base and i0 (an index the caller is iterating relative to) are updated if the queue shifts. The caller now owns the packet
static struct _hv_send_packet* _hv_send_slot_take(struct _hv_remote* state, size_t i, struct _hv_send_packet** spacket, uint32_t* rsz, uint32_t* base, uint64_t* i0, bool bypass){
	struct _hv_send_packet* p = *spacket, *next = p->next;
	if(!(*spacket = next)){
		state->send_order_end = spacket;
	}else{
		// set next's prev
		uintptr_t tagged = (uintptr_t)spacket | 1;
		ring_buffer_set(&state->send_queue, _hv_send_slot(state, next, bypass, *base), &tagged, sizeof(tagged), true);
	}
	if(i == 0){
		// Shift off this slot and any acked slots directly after it
		size_t j = 1;
		i = sizeof(struct _hv_send_packet*);
		while(j < *rsz){
			ring_buffer_get(&state->send_queue, i, &spacket, sizeof(spacket), true);
			if((uintptr_t)spacket != 1) break;
			i += sizeof(struct _hv_send_packet*); j++;
		}
		ring_buffer_shift_discard(&state->send_queue, i, false);
		*rsz -= j; *base += j; *i0 -= i;
	}else{
		uintptr_t acked_v = 1;
		ring_buffer_set(&state->send_queue, i, &acked_v, sizeof(acked_v), true);
	}
	state->qd_bytes4 -= p->len4;
	return p;
}

static void _hv_ackd(struct _hv_remote* state, uint8_t* packet, unsigned plen, uint64_t t0, uint64_t lo0, uint64_t lo2, uint64_t i0, bool bypass){
	uint32_t rsz = ring_buffer_size(&state->send_queue) / sizeof(struct _hv_send_packet*), base = _hv_send_base(state);
	uint8_t* packet_end = packet+plen;
	packet += 20;
	if(plen > 20) t0 -= le32toh(*(uint32_t*)(packet_end-4))>>8;
	uint32_t x = 0;
	//if(DEBUG) check_send(state);

	for(;;){
		int8_t delta = (int8_t)(uint8_t)x;
		//printf(packet == packet_end ? "+%d\n" : "+%d", delta);
		size_t i = i0 + (size_t)(ssize_t)delta * sizeof(struct _hv_send_packet*);
		uint64_t t = t0+(x>>8), lo = lo0+(uint64_t)(int64_t)delta;
		if(i >= (size_t)rsz * sizeof(struct _hv_send_packet*)) next: {
			if(packet < packet_end){
				x = le32toh(*(uint32_t*)packet);
				packet += 4;
				continue;
			}else break;
		}
		uintptr_t v;
		ring_buffer_get(&state->send_queue, i, &v, sizeof(v), true);
		// 0: not in send order (in flight), 1: already acked, |2: not sent yet
		v--;
		if(!v || (v & 1)) goto next;
		struct _hv_send_packet** spacket = (struct _hv_send_packet**)v;

		struct _hv_send_packet* p = _hv_send_slot_take(state, i, spacket, &rsz, &base, &i0, bypass);
		assert((uint32_t)lo == _hv_lseqof(p, bypass));

		if(!p->resent){
			// ADJUSTMENTS HERE
			float i_minlat = 1.f / state->min_latency;
			if(i_minlat > 1.f/_HV_SEND_TICK) i_minlat = 1.f/_HV_SEND_TICK;
			float ipprt = state->us_per_byte * ((p->len4<<2)+48) * i_minlat;
			if(ipprt > 1.f) ipprt = 1.f;
			float lat = (int64_t)((t - p->time_lo)<<21)>>21;
			float dt = (float)(t - state->min_latency_when) * i_minlat * .03125f;
			if(lat < state->min_latency * (dt < 1.f ? 1.f : dt)){
				state->min_latency = lat;
				state->min_latency_when = t;
			}
			assert(lat >= 0.f);
			uint32_t rtt_gate = (uint32_t)state->rtt_gate_lo|(uint32_t)state->rtt_gate_hi<<16;
			float ithr = (int64_t)((t-state->last_ack)<<16)>>16;
			if(ithr > 0.f) state->last_ack = t;
			else ithr = 0.f;
			if(rtt_gate != 2){
				if(rtt_gate == 8){
					rtt_gate = (uint32_t)lo2<<1|1;
					state->rtt_gate_lo = rtt_gate;
					state->rtt_gate_hi = rtt_gate>>16;
					state->avg_latency = lat;
					goto adj_end;
				}else if((uint32_t)(lo<<1|1) == rtt_gate){
					state->rtt_gate_lo = 2;
					state->rtt_gate_hi = 0;
				}else{
					_hv_update_throughput(state, p, ithr, ipprt*.25f);
					state->avg_latency += (lat - state->avg_latency)*ipprt;
					if unlikely((rtt_gate&5)==4){
						// Partition restored
						state->rtt_gate_hi = 0;
						state->rtt_gate_lo = array_buffer_size(&state->pipes_with_unsent) ? 8 : 0;
					}
					goto adj_end;
				}
			}
			_hv_update_throughput(state, p, ithr, ipprt*.25f);
			lat = (lat - state->avg_latency) * ipprt;
			state->avg_latency += lat*.125f;
			assert(state->avg_latency < 1e8f);
			//if(drand48() < .03f) printf("u/b=%f min_l=%.0fus avg_l=%.0fus\n", state->us_per_byte, state->min_latency, state->avg_latency);
			if(lat > 0) lat *= 2.f;
			dt = state->avg_latency-state->min_latency;
			float k = lat/dt;
			state->send_window += (uint64_t)(int64_t)(lat + dt*ipprt*.5f);
			state->growth += k*-.5f + .0625f*ipprt;
			if(state->growth > 0.f) state->growth = 0.f;
			if(state->growth < -8.f) state->growth = -8.f;
		}
		adj_end:
		_hv_free(p, _hv_packet_allocsz(p));
		//if(DEBUG) check_send(state);
		goto next;
	}
}

// Maybe todo: refactor this function
// Currently, it serves
// _hv_queue_ack(_, lo, hi, 0, true) when i==0 => ack only [lo,hi]
// _hv_queue_ack(_, lo, hi, 0, true) when i>0 => send what's there, don't add [lo,hi]
// _hv_queue_ack(_, lo, hi, t, _) when i==0 => append and conditionally send
// We should separate the queueing and sending logic into 2 functions
static void _hv_queue_ack(struct _hv_remote* state, uint64_t lo, uint32_t hi, uint64_t t, bool imm, bool bypass){
	unsigned i = state->ack_coal_i;
	//if(t || !i) assert(validate_ack(state, lo));
	if(t){
		if(!i) add: {
			state->ack_coal_buf[14] = (uint32_t)lo;
			state->ack_coal_tim0 = t;
			state->ack_coal_i = i = 1;
		}else{
			t = ((t<<8)-(state->ack_coal_tim0<<8)) >> 8;
			uint32_t seq = (uint32_t)lo-state->ack_coal_buf[14];
			if(!seq) return; // We already have this seq in the ack queue. sending seq==0 would be dangerous since we use that to differentiate another packet type
			if(t >= 0x1000000 || seq != (uint32_t)((int32_t)(seq<<24)>>24)){
				_hv_resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
				goto imm;
			}
			seq = (seq&0xff)|(uint32_t)t<<8;
			if(i == 15) imm = true;
			if(imm) _hv_resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
			state->ack_coal_buf[i-1] = seq;
			state->ack_coal_i = ++i;
		}
	}else if(i) _hv_resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
	else i = 1;
	if(imm) imm: {
		if(bypass){
			uint8_t packet[72];
			*(uint32_t*)packet = htole32(hi); *(uint32_t*)(packet+4) = htole32(lo>>32);
			//printf("acking [%u,%llu]+%u\n", hi, lo, i-1);
			uint32_t* pl = (uint32_t*)(packet+8);
			pl[0] = htole32(lo);
			if(i > 1){
				for(unsigned j = 1; j < i; j++)
					pl[j] = htole32(state->ack_coal_buf[j-1]);
				if(i&1) pl[i++] = 0;
			}
			uint64_t crc = crc64(state->recv_crcinit, packet, 8+(i<<2));
			*(uint32_t*)packet = htole32(crc); *(uint32_t*)(packet+4) = htole32(crc>>32);
			bool send_success = x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet, 9+(i<<2));
			soft_assert(send_success);
		}else{
			uint32_t chacha[30] = CHACHA20_INIT;
			memcpy(chacha+4, state->recv_key, 32);
			chacha[12] = 0xFFFFFFFE; // Should never collide with states used by actual payload
			chacha[13] = (uint32_t)lo; chacha[14] = (uint32_t)(lo>>32); chacha[15] = hi;
			ChaCha20_block(chacha);
			//printf("acking [%u,%llu]+%u\n", hi, lo, i-1);
			uint8_t* packet = (uint8_t*)(chacha+8); // 84 bytes
			uint32_t* pl = (uint32_t*)(packet+16);
			pl[0] = htole32(lo);
			for(unsigned j = 1; j < i; j++)
				pl[j] = htole32(state->ack_coal_buf[j-1]);
			Poly1305(packet+20, (i<<2)-4, (uint8_t*)chacha, packet);
			bool send_success = x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet, 16+(i<<2));
			soft_assert(send_success);
		}
		state->ack_coal_i = 0;
		if(!imm) goto add; // forced immediate send from overflow
	}else _hv_link_unsent_ack(state);
}

static void _hv_send_probe_ack_err(hivemind_server_t* s, uint32_t opts, const remote_t* to){
	uint8_t packet2[80];
	uint32_t* start = (uint32_t*)(packet2+36);
	_hv_nalloc_id(s, start+4);
	start[10] = start[4];
	memcpy(start, s->first_id, 20);
	start[9] = start[0];
	_hv_keyless_packet_finish(s, to, packet2, 40, opts);
}
static void _hv_send_probe_ack_err_enc_bypass(hivemind_server_t* s, uint32_t opts, const remote_t* to){
	uint8_t packet2[61];
	memcpy(packet2+20, s->first_id, 20);
	_hv_nalloc_id(s, (uint32_t*)(packet2+40));
	_hv_crcinitless_packet_finish(s, to, packet2, 40, opts);
}

#define _hv_is_worth_move(plen, buflen) ((plen) >= ((buflen)>>1)+((buflen)>>3))

// Contents of recv_queue:
// OLD
// size=0 ptr=0 -> None
// size=0 ptr=X -> Reassembly head
// size=N ptr=X -> Saved packet
// size=65535 ptr=0 -> Already received
// size=65535 ptr=N -> Already received dependent packet (fully reassembled, waiting)
// size=65534 ptr=N -> Dependent packet idx

// NEW
// (seq<<1|1) > 2 -> Dependent packet idx
// ptr (algn 4) -> reassembly head
// ptr (algn 4) | 2 -> Saved packet. Fully reassembled if cur == total
// 0 -> Not received
// 1 -> Already received
// 2 -> Already received, last packet of a message that couldn't be delivered. Its ack_err is unconfirmed (see ack_err_q)

// Ack scheme
// The last packet to be acked of a given message must be the last packet of the message
// Packets of a message should not be acked until all dependent messages' last packets have also been acked

static inline bool _hv_block_add(struct _hv_packet_reassembly* block, uint8_t* p, unsigned plen){
	size_t avail = block->total - block->cur, to_add = avail <= plen ? avail : plen;
	memcpy(block->data + block->cur, p, to_add);
	block->cur += to_add;
	return avail <= plen;
}

#define _hv_is_partial(p) ((p)>2&&((p)&3)==2)
#define _hv_is_reassembly(p) ((p)>2&&!((p)&3))

// Mark a recv_queue slot as processed. Processed slots at the front are shifted off, advancing recv_seq_lo
static inline void _hv_recv_slot_done(struct _hv_remote* state, size_t idx){
	uintptr_t cur = 1;
	if(idx){
		ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);
		return;
	}
	size_t sz = ring_buffer_size(&state->recv_queue);
	do idx += sizeof(uintptr_t);
	while(idx < sz && (ring_buffer_get(&state->recv_queue, idx, &cur, sizeof(cur), true), cur == 1));
	uint64_t seq_lo = state->recv_seq_lo;
	if((state->recv_seq_lo = seq_lo + idx/sizeof(uintptr_t)) < seq_lo) state->recv_seq_hi++;
	ring_buffer_shift_discard(&state->recv_queue, idx < sz ? idx : sz, false);
}

// ack_err / ack_err_ack
// A message whose pipe can't be acquired is answered with an ack_err in place of the ack for its last packet. The slot of that packet stays 2 (pinning recv_seq_lo) and the error stays in ack_err_q, resent until the sender confirms it with an ack_err_ack
// They live in the same space as keyless packets (marker word with low byte 0, where an ack would have a nonzero delta), but are signed with the session key
// encrypted (24B): [0,16) poly1305 tag over [20,24), [16,20) seq low32, [20,24) opts<<8
// bypass (16B + flag byte): [0,8) crc64 over [hi, lo>>32] ++ [8,16), [8,12) seq low32, [12,16) opts<<8
// ack_err: opts = 0x800001 | reason<<8, chacha_in[12] = -3, signed with the receiving side's key
// ack_err_ack: opts = 0x800002, chacha_in[12] = -4, signed with the sending side's key (the same key, seen from the other end)
#define _HV_ACK_ERR 0x800001
#define _HV_ACK_ERR_ACK 0x800002

// Fill an ack_err/ack_err_ack for the full sequence number [hi,lo], signed with this side's send key (use_send_key) or recv key
static void _hv_ack_ext_sign(struct _hv_remote* state, uint32_t packet[6], uint64_t lo, uint32_t hi, bool is_reack, bool bypass){
	if(bypass){
		packet[0] = htole32(hi); packet[1] = htole32(lo>>32);
		packet[2] = htole32(lo); packet[3] = htole32((uint32_t)is_reack);
		packet[4] = 0;
		uint64_t crc = crc64(is_reack ? state->send_crcinit : state->recv_crcinit, (uint8_t*)packet, 16);
		packet[0] = htole32(crc); packet[1] = htole32(crc>>32);
		packet[3] = 0x800001 + is_reack;
	}else{
		uint32_t chacha[16] = CHACHA20_INIT;
		memcpy(chacha+4, is_reack ? state->send_key : state->recv_key, 32);
		chacha[12] = is_reack ? 0xFFFFFFFC : 0xFFFFFFFD;
		chacha[13] = (uint32_t)lo; chacha[14] = (uint32_t)(lo>>32); chacha[15] = hi;
		ChaCha20_block(chacha);
		memcpy(packet, chacha, 16);
		packet[4] = htole32(lo);
		packet[5] = 0x800001 + is_reack;
	}
}

// ack_err is sent by the receiving side, ack_err_ack by the sending side
static void _hv_send_ack_ext(struct _hv_remote* state, uint64_t lo, uint32_t hi, bool is_reack, bool bypass){
	uint32_t packet[6];
	_hv_ack_ext_sign(state, packet, lo, hi, is_reack, bypass);

	bool send_success = x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet, bypass ? 17 : 24);
	soft_assert(send_success);
}

// Check a received ack_err (verified with our send key) or ack_err_ack (verified with our recv key)
static bool _hv_ack_ext_valid(struct _hv_remote* state, const uint8_t* packet, bool from_reack, uint64_t lo, uint32_t hi, bool bypass){
	uint32_t expect[6];
	_hv_ack_ext_sign(state, expect, lo, hi, from_reack, bypass);
	uint32_t* ptag = (uint32_t*)packet;
	return bypass ? expect[0] == ptag[0] && expect[1] == ptag[1] : !memcmp16(expect, ptag);
}

static void _hv_ack_err_ack_recvd(hivemind_server_t* s, struct _hv_remote* state, const uint8_t* packet, uint32_t seq, bool bypass){
	uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
	shared_lock_release(&s->state_lock);
	if(l == 1) goto rend;
	uint64_t lo = state->recv_seq_lo; uint32_t hi = state->recv_seq_hi;
	_hv_resolve_seq(&lo, &hi, seq);
	size_t idx = (lo - state->recv_seq_lo) * sizeof(uintptr_t);
	if(idx >= ring_buffer_size(&state->recv_queue)) goto rend;
	uintptr_t cur;
	ring_buffer_get(&state->recv_queue, idx, &cur, sizeof(cur), true);
	if(cur != 2 || !_hv_ack_ext_valid(state, packet, true, lo, hi, bypass)) goto rend;
	_hv_recv_slot_done(state, idx);
	rend:
	_hv_time_lock_rel(&state->recv_last_used, l);
}

// Received an ack_err/ack_err_ack. Expects the state lock held shared (released here)
static void _hv_ack_err_recvd(hivemind_server_t* s, struct _hv_remote* state, const uint8_t* packet, uint32_t seq, bool bypass){
	// We are the sender: fire the error feedback of the message ending at this packet, in place of acking it
	uint64_t l = _hv_time_lock_acq(&state->send_last_used);
	shared_lock_release(&s->state_lock);
	void* pa = 0;
	if(l == 1) goto send;
	uint32_t rsz = ring_buffer_size(&state->send_queue) / sizeof(struct _hv_send_packet*);
	uint64_t lo2 = state->send_seq_lo - rsz, lo = lo2; uint32_t hi = state->send_seq_hi;
	if(lo2 > state->send_seq_lo) hi--;
	_hv_resolve_seq(&lo, &hi, seq);
	int64_t d = (int64_t)(lo - lo2);
	if(d >= (int64_t)rsz || !_hv_ack_ext_valid(state, packet, false, lo, hi, bypass)) goto send;
	// Behind the queue: already settled, our ack_err_ack must have been lost
	bool reply = d < 0;
	uintptr_t udata;
	if(!reply){
		size_t i = (size_t)d * sizeof(struct _hv_send_packet*);
		uintptr_t v;
		ring_buffer_get(&state->send_queue, i, &v, sizeof(v), true);
		if(!v || !((uintptr_t)v&1)) goto reply;
		reply = true;
		if(v > 1){
			struct _hv_send_packet** spacket = (struct _hv_send_packet**)(v-1);
			uint32_t base = _hv_send_base(state); uint64_t i0 = 0;
			struct _hv_send_packet* p = _hv_send_slot_take(state, i, spacket, &rsz, &base, &i0, bypass);
			assert((uint32_t)lo == _hv_lseqof(p, bypass));
			pa = _hv_pipe_acquire(s, p->payload4+p->len4);
			udata = *(uint32_t*)(p->payload4+p->len4+5);
		#if UINTPTR_MAX > UINT32_MAX
			udata |= (uintptr_t)*(uint32_t*)(p->payload4+p->len4+6)<<32;
		#endif
			_hv_free(p, _hv_packet_allocsz(p));
		}
	}
	reply: if(reply) _hv_send_ack_ext(state, lo, hi, true, bypass);
	l = _hv_internal_clock();
	send:
	_hv_time_lock_rel(&state->send_last_used, l);
	if(pa){
		struct _hv_tls_packet_detach d = {.packet_on_heap = SIZE_MAX};
		_hv_fire_pipe_end(s, pa, (uint8_t*)udata, (SIZE_MAX-63) | HIVEMIND_CLOSED_PIPE_INVALID, &d);
	}
}

static inline uint8_t* _hv_push_packet(hivemind_server_t* s, struct _hv_remote* state, unsigned plen, uint64_t lo, uint32_t hi, uint8_t* p0, unsigned header, unsigned buflen, uint64_t tim, uint64_t msglen, uint32_t pipe_last, bool bypass){
	uint8_t* p = p0 + header;
	uint64_t idx = (lo - state->recv_seq_lo) * sizeof(uintptr_t);
	bool ack = true;
	uint32_t lo32 = (uint32_t)lo, next = lo32;
	if(idx >= ring_buffer_size(&state->recv_queue)){
		ring_buffer_push_memset(&state->recv_queue, 0, idx - ring_buffer_size(&state->recv_queue), false);
	}else{
		uintptr_t cur;
		ring_buffer_get(&state->recv_queue, idx, &cur, sizeof(cur), true);
		if(cur){
			if(cur < 3){
				// already processed
				if(cur == 2) _hv_send_ack_ext(state, lo, hi, false, bypass);
				else _hv_queue_ack(state, lo, hi, tim, false, bypass);
				goto done;
			}else if(cur&1){
				// dependent
				next += cur>>1;
			}else{
				// Ack if this packet is an unfinished reassembly (then it's not the last) or if the next packet has already arrived and it's also a partial (then it's also not the last)
				if(cur&2 ? (idx != ring_buffer_size(&state->recv_queue) && (ring_buffer_get(&state->recv_queue, idx + sizeof(uintptr_t), &cur, sizeof(cur), true), _hv_is_partial(cur))) : (((struct _hv_packet_reassembly*)cur)->cur < ((struct _hv_packet_reassembly*)cur)->total))
					_hv_queue_ack(state, lo, hi, tim, false, bypass);
				goto done;
			}
		}
	}
	struct _hv_packet_reassembly* block = 0;
	if(msglen != UINT64_MAX){
		// new message
		if(plen >= msglen){
			msg_complete:
			if(pipe_last == lo32) goto skip_check;
			uint64_t idx2 = (pipe_last - state->recv_seq_lo) * sizeof(uintptr_t);
			if(idx2 >= ring_buffer_size(&state->recv_queue)){
				//assert(false, "pipe_next points forward");
				goto skip_check;
			}
			uintptr_t cur;
			ring_buffer_get(&state->recv_queue, idx2, &cur, sizeof(cur), true);
			if(!cur){
				cur = (lo32-pipe_last)<<1 | 1;
				ring_buffer_set(&state->recv_queue, idx2, &cur, sizeof(cur), true);
				goto realloc_and_put;
			}else if(cur > 2){
				if unlikely(!soft_assert(!(cur&1))) goto realloc_and_put; // should never happen in practice since this packet would have been already received and ignored
				if(cur&2){
					uint8_t* dep = (uint8_t*)(cur-2);
					*(uint32_t*)(dep-4) = lo32;
					goto realloc_and_put;
				}else{
					struct _hv_packet_reassembly* dep = (struct _hv_packet_reassembly*)cur;
					// dependency
					dep->pipe_next = lo32;
					realloc_and_put:
					if(!block){
						block = _hv_alloc(sizeof(struct _hv_packet_reassembly) + msglen);
						block->total = msglen; block->pipe_next = lo32;
						block->pipe_last = pipe_last;
						memcpy(block->pipe, p-20, 20);
						memcpy(block->data, p, msglen);
					}
					_hv_recv_slot_done(state, idx);
					goto done;
				}
			}
			skip_check: {}
			// fire msg, along with any messages on the same pipe that were waiting for it
			// Each one is fully settled (ack or ack_err queued, slot processed) and its pipe slot acquired before the recv lock is released, and only then is the handler invoked
			// Anyone who sees it as processed must take the recv lock after us, so they can only acquire the pipe after us, keeping pipe order without holding the recv lock during the handler
			uint64_t kdw = state->key_derived_when;
			const uint32_t* id = block ? block->pipe : (uint32_t*)(p - 20);
			void* pipe = _hv_pipe_acquire(s, id);
			if(pipe){
				_hv_queue_ack(state, lo, hi, tim, false, bypass);
				_hv_recv_slot_done(state, idx);
			}else{
				uintptr_t cur = 2;
				ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);
				_hv_send_ack_ext(state, lo, hi, false, bypass);
			}
			state->recv_unlocked_ref++;
			_hv_time_lock_rel(&state->recv_last_used, tim);
			if(!block){
				// directly from packet
				bool move = _hv_is_worth_move(plen, buflen);
				struct _hv_tls_packet_detach d = {.packet_on_heap = move ? ~header : plen};
				if(pipe) _hv_fire_pipe_end(s, pipe, p, plen, &d);
				if(move && d.packet_on_heap == SIZE_MAX){
					p0 = _hv_alloc(buflen);
				}
			}else{
				// from reassembly completion
				struct _hv_tls_packet_detach d = {.packet_on_heap = ~sizeof(struct _hv_packet_reassembly)};
				if(pipe) _hv_fire_pipe_end(s, pipe, block->data, block->total, &d);
				if(d.packet_on_heap != SIZE_MAX) free(block);
			}
			_hv_time_lock_acq(&state->recv_last_used);
			// Indices and sequence numbers are recomputed each time since other threads may have shifted the queue while we were unlocked
			// A new kEX throws away the whole recv queue, including the rest of this chain
			while(next != lo32 && state->key_derived_when == kdw){
				lo = state->recv_seq_lo; hi = state->recv_seq_hi;
				_hv_resolve_seq(&lo, &hi, next);
				size_t idx2 = (lo - state->recv_seq_lo) * sizeof(uintptr_t);
				assert(idx2 < ring_buffer_size(&state->recv_queue));
				uintptr_t cur;
				ring_buffer_get(&state->recv_queue, idx2, &cur, sizeof(cur), true);
				assert(cur > 2 && !(cur&3));
				block = (struct _hv_packet_reassembly*)cur;
				lo32 = next; next = block->pipe_next;
				pipe = _hv_pipe_acquire(s, block->pipe);
				if(pipe){
					_hv_queue_ack(state, lo, hi, tim, false, bypass);
					_hv_recv_slot_done(state, idx2);
				}else{
					uintptr_t cur = 2;
					ring_buffer_set(&state->recv_queue, idx2, &cur, sizeof(cur), true);
					_hv_send_ack_ext(state, lo, hi, false, bypass);
				}
				_hv_time_lock_rel(&state->recv_last_used, tim);
				struct _hv_tls_packet_detach d = {.packet_on_heap = ~sizeof(struct _hv_packet_reassembly)};
				if(pipe) _hv_fire_pipe_end(s, pipe, block->data, block->total, &d);
				if(d.packet_on_heap != SIZE_MAX) free(block);
				_hv_time_lock_acq(&state->recv_last_used);
			}
			state->recv_unlocked_ref--;
			goto done;
		}else{
#if SIZE_MAX < 0xFFFFFFFFFFFF
			if unlikely(msglen > (SIZE_MAX-sizeof(struct _hv_packet_reassembly))){
				fputs("hivemind: _hv_push_packet(): Message size exhausts user address space\n", stderr);
				abort();
			}
#endif
			block = _hv_alloc(sizeof(struct _hv_packet_reassembly) + msglen);
			memcpy(block->pipe, p-20, 20);
			memcpy(block->data, p, msglen);
			block->total = msglen; block->cur = msglen;
			block->pipe_last = pipe_last;
			assert(next == lo32);
			add_more:
			if(idx + sizeof(uintptr_t) < ring_buffer_size(&state->recv_queue)){
				uintptr_t cur;
				ring_buffer_get(&state->recv_queue, idx + sizeof(uintptr_t), &cur, sizeof(cur), true);
				if(_hv_is_partial(cur)){
					_hv_queue_ack(state, lo, hi, tim, false, bypass);
					next: {}
					uint8_t* p2 = (uint8_t*)(cur - 2);
					bool end = _hv_block_add(block, p2, *(uint16_t*)(p2-6));
					free(p2 - (bypass ? 12 : 20)); // current `header` is for first-of-a-message packet
					cur = 1;
					ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);

					idx += sizeof(uintptr_t);
					lo32++; if(!++lo) hi++;
					if(end){
						block->pipe_next = next = *(uint32_t*)(p2-4);
						goto msg_complete;
					}
					ring_buffer_get(&state->recv_queue, idx + sizeof(uintptr_t), &cur, sizeof(cur), true);
					if(_hv_is_partial(cur)) goto next;
					cur = (uintptr_t)block;
					ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);
				}
			}
		}
	}else{
		if(!idx) goto done;
		uintptr_t cur;
		ring_buffer_get(&state->recv_queue, idx - sizeof(uintptr_t), &cur, sizeof(cur), true);
		if(_hv_is_reassembly(cur)){
			block = (struct _hv_packet_reassembly*)cur;
			pipe_last = block->pipe_last;
			bool end = _hv_block_add(block, p, plen);
			if(end){
				if(idx == sizeof(uintptr_t)){
					idx = 0;
					ring_buffer_shift_discard(&state->recv_queue, sizeof(uintptr_t), false);
					if(!++state->recv_seq_lo) state->recv_seq_hi++;
				}else{
					cur = 1;
					ring_buffer_set(&state->recv_queue, idx - sizeof(uintptr_t), &cur, sizeof(cur), true);
				}
				block->pipe_next = next;
				goto msg_complete;
			}else{
				cur = 1;
				ring_buffer_set(&state->recv_queue, idx - sizeof(uintptr_t), &cur, sizeof(cur), true);
				goto add_more;
			}
		}else add: {
			uint8_t* r = p;
			if(_hv_is_worth_move(plen, buflen)) p = _hv_alloc(buflen);
			else{
				r = _hv_alloc(plen + header) + header;
				memcpy(r, p, plen);
			}
			*(uint32_t*)(r-4) = next;
			*(uint16_t*)(r-6) = plen;
			*(uint16_t*)(r-8) = buflen;
			cur = (uintptr_t)r | 2;
			ring_buffer_set(&state->recv_queue, idx, &cur, sizeof(cur), true);
			if(soft_assert(idx)){
				ring_buffer_get(&state->recv_queue, idx - sizeof(uintptr_t), &cur, sizeof(cur), true);
				if(_hv_is_partial(cur))
					_hv_queue_ack(state, lo-1, hi - !lo, tim, false, bypass);
			}
			if(idx < ring_buffer_size(&state->recv_queue) - sizeof(uintptr_t)){
				ring_buffer_get(&state->recv_queue, idx + sizeof(uintptr_t), &cur, sizeof(cur), true);
				if(_hv_is_partial(cur))
					_hv_queue_ack(state, lo, hi, tim, false, bypass);
			}
		}
	}
	done:
	_hv_time_lock_rel(&state->recv_last_used, tim);
	return p0;
}

static uint8_t* _hv_drain_reads(hivemind_server_t* s, uint8_t* packet, unsigned buflen, bool original){
	for(unsigned read_count = 0;;){
		remote_t from;
		unsigned plen = (unsigned)x_udp_next_read(s->handle, &from, (char*)packet, buflen);
		if((int)plen < 0) break;
		if(original && ++read_count == 256){
			// Only the original reader should request help
			// quadratic increase is enough, exponential increase is dangerous
			hivemind_server_t* expected = 0;
			if(atomic_compare_exchange_strong_explicit(&_hv_meta.read_help_requested, &expected, s, memory_order_release, memory_order_relaxed)) x_event_queue_wake(&_hv_meta.queue, 0);
			else read_count = 255; // if we fail, we should try again immediately next time
		}
		if(_hv_addr_compare(&from.addr, from.port, &s->addr, le16toh(s->port_le), s->encryption_bypass_prefix_v4, s->encryption_bypass_prefix_v6)){
			// Encryption bypass
			if(plen < 12) continue;
			uint64_t crc = (uint64_t)le32toh(*(uint32_t*)packet)|(uint64_t)le32toh(*(uint32_t*)(packet+4))<<32;
			uint32_t seq = le32toh(*(uint32_t*)(packet+8)), pipe_last = seq;
			unsigned flags = plen&3; plen &= ~3;
			if(flags == 1){
				// ack
				if likely(plen == 12 || packet[12]){
					struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, 0);
					_hv_time_lock_acq(&state->send_last_used);
					uint64_t tim = _hv_internal_clock();
					shared_lock_release(&s->state_lock);
					uint64_t lo0 = state->send_seq_lo; uint32_t hi = state->send_seq_hi;
					uint32_t rsz = ring_buffer_size(&state->send_queue) / sizeof(struct _hv_send_packet*);
					uint64_t lo2 = lo0 - rsz;
					if(lo2>lo0) hi--; lo0 = lo2;
					_hv_resolve_seq(&lo0, &hi, seq);
					size_t i0 = (lo0 - lo2) * sizeof(struct _hv_send_packet*);
					lo2 += rsz;
					if(i0 < (rsz+128)*sizeof(struct _hv_send_packet*)){
						//printf("ack'd [%u,%llu]", hi, lo0);
						*(uint32_t*)(packet+4) = htole32(lo0>>32);
						*(uint32_t*)packet = htole32(hi);
						if(plen > 12 && !packet[plen-4]) plen -= 4;
						if(crc64(state->recv_crcinit, packet, plen) == crc) _hv_ackd(state, packet, plen, tim, lo0, lo2, i0, true);
					}
					_hv_time_lock_rel(&state->send_last_used, tim);
					continue;
				}
				if(plen < 24) continue;
				uint32_t opts = le32toh(*(uint32_t*)(packet+12))>>8;
				if(opts & 0x800000){
					struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, 0);
					if(state){
						if(opts == 0x800001)
							_hv_ack_err_recvd(s, state, packet, seq, true);
						else if(opts == 0x800002)
							_hv_ack_err_ack_recvd(s, state, packet, seq, true);
						shared_lock_release(&s->state_lock);
					}
					continue;
				}
				uint64_t crcinit = (uint64_t)le32toh(*(uint32_t*)(packet+8)) | (uint64_t)le32toh(*(uint32_t*)(packet+16))<<32;
				uint64_t t = epoch_now()/MILLISECOND_US, t1 = crcinit>>8;
				if((t>t1?t-t1:t1-t) > _HV_STATE_LIFETIME/1000)
					continue; // replay
				uint64_t dhash = _hv_mix64_addr(s->addr, le16toh(s->port_le)), shash = _hv_mix64_addr(from.addr, from.port);
				*(uint32_t*)packet = htole32(shash); *(uint32_t*)(packet+4) = htole32(shash>>32);
				*(uint32_t*)(packet+8) = htole32(dhash); *(uint32_t*)(packet+16) = htole32(dhash>>32);
				if(crc64(crcinit, packet, plen) != crc)
					continue; // crc failed
				unsigned payload_len = plen-20;
				struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, _HV_FIND_CREATE);
				if(!state) continue;
				uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
				// Prevent replay attack
				if(t1 <= state->key_derived_when){
					_hv_time_lock_rel(&state->recv_last_used, l);
					shared_lock_release(&s->state_lock);
					continue;
				}
				state->key_derived_when = t1;
				_hv_time_lock_rel(&state->recv_last_used, _hv_internal_clock());
				if(opts&2){
					if(payload_len != 40){
						shared_lock_release(&s->state_lock);
						continue;
					}
					// ack err
					array_buffer_t dropped = {0};
					_hv_time_lock_acq_excl(&state->send_last_used, &state->send_unlocked_ref);
					shared_lock_release(&s->state_lock);
					bool re_kex = _hv_filter_send_queue(s, state, (uint32_t*)(packet+12), (uint32_t*)(packet+32), opts&1, true, &dropped);
					_hv_time_lock_rel(&state->send_last_used, re_kex ? 1 : _hv_internal_clock());
					_hv_fire_dropped(s, array_buffer_data(&dropped), array_buffer_size(&dropped), HIVEMIND_CLOSED_PIPE_INVALID);
					array_buffer_destroy(&dropped);
				}else if(opts&1) goto probe_ackd;
				else if(!payload_len){
					shared_lock_release(&s->state_lock);
					if(l == 1) _hv_send_probe_ack_err_enc_bypass(s, 2, &from); // probe ack err
					else _hv_crcinitless_packet_finish(s, &from, packet, 0, 1); // probe ack
				}else shared_lock_release(&s->state_lock);
				continue;
			}
			
			unsigned header = 12;
			uint64_t crcinit = 0, len = -1ull;
			if unlikely(flags == 2){
				// New connection requested
				header = 36;
				crcinit = (uint64_t)htole32(*(uint32_t*)(packet+8))|(uint64_t)htole32(*(uint32_t*)(packet+12))<<32;
				uint64_t dhash = _hv_mix64_addr(s->addr, le16toh(s->port_le)), shash = _hv_mix64_addr(from.addr, from.port);
				*(uint32_t*)packet = htole32(shash); *(uint32_t*)(packet+4) = htole32(shash>>32);
				*(uint32_t*)(packet+8) = htole32(dhash); *(uint32_t*)(packet+12) = htole32(dhash>>32);
				if(crc64(crcinit, packet, plen) != crc) continue;
				len = (uint64_t)le16toh(*(uint16_t*)(packet+plen))|(uint64_t)(*(uint32_t*)(packet+plen-4))<<16;
				plen -= 4;
			}else if(flags == 3){
				header = 32;
				len = (uint64_t)le16toh(*(uint16_t*)(packet+plen));
				pipe_last = *(packet+plen+2);
				if(pipe_last == 0xff){
					len |= (uint64_t)le32toh(*(uint32_t*)(packet+plen-4))<<16;
					pipe_last = le32toh(*(uint32_t*)(packet+plen-8));
					plen -= 8;
				}else pipe_last = seq-pipe_last;
			}

			struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, flags == 2 ? _HV_FIND_CREATE : 0);
			if unlikely(!state) continue;
			uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
			uint64_t tim = _hv_internal_clock();
			shared_lock_release(&s->state_lock);
			uint64_t lo = 0; uint32_t hi = 0;
			size_t idx;
			if likely(flags != 2){
				if(l == 1){
					_hv_time_lock_rel(&state->recv_last_used, l);
					continue;
				}
				crcinit = state->recv_crcinit;
				lo = state->recv_seq_lo; hi = state->recv_seq_hi;
				_hv_resolve_seq(&lo, &hi, seq);
				idx = lo - state->recv_seq_lo;
				if(idx > 0xffffffff) ack_abort: {
					_hv_queue_ack(state, lo, hi, tim, false, true);
					_hv_time_lock_rel(&state->recv_last_used, tim);
					continue;
				}
				idx *= sizeof(uintptr_t);
				if(idx > 0 && idx < ring_buffer_size(&state->recv_queue)){
					uintptr_t p;
					ring_buffer_get(&state->recv_queue, idx, &p, sizeof(uintptr_t), true);
					if(p == 2){
						_hv_send_ack_ext(state, lo, hi, false, true);
						_hv_time_lock_rel(&state->recv_last_used, tim);
						continue;
					}
					// Odd values > 1 are dependency markers in a slot that hasn't been received yet
					if(p && !(p > 1 && (p&1))) goto ack_abort;
				}
				*(uint32_t*)packet = htole32(hi); *(uint32_t*)(packet+4) = htole32(lo>>32);
			}
			//printf("got %llu\n", lo);
			state->recv_unlocked_ref++;
			_hv_time_lock_rel(&state->recv_last_used, tim);
			if(crc64(crcinit, packet, plen) != crc){
				l = _hv_time_lock_acq(&state->recv_last_used);
				state->recv_unlocked_ref--;
				_hv_time_lock_rel(&state->recv_last_used, l);
				continue; // crc failed
			}
			uint8_t* payload = packet + header; plen -= header;
			l = _hv_time_lock_acq(&state->recv_last_used);
			state->recv_unlocked_ref--;
			if unlikely(flags == 2){
				uint64_t kdw = crcinit>>8;
				uint32_t last[5];
				_hv_nalloc_id(s, last);
				if unlikely(!_hv_pipeid_in_range((uint32_t*)(payload-20), s->first_id, last)){
					// Pipe range test failed, send probe ack err
					_hv_send_probe_ack_err_enc_bypass(s, 3, &from);
					_hv_time_lock_rel(&state->recv_last_used, l);
					continue;
				}else if(kdw <= state->key_derived_when){
					unsigned ackv = state->ack_coal_i;
					state->ack_coal_i = 0;
					_hv_queue_ack(state, 0, 0, 0, true, true);
					state->ack_coal_i = ackv;
					_hv_time_lock_rel(&state->recv_last_used, l);
					continue;
				}
				state->key_derived_when = kdw;
				state->recv_seq_lo = 0; state->recv_seq_hi = 0;
				_hv_remote_cleanup_recv(state, true);
				state->ack_coal_i = 0;
				state->recv_crcinit = crcinit;
				_hv_queue_ack(state, 0, 0, 0, true, true);
			}
			if(len != -1ull) header += 20;
			packet = _hv_push_packet(s, state, plen, lo, hi, packet, header, buflen, tim, len, pipe_last, true);
			continue;
		}
		if(plen < 20 || (plen&3)) continue;
		uint32_t seq = le32toh(*(uint32_t*)(packet+16));
		if(plen < 84){
			// ack
			if likely(plen == 20 || packet[20] != 0){
				struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, 0);
				if(!state) continue;
				_hv_time_lock_acq(&state->send_last_used);
				uint64_t tim = _hv_internal_clock();
				shared_lock_release(&s->state_lock);
				uint64_t lo0 = state->send_seq_lo; uint32_t hi = state->send_seq_hi;
				uint32_t rsz = ring_buffer_size(&state->send_queue) / sizeof(struct _hv_send_packet*);
				uint64_t lo2 = lo0 - rsz;
				if(lo2>lo0) hi--; lo0 = lo2;
				_hv_resolve_seq(&lo0, &hi, seq);

				size_t i0 = (lo0 - lo2) * sizeof(struct _hv_send_packet*);
				lo2 += rsz;
				if(i0 < (rsz+128)*sizeof(struct _hv_send_packet*)){
					//printf("ack'd [%u,%llu]", hi, lo0);
					union{
						uint32_t words[16];
						uint8_t bytes[64];
					} chacha = {.words = CHACHA20_INIT};
					memcpy(chacha.words+4, state->send_key, 32);
					chacha.words[12] = 0xFFFFFFFE; chacha.words[13] = (uint32_t)lo0;
					chacha.words[14] = (uint32_t)(lo0>>32); chacha.words[15] = hi;
					ChaCha20_block(chacha.words);
					Poly1305(packet+20, plen-20, chacha.bytes, chacha.bytes+32);
					uint32_t *dtag = (uint32_t*)(chacha.bytes+32), *ptag = (uint32_t*)packet;
					if(!memcmp16(dtag, ptag)) _hv_ackd(state, packet, plen, tim, lo0, lo2, i0, false);
					// else poly failed
				}
				_hv_time_lock_rel(&state->send_last_used, tim);
				continue;
			}
			unsigned payload_len = plen-40;
			uint32_t* knonce = (uint32_t*)(packet+20);
			uint32_t opts = le32toh(*knonce)>>8;
			if(opts & 0x800000){
				struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, 0);
				if(state){
					if(opts == 0x800001)
						_hv_ack_err_recvd(s, state, packet, seq, false);
					else if(opts == 0x800002)
						_hv_ack_err_ack_recvd(s, state, packet, seq, false);
					shared_lock_release(&s->state_lock);
				}
				continue;
			}
			knonce[0] = *(uint32_t*)(packet+16);
			uint32_t tag[4], *ptag = (uint32_t*)packet;
			uint32_t poly_key[8];
			uint64_t t = epoch_now()/MILLISECOND_US, t1 = _hv_keyless_sig2(s, &from, knonce, poly_key, (uint32_t*)(packet+40), payload_len > 32 ? 8 : payload_len>>2);
			if((t>t1?t-t1:t1-t) > _HV_STATE_LIFETIME/1000)
				continue; // replay
			*(uint32_t*)(packet+36) = htole32(opts<<8);
			if(payload_len) Poly1305(packet+36, payload_len+4, (uint8_t*)poly_key, (uint8_t*)tag);
			else memcpy(tag, poly_key, 16);
			if(memcmp16(tag, ptag))
				continue; // sig failed
			struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, _HV_FIND_CREATE);
			if(!state) continue;
			uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
			// Prevent replay attack
			if(t1 <= state->key_derived_when){
				_hv_time_lock_rel(&state->recv_last_used, l);
				shared_lock_release(&s->state_lock);
				continue;
			}
			state->key_derived_when = t1;
			_hv_time_lock_rel(&state->recv_last_used, _hv_internal_clock());
			if(opts&2){
				if(payload_len != 40){
					shared_lock_release(&s->state_lock);
					continue;
				}
				// ack err
				uint32_t pipe0[5]; pipe0[0] = *(knonce+13); memcpy(pipe0+1, knonce+5, 16);
				*(knonce+8) = *(knonce+14);
				array_buffer_t dropped = {0};
				_hv_time_lock_acq_excl(&state->send_last_used, &state->send_unlocked_ref);
				shared_lock_release(&s->state_lock);
				bool re_kex = _hv_filter_send_queue(s, state, pipe0, knonce+8, opts&1, false, &dropped);
				_hv_time_lock_rel(&state->send_last_used, re_kex ? 1 : _hv_internal_clock());
				_hv_fire_dropped(s, array_buffer_data(&dropped), array_buffer_size(&dropped), HIVEMIND_CLOSED_PIPE_INVALID);
				array_buffer_destroy(&dropped);
			}else if(opts&1) probe_ackd: {
				// probe ack
				_hv_time_lock_acq(&state->send_last_used);
				shared_lock_release(&s->state_lock);
				state->rtt_gate_lo = state->rtt_gate_hi = 0;
				size_t q_sz = ring_buffer_size(&state->send_queue);
				for(size_t i = 0; i < q_sz; i += sizeof(struct _hv_send_packet*)){
					struct _hv_send_packet** p;
					ring_buffer_get(&state->send_queue, i, &p, sizeof(p), true);
					if(p && ((uintptr_t)p & 1)) (*(struct _hv_send_packet**)((uintptr_t)p & ~1))->resent = 0;
				}
				_hv_time_lock_rel(&state->send_last_used, _hv_internal_clock());
			}else if(!payload_len){
				shared_lock_release(&s->state_lock);
				if(l == 1) _hv_send_probe_ack_err(s, 2, &from); // probe ack err
				else _hv_keyless_packet_finish(s, &from, packet, 0, 1); // probe ack
			}else shared_lock_release(&s->state_lock);
			continue;
		}
		uint32_t chacha_in[16] = CHACHA20_INIT;
		uint64_t kdw = 0, len = -1ull;
		uint32_t pipe_last;
		unsigned header = plen&63, plen2 = plen;
		if unlikely(!header){
			header = 64;
			// New connection requested
			// We should really reject invalid new connections as soon as possible
			// This is what _hv_ram_packed_kex_verify does
			kdw = _hv_ram_packed_kex_verify(s, &from, chacha_in+4, (uint32_t*)(packet+16));
			if(!kdw) continue;
		}
		struct _hv_remote* state = _hv_state_find(s, from.addr, from.port, !!kdw);
		if unlikely(!state) continue;
		uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
		uint64_t tim = _hv_internal_clock();
		shared_lock_release(&s->state_lock);
		uint64_t lo = 0; uint32_t hi = 0;
		size_t idx;
		if likely(!kdw){
			if(l == 1){
				_hv_time_lock_rel(&state->recv_last_used, l);
				continue;
			}
			memcpy(chacha_in+4, state->recv_key, 32);
			lo = state->recv_seq_lo; hi = state->recv_seq_hi;
			_hv_resolve_seq(&lo, &hi, seq);
			idx = lo - state->recv_seq_lo;
			if(idx > 0xffffffff) ack_abort2: {
				_hv_queue_ack(state, lo, hi, tim, false, false);
				_hv_time_lock_rel(&state->recv_last_used, tim);
				continue;
			}
			idx *= sizeof(uintptr_t);
			if(idx > 0 && idx < ring_buffer_size(&state->recv_queue)){
				uintptr_t p;
				ring_buffer_get(&state->recv_queue, idx, &p, sizeof(uintptr_t), true);
				if(p == 2){
					_hv_send_ack_ext(state, lo, hi, false, false);
					_hv_time_lock_rel(&state->recv_last_used, tim);
					continue;
				}
				// Odd values > 1 are dependency markers in a slot that hasn't been received yet
				if(p && !(p > 1 && (p&1))) goto ack_abort2;
			}
			chacha_in[13] = (uint32_t)lo; chacha_in[14] = (uint32_t)(lo>>32); chacha_in[15] = hi;
		}
		//printf("got %llu\n", lo);
		state->recv_unlocked_ref++;
		_hv_time_lock_rel(&state->recv_last_used, tim);
		uint32_t d[16]; memcpy(d, chacha_in, 64);
		d[12] = 0xffffffff; ChaCha20_block(d);
		if unlikely(header == 64){
			len = (uint64_t)le32toh(*(uint32_t*)(packet+plen-4) ^ d[15])|(uint64_t)le32toh(*(uint32_t*)(packet+plen-8) ^ d[14])<<32;
			header = 40; plen -= 8;
		}else if(header == 44){
			uint32_t x = le32toh(*(uint32_t*)(packet+plen-4) ^ d[15]);
			len = x>>16; pipe_last = seq-(x&0xffff);
			plen -= 4; header = 40;
		}else if(header == 52){
			len = (uint64_t)(le32toh(*(uint32_t*)(packet+plen-4) ^ d[15])&0xffff)|(uint64_t)le16toh(*(uint16_t*)(packet+plen-8) ^ d[14])<<16;
			pipe_last = le32toh(*(uint32_t*)(packet+plen-12) ^ d[13]);
			plen -= 12; header = 40;
		}else if(header != 20) continue;
		uint8_t* payload = packet + header; plen -= header;
		Poly1305(payload, plen2 - header, (uint8_t*) d, (uint8_t*)(d+8));
		uint32_t *ptag = (uint32_t*)packet;
		if(memcmp16(d+8, ptag)){
			l = _hv_time_lock_acq(&state->recv_last_used);
			state->recv_unlocked_ref--;
			_hv_time_lock_rel(&state->recv_last_used, l);
			continue; // poly failed
		}
		chacha_in[12] = 0;
		ChaCha20_block_xor(chacha_in, payload, plen>>6);
		if(len != UINT64_MAX){
			uint32_t* pipeid = (uint32_t*)(payload-20);
			for(unsigned i = 0; i < 5; i++) pipeid[i] ^= d[8+i];
		}
		l = _hv_time_lock_acq(&state->recv_last_used);
		state->recv_unlocked_ref--;
		if unlikely(kdw){
			uint32_t last[5];
			_hv_nalloc_id(s, last);
			if(!_hv_pipeid_in_range((uint32_t*)(payload-20), s->first_id, last)) kdw = -1ull;
			if unlikely(kdw == -1ull){
				// Pipe range test failed, send probe ack err
				_hv_send_probe_ack_err(s, 3, &from);
				_hv_time_lock_rel(&state->recv_last_used, l);
				continue;
			}else if(kdw <= state->key_derived_when){
				unsigned ackv = state->ack_coal_i;
				state->ack_coal_i = 0;
				_hv_queue_ack(state, 0, 0, 0, true, false);
				state->ack_coal_i = ackv;
				_hv_time_lock_rel(&state->recv_last_used, l);
				continue;
			}
			state->key_derived_when = kdw;
			state->recv_seq_lo = 0; state->recv_seq_hi = 0;
			_hv_remote_cleanup_recv(state, false);
			state->ack_coal_i = 0;
			memcpy(state->recv_key, chacha_in+4, 32);
			_hv_queue_ack(state, 0, 0, 0, true, false);
		}
		packet = _hv_push_packet(s, state, plen, lo, hi, packet, header, buflen, tim, len, pipe_last, false);
	}
	return packet;
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
		if(ev.type & (X_EVENT_READABLE/*|X_EVENT_WRITABLE*/))
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
				retry:
				atomic_store_explicit(&self.hazard, help, memory_order_relaxed);
				//thread_memory_barrier(mb_co_acquire); // order protected by the `acq_rel` xchg
				if(help == atomic_exchange_explicit(&_hv_meta.read_help_requested, 0, memory_order_acq_rel)){
					x_event_queue_wake(&_hv_meta.queue, 0); // someone else deal with any wakes
					ev.data.ptr = help;
					goto recv_packet;
				} // if changed, another wakeup will handle it
			}
			uint64_t wake = GC_FREQ;
			// early test
			uint64_t tim = _hv_internal_clock();
			if((uintptr_t)atomic_load_explicit(&_hv_meta.unsent_ack, memory_order_relaxed) > 1){
				struct _hv_remote* state = atomic_exchange_explicit(&_hv_meta.unsent_ack, 0, memory_order_acquire), *head = state;
				atomic(struct _hv_remote*) *prev = (atomic(struct _hv_remote*)*)&head;
				new_unsent_acks:
				while((uintptr_t)state > 1){
					uint64_t l = _hv_time_lock_acq(&state->recv_last_used);
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
								if(!state->undrained_next){ free(state); goto next_a; }
								else _hv_time_lock_rel(&state->send_last_used, l);
							}
						}
					}else prev = &state->unsent_ack_next;
					_hv_time_lock_rel(&state->recv_last_used, l);
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
					uint64_t l = _hv_time_lock_acq(&state->send_last_used);
					uint64_t tim = _hv_internal_clock();
					struct _hv_remote* n = atomic_load_explicit(&state->undrained_next, memory_order_relaxed);
					if(!ring_buffer_size(&state->send_queue)){
						atomic_store_explicit(prev, n, memory_order_relaxed);
						atomic_store_explicit(&state->undrained_next, 0, memory_order_relaxed);
						if unlikely(!state->prevp){
							uint64_t l = _hv_time_lock_try_acq(&state->recv_last_used);
							if(l){
								if(!atomic_load_explicit(&state->unsent_ack_next, memory_order_relaxed)){ free(state); goto next_u; }
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
			hivemind_server_t* s = (hivemind_server_t*) ev.data.ptr;
			atomic_thread_fence(memory_order_acquire);
			uint16_t mtu = le16toh(s->mtu_le);
			if(packetsz < mtu){
				free(packet);
				packet = (uint8_t*)_hv_alloc(packetsz = mtu);
			}
			packet = _hv_drain_reads(s, packet, packetsz, ev.type == X_EVENT_READABLE);
			atomic_store_explicit(&self.hazard, 0, memory_order_release);
		}
		/*if(ev.type & X_EVENT_WRITABLE){
			hivemind_server_t* s = (hivemind_server_t*) ev.data.ptr;
			atomic_thread_fence(memory_order_acquire);
			// Server open

			//atomic_store_explicit(&self.hazard, 0, memory_order_release);
		}*/
		if(ev.type & X_EVENT_CLOSE){
			hivemind_server_t* s = (hivemind_server_t*) ev.data.ptr;
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
	free(packet);
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