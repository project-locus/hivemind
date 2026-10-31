#pragma once
#include "plumbing.c"

static void _hv_send_packet(struct _hv_remote* state, struct _hv_send_packet* packet, uint64_t now, bool bypass){
	unsigned len = packet->len4<<2;
	if(bypass && packet->first) len -= packet->kex ? 2 : 1;
	soft_assert(x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet->payload4, len));
	packet->time_lo = now;
}

// Undo the encryption of a sent (non bypass) packet with full sequence number [hi,lo], restoring the plaintext hivemind_send built
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
		}else{ tail = 1; }
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
	t[-1] = htole32(bypass ? (x&0xffff) | diff<<16 : (x&0xffff0000) | diff);
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
	struct _hv_send_packet* k = (struct _hv_send_packet*)_hv_alloc(sizeof(struct _hv_send_packet) + 4*(khdr+2) + (data ? 0 : fb));
	k->len4 = khdr+2; k->first = k->kex = 1; k->resent = 0; k->time_lo = 0;
	k->has_err_fb = !data && f->has_err_fb;
	memcpy(k->payload4+khdr-5, pipeid, 20);
	k->payload4[khdr+1] = htole32(len&0xffff);
	k->payload4[khdr] = htole32(len>>16);
	struct _hv_send_packet* tail_p = k;
	if(data){
		struct _hv_send_packet* c = (struct _hv_send_packet*)_hv_alloc(sizeof(struct _hv_send_packet) + 4*(chdr+data) + fb);
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
		state->send_crcinit = epoch_now()/MILLISECOND_US;
	}else{
		remote_t to = {.addr = state->addr, .port = state->port};
		_hv_make_signed_auth(s, &to, f->payload4+4, state->send_key, 0, 0, epoch_now()/MILLISECOND_US);
	}
	return f;
}

static inline void _hv_fire_dropped(hivemind_server_t* s, uint32_t* dropped, size_t count, hivemind_pipe_err_reason_t reason){
	while(count -= 20+sizeof(uintptr_t)){
		uintptr_t udata = dropped[5];
	#if UINTPTR_MAX > UINT32_MAX
		udata |= (uintptr_t)dropped[6] << 32;
	#endif
		_hv_fire_pipe_err(s, dropped, (void*)udata, reason);
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
	}else{
		while(ring_iterator_next(&it, &v, sizeof(v), true)){
			if(v < 2) continue;
			struct _hv_send_packet* p = v&1 ? *(struct _hv_send_packet**)(v-1) : (struct _hv_send_packet*)v;
			if(p->has_err_fb)
				array_buffer_push(dropped, p->payload4 + p->len4, 20 + sizeof(uintptr_t));
			array_buffer_push(&to_free, &p, sizeof(struct _hv_send_packet*));
		}
	}
	ring_buffer_destroy(&old_send_queue);
	array_buffer_destroy(&old_pipes);
	hash_table_set_rank(&old_b, 0);

	array_iterator_t it2 = array_buffer_iterator(&to_free, 0, SIZE_MAX);
	struct _hv_send_packet* to_free_p;
	while(array_iterator_next(&it2, &to_free_p, sizeof(struct _hv_send_packet*))) _hv_free(to_free_p, _hv_packet_allocsz(to_free_p));
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
		if(now - state->last_ack > state->server->message_timeout) goto timeout;
		uint32_t rtt_gate = (uint32_t)state->rtt_gate_lo | (uint32_t)state->rtt_gate_hi<<16;
		if(rtt_gate < 8){
			// Timer expired, send a probe packet
			uint8_t packet[40];
			remote_t to = {.addr = state->addr, .port = state->port};
			if(bypass) _hv_standalone_bypass_packet_finish(state->server, &to, packet, 0, 0);
			else _hv_standalone_packet_finish(state->server, &to, packet, 0, 0);
			rtt_gate = 4096;
		}else{ rtt_gate -= 8; }
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
	uint64_t cutoff = now;
	if(!isinf(state->min_latency)){
		cutoff = (uint64_t)(state->min_latency + (state->avg_latency-state->min_latency)*4.);
		if(cutoff < _HV_SEND_TICK*2) cutoff = _HV_SEND_TICK*2;
		cutoff = (now - cutoff) << 20;
	}
	struct _hv_send_packet** replace = 0;
	uint32_t base = _hv_send_base(state);
	if(packet){
		if unlikely(packet->resent /* short-circuit */ && now - state->last_ack > state->server->message_timeout) timeout: {
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
			if((int64_t)((packet->time_lo<<20) - cutoff) >= 0) exit_loop: {
				if(packet == packet0) packet0 = 0;
				state->send_order_start = packet;
				break;
			}
			if unlikely(packet->resent++ == 7){
				// go into probe mode
				state->rtt_gate_lo = 4; state->rtt_gate_hi = 0;
				packet->resent = 1;
				goto exit_loop;
			}
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
				crc = crc64(crcinit, (uint8_t*)packet->payload4, (packet->len4<<2)-2);
				packet->payload4[2] = htole32(crcinit); packet->payload4[3] = htole32(crcinit>>32);
			}else{ crc = crc64(crcinit, (uint8_t*)packet->payload4, (packet->len4<<2) - packet->first); }
			packet->payload4[0] = htole32(crc); packet->payload4[1] = htole32(crc>>32);
		}else{ _hv_encrypt_packet(chacha_in, packet); }
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

	for(;;){
		int8_t delta = (int8_t)(uint8_t)x;
		size_t i = i0 + (size_t)(ssize_t)delta*sizeof(struct _hv_send_packet*);
		uint64_t t = t0+(x>>8), lo = lo0+(uint64_t)(int64_t)delta;
		if(i >= (size_t)rsz * sizeof(struct _hv_send_packet*)) next: {
			if(packet < packet_end){
				x = le32toh(*(uint32_t*)packet);
				packet += 4;
				continue;
			}else{ break; }
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
			float lat = (int64_t)((t - p->time_lo)<<20)>>20;
			float dt = (float)(t - state->min_latency_when) * i_minlat * .03125f;
			if(lat < state->min_latency * (dt < 1.f ? 1.f : dt)){
				state->min_latency = lat;
				state->min_latency_when = t;
			}
			assert(lat >= 0.f);
			uint32_t rtt_gate = (uint32_t)state->rtt_gate_lo | (uint32_t)state->rtt_gate_hi<<16;
			float ithr = (int64_t)((t-state->last_ack)<<16)>>16;
			if(ithr > 0.f) state->last_ack = t;
			else ithr = 0.f;
			if(rtt_gate != 2){
				if(rtt_gate == 8){
					rtt_gate = (uint32_t)lo2<<1 | 1;
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
			seq = (seq&0xff) | (uint32_t)t<<8;
			if(i == 15) imm = true;
			if(imm) _hv_resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
			state->ack_coal_buf[i-1] = seq;
			state->ack_coal_i = ++i;
		}
	}else if(i){
		_hv_resolve_seq(&lo, &hi, state->ack_coal_buf[14]);
	}else{ i = 1; }
	if(imm) imm: {
		if(bypass){
			uint8_t packet[72];
			*(uint32_t*)packet = htole32(hi); *(uint32_t*)(packet+4) = htole32(lo>>32);
			uint32_t* pl = (uint32_t*)(packet+8);
			pl[0] = htole32(lo);
			if(i > 1){
				for(unsigned j = 1; j < i; j++)
					pl[j] = htole32(state->ack_coal_buf[j-1]);
				if(i&1) pl[i++] = 0;
			}
			uint64_t crc = crc64(state->recv_crcinit, packet, 8+(i<<2));
			*(uint32_t*)packet = htole32(crc); *(uint32_t*)(packet+4) = htole32(crc>>32);
			
			soft_assert(x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet, 9+(i<<2)));
		}else{
			uint32_t chacha[30] = CHACHA20_INIT;
			memcpy(chacha+4, state->recv_key, 32);
			chacha[12] = 0xfffffffe; // Should never collide with states used by actual payload
			chacha[13] = (uint32_t)lo; chacha[14] = (uint32_t)(lo>>32); chacha[15] = hi;
			ChaCha20_block(chacha);
			uint8_t* packet = (uint8_t*)(chacha+8); // 84 bytes
			uint32_t* pl = (uint32_t*)(packet+16);
			pl[0] = htole32(lo);
			for(unsigned j = 1; j < i; j++)
				pl[j] = htole32(state->ack_coal_buf[j-1]);
			Poly1305(packet+20, (i<<2)-4, (uint8_t*)chacha, packet);

			soft_assert(x_udp_send(_hv_state_handle(state), (remote_t){state->addr, state->port, 0, 0}, (char*)packet, 16+(i<<2)));
		}
		state->ack_coal_i = 0;
		if(!imm) goto add; // forced immediate send from overflow
	}else{ _hv_link_unsent_ack(state); }
}