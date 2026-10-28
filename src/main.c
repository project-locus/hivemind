#include "tasks.c"

void hivemind_init(hivemind_server_t* s, const uint8_t master_key[32], hivemind_on_pipe_msg_fn_t on_msg){
	memset(s, 0, sizeof(*s));
	s->on_msg = on_msg;
	s->udata = s;
	s->message_timeout = 900 * SECOND_US;
	s->backpressure_limit = 2147483648;
	s->encryption_bypass_prefix_v4 = 32;
	s->encryption_bypass_prefix_v6 = 128;
	s->network_bypass_prefix_v4 = 255;
	s->network_bypass_prefix_v6 = 255;
	shared_lock_init(&s->state_lock);
	shared_lock_init(&s->pipes_lock);
	x_randombytes(s->_rand_bytes, 16);
#ifndef __SIZEOF_INT128__
	atomic_init(&s->_id_lock, ATOMIC_FLAG_INIT);
#endif
	for(unsigned i = 0; i < 8; i++) s->master_key[i] = (uint32_t)master_key[i<<2] | (uint32_t)master_key[i<<2 | 1]<<8 | (uint32_t)master_key[i<<2 | 2]<<16 | (uint32_t)master_key[i<<2 | 3]<<24;
}
bool hivemind_start(hivemind_server_t* s, remote_t where, ip_addr_t reflect_test){
	x_socket_t sock = x_udp_bound(where);
	if(sock == X_SOCKET_INVALID) return false;
	s->handle = sock;
	bool has_addr = s->addr.dwords[0] || s->addr.dwords[1] || s->addr.dwords[2] || s->addr.dwords[3];
	if(!has_addr || !s->port_le || !s->mtu_le){
		if(!x_udp_reflect(sock, reflect_test, &where, true)) err: {
			x_socket_free(sock);
			return false;
		}
		if(!has_addr) s->addr = where.addr;
		if(!s->port_le) s->port_le = htole16(where.port);
		if(!s->mtu_le) s->mtu_le = htole16(where.mtu);
	}
	s->mtu_le &= htole16(~3);
	// 256MB total. Can queue 128MB every _HV_SEND_TICK which is 64GB/s or 512Gbps (realistically a bit less but this is still more than good enough)
	if(!x_udp_opts(sock, 131072 * 1024, 131072 * 1024))
		goto err;

	_hv_nalloc_id(s, s->first_id);
	if(s->network_bypass_prefix_v4 < 48 || s->network_bypass_prefix_v6 < 144){
		atomic_init(&s->vq_flag, 1);
		char name[56]; _hv_vq_name(name, s->addr, le16toh(s->port_le));
		struct _hv_vq* b = _hv_alloc(sizeof(struct _hv_vq));
		atomic_init(&b->ref, 1);
		s->vq_block = b;
		if(!vqueue_open(&b->q, name, sizeof(name))) err2: {
			_hv_free(b, sizeof(struct _hv_vq));
			goto err;
		}
		thread_detach(thread_create((void*(*)(void*))_hv_vq_loop, s, 0));
	}else{ atomic_init(&s->vq_flag, 0); }

	lock_acquire(&_hv_meta.threads_lock, 1);
	if(!_hv_meta.threads_max){
		if(!x_event_queue_init(&_hv_meta.queue)) err3: {
			lock_release(&_hv_meta.threads_lock, 1);
			goto err2;
		}
		if(!x_event_queue_add(&_hv_meta.queue, sock, (x_userdata_t){.ptr = s})){
			x_event_queue_destroy(&_hv_meta.queue);
			goto err3;
		}
		_hv_meta.threads_cur = 1; _hv_meta.threads_max = (uint32_t)available_concurrency()-1;
		_hv_meta.scale_changed = _hv_internal_clock();
		atomic_store_explicit(&_hv_meta.scale_at, _hv_meta.scale_changed, memory_order_release);
		thread_detach(thread_create(_hv_listen, 0, 0));
	}else if(!x_event_queue_add(&_hv_meta.queue, sock, (x_userdata_t){.ptr = s})){ goto err2; }
	hivemind_server_t* prev = atomic_load_explicit(&_hv_meta.servers, memory_order_relaxed);
	if(prev) prev->prevp = &s->next;
	atomic_init(&s->next, prev);
	atomic_store_explicit(s->prevp = &_hv_meta.servers, s, memory_order_release);
	lock_release(&_hv_meta.threads_lock, 1);
	return true;
}

uint8_t* hivemind_packet_detach(const uint8_t* p){
	struct _hv_tls_packet_detach* d = tls_packet_detach;
	struct _hv_vq* b = d->vq_block;
	if(b){
		*(struct _hv_vq**)(p - 20) = b;
		*(size_t*)(p - 20 + sizeof(struct _hv_vq*)) = d->packet_on_heap;
		*(uint16_t*)(p - 2) = 0xffff;
		atomic_fetch_add_explicit(&b->ref, 1, memory_order_relaxed);
		d->packet_on_heap = SIZE_MAX; d->vq_block = 0;
		return (uint8_t*)p;
	}
	if(d->packet_on_heap >= SIZE_MAX-1){ d->packet_on_heap |= 1; return (uint8_t*)p; }
	uint8_t* p2 = (uint8_t*)_hv_alloc(d->packet_on_heap);
	if(d->packet_on_heap) memcpy(p2, p, d->packet_on_heap);
	d->packet_on_heap = SIZE_MAX;
	return p2;
}
void hivemind_packet_free(const uint8_t* p){
	if((uintptr_t)p & 7){
		uint16_t off = *(uint16_t*)(p-2);
		if(off == 0xffff){
			p -= 20;
			struct _hv_vq* b = *(struct _hv_vq**)p;
			vqueue_free(&b->q, (vqueue_block_t){.size = *(size_t*)(p+sizeof(struct _hv_vq*)), .data = (uint8_t*)p});
			if unlikely(atomic_fetch_sub_explicit(&b->ref, 1, memory_order_acq_rel) == 1){
				vqueue_close(&b->q);
				_hv_free(b, sizeof(struct _hv_vq));
			}
			return;
		}
		p -= off;
	}
	free((void*)p);
}
void hivemind_pipe_unlock(void){
	struct _hv_tls_packet_detach* d = tls_packet_detach;
	if(d->pipe_lock) lock_release(d->pipe_lock, 1), d->pipe_lock = 0;
}

void hivemind_create_pipe(hivemind_server_t* s, hivemind_pipe_t* pipe, void* udata, hivemind_pipe_qos_t qos){
	pipe->addr = s->addr; pipe->port_mtu_packed_le = s->port_mtu_packed_le | htole32((qos&3)<<16);
	_hv_alloc_id(s, pipe->id, epoch_now()/MILLISECOND_US);
	_hv_append_pipe(s, pipe->id, udata);
}
void* hivemind_close_pipe(hivemind_server_t* s, const hivemind_pipe_t* pipe){
	assert(!memcmp(pipe->dwords, &s->dwords, 20));
	return _hv_kill_pipe(s, pipe->id);
}

void hivemind_send(hivemind_server_t* s, const hivemind_pipe_t* to, const uint8_t* msg, size_t len, const hivemind_pipe_t* f_return_pipe, uintptr_t errudata){
#ifndef HIVEMIND_NO_LOCAL_BYPASS
	if(!memcmp(s->dwords, to->dwords, 18 /* Everything except MTU */)){
		// Zero-copy loopback shortcut
		struct _hv_tls_packet_detach d = {.packet_on_heap = len};
		_hv_fire_pipe(s, to->id, msg, len, &d);
		return;
	}
#endif
#if (SIZE_MAX>>1) < 0x7fffffffffff-64
	if unlikely(len > (SIZE_MAX>>1)){
		fputs("hivemind: hivemind_send(): Message size exhausts user address space\n", stderr);
		abort();
	}
#else
	if unlikely(len > 0x7fffffffffff){
		fputs("hivemind: hivemind_send(): Message size exceeds protocol limit\n", stderr);
		abort();
	}
#endif
	unsigned port = le16toh(to->port_le), mtu = le16toh(to->mtu_le)>>2;
	struct _hv_remote* state = _hv_state_find(s, to->addr, (uint16_t)port, _HV_FIND_CREATE | _HV_FIND_INCLUDE_VQ);
	if(state->bypass_type & 2){
		struct _hv_remote_vq* state_vq = (struct _hv_remote_vq*)state;
		bool open = state->bypass_type & 1;
		atomic_fetch_add_explicit(&state_vq->ref, open, memory_order_relaxed);
		shared_lock_release(&s->state_lock);
		if(open){
			vqueue_block_t block = vqueue_alloc(&state_vq->q, len+20);
			memcpy(block.data, to->id, 20);
			memcpy(block.data+20, msg, len);
			vqueue_post(&state_vq->q, block);
			atomic_store_explicit(&state_vq->vq_last_used, _hv_internal_clock(), memory_order_relaxed);
			atomic_fetch_sub_explicit(&state_vq->ref, 1, memory_order_release);
		}
		return;
	}
	const uint8_t* omsg = msg;
	retry: {}
	size_t pad_len = (len+3)>>2, num_packets = 1;
	uint64_t seq_lo; uint32_t seq_hi;
	unsigned ser_mtu = state->server_mtu<<2;
	if(ser_mtu < mtu) mtu = ser_mtu;
	bool bypass = state->bypass_type & 1;
	unsigned extra = 0, header;
	if(bypass){
		// Encryption bypass
		mtu -= header = 3;
	}else{
		pad_len = (pad_len + 15ull) & -16ull;
		mtu -= header = 5; extra = mtu&15u; mtu &= -16u;
	}
	header += 5; // pipeid
	assert(mtu && mtu < 65536);

	if(pad_len > (size_t)mtu) num_packets += (pad_len-1ull) / mtu;

	retry_acq: {}
	uint64_t l = _hv_time_lock_acq(&state->send_last_used);
	if(state->send_unlocked_ref&0x80000000){
		// Someone's waiting on a strong exclusive lock
		_hv_time_lock_rel(&state->send_last_used, l);
		thread_yield();
		goto retry_acq;
	}
	shared_lock_release(&s->state_lock);

	uint64_t tim = _hv_internal_clock();
	struct _hv_send_packet* packet = 0;
	// plen excludes the header which is kinda sus
	unsigned plen = 0, true_plen = 0;
	struct _hv_send_packet_placeholder plch;
	uint32_t pipe_last;
	bool last, long_encoding;
	size_t total_size = 0;
	size_t rsz = ring_buffer_size(&state->send_queue) / sizeof(struct _hv_send_packet*);
	if unlikely(l == 1 || (tim-l) > _HV_STATE_LIFETIME){
		if(!state->prevp){
			state->send_unlocked_ref--;
			_hv_time_lock_rel(&state->send_last_used, 1);
			return;
		}
		if(bypass){
			header = 9;
			num_packets += (num_packets*mtu - pad_len) < 8;
			if unlikely((size_t)rsz + num_packets > 0x80000000) goto overflow;
			last = num_packets == 1;
			plen = last ? (unsigned)pad_len : mtu-8;
			packet = (struct _hv_send_packet*)_hv_alloc(sizeof(struct _hv_send_packet) + 4*(true_plen = header+plen+2) + (last && f_return_pipe ? 20+sizeof(uintptr_t) : 0));
			uint64_t shash = _hv_mix64_addr(s->addr, le16toh(s->port_le)), dhash = _hv_mix64_addr(to->addr, le16toh(to->port_le));
			packet->payload4[0] = htole32(shash); packet->payload4[1] = htole32(shash>>32);
			packet->payload4[2] = htole32(dhash); packet->payload4[3] = htole32(dhash>>32);
			_hv_nalloc_id(s, state->send_key+3);
			state->send_key[2] = 0;
			state->send_crcinit = _hv_alloc_id_short(s);
		}else{
			unsigned first_mtu = mtu;
			header = 14;
			if(extra < 11){
				num_packets += (num_packets*mtu - pad_len) < 16;
				first_mtu -= 16;
			}
			if unlikely((size_t)rsz + num_packets > 0x80000000) goto overflow;
			last = num_packets == 1;
			plen = last ? (unsigned)pad_len : first_mtu;
			packet = (struct _hv_send_packet*)_hv_alloc(sizeof(struct _hv_send_packet) + 4*(true_plen = header+plen+2) + (last && f_return_pipe ? 20+sizeof(uintptr_t) : 0));
			_hv_ram_packed_kex(s, state, packet->payload4+4);
		}
		total_size = pad_len + header + 2 + (num_packets-1)*(bypass ? 3 : 5);
		packet->payload4[true_plen-1] = htole32(len&0xffff);
		packet->payload4[true_plen-2] = htole32(len>>16);
		plen -= 2;
		packet->kex = 1;
		state->send_seq_hi = state->send_seq_lo = 0;
		assert(!ring_buffer_size(&state->send_queue));
		assert(!state->send_order_start);
	}
	seq_lo = state->send_seq_lo; seq_hi = state->send_seq_hi;
	pipe_last = _hv_find_pipe_last(state, to->id, le16toh(to->mtu_le), (uint32_t)seq_lo, &plch);
	if(plen) assert(!pipe_last); // if(kex)
	if(!rsz){
		state->rtt_gate_hi = 0;
		state->rtt_gate_lo = 8;
		state->last_ack = tim;
	}
	if likely(!plen){
		long_encoding = len >= 65535 || (uint32_t)state->send_seq_lo - pipe_last > (bypass ? 0xfe : 0xffff);
		unsigned needed = long_encoding ? 8 : 6;
		if(bypass) num_packets += (num_packets*mtu - pad_len) < needed;
		else if(extra < needed) num_packets += (num_packets*mtu - pad_len) < 16;
		total_size = pad_len + header + needed - 5 + (num_packets-1)*(bypass ? 3 : 5);
		if unlikely((size_t)rsz + num_packets > 0x80000000) overflow: {
			// Don't do this if coming from kex path (goto overflow;)
			if(!plen) _hv_add_to_send_pipe(state, to->id, plch.next, &plch.next, 0, &plch);
			_hv_time_lock_rel(&state->send_last_used, tim);
			if(f_return_pipe){
				struct _hv_tls_packet_detach d = {.packet_on_heap = SIZE_MAX};
				_hv_fire_pipe(s, f_return_pipe->id, (uint8_t*)errudata, (SIZE_MAX-63) | HIVEMIND_CLOSED_BACKPRESSURE, &d);
			}
			return;
		}
	}
	if(state->qd_bytes4 + total_size > (s->backpressure_limit>>2)) goto overflow;
	state->qd_bytes4 += total_size;
	if((state->send_seq_lo = seq_lo+num_packets) < seq_lo) state->send_seq_hi = seq_hi+1;
	ring_buffer_push_memset(&state->send_queue, 0, num_packets * sizeof(struct _hv_send_packet*), false);
	state->send_unlocked_ref++;
	_hv_time_lock_rel(&state->send_last_used, tim);

	if likely(!plen){
		unsigned needed = long_encoding ? 8 : 6;
		last = num_packets == 1;
		plen = last ? (unsigned)pad_len : mtu - (bypass ? needed : extra < needed ? 16 : 0);
		packet = (struct _hv_send_packet*)_hv_alloc(sizeof(struct _hv_send_packet) + 4*(true_plen = header+plen+needed-5) + (last && f_return_pipe ? 20+sizeof(uintptr_t) : 0));
		packet->kex = 0;
		packet->payload4[bypass ? 2 : 4] = htole32(seq_lo);
		packet->payload4[0] = htole32(seq_hi);
		packet->payload4[1] = htole32(seq_lo>>32);
		if(bypass){
			if(long_encoding){
				packet->payload4[true_plen-1] = htole32(0xffff0000 | len);
				packet->payload4[true_plen-2] = htole32(len>>16);
				packet->payload4[true_plen-3] = htole32(pipe_last);
			}else{ packet->payload4[true_plen-1] = htole32(len | ((uint32_t)seq_lo - pipe_last)<<16); }
		}else if(long_encoding){
			packet->payload4[true_plen-1] = htole32(0xffff0000 | len);
			packet->payload4[true_plen-2] = htole32(len >> 16);
			packet->payload4[true_plen-3] = htole32(pipe_last);
		}else{ packet->payload4[true_plen-1] = htole32(len<<16 | ((uint32_t)seq_lo - pipe_last)); }
		plen -= long_encoding ? 3 : 1;
	}
	struct _hv_send_packet** packets = (struct _hv_send_packet**)(num_packets <= 8 ? alloca(num_packets*sizeof(struct _hv_send_packet*)) : _hv_alloc(num_packets*sizeof(struct _hv_send_packet*))), **ppackets = packets;
	memcpy(packet->payload4+header-5, to->id, 20);
	packet->resent = 0; packet->first = 1; packet->has_err_fb = 0;
	uint8_t* p = (uint8_t*)(packet->payload4 + header);
	if(0) more: {
		last = pad_len <= (size_t)mtu;
		plen = last ? (unsigned)pad_len : mtu;
		header = bypass ? 3 : 5;
		packet = (struct _hv_send_packet*)_hv_alloc(sizeof(struct _hv_send_packet) + 4*(true_plen = header + plen) + (last && f_return_pipe ? 20+sizeof(uintptr_t) : 0));
		packet->first = packet->resent = packet->kex = 0; packet->has_err_fb = 0;
		p = (uint8_t*)(packet->payload4 + header);
		packet->payload4[header-1] = htole32(seq_lo);
		packet->payload4[0] = htole32(seq_hi);
		packet->payload4[1] = htole32(seq_lo>>32);
	}
	if(last){
		// last packet
		memset(p + len, 0, (plen<<2) - len);
		if(len) memcpy(p, msg, len);
	}else{
		memcpy(p, msg, (plen<<2));
		msg += (plen<<2); len -= (plen<<2);
	}
	pad_len -= plen;
	packet->len4 = true_plen;

	if(!++seq_lo) seq_hi++;
	if(ppackets != packets)
		(*(ppackets-1))->next = packet;
	*ppackets++ = packet;
	if(!last) goto more;

	if(f_return_pipe){
		packet->has_err_fb = 1;
		memcpy(packet->payload4+true_plen, f_return_pipe->id, 20);
		packet->payload4[true_plen+5] = errudata;
#if UINTPTR_MAX > UINT32_MAX
		packet->payload4[true_plen+6] = errudata>>32;
#endif
	}
	assert((size_t)(ppackets - packets) == num_packets);
	_hv_time_lock_acq(&state->send_last_used);
	if unlikely(!state->prevp){
		for(size_t i = 0; i < num_packets; i++) _hv_free(packets[i], _hv_packet_allocsz(packets[i]));
		_hv_time_lock_rel(&state->send_last_used, tim = _hv_internal_clock());
		len += (msg == omsg ? 0 /* avoid UB when msg==NULL */ : msg - omsg); msg = omsg;
		goto retry;
	}
	state->send_unlocked_ref--;
	size_t i = ring_buffer_size(&state->send_queue) + (seq_lo - state->send_seq_lo - num_packets)*sizeof(struct _hv_send_packet*);
	ring_buffer_set(&state->send_queue, i, packets, num_packets * sizeof(struct _hv_send_packet*), false);
	_hv_add_to_send_pipe(state, to->id, packets[0], &(*(ppackets-1))->next, total_size, &plch);
	tim = _hv_drain_writes(state, tim = _hv_internal_clock(), bypass);
	if(!atomic_load_explicit(&state->undrained_next, memory_order_relaxed)){
		struct _hv_remote* n = atomic_load_explicit(&_hv_meta.undrained, memory_order_relaxed);
		retry_acq2: atomic_store_explicit(&state->undrained_next, n, memory_order_relaxed);
		if(!atomic_compare_exchange_weak_explicit(&_hv_meta.undrained, &n, state, memory_order_acq_rel, memory_order_relaxed)) goto retry_acq2;
		x_event_queue_wake(&_hv_meta.queue, _HV_SEND_TICK);
	}
	_hv_time_lock_rel(&state->send_last_used, tim);
	if(num_packets > 8) _hv_free(packets, num_packets * sizeof(struct _hv_send_packet*));
}

void hivemind_quit(hivemind_server_t* s, hivemind_generic_fn_t on_close, hivemind_pipe_finish_fn_t pipe_finish){
	s->open_close_cb = on_close;
	s->finish_cb = pipe_finish;
	x_socket_t h = s->handle;
	if(atomic_load_explicit(&s->vq_flag, memory_order_acquire)){
		vqueue_post(&s->vq_block->q, vqueue_alloc(&s->vq_block->q, 0));
	}
	tsan_fence(memory_order_release);
	x_udp_close(h);
}

static const char b64_alphabet[64] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','_'};
// Parsing chars >= 128 as whatever they map to mod 128 is smelly but very slightly faster and non-base64 chars should not appear in pipe strings anyway (especially when the rest of the pipe is correct), if they do it's on you
static const uint8_t b64_alphabet2[128] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,62,0,62,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,63,0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0};
size_t hivemind_pipe_to_string(const hivemind_pipe_t* pipe, char out[HIVEMIND_PIPE_STR_MAX_LEN]){
	ip_to_string(pipe->addr, out);
	size_t i = strlen(out);
	uint16_t mtu = le16toh(pipe->mtu_le);
	snprintf(out+i, HIVEMIND_PIPE_STR_MAX_LEN-i, "/%u/%u/%llu/", le16toh(pipe->port_le), mtu&~3, (unsigned long long)le32toh(pipe->id[0])<<32 | ((unsigned long long)le32toh(pipe->id[1])&0xffffff));
	i += strlen(out+i+7)+7;
	uint8_t* rand = (uint8_t*)pipe->id + 7;
	for(int j = 0; j < 4; j++){
		uint32_t x = (uint32_t)(rand[j*3]<<16 | rand[j*3 + 1]<<8 | rand[j*3 + 2]);
		out[i++] = b64_alphabet[x>>18]; out[i++] = b64_alphabet[x>>12 & 63];
		out[i++] = b64_alphabet[x>>6 & 63]; out[i++] = b64_alphabet[x&63];
	}
	out[i++] = b64_alphabet[rand[12]>>2]; out[i++] = b64_alphabet[(rand[12]<<4)&63];
	out[i++] = 'A' + (mtu&3);
	out[i] = 0;
	return i;
}
bool hivemind_pipe_from_string(hivemind_pipe_t* pipe, const char in[HIVEMIND_PIPE_STR_MAX_LEN]){
	size_t len = strnlen(in, HIVEMIND_PIPE_STR_MAX_LEN);
	if(len >= HIVEMIND_PIPE_STR_MAX_LEN) return false;
	char str[HIVEMIND_PIPE_STR_MAX_LEN];
	memcpy(str, in, len+1);
	char* f = strchr(str, '/');
	if(!f) return false;
	size_t i = (size_t)(f-str);
	if(i >= len) return false;
	str[i] = '\0';
	pipe->addr = ip_from_string(str);
	unsigned port, mtu, off; unsigned long long tim;
	char id_b64[19], qos;
	if(sscanf(str+i+1, "%u/%u/%llu/%18s%c%n", &port, &mtu, &tim, id_b64, &qos, &off) != 4) return false;
	if((off+i+1) != len) return false;
	qos &= ~32; // cheap tolower
	pipe->port_le = htole16(port); pipe->mtu_le = htole16((mtu&~3) | (qos >= 'A' && qos <= 'D' ? qos-'A' : 0));
	for(int i = 0; i < 4; i++){
		uint32_t x = (uint32_t)(b64_alphabet2[id_b64[i<<2]&127]<<18 | b64_alphabet2[id_b64[i<<2 | 1]&127]<<12 | b64_alphabet2[id_b64[i<<2 | 2]&127]<<6 | b64_alphabet2[id_b64[i<<2 | 3]&127]);
		str[i*3 + 3] = (char)(x>>16); str[i*3 + 4] = (char)(x>>8); str[i*3 + 5] = (char)x;
	}
	str[15] = (char)(b64_alphabet2[id_b64[16]&127]<<2 | b64_alphabet2[id_b64[17]&127]>>4);
	memcpy(pipe->id+2, str+4, 12); // byte str+3 is copied manually
	pipe->id[0] = htole32(tim>>24);
	pipe->id[1] = htole32(tim&0xffffff | (uint32_t)str[3]<<24);
	return true;
}