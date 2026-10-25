#pragma once
#include "plumbing.c"

deprecated("Debug")
static void check_send(struct _hv_remote* state){
	bool bypass = state->bypass_type == 1;
	size_t sz = ring_buffer_size(&state->send_queue);
	if(!sz)
		assert(state->send_order_end == &state->send_order_start);
	uint32_t lo = state->send_seq_lo-sz/sizeof(struct _hv_send_packet*);
	for(size_t j = 0; j < sz; j += sizeof(struct _hv_send_packet*)){
		struct _hv_send_packet* v2;
		ring_buffer_get(&state->send_queue, j, &v2, sizeof(struct _hv_send_packet*), true);
		if(v2) assert(lo == _hv_lseqof((uintptr_t)v2 & 1 ? *(struct _hv_send_packet**)((uint8_t*)v2 - 1) : v2, bypass));
		lo++;
	}
}

deprecated("Debug")
static bool validate_ack(struct _hv_remote* state, uint64_t seq){
	size_t idx = (seq-state->recv_seq_lo);
	if(idx > SIZE_MAX/sizeof(uintptr_t)) return true;
	size_t sz = ring_buffer_size(&state->recv_queue);
	idx *= sizeof(uintptr_t);
	if(idx >= sz) return false;
	uintptr_t m;
	ring_buffer_get(&state->recv_queue, idx, &m, sizeof(m), true);
	return m;
}

static array_buffer_t logs;
#define logf(...) do{ \
	char* __out; int __len = asprintf(&__out, __VA_ARGS__); \
	array_buffer_push(&logs, __out, (size_t)__len); free(__out); \
}while(0);
static void _uncork_logs(void){
	fwrite(array_buffer_data(&logs), array_buffer_size(&logs), 1, stdout);
	array_buffer_destroy(&logs);
	memset(&logs, 0, sizeof(logs));
}
static void (*uncork_logs)(void) = _uncork_logs;