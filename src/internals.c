#pragma once
#include <a.h>
#include <string.h>
#include "x.h"
#include <time.h>
#include <stdatomic.h>
#include <alloca.h>
#include <polyutils.h>
#define VQUEUE_IMPL
#include <vqueue.h>
#define _HV_NO_STRUCT_DEFINITION
typedef struct hivemind_server hivemind_server_t;
#include <hivemind.h>

static_assert(CHAR_BIT == 8);

#define _hv_internal_clock() mono_now()

#define memcmp16(a, b) (((uint64_t)(a)[0]|(uint64_t)(a)[1]<<32) ^ ((uint64_t)(b)[0]|(uint64_t)(b)[1]<<32)) | \
	(((uint64_t)(a)[2]|(uint64_t)(a)[3]<<32) ^ ((uint64_t)(b)[2]|(uint64_t)(b)[3]<<32))

static inline void* _hv_alloc(size_t bytes){
	void* addr = malloc(bytes);
	if unlikely(!addr){
		fputs("hivemind: _hv_alloc(): Heap out of memory\n", stderr);
		abort();
	}
	assert(!((uintptr_t)addr&7)); // Aligned
	return addr;
}
static inline void* _hv_alloc_a(size_t bytes, size_t to){
	void* addr = aligned_alloc(to, bytes);
	if unlikely(!addr){
		fputs("hivemind: _hv_alloc(): Heap out of memory\n", stderr);
		abort();
	}
	return addr;
}
#define _HV_ALLOCATOR_SIZED 0
static inline void _hv_free(void* addr, size_t bytes){ free(addr); (void)bytes; }

// Used by hashmaps
static inline uint64_t _hv_mix64(uint64_t x){
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9u;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebu;
	x ^= x >> 31;
	return x;
}

static inline uint64_t _hv_mix64_addr(ip_addr_t addr, uint16_t port){
	return _hv_mix64(((uint64_t)addr.dwords[0]<<32|addr.dwords[1]) ^ _hv_mix64((uint64_t)addr.dwords[2]<<32|addr.dwords[3]) ^ (port * 0x9e3779b97f4a7c15ull));
}

struct _hv_send_packet{
	struct _hv_send_packet* next; // can be tagged before its in send order linked list (but not after)
	uint64_t len4:14, resent:1, first:1, kex:1, has_err_fb:1, time_lo:46;
	uint32_t payload4[];
};

#define _hv_packet_allocsz(p) (sizeof(struct _hv_send_packet) + ((p)->len4<<2) + ((p)->has_err_fb?20+sizeof(uintptr_t):0))

struct _hv_send_packet_placeholder{
	struct _hv_send_packet* next; // can be tagged
	struct _hv_send_packet** prevp; // not tagged
};

static inline uint32_t _hv_lseqof(struct _hv_send_packet* p, bool bypass){
	return p->kex ? 0 : le32toh(*(uint32_t*)(p->payload4+(bypass?2:4)));
}

#ifdef __SIZEOF_INT128__
typedef signed __int128 int128_t;
typedef unsigned __int128 uint128_t;
#endif

struct _hv_remote_vq{
	// Identical to start of struct _hv_remote
	uintptr_t next_;
	
	ip_addr_t addr; uint16_t port, server_mtu:14, bypass_type:2;
	atomic(uint32_t) ref;
	
	atomic(uint64_t) vq_last_used;
	struct _hv_remote** prevp;
	vqueue_t q;
};

struct _hv_send_pipe{
	void* next; // as is used by hash_table_t
	uint32_t id[5];
	uint32_t dependency_hi; uint64_t dependency_lo;
	size_t queued; // bytes>>2, highest 2 bits encode QoS instead
	struct _hv_send_packet *start, **end; // start can be tagged
};

struct _hv_remote{
	// Field order is specific and to avoid an entire cache line of wasted padding and reduce false sharing
	// This layout is optimized for 64 bit pointers and size_t.

	// == 1st cache line: infrequently written. This line needs to be quick to access across many threads since it's what's used to traverse the linked list ==

	// Linked list structure for use in linked list hashmaps
	struct _hv_remote* next;
	// Used as key in hashmaps
	ip_addr_t addr; uint16_t port, server_mtu:14, bypass_type:2;
#if SIZEOF_X_HANDLE <= 4
	x_socket_t handle;
#endif
	struct hivemind_server* server;
	// Back pointer for the bucket linked list
	struct _hv_remote** prevp;
	// 16B left
	
	// == 2-4th cache line: frequently written by send/drain logic ==
	// Timestamp when last packet was sent. Also used as a lock and init flag (1 = uninit, 0 = locked)
	// See _hv_time_lock_acq/_hv_time_lock_rel
	alignas(CACHE_LINE) atomic(uint64_t) send_last_used;
	// While unmasking a packet, or performing another expensive operation, it is not beneficial to unnecessarily hold on to the send_last_used lock. We temporarily release that lock, incrementing this value to make sure the remote is not GC'd in between. Since this value is only touched inside the lock, it does not need to be atomic
	uint32_t send_unlocked_ref;
	uint32_t send_seq_hi; uint64_t send_seq_lo; // Protocol sequence numbers
	// Linked list of undrained queues
	atomic(struct _hv_remote*) undrained_next;
	// send_key is moved to the first cache line to save 1 cache line on the struct size
	// It's infrequently written so this should be fine performance-wise
	
	// (Potentially hole-y) Ring buffer of send packets, one slot per sequence number. Slot 0 is sequence `send_seq_lo - size`, so any index derived from the size must be recomputed after the lock is released and reacquired (acks shift acked slots off the front)
	// `0` => Reserved, not in send_order (being built by hivemind_send, or currently being (re)sent with the lock released). Acks for these are ignored
	// `1` => Already acked (a hole; leading holes are shifted off the front)
	// `packet|2` => Queued in a pipe but not sent yet
	// otherwise => In the send_order linked list. The element is a pointer to &prev->next (or &send_order_start). This allows us to remove the packet from the linked list easily without making it a doubly linked list.
	ring_buffer_t send_queue;
	// Rolling window for tracking how many packets can be sent how fast in us
	uint64_t send_window;
	// ---
	// Linked list of all sent packets, in the order that they were last sent (and therefore the same order that they should be resent if needed).
	// `send_order_end` is not a pointer to the last packet but to the last packet's next field (or a pointer to `send_order_start` if the list is empty). `*send_order_end` should always be `NULL`
	struct _hv_send_packet *send_order_start, **send_order_end;

	size_t unsent_iter_i;
	hash_table_t pipes_with_unsent_b;
	array_buffer_t pipes_with_unsent;
	// 8B left
	

	// ---
	union{ uint32_t send_key[8]; uint64_t send_crcinit; }; // Derived local key for outgoing
	
	// Packed tightly for memory efficiency
	// `min_latency_when` -> When `min_latency` was achieved
	// `last_ack` -> When the last ack was received
	// rtt_gate = rtt_gate_lo|rtt_gate_hi<<16 -> Sequence number of when to start measuring latency deltas. We don't want to do this during the first RTT since that's when we're finding the min/average latency.
	// `rtt_gate == 0` -> No packets acked yet. When the first packet is acked, rtt_gate is set to the next unsent packet if any
	// `rtt_gate == seq<<1|1` -> Wait until this seq to start measuring latency deltas
	// `rtt_gate == 2` -> We are measuring latency deltas
	uint64_t min_latency_when:48, rtt_gate_lo:16; uint64_t last_ack:48, rtt_gate_hi:16;
	// Minimum latency that was captured somewhat recently
	// Average latency over some amount of RTTs
	// Microseconds per byte (inverse bandwidth), adjusted for growth rate
	// Growth rate, used to inflate `us_per_byte` to try sending faster when we thing more bandwidth may be available
	float min_latency, avg_latency, us_per_byte, growth;

	// == 5th-7th cache line: frequently written by recv logic ==
	// See send_last_used
	alignas(CACHE_LINE) atomic(uint64_t) recv_last_used;
	uint32_t recv_unlocked_ref; // See send_unlocked_ref
	uint32_t recv_seq_hi; uint64_t recv_seq_lo; // Protocol sequence numbers
	// Ring buffer of out-of-order-packets
	// cur_packet contains the currently-being-reconstructed packet, if any, and its length in cur_packet_left (if no packet is being reconstructed then cur_packet_left is undefined)
	// recv_queue[0] contains the head of the currently-being-reconstructed (head = where data is appended). This replaces what would otherwise certainly be a null (since the next packet that hasn't yet been received). If no packet is being reconstructed, then this is null (or if there are no packets in the queue then the queue is completely empty)
	ring_buffer_t recv_queue;
	// Key derivation timestamp to thwart replay attacks. Forgotten after state cutoff (all key derivations older than that window are rejected regardless)
	uint64_t key_derived_when;
	// ACK coalescing stuff
	// Linked list of all remotes with unsent acks
	atomic(struct _hv_remote*) unsent_ack_next;
	// ---
	uint32_t ack_coal_buf[15];
	// 4B left

	// ---
	// Derived local key for incoming packets (and to sign ACKs)
	union{ uint32_t recv_key[8]; uint64_t recv_crcinit; };
	// ACK coalescing stuff
	// ack_coal_i = current index in ack_coal_buf
	// ack_coal_tim0 = _hv_internal_clock() time for first ack, used to encode `dt`s in ack_coal_buf
	uint64_t ack_coal_tim0:56, ack_coal_i:8;
	// Buffer of coalesced acks. Up to 16 acks can be coalesced together (the 16th is stored in `_hv_queue_ack`'s stack when the buffer is found to be full). When the buffer is not full, the last element in this buffer is the low 32 bits of the ack's base sequence. All other values are packed `diff`s + `dt`s.
	size_t qd_bytes4;

	alignas(16) char unused_[16];
};
#define _HV_REMOTE_SIZE (sizeof(struct _hv_remote)-16)

// We don't need it to be 384 exactly but we wanna know if it ever jumps up
// In that case, either reshuffle fields to keep it same size or increase this assert to the new size
// Struct alignment >= CACHE_LINE so even a single poorly placed field can bump the size dramatically
static_assert(sizeof(struct _hv_remote) <= 448, "sizeof(_hv_remote) changed");

// Low 32 bits of the sequence number of send_queue's slot 0. Only valid until the send lock is released (or acks shift the queue)
static inline uint32_t _hv_send_base(struct _hv_remote* state){
	return (uint32_t)state->send_seq_lo - (uint32_t)(ring_buffer_size(&state->send_queue) / sizeof(struct _hv_send_packet*));
}
static inline size_t _hv_send_slot_b(struct _hv_send_packet* p, bool bypass, uint32_t base){
	return (size_t)(uint32_t)(_hv_lseqof(p, bypass) - base) * sizeof(struct _hv_send_packet*);
}
// _hv_send_slot(state, p, bypass[, base]) -> byte index of a packet's slot in send_queue
// Without `base` it is recomputed from state. The compiler can't do this for us: ring_buffer_set stores through a char* which may alias *state, so the size and send_seq_lo are reloaded after every set
#define _HV_SEND_SLOT_SEL(_1, _2, _3, _4, f, ...) f
#define _hv_send_slot(...) _HV_SEND_SLOT_SEL(__VA_ARGS__, _hv_send_slot4, _hv_send_slot3, _)(__VA_ARGS__)
#define _hv_send_slot3(state, p, bypass) _hv_send_slot_b(p, bypass, _hv_send_base(state))
#define _hv_send_slot4(state, p, bypass, base) _hv_send_slot_b(p, bypass, base)

static inline uint64_t _hv_send_pipe_hash(const uint32_t id[5]){
	return _hv_mix64((uint64_t)id[1]<<32|id[4])^_hv_mix64((uint64_t)id[2]<<32|id[3]);
}

// Remove the pipe at offset `off` (offset of the end of the element, as stored in the hash table) from its hash chain
static void _hv_unsent_unlink(struct _hv_remote* state, struct _hv_send_pipe* ps, size_t off){
	char* data = array_buffer_data(&state->pipes_with_unsent);
	uint64_t hash = _hv_send_pipe_hash(ps->id);
	size_t p = (size_t)hash_table_find(&state->pipes_with_unsent_b, hash);
	if(p == off){
		hash_table_put(&state->pipes_with_unsent_b, hash, ps->next);
		return;
	}
	while(p){
		struct _hv_send_pipe* p2 = (struct _hv_send_pipe*)(data + p) - 1;
		if((size_t)p2->next == off){
			p2->next = ps->next;
			return;
		}
		p = (size_t)p2->next;
	}
	assert(0, "Pipe not found in its hash chain");
}

// Placeholders at the head of a pipe point back into pipes_with_unsent. Call after the array may have moved
static void _hv_unsent_fix_placeholders(struct _hv_remote* state){
	size_t sz = array_buffer_size(&state->pipes_with_unsent);
	char* data = array_buffer_data(&state->pipes_with_unsent);
	for(size_t i = 0; i < sz; i += sizeof(struct _hv_send_pipe)){
		struct _hv_send_pipe* ps = (struct _hv_send_pipe*)(data+i);
		if((uintptr_t)ps->start & 1)
			((struct _hv_send_packet_placeholder*)((uintptr_t)ps->start-1))->prevp = &ps->start;
	}
}

struct _hv_pipe{
	atomic(uintptr_t) next;
	uint32_t id[5]; lock_t ref;
	void* udata;
};

struct _hv_vq{
	atomic(size_t) ref;
	vqueue_t q;
};

struct hivemind_server{
	union{
		struct{
			ip_addr_t addr;
			union{ struct{ uint16_t port_le, mtu_le; }; uint32_t port_mtu_packed_le; };
		};
		uint32_t dwords[5];
	};
	uint8_t encryption_bypass_prefix_v6, encryption_bypass_prefix_v4;
	uint8_t network_bypass_prefix_v6, network_bypass_prefix_v4;
	void* udata;
	uint64_t message_timeout;
	size_t backpressure_limit;
	hivemind_on_pipe_msg_fn_t on_msg;
	hivemind_generic_fn_t open_close_cb;
	hivemind_pipe_finish_fn_t finish_cb;
	uint32_t master_key[8];

#ifdef __SIZEOF_INT128__
	union{
		atomic(uint128_t) _id;
		char _rand_bytes[16];
	};
#else
	union{
		struct{ uint64_t _id_hi, _id_lo; };
		char _rand_bytes[16];
	};
	atomic_flag _id_lock;
#endif
	uint8_t buckets_exp, pipes_bucket_exp;
	atomic(uint8_t) vq_flag;
	shared_lock_t state_lock, pipes_lock;
	size_t remote_count;
	struct _hv_remote** remote_buckets;
	atomic(size_t) pipes_heap_i, deleted_pipes;
	atomic(uintptr_t)* pipes_data;
	atomic(hivemind_server_t*) next, *prevp;
	x_socket_t handle;
	uint32_t first_id[5];
	struct _hv_vq* vq_block;
	alignas(256) char end_[];
};

static_assert(sizeof(hivemind_server_t) == 256);

#ifdef __SIZEOF_INT128__
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Watomic-alignment"
	static void _hv_alloc_id(hivemind_server_t* s, uint32_t out[5], uint64_t t){
		uint128_t v = atomic_fetch_add_explicit(&s->_id, 1, memory_order_relaxed);
		out[0] = htole32(t>>24); out[1] = htole32(t&0xffffff|v>>96<<24);
		out[2] = htole32(v>>64); out[3] = htole32(v>>32);
		out[4] = htole32(v);
	}
	static void _hv_nalloc_id(hivemind_server_t* s, uint32_t out[5]){
		uint64_t t = epoch_now()/MILLISECOND_US;
		uint128_t v = atomic_load_explicit(&s->_id, memory_order_relaxed);
		out[0] = htole32(t>>24); out[1] = htole32(t&0xffffff|v>>96<<24);
		out[2] = htole32(v>>64); out[3] = htole32(v>>32);
		out[4] = htole32(v);
	}
	static inline uint64_t _hv_alloc_id_short(hivemind_server_t* s){
		uint64_t t = epoch_now()/MILLISECOND_US;
		uint64_t lo = (uint64_t)atomic_fetch_add_explicit(&s->_id, 1, memory_order_relaxed);
		return t<<8|(lo&0xff);
	}
	#pragma clang diagnostic pop
#else
	#warning No 16-byte atomic primitive detected. If they are available, consider compiling with appropriate flags, e.g -mcx16. Falling back to lock-based approach
	static void _hv_alloc_id(hivemind_server_t* s, uint32_t out[5], uint64_t t){
		uint8_t spin = 32;
		while(atomic_flag_test_and_set_explicit(&s->_id_lock, memory_order_acquire)) if(spin) spin--, thread_relax(); else thread_yield();
		uint64_t lo = s->_id_lo++, hi = s->_id_hi; if(lo == -1ull) s->_id_hi = hi+1;
		atomic_flag_clear_explicit(&s->_id_lock, memory_order_release);
		out[0] = htole32(t); out[1] = htole32(t<<8>>40|hi>>32<<24);
		out[2] = htole32(hi); out[3] = htole32(lo>>32);
		out[4] = htole32(lo);
	}
	static void _hv_nalloc_id(hivemind_server_t* s, uint32_t out[5]){
		uint64_t t = epoch_now()/MILLISECOND_US;
		uint8_t spin = 32;
		while(atomic_flag_test_and_set_explicit(&s->_id_lock, memory_order_acquire)) if(spin) spin--, thread_relax(); else thread_yield();
		uint64_t lo = s->_id_lo, hi = s->_id_hi;
		atomic_flag_clear_explicit(&s->_id_lock, memory_order_release);
		out[0] = htole32(t); out[1] = htole32(t<<8>>40|hi>>32<<24);
		out[2] = htole32(hi); out[3] = htole32(lo>>32);
		out[4] = htole32(lo);
	}
	static inline uint64_t _hv_alloc_id_short(hivemind_server_t* s){
		uint64_t t = epoch_now()/MILLISECOND_US;
		uint8_t spin = 32;
		while(atomic_flag_test_and_set_explicit(&s->_id_lock, memory_order_acquire)) if(spin) spin--, thread_relax(); else thread_yield();
		uint64_t lo = s->_id_lo++; if(lo == -1ull) s->_id_hi++;
		atomic_flag_clear_explicit(&s->_id_lock, memory_order_release);
		return t<<8|(lo&0xff);
	}
#endif

// Time-carrying lock. These locks are used both to protect a resource and signal when it was last used (for GC). States are:
// 0 = locked
// 1 = uninitialized (serves as a sentinel value for "never used before")
// >1 = unlocked and contains the time of last use. The time is updated on most lock releases (but not all, e.g if the lock was acquired but the resource wasn't "touched")
static inline uint64_t _hv_time_lock_acq(atomic(uint64_t)* ptr){
	uint64_t l;
	for(;;){
		l = atomic_exchange_explicit(ptr, 0, memory_order_acquire);
		if(l) return l;
		thread_yield();
	}
}
static inline uint64_t _hv_time_lock_try_acq(atomic(uint64_t)* ptr){
	return atomic_exchange_explicit(ptr, 0, memory_order_acquire);
}
// Peek at the value of a time lock without acquiring it. See `_hv_time_lock_acq`
static inline uint64_t _hv_time_lock_peek(atomic(uint64_t)* ptr){
	uint64_t l;
	for(;;){
		l = atomic_load_explicit(ptr, memory_order_acquire);
		if(l) return l;
		thread_yield();
	}
}
// Release a time lock and set the last used time. See `_hv_time_lock_acq`
static inline void _hv_time_lock_rel(atomic(uint64_t)* ptr, uint64_t l){
	atomic_store_explicit(ptr, l, memory_order_release);
}

static void _hv_time_lock_acq_excl(atomic(uint64_t)* ptr, uint32_t* ref){
	uint64_t l = _hv_time_lock_acq(ptr);
	if(!*ref) return;
	*ref |= 0x80000000;
	retry:
	_hv_time_lock_rel(ptr, l);
	thread_yield();
	_hv_time_lock_acq(ptr);
	if(*ref & 0x7fffffff) goto retry;
	*ref = 0;
}

#define _HV_SEND_BURST 6000
#define _HV_SEND_TICK 2000 // 2ms in useconds
#define _HV_STATE_LIFETIME 14400000000 // 4h in useconds

// Resolve a 96-bit sequence number from the low 32 bits and a reference sequence number
// The returned sequence number is within +/- 2^31 of the reference sequence number
static inline void _hv_resolve_seq(uint64_t* lo, uint32_t* hi, uint32_t seq){
	uint64_t lo1 = *lo, lo2 = (lo1 & 0xffffffff00000000) | seq;
	*lo = lo2 + ((lo2-lo1+(0x80000000))&0xffffffff00000000);
	*hi += (lo2>>32)-(lo1>>32);
}

struct _hv_packet_reassembly{
	size_t total; union{ size_t cur; uint32_t pipe_next; };
	uint32_t pipe_last;
	uint32_t pipe[5];
	uint8_t data[];
};

static inline void _hv_remote_cleanup_recv(struct _hv_remote* state, bool bypass){
	ring_iterator_t it = ring_buffer_iterator(&state->recv_queue, 0, SIZE_MAX);
	uintptr_t ptr;
	while(ring_iterator_next(&it, &ptr, sizeof(ptr), true)){
		if(ptr <= 3) continue;
		if(!(ptr&3)) _hv_free((void*)ptr, sizeof(struct _hv_packet_reassembly) + ((struct _hv_packet_reassembly*)ptr)->total);
		else if((ptr&3)==2) free((uint8_t*)(ptr - 2 - (bypass ? 12 : 20)));
	}
	ring_buffer_destroy(&state->recv_queue);
	state->recv_queue = (ring_buffer_t){};
}

static void _hv_remote_cleanup_send(struct _hv_remote* state){
	struct _hv_send_packet* p = state->send_order_start;
	while(p){
		struct _hv_send_packet* p2 = p->next;
		_hv_free(p, _hv_packet_allocsz(p)); p = p2;
	}
	state->send_order_start = 0; state->send_order_end = &state->send_order_start;
	state->send_window = 0;
	ring_buffer_destroy(&state->send_queue);
	state->send_queue = (ring_buffer_t){};

	size_t sz = array_buffer_size(&state->pipes_with_unsent);
	char* unsent_data = array_buffer_data(&state->pipes_with_unsent);
	for(size_t i = 0; i < sz; i += sizeof(struct _hv_send_pipe)){
		struct _hv_send_pipe* ps = (struct _hv_send_pipe*)(unsent_data+i);
		struct _hv_send_packet* packet = ps->next;
		while(packet){
			if((uintptr_t)packet & 1){
				struct _hv_send_packet_placeholder* p2 = (struct _hv_send_packet_placeholder*)((char*)packet - 1);
				packet = p2->next;
			}else{
				struct _hv_send_packet* p2 = packet->next;
				_hv_free(packet, _hv_packet_allocsz(packet));
				packet = p2;
			}
		}
	}
	array_buffer_destroy(&state->pipes_with_unsent);
	memset(&state->pipes_with_unsent, 0, sizeof(state->pipes_with_unsent));
	hash_table_set_rank(&state->pipes_with_unsent_b, 0);
	state->qd_bytes4 = 0;
}