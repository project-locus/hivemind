// ./test.sh utils
// clang -g -Og -fsanitize=address,undefined -I../include utils.c -o test.out && ./test.out [seed]; rm test.out
// clang -DFUZZ_ITERS=5000000 -O3 -I../include utils.c -o test.out && ./test.out [seed]; rm test.out

#include <stdio.h>
#include "../src/utils.h"

#ifndef FUZZ_ITERS
#define FUZZ_ITERS 200000
#endif
#ifndef LOCK_THREADS
#define LOCK_THREADS 8
#endif
#ifndef LOCK_ITERS
#define LOCK_ITERS 200000
#endif

static uint64_t failed = 0, passed = 0;
static uint64_t seed;

#define CHECK(cond, ...) (likely(cond) ? (void)passed++ : (void)(failed++, \
	printf("\x1b[31m%s:%d: CHECK(%s) failed: \x1b[m", __FILE__, __LINE__, #cond), printf(__VA_ARGS__), printf("\n")))
// Like CHECK but bails out of the enclosing function, so that one fuzz divergence doesn't produce thousands of lines
#define FCHECK(cond, ...) do{ if unlikely(!(cond)){ failed++; \
	printf("\x1b[31m%s:%d: CHECK(%s) failed at iteration %zu: \x1b[m", __FILE__, __LINE__, #cond, iter); \
	printf(__VA_ARGS__); printf("\n"); return; } passed++; }while(0)

static uint64_t rng_state;
static inline uint64_t rnd(void){
	// xorshift64*
	uint64_t x = rng_state;
	x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
	rng_state = x;
	return x * 0x2545f4914f6cdd1dull;
}
// Uniform-ish in [0, n)
static inline size_t rnd_n(size_t n){ return n ? (size_t)(rnd() % n) : 0; }
// Biased towards small sizes but occasionally large, to exercise both inline storage and heap growth
static inline size_t rnd_len(size_t max){
	size_t r;
	switch(rnd()&3){
		case 0: r = rnd_n(9); break;
		case 1: r = rnd_n(33); break;
		case 2: r = rnd_n(257); break;
		default: r = rnd_n(4097); break;
	}
	return r > max ? max : r;
}
static void rnd_bytes(void* p, size_t n){
	for(size_t i = 0; i < n; i++) ((uint8_t*)p)[i] = (uint8_t)rnd();
}

/* ==================== size_magn ==================== */

static void test_size_magn(void){
	CHECK(size_magn(1) == 1, "%zu", size_magn(1));
	CHECK(size_magn(2) == 2, "%zu", size_magn(2));
	CHECK(size_magn(3) == 2, "%zu", size_magn(3));
	CHECK(size_magn(7) == 3, "%zu", size_magn(7));
	CHECK(size_magn(8) == 4, "%zu", size_magn(8));
	CHECK(size_magn(31) == 5, "%zu", size_magn(31));
	CHECK(size_magn(SIZE_MAX) == sizeof(size_t)*CHAR_BIT, "%zu", size_magn(SIZE_MAX));
	for(unsigned b = 0; b < sizeof(size_t)*CHAR_BIT; b++){
		size_t x = (size_t)1 << b;
		CHECK(size_magn(x) == b+1, "size_magn(1<<%u) = %zu", b, size_magn(x));
		CHECK(size_magn(x|(x-1)) == b+1, "size_magn((2<<%u)-1) = %zu", b, size_magn(x|(x-1)));
	}
	size_t iter = 0;
	for(; iter < 100000; iter++){
		size_t x = (size_t)rnd() >> rnd_n(sizeof(size_t)*CHAR_BIT); if(!x) x = 1;
		size_t m = size_magn(x);
		FCHECK(m >= 1 && m <= sizeof(size_t)*CHAR_BIT && (x >> (m-1)) == 1, "size_magn(%zu) = %zu", x, m);
	}
}

/* ==================== fast/discrete exp2/log2 ==================== */

static void test_math(void){
	// Exact at integers
	for(int i = -60; i <= 60; i++){
		CHECK(fast_exp2f((float)i) == ldexpf(1.f, i), "fast_exp2f(%d) = %g", i, fast_exp2f((float)i));
		CHECK(discrete_exp2f((float)i) == ldexpf(1.f, i), "discrete_exp2f(%d) = %g", i, discrete_exp2f((float)i));
		CHECK(discrete_log2f(ldexpf(1.f, i)) == (float)i, "discrete_log2f(2^%d) = %g", i, discrete_log2f(ldexpf(1.f, i)));
	}
	float max_fast = 0, max_disc = 0, max_log = 0;
	size_t iter = 0;
	for(; iter < 1000000; iter++){
		float x = (float)((double)(rnd()>>11) * 0x1p-53 * 120. - 60.);
		float ref = exp2f(x);
		float rf = fabsf(fast_exp2f(x)/ref - 1.f), rd = fabsf(discrete_exp2f(x)/ref - 1.f);
		if(rf > max_fast) max_fast = rf;
		if(rd > max_disc) max_disc = rd;
		FCHECK(rf <= 0.00206f, "fast_exp2f(%.9g) = %.9g, exp2f = %.9g (rel err %g)", x, fast_exp2f(x), ref, rf);
		FCHECK(rd <= 0.0616f, "discrete_exp2f(%.9g) = %.9g, exp2f = %.9g (rel err %g)", x, discrete_exp2f(x), ref, rd);
		// discrete_exp2f only ever underestimates (chord below the convex curve)
		FCHECK(discrete_exp2f(x) >= ref*0.999999f, "discrete_exp2f(%.9g) = %.9g > exp2f = %.9g", x, discrete_exp2f(x), ref);
		// discrete_log2f is the exact inverse of discrete_exp2f
		float back = discrete_log2f(discrete_exp2f(x));
		FCHECK(fabsf(back - x) <= 1e-5f*fmaxf(1.f, fabsf(x)), "discrete_log2f(discrete_exp2f(%.9g)) = %.9g", x, back);
		// discrete_log2f vs log2f: max abs error is max(log2(1+t)-t) ~= 0.0861
		float y = ref, le = fabsf(discrete_log2f(y) - log2f(y));
		if(le > max_log) max_log = le;
		FCHECK(le <= 0.0862f, "discrete_log2f(%.9g) = %.9g, log2f = %.9g", y, discrete_log2f(y), log2f(y));
	}
	// Monotonicity on a fine grid
	iter = 0;
	float pf = fast_exp2f(-30.f), pd = discrete_exp2f(-30.f), pl = discrete_log2f(0x1p-30f);
	for(float x = -30.f; x <= 30.f; x += 1.f/1024, iter++){
		float f = fast_exp2f(x), d = discrete_exp2f(x), l = discrete_log2f(exp2f(x));
		FCHECK(f >= pf && d >= pd && l >= pl, "non-monotonic at x=%.9g", x);
		pf = f; pd = d; pl = l;
	}
	printf("  fast_exp2f max rel err %.5f%%, discrete_exp2f max rel err %.3f%%, discrete_log2f max abs err %.5f\n", max_fast*100, max_disc*100, max_log);
}

/* ==================== ring_buffer_t ==================== */

static size_t ring_cap(ring_buffer_t* rb){ return rb->cap_exp ? (size_t)1 << rb->cap_exp : sizeof(char*); }

static void test_ring_buffer_unit(void){
	ring_buffer_t rb = {0};
	CHECK(ring_buffer_size(&rb) == 0, "%zu", ring_buffer_size(&rb));
	// Inline storage
	ring_buffer_push(&rb, "abcd", 4, false);
	CHECK(rb.cap_exp == 0 && ring_buffer_size(&rb) == 4, "cap_exp=%u size=%zu", (unsigned)rb.cap_exp, ring_buffer_size(&rb));
	char out[64] = {0};
	ring_buffer_shift(&rb, out, 2, false);
	CHECK(!memcmp(out, "ab", 2) && ring_buffer_size(&rb) == 2, "%.2s", out);
	// Wrap around within inline storage
	ring_buffer_push(&rb, "efghij", 6, false);
	CHECK(rb.cap_exp == 0 && ring_buffer_size(&rb) == 8, "cap_exp=%u", (unsigned)rb.cap_exp);
	ring_buffer_get(&rb, 0, out, 8, false);
	CHECK(!memcmp(out, "cdefghij", 8), "%.8s", out);
	// Grow out of inline storage while wrapped
	ring_buffer_push(&rb, "k", 1, false);
	CHECK(rb.cap_exp == 5 && ring_buffer_size(&rb) == 9, "cap_exp=%u", (unsigned)rb.cap_exp);
	ring_buffer_get(&rb, 0, out, 9, false);
	CHECK(!memcmp(out, "cdefghijk", 9), "%.9s", out);
	ring_buffer_set(&rb, 1, "XY", 2, false);
	ring_buffer_get(&rb, 0, out, 9, false);
	CHECK(!memcmp(out, "cXYfghijk", 9), "%.9s", out);
	ring_buffer_push_memset(&rb, 'z', 3, false);
	size_t off = ring_buffer_push_garbage(&rb, 2, false);
	CHECK(off == 12, "%zu", off);
	ring_buffer_set(&rb, off, "!?", 2, false);
	ring_buffer_get(&rb, 0, out, 14, false);
	CHECK(!memcmp(out, "cXYfghijkzzz!?", 14), "%.14s", out);
	// Shrink back to inline
	ring_buffer_shift_discard(&rb, 8, false);
	CHECK(rb.cap_exp == 0 && ring_buffer_size(&rb) == 6, "cap_exp=%u size=%zu", (unsigned)rb.cap_exp, ring_buffer_size(&rb));
	ring_buffer_get(&rb, 0, out, 6, false);
	CHECK(!memcmp(out, "kzzz!?", 6), "%.6s", out);
	ring_buffer_reserve(&rb, 1000);
	CHECK(ring_cap(&rb) >= 1000 && ring_buffer_size(&rb) == 6, "cap=%zu", ring_cap(&rb));
	ring_buffer_get(&rb, 0, out, 6, false);
	CHECK(!memcmp(out, "kzzz!?", 6), "%.6s", out);
	ring_buffer_destroy(&rb);

	// Iterator over aligned 8-byte elements, including across the wrap point. `while(next)` must visit every element
	memset(&rb, 0, sizeof(rb));
	for(uint64_t i = 0; i < 4; i++) ring_buffer_push(&rb, &i, 8, true);
	for(uint64_t i = 0; i < 2; i++){ uint64_t v; ring_buffer_shift(&rb, &v, 8, true); }
	for(uint64_t i = 4; i < 6; i++) ring_buffer_push(&rb, &i, 8, true); // 2..5, wraps (cap 32)
	CHECK(rb.cap_exp == 5 && rb.l == 16, "cap_exp=%u l=%zu", (unsigned)rb.cap_exp, (size_t)rb.l);
	ring_iterator_t it = ring_buffer_iterator(&rb, 0, SIZE_MAX);
	uint64_t v, expect = 2; int count = 0;
	while(ring_iterator_next(&it, &v, 8, true)){
		CHECK(v == expect, "got %llu expected %llu", (unsigned long long)v, (unsigned long long)expect);
		expect++; count++;
	}
	CHECK(count == 4, "while(ring_iterator_next(...)) visited %d of 4 elements", count);
	CHECK(!ring_iterator_next(&it, &v, 8, true), "iterator not exhausted");
	// Empty iterator
	it = ring_buffer_iterator(&rb, 32, 10);
	CHECK(!ring_iterator_next(&it, &v, 8, true), "empty iterator yielded");
	ring_buffer_destroy(&rb);
}

#define RING_MAX 65536
static uint8_t ring_ref[RING_MAX*2], ring_tmp[RING_MAX*2], ring_in[RING_MAX];

static void ring_check_all(ring_buffer_t* rb, size_t ref_len, size_t iter, int* bad){
	*bad = 1;
	FCHECK(ring_buffer_size(rb) == ref_len, "size %zu != ref %zu", ring_buffer_size(rb), ref_len);
	size_t cap = ring_cap(rb);
	FCHECK(!(cap&(cap-1)) && cap >= ref_len && rb->l < cap, "cap=%zu l=%zu size=%zu", cap, (size_t)rb->l, ref_len);
	if(ref_len) ring_buffer_get(rb, 0, ring_tmp, ref_len, false);
	FCHECK(!memcmp(ring_tmp, ring_ref, ref_len), "contents diverged (size=%zu, cap=%zu, l=%zu)", ref_len, cap, (size_t)rb->l);
	*bad = 0;
}

// Byte-granular (unaligned) fuzz against a flat reference queue
static void fuzz_ring_buffer_bytes(void){
	ring_buffer_t rb = {0};
	size_t len = 0, iter = 0;
	int bad = 0;
	for(; iter < FUZZ_ITERS; iter++){
		unsigned op = (unsigned)rnd_n(10);
		// Keep the size bounded by favoring removal when large
		if(len > RING_MAX/2 && op < 4) op += 4;
		switch(op){
		case 0: case 1: { // push
			size_t n = rnd_len(RING_MAX - len);
			rnd_bytes(ring_in, n);
			ring_buffer_push(&rb, ring_in, n, false);
			memcpy(ring_ref+len, ring_in, n); len += n;
		} break;
		case 2: { // push_memset
			size_t n = rnd_len(RING_MAX - len); char c = (char)rnd();
			ring_buffer_push_memset(&rb, c, n, false);
			memset(ring_ref+len, c, n); len += n;
		} break;
		case 3: { // push_garbage + set
			size_t n = rnd_len(RING_MAX - len);
			size_t at = ring_buffer_push_garbage(&rb, n, false);
			FCHECK(at == len, "push_garbage returned %zu, expected %zu", at, len);
			rnd_bytes(ring_in, n);
			if(n) ring_buffer_set(&rb, at, ring_in, n, false);
			memcpy(ring_ref+len, ring_in, n); len += n;
		} break;
		case 4: case 5: { // shift
			size_t n = rnd_len(len);
			ring_buffer_shift(&rb, ring_tmp, n, false);
			FCHECK(!memcmp(ring_tmp, ring_ref, n), "shift(%zu) returned wrong bytes", n);
			memmove(ring_ref, ring_ref+n, len-n); len -= n;
		} break;
		case 6: { // shift_discard
			size_t n = rnd_len(len);
			ring_buffer_shift_discard(&rb, n, false);
			memmove(ring_ref, ring_ref+n, len-n); len -= n;
		} break;
		case 7: { // get (random range)
			size_t i = rnd_n(len+1), n = rnd_len(len-i);
			if(n) ring_buffer_get(&rb, i, ring_tmp, n, false);
			FCHECK(!memcmp(ring_tmp, ring_ref+i, n), "get(%zu, %zu) returned wrong bytes", i, n);
		} break;
		case 8: { // set (random range)
			size_t i = rnd_n(len+1), n = rnd_len(len-i);
			rnd_bytes(ring_in, n);
			if(n) ring_buffer_set(&rb, i, ring_in, n, false);
			memcpy(ring_ref+i, ring_in, n);
		} break;
		case 9: { // reserve
			size_t n = rnd_len(RING_MAX);
			ring_buffer_reserve(&rb, n);
			FCHECK(ring_cap(&rb) >= n, "reserve(%zu) gave cap %zu", n, ring_cap(&rb));
		} break;
		}
		ring_check_all(&rb, len, iter, &bad);
		if(bad) break;
	}
	ring_buffer_destroy(&rb);
}

// Byte-granular iterator fuzz: iterate a random window in random-sized (unaligned) chunks
static void fuzz_ring_iterator_bytes(void){
	size_t iter = 0;
	for(; iter < FUZZ_ITERS/20; iter++){
		ring_buffer_t rb = {0};
		// Build a buffer with a random head offset so the data wraps
		size_t pre = rnd_len(512), len = rnd_len(2048);
		ring_buffer_push_memset(&rb, 0, pre, false);
		rnd_bytes(ring_ref, len);
		ring_buffer_push(&rb, ring_ref, len, false);
		ring_buffer_shift_discard(&rb, pre, false);
		ring_buffer_push(&rb, ring_ref, 0, false);
		size_t i = rnd_n(len+1), count = rnd_n(len+16);
		size_t expect = count > len-i ? len-i : count;
		ring_iterator_t it = ring_buffer_iterator(&rb, i, count);
		size_t got = 0;
		while(got < expect){
			size_t n = 1+rnd_n(expect-got < 64 ? expect-got : 64);
			ring_iterator_next(&it, ring_tmp+got, n, false);
			FCHECK(!memcmp(ring_tmp+got, ring_ref+i+got, n), "iterator chunk [%zu,+%zu) of window [%zu,+%zu) wrong (cap=%zu, l=%zu)", got, n, i, expect, ring_cap(&rb), (size_t)rb.l);
			got += n;
		}
		uint8_t dummy;
		FCHECK(!ring_iterator_next(&it, &dummy, 1, false), "iterator yielded past end of window [%zu,+%zu)", i, expect);
		ring_buffer_destroy(&rb);
	}
}

// Element-granular (aligned) fuzz with 8-byte elements, matching how the library uses the ring buffer
static void fuzz_ring_buffer_aligned(void){
	ring_buffer_t rb = {0};
	uint64_t* ref = (uint64_t*)ring_ref;
	size_t len = 0, iter = 0; // len in elements
	const size_t MAXE = RING_MAX/8;
	int bad = 0;
	for(; iter < FUZZ_ITERS; iter++){
		unsigned op = (unsigned)rnd_n(9);
		if(len > MAXE/2 && op < 3) op += 3;
		switch(op){
		case 0: case 1: { // push n elements one by one
			size_t n = rnd_len(MAXE - len);
			for(size_t k = 0; k < n; k++){ uint64_t v = rnd(); ring_buffer_push(&rb, &v, 8, true); ref[len++] = v; }
		} break;
		case 2: { // push_memset
			if(len >= MAXE) break;
			char c = (char)rnd();
			ring_buffer_push_memset(&rb, c, 8, true);
			memset(ref+len, c, 8); len++;
		} break;
		case 3: case 4: { // shift
			size_t n = rnd_len(len);
			for(size_t k = 0; k < n; k++){
				uint64_t v; ring_buffer_shift(&rb, &v, 8, true);
				FCHECK(v == ref[k], "shift element %zu: %llx != %llx", k, (unsigned long long)v, (unsigned long long)ref[k]);
			}
			memmove(ref, ref+n, (len-n)*8); len -= n;
		} break;
		case 5: { // shift_discard
			size_t n = rnd_len(len);
			for(size_t k = 0; k < n; k++) ring_buffer_shift_discard(&rb, 8, true);
			memmove(ref, ref+n, (len-n)*8); len -= n;
		} break;
		case 6: { // get/set random element
			if(!len) break;
			size_t i = rnd_n(len); uint64_t v;
			ring_buffer_get(&rb, i*8, &v, 8, true);
			FCHECK(v == ref[i], "get element %zu: %llx != %llx", i, (unsigned long long)v, (unsigned long long)ref[i]);
			v = rnd(); ring_buffer_set(&rb, i*8, &v, 8, true); ref[i] = v;
		} break;
		case 7: case 8: { // iterate a random window
			size_t i = rnd_n(len+1), count = rnd_n(len+2);
			size_t expect = count > len-i ? len-i : count;
			ring_iterator_t it = ring_buffer_iterator(&rb, i*8, count*8);
			uint64_t v; size_t k = 0;
			for(; k < expect; k++){
				ring_iterator_next(&it, &v, 8, true);
				FCHECK(v == ref[i+k], "iterator element %zu of window [%zu,+%zu): %llx != %llx", k, i, expect, (unsigned long long)v, (unsigned long long)ref[i+k]);
			}
			FCHECK(!ring_iterator_next(&it, &v, 8, true), "iterator yielded past end of window [%zu,+%zu)", i, expect);
		} break;
		}
		ring_check_all(&rb, len*8, iter, &bad);
		if(bad) break;
	}
	ring_buffer_destroy(&rb);
}

/* ==================== array_buffer_t ==================== */

static size_t array_cap(array_buffer_t* ab){ return ab->cap_exp ? (size_t)1 << ab->cap_exp : sizeof(char*); }

static void test_array_buffer_unit(void){
	array_buffer_t ab = {0};
	char out[64] = {0};
	CHECK(array_buffer_size(&ab) == 0 && array_buffer_data(&ab) == ab.data_i, "empty array_buffer_t");
	array_buffer_push(&ab, "abcdef", 6);
	CHECK(ab.cap_exp == 0 && !memcmp(array_buffer_data(&ab), "abcdef", 6), "inline push");
	array_buffer_push_memset(&ab, 'x', 4);
	CHECK(ab.cap_exp == 5 && array_buffer_size(&ab) == 10 && !memcmp(array_buffer_data(&ab), "abcdefxxxx", 10), "grow");
	char* g = (char*)array_buffer_push_garbage(&ab, 2);
	CHECK(g == (char*)array_buffer_data(&ab)+10, "push_garbage pointer");
	memcpy(g, "!?", 2);
	array_buffer_set(&ab, 0, "AB", 2);
	array_buffer_get(&ab, 0, out, 12);
	CHECK(!memcmp(out, "ABcdefxxxx!?", 12), "%.12s", out);
	array_buffer_setsize_garbage(&ab, 3);
	CHECK(ab.cap_exp == 0 && array_buffer_size(&ab) == 3 && !memcmp(array_buffer_data(&ab), "ABc", 3), "setsize shrink to inline");
	array_buffer_setsize_garbage(&ab, 100);
	CHECK(array_cap(&ab) >= 100 && !memcmp(array_buffer_data(&ab), "ABc", 3), "setsize grow");
	array_buffer_pop_discard(&ab, 97);
	CHECK(ab.cap_exp == 0 && array_buffer_size(&ab) == 3 && !memcmp(array_buffer_data(&ab), "ABc", 3), "pop_discard shrink");
	array_buffer_reserve(&ab, 500);
	CHECK(array_cap(&ab) >= 500 && array_buffer_size(&ab) == 3 && !memcmp(array_buffer_data(&ab), "ABc", 3), "reserve");
	array_buffer_destroy(&ab);

	// pop takes from the end (stack order), both inline and on the heap
	memset(&ab, 0, sizeof(ab));
	array_buffer_push(&ab, "abcd", 4);
	memset(out, 0, sizeof(out));
	array_buffer_pop(&ab, out, 1);
	CHECK(out[0] == 'd' && array_buffer_size(&ab) == 3, "inline pop returned '%c'", out[0]);
	array_buffer_push(&ab, "0123456789abcdefghijklmnopqrstuvwxyz", 36);
	array_buffer_pop(&ab, out, 2);
	CHECK(!memcmp(out, "yz", 2) && array_buffer_size(&ab) == 37, "heap pop returned \"%.2s\"", out);
	array_buffer_destroy(&ab);

	// Iterator. `while(next)` must visit every element
	memset(&ab, 0, sizeof(ab));
	for(uint64_t i = 0; i < 5; i++) array_buffer_push(&ab, &i, 8);
	array_iterator_t it = array_buffer_iterator(&ab, 8, SIZE_MAX);
	uint64_t v, expect = 1; int count = 0;
	// count bound keeps a broken end condition from reading past the allocation
	while(array_iterator_next(&it, &v, 8)){
		CHECK(v == expect, "got %llu expected %llu", (unsigned long long)v, (unsigned long long)expect);
		expect++; count++;
	}
	CHECK(count == 4, "while(array_iterator_next(...)) visited %d of 4 elements", count);
	array_buffer_destroy(&ab);
}

#define ARRAY_MAX 65536
static void fuzz_array_buffer(void){
	array_buffer_t ab = {0};
	static uint8_t ref[ARRAY_MAX], tmp[ARRAY_MAX], in[ARRAY_MAX];
	size_t len = 0, iter = 0;
	for(; iter < FUZZ_ITERS; iter++){
		unsigned op = (unsigned)rnd_n(11);
		if(len > ARRAY_MAX/2 && op < 4) op += 4;
		switch(op){
		case 0: case 1: { // push
			size_t n = rnd_len(ARRAY_MAX - len);
			rnd_bytes(in, n);
			array_buffer_push(&ab, in, n);
			memcpy(ref+len, in, n); len += n;
		} break;
		case 2: { // push_memset
			size_t n = rnd_len(ARRAY_MAX - len); int c = (uint8_t)rnd();
			array_buffer_push_memset(&ab, c, n);
			memset(ref+len, c, n); len += n;
		} break;
		case 3: { // push_garbage, write through the returned pointer
			size_t n = rnd_len(ARRAY_MAX - len);
			uint8_t* p = (uint8_t*)array_buffer_push_garbage(&ab, n);
			FCHECK(p == (uint8_t*)array_buffer_data(&ab)+len, "push_garbage returned wrong pointer");
			rnd_bytes(p, n);
			memcpy(ref+len, p, n); len += n;
		} break;
		case 4: case 5: { // pop_discard
			size_t n = rnd_len(len);
			array_buffer_pop_discard(&ab, n);
			len -= n;
		} break;
		case 6: { // setsize_garbage (grow and fill, or shrink)
			size_t n = rnd_len(ARRAY_MAX);
			array_buffer_setsize_garbage(&ab, n);
			if(n > len){
				rnd_bytes(in, n-len);
				array_buffer_set(&ab, len, in, n-len);
				memcpy(ref+len, in, n-len);
			}
			len = n;
		} break;
		case 7: { // get
			size_t i = rnd_n(len+1), n = rnd_len(len-i);
			array_buffer_get(&ab, i, tmp, n);
			FCHECK(!memcmp(tmp, ref+i, n), "get(%zu, %zu) returned wrong bytes", i, n);
		} break;
		case 8: { // set
			size_t i = rnd_n(len+1), n = rnd_len(len-i);
			rnd_bytes(in, n);
			array_buffer_set(&ab, i, in, n);
			memcpy(ref+i, in, n);
		} break;
		case 9: { // iterate a random window in random-sized chunks
			size_t i = rnd_n(len+1), count = rnd_n(len+16);
			size_t expect = count > len-i ? len-i : count, got = 0;
			array_iterator_t it = array_buffer_iterator(&ab, i, count);
			FCHECK(it.remaining == expect, "iterator remaining %zu != %zu", it.remaining, expect);
			while(got < expect){
				size_t n = 1+rnd_n(expect-got < 64 ? expect-got : 64);
				array_iterator_next(&it, tmp+got, n);
				FCHECK(!memcmp(tmp+got, ref+i+got, n), "iterator chunk [%zu,+%zu) of window [%zu,+%zu) wrong", got, n, i, expect);
				got += n;
			}
		} break;
		case 10: { // reserve
			size_t n = rnd_len(ARRAY_MAX);
			array_buffer_reserve(&ab, n);
			FCHECK(array_cap(&ab) >= n, "reserve(%zu) gave cap %zu", n, array_cap(&ab));
		} break;
		}
		size_t cap = array_cap(&ab);
		FCHECK(array_buffer_size(&ab) == len, "size %zu != ref %zu", array_buffer_size(&ab), len);
		FCHECK(!(cap&(cap-1)) && cap >= len, "cap=%zu size=%zu", cap, len);
		FCHECK(!memcmp(array_buffer_data(&ab), ref, len), "contents diverged (size=%zu, cap=%zu)", len, cap);
	}
	array_buffer_destroy(&ab);
}

/* ==================== hash_table_t ==================== */

static void test_hash_table(void){
	hash_table_t t = {0};
	CHECK(hash_table_rank(&t) == 0 && hash_table_find(&t, 123) == 0, "empty table");
	// Rank 0 is a single slot shared by all hashes
	hash_table_put(&t, 5, (void*)0x1234);
	CHECK(hash_table_find(&t, 5) == (void*)0x1234 && hash_table_find(&t, 999) == (void*)0x1234, "rank 0 single slot");
	hash_table_set_rank(&t, 3);
	CHECK(hash_table_rank(&t) == 3, "rank %u", hash_table_rank(&t));
	for(uint64_t h = 0; h < 8; h++) CHECK(hash_table_find(&t, h) == 0, "slot %llu not zeroed after set_rank", (unsigned long long)h);
	hash_table_put(&t, 1, (void*)0x10);
	hash_table_put(&t, 9, (void*)0x90); // collides with 1
	CHECK(hash_table_find(&t, 1) == (void*)0x90 && hash_table_find(&t, 2) == 0, "rank 3 masking");
	hash_table_set_rank(&t, 0);
	CHECK(hash_table_rank(&t) == 0 && hash_table_find(&t, 1) == 0, "back to rank 0");

	size_t iter = 0;
	void* ref[1<<12];
	unsigned rank = 0; ref[0] = 0;
	for(; iter < FUZZ_ITERS; iter++){
		uint64_t h = rnd();
		switch(rnd_n(16)){
		case 0: {
			rank = (unsigned)rnd_n(13);
			hash_table_set_rank(&t, rank);
			memset(ref, 0, sizeof(void*) << rank);
		} break;
		case 1: case 2: case 3: case 4: case 5: case 6: case 7: {
			void* v = (void*)(uintptr_t)(rnd() & 0x00ffffffffffffffull);
			hash_table_put(&t, h, v);
			ref[h & (((uint64_t)1<<rank)-1)] = v;
		} break;
		default: {
			void* v = hash_table_find(&t, h);
			FCHECK(v == ref[h & (((uint64_t)1<<rank)-1)], "find(%llx) at rank %u returned %p", (unsigned long long)h, rank, v);
		}
		}
		FCHECK(hash_table_rank(&t) == rank, "rank %u != %u", hash_table_rank(&t), rank);
	}
	hash_table_set_rank(&t, 0);
}

/* ==================== shared_lock_t ==================== */

static void test_shared_lock_unit(void){
	shared_lock_t s;
	shared_lock_init(&s);
	CHECK(lock_fetch(&s) == LOCK_MAX, "init %u", lock_fetch(&s));

	// Shared parts stack, block exclusive
	CHECK(shared_lock_try_acquire(&s), "first shared");
	CHECK(shared_lock_try_acquire(&s), "second shared");
	CHECK(!exclusive_lock_try_acquire(&s), "exclusive while shared held");
	CHECK(!shared_lock_try_upgrade(&s), "try_upgrade with 2 shared holders");
	shared_lock_release(&s);
	shared_lock_release(&s);
	CHECK(lock_fetch(&s) == LOCK_MAX, "after shared release %u", lock_fetch(&s));
	shared_lock_wait(&s); // must not block
	exclusive_lock_wait(&s); // must not block
	CHECK(lock_fetch(&s) == LOCK_MAX, "after waits %u", lock_fetch(&s));

	// Exclusive blocks everything
	CHECK(exclusive_lock_try_acquire(&s), "exclusive on free lock");
	CHECK(lock_fetch(&s) == 0, "exclusive held %u", lock_fetch(&s));
	CHECK(!shared_lock_try_acquire(&s), "shared while exclusive held");
	CHECK(!exclusive_lock_try_acquire(&s), "exclusive while exclusive held");
	exclusive_lock_release(&s);
	CHECK(lock_fetch(&s) == LOCK_MAX, "after exclusive release %u", lock_fetch(&s));

	// Blocking variants on a free lock
	exclusive_lock_acquire(&s);
	CHECK(lock_fetch(&s) == 0, "exclusive_lock_acquire %u", lock_fetch(&s));
	// Downgrade keeps one shared part, lets other readers in, keeps writers out
	exclusive_lock_downgrade(&s);
	CHECK(lock_fetch(&s) == LOCK_MAX-1, "downgrade %u", lock_fetch(&s));
	CHECK(!exclusive_lock_try_acquire(&s), "exclusive after downgrade");
	CHECK(shared_lock_try_acquire(&s), "shared after downgrade");
	shared_lock_release(&s);
	// Upgrade with sole shared holder does not drop the shared part
	CHECK(shared_lock_upgrade(&s), "upgrade as sole holder should be lossless");
	CHECK(lock_fetch(&s) == 0, "after upgrade %u", lock_fetch(&s));
	exclusive_lock_release(&s);

	shared_lock_acquire(&s);
	CHECK(lock_fetch(&s) == LOCK_MAX-1, "shared_lock_acquire %u", lock_fetch(&s));
	CHECK(shared_lock_try_upgrade(&s), "try_upgrade as sole holder");
	CHECK(lock_fetch(&s) == 0, "after try_upgrade %u", lock_fetch(&s));
	exclusive_lock_release(&s);
	CHECK(lock_fetch(&s) == LOCK_MAX, "final %u", lock_fetch(&s));
}

static shared_lock_t stress_lock;
static atomic_int stress_readers, stress_writers, stress_errors;
static uint64_t stress_counter; // protected by the exclusive part, deliberately non-atomic
static atomic_uint_fast64_t stress_expected;

static void stress_check_excl(void){
	if(atomic_fetch_add(&stress_writers, 1) != 0) atomic_fetch_add(&stress_errors, 1);
	if(atomic_load(&stress_readers) != 0) atomic_fetch_add(&stress_errors, 1);
	uint64_t c = stress_counter; thread_relax(); stress_counter = c+1;
	atomic_fetch_add_explicit(&stress_expected, 1, memory_order_relaxed);
	atomic_fetch_sub(&stress_writers, 1);
}
static void stress_check_shared(void){
	atomic_fetch_add(&stress_readers, 1);
	if(atomic_load(&stress_writers) != 0) atomic_fetch_add(&stress_errors, 1);
	uint64_t c = stress_counter; thread_relax();
	if(c != stress_counter) atomic_fetch_add(&stress_errors, 1);
	atomic_fetch_sub(&stress_readers, 1);
}

static void* stress_thread(void* arg){
	uint64_t r = (uint64_t)(uintptr_t)arg * 0x9e3779b97f4a7c15ull | 1;
	for(int i = 0; i < LOCK_ITERS; i++){
		r ^= r >> 12; r ^= r << 25; r ^= r >> 27;
		switch((r * 0x2545f4914f6cdd1dull) >> 61){
		case 0: case 1: case 2:
			shared_lock_acquire(&stress_lock); stress_check_shared(); shared_lock_release(&stress_lock); break;
		case 3:
			if(shared_lock_try_acquire(&stress_lock)){ stress_check_shared(); shared_lock_release(&stress_lock); } break;
		case 4:
			exclusive_lock_acquire(&stress_lock); stress_check_excl(); exclusive_lock_release(&stress_lock); break;
		case 5:
			if(exclusive_lock_try_acquire(&stress_lock)){ stress_check_excl(); exclusive_lock_release(&stress_lock); } break;
		case 6:
			shared_lock_acquire(&stress_lock); stress_check_shared();
			shared_lock_upgrade(&stress_lock); stress_check_excl();
			exclusive_lock_downgrade(&stress_lock); stress_check_shared();
			shared_lock_release(&stress_lock); break;
		case 7:
			shared_lock_acquire(&stress_lock); stress_check_shared();
			if(shared_lock_try_upgrade(&stress_lock)){ stress_check_excl(); exclusive_lock_release(&stress_lock); }
			else shared_lock_release(&stress_lock);
			break;
		}
	}
	return 0;
}

static void test_shared_lock_stress(void){
	shared_lock_init(&stress_lock);
	thread_t th[LOCK_THREADS];
	for(uintptr_t i = 0; i < LOCK_THREADS; i++) th[i] = thread_create(stress_thread, (void*)(uintptr_t)(seed+i), 0);
	for(int i = 0; i < LOCK_THREADS; i++) thread_join(th[i]);
	CHECK(!atomic_load(&stress_errors), "%d mutual exclusion violations", atomic_load(&stress_errors));
	CHECK(stress_counter == atomic_load(&stress_expected), "counter %llu != %llu (lost updates)", (unsigned long long)stress_counter, (unsigned long long)atomic_load(&stress_expected));
	CHECK(lock_fetch(&stress_lock) == LOCK_MAX, "lock not fully released: %u", lock_fetch(&stress_lock));
}

/* ==================== main ==================== */

#define RUN(fn) do{ int f0 = failed; printf("%s\n", #fn); fn(); if(failed != f0) printf("\x1b[31m  %d failures\x1b[m\n", failed-f0); }while(0)

int main(int argc, char** argv){
	setvbuf(stdout, 0, _IONBF, 0);
	seed = argc > 1 ? strtoull(argv[1], 0, 0) : epoch_now();
	if(!seed) seed = 1;
	rng_state = seed;
	printf("seed=%llu\n", (unsigned long long)seed);

	RUN(test_size_magn);
	RUN(test_math);
	RUN(test_ring_buffer_unit);
	RUN(fuzz_ring_buffer_bytes);
	RUN(fuzz_ring_iterator_bytes);
	RUN(fuzz_ring_buffer_aligned);
	RUN(test_array_buffer_unit);
	RUN(fuzz_array_buffer);
	RUN(test_hash_table);
	RUN(test_shared_lock_unit);
	RUN(test_shared_lock_stress);

	if(failed) printf("\x1b[31m%d/%d checks failed\x1b[m\n", failed, failed+passed);
	else printf("\x1b[32mAll %d checks passed\x1b[m\n", passed);
	return failed != 0;
}
