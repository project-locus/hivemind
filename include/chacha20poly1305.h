/**
 * Relatively fast and low-level ChaCha20 and Poly1305 implementation
 * Matthew Reiner, 2026
 * Available under the GPL 3.0 license
 * Fuzz-tested on over 2.5 billion unique inputs for each algorithm, to match libsodium's implementation 1:1
 * Tests performed with clang -O3 and included UB-sanitizer and address-sanitizer
 */
#pragma once
#ifndef _DEFAULT_SOURCE
	#define _DEFAULT_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/**
 * @param in Host-endian initial state
 * @param out Content that will be XOR'd with chacha20 result. Zero this array before calling in order to get raw chacha20 output, or use ChaCha20_block. Must be 4-byte aligned.
 */
void ChaCha20_block_xor(uint32_t in[16], uint8_t out[64], uint32_t n);

/**
 * @param in Host-endian initial state. Content is modified in-place with chacha20 result and result is in little-endian
 */
void ChaCha20_block(uint32_t io[16]);

/**
 * @param in Contents to compute checksum over. No alignment requirement
 * @param inlen Length of `in` in bytes
 * @param key Input key. Must be 4-byte aligned.
 * @param out Content that will be populated with Poly1305 result. Must be 4-byte aligned
 */
void Poly1305(const uint8_t *in, size_t inlen, const uint8_t key[32], uint8_t out[16]);

#if defined(__INTELLISENSE__) || defined(CHACHA20_POLY1305_IMPL)

#ifdef _MSC_VER
	#define _CC20_P1305_ALWAYSINLINE __forceinline
#else
	#define _CC20_P1305_ALWAYSINLINE __attribute__((always_inline))
#endif

#if defined(_MSC_VER) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	#define _cc20_p1305_le32bswap(x) ((uint32_t)(x))
#else
	#define _cc20_p1305_le32bswap(x) __builtin_bswap32(x)
#endif

#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)
#include <arm_neon.h>

#define _cc20_p1305_CHACHA20_ROUND(a, b, c, d) do { \
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = veorq_u32(vshlq_n_u32(d, 16), vshrq_n_u32(d, 16)); \
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = veorq_u32(vshlq_n_u32(b, 12), vshrq_n_u32(b, 20)); \
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = veorq_u32(vshlq_n_u32(d, 8), vshrq_n_u32(d, 24)); \
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = veorq_u32(vshlq_n_u32(b, 7), vshrq_n_u32(b, 25)); \
} while(0)

void ChaCha20_block_xor(uint32_t in[16], uint8_t out[64], uint32_t n){
	start: {}
	uint32x4_t a = vld1q_u32(in + 0);
	uint32x4_t b = vld1q_u32(in + 4);
	uint32x4_t c = vld1q_u32(in + 8);
	uint32x4_t d = vld1q_u32(in + 12);

	for(int i = 0; i < 10; i++){
		_cc20_p1305_CHACHA20_ROUND(a, b, c, d);
		b = vextq_u32(b, b, 1);
		c = vextq_u32(c, c, 2);
		d = vextq_u32(d, d, 3);
		_cc20_p1305_CHACHA20_ROUND(a, b, c, d);
		b = vextq_u32(b, b, 3);
		c = vextq_u32(c, c, 2);
		d = vextq_u32(d, d, 1);
	}

	a = vaddq_u32(a, vld1q_u32(in + 0));
	b = vaddq_u32(b, vld1q_u32(in + 4));
	c = vaddq_u32(c, vld1q_u32(in + 8));
	d = vaddq_u32(d, vld1q_u32(in + 12));

	vst1q_u32((uint32_t*)(out + 0),  veorq_u32(a, vld1q_u32((uint32_t*)(out + 0))));
	vst1q_u32((uint32_t*)(out + 16), veorq_u32(b, vld1q_u32((uint32_t*)(out + 16))));
	vst1q_u32((uint32_t*)(out + 32), veorq_u32(c, vld1q_u32((uint32_t*)(out + 32))));
	vst1q_u32((uint32_t*)(out + 48), veorq_u32(d, vld1q_u32((uint32_t*)(out + 48))));
	if(--n){ in[12]++; out += 64; goto start; }
}
void ChaCha20_block(uint32_t io[16]){
	uint32x4_t a = vld1q_u32(io + 0);
	uint32x4_t b = vld1q_u32(io + 4);
	uint32x4_t c = vld1q_u32(io + 8);
	uint32x4_t d = vld1q_u32(io + 12);

	for(int i = 0; i < 10; i++){
		_cc20_p1305_CHACHA20_ROUND(a, b, c, d);
		b = vextq_u32(b, b, 1);
		c = vextq_u32(c, c, 2);
		d = vextq_u32(d, d, 3);
		_cc20_p1305_CHACHA20_ROUND(a, b, c, d);
		b = vextq_u32(b, b, 3);
		c = vextq_u32(c, c, 2);
		d = vextq_u32(d, d, 1);
	}

	vst1q_u32(io + 0,  vaddq_u32(a, vld1q_u32(io + 0)));
	vst1q_u32(io + 4, vaddq_u32(b, vld1q_u32(io + 4)));
	vst1q_u32(io + 8, vaddq_u32(c, vld1q_u32(io + 8)));
	vst1q_u32(io + 12, vaddq_u32(d, vld1q_u32(io + 12)));
}

#undef _cc20_p1305_CHACHA20_ROUND

#else

#define _cc20_p1305_CHACHA20_ROUND(a, b, c, d) \
	a += b; d ^= a; d = d << 16 | d >> 16; \
	c += d; b ^= c; b = b << 12 | b >> 20; \
	a += b; d ^= a; d = d << 8 | d >> 24; \
	c += d; b ^= c; b = b << 7 | b >> 25
static inline void ChaCha20_block_xor__software(uint32_t in[16], uint8_t out[64], uint32_t n){
	uint32_t state[16];
	start: {}
	memcpy(state, in, 64);

	for(int i = 0; i < 10; i++){
		_cc20_p1305_CHACHA20_ROUND(state[0], state[4], state[ 8], state[12]); // Column 0
		_cc20_p1305_CHACHA20_ROUND(state[1], state[5], state[ 9], state[13]); // Column 1
		_cc20_p1305_CHACHA20_ROUND(state[2], state[6], state[10], state[14]); // Column 2
		_cc20_p1305_CHACHA20_ROUND(state[3], state[7], state[11], state[15]); // Column 3
		_cc20_p1305_CHACHA20_ROUND(state[0], state[5], state[10], state[15]); // Diagonal 1 (main diagonal)
		_cc20_p1305_CHACHA20_ROUND(state[1], state[6], state[11], state[12]); // Diagonal 2
		_cc20_p1305_CHACHA20_ROUND(state[2], state[7], state[ 8], state[13]); // Diagonal 3
		_cc20_p1305_CHACHA20_ROUND(state[3], state[4], state[ 9], state[14]); // Diagonal 4
	}

	for(int i = 0; i < 16; i++)
		((uint32_t*)out)[i] ^= _cc20_p1305_le32bswap(state[i] + in[i]);

	if(--n){ in[12]++; out += 64; goto start; }
}
static inline void ChaCha20_block__software(uint32_t io[16]){
	uint32_t state[16];
	memcpy(state, io, 64);

	for(int i = 0; i < 10; i++){
		_cc20_p1305_CHACHA20_ROUND(state[0], state[4], state[ 8], state[12]); // Column 0
		_cc20_p1305_CHACHA20_ROUND(state[1], state[5], state[ 9], state[13]); // Column 1
		_cc20_p1305_CHACHA20_ROUND(state[2], state[6], state[10], state[14]); // Column 2
		_cc20_p1305_CHACHA20_ROUND(state[3], state[7], state[11], state[15]); // Column 3
		_cc20_p1305_CHACHA20_ROUND(state[0], state[5], state[10], state[15]); // Diagonal 1 (main diagonal)
		_cc20_p1305_CHACHA20_ROUND(state[1], state[6], state[11], state[12]); // Diagonal 2
		_cc20_p1305_CHACHA20_ROUND(state[2], state[7], state[ 8], state[13]); // Diagonal 3
		_cc20_p1305_CHACHA20_ROUND(state[3], state[4], state[ 9], state[14]); // Diagonal 4
	}

	for(int i = 0; i < 16; i++)
		io[i] = _cc20_p1305_le32bswap(state[i] + io[i]);
}
#undef _cc20_p1305_CHACHA20_ROUND
#if defined(__riscv)
#if (defined(__GNUC__) || defined(__clang__)) && defined(__has_builtin)
#if __has_builtin(__builtin_cpu_supports)
	#define _CC20_P1305_SIMD __attribute__((target("arch=+v"))) static
	#define _cc20_p1305_CHACHA20_ROUND(a, b, c, d, vl) \
		a = __riscv_vadd_vv_u32m1(a, b, vl); d = __riscv_vxor_vv_u32m1(d, a, vl); d = __riscv_vror_vi_u32m1(d, 16, vl); \
		c = __riscv_vadd_vv_u32m1(c, d, vl); b = __riscv_vxor_vv_u32m1(b, c, vl); b = __riscv_vror_vi_u32m1(b, 20, vl); \
		a = __riscv_vadd_vv_u32m1(a, b, vl); d = __riscv_vxor_vv_u32m1(d, a, vl); d = __riscv_vror_vi_u32m1(d, 24, vl); \
		c = __riscv_vadd_vv_u32m1(c, d, vl); b = __riscv_vxor_vv_u32m1(b, c, vl); b = __riscv_vror_vi_u32m1(b, 25, vl);

	_CC20_P1305_SIMD void ChaCha20_block_xor__simd(uint32_t in[16], uint8_t out[64], uint32_t n){
		size_t vl = __riscv_vsetvl_e32m1(4);
		vuint32m1_t idx_rot1 = __riscv_vle32_v_u32m1((const uint32_t[4]){1, 2, 3, 0}, vl);
		vuint32m1_t idx_rot2 = __riscv_vle32_v_u32m1((const uint32_t[4]){2, 3, 0, 1}, vl);
		vuint32m1_t idx_rot3 = __riscv_vle32_v_u32m1((const uint32_t[4]){3, 0, 1, 2}, vl);

		start: {}
		vuint32m1_t a = __riscv_vle32_v_u32m1(in + 0, vl);
		vuint32m1_t b = __riscv_vle32_v_u32m1(in + 4, vl);
		vuint32m1_t c = __riscv_vle32_v_u32m1(in + 8, vl);
		vuint32m1_t d = __riscv_vle32_v_u32m1(in + 12, vl);

		for(int i = 0; i < 10; i++){
			_cc20_p1305_CHACHA20_ROUND(a, b, c, d, vl);
			b = __riscv_vrgather_vv_u32m1(b, idx_rot1, vl);
			c = __riscv_vrgather_vv_u32m1(c, idx_rot2, vl);
			d = __riscv_vrgather_vv_u32m1(d, idx_rot3, vl);
			_cc20_p1305_CHACHA20_ROUND(a, b, c, d, vl);
			b = __riscv_vrgather_vv_u32m1(b, idx_rot3, vl); // rot3 is the inverse of rot1
			c = __riscv_vrgather_vv_u32m1(c, idx_rot2, vl); // rot2 is the inverse of rot2
			d = __riscv_vrgather_vv_u32m1(d, idx_rot1, vl); // rot1 is the inverse of rot3
		}

		a = __riscv_vadd_vv_u32m1(a, __riscv_vle32_v_u32m1(in + 0, vl), vl);
		b = __riscv_vadd_vv_u32m1(b, __riscv_vle32_v_u32m1(in + 4, vl), vl);
		c = __riscv_vadd_vv_u32m1(c, __riscv_vle32_v_u32m1(in + 8, vl), vl);
		d = __riscv_vadd_vv_u32m1(d, __riscv_vle32_v_u32m1(in + 12, vl), vl);

		__riscv_vse32_v_u32m1((uint32_t*)out + 0, __riscv_vxor_vv_u32m1(a, __riscv_vle32_v_u32m1((uint32_t*)out + 0, vl), vl), vl);
		__riscv_vse32_v_u32m1((uint32_t*)out + 4, __riscv_vxor_vv_u32m1(b, __riscv_vle32_v_u32m1((uint32_t*)out + 4, vl), vl), vl);
		__riscv_vse32_v_u32m1((uint32_t*)out + 8, __riscv_vxor_vv_u32m1(c, __riscv_vle32_v_u32m1((uint32_t*)out + 8, vl), vl), vl);
		__riscv_vse32_v_u32m1((uint32_t*)out + 12, __riscv_vxor_vv_u32m1(d, __riscv_vle32_v_u32m1((uint32_t*)out + 12, vl), vl), vl);

		if(--n){ in[12]++; out += 64; goto start; }
	}
	_CC20_P1305_SIMD void ChaCha20_block__simd(uint32_t io[16]){
		size_t vl = __riscv_vsetvl_e32m1(4);
		vuint32m1_t idx_rot1 = __riscv_vle32_v_u32m1((const uint32_t[4]){1, 2, 3, 0}, vl);
		vuint32m1_t idx_rot2 = __riscv_vle32_v_u32m1((const uint32_t[4]){2, 3, 0, 1}, vl);
		vuint32m1_t idx_rot3 = __riscv_vle32_v_u32m1((const uint32_t[4]){3, 0, 1, 2}, vl);

		vuint32m1_t a = __riscv_vle32_v_u32m1(io + 0, vl);
		vuint32m1_t b = __riscv_vle32_v_u32m1(io + 4, vl);
		vuint32m1_t c = __riscv_vle32_v_u32m1(io + 8, vl);
		vuint32m1_t d = __riscv_vle32_v_u32m1(io + 12, vl);

		for(int i = 0; i < 10; i++){
			_cc20_p1305_CHACHA20_ROUND(a, b, c, d, vl);
			b = __riscv_vrgather_vv_u32m1(b, idx_rot1, vl);
			c = __riscv_vrgather_vv_u32m1(c, idx_rot2, vl);
			d = __riscv_vrgather_vv_u32m1(d, idx_rot3, vl);
			_cc20_p1305_CHACHA20_ROUND(a, b, c, d, vl);
			b = __riscv_vrgather_vv_u32m1(b, idx_rot3, vl); // rot3 is the inverse of rot1
			c = __riscv_vrgather_vv_u32m1(c, idx_rot2, vl); // rot2 is the inverse of rot2
			d = __riscv_vrgather_vv_u32m1(d, idx_rot1, vl); // rot1 is the inverse of rot3
		}

		__riscv_vse32_v_u32m1((uint32_t*)io + 0, __riscv_vadd_vv_u32m1(a, __riscv_vle32_v_u32m1(io + 0, vl), vl), vl);
		__riscv_vse32_v_u32m1((uint32_t*)io + 4, __riscv_vadd_vv_u32m1(b, __riscv_vle32_v_u32m1(io + 4, vl), vl), vl);
		__riscv_vse32_v_u32m1((uint32_t*)io + 8, __riscv_vadd_vv_u32m1(c, __riscv_vle32_v_u32m1(io + 8, vl), vl), vl);
		__riscv_vse32_v_u32m1((uint32_t*)io + 12, __riscv_vadd_vv_u32m1(d, __riscv_vle32_v_u32m1(io + 12, vl), vl), vl);
	}

	extern static void (*_Atomic ChaCha20_block_xor__impl)(uint32_t[16], uint8_t[64], uint32_t);
	extern static void (*_Atomic ChaCha20_block__impl)(uint32_t[16]);
	_CC20_P1305_ALWAYSINLINE static void _cc20_p1305_simd_decide(){
		int supports = __builtin_cpu_supports("v") > 0 && __builtin_cpu_supports("zvkb") > 0;
		atomic_store_explicit(&ChaCha20_block_xor__impl, supports ? ChaCha20_block_xor__simd : ChaCha20_block_xor__software, memory_order_relaxed);
		atomic_store_explicit(&ChaCha20_block__impl, supports ? ChaCha20_block__simd : ChaCha20_block__software, memory_order_relaxed);
	}

	#undef _cc20_p1305_CHACHA20_ROUND

#else
	#warning Compiling for RISC-V: Use a more recent compiler version that supports __builtin_cpu_supports. SIMD disabled
#endif
#else
	#warning Compiling for RISC-V: Use a version of GCC or Clang that supports __has_builtin. SIMD disabled
#endif
#elif (defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
	#include <immintrin.h>
	
	#ifdef _MSC_VER
		#define _CC20_P1305_SIMD static
	#else
		#define _CC20_P1305_SIMD __attribute__((target("ssse3"))) static
	#endif

	#define _cc20_p1305_CHACHA20_ROUND(a, b, c, d) do { \
		a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = _mm_shuffle_epi8(d, rot16); \
		c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = _mm_xor_si128(_mm_slli_epi32(b, 12), _mm_srli_epi32(b, 20)); \
		a = _mm_add_epi32(a, b); d = _mm_xor_si128(d, a); d = _mm_shuffle_epi8(d, rot8); \
		c = _mm_add_epi32(c, d); b = _mm_xor_si128(b, c); b = _mm_xor_si128(_mm_slli_epi32(b, 7), _mm_srli_epi32(b, 25)); \
	} while(0)
	_CC20_P1305_SIMD ChaCha20_block_xor__simd(uint32_t in[16], uint8_t out[64], uint32_t n){
		const __m128i rot16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
		const __m128i rot8  = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

		start: {}
		__m128i a = _mm_loadu_si128((const __m128i*)(in + 0));
		__m128i b = _mm_loadu_si128((const __m128i*)(in + 4));
		__m128i c = _mm_loadu_si128((const __m128i*)(in + 8));
		__m128i d = _mm_loadu_si128((const __m128i*)(in + 12));

		for(int i = 0; i < 10; i++){
			_cc20_p1305_CHACHA20_ROUND(a, b, c, d);
			b = _mm_shuffle_epi32(b, _MM_SHUFFLE(0, 3, 2, 1));
			c = _mm_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
			d = _mm_shuffle_epi32(d, _MM_SHUFFLE(2, 1, 0, 3));
			_cc20_p1305_CHACHA20_ROUND(a, b, c, d);
			b = _mm_shuffle_epi32(b, _MM_SHUFFLE(2, 1, 0, 3));
			c = _mm_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
			d = _mm_shuffle_epi32(d, _MM_SHUFFLE(0, 3, 2, 1));
		}
		a = _mm_add_epi32(a, _mm_loadu_si128((const __m128i*)(in + 0)));
		b = _mm_add_epi32(b, _mm_loadu_si128((const __m128i*)(in + 4)));
		c = _mm_add_epi32(c, _mm_loadu_si128((const __m128i*)(in + 8)));
		d = _mm_add_epi32(d, _mm_loadu_si128((const __m128i*)(in + 12)));

		_mm_storeu_si128((__m128i*)(out +  0), _mm_xor_si128(a, _mm_loadu_si128((const __m128i*)(out +  0))));
		_mm_storeu_si128((__m128i*)(out + 16), _mm_xor_si128(b, _mm_loadu_si128((const __m128i*)(out + 16))));
		_mm_storeu_si128((__m128i*)(out + 32), _mm_xor_si128(c, _mm_loadu_si128((const __m128i*)(out + 32))));
		_mm_storeu_si128((__m128i*)(out + 48), _mm_xor_si128(d, _mm_loadu_si128((const __m128i*)(out + 48))));
		if(--n){ in[12]++; out += 64; goto start; }
	}
	_CC20_P1305_SIMD ChaCha20_block__simd(uint32_t io[16]){
		const __m128i rot16 = _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
		const __m128i rot8  = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

		__m128i a = _mm_loadu_si128((const __m128i*)(io + 0));
		__m128i b = _mm_loadu_si128((const __m128i*)(io + 4));
		__m128i c = _mm_loadu_si128((const __m128i*)(io + 8));
		__m128i d = _mm_loadu_si128((const __m128i*)(io + 12));

		for(int i = 0; i < 10; i++){
			_cc20_p1305_CHACHA20_ROUND(a, b, c, d);
			b = _mm_shuffle_epi32(b, _MM_SHUFFLE(0, 3, 2, 1));
			c = _mm_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
			d = _mm_shuffle_epi32(d, _MM_SHUFFLE(2, 1, 0, 3));
			_cc20_p1305_CHACHA20_ROUND(a, b, c, d);
			b = _mm_shuffle_epi32(b, _MM_SHUFFLE(2, 1, 0, 3));
			c = _mm_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
			d = _mm_shuffle_epi32(d, _MM_SHUFFLE(0, 3, 2, 1));
		}

		_mm_storeu_si128((__m128i*)(io +  0), _mm_add_epi32(a, _mm_loadu_si128((const __m128i*)(io + 0))));
		_mm_storeu_si128((__m128i*)(io + 16), _mm_add_epi32(b, _mm_loadu_si128((const __m128i*)(io + 4))));
		_mm_storeu_si128((__m128i*)(io + 32), _mm_add_epi32(c, _mm_loadu_si128((const __m128i*)(io + 8))));
		_mm_storeu_si128((__m128i*)(io + 48), _mm_add_epi32(d, _mm_loadu_si128((const __m128i*)(io + 12))));
	}
	extern static void (*_Atomic ChaCha20_block_xor__impl)(uint32_t[16], uint8_t[64], uint32_t);
	extern static void (*_Atomic ChaCha20_block__impl)(uint32_t[16]);
	_CC20_P1305_ALWAYSINLINE static void _cc20_p1305_simd_decide(){		
#ifdef _MSC_VER
		int cpuInfo[4];
		__cpuid(cpuInfo, 1);
		int supports = (cpuInfo[2] & (1 << 9));
#else
      int supports = __builtin_cpu_supports("ssse3") > 0;
#endif
		atomic_store_explicit(&ChaCha20_block_xor__impl, supports ? ChaCha20_block_xor__simd : ChaCha20_block_xor__software, memory_order_relaxed);
		atomic_store_explicit(&ChaCha20_block__impl, supports ? ChaCha20_block__simd : ChaCha20_block__software, memory_order_relaxed);
	}
#else
	_CC20_P1305_ALWAYSINLINE void ChaCha20_block_xor(uint32_t in[16], uint8_t out[64], uint32_t n){ ChaCha20_block_xor__software(io); }
	_CC20_P1305_ALWAYSINLINE void ChaCha20_block(uint32_t io[16]){ ChaCha20_block__software(in, out, n); }
#endif
#ifdef _CC20_P1305_SIMD
	#include <stdatomic.h>
	static void ChaCha20_block_xor__decide(uint32_t in[16], uint8_t out[64], uint32_t n){
		_cc20_p1305_simd_decide(); atomic_load_explicit(&ChaCha20_block_xor__impl, memory_order_relaxed)(in, out, n);
	}
	static void ChaCha20_block__decide(uint32_t io[16]){
		_cc20_p1305_simd_decide(); atomic_load_explicit(&ChaCha20_block__impl, memory_order_relaxed)(io);
	}
	static void (*_Atomic ChaCha20_block_xor__impl)(uint32_t[16], uint8_t[64], uint32_t) = ChaCha20_block_xor__decide;
	static void (*_Atomic ChaCha20_block__impl)(uint32_t[16]) = ChaCha20_block__decide;
	_CC20_P1305_ALWAYSINLINE void ChaCha20_block_xor(uint32_t in[16], uint8_t out[64], uint32_t n){ atomic_load_explicit(&ChaCha20_block_xor__impl, memory_order_relaxed)(in, out, n); }
	_CC20_P1305_ALWAYSINLINE void ChaCha20_block(uint32_t io[16]){ atomic_load_explicit(&ChaCha20_block__impl, memory_order_relaxed)(io); }
	#undef _CC20_P1305_SIMD
#endif
#undef _CC20_P1305_ALWAYSINLINE

#endif
#undef _cc20_p1305_CHACHA20_ROUND

#define _cc20_p1305_POLY1305_LOAD(m0,m1,m2,m3,m4,buf) m0 = _cc20_p1305_le32bswap(((uint32_t*)buf)[0]); \
	m1 = _cc20_p1305_le32bswap(((uint32_t*)buf)[1]); \
	m2 = _cc20_p1305_le32bswap(((uint32_t*)buf)[2]); \
	m3 = _cc20_p1305_le32bswap(((uint32_t*)buf)[3]); \
	m4 |= m3 >> 8; \
	m3 = (m2 >> 14 | m3 << 18) & 0x3ffffff; \
	m2 = (m1 >> 20 | m2 << 12) & 0x3ffffff; \
	m1 = (m0 >> 26 | m1 << 6) & 0x3ffffff; \
	m0 &= 0x3ffffff;

void Poly1305(const uint8_t *in, size_t inlen, const uint8_t key[32], uint8_t out[16]){
	uint32_t r0, r1, r2, r3, r4 = 0;
	uint32_t s1, s2, s3, s4;

	uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

	_cc20_p1305_POLY1305_LOAD(r0,r1,r2,r3,r4,key)

	r1 &= 0x3ffff03;
	r2 &= 0x3ffc0ff;
	r3 &= 0x3f03fff;
	r4 &= 0x00fffff;

	s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;

	while(inlen){
		uint32_t m0, m1, m2, m3, m4 = 0;
		uint32_t c;
		
		int block = 16;
#ifdef __cplusplus
		alignas(4) char buf[16] = {0};
#else
		_Alignas(4) char buf[16] = {0};
#endif
		if(inlen < 16){
			buf[block = (int)inlen] = 1;
		}else m4 = 0x1000000;
		memcpy(buf, in, block);

		_cc20_p1305_POLY1305_LOAD(m0,m1,m2,m3,m4,buf)

		h0 += m0; h1 += m1; h2 += m2; h3 += m3; h4 += m4;

		// multiply (h *= r)
		uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
		uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
		uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
		uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
		uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

		// carry propagation
		c  = (uint32_t)(d0 >> 26); h0 = d0 & 0x3ffffff; d1 += c;
		c  = (uint32_t)(d1 >> 26); h1 = d1 & 0x3ffffff; d2 += c;
		c  = (uint32_t)(d2 >> 26); h2 = d2 & 0x3ffffff; d3 += c;
		c  = (uint32_t)(d3 >> 26); h3 = d3 & 0x3ffffff; d4 += c;
		c  = (uint32_t)(d4 >> 26); h4 = d4 & 0x3ffffff; h0 += c * 5;
		c  = (uint32_t)(h0 >> 26); h0 &= 0x3ffffff; h1 += c;

		in += block;
		inlen -= (size_t)block;
	}

	// final reduction
	uint32_t c;
	c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
	c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
	c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
	c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
	c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

	// compute h + -p to check if reduction needed
	uint32_t g0 = h0 + 5;
	c = g0 >> 26; g0 &= 0x3ffffff;
	uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	uint32_t g4 = h4 + c - (1ULL << 26);

	uint32_t mask = (g4 >> 31) - 1;
	h0 = (h0 & ~mask) | (g0 & mask);
	h1 = (h1 & ~mask) | (g1 & mask);
	h2 = (h2 & ~mask) | (g2 & mask);
	h3 = (h3 & ~mask) | (g3 & mask);
	h4 = (h4 & ~mask) | (g4 & mask);

	// serialize h
	uint64_t f0 = (uint64_t)((h0      ) | (h1 << 26)) + _cc20_p1305_le32bswap(((uint32_t*)key)[4]);
	uint64_t f1 = (uint64_t)((h1 >> 6 ) | (h2 << 20)) + _cc20_p1305_le32bswap(((uint32_t*)key)[5]) + (f0 >> 32);
	uint64_t f2 = (uint64_t)((h2 >> 12) | (h3 << 14)) + _cc20_p1305_le32bswap(((uint32_t*)key)[6]) + (f1 >> 32);
	uint64_t f3 = (uint64_t)((h3 >> 18) | (h4 << 8 )) + _cc20_p1305_le32bswap(((uint32_t*)key)[7]) + (f2 >> 32);

	((uint32_t*)out)[0] = _cc20_p1305_le32bswap(f0);
	((uint32_t*)out)[1] = _cc20_p1305_le32bswap(f1);
	((uint32_t*)out)[2] = _cc20_p1305_le32bswap(f2);
	((uint32_t*)out)[3] = _cc20_p1305_le32bswap(f3);
}

#undef _cc20_p1305_POLY1305_LOAD
#undef _cc20_p1305_le32bswap
#undef _cc20_p1305_le32bswap

#endif