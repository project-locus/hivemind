/**
 * Relatively fast and low-level crc64 implementation using the Jones polynomial 0x1ad93d23594c935a9
 * Matthew Reiner, 2026
 * Available under the GPL 3.0 license
 * SIMD support for x86, arm and RISC-V
 * Software fallback
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>

// Compute the crc64 checksum of a block of data using the Jones polynomial (`0x1ad93d23594c935a9`), using an initial value (different initial values will result in different checksums).
uint64_t crc64(uint64_t init, const uint8_t* data, size_t len);

#if defined(CRC64_IMPL) || defined(__INTELLISENSE__)

static uint64_t crc64__software(uint64_t x, const uint8_t *data, size_t len){
	for(size_t i = 0; i < len; ++i){
		x ^= (uint64_t)data[i];
		for(unsigned bit = 0; bit < 8; ++bit)
			x = (x >> 1) ^ (x&1 ? 0x95ac9329ac4bc9b5ull : 0); // Jones polynomial
	}
	return x;
}

#ifdef _MSC_VER
	#define _CRC64_ALWAYSINLINE __forceinline
#else
	#define _CRC64_ALWAYSINLINE __attribute__((always_inline))
#endif

#if defined(__ARM_ARCH) && __ARM_ARCH >= 8
#define _CRC64_ARM
#define _CRC64_ARM_RISCV_TARGET __attribute__((target("aes")))
#include <arm_neon.h>
#elif defined(__riscv) && (__riscv_xlen >= 64) && (defined(__GNUC__) || defined(__clang__)) && defined(__has_builtin)
#if __has_builtin(__builtin_cpu_supports)
#define _CRC64_RISCV
#define _CRC64_ARM_RISCV_TARGET __attribute__((target("zbc")))
#include <riscv_bitmanip.h>
#endif
#endif

#if (defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
#include <immintrin.h>

#ifndef _MSC_VER
__attribute__((target("pclmul,sse4.1")))
#endif
static uint64_t crc64__simd(uint64_t crc, const uint8_t* data, size_t len){
	__m128i rk1_rk2 = _mm_set_epi64x(0x381d0015c96f4444ull, 0xd9d7be7d505da32cull);

	if(len < 32) return crc64__software(crc, data, len);

	__m128i acc = _mm_loadu_si128((const __m128i*) data);
	acc = _mm_xor_si128(acc, _mm_set_epi64x(0, crc));
	data += 16; len -= 16;

	do{
		__m128i ch = _mm_loadu_si128((const __m128i*) data);
		acc = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(acc, rk1_rk2, 0x00), _mm_clmulepi64_si128(acc, rk1_rk2, 0x11)), ch);
		data += 16; len -= 16;
	}while(len >= 16);

	uint8_t tail[32];
	_mm_storeu_si128((__m128i*) tail, acc);
	if(len) memcpy(tail + 16, data, len);

	return crc64__software(0, tail, 16 + len);
}

static uint64_t crc64__decide(uint64_t crc, const uint8_t* data, size_t len);
static uint64_t (*_Atomic crc64__impl)(uint64_t, const uint8_t*, size_t) = crc64__decide;
static uint64_t crc64__decide(uint64_t crc, const uint8_t* data, size_t len){
#ifdef _MSC_VER
	int cpuInfo[4];
	__cpuid(cpuInfo, 1);
	int supports = !(~cpuInfo[2] & (1<<19 | 1<<1)); // Both need to be set
#else
	int supports = __builtin_cpu_supports("pclmul") > 0 && __builtin_cpu_supports("sse4.1") > 0;
#endif
	uint64_t (*impl)(uint64_t, const uint8_t*, size_t) = supports ? crc64__simd : crc64__software;
	atomic_store_explicit(&crc64__impl, impl, memory_order_relaxed);
	return impl(crc, data, len);
}
_CRC64_ALWAYSINLINE uint64_t crc64(uint64_t crc, const uint8_t* data, size_t len){ return atomic_load_explicit(&crc64__impl, memory_order_relaxed)(crc, data, len); };

#elif defined(_CRC64_ARM_RISCV_TARGET)

#if defined(_MSC_VER) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	#define _crc64_le64bswap(x) ((uint64_t)(x))
#else
	#define _crc64_le64bswap(x) __builtin_bswap64(x)
#endif

_CRC64_ARM_RISCV_TARGET static uint64_t crc64__simd(uint64_t crc, const uint8_t* data_, size_t len){
	if(len < 32) return crc64__software(crc, data_, len);

#ifdef _MSC_VER
	uint64_t __unaligned* data = (uint64_t*) data_;
#else
	uint64_t __attribute__((aligned(1)))* data = (uint64_t*) data_;
#endif

	uint64_t acc[2] = {_crc64_le64bswap(data[0]), _crc64_le64bswap(data[1])};
	acc[0] ^= crc;
	data += 2; len -= 16;
		do{
#ifdef _CRC64_ARM
		poly128_t p0 = vmull_p64((poly64_t)acc[0], (poly64_t)0xd9d7be7d505da32cull);
		poly128_t p1 = vmull_p64((poly64_t)acc[1], (poly64_t)0x381d0015c96f4444ull);
		uint64x2_t r = veorq_u64(vreinterpretq_u64_p128(p0), vreinterpretq_u64_p128(p1));
		acc[0] = vgetq_lane_u64(r, 0); acc[1] = vgetq_lane_u64(r, 1);
#else
		uint64_t p0lo = __builtin_riscv_clmul(acc[0], 0xd9d7be7d505da32cull), p0hi = __builtin_riscv_clmulh(acc[0], 0xd9d7be7d505da32cull);
		uint64_t p1lo = __builtin_riscv_clmul(acc[1], 0x381d0015c96f4444ull), p1hi = __builtin_riscv_clmulh(acc[1], 0x381d0015c96f4444ull);
		acc[0] = p0lo^p1lo; acc[1] = p0hi^p1hi;
#endif
	acc[0] ^= _crc64_le64bswap(data[0]); acc[1] ^= _crc64_le64bswap(data[1]);
	data += 2; len -= 16;
	}while(len >= 16);
	uint64_t tail[4] = {_crc64_le64bswap(acc[0]), _crc64_le64bswap(acc[1])};
	if(len) memcpy(tail+2, data, len);

	return crc64__software(0, (uint8_t*) tail, 16+len);
}
static uint64_t crc64__decide(uint64_t crc, const uint8_t* data, size_t len);
static uint64_t (*_Atomic crc64__impl)(uint64_t, const uint8_t*, size_t) = crc64__decide;
_CRC64_ALWAYSINLINE uint64_t crc64(uint64_t crc, const uint8_t* data, size_t len){ return atomic_load_explicit(&crc64__impl, memory_order_relaxed)(crc, data, len); };
#ifdef _CRC64_RISCV
	static uint64_t crc64__decide(uint64_t crc, const uint8_t* data, size_t len){
		uint64_t (*impl)(uint64_t, const uint8_t*, size_t) = __builtin_cpu_supports("zbc") > 0 ? crc64__simd : crc64__software;
		atomic_store_explicit(&crc64__impl, impl, memory_order_relaxed);
		return impl(crc, data, len);
	}
	#undef _CRC64_RISCV
#else
#ifdef __linux__
	#include <sys/auxv.h>
	#include <asm/hwcap.h>
	static uint64_t crc64__decide(uint64_t crc, const uint8_t* data, size_t len){
		uint64_t (*impl)(uint64_t, const uint8_t*, size_t) = (getauxval(AT_HWCAP) & HWCAP_PMULL)
#ifdef HWCAP2_PMULL
			|| (getauxval(AT_HWCAP2) & HWCAP2_PMULL)
#endif
#elif defined(__APPLE__) || defined(__FreeBSD__)
	#include <sys/sysctl.h>
	static uint64_t crc64__decide(uint64_t crc, const uint8_t* data, size_t len){
		int v = 0; size_t sz = sizeof(v);
		uint64_t (*impl)(uint64_t, const uint8_t*, size_t) = sysctlbyname("hw.optional.arm.FEAT_PMULL", &v, &sz, 0, 0) == 0 && v != 0
#else
	static uint64_t crc64__decide(uint64_t crc, const uint8_t* data, size_t len){
		uint64_t (*impl)(uint64_t, const uint8_t*, size_t) =
#ifdef __ARM_FEATURE_CRYPTO
		__ARM_FEATURE_CRYPTO
#else
#warning "Building on an OS with no reliable run-time detection of PMULL arm extension. If this extension is indeed available, compile with arm crypto extension enabled (-march=...+crypto) or define -D__ARM_FEATURE_CRYPTO=1"
		0
#endif
#endif
			? crc64__simd : crc64__software;
		atomic_store_explicit(&crc64__impl, impl, memory_order_relaxed);
		return impl(crc, data, len);
	}
	#undef _CRC64_ARM
#endif
#undef _CRC64_ARM_RISCV_TARGET

#undef _crc64_le64bswap
#else
_CRC64_ALWAYSINLINE uint64_t crc64(uint64_t crc, const uint8_t* data, size_t len){ return crc64__software(crc, data, len) };
#endif
#undef _CRC64_ALWAYSINLINE

#endif