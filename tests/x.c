// ./test.sh x
// clang -g -Og -fsanitize=address -fsanitize=undefined -I../include x.c -o test.out && ./test.out [seed]; rm test.out

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "x.h"

#ifndef FUZZ_ITERS
#define FUZZ_ITERS 20000
#endif

static int failed = 0, passed = 0;
static uint64_t seed;

#define CHECK(cond, ...) ((cond) ? (void)passed++ : (void)(failed++, \
	printf("\x1b[31m%s:%d: CHECK(%s) failed: \x1b[m", __FILE__, __LINE__, #cond), printf(__VA_ARGS__), printf("\n")))
// Like CHECK but bails out of the enclosing function, so that one fuzz divergence doesn't produce thousands of lines
#define FCHECK(cond, ...) do{ if(!(cond)){ failed++; \
	printf("\x1b[31m%s:%d: CHECK(%s) failed at iteration %zu (seed=%llu): \x1b[m", __FILE__, __LINE__, #cond, iter, (unsigned long long)seed); \
	printf(__VA_ARGS__); printf("\n"); return; } passed++; }while(0)

static uint64_t rng_state;
static inline uint64_t rnd(void){
	// xorshift64*
	uint64_t x = rng_state;
	x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
	rng_state = x;
	return x * 0x2545f4914f6cdd1dull;
}
static inline size_t rnd_n(size_t n){ return n ? (size_t)(rnd() % n) : 0; }
static void rnd_bytes(void* p, size_t n){
	for(size_t i = 0; i < n; i++) ((uint8_t*)p)[i] = (uint8_t)rnd();
}

static uint64_t now_us(void){
	struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec*1000000 + (uint64_t)ts.tv_nsec/1000;
}

static char tmpdir[512];
static char* path(const char* name){
	static char buf[4][600]; static int i = 0;
	char* p = buf[i++&3];
	snprintf(p, 600, "%s/%s", tmpdir, name);
	return p;
}

/* ==================== files & directories ==================== */

static void test_files(void){
	uint8_t buf[256], out[256];

	CHECK(x_stat(path("nope")).type == X_FILE_NOT_FOUND, "missing file stat");
	CHECK(x_open(path("nodir/file"), 0) == X_FILE_INVALID, "open in missing directory");
	CHECK(x_open(path("nope"), X_FILE_READONLY) == X_FILE_INVALID, "readonly open must not create");
	CHECK(x_stat(path("nope")).type == X_FILE_NOT_FOUND, "readonly open created the file");

	x_file_t f = x_open(path("a"), 0);
	CHECK(f != X_FILE_INVALID, "create");
	CHECK(x_getsize(f) == 0, "new file size %llu", (unsigned long long)x_getsize(f));
	for(int i = 0; i < 256; i++) buf[i] = (uint8_t)i;
	CHECK(x_write(f, buf, 0, 100) == 100, "write");
	CHECK(x_write(f, buf+100, 1000, 50) == 50, "write past end");
	CHECK(x_getsize(f) == 1050, "size after sparse write %llu", (unsigned long long)x_getsize(f));
	memset(out, 0xaa, sizeof(out));
	CHECK(x_read(f, out, 0, 100) == 100 && !memcmp(out, buf, 100), "read back");
	CHECK(x_read(f, out, 100, 10) == 10, "read hole");
	CHECK(!memcmp(out, (uint8_t[10]){0}, 10), "hole not zero");
	CHECK(x_read(f, out, 1000, 256) == 50 && !memcmp(out, buf+100, 50), "short read at EOF");
	CHECK(x_read(f, out, 5000, 10) == 0, "read past EOF");

	CHECK(x_setsize(f, 20), "truncate");
	CHECK(x_getsize(f) == 20 && x_read(f, out, 0, 256) == 20 && !memcmp(out, buf, 20), "truncated contents");
	CHECK(x_setsize(f, 64), "extend");
	CHECK(x_read(f, out, 0, 256) == 64 && !memcmp(out, buf, 20) && !memcmp(out+20, (uint8_t[44]){0}, 44), "extended bytes are zero");
	CHECK(x_flush(f), "flush");
	x_close(f);

	uint64_t t = (uint64_t)time(0)*1000000;
	x_stat_t st = x_stat(path("a"));
	CHECK(st.type == X_FILE_TYPE_FILE && st.size == 64, "stat type=%u size=%llu", (unsigned)st.type, (unsigned long long)st.size);
	CHECK(st.modified + 10000000 > t && st.modified < t + 10000000, "mtime %llu vs now %llu", (unsigned long long)st.modified, (unsigned long long)t);

	// Read-only handle: reads work, writes fail (documented to return 0)
	f = x_open(path("a"), X_FILE_READONLY);
	CHECK(f != X_FILE_INVALID, "readonly open existing");
	CHECK(x_read(f, out, 0, 20) == 20 && !memcmp(out, buf, 20), "readonly read");
	size_t w = x_write(f, buf, 0, 10);
	CHECK(w == 0, "write to readonly handle returned %zu, documented to return 0", w);
	x_close(f);
	size_t r = x_read(X_FILE_INVALID, out, 0, 10);
	CHECK(r == 0, "read from invalid handle returned %zu, documented to return 0", r);

	// Flags shouldn't break basic I/O
	f = x_open(path("flags"), X_FILE_SEQUENTIAL | X_FILE_WRITE_THROUGH);
	CHECK(f != X_FILE_INVALID && x_write(f, buf, 0, 16) == 16 && x_read(f, out, 0, 16) == 16 && !memcmp(out, buf, 16), "sequential|write_through I/O");
	x_close(f);

	// Directories
	CHECK(x_mkdir(path("d")), "mkdir");
	CHECK(!x_mkdir(path("d")), "mkdir existing");
	CHECK(x_stat(path("d")).type == X_FILE_TYPE_FOLDER, "folder stat");
	CHECK(x_move(path("a"), path("d/b")), "move into folder");
	CHECK(x_stat(path("a")).type == X_FILE_NOT_FOUND && x_stat(path("d/b")).size == 64, "moved");
	f = x_open(path("d/c"), 0); x_write(f, "x", 0, 1); x_close(f);
	// Move replaces an existing target
	CHECK(x_move(path("d/c"), path("d/b")), "move over existing");
	CHECK(x_stat(path("d/b")).size == 1 && x_stat(path("d/c")).type == X_FILE_NOT_FOUND, "move replaced target");
	f = x_open(path("d/c"), 0); x_close(f);

	x_folder_list_t dl = x_dir_open(path("d"));
	CHECK(dl != 0, "dir_open");
	int seen_b = 0, seen_c = 0, other = 0; char* n;
	while(dl && (n = x_dir_next(dl))){
		if(!strcmp(n, "b")) seen_b++;
		else if(!strcmp(n, "c")) seen_c++;
		else if(strcmp(n, ".") && strcmp(n, "..")) other++;
	}
	if(dl) x_dir_close(dl);
	CHECK(seen_b == 1 && seen_c == 1 && !other, "listing b=%d c=%d other=%d", seen_b, seen_c, other);
	CHECK(x_dir_open(path("nope")) == 0, "dir_open missing");

	CHECK(!x_remove(path("d")), "remove non-empty folder");
	CHECK(x_remove(path("d/b")) && x_remove(path("d/c")), "remove files");
	CHECK(x_remove(path("d")), "remove empty folder");
	CHECK(!x_remove(path("d")), "remove missing");
	CHECK(x_remove(path("flags")), "remove flags file");
}

// Random pread/pwrite/truncate against an in-memory model
static void fuzz_files(void){
	enum{ MAXF = 1<<18 };
	static uint8_t ref[MAXF], tmp[MAXF], in[MAXF];
	size_t len = 0, iter = 0;
	x_file_t f = x_open(path("fuzz"), 0);
	if(f == X_FILE_INVALID){ CHECK(0, "open fuzz file"); return; }
	for(; iter < FUZZ_ITERS; iter++){
		switch(rnd_n(4)){
		case 0: case 1: { // write (possibly past the end, leaving a zeroed hole)
			size_t at = rnd_n(len + 4096 < MAXF ? len + 4096 : MAXF);
			size_t n = rnd_n((MAXF - at) < 8192 ? MAXF - at : 8192);
			rnd_bytes(in, n);
			FCHECK(x_write(f, in, at, n) == n, "write(%zu, %zu)", at, n);
			if(!n) break; // a zero-length write doesn't extend the file
			if(at > len) memset(ref+len, 0, at-len);
			memcpy(ref+at, in, n);
			if(at+n > len) len = at+n;
		} break;
		case 2: { // read (possibly past the end)
			size_t at = rnd_n(len + 4096), n = rnd_n(8192);
			size_t expect = at >= len ? 0 : (len-at < n ? len-at : n);
			size_t got = x_read(f, tmp, at, n);
			FCHECK(got == expect, "read(%zu, %zu) returned %zu, expected %zu (len=%zu)", at, n, got, expect, len);
			FCHECK(!expect || !memcmp(tmp, ref+at, expect), "read(%zu, %zu) contents", at, n);
		} break;
		case 3: { // setsize
			if(rnd_n(4)) break;
			size_t n = rnd_n(MAXF);
			FCHECK(x_setsize(f, n), "setsize(%zu)", n);
			if(n > len) memset(ref+len, 0, n-len);
			len = n;
		} break;
		}
		FCHECK(x_getsize(f) == len, "size %llu != %zu", (unsigned long long)x_getsize(f), len);
	}
	x_close(f);
	x_remove(path("fuzz"));
}

/* ==================== pages & mappings ==================== */

static void test_pages(void){
	uint8_t* p = (uint8_t*)x_pagealloc(3);
	CHECK(p != 0, "pagealloc");
	if(!p) return;
	CHECK(!((uintptr_t)p & 4095), "pagealloc alignment %p", (void*)p);
	size_t nz = 0;
	for(size_t i = 0; i < 3*X_PAGE_SIZE; i++) nz += p[i] != 0;
	CHECK(!nz, "pagealloc not zeroed (%zu nonzero bytes)", nz);
	memset(p, 0x5a, 3*X_PAGE_SIZE);
	x_touch_pages(p, 3);
	x_invalidate_pages(p+X_PAGE_SIZE, 1);
	// Each byte of an invalidated region is either the last written value or zero
	size_t bad = 0;
	for(size_t i = 0; i < 3*X_PAGE_SIZE; i++)
		bad += (i >= X_PAGE_SIZE && i < 2*X_PAGE_SIZE) ? (p[i] != 0x5a && p[i] != 0) : p[i] != 0x5a;
	CHECK(!bad, "%zu bytes corrupted by invalidate", bad);
	x_pagefree(p, 3);

	// Shared mapping writes through to the file
	x_file_t f = x_open(path("map"), 0);
	CHECK(f != X_FILE_INVALID && x_setsize(f, 3*X_PAGE_SIZE), "map file");
	uint8_t pat[64]; for(int i = 0; i < 64; i++) pat[i] = (uint8_t)(i*7+1);
	x_write(f, pat, X_PAGE_SIZE+100, 64);
	uint8_t* m = (uint8_t*)x_mapfile(f, 1, 2, false);
	CHECK(m != 0, "mapfile shared");
	if(m){
		CHECK(!memcmp(m+100, pat, 64), "mapping offset: page 1 not at start of mapping");
		memcpy(m+X_PAGE_SIZE+5, "hello", 5);
		x_sync_pages(m, 2);
		uint8_t out[5];
		CHECK(x_read(f, out, 2*X_PAGE_SIZE+5, 5) == 5 && !memcmp(out, "hello", 5), "shared mapping write not visible in file");
		x_pagefree(m, 2);
	}
	// Private copy: writes don't reach the file, and file writes after mapping don't matter for this check
	m = (uint8_t*)x_mapfile(f, 0, 3, true);
	CHECK(m != 0, "mapfile copy");
	if(m){
		CHECK(!memcmp(m+X_PAGE_SIZE+100, pat, 64), "copy mapping contents");
		memcpy(m+X_PAGE_SIZE+100, "zzzz", 4);
		uint8_t out[4];
		CHECK(x_read(f, out, X_PAGE_SIZE+100, 4) == 4 && !memcmp(out, pat, 4), "copy mapping wrote back to file");
		x_pagefree(m, 3);
	}
	x_close(f);
	x_remove(path("map"));
}

/* ==================== randomness ==================== */

static void test_random(void){
	uint8_t a[4096], b[4096];
	memset(a, 0, sizeof(a)); memset(b, 0, sizeof(b));
	x_randombytes(a, 0);
	CHECK(!a[0], "zero-length randombytes wrote");
	x_randombytes(a, sizeof(a));
	x_randombytes(b, sizeof(b));
	CHECK(memcmp(a, b, sizeof(a)), "two random buffers identical");
	// Bit balance: 32768 bits, expect 16384 ± ~90 (sigma); allow 6 sigma
	size_t ones = 0;
	for(size_t i = 0; i < sizeof(a); i++) ones += (size_t)__builtin_popcount(a[i]);
	CHECK(ones > 16384-550 && ones < 16384+550, "bit balance %zu/32768", ones);
	// Byte distribution chi-squared over 256 buckets with 1M samples (df=255, p≈1e-6 cutoff ~ 370)
	static uint8_t big[1<<20]; size_t cnt[256] = {0};
	x_randombytes(big, sizeof(big));
	for(size_t i = 0; i < sizeof(big); i++) cnt[big[i]]++;
	double chi = 0, e = sizeof(big)/256.;
	for(int i = 0; i < 256; i++) chi += (cnt[i]-e)*(cnt[i]-e)/e;
	CHECK(chi < 370, "chi-squared %.1f", chi);
	// Odd lengths / unaligned destinations leave neighbours untouched
	for(size_t len = 1; len < 70; len++){
		memset(a, 0xee, 80);
		x_randombytes(a+3, len);
		CHECK(a[2] == 0xee && a[3+len] == 0xee, "randombytes(%zu) overran", len);
	}

	memset(a, 0xff, sizeof(a));
	x_zerobytes(a+1, 100);
	CHECK(a[0] == 0xff && a[101] == 0xff && !memcmp(a+1, (uint8_t[100]){0}, 100), "zerobytes");
	x_zerobytes(a, 0);
	CHECK(a[0] == 0xff, "zero-length zerobytes wrote");
}

/* ==================== IP addresses ==================== */

static ip_addr_t ip_bytes(const uint8_t b[16]){ ip_addr_t a; memcpy(a.bytes, b, 16); return a; }

static void test_ip(void){
	static const struct{ const char* in; uint8_t bytes[16]; const char* out; enum ip_kind kind; } cases[] = {
		{"1.2.3.4", {0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4}, "1.2.3.4", IP_KIND_V4},
		{"255.255.255.255", {0,0,0,0,0,0,0,0,0,0,0xff,0xff,255,255,255,255}, "255.255.255.255", IP_KIND_V4},
		{"127.0.0.1", {0,0,0,0,0,0,0,0,0,0,0xff,0xff,127,0,0,1}, "127.0.0.1", IP_KIND_V4},
		{"::ffff:192.168.1.42", {0,0,0,0,0,0,0,0,0,0,0xff,0xff,192,168,1,42}, "192.168.1.42", IP_KIND_V4},
		{"::1", {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, "::1", IP_KIND_V6},
		{"::", {0}, "::", IP_KIND_V6},
		{"0.0.0.0", {0,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0,0}, "0.0.0.0", IP_KIND_V4},
		{"2001:db8:1001:2002:db8::1234", {0x20,0x01,0x0d,0xb8,0x10,0x01,0x20,0x02,0x0d,0xb8,0,0,0,0,0x12,0x34}, "2001:db8:1001:2002:db8::1234", IP_KIND_V6},
		{"fe80::1", {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, "fe80::1", IP_KIND_V6},
		{"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IP_KIND_V6},
		// Invalid input parses to ::
		{"", {0}, "::", IP_KIND_V6},
		{"1.2.3", {0}, "::", IP_KIND_V6},
		{"256.1.1.1", {0}, "::", IP_KIND_V6},
		{"1::2::3", {0}, "::", IP_KIND_V6},
		{"localhost", {0}, "::", IP_KIND_V6},
		{" 1.2.3.4", {0}, "::", IP_KIND_V6},
	};
	for(size_t i = 0; i < sizeof(cases)/sizeof(*cases); i++){
		ip_addr_t a = ip_from_string(cases[i].in);
		CHECK(!memcmp(a.bytes, cases[i].bytes, 16), "ip_from_string(\"%s\")", cases[i].in);
		char s[IP_STR_MAX_LEN];
		enum ip_kind k = ip_to_string(ip_bytes(cases[i].bytes), s);
		CHECK(k == cases[i].kind && !strcmp(s, cases[i].out), "ip_to_string(\"%s\") = \"%s\" kind %d", cases[i].in, s, (int)k);
	}

	// Round trip random addresses: v6, v4-mapped, and v6 with long zero runs
	size_t iter = 0;
	for(; iter < FUZZ_ITERS*10; iter++){
		uint8_t b[16]; rnd_bytes(b, 16);
		switch(rnd_n(3)){
		case 0: memset(b, 0, 10); b[10] = b[11] = 0xff; break;
		case 1: for(int j = 0; j < 8; j++) if(rnd_n(2)) b[2*j] = b[2*j+1] = 0; break;
		}
		static const uint8_t mapped0[16] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0,0};
		char s[IP_STR_MAX_LEN];
		memset(s, 'X', sizeof(s));
		enum ip_kind k = ip_to_string(ip_bytes(b), s);
		FCHECK(memchr(s, 0, IP_STR_MAX_LEN) != 0, "ip_to_string not terminated");
		bool v4 = !memcmp(b, mapped0, 12);
		FCHECK(k == (v4 ? IP_KIND_V4 : IP_KIND_V6), "kind %d for \"%s\"", (int)k, s);
		FCHECK(v4 == !strchr(s, ':'), "\"%s\" has wrong format for kind", s);
		ip_addr_t back = ip_from_string(s);
		FCHECK(!memcmp(back.bytes, b, 16), "round trip of \"%s\"", s);
	}

	// Random junk strings must agree with inet_pton
	iter = 0;
	static const char alphabet[] = "0123456789abcdefABCDEF:.:.x ";
	for(; iter < FUZZ_ITERS*10; iter++){
		char s[48]; size_t n = rnd_n(sizeof(s));
		for(size_t j = 0; j < n; j++) s[j] = alphabet[rnd_n(sizeof(alphabet)-1)];
		s[n] = 0;
		uint8_t ref[16] = {0};
		if(inet_pton(AF_INET6, s, ref) != 1){
			memset(ref, 0, 16);
			uint8_t v4[4];
			if(inet_pton(AF_INET, s, v4) == 1){ ref[10] = ref[11] = 0xff; memcpy(ref+12, v4, 4); }
		}
		ip_addr_t a = ip_from_string(s);
		FCHECK(!memcmp(a.bytes, ref, 16), "ip_from_string(\"%s\") disagrees with inet_pton", s);
	}

}

/* ==================== network interfaces ==================== */

static int count_open_fds(void){
	int n = 0;
	for(int fd = 0; fd < 4096; fd++) n += fcntl(fd, F_GETFD) != -1;
	return n;
}
// Reference MTU straight from the OS, or -1 if it can't be read
static int ref_mtu(const char* name){
	struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0) return -1;
	int r = ioctl(s, SIOCGIFMTU, &ifr);
	close(s);
	return r ? -1 : ifr.ifr_mtu;
}

static void test_interfaces(void){
	char name[INTERFACE_STR_MAX_LEN];
	CHECK(INTERFACE_STR_MAX_LEN >= IFNAMSIZ, "INTERFACE_STR_MAX_LEN %zu < IFNAMSIZ", INTERFACE_STR_MAX_LEN);

	CHECK(interface_from_str("definitely-not-an-if") == 0, "bogus interface found");
	CHECK(interface_from_str("") == 0, "empty interface name found");
	uint32_t lo = interface_from_str("lo"); if(!lo) lo = interface_from_str("lo0");
	CHECK(lo != 0, "loopback interface not found");

	// interface_to_str: invalid indices give "", valid ones round trip through interface_from_str
	memset(name, 'X', INTERFACE_STR_MAX_LEN);
	interface_to_str(0, name);
	CHECK(name[0] == 0, "interface_to_str(0) = \"%.*s\"", (int)INTERFACE_STR_MAX_LEN, name);
	memset(name, 'X', INTERFACE_STR_MAX_LEN);
	interface_to_str(0x7fffffff, name);
	CHECK(name[0] == 0, "interface_to_str(bogus) = \"%.*s\"", (int)INTERFACE_STR_MAX_LEN, name);
	interface_to_str(lo, name);
	CHECK(!strcmp(name, "lo") || !strcmp(name, "lo0"), "loopback name \"%s\"", name);

	// interface_mtu: invalid indices give 0
	CHECK(interface_mtu(0) == 0, "interface_mtu(0) = %zu", interface_mtu(0));
	CHECK(interface_mtu(0x7fffffff) == 0, "interface_mtu(bogus) = %zu", interface_mtu(0x7fffffff));

	// Every interface the OS lists: name <-> index round trip, MTU agrees with the OS
	struct ifaddrs* ifap;
	if(getifaddrs(&ifap)){ CHECK(0, "getifaddrs"); return; }
	int n_if = 0;
	for(struct ifaddrs* ifa = ifap; ifa; ifa = ifa->ifa_next){
		// getifaddrs lists an interface once per address; only check the first occurrence
		bool dup = false;
		for(struct ifaddrs* p = ifap; p != ifa; p = p->ifa_next) if(!strcmp(p->ifa_name, ifa->ifa_name)){ dup = true; break; }
		if(dup) continue;
		n_if++;
		uint32_t idx = interface_from_str(ifa->ifa_name);
		CHECK(idx != 0, "interface_from_str(\"%s\") = 0", ifa->ifa_name);
		memset(name, 'X', INTERFACE_STR_MAX_LEN);
		interface_to_str(idx, name);
		CHECK(memchr(name, 0, INTERFACE_STR_MAX_LEN) && !strcmp(name, ifa->ifa_name), "interface_to_str(%u) = \"%.*s\", expected \"%s\"", idx, (int)INTERFACE_STR_MAX_LEN, name, ifa->ifa_name);
		int ref = ref_mtu(ifa->ifa_name);
		size_t mtu = interface_mtu(idx);
		if(ref < 0) CHECK(mtu == 0, "interface_mtu(%s) = %zu but the OS reports none", ifa->ifa_name, mtu);
		else CHECK(mtu == (size_t)ref, "interface_mtu(%s) = %zu, OS reports %d", ifa->ifa_name, mtu, ref);
	}
	freeifaddrs(ifap);
	CHECK(n_if > 0, "no interfaces listed");

	// Random indices: either invalid (empty name, 0 MTU) or a real interface that round trips
	size_t iter = 0;
	for(; iter < 2000; iter++){
		uint32_t idx = (uint32_t)(rnd_n(2) ? rnd_n(64) : rnd());
		char ref[IFNAMSIZ];
		bool valid = if_indextoname(idx, ref) != 0;
		memset(name, 'X', INTERFACE_STR_MAX_LEN);
		interface_to_str(idx, name);
		FCHECK(memchr(name, 0, INTERFACE_STR_MAX_LEN), "interface_to_str(%u) not terminated", idx);
		FCHECK(valid ? !strcmp(name, ref) && interface_from_str(name) == idx : name[0] == 0, "interface_to_str(%u) = \"%s\" (valid=%d)", idx, name, valid);
		if(!valid) FCHECK(interface_mtu(idx) == 0, "interface_mtu(%u) = %zu for invalid index", idx, interface_mtu(idx));
	}

	// interface_mtu must not leak its temporary socket, on success or failure
	int fds = count_open_fds();
	for(int i = 0; i < 200; i++){ interface_mtu(lo); interface_mtu(0x7fffffff); }
	int leaked = count_open_fds() - fds;
	CHECK(leaked == 0, "interface_mtu leaked %d file descriptors over 400 calls", leaked);

	// x_udp_reflect(extinfo) agrees with interface_to_str/interface_mtu
	static const char* dests[] = {"127.0.0.1", "::1"};
	for(int i = 0; i < 2; i++){
		x_socket_t s = x_udp_auto();
		remote_t r = {0};
		CHECK(x_udp_reflect(s, ip_from_string(dests[i]), &r, true), "reflect %s", dests[i]);
		interface_to_str(r.interface, name);
		CHECK(r.interface == lo, "reflect %s picked interface %u (\"%s\"), expected loopback %u", dests[i], r.interface, name, lo);
		CHECK(r.mtu > 0 && r.mtu + 48 == interface_mtu(r.interface), "reflect %s mtu %u vs interface_mtu %zu", dests[i], r.mtu, interface_mtu(r.interface));
		r = (remote_t){.interface = 123, .mtu = 456};
		CHECK(x_udp_reflect(s, ip_from_string(dests[i]), &r, false) && r.interface == 0 && r.mtu == 0, "reflect %s without extinfo: interface %u mtu %u", dests[i], r.interface, r.mtu);
		x_socket_free(s);
	}
}

/* ==================== UDP ==================== */

static uint16_t sock_port(x_socket_t s){
	struct sockaddr_in6 a; socklen_t l = sizeof(a);
	if(getsockname(s, (struct sockaddr*)&a, &l)) return 0;
	return ntohs(a.sin6_port);
}

// Read with a deadline (sockets are non-blocking)
static int read_wait(x_socket_t s, remote_t* from, void* buf, size_t max, uint64_t timeout_us){
	uint64_t end = now_us() + timeout_us;
	for(;;){
		int r = x_udp_next_read(s, from, buf, max);
		if(r >= 0 || now_us() > end) return r;
		struct timespec ts = {0, 200000}; nanosleep(&ts, 0);
	}
}

static void test_udp(void){
	remote_t bind6 = {.addr = ip_from_string("::1")}, bind_any = {0};
	x_socket_t srv = x_udp_bound(bind6);
	CHECK(srv != X_SOCKET_INVALID, "bind ::1");
	x_socket_t srv_any = x_udp_bound(bind_any);
	CHECK(srv_any != X_SOCKET_INVALID, "bind ::");
	x_socket_t cli = x_udp_auto();
	CHECK(cli != X_SOCKET_INVALID, "udp_auto");
	if(srv == X_SOCKET_INVALID || srv_any == X_SOCKET_INVALID || cli == X_SOCKET_INVALID) return;
	CHECK(x_udp_opts(srv, 1<<20, 1<<20) && x_udp_opts(cli, 1<<16, 0), "udp_opts");
	uint16_t port = sock_port(srv), port_any = sock_port(srv_any);
	CHECK(port && port_any && port != port_any, "ports %u %u", port, port_any);

	// Binding the same address+port twice fails
	remote_t dup = bind6; dup.port = port;
	x_socket_t s2 = x_udp_bound(dup);
	CHECK(s2 == X_SOCKET_INVALID, "double bind succeeded");
	if(s2 != X_SOCKET_INVALID) x_socket_free(s2);

	uint8_t buf[2048], out[2048];
	remote_t from;
	CHECK(x_udp_next_read(srv, &from, out, sizeof(out)) == -1, "read on empty socket");

	// v6 loopback
	remote_t to = {.addr = ip_from_string("::1"), .port = port};
	rnd_bytes(buf, 1000);
	CHECK(x_udp_send(cli, to, buf, 1000), "send v6");
	memset(&from, 0, sizeof(from));
	int r = read_wait(srv, &from, out, sizeof(out), 1000000);
	CHECK(r == 1000 && !memcmp(out, buf, 1000), "recv v6 r=%d", r);
	char s[IP_STR_MAX_LEN]; ip_to_string(from.addr, s);
	CHECK(!strcmp(s, "::1") && from.port == sock_port(cli), "from %s port %u (client port %u)", s, from.port, sock_port(cli));

	// v4 via dual-stack socket, and reply back to the reported sender
	to = (remote_t){.addr = ip_from_string("127.0.0.1"), .port = port_any};
	CHECK(x_udp_send(cli, to, buf, 10), "send v4");
	r = read_wait(srv_any, &from, out, sizeof(out), 1000000);
	ip_to_string(from.addr, s);
	CHECK(r == 10 && !strcmp(s, "127.0.0.1") && from.port == sock_port(cli), "recv v4 r=%d from %s:%u", r, s, from.port);
	CHECK(x_udp_send(srv_any, from, "pong", 4), "reply");
	r = read_wait(cli, 0, out, sizeof(out), 1000000);
	CHECK(r == 4 && !memcmp(out, "pong", 4), "reply recv r=%d", r);

	// Zero-length datagram, and truncation to maxlen
	to = (remote_t){.addr = ip_from_string("::1"), .port = port};
	CHECK(x_udp_send(cli, to, buf, 0), "send empty");
	r = read_wait(srv, 0, out, sizeof(out), 1000000);
	CHECK(r == 0, "empty datagram r=%d", r);
	CHECK(x_udp_send(cli, to, buf, 100), "send 100");
	memset(out, 0xee, 100);
	r = read_wait(srv, 0, out, 10, 1000000);
	CHECK(r == 10 && !memcmp(out, buf, 10) && out[10] == 0xee, "truncated read r=%d", r);
	CHECK(x_udp_next_read(srv, 0, out, sizeof(out)) == -1, "truncated remainder was not discarded");

	// Oversized datagram fails
	static uint8_t huge[70000];
	CHECK(!x_udp_send(cli, to, huge, sizeof(huge)), "70000 byte send succeeded");

	// reflect: which local address would be used for a destination
	remote_t refl = {0};
	x_socket_t rs = x_udp_auto();
	CHECK(x_udp_reflect(rs, ip_from_string("127.0.0.1"), &refl, true), "reflect v4 loopback");
	ip_to_string(refl.addr, s);
	CHECK(!strcmp(s, "127.0.0.1") && refl.mtu > 0 && refl.mtu <= 65535-48, "reflect v4 got %s mtu %u", s, refl.mtu);
	// Fresh socket: on macOS, a socket that reflected to a v4 address can't reflect to a v6 one afterwards (EINVAL)
	x_socket_t rs6 = x_udp_auto();
	refl = (remote_t){0};
	CHECK(x_udp_reflect(rs6, ip_from_string("::1"), &refl, true), "reflect v6 loopback");
	ip_to_string(refl.addr, s);
	CHECK(!strcmp(s, "::1") && refl.mtu > 0, "reflect v6 got %s mtu %u", s, refl.mtu);
	x_socket_free(rs6);
	// The socket must still be usable (disconnected) afterwards
	CHECK(x_udp_send(rs, to, "z", 1) && read_wait(srv, 0, out, 10, 1000000) == 1 && out[0] == 'z', "socket unusable after reflect");
	x_socket_free(rs);

	// Fuzz: random sizes and payloads, delivered in order and intact on loopback
	size_t iter = 0;
	for(; iter < FUZZ_ITERS/10; iter++){
		size_t n = rnd_n(1473);
		rnd_bytes(buf, n);
		FCHECK(x_udp_send(cli, to, buf, n), "send %zu", n);
		r = read_wait(srv, &from, out, sizeof(out), 1000000);
		FCHECK(r == (int)n && !memcmp(out, buf, n), "recv %zu got %d", n, r);
	}

	x_socket_free(srv); x_socket_free(srv_any); x_socket_free(cli);
}

/* ==================== event queues ==================== */

// Wait for an event (unlocking the queue each time) until one has any of `mask`'s bits, or the deadline. Returns that event, or a TIMEOUT event
static x_event_t wait_for(x_event_queue_t* q, uint32_t mask, uint64_t timeout_us){
	uint64_t end = now_us() + timeout_us;
	for(;;){
		uint64_t t = now_us();
		if(t >= end) return (x_event_t){X_EVENT_TIMEOUT, {0}};
		x_event_t ev = x_event_queue_wait(q, end-t);
		x_event_queue_unlock(q);
		if(ev.type & mask) return ev;
	}
}
static void drain(x_event_queue_t* q){
	for(int i = 0; i < 1000; i++){
		x_event_t ev = x_event_queue_wait(q, 0);
		x_event_queue_unlock(q);
		if(ev.type == X_EVENT_TIMEOUT) return;
	}
}

static void test_event_queue(void){
	x_event_queue_t q;
	CHECK(x_event_queue_init(&q), "init");

	// Timeout with nothing registered
	uint64_t t0 = now_us();
	x_event_t ev = x_event_queue_wait(&q, 30000);
	x_event_queue_unlock(&q);
	uint64_t dt = now_us()-t0;
	CHECK(ev.type == X_EVENT_TIMEOUT, "type %u", ev.type);
	CHECK(dt >= 25000 && dt < 500000, "30ms timeout took %llums", (unsigned long long)dt/1000);
	t0 = now_us();
	ev = x_event_queue_wait(&q, 0);
	x_event_queue_unlock(&q);
	CHECK(ev.type == X_EVENT_TIMEOUT && now_us()-t0 < 50000, "zero timeout");

	// Immediate wake
	x_event_queue_wake(&q, 0);
	ev = wait_for(&q, X_EVENT_WAKE, 1000000);
	CHECK(ev.type == X_EVENT_WAKE, "wake(0) type %u", ev.type);
	ev = x_event_queue_wait(&q, 20000); x_event_queue_unlock(&q);
	CHECK(ev.type == X_EVENT_TIMEOUT, "wake fired twice (type %u)", ev.type);

	// Delayed wake
	t0 = now_us();
	x_event_queue_wake(&q, 50000);
	ev = wait_for(&q, X_EVENT_WAKE, 2000000);
	dt = now_us()-t0;
	CHECK(ev.type == X_EVENT_WAKE && dt >= 45000 && dt < 1000000, "wake(50ms) type %u after %llums", ev.type, (unsigned long long)dt/1000);
	// An earlier wake overrides a later one
	t0 = now_us();
	x_event_queue_wake(&q, 2000000);
	x_event_queue_wake(&q, 30000);
	ev = wait_for(&q, X_EVENT_WAKE, 3000000);
	dt = now_us()-t0;
	CHECK(ev.type == X_EVENT_WAKE && dt < 1000000, "earlier wake did not override later one (%llums)", (unsigned long long)dt/1000);
	// A later wake does not delay an earlier one
	t0 = now_us();
	x_event_queue_wake(&q, 30000);
	x_event_queue_wake(&q, 2000000);
	ev = wait_for(&q, X_EVENT_WAKE, 3000000);
	dt = now_us()-t0;
	CHECK(ev.type == X_EVENT_WAKE && dt < 1000000, "later wake delayed earlier one (%llums)", (unsigned long long)dt/1000);
	drain(&q);

	// Sockets
	x_socket_t srv = x_udp_bound((remote_t){.addr = ip_from_string("::1")});
	x_socket_t cli = x_udp_auto();
	remote_t to = {.addr = ip_from_string("::1"), .port = sock_port(srv)};
	CHECK(x_event_queue_add(&q, srv, (x_userdata_t){.u32 = 0x1234}), "add");
	CHECK(x_event_queue_add(&q, srv, (x_userdata_t){.u32 = 0x1234}), "re-add same socket");
	ev = wait_for(&q, X_EVENT_WRITABLE, 1000000);
	CHECK((ev.type & X_EVENT_WRITABLE) && ev.data.u32 == 0x1234, "initial writable type %u data %x", ev.type, ev.data.u32);
	drain(&q);
	x_udp_send(cli, to, "hi", 2);
	ev = wait_for(&q, X_EVENT_READABLE, 1000000);
	CHECK((ev.type & X_EVENT_READABLE) && ev.data.u32 == 0x1234, "readable type %u data %x", ev.type, ev.data.u32);
	uint8_t out[16];
	CHECK(x_udp_next_read(srv, 0, out, sizeof(out)) == 2, "read after readable");
	drain(&q);

	// Removed sockets produce no events
	CHECK(x_event_queue_remove(&q, srv), "remove");
	x_udp_send(cli, to, "hi", 2);
	ev = wait_for(&q, X_EVENT_READABLE, 100000);
	CHECK(ev.type == X_EVENT_TIMEOUT, "event after remove type %u", ev.type);
	x_udp_next_read(srv, 0, out, sizeof(out));

	// Close emits X_EVENT_CLOSE
	CHECK(x_event_queue_add(&q, srv, (x_userdata_t){.u32 = 0x5678}), "re-add");
	//drain(&q);
	x_udp_close(srv);
	ev = wait_for(&q, X_EVENT_CLOSE, 1000000);
	CHECK((ev.type & X_EVENT_CLOSE) && ev.data.u32 == 0x5678, "close event type %u data %x", ev.type, ev.data.u32);
	x_socket_free(srv);
	x_socket_free(cli);
	x_event_queue_destroy(&q);
}

// Many sockets, many packets: every packet is delivered exactly once via readable events (edge-triggered: read until empty)
static void fuzz_event_queue(void){
	enum{ NS = 8 };
	x_event_queue_t q;
	if(!x_event_queue_init(&q)){ CHECK(0, "init"); return; }
	x_socket_t s[NS]; remote_t to[NS];
	x_socket_t cli = x_udp_auto();
	x_udp_opts(cli, 1<<20, 0);
	for(int i = 0; i < NS; i++){
		s[i] = x_udp_bound((remote_t){.addr = ip_from_string("::1")});
		x_udp_opts(s[i], 0, 1<<20);
		to[i] = (remote_t){.addr = ip_from_string("::1"), .port = sock_port(s[i])};
		x_event_queue_add(&q, s[i], (x_userdata_t){.u32 = (uint32_t)i+1});
	}
	drain(&q);
	size_t iter = 0;
	for(; iter < FUZZ_ITERS/100; iter++){
		uint32_t sent[NS] = {0}, got[NS] = {0}, total = 0, rcvd = 0;
		size_t batch = 1+rnd_n(64);
		for(size_t k = 0; k < batch; k++){
			int i = (int)rnd_n(NS);
			uint32_t msg[2] = {(uint32_t)i, sent[i]++};
			x_udp_send(cli, to[i], msg, sizeof(msg));
			total++;
		}
		uint64_t end = now_us() + 2000000;
		while(rcvd < total && now_us() < end){
			x_event_t ev = x_event_queue_wait(&q, 100000);
			x_event_queue_unlock(&q);
			if(!(ev.type & X_EVENT_READABLE)) continue;
			int i = (int)ev.data.u32-1;
			FCHECK(i >= 0 && i < NS, "event for unknown socket data %u", ev.data.u32);
			uint32_t msg[2]; int r;
			while((r = x_udp_next_read(s[i], 0, msg, sizeof(msg))) >= 0){
				FCHECK(r == 8 && msg[0] == (uint32_t)i && msg[1] == got[i], "socket %d got [%u,%u] expected [%d,%u]", i, msg[0], msg[1], i, got[i]);
				got[i]++; rcvd++;
			}
		}
		FCHECK(rcvd == total, "received %u of %u packets (lost readable event?)", rcvd, total);
	}
	for(int i = 0; i < NS; i++) x_socket_free(s[i]);
	x_socket_free(cli);
	x_event_queue_destroy(&q);
}

// Several threads waiting on one queue: each wake/event goes to exactly one thread, and none deadlock
static x_event_queue_t mt_q;
static _Atomic int mt_wakes, mt_stop;
static void* mt_waiter(void* _){
	(void)_;
	while(!atomic_load(&mt_stop)){
		x_event_t ev = x_event_queue_wait(&mt_q, 50000);
		x_event_queue_unlock(&mt_q);
		if(ev.type == X_EVENT_WAKE) atomic_fetch_add(&mt_wakes, 1);
	}
	return 0;
}
static void test_event_queue_threads(void){
	enum{ NT = 4, NW = 200 };
	CHECK(x_event_queue_init(&mt_q), "init");
	pthread_t th[NT];
	for(int i = 0; i < NT; i++) pthread_create(&th[i], 0, mt_waiter, 0);
	int lost = 0;
	for(int i = 0; i < NW; i++){
		int before = atomic_load(&mt_wakes);
		x_event_queue_wake(&mt_q, 0);
		uint64_t end = now_us() + 1000000;
		while(atomic_load(&mt_wakes) == before && now_us() < end){ struct timespec ts = {0, 100000}; nanosleep(&ts, 0); }
		if(atomic_load(&mt_wakes) == before) lost++;
	}
	atomic_store(&mt_stop, 1);
	for(int i = 0; i < NT; i++) pthread_join(th[i], 0);
	CHECK(!lost, "%d of %d wakes never delivered", lost, NW);
	CHECK(atomic_load(&mt_wakes) <= NW, "%d wakes delivered for %d wake calls", atomic_load(&mt_wakes), NW);
	x_event_queue_destroy(&mt_q);
}

/* ==================== main ==================== */

#define RUN(fn) do{ int f0 = failed; printf("%s\n", #fn); fn(); if(failed != f0) printf("\x1b[31m  %d failures\x1b[m\n", failed-f0); }while(0)

int main(int argc, char** argv){
	setvbuf(stdout, 0, _IONBF, 0);
	seed = argc > 1 ? strtoull(argv[1], 0, 0) : now_us() ^ (uint64_t)time(0);
	if(!seed) seed = 1;
	rng_state = seed;
	printf("seed=%llu\n", (unsigned long long)seed);

	const char* t = getenv("TMPDIR");
	snprintf(tmpdir, sizeof(tmpdir), "%s/x_test_XXXXXX", t && *t ? t : "/tmp");
	if(!mkdtemp(tmpdir)){ perror("mkdtemp"); return 1; }

	RUN(test_files);
	RUN(fuzz_files);
	RUN(test_pages);
	RUN(test_random);
	RUN(test_ip);
	RUN(test_interfaces);
	RUN(test_udp);
	RUN(test_event_queue);
	RUN(fuzz_event_queue);
	RUN(test_event_queue_threads);

	// not x_remove: it can't remove directories on macOS
	rmdir(path("d"));
	rmdir(tmpdir);
	if(failed) printf("\x1b[31m%d/%d checks failed (seed=%llu)\x1b[m\n", failed, failed+passed, (unsigned long long)seed);
	else printf("\x1b[32mAll %d checks passed\x1b[m\n", passed);
	return failed != 0;
}
