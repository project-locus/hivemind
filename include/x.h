#pragma once

#ifdef __cplusplus
	#ifdef _MSC_VER
		#pragma warning(push)
		#pragma warning(disable : 4838 2397)
	#else
		#pragma GCC diagnostic push
		#pragma GCC diagnostic ignored "-Wc++11-narrowing"
		#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
	#endif
#endif

#include <limits.h>
#include <stdlib.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#undef NOMINMAX
// Top tier windows trolling
#undef near
#undef far
#undef pascal
#undef cdecl

#if UINTPTR_MAX == UINT64_MAX
#define SIZEOF_X_HANDLE 8
#else
#define SIZEOF_X_HANDLE 4
#endif
typedef SSIZE_T ssize_t;
typedef SIZE_T size_t;
typedef HANDLE x_file_t;
typedef struct{
	HANDLE hFind;
	_WIN32_FIND_DATAA a;
}* x_folder_list_t;
typedef SOCKET x_socket_t;
static const x_file_t X_FILE_INVALID = (x_file_t) INVALID_HANDLE_VALUE;
static const x_socket_t X_SOCKET_INVALID = (x_socket_t) INVALID_SOCKET;
#else
#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <net/if.h>

#define SIZEOF_X_HANDLE 4
typedef int x_file_t;
typedef DIR* x_folder_list_t;
static const x_file_t X_FILE_INVALID = (x_file_t) -1;
typedef int x_socket_t;
static const x_socket_t X_SOCKET_INVALID = (x_socket_t) -1;
static const size_t INTERFACE_STR_MAX_LEN = IFNAMSIZ;
#endif

typedef union x_userdata{
	void* ptr;
	x_socket_t socket;
	uint32_t u32;
	uintptr_t uptr;
} x_userdata_t;

typedef struct x_event{
	uint32_t type;
	x_userdata_t data;
} x_event_t;

#define _X_INLINE_EVENT_BUFFER 20
#if defined(__linux__)

#include <sys/epoll.h>

typedef struct x_event_queue{
	int _fd, _tfd;
	_Atomic uint64_t _min_wake;
	_Atomic uint32_t _bits;
	struct epoll_event _ev[_X_INLINE_EVENT_BUFFER];
} x_event_queue_t;
#else
typedef struct x_event_queue{
	int _fd; _Atomic uint32_t _bits;
	_Atomic uint64_t _min_wake;
	struct{ uint32_t typ, udata[sizeof(uintptr_t)>>2]; } _ev[_X_INLINE_EVENT_BUFFER];
} x_event_queue_t;
#endif

static const uint64_t X_FILE_NOT_FOUND = 0, X_FILE_UNKNOWN = 0,
	X_FILE_TYPE_FILE = 1,
	X_FILE_TYPE_FOLDER = 2,
	X_FILE_TYPE_SPECIAL = 3;
typedef struct x_stat{
	uint64_t type:4;
	uint64_t modified:60;
	uint64_t size;
} x_stat_t;

static const uint32_t X_EVENT_SIGNAL = 256, X_EVENT_TIMEOUT = 512, X_EVENT_WAKE = 1024, X_EVENT_EOF = 8192, X_EVENT_CLOSE = 16, X_EVENT_READABLE = 1, X_EVENT_WRITABLE = 4, X_EVENT_ERROR = 8;

typedef struct ip_addr{ union{
	struct{ uint8_t bytes[16]; };
	struct{ uint16_t words[8]; };
	struct{ uint32_t dwords[4]; };
}; } ip_addr_t;

typedef struct remote{
	ip_addr_t addr;
	uint16_t port, mtu;
	uint32_t interface;
} remote_t;

static const size_t IP_STR_MAX_LEN = 40;

// Create a directory
static bool x_mkdir(const char* name);

// Delete a file or empty directory
static bool x_remove(const char* name);

// Open a directory for listing files
static x_folder_list_t x_dir_open(const char* name);
// Get the next file in a directory listing, or 0 (NULL) if there are no more files. The returned string is valid until the next call to x_dir_next() or x_dir_close()
static char* x_dir_next(x_folder_list_t dir);
// Close a directory listing
static void x_dir_close(x_folder_list_t dir);

// Open a file from a null-terminated string specifying the pathname
static x_file_t x_open(const char* name, unsigned flags);

// Move a file atomically
static bool x_move(const char* old_name, const char* new_name);


// Get the size of a file in bytes
static uint64_t x_getsize(x_file_t fd);

// Read `count` bytes from fd, starting at offset `start`. Data is written to `buf`, which is expected to be valid, writable memory for at least `count` bytes. The number of bytes actually read is returned, which may be less than the number of bytes requested if the end of the file was found, or 0 if the file could not be read from
static size_t x_read(x_file_t fd, void* buf, uint64_t start, size_t count);

// Write `count` bytes to fd, starting at offset `start`. Data is read from `buf`, which is expected to be valid, readable memory for at least `count` bytes. The number of bytes actually written is returned, which may be less than the number of bytes requested under special circumstances (old systems, disk full), or 0 if the file could not be written to
static size_t x_write(x_file_t fd, const void* buf, uint64_t start, size_t count);

// Set the size of a file in bytes. If the size is smaller than the current size, the file is truncated, otherwise it is expanded and the additional bytes are all set to 0
static bool x_setsize(x_file_t fd, uint64_t sz);

// Close a file. The x_file_t becomes invalid before the function returns and new calls to x_open may create x_file_t handles that compare == to this one. It is best practice to completely forget the old file handle and never assume anything about it after it has been closed, much like you would with a pointer that has been free()'d
static void x_close(x_file_t fd);

// Maps a region of a x_file_t to memory, from page `off` (byte `off * X_PAGE_SIZE`) to, and excluding, page `off+sz` (byte `(off+sz) * X_PAGE_SIZE`)
// If copy == false, the memory region returned will be a live view into the file. Anything written to this memory will be written back to the file and visible to any other process that has also mapped the same region. Note that mixing writes via both x_read()/x_write() and accessing the mapped memory results in unpredictable behavior. Writes may fail, be torn, or not be visible immediately.
// If copy == true, the memory region will be populated with a copy of the file's contents, and any modifications will not be written back to the file, and effectively becomes private memory much like x_pagealloc(). It is then safe to x_read()/x_write() the region, as it will not affect the mapped memory in any way
// In either case, the returned pointer should be freed with x_pagefree()
// On failure, 0 (NULL) is returned
static void* x_mapfile(x_file_t fd, uint64_t off, size_t sz, bool copy);

// Allocate `sz` pages (`sz * X_PAGE_SIZE` bytes) of memory, with all bytes initially set to 0
static void* x_pagealloc(size_t sz);

// Free memory returned by x_pagealloc() or x_mapfile(). `sz` must exactly match the size of the allocation/mapping. Freeing only part of an allocation/mapping is undefined behavior.
static void x_pagefree(void* ptr, size_t sz);

// Touch a page range. This hints to the OS to bring the pages into cache if they aren't already
// This function works on all kinds of memory, including memory returned by `x_pagealloc`, `x_mapfile`, or any other external source.
// `where` must be page-aligned and `sz` is measured in pages (`sz * X_PAGE_SIZE` bytes)
static void x_touch_pages(void* where, size_t sz);

// Invalidate a page range. After this call, the contents of any individual cache line within the invalidated region is either the last written value, or zero for pages returned by `x_pagealloc`-pages, or the contents of the underlying file at that region for `x_mapfile`-pages
// `where` must be page-aligned and `sz` is measured in pages (`sz * X_PAGE_SIZE` bytes)
static void x_invalidate_pages(void* where, size_t sz);

// Synchronize a page range. After this call, all contents of these pages have been copied back to the underlying file
// `where` must be page-aligned and `sz` is measured in pages (`sz * X_PAGE_SIZE` bytes)
static void x_sync_pages(void* where, size_t sz);

// Check if a file exists and get metadata
static x_stat_t x_stat(const char* name);

// Page size used by X (always 65536). Specifically, x_mapfile()/x_pagealloc()/x_pagefree() have all their size/offset arguments measured in pages of 65536 bytes. Converting from pages to bytes or vice versa is as simple a shifting right (>>) or left (<<) 16 bits respectively
static const size_t X_PAGE_SIZE = 65536;

// Parse an IP, such as "1.2.3.4", "2001:db8:1001:2002:db8::1234", or "::ffff:192.168.1.42", into an `ip_addr_t`
static ip_addr_t ip_from_string(const char* str);

enum ip_kind{
	IP_KIND_INVALID = 0,
	IP_KIND_V4 = 4, IP_KIND_V6 = 6,
};
// Stringify an ip_addr_t into a human-readable string, such as "1.2.3.4" or "2001:db8:1001:2002:db8::1234"
static enum ip_kind ip_to_string(ip_addr_t addr, char out[IP_STR_MAX_LEN]);

// Find the index of a network interface from its name, such as "eth0" or "en0". Returns 0 if the interface was not found (0 is never a valid interface index).
static uint32_t interface_from_str(const char* interface_name);

// Get the name of a network interface from its index, such as "eth0" or "en0". Fills `out` with an empty string the interface was invalid (e.g 0 is never a valid interface index).
static void interface_to_str(uint32_t i, char out[INTERFACE_STR_MAX_LEN]);

// Find an interface's raw MTU (which will not subtract IP/TCP/UDP/... header sizes)
static size_t interface_mtu(uint32_t i);

// Create a new UDP socket which will automatically select a port/address/interface as needed, ideal for clients
static x_socket_t x_udp_auto(void);

// Get information about which IP and port would be used to send a packet to a specific address, as well as optionally the interface and its MTU for that path (if extinfo is true). The MTU here only counts the maximum UDP payload length, Appropriate IPv4/IPv6 or UDP header sizes are subtracted for you.
// This function is only guaranteed to succeed once per socket
static bool x_udp_reflect(x_socket_t s, ip_addr_t to, remote_t* from, bool extinfo);

// Set socket options for a UDP socket, specifically the send and receive buffer sizes. Note that these sizes are not guaranteed to be set to exactly what you specify, the operating system may silently round them up or down, and there may be hard limits on how large they can be.
static bool x_udp_opts(x_socket_t s, size_t send_buf, size_t recv_buf);

// Create a new UDP socket with manually specified port/address/interface, ideal for servers.
// Pass `NULL` to `interface` to automatically pick the interface based on `addr`, or listen on all interfaces if `addr` is zero (::)
// Pass `0` to `port` to have a port picked for you, usually in the "ephemeral range" (e.g 32768-60999 on linux, 49152-65535 elsewhere)
static x_socket_t x_udp_bound(remote_t addr);

// Send a UDP packet from `msg` of exactly `msglen` bytes to the specified IP and port. The address/port to send from, as well as the interface, is determined by `sock` and how it was created (see `x_udp_auto` and `x_udp_bound`). UDP supports message sizes as low as zero bytes, max message size is dependent on a lot of factors but a safe limit is 1472 bytes. Anything more will fail (return false)
static bool x_udp_send(x_socket_t sock, remote_t to, const void* msg, size_t msglen);

// Read a UDP packet into `msg` of up to `maxlen` bytes (any additional bytes that did not fit are discarded). The IP and port are written to `from` if it is not null. The address/port to receive from, as well as the interface, is determined by `sock` and how it was created (see `x_udp_auto` and `x_udp_bound`). UDP supports message sizes as low as zero bytes or, in theory, as high as 65527 bytes, however most real-world networks will impose much lower limits (typically around 1500 bytes). On success, the number of bytes read is returned. On failure, -1 is returned.
static int x_udp_next_read(x_socket_t sock, remote_t* from, void* msg, size_t maxlen);

// Close a UDP socket. This will free up the address/port that was used by this socket, and emit an X_EVENT_CLOSE event for that socket.
static void x_udp_close(x_socket_t sock);
// Free a socket. Any operations on this socket become invalid. The socket is closed if it was not already. Note that if this socket was already attached to an event queue, you may still receive delayed events up until its corresponding close event (which will not be fired unless you called `x_*_close`)
static void x_socket_free(x_socket_t sock);

// Construct an event queue object. If construction fails for any reason, false is returned and `out` is unmodified
static bool x_event_queue_init(x_event_queue_t* out);

// Add a socket to an event queue, which will emit X_EVENT_READABLE/X_EVENT_WRITABLE/X_EVENT_CLOSED events when the socket becomes readable/writable/closed respectively
static bool x_event_queue_add(x_event_queue_t* queue, x_socket_t sock, x_userdata_t data);

// Wait for the next event, or up until `timeout` microseconds (in which case an X_EVENT_TIMEOUT event is returned), or a process signal is received (in which case an X_EVENT_SIGNAL event is returned). Waiting on the same event queue from multiple threads is well-defined: exactly one of the waiting threads will receive any given event. Which thread receives it is not defined, it may be different even for the same socket, and may not be evenly distributed. A `timeout` of -1 means to wait indefinitely until an event occurs.
static x_event_t x_event_queue_wait(x_event_queue_t* queue, uint64_t timeout);

// Remove a socket from an event queue, see `x_event_queue_add`.
static bool x_event_queue_remove(x_event_queue_t* queue, x_socket_t sock);

// Emits a X_EVENT_WAKE event on an event queue, optionally, after an amount of time has passed (`timeout` is provided in microseconds). Any thread currently blocked on a wait call will return. Note that multiple X_EVENT_WAKE events may be coalesced into one, and a wake event with an earlier timeout may cancel any wake event with a later timeout. This method is intended to be called from other threads and the relevant memory order semantics is memory_order_release on the calling thread and memory_order_acquire on the waiting thread.
static void x_event_queue_wake(x_event_queue_t* queue, uint64_t timeout);

// Destructs an event queue object, freeing all of its resources. It is invalid to call this while any thread is blocking on the queue.
static void x_event_queue_destroy(x_event_queue_t* q);

// Fills `data` with `len` bytes of high quality random bytes suitable for cryptographic purposes among many others.
static void x_randombytes(void* data, size_t len);

// Clears `data` of `len` bytes, setting them to zero in a crytpographically secure way (i.e it is constant time and will not be optimized away)
static void x_zerobytes(void* data, size_t len);


#ifdef _WIN32
#include <malloc.h>
#include <libloaderapi.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#endif
#define alloca _alloca

static const unsigned X_FILE_READONLY = 1;
static const unsigned X_FILE_SEQUENTIAL = 2;
static const unsigned X_FILE_READ_THROUGH = FILE_FLAG_NO_BUFFERING<<2;
static const unsigned X_FILE_WRITE_THROUGH = FILE_FLAG_WRITE_THROUGH<<2;
static x_file_t x_open(const char* name, unsigned flags){
	return (x_file_t) CreateFileA(name, GENERIC_READ | (flags&1 ? 0 : GENERIC_WRITE), FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		flags&1 ? OPEN_EXISTING : OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_POSIX_SEMANTICS | (flags&2 ? FILE_FLAG_SEQUENTIAL_SCAN : FILE_FLAG_RANDOM_ACCESS) | (flags>>2),
	NULL);
}

static uint64_t x_getsize(x_file_t fd){
	LARGE_INTEGER li;
	if (!GetFileSizeEx(fd, &li)) return 0;
	return li.QuadPart;
}

static size_t x_read(x_file_t fd, void* buf, uint64_t start, size_t count){
	DWORD bytesRead;
	OVERLAPPED overlapped = {0};
	overlapped.Offset = (DWORD) start;
	overlapped.OffsetHigh = (DWORD) (start >> 32);
	char* _buf = (char*) buf;
	#if SIZE_MAX > 0xffffffff
	if(count > 0xffffffff){
		// Do not "fix" what you do not understand
		// Ignorance sees bad code, but fast code is not for the ignorant
		// Learn the -O3 way and you will appreciate the beauty and fragility
		// of what you almost broke by being impatient
		do{
			DWORD tot = ReadFile(fd, _buf, 0xfffff000, &bytesRead, &overlapped) ? bytesRead : 0;
			if(tot < 0xfffff000)
				return (_buf-(char*)buf) + tot;
			_buf += 0xfffff000; count -= 0xfffff000;
			size_t b = _buf-(char*)buf;
			overlapped.Offset = b;
			overlapped.OffsetHigh = b>>32;
		}while(count > 0xffffffff);
		return (_buf-(char*)buf) + (ReadFile(fd, _buf, (DWORD) count, &bytesRead, &overlapped) ? bytesRead : 0);
	}
	#endif
	return ReadFile(fd, _buf, (DWORD) count, &bytesRead, &overlapped) ? bytesRead : 0;
}

static size_t x_write(x_file_t fd, const void* buf, uint64_t start, size_t count){
	DWORD bytesWritten;
	OVERLAPPED overlapped = {0};
	overlapped.Offset = (DWORD) start;
	overlapped.OffsetHigh = (DWORD) (start >> 32);
	const char* _buf = (const char*) buf;
	#if SIZE_MAX > 0xffffffff
	if(count > 0xffffffff){
		// See the comment in the x_read() implementation
		do{
			DWORD tot = WriteFile(fd, _buf, 0xfffff000, &bytesWritten, &overlapped) ? bytesWritten : 0;
			if(tot < 0xfffff000)
				return (_buf-(const char*)buf) + tot;
			_buf += 0xfffff000; count -= 0xfffff000;
			size_t b = _buf-(const char*)buf;
			overlapped.Offset = b;
			overlapped.OffsetHigh = b>>32;
		}while(count > 0xffffffff);
		return (_buf-(const char*)buf) + (WriteFile(fd, _buf, (DWORD) count, &bytesWritten, &overlapped) ? bytesWritten : 0);
	}
	#endif
	return WriteFile(fd, _buf, (DWORD) count, &bytesWritten, &overlapped) ? bytesWritten : 0;
}

static bool x_setsize(x_file_t fd, uint64_t sz){
	FILE_END_OF_FILE_INFO eof;
	eof.EndOfFile.QuadPart = sz;
	return SetFileInformationByHandle(fd, FileEndOfFileInfo, &eof, sizeof(eof));
}

static bool x_flush(x_file_t fd){ return FlushFileBuffers(fd); }

static void x_close(x_file_t fd){ CloseHandle(fd); }

static void* x_mapfile(x_file_t fd, uint64_t off, size_t sz, bool copy){
	HANDLE hMap = CreateFileMapping(fd, NULL, copy ? PAGE_WRITECOPY : PAGE_READWRITE, 0, 0, NULL);
	if (!hMap) return 0;
	void* ptr = MapViewOfFile(hMap, copy ? FILE_MAP_COPY : FILE_MAP_READ|FILE_MAP_WRITE, off >> 16, off << 16, sz << 16);
	CloseHandle(hMap);
	return ptr;
}

static void* x_pagealloc(size_t sz){
	return VirtualAlloc(0, sz<<16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}
static void x_pagefree(void* ptr, size_t sz){
	VirtualFree(ptr, 0, MEM_RELEASE) || UnmapViewOfFile(ptr);
}

static void x_touch_pages(void* where, size_t sz){
	WIN32_MEMORY_RANGE_ENTRY data[1] = {.VirtualAddress = where, .NumberOfBytes = sz<<16};
	PrefetchVirtualMemory(GetCurrentProcess(), 1, data, 0);
}

static void x_invalidate_pages(void* where, size_t sz){
	DiscardVirtualMemory(where, sz<<16);
}

static void x_sync_pages(void* where, size_t sz){
	FlushViewOfFile(where, sz<<16);
}

static x_stat_t x_stat(const char* name){
	x_stat_t ret;
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if(!GetFileAttributesExA(name, GetFileExInfoStandard, &fad)){
		ret.type = X_FILE_NOT_FOUND;
		ret.modified = 0;
		ret.size = 0;
		return ret;
	}
	ULARGE_INTEGER ull;
	ull.LowPart = fad.ftLastWriteTime.dwLowDateTime;
	ull.HighPart = fad.ftLastWriteTime.dwHighDateTime;
	// to milliseconds since unix epoch
	ret.type = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? X_FILE_TYPE_FOLDER :
		(fad.dwFileAttributes & (FILE_ATTRIBUTE_DEVICE|FILE_ATTRIBUTE_REPARSE_POINT)) ? X_FILE_TYPE_SPECIAL : X_FILE_TYPE_FILE;
	ret.modified = (ull.QuadPart - 116444736000000000ULL) / 10;
	ull.LowPart = fad.nFileSizeLow;
	ull.HighPart = fad.nFileSizeHigh;
	ret.size = ull.QuadPart;
	return ret;
}

static bool x_mkdir(const char* name){
	return CreateDirectoryA(name, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool x_remove(const char* name){
	return DeleteFileA(name) || RemoveDirectoryA(name);
}

static x_folder_list_t x_dir_open(const char* name){
	int len = strlen(name) + 3;
	char* buf;
	if(len < 256) buf = (char*) alloca(len);
	else buf = (char*) malloc(len);
	memcpy(buf, name, len-3);
	buf[len-3] = '\\'; buf[len-2] = '*'; buf[len-1] = 0;
	x_folder_list_t ret = (x_folder_list_t) malloc(sizeof(x_folder_list_t));
	HANDLE h = FindFirstFileA(buf, &ret->a);
	ret->a.cAlternateFileName[0] = 1;
	if(len >= 256) free(buf);
	ret->hFind = h;
	return ret;
}
static char* x_dir_next(x_folder_list_t dir){
	if(dir->a.cAlternateFileName[0]){
		dir->a.cAlternateFileName[0] = 0;
		return dir->a.cFileName;
	}
	bool success = FindNextFileA(dir->hFind, &dir->a);
	dir->a.cAlternateFileName[0] = 0;
	return success ? dir->a.cFileName : 0;
}
static void x_dir_close(x_folder_list_t dir){
	FindClose(dir->hFind);
	free(dir);
}

static bool x_move(const char* old_name, const char* new_name){
	// MoveFileExA() usually fails to replace a file that is still open
	return ReplaceFileA(new_name, old_name, 0, 0, 0, 0);
}

static void x_zerobytes(void* data, size_t len){
	SecureZeroMemory(data, len);
}
// On windows, we can basically pretend volatile == atomic (this is why intrin.h has no InterlockedLoad)
__declspec(selectany) BOOL (WINAPI* volatile ProcessPrng_)(PBYTE, SIZE_T) = 0;
static void x_randombytes(void* data, size_t len){
	BOOL (WINAPI* ProcessPrng_impl)(PBYTE, SIZE_T) = ProcessPrng_;
	if(!ProcessPrng_impl){
		void* sym = GetProcAddress(LoadLibraryA("bcryptprimitives.dll"), "ProcessPrng");
		if(!sym) abort();
		ProcessPrng_ = ProcessPrng_impl = (BOOL (WINAPI*)(PBYTE, SIZE_T))sym;
		// No acq/rel needed to publish newly mapped pages, page faults are served consistently with program order
	}
	ProcessPrng_impl(data, len);
}

#else
#define _FILE_OFFSET_BITS 64
#include <sys/mman.h>
#include <sys/stat.h>
#include <net/if.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <alloca.h>

static const unsigned X_FILE_READONLY = O_RDWR | O_CREAT; // (O_RDWR | O_CREAT) ^ X_FILE_READONLY == O_RDONLY
static const unsigned X_FILE_SEQUENTIAL = O_CLOEXEC; // flag that doesn't need to be AND'd out when passing to open()
#ifdef O_DIRECT
	static const unsigned X_FILE_READ_THROUGH = O_DIRECT;
	#define _X_OPEN_FLAG_MASK ~0
#else
	static const unsigned X_FILE_READ_THROUGH = O_ASYNC; // dummy flag that we're not gonna use
	#define _X_OPEN_FLAG_MASK ~O_ASYNC
#endif
static const unsigned X_FILE_WRITE_THROUGH = O_SYNC;
static x_file_t x_open(const char* name, unsigned flags){
	x_file_t f = (x_file_t) open(name, ((O_RDWR | O_CREAT) ^ (flags&_X_OPEN_FLAG_MASK)) | O_CLOEXEC, 0666);
#undef _X_OPEN_FLAG_MASK
	if(flags & X_FILE_SEQUENTIAL){
#ifdef POSIX_FADV_SEQUENTIAL
		posix_fadvise(f, 0, 0, POSIX_FADV_SEQUENTIAL);
#else
		fcntl(f, F_RDAHEAD, 1);
#endif
	}
#if !defined(O_DIRECT) && defined(F_NOCACHE)
	if(flags & X_FILE_READ_THROUGH){
		fcntl(f, F_NOCACHE, 1);
	}
#endif
	return f;
}

static uint64_t x_getsize(x_file_t fd){
	struct stat st;
	return fstat(fd, &st) ? 0 : (uint64_t)st.st_size;
}

static size_t x_read(x_file_t fd, void* buf, uint64_t start, size_t count){
	size_t r = pread(fd, buf, count, (off_t)start);
	return r == SIZE_MAX ? 0 : r;
}

static size_t x_write(x_file_t fd, const void* buf, uint64_t start, size_t count){
	size_t r = pwrite(fd, buf, count, (off_t)start);
	return r == SIZE_MAX ? 0 : r;
}

static bool x_setsize(x_file_t fd, uint64_t sz){
	return !ftruncate(fd, (off_t)sz);
}

static bool x_flush(x_file_t fd){ return !fsync(fd); }

static void x_close(x_file_t fd){ close(fd); }

static void* x_mapfile(x_file_t fd, uint64_t off, size_t sz, bool copy){
	void* ptr = mmap(NULL, sz << 16, PROT_READ | PROT_WRITE, copy ? MAP_PRIVATE : MAP_SHARED, fd, (off_t)(off << 16));
	return ptr == MAP_FAILED ? 0 : ptr;
}

static void* x_pagealloc(size_t sz){
	void* ptr = mmap(NULL, sz << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	return ptr == MAP_FAILED ? 0 : ptr;
}

static void x_pagefree(void* ptr, size_t sz){
	munmap(ptr, sz<<16);
}

static void x_touch_pages(void* where, size_t sz){
	madvise(where, sz<<16, MADV_WILLNEED);
}

static void x_invalidate_pages(void* where, size_t sz){
	madvise(where, sz<<16, MADV_DONTNEED);
}

static void x_sync_pages(void* where, size_t sz){
	msync(where, sz<<16, MS_ASYNC);
}

static x_stat_t x_stat(const char* name){
	struct stat st;
	x_stat_t ret;
	if(stat(name, &st) < 0){
		ret.type = X_FILE_NOT_FOUND;
		return ret;
	}
	int a = st.st_mode & S_IFMT;
	ret.type = a == S_IFREG ? X_FILE_TYPE_FILE : a == S_IFDIR ? X_FILE_TYPE_FOLDER : X_FILE_TYPE_SPECIAL;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	ret.modified = ((uint64_t)st.st_mtimespec.tv_sec)*1000000+(uint64_t)(st.st_mtimespec.tv_nsec/1000);
#else
	ret.modified = ((uint64_t)st.st_mtim.tv_sec)*1000000+(uint64_t)(st.st_mtim.tv_nsec/1000);
#endif
	ret.size = (uint64_t)st.st_size;
	return ret;
}

static bool x_mkdir(const char* name){
	return mkdir(name, 0777) == 0;
}

static bool x_remove(const char* name){
	return unlink(name) == 0 || (errno != EACCES && rmdir(name) == 0);
}

static x_folder_list_t x_dir_open(const char* name){ return opendir(name); }
static char* x_dir_next(x_folder_list_t dir){
	struct dirent* ent;
	ent = readdir(dir);
	return ent ? ent->d_name : 0;
}
static void x_dir_close(x_folder_list_t dir){ closedir(dir); }

static bool x_move(const char* old_name, const char* new_name){
	return !rename(old_name, new_name);
}

static ip_addr_t ip_from_string(const char* str){
	ip_addr_t a = {.words={0}};
	if(inet_pton(AF_INET6, str, &a) != 1){
		if(inet_pton(AF_INET, str, &a.dwords[3]) == 1) a.words[5] = 0xffff;
	}
	return a;
}

static enum ip_kind ip_to_string(ip_addr_t addr, char out[IP_STR_MAX_LEN]){
	bool ipv6 = addr.dwords[0] | addr.dwords[1] | addr.words[4] | (uint16_t)~addr.words[5];
	if(!inet_ntop(ipv6 ? AF_INET6 : AF_INET, ipv6 ? (void*)&addr : (void*)&addr.dwords[3], out, IP_STR_MAX_LEN)){
		out[0] = '\0';
		return IP_KIND_INVALID;
	}
	return ipv6 ? IP_KIND_V6 : IP_KIND_V4;
}

static x_socket_t x_udp_auto(void){
#ifdef SOCK_NONBLOCK
	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#else
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	fcntl(fd, F_SETFL, O_NONBLOCK);
#endif
	if(fd < 0) return X_SOCKET_INVALID;
	uint32_t off = 0;
	if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, 4) < 0){
		close(fd);
		fd = X_SOCKET_INVALID;
	}
	return fd;
}

static uint32_t interface_from_str(const char* i){ return if_nametoindex(i); }
static void interface_to_str(uint32_t i, char out[INTERFACE_STR_MAX_LEN]){ if(!if_indextoname(i, out)) out[0] = '\0'; }

static size_t interface_mtu(uint32_t i){
	if(!i) return 0;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if_indextoname(i, ifr.ifr_name);
	int s = socket(AF_INET6, SOCK_DGRAM, 0);
	if(s < 0) return 0;
	if(ioctl(s, SIOCGIFMTU, &ifr)) ifr.ifr_mtu = 0;
	close(s);
	return (size_t)ifr.ifr_mtu;
}

static x_socket_t x_udp_bound(remote_t from){
	struct sockaddr_in6 addr;
	addr.sin6_family = AF_INET6;
	*(ip_addr_t*)&addr.sin6_addr = from.addr;
	addr.sin6_scope_id = from.interface;
	addr.sin6_flowinfo = 0;
	addr.sin6_port = htons(from.port);
#ifdef SOCK_NONBLOCK
	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#else
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	fcntl(fd, F_SETFL, O_NONBLOCK);
#endif
	if(fd < 0) return X_SOCKET_INVALID;
	if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &addr.sin6_flowinfo, 4) < 0 || bind(fd, (struct sockaddr*)&addr, sizeof(addr)) || fcntl(fd, F_SETFL, O_NONBLOCK) < 0){
		close(fd);
		fd = X_SOCKET_INVALID;
	}
	return fd;
}

static bool x_udp_reflect(x_socket_t s, ip_addr_t to, remote_t* from, bool extinfo){
	struct sockaddr_in6 addr = {.sin6_family = AF_INET6};
	addr.sin6_port = htons(9);
	*(ip_addr_t*)&addr.sin6_addr = to;
	socklen_t addrlen = sizeof(addr);
	if(connect(s, (struct sockaddr*) &addr, addrlen)) return false;
	int r = getsockname(s, (struct sockaddr*)&addr, &addrlen);
	struct sockaddr_in6 unspec = {.sin6_family = AF_UNSPEC};
	(void)connect(s, (struct sockaddr*)&unspec, sizeof(unspec));
	if(r) return false;
	if(addr.sin6_family == AF_INET6){
		from->addr = *(ip_addr_t*)&addr.sin6_addr;
		from->port = ntohs(addr.sin6_port);
	}else{
		struct sockaddr_in* addr4 = (struct sockaddr_in*)&addr;
		from->addr.dwords[0] = from->addr.dwords[1] = 0;
		from->addr.words[4] = 0; from->addr.words[5] = 0xffff;
		from->addr.dwords[3] = addr4->sin_addr.s_addr;
		from->port = ntohs(addr.sin6_port);
	}
	uint32_t* d = from->addr.dwords;
	int o = 48;
	if(extinfo){
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		if(addr.sin6_family == AF_INET6 && addr.sin6_scope_id){
			if(!if_indextoname(addr.sin6_scope_id, ifr.ifr_name)) return false;
			from->interface = addr.sin6_scope_id;
		}else{
			struct ifaddrs *ifap;
			if(getifaddrs(&ifap)) return false;
			if(!from->addr.dwords[0] && !from->addr.dwords[1] && from->addr.dwords[2] == ntohl(0x0000ffff)){
				// ipv4
				//o = 28;
				for(struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next){
					struct sockaddr_in* addr = (struct sockaddr_in*) ifa->ifa_addr;
					if(!addr || addr->sin_family != AF_INET) continue;
					uint32_t mask = ((struct sockaddr_in*) ifa->ifa_netmask)->sin_addr.s_addr;
					if((d[3] & mask) != (addr->sin_addr.s_addr & mask)) continue;
					from->interface = if_nametoindex(ifa->ifa_name);
					strncpy(ifr.ifr_name, ifa->ifa_name, IF_NAMESIZE);
					break;
				}
			}else{
				// ipv6
				for(struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next){
					struct sockaddr_in6* addr = (struct sockaddr_in6*) ifa->ifa_addr;
					if(!addr || addr->sin6_family != AF_INET6) continue;
					uint32_t* addrw = (uint32_t*)&addr->sin6_addr;
					uint32_t* mask = (uint32_t*)&((struct sockaddr_in6*) ifa->ifa_netmask)->sin6_addr;
					if(((d[0] & mask[0]) ^ (addrw[0] & mask[0])) | ((d[1] & mask[1]) ^ (addrw[1] & mask[1])) | ((d[2] & mask[2]) ^ (addrw[2] & mask[2])) | ((d[3] & mask[3]) ^ (addrw[3] & mask[3]))) continue;
					from->interface = if_nametoindex(ifa->ifa_name);
					strncpy(ifr.ifr_name, ifa->ifa_name, IF_NAMESIZE);
					break;
				}
			}
			freeifaddrs(ifap);
			if(!ifr.ifr_name[0]) return false;
		}
		if(ioctl(s, SIOCGIFMTU, &ifr)) return false;
		from->mtu = (uint16_t)(ifr.ifr_mtu - o);
	}else{
		from->mtu = 0;
		from->interface = 0;
	}
	return true;
}

static bool x_udp_opts(x_socket_t s, size_t send_buf, size_t recv_buf){
	bool f = true;
	if(send_buf){
		int snd = send_buf > INT_MAX ? INT_MAX : send_buf < 64 ? 64 : (int)send_buf;
		if(setsockopt(s, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd))) f = false;
	}
	if(recv_buf){
		int rcv = recv_buf > INT_MAX ? INT_MAX : recv_buf < 64 ? 64 : (int)recv_buf;
		if(setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv))) f = false;
	}
	return f;
}

static bool x_udp_send(x_socket_t sock, remote_t to, const void* msg, size_t msglen){
	struct sockaddr_in6 addr;
	addr.sin6_flowinfo = 0;
	addr.sin6_scope_id = to.interface;
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(to.port);
	*(ip_addr_t*)&addr.sin6_addr = to.addr;
	return (size_t)sendto(sock, msg, msglen, 0, (struct sockaddr*) &addr, sizeof(addr)) == msglen;
}
static int x_udp_next_read(x_socket_t sock, remote_t* from, void* msg, size_t maxlen){
	struct sockaddr_in6 addr = {0}; socklen_t sz = sizeof(addr);
	int v = (int)recvfrom(sock, msg, maxlen, 0, (struct sockaddr*) &addr, &sz);
	if(v < 0) return -1;
	if(from){
		if(addr.sin6_family == AF_INET6){
			from->addr = *(ip_addr_t*)&addr.sin6_addr;
			from->port = ntohs(addr.sin6_port);
			from->interface = addr.sin6_scope_id;
		}else{
			struct sockaddr_in* addr4 = (struct sockaddr_in*)&addr;
			from->addr.dwords[0] = from->addr.dwords[1] = 0;
			from->addr.words[4] = 0; from->addr.words[5] = 0xffff;
			from->addr.dwords[3] = addr4->sin_addr.s_addr;
			from->port = ntohs(addr.sin6_port);
			from->interface = 0;
		}
	}
	return v;
}
static void x_udp_close(x_socket_t sock){
	struct sockaddr_in6 addr = {.sin6_family = AF_INET6, .sin6_port = htons(9)};
	*(ip_addr_t*)&addr.sin6_addr = (ip_addr_t){};
	// POSIX standard doesn't let us shutdown() a non-connected UDP socket
	// We make the socket "invalid" by connecting to :: which disables all "real" reads.
	// On Linux, we also call shutdown(SHUT_RDWR) after connect() so that epoll emits EPOLLHUP
	// (which equals X_EVENT_CLOSE), making event detection reliable without relying on
	// the writable-byte-count that kqueue provides but epoll does not.
#if !defined(__linux__)
	int one = 1; setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &one, sizeof(one));
#endif
	(void)connect(sock, (struct sockaddr*) &addr, sizeof(addr));
#if defined(__linux__)
	shutdown(sock, SHUT_RDWR);
#endif
}
static void x_socket_free(x_socket_t sock){ close(sock); }

static void x_zerobytes(void* data, size_t len){
#ifdef __APPLE__
	/* Apple does implement `memset_s` but including it is painful (the user is forced to either examine their include tree and define the feature test macro before any other includes, or define it as a compile flag. To add insult to injury, apple does not declare in any way if it was actually defined) */
	memset(data, 0, len);
	__asm__ volatile("" ::: "memory");
#elif defined(__NetBSD__)
	explicit_memset(data, 0, len);
#else
	explicit_bzero(data, len);
#endif
}

#include <sys/syscall.h>
#include <time.h>
#if defined(__linux__)
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/random.h>
#include <linux/futex.h>

static bool x_event_queue_init(x_event_queue_t* out){
	int fd = epoll_create1(0);
	if(fd < 0) return false;
	out->_fd = fd; out->_tfd = 0;
	atomic_init(&out->_min_wake, -1);
	atomic_init(&out->_bits, 0);
	return true;
}
_Static_assert(sizeof(struct epoll_event) <= sizeof(x_event_t), "");
static bool x_event_queue_add(x_event_queue_t* queue, x_socket_t sock, x_userdata_t data){
	struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI | EPOLLET, .data = {.ptr = data.ptr}};
	return !epoll_ctl(queue->_fd, EPOLL_CTL_ADD, sock, &ev) ||
		(errno == EEXIST && !epoll_ctl(queue->_fd, EPOLL_CTL_MOD, sock, &ev));
}
static x_event_t x_event_queue_wait(x_event_queue_t* queue, uint64_t timeout){
	uint32_t wc;
	if((wc=atomic_fetch_or_explicit(&queue->_bits, 1024, memory_order_acquire))&1024){
		// another thread is already waiting on this queue
		struct timespec now;
		if(timeout != -1ull) clock_gettime(CLOCK_MONOTONIC, &now);
		atomic_fetch_add_explicit(&queue->_bits, 2048, memory_order_relaxed);
		wc = atomic_load_explicit(&queue->_bits, memory_order_relaxed);
		while(wc&1024){
			if(timeout != -1ull){
				struct timespec n2;
				n2.tv_sec = timeout / 1000000;
				n2.tv_nsec = (timeout - (uint64_t)n2.tv_sec * 1000000)*1000;
				if(syscall(SYS_futex, &queue->_bits, FUTEX_WAIT_PRIVATE, wc, &n2) && errno == EINTR) return (x_event_t){X_EVENT_SIGNAL, {0}};
				clock_gettime(CLOCK_MONOTONIC, &n2);
				uint64_t rm = (uint64_t)(n2.tv_sec - now.tv_sec) * 1000000 + (uint64_t)((n2.tv_nsec - now.tv_nsec)/1000);
				if(timeout >= rm) timeout -= rm;
				else return (x_event_t){X_EVENT_TIMEOUT, {0}};
				now = n2;
			}else if(syscall(SYS_futex, &queue->_bits, FUTEX_WAIT_PRIVATE, wc, 0) && errno == EINTR){ return (x_event_t){X_EVENT_SIGNAL, {0}}; }
			wc = atomic_fetch_or_explicit(&queue->_bits, 1024, memory_order_acquire);
		}
	}
	x_event_t ev;
	uint8_t w = wc&31; wc &= 1023;
	if(w < (wc>>5)){
		wc++;
		ev.type = queue->_ev[w].events;
		ev.data.ptr = queue->_ev[w].data.ptr;
	}else{
		a: {} int c;
		if(timeout+1ull > (1ull+INT_MAX*1000ull)){
			timeout -= INT_MAX*1000ull;
			c = epoll_wait(queue->_fd, (struct epoll_event*) queue->_ev, _X_INLINE_EVENT_BUFFER, INT_MAX);
			if(!c) goto a;
		}else{ c = epoll_wait(queue->_fd, (struct epoll_event*) queue->_ev, _X_INLINE_EVENT_BUFFER, timeout==-1ull?-1:timeout/1000); }
		if(c <= 0) ev = (x_event_t){c ? X_EVENT_SIGNAL : X_EVENT_TIMEOUT, {0}};
		else{
			wc = c<<5|1;
			ev.type = queue->_ev[0].events;
			ev.data.ptr = queue->_ev[0].data.ptr;
		}
	}
	if(!ev.data.ptr && ev.type == EPOLLIN && atomic_exchange_explicit(&queue->_min_wake, -1, memory_order_acq_rel) != -1ull)
		ev.type = X_EVENT_WAKE;
	queue->_ev[0].events = wc;
	return ev;
}

static void x_event_queue_unlock(x_event_queue_t* queue){
	uint32_t v = atomic_exchange_explicit(&queue->_bits, queue->_ev[0].events, memory_order_release);
	if(v>>11){
		v = (v-2048)&-2048;
		if(v) atomic_fetch_add_explicit(&queue->_bits, v, memory_order_relaxed);
		syscall(SYS_futex, &queue->_bits, FUTEX_WAKE_PRIVATE, 1);
	}
}

static bool x_event_queue_remove(x_event_queue_t* queue, x_socket_t sock){ return !epoll_ctl(queue->_fd, EPOLL_CTL_DEL, sock, 0); }

static void x_event_queue_wake(x_event_queue_t* queue, uint64_t when){
	if(!queue->_tfd){
		queue->_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
		struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data = {0}};
		epoll_ctl(queue->_fd, EPOLL_CTL_ADD, queue->_tfd, &ev);
	}
	struct itimerspec tim = {{0,0},{0,0}};
	if(!when){
		tim.it_value.tv_nsec = 1;
		uint64_t v; read(queue->_tfd, &v, 8); // reset it
		timerfd_settime(queue->_tfd, TFD_TIMER_ABSTIME, &tim, 0);
		atomic_store_explicit(&queue->_min_wake, 0, memory_order_release);
	}else{
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		when += (uint64_t)(ts.tv_nsec/1000) + 1000000*(uint64_t)ts.tv_sec;
		uint64_t other = atomic_load_explicit(&queue->_min_wake, memory_order_acquire);
		if(other == -1ull){ uint64_t v; read(queue->_tfd, &v, 8); } // reset it
		if(when > other){
			return;
			retry:
			if(when > other) when = other;
		}
		struct itimerspec tim;
		tim.it_interval = (struct timespec){0};
		tim.it_value.tv_sec = when/1000000; tim.it_value.tv_nsec = (when-(uint64_t)tim.it_value.tv_sec*1000000)*1000;
		timerfd_settime(queue->_tfd, TFD_TIMER_ABSTIME, &tim, 0);
		if(!atomic_compare_exchange_strong_explicit(&queue->_min_wake, &other, when, memory_order_release, memory_order_acquire)) goto retry;
	}
}

static void x_event_queue_destroy(x_event_queue_t* q){
	close(q->_fd);
	if(q->_tfd) close(q->_tfd);
}

static void x_randombytes(void* data, size_t len){
	while(len){
		ssize_t r = getrandom(data, len, 0);
		if (r < 0) continue;
		data = (char*)data+r; len -= r;
	}
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/event.h>

static bool x_event_queue_init(x_event_queue_t* out){
	int fd = kqueue();
	if(fd < 0) return false;
	out->_fd = fd;
	atomic_init(&out->_bits, 0);
	atomic_init(&out->_min_wake, -1ull);
	struct kevent ev = {
		.ident = 0, .filter = EVFILT_USER, .flags = EV_ADD | EV_CLEAR, .fflags = 0, .data = 0, .udata = 0
	};
	kevent(fd, &ev, 1, 0, 0, 0);
	return true;
}

static bool x_event_queue_add(x_event_queue_t* queue, x_socket_t sock, x_userdata_t data){
	struct kevent ev[2] = {
		{ .ident = (uintptr_t)sock, .filter = EVFILT_READ, .flags = EV_ADD | EV_CLEAR, .fflags = 0, .data = 0, .udata = data.ptr },
		{ .ident = (uintptr_t)sock, .filter = EVFILT_WRITE, .flags = EV_ADD | EV_CLEAR, .fflags = 0, .data = 0, .udata = data.ptr },
	};
	return !kevent(queue->_fd, ev, 2, 0, 0, 0);
}
static x_event_t x_event_queue_wait(x_event_queue_t* queue, uint64_t timeout){
	uint32_t wc;
	if((wc=atomic_fetch_or_explicit(&queue->_bits, 1024, memory_order_acquire))&1024){
		// another thread is already waiting on this queue
		struct timespec now;
		if(timeout != -1ull) clock_gettime(CLOCK_MONOTONIC, &now);
		atomic_fetch_add_explicit(&queue->_bits, 2048, memory_order_relaxed);
		wc = atomic_load_explicit(&queue->_bits, memory_order_relaxed);
#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		while(wc&1024){
			if(timeout != -1ull){
				if(syscall(SYS_ulock_wait, 0x1000001, &queue->_bits, wc, timeout >> 32 ? 0xffffffff : timeout) && errno == EINTR) return (x_event_t){X_EVENT_SIGNAL, {0}};
				struct timespec n2;
				clock_gettime(CLOCK_MONOTONIC, &n2);
				uint64_t rm = (uint64_t)(n2.tv_sec - now.tv_sec) * 1000000 + (uint64_t)((n2.tv_nsec - now.tv_nsec)/1000);
				if(timeout > rm) timeout -= rm;
				else return (x_event_t){X_EVENT_TIMEOUT, {0}};
				now = n2;
			}else if(syscall(SYS_ulock_wait, 0x1000001, &queue->_bits, wc,  0) && errno == EINTR){ return (x_event_t){X_EVENT_SIGNAL, {0}}; }
			wc = atomic_fetch_or_explicit(&queue->_bits, 1024, memory_order_acquire);
		}
#else
		if(timeout != -1ull){
			uint64_t sec = timeout/1000000;
			struct _umtx_time ut = {._timeout = now, ._clockid = CLOCK_MONOTONIC, .flags = UMTX_ABSTIME};
			ut._timeout.tv_nsec += timeout-sec*1000000;
			if(ut._timeout.tv_nsec > 1000000000){
				ut._timeout.tv_nsec -= 1000000000; sec++;
			}
			ut._timeout.tv_sec += sec;
			while(wc&1024){
				if(_umtx_op(&queue->_bits, UMTX_OP_WAIT_UINT_PRIVATE, wc, sizeof(ut), &ut) && errno == EINTR) return (x_event_t){X_EVENT_SIGNAL, {0}};
				wc = atomic_fetch_or_explicit(&queue->_bits, 1024, memory_order_acquire);
			}
			if(timeout != -1ull) clock_gettime(CLOCK_MONOTONIC, &ut._timeout);
			uint64_t rm = (uint64_t)(ut._timeout.tv_sec - now.tv_sec) * 1000000 + (uint64_t)((ut._timeout.tv_nsec - now.tv_nsec)/1000);
			if(timeout >= rm) timeout -= rm;
			else else return (x_event_t){X_EVENT_TIMEOUT, {0}};
		}else{
			while(wc&1024){
				if(_umtx_op(&queue->_bits, UMTX_OP_WAIT_UINT_PRIVATE, wc, 0, 0) && errno == EINTR)
					return (x_event_t){X_EVENT_SIGNAL, {0}};
				wc = atomic_fetch_or_explicit(&queue->_bits, 1024, memory_order_acquire);
			}
		}
#endif
	}
	x_event_t ev;
	uint8_t w = wc&31; wc &= 1023;
	if(w < (wc>>5)){
		found: wc++;
		ev.type = queue->_ev[w].typ;
#if UINTPTR_MAX == UINT64_MAX
		ev.data.uptr = queue->_ev[w].udata[0]|(uint64_t)queue->_ev[w].udata[1]<<32;
#else
		ev.data.uptr = queue->_ev[w].udata[0];
#endif
	}else{
		struct kevent evs[_X_INLINE_EVENT_BUFFER];
		struct timespec tim;
		if(timeout != -1ull) tim.tv_sec = timeout/1000000, tim.tv_nsec = (long)(timeout - (uint64_t)tim.tv_sec * 1000000)*1000;
		int c = kevent(queue->_fd, 0, 0, evs, _X_INLINE_EVENT_BUFFER, timeout == -1ull ? 0 : &tim);
		if(c <= 0) return (x_event_t){c ? X_EVENT_SIGNAL : X_EVENT_TIMEOUT, {0}};
		int j = 0;
		for(int i = 0; i < c; i++){
			uint32_t f = (uint16_t)evs[i].filter;
			// -1 => 1, -2 => 4, -10 => 1024, -7 => 1024, -15 => 8
			f = 1<<(0xa030a020u>>((f^f<<2)&28)&15);
			if(f & (X_EVENT_READABLE | X_EVENT_WRITABLE))
				if(evs[i].flags&EV_EOF) f |= X_EVENT_EOF;
			if((f & X_EVENT_WRITABLE) && evs[i].data == 1)
				f = (f&~X_EVENT_WRITABLE) | X_EVENT_CLOSE;

			queue->_ev[j].typ = f;
			queue->_ev[j].udata[0] = (uint32_t)(uintptr_t)evs[i].udata;
#if UINTPTR_MAX == UINT64_MAX
			queue->_ev[j].udata[1] = (uint32_t)((uintptr_t)evs[i].udata>>32);
#endif
			j++;
		}
		wc = (uint32_t)j<<5; w = 0;
		goto found;
	}
	if(ev.type == X_EVENT_WAKE)
		atomic_store_explicit(&queue->_min_wake, -1, memory_order_release);
	queue->_ev[0].typ = wc;
	return ev;
}

static void x_event_queue_unlock(x_event_queue_t* queue){
	uint32_t v = atomic_exchange_explicit(&queue->_bits, queue->_ev[0].typ, memory_order_release);
	if(v>>11){
		v = (v-2048)&-2048u;
		if(v) atomic_fetch_add_explicit(&queue->_bits, v, memory_order_relaxed);
#ifdef __APPLE__
		syscall(SYS_ulock_wake, 0x1000001, &queue->_bits, 1);
#pragma clang diagnostic pop
#else
		_umtx_op(&queue->_bits, UMTX_OP_WAKE, 1, 0, 0);
#endif
	}
}

static bool x_event_queue_remove(x_event_queue_t* queue, x_socket_t sock){
	struct kevent ev[2] = {
		{ .ident = (uintptr_t)sock, .filter = EVFILT_READ, .flags = EV_DELETE, .fflags = 0, .data = 0, .udata = 0 },
		{ .ident = (uintptr_t)sock, .filter = EVFILT_WRITE, .flags = EV_DELETE, .fflags = 0, .data = 0, .udata = 0 }
	};
	return !kevent(queue->_fd, ev, 2, 0, 0, 0);
}

static void x_event_queue_wake(x_event_queue_t* queue, uint64_t when){
	if(when){
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		uint64_t now = (uint64_t)(ts.tv_nsec/1000) + 1000000*(uint64_t)ts.tv_sec;
		uint64_t other = atomic_load_explicit(&queue->_min_wake, memory_order_acquire);
		if(now+when > other){
			return;
			retry:
			if(now+when > other)
				when = other>=now?other-now:0;
		}
		struct kevent ev = {
			.ident = 0, .filter = EVFILT_TIMER, .flags = EV_ADD | EV_ONESHOT,
			.fflags = NOTE_USECONDS, .data = when>INTPTR_MAX?INTPTR_MAX:(intptr_t)when, .udata = 0
		};
		kevent(queue->_fd, &ev, 1, 0, 0, 0);
		if(!atomic_compare_exchange_strong_explicit(&queue->_min_wake, &other, now+when, memory_order_release, memory_order_acquire)) goto retry;
		return;
	}
	uint64_t c = atomic_exchange_explicit(&queue->_min_wake, 0, memory_order_acq_rel);
	struct kevent ev[2] = {{
		.ident = 0, .filter = EVFILT_USER, .flags = 0,
		.fflags = NOTE_TRIGGER, .data = 0, .udata = 0
	}};
	int count = 1;
	if(c != -1ull){
		count++;
		ev[1].filter = EVFILT_TIMER;
		ev[1].flags = EV_DELETE;
	}
	kevent(queue->_fd, ev, count, 0, 0, 0);
}

static void x_event_queue_destroy(x_event_queue_t* q){ close(q->_fd); }

static void x_randombytes(void* data, size_t len){ arc4random_buf(data, len); }

#else
#warning "Unsupported platform for event queues. This will generate a linker error if event-queue-related functions are used."
#endif
#endif

#ifdef __cplusplus
	#ifdef _MSC_VER
		#pragma warning(pop)
	#else
		#pragma GCC diagnostic pop
	#endif
#endif