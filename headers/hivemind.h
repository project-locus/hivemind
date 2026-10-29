#pragma once
#ifdef __cplusplus
#define _Alignas alignas
extern "C" {
#endif
#include "x.h"

// [IP]/[port]/[mtu]/[time]/[rand_b64][QOS]
// See `hivemind_pipe_to_string()` and `hivemind_pipe_from_string()`
static const size_t HIVEMIND_PIPE_STR_MAX_LEN = IP_STR_MAX_LEN + /* port, mtu */ 12 + /* time */ 18 + /* rand_b64 */ 19 + /*QOS*/ 1;

// Bitfield. More than one value may be set
typedef enum hivemind_pipe_err_reason{
	HIVEMIND_CLOSED_PIPE_INVALID = 1, // This specific pipe definitely no longer exists as declared by the recipient node.
	HIVEMIND_CLOSED_TIMEOUT = 4, // This close event was generated as the result of a timeout. If the pipe still exists, resending to this pipe forfeits all order/delivery guarantees relative to previous messages. The simplest way to handle this consistently is to treat the same pipe as if it was an unrelated pipe (even if their byte representations compare equal).
	HIVEMIND_CLOSED_BACKPRESSURE = 8 // This close event was generated as a result of too much data being queued to be sent. This can be because the receiver was not acknowledging data fast enough (e.g you are sending faster than the physical link or machines can handle) or because too much data was being queued without checking backpressure (see `hivemind_link_metrics()`)
} hivemind_pipe_err_reason_t;

typedef void (*hivemind_generic_fn_t)(void* server_udata);
typedef void (*hivemind_on_pipe_msg_fn_t)(void* server_udata, void* pipe_data, const uint8_t* data, size_t len);
typedef void (*hivemind_on_pipe_err_fn_t)(void* server_udata, void* pipe_data, void* err_udata, hivemind_pipe_err_reason_t reason);
typedef void (*hivemind_pipe_finish_fn_t)(void* server_udata, void* pipe_data);

typedef struct hivemind_server hivemind_server_t;
#ifndef _HV_NO_STRUCT_DEFINITION
// The main server struct. See note on `hivemind_init()`. This struct is somewhat large and includes some padding for ABI stability.
// Only fields declared and documented in this header file are guaranteed to be ABI-stable. The remainder of the struct (including all "padding") is reserved for internal use and should not be touched after they are initialized by `hivemind_init()`
struct hivemind_server{ union{
	_Alignas(16) const char bytes_[320];
	struct{
		// IP address returned by the reflection test, which is used to determine the public IP when constructing pipes. Note that this may be an IPv4-mapped IPv6 address. This value can be written after `hivemind_init()` but before `hivemind_start()`, see the note on `hivemind_start()`.
		ip_addr_t addr;
		// Port and MTU used when constructing pipes, all in little-endian. These values can be written after `hivemind_init()` but before `hivemind_start()`, see the note on `hivemind_start()`.
		// ```c
		// union{
		// 	struct{  uint16_t port_le, mtu_le;  };
		// 	uint32_t port_mtu_packed_le;
		// 	struct{ uint8_t port_lo, port_hi, mtu_lo, mtu_hi; };
		// };
		// ```
		union{ struct{ uint16_t port_le, mtu_le; }; uint32_t port_mtu_packed_le; struct{ uint8_t port_lo, port_hi, mtu_lo, mtu_hi; }; };

		// Encryption bypass allows hivemind to avoid encrypting traffic within an internal network, saving both CPU and a small amount of bandwidth.
		// To prevent data corruption, accidental replays, etc..., a checksum is still enforced for every packet (specifically, CRC64) as well as other policies similar to encrypted traffic, the main difference being that these policies are only designed to avoid accidental mishaps. A malicious actor with access to your internal network can cause a lot more issues than just that of confidentiality (e.g Denial of service, Message/ack forgery, etc...)
		// You can set individual CIDR mask for IPv6 and IPv4. This mask can be up to 16 bits longer to also match the high bits of the port. Anything higher disables encryption bypass
		// The default is /128 for IPv6 (Match IP but port can differ) and /32 for IPv4 (ditto), effectively enabling encryption bypass for traffic within the same machine
		// This setting should be identical between servers that expect to use encryption bypass. Using different settings may lead to one server rejecting packets sent by another, either because received traffic is expected to be encrypted but isn't, or vice versa.
		// See also: `network_bypass_prefix_v6`, `network_bypass_prefix_v4`
		uint8_t encryption_bypass_prefix_v6, encryption_bypass_prefix_v4;
		// Network bypass allows hivemind to avoid the kernel's network stack, instead using vqueue, a copyless IPC protocol utilizing shared memory, saving a lot of CPU
		// Queue identifiers are derived from the receiver IP/port
		// You can set individual CIDR mask for IPv6 and IPv4. This mask can be up to 16 bits longer to also match the high bits of the port. Anything higher disables network bypass
		// The default is 255 for IPv6 and 255 for IPv4, which disables network bypass
		// This setting should be identical between servers that expect to use network bypass. Using different settings may lead to one server rejecting packets sent by another.
		// Note that unless hivemind is built with -DHIVEMIND_NO_LOCAL_BYPASS, traffic to the same IP and port will always bypass both the network stack and the kernel, and the message event is delivered synchronously and without copying (see note on `hivemind_send()`)
		// See also: `encryption_bypass_prefix_v6`, `encryption_bypass_prefix_v4`
		uint8_t network_bypass_prefix_v6, network_bypass_prefix_v4;
		// User data passed to `on_pipe_msg` / `on_close` callbacks as the first argument. Default is a pointer to the hivemind server. This value can be written after `hivemind_init()` but before `hivemind_start()`, see the note on `hivemind_init()`.
		void* udata;
		// How long a connection can go without any ACKs before it is presumed dead, in microseconds.
		// This value dictates the longest that a network partition can last before delivery guarantees become invalid and an error is produced
		// Default: 15min (900'000'000)
		// This value can be written after `hivemind_init()` but before `hivemind_start()`, see the note on `hivemind_init()`.
		uint64_t message_timeout;
		// How many bytes a connection can have queued before we consider it too slow and reject new messages as a failsafe against OOM.
		// Note that this tracks network bytes as an approximation of memory usage, rather than an exact number of application bytes.
		// Default: 2GB
		// This value can be written after `hivemind_init()` but before `hivemind_start()`, see the note on `hivemind_init()`.
		size_t backpressure_limit;
		// Pipe message callback, see `hivemind_init()`
		hivemind_on_pipe_msg_fn_t on_pipe_msg;
		// Message delivery error callback for a target return pipe, see note on `hivemind_send()`
		hivemind_on_pipe_err_fn_t on_pipe_err;
	};
	// Combined IP address, port and MTU used when constructing pipes. This is a view over the exact same memory as the `addr`, `port_le` and `mtu_le` fields. The same write restrictions apply.
	uint32_t dwords[5];
}; };
#endif

// 40-byte struct representing a pipe (align=4). This is an aggregate struct, you can pass it around, reconstruct it, etc. All fields are public and ABI-stable. The `id` field is a 160-bit unique identifier that is used to distinguish pipes with the same address. Note that fields are all in little-endian format, this means the byte-for-byte representation is identical on all machine, allowing you to safely serialize and deserialize pipes with e.g `memcpy()`. If you want a nicer human-readable format, see `hivemind_pipe_to_string()` and `hivemind_pipe_from_string()`.
typedef struct hivemind_pipe{ union{
	struct{
		ip_addr_t addr;
		union{ struct{ uint16_t port_le, mtu_le; }; uint32_t port_mtu_packed_le; };
		uint32_t id[5];
	};
	uint32_t dwords[10];
	uint8_t bytes[40];
}; } hivemind_pipe_t;
_Static_assert(_Alignof(hivemind_pipe_t) <= 4, "");
_Static_assert(sizeof(hivemind_pipe_t) == 40, "");

typedef enum hivemind_pipe_qos{
	HIVEMIND_QOS_REALTIME = 0,
	HIVEMIND_QOS_FASTER = 1,
	HIVEMIND_QOS_SLOWER = 2,
	HIVEMIND_QOS_BACKGROUND = 3
} hivemind_pipe_qos_t;

// Resolves (updates) a master key. An older key can be used to derive a newer key, but not the other way around. Forgetting the older key is fundamental to ensuring forward secrecy (that old traffic cannot be decrypted even if today the key is leaked)
// If `in` is null, a new key will be generated from the OS's high-quality random number generator (which is assumed to exist, failure is fatal).
void hivemind_resolve_key(/*optional*/ const uint8_t in[64], uint8_t out[64]);

// See `hivemind_start()` 
static const ip_addr_t HIVEMIND_WAN_V4 = {.words={0,0,0,0,0,0xffff,0x0808,0x0808}}; // ::ffff:8.8.8.8
// See `hivemind_start()` 
static const ip_addr_t HIVEMIND_WAN_V6 = {.bytes={32,1,72,96,72,96,0,0,0,0,0,0,8,8,8,8}}; // 2001:4860:4860::8888

// Initialize a server with the given master key and message callback.
// If the master key is null, a new one is generated (see `hivemind_get_key()` and `hivemind_resolve_key()`)
// You are expected to allocate the server struct yourself, and it must have a stable address between the call to `hivemind_start()` and the `on_close` callback handler passed to `hivemind_quit()` being invoked. If you move the struct between this call and `hivemind_start()`, remember to set `udata`, otherwise callbacks may be passed a stale pointer!
// Additional non-essential parameters can be configured after this function but before `hivemind_start()`. These include, most notably,
// - `server.udata`: Userdata passed as the first argument to `on_pipe_msg` and `on_close`
// - `server.message_timeout`: Network partitions longer than this value, in microseconds, can result in message delivery failure (see note on `hivemind_send()`)
void hivemind_init(hivemind_server_t* server, /*optional*/ const uint8_t master_key[64], hivemind_on_pipe_msg_fn_t on_pipe_msg);

// Get a server's latest master key. This may differ from the key passed to `hivemind_init()` as the server automatically rotates it as needed (see `hivemind_resolve_key()`)
void hivemind_get_key(hivemind_server_t* server, uint8_t out[64]);

// Start listening on the given address, with an optional reflection test IP (this is used to discover the local address, port and MTU). Returns true on success.
// If you would like to supply your own address, port, MTU or any combination of those, you can write to the corresponding fields in the server struct after `hivemind_init()` and before `hivemind_start()`, and they will be used instead of the results from the reflection test. When all 3 are provided before `hivemind_start()`, the reflection test is skipped and the `reflect_test` argument is unused (in any other case, passing `{0}` may fail).
bool hivemind_start(hivemind_server_t* server, remote_t where, ip_addr_t reflect_test);

// Quit the server. The `on_close` callback will be called once the server is fully stopped. The server struct can be reused / freed from the moment this callback is called.
// Pipes must not be created/deleted and messages must not be sent from the moment this function is called (with an exception detailed below). `pipe_finish` is called for every currently open pipe.
// Calls to `on_pipe_msg` are serialized before this function, at least up until they call `hivemind_pipe_unlock()`. This makes it safe to send messages and create/delete pipes from within them before `hivemind_pipe_unlock()`. It is also safe to do so from within `pipe_finish` handlers. All calls to `pipe_finish` are serialised with respect to: each other, `on_close`, `hivemind_close_pipe()`'s return, and `on_pipe_msg` handler for that pipe (up until `hivemind_pipe_unlock()`, see note on `hivemind_close_pipe()`).
void hivemind_quit(hivemind_server_t* server, hivemind_generic_fn_t on_close, hivemind_pipe_finish_fn_t pipe_finish);

// Detach a received packet, so it can be safely modified, and accessed after the callback returns. You must call `hivemind_packet_free()` on the returned pointer once you are done with it. The returned pointer may or may not be the same as the input pointer, however you should not use the input pointer after calling this function. Note that there are still no alignment guarantees on the returned pointer.
// This function very rarely needs to actually copy the packet. Most of the time it just marks the packet as detached, so that it is not freed after your callback returns.
// Calling this function outside of a callback invocation is undefined behavior.
uint8_t* hivemind_packet_detach(const uint8_t* packet);

// Free a detached packet. You must call this function on the pointer returned by `hivemind_packet_detach()` once you are done with the packet. Much like `free()`, this function also accepts null pointers and is a no-op in that case.
// Can be called at any time after `hivemind_packet_detach()`, even from another thread (this must be at least minimally synchronized, e.g acquire/release).
void hivemind_packet_free(const uint8_t* packet);

// By default, a callback invocation guarantees both that the current pipe remains available, and enforces message order even when multiple messages are processed on different threads. To offer this guarantee, calls are serialized against each other and against `hivemind_close_pipe()`, which may cause unnecessary blocking. If you want to release this serialization early in the callback, you can call `hivemind_pipe_unlock()`.
// A typical pattern is to queue the message, then call `hivemind_pipe_unlock()`. Doing this, when concurrently receiving messages and potentially closing the pipe, guarantees that queued order is the same as the pipe's logical order, and that when freeing, one of two things will happen:
// - `hivemind_close_pipe()` blocks until all remaining `hivemind_pipe_unlock()`s are called, and the closer thread will see pending messages and know not to free the associated (user) data yet.
// - `hivemind_close_pipe()` happens early enough and the message is rejected, your message callback was never invoked, no use-after-free.
// Calling this function outside of a callback invocation is undefined behavior.
void hivemind_pipe_unlock(void);

// Send a message to the given pipe. Messages larger than the MTU of the pipe or server (minus overhead) will be fragmented, which primarily affects tail latency.
// The message will be copied, `msg` does not need to remain valid after this function returns. This function may also perform some of the encryption and invoke the kernel. If the current thread is important (e.g UI thread) and the message is large, you should probably defer this call to another thread.
// BEWARE: If the destination pipe has the same address as the server, the message may be delivered synchronously and copy-less. It is therefore possible for the `on_pipe_msg` callback to be called before `hivemind_send()` returns. (Note that `hivemind_packet_detach()` / `hivemind_packet_free()` still work as expected even in this case). This behavior can be disabled by building hivemind with `-DHIVEMIND_NO_LOCAL_BYPASS`.
// In the case that either the recipient pipe was closed, or a network partition caused a delivery timeout, a message delivery failure notification is sent to f_return_pipe (if supplied), which must be a pipe belonging to this instance. The pipe's error callback will be invoked (i.e `server->on_pipe_err`, which must be non-null if f_return_pipe is ever specified, and invoked with the pipe userdata just like `on_pipe_msg`). `err_udata` is passed to the error callback as well as the failure reason. Passing an f_return_pipe not belonging to (not created by) this server is undefined behavior.
void hivemind_send(hivemind_server_t* server, const hivemind_pipe_t* to, const uint8_t* msg, size_t len, /*optional*/ const hivemind_pipe_t* f_return_pipe, /*optional*/ void* err_udata);

// Fields which reference "network bytes" measure bytes after messages are split up into packets. Each packet may incur ~20-50 bytes of overhead depending on the IP version and bypass mode
typedef struct hivemind_link_metrics{
	struct{
		// Backpressure for this entire remote, which is an approximation for how many network bytes have been queued but not acked (this may include bytes which have already left the machine, unlike `pipe_backpressure`). This is the metric that is checked against `backpressure_limit` in `hivemind_server_t` and may cause message delivery failure with reason `HIVEMIND_CLOSED_BACKPRESSURE`
		size_t bytes_in_flight;
		// Measured (approximate) link capacity in network bytes per microsecond
		float bandwidth;
		// Measured (approximate) ideal link latency (i.e fastest measured) and actual measured link latency (greater than ideal latency and depends on packet queue utilization and latency jitter), all in microsecond
		float latency, effective_latency;
		// Effective mtu in application bytes as negotiated between pipe mtu and configured server mtu 
		unsigned mtu;
	} remote;
	// Backpressure for this specific pipe, which is an approximation for how many network bytes are queued but delivery has not yet been attempted.
	size_t pipe_backpressure;
} hivemind_link_metrics_t;
// Get approximate metrics about the network link used to communicate with a specific pipe
void hivemind_link_metrics(hivemind_server_t* server, const hivemind_pipe_t* to, hivemind_link_metrics_t* out);

// Create a new pipe to listen on. The `udata` pointer is not interpreted by the library, but will be passed to the `on_pipe_msg` callback when a message is received on this pipe. For concurrency and use-after-free concerns, see the note on `hivemind_pipe_unlock()`.
// `on_pipe_msg` may also be invoked for this pipe if it is used in a failure return pipe, see the note on `hivemind_send()`.
void hivemind_create_pipe(hivemind_server_t* server, hivemind_pipe_t* out_pipe, void* udata, hivemind_pipe_qos_t qos);
// Close a pipe. The return value is the `udata` pointer that was passed to `hivemind_create_pipe()`, or `NULL` if the pipe was not found. If the same pipe is closed more than once, only one of them will return the userdata, all others will return null. For concurrency and use-after-free concerns, see the note on `hivemind_pipe_unlock()`. Calling this function on a pipe not belonging to (not created by) this server is undefined behavior.
// Message delivery failure notifications will also follow the same semantics as regular messages: if they would be delivered after this close, they are instead discarded.
void* hivemind_close_pipe(hivemind_server_t* server, const hivemind_pipe_t* pipe);

// Get the string representation of a pipe, which currently looks like `[IP]/[port]/[mtu]/[time]/[rand_b64][QOS]`. The string is null-terminated and its length (excluding the null character) is returned. HIVEMIND_PIPE_STR_MAX_LEN includes space for the null-terminator (the returned value is therefore always smaller than this)
size_t hivemind_pipe_to_string(const hivemind_pipe_t* pipe, char out[HIVEMIND_PIPE_STR_MAX_LEN]);

// Parse a string representation of a pipe, which currently looks like `[IP]/[port]/[mtu]/[time]/[rand_b64][QOS]`. If the string represents a valid pipe, the function returns true and writes the result to `pipe`. Otherwise, it returns false and the contents of `pipe` are invalidated.
bool hivemind_pipe_from_string(const char in[HIVEMIND_PIPE_STR_MAX_LEN], hivemind_pipe_t* pipe);

#ifdef __cplusplus
} /* extern "C" */
#endif