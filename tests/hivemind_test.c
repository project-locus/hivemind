#include "hivemind.h"
#include <polyutils.h>

hivemind_server_t ser;
atomic uint32_t cnt = 0;
double t0;
uint8_t data[10000000];
void on_msg(hivemind_server_t* s, void* udata, const uint8_t* data2, size_t len){
	printf("Got %zu bytes in %.2fms\n", len, ((double)mono_now()-t0)/1000.);
	int cmp = len == sizeof(data) ? memcmp(data, data2, len) : 1;
	if(cmp){
		printf("\x1b[31m=== Fail ===\x1b[m\n");
		if(len != sizeof(data)){
			printf("Lengths didn't match: %zu != %zu\n", len, sizeof(data));
		}else for(size_t i = 0; i < len; i++){
			if(data[i] != data2[i]){
				printf("From byte %zu didn't match:\n", i);
				size_t dlen = len-i; if(dlen > 256) dlen = 256;
				hexdump(data2+i, dlen); hexdump(data+i, dlen);
				break;
			}
		}
		breakpoint();
	}else printf("\x1b[32m=== Pass ===\x1b[m\n");
	if(atomic_fetch_add(&cnt, -1) == 1)
		atomic_wake_condition(&cnt, 1);
}

#define PORT 3331
uint8_t MASTER_KEY[32];

void on_done(void* _){
	atomic_fetch_add(&cnt, 1);
	atomic_wake_condition(&cnt, 1);
}

int main(){
	srand48((long)mono_now());
	uint64_t start = mono_now();
	x_file_t f = x_open(".master.key", 0);
	if(x_getsize(f) < 32){
		x_randombytes(MASTER_KEY, 32);
		x_write(f, MASTER_KEY, 0, 32);
	}else{
		x_read(f, MASTER_KEY, 0, 32);
	}
	x_close(f);
	hivemind_init(&ser, MASTER_KEY, (void(*)(void*, void*, const uint8_t*, size_t)) on_msg);
	if(!hivemind_start(&ser, (remote_t){{0}, PORT, 0, 0}, ip_from_string("127.0.0.1"))){
		printf("\x1b[31mFailed to bind to :%d\x1b[m\n", PORT);
		return 1;
	}
	char addr[40];
	ip_to_string(ser.addr, addr);
	printf("\x1b[32mServer started in %.2fms\x1b[33m\nRecv address: [%s]:%d MTU=%d\x1b[m\n", (mono_now() - start) / 1000.f, addr, le16toh(ser.port_le), le16toh(ser.mtu_le));

	hivemind_pipe_t recpt;
	hivemind_create_pipe(&ser, &recpt, NULL, HIVEMIND_QOS_REALTIME);
	x_randombytes(data, sizeof(data));
	/*for(uint32_t i = 0; i < sizeof(data); i+=4){
		*(uint32_t*)(data+i) = htonl(i>>2);
	}*/
	t0 = (double) mono_now();
	cnt = 100;
	for(unsigned i = 0; i < 100; i++){
		hivemind_send(&ser, &recpt, data, sizeof(data), NULL, 0);
	}

	atomic_wait_until(&cnt, !cnt);
	printf("\x1b[33mShutting down...\x1b[m\n");
	hivemind_quit(&ser, on_done, NULL);
	atomic_wait_until(&cnt, cnt);
}