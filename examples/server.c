#include <hivemind.h>

void load_master_key(uint8_t key[64], const char* filename){
	x_file_t fd = x_open(filename, 0);
	if(x_getsize(fd) < 64){
		// Generate new key
		hivemind_resolve_key(NULL, key);
		x_write(fd, key, 0, 64);
	}else{
		// Load existing key
		x_read(fd, key, 0, 64);
	}
	x_close(fd);
}

void on_msg(hivemind_server_t* s, void* userdata, uint8_t* payload, size_t size){
	printf("Got %zu bytes: %s", size, payload);
}

hivemind_server_t h_server;
int main(){
	uint8_t master_key[64];
	load_master_key(master_key, "./.master.key");
	hivemind_init(&h_server, master_key, (hivemind_on_pipe_msg_fn_t) on_msg);

	hivemind_start(&h_server, (remote_t){
		.addr = {0} /* [::] aka anywhere */, .port = 3331,
		.mtu = 0 /* unused */, .interface = 0 /* auto */,
	}, /*for address discovery*/ HIVEMIND_WAN_V4);

	hivemind_pipe_t pipe;
	// The pipe type is contiguous, trivially copyable and has a platform-independent binary representation.
	hivemind_create_pipe(&h_server, &pipe, /*userdata*/ NULL, HIVEMIND_QOS_REALTIME);

	// Potentially on another machine/instance
	const uint8_t data[] = "Hello, world!";
	hivemind_send(&h_server, &pipe, data, sizeof(data), NULL, 0);
}