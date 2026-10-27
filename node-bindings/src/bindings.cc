#include <uv.h>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <mutex>
#include "utils.hh"
#include <hivemind.h>
#include <assert.h>

#define SECOND_US 1000000

class HivemindServerJS : public Napi::ObjectWrap<HivemindServerJS>{
	using enum std::memory_order;
	enum class State{
		CLOSED = 0,
		OPENING = 16, OPENING_READY,
		OPEN = 32,
		CLOSING = 48, CLOSING_READY
	};
	struct PipeMeta{
		Napi::FunctionReference cb;
		std::atomic<size_t> ref;
	};
	struct Msg{
		PipeMeta* m;
		uint8_t* data; size_t size;
	};
	static void on_msg(void* s_, void* udata, const uint8_t* payload, size_t size){
		HivemindServerJS* s = (HivemindServerJS*)s_;
		PipeMeta* m = static_cast<PipeMeta*>(udata);
		m->ref.fetch_add(1, relaxed);
		s->msg_lock.lock();
		hivemind_pipe_unlock(); // happens after msg_lock acquire to preserve order for same pipes
		s->msgs.push_back({m, hivemind_packet_detach(payload), size});
		s->msg_lock.unlock();
		uv_async_send(&s->async_handle);
	}
	static void handle_closed(uv_handle_t* handle){
		HivemindServerJS* s = (HivemindServerJS*) handle->data;
		s->Unref();
	}
	static void async_cb(uv_async_t* handle){
		HivemindServerJS* s = (HivemindServerJS*) handle->data;
		s->msg_lock.lock();
		State state = s->state.load(relaxed);
		auto v = std::move(s->msgs);
		s->msg_lock.unlock();
		Napi::HandleScope _(s->Env());
		if(state == State::OPENING_READY){
			s->state = State::OPEN;
			s->on_open_close->Resolve(s->Env().Undefined());
			s->on_open_close.destruct();
		}
		for(auto& item : v){
			if(!item.m->cb.IsEmpty()){
				auto v = Napi::ArrayBuffer::New(s->Env(), item.data, item.size);
				item.m->cb.Value().Call({v});
				v.Detach();
			}
			if(item.m->ref.fetch_sub(1, release) == 1){
				atomic_thread_fence(memory_order_acquire);
				delete item.m;
			}
			hivemind_packet_free(item.data);
		}
		if(state == State::CLOSING_READY){
			s->state.store(State::CLOSED, relaxed);
			uv_close((uv_handle_t*)&s->async_handle, &HivemindServerJS::handle_closed);
			s->on_open_close->Resolve(s->Env().Undefined());
			s->on_open_close.destruct();
		}
	}
	static void on_done(void* s_){
		HivemindServerJS* s = (HivemindServerJS*)s_;
		bool send = s->state.load(relaxed) == State::CLOSING;
		s->state.store(State::CLOSING_READY, release);
		if(send) uv_async_send(&s->async_handle);
	}
	static void free_pipe(void* s_, void* p_){
		delete (PipeMeta*)p_;
	}
	static Napi::Value PipeToString(const Napi::CallbackInfo& info){
		if(info.Length() != 1 || !info[0].IsArrayBuffer()) err: {
			Napi::TypeError::New(info.Env(), "Failed to execute 'pipeToString': First argument must be an ArrayBuffer of length 40").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto pipev = info[0].As<Napi::ArrayBuffer>();
		if(pipev.ByteLength() < sizeof(hivemind_pipe_t)) goto err;
		hivemind_pipe_t pipe;
		memcpy(&pipe, pipev.Data(), sizeof(hivemind_pipe_t));
		char out[HIVEMIND_PIPE_STR_MAX_LEN];
		hivemind_pipe_to_string(&pipe, out);
		return Napi::String::New(info.Env(), out);
	}
	static Napi::Value PipeFromString(const Napi::CallbackInfo& info){
		if(info.Length() != 1 || !info[0].IsString()) err: {
			Napi::TypeError::New(info.Env(), "Failed to execute 'pipeFromString': First argument must be a string").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto pipev = Napi::ArrayBuffer::New(info.Env(), sizeof(hivemind_pipe_t));
		if(!hivemind_pipe_from_string((hivemind_pipe_t*) pipev.Data(), info[0].As<Napi::String>().Utf8Value().c_str())) return info.Env().Null();
		return pipev;
	}

	static Napi::Function GetClass(Napi::Env env){
		return DefineClass(env, "HivemindServer", {
			StaticMethod("pipeToString", &HivemindServerJS::PipeToString),
			StaticMethod("pipeFromString", &HivemindServerJS::PipeFromString),
			InstanceMethod("listen", &HivemindServerJS::Listen),
			InstanceMethod("createPipe", &HivemindServerJS::CreatePipe),
			InstanceMethod("deletePipe", &HivemindServerJS::DeletePipe),
			InstanceMethod("send", &HivemindServerJS::Send),
			InstanceMethod("quit", &HivemindServerJS::Quit),
			InstanceMethod("address", &HivemindServerJS::GetBoundAddress),
			InstanceAccessor("readyState", &HivemindServerJS::GetReadyState, 0),
			StaticValue("CLOSED", Napi::Number::New(env, (int)State::CLOSED>>1)),
			StaticValue("OPENING", Napi::Number::New(env, (int)State::OPENING>>1)),
			StaticValue("OPEN", Napi::Number::New(env, (int)State::OPEN>>1)),
			StaticValue("CLOSING", Napi::Number::New(env, (int)State::CLOSING>>1)),
			StaticValue("QOS_REALTIME", Napi::Number::New(env, HIVEMIND_QOS_REALTIME)),
			StaticValue("QOS_FASTER", Napi::Number::New(env, HIVEMIND_QOS_FASTER)),
			StaticValue("QOS_SLOWER", Napi::Number::New(env, HIVEMIND_QOS_SLOWER)),
			StaticValue("QOS_BACKGROUND", Napi::Number::New(env, HIVEMIND_QOS_BACKGROUND)),
		});
	}
	std::mutex msg_lock;
	std::atomic<State> state = State::CLOSED;
	std::vector<Msg> msgs;
	union{
		struct{ void* save_data; size_t save_size; };
		Napi::FunctionReference user_data;
	};
	uv_async_t async_handle;
	Napi::AsyncContext async_context;
	slot<Napi::Promise::Deferred> on_open_close;
	hivemind_server_t server_;
	public:
	HivemindServerJS(const Napi::CallbackInfo& info) : Napi::ObjectWrap<HivemindServerJS>(info), async_context(info.Env(), "Hivemind"){
		auto env = info.Env();
		if(info.Length() != 1 || !info[0].IsObject()){
			Napi::TypeError::New(env, "Failed to construct 'HivemindServer': First and only argument must be an object").ThrowAsJavaScriptException();
		}
		auto props = info[0].As<Napi::Object>();
		auto keyv = props.Get("key");
		if(!keyv.IsTypedArray()) key_err: {
			Napi::TypeError::New(env, "Failed to construct 'HivemindServer': property 'key' is not a TypedArray of at least 32 bytes").ThrowAsJavaScriptException();
		}
		auto key = keyv.As<Napi::Uint8Array>();
		if(key.ByteLength() < 32) goto key_err;

		hivemind_init(&server_, key.Data(), (hivemind_on_pipe_msg_fn_t) HivemindServerJS::on_msg);

		server_.udata = this;
		auto partv = props.Get("maxPartition");
		if(partv.IsNumber()){
			double v = partv.As<Napi::Number>().DoubleValue()*1000.;
			// sane minimum 5min
			if(v < 0 || v >= (double)UINT64_MAX) server_.message_timeout = UINT64_MAX;
			else if(v < 300*SECOND_US) server_.message_timeout = 300*SECOND_US;
			else server_.message_timeout = v;
		}

		auto addrv = props.Get("selfAddress");
		if(addrv.IsString()){
			char str[IP_STR_MAX_LEN];
			Napi_utf8_copy(addrv.As<Napi::String>(), str, IP_STR_MAX_LEN);
			server_.addr = ip_from_string(str);
		}
		auto portv = props.Get("selfPort");
		if(portv.IsNumber()){
			int port = portv.As<Napi::Number>().Uint32Value();
			server_.port_lo = port;
			server_.port_hi = port>>8;
		}
		auto mtuv = props.Get("selfMtu");
		if(mtuv.IsNumber()){
			int mtu = mtuv.As<Napi::Number>().Uint32Value();
			if(mtu > 65535) mtu = 65535;
			server_.mtu_lo = mtu;
			server_.mtu_hi = mtu>>8;
		}

		auto encBypassV6 = props.Get("encryptionBypassPrefixV6");
		if(encBypassV6.IsNumber()){
			int v = encBypassV6.As<Napi::Number>().Uint32Value();
			if(v > 255) v = 255;
			server_.encryption_bypass_prefix_v6 = (uint8_t)v;
		}
		auto encBypassV4 = props.Get("encryptionBypassPrefixV4");
		if(encBypassV4.IsNumber()){
			int v = encBypassV4.As<Napi::Number>().Uint32Value();
			if(v > 255) v = 255;
			server_.encryption_bypass_prefix_v4 = (uint8_t)v;
		}

		auto netBypassV6 = props.Get("networkBypassPrefixV6");
		if(netBypassV6.IsNumber()){
			int v = netBypassV6.As<Napi::Number>().Uint32Value();
			if(v > 255) v = 255;
			server_.network_bypass_prefix_v6 = (uint8_t)v;
		}
		auto netBypassV4 = props.Get("networkBypassPrefixV4");
		if(netBypassV4.IsNumber()){
			int v = netBypassV4.As<Napi::Number>().Uint32Value();
			if(v > 255) v = 255;
			server_.network_bypass_prefix_v4 = (uint8_t)v;
		}
	}
	Napi::Value Listen(const Napi::CallbackInfo& info){
		if(this->state.load(relaxed) != State::CLOSED){
			Napi::Error::New(info.Env(), "Failed to execute 'listen' on 'HivemindServer': The server is already running").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		int argc = info.Length();
		if(argc < 1 || !info[0].IsNumber()){
			Napi::TypeError::New(info.Env(), "Failed to execute 'listen' on 'HivemindServer': first argument must be a valid port number").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		remote_t r;
		r.port = (uint16_t) info[0].As<Napi::Number>().Uint32Value();
		ip_addr_t test = HIVEMIND_WAN_V4;
		if(argc >= 2){
			if(info[1].IsString()){
				char str[IP_STR_MAX_LEN];
				Napi_utf8_copy(info[1].As<Napi::String>(), str, IP_STR_MAX_LEN);
				r.addr = ip_from_string(str);
			}
			if(argc >= 3){
				if(info[2].IsString())
					r.interface = interface_from_str(info[2].As<Napi::String>().Utf8Value().c_str());
				if(argc >= 4 && info[3].IsString()){
					char str[IP_STR_MAX_LEN];
					Napi_utf8_copy(info[3].As<Napi::String>(), str, IP_STR_MAX_LEN);
					test = ip_from_string(str);
				}
			}
		}
		// ref
		uv_loop_t* loop;
		napi_status err;
		err = napi_get_uv_event_loop(info.Env(), &loop);
		assert(err == napi_ok && "napi_get_uv_event_loop");
		int err2 = uv_async_init(loop, &async_handle, async_cb);
		assert(!err2 && "uv_async_init");
		async_handle.data = this;
		if(!hivemind_start(&server_, r, test)){
			uv_unref((uv_handle_t*)&async_handle);
			Napi::Error::New(info.Env(), "Failed to execute 'listen' on 'HivemindServer': could not bind to address").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		this->state.store(State::OPEN, relaxed);
		this->Ref();
		auto def = Napi::Promise::Deferred::New(info.Env());
		def.Resolve(info.Env().Undefined());
		return def.Promise();
	}

	HivemindServerJS(HivemindServerJS&&) = delete;
	HivemindServerJS& operator=(HivemindServerJS&&) = delete;
	HivemindServerJS(const HivemindServerJS&) = delete;
	HivemindServerJS& operator=(const HivemindServerJS&) = delete;

	Napi::Value CreatePipe(const Napi::CallbackInfo& info){
		if(info.Length() < 1 || !info[0].IsFunction()){
			Napi::TypeError::New(info.Env(), "Failed to execute 'createPipe' on 'HivemindServer': First argument must be a function").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto ref = new PipeMeta{ Napi::Persistent(info[0].As<Napi::Function>()), 1 };
		auto buf = Napi::ArrayBuffer::New(info.Env(), sizeof(hivemind_pipe_t));
		hivemind_create_pipe(&server_, (hivemind_pipe_t*) buf.Data(), ref, info.Length() >= 2 ? (hivemind_pipe_qos_t)info[1].ToNumber().Int32Value() : HIVEMIND_QOS_REALTIME);
		return buf;
	}
	Napi::Value GetReadyState(const Napi::CallbackInfo& info){
		return Napi::Number::New(info.Env(), (int)this->state.load(relaxed)>>4);
	}
	Napi::Value DeletePipe(const Napi::CallbackInfo& info){
		if(info.Length() < 1 || !info[0].IsArrayBuffer()) err: {
			Napi::TypeError::New(info.Env(), "Failed to execute 'deletePipe' on 'HivemindServer': First argument must be an ArrayBuffer of length 40").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto pipev = info[0].As<Napi::ArrayBuffer>();
		if(pipev.ByteLength() < sizeof(hivemind_pipe_t)) goto err;
		hivemind_pipe_t pipe;
		memcpy(&pipe, pipev.Data(), sizeof(hivemind_pipe_t));
		PipeMeta* m = (PipeMeta*) hivemind_close_pipe(&server_, &pipe);
		m->cb.Unref();
		if(m->ref.fetch_sub(1, release) == 1){
			atomic_thread_fence(memory_order_acquire);
			delete m;
		}
		return info.Env().Undefined();
	}

	Napi::Value GetBoundAddress(const Napi::CallbackInfo& info){
		char out[IP_STR_MAX_LEN];
		enum ip_kind kind = ip_to_string(server_.addr, out);
		auto ret = Napi::Object::New(info.Env());
		ret.Set("address", Napi::String::New(info.Env(), out));
		ret.Set("port", Napi::Number::New(info.Env(), server_.port_lo|server_.port_hi<<8));
		char family[] = "IPv6";
		if(kind == IP_KIND_V4) family[3] = '4';
		ret.Set("family", Napi::String::New(info.Env(), family));
		return ret;
	}

	Napi::Value Send(const Napi::CallbackInfo& info){
		Napi::Env env = info.Env();

		if(info.Length() < 2 || !info[0].IsArrayBuffer()) type_err: {
			Napi::TypeError::New(info.Env(), "Failed to execute 'send' on 'HivemindServer': First argument must be an ArrayBuffer of length 40. Second argument must be an ArrayBufferView").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		auto tov = info[0].As<Napi::ArrayBuffer>();
		if(tov.ByteLength() < 40) goto type_err;
		void* data; size_t sz;
		if(info[1].IsTypedArray()){
			auto v = info[1].As<Napi::TypedArrayOf<uint8_t>>();
			data = v.Data(); sz = v.ByteLength();
		}else if(info[1].IsArrayBuffer()){
			auto v = info[1].As<Napi::ArrayBuffer>();
			data = v.Data(); sz = v.ByteLength();
		}else if(info[1].IsDataView()){
			auto v = info[1].As<Napi::ArrayBuffer>();
			data = v.Data(); sz = v.ByteLength();
		}else goto type_err;
		hivemind_pipe_t to, *to_ptr = (hivemind_pipe_t*) tov.Data();
		if((uintptr_t)to_ptr & 3){
			// Unaligned, copy to stack
			memcpy(&to, tov.Data(), sizeof(to));
			to_ptr = &to;
		}
		hivemind_send(&server_, to_ptr, (uint8_t*) data, sz, NULL, 0);
		return env.Undefined();
	}

	Napi::Value Quit(const Napi::CallbackInfo& info){
		if(this->state.load(relaxed) != State::OPEN){
			Napi::Error::New(info.Env(), "Failed to execute 'quit' on 'HivemindServer': The server is not running").ThrowAsJavaScriptException();
			return info.Env().Undefined();
		}
		this->state.store(State::CLOSING, relaxed);
		hivemind_quit(&server_, (hivemind_generic_fn_t) HivemindServerJS::on_done, (hivemind_pipe_finish_fn_t) HivemindServerJS::free_pipe);
		// Beyond this part it is not possible to receive more messages
		on_open_close.construct(Napi::Promise::Deferred::New(info.Env()));
		return on_open_close->Promise();
	}
	~HivemindServerJS(){
		x_zerobytes(&server_, sizeof(server_));
	}
	friend Napi::Object Init(Napi::Env env, Napi::Object exports);
};

Napi::Object Init(Napi::Env env, Napi::Object exports){
	return HivemindServerJS::GetClass(env);
}

NODE_API_MODULE(hivemind, Init)