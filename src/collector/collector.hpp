#pragma once
#include <memory>
#include <atomic>
#include <functional>
#include <thread>
#include "common/event.hpp"
#include <optional>
#include <bpf/libbpf.h>

struct mutex_probe_bpf;  // forward

namespace weave {

    class Collector {
    public:
        explicit Collector(pid_t target_pid);
        ~Collector();


        bool start();

        void stop();

        void set_callback(std::function<void(const MutexEvent&)> cb);

    private:
        pid_t target_pid_;
        std::unique_ptr<mutex_probe_bpf, void(*)(mutex_probe_bpf*)> skel_{ nullptr, nullptr };
        struct ring_buffer* ring_buf_ = nullptr;
        std::atomic<bool> running_{ false };
        std::thread poll_thread_;
        std::function<void(const MutexEvent&)> callback_;


        bool load_bpf();
        bool attach_uprobes();
        std::optional<std::string> find_libc_path() const;
        std::optional<uint64_t> get_symbol_offset(const std::string& path, const std::string& sym) const;

        void poll_loop();
        static int handle_event(void* ctx, void* data, size_t size);
    };

} 