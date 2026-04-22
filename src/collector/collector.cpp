#include "collector/collector.hpp"
#include "mutex_probe.skel.h"
#include <bpf/libbpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <optional>

namespace weave {

    Collector::Collector(pid_t target_pid) : target_pid_(target_pid) {
        elf_version(EV_CURRENT);
    }

    Collector::~Collector() {
        stop();
    }

    bool Collector::start() {
        if (running_) return true;
        if (!load_bpf()) return false;
        if (!attach_uprobes()) return false;

        running_ = true;
        poll_thread_ = std::thread(&Collector::poll_loop, this);
        std::cout << "[Collector] Started\n";
        return true;
    }

    void Collector::stop() {
        if (!running_) return;
        running_ = false;
        if (poll_thread_.joinable()) poll_thread_.join();
        ring_buffer__free(ring_buf_);
        ring_buf_ = nullptr;
        skel_.reset();
        std::cout << "[Collector] Stopped\n";
    }

    void Collector::set_callback(std::function<void(const MutexEvent&)> cb) {
        callback_ = std::move(cb);
    }

    bool Collector::load_bpf() {
        mutex_probe_bpf* skel_raw = mutex_probe_bpf__open();
        if (!skel_raw) {
            std::cerr << "Failed to open BPF skeleton\n";
            return false;
        }
        skel_ = { skel_raw, mutex_probe_bpf__destroy };

        if (mutex_probe_bpf__load(skel_.get())) {
            std::cerr << "Failed to load BPF program\n";
            return false;
        }

        ring_buf_ = ring_buffer__new(bpf_map__fd(skel_->maps.events), handle_event, this, nullptr);
        if (!ring_buf_) {
            std::cerr << "Failed to create ring buffer\n";
            return false;
        }
        return true;
    }

    std::optional<std::string> Collector::find_libc_path() const {
        std::string maps_path = "/proc/" + std::to_string(target_pid_) + "/maps";
        std::ifstream maps(maps_path);
        if (!maps) return std::nullopt;

        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("libc.so") != std::string::npos || line.find("libpthread.so") != std::string::npos) {
                size_t pos = line.find('/');
                if (pos != std::string::npos) {
                    std::string path = line.substr(pos);
                    path.erase(path.find_last_not_of(" \t\n\r") + 1);
                    return path;
                }
            }
        }
        return std::nullopt;
    }

    std::optional<uint64_t> Collector::get_symbol_offset(const std::string& path, const std::string& sym) const {
        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) return std::nullopt;

        Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
        if (!elf) {
            close(fd);
            return std::nullopt;
        }

        Elf_Scn* scn = nullptr;
        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            if (gelf_getshdr(scn, &shdr) == nullptr) continue;
            if (shdr.sh_type == SHT_DYNSYM) {
                Elf_Data* data = elf_getdata(scn, nullptr);
                size_t cnt = shdr.sh_size / shdr.sh_entsize;
                for (size_t i = 0; i < cnt; ++i) {
                    GElf_Sym sym_data;
                    if (gelf_getsym(data, i, &sym_data) == nullptr) continue;
                    const char* name = elf_strptr(elf, shdr.sh_link, sym_data.st_name);
                    if (name && sym == name) {
                        elf_end(elf);
                        close(fd);
                        return sym_data.st_value;
                    }
                }
            }
        }
        elf_end(elf);
        close(fd);
        return std::nullopt;
    }

    bool Collector::attach_uprobes() {
        auto libc_path = find_libc_path();
        if (!libc_path) {
            std::cerr << "Could not find libc in target process\n";
            return false;
        }
        std::cout << "Using libc: " << *libc_path << "\n";

 
        auto offset = get_symbol_offset(*libc_path, "pthread_mutex_lock");
        if (!offset) {
            std::cerr << "Could not find pthread_mutex_lock symbol\n";
            return false;
        }
        std::cout << "pthread_mutex_lock offset: 0x" << std::hex << *offset << std::dec << "\n";

        struct bpf_link* link = bpf_program__attach_uprobe(
            skel_->progs.uprobe_mutex_lock,
            false,              
            target_pid_,
            libc_path->c_str(),
            *offset
        );
        if (!link) {
            std::cerr << "Failed to attach uprobe to pthread_mutex_lock\n";
            return false;
        }

        std::cout << "Attached uprobe to pthread_mutex_lock\n";

     
        link = bpf_program__attach_uprobe(
            skel_->progs.uretprobe_mutex_lock,
            true,                
            target_pid_,
            libc_path->c_str(),
            *offset
        );
        if (!link) {
            std::cerr << "Failed to attach uretprobe to pthread_mutex_lock\n";
            return false;
        }
        std::cout << "Attached uretprobe to pthread_mutex_lock\n";

        return true;
    }

    void Collector::poll_loop() {
        while (running_) {
            int err = ring_buffer__poll(ring_buf_, 100 );
            if (err < 0 && err != -EINTR) {
                std::cerr << "ring_buffer__poll error: " << err << "\n";
                break;
            }
        }
    }

    int Collector::handle_event(void* ctx, void* data, size_t size) {
        auto* self = static_cast<Collector*>(ctx);
        if (size != sizeof(RawMutexEvent)) {
            std::cerr << "Event size mismatch: " << size << " vs " << sizeof(RawMutexEvent) << "\n";
            return -1;
        }
        RawMutexEvent* raw = static_cast<RawMutexEvent*>(data);
        MutexEvent ev = MutexEvent::from_raw(*raw);
        if (self->callback_) {
            self->callback_(ev);
        }
        else {
            
            std::cout << "[Event] type=" << static_cast<int>(ev.type)
                << " pid=" << ev.pid << " tid=" << ev.tid
                << " mutex=0x" << std::hex << ev.mutex_addr << std::dec
                << " time=" << ev.timestamp_ns << " ns\n";
        }
        return 0;
    }

} 