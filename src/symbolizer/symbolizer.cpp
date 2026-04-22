#include "symbolizer/symbolizer.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>

namespace weave {

    Symbolizer::Symbolizer(pid_t pid) : pid_(pid) {

        if (elf_version(EV_CURRENT) == EV_NONE) {
            throw std::runtime_error("ELF library initialization failed");
        }
        parse_maps();
    }

    void Symbolizer::parse_maps() {
        regions_.clear();
        std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
        std::ifstream maps(maps_path);
        if (!maps.is_open()) {
            throw std::runtime_error("Failed to open " + maps_path);
        }

        std::string line;
        while (std::getline(maps, line)) {
            std::istringstream iss(line);
            std::string addr_range, perms, offset_str, dev, inode, path;
            iss >> addr_range >> perms >> offset_str >> dev >> inode;
            std::getline(iss, path);

            if (!path.empty() && path[0] == ' ') {
                path = path.substr(1);
            }

            size_t dash = addr_range.find('-');
            if (dash == std::string::npos) continue;
            uint64_t start = std::stoull(addr_range.substr(0, dash), nullptr, 16);
            uint64_t end = std::stoull(addr_range.substr(dash + 1), nullptr, 16);
            uint64_t offset = std::stoull(offset_str, nullptr, 16);

            MemoryRegion region;
            region.start = start;
            region.end = end;
            region.file_offset = offset;
            region.path = path;
            region.is_readable = (perms.size() >= 1 && perms[0] == 'r');
            region.is_executable = (perms.size() >= 3 && perms[2] == 'x');
            regions_.push_back(region);
        }
    }

    const Symbolizer::MemoryRegion* Symbolizer::find_region(uint64_t addr) const {
        for (const auto& r : regions_) {
            if (addr >= r.start && addr < r.end) {
                return &r;
            }
        }
        return nullptr;
    }

    void Symbolizer::load_elf_symbols(const std::string& path, ElfSymbolCache& cache) {
        if (path.empty() || path[0] == '[') {
            // [heap], [stack], [vdso]
            cache.loaded = true;
            return;
        }

        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) {
            cache.loaded = true;
            return;
        }

        Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
        if (!elf) {
            close(fd);
            cache.loaded = true;
            return;
        }

        Elf_Scn* scn = nullptr;
        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            if (gelf_getshdr(scn, &shdr) == nullptr) continue;
            if (shdr.sh_type == SHT_DYNSYM) {
                Elf_Data* data = elf_getdata(scn, nullptr);
                if (!data) continue;

                size_t sym_count = shdr.sh_size / shdr.sh_entsize;
                for (size_t i = 0; i < sym_count; ++i) {
                    GElf_Sym sym;
                    if (gelf_getsym(data, i, &sym) == nullptr) continue;

                    if (GELF_ST_TYPE(sym.st_info) == STT_OBJECT && sym.st_size > 0) {
                        const char* name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                        if (name && name[0] != '\0') {
                            cache.addr_to_name[sym.st_value] = name;
                        }
                    }
                }
                break; 
            }
        }

        elf_end(elf);
        close(fd);
        cache.loaded = true;
    }

    std::string Symbolizer::format_hex(uint64_t addr) const {
        std::ostringstream oss;
        oss << "0x" << std::hex << addr;
        return oss.str();
    }

    std::string Symbolizer::resolve_mutex(uint64_t addr) {
        const MemoryRegion* region = find_region(addr);
        if (!region) {
            return format_hex(addr);
        }

        if (region->path.empty() || region->path[0] == '[') {
            return format_hex(addr);
        }

        uint64_t file_offset = addr - region->start + region->file_offset;


        auto& cache = elf_cache_[region->path];
        if (!cache.loaded) {
            load_elf_symbols(region->path, cache);
        }

        auto it = cache.addr_to_name.find(file_offset);
        if (it != cache.addr_to_name.end()) {
            return it->second;
        }

        return format_hex(addr);
    }

    std::string Symbolizer::get_thread_name(uint32_t tid) {
        auto it = thread_names_.find(tid);
        if (it != thread_names_.end()) {
            return it->second;
        }

        std::string comm_path = "/proc/" + std::to_string(pid_) + "/task/" + std::to_string(tid) + "/comm";
        std::ifstream comm(comm_path);
        std::string name;
        if (std::getline(comm, name)) {
            thread_names_[tid] = name;
            return name;
        }


        name = std::to_string(tid);
        thread_names_[tid] = name;
        return name;
    }

    void Symbolizer::refresh() {
        parse_maps();

        elf_cache_.clear();
        // thread_names_.clear();
    }

} 
