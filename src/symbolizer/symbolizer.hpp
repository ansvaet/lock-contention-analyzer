#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace weave {

	class Symbolizer {
	public:
		explicit Symbolizer(pid_t pid);
		~Symbolizer() = default;

		Symbolizer(const Symbolizer&) = delete;
		Symbolizer& operator=(const Symbolizer&) = delete;

		std::string resolve_mutex(uint64_t addr);
		std::string get_thread_name(uint32_t tid);
		void refresh();

	private:
		pid_t pid_;

		struct MemoryRegion {
			uint64_t start;
			uint64_t end;
			uint64_t file_offset;  
			std::string path;      
			bool is_readable;
			bool is_executable;
		};


		struct ElfSymbolCache {
			std::unordered_map<uint64_t, std::string> addr_to_name;
			bool loaded = false;  

		std::vector<MemoryRegion> regions_;
		std::unordered_map<std::string, ElfSymbolCache> elf_cache_;   
		std::unordered_map<uint32_t, std::string> thread_names_;      

		void parse_maps();
		const MemoryRegion* find_region(uint64_t addr) const;
		void load_elf_symbols(const std::string& path, ElfSymbolCache& cache);
		std::string format_hex(uint64_t addr) const;

	};
}