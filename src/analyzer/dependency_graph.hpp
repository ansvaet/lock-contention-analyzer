#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <memory>
#include <shared_mutex>
#include "common/event.hpp"
#include "common/histogram.hpp"

namespace weave {
    class Symbolizer;

    class DependencyGraph {
    public:
        struct ThreadInfo {
            uint32_t tid;
            std::string name;

            std::optional<uint64_t> waiting_for; // какой мьюекст ждет
            std::unordered_set<uint64_t> holding; // какие мьтексы держит

            std::optional<uint64_t> wait_start_ns; // когда начал ждать мьютекс
            std::unordered_map<uint64_t, uint64_t> hold_start_ns; // когда захватил

            uint64_t total_wait_time_ns = 0;
            uint64_t total_hold_time_ns = 0;
            uint32_t lock_acquisitions = 0;
            uint32_t lock_contentions = 0;
            Histogram wait_histogram;
            Histogram hold_histogram;
        };

        struct MutexInfo {
            uint64_t addr;
            std::string symbol_name;

            std::optional<uint32_t> held_by; 
            std::unordered_set<uint32_t> waiting_threads;  
            
            uint64_t total_wait_time_ns = 0;
            uint64_t total_hold_time_ns = 0;
            uint32_t acquisition_count = 0;
            uint32_t contention_count = 0;
            Histogram wait_histogram;
            Histogram hold_histogram;
        };

        struct Snapshot {
            struct ThreadSnapshot {
                uint32_t tid;
                std::string name;
                bool is_waiting;
                uint64_t waiting_for_mutex;
                std::vector<uint64_t> holding;
                uint64_t total_wait_ms;
                uint64_t total_hold_ms;
                uint32_t contentions;
            };

            struct MutexSnapshot {
                uint64_t addr;
                std::string name;
                std::optional<uint32_t> held_by;
                std::vector<uint32_t> waiting_threads;
                uint64_t avg_wait_ms;
                uint64_t max_wait_ms;
                uint64_t avg_hold_ms;
                uint32_t contention_count;
                uint32_t acquisition_count;
                uint64_t p95_wait_ms;
                uint64_t p99_wait_ms;
            };

            std::vector<ThreadSnapshot> threads;
            std::vector<MutexSnapshot> mutexes;
            std::vector<std::vector<uint32_t>> deadlock_cycles;
        };

        void process_event(const MutexEvent& ev);
        Snapshot create_snapshot() const;
        Snapshot create_snapshot(Symbolizer& sym) const;
        void clear();

    private:
        mutable std::shared_mutex mutex_;
        std::unordered_map<uint32_t, ThreadInfo> threads_;
        std::unordered_map<uint64_t, MutexInfo> mutexes_;

        ThreadInfo& get_or_create_thread(uint32_t tid);
        MutexInfo& get_or_create_mutex(uint64_t addr);

        void handle_lock_enter(const MutexEvent& ev);
        void handle_lock_exit(const MutexEvent& ev);
        void handle_unlock(const MutexEvent& ev);
        void handle_trylock_ok(const MutexEvent& ev);
        void handle_trylock_fail(const MutexEvent& ev);

        std::vector<std::vector<uint32_t>> find_cycles() const;
    };

} 