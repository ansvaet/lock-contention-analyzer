#include "analyzer/dependency_graph.hpp"
#include "symbolizer/symbolizer.hpp"
#include <algorithm>
#include <shared_mutex>
#include <mutex>

namespace weave {

DependencyGraph::ThreadInfo& DependencyGraph::get_or_create_thread(uint32_t tid) {
    auto it = threads_.find(tid);
    if (it == threads_.end()) {
        ThreadInfo info;
        info.tid = tid;
        info.name = std::to_string(tid); // потом заменим на имя из /proc
        it = threads_.emplace(tid, std::move(info)).first;
    }
    return it->second;
}

DependencyGraph::MutexInfo& DependencyGraph::get_or_create_mutex(uint64_t addr) {
    auto it = mutexes_.find(addr);
    if (it == mutexes_.end()) {
        MutexInfo info;
        info.addr = addr;
        it = mutexes_.emplace(addr, std::move(info)).first;
    }
    return it->second;
}

void DependencyGraph::handle_lock_enter(const MutexEvent& ev) {
    std::unique_lock lock(mutex_);
    
    auto& thread = get_or_create_thread(ev.tid);
    auto& mutex = get_or_create_mutex(ev.mutex_addr);
    

    if (thread.waiting_for.has_value()) {
        uint64_t old_mutex = *thread.waiting_for;
        auto& old_m = mutexes_.at(old_mutex);
        old_m.waiting_threads.erase(ev.tid);
    }
    
    thread.waiting_for = ev.mutex_addr;
    if (mutex.held_by.has_value()) {
        thread.wait_start_ns = ev.timestamp_ns;
    }
    else {
        thread.wait_start_ns = std::nullopt;
    }
    mutex.waiting_threads.insert(ev.tid);
}


void DependencyGraph::handle_lock_exit(const MutexEvent& ev) {
    std::unique_lock lock(mutex_);
    
    auto& thread = get_or_create_thread(ev.tid);

    if (!thread.waiting_for.has_value()) {

        return;
    }
    
    uint64_t mutex_addr = *thread.waiting_for;
    auto& mutex = get_or_create_mutex(mutex_addr);
    
    uint64_t wait_time = 0;
    if (thread.wait_start_ns.has_value()) {
        wait_time = ev.timestamp_ns - *thread.wait_start_ns;
    }

    if (wait_time > 0) {
        thread.total_wait_time_ns += wait_time;
        thread.wait_histogram.record(wait_time);
        mutex.total_wait_time_ns += wait_time;
        mutex.wait_histogram.record(wait_time);
        thread.lock_contentions++;
        mutex.contention_count++;
    }
    
    mutex.waiting_threads.erase(ev.tid);
    thread.waiting_for = std::nullopt;
    thread.wait_start_ns = std::nullopt;
    

    if (mutex.held_by.has_value() && *mutex.held_by != ev.tid) {

        uint32_t old_holder = *mutex.held_by;
        auto& old_thread = threads_.at(old_holder);
        old_thread.holding.erase(mutex_addr);
        old_thread.hold_start_ns.erase(mutex_addr);
    }
    

    mutex.held_by = ev.tid;
    thread.holding.insert(mutex_addr);
    thread.hold_start_ns[mutex_addr] = ev.timestamp_ns;
    
    thread.lock_acquisitions++;
    mutex.acquisition_count++;
}

void DependencyGraph::handle_unlock(const MutexEvent& ev) {
    std::unique_lock lock(mutex_);
    
    auto& thread = get_or_create_thread(ev.tid);
    auto& mutex = get_or_create_mutex(ev.mutex_addr);
    

    if (mutex.held_by.has_value() && *mutex.held_by == ev.tid) {

        auto it = thread.hold_start_ns.find(ev.mutex_addr);
        if (it != thread.hold_start_ns.end()) {
            uint64_t hold_time = ev.timestamp_ns - it->second;
            thread.total_hold_time_ns += hold_time;
            thread.hold_histogram.record(hold_time);
            mutex.total_hold_time_ns += hold_time;
            mutex.hold_histogram.record(hold_time);
            thread.hold_start_ns.erase(it);
        }
        
        thread.holding.erase(ev.mutex_addr);
        mutex.held_by = std::nullopt;
    }
}


void DependencyGraph::handle_trylock_ok(const MutexEvent& ev) {
    std::unique_lock lock(mutex_);
    
    auto& thread = get_or_create_thread(ev.tid);
    auto& mutex = get_or_create_mutex(ev.mutex_addr);
    

    if (mutex.held_by.has_value() && *mutex.held_by == ev.tid) {

        return;
    }

    if (mutex.held_by.has_value()) {
        uint32_t old_holder = *mutex.held_by;
        auto& old_thread = threads_.at(old_holder);
        old_thread.holding.erase(ev.mutex_addr);
        old_thread.hold_start_ns.erase(ev.mutex_addr);
    }
    
    mutex.held_by = ev.tid;
    thread.holding.insert(ev.mutex_addr);
    thread.hold_start_ns[ev.mutex_addr] = ev.timestamp_ns;
    
    thread.lock_acquisitions++;
    mutex.acquisition_count++;
}

void DependencyGraph::handle_trylock_fail(const MutexEvent& ev) {
    std::unique_lock lock(mutex_);
    
    auto& mutex = get_or_create_mutex(ev.mutex_addr);
    mutex.contention_count++;

}

void DependencyGraph::process_event(const MutexEvent& ev) {
    switch (ev.type) {
        case EventType::MutexLockEnter:
            handle_lock_enter(ev);
            break;
        case EventType::MutexLockExit:
            handle_lock_exit(ev);
            break;
        case EventType::MutexUnlock:
            handle_unlock(ev);
            break;
        case EventType::MutexTryLockOk:
            handle_trylock_ok(ev);
            break;
        case EventType::MutexTryLockFail:
            handle_trylock_fail(ev);
            break;
    }
}


std::vector<std::vector<uint32_t>> DependencyGraph::find_cycles() const {
    std::vector<std::vector<uint32_t>> cycles;
    
    enum class Color { White, Gray, Black };
    std::unordered_map<uint32_t, Color> color;
    std::unordered_map<uint32_t, uint32_t> parent;

    for (const auto& [tid, _] : threads_) {
        color[tid] = Color::White;
    }
    
    // Рекурсивная лямбда для DFS
    std::function<void(uint32_t)> dfs = [&](uint32_t tid) {
        color[tid] = Color::Gray;
        
        const auto& thread = threads_.at(tid);
        if (thread.waiting_for.has_value()) {
            uint64_t mutex_addr = *thread.waiting_for;
            auto mutex_it = mutexes_.find(mutex_addr);
            if (mutex_it != mutexes_.end() && mutex_it->second.held_by.has_value()) {
                uint32_t holder_tid = *mutex_it->second.held_by;
                parent[holder_tid] = tid;
                
                if (color[holder_tid] == Color::Gray) {

                    std::vector<uint32_t> cycle;
                    uint32_t curr = holder_tid;
                    do {
                        cycle.push_back(curr);
                        curr = parent[curr];
                    } while (curr != holder_tid);

                    cycles.push_back(std::move(cycle));
                } else if (color[holder_tid] == Color::White) {
                    dfs(holder_tid);
                }
            }
        }
        
        color[tid] = Color::Black;
    };
   
    for (const auto& [tid, _] : threads_) {
        if (color[tid] == Color::White) {
            dfs(tid);
        }
    }
    
    return cycles;
}


DependencyGraph::Snapshot DependencyGraph::create_snapshot() const {
    std::shared_lock lock(mutex_);

    Snapshot snap;

    snap.threads.reserve(threads_.size());
    for (const auto& [tid, t] : threads_) {
        Snapshot::ThreadSnapshot ts;
        ts.tid = t.tid;
        ts.name = t.name;  
        ts.is_waiting = t.waiting_for.has_value();
        ts.waiting_for_mutex = t.waiting_for.value_or(0);
        ts.holding.assign(t.holding.begin(), t.holding.end());
        ts.total_wait_ms = t.total_wait_time_ns / 1'000'000;
        ts.total_hold_ms = t.total_hold_time_ns / 1'000'000;
        ts.contentions = t.lock_contentions;
        snap.threads.push_back(std::move(ts));
    }

    snap.mutexes.reserve(mutexes_.size());
    for (const auto& [addr, m] : mutexes_) {
        Snapshot::MutexSnapshot ms;
        ms.addr = m.addr;
        ms.name = m.symbol_name.empty() ? ("0x" + std::to_string(addr)) : m.symbol_name;
        ms.held_by = m.held_by;
        ms.waiting_threads.assign(m.waiting_threads.begin(), m.waiting_threads.end());
        ms.avg_wait_ms = m.wait_histogram.mean() / 1'000'000;
        ms.max_wait_ms = m.wait_histogram.max() / 1'000'000;
        ms.avg_hold_ms = m.hold_histogram.mean() / 1'000'000;
        ms.contention_count = m.contention_count;
        ms.acquisition_count = m.acquisition_count;
        ms.p95_wait_ms = m.wait_histogram.percentile(0.95) / 1'000'000;
        ms.p99_wait_ms = m.wait_histogram.percentile(0.99) / 1'000'000;
        snap.mutexes.push_back(std::move(ms));
    }

    snap.deadlock_cycles = find_cycles();
    return snap;
}

DependencyGraph::Snapshot DependencyGraph::create_snapshot(Symbolizer& sym) const {
    std::shared_lock lock(mutex_);
    
    Snapshot snap;
    

    snap.threads.reserve(threads_.size());
    for (const auto& [tid, t] : threads_) {
        Snapshot::ThreadSnapshot ts;
        ts.tid = t.tid;

        ts.name = sym.get_thread_name(t.tid);
        ts.is_waiting = t.waiting_for.has_value();
        ts.waiting_for_mutex = t.waiting_for.value_or(0);
        ts.holding.assign(t.holding.begin(), t.holding.end());
        ts.total_wait_ms = t.total_wait_time_ns / 1'000'000;
        ts.total_hold_ms = t.total_hold_time_ns / 1'000'000;
        ts.contentions = t.lock_contentions;
        snap.threads.push_back(std::move(ts));
    }
    
    snap.mutexes.reserve(mutexes_.size());
    for (const auto& [addr, m] : mutexes_) {
        Snapshot::MutexSnapshot ms;
        ms.addr = m.addr;
        
        ms.name = sym.resolve_mutex(m.addr);
        ms.held_by = m.held_by;
        ms.waiting_threads.assign(m.waiting_threads.begin(), m.waiting_threads.end());
        ms.avg_wait_ms = m.wait_histogram.mean() / 1'000'000;
        ms.max_wait_ms = m.wait_histogram.max() / 1'000'000;
        ms.avg_hold_ms = m.hold_histogram.mean() / 1'000'000;
        ms.contention_count = m.contention_count;
        ms.acquisition_count = m.acquisition_count;
        ms.p95_wait_ms = m.wait_histogram.percentile(0.95) / 1'000'000;
        ms.p99_wait_ms = m.wait_histogram.percentile(0.99) / 1'000'000;
        snap.mutexes.push_back(std::move(ms));
    }
        snap.deadlock_cycles = find_cycles();
    
    return snap;
}

void DependencyGraph::clear() {
    std::unique_lock lock(mutex_);
    threads_.clear();
    mutexes_.clear();
}

} 