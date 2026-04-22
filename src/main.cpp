#include <iostream>
#include <signal.h>
#include <thread>
#include <atomic>
#include "collector/collector.hpp"
#include "common/spsc_queue.hpp"
#include "analyzer/dependency_graph.hpp"
#include "symbolizer/symbolizer.hpp"

using namespace weave;

static std::atomic<bool> running{ true };

void sig_handler(int) {
    running = false;
}

constexpr size_t QUEUE_CAPACITY = 1024 * 1024; 

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pid>\n";
        return 1;
    }
    pid_t target_pid = std::stoi(argv[1]);

    std::cout << "weave v0.1.0 - Lock Contention Analyzer\n";
    std::cout << "Target PID: " << target_pid << "\n";

    auto queue = std::make_shared<SPSCQueue<MutexEvent, QUEUE_CAPACITY>>();

    Collector collector(target_pid);

    collector.set_callback([queue](const MutexEvent& ev) {
        if (!queue->try_push(ev)) {

        }
        });

    if (!collector.start()) {
        std::cerr << "Failed to start collector\n";
        return 1;
    }

    Symbolizer symbolizer(target_pid);
    DependencyGraph graph;

 
    std::thread analyzer_thread([&]() {
        while (running) {
            auto ev_opt = queue->try_pop();
            if (ev_opt.has_value()) {
                graph.process_event(*ev_opt);
            }
            else {
   
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
        });

    std::thread stats_thread([&]() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(2));

            auto snapshot = graph.create_snapshot(symbolizer);

            std::cout << "\n=== Snapshot ===\n";
            std::cout << "Threads: " << snapshot.threads.size() << "\n";
            std::cout << "Mutexes: " << snapshot.mutexes.size() << "\n";

            std::vector<DependencyGraph::Snapshot::MutexSnapshot> mutexes = snapshot.mutexes;
            std::sort(mutexes.begin(), mutexes.end(),
                [](const auto& a, const auto& b) {
                    return a.contention_count > b.contention_count;
                });

            std::cout << "\nTop contended mutexes:\n";
            for (size_t i = 0; i < std::min(size_t(5), mutexes.size()); ++i) {
                const auto& m = mutexes[i];
                std::cout << "  " << m.name
                    << " | waits: " << m.contention_count
                    << " | avg wait: " << m.avg_wait_ms << "ms"
                    << " | p95: " << m.p95_wait_ms << "ms\n";
            }

            if (!snapshot.deadlock_cycles.empty()) {
                std::cout << "\n DEADLOCK DETECTED! Cycles:\n";
                for (const auto& cycle : snapshot.deadlock_cycles) {
                    std::cout << "  ";
                    for (uint32_t tid : cycle) {
                        std::cout << "T" << tid << " -> ";
                    }
                    std::cout << "T" << cycle[0] << "\n";
                }
            }
            std::cout << "=================\n";
        }
        });

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    std::cout << "Running... Press Ctrl+C to stop\n";

    analyzer_thread.join();
    stats_thread.join();

    collector.stop();
    std::cout << "Done.\n";

    return 0;
}