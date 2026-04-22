#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <algorithm>

namespace weave {

    class Histogram {
        static constexpr int kNumBuckets = 64;

        std::array<std::atomic<uint64_t>, kNumBuckets> counts_{};
        std::atomic<uint64_t> total_count_{ 0 };
        std::atomic<uint64_t> total_sum_{ 0 };
        std::atomic<uint64_t> max_value_{ 0 };

        static int bucket_index(uint64_t value) {
            if (value == 0) return 0;

            int bit = 63 - __builtin_clzll(value)+1;

            return std::min(kNumBuckets - 1, bit);
        }

        static uint64_t bucket_upper_bound(int index) {
            if (index == 0) return 1;
            return 1ULL << index;
        }

    public:
        Histogram() = default;

        Histogram(const Histogram& other) {
            for (int i = 0; i < kNumBuckets; ++i) {
                counts_[i].store(other.counts_[i].load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
            }
            total_count_.store(other.total_count_.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
            total_sum_.store(other.total_sum_.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
            max_value_.store(other.max_value_.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
        }

        Histogram& operator=(const Histogram& other) {
            if (this != &other) {
                for (int i = 0; i < kNumBuckets; ++i) {
                    counts_[i].store(other.counts_[i].load(std::memory_order_relaxed),
                        std::memory_order_relaxed);
                }
                total_count_.store(other.total_count_.load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
                total_sum_.store(other.total_sum_.load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
                max_value_.store(other.max_value_.load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
            }
            return *this;
        }

        void record(uint64_t value) {
            int idx = bucket_index(value);
            counts_[idx].fetch_add(1, std::memory_order_relaxed);
            total_count_.fetch_add(1, std::memory_order_relaxed);
            total_sum_.fetch_add(value, std::memory_order_relaxed);

            // Обновляем максимум через CAS
            uint64_t prev = max_value_.load(std::memory_order_relaxed);
            while (value > prev) {
                if (max_value_.compare_exchange_weak(prev, value,
                    std::memory_order_relaxed,
                    std::memory_order_relaxed)) {
                    break;
                }
            }
        }

        uint64_t percentile(double p) const {
            if (p < 0.0) p = 0.0;
            if (p > 1.0) p = 1.0;

            uint64_t count = total_count_.load(std::memory_order_relaxed);
            if (count == 0) return 0;

            uint64_t threshold = static_cast<uint64_t>(count * p);
            if (threshold >= count) threshold = count - 1;

            uint64_t cumulative = 0;
            for (int i = 0; i < kNumBuckets; ++i) {
                cumulative += counts_[i].load(std::memory_order_relaxed);
                if (cumulative > threshold) {
                    return bucket_upper_bound(i);
                }
            }

            return max_value_.load(std::memory_order_relaxed);
        }

        uint64_t mean() const {
            uint64_t cnt = total_count_.load(std::memory_order_relaxed);
            if (cnt == 0) return 0;
            return total_sum_.load(std::memory_order_relaxed) / cnt;
        }

        uint64_t count() const {
            return total_count_.load(std::memory_order_relaxed);
        }

        uint64_t max() const {
            return max_value_.load(std::memory_order_relaxed);
        }

        uint64_t sum() const {
            return total_sum_.load(std::memory_order_relaxed);
        }

        void clear() {
            for (int i = 0; i < kNumBuckets; ++i) {
                counts_[i].store(0, std::memory_order_relaxed);
            }
            total_count_.store(0, std::memory_order_relaxed);
            total_sum_.store(0, std::memory_order_relaxed);
            max_value_.store(0, std::memory_order_relaxed);
        }

        std::array<uint64_t, kNumBuckets> buckets() const {
            std::array<uint64_t, kNumBuckets> result;
            for (int i = 0; i < kNumBuckets; ++i) {
                result[i] = counts_[i].load(std::memory_order_relaxed);
            }
            return result;
        }

    };
} 