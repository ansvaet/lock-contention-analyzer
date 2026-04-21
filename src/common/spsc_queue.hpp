#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <optional>

namespace weave {

	template<typename T, size_t Capacity>
	class SPSCQueue {
		static_assert((Capacity& (Capacity - 1)) == 0,
			"Capacity must be a power of 2");
		static constexpr size_t kMask = Capacity - 1;

		std::array<T, Capacity> buffer_;
		
		alignas(64) std::atomic<size_t> write_pos_{ 0 };
		alignas(64) std::atomic<size_t> read_pos_{ 0 };
	public:
		SPSCQueue() = default;

		SPSCQueue(const SPSCQueue&) = delete;
		SPSCQueue& operator=(const SPSCQueue&) = delete;

		constexpr size_t capacity() const {
			return Capacity;
		}
		bool empty() const {
			return read_pos_.load(std::memory_order_acquire)
				== write_pos_.load(std::memory_order_acquire);
		}
		size_t size_approx() const {
			size_t w = write_pos_.load(std::memory_order_relaxed);
			size_t r = read_pos_.load(std::memory_order_relaxed);
			return (w - r) & kMask;
		}

		std::optional<T> try_pop() {
			size_t read = read_pos_.load(std::memory_order_relaxed);

			if (read == write_pos_.load(std::memory_order_acquire)) {
				return std::nullopt;
			}

			T item = buffer_[read];

			read_pos_.store((read + 1) & kMask, std::memory_order_release);
			return item;
		}

		bool try_push(const T& item) {
			size_t write = write_pos_.load(std::memory_order_relaxed);
			size_t next = (write + 1) & kMask;

			if (next == read_pos_.load(std::memory_order_acquire)) {
				return false;
			}

			buffer_[write] = item;

			write_pos_.store(next, std::memory_order_release);
			return true;
		}
	};
}