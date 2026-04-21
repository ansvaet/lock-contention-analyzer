#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <atomic>
#include "common/spsc_queue.hpp"

TEST(SPSCQueueTest, NewQueueIsEmpty) {
    weave::SPSCQueue<int, 16> q;
    EXPECT_TRUE(q.empty());
    EXPECT_EQ(q.size_approx(), 0);
}

TEST(SPSCQueueTest, PushPopSingleElement) {
    weave::SPSCQueue<int, 16> q;

    EXPECT_TRUE(q.try_push(42));
    EXPECT_FALSE(q.empty());
    EXPECT_EQ(q.size_approx(), 1);

    auto val = q.try_pop();
    EXPECT_TRUE(val.has_value());
    EXPECT_EQ(*val, 42);
    EXPECT_TRUE(q.empty());
}

TEST(SPSCQueueTest, PopEmptyReturnsNullopt) {
    weave::SPSCQueue<int, 16> q;
    auto val = q.try_pop();
    EXPECT_FALSE(val.has_value());
}

TEST(SPSCQueueTest, FifoOrder) {
    weave::SPSCQueue<int, 16> q;

    q.try_push(1);
    q.try_push(2);
    q.try_push(3);

    EXPECT_EQ(*q.try_pop(), 1);
    EXPECT_EQ(*q.try_pop(), 2);
    EXPECT_EQ(*q.try_pop(), 3);
}

TEST(SPSCQueueTest, FullQueueRejectsPush) {
    weave::SPSCQueue<int, 4> q;  // Ёмкость 4, но слотов для записи 3

    EXPECT_TRUE(q.try_push(1));
    EXPECT_TRUE(q.try_push(2));
    EXPECT_TRUE(q.try_push(3));
    EXPECT_FALSE(q.try_push(4));  // Очередь полна
}

TEST(SPSCQueueTest, WrapAround) {
    weave::SPSCQueue<int, 4> q;

    // Заполняем
    q.try_push(1);
    q.try_push(2);
    q.try_push(3);

    // Читаем один
    EXPECT_EQ(*q.try_pop(), 1);

    // Теперь можем записать ещё
    EXPECT_TRUE(q.try_push(4));

    // Читаем остальное
    EXPECT_EQ(*q.try_pop(), 2);
    EXPECT_EQ(*q.try_pop(), 3);
    EXPECT_EQ(*q.try_pop(), 4);
}

 //Многопоточные тесты
//TEST(SPSCQueueTest, ConcurrentPushPop) {
//    weave::SPSCQueue<int, 1024> q;
//    std::atomic<bool> stop{ false };
//    std::vector<int> consumed;
//    std::mutex consumed_mutex;
//
//    // Producer thread
//    std::thread producer([&]() {
//        int i = 0;
//        while (!stop) {
//            if (q.try_push(i)) {
//                ++i;
//            }
//        }
//        // Записываем сколько всего отправлено
//        q.try_push(-1);
//        });
//
//    // Consumer thread
//    std::thread consumer([&]() {
//        while (true) {
//            auto val = q.try_pop();
//            if (val.has_value()) {
//                if (*val == -1) break;
//                std::lock_guard<std::mutex> lock(consumed_mutex);
//                consumed.push_back(*val);
//            }
//        }
//        });
//
//    // Даём поработать 100ms
//    std::this_thread::sleep_for(std::chrono::milliseconds(100));
//    stop = true;
//
//    producer.join();
//    consumer.join();
//
//    // Проверяем что все числа получены по порядку
//    EXPECT_FALSE(consumed.empty());
//    for (size_t i = 1; i < consumed.size(); ++i) {
//        EXPECT_EQ(consumed[i], consumed[i - 1] + 1);
//    }
//}

