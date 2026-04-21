#include <gtest/gtest.h>
#include "common/event.hpp"

TEST(EventTest, RawMutexEventSize) {
    EXPECT_EQ(sizeof(weave::RawMutexEvent), 48);
}

TEST(EventTest, FromRawConversion) {
    weave::RawMutexEvent raw{};
    raw.event_type = 1; // MutexLockEnter
    raw.pid = 1234;
    raw.tid = 5678;
    raw.mutex_addr = 0x7f3a12340000;
    raw.timestamp_ns = 123456789;

    auto ev = weave::MutexEvent::from_raw(raw);

    EXPECT_EQ(ev.type, weave::EventType::MutexLockEnter);
    EXPECT_EQ(ev.pid, 1234);
    EXPECT_EQ(ev.tid, 5678);
    EXPECT_EQ(ev.mutex_addr, 0x7f3a12340000);
    EXPECT_EQ(ev.timestamp_ns, 123456789);
}

TEST(EventTest, TrylockSuccess) {
    weave::RawMutexEvent raw{};
    raw.event_type = 5; // MutexTryLockOk

    auto ev = weave::MutexEvent::from_raw(raw);
    EXPECT_EQ(ev.type, weave::EventType::MutexTryLockOk);
    EXPECT_TRUE(ev.trylock_success);
}

TEST(EventTest, TrylockFail) {
    weave::RawMutexEvent raw{};
    raw.event_type = 4; // MutexTryLockFail

    auto ev = weave::MutexEvent::from_raw(raw);
    EXPECT_EQ(ev.type, weave::EventType::MutexTryLockFail);
    EXPECT_FALSE(ev.trylock_success);
}

