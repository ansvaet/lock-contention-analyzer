#pragma once

#include <cstdint>
#include <string>
#include <chrono>

namespace weave {

    enum class EventType : uint8_t {
        MutexLockEnter = 1,     // Поток вызвал pthread_mutex_lock, начал ждать
        MutexLockExit = 2,      // Поток получил mutex (возврат из pthread_mutex_lock)
        MutexUnlock = 3,        // Поток вызвал pthread_mutex_unlock
        MutexTryLockFail = 4,   // pthread_mutex_trylock вернул EBUSY (mutex занят)
        MutexTryLockOk = 5,     // pthread_mutex_trylock успешно захватил mutex
    };


    struct RawMutexEvent {
        uint32_t event_type;    
        uint32_t pid;           
        uint32_t tid;          
        uint64_t mutex_addr;   
        uint64_t timestamp_ns; 
        uint64_t wait_time_ns;  
        int32_t  trylock_result; 
        int32_t  stack_id;      
    };

    static_assert(sizeof(RawMutexEvent) == 48, "RawMutexEvent must be 48 bytes");

    struct MutexEvent {
        EventType type;
        uint32_t pid;          
        uint32_t tid;           
        uint64_t mutex_addr;    
        uint64_t timestamp_ns;  
        uint64_t wait_time_ns;  
        uint32_t stack_id; 
        bool trylock_success;

        static MutexEvent from_raw(const RawMutexEvent& raw) {
            MutexEvent ev;
            ev.type = static_cast<EventType>(raw.event_type);
            ev.pid = raw.pid;
            ev.tid = raw.tid;
            ev.mutex_addr = raw.mutex_addr;
            ev.timestamp_ns = raw.timestamp_ns;
            ev.wait_time_ns = raw.wait_time_ns;
            ev.stack_id = raw.stack_id;

            if (ev.type == EventType::MutexTryLockOk) {
                ev.trylock_success = true;
            }
            else if (ev.type == EventType::MutexTryLockFail) {
                ev.trylock_success = false;
            }

            return ev;
        }
    };
}