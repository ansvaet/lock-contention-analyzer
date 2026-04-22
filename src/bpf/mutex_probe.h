#ifndef __MUTEX_PROBE_H
#define __MUTEX_PROBE_H

enum event_type {
    EVENT_LOCK_ENTER = 1,
    EVENT_LOCK_EXIT = 2,
    EVENT_UNLOCK = 3,
    EVENT_TRYLOCK_OK = 4,
    EVENT_TRYLOCK_FAIL = 5,
    EVENT_TRYLOCK = 6,  
};

struct mutex_event {
    unsigned int event_type;
    unsigned int pid;
    unsigned int tid;
    unsigned long long mutex_addr;
    unsigned long long timestamp_ns;
    unsigned long long wait_time_ns;
    int trylock_result;
    int stack_id;
};

#endif