// src/bpf/mutex_probe.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "mutex_probe.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   
    __type(value, __u64);  
} waiting_mutex SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
} stacks SEC(".maps");


static __always_inline void send_event(void* ctx, enum event_type type, __u64 mutex_addr, __u64 wait_ns) {
    struct mutex_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->event_type = type;
    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;
    e->mutex_addr = mutex_addr;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->wait_time_ns = wait_ns;
    e->trylock_result = 0;
    e->stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    bpf_ringbuf_submit(e, 0);
}

SEC("uprobe/pthread_mutex_lock")
int uprobe_mutex_lock(struct pt_regs* ctx) {
    void* mutex = (void*)PT_REGS_PARM1(ctx);
    __u64 addr = (__u64)mutex;
    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&waiting_mutex, &tid, &addr, BPF_ANY);
    send_event(ctx, EVENT_LOCK_ENTER, addr, 0);
    return 0;
}

SEC("uretprobe/pthread_mutex_lock")
int uretprobe_mutex_lock(struct pt_regs* ctx) {
    __u32 tid = bpf_get_current_pid_tgid();
    __u64* addr_ptr = bpf_map_lookup_elem(&waiting_mutex, &tid);
    if (!addr_ptr) return 0;
    __u64 addr = *addr_ptr;
    bpf_map_delete_elem(&waiting_mutex, &tid);

    send_event(ctx, EVENT_LOCK_EXIT, addr, 0);
    return 0;
}

SEC("uprobe/pthread_mutex_unlock")
int uprobe_mutex_unlock(struct pt_regs* ctx) {
    void* mutex = (void*)PT_REGS_PARM1(ctx);
    send_event(ctx, EVENT_UNLOCK, (__u64)mutex, 0);
    return 0;
}

SEC("uprobe/pthread_mutex_trylock")
int uprobe_mutex_trylock(struct pt_regs* ctx) {
    void* mutex = (void*)PT_REGS_PARM1(ctx);

    __u64 addr = (__u64)mutex;
    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&waiting_mutex, &tid, &addr, BPF_ANY);
    send_event(ctx, EVENT_TRYLOCK, addr, 0);
    return 0;
}

SEC("uretprobe/pthread_mutex_trylock")
int uretprobe_mutex_trylock(struct pt_regs* ctx) {
    int ret = PT_REGS_RC(ctx);
    __u32 tid = bpf_get_current_pid_tgid();
    __u64* addr_ptr = bpf_map_lookup_elem(&waiting_mutex, &tid);
    if (!addr_ptr) return 0;
    __u64 addr = *addr_ptr;
    bpf_map_delete_elem(&waiting_mutex, &tid);
    enum event_type type = (ret == 0) ? EVENT_TRYLOCK_OK : EVENT_TRYLOCK_FAIL;
    send_event(ctx, type, addr, 0);
    return 0;
}