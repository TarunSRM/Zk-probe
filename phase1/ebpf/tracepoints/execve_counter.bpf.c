#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Map storing execve count - using __u64 directly for compatibility */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);  /* Direct __u64, not struct */
} execve_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&execve_map, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";