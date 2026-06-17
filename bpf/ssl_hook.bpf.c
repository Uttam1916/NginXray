#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct SSL_data {
    __u32 len;
    __u8 buf[8192];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192 * 128);
} ringbuf SEC(".maps")
