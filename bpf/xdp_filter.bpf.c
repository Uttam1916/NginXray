#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>

// ip key
struct lpm_key {
  __u32 prefixlen;
  __u32 ip;
};

// longest prefix match trie
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 255);
  __uint(map_flags, BPF_F_NO_PREALLOC);

  __type(key, struct lpm_key);
  __type(value, __u32);
} lpm_map SEC(".maps");

// define xdp section
SEC("xdp")
int filter(struct xdp_md *ctx) {
  // cast it into a long pointer
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;

  // check if packet shape is correct
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  // only deal with ipv4 currently
  if (eth->h_proto != __constant_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *ip = (void *)(eth + 1);

  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

  // traceprint ip
  bpf_printk("src=%x", ip->saddr);
  struct lpm_key key = {};

  key.prefixlen = 32;
  key.ip = ip->saddr;

  __u32 *blocked;

  // get value from trie if ip exists in it
  blocked = bpf_map_lookup_elem(&lpm_map, &key);

  // print status
  if (blocked) {
    bpf_printk("DROP");
    return XDP_DROP;
  }
  bpf_printk("PASS");

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
