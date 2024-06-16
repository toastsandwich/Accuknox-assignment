//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define _TCP 6

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} tcp_pkt_count_t SEC(".maps");

static __always_inline unsigned char lookup_pkt_tcp(struct xdp_md *ctx) {
    unsigned char protocol = 0;
    void *data = (void*)(long) ctx->data;
    void *data_end = (void*)(long) ctx->data_end;

    struct ethhdr *eth = data;
    if(data + sizeof(struct ethhdr) > data_end)
        return 0;
    
    if(bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
    }
    return protocol;
}

SEC("xdp")
int count_tcp_packets(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&tcp_pkt_count_t, &key);
    __u64 protocol = lookup_pkt_tcp(ctx);
    if (count && protocol == _TCP) {
        bpf_printk("tcp packet found count will increase");
        __sync_fetch_and_add(count, 1);
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";