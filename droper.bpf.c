#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <sys/cdefs.h>

#define __TCP 6

static __always_inline char lookup_protocol(struct xdp_md *ctx) {
    unsigned char protocol = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if(data + sizeof(struct ethhdr) > data_end)
        return 0;

    if(bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
    }
    return protocol;
}

SEC("xdp_drop")
int xdp_drop_tcp_func(struct xdp_md *ctx) {
    long protocol = lookup_protocol(ctx);
    if(protocol == __TCP) {
        return XDP_DROP;
    }
    return XDP_PASS;
}