//go:build ignore

#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <sys/cdefs.h>

#define _TCP 6

struct data_t {
    __u32 protocol;
    __u32 port;
    char status[5];
    char padding[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct data_t);
    __uint(max_entries, 1);
} tcp_pkt_t SEC(".maps");

// helper function to get TCP Header
static __always_inline struct tcphdr* get_tcp_header(struct xdp_md *ctx) {
    void *data = (void *)(long) ctx->data;
    void *data_end = (void *)(long) ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end)
        return NULL;

    struct ethhdr *eth = data;

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        // Calculate the IP header start
        struct iphdr *iph = data + sizeof(struct ethhdr);

        // Ensure IP header fits within packet boundaries
        if ((void *)(iph + 1) > data_end)
            return NULL;

        // Validate IP header length
        if (iph->ihl < 5 || iph->ihl > 15) // ihl is in 32-bit words, must be 5-15
            return NULL;

        // Calculate TCP header start based on IP header length (in bytes)
        struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

        // Ensure TCP header fits within packet boundaries
        if ((void *)(tcph + 1) > data_end)
            return NULL;

        // Return pointer to TCP header
        return tcph;
    }

    // Not an IPv4 packet, return NULL
    return NULL;
}

// main function of XDP
SEC("xdp")
int drop_tcp_packets(struct xdp_md *ctx) {
    __u32 key = 0; //key for map
    struct data_t *data = bpf_map_lookup_elem(&tcp_pkt_t, &key);
    // if data not found pass
    if (!data) {
        return XDP_PASS; 
    }
    // get tcp header
    struct tcphdr *tcph = get_tcp_header(ctx);
    if (!tcph) {
        data->port = 0;
        data->protocol = 0;
        strncpy(data->status, "Pass", sizeof(data->status) - 1);
        data->status[sizeof(data->status) - 1] = '\0'; 
        return XDP_PASS;
    }
    // check the port
    if (bpf_ntohs(tcph->dest) == 4040) {
        data->port = bpf_ntohs(tcph->dest);
        data->protocol = _TCP;
        strncpy(data->status, "Drop", sizeof(data->status) - 1);
        data->status[sizeof(data->status) - 1] = '\0'; 
        return XDP_DROP;
    } else {
        data->port = bpf_ntohs(tcph->source);
        data->protocol = _TCP;
        strncpy(data->status, "Pass", sizeof(data->status) - 1);
        data->status[sizeof(data->status) - 1] = '\0'; 
        return XDP_PASS;
    }
}

// license
char LICENSE[] SEC("license") = "Dual BSD/GPL";