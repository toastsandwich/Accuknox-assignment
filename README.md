# 🚀 TCP Packet Dropper (using eBPF and Cilium)
Welcome to the journey where I learned to write code to modify the kernel to our needs. This repository contains code that drops TCP packets incoming to port 4040 using the power of eBPF (extended Berkeley Packet Filtering). It does more than its name suggests 😉

# 📋 Requirements
- 🐧 A Linux-based operating system (bare-metal or VM)
- 📦 Installed packages: ```llvm, clang, go, bpftools, make```
- 🌐 Basic networking knowledge

#🛠️ How to Run
📂 Clone the repository:
```bash
git clone https://github.com/toastsandwich/Accuknox-assignment
```
📦 Install required packages:
```bash
make
```
🏗️ Build the code:

```bash
make build
```
🚀 Run the build as root:
```bash
sudo ./Accuknox-assignment
```

# 🔑 Key Components
1. Data Structures
```c
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
```
- data_t struct helps to interact with userspace code.
- tcp_pkt_t is a map array working with BPF to map our data.

2. TCP Header Extraction
```c
static __always_inline struct tcphdr* get_tcp_header(struct xdp_md *ctx) {
    // Retrieve packet data and data_end pointer from context
    void *data = (void *)(long) ctx->data;
    void *data_end = (void *)(long) ctx->data_end;

    // Ensure Ethernet header fits within packet boundaries
    if (data + sizeof(struct ethhdr) > data_end)
        return NULL;

    // Extract Ethernet header
    struct ethhdr *eth = data;

    // Check if Ethernet frame contains an IPv4 packet
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
```
- This function retrieves the TCP header required to check the request. If the destination port is 4040, the packet is dropped.
# ⚙️ How it Works
- Initialization: The eBPF program is loaded into the kernel and attached to a network interface.
- Packet Inspection: Incoming packets are intercepted and passed to the eBPF program.
- Header Extraction: The program extracts the Ethernet, IP, and TCP headers to inspect the packet's destination port.
- Packet Dropping: If the destination port is 4040, the packet is dropped; otherwise, it is allowed to pass through.

# 🖥️ eBPF + Cilium in action
![output](https://github.com/toastsandwich/Accuknox-assignment/assets/83450905/cb4b455d-6437-4736-a1bf-997c2bc848af)
- This program monitors port 4040 and skips rest of them.
- If packet contains TCP protocol, the port is checked.
  ```go
    if port == 4040 {
      drop
    } else {
      pass
    }
  ```
  
# 🧑‍🦱 Author
[@toastsandwich](https://www.github.com/toastsandwich)
