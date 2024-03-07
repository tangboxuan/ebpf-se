#include "linux/bpf.h"
#include <linux/if_ether.h>
#include <linux/ip.h>

struct ethhdr* get_l2(struct xdp_md *ctx) {
    return (void*)(long)(ctx->data);
}

void* get_l3(struct ethhdr *eth) {
    return eth + 1;
}

void* get_l4(struct iphdr *ip) {
    return ip + 1;
}