#include <linux/bpf.h>

struct ethhdr* get_ethhdr(struct xdp_md* ctx) {
    return (struct ethhdr*)(long)ctx->data;
}

struct iphdr* get_iphdr(struct xdp_md* ctx) {
    return (struct iphdr*)((void*)(long)ctx->data + sizeof(struct ethhdr));
}

struct udphdr* get_udphdr(struct xdp_md* ctx) {
    return (struct udphdr*)((void*)(long)ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
}