#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "../common/parsing_helpers.h"

struct ethhdr* get_eth(struct xdp_md *ctx) {
    return (struct ethhdr*)(long)(ctx->data);
}

int get_eth_proto(struct xdp_md *ctx) {
    struct ethhdr *eth = get_eth(ctx);
    struct vlan_hdr *vlh = (struct vlan_hdr*)(eth+1);
    __u16 h_proto = eth->h_proto;

    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		vlh++;
	}
    return h_proto;
}

struct iphdr* get_ip(struct xdp_md *ctx) {
    struct ethhdr *eth = get_eth(ctx);
    struct vlan_hdr *vlh = (struct vlan_hdr *)(eth+1);
    __u16 h_proto = eth->h_proto;

    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		vlh++;
	}
    return (void*)(vlh);
}

int get_ip_protocol(struct xdp_md *ctx) {
    struct iphdr* ip = get_ip(ctx);
    return ip->protocol;
}

void* get_tcp_udp(struct xdp_md *ctx) {
    struct iphdr *ip = get_ip(ctx);
    int iphdr_size = ip->ihl * 4;
    return ((void*)(ip)) + iphdr_size;
}