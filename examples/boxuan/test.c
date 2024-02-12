#include <stdlib.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "klee/klee.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct boxuan_pkt {
	struct ethhdr ether;
	struct iphdr ipv4;
	struct tcphdr tcp;
	char payload[100];
};


#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END)                                  \
        (((void *)PTR) + OFFSET > ((void *)END))

SEC("xdp")
int xdp_main(struct xdp_md* ctx) {
	void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr* eth = data;

        if (CHECK_OUT_OF_BOUNDS(data, sizeof(struct ethhdr), data_end))
                return XDP_DROP;

        struct iphdr *ip = data + sizeof(struct ethhdr);
        if (CHECK_OUT_OF_BOUNDS(ip, sizeof(struct iphdr), data_end))
                return XDP_DROP;

        if (ip->protocol != IPPROTO_TCP) {
                return XDP_PASS;
        }
        struct tcphdr *tcp = (void *) ip + sizeof(struct iphdr);
        if (CHECK_OUT_OF_BOUNDS(tcp, sizeof(struct tcphdr), data_end))
                return XDP_DROP;
	char* payload = (void *) tcp + sizeof(struct tcphdr);
	if (payload[0] == '\0') return XDP_DROP;

	return XDP_PASS;
}


int main() {      
	struct boxuan_pkt *pkt = malloc(sizeof(struct boxuan_pkt));
	klee_make_symbolic(pkt, sizeof(struct boxuan_pkt), "pkt");
//	pkt->ether.h_proto = bpf_htons(ETH_P_IP);
//	pkt->ipv4.version = 4;
//	pkt->ipv4.ihl = sizeof(struct iphdr) / 4;
//	pkt->tcp.doff = sizeof(struct tcphdr) / 4;

	struct xdp_md test;
    test.data = (long)(&(pkt->ether));
	test.data_end = (long)(pkt + 1);
	test.data_meta = 0;
	test.ingress_ifindex = 0;
	test.rx_queue_index = 0;
	return xdp_main(&test);
}


