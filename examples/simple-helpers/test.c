#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	void* data     = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr  *ip;
	struct tcphdr *tcp;
	char		  *payload;
	uint64_t nh_off = 0;

	eth = data;
	nh_off = sizeof(*eth);
	// if (data  + nh_off  > data_end)
	// 	goto EOP;

	ip = data + nh_off;
	nh_off += sizeof(*ip);
	if (data + nh_off  > data_end)
		goto EOP;

	if(ip->protocol != IPPROTO_TCP){
		return XDP_PASS;
	}

	tcp = data + nh_off;
	nh_off += sizeof(*tcp);
	// if (data + nh_off  > data_end)
	// 	goto EOP;

	payload = data + nh_off;
	nh_off += 1;
	if (data + nh_off  > data_end)
		goto EOP;

	if (payload[0] == '\0') return XDP_DROP;

	return XDP_PASS;

	EOP:
		return XDP_DROP;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <assert.h>
#include <stdlib.h>
int xdp_spec(struct xdp_md *ctx) {
	struct pkt *packet = (void *)(long)(ctx->data);
	struct iphdr *ip = (void*)&(packet->ipv4);
	char *payload = (void *)&(packet->payload);

	if (ip->protocol != IPPROTO_TCP) {
			return XDP_PASS;
	}
	if (payload[0] == '\0') return XDP_DROP;
	return XDP_PASS;
}

int main() {
	struct pkt *packet = malloc(sizeof(struct pkt));
	klee_make_symbolic(packet, sizeof(*packet), "packet");
	struct xdp_md test;
	klee_make_symbolic(&test, sizeof(test), "test");
	test.data = (long)(packet);
	test.data_end = (long)(packet + 1);
	assert(xdp_main(&test)==xdp_spec(&test));
	return 0;
}
#endif