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

	if (payload[0] == '\0') {
		payload[0] = '\1';
		return XDP_DROP;
	}
	if (payload[1] == '\0') {
		payload[2] = '\1';
		return XDP_PASS;
	}
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

	if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
	if (payload[0] == '\0') {
		payload[0] = '\1';
		return XDP_DROP;
	}
	if (payload[1] == '\0') {
		payload[2] = '\2';
		return XDP_PASS;
	}
	return XDP_PASS;
}

typedef int(*xdp_func)(struct xdp_md*);
struct xdp_end_state {
	int rvalue;
	struct pkt pkt;
};

#include <stdbool.h>
#include <string.h>
bool xdp_end_state_equal(struct xdp_end_state *a, struct xdp_end_state *b) {
	return a->rvalue == b->rvalue && memcmp(&(a->pkt), &(b->pkt), sizeof(struct pkt)) == 0;
}

struct xdp_end_state get_xdp_end_state(xdp_func f, struct xdp_md* ctx) {
	struct xdp_end_state s;
	s.rvalue = f(ctx);
	memcpy(&(s.pkt), (void*)(long)ctx->data, sizeof (struct pkt));
	return s;
}

void functional_verify(xdp_func prog, xdp_func spec, struct pkt* packet) {
	struct xdp_md ctx;
	struct xdp_md ctx_copy;
	struct pkt* packet_copy = malloc(sizeof(struct pkt));
	memcpy(packet_copy, packet, sizeof(struct pkt));
	ctx.data = (long)packet;
	ctx.data_end = (long)(packet + 1);
	ctx_copy.data = (long)packet_copy;
	ctx_copy.data_end = (long)(packet_copy + 1);
	struct xdp_end_state prog_end_state = get_xdp_end_state(prog, &ctx);
	struct xdp_end_state spec_end_state = get_xdp_end_state(spec, &ctx_copy);
	assert(xdp_end_state_equal(&prog_end_state, &spec_end_state));
}

int main() {
	struct pkt *packet = malloc(sizeof(struct pkt));
	klee_make_symbolic(packet, sizeof(*packet), "packet");
	// struct xdp_md test;
	// test.data = (long)(packet);
	// test.data_end = (long)(packet + 1);
	functional_verify(xdp_main, xdp_spec, packet);
	return 0;
}
#endif