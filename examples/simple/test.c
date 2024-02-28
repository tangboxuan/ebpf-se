#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	return XDP_PASS;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <assert.h>
#include <stdlib.h>
int xdp_spec(struct xdp_md *ctx) {
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