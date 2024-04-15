#include <stdlib.h>
#include <linux/bpf.h>
#include <klee/klee.h>

void* create_packet(size_t pkt_size) {
	void *packet = malloc(pkt_size);
	klee_make_symbolic(packet, pkt_size, "packet");
	return packet;
}

struct xdp_md* create_ctx() {
    void* ctx = malloc(sizeof(struct xdp_md));
    klee_make_symbolic(ctx, sizeof(struct xdp_md), "ctx");
    return (struct xdp_md*)ctx;
}