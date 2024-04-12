#include <stdlib.h>
#include <linux/bpf.h>
#include <klee/klee.h>

void* create_packet(size_t pkt_size) {
	void *packet = malloc(pkt_size);
	klee_make_symbolic(packet, pkt_size, "packet");
	return packet;
}

struct xdp_md* create_ctx(void* pkt, size_t pkt_size, size_t eth_offset) {
    struct xdp_md* ctx = (struct xdp_md*) malloc(sizeof(struct xdp_md));
    klee_make_symbolic(ctx, sizeof(struct xdp_md), "ctx");
    ctx->data = (long)pkt + eth_offset;
    ctx->data_end = (long)pkt + pkt_size;
    return (struct xdp_md*)ctx;
}