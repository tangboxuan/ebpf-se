#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <linux/bpf.h>

typedef int(*xdp_func)(struct xdp_md*);

struct xdp_end_state {
	int rvalue;
	void* pkt;
};

bool xdp_end_state_equal(struct xdp_end_state *a, struct xdp_end_state *b, size_t packet_size) {
	return a->rvalue == b->rvalue && memcmp(a->pkt, b->pkt, packet_size) == 0;
}

struct xdp_end_state get_xdp_end_state(xdp_func f, struct xdp_md* ctx, size_t eth_offset) {
	struct xdp_end_state s;
	s.pkt = (void*)(long)(ctx->data) - eth_offset;
	s.rvalue = f(ctx);
	return s;
}

void functional_verify(xdp_func prog, 
					   xdp_func spec, 
					   struct xdp_md *ctx, 
					   size_t packet_size,
					   size_t eth_offset) {
	struct xdp_md ctx_copy;
    memcpy(&ctx_copy, ctx, sizeof(struct xdp_md));
	void* packet = (void*)(long)(ctx->data) - eth_offset;
	void* packet_copy = malloc(packet_size);
	memcpy(packet_copy, packet, packet_size);
	ctx_copy.data = (long)(packet_copy + eth_offset);
	ctx_copy.data_end = (long)(packet_copy + packet_size);
	struct xdp_end_state prog_end_state = get_xdp_end_state(prog, ctx, eth_offset);
	struct xdp_end_state spec_end_state = get_xdp_end_state(spec, &ctx_copy, eth_offset);
	assert(xdp_end_state_equal(&prog_end_state, &spec_end_state, packet_size));
}