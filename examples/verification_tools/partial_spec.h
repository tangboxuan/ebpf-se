#include <linux/bpf.h>
#include <stdbool.h>
#include "common.h"
#include "assert.h"

enum xdp_action_verify {
    XDP_ANY = XDP_REDIRECT + 1,
    XDP_ABORTED_IGNORE_STATE,
	XDP_DROP_IGNORE_STATE,
	XDP_PASS_IGNORE_STATE,
	XDP_TX_IGNORE_STATE,
	XDP_REDIRECT_IGNORE_STATE,
    XDP_ANY_IGNORE_STATE
};

struct xdp_end_state {
	int rvalue;
	void* pkt;
};

struct xdp_end_state get_xdp_end_state(xdp_func f, struct xdp_md* ctx, size_t eth_offset) {
	struct xdp_end_state s;
	s.pkt = (void*)(long)(ctx->data) - eth_offset;
	s.rvalue = f(ctx);
	return s;
}

void check_return_value(struct xdp_end_state *prog, struct xdp_end_state *spec) {
    bool return_value_equal = prog->rvalue == spec->rvalue || prog->rvalue + XDP_ABORTED_IGNORE_STATE == spec->rvalue;
    assert(return_value_equal);
}

void check_packet(struct xdp_end_state *x, struct xdp_end_state *y, size_t packet_size) {
    bool end_packet_state_equal = memcmp(x->pkt, y->pkt, packet_size) == 0;
    assert(end_packet_state_equal);
}

void functional_verify(xdp_func xdp_main, 
                      xdp_func xdp_spec, 
                      struct xdp_md *ctx,
                      size_t packet_size,
					  size_t eth_offset) {
    // Make a copy of packet
    void* packet = (void*)(long)ctx->data;
    void* packet_copy = malloc(packet_size - eth_offset);
	memcpy(packet_copy, packet, packet_size - eth_offset);

    // Make a copy of ctx
    struct xdp_md ctx_copy;
    memcpy(&ctx_copy, ctx, sizeof(struct xdp_md));
	ctx_copy.data = (long)packet_copy + eth_offset;
	ctx_copy.data_end = (long)packet_copy + packet_size;

    // Run the spec
	struct xdp_end_state spec_end_state = get_xdp_end_state(xdp_spec, &ctx_copy, eth_offset);

    if(spec_end_state.rvalue != XDP_ANY_IGNORE_STATE) {
        // Run the program
        struct xdp_end_state prog_end_state = get_xdp_end_state(xdp_main, ctx, eth_offset);

        if (spec_end_state.rvalue != XDP_ANY && spec_end_state.rvalue != XDP_ANY_IGNORE_STATE)
            check_return_value(&prog_end_state, &spec_end_state);

        if (spec_end_state.rvalue <= XDP_ANY)
            check_packet(&prog_end_state, &spec_end_state, packet_size);
    }
}