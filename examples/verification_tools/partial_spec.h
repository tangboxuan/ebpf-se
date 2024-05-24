#include <linux/bpf.h>
#include <stdbool.h>
#include "common.h"
#include "assert.h"

#ifndef PARTIAL_SPEC
#define PARTIAL_SPEC

#define BPF_RETURN(x) return x

typedef int (*maps_func)(void);

void functional_verify(xdp_func xdp_main, 
                      xdp_func xdp_spec, 
                      struct xdp_md *ctx,
                      size_t packet_size,
					  size_t eth_offset,
                      maps_func set_up_maps) {
    // Make a copy of packet
    void* packet = (void*)(long)ctx->data - eth_offset;
    void* packet_copy = malloc(packet_size);
    assert(packet_copy != NULL);
	memcpy(packet_copy, packet, packet_size);

    // Make a copy of ctx
    struct xdp_md ctx_copy;
    memcpy(&ctx_copy, ctx, sizeof(struct xdp_md));
	ctx_copy.data = (long)packet_copy + eth_offset;
	ctx_copy.data_end = (long)packet_copy + packet_size;

    set_up_maps();
	struct xdp_end_state spec_end_state = get_xdp_end_state(xdp_spec, &ctx_copy);

    if(spec_end_state.rvalue != XDP_ANY_IGNORE_STATE) {
        // Run the program
        for (size_t no = 0; no < bpf_map_ctr; no++) {
            BPF_MAP_RESET(bpf_map_stubs[no]);
        }
        set_up_maps();
        struct xdp_end_state prog_end_state = get_xdp_end_state(xdp_main, ctx);

        if (spec_end_state.rvalue != XDP_ANY)
            assert(return_value_equal(&prog_end_state, &spec_end_state));

        if (spec_end_state.rvalue <= XDP_ANY)
            assert(end_state_equal(&prog_end_state, &spec_end_state, eth_offset));
    }
}

#endif