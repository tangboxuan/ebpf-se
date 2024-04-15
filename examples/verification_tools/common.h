#include <stdlib.h>
#include <linux/bpf.h>
#include <klee/klee.h>

uint32_t ipv4_uint8_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint32_t result = 0;
    result += a;
    result <<= 8;
    result += b;
    result <<= 8;
    result += c;
    result <<= 8;
    result += d;
    return result;
}

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