#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#include <bpf/bpf_helpers.h>
#include "../verification_tools/assert_spec.h"

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, int);
// 	__type(value, int);
// 	__uint(max_entries, 4);
// } example_table SEC(".maps");

struct bpf_map_def SEC("maps") example_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 8,
};

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	BPF_ASSERT_NOT_RETURN(XDP_ABORTED);
	BPF_ASSERT_NOT_RETURN(XDP_REDIRECT);
	// BPF_ASSERT_NOT_RETURN(XDP_DROP);

	void* data     = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr  *ip;
	struct tcphdr *tcp;
	char		  *payload;
	uint64_t nh_off = 0;
	int x = 100;
	BPF_ASSERT_CONSTANT(&x, 4);

	eth = data;
	nh_off = sizeof(*eth);
	if (data  + nh_off  > data_end)
		goto EOP;

	ip = data + nh_off;
	nh_off += sizeof(*ip);
	if (data + nh_off  > data_end)
		goto EOP;

	if(ip->protocol != IPPROTO_TCP){
		return (XDP_PASS);
	}

	tcp = data + nh_off;
	nh_off += sizeof(*tcp);
	if (data + nh_off  > data_end) {
	 	goto EOP;
	}

	payload = data + nh_off;
	BPF_ASSERT_IF_THEN_EQ(payload[0] != '\0', &payload[1], char, '\0');
	BPF_ASSERT_IF_THEN_NEQ(payload[0] != '\0', &payload[0], char, '\0');
	BPF_ASSERT_IF_THEN_EQ(payload[0] == '\0', &payload[2], char, '\1');

	BPF_ASSERT_LEADS_TO_ACTION(payload[0] != '\0', XDP_PASS);
	BPF_ASSERT_LEADS_TO_ACTION(payload[0] == '\0', XDP_TX);

	BPF_ASSERT_IF_ACTION_THEN_EQ(XDP_PASS, &payload[1], char, '\0');
	BPF_ASSERT_IF_ACTION_THEN_NEQ(XDP_PASS, &payload[0], char, '\0');
	BPF_ASSERT_IF_ACTION_THEN_EQ(XDP_TX, &payload[2], char, '\1');

	nh_off += 3;
	if (data + nh_off  > data_end)
		goto EOP;

	char value = '\0';
	
	if (payload[0] == value) {
		BPF_ASSERT_RETURN(XDP_TX);

		value = '\1';
		if (payload[2] != value)
			payload[2] = value;
		
		BPF_ASSERT("", payload[2]=='\1');
		return (XDP_TX);
	}
	BPF_ASSERT("", payload[0]!=0);
	BPF_ASSERT_RETURN(XDP_PASS);
	BPF_ASSERT_CONSTANT(&value, sizeof(value));

	payload[1] = value;
	return (XDP_PASS);

	EOP:
		return (XDP_DROP);
}


#ifdef KLEE_VERIFICATION
// int set_up_maps() {
//   return 0;
// }

int main() {
	struct pkt *packet = create_packet(sizeof(struct pkt));
	struct xdp_md *ctx = create_ctx(packet, sizeof(struct pkt), 0);
	// set_up_maps();
	BPF_RETURN(xdp_main(ctx));
}
#endif