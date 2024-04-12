#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
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
	void* data     = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr  *ip;
	struct tcphdr *tcp;
	char		  *payload;
	uint64_t nh_off = 0;

	eth = data;
	nh_off = sizeof(*eth);
	if (data  + nh_off  > data_end)
		goto EOP;

	ip = data + nh_off;
	nh_off += sizeof(*ip);
	if (data + nh_off  > data_end)
		goto EOP;

	if(ip->protocol != IPPROTO_TCP){
		return XDP_PASS;
	}

	tcp = data + nh_off;
	nh_off += sizeof(*tcp);
	if (data + nh_off  > data_end)
	 	goto EOP;

	payload = data + nh_off;
	nh_off += 3;
	if (data + nh_off  > data_end)
		goto EOP;

	int key = 0;
	
	int* lookuped_value = bpf_map_lookup_elem(&example_table, &key);
	if (!lookuped_value) return XDP_DROP;
	payload[0] = *lookuped_value;
	BPF_ASSERT(payload[0]==0);

	if (payload[1] == '\0') {
		int value = 1;
		bpf_map_update_elem(&example_table, &key, &value, 0);
		BPF_ASSERT_MAP(&example_table, &key, &value);
	}

	lookuped_value = bpf_map_lookup_elem(&example_table, &key);
	if (!lookuped_value) return XDP_DROP;
	payload[2] = *lookuped_value;
	BPF_ASSERT(payload[2]==0||payload[2]==1);
	return XDP_PASS;

	EOP:
		return XDP_DROP;
}


#ifdef KLEE_VERIFICATION
#include "../verification_tools/common.h"
int set_up_maps() {
  BPF_MAP_INIT(&example_table, "example_table", "example_key", "example_value");
  int key = 0;
  int value = 0;
  if(bpf_map_update_elem(&example_table, &key, &value, 0) < 0)
    return -1;
  return 0;
}

int main() {
	struct pkt *packet = create_packet(sizeof(struct pkt));
	struct xdp_md *ctx = create_ctx(packet, sizeof(struct pkt), 0);
	set_up_maps();
	xdp_main(ctx);
}
#endif