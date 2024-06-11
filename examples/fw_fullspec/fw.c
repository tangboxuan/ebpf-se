/* Driver for klee verification */
#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include "assert.h"
#endif
#include <stdlib.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#ifndef USES_BPF_MAP_DELETE_ELEM
#define USES_BPF_MAP_DELETE_ELEM
#endif

#ifndef USES_BPF_REDIRECT_MAP
#define USES_BPF_REDIRECT_MAP
#endif

#include "xdp_fw_kern.h"

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

#ifdef KLEE_VERIFICATION
#include "../verification_tools/partial_spec.h"
int set_up_maps() {

  /* Init from xdp_fw_user.c */

  // struct flow_ctx_table_key flow_key = {0};
	// flow_key.ip_proto = 6;
	// flow_key.ip_src = ipv4_uint8_to_uint32(10,0,0,1);
	// flow_key.ip_dst = ipv4_uint8_to_uint32(10,0,0,2);
	// flow_key.l4_src = 27;
	// flow_key.l4_dst = 28;

  // struct flow_ctx_table_leaf new_flow = {0};
  // new_flow.in_port = B_PORT;
  // new_flow.out_port = A_PORT;

  // bpf_map_update_elem(&flow_ctx_table, &flow_key, &new_flow, BPF_ANY);
  return 0;
  /* Init done */
}


int main(int argc, char** argv){
  struct pkt *packet = create_packet(sizeof(struct pkt));
  packet->ether.h_proto = BE_ETH_P_IP;
  packet->ipv4.version = 4;
  packet->ipv4.ihl = sizeof(struct iphdr) / 4;
  packet->tcp.doff = sizeof(struct tcphdr) / 4;
  struct xdp_md *ctx = create_ctx(packet, sizeof(struct pkt), 0);
  ctx->data_meta = 0;
  __u32 temp;
  klee_make_symbolic(&(temp), sizeof(temp), "VIGOR_DEVICE");
  klee_assume(temp==A_PORT||temp==B_PORT);
  ctx->ingress_ifindex = temp;
  ctx->rx_queue_index = 0;
  BPF_MAP_INIT(&tx_port, "tx_devices_map", "", "tx_device");
  BPF_MAP_INIT(&flow_ctx_table, "flowtable", "pkt.flow", "output_port");
  #define num_ports 2
  int key[num_ports] = {B_PORT,A_PORT};
	int ifindex_out[num_ports] = {B_PORT,A_PORT};

  for(uint i = 0; i < num_ports; i++){
    if(bpf_map_update_elem(&tx_port, &key[i], &ifindex_out[i], 0) < 0)
      return -1;
  }
  struct flow_ctx_table_key flow_key  = {0};
  flow_key.ip_proto = packet->ipv4.protocol;
	flow_key.ip_src = packet->ipv4.saddr;
	flow_key.ip_dst = packet->ipv4.daddr;
	flow_key.l4_src = packet->tcp.source;
	flow_key.l4_dst = packet->tcp.dest;
  klee_assume(flow_key.ip_src <= flow_key.ip_dst);
  klee_assume(flow_key.l4_src <= flow_key.l4_dst);
	// biflow(&flow_key);
  bpf_map_delete_elem(&flow_ctx_table, &flow_key);

  functional_verify(xdp_fw_prog, xdp_fw_spec, ctx, sizeof(struct pkt), 0);
}
#endif