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
  #define num_ports 2
  int key[num_ports] = {B_PORT,A_PORT};
	int ifindex_out[num_ports] = {B_PORT,A_PORT};

  for(uint i = 0; i < num_ports; i++){
    if(bpf_map_update_elem(&tx_port, &key[i], &ifindex_out[i], 0) < 0)
      return -1;
  }

  struct flow_ctx_table_key flow_key = {0};
	flow_key.ip_proto = 6;
	flow_key.ip_src = 101;
	flow_key.ip_dst = 102;
	flow_key.l4_src = 103;
	flow_key.l4_dst = 104;

  struct flow_ctx_table_leaf new_flow = {0};
  new_flow.in_port = B_PORT;
  new_flow.out_port = A_PORT;

  bpf_map_update_elem(&flow_ctx_table, &flow_key, &new_flow, 0);
  return 0;
  /* Init done */
}

int dummy_set_up_maps() {
  return 0;
}

int main(int argc, char** argv){
  struct pkt *packet = create_packet(sizeof(struct pkt));
  packet->ether.h_proto = BE_ETH_P_IP;
  packet->ipv4.version = 4;
  packet->ipv4.protocol = 6;
  packet->ipv4.ihl = sizeof(struct iphdr) / 4;
  packet->ipv4.saddr = 101;
  packet->ipv4.daddr = 102;
  packet->tcp.doff = sizeof(struct tcphdr) / 4;
  packet->tcp.source = 103;
  packet->tcp.dest = 104;
  struct xdp_md *ctx = create_ctx(packet, sizeof(struct pkt), 0);
  ctx->data_meta = 0;
  __u32 temp;
  ctx->ingress_ifindex = B_PORT;
  ctx->rx_queue_index = 0;

  REGISTER_MAP(&tx_port);
  REGISTER_MAP(&flow_ctx_table);

  bpf_begin();

  functional_verify(xdp_fw_prog, xdp_fw_spec, ctx, sizeof(struct pkt), 0, set_up_maps);
}
#endif