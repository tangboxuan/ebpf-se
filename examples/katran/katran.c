/* Driver for klee verification */
#include "klee/klee.h"
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

#ifndef USES_BPF_GET_SMP_PROC_ID
#define USES_BPF_GET_SMP_PROC_ID
#endif

#ifndef USES_BPF_KTIME_GET_NS
#define USES_BPF_KTIME_GET_NS
#endif

#ifndef USES_BPF_XDP_ADJUST_HEAD
#define USES_BPF_XDP_ADJUST_HEAD
#endif

#include "katran_pkts.h"
#include "../verification_tools/partial_spec.h"
#include "../verification_tools/parsing_helpers_spec.h"
int spec(struct xdp_md* ctx) {
  struct eth_hdr *eth = get_eth(ctx);
  if (eth->eth_proto == BE_ETH_P_IP) {
    struct iphdr *iph = (struct iphdr*)(eth+1);
    if (iph->frag_off & PCKT_FRAGMENTED) {
      return XDP_DROP;
    }
    if (iph->protocol == IPPROTO_ICMP) {
      struct icmphdr *icmp = (struct icmphdr*)(iph+1);
      if (icmp->type == ICMP_ECHO) {
        return XDP_TX_IGNORE_STATE;
      }
    }
  }
  return XDP_ANY_IGNORE_STATE;
}

int main(int argc, char** argv){
  BPF_TIME_INIT();
  BPF_MAP_INIT(&vip_map, "vip_map", "pkt.vip", "vip_metadata");
  BPF_MAP_OF_MAPS_INIT(&lru_mapping, &fallback_cache, "flowtable", "pkt.flow", "backend");
  BPF_MAP_INIT(&fallback_cache, "flowtable", "pkt.flow", "backend");
  BPF_MAP_INIT(&ch_rings, "vip_to_real_map", "", "backend_real_id");
  BPF_MAP_INIT(&reals, "backend_metadata_map", "", "backend_metadata");
  BPF_MAP_INIT(&reals_stats, "backend_stats_map", "", "backend_stats");
  BPF_MAP_INIT(&stats, "vip_stats_map", "", "vip_stats");
  BPF_MAP_INIT(&quic_mapping, "conn_id_to_real_map", "", "backend_real_id");
  BPF_MAP_INIT(&ctl_array, "backend_mac_addrs_map", "", "backend_mac_addrs");

  BPF_MAP_RESET(&reals);
  BPF_MAP_RESET(&reals_stats);
  BPF_MAP_RESET(&stats);
  BPF_MAP_RESET(&quic_mapping);
  BPF_MAP_RESET(&ctl_array);

  #ifdef LPM_SRC_LOOKUP
  BPF_MAP_INIT(lpm_src_v4);
  BPF_MAP_INIT(lpm_src_v6);
  #endif

  struct xdp_md test;
  // get_packet(IPV4,&test);
  // klee_print_expr("done creating packet", 0);
  enum PacketTypes type;

  if(klee_int("pkt.isIPv4")){
    if(klee_int("pkt.is_fragmented"))
      type = FRAGV4;
      // get_packet(FRAGV4,&test);
    else if(klee_int("pkt.isICMP"))
      type = ICMPV4;
      // get_packet(ICMPV4,&test);
    else
      type = IPV4;
      // get_packet(IPV4,&test);
  }
  else if(klee_int("pkt.isIPv6")) {
    // ipv6
    if(klee_int("pkt.is_fragmented"))
      type = FRAGV6;
      // get_packet(FRAGV6,&test);
    else if(klee_int("pkt.isICMP"))
      type = ICMPV6;
      // get_packet(ICMPV6,&test); 
    else
      type = IPV6;
      // get_packet(IPV6,&test);
  }
  else{
    type = NON_IP;
    // get_packet(NON_IP,&test);
  }

  get_packet(type, &test);

  test.data_meta = 0;
  test.ingress_ifindex = 0;
  test.rx_queue_index = 0;

  bpf_begin();

  klee_print_expr("type", type);
  klee_print_expr("packet_size", get_packet_size(type));

  functional_verify(balancer_ingress, spec, &test, get_packet_size(type), get_eth_offset(type));

  // if (balancer_ingress(&test))
  //   return 1;
  // return 0;
}

// 16110 paths
// 11:50.61