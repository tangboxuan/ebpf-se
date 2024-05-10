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
int f(int x, int y) {
	if (x%2==0) { 
		return 1; // 
	}
	if (y%2==0) {
		return 2; //
	}
	return 0;
} 

int f_spec(int x, int y) {
	if (y==6) {
		return 2; 
	}
	return -1;
}

#ifdef KLEE_VERIFICATION
#include "../verification_tools/partial_spec.h"

int main() {
	int x;
	klee_make_symbolic(&x, sizeof(int), "x");
	int y;
	klee_make_symbolic(&y, sizeof(int), "y");
	int a = f(x,y);
	int b = f_spec(x,y);
	if (b != -1) {
		assert(a==b);
	}
}
#endif