#include <stdlib.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "klee/klee.h"

SEC("xdp")
int xdp_main(int x) {
	if (x == 0) return 0;
	if (x < 0) return -1;
	return 1;
}

int main() {      
	int x;
	klee_make_symbolic(&x, sizeof(int), "x");
	return xdp_main(x);
}
