#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>


#ifdef KLEE_VERIFICATION
bool bpf_map_contains(void* map, const void* key) {
    void* lookup_value = bpf_map_lookup_elem(map, key);
    return lookup_value != NULL;
}
#define BPF_ASSERT(msg, x) assert(msg && x)
#define BPF_ASSERT_MAP_CONTAINS(map, key) assert(bpf_map_contains(map, key))
#define BPF_ASSERT_MAP_NOT_CONTAINS(map, key) assert(!bpf_map_contains(map, key))
#else
#define BPF_ASSERT(msg, x) {}
#define BPF_ASSERT_MAP_CONTAINS(map, key) {}
#define BPF_ASSERT_MAP_NOT_CONTAINS(map, key) {}
#endif
