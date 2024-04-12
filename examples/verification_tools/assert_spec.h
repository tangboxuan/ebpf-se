#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>

#ifdef KLEE_VERIFICATION
#define BPF_ASSERT(x) assert(x)
#define BPF_ASSERT_MAP(map, key, value) _bpf_assert_map(map, key, value)

void _bpf_assert_map(const struct bpf_map_def* map, const void* key, const void* value) {
    void* lookup_value = bpf_map_lookup_elem(map, key);
    assert(!memcmp(value, lookup_value, map->value_size));
}
#else
#define BPF_ASSERT(x) void
#define BPF_ASSERT_MAP(map, key, value) void
#endif
