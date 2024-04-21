#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>

bool bpf_map_contains(const void* map, const void* key) {
    void* lookup_value = bpf_map_lookup_elem(map, key);
    return lookup_value != NULL;
}

#ifdef KLEE_VERIFICATION
#define BPF_ASSERT(msg, x) assert(msg && x)
#define BPF_ASSERT_MAP_VALUE(map, key, value) _bpf_assert_map_value(map, key, value)

void _bpf_assert_map_value(const struct bpf_map_def* map, const void* key, const void* value) {
    void* lookup_value = bpf_map_lookup_elem(map, key);
    assert(memcmp(value, lookup_value, map->value_size) == 0);
}
#else
#define BPF_ASSERT(msg, x) void
#define BPF_ASSERT_MAP_VALUE(map, key, value) void
#endif
