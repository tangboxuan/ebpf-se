#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

#ifdef KLEE_VERIFICATION

int expected_return = -1;

int expected_not_returns_count = 0;
enum xdp_action expected_not_returns[4];

#define MAX_CONSTANTS 10
int constants = 0;
void* constants_pointer[MAX_CONSTANTS];
size_t constants_size[MAX_CONSTANTS];
int constants_buffer_ptr = 0;
char constants_buffer[MAX_CONSTANTS * 8];

#define MAX_LEADS_TO 10
int leads_to = 0;
enum xdp_action leads_to_return_values[MAX_LEADS_TO];
bool leads_to_bools[MAX_LEADS_TO];

#define MAX_IFS 10
int ifs = 0;
enum xdp_action ifs_return_values[MAX_IFS];
bool ifs_bools[MAX_IFS];
void* ifs_targets[MAX_IFS];
void* ifs_expecteds[MAX_IFS];
size_t ifs_sizes[MAX_IFS];

void _set_expected_return(value) {
    expected_return = value;
}

void _set_expected_not_return(value) {
    assert(expected_not_returns_count < 4 && "Maximum of 4 BPF_ASSERT_NOT_RETURN expected");
    expected_not_returns[expected_not_returns_count] = value;
    expected_not_returns_count++;
}

void _add_constant(void* ptr, size_t len) {
    assert(constants < MAX_CONSTANTS && "Increase MAX_CONSTANTS");
    constants_pointer[constants] = ptr;
    constants_size[constants] = len;
    memcpy(constants_buffer + constants_buffer_ptr, ptr, len);
    constants_buffer_ptr += len;
    constants++;
}

void _add_leads_to(bool condition, enum xdp_action return_value) {
    assert(leads_to < MAX_LEADS_TO && "Increase MAX_LEADS_TO");
    leads_to_return_values[leads_to] = return_value;
    leads_to_bools[leads_to] = condition;
    leads_to++;
}

void _add_if(enum xdp_action return_value, void* addr, void *value, size_t size, bool if_bool) {
    assert(ifs < MAX_IFS && "Increase MAX_IFS");
    ifs_return_values[ifs] = return_value;
    ifs_bools[ifs] = if_bool;
    ifs_targets[ifs] = addr;
    ifs_expecteds[ifs] = value;
    ifs_sizes[ifs] = size;
    ifs++;
}

void _run_unrestricted_asserts(enum xdp_action return_value) {
    bool bpf_assert_return = expected_return == -1 || expected_return == return_value;
    assert(bpf_assert_return && "Return value not equal to expected");
    for (int i = 0; i < expected_not_returns_count; i++) {
        bool bpf_assert_not_return = expected_not_returns[i] != return_value;
        assert(bpf_assert_not_return && "Return value equals to non allowed value");
    }
    constants_buffer_ptr = 0;
    for (int i = 0; i < constants; i++) {
        bool unchanged = !memcmp(constants_pointer[i], constants_buffer + constants_buffer_ptr, constants_size[i]);
        assert(unchanged && "Constant value changed");
        constants_buffer_ptr += constants_size[i];
    }
    for (int i = 0; i < leads_to; i++) {
        if (leads_to_bools[i]) assert(return_value == leads_to_return_values[i]);
    }
    for (int i = 0; i < ifs; i++) {
        if (ifs_return_values[i] == return_value) {
            bool bpf_assert_if = !memcmp(ifs_targets[i], ifs_expecteds[i], ifs_sizes[i]);
            if(!ifs_bools[i]) bpf_assert_if = !bpf_assert_if;
            assert(bpf_assert_if);       
        }
        free(ifs_expecteds[i]);
    }
}

#define BPF_ASSERT(msg, x) assert(msg && x)
#define BPF_ASSERT_RETURN(value) _set_expected_return(value)
#define BPF_ASSERT_NOT_RETURN(value) _set_expected_not_return(value)
#define BPF_ASSERT_CONSTANT(addr, len) _add_constant(addr, len)
#define BPF_ASSERT_NOT_TRAVERSED() assert("Traversed a path not to be traversed" && false)
#define BPF_ASSERT_LEADS_TO(condition, return_value) _add_leads_to(condition, return_value)
#define _BPF_ASSERT_IF_THEN(return_value, target, type, value, eq_bool) {\
    type* expected = (type*)malloc(sizeof(type));\
    *expected = value;\
    _add_if(return_value, target, expected, sizeof(type), eq_bool);\
}
#define BPF_ASSERT_IF_THEN_EQ(return_value, target, type, value) _BPF_ASSERT_IF_THEN(return_value, target, type, value, true)
#define BPF_ASSERT_IF_THEN_NEQ(return_value, target, type, value) _BPF_ASSERT_IF_THEN(return_value, target, type, value, false)
#define BPF_RETURN(return_value) {_run_unrestricted_asserts(return_value); return return_value;}
#else
#define BPF_ASSERT(msg, x) {}
#define BPF_ASSERT_RETURN(value) {}
#define BPF_ASSERT_NOT_RETURN(value) {}
#define BPF_ASSERT_NOT_TRAVERSED() {}
#define BPF_ASSERT_CONSTANT(addr, len) {}
#define BPF_LEADS_TO(condition, return_value) {}
#define BPF_ASSERT_IF_THEN_EQ(return_value, target, type, value) {}
#define BPF_RETURN(return_value) (return return_value)
#endif
