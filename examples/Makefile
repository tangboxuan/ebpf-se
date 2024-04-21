ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
LIBBPF_DIR:=$(ROOT_DIR)/../../libbpf-stubbed/src
COMMON_DIR:=$(ROOT_DIR)/../common
PIX_DIR:= $(ROOT_DIR)/../..
KLEE_PATH:=$(ROOT_DIR)/../../tool/deps/klee
LIBXDP_PATH:=$(ROOT_DIR)/../../tool/deps/libxdp
XDP_PATH:=$(ROOT_DIR)/../../tool/deps/xdp

LLVM_RELEASE=12
LLC=llc-$(LLVM_RELEASE)
CLANG=clang-$(LLVM_RELEASE)
LLVM_STRIP=llvm-strip-$(LLVM_RELEASE)
CC := gcc
UNAME_P := $(shell uname -p)

XDP_C ?= ${XDP_TARGETS:=.c}
XDP_BC = ${XDP_C:.c=.bc}
XDP_OBJ = ${XDP_C:.c=.o}

OBJECT_LIBBPF = $(LIBBPF_DIR)/obj/libbpf.a

# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

LDFLAGS ?= -L$(LIBBPF_DIR)

BPF_CFLAGS ?= -I$(ROOT_DIR)/../headers/ -I /usr/include/$(UNAME_P)-linux-gnu
KLEE_BPF_CFLAGS ?= $(BPF_CFLAGS) -I$(LIBBPF_DIR)/build/usr/include/ 
ACTUAL_BPF_CFLAGS ?= $(BPF_CFLAGS) 
XDP_CFLAGS = -I $(XDP_PATH)

ifeq ($(REPLAY), 1)
	BPF_CFLAGS += -DREPLAY
endif

clean-klee:
	rm -rf $(ROOT_DIR)/klee-*
	rm -f $(ROOT_DIR)/res-tree-*
	rm -f $(ROOT_DIR)/neg-tree*

clean: clean-klee
	@#rm -rf $(LIBBPF_DIR)/build
	@#$(MAKE) -C $(LIBBPF_DIR) clean
	@#$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(XDP_OBJ)
	rm -f *.ll *.bc
	rm -f *~
	rm -f replayer

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

xdp-target: $(XDP_C) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-DKLEE_VERIFICATION\
		$(KLEE_BPF_CFLAGS) \
		-I $(KLEE_INCLUDE) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-Wall \
		-Wno-unused-value \
		-Wno-unused-variable \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-fno-builtin \
		-O0 -emit-llvm -c -g $(XDP_C)
	#$(LLC) -I $(KLEE_INCLUDE) -march=bpf -filetype=obj $(XDP_BC) -o ${XDP_OBJ}

libbpf:
	cd $(LIBBPF_DIR) && bash build.sh

symbex:
	/usr/bin/time -v \
		klee -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 -libc=uclibc --external-calls=all --disable-verify \
		-solver-backend=z3 --exit-on-error -max-memory=750000 -search=dfs $(XDP_BC)

#loader:
#	$(CLANG) $(XDP_CFLAGS) $(COMMON_DIR)/loader.c -o $(COMMON_DIR)/loader -lxdp

verify:
	@if [ $(shell id -u) != 0 ]; then echo Requires sudo; exit 1; fi
	@$(CLANG) \
		-target bpf \
		$(ACTUAL_BPF_CFLAGS) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-fno-builtin \
		-O2 -g -c $(XDP_C) -o $(XDP_OBJ) 
	@echo $(XDP_C) compiled!
	@../verification_tools/xdp-loader load -m skb lo $(XDP_OBJ) -vv 2> verifier_log; \
		if [ $$? = 0 ]; then \
		echo $(XDP_TARGETS) $(XDP_FUNCTION) passed verification; \
		../verification_tools/xdp-loader unload lo --all; \
		else \
		grep -Fxq "legacy map definitions" verifier_log; \
		if [ $$? ]; then \
		echo Legacy BPF map definitions not supported; \
		else \
		echo $(XDP_TARGETS) $(XDP_FUNCTION) failed verification; \
		cat verifier_log | awk '/-- BEGIN /{flag=1; next}/libbpf: -- END /{flag=0} flag' ; \
		fi \
		fi
	@rm verifier_log
	@#$(COMMON_DIR)/loader $(XDP_OBJ) $(XDP_SECTION) $(XDP_FUNCTION)

.PHONY: replayer
replayer:
	$(CLANG) -DKLEE_VERIFICATION -I $(KLEE_INCLUDE) -L $(KLEE_PATH)/build/lib $(XDP_C) -lkleeRuntest -o replayer

viewer:
	g++ -I $(KLEE_INCLUDE) \
		$(COMMON_DIR)/ktest_viewer.c \
		$(KLEE_PATH)/build/lib/Basic/CMakeFiles/kleeBasic.dir/KTest.cpp.o \
		-o $(COMMON_DIR)/ktest_viewer

replay:
	@F=$(shell printf "%06d" $f); \
	$(COMMON_DIR)/ktest_viewer klee-last/test$$F.ktest; \
	KTEST_FILE=klee-last/test$$F.ktest ./replayer ; #echo Return Value: $$?

assert: clean-klee xdp-target symbex