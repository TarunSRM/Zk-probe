# Phase 1 Makefile
# Builds eBPF programs and userspace collector

CLANG := clang
LLC := llc
BPFTOOL := bpftool
CC := gcc

# Directories
EBPF_DIR := ebpf
BUILD_DIR := build/bpf
USERSPACE_DIR := userspace/collector
INCLUDE_DIR := include

# Flags
CLANG_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I$(INCLUDE_DIR)
USERSPACE_CFLAGS := -Wall -O2
USERSPACE_LIBS := -lbpf -lssl -lcrypto

# eBPF source files
EBPF_SOURCES := $(wildcard $(EBPF_DIR)/tracepoints/*.bpf.c) \
                $(wildcard $(EBPF_DIR)/xdp/*.bpf.c)

# eBPF object files
EBPF_OBJECTS := $(patsubst $(EBPF_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(EBPF_SOURCES))

# Userspace binary
USERSPACE_BIN := $(USERSPACE_DIR)/phase1_loader

.PHONY: all clean vmlinux

all: vmlinux $(EBPF_OBJECTS) $(USERSPACE_BIN)

# Generate vmlinux.h if not present
vmlinux:
	@if [ ! -f $(INCLUDE_DIR)/vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		mkdir -p $(INCLUDE_DIR); \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(INCLUDE_DIR)/vmlinux.h; \
	fi

# Build eBPF programs
$(BUILD_DIR)/%.bpf.o: $(EBPF_DIR)/%.bpf.c
	@mkdir -p $(dir $@)
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

# Build userspace collector
$(USERSPACE_BIN): $(USERSPACE_DIR)/phase1_loader.c
	$(CC) $(USERSPACE_CFLAGS) -o $@ $< $(USERSPACE_LIBS)

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(USERSPACE_BIN)

.PHONY: help
help:
	@echo "Phase 1 Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build everything (default)"
	@echo "  vmlinux   - Generate vmlinux.h"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this message"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang (LLVM)"
	@echo "  - bpftool"
	@echo "  - libbpf-dev"
	@echo "  - libssl-dev"