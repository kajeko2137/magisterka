# SPDX-License-Identifier: GPL-2.0
#
# TLS - Tiered Lottery Scheduler, build.

# no $(abspath)/$(realpath): a path containing a space breaks both.
# $(CURDIR) is already absolute.
SCX_DIR		= $(CURDIR)/../scx
SCX_INCLUDE	:= $(SCX_DIR)/scheds/include
SCX_VMLINUX	:= $(SCX_DIR)/scheds/vmlinux

BUILD		?= build
OBJ		:= $(BUILD)/tls.bpf.o
LOADER		:= $(BUILD)/tls

SRC_BPF		:= src/bpf/main.bpf.c
SRC_INC		:= src/include
SRC_LOADER	:= userspace/tls.c

# BTF source used to generate vmlinux.h.
BTF		?= /sys/kernel/btf/vmlinux
KERNELRELEASE	?= $(shell uname -r)

# generated header location; override to reuse an existing one.
GEN_VMLINUX	:= $(BUILD)/vmlinux/vmlinux.h
VMLINUX_H	?= $(GEN_VMLINUX)

# Debian installs clang under /usr/lib/llvm-<N>/bin, not on PATH.
# search those locations too.
CLANG		?= $(shell \
	for c in clang clang-22 clang-21 clang-20 clang-19 clang-18 \
		 /usr/lib/llvm-22/bin/clang /usr/lib/llvm-21/bin/clang \
		 /usr/lib/llvm-20/bin/clang /usr/lib/llvm-19/bin/clang \
		 /usr/lib/llvm-18/bin/clang; do \
		if command -v $$c >/dev/null 2>&1; then command -v $$c; break; fi; \
		if [ -x $$c ]; then echo $$c; break; fi; \
	done)

# ABI check reads struct_ops metadata with the objdump of the same LLVM.
LLVM_BIN	?= $(dir $(CLANG))
LLVM_OBJDUMP	?= $(shell \
	for o in $(LLVM_BIN)llvm-objdump llvm-objdump \
		 /usr/lib/llvm-19/bin/llvm-objdump; do \
		if command -v $$o >/dev/null 2>&1; then command -v $$o; break; fi; \
		if [ -x $$o ]; then echo $$o; break; fi; \
	done)

PYTHON		?= python3
CC		?= cc

# -g for BTF, -mcpu=v4 is what sched_ext assumes, -D__TARGET_ARCH_x86
# selects the x86 register accessors, -mllvm -disable-ldsx and
# -disable-gotox keep the object verifiable on current kernels.
# bpf-compat supplies the gnu/stubs.h shim the scx headers expect.
BPF_CFLAGS	:= -g -O2 -Wall -Wno-compare-distinct-pointer-types \
		   -D__TARGET_ARCH_x86 -mcpu=v4 \
		   -mllvm -disable-ldsx \
		   -I"$(patsubst %/,%,$(dir $(VMLINUX_H)))" \
		   -I"$(SCX_VMLINUX)" \
		   -I"$(SCX_INCLUDE)" \
		   -I"$(SCX_INCLUDE)/bpf-compat" \
		   -I"$(SRC_INC)"

BPF_TARGET	:= -target bpf

# without libbpf-dev, libbpf.so.1 plus /usr/include/bpf is enough.
LOADER_CFLAGS	:= -O2 -g -Wall -Wextra -Wno-unused-parameter

# prefer the -dev symlink, else the versioned soname (needs -l: syntax).
LIBBPF_LIB	:= $(shell \
	for l in /usr/lib/x86_64-linux-gnu/libbpf.so \
		 /usr/lib/x86_64-linux-gnu/libbpf.so.1 \
		 /usr/lib/libbpf.so \
		 /usr/lib/libbpf.so.1; do \
		[ -e $$l ] && { echo $$l; break; }; \
	done)
# -lelf does not resolve against a runtime-only libelf, so probe libelf,
# zlib and zstd; LOADER_LDLIBS can be overridden.

ELF_LIB		:= $(firstword $(wildcard \
		     /usr/lib/x86_64-linux-gnu/libelf.so \
		     /usr/lib/libelf.so \
		     /usr/lib64/libelf.so))
ZLIB_LIB	:= $(firstword $(wildcard \
		     /usr/lib/x86_64-linux-gnu/libz.so \
		     /usr/lib/libz.so \
		     /usr/lib64/libz.so))
ZSTD_LIB	:= $(firstword $(wildcard \
		     /usr/lib/x86_64-linux-gnu/libzstd.so \
		     /usr/lib/libzstd.so \
		     /usr/lib64/libzstd.so))

LOADER_LDLIBS	?= $(if $(LIBBPF_LIB),$(LIBBPF_LIB),-lbpf) \
		   $(if $(ELF_LIB),-lelf) \
		   $(if $(ZLIB_LIB),-lz)

.PHONY: all clean check-env check-abi verify run stop stats help \
	vmlinux loader bpf print-config

all: $(OBJ) $(LOADER)

# generated from the running kernel's BTF; it must match the kernel the
# object is loaded onto. The scx vendored fallback header, used when the
# kernel has no sched_ext, is not ABI-valid here; check-abi reports it.

VMLINUX_REAL	:= $(patsubst %/,%,$(dir $(VMLINUX_H)))
VMLINUX_MIN	:= 60000

vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@mkdir -p "$(VMLINUX_REAL)"
	@set -e; \
	if [ -f "$@" ]; then \
		echo "  KEEP    $@ (already present)"; \
		exit 0; \
	fi; \
	echo "  GEN     $@"; \
	if $(PYTHON) scripts/gen_vmlinux_h.py --btf "$(BTF)" --out "$@.tmp" 2>"$@.err"; then \
		mv "$@.tmp" "$@"; \
		rm -f "$@.err"; \
		printf 'source=generated\nbtf=%s\nkernel=%s\n' \
			"$(BTF)" "$(KERNELRELEASE)" > "$(VMLINUX_REAL)/PROVENANCE"; \
		echo "  BTF     generated from $(BTF), ABI matches this kernel"; \
		exit 0; \
	fi; \
	sed -n '1,40p' "$@.err"; \
	if [ -f "$(SCX_VMLINUX)/vmlinux.h" ]; then \
		echo ""; \
		echo "  FALLBACK using the scx checkout's vendored vmlinux.h"; \
		cp "$(SCX_VMLINUX)/vmlinux.h" "$@"; \
		rm -f "$@.err"; \
		printf 'source=scx-fallback\nheader=%s\nkernel=%s\n' \
			"$(SCX_VMLINUX)/vmlinux.h" "$(KERNELRELEASE)" \
			> "$(VMLINUX_REAL)/PROVENANCE"; \
		echo ""; \
		echo "  ##########################################################"; \
		echo "  # WARNING: this object is NOT ABI-valid for this machine. #"; \
		echo "  ##########################################################"; \
		echo "  # The header came from the scx checkout, not from your"; \
		echo "  # running kernel, because this kernel has no sched_ext."; \
		echo "  # The object will compile and is useful for development,"; \
		echo "  # but it cannot be attached here, and it must be rebuilt"; \
		echo "  # on the sched_ext kernel before you run it there."; \
		echo "  #"; \
		if ! command -v bpftool >/dev/null 2>&1; then \
			echo "  # Note: bpftool is not installed. Generating vmlinux.h\n  # correctly needs it. Install it before building for the target\n  # kernel: sudo apt install bpftool"; \
		fi; \
		exit 0; \
	fi; \
	rm -f "$@.tmp" "$@.err"; \
	echo ""; \
	echo "vmlinux.h generation failed and no fallback was found."; \
	echo "Pass VMLINUX_H=<path-to-vmlinux.h> to use one you already have."; \
	echo "Run 'make check-env' for the full picture."; \
	exit 1

vmlinux: $(VMLINUX_H)

$(OBJ): $(SRC_BPF) $(wildcard src/bpf/*.c) $(wildcard $(SRC_INC)/*.h) $(VMLINUX_H)
	@mkdir -p $(dir $@)
	@echo "  CLANG   $@"
	@$(CLANG) $(BPF_TARGET) $(BPF_CFLAGS) -c $(SRC_BPF) -o $@

bpf: $(OBJ)

$(LOADER): $(SRC_LOADER) $(wildcard userspace/*.h) | $(OBJ)
	@mkdir -p $(dir $@)
	@echo "  CC      $@"
	@$(CC) $(LOADER_CFLAGS) -o $@ $(SRC_LOADER) $(LOADER_LDLIBS)

loader: $(LOADER)

# build and run capability are separate: building needs clang and a
# vmlinux.h, running needs a sched_ext kernel.
check-env:
	@echo "== build environment =="
	@printf '  %-22s %s\n' "clang" "$(if $(CLANG),$(CLANG),MISSING)"
	@$(CLANG) --version 2>/dev/null | head -1 | sed 's/^/                          /' || true
	@printf '  %-22s %s\n' "llvm-objdump" "$(if $(LLVM_OBJDUMP),$(LLVM_OBJDUMP),MISSING (optional))"
	@printf '  %-22s %s\n' "python3" "$$($(PYTHON) --version 2>&1 || echo MISSING)"
	@printf '  %-22s %s\n' "host cc" "$$($(CC) --version 2>&1 | head -1 || echo MISSING)"
	@printf '  %-22s %s\n' "scx headers" "$$( \
		if [ -f "$(SCX_INCLUDE)/scx/common.bpf.h" ]; then echo "$(SCX_INCLUDE)"; \
		else echo "MISSING: pass SCX_DIR=<path-to-scx-checkout>"; fi)"
	@printf '  %-22s %s\n' "libbpf" "$(strip $(LOADER_LDLIBS))"
	@echo
	@echo "== target kernel =="
	@printf '  %-22s %s\n' "uname -r" "$(KERNELRELEASE)"
	@printf '  %-22s %s\n' "BTF" "$$(if [ -f "$(BTF)" ]; then echo "$(BTF)"; else echo MISSING; fi)"
	@printf '  %-22s %s\n' "sched_ext state" "$$(cat /sys/kernel/sched_ext/state 2>/dev/null || echo 'NOT AVAILABLE')"
	@printf '  %-22s %s\n' "CONFIG_SCHED_CLASS_EXT" "$$( \
		if zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_SCHED_CLASS_EXT=y'; then echo y; \
		elif grep -qs '^CONFIG_SCHED_CLASS_EXT=y' /boot/config-$(KERNELRELEASE); then echo y; \
		else echo 'NOT SET - this kernel cannot run sched_ext schedulers'; fi)"
	@echo
	@echo "== generated header =="
	@printf '  %-22s %s\n' "VMLINUX_H" "$(VMLINUX_H)"
	@printf '  %-22s %s\n' "exists" "$$(if [ -f "$(VMLINUX_H)" ]; then echo yes; else echo "will be generated"; fi)"
	@printf '  %-22s %s\n' "header source" "$$( \
		p=$$(dirname "$(VMLINUX_H)")/PROVENANCE; \
		if [ -f "$$p" ] && grep -q '^source=scx-fallback' "$$p"; then \
			echo "scx checkout (NOT ABI-valid here)"; \
		elif [ -f "$$p" ]; then \
			echo "this kernel's BTF (ABI matches)"; \
		elif [ -f "$(VMLINUX_H)" ]; then \
			echo "unknown (header present, no PROVENANCE file)"; \
		else echo "not generated yet"; fi)"

# compares the compiled struct sched_ext_ops layout with the running
# kernel's; a mismatch means the wrong callback runs.
check-abi: $(OBJ)
	@$(PYTHON) scripts/check_abi.py \
		--btf $(BTF) \
		--header $(VMLINUX_H) \
		--object $(OBJ) \
		--objdump "$(LLVM_OBJDUMP)"

# loads the object so the verifier can reject it, without attaching it
# as the active scheduler.
verify: $(OBJ) $(LOADER)
	@$(LOADER) --verify $(OBJ)

# needs root; the loader restores the default scheduler on exit, even on
# Ctrl-C.
run: $(LOADER) $(OBJ)
	@test $$(id -u) -eq 0 || { echo "make run needs root."; exit 1; }
	$(LOADER) $(OBJ)

stop:
	@if [ -w /sys/kernel/sched_ext/root/ops ]; then \
		echo "Detaching the active sched_ext scheduler..."; \
		echo > /sys/kernel/sched_ext/root/ops 2>/dev/null || \
			{ echo "Writing to /sys/kernel/sched_ext/root/ops failed."; \
			  echo "Kill the loader process instead (it detaches on exit)."; exit 1; }; \
	else \
		echo "/sys/kernel/sched_ext is not present."; \
		echo "Either no scheduler is attached, or this kernel has no sched_ext."; \
		echo "If a loader is running, kill it; it restores the default scheduler on exit."; \
	fi

stats: $(LOADER)
	@$(LOADER) --stats $(OBJ)

clean:
	rm -rf $(BUILD)

# $(info) rather than echo: the quoted include paths would end an echo
# string early.
print-config:
	$(info CLANG           = $(CLANG))
	$(info LLVM_OBJDUMP    = $(LLVM_OBJDUMP))
	$(info SCX_DIR         = $(SCX_DIR))
	$(info SCX_INCLUDE     = $(SCX_INCLUDE))
	$(info BTF             = $(BTF))
	$(info KERNELRELEASE   = $(KERNELRELEASE))
	$(info VMLINUX_H       = $(VMLINUX_H))
	$(info OBJ             = $(OBJ))
	$(info LOADER          = $(LOADER))
	$(info LOADER_LDLIBS   = $(LOADER_LDLIBS))
	$(info BPF_CFLAGS      = $(BPF_CFLAGS))
	@:

help:
	@echo "TLS build"
	@echo
	@echo "  make              build build/tls.bpf.o and build/tls"
	@echo "  make check-env    report whether this machine can build and run this"
	@echo "  make check-abi    verify vmlinux.h matches the kernel you will load on"
	@echo "  make verify       load the object to run the BPF verifier, then detach"
	@echo "  make run          attach the scheduler (needs root)"
	@echo "  make stop         detach the active sched_ext scheduler"
	@echo "  make stats        show what the scheduler has been doing"
	@echo "  make clean        remove build outputs"
	@echo "  make print-config show the resolved toolchain and paths"
	@echo
	@echo "Cross-building for another kernel:"
	@echo "  make BTF=/boot/vmlinux-6.13.0 KERNELRELEASE=6.13.0"
	@echo "  make VMLINUX_H=/path/to/vmlinux.h"
	@echo
