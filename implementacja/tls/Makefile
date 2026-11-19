# SPDX-License-Identifier: GPL-2.0
#
# TLS - Tiered Lottery Scheduler, build.
#
# ---------------------------------------------------------------------------
# QUICK START
# ---------------------------------------------------------------------------
#   make                 build build/tls.bpf.o and build/tls
#   make check-env       report whether this machine can build and run this
#   make check-abi       verify vmlinux.h matches the kernel you will load on
#   make verify          load the object to run the BPF verifier, then detach
#   make run             attach the scheduler (needs root)
#   make stop            detach the scheduler
#   make stats           show what the scheduler has been doing
#   make clean           remove build outputs
#
# ---------------------------------------------------------------------------
# WHY THE FIRST BUILD MAY NEED TWO THINGS FROM YOU
# ---------------------------------------------------------------------------
#  1. clang.  Debian installs it outside PATH under /usr/lib/llvm-<N>/bin.
#     This Makefile finds it automatically; see the CLANG discovery block.
#     If clang is genuinely absent: sudo apt install clang llvm bpftool
#     (or libbpf-dev, which pulls in bpftool).
#
#  2. vmlinux.h.  The BPF program is compiled against a type description of
#     the kernel it will load onto. The scx repo ships one generated from a
#     much newer kernel, and loading a struct_ops object compiled against the
#     wrong layout is how you get a scheduler that runs the wrong function
#     pointers. `make` therefore generates vmlinux.h from *your* kernel's BTF
#     into build/vmlinux/ unless you point it somewhere else. See
#     VMLINUX_H below and scripts/gen_vmlinux_h.py.
#
# ---------------------------------------------------------------------------
# POINTING AT A DIFFERENT KERNEL
# ---------------------------------------------------------------------------
# To build against a kernel that is not the running one - for example a
# hand-built sched_ext kernel installed in /boot - give both the BTF source
# and trust the ABI check:
#
#   make BTF=/boot/vmlinux-6.13.0 KERNELRELEASE=6.13.0
#
# or, if you already have a vmlinux.h you trust:
#
#   make VMLINUX_H=/path/to/vmlinux.h SKIP_ABI_CHECK=1
#
# Never leave SKIP_ABI_CHECK=1 in a habitual build. See docs in
# scripts/check_abi.py for what it actually verifies.

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
# This directory sits next to the sched-ext checkout, which supplies the
# shared scx BPF headers and, optionally, a pre-generated vmlinux.h.
# NOTE: no $(abspath ...) or $(realpath ...) here. Both mishandle a
# path containing a space, and abspath silently splits it into two
# nonexistent paths. $(CURDIR) is already absolute, so concatenation
# is both simpler and correct.
SCX_DIR		= $(CURDIR)/../scx
SCX_INCLUDE	:= $(SCX_DIR)/scheds/include
SCX_VMLINUX	:= $(SCX_DIR)/scheds/vmlinux

BUILD		?= build
OBJ		:= $(BUILD)/tls.bpf.o
LOADER		:= $(BUILD)/tls

SRC_BPF		:= src/bpf/main.bpf.c
SRC_INC		:= src/include
SRC_LOADER	:= userspace/tls.c

# ---------------------------------------------------------------------------
# Target kernel
# ---------------------------------------------------------------------------
# BTF is the type information used to generate vmlinux.h. On a running kernel
# it is /sys/kernel/btf/vmlinux.
BTF		?= /sys/kernel/btf/vmlinux
KERNELRELEASE	?= $(shell uname -r)

# Where the generated vmlinux.h goes. Override VMLINUX_H to use your own.
GEN_VMLINUX	:= $(BUILD)/vmlinux/vmlinux.h
VMLINUX_H	?= $(GEN_VMLINUX)

# ---------------------------------------------------------------------------
# Toolchain discovery
# ---------------------------------------------------------------------------
# Debian and Ubuntu install clang as /usr/lib/llvm-<N>/bin/clang without
# putting it on PATH. Search the usual locations before giving up, and report
# what was found so that a build failure is never a mystery about which clang
# ran.
CLANG		?= $(shell \
	for c in clang clang-22 clang-21 clang-20 clang-19 clang-18 \
		 /usr/lib/llvm-22/bin/clang /usr/lib/llvm-21/bin/clang \
		 /usr/lib/llvm-20/bin/clang /usr/lib/llvm-19/bin/clang \
		 /usr/lib/llvm-18/bin/clang; do \
		if command -v $$c >/dev/null 2>&1; then command -v $$c; break; fi; \
		if [ -x $$c ]; then echo $$c; break; fi; \
	done)

# llvm-objdump is used by the ABI check to read the compiled struct_ops
# metadata; prefer the one that belongs to CLANG so the LLVM versions agree.
LLVM_BIN	?= $(dir $(CLANG))
LLVM_OBJDUMP	?= $(shell \
	for o in $(LLVM_BIN)llvm-objdump llvm-objdump \
		 /usr/lib/llvm-19/bin/llvm-objdump; do \
		if command -v $$o >/dev/null 2>&1; then command -v $$o; break; fi; \
		if [ -x $$o ]; then echo $$o; break; fi; \
	done)

PYTHON		?= python3
CC		?= cc

# ---------------------------------------------------------------------------
# BPF compile flags
# ---------------------------------------------------------------------------
# These mirror what the scx project's own build (rust/scx_cargo) uses, so a
# scheduler built here is compiled the same way as the upstream ones. The
# notable ones:
#
#   -g                     required: the verifier and the ABI check read BTF
#   -mcpu=v4               the instruction set sched_ext assumes
#   -D__TARGET_ARCH_x86    selects the x86 register accessors in bpf_tracing.h
#   -disable-ldsx          sign-extending loads from arena memory need a JIT
#                          that predates most sched_ext kernels
#   -disable-gotox         clang >= 22 lowers large switches to jump tables,
#                          which older kernels cannot verify
#
# bpf-compat is on the include path because the scx headers expect a
# gnu/stubs.h shim when compiling for the BPF target.
BPF_CFLAGS	:= -g -O2 -Wall -Wno-compare-distinct-pointer-types \
		   -D__TARGET_ARCH_x86 -mcpu=v4 \
		   -mllvm -disable-ldsx \
		   -I"$(patsubst %/,%,$(dir $(VMLINUX_H)))" \
		   -I"$(SCX_VMLINUX)" \
		   -I"$(SCX_INCLUDE)" \
		   -I"$(SCX_INCLUDE)/bpf-compat" \
		   -I"$(SRC_INC)"

BPF_TARGET	:= -target bpf

# The loader needs libbpf. Debian's libbpf-dev is the clean way; without it,
# libbpf.so.1 plus the headers in /usr/include/bpf are enough, and the loader
# links against the versioned soname directly.
LOADER_CFLAGS	:= -O2 -g -Wall -Wextra -Wno-unused-parameter

# libbpf: prefer the -dev package's unversioned symlink, fall back to the
# versioned soname that ships with the runtime package. The versioned form
# needs the linker's -l: syntax, which is why this is a script rather than a
# plain -lbpf.
LIBBPF_LIB	:= $(shell \
	for l in /usr/lib/x86_64-linux-gnu/libbpf.so \
		 /usr/lib/x86_64-linux-gnu/libbpf.so.1 \
		 /usr/lib/libbpf.so \
		 /usr/lib/libbpf.so.1; do \
		[ -e $$l ] && { echo $$l; break; }; \
	done)
# ---------------------------------------------------------------------------
# Linker inputs for the userspace loader
# ---------------------------------------------------------------------------
# libbpf needs libelf and zlib. On a machine with libbpf-dev those arrive as
# -lelf -lz. Where only the runtime library is present (libelf.so.1 without
# the libelf.so development symlink) -lelf does not resolve, but the link
# still succeeds because the dynamic libbpf declares them as dependencies and
# the dynamic linker resolves them at load time. So each one is probed and
# included only when the linker can actually find it, which keeps the build
# working on both a full development install and a bare runtime one.
#
# LOADER_LDLIBS can be overridden on the command line if your layout differs.

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

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------
.PHONY: all clean check-env check-abi verify run stop stats help \
	vmlinux loader bpf print-config

all: $(OBJ) $(LOADER)

# ---------------------------------------------------------------------------
# vmlinux.h
# ---------------------------------------------------------------------------
# The header defines struct sched_ext_ops, so it decides the ABI. It is
# generated rather than committed, because the layout must match the kernel
# that will load the object: the kernel matches the compiled struct_ops
# against its own BTF, and the wrong header produces an object that either
# fails to attach or, worse, attaches and calls the wrong callbacks.
#
# The resolution order is:
#
#   1. VMLINUX_H=<path> on the command line, or a pre-existing
#      build/vmlinux/vmlinux.h. Never overridden. Use this when building for
#      a kernel other than the one you are running.
#   2. Generated from the running kernel's BTF (/sys/kernel/btf/vmlinux).
#      This is the correct default and the only fully trustworthy option.
#   3. The vmlinux.h vendored in the scx checkout, used only if step 2 proves
#      the running kernel has no sched_ext. It lets you develop and compile on
#      a machine that cannot run the scheduler, but the resulting object is
#      NOT ABI-valid for the machine you are on. `make check-abi` says so, and
#      the build prints a warning when this fallback is taken.
#
# Step 3 is why `make` succeeds on a kernel without sched_ext. Do not mistake
# that for the scheduler being runnable there.

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
		echo "  # See README.md, section 'Building for a different kernel'."; \
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

# ---------------------------------------------------------------------------
# BPF object
# ---------------------------------------------------------------------------
$(OBJ): $(SRC_BPF) $(wildcard src/bpf/*.c) $(wildcard $(SRC_INC)/*.h) $(VMLINUX_H)
	@mkdir -p $(dir $@)
	@echo "  CLANG   $@"
	@$(CLANG) $(BPF_TARGET) $(BPF_CFLAGS) -c $(SRC_BPF) -o $@

bpf: $(OBJ)

# ---------------------------------------------------------------------------
# userspace loader
# ---------------------------------------------------------------------------
$(LOADER): $(SRC_LOADER) $(wildcard userspace/*.h) | $(OBJ)
	@mkdir -p $(dir $@)
	@echo "  CC      $@"
	@$(CC) $(LOADER_CFLAGS) -o $@ $(SRC_LOADER) $(LOADER_LDLIBS)

loader: $(LOADER)

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
# check-env answers "can this machine build and, separately, run this?" Those
# are different questions: building needs clang and a vmlinux.h, running needs
# a kernel with sched_ext enabled. Reporting both separately stops the common
# confusion of a successful build being mistaken for a runnable scheduler.
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
			echo "scx checkout (NOT ABI-valid here - see README)"; \
		elif [ -f "$$p" ]; then \
			echo "this kernel's BTF (ABI matches)"; \
		elif [ -f "$(VMLINUX_H)" ]; then \
			echo "unknown (header present, no PROVENANCE file)"; \
		else echo "not generated yet"; fi)"

# check-abi compares the struct sched_ext_ops layout the object was compiled
# against with the layout the running kernel actually exposes. Mismatched
# struct_ops layouts are the single most confusing failure mode in sched_ext:
# the object loads, and then the wrong callback runs.
check-abi: $(OBJ)
	@$(PYTHON) scripts/check_abi.py \
		--btf $(BTF) \
		--header $(VMLINUX_H) \
		--object $(OBJ) \
		--objdump "$(LLVM_OBJDUMP)"

# verify loads the object and its struct_ops map without attaching it as the
# active scheduler, so the BPF verifier gets to reject it and you get a usable
# error message instead of a machine that hangs. This is the check to run after
# every change.
verify: $(OBJ) $(LOADER)
	@$(LOADER) --verify $(OBJ)

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
# Attaching needs root and a sched_ext-capable kernel. The loader restores the
# kernel's default scheduler when it exits, including on Ctrl-C, so `make run`
# is safe to interrupt.
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

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
clean:
	rm -rf $(BUILD)

# Printed with $(info) rather than shell echo: the include paths are quoted,
# because this workspace lives under a directory whose name contains a space,
# and those quotes would otherwise terminate the echo string early.
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
	@echo "Full commentary is in the header of this Makefile."
	@echo "The scheduler contract you implement is in src/bpf/tls_core.bpf.c."
