/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TLS - BPF maps and globals.
 *
 * Included by src/bpf/main.bpf.c after <scx/common.bpf.h>, so the kernel
 * BPF types (struct task_struct, bpf_spin_lock, ...) are already defined.
 *
 * Nothing in this file implements scheduling policy. It defines the
 * storage the policy lives in.
 *
 * MAP INVENTORY
 * -------------
 *   tls_tunables    .rodata        loader-writable configuration
 *   task_ctx_stor      task storage   per-task state (struct tls_task_ctx)
 *   cpu_ctx_stor       array[256]     per-CPU runqueues and counters
 *   tls_stats       percpu array   cheap counters, no locking needed
 *
 * There is intentionally no global DSQ of our own: every task is parked on
 * its owning CPU's built-in local DSQ, and the runqueues above are the
 * scheduler's own bookkeeping. See tls_stubs.bpf.c:dispatch() for the
 * reasoning, and change it if the policy needs a shared queue.
 */
#ifndef __TLS_CORE_BPF_H
#define __TLS_CORE_BPF_H

#include "tls_intf.h"

/* ------------------------------------------------------------------ */
/* Configuration                                                        */
/* ------------------------------------------------------------------ */
/*
 * The loader writes this region before attaching. Until it does, every
 * field is zero and the BPF side falls back to compile-time defaults, so a
 * hand-loaded object (bpftool, a test harness) still runs.
 */
const volatile struct tls_tunables tls_tunables SEC(".rodata");

/* Convenience accessors with the 0-means-default rule applied. */
static __always_inline u64 tls_slice_ns(void)
{
	return tls_tunables.slice_ns ?: TLS_SLICE_NS;
}

static __always_inline u64 tls_rotate_ns(void)
{
	return tls_tunables.rotate_ns ?: TLS_ROTATE_NS;
}

static __always_inline u64 tls_balance_ns(void)
{
	return tls_tunables.balance_ns ?: TLS_BALANCE_NS;
}

static __always_inline u64 tls_sanctuary_budget(void)
{
	return tls_tunables.sanctuary_budget_cycles
		?: TLS_SANCTUARY_BUDGET_CYCLES;
}

/* ------------------------------------------------------------------ */
/* Per-task state                                                       */
/* ------------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct tls_task_ctx);
} task_ctx_stor SEC(".maps");

static __always_inline struct tls_task_ctx *
tls_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

static __always_inline struct tls_task_ctx *
tls_task_ctx_alloc(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/* ------------------------------------------------------------------ */
/* Per-CPU runqueues                                                    */
/* ------------------------------------------------------------------ */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, TLS_MAX_CPUS);
	__type(key, u32);
	__type(value, struct tls_cpu_ctx);
} cpu_ctx_stor SEC(".maps");

/*
 * Look up the runqueue of a CPU. Returns NULL for an out-of-range CPU; no
 * caller may dereference the result without checking.
 */
static __always_inline struct tls_cpu_ctx *
tls_cpu_ctx_of(s32 cpu)
{
	u32 key;

	if (cpu < 0 || cpu >= (s32)TLS_MAX_CPUS)
		return NULL;
	key = (u32)cpu;
	return bpf_map_lookup_elem(&cpu_ctx_stor, &key);
}

/* The runqueue of the CPU the calling BPF program is executing on. */
static __always_inline struct tls_cpu_ctx *tls_this_cpu_ctx(void)
{
	return tls_cpu_ctx_of(bpf_get_smp_processor_id());
}

/* ------------------------------------------------------------------ */
/* Cheap global counters                                                */
/* ------------------------------------------------------------------ */
/*
 * The per-CPU context already carries the policy-relevant counters. This
 * map exists for events that are interesting summed across the machine
 * rather than per CPU, and for anything the userspace side polls for
 * liveliness.
 */
enum tls_stat_id {
	TLS_STAT_DRAWS = 0,
	TLS_STAT_EMPTY_POOL_DRAWS,
	TLS_STAT_PROMOTIONS,
	TLS_STAT_DEMOTIONS,
	TLS_STAT_SANCTUARY_ENTRIES,
	TLS_STAT_SANCTUARY_OVERRUNS,
	TLS_STAT_TIER_OVERFLOWS,
	TLS_STAT_STEALS,
	TLS_STAT_KICKS,
	TLS_STAT_NR,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, TLS_STAT_NR);
	__type(key, u32);
	__type(value, u64);
} tls_stats SEC(".maps");

static __always_inline void tls_stat_inc(enum tls_stat_id id)
{
	u64 *v;
	u32 key = (u32)id;

	v = bpf_map_lookup_elem(&tls_stats, &key);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline void tls_stat_add(enum tls_stat_id id, u64 n)
{
	u64 *v;
	u32 key = (u32)id;

	v = bpf_map_lookup_elem(&tls_stats, &key);
	if (v)
		__sync_fetch_and_add(v, n);
}

#endif /* __TLS_CORE_BPF_H */
