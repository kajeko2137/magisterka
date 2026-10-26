/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TLS - BPF maps and globals.
 *
 * included after <scx/common.bpf.h>: kernel BPF types are defined.
 *
 * no global DSQ of our own: tasks park on their CPU's local DSQ; the
 * runqueues here are only the scheduler's bookkeeping.
 */
#ifndef __TLS_CORE_BPF_H
#define __TLS_CORE_BPF_H

#include "tls_intf.h"

/*
 * loader writes this region before attaching. Until it does, each field
 * is zero and the BPF side uses the compile-time default, so a
 * hand-loaded object (bpftool, test harness) still runs.
 */
const volatile struct tls_tunables tls_tunables SEC(".rodata");

/* accessors below: 0 means fall back to the compile-time default */
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, TLS_MAX_CPUS);
	__type(key, u32);
	__type(value, struct tls_cpu_ctx);
} cpu_ctx_stor SEC(".maps");

/* NULL for an out-of-range CPU; callers must check */
static __always_inline struct tls_cpu_ctx *
tls_cpu_ctx_of(s32 cpu)
{
	u32 key;

	if (cpu < 0 || cpu >= (s32)TLS_MAX_CPUS)
		return NULL;
	key = (u32)cpu;
	return bpf_map_lookup_elem(&cpu_ctx_stor, &key);
}

static __always_inline struct tls_cpu_ctx *tls_this_cpu_ctx(void)
{
	return tls_cpu_ctx_of(bpf_get_smp_processor_id());
}

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

/* per-CPU array: any callback may bump these without a lock, and the
 * loader sums them for events of interest across the whole machine. */
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
