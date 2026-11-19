// SPDX-License-Identifier: GPL-2.0
/*
 * TLS - scheduling policy helpers.
 *
 * Included by src/bpf/main.bpf.c after tls_bpf_impl.h and before
 * tls_core.bpf.c so all policy helpers share the single BPF translation
 * unit and can be inlined directly into the sched_ext callbacks.
 */

/*
 * tls_is_sanctuary_task - classify whether a task belongs in Tier -1
 * (TIER_SANCTUARY) for bottom-half interrupt / async I/O servicing.
 */
static __always_inline bool tls_is_sanctuary_task(const struct task_struct *p)
{
	/* Async I/O workers (io_uring) */
	if (p->flags & PF_IO_WORKER)
		return true;

	/* Deferred interrupt / softirq bottom-half kernel threads */
	if ((p->flags & PF_KTHREAD) &&
	    (!__builtin_memcmp(p->comm, "ksoftirqd/", 10) ||
	     !__builtin_memcmp(p->comm, "irq/", 4)))
		return true;

	return false;
}

/*
 * tls_pick_lowest_load_cpu - pick an allowed online CPU with the lowest
 * load_factor, keeping `orig_cpu` if it is allowed and within 10 tickets of
 * the minimum load to preserve cache locality.
 */
static __always_inline s32 tls_pick_lowest_load_cpu(struct task_struct *p,
						    s32 orig_cpu)
{
	const struct cpumask *online = NULL;
	struct tls_cpu_ctx *cand;
	u32 nr_cpus = scx_bpf_nr_cpu_ids();
	u32 start, i, cpu;
	u64 orig_load = ~0ULL;
	u64 best_load = ~0ULL;
	bool orig_allowed = false;
	s32 best_cpu = -1;

	if (nr_cpus == 0)
		return orig_cpu;
	if (nr_cpus > TLS_MAX_CPUS)
		nr_cpus = TLS_MAX_CPUS;

	/* Start scanning at orig_cpu so exact ties keep cache locality
	 * instead of piling tasks onto CPU 0. */
	if (orig_cpu >= 0 && (u32)orig_cpu < nr_cpus)
		start = (u32)orig_cpu;
	else
		start = 0;

	if (bpf_ksym_exists(scx_bpf_get_online_cpumask))
		online = scx_bpf_get_online_cpumask();

	for (i = 0; i < TLS_MAX_CPUS; i++) {
		if (i >= nr_cpus)
			break;

		cpu = start + i;
		if (cpu >= nr_cpus)
			cpu -= nr_cpus;

		if (online && !bpf_cpumask_test_cpu(cpu, online))
			continue;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		cand = tls_cpu_ctx_of((s32)cpu);
		if (!cand)
			continue;

		if ((s32)cpu == orig_cpu) {
			orig_allowed = true;
			orig_load = cand->load_factor;
		}

		if (cand->load_factor < best_load) {
			best_load = cand->load_factor;
			best_cpu = (s32)cpu;
		}
	}

	if (online)
		scx_bpf_put_cpumask(online);

	if (orig_allowed && (orig_load <= best_load || orig_load - best_load <= 10))
		return orig_cpu;

	if (best_cpu >= 0)
		return best_cpu;
	return orig_cpu;
}
