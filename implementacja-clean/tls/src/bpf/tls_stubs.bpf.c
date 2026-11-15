// SPDX-License-Identifier: GPL-2.0
/*
 * TLS - kernel-facing function stubs.
 *
 * Copyright (c) 2026 <your name>
 *
 * Lifecycle, enqueue/dispatch, tick and dump callbacks for the TLS
 * sched_ext scheduler. Policy bodies are TODO.
 */

/* prelude: reporting and arithmetic helpers */

/* TLS_ERR aborts the scheduler (SCX_EXIT_ERROR_BPF); use it only for
 * invariant violations. TLS_WARN prints and continues. Both are
 * rate-limited by the kernel.
 */
#define TLS_ERR(fmt, args...)	scx_bpf_error(fmt, ##args)
#define TLS_WARN(fmt, args...)	bpf_printk("tls: " fmt, ##args)

/* (rnd * total_tickets) >> 32 is exact while total_tickets stays far
 * below 2^32 (about 2^21 here), and avoids the division a modulo needs.
 */
static __always_inline u64 tls_scale_to_pool(u32 rnd, u64 total_tickets)
{
	return ((u64)rnd * total_tickets) >> 32;
}

/* scheduler lifecycle */

s32 BPF_STRUCT_OPS(tls_init)
{
	struct tls_cpu_ctx *cc;
	u32 nr_cpus = scx_bpf_nr_cpu_ids();
	u32 cpu;
	u64 now = bpf_ktime_get_ns();

	if (nr_cpus > TLS_MAX_CPUS) {
		TLS_ERR("tls: %u cpus exceeds TLS_MAX_CPUS (%u); "
			   "raise it in tls_intf.h and rebuild",
			   nr_cpus, (u32)TLS_MAX_CPUS);
		return -22;	/* -EINVAL */
	}

	/*
	 * Bring up every slot, not just the online ones: a CPU onlined
	 * later would find an uninitialised context. TLS_MAX_CPUS is a
	 * compile-time bound, as the verifier needs.
	 */
	for (cpu = 0; cpu < TLS_MAX_CPUS; cpu++) {
		cc = tls_cpu_ctx_of((s32)cpu);
		if (!cc)
			continue;

		cc->cpu = (s32)cpu;
		cc->prng_state = 0;	/* TODO: seed */
		cc->total_tickets = 0;
		cc->load_factor = 0;
		cc->anchor_slot = -1;
		cc->last_rotate_ns = now;
		cc->last_balance_ns = now;
		cc->last_slice_start_ns = 0;
		cc->rotation_epoch = 0;

		/* without this the ticket pool stays empty */
		tls_weight_table_init(cc);
	}

	/* no rdrand/rdseed in BPF; seed from bpf_get_prandom_u32() */

	return 0;
}

void BPF_STRUCT_OPS(tls_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(tls_uei, ei);
}

void BPF_STRUCT_OPS(tls_cpu_online, s32 cpu)
{
	struct tls_cpu_ctx *cc = tls_cpu_ctx_of(cpu);

	if (!cc)
		return;

	cc->cpu = cpu;
	/*
	 * A CPU onlined after attach may have missed the weight table
	 * init in tls_init(); redoing it is cheap and idempotent.
	 */
	if (cc->weights[tls_tier_slot(TIER_HIGH)] == 0 &&
	    cc->weights[tls_tier_slot(TIER_MEDIUM)] == 0 &&
	    cc->weights[tls_tier_slot(TIER_LOW)] == 0 &&
	    cc->weights[tls_tier_slot(TIER_BACKGROUND)] == 0)
		tls_weight_table_init(cc);
}

void BPF_STRUCT_OPS(tls_cpu_offline, s32 cpu)
{
	struct tls_cpu_ctx *cc = tls_cpu_ctx_of(cpu);
	struct tls_task_ctx *tc;
	struct task_struct *p;
	s32 tier;
	u32 i;

	if (!cc)
		return;

	for (tier = TIER_MIN; tier <= TIER_MAX; tier++) {
		u32 slot = tls_tier_slot(tier);

		/*
		 * From the tail: swap-and-pop keeps indices valid; the
		 * element moved into the hole was already visited.
		 */
		for (i = cc->tiers[slot].nr; i > 0; i--) {
			p = cc->tiers[slot].tasks[i - 1];
			if (!p)
				continue;

			tc = tls_task_ctx(p);
			if (tc) {
				tc->linked = false;
				tc->slot = -1;
				tc->cpu = -1;
			}
			cc->tiers[slot].tasks[i - 1] = NULL;
			cc->tiers[slot].nr = i - 1;
		}
	}

	tls_recount_tickets(cc);
	tls_update_load_factor(cc);
}

/* per-task lifecycle */

s32 BPF_STRUCT_OPS(tls_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct tls_task_ctx *tc;

	tc = tls_task_ctx_alloc(p);
	if (!tc) {
		TLS_WARN("init_task: no task storage for %d", p->pid);
		return -12;	/* -ENOMEM */
	}

	/*
	 * Zero the whole context, so a field added later cannot pick up
	 * a stale storage slot.
	 */
	__builtin_memset(tc, 0, sizeof(*tc));

	tc->tier = TIER_ANCHOR;		/* new tasks land here */
	tc->slot = -1;
	tc->cpu = -1;
	tc->linked = false;
	tc->slice_start_ns = 0;
	tc->sanctuary_enter_tsc = 0;

	/*
	 * Per-task entropy mixed into the draw, so two tasks in the
	 * same tier at the same nanosecond do not correlate.
	 */
	tc->prng_state = ((u64)bpf_get_prandom_u32() << 32) |
			 bpf_get_prandom_u32();
	if (tc->prng_state == 0)
		tc->prng_state = 0x9e3779b97f4a7c15ULL;

	(void)args;
	return 0;
}

void BPF_STRUCT_OPS(tls_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	tls_unlink(p);
	(void)args;
}

void BPF_STRUCT_OPS(tls_enable, struct task_struct *p)
{
	struct tls_task_ctx *tc;
	struct tls_cpu_ctx *cc;
	s32 cpu;

	tc = tls_task_ctx_alloc(p);
	if (!tc) {
		TLS_WARN("enable: no task storage for %d", p->pid);
		return;
	}

	if (!tls_tier_valid(tc->tier))
		tc->tier = TIER_ANCHOR;

	/*
	 * enable() also runs for a running task, which is legitimately
	 * unlinked and gets enqueued when it next blocks.
	 */
	if (tc->linked)
		return;

	cpu = (s32)bpf_get_smp_processor_id();
	cc = tls_cpu_ctx_of(cpu);
	if (!cc)
		return;

	/* not retried: enqueue() makes the same call */
	(void)tls_tier_push(cc, tc->tier, p);
}

void BPF_STRUCT_OPS(tls_disable, struct task_struct *p)
{
	tls_unlink(p);
}

/* enqueue: the one callback that must never drop a task */

void BPF_STRUCT_OPS(tls_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct tls_cpu_ctx *cc;
	struct tls_task_ctx *tc;
	struct tls_tier *t;
	s32 cpu, tier;
	u64 slice;

	tc = tls_task_ctx_alloc(p);
	if (!tc) {
		/* no storage: the task still has to run */
		TLS_WARN("enqueue: no storage for %d, bypassing", p->pid);
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, 0, enq_flags);
		return;
	}

	cpu = scx_bpf_task_cpu(p);
	if (cpu < 0)
		cpu = (s32)bpf_get_smp_processor_id();

	cc = tls_cpu_ctx_of(cpu);
	if (!cc) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, 0, enq_flags);
		return;
	}

	/*
	 * Already parked: it was woken while queued and keeps its tier.
	 * Re-pushing would put it in two tier arrays.
	 */
	if (tc->linked) {
		slice = tls_slice_ns();
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, enq_flags);
		return;
	}

	/*
	 * Not linked: brand new, or unlinked by a migration.
	 */
	tier = tls_tier_valid(tc->tier) ? tc->tier : TIER_ANCHOR;

	if (tls_tier_push(cc, tier, p)) {
		/*
		 * Tier full: fall back to the anchor, then the DSQ. An
		 * unqueued task is a hang; a short slice beats a
		 * stalled scheduler.
		 */
		if (tier != TIER_ANCHOR && tls_tier_push(cc, TIER_ANCHOR, p) == 0) {
			tier = TIER_ANCHOR;
		} else {
			slice = tls_slice_ns();
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, enq_flags);
			return;
		}
	}

	t = &cc->tiers[tls_tier_slot(tier)];

	/* TODO: the lottery draw. */
	(void)t;
	slice = tls_slice_ns();
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, enq_flags);
}

void BPF_STRUCT_OPS(tls_dequeue, struct task_struct *p, u64 deq_flags)
{
	tls_unlink(p);
	(void)deq_flags;
}

/* dispatch: hand work to the CPU */

void BPF_STRUCT_OPS(tls_dispatch, s32 cpu, struct task_struct *prev)
{
	struct tls_cpu_ctx *cc = tls_cpu_ctx_of(cpu);

	if (!cc)
		return;

	/*
	 * TODO: the draw and the drain loop. Empty is safe while
	 * enqueue() inserts directly on a DSQ.
	 */
	(void)prev;
}

/* the quantum: tick, stopping, quiescent */

void BPF_STRUCT_OPS(tls_tick, struct task_struct *p)
{
	struct tls_task_ctx *tc = tls_task_ctx(p);
	struct tls_cpu_ctx *cc = tls_this_cpu_ctx();
	u64 now;

	if (!cc)
		return;

	now = bpf_ktime_get_ns();

	(void)tc;
	(void)now;

	/* TODO: the 10 ms quantum and the 150 ms rotation. */
}

void BPF_STRUCT_OPS(tls_stopping, struct task_struct *p, bool running)
{
	tls_unlink(p);
	(void)running;
}

void BPF_STRUCT_OPS(tls_quiescent, struct task_struct *p, u64 flags)
{
	struct tls_cpu_ctx *cc = tls_this_cpu_ctx();

	if (!cc)
		return;

	cc->last_rotate_ns = bpf_ktime_get_ns();
	(void)p;
	(void)flags;
}

/* CPU selection and passive placement */

s32 BPF_STRUCT_OPS(tls_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (cpu < 0)
		cpu = prev_cpu;

	/* idle CPU found: kick it so the wakeup lands there */
	if (is_idle)
		scx_bpf_kick_cpu(cpu, 0);

	/* TODO: lowest-load-factor placement. */
	return cpu;
}

/* running and runnable accounting */

/*
 * bpf_ktime_get_ns() is the substitute for the RDTSC cycle budget: BPF
 * cannot execute rdtsc and has no inline asm. Unit is nanoseconds.
 */
void BPF_STRUCT_OPS(tls_running, struct task_struct *p)
{
	struct tls_task_ctx *tc = tls_task_ctx(p);
	u64 now = bpf_ktime_get_ns();

	if (!tc)
		return;

	tc->slice_start_ns = now;

	/* TODO: enforce the sanctuary budget in tls_tick() */
	tc->sanctuary_enter_tsc = now;
	(void)now;
}

void BPF_STRUCT_OPS(tls_runnable, struct task_struct *p, u64 enq_flags)
{
	(void)p;
	(void)enq_flags;
}

/* load balancing */

void BPF_STRUCT_OPS(tls_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	struct tls_cpu_ctx *cc = tls_cpu_ctx_of(cpu);

	if (cc)
		cc->kicks++;	/* reusing the counter as an acquire count */
	(void)args;
}

/*
 * cc->lock_opaque is a u64 placeholder; actually taking the lock needs
 * the field declared as struct bpf_spin_lock in struct tls_cpu_ctx.
 */
void BPF_STRUCT_OPS(tls_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	struct tls_cpu_ctx *cc = tls_cpu_ctx_of(cpu);

	if (cc)
		cc->last_balance_ns = bpf_ktime_get_ns();
	(void)args;
}

/* optional: hints for the kernel's own bookkeeping */

bool BPF_STRUCT_OPS(tls_yield, struct task_struct *p, struct task_struct *from)
{
	(void)p;
	(void)from;
	return false;
}

void BPF_STRUCT_OPS(tls_set_weight, struct task_struct *p, u32 weight)
{
	(void)p;
	(void)weight;
}

void BPF_STRUCT_OPS(tls_set_cpumask, struct task_struct *p, const struct cpumask *cpumask)
{
	(void)p;
	(void)cpumask;
}

void BPF_STRUCT_OPS(tls_update_idle, s32 cpu, bool idle)
{
	(void)cpu;
	(void)idle;
}

/* optional: diagnostics */

/*
 * BPF_STRUCT_OPS() wraps each callback in a BPF_PROG() taking a ctx
 * pointer, so the callbacks cannot call one another; the work lives in
 * static helpers.
 */
static void tls_dump_one_cpu(s32 cpu)
{
	struct tls_cpu_ctx *cc;

	cc = tls_cpu_ctx_of(cpu);
	if (!cc)
		return;

	/* Split for the same 12-argument reason as tls_dump(). */
	scx_bpf_dump("cpu %3d: sanctuary=%u anchor=%u high=%u medium=%u "
		     "low=%u background=%u\n",
		     cpu,
		     cc->tiers[tls_tier_slot(TIER_SANCTUARY)].nr,
		     cc->tiers[tls_tier_slot(TIER_ANCHOR)].nr,
		     cc->tiers[tls_tier_slot(TIER_HIGH)].nr,
		     cc->tiers[tls_tier_slot(TIER_MEDIUM)].nr,
		     cc->tiers[tls_tier_slot(TIER_LOW)].nr,
		     cc->tiers[tls_tier_slot(TIER_BACKGROUND)].nr);

	scx_bpf_dump("cpu %3d: tickets=%llu load=%llu epoch=%u "
		     "selections=%llu steals=%llu rotations=%llu\n",
		     cpu,
		     (unsigned long long)cc->total_tickets,
		     (unsigned long long)cc->load_factor,
		     cc->rotation_epoch,
		     (unsigned long long)cc->selections,
		     (unsigned long long)cc->steals_completed,
		     (unsigned long long)cc->rotations);
}

static void tls_dump_cpu_header(void)
{
	scx_bpf_dump("cpu  sanctuary anchor high medium low "
		     "background  tickets  load  epoch  "
		     "selections  steals  rotations\n");
}

void BPF_STRUCT_OPS(tls_dump_cpu, struct scx_dump_ctx *dctx, s32 cpu, bool header)
{
	u32 i;

	(void)dctx;

	if (header)
		tls_dump_cpu_header();

	if (cpu < 0) {
		for (i = 0; i < TLS_MAX_CPUS; i++)
			tls_dump_one_cpu((s32)i);
		return;
	}

	tls_dump_one_cpu(cpu);
}

void BPF_STRUCT_OPS(tls_dump_task, struct scx_dump_ctx *dctx, struct task_struct *p)
{
	struct tls_task_ctx *tc;

	if (!p)
		return;

	tc = tls_task_ctx(p);
	if (!tc) {
		scx_bpf_dump("task %d: no tls storage\n", p->pid);
		return;
	}

	scx_bpf_dump("task %d: tier=%d slot=%d cpu=%d linked=%d "
			  "losses=%u sel=%u dem=%u prom=%u rot=%u steals=%u "
			  "trans=%u\n",
			  p->pid, tc->tier, tc->slot, tc->cpu, (int)tc->linked,
			  tc->losses, tc->times_selected, tc->demotions,
			  tc->promotions, tc->rotations_seen, tc->steals_won,
			  tc->transitions);
	(void)dctx;
}

void BPF_STRUCT_OPS(tls_dump, struct scx_dump_ctx *dctx)
{
	u32 i;

	/*
	 * scx_bpf_dump() is capped at 12 arguments; a larger call is a
	 * compile error, not a truncation.
	 */
	scx_bpf_dump("tls tunables: slice=%llu ns rotate=%llu ns "
		     "balance=%llu ns\n",
		     (unsigned long long)tls_slice_ns(),
		     (unsigned long long)tls_rotate_ns(),
		     (unsigned long long)tls_balance_ns());

	scx_bpf_dump("tls tunables: sanctuary_budget=%llu ns "
		     "promote_after_losses=%u verbose=%u\n",
		     (unsigned long long)tls_sanctuary_budget(),
		     tls_tunables.promote_after_losses,
		     tls_tunables.verbose);

	scx_bpf_dump("tls tunables: balance_ratio=%u/%u "
		     "rotate_reverse=%d soft_overflow=%d\n",
		     tls_tunables.balance_ratio_num,
		     tls_tunables.balance_ratio_den,
		     (int)tls_tunables.rotate_reverse,
		     (int)tls_tunables.soft_overflow);

	tls_dump_cpu_header();
	for (i = 0; i < TLS_MAX_CPUS; i++)
		tls_dump_one_cpu((s32)i);
	(void)dctx;
}
