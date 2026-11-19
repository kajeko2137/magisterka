// SPDX-License-Identifier: GPL-2.0
/*
 * TLS - kernel-facing function stubs.
 *
 * Copyright (c) 2026 <your name>
 *
 * ===========================================================================
 * READ THIS BEFORE WRITING ANY CODE
 * ===========================================================================
 *
 * This file is the complete set of functions you must implement to turn the
 * TLS architecture document into a running sched_ext scheduler. Nothing is
 * implemented for you: every function body below compiles, loads, and keeps
 * the machine running, but makes no scheduling decision.
 *
 * What IS provided, so you do not have to write it:
 *
 *   - the loader (userspace/tls.c): opens, configures and attaches this
 *     object, and decodes the kernel's stop reason when it detaches
 *   - maps and per-CPU / per-task storage (src/include/tls_core.bpf.h)
 *   - O(1) tier array primitives: push, swap-and-pop removal, unlink,
 *     occupancy queries, ticket recount (src/include/tls_bpf_impl.h)
 *   - the struct sched_ext_ops table (src/bpf/main.bpf.c)
 *   - a build that produces a loadable tls.bpf.o (Makefile)
 *
 * What is NOT provided, because it is your thesis:
 *
 *   the algorithm. The lottery draw, the ticket arithmetic, tier
 *   classification, demotion, the starvation rotation, passive load
 *   placement and work stealing are all absent. Each is marked TODO below.
 *
 * ---------------------------------------------------------------------------
 * HOW TO READ A STUB
 * ---------------------------------------------------------------------------
 * Every function carries a block in this shape:
 *
 *   WHEN CALLED   the kernel condition that invokes it, and whether it may
 *                 block (almost none may)
 *   ARGS          what the kernel guarantees about each argument
 *   RETURN        what the kernel does with the returned value
 *   DEFAULT       what happens if you leave the body as it stands
 *   MUST          invariants that must hold, or the scheduler aborts
 *   IMPLEMENT     what the architecture document says this should do
 *
 * If you read only one line per function, read MUST.
 *
 * ---------------------------------------------------------------------------
 * FULL CALLBACK INVENTORY
 * ---------------------------------------------------------------------------
 * The kernel exposes the callbacks below. `Optional` means the kernel has a
 * defined fallback when the member is NULL; `Required` means leaving it out
 * (or leaving it unable to make progress) stops the scheduler.
 *
 *   #   Callback        Step  Optional?                Kernel fallback if NULL
 *   --  --------------  ----  -----------------------  -----------------------
 *   1   init             1    Optional                 nothing to initialise
 *   2   exit             1    Optional                 no cleanup
 *   3   cpu_online       1    Optional                 treated as always online
 *   4   cpu_offline      1    Optional                 no evacuation
 *   5   init_task        2    Required in practice     no per-task state
 *   6   exit_task        2    Optional                 task storage reclaimed
 *   7   enable           2    Optional                 no per-task init
 *   8   disable          2    Optional                 no per-task cleanup
 *   9   select_cpu       6    Optional                 wake to prev_cpu
 *  10   enqueue          3    REQUIRED                 -
 *  11   dequeue          -    Optional (not registered) nothing
 *  12   dispatch         4    Optional                 local DSQ drains only
 *  13   tick             5    Optional                 no preemption timer
 *  14   runnable         7    Optional                 no wakeup tracking
 *  15   running          7    Optional                 no slice accounting
 *  16   stopping         5    Optional                 no exit cleanup
 *  17   quiescent        5    Optional                 no CPU-release tracking
 *  18   yield            -    Optional                 task goes back to DSQ
 *  19   set_weight       -    Optional                 weight ignored
 *  20   set_cpumask      -    Optional                 affinity ignored
 *  21   update_idle      -    Optional                 kernel tracks idleness
 *  22   dump             -    Optional                 no scheduler dump
 *  23   dump_cpu         -    Optional                 no per-CPU dump
 *  24   dump_task        -    Optional                 no per-task dump
 *  25   cpu_acquire      -    Optional                 no acquire accounting
 *  26   cpu_release      -    Optional                 no release accounting
 *
 * The order of the functions below follows the implementation order, not the
 * table order, because that is the order in which they can be tested.
 *
 * ---------------------------------------------------------------------------
 * IMPLEMENTATION ORDER
 * ---------------------------------------------------------------------------
 * Do not write the lottery first. A broken lifecycle looks exactly like a
 * broken lottery: a hang. Get the lifecycle right, then the policy.
 *
 *   Step 1  tls_init()               per-CPU structures, weight table
 *   Step 2  tls_init_task()          per-task state, initial tier
 *   Step 3  tls_enqueue()            park the task in a tier
 *   Step 4  tls_dispatch()           hand a task to the local DSQ
 *
 *           After step 4 the object attaches and tasks run. This is what
 *           "a functional scheduler" means for this workspace. Verify with
 *           `make verify`, then attach it and confirm the machine stays
 *           responsive before touching anything else.
 *
 *   Step 5  tls_tick()               the 10 ms quantum and demotion
 *   Step 6  tls_wakeup_select_cpu()  passive load placement on wakeup
 *   Step 7  tls_running()            slice start accounting
 *   Step 8  the lottery draw       O(1) winner selection
 *   Step 9  the starvation rotation  the 150 ms weight permutation
 *   Step 10 the load balancer      bottom-up batch stealing
 *
 * Every step after 4 is an independently measurable improvement.
 *
 * ---------------------------------------------------------------------------
 * THREE WAYS THIS SCHEDULER WILL HANG YOUR MACHINE
 * ---------------------------------------------------------------------------
 *  1. A runnable task never handed to the kernel. Every task passed to
 *     tls_enqueue() must end up either in a tier array or on a DSQ.
 *     Dropping one is a hang, reported as SCX_EXIT_ERROR_STALL.
 *
 *  2. A task handed to the kernel twice, or a task_ctx->linked flag that
 *     disagrees with the tier arrays. That corrupts the arrays and usually
 *     shows up much later as a wild pointer or a verifier rejection.
 *
 *  3. Blocking in a callback. None of the callbacks below may sleep. Use the
 *     dispatch buffer via scx_bpf_dsq_insert() rather than anything that
 *     waits.
 *
 * While testing, keep a serial console or a second shell available, and read
 * the loader's exit report: it decodes the kernel's stop reason for you.
 *
 * ---------------------------------------------------------------------------
 * REFERENCE
 * ---------------------------------------------------------------------------
 * The kernel's contract for each callback is in
 * Documentation/scheduler/sched-ext.rst in the kernel source tree. The exact
 * struct layout you are compiled against is recovered from your kernel's BTF
 * into vmlinux.h; `make check-abi` tells you whether that header matches the
 * kernel you are about to load onto.
 */

/* ================================================================== */
/* Prelude: reporting and arithmetic helpers                           */
/* ================================================================== */
/*
 * Infrastructure, not algorithm. These exist so that the stubs below have a
 * consistent way to report a problem, and so that the ticket-scaling
 * arithmetic the architecture document specifies lives in exactly one place.
 */

/*
 * TLS_ERR   aborts the scheduler. The kernel detaches it and the loader
 *              reports SCX_EXIT_ERROR_BPF. Use it only for invariant
 *              violations: falling back to the kernel's default scheduler is
 *              a drastic action.
 * TLS_WARN  prints to the kernel log and continues. Use it for
 *              recoverable oddities you want to see while developing.
 *
 * Both are rate-limited by the kernel, so a call from a hot path will not
 * flood dmesg, but it will still show up in profiles.
 */
#define TLS_ERR(fmt, args...)	scx_bpf_error(fmt, ##args)
#define TLS_WARN(fmt, args...)	bpf_printk("tls: " fmt, ##args)

/*
 * tls_scale_to_pool - the document's O(1) winner scaling.
 *
 * Implements the architecture document's
 *
 *     Winning_Ticket = (xorshift_value * total_tickets) >> 32
 *
 * with `rnd` a full 32-bit uniform value and `total_tickets` the pool size
 * from cpu_ctx->total_tickets. The shift form is what avoids the division -
 * and therefore the modulo - that a naive `% total_tickets` would need. It is
 * exact whenever total_tickets is far below 2^32, which holds by
 * construction: at most TLS_MAX_CPUS * TLS_TIER_CAPACITY * 30 tickets
 * per CPU, about 2^21.
 *
 * Provided so that the scaling step is not a place where an off-by-one hides.
 * If you conclude the document's formula is wrong, change it here and justify
 * the change in the thesis, rather than inlining a different one at the call
 * site.
 */
static __always_inline u64 tls_scale_to_pool(u32 rnd, u64 total_tickets)
{
	return ((u64)rnd * total_tickets) >> 32;
}

/* ================================================================== */
/* STEP 1 - scheduler lifecycle                                       */
/* ================================================================== */

/*
 * tls_init - one-shot initialisation, before any task is scheduled.
 *
 * WHEN CALLED   Once, when the scheduler is attached, before the first task
 *               is enqueued. Runs on one CPU with no concurrency.
 * ARGS          none
 * RETURN        0 to accept. Non-zero aborts the attach and the loader
 *               reports the value; use it to refuse to run on hardware the
 *               scheduler cannot support.
 * DEFAULT       Initialises every per-CPU context, including the weight
 *               table and the sanctuary/rotation timestamps. Sufficient for
 *               the scheduler to run.
 * MUST          Do not touch task state here: no task exists yet.
 * IMPLEMENT     Already done. The one thing worth checking is the CPU count
 *               guard below: if this machine has more CPUs than
 *               TLS_MAX_CPUS, the per-CPU map cannot serve them all, and
 *               silently running with a truncated map would make placement
 *               and stealing read the wrong runqueue.
 */
s32 BPF_STRUCT_OPS(tls_init)
{
    // look into tls_core.bpf.h for the declaration of this type
	struct tls_cpu_ctx *cpu_ctx;
	u32 nr_cpus = scx_bpf_nr_cpu_ids();
	u32 cpu; //just a loop counter
	u64 now = bpf_ktime_get_ns();

	if (nr_cpus > TLS_MAX_CPUS) {
		TLS_ERR("tls: %u cpus exceeds TLS_MAX_CPUS (%u); "
			   "raise it in tls_intf.h and rebuild",
			   nr_cpus, (u32)TLS_MAX_CPUS);
		return -22;	/* -EINVAL */
	}

	/*
	 * Bring up every CPU slot, not just the online ones: a CPU that is
	 * offline now can come online later and would otherwise find an
	 * uninitialised context.
	 *
	 * The bound is a compile-time constant, which is what the verifier
	 * needs. TLS_MAX_CPUS is 256, so this is 256 iterations of a few
	 * stores - well inside the load-time budget.
	 */
	for (cpu = 0; cpu < TLS_MAX_CPUS; cpu++) {
		cpu_ctx = tls_cpu_ctx_of((s32)cpu);
		if (!cpu_ctx)
			continue;

		cpu_ctx->cpu = (s32)cpu;
		cpu_ctx->total_tickets = 0;
		cpu_ctx->load_factor = 0;
		cpu_ctx->anchor_slot = -1;
		cpu_ctx->last_rotate_ns = now;
		cpu_ctx->last_balance_ns = now;
		cpu_ctx->last_slice_start_ns = 0;
		cpu_ctx->rotation_epoch = 0;

		// bpf call returns a 32 bit number so we get 2 of them to fill a 64 bit prng state
		cpu_ctx->prng_state = ((u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();

		// we can't let that be 0 because  the xorshift won't work so we replace the 0.
	    if (cpu_ctx->prng_state == 0)
		{
			cpu_ctx->prng_state = 0x9e3779b97f4a7c15ULL;
		}
		/*
		 * The base weight table. Without this, total_tickets is 0 for
		 * every CPU and the lottery has an empty pool forever.
		 */
		tls_weight_table_init(cpu_ctx);
	}

	/*
	 * TODO(policy) - PRNG seeding and the hardware-entropy requirement.
	 *
	 * The architecture document asks for "hardware entropy (RDRAND /
	 * RDSEED) coupled with a high-performance Xorshift PRNG". Two
	 * constraints you need to resolve before writing that code:
	 *
	 *   a) BPF programs cannot execute RDRAND/RDSEED directly. There is
	 *      no helper and no allowed inline-asm path. What BPF does expose
	 *      is bpf_get_prandom_u32(), which the kernel sources from its
	 *      own CSPRNG. Read the document's wording as "a hardware-seeded
	 *      entropy source" and use that, or seed from
	 *      bpf_ktime_get_ns() mixed with the CPU id, and state the
	 *      substitution explicitly in the thesis.
	 *
	 *   b) Xorshift needs a non-zero state. A zero state is a fixed point
	 *      and yields zero forever, which turns the lottery into "always
	 *      pick tier 1". Guard the seed.
	 *
	 * A correct skeleton, to be filled in:
	 *
	 *     cpu_ctx->prng_state = ((u64)bpf_get_prandom_u32() << 32) |
	 *                           bpf_get_prandom_u32();
	 *     if (cpu_ctx->prng_state == 0)
	 *             cpu_ctx->prng_state = 0x9e3779b97f4a7c15ULL;
	 *
	 * and then implement the step function in the entropy section near
	 * the bottom of this file.
	 */

	return 0;
}

/*
 * tls_exit - report why the scheduler stopped.
 *
 * WHEN CALLED   Once, when the scheduler is detaching, for any reason:
 *               a clean stop, a BPF error, a watchdog stall, a sysrq
 *               override. This is the last BPF code to run.
 * ARGS          ei: the kernel's exit record. Never NULL.
 * RETURN        void
 * DEFAULT       Copies the reason and the BPF error message out through the
 *               UEI map so the loader can print them. Sufficient.
 * MUST          Do not enqueue, dispatch, or kick anything; the scheduler is
 *               already going away. Do not spin.
 * IMPLEMENT     Already done. If you add scheduler-owned resources in
 *               tls_init(), release them here.
 */
void BPF_STRUCT_OPS(tls_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(tls_uei, ei);
}

/*
 * tls_cpu_online - a CPU is becoming usable.
 *
 * WHEN CALLED   During scheduler attach for every CPU already online, and
 *               later whenever a CPU is onlined. May run before the first
 *               task is enqueued.
 * ARGS          cpu: a valid, online CPU id.
 * RETURN        void
 * DEFAULT       Records the CPU in its own context. Sufficient for the
 *               attach-time case, because tls_init() already prepared
 *               every slot.
 * MUST          Do not assume any task is running on `cpu`.
 * IMPLEMENT     Already done for the state this skeleton owns. If you add
 *               per-CPU resources beyond the context struct, acquire them
 *               here and release them in tls_cpu_offline().
 */
void BPF_STRUCT_OPS(tls_cpu_online, s32 cpu)
{
	struct tls_cpu_ctx *cpu_ctx = tls_cpu_ctx_of(cpu);

	if (!cpu_ctx)
		return;

	cpu_ctx->cpu = cpu;
	/*
	 * A CPU that is onlined after the scheduler attached may have missed
	 * the weight table initialisation in tls_init() if its slot was
	 * reset. Re-establish the invariant; this is cheap and idempotent.
	 */
	if (cpu_ctx->weights[tls_tier_slot(TIER_HIGH)] == 0 &&
	    cpu_ctx->weights[tls_tier_slot(TIER_MEDIUM)] == 0 &&
	    cpu_ctx->weights[tls_tier_slot(TIER_LOW)] == 0 &&
	    cpu_ctx->weights[tls_tier_slot(TIER_BACKGROUND)] == 0)
		tls_weight_table_init(cpu_ctx);
}

/*
 * tls_cpu_offline - a CPU is going away; evacuate its runqueue.
 *
 * WHEN CALLED   When a CPU is offlined, before it stops running tasks for
 *               this scheduler. The CPU's local DSQ is drained by the kernel
 *               separately.
 * ARGS          cpu: the CPU going offline. It is still online during the
 *               call, so its context is readable.
 * RETURN        void
 * DEFAULT       Unlinks every task in every tier of that CPU so that no
 *               dangling pointer is left in a context that will not run
 *               again, and records the loss.
 * MUST          Tasks that are unlinked here must still be *scheduled* -
 *               the kernel re-enqueues tasks it migrates off the dying CPU,
 *               so unlinking is correct and dropping them is not. If you
 *               change this to keep the tasks linked, you must arrange for
 *               them to be moved to another CPU's arrays under that CPU's
 *               lock, or they will never run again.
 * IMPLEMENT     The loop below is mechanical evacuation and is complete. The
 *               TODO is the migration decision: whether to let the kernel
 *               place these tasks (current behaviour) or to preserve tier
 *               membership by migrating them to a chosen CPU.
 */
void BPF_STRUCT_OPS(tls_cpu_offline, s32 cpu)
{
	struct tls_cpu_ctx *cpu_ctx = tls_cpu_ctx_of(cpu);
	struct tls_task_ctx *task_ctx;
	struct task_struct *p;
	s32 tier_id;
	u32 i;

	if (!cpu_ctx)
		return;

	for (tier_id = TIER_MIN; tier_id <= TIER_MAX; tier_id++) {
		u32 slot = tls_tier_slot(tier_id);

		/*
		 * Sanctuary first, then the lottery lanes. Iterating from the
		 * tail keeps the swap-and-pop indices valid: remove_at()
		 * moves the last element into the hole, and that element has
		 * already been visited.
		 */
		for (i = cpu_ctx->tiers[slot].nr; i > 0; i--) {
			p = cpu_ctx->tiers[slot].tasks[i - 1];
			if (!p)
				continue;

			task_ctx = tls_task_ctx(p);
			if (task_ctx) {
				task_ctx->linked = false;
				task_ctx->slot = -1;
				task_ctx->cpu = -1;
			}
			cpu_ctx->tiers[slot].tasks[i - 1] = NULL;
			cpu_ctx->tiers[slot].nr = i - 1;
		}
	}

	tls_recount_tickets(cpu_ctx);
	tls_update_load_factor(cpu_ctx);
}

/* ================================================================== */
/* STEP 2 - per-task lifecycle                                        */
/* ================================================================== */

/*
 * tls_init_task - allocate and initialise per-task state.
 *
 * WHEN CALLED   When a task is created or when the scheduler attaches to an
 *               existing task. Runs in the task's own context, so it may
 *               block in the general case, but treat it as non-blocking.
 * ARGS          p:     the task. Its task storage is writable here.
 *               args:  { .fork = true } for a freshly forked task,
 *                      { .fork = false } for a pre-existing one.
 *                      .cgroup is the cgroup in the same union slot - read
 *                      it only when needed.
 * RETURN        0 to accept the task. Non-zero makes the kernel refuse to
 *               move the task to this scheduler; the loader reports it.
 * DEFAULT       Allocates the per-task context and routes bottom-half I/O /
 *               interrupt threads to Tier -1 (TIER_SANCTUARY) and all other
 *               tasks to Tier 0 (TIER_ANCHOR).
 * MUST          Task storage is created with
 *               BPF_LOCAL_STORAGE_GET_F_CREATE; if the allocation fails,
 *               returning non-zero is correct but will fail the task's
 *               scheduling. The kernel reclaims task storage on exit, so
 *               there is nothing to free in tls_exit_task().
 * IMPLEMENT     Classification between TIER_SANCTUARY and TIER_ANCHOR is
 *               done via tls_is_sanctuary_task(); admission into the
 *               Sanctuary slot itself happens in tls_enqueue().
 */
s32 BPF_STRUCT_OPS(tls_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct tls_task_ctx *task_ctx;

	task_ctx = tls_task_ctx_alloc(p);
	if (!task_ctx) {
		TLS_WARN("init_task: no task storage for %d", p->pid);
		return -12;	/* -ENOMEM */
	}

	/*
	 * Zero the whole context rather than field-by-field, so that a field
	 * added to struct tls_task_ctx later cannot be left holding
	 * whatever was in the storage slot. The compiler turns this into
	 * stores; the verifier needs no special handling.
	 */
	__builtin_memset(task_ctx, 0, sizeof(*task_ctx));

	if (tls_is_sanctuary_task(p))
        task_ctx->tier = TIER_SANCTUARY;
	else
        task_ctx->tier = TIER_ANCHOR;


	task_ctx->slot = -1;
	task_ctx->cpu = -1;
	task_ctx->linked = false;

	(void)args;
	return 0;
}

/*
 * tls_exit_task - the task is gone.
 *
 * WHEN CALLED   Just before the task's task_struct is freed. The task cannot
 *               be enqueued from here and does not need to be.
 * ARGS          p:    the exiting task. Its context is still readable.
 *               args: { .cancelled = true } if the task is exiting without
 *                     its scheduling state having been set up, or the
 *                     scheduler is detaching; in that case it may already be
 *                     unlinked.
 * RETURN        void
 * DEFAULT       Unlinks the task from its tier if it is still linked.
 *               Necessary: a task can exit while parked in a tier array, and
 *               leaving a freed task_struct pointer in the array is a
 *               use-after-free that the verifier cannot catch.
 * MUST          Never call scx_bpf_dsq_insert() here; the task is dying.
 * IMPLEMENT     Already done. The one subtlety is the double-unlink guard:
 *               tls_unlink() is idempotent through task_ctx->linked, so a task
 *               that was already removed is not removed twice.
 */
void BPF_STRUCT_OPS(tls_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	tls_unlink(p);
	(void)args;
}

/*
 * tls_enable - the task has been handed to this scheduler.
 *
 * WHEN CALLED   When a task becomes schedulable by this scheduler: at attach
 *               for every runnable task, on fork, and on a class switch.
 *               Always preceded by tls_init_task().
 * ARGS          p: the task, with valid task storage.
 * RETURN        void
 * DEFAULT       Makes sure the task has storage and a valid tier, leaving
 *               actual tier placement/admission to tls_enqueue(). This is
 *               the second half of the "new task appears" path and is
 *               deliberately defensive: a task reaching enable() without
 *               storage would otherwise fail in enqueue().
 * MUST          Ensure task storage exists and task_ctx->tier is valid so that
 *               tls_enqueue() can schedule the task when it becomes runnable.
 * IMPLEMENT     Complete. Classification policy belongs in
 *               tls_init_task(); this function only guarantees the
 *               storage and tier invariants hold.
 */
void BPF_STRUCT_OPS(tls_enable, struct task_struct *p)
{
	struct tls_task_ctx *task_ctx;

	task_ctx = tls_task_ctx_alloc(p);
	if (!task_ctx) {
		TLS_WARN("enable: no task storage for %d", p->pid);
		return;
	}

	if (!tls_tier_valid(task_ctx->tier))
		task_ctx->tier = TIER_ANCHOR;
}

/*
 * tls_disable - the task is leaving this scheduler.
 *
 * WHEN CALLED   When a task stops being schedulable by this scheduler:
 *               on exit, on a class switch away, or when the scheduler
 *               detaches. After this the kernel no longer calls the
 *               callbacks below for this task.
 * ARGS          p: the task.
 * RETURN        void
 * DEFAULT       Unlinks the task from its tier and leaves its storage in
 *               place for the kernel to reclaim.
 * MUST          Do not free task storage; the kernel owns its lifetime.
 * IMPLEMENT     Complete.
 */
void BPF_STRUCT_OPS(tls_disable, struct task_struct *p)
{
	tls_unlink(p);
}

/* ================================================================== */
/* STEP 3 - enqueue: the one callback that must never drop a task      */
/* ================================================================== */

/*
 * tls_enqueue - a task became runnable; place it.
 *
 * WHEN CALLED   Whenever a task becomes runnable: a wakeup from sleep, a
 *               fork, a migration, an expired slice, a sched_yield, or
 *               because the kernel is re-enqueueing after a preemption.
 *               Also called for tasks the scheduler itself did not place,
 *               such as a task whose affinity changed.
 * ARGS          p:          the runnable task. It is NOT running and is not
 *                           on any DSQ.
 *               enq_flags:  a bitmask of SCX_ENQ_* values. The ones that
 *                           matter to a policy like this one:
 *
 *                 SCX_ENQ_WAKEUP        it was asleep and is waking up; the
 *                                       latency-sensitive case
 *                 SCX_ENQ_PREEMPT       it is expected to preempt currently
 *                                       running work
 *                 SCX_ENQ_CPU_SELECTED  tls_wakeup_select_cpu() already chose
 *                                       a CPU for it, so do not re-decide
 *                 SCX_ENQ_LAST          it is the last task in this batch
 *                 SCX_ENQ_REENQ         the kernel is re-enqueueing it
 *                 SCX_ENQ_HEAD          insert at the head, not the tail
 *
 *                           Test flags with `enq_flags & SCX_ENQ_WAKEUP`.
 *                           The full set is in your vmlinux.h.
 * RETURN        void. There is no way to report failure; a task that is not
 *               made reachable here is a hang.
 * DEFAULT       Every task goes to the anchor tier of the CPU it last ran on
 *               (or CPU 0 if it has no CPU), and is then pushed straight to
 *               that CPU's local DSQ so that it can actually run. The
 *               scheduler is functional but performs no lottery at all.
 * MUST          1. Leave the task reachable. Either it is in a tier array
 *                  AND will be dispatched later, or it is already on a DSQ.
 *               2. Never insert the same task twice. The
 *                  `enq_flags & SCX_ENQ_CPU_SELECTED` hint tells you the CPU
 *                  was already chosen; it does not tell you the task was
 *                  already inserted.
 *               3. Do not block.
 * IMPLEMENT     TODO - this is the heart of TLS. The intended shape:
 *
 *                 a) Get or create the task context; if the task is not yet
 *                    linked, choose its tier. The document's rule for a
 *                    newly runnable task is Tier 0 (anchor). Tasks woken by
 *                    SCX_ENQ_WAKEUP after sleeping at least
 *                    TLS_WAKEUP_MIN_SLEEP_NS reset their carried-over slice
 *                    usage and, if in Tiers 2..4, promote one tier up
 *                    (tier - 1, capped at TIER_HIGH / Tier 1) without
 *                    preempting the running task.
 *                 b) Pick the target CPU. If SCX_ENQ_CPU_SELECTED is set, use
 *                    scx_bpf_task_cpu(p). Otherwise this is the passive
 *                    placement decision: route to the CPU with the lowest
 *                    atomic load_factor (mirroring total_tickets across
 *                    Tiers 0..4) - see tls_update_load_factor() in
 *                    tls_bpf_impl.h and tls_pick_lowest_load_cpu() in
 *                    tls_helpers.bpf.c.
 *                 c) Push into that CPU's tier array with
 *                    tls_tier_push(). It returns -2 if the tier is full;
 *                    the anchor tier is the documented overflow destination,
 *                    and if even that is full you must still leave the task
 *                    reachable - the local DSQ is the last-resort fallback
 *                    and the current default body shows how.
 *                 d) The kernel calls tls_dispatch() to refill the local
 *                    DSQ. If you choose instead to insert immediately here,
 *                    you do not need dispatch() at all - but pick one, and
 *                    do not do both, or a task will run twice per slot.
 *
 *               The default body below deliberately does (c)'s fallback and
 *               (d) together so the machine runs before you write anything.
 *               Replace it rather than extending it.
 */
void BPF_STRUCT_OPS(tls_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct tls_cpu_ctx *cpu_ctx;
	struct tls_task_ctx *task_ctx;
	struct tls_tier *tier;
	bool qualified_wakeup = false;
	s32 cpu, tier_id;
	u64 slice;

	task_ctx = tls_task_ctx_alloc(p);
	if (!task_ctx) {
		/*
		 * No storage means we cannot track this task. It still must
		 * run, so hand it to the kernel directly and let the kernel's
		 * built-in behaviour take over for this one task.
		 */
		TLS_WARN("enqueue: no storage for %d, bypassing", p->pid);
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, 0, enq_flags);
		return;
	}

	/*
	 * If the task is already parked, it was woken while queued: it only
	 * needs to become dispatchable, and it keeps its tier. Re-pushing it
	 * would violate the "one tier array at a time" invariant.
	 */
	if (task_ctx->linked) {
		s32 linked_cpu = task_ctx->cpu;

		if (task_ctx->tier == TIER_SANCTUARY)
			slice = tls_sanctuary_budget();
		else
			slice = tls_slice_ns();

		if (linked_cpu >= 0 && linked_cpu < (s32)TLS_MAX_CPUS)
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)(u32)linked_cpu,
					   slice, enq_flags);
		else
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, enq_flags);
		return;
	}

	cpu = scx_bpf_task_cpu(p);
	if (cpu < 0)
		cpu = (s32)bpf_get_smp_processor_id();

	if (!(enq_flags & SCX_ENQ_CPU_SELECTED))
		cpu = tls_pick_lowest_load_cpu(p, cpu);

	cpu_ctx = tls_cpu_ctx_of(cpu);
	if (!cpu_ctx) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, 0, enq_flags);
		return;
	}

	/*
	 * Tier 1 crowding guard (minimum sleep threshold): only a genuine sleep
	 * of at least TLS_WAKEUP_MIN_SLEEP_NS resets carried-over slice usage
	 * and qualifies for wakeup promotion. Brief futex/pipe/page-fault
	 * micro-sleeps neither clear slice_used_ns nor promote the task.
	 */
	if (enq_flags & SCX_ENQ_WAKEUP) {
		u64 now = bpf_ktime_get_ns();
		u64 slept_ns = 0;

		if (task_ctx->last_sleep_ns != 0 && now > task_ctx->last_sleep_ns)
			slept_ns = now - task_ctx->last_sleep_ns;

		if (slept_ns >= TLS_WAKEUP_MIN_SLEEP_NS) {
			task_ctx->slice_used_ns = 0;
			qualified_wakeup = true;
		}

		task_ctx->last_sleep_ns = 0;
	}

	/*
	 * Tier -1 (Sanctuary) bypasses the lottery and preempts the target CPU
	 * with a strict 1 ms budget; if its single slot is already busy, defer
	 * the task into Tier 0 (Anchor).
	 */
	if (task_ctx->tier == TIER_SANCTUARY) {
		if (tls_sanctuary_enter(cpu_ctx, p) == 0) {
			slice = tls_sanctuary_budget();
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)(u32)cpu,
					   slice,
					   enq_flags | SCX_ENQ_PREEMPT | SCX_ENQ_HEAD);
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			return;
		}
		tier_id = TIER_ANCHOR;
	} else if (tls_tier_valid(task_ctx->tier)) {
		tier_id = task_ctx->tier;
	} else {
		tier_id = TIER_ANCHOR;
	}

	/*
	 * Wakeup promotion: tasks in Tiers 2..4 waking from a qualified sleep
	 * step up one tier (capped at Tier 1 / TIER_HIGH) without preempting
	 * the CPU.
	 */
	if (qualified_wakeup && tier_id > TIER_HIGH)
		tier_id--;

	task_ctx->tier = tier_id;

	if (tls_tier_push(cpu_ctx, tier_id, p)) {
		/*
		 * The chosen tier is full. Fall back to the anchor tier, and
		 * if that is full too, put the task straight on the local DSQ:
		 * an unqueued runnable task is a hang, and a short slice is a
		 * far better failure than a stalled scheduler.
		 */
		if (tier_id != TIER_ANCHOR &&
		    tls_tier_push(cpu_ctx, TIER_ANCHOR, p) == 0) {
			tier_id = TIER_ANCHOR;
		} else {
			slice = tls_slice_ns();
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)(u32)cpu,
					   slice, enq_flags);
			return;
		}
	}

	tier = &cpu_ctx->tiers[tls_tier_slot(tier_id)];

	/*
	 * TODO(policy): the lottery. The architecture document wants the draw
	 * to happen here or in dispatch(): compute the total ticket pool,
	 * generate a winning ticket with the entropy mixing, walk the tier
	 * boundaries to find the winning tier, and divide to get the winning
	 * index. tls_scale_to_pool() at the top of this file is the
	 * scaling step, and cpu_ctx->total_tickets is already maintained by
	 * tls_recount_tickets() on every push and pop.
	 *
	 * What is deliberately absent here: the draw itself, the boundary
	 * walk, and the index arithmetic. Those are the algorithm.
	 *
	 * The placeholder below ignores the lottery and dispatches the task
	 * that just arrived, using the tier the kernel is told it belongs to.
	 * It exists only so that `make` produces something that runs; it is
	 * not a simplification of the algorithm and should be replaced, not
	 * tuned.
	 */
	(void)tier;
	slice = tls_slice_ns();
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, slice, enq_flags);
}

/*
 * tls_dequeue - a task is being removed from a DSQ.
 *
 * WHEN CALLED   When the kernel removes a task from a DSQ: it is being
 *               migrated, its affinity narrowed, or a re-enqueue is
 *               replacing it.
 * ARGS          p:          the task being removed.
 *               deq_flags:  currently unused; reserved.
 * RETURN        void
 * DEFAULT       Not registered. The scheduler unlinks tasks explicitly in
 *               the lifecycle callbacks, so a dequeue hook would do the same
 *               work twice and risk double removal.
 * MUST          If you register this, it must be idempotent with respect to
 *               tls_unlink(), because both paths can run for the same
 *               task.
 * IMPLEMENT     Left unregistered in main.bpf.c on purpose. Register it only
 *               if you move to a policy where the kernel, rather than this
 *               scheduler, evicts tasks from the runqueue.
 */
void BPF_STRUCT_OPS(tls_dequeue, struct task_struct *p, u64 deq_flags)
{
	tls_unlink(p);
	(void)deq_flags;
}

/* ================================================================== */
/* STEP 4 - dispatch: hand work to the CPU                             */
/* ================================================================== */

/*
 * tls_dispatch - refill a CPU's local DSQ.
 *
 * WHEN CALLED   On the CPU identified by `cpu`, when its local DSQ has room
 *               and the scheduler may provide more work. Also called when a
 *               CPU is kicked awake. This runs with the target CPU's
 *               runqueue lock held, so it is atomic with respect to that
 *               CPU's scheduling but NOT with respect to remote access from
 *               another CPU's tls_dispatch().
 * ARGS          cpu:  the CPU to feed. Not necessarily the current CPU.
 *               prev: the task that just stopped running, or NULL. Ignore it
 *                     unless you want to implement keep-last behaviour.
 * RETURN        void
 * DEFAULT       A no-op: it does not insert anything, because the default
 *               tls_enqueue() already puts tasks on the local DSQ.
 *               Consistent, and the reason the scheduler runs before you
 *               write the lottery.
 * MUST          1. Every task you remove from a tier array here must be
 *                  inserted on a DSQ in the same call. Pulling a task out
 *                  and then failing to insert it is a lost task and a hang.
 *               2. Bound the work per call. The kernel gives you a budget
 *                  of scx_bpf_dispatch_nr_slots() insertions; exceeding it
 *                  is an error. The loop below stops at that bound.
 *               3. A task can only be dispatched to the CPU it is allowed to
 *                  run on. If you dispatch to a specific CPU, only take
 *                  tasks whose affinity permits it, or use SCX_DSQ_LOCAL
 *                  which targets the CPU being fed.
 * IMPLEMENT     TODO - with the lottery in enqueue(), this function only has
 *               to move already-decided tasks, and the structure is:
 *
 *                 a) Return immediately if the CPU's total_tickets is 0:
 *                    there is nothing to draw from.
 *                 b) Draw a winner: tls_scale_to_pool() of the mixed
 *                    PRNG output against cpu_ctx->total_tickets.
 *                 c) Walk the tier boundaries from TIER_HIGH downward,
 *                    subtracting each tier's contribution, until the
 *                    winning ticket falls inside a tier.
 *                 d) Divide the remaining offset by that tier's live weight
 *                    to get the index, and swap-and-pop it out with
 *                    tls_tier_remove_at().
 *                 e) scx_bpf_dsq_insert() the winner onto SCX_DSQ_LOCAL with
 *                    its slice, then repeat until the budget is exhausted or
 *                    the pool is empty.
 *
 *               If instead you keep the draw in enqueue(), this function can
 *               drain the tier arrays in tier order without any lottery. The
 *               document does not say which of the two places owns the draw;
 *               either is defensible, but state your choice.
 */
void BPF_STRUCT_OPS(tls_dispatch, s32 cpu, struct task_struct *prev)
{
	struct tls_cpu_ctx *cpu_ctx = tls_cpu_ctx_of(cpu);

	if (!cpu_ctx)
		return;

	/*
	 * TODO(policy): the lottery draw and the drain loop go here.
	 *
	 * The body is intentionally empty. An empty dispatch() is safe
	 * whenever enqueue() inserts directly onto a DSQ, which is what the
	 * default enqueue() does. If you move insertion here, this function
	 * must never return with a runnable task still in a tier array and
	 * the local DSQ empty.
	 */
	(void)prev;
}

/* ================================================================== */
/* STEP 5 - the quantum: tick, stopping, quiescent                     */
/* ================================================================== */

/*
 * tls_tick - the scheduler's periodic hook on a running task.
 *
 * WHEN CALLED   Periodically while a task is running on a CPU, at the
 *               granularity the kernel chooses (typically once per
 *               scheduler tick, not every timer interrupt). Also the only
 *               callback where the architecture document's "every 10 ms"
 *               and "every 150 ms" clocks can be driven for a busy CPU.
 * ARGS          p: the currently running task. Not NULL.
 * RETURN        void
 * DEFAULT       Counts ticks and does nothing else. The scheduler does NOT
 *               preempt on a 10 ms quantum yet and does NOT rotate tiers
 *               every 150 ms.
 * MUST          1. This runs with the task's runqueue lock held and in
 *                  interrupt context. Do not block, do not take a BPF
 *                  spinlock that could be held by another CPU for long.
 *               2. If you preempt by kicking the current CPU, be aware that
 *                  you are already on it; the usual way to force a
 *                  reschedule is to insert a higher-priority task on
 *                  SCX_DSQ_LOCAL and let the kernel notice, or to call
 *                  scx_bpf_kick_cpu().
 * IMPLEMENT     TODO - two independent mechanisms live here. Implement them
 *               separately so you can measure them separately.
 *
 *               A. The 10 ms quantum and demotion.
 *                  Compare bpf_ktime_get_ns() against
 *                  cpu_ctx->last_slice_start_ns (set in tls_running()) and
 *                  tls_slice_ns(). On expiry, demote one tier per the
 *                  document: TIER_HIGH->TIER_MEDIUM->TIER_LOW->
 *                  TIER_BACKGROUND, then stop (Tier 4 is the floor; the
 *                  rotation is what rescues tasks from it). Demotion is
 *                  swap-and-pop, so it is: unlink from the old tier, push
 *                  to the new tier.
 *
 *               B. The 150 ms starvation rotation.
 *                  Compare the current time against cpu_ctx->last_rotate_ns
 *                  and tls_rotate_ns(). On expiry, permute the live weights
 *                  in cpu_ctx->weights[] rather than the tier contents: lane 4
 *                  takes lane 1's weight and lanes 1-3 shift down one level.
 *                  This is what cpu_ctx->weights[] exists for - it makes the
 *                  rotation four u32 moves plus a tls_recount_tickets()
 *                  call, with no task relocated and no slot index to repair.
 *                  Do not implement the rotation by moving task pointers:
 *                  that is O(capacity) per lane and races a remote steal.
 *                  Then set cpu_ctx->last_rotate_ns, bump
 *                  cpu_ctx->rotation_epoch and cpu_ctx->rotations, and count
 *                  TLS_STAT_* as appropriate.
 *
 *               Both mechanisms need to run even when this CPU has no
 *               running task, so also drive them from tls_dispatch() or
 *               from the load-balance path at step 10; tick() alone will
 *               not fire on an idle CPU.
 */
void BPF_STRUCT_OPS(tls_tick, struct task_struct *p)
{
	struct tls_task_ctx *task_ctx = tls_task_ctx(p);
	struct tls_cpu_ctx *cpu_ctx = tls_this_cpu_ctx();
	u64 now;

	if (!cpu_ctx)
		return;

	now = bpf_ktime_get_ns();

	/*
	 * Keep the rotation and balance deadlines observable even while the
	 * policy is unwritten, so that `tls stats` has something to show
	 * and so that the plumbing is proven before the algorithm is added.
	 */
	(void)task_ctx;
	(void)now;

	/* TODO(policy): mechanism A - the 10 ms quantum and demotion. */
	/* TODO(policy): mechanism B - the 150 ms starvation rotation. */
}

/*
 * tls_stopping - the running task is about to stop.
 *
 * WHEN CALLED   When the running task on this CPU is being descheduled, just
 *               before it stops. Symmetric with tls_running().
 * ARGS          p:        the task stopping. Still running.
 *               runnable: true if it is still runnable (slice expired,
 *                         preempted, or yielding), false if it is blocking /
 *                         going to sleep or exiting.
 * RETURN        void
 * DEFAULT       Unlinks the task, accumulates runtime toward its current
 *               quantum (demoting on exhaustion), and stamps last_sleep_ns
 *               when blocking so tls_enqueue() can enforce the minimum sleep
 *               threshold for wakeup promotion.
 * MUST          The task must not remain linked while it is running;
 *               otherwise a remote steal could take a task that is executing
 *               on another CPU.
 * IMPLEMENT     Complete for quota accounting, demotion, and Tier 1 crowding
 *               guards.
 */
void BPF_STRUCT_OPS(tls_stopping, struct task_struct *p, bool runnable)
{
	struct tls_task_ctx *task_ctx;
	struct tls_cpu_ctx *cpu_ctx;
	u64 now, delta;
	s32 cpu;

	tls_unlink(p);

	task_ctx = tls_task_ctx(p);
	if (!task_ctx)
		return;

	/*
	 * Use p's CPU context rather than bpf_get_smp_processor_id(), because
	 * ops.stopping() can occasionally run from another CPU during
	 * migration while holding p's rq lock.
	 */
	cpu = scx_bpf_task_cpu(p);
	cpu_ctx = tls_cpu_ctx_of(cpu);
	if (!cpu_ctx)
		return;

	now = bpf_ktime_get_ns();

	/*
	 * Tier 1 crowding guard (cumulative runtime carry-over): accumulate
	 * elapsed runtime into task_ctx->slice_used_ns across short sleeps so
	 * a task that blocks briefly before 10 ms cannot evade demotion.
	 */
	delta = 0;
	if (cpu_ctx->last_slice_start_ns != 0 && now > cpu_ctx->last_slice_start_ns)
		delta = now - cpu_ctx->last_slice_start_ns;

	cpu_ctx->last_slice_start_ns = 0;
	task_ctx->slice_used_ns += delta;

	if (task_ctx->tier == TIER_SANCTUARY) {
		if (task_ctx->slice_used_ns >= tls_sanctuary_budget()) {
			task_ctx->tier = TIER_ANCHOR;
			task_ctx->slice_used_ns = 0;
		}
	} else {
		if (task_ctx->slice_used_ns >= tls_slice_ns()) {
			if (task_ctx->tier < TIER_BACKGROUND)
				task_ctx->tier++;
			task_ctx->slice_used_ns = 0;
		}
	}

	/*
	 * Tier 1 crowding guard (sleep start stamp): only stamp last_sleep_ns
	 * when the task is actually blocking so preemption wait time never
	 * counts as sleep time.
	 */
	if (!runnable)
		task_ctx->last_sleep_ns = now;
	else
		task_ctx->last_sleep_ns = 0;
}

/*
 * tls_quiescent - the CPU is about to become idle.
 *
 * WHEN CALLED   When the CPU stops running this scheduler's tasks and is
 *               about to go idle, or after an idle period ends.
 * ARGS          p:     the last task that ran, or NULL.
 *               flags: SCX_QUIESCENT_* values.
 * RETURN        void
 * DEFAULT       Records the deadline state so that the rotation and balance
 *               clocks are not applied retroactively after a long idle
 *               period.
 * MUST          Nothing may be enqueued from here; the CPU is going idle by
 *               definition.
 * IMPLEMENT     TODO - if you drive the rotation from here rather than from
 *               tls_tick(), this is where an idle CPU would notice that
 *               150 ms have passed. Applying a rotation to an idle CPU's
 *               weights is harmless and cheap. Decide and document whether
 *               idle CPUs participate in rotation.
 */
void BPF_STRUCT_OPS(tls_quiescent, struct task_struct *p, u64 flags)
{
	struct tls_cpu_ctx *cpu_ctx = tls_this_cpu_ctx();

	if (!cpu_ctx)
		return;

	cpu_ctx->last_rotate_ns = bpf_ktime_get_ns();
	(void)p;
	(void)flags;
}

/* ================================================================== */
/* STEP 6 - CPU selection on wakeup and passive placement              */
/* ================================================================== */

/*
 * tls_wakeup_select_cpu - pick the target CPU on wakeup (ops.select_cpu).
 *
 * WHEN CALLED   On wakeups (and fork/exec CPU selection) when the task can
 *               migrate (nr_cpus_allowed > 1), before its runqueue lock is
 *               taken. Not called on slice-expired/preemption re-enqueues or
 *               single-CPU pinned tasks.
 * ARGS          p:          the waking task.
 *               prev_cpu:   the CPU it last ran on (keeps L1/L2 locality).
 *               wake_flags: WF_* wakeup flags (e.g. WF_SYNC).
 * RETURN        Target CPU id (must be in p->cpus_ptr). The kernel migrates
 *               p there and sets SCX_ENQ_CPU_SELECTED for tls_enqueue().
 * DEFAULT       Delegates to scx_bpf_select_cpu_dfl() to prefer an idle CPU
 *               (or prev_cpu) and kicks it if idle.
 * IMPLEMENT     TODO(Step 6) - replace or combine with passive load_factor
 *               placement (tls_pick_lowest_load_cpu()) while preserving
 *               idle-CPU kicks and p->cpus_ptr affinity checks.
 */
s32 BPF_STRUCT_OPS(tls_wakeup_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	/*
	 * The kernel's default selector: finds an idle CPU in the task's
	 * cpumask, falling back to prev_cpu, and reports whether it found one.
	 */
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (cpu < 0)
		cpu = prev_cpu;

	/*
	 * If we found an idle CPU, tell the rest of the path that the CPU
	 * decision is already made. tls_enqueue() uses this through
	 * SCX_ENQ_CPU_SELECTED.
	 */
	if (is_idle)
		scx_bpf_kick_cpu(cpu, 0);

	/* TODO(policy): replace with the lowest-load-factor placement. */
	return cpu;
}

/* ================================================================== */
/* STEP 7 - running and runnable accounting                            */
/* ================================================================== */

/*
 * tls_running - the task has started running on this CPU.
 *
 * WHEN CALLED   When a task is switched in, after the context switch has been
 *               committed. Symmetric with tls_stopping().
 * ARGS          p: the task that is now running.
 * RETURN        void
 * DEFAULT       Stamps cpu_ctx->last_slice_start_ns on the current CPU. This is
 *               what makes the quantum (and Tier -1 budget) in tls_tick()
 *               measurable at all.
 * MUST          Do not insert anything on a DSQ here; the task is already
 *               running. Doing so is the classic double-enqueue.
 * IMPLEMENT     TODO - the RDTSC half. The architecture document specifies
 *               that Tier -1 runs under "a strict hardware cycle budget
 *               (RDTSC) to prevent interrupt livelocks". BPF cannot execute
 *               RDTSC; there is no helper for it and inline asm is not
 *               available. The timestamp below is the substitute:
 *               bpf_ktime_get_ns() gives the same ordering property (a
 *               monotonic hardware-derived clock) in nanoseconds, and the
 *               budget can be expressed in nanoseconds instead of cycles.
 *               State the substitution and its consequence in the thesis:
 *               a nanosecond budget is not invariant to CPU frequency, so a
 *               core running below its nominal clock gets more wall time per
 *               budget unit.
 *
 *               The per-CPU slice stamp below covers both normal slices and
 *               Tier -1 sanctuary entries, since at most one task runs on a
 *               CPU at a time.
 */
void BPF_STRUCT_OPS(tls_running, struct task_struct *p)
{
	struct tls_cpu_ctx *cpu_ctx = tls_this_cpu_ctx();
	u64 now = bpf_ktime_get_ns();

	(void)p;
	if (!cpu_ctx)
		return;

	/*
	 * TODO(policy): if task_ctx->tier == TIER_SANCTUARY, enforce the budget
	 * against cpu_ctx->last_slice_start_ns in tls_tick().
	 */
	cpu_ctx->last_slice_start_ns = now;
}

/*
 * tls_runnable - the task has become runnable but is not yet running.
 *
 * WHEN CALLED   When a task is woken and enqueued, before it is dispatched.
 *               Complements tls_running(), which fires later.
 * ARGS          p:          the newly runnable task.\n *               enq_flags:  the same flags tls_enqueue() received.
 * RETURN        void
 * DEFAULT       Nothing beyond keeping the wakeup observable. The scheduler
 *               currently classifies on the enqueue path instead.
 * MUST          Do not enqueue the task here; tls_enqueue() has already
 *               been or will be called for it. Doing so double-enqueues.
 * IMPLEMENT     TODO - wakeup-promotion accounting. If you promote a task on
 *               SCX_ENQ_WAKEUP (the latency case the tiers exist for), this
 *               is the natural place to record it, because it has the flags
 *               and runs exactly once per wakeup. Whatever you decide, keep
 *               the promotion itself in one place; two paths that both
 *               promote will promote twice.
 */
void BPF_STRUCT_OPS(tls_runnable, struct task_struct *p, u64 enq_flags)
{
	(void)p;
	(void)enq_flags;
}

/* ================================================================== */
/* STEP 8 - the lottery: the algorithm itself                          */
/* ================================================================== */
/*
 * Everything under this heading is where the TLS algorithm goes. None of
 * it can be written for you without writing your thesis, and all of it is
 * reachable from the three callbacks above:
 *
 *   the draw        called from tls_dispatch() or tls_enqueue()
 *   entropy         see the seeding TODO in tls_init()
 *   classification  see the TODO in tls_enqueue()
 *   demotion        see mechanism A in tls_tick()
 *   rotation        see mechanism B in tls_tick()
 *   placement       see the TODO in tls_wakeup_select_cpu()
 *   stealing        step 10, below
 *
 * Provided so that the arithmetic has a home and so the skeleton shows where
 * the boundary between mechanism and policy sits:
 *
 *   cpu_ctx->total_tickets     maintained on every push and pop, ready to be
 *                              the divisor of the draw
 *   cpu_ctx->weights[]         the live ticket weights, already permutable
 *                              for the rotation
 *   tls_scale_to_pool()     the document's shift-based scaling step
 *   tls_tickets_of_tier()   one tier's contribution to the pool
 *   tls_tier_remove_at()    O(1) swap-and-pop of the winner
 *   tls_update_load_factor()  the placement and stealing metric
 *
 * Explicitly not provided, because implementing it would be implementing your
 * algorithm: the boundary walk that maps a winning ticket to a tier, the
 * index division inside that tier, the xorshift step, the demotion ladder,
 * the rotation permutation and the victim-selection rule.
 */

/* ================================================================== */
/* STEP 10 - load balancing                                            */
/* ================================================================== */

/*
 * tls_cpu_acquire - this CPU has been granted an idle CPU.
 *
 * WHEN CALLED   When the kernel hands an idle CPU to this scheduler, usually
 *               because a prior scx_bpf_kick_cpu() or an idle search asked
 *               for it. Pairs with tls_cpu_release().
 * ARGS          cpu:  the CPU being acquired. It is idle and will not run
 *                     other tasks until released.
 *               args: currently an empty struct; reserved for future fields.
 *                     Do not read it.
 * RETURN        void
 * DEFAULT       Marks the acquisition in the CPU's counters.
 * MUST          The kernel guarantees the CPU stays idle until release, so
 *               this is the only window in which a task can be placed on it
 *               without a race. If you place a task here, place it before
 *               returning.
 * IMPLEMENT     TODO - this is where bottom-up batch stealing belongs if you
 *               use the acquire/release mechanism rather than a periodic
 *               scan. See the note under tls_cpu_release().
 */
void BPF_STRUCT_OPS(tls_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	struct tls_cpu_ctx *cpu_ctx = tls_cpu_ctx_of(cpu);

	if (cpu_ctx)
		cpu_ctx->kicks++;	/* reusing the counter as an acquire count */
	(void)args;
}

/*
 * tls_cpu_release - the acquired CPU is being taken back.
 *
 * WHEN CALLED   When the kernel reclaims an idle CPU from this scheduler, for
 *               example because a higher-priority class needs it. Pairs with
 *               tls_cpu_acquire().
 * ARGS          cpu:  the CPU being released.
 *               args: { .reason = one of the SCX_CPU_PREEMPT_* values,
 *                       .task   = the task that caused the preemption, or
 *                                 NULL }
 * RETURN        void
 * DEFAULT       Records the release.
 * MUST          This can be called asynchronously while you are mid-placement
 *               on `cpu`. Any state you keep about "owning" a CPU must be
 *               invalidated here.
 * IMPLEMENT     TODO - bottom-up batch stealing. The document's rule:
 *               every 100 ms a core checks for load imbalance across
 *               neighbouring cores and, if the imbalance exceeds the
 *               threshold, acquires the target core's spinlock and pointer
 *               swaps its lowest tier with the thief's Tier 2. Work stealing
 *               targets Tier 4, cascading to Tier 3 only if necessary, and
 *               Tiers 0 and 1 stay pinned for cache locality.
 *
 *               Two things the skeleton gives you for that:
 *                 - cpu_ctx->load_factor, already computed from Tier -1,
 *                   Tier 3 and Tier 4 by tls_update_load_factor(), readable
 *                   remotely without a lock;
 *                 - tls_tunables.balance_ratio_num / _den, the threshold
 *                   the loader can set at runtime without a rebuild.
 *
 *               Two things you must be careful about:
 *                 - the spinlock: cpu_ctx->lock_opaque is declared as a u64
 *                   so that this header does not depend on the BPF spinlock
 *                   type. To actually take the lock you must declare the
 *                   field as struct bpf_spin_lock in
 *                   struct tls_cpu_ctx and re-run the build. Do that
 *                   consciously; a spinlock held across a map update is the
 *                   usual cause of a map-full or stall abort here.
 *                 - "pointer swaps its lowest tier with its Tier 2" moves
 *                   tasks between tiers, which changes
 *                   task_ctx->tier/slot/cpu for every moved task. Use
 *                   tls_tier_push() and tls_tier_remove_at() rather
 *                   than memcpy, or the slot indices will be stale.
 */
void BPF_STRUCT_OPS(tls_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	struct tls_cpu_ctx *cpu_ctx = tls_cpu_ctx_of(cpu);

	if (cpu_ctx)
		cpu_ctx->last_balance_ns = bpf_ktime_get_ns();
	(void)args;
}

/* ================================================================== */
/* Optional: hints the kernel uses to keep its own bookkeeping sane    */
/* ================================================================== */

/*
 * tls_yield - the running task called sched_yield().
 *
 * WHEN CALLED   When the running task yields. On a CPU with other runnable
 *               tasks the kernel would normally pick the next one, so
 *               returning false is a valid answer.
 * ARGS          p:    the yielding task.
 *               from: the task to yield to, or NULL if it is yielding to
 *                     whatever is next.
 * RETURN        true to tell the kernel to ignore the yield and let this
 *               scheduler keep the task running; false to honour it.
 * DEFAULT       false, i.e. honour the yield, because the scheduler does not
 *               yet know whether the task has any tier left to give.
 * MUST          Returning true when the task cannot make progress causes a
 *               busy loop. Only suppress a yield if you are certain the task
 *               will be preempted by tls_tick().
 * IMPLEMENT     TODO - a lottery scheduler is a poor place to ignore yields;
 *               the tiers already express priority. The interesting case the
 *               document implies is Tier -1: a sanctuary task that yields
 *               should probably keep the CPU until its cycle budget expires,
 *               which is what returning true would express. That needs the
 *               budget from step 7 to be implemented first.
 */
bool BPF_STRUCT_OPS(tls_yield, struct task_struct *p, struct task_struct *from)
{
	(void)p;
	(void)from;
	return false;
}

/*
 * tls_set_weight - the task's nice value changed.
 *
 * WHEN CALLED   When a task's nice value is set, and at attach time for every
 *               task, so that the initial values are applied.
 * ARGS          p:      the task.
 *               weight: the new nice-derived weight in the kernel's own
 *                       0..10000 scale, where 1024 is nice 0. This is NOT a
 *                       ticket count.
 * RETURN        void
 * DEFAULT       Records the last weight for the dump output and otherwise
 *               ignores it, because in the document every task in a tier
 *               holds the same fixed number of tickets.
 * MUST          Do not overwrite the tier weights in cpu_ctx->weights[] from
 *               here: those are per-CPU lane weights shared by every task in
 *               the lane, and changing them per task would corrupt the pool.
 * IMPLEMENT     TODO - decide and document the stance. The document's
 *               architecture is explicit that "every process assigned to a
 *               specific tier holds an equal, predetermined number of
 *               tickets", which makes nice values deliberately irrelevant.
 *               That is a defensible design choice for a thesis and worth
 *               stating as one; the alternative is to scale a task's ticket
 *               contribution by `weight`, which would require the pool
 *               arithmetic to stop being nr * lane_weight.
 */
void BPF_STRUCT_OPS(tls_set_weight, struct task_struct *p, u32 weight)
{
	(void)p;
	(void)weight;
}

/*
 * tls_set_cpumask - the task's CPU affinity changed.
 *
 * WHEN CALLED   When a task's cpumask is changed, and at attach time for
 *               every task.
 * ARGS          p:       the task.
 *               cpumask: the new allowed mask. Readable for the duration of
 *                        the call only; do not store the pointer.
 * RETURN        void
 * DEFAULT       Nothing. The task stays where it is; affinity only constrains
 *               where it may be placed next, and the placement paths respect
 *               it.
 * MUST          If the task is currently linked in a CPU's tier array and the
 *               new mask excludes that CPU, the task will not run until it is
 *               moved. The kernel handles this case for tasks this scheduler
 *               has not dispatched, but a task you moved yourself must be
 *               migrated by you.
 * IMPLEMENT     TODO - the correctness argument for your placement code. If
 *               your tls_wakeup_select_cpu() and stealing paths only ever choose
 *               CPUs from the task's mask, and tls_enqueue() uses
 *               scx_bpf_task_cpu() when SCX_ENQ_CPU_SELECTED is set, then no
 *               action is needed here and this function can stay empty. Say
 *               so explicitly in the code, because an empty cpumask handler
 *               is otherwise indistinguishable from a missing one.
 */
void BPF_STRUCT_OPS(tls_set_cpumask, struct task_struct *p, const struct cpumask *cpumask)
{
	(void)p;
	(void)cpumask;
}

/*
 * tls_update_idle - a CPU entered or left the idle state.
 *
 * WHEN CALLED   When the kernel's notion of a CPU's idleness changes.
 * ARGS          cpu:   the CPU.
 *               idle:  true when it became idle, false when it became busy.
 * RETURN        void
 * DEFAULT       Nothing. The kernel tracks idleness itself and the placement
 *               paths query it through the kernel's idle cpumask helpers, so
 *               a shadow copy would only be a second source of truth to keep
 *               in sync.
 * MUST          If you do maintain a shadow idle set, it must be exact: a
 *               CPU wrongly believed idle will be kicked forever, and one
 *               wrongly believed busy will be under-used.
 * IMPLEMENT     TODO - optional. Only implement this if your placement needs
 *               to avoid a helper call in a hot path. The kernel's
 *               scx_bpf_test_and_clear_cpu_idle() is the accurate primitive
 *               and is usually cheaper than the bookkeeping.
 */
void BPF_STRUCT_OPS(tls_update_idle, s32 cpu, bool idle)
{
	(void)cpu;
	(void)idle;
}

/* ================================================================== */
/* Optional: diagnostics                                               */
/* ================================================================== */
/*
 * The three dump callbacks are invoked by `scxctl dump` / the sysfs dump
 * trigger and by the kernel when the scheduler stops with an error. They run
 * in a context where blocking is allowed, so they may take locks and iterate
 * freely. Their output is the single most useful debugging tool for a
 * scheduler, which is why the bodies below are complete rather than empty:
 * a dump that prints the tier occupancy, the ticket pool and the rotation
 * epoch will tell you more about a misbehaving lottery than any amount of
 * printk.
 */

/*
 * tls_dump_cpu - per-CPU dump, or a header plus every CPU.
 *
 * WHEN CALLED   From tls_dump() with cpu == -1, and per CPU by the kernel
 *               with header == true on the first call.
 * ARGS          dctx:   as above.
 *               cpu:    -1 means "all CPUs, with a header".
 *               header: true on the first call of a group, so that a header
 *                       line is printed once rather than per CPU.
 * RETURN        void
 * DEFAULT       Prints one line per CPU: tier occupancy per lane, the ticket
 *               pool, the load factor, the rotation epoch and the counters.
 *               This is the view that lets you sanity-check that
 *               total_tickets equals the sum of nr * weight after every
 *               operation, which is the single most valuable invariant to
 *               watch while implementing.
 * MUST          Bounded output. Iterating TLS_MAX_CPUS CPUs is fine;
 *               iterating every task in every tier is not, so per-task
 *               detail belongs in tls_dump_task().
 * IMPLEMENT     Complete for the state this skeleton has. Extend it as the
 *               state grows.
 */
/*
 * The three dump callbacks cannot call one another.
 *
 * BPF_STRUCT_OPS() expands to BPF_PROG(), which generates a wrapper taking
 * `unsigned long long *ctx` around a static function. So the name
 * tls_dump_cpu() refers to the ctx-taking wrapper, not to the function
 * with the parameters we want, and a plain call does not compile. Each
 * callback below therefore does its work in a static helper, and the helpers
 * call each other normally.
 */
static void tls_dump_one_cpu(s32 cpu)
{
	struct tls_cpu_ctx *cpu_ctx;

	cpu_ctx = tls_cpu_ctx_of(cpu);
	if (!cpu_ctx)
		return;

	/* Split for the same 12-argument reason as tls_dump(). */
	scx_bpf_dump("cpu %3d: sanctuary=%u anchor=%u high=%u medium=%u "
		     "low=%u background=%u\n",
		     cpu,
		     cpu_ctx->tiers[tls_tier_slot(TIER_SANCTUARY)].nr,
		     cpu_ctx->tiers[tls_tier_slot(TIER_ANCHOR)].nr,
		     cpu_ctx->tiers[tls_tier_slot(TIER_HIGH)].nr,
		     cpu_ctx->tiers[tls_tier_slot(TIER_MEDIUM)].nr,
		     cpu_ctx->tiers[tls_tier_slot(TIER_LOW)].nr,
		     cpu_ctx->tiers[tls_tier_slot(TIER_BACKGROUND)].nr);

	scx_bpf_dump("cpu %3d: tickets=%llu load=%llu epoch=%u "
		     "selections=%llu steals=%llu rotations=%llu\n",
		     cpu,
		     (unsigned long long)cpu_ctx->total_tickets,
		     (unsigned long long)cpu_ctx->load_factor,
		     cpu_ctx->rotation_epoch,
		     (unsigned long long)cpu_ctx->selections,
		     (unsigned long long)cpu_ctx->steals_completed,
		     (unsigned long long)cpu_ctx->rotations);
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

/*
 * tls_dump_task - one task's scheduling state.
 *
 * WHEN CALLED   Per task, from the kernel's dump path, when a task is
 *               involved in a stall or is explicitly requested.
 * ARGS          dctx: as above.
 *               p:    the task. Its storage is readable.
 * RETURN        void
 * DEFAULT       Prints pid, tier, slot, owner CPU and linked flag.
 * MUST          A task with no storage is legal here (a task the scheduler
 *               never took over). The NULL check below handles it.
 * IMPLEMENT     Complete. Add fields if you extend struct tls_task_ctx.
 */
void BPF_STRUCT_OPS(tls_dump_task, struct scx_dump_ctx *dctx, struct task_struct *p)
{
	struct tls_task_ctx *task_ctx;

	if (!p)
		return;

	task_ctx = tls_task_ctx(p);
	if (!task_ctx) {
		scx_bpf_dump("task %d: no tls storage\n", p->pid);
		return;
	}

	scx_bpf_dump("task %d: tier=%d slot=%d cpu=%d linked=%d slice_used=%llu\n",
		     p->pid, task_ctx->tier, task_ctx->slot, task_ctx->cpu,
		     (int)task_ctx->linked,
		     (unsigned long long)task_ctx->slice_used_ns);
	(void)dctx;
}
/*
 * tls_dump - whole-scheduler dump.
 *
 * WHEN CALLED   On demand, and when the scheduler is stopping. Blocking is
 *               allowed.
 * ARGS          dctx: opaque dump context. Pass it straight through to
 *               scx_bpf_dump(); do not inspect it.
 * RETURN        void
 * DEFAULT       Prints the version, the tunables actually in force and the
 *               per-CPU summary line for every CPU.
 * MUST          Output goes to the kernel log. Keep it bounded; the kernel
 *               truncates after exit_dump_len and a truncated dump hides the
 *               end, which is usually the interesting part.
 * IMPLEMENT     Extended as you add state. Anything you add to
 *               struct tls_cpu_ctx should appear here.
 */
void BPF_STRUCT_OPS(tls_dump, struct scx_dump_ctx *dctx)
{
	u32 i;

	/*
	 * scx_bpf_dump() is variadic through the bpf_printk() machinery,
	 * which is capped at 12 arguments. Keep each call well under that
	 * limit; an oversized call is a compile error, not a truncation.
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
