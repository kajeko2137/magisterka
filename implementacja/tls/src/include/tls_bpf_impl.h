/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TLS - tier array maintenance helpers.
 *
 * Included by src/bpf/main.bpf.c after tls_core.bpf.h. Depends on the
 * maps declared there (tls_this_cpu_ctx, tls_task_ctx, tls_stats).
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE IS, AND IS NOT
 * ---------------------------------------------------------------------------
 * These functions are *mechanism*, not *policy*. They keep the per-CPU tier
 * arrays self-consistent and enforce the invariants the verifier cannot
 * check. They contain no scheduling decisions: nothing here chooses a tier,
 * decides when to demote, or draws a ticket. Every such decision lives in
 * src/bpf/tls_stubs.bpf.c.
 *
 * You should not need to edit this file to implement TLS. If you find
 * yourself wanting to, that is a signal the interface between mechanism and
 * policy is wrong - say so rather than reaching in.
 *
 * ---------------------------------------------------------------------------
 * THE MECHANISM / POLICY BOUNDARY - enforced, please keep it
 * ---------------------------------------------------------------------------
 * Every function in this file does exactly one of:
 *
 *   - translate between a tier id and its array slot,
 *   - link or unlink a task in a per-CPU tier array (swap-and-pop),
 *   - set or clear the single-slot Tier -1 sanctuary lane,
 *   - recompute a derived counter (total_tickets, load_factor),
 *   - report occupancy.
 *
 * None of them decides anything. Concretely, and by design, this file
 * contains no function that:
 *
 *   - draws a winning ticket or scales PRNG output,
 *   - chooses which tier a task belongs in,
 *   - decides whether a quantum has expired or a task should be demoted,
 *   - performs the starvation rotation,
 *   - selects a victim core for stealing,
 *   - applies a TIER_SANCTUARY RDTSC budget.
 *
 * Those are the TLS algorithm and they belong in
 * src/bpf/tls_stubs.bpf.c. tls_weight_table_init() below copies the
 * *document's* weights into live state; it does not decide them.
 *
 * If a future change to this file starts making decisions, the split has
 * been lost and the algorithm is no longer in one place.
 *
 * ---------------------------------------------------------------------------
 * THE INVARIANTS THESE FUNCTIONS MAINTAIN
 * ---------------------------------------------------------------------------
 * For every (cpu, tier_id):
 *
 *   I1. tiers[slot].nr <= TLS_TIER_CAPACITY
 *   I2. tiers[slot].tasks[0 .. nr) are non-NULL and densely packed
 *   I3. for each i in [0, nr): task_ctx(tasks[i])->slot == i
 *                             && task_ctx(tasks[i])->tier == tier_id
 *                             && task_ctx(tasks[i])->cpu  == cpu
 *                             && task_ctx(tasks[i])->linked == true
 *   I4. a task appears in at most one (cpu, tier_id) array across the whole
 *       machine
 *   I5. tier_id == TIER_SANCTUARY is never used with the array push/remove
 *       helpers; the sanctuary lane is strict-priority and holds at most
 *       one task, managed by tls_sanctuary_enter() / tls_sanctuary_clear()
 *       (and cleaned up by tls_unlink())
 *
 * A task that is not linked into any tier (task_ctx->linked == false) is
 * either running, on a DSQ awaiting dispatch, or being migrated. That is a
 * legal state; it is not an error, and the helpers below tolerate it.
 *
 * ---------------------------------------------------------------------------
 * O(1) GUARANTEE
 * ---------------------------------------------------------------------------
 * The architecture document specifies swap-and-pop for every removal so
 * that demotion and stealing are O(1). tls_tier_remove_at() implements
 * exactly that: the removed slot is overwritten by the last element and nr
 * is decremented, repairing the moved element's slot index in O(1) so
 * tls_tier_remove_task() never needs to scan the array.
 */

#ifndef __TLS_BPF_IMPL_H
#define __TLS_BPF_IMPL_H

#include "tls_intf.h"

/* ------------------------------------------------------------------ */
/* Tier id validation                                                   */
/* ------------------------------------------------------------------ */

/*
 * Is this a tier id the kernel may hand us or that policy may compute?
 * Guards against a corrupted task_ctx->tier turning into an out-of-bounds
 * map index, which the verifier would otherwise have to reject the whole
 * program over.
 */
static __always_inline bool tls_tier_valid(s32 tier_id)
{
	return tier_id >= TIER_MIN && tier_id <= TIER_MAX;
}

/*
 * Convert a tier id to its slot in struct tls_cpu_ctx.tiers.
 * Only call with a value for which tls_tier_valid() is true.
 */
static __always_inline u32 tls_tier_slot(s32 tier_id)
{
	return (u32)(tier_id - TIER_MIN);
}

/* ------------------------------------------------------------------ */
/* Forward declarations                                                 */
/* ------------------------------------------------------------------ */
/*
 * Defined below, but called by helpers earlier in this file, so C needs to
 * have seen them. Their definitions stay next to their explanations rather
 * than being moved up: the ordering requirement is a compile detail, not a
 * design one.
 */
static __always_inline void tls_recount_tickets(struct tls_cpu_ctx *cpu_ctx);
static __always_inline void tls_update_load_factor(struct tls_cpu_ctx *cpu_ctx);
static __always_inline struct task_struct *
tls_sanctuary_task(struct tls_cpu_ctx *cpu_ctx);
static __always_inline bool tls_sanctuary_clear(struct tls_cpu_ctx *cpu_ctx);

/*
 * Tickets one task contributes at a given tier. Tier -1 (sanctuary)
 * contributes zero because it bypasses the lottery. Tier 0 (anchor)
 * contributes TLS_TICKETS_ANCHOR (30) and is included in the lottery pool
 * while staying excluded from starvation rotation.
 */
static __always_inline u64 tls_tickets_for(s32 tier_id)
{
	switch (tier_id) {
	case TIER_ANCHOR:
		return TLS_TICKETS_ANCHOR;
	case TIER_HIGH:
		return TLS_TICKETS_HIGH;
	case TIER_MEDIUM:
		return TLS_TICKETS_MEDIUM;
	case TIER_LOW:
		return TLS_TICKETS_LOW;
	case TIER_BACKGROUND:
		return TLS_TICKETS_BACKGROUND;
	case TIER_SANCTUARY:
	default:
		return 0;
	}
}

/*
 * Tickets contributed by all tasks currently in one tier of one CPU.
 *
 * Reads cpu_ctx->weights[], not the compile-time table, because the live
 * weights are what the starvation rotation permutes for Tiers 1..4. Zero for
 * Tier -1 (sanctuary) by construction of tls_weight_table_init().
 */
static __always_inline u64 tls_tickets_of_tier(struct tls_cpu_ctx *cpu_ctx,
						  s32 tier_id)
{
	u32 slot;

	if (!cpu_ctx || !tls_tier_valid(tier_id))
		return 0;
	slot = tls_tier_slot(tier_id);
	return (u64)cpu_ctx->tiers[slot].nr * (u64)cpu_ctx->weights[slot];
}

/*
 * Fill cpu_ctx->weights[] with the architecture document's base weights for
 * one rotation epoch. Called once per CPU from tls_init().
 *
 * Tier -1 gets zero (bypasses the lottery); Tier 0 gets 30 and stays fixed
 * across rotations.
 *
 * NOTE for the implementer: cpu_ctx->weights[] is live state, not a constant
 * table. It exists so that the 150 ms starvation rotation can be applied by
 * permuting four u32 values instead of relocating task pointers, which is
 * what makes the rotation O(1) and free of per-task bookkeeping. The
 * rotation itself is policy and therefore lives in tls_stubs.bpf.c; see
 * the TODO on tls_tick().
 */
static __always_inline void tls_weight_table_init(struct tls_cpu_ctx *cpu_ctx)
{
	s32 tier_id;

	if (!cpu_ctx)
		return;

	for (tier_id = TIER_MIN; tier_id <= TIER_MAX; tier_id++)
		cpu_ctx->weights[tls_tier_slot(tier_id)] =
			(u32)tls_tickets_for(tier_id);

	cpu_ctx->weights_pad = 0;
	tls_recount_tickets(cpu_ctx);
}

/* ------------------------------------------------------------------ */
/* Total ticket pool                                                    */
/* ------------------------------------------------------------------ */

/*
 * Recompute cpu_ctx->total_tickets from the live occupancy of the lottery
 * tiers (Tiers 0..4).
 *
 * This is the architecture document's
 *
 *     Total Tickets = (T0 x 30) + (T1 x 20) + (T2 x 12) + (T3 x 6) + (T4 x 2)
 *
 * (section 2, step 1), with the weights read from the live cpu_ctx->weights[]
 * table so that the starvation rotation is picked up automatically.
 *
 * Written as a bounded loop rather than a hand-unrolled expression so that
 * changing the tier geometry in tls_intf.h cannot silently desynchronise
 * it. Recomputing rather than applying an incremental delta is deliberate: an
 * incremental update is one missed subtraction away from a pool size that
 * drifts without bound, and the draw is O(1) either way. Five lottery tiers
 * (0..4) cost five multiply-adds.
 *
 * The loop bound is a compile-time constant, which is what the verifier
 * requires in order to prove termination.
 */
static __always_inline void tls_recount_tickets(struct tls_cpu_ctx *cpu_ctx)
{
	u64 total = 0;
	s32 tier_id;

	if (!cpu_ctx)
		return;

	/*
	 * A plain bounded loop rather than bpf_for(). The bounds are
	 * constants, which is all the verifier needs, and this form has no
	 * dependency on the open-coded iterator kfuncs - one fewer kernel
	 * feature to rely on, at no measurable cost for a bound of five.
	 */
	for (tier_id = TIER_ANCHOR; tier_id <= TIER_MAX; tier_id++) {
		total += tls_tickets_of_tier(cpu_ctx, tier_id);
	}

	cpu_ctx->total_tickets = total;
}

/* ------------------------------------------------------------------ */
/* Load factor                                                          */
/* ------------------------------------------------------------------ */

/*
 * Recompute the atomic load factor other cores read during passive
 * placement and work stealing.
 *
 * Mirrors cpu_ctx->total_tickets (the sum of all live tickets on this CPU).
 *
 * The store is a plain u64. It is read by other cores without a lock. A torn
 * read is impossible on x86_64 for an aligned u64, and a stale read costs at
 * most one suboptimal placement.
 */
static __always_inline void tls_update_load_factor(struct tls_cpu_ctx *cpu_ctx)
{
	if (!cpu_ctx)
		return;

	cpu_ctx->load_factor = cpu_ctx->total_tickets;
}

/* ------------------------------------------------------------------ */
/* Push                                                                 */
/* ------------------------------------------------------------------ */

/*
 * Append a task to (cpu_ctx, tier_id). Does not modify the task's context
 * beyond the bookkeeping fields it owns; the caller is responsible for
 * setting task_ctx->tier before calling (or for letting this function do it,
 * which is the usual case).
 *
 * Returns:
 *   0   on success, task linked and task_ctx updated
 *  -1   if cpu_ctx is NULL, the tier is invalid, or the tier is the sanctuary
 *       lane (use tls_sanctuary_enter() instead)
 *  -2   if the tier is at TLS_TIER_CAPACITY and soft_overflow is off
 *
 * On -2 with soft_overflow on, the task is not linked and the caller must
 * put it somewhere else. Dropping a task on the floor is never acceptable:
 * an unqueued runnable task is a hang, which the kernel reports as
 * SCX_EXIT_ERROR_STALL. See tls_stubs.bpf.c:tls_enqueue() for the
 * fallback the default implementation uses.
 */
static __always_inline int tls_tier_push(struct tls_cpu_ctx *cpu_ctx,
					 s32 tier_id, struct task_struct *p)
{
	struct tls_task_ctx *task_ctx;
	struct tls_tier *tier;
	u32 slot, idx;

	if (!cpu_ctx || !p || !tls_tier_valid(tier_id) ||
	    tier_id == TIER_SANCTUARY)
		return -1;

	slot = tls_tier_slot(tier_id);
	tier = &cpu_ctx->tiers[slot];

	if (tier->nr >= TLS_TIER_CAPACITY) {
		/*
		 * The tier is full. Bump the counter before returning so that
		 * `tls stats` shows the pressure even when the caller
		 * silently reroutes the task.
		 */
		tls_stat_inc(TLS_STAT_TIER_OVERFLOWS);
		if (!tls_tunables.soft_overflow)
			return -2;
		/* soft_overflow: fall through and report failure anyway;
		 * the caller decides where the task goes. */
		return -2;
	}

	idx = tier->nr;
	tier->tasks[idx] = p;
	tier->nr = idx + 1;

	task_ctx = tls_task_ctx(p);
	if (task_ctx) {
		task_ctx->tier = tier_id;
		task_ctx->slot = (s32)idx;
		task_ctx->cpu = cpu_ctx->cpu;
		task_ctx->linked = true;
	}

	tls_recount_tickets(cpu_ctx);
	tls_update_load_factor(cpu_ctx);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Remove                                                               */
/* ------------------------------------------------------------------ */

/*
 * Swap-and-pop the entry at `idx` out of (cpu_ctx, tier_id).
 *
 * This is the O(1) removal the architecture document specifies: the last
 * element fills the hole left by the removed one and nr shrinks. Only the
 * element that moved needs its task_ctx->slot repaired.
 *
 * `idx` must satisfy idx < nr; the check is kept because a stale slot index
 * is the most likely bug in this scheduler and an out-of-bounds access here
 * would be rejected by the verifier with an unhelpful message.
 */
static __always_inline void tls_tier_remove_at(struct tls_cpu_ctx *cpu_ctx,
					       s32 tier_id, u32 idx)
{
	struct tls_task_ctx *moved;
	struct tls_tier *tier;
	struct task_struct *last;
	u32 slot, last_idx;

	if (!cpu_ctx || !tls_tier_valid(tier_id) || tier_id == TIER_SANCTUARY)
		return;

	slot = tls_tier_slot(tier_id);
	tier = &cpu_ctx->tiers[slot];

	if (idx >= tier->nr || tier->nr == 0)
		return;

	last_idx = tier->nr - 1;
	last = tier->tasks[last_idx];

	tier->tasks[idx] = last;
	tier->tasks[last_idx] = NULL;
	tier->nr = last_idx;

	/*
	 * Repair the moved element's back-pointer. If idx == last_idx the
	 * element that moved is the one we just removed, so there is nothing
	 * to repair.
	 */
	if (idx != last_idx && last) {
		moved = tls_task_ctx(last);
		if (moved)
			moved->slot = (s32)idx;
	}

	tls_recount_tickets(cpu_ctx);
	tls_update_load_factor(cpu_ctx);
}

/*
 * Remove a specific task from (cpu_ctx, tier_id) in O(1) using task_ctx->slot.
 *
 * task_ctx->slot is authoritative because tls_tier_remove_at() repairs it on
 * every swap-and-pop. Returns true if the task was found at task_ctx->slot and
 * unlinked; false if task_ctx->slot does not match `p`.
 */
static __always_inline bool tls_tier_remove_task(struct tls_cpu_ctx *cpu_ctx,
						 s32 tier_id,
						 struct task_struct *p)
{
	struct tls_task_ctx *task_ctx;
	struct tls_tier *tier;
	u32 slot;

	if (!cpu_ctx || !p || !tls_tier_valid(tier_id) ||
	    tier_id == TIER_SANCTUARY)
		return false;

	slot = tls_tier_slot(tier_id);
	tier = &cpu_ctx->tiers[slot];

	task_ctx = tls_task_ctx(p);
	if (task_ctx && task_ctx->slot >= 0 && (u32)task_ctx->slot < tier->nr &&
	    tier->tasks[task_ctx->slot] == p) {
		tls_tier_remove_at(cpu_ctx, tier_id, (u32)task_ctx->slot);
		task_ctx->linked = false;
		task_ctx->slot = -1;
		task_ctx->cpu = -1;
		return true;
	}

	return false;
}

/* ------------------------------------------------------------------ */
/* Unlink from wherever the task currently is                           */
/* ------------------------------------------------------------------ */

/*
 * Detach a task from whatever tier array (or sanctuary slot) currently holds
 * it, using only the task's own context. This is what the lifecycle callbacks
 * (stopping, disable, exit_task, cpu_offline) call, because they are handed
 * a task and must not have to guess which CPU owns it.
 *
 * Returns true if the task was linked and has now been unlinked. A false
 * return is not an error: it means the task was already detached, which is
 * the case for a task that is running or parked on a DSQ.
 *
 * Steps: locate the owning CPU's context, verify the task really is in that
 * tier, then unlink or swap-and-pop it.
 */
static __always_inline bool tls_unlink(struct task_struct *p)
{
	struct tls_task_ctx *task_ctx;
	struct tls_cpu_ctx *cpu_ctx;

	if (!p)
		return false;

	task_ctx = tls_task_ctx(p);
	if (!task_ctx || !task_ctx->linked)
		return false;

	/*
	 * task_ctx->cpu is the owning CPU. It can legitimately be stale if the
	 * task was migrated without the scheduler noticing, so treat a
	 * lookup failure as "already detached" rather than an error.
	 */
	cpu_ctx = tls_cpu_ctx_of(task_ctx->cpu);
	if (!cpu_ctx) {
		task_ctx->linked = false;
		task_ctx->slot = -1;
		return false;
	}

	if (!tls_tier_valid(task_ctx->tier)) {
		task_ctx->linked = false;
		task_ctx->slot = -1;
		return false;
	}

	if (task_ctx->tier == TIER_SANCTUARY) {
		if (tls_sanctuary_task(cpu_ctx) == p)
			return tls_sanctuary_clear(cpu_ctx);
		task_ctx->linked = false;
		task_ctx->slot = -1;
		return false;
	}

	return tls_tier_remove_task(cpu_ctx, task_ctx->tier, p);
}

/* ------------------------------------------------------------------ */
/* Occupancy queries used by placement and stealing                     */
/* ------------------------------------------------------------------ */

/*
 * Number of tasks in (cpu, tier_id), or 0 if the CPU or tier is invalid. Safe
 * to call on a remote CPU: it reads a single u32 that is only mutated under
 * that CPU's lock, and a stale value costs at most one suboptimal placement
 * or steal.
 */
static __always_inline u32 tls_tier_nr(s32 cpu, s32 tier_id)
{
	struct tls_cpu_ctx *cpu_ctx;

	if (!tls_tier_valid(tier_id) || tier_id == TIER_SANCTUARY)
		return 0;

	cpu_ctx = tls_cpu_ctx_of(cpu);
	if (!cpu_ctx)
		return 0;

	return cpu_ctx->tiers[tls_tier_slot(tier_id)].nr;
}

/* Total tasks parked in the lottery tiers (Tiers 0..4) of a CPU. */
static __always_inline u32 tls_cpu_nr_queued(s32 cpu)
{
	struct tls_cpu_ctx *cpu_ctx;
	u32 total = 0;
	s32 tier_id;

	cpu_ctx = tls_cpu_ctx_of(cpu);
	if (!cpu_ctx)
		return 0;

	for (tier_id = TIER_ANCHOR; tier_id <= TIER_MAX; tier_id++) {
		total += cpu_ctx->tiers[tls_tier_slot(tier_id)].nr;
	}

	return total;
}

/*
 * Is the sanctuary lane occupied on this CPU? The sanctuary lane is
 * strict-priority, so this is the predicate the enqueue path consults to
 * decide whether a normal task may be admitted at all.
 *
 * The sanctuary holds at most one task, tracked in tiers[slot].tasks[0];
 * nr is therefore 0 or 1 and is the whole answer.
 */
static __always_inline bool tls_sanctuary_busy(struct tls_cpu_ctx *cpu_ctx)
{
	if (!cpu_ctx)
		return false;
	return cpu_ctx->tiers[tls_tier_slot(TIER_SANCTUARY)].nr != 0;
}

/* The sanctuary occupant, or NULL. */
static __always_inline struct task_struct *
tls_sanctuary_task(struct tls_cpu_ctx *cpu_ctx)
{
	if (!cpu_ctx || cpu_ctx->tiers[tls_tier_slot(TIER_SANCTUARY)].nr == 0)
		return NULL;
	return cpu_ctx->tiers[tls_tier_slot(TIER_SANCTUARY)].tasks[0];
}

/*
 * Admit `p` into this CPU's sanctuary lane (Tier -1). Holds at most one task.
 *
 * Returns:
 *   0   on success, task linked into tiers[slot(TIER_SANCTUARY)].tasks[0]
 *  -1   if cpu_ctx or p is NULL
 *  -2   if the sanctuary lane is already occupied
 */
static __always_inline int tls_sanctuary_enter(struct tls_cpu_ctx *cpu_ctx,
					       struct task_struct *p)
{
	struct tls_task_ctx *task_ctx;
	struct tls_tier *tier;

	if (!cpu_ctx || !p)
		return -1;

	tier = &cpu_ctx->tiers[tls_tier_slot(TIER_SANCTUARY)];
	if (tier->nr != 0)
		return -2;

	tier->tasks[0] = p;
	tier->nr = 1;

	task_ctx = tls_task_ctx(p);
	if (task_ctx) {
		task_ctx->tier = TIER_SANCTUARY;
		task_ctx->slot = 0;
		task_ctx->cpu = cpu_ctx->cpu;
		task_ctx->linked = true;
	}

	cpu_ctx->sanctuary_entries++;
	tls_stat_inc(TLS_STAT_SANCTUARY_ENTRIES);
	tls_update_load_factor(cpu_ctx);
	return 0;
}

/*
 * Remove the current occupant (if any) from this CPU's sanctuary lane.
 * Preserves task_ctx->tier so the caller decides whether the task stays Tier -1
 * (normal block/yield) or drops to TIER_ANCHOR (budget overrun).
 *
 * Returns true if an occupant was cleared, false if the lane was already empty.
 */
static __always_inline bool tls_sanctuary_clear(struct tls_cpu_ctx *cpu_ctx)
{
	struct tls_task_ctx *task_ctx;
	struct tls_tier *tier;
	struct task_struct *p;

	if (!cpu_ctx)
		return false;

	tier = &cpu_ctx->tiers[tls_tier_slot(TIER_SANCTUARY)];
	if (tier->nr == 0)
		return false;

	p = tier->tasks[0];
	tier->tasks[0] = NULL;
	tier->nr = 0;

	if (p) {
		task_ctx = tls_task_ctx(p);
		if (task_ctx) {
			task_ctx->linked = false;
			task_ctx->slot = -1;
			task_ctx->cpu = -1;
		}
	}

	tls_update_load_factor(cpu_ctx);
	return true;
}

#endif /* __TLS_BPF_IMPL_H */
