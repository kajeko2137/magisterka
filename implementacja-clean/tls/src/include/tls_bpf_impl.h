/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TLS - tier array maintenance helpers.
 *
 * Included by src/bpf/main.bpf.c after tls_core.bpf.h.
 */

#ifndef __TLS_BPF_IMPL_H
#define __TLS_BPF_IMPL_H

#include "tls_intf.h"

/*
 * invariant: for a linked task, tc->slot indexes it in
 * tiers[tc->cpu].tasks[tc->tier], and a task sits in at most one
 * tier array machine-wide. unlinked means running, on a DSQ or
 * migrating.
 */

/* rejects a corrupted tc->tier before it becomes a bad array index */
static __always_inline bool tls_tier_valid(s32 tier)
{
	return tier >= TIER_MIN && tier <= TIER_MAX;
}

/* checked slot conversion; only call after tls_tier_valid() */
static __always_inline u32 tls_tier_slot(s32 tier)
{
	return (u32)(tier - TIER_MIN);
}

/* defined below, but called by tls_weight_table_init() above */
static __always_inline void tls_recount_tickets(struct tls_cpu_ctx *cc);
static __always_inline void tls_update_load_factor(struct tls_cpu_ctx *cc);

/* tickets one task contributes at this tier; -1 and 0 give none */
static __always_inline u64 tls_tickets_for(s32 tier)
{
	switch (tier) {
	case TIER_HIGH:
		return TLS_TICKETS_HIGH;
	case TIER_MEDIUM:
		return TLS_TICKETS_MEDIUM;
	case TIER_LOW:
		return TLS_TICKETS_LOW;
	case TIER_BACKGROUND:
		return TLS_TICKETS_BACKGROUND;
	case TIER_ANCHOR:
	case TIER_SANCTUARY:
	default:
		return 0;
	}
}

/* tickets held by every task in one tier; reads the live weights,
 * which the rotation permutes */
static __always_inline u64 tls_tickets_of_tier(struct tls_cpu_ctx *cc,
						  s32 tier)
{
	u32 slot;

	if (!cc || !tls_tier_valid(tier))
		return 0;
	slot = tls_tier_slot(tier);
	return (u64)cc->tiers[slot].nr * (u64)cc->weights[slot];
}

/* fill cc->weights[] with the base weights for one rotation epoch */
static __always_inline void tls_weight_table_init(struct tls_cpu_ctx *cc)
{
	s32 tier;

	if (!cc)
		return;

	for (tier = TIER_MIN; tier <= TIER_MAX; tier++)
		cc->weights[tls_tier_slot(tier)] =
			(u32)tls_tickets_for(tier);

	cc->weights_pad = 0;
	tls_recount_tickets(cc);
}

/* recompute total_tickets from live occupancy of the lottery tiers.
 * a full recount rather than a delta, so the pool cannot drift;
 * the loop bound is a compile-time constant the verifier can see. */
static __always_inline void tls_recount_tickets(struct tls_cpu_ctx *cc)
{
	u64 total = 0;
	s32 tier;

	if (!cc)
		return;

	for (tier = TIER_GP_FIRST; tier <= TIER_GP_LAST; tier++) {
		total += tls_tickets_of_tier(cc, tier);
	}

	cc->total_tickets = total;
}

/* load factor other cores read during placement and stealing: tiers 3
 * and 4, plus one unit if the sanctuary lane is occupied. no lock;
 * a stale read costs at most one suboptimal placement. */
static __always_inline void tls_update_load_factor(struct tls_cpu_ctx *cc)
{
	if (!cc)
		return;

	cc->load_factor =
		(u64)cc->tiers[tls_tier_slot(TIER_LOW)].nr +
		(u64)cc->tiers[tls_tier_slot(TIER_BACKGROUND)].nr +
		/* the sanctuary lane, worth one unit when occupied */
		(u64)(cc->tiers[tls_tier_slot(TIER_SANCTUARY)].nr != 0);
}

/* append p to (cc, tier) and point its ctx at this cpu. returns -1 on
 * a bad argument or the sanctuary lane, -2 when the tier is full */
static __always_inline int tls_tier_push(struct tls_cpu_ctx *cc, s32 tier,
					    struct task_struct *p)
{
	struct tls_task_ctx *tc;
	struct tls_tier *t;
	u32 slot, idx;

	if (!cc || !p || !tls_tier_valid(tier) || tier == TIER_SANCTUARY)
		return -1;

	slot = tls_tier_slot(tier);
	t = &cc->tiers[slot];

	if (t->nr >= TLS_TIER_CAPACITY) {
		/* count the overflow even if the caller reroutes the task */
		tls_stat_inc(TLS_STAT_TIER_OVERFLOWS);
		if (!tls_tunables.soft_overflow)
			return -2;
		/* soft_overflow still reports the failure to the caller */
		return -2;
	}

	idx = t->nr;
	t->tasks[idx] = p;
	t->nr = idx + 1;

	tc = tls_task_ctx(p);
	if (tc) {
		tc->tier = tier;
		tc->slot = (s32)idx;
		tc->cpu = cc->cpu;
		tc->linked = true;
	}

	tls_recount_tickets(cc);
	tls_update_load_factor(cc);
	return 0;
}

/* swap-and-pop the entry at idx: the last entry fills the hole and nr
 * shrinks, so only the moved entry needs its back-pointer repaired.
 * idx must be < nr. */
static __always_inline void tls_tier_remove_at(struct tls_cpu_ctx *cc,
						  s32 tier, u32 idx)
{
	struct tls_task_ctx *moved;
	struct tls_tier *t;
	struct task_struct *last;
	u32 slot, last_idx;

	if (!cc || !tls_tier_valid(tier) || tier == TIER_SANCTUARY)
		return;

	slot = tls_tier_slot(tier);
	t = &cc->tiers[slot];

	if (idx >= t->nr || t->nr == 0)
		return;

	last_idx = t->nr - 1;
	last = t->tasks[last_idx];

	t->tasks[idx] = last;
	t->tasks[last_idx] = NULL;
	t->nr = last_idx;

	/* nothing to repair when the last entry was the one removed */
	if (idx != last_idx && last) {
		moved = tls_task_ctx(last);
		if (moved)
			moved->slot = (s32)idx;
	}

	tls_recount_tickets(cc);
	tls_update_load_factor(cc);
}

/* remove p by slot; falls back to a bounded scan when tc->slot is
 * stale. returns true if the task was found and unlinked. */
static __always_inline bool tls_tier_remove_task(struct tls_cpu_ctx *cc,
						    s32 tier,
						    struct task_struct *p)
{
	struct tls_task_ctx *tc;
	struct tls_tier *t;
	u32 slot, i;

	if (!cc || !p || !tls_tier_valid(tier) || tier == TIER_SANCTUARY)
		return false;

	slot = tls_tier_slot(tier);
	t = &cc->tiers[slot];

	tc = tls_task_ctx(p);
	if (tc && tc->slot >= 0 && (u32)tc->slot < t->nr &&
	    t->tasks[tc->slot] == p) {
		tls_tier_remove_at(cc, tier, (u32)tc->slot);
		if (tc)
			tc->linked = false;
		return true;
	}

	/* Slow path: find the task by scan. */
	for (i = 0; i < TLS_TIER_CAPACITY; i++) {
		if (i >= t->nr)
			break;
		if (t->tasks[i] == p) {
			tls_tier_remove_at(cc, tier, i);
			if (tc)
				tc->linked = false;
			return true;
		}
	}

	return false;
}

/* detach p from whichever tier array holds it, using only its own ctx;
 * the lifecycle callbacks get a task, not a cpu. false means it was
 * already detached, not an error. */
static __always_inline bool tls_unlink(struct task_struct *p)
{
	struct tls_task_ctx *tc;
	struct tls_cpu_ctx *cc;

	if (!p)
		return false;

	tc = tls_task_ctx(p);
	if (!tc || !tc->linked)
		return false;

	/* tc->cpu can be stale after a migration the scheduler did not
	 * see; a failed lookup means already detached */
	cc = tls_cpu_ctx_of(tc->cpu);
	if (!cc) {
		tc->linked = false;
		tc->slot = -1;
		return false;
	}

	if (!tls_tier_valid(tc->tier)) {
		tc->linked = false;
		tc->slot = -1;
		return false;
	}

	return tls_tier_remove_task(cc, tc->tier, p);
}

/* tasks in (cpu, tier); safe on a remote cpu, where a stale count
 * costs at most one suboptimal placement or steal */
static __always_inline u32 tls_tier_nr(s32 cpu, s32 tier)
{
	struct tls_cpu_ctx *cc;

	if (!tls_tier_valid(tier) || tier == TIER_SANCTUARY)
		return 0;

	cc = tls_cpu_ctx_of(cpu);
	if (!cc)
		return 0;

	return cc->tiers[tls_tier_slot(tier)].nr;
}

/* total tasks in the lottery tiers of one cpu */
static __always_inline u32 tls_cpu_nr_queued(s32 cpu)
{
	struct tls_cpu_ctx *cc;
	u32 total = 0;
	s32 tier;

	cc = tls_cpu_ctx_of(cpu);
	if (!cc)
		return 0;

	for (tier = TIER_GP_FIRST; tier <= TIER_GP_LAST; tier++) {
		total += cc->tiers[tls_tier_slot(tier)].nr;
	}

	return total;
}

/* the sanctuary lane is strict priority and holds at most one task, so
 * nr is 0 or 1; the enqueue path uses this to admit or refuse work */
static __always_inline bool tls_sanctuary_busy(struct tls_cpu_ctx *cc)
{
	if (!cc)
		return false;
	return cc->tiers[tls_tier_slot(TIER_SANCTUARY)].nr != 0;
}

/* the sanctuary occupant, or NULL */
static __always_inline struct task_struct *
tls_sanctuary_task(struct tls_cpu_ctx *cc)
{
	if (!cc || cc->tiers[tls_tier_slot(TIER_SANCTUARY)].nr == 0)
		return NULL;
	return cc->tiers[tls_tier_slot(TIER_SANCTUARY)].tasks[0];
}

#endif /* __TLS_BPF_IMPL_H */
