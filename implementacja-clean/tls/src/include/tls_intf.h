/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TLS - Tiered Lottery Scheduler, x86_64
 *
 * Shared interface header: tier geometry, state layouts, tunables.
 * Keep every type here POD; it crosses to userspace through BTF.
 */
#ifndef __TLS_INTF_H
#define __TLS_INTF_H

/* type aliases for host-only builds; the BPF build uses vmlinux.h */
#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif

#include <stdbool.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif

/*
 * tier ids are signed: -1 is the sanctuary lane (strict priority, not
 * in the draw), 0 the anchor, excluded from the rotation with it.
 * TIER_GP_FIRST..TIER_GP_LAST is the range the rotation permutes.
 */
#define TIER_SANCTUARY		(-1)
#define TIER_ANCHOR		 0
#define TIER_HIGH		 1
#define TIER_MEDIUM		 2
#define TIER_LOW		 3
#define TIER_BACKGROUND		 4

#define TIER_GP_FIRST		TIER_HIGH	/* first tier of the rotation */
#define TIER_GP_LAST		TIER_BACKGROUND	/* last tier of the rotation */
#define TLS_NR_GP_TIERS	(TIER_GP_LAST - TIER_GP_FIRST + 1)

/*
 * tier ids run TIER_MIN..TIER_MAX; slot i holds tier i + TIER_MIN, so
 * TIER_SANCTUARY (-1) occupies slot 0.
 */
#define TIER_MIN		TIER_SANCTUARY
#define TIER_MAX		TIER_BACKGROUND
#define TLS_NR_TIERS		(TIER_MAX - TIER_MIN + 1)

/* tier id (-1..4) to slot (0..5), used for every array index */
#define TLS_TIER_SLOT(__tier)	((__tier) - TIER_MIN)

/* tickets granted per task in each tier; -1 and 0 grant none */
#define TLS_TICKETS_ANCHOR		30u
#define TLS_TICKETS_HIGH		20u
#define TLS_TICKETS_MEDIUM		12u
#define TLS_TICKETS_LOW		6u
#define TLS_TICKETS_BACKGROUND	2u

/*
 * max tasks resident in one tier of one CPU. bounds the arrays so the
 * verifier can reason about every index statically. 256 entries of 8
 * bytes is 2 KiB per tier, 12 KiB per CPU.
 */
#define TLS_TIER_CAPACITY	256u

/* per-CPU arrays cover this many CPUs; init() refuses more */
#define TLS_MAX_CPUS		256u

/* reschedule quantum; a selected task is demoted after this long */
#define TLS_SLICE_NS			(10ull * 1000 * 1000)

/* starvation rotation period; tier 4 moves to tier 1 and the other
 * general-purpose tiers shift down one */
#define TLS_ROTATE_NS		(150ull * 1000 * 1000)

/* load-balance period; a core checks neighbours for imbalance */
#define TLS_BALANCE_NS		(100ull * 1000 * 1000)

/* a tier -1 task burning more than this many RDTSC cycles is
 * demoted */
#define TLS_SANCTUARY_BUDGET_CYCLES	(200ull * 1000)

/* kicks at a stuck idle CPU before the scheduler reports it */
#define TLS_MAX_KICK_RETRIES		3u

/* why a task left a tier, recorded per task for accounting */
enum tls_outcome {
	TLS_OUTCOME_NONE = 0,
	TLS_OUTCOME_QUANTUM_EXPIRED,
	TLS_OUTCOME_BLOCKED,
	TLS_OUTCOME_YIELDED,
	TLS_OUTCOME_PREEMPTED,
	TLS_OUTCOME_ROTATED,
	TLS_OUTCOME_STOLEN,
	/* lost the lottery promote_after_losses times in a row */
	TLS_OUTCOME_PROMOTED,
};

enum tls_lane {
	TLS_LANE_LOTTERY	= 0,	/* tiers 0..4, won by the ticket draw */
	TLS_LANE_SANCTUARY	= 1,	/* tier -1, strict priority, no draw */
};

struct tls_task_ctx {
	/* current tier id, -1..4 */
	s32 tier;
	/* index in the owning tier array; -1 when not linked */
	s32 slot;
	/* cpu whose tier array currently owns this task */
	s32 cpu;
	/* true while the task sits in tiers[cpu].tasks[tier]; guards
	 * the unlink path against double removal */
	bool linked;

	/* bpf_ktime_get_ns() when the current slice started */
	u64 slice_start_ns;
	/* per-task xor-shift state, mixed into the entropy */
	u64 prng_state;
	/* consecutive lottery losses, used by the promotion fallback */
	u32 losses;
	/* RDTSC taken when a tier -1 task started running */
	u64 sanctuary_enter_tsc;

	/* accounting, written on tier transitions */
	u32 transitions;
	u32 quantum_expiries;
	u32 promotions;
	u32 demotions;
	u32 rotations_seen;
	u32 steals_won;
	u32 times_selected;
};

struct tls_tier {
	/* dense in [0, nr) */
	struct task_struct *tasks[TLS_TIER_CAPACITY];
	/* live entries in tasks[] */
	u32 nr;
	/* unused under swap-and-pop; kept so a FIFO change would not
	 * reshape the struct */
	u32 head;
	u32 tail;
	/* explicit padding to 8 bytes, keeps the BTF layout stable */
	u32 __pad;
};

struct tls_cpu_ctx {
	/* tier slots, indexed by TLS_TIER_SLOT(tier) */
	struct tls_tier tiers[TLS_NR_TIERS];
	/*
	 * live weight per tier slot; the rotation permutes these values,
	 * so it costs no data movement. the sanctuary and anchor slots stay
	 * zero and are never drawn.
	 */
	u32 weights[TLS_NR_TIERS];
	u32 weights_pad;

	/* cached sum of nr * weights over the lottery tiers; sanctuary and
	 * anchor hold no tickets, so the draw is one load */
	u64 total_tickets;

	/* xorshift64 state, reseeded every rotation; never zero */
	u64 prng_state;

	/* load factor other cores read for placement and stealing */
	u64 load_factor;

	/* spinlock protecting remote (stealing) access to this struct;
	 * declared as u64, the includer supplies the BPF type */
	u64 lock_opaque;

	/* cached anchor slot; swap-and-pop pivot on a demotion append */
	s32 anchor_slot;

	/* cpu this context belongs to; redundant with the map key */
	s32 cpu;

	/* timestamps, BPF clock domain */
	u64 last_rotate_ns;
	u64 last_balance_ns;
	u64 last_slice_start_ns;

	u64 selections;
	u64 draws_with_empty_pool;
	u64 steals_attempted;
	u64 steals_completed;
	u64 rotations;
	u64 sanctuary_entries;
	u64 sanctuary_overruns;		/* Tier -1 budget exceeded */
	u64 kicks;
	u32 rotation_epoch;		/* increments on every rotation */
	u32 __pad0;
};

struct tls_tunables {
	/* must equal TLS_TUNABLES_MAGIC, else the load fails */
	u32 magic;
	/* struct version, bumped when this layout changes */
	u32 version;

	/* base slice in ns; 0 means TLS_SLICE_NS */
	u64 slice_ns;
	/* rotation period in ns; 0 means TLS_ROTATE_NS */
	u64 rotate_ns;
	/* balance period in ns; 0 means TLS_BALANCE_NS */
	u64 balance_ns;
	/* sanctuary RDTSC budget in cycles; 0 means the default */
	u64 sanctuary_budget_cycles;

	/* consecutive losses before promotion; 0 disables the fallback */
	u32 promote_after_losses;
	/* steal when victim_load * num > thief_load * den; both must be
	 * non-zero or balancing is skipped */
	u32 balance_ratio_num;
	u32 balance_ratio_den;

	/* 0 quiet, 1 lifecycle, 2 per-draw trace (expensive) */
	u32 verbose;
	/* run the rotation backwards, for A/B benchmarks */
	bool rotate_reverse;
	/* warn instead of erroring when a tier overflows */
	bool soft_overflow;
	/* pad to a multiple of 8 bytes */
	u8 __pad[2];
};

#define TLS_TUNABLES_MAGIC	0x54534C78u	/* "TSLx" */
#define TLS_TUNABLES_VERSION	1u

/*
 * tier arrays live in struct tls_cpu_ctx, the value type of an array
 * map with TLS_MAX_CPUS entries: about 3 MiB of scheduler memory.
 */
#define TLS_CPU_CTX_BYTES \
	((u64)sizeof(struct tls_cpu_ctx) * TLS_MAX_CPUS)

#endif /* __TLS_INTF_H */
