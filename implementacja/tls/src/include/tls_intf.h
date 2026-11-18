/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TLS - Tiered Lottery Scheduler, x86_64
 *
 * Shared interface header: tier geometry, ticket weights, per-task and
 * per-CPU state layouts, and the tunables block that the userspace loader
 * writes into .rodata before the scheduler attaches.
 *
 * This header is deliberately freestanding. It is included by the BPF
 * program (src/bpf/main.bpf.c) and, after the BPF build, by the userspace
 * loader through the generated BTF so that the two sides cannot drift.
 *
 * ---------------------------------------------------------------------------
 * LAYOUT RULES - read before editing
 * ---------------------------------------------------------------------------
 *  1. Everything in this file is shared with the kernel through BTF. Do not
 *     use pointers into userspace, bitfields, or types whose size differs
 *     between BPF and the host compiler.
 *  2. `struct tls_tunables` is the ONLY struct the userspace loader is
 *     allowed to write. It lives in the .rodata map and must stay
 *     POD-only. Adding a field here is a change the loader must mirror in
 *     userspace/tls.c (see TUNABLES_* macros there).
 *  3. Tier indices below are signed: TIER_SANCTUARY is -1. Do not index an
 *     array with a raw tier id; use tls_tier_slot() from the BPF side.
 */
#ifndef __TLS_INTF_H
#define __TLS_INTF_H

/* ------------------------------------------------------------------ */
/* Kernel type aliases for host-only builds (unit tests, tooling).     */
/* The BPF build gets the real definitions from vmlinux.h.             */
/* ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------ */
/* Tier geometry                                                       */
/* ------------------------------------------------------------------ */
/*
 * Tier ids are the architecture's own numbering and are signed:
 *
 *   -1  Sanctuary    strict-priority I/O bottom-half lane; not a lottery
 *                    participant, bounded by a 1 ms execution budget.
 *    0  Anchor       30 tickets. Landing zone for new tasks and deferred
 *                    I/O. Structurally excluded from starvation rotation.
 *    1  High         20 tickets. Interactive / low-latency.
 *    2  Medium       12 tickets. Standard interactive and intermediate work.
 *    3  Low           6 tickets. Throughput-oriented compute.
 *    4  Background    2 tickets. Bulk background workers.
 *
 * TIER_GP_FIRST / TIER_GP_LAST bound the "general-purpose" tiers: the
 * contiguous range the starvation rotation permutes. Tiers -1 and 0 are
 * locked and must never be moved into or out of it.
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
 * Number of lottery slots. Slot i holds the state of tier id
 * (i + TIER_MIN). TIER_MIN is the most negative tier id.
 */
#define TIER_MIN		TIER_SANCTUARY
#define TIER_MAX		TIER_BACKGROUND
#define TLS_NR_TIERS		(TIER_MAX - TIER_MIN + 1)

/*
 * Translate a tier id (-1..4) into an array slot (0..5).
 * Used by the BPF side for every map lookup and array index.
 */
#define TLS_TIER_SLOT(__tier)	((__tier) - TIER_MIN)

/*
 * Tickets granted per task, indexed by tier id. Index 0 is unused padding
 * so that the table can be indexed by the raw tier id after the sanctuary
 * case has been handled separately.
 *
 * Declared here (not in the BPF file) because the userspace loader parses
 * these out of BTF to print the ticket pool it is about to install.
 */
#define TLS_TICKETS_ANCHOR		30u
#define TLS_TICKETS_HIGH		20u
#define TLS_TICKETS_MEDIUM		12u
#define TLS_TICKETS_LOW		6u
#define TLS_TICKETS_BACKGROUND	2u

/*
 * Maximum number of tasks that may be resident in a single tier on a single
 * CPU. Bounds the fixed-size tier arrays so the BPF verifier can reason
 * about every index statically and so that, in the architecture document's
 * terms, the arena stays cache-friendly.
 *
 * 512 * 8 bytes = 4 KiB per tier, 24 KiB per CPU for all six tiers.
 */
#define TLS_TIER_CAPACITY	512u

/*
 * Maximum number of CPUs the per-CPU arrays cover. The scheduler refuses to
 * load if the machine reports more (see init() in tls_stubs.bpf.c).
 */
#define TLS_MAX_CPUS		256u

/* ------------------------------------------------------------------ */
/* Timing constants (nanoseconds)                                       */
/* ------------------------------------------------------------------ */
/*
 * Reschedule quantum. Every task that the lottery selects runs for at most
 * this long before it is demoted one tier. This is the "10 ms local timer
 * interrupt" cycle from the architecture document.
 */
#define TLS_SLICE_NS			(10ull * 1000 * 1000)

/*
 * Starvation rotation period. Every this often, the general-purpose tiers
 * are permuted: Tier 4 -> Tier 1, Tiers 1..3 shift down one level.
 */
#define TLS_ROTATE_NS		(150ull * 1000 * 1000)

/*
 * Load-balancing period. Every this often a core checks neighbouring cores
 * for a load imbalance and, if one is found, steals from the victim's
 * lowest tier.
 */
#define TLS_BALANCE_NS		(100ull * 1000 * 1000)

/*
 * Sanctuary time budget (nanoseconds). A Tier -1 task that burns more than
 * this much time (1 ms default) is demoted so that a runaway bottom-half
 * handler cannot livelock the core.
 */
#define TLS_SANCTUARY_BUDGET_CYCLES	(1000ull * 1000)

/*
 * An idle CPU that has been kicked more than this many times without the
 * target starting to run is considered stuck; the scheduler reports it
 * rather than spinning.
 */
#define TLS_MAX_KICK_RETRIES		3u

/* ------------------------------------------------------------------ */
/* Enumerations                                                         */
/* ------------------------------------------------------------------ */

/*
 * Why a task left a tier. Recorded per task for accounting and dumped by
 * dump_task(). Rate of TLS_REASON_QUANTUM_EXPIRED against the others is
 * the primary tuning signal for the demotion policy.
 */
enum tls_outcome {
	TLS_OUTCOME_NONE = 0,
	/* Ran its full TLS_SLICE_NS and was demoted one tier. */
	TLS_OUTCOME_QUANTUM_EXPIRED,
	/* Slept or blocked before the quantum expired; keeps its tier. */
	TLS_OUTCOME_BLOCKED,
	/* Yielded explicitly. */
	TLS_OUTCOME_YIELDED,
	/* Preempted by a higher-priority task inside the same core. */
	TLS_OUTCOME_PREEMPTED,
	/* Promoted by the starvation rotation. */
	TLS_OUTCOME_ROTATED,
	/* Migrated to another core by the load balancer. */
	TLS_OUTCOME_STOLEN,
	/* Lost the lottery enough times in a row to warrant promotion. */
	TLS_OUTCOME_PROMOTED,
};

/*
 * Which counters a task contributes to. Kept as a bitmask so dispatch can
 * charge several buckets in one write.
 */
enum tls_lane {
	TLS_LANE_LOTTERY	= 0,	/* Tiers 0..4, won by the ticket draw */
	TLS_LANE_SANCTUARY	= 1,	/* Tier -1, strict priority */
};

/* ------------------------------------------------------------------ */
/* Per-task state                                                       */
/* ------------------------------------------------------------------ */
/*
 * BPF task storage. Allocated in init_task(), freed by the kernel on task
 * exit (task storage needs no explicit free; exit_task() only clears
 * scheduler-owned references).
 *
 * Sizing: keep this small. It is copied on fork and lives for the task's
 * lifetime.
 */
struct tls_task_ctx {
	/* Current tier id, -1..4. Authoritative tier membership. */
	s32 tier;
	/* Circular index of this task inside its tier array, or -1 if the
	 * task is not currently linked into any tier (e.g. it is on a DSQ
	 * and has already been unlinked, or it is the sanctuary occupant). */
	s32 slot;
	/* CPU whose tier array currently owns this task. */
	s32 cpu;
	/* Whether this task is currently linked into tiers[cpu].tasks[tier].
	 * Guards the unlink path against double removal. */
	bool linked;
	/* Explicit padding to 16 bytes for stable BTF layout. */
	u8 __pad[3];
};

/* ------------------------------------------------------------------ */
/* Per-tier state                                                       */
/* ------------------------------------------------------------------ */
/*
 * One fixed-capacity ring of task pointers per (cpu, tier). The
 * architecture document calls for swap-and-pop removal so that demotion is
 * O(1); this layout supports that directly:
 *
 *   remove(i):  tasks[i] = tasks[--nr];  fix the moved task's slot index.
 *
 * Quota accounting is stored alongside so that the total ticket pool is a
 * pure function of `nr` and the compile-time weight table.
 */
struct tls_tier {
	/* Task pointers, densely packed in [0, nr). */
	struct task_struct *tasks[TLS_TIER_CAPACITY];
	/* Number of live entries in `tasks`. */
	u32 nr;
	/* head/tail are unused by the swap-and-pop discipline and are kept
	 * only so that a future FIFO ordering change does not reshape the
	 * struct. */
	u32 head;
	u32 tail;
	/* Padding to 8 bytes; explicit so the layout is stable across BTF
	 * regeneration. */
	u32 __pad;
};

/* ------------------------------------------------------------------ */
/* Per-CPU state                                                        */
/* ------------------------------------------------------------------ */
/*
 * Everything a core needs to run the lottery without touching another
 * core's memory. `lock` guards the tier arrays, the counters and `prng`
 * against a remote steal from the load balancer; the local CPU only ever
 * contends with a thief.
 */
struct tls_cpu_ctx {
	/* Tier slots, indexed by TLS_TIER_SLOT(tier). */
	struct tls_tier tiers[TLS_NR_TIERS];

	/*
	 * Ticket weight currently granted per task in each tier slot. This is
	 * NOT the compile-time table in tls_tickets_for(): the starvation
	 * rotation permutes these values, which is what makes the rotation
	 * O(1) with no data movement. See tls_rotate_weights() in
	 * tls_stubs.bpf.c for the argument.
	 *
	 * Invariant: for every tier, weights[slot] equals the weight the
	 * architecture document assigns to the tier this slot represents
	 * *this rotation epoch*. Tier -1 (0 tickets, bypasses lottery) and
	 * Tier 0 (30 tickets, excluded from rotation) are locked, so
	 * weights[slot(TIER_SANCTUARY)] and weights[slot(TIER_ANCHOR)] always
	 * keep their initial values.
	 */
	u32 weights[TLS_NR_TIERS];
	u32 weights_pad;

	/*
	 * Total tickets currently live on this CPU:
	 *   sum over Tiers 0..4 of tiers[slot].nr * weights[slot]
	 * Tier -1 holds no tickets (sanctuary bypasses the draw). Cached
	 * rather than recomputed so that the draw is a single load.
	 */
	u64 total_tickets;

	/* Xorshift64 PRNG state, seeded from RDRAND/RDSEED in init() and
	 * reseeded every rotation. Never zero. */
	u64 prng_state;

	/* Atomic load factor used by passive placement on other cores,
	 * mirroring total_tickets (sum of all tickets across tiers). */
	u64 load_factor;

	/* Spinlock protecting remote access (stealing) to this struct. */
	/* NOTE: sched_ext provides bpf_spin_lock via the verifier; the field
	 * is declared as the BPF type by the includer, so keep it opaque
	 * here and let the BPF side cast. */
	u64 lock_opaque;

	/* Most recent anchor in this field's slot, used as the
	 * swap-and-pop pivot when a demoted task must be appended. */
	s32 anchor_slot;

	/* cpu id this context belongs to; redundant with the map key but
	 * makes dump output self-describing. */
	s32 cpu;

	/* --- timestamps, BPF clock domain --- */
	u64 last_rotate_ns;		/* last starvation rotation on this CPU */
	u64 last_balance_ns;		/* last load-balance attempt */
	u64 last_slice_start_ns;	/* for slice accounting */

	/* --- accounting --- */
	u64 selections;			/* lottery draws performed */
	u64 draws_with_empty_pool;	/* draws that found total_tickets == 0 */
	u64 steals_attempted;
	u64 steals_completed;
	u64 rotations;
	u64 sanctuary_entries;
	u64 sanctuary_overruns;		/* Tier -1 budget exceeded */
	u64 kicks;			/* idle-CPU kicks issued */
	u32 rotation_epoch;		/* increments on every rotation */
	u32 __pad0;
};

/* ------------------------------------------------------------------ */
/* Tunables - the userspace <-> BPF control surface                     */
/* ------------------------------------------------------------------ */
/*
 * Populated by the loader into the .rodata map before attach. The BPF side
 * reads these through the `tunables` global defined in tls_core.bpf.h;
 * they are read-only from BPF.
 *
 * Every field has a safe default in the loader. A zero-initialised
 * .rodata (which is what happens if the loader does not write it) must
 * still produce a runnable scheduler, so treat 0 as "use the compile-time
 * default" in the enum fields and never divide by a raw tunable.
 */
struct tls_tunables {
	/* u32 magic; must equal TLS_TUNABLES_MAGIC, else the BPF side
	 * reports a load-time error instead of running with garbage. */
	u32 magic;
	/* Struct version; bumped whenever this layout changes. */
	u32 version;

	/* Base slice in nanoseconds. 0 => TLS_SLICE_NS. */
	u64 slice_ns;
	/* Rotation period in nanoseconds. 0 => TLS_ROTATE_NS. */
	u64 rotate_ns;
	/* Balancing period in nanoseconds. 0 => TLS_BALANCE_NS. */
	u64 balance_ns;
	/* Sanctuary budget in nanoseconds (1 ms default). 0 => TLS_SANCTUARY_BUDGET_CYCLES. */
	u64 sanctuary_budget_cycles;

	/* Consecutive losses before a task is promoted a tier. 0 disables
	 * the promotion fallback entirely (pure architecture behaviour). */
	u32 promote_after_losses;
	/* Load imbalance numerator/denominator: steal when
	 *   victim->load_factor * balance_ratio_num
	 *     > thief->load_factor * balance_ratio_den
	 * Both must be non-zero or balancing is skipped. */
	u32 balance_ratio_num;
	u32 balance_ratio_den;

	/* Verbosity: 0 = quiet, 1 = lifecycle events, 2 = per-draw trace
	 * (very expensive; development only). */
	u32 verbose;
	/* Run the starvation rotation in reverse (Tier 1 -> Tier 4) for A/B
	 * benchmarking of the rotation direction. */
	bool rotate_reverse;
	/* Emit a warning instead of an error when a tier overflows. */
	bool soft_overflow;
	/* Pad to a multiple of 8 bytes. */
	u8 __pad[2];
};

#define TLS_TUNABLES_MAGIC	0x54534C78u	/* "TSLx" */
#define TLS_TUNABLES_VERSION	1u

/* ------------------------------------------------------------------ */
/* Map sizing                                                           */
/* ------------------------------------------------------------------ */
/*
 * The tier arrays live inside struct tls_cpu_ctx, which is the value
 * type of an array map with TLS_MAX_CPUS entries. That map is the bulk
 * of the scheduler's memory:
 *
 *   sizeof(struct tls_cpu_ctx) * 256
 *
 * with TLS_TIER_CAPACITY == 512 this is roughly 6 MiB. Reduce
 * TLS_TIER_CAPACITY first if the verifier or the machine complains.
 */
#define TLS_CPU_CTX_BYTES \
	((u64)sizeof(struct tls_cpu_ctx) * TLS_MAX_CPUS)

#endif /* __TLS_INTF_H */
