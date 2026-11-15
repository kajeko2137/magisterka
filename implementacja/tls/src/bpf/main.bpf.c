// SPDX-License-Identifier: GPL-2.0
/*
 * TLS - Tiered Lottery Scheduler for x86_64, sched_ext front end.
 *
 * Copyright (c) 2026 <your name>
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE IS
 * ---------------------------------------------------------------------------
 * This is the single translation unit that becomes tls.bpf.o. It does
 * three things and nothing else:
 *
 *   1. Includes the sched_ext BPF headers and the shared interface header.
 *   2. Includes the maps/globals, the O(1) tier primitives, and the callback
 *      implementations (this is a textual include, so everything ends up in
 *      one translation unit and the compiler can inline the tier helpers
 *      into the callbacks, which is what keeps the lottery at its stated
 *      cycle budget).
 *   3. Defines the struct sched_ext_ops object the kernel calls into.
 *
 * ---------------------------------------------------------------------------
 * WHAT YOU IMPLEMENT
 * ---------------------------------------------------------------------------
 * Nothing in this file. Every function body you need to write is in
 * src/bpf/tls_stubs.bpf.c, and each one carries the kernel's contract for
 * that callback. Start with the implementation order in that file's header.
 *
 * The only things here you might touch, both marked below:
 *
 *   - TLS_OPS_FLAGS, if the policy needs different enqueue semantics.
 *   - TLS_OPS_TIMEOUT_MS, once dispatch() can block.
 *
 * ---------------------------------------------------------------------------
 * INCLUDE ORDER IS LOAD-BEARING
 * ---------------------------------------------------------------------------
 *   <scx/common.bpf.h>       pulls in vmlinux.h: struct task_struct, the
 *                            scx_bpf_* kfunc prototypes, SCX_* enums
 *   <scx/compat.bpf.h>       version-compatibility shims for the helpers
 *                            whose names changed between kernel releases
 *   <scx/user_exit_info.bpf.h>  the UEI map used by tls_exit()
 *   tls_intf.h            tier geometry and state layouts
 *   tls_core.bpf.h        maps, globals, tunables  (needs the kernel types)
 *   tls_bpf_impl.h        tier primitives         (needs the maps)
 *   tls_helpers.bpf.c     policy helpers          (needs the primitives)
 *   tls_stubs.bpf.c       callbacks               (needs all of the above)
 *
 * tls_stubs.bpf.c is included last because the ops table at the bottom of
 * this file takes the address of every callback, so the callbacks must be
 * declared first.
 *
 * ---------------------------------------------------------------------------
 * BUILD
 * ---------------------------------------------------------------------------
 *   make              generate vmlinux.h if needed, build the .bpf.o
 *   make verify       build, then load the object to run the BPF verifier
 *   make check-abi    confirm vmlinux.h matches the target kernel
 *   make help         all targets
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>

#include "tls_intf.h"
#include "tls_core.bpf.h"
#include "tls_bpf_impl.h"

char _license[] SEC("license") = "GPL";

/*
 * Exit information. The loader reads this map after the scheduler detaches
 * in order to explain why it stopped: a clean stop, a BPF error, a watchdog
 * stall, or a sysrq override.
 */
UEI_DEFINE(tls_uei);

/*
 * Policy helpers used by the callbacks below.
 */
#include "tls_helpers.bpf.c"

/*
 * The callback implementations, and the lottery algorithm that belongs
 * between them.
 */
#include "tls_stubs.bpf.c"

/*
 * ---------------------------------------------------------------------------
 * struct sched_ext_ops - the kernel's interface to this scheduler
 * ---------------------------------------------------------------------------
 * Only the members listed below are set. Every unset member is NULL and the
 * kernel falls back to its own defined behaviour for that callback, which is
 * documented per callback in tls_stubs.bpf.c so that you can always tell
 * "not called" from "called and did nothing".
 *
 *   Member          Implemented in            Optional?
 *   --------------  ------------------------  -----------------------------
 *   select_cpu      tls_select_cpu()       optional, but leave it in
 *   enqueue         tls_enqueue()          REQUIRED
 *   dispatch        tls_dispatch()         optional; see the note below
 *   tick            tls_tick()             optional; needed for the 10 ms
 *                                             quantum and 150 ms rotation
 *   runnable        tls_runnable()         optional
 *   running         tls_running()          optional; needed for slice
 *                                             accounting
 *   stopping        tls_stopping()         optional; needed so a running
 *                                             task is not left linked
 *   quiescent       tls_quiescent()        optional
 *   yield           tls_yield()            optional
 *   set_weight      tls_set_weight()       optional
 *   set_cpumask     tls_set_cpumask()      optional
 *   update_idle     tls_update_idle()      optional
 *   init_task       tls_init_task()        required in practice
 *   exit_task       tls_exit_task()        optional
 *   enable          tls_enable()           optional
 *   disable         tls_disable()          optional
 *   dump            tls_dump()             optional, useful
 *   dump_cpu        tls_dump_cpu()         optional, useful
 *   dump_task       tls_dump_task()        optional, useful
 *   cpu_online      tls_cpu_online()       optional
 *   cpu_offline     tls_cpu_offline()      optional
 *   cpu_acquire     tls_cpu_acquire()      optional
 *   cpu_release     tls_cpu_release()      optional
 *   init            tls_init()             optional
 *   exit            tls_exit()             optional
 *
 * Deliberately NOT registered:
 *
 *   dequeue   tls_dequeue() exists and is documented in the stubs file,
 *             but is left unregistered. sched_ext calls dequeue() when a task
 *             leaves a DSQ, and this scheduler unlinks tasks explicitly in
 *             the lifecycle callbacks, so registering it would do the same
 *             work twice and risk a double removal from a tier array.
 *             Register it only if you move to a policy where the kernel,
 *             rather than this scheduler, evicts tasks.
 *
 *   cgroup_*  not part of the TLS specification. Leaving them NULL keeps
 *             the kernel's built-in cgroup behaviour, which is what the
 *             architecture document assumes.
 *
 * Note on dispatch(): sched_ext calls dispatch() to refill a CPU's local DSQ,
 * and only when that DSQ has room. The default tls_enqueue() inserts
 * straight onto SCX_DSQ_LOCAL, so the local DSQ drives execution and
 * dispatch() has nothing to do yet. It is registered anyway because it is the
 * natural home for the lottery draw if you choose to batch, and because a
 * registered dispatch() that cannot make progress is exactly what produces
 * SCX_EXIT_ERROR_STALL - so having it visible in the ops table is a reminder
 * that it must stay consistent with enqueue(). Pick one of the two to own
 * insertion; do not let both insert.
 */

/*
 * Ops flags.
 *
 *   0 means no behaviour changes from the kernel's defaults, which is what
 *   this scheduler wants:
 *
 *   SCX_OPS_SWITCH_PARTIAL is deliberately left off, so realtime and deadline
 *   tasks stay on their own scheduling classes. That matches the architecture
 *   document's intent for Tier -1 as a strict-priority lane inside this
 *   scheduler rather than a takeover of the other classes.
 *
 *   SCX_OPS_ENQ_LAST would report the last task of a batch so that a
 *   scheduler can act once per batch. Nothing here batches yet.
 *
 * TODO(policy): revisit if TLS should also own SCHED_IDLE or
 * SCHED_BATCH tasks, or if the lottery should be told about batch
 * boundaries.
 */
#define TLS_OPS_FLAGS	0

/*
 * Watchdog timeout.
 *
 * If a single BPF callback occupies a CPU for longer than this, the kernel
 * aborts the scheduler with SCX_EXIT_ERROR_STALL and the machine returns to
 * the kernel's default scheduler. The kernel default is 30 s; 5 s is plenty
 * for this scheduler and fails faster, which is what you want while
 * implementing: a stall is a bug in the tier bookkeeping, and finding out in
 * five seconds rather than thirty matters.
 *
 * TODO(policy): raise this if you ever make dispatch() spin, and lower it
 * further while bringing up a new mechanism.
 */
#define TLS_OPS_TIMEOUT_MS	5000

/*
 * The ops object. This is what the kernel registers; every NULL member above
 * stays NULL because it is not named here.
 */
SCX_OPS_DEFINE(tls_ops,
	.select_cpu		= (void *)tls_select_cpu,
	.enqueue		= (void *)tls_enqueue,
	.dispatch		= (void *)tls_dispatch,
	.tick			= (void *)tls_tick,
	.runnable		= (void *)tls_runnable,
	.running		= (void *)tls_running,
	.stopping		= (void *)tls_stopping,
	.quiescent		= (void *)tls_quiescent,
	.yield			= (void *)tls_yield,
	.set_weight		= (void *)tls_set_weight,
	.set_cpumask		= (void *)tls_set_cpumask,
	.update_idle		= (void *)tls_update_idle,
	.init_task		= (void *)tls_init_task,
	.exit_task		= (void *)tls_exit_task,
	.enable			= (void *)tls_enable,
	.disable		= (void *)tls_disable,
	.dump			= (void *)tls_dump,
	.dump_cpu		= (void *)tls_dump_cpu,
	.dump_task		= (void *)tls_dump_task,
	.cpu_online		= (void *)tls_cpu_online,
	.cpu_offline		= (void *)tls_cpu_offline,
	.cpu_acquire		= (void *)tls_cpu_acquire,
	.cpu_release		= (void *)tls_cpu_release,
	.init			= (void *)tls_init,
	.exit			= (void *)tls_exit,
	.flags			= TLS_OPS_FLAGS,
	.timeout_ms		= TLS_OPS_TIMEOUT_MS,
	.name			= "tls"
);
