// SPDX-License-Identifier: GPL-2.0
/*
 * TLS - Tiered Lottery Scheduler for x86_64, sched_ext front end.
 *
 * Copyright (c) 2026 <your name>
 *
 * Builds tls.bpf.o: maps, tier primitives, callbacks, and the ops
 * object the kernel calls into.
 */

/* kernel types first: everything below needs task_struct and kfuncs */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>

#include "tls_intf.h"
#include "tls_core.bpf.h"
#include "tls_bpf_impl.h"

char _license[] SEC("license") = "GPL";

/* loader reads this after detach to say why the scheduler stopped */
UEI_DEFINE(tls_uei);

/*
 * callbacks and the lottery between them, included last because the ops
 * table below takes the address of every one of them.
 */
#include "tls_stubs.bpf.c"

/* 0: no flags, so rt and deadline tasks keep their own classes */
#define TLS_OPS_FLAGS	0

/* a callback holding a CPU longer than this aborts the scheduler */
#define TLS_OPS_TIMEOUT_MS	5000

/* dequeue() not registered: lifecycle callbacks unlink tasks */
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
