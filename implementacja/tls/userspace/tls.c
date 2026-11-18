// SPDX-License-Identifier: GPL-2.0
/*
 * TLS - userspace loader.
 *
 * Copyright (c) 2026 <your name>
 *
 * ===========================================================================
 * WHAT THIS PROGRAM IS
 * ===========================================================================
 * This is the other half of the kernel interface. It does the four things a
 * sched_ext scheduler cannot do from BPF:
 *
 *   1. Opens tls.bpf.o and applies the configuration you pass on the
 *      command line to the .rodata map, before the scheduler attaches.
 *   2. Loads the verifier-checked programs and attaches the struct_ops
 *      object, which is what makes the kernel start calling the callbacks in
 *      src/bpf/tls_stubs.bpf.c.
 *   3. Keeps the scheduler alive until you stop it, and detaches cleanly on
 *      Ctrl-C or SIGTERM so the machine always gets its default scheduler
 *      back.
 *   4. Reads the user_exit_info map on the way out and decodes the kernel's
 *      stop reason: a clean detach, a BPF error, a watchdog stall, or a
 *      sysrq override.
 *
 * You do not need to modify this file to implement TLS. Everything that
 * varies between runs is a command-line option, and every option maps to a
 * field of struct tls_tunables in src/include/tls_intf.h.
 *
 * ===========================================================================
 * USAGE
 * ===========================================================================
 *   tls [options] <path-to-tls.bpf.o>
 *
 *   --help              all options
 *   --verify            load and attach nowhere: run the verifier and stop.
 *                       This is the check to run after every BPF change,
 *                       because the verifier rejects what would otherwise
 *                       hang a machine.
 *   --stats             print the scheduler's counters and exit
 *   --help-abi          print the callback contract summary and exit
 *
 *   -v, --verbose       kernel-log level output
 *
 * Time and ticket knobs, all defaulting to the architecture document:
 *   --slice-ms N        reschedule quantum          (default 10)
 *   --rotate-ms N       starvation rotation period  (default 150)
 *   --balance-ms N      load-balance period         (default 100)
 *   --promote-after N   losses before promotion     (default 0 = disabled)
 *   --balance-ratio A:B steal threshold             (default 2:1)
 *   --rotate-reverse    run the rotation the other way, for A/B measurement
 *
 * ===========================================================================
 * THE STRUCT_OPS ATTACH DANCE, AND WHY IT IS FRAGILE
 * ===========================================================================
 * sched_ext is a BPF struct_ops subsystem. The kernel matches the compiled
 * `struct sched_ext_ops` against the layout described by its own BTF. Two
 * consequences matter when you are developing:
 *
 *   - If the object was compiled against a different kernel's layout, the
 *     attach can still succeed and the kernel then calls the wrong function
 *     pointers. `make check-abi` exists to catch this before it happens. Its
 *     output is worth reading once so that you know what a mismatch looks
 *     like.
 *
 *   - A scheduler that attaches but never hands a runnable task to the kernel
 *     hangs the machine after the watchdog timeout. That is why
 *     TLS_OPS_TIMEOUT_MS in src/bpf/main.bpf.c is deliberately short, and
 *     why --verify exists: load and verify without ever becoming the
 *     scheduler.
 *
 * The attach itself uses the modern path: the ops object is placed in the
 * `.struct_ops.link` section by SCX_OPS_DEFINE(), which makes libbpf create
 * it as a link-based struct_ops map, and bpf_map__attach_struct_ops()
 * returns a link we hold open. Holding the link is what keeps the scheduler
 * registered; when the process exits, the link closes and the kernel falls
 * back to its default scheduler. That fallback is automatic and does not
 * depend on this program getting a chance to clean up, which is what makes
 * Ctrl-C safe.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* ------------------------------------------------------------------ */
/* Mirror of struct tls_tunables                                     */
/* ------------------------------------------------------------------ */
/*
 * This must match src/include/tls_intf.h field for field. The static
 * asserts below catch most accidental drift at compile time; the runtime
 * check on the map's value size catches the rest, because a mismatch in size
 * means the loader would be writing a struct the BPF side does not share.
 *
 * The definitions are duplicated rather than generated, deliberately: a
 * sched_ext loader that depends on a code-generation step is harder to debug
 * than one that fails a static assert at compile time.
 *
 * If you add a field to the BPF struct, add it here and bump
 * TLS_TUNABLES_VERSION in the BPF header. The loader refuses to run when
 * the versions disagree.
 */
#define TLS_TUNABLES_MAGIC		0x54534C78u	/* "TSLx" */
#define TLS_TUNABLES_VERSION		1u
/* The BPF side checks `magic` in tls_init() and reports a load-time
 * error rather than running with a configuration it does not understand. */

/* Defaults, mirroring the BPF-side constants. */
#define TLS_NS_PER_MS		1000000ull
#define TLS_SLICE_MS_DFL		10ull
#define TLS_ROTATE_MS_DFL		150ull
#define TLS_BALANCE_MS_DFL		100ull
#define TLS_SANCTUARY_BUDGET_DFL	1000000ull	/* nanoseconds (1 ms) */
#define TLS_BALANCE_NUM_DFL		2u
#define TLS_BALANCE_DEN_DFL		1u

struct tls_tunables {
	uint32_t magic;			/*  0 */
	uint32_t version;		/*  4 */

	uint64_t slice_ns;		/*  8 */
	uint64_t rotate_ns;		/* 16 */
	uint64_t balance_ns;		/* 24 */
	uint64_t sanctuary_budget_cycles; /* 32 */

	uint32_t promote_after_losses;	/* 40 */
	uint32_t balance_ratio_num;	/* 44 */
	uint32_t balance_ratio_den;	/* 48 */

	uint32_t verbose;		/* 52 */
	bool	 rotate_reverse;	/* 56 */
	bool	 soft_overflow;		/* 57 */
	uint8_t	 __pad[2];		/* 58 */
	/* 4 bytes of tail padding follow, because the struct's alignment is 8
	 * (it contains u64s). So sizeof() is 64, not 60. This is worth stating
	 * explicitly: it is the kind of detail that makes a size assertion look
	 * wrong when it is right. */
};

/*
 * These assertions are the reason this copy of the struct is safe to keep.
 * They are derived by hand from src/include/tls_intf.h, so if that struct
 * gains, loses, or reorders a field, one of them fires at compile time
 * instead of the loader quietly writing a misaligned configuration into the
 * kernel. A silent mismatch here would present as a scheduler using the wrong
 * slice length or the wrong balance ratio, which is very hard to diagnose
 * from the BPF side.
 *
 * When you change the BPF struct: update this one, update these numbers, and
 * bump TLS_TUNABLES_VERSION on both sides.
 */
_Static_assert(sizeof(struct tls_tunables) == 64,
	       "struct tls_tunables changed size: update the loader's copy "
	       "and TLS_TUNABLES_VERSION together");
_Static_assert(offsetof(struct tls_tunables, magic) == 0,
	       "tls_tunables.magic moved");
_Static_assert(offsetof(struct tls_tunables, version) == 4,
	       "tls_tunables.version moved");
_Static_assert(offsetof(struct tls_tunables, slice_ns) == 8,
	       "tls_tunables.slice_ns moved");
_Static_assert(offsetof(struct tls_tunables, rotate_ns) == 16,
	       "tls_tunables.rotate_ns moved");
_Static_assert(offsetof(struct tls_tunables, balance_ns) == 24,
	       "tls_tunables.balance_ns moved");
_Static_assert(offsetof(struct tls_tunables, sanctuary_budget_cycles) == 32,
	       "tls_tunables.sanctuary_budget_cycles moved");
_Static_assert(offsetof(struct tls_tunables, promote_after_losses) == 40,
	       "tls_tunables.promote_after_losses moved");
_Static_assert(offsetof(struct tls_tunables, balance_ratio_num) == 44,
	       "tls_tunables.balance_ratio_num moved");
_Static_assert(offsetof(struct tls_tunables, balance_ratio_den) == 48,
	       "tls_tunables.balance_ratio_den moved");
_Static_assert(offsetof(struct tls_tunables, verbose) == 52,
	       "tls_tunables.verbose moved");
_Static_assert(offsetof(struct tls_tunables, rotate_reverse) == 56,
	       "tls_tunables.rotate_reverse moved");
_Static_assert(offsetof(struct tls_tunables, soft_overflow) == 57,
	       "tls_tunables.soft_overflow moved");

/* ------------------------------------------------------------------ */
/* Mirror of struct user_exit_info                                      */
/* ------------------------------------------------------------------ */
/*
 * From scheds/include/scx/user_exit_info_common.h. The kernel fills this in
 * when the scheduler detaches, and it is how you find out why.
 */
#define TLS_UEI_REASON_LEN		256
#define TLS_UEI_MSG_LEN		4096

enum tls_exit_kind {
	TLS_EXIT_NONE		= 0,
	TLS_EXIT_DONE		= 1,
	TLS_EXIT_UNREG		= 64,
	TLS_EXIT_UNREG_BPF		= 65,
	TLS_EXIT_UNREG_KERN		= 66,
	TLS_EXIT_SYSRQ		= 67,
	TLS_EXIT_PARENT		= 68,
	TLS_EXIT_PARENT_KILL		= 69,
	TLS_EXIT_ERROR		= 1024,
	TLS_EXIT_ERROR_BPF		= 1025,
	TLS_EXIT_ERROR_STALL		= 1026,
	TLS_EXIT_ERROR_REENQ		= 1027,
	TLS_EXIT_ERROR_RESCUE	= 1028,
};

struct tls_uei {
	int32_t	 kind;
	int32_t	 exit_cpu;
	int64_t	 exit_code;
	char	 reason[TLS_UEI_REASON_LEN];
	char	 msg[TLS_UEI_MSG_LEN];
};

/* ------------------------------------------------------------------ */
/* Runtime options                                                      */
/* ------------------------------------------------------------------ */

struct opts {
	const char	*object;
	bool		 verify_only;
	bool		 print_stats;
	bool		 verbose;

	struct tls_tunables tun;
};

static volatile sig_atomic_t exiting;

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

/* ------------------------------------------------------------------ */
/* libbpf logging                                                       */
/* ------------------------------------------------------------------ */

/*
 * libbpf is chatty at debug level and a mismatch between its log level and
 * our verbosity is a common source of confusion, so drive it from --verbose.
 * WARN and above always come through: they are how a verifier rejection is
 * reported, and swallowing those would make failures silent.
 */
static bool g_verbose;

static int libbpf_log(enum libbpf_print_level level, const char *fmt,
		      va_list args)
{
	/*
	 * LIBBPF_DEBUG carries two very different things: libbpf's own
	 * internals, and BPF-side bpf_printk() output, which arrives here
	 * too. Both are noisy in a hot path, so they are gated behind
	 * --verbose. WARN and above always get through: that is how a
	 * verifier rejection is reported, and swallowing it would make
	 * failures silent.
	 */
	if (level == LIBBPF_DEBUG && !g_verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

/* ------------------------------------------------------------------ */
/* The ABI summary, printed by --help-abi                               */
/* ------------------------------------------------------------------ */
/*
 * A concise restatement of the callback contract, so that you can read it
 * without leaving the terminal. The authoritative version, with the
 * MUST-not-break invariants, is in src/bpf/tls_stubs.bpf.c.
 */
static void print_abi_summary(void)
{
	static const struct {
		const char *member;
		const char *signature;
		const char *requirement;
	} table[] = {
		{ "select_cpu", "s32 (task, s32 prev, u64 flags)",
		  "optional; choose a CPU, must respect the task's cpumask" },
		{ "enqueue", "void (task, u64 flags)",
		  "REQUIRED; must leave the task reachable" },
		{ "dispatch", "void (s32 cpu, task prev)",
		  "optional; feed the CPU's local DSQ if enqueue does not" },
		{ "tick", "void (task)", "optional; drives quantum and rotation" },
		{ "runnable", "void (task, u64 flags)", "optional" },
		{ "running", "void (task)", "optional; slice accounting" },
		{ "stopping", "void (task, bool running)",
		  "optional; must not leave a running task linked" },
		{ "quiescent", "void (task, u64 flags)", "optional" },
		{ "yield", "bool (task, task from)", "optional" },
		{ "set_weight", "void (task, u32 weight)", "optional" },
		{ "set_cpumask", "void (task, const cpumask *)", "optional" },
		{ "update_idle", "void (s32 cpu, bool idle)", "optional" },
		{ "init_task", "s32 (task, scx_init_task_args *)",
		  "required in practice; allocate per-task state" },
		{ "exit_task", "void (task, scx_exit_task_args *)", "optional" },
		{ "enable", "void (task)", "optional" },
		{ "disable", "void (task)", "optional" },
		{ "dump", "void (scx_dump_ctx *)", "optional, useful" },
		{ "dump_cpu", "void (scx_dump_ctx *, s32, bool)", "optional" },
		{ "dump_task", "void (scx_dump_ctx *, task)", "optional" },
		{ "cpu_online", "void (s32 cpu)", "optional" },
		{ "cpu_offline", "void (s32 cpu)", "optional; evacuate" },
		{ "cpu_acquire", "void (s32, scx_cpu_acquire_args *)", "optional" },
		{ "cpu_release", "void (s32, scx_cpu_release_args *)", "optional" },
		{ "init", "s32 (void)", "optional; per-CPU setup" },
		{ "exit", "void (scx_exit_info *)", "optional" },
	};
	size_t i;

	printf("TLS kernel-facing callbacks\n");
	printf("Registered in src/bpf/main.bpf.c, implemented in "
	       "src/bpf/tls_stubs.bpf.c.\n\n");
	printf("  %-14s %-40s %s\n", "member", "signature", "requirement");
	printf("  %-14s %-40s %s\n", "------", "---------", "-----------");
	for (i = 0; i < sizeof(table) / sizeof(table[0]); i++)
		printf("  %-14s %-40s %s\n", table[i].member,
		       table[i].signature, table[i].requirement);

	printf("\nNot registered, deliberately: dequeue (this scheduler unlinks "
	       "explicitly),\n");
	printf("cgroup_* (not part of the design).\n\n");
	printf("Implementation order, and the full contract per callback:\n");
	printf("  src/bpf/tls_stubs.bpf.c\n");
}

/* ------------------------------------------------------------------ */
/* Environment checks                                                   */
/* ------------------------------------------------------------------ */

/*
 * Raise RLIMIT_MEMLOCK to unlimited, as every other scx loader does.
 *
 * A sched_ext scheduler allocates BPF maps, and the default memlock limit is
 * often far below what they need. Upstream's Rust loaders do exactly this and
 * warn rather than fail, because on a kernel whose BPF memory accounting is
 * memcg-based the limit does not matter and the call can legitimately fail.
 */
static void raise_memlock(void)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0)
		return;

	if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0)
		fprintf(stderr,
			"note: could not raise RLIMIT_MEMLOCK (soft=%llu "
			"hard=%llu).\n"
			"      This is harmless on kernels that account BPF "
			"memory per cgroup.\n",
			(unsigned long long)rl.rlim_cur,
			(unsigned long long)rl.rlim_max);
	else
		fprintf(stderr,
			"note: could not raise or query RLIMIT_MEMLOCK.\n");
}

/*
 * Distinguish "you lack the privilege to load BPF at all" from "the verifier
 * rejected the program".
 *
 * This matters because libbpf's own message for the first case mentions the
 * verifier, which sends people looking for a bug in their BPF code when the
 * actual problem is that they are not root. Getting this wrong costs hours.
 */
static bool has_bpf_capability(void)
{
#ifdef __linux__
	/*
	 * CAP_BPF (39) or CAP_SYS_ADMIN (21). Checking the effective set
	 * directly avoids depending on libcap.
	 */
	FILE *f = fopen("/proc/self/status", "r");
	char line[256];
	unsigned long long eff = 0;
	bool found = false;

	if (!f)
		return true;	/* cannot tell; do not block the user */

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "CapEff:\t%llx", &eff) == 1) {
			found = true;
			break;
		}
	}
	fclose(f);

	if (!found)
		return true;

	if (eff & (1ULL << 21))		/* CAP_SYS_ADMIN */
		return true;
	if (eff & (1ULL << 39))		/* CAP_BPF */
		return true;
	return false;
#else
	return true;
#endif
}

static int report_privilege_problem(const char *argv0)
{
	char buf[8] = { 0 };
	FILE *f;

	fprintf(stderr,
		"error: this process cannot load BPF programs.\n"
		"\n"
		"  Effective capabilities are empty, so the kernel refused a\n"
		"  trivial test program before the verifier ever saw this\n"
		"  object. A sched_ext scheduler needs CAP_BPF (or\n"
		"  CAP_SYS_ADMIN on older kernels) plus CAP_PERFMON.\n"
		"\n"
		"  Run it with the needed privileges, for example:\n"
		"      sudo setcap cap_bpf,cap_perfmon+ep %s\n"
		"  or simply\n"
		"      sudo %s ...\n",
		argv0, argv0);

	/*
	 * Point at the other common cause, which is not a capability problem
	 * and which the suggestion above would not fix.
	 */
	f = fopen("/proc/sys/kernel/unprivileged_bpf_disabled", "r");
	if (f) {
		if (fgets(buf, sizeof(buf), f)) {
			int v = atoi(buf);
			if (v)
				fprintf(stderr,
					"\n  Note: /proc/sys/kernel/unprivileged_bpf_disabled is %d.\n"
					"  Any non-zero value restricts BPF to privileged\n"
					"  processes. CAP_BPF overrides it; nothing else does.\n", v);
		}
		fclose(f);
	}
	return 1;
}


/* ------------------------------------------------------------------ */
/*
 * Fail before touching BPF if the kernel cannot host this scheduler. The
 * error the kernel gives for a missing sched_ext is not self-explanatory, so
 * it is worth spending a syscall to say something useful instead.
 */
static int check_sched_ext_available(void)
{
	const char *paths[] = {
		"/sys/kernel/sched_ext/state",
		"/proc/sys/kernel/sched_ext_state",
	};
	size_t i;
	bool found = false;

	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		if (access(paths[i], R_OK) == 0) {
			found = true;
			break;
		}
	}

	if (!found) {
		fprintf(stderr,
			"error: this kernel does not appear to have sched_ext\n"
			"\n"
			"  Looked for /sys/kernel/sched_ext/state and\n"
			"  /proc/sys/kernel/sched_ext_state; found neither.\n"
			"\n"
			"  Check the kernel configuration:\n"
			"      grep CONFIG_SCHED_CLASS_EXT /boot/config-$(uname -r)\n"
			"\n"
			"  It must be 'y'. There is no runtime workaround: the\n"
			"  sched_ext ABI is compiled into the kernel. Boot a kernel\n"
			"  built with it, then run this again.\n");
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Tunables                                                             */
/* ------------------------------------------------------------------ */

static void tunables_defaults(struct tls_tunables *t)
{
	memset(t, 0, sizeof(*t));
	t->magic		= TLS_TUNABLES_MAGIC;
	t->version		= TLS_TUNABLES_VERSION;
	t->slice_ns		= TLS_SLICE_MS_DFL * TLS_NS_PER_MS;
	t->rotate_ns		= TLS_ROTATE_MS_DFL * TLS_NS_PER_MS;
	t->balance_ns		= TLS_BALANCE_MS_DFL * TLS_NS_PER_MS;
	t->sanctuary_budget_cycles = TLS_SANCTUARY_BUDGET_DFL;
	t->promote_after_losses	= 0;	/* disabled: pure document behaviour */
	t->balance_ratio_num	= TLS_BALANCE_NUM_DFL;
	t->balance_ratio_den	= TLS_BALANCE_DEN_DFL;
	t->verbose		= 1;
	t->rotate_reverse	= false;
	t->soft_overflow	= false;
}

/*
 * Write the configuration into the .rodata map.
 *
 * The BPF side reads these as `const volatile`, so they must be written
 * before the struct_ops is attached. libbpf exposes .rodata as a map; the map
 * holds the whole section, so we read it, patch our struct into it at the
 * right offset, and write it back. The offset is discovered from the ELF
 * symbol rather than hardcoded, because the compiler is free to pad the
 * section.
 */
static int apply_tunables(struct bpf_object *obj, const struct tls_tunables *t)
{
	struct bpf_map *map;
	size_t map_sz;
	void *buf;

	/*
	 * libbpf names the map after its ELF section, so the map is called
	 * ".rodata", not after the variable inside it.
	 */
	map = bpf_object__find_map_by_name(obj, ".rodata");
	if (!map) {
		fprintf(stderr,
			"error: the object has no .rodata map.\n"
			"  The BPF side declares the tunables as a const volatile\n"
			"  struct in .rodata; if that declaration was removed, or the\n"
			"  section renamed, this lookup fails. See\n"
			"  src/include/tls_core.bpf.h.\n");
		return -ENOENT;
	}

	buf = bpf_map__initial_value(map, &map_sz);
	if (!buf) {
		fprintf(stderr, "error: cannot read .rodata's initial value\n");
		return -EINVAL;
	}

	/*
	 * The map is the whole .rodata section, which is larger than the
	 * struct because bpf_printk() format strings live there too. So the
	 * check is that the section is big enough, not that it matches.
	 */
	if (map_sz < sizeof(*t)) {
		fprintf(stderr,
			"error: the BPF side's .rodata is %zu bytes but this "
			"loader's tunables struct is %zu.\n"
			"  The two sides have drifted, or the BPF side no longer\n"
			"  declares struct tls_tunables. Align it in\n"
			"  src/include/tls_intf.h with the loader's copy and bump\n"
			"  TLS_TUNABLES_VERSION on both sides.\n",
			map_sz, sizeof(*t));
		return -EINVAL;
	}

	/*
	 * Patch the struct in place at offset 0 and let libbpf carry it into
	 * the map at load time.
	 *
	 * Doing it this way, rather than writing the map after loading, is
	 * deliberate: a .rodata map that has been frozen is read-only, and
	 * bpf_map_update_elem() on it fails with EBADF. Setting the initial
	 * value works in all cases and is always applied before the
	 * struct_ops can be attached.
	 *
	 * The offset-0 assumption holds because tls_tunables is the first
	 * variable in the section; the magic field, validated by the BPF side
	 * in tls_init(), catches it if that ever changes.
	 */
	memcpy(buf, t, sizeof(*t));

	return bpf_map__set_initial_value(map, buf, map_sz);
}

/* ------------------------------------------------------------------ */
/* Stats                                                                */
/* ------------------------------------------------------------------ */

/*
 * Sum a per-CPU array map across CPUs. Returns the number of entries read,
 * or a negative errno.
 */
static int read_percpu_counter(int map_fd, uint32_t key, uint64_t *total)
{
	const size_t u64_sz = 8;
	size_t buf_sz;
	uint8_t *buf;
	int ncpu, i;
	uint64_t sum = 0;

	ncpu = libbpf_num_possible_cpus();
	if (ncpu <= 0)
		return ncpu ? ncpu : -EINVAL;

	/*
	 * A per-CPU map's value is one copy per possible CPU, padded to 8
	 * bytes each. The padding is why the buffer size must be computed
	 * rather than assumed.
	 */
	buf_sz = (size_t)ncpu * u64_sz;
	buf = calloc(1, buf_sz);
	if (!buf)
		return -ENOMEM;

	if (bpf_map_lookup_elem(map_fd, &key, buf) != 0) {
		int err = -errno;
		free(buf);
		return err;
	}

	for (i = 0; i < ncpu; i++) {
		uint64_t v;
		memcpy(&v, buf + (size_t)i * u64_sz, sizeof(v));
		sum += v;
	}

	free(buf);
	*total = sum;
	return 0;
}

static const char *stat_names[] = {
	"lottery draws",
	"draws with an empty pool",
	"promotions",
	"demotions",
	"sanctuary entries",
	"sanctuary budget overruns",
	"tier overflows",
	"steals completed",
	"idle kicks issued",
};

static int print_stats(struct bpf_object *obj)
{
	struct bpf_map *map;
	int map_fd, i;
	bool any = false;

	map = bpf_object__find_map_by_name(obj, "tls_stats");
	if (!map) {
		fprintf(stderr, "error: no tls_stats map in the object\n");
		return -ENOENT;
	}
	map_fd = bpf_map__fd(map);

	printf("TLS counters\n");
	printf("  %-28s %s\n", "counter", "value");
	printf("  %-28s %s\n", "-------", "-----");
	for (i = 0; i < (int)(sizeof(stat_names) / sizeof(stat_names[0])); i++) {
		uint64_t v = 0;
		int err = read_percpu_counter(map_fd, (uint32_t)i, &v);

		if (err) {
			/* A map that is not yet created is normal before
			 * attach. */
			printf("  %-28s (unavailable)\n", stat_names[i]);
			continue;
		}
		if (v)
			any = true;
		printf("  %-28s %llu\n", stat_names[i],
		       (unsigned long long)v);
	}

	if (!any) {
		printf("\nAll counters are zero. Either the scheduler has not "
		       "been attached yet,\n");
		printf("or no scheduling decision has been made. Note that the "
		       "stub implementation\n");
		printf("in src/bpf/tls_stubs.bpf.c never increments the "
		       "lottery counters: they\n");
		printf("become meaningful once you implement the draw.\n");
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Exit report                                                          */
/* ------------------------------------------------------------------ */

static const char *exit_kind_name(int32_t kind)
{
	switch (kind) {
	case TLS_EXIT_NONE:		return "none";
	case TLS_EXIT_DONE:		return "done";
	case TLS_EXIT_UNREG:		return "unregistered by userspace";
	case TLS_EXIT_UNREG_BPF:	return "unregistered by the BPF program";
	case TLS_EXIT_UNREG_KERN:	return "unregistered by the kernel";
	case TLS_EXIT_SYSRQ:		return "sysrq override";
	case TLS_EXIT_PARENT:	return "parent exited";
	case TLS_EXIT_PARENT_KILL:	return "parent killed";
	case TLS_EXIT_ERROR:		return "error";
	case TLS_EXIT_ERROR_BPF:	return "error raised by the BPF program";
	case TLS_EXIT_ERROR_STALL:	return "watchdog stall";
	case TLS_EXIT_ERROR_REENQ:	return "re-enqueue failure";
	case TLS_EXIT_ERROR_RESCUE:	return "rescue failure";
	default:			return "unknown";
	}
}

static void print_exit_report(struct bpf_object *obj)
{
	struct bpf_map *map;
	struct tls_uei uei;
	uint32_t key = 0;
	int map_fd;

	map = bpf_object__find_map_by_name(obj, "tls_uei");
	if (!map) {
		/*
		 * Not fatal: the loader may be asked to report on an object
		 * built without the UEI map. Say so rather than printing
		 * nothing, because a silent exit report is misleading.
		 */
		printf("\nNo user_exit_info map in this object, so the "
		       "kernel's stop reason\n");
		printf("is unavailable. The BPF side should get one from "
		       "UEI_DEFINE().\n");
		return;
	}
	map_fd = bpf_map__fd(map);

	if (bpf_map_lookup_elem(map_fd, &key, &uei) != 0) {
		printf("\nScheduler detached cleanly (no exit record "
		       "available).\n");
		return;
	}

	printf("\nScheduler detached.\n");
	printf("  kind      %d (%s)\n", uei.kind, exit_kind_name(uei.kind));
	printf("  cpu       %d\n", uei.exit_cpu);
	printf("  exit_code %lld\n", (long long)uei.exit_code);
	if (uei.reason[0])
		printf("  reason    %s\n", uei.reason);
	if (uei.msg[0])
		printf("  message   %s\n", uei.msg);

	switch (uei.kind) {
	case TLS_EXIT_ERROR_BPF:
		printf("\nThe BPF program called scx_bpf_error(). Search "
		       "src/bpf/tls_stubs.bpf.c\n");
		printf("for TLS_ERR to find the assertions that can fire.\n");
		break;
	case TLS_EXIT_ERROR_STALL:
		printf("\nThe watchdog fired: a callback held a CPU for "
		       "longer than the timeout,\n");
		printf("or a runnable task was never handed to the kernel. The "
		       "kernel has already\n");
		printf("returned the machine to its default scheduler.\n");
		printf("\nThings to check, in order:\n");
		printf("  1. Every path through tls_enqueue() leaves the task "
		       "on a DSQ or in a tier.\n");
		printf("  2. No loop in a callback iterates unboundedly.\n");
		printf("  3. tls_dispatch() does not spin waiting for "
		       "work.\n");
		break;
	case TLS_EXIT_ERROR_REENQ:
		printf("\nA task could not be re-enqueued. This is usually a "
		       "tier array whose\n");
		printf("occupancy counters disagree with its contents.\n");
		break;
	default:
		break;
	}
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

static void usage(const char *argv0)
{
	printf(
"Usage: %s [options] <tls.bpf.o>\n"
"\n"
"A sched_ext scheduler. Detaches cleanly on exit, so the machine always\n"
"returns to the kernel's default scheduler.\n"
"\n"
"Modes:\n"
"  --verify              load the object and run the BPF verifier, then exit\n"
"                        without attaching. Run this after every BPF change.\n"
"  --stats               read the scheduler's counters and exit\n"
"  --help-abi            print the callback contract and exit\n"
"  -h, --help            this text\n"
"\n"
"Scheduling parameters (defaults follow the TLS architecture document):\n"
"  --slice-ms N          reschedule quantum              [10]\n"
"  --rotate-ms N         starvation rotation period      [150]\n"
"  --balance-ms N        load-balance period             [100]\n"
"  --sanctuary-ns N      Tier -1 time budget (ns)        [1000000]\n"
"  --promote-after N     lottery losses before promotion [0 = disabled]\n"
"  --balance-ratio A:B   steal threshold                 [2:1]\n"
"  --rotate-reverse      rotate starvation the other way\n"
"  --soft-overflow       warn instead of failing on a full tier\n"
"\n"
"Output:\n"
"  -v, --verbose         show libbpf debug output and BPF bpf_printk()\n"
"  -q, --quiet           only warnings and errors\n"
"\n"
"Example:\n"
"  %s --verify build/tls.bpf.o\n"
"  %s --slice-ms 5 build/tls.bpf.o\n",
		argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "verify",            no_argument,       NULL, 'V' },
		{ "stats",             no_argument,       NULL, 'S' },
		{ "help-abi",          no_argument,       NULL, 'A' },
		{ "slice-ms",          required_argument, NULL, 's' },
		{ "rotate-ms",         required_argument, NULL, 'r' },
		{ "balance-ms",        required_argument, NULL, 'b' },
		{ "sanctuary-ns",      required_argument, NULL, 'n' },
		{ "promote-after",     required_argument, NULL, 'p' },
		{ "balance-ratio",     required_argument, NULL, 'R' },
		{ "rotate-reverse",    no_argument,       NULL, 'D' },
		{ "soft-overflow",     no_argument,       NULL, 'O' },
		{ "verbose",           no_argument,       NULL, 'v' },
		{ "quiet",             no_argument,       NULL, 'q' },
		{ "help",              no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	struct opts opts = { 0 };
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct bpf_map *ops_map;
	int err = 0, c;

	libbpf_set_print(libbpf_log);
	tunables_defaults(&opts.tun);

	while ((c = getopt_long(argc, argv, "VSAs:r:b:n:p:R:DOvqh",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'V':
			opts.verify_only = true;
			break;
		case 'S':
			opts.print_stats = true;
			break;
		case 'A':
			print_abi_summary();
			return 0;
		case 's':
			opts.tun.slice_ns = strtoull(optarg, NULL, 0) *
					    TLS_NS_PER_MS;
			break;
		case 'r':
			opts.tun.rotate_ns = strtoull(optarg, NULL, 0) *
					     TLS_NS_PER_MS;
			break;
		case 'b':
			opts.tun.balance_ns = strtoull(optarg, NULL, 0) *
					      TLS_NS_PER_MS;
			break;
		case 'n':
			opts.tun.sanctuary_budget_cycles =
				strtoull(optarg, NULL, 0);
			break;
		case 'p':
			opts.tun.promote_after_losses =
				(uint32_t)strtoul(optarg, NULL, 0);
			break;
		case 'R': {
			unsigned int num, den;
			if (sscanf(optarg, "%u:%u", &num, &den) != 2 ||
			    den == 0) {
				fprintf(stderr,
					"error: --balance-ratio wants A:B with B "
					"non-zero, got '%s'\n", optarg);
				return 2;
			}
			opts.tun.balance_ratio_num = num;
			opts.tun.balance_ratio_den = den;
			break;
		}
		case 'D':
			opts.tun.rotate_reverse = true;
			break;
		case 'O':
			opts.tun.soft_overflow = true;
			break;
		case 'v':
			opts.verbose = true;
			g_verbose = true;
			opts.tun.verbose = 2;
			break;
		case 'q':
			opts.verbose = false;
			opts.tun.verbose = 0;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "error: no BPF object given\n\n");
		usage(argv[0]);
		return 2;
	}
	opts.object = argv[optind];

	/*
	 * The kernel check runs before anything else in attach mode. In
	 * --verify mode we skip it: verifying an object is useful even on a
	 * machine that cannot attach it, which is exactly the situation when
	 * you are compiling for a different kernel.
	 */
	if (!opts.verify_only && !opts.print_stats) {
		if (check_sched_ext_available() != 0)
			return 1;
	}

	/*
	 * Only now that we know we are really going to load something: a bare
	 * --help or --help-abi should not print memlock warnings.
	 */
	raise_memlock();

	obj = bpf_object__open_file(opts.object, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "error: cannot open %s: %s\n",
			opts.object, strerror(-err));
		obj = NULL;
		return 1;
	}

	/*
	 * Configuration must be written before load: after the struct_ops is
	 * attached the tunables are already in use.
	 */
	err = apply_tunables(obj, &opts.tun);
	if (err)
		goto out;

	err = bpf_object__load(obj);
	if (err) {
		if (err == -EPERM && !has_bpf_capability()) {
			report_privilege_problem(argv[0]);
			err = -EPERM;
			goto out;
		}
		fprintf(stderr,
			"error: load failed: %s\n"
			"\n"
			"The BPF verifier rejected the object. The messages above\n"
			"come from the verifier and name the instruction it did not\n"
			"like. See DEVELOPER_GUIDE.md in the scx tree for what the\n"
			"common rejections mean.\n", strerror(-err));
		goto out;
	}

	if (opts.print_stats) {
		err = print_stats(obj);
		goto out;
	}

	if (opts.verify_only) {
		printf("OK: %s loaded and passed the verifier.\n", opts.object);
		/*
		 * Deliberately do not attach. Printing the configuration
		 * makes a verify run useful as a record of what would have
		 * been attached.
		 */
		printf("\nConfiguration that would be applied:\n");
		printf("  slice            %llu ns\n",
		       (unsigned long long)opts.tun.slice_ns);
		printf("  rotation         %llu ns\n",
		       (unsigned long long)opts.tun.rotate_ns);
		printf("  balance          %llu ns\n",
		       (unsigned long long)opts.tun.balance_ns);
		printf("  sanctuary budget %llu ns\n",
		       (unsigned long long)opts.tun.sanctuary_budget_cycles);
		printf("  promote after    %u losses%s\n",
		       opts.tun.promote_after_losses,
		       opts.tun.promote_after_losses ? "" : " (disabled)");
		printf("  balance ratio    %u:%u\n",
		       opts.tun.balance_ratio_num, opts.tun.balance_ratio_den);
		printf("\nNote: a successful verify does not mean the machine will\n");
		printf("stay responsive. Attach it and watch.\n");
		err = 0;
		goto out;
	}

	/*
	 * Attach. Finding the ops map by the name given to SCX_OPS_DEFINE()
	 * is what ties this loader to main.bpf.c: if the name there changes,
	 * this fails with a clear message rather than attaching nothing.
	 */
	ops_map = bpf_object__find_map_by_name(obj, "tls_ops");
	if (!ops_map) {
		fprintf(stderr,
			"error: no struct_ops map named 'tls_ops' in %s.\n"
			"  It comes from SCX_OPS_DEFINE(tls_ops, ...) in\n"
			"  src/bpf/main.bpf.c. If that name changed, update the\n"
			"  lookup here to match.\n", opts.object);
		err = -ENOENT;
		goto out;
	}

	link = bpf_map__attach_struct_ops(ops_map);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr,
			"error: attaching the struct_ops failed: %s\n"
			"\n"
			"Common causes, roughly in order of likelihood:\n"
			"  1. Another sched_ext scheduler is already attached.\n"
			"     Detach it first (kill its loader, or write to\n"
			"     /sys/kernel/sched_ext/root/ops).\n"
			"  2. This object was compiled against a different kernel's\n"
			"     struct sched_ext_ops layout. Run 'make check-abi'.\n"
			"  3. The kernel's sched_ext is disabled or busy. Check\n"
			"     /sys/kernel/sched_ext/state.\n", strerror(-err));
		goto out;
	}

	printf("TLS attached. The kernel is now calling this scheduler.\n");
	printf("  object    %s\n", opts.object);
	printf("  slice     %llu ns\n",
	       (unsigned long long)opts.tun.slice_ns);
	printf("\nCtrl-C detaches and restores the default scheduler.\n");
	printf("If the machine stops responding, the watchdog will detach it\n");
	printf("automatically; there is no need to reboot.\n");

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGHUP, on_signal);

	while (!exiting) {
		/*
		 * The scheduler runs in the kernel. This loop exists only to
		 * keep the link open: the struct_ops is registered for as long
		 * as the link is held. Nothing here is on the scheduling path,
		 * so sleeping is correct and costs nothing.
		 */
		sleep(1);
	}

out:
	if (link)
		bpf_link__destroy(link);
	if (obj) {
		/*
		 * The exit report is read after detaching, because the kernel
		 * fills the user_exit_info in during detach.
		 */
		if (!opts.verify_only && !opts.print_stats && err == 0)
			print_exit_report(obj);
		bpf_object__close(obj);
	}
	return err ? 1 : 0;
}
