# Developing TLS

A practical guide to the edit → build → verify → attach loop, and to not
hanging your machine while you are in it.

The full callback contract lives at the top of
[`src/bpf/tls_stubs.bpf.c`](src/bpf/tls_stubs.bpf.c). This file is the
workflow; that file is the specification.

---

## The loop

```sh
make                     # compile the object and the loader
make check-abi           # struct_ops layout still matches the target kernel
make verify              # run the BPF verifier, do not attach
sudo make run            # attach; Ctrl-C detaches
```

`make verify` is the important one. The verifier rejects the object *before* it
can become the scheduler, and its message names the instruction it disliked.
Every minute spent getting `make verify` clean is a minute not spent rebooting.

Run `make check-abi` after any change that touches the ops table, the tunables
struct, or `vmlinux.h`. It is cheap and it catches the one class of bug that
otherwise presents as inexplicable scheduler behaviour.

---

## The toolbox for when something is wrong

`scx_bpf_dump()` is the primary debugging tool, wired up in
`tls_dump()`, `tls_dump_cpu()` and `tls_dump_task()`. Those three are
already complete and working: they print tunables, per-CPU tier occupancy,
ticket totals, load factors, and per-task accounting.

Trigger a dump with:

```sh
cat /sys/kernel/sched_ext/root/ops     # current state
echo 1 > /proc/sys/kernel/sysrq        # if sysrq is restricted
```

and read the result in `dmesg`. A dump on a stall is produced automatically.

Two constraints on `scx_bpf_dump()`:

- It is variadic through the `bpf_printk()` machinery, which is **capped at
  about 12 arguments**. An oversized call is a compile error, not a silent
  truncation, so you will find out immediately — but the fix is to split the
  call, which the existing dump functions demonstrate.
- Output is truncated by `exit_dump_len` (default 32768). Put the interesting
  part first; a truncated dump hides the end.

Avoid calling `scx_bpf_dump()` inside hot scheduling callbacks (`tls_enqueue`,
`tls_dispatch`, `tls_tick`); trigger dumps on demand or on exit/stall instead.

---

## Three ways this scheduler will hang your machine

### 1. A runnable task is never handed to the kernel

Every task passed to `tls_enqueue()` must end up either in a tier array or
on a DSQ. Dropping one means a runnable task the kernel never sees.

This is the single most likely bug, because a tier array can be full, a lookup
can fail, and it is easy to write a `return` on a path that should have fallen
back. The current `tls_enqueue()` default shows the fallback chain:
tier → `TIER_ANCHOR` → `SCX_DSQ_LOCAL`. Keep that shape.

Symptom: the machine stops responding, and about 5 seconds later the watchdog
detaches the scheduler and reports `SCX_EXIT_ERROR_STALL`. The machine comes
back on its own — that is what `timeout_ms` is for.

### 2. A task is handed to the kernel twice, or `ctx->linked` disagrees with the arrays

`tc->linked` and the tier arrays must never disagree. `tls_tier_push()`
sets the flag and `tls_tier_remove_task()` clears it; do not manipulate
`tc->linked` by hand.

Symptom: corrupted tier arrays. It usually appears much later as a wild
pointer, a verifier rejection on the next build, or a task that appears in two
tiers at once and is then dispatched twice.

### 3. Blocking in a callback

No callback in `struct sched_ext_ops` may sleep. Do not take a mutex, do not
allocate, do not call anything that waits. `tls_init()` is the exception in
some kernel versions; check the `WHEN CALLED` block for the specific callback
before assuming.

Symptom: the verifier rejects the object at load time, naming the helper you
called. This is the good outcome.

---

## If it hangs anyway

The scheduler detaches itself when the watchdog fires, so **usually you only
have to wait about five seconds.** `timeout_ms` is set by
`TLS_OPS_TIMEOUT_MS` in `src/bpf/main.bpf.c`; raise it to debug a slow
startup, lower it to fail faster.

If it does not come back:

1. `Ctrl-C` the loader. The `bpf_link` closes and the kernel reverts to its
   default scheduler. This works even if your BPF code is wedged, because the
   link is closed by the kernel, not by your code.
2. If you have a second shell, kill the loader by PID: `sudo pkill tls`.
3. If the machine is unresponsive, use sysrq:
   `Alt`+`SysRq`+`I` (kill all tasks except init), then `Alt`+`SysRq`+`B`
   (reboot). Over a serial console, `echo i > /proc/sysrq-trigger`.
4. Nothing here can leave the machine permanently unbootable. sched_ext state
   does not survive a reboot, because the scheduler only exists while the
   loader holds the link.

When testing a new idea, prefer a VM or a spare machine for the first attach.

---

## Reading a verifier rejection

`make verify` output comes in two parts: libbpf's, then the verifier's. The
useful part is the verifier's, which looks like:

```
0: R1=ctx() R10=fp0
...
; src/bpf/tls_stubs.bpf.c:812
19: (85) call bpf_ktime_get_ns#5
R0 invalid mem access 'scalar'
```

Read it bottom-up: the last line is the complaint, the line above is the
instruction, and the line above that is the source line. The register
annotations say what the verifier believed about each register at that point —
usually the answer is that something could be NULL and you did not check.

The three rejections you are most likely to hit here:

| Message | Cause |
|---|---|
| `invalid mem access` | a map lookup returned NULL and the result was used; check the pointer |
| `not allowed to call` / `unknown func` | a `scx_bpf_*` kfunc this kernel does not have, usually a version mismatch |
| `back-edge` / `loop is not bounded` | a loop whose bound the verifier cannot prove; use a compile-time constant bound, as the existing loops do |

`bpf_for()` open-coded iterators work on newer kernels, but the stubs use plain
bounded `for` loops so that nothing depends on a kernel feature you may not
have.

---

## The implementation order, and why it is that order

From the stub file header, repeated here because it is the plan:

| Step | Function | What it unlocks |
|---|---|---|
| 1 | `tls_init` | per-CPU structures, weight table |
| 2 | `tls_init_task` | per-task state, initial tier |
| 3 | `tls_enqueue` | park the task in a tier |
| 4 | `tls_dispatch` | hand a task to the local DSQ |
| | | **steps 1–4 = a functional scheduler** |
| 5 | `tls_tick` | the 10 ms quantum and demotion |
| 6 | `tls_wakeup_select_cpu` | passive load placement on wakeup |
| 7 | `tls_running` | slice start accounting |
| 8 | the lottery draw | O(1) winner selection |
| 9 | the starvation rotation | the 150 ms weight permutation |
| 10 | the load balancer | bottom-up batch stealing |

**Do not write the lottery first.** A broken lifecycle and a broken lottery
both present as a hang, and a hang tells you nothing about which one it is.

After step 4, attach the scheduler and confirm the machine stays responsive.
Only then start on the policy. Every step after 4 is an independently
measurable improvement, which is also what makes it a good thesis structure:
each step is one experiment.

---

## Measuring

Record per experiment that the machine stayed responsive, along with any
state dumps and exit reports:

```sh
cat /sys/kernel/sched_ext/root/ops            # what is attached
dmesg | tail -50                              # dumps and watchdog reports
```

The policy callbacks do not keep extra event statistics counters (`tls_stats`)
to avoid hot-path overhead; only the live scheduler state required by the
algorithm (per-tier `nr`, `total_tickets`, `load_factor`, and `weights[]`) is
maintained.

---

## The mechanism/policy boundary

`src/include/tls_bpf_impl.h` provides the tier arrays, ticket accounting and
task linking. It deliberately contains **no policy**, and carries a
`MECHANISM / POLICY BOUNDARY` section listing what must stay out of it.

The structure to preserve:

- `tls_intf.h` — *what exists*: types, geometry, tunables. No logic.
- `tls_bpf_impl.h` — *how the data structures work*: push, remove, link,
  recount. No decisions.
- `tls_stubs.bpf.c` — *what the scheduler decides*. All your policy.

If you find yourself adding a decision to `tls_bpf_impl.h`, it belongs in a
stub instead. Keeping that line clean is what makes the tiers testable and the
thesis defensible: the mechanism is fixed, and the experiments vary only the
policy.
