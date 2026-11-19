# TLS — a sched_ext scheduler skeleton

Tiered Lottery Scheduler for x86_64, as a bare C BPF sched_ext scheduler.

**This tree is a prepared workspace, not an implementation.** The scheduling
policy is deliberately absent. Every kernel-facing callback exists, compiles,
and carries a contract describing exactly what it must do; the bodies either
provide a safe functional default or stop at a clearly marked `TODO`. Your job
is to fill in the policy.

```
src/include/tls_intf.h             types, tier geometry, tunables  (the contract)
src/include/tls_structures.bpf.h   maps, storage, accessors        (the plumbing)
src/include/tls_bpf_impl.h         tier/lottery mechanism          (no policy)
src/bpf/main.bpf.c                 one translation unit + the ops table
src/bpf/tls_core.bpf.c             >>> THE 26 CALLBACKS YOU IMPLEMENT <<<
userspace/tls.c                    libbpf loader, exit report
scripts/                           BTF reading, vmlinux.h, ABI checking
```

---

## The one thing to read first

`src/bpf/tls_core.bpf.c`. It opens with an inventory table of all 26
callbacks and a numbered implementation order. Work through it top to bottom.
Steps 1–4 of that order produce a scheduler that boots and runs.

Each callback states:

| | |
|---|---|
| `WHEN CALLED` | the exact kernel context, and whether blocking is allowed |
| `ARGS` | what each parameter means and what is valid to read |
| `RETURN` | the meaning of every return value |
| `DEFAULT` | what the body currently does |
| `MUST` | invariants that break the machine if violated |
| `IMPLEMENT` | what you are expected to add |

---

## Build

```sh
make            # build/tls.bpf.o (the scheduler) and build/tls (loader)
make check-env  # toolchain, target kernel, sched_ext availability
make check-abi  # does the object's struct_ops match the target kernel?
make verify     # load and run the BPF verifier, then detach (no attach)
make run        # attach (needs root) — Ctrl-C restores the default scheduler
```

`make help` lists everything, including the `VMLINUX_H=`, `BTF=`, `SCX_DIR=`
and `CLANG=` overrides.

### Requirements

- `clang` and `llvm-objdump` (LLVM 15+; 19 verified)
- `libbpf` — `libbpf-dev` is the clean way, runtime `libbpf.so.1` also works
- **`bpftool`** — needed to generate `vmlinux.h` from a kernel. Without it the
  build falls back to the `vmlinux.h` vendored in the scx checkout, which is
  fine for developing but is not ABI-valid for the machine you are on.
- `python3` (3.8+), used for the ABI tooling; no third-party modules
- the `scx` checkout, at `../scx` by default, for `scheds/include/`
- a kernel with `CONFIG_SCHED_CLASS_EXT=y` to actually run it

```sh
sudo apt install clang llvm libbpf-dev bpftool    # Debian/Ubuntu
```

---

## The kernel prerequisite, stated plainly

sched_ext is compiled into the kernel. There is no module to load and no
runtime switch. Check before anything else:

```sh
grep CONFIG_SCHED_CLASS_EXT /boot/config-$(uname -r)
ls /sys/kernel/sched_ext/state
```

Both must succeed. If the config option is unset, the kernel has no
`struct sched_ext_ops`, no `scx_bpf_*` kfuncs, and no
`/sys/kernel/sched_ext`; nothing built here can attach, and `make` will report
it during `vmlinux.h` generation.

If you are reading this because the machine you are on **cannot** run the
scheduler, see *Building for a different kernel* below. You can still write and
compile the whole scheduler on such a machine.

---

## Building for a different kernel

`vmlinux.h` defines `struct sched_ext_ops`, so it decides the ABI. The Makefile
resolves it in this order:

1. **`VMLINUX_H=<path>`**, or an existing `build/vmlinux/vmlinux.h`. Never
   overridden. Use this to build for a kernel other than the running one.
2. **Generated from the running kernel's BTF.** The correct default.
3. **The `vmlinux.h` vendored in the scx checkout.** Used only if step 2 cannot
   run — because the kernel has no sched_ext, or because `bpftool` is missing —
   so that the tree still compiles on a machine that cannot run it. The build
   prints a loud warning and records the choice in
   `build/vmlinux/PROVENANCE`, which `make check-env` reports as
   `header source`.

Hint: the scx checkout's own `vmlinux.h` is from Linux 7.3-rc5. Recent kernels
have grown sched_ext members (`sub_attach`, `init_cids`, `cid_shard_size`, …),
so an object built against it will not match a 6.12 kernel. `make check-abi`
will say so, which is the point of having it.

### About the built-in header generator

`scripts/gen_vmlinux_h.py` can read BTF itself, without `bpftool`, and its
`--check-only` mode is genuinely useful: it tells you whether a given kernel
has sched_ext, listing the missing types by name. That is the check the
Makefile runs.

Its header *emission* is a partial fallback, and is opt-in behind
`--allow-incomplete-emitter`. It understands the sched_ext ABI and the core
scheduling types, including function pointers, bitfields, anonymous members,
`enum64` and typedefs of anonymous structs, but it does not handle the whole
kernel type graph — mutually recursive incomplete types, `atomic_t`-style
typedef collisions and arrays of incomplete elements defeat it, so its output
does not compile as a complete `vmlinux.h`. `bpftool` does not have this
problem and is the supported path. The script refuses to use the incomplete
emitter unless you ask for it, rather than silently producing a header of
unknown quality.

An object built via step 3 is useful for development and **is not ABI-valid for
the machine that produced it**. Rebuild on the target before running:

```sh
rm -rf build && make
```

To cross-build from another machine, copy the target's BTF over:

```sh
scp target:/sys/kernel/btf/vmlinux ./target.btf
make BTF=./target.btf
```

---

### Why the ABI check matters

The kernel matches struct_ops members by offset, not by name. If the object was
built against a different layout, the attach can *succeed* and the kernel then
calls whatever function pointer sits at the offset it expects. Your `enqueue`
runs where `dispatch` was meant to. That presents as a scheduler logic bug, and
you lose a day reading the wrong code.

`make check-abi` compares the layout embedded in the compiled object against
the target kernel's BTF and reports every difference. Exit codes: `0`
compatible, `1` incompatible, `2` could not run, `3` the kernel has no
sched_ext.

---

## Running it

```sh
sudo ./build/tls build/tls.bpf.o     # or: sudo make run
```

The loader holds a `bpf_link` to the struct_ops for as long as it runs. Ctrl-C
detaches and the kernel's default scheduler resumes; this does not depend on
the process cleaning up gracefully, so the machine always comes back.

Tunables are command-line options and match `struct tls_tunables`:

```sh
./build/tls --help
./build/tls --slice-ms 5 --rotate-ms 100 build/tls.bpf.o
./build/tls --verify build/tls.bpf.o    # verifier only, never attaches
./build/tls --help-abi                     # the callback contract, in full
```

When the scheduler stops, the loader decodes `user_exit_info` and says whether
it was a clean detach, a BPF error, a watchdog stall, or a sysrq override, with
the likely cause for each.

---

## What is provided, and what is not

**Provided** — the mechanism, with no policy decisions baked in:

- Tier geometry for Sanctuary/Anchor/High/Medium/Low/Background, with the
  signed tier index handled by `tls_tier_slot()`
- Per-CPU runqueues (`struct tls_tier` arrays) with push, swap-and-pop
  removal, and unlink
- The ticket accounting *plumbing*: `weights[]` per CPU, `total_tickets`,
  per-tier counts, and a recount that recomputes totals from the weights
- The `Winning_Ticket` arithmetic helper and a PRNG-scaled draw helper
- Per-task and per-CPU storage maps
- A working `enqueue` default (push to tier, fall back to Anchor then the local
  DSQ) so the scheduler is functional before you write any policy
- A complete, working `dump` / `dump_cpu` / `dump_task` — the fastest way to
  see what your lottery is doing
- The loader, the ABI checker, and the build system

**Not provided** — this is your work:

- The lottery draw itself (`tls_dispatch`, and the draw in `tls_enqueue`)
- Boundary walking and index division across tiers
- The starvation rotation permutation in `tls_tick`
- Batch stealing and victim selection
- Load-factor placement on wakeup in `tls_wakeup_select_cpu`
- The xorshift step and its seeding policy

`src/include/tls_bpf_impl.h` carries an explicit
`MECHANISM / POLICY BOUNDARY` section listing what must stay out of it.

---

## Two substitutions worth knowing about

The architecture document specifies hardware instructions that BPF cannot
execute. Both substitutes are deliberate and should be justified in the thesis:

| Document | BPF reality | Substitute |
|---|---|---|
| `RDTSC` for the Sanctuary cycle budget | no inline asm, no `RDTSC` from BPF | `bpf_ktime_get_ns()`, a nanosecond budget |
| `RDRAND`/`RDSEED` for lottery entropy | not callable | `bpf_get_prandom_u32()` |

`bpf_get_prandom_u32()` is a fast per-CPU PRNG, not a CSPRNG. For a lottery
that only needs to be fair and unpredictable enough to avoid pathological
correlation, it is the intended tool; the thesis should say so rather than
imply hardware entropy.

---

## Developing

See [`DEVELOPING.md`](DEVELOPING.md) for the edit/build/verify loop, how to
read a verifier rejection, how to make the machine come back if a scheduler
hangs it, and the three ways this scheduler will hang your machine.
