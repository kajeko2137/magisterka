#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
check_abi.py - verify that a compiled sched_ext object matches a kernel.

WHY THIS EXISTS
---------------
A sched_ext scheduler is a BPF struct_ops object. The kernel takes the
`struct sched_ext_ops` instance the object defines and matches it, member by
member and offset by offset, against the layout in its own BTF. Nothing about
that match is checked by name at run time.

The failure mode is therefore unusually nasty. When the object was compiled
against a different kernel's layout, one of three things happens:

  1. The attach fails, sometimes with an error that mentions a member name,
     sometimes not. This is the good outcome.

  2. The attach succeeds. The kernel then calls whatever function pointer
     happens to live at the offset it expects. Your `enqueue` gets called
     where `dispatch` was meant to be, the scheduler misbehaves in a way that
     looks like a logic bug, and you spend a day reading the wrong code.

  3. The struct is smaller than the kernel's. The kernel reads members past
     the end of your object and calls garbage. On a uniprocessor VM this
     sometimes appears to work.

This script exists to turn all three into a clear, up-front report.

HOW IT WORKS
------------
It reads `struct sched_ext_ops` out of two places and compares them:

  - the kernel's BTF (from /sys/kernel/btf/vmlinux by default), which is the
    authority, and
  - the BTF that clang embedded in the compiled object, which records the
    layout the object was actually built against.

Comparing the object's embedded BTF rather than the header text is deliberate:
it is the truth about what was compiled, after all the preprocessing, inlining
and record-layout decisions, and it is unaffected by which -I order or
vmlinux.h was in play.

It also checks the callback inventory: every function pointer the object
populates must exist as a member of the kernel's struct, because a populated
member the kernel has never heard of is silently ignored, and a kernel member
the object leaves empty may be mandatory.

EXIT CODES
----------
  0  the layouts are compatible
  1  the layouts differ (details on stdout)
  2  the check could not run (missing input, unreadable BTF)
  3  the kernel has no sched_ext, so there is nothing to compare against
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import subprocess
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import btf as btfmod  # noqa: E402

OPS_STRUCT = "sched_ext_ops"

# Members the design relies on. Used only to phrase the report usefully; a
# missing member is reported whether or not it is in this list.
CALLBACK_MEMBERS = {
    "select_cpu", "enqueue", "dequeue", "dispatch", "tick", "runnable",
    "running", "stopping", "quiescent", "yield", "set_weight", "set_cpumask",
    "update_idle", "init_task", "exit_task", "enable", "disable", "dump",
    "dump_cpu", "dump_task", "cpu_online", "cpu_offline", "cpu_acquire",
    "cpu_release", "init", "exit", "cgroup_init", "cgroup_exit",
    "cgroup_prep_move", "cgroup_move", "cgroup_cancel_move",
    "cgroup_set_weight",
}


class ObjectBTF:
    """
    Reads BTF out of a compiled BPF object, the way libbpf does.

    The BTF may live in a section called .BTF (the normal case for a clang
    -g build) or be embedded in a split BTF form we do not need here.
    """

    def __init__(self, path: str):
        self.path = path
        self.blob = self._extract()

    def _extract(self) -> bytes:
        with open(self.path, "rb") as fh:
            data = fh.read()

        if data[:4] == b"\x7fELF":
            return self._from_elf(data)

        # A raw .BTF file, possibly compressed.
        for name, fn in (("gzip", lambda b: zlib.decompress(b, 31)),
                         ("zlib", zlib.decompress)):
            try:
                return fn(data)
            except Exception:
                pass
        return data

    def _from_elf(self, data: bytes) -> bytes:
        if data[4] != 2 or data[5] != 1:
            raise SystemExit(f"{self.path}: not a little-endian ELF64 file")

        e_shoff, = struct.unpack_from("<Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)

        sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                struct.unpack_from("<IIQQQQ", data, off)
            sections.append((sh_name, sh_type, sh_offset, sh_size))

        if e_shstrndx >= len(sections):
            raise SystemExit(f"{self.path}: bad section name table index")
        _, _, str_off, str_size = sections[e_shstrndx]
        shstrtab = data[str_off:str_off + str_size]

        for sh_name, sh_type, sh_offset, sh_size in sections:
            end = shstrtab.find(b"\0", sh_name)
            name = shstrtab[sh_name:end].decode("utf-8", "replace")
            if name == ".BTF":
                return data[sh_offset:sh_offset + sh_size]

        raise SystemExit(
            f"{self.path}: no .BTF section.\n"
            "  The object was built without debug information, so there is\n"
            "  nothing to compare. Rebuild with -g (the Makefile always does).")


def load_kernel_btf(path: str):
    """Read a kernel BTF file, transparently decompressing it."""
    with open(path, "rb") as fh:
        data = fh.read()

    # /sys/kernel/btf/vmlinux is raw BTF; a saved copy is often gzipped.
    if data[:2] == b"\x1f\x8b":
        data = zlib.decompress(data, 31)

    return data


def member_offsets(btf, struct_name: str):
    """
    Return {member_name: (bit_offset, bitfield_bits)} for a struct.

    Raises KeyError if the struct is absent.
    """
    t = btf.by_name(struct_name)
    if t is None:
        raise KeyError(struct_name)

    out = {}
    for m in t.members:
        # Anonymous members (empty name) are legal in the kernel's structs.
        # They are reported under a synthetic name so they still show up in a
        # diff rather than silently disappearing.
        name = m.name if m.name else f"<anonymous@{m.offset_bits}>"
        bits = m.offset_bits >> 24
        off = m.offset_bits & 0xFFFFFF
        out[name] = (off, bits)
    return out, t


def describe_diff(kernel, obj, label_k: str, label_o: str):
    """Print a member-by-member comparison. Returns True if equal."""
    same = True
    all_names = list(kernel.keys())
    for n in obj:
        if n not in kernel:
            all_names.append(n)

    print(f"\n  {'member':<24} {label_k:>12} {label_o:>12}  status")
    print(f"  {'-' * 24} {'-' * 12} {'-' * 12}  ------")

    for name in all_names:
        k = kernel.get(name)
        o = obj.get(name)

        if k is None:
            print(f"  {name:<24} {'(absent)':>12} {o[0]:>12}  "
                  "EXTRA in object")
            same = False
            continue
        if o is None:
            note = ""
            if name in CALLBACK_MEMBERS:
                note = "MISSING in object (a callback!)"
            else:
                note = "missing in object"
            print(f"  {name:<24} {k[0]:>12} {'(absent)':>12}  {note}")
            same = False
            continue

        k_off, k_bits = k
        o_off, o_bits = o
        if k_off != o_off or k_bits != o_bits:
            detail = f"{o_off} ({o_bits} bits)" if o_bits else str(o_off)
            expect = f"{k_off} ({k_bits} bits)" if k_bits else str(k_off)
            print(f"  {name:<24} {expect:>12} {detail:>12}  "
                  "OFFSET MISMATCH")
            same = False
        else:
            flag = ""
            if name in CALLBACK_MEMBERS:
                flag = "callback"
            print(f"  {name:<24} {k_off:>12} {o_off:>12}  "
                  f"ok{(' - ' + flag) if flag else ''}")

    return same


def inventory_report(btf_ops, object_members):
    """
    Report populated callbacks that the kernel's struct does not have.

    A populated member the kernel does not know about is silently dropped at
    load time: the callback is never called and nothing says so. This is worth
    an explicit warning because a scheduler whose `enqueue` is silently
    dropped hangs the machine.
    """
    # Members that are configuration, not callbacks. They are populated by
    # SCX_OPS_DEFINE and are not interesting in a callback inventory.
    prelude = {"dispatch_max_batch", "flags", "timeout_ms", "exit_dump_len",
               "hotplug_seq", "name", "priv", "rescue_bandwidth_ppt",
               "rescue_quantum_us", "cid_shard_size", "sub_cgroup_id"}
    unknown = []
    for name in object_members:
        if name.startswith("<anonymous@") or name in prelude:
            continue
        if name not in btf_ops:
            unknown.append(name)

    if unknown:
        print("\n  Populated members the kernel's struct does not have:")
        for n in sorted(unknown):
            print(f"    - {n}")
        print("  These will be ignored at load time, silently.")
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compare a compiled sched_ext object's struct_ops "
                    "layout against a kernel's BTF.")
    ap.add_argument("--btf", default="/sys/kernel/btf/vmlinux",
                    help="kernel BTF (default: /sys/kernel/btf/vmlinux)")
    ap.add_argument("--object", required=True,
                    help="compiled BPF object with a .BTF section")
    ap.add_argument("--header", default=None,
                    help="the vmlinux.h used to build it, for the report only")
    ap.add_argument("--objdump", default=None,
                    help="llvm-objdump, used to list populated members")
    ap.add_argument("--struct", default=OPS_STRUCT,
                    help=f"struct to compare (default: {OPS_STRUCT})")
    args = ap.parse_args()

    # --- the object's view ------------------------------------------------
    try:
        obj_blob = ObjectBTF(args.object).blob
        obj_btf = btfmod.BTF(obj_blob)
    except SystemExit as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except btfmod.BTFError as e:
        print(f"error: cannot parse the object's BTF: {e}", file=sys.stderr)
        return 2

    try:
        obj_members, obj_type = member_offsets(obj_btf, args.struct)
    except KeyError:
        print(f"error: {args.object} has no {args.struct} in its BTF.\n"
              f"  Either the object was built without the struct_ops table, "
              f"or\n  the struct has a different name.",
              file=sys.stderr)
        return 2

    # --- the kernel's view ------------------------------------------------
    if not os.path.exists(args.btf):
        print(f"error: no kernel BTF at {args.btf}", file=sys.stderr)
        print("  Point --btf at the target kernel's "
              "/sys/kernel/btf/vmlinux.", file=sys.stderr)
        return 2

    try:
        kblob = load_kernel_btf(args.btf)
        kbtf = btfmod.BTF(kblob)
    except Exception as e:
        print(f"error: cannot parse {args.btf}: {e}", file=sys.stderr)
        return 2

    try:
        k_members, k_type = member_offsets(kbtf, args.struct)
    except KeyError:
        print("=" * 72)
        print("THIS KERNEL HAS NO SCHED_EXT")
        print("=" * 72)
        print(f"\n{args.btf} does not define `struct {args.struct}`.")
        print("The kernel was built without CONFIG_SCHED_CLASS_EXT, so there "
              "is\nnothing to compare the object against and nothing here "
              "could\never attach it.")
        print("\nCheck with:")
        print("    grep CONFIG_SCHED_CLASS_EXT /boot/config-$(uname -r)")
        print("\nA sched_ext ABI is compiled into the kernel; it cannot be "
              "added at\nrun time. Compare against the BTF of the kernel you "
              "will actually\nboot, by copying that file over and passing "
              "--btf <path>.")
        return 3

    # --- the populated-member inventory -----------------------------------
    # Prefer the object's own BTF: an unpopulated member is still present in
    # the struct there, so the BTF alone cannot tell us which are populated.
    # llvm-objdump on .struct_ops.link can, and we use it when available.
    populated = None
    if args.objdump:
        populated = read_populated_members(args.objdump, args.object, obj_btf, args.struct)

    # --- report -----------------------------------------------------------
    print("TLS struct_ops ABI check")
    print(f"  object     {args.object}")
    print(f"  kernel BTF {args.btf}")
    if args.header:
        print(f"  header     {args.header}")
    print(f"  struct     {args.struct}")
    print(f"  kernel size {k_type.size} bytes, {len(k_members)} members")
    print(f"  object size {obj_type.size} bytes, {len(obj_members)} members")

    ok = True
    if k_type.size != obj_type.size:
        print(f"\n  SIZE MISMATCH: kernel {k_type.size} != "
              f"object {obj_type.size} bytes")
        ok = False

    if not describe_diff(k_members, obj_members, "kernel", "object"):
        ok = False

    if populated is not None:
        if not inventory_report(k_members, populated):
            ok = False
        else:
            print(f"\n  All {len(populated)} populated members exist in the "
                  "kernel's struct.")

    print()
    if ok:
        print("RESULT: compatible. The object's struct_ops layout matches "
              "this kernel's.")
        return 0

    print("=" * 72)
    print("RESULT: INCOMPATIBLE - do not attach this object to this kernel")
    print("=" * 72)
    print("""
The kernel matches struct_ops members by offset. With the differences above,
attaching would let the kernel call the wrong function pointer, which
presents as a scheduling bug rather than a load error.

What to do:

  * If the object was built from the scx checkout's vendored vmlinux.h (a
    fallback used when the build machine has no sched_ext), rebuild it on the
    target kernel so the header is generated from that kernel's BTF:

        rm -rf build && make

  * If you must build for one kernel on another machine, copy that kernel's
    BTF over and point the build at it:

        scp target:/sys/kernel/btf/vmlinux ./target.vmlinux.btf
        make BTF=./target.vmlinux.btf VMLINUX_H=build/vmlinux/vmlinux.h

  * If the two kernels are genuinely different versions with different
    sched_ext ABIs, the object cannot be made compatible. Build on the target.
""")
    return 1


def read_populated_members(objdump: str, path: str, btf, struct_name: str):
    """
    Find which ops members the object actually populates.

    This is read from the relocations in .rel.struct_ops.link, which fill the
    struct_ops map member by member. Each relocation has a byte offset into the
    map, and the map's layout is exactly struct sched_ext_ops, so the member
    name comes from the BTF member at that offset.

    Doing it by offset rather than by symbol name matters: a function
    annotated BPF_STRUCT_OPS(tls_enqueue, ...) lands in a section called
    `struct_ops/tls_enqueue`, and `tls_enqueue` is not the kernel's
    member name (`enqueue` is). The offset is unambiguous.

    Returns a set of member names, or None if the information is unavailable.
    """
    if not os.path.exists(objdump):
        return None

    try:
        t = btf.by_name(struct_name)
    except Exception:
        return None
    if t is None:
        return None

    # byte offset -> member name
    by_offset = {}
    for m in t.members:
        if m.name:
            by_offset[(m.offset_bits & 0xFFFFFF) // 8] = m.name

    try:
        proc = subprocess.run([objdump, "-r", path],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None

    members = set()
    current = None

    # llvm-objdump groups relocations under `RELOCATION RECORDS FOR [<sec>]:`
    # headers. Only the struct_ops map sections are interesting: the offsets
    # there are offsets into struct sched_ext_ops.
    #
    # Matching bare relocation lines without tracking the section would sweep
    # in every relocation in the object, whose offsets would then resolve to
    # bogus member names because they happen to be small integers.
    for line in proc.stdout.splitlines():
        stripped = line.strip()

        m = re.match(r"RELOCATION RECORDS FOR \[(.+?)\]:", stripped)
        if m:
            current = m.group(1)
            continue

        # Two very different kinds of section name contain "struct_ops":
        #
        #   struct_ops/tls_enqueue   one BPF program, in its own section,
        #                               named after the function
        #   .struct_ops.link            the map itself, whose relocations are
        #                               the member fills we want
        #
        # Only the map section has offsets into struct sched_ext_ops. Taking
        # the program sections too would resolve their stack offsets as if
        # they were member offsets and invent members that do not exist.
        if current is None:
            continue
        base = current[4:] if current.startswith(".rel") else current
        if base not in (".struct_ops", ".struct_ops.link"):
            continue

        m = re.match(r"^([0-9a-fA-F]+)\s+R_BPF_64_", stripped)
        if not m:
            continue

        off = int(m.group(1), 16)
        name = by_offset.get(off)
        if name:
            members.add(name)

    return members or None


if __name__ == "__main__":
    sys.exit(main())
