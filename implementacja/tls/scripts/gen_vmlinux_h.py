#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
Generate a vmlinux.h for a target kernel.

WHY THIS EXISTS
---------------
A sched_ext BPF object is a struct_ops object: the kernel matches the compiled
`struct sched_ext_ops` layout against the layout its own BTF describes. If the
two disagree, the object still loads and the kernel then calls the wrong
function pointers. The failure is silent and looks like a scheduler bug. So
the header must be generated from the kernel that will load the object, not
copied from a dependency.

The scx tree ships a pre-generated vmlinux.h, but it is generated from a much
newer kernel than a typical development machine (7.3-rc5 as of this writing)
and it is not a safe substitute. This script produces the right one.

TWO MODES
---------
1. bpftool (preferred, exact)

       scripts/gen_vmlinux_h.py --bpftool --btf /sys/kernel/btf/vmlinux \
                                --out build/vmlinux/vmlinux.h

   Shells out to `bpftool btf dump file <btf> format c`. This is the reference
   implementation and what the kernel documentation recommends. Install it
   with `apt install bpftool` (or libbpf-dev, which depends on it).

2. Built-in emitter (fallback, no external dependency)

       scripts/gen_vmlinux_h.py --btf /sys/kernel/btf/vmlinux --out ...

   Uses scripts/btf.py and emits the types itself.

   IMPORTANT: in this mode the emitter targets the type subset that a
   sched_ext scheduler actually needs - the task/CPU/sched types, the
   sched_ext ABI, and their transitive dependencies - rather than the whole
   kernel. It is NOT a drop-in replacement for bpftool's output. A full
   vmlinux.h is roughly 10k structs and contains mutually incompatible
   duplicate type names (the same name defined differently in different
   translation units of the kernel), which a single-pass emitter cannot
   reconcile the way bpftool does.

   This mode is mainly useful when the machine cannot install bpftool, or to
   produce a minimal header for a specific kernel. If you find yourself
   fighting it, install bpftool.

WHAT THE OUTPUT MUST CONTAIN
----------------------------
Whatever generated it, the header must define, at minimum:

    struct task_struct            the unit of scheduling
    struct cpumask                affinity and idle masks
    struct sched_ext_ops          the struct_ops the kernel matches
    SCX_* enums and flags         SCX_ENQ_*, SCX_DSQ_*, SCX_EXIT_*
    the scx_bpf_* kfunc decls     every helper the scheduler calls
    struct scx_init_task_args, struct scx_exit_task_args, ...

`--require-scx` (on by default) verifies this and fails loudly with an
explanation if the kernel's BTF does not describe sched_ext. That is the
check that catches CONFIG_SCHED_CLASS_EXT=n, which is the single most common
reason a sched_ext build is impossible on a given machine.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import btf as btfmod
except ImportError as exc:  # pragma: no cover
    print(f"error: cannot import scripts/btf.py: {exc}", file=sys.stderr)
    print("Run this script from the tls directory, or via `make`.",
          file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# What the header must contain for a sched_ext scheduler to compile
# ---------------------------------------------------------------------------
# These are checked against the BTF before anything is emitted, so that a
# missing feature is reported as "this kernel cannot host this scheduler"
# rather than as a wall of C compile errors.
REQUIRED_SCX_TYPES = (
    "sched_ext_ops",
    "sched_ext_ops_cid",
    "scx_init_task_args",
    "scx_exit_task_args",
    "scx_exit_info",
    "scx_cpu_acquire_args",
    "scx_cpu_release_args",
    "scx_dump_ctx",
)

REQUIRED_CORE_TYPES = (
    "task_struct",
    "cpumask",
)


def scx_types_present(btf: "btfmod.BTF") -> dict[str, bool]:
    return {name: btf.by_name(name) is not None for name in REQUIRED_SCX_TYPES}


def core_types_present(btf: "btfmod.BTF") -> dict[str, bool]:
    return {name: btf.by_name(name) is not None for name in REQUIRED_CORE_TYPES}


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------

# Type kinds that are emitted. FUNC, FUNC_PROTO, VAR and DATASEC are not part
# of a vmlinux.h: a schedulers needs type layouts and kfunc prototypes, and
# the kfuncs come from the SCX headers in the scx tree, not from BTF.
EMITTABLE_KINDS = (
    btfmod.KIND_INT,
    btfmod.KIND_PTR,
    btfmod.KIND_ARRAY,
    btfmod.KIND_STRUCT,
    btfmod.KIND_UNION,
    btfmod.KIND_ENUM,
    btfmod.KIND_ENUM64,
    btfmod.KIND_TYPEDEF,
    btfmod.KIND_FWD,
    btfmod.KIND_FLOAT,
    # FUNC_PROTO matters: struct sched_ext_ops is almost entirely an array of
    # function pointers, so a header that cannot express them cannot express
    # the ABI the kernel matches against.
    btfmod.KIND_FUNC_PROTO,
)

# Integer width -> C spelling, indexed by byte size.
INT_C_NAMES = {
    1: "u8", 2: "u16", 4: "u32", 8: "u64",
}

INT_C_NAMES_SIGNED = {
    1: "s8", 2: "s16", 4: "s32", 8: "s64",
}


class Emitter:
    """
    Emits C declarations for a set of BTF types and their dependencies.

    Dependencies are discovered by walking each requested type, so the output
    is closed under reference: every type named in the output is also defined
    in the output.
    """

    def __init__(self, btf: "btfmod.BTF", roots: list[str],
                 anon_prefix: str = "__anon"):
        self.btf = btf
        self.anon_prefix = anon_prefix
        # Types to emit, keyed by type id, in insertion-discovering order.
        self.order: list[int] = []
        self.seen: set[int] = set()
        # Anonymous struct/union/enum get synthetic names because C has no
        # other way to refer to them from the declaration that uses them.
        self.anon_names: dict[int, str] = {}
        self._fwd_resolved: set[str] = set()
        self.anon_counter = 0
        self.roots = roots
        # Names that could not be resolved to a C spelling, for reporting.
        self.unresolved: set[str] = set()

    # -- discovery -------------------------------------------------------

    def collect(self) -> None:
        for name in self.roots:
            t = self.btf.by_name(name)
            if t is None:
                continue
            self._visit(t.id)

    def _visit(self, type_id: int) -> None:
        """Recursively register this type and everything it references."""
        if type_id in self.seen or type_id == 0:
            return
        t = self.btf.get(type_id)
        if t is None:
            return
        if t.kind not in EMITTABLE_KINDS:
            # Walk through it without emitting: e.g. a member whose type is a
            # function pointer still needs its argument types... but we do not
            # emit FUNC_PROTO, so just record the miss.
            return
        self.seen.add(type_id)

        # Depth-first, and appended AFTER the dependencies, so that self.order
        # is a valid C emission order: a type's definition comes after
        # everything it needs. Appending before recursing instead produces a
        # header that lists `struct thread_info thread_info;` as a member of
        # task_struct hundreds of lines before `struct thread_info {` is
        # defined, which does not compile.
        if t.kind == btfmod.KIND_PTR:
            self._visit(t.type_id)
        elif t.kind == btfmod.KIND_ARRAY:
            self._visit(t.type_id)
        elif t.kind in (btfmod.KIND_STRUCT, btfmod.KIND_UNION):
            for m in t.members:
                self._visit(m.type_id)
                self._force_complete(m.type_id)
        elif t.kind == btfmod.KIND_TYPEDEF:
            self._visit(t.type_id)
        elif t.kind == btfmod.KIND_FUNC_PROTO:
            self._visit(t.type_id)          # return type
            for prm in t.params:
                self._visit(prm.type_id)
        elif t.kind == btfmod.KIND_FWD:
            # A forward declaration is not enough when the struct is used by
            # value: C requires a complete type. The kernel's BTF routinely
            # forward-declares `struct thread_info` early and defines it
            # later, so resolve the name and pull in the real definition.
            self._visit_fwd_target(t)

        self.order.append(type_id)

    def _visit_fwd_target(self, fwd: "btfmod.BTFType") -> None:
        """
        If a forward declaration has a matching struct/union definition with
        the same name, visit that definition.

        Emitting only the forward declaration is correct when the type is used
        through a pointer, and wrong when it is used by value, which is how
        `struct thread_info thread_info;` appears in task_struct.
        """
        if not fwd.name or fwd.name in self._fwd_resolved:
            return
        self._fwd_resolved.add(fwd.name)

        for t in self.btf.types.values():
            if t.name != fwd.name:
                continue
            if t.kind in (btfmod.KIND_STRUCT, btfmod.KIND_UNION):
                self._visit(t.id)
                return

    def _force_complete(self, type_id: int) -> None:
        """
        Make sure a member's type will have a complete definition.

        Called for every struct/union member, because C needs the complete
        type there whether or not the reference is through a pointer.
        """
        t = self.btf.get(type_id)
        if t is None or type_id == 0:
            return
        inner = self.btf.resolve(type_id) or t
        if inner.kind in (btfmod.KIND_STRUCT, btfmod.KIND_UNION):
            self._visit(inner.id)
        elif inner.kind in (btfmod.KIND_FWD,):
            self._visit_fwd_target(inner)

    # -- naming ----------------------------------------------------------

    def name_of(self, type_id: int) -> str:
        """A C-usable name for a type id, creating one for anonymous types."""
        t = self.btf.get(type_id)
        if t is None:
            self.unresolved.add(f"<missing type {type_id}>")
            return "void"
        if t.name:
            return t.name
        if t.kind in (btfmod.KIND_STRUCT, btfmod.KIND_UNION,
                      btfmod.KIND_ENUM, btfmod.KIND_ENUM64):
            if t.id not in self.anon_names:
                self.anon_counter += 1
                self.anon_names[t.id] = f"{self.anon_prefix}_{self.anon_counter}"
            return self.anon_names[t.id]
        if t.kind == btfmod.KIND_PTR:
            return self.name_of(t.type_id) + " *"
        if t.kind == btfmod.KIND_FUNC_PROTO:
            # Only reachable if a function prototype is used as a value type
            # rather than through a pointer, which the kernel does not do.
            self.unresolved.add(f"<function prototype id {t.id} not via "
                                "pointer>")
            return "void"

        self.unresolved.add(f"<{t.kind_name.lower()} id {t.id}>")
        return "void"

    def declare(self, type_id: int) -> str:
        """The C spelling used to *refer* to a type, in a type position."""
        if type_id == 0:
            # Type id 0 is `void`: BTF numbering starts at 1, so a PTR whose
            # target is 0 is `void *`. This is not a missing type.
            return "void"
        t = self.btf.get(type_id)
        if t is None:
            return "void"

        if t.kind == btfmod.KIND_PTR:
            return self.declare(t.type_id) + " *"
        if t.kind == btfmod.KIND_FUNC_PROTO:
            # A bare prototype in a type position: C needs a declarator, so
            # this spelling is only valid through _declarator(). Callers in a
            # type position are handled there.
            return self._func_proto_type(t)
        if t.kind == btfmod.KIND_CONST:
            return "const " + self.declare(t.type_id)
        if t.kind == btfmod.KIND_VOLATILE:
            return "volatile " + self.declare(t.type_id)
        if t.kind == btfmod.KIND_RESTRICT:
            return self.declare(t.type_id)
        if t.kind == btfmod.KIND_TYPE_TAG:
            return self.declare(t.type_id)
        if t.kind == btfmod.KIND_TYPEDEF:
            return t.name
        if t.kind in (btfmod.KIND_STRUCT, btfmod.KIND_UNION):
            keyword = "struct" if t.kind == btfmod.KIND_STRUCT else "union"
            return f"{keyword} {self.name_of(type_id)}"
        if t.kind in (btfmod.KIND_ENUM, btfmod.KIND_ENUM64):
            return f"enum {self.name_of(type_id)}"
        if t.kind == btfmod.KIND_FWD:
            # A forward declaration: treat as a pointer-only type.
            return f"struct {t.name}" if t.name else "void"
        if t.kind == btfmod.KIND_INT:
            return self._int_name(t)
        if t.kind == btfmod.KIND_FLOAT:
            return "float" if t.size == 4 else "double"
        if t.kind == btfmod.KIND_ARRAY:
            # An array type in a declaration position needs the declarator
            # syntax, which is handled by _declarator(); this is only reached
            # for array-of-array, which the kernel does not use.
            return self.declare(t.type_id)

        if t.kind == btfmod.KIND_FUNC_PROTO:
            # Only reachable if a function prototype is used as a value type
            # rather than through a pointer, which the kernel does not do.
            self.unresolved.add(f"<function prototype id {t.id} not via "
                                "pointer>")
            return "void"

        self.unresolved.add(f"<{t.kind_name.lower()} id {t.id}>")
        return "void"

    def _func_proto_type(self, t: "btfmod.BTFType") -> str:
        """
        The return type of a function prototype, which is what a pointer to it
        points at.
        """
        return self.declare(t.type_id)

    def _func_ptr_declarator(self, proto: "btfmod.BTFType", ident: str) -> str:
        """
        `ret (*ident)(argtypes)` for a pointer to a function prototype.

        Parameter names are deliberately omitted: they are noise in a
        generated header and the kernel's own prototypes vary, so emitting
        only types keeps the output deduplicated and comparable.
        """
        ret = self.declare(proto.type_id)
        if proto.params:
            args = ", ".join(
                ("..." if not p.name and p.type_id == 0
                 else self._param_decl(p))
                for p in proto.params)
        else:
            args = "void"
        return f"{ret} (*{ident})({args})"

    def _param_decl(self, p: "btfmod.BTFParam") -> str:
        """One parameter's type, including its own pointer/array forms."""
        pt = self.btf.get(p.type_id)
        if pt is None:
            return "void"
        if pt.kind == btfmod.KIND_PTR:
            inner = self.btf.get(pt.type_id)
            if inner is not None and inner.kind == btfmod.KIND_FUNC_PROTO:
                return self._func_ptr_declarator(inner, "")
            return self.declare(p.type_id)
        if pt.kind == btfmod.KIND_ARRAY:
            # An array parameter decays to a pointer in C, and the kernel's
            # BTF describes them as arrays. Emit the decayed form.
            return self.declare(pt.type_id) + " *"
        if pt.kind == btfmod.KIND_FUNC_PROTO:
            return self._func_ptr_declarator(pt, "")
        return self.declare(p.type_id)

    def _int_name(self, t: "btfmod.BTFType") -> str:
        enc = t.int_encoding
        if enc & btfmod.BTF_INT_BOOL:
            return "bool" if t.size == 1 else "u32"
        if enc & btfmod.BTF_INT_CHAR:
            return "char" if not (enc & btfmod.BTF_INT_SIGNED) else "signed char"
        table = INT_C_NAMES_SIGNED if (enc & btfmod.BTF_INT_SIGNED) else INT_C_NAMES
        if t.size in table:
            return table[t.size]
        # Odd widths: fall back to a fixed-width spelling. _BitInt is real C23
        # and clang 19 supports it, but the BPF target does not accept it, so
        # widen instead and note the change.
        width = t.size * 8
        self.unresolved.add(f"<int of {width} bits>")
        if width <= 8:
            return "u8"
        if width <= 16:
            return "u16"
        if width <= 32:
            return "u32"
        return "u64"

    def _declarator(self, type_id: int, ident: str) -> str:
        """
        A complete member declarator for `ident` of the given type.

        C declarator syntax is inside-out, so this accumulates the declarator
        suffix while walking down to the base type and then joins them. That
        is what makes arrays of function pointers, pointers to arrays, and
        typedefs that hide either one all come out right:

            u64 (*tick)(struct task_struct *);     member of sched_ext_ops
            struct cpumask *cpus[4];
            void (*handlers[MAX])(int);
        """
        if type_id == 0:
            # void
            return f"void {ident}"
        t = self.btf.get(type_id)
        if t is None:
            return f"void {ident}"

        suffix = ""          # accumulated declarator, e.g. "[4]" or "(*)"
        depth = 0            # guard against a malformed cyclic blob

        while t is not None and depth < 32:
            depth += 1

            if t.kind == btfmod.KIND_PTR:
                inner = self.btf.get(t.type_id)
                if inner is not None and inner.kind == btfmod.KIND_FUNC_PROTO:
                    # Pointer to function: the declarator is (*ident)(args).
                    return self._func_ptr_declarator(inner, ident + suffix)
                suffix = "*" + suffix
                t = inner
                continue

            if t.kind == btfmod.KIND_FUNC_PROTO:
                # A prototype reached without a pointer: treat as a pointer to
                # it, since that is the only C-expressible form.
                return self._func_ptr_declarator(t, ident + suffix)

            if t.kind == btfmod.KIND_ARRAY:
                # Arrays bind tighter than pointers, so the suffix goes on the
                # right of the identifier and pointers accumulate to its left.
                suffix = f"[{t.array_nelems}]" + suffix
                t = self.btf.get(t.type_id)
                continue

            if t.kind in (btfmod.KIND_CONST, btfmod.KIND_VOLATILE,
                          btfmod.KIND_RESTRICT, btfmod.KIND_TYPE_TAG):
                t = self.btf.get(t.type_id)
                continue

            if t.kind == btfmod.KIND_TYPEDEF:
                # A typedef could still be a function pointer type; look
                # through it only to detect that case, otherwise use its name.
                resolved = self.btf.resolve(t.id)
                if resolved is not None and resolved.kind == btfmod.KIND_FUNC_PROTO:
                    return self._func_ptr_declarator(resolved, ident + suffix)
                if resolved is not None and resolved.kind == btfmod.KIND_PTR:
                    underlying = self.btf.get(resolved.type_id)
                    if (underlying is not None and
                            underlying.kind == btfmod.KIND_FUNC_PROTO):
                        return f"{t.name} {ident}{suffix}"
                return f"{t.name} {self._join_ptr(ident, suffix)}"

            if t.kind in (btfmod.KIND_STRUCT, btfmod.KIND_UNION):
                keyword = "struct" if t.kind == btfmod.KIND_STRUCT else "union"
                return f"{keyword} {self.name_of(t.id)} {self._join_ptr(ident, suffix)}"

            if t.kind in (btfmod.KIND_ENUM, btfmod.KIND_ENUM64):
                return f"enum {self.name_of(t.id)} {self._join_ptr(ident, suffix)}"

            if t.kind == btfmod.KIND_FWD:
                return f"struct {t.name} *{ident}{suffix}" if t.name else f"void *{ident}{suffix}"

            if t.kind == btfmod.KIND_INT:
                return f"{self._int_name(t)} {self._join_ptr(ident, suffix)}"

            if t.kind == btfmod.KIND_FLOAT:
                base = "float" if t.size == 4 else "double"
                return f"{base} {self._join_ptr(ident, suffix)}"

            break

        if t is None:
            # The walk reached type id 0, which is `void`. `void *p` is what
            # this means; it is not an unresolvable base, and reporting it as
            # one produced `void *p*`.
            return f"void {self._join_ptr(ident, suffix)}"

        # Unresolvable base.
        self.unresolved.add(f"<{t.kind_name.lower()} id {t.id}>")
        return f"void *{ident}{suffix}"

    @staticmethod
    def _join_ptr(ident: str, suffix: str) -> str:
        """
        Place accumulated '*' marks next to the identifier.

        `ident` may already have array suffixes appended, in which case the
        pointer needs parentheses: `(*p)[4]`, not `*p[4]`.
        """
        stars = ""
        rest = suffix
        while rest.startswith("*"):
            stars += "*"
            rest = rest[1:]
        if not stars:
            return f"{ident}{rest}"
        if rest:
            # Array suffix present: the pointer must bind to the identifier.
            return f"({stars}{ident}){rest}"
        return f"{stars}{ident}"

    # -- emission --------------------------------------------------------

    def emit(self) -> str:
        out: list[str] = []
        out.append("""/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vmlinux.h - kernel type definitions, generated, do not edit.
 *
 * Generated by tls/scripts/gen_vmlinux_h.py from the BTF of the target
 * kernel. Regenerate it whenever the target kernel changes; a struct_ops
 * object compiled against a different kernel's layout will load and then
 * dispatch to the wrong callbacks.
 *
 * This header is not a complete vmlinux.h. It contains the types a sched_ext
 * scheduler needs and their transitive dependencies. See the generator's
 * docstring for why that distinction matters.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

typedef _Bool bool;
""")

        # Anonymous types get named up front so that a member referring to one
        # has something to refer to. C requires the definition to appear
        # before use for by-value members, and self.order is built in
        # dependency order (see _visit), so emitting it in sequence is valid.
        for tid in self.order:
            chunk = self._emit_one(tid)
            if chunk:
                out.append(chunk)

        out.append("""
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
""")
        return "".join(out)

    def _emit_one(self, type_id: int) -> str:
        t = self.btf.get(type_id)
        if t is None:
            return ""

        if t.kind == btfmod.KIND_INT or t.kind == btfmod.KIND_FLOAT:
            # Nothing to define: these are spelled inline where used.
            return ""

        if t.kind == btfmod.KIND_FWD:
            if not t.name:
                return ""
            return f"struct {t.name};\n"

        if t.kind == btfmod.KIND_TYPEDEF:
            inner = self.btf.get(t.type_id)
            if inner is None:
                return ""
            # A typedef of an anonymous struct: name the struct, then the
            # typedef. This is how the kernel declares most of its handle
            # types.
            if inner.kind in (btfmod.KIND_STRUCT, btfmod.KIND_UNION) and not inner.name:
                keyword = ("struct" if inner.kind == btfmod.KIND_STRUCT
                           else "union")
                body = self._emit_record(inner, t.name)
                if body:
                    return (f"typedef {keyword} {t.name} {{\n{body}"
                            f"}} {t.name};\n\n")
                return ""
            # A typedef of an anonymous enum.
            if inner.kind in (btfmod.KIND_ENUM, btfmod.KIND_ENUM64) and not inner.name:
                entries = self._emit_enumerators(inner)
                return f"enum {t.name} {{\n{entries}}};\n\n"
            # A typedef of an array, e.g. `u8 mac[6]`.
            if inner.kind == btfmod.KIND_ARRAY:
                return f"typedef {self._declarator(inner.id, t.name)};\n\n"
            return f"typedef {self.declare(t.type_id)} {t.name};\n\n"

        if t.kind in (btfmod.KIND_STRUCT, btfmod.KIND_UNION):
            keyword = "struct" if t.kind == btfmod.KIND_STRUCT else "union"
            name = self.name_of(type_id)
            body = self._emit_record(t, name)
            if body is None:
                # Already emitted, or nothing to say.
                return ""
            return f"{keyword} {name} {{\n{body}}};\n\n"

        if t.kind in (btfmod.KIND_ENUM, btfmod.KIND_ENUM64):
            name = self.name_of(type_id)
            entries = self._emit_enumerators(t)
            if not entries:
                return ""
            return f"enum {name} {{\n{entries}}};\n\n"

        return ""

    def _emit_record(self, t: "btfmod.BTFType", name: str) -> str | None:
        """Members of a struct or union, indented."""
        lines: list[str] = []
        for m in t.members:
            mt = self.btf.get(m.type_id)
            if mt is None:
                continue
            mname = m.name
            if not mname:
                # An anonymous member: C11 allows the type to be declared
                # inline, which is how the kernel uses them. An anonymous
                # struct/union member gets its definition inlined here.
                if mt.kind in (btfmod.KIND_STRUCT, btfmod.KIND_UNION):
                    keyword = ("struct" if mt.kind == btfmod.KIND_STRUCT
                               else "union")
                    body = self._emit_record(mt, "")
                    if body:
                        lines.append(f"\t{keyword} {{\n{body}\t}};")
                        continue
                lines.append(f"\t{self._declarator(mt.id, '')}".rstrip() + ";")
                continue
            # Bitfields: `type name : width;`
            bits = m.bitfield_size
            decl = self._declarator(mt.id, mname)
            if bits:
                decl = f"{decl} : {bits}"
            lines.append(f"\t{decl};")
        if not lines:
            return None
        return "\n".join(lines) + "\n"

    def _emit_enumerators(self, t: "btfmod.BTFType") -> str:
        lines: list[str] = []
        for m in t.members:
            if t.kind == btfmod.KIND_ENUM64 or m.value > 0xFFFFFFFF or m.value < 0:
                lines.append(f"\t{m.name} = {m.value}LL,")
            else:
                lines.append(f"\t{m.name} = {m.value},")
        if not lines:
            return ""
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def generate_with_bpftool(bpftool: str, btf_path: str, out_path: str) -> int:
    """The exact path: let bpftool do it."""
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    cmd = [bpftool, "btf", "dump", "file", btf_path, "format", "c"]
    print(f"  BTF     {' '.join(cmd)}", file=sys.stderr)
    try:
        with open(out_path, "w") as fh:
            proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE,
                                  text=True)
    except OSError as exc:
        print(f"error: cannot run {bpftool}: {exc}", file=sys.stderr)
        return 1
    if proc.returncode != 0:
        print(f"error: bpftool failed ({proc.returncode}):", file=sys.stderr)
        print(textwrap.indent(proc.stderr.strip(), "    "), file=sys.stderr)
        try:
            os.unlink(out_path)
        except OSError:
            pass
        return proc.returncode
    return 0


def report_missing(btf: "btfmod.BTF", btf_path: str) -> bool:
    """
    Check that the kernel describes sched_ext and report clearly if not.

    Returns True if sched_ext is present.
    """
    scx = scx_types_present(btf)
    core = core_types_present(btf)

    missing_core = [k for k, v in core.items() if not v]
    missing_scx = [k for k, v in scx.items() if not v]

    if not missing_core and not missing_scx:
        return True

    print("", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    print("THIS KERNEL CANNOT HOST A SCHED_EXT SCHEDULER", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    print(f"BTF source: {btf_path}", file=sys.stderr)

    if missing_core:
        print("", file=sys.stderr)
        print("Missing core types, which means CONFIG_DEBUG_INFO_BTF is off or",
              file=sys.stderr)
        print("the BTF blob is not a kernel BTF:", file=sys.stderr)
        for name in missing_core:
            print(f"    {name}", file=sys.stderr)

    if missing_scx:
        print("", file=sys.stderr)
        print(f"Missing {len(missing_scx)} sched_ext types, which means this "
              "kernel was built", file=sys.stderr)
        print("without sched_ext. Check with:", file=sys.stderr)
        print("", file=sys.stderr)
        print("    grep CONFIG_SCHED_CLASS_EXT /boot/config-$(uname -r)",
              file=sys.stderr)
        print("", file=sys.stderr)
        for name in missing_scx:
            print(f"    {name}", file=sys.stderr)
        print("", file=sys.stderr)
        print("There is no workaround: a scheduler cannot be compiled or loaded",
              file=sys.stderr)
        print("against a kernel with CONFIG_SCHED_CLASS_EXT unset. Boot a kernel",
              file=sys.stderr)
        print("whose config sets it to y, then re-run this script against that",
              file=sys.stderr)
        print("kernel's BTF.", file=sys.stderr)
    print("", file=sys.stderr)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate vmlinux.h for a target kernel from its BTF.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              # from the running kernel, using bpftool if available
              gen_vmlinux_h.py --btf /sys/kernel/btf/vmlinux --out build/vmlinux/vmlinux.h

              # force the built-in emitter
              gen_vmlinux_h.py --btf /sys/kernel/btf/vmlinux --no-bpftool --out ...

              # check a kernel without writing anything
              gen_vmlinux_h.py --btf /boot/vmlinux-6.13.0 --check-only
            """))
    ap.add_argument("--btf", default="/sys/kernel/btf/vmlinux",
                    help="BTF blob: /sys/kernel/btf/vmlinux, an ELF with a "
                         ".BTF section, or a compressed blob "
                         "(default: %(default)s)")
    ap.add_argument("--out", help="output header path")
    ap.add_argument("--bpftool", nargs="?", const="__auto__", default=None,
                    help="use bpftool (optionally give its path); requires "
                         "--bpftool explicitly, since the built-in emitter is "
                         "not equivalent")
    ap.add_argument("--allow-incomplete-emitter", action="store_true",
                    help="permit the built-in emitter when bpftool is "
                         "missing. It produces a header that is KNOWN NOT to "
                         "compile for a full kernel type graph; see the "
                         "module docstring. Off by default.")
    ap.add_argument("--no-bpftool", action="store_true",
                    help="never use bpftool, even if installed")
    ap.add_argument("--check-only", action="store_true",
                    help="verify the BTF describes sched_ext, then exit")
    ap.add_argument("--require-scx", dest="require_scx", action="store_true",
                    default=True,
                    help="fail if the kernel has no sched_ext types "
                         "(default: on)")
    ap.add_argument("--no-require-scx", dest="require_scx", action="store_false",
                    help="generate anyway, even without sched_ext types")
    ap.add_argument("--coverage", action="store_true",
                    help="report what the built-in emitter covered")
    args = ap.parse_args()

    if not args.check_only and not args.out:
        ap.error("--out is required unless --check-only is given")

    print(f"  BTF     reading {args.btf}", file=sys.stderr)
    try:
        btf = btfmod.load_btf(args.btf)
    except btfmod.BTFError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"  BTF     {len(btf.types)} types", file=sys.stderr)

    ok = report_missing(btf, args.btf) if args.require_scx else True
    if not ok:
        return 3
    if args.check_only:
        print("  BTF     sched_ext types present: this kernel can host a "
              "sched_ext scheduler", file=sys.stderr)
        return 0

    # bpftool path
    use_bpftool = False
    bpftool_path = None
    if not args.no_bpftool:
        if args.bpftool is not None and args.bpftool != "__auto__":
            bpftool_path = args.bpftool
            use_bpftool = True
        elif args.bpftool == "__auto__":
            bpftool_path = shutil.which("bpftool")
            use_bpftool = bpftool_path is not None
            if not use_bpftool and not args.allow_incomplete_emitter:
                print("\n  ERROR: bpftool was not found.\n"
                      "\n"
                      "  bpftool is how vmlinux.h is correctly generated. The\n"
                      "  built-in emitter in this script is an incomplete\n"
                      "  fallback: it handles the sched_ext ABI and the core\n"
                      "  scheduling types, but not the full kernel type graph,\n"
                      "  so its output does not compile as a whole.\n"
                      "\n"
                      "  Install it:\n"
                      "      sudo apt install bpftool        # Debian/Ubuntu\n"
                      "      sudo dnf install bpftool        # Fedora\n"
                      "\n"
                      "  Or supply a header you already have, and skip this\n"
                      "  script entirely:\n"
                      "      make VMLINUX_H=/path/to/vmlinux.h\n"
                      "\n"
                      "  To use the incomplete emitter anyway (for inspecting\n"
                      "  the sched_ext ABI, not for building):\n"
                      "      scripts/gen_vmlinux_h.py --allow-incomplete-emitter ...\n",
                      file=sys.stderr)
                return 5
            if not use_bpftool:
                print("  BTF     bpftool not found; using the built-in "
                      "emitter because --allow-incomplete-emitter was given",
                      file=sys.stderr)

    if use_bpftool:
        assert bpftool_path is not None
        rc = generate_with_bpftool(bpftool_path, args.btf, args.out)
        if rc != 0:
            return rc
        size = os.path.getsize(args.out)
        print(f"  GEN     {args.out} ({size} bytes, bpftool)", file=sys.stderr)
        return 0

    # Built-in emitter path. Emit the sched_ext ABI and the core scheduling
    # types, plus everything they reference.
    roots = list(REQUIRED_SCX_TYPES) + list(REQUIRED_CORE_TYPES) + [
        # Types a scheduler reaches for constantly. Listing them as roots
        # rather than relying on discovery keeps the header usable even when
        # a member of sched_ext_ops does not reference them directly.
        "sched_ext_ops", "scx_bpf_dsq_insert_vtime_args",
        "scx_bpf_select_cpu_and_args", "scx_event_stats",
        "cgroup", "rq", "cpumask", "list_head", "rcu_head",
    ]
    em = Emitter(btf, roots)
    em.collect()
    text = em.emit()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as fh:
        fh.write(text)

    print(f"  GEN     {args.out} ({len(text)} bytes, built-in emitter)",
          file=sys.stderr)
    print(f"  GEN     {len(em.order)} types emitted, "
          f"{len(em.anon_names)} anonymous types named", file=sys.stderr)
    if em.unresolved:
        print(f"  WARN    {len(em.unresolved)} types had no C spelling and "
              "were widened or replaced with void:", file=sys.stderr)
        for name in sorted(em.unresolved)[:10]:
            print(f"            {name}", file=sys.stderr)
        if len(em.unresolved) > 10:
            print(f"            ... and {len(em.unresolved) - 10} more",
                  file=sys.stderr)
        print("          This affects correctness of the generated header. "
              "Install bpftool and", file=sys.stderr)
        print("          re-run for an exact header.", file=sys.stderr)
        if args.coverage:
            return 0
        return 4

    return 0


if __name__ == "__main__":
    sys.exit(main())
