#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
Minimal BTF reader.

This module exists so that the TLS build does not depend on bpftool being
installed. It parses the BTF blob that a kernel exposes at
/sys/kernel/btf/vmlinux (or a standalone .btf file, or the .BTF section of an
ELF object) and exposes just enough of the type graph for two jobs:

  1. scripts/gen_vmlinux_h.py - emit a vmlinux.h for the target kernel.
  2. scripts/check_abi.py     - compare the struct sched_ext_ops layout the
                                BPF object was compiled against with the layout
                                the target kernel actually exposes.

Reference: Documentation/bpf/btf.rst in the kernel source tree.

SCOPE AND HONEST LIMITS
-----------------------
This is not a general-purpose BTF implementation. It decodes the types a
vmlinux.h needs (struct, union, enum, typedef, pointer, array, function
prototype, integer, enum64, and the float/complex/decl_tag types only far
enough to reject them), resolves names, and computes member offsets and sizes
including bitfields.

It deliberately does NOT:
  - decode BTF.ext (function/line info), which vmlinux.h does not need
  - resolve anything requiring kernel headers
  - handle BTF_KIND_DECL_TAG or BTF_KIND_TYPE_TAG semantics, beyond skipping
    them, since they do not change a type's size or a member's offset

If you have bpftool, prefer `bpftool btf dump file <btf> format c`: it is the
reference implementation, and it is what the kernel's own documentation
recommends. This reader is the fallback for the case that this machine cannot
install it.
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from typing import Optional

BTF_MAGIC = 0xEB9F

# BTF kind numbers, from include/uapi/linux/btf.h
KIND_UNKNOWN = 0
KIND_INT = 1
KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_UNION = 5
KIND_ENUM = 6
KIND_FWD = 7
KIND_TYPEDEF = 8
KIND_VOLATILE = 9
KIND_CONST = 10
KIND_RESTRICT = 11
KIND_FUNC = 12
KIND_FUNC_PROTO = 13
KIND_VAR = 14
KIND_DATASEC = 15
KIND_FLOAT = 16
KIND_DECL_TAG = 17
KIND_TYPE_TAG = 18
KIND_ENUM64 = 19

KIND_NAMES = {
    KIND_UNKNOWN: "UNKNOWN", KIND_INT: "INT", KIND_PTR: "PTR",
    KIND_ARRAY: "ARRAY", KIND_STRUCT: "STRUCT", KIND_UNION: "UNION",
    KIND_ENUM: "ENUM", KIND_FWD: "FWD", KIND_TYPEDEF: "TYPEDEF",
    KIND_VOLATILE: "VOLATILE", KIND_CONST: "CONST",
    KIND_RESTRICT: "RESTRICT", KIND_FUNC: "FUNC",
    KIND_FUNC_PROTO: "FUNC_PROTO", KIND_VAR: "VAR",
    KIND_DATASEC: "DATASEC", KIND_FLOAT: "FLOAT",
    KIND_DECL_TAG: "DECL_TAG", KIND_TYPE_TAG: "TYPE_TAG",
    KIND_ENUM64: "ENUM64",
}

# BTF integer encoding bits, from the low byte of struct btf_int. These
# describe how to spell an integer type in C.
BTF_INT_SIGNED = 1 << 0
BTF_INT_CHAR = 1 << 1
BTF_INT_BOOL = 1 << 2

# Kinds that are transparent wrappers: they carry no layout of their own, so
# anything walking to the underlying type should step through them.
KIND_MODIFIERS = (KIND_VOLATILE, KIND_CONST, KIND_RESTRICT, KIND_TYPE_TAG)


class BTFError(Exception):
    """Raised for anything that makes the blob unreadable."""


# ---------------------------------------------------------------------------
# Type records
# ---------------------------------------------------------------------------

@dataclass
class BTFMember:
    """A struct/union member, or an enum entry."""
    name: str
    type_id: int
    # struct/union: bit offset within the type
    offset_bits: int = 0
    # enum: the value. For BTF_KIND_ENUM64 this can exceed 32 bits.
    value: int = 0

    @property
    def bitfield_size(self) -> int:
        return self.offset_bits >> 24

    @property
    def bit_offset(self) -> int:
        return self.offset_bits & 0xFFFFFF


@dataclass
class BTFParam:
    name: str
    type_id: int


@dataclass
class BTFType:
    """One entry from the BTF type section."""
    id: int
    kind: int
    name: str
    # Non-zero for kinds that have a size (INT, STRUCT, UNION, ENUM, ENUM64,
    # FLOAT, and DATASEC where it is the section size).
    size: int = 0
    # The kind-dependent "type" field. For PTR/CONST/VOLATILE/TYPEDEF/
    # TYPE_TAG/FUNC this is the referenced type. For ARRAY it is the element
    # type. For FUNC_PROTO it is the return type.
    type_id: int = 0
    # STRUCT/UNION: vlen is the member count. ENUM/ENUM64: the entry count.
    vlen: int = 0
    # INT
    int_encoding: int = 0
    # ARRAY
    array_index_type: int = 0
    array_nelems: int = 0
    # FUNC_PROTO
    linkage: int = 0
    # VAR
    var_linkage: int = 0
    # members for STRUCT/UNION, entries for ENUM/ENUM64
    members: list[BTFMember] = field(default_factory=list)
    # params for FUNC_PROTO
    params: list[BTFParam] = field(default_factory=list)
    # DATASEC entries: (type_id, offset, size)
    datasec_entries: list[tuple[int, int, int]] = field(default_factory=list)

    @property
    def kind_name(self) -> str:
        return KIND_NAMES.get(self.kind, f"KIND_{self.kind}")


class BTF:
    """A parsed BTF blob."""

    def __init__(self, data: bytes):
        self.types: dict[int, BTFType] = {}
        self._strings: bytes = b""
        self._parse(data)

    # -- parsing ---------------------------------------------------------

    def _parse(self, data: bytes) -> None:
        if len(data) < 24:
            raise BTFError("blob is shorter than a BTF header")

        magic, version, flags, hdr_len = struct.unpack_from("<HBBI", data, 0)
        if magic != BTF_MAGIC:
            raise BTFError(
                f"bad BTF magic {magic:#x}; expected {BTF_MAGIC:#x}. "
                "If this is an ELF file, extract its .BTF section first."
            )
        if version != 1:
            raise BTFError(f"unsupported BTF version {version}")

        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", data, 8)
        base = hdr_len
        type_start = base + type_off
        type_end = type_start + type_len
        str_start = base + str_off
        str_end = str_start + str_len
        if type_end > len(data) or str_end > len(data):
            raise BTFError("BTF header offsets run past the end of the blob")

        self._strings = data[str_start:str_end]

        # Type id 0 is the void type and is implicit; ids then run 1..n in
        # the type section.
        off = type_start
        type_id = 1
        while off < type_end:
            off = self._parse_one(data, off, type_id)
            type_id += 1

    def _str(self, off: int) -> str:
        if off == 0:
            return ""
        end = self._strings.find(b"\0", off)
        if end < 0:
            raise BTFError(f"unterminated string at offset {off}")
        return self._strings[off:end].decode("utf-8", errors="replace")

    def _parse_one(self, data: bytes, off: int, type_id: int) -> int:
        # struct btf_type: name_off, info, size/type
        name_off, info, size_or_type = struct.unpack_from("<III", data, off)
        off += 12

        kind = (info >> 24) & 0x1F
        kind_flag = (info >> 31) & 1
        vlen = info & 0xFFFF

        t = BTFType(id=type_id, kind=kind, name=self._str(name_off))

        if kind == KIND_INT:
            # struct btf_int is a single u32: 8 bits of encoding, 8 bits of
            # bit offset within the integer, then 16 bits of unused padding.
            t.size = size_or_type
            t.int_encoding, = struct.unpack_from("<I", data, off)
            off += 4

        elif kind in (KIND_PTR, KIND_CONST, KIND_VOLATILE, KIND_RESTRICT,
                      KIND_TYPEDEF, KIND_TYPE_TAG, KIND_FUNC):
            t.type_id = size_or_type

        elif kind == KIND_ARRAY:
            # struct btf_array: type, index_type, nelems
            t.type_id, t.array_index_type, t.array_nelems = \
                struct.unpack_from("<III", data, off)
            off += 12

        elif kind in (KIND_STRUCT, KIND_UNION):
            t.size = size_or_type
            t.vlen = vlen
            for _ in range(vlen):
                m_name, m_type, m_off = struct.unpack_from("<III", data, off)
                off += 12
                # With kind_flag set, the member offset carries the bitfield
                # size in its top 8 bits. The encoding differs between struct
                # and union; normalise to "offset_bits" and read bitfield_size
                # from it.
                if kind_flag:
                    if kind == KIND_STRUCT:
                        bits = m_off >> 24
                        bit_off = m_off & 0xFFFFFF
                    else:
                        # union: bit_offset is the low 24 bits and
                        # bitfield_size the high 8
                        bits = m_off >> 24
                        bit_off = m_off & 0xFFFFFF
                else:
                    bits = 0
                    bit_off = m_off
                t.members.append(BTFMember(
                    name=self._str(m_name), type_id=m_type,
                    offset_bits=(bits << 24) | bit_off))

        elif kind in (KIND_ENUM, KIND_ENUM64):
            t.size = size_or_type
            t.vlen = vlen
            for _ in range(vlen):
                if kind == KIND_ENUM:
                    e_name, e_val = struct.unpack_from("<Ii", data, off)
                    off += 8
                else:
                    e_name, e_val_lo, e_val_hi = \
                        struct.unpack_from("<III", data, off)
                    off += 12
                    e_val = (e_val_hi << 32) | e_val_lo
                    if e_val & (1 << 63):
                        e_val -= 1 << 64
                t.members.append(BTFMember(
                    name=self._str(e_name), type_id=0, value=e_val))

        elif kind == KIND_FWD:
            # struct btf_fwd_common has no extra data; size_or_type is unused
            pass

        elif kind == KIND_FUNC_PROTO:
            t.type_id = size_or_type  # return type
            t.vlen = vlen
            for _ in range(vlen):
                p_name, p_type = struct.unpack_from("<II", data, off)
                off += 8
                t.params.append(BTFParam(name=self._str(p_name),
                                         type_id=p_type))

        elif kind == KIND_VAR:
            # struct btf_var: linkage
            t.type_id = size_or_type
            t.var_linkage, = struct.unpack_from("<I", data, off)
            off += 4

        elif kind == KIND_DATASEC:
            t.size = size_or_type
            t.vlen = vlen
            for _ in range(vlen):
                d_type, d_off, d_size = struct.unpack_from("<III", data, off)
                off += 12
                t.datasec_entries.append((d_type, d_off, d_size))

        elif kind == KIND_FLOAT:
            t.size = size_or_type

        elif kind == KIND_DECL_TAG:
            # struct btf_decl_tag: component_idx
            off += 4

        else:
            raise BTFError(
                f"unhandled BTF kind {kind} ({t.kind_name}) at type id "
                f"{type_id}; this reader does not implement it")

        self.types[type_id] = t
        return off

    # -- lookup and navigation -------------------------------------------

    def get(self, type_id: int) -> Optional[BTFType]:
        return self.types.get(type_id)

    def by_name(self, name: str, kinds=(KIND_STRUCT, KIND_UNION,
                                       KIND_ENUM, KIND_TYPEDEF)) -> Optional[BTFType]:
        """First type with this name and one of the given kinds."""
        for t in self.types.values():
            if t.name == name and t.kind in kinds:
                return t
        return None

    def resolve(self, type_id: int) -> Optional[BTFType]:
        """Strip typedefs and cv-qualifiers; return the underlying type."""
        seen = set()
        t = self.types.get(type_id)
        while t is not None and (t.kind == KIND_TYPEDEF or
                                 t.kind in KIND_MODIFIERS):
            if t.id in seen:
                return t
            seen.add(t.id)
            t = self.types.get(t.type_id)
        return t

    def type_name(self, type_id: int) -> str:
        """A readable name for a type id, for diagnostics."""
        t = self.types.get(type_id)
        if t is None:
            return f"<missing type {type_id}>"
        if t.name:
            return t.name
        if t.kind == KIND_PTR:
            return self.type_name(t.type_id) + " *"
        return f"<{t.kind_name.lower()} {t.id}>"

    # -- layout ----------------------------------------------------------

    def sizeof(self, type_id: int) -> Optional[int]:
        """
        Size in bytes, or None if this reader cannot determine it.

        A pointer is 8 bytes because every kernel this targets is 64-bit; this
        is the one target-specific constant in the module, and it is not
        configurable on purpose, since a 32-bit kernel cannot run sched_ext.
        """
        t = self.resolve(type_id)
        if t is None:
            return None
        if t.kind == KIND_PTR:
            return 8
        if t.kind == KIND_ARRAY:
            elem = self.sizeof(t.type_id)
            if elem is None:
                return None
            return elem * t.array_nelems
        if t.kind in (KIND_INT, KIND_FLOAT, KIND_STRUCT, KIND_UNION,
                      KIND_ENUM, KIND_ENUM64):
            return t.size
        if t.kind == KIND_FWD:
            return None
        return None

    def member_bit_offset(self, struct_type_id: int, member_name: str) -> Optional[int]:
        """Bit offset of a named member, or None. For diagnostics only."""
        t = self.resolve(struct_type_id)
        if t is None or t.kind not in (KIND_STRUCT, KIND_UNION):
            return None
        for m in t.members:
            if m.name == member_name:
                return m.bit_offset
        return None


# ---------------------------------------------------------------------------
# Loading from the several places a BTF blob hides
# ---------------------------------------------------------------------------

def _read_elf_section(data: bytes, section_name: str) -> Optional[bytes]:
    """
    Extract a named section from an ELF file, without depending on pyelftools.

    Supports both 32- and 64-bit little-endian ELF, which covers anything this
    script will realistically be pointed at.
    """
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None

    ei_class = data[4]          # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]           # 1 = little endian
    if ei_data != 1:
        raise BTFError("big-endian ELF is not supported")

    if ei_class == 2:
        e_shoff, = struct.unpack_from("<Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    elif ei_class == 1:
        e_shoff, = struct.unpack_from("<I", data, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    else:
        raise BTFError(f"unsupported ELF class {ei_class}")

    if e_shoff == 0 or e_shnum == 0:
        return None

    def section_header(idx: int):
        off = e_shoff + idx * e_shentsize
        if ei_class == 2:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                struct.unpack_from("<IIQQQQ", data, off)
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                struct.unpack_from("<IIIIII", data, off)
        return sh_name, sh_type, sh_offset, sh_size

    shstr_name, _t, shstr_off, shstr_size = section_header(e_shstrndx)
    shstrtab = data[shstr_off:shstr_off + shstr_size]

    def strtab_get(off: int) -> str:
        end = shstrtab.find(b"\0", off)
        return shstrtab[off:end].decode("utf-8", errors="replace")

    for i in range(e_shnum):
        sh_name, sh_type, sh_offset, sh_size = section_header(i)
        if strtab_get(sh_name) == section_name:
            return data[sh_offset:sh_offset + sh_size]
    return None


def load_btf(path: str) -> BTF:
    """
    Load a BTF blob from any of:
      - a raw BTF file, such as /sys/kernel/btf/vmlinux
      - an ELF file containing a .BTF section, such as a vmlinux image
      - a .btf.gz / .btf.zst compressed blob

    Raises BTFError with an actionable message on failure.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise BTFError(
            f"cannot read {path}: {exc}. On a running kernel the BTF blob is "
            "/sys/kernel/btf/vmlinux; check that CONFIG_DEBUG_INFO_BTF=y."
        ) from exc

    if data[:4] == b"\x1f\x8b":
        import gzip
        data = gzip.decompress(data)
    elif data[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard  # type: ignore
        except ImportError as exc:
            raise BTFError(
                "this BTF file is zstd-compressed and the 'zstandard' Python "
                "module is not installed; either install it or decompress the "
                "file yourself and pass the result"
            ) from exc
        data = zstandard.ZstdDecompressor().decompress(data, max_output_size=1 << 30)

    if data[:4] == b"\x7fELF":
        section = _read_elf_section(data, ".BTF")
        if section is None:
            raise BTFError(
                f"{path} is an ELF file but has no .BTF section. A kernel "
                "image built without CONFIG_DEBUG_INFO_BTF cannot supply one; "
                "use /sys/kernel/btf/vmlinux from a running kernel instead."
            )
        data = section

    return BTF(data)


def main(argv: list[str]) -> int:
    """Self-test: `btf.py <file> [type-name ...]`."""
    if len(argv) < 2:
        print(__doc__)
        print("usage: btf.py <btf-file> [type-name ...]", file=sys.stderr)
        return 2

    try:
        btf = load_btf(argv[1])
    except BTFError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"{argv[1]}: {len(btf.types)} types, "
          f"{len(btf._strings)} bytes of strings")

    if len(argv) == 2:
        # Summarise by kind, which is the quickest sanity check that the
        # parser walked the whole type section.
        from collections import Counter
        counts = Counter(t.kind_name for t in btf.types.values())
        for kind, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"  {kind:<12} {n}")
        return 0

    for name in argv[2:]:
        t = btf.by_name(name)
        if t is None:
            print(f"\n{name}: not found")
            continue
        print(f"\n{t.kind_name} {name} (id {t.id}) size={t.size}")
        for m in t.members:
            if t.kind in (KIND_ENUM, KIND_ENUM64):
                print(f"    {m.name} = {m.value}")
            else:
                bf = m.bitfield_size
                extra = f" bitfield:{bf}" if bf else ""
                print(f"    +{m.bit_offset // 8:<6} {m.name:<32} "
                      f"{btf.type_name(m.type_id)}{extra}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
