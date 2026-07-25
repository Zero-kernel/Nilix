#!/usr/bin/env python3
"""
PO-ABI-01: Static ABI Layout Oracle (three-legged cross-language gate)

D2-TST-ABI-BYTES. This oracle proves the kernel's syscall-boundary ABI structures
match the Linux x86-64 KERNEL ABI (uapi), NOT glibc's feature-macro-selected
variants. It is deliberately NON-SELF-REFERENTIAL:

  Leg A  (Rust actuals)  -- parses the kernel Rust sources AT CHECK TIME: a small
                            deterministic repr(C) x86-64 layout engine computes
                            field offsets/sizes for the boundary structs, and a
                            DEMAND-DRIVEN const-expression evaluator extracts the
                            declared signal-frame / sigaction / dirent constants.
  Leg B  (reference)     -- an explicit, per-entry-cited Linux x86-64 KERNEL-ABI
                            reference table hand-transcribed from uapi headers.
  Leg C  (gcc actuals)   -- generates a C program whose EXPECTED literals come from
                            Leg B (the reference table, never the Rust parse) and
                            checks them against gcc-native structs via offsetof/
                            sizeof. This re-validates the reference table itself
                            against an independent toolchain.

Leg A is compared against Leg B (the primary gate). Leg C independently confirms
Leg B is a faithful transcription of the platform ABI where glibc mirrors the
kernel layout. Structs with no glibc mirror (kernel k_sigaction, the Zero-OS
frame-contract constants) are TABLE_ONLY with the reason printed.

Two former KNOWN-DIVERGENCE structs (VfsStat, UtsName) were CONVERTED to the
Linux layouts on 2026-07-24 (finding D2-ABI-STAT-LAYOUT RESOLVED): VfsStat is
now the x86-64 `struct stat` (144B) and UtsName the full `new_utsname` (390B).
Both are enforced as LINUX_UAPI entries with Leg-C gcc cross-checks; the
ZEROOS_DIVERGENT layer machinery is retained for future deliberate forks.

Scope: LAYOUT ONLY. Network byte order, integer overflow, and errno semantics are
behavioral and are covered by `make musl-check`, not here.

Usage:
    python3 scripts/abi_layout_oracle.py --self-test        # unit + negative tests
    python3 scripts/abi_layout_oracle.py --check            # full gate (default)
    python3 scripts/abi_layout_oracle.py --emit-c PATH      # dump the C leg only
Options:
    --skip-cc        skip the gcc Leg-C cross-check. WINDOWS-MIRROR CONVENIENCE
                     ONLY; the `make abi-check` target never passes it, so CI /
                     the devbox fail closed if gcc is absent.
    --cc CC          C compiler (default: gcc)
    --work-dir DIR   scratch dir for the C leg (default: <repo>/target/abi-oracle)

Exit codes:
    0  all layouts match
    1  layout MISMATCH (Leg A vs Leg B, or Leg C vs Leg B) -- a real ABI drift
    2  SOURCE DRIFT / parse / self-test / toolchain failure -- fail closed, never
       a silent skip (a renamed struct, an unparseable const, a missing gcc, or a
       self-test failure all land here)
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Kernel Rust sources parsed by Leg A (relative to repo root). Read utf-8 with \r
# stripped -- the repo's rustfmt uses Windows (CRLF) newlines.
SOURCES = {
    "syscall": "kernel/kernel_core/syscall.rs",
    "poll": "kernel/kernel_core/poll.rs",
    "process": "kernel/kernel_core/process.rs",
    "signal": "kernel/kernel_core/signal.rs",
    "signal_frame": "kernel/kernel_core/signal_frame.rs",
}


class SourceDriftError(Exception):
    """Raised (=> exit 2) when the Rust source cannot be parsed as the oracle
    expects: a struct is missing/renamed/non-unique, a repr(C) attribute is gone,
    an unknown field type appears, or a wanted constant cannot be resolved. Fail
    closed -- NEVER guess a layout."""


# ---------------------------------------------------------------------------
# Leg A: repr(C) x86-64 layout engine
# ---------------------------------------------------------------------------

# Primitive/scalar sizes+aligns on x86-64 (LP64). Pointers and [u8; N] handled
# separately. Only the types actually used by the boundary structs are listed;
# an unknown token is a hard error (fail closed), not a guess.
TYPE_TABLE = {
    "i8": (1, 1), "u8": (1, 1),
    "i16": (2, 2), "u16": (2, 2),
    "i32": (4, 4), "u32": (4, 4),
    "i64": (8, 8), "u64": (8, 8),
    "isize": (8, 8), "usize": (8, 8),
}

_PTR_RE = re.compile(r"^\*\s*(?:const|mut)\s+\w+$")
_ARR_U8_RE = re.compile(r"^\[\s*u8\s*;\s*(\d+)\s*\]$")


def _align_up(off, align):
    return (off + align - 1) & ~(align - 1)


def _field_type_layout(ty):
    """(size, align) for a field type string, or raise SourceDriftError."""
    ty = ty.strip()
    if ty in TYPE_TABLE:
        return TYPE_TABLE[ty]
    if _PTR_RE.match(ty):
        return (8, 8)
    m = _ARR_U8_RE.match(ty)
    if m:
        return (int(m.group(1)), 1)
    raise SourceDriftError(
        f"unknown field type {ty!r}: the layout engine only models "
        f"{sorted(TYPE_TABLE)}, `*const/*mut T`, and `[u8; N]`. Extend TYPE_TABLE "
        f"with a source-cited size/align if a new primitive is genuinely needed."
    )


class StructLayout:
    def __init__(self, name, fields, size, align):
        self.name = name
        self.fields = fields  # list[(name, offset, size)]
        self.size = size
        self.align = align

    def offset(self, field):
        for n, off, _ in self.fields:
            if n == field:
                return off
        raise SourceDriftError(f"struct {self.name}: no field {field!r}")


# `#[repr(C)]` or `#[repr(C, align(N))]` (align optional). Other repr forms are
# rejected by absence (the struct won't be found with the required repr).
_REPR_RE = re.compile(r"#\[repr\(C(?:\s*,\s*align\((\d+)\))?\)\]")
_FIELD_RE = re.compile(r"^(?:pub(?:\(crate\))?\s+)?(\w+)\s*:\s*(.+?)\s*,?$")


def parse_repr_c_struct(text, name):
    """Locate the UNIQUE `#[repr(C..)] ... struct <name> { .. }` and compute its
    standard C layout. Tolerates interleaved #[derive(..)] attributes, /// and //!
    doc lines, per-field doc lines, trailing `// ..` comments on field lines, AND
    free-standing `// ..` comment lines inside the body. Raises SourceDriftError on
    a missing / non-unique / non-repr(C) struct or an unknown field type."""
    # Include the optional visibility prefix so `head` ends at a clean line
    # boundary (the newline before `pub struct ..`), not mid-line on a `pub `
    # fragment that would abort the backward attribute scan.
    struct_re = re.compile(
        r"(?:pub(?:\(crate\))?\s+)?struct\s+" + re.escape(name) + r"\b\s*\{", re.M)
    matches = list(struct_re.finditer(text))
    if not matches:
        raise SourceDriftError(f"struct {name!r} not found")
    if len(matches) > 1:
        raise SourceDriftError(f"struct {name!r} is not unique ({len(matches)} defs)")
    sm = matches[0]

    # Require a repr(C) attribute in the (up to 12) lines preceding `struct Name {`.
    head = text[:sm.start()]
    preceding = head.splitlines()[-12:]
    explicit_align = None
    saw_repr_c = False
    for line in reversed(preceding):
        s = line.strip()
        rm = _REPR_RE.search(s)
        if rm:
            saw_repr_c = True
            if rm.group(1):
                explicit_align = int(rm.group(1))
            break
        # Stop scanning back once we leave the attribute/doc block.
        if s and not (s.startswith("#[") or s.startswith("///") or
                      s.startswith("//!") or s.startswith("//") or s == ""):
            break
    if not saw_repr_c:
        raise SourceDriftError(f"struct {name!r} lacks a #[repr(C)] attribute")

    # Body: from the opening brace to the matching close brace (these structs have
    # no nested braces).
    body_start = sm.end()
    depth = 1
    i = body_start
    while i < len(text) and depth:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    if depth:
        raise SourceDriftError(f"struct {name!r}: unbalanced braces")
    body = text[body_start:i - 1]

    off = 0
    max_align = 1
    fields = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("//") or line.startswith("#["):
            continue  # doc line, standalone comment line, or field attribute
        # strip a trailing line comment on a field line
        line = re.sub(r"\s*//.*$", "", line).strip()
        if not line:
            continue
        fm = _FIELD_RE.match(line)
        if not fm:
            raise SourceDriftError(
                f"struct {name!r}: unparseable body line {raw.strip()!r}"
            )
        fname, fty = fm.group(1), fm.group(2)
        fsize, falign = _field_type_layout(fty)
        off = _align_up(off, falign)
        fields.append((fname, off, fsize))
        off += fsize
        max_align = max(max_align, falign)

    if explicit_align is not None:
        max_align = max(max_align, explicit_align)
    size = _align_up(off, max_align)
    return StructLayout(name, fields, size, max_align)


# ---------------------------------------------------------------------------
# Leg A: demand-driven const-expression evaluator
# ---------------------------------------------------------------------------

_CONST_DECL_RE_TMPL = (
    r"(?:pub\s+)?const\s+{name}\s*:\s*(?:u64|u32|usize|i64|i32|u16)\s*=\s*(.+?);"
)
_ARITH_CHARSET_RE = re.compile(r"^[\w\s+\-*/()]+$")
_OFFSETOF_RE = re.compile(r"core::mem::offset_of!\(\s*(\w+)\s*,\s*(\w+)\s*\)")
_SIZEOF_RE = re.compile(r"core::mem::size_of::<\s*(\w+)\s*>\(\)")


def _find_const_rhs(texts, name):
    """Return (rhs_str, source_key) for `const <name>` across the given sources,
    including function-local consts. Raise SourceDriftError if absent -- naming the
    regex's visibility/type limits so a re-scoped (`pub(crate)`) or re-typed const
    yields an actionable message rather than a bare miss."""
    rx = re.compile(_CONST_DECL_RE_TMPL.format(name=re.escape(name)))
    for key, text in texts.items():
        m = rx.search(text)
        if m:
            return m.group(1).strip(), key
    raise SourceDriftError(
        f"const {name!r} not found. The const regex matches only `[pub] const "
        f"NAME: {{u64|u32|usize|i64|i32|u16}} = ...;` -- a `pub(crate)` visibility "
        f"or a type outside that set will miss. Update the oracle's regex WITH the "
        f"source change if the declaration legitimately changed."
    )


def eval_const(name, texts, structs, _stack=None):
    """DEMAND-DRIVEN: resolve only `name` and its transitive dependencies, never
    sweeping every const in the file (the sources contain consts whose RHS uses
    `&`/`|`/`<<`/octal/calls -- e.g. signal_frame.rs RFLAGS_SANITIZE_AND -- which
    are intentionally OUTSIDE this evaluator's arithmetic grammar and must not
    force a spurious failure)."""
    _stack = _stack or []
    if name in _stack:
        raise SourceDriftError(f"const cycle: {' -> '.join(_stack + [name])}")
    rhs, _ = _find_const_rhs(texts, name)

    # Resolve offset_of! / size_of via the layout engine.
    def _sub_offsetof(m):
        sname, fname = m.group(1), m.group(2)
        if sname not in structs:
            raise SourceDriftError(
                f"offset_of!({sname}, {fname}) references un-modelled struct {sname!r}"
            )
        return str(structs[sname].offset(fname))

    def _sub_sizeof(m):
        tname = m.group(1)
        if tname in structs:
            return str(structs[tname].size)
        if tname in TYPE_TABLE:
            return str(TYPE_TABLE[tname][0])
        raise SourceDriftError(f"size_of::<{tname}>() references un-modelled type {tname!r}")

    expr = _OFFSETOF_RE.sub(_sub_offsetof, rhs)
    expr = _SIZEOF_RE.sub(_sub_sizeof, expr)
    # strip `as u64` / `as usize` / ... width casts
    expr = re.sub(r"\bas\s+(?:u64|u32|usize|i64|i32|u16|u8)\b", "", expr)
    # numeric literals: allow underscores + hex
    expr = re.sub(r"0x([0-9A-Fa-f_]+)", lambda m: str(int(m.group(1).replace("_", ""), 16)), expr)
    expr = re.sub(r"\b(\d[\d_]*)\b", lambda m: m.group(1).replace("_", ""), expr)

    # Any bare identifier remaining must be another const (transitive closure).
    for ident in sorted(set(re.findall(r"[A-Za-z_]\w*", expr))):
        val = eval_const(ident, texts, structs, _stack + [name])
        expr = re.sub(r"\b" + re.escape(ident) + r"\b", str(val), expr)

    if not _ARITH_CHARSET_RE.match(expr):
        raise SourceDriftError(
            f"const {name!r} RHS {rhs!r} reduced to {expr!r}, which is outside the "
            f"evaluator's arithmetic grammar [\\w\\s+\\-*/()]. This evaluator is "
            f"demand-driven and intentionally supports only +,-,*,/,parens, "
            f"integer literals, `as` casts, offset_of!, and size_of."
        )
    try:
        # Arithmetic only; no names/attributes remain past the charset gate.
        return int(eval(expr, {"__builtins__": {}}, {}))
    except Exception as exc:  # noqa: BLE001 (fail closed on any eval surprise)
        raise SourceDriftError(f"const {name!r}: cannot evaluate {expr!r}: {exc}")


# ---------------------------------------------------------------------------
# Leg B: Linux x86-64 KERNEL-ABI reference table
# ---------------------------------------------------------------------------
# Layer tags:
LINUX_UAPI = "LINUX_UAPI"                       # kernel uapi; glibc mirrors it -> Leg C checks
LINUX_UAPI_TABLE_ONLY = "LINUX_UAPI_TABLE_ONLY" # kernel uapi; no faithful glibc mirror -> table only
ZEROOS_FRAME_CONTRACT = "ZEROOS_FRAME_CONTRACT" # Zero-OS placement derived from Linux components
ZEROOS_DIVERGENT = "ZEROOS_DIVERGENT"           # deliberately differs from Linux; pinned KNOWN-DIVERGENCE

# Struct reference entries: name -> dict(src, layer, cite, fields=[(name, off, size)], size,
#                                        c_type/c_include for Leg C when LINUX_UAPI)
STRUCT_REFS = {
    "TimeSpec": dict(
        src="syscall", layer=LINUX_UAPI, cite="uapi/linux/time.h struct timespec",
        fields=[("tv_sec", 0, 8), ("tv_nsec", 8, 8)], size=16,
        c_type="struct timespec", c_include="time.h",
        c_fields=[("tv_sec", 0), ("tv_nsec", 8)],
    ),
    "TimeVal": dict(
        src="syscall", layer=LINUX_UAPI, cite="uapi/linux/time.h struct timeval",
        fields=[("tv_sec", 0, 8), ("tv_usec", 8, 8)], size=16,
        c_type="struct timeval", c_include="sys/time.h",
        c_fields=[("tv_sec", 0), ("tv_usec", 8)],
    ),
    "PollFd": dict(
        src="poll", layer=LINUX_UAPI, cite="uapi/asm-generic/poll.h struct pollfd",
        fields=[("fd", 0, 4), ("events", 4, 2), ("revents", 6, 2)], size=8,
        c_type="struct pollfd", c_include="poll.h",
        c_fields=[("fd", 0), ("events", 4), ("revents", 6)],
    ),
    "RLimit": dict(
        src="process", layer=LINUX_UAPI, cite="uapi/linux/resource.h struct rlimit64",
        fields=[("rlim_cur", 0, 8), ("rlim_max", 8, 8)], size=16,
        c_type="struct rlimit", c_include="sys/resource.h",
        c_fields=[("rlim_cur", 0), ("rlim_max", 8)],
    ),
    "Iovec": dict(
        src="syscall", layer=LINUX_UAPI, cite="uapi/linux/uio.h struct iovec",
        fields=[("iov_base", 0, 8), ("iov_len", 8, 8)], size=16,
        c_type="struct iovec", c_include="sys/uio.h",
        c_fields=[("iov_base", 0), ("iov_len", 8)],
    ),
    "SockAddrIn": dict(
        src="syscall", layer=LINUX_UAPI, cite="uapi/linux/in.h struct sockaddr_in",
        fields=[("sin_family", 0, 2), ("sin_port", 2, 2), ("sin_addr", 4, 4),
                ("sin_zero", 8, 8)], size=16,
        c_type="struct sockaddr_in", c_include="netinet/in.h",
        c_fields=[("sin_family", 0), ("sin_port", 2), ("sin_addr", 4)],
    ),
    "OpenHow": dict(
        # Linux 5.6+ openat2(2). All-u64 fields defeat the in-tree size assert, so
        # a field REORDER is silent without an offset check -- exactly the drift
        # this oracle exists to catch.
        src="syscall", layer=LINUX_UAPI_TABLE_ONLY,
        cite="uapi/linux/openat2.h struct open_how (Linux 5.6+); TABLE_ONLY unless "
             "<linux/openat2.h> is present at Leg-C compile time",
        fields=[("flags", 0, 8), ("mode", 8, 8), ("resolve", 16, 8)], size=24,
        c_type="struct open_how", c_include="linux/openat2.h", c_optional=True,
        c_fields=[("flags", 0), ("mode", 8), ("resolve", 16)],
    ),
    "LinuxDirent64": dict(
        # sizeof(rust) is tail-padded to 24; the WIRE name offset is 19 (pinned
        # separately as LINUX_DIRENT64_NAME_OFFSET). R180-25: never use the struct
        # sizeof as the wire tail.
        src="syscall", layer=LINUX_UAPI, cite="uapi/linux/dirent.h dirent64 header",
        fields=[("d_ino", 0, 8), ("d_off", 8, 8), ("d_reclen", 16, 2),
                ("d_type", 18, 1)], size=24,
        c_type="struct dirent64", c_include="dirent.h",
        c_fields=[("d_ino", 0), ("d_off", 8), ("d_reclen", 16), ("d_type", 18)],
        # glibc `struct dirent64` embeds `char d_name[256]` inline (sizeof 280), so
        # its sizeof is NOT the kernel wire header size 24. Only the header field
        # OFFSETS are a meaningful glibc cross-check (R180-25). The Rust side's
        # sizeof==24 is still validated in Leg A vs Leg B.
        c_skip_size=True,
    ),
    "SigAction": dict(
        # KERNEL k_sigaction wire (handler/flags/restorer/mask, mask 8 bytes =
        # _NSIG(64)/8). glibc `struct sigaction` (128-byte mask, int flags) is a
        # DIFFERENT layer and is deliberately NOT compared in Leg C.
        src="signal", layer=LINUX_UAPI_TABLE_ONLY,
        cite="arch/x86/include/uapi/asm/signal.h kernel rt_sigaction wire (NOT libc "
             "struct sigaction)",
        fields=[("handler", 0, 8), ("flags", 8, 8), ("restorer", 16, 8),
                ("mask", 24, 8)], size=32,
    ),
    "VfsStat": dict(
        # D2-ABI-STAT-LAYOUT RESOLVED (2026-07-24): converted from the former
        # 112-byte private layout to the Linux x86-64 struct stat wire layout.
        # pad0/unused0..2 are explicit zero fields (no implicit padding).
        src="syscall", layer=LINUX_UAPI,
        cite="arch/x86/include/uapi/asm/stat.h struct stat (x86-64, 144B); "
             "musl reads these exact offsets",
        fields=[("dev", 0, 8), ("ino", 8, 8), ("nlink", 16, 8), ("mode", 24, 4),
                ("uid", 28, 4), ("gid", 32, 4), ("pad0", 36, 4), ("rdev", 40, 8),
                ("size", 48, 8), ("blksize", 56, 8), ("blocks", 64, 8),
                ("atime_sec", 72, 8), ("atime_nsec", 80, 8), ("mtime_sec", 88, 8),
                ("mtime_nsec", 96, 8), ("ctime_sec", 104, 8), ("ctime_nsec", 112, 8),
                ("unused0", 120, 8), ("unused1", 128, 8), ("unused2", 136, 8)],
        size=144,
        c_type="struct stat", c_include="sys/stat.h",
        c_fields=[("st_dev", 0), ("st_ino", 8), ("st_nlink", 16), ("st_mode", 24),
                  ("st_uid", 28), ("st_gid", 32), ("st_rdev", 40), ("st_size", 48),
                  ("st_blksize", 56), ("st_blocks", 64), ("st_atim", 72),
                  ("st_mtim", 88), ("st_ctim", 104)],
    ),
    "UtsName": dict(
        # D2-ABI-STAT-LAYOUT LOW leg RESOLVED (2026-07-24): domainname added ->
        # full Linux new_utsname (6 x [u8;65] = 390B).
        src="syscall", layer=LINUX_UAPI,
        cite="include/uapi/linux/utsname.h struct new_utsname (390B incl. "
             "domainname); glibc/musl utsname mirrors it",
        fields=[("sysname", 0, 65), ("nodename", 65, 65), ("release", 130, 65),
                ("version", 195, 65), ("machine", 260, 65),
                ("domainname", 325, 65)], size=390,
        c_type="struct utsname", c_include="sys/utsname.h",
        c_fields=[("sysname", 0), ("nodename", 65), ("release", 130),
                  ("version", 195), ("machine", 260), ("domainname", 325)],
    ),
}

# Const reference entries: rust-const-name -> dict(expected, layer, cite)
CONST_REFS = {
    # rt_sigframe / ucontext / sigcontext / siginfo -- Linux-pinned components.
    "OFF_PRETCODE": dict(expected=0, layer=LINUX_UAPI,
                         cite="arch/x86 rt_sigframe: pretcode@0"),
    "OFF_UC": dict(expected=8, layer=LINUX_UAPI,
                   cite="arch/x86 rt_sigframe: uc@8"),
    "OFF_UC_STACK_FLAGS": dict(expected=32, layer=LINUX_UAPI,
                               cite="uapi ucontext: uc_stack.ss_flags = uc+16+8"),
    "OFF_MCONTEXT": dict(expected=48, layer=LINUX_UAPI,
                         cite="uapi ucontext: uc_mcontext = uc+40"),
    "OFF_SIGINFO": dict(expected=312, layer=LINUX_UAPI,
                        cite="rt_sigframe: siginfo = uc(8)+UC_SIZE(304)"),
    "UC_SIZE": dict(expected=304, layer=LINUX_UAPI,
                    cite="uapi ucontext: 8+8+24+256+8 (kernel 8-byte sigset)"),
    "SIGINFO_SIZE": dict(expected=128, layer=LINUX_UAPI,
                         cite="uapi/asm-generic/siginfo.h"),
    "FXSAVE_SIZE": dict(expected=512, layer=LINUX_UAPI,
                        cite="Intel SDM FXSAVE image"),
    "MC_R8": dict(expected=48, layer=LINUX_UAPI, cite="sigcontext greg r8 (mcontext+0)"),
    "MC_R9": dict(expected=56, layer=LINUX_UAPI, cite="sigcontext greg r9"),
    "MC_R10": dict(expected=64, layer=LINUX_UAPI, cite="sigcontext greg r10"),
    "MC_R11": dict(expected=72, layer=LINUX_UAPI, cite="sigcontext greg r11"),
    "MC_R12": dict(expected=80, layer=LINUX_UAPI, cite="sigcontext greg r12"),
    "MC_R13": dict(expected=88, layer=LINUX_UAPI, cite="sigcontext greg r13"),
    "MC_R14": dict(expected=96, layer=LINUX_UAPI, cite="sigcontext greg r14"),
    "MC_R15": dict(expected=104, layer=LINUX_UAPI, cite="sigcontext greg r15"),
    "MC_RDI": dict(expected=112, layer=LINUX_UAPI, cite="sigcontext greg rdi"),
    "MC_RSI": dict(expected=120, layer=LINUX_UAPI, cite="sigcontext greg rsi"),
    "MC_RBP": dict(expected=128, layer=LINUX_UAPI, cite="sigcontext greg rbp"),
    "MC_RBX": dict(expected=136, layer=LINUX_UAPI, cite="sigcontext greg rbx"),
    "MC_RDX": dict(expected=144, layer=LINUX_UAPI, cite="sigcontext greg rdx"),
    "MC_RAX": dict(expected=152, layer=LINUX_UAPI, cite="sigcontext greg rax"),
    "MC_RCX": dict(expected=160, layer=LINUX_UAPI, cite="sigcontext greg rcx"),
    "MC_RSP": dict(expected=168, layer=LINUX_UAPI, cite="sigcontext greg rsp"),
    "MC_RIP": dict(expected=176, layer=LINUX_UAPI, cite="sigcontext greg rip"),
    "MC_EFLAGS": dict(expected=184, layer=LINUX_UAPI, cite="sigcontext eflags"),
    "MC_FPSTATE_PTR": dict(expected=232, layer=LINUX_UAPI,
                           cite="sigcontext fpstate ptr (mcontext+184)"),
    "SI_SIGNO": dict(expected=312, layer=LINUX_UAPI, cite="siginfo si_signo (frame-abs)"),
    "SI_ERRNO": dict(expected=316, layer=LINUX_UAPI, cite="siginfo si_errno"),
    "SI_CODE": dict(expected=320, layer=LINUX_UAPI, cite="siginfo si_code"),
    "SIGRETURN_MCONTEXT_FROM_UC": dict(expected=40, layer=LINUX_UAPI,
                                       cite="uc+40 = uc_mcontext (Linux)"),
    # Zero-OS contiguous-fpstate contract: DERIVED from Linux components, not a
    # Linux-fixed offset (Linux locates fpstate via the mc.fpstate pointer). Pinned
    # because rt_sigreturn re-derives fpstate from RSP at this fixed offset (SROP
    # gate) -- the exact contract D1RES-R1's buffer conversion must NOT disturb.
    "OFF_FPSTATE": dict(expected=440, layer=ZEROOS_FRAME_CONTRACT,
                        cite="Zero-OS contiguous placement: OFF_UC+UC_SIZE+SIGINFO_SIZE = 8+304+128"),
    "FRAME_SIZE": dict(expected=952, layer=ZEROOS_FRAME_CONTRACT,
                       cite="Zero-OS: OFF_FPSTATE(440)+FXSAVE_SIZE(512)"),
    "SIGRETURN_FPSTATE_FROM_UC": dict(expected=432, layer=ZEROOS_FRAME_CONTRACT,
                                      cite="Zero-OS SROP gate: OFF_FPSTATE-OFF_UC = 440-8"),
    # dirent64 wire name offset + kernel sigset size + rt_sigaction wire size.
    "LINUX_DIRENT64_NAME_OFFSET": dict(expected=19, layer=LINUX_UAPI,
                                       cite="dirent64 wire: d_type(18)+1"),
    "LINUX_KERNEL_SIGSET_SIZE": dict(expected=8, layer=LINUX_UAPI,
                                     cite="kernel sigset _NSIG(64)/8"),
    "SIGACTION_BYTES": dict(expected=32, layer=LINUX_UAPI,
                            cite="kernel rt_sigaction wire size"),
}

# ---------------------------------------------------------------------------
# Source drift tripwires: exact lines that must exist verbatim in the manual
# serializers/decoders (which have no repr(C) struct to parse). Miss => exit 2.
# ---------------------------------------------------------------------------
TRIPWIRES = [
    ("syscall", r"record\[0\.\.8\]\.copy_from_slice\(&entry\.ino\.to_ne_bytes",
     "dirent64 d_ino@0..8"),
    ("syscall", r"record\[8\.\.16\]\.copy_from_slice\(&entry\.next_cookie",
     "dirent64 d_off (RF180-14 resume cookie)@8..16"),
    ("syscall", r"record\[16\.\.18\]\.copy_from_slice\(&\(reclen as u16\)",
     "dirent64 d_reclen@16..18"),
    ("syscall", r"record\[18\] = d_type;", "dirent64 d_type@18"),
    ("syscall", r"let name_start = LINUX_DIRENT64_NAME_OFFSET;",
     "dirent64 name@LINUX_DIRENT64_NAME_OFFSET"),
    ("syscall", r"\.map\(\|value\| value & !7\)", "dirent64 reclen 8-byte align"),
    ("syscall", r"FileType::Regular => 8,", "DT_REG=8"),
    ("syscall", r"FileType::Directory => 4,", "DT_DIR=4"),
    ("syscall", r"FileType::CharDevice => 2,", "DT_CHR=2"),
    ("syscall", r"FileType::BlockDevice => 6,", "DT_BLK=6"),
    ("syscall", r"FileType::Symlink => 10,", "DT_LNK=10"),
    ("syscall", r"FileType::Fifo => 1,", "DT_FIFO=1"),
    ("syscall", r"FileType::Socket => 12,", "DT_SOCK=12"),
    ("syscall", r"let handler = rd\(0\);", "rt_sigaction handler@0"),
    ("syscall", r"let flags = rd\(8\);", "rt_sigaction flags@8"),
    ("syscall", r"let restorer = rd\(16\);", "rt_sigaction restorer@16"),
    ("syscall", r"let mask = rd\(24\);", "rt_sigaction mask@24"),
]


# ---------------------------------------------------------------------------
# Leg C: C generator (expected literals sourced from Leg B ONLY)
# ---------------------------------------------------------------------------

def emit_c(reference):
    """Generate the C cross-check program. Its expected literals come from the Leg-B
    reference table (never from the Rust parse) -- Leg C independently confirms Leg B
    is a faithful transcription of the platform ABI. LINUX_UAPI structs with a glibc
    mirror are checked; TABLE_ONLY / ZEROOS entries emit an explanatory comment."""
    lines = []
    lines.append("/* PO-ABI-01 Leg C (auto-generated). Expected literals come from the")
    lines.append("   oracle's Linux x86-64 reference table, NOT from the Rust parse. */")
    lines.append("#define _GNU_SOURCE")
    lines.append("#ifndef __x86_64__")
    lines.append('#error "ABI layout oracle: x86-64 Linux only"')
    lines.append("#endif")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdio.h>")
    lines.append("#include <time.h>")
    lines.append("#include <sys/time.h>")
    lines.append("#include <sys/resource.h>")
    lines.append("#include <sys/uio.h>")
    lines.append("#include <poll.h>")
    lines.append("#include <netinet/in.h>")
    lines.append("#include <dirent.h>")
    lines.append("#include <sys/stat.h>")
    lines.append("#include <sys/utsname.h>")
    lines.append("#if defined(__has_include)")
    lines.append("#  if __has_include(<linux/openat2.h>)")
    lines.append("#    include <linux/openat2.h>")
    lines.append("#    define HAVE_OPENAT2 1")
    lines.append("#  endif")
    lines.append("#endif")
    lines.append('_Static_assert(sizeof(void *) == 8, "LP64 x86-64 required");')
    lines.append("")
    lines.append("static int fails = 0;")
    lines.append('#define CK_OFF(ty, field, exp) do { size_t a = offsetof(ty, field); \\')
    lines.append('  if (a != (size_t)(exp)) { fprintf(stderr, "ABI-C-FAIL: " #ty "." #field \\')
    lines.append('    " offset expected %zu got %zu\\n", (size_t)(exp), a); fails++; } } while (0)')
    lines.append('#define CK_SZ(ty, exp) do { size_t a = sizeof(ty); \\')
    lines.append('  if (a != (size_t)(exp)) { fprintf(stderr, "ABI-C-FAIL: " #ty \\')
    lines.append('    " sizeof expected %zu got %zu\\n", (size_t)(exp), a); fails++; } } while (0)')
    lines.append("")
    lines.append("int main(void) {")

    for name, ref in reference["structs"].items():
        layer = ref["layer"]
        if layer == LINUX_UAPI or (layer == LINUX_UAPI_TABLE_ONLY and ref.get("c_type") and ref.get("c_optional")):
            if not ref.get("c_type"):
                lines.append(f"    /* {name}: {layer}, no C mirror -- table only */")
                continue
            guard = ref.get("c_optional")
            if guard:
                lines.append("#ifdef HAVE_OPENAT2")
            cty = ref["c_type"]
            for fname, off in ref.get("c_fields", []):
                lines.append(f"    CK_OFF({cty}, {fname}, {off});")
            if not ref.get("c_skip_size"):
                lines.append(f"    CK_SZ({cty}, {ref['size']});")
            else:
                lines.append(f"    /* {name}: sizeof skipped in C leg -- glibc embeds "
                             f"the name buffer inline; wire header size checked in Leg A/B */")
            if guard:
                lines.append("#else")
                lines.append(f'    /* {name}: <linux/openat2.h> absent -- TABLE_ONLY this build */')
                lines.append("#endif")
        else:
            lines.append(f"    /* {name}: {layer} -- {ref['cite']} (table only, no C check) */")

    # ucontext / siginfo greg cross-check (glibc handler-visible ucontext IS the
    # kernel frame through uc_sigmask). Checked as a block under its own include.
    lines.append("#include <ucontext.h>")
    lines.append("#include <signal.h>")
    lines.append("    /* ucontext_t/mcontext greg offsets mirror the kernel sigcontext. */")
    lines.append("    CK_OFF(ucontext_t, uc_mcontext, 40);")
    lines.append("    CK_OFF(ucontext_t, uc_stack.ss_flags, 24);")
    lines.append("")
    lines.append("    if (fails) { fprintf(stderr, \"ABI-C-REF: %d mismatch(es)\\n\", fails); return 1; }")
    lines.append('    printf("ABI-C-REF-OK: reference table matches gcc-native x86-64 layouts\\n");')
    lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _read_sources():
    texts = {}
    for key, rel in SOURCES.items():
        p = REPO_ROOT / rel
        if not p.is_file():
            raise SourceDriftError(f"source {rel} not found at {p}")
        texts[key] = p.read_text(encoding="utf-8").replace("\r", "")
    return texts


def _build_reference():
    return {"structs": STRUCT_REFS, "consts": CONST_REFS}


def run_check(cc="gcc", work_dir=None, skip_cc=False):
    """Full gate. Returns an exit code (0/1/2)."""
    texts = _read_sources()
    reference = _build_reference()

    # --- parse all referenced structs (Leg A) ---
    structs = {}
    for name, ref in reference["structs"].items():
        structs[name] = parse_repr_c_struct(texts[ref["src"]], name)

    mismatches = 0
    checked_vals = 0

    # --- Leg A vs Leg B: structs ---
    for name, ref in reference["structs"].items():
        L = structs[name]
        by = dict((n, (o, s)) for n, o, s in L.fields)
        for fname, exp_off, exp_size in ref["fields"]:
            if fname not in by:
                print(f"ABI-FAIL: {name}.{fname} missing in Rust source", file=sys.stderr)
                mismatches += 1
                continue
            act_off, act_size = by[fname]
            checked_vals += 1
            if act_off != exp_off or act_size != exp_size:
                print(f"ABI-FAIL: {name}.{fname} expected off={exp_off} size={exp_size} "
                      f"got off={act_off} size={act_size} [{ref['cite']}]", file=sys.stderr)
                mismatches += 1
        checked_vals += 1
        if L.size != ref["size"]:
            print(f"ABI-FAIL: {name} sizeof expected {ref['size']} got {L.size} "
                  f"[{ref['cite']}]", file=sys.stderr)
            mismatches += 1
        # KNOWN-DIVERGENCE facts must still hold (a half-conversion trips these).
        for desc, pred in ref.get("divergence", []):
            checked_vals += 1
            if not pred(L):
                print(f"ABI-FAIL: {name} KNOWN-DIVERGENCE broken: {desc} -- a partial "
                      f"conversion toward the Linux layout was detected. Convert fully "
                      f"and update the reference table, or revert. [{ref['cite']}]",
                      file=sys.stderr)
                mismatches += 1

    # --- Leg A vs Leg B: constants (demand-driven) ---
    for cname, ref in reference["consts"].items():
        val = eval_const(cname, texts, structs)
        checked_vals += 1
        if val != ref["expected"]:
            print(f"ABI-FAIL: const {cname} expected {ref['expected']} got {val} "
                  f"[{ref['cite']}]", file=sys.stderr)
            mismatches += 1

    # --- source drift tripwires ---
    tripwires_ok = 0
    for key, pattern, desc in TRIPWIRES:
        if not re.search(pattern, texts[key]):
            raise SourceDriftError(
                f"tripwire MISSING ({desc}): pattern {pattern!r} not found in "
                f"{SOURCES[key]}. A manual serializer/decoder changed shape without "
                f"the oracle being updated -- fail closed."
            )
        tripwires_ok += 1

    # --- Leg C: gcc cross-check of the reference table ---
    c_status = "skipped"
    if not skip_cc:
        work = Path(work_dir) if work_dir else (REPO_ROOT / "target" / "abi-oracle")
        work.mkdir(parents=True, exist_ok=True)
        c_src = work / "abi_leg_c.c"
        c_bin = work / "abi_leg_c"
        c_src.write_text(emit_c(reference), encoding="utf-8")
        try:
            subprocess.run([cc, "-std=c11", "-Werror", str(c_src), "-o", str(c_bin)],
                           check=True, capture_output=True, text=True)
        except FileNotFoundError:
            raise SourceDriftError(
                f"C compiler {cc!r} not found. Leg C is mandatory in `make abi-check` "
                f"(fail closed). Install gcc or, for the Windows mirror only, pass "
                f"--skip-cc (the make target never does)."
            )
        except subprocess.CalledProcessError as exc:
            raise SourceDriftError(f"Leg-C compile failed:\n{exc.stderr}")
        proc = subprocess.run([str(c_bin)], capture_output=True, text=True)
        if proc.returncode == 0:
            c_status = "run"
        else:
            print(proc.stderr.strip(), file=sys.stderr)
            mismatches += 1
            c_status = "MISMATCH"

    if mismatches:
        print(f"ABI-ORACLE: FAIL ({mismatches} mismatch(es))", file=sys.stderr)
        return 1
    print(f"ABI-ORACLE: PASS ({len(reference['structs'])} structs, {checked_vals} values, "
          f"{tripwires_ok} tripwires, C-leg: {c_status})")
    return 0


# ---------------------------------------------------------------------------
# Self-tests (negative cases prove the gate can actually FAIL)
# ---------------------------------------------------------------------------

def run_self_tests():
    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    # layout engine: u32-then-u64 padding gap + trailing pad (fields one-per-line,
    # as every real kernel repr(C) struct is written).
    src = "#[repr(C)]\npub struct T {\n    a: u32,\n    b: u64,\n    c: u16,\n}\n"
    L = parse_repr_c_struct(src, "T")
    check(L.offset("a") == 0 and L.offset("b") == 8 and L.offset("c") == 16,
          f"padding-gap offsets wrong: {L.fields}")
    check(L.size == 24 and L.align == 8, f"trailing pad size wrong: {L.size}/{L.align}")

    # [u8; N] arrays (UtsName shape)
    L2 = parse_repr_c_struct(
        "#[repr(C)]\nstruct U {\n    x: [u8; 65],\n    y: [u8; 65],\n}\n", "U")
    check(L2.offset("y") == 65 and L2.size == 130 and L2.align == 1,
          f"array layout wrong: {L2.fields}/{L2.size}")

    # repr(C, align(4)) override + [u8;4] (SockAddrIn shape); with a #[derive] line
    # between the repr attr and the struct (the real SockAddrIn shape).
    L3 = parse_repr_c_struct(
        "#[repr(C, align(4))]\n#[derive(Clone, Copy)]\nstruct S {\n    f: u16,\n"
        "    p: u16,\n    a: [u8; 4],\n    z: [u8; 8],\n}\n", "S")
    check(L3.offset("a") == 4 and L3.size == 16 and L3.align == 4,
          f"align-override layout wrong: {L3.fields}/{L3.size}/{L3.align}")

    # pointer field (Iovec shape)
    L4 = parse_repr_c_struct(
        "#[repr(C)]\nstruct I {\n    p: *const u8,\n    n: usize,\n}\n", "I")
    check(L4.offset("n") == 8 and L4.size == 16, f"pointer layout wrong: {L4.fields}")

    # standalone // comment line inside body (LinuxDirent64 shape)
    src_c = ("#[repr(C)]\nstruct D {\n    a: u64,\n    b: i64,\n    c: u16,\n"
             "    d: u8,\n    // followed by name bytes\n}\n")
    L5 = parse_repr_c_struct(src_c, "D")
    check(L5.offset("d") == 18 and L5.size == 24,
          f"standalone-comment struct parse wrong: {L5.fields}/{L5.size}")

    # const evaluator: chain + offset_of! + size_of + as-cast + underscores
    texts = {
        "t": ("const A: u64 = 8;\nconst B: u64 = 16 + 8;\n"
              "const C: u64 = A + B;\n"
              "const D: usize = core::mem::offset_of!(D, d) + 1;\n"
              "const E: usize = core::mem::size_of::<u64>();\n"
              "const F: u64 = 0xFF_00 as u64;\n"
              # an UNRELATED const whose RHS is outside the arithmetic grammar:
              # demand-driven eval must NOT touch it.
              "const IGNORED: u64 = 0xFFFF & !0x100 | 0x2;\n"),
    }
    st = {"D": L5}
    check(eval_const("C", texts, st) == 32, "const chain eval wrong")
    check(eval_const("D", texts, st) == 19, "offset_of! eval wrong")
    check(eval_const("E", texts, st) == 8, "size_of eval wrong")
    check(eval_const("F", texts, st) == 0xFF00, "hex/as-cast eval wrong")
    # NEGATIVE: an unresolvable/out-of-grammar wanted const must raise (fail closed).
    try:
        eval_const("IGNORED", texts, st)
        failures.append("out-of-grammar const did not raise (should fail closed)")
    except SourceDriftError:
        pass
    # but resolving a sibling must NOT be poisoned by IGNORED's presence:
    check(eval_const("A", texts, st) == 8, "demand-driven eval touched unrelated const")

    # NEGATIVE: comparator must report a swapped-field struct as a mismatch.
    swapped = parse_repr_c_struct(
        "#[repr(C)]\nstruct P {\n    b: u64,\n    a: u32,\n}\n", "P")
    bad = dict((n, (o, s)) for n, o, s in swapped.fields)
    # reference says a@0/u32, b@8/u64; swapped source has b@0, a@8 -> mismatch
    mm = 0
    for fname, exp_off, exp_size in [("a", 0, 4), ("b", 8, 8)]:
        ao, asz = bad[fname]
        if ao != exp_off or asz != exp_size:
            mm += 1
    check(mm > 0, "comparator failed to flag a swapped-field struct")

    # NEGATIVE: a missing tripwire pattern must raise.
    try:
        if not re.search(r"THIS_LINE_DOES_NOT_EXIST_ANYWHERE", "some text"):
            raise SourceDriftError("tripwire absent (expected)")
        failures.append("missing-tripwire negative test did not raise")
    except SourceDriftError:
        pass

    # NEGATIVE: unknown field type must raise (fail closed, never guess).
    try:
        parse_repr_c_struct("#[repr(C)]\nstruct X {\n    f: SomeWeirdType,\n}\n", "X")
        failures.append("unknown field type did not raise")
    except SourceDriftError:
        pass

    # NEGATIVE: missing repr(C) must raise.
    try:
        parse_repr_c_struct("struct N {\n    a: u64,\n}\n", "N")
        failures.append("missing repr(C) did not raise")
    except SourceDriftError:
        pass

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        print(f"ABI-ORACLE self-test: {len(failures)} failure(s)", file=sys.stderr)
        return 2
    print("ABI-ORACLE self-test: PASS")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="PO-ABI-01 three-legged ABI layout oracle")
    ap.add_argument("--check", action="store_true", help="run the full gate (default)")
    ap.add_argument("--self-test", action="store_true", help="run unit + negative self-tests")
    ap.add_argument("--emit-c", metavar="PATH", help="write the Leg-C C program and exit")
    ap.add_argument("--skip-cc", action="store_true",
                    help="skip the gcc cross-check (Windows-mirror convenience only)")
    ap.add_argument("--cc", default="gcc", help="C compiler for Leg C (default: gcc)")
    ap.add_argument("--work-dir", default=None, help="scratch dir for the C leg")
    args = ap.parse_args(argv)

    try:
        if args.emit_c:
            Path(args.emit_c).write_text(emit_c(_build_reference()), encoding="utf-8")
            print(f"wrote {args.emit_c}")
            return 0
        if args.self_test:
            return run_self_tests()
        # default action is --check
        return run_check(cc=args.cc, work_dir=args.work_dir, skip_cc=args.skip_cc)
    except SourceDriftError as exc:
        print(f"ABI-ORACLE: SOURCE DRIFT (exit 2): {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
