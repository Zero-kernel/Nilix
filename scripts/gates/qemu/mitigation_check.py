#!/usr/bin/env python3
"""Prove the implemented dual-root mechanism; full KPTI/retpoline stay unsupported."""
import argparse
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

MAX_EXEC_RETRIES = 64
# Repeated stops for an already recorded site/CPU pair only pause the proof
# while the outstanding CPUs are waited for; they must never be unbounded.
MAX_PAIR_REPEATS = 4096

try:
    from qemu_fuzz_smoke import source_identity
except ModuleNotFoundError:  # direct execution from the repository root
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from scripts.gates.qemu.qemu_fuzz_smoke import source_identity

TOOLCHAIN = "nightly-2025-12-08"
PHYSICAL = 0x000FFFFFFFFFF000
STUBS = ("syscall_entry_stub", "timer_interrupt_stub", "switch_to_user")
DORMANT_ENTRY = "enter_usermode"
USER_FLAGS_MASK = 0xFFFFFFFFFFE2CFFF
ANCHOR = "zero_mitigation_probe_anchor"
RELEASE = "ZERO_MITIGATION_PROBE_RELEASE"


class ProofFailure(RuntimeError):
    pass


class EvidenceUnavailable(RuntimeError):
    pass


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf8")


@dataclass(frozen=True)
class Instruction:
    address: int
    length: int
    mnemonic: str
    operands: str
    raw: bytes = b""

    def op(self):
        return re.sub(r"\s+|(?:qword|dword|word|byte)\s+ptr\s*", "", self.operands.lower())


def parse_disassembly(text):
    symbols, current = {}, None
    for line in text.splitlines():
        label = re.match(r"^\s*([0-9a-fA-F]+)\s+<(.+)>:\s*$", line)
        if label:
            current = label[2]
            if current in symbols:
                base = re.sub(r"::h[0-9a-f]+$", "", current).split("::")[-1]
                if base in (*STUBS, DORMANT_ENTRY, ANCHOR):
                    raise ProofFailure(f"duplicate disassembly symbol: {current}")
                # Demangling may give unrelated Rust monomorphizations the same
                # printed name. Only the named proof bodies must be unique; the
                # complete disassembly still retains every generated function.
                current = None
                continue
            symbols[current] = []
            continue
        instruction = re.match(
            r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)"
            r"([a-zA-Z][a-zA-Z0-9.]*)\s*(.*?)\s*$", line)
        if current is not None and instruction:
            raw = bytes.fromhex(instruction[2])
            symbols[current].append(Instruction(int(instruction[1], 16), len(raw),
                                                 instruction[3].lower(), instruction[4], raw))
    return symbols


def body_for(symbols, base):
    matches = [(name, body) for name, body in symbols.items()
               if re.sub(r"::h[0-9a-f]+$", "", name).split("::")[-1] == base]
    if len(matches) != 1 or not matches[0][1]:
        raise EvidenceUnavailable(f"expected one generated body for {base}, found {len(matches)}")
    return matches[0][1]


def require(condition, message):
    if not condition:
        raise ProofFailure(message)


def branch_target(instruction):
    match = re.match(r"(?:0x)?([0-9a-fA-F]+)(?:\s|$|<)", instruction.operands)
    return int(match[1], 16) if match else None


def immediate_is(instruction, destination, expected):
    operands = instruction.op().split(",")
    if len(operands) != 2 or operands[0] != destination:
        return False
    try:
        value = int(operands[1], 0)
    except ValueError:
        return False
    return -(1 << 63) <= value < (1 << 64) and value & ((1 << 64) - 1) == expected & ((1 << 64) - 1)


def instruction_is(instruction, mnemonic, operands=""):
    return instruction.mnemonic == mnemonic and instruction.op() == operands


def check_target_load(body, index, offset):
    register = body[index].op().split(",")[1]
    require(register in ("rax", "rdx"), "unexpected CR3 source register")
    loads = [i for i in range(max(0, index - 10), index)
             if body[i].mnemonic == "mov" and body[i].op() in
             (f"{register},gs:[{offset}]", f"{register},gs:[0x{offset:x}]")]
    require(bool(loads), f"CR3 source lacks expected GS offset {offset}")
    load = loads[-1]
    between = body[load + 1:index]
    require(len(between) in (2, 4), "unexpected instructions between root load and CR3 write")
    require(index + 1 < len(body), "CR3 write has no continuation")
    if len(between) == 4:
        require(instruction_is(between[0], "test", f"{register},{register}"),
                "zero-root test uses wrong register")
        require(between[1].mnemonic in ("je", "jz") and
                branch_target(between[1]) == body[index + 1].address,
                "zero-root branch does not skip exactly the CR3 write")
    comparison, skip = between[-2:]
    opposite = 40 if offset == 32 else 32
    expected_comparisons = (f"{register},gs:[{opposite}]", f"{register},gs:[0x{opposite:x}]")
    require(comparison.mnemonic == "cmp" and comparison.op() in expected_comparisons,
            "same-root comparison uses wrong register/root")
    require(skip.mnemonic in ("je", "jz") and branch_target(skip) == body[index + 1].address,
            "same-root branch does not skip exactly the CR3 write")
    return register


def check_flags_mask(sequence, scratch):
    require(len(sequence) == 3 and sequence[0].mnemonic in ("mov", "movabs") and
            immediate_is(sequence[0], scratch, USER_FLAGS_MASK) and
            instruction_is(sequence[1], "and", f"r11,{scratch}") and
            sequence[2].mnemonic == "or" and immediate_is(sequence[2], "r11", 0x200),
            "user return does not sanitize RFLAGS and enable IF")


def check_syscall_paths(body, writes):
    """Prove the normal, nested-user and kernel-origin branches independently.

    The two early carry branches identify the rejection blocks. Neither is a
    normal return that needs another CR3 write: user rejection never left its
    original root; kernel rejection never changed GS, stack or root ownership.
    Unknown branches/returns fail closed instead of disappearing behind a count.
    """
    require(len(body) >= 12 and len(writes) == 2, "incomplete syscall entry body")
    addresses = {item.address: index for index, item in enumerate(body)}
    require(len(addresses) == len(body), "ambiguous syscall instruction addresses")
    carry = ("jb", "jc", "jnae")
    require(instruction_is(body[0], "clac") and body[1].mnemonic == "bt" and
            immediate_is(body[1], "rcx", 47) and instruction_is(body[2], "lfence") and
            body[3].mnemonic in carry, "kernel-origin guard must precede SWAPGS")
    require(instruction_is(body[4], "swapgs") and instruction_is(body[5], "lfence") and
            body[6].mnemonic == "lock" and body[6].op() in
            ("btsgs:[24],0", "btsgs:[0x18],0x0", "btsgs:[24],0x0", "btsgs:[0x18],0") and
            body[7].mnemonic in carry,
            "nested guard must reserve the active bit before scratch/stack ownership")
    require(body[8].mnemonic == "mov" and body[8].op() in ("gs:[8],rsp", "gs:[0x8],rsp") and
            body[9].mnemonic == "mov" and body[9].op() in ("rsp,gs:[0]", "rsp,gs:[0x0]") and
            9 < writes[0], "nested rejection occurs after a user-stack/scratch side effect")
    kernel = addresses.get(branch_target(body[3]))
    nested = addresses.get(branch_target(body[7]))
    require(kernel is not None and nested is not None and 9 < nested < kernel,
            "entry guards do not target distinct rejection blocks")

    # These short terminal blocks have no hidden memory access or control flow.
    rejection = body[nested:kernel]
    require(len(rejection) == 7 and rejection[0].mnemonic == "mov" and
            immediate_is(rejection[0], "rax", -16), "invalid nested-user rejection block")
    check_flags_mask(rejection[1:4], "r10")
    require(instruction_is(rejection[4], "swapgs") and instruction_is(rejection[5], "lfence") and
            rejection[6].mnemonic in ("sysret", "sysretq"),
            "nested rejection must restore user GS then SYSRET without stack/root writes")
    kernel_block = body[kernel:kernel + 4]
    require(len(kernel_block) == 4 and kernel_block[0].mnemonic == "mov" and
            immediate_is(kernel_block[0], "rax", -16) and
            instruction_is(kernel_block[1], "push", "r11") and
            instruction_is(kernel_block[2], "popfq") and instruction_is(kernel_block[3], "jmp", "rcx"),
            "kernel rejection must preserve GS/CR3 and restore its caller flags/continuation")
    require(all(item.mnemonic == "int3" for item in body[kernel + 4:]),
            "unexpected code after kernel-origin rejection")
    returns = [i for i, item in enumerate(body) if item.mnemonic in ("sysret", "sysretq")]
    nested_return = nested + 6
    require(len(returns) == 2 and nested_return in returns,
            "syscall body must have exactly normal and nested-user SYSRET paths")
    normal = next(index for index in returns if index != nested_return)
    require(writes[0] < writes[1] < normal < nested,
            "normal CR3 writes do not precede their own SYSRET")
    require(instruction_is(body[normal - 2], "swapgs") and instruction_is(body[normal - 1], "lfence"),
            "normal SYSRET lacks final SWAPGS/LFENCE")
    require({i for i, item in enumerate(body) if item.mnemonic == "swapgs"} == {4, normal - 2, nested + 4},
            "unexpected SWAPGS changes syscall GS ownership")

    # Noncanonical or high-half saved RIP/RSP must leave the normal path while
    # kernel GS/root/stack are still owned, into the named no-return handler.
    bad = normal + 1
    fatal = body[bad:nested]
    require(len(fatal) == 5 and fatal[0].mnemonic == "mov" and fatal[0].op() in
            ("rdi,[r12+8]", "rdi,[r12+0x8]") and fatal[1].mnemonic == "mov" and fatal[1].op() in
            ("rsi,[r12+32]", "rsi,[r12+0x20]") and fatal[2].mnemonic == "mov" and fatal[2].op() in
            ("r12,[r12+96]", "r12,[r12+0x60]") and fatal[3].mnemonic == "sub" and
            immediate_is(fatal[3], "rsp", 8) and fatal[4].mnemonic.startswith("call") and
            re.search(r"<syscall_bad_return>$", fatal[4].operands),
            "bad user return is not routed to the owned-root no-return handler")
    guards = []
    for offset in (8, 32):
        candidates = [i for i in range(writes[0] + 1, writes[1]) if body[i].mnemonic == "mov" and
                      body[i].op() in (f"rdx,[r12+{offset}]", f"rdx,[r12+0x{offset:x}]")]
        require(len(candidates) == 1, "missing/ambiguous saved user return address guard")
        start = candidates[0]
        sequence = body[start:start + 8]
        require(len(sequence) == 8 and instruction_is(sequence[1], "mov", "rbx,rdx") and
                sequence[2].mnemonic == "shl" and immediate_is(sequence[2], "rbx", 16) and
                sequence[3].mnemonic == "sar" and immediate_is(sequence[3], "rbx", 16) and
                instruction_is(sequence[4], "cmp", "rbx,rdx") and sequence[5].mnemonic in ("jne", "jnz") and
                branch_target(sequence[5]) == body[bad].address and sequence[6].mnemonic == "bt" and
                immediate_is(sequence[6], "rdx", 47) and sequence[7].mnemonic in carry and
                branch_target(sequence[7]) == body[bad].address and start + 7 < writes[1],
                "saved RIP/RSP checks do not reject canonicality/high-half violations before return")
        guards.extend((start + 5, start + 7))
    flags = [i for i in range(guards[-1] + 1, writes[1]) if body[i].mnemonic == "mov" and
             body[i].op() in ("r11,[r12+88]", "r11,[r12+0x58]")]
    require(len(flags) == 1, "normal return lacks saved user RFLAGS")
    check_flags_mask(body[flags[0] + 1:flags[0] + 4], "r13")
    require(not any("r11" in item.op() for item in body[flags[0] + 4:normal]),
            "normal user RFLAGS may change after sanitization")
    epilogues = [i for i in range(writes[0] + 1, writes[1]) if body[i].mnemonic == "jmp"]
    require(len(epilogues) == 1 and branch_target(body[epilogues[0]]) == body[epilogues[0] + 1].address and
            instruction_is(body[epilogues[0] + 1], "cli"), "normal epilogue has an unexpected control transfer")
    allowed_branches = {3, 7, writes[0] - 1, writes[1] - 1, *guards, *epilogues, kernel + 3}
    branches = {i for i, item in enumerate(body) if item.mnemonic.startswith(("j", "loop"))}
    require(branches == allowed_branches, "unknown syscall branch could bypass root/return ownership")
    require(not any(item.mnemonic.startswith(("iret", "ret")) or item.mnemonic in ("syscall", "sysenter", "sysexit")
                    for item in body), "unknown syscall return/entry instruction")
    return {"normal_return": normal, "nested_guard": 7, "nested_entry": nested,
            "nested_return": nested_return, "kernel_guard": 3, "kernel_entry": kernel,
            "kernel_return": kernel + 3, "bad_return": bad, "bad_guards": guards}


def check_cs_guard(body, index, returning):
    candidates = [i for i in range(max(0, index - 12), index)
                  if body[i].mnemonic == "test" and body[i].op() in ("al,3", "al,0x3")]
    require(bool(candidates), "timer CR3 load lacks CS-RPL test")
    test = candidates[-1]
    require(test > 0 and body[test - 1].mnemonic == "mov" and
            body[test - 1].op() in ("rax,[rsp+128]", "rax,[rsp+0x80]"),
            "timer RPL test is not sourced from hardware-frame CS")
    skip = index + 1
    if returning:
        swap = next((i for i in range(skip, len(body)) if body[i].mnemonic == "swapgs"), None)
        require(swap is not None and swap + 1 < len(body), "timer return has no GS restore")
        skip = swap + 1
    require(test + 1 < index and body[test + 1].mnemonic in ("je", "jz") and
            branch_target(body[test + 1]) == body[skip].address,
            "kernel-origin timer path does not skip CR3 write")


def verify_generated(symbols, scope=None):
    dormant = [name for name in symbols if re.sub(r"::h[0-9a-f]+$", "", name).split("::")[-1] == DORMANT_ENTRY]
    if dormant:
        raise EvidenceUnavailable("manual enter_usermode is unexpectedly linked; its runtime scope requires review")
    sites = []
    syscall_paths = None
    for name in STUBS:
        body = body_for(symbols, name)
        writes = [i for i, item in enumerate(body)
                  if item.mnemonic == "mov" and item.op().startswith("cr3,")]
        expected = 2 if name in STUBS[:2] else 1
        require(len(writes) == expected, f"{name}: expected {expected} CR3 writes")
        if name == "syscall_entry_stub":
            syscall_paths = check_syscall_paths(body, writes)
            end = syscall_paths["normal_return"]
        else:
            exits = [i for i, item in enumerate(body) if item.mnemonic in ("iret", "iretq")]
            require(len(exits) == 1, f"{name}: missing/ambiguous normal return")
            end = exits[0]
        require(writes[-1] < end, f"{name}: user root loaded after return")
        swaps = [i for i in range(writes[-1] + 1, end) if body[i].mnemonic == "swapgs"]
        require(len(swaps) == 1, f"{name}: user CR3 must precede final swapgs")
        require(not any(item.mnemonic.startswith("call") for item in body[writes[-1] + 1:end]),
                f"{name}: Rust call remains after user-root write")
        if expected == 2:
            calls = [i for i in range(end) if body[i].mnemonic.startswith("call")]
            require(bool(calls) and writes[0] < calls[0] <= calls[-1] < writes[1],
                    f"{name}: CR3 writes do not bracket the normal Rust body")
        if name == "timer_interrupt_stub":
            for sequence, index in enumerate(writes):
                check_cs_guard(body, index, sequence == 1)
        for sequence, index in enumerate(writes):
            direction = "kernel" if expected == 2 and sequence == 0 else "user"
            register = check_target_load(body, index, 32 if direction == "kernel" else 40)
            sites.append({"name": f"{name}:{direction}", "stub": name,
                          "direction": direction, "address": body[index].address,
                          "length": body[index].length, "register": register,
                          "bytes": body[index].raw.hex()})
    require(len({site["address"] for site in sites}) == 5, "CR3 sites are not five distinct linked instructions")
    if scope is not None:
        body = body_for(symbols, "syscall_entry_stub")
        scope.update({"linked_entry_bodies": list(STUBS), "linked_cr3_sites": 5,
                      "manual_entry": {"name": DORMANT_ENTRY, "linked": False, "executed": False},
                      "syscall_paths": {name: [hex(body[i].address) for i in index] if isinstance(index, list)
                                        else hex(body[index].address) for name, index in syscall_paths.items()},
                      "rejection_path_evidence": "generated control flow; not dynamically exercised by the workload"})
    return sites


def verify_mutations(symbols):
    verified = []
    sites = verify_generated(symbols)

    def copy_bodies():
        return {name: list(body) if re.sub(r"::h[0-9a-f]+$", "", name).split("::")[-1] in STUBS else body
                for name, body in symbols.items()}

    def rejected(label, mutated):
        try:
            verify_generated(mutated)
        except (ProofFailure, EvidenceUnavailable):
            verified.append(label)
        else:
            raise ProofFailure("mutation escaped oracle: " + label)

    for site in sites:
        mutated = copy_bodies()
        body = body_for(mutated, site["stub"])
        body[:] = [item for item in body if item.address != site["address"]]
        rejected("delete:" + site["name"], mutated)
    for name in STUBS:
        mutated = copy_bodies()
        body = body_for(mutated, name)
        index = next(i for i, item in enumerate(body) if item.op().startswith("cr3,"))
        moved = body.pop(index)
        marker = next(i for i in range(index, len(body))
                      if body[i].mnemonic.startswith("call") or body[i].mnemonic == "swapgs")
        body.insert(marker + 1, moved)
        rejected("reorder:" + name, mutated)

    original = body_for(symbols, "syscall_entry_stub")
    writes = [i for i, item in enumerate(original) if item.mnemonic == "mov" and item.op().startswith("cr3,")]
    paths = check_syscall_paths(original, writes)
    nested, kernel, normal = paths["nested_entry"], paths["kernel_entry"], paths["normal_return"]
    changes = [
        ("kernel-guard-target", 3, {"operands": hex(original[4].address)}),
        ("kernel-guard-polarity", 3, {"mnemonic": "jae"}),
        ("kernel-origin-fence", 2, {"mnemonic": "nop"}),
        ("nested-guard-target", 7, {"operands": hex(original[8].address)}),
        ("nested-active-bit", 6, {"operands": "bts qword ptr gs:[0x18], 1"}),
        ("nested-cr3-write", nested, {"mnemonic": "mov", "operands": "cr3, rax"}),
        ("nested-rust-call", nested, {"mnemonic": "call", "operands": "0x9990 <unowned_rust>"}),
        ("nested-stack-write", nested, {"mnemonic": "mov", "operands": "qword ptr [rsp], rax"}),
        ("nested-owner-clear", nested + 1, {"mnemonic": "mov", "operands": "qword ptr gs:[0x18], 0"}),
        ("nested-flags-mask", nested + 1, {"operands": "r10, -1"}),
        ("nested-flags-if", nested + 3, {"operands": "r11, 0"}),
        ("nested-return-fence", nested + 5, {"mnemonic": "nop"}),
        ("kernel-root-write", kernel, {"mnemonic": "mov", "operands": "cr3, rax"}),
        ("kernel-gs-swap", kernel, {"mnemonic": "swapgs", "operands": ""}),
        ("kernel-flags-source", kernel + 1, {"operands": "rax"}),
        ("kernel-continuation", kernel + 3, {"operands": "rax"}),
        ("normal-root-bypass", writes[1] - 1, {"operands": hex(original[normal].address)}),
        ("normal-return-fence", normal - 1, {"mnemonic": "nop"}),
        ("normal-flags-after-mask", normal - 3, {"mnemonic": "or", "operands": "r11, 0x3000"}),
        ("normal-extra-swapgs", writes[0] + 2, {"mnemonic": "swapgs", "operands": ""}),
    ]
    changes += [(f"bad-return-guard-{number}", index, {"operands": hex(original[normal].address)})
                for number, index in enumerate(paths["bad_guards"])]
    for label, index, replacement in changes:
        mutated = copy_bodies()
        body = body_for(mutated, "syscall_entry_stub")
        body[index] = replace(body[index], **replacement)
        rejected("syscall:" + label, mutated)
    mutated = copy_bodies()
    body = body_for(mutated, "syscall_entry_stub")
    body.append(replace(body[normal], address=body[-1].address + body[-1].length))
    rejected("syscall:extra-sysret", mutated)
    mutated = copy_bodies()
    mutated[DORMANT_ENTRY] = list(body_for(symbols, "switch_to_user"))
    rejected("scope:unexpected-manual-entry", mutated)
    return verified


MAP_FIELDS = {"shared_user": "true", "recursive_absent": "true", "private_island": "true",
              "lower_island_absent": "true", "text_retained": "true", "data_retained": "true",
              "heap_retained": "true", "stack_retained": "true", "full_isolation": "false"}


def parse_mapping_records(serial):
    records = []
    for line in serial.splitlines():
        if "MITIGATION-MAP" not in line:
            continue
        match = re.search(r"MITIGATION-MAP PASS (.+)$", line.strip())
        require(match is not None, "malformed/failed mapping record")
        pairs = [token.split("=", 1) for token in match[1].split()]
        require(all(len(pair) == 2 for pair in pairs), "malformed mapping field")
        fields = dict(pairs)
        require(len(fields) == len(pairs) and set(fields) == set(MAP_FIELDS) | {"kernel", "user", "low_alias"},
                "mapping fields missing, duplicated or unexpected")
        require(all(fields[key] == value for key, value in MAP_FIELDS.items()),
                "mapping record contradicts partial-isolation contract")
        require(fields["low_alias"] in ("true", "false"), "invalid low_alias observation")
        require(all(re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", fields[key]) for key in ("kernel", "user")),
                "invalid physical root value")
        kernel, user = int(fields["kernel"], 16), int(fields["user"], 16)
        require(kernel != user and kernel != 0 and user != 0 and
                kernel & PHYSICAL == kernel and user & PHYSICAL == user,
                "roots are identical, unaligned or outside physical mask")
        records.append({**fields, "kernel": kernel, "user": user})
    if not records:
        raise EvidenceUnavailable("actual constructor mapping records not observed")
    return records


def parse_registers(text):
    registers = {name.lower(): int(value, 16)
                 for name, value in re.findall(r"\b([A-Z][A-Z0-9]+)\s*=\s*([0-9a-fA-F]+)\b", text)}
    if not {"rip", "cr3", "rax", "rdx", "cs", "cpl"}.issubset(registers):
        raise EvidenceUnavailable("monitor did not expose RIP/CR3/RAX/RDX/CS/CPL")
    return registers


def parse_stop_thread(stop):
    # qC describes the thread selected for general operations. In all-stop
    # mode it can remain on the BSP when another CPU triggers a breakpoint.
    # Only the event's explicit thread field identifies the stopped CPU.
    if not re.fullmatch(r"T[0-9a-fA-F]{2}(?:[^;\r\n]+;)*", stop):
        raise EvidenceUnavailable("RSP proof stop lacks a complete T thread record")
    if int(stop[1:3], 16) != 5:
        raise ProofFailure(f"RSP proof stop was not SIGTRAP: {stop}")
    fields = [field.split(":", 1) for field in stop[3:].split(";") if field]
    if any(len(field) != 2 or not field[0] for field in fields):
        raise EvidenceUnavailable("RSP proof stop has malformed fields")
    threads = [value for key, value in fields if key == "thread"]
    if len(threads) != 1 or not re.fullmatch(
            r"(?:p[0-9a-fA-F]{1,16}\.)?[0-9a-fA-F]{1,16}", threads[0]):
        raise EvidenceUnavailable("RSP proof stop has missing, malformed or ambiguous thread identity")
    thread = threads[0]
    identities = thread[1:].split(".") if thread.startswith("p") else [thread]
    if any(int(identity, 16) == 0 for identity in identities):
        raise EvidenceUnavailable("RSP proof stop identifies no concrete QEMU thread")
    return thread


def parse_anchor_symbols(text):
    found = {}
    for name in (ANCHOR, RELEASE):
        matches = re.findall(r"^\s*([0-9a-fA-F]+)\s+.*\s" + re.escape(name) + r"\s*$", text, re.M)
        if len(matches) != 1:
            raise EvidenceUnavailable(f"expected one retained ELF symbol {name}, found {len(matches)}")
        found[name] = int(matches[0], 16)
        require(found[name] >= 0xFFFF800000000000, "anchor symbol is not in canonical kernel space")
    require(found[ANCHOR] != found[RELEASE], "anchor function aliases release byte")
    return found


def relocate_sites(serial, linked, sites):
    observations = []
    for line in serial.splitlines():
        if "MITIGATION-ANCHOR" not in line:
            continue
        match = re.search(r"MITIGATION-ANCHOR symbol=" + ANCHOR +
                          r" runtime=(0x[0-9a-fA-F]+) release=(0x[0-9a-fA-F]+)$", line.strip())
        require(match is not None, "malformed runtime relocation anchor")
        observations.append((int(match[1], 16), int(match[2], 16)))
    if not observations:
        raise EvidenceUnavailable("runtime relocation anchor not observed")
    require(len(set(observations)) == 1, "runtime relocation anchors disagree")
    anchor, release = observations[0]
    slide = anchor - linked[ANCHOR]
    require(release - linked[RELEASE] == slide, "function/data anchors disagree on relocation")
    require(slide & 4095 == 0, "runtime relocation is not page aligned")
    require(all(0xFFFF800000000000 <= address <= 0xFFFFFFFFFFFFFFFF
                for address in (anchor, release)), "runtime anchor is not canonical kernel memory")
    relocated = [{**site, "linked_address": site["address"], "address": site["address"] + slide}
                 for site in sites]
    require(all(0xFFFF800000000000 <= site["address"] <= 0xFFFFFFFFFFFFFFFF
                for site in relocated), "runtime proof site is outside kernel memory")
    return relocated, {"anchor": anchor, "release": release, "slide": slide,
                       "linked_symbols": linked, "record_count": len(observations)}


def verify_transition(site, before, after):
    source, previous, current = (before[site["register"]] & PHYSICAL,
                                 before["cr3"] & PHYSICAL, after["cr3"] & PHYSICAL)
    require(before["rip"] == site["address"], "stop was not at the expected generated instruction")
    require(after["rip"] == site["address"] + site["length"], "single-step did not retire exactly the CR3 write")
    require(source != 0 and previous != current and current == source,
            "CR3 did not change to its actual source-register physical root")
    require(all(registers["cpl"] == 0 and registers["cs"] & 3 == 0
                for registers in (before, after)), "CR3 write did not execute at CPL0")


def step_cr3_instruction(remote, site, before, thread, attempts, record_path):
    """Retry only a wholly unchanged debugger stop; never count it as retirement."""
    opcode = bytes.fromhex(site["bytes"])
    for attempt in range(3):  # One initial attempt, at most two no-progress retries.
        record = {"site": site["name"], "address": site["address"],
                  "thread": thread, "attempt": attempt + 1, "before": dict(before)}
        attempts.append(record)
        try:
            actual = remote.memory(site["address"], site["length"])
            record["opcode_before"] = actual.hex()
            require(actual == opcode, "CR3 opcode changed before single-step")
            record["command"] = "vCont;s:" + thread
            stop = remote.step_thread(thread)
            record["stop"] = stop
            after_thread, after = remote.registers(stop, expected_thread=thread)
            record.update(after_thread=after_thread, after=after)
            actual = remote.memory(site["address"], site["length"])
            record["opcode_after"] = actual.hex()
            require(actual == opcode, "CR3 opcode changed during single-step")
            if after == before:
                # A pending debugger trap may stop before the instruction runs.
                # Every exposed register, including keys, must be unchanged.
                # A different thread/signal/opcode is rejected before this gate.
                record["outcome"] = "no-progress"
                require(attempt < 2, "single-step made no progress after three attempts")
                continue
            verify_transition(site, before, after)
            record["outcome"] = "retired"
            return after
        except (ProofFailure, EvidenceUnavailable) as error:
            record["error"] = str(error)
            record.setdefault("outcome", "rejected")
            raise
        finally:
            # Retain unsuccessful observations even when the proof aborts.
            write_json(record_path, attempts)
    raise AssertionError("bounded CR3 step must return or fail")


def bind_transitions(sites, transitions, mappings, cpus=1):
    require({item["name"] for item in transitions} == {site["name"] for site in sites} and
            len({(item["name"], item["cpu"]) for item in transitions}) == len(transitions),
            "missing or duplicate site/CPU observations")
    for site in sites:
        observed = {item["cpu"] for item in transitions if item["name"] == site["name"]}
        required = cpus if site["stub"] in STUBS[:2] else 1
        require(len(observed) == required and observed <= set(range(cpus)),
                "missing requested CPU transition: " + site["name"])
    for transition in transitions:
        available = transition.get("mapping_records_before", mappings)
        pairs = {(record["kernel"], record["user"]) for record in available}
        before = transition["before"]["cr3"] & PHYSICAL
        after = transition["after"]["cr3"] & PHYSICAL
        pair = (after, before) if transition["direction"] == "kernel" else (before, after)
        require(pair in pairs, "observed CR3 transition has no actual constructor pair")
        if transition["direction"] == "user":
            returned = transition.get("user_return", {})
            require(returned.get("cpl") == 3 and returned.get("cs", 0) & 3 == 3 and
                    returned.get("cr3", 0) & PHYSICAL == after,
                    "user-root write did not reach a matching CPL3 return")


def verify_workload(serial, cpus):
    lines = serial.splitlines()
    clock = [line for line in lines if line.startswith("BSP-TIMER ")]
    require(len(clock) == 1, "missing or duplicate BSP clock observation")
    rate = re.fullmatch(r"BSP-TIMER PASS: ticks=(\d+) hpet_ms=(\d+) tolerance_percent=25", clock[0])
    require(rate is not None, "BSP clock reference failed or was unavailable")
    ticks, elapsed = map(int, rate.groups())
    require(elapsed >= 250 and elapsed * 3 // 4 <= ticks <= elapsed * 5 // 4,
            "BSP tick rate is outside the independently measured 1 kHz band")
    start = f"MITIGATION-WORKLOAD BEGIN pid=1 cpus={cpus} forks={cpus} execs={cpus}"
    finish = f"MITIGATION-WORKLOAD PASS cpus={cpus} forks={cpus} execs={cpus}"
    require(lines.count(start) == 1 and lines.count(finish) == 1,
            "missing or duplicate workload boundary")
    start_index, finish_index = lines.index(start), lines.index(finish)
    workers, waits, retries = {}, {}, {}
    for index, line in enumerate(lines):
        if line.startswith("MITIGATION-WORKER "):
            match = re.fullmatch(r"MITIGATION-WORKER (BEGIN|PASS|RETRY) phase=(fork|exec) cpu=(\d+) pid=(\d+) (.+)", line)
            require(match is not None, "malformed worker observation")
            state, phase, cpu, pid, fields = match.groups()
            cpu, pid = int(cpu), int(pid)
            if state == "RETRY":
                detail = re.fullmatch(r"attempt=(\d+) errno=(\d+)", fields)
                require(detail is not None and phase == "exec" and int(detail[1]) > 0 and
                        int(detail[1]) <= MAX_EXEC_RETRIES and int(detail[2]) == 12,
                        "malformed transient exec retry")
                key = (phase, cpu, int(detail[1]))
                require(key not in retries and 0 <= cpu < cpus and pid > 1,
                        "duplicate or invalid worker retry")
                retries[key] = (pid, index)
                continue
            key = (state, phase, cpu)
            require(key not in workers and 0 <= cpu < cpus and pid > 1,
                    "duplicate or invalid worker identity")
            if state == "BEGIN":
                detail = re.fullmatch(r"affinity=([0-9a-f]+)", fields)
                require(detail is not None and int(detail[1], 16) == 1 << cpu,
                        "worker affinity target differs from requested CPU")
            else:
                detail = re.fullmatch(r"calls=(\d+) elapsed_ms=(\d+) checksum=([0-9a-f]+)", fields)
                require(detail is not None and int(detail[1]) > 0 and int(detail[2]) >= 250,
                        "worker did not exercise syscall and timer workload")
            workers[key] = (pid, index)
        elif line.startswith("MITIGATION-WAIT "):
            match = re.fullmatch(r"MITIGATION-WAIT PASS cpu=(\d+) pid=(\d+) raw_status=0 code=0", line)
            require(match is not None, "worker did not exit successfully")
            cpu, pid = map(int, match.groups())
            require(cpu not in waits and 0 <= cpu < cpus, "duplicate or invalid worker wait")
            waits[cpu] = (pid, index)
    expected = {(state, phase, cpu) for state in ("BEGIN", "PASS")
                for phase in ("fork", "exec") for cpu in range(cpus)}
    require(set(workers) == expected and set(waits) == set(range(cpus)),
            "worker fork/exec/return/wait evidence is incomplete")
    worker_pids = set()
    for cpu in range(cpus):
        observations = [workers[(state, phase, cpu)] for phase in ("fork", "exec")
                        for state in ("BEGIN", "PASS")] + [waits[cpu]]
        pids = {pid for pid, _ in observations}
        require(len(pids) == 1, "exec/wait changed worker process identity")
        worker_pids.update(pids)
        order = [start_index] + [index for _, index in observations] + [finish_index]
        require(order == sorted(set(order)), "worker lifecycle observations are out of order")
    require(len(worker_pids) == cpus, "workers do not have distinct process identities")
    for cpu in range(cpus):
        attempts = sorted(attempt for phase, retry_cpu, attempt in retries
                          if phase == "exec" and retry_cpu == cpu)
        require(attempts == list(range(1, len(attempts) + 1)),
                "worker retry attempts are not contiguous")
        expected_pid = workers.get(("BEGIN", "exec", cpu), (None,))[0]
        require(all(pid == expected_pid for (phase, retry_cpu, _), (pid, _) in retries.items()
                    if phase == "exec" and retry_cpu == cpu),
                "worker retry changed process identity")
        # A transient ENOMEM can be reported either by the forking image before
        # exec succeeds (between fork PASS and the new image's BEGIN marker) or
        # by a synthetic monitor fixture after BEGIN. Accept both bounded
        # positions while rejecting retries outside the worker's lifecycle.
        begin_index = workers[("BEGIN", "exec", cpu)][1]
        fork_pass_index = workers[("PASS", "fork", cpu)][1]
        pass_index = workers[("PASS", "exec", cpu)][1]
        require(all((fork_pass_index < index < begin_index) or
                    (begin_index < index < pass_index)
                    for (phase, retry_cpu, _), (_, index) in retries.items()
                    if phase == "exec" and retry_cpu == cpu),
                "worker retry is outside its exec lifecycle")
    exits = [(index, match[1]) for index, line in enumerate(lines)
             if (match := re.fullmatch(r"Process 1 terminated with exit code (\d+)", line))]
    require(len(exits) == 1 and exits[0][1] == "0" and exits[0][0] > finish_index,
            "proof workload PID1 did not complete once after its successful workers")
    require(not re.search(r"KERNEL PANIC|panicked at|MITIGATION-.*(?:FAIL|UNREAPED)", serial),
            "failed mitigation workload")


def verify_build_provenance(record, kernel_hash):
    require(isinstance(record, dict) and record.get("target") == "build-mitigation-probe" and
            record.get("status") == 0, "missing successful executed mitigation build record")
    steps = record.get("steps", [])
    require(isinstance(steps, list) and len(steps) >= 3, "missing workload/bootloader/kernel build commands")
    for step in steps:
        require(isinstance(step, dict) and isinstance(step.get("cwd"), str) and
                isinstance(step.get("env"), dict) and isinstance(step.get("argv"), list) and
                bool(step["argv"]) and all(isinstance(arg, str) for arg in step["argv"]),
                "malformed executed build step")
    outputs = record.get("outputs", {})
    require(isinstance(outputs, dict) and kernel_hash in outputs.values(),
            "built output hash does not match the proof ELF")


class Remote:
    """Small acknowledged RSP client; never invokes a shell or external GDB."""
    def __init__(self, connection, deadline):
        self.connection, self.deadline, self.transcript = connection, deadline, []
        self.thread_step_supported = False
        self.buffer = b""
        self.buffer_offset = 0

    def byte(self):
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise EvidenceUnavailable("RSP observation deadline expired")
            if self.buffer_offset < len(self.buffer):
                value = self.buffer[self.buffer_offset:self.buffer_offset + 1]
                self.buffer_offset += 1
                return value
            self.connection.settimeout(min(remaining, 5))
            try:
                self.buffer = self.connection.recv(65536)
                self.buffer_offset = 0
            except socket.timeout:
                continue
            if not self.buffer:
                raise EvidenceUnavailable("QEMU closed its RSP connection")

    def send(self, text):
        payload = text.encode("ascii")
        packet = b"$" + payload + b"#" + f"{sum(payload) & 255:02x}".encode()
        self.transcript.append({"send": text})
        self.connection.sendall(packet)

    def receive(self):
        while True:
            byte = self.byte()
            if byte == b"$":
                break
            if byte == b"-":
                raise EvidenceUnavailable("RSP server rejected request checksum")
            if byte not in (b"+",):
                raise EvidenceUnavailable("unexpected RSP packet prefix")
        encoded = bytearray()
        while True:
            byte = self.byte()
            if byte == b"#":
                break
            encoded.extend(byte)
            if len(encoded) > 1024 * 1024:
                raise EvidenceUnavailable("RSP reply exceeded bound")
        checksum = self.byte() + self.byte()
        if checksum != f"{sum(encoded) & 255:02x}".encode():
            raise EvidenceUnavailable("RSP reply checksum mismatch")
        self.connection.sendall(b"+")
        decoded, index = bytearray(), 0
        while index < len(encoded):
            value = encoded[index]
            if value == ord("}"):
                index += 1
                if index >= len(encoded):
                    raise EvidenceUnavailable("truncated RSP escape")
                decoded.append(encoded[index] ^ 32)
            elif value == ord("*"):
                index += 1
                if not decoded or index >= len(encoded) or encoded[index] < 29:
                    raise EvidenceUnavailable("invalid RSP run-length data")
                decoded.extend([decoded[-1]] * (encoded[index] - 29))
            else:
                decoded.append(value)
            index += 1
        response = decoded.decode("ascii")
        self.transcript.append({"receive": response})
        return response

    def command(self, text):
        self.send(text)
        return self.receive()

    def ok(self, text):
        reply = self.command(text)
        if reply != "OK":
            raise EvidenceUnavailable(f"RSP command unsupported/rejected: {text}: {reply}")

    def interrupt(self):
        self.transcript.append({"interrupt": True})
        self.connection.sendall(b"\x03")
        response = self.receive()
        if not response.startswith(("T", "S")):
            raise EvidenceUnavailable("RSP interrupt did not stop all guest CPUs")
        return response

    def memory(self, address, length):
        response = self.command(f"m{address:x},{length:x}")
        if not re.fullmatch(r"[0-9a-fA-F]{" + str(length * 2) + r"}", response):
            raise EvidenceUnavailable(f"RSP cannot read {length} bytes at {address:x}")
        return bytes.fromhex(response)

    def monitor(self, text):
        reply = self.command("qRcmd," + text.encode().hex())
        output = bytearray()
        while reply.startswith("O") and reply != "OK":
            output.extend(bytes.fromhex(reply[1:]))
            reply = self.receive()
        if reply != "OK":
            raise EvidenceUnavailable(f"QEMU monitor command failed: {text}: {reply}")
        return output.decode("ascii", errors="replace")

    def registers(self, stop, expected_thread=None):
        thread = parse_stop_thread(stop)
        if expected_thread is not None:
            require(thread == expected_thread, "single-step changed QEMU CPU thread")
        cpu = int(thread.split(".")[-1], 16) - 1
        self.ok("Hg" + thread)
        self.ok("Hc" + thread)
        if self.monitor(f"cpu {cpu}").strip():
            raise EvidenceUnavailable("QEMU monitor rejected CPU selection")
        return thread, parse_registers(self.monitor("info registers"))

    def require_thread_steps(self):
        if self.thread_step_supported:
            return
        response = self.command("vCont?")
        if not re.fullmatch(r"vCont(?:;[A-Za-z])+", response) or "s" not in response.split(";")[1:]:
            raise EvidenceUnavailable("RSP does not advertise thread-specific vCont step: " + response)
        self.thread_step_supported = True

    def step_thread(self, thread):
        # Validate a concrete ID so no wildcard/default action can resume peers.
        if parse_stop_thread("T05thread:" + thread + ";") != thread:
            raise EvidenceUnavailable("RSP step needs exactly one concrete thread identity")
        self.require_thread_steps()
        # QEMU's legacy s sets c_cpu's step flag then resumes the entire VM.
        # A sole vCont action leaves unspecified vCPUs stopped during this step.
        return self.command("vCont;s:" + thread)


def run_tool(command, output):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceUnavailable(f"tool unavailable: {command}: {error}") from error
    output.write_bytes(result.stdout)
    if result.returncode:
        raise EvidenceUnavailable(f"tool failed ({result.returncode}): {command}; see {output.name}")
    return result.stdout.decode(errors="replace")


def tools_for(args, output):
    rustc = Path(run_tool(["rustup", "which", "--toolchain", args.toolchain, "rustc"],
                         output / "rustc-path.txt").strip())
    version = run_tool([str(rustc), "-vV"], output / "rustc-version.txt")
    host = re.search(r"^host: (.+)$", version, re.M)
    if not host:
        raise EvidenceUnavailable("rustc host triple not available")
    suffix = ".exe" if os.name == "nt" else ""
    objdump = args.objdump or rustc.parent.parent / "lib/rustlib" / host[1] / "bin" / ("llvm-objdump" + suffix)
    run_tool([str(objdump), "--version"], output / "objdump-version.txt")
    return rustc, objdump


def runtime_qemu_command(qemu, firmware, guest, output, socket_path, cpus, cpu_model):
    # icount keeps stopped debugger round trips out of the virtual timer clock.
    # Four logical vCPUs are still required; host execution is serialized by TCG.
    return [qemu, "-accel", "tcg,thread=single", "-icount", "shift=3,align=off,sleep=off",
            "-machine", "q35", "-bios", str(firmware),
            "-drive", f"format=raw,file=fat:{guest},snapshot=on", "-m", "256M",
            "-smp", str(cpus), "-cpu", cpu_model, "-display", "none",
            "-serial", f"file:{output / 'serial.log'}", "-no-reboot", "-no-shutdown",
            "-gdb", f"unix:{socket_path},server=on,wait=off", "-S"]


def runtime(args, output, sites, expected_kernel, linked, anchor_bytes):
    if not hasattr(socket, "AF_UNIX") or args.esp is None:
        raise EvidenceUnavailable("runtime proof requires Unix sockets and --esp")
    qemu = shutil.which(args.qemu)
    firmware = args.firmware or next((Path(name) for name in [os.environ.get("OVMF_PATH", ""),
        "/usr/share/qemu/OVMF.fd", "/usr/share/ovmf/OVMF.fd", "/usr/share/OVMF/OVMF_CODE.fd"]
        if name and Path(name).is_file()), None)
    if qemu is None or firmware is None:
        raise EvidenceUnavailable("QEMU or OVMF unavailable")
    if digest(args.esp / "kernel.elf") != expected_kernel:
        raise ProofFailure("ESP kernel differs from the statically verified ELF")
    guest = output / "esp"
    (guest / "EFI/BOOT").mkdir(parents=True)
    for name in ("kernel.elf", "EFI/BOOT/BOOTX64.EFI"):
        shutil.copyfile(args.esp / name, guest / name)
    require(digest(guest / "kernel.elf") == expected_kernel, "ESP kernel changed while copied")
    bootloader = guest / "EFI/BOOT/BOOTX64.EFI"
    identity = {"kernel": {"path": str(guest / "kernel.elf"), "sha256": digest(guest / "kernel.elf")},
                "bootloader": {"path": str(bootloader), "sha256": digest(bootloader)},
                "firmware": {"path": str(firmware.resolve()), "sha256": digest(firmware)},
                "qemu": {"path": qemu, "sha256": digest(qemu)}}
    write_json(output / "guest-inputs.json", identity)
    run_tool([qemu, "--version"], output / "qemu-version.txt")
    socket_dir = Path(tempfile.mkdtemp(prefix="mc-rsp-", dir="/tmp" if Path("/tmp").is_dir() else None))
    socket_path = socket_dir / "gdb"
    command = runtime_qemu_command(qemu, firmware, guest, output, socket_path, args.smp, args.cpu)
    write_json(output / "qemu-command.json", command)
    transitions, step_attempts, process, remote, connection = [], [], None, None, None
    deadline = time.monotonic() + args.timeout
    try:
        with (output / "qemu.stderr").open("wb") as error_log:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=error_log)
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            while True:
                if process.poll() is not None:
                    raise EvidenceUnavailable("QEMU exited before its RSP socket became ready")
                try:
                    connection.connect(str(socket_path))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if time.monotonic() >= deadline:
                        raise EvidenceUnavailable("QEMU RSP socket never became ready")
                    time.sleep(0.02)
            remote = Remote(connection, deadline)
            remote.command("qSupported:multiprocess+;hwbreak+")
            remote.command("?")
            remote.require_thread_steps()
            remote.ok("Qqemu.sstep=7")
            # The feature-only constructor waits on a zero release byte before
            # user entry. Obtain the loader's actual relocation, then stop every
            # CPU before touching the rendezvous or setting runtime breakpoints.
            remote.send("c")
            while True:
                if process.poll() is not None:
                    raise EvidenceUnavailable("QEMU exited before the relocation rendezvous")
                if time.monotonic() >= deadline:
                    raise EvidenceUnavailable("runtime relocation rendezvous was not observed")
                serial_path = output / "serial.log"
                prefix = serial_path.read_bytes() if serial_path.exists() else b""
                complete = prefix[:prefix.rfind(b"\n") + 1]
                if b"MITIGATION-ANCHOR" in complete:
                    break
                if re.search(rb"KERNEL PANIC|panicked at", complete):
                    raise ProofFailure("guest failed before relocation rendezvous")
                time.sleep(0.02)
            remote.interrupt()
            sites, relocation = relocate_sites(complete.decode(errors="replace"), linked, sites)
            relocation.update(serial_prefix_bytes=len(complete),
                              serial_prefix_sha256=hashlib.sha256(complete).hexdigest())
            require(remote.memory(relocation["release"], 1) == b"\0",
                    "relocation rendezvous was already released")
            require(remote.memory(relocation["anchor"], len(anchor_bytes)) == anchor_bytes,
                    "runtime anchor instruction differs from verified ELF")
            for site in sites:
                require(remote.memory(site["address"], site["length"]) == bytes.fromhex(site["bytes"]),
                        "runtime CR3 instruction differs from verified ELF: " + site["name"])
            relocation["runtime_instruction_bytes_verified"] = True
            write_json(output / "relocation.json", relocation)
            write_json(output / "runtime-sites.json", sites)
            remaining = {site["address"]: site for site in sites}
            observed_cpus = {site["name"]: set() for site in sites}
            repeats = 0
            for address in remaining:
                remote.ok(f"Z1,{address:x},1")
            remote.ok(f"M{relocation['release']:x},1:01")
            require(remote.memory(relocation["release"], 1) == b"\x01", "rendezvous release write did not persist")
            while remaining:
                remote.ok("Hc-1")
                stop = remote.command("c")
                if not stop.startswith(("T", "S")):
                    raise EvidenceUnavailable(f"guest did not stop at a proof site: {stop}")
                thread, before = remote.registers(stop)
                cpu = int(thread.split(".")[-1], 16) - 1
                require(0 <= cpu < args.smp, "observed CPU is outside requested topology")
                site = remaining.get(before["rip"])
                if site is None:
                    raise ProofFailure(f"unexpected guest stop RIP={before['rip']:x}: {stop}")
                # QEMU keeps an address-level breakpoint armed for every vCPU
                # that reaches it, so a site whose remaining CPUs never appear
                # is revisited without progress. Bound those repeats so the
                # proof reports the missing observation instead of letting the
                # run end on an uninformative expired deadline.
                if cpu in observed_cpus[site["name"]]:
                    repeats += 1
                    require(repeats <= MAX_PAIR_REPEATS,
                            "proof site never reached its remaining CPUs: " + site["name"])
                prefix = (output / "serial.log").read_bytes()
                mappings_before = parse_mapping_records(prefix.decode(errors="replace"))
                # Remove this site's breakpoint before stepping through its instruction.
                remote.ok(f"z1,{site['address']:x},1")
                after = step_cr3_instruction(remote, site, before, thread, step_attempts,
                                             output / "cr3-step-attempts.json")
                returned = None
                # Breakpoints are shared by all vCPUs. A pair already verified
                # still retires and checks its CR3 write, but needs no second
                # CPL3 epilogue trace while we wait for the remaining CPUs.
                if site["direction"] == "user" and cpu not in observed_cpus[site["name"]]:
                    for _ in range(128):
                        step = remote.step_thread(thread)
                        require(step.startswith(("T", "S")), "user return did not produce a step stop")
                        return_thread, returned = remote.registers(step, expected_thread=thread)
                        require(return_thread == thread, "user return changed CPU thread")
                        if returned["cpl"] == 3:
                            break
                    require(returned["cpl"] == 3 and returned["cs"] & 3 == 3 and
                            returned["cr3"] & PHYSICAL == after["cr3"] & PHYSICAL,
                            "entry/return path did not reach CPL3 with its user root")
                if cpu not in observed_cpus[site["name"]]:
                    transitions.append({**site, "thread": thread, "cpu": cpu, "before": before, "after": after,
                                        "user_return": returned, "mapping_records_before": mappings_before,
                                        "serial_prefix_bytes": len(prefix),
                                        "serial_prefix_sha256": hashlib.sha256(prefix).hexdigest()})
                    observed_cpus[site["name"]].add(cpu)
                write_json(output / "transitions.json", transitions)
                required = args.smp if site["stub"] in STUBS[:2] else 1
                if len(observed_cpus[site["name"]]) == required:
                    del remaining[site["address"]]
                else:
                    remote.ok(f"Z1,{site['address']:x},1")
            remote.ok("Hc-1")
            remote.send("c")
            while True:
                content = (output / "serial.log").read_text(errors="replace")
                if re.search(r"KERNEL PANIC|panicked at|MITIGATION-.*FAIL", content):
                    raise ProofFailure("guest reported a failed mitigation workload")
                if re.search(r"^Process 1 terminated with exit code \d+$", content, re.M):
                    verify_workload(content, args.smp)
                    break
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise EvidenceUnavailable("mitigation workload did not complete after tracing")
                time.sleep(0.02)
    finally:
        if connection is not None:
            connection.close()
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            (output / "qemu.status").write_text(str(process.returncode) + "\n")
        if remote is not None:
            write_json(output / "rsp-transcript.json", remote.transcript)
        write_json(output / "transitions.json", transitions)
        write_json(output / "cr3-step-attempts.json", step_attempts)
        if socket_path.exists():
            socket_path.unlink()
        socket_dir.rmdir()
    serial_bytes = (output / "serial.log").read_bytes()
    serial = serial_bytes.decode(errors="replace")
    require(not re.search(r"KERNEL PANIC|panicked at|MITIGATION-MAP FAIL", serial), "guest failure during proof")
    mappings = parse_mapping_records(serial)
    write_json(output / "mappings.json", mappings)
    bind_transitions(sites, transitions, mappings, args.smp)
    verify_workload(serial, args.smp)
    require(hashlib.sha256(serial_bytes[:relocation["serial_prefix_bytes"]]).hexdigest() ==
            relocation["serial_prefix_sha256"], "runtime relocation evidence changed after observation")
    for transition in transitions:
        prefix = serial_bytes[:transition["serial_prefix_bytes"]]
        require(hashlib.sha256(prefix).hexdigest() == transition["serial_prefix_sha256"],
                "constructor evidence prefix changed after observation")
    for key in ("kernel", "bootloader", "firmware", "qemu"):
        require(digest(Path(identity[key]["path"])) == identity[key]["sha256"], "guest/tool input changed")
    return {"sites_observed": len(transitions), "threads_observed": sorted({item["thread"] for item in transitions}),
            "mapping_records": len(mappings), "workload": "fork/exec/pinned-workers/PID1 complete",
            "execution_model": "four logical vCPUs; single-thread TCG; instruction-counted virtual time",
            "termination": "harness stop after tracing and workload completion"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-elf", required=True, type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path(".validation/mitigation"))
    parser.add_argument("--toolchain", default=TOOLCHAIN)
    parser.add_argument("--objdump", type=Path)
    parser.add_argument("--input-manifest", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--build-command-json", type=Path)
    parser.add_argument("--runtime", action="store_true")
    parser.add_argument("--esp", type=Path)
    parser.add_argument("--firmware", type=Path)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--timeout", type=int, default=900,
                        help="total boot, tracing and workload deadline in seconds (1..900)")
    parser.add_argument("--smp", type=int, choices=(4,), default=4)
    parser.add_argument("--cpu", default="qemu64,+smep,+smap,+umip,+rdrand")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 900 or (args.input_manifest and not args.revision):
        parser.error("timeout must be 1..900; input manifest requires revision")
    args.kernel_elf = args.kernel_elf.resolve()
    if args.esp:
        args.esp = args.esp.resolve()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=args.artifacts.resolve()))
    result = {"status": 2, "static": "not-run", "dynamic": "not-run",
              "full_isolation": False, "compiler_retpoline": "unsupported",
              "scope": "implemented dual-root paths; no speculative-side-channel or physical-hardware qualification"}
    write_json(output / "command.json", sys.argv)
    active_stage = "static"
    try:
        root = Path(__file__).resolve().parents[3]
        identity = source_identity(root, args.input_manifest, args.revision)
        identity["kernel_elf"] = {"path": str(args.kernel_elf), "sha256": digest(args.kernel_elf)}
        with args.kernel_elf.open("rb") as stream:
            header = stream.read(64)
        require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01" and
                int.from_bytes(header[18:20], "little") == 62,
                "proof requires a little-endian x86-64 ELF")
        captured_elf = output / "kernel.elf"
        shutil.copyfile(args.kernel_elf, captured_elf)
        require(digest(captured_elf) == identity["kernel_elf"]["sha256"], "ELF changed during capture")
        identity["build_command"] = (json.loads(args.build_command_json.read_text())
                                     if args.build_command_json else "not supplied; provenance incomplete")
        if not args.build_command_json:
            raise EvidenceUnavailable("--build-command-json is required for executed build provenance")
        verify_build_provenance(identity["build_command"], identity["kernel_elf"]["sha256"])
        identity["proof_script_sha256"] = digest(Path(__file__))
        write_json(output / "inputs.json", identity)
        rustc, objdump = tools_for(args, output)
        identity["tools"] = {str(path): digest(path) for path in (rustc, objdump)}
        write_json(output / "inputs.json", identity)
        command = [str(objdump), "--disassemble", "--demangle", "--x86-asm-syntax=intel", str(captured_elf)]
        write_json(output / "disassembly-command.json", command)
        disassembly = run_tool(command, output / "disassembly.txt")
        symbols = parse_disassembly(disassembly)
        scope = {}
        sites = verify_generated(symbols, scope)
        write_json(output / "generated-scope.json", scope)
        write_json(output / "sites.json", sites)
        write_json(output / "mutations.json", verify_mutations(symbols))
        result.update(static="pass", status=0)
        if args.runtime:
            active_stage = "dynamic"
            result["dynamic"] = "pending"
            command = [str(objdump), "--syms", str(captured_elf)]
            write_json(output / "symbols-command.json", command)
            linked = parse_anchor_symbols(run_tool(command, output / "elf-symbols.txt"))
            anchor_bytes = body_for(symbols, ANCHOR)[0].raw
            require(bool(anchor_bytes), "retained relocation anchor has no instruction bytes")
            result["runtime"] = runtime(args, output, sites, identity["kernel_elf"]["sha256"], linked, anchor_bytes)
            result["dynamic"] = "pass"
        else:
            result["limitation"] = "runtime mapping and actual CR3 transitions not run; use --runtime"
    except ProofFailure as error:
        result[active_stage] = "fail"
        result.update(status=1, error=str(error))
    except (EvidenceUnavailable, OSError, ValueError, subprocess.SubprocessError) as error:
        result[active_stage] = "blocked"
        result.update(status=2, error=str(error))
    finally:
        # Preserve mapping observations even when dynamic tracing was incomplete.
        if (output / "serial.log").exists() and not (output / "mappings.json").exists():
            try:
                write_json(output / "mappings.json", parse_mapping_records((output / "serial.log").read_text(errors="replace")))
            except (ProofFailure, EvidenceUnavailable) as error:
                result["mapping_observation_error"] = str(error)
        write_json(output / "result.json", result)
        (output / "gate.status").write_text(str(result["status"]) + "\n")
        write_json(output / "artifacts.sha256.json", {str(path.relative_to(output)): digest(path)
                   for path in sorted(output.rglob("*")) if path.is_file()})
        print(f"MITIGATION-PROOF status={result['status']} static={result['static']} dynamic={result['dynamic']} full_isolation=false retpoline=unsupported artifacts={output}")
        if "error" in result:
            print(result["error"])
    return result["status"]


if __name__ == "__main__":
    raise SystemExit(main())
