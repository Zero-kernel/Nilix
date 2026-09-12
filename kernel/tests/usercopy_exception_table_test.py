"""Assemble production usercopy, verify linked RIPs, and optionally fault it on Linux."""

import argparse
import hashlib
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tempfile


TOOLCHAIN = "nightly-2025-12-08"
EXPECTED = {
    "get_u8": bytes.fromhex("8a06"),
    "get_u32": bytes.fromhex("8b06"),
    "get_u64": bytes.fromhex("488b06"),
    "put_u8": bytes.fromhex("408837"),
    "cmpxchg_u32": bytes.fromhex("f00fb117"),
}


def run(command):
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{command!r}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def elf_sections(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise AssertionError("expected little-endian ELF64")
    offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size, count, names_index = struct.unpack_from("<HHH", data, 58)
    entries = [struct.unpack_from("<IIQQQQIIQQ", data, offset + index * entry_size)
               for index in range(count)]
    names_entry = entries[names_index]
    names = data[names_entry[4]:names_entry[4] + names_entry[5]]
    return {
        names[entry[0]:].split(b"\0", 1)[0].decode():
        (entry[3], data[entry[4]:entry[4] + entry[5]])
        for entry in entries
    }


def verify_table(path, objdump):
    sections = elf_sections(path)
    text_base, text = sections[".text"]
    if ".ex_table" in sections:
        table_base, table = sections[".ex_table"]
    else:
        symbols = run([str(objdump), "--syms", str(path)])
        table_base = int(re.search(r"^([0-9a-f]+).*\b__ex_table_start$", symbols, re.M).group(1), 16)
        table_end = int(re.search(r"^([0-9a-f]+).*\b__ex_table_end$", symbols, re.M).group(1), 16)
        rodata_base, rodata = sections[".rodata"]
        assert rodata_base <= table_base <= table_end <= rodata_base + len(rodata)
        table = rodata[table_base - rodata_base:table_end - rodata_base]
    assert len(table) == 8 * len(EXPECTED), "unexpected entry count"
    disassembly = run([str(objdump), "--disassemble", "--no-show-raw-insn", str(path)])
    instructions = {int(match.group(1), 16): match.group(2).strip()
                    for match in re.finditer(r"^\s*([0-9a-f]+):\s+(.*)$", disassembly, re.M)}
    for index, (name, opcode) in enumerate(EXPECTED.items()):
        fault_rel, fixup_rel = struct.unpack_from("<ii", table, index * 8)
        fault = table_base + index * 8 + fault_rel
        fixup = table_base + index * 8 + 4 + fixup_rel
        assert fault in instructions, f"{name}: fault RIP not an instruction boundary"
        assert fixup in instructions, f"{name}: fixup RIP not an instruction boundary"
        actual = text[fault - text_base:fault - text_base + len(opcode)]
        assert actual == opcode, f"{name}: table points to {actual.hex()}, expected {opcode.hex()}"
        print(f"{name}: table RIP == disassembled memory instruction ({instructions[fault]})")


def build_elf(assembly, directory, rustc, linker, name):
    source = directory / f"{name}.rs"
    obj = directory / f"{name}.o"
    elf = directory / f"{name}.elf"
    source.write_text('#![no_std]\ncore::arch::global_asm!(r#"' + assembly + '"#);\n', encoding="utf8")
    run([str(rustc), "--edition=2021", "--crate-type=lib", "--emit=obj",
         "--target=x86_64-unknown-none", str(source), "-o", str(obj)])
    linker_script = Path(__file__).resolve().parents[1] / "kernel.ld"
    run([str(linker), "-flavor", "gnu", "-m", "elf_x86_64", "-T", str(linker_script),
         "-e", "__zero_os_usercopy_get_u8", str(obj), "-o", str(elf)])
    return elf


def main():
    if not __debug__:
        raise RuntimeError("verification requires Python assertions; disable optimization")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", action="store_true", help="require Linux x86_64 hosted fault probe")
    parser.add_argument("--kernel-elf", type=Path, help="also verify a final linked kernel ELF")
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    usercopy = root / "kernel/kernel_core/usercopy.rs"
    source = usercopy.read_text(encoding="utf8")
    match = re.search(r'core::arch::global_asm!\(\s*r#"(.*?)"#\s*\);', source, re.S)
    assert match, "production assembly not found"
    assembly = match.group(1)
    rustc = Path(run(["rustup", "which", "--toolchain", TOOLCHAIN, "rustc"]).strip())
    host = re.search(r"^host: (.+)$", run([str(rustc), "-vV"]), re.M).group(1)
    suffix = ".exe" if platform.system() == "Windows" else ""
    tools = rustc.parent.parent / "lib/rustlib" / host / "bin"
    linker, objdump = tools / f"rust-lld{suffix}", tools / f"llvm-objdump{suffix}"
    if options.kernel_elf:
        verify_table(options.kernel_elf, objdump)
        print(f"Kernel ELF SHA256={hashlib.sha256(options.kernel_elf.read_bytes()).hexdigest()}")
    with tempfile.TemporaryDirectory(prefix="ksa002-") as temporary:
        directory = Path(temporary)
        verify_table(build_elf(assembly, directory, rustc, linker, "usercopy"), objdump)
        old = assembly.replace("    mov eax, esi\n.Lcmpxchg_u32_access:",
                               ".Lcmpxchg_u32_access:\n    mov eax, esi")
        assert old != assembly, "mutation did not recreate the original defect"
        try:
            verify_table(build_elf(old, directory, rustc, linker, "old_usercopy"), objdump)
        except AssertionError as error:
            assert "cmpxchg_u32: table points to" in str(error), str(error)
            print("KSA-002: original misplaced-label mutation rejected")
        else:
            raise AssertionError("original misplaced label unexpectedly passed")
        if options.runtime:
            assert platform.system() == "Linux" and platform.machine() == "x86_64"
            compiler = shutil.which("cc")
            assert compiler, "runtime check requires a C compiler"
            assembler = directory / "usercopy.S"
            assembler.write_text(
                '.intel_syntax noprefix\n.pushsection .ex_table,"a"\n.balign 8\n'
                '.global __ksa_ex_start\n__ksa_ex_start:\n.popsection\n' + assembly +
                '\n.pushsection .ex_table,"a"\n.global __ksa_ex_end\n__ksa_ex_end:\n.popsection\n'
                '.section .note.GNU-stack,"",@progbits\n', encoding="utf8")
            binary = directory / "usercopy_fault_probe"
            run([compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIE", "-pie",
                 str(assembler), str(root / "kernel/tests/usercopy_fault_probe.c"), "-o", str(binary)])
            output = run([str(binary)])
            assert "3 exact-RIP fault recoveries passed" in output
            print(output.strip())
        else:
            print("Kernel/hosted runtime fault probe: NOT RUN (use --runtime on Linux)")
    print(f"KSA-002 assembly verification passed; usercopy SHA256={hashlib.sha256(usercopy.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
