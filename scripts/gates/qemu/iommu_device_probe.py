#!/usr/bin/env python3
"""P3-2: run the terminal Zero-OS Q35/EDU DMA and MSI evidence profile."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

try:
    from gate_log import SERIAL_FATAL
except ModuleNotFoundError:  # direct execution from the repository root
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from scripts.ci.gate_log import SERIAL_FATAL
from iommu_failure_probe import digest, identity_errors

CASES = ("translated", "replacement", "msi", "readonly", "unmapped", "detach")
COMPLETE = "KSA-P3-DEVICE COMPLETE cases=6 scratch=retained physical=false"


def evaluate(serial, trace, stderr, qemu_status):
    errors = []
    if qemu_status != 33:
        errors.append(f"QEMU status {qemu_status}, expected terminal success 33")
    if SERIAL_FATAL.search(serial) or SERIAL_FATAL.search(stderr) or "KSA-P3-DEVICE FAIL" in serial:
        errors.append("fatal guest evidence")
    if serial.count("KSA-P3-DEVICE BEGIN version=1") != 1 or serial.count(COMPLETE) != 1:
        errors.append("missing/duplicate begin or completion")
    setups = re.findall(r"^KSA-P3-SETUP sid=0028 bar=(0x[0-9a-f]+) cap=(0x[0-9a-f]+) ecap=(0x[0-9a-f]+) gsts=(0x[0-9a-f]+)$", serial, re.M)
    if len(setups) != 1:
        errors.append("missing/duplicate endpoint and VT-d setup")
    else:
        bar, cap, ecap, gsts = (int(value, 16) for value in setups[0])
        if bar < 256 * 1024 * 1024 or bar & 0xfffff or bar + 0x100000 > 1 << 32 or cap & 0x400 == 0 or ecap & 10 != 10 or gsts & 0xc7000000 != 0xc7000000:
            errors.append("unexpected BAR/capability or unacknowledged VT-d setup")
    records = re.findall(r"^KSA-P3-DEVICE PASS case=(\w+).*", serial, re.M)
    if tuple(records) != CASES or (records and serial.rfind("KSA-P3-DEVICE PASS") > serial.find(COMPLETE)):
        errors.append("case coverage/order differs")
    if not 0 <= serial.find("KSA-P3-DEVICE BEGIN version=1") < serial.find("KSA-P3-DEVICE PASS") < serial.find(COMPLETE):
        errors.append("begin/cases/completion out of order")
    mapped = re.search(r"^KSA-P3-DEVICE PASS case=translated iova=(0x[0-9a-f]+) gpa=(0x[0-9a-f]+) source_iova=(0x[0-9a-f]+) source_gpa=(0x[0-9a-f]+) bytes=64 canary=unchanged$", serial, re.M)
    replaced = re.search(r"^KSA-P3-DEVICE PASS case=replacement iova=(0x[0-9a-f]+) old_gpa=(0x[0-9a-f]+) new_gpa=(0x[0-9a-f]+) old=unchanged$", serial, re.M)
    if not mapped or not replaced:
        errors.append("missing nonidentity DMA observations")
    else:
        iova, gpa, src, src_gpa = (int(x, 16) for x in mapped.groups())
        riova, old, new = (int(x, 16) for x in replaced.groups())
        if iova == gpa or src == src_gpa or (riova, old) != (iova, gpa) or new in (old, iova):
            errors.append("identity/bad replacement mapping")
        for addr, physical in ((iova, gpa), (iova, new), (src, src_gpa)):
            needle = f"vtd_dmar_translate dev 00:05.00 iova {addr:#x} -> gpa {physical:#x} "
            if needle not in trace:
                errors.append(f"missing actual translation {addr:#x}->{physical:#x}")
        for reason, write in ((5, 1), (6, 0), (2, 1)):
            if f"vtd_dmar_fault sid 0x28 fault {reason} addr {iova:#x} write {write}" not in trace:
                errors.append(f"missing device fault {reason}")
    faults = re.findall(r"^KSA-P3-FAULT sid=0028 iova=(0x[0-9a-f]+) reason=(\d+) write=(true|false) lo=(0x[0-9a-f]+) hi=(0x[0-9a-f]+)$", serial, re.M)
    if [(int(f[1]), f[2]) for f in faults] != [(5, "true"), (6, "false"), (2, "true")]:
        errors.append("fault coverage/order differs")
    for addr, reason, write, lo, hi in faults:
        lo, hi = int(lo, 16), int(hi, 16)
        if not hi & (1 << 63) or hi & 0xffff != 0x28 or (hi >> 32) & 255 != int(reason) or (hi & (1 << 62) == 0) != (write == "true") or lo & ~4095 != int(addr, 16):
            errors.append("raw FRCD and decoded observation disagree")
        if mapped and int(addr, 16) != int(mapped[1], 16):
            errors.append("fault address differs from tested IOVA")
    for needle in ("vtd_inv_desc_cc_device", "vtd_inv_desc_iotlb_domain", "vtd_inv_desc_wait_sw", "vtd_inv_desc_iec", "vtd_reg_ir_root", "vtd_ir_remap_msi_req", "vector 49 deliver 0 dest 0x0 mode 0"):
        if needle not in trace:
            errors.append("missing " + needle)
    if sum("vtd_ir_remap index " in line and "vector 49 deliver 0 dest 0x0 mode 0" in line for line in trace.splitlines()) != 2:
        errors.append("expected two independently traced remapped MSI deliveries")
    if not re.search(r"^KSA-P3-DEVICE PASS case=msi delivered=2 wrong_sid=denied retired=denied reused=true index=\d+ lo=0x[0-9a-f]+ hi=0x[0-9a-f]+$", serial, re.M):
        errors.append("missing MSI positive/negative/reuse evidence")
    for needle in ("invalid IRTE SID", "non-present IRTE"):
        if needle not in stderr:
            errors.append("missing emulator MSI rejection: " + needle)
    for case, detail in (("readonly", "canary=unchanged context=quarantined bme=off"), ("unmapped", "canary=unchanged context=quarantined bme=off"), ("detach", "reenabled=probe_only canary=unchanged context=absent bme=off")):
        if f"KSA-P3-DEVICE PASS case={case} {detail}" not in serial:
            errors.append("missing containment detail for " + case)
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--smp", type=int, choices=(1, 4), default=1)
    parser.add_argument("--timeout", type=int, choices=range(1, 901), default=900, metavar="1..900",
                        help="maximum seconds for the QEMU evidence run")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    manifest = args.input_manifest.resolve()
    manifest_bytes = manifest.read_bytes()
    expected = dict((name, sha) for sha, name in (line.split("  ", 1) for line in manifest_bytes.decode().splitlines()))
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    qemu = shutil.which("qemu-system-x86_64")
    firmware = next((Path(p) for p in (os.environ.get("OVMF_PATH", ""), "/usr/share/qemu/OVMF.fd", "/usr/share/ovmf/OVMF.fd", "/usr/share/OVMF/OVMF_CODE.fd") if p and Path(p).is_file()), None)
    if not qemu or not firmware:
        parser.error("QEMU and OVMF are required")
    tools = {name: {"path": str(path), "sha256": digest(Path(path))} for name, path in (("qemu", qemu), ("firmware", firmware), ("python", Path(os.sys.executable)))}
    args.artifacts.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="edu-", dir=args.artifacts.resolve()))
    print(f"ARTIFACTS {run}", flush=True)
    (run / "inputs.sha256").write_bytes(manifest_bytes)
    result = {"status": 2, "revision": args.revision, "input_manifest_sha256": manifest_hash, "tools": tools, "smp": args.smp, "physical": False, "commands": []}

    def check_identity():
        errors = identity_errors(root, expected, manifest, manifest_hash, tools)
        if errors:
            result["identity_errors"] = errors
            raise RuntimeError("validation inputs changed")

    def execute(name, command, cwd=root, env=None, timeout=600):
        result["commands"].append({"name": name, "argv": command, "cwd": str(cwd), "env": env or {}})
        (run / (name + ".command.json")).write_text(json.dumps(result["commands"][-1], indent=2) + "\n")
        with (run / (name + ".log")).open("wb") as log:
            status = subprocess.run(command, cwd=cwd, env={**os.environ, **(env or {})}, stdout=log, stderr=subprocess.STDOUT, timeout=timeout).returncode
        (run / (name + ".status")).write_text(str(status) + "\n")
        check_identity()
        return status

    try:
        check_identity()
        execute("qemu-version", [qemu, "--version"])
        execute("rustc-version", ["rustc", "+nightly-2025-12-08", "-vV"])
        out = root / "kernel-target/iommu-device-probe"
        flags = f"-C link-arg=-T{root}/kernel/kernel.ld -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-pie -C relocation-model=pie -C code-model=kernel -C panic=abort"
        env = {"CARGO_TARGET_DIR": str(out), "RUSTFLAGS": flags, "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags.split())}
        build = ["cargo", "+nightly-2025-12-08", "build", "--release", "--target", "x86_64-unknown-none", "-Z", "build-std=core,alloc,compiler_builtins", "--features", "iommu_device_probe", "--locked"]
        if execute("build", build, root / "kernel", env) != 0:
            raise RuntimeError("kernel build failed; guest not run")
        boot = root / "bootloader-target"
        if execute("bootloader-build", ["cargo", "+nightly-2025-12-08", "build", "--release", "--target", "x86_64-unknown-uefi", "--locked"], root / "bootloader", {"CARGO_TARGET_DIR": str(boot), "RUSTFLAGS": "", "CARGO_ENCODED_RUSTFLAGS": ""}) != 0:
            raise RuntimeError("bootloader build failed; guest not run")
        esp = run / "esp"
        (esp / "EFI/BOOT").mkdir(parents=True)
        shutil.copyfile(out / "x86_64-unknown-none/release/kernel", esp / "kernel.elf")
        shutil.copyfile(boot / "x86_64-unknown-uefi/release/bootloader.efi", esp / "EFI/BOOT/BOOTX64.EFI")
        images = {str(p): digest(p) for p in (esp / "kernel.elf", esp / "EFI/BOOT/BOOTX64.EFI")}
        result["images"] = images
        serial, trace, stderr = (run / x for x in ("serial.log", "vtd.trace", "qemu.stderr"))
        cmd = [qemu, "-bios", str(firmware), "-machine", "q35", "-accel", "tcg,thread=single", "-smp", str(args.smp), "-m", "256M", "-cpu", "qemu64,+smep,+smap,+umip,+rdrand", "-device", "intel-iommu,intremap=on,aw-bits=48,caching-mode=on", "-device", "edu,addr=05.0,dma_mask=4294967295", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-drive", f"format=raw,file=fat:{esp},snapshot=on", "-display", "none", "-vga", "std", "-nic", "none", "-no-reboot", "-no-shutdown", "-serial", f"file:{serial}", "-trace", f"enable=vtd_*,file={trace}"]
        (run / "qemu.command.json").write_text(json.dumps(cmd, indent=2) + "\n")
        try:
            with stderr.open("wb") as log:
                qstatus = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=log, timeout=args.timeout).returncode
        except subprocess.TimeoutExpired:
            qstatus = "timeout"
        (run / "qemu.status").write_text(str(qstatus) + "\n")
        errors = evaluate(*(p.read_text(errors="replace") if p.exists() else "" for p in (serial, trace, stderr)), qstatus)
        errors += ["guest image changed: " + p for p, sha in images.items() if digest(Path(p)) != sha]
        result.update({"status": 1 if errors else 0, "errors": errors, "qemu_status": qstatus})
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        result["exception"] = str(error)
    finally:
        errors = identity_errors(root, expected, manifest, manifest_hash, tools)
        result["final_identity_errors"] = errors
        if errors:
            result["status"] = 1
        (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        hashes = {str(p.relative_to(run)): digest(p) for p in run.rglob("*") if p.is_file()}
        (run / "artifacts.sha256.json").write_text(json.dumps(hashes, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "errors": result.get("errors"), "exception": result.get("exception"), "artifacts": str(run)}), flush=True)
    return result["status"]


if __name__ == "__main__":
    raise SystemExit(main())
