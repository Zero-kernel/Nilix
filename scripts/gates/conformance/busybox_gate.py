#!/usr/bin/env python3
"""Nilix #66 BusyBox boot gate.

Exercises an unmodified static musl BusyBox binary on Nilix across two boots:
  Boot 1:
    1. Scripted ash workload on /mnt/test: pipelines, redirection, background
       jobs (& + wait), FIFO pipe, and file operations (mkdir/cp/mv/chmod/stat/
       rm/sync).
    2. Interactive ash job control over the live serial console:
       start foreground job -> ^Z (SIGTSTP) -> bg -> fg -> ^C (SIGINT) ->
       write persistence token on /mnt/test -> sync -> exit 0.
  Between boots:
    - Host verifies journal is quiescent and runs `e2fsck -fn` on a scratch copy
      (via stress_protocol.strip_private_journal_bits).
  Boot 2 (reboot persistence):
    - Boots the SAME Ext3 disk image, verifies persisted files and contents on
      /mnt/test via BusyBox ash, and exits 0.
    - Host runs `e2fsck -fn` a second time.

On success, prints `BUSYBOX-GATE OK` exactly once and exits 0.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.gates.stress import stress_protocol

CPU_MODEL = "qemu64,+smep,+smap,+umip,+rdrand,+rdtscp"
PROMPT = "BB-PROMPT> "

PID1_EXIT_RE = re.compile(
    r"Process 1 (?:exited with code|terminated with exit code) (-?[0-9]+)\s*$",
    re.MULTILINE,
)
FATAL_RE = re.compile(
    r"\bKERNEL PANIC\b|\bpanicked at\b|\bPANIC:|\btriple fault\b|^BB-ERROR ",
    re.MULTILINE,
)

GATE_SCRIPT_SH = """#!/mnt/test/bin/busybox sh
set -eu

# 1. Pipelines and redirection
printf 'cherry\\napple\\nbanana\\napple\\n' > /tmp/items.txt
grep -v banana /tmp/items.txt | sort | uniq > /tmp/sorted.txt
cnt="$(wc -l < /tmp/sorted.txt | tr -d ' ')"
test "$cnt" = "2"

# 2. Background job + wait
(sleep 1; echo "bg-worker-ok" > /mnt/test/bg.out) &
bg_pid=$!
wait "$bg_pid"
test "$(cat /mnt/test/bg.out)" = "bg-worker-ok"

# 3. File operations on /mnt/test (Ext3) + metadata on /tmp (RamFs)
mkdir /mnt/test/work
mkdir /mnt/test/work/sub
echo "alpha" > /mnt/test/work/orig.txt
echo "beta" >> /mnt/test/work/orig.txt
cp /mnt/test/work/orig.txt /mnt/test/work/sub/moved.txt
test "$(wc -l < /mnt/test/work/sub/moved.txt | tr -d ' ')" = "2"
rm -f /mnt/test/work/orig.txt
echo "ramfs-meta" > /tmp/meta.txt
chmod 0640 /tmp/meta.txt
mv /tmp/meta.txt /tmp/meta_moved.txt
test "$(cat /tmp/meta_moved.txt)" = "ramfs-meta"

# 4. Named FIFO on /tmp (RamFs)
mkfifo /tmp/bb.fifo
(echo "fifo-payload" > /tmp/bb.fifo) &
fifo_val="$(cat /tmp/bb.fifo)"
wait
test "$fifo_val" = "fifo-payload"

sync
echo "BB-SCRIPT-STEPS-OK"
"""

VERIFY_PERSIST_SH = """#!/mnt/test/bin/busybox sh
set -eu
test -f /mnt/test/persist.txt
test "$(cat /mnt/test/persist.txt)" = "NILIX-PERSIST-TOKEN-66"
test -f /mnt/test/work/sub/moved.txt
test "$(wc -l < /mnt/test/work/sub/moved.txt | tr -d ' ')" = "2"
test "$(cat /mnt/test/bg.out)" = "bg-worker-ok"
echo "BB-PERSIST-OK"
"""


@dataclass(frozen=True)
class BusyBoxEval:
    ok: bool
    errors: tuple[str, ...]


def evaluate_busybox_logs(boot1_log: str, boot2_log: str) -> BusyBoxEval:
    """Pure verifier for Boot 1 (scripted + interactive job control) and Boot 2 (persistence)."""
    errors: list[str] = []

    for label, text in (("boot1", boot1_log), ("boot2", boot2_log)):
        if FATAL_RE.search(text):
            errors.append(f"{label}: fatal kernel panic or BB-ERROR observed")
        exits = [int(m.group(1)) for m in PID1_EXIT_RE.finditer(text)]
        if exits != [0]:
            errors.append(f"{label}: expected single PID 1 exit 0, observed {exits}")

    required_boot1 = (
        ("BB-SCRIPT-STEPS-OK", "scripted pipeline/redirection/bg/file-ops phase did not complete"),
        ("BB-SCRIPTED OK", "init did not report BB-SCRIPTED OK"),
        ("BB-INTERACTIVE-READY", "interactive ash phase did not start"),
        ("Stopped", "interactive ^Z did not stop foreground job"),
        ("BB-BG-OK", "interactive bg command did not return to shell"),
        ("BB-FG-CTRLC-OK", "interactive fg + ^C did not return to live shell"),
        ("BB-INTERACTIVE-OK", "interactive shell did not finish cleanly"),
    )
    for marker, reason in required_boot1:
        if marker not in boot1_log:
            errors.append(f"boot1: {reason} (missing {marker!r})")

    required_boot2 = (
        ("BB-PERSIST-OK", "persisted /mnt/test files missing or corrupted after reboot"),
        ("BB-BOOT2-DONE", "boot2 init did not finish cleanly"),
    )
    for marker, reason in required_boot2:
        if marker not in boot2_log:
            errors.append(f"boot2: {reason} (missing {marker!r})")

    return BusyBoxEval(ok=not errors, errors=tuple(errors))


def find_ovmf(override: str | None) -> Path:
    candidates = [
        override or "",
        os.environ.get("OVMF_PATH", ""),
        "/usr/share/qemu/OVMF.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ]
    for item in candidates:
        if item and Path(item).is_file():
            return Path(item)
    raise RuntimeError("OVMF firmware not found (set OVMF_PATH or --ovmf)")


def build_disk_image(busybox_bin: Path, disk_path: Path, size_mb: int = 64) -> None:
    for tool in ("mkfs.ext3", "debugfs", "dd", "e2fsck"):
        if not shutil.which(tool):
            raise RuntimeError(f"{tool} not found in PATH")
    if not busybox_bin.is_file():
        raise RuntimeError(f"missing static busybox binary: {busybox_bin}")

    disk_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bb-img-", dir=disk_path.parent) as td:
        td_path = Path(td)
        gate_script = td_path / "gate_script.sh"
        persist_script = td_path / "verify_persist.sh"
        gate_script.write_text(GATE_SCRIPT_SH, encoding="utf-8")
        persist_script.write_text(VERIFY_PERSIST_SH, encoding="utf-8")
        os.chmod(gate_script, 0o755)
        os.chmod(persist_script, 0o755)

        tmp_img = td_path / "busybox.img"
        subprocess.run(
            ["dd", "if=/dev/zero", f"of={tmp_img}", "bs=1M", f"count={size_mb}", "status=none"],
            check=True,
        )
        subprocess.run(
            ["mkfs.ext3", "-q", "-F", "-b", "4096", "-I", "256", "-J", "size=4", "-L", "nilix-bb", str(tmp_img)],
            check=True,
        )
        cmd_file = td_path / "debugfs.cmds"
        cmd_file.write_text(
            "\n".join(
                [
                    "mkdir /test",
                    "mkdir /test/bin",
                    f"write {busybox_bin} /test/bin/busybox",
                    "set_inode_field /test/bin/busybox mode 0100755",
                    f"write {gate_script} /test/gate_script.sh",
                    "set_inode_field /test/gate_script.sh mode 0100755",
                    f"write {persist_script} /test/verify_persist.sh",
                    "set_inode_field /test/verify_persist.sh mode 0100755",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        subprocess.run(["debugfs", "-w", "-f", str(cmd_file), str(tmp_img)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.move(str(tmp_img), str(disk_path))


def verify_ext3_clean(disk_path: Path, scratch_dir: Path, label: str) -> None:
    """Confirm quiescent journal and clean host e2fsck -fn on a scratch copy."""
    probe = stress_protocol.probe_journal(disk_path)
    if probe["journal_start"] != 0:
        raise RuntimeError(f"{label}: journal is not quiescent (journal_start={probe['journal_start']})")
    copy = scratch_dir / f"{label}-fsck.img"
    shutil.copyfile(disk_path, copy)
    try:
        stress_protocol.strip_private_journal_bits(copy)
        res = subprocess.run(
            ["e2fsck", "-fn", str(copy)],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            raise RuntimeError(f"{label}: e2fsck -fn failed (rc={res.returncode}):\n{res.stdout}\n{res.stderr}")
    finally:
        copy.unlink(missing_ok=True)


class SerialSession:
    """Bidirectional QEMU COM1 serial session over stdin/stdout pipes."""

    def __init__(self, proc: subprocess.Popen[bytes], log_path: Path) -> None:
        self.proc = proc
        self.log_path = log_path
        self.buf = ""
        assert proc.stdout is not None and proc.stdin is not None
        self.fd_out = proc.stdout.fileno()
        self.stdin = proc.stdin
        os.set_blocking(self.fd_out, False)

    def _pump(self, timeout: float) -> None:
        rlist, _, _ = select.select([self.fd_out], [], [], max(0.0, timeout))
        if not rlist:
            return
        try:
            chunk = os.read(self.fd_out, 8192)
        except BlockingIOError:
            return
        if not chunk:
            return
        text = chunk.decode("utf-8", errors="replace")
        self.buf += text
        with self.log_path.open("a", encoding="utf-8") as fp:
            fp.write(text)

    def wait_for(self, needle: str, timeout: float, start_pos: int = 0) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            idx = self.buf.find(needle, start_pos)
            if idx >= 0:
                return idx + len(needle)
            if FATAL_RE.search(self.buf):
                raise RuntimeError(f"fatal marker observed while waiting for {needle!r}")
            if self.proc.poll() is not None:
                self._pump(0.05)
                idx = self.buf.find(needle, start_pos)
                if idx >= 0:
                    return idx + len(needle)
                raise RuntimeError(f"QEMU exited early while waiting for {needle!r}")
            self._pump(min(0.1, deadline - time.monotonic()))
        raise RuntimeError(f"timed out after {timeout:.1f}s waiting for {needle!r}")

    def wait_for_regex(self, pattern: re.Pattern[str], timeout: float, start_pos: int = 0) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            m = pattern.search(self.buf, start_pos)
            if m:
                return m.end()
            if FATAL_RE.search(self.buf):
                raise RuntimeError(f"fatal marker observed while waiting for {pattern.pattern!r}")
            if self.proc.poll() is not None:
                self._pump(0.05)
                m = pattern.search(self.buf, start_pos)
                if m:
                    return m.end()
                raise RuntimeError(f"QEMU exited early while waiting for {pattern.pattern!r}")
            self._pump(min(0.1, deadline - time.monotonic()))
        raise RuntimeError(f"timed out after {timeout:.1f}s waiting for {pattern.pattern!r}")

    def send(self, payload: bytes) -> None:
        self.stdin.write(payload)
        self.stdin.flush()

    def drain(self, duration: float) -> None:
        end = time.monotonic() + duration
        while time.monotonic() < end:
            self._pump(min(0.05, end - time.monotonic()))


def qemu_cmd(esp: Path, disk: Path, ovmf: Path, cpus: int) -> list[str]:
    qemu = shutil.which("qemu-system-x86_64")
    if not qemu:
        raise RuntimeError("qemu-system-x86_64 not found in PATH")
    return [
        qemu,
        "-bios",
        str(ovmf),
        "-drive",
        f"format=raw,file=fat:{esp},snapshot=on",
        "-drive",
        f"if=none,file={disk},format=raw,id=vdisk0,cache=writeback",
        "-device",
        "virtio-blk-pci,drive=vdisk0,logical_block_size=512,physical_block_size=512",
        "-m",
        "512M",
        "-smp",
        str(cpus),
        "-vga",
        "std",
        "-no-reboot",
        "-no-shutdown",
        "-cpu",
        CPU_MODEL,
        "-netdev",
        "user,id=net0,restrict=on,ipv6=off",
        "-device",
        "virtio-net-pci,netdev=net0,romfile=",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
    ]


def stop_qemu(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def run_boot1(esp: Path, disk: Path, ovmf: Path, cpus: int, timeout: int, run_dir: Path) -> str:
    log_path = run_dir / "boot1.serial.log"
    err_path = run_dir / "boot1.qemu.stderr"
    log_path.write_text("", encoding="utf-8")
    with err_path.open("wb") as errf:
        proc = subprocess.Popen(
            qemu_cmd(esp, disk, ovmf, cpus),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errf,
        )
        try:
            sess = SerialSession(proc, log_path)
            pos = sess.wait_for("BB-INTERACTIVE-READY", timeout)
            pos = sess.wait_for(PROMPT, 30, start_pos=pos)

            # 1. Start a foreground job and suspend it with real Ctrl-Z (0x1A).
            sess.send(b"sleep 30\n")
            sess.drain(0.6)
            sess.send(b"\x1a")
            pos = sess.wait_for("Stopped", 15, start_pos=pos)
            pos = sess.wait_for(PROMPT, 15, start_pos=pos)

            # 2. Resume the stopped job in the background with `bg`.
            sess.send(b"bg && echo BB-BG-OK\n")
            pos = sess.wait_for("BB-BG-OK", 15, start_pos=pos)
            pos = sess.wait_for(PROMPT, 15, start_pos=pos)

            # 3. Bring it back to the foreground with `fg` and interrupt with Ctrl-C (0x03).
            sess.send(b"fg\n")
            sess.drain(0.5)
            sess.send(b"\x03")
            pos = sess.wait_for(PROMPT, 15, start_pos=pos)

            # 4. Confirm the shell survived ^C, write persistence token + boot2 flag, sync, exit 0.
            sess.send(
                b"echo BB-FG-CTRLC-OK && "
                b"echo NILIX-PERSIST-TOKEN-66 > /mnt/test/persist.txt && "
                b"touch /mnt/test/boot2.flag && "
                b"sync && "
                b"echo BB-INTERACTIVE-OK && "
                b"exit 0\n"
            )
            pos = sess.wait_for("BB-INTERACTIVE-OK", 20, start_pos=pos)
            sess.wait_for_regex(PID1_EXIT_RE, 20, start_pos=pos)
            sess.drain(0.3)
            return sess.buf
        finally:
            stop_qemu(proc)


def run_boot2(esp: Path, disk: Path, ovmf: Path, cpus: int, timeout: int, run_dir: Path) -> str:
    log_path = run_dir / "boot2.serial.log"
    err_path = run_dir / "boot2.qemu.stderr"
    log_path.write_text("", encoding="utf-8")
    with err_path.open("wb") as errf:
        proc = subprocess.Popen(
            qemu_cmd(esp, disk, ovmf, cpus),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errf,
        )
        try:
            sess = SerialSession(proc, log_path)
            pos = sess.wait_for("BB-BOOT2-DONE", timeout)
            sess.wait_for_regex(PID1_EXIT_RE, 20, start_pos=pos)
            sess.drain(0.3)
            return sess.buf
        finally:
            stop_qemu(proc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--esp", type=Path, default=ROOT / "esp-busybox")
    parser.add_argument(
        "--busybox",
        type=Path,
        default=ROOT / "target/conformance/build/busybox/busybox",
    )
    parser.add_argument("--ovmf", default=None)
    parser.add_argument("--cpus", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--artifacts", type=Path, default=ROOT / "target/conformance/artifacts")
    args = parser.parse_args()

    try:
        ovmf = find_ovmf(args.ovmf)
        if not (args.esp / "kernel.elf").is_file():
            raise RuntimeError(f"missing BusyBox gate kernel image: {args.esp / 'kernel.elf'}")
        if not args.busybox.is_file():
            raise RuntimeError(f"missing static BusyBox binary: {args.busybox}")
    except RuntimeError as err:
        print(f"BUSYBOX-GATE BLOCKED: {err}", file=sys.stderr)
        return 2

    args.artifacts.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="busybox-", dir=args.artifacts))
    disk_path = run_dir / "busybox-ext3.img"

    boot1_log = ""
    boot2_log = ""
    fsck_errors: list[str] = []
    try:
        build_disk_image(args.busybox.resolve(), disk_path)
        boot1_log = run_boot1(args.esp.resolve(), disk_path, ovmf, args.cpus, args.timeout, run_dir)
        verify_ext3_clean(disk_path, run_dir, "boot1")
        boot2_log = run_boot2(args.esp.resolve(), disk_path, ovmf, args.cpus, args.timeout, run_dir)
        verify_ext3_clean(disk_path, run_dir, "boot2")
    except Exception as exc:  # noqa: BLE001 - preserve full diagnostics in artifact report
        fsck_errors.append(str(exc))
    finally:
        disk_path.unlink(missing_ok=True)

    ev = evaluate_busybox_logs(boot1_log, boot2_log)
    all_errors = list(ev.errors) + fsck_errors
    report = {
        "ok": not all_errors,
        "errors": all_errors,
        "artifacts": str(run_dir),
    }
    (run_dir / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if not all_errors:
        print("BUSYBOX-GATE OK")
        return 0

    for err in all_errors:
        print(f"BUSYBOX-GATE ERROR: {err}", file=sys.stderr)
    print(f"BUSYBOX-GATE FAIL artifacts={run_dir}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
