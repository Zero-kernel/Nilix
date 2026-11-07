#!/usr/bin/env python3
"""Own a functional QEMU run until its exit-cleanup witness, then retain evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


EXIT = re.compile(r"Process 1 (?:exited with code|terminated with exit code) (-?\d+)\s*$")
CLEANUP = re.compile(r"CI-EXIT pid=1 code=(-?\d+) stage=teardown-complete\s*$")
SUMMARY = re.compile(r"=== Test Summary: \d+ passed, \d+ deferred(?: \([^()\r\n]*\))?, \d+ failed ===")
TERMINAL_FATAL = re.compile(r"\bKERNEL PANIC\b|\bpanicked at\b|\bPANIC:|\btriple fault\b", re.IGNORECASE)
SETTLE_SECONDS = 2.0
STOP_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 3600


def completion(serial: str, profile: str, *, final: bool = False) -> tuple[bool, str | None]:
    """A terminal witness triggers collection; final gate assertions decide PASS."""
    # Do not recognize a record until its newline has arrived.
    cut = serial.rfind("\n") + 1
    if final and any(marker in serial[cut:] for marker in ("CI-EXIT", "Process 1 ")):
        return False, "unterminated completion record"
    lines = serial[:cut].splitlines()
    witnesses = [(n, CLEANUP.search(line)) for n, line in enumerate(lines) if "CI-EXIT" in line]
    if not witnesses:
        return False, None
    if len(witnesses) != 1 or witnesses[0][1] is None or sum(line.count("CI-EXIT") for line in lines) != 1:
        return False, "malformed or duplicate exit-cleanup witness"
    position, witness = witnesses[0]
    exits = [(n, EXIT.search(line)) for n, line in enumerate(lines) if EXIT.search(line)]
    if not exits or any(n >= position or match[1] != witness[1] for n, match in exits):
        return False, "exit-cleanup witness lacks ordered, consistent PID 1 exit evidence"
    # sys_exit can print both phrasings, whereas musl exit_group prints only
    # 'terminated'. Reject duplicate copies of either semantic record.
    for phrase in ("exited with code", "terminated with exit code"):
        if sum(phrase in lines[n] for n, _ in exits) > 1:
            return False, "duplicate PID 1 exit record"
    summaries = [n for n, line in enumerate(lines) if "Test Summary" in line]
    if len(summaries) != 1 or summaries[0] >= min(n for n, _ in exits) or not SUMMARY.fullmatch(lines[summaries[0]]):
        return False, "exit cleanup lacks one complete, ordered runtime summary"
    if int(witness[1]) == 0:
        if profile == "musl" and "musl libc test passed!" not in lines[:position]:
            return False, "musl final result is missing before exit cleanup"
        if profile == "ring3" and not any(re.fullmatch(r"\s*Results: \d+ passed, \d+ failed", line) for line in lines[:position]):
            return False, "Ring-3 final result is missing before exit cleanup"
    return True, None


def termination_errors(serial: str, mode: str, receipt: dict | None, status: int) -> list[str]:
    if mode != "completion":
        return ["unknown QEMU completion mode"]
    if not isinstance(receipt, dict):
        return ["missing QEMU termination receipt"]
    errors = []
    if (receipt.get("schema") != 1 or receipt.get("mode") != mode
            or receipt.get("reason") != "completed" or status != 0
            or receipt.get("runner_status") != status or receipt.get("qemu_returncode") != 0
            or receipt.get("stop_method") != "qmp-quit" or receipt.get("forced_kill") is not False
            or receipt.get("signal") is not None or receipt.get("error") is not None):
        errors.append("QEMU did not complete the controlled exit protocol")
    profile = receipt.get("profile")
    if profile not in ("runtime", "musl", "ring3"):
        errors.append("unknown completion profile")
    else:
        ready, error = completion(serial, profile, final=True)
        if not ready or error:
            errors.append(error or "missing exit-cleanup witness")
    # A receipt must describe this finalized serial stream, not an earlier poll.
    digest = hashlib.sha256(serial.encode("utf-8")).hexdigest()
    if receipt.get("serial_text_sha256") != digest:
        errors.append("serial evidence differs from the termination receipt")
    try:
        started = receipt["completion_seconds"]
        stopped = receipt["stop_requested_seconds"]
        deadline = receipt["deadline_seconds"]
        if not all(isinstance(value, (int, float)) and not isinstance(value, bool)
                   for value in (started, stopped, deadline)):
            raise ValueError("non-numeric timing")
        if not (0 <= started <= stopped <= deadline <= MAX_TIMEOUT_SECONDS
                and stopped - started >= SETTLE_SECONDS
                and receipt.get("settle_seconds") == SETTLE_SECONDS):
            raise ValueError("invalid timing")
    except (KeyError, TypeError, ValueError):
        errors.append("invalid completion/observation timing in receipt")
    return errors


def request_quit(path: str, deadline: float) -> None:
    """Negotiate QMP before quit. EOF after sending quit is permitted by QMP."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(max(0.01, deadline - time.monotonic()))
        client.connect(path)
        with client.makefile("rb") as stream:
            greeting = json.loads(stream.readline(1 << 20))
            if not isinstance(greeting, dict) or "QMP" not in greeting:
                raise ValueError("missing QMP greeting")
            client.sendall(b'{"execute":"qmp_capabilities","id":"capabilities"}\r\n')
            while True:
                client.settimeout(max(0.01, deadline - time.monotonic()))
                response = json.loads(stream.readline(1 << 20))
                if not isinstance(response, dict):
                    raise ValueError("invalid QMP capability response")
                if response.get("id") == "capabilities":
                    if "return" not in response:
                        raise ValueError("QMP capability negotiation failed")
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("QMP capability negotiation timed out")
            client.sendall(b'{"execute":"quit","id":"quit"}\r\n')
            while True:
                client.settimeout(max(0.01, deadline - time.monotonic()))
                line = stream.readline(1 << 20)
                if not line:
                    return
                response = json.loads(line)
                if not isinstance(response, dict):
                    raise ValueError("invalid QMP quit response")
                if response.get("id") == "quit":
                    if "return" not in response:
                        raise ValueError("QMP quit was rejected")
                    return
                if time.monotonic() >= deadline:
                    raise TimeoutError("QMP quit response timed out")


def run(args: argparse.Namespace) -> int:
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or "-qmp" in command:
        raise ValueError("provide a QEMU command without an existing QMP endpoint")
    record = dict(schema=1, mode="completion", profile=args.profile, reason="launch-error",
                  deadline_seconds=args.timeout, settle_seconds=SETTLE_SECONDS,
                  completion_seconds=None, stop_requested_seconds=None, elapsed_seconds=0,
                  qemu_returncode=None, stop_method=None, forced_kill=False, signal=None,
                  error=None, runner_status=2)
    started = time.monotonic()
    process = None
    previous_handlers = {}

    def cancelled(signum, _frame):
        record["signal"] = signum

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, cancelled)
    try:
        # A short private pathname also works when artifact directories exceed
        # the Unix socket path limit. The socket is never network-accessible.
        with tempfile.TemporaryDirectory(prefix="nilix-qmp-", dir="/tmp") as control:
            endpoint = str(Path(control) / "qmp")
            for path in (args.serial, args.qemu_stderr):
                if path.exists() and path.stat().st_size:
                    raise ValueError(f"refusing stale diagnostic output: {path}")
            args.serial.touch()
            with args.qemu_stderr.open("wb") as diagnostics:
                process = subprocess.Popen([*command, "-qmp", f"unix:{endpoint},server=on,wait=off"],
                                           stdout=subprocess.DEVNULL, stderr=diagnostics, start_new_session=True)
                deadline = started + args.timeout
                while True:
                    now = time.monotonic()
                    if record["signal"] is not None:
                        record["reason"] = "cancelled"
                        break
                    if process.poll() is not None:
                        record["reason"] = "unexpected-exit"
                        break
                    if now >= deadline:
                        record["reason"] = "deadline"
                        break
                    serial = args.serial.read_text(encoding="utf-8", errors="replace")
                    diagnostics_text = args.qemu_stderr.read_text(encoding="utf-8", errors="replace")
                    if TERMINAL_FATAL.search(serial) or TERMINAL_FATAL.search(diagnostics_text):
                        record["reason"] = "fatal-output"
                        break
                    ready, error = completion(serial, args.profile)
                    if error:
                        record.update(reason="invalid-completion", error=error)
                        break
                    if ready and record["completion_seconds"] is None:
                        record["completion_seconds"] = now - started
                    if ready and now - started - record["completion_seconds"] >= SETTLE_SECONDS:
                        record["reason"] = "completed"
                        break
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
                if process.poll() is None:
                    record["stop_requested_seconds"] = time.monotonic() - started
                    stop_deadline = time.monotonic() + STOP_SECONDS
                    try:
                        request_quit(endpoint, min(stop_deadline, time.monotonic() + 2))
                        record["stop_method"] = "qmp-quit"
                        process.wait(timeout=max(0.01, stop_deadline - time.monotonic()))
                    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                        record.update(reason="stop-error", error=str(error), stop_method="term")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record["error"] = str(error)
    finally:
        if process is not None and process.poll() is None:
            # Only signal the still-owned child's private process group. Never
            # search for another QEMU by name or signal a reaped numeric PID.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                record["forced_kill"] = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if process is not None:
            record["qemu_returncode"] = process.returncode
            record["qemu_pid"] = process.pid
        if record["signal"] is not None:
            record["reason"] = "cancelled"
        record["elapsed_seconds"] = time.monotonic() - started
        try:
            serial = args.serial.read_text(encoding="utf-8", errors="replace") if args.serial.exists() else ""
        except OSError as error:
            serial = ""
            record["error"] = str(error)
        record["serial_text_sha256"] = hashlib.sha256(serial.encode("utf-8")).hexdigest()
        record["runner_status"] = (0 if record["reason"] == "completed" and record["qemu_returncode"] == 0
                                   and not record["forced_kill"] and record["error"] is None else 1)
        args.receipt.write_text(json.dumps(record, indent=2) + "\n")
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    print(f"QEMU-RUN reason={record['reason']} elapsed={record['elapsed_seconds']:.3f}s "
          f"status={record['qemu_returncode']} receipt={args.receipt}")
    return record["runner_status"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, type=Path)
    parser.add_argument("--qemu-stderr", type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--profile", choices=("runtime", "musl", "ring3"), default="runtime")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--verify-status", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.verify_status is not None:
        try:
            errors = termination_errors(args.serial.read_text(encoding="utf-8", errors="replace"),
                                        "completion", json.loads(args.receipt.read_text()), args.verify_status)
        except (OSError, ValueError) as error:
            errors = [str(error)]
        for error in errors:
            print("QEMU-RUN FAIL: " + error)
        return int(bool(errors))
    if not 1 <= args.timeout <= MAX_TIMEOUT_SECONDS or args.qemu_stderr is None:
        parser.error(f"timeout must be 1..{MAX_TIMEOUT_SECONDS} and --qemu-stderr is required")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
