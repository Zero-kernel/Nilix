#!/usr/bin/env python3
"""Phased QEMU interrupt tracing (THREAD-HB C1).

Guests boot with `-d int,cpu_reset`. Once the serial log shows the kernel's AP
acknowledgement marker, `log cpu_reset` over QMP stops the per-interrupt
register dumps that dominate TCG guests at 16 vCPUs, while QEMU keeps logging
`Triple fault` under the `cpu_reset` item. The receipt binds the switch to the
serial prefix that triggered it. A missing marker or a confirmed rejection leaves
full tracing on. An unacknowledged command has unknown scope and fails the gate.

Gate defaults (private design thread-hb-trace-phase-design.md §3.2): `phased`
only where the verdict reads no interrupt-log class that the kernel cannot also
report on serial (the stress profiles and the Ring-3 oracle); `full` for every
gate_log.py verdict until a kernel exception ledger covers faults the kernel
resolves silently. `NILIX_QEMU_TRACE=full|phased` overrides the default; a
phased run of a full-default gate is diagnostic and never better than QUALIFIED.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import sys
import time


POLICIES = ("full", "phased")
BOOT_ITEMS = "int,cpu_reset"
STEADY_ITEMS = "cpu_reset"
# Printed once by wait_for_process_deferred_acknowledgements after AP bring-up,
# the trampoline NX change and the in-kernel tests, before any user task runs.
MARKER = re.compile(rb"\[SMP\] process-deferred gate complete: ([0-9]+)/([0-9]+) APs acknowledged\r?\n")
OUTCOMES = ("switched", "switch-failed", "switch-unknown", "marker-missing", "qemu-exited", "aborted")
QMP_SECONDS = 5.0
POLL_SECONDS = 0.05
# Diagnostic tail after a missed completion deadline: the verdict is already a
# failure, so restoring the full trace cannot perturb a judged window.
TAIL_SECONDS = 10.0
LABELS = {0: "OK", 1: "FAIL", 2: "INCOMPLETE", 3: "QUALIFIED"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def find_marker(serial: bytes, cpus: int) -> tuple[int, int] | None:
    """Offsets of the first acknowledgement line, if it reports `cpus` vCPUs."""
    match = MARKER.search(serial)
    if match is None or not int(match[1]) == int(match[2]) == cpus - 1:
        return None
    return match.start(), match.end()


class HmpOutcomeUnknown(ValueError):
    """The command may have taken effect, but no valid reply proves its outcome."""


def hmp(path: str, command_line: str, timeout: float = QMP_SECONDS) -> dict:
    """Run one HMP command in a fresh QMP session and return QEMU's reply."""
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(path)
        with client.makefile("rb") as stream:
            def receive(identifier: str | None) -> dict:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("QMP reply deadline expired")
                    client.settimeout(remaining)
                    line = stream.readline(1 << 20)
                    if not line:
                        raise ConnectionError("QMP closed the session")
                    reply = json.loads(line)
                    if not isinstance(reply, dict):
                        raise ValueError("invalid QMP message")
                    if identifier is None or reply.get("id") == identifier:
                        return reply

            if "QMP" not in receive(None):
                raise ValueError("missing QMP greeting")
            client.sendall(b'{"execute":"qmp_capabilities","id":"capabilities"}\r\n')
            if "return" not in receive("capabilities"):
                raise ValueError("QMP capability negotiation failed")
            request = {"execute": "human-monitor-command", "arguments": {"command-line": command_line}, "id": "hmp"}
            try:
                # Even a sendall error can follow delivery of the full request.
                # Once delivery is attempted, transport errors cannot prove that
                # QEMU kept the previous trace mask.
                client.sendall(json.dumps(request).encode() + b"\r\n")
                reply = receive("hmp")
                if not (isinstance(reply.get("return"), str) or isinstance(reply.get("error"), dict)):
                    raise ValueError("invalid HMP reply")
                return reply
            except (OSError, ValueError) as error:
                raise HmpOutcomeUnknown(str(error)) from error


class TracePhase:
    """Switch one QEMU's log from BOOT_ITEMS to STEADY_ITEMS after the marker."""

    def __init__(self, qmp: str, serial: Path, intlog: Path, cpus: int) -> None:
        self.qmp, self.serial, self.intlog, self.cpus = qmp, serial, intlog, cpus
        self.started = time.monotonic()
        self.receipt = dict(
            schema=1, policy="phased", boot_items=BOOT_ITEMS, steady_items=STEADY_ITEMS, cpus=cpus,
            marker=MARKER.pattern.decode(), outcome=None, marker_offset=None, marker_end=None,
            serial_prefix_sha256=None, serial_bytes_at_switch=None, switched_seconds=None,
            intlog_bytes_at_switch=None, intlog_bytes_final=None, qmp_reply=None, error=None, tail=None)

    @property
    def pending(self) -> bool:
        return self.receipt["outcome"] is None

    def poll(self, timeout: float = QMP_SECONDS) -> bool:
        """Switch once the marker has arrived; True after the one attempt."""
        if not self.pending:
            return True
        serial = self.serial.read_bytes()
        found = find_marker(serial, self.cpus)
        if found is None:
            return False
        self.receipt.update(marker_offset=found[0], marker_end=found[1],
                            serial_prefix_sha256=digest(serial[:found[1]]))
        try:
            reply = hmp(self.qmp, "log " + STEADY_ITEMS, timeout=min(QMP_SECONDS, timeout))
        except HmpOutcomeUnknown as error:
            self.receipt.update(outcome="switch-unknown", error=str(error))
            return True
        except (OSError, ValueError) as error:
            self.receipt.update(outcome="switch-failed", error=str(error))
            return True
        self.receipt["qmp_reply"] = reply
        if reply.get("return") != "":
            # HMP reports a rejected item as text in an otherwise successful reply.
            self.receipt.update(outcome="switch-failed", error="QEMU did not accept the log change")
            return True
        # Bytes beyond these offsets were written after QEMU applied the change.
        self.receipt.update(outcome="switched", switched_seconds=round(time.monotonic() - self.started, 3),
                            serial_bytes_at_switch=size(self.serial), intlog_bytes_at_switch=size(self.intlog))
        return True

    def tail(self, stop) -> None:
        """Restore the full trace for TAIL_SECONDS before a failed run is stopped."""
        if self.receipt["outcome"] != "switched":
            return
        record = dict(started_seconds=round(time.monotonic() - self.started, 3), seconds=TAIL_SECONDS)
        try:
            record["qmp_reply"] = hmp(self.qmp, "log " + BOOT_ITEMS)
        except (OSError, ValueError) as error:
            record["error"] = str(error)
        self.receipt["tail"] = record
        until = time.monotonic() + TAIL_SECONDS
        while "error" not in record and time.monotonic() < until and not stop():
            time.sleep(POLL_SECONDS)

    def finish(self, outcome: str) -> dict:
        """Close the receipt; `outcome` applies only if no switch was attempted."""
        if self.pending:
            self.receipt["outcome"] = outcome
        self.receipt["intlog_bytes_final"] = size(self.intlog)
        return self.receipt


def verify(policy: str, default: str, receipt: object, serial: bytes) -> tuple[int, str, list[str]]:
    """Return (status, trace scope, reasons); status 0 ok, 1 fail, 2 incomplete, 3 qualified."""
    if policy not in POLICIES or default not in POLICIES:
        return 1, "unknown", ["unknown interrupt-trace policy"]
    if policy == "full":
        return 0, "full", []
    if not isinstance(receipt, dict):
        return 2, "unknown", ["missing interrupt-trace receipt for a phased run"]
    if (receipt.get("schema") != 1 or receipt.get("policy") != "phased"
            or receipt.get("outcome") not in OUTCOMES or not isinstance(receipt.get("cpus"), int)
            or isinstance(receipt.get("cpus"), bool)):
        return 1, "unknown", ["malformed interrupt-trace receipt"]
    if receipt["outcome"] == "switch-unknown":
        return 1, "unknown", ["interrupt-trace switch was not acknowledged; trace scope is unknown"]
    if receipt["outcome"] != "switched":
        return 0, "full", [f"interrupt trace stayed full ({receipt['outcome']})"]
    found = find_marker(serial, receipt["cpus"])
    at_switch, final = receipt.get("intlog_bytes_at_switch"), receipt.get("intlog_bytes_final")
    reply = receipt.get("qmp_reply")
    if (found is None or [receipt.get("marker_offset"), receipt.get("marker_end")] != list(found)
            or receipt.get("serial_prefix_sha256") != digest(serial[:found[1]])
            or not isinstance(receipt.get("serial_bytes_at_switch"), int)
            or not found[1] <= receipt["serial_bytes_at_switch"] <= len(serial)
            or not isinstance(reply, dict) or reply.get("return") != ""
            or not isinstance(at_switch, int) or not isinstance(final, int) or final < at_switch):
        return 1, "phased", ["interrupt-trace receipt does not match the final serial log"]
    if default == "full":
        return 3, "phased", ["interrupt trace reduced after boot by NILIX_QEMU_TRACE=phased: "
                             "diagnostic, not an acceptance result"]
    return 0, "phased", []


def load_receipt(path: Path | None) -> object:
    try:
        return json.loads(path.read_text()) if path is not None else None
    except (OSError, ValueError):
        return None


def sidecar(args: argparse.Namespace) -> int:
    """Switch a QEMU started elsewhere; exits after the attempt, on QEMU or parent exit, or at the deadline."""
    stopped = []
    signal.signal(signal.SIGTERM, lambda *_: stopped.append(True))
    parent = os.getppid()
    phase = TracePhase(str(args.qmp), args.serial, args.intlog, args.cpus)
    deadline = time.monotonic() + args.timeout
    outcome = "marker-missing"
    while not phase.poll():
        if stopped or (args.watch_parent and os.getppid() != parent):
            outcome = "aborted"
            break
        if args.pid is not None:
            try:
                os.kill(args.pid, 0)
            except ProcessLookupError:
                outcome = "qemu-exited"
                break
        if time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
    args.receipt.write_text(json.dumps(phase.finish(outcome), indent=2) + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    switch = commands.add_parser("switch", help="switch a running QEMU after the marker and write a receipt")
    switch.add_argument("--qmp", required=True, type=Path)
    switch.add_argument("--serial", required=True, type=Path)
    switch.add_argument("--intlog", required=True, type=Path)
    switch.add_argument("--cpus", required=True, type=int)
    switch.add_argument("--receipt", required=True, type=Path)
    switch.add_argument("--timeout", required=True, type=float)
    switch.add_argument("--pid", type=int, help="stop waiting once this process has exited")
    switch.add_argument("--watch-parent", action="store_true", help="stop waiting once the parent has exited")
    check = commands.add_parser("verify", help="check a run's receipt against its final serial log")
    check.add_argument("--policy", required=True, choices=POLICIES)
    check.add_argument("--default", required=True, choices=POLICIES)
    check.add_argument("--receipt", required=True, type=Path)
    check.add_argument("--serial", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "switch":
        if args.cpus < 1:
            parser.error("--cpus must be positive")
        return sidecar(args)
    try:
        serial = args.serial.read_bytes()
    except OSError as error:
        print(f"TRACE-PHASE INCOMPLETE: cannot read {args.serial}: {error}")
        return 2
    status, scope, reasons = verify(args.policy, args.default, load_receipt(args.receipt), serial)
    print(f"TRACE-PHASE {LABELS[status]}: policy={args.policy} default={args.default} scope={scope}")
    for reason in reasons:
        print(f"  {reason}")
    return status


if __name__ == "__main__":
    sys.exit(main())
