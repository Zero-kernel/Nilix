"""Phased interrupt tracing (THREAD-HB C1) against a synthetic multi-session QMP QEMU."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from scripts.ci import gate_log, qemu_run, qemu_trace


ROOT = Path(__file__).resolve().parents[2]
CLEAN = (ROOT / "scripts/fixtures/gate_logs/clean-smp.serial").read_text()
MARKER = "[SMP] process-deferred gate complete: 3/3 APs acknowledged\n"
WITNESS = "CI-EXIT pid=1 code=0 stage=teardown-complete\n"

# Serves any number of QMP sessions, records HMP commands, and appends serial
# chunks on a schedule: FAKE_SCRIPT is [[delay_seconds, text], ...].
FAKE_QEMU = r'''
import json, os, socket, sys, threading, time
from pathlib import Path
argv = sys.argv
serial = Path(argv[argv.index('-serial') + 1].removeprefix('file:'))
intlog = Path(argv[argv.index('-D') + 1])
endpoint = argv[argv.index('-qmp') + 1].split(',', 1)[0].removeprefix('unix:')
commands = Path(os.environ['FAKE_COMMANDS'])
reply = os.environ.get('FAKE_HMP_REPLY', '')
intlog.write_text('     0: v=20 e=0000 i=0 cpl=0 IP=0008:ffffffff80001000\n')
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(endpoint)
server.listen(4)

def serve():
    while True:
        client, _ = server.accept()
        with client, client.makefile('rb') as stream:
            client.sendall(b'{"QMP":{"version":{},"capabilities":[]}}\r\n')
            for line in stream:
                request = json.loads(line)
                if request['execute'] == 'qmp_capabilities':
                    client.sendall(json.dumps({'return': {}, 'id': request['id']}).encode() + b'\r\n')
                elif request['execute'] == 'human-monitor-command':
                    with commands.open('a') as out:
                        out.write(request['arguments']['command-line'] + '\n')
                    client.sendall(json.dumps({'return': reply, 'id': request['id']}).encode() + b'\r\n')
                elif request['execute'] == 'quit':
                    with commands.open('a') as out:
                        out.write('quit\n')
                    os._exit(0)

threading.Thread(target=serve, daemon=True).start()
for delay, chunk in json.loads(os.environ['FAKE_SCRIPT']):
    time.sleep(delay)
    with serial.open('a') as out:
        out.write(chunk)
while True:
    time.sleep(1)
'''


def switched_receipt(serial: bytes, cpus: int = 4) -> dict:
    start, end = qemu_trace.find_marker(serial, cpus)
    return dict(schema=1, policy="phased", boot_items="int,cpu_reset", steady_items="cpu_reset", cpus=cpus,
                outcome="switched", marker_offset=start, marker_end=end,
                serial_prefix_sha256=qemu_trace.digest(serial[:end]), serial_bytes_at_switch=end,
                intlog_bytes_at_switch=100, intlog_bytes_final=100, qmp_reply={"return": "", "id": "hmp"})


class MarkerAndVerifyTests(unittest.TestCase):
    serial = ("boot\n" + MARKER + "user work\n").encode()

    def test_marker_needs_a_complete_line_with_the_expected_topology(self):
        self.assertIsNotNone(qemu_trace.find_marker(self.serial, 4))
        self.assertIsNone(qemu_trace.find_marker(self.serial, 2))
        self.assertIsNone(qemu_trace.find_marker(MARKER.rstrip("\n").encode(), 4))
        single = b"[SMP] process-deferred gate complete: 0/0 APs acknowledged\n"
        self.assertEqual(qemu_trace.find_marker(single, 1), (0, len(single)))

    def test_full_policy_needs_no_receipt(self):
        self.assertEqual(qemu_trace.verify("full", "phased", None, b"")[:2], (0, "full"))

    def test_phased_run_without_receipt_is_incomplete(self):
        self.assertEqual(qemu_trace.verify("phased", "phased", None, self.serial)[0], 2)

    def test_consistent_switch_passes_a_phased_default_and_qualifies_a_full_default(self):
        receipt = switched_receipt(self.serial)
        self.assertEqual(qemu_trace.verify("phased", "phased", receipt, self.serial), (0, "phased", []))
        status, scope, reasons = qemu_trace.verify("phased", "full", receipt, self.serial)
        self.assertEqual((status, scope), (3, "phased"))
        self.assertIn("diagnostic", reasons[0])

    def test_inconsistent_receipts_fail(self):
        good = switched_receipt(self.serial)
        for field, value in (("marker_offset", 1), ("serial_prefix_sha256", "0" * 64),
                             ("serial_bytes_at_switch", 0), ("serial_bytes_at_switch", 10**6),
                             ("qmp_reply", {"return": "Invalid log option"}), ("intlog_bytes_final", 99),
                             ("cpus", 2), ("cpus", True), ("outcome", "unknown"), ("schema", 2)):
            with self.subTest(field=field, value=value):
                self.assertEqual(qemu_trace.verify("phased", "phased", dict(good, **{field: value}),
                                                   self.serial)[0], 1)
        changed = self.serial.replace(b"boot", b"BOOT")
        self.assertEqual(qemu_trace.verify("phased", "phased", good, changed)[0], 1)

    def test_runs_that_never_switched_stay_full(self):
        for outcome in ("switch-failed", "marker-missing", "qemu-exited", "aborted"):
            receipt = dict(schema=1, policy="phased", cpus=4, outcome=outcome)
            self.assertEqual(qemu_trace.verify("phased", "full", receipt, self.serial)[:2], (0, "full"))


class GateLogTraceTests(unittest.TestCase):
    serial = ("boot\n" + MARKER).encode()

    def result(self, status):
        return gate_log.GateResult(status, (1, 0, 0), 0, 0, ("prior",), {"strict_requested": False})

    def test_worst_verdict_wins_and_strict_rejects_a_diagnostic_scope(self):
        receipt = switched_receipt(self.serial)
        self.assertEqual(gate_log.apply_trace(self.result(0), "phased", "full", receipt, self.serial, False).status, 3)
        self.assertEqual(gate_log.apply_trace(self.result(0), "phased", "full", receipt, self.serial, True).status, 1)
        self.assertEqual(gate_log.apply_trace(self.result(1), "phased", "full", receipt, self.serial, False).status, 1)
        self.assertEqual(gate_log.apply_trace(self.result(0), "phased", "phased", None, self.serial, False).status, 2)
        self.assertEqual(gate_log.apply_trace(self.result(3), "phased", "phased", receipt, self.serial, False).status, 3)
        kept = gate_log.apply_trace(self.result(0), "full", "full", None, b"", False)
        self.assertEqual((kept.status, kept.details["trace_scope"]), (0, "full"))


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="qemu-trace-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = self.root / "fake_qemu.py"
        self.fake.write_text(FAKE_QEMU)
        self.serial, self.intlog = self.root / "serial.log", self.root / "interrupts.log"
        self.commands = self.root / "commands.log"
        self.commands.touch()

    def environment(self, script, reply=""):
        return dict(os.environ, FAKE_COMMANDS=str(self.commands), FAKE_SCRIPT=json.dumps(script),
                    FAKE_HMP_REPLY=reply)

    def qemu(self):
        return [sys.executable, str(self.fake), "-serial", f"file:{self.serial}", "-D", str(self.intlog)]

    def supervise(self, script, timeout=30, reply=""):
        receipt, trace = self.root / "run.json", self.root / "trace.json"
        command = [sys.executable, str(ROOT / "scripts/ci/qemu_run.py"), "--serial", str(self.serial),
                   "--qemu-stderr", str(self.root / "qemu.stderr"), "--receipt", str(receipt),
                   "--timeout", str(timeout), "--trace-policy", "phased", "--intlog", str(self.intlog),
                   "--trace-cpus", "4", "--trace-receipt", str(trace), "--", *self.qemu()]
        subprocess.run(command, env=self.environment(script, reply), capture_output=True, timeout=120, check=False)
        return json.loads(receipt.read_text()), json.loads(trace.read_text())

    def test_completion_switches_after_the_marker_then_quits(self):
        # The fixture already carries the 3/3 marker after its runtime summary.
        self.assertIn(MARKER, CLEAN)
        run, trace = self.supervise([[0.1, CLEAN], [0.3, WITNESS]])
        self.assertEqual(run["reason"], "completed")
        self.assertEqual(trace["outcome"], "switched")
        self.assertEqual(self.commands.read_text().splitlines(), ["log cpu_reset", "quit"])
        serial = self.serial.read_bytes()
        self.assertEqual(qemu_trace.verify("phased", "phased", trace, serial)[0], 0)
        self.assertEqual(gate_log.evaluate(serial.decode(), "", "", "", 0, termination_mode="completion",
                                           termination_receipt=run).status, 0)

    def test_rejected_switch_keeps_the_full_trace(self):
        _, trace = self.supervise([[0.1, CLEAN], [0.1, WITNESS]], reply="Invalid log option\r\n")
        self.assertEqual(trace["outcome"], "switch-failed")
        self.assertEqual(qemu_trace.verify("phased", "phased", trace, self.serial.read_bytes())[:2], (0, "full"))

    def test_no_marker_before_completion_is_recorded(self):
        _, trace = self.supervise([[0.1, CLEAN.replace(MARKER, "")], [0.1, WITNESS]])
        self.assertEqual(trace["outcome"], "marker-missing")
        self.assertEqual(self.commands.read_text().splitlines(), ["quit"])

    def test_missed_deadline_restores_the_full_trace_before_stopping(self):
        # Patch the module the supervisor actually imported (script or package path).
        module = sys.modules[qemu_run.TracePhase.__module__]
        original = module.TAIL_SECONDS
        module.TAIL_SECONDS = 0.3
        self.addCleanup(setattr, module, "TAIL_SECONDS", original)
        args = argparse.Namespace(command=["--", *self.qemu()], serial=self.serial,
                                  qemu_stderr=self.root / "qemu.stderr", receipt=self.root / "run.json",
                                  profile="runtime", timeout=2, trace_policy="phased", intlog=self.intlog,
                                  trace_cpus=4, trace_receipt=self.root / "trace.json")
        previous = {name: os.environ.get(name) for name in ("FAKE_COMMANDS", "FAKE_SCRIPT", "FAKE_HMP_REPLY")}
        os.environ.update(self.environment([[0.1, MARKER]]))
        try:
            self.assertEqual(qemu_run.run(args), 1)
        finally:
            for name, value in previous.items():
                os.environ.pop(name, None) if value is None else os.environ.__setitem__(name, value)
        trace = json.loads((self.root / "trace.json").read_text())
        run = json.loads((self.root / "run.json").read_text())
        self.assertEqual(run["reason"], "deadline")
        self.assertLess(run["elapsed_seconds"], 8)
        self.assertEqual(trace["tail"]["qmp_reply"]["return"], "")
        self.assertEqual(self.commands.read_text().splitlines(), ["log cpu_reset", "log int,cpu_reset", "quit"])

    def test_window_mode_keeps_the_timeout_contract(self):
        script = (f'ROOT={ROOT}; ser={self.serial}; qemuerr={self.root}/qemu.stderr; '
                  f'timeoutlog={self.root}/timeout.log; : > "$ser"; '
                  f'source "$ROOT/scripts/ci/qemu_run.sh"; export QEMU_GATE_MODE=window; '
                  f'QEMU_TRACE_POLICY=phased; QEMU_TRACE_INTLOG={self.intlog}; QEMU_TRACE_CPUS=4; '
                  f'run_gate_qemu 3 runtime '
                  f'{sys.executable} {self.fake} -serial file:{self.serial} -D {self.intlog}; '
                  f'qemu_status=$?; verify_gate_termination && echo CONTRACT-OK')
        result = subprocess.run(["bash", "-c", script], env=self.environment([[0.2, MARKER]]),
                                capture_output=True, text=True, timeout=60)
        self.assertIn("CONTRACT-OK", result.stdout, result.stdout + result.stderr)
        trace = json.loads(Path(str(self.serial) + ".trace.json").read_text())
        self.assertEqual(trace["outcome"], "switched")
        self.assertEqual(self.commands.read_text().splitlines(), ["log cpu_reset"])


class SidecarTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="qemu-trace-sidecar-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.serial, self.receipt = self.root / "serial.log", self.root / "trace.json"
        self.serial.touch()

    def start(self, *extra):
        return subprocess.Popen([sys.executable, str(ROOT / "scripts/ci/qemu_trace.py"), "switch",
                                 "--qmp", str(self.root / "missing.sock"), "--serial", str(self.serial),
                                 "--intlog", str(self.root / "interrupts.log"), "--cpus", "4",
                                 "--receipt", str(self.receipt), "--timeout", "30", *extra])

    def test_terminate_before_the_marker_records_aborted(self):
        process = self.start()
        time.sleep(0.3)
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=10), 0)
        self.assertEqual(json.loads(self.receipt.read_text())["outcome"], "aborted")

    def test_exited_qemu_is_recorded(self):
        finished = subprocess.Popen([sys.executable, "-c", "pass"])
        finished.wait()
        process = self.start("--pid", str(finished.pid))
        self.assertEqual(process.wait(timeout=10), 0)
        self.assertEqual(json.loads(self.receipt.read_text())["outcome"], "qemu-exited")

    def test_unreachable_qmp_after_the_marker_fails_the_switch_safely(self):
        process = self.start()
        self.serial.write_text(MARKER)
        self.assertEqual(process.wait(timeout=20), 0)
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual(receipt["outcome"], "switch-failed")
        self.assertEqual(qemu_trace.verify("phased", "phased", receipt, self.serial.read_bytes())[:2], (0, "full"))


if __name__ == "__main__":
    unittest.main()
