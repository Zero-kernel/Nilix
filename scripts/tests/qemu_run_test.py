"""Exercise the real supervisor against an owned synthetic QMP process."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from scripts.ci import gate_log, qemu_run


ROOT = Path(__file__).resolve().parents[2]
CLEAN = (ROOT / "scripts/fixtures/gate_logs/clean-smp.serial").read_text()
WITNESS = "CI-EXIT pid=1 code=0 stage=teardown-complete\n"

FAKE_QEMU = r'''
import json, os, signal, socket, sys, time
from pathlib import Path
serial = Path(sys.argv[sys.argv.index('-serial') + 1].removeprefix('file:'))
intlog = Path(sys.argv[sys.argv.index('-D') + 1]) if '-D' in sys.argv else None
if intlog is not None:
    intlog.write_text(Path(os.environ['GATE_INTLOG']).read_text() if 'GATE_INTLOG' in os.environ else '')
endpoint = sys.argv[sys.argv.index('-qmp') + 1].split(',', 1)[0].removeprefix('unix:')
mode = os.environ['FAKE_MODE']
Path(str(serial) + '.pid').write_text(str(os.getpid()))
if mode == 'reject-and-ignore-term':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(endpoint)
server.listen(1)
serial.write_text(Path(os.environ['FAKE_SERIAL']).read_text())
if mode == 'early-fault':
    with serial.open('a') as out:
        out.write('KERNEL PANIC before cleanup\n')
if mode == 'unexpected-exit':
    with serial.open('a') as out:
        out.write('CI-EXIT pid=1 code=0 stage=teardown-complete\n')
    raise SystemExit(0)
time.sleep(0.25)
if mode not in ('missing-witness', 'cancel'):
    with serial.open('a') as out:
        out.write('CI-EXIT pid=1 code=0 stage=teardown-complete\n')
        if mode == 'duplicate':
            out.write('CI-EXIT pid=1 code=0 stage=teardown-complete\n')
if mode == 'late-fault':
    time.sleep(0.25)
    with serial.open('a') as out:
        out.write('KERNEL PANIC after completion\n')
    print('late diagnostic retained', file=sys.stderr, flush=True)
client, _ = server.accept()
with client, client.makefile('rb') as stream:
    client.sendall(b'{"QMP":{"version":{},"capabilities":[]}}\r\n')
    for line in stream:
        request = json.loads(line)
        if mode == 'reject-and-ignore-term':
            client.sendall(json.dumps({'error':{'class':'GenericError'}, 'id':request['id']}).encode()+b'\r\n')
            while True:
                time.sleep(1)
        if request['execute'] == 'qmp_capabilities':
            client.sendall(b'{"event":"TEST_EVENT"}\r\n')
            client.sendall(json.dumps({'return':{}, 'id':request['id']}).encode()+b'\r\n')
        elif request['execute'] == 'quit':
            if mode == 'quit-interrupt-fault' and intlog is not None:
                with intlog.open('a') as out:
                    out.write('  42: v=0e e=0011 i=0 cpl=0 IP=0008:ffffffff80001000\n')
            if mode == 'quit-fault':
                with serial.open('a') as out:
                    out.write('KERNEL PANIC during QMP shutdown\n')
                print('late diagnostic retained', file=sys.stderr, flush=True)
            if mode == 'quit-error':
                client.sendall(json.dumps({'error':{'class':'GenericError'}, 'id':request['id']}).encode()+b'\r\n')
            # Successful quit may EOF before responding, as real QEMU may.
            break
'''


class CompletionTests(unittest.TestCase):
    def test_early_exit_and_partial_record_are_not_completion(self):
        self.assertEqual(qemu_run.completion(CLEAN, "runtime"), (False, None))
        self.assertEqual(qemu_run.completion(CLEAN + WITNESS.rstrip(), "runtime"), (False, None))
        self.assertTrue(qemu_run.completion(CLEAN + WITNESS, "runtime")[0])
        self.assertTrue(qemu_run.completion(CLEAN + '/ nilix# ' + WITNESS, "runtime")[0])
        self.assertFalse(qemu_run.completion(CLEAN + WITNESS + 'CI-EXIT', "runtime", final=True)[0])

    def test_cleanup_requires_unique_consistent_ordered_records(self):
        for serial in (WITNESS + CLEAN, CLEAN + WITNESS * 2,
                       CLEAN + WITNESS.replace('code=0', 'code=7'),
                       CLEAN + WITNESS.replace('stage=', 'bad='),
                       CLEAN + CLEAN + WITNESS):
            with self.subTest(serial=serial):
                ready, error = qemu_run.completion(serial, "runtime")
                self.assertFalse(ready)
                self.assertIsNotNone(error)

    def test_profile_specific_end_records_are_required(self):
        for profile, marker in (("musl", "musl libc test passed!\n"),
                                ("ring3", "  Results: 52 passed, 0 failed\n")):
            with self.subTest(profile=profile):
                self.assertFalse(qemu_run.completion(CLEAN + WITNESS, profile)[0])
                self.assertTrue(qemu_run.completion(CLEAN + marker + WITNESS, profile)[0])


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux QEMU process ownership")
class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="qemu-run-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.serial = self.root / "serial"
        self.stderr = self.root / "qemu.stderr"
        self.receipt = self.root / "run.json"
        self.fake = self.root / "qemu.py"
        self.fake.write_text(FAKE_QEMU)
        (self.root / "fixture").write_text(CLEAN)

    def start(self, mode="normal", timeout=900):
        command = [sys.executable, str(ROOT / "scripts/ci/qemu_run.py"),
                   "--serial", str(self.serial), "--qemu-stderr", str(self.stderr),
                   "--receipt", str(self.receipt), "--timeout", str(timeout), "--",
                   sys.executable, str(self.fake), "-serial", "file:" + str(self.serial)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env={**os.environ, "FAKE_MODE": mode, "FAKE_SERIAL": str(self.root / 'fixture')})

        def cleanup():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        self.addCleanup(cleanup)
        return process

    def finish(self, process):
        stdout, stderr = process.communicate(timeout=18)
        self.assertTrue(self.receipt.exists(), stdout + stderr)
        receipt = json.loads(self.receipt.read_text())
        if 'qemu_pid' in receipt:
            with self.assertRaises(ProcessLookupError):
                os.kill(receipt['qemu_pid'], 0)
        return receipt

    def verdict(self, receipt, status=0, serial=None):
        return gate_log.evaluate(self.serial.read_text() if serial is None else serial,
                                 "", self.stderr.read_text(), "", status,
                                 termination_mode="completion", termination_receipt=receipt)

    def test_collects_without_waiting_for_900_seconds_and_retains_tail(self):
        process = self.start()
        receipt = self.finish(process)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(receipt['reason'], 'completed')
        self.assertGreaterEqual(receipt['completion_seconds'], 0.20)
        self.assertGreaterEqual(receipt['stop_requested_seconds'] - receipt['completion_seconds'], 2)
        self.assertLess(receipt['elapsed_seconds'], 10)
        self.assertEqual(self.verdict(receipt).status, 0)
        for field, value in (('reason', 'deadline'), ('qemu_returncode', -15),
                             ('forced_kill', True), ('signal', 15), ('mode', 'window'),
                             ('stop_requested_seconds', 0), ('settle_seconds', 0)):
            changed = copy.deepcopy(receipt)
            changed[field] = value
            self.assertEqual(self.verdict(changed).status, 1, field)
        self.assertEqual(self.verdict(receipt, serial=self.serial.read_text() + 'changed\n').status, 1)

    def test_fatal_output_during_tail_overrides_completed_process(self):
        process = self.start('quit-fault')
        receipt = self.finish(process)
        self.assertEqual(receipt['reason'], 'completed')
        self.assertIn('late diagnostic retained', self.stderr.read_text())
        self.assertEqual(self.verdict(receipt).status, 1)

    def test_fatal_output_before_or_during_tail_stops_without_waiting(self):
        for mode in ('early-fault', 'late-fault'):
            with self.subTest(mode=mode):
                for path in (self.serial, self.stderr, self.receipt):
                    path.unlink(missing_ok=True)
                process = self.start(mode)
                receipt = self.finish(process)
                self.assertEqual(receipt['reason'], 'fatal-output')
                self.assertLess(receipt['elapsed_seconds'], 2)
                self.assertEqual(self.verdict(receipt, process.returncode).status, 1)

    def test_deadline_without_cleanup_witness_never_passes(self):
        process = self.start('missing-witness', timeout=1)
        receipt = self.finish(process)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(receipt['reason'], 'deadline')
        self.assertEqual(self.verdict(receipt, process.returncode).status, 1)

    def test_spontaneous_clean_exit_is_not_host_controlled_completion(self):
        process = self.start('unexpected-exit')
        receipt = self.finish(process)
        self.assertEqual(receipt['qemu_returncode'], 0)
        self.assertEqual(receipt['reason'], 'unexpected-exit')
        self.assertNotEqual(process.returncode, 0)

    def test_duplicate_witness_fails_and_reaps_child(self):
        process = self.start('duplicate')
        receipt = self.finish(process)
        self.assertEqual(receipt['reason'], 'invalid-completion')
        self.assertNotEqual(process.returncode, 0)

    def test_rejected_quit_cannot_pass_even_if_qemu_exits_zero(self):
        process = self.start('quit-error')
        receipt = self.finish(process)
        self.assertEqual(receipt['reason'], 'stop-error')
        self.assertNotEqual(process.returncode, 0)

    def test_cancel_records_reason_and_reaps_child(self):
        process = self.start('cancel')
        until = time.monotonic() + 5
        while not Path(str(self.serial) + '.pid').exists() and time.monotonic() < until:
            time.sleep(0.01)
        self.assertTrue(Path(str(self.serial) + '.pid').exists())
        process.send_signal(signal.SIGTERM)
        receipt = self.finish(process)
        self.assertEqual(receipt['reason'], 'cancelled')
        self.assertEqual(receipt['signal'], signal.SIGTERM)
        self.assertNotEqual(process.returncode, 0)

    def test_forced_kill_is_recorded_as_failure(self):
        process = self.start('reject-and-ignore-term')
        receipt = self.finish(process)
        self.assertTrue(receipt['forced_kill'])
        self.assertEqual(receipt['qemu_returncode'], -signal.SIGKILL)
        self.assertNotEqual(process.returncode, 0)

    def test_stale_serial_is_rejected_before_launch(self):
        self.serial.write_text(CLEAN + WITNESS)
        process = self.start()
        receipt = self.finish(process)
        self.assertEqual(receipt['reason'], 'launch-error')
        self.assertFalse(Path(str(self.serial) + '.pid').exists())
        self.assertNotEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
