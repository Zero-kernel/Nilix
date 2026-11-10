"""A full stress window must end with a successful host TERM, not a VM exit."""

from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.tests import stress_protocol_test as fixture


ROOT = Path(__file__).resolve().parents[2]


class StressTerminationTests(unittest.TestCase):
    def setUp(self):
        if shutil.which("timeout") is None:
            self.skipTest("GNU timeout is required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = fixture.make_config(
            "thread", workers=2, churn_waves=3, contention_iterations=5,
            heartbeat_max_ms=1000,
        )
        (self.directory / "stress.cfg").write_bytes(self.config.to_bytes())
        for name in ("interrupt.log", "qemu.stderr"):
            (self.directory / name).write_text("")
        (self.directory / "guest.py").write_text('''
from pathlib import Path
import signal
import sys
import time
mode, ready = sys.argv[1:]
if mode == "ignore":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
elif mode == "term-zero":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
elif mode == "orphan":
    def stopped(*_):
        Path("guest.stopped").touch()
        sys.exit(0)
    signal.signal(signal.SIGTERM, stopped)
Path(ready).touch()
if mode.startswith("exit"):
    sys.exit(int(mode[4:]))
while True:
    time.sleep(1)
''', encoding="utf-8")

    def run_gate(self, mode, *, tail=True):
        config = self.config
        ready = fixture.ready(config, "normal")
        hb1 = fixture.heartbeat(config, 1, 12, fixture.CHECKSUM_A)
        hb2 = fixture.heartbeat(config, 2, 24, fixture.CHECKSUM_B)
        lines = [fixture.begin(config), ready,
                 fixture.thread_round(config, 1, fixture.CHECKSUM_A),
                 fixture.common_pass(config, 12, fixture.CHECKSUM_A), hb1,
                 fixture.thread_round(config, 2, fixture.CHECKSUM_B), hb2]
        if tail:
            lines.append(fixture.thread_round(config, 3, fixture.CHECKSUM_A))
        fixture.write_log(self.directory / "serial.log", lines)
        fixture.write_events(self.directory / "events.jsonl", [
            (1_000_000_000, ready), (1_500_000_000, hb1), (2_000_000_000, hb2),
        ])
        source = (ROOT / "scripts/gates/stress/stress_test.sh").read_text()

        def function(name):
            start = source.index(name + "() {")
            return source[start:source.index("\n}\n", start) + 3]

        script = f'''
set -uo pipefail
cd {shlex.quote(str(self.directory))}
PYTHON={shlex.quote(sys.executable)}
PROTOCOL={shlex.quote(str(ROOT / "scripts/gates/stress/stress_protocol.py"))}
TRACE_TOOL={shlex.quote(str(ROOT / "scripts/ci/qemu_trace.py"))}
TRACE_POLICY=full
TRACE_RECEIPT=trace.json
SERIAL_LOG=serial.log
EVENT_LOG=events.jsonl
INTERRUPT_LOG=interrupt.log
QEMU_STDERR=qemu.stderr
RUN_END_NS=2500000000
STRESS_HEARTBEAT_GRACE_MS=0
STRESS_SHUTDOWN_GRACE={0 if mode == "ignore" else 1}
TEST_FAIL=1
stop_trace() {{ :; }}
stop_monitor() {{ :; }}
{function("stop_vm")}
{function("validate_current_log")}
'''
        # A direct child exercises the supported PID-TERM fallback with exit 0.
        prefix = "" if mode == "term-zero" else "timeout -k 2s 30s "
        script += f'''{prefix}"$PYTHON" guest.py {shlex.quote(mode)} guest.ready &
ACTIVE_PID=$!
TEST_PID=$ACTIVE_PID
trap 'kill -KILL -- "-$TEST_PID" 2>/dev/null || kill -KILL "$TEST_PID" 2>/dev/null || true' EXIT
for i in {{1..300}}; do
    [ -f guest.ready ] && break
    sleep 0.01
done
[ -f guest.ready ] || exit 98
'''
        if mode == "orphan":
            script += 'kill -KILL "$ACTIVE_PID"\n'
        if mode.startswith("exit") or mode == "orphan":
            script += '''for i in {1..300}; do
    kill -0 "$ACTIVE_PID" 2>/dev/null || break
    sleep 0.01
done
'''
        script += '''stop_vm TERM
echo "STOP status=$VM_STATUS host_terminated=${VM_HOST_TERMINATED:-0}"
validate_current_log stress.cfg normal 2 0
gate=$?
'''
        if mode == "orphan":
            script += '''for i in {1..100}; do
    [ -f guest.stopped ] && break
    sleep 0.01
done
[ -f guest.stopped ] || { echo "CHILD LEFT RUNNING"; exit 99; }
echo "CHILD TERM OBSERVED"
'''
        script += 'exit "$gate"\n'
        return subprocess.run(["bash", "-c", script], text=True, capture_output=True, timeout=10)

    def test_host_term_accepts_a_fresh_unpaired_tail(self):
        for mode, status in (("live", 143), ("term-zero", 0)):
            with self.subTest(mode=mode):
                result = self.run_gate(mode)
                self.assertIn(result.returncode, (0, 3), result.stdout + result.stderr)
                self.assertIn(f"STOP status={status} host_terminated=1", result.stdout)
                (self.directory / "guest.ready").unlink()

    def test_spontaneous_exit_cannot_use_the_host_cut_exception(self):
        for mode in ("exit0", "exit42"):
            with self.subTest(mode=mode):
                result = self.run_gate(mode)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                (self.directory / "guest.ready").unlink()

    def test_spontaneous_exit_fails_even_after_a_paired_heartbeat(self):
        result = self.run_gate("exit42", tail=False)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_forced_kill_cannot_qualify_the_window(self):
        result = self.run_gate("ignore")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("host_terminated=0", result.stdout)

    def test_dead_supervisor_still_cleans_its_live_child(self):
        result = self.run_gate("orphan")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("CHILD TERM OBSERVED", result.stdout)
        self.assertIn("host_terminated=0", result.stdout)


if __name__ == "__main__":
    unittest.main()
