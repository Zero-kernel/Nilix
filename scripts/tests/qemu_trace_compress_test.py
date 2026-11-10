#!/usr/bin/env python3
"""run_gate_qemu QEMU_TRACE_COMPRESS=zstd: the FIFO, the stream and its failures."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
ZSTD = shutil.which("zstd")
# Records the -D path it was given, then writes the trace as QEMU's log does:
# open, write, close, and reopen to append, unless asked not to open it at all.
FAKE_QEMU = r'''#!/bin/bash
log=''
while [ "$#" -gt 0 ]; do
    case "$1" in -D) log="$2"; shift 2 ;; *) shift ;; esac
done
printf '%s\n' "$log" >"$FAKE_DIR/log.path"
if [ "${FAKE_MODE:-}" != no-log ]; then
    printf 'first open\n' >"$log"
    cat "$FAKE_DIR/trace" >>"$log"
fi
[ "${FAKE_MODE:-}" = exit ] && exit 0
exec sleep 30
'''


@unittest.skipUnless(ZSTD and shutil.which("bash") and shutil.which("timeout"), "needs bash, GNU timeout and zstd")
class TraceCompressionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="qemu-trace-zstd-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fake = self.root / "qemu"
        self.fake.write_text(FAKE_QEMU, newline="\n")
        self.fake.chmod(0o755)
        self.intlog = self.root / "intlog.zst"
        # Large enough to fill the pipe several times over.
        self.trace = "".join(f"{n}: v=ef e=0000 i=0 cpl=0 IP=0008:ffffffff80001000\n" for n in range(20000))
        (self.root / "trace").write_text(self.trace)

    def run_gate(self, *qemu_args: str, compress: str = "zstd", policy: str = "full", mode: str = "exit",
                 window: str = "3") -> subprocess.CompletedProcess:
        script = ('source "$ROOT/scripts/ci/qemu_run.sh"; ser="$WORK/serial"; qemuerr="$WORK/qemu.stderr"; '
                  'timeoutlog="$WORK/timeout.log"; run_gate_qemu "$WINDOW" runtime "$@"; echo "STATUS=$?"')
        environment = dict(os.environ, ROOT=str(ROOT), WORK=str(self.root), WINDOW=window, FAKE_DIR=str(self.root),
                           FAKE_MODE=mode, QEMU_GATE_MODE="window", QEMU_TRACE_COMPRESS=compress,
                           QEMU_TRACE_POLICY=policy, QEMU_TRACE_INTLOG=str(self.intlog),
                           PATH=os.pathsep.join((str(self.bin), os.environ["PATH"])))
        return subprocess.run(["bash", "-c", script, "_", *(qemu_args or (str(self.fake), "-D", str(self.intlog)))],
                              env=environment, capture_output=True, text=True, timeout=60)

    def decompressed(self, path: Path) -> str:
        return subprocess.run([ZSTD, "-dcq", "--", str(path)], check=True, capture_output=True, text=True).stdout

    def assert_fifo_removed(self):
        fifo = Path((self.root / "log.path").read_text().strip())
        self.assertNotEqual(fifo, self.intlog)
        self.assertFalse(fifo.parent.exists())

    def test_trace_is_one_complete_zstd_stream_with_unchanged_content(self):
        result = self.run_gate()
        self.assertIn("STATUS=0", result.stdout, result.stdout + result.stderr)
        self.assertEqual(self.intlog.read_bytes()[:4], b"\x28\xb5\x2f\xfd")
        self.assertEqual(self.decompressed(self.intlog), "first open\n" + self.trace)
        self.assert_fifo_removed()

    def test_window_timeout_status_and_contract_are_unchanged(self):
        result = self.run_gate(mode="window", window="1")
        self.assertIn("STATUS=124", result.stdout, result.stdout + result.stderr)
        self.assertEqual(self.decompressed(self.intlog), "first open\n" + self.trace)
        self.assertEqual((self.root / "timeout.log").read_text().count("sending signal TERM"), 1)
        self.assert_fifo_removed()

    def test_qemu_that_never_opens_its_log_cannot_hang_the_gate(self):
        result = self.run_gate(mode="no-log", window="1")
        self.assertIn("STATUS=124", result.stdout, result.stdout + result.stderr)
        self.assertEqual(self.decompressed(self.intlog), "")
        self.assert_fifo_removed()

    def test_failed_compressor_leaves_no_readable_trace(self):
        failing = self.bin / "zstd"
        failing.write_text('#!/bin/bash\ncat >/dev/null\nexit 1\n', newline="\n")
        failing.chmod(0o755)
        result = self.run_gate()
        self.assertIn("STATUS=0", result.stdout, result.stdout + result.stderr)
        self.assertIn("QEMU-RUN TRACE-COMPRESS FAILED: zstd status 1", result.stdout)
        self.assertFalse(self.intlog.exists())
        self.assertTrue(Path(f"{self.intlog}.partial").exists())

    def test_misconfiguration_is_blocked_before_launch(self):
        cases = (
            ({"compress": "gzip"}, "QEMU_TRACE_COMPRESS must be none or zstd"),
            ({"policy": "phased"}, "needs the full trace policy"),
            ({}, 'exactly one -D "$QEMU_TRACE_INTLOG"'),
        )
        for options, message in cases:
            with self.subTest(message=message):
                arguments = () if options else (str(self.fake), "-D", str(self.root / "elsewhere"))
                result = self.run_gate(*arguments, **options)
                self.assertIn("STATUS=2", result.stdout, result.stdout + result.stderr)
                self.assertIn(message, result.stdout)
                self.assertFalse((self.root / "log.path").exists())
        duplicate = self.run_gate(str(self.fake), "-D", str(self.intlog), "-D", str(self.intlog))
        self.assertIn("STATUS=2", duplicate.stdout)
        self.assertFalse((self.root / "log.path").exists())

    def test_another_log_destination_cannot_bypass_the_compressed_trace(self):
        other = self.root / "other.log"
        for destinations in ((str(self.intlog), str(other)), (str(other), str(self.intlog))):
            with self.subTest(destinations=destinations):
                result = self.run_gate(str(self.fake), "-D", destinations[0], "-D", destinations[1])
                self.assertIn("STATUS=2", result.stdout, result.stdout + result.stderr)
                self.assertFalse((self.root / "log.path").exists())
                self.assertFalse(other.exists())

    def test_uncompressed_runs_pass_the_log_path_through(self):
        result = self.run_gate(compress="none")
        self.assertIn("STATUS=0", result.stdout, result.stdout + result.stderr)
        self.assertEqual(self.intlog.read_text(), "first open\n" + self.trace)
        self.assertEqual(Path((self.root / "log.path").read_text().strip()), self.intlog)


if __name__ == "__main__":
    unittest.main()
