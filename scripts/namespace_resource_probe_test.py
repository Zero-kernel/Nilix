"""Require both namespace and actual-stack VFS teardown evidence."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gate_inputs
import namespace_resource_probe as probe
from namespace_resource_probe import evidence_passes


NAMESPACE = "\n".join(
    line for kind in range(3) for line in (
        f"KSA-003-RESOURCE PASS kind={kind} boundaries={5 if kind == 0 else 4} attempts=4 rejected_arc=1 admission_pressure=1 last_reference=1 counts=exact heap=exact",
        f"KSA-003-SMP PASS kind={kind} cpu_mask=0xf rounds=8 limit=4 winners=3 rejected=1 counts=exact heap=exact",
    )
) + "\nKSA-003-PROBES PASS types=3 cpus=4 rounds=24 counts=exact heap=exact\n"
VFS = ("KSA-VFS-RESOURCE PASS depth=600 path_bytes=4200 cases=last-cwd,final-namespace "
       "stack_bytes=32768 stack_touched=3072 stack_restored=true tables=exact "
       "heap_vfs=exact heap_ramfs=exact heap_core=exact frames=exact "
       "admission_exhausted_at_entry=true\n")


class ResourceEvidenceTests(unittest.TestCase):
    def test_complete_resource_evidence(self):
        for status in (0, 3):
            self.assertTrue(evidence_passes(NAMESPACE + VFS, status))

    def test_missing_duplicate_and_failed_records(self):
        for serial in (NAMESPACE, VFS, NAMESPACE + VFS * 2,
                       NAMESPACE * 2 + VFS, NAMESPACE + VFS.replace("PASS", "FAIL")):
            self.assertFalse(evidence_passes(serial, 0))

    def test_scope_and_restoration_must_match(self):
        for before, after in (("depth=600", "depth=60"), ("path_bytes=4200", "path_bytes=4096"),
                              ("last-cwd,final-namespace", "last-cwd"), ("stack_restored=true", "stack_restored=false"),
                              ("heap_core=exact", "heap_core=unknown"), ("frames=exact", "frames=leaked"),
                              ("admission_exhausted_at_entry", "admission_exhausted")):
            self.assertFalse(evidence_passes(NAMESPACE + VFS.replace(before, after), 0))

    def test_actual_stack_bounds_and_headroom(self):
        for size, touched in ((8192, 1000), (65537, 1000), (32769, 1000),
                              (32768, 0), (32768, 28673), (32768, 32768)):
            serial = VFS.replace("stack_bytes=32768", f"stack_bytes={size}")
            serial = serial.replace("stack_touched=3072", f"stack_touched={touched}")
            self.assertFalse(evidence_passes(NAMESPACE + serial, 0))

    def test_fatal_and_failed_platform_override_complete_records(self):
        self.assertFalse(evidence_passes(NAMESPACE + VFS + "KERNEL PANIC", 0))
        for status in (1, 2, 124, -9):
            self.assertFalse(evidence_passes(NAMESPACE + VFS, status))

    def test_unexpected_fields_and_prefix_do_not_count(self):
        for serial in ("ignored " + VFS, VFS.rstrip() + " stack_restored=true\n"):
            self.assertFalse(evidence_passes(NAMESPACE + serial, 0))


class CollectorTests(unittest.TestCase):
    def run_fixture(self, change=None, phase=None, schema="current", sidecar="3"):
        with tempfile.TemporaryDirectory(prefix="namespace-collector-") as temporary:
            root = Path(temporary).resolve()
            (root / "kernel").mkdir()
            for name in ("kernel-target/namespace-probe/x86_64-unknown-none/release/kernel",
                         "bootloader-target/x86_64-unknown-uefi/release/bootloader.efi"):
                path = root / name
                path.parent.mkdir(parents=True)
                path.write_bytes(b"synthetic boot image")
            source, manifest = root / "source.txt", root / "inputs.sha256"
            source.write_bytes(b"source")
            manifest.write_text(hashlib.sha256(source.read_bytes()).hexdigest() + "  source.txt\n")
            artifacts = root / "artifacts"
            guests = []

            def mutate(at):
                if at == phase:
                    path = {"source": source, "manifest": manifest}.get(change)
                    if path:
                        path.write_bytes(path.read_bytes() + b"changed")

            def execute(command, **kwargs):
                if command[0] == "cargo":
                    mutate("build")
                    return SimpleNamespace(returncode=0)
                guests.append(command)
                paths = [root / name for name in ("serial", "interrupts", "qemuerr", "timeoutlog", "counts", "status")]
                contents = [NAMESPACE + VFS, "", "", "", "{}", sidecar]
                for path, content in zip(paths, contents):
                    path.write_text(content)
                for name in ("firmware", "qemu"):
                    (root / name).write_bytes(b"synthetic tool")
                gate_inputs.prepare(Path(command[-1]), Path(str(paths[0]) + ".inputs"), root / "firmware", root / "qemu")
                fields = list(zip(("serial", "intlog", "qemuerr", "timeoutlog", "counts", "gate_status"), paths))
                if schema == "old":
                    fields = fields[:4]
                record = "SMP-4CORE-TEST ARTIFACTS: " + " ".join(f"{key}={path}" for key, path in fields) + "\n"
                kwargs["stdout"].write((record * (2 if schema == "duplicate" else 1)).encode())
                mutate("guest")
                return SimpleNamespace(returncode=3)

            argv = ["namespace_resource_probe.py", "--input-manifest", str(manifest),
                    "--revision", "declared-export-base", "--artifacts", str(artifacts)]
            with patch.object(probe, "__file__", str(root / "scripts/namespace_resource_probe.py")), \
                    patch.object(sys, "argv", argv), patch.object(probe.subprocess, "run", side_effect=execute), \
                    contextlib.redirect_stdout(io.StringIO()):
                status = probe.main()
            run, = artifacts.iterdir()
            result = json.loads((run / "result.json").read_text())
            retained = {path.relative_to(run).as_posix() for path in run.rglob("*") if path.is_file()}
            return status, result, guests, retained

    def test_current_shell_artifacts_and_qualified_status_are_retained(self):
        status, result, guests, retained = self.run_fixture()
        self.assertEqual(status, 0)
        self.assertEqual(result["platform_status"], 3)
        self.assertEqual(result["platform_status_sidecar"], "3")
        self.assertEqual(result["source_identity_authority"], "sha256_manifest")
        self.assertEqual(result["export_base_revision_declared"], "declared-export-base")
        self.assertEqual(len(guests), 1)
        self.assertTrue({"counts.json", "platform.status", "inputs.sha256", "guest-inputs/inputs.json",
                         "guest-inputs/esp/kernel.elf", "guest-inputs/esp/EFI/BOOT/BOOTX64.EFI"} <= retained)

    def test_wrong_artifact_schema_or_sidecar_cannot_pass(self):
        for kwargs in ({"schema": "old"}, {"schema": "duplicate"}, {"sidecar": "0"}):
            status, result, _, _ = self.run_fixture(**kwargs)
            self.assertEqual(status, 1)
            self.assertFalse(result["pass"])

    def test_input_changes_fail_and_unstable_build_cannot_launch(self):
        for phase in ("build", "guest"):
            for name in ("source", "manifest"):
                status, result, guests, _ = self.run_fixture(name, phase)
                self.assertEqual(status, 1)
                self.assertFalse(result["pass"])
                self.assertTrue(result["identity_errors_final"])
                if phase == "build":
                    self.assertFalse(guests)


if __name__ == "__main__":
    unittest.main()
