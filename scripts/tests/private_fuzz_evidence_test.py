"""Exercise real age round trips and fail-closed evidence publication."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts.fuzz import private_evidence as evidence


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("age") or not shutil.which("age-keygen"):
            raise RuntimeError("private fuzz evidence tests require age and age-keygen")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nilix-private-evidence-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.identity = self.root / "test-identity.txt"
        subprocess.run(["age-keygen", "-o", str(self.identity)], check=True, capture_output=True)
        self.recipient = subprocess.check_output(
            ["age-keygen", "-y", str(self.identity)], text=True,
        ).strip()
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        (self.private / "run.json").write_text('{"revision":"fixture","exit_code":1}\n')
        (self.private / "libfuzzer.log").write_text("PRIVATE-TRACE-CANARY\n")
        (self.private / "findings").mkdir()
        (self.private / "findings/crash-one").write_bytes(b"PRIVATE-INPUT-CANARY")
        (self.private / "candidate-index.json").write_text(
            '{"candidates":[{"candidate_id":"opaque-fixture","input":"findings/crash-one"}]}\n'
        )
        self.output = self.root / "public/campaign.tar.gz.age"

    def test_age_round_trip_retains_raw_input_and_its_private_index(self):
        evidence.preflight(self.recipient)
        evidence.seal(self.private, self.output, self.recipient)
        ciphertext = self.output.read_bytes()
        self.assertTrue(ciphertext.startswith(evidence.AGE_HEADER))
        self.assertNotIn(b"PRIVATE-INPUT-CANARY", ciphertext)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        plaintext = subprocess.check_output(["age", "-d", "-i", str(self.identity), str(self.output)])
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as archive:
            self.assertEqual(archive.extractfile("findings/crash-one").read(), b"PRIVATE-INPUT-CANARY")
            index = json.load(archive.extractfile("candidate-index.json"))
            self.assertEqual(index["candidates"][0]["input"], "findings/crash-one")
            self.assertEqual(archive.extractfile("libfuzzer.log").read(), b"PRIVATE-TRACE-CANARY\n")
        self.assertEqual([path.name for path in self.output.parent.iterdir()], [self.output.name])

    def test_tampered_ciphertext_fails_authentication(self):
        evidence.seal(self.private, self.output, self.recipient)
        data = bytearray(self.output.read_bytes())
        data[-1] ^= 1
        self.output.write_bytes(data)
        result = subprocess.run(["age", "-d", "-i", str(self.identity), str(self.output)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_missing_private_or_invalid_recipient_never_passes_preflight(self):
        for value in ("", "AGE-SECRET-KEY-1PRIVATE", "age1invalid"):
            with self.subTest(value=value), self.assertRaises(evidence.EvidenceError):
                evidence.preflight(value)
        self.assertFalse(self.output.exists())

    def test_symlink_and_hardlink_cannot_import_unrelated_files(self):
        for kind in ("symbolic", "hard"):
            path = self.private / "unrelated"
            if kind == "symbolic":
                path.symlink_to(self.identity)
            else:
                os.link(self.identity, path)
            with self.subTest(kind=kind), self.assertRaises(evidence.EvidenceError):
                evidence.seal(self.private, self.output, self.recipient)
            path.unlink()
        self.assertFalse(self.output.exists())

    def test_size_limit_and_incomplete_run_cannot_publish_an_archive(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.seal(self.private, self.output, self.recipient, max_bytes=1)
        (self.private / "run.json").unlink()
        with self.assertRaises(evidence.EvidenceError):
            evidence.seal(self.private, self.output, self.recipient)
        self.assertFalse(self.output.exists())

    def test_encryption_error_and_non_ciphertext_output_are_not_published(self):
        fake = self.root / "broken-age"
        for code in (1, 0):
            fake.write_text(
                "#!/usr/bin/env python3\nimport pathlib, sys\n"
                "pathlib.Path(sys.argv[sys.argv.index('--output')+1]).write_bytes(b'PRIVATE-INPUT-CANARY')\n"
                "sys.stdin.buffer.read()\n"
                f"raise SystemExit({code})\n"
            )
            fake.chmod(0o700)
            with self.subTest(code=code), self.assertRaises(evidence.EvidenceError):
                evidence.seal(self.private, self.output, self.recipient, age=str(fake))
            self.assertFalse(self.output.exists())
            self.assertEqual(list(self.output.parent.iterdir()), [])

    def test_existing_archive_and_output_inside_private_tree_are_refused(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.seal(self.private, self.private / "output.age", self.recipient)
        evidence.seal(self.private, self.output, self.recipient)
        original = self.output.read_bytes()
        with self.assertRaises(evidence.EvidenceError):
            evidence.seal(self.private, self.output, self.recipient)
        self.assertEqual(self.output.read_bytes(), original)

    def test_campaign_keeps_nonzero_exit_and_raw_diagnostics_out_of_public_stdout(self):
        project = self.root / "source"
        project.mkdir()
        (project / "input.rs").write_text("fixture\n")
        subprocess.run(["git", "init", "-q", str(project)], check=True, capture_output=True)
        subprocess.run(["git", "add", "input.rs"], cwd=project, check=True)
        subprocess.run(
            ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
             "commit", "-qm", "fixture"], cwd=project, check=True,
        )
        tools = self.root / "tools"
        tools.mkdir()
        cargo = tools / "cargo"
        cargo.write_text(
            "#!/usr/bin/env python3\nimport os, pathlib, sys\n"
            "if '--version' in sys.argv: print('fixture'); raise SystemExit(0)\n"
            "assert 'NILIX_FUZZ_FINGERPRINT_KEY' not in os.environ\n"
            "prefix = next(x.split('=',1)[1] for x in sys.argv if x.startswith('-artifact_prefix='))\n"
            "pathlib.Path(prefix, 'crash-private').write_bytes(b'PRIVATE-REPRO')\n"
            "print('PRIVATE-STACK-TRACE', file=sys.stderr)\n"
            "raise SystemExit(77)\n"
        )
        cargo.chmod(0o700)
        private = self.root / "campaign"
        output = io.StringIO()
        with patch.dict(os.environ, {
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "NILIX_FUZZ_FINGERPRINT_KEY": "PRIVATE-SECRET-CANARY",
        }), contextlib.redirect_stdout(output):
            code = evidence.run_campaign(project, private, "fuzz_syscall", 1)
        self.assertEqual(code, 77)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("PRIVATE-STACK-TRACE", (private / "libfuzzer.log").read_text())
        self.assertEqual((private / "findings/crash-private").read_bytes(), b"PRIVATE-REPRO")
        metadata = json.loads((private / "run.json").read_text())
        self.assertEqual(metadata["exit_code"], 77)
        self.assertEqual(metadata["source_sha256"]["input.rs"], evidence.digest(project / "input.rs"))
        self.assertNotIn("PRIVATE-SECRET-CANARY", (private / "run.json").read_text())
        with self.assertRaises(FileExistsError):
            evidence.run_campaign(project, private, "fuzz_syscall", 1)

    def test_qemu_campaign_keeps_libfuzzer_timeout_above_guest_bound(self):
        qemu = evidence.campaign_command(self.private, "fuzz_syscall_qemu", 60)
        self.assertIn("--features", qemu)
        self.assertIn("qemu-executor", qemu)
        self.assertIn("-timeout=1200", qemu)
        host = evidence.campaign_command(self.private, "fuzz_syscall", 60)
        self.assertNotIn("--features", host)
        self.assertNotIn("-timeout=1200", host)


if __name__ == "__main__":
    unittest.main()
