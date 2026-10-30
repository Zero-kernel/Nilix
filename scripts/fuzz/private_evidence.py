#!/usr/bin/env python3
"""Run private campaigns and stream their evidence into an age-encrypted archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
TARGETS = {
    "fuzz_syscall", "fuzz_vfs_path", "fuzz_signal_delivery", "fuzz_memory_ops",
    "fuzz_ipc_message", "fuzz_scheduler", "fuzz_network_packet", "fuzz_cgroup_ops",
    "fuzz_elf_loader", "fuzz_futex_ops", "fuzz_syscall_qemu",
}
AGE_HEADER = b"age-encryption.org/v1\n"
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024


class EvidenceError(Exception):
    """Messages are fixed public diagnostics, never raw fuzzer/tool output."""


def recipients_text(value):
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines or any(not line.startswith("age1") or not line.isalnum() for line in lines):
        raise EvidenceError("Configure FUZZ_EVIDENCE_RECIPIENTS with native age public keys.")
    return "\n".join(lines) + "\n"


def preflight(recipients, age="age"):
    """Validate encryption before launching any campaign that could find a bug."""
    with tempfile.TemporaryDirectory(prefix="nilix-age-preflight-") as directory:
        keys = Path(directory) / "recipients.txt"
        keys.write_text(recipients_text(recipients))
        probe = subprocess.run(
            [age, "--encrypt", "--recipients-file", str(keys)],
            input=b"nilix encryption preflight\n", capture_output=True, timeout=30,
        )
        if probe.returncode or not probe.stdout.startswith(AGE_HEADER):
            raise EvidenceError("The fuzz evidence recipient or age encryption tool is invalid.")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def tool_version(command):
    try:
        result = subprocess.run(command, capture_output=True, timeout=15)
        return (result.stdout + result.stderr)[:8192].decode("utf8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def campaign_command(private, target, seconds, *, seed=None, corpus=None):
    command = ["cargo", "+nightly-2025-12-08", "fuzz", "run", target]
    if corpus is not None:
        command.append(str(corpus.resolve()))
    if target == "fuzz_syscall_qemu":
        command.extend(["--features", "qemu-executor"])
    command.extend([
        "--", f"-max_total_time={seconds}", "-rss_limit_mb=4096",
        "-print_final_stats=1", f"-artifact_prefix={private / 'findings'}/",
    ])
    if target == "fuzz_syscall_qemu":
        # libFuzzer must not preempt the executor's own 900-second guest bound.
        command.append("-timeout=1200")
    if seed is not None:
        command.append(f"-seed={seed}")
    return command


def run_campaign(root, private, target, seconds, *, seed=None, corpus=None):
    if target not in TARGETS or not 1 <= seconds <= 1200:
        raise EvidenceError("Invalid fuzz target or campaign duration.")
    # Exclusive creation prevents stale findings or an earlier run from being
    # attributed to this invocation. Raw evidence never enters a build cache.
    private.mkdir(mode=0o700, parents=True, exist_ok=False)
    (private / "findings").mkdir(mode=0o700)
    command = campaign_command(private, target, seconds, seed=seed, corpus=corpus)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    inputs = {name: digest(root / name) for name in tracked if name and (root / name).is_file()}
    (private / "source.patch").write_bytes(
        subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=root)
    )
    kernel = Path(os.environ.get("NILIX_FUZZ_KERNEL", root / "esp-syz/kernel.elf")).resolve()
    images = [kernel, kernel.parent / "EFI/BOOT/BOOTX64.EFI"] if target == "fuzz_syscall_qemu" else []
    metadata = {
        "schema": "nilix-private-campaign-v1", "revision": revision, "target": target,
        "command": command, "source_sha256": inputs,
        "images_sha256": {str(path): digest(path) for path in images if path.is_file()},
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "tools": {name: tool_version(tool_command) for name, tool_command in {
            "rustc": ["rustc", "+nightly-2025-12-08", "-vV"],
            "cargo-fuzz": ["cargo", "fuzz", "--version"],
            "qemu": ["qemu-system-x86_64", "--version"],
        }.items()},
        "started_at": time.time(), "exit_code": None,
    }
    write_json(private / "run.json", metadata)
    environment = os.environ.copy()
    # Neither dependency build scripts nor the fuzzer need the HMAC secret.
    environment.pop("NILIX_FUZZ_FINGERPRINT_KEY", None)
    environment.pop("NILIX_FUZZ_ARTIFACTS", None)
    environment["NILIX_FUZZ_FAILURE_ARTIFACTS"] = str(private / "guests")
    with (private / "libfuzzer.log").open("wb") as log:
        result = subprocess.run(command, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT)
    code = result.returncode if result.returncode >= 0 else 128 - result.returncode
    metadata.update(exit_code=code, finished_at=time.time())
    write_json(private / "run.json", metadata)
    return code


def archive_entries(private, max_bytes):
    if private.is_symlink() or not private.is_dir():
        raise EvidenceError("The private evidence directory is missing or unsafe.")
    if not (private / "run.json").is_file() or not (private / "libfuzzer.log").is_file():
        raise EvidenceError("The private campaign evidence is incomplete.")
    entries, total = [], 0
    for path in sorted(private.rglob("*")):
        mode = path.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise EvidenceError("Private evidence contains a link or special file; refusing to archive it.")
        if stat.S_ISREG(mode):
            if path.stat().st_nlink != 1:
                raise EvidenceError("Private evidence contains a hard link; refusing to archive it.")
            total += path.stat().st_size
        if total > max_bytes:
            raise EvidenceError("Private evidence exceeds the archive size limit.")
        entries.append(path)
    return entries


def seal(private, output, recipients, age="age", max_bytes=MAX_ARCHIVE_BYTES):
    private, output = private.absolute(), output.absolute()
    if output.is_relative_to(private) or output.exists():
        raise EvidenceError("The encrypted output must be new and outside the private evidence directory.")
    keys_text = recipients_text(recipients)
    entries = archive_entries(private, max_bytes)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Only ciphertext is staged on disk. No plaintext tar file can be picked up
    # by an artifact upload, even when age exits or the tar stream fails.
    with tempfile.TemporaryDirectory(prefix=".nilix-age-", dir=output.parent) as directory:
        staging = Path(directory)
        keys = staging / "recipients.txt"
        keys.write_text(keys_text)
        encrypted = staging / "evidence.age"
        with (staging / "age.stderr").open("wb") as diagnostics:
            process = subprocess.Popen(
                [age, "--encrypt", "--recipients-file", str(keys), "--output", str(encrypted)],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=diagnostics,
            )
            try:
                with process.stdin as stream:
                    with tarfile.open(fileobj=stream, mode="w|gz") as archive:
                        for path in entries:
                            archive.add(path, arcname=str(path.relative_to(private)), recursive=False)
                code = process.wait(timeout=120)
            except BaseException:
                process.kill()
                process.wait()
                raise
        if code or not encrypted.is_file():
            raise EvidenceError("Fuzz evidence encryption failed; no artifact was published.")
        with encrypted.open("rb") as stream:
            if stream.read(len(AGE_HEADER)) != AGE_HEADER:
                raise EvidenceError("The evidence output is not an age ciphertext.")
        encrypted.chmod(0o600)
        os.replace(encrypted, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    check = commands.add_parser("preflight")
    check.add_argument("--age", default="age")
    run = commands.add_parser("run")
    run.add_argument("--private-dir", required=True, type=Path)
    run.add_argument("--target", required=True, choices=sorted(TARGETS))
    run.add_argument("--timeout", required=True, type=int)
    run.add_argument("--seed", type=int)
    run.add_argument("--corpus", type=Path)
    encrypt = commands.add_parser("seal")
    encrypt.add_argument("--private-dir", required=True, type=Path)
    encrypt.add_argument("--output", required=True, type=Path)
    encrypt.add_argument("--age", default="age")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.operation == "preflight":
            preflight(os.environ.get("FUZZ_EVIDENCE_RECIPIENTS", ""), args.age)
        elif args.operation == "run":
            code = run_campaign(ROOT, args.private_dir.resolve(), args.target, args.timeout,
                                seed=args.seed, corpus=args.corpus)
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
                    stream.write(f"exit_code={code}\n")
            # CI validates the captured outcome after evidence has been retained.
            print(f"Private campaign completed; exit_code={code}.")
        else:
            seal(args.private_dir, args.output,
                 os.environ.get("FUZZ_EVIDENCE_RECIPIENTS", ""), args.age)
    except EvidenceError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        # Never expose a raw tool error, path or traceback in the public CI log.
        print("Private evidence operation failed; inspect the private run directory.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
