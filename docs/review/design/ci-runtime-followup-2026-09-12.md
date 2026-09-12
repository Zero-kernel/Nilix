# CI runtime follow-up — transient mount I/O and mitigation event order

**Date:** 2026-09-12
**Status:** IMPLEMENTED (verification pending rerun)
**Scope:** the two failures observed in CI run 34699324708 on `83a8bc2`; no
change to the Preview release gate or to unsupported capability claims.

## Evidence and root causes

The 4-CPU mitigation guest emitted `MITIGATION-WORKER RETRY phase=exec` after
fork completion and before the replacement image could emit `BEGIN phase=exec`.
The validator only accepted retries between BEGIN and PASS, so a valid bounded
ENOMEM recovery was rejected as “outside its exec phase”.

The qemu-fuzz `uname` seed booted with `/mnt` left on the ramfs fallback because
the first ext3 superblock read returned a transient block I/O error immediately
after virtio publication. The guest then correctly reported `input_open:-2` for
the absent `/mnt/test/syz-program.bin`. A later independent seed mounted the
image and completed successfully.

## Changes and invariants

- `scripts/gates/qemu/mitigation_check.py` accepts a retry only after the same
  worker's fork PASS and either before exec BEGIN (the production `execve`
  retry path) or between exec BEGIN and PASS (fixture compatibility). Identity,
  contiguous attempts, errno 12, ordering and final wait checks remain strict.
- `scripts/tests/mitigation_check_test.py` covers the production retry position
  as well as the existing monitor fixture position.
- `kernel/vfs/ext2.rs` retries the first superblock read at most three times for
  `Busy`, `NoMem` or generic `Io`. Short reads, invalid requests, media errors,
  unsupported devices and a final exhausted retry still return `FsError::Io`.
  No journal or filesystem publication occurs until this read succeeds.

## Verification

`mitigation_check_test.py` passes all 48 tests after the validator change and
the combined focused run passes 56 tests. The Rust hosted fixture also covers
`Io → NoMem → success`, persistent `Busy` (three calls), short reads and a
non-transient `Invalid` error. Shell syntax, Python compilation, `cargo check`
for the no-std kernel target and Rust formatting checks pass. The Windows host
cannot run the vfs hosted test because the GNU target standard library is not
installed; CI remains the required target test. The next CI run must show the
mitigation workload with a pre-exec retry and the qemu-fuzz two-seed mount/input
contract before this record becomes VERIFIED.
