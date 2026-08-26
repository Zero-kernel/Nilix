# Syzkaller-Style Fuzz Crash Triage — 2026-08-16 (run 31930556648)

**Run:** `Syzkaller-Style Fuzzing` workflow_dispatch, commit `da779c4`, all 16 steps green.
**Crashes observed:** 11 `crash-*.bin` files (artifact `syzkaller-crashes-3`, 1962 B).
**Verdict: all 11 are SPURIOUS.** They are boot-time kernel integration-test panics,
not bugs found by the fuzz program. The fuzz program never executed in any crash run.

## Evidence

Reproduced with a faithful replay harness (`userspace/nilix-syz-fuzzer/src/bin/replay.rs`,
added for this triage) that re-runs a saved `SyscallProgram` through the real
`QemuExecutor` and prints the classification + full serial log + QEMU stderr.

- All 11 `crash-*.bin` decode to trivial combinations of two pure-noarg syscalls:
  `getpid` (39) and `getppid` (110). Four of them are byte-identical to the single
  corpus seed `prog-0.bin` (`getpid; getppid`) — i.e. the *same* program is recorded
  as both a corpus success and a crash.
- 8/8 replay runs of `getpid; getppid` crashed with `classification=kernel_panic`.
- Across those 8 crash runs there are **0** `NILIX_SYZ_V2_BEGIN` markers and **0**
  `fuzz_runner`/`syz-program` references in the serial log. The guest executor never
  started. The kernel panicked during boot self-tests, before the program ran.

## Two boot-time panic sites (both in `kernel/src/integration_test.rs`)

The KCOV kernel boots under the **Balanced** profile (`debug_interfaces: true`),
so `main.rs:1327` runs `integration_test::run_all_tests()` unconditionally. Two of
those boot self-tests panic under the fuzzer's environment:

1. **`integration_test.rs:422`** — `open production ext3 allocation probe: NotFound`
   ```rust
   // line 421-422
   let alloc_file_ops = vfs::open("/mnt/test/alloc.bin", alloc_flags, 0)
       .expect("open production ext3 allocation probe");
   ```
   The boot self-test `.expect()`s `/mnt/test/alloc.bin` on the mounted ext fs. The
   syz-fuzzer's `Ext3Transport::prepare` builds a fresh `mke2fs` ext3 image containing
   only `/test/syz-program.bin` — no `/test/alloc.bin`. When the disk mounts at `/mnt`
   as ext2/ext3, the probe panics. (The production `make disk-ext2.img` /
   `ensure-ext3-image` fixture *does* create `/test/alloc.bin` via `debugfs`.)

2. **`integration_test.rs:576`** — `D1-RES: boot unledgered footprint N B exceeds budget M B`
   ```rust
   // line 576-581
   assert!(
       baseline_unledgered <= mm::BOOT_UNLEDGERED_FOOTPRINT_MAX_BYTES,
       "D1-RES: boot unledgered footprint {} B exceeds budget {} B", ...
   );
   ```
   The boot heap-budget invariant. KASLR (enabled in the KCOV kernel: text+heap+
   kstack+user randomization) and the syz disk's altered boot allocation pattern
   push the unledgered footprint over a budget calibrated for the production
   fixture image, so the assert fires on a KASLR-dependent subset of boots.

## Which panic fires is KASLR-nondeterministic

In 8 replay runs: `:576` fired on runs 1/2/5/8, `:422` on runs 3/4/6/7. The first
panic halts the boot, so whichever self-test trips first wins. `:576` is
KASLR-sensitive; on boots where it passes, execution reaches `:422` and panics
there. A rare boot where `:576` passes **and** `/mnt` is not mounted (virtio-blk
detection race) skips both probes → the program runs → a corpus success. This
matches the 1-corpus-vs-11-crashes split and the byte-identical-program duplication.

## Root cause

**Fuzzer harness / test-fixture mismatch.** The syz-fuzzer boots the kernel under
the Balanced profile (full boot integration-test suite, strict fixture + memory
assumptions) using a minimal fresh ext3 disk that violates those assumptions:
missing `/test/alloc.bin` (→ `:422`) and a KASLR-varied boot footprint that exceeds
the fixture-calibrated D1-RES budget (→ `:576`). The fuzz program is irrelevant —
it never runs.

## Recommended fixes (for a follow-up task — none applied here)

1. **Fuzzer side (minimal, fixes `:422` only):** `Ext3Transport::prepare` should
   also create `/test/alloc.bin` (empty regular file) on the fresh ext3 image,
   mirroring `ensure-ext3-image`.
2. **Kernel side (`:422` robustness):** replace the `.expect()` with a graceful
   skip (as the non-ext2 `/mnt` branch already does) — a missing probe file must
   not kernel-panic.
3. **Build/profile (cleanest for fuzzing, fixes both):** boot the KCOV/fuzz
   kernel under the Secure profile (`debug_interfaces_enabled = false`) so
   `main.rs:1327` skips the boot self-test suite and boots straight to the fuzz
   program. Faster, deterministic, no fixture dependency. Caveat: shifts
   coverage (kptr/audit fail-closed) — acceptable and arguably more correct.
4. **`:576` specifically:** do not blanket-relax. Investigate whether
   `BOOT_UNLEDGERED_FOOTPRINT_MAX_BYTES` is calibrated too tightly to one
   fixture, or whether the syz-disk mount genuinely leaks unledgered page-cache
   bytes (a real accounting gap). Resolve on evidence.

## Artifacts

- Crash programs: `.syz-triage/unpacked/crashes/crash-*.bin` (local + devbox)
- Replay harness: `userspace/nilix-syz-fuzzer/src/bin/replay.rs` (dual-written,
  md5 `96e69561…`; not committed — triage tool)
- Replay logs: `/tmp/replay1.out`, `/tmp/replay8.out` on the devbox
