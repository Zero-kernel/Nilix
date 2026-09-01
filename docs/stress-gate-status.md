# Monthly Stress Gate (stress-v2) — Honest Status

**Date:** 2026-09-01
**Scope:** `.github/workflows/monthly-stress-test.yml`, `scripts/stress_test.sh`,
`scripts/stress_protocol.py`, `userspace/stress_runner.c`, `Makefile` stress targets
**Verdict:** the gate has **never passed end-to-end**. Three real defects are now fixed and
verified; a fully green 6-profile run is still blocked on kernel-side gaps.

This document exists because the gate's green history is misleading and because the
scale of the remaining work is larger than a first reading of the code suggests.
It is written to be picked up cold by the next session.

---

## 1. Executive summary

| Item | State |
|------|-------|
| `make build-stress` | **FIXED** — was exit 2, now exit 0 |
| `stress_test.sh` `set -u` crash | **FIXED** — verified |
| ESP corruption via `fat:rw:` | **FIXED** — verified |
| `userspace/stress_runner.c` (V2 guest) | **WRITTEN** — builds clean; config/header proven on real hardware |
| A green `memory` profile run | **BLOCKED** — `mmap` returns ENOMEM in-guest |
| A green `smp` profile run | **BLOCKED** — no shared memory in the kernel |
| A green `block` profile run | **BLOCKED** — no `fsync` in the kernel |
| `cpu` / `process` / `combined` | **UNVERIFIED** — never reached a full round |

Nothing in this work is committed. The manual-commit rule was observed.

---

## 2. How the gate broke

Two commits on **2026-08-04**, the same day:

- **`e7e2cff`** *"test(stress): add comprehensive stress test infrastructure"* — added
  `scripts/stress_protocol.py` (1593 lines), rewrote `scripts/stress_test.sh` (928 lines),
  and added **two** guests: `userspace/stress_runner.c` (635 lines) and
  `userspace/stress_runner_advanced.c` (545 lines).
- **`4357994`** *"refactor(userspace): enhance syz executor and remove old stress runner"* —
  **deleted** `userspace/stress_runner.c` and did **not** touch the `Makefile`.

`Makefile:232` still compiled the deleted file, so the CI build step died with:

```
cc1: fatal error: userspace/stress_runner.c: No such file or directory
make: *** [Makefile:231: build-stress-runner] Error 1
```

That is the visible failure in run
[33369694867](https://github.com/Zero-kernel/Nilix/actions/runs/33369694867).

### 2.1 The deeper problem: no guest ever spoke the harness protocol

The harness added in `e7e2cff` speaks a **V2** contract. Neither guest in that same commit
did:

| Producer | Protocol | Matches harness? |
|----------|----------|------------------|
| `scripts/stress_protocol.py` (consumer) | `NILIX_STRESS_V2_*`, config magic `NILSTR2` | — |
| deleted `stress_runner.c` | `NILIX_STRESS_BEGIN version=1` (**V1**) | no |
| `stress_runner_advanced.c` | `NILIX_STRESS_ADVANCED_*`, self-contained, no config, no profiles | no |

Before this session, a repo-wide search for a `NILIX_STRESS_V2_*` **producer** returned
nothing — only the three harness/consumer files referenced those markers. So restoring the
deleted V1 file would have converted a build failure into a validation failure, not a pass:
`validate_header` (`scripts/stress_protocol.py:1054`) hard-requires `BEGIN` + `READY` as the
first two V2 markers with matching run id, `config_sha256`, `vcpus` and `workers`.

### 2.2 The green history is an artifact

`monthly-stress-test.yml` runs on cron `0 2 28-31 * *` and gates the real job behind a
last-day-of-month check. Every "success" in the run list is a **6–8 second skip**:

| Run | Date | Duration | What actually happened |
|-----|------|----------|------------------------|
| 33299463754, 33242875797, 33175259256 | Aug 28–30 | 7s | `check-last-day=false` → job skipped |
| 30514583565, 30423526126, 30329806192 | Jul 28–30 | 6–8s | skipped |
| 30606484394 | Jul 31 | 2m6s | **failed** (pre-`e7e2cff` harness) |
| 33369694867 | Aug 31 | 1m9s | **failed** (build step) |

Only two runs ever executed the job. Both failed. The V2 harness has had exactly one real
execution in its life.

---

## 3. Fixes landed (verified)

### 3.1 `make build-stress` — exit 2 → exit 0

A new `userspace/stress_runner.c` was written at the path the `Makefile` already expected,
so no `Makefile` edit was needed. Verified on the devbox: `make build-stress` → **exit 0**,
`Stress kernel SHA-256: 0fcac1b0f3452da6adc612f0f823923d5b232fa8f190f1a68fa759d750ab8c53`.

### 3.2 `scripts/stress_test.sh` — `set -u` crash in `wait_soak_window`

```bash
local duration="$1" deadline=$((SECONDS + duration))    # BUG
```

Bash expands **every word** of a `local` invocation before assigning any of them, so the
arithmetic read `duration` while it was still unset. Under the script's
`set -uo pipefail` (line 9) that aborted the run:

```
scripts/stress_test.sh: line 384: duration: unbound variable
```

Split into two statements. This was the **only** instance of the pattern in the file.
`scripts/stress_test_test.sh` passes.

### 3.3 `scripts/stress_test.sh` — ESP corruption via `fat:rw:`

`start_vm` pointed QEMU's writable virtual FAT at the **source** ESP directory:

```bash
-drive "format=raw,file=fat:rw:$ESP"
```

OVMF stores `NvVars` on that volume, so the firmware wrote back into the tree and mutated
`BOOTX64.EFI` in place. Demonstrated directly — install a known-good binary, boot once,
re-hash:

```
BEFORE: 2d3c7aa5a392ce60ef62c3e0134727a2  esp-stress/EFI/BOOT/BOOTX64.EFI
AFTER:  27f72ac7e94eba987c77f3eda5eb26f6  esp-stress/EFI/BOOT/BOOTX64.EFI
```

Consequence: the **first** boot after a build succeeds, and every later boot dies in
firmware with `BdsDxe: ... Load Error`, then falls through to PXE. That is why the harness
appeared to have a broken bootloader.

`start_vm` now copies the ESP to a per-boot throwaway directory (mirroring the harness's
already-disposable per-attempt disk image) and drops any stale `NvVars`. Verified: after a
full run the source ESP hash is unchanged at `2d3c7aa5…`, and the guest boots reliably on
repeated attempts.

> **`Makefile:339` has the same `fat:rw:$(QEMU_ESP)` pattern** and was left untouched. It is
> very likely the same latent trap for `make run` / `make run-stress`. Not fixed here
> because it was outside the failing gate; flagged as a follow-up.

### 3.4 Unrelated devbox repair

`disk-ext2.img` on the devbox was corrupt (`UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY`,
breaking `make ensure-ext3-image`). Moved to `/tmp/disk-ext2.img.corrupt.bak` and
regenerated. Local-environment only; no repo change.

---

## 4. The V2 contract (so it need not be re-derived)

Extracted from `scripts/stress_protocol.py`. Recording it here because it is spread across
~700 lines of validator and is the expensive part to reconstruct.

**Config record** — 256 bytes, injected by `debugfs` into the ext3 image at `/test/stress.cfg`,
visible in-guest as `/mnt/test/stress.cfg`. Layout `<8sHHIIIQQIIIIQQQQIIIIII104s32s8s`:

| Offset | Field | Offset | Field |
|--------|-------|--------|-------|
| 0 | magic `NILSTR2\0` | 56 | `memory_limit_delta` (u64) |
| 8 | version = 2 (u16) | 64 | `memory_chunk_bytes` (u64) |
| 10 | header_bytes = 40 (u16) | 72 | `cpu_iterations` (u64) |
| 12 | total_bytes = 256 (u32) | 80 | `contention_iterations` (u64) |
| 16 | profile 1..6 (u32) | 88 | `churn_fanout` (u32) |
| 20 | flags (u32) | 92 | `churn_waves` (u32) |
| 24 | `run_id` (u64) | 96 | `io_block_bytes` (u32) |
| 32 | `seed` (u64) | 100 | `io_slots` (u32) |
| 40 | `vcpus` (u32) | 104 | `io_writes_per_round` (u32) |
| 44 | `workers` (u32) | 108 | `reclaim_percent` (u32) |
| 48 | `heartbeat_max_ms` (u32) | 112 | reserved, 104 bytes, **must be zero** |
| 52 | `rounds_per_heartbeat` (u32) | 216 | SHA-256 of bytes `[0,216)` |
| | | 248 | end magic `NILEND2\0` |

Profiles: `1=memory 2=cpu 3=smp 4=process 5=block 6=combined`.
Flags: `1=require_oom 2=pin_workers 4=block_crash_auto 8=host_terminated 16=require_qmp_vcpus`.

**Marker order (normal mode) is load-bearing:**

```
BEGIN -> READY -> ROUND(1) -> PASS -> HEARTBEAT(1) -> ROUND(2) -> HEARTBEAT(2) -> ...
```

- `PASS` sits strictly between round 1 and heartbeat 1 and must carry counters
  **byte-identical** to heartbeat 1.
- `HEARTBEAT(N).cycles == N * rounds_per_heartbeat`; `cycles` and `ops` must **strictly
  increase**; checksum echoes round N's.
- Checksums are 16 lowercase hex digits and **may not be zero**.
- Most numeric fields use `POS_UINT_RE` = `[1-9][0-9]{0,19}`, i.e. they must be **non-zero**.
  This notably means `combined` must report all five of `memory_ops`/`cpu_ops`/`smp_ops`/
  `process_ops`/`io_ops` as >= 1.
- `validate_runtime_summary` additionally requires a kernel
  `Test Summary: N passed, M deferred..., K failed` line with `K == 0`.

Per-profile arithmetic is asserted exactly (`validate_profile_marker`), e.g. `memory`
requires `limit == baseline + delta`, `recovered == baseline` **exactly**, `peak >=
limit - chunk`, and `oom_events >= 1`; `process` requires `spawned == reaped ==
fanout * waves`, `limit_hits == waves`, `recovered_forks == waves`.

**Useful kernel ABI for the guest** (`kernel/kernel_core/syscall.rs`): cgroup syscalls
`500` create / `502` attach / `503` set_limit / `516` get_stats2; controllers
`CPU=1 MEMORY=2 PIDS=4`; limits `MEMORY_MAX=3 PIDS_MAX=5`. `CgroupStatsBuf` is `#[repr(C)]`,
136 bytes (v1 prefix 104), with `memory_current@32`, `memory_events_max@48`,
`pids_events_max@56` — which is what supplies `oom_events` and `limit_hits` without needing
`/sys/fs/cgroup` mounted.

---

## 5. What the new guest does, and what is proven

`userspace/stress_runner.c` (~1150 lines) implements the config parser (including its own
SHA-256), the marker/sequencing state machine, and the `memory`, `cpu`, `smp`, `process`
and `combined` phases. `block` fail-closes with `stage=fsync_unsupported`.

**Proven on real Nilix** (booted stress kernel, harness-injected config):

```
NILIX_STRESS_V2_BEGIN run=34c7e5915b9134b5 profile=memory \
  config_sha256=c432153bcb7139d68351e2725608b9a37397e83ed572422204cfa9f3ff677c07 vcpus=1 workers=1
NILIX_STRESS_V2_READY run=34c7e5915b9134b5 profile=memory mode=normal
```

The digest matched the host's `make-config` output exactly, which proves the 216-byte prefix
boundary and the independent SHA-256 are both correct, and that the guest really read its
config off ext3. `stress_protocol.py validate-log` accepts this header. Builds clean under
`-std=c11 -static -O2 -Wall -Wextra -Werror`.

A compile-time `STRESS_GUEST_ROOT` override was added so the parser and marker formatting
can be exercised on a plain Linux host; the shipped guest always uses `/mnt/test`.

**Not proven:** no profile has completed a single full round, so no `ROUND`/`PASS`/
`HEARTBEAT` marker has ever been emitted or validated. The per-profile arithmetic in this
guest is written to the contract but is **untested**.

---

## 6. Kernel gaps that block a green run

These were found by *running* the guest, not by reading the syscall table.

| # | Gap | Evidence | Blocks |
|---|-----|----------|--------|
| K1 | `sys_cgroup_attach` returns `EIO` for the initial Ring-3 process. `migrate_task_locked` requires the task to already be in its current cgroup's set; nothing inserts PID 1 into root's. | `cgroup.rs:3189` → `TaskNotAttached` → `syscall.rs:19944` | worked around |
| K2 | `sys_mmap` **ignores its `flags` argument** (`_flags`), so `MAP_SHARED` is silently private. No cross-process shared memory exists. | `syscall.rs:13576` | **smp** (needs a shared contended counter) |
| K3 | `mmap` returns `ENOMEM` in-guest even for a 4 KiB request, reproducibly. Narrowed to the cgroup charge or frame allocation; **not isolated**. | `stage=report_mmap errno=12`; candidates `syscall.rs:13784`, `syscall.rs:13926` | **memory** |
| K4 | No `fsync`/`fdatasync`. Slots 74/75/162/277 unbound; `FileSystem::sync` is a default no-op that ext2 never overrides. | `vfs/traits.rs:130` | **block** |

K1 is worked around in userspace: every cgroup-resident phase runs in a forked worker,
because `fork` **does** attach children to the parent's cgroup (`fork.rs:314`).

K4 is the smallest of the four: `flush_device()` (`ext2.rs:9104`) already reaches
`dev.flush()` down to `virtio/blk.rs:1853`, so wiring `sys_fsync` means overriding `sync()`
in `Ext2Fs` and dispatching fd → inode → filesystem. It is not a from-scratch journaling
project.

K2 is the most structural. Without shared anonymous mappings (or working threads), the
`smp` profile's "protected counter with real lock contention, `spins > 0`" is
**unimplementable as specified**. Child→parent reporting can move to pipes, but the
contended counter cannot.

---

## 7. Corrections — things stated wrongly during this work

Recorded deliberately, because both would misdirect a reader of the transcript.

1. **"The freshly-built bootloader is broken."** Wrong. The md5 identified as a bad build
   (`27f72ac7…`) was simply the post-boot **mutated** state caused by the `fat:rw:`
   write-back in §3.3. There is no bootloader regression. The isolation experiment that
   produced the wrong conclusion (swapping in an older `BOOTX64.EFI` and seeing it boot) was
   confounded: the older binary worked because it was *freshly copied*, not because it was
   older.

2. **"5 of 6 profiles are implementable today."** Overstated. That audit checked syscall
   **presence** in the dispatch table and concluded feasibility. Presence is not semantics:
   `sys_mmap` is listed and dispatches, but ignores `MAP_SHARED` (K2); `sys_cgroup_attach` is
   listed and dispatches, but cannot work for PID 1 (K1). Both gaps only surfaced by
   executing the guest. Future feasibility claims for this gate should be backed by a
   booted round, not a table lookup.

An earlier reading of the run history also has to be stated carefully: the workflow is
**monthly** (cron `0 2 28-31 * *` plus a last-day gate), not weekly.

---

## 8. Verification method

Per project rules all builds/tests ran on the remote Linux devbox; the Windows tree is a
mirror. Exit codes were captured explicitly (`echo $? > file`) rather than inferred from a
piped tail, and every file written was md5-compared across both environments.

Long commands were run under `nohup` on the devbox because the SSH helper caps at 30s.

**Uncommitted at time of writing:**

| Path | Change |
|------|--------|
| `rust-toolchain.toml` | added `rust-analyzer` component (unrelated fix — VS Code) |
| `userspace/stress_runner.c` | new V2 guest |
| `scripts/stress_test.sh` | §3.2 + §3.3 fixes |
| `docs/stress-gate-status.md` | this document |

---

## 9. Open decisions for the next session

1. **K3 first.** Isolate the in-guest `mmap` ENOMEM — it gates the `memory` profile and is
   plausibly small. Cheapest probe: have the guest report its own `CgroupStatsBuf` in the
   FAIL `detail` field to distinguish the cgroup charge from frame exhaustion.
2. **Decide K2's disposition.** Either implement shared anonymous mappings (honour
   `MAP_SHARED`), or accept that `smp` cannot meet its contract and amend the harness rather
   than let the guest fake a contended counter.
3. **K4** as previously agreed: `sys_fsync`/`sys_fdatasync` + `Ext2Fs::sync`, then flip the
   `block` profile on.
4. **K1** — decide whether to keep the userspace fork workaround or fix root-cgroup
   membership for the init task in the kernel.
5. **`Makefile:339`** — apply the §3.3 ESP-copy fix to `make run` / `run-stress` too.
6. **Interim CI policy.** Until at least one profile is green, decide whether the monthly
   job should keep failing loudly (and commenting on commits) or be gated to
   `workflow_dispatch`. It currently fails every month-end and posts a commit comment.

Do **not** mark this gate green, or advance any release/streak counter on its behalf, until
a profile has produced a validated `PASS` + `HEARTBEAT` sequence from a booted run.
