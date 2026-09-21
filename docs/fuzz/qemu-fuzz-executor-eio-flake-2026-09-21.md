# QEMU fuzz executor `EIO` flake — 2026-09-21

**Date:** 2026-09-21
**Status:** fix implemented and validated on the devbox (remote tree `4c19b99`, QEMU/TCG smoke green); the affected CI job also reruns green on the pre-fix revision
**Independent review:** PENDING - a delegated read-only reviewer is still running, so no independent verdict is claimed and sections 4-5 are self-validation plus self-review only
**Code commit:** `4c19b99` - `fix(block): run the synchronous virtio-blk waits again`, on top of `bb828d8` (attribution), `3b709d4` (quarantine short-circuit) and `49d0db3` (no-progress budget)
**Scope:** `kernel/block` virtio-blk synchronous request path; no filesystem semantics change

---

## 1. Symptom

`QEMU / qemu-fuzz` (run `35561080728`, job `106213948271`) failed while every other
gate in the job passed:

| gate | result |
|---|---|
| adapter / kcov-host / kcov-guest / executor-build | PASS |
| executor-guest (attempt 1) | FAIL — `QEMU-FUZZ-GATE FAIL: adapter exited 1` |
| executor-guest (retry 1) | FAIL — `executor-guest (retry 1)` |

The two retained executor attempts failed in *different* stages of the guest
result publication path, with no kernel panic and a clean process exit:

```text
attempt 1 (gate-i6dmsh7g): NILIX_SYZ_V2_FAIL ... stage=result_open  code=-5   (EIO)
attempt 2 (gate-fa4c3ss4): NILIX_SYZ_V2_FAIL ... stage=result_write code=-5   (EIO)
```

Rerunning the same revision/job (`gh run rerun --failed`) passed, so the failure is
environment/timing dependent, not a deterministic regression.

## 2. Identity and disk forensics (retained artifacts)

* `esp-syz/kernel.elf` was byte-identical to the previous green run
  (`f08f1cd538ecc30a9ad9985474fca9bcb47fa2de375bfc36c1f6f999ffc9430a`, jobs
  `106204562568` and `106213948271`), so the guest code is unchanged.
* `BOOTX64.EFI` differed only in the PE/COFF timestamp words (offsets `0x80` and
  `0x10810`); the code is identical.
* Failed images (`syz-disk.img`, retained per guest) are internally consistent:

| image | `free_blocks` | inode 16 (`.syz-result.bin.tmp`) | data block |
|---|---|---|---|
| attempt 1 | 26598 | mode `0600`, size 0 | none |
| attempt 2 | 26597 | mode `0600`, size 4096 | 6170 |
| green run | 26596 | mode `0600`, size 4264 | 6170 (+1) |

  The inode bitmap bit, block bitmap bit, group descriptor and superblock counters
  all match the fully written metadata homes, i.e. **every home of the failing
  transaction reached the disk**.
* Journal tail (big-endian JBD2 headers):

| image | journal superblock | transaction records |
|---|---|---|
| attempt 1 | `s_sequence=4`, `s_start=1` (dirty) | descriptor seq=4 @L1, 5 images, commit seq=4 @L7 |
| attempt 2 | `s_sequence=5`, `s_start=1` (dirty) | descriptor seq=5 @L1, 4 images, commit seq=5 @L6 |
| green run | `s_start=0` (clean) | tail commits of seq 7/6/4 |

  Read against the boot probe order (R180-6 `alloc.bin` write, create probe,
probe write = sequences 1–3), attempt 1 died inside the executor `open()` transaction
(seq 4) and attempt 2 died inside the first result `write()` transaction (seq 5).
  Both left the journal with a complete descriptor/image/commit chain and an
uncleared `s_start=1` superblock, i.e. the failure occurred in the *last* phase of
`commit_metadata_transaction`: the post-home flush or the journal-clear step.

## 3. Mechanism

The ext2/JBD2 driver fails the mount closed (`io_faulted`) when a block request
returns an error, which is correct: the durability of the transaction is unknown.
The block layer therefore has to be the place that explains *why* the device
request failed — and in this artifact it explained nothing: the failure path of
`kernel/block/src/virtio/blk.rs` reported through `kprintln!`, which the `klog`
crate compiles out of release builds. No `[virtio-blk]` line exists in either
failed serial log even for the worst case (timeout + device reset).

The synchronous wait itself was bounded by a fixed iteration count:

```rust
let mut timeout = 1_000_000u32;
while timeout > 0 && completion.is_none() { ... core::hint::spin_loop(); timeout -= 1; }
```

An iteration count is not a wall-clock bound. A temporary TSC/spin probe on the
devbox (QEMU 6.2, TCG, unloaded) measured:

| request | spins (max) | cycles (max) | approx wall time |
|---|---|---|---|
| read/write | 26,594 | 30.0 M | ~10 ms |
| flush | 22,653 | 21.3 M | ~7 ms |

so the old 1M-iteration budget corresponds to roughly **0.3 s** of wall time, only
~44x the worst healthy flush observed. On a loaded CI host (emulated guest, shared
runner storage) a single stuck `fsync` is enough to expire that budget; the driver
then marks the request abandoned, resets the device and returns `EIO`, which the
filesystem correctly reports as a fail-closed I/O error to `open()`/`write()`.

## 4. Fix (R189-1)

`kernel/block/src/virtio/blk.rs`:

1. **Monotonic no-progress watchdog.** Both synchronous wait loops (`do_request`,
   `flush`) now poll against a monotonic iteration budget
   (`REQUEST_WAIT_MAX_SPINS = 50_000_000` no-progress polls, i.e. ~1900x the
   worst healthy latency measured on the devbox: 26,594 polls for a read/write
   and 22,653 for a flush). The budget needs no clock. A wall-clock deadline was
   implemented first and dropped again - see section 4b for why, and for the
   predicate regression that had to be fixed before either design could work.
2. **Release-visible attribution.** All 19 driver diagnostics that previously used
   `kprintln!` now use `klog!(Error|Warn, ...)`; the expiry messages additionally
   carry the spent poll count. `completion.rs` logs the raw device status byte
   for every non-`OK` completion, and the DMA bounce-buffer allocation failures log
   the request kind, sector and byte count before returning `NoMem`.
3. **Quarantined-ring short-circuit.** Independent review of `bb828d8` found that
   the release-visible SECURITY diagnostics in `pop_used` were re-emitted once per
   poll iteration after a used-ring violation quarantined the queue, and that the
   same bump removed the last caller of the fatal-aware `has_used()` guard.
   `pop_used` now returns `None` immediately while `fatal` is set, both
   synchronous waits end as soon as the queue is quarantined (reporting
   `... aborted by used-ring quarantine ...`), and the wait no longer holds the
   device lock for the whole budget before the reset.

`scripts/tools/hosted_subcrate_tests.sh` raises the `block` exact-count oracle from
22 to 24 (watchdog oracle plus used-ring quarantine oracle);

## 4b. The R189-1 predicate regression, and why the watchdog is still a counter (2026-09-21)

**The regression.** The used-ring quarantine fix (`3b709d4`) factored the wait
condition into

```rust
fn wait_should_continue(completed: bool, quarantined: bool, budget_expired: bool) -> bool {
    !completed && !quarantined && !budget_expired
}
```

but kept the call sites passing `completion.is_none()`:

```rust
while wait_should_continue(completion.is_none(), self.queue.is_fatal(), wait.expired()) {
```

which is false on entry: `completion.is_none()` is true, and the freshly named
parameter negates it. Both synchronous wait loops therefore skipped their bodies,
`completion` stayed `None`, and the timeout path abandoned *every* healthy request
on the first check, reset the device mid-transaction and returned `EIO`. A devbox
smoke run on that revision failed with

```text
[virtio-blk] request wait budget expired head=0 sector=262142 bytes=512 cycles=284024, ...
[virtio-blk] R106-3: initiating device reset for vda
[virtio-blk] request wait budget expired head=0 sector=2 bytes=1024 cycles=882, ...
Registered /dev/vda but failed to initialize ext2: Io
```

Temporary instrumentation of the failure site gave the decisive reading:

```text
[virtio-blk] diag budget=50000000 left=50000000 spent=0 head=0
[virtio-blk] diag fatal=false dev_failed=false head=0
```

`left == budget` with `spent == 0` and `fatal == false` is only reachable when the
loop body never ran: the watchdog was never charged and the queue was never
quarantined. The predicate is now `pending && !quarantined && !budget_expired`
(the first argument is the *pending* state at both call sites), and the quarantine
oracle asserts that call-site argument shape, so an inversion fails the hosted gate
instead of reaching QEMU.

**Withdrawn claim.** An earlier revision of this record blamed the same smoke
failure on RDTSC moving backwards, because `cycles=882` looked impossible for a
30e9-cycle budget. That inference was wrong: those cycles are simply the time
between `WaitDeadline::start()` and the timeout path of a skipped loop, i.e. setup
time. Nothing in this artifact shows this guest's RDTSC is non-monotonic, and no
clock-based conclusion should be drawn from it.

**Why the final watchdog is still a counter.** The iteration budget is kept over
the TSC deadline for narrower reasons: it needs no clock assumption at all (the
only cheap clock on this path is RDTSC), it is charged by the same loop that polls
the device, and its spent count is directly observable in the release diagnostic
(`spins=`). It sits ~1900x above the worst healthy latency measured on this devbox
under TCG.

## 5. Validation

| check | result |
|---|---|
| `cargo test -p block --features mm/host_harness --lib` | 24/24 pass (`wait_budget_is_monotonic_and_bounded`, `quarantined_queue_stops_draining_and_ends_the_wait`) |
| `cd kernel && cargo clippy --release --target x86_64-unknown-none -Z build-std=...` | exit 0 (no new errors; the crate's pre-existing warnings are unchanged) |
| `cd kernel && cargo check --release --target x86_64-unknown-none -Z build-std=...` | exit 0 |
| `make lint` (remote tree `4c19b99`) | exit 0 (ABI oracle PASS) |
| `make test-hosted-subcrates` (remote tree `4c19b99`) | exit 0 - 447 unit tests; `block` 24/24 |
| `make build-syz-kcov` (remote tree `4c19b99`, `kernel/block/src/virtio/blk.rs` sha256 `ee4fae7f293602146ab115136ea27984d9f9934c896234833e4887bbf0ad03d5`) | exit 0 - `esp-syz/kernel.elf` sha256 `95d46b50c3dc2c6036a9228936f053700ed15194c78e6d2ca4c2d1060ab79850` |
| `qemu_smoke` with that kernel (remote, TCG) | `QEMU-FUZZ-SMOKE PASS seeds=2`; both guests `NILIX_SYZ_V2_PASS`; zero `virtio-blk` diagnostics on the healthy path |
| forced short-budget proof (budget temporarily `1_000` polls, same tree) | release serial carries `[virtio-blk] request wait budget expired head=2 sector=40 bytes=4096 spins=1000 ...` plus `R106-3: initiating device reset` / `reset successful`, and the guest fails closed - the attributed diagnostic the 2026-09-21 artifact was missing |
| instrumentation of the failure site with the R189-1 predicate regression (trees `3b709d4`, `49d0db3`) | `diag budget=50000000 left=50000000 spent=0 head=0`, `diag fatal=false dev_failed=false`, then `request wait budget expired ... spins=0` - proves the wait loop never polled; see section 4b |
| remote smoke on the predicate regression (trees `3b709d4`, `49d0db3`) | FAIL - every request abandoned before its first poll, `Registered /dev/vda but failed to initialize ext2: Io` |
| five repeat smoke runs with the unmodified CI kernel on the devbox | 5/5 PASS (no local reproduction; consistent with a host-latency flake) |
| CI re-run of the failing job on the same revision (`gh run rerun --failed`) | PASS |
## 6. Residuals

* The exact expired/aborted operation of the 2026-09-21 failure cannot be attributed
  retroactively: the retention of the failed disk proves the phase but not the
  device-level cause. The promoted diagnostics make the next occurrence
  attributable from the retained serial log (timeout vs. device status vs. DMA
  allocation failure).
* The watchdog remains a watchdog: a genuinely wedged device is still abandoned and
  the filesystem still fails closed after the budget expires (`Error` log + device
  reset). No durability guarantee is weakened.
* A device that returns a non-`OK` status for a `FLUSH` is still not retried; a
  retry would be idempotent but is not justified by the current evidence.
