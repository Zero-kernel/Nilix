# QEMU fuzz executor `EIO` flake — 2026-09-21

**Date:** 2026-09-21
**Status:** fix implemented and validated locally/remotely (remote tree `bb828d8`); the affected CI job reruns green on the pre-fix revision
**Code commit:** `bb828d8` — `fix(block): attribute virtio-blk failures and wait on a TSC deadline`
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

1. **Wall-clock watchdogs.** Both synchronous wait loops (`do_request`, `flush`)
   now poll against a wrap-safe monotonic TSC deadline
   (`REQUEST_WAIT_TIMEOUT_CYCLES = 30_000_000_000`, i.e. at least ~6 s of real
   time on any CPU up to 5 GHz and longer on slower/TCG parts). Requests are only
   abandoned, and the device only reset, after a latency that no plausible host
   I/O can reach.
2. **Release-visible attribution.** All 19 driver diagnostics that previously used
   `kprintln!` now use `klog!(Error|Warn, ...)`; the expiry messages additionally
   carry the elapsed cycle count. `completion.rs` logs the raw device status byte
   for every non-`OK` completion, and the DMA bounce-buffer allocation failures log
   the request kind, sector and byte count before returning `NoMem`.

`scripts/tools/hosted_subcrate_tests.sh` raises the `block` exact-count oracle from
22 to 23 for the new unit test;

## 5. Validation

| check | result |
|---|---|
| `cargo test -p block --features mm/host_harness --lib` | 23/23 pass (new `wait_budget_is_monotonic_and_wrap_safe`) |
| `cd kernel && cargo clippy --release --target x86_64-unknown-none -Z build-std=...` | exit 0 (no new warnings) |
| `cd kernel && cargo check --release --target x86_64-unknown-none -Z build-std=...` | exit 0 |
| `make lint` (remote tree `bb828d8`) | exit 0 (ABI oracle PASS) |
| `make test-hosted-subcrates` (remote tree `bb828d8`) | exit 0 — 446 unit tests; `block` 23/23 |
| `make build-syz-kcov` (remote tree `bb828d8`) | exit 0 — `esp-syz/kernel.elf` sha256 `311d2f2011c4617b3f82bfa1f3a1afc59eb32696d47de416e8f63e84207ec523` |
| `qemu_smoke` with that kernel (remote, TCG) | `QEMU-FUZZ-SMOKE PASS seeds=2`; both guests `NILIX_SYZ_V2_PASS`; zero `virtio-blk` diagnostics on the healthy path |
| forced short-budget proof (budget temporarily `1_000` cycles, same tree) | release serial log now carries `[virtio-blk] request wait budget expired head=0 sector=2 bytes=1024 cycles=3956 ...` plus `R106-3: initiating device reset` / `reset successful`, and the guest fails closed — the exact attribution that was missing on 2026-09-21 |
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
