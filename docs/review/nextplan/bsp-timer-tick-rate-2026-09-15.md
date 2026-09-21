# BSP-TIMER-1 — BSP timer tick rate is firmware-dependent, not the 1 kHz the clock assumes

**Date:** 2026-09-15
**Plan item / Finding:** New. Discovered while diagnosing the `QEMU / mitigation` failure on
run [34878897944](https://github.com/Zero-kernel/Nilix/actions/runs/34878897944) (commit `e3fbf9b`).
**Status:** IMPLEMENTED with independently reviewed, passing clock/mitigation proofs
(2026-09-20). The CI matrix leg is restored. Broader runtime/boot/SMP qualification and
a new Actions/QEMU 8.2 run remain pending; see the scoped results below.
**Scope and authorization:** User authorized continued implementation of the timer defect
and shared-anonymous follow-up on 2026-09-20. Historically, the user authorized (2026-09-15) recording the design and current state
in `next-plan` and disabling the failing gate. Code changes to the tick source were **not**
authorized for that earlier round.
**Designed by:** Original 2026-09-15 Claude record was self-reviewed only. The 2026-09-20
MODE D implementation and HPET oracle were independently reviewed by `/root/timer_review`.
**Amendment mode:** normal.
**Sources:** local `main` @ `aeb7d44`; devbox `40c-devbox-ts` @ `f52da06` + WIP and @ `f516582`;
CI artifacts for runs 34774724225 (`f52da06`, green) and 34935569381 (`aeb7d44`, red).

## 1. Requirement and Threat Model

The kernel documents its millisecond clock as 1 kHz and drives all ms-granular timing from it:
TCP RTO/TIME_WAIT sweeps, hung-task watchdogs, and scheduler tick accounting. The invariant the
system *believes* it holds is **one global tick == one millisecond**.

The defect is that the BSP's tick source is never programmed by the kernel, so that invariant
holds only if the firmware happened to leave the 8254 PIT at ~1 kHz. This is a correctness bug
(timing is silently wrong) and an operability bug (gates that require per-CPU timer observations
become flaky). It is not memory-unsafe.

Out of scope here: whether the mis-rated clock has already corrupted long-running behaviour on
production paths (power, TCP, watchdogs). That is a consequence to assess, not a premise.

## 2. Current-State Analysis

### 2.1 Two different tick sources, only one of them calibrated

| CPU | Source | Setup | Rate |
| --- | --- | --- | --- |
| APs (1..N) | LAPIC timer, vector 32 | `init_lapic_for_ap()` ends with `start_lapic_timer()` — `kernel/arch/apic.rs:900` | calibrated ~1 kHz |
| **BSP (CPU 0)** | **8259 PIC IRQ0 → PIT, vector 32** | `init_lapic()` (`kernel/arch/apic.rs:779`) — **does not start any timer** | **unprogrammed** |

`init_lapic()` deliberately keeps `LINT0 = DELIVERY_EXTINT` ("LINT0 connects to the 8259 PIC's
INTR output on the BSP", `kernel/arch/apic.rs:817-819`) and masks `LVT_TIMER`
(`kernel/arch/apic.rs:816`). The AP path comments confirm the split:
*"Without this, AP would never get timer interrupts (PIT IRQ0 only goes to BSP)"*
(`kernel/arch/apic.rs:897-898`), and the IRQ body branches on it —
*"BSP receives PIT IRQ0 via 8259 PIC, APs receive LAPIC timer interrupts"*
(`kernel/arch/interrupts.rs:1825`, EOI split at `:1909-1912`).

### 2.2 The PIT is never programmed for runtime

`grep` over `kernel/` finds exactly one PIT command-port user — `calibrate_with_pit()`
(`kernel/arch/apic.rs:507`), which drives **channel 2** only, and only as a calibration
reference. The PIT constants present are `PIT_COMMAND_PORT`, `PIT_CHANNEL2_DATA_PORT`,
`PIT_CHANNEL2_GATE_PORT` (`kernel/arch/apic.rs:269-279`). There is **no channel-0
programming anywhere in the tree**. QEMU's PIT therefore runs at whatever the firmware left —
BIOS convention is mode 3 at ~18.2 Hz.

### 2.3 The wall clock is the BSP tick count

```rust
/// 假设时钟中断频率为 1000Hz（每毫秒一次）
/// 如果实际频率不同，需要相应调整
pub fn current_timestamp_ms() -> u64 { get_ticks() }   // kernel/kernel_core/time.rs:154-156
```

`on_timer_tick()` (which increments `TICK_COUNT`) is called **only when `is_bsp`**
(`kernel/arch/interrupts.rs:1873-1875`, guarded with the comment *"Only BSP should increment
global tick count to avoid time advancing N× faster"*). So the guard against N× drift is
correct, but it makes the entire millisecond clock a function of the **unprogrammed PIT rate**.

### 2.4 Runtime measurement

Per-CPU stops at `timer_interrupt_stub` (the harness arms it on all 4 CPUs):

| Environment | CPU 0 (BSP) | CPU 1 | CPU 2 | CPU 3 | Gate |
| --- | --- | --- | --- | --- | --- |
| devbox QEMU 6.2, 40 cores | **1** | 34 | 36 | 44 | pass (17/17) |
| CI QEMU 8.2, ubuntu-24.04 | **0** | 866 | 632 | 540 | fail |

The BSP takes roughly **1/35th** the timer interrupts of an AP, and the devbox passes on a
**single** BSP observation with no margin. On CI that one observation never lands inside the
900-second window.

## 3. Blast Radius

- **Time base (system-wide).** Every ms-granular timeout and the watchdog cadence inherit the
  BSP rate. Changing it shifts scheduler preemption granularity on the BSP.
- **No memory-safety or lifetime impact.** No allocation, locking or pointer discipline changes
  under either candidate approach.
- **IRQ routing.** Approach B moves the BSP off the PIC for the timer; the PIC must stay enabled
  because keyboard (IRQ1) and serial (IRQ4) still arrive through it, and the BSP EOI path
  (`kernel/arch/interrupts.rs:1909`) currently assumes IRQ0 comes from the PIC.

## 4. Candidate Approaches

**A. Program PIT channel 0 for ~1 kHz periodic (recommended).** Write `0x36` to port `0x43`
then divisor `1193182 / 1000 = 1193` to port `0x40`, once, on the BSP before interrupts are
enabled (natural home: alongside the existing calibration in the `kernel/src/main.rs:846` path,
or at the end of `apic::init()`). Keeps the PIC/ExtINT route, the EOI logic and every other IRQ
unchanged. Safety argument: the BSP tick becomes the rate the code already assumes; the only
behavioural change is that it is now *fast*, which is the documented intent. Risk: modest, but
the change is to the system clock, so every ms-based timeout shifts at once.

**B. Start the BSP's LAPIC timer and mask IRQ0.** Call `start_lapic_timer()` on the BSP for
symmetry with the APs, and mask IRQ0 in the 8259 (mask1 `0xEC` → `0xED`). Cleaner long-term
(removes the legacy dependency) but strictly larger: the BSP EOI path would need to stop sending
a PIC EOI on timer ticks, otherwise each tick can prematurely clear an unrelated in-service PIC
IRQ (keyboard/serial). Rejected for this round as the higher-risk option.

**C. Leave it, document.** Not acceptable as a destination: the ms clock stays wrong.

## 5. Decision Record

The 2026-09-15 recommendation was **approach A**; that round only recorded the design and
disabled the gate. The 2026-09-20 continuation implements A under the current authorization.

**Historical interim disposition (2026-09-15):** `mitigation` was removed from the
`.github/workflows/ci.yml` `qemu` matrix, so the flaky gate no longer blocks `CI result`.
The `mitigation)` branch in `scripts/ci/entrypoint.sh:128` and `make test-security-mitigations`
are retained, so the proof still runs locally and can be re-enabled with a one-line revert once
the tick rate is fixed. The `mitigation-status` / `mitigation-mappings` **hosted** suites
(`scripts/tools/hosted_subcrate_tests.sh:235,241`) are unrelated to the QEMU gate and stay
enabled.

This is a deliberate, recorded scope reduction with a re-enable condition — not a
`continue-on-error` mask, which the task contract forbids.

## 6. Defense in Depth

The dedicated mitigation guest now compares `TICK_COUNT` with HPET and requires a numerical
rate witness. Ordinary boot retains its HPET-optional contract. This distinguishes nominal
rate correctness from firmware assumptions without making HPET a new production requirement.

## 7. Implementation Plan

Authorized 2026-09-20: `apic::init_bsp_tick()` programs channel 0 with command 0x36 and
divisor 1193 (1000.153 Hz, +153 ppm), after LAPIC calibration and before AP startup/STI.
An IF=0 assertion enforces the early-boot calling contract. IRQ routing, EOI and the
single BSP global-counter writer are unchanged; calibration uses channel 2.

The dedicated `mitigation_probe` guest measures the serviced tick count against HPET
for at least 250 ms, after BSP STI/deferred acknowledgements and before scheduling any
user task. It handles 32-bit HPET wrap and bounds polling independently of the PIT.
A 25% rate band distinguishes the defective ~18 Hz source and duplicate accounting
while allowing IRQ latency. Missing HPET or a failed measurement blocks this dedicated
guest (diagnostic plus panic); ordinary boot does not require HPET. The host parser
requires exactly one valid numerical `BSP-TIMER PASS` witness. This checks the nominal
rate, not uninterrupted wall-clock accuracy: long IF=0 periods can still lose ticks.

## 8. Test and Verification Plan

- **Oracle 1:** `current_timestamp_ms()` advance rate against the independent HPET window.
  Debugger stop counts are NOT a frequency oracle: they sample user-return CR3 sites,
  and a site's breakpoint disappears once its CPU coverage is complete.
- **Oracle 2:** mitigation still requires all four CPUs and all 17 transitions. Run the
  retained local gate directly before deciding to restore its CI matrix entry.
- **Oracle 3:** the mitigation gate historically passed only via the retry (see the
  2026-09-15 interim result in §9); the 2026-09-20 implementation now has first-attempt
  proofs and a zero-retry CI entry.
- **Regression:** `make build`, `make lint`, `make test`, `make boot-check`,
  `make test-smp-4core`, `make musl-check`, and `make test-ring3-mm`; the tick-rate
  change affects every ms-granular path, so this needs a full gate pass, not a targeted one.

## 9. Open Questions and Limitations

### 2026-09-20 execution evidence

Host `40c-devbox-ts` (`bf05c156b9a3`), QEMU 6.2.0, Rust
`1.94.0-nightly (ba2142a19 2025-12-07)`. Primary isolated tree:
`/tmp/zero-os-nilix-20260920`, based on `6f072978513f236354b0dde720375fd69d053398`.
The original remote checkout at `f52da06` plus WIP was not overwritten.

| Gate | Actual result |
| --- | --- |
| `make build`, `make lint` | Exit 0; final lint rechecked after the test-fixture amendment |
| `make test-hosted-subcrates` | Exit 0 after updating both exact-count declarations; 444 unit tests, CpuLocal doctests and 3 compile checks |
| mitigation parser / CI entry+report tests | 48/48 and 13/13, exit 0 |
| `make test-security-mitigations` | Exit 0, first attempt; `run-6etxdlko`, 17/17 transitions, timer CPUs 0/1/2/3, 250 ticks / 250 HPET ms |
| Second direct `mitigation_check.py --runtime --smp 4` | Exit 0, no retry; `run-tjbi0uhw`, 17/17, all timer CPUs, 251 ticks / 250 HPET ms |
| Final `CI_GUEST_RETRIES=0 bash scripts/ci/entrypoint.sh mitigation` | Exit 0; `.validation/ci-final/run.hfKT07`: build, runtime proof and unsupported-retpoline boundary all PASS; `proof/run-h4b_d1ok` has 17/17, all timer CPUs, 250 ticks / 250 HPET ms |
| `make test`, `make boot-check`, `make test-smp-4core` | Make exits 2 because the underlying gate exits **3 QUALIFIED**: respectively 35/39/0, 28/46/0, 37/37/0 passed/deferred/failed; not strict passes |
| `make musl-check` | Exit 0, required libc/poll/socket/stat/uname markers and PID 1 exit 0; not a shared-mmap-specific musl oracle |

The final CI entry runs the merged source including the dedicated `syscall_test`-only
cgroup fixture amendment. Its `inputs.json`, command records and guest ELF hashes
are retained under the CI artifact directory. Kernel MM/IRQ source is byte-identical
across the primary and Ring-3 validation copies; the latter's 13/13 results and remaining
MM limits are recorded in [the shared follow-up](../design/st-k2-shared-fault-lifecycle-design.md).
Local evidence is retained in `.tmp-nilix-20260920/` (including the original
`evidence.tar.gz`, SHA256 `74ecc7346194363687c570a8d4e0bed79d6f76b9b98a2307cc8ffaa7722b53be`).
The final archive `evidence-final.tar.gz` also includes the final CI entry and tested
kernel ELFs (SHA256 `a0e9ef322be90187c67c51613c00b05342d4c40c297ef22a379b3ef5f318dc6b`).
The initial standard-gate failures/qualifications are preserved; no retry converted
a missing four-CPU clock observation into acceptance.

The matrix re-enable is a working-tree change; no commit/push or new GitHub Actions run
was performed. The local QEMU evidence does not claim an observed QEMU 8.2 result.

- **The gate failure was previously attributed to `f516582` (the mremap slice) and that
  attribution was wrong.** The last green run at `f52da06` failed its *first* attempt with the
  identical `dynamic=blocked` and passed only on retry (`attempt=1/2 status=2 action=retry`,
  `attempt=2/2 status=0 action=recovered`); its artifact retains both proof runs —
  `run-mw90g82x` (17/17) and `run-xfnmib6p` at 15/17 missing `timer_interrupt_stub` on
  CPU 0. The gate has been **chronically flaky**, not newly regressed.
- **Not proven:** that QEMU 8.2 leaves the PIT at a different rate than 6.2. The measured
  asymmetry is consistent with an unprogrammed PIT and is enough to explain the flakiness, but
  the exact PIT rate on each environment has not been read directly.
- **Not assessed:** how long the ms clock has been skewed in production configurations, and
  which timeouts were tuned around the slow clock.
- Two commits landed during this investigation and remain on `main`:
  `edbe666` (restore `mm.mmap_regions.clear()` in `exec_from_bytes`, real bug independently of
  this finding) and `aeb7d44` (bound repeated proof-site stops, which is what made the missing
  CPU 0 observation visible instead of an opaque deadline).

## 10. References

- `kernel/arch/apic.rs` — `init_lapic():779`, `init_lapic_for_ap():850`, `start_lapic_timer():604`,
  calibration `:386-583`, PIT constants `:269-279`
- `kernel/arch/interrupts.rs` — timer IRQ body `:1820-1915`, BSP/AP EOI split `:1909`
- `kernel/kernel_core/time.rs` — `on_timer_tick():64`, `get_ticks():145`,
  `current_timestamp_ms():154`
- `scripts/gates/qemu/mitigation_check.py` — site arming and required-CPU policy
- `docs/ci-testing.md` — gate map and the earlier collector-overhead repair
- CI runs 34774724225 (green, internally flaky) and 34878897944 / 34935569381 (red)

## Deviation and Amendment Log

| Date | Section | Change and evidence | Safety impact | Review outcome | User decision if required |
| --- | --- | --- | --- | --- | --- |
| 2026-09-15 | all | Initial record. Prior attribution to `f516582` withdrawn after the `f52da06` artifact showed attempt 1 failing identically. | None (record only) | Self-review only | User directed: record + disable gate, do not change the tick source yet |
| 2026-09-20 | 7–9 | Implement approach A and require a numerical HPET oracle; discard breakpoint-count ratios as a frequency assertion. Restore the CI matrix after two first-attempt proofs, then pass the final zero-retry CI entry. | Preserves IRQ route, EOI and BSP-only time ownership; acknowledges coalesced ticks. | Independent `/root/timer_review` design/change review passed; exact execution evidence above. General strict qualification remains open. | Current continuation request authorizes implementation. |
