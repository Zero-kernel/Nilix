# BSP-TIMER-1 — BSP timer tick rate is firmware-dependent, not the 1 kHz the clock assumes

**Date:** 2026-09-15
**Plan item / Finding:** New. Discovered while diagnosing the `QEMU / mitigation` failure on
run [34878897944](https://github.com/Zero-kernel/Nilix/actions/runs/34878897944) (commit `e3fbf9b`).
**Status:** DRAFT — root cause established with source + runtime evidence; the fix touches the
system-wide time base and has not been designed to completion or independently reviewed.
The affected gate is **disabled** in CI in the interim (see §5).
**Scope and authorization:** User authorized (2026-09-15) recording the design and current state
in `next-plan` and disabling the failing gate. Code changes to the tick source were **not**
authorized for this round.
**Designed by:** Claude (session), MODE S self-review only — **no independent review yet**.
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

Routine technical choice within the authorized scope: **approach A** is the recommendation.
It was **not implemented**, because the user directed this round to record the design and
disable the gate instead. Approach A remains the proposed next step.

**Interim disposition (this is what is actually in the tree):** `mitigation` is removed from the
`.github/workflows/ci.yml` `qemu` matrix, so the flaky gate no longer blocks `CI result`.
The `mitigation)` branch in `scripts/ci/entrypoint.sh:128` and `make test-security-mitigations`
are retained, so the proof still runs locally and can be re-enabled with a one-line revert once
the tick rate is fixed. The `mitigation-status` / `mitigation-mappings` **hosted** suites
(`scripts/tools/hosted_subcrate_tests.sh:235,241`) are unrelated to the QEMU gate and stay
enabled.

This is a deliberate, recorded scope reduction with a re-enable condition — not a
`continue-on-error` mask, which the task contract forbids.

## 6. Defense in Depth

Once approach A lands, the natural fail-closed check is a boot assertion that the BSP tick rate
matches the documented rate (e.g. compare `TICK_COUNT` delta against HPET over a window, and
report a qualification if they diverge). That turns a silent timing skew into an explicit
signal. Out of scope for this record.

## 7. Implementation Plan

Not authorized this round. For the record, approach A is: one BSP-side helper in
`kernel/arch/apic.rs` that programs PIT channel 0, called once from the existing BSP init
sequence after calibration; no other file changes.

## 8. Test and Verification Plan

- **Precondition:** the mitigation gate must be re-enabled for the fix to be exercised.
- **Oracle 1:** BSP tick rate. The devbox measured 1 BSP timer interrupt against 34-44 per AP;
  after the fix the ratio should be ~1:1. This is directly observable from the existing
  `rsp-transcript.json` per-CPU stop counts — no new instrumentation needed.
- **Oracle 2:** `current_timestamp_ms()` advance rate against HPET over a known window.
- **Oracle 3:** the mitigation gate passes **first try, repeatedly** (it currently passes only
  via the retry — see §9).
- **Regression:** `make test` (boot/SMP, iommu, musl) plus `make test-ring3-mm`; the tick-rate
  change affects every ms-granular path, so this needs a full gate pass, not a targeted one.

## 9. Open Questions and Limitations

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
