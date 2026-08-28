# Security Audit Status

Nilix is developed under a continuous adversarial-review process: each round audits the
kernel, files findings by severity, fixes them, and converges via bidirectional peer review
(Claude Code + the Codex MCP) before the round closes. This is the detail behind
[README §Status](../README.md); the dated recent-additions log lives in
[CHANGELOG.md](../CHANGELOG.md).

---

## Metrics

| Metric | Value |
|--------|-------|
| Audit rounds | **187** R-series (R187 KCOV remediation completed 2026-08-08; ReviewFix closure 2026-08-08) |
| Cumulative findings | ~1,340 (historical IDs include merged/refuted findings) |
| Findings fixed/resolved | ~1,184 |
| Latest R-series round | R187 — KCOV authority/access/topology; 7 fixes, 7 PASS (review-fix 8/8 repaired) |
| Latest review-fix pass | RF187 — 7/7 fixes PASS, 8/8 RF defects repaired, 0 escalated; remote ladder green |
| Standalone full-codebase audit | R188 (audit 2026-08-07; remediation 2026-08-27) — 3 HIGH + 24 MEDIUM fixed; not an R-series round; residuals U37-1/U55-6/U29-3 open; streak unchanged 0/3 |
| Current actionable debt | **1 HIGH** (`R186-4`, carried) |
| 1.0-Preview release gate | **BLOCKED** — carried `R186-4` HIGH remains; zero-HIGH streak 0/3 |

---

## R186 — VMA/MM aggregate admission

R186 found 18 issues in total: 17 actionable findings and one INFO. Sixteen actionables
are fully fixed; `R186-18` is fixed and review-verified through shared credential
generation, writer-fair authorization, and stable subject ownership across side effects
and publication. `R186-4` remains the sole HIGH blocker. The round therefore reset the
zero-HIGH streak to 0/3 and reopened the aggregate heap-admission design parent. See the
[R186 report](review/audits/qa-2026-07-28.md) and the
[current plan](review/nextplan/next-phase-plan-2026-07-23-v2.md).

The authoritative **RF186 ReviewFix closure** reviewed all 16 landed fixes: 2 PASS,
12 PARTIAL, and 2 FAIL. All 24 defects (`RF186-1`…`RF186-24`) are repaired with
0 escalations. Final execution passes net 110/110 under default parallelism, conntrack
stress 50/50, and the complete fmt/clippy/build/lint/test/boot/musl ladder. `R186-4` was
never fixed and remains outside the Stage-3 verdict scope, so the gate and streak remain
unchanged. See the [authoritative RF186 report](review/reviewfix/reviewfix-2026-07-30.md).

## R187 — KCOV observability (2026-08-08)

R187 audited the KCOV observability surface and recorded 7 findings — authority,
IRQ/NMI/soft-progress admission, exact dump, occupied-slot collision semantics, fuzzer
timing/control, documentation, and static CPU/topology safety. All 7 are fixed and the
ReviewFix closure verified 7/7 PASS. Eight review-fix defects (RF187-1…RF187-8) were
repaired with 0 escalations: KCOV authority is now host-root-only (the reserved
`CapRights::KCOV` bit cannot elevate a caller), an allocation-free soft-progress guard
spans the public deferred-callback drain, the CPU online topology is unified under one
authoritative `cpu_local` mask, and the fuzzer ABI reports occupied bitmap slots with
bounded KCOV control retries. R187 added no new open HIGH; the gate remains BLOCKED on
the carried `R186-4` and the streak stays 0/3. See the
[R187 report](review/audits/qa-2026-08-05.md) and the
[RF187 closure](review/reviewfix/reviewfix-2026-08-08.md).

## R188 — Standalone full-codebase audit (audit 2026-08-07; remediation 2026-08-27)

A standalone full-codebase audit (R188, 2026-08-07) was remediated on 2026-08-27: all
three HIGH findings (`U06-1` cgroup port-uncharge, `U09-1/2/3` signal-delivery ABI and
lock lifetime, `U34-1` robust-futex teardown) and all 24 MEDIUM findings are fixed, along
with the implementation-ready LOW/associated set. Residual design work — `U37-1`
(KPTI/dual-CR3), `U55-6` (early-boot identity-map W+X transition), and `U29-3`
(VM-passthrough lifecycle) — remains explicitly open and is not counted as fixed. This is
a *standalone* audit, not part of the R-series, so it makes no zero-HIGH streak claim and
the gate remains BLOCKED on carried `R186-4`. All remote gates pass against the
synchronized tree. See the
[audit document](security/full-codebase-audit-2026-08-07.md) (§13 dispositions).

---

## Hosted sub-crate tests

CI runs `make test-hosted-subcrates`: **239 hosted sub-crate tests** in total —
**169 default-parallel** across audit, MM, block, seccomp, net, and the focused RF186
capability lifecycle pair, plus compile checks for IPC, kernel_core, and kernel test code.
Exact test-count oracles prevent zero-test/filter drift from passing silently. Full
capability and privileged kernel suites remain QEMU-only because hosted execution cannot
safely run interrupt/MMIO paths.
