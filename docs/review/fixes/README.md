# QA Audit Fix Documentation

This directory contains fix plans, implementation details, and summaries for security audit findings.

## R187 Fixes (August 2026)

- **[R187-fix-summary.md](R187-fix-summary.md)** - KCOV remediation: 7/7 findings fixed,
  0 rejected, 0 open; IRQ/NMI async-context and CPU-topology hardening verified alongside devbox
  build/lint/test and KCOV E2E PASS; targeted hosted suites pass 6/6, 9/9, 1/1, and 1/1;
  Cargo all-targets executes the three executor regressions; Stage-3 review-fix pending.
- **[R187 audit/fix record](../audits/qa-2026-08-05.md)** - authoritative per-finding
  dispositions, verification evidence, and plan-impact handoff.

## R186 Fixes (July 2026)

- **[R186 audit/fix record](../audits/qa-2026-07-28.md)** - 16/17 actionables fixed,
  0 partial, `R186-4` sole open HIGH.
- **[Authoritative R186 ReviewFix](../reviewfix/reviewfix-2026-07-30.md)** -
  16 fixes reviewed (2 PASS / 12 PARTIAL / 2 FAIL); 24/24 RF defects repaired,
  0 escalated. Source and environment closure are complete; focused/default-parallel
  checks and the full final remote ladder are green.
- **[Current next-phase plan](../nextplan/next-phase-plan-2026-08-01.md)** -
  Live remaining-work, R187 Stage-2 status, and release-gate state (Stage-3 review next).

## R181 Fixes (July 2026)

- **[R181-fix-summary.md](R181-fix-summary.md)** - R181 fix round (5/5 actionable closed: futex errno class, CLONE_VM migration re-count primitive both front doors, accept backoff + 2 documented dispositions; MODE C, avg 1.2 iterations)

## R180 Fixes (July 2026)

- **[R180-fix-summary.md](R180-fix-summary.md)** - R180 historical review-fix plus convergence through RF180-59 (32/32 implementation findings closed; design blockers retained; MODE D)

## R178 Fixes (July 2026)

- **[R178-fix-summary.md](R178-fix-summary.md)** - Complete R178 CRITICAL+HIGH fix summary (11 findings)

## R174 Fixes (July 2026)

- **[R174-fix-plan.md](R174-fix-plan.md)** - Comprehensive fix plan for R174 findings
- **[R174-fix-summary.md](R174-fix-summary.md)** - Fix implementation summary
- **[R174-HIGH-fixes-implementation.md](R174-HIGH-fixes-implementation.md)** - HIGH severity fix implementation details
- **[R174-HIGH-fixes-complete.md](R174-HIGH-fixes-complete.md)** - HIGH severity fix completion report
- **[R174-summary.md](R174-summary.md)** - R174 audit and fix summary

## R173 Fixes (June-July 2026)

- **[r173-complete-package-summary.md](r173-complete-package-summary.md)** - Complete R173 remediation package
- **[r173-defense-in-depth-analysis.md](r173-defense-in-depth-analysis.md)** - Defense-in-depth analysis and fixes

## R170 Fixes (Jan-June 2026)

- **[r170-fix-alignment-brief.md](r170-fix-alignment-brief.md)** - R170 fix alignment brief
- **[r170-fix-review-batch1.md](r170-fix-review-batch1.md)** - R170 fix review batch 1
- **[r170-fix-review-batch2.md](r170-fix-review-batch2.md)** - R170 fix review batch 2

## Fix Workflow

1. **Audit** → Findings categorized by severity (see [../audits/](../audits/))
2. **Fix Plan** → Comprehensive fix strategy (R17X-fix-plan.md)
3. **Implementation** → Detailed implementation with verification (R17X-fix-summary.md)
4. **Completion** → Fix validation and gate status (R17X-HIGH-fixes-complete.md)
5. **Summary** → Executive summary and next steps (R17X-summary.md)

## Fix Categories

### Memory Safety
- Use-after-free (UAF) fixes
- Double-free prevention
- Uninitialized memory handling
- Buffer overflow protection

### Concurrency
- Data race elimination
- Deadlock prevention
- TOCTOU (Time-of-Check-Time-of-Use) fixes
- Lock ordering enforcement

### Resource Management
- Memory leak fixes
- Reference counting corrections
- Quota enforcement
- Resource exhaustion prevention

### Architecture Compliance
- IRQ safety propagation (see [../../overview/06-security/safety/](../../overview/06-security/safety/))
- Lock hierarchy enforcement
- TLB coherency fixes
- FPU state management

### ABI Safety
- repr(C) layout verification
- FFI boundary validation
- Syscall ABI compliance
- Struct padding audits

## Verification Standards

All fixes must record:

- Build and lint results
- Relevant hosted tests when supported, otherwise an explicit NOT-RUN/PENDING disposition
- Default runtime and boot-gate results
- Targeted SMP or hardware-path verification where required
- Independent review/convergence evidence and the actual operating mode

## Related Documentation

- **[../audits/](../audits/)** - Security audit reports
- **[../remediation/](../remediation/)** - Remediation roadmaps
- **[../../overview/reports/](../../overview/reports/)** - Implementation status reports
- **[../../overview/06-security/safety/](../../overview/06-security/safety/)** - IRQ safety and sync primitive documentation
- **[../../overview/testing/](../../overview/testing/)** - Test coverage and implementation plans
