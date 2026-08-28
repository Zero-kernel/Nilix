# Nilix Documentation

Comprehensive documentation for the Nilix kernel project — the **内容概览** index. This is
the hub the top-level [README](../README.md) defers to; each entry below links to an
overview or detail document.

> **Reading order for the architecture:** start with the readable
> [`architecture.md`](architecture.md) (composition diagram, crate layering & dependency
> DAG, boot flow, syscall path, core components), then the deep
> [`overview/architecture/ARCHITECTURE.md`](overview/architecture/ARCHITECTURE.md) for the
> lock ordering, critical code paths, and historical audit record.
> **Note:** the `overview/` subtree predates R187 (KCOV, 2026-08-08) and the 2026-08-27 R188
> standalone-audit remediation; for current audit numbers see
> [`security-audit-status.md`](security-audit-status.md).

## Directory Structure

### [architecture.md](architecture.md) · [overview/architecture/](overview/architecture/)
Workspace layout, the verified crate layering & dependency DAG (Mermaid), the boot flow,
the syscall path, and the core subsystems (3.1–3.10). The `overview/architecture/` tree
holds the deep reference (lock ordering, critical code paths, historical findings) and
per-subsystem deep dives in [`overview/02-architecture/subsystems/`](overview/02-architecture/subsystems/).

- **[architecture.md](architecture.md)** - Readable architecture: composition + DAG + boot + syscall + components
- **[overview/architecture/ARCHITECTURE.md](overview/architecture/ARCHITECTURE.md)** - Deep subsystem map (lock ordering, critical paths, findings)

### [architecture/](overview/architecture/)
Architectural documentation covering all 25 kernel crates, their responsibilities, key abstractions, and interdependencies.

- **[ARCHITECTURE.md](overview/architecture/ARCHITECTURE.md)** - Complete subsystem map

### [review/](review/)
Security audit reports, fix documentation, and remediation tracking.

- **[audits/](review/audits/)** - QA security audit reports through R187 (R188 standalone audit in [security/](security/))
- **[fixes/](review/fixes/)** - Fix plans and implementation details for R17x findings
- **[remediation/](review/remediation/)** - Remediation roadmaps and open findings inventory

### [safety/](overview/06-security/safety/)
IRQ safety analysis, lock ordering documentation, and sync primitive migration guides.

- **[IRQ_SAFETY_AUDIT.md](overview/06-security/safety/IRQ_SAFETY_AUDIT.md)** - IRQ safety audit
- **[IRQ_SAFETY_PROPAGATION_PLAN.md](overview/06-security/safety/IRQ_SAFETY_PROPAGATION_PLAN.md)** - IRQ-safe primitive propagation
- **[SYNC_SAFE_MIGRATION_GUIDE.md](overview/06-security/safety/SYNC_SAFE_MIGRATION_GUIDE.md)** - Migration guide

### [testing/](overview/testing/)
Test coverage analysis, expansion plans, and implementation documentation.

- **[test-coverage-summary.md](overview/testing/test-coverage-summary.md)** - Current coverage
- **[test-coverage-expansion-plan.md](overview/testing/test-coverage-expansion-plan.md)** - Coverage roadmap
- **[test-implementation-complete.md](overview/testing/test-implementation-complete.md)** - Completed work

### [reports/](overview/reports/)
Final implementation status reports and comprehensive summaries of major QA work.

- **[FINAL_IMPLEMENTATION_STATUS.md](overview/reports/FINAL_IMPLEMENTATION_STATUS.md)** - Latest status
- **[COMPLETE_QA_REMEDIATION_FINAL.md](overview/reports/COMPLETE_QA_REMEDIATION_FINAL.md)** - Complete remediation summary

### [overview/](overview/)
Subsystem, architecture, safety, testing, and report documentation.

## Quick Navigation

### For New Contributors
1. Read the canonical [contributor guide](../CONTRIBUTING.md) and [governance model](../GOVERNANCE.md)
2. Start with [architecture.md](architecture.md) for the readable overview, then [overview/architecture/ARCHITECTURE.md](overview/architecture/ARCHITECTURE.md) for the deep reference
3. Review the [security audit status](security-audit-status.md) for current status (R187 latest R-series; R188 standalone)
4. Check the [current next-phase plan](review/nextplan/) for open work (newest dated snapshot)

### For Security Auditors
1. Read the public threat model in [roadmap.md](roadmap.md#32-threat-model) and report vulnerabilities under [SECURITY.md](../SECURITY.md)
2. Latest R-series audit: [review/audits/qa-2026-08-05.md](review/audits/qa-2026-08-05.md) (R187); standalone full-codebase audit: [security/full-codebase-audit-2026-08-07.md](security/full-codebase-audit-2026-08-07.md) (R188)
3. Fix history: [review/fixes/](review/fixes/)
4. Open findings: [review/remediation/](review/remediation/)

### For Developers Fixing Bugs
1. Check the [current next-phase plan](review/nextplan/next-phase-plan-2026-07-23-v2.md) for the prioritized bug list
2. Review related audit findings in [review/audits/](review/audits/)
3. Follow fix patterns in [review/fixes/](review/fixes/)
4. Add regression tests per [testing/](overview/testing/) guidelines

### For IRQ Safety Work
1. Read [safety/IRQ_SAFETY_AUDIT.md](overview/06-security/safety/IRQ_SAFETY_AUDIT.md)
2. Follow [safety/SYNC_SAFE_MIGRATION_GUIDE.md](overview/06-security/safety/SYNC_SAFE_MIGRATION_GUIDE.md)
3. Check [safety/IRQ_LOCK_SITE_INVENTORY.md](overview/06-security/safety/IRQ_LOCK_SITE_INVENTORY.md) for lock sites

## Documentation Standards

### File Naming
- Use kebab-case for multi-word files: `test-coverage-summary.md`
- Use PascalCase for subsystem docs: `ARCHITECTURE.md`, `IRQ_SAFETY_AUDIT.md`
- Include dates for versioned docs: `qa-2026-07-02-v5.md`, `remediation-roadmap-2026-07-02.md`

### Cross-References
- Use relative paths: `[link](../other-dir/file.md)`
- Always verify links after moving files
- Update all references when relocating documentation

### README Files
Each subdirectory has a README.md providing:
- Overview of contents
- File descriptions
- Related documentation links
- Usage guidelines

## Quality Gate Status

Current gate status for 1.0-Preview: **BLOCKED** (authoritative state 2026-08-27). Full
detail in [`security-audit-status.md`](security-audit-status.md); dated changes in
[`../CHANGELOG.md`](../CHANGELOG.md); CI/fuzzing detail in [`quality-gates.md`](quality-gates.md).

- ✅ 0 open CRITICAL findings
- ❌ 1 open HIGH finding (`R186-4`, VMA/MM aggregate admission); zero-HIGH streak **0/3**
- ✅ R187 KCOV remediation (2026-08-08): 7 findings fixed, 7/7 PASS, 8/8 review-fix defects
  repaired, 0 escalated — no new open HIGH
- ✅ R188 standalone full-codebase audit remediated (2026-08-27): 3 HIGH + 24 MEDIUM fixed;
  residuals `U37-1`/`U55-6`/`U29-3` open; standalone (not R-series), streak unchanged 0/3
- ✅ R186: 16 of 17 actionables fixed; `R186-4` is the sole open actionable; 24 `RF186-*`
  defects repaired, 0 escalated
- ✅ Remote ladder green: fmt/clippy/lint/build/boot-check/musl-check PASS;
  `make test` = **34 passed / 39 deferred / 0 failed**, 0 panic, 0 NX
- ✅ Hosted sub-crate CI: **239 hosted tests** (169 default-parallel) with exact-count
  oracles; privileged suites remain QEMU-only by explicit contract

See the [R187 report](review/audits/qa-2026-08-05.md), the
[RF187 closure](review/reviewfix/reviewfix-2026-08-08.md), the
[R186 report](review/audits/qa-2026-07-28.md), the
[RF186 review-fix report](review/reviewfix/reviewfix-2026-07-30.md), and the
[R188 standalone audit](security/full-codebase-audit-2026-08-07.md) (§13 dispositions).

## Recent Audit Rounds

- **R188** (Aug 27, 2026): standalone full-codebase audit remediation — 3 HIGH + 24 MEDIUM
  fixed; residuals `U37-1`/`U55-6`/`U29-3` open; not R-series; streak 0/3 -
  [security/full-codebase-audit-2026-08-07.md](security/full-codebase-audit-2026-08-07.md)
- **RF187** (Aug 8, 2026): KCOV review-fix closure — 7/7 PASS, 8/8 defects repaired, 0
  escalated - [reviewfix/reviewfix-2026-08-08.md](review/reviewfix/reviewfix-2026-08-08.md)
- **R187** (Aug 8, 2026): KCOV authority/access/topology - [audits/qa-2026-08-05.md](review/audits/qa-2026-08-05.md)
- **RF186 final** (July 30, 2026): 16 fixes reviewed; 2 PASS / 12 PARTIAL / 2 FAIL;
  24/24 defects repaired, 0 escalated; final environment ladder green -
  [reviewfix/reviewfix-2026-07-30.md](review/reviewfix/reviewfix-2026-07-30.md)
- **R186** (July 28, 2026): full-codebase audit and fix record - [audits/qa-2026-07-28.md](review/audits/qa-2026-07-28.md)
- **R185** (July 23, 2026): Clean verification round - [audits/qa-2026-07-23-v2.md](review/audits/qa-2026-07-23-v2.md)
- **R184** (July 23, 2026): Findings round and review-fix - [audits/qa-2026-07-23.md](review/audits/qa-2026-07-23.md)
- **R174** (July 2, 2026): Historical comprehensive audit - [audits/qa-2026-07-02-v5.md](review/audits/qa-2026-07-02-v5.md)
- **R173** (June-July 2026): IRQ safety campaign - [fixes/r173-complete-package-summary.md](review/fixes/r173-complete-package-summary.md)
- **R172** (June 2026): VFS/ramfs audit - [audits/qa-2026-06-*.md](review/audits/)
- **R170-R171** (Jan-June 2026): Quota system, cgroup memory safety

## Contributing to Documentation

When adding or updating documentation:

1. **Choose the right location**
   - Architecture docs → `overview/architecture/`
   - Audit reports → `review/audits/`
   - Fix plans/implementation → `review/fixes/`
   - Safety analysis → `overview/06-security/safety/`
   - Test plans/coverage → `overview/testing/`
   - Final summaries → `overview/reports/`

2. **Follow naming conventions**
   - See "File Naming" above

3. **Update cross-references**
   - Check all relative links
   - Update README files in affected directories

4. **Dual-write to remote**
   - Local: `D:\project\Zero-os\docs\`
   - Remote: `/home/dev/workspace/project/rsproject/Zero-os/docs/`

5. **Manual commit only**
   - Do not auto-commit documentation
   - Commit only when explicitly requested

## See Also

- **[review/nextplan/](review/nextplan/)** - Current prioritized roadmap for 1.0-Preview
- **[open-findings-executive-summary.md](review/other/open-findings-executive-summary.md)** - Executive summary of open findings
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Contributor guidelines
- **[README.md](../README.md)** - Project README
