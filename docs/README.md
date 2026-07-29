# Zero-OS Documentation

Comprehensive documentation for the Zero-OS kernel project.

## Directory Structure

### [architecture/](overview/architecture/)
Architectural documentation covering all 25 kernel crates, their responsibilities, key abstractions, and interdependencies.

- **[ARCHITECTURE.md](overview/architecture/ARCHITECTURE.md)** - Complete subsystem map

### [review/](review/)
Security audit reports, fix documentation, and remediation tracking.

- **[audits/](review/audits/)** - QA security audit reports through R186
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
1. Start with [architecture/ARCHITECTURE.md](overview/architecture/ARCHITECTURE.md) for subsystem overview
2. Review the [R186 audit/fix record](review/audits/qa-2026-07-28.md) for current status
3. Check the [current next-phase plan](review/nextplan/next-phase-plan-2026-07-23-v2.md) for open work

### For Security Auditors
1. Latest audit: [review/audits/qa-2026-07-28.md](review/audits/qa-2026-07-28.md) (R186)
2. Fix history: [review/fixes/](review/fixes/)
3. Open findings: [review/remediation/](review/remediation/)

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

Current gate status for 1.0-Preview: **BLOCKED**
- ✅ 0 open CRITICAL findings
- ❌ 1 open HIGH finding (`R186-4`, VMA/MM aggregate admission)
- ✅ 16 of 17 actionable R186 findings fully fixed; `R186-4` is the sole open actionable
- ✅ Default remote gates: build/lint clean; `make test` = 31 passed / 39 deferred / 0 failed

See the [R186 audit/fix record](review/audits/qa-2026-07-28.md) for details.

## Recent Audit Rounds

- **R186** (July 28, 2026): Latest full-codebase audit and fix record - [audits/qa-2026-07-28.md](review/audits/qa-2026-07-28.md)
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
