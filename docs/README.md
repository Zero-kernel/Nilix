# Zero-OS Documentation

Comprehensive documentation for the Zero-OS kernel project.

## Directory Structure

### [architecture/](architecture/)
Architectural documentation covering all 23 kernel subsystems, their responsibilities, key abstractions, and interdependencies.

- **[ARCHITECTURE.md](architecture/ARCHITECTURE.md)** - Complete subsystem map

### [review/](review/)
Security audit reports, fix documentation, and remediation tracking.

- **[audits/](review/audits/)** - QA security audit reports (R170-R174, 152 audits)
- **[fixes/](review/fixes/)** - Fix plans and implementation details for R17x findings
- **[remediation/](review/remediation/)** - Remediation roadmaps and open findings inventory

### [safety/](safety/)
IRQ safety analysis, lock ordering documentation, and sync primitive migration guides.

- **[IRQ_SAFETY_AUDIT.md](safety/IRQ_SAFETY_AUDIT.md)** - IRQ safety audit
- **[IRQ_SAFETY_PROPAGATION_PLAN.md](safety/IRQ_SAFETY_PROPAGATION_PLAN.md)** - IRQ-safe primitive propagation
- **[SYNC_SAFE_MIGRATION_GUIDE.md](safety/SYNC_SAFE_MIGRATION_GUIDE.md)** - Migration guide

### [testing/](testing/)
Test coverage analysis, expansion plans, and implementation documentation.

- **[test-coverage-summary.md](testing/test-coverage-summary.md)** - Current coverage
- **[test-coverage-expansion-plan.md](testing/test-coverage-expansion-plan.md)** - Coverage roadmap
- **[test-implementation-complete.md](testing/test-implementation-complete.md)** - Completed work

### [reports/](reports/)
Final implementation status reports and comprehensive summaries of major QA work.

- **[FINAL_IMPLEMENTATION_STATUS.md](reports/FINAL_IMPLEMENTATION_STATUS.md)** - Latest status
- **[COMPLETE_QA_REMEDIATION_FINAL.md](reports/COMPLETE_QA_REMEDIATION_FINAL.md)** - Complete remediation summary

### [document/](document/)
Legacy subsystem documentation (00-16 numbered docs) - to be integrated with architecture/.

## Quick Navigation

### For New Contributors
1. Start with [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md) for subsystem overview
2. Review [reports/FINAL_IMPLEMENTATION_STATUS.md](reports/FINAL_IMPLEMENTATION_STATUS.md) for current status
3. Check [review/remediation/open-findings-inventory-2026-07-02.md](review/remediation/open-findings-inventory-2026-07-02.md) for open work

### For Security Auditors
1. Latest audit: [review/audits/qa-2026-07-02-v5.md](review/audits/qa-2026-07-02-v5.md) (R174)
2. Fix history: [review/fixes/](review/fixes/)
3. Open findings: [review/remediation/](review/remediation/)

### For Developers Fixing Bugs
1. Check [next-phase-plan.md](next-phase-plan.md) for prioritized bug list
2. Review related audit findings in [review/audits/](review/audits/)
3. Follow fix patterns in [review/fixes/](review/fixes/)
4. Add regression tests per [testing/](testing/) guidelines

### For IRQ Safety Work
1. Read [safety/IRQ_SAFETY_AUDIT.md](safety/IRQ_SAFETY_AUDIT.md)
2. Follow [safety/SYNC_SAFE_MIGRATION_GUIDE.md](safety/SYNC_SAFE_MIGRATION_GUIDE.md)
3. Check [safety/IRQ_LOCK_SITE_INVENTORY.md](safety/IRQ_LOCK_SITE_INVENTORY.md) for lock sites

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

Current gate status for 1.0-Preview: **QUALIFIED**
- ✅ 0 CRITICAL findings
- ✅ 0 HIGH findings
- ✅ All tests passing (17 single-core + 22 SMP)
- ✅ Build/lint clean

See [reports/FINAL_IMPLEMENTATION_STATUS.md](reports/FINAL_IMPLEMENTATION_STATUS.md) for details.

## Recent Audit Rounds

- **R174** (July 2, 2026): Latest comprehensive audit - [audits/qa-2026-07-02-v5.md](review/audits/qa-2026-07-02-v5.md)
- **R173** (June-July 2026): IRQ safety campaign - [fixes/r173-complete-package-summary.md](review/fixes/r173-complete-package-summary.md)
- **R172** (June 2026): VFS/ramfs audit - [audits/qa-2026-06-*.md](review/audits/)
- **R170-R171** (Jan-June 2026): Quota system, cgroup memory safety

## Contributing to Documentation

When adding or updating documentation:

1. **Choose the right location**
   - Architecture docs → `architecture/`
   - Audit reports → `review/audits/`
   - Fix plans/implementation → `review/fixes/`
   - Safety analysis → `safety/`
   - Test plans/coverage → `testing/`
   - Final summaries → `reports/`

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

- **[next-phase-plan.md](next-phase-plan.md)** - Prioritized roadmap for 1.0-Preview
- **[open-findings-executive-summary.md](open-findings-executive-summary.md)** - Executive summary of open findings
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Contributor guidelines
- **[README.md](../README.md)** - Project README
