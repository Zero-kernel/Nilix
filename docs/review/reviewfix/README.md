# Review-Fix Reports

Stage-3 (`kernel-review-fix`) verdict + repair reports: `reviewfix-{YYYY-MM-DD}[-vN].md`.

Naming/versioning/discovery rules are identical to the QA reports in `../audits/`
(`.claude/skills/shared/loop-protocol.md` § 2). The round number equals the audited round whose
fixes are reviewed; defects are numbered `RF{N}-{k}`.

- `reviewfix-2026-07-17.md` — R180: 4 PASS / 8 PARTIAL / 4 FAIL; 8 re-repaired,
  4 escalated; final 12/18 HIGH closed.
- `reviewfix-2026-07-19.md` - R180 continuation: RF180-52 PARTIAL corrected by RF180-54;
  RF180-55 separately fixed musl artifact identity; final 32/32 implementation findings closed;
  design findings and zero-HIGH streak remain open.
- `reviewfix-2026-07-19-v2.md` - authoritative R180 convergence follow-up: RF180-54/55 re-opened
  as PARTIAL and re-repaired by RF180-56..59; complete SMP oracle/window/supervisor,
  independently bounded duplicate-free single-BSP admission, and isolated final-musl-package
  provenance.
- `reviewfix-2026-07-29.md` — **R186 fix review (current).** 10 defects filed and repaired
  (`RF186-1`…`RF186-8`, `RF186-11`, `RF186-12`): 2 outright FAIL — R186-1's fix relocated the
  open/openat PCB recursion, R186-10's COW retry budget made cross-CPU contention user-fatal — and 8
  PARTIAL. Adds typed BAR-aperture authority + all-or-nothing MMIO transactions, an owned credential
  authorization span, allocation-free `cgroupfs` readdir, ext2 dirent/inode type binding, and a
  `#[must_use]` two-phase mediated `CapTable` mint. **MODE S** (Codex unreachable) — converged but
  unwitnessed; `RF186-4`/`RF186-7` flagged for re-derivation. Records host unit-test execution debt.
