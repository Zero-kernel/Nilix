# Nilix Documentation

Start with the current capability and execution records. Older overview,
audit and completion documents are dated evidence and can describe superseded
implementations; a historical COMPLETE heading is not a current product claim.

## Current entrypoints

| Need | Document |
| --- | --- |
| What the kernel can do and what is missing | [Roadmap](roadmap.md) — all 25 kernel libraries, component capabilities, Linux gaps, trust boundaries and release conditions |
| Priorities, dependencies and implementation handoff | [Current nextplan](next-phase-plan.md) — full September 12 rollover; both KSA and older open queues |
| Execution paths and crate graph | [Architecture](architecture.md); capability availability is governed by the roadmap |
| Run tests and read reports | [CI/testing guide](ci-testing.md), [quality gates](quality-gates.md), [scripts](../scripts/README.md) |
| Audit acceptance vs release readiness | [Security status](security-audit-status.md) |
| Supported VT-d/platform modes | [VT-d matrix](vtd-support-matrix.md) |
| Experimental livepatch limits | [Livepatch support](livepatch-support.md) |
| Stress failure history and open profile contracts | [Stress-v2 historical record](stress-gate-status.md) |
| Recent changes | [Commit history](https://github.com/Zero-kernel/Nilix/commits/main/) |

## Current state

The kernel runs static Ring-3/musl programs and has substantial MM/process/VFS/
network/SMP/security infrastructure. KSA-001..020 are accepted within their
rubrics, and the QEMU EDU slice is accepted. Physical VT-d, full KPTI, compiler
retpoline and production livepatch remain unqualified or unsupported.

**1.0-Preview is blocked.** R186-4 admission closure, historical review lineage,
all-six stress acceptance and strict profile/full-audit conditions remain;
the recorded clean-audit streak is 0/3. The roadmap and nextplan keep current
counts and evidence limits together.

## Architecture and subsystem references

- [Readable architecture](architecture.md): composition, layering, boot, syscall
  and component paths.
- [Current design records](review/design/README.md): item-specific invariants,
  decisions, current-source amendments and acceptance oracles.
- Local historical references: `docs/overview/architecture/ARCHITECTURE.md`,
  `docs/overview/02-architecture/subsystems/` and `docs/design/`. These are
  maintainer archives, outside the files distributed by a normal clone.

## Audit, repair and plan history

| Collection | Purpose |
| --- | --- |
| [Audits](review/audits/) | Dated original findings, including KSA-2026-09-06 |
| [Fixes](review/fixes/) | Repair ledgers, source/evidence handoffs and scoped reviews |
| [Review-fix](review/reviewfix/) | Independent verdicts and repair acceptance |
| [Nextplan archive](review/nextplan/) | Full rollovers and historical status addenda |
| [Standalone security records](security/) | R188 and other standalone investigations |
| [Remediation archive](review/remediation/) | Historical debt inventories |
| Local `docs/overview/testing/` archive | Older test expansion/coverage design |
| Local `docs/overview/06-security/safety/` archive | IRQ/locking and primitive migration references |
| [Fuzz investigations](fuzz/) | Historical crash triage and filesystem evidence |

The [security status and source ledger](security-audit-status.md#record-provenance)
summarize the September 11 software acceptance and September 12 QEMU device
evidence, retaining the original record identities. Archive indexes can be
public even when their underlying local audit artifacts are not distributed.

## Maintaining these documents

Use one current capability inventory (roadmap) and one complete dated nextplan.
Keep README/README_zh summaries aligned with them. Preserve source/evidence
links, rejected or deferred capability boundaries and every open plan item.
Use meaningful component/test evidence rather than file counts or lifetime
audit totals as a maturity score.

Documentation-only updates require link/reference and consistency checks.
Remote synchronization applies at relevant validation/handoff boundaries under
the local project contract; it is not a per-edit dual-write rule.
Commit/push follows user authorization.

## Contributor entrypoints

[CONTRIBUTING](../CONTRIBUTING.md) · [GOVERNANCE](../GOVERNANCE.md) ·
[SUPPORT](../SUPPORT.md) · [SECURITY](../SECURITY.md) · [README](../README.md)
