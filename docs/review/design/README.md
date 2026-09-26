# Current planning designs

Start with the [September 12 handoff](next-handoff-2026-09-12.md) and
[current plan](../nextplan/next-phase-plan-2026-09-12.md).

| Design | Scope | Current status |
| --- | --- | --- |
| [P0-A / R186-4](p0-a-r186-4-admission-closure-design.md) | Admission, ownership and live accounting oracles | Current-tree mechanism review and validation required |
| [ST-K2](st-k2-map-shared-design.md) | Phase 1 flags/pipe reports; Phase 2 shared-anonymous memory | Phase 1 source refresh; Phase 2 ownership revalidation required |
| [ST-K4](st-k4-fsync-writeback-design.md) | Four durability syscalls and guest block/recovery workload | DRAFT until current object/namespace/device contracts are reviewed |
| [ST-K2 lifecycle](st-k2-shared-fault-lifecycle-design.md) | Shared-fault PT ledger, teardown and migration | Implemented; scoped lifecycle review passed |
| [ST-K3 process lifecycle](st-k3-process-lifecycle-design.md) | `waitid`, ROOT-INIT registration, F2 frameless-fork refusal, Ring-3 lifecycle oracles | Implemented 2026-09-25; hosted and Ring-3 oracles pass; independent high-risk review pending |

The older full designs preserve the September 1 decisions and dated evidence.
Their September 12 handoff amendments take precedence over obsolete source
representations and line numbers. A historical READY heading does not grant
current implementation acceptance. Other designs remain in the local archive.

The September 12 plan still lists **F2** and **ROOT-INIT** as open. Both were
closed on 2026-09-25; see the ST-K3 process lifecycle record for the change
and its executed evidence. The plan is left unedited as a dated record.
