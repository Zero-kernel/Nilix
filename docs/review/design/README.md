# Current planning designs

Start with the [October 17 handoff](next-handoff-2026-10-17.md) for the GAP-5/6
thread and scheduler work. The [September 12 handoff](next-handoff-2026-09-12.md)
and its [plan](../nextplan/next-phase-plan-2026-09-12.md) still govern the P0 and
ST-K items below.

| Design | Scope | Current status |
| --- | --- | --- |
| [P0-A / R186-4](p0-a-r186-4-admission-closure-design.md) | Admission, ownership and live accounting oracles | Current-tree mechanism review and validation required |
| [ST-K2](st-k2-map-shared-design.md) | Phase 1 flags/pipe reports; Phase 2 shared-anonymous memory | Phase 1 source refresh; Phase 2 ownership revalidation required |
| [ST-K4](st-k4-fsync-writeback-design.md) | Four durability syscalls and guest block/recovery workload | DRAFT until current object/namespace/device contracts are reviewed |
| [ST-K2 lifecycle](st-k2-shared-fault-lifecycle-design.md) | Shared-fault PT ledger, teardown and migration | Implemented; scoped lifecycle review passed |
| [ST-K3 process lifecycle](st-k3-process-lifecycle-design.md) | `waitid`, ROOT-INIT registration, F2 frameless-fork refusal, Ring-3 lifecycle oracles | Implemented 2026-09-25; hosted and Ring-3 oracles pass; independent high-risk review pending |
| [Handoff 2026-10-17](next-handoff-2026-10-17.md) | What the GAP-5/6 series (`9ae1674..bd487f0`) landed, twelve open items ordered by what blocks default thread enablement, and the next plan: scoped security audit, leader exec, 16-CPU and soak runs for threads, enablement decision | Written 2026-10-17; everything in it is verification pending |
| [GAP-5/6 threads and scheduler status](gap-5-6-threads-scheduler-status-2026-09-28.md) | Shared `SignalTable`/`FsContextHandle`/`FilesTable`, thread groups and musl pthreads in the guest-only preview, futex requeue/bitset, W-3/W-4 selective wait, F4/F6 sentinel, F7 inventory, 2–64 CPU qualification, pressure soak and `/proc/schedstat` metrics | Updated 2026-10-17 (final kernel g60, runner g63): QUALIFIED 0 failed on 2/4/8/16 CPUs; thread legs pass on 1/2/4/8 CPUs; memory/cpu/smp soaks QUALIFIED; F8 and F10-F15 fixed (independent review pending), F9 open; thread flags still `EINVAL` in default builds; nothing DONE |
| [GAP-5 slice 3: `FilesHandle` design](gap-5-slice3-files-handle-design.md) | Shared fd table: charge ownership, lock order, last-reference teardown, exec unshare, four gated migration steps | Steps 1-3 implemented 2026-10-17 (`FilesTable`, owner count, `CLONE_FILES` inside a thread group), verification pending; exec unshare (step 4) open |
| [GAP-5 slice 4: thread groups design](gap-5-slice4-thread-group-design.md) | Thread groups (`CLONE_VM`, `CLONE_SIGHAND`, `CLONE_THREAD`): verified gaps G1-G8 (tree/reaping, group death, clear-tid, futex prepare, identity, signals), futex ABI for musl pthreads, seven gated steps | Steps 1-6 implemented 2026-10-16/17, step 7 staged behind the guest-only `thread_preview`; verification pending (default builds still refuse the flags) |

The older full designs preserve the September 1 decisions and dated evidence.
Their September 12 handoff amendments take precedence over obsolete source
representations and line numbers. A historical READY heading does not grant
current implementation acceptance. Other designs remain in the local archive.

The September 12 plan still lists **F2** and **ROOT-INIT** as open. Both were
closed on 2026-09-25; see the ST-K3 process lifecycle record for the change
and its executed evidence. The plan is left unedited as a dated record.
