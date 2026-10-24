# Current planning designs

Start with the [October 22 handoff](next-handoff-2026-10-22.md): the R191 records and
residual gaps and the next implementation group (ST-K2-P2a, implemented 2026-10-23 per its
[design](st-k2-p2a-lazy-preflight-design.md); NEXT is now TD-LSM-1), which
supersedes the plan and storage notes of the [October 20 handoff](next-handoff-2026-10-20.md)
for the GAP-5/6 thread and scheduler work (itself superseding the [October 17 one](next-handoff-2026-10-17.md)). The [September 12 handoff](next-handoff-2026-09-12.md)
and its [plan](../nextplan/next-phase-plan-2026-09-12.md) still govern the P0 and
ST-K items below.

| Design | Scope | Current status |
| --- | --- | --- |
| [P0-A / R186-4](p0-a-r186-4-admission-closure-design.md) | Admission, ownership and live accounting oracles | Current-tree mechanism review and validation required |
| [ST-K2](st-k2-map-shared-design.md) | Phase 1 flags/pipe reports; Phase 2 shared-anonymous memory | Phase 1 source refresh; Phase 2 ownership revalidation required |
| [ST-K4](st-k4-fsync-writeback-design.md) | Four durability syscalls and guest block/recovery workload | DRAFT until current object/namespace/device contracts are reviewed |
| [ST-K2 lifecycle](st-k2-shared-fault-lifecycle-design.md) | Shared-fault PT ledger, teardown and migration | Implemented; scoped lifecycle review passed; its preflight item is ST-K2-P2a |
| [ST-K2-P2a](st-k2-p2a-lazy-preflight-design.md) | Syscall preflight (`verify_user_memory`) resolves lazy pages through a guarded, content-preserving access instead of rejecting them | Implemented 2026-10-23, independently reviewed, final-tree gates pass (ring3-mm preflight leg PASS); pending the next `kernel-security-audit` |
| [D0-ISO-1](d0-iso-1-user-identity-map-boundary-design.md) | User/kernel boundary over the low identity map kept in every user address space: ownership walk, usercopy page checks, VMA/brk refusal, page-table manager guards, CR0.WP on the BSP (R192-1..3) | Implemented 2026-10-23 (Approach B, then Approach A and the KPTI user-root mirror in the follow-up), independently reviewed; pending stage-3 review-fix; R192-RES-2 (eager population) implemented 2026-10-23 in its own design |
| [R192-RES-2](r192-res-2-bounded-eager-population-design.md) | Eager population (`brk` grow, private `mmap`, `mprotect` Path A, `mremap` tail) in bounded, all-or-nothing page-table holds with no allocation under the lock; fixes four pre-existing defects the design review found (LEAD-MREMAP-RELOC-UAF-1 CRITICAL, LEAD-MREMAP-ROLLBACK-FLUSH-1, LEAD-ROLLBACK-PRUNE-LEDGER-1, LEAD-MREMAP-MIGRATE-1) and one the code re-review found (LEAD-PT-ZERO-LINK-1) | Implemented 2026-10-23 by interview; independently reviewed over three rounds, findings fixed; final-tree gates pass (ring3-mm 44/0 in 256 MiB and 3 GiB guests, hosted 545); pending stage-3 review-fix; residual R192-RES-2a (mremap relocation move) open |
| [ST-K3 process lifecycle](st-k3-process-lifecycle-design.md) | `waitid`, ROOT-INIT registration, F2 frameless-fork refusal, Ring-3 lifecycle oracles | Implemented 2026-09-25; hosted and Ring-3 oracles pass; independent high-risk review pending |
| [Handoff 2026-10-22](next-handoff-2026-10-22.md) | After the R191 fix: associated records, R191 residual gaps, next group besides review-fix (ST-K2-P2a, TD-LSM-1, TD-SERIAL-1, TD-USERCOPY-1), carried thread debt, nilix-dev storage after cleanup | Priorities only, written 2026-10-22; each item names its design work |
| [Handoff 2026-10-20](next-handoff-2026-10-20.md) | Thread groups enabled by default after every known gap closed (exec from a thread group, G7, G8, procfs, futex parity, PI futexes, F9, the soak-found fixes); next: stage 2-3 over the batch, then thread and serial-lock debt | Rewritten 2026-10-21; reviewed, final ladder on `src22` passes except 8-CPU musl-check (console interleaving) |
| [Handoff 2026-10-17](next-handoff-2026-10-17.md) | What the GAP-5/6 series (`9ae1674..bd487f0`) landed, twelve open items ordered by what blocks default thread enablement, and the next plan: scoped security audit, leader exec, 16-CPU and soak runs for threads, enablement decision | Written 2026-10-17; everything in it is verification pending |
| [GAP-5/6 threads and scheduler status](gap-5-6-threads-scheduler-status-2026-09-28.md) | Shared `SignalTable`/`FsContextHandle`/`FilesTable`, thread groups and musl pthreads in the guest-only preview, futex requeue/bitset, W-3/W-4 selective wait, F4/F6 sentinel, F7 inventory, 2–64 CPU qualification, pressure soak and `/proc/schedstat` metrics | Updated 2026-10-17 (final kernel g60, runner g63): QUALIFIED 0 failed on 2/4/8/16 CPUs; thread legs pass on 1/2/4/8 CPUs; memory/cpu/smp soaks QUALIFIED; F8 and F10-F15 fixed (independent review pending), F9 open; thread flags still `EINVAL` in default builds; nothing DONE |
| [GAP-5 slice 3: `FilesHandle` design](gap-5-slice3-files-handle-design.md) | Shared fd table: charge ownership, lock order, last-reference teardown, exec unshare, four gated migration steps | Steps 1-3 implemented 2026-10-17 (`FilesTable`, owner count, `CLONE_FILES` inside a thread group), verification pending; exec unshare (step 4) open |
| [GAP-5 slice 4: thread groups design](gap-5-slice4-thread-group-design.md) | Thread groups (`CLONE_VM`, `CLONE_SIGHAND`, `CLONE_THREAD`): verified gaps G1-G8 (tree/reaping, group death, clear-tid, futex prepare, identity, signals), futex ABI for musl pthreads, seven gated steps | Steps 1-7 done 2026-10-20: G1-G8, exec from any thread, futex parity and PI; the thread flags are enabled in every build (`thread_preview` removed); reviewed D3-D5 debt recorded; final-tree gates in the [status record](gap-5-6-threads-scheduler-status-2026-09-28.md) "Fourth batch" |

The older full designs preserve the September 1 decisions and dated evidence.
Their September 12 handoff amendments take precedence over obsolete source
representations and line numbers. A historical READY heading does not grant
current implementation acceptance. Other designs remain in the local archive.

The September 12 plan still lists **F2** and **ROOT-INIT** as open. Both were
closed on 2026-09-25; see the ST-K3 process lifecycle record for the change
and its executed evidence. The plan is left unedited as a dated record.
