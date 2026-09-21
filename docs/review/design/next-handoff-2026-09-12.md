# Next implementation handoff — source refresh, 2026-09-12

**Plan:** [v16.0](../nextplan/next-phase-plan-2026-09-12.md).
**Source:** 3254318c5ef19ee9eb23246e14e9e01582af7e28; a84e963 only changes CI budget/docs.
**Scope:** planning and revalidation notes for R188-RF, P0-A, ST-K2-P1 and ST-K4.
**Status:** DRAFT for current-tree implementation; existing user decisions are preserved.
**Review:** author source review and independent scoped refresh review by
`/root/ci_repair_review` complete on 2026-09-12. This verifies the source bridge
and DRAFT boundaries, not a full mechanism review or implementation acceptance.
No runtime code, allocation model or syscall is implemented by this record.

## 1. Why old designs need a source bridge

The September 1 designs precede KSA's ordinary fd 0/1/2 objects, pinned filesystem
identity, namespace retirement, credential lifecycle, owned BIO and page-table
ownership repairs. Their original risk analysis is valuable; stale line numbers
and old representation assumptions must not be copied into a new implementation.

Read the existing full designs:
[P0-A](p0-a-r186-4-admission-closure-design.md),
[ST-K2](st-k2-map-shared-design.md),
[ST-K4](st-k4-fsync-writeback-design.md).
This note overrides only the obsolete premises listed below. It does not
retroactively alter historical approvals or validation.

## 2. R188-RF — evidence reconciliation before closure credit

**Risk/depth:** review action; no dedicated kernel design or waiver needed.
The September 1 plan made R188 original review a prerequisite for P0-A closure.
The newer KSA review independently accepts a different 20-finding rubric; its
existence alone does not prove every original R188 actionable was reviewed.

Input set: [R188 audit](../../security/full-codebase-audit-2026-08-07.md),
August plan, KSA audit, final KSA review and current relevant source. The
[source ledger](../../security-audit-status.md#record-provenance) identifies the
local historical records; absent original artifacts leave their mapping rows
verification pending.

Deliver an original-ID → final code → independent review → gate mapping.
Reuse KSA overlap only where the original invariant and tested revision match.
Review uncovered original repairs independently; a substantive defect enters
the queue at its own impact/priority. No new full-audit streak credit follows
from administrative mapping or an unchanged old PASS. Missing historical
artifacts mean verification pending for that row, not an invented failure/pass.

## 3. P0-A / R186-4 — current allocation and ownership premises

**Risk:** shared allocation/accounting and concurrency; full design and independent
mechanism/change review required. The previous mechanism-review decision stands.

| Current source | Observation / implementation constraint |
| --- | --- |
| [MmState](../../../kernel/kernel_core/process.rs), mmap_regions/pt_charged_frames | Already AdmittedMap; preserve installed/retired capacity ownership rather than reintroduce raw maps |
| [fork_inner](../../../kernel/kernel_core/fork.rs), snapshot reservation and from_sorted_vec_charged | Raw snapshot allocation still precedes class admission; reservation must precede allocation and transfer once to the adopted buffer |
| [admitted.rs](../../../kernel/mm/admitted.rs), from_sorted_vec_charged | Infallible shrink_to_fit still exists; actual allocated capacity governs the charge |
| [heap_admission.rs](../../../kernel/mm/heap_admission.rs) | Reserved and committed lanes must remain separately symmetric; use its actual sizing/receipt APIs |
| [runtime tests](../../../kernel/src/runtime_tests.rs), VMA coexistence/pressure/fork | Preserve tests but replace any constant-only or deferred success-path acceptance with discriminating live outcomes |

Do not pre-reserve and then call a constructor that reserves the same amount
again. Do not release the first reservation and reacquire under pressure.
Use the existing full design's single transfer and capacity-sized accounting;
review both zero-length and extra-capacity inputs against current API contracts.

Regression oracles: admission rejection before heap growth; reserved lane back
to baseline after every commit/rollback; committed delta equal to owned capacity;
allocation/PT/child-publication failure releases once; remove-retaining-capacity
remains charged until actual retirement; fork/exec/unmap/reap under pressure do
not leak, undercharge, deadlock or panic. Include current credential and shared
supervisor-table cleanup, not a pre-KSA partial-child model.

Gate set on the final affected source: hosted MM/core, VMA runtime tests, build/
lint/fmt/Clippy, boot, musl, SMP/resource pressure and independent review. Do not
close R186-4 from the hosted tests or AdmittedMap field declarations alone.

## 4. ST-K2-P1 — honest mmap flags and usable stress reports

**Risk:** Linux ABI and guest/host protocol. Preserve the reviewed two-phase plan:
Phase 1 is flags validation plus pipe reports; Phase 2 adds shared-anonymous
memory after admission/ownership prerequisites.

[sys_mmap](../../../kernel/kernel_core/syscall.rs) currently uses fd >= 0 to
reject file mappings and forwards flags to the LSM hook, but does not implement
the complete flags contract. [stress_runner.c](../../../userspace/stress_runner.c)
still uses MAP_SHARED report pages. These premises remain live.

Phase 1 accepts the documented private-anonymous supported shape and rejects
unsupported MAP_SHARED/MAP_SHARED_VALIDATE/MAP_FIXED/unknown forms after policy
evaluation, with the original EOPNOTSUPP contract. No unsupported flag may appear
successful with private behavior. File-backed mappings remain unsupported.

Replace report-page sharing with explicit pipe records only in the relevant
guest workers. Validate partial reads/writes, EINTR, EOF before completion,
child failure, fd closure and exact per-worker identity/counts. Close unused
pipe ends on every parent/child error path; bounded buffers must not deadlock
the parent waiting for a child whose report cannot drain.

The memory workload must hit its intended cgroup charge limit before the VMA
map-count cap. Keep operations/oom_events/restoration discriminating; don't
turn a missing report into a zero-work PASS. Real memory/cpu/process profiles
must satisfy the existing stress-v2 validator and the 900-second scope.

Phase 2 remains outside this initial implementation slice: PAGE_REF_COUNT is
the frame lifetime owner; first-toucher charging and its accepted rmdir-EBUSY
consequence remain. Recheck RF180-20 supervisor-table ownership, COW exclusion,
try-only fault locking, usercopy, migration and every by-length uncharge site
before implementing the old Phase 2 design. The revalidation also covers the two
procfs mapping/flags consumers, the currently unconsumed `mmap.toml` and fuzz
corpus assumptions, TGID-scoped futex limitations, and exec's shared-address-space
and transient-state gates. These are part of the Phase 2 blast radius even when
the Phase 1 flags/pipe slice does not modify them.

## 5. ST-K4 — refresh durability against file objects and namespaces

**Risk:** storage durability, authorization, lifetime and shared block state.
The original device-flush depth, all four syscall numbers and guest block/crash
workload scope remain. Per-inode writeback was rejected previously; do not
silently restore that abandoned implementation.

Changed premises:

| Old premise | Current source / required replacement |
| --- | --- |
| fd 0/1/2 are always consoles | Ordinary entries are accepted under KSA-005. Decide fsync admissibility from the resolved FileOps/object kind, never the numeric fd. A regular file duplicated onto fd 1 must behave like that file. |
| Looking up a path/current namespace locates an open fd's filesystem | KSA VFS context/identity/pivot/retirement changes require the opened object's pinned filesystem/mount lifetime. A cwd/pivot/namespace change must not retarget a flush to an unrelated filesystem. |
| Raw BIO buffers/callbacks can be reused | KSA-018 supplies owned BIO/completion contracts. Keep completion and potentially reentrant flush callbacks outside queue/registry locks. |
| A write-through cache dirty bit means all bytes are durable | Recheck current ext2 write/flush/journal completion, poison and cached-write ordering. Dirty state alone is not evidence of a completed device barrier. |
| Host block validator implies an implemented guest | The guest still explicitly fails fsync_unsupported. Implement real block records, writes/flushes/reads and kill/recovery evidence in the same item. |

Sources: [FD/syscall dispatch](../../../kernel/kernel_core/syscall.rs),
[FileOps interface](../../../kernel/kernel_core/process.rs),
[VFS FileHandle/FileLifetime](../../../kernel/vfs/traits.rs),
[VFS manager](../../../kernel/vfs/manager.rs),
[namespace operations](../../../kernel/vfs/operations.rs),
[mount ownership](../../../kernel/vfs/path.rs),
[Ext2](../../../kernel/vfs/ext2.rs),
[BIO](../../../kernel/block/src/lib.rs),
[virtio-blk](../../../kernel/block/src/virtio/blk.rs),
[stress guest](../../../userspace/stress_runner.c) and
[host protocol](../../../scripts/gates/stress/stress_protocol.py).

Current-tree design acceptance must trace the exact open-object → owning FS →
device flush path, errors, locks and retirement. Preserve bad/closed/O_PATH,
pipe/socket, read-only regular file and directory cases by kind; include a
regular file dup2'd to 0/1/2. Distinguish operation failure/unsupported barrier
from successful persistent flush. Never acknowledge a no-op flush as physical
durability when the device lacks a supported guarantee.

The current representation is concrete: `FileHandle.owner` in `traits.rs` is
`FileLifetime::Filesystem(Arc<dyn FileSystem>)` or
`FileLifetime::Mount(Arc<path::Mount>)`; the latter owns `mount.fs`.
`FileHandle::clone` preserves that owner and the shared offset/status object.
There is no current `filesystem_for_inode` helper. Resolve and clone the handle
under the PCB lock as the existing `vfs_readdir_callback` does, release that
lock, then access the owning filesystem through an internal FileHandle method.
Do not reacquire an inode's filesystem from a namespace registry or retain the
PCB/shared-offset lock during flush. An open descriptor must keep both inode
and mount/filesystem alive until completion, even if the namespace table retires.

`Vfs.mount_tables` now holds admitted namespace-table owners in `manager.rs`;
`operations.rs` owns materialization/removal, and `path.rs` owns `MountView`.
The global/namespace `sync` policy must therefore define its set of visible
filesystem instances and clone owners before releasing registry/topology locks.
Snapshot allocation must be fallible/admitted, filesystem IDs must be deduplicated,
and a concurrent namespace retirement must not turn a pinned target into a dangling
reference. Enumeration failure and partial flush failure cannot disappear into
the current default `FileSystem::sync() -> Ok(())`.

The block trait's default `flush` returns NotSupported, whereas current virtio-blk
returns `Ok(())` when `VIRTIO_BLK_F_FLUSH` is absent, assuming write-through.
That assumption is insufficient for a persistent fsync contract. The full ST-K4
amendment must add a trustworthy device durability capability (actual flush,
explicitly guaranteed write-through, or unsupported) and propagate unsupported
or failed guarantees through Ext2 and the syscall. Volatile ramfs success must
remain explicitly volatile; it is not evidence of persistent-media durability.
Keep this amendment scoped to the device-flush design; do not introduce a new
per-inode writeback engine as an incidental change.

For sync and sync_file_range, explicitly document the limited supported scope
and Linux divergence from the inherited device-flush plan; don't label the
whole family full Linux writeback semantics. Check signed offsets/ranges/flags,
pledge/seccomp dispatch parity, poisoned mounts and failure propagation.

Oracles: measured flush invocation/completion after call entry; injected device
failure cannot return success or discard dirty/error evidence; descriptors keep
the same owner across pivot/teardown; stress block round has exact valid_slots,
bytes/checksum/generation records; kill/reopen replay proves the supported
journal contract with a non-default cache policy as needed. Guest completion,
host validation and restored storage identity are all required.

**Current readiness:** the fd/namespace/BIO adaptations are implementation-
blocking source changes to the September 1 design. This note identifies them
and preserves decisions; ST-K4 is DRAFT until the full per-file contract and
independent review are updated. The other plan work is unaffected.

## 6. Acceptance and amendment record

| Date | Change | Safety impact | Review state |
| --- | --- | --- | --- |
| 2026-09-12 | Restore R188/P0-A/ST-K2/ST-K4 handoff alongside scoped KSA closeout | No runtime changes; prevents lost admission/stress obligations and stale FD/ownership assumptions | Author source review and independent scoped review by /root/ci_repair_review |
| 2026-09-12 | Correct FileOps/FileHandle source links and explicitly bind the plan to FileLifetime, current mount registries and real flush capability | Reviewer-confirmed obsolete source assumptions removed from the current handoff; old design remains dated/DRAFT | Independent reviewer reconfirmed the updated §5 against source; full ST-K4 mechanism amendment still pending |

The independent review confirmed P0-A's pre-admission snapshot/shrink paths and
ST-K2's flags/report-page premises. It identified the FileOps source misreference
and obsolete filesystem lookup; the updated §5 and old design header resolve
those documentation findings. The PO ledger's unmapped labels remain explicitly
verification pending in the current plan.

Future implementation uses kernel-implement after the appropriate review-stage
inputs. This planning task does not execute a kernel repair, hardware run or
new audit. Existing choices do not need another interview; genuine changes to
explicit user decisions must still be identified.
