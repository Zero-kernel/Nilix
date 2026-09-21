# ST-K2-P2 — Shared fault lifecycle and PT accounting follow-up

**Date:** 2026-09-20; verification follow-up 2026-09-21
**Status:** IMPLEMENTED; scoped lifecycle review passed. Current Ring-3 result is
13 PASS, 0 FAIL and 1 explicit PTE-only preflight SKIP (observed EFAULT).
Final-region refcount/buddy/charge and local forced Busy/saved-IF=0 probes execute;
the dedicated shared-mmap musl gate passes. Complete race/failure qualification remains pending.
**Authorization:** Continue the two user-named Nilix issues, including shared-anonymous
fault, teardown and accounting evidence. File mappings and shared `mremap` remain unsupported.
**Baseline:** `6f072978513f236354b0dde720375fd69d053398`.
**Review:** Independent read-only reviewer `/root/shared_review` passed the final scoped
patch, including admission-order correction and cgroup fixture cleanup. No full audit claimed.
On 2026-09-21 the same reviewer independently checked the final five-oracle additions;
no remaining definite code defect was found within their stated scope.

## 1. Requirements and evidence

The 2026-09-14 amendment in `st-k2-map-shared-design.md` claims a `SharedPage.charged_bytes`
repair absent from this baseline. Do not restore that proposed mechanism: page tables can
outlive a shared region while serving an adjacent private VMA. Region teardown may release
DATA accounting; PT accounting follows physical table lifetime and the address space.

The baseline fault ignores VMA transient/fork state, permitting remap between munmap PT
teardown and side-map removal. Munmap's shootdown is conditional on immediately freeable
DATA frames, omitting shared leaves with a region pin. Late concurrent not-present faults
also treat an already-installed shared leaf as fatal, and reserve charge before noticing it.

## 2. Invariants and threat model

Ring-3 controls shared mappings and CLONE_VM races. Preserve try-only fault locking,
charge-before-publication, PAGE_REF_COUNT ownership, writable fork sharing, and canonical
Process -> MmState -> region -> PT -> buddy order. Never free a leaf before synchronous
address-space TLB invalidation. Never uncharge a PT frame while it remains reachable.

## 3. Transaction exclusion and repeated faults

Under MmState, require an exact committed shared VMA matching the region and reject
transient/fork reservations with Busy. Missing metadata is NotShared. Check an already
resident matching leaf under PT_LOCK before any charge/refcount change, accepting only
matching physical frame and PRESENT/USER/W/NX permissions; invalidate the local stale TLB.
The same MmState hold prevents legitimate mapping changes between this check and install.

## 4. PT ledger design and alternatives

Use a separate admitted per-AS `shared_fault_pt_frames` map. Mmap publication and fork
preparation reserve `existing ledger length + sum(region PT/PD/PDPT span bounds)` storage.
Spans use checked interval arithmetic at 2 MiB, 1 GiB and 512 GiB boundaries. Separate
storage prevents eager mmap/brk paths consuming fault reservations. Reject metadata OOM
before publication; fault never expands storage. Its fixed allocator cannot allocate more
PT frames than remaining reserved slots. Reserved insert records actual physical identities.

Success and failed-map retention both record surviving tables. Rollback removes freed
identities from its fixed frame array. Any conservative charge-refund surplus remains in
the existing inherited basis. DATA stays on the region's first-toucher owner; PT follows
the address space on migration. Fork's existing copied-table inherited basis is unchanged.

I': `pt_charged_bytes = pt_inherited_bytes + 4096 * (eager_ledger.len + fault_ledger.len)`.
Brk shrink, munmap and private mremap shrink reconcile both maps before returning freed
tables to buddy. Fault ledger removal retains reserved capacity while a region remains;
exec/last-exit clear it. Rejected alternative: putting PT bytes on the region (early uncharge).

## 5. TLB and cleanup

Munmap tracks whether any leaf was removed independently of refcount's final-free result.
Synchronously shoot down the range before releasing the region pin or any deferred DATA
frame. PT prune/free retains its existing clear -> flush -> remove-ledger -> free order.

## 6. Validation and limits

Run hosted provenance/admission regressions plus guest first-touch (including controlled
usercopy), fork-before-first-touch visibility, teardown and repeated allocation cycles.
Keep adjacent private mappings live to disprove premature PT uncharge. Require build/lint,
runtime, boot, four-CPU SMP and musl gates, preserving qualified/blocked outcomes.

Busy now explicitly drains the lock-free local shootdown mailbox while #PF has IF=0
and AC=0, before retry. This preserves the single-consumer rule and lets a remote PT
lock holder receive its ACK even when usercopy's saved IF is zero; it does not enable
interrupts or convert transient contention into EFAULT. Same-CPU PT reentry is diagnosed.
The cross-page uname oracle now forces one Busy return from guarded usercopy, followed
by successful retry. The consuming CPU is recorded atomically; after the helper returns,
the handler asserts saved CPL=0 and saved RFLAGS.IF=0 and uses its bounded, lock-free
serial writer. The hook is default-off and wired through kernel/arch/kernel_core's
`syscall_test` features. It neither holds a remote PT lock nor queues a remote shootdown;
a runtime oracle proving a remote holder receives its ACK remains pending.
The complete acceptance remains pending where evidence is absent: same-CPU PCB/MM
lock reentry is not solved by that mailbox drain (the hosted test covers PT try-lock only),
PTE-only syscall preflight rejects a valid lazy shared buffer with EFAULT, and concurrent
last-owner/parent-unmap-first lifetime and CLONE_VM fault/unmap/exec/exit races need dedicated probes. These
are not proved by hosted metadata tests or by marking an EPERM migration attempt PASS.
The new quiescent guest last-region oracle uses an actual managed frame and two region
Arcs: releasing the mapping reference leaves one region pin, a non-final Arc drop retains
the pin, frame and charge, and the final drop restores the refcount slot, buddy free-page
total and root-cgroup DATA counter. It does not observe physical-address reuse or an SMP race.
The current task does not claim those broader paths accepted merely by adding local fixes.
Private mmap/brk/mprotect/mremap failure rollback also invokes generic table prune without
reconciling either identity ledger. An empty PD retained by shared-fault OOM can later be
pruned there, leaving stale charge/provenance until AS teardown. This pre-existing family
needs rollback limited to transaction-owned tables or a carried reclaim transaction;
the present three successful shrink/unmap paths do not prove complete failure cleanup.

The VFS cgroup-rmdir mapping already exists (`CgroupError::NotEmpty` -> `FsError::Busy`
-> EBUSY), and deletion checks origin `mem_pinned`. The new guest executes that boundary:
resident shared DATA keeps its first-toucher cgroup busy after the task migrates;
last munmap releases the charge and rmdir succeeds. An untouched region has no DATA owner
yet; its heap metadata reservation alone does not pin the creator's cgroup. This follows
the existing first-toucher policy rather than introducing an origin-at-mmap owner.

Current feature boundary: private anonymous/PROT_NONE mremap grow, shrink and MAYMOVE
already exist and run in the Ring-3 fixture; file-backed mmap, shared mremap, FIXED and
DONTUNMAP remain unsupported. The earlier description of all mremap as an ENOSYS stub
is historical. This follow-up changes shared PT reconciliation used by private shrink,
not the scope of those supported ABIs or acceptance of the whole mremap transaction.

## 7. Handoff

Update the living shared design and CURRENT plan with measured outcomes. Independent
change review and final-tree gate evidence determine acceptance, followed by an authorized
`kernel-security-audit` of the timer and changed MM paths.

## 8. Earlier executed evidence (2026-09-20)

Both copies are isolated on `40c-devbox-ts`, based on
`6f072978513f236354b0dde720375fd69d053398`; QEMU 6.2 and the pinned nightly toolchain.
The primary `/tmp/zero-os-nilix-20260920` runs the comprehensive gates; the separate
`/tmp/zero-os-nilix-ring3-20260920` validates the final test-only fixture amendment
without mutating the tree while other checks run. Their APIC, IRQ, fork, process and
syscall sources have identical SHA256 values in the saved `evidence-summary.json`.

The dedicated fixture is **already root** (`create_process` with ppid=0). The old test's
claim that every attach refusal meant euid=65534 was false. `create_process` deliberately
leaves cgroup membership registration to the caller; missing membership makes migration
return TaskNotAttached/EIO. Only `cfg(feature="syscall_test")` now admits root membership
before scheduler publication. Admission failure cleans the unscheduled PCB; scheduler
rejection detaches first; normal exit detaches from its current cgroup. No credential
change or general `create_process` policy change was made.

| Execution | Result and oracle |
| --- | --- |
| Baseline `make test-ring3-mm` | Make 2 / oracle 1, 10 passed / 1 failed. `memory.current` 45056 -> 57344 -> 53248: 8192 bytes retained after munmap. Baseline serial `/tmp/tmp.9Ph661vlj8`. |
| Earlier `make test-ring3-mm` | **Exit 0, 13 passed / 0 failed, PID 1 exit 0** before adding the preflight and forced-Busy probes below. Serial `/tmp/tmp.Iz1ls2JQkQ`; two kernel-mode PF err=2 observations in cross-page uname copyout. |
| Shared fork + teardown | Parent write visible to child; child first-touches a previously absent second page; parent faults in the same contents after reaping. Counter 49152 -> 61440 -> 49152. |
| Adjacent private PT lifetime | Three cycles: shared munmap refunds DATA only while the private neighbor keeps PT live; final private munmap restores the exact baseline. Initial low-address fixture hit the supervisor identity map; the accepted fixture uses 128 GiB. |
| Migration + VFS rmdir | Counter 49152 -> 61440 -> **4096** at the origin after task migration. Rmdir returns EBUSY with resident shared DATA; last munmap yields zero and rmdir succeeds. No permission refusal is counted as PASS. |
| Hosted | Exit 0, 444 unit tests including new capacity/provenance regression; kernel-core 73/73. Guest syscalls/faults are not inferred from hosted results. |
| Build/lint/base musl | Exit 0. Final lint includes the fixture amendment. Basic musl markers do not prove a shared-mmap musl workload. |
| Runtime / boot / 4-core SMP | Underlying gates exit 3 QUALIFIED (make 2): 35/39/0, 28/46/0, 37/37/0; zero failures, existing deferrals, not strict passes. |
| Extra CPU/SMP stress | **Not accepted.** Supplied disk fails host fsck (unknown journal incompatibility); a separately created, checked Ext3 image permits both shared consumers to execute. Their host verdict then fails with `ModuleNotFoundError: gate_log` in `stress_protocol.py:1249`. Preserved artifacts `/tmp/nilix-stress-v2.51qfEygD`; workload markers are not substituted for a gate pass. |

The guest source and embedded ELF are synchronized back locally; ELF SHA256:
`54dd2e9828b6bbb06205c6a69013ce9c48faa820141930e020cd4924b920d8ad`.
Final primary-tree lint and the zero-retry mitigation CI entry pass after merging this
fixture-only delta; ordinary runtime/boot/SMP evidence above predates that delta and is
reused for unchanged production call paths. Exact manifests, logs, negative intermediate
results and the final CI proof are under `.tmp-nilix-20260920/` locally and `.validation/`
in the named remote copies. Neither the original devbox WIP nor Git history was overwritten.

## 9. Five requested verification boundaries (2026-09-21)

Final execution tree: `40c-devbox-ts:/tmp/zero-os-nilix-rerun2-20260920`, detached from
`6f072978513f236354b0dde720375fd69d053398`. The prior dirty validation trees are preserved.
The selected source manifest was checked byte-for-byte before building. No live gate ran
against source files being edited. Local Windows formatting and CRLF-aware diff checks pass.

| Requested boundary | Executed evidence | Remaining limit |
| --- | --- | --- |
| PTE-only preflight | Fresh shared page passed to getrandom without prior touch returns EFAULT; explicit SKIP exactly once. Future PASS requires the exact requested PAGE byte count. | Confirmed functional defect in `verify_user_memory`, not an accepted lazy-buffer ABI. Caller-lock-safe preflight repair is still open. |
| Exact last frame/region release | Real managed frame, mapping-ref release, two region Arcs, intermediate refs=1/free-pages -1/charge +4096, final refs=0/free-pages restored/charge restored. `ST-K2-LAST-REGION-RELEASE PASS: refs=0 frames=1 charge=0` exactly once. | Quiescent boot self-test; no allocator-address reuse, concurrent last-owner or parent-first-unmap proof. |
| Same-CPU reentry | Windows MM hosted 27/27: PT owner recorded while held, nested `try_with_current_manager` returns None, owner cleared on release. | Does not trigger the actual #PF fail-stop guard or exercise same-CPU Process/MmState reentry. |
| Forced Busy / saved IF=0 | `ST-K2-FORCED-BUSY-USERCOPY-IF0` exactly once; CPL0 and saved IF=0 assertions execute; the following uname copyout succeeds across both fresh pages. | Local test injection only. Remote CPU PT-lock ownership, queued shootdown and ACK progress remain unproved. |
| Dedicated musl marker | Actual musl mmap/munmap and waitpid plus raw fork: parent first-touch, child inherited-page write and fresh second-page write, parent visibility; `MUSL-SHARED-MMAP-OK` exactly once. | Does not add file mapping, shared mremap or simultaneous fault/teardown race coverage. |

`KERNEL_TEST_TIMEOUT=120 make test-ring3-mm` exits 0. Serial `/tmp/tmp.LK7tIU8Dvk`
contains 13 passed / 0 failed, one preflight SKIP, both kernel oracle markers exactly once,
and PID 1 terminated with exit code 0. The reused boot harness reports 1 because handled
page faults violate its ordinary hello fixture; the dedicated Ring-3 verdict explicitly
checks terminal failures and the expected demand-fault outcomes.

`MUSL_CHECK_TIMEOUT=180 make musl-check` exits 0. A second execution of the same image,
with `MUSL_CHECK_LOG_DIR` set, also exits 0 and retains
`.validation/musl-final/musl.7ynrWk/serial.log`: dedicated marker once, final libc marker,
PID 1 exit 0 and zero NX faults. Packaged kernel SHA256:
`0c708161818e08c0145ed92abe39d3e7c563b2d5dc80a99b640a6ea60690834d`.

Windows kernel-core hosted is 72/72 (Linux additionally executes its platform-only
usercopy test). Guest integration assertions are not counted as hosted executions.
Final Linux `make test-hosted-subcrates` exits 0 with 445 unit executions (MM 27,
kernel-core 73), CpuLocal doctests and three compile checks; `make lint` and ordinary
`make build` also exit 0. The MM exact-count gate was updated for the new reentry test.
Review corrected missing feature forwarding, exception-context console locking,
the last-frame baseline position and the preflight future-success byte-count check.

Final `make test`, `make boot-check`, and `make test-smp-4core` each exit 2 because
their underlying gates exit 3 QUALIFIED: 35/39/0, 28/46/0 and 37/37/0
passed/deferred/failed. The four-CPU log records online_cpus=4, all three cross-CPU
smoke PASS records, the AP readiness summary and PID 1 exit. None supplies the missing
shared-fault contention oracle. The unchanged Ring-3 evaluator was also replayed over
seven serial fixtures: the positive record exits 0; missing/duplicate Busy,
missing last-release, missing/duplicate preflight, and a failing summary all exit 1.

Retained archive: `.tmp-nilix-20260920/shared-verification-20260921.tar.gz`, SHA256
`d8923208007d97b49fb3e6489495aa05a53b7a61fd0a02008668d5791f0a8fd1`.
The extracted `verification-20260921/verification-summary.json` binds the selected
source and binary hashes to the named remote tree, serial logs and gate outcomes.
All 22 recorded source/binary hashes match the local mirror after copying back the
tested fixtures: syscall ELF `3e0f713f0e6859e3647af7009d5ed6ef059734ce11c07ca3d867fcef09ee0e4b`,
musl ELF `dae47a424c1999773ff6c10f6d3c0c50ec24bbe52ef9f6546711cc643183ba4b`.

Next scoped work: repair PTE-only preflight with safe caller locking; reconcile generic
private rollback table reclamation; add actual same-CPU exception and cross-CPU
PT-lock/shootdown/ACK probes, parent-first-unmap and concurrent final-owner oracles;
repair the standalone stress gate's imports/fault-outcome policy. File-backed mmap and
shared mremap remain separate future features. These limits prevent declaring all of
ST-K2-P2 or the full mremap design DONE. The next independent stage is a scoped
`kernel-security-audit` using this design, final diff and retained manifests/logs.
