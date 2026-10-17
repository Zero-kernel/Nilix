# GAP-5/6 current status: threads/TLS and scheduler/SMP (2026-09-28)

Source plan: [kernel gap implementation plan §5/§6](../../design/kernel-gap-implementation-plan-2026-09-13.md).
Nextplan rows: [next-phase plan](../nextplan/next-phase-plan-2026-09-13.md) (F7, F4/F6, W-3, W-4, F-4).
Tree: branch `gap5-6-threads-scheduler` on top of `cb503cf`, one commit per feature (F8, the GAP-6 base, the thread model, F13, futex/musl, F10, F14, F15, F12, `/proc/schedstat`, F11, stress tooling, `KERNEL_TEST_CPUS`, docs).

## Summary

Updated 2026-10-17. "Preview" means the `thread_preview` cargo feature, which only the
guest test builds (`syscall_test`, `musl_test`) enable; default and production builds
still refuse `CLONE_SIGHAND|CLONE_THREAD|CLONE_FS|CLONE_FILES`.

| Item | Status | Evidence |
|------|--------|----------|
| §5 slice 1: shared `SignalTable` handle | Implemented; shared for real in the preview | Lock order PCB → table (leaf); IRQ delivery try-locks. Sharing is exercised by the ring3-mm thread legs and the musl pthread workload |
| §5 slice 2: shared `FsContextHandle` (root/cwd/umask) | Implemented; shared for real in the preview | Hosted tests; ring3-mm `CLONE_FS` shared-table leg |
| §5 slice 3: `FilesHandle` → `FilesTable` | Steps 1-3 implemented, verification pending | `Process.files: Arc<FilesTable>` behind its own leaf lock, an owner count so only the last owner closes descriptors and returns the charge, and a `CLONE_FILES` branch inside a thread group. Three hosted tests; ring3-mm shared-table leg; musl threads `dup` into the shared table. Exec while shared returns `EBUSY` (unshare open) |
| §5 slice 4: thread groups (`CLONE_VM`+`CLONE_SIGHAND`+`CLONE_THREAD`) | Steps 1-6 implemented, step 7 staged (preview), verification pending | [Slice 4 design](gap-5-slice4-thread-group-design.md): G1 `ThreadGroup` membership, auto-reap and exactly-once leader report; G2 group death; G3 clear-tid without the mmap gate (was a live bug); G4 futex prepare waits out a sibling; G5/G6 identity and namespace check; G7 process-directed target selection, `tkill`/`tgkill`, group stop/continue. Review D1 fixed. g58 and g60 (final kernel): the ring3-mm thread legs pass on 1/2/4/8 CPUs (15 boots) and the musl pthread workload on 1/2/4/8 CPUs (11 runs); 16 CPUs not run. Default enablement waits for exec-from-a-thread semantics and an independent review of G1/G2/G7 and the shared fd table |
| §5 TLS before runnable | Verified in source and guest | `fs_base`/`gs_base` written under the child lock before scheduler admission; the musl workload checks `__thread` values per thread |
| §5 `exit_group` shared exit state | Implemented, verification pending | `ThreadGroup.exiting` is set before `request_exit_group_atomic` wakes the siblings; a new group gets a new `Arc`, so the handle itself is the generation. ring3-mm: `exit_group` from a non-leader ends the group with its status |
| §5 futex operations for pthreads | Implemented 2026-10-17; g58 and g60 gates pass; independent review pending | Linux op decoding; `FUTEX_REQUEUE`/`CMP_REQUEUE` served by waking the would-be requeued waiters (musl's `pthread_cond_broadcast` hung on `ENOSYS`); `WAIT_BITSET`/`WAKE_BITSET` with MATCH_ANY. Hosted decoder test; ring3-mm requeue leg; musl broadcast and timed-wait legs |
| §5 pthread-like static workload | Passes (g58 6/6 and g60 5/5 musl-check on 1/2/4/8 CPUs, with the broadcast and timed-wait legs) | musl `pthread_create`/`join`, mutex contention, TLS, shared fd table: `MUSL-PTHREAD-OK` |
| §5 robust futex list per thread | Per task by construction | `set_robust_list` state lives in each task's PCB and the exit walk runs per task; no thread-specific guest leg |
| §5 exec from a thread group | Open | Returns `EBUSY`; Linux kills the other threads and unshares the fd table |
| §6 W-3 selective-wait over-wake | Implemented, guest-asserted | Ring-3 leg reads `/proc/waitstat` before/after the targeted wait and requires zero over-wakes |
| §6 W-4 nested-zombie rubric | Guest-verified | `test_selective_wait_nested_zombie` passes |
| §6 F4/F6 locked diagnostics and switch sentinel | Implemented | 2/4/8/16-CPU QUALIFIED with 0 failures; reviewed clean |
| §6 F7 stacks/PCB size | Partial | Compile-time PCB ≤ half-stack budget; contiguous stack allocation fails with `ENOMEM` after an admitted RCU reclaim slot; size inventory below. In-place PCB construction open |
| §6 2/4/8/16-CPU qualification | QUALIFIED (not strict), 0 failures, on every tree through the final one (g58 and g60: 2/4/8/16 QUALIFIED 37/37/0) | See gate tables |
| §6 64-CPU reject ceiling | Guest-verified (2026-10-16) | 64 CPUs: 64/64 online, 0 failed. 65 CPUs: MADT rejected, BSP-only fallback, 0 failed |
| §6 F8 (new): buddy metadata on the boot heap | Fixed (QUALIFIED gates, 0 failed; reviewed) | Metadata in boot-reserved frames beside the COW table; `-m 1G` boots |
| §6 F9 (new): boots with 2 GiB of RAM or more panic | Open, recorded | Pre-existing; early-boot direct-map limit (bootloader/mm work, outside §6) |
| §6 F10 (new, pressure soak): `fork` `ENOMEM` after about 10,000 process creations | Fixed; soak-verified | PID reuse window and geometric table growth. The cpu profile then completed its window twice (g56x1: 6,733 rounds, g56x2: 6,689 rounds, about 27,000 forks each) |
| §6 F11 (new, pressure soak): a ready task pinned to one CPU was stranded in another CPU's queue | Root cause found and fixed; soak-verified (g60 cpu 7,079 and g63 smp 6,630 rounds, no stall); independent review pending | A stall dump (stress builds only) caught it: a worker pinned to CPU 3 sat in CPU 2's queue, CPU 3 idled, and `steal_one` only ever probed the single longest queue (CPU 0, longer because it also held the Blocked runner). Stealing now tries every other CPU, longest first. Earlier reading of the symptom as a lost exit wake was wrong. See "F11 root cause" |
| §6 F12 (new, pressure soak): `[PF ENTRY]` traces split console lines | Fixed in the kernel; the g58b/g60/g63 soaks print no trace and split no marker; independent review pending | The release kernel now traces only page faults that do not resolve (kill or panic); the serial port has no lock, and copy-on-write traces from one CPU split other CPUs' lines |
| §6 F13 (new): a WaitQueue wait took a reschedule that returned without a switch as a wake | Fixed; g58 gates pass; independent review pending | Pre-existing in `WaitQueue::finish_prepared`; exposed by the musl timed wait on one CPU (PID 1 lost, musl-check hung). Bisected and fixed; see "Second batch" |
| §6 F14 (new): stack demand-growth killed the task on lock contention | Fixed; g58 gates pass; independent review pending | Pre-existing (RF178-12 try-only fault path). Every lock in `try_demand_grow_user_stack` is a try-lock and `EAGAIN` fell through to SIGSEGV; the first SMP ring3-mm run of the final tree (g57, 2 CPUs) failed the stack-guard leg with exit 139 on the lowest lazy page. The fault handler now retries the access on `EAGAIN`, as the COW Busy arm does |
| §6 F15 (new): `getppid` could return 0 while the parent exits | Fixed; g58 gates pass; independent review pending | Pre-existing (lifecycle ordering). `terminate_process` detached the dying task from its PID namespaces before reparenting its children, so an orphan's `getppid` translated an unmapped pid to 0. Found by the 4-CPU ring3-mm root-init leg in g57. Children are now reparented before the namespace detach |
| §6 stress `smp` profile rejected for `spins=0` | Fixed in the runner; g63 smp profile QUALIFIED with contention in every round | A start barrier (workers were forked one at a time) plus a contention seed (worker 0 holds the lock across the barrier until another worker fails an acquire), since about 1% of barrier rounds still did not overlap on TCG |
| §6 retained migration/RCU/latency metrics | Implemented; retained in every g58b soak log |  `/proc/schedstat`: per-CPU context switches and migrations-in, RCU callback backlog, wait over-wakes. The stress runner copies it into the serial log every 256 rounds; per-round `wall_ns` is the latency record. Ring-3 leg checks the file |

Nothing here is DONE. Gates are QUALIFIED rather than strict, and each item has open
acceptance work (see Review and Residual risk).

## §5 Threads, TLS, pthread prerequisites

**Landed (slices 1-2 of 4).** Slice 1: `SignalTable` (`kernel/kernel_core/signal.rs:339`) wraps the
disposition array behind its own lock. The field is `Process.sigactions: Arc<SignalTable>`
(`process.rs:1915`).

- Allocation is fallible and admitted in the PCB heap-charge ledger.
- Fork deep-copies the table. The manual `CLONE_VM` path shares the `Arc` only when
  `CLONE_SIGHAND` is set, and drops a displaced table after the child guard is released.
- Lock order: PCB → table (leaf). IRQ-return delivery only try-locks and defers on
  contention. The table stays held across the snapshot recheck and the `SA_RESETHAND` commit.
- The generation counter is a diagnostic mutation count (`signal.rs:403`), never an identity.
- Blocked, pending and handler-scratch state stay per task.

**Preview, not default (2026-10-17).** Default builds still omit
`CLONE_SIGHAND | CLONE_THREAD | CLONE_FILES | CLONE_FS` from `SUPPORTED_CLONE_FLAGS`, so
those flags return `EINVAL`. The `thread_preview` feature (enabled only by the guest test
builds) admits them together with `CLONE_SYSVSEM` and `CLONE_DETACHED`, so the ring3-mm
thread legs and musl's own `pthread_create` exercise every shared handle for real.

**Before default enablement (status 2026-10-17):**

1. Landed (slice 3, steps 1-3): `FilesTable` ([design](gap-5-slice3-files-handle-design.md)).
   `Process.files: Arc<FilesTable>` holds the fd state behind one leaf lock (every former
   `get_fd` borrow now goes through it), with an owner count: only the last owner closes
   the descriptors and returns the charge. `CLONE_FILES` shares the table inside a thread
   group only. Open: unsharing on exec (exec now returns `EBUSY` while the table is shared).
2. Landed (slice 2): `FsContextHandle` (`kernel/kernel_core/fs_context.rs:110`) moves
   root, cwd and umask behind one leaf lock as `Process.fs: Arc<FsContextHandle>`.
   - Allocation is fallible and charged with the PCB (`arc_charge_bytes`).
   - Fork deep-copies (`copy_from`); the manual clone path shares only with `CLONE_FS`.
   - chdir/chroot publish via `replace_if_matches`, so the snapshot check and the store
     share one handle critical section. The displaced or rejected directory state is
     dropped after the PCB guard (`kernel/vfs/operations.rs`), so a final directory drop
     never runs under it. `umask` uses `set_umask` (atomic swap under the handle lock).
   - Remaining hosted-test `replace` sites drop under the guard only in test fixtures.
3. `MmHandle` last-owner accounting exists via `Arc::strong_count(&proc.mm)`, plus exec
   refusal while shared. Unchanged.
4. Landed (slice 4): the thread group's shared exit state (`ThreadGroup.exiting`, set
   before siblings are woken), TLS before runnable, and per-task robust-futex lists.
5. Landed: the pthread-like static workload (musl, `MUSL-PTHREAD-OK`) and the futex
   operations its condition variables need; on the final tree (g58) the ring3-mm thread
   legs (via `KERNEL_TEST_CPUS`) and the musl workload pass on 1/2/4/8 CPUs. Open: a
   16-CPU run, exec from a thread group (`de_thread`/`unshare_files`; sketch in the slice-4
   design), and an independent lifetime/lock review of G1/G2/G7 and the shared fd table.

## §6 Scheduler, SMP, pressure

- **W-3.**
  - A pid-targeted `wait4`/`waitid` narrows its published wake filter from `Some(0)` to
    the target's global pid before sleeping. It narrows only while `Blocked` + `Some(0)`
    are still published, so an exit mid-scan cannot be lost.
  - Wake sites match `Some(0) || Some(pid)`.
  - A resume that re-blocks bumps `WAIT_OVER_WAKES` (`process.rs:5937`), counted only when the
    task actually left `Blocked` (a bailed `force_reschedule` no longer inflates it).
  - `/proc/waitstat` (`kernel/vfs/procfs.rs:1514`) exposes the counter; the Ring-3 leg asserts
    it does not move across the sibling-exit targeted wait.
  - Open: a bounded per-call wake budget for non-wait waiters.
- **W-4.** `test_selective_wait_nested_zombie` (`userspace/src/syscall_test.rs:1539`) forks
  fast and slow siblings and checks four things:
  - the slow one is reaped by pid while the fast zombie is ignored;
  - the fast one is then reaped with its own status;
  - `P_ALL|WNOHANG` returns `ECHILD`;
  - the same holds one generation down.
- **F4/F6.**
  - SCHED-TRAP builds a fixed `SchedTrapEvent` (`enhanced_scheduler.rs:510`) and formats
    it only after every scheduler/PCB guard drops.
  - A release-compiled `SwitchSentinel` (`:534`, armed at `:2807`) checks the resumed
    task's pid and generation against the CPU's published identity.
- **F7.** `PCB_STACK_BUDGET` + const assert (`process.rs:238`). A failed contiguous
  order-3 stack allocation already ends in `ENOMEM` (see the inventory), and the
  run-queue/RCU sizes are inventoried below. Open: in-place PCB construction.
- **F7 size inventory (2026-10-16).**

  | Object | Size and bound | Source |
  |--------|----------------|--------|
  | Per-task kernel stack | 8 pages (32 KiB), order-3 contiguous, plus 1 unmapped guard page; 36 KiB virtual slot per PID; 32,768 PIDs | `process.rs:225-231`, `allocate_kernel_stack` |
  | PCB | `size_of::<Process>() <= 16 KiB` (half a stack), const-asserted | `process.rs:238` |
  | BSP boot stack; per-CPU double-fault and NMI IST stacks | 64 KiB; 32 KiB each | `arch/gdt.rs:45-51` |
  | Ready queue | one `(priority, pid)`-ordered admitted map per CPU, fallibly grown; selection visits at most 16 entries, insert retries 4 | `enhanced_scheduler.rs:83,108,333,721` |
  | RCU callbacks | static pool of 32,768 stack + 256 general slots (about 1.4 MiB, no heap); drain budget 16/64/256 at backlog <256/≥256/≥1024 | `rcu.rs:100-107,471-487` |
  | Stack allocation failure | `KernelStackError::AllocationFailed` before any mapping → `ProcessCreationFailed` → `ENOMEM` from fork/clone; the RCU reclaim slot is reserved first | `process.rs:1008`, `fork.rs:198`, `syscall.rs:4599` |

- **Wake budget.** `WaitQueue::wake_one`/`wake_n` are bounded; `wake_all` drains the queue under its lock with IRQs off. For wait4, W-3 already limits an exit to one parent wake. Slice 4 kept that bound: a child is linked to the task that forked it, so only that thread can wait for it and an exit still has one matching waiter. Linux lets any thread of the group wait for any member's children; adopting that (a G8 item) is when a per-call budget becomes necessary.
- **Retained metrics (2026-10-17, verification pending).** `/proc/schedstat` (inode 8,
  `kernel/vfs/procfs.rs`) prints `cpus_online N`, one `cpuN switches=S migrations_in=M`
  line per online CPU, `rcu_backlog B` and `wait_over_wakes W`. Every value is a lock-free
  read: per-CPU counters in `kernel_core::process` (`note_context_switch` at both switch
  commits, `note_task_migration` at the steal and balance commits in
  `enhanced_scheduler.rs`) and `rcu::callback_backlog` (the existing `CALLBACK_COUNT`
  atomic). The stress runner copies the file into the serial log as `NILIX_SCHEDSTAT`
  lines every 256 rounds; the host parser reads only `NILIX_STRESS_V2_` lines, so the
  protocol is unchanged and the retained `serial.log` carries the evidence. Per-round
  `wall_ns`/`cpu_ns` in the cpu markers is the latency record. Ring-3 leg
  `test_proc_schedstat` requires one line per online CPU and a switch count that advances
  across a fork and reap.
- **Gate tooling.** `scripts/ci/gate_log.py` streams multi-GiB `-d int` logs.
  `ring3_mm_oracle.sh` adds the selective-wait leg.

## Validation (nilix-dev, `/tmp/nilix-gap56-0928`, logs `/tmp/g56b-*.log`)

Remote file hashes were compared against local before the runs.

| Gate | Result |
|------|--------|
| `make build` | OK |
| `make lint` | OK after resync of a stale remote `signal.rs` (comment-only); ABI-ORACLE PASS |
| hosted unit tests | 454 OK |
| `make test` | QUALIFIED: passed=35 deferred=39 failed=0 |
| ring3-mm | 18 passed, 0 failed (includes selective-wait and pids.max) |
| `test-smp` (2 CPU) | QUALIFIED: 37/37/0, QEMU exceptions 0, RF178-33 PASS, R175 D0 cross 3 |
| `test-smp-4core` | QUALIFIED: 4/4 online, 37/37/0, exceptions 0 |
| `extended_smp_test.sh` 8 CPU | QUALIFIED: 8/8 online, 37/37/0, NX/reset/supervisor faults 0, IPI and TLB shootdown PASS |
| `extended_smp_test.sh` 16 CPU | QUALIFIED: 16/16 online, 37/37/0, faults 0, IPI and TLB shootdown PASS |

The extended script exits 3 (QUALIFIED), and make reports that as `Error 3`. These are
zero-failure qualifications, not strict passes. The deferred checks are pre-existing
placeholders. No stress-v2 or pressure soak was run.

Final-tree rerun (after the review fixes and a CRLF restore of `syscall.rs`; hashes
re-verified, logs `/tmp/g56c-*.log`):

| Gate | Result |
|------|--------|
| `make build`, `make lint` | OK |
| `make test` | QUALIFIED: 35/39/0 |
| ring3-mm | RING3-MM OK; `[PASS]` selective wait and `[PASS]` pids.max in serial |
| `test-smp` (2 CPU) | QUALIFIED: 37/37/0, exceptions 0, RF178-33 PASS, R175 D0 cross 3 |

The ring3-mm run prints `boot-harness: GATE-LOG FAIL` (status 1). That is the generic boot
classifier, not this gate's verdict. Its two reasons trace to handled demand faults the
oracle is built to exercise:

- 102 `[PF ENTRY]` serial lines, which the generic `SERIAL_FATAL` bans;
- three supervisor write faults (`v=0e e=0002 cpl=0`, CR2 `0x100d673f3d`/`0x100d674000`, a
  user address) during the multi-page usercopy first-touch leg.

There are no `[PAGE FAULT]`/`[GPF]`/`[#UD]`/panic markers and no `v=0e e=0011`, `cpu_reset`
or triple fault. `ring3_mm_oracle.sh:10-17` documents the substitution of its fault-tolerant
verdict, which passed.

Slice-2 tree (`FsContextHandle`, logs `/tmp/g56c-*.log`):

| Gate | Result |
|------|--------|
| `make build`, `make lint` | OK |
| hosted unit tests | 457 OK (3 new `FsContextHandle` tests) |
| ring3-mm | all oracles pass; generic boot classifier FAIL for the handled-fault reasons above |
| `make test` | QUALIFIED: 35/39/0 |
| `test-smp` (2 CPU) | QUALIFIED: 37/37/0 |
| `test-smp-4core` | QUALIFIED: 37/37/0 |
| `extended_smp_test.sh` 8/16 CPU | Not collected here (host outage); covered by the g56e run below, which includes this tree |

The chdir drop-after-guard fix in `kernel/vfs/operations.rs` was made during this run. Its
remote hash could not be re-verified before the host went down, so the slice-2 rows above
cover the tree without that fix. The g56e run below was made on a tree whose ten kernel/userspace
file hashes match local, including that fix, so it supersedes these rows.

The earlier `/tmp/g56d-*.log` 8/16-CPU attempt is void. It overlapped the g56c rebuild in
the same tree: the 8-core leg ended `GATE-INPUTS FAIL: kernel.elf changed`, and the 16-core
leg was terminated by make mid-run (`PID 1 exited with code 1`, QEMU TERM). Neither result
counts for or against the diff. Future runs must use separate trees.

`FilesHandle` step 1 tree (`FdState` grouping on top of slice 2 and the chdir fix, logs
`/tmp/g56e-*.log`; remote hashes re-verified after the run):

| Gate | Result |
|------|--------|
| `make build`, `make lint` | OK |
| `make test` | QUALIFIED: 35/39/0 (make reports the QUALIFIED status as exit 2) |
| ring3-mm | RING3-MM OK: 31 `[PASS]`, 0 `[FAIL]` (selective wait and pids.max pass); generic boot classifier FAIL for the handled-fault reasons above |
| `test-smp` (2 CPU) | QUALIFIED: 2 online, 37/37/0, exceptions 0, RF178-33 PASS, R175 D0 cross 3 |
| `test-smp-4core` | QUALIFIED: 4 online, 37/37/0, exceptions 0 |
| `extended_smp_test.sh` 8/16 CPU | QUALIFIED both (`failed=0 incomplete=0 qualified=2`): 37/37/0, NX 0, CPU resets 0, IPI and TLB shootdown PASS |

`FilesHandle` step 2 tree (charge-owner tracking, logs `/tmp/g56f-*.log`):

| Gate | Result |
|------|--------|
| `make build`, `make lint` | OK |
| hosted unit tests | 458 OK (new `gap5_fd_charge_owner_follows_membership`) |
| `make test` | QUALIFIED: 35/39/0 |
| ring3-mm | RING3-MM OK; generic boot classifier FAIL for the handled-fault reasons above |
| `test-smp` (2 CPU) | QUALIFIED: 37/37/0, exceptions 0, RF178-33 PASS, R175 D0 cross 3 |
| `test-smp-4core` | QUALIFIED: 4/4 online, 37/37/0, exceptions 0 |
| `extended_smp_test.sh` 8/16 CPU | QUALIFIED both (`failed=0 incomplete=0 qualified=2`): 37/37/0 |

The g56g follow-up adds only a hosted unit test (`gap5_fd_charge_conserved_across_copy_drop_and_rollback`): hosted 459 OK and `make lint` OK (logs `/tmp/g56g-*.log`). No kernel runtime code changed, so the g56f boot and SMP rows still apply.

All gates on this tree are zero-failure qualifications, not strict passes.

64/65-CPU ceiling (2026-10-16, host `nilix-dev`, ESP `/tmp/g56h-esp`
built from the g56f tree, kernel.elf sha256 `437ecaef…`, logs `/tmp/g56i-*`):

| Run | Result |
|-----|--------|
| `-smp 64 -m 512M` | `[SMP] 64 CPU(s) online`; `smp_online` PASS; RUNTIME-COUNTS passed=36 warning=1 deferred=37 failed=0; PID 1 exit 0; `e=0011` 0, `cpu_reset` 0 |
| `-smp 65 -m 512M` | `[SMP] rejecting invalid MADT LAPIC topology (id=64, count=64)`, BSP-only fallback (`1 CPU(s) online`); passed=28 deferred=46 failed=0; PID 1 exit 0; `e=0011` 0, `cpu_reset` 0 |

These were direct QEMU boots with the gate's command line (`-m 512M`, same CPU model and
OVMF), not a `scripts/gates` wrapper, so they are ad-hoc evidence. The 64-CPU value stays
a reject boundary: one APIC past `MAX_CPUS` discards the whole MADT topology instead of
starting a partial set.

**F8 (new finding, open).** The first ceiling attempt used `-m 1G` and both boots panicked
at the D1-RES oracle (`integration_test.rs:734`): `boot unledgered footprint 343632 B` (64
CPUs) and `399872 B` (BSP-only) against the 327,680 B ceiling. At 512M the same kernel
measured 255,048 B and 262,904 B. The growth tracks RAM, not CPUs:
`BuddyAllocator::page_state` (`mm/buddy_allocator.rs:331`, one byte per managed page) and the
`FixedFreeMap` order bitmaps are allocated on the 2 MiB kernel heap and are not admitted.
The managed window is capped at 1 GiB (`HIGH_HALF_MAP_LIMIT`, `mm/memory.rs:407`), so the
metadata peaks near 290 KiB. Consequences:

- every profile with `debug_interfaces_enabled` (the integration tests run at boot,
  `src/main.rs:1373`) panics on a guest or machine with about 1 GiB of RAM or more;
- in every profile, the heap arbiter assumes that unledgered use stays within the
  carve-out, and buddy metadata alone can consume most of it.

Suggested repair, following RF178-31 (the COW refcount table): place the buddy metadata in
boot-reserved physical frames from the managed window instead of the heap. Not fixed in
this change.

## Review

Two independent read-only reviews of the GAP-5/6 kernel diff completed. Neither found
a D0–D2 defect or a live deadlock, IRQ spin, lost wakeup or sentinel false positive.
Both confirmed the lock order (PCB → table leaf), IRQ try-lock use, `copy_from` ordering,
exec refusal while the address space is shared, the W-3 interleavings and the gate_log
chunking.

| Finding | Severity | Resolution |
|---------|----------|------------|
| Process-context `SA_RESETHAND` commit reset the slot without rechecking it, so a sibling's `rt_sigaction` could be lost once `CLONE_SIGHAND` is live | D3, latent | Fixed: `SignalTable::reset_if_unchanged` resets only the Phase-1 disposition |
| Exec resets a table that could later be shared | Low, latent | `debug_assert` that the table is unshared; unshare step required before enabling `CLONE_SIGHAND` |
| Stale lock contract on `has_deliverable_signal_locked` | Doc | Fixed |
| `CLONE_SIGHAND` share path is untested; per-PCB heap charge no longer follows the shared table's lifetime | D4, latent | Open, prerequisite for enablement |
| W-3 guest test passes with or without narrowing; `wait_over_wake_count` has no reader; the counter also counts resumes that never switched | D4 | Fixed: `/proc/waitstat` reader, zero-delta assertion in the guest leg, counter gated on leaving `Blocked` |
| IRQ-path final `Arc` drop becomes possible if a future unshare swaps the field | Info | Recorded as an enablement constraint |
| `send_signal_inner` locks the table twice; test sibling ordering is probabilistic | D5 | Tracked debt |

The fixes were rebuilt and linted on the final tree (see Validation).

F8 tree (g56j, `/tmp/nilix-gap56-1016`, kernel.elf `2648792a…`, logs `/tmp/g56j-*`):

| Gate | Result |
|------|--------|
| `make build`, hosted (`mm` 30), `make lint` | OK |
| `make test` | QUALIFIED: 35/39/0 |
| ring3-mm | RING3-MM OK |
| `-m 1G -smp 4` direct boot | D1-RES baseline 168,680 B; runtime passed=37 deferred=37 failed=0; PID 1 exit 0 |
| `-m 4G -smp 4` direct boot | panics early (F9, pre-existing) |
| `test-smp`, `test-smp-4core` | QUALIFIED 37/37/0, exceptions 0 |
| `extended_smp_test.sh` 8/16 CPU | QUALIFIED both, 16/16 online, NX 0, CPU resets 0, IPI and TLB shootdown PASS |

Slice-4 batch tree (g56k, `/tmp/nilix-gap56-1016b`: F8 review fix, G1-G6, G2, the D1
CR3 guard and the G4 tick deadline; kernel.elf `7edf2bc5…`; logs `/tmp/g56k-*`):

| Gate | Result |
|------|--------|
| `make build`, hosted (`kernel-core` 86, `mm` 30, `ipc` 4/18), `make lint` | OK |
| `make test` | QUALIFIED: 35/39/0 |
| ring3-mm | RING3-MM OK, `Results: 19 passed, 0 failed`; `[PASS] CLONE_CHILD_CLEARTID clears a .bss tid word at exit` (G3 guest-verified); shared-anon legs pass with the D1 guard in place |
| `-m 1G -smp 4` direct boot | D1-RES baseline 168,680 B; runtime passed=37 deferred=37 failed=0; PID 1 exit 0 |
| `test-smp`, `test-smp-4core` | QUALIFIED 37/37/0, exceptions 0 |
| `extended_smp_test.sh` 8/16 CPU | QUALIFIED both (`failed=0 incomplete=0 qualified=2`), 8/8 and 16/16 online, NX 0, CPU resets 0, IPI and TLB shootdown PASS |

Thread-preview tree (G2, G7, `thread_preview`; logs `/tmp/g56l-*` on `/tmp/nilix-gap56-1016b`,
then `/tmp/g56m-*` on `/tmp/nilix-gap56-1016c` with the wait-loop drain fix):

| Gate | Result |
|------|--------|
| `make build`, hosted, `make lint` (g56l) | OK |
| `make test` (g56l) | QUALIFIED: 35/39/0 |
| `-m 1G -smp 4` direct boot (g56l) | runtime 0 failed, PID 1 exit 0 |
| ring3-mm (g56l) | FAIL: the thread-group leg hung after all three groups exited. Root cause: on one CPU the waiting parent spins in `wait_reap_core`, where nothing ran the thread auto-reap drain, so a group whose leader exited first was never reported. Fixed by draining at the top of every wait pass |
| ring3-mm (g56m, fixed tree) | RING3-MM OK, `Results: 21 passed, 0 failed`, PID 1 exit 0: `[PASS] tkill and tgkill reach exactly the named task`, `[PASS] thread groups share identity, exit as one and are reaped once` (three real `CLONE_VM`+`CLONE_SIGHAND`+`CLONE_THREAD` groups: hosts exit 0x31/0x42/137 and every thread terminates) |
| SMP 2/4/8/16 (g56l) | Stopped: superseded by g56n on the fixed tree |
| g56n (`/tmp/nilix-gap56-1016c`, fixed tree, kernel.elf `b2559695…`): build/hosted/lint | OK |
| g56n `make test`; `-m 1G` boot; ring3-mm | QUALIFIED 35/39/0; 0 failed, PID 1 exit 0; RING3-MM OK (thread-group leg passes) |
| g56n SMP 2/4/8/16 | QUALIFIED 37/37/0 on every profile, 16/16 online, NX 0, CPU resets 0, IPI and TLB shootdown PASS |
| g56n `make stress-test` | Did not start: the stress host self-test was broken before any QEMU run (pre-existing, see below). Rerun as g56p |

Shared fd table, futex ABI and musl pthreads (g56o, `/tmp/nilix-gap56-1016d`, kernel.elf
`28580493…`; one clean run after three overlapping runs were stopped and discarded):

| Gate | Result |
|------|--------|
| `make build`, hosted (`kernel-core` 87, with the `cpu_local` test-race fix), `make lint` | OK |
| `make test` | QUALIFIED |
| ring3-mm | RING3-MM OK, `Results: 21 passed, 0 failed`: `[PASS] thread groups share identity and files, exit as one and are reaped once` (adds the CLONE_FILES and CLONE_FS leg) |
| `make musl-check` | MUSL-CHECK OK: static musl guest exits 0 with `MUSL-PTHREAD-OK` required (four `pthread_create` threads, mutex contention, `__thread` TLS, shared fd table, `pthread_join`) |
| SMP 2/4/8/16 (g56t) | QUALIFIED 37/37/0 on every profile; 8/8 and 16/16 online; `failed=0 incomplete=0 qualified=2` |

Pressure soak (g56p, `make stress-test`, G1/G2/G7 tree, first run ever of this gate):

| Profile | Result |
|---------|--------|
| memory | Workload ran the full window: 3,137 OOM-recovery cycles, usage back to the 212,992 B baseline every time. Marked failed only by the protocol's generic fatal regex, which bans the `[PF ENTRY]` lines of the deliberate faults (same as ring3-mm) |
| cpu, smp | `fork` returned `ENOMEM` deterministically at iteration 2,577 (about 10,300 forks). Root cause found (pre-existing, see F10); fix under test |
| process | `process_limit_not_enforced`: `RLIMIT_NPROC` is not implemented |
| block | `fsync` returns `ENOSYS` |
| combined | `open` mode returns `ENOSYS` |

## Review of the 2026-10-16 batch (F8, G3, G4, G5/G6)

One independent read-only review. G1 landed during the review and is not covered by it.

| Finding | Severity | Resolution |
|---------|----------|------------|
| `handle_shared_page_fault` resolves against the *current* task's `shared_regions` and installs into the *active* page table. Exit-time writes for a non-current task (the G3 clear-tid write from the deferred IRQ-kill drain, and the pre-existing robust-list walk) run under that task's CR3, so a not-present fault could map the current task's shared frame into another address space, write into it and charge the wrong cgroup | D1 (widened by G3; narrower form pre-existing) | Fixed: the resolver declines unless the active root is the current task's `memory_space` or KPTI `user_memory_space` (`fork.rs`); the usercopy fixup then fails the copy. G3 comment corrected |
| A COW tid word is not cleared when the drain runs from the idle loop (`current_pid() == None` skips the COW arm) | D4 | Open, tracked; the word is left set, no wake |
| One more metadata reservation turns a 63-range memory map from booting into a panic | D4 | Fixed: the reservation builder keeps two slots for the metadata ranges |
| G4 bounded by retries, not time; an idle CPU burns them instantly | D4 | Fixed: 100-tick deadline plus a yield backstop for the host harness |
| Ring-3 clear-tid leg covers only self-exit, not the drain path | D5 | Open: add a SIGKILL-while-spinning leg |
| Redundant clear-tid range pre-check | D5 | Fixed: `copy_to_user_safe` validates the range |

Checked clean: F8 slice construction, alignment, reinitialization, reservation and
direct-map containment; G4 lock context and RF180-47 serialization; G5/G6 lock order and
unchanged behaviour for ordinary processes.

Pre-existing stress-gate breakage found by g56n: `scripts/tests/stress_protocol_test.py`
put `scripts/` instead of the repository root on `sys.path` after commit 3254318 moved it,
and `stress_protocol.py` imported `gate_log` without its new `scripts/ci` location (the
"stale gate_log import" the plan already recorded). Both fixed; the 12 host self-tests
pass on the host's Python 3.10.

Soak results with all fixes (tree `/tmp/nilix-gap56-1016e`: G1-G7, shared fd table, PID window):

| Run | Profile | Result |
|-----|---------|--------|
| g56v | memory | QUALIFIED: workload completed the window; runtime/security prerequisites remain |
| g56v | cpu | Hung after round 733: two of round 734's four workers never exited and the guest went silent for 811 s (F11) |
| g56v | smp | Ran 4,427 rounds; rejected because some rounds report `spins=0`, and the protocol requires lock contention in every round while the runner forks workers without a start barrier (test design) |
| hang1 | cpu | Full window, 7,437 rounds (about 29,700 forks), no hang; rejected on a marker line split by a kernel `[PF ENTRY]` print (F12) |
| hang2 | cpu | Rejected before the first round: the `READY` marker was split the same way (F12) |
| hang3 (shared fd table, no PID window) | cpu | `fork` `ENOMEM` at round 2,575, confirming F10 and its fix |
| g56x1 (rerun on the hang1 tree) | cpu | QUALIFIED: full window, 6,733 rounds, no hang, no split marker; 124,534 `[PF ENTRY]` lines in a 7.4 MB serial log; artifacts `/tmp/nilix-stress-v2.90QkQ5yD` |
| g56x2 (rerun on the hang2 tree) | cpu | QUALIFIED: full window, 6,689 rounds, no hang; 123,228 `[PF ENTRY]` lines; artifacts `/tmp/nilix-stress-v2.hKP2YXYT` |

Both g56x runs end `STRESS-TEST QUALIFIED: 1 profile(s) completed with runtime
qualifications` (make reports exit 3). QMP shows all four vCPUs ticking at the end of each
window.

- **F11 (open, not reproduced):** one guest hang in about 18,000 cpu-profile rounds (g56v,
  after round 733: two of round 734's four workers never exited and the guest went
  silent). The three full-window cpu runs on the same code since then (hang1, g56x1,
  g56x2; about 20,900 rounds and 84,000 forks) did not hang. No artifacts exist for the
  hung run; every later soak keeps them (`STRESS_KEEP_ARTIFACTS=1`).
- **F12 (fixed in the kernel, verification pending):** the release kernel wrote
  `[PF ENTRY] err=…` to the serial port on every page fault, and the serial writer has no
  lock (`vga_buffer::_print` writes byte by byte), so under a fork-heavy load a
  copy-on-write trace from one CPU split a marker line another CPU was writing, and the
  stress protocol rejected the run (hang1, hang2). There is no console lock to share, so
  the fix is in the trace itself: release builds now print `[PF ENTRY]` only for a fault
  that does not resolve, just before the kill or panic path
  (`trace_unresolved_page_fault`, `arch/interrupts.rs`); copy-on-write, shared-anonymous
  and stack demand faults and usercopy fixups return without a trace. Debug builds still
  trace every fault at entry. Effect on the gates: no gate requires `[PF ENTRY]`; the
  boot and SMP parsers that ban it never see resolved faults (their boots have none); the
  ring3-mm, musl and stress verdicts already ignore it. The gate comments that described
  handled faults as traced were updated.

Stress verdict regex (found by g56u): after the PID fix, `cpu` ran the full 900 s window
(6,601 rounds, about 26,000 forks, PIDs recycled below 2,000) and `smp` 7,628 rounds, with no
guest failure. Both were still marked failed because `stress_protocol.py` reused
`gate_log.SERIAL_FATAL`, which bans the `[PF ENTRY]` trace printed on every handled page
fault, so no fork-heavy profile could ever pass. The stress protocol now uses a
terminal-outcome regex (`STRESS_TERMINAL_FATAL`, same rule as ring3-mm and the musl
probe), covered by two new host self-tests (14 total, all pass).

Pre-existing hosted-test race found by g56o (not caused by this work): in
`kernel/cpu_local/lib.rs`, `non_task_context_classifier_rejects_irq_and_interrupt_masking`
toggled the shared host CPU's IRQ/NMI context without `TOPOLOGY_TEST_LOCK`, so under default
test parallelism `soft_progress_context_is_fail_closed_and_non_reentrant` could observe
`Some(true)`. Fixed by taking the same lock (test-only).

## Second batch (2026-10-17): futex ops, F12, metrics, SMP thread runs, F13

Changes: `FUTEX_REQUEUE`/`CMP_REQUEUE`/bitset ops, F12, the smp-soak start barrier,
`/proc/schedstat`, Ring-3 legs (futex requeue, schedstat, kill-while-blocked clear-tid),
musl broadcast and timed-wait legs, `KERNEL_TEST_CPUS`, and the F13 fix below. Hosted
suite 468 (kernel-core 90 with the futex decoder test).

g56z and g56s1, tree `/tmp/nilix-gap56-1017a` before the F13 fix (33 and 34 files
hash-verified):

| Gate | Result |
|------|--------|
| `make build`, hosted (468), `make lint` | OK |
| `make test` | QUALIFIED 35/39/0 |
| ring3-mm, 1 CPU | RING3-MM OK, `Results: 23 passed, 0 failed`, PID 1 exit 0; 2 `[PF ENTRY]` lines (deliberate faults; about 100 before F12) |
| ring3-mm, `KERNEL_TEST_CPUS=2/4/8` (g56s1) | RING3-MM OK on each; 2/4/8 CPUs online; the thread-group, tkill, futex-requeue, schedstat and clear-tid legs pass |
| musl-check, 1 CPU | **FAIL**: `MUSL-PTHREAD-OK` printed, then PID 1 hung (F13) |
| musl-check, `MUSL_CHECK_CPUS=2/4/8` (g56s1) | MUSL-CHECK OK on each |
| SMP 2/4 | QUALIFIED 37/37/0, 0 QEMU exceptions |
| SMP 8/16, stress | Stopped for the F13 fix; rerun as g57 |

**F13 (new, fixed, verification pending): a WaitQueue wait took a reschedule that
returned without a switch as a wake.** `WaitQueue::finish_prepared` (`kernel/ipc/sync.rs`,
the futex and `wait_with_timeout` path) called `force_reschedule()` once and then
classified the outcome. `reschedule_now` can return with the caller still `Blocked`: it
bails on try-lock contention in `drain_tick_debt_before_switch`/`finish_pending_prev`, on a
non-preemptible CPU, and when `prepare_switch` returns `None` (it hands a CPU with nothing
runnable to its idle frame only for an exiting task). `wait_reap_core` documents this and
loops. `finish_prepared` instead reported `Woken`: the futex call returned 0, the timer
was disarmed, and the task went back to user mode still `Blocked` and still queued. A
task switched out in that state is never re-queued. In the musl guest PID 1 was lost
before it reached the VFS probe's `waitpid` (raw-`write` markers, below), so the child's
exit had nothing to wake. The bug predates this batch (M1-02). The new single-threaded
`pthread_cond_timedwait` right after the four threads exit is the only workload seen to
trigger it; which bail path fires there is not established. A lone 20 ms timed wait in a
forked ring3-mm host sleeps correctly on the pre-fix kernel (negative control below), so
an empty run queue alone does not trigger it.

Bisect (1-CPU musl-check, logs `/tmp/g56r-*`, `/tmp/g56q-*`, `/tmp/g56p-*`, artifacts kept):

| Tree | Kernel | musl probe | Result |
|------|--------|------------|--------|
| 1016d | g56o | g56o | 5/5 OK |
| 1017f | before the fix | g56o | 5/5 OK |
| 1017c | before the fix | new (broadcast and timed wait) | 1/5 OK; earlier single runs: c OK, g56z hung |
| 1017e | before the fix | new, no broadcast | hung |
| 1017h | before the fix | new, no timed wait | 5/5 OK (one earlier run, d, OK) |
| 1017g | before the fix | new, with raw-`write` markers around the VFS `waitpid` | 5/5 hung, no marker printed: PID 1 was lost before it reached `waitpid` |
| 1017i | **fixed** | new | 10/10 OK (two batches of 5) |

The hung guests idle in `kernel::shell::init_and_run` (the CPU's idle frame), symbolized
from the `-d int` log after subtracting the 0x2500000 load offset.

Fix: `finish_prepared` now calls `block_until_resolved`, which yields until the task is no
longer `Blocked` or a kill or handler signal is pending, the same discipline as
`wait_reap_core`. With interrupts disabled (an invalid wait context, since neither the
timer nor a cross-CPU wake could resolve it) it keeps the single reschedule. The
ring3-mm futex host now also makes a lone 20 ms `FUTEX_WAIT_BITSET` and requires
`ETIMEDOUT` no earlier than the deadline (exit 0xa0 or 0xa1 otherwise). That pins the
contract but is not a regression test for F13: with the new guest on the pre-fix kernel
(tree 1017c, log `/tmp/g56neg.log`) ring3-mm still passes 23/0. The F13 evidence is the
musl bisect above. Related, not changed: `WaitQueue::finish_wait` (pipes, `KMutex`,
semaphore, condvar, PI futex) has the same single-reschedule shape; its callers re-check
their condition and re-queue, so it can spin but not report a false wake, and it is left
for a separate review.

**F14 (new, fixed, verification pending): stack demand-growth turned lock contention
into SIGSEGV.** `try_demand_grow_user_stack` (RF178-12) takes PROCESS_TABLE, the PCB,
MmState, the cgroup fault charge, the page tables and the buddy allocator with try-locks
only, and returns `EAGAIN` when any of them is held. The page-fault handler treated every
error as fatal, so on SMP a stack touch that raced another CPU's table scan (here, PID 1's
`waitid` loop) killed the task. The ring3-mm stack-guard leg passed on 1, 2, 4 and 8 CPUs
before (g56s1) and failed once on 2 CPUs in g57 (`lowest-lazy exit 139 [FAIL] stack guard:
the lowest lazy stack page did not demand-grow`). `EAGAIN` is returned before any
publication, or after a committed prefix, so the handler now returns and retries the
instruction through IRETQ, as the COW `Busy` arm does; other errors stay fatal. Timer
interrupts at the user instruction boundary keep the lock holder schedulable.

**F15 (new, fixed, verification pending): `getppid` could return 0 while the parent
exits.** `terminate_process` ran `detach_pid_chain` (the dying pid loses its namespace
mapping) and only then, after the clear-tid write, `reparent_orphans`. In between, a
child's `ppid` still named the dying pid, and `sys_getppid` translates a pid with no
mapping in the caller's namespace to 0. On SMP a child running on another CPU could see
that 0; the ring3-mm root-init leg exits `GC_REPARENTED_ELSEWHERE` when it does, and failed
once on 4 CPUs in g57 (`orphan's ppid moved but not to PID 1`). Linux reparents in
`exit_notify`, long before the pid is released. Children are now reparented right after
the init-death cascade and before the detach. Reaper selection is unchanged: it already
skips the dying pid and any namespace that is shutting down, and the cascade marks a dying
namespace first.

g57 (final tree before F14/F15, logs `/tmp/g57-*`): build, hosted, lint OK; `make test`
QUALIFIED 35/39/0; ring3-mm on 1 CPU 23/0; on 2 CPUs 22/1 (stack guard, F14); on 4 CPUs
21/2 (stack guard, F14; root-init reparent, F15). Stopped there for the F14/F15 fixes;
rerun as g58. Extra F13 confirmation on tree 1017i: 10/10 single-CPU musl-check runs OK.

Final tree (g58/g58b, `/tmp/nilix-gap56-1017a`, 35 files hash-verified against the
working tree: every change above including F13, F14 and F15; logs `/tmp/g58-*`,
`/tmp/g58b-*`):

| Gate | Result |
|------|--------|
| `make build`, hosted (468), `make lint` | OK |
| `make test` | QUALIFIED 35/39/0 |
| ring3-mm on 1, 2, 4 and 8 CPUs, two boots each (`KERNEL_TEST_CPUS`) | 8/8 RING3-MM OK, each `Results: 23 passed, 0 failed` with every CPU online |
| musl-check 1 CPU ×3, 2, 4, 8 CPUs | 6/6 MUSL-CHECK OK (`MUSL-PTHREAD-OK` with the broadcast and timed-wait legs, clean exit, 0 NX faults) |
| SMP 2/4 | QUALIFIED 37/37/0 on both, 2 and 4 CPUs online, 0 QEMU exceptions, RF178-33 PASS |
| SMP 8/16 (`extended_smp_test.sh`) | QUALIFIED both (`failed=0 incomplete=0 qualified=2`), 37/37/0, NX 0, CPU resets 0, IPI and TLB shootdown PASS |
| Pressure soak (memory, cpu, smp; artifacts `/tmp/nilix-stress-v2.Po01HWLE`) | memory QUALIFIED (2,543 rounds); cpu QUALIFIED (full window, 7,489 rounds, **0** `[PF ENTRY]` lines where g56x1 had 124,534, no split marker); **smp FAILED: guest hang after round 93 (F11 reproduced, below)**. Every profile's serial log carries `NILIX_SCHEDSTAT` samples (cpu: 210 lines, about 10,000 migrations into each of the 4 CPUs, RCU backlog 0, over-wakes 0) |

**F11 reproduced (g58b, smp profile)** (superseded by "F11 root cause" below). Rounds 1-93 completed with contention (`spins=4`,
counter exact, done mask full). The serial log then shows round 94's four workers
terminating (`Process 370`-`373 terminated with exit code 0`) and nothing more: the
runner, blocked in `waitpid` for its workers, never emitted round 94's marker, and the
host stopped QEMU at the end of the window. Symbolized from the kept `-d int` log (load
offset 0x6ab0000), all four vCPUs spend the silence in `arch::smp::ap_idle_loop`,
`Scheduler::reschedule_now`/`next_queue_entry`/`lock_ready_queue_or_defer` and the
deferred-work drains, so nothing is runnable: a lost exit-to-parent wake, or a
reapability flag (`on_cpu`, `switch_reap_pending`) left set. The g56v hang had the same
shape in the cpu profile. Observations, not proof: the smp profile ran 4,427 rounds
without hanging before the start barrier (g56v) and hung at round 94 with it, so
near-simultaneous exits on four CPUs look like the trigger; the cpu profile, which forks
without a barrier, completed 7,489 rounds on the same kernel. F13 is not involved (the
runner waits with `wait4`, not a WaitQueue). Next step: a stall dump in the stress kernel
(each task's state, `waiting_child`, `on_cpu`, `switch_reap_pending` and every CPU's
pending-previous slot), then the smp profile until it hangs again.

**F11 root cause (g59, stall dump).** A diagnostic behind a new `stall_dump` feature,
which only the stress kernel enables (`stress_runner` turns it on): when the guest console
has been silent for 10 s, the next process-context `reschedule_now` prints every online
CPU's current task, published generation, pending-previous slot, `need_resched` and ready
queue, then every task's state, wait filter, `on_cpu`, `switch_reap_pending`,
`teardown_done`, group size, affinity and children (`stall_dump_if_silent`,
`dump_tasks_for_stall`; try-locks only, printed once). Two smp runs hung (rounds 219 and
495) and dumped the same picture:

| Task / CPU | State |
|------------|-------|
| PID 1 (runner) | `Blocked`, `waiting_child` = the first worker (it reaps in order) |
| Workers 1-3 | `Ready`/`Running`, current on CPUs 0-2, spinning at the start barrier |
| Worker 4 | `Ready`, `on_cpu=false`, `allowed_cpus=0x8`; on no CPU and in none of the queues of CPUs 0, 1 and 3 (CPU 2's queue was locked at dump time, so it is there) |
| CPU 3 | idle, empty queue, `need_resched=false` |
| CPU 0 | queue: worker 1 (pinned to CPU 0) and the Blocked runner, length 2 |

Each worker pins itself with `sched_setaffinity` right after `fork`. The fourth one ran on
CPU 2 when it pinned itself to CPU 3, so its next switch-out re-queued it on CPU 2, which may
not run it. CPU 3's idle loop does try to steal on every pass, but `steal_one` picked only
the single longest queue, CPU 0 (length 2 only because the Blocked runner is a member, and
the tie with CPU 2 went to the lower CPU), and nothing there may run on CPU 3. Load
balancing has the same single-source shape. So the task was stranded; the other workers
spun at the barrier waiting for it, and the runner waited for them. Without the barrier
the stranded worker only delays its own round until the other queues drain, which is why
the cpu profile hung once in 28,000 rounds and the smp profile, after the barrier, within
100-500 rounds. Nothing was lost on the exit path; the earlier reading was wrong.

Fix: `steal_one` now collects every other online CPU with queued work, sorts them by
length, and tries each source (`steal_from`, the old per-source body) until one yields a
task that may run here. Verification pending: g60 (full ladder plus the soak). The
`stall_dump` code stays compiled into stress builds only.

Final kernel (g60, `/tmp/nilix-gap56-1017a` with the F11 fix and the `stall_dump`
diagnostic, 36 files hash-verified; logs `/tmp/g60-*`, soak artifacts
`/tmp/nilix-stress-v2.ZtePvW3j`):

| Gate | Result |
|------|--------|
| `make build`, hosted (468), `make lint` | OK |
| `make test` | QUALIFIED 35/39/0 |
| ring3-mm on 1, 2, 2, 4, 4, 8, 8 CPUs | 7/7 RING3-MM OK, each `23 passed, 0 failed`, every CPU online |
| musl-check on 1, 1, 2, 4, 8 CPUs | 5/5 MUSL-CHECK OK |
| SMP 2/4/8/16 | QUALIFIED 37/37/0 on each; 8/16: NX 0, CPU resets 0, IPI and TLB shootdown PASS |
| Soak memory | QUALIFIED, 3,036 rounds, 0 `[PF ENTRY]` |
| Soak cpu | QUALIFIED, full window, 7,079 rounds, 0 `[PF ENTRY]`, no stall dump |
| Soak smp | **Full window, 6,421 rounds, no hang and no stall dump** (F11 fixed for this reproducer; it hung within 93-495 rounds before). Rejected by the protocol because 92 rounds (1.4%) reported `spins=0`; see below |
| Metrics | `NILIX_SCHEDSTAT` in every profile's log; smp: about 17,000-19,600 migrations into each CPU, RCU backlog 0, 3 wait over-wakes |

**Zero-contention rounds.** The start barrier makes the four workers start together, but
on TCG the vCPU threads do not always overlap, so about 1% of rounds still saw no failed
acquire, and the protocol rejects any round without contention. The runner now seeds
contention: worker 0 takes the lock before it arrives at the start barrier and holds it,
as its iteration 0, until another worker has failed to acquire it
(`SharedRegion.contended`, set in `spin_lock_acquire`). No other worker can run an
iteration without the lock, so one of them fails an acquire once the barrier opens, and
the counter and checksum are unchanged. The worker-fork failure path releases the seed as
it releases the barrier. A first version took the lock after the barrier and deadlocked
when the other three workers ran all their iterations before worker 0 started (g62, round
120; the stall dump showed them as zombies and worker 0 spinning on CPU 0).

**Host race in the marker wait (g61).** The first smp run with the seed (g61) was rejected
before round 1: `malformed or unknown stress-v2 marker: 'NILIX_STRESS_V2_BEGIN run=…
profile=smp confi'`, although the serial log holds the complete line. `command_wait_marker`
polls the live serial file through `protocol_lines`, which kept the final unterminated
line; the guest's serial writer emits a line byte by byte, so a poll mid-write saw half a
marker and failed the run. Pre-existing host-side race, not a guest fault. Live polling
now ignores an unterminated final line (`protocol_lines(..., live=True)`); the post-run
parse is unchanged. Two host self-tests cover both modes (16 self-tests pass). g62 then ran with both
fixes and hit the seed deadlock above; verification of the corrected seed is g63 (smp
profile alone):

| Run | Result |
|-----|--------|
| g63 smp profile (final runner and protocol; artifacts `/tmp/nilix-stress-v2.fnmqZjYc`) | **QUALIFIED**: full window, 6,630 rounds, every round contended (0 rounds with `spins=0`), no stall dump, 0 `[PF ENTRY]`; 16 host self-tests pass |

With g60's memory and cpu profiles, all three soak profiles qualify on the final kernel.
No kernel source changed after g60; g61-g63 changed only `userspace/stress_runner.c` (smp
worker) and `scripts/gates/stress/stress_protocol.py` (live marker wait) plus its tests.

The first g58 pass filled the host disk: eight parallel ring3-mm boots and the kept bisect
artifacts left about 77 GB of QEMU `-d int` logs, so the musl boots could not write their
logs and the SMP and stress steps failed with `No space left on device` before running
anything. The ring3-mm boots had finished first. The interrupt logs of this session's runs
were deleted (serial logs and the cited stress artifacts kept) and the failed steps rerun as
g58b; those first-pass failures are environmental and count neither way.

## Residual risk

- Thread sharing (signal table, fs context, fd table, thread group) runs only in the
  guest test builds; it passes on 1/2/4/8 CPUs (g58) but has not run at 16 CPUs or under a
  pressure soak.
  The lifetime/lock argument for G1/G2/G7 and `FilesTable` has had no independent review
  (a review started on 2026-10-17 was stopped before it reported).
- `FUTEX_REQUEUE` wakes instead of moving waiters: correct for retrying users, but a
  broadcast wakes every waiter at once (thundering herd).
- Exec from a thread group returns `EBUSY` instead of Linux's kill-siblings-and-unshare.
- F11 fix (multi-source stealing) is verified by the g60 gates and the g60/g63 soaks only.
  Load balancing (`balance_queues`) still picks one busiest and one idlest CPU, and
  `sched_setaffinity` does not move a task off a CPU it may no longer use; stealing now
  covers both, but neither was changed.
- The soak profiles qualify (not strictly pass); process, block and combined profiles
  still fail on features outside §5/§6 (`RLIMIT_NPROC`, `fsync`, `open` mode).
- `WaitQueue::finish_wait` keeps the single-reschedule shape that F13 removed from
  `finish_prepared`; its callers loop, but it was not re-reviewed.
- F12 trade-off: a release kernel that hangs inside fault resolution leaves no
  `[PF ENTRY]` trace; debug builds keep the entry trace.
- W-3 bounds wait wakes, not general wait-queue work.
- F7 contiguous-stack fragmentation under memory pressure is unmeasured.
- F9: guests with 2 GiB of RAM or more panic in early boot (pre-existing).
