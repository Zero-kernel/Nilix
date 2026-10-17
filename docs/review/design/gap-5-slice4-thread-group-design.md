# GAP-5 Slice 4: Thread Groups (`CLONE_VM|CLONE_SIGHAND|CLONE_THREAD`) Design

Status (2026-10-17): steps 1-6 implemented; step 7 staged behind the `thread_preview`
feature, which only guest test builds enable. Verification pending: default builds still
refuse the thread flags, and default enablement waits for an independent review and
exec-from-a-thread semantics (see Steps). Designed 2026-10-16. Parent:
[GAP-5/6 status](gap-5-6-threads-scheduler-status-2026-09-28.md), plan §5
(`docs/design/kernel-gap-implementation-plan-2026-09-13.md`).

Plan §5 orders the work: `CLONE_VM|CLONE_SIGHAND|CLONE_THREAD` first (own user stack,
same tgid, no namespace creation), then `CLONE_FILES`, then `CLONE_FS`. This document
covers the first step. Without `CLONE_FS`/`CLONE_FILES`/`CLONE_SYSVSEM` musl's
`pthread_create` still fails, so only raw-`clone` users gain from it; the pthread
workload comes after slices 3 and 2 are enabled.

## Current tree facts (verified 2026-10-16)

`sys_clone` already builds most of a thread: shared tgid and `is_thread`, a shared
group-exit token (`Arc<AtomicBool>`, R153-3), shared credentials and capability table,
and a shared `SignalTable` under `CLONE_SIGHAND`. `SUPPORTED_CLONE_FLAGS`
(`syscall.rs:4662`) rejects `SIGHAND/THREAD/FILES/FS`, pinned by
`rf186_clone_contract_tests`.

Already correct:

- **TLS before runnable.** `fs_base`/`gs_base` are written under the child lock
  (`syscall.rs:5668-5687`) before scheduler admission (`:6026`, `Provisioning`) and the
  Ready commit (`:6147`); the switch path saves and restores FS/GS (`enhanced_scheduler.rs`
  ~2527-2694) and SYSRET commits the staged bases (`arch/syscall.rs:1230-1241`).
- **exec in a multi-threaded group** returns `EBUSY` (`syscall.rs:6339-6386`); it does
  not kill siblings.
- **Shared address-space teardown.** `keep_address_space` and
  `mm_shared = Arc::strong_count(&mm) > 1` keep the last-owner rules; per-fd capability
  refcounts are paid back per thread.
- **cgroups.** Threads are attached and charged per task; migration is refused while the
  address space is shared.

Missing or wrong (the gaps this slice closes):

| # | Gap | Evidence |
|---|-----|----------|
| G1 | A thread is a child of its creator: listed in `children`, reapable by `wait4(-1)`/`wait4(tid)`, sends `SIGCHLD` on exit, and is never auto-reaped. Zombie threads keep the address-space share count above 1, so exec and cgroup attach stay `EBUSY`. The leader becomes a reapable zombie while threads still run. | `terminate_process` (`process.rs:9354-9676`), `wait_reap_core` (`syscall.rs:7698`), `cleanup_zombie` refuses self-reap |
| G2 | Fatal default signals, user faults, seccomp kill and OOM terminate one task, not the group. | `signal.rs:1126-1134`, `syscall.rs:8726-8747`, `arch/interrupts.rs:709/738/1335/1393`, `syscall.rs:3936`, `process.rs:11563` |
| G3 | The exit-time `CLONE_CHILD_CLEARTID` write and futex wake are skipped unless the word lies in an mmap region; `.bss`/`.data`/main-stack words are never cleared. This is live today for `CLONE_VM|CLONE_CHILD_CLEARTID`. | `process.rs:9552-9625` |
| G4 | The futex prepare gate admits one prepare per tgid; two threads of one group waiting at once get `ENOMEM`. | `ipc/futex.rs:348-361` |
| G5 | `getpid` returns the caller's own id and `getppid` the creating thread. | `syscall.rs:8033-8061` |
| G6 | A thread is created in the caller's `pid_ns_for_children`, which differs from the caller's namespace after `unshare(CLONE_NEWPID)`. | `process.rs:5160`, `syscall.rs:5430` |
| G7 | Process-directed signals go to the leader only (`ESRCH` once it is a zombie); no `tkill`/`tgkill`; no group stop. | `signal.rs:907-1201` |
| G8 | Lower priority: orphan reparenting to a surviving sibling, namespace-init death with live siblings, LSM `tgid = pid`, procfs listing, futex `FUTEX_PRIVATE_FLAG`, `get_robust_list`. | survey 2026-10-16 |

Related finding, not a thread gap: futex keys are `(tgid, uaddr)` (`ipc/lib.rs:757`), so
a `CLONE_VM` child that is not a thread cannot futex-wake its parent on a shared word.
Linux keys private futexes by address space.

## Target semantics

- **Identity.** `getpid` returns the group's namespace-local tgid, cached per thread at
  creation (the leader's namespace mapping disappears when it exits). `getppid` returns
  the leader's parent. `gettid` is unchanged. `CLONE_THREAD` is `EINVAL` unless
  `pid_ns_for_children` is the caller's own namespace.
- **Tree.** A thread's `ppid` is the leader's parent, and it is not inserted into any
  `children` list. `wait*` never returns a non-leader thread. A thread's exit sends no
  `SIGCHLD`.
- **Non-leader exit.** The thread becomes a zombie that is released without a waiter: a
  reaper context (not the dying thread, which runs on its own stack) frees it. Kernel
  stack reclaim already defers through RCU.
- **Leader exit with live threads.** The leader stays a zombie that is not reportable.
  When the last thread of the group exits, the parent is notified once (`SIGCHLD` plus
  wake) and the leader becomes reapable with the group exit status.
- **Group death.** One helper (`kill_thread_group(tgid, code)`) sets the shared token and
  calls `request_exit_group_atomic`. Fatal default signal dispositions, fatal user faults,
  seccomp kill and OOM kill go through it. `exit_group` keeps its path. The token
  becomes a generation (`AtomicU64`) so a racing `clone(CLONE_THREAD)` that observed the
  pre-exit generation is refused at publication.
- **Signals.** `kill(tgid)` picks a live thread that does not block the signal, otherwise
  queues on the leader if alive, otherwise any live thread. `tgkill(tgid, tid, sig)` and
  `tkill(tid, sig)` target one thread. Group stop/continue applies to every thread.
- **clear-tid.** Self-exit writes 0 with the fault-tolerant `copy_to_user_safe` for any
  user address (`< USER_SPACE_TOP`) and futex-wakes only when the write succeeded; no
  mmap-region gate. A fault (unmapped, not present) skips the wake, as Linux does.
- **Futex prepare.** Admission is per task (tgid, tid), with the existing global bound on
  concurrently preparing tasks.

## G1 detail: `ThreadGroup` handle and reaping

Replace the bare group-exit token (`thread_group_exiting: Arc<AtomicBool>`) with one shared
object, `thread_group: Arc<ThreadGroup>`:

```text
ThreadGroup { exiting: AtomicBool,        // today's token (step 5 makes it a generation)
              members: AtomicUsize,       // tasks of this tgid present in PROCESS_TABLE
              parent_notified: AtomicBool } // group exit reported to the parent once
```

- **Membership.** `Process::new` creates a group with `members = 1`. The CLONE_THREAD
  publication (already under `PROCESS_TABLE`) installs the creator's group in the child
  and increments `members`. Every removal of a task from `PROCESS_TABLE`
  (`cleanup_zombie`, `cleanup_unscheduled_process`) decrements it under the same lock.
  So `members` changes only under `PROCESS_TABLE`.
- **Out of the tree.** At clone's final commit (after the last rollback path; earlier,
  `cleanup_unscheduled_process` reads `ppid == 0` as "joined a cpuset"), a thread is
  removed from the creator's `children` and gets `ppid = 0`. The existing exit, switch
  handoff (`finish_pending_prev` → `wake_reaper_after_switch`) and wait fallback scan
  already treat `ppid == 0` as "no parent": no `SIGCHLD`, no parent wake, never matched
  by `wait*`. `getppid` reads the leader (G5).
- **Auto-reap.** After `teardown_done`, `terminate_process` marks a non-leader thread in a
  static PID bitmap (`PID_MAX` bits) and raises a pending flag. The process-context
  deferred drain (`scheduler_hook.rs`, beside `drain_deferred_irq_terminates`) calls
  `cleanup_zombie(pid)` for each marked pid that is `Zombie && teardown_done && !on_cpu &&
  !switch_reap_pending`, and leaves the others marked for the next drain. Only this drain
  reaps non-leader threads, and a pid cannot be recycled before it is reaped, so the bit
  needs no generation. The drain never runs on the dying thread's own stack
  (`cleanup_zombie` refuses self-reap).
  `wait_reap_core` also runs the drain at the top of every pass. Found by the first
  guest run (g56l): on one CPU a parent blocked in `wait4` spins in its rescan loop,
  where no other process context ever runs the deferred drain, so a group whose leader
  exited before its last thread was never reported.
- **Leader.** `wait_reap_core` and `cleanup_zombie` treat a zombie leader as reapable only
  when `members == 1`. Once the leader is a zombie and alone it cannot gain members, so
  the check is stable.
- **Parent notification, exactly once.** Two places decide, both under `PROCESS_TABLE`
  and after the leader's `teardown_done` store: the leader's own exit (notify if
  `members == 1`) and the removal of a non-leader (notify if `members` drops to 1 and the
  leader is a torn-down zombie). Whichever runs second sees the other's effect, so at
  least one notifies; `parent_notified` (CAS) makes it exactly one. A single-task
  process takes the first path, so its exit sends `SIGCHLD` exactly as today, at the
  cost of one extra `PROCESS_TABLE` acquisition per exit.

## G2 detail: group death

- A fatal outcome sets `Process.group_fatal` under the PCB lock: the send-time fatal
  default (`send_signal_inner`), the safe-point default (`apply_default_at_safepoint`),
  seccomp Kill/Trap, signal-frame and `rt_sigreturn` failures, fatal user exceptions and
  page faults (`terminate_group_self_and_halt`), and the OOM post (`oom_kill`).
- `terminate_process` takes the flag in its first critical section. Right after the
  Zombie publication it stores `thread_group.exiting` and calls
  `request_exit_group_atomic(pid, &group, code)`, the same marking exit_group uses, in
  process context with no lock held. Siblings consume an ordinary pending kill and do
  not set the flag, so marking does not recurse.
- A remote fatal post sets the flag at post time, so the target's later self-termination
  through `take_pending_process_exit` still ends the group.
- `request_exit_group_atomic` returns without scanning the table when the caller is the
  group's only member, so single-task processes pay one table-lock acquisition and
  behave as before.
- Not yet: the exiting flag is still a bool, not a generation; group stop and
  process-directed signal routing are G7.

## G7 detail: signals

- `send_signal` and `send_signal_kernel` (kill(2) and the parent SIGCHLD, the only two
  callers) are process-directed: `select_process_directed_target` picks the named task
  if it does not block the signal, else another live member that does not, else the
  named task if live, else any live member. A single-task group skips the scan.
- `tkill` (200) and `tgkill` (234) are dispatched. They share `kill_common` with kill(2),
  so namespace translation, init protection, POSIX/user-namespace permission and the LSM
  hook are identical; `tgkill` additionally requires the tid to belong to the named
  group (else `ESRCH`). Non-positive ids are `EINVAL`. Delivery uses
  `send_signal_thread`, which skips target selection. musl's `raise()` uses `tkill`,
  which was `ENOSYS` before.
- Job control is process-wide even when thread-directed: a stop applied to the target
  and every SIGCONT are carried to the other live members
  (`propagate_group_job_control`) before a self-stop parks the sender. A posted fatal
  exit still wins over the stop.
- Fatal defaults end the group through G2.
- Not covered: a shared pending queue (the plan keeps pending per task, so a signal
  blocked by every member waits on one thread), `rt_tgsigqueueinfo`, `sigaltstack`, and
  pledge grants for `tkill`/`tgkill` (they have no seccomp promise constant yet).

## Futex ABI and the musl pthread workload

- `sys_futex` decodes the Linux ABI (`decode_linux_futex_op`, `syscall.rs`).
  `FUTEX_PRIVATE_FLAG` (128) is masked: futexes are always keyed by tgid, so private is
  the only mode. `FUTEX_LOCK_PI`/`FUTEX_UNLOCK_PI` moved from the custom 3/4 to Linux 6/7,
  and the old custom op 2 (`FUTEX_WAIT_TIMEOUT`) is gone; no in-tree caller used the custom
  numbering. Served operations:

  | Op | Behaviour |
  |----|-----------|
  | `FUTEX_WAIT` (0) | Optional relative timeout |
  | `FUTEX_WAKE` (1) | Wakes up to `val` waiters |
  | `FUTEX_REQUEUE` (3), `FUTEX_CMP_REQUEUE` (4) | Added 2026-10-17. Both counts are validated as non-negative ints (`nr_requeue` from the timeout slot); `uaddr2` must be an aligned user address; `CMP_REQUEUE` returns `EAGAIN` when `*uaddr != val3`. The would-be requeued waiters are **woken** instead of moved (see below) |
  | `FUTEX_LOCK_PI` (6), `FUTEX_UNLOCK_PI` (7) | Unchanged PI implementation |
  | `FUTEX_WAIT_BITSET` (9), `FUTEX_WAKE_BITSET` (10) | Added 2026-10-17, only with `FUTEX_BITSET_MATCH_ANY`. The wait timeout is absolute, measured on the millisecond tick that `clock_gettime` reports for both clocks; a deadline already passed times out after the value check |

  Everything else is `ENOSYS`: `FUTEX_WAKE_OP`, the requeue-PI pair, `FUTEX_LOCK_PI2`, and
  bitset ops with a partial mask. A partial mask is refused rather than widened to
  MATCH_ANY, because a targeted `WAKE_BITSET` could then wake a waiter of another mask and
  leave the intended one asleep. As on Linux, `FUTEX_CLOCK_REALTIME` (256) is accepted
  only with `FUTEX_WAIT_BITSET` (`ENOSYS` otherwise). Hosted test:
  `gap5_futex_abi_tests::linux_futex_ops_decode_to_served_requests`.
- **Requeue by wake.** Each waiter keeps a reference to the bucket it sleeps in and
  decrements that bucket's waiter count itself, so moving it to another queue would need a
  per-waiter bucket handoff. Instead, `REQUEUE`/`CMP_REQUEUE` wake up to
  `nr_wake + nr_requeue` waiters on `uaddr`. This is ABI-legal: `FUTEX_WAIT` may return 0
  spuriously, and requeue users (musl's and glibc's condition variables) re-check their
  word and wait again on `uaddr2` if needed. The cost is a thundering herd on broadcast,
  never a lost wake-up. Before this change `FUTEX_REQUEUE` returned `ENOSYS`, which hangs
  musl's `pthread_cond_broadcast` with two or more sleeping waiters: musl clears the next
  waiter's barrier word and relies on the requeue to wake it.
- musl's `pthread_create` passes `CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|
  CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID|CLONE_DETACHED`.
  The preview accepts `CLONE_SYSVSEM` (no SysV semaphores exist, so there is no undo list)
  and `CLONE_DETACHED` (ignored by Linux since 2.6). The `musl_test` kernel feature turns
  the preview on.
- `userspace/pthread_probe.c` (part of the musl guest): four `pthread_create`d threads
  contend on a `pthread_mutex_t` 2000 times each, park on a condition variable until one
  `pthread_cond_broadcast` releases all of them (musl's requeue chain), check `__thread`
  TLS, report `getpid`/`gettid`, `dup` a descriptor into the shared table, and are joined
  with their return values. The main thread then requires `ETIMEDOUT` from a 5 ms
  `pthread_cond_timedwait`. `musl_check.sh` requires `MUSL-PTHREAD-OK`. That timed wait,
  made on one CPU right after the threads exit, exposed F13: `WaitQueue::finish_prepared`
  took a reschedule that returned without a switch as a wake and left the task `Blocked`,
  which later lost PID 1 (status record, "Second batch"). Fixed by yielding until the wait
  is resolved. The ring3-mm futex leg also checks that a lone 20 ms timed wait times out;
  that check passes on the old kernel too, so the musl leg remains the F13 reproducer.
- Ring-3 leg `test_futex_requeue` (ring3-mm, in a forked host): the argument contract
  above, then `CMP_REQUEUE` must count a sibling thread sleeping in `FUTEX_WAIT` exactly
  once and that thread's wait must return 0. The leg then wakes `uaddr2` too, so it also
  holds on Linux, where the waiter would still be asleep on the target.

## Lock order and lifetime

- Existing order: `PROCESS_TABLE` → PCB lock → leaf locks (signal table, fs context, cap
  table, mm). Group scans take `PROCESS_TABLE` and then each PCB, never a PCB first.
- Auto-reap of a non-leader thread runs in process context after the dying thread's
  `on_cpu` clears, reusing the deferred-kill drain discipline (`process.rs:9245`).
- Leader notification is decided under `PROCESS_TABLE` (count of live group members),
  so two last-thread exits cannot both, or neither, notify.
- Final `Arc` drops (signal table, fs context, mm) happen outside PCB and table locks.

## Steps (each gated; the flag stays rejected until step 7)

1. **G3 clear-tid** (live bug): remove the mmap-region gate, wake only after a successful
   write. Ring-3 test: `CLONE_VM|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID` with the tid word
   in `.bss`; the parent polls for 0 with a bound (the futex wake cannot reach the parent
   until futex keys follow the address space).
2. **G4 futex prepare** per task, with a hosted test of two concurrent preparers of one tgid.
3. **G5/G6 identity**: cached namespace-local tgid, group parent, namespace check. Hosted
   tests for the selection logic; non-thread behaviour unchanged in Ring 3.
4. **G1 tree and reaping**: thread-aware `terminate_process`, `wait_reap_core` filter,
   auto-reap queue, delayed leader notification. Hosted tests for the
   last-member/notify decision.
5. **G2 group death**: implemented through `group_fatal` (see G2 detail); generation token open.
6. **G7 signals**: implemented (see G7 detail).
7. **Enable**, staged. Done so far: a `thread_preview` cargo feature of `kernel_core`, implied by the guest-only `syscall_test` and `musl_test` features, adds `CLONE_SIGHAND|CLONE_THREAD|CLONE_FS|CLONE_FILES|CLONE_SYSVSEM|CLONE_DETACHED` to `SUPPORTED_CLONE_FLAGS` (`CLONE_FILES` only inside a thread group); default and production builds still refuse them. The ring3-mm guest runs a four-leg thread workload in forked hosts (identity and clear-tid join, exit_group from a non-leader, a `CLONE_FILES|CLONE_FS` shared-table leg, process-directed SIGKILL), each ending in exactly one parent reap, plus the futex requeue leg; the musl guest runs real `pthread_create`/`pthread_join` with mutex, condition-variable and TLS checks. Exec from a thread group still returns `EBUSY`: Linux kills the other threads and unshares the fd table (`de_thread`, `unshare_files`), which is not implemented. On the final tree (g58) these legs pass on 1/2/4/8 CPUs. Default enablement remains: exec semantics, a 16-CPU run, then update
   `rf186_clone_contract_tests`. Ring-3 raw-clone workload: two threads on separate
   stacks share memory, `getpid` equal and `gettid` distinct, `kill(getpid())` handled by
   a non-blocking thread, `tgkill` hits one thread, a thread exit is not reaped by
   `wait4`, `exit_group` from a thread ends the group, the parent reaps once with the
   group status, exec from a two-thread group is `EBUSY`, and the clear-tid futex wakes a
   joiner. Independent lock/lifetime review. Gates: build, lint, hosted, `make test`,
   ring3-mm, SMP 2/4/8/16.

G8 items follow step 7 and are tracked in the status record.

## Open: exec from a thread group (before default enablement)

Today `execve` from any member of a group with more than one member returns `EBUSY`
(the address space and fd table are shared). Linux instead runs `de_thread`: the caller
kills every other member, waits until they are gone, takes over the leader's PID if it is
not the leader, and then unshares the fd table (`unshare_files`) before loading the image.
musl's `posix_spawn` and `system` use a `CLONE_VM|CLONE_VFORK` child, not a thread, so the
common spawn path is unaffected; a threaded program that calls `execve` directly is.

Proposed order, each step gated like the ones above:

1. **Leader exec.** Add a group "exec in progress" state, distinct from `exiting`, so the
   siblings die without a group exit status or a parent report. Post a kill to every other
   member (as `request_exit_group_atomic` does, minus the caller) and wait, interruptibly
   by a kill aimed at the caller, until `members() == 1`; the auto-reap drain releases the
   siblings. The shared mm and `FilesTable` then have one owner, and the existing exec path
   runs unchanged. Ring-3 leg: a two-thread group whose leader execs a marker program and
   is reaped once with the new image's status.
2. **Non-leader exec.** The caller must take over the group's PID: the `PROCESS_TABLE`
   slot, the PID-namespace mappings, `ns_tgid`, the parent's `children` entry and the
   cgroup membership all name the leader. This needs its own design; until then a
   non-leader exec keeps returning `EBUSY`.
3. **Close-on-exec on a table shared outside the group.** Not reachable: `CLONE_FILES`
   is refused outside a thread group, so after step 1 the table has one owner.

## Acceptance

- Every step: no regressions on the gate ladder; hosted tests for its decision logic.
- Step 7: the Ring-3 thread workload passes on 2/4/8/16 CPUs; zombies, PIDs and kernel
  stacks return to baseline after the workload (procfs task count and `pids.current`);
  independent review finds no D0-D2 lifetime or lock-order defect.
