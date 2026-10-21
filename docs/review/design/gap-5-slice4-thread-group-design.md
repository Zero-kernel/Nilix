# GAP-5 Slice 4: Thread Groups (`CLONE_VM|CLONE_SIGHAND|CLONE_THREAD`) Design

Status (2026-10-20): steps 1-7 done. Every known gap is closed and the thread flags are
accepted in every build (`thread_preview` removed): G1-G8, the G7 shared pending set,
futex parity (true requeue, `FUTEX_WAKE_OP`, partial bitsets, keys by address space),
the PI user-word protocol and requeue-PI, and exec from the leader and from a non-leader.
Independent reviews of the exec, G7/G8 and PI work left no open D0-D2; the remaining
D3-D5 debt is listed in each section's review table and "Not covered" notes. Final-tree
gate results: the status record's "Fourth batch". Designed 2026-10-16. Parent:
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
Linux keys private futexes by address space. (Closed 2026-10-20: keys follow the address
space, see "Futex parity".)

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
- **Init protection is per process** (review D1, 2026-10-20): `kill_common` and
  `send_signal_inner` test the target's `tgid` (`is_init(tgid)`, `tgid == 1`), so a
  non-leader thread of PID 1 or of a namespace init is protected like its leader,
  whichever of `kill`, `tkill` or `tgkill` names it (Linux `SIGNAL_UNKILLABLE`).
- **A stop applied at a safe point stops the group** (review D2, 2026-10-20):
  `apply_default_at_safepoint` carries the stop to the other members
  (`propagate_group_job_control(pid, false)`) before it parks, as the send-time path
  does.
- The shared pending queue is covered by "G7 shared pending set" below.
- Not covered: `rt_tgsigqueueinfo`, `sigaltstack`, and pledge grants for
  `tkill`/`tgkill` (they have no seccomp promise constant yet).

### procfs thread listing (2026-10-20)

The G8 procfs item, in `kernel/vfs/procfs.rs` only (kernel_core is unchanged).

- **Listing.** `/proc` readdir lists thread-group leaders only (`tgid == pid`). A
  non-leader id still resolves by lookup (`/proc/<tid>`), as on Linux.
- **Task directories.** `/proc/<pid>/task/` lists the live members of pid's group as
  ids in the viewer's PID namespace, leader first, then by global id; `<pid>` may be
  any member. `/proc/<pid>/task/<tid>/` serves `status cmdline stat maps uid_map
  gid_map fd` for that thread through the per-pid code (no nested `task`). Lookup
  binds the tid exactly as `/proc/<tid>` does (DAC, viewer namespace, generation) and
  returns `ENOENT` for a task outside the group. `..` works from both directories.
- **Membership** is `Arc::ptr_eq` on `thread_group`, never the tgid number.
- **Group fields.** For every task, `status`/`stat` report Tgid (and stat
  pgrp/session) as the group id, PPid as the leader's parent (a thread's own `ppid` is
  0), and `Threads:`/stat field 20 as the live member count. The stat line now has the
  52 proc(5) fields; it had 46, with priority in field 17 and a constant 1 in field 19.
- **Self links.** `/proc/self` names the caller's group leader, as `getpid()` does,
  and falls back to the calling task when the leader cannot be bound (a zombie, or
  refused by DAC). `/proc/thread-self` is a symlink to `<tgid>/task/<tid>` in the
  caller's namespace. `/proc/self/task` comes from the pid directory.
- **Lock order.** One helper, `scan_thread_group`, takes `PROCESS_TABLE` and then one
  PCB at a time; it never takes the table while holding a PCB lock. PID-namespace
  translation runs after both are released. The membership check at lookup takes
  the two PCB locks one after the other, not nested.
- **Allocation bounds.** The listing snapshot is an `AdmittedVec<TaskMember>`
  (Procfs class). It is reserved before `PROCESS_TABLE` is taken, sized by the group's
  reference count (each member PCB holds one) and capped at `PID_MAX`, and it grows
  only through `try_push`. A task whose group has one reference skips the scan, so
  single-threaded `status`/`stat` reads cost what they did. As in the root listing,
  each readdir step rescans the table.
- **Visibility** (`proc_task_visible`). A zombie leader whose group still has live
  threads stays visible, as on Linux: it is listed in `/proc`, `/proc/<tgid>`
  resolves, and `/proc/<pid>/task` lists it (first) and `Threads:` counts it (review
  D5, 2026-10-20; the listing and the count use the same test). A task still being
  created (`Provisioning`) is hidden everywhere, as Linux attaches a new task's ids
  only once it is complete. Other zombies are hidden (Linux shows a zombie process
  until it is reaped; a deviation).
- **Not covered.** `..` from `/proc/<pid>/task/<tid>/fd` leads to `/proc/<tid>`. A
  sibling's entries stay subject to per-task DAC, so a caller whose UID is unmapped in
  its user namespace is refused where Linux exempts the same thread group.
- **Tests.** Hosted, vfs (3 new): leader-first ordering and the root filter; the
  52-field stat line with `num_threads` in field 20; a `PROCESS_TABLE` fixture with a
  leader, two threads and an unrelated task that has the leader's tgid number. The
  fixture covers the root listing, lookup of a hidden tid, `task/` reached from the
  leader and from a thread, refusal of the unrelated task, per-task `status`/`stat`
  fields, `..`, `self`/`thread-self` read by a thread, a zombie member leaving the
  listing and the count, a `Provisioning` member neither listed nor reachable, and a
  zombie leader with a live thread still listed and counted. Ring 3 (ring3-mm, `test_proc_thread_listing`): a forked host
  with one spinning CLONE_THREAD member checks the root listing, `/proc/<tid>/status`,
  that `/proc/<host>/task` lists the host and then the thread, and `Tgid`, `Pid` and
  `Threads: 2` in the thread's task status. PASS line: `procfs lists group leaders and
  /proc/<pid>/task members with Tgid and Threads`.

### G7 shared pending set (2026-10-20)

Gap: pending sets were per task, so a process-directed signal queued on one thread was
lost if that thread exited first (the exec drain made this reachable, review F2a), and a
signal blocked by the chosen thread waited there even after another thread unblocked it.
Linux keeps process-directed signals in `signal->shared_pending`.

- **State.** `ThreadGroup.shared_pending: AtomicU64`, one bit per signal like the private
  `PendingSignals`. Atomic, so it is read under any member's PCB lock with no new lock
  order; a fork gets a new group (empty set), exec keeps the group (set preserved).
- **Send.** `send_signal` and `send_signal_kernel` (kill(2), SIGCHLD, cascades) queue in the
  group set; `send_signal_thread` (`tkill`, `tgkill`) queues in the target's own set.
  Target selection still decides which thread is woken and which runs send-time default
  actions (fatal, stop, continue, ignore); those consume the instance from both sets.
- **Visibility.** Delivery checks use `Process::pending_bits()` = own | group
  (`signal_is_deliverable` callers on the delivery paths, the send-time wake,
  `discard_inert_pending`, `has_pending_signals`). Wait aborts use
  `wait_pending_bits()` instead (below).
- **Claim before delivery.** Delivery picks a signal under the PCB lock, builds the frame
  without it, and clears the bit only at commit. A group bit is therefore claimed first:
  `Process::claim_pending(sig)` moves it into the task's own set with one atomic
  fetch-and-clear, so two threads can never both deliver it; the loser finds nothing to
  deliver. The three delivery paths (syscall-return safe point, IRQ return,
  `apply_default_at_safepoint`) claim right after selection and otherwise run unchanged.
- **Discard.** Ignored dispositions, consumed defaults and the SIGCONT/stop mutual
  exclusion clear both sets (`discard_pending`).

**Claim tracking, chosen member and retargeting (review D3 #4-#6, 2026-10-20).** The first
version claimed before the commit and kept a deferred claim in the claimant's own set,
woke only the selected member, and let every member's wait abort for any group bit.
The rework follows Linux's `TIF_SIGPENDING` model:

- **Claimed bits** (`Process.group_claimed`). `claim_pending` records a bit it moved out
  of the group set; a commit or consumption clears it (`consume_own_pending`); a
  thread-directed instance of the same signal clears it at send time (that instance is
  the task's own). `return_claimed_signals(mask)` moves claimed, undelivered bits in
  `mask` back to the group set.
- **Chosen member** (`Process.shared_chosen`, one bit per signal). The send sets the
  signal's bit on the member it selected. `wait_pending_bits()` = own | (group set &
  chosen bits) is what `should_abort_pending_block` and `has_deliverable_signal` (every
  interruptible wait) test, so only the member chosen for a signal ends its wait for
  it, and a choice for one signal never interrupts a wait for another. Delivery still
  sees the whole group set at every safe point.
- **Recalculation** (`recalc_shared_signals(mark)`, Linux `recalc_sigpending` plus
  `retarget_shared_pending`): claimed bits the task now blocks go back to the group, and
  it keeps only chosen bits it can take now: unblocked, and none while it runs a handler
  (handler frames do not nest here, so a caught signal waits until `rt_sigreturn`). A
  mask the task installs itself (`rt_sigprocmask`, `ppoll`, `pselect6`) also marks
  every group signal it can now take (`mark`, Linux `set_current_blocked`), so a
  non-leader whose `pselect6` mask opens for a signal queued earlier returns at once
  (second review D2). Without `mark` (syscall entry of a multi-member task, the top of
  every syscall-return delivery, a handler commit) it only prunes and hands back, so
  entering a syscall never turns into a spurious `EINTR`. The IRQ-return delivery path
  cannot take `PROCESS_TABLE`; the task's next syscall entry hands on what its new
  handler mask blocks.
- **Retarget** (`retarget_shared_signals`): when a recalculation says so, when the
  member a send selected cannot take the signal at queue time (it blocked it after the
  unlocked selection read its mask, or it is inside a handler and the signal is caught),
  or when a chosen or claiming member exits (`terminate_process` returns every claimed
  bit), another live member that does not block a pending group signal and is not
  inside a handler is chosen under `PROCESS_TABLE`, marked and woken if it waits. A
  single-member group skips the scan. Lock order `PROCESS_TABLE` -> one PCB at a time;
  never called with a PCB held. Selection also prefers a member that is not inside a
  handler.
- **Exec handoff.** The exec'ing thread returns its claimed group signals to the group
  before it snapshots its own pending set, and the leader returns its own claimed bits
  before installing that set, so a group signal is neither lost nor delivered twice
  across a non-leader exec.
- **Exit before claim.** Syscall-return delivery checks `pending_kill` before it claims,
  and runs the posted exit instead.
- **Selection race.** `send_process_signal` retries the selection (up to four times)
  when the selected member became a zombie before `send_signal_inner` locked it, so
  `kill(2)` on a live process no longer reports `ESRCH` and a kernel `SIGCHLD` is not
  dropped.

- **Not covered.** Pending stop bits in other members' own sets are not cleared by
  SIGCONT (only send-time defaults set them). The retry bound is four selections; a group
  that loses four selected members in a row reports `ESRCH`, as does `kill(tgid)` when
  the leader is a zombie and every live thread already has a posted exit (the process is
  dying). A `tkill` of a signal a thread has claimed from the group set merges the two
  instances (standard signals coalesce). With no syscall restart, a chosen member whose
  wait ended for a signal another member claimed first still returns `EINTR` (a narrow
  window between the abort and its own claim).
- **Tests.** Hosted: claim is exclusive and moves the bit; `pending_bits` merges; only the
  chosen member's wait sees group bits; a claimed bit the task then blocks goes back to
  the group and asks for a retarget; a thread-directed instance stays; an installed mask
  marks a queued group signal and a handler gives it up; a delivered claim leaves
  nothing to return; selection prefers a member outside a handler. musl guest
  (`pthread_signal_smoke`, marker `MUSL-PTHREAD-SIGNAL-OK`, required by musl-check):
  (A) `kill(getpid(), SIGUSR2)` while the main thread blocks it wakes the one worker
  that does not, out of `nanosleep`, and its handler runs there within 2 s; (B) every
  member blocks SIGUSR1, it is sent, then a worker's `pselect6` opens its mask and
  returns `EINTR` at once with the handler run in that worker. In both legs the main
  thread's later unblock delivers nothing more (exactly one delivery).

### G8 process-wide children, namespace init, identity (2026-10-20)

Gaps: a thread's children were the creating thread's alone (other threads got `ECHILD`;
the children went to the namespace init when that thread exited; `getppid` in the child
named the thread); a namespace init whose leader exited before its threads tore the
namespace down at once and cleared its reaper; the leader's PID mapping vanished with
the leader thread, so `kill(tgid)` failed while threads ran; LSM subjects carried
`tgid = pid`; no `get_robust_list`.

- **Live members.** `ThreadGroup.live` counts members that have not begun exiting; each
  task leaves once (`Process.group_live`, in `terminate_process`'s first critical section
  or in `cleanup_unscheduled_process` for a task that never ran). The atomic decrement
  that reaches zero names the one last live member.
- **Leader identity.** A leader that exits while its group has live members keeps its
  PID-namespace chain (mappings and any init registration) in its zombie PCB. The last
  live member takes it (`take_deferred_leader_chain`), runs the namespace-init cascade
  under the group id, and detaches it. A lone task is its own last member: unchanged.
  The zombie leader's PID cannot be recycled before its reap, so the retained
  registration cannot alias.
- **Reapers.** `reparent_orphans` gives a dying task's children to a live member of its
  group first (`live_group_member_locked`), and a candidate reaper that is a zombie
  leader with live members (a multi-threaded init) resolves to one of them
  (`resolve_reaper_locked`), as Linux moves `child_reaper`. Same one-PCB-at-a-time
  protocol under `PROCESS_TABLE` as before.
- **getppid.** A parent that is a non-leader thread is reported as its group: the leader's
  mapping, or the group's cached `ns_tgid` when the caller shares its namespace.
- **Group-wide wait.** A caller whose group has more than one member uses
  `wait_reap_group`: one `PROCESS_TABLE` pass collects the members, a second finds
  children of any member. Both wait paths claim a zombie (`Process.wait_claimed`, CAS)
  before reporting it, so two waiting threads never report one child; a failed report
  releases the claim. Single-member groups keep the existing blocking path unchanged
  apart from the claim.
- **Sleeping group wait** (review D3, 2026-10-20; it polled once per tick before, one
  global table scan per tick per waiting thread). `ThreadGroup.child_waiters` counts
  members inside the wait and `ThreadGroup.child_events` counts reports. The waiter
  reads `child_events` before its scan and again under its PCB lock just before it
  publishes `Blocked` (with `waiting_child = Some(0)`); a changed count means rescan.
  `notify_parent_of_group_exit` (the one funnel for "a child became reportable") wakes
  the recorded parent as before, then bumps `child_events` and, while `child_waiters`
  is non-zero, readies every member of the parent's group that sleeps in a wait for any
  child or for this child (`wake_group_child_waiters`, `PROCESS_TABLE` -> one PCB at a
  time, no lock held on entry). Either the report lands before the re-read or it finds
  the waiter `Blocked`. Two transitions send no report and are polled briefly instead:
  a reported zombie that has not switched out yet (`on_cpu`, `switch_reap_pending`,
  `teardown_done`), and a zombie another waiter claimed (its report may fail and
  release the claim). Signals, kills and an exec handoff wake the waiter through the
  existing paths and `should_abort_pending_block` at the commit.
- **Report target** (second review D2). The report used the parent pid read when the
  exiting task began `terminate_process`; if that parent thread exited meanwhile and
  handed the zombie leader to a sibling, the report went nowhere (no SIGCHLD, no wake)
  and a group wait could sleep for good, or a recycled pid got the SIGCHLD.
  `notify_parent_of_group_exit` now reads the leader's current parent, and that parent's
  thread group, under `PROCESS_TABLE` (where reparenting runs) when it reports.
- **Fork deadlock** (cpu soak, 2026-10-21). That report first locked the parent's PCB
  while it held `PROCESS_TABLE`. `fork_inner` ran with the parent's PCB held and looked
  the child up with `get_process` (PCB -> `PROCESS_TABLE`, the reverse of the documented
  order, pre-existing). A child whose exit was reported while its parent forked the next
  one deadlocked both, and every later table user spun behind them: the cpu soak
  stalled in four of four runs (52 to 202 rounds). QMP register samples showed the
  exiting child in `notify_parent_of_group_exit` spinning on the parent's PCB lock with
  the table held, and the parent in `fork_inner` spinning on the table. Fixed at the
  source: `sys_fork` passes the child's `Arc` into `fork_inner`. The report also takes
  only the zombie leader's PCB under the table and locks the live parent after
  releasing it, and `current_tgid` (the LSM tgid provider) no longer locks a PCB under
  the table.
- **Lock-order audit** (2026-10-21, independent, static). With the fork fix no path
  holds a PCB and then blocks on `PROCESS_TABLE`. Two indirect three-task cycles
  remained, each closed by any `PROCESS_TABLE` -> live-PCB scan (procfs `list_pids`, the
  wait4 fallback scan, `retarget_shared_signals`, `select_process_directed_target`,
  `wake_group_child_waiters`, the exec share counts, ...):
  - PCB -> `pipe.inner` (`PipeHandle::duplicate` under a PCB: every pipe `read`/`write`
    callback, `fork_inner`, `sys_clone`, `dup*`, `fcntl`, `fstat`, `lseek`) while a holder
    of `pipe.inner` arms or wakes a wait queue (`PROCESS_TABLE`). Fixed: the end counts
    are atomics outside `inner`; a duplicate starts from a live end (count >= 1 -> >= 2,
    no wake) and takes no lock; the decrement and every zero check stay under `inner`.
  - PCB -> `sockets.read()` (`SocketFile::try_clone_box`, status flags,
    `socket_handle_from_fd`) while `try_publish_cookie_child` woke an accept waiter
    (`PROCESS_TABLE`) with `sockets.write()` and `tcp_conns` held. Fixed: those two are
    released before the wake.
  - Suspected, not confirmed (debt): a two-task pipe variant needing a stale waiter
    entry for a running task; a `PidNamespace` Arc dropped under the table in
    `list_pids` (its drop takes `parent.children`); the unannotated usercopy fault
    fallback, which takes the table from whatever locks the faulting code holds.
- **1-CPU kill livelock** (ring3-mm on one CPU, 2026-10-21; pre-existing, timing
  dependent). A task killed while it spins in user mode is ended at a timer interrupt:
  the IRQ path puts it in the IRQ-kill non-runnable set and the deferred drain
  (`drain_deferred_irq_terminates`) terminates it from process context, which runs at
  syscall return, in nanosleep and in the idle loop. If the killer's time slice ended
  between `kill` and `waitid`, the victim's interrupt handed the CPU back to the killer
  while it was still `Ready`; the killer then blocked in `wait_reap_core` with nothing
  else runnable, and the scheduler keeps such a task on the CPU (only a terminal task is
  handed to the idle context). It spun in its wait loop and the drain never ran: two of
  five one-CPU runs hung (the thread-group SIGKILL leg and the clear-tid keeper). QMP
  samples showed only kernel-mode wait and scheduler frames; guest memory showed the
  victim in both the deferred-kill and non-runnable sets with the drain flag set.
  Fixed: `run_blocked_wait_drains` (deferred IRQ kills, then thread auto-reap) runs on
  every pass of the wait4/waitid loops (after their signal checks, so the scan reports a
  child the pass ended), the exec drain and `WaitQueue::block_until_resolved`, the
  busy-wait loops that stand in for idle.
- **Review of the livelock fix** (2026-10-21, independent, static): no self-deadlock;
  no wait holds a lock, permit or PCB across the sleep, and ending another task there
  takes only spin locks. D2: the victim's handoff could go straight to another Ready
  task that spins in user mode, and then no drain runs at all until some task enters the
  kernel (the same hang on one CPU, now with a bystander); the socket, stdin and stop
  barrier loops (D3) had the same gap. Fixed in `prepare_switch`: a task in the IRQ-kill
  set is always handed to the idle context, whose next pass drains it before it
  schedules, at the cost of one extra switch per IRQ kill. New ring3-mm leg: a spinner
  killed at a timer interrupt is reaped while another spinner runs. Also fixed: the
  drains read their pending flag before the swap (D4, cost). Debt: nothing asserts that
  the drained teardown never sleeps, which a waiter mid-wait now relies on (D4); the exec
  loop's drain is redundant with `yield_and_halt` (D5).
- **Second review** (2026-10-21, of the scheduler fix): no D0-D2; the handoff with a
  live candidate keeps every invariant of the existing no-candidate handoff (KSA-011
  `on_cpu`, a saved bootstrap context, tick debt, generation, FPU owner), and both idle
  loops drain before they schedule. D3, fixed: an exited non-leader thread also switched
  straight to a candidate, so with a user-mode bystander nothing auto-reaped it and a
  parent waiting for a group whose leader had exited hung; such a thread (marked for
  auto-reap) now goes to the idle context too, and a second ring3-mm leg covers it (the
  thread exits with its own code; the parent must see the leader's). D4, fixed: the BSP
  idle loop (the kernel shell) halted once before every drain, so each such handoff
  waited up to a tick; it now skips `hlt` while `need_resched` is set, as the AP idle
  loop does. D5, fixed: a wrong comment on the wait4 drain (its Blocked recheck still
  runs before the scan). Negative controls on one CPU: with the HEAD scheduler the guest
  stops at the kill leg; with the kill-only handoff, at the thread leg. Debt: the kernel
  shell polls the keyboard buffer that user stdin also reads before it drains (D3,
  pre-existing; now also after BSP handoffs); on SMP, a contended `finish_pending_prev`
  can leave the victim on its CPU at the idle pass, so the candidate runs first and
  another CPU drains it (D4); `waitid` reports a killed child as `CLD_EXITED` with
  128+signal where Linux reports `CLD_KILLED` with the signal, which the kill legs
  encode (D4, pre-existing); other deferred work (stdin wakes, TCP timers, RCU) still
  waits for a kernel entry when every task spins in user mode (the CPL3 soft-progress
  point is the general fix).
- **Review of these fixes** (2026-10-21, independent, static): no D0-D3; fork, report,
  pipe and socket changes are correct and break both cycles. Comments fixed: the
  `pipe.inner` invariant (never taken with a PCB held) is documented. Debt: the socket
  timer sweep calls `mark_closed` (a wake) under `sockets.read()` (D4, latent: harmless
  while spin's `RwLock` lets readers pass a waiting writer); the report signals and
  wakes the parent by pid after the table is released, so a reused pid can get a stray
  `SIGCHLD` (D4, pre-existing); `reparent_orphans` does not notify the adopter of an
  already-zombie leader whose whole parent group died (D4, pre-existing; Linux
  `reparent_leader`); the `parent_pid == 0` return comes after the parent lookup (D5).
- **Reparenting races** (review D2, 2026-10-20). `wait_reap_core` treats a `children`
  entry whose child's `ppid` is no longer the caller as stale. `reparent_orphans` moves a
  child only while its `ppid` still names the dying task. `wait_reap_group` unlinks the
  reaped child from its current parent under `PROCESS_TABLE` (reparenting runs under
  the same lock). A group that grows between the member reserve and the scan is
  rescanned instead of failing with `ENOMEM` (review D4).
- **LSM.** `lsm::register_tgid_provider`; `ProcessCtx::from_current` and
  `SyscallCtx::from_current` carry the real tgid.
- **get_robust_list (274).** The caller, a task of its own group, or an ADMIN/host-root
  caller (a conservative stand-in for the ptrace-read check).
- **Not covered.** A group wait scans the whole table per wake (two passes), and each
  report to a group with sleeping waiters scans it once more. A child's parent link
  still names the creating thread until it exits.
- **Tests.** Hosted: last-live selection and the zombie-leader reaper redirect. Ring 3
  (`test_thread_group_children`): the child of a live thread is reaped by the leader's
  `wait4(-1)` and sees the process as its parent; a thread exits before its child and the
  leader still reaps it; `get_robust_list` from a thread reads the leader's head.

### Shared credential admission (2026-10-21)

Found by the thread soak (stress profile `thread`, 4 vCPUs, 900 s). After the fourth
batch's final ladder, extra soaks stalled in 14 of 27 runs on trees `src12` to `src19`:
the runner stopped printing rounds and the stall dump showed a worker Blocked in a futex
wait that nothing would wake. A stress-only futex trace (since removed) showed that the
second waiter of musl's condvar broadcast chain was never requeued or woken: its
`FUTEX_REQUEUE` never reached the futex code. Syscall-error logging then caught
`FUTEX_REQUEUE|PRIVATE` (`op 0x83`, the `unlock_requeue` hand-off to the mutex) failing
with `EPERM`, and `clone` with `EAGAIN` (musl's `pthread_create` reports any clone
failure as `EAGAIN`).

Root cause (R186 `SharedCredentials`, pre-existing, exposed by thread sharing): the
admission word holds a writer bit and a reader count (2 per reader).
`try_acquire_read_admission` (behind `try_read`) and `try_begin_authorization` made one
compare-exchange from a value they had just loaded and failed if it lost, so a reader
that entered or left between the load and the exchange failed another reader with no
writer present. Members of a thread group share one credentials `Arc`, and every
LSM-checked syscall reads it: `current_credentials()` returned `None`,
`lsm_current_process_ctx` mapped that to `EPERM`, and the clone path mapped its failed
`try_credentials_read` to `EAGAIN`. musl ignores the requeue result, so the waiter slept
forever.

- **Fix.** `try_admit_reader` retries with the value it observed and fails only when the
  writer bit is set; both try paths use it. A pending writer still blocks new readers,
  and readers admitted before the claim still drain before it writes. The writer claim
  (`CredentialMutationGuard::try_claim`) is a `fetch_or`, so reader churn cannot starve
  it. The retry loop is lock-free: an exchange fails only because another thread
  changed the word.
- **Tests.** Hosted `gap5_concurrent_readers_never_fail_admission_without_a_writer`: four
  threads take 20,000 ordinary reads and authorization spans each with no writer, and
  every attempt must succeed. `gap5_writer_claim_excludes_concurrent_readers`: two
  writers claim and drain while three threads read; no reader is inside while a writer
  is, and the word returns to zero.
- **Review** (2026-10-21, independent; included a native model of the old and new
  admission): no defect in the fix. The claim, drain and release keep writer
  preference; a waiting writer still blocks both try paths and `begin_authorization`;
  the orderings pair; spin's `try_read` cannot fail without a writer, and only `mutate`
  and `replace_unpublished` write the payload, after the drain. The model failed 65,000
  to 87,000 of 160,000 old-style attempts per run and none with the fix. Every
  credential try path now uses `try_admit_reader`. No syscall sets the writer bit today
  (the supplementary-group setters have no caller and there is no `set*id`), so the
  remaining fail-closed returns cannot occur yet. Debt, pre-existing:
  - D3 (latent): the exec LSM hook (`if let Some(exec_ctx) = lsm_current_process_ctx()`)
    and the kill path's `hook_signal_send` are skipped when the context is `None`, so
    they fail open. Before this fix a sibling's syscalls could produce `None` at will;
    once a `set*id` syscall exists, any credential writer window does. They should fail
    closed (`EPERM`).
  - D5: the `debug_assert!(lsm_ctx.is_some())` at syscall entry contradicts the R184
    fail-closed comment next to it and would panic a debug build during a writer window.
  - Suspected (D4, unverified): `drain_deferred_stdin_wakes` drops a popped waiter when
    its PCB try-lock fails, which can lose a stdin wake.
- **Found by the hosted gate after the review** (tree `src20`): the first form of
  `try_acquire_read_admission` was `try_admit_reader().then_some(CredentialReadAdmission
  { .. })`. `then_some` builds its value even when the bool is false, so a refused reader
  dropped an admission it never held and released a unit it never took. The vfs test
  `access_context_fails_new_admission_but_derives_existing_span_behind_writer` (a held
  authorization span, then a refused reader behind a pending writer) aborted on the
  underflow assertion in `derive`. The admission is now built only after a unit is
  held. The second hosted test should catch it as well, since its readers are refused
  while a writer is pending (not run against the faulty form).
- **Validation** (`src22`, 2026-10-21): seven thread soaks QUALIFIED with 0 stall dumps
  and 0 failures (451 to 595 rounds each, run beside the full ladder), against 14 stalls
  in 27 runs before the fix; hosted 515 OK. Full results are in the GAP-5/6 status
  record, fourth batch.

## Futex ABI and the musl pthread workload

- `sys_futex` decodes the Linux ABI (`decode_linux_futex_op`, `syscall.rs`).
  `FUTEX_PRIVATE_FLAG` (128) is masked: futexes are private to the address space (keyed by
  tgid until 2026-10-20, see "Futex parity"), so private is the only mode.
  `FUTEX_LOCK_PI`/`FUTEX_UNLOCK_PI` moved from the custom 3/4 to Linux 6/7, and the old
  custom op 2 (`FUTEX_WAIT_TIMEOUT`) is gone; no in-tree caller used the custom
  numbering. Served operations:

  | Op | Behaviour |
  |----|-----------|
  | `FUTEX_WAIT` (0) | Optional relative timeout |
  | `FUTEX_WAKE` (1) | Wakes up to `val` waiters |
  | `FUTEX_REQUEUE` (3), `FUTEX_CMP_REQUEUE` (4) | Added 2026-10-17. Both counts are validated as non-negative ints (`nr_requeue` from the timeout slot); `uaddr2` must be an aligned user address; `CMP_REQUEUE` returns `EAGAIN` when `*uaddr != val3`. Since 2026-10-20 the requeued waiters are **moved** and keep sleeping (see "Futex parity"); until then they were woken |
  | `FUTEX_WAKE_OP` (5) | Added 2026-10-20 (see "Futex parity") |
  | `FUTEX_LOCK_PI` (6), `FUTEX_UNLOCK_PI` (7) | Linux user-word protocol since 2026-10-20 (see "PI futex user-word protocol and requeue-PI"); before, the PI mutex was owned in the kernel and the word ignored. `LOCK_PI` takes an absolute `CLOCK_REALTIME` deadline |
  | `FUTEX_TRYLOCK_PI` (8), `FUTEX_LOCK_PI2` (13) | Added 2026-10-20. `TRYLOCK_PI` is `EAGAIN` when contended; `LOCK_PI2`'s absolute deadline is `CLOCK_MONOTONIC` unless `FUTEX_CLOCK_REALTIME` is set |
  | `FUTEX_WAIT_REQUEUE_PI` (11), `FUTEX_CMP_REQUEUE_PI` (12) | Added 2026-10-20. `CMP_REQUEUE_PI` requires `nr_wake == 1`; `uaddr == uaddr2` is `EINVAL`; returns woken + requeued |
  | `FUTEX_WAIT_BITSET` (9), `FUTEX_WAKE_BITSET` (10) | Added 2026-10-17 with `FUTEX_BITSET_MATCH_ANY` only; any non-zero mask since 2026-10-20. The wait timeout is absolute, measured on the millisecond tick that `clock_gettime` reports for both clocks; a deadline already passed times out after the value check |

  Everything else is `ENOSYS`: `FUTEX_FD` (2) and unknown commands (until 2026-10-20 also
  8, 11, 12 and 13). An empty bitset is `EINVAL`. As on Linux, `FUTEX_CLOCK_REALTIME` (256)
  is accepted only with `FUTEX_WAIT_BITSET`, `FUTEX_WAIT_REQUEUE_PI` and `FUTEX_LOCK_PI2`
  (`ENOSYS` otherwise). Hosted tests:
  `gap5_futex_abi_tests::linux_futex_ops_decode_to_served_requests` and
  `gap5_futex_abi_tests::futex_pi_ops_decode_with_linux_clock_and_count_rules`.
- **Requeue by wake** (2026-10-17 to 2026-10-20, superseded by "Futex parity"). Each
  waiter kept a reference to the bucket it slept in and decremented that bucket's waiter
  count itself, so `REQUEUE`/`CMP_REQUEUE` woke up to `nr_wake + nr_requeue` waiters on
  `uaddr` instead of moving them. That was ABI-legal (`FUTEX_WAIT` may return 0
  spuriously, and musl's and glibc's condition variables re-check their word) at the cost
  of a thundering herd on broadcast. Before it, `FUTEX_REQUEUE` returned `ENOSYS`, which
  hangs musl's `pthread_cond_broadcast` with two or more sleeping waiters: musl clears the
  next waiter's barrier word and relies on the requeue to release it.
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
  once and that thread's wait must return 0 once `uaddr2` is woken (the waiter sleeps on
  the target, as on Linux). Since 2026-10-20 its partial-bitset check expects the value
  check's `EAGAIN` instead of `ENOSYS`.

### Futex parity (2026-10-20)

Adds a real requeue, `FUTEX_WAKE_OP`, partial bitsets and address-space futex keys.
The requeue-PI pair stayed `ENOSYS` here (blocker below); it was added later on
2026-10-20 (see "PI futex user-word protocol and requeue-PI"). Files: `kernel/ipc/futex.rs`,
`kernel/ipc/lib.rs`, the futex region and `FutexCallback` of
`kernel/kernel_core/syscall.rs`, `userspace/src/syscall_test.rs`.

**Premises verified on the tree before the change.**

- The callback was `fn(uaddr, op, val, current, timeout)`: no room for `uaddr2`, `val3` or
  a second count. It now takes one decoded `FutexRequest` (`kernel_core::syscall`).
- A plain waiter slept on its bucket's `WaitQueue`, whose entries are only `(pid, gen)`:
  no per-waiter mask (hence partial bitsets were refused) and no way to move a sleeper
  without changing `sync.rs`.
- Timeouts do not depend on the queue: `TIMED_WAITERS` is keyed by `(pid, seq)` and the
  timer IRQ wakes through the PCB (M1-02), and `finish_prepared` removes only the exact
  `(pid, gen)` entry from the queue it armed on. A task can therefore stay asleep on one
  queue while its futex membership moves elsewhere.
- `compare_exchange_user_u32` and `read_user_u32_atomic` (RF187-U34) are fault-safe; the
  page-fault handler resolves a copy-on-write fault before the exception-table fixup, so
  a kernel CAS on a COW word breaks the COW as a user store would.
- The PI mutex is owned in the kernel (`FutexBucket.owner`): `futex_lock_pi` ignores the
  user word and `futex_unlock_pi` never writes it.
- Every task sharing an address space holds the same `Arc<Mutex<MmState>>` (`sys_clone`
  hands the parent's `mm` to a `CLONE_VM` child; `fork.rs` allocates a new one); `exec`
  keeps the `Arc` and runs only when `address_space_share_count` is 1. Nothing calls
  `Arc::get_mut`/`try_unwrap` on `mm`; the sharing checks read `Arc::strong_count`.
- The clear-tid wake callback receives only the TGID and can run for a task that is not
  current (deferred kill drain), with no PCB lock held. The group leader stays in the
  process table while any member lives (G1), and RF180-3 keeps the TGID number pinned.
- The ipc hosted suite runs only `robust_` tests; kernel_core runs all.

**Data structures.**

- `FutexSpace { id, pin }`: `id` is the address of the task's `MmState` allocation, `pin`
  a `Weak` to it. Bucket creation stores the pin in `FutexBucket.space_pin`, so the
  allocation (not the address space) outlives every bucket of the space and a later
  address space cannot get the same id while a bucket still carries it. A `Weak` leaves
  `Arc::strong_count` alone. The pin replaces RF180-3's TGID pin for futex purposes.
- `FutexBucket.waiters: AdmittedDeque<FutexWaiterRecord>`: the plain waiters homed in the
  bucket, FIFO. A record is `{ origin: uaddr, pid: u32, bitset }` (two words).
- A plain waiter's **origin** is the bucket it called `FUTEX_WAIT` on. It sleeps on that
  bucket's queue for the whole wait and is counted in the origin's `waiter_count` until
  its own epilogue (so `waiter_count` now means "physically attached": PI waiters and
  plain sleepers of this queue). Its **home** is the bucket whose list holds its record;
  a requeue changes the home only.
- `FUTEX_WAKE_MARKS`: one bit per PID (`PID_MAX/64 + 1` words, 4 KiB): "a waker removed
  this task's record". A task has at most one futex wait in flight.
- `FutexDeferredWakes`: up to one bucket's worth of `(origin, pid)` wakes that must run
  after the home lock is dropped, because finding the origin bucket takes `FUTEX_TABLE`.

**Wait (`futex_wait`).** Clear the mark. Under the origin bucket lock (live-bucket and
`unlinked` checks as before): `waiter_count < 16`, records `< 16` (`< 32` since the PI
change, review F2), list capacity prepared
outside the lock, re-read the word (`EAGAIN` on mismatch, `EFAULT` on fault), reserve
`waiter_count`, push the record. Every waker and requeue scans records under that same
lock, so a waker either finds the record or stored its value before the read (the Linux
hash-bucket rule; the previous re-read under the queue lock is no longer needed). Then arm
on the origin queue with `try_prepare_with_timeout_after`, whose under-lock check is "mark
not set". A waker sets the mark before it takes the origin queue lock in `wake_specific`,
so either the arm sees the mark (no sleep) or the waker finds the task queued.

**Wake (`futex_wake`, `futex_wake_bitset`).** Under the home lock, take up to `n` records,
oldest first, whose `bitset & mask != 0`; for each set the mark, then `wake_specific` on
the home queue when `origin == home`, else defer. Deferred wakes run after the lock:
look up the origin bucket (table-resident while the sleeper is attached) and
`wake_specific`. `FUTEX_WAKE` uses MATCH_ANY; plain `FUTEX_WAIT` stores MATCH_ANY.

**Requeue (`futex_requeue`).** Same key: wake `nr_wake`, report `min(nr_requeue, rest)`,
move nothing (as Linux). Distinct keys: (1) without locks, snapshot the source's record
count; if waiters will move, get or create the target bucket (preparation gate, as for a
wait) and prepare list backing for them. (2) Take `FUTEX_TABLE`, look both buckets up
live, lock them in ascending key order, repeat the `CMP_REQUEUE` comparison under the
source lock (`EAGAIN`), install the prepared backing, wake `nr_wake` records, then pop up
to `nr_requeue` more and push each onto the target. A record that cannot be moved (no
target, target at 16 records, or backing a racing growth used up) is woken instead and
still counted: an early return from `FUTEX_WAIT` is legal, a record left on the source
would miss the wake its waker sends to the target. If the created target was reaped before
step 2, retry (bounded by `FUTEX_REVALIDATE_RETRIES`, then the fallback wakes). Moved
records keep `origin` and `bitset`; the sleeper is untouched. Returns woken + requeued.

**`FUTEX_WAKE_OP`.** Decode in kernel_core (`FutexWakeOp`): op bits 28-30, shift flag bit
31, cmp bits 24-27, 12-bit signed `oparg`/`cmparg`; unknown op or cmp is `ENOSYS`; a shift
outside 0..=31 is masked as on Linux. `nr_wake2` comes from the timeout slot; neither
count is validated (Linux does not). The syscall checks `uaddr2` (non-null `EFAULT`,
aligned `EINVAL`, present and writable or COW `EFAULT`). The IPC side applies the op with
a CAS loop (`read_user_u32_atomic` + `compare_exchange_user_u32`, `EFAULT` on fault, the
word unchanged), then wakes `nr_wake` on `uaddr` and, if the old value compares true,
`nr_wake2` on `uaddr2`; returns the sum. The update runs before either wake and without a
bucket lock: a waiter on `uaddr2` queues only after reading the word under its bucket
lock, which the later wake takes, so it either saw the new value or is woken.

**Lock order.** `FUTEX_TABLE` -> bucket (two buckets only in a requeue: ascending key) ->
`WaitQueue.waiters` -> `PROCESS_TABLE` -> PCB. No path holds a bucket lock and then takes
`FUTEX_TABLE` (deferred wakes and the moved-record scan run after the bucket lock is
dropped); `wake_specific` under a bucket lock follows the existing bucket -> waiters order
(`cleanup_empty_bucket` already takes the queue lock under a bucket). No allocation or
free under a bucket, table or queue lock: list backing is prepared before and retired
after, removed records are `Copy`, bucket `Arc`s are dropped after the locks.

**Epilogue, timeout, signal, EFAULT.** After `finish_prepared` (or an immediate outcome):
`cancel_wait` on the origin queue (drops an entry a spurious return left behind); under
the origin lock decrement `waiter_count` and, unless the mark is set, remove the record if
it is there. If it is in neither state, a requeue moved it: unless the mark is now set,
scan the space's buckets under `FUTEX_TABLE` (requeues move only under that lock, so the
scan cannot miss a record in flight) and remove it. Then `cleanup_empty_bucket` on the
origin and, if different, the bucket the record was found in. A set mark means a waker
counted this task: the wait returns 0 even if a timeout or signal also ended the sleep
(Linux's `futex_unqueue` rule). Otherwise the outcome maps as before (`ETIMEDOUT`,
`EINTR`, `ENOMEM`; a sleep that ended for no reason returns 0). A fault on the word at
publication returns `EFAULT` with nothing published; a fault in `CMP_REQUEUE`'s locked
re-read returns `EFAULT` with nothing moved; a `WAKE_OP` fault returns `EFAULT` before any
wake.

**Waiter lifetime across requeue.** Records are plain data; nothing points into a task's
stack. The origin bucket cannot be unlinked while the sleeper is attached (`waiter_count`)
or its queue entry exists (`cleanup_empty_bucket` also requires an empty record list);
a home bucket cannot be unlinked while it holds a record. A wake through a stale origin
lookup (the sleeper already left and a new bucket took the address) could at worst end a
later wait of the same task early; since the PI change, a deferred wake readies the task
only while its wake mark is set (review F3, I-PI4). It cannot consume another task's wake
because records, not queue entries, carry the count.

**Exit cleanup.** `cleanup_process_futexes` walks every bucket (at most
`MAX_FUTEX_BUCKETS_GLOBAL`), since a space can span thread groups: drop the reaped PID's
records (only a task that died inside a wait could leave one), then the unchanged PI-waiter,
queue-entry and owner passes. The last-thread-of-TGID unlink is replaced by unlinking every
bucket whose space is dead (`pin.strong_count() == 0`); the reaped task's PCB still holds
its `mm` during the callback, so its own space goes on a later pass, during which the pin
keeps the id unique. Robust-list release keys by the dying task's `mm` (read under its PCB
lock) and wakes one record of a non-PI futex (until the PI change, the queue's `wake_one`
when no record existed; that fallback is gone, review F5). The clear-tid wake keys by the
leader's `mm`. PI
ownership is still per PID; `FutexKey` keeps its `(usize, usize)` shape, so the PCB's PI
boost map and `waiting_on_futex` are unchanged.

**Budget.** A plain waiter now uses a wait-queue entry, a two-word record and possibly a
timeout entry; a PI waiter a queue entry and a PI-map entry. Both fit the existing
eight-word `FUTEX_PER_WAITER_RAW_BYTES`, and a bucket holds at most 16 attachments and 16
records, so `MAX_FUTEX_BUCKETS_GLOBAL`/`PER_TGID` (now per space) are unchanged. The mark
bitmap is static.

**Requeue-PI blocker (not implemented, `ENOSYS`).** `FUTEX_WAIT_REQUEUE_PI` must return
owning `uaddr2`, and `FUTEX_CMP_REQUEUE_PI` takes the PI lock for the top waiter by an
atomic update of `*uaddr2` (`futex_proxy_trylock_atomic`: 0 -> TID, else set
`FUTEX_WAITERS`) and requeues the rest as rt-mutex waiters of the owner named by the
word. That requires the Linux PI word protocol: the owner's TID in the user word,
`FUTEX_WAITERS`/`FUTEX_OWNER_DIED` maintained by the kernel, `LOCK_PI` finding the owner
from the word (userspace takes an uncontended PI mutex with a CAS and never enters the
kernel) and `UNLOCK_PI` failing with `EPERM` when the word does not name the caller. This
kernel's PI mutex is owned in the kernel and never reads or writes the word, so a
requeue-PI built on it would return "owning" a mutex whose word userspace sees as free (or
as another thread's), and could not see an owner that took the lock in userspace. Doing it
correctly means first moving `LOCK_PI`/`UNLOCK_PI` to the user-word protocol, then adding
the requeue-PI state machine (wake/requeue/timeout races of `futex_requeue_pi_wakeup_sync`).
musl never uses requeue-PI and glibc's condition variables stopped using it in 2.25.

**Differences from Linux, and why.**

- Requeue moves at most 16 records into one bucket; the rest are woken (bounded memory).
- `FUTEX_WAKE_OP`: an unknown comparison is refused before the word is modified (Linux
  applies the op, then returns `ENOSYS`); the CAS loop gives up after 64 rounds of 64
  attempts with a yield between rounds and returns `EAGAIN` with the word unchanged (Linux
  retries without bound). A wake count of 0 wakes nobody, here as for `FUTEX_WAKE` (Linux
  wakes one); a negative count wakes up to `u32` of them (Linux: one).
- `FUTEX_WAKE`, `WAKE_BITSET` and `WAKE_OP` wake only plain waiters; Linux returns
  `EINVAL` when it meets a PI waiter on the word. (Since the PI change these return
  `EINVAL` too, before doing any work, and robust release no longer wakes PI waiters.)
- A sleep that ends without a wake, timeout or signal returns 0; Linux re-waits.
- Shared (non-private) futexes are still keyed like private ones, so two processes do not
  share a futex through a `MAP_SHARED` mapping (unchanged).

**Tests.** kernel_core hosted (+3, `gap5_futex_abi_tests`): partial bitsets decode with
their mask; `WAKE_OP` word validation (every valid op/cmp with and without the shift,
`ENOSYS` otherwise, `nr_wake2` from the timeout slot); `WAKE_OP` arithmetic (wrapping
`ADD`, negative operands, shift masking) and signed comparisons; the decode table test is
updated. ipc hosted (+6, `futex_parity_*`, outside the `robust_` filter): bitset wakes take
only intersecting records, oldest first, with marks; requeue moves records in order with
their bitsets and origins while `waiter_count` stays on the origin, and a later target wake
is deferred to the origin queue; unmovable records are woken and counted; waiter-list
growth installs prepared backing without allocating under the lock; key spaces are equal
for sharers, different after fork, and the pin detects a dead space without holding a
strong reference; wake marks are per PID and bounded. Ring-3 `test_futex_parity`
(ring3-mm, forked host): the `WAKE_OP` argument contract; `WAKE_OP` leaves a sleeper on
`uaddr2` asleep when the comparison fails and wakes it when it holds (word values checked);
`CMP_REQUEUE` moves a sleeper that stays asleep (source wake returns 0, a self-requeue count
finds it on the target) until the target is woken; with sleepers of masks 1 and 2, a mask-4
wake wakes none, a mask-2 wake exactly the second; a `CLONE_VM` child that is not a thread
is visible to and woken by its parent. All Ring-3 checks also hold on Linux.

**Open.** Run the hosted suites (add `futex_parity_` to the ipc filter), the ring3-mm guest
on 1/2/4/8 CPUs and the musl pthread guest (its condition-variable broadcast now goes
through a real requeue). Requeue-PI waits for a user-word PI protocol (done; see below).

### PI futex user-word protocol and requeue-PI (2026-10-20)

PI futexes now follow the Linux user-word protocol, and the four missing PI operations
are served: `FUTEX_TRYLOCK_PI` (8), `FUTEX_WAIT_REQUEUE_PI` (11), `FUTEX_CMP_REQUEUE_PI`
(12) and `FUTEX_LOCK_PI2` (13). This resolves the requeue-PI blocker in "Futex parity".
Files: `kernel/ipc/futex.rs`, `kernel/ipc/sync.rs` (`WaitQueue::wake_specific_if`), and
`kernel/ipc/lib.rs` (the callback builds a `PiCaller`; `NotOwner` maps to `EPERM` and
`Deadlock` to `EDEADLK`). In `kernel/kernel_core/syscall.rs` it changes the futex decode,
`sys_futex`, `FutexRequest` and `SyscallError::EDEADLK` (-35). It also adds legs to
`userspace/src/syscall_test.rs`. The PI review fixes (below) add a killable wait to
`sync.rs`, no-fault user-word helpers to `kernel/kernel_core/usercopy.rs`, their
page-fault fixup to `kernel/arch/interrupts.rs`, and one line to
`terminate_self_and_halt` in `kernel/kernel_core/process.rs`.

**Premises verified on the tree.**

- `gettid` returns `pid_in_owning_namespace(&pid_ns_chain)`, which is what user space
  stores in the word. `resolve_pid_in_namespace(owning_namespace(chain), tid)` maps a word's
  TID back to a global PID (Linux `find_get_task_by_vpid`). The exiting path detaches the
  namespace chain after the exit callback, so a gone owner's TID resolves to nothing.
- `terminate_process` publishes `Zombie` and then runs the registered robust callback
  (`exit_robust_futexes_with_tid`) while the address space is retained. Only after that
  does it clear the child TID and publish `teardown_done`. `Zombie && !teardown_done` therefore
  means "its futex exit work has not run yet". `PID_MAX` fits the 30-bit TID field (asserted).
- `compare_exchange_user_u32` and `read_user_u32_atomic` are fault-safe. `sys_futex`
  verifies the word writable (or COW) before a PI call, and the callback checks that it is present.
- (PI review) Both helpers resolve a fault: a write to a copy-on-write word runs the COW
  path (PT_LOCK, frame allocation, a TLB shootdown that waits for every CPU running the
  address space), and a non-present shared-anonymous page runs the demand path. A
  `UserAccessGuard` keeps IF=0 for the access itself; a spin `Mutex` does not disable
  interrupts, but `WaitQueue` takes its lock with IF=0. Exception exits (user #PF, #GP and
  the other fatal user exceptions, the #NM/#DB/#BP pending-kill exits) and the stop
  barrier call `terminate_self_and_halt` with IF=0, so the robust callback, the PI release
  and the clear-tid wake ran with IF=0. The deferred-kill drain runs in process context
  with IF=1 (`reschedule_if_needed_inner` debug-asserts it).

**User word.** The word is `TID | FUTEX_WAITERS (bit 31) | FUTEX_OWNER_DIED (bit 30)`, and
the TID mask is `0x3fffffff`. User space takes a free lock with a CAS `0 -> tid` and
releases an uncontended one with `tid -> 0`. It enters the kernel only when the CAS fails
or `WAITERS` is set.

**PI state.** It is kept per bucket. `pi_owner: Option<PiOwner { pid, tid, fixup }>` is
Linux's `pi_state->owner`. `pi_waiters: AdmittedMap<pid, PiWaiter { origin, seq, tid,
priority }>` is ordered by (priority, arrival `seq`). It holds the `LOCK_PI` waiters
sleeping on this bucket's queue and the requeue-PI waiters moved here, which sleep on their
source bucket's queue (`origin`). The word, not `pi_owner`, says who owns an uncontended
mutex.

**`LOCK_PI` / `LOCK_PI2` / `TRYLOCK_PI`** (`futex_lock_pi`):

- The caller reserves its boost slot and wait edge unless this is a trylock. It then
  retries until it has a result (PI review D2-2): only a kill or the deadline ends the
  loop early, and rounds that did not sleep are separated by a yield, with a one-tick
  sleep every 16th round (`pi_pause`).
- **Each attempt.** The caller reads the word and resolves the TID it names with no lock
  held. It takes the preparation gate and the bucket, prepares PI-map backing outside the
  lock and clears its own marks. Under the bucket lock, `pi_take_or_attach_locked` (Linux
  `futex_lock_pi_atomic`) does the following:
  - If the TID is the caller's: `EDEADLK`.
  - If PI state exists: the word must agree with it (its owner's TID, a pending fixup, or
    TID 0 with `OWNER_DIED` in transit), else `EINVAL`. The caller joins it.
  - If TID is 0 and there is no state: CAS to `(word & OWNER_DIED) | tid`. The lock is
    taken, and the call returns 0 with `OWNER_DIED` kept, so user space reports
    `EOWNERDEAD`.
  - Otherwise: CAS `WAITERS` in, then attach to the owner the word names. That TID must
    still be the one resolved before the lock, else the attempt retries. Owner liveness is
    checked under the bucket lock (bucket -> `PROCESS_TABLE` -> PCB):
    - live: it becomes `pi_owner`;
    - exiting: wait for its exit work (Linux `wait_for_owner_exiting`), then retry;
    - gone or unresolvable: `ESRCH`, unless the word changed meanwhile (retry; Linux
      `handle_exit_race`).
- A trylock returns `EAGAIN` instead of queueing.
- **Queueing.** A waiter inserts its `PiWaiter`, attaches (`waiter_count`), donates its
  priority (`recompute_pi_state`), and arms on the bucket's queue with the check "wake
  mark not set".
- **Epilogue** (`leave_pi_wait`). The waiter calls `cancel_wait` and drops its attachment.
  Then:
  - If its grant mark is set, it owns the lock; it runs the owner-death fixup if one is
    pending, retrying until it succeeds.
  - Otherwise it removes its entry and settles the state.
- A grant beats a timeout or kill that also ended the sleep. A sleep that ended for no
  reason, or because a handler signal readied the task, retries (the sleep is killable).
- At the 16-waiter bound the caller is not queued; it polls for a slot once a tick.
- A caller that already holds the lock with its owner-death fixup pending (an earlier
  call could not store its TID) finishes the fixup and gets 0.
- **Timeouts.** `LOCK_PI` takes an absolute `CLOCK_REALTIME` deadline. `LOCK_PI2` takes
  `CLOCK_MONOTONIC`, or `CLOCK_REALTIME` with `FUTEX_CLOCK_REALTIME`, which `LOCK_PI` and
  `TRYLOCK_PI` refuse with `ENOSYS`. A free word is taken even when the deadline has passed.

**`UNLOCK_PI`** (`futex_unlock_pi`):

- If the word's TID is not the caller's: `EPERM`, unless the caller holds the PI state with
  its owner-death fixup pending; it then finishes the fixup and unlocks.
- If there is no bucket: CAS the word to 0, and drop any donation the caller still holds
  for the key.
- Otherwise, under the bucket lock, the kernel prunes dead waiters, settles the state, and
  then (Linux `wake_futex_pi`):
  - If the state belongs to another task or awaits a fixup: `EINVAL`.
  - If there is a top waiter: CAS the word to `top_tid | FUTEX_WAITERS`, remove the
    waiter, and grant. A grant sets `pi_owner`, the grant mark and the wake mark, and
    defers the wake to the grantee's origin queue.
  - If there is none: CAS the word to 0.
- Then the boosts are refreshed (the caller loses its donation and the new owner gets the
  rest), and only then does the deferred wake run. A word that changed or faulted is
  retried without a bound (glibc ignores `UNLOCK_PI`'s result); only a kill ends the call.

**Owner death.** The exit callback (`exit_robust_futexes_with_tid`, the existing hook, run
by `terminate_process` right after `Zombie`) handles it in three steps:

1. It walks the robust list. Bit 0 of every list pointer marks a PI entry. Each owned
   word becomes `(word & WAITERS) | OWNER_DIED`.
2. After interrupts and the caller's page tables are restored, it wakes the oldest record
   of each marked non-PI word.
3. It calls `release_pi_states_of(pid)` (Linux `exit_pi_state_list`). Every PI state the
   dying task owns goes to its top live waiter with `fixup = true`. The kernel does not
   write the word; the grantee stores `OWNER_DIED | tid | WAITERS` in its own context
   (`pi_fixup_owner`, Linux `__fixup_pi_state_owner`).

The heir of an owner that died holding the PI state finds `OWNER_DIED`, robust owner or not:
Linux's fixup sets it whenever `exit_pi_state_list` cleared the owner (PI review D5; until
then this kernel set it only for a robust owner, whose walk had written it). A robust owner
that dies with no waiter leaves `OWNER_DIED` in the word. The reap-time
`cleanup_process_futexes` repeats the release, which normally finds nothing.

The exit work runs with interrupts enabled on every path (PI review D2-1):
`terminate_self_and_halt` enables them before `terminate_process`, as `sys_exit` already
had them, and the deferred-kill drain runs in process context. The robust walk itself
still disables them around its CR3 window. Kernel code is not preempted (the timer
reschedules only on a return to user mode), and the halt loop enabled interrupts anyway.

**`WAIT_REQUEUE_PI`** (`futex_wait_requeue_pi`):

- If `uaddr == uaddr2`: `EINVAL`. If the value check fails: `EAGAIN`. Otherwise the caller
  reserves the boost slot for `uaddr2`.
- **Record.** The caller publishes a requeue-PI record on `uaddr`'s bucket (bitset 0;
  `origin` holds `uaddr2`; still two words). It stays attached there and sleeps on that
  queue throughout.
- **Outcome after each sleep** (the sleep is killable, PI review D2-2; a handler signal
  ends it as a wake, told apart by a pending deliverable signal):
  - If its record is still on the source: a handler signal sleeps again with the record in
    place (Linux restarts the call, `ERESTARTNOINTR`); otherwise `ETIMEDOUT`, `EAGAIN`
    for a wake for no reason, or `EINTR` for a kill (Linux
    `handle_early_requeue_pi_wakeup`).
  - If it is a PI waiter of `uaddr2` with no mark: a spurious wake sleeps again; a timeout
    is `ETIMEDOUT`; a handler signal is `EAGAIN` (Linux converts the `EINTR`).
  - If it has a deadlock mark: `EDEADLK`.
  - If it has a grant: it owns `uaddr2`, runs the fixup if pending, and returns 0.
  - If it has a wake mark but no grant: `EAGAIN`.

**`CMP_REQUEUE_PI`** (`futex_cmp_requeue_pi`):

- **Decode.** `nr_wake` must be 1, and both counts must be non-negative ints (`EINVAL`).
  `uaddr == uaddr2` is `EINVAL`. `*uaddr != val3` is `EAGAIN`, checked first without locks
  and again under the source lock.
- **Phase 1, no lock held.** Snapshot the source record count. Read `uaddr2` and resolve
  the owner it names. Get or create the target bucket, with PI-map backing for
  `min(queued, nr_requeue + 1, 16)` waiters.
- **Phase 2** runs under `FUTEX_TABLE` and both bucket locks in ascending key order:
  - Repeat the comparison and install the backing.
  - The oldest source record must be a requeue-PI record for this `uaddr2`; otherwise
    `EINVAL` (a plain waiter, or one that named another PI futex).
  - Proxy-lock `uaddr2` for that waiter with the same take/attach step (Linux
    `futex_proxy_trylock_atomic`; `WAITERS` set when `nr_requeue > 0`):
    - If taken, the record is popped, the waiter is granted (deferred wake on the source
      queue) and counted.
    - If the take fails (`EDEADLK`, `ESRCH`, `EINVAL`, `EFAULT`), the operation fails and
      nothing moves.
  - Then move up to `nr_requeue` records, one more when the lock was not taken, oldest
    first:
    - A record that is not for `uaddr2` stops the pass with `EINVAL`.
    - The current PI owner's own record is woken with `EDEADLK` and stops the pass with
      `EDEADLK`.
    - A dead task's record is dropped and not counted.
    - A waiter that finds the target at its 16-waiter bound is woken (`EAGAIN`) and
      counted.
- **After the locks.** Refresh the target's boosts, run the deferred wakes, then clean
  up. Return woken + requeued; an error discards the count, as on Linux.

**Plain operations on PI words.** `FUTEX_WAKE`, `WAKE_BITSET`, `WAKE_OP`, `REQUEUE` and
`CMP_REQUEUE` return `EINVAL` for a word with PI waiters or requeue-PI records. Plain
requeue therefore never moves a requeue-PI waiter. The clear-tid wake (`futex_wake`) reports 0
there.

**Lock order.** The order is `FUTEX_TABLE` -> bucket (two only in a requeue, ascending key)
-> `WaitQueue.waiters` -> `PROCESS_TABLE` -> PCB.

- The user word is read and CASed under the PI bucket lock, as Linux does under the hash
  bucket lock. Under any futex lock (bucket, `FUTEX_TABLE`, wait queue) the access never
  resolves a fault (PI review D2-1, `LockedWord`): it returns `WordFault`, and the
  operation drops every lock, faults the word in with an ordinary access
  (`fault_in_word`: a read, or a `lock cmpxchg` that cannot change the word but breaks
  copy-on-write), and starts over. This covers the PI steps, the owner-death fixup,
  `FUTEX_WAIT`'s value check and the `CMP_REQUEUE`/`CMP_REQUEUE_PI` compare.
- TID resolution (namespace locks) runs with no lock held. Liveness reads run under the
  bucket lock (bucket -> `PROCESS_TABLE` -> PCB).
- Boost updates (`refresh_pi_boosts`, PI review D3) apply the owner's entry under the lock
  of the bucket whose waiters it reflects (bucket -> `PROCESS_TABLE` -> PCB). A chain step
  then looks up the next bucket, records the owner's new priority in its `PiWaiter` entry
  there and boosts that bucket's owner under that bucket's lock.
- Grants and requeue-PI wakes are deferred until every bucket lock is dropped and the new
  owner has its donation.
- The robust walk, which runs with IRQs off and possibly under the dying task's CR3, takes
  no futex lock since this change.
- No allocation or free happens under a bucket, table or queue lock: PI-map backing is
  prepared before and retired after, and the boost slot is reserved before queueing. A
  boost step that would need room in the owner's boost map (an owner that took the lock
  in user space reserved none) leaves the lock, reserves the room under the owner's PCB
  lock only, and redoes the step; without memory the owner goes unboosted (PI review D4).

**Invariants.**

- I-PI1: `pi_owner` is `Some` exactly when `pi_waiters` is non-empty or a fixup is
  pending. `settle_pi_state` re-establishes this before every PI bucket-lock release.
- I-PI2: a PI waiter's entry is removed only under its bucket lock, by one of: itself, a
  granter (which sets the grant mark under that lock), a requeue, or reap cleanup. The
  waiter reads the grant mark under the same lock, so a hand-off is neither lost nor
  doubled.
- I-PI3: every waiter is attached (`waiter_count`) to the bucket whose queue it sleeps on
  until its own epilogue. A requeue moves only records or PI entries, never the sleeper.
- I-PI4: a deferred wake readies a task only if its wake mark is still set, checked under
  the queue lock. A wait clears its marks before it publishes and arms, so a late wake
  cannot end a later wait (`wake_specific_if`).
- I-PI5: requeue-PI records move only under `FUTEX_TABLE` and both bucket locks. A waiter
  that finds no mark finds its record on the source or its entry on the target.

**Differences from Linux, and why.**

- A handler signal for a task blocked in `LOCK_PI`/`LOCK_PI2`, or in `WAIT_REQUEUE_PI`
  before its requeue, does not end the call; the handler runs when the call returns
  (after the lock is taken, the timeout, or the requeue). Linux runs the handler at once
  and restarts the call (`ERESTARTNOINTR`). This kernel has no syscall restart, and the
  `EINTR` it returned before made glibc treat the mutex as acquired.
- `LOCK_PI` still returns `ENOMEM` when memory or futex metadata (bucket budget, wait-queue
  or PI-map backing, the boost reservation) is exhausted, as Linux's pi_state allocation
  can. It no longer does so at the waiter bound or on preparation-gate contention.
- There are at most 16 PI waiters per futex: a further `LOCK_PI` polls for a slot once a
  tick (killable, deadline-aware) instead of queueing, and a requeue-PI waiter that does
  not fit is woken with `EAGAIN`.
- No ABBA deadlock detection: Linux's rt-mutex chain walk returns `EDEADLK` to a `LOCK_PI`
  that would close a wait-for cycle; here both tasks sleep (until a deadline or a kill).
  The boost walk stops at the cycle (owner bitmap). Only the word naming the caller is
  `EDEADLK`.
- Plain operations refuse a PI or requeue-PI word before doing any work. Linux may wake or
  move some waiters before it meets one.
- Source records (plain and requeue-PI) are served FIFO; Linux orders its hash-bucket list
  by priority for RT tasks. PI waiters are ordered by priority, then FIFO, as on Linux; a
  waiter's recorded priority follows its own boosts through the chain walk.
- `CLOCK_REALTIME` and `CLOCK_MONOTONIC` deadlines read the same millisecond tick.
- `WAIT_REQUEUE_PI` and `CMP_REQUEUE_PI` still give up after 1024 rounds with `EAGAIN`
  (spurious wakes, changed or faulting words), an error Linux documents for both.
- `EDEADLK` (-35) had to be added to `SyscallError`.

**Review follow-ups folded in (from the futex-parity review).**

- F2 (records). A requeue moves a record into a bucket only while that bucket holds fewer
  than 16 records. A direct `FUTEX_WAIT` or `WAIT_REQUEUE_PI` is admitted while
  `waiter_count < 16` and the bucket holds fewer than 32 records
  (`MAX_FUTEX_RECORDS_PER_BUCKET`, `direct_waiter_fits`). A broadcast requeue therefore no
  longer locks contending lockers out with `ENOMEM`. The 16 extra record slots are charged
  in `FUTEX_BUCKET_RAW_BYTES`, so `MAX_FUTEX_BUCKETS_GLOBAL` shrinks slightly.
  `FUTEX_DEFERRED_WAKES` equals the record bound.
- F3 (stale deferred wake): fixed by I-PI4.
- F5 (robust `wake_one` fallback): removed. Robust release wakes only a record of a non-PI
  word without PI state.
- F7 (exec):
  - `ipc::futex_drop_space(space: usize) -> usize` unlinks every bucket of the space that
    no task waits on, together with any PI state it still holds. `space` is
    `FutexSpace::id_of_mm(&mm)`, i.e. `Arc::as_ptr(&proc.mm) as usize`.
  - It returns the number of buckets it had to leave in place (0 after exec's drain).
  - It allocates nothing and frees after the locks. Lock order: `FUTEX_TABLE` -> bucket.
  - The exec commit calls it through a registered callback.
- F8 (bounds and comments):
  - `prepare_requeue_target` sizes backing only for the records that may move.
  - `get_or_create_bucket` (unpinned) is now `#[cfg(test)]`.
  - `MAX_FUTEX_BUCKETS_PER_TGID` is renamed `MAX_FUTEX_BUCKETS_PER_SPACE`, and the
    `FUTEX_TABLE` key comment is fixed.
- The robust walk now marks words inside the IRQs-off, foreign-CR3 window and queues their
  addresses on the stack (`RobustReleases`, at most 256). It wakes after restoring them, so
  no `FUTEX_TABLE` or bucket lock is taken in that window.

**PI review fixes (2026-10-20).** An independent review of the PI work (static) found the
following; each fix is marked `GAP-5 PI review <id>` in the code.

- D2-1 (a COW fault resolved under a futex lock; IF=0 exit work could spin on that lock).
  A write to a copy-on-write PI word under the bucket lock (or under `FUTEX_TABLE` and both
  buckets in `CMP_REQUEUE_PI`) ran the COW path, whose TLB shootdown waits for every CPU
  of the address space with the lock held. A sibling taking a fatal user exception ran its
  exit work with IF=0 and spun on that lock without acknowledging. Fixed in two parts:
  - `read_user_u32_atomic_nofault` and `compare_exchange_user_u32_nofault`
    (`usercopy.rs`) mark the access no-fault; the page-fault handler takes the
    exception-table fixup for such an access before the COW and demand paths
    (`interrupts.rs`). `UserCopyGuard::new` clears the mark, so only these helpers set it.
    Every user-word access under a futex lock goes through `LockedWord`
    (`LockedUserWord`), and every operation turns its `WordFault` into "drop the locks,
    `fault_in_word`, retry". Nothing changes under a lock before an access that can
    fault, so a retry starts from a clean state. Fault-ins are bounded where the
    operation may fail (16 for `FUTEX_WAIT`'s check and `CMP_REQUEUE`, then `EFAULT`;
    1024 rounds for `CMP_REQUEUE_PI`, then `EAGAIN`) and unbounded but killable for the
    PI lock, unlock and fixup, since a racing fork can make the page copy-on-write
    again (Linux loops the same way).
  - `terminate_self_and_halt` enables interrupts before the teardown (see "Owner death").
    With both parts, no futex lock is held across a wait for another CPU, and the exit
    work never spins with IF=0.
- D2-2 (untimed `LOCK_PI` returned `EINTR`, `EAGAIN` and `ENOMEM`). glibc takes `EINTR` and
  `EAGAIN` for "acquired" and aborts on `ENOMEM`; musl sleeps forever on the last two.
  - The PI wait is killable (`WaitQueue::try_prepare_killable_with_timeout_after`: a
    pending handler signal neither aborts the arm nor ends the sleep as an
    interruption), and the owner-exit wait, the gate wait and the fixup check only for a
    kill. A handler signal that readies the task is a spurious wake.
  - The attempt bound (1024), the owner-exit bound (1000 ticks), the fixup bound
    (64 x 64 CAS) and the `UNLOCK_PI` bound (64 rounds) are gone: those loops retry with
    `pi_pause` (yield, a tick's sleep every 16th round) until a result, a kill (`EINTR`,
    never seen by user space) or the deadline (`ETIMEDOUT`).
  - The 16-waiter bound is no longer `ENOMEM`: the locker polls for a slot once a tick.
    A busy preparation gate is waited for (`FutexPreparePermit::acquire_killable`).
  - `TRYLOCK_PI` keeps its Linux results. `WAIT_REQUEUE_PI`: see its outcome list.
- D3 (stale donation). Two refreshes of one bucket could apply out of order after the lock
  and leave the owner boosted; with no bucket left, `UNLOCK_PI` never cleared it. Now each
  boost step applies under the bucket lock (see "Lock order"), and the no-bucket unlock
  drops the caller's donation for the key.
- D4 (fixup wedge). A grantee whose fixup gave up (or faulted) was the kernel owner of a
  word that did not name it: its `UNLOCK_PI` was `EPERM` and its `LOCK_PI` queued behind
  itself. The fixup no longer gives up; if it faults on an unmapped word, the grantee's
  next `LOCK_PI`/`TRYLOCK_PI` finishes it and returns 0, and its `UNLOCK_PI` finishes it
  and unlocks.
- D4 (`try_reserve` under the PCB lock; a failure was `ENOMEM` for the waiter). A boost
  step that needs room reserves it under the owner's PCB lock with no futex lock held and
  redoes the step; without memory the owner runs unboosted and the waiter still waits.
- D5 (`OWNER_DIED` for a non-robust owner's heir): fixed, see "Owner death".
- D5 (no ABBA `EDEADLK`): recorded under "Differences from Linux".
- Not changed (review: not a defect): between a grant and the refresh the new owner briefly
  runs unboosted; the grant's wake runs only after the refresh.

**Tests.**

- **ipc hosted** (+10 in `futex.rs`, 22 -> 32; `futex_pi_list_pointers_carry_the_pi_bit`
  is named to stay outside the `robust_` filter, so that suite still runs 4 and filters 10
  more):
  - `futex_pi_lock_step_follows_the_linux_word_protocol`
  - `futex_pi_unlock_step_checks_the_word_then_the_state`
  - `futex_pi_unlock_hands_off_to_the_top_waiter_and_defers_its_wake`
  - `futex_pi_owner_death_hands_the_lock_over_with_a_pending_fixup`
  - `futex_pi_requeue_pi_records_are_refused_by_plain_wakes_and_requeues`
  - `futex_pi_cmp_requeue_pi_moves_only_waiters_for_its_pi_futex`
  - `futex_pi_requeue_pi_wait_results_follow_linux`
  - `futex_pi_list_pointers_carry_the_pi_bit`
  - `futex_parity_requeued_records_leave_room_for_direct_waiters`
  - `futex_parity_drop_space_unlinks_the_idle_buckets_of_one_space`
  - Updated: `futex_pi_waiter_backing_retires_after_bucket_unlock`.
  - The hosted tests check decision logic and locked bookkeeping only. A hosted test cannot
    run a `WaitQueue` wake or touch user memory, so every wake in them is deferred and
    never run.
  - PI review (+2, 38 -> 40 ipc lib tests; the `robust_ futex_parity_ futex_pi_` filter
    now runs 23 and filters 17; `robust_` alone still runs 4). The locked steps take a
    `LockedWord`, so the tests drive them on an in-memory word (`TestWord`) that can be
    made to fault:
    - New `futex_pi_locked_steps_fault_in_and_wait_for_a_slot`: a faulting take reports
      `WordFault` and takes nothing, then takes the lock; at the waiter bound the lock
      step is `Full` (not `ENOMEM`); a caller with a pending fixup gets `Acquired` and
      the word `OWNER_DIED|tid|WAITERS`, after a faulting first try.
    - New `futex_pi_requeue_pi_signals_restart_before_the_requeue_and_end_it_after`:
      before the requeue a handler signal keeps the record (up to the give-up bound),
      a wake for no reason is `EAGAIN` and a timeout `ETIMEDOUT`; after it a spurious wake
      keeps waiting and a handler signal is `EAGAIN`, leaving the PI futex.
    - `futex_pi_unlock_hands_off_to_the_top_waiter_and_defers_its_wake` now drives
      `unlock_pi_locked` itself: `EPERM`, a faulting word that changes nothing, then three
      hand-offs and the final release to 0.
    - `futex_pi_owner_death_hands_the_lock_over_with_a_pending_fixup` runs the fixup
      through `pi_fixup_locked`: the heir of a non-robust owner gets `OWNER_DIED`.
    - `futex_pi_unlock_step_checks_the_word_then_the_state`: `pi_fixup_word` is
      `OWNER_DIED|tid|WAITERS`.
- **kernel_core hosted** (+1):
  - `gap5_futex_abi_tests::futex_pi_ops_decode_with_linux_clock_and_count_rules`
  - `linux_futex_ops_decode_to_served_requests` is updated; only 2, 14 and 15 stay
    unserved.
- **Ring-3 `test_futex_pi`** (ring3-mm). It has four legs, each in a forked host with
  `CLONE_THREAD` siblings, and every check also holds on Linux:
  1. CAS fast path and contracts. The CAS fast path and the kernel's take-over of a free,
     stale-`WAITERS` or `OWNER_DIED` word. `EDEADLK` from `LOCK_PI` and `TRYLOCK_PI` on the
     caller's own lock. `EPERM` from `UNLOCK_PI` on a word naming 0 or another TID. `ESRCH`
     with `WAITERS` left set for a TID nobody has. The clock-flag `ENOSYS` cases. The
     requeue-PI argument contract (`EINVAL`/`EAGAIN`, a 0 count with nobody waiting, and
     `ETIMEDOUT` for a passed deadline).
  2. Hand-off. A contended `LOCK_PI` from a sibling sets `WAITERS`. `UNLOCK_PI` hands the
     lock to the oldest waiter as `tid|WAITERS`. Then the old owner's `UNLOCK_PI` is
     `EPERM`, `TRYLOCK_PI` is `EAGAIN`, and an absolute-deadline `LOCK_PI` is `ETIMEDOUT`
     no earlier than its deadline. The next unlock hands the lock to the second waiter;
     the last unlock leaves 0.
  3. Owner death. A robust owner (PI-tagged list entry) exits with a waiter, which returns
     0 with `tid|WAITERS|OWNER_DIED`. With nobody waiting, a robust owner's death leaves
     `OWNER_DIED`, and the next `LOCK_PI` takes it as `OWNER_DIED|tid`. A non-robust dead
     owner gives `ESRCH`.
  4. Requeue-PI round. A plain wake on the condition word is `EINVAL` while a requeue-PI
     waiter sleeps there. `CMP_REQUEUE_PI` to another PI word is `EINVAL`, and so is a
     plain `CMP_REQUEUE`. `CMP_REQUEUE_PI` makes the first waiter the owner (returns 1,
     word `tid|WAITERS`). A second waiter is requeued (returns 1, stays asleep, off the
     condition word) and is handed the lock by the owner's `UNLOCK_PI`.

  New lines:
  - `[PASS] futex PI: user-space CAS fast path, kernel take-over and EDEADLK/EPERM/ESRCH contracts`
  - `[PASS] futex PI: UNLOCK_PI hands the lock to the oldest waiter as tid|FUTEX_WAITERS; TRYLOCK_PI is EAGAIN while it is held`
  - `[PASS] futex PI: a dead robust owner leaves OWNER_DIED and its waiter inherits the lock`
  - `[PASS] futex PI: CMP_REQUEUE_PI wakes one waiter as owner and requeues one that is later handed the lock`

  PI review legs (three more forked hosts; every check also holds on Linux):
  5. Copy-on-write word. The word sits alone on a page that the test process writes before
     forking the host, which only reads it. `LOCK_PI` takes it (its CAS meets the COW
     page). A sibling queues; the host forks a child that exits at once, so the page is
     COW again, and `UNLOCK_PI` hands the lock to the sibling as `tid|WAITERS` (its CAS
     meets the COW page). After one more fork the sibling's unlock leaves 0. The forks
     from a host with a live sibling print the kernel's multi-threaded fork warning.
  6. Handler signal. With a `SIGUSR1` handler (`SA_RESTORER` trampoline) installed, two
     `tgkill`s to a sibling blocked in `LOCK_PI` do not end the call; the owner's unlock
     hands it the lock, the call returns 0 with its TID in the word, and the handler has
     run.
  7. Non-robust owner death. An owner with an empty robust list dies holding the lock with
     a waiter, which returns 0 with `tid|WAITERS|OWNER_DIED`.

  New lines:
  - `[PASS] futex PI: LOCK_PI and UNLOCK_PI update a copy-on-write word after a fork`
  - `[PASS] futex PI: a handler signal does not end LOCK_PI, which returns 0 owning the lock`
  - `[PASS] futex PI: a dead non-robust owner hands the lock to its waiter with OWNER_DIED`

**Second PI review (2026-10-20).** An independent static review of the fix delta (with
the exec handoff in the tree) found no D0/D1. It closed D2-1, the direct-owner part of D3,
both D4s and the `OWNER_DIED` D5, and found:

| Finding | Severity | Disposition |
|---|---|---|
| D2-A: a killable arm checked only `pending_kill`, so a leader that armed a `LOCK_PI` or `WAIT_REQUEUE_PI` wait after a sibling published an exec handoff slept and the exec never completed | D2 | Fixed: `arm_must_abort` (`sync.rs`) uses `process::wait_abort_locked` (`pending_kill` or `exec_handoff`) for a killable arm |
| D3-B: the chain step for `previous` was dropped (B keeps its boosted entry in K2 after A leaves K, so C stays boosted), and chain hops applied a priority snapshot after the upstream lock, so two refreshes could land out of order one hop down | D3 | Fixed: `pi_boost_step_locked` reads the waiter's live `dynamic_priority` under the downstream bucket lock (bucket -> PCB is in the order), so the last writer converges; `refresh_pi_boosts` walks the chain from the new owner and from `previous` (`walk_pi_chain`) |
| D3-A: a handler signal for a task blocked in `LOCK_PI`/`WAIT_REQUEUE_PI` runs only when the call returns (Linux: `-ERESTARTNOINTR`, handler, restart). A runtime that holds a PI mutex and waits for every thread's handler (Boehm/Mono stop-the-world) hangs; a group signal chosen for such a waiter is not handed to an idle sibling | D3 | Open (debt): restart the call by rewinding the frame when the sigframe is built, and retarget away from a killable waiter as from an in-handler member |
| D4-A: past the 16-waiter bound, lockers poll once a tick with no FIFO order and no donation | D4 | Open (debt): an overflow wait woken on slot release, or a larger bound for PI words |
| D5: the COW leg's last unlock takes the no-bucket path (resolving CAS) | D5 | Test comment corrected; the locked paths are covered by the leg's first two steps |
| D5: the usercopy fallback in the `#PF` handler now tears down with IF=1 while the interrupted kernel context may hold locks; the early no-fault fixup accepts any exception-table RIP | D5 | Open (debt): unreachable in practice (see the review's scope check); harden by recording the helpers' RIP range |
| D5 (outside the delta): exec clears the robust list and drops idle buckets but runs no `exit_robust_list`/`exit_pi_state_list` equivalent, so waiters on a PI lock held by a task that execs wait until it exits | D5 | Open (debt) |

A third independent pass (2026-10-21) read that delta. It confirmed D2-A (every killable
arm and `pi_pause` ends on a handoff; state on the early return is consistent; `EINTR`
is replaced by the exec's result) and D3-B (lock order, no allocation under the bucket
lock, cycle termination, convergence), and found:

| Finding | Severity | Disposition |
|---|---|---|
| F1: a `LOCK_PI` waiter's own entry used the priority read at the call's entry, so a retry (after a handler-signal wake) re-inserted it without a boost it had gained while waiting, and a chain hop that reached the bucket before the entry existed updated nothing: the owner could run unboosted while a high-priority task waited | D3 | Fixed: `pi_lock_locked` publishes the caller's live `dynamic_priority`, read under the bucket lock |
| F2: no test drives `pi_boost_step_locked`/`walk_pi_chain` or a two-hop chain | D4 | Open (debt): a runtime test with three PCBs on two keys |
| F3: comments said only a kill ends the killable waits | D5 | Fixed: they name the exec handoff too |
| F4: `walk_pi_chain` holds a PID bitmap per call and `refresh_pi_boosts` makes two | D5 | Fixed: `#[inline(never)]` |
| Starvation aging and `restore_static_priority` change `dynamic_priority` without following the PI wait edge (pre-existing) | D4 | Open (debt) |

The Ring-3 handler-signal leg first failed on the gate: its waiter ran on a static
(`.bss`) stack, where this kernel refuses a sigframe (RF178-34: frames only on the main
stack or an mmap VMA; Linux allows any writable stack), and the host died with
`SIGSEGV`. The leg now gives the waiter an mmap'd stack (`pi_spawn_on`); the static-stack
refusal is recorded as a deviation.

**Status.** Hosted pins: `robust_ futex_parity_ futex_pi_` runs 23 and filters 17 (40 ipc
lib tests); `kernel-core` 103. The seven PI PASS lines are pinned in
`ring3_mm_oracle.sh`. `futex_drop_space` runs at exec (F7). Gate results for the final
tree are in the status record ("Fourth batch").

**Residual risks** (besides the open rows above):

- Between a grant and the boost refresh, the new owner briefly runs unboosted.
- The boost step takes the owner's PCB lock under the bucket lock and recomputes its time
  slice, which reads the cgroup weight with try-locks only.
- Not covered by a test: more than 16 waiters, a kill during a killable wait, an exec
  handoff racing `LOCK_PI`, a timeout or signal racing a hand-off, a timeout after a
  requeue, `CMP_REQUEUE_PI` `EDEADLK` and fault paths, SMP stress of PI locks.

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
   in `.bss`; the parent polls for 0 with a bound (the futex wake could not reach the parent
   until futex keys followed the address space, 2026-10-20).
2. **G4 futex prepare** per task, with a hosted test of two concurrent preparers of one tgid.
3. **G5/G6 identity**: cached namespace-local tgid, group parent, namespace check. Hosted
   tests for the selection logic; non-thread behaviour unchanged in Ring 3.
4. **G1 tree and reaping**: thread-aware `terminate_process`, `wait_reap_core` filter,
   auto-reap queue, delayed leader notification. Hosted tests for the
   last-member/notify decision.
5. **G2 group death**: implemented through `group_fatal` (see G2 detail); generation token open.
6. **G7 signals**: implemented (see G7 detail).
7. **Enable**: done 2026-10-20 once every known gap was closed: `thread_preview` is
   removed and `SUPPORTED_CLONE_FLAGS` always includes the thread flags
   (`rf186_clone_contract_tests` updated). History of the staged phase:  a `thread_preview` cargo feature of `kernel_core`, implied by the guest-only `syscall_test` and `musl_test` features, adds `CLONE_SIGHAND|CLONE_THREAD|CLONE_FS|CLONE_FILES|CLONE_SYSVSEM|CLONE_DETACHED` to `SUPPORTED_CLONE_FLAGS` (`CLONE_FILES` only inside a thread group); default and production builds still refuse them. The ring3-mm guest runs a four-leg thread workload in forked hosts (identity and clear-tid join, exit_group from a non-leader, a `CLONE_FILES|CLONE_FS` shared-table leg, process-directed SIGKILL), each ending in exactly one parent reap, plus the futex requeue leg; the musl guest runs real `pthread_create`/`pthread_join` with mutex, condition-variable and TLS checks. Exec from a thread group still returns `EBUSY`: Linux kills the other threads and unshares the fd table (`de_thread`, `unshare_files`), which is not implemented. On the staged tree (g58) these legs passed on 1/2/4/8 CPUs; the exec semantics, the 16-CPU run and the `rf186_clone_contract_tests` update that this phase still needed are done. Ring-3 raw-clone workload: two threads on separate
   stacks share memory, `getpid` equal and `gettid` distinct, `kill(getpid())` handled by
   a non-blocking thread, `tgkill` hits one thread, a thread exit is not reaped by
   `wait4`, `exit_group` from a thread ends the group, the parent reaps once with the
   group status, exec from a two-thread group is `EBUSY`, and the clear-tid futex wakes a
   joiner. Independent lock/lifetime review. Gates: build, lint, hosted, `make test`,
   ring3-mm, SMP 2/4/8/16.

G8 items follow step 7 and are tracked in the status record.

## Exec from a thread group (done 2026-10-20, before default enablement)

Until 2026-10-20 `execve` from any member of a group with more than one member returned
`EBUSY` (the address space and fd table are shared). Linux instead runs `de_thread`: the caller
kills every other member, waits until they are gone, takes over the leader's PID if it is
not the leader, and then unshares the fd table (`unshare_files`) before loading the image.
musl's `posix_spawn` and `system` use a `CLONE_VM|CLONE_VFORK` child, not a thread, so the
common spawn path is unaffected; a threaded program that calls `execve` directly is.

Order, each step gated like the ones above:

1. **Leader exec.** Implemented 2026-10-20 (design below), independently reviewed with no
   D0-D2 finding; the Ring-3 leg passes on 1/2/4/8/16 CPUs. Add a group "exec in
   progress" state, distinct from `exiting`, so the
   siblings die without a group exit status or a parent report. Post a kill to every other
   member (as `request_exit_group_atomic` does, minus the caller) and wait, interruptibly
   by a kill aimed at the caller, until `members() == 1`; the auto-reap drain releases the
   siblings. The shared mm and `FilesTable` then have one owner, and the existing exec path
   runs unchanged. Ring-3 leg: a two-thread group whose leader execs a marker program and
   is reaped once with the new image's status.
2. **Non-leader exec.** Implemented 2026-10-20 as a handoff to the leader instead of a
   PID takeover (the `PROCESS_TABLE` slot, PID-namespace mappings, `ns_tgid`, the
   parent's `children` entry, the cgroup membership and the kernel stack all name the
   leader); design and review below.
3. **Close-on-exec on a table shared outside the group.** Not reachable: `CLONE_FILES`
   is refused outside a thread group, so after step 1 the table has one owner.

### Leader exec design (step 1, 2026-10-20)

Premises verified against `main` at `a5f9441`: `exec_from_bytes` refuses on
`files.owners() > 1`, `thread_group_size(tgid) > 1` and `address_space_share_count > 1`
before any work; `request_exit_group_atomic` posts a fatal exit to every other member
under `PROCESS_TABLE` without setting `exiting`; a non-leader's exit marks it for the
auto-reap drain, and its reap (`cleanup_zombie`) drops `members` in Phase 1 and releases
its fd-table owner and pins the raw tgid (`tgid_inflight`) until the end of Phase 2; a
dying task switches to the boot CR3 before it halts.

- **Where.** In `exec_from_bytes`, after the LSM exec hook, the comm-name preparation
  and a new pure pre-flight `elf_loader::validate_elf_image`, and before the existing
  refusals. An image that fails these checks is refused before any sibling is touched.
- **Who.** Only the leader (`tgid == pid`) drains. A non-leader still gets `EBUSY`
  (step 2). If a task outside the group shares the address space (a `CLONE_VM` child
  that is not a thread), exec returns `EBUSY` before killing anyone, as today. That count
  runs after the drain claim (below): a non-thread `CLONE_VM` clone checks
  `exec_draining()` under the child lock that publishes its address space, so either the
  count sees the child or the clone sees the claim and aborts with `EBUSY`.
- **State.** `ThreadGroup.exec_draining: AtomicBool`, separate from `exiting`. The leader
  claims it by CAS; a guard clears it on every return from `exec_from_bytes`. `exiting`
  stays one-way, so an `exit_group` that races the exec is never undone. If `exiting` is
  already set, exec waits for the exit that the setter posts to every other member and
  returns `EINTR`; the epilogue then ends the caller (it never reaches user mode).
- **No new members.** Every `exiting` check in `sys_clone(CLONE_THREAD)` refuses while
  `exec_draining` is set too (`ThreadGroup::closed()`). The flag is stored before the kill
  scan takes `PROCESS_TABLE`, and the publication check runs under `PROCESS_TABLE`: a
  thread published before the scan is a member the scan kills (a `Provisioning` one dies
  at admission or rolls back), and one published after sees the flag and aborts.
- **Kill.** `request_exit_group_atomic(pid, group, 128 + SIGKILL)`. Siblings consume an
  ordinary posted exit: no `group_fatal`, no parent report (the leader is alive, so the
  last-member removal finds no reportable zombie leader).
- **Wait (killable, like Linux `de_thread`).** Loop: run `drain_thread_autoreap()`; if the
  leader has a posted fatal exit, return `EINTR`; stop once `members() == 1`, the fd table
  has one owner, and no Phase-2 reap of this tgid is in flight; otherwise yield and halt
  until the next interrupt (the `nanosleep` pattern). Waiting for `tgid_inflight == 0`, not
  only `members == 1`, orders every sibling's `free_process_resources` (mm accounting,
  fd-table release) before exec rewrites the shared `MmState`. Each sibling ran its
  clear-tid write and robust-list walk in `terminate_process`, before its reap, so they hit
  the old address space while it is still live. Non-fatal signals do not interrupt the
  wait.
- **After the wait** the existing refusals run unchanged and pass. The disposition table
  may still be referenced by a reaped sibling's PCB during its final drop; no live task
  can read it (`CLONE_SIGHAND` needs `CLONE_VM`, and the share count admits only the
  caller), so exec's `strong_count == 1` assertion becomes `members() == 1`.
- **Signals during the drain.** Process-directed target selection never chooses a member
  with a posted fatal exit, named or not, and while the group is draining it chooses only
  the leader (a dying sibling may already have consumed its posted exit on the way out).
  A process-directed signal queued before the drain sits in the group set, and one a
  dying sibling claimed but did not deliver goes back to it when the sibling exits
  ("G7 shared pending set"), so the leader still receives it. Job-control stops are not
  applied to a task of a draining group (Linux suppresses group stops during
  `de_thread`), so a `SIGSTOP` cannot park the drain under the staging admission.
- **clear-tid.** The exec commit clears `clear_child_tid` next to the robust-list reset
  (Linux `exec_mm_release`); before, an exit after an exec that did not call
  `set_tid_address` again zeroed and futex-woke an address in the new image.
- **Failure after the drain.** The siblings stay dead; the leader keeps its old image (the
  existing rollback) and gets the error. Linux kills the process past its point of no
  return instead. This is a deliberate, safe deviation.
- **Lock order.** The drain holds no lock while waiting. `request_exit_group_atomic` takes
  `PROCESS_TABLE` → each PCB, as for `exit_group`; the tgid in-flight probe takes
  `REAPING_PID_STATE` alone.
- **Tests.** Hosted: `exec_draining` closes the group to new members and the claim is
  exclusive; target selection skips dying members and, during a drain, everyone but the
  leader. Ring 3 (ring3-mm, forked host): a leader with a thread spinning in user mode
  (ended from an interrupt) and a thread blocked in `FUTEX_WAIT`, both sharing the fd
  table and carrying `CLONE_CHILD_CLEARTID` words, sees a non-leader exec fail with
  `EBUSY`, then execs a minimal image through `spawn_image` and is reaped once with that
  image's exit status; no task of the group is left. Gates on 1/2/4/8/16 CPUs.

#### Review (2026-10-20)

An independent reviewer read the diff against this design (lock order, clone
publication, address-space and fd-table lifetime, parent report, races with
`exit_group`, fatal signals, OOM and the namespace cascade, LSM/pre-flight reordering,
signal routing, the Ring-3 leg). No D0-D2 finding. Dispositions, all re-reviewed:

| Finding | Severity | Disposition |
|---|---|---|
| F1 non-thread `CLONE_VM` sharer published between the foreign count and the kill scan; siblings ended, then `EBUSY` | D3 | Fixed: claim before the count; clone checks the claim under the publishing child lock |
| F2a signal queued on a sibling before the drain is lost | D3 | Fixed by the G7 shared pending set and claim return (2026-10-20) |
| F2b/c named dying sibling, or one that consumed its posted exit, still chosen | D3 | Fixed: dying members never chosen; leader only while draining |
| F3 exec never cleared `clear_child_tid` (pre-existing) | D4 | Fixed in the exec commit |
| F4 `EINTR` could reach user mode before the leader's kill was posted | D5 | Fixed: wait for the post |
| F5 comment overclaimed the pre-flight | D5 | Fixed: segment checks run in `load_elf`, after the drain |
| F6 Ring-3 leg missed the interrupt kill path and clear-tid words | D5 | Fixed in the leg |
| Re-review: a signal the leader blocks, sent between the claim and an `EBUSY` from a foreign sharer, waits on the leader | D5 | Accepted (delayed, not lost) |

### Non-leader exec design (exec step 2, 2026-10-20)

**Why not a PID takeover.** Linux's `de_thread` gives the exec'ing thread the leader's
PID. Here a PID fixes the kernel-stack address (`KSTACK_BASE + pid * KSTACK_STRIDE`;
`free_kernel_stack` quarantines a stack whose base does not match its PID), the scheduler
queue key `(pid, generation)`, per-CPU current-pid and FPU-owner slots, cgroup and
watchdog registrations, RCU stack permits and futex/IPC keys; the root PID namespace is
identity-mapped (`attach_root_pid_reserved`), so an alias cannot leave the global PID
behind. Moving a running task to another PID would mean re-keying all of these.

**Handoff instead.** The leader L keeps its identity and performs the exec; the calling
thread T prepares it and exits. Externally this matches Linux: the new image's only
thread has `tid == pid ==` the old process id, and T's tid disappears.

1. **T, before the point of no return:** LSM exec hook, `validate_elf_image`, comm name
   (as for every exec). Then the drain claim: if another exec holds it, T waits
   (killably) until the claim is released and retries, or dies when that exec ends it.
   With the claim: refuse `EBUSY` if a task outside the group shares the address space,
   if L is a zombie or already exiting (`group_live` false; a deliberate deviation:
   Linux would take over the zombie leader's PID), or if the stub page (below) cannot
   be mapped. Build an `ExecHandoff` (fallible allocation): the image bytes, argv, envp,
   execfn, the front-end's staging admission (`TransientPeakGuard`, held by the handoff
   and then by L until its exec returns), and T's own state that Linux keeps across exec
   and that can differ from L's here: blocked mask, T's thread-directed pending signals, rlimits (per task here),
   CPU affinity, seccomp state (filters and `no_new_privs`), pledge state, the
   `pid_ns_for_children` that `unshare(CLONE_NEWPID)` may have changed, and T's fd table
   (with its own owner count, so T's exit cannot close it) and fs context when they are
   not L's (`CLONE_FILES` and `CLONE_FS` are optional for threads). Unchanged by construction: credentials, capability table and signal
   dispositions (shared by every thread), cgroup (migration is refused while the address
   space is shared), mount/ipc/net/user namespaces (`unshare` and `setns` refuse
   `CLONE_NEWNS` in a group and support nothing else), static priority (no setter).
2. **Publish (point of no return)** under `PROCESS_TABLE` and L's PCB lock: refuse if
   `exiting` is set (T then waits for its own posted exit and returns `EINTR`) or L is no
   longer live; otherwise store the handoff in L's PCB, make a parked L runnable and clear
   its job-control stop (as a fatal post does), and post a fatal exit to every other
   member except L and T. Siblings then die as in the leader drain. While a handoff is
   pending (and while the group drains), job-control stops are not applied to L.
3. **Stub** (mapped before the publish, so a failure is an `EBUSY` before the point of
   no return). T maps one private frame holding `mov eax, 39; syscall; ud2` read-only
   and executable at `USER_STACK_TOP` (`0x7FFF_FFFF_E000`), the unused page just above
   the main stack (`ensure_exec_stub`). Its page table always exists (the eager stack
   pages share it) and the KPTI user root shares it, so the map allocates no table
   (`EBUSY` if it is missing). `mmap` and `mremap` never place a user mapping on that
   page (`user_mapping_reserved_window`), so a page already present there is a stub an
   earlier, abandoned handoff left, and it is reused. (The stack guard page was
   considered and rejected: it lives in a different 2 MiB page table that normally does
   not exist.) The frame is an ordinary untracked user page: exec frees it with the old
   address space, teardown frees it, a fork that races the handoff copies it like any
   read-only page.
4. **T waits** (killably) until L has taken the handoff. It then hands its drain claim
   to L's exec (`ExecDrainGuard::hand_over`), posts its own exit unless a fatal exit is
   already posted (`request_process_exit_if_unposted`, so a real exit code is never
   overwritten) and returns `EINTR`; the syscall-return gate ends it after every frame
   above has unwound. If L becomes a zombie or leaves the live set first (a leader
   `exit` racing the publish), T takes the handoff back (returning the fd-table owner
   count) and returns `EBUSY`; the siblings it ended stay ended (deviation: Linux would
   complete the exec). The stub page stays mapped in that case. A leader that dies
   with a handoff still in its PCB drops it in `terminate_process`, not at its reap.
5. **L takes it at the first safe point.** One PCB-lock gate, shared with the existing
   pending-kill check, runs at syscall entry and at syscall return; a pending kill always
   wins.
   - *Syscall entry:* the gate also snapshots the syscall-frame binding whenever the task
     is in a group with more than one member (before: only for 59/517 or with a handler
     installed). With a handoff pending, the call is skipped before seccomp and the LSM
     syscall hook (T's seccomp state is installed into L instead) and L runs the exec.
     The exec is audited as syscall 59 with its result; the skipped call gets no audit
     record and no LSM exit hook, and the leader does not run the exec LSM hook again
     (T ran it for the same image and the group's shared credentials). T's own
     `execve` is audited as returning `EINTR` (deviation).
   - *Blocked in a syscall:* `wait_should_abort` also reports L's own pending handoff, so
     every interruptible wait returns `EINTR`, and `should_abort_pending_block` reports
     it too, so a wait that committed `Blocked` after the publish is not missed (review
     F1); the syscall return gate then runs the exec
     on the frame binding saved at entry. The reviewer's concern (an `EINTR` the epilogue
     does not consume livelocks) does not apply: the return gate consumes the handoff,
     and with no saved binding the next syscall entry does. L takes the handoff out of its
     PCB before its own drain, so the drain's abort check sees nothing.
   - *Running in user mode:* at timer-interrupt return to ring 3, after the pending-exit
     deferral and before signal delivery, a try-lock check redirects RIP to the stub and
     clears TF, AC and DF; the next instruction enters a syscall. The check runs only
     while a handoff is pending anywhere (`EXEC_HANDOFFS_PENDING`, one atomic load per
     tick otherwise).
   - *L in its own exec:* if T claimed first, L's drain waits on the claim; the handoff
     ends that wait with `EINTR` and the return gate runs T's exec instead (L's exec is
     lost, as the losing exec in Linux).
   Applying the handoff: L installs T's state (above), with its seccomp generation
   bumped past both tasks' (never moved back), replaces its own thread-directed pending
   signals with T's, installs T's fd table and fs context if they differ (releasing its
   own), and runs `exec_from_bytes` as a leader exec whose drain owns the claim T made
   (the guard releases it even when the group already has one member). The staging
   admission is released when that exec returns. The exec commit drops the old image's
   futex buckets (`futex_drop_space`; the `mm` object and its key space survive exec).
6. **Failure after the publish** (load error, out of memory, a fatal exit posted during
   the drain): the result goes back through the gate; a pending fatal exit wins with its
   own code, otherwise the group dies with `SIGSEGV` (Linux `force_fatal_sig`). The
   segment checks still run in `load_elf`, after the point of no return.

**Invariants.** At most one handoff per group (the drain claim). Only L consumes it, and
only L's own PCB holds it. T owns the stub frame until it is mapped; afterwards the
address space owns it. No PID-keyed state moves. Lock order: `PROCESS_TABLE` -> L's PCB
for the publish; the gate takes only the current task's PCB; the IRQ hook only
try-locks; the stub map takes `PT_LOCK` with no PCB held.

**Known deviations.** A thread-directed signal sent to T after it built the handoff is
lost with T. A zombie or exiting leader gives `EBUSY` (Linux completes the exec). A
leader in an uninterruptible wait or a job-control stop that cannot be woken delays the
exec until it returns. A fork by a dying sibling during the handoff can complete, as
during `exit_group` today.

**Tests.** Ring 3 (forked host): a non-leader execs a marker image while the leader
(a) blocks in `FUTEX_WAIT`, (b) spins in user mode, (c) sleeps in `nanosleep`; a third
thread of the group is ended; the host reaps the process once with the new image's
status; one leg's image exits with its `getpid()`, which the host matches against the
old tgid. Hosted: the handoff gate order (kill before handoff), state transfer, the
`wait_should_abort` and `should_abort_pending_block` reports, stop suppression, the
pending-handoff count, and the handoff going back to T when L dies.

#### Review (2026-10-20)

An independent reviewer read the first draft of this design (verdict: conditional go).

| Finding | Severity | Disposition |
|---|---|---|
| A static, boot-allocated stub frame would be freed by teardown (`PAGE_REF_COUNT` reports it untracked), refcounted by fork and reused across processes | D1 | Fixed in the design: a private per-handoff frame owned by the address space, never shared |
| A zombie leader | D3 | `EBUSY`, recorded as a deviation |
| State transfer list incomplete (fd table, fs, `no_new_privs`, affinity, namespaces, L's own pending) | D3 | Transfer list above; each other field checked shared or immutable within a group |
| Widening `wait_should_abort` | D3 | Kept, with the return gate consuming the handoff (see step 5) |
| Frame binding missing for a blocked leader | D4 | Snapshot at entry for every task in a multi-member group |
| Failure handling after the handoff | D4 | `SIGSEGV`, pending kill first, gate re-checked after the exec |
| Stub at the guard page "shares the stack-top page table" | (premise) | Wrong: different 2 MiB table. The stub moved to `USER_STACK_TOP` |
| Not raised: a leader `exit` racing the publish loses the exec | (new) | T waits for consumption and returns `EBUSY` if L dies first |

#### Implementation review (2026-10-20)

An independent reviewer read the implementation (no D0/D1). Dispositions:

| Finding | Severity | Disposition |
|---|---|---|
| F1 a wait that commits `Blocked` after the publish misses it | D2 | Fixed: `should_abort_pending_block` reports a pending handoff |
| F2 T holds the system-wide staging admission while L can be stopped indefinitely; L then execs without it | D2 | Fixed: the admission moves into the handoff and L holds it through its exec; stops are not applied during a handoff or a drain |
| F3 the stub page may be in use; a failed map lands after the point of no return | D3 | Fixed: mapped before the publish; `mmap`/`mremap` reserve the page; a present page is a reused stub |
| F4 audit records the exec under L's skipped call and runs hooks twice | D3 | Fixed: audited as 59; no exit hook for the skipped call; the exec LSM hook runs once (in T). T's `execve` is still audited as `EINTR` |
| F5 a zombie leader keeps the handoff until its reap | D4 | Fixed: dropped in `terminate_process`; the poll reports abandoned from `group_live` |
| F6 the handoff's fd table had no owner count | D4 | Fixed: own owner count, returned on drop or abandon |
| F7 extra IRQ work on every tick | D4 | Fixed: gated on `EXEC_HANDOFFS_PENDING` |
| F8 T's self-posted exit could overwrite a real code | D5 | Fixed: `request_process_exit_if_unposted` |
| F9 `seccomp_generation` could move back | D5 | Fixed: `max(L, T) + 1` |
| F10 early returns leave `exec_draining` set; legs miss `getpid` | D5 | Accepted (the group dies with `SIGSEGV`); `getpid` leg added |
| Default-enablement risk: `wait_reap_group` polls with a table scan per tick per waiter | D3 | Fixed: sleeping group wait (G8) |

A second independent review (2026-10-20) read the fixes above, the G7 rework, the
sleeping group wait and procfs. No D0/D1; F1, F3, F5-F9 closed, F2 closed except that L
holds the staging admission through an uninterruptible wait (recorded deviation), F10
accepted. Its new findings and dispositions:

| Finding | Severity | Disposition |
|---|---|---|
| A non-leader in `ppoll`/`pselect6` never sees a group signal queued before it opened its mask | D2 | Fixed: mask installs mark takeable group signals (`recalc_shared_signals(true)`) |
| The group-exit report went to the parent pid read at exit start; a parent that exited meanwhile left a group wait asleep | D2 | Fixed: current parent and its group read under `PROCESS_TABLE` at report time |
| Selection read the target's mask unlocked; a target that blocked the signal before the queue kept it | D3 | Fixed: retarget at queue time |
| A chosen member inside a handler keeps a caught signal; an IRQ-entered handler's mask was recalculated only at the next syscall return | D3 | Fixed: handler-aware selection, retarget and recalculation; recalculation at syscall entry |
| Exec handoff lost the leader's claimed group signals and duplicated the thread's | D3 | Fixed: both return claimed bits first |
| Retarget scanned the table for a single-task process | D4 | Fixed: single-member short-circuit |
| One chosen flag made a member chosen for one signal abort waits for another | D4 | Fixed: per-signal chosen mask; a narrow abort-then-lose window remains (recorded) |
| PCB `Arc` held across no-return exits in signal delivery | D4 | Fixed: dropped before every terminate in `maybe_deliver_signal` |
| `tkill` onto a claimed instance merges; SIGCONT leaves other members' claimed stop bits; `kill(tgid)` `ESRCH` with a zombie leader and only dying threads | D5 | Recorded (G7 "Not covered") |

## Acceptance

- Every step: no regressions on the gate ladder; hosted tests for its decision logic.
- Step 7: the Ring-3 thread workload passes on 2/4/8/16 CPUs; zombies, PIDs and kernel
  stacks return to baseline after the workload (procfs task count and `pids.current`);
  independent review finds no D0-D2 lifetime or lock-order defect.
