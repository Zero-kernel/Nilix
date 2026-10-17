# GAP-5 Slice 3: Shared File-Descriptor Table (`FilesHandle`) Design

Status (2026-10-17): steps 1-3 IMPLEMENTED, verification pending (g56o).
- Step 1 (2026-09-28): fd fields grouped into `process::FdState`.
- Step 2: the table records its charged cgroup and an owner count; only the last owner's
  teardown closes descriptors and returns the charge (`free_process_resources`,
  `Process.files_released` guards a repeated teardown).
- Step 3: `Process.files: Arc<FilesTable>` with its own leaf lock (`FilesTable::lock`);
  `FdState` methods run under it, `Process` wrappers pass the RLIMIT_NOFILE bound and the
  capability table. `get_fd` returns `FdRef`, which holds the table lock. Under the guest
  `thread_preview` feature, `CLONE_FILES` inside a thread group shares the `Arc`
  (owner +1, no copy, no batch charge, no per-fd cap bump); `CLONE_FILES` without
  `CLONE_THREAD` is `EINVAL`, because a shared table needs the shared capability table its
  cap ids refer to. Exec refuses (`EBUSY`) while the table is shared, instead of unsharing.
- Step 4 (default enablement) open.
Parent: [GAP-5/6 status](gap-5-6-threads-scheduler-status-2026-09-28.md),
plan §5 (`docs/design/kernel-gap-implementation-plan-2026-09-13.md`).

## Current tree facts

- fd state is per-PCB: `fd_table`, `cloexec_fds` (`process.rs:2052-2057`),
  `fd_reservations`/`fd_cloexec_reservations` bitmaps and
  `fd_reservations_charged_count` (`process.rs:2060-2071`), `fds_charged_count`
  (`process.rs:2091`). About 90 `fd_table` references across ten kernel files.
- `CLONE_FILES` today deep-copies under the PCB locks and bumps each fd's cap
  refcount like dup (`syscall.rs:5790-5830`); the batch charge is set only after
  the last error path (`syscall.rs:6092-6133`). Fork does the same (`fork.rs:1155`).
- INV-CG-FD (`process.rs:2082-2091`) and three contract comments rely on "never
  Arc-shared, even under CLONE_FILES": exit uncharge (`process.rs:10411`), exec
  cloexec drain (`process.rs:3374`), exec capacity reservation (`syscall.rs:6702`).
- The cap table is already shared under `CLONE_THREAD`; exit pays back per-fd cap
  refcounts before teardown (`process.rs:10397-10408`).

## Target shape

Move all fd state into one object held as `Process.files: Arc<FilesHandle>`,
mirroring `FsContextHandle` (slice 2):

```text
FilesHandle { inner: SpinLock<FdState> }
FdState { fd_table, cloexec_fds, fd_reservations, fd_cloexec_reservations,
          fd_reservations_charged_count, fds_charged_count, cgroup_id }
```

- Charge follows the object: `fds_charged_count` and the charged cgroup live in
  `FdState`. The uncharge runs once, in `FilesHandle::drop` / last-reference
  teardown, not per PCB. INV-CG-FD becomes "charged count == descriptors held by
  this table, charged to the table's cgroup".
- The table is created charged (`arc_charge_bytes::<FilesHandle>()` in
  `try_new_pcb`), like the signal table.

## Lock order and lifetime

- Order: PCB lock -> `FilesHandle` lock -> cap-table leaf. The files lock never
  takes a PCB, scheduler or VFS lock. `copy_from` snapshots then locks the
  destination, with a `ptr::eq` guard (same as `SignalTable::copy_from`).
- `FileDescriptor` drops never run under either lock. Close, dup2 replace, exec
  cloexec and exit collect into a pre-reserved buffer and drop after release.
- Exit: a thread's exit only drops its `Arc`. It must not close fds or uncharge
  while siblings hold the table. The per-fd cap payback moves to the last-reference
  teardown, because caps are counted per table, not per thread.
- The final `Arc` drop must happen in process context with no locks held; never in
  IRQ. `free_process_resources` takes the `Arc` out of the PCB, drops the guard,
  then drops the `Arc`.

## Exec

Exec with a shared table must first unshare it (Linux `unshare_files`): allocate
a fallible, charged copy before any irreversible exec step, returning ENOMEM on
failure. Only then run the cloexec drain on the private copy. That keeps the
existing capacity argument (`syscall.rs:6702`) valid. The exec share-count gate
for CLONE_VM siblings stays as defense in depth.

## Concurrency hazards to cover

- Two threads allocating fds: reservation bitmap and `files.max` charge updated
  under the files lock only.
- close vs. an in-flight syscall using that fd: operations clone the
  `FileDescriptor` `Arc` under the lock and drop the lock before blocking I/O,
  so close only removes the table entry.
- procfs `/proc/<pid>/fd` enumerates under the files lock with a fallible
  pre-reserved key buffer (`procfs.rs:2082`).
- poll/select snapshot descriptors under the lock, then wait unlocked.

## Migration steps (each gated before the next)

Deviations recorded during implementation: the table is `FilesTable { inner:
Mutex<FdState> }` with the owner count inside `FdState` (decided under the same lock), not
a separate handle type; exec refuses a shared table with `EBUSY` rather than unsharing it
(no exec path can reach a shared table today, because a shared table implies a shared
address space, which exec already refuses).

1. Introduce `FilesHandle` with accessors. Change PCB call sites to
   `proc.files.lock()`. Behaviour unchanged, always private. Gates: build, lint,
   hosted, `make test`, ring3-mm, SMP 2/4/8/16.
2. Move charge ownership and exit/exec paths to the handle. Rewrite the three
   "never Arc-shared" contracts. Add a hosted unit test for charge conservation
   across copy, drop and a failed clone.
3. Add the dormant `CLONE_FILES` share branch (`Arc::clone`), with exec unshare.
   The flag stays rejected until `MmHandle` and `CLONE_THREAD` land.
4. Enable with the thread flags. Add a Ring-3 test: threads share open/close,
   exec unshares, exit of one thread keeps sibling fds live, and the `files.max`
   charge returns to baseline after all threads exit.

## Acceptance

- No `FileDescriptor` drop under PCB or files lock (grep audit plus review).
- `files.max` usage returns to baseline after fork, clone, exec and exit storms
  (pressure soak).
- 2/4/8/16-CPU gates with 0 failures. Independent review of lock order and last-
  reference teardown before the flag is enabled.
