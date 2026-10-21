# Next implementation handoff — thread groups enabled by default, 2026-10-20

**Source:** `main` at `a5f9441` plus an uncommitted working-tree diff (no commit or push;
`kernel/mm/firmware.rs` is a new untracked file).
**Supersedes:** [next-handoff-2026-10-17](next-handoff-2026-10-17.md) and the first
version of this file (written after the third batch). The user waived the 10-17 step 1
(scoped review of `cb503cf..HEAD`) on the strength of the R190 full-tree audit, then
decided to enable the thread flags only after every known gap was fixed.
**Record:** [GAP-5/6 status](gap-5-6-threads-scheduler-status-2026-09-28.md), "Third
batch" and "Fourth batch"; [slice 4 design](gap-5-slice4-thread-group-design.md).
**Status:** VALIDATED on `src22`, except musl-check at 8 CPUs (console marker interleaving, three of three; the guest passes; serial-lock debt)

## 1. What this round did

| Item | Result |
|---|---|
| Leader exec (10-17 step 2) | The leader ends the other members, waits until it alone owns the address space and fd table, then execs |
| Non-leader exec | Handed to the leader, which keeps the PID (`ExecHandoff`, stub page at `USER_STACK_TOP`) |
| 16 CPUs and a thread soak (10-17 step 3) | `musl_check.sh` accepts 16 CPUs; stress profile `thread` (id 7) |
| G7 shared pending set | Group-wide pending signals claimed by one member; per-signal chosen mask; recalculation on mask changes; retargeting |
| G8 | Sleeping group `wait4`; group-wide children; children handed on by a dying member; group-exit report to the current parent |
| procfs | `/proc/<pid>/task` member lists, `Tgid`/`Threads` |
| Futex parity | True requeue, `FUTEX_WAKE_OP`, partial bitsets, keys by address space; `futex_drop_space` at exec |
| PI futexes | Linux user-word protocol, `LOCK_PI`/`LOCK_PI2`/`TRYLOCK_PI`/`UNLOCK_PI`, requeue-PI, priority inheritance with a chain walk, no-fault locked word access, killable waits |
| Debt items | `finish_wait` and pipe wakes; affinity kick; F9 (boots with 2 GiB or more); firmware memory-type check; clear-tid D4/D5 residue |
| Enablement (old step 4) | `thread_preview` removed; thread flags in every build; `rf186_clone_contract_tests`, README rows and roadmap updated |
| Found by the gates | Fork deadlock (`fork_inner` looked up the child with the parent's PCB held; the cpu soak stalled in every run); two indirect lock cycles through `pipe.inner` and `sockets` (static audit); a one-CPU livelock where a deferred IRQ kill never drained while the killer spun in `waitid` (2 of 5 one-CPU ring3-mm runs), and, from its reviews, the same gap when the victim or an exited thread handed the CPU to a user-mode spinner (the scheduler now routes both through the idle context). A thread-soak stall (14 of 27 extra soaks): `SharedCredentials` reader admission failed when a sibling's reader came or went at the same moment, so musl's `FUTEX_REQUEUE` failed with `EPERM` and its condvar waiter slept forever, and `clone` failed with `EAGAIN`. All fixed; see the slice-4 design, G8 and "Shared credential admission" |
| Reviews | Independent reviews of leader exec, non-leader exec (two passes, also covering G7/G8/procfs), the PI work, the PI fix delta, a PI third pass, the lock-order audit and its fixes, the blocked-wait drain (two passes), and the credential admission fix: no D0-D2 open |

## 2. Next plan

1. **Stage 2-3** (`kernel-security-audit`, then `kernel-review-fix`) over this diff (59
   tracked files, about +17,500/-4,900 lines, plus `kernel/mm/firmware.rs`). Then commit
   in reviewable pieces: third batch (leader exec, waits/pipes, F9, thread soak); G7
   shared pending; G8 and procfs; non-leader exec; futex parity; PI futexes; enablement
   and docs.
2. **Thread debt** (all recorded in the slice-4 design):
   - D3-A: a handler signal for a thread blocked in `LOCK_PI`/`WAIT_REQUEUE_PI` runs only
     when the call returns (needs a syscall restart; Boehm/Mono stop-the-world risk), and a
     group signal chosen for such a waiter is not retargeted.
   - D4-A: past 16 PI waiters, lockers poll once a tick with no FIFO order or donation.
   - D5: exec runs no `exit_robust_list`/`exit_pi_state_list` equivalent; the early `#PF`
     no-fault fixup accepts any exception-table RIP; the usercopy fallback tears down with
     IF=1.
   - Sigframes are refused on a static stack (RF178-34; Linux allows any writable stack).
   - G7 D5s: `tkill` onto a claimed instance merges; SIGCONT leaves other members'
     claimed stop bits; `kill(tgid)` `ESRCH` with a zombie leader and only dying threads;
     a narrow abort-then-lose `EINTR` window.
   - Exec: the leader holds the staging admission through an uninterruptible wait (F2
     residual); T's `execve` is audited as `EINTR`; a failure after the drain leaves the
     leader single-threaded with its old image.
   - Locks and reaping (slice-4 design, G8): the socket timer sweep wakes under
     `sockets.read()` (D4, latent); the group-exit report signals the parent by pid after
     the table is released, so a reused pid can get a stray `SIGCHLD` (D4);
     `reparent_orphans` does not notify the adopter of an already-zombie leader (D4);
     suspected, unconfirmed cycles: a two-task pipe variant, a `PidNamespace` drop under
     the table in `list_pids`, and the unannotated usercopy fault fallback.
   - Idle and deferred work (slice-4 design, G8 "Second review"): the BSP idle loop is
     the kernel shell, which polls the keyboard buffer user stdin also reads before it
     drains (D3); on SMP a contended `finish_pending_prev` lets the candidate run before
     the idle drain (D4); `waitid` reports a killed child as `CLD_EXITED` with 128+signal
     (D4); stdin wakes, TCP timers and RCU still wait for a kernel entry when every task
     spins in user mode; nothing asserts that a drained teardown never sleeps (D4).
   - Credentials and LSM (slice-4 design, "Shared credential admission"): the exec LSM
     hook and the kill path's `hook_signal_send` are skipped when the LSM context is
     `None` (fail open; D3, latent now that admission no longer fails spuriously, but
     any future `set*id` writer window reopens it); the syscall-entry
     `debug_assert!(lsm_ctx.is_some())` contradicts the R184 fail-closed path (D5);
     `drain_deferred_stdin_wakes` may drop a waiter whose PCB try-lock fails
     (suspected D4).
   - Tooling: QEMU's end-of-window termination can cut the last stress round, and
     `stress_protocol.py validate-log` rejects it: a marker cut mid-line (src12) or a
     round whose HEARTBEAT never printed ("last profile round has no HEARTBEAT", src16,
     guest healthy at 3,177 rounds). Both hit stress-smp; reruns qualify. A
     host-terminated run should drop an incomplete final round.
3. **Serial lock (do before the next ladder):** the kernel shell's start-up lines and
   banner on the BSP race PID 1's first output on an AP, byte by byte. musl-check at 8
   CPUs failed in all three `src22` runs (one of three on `src16`) on split markers,
   with the guest at exit 0. Whole writes need to be atomic on the UART (IRQ-safe, with
   the panic path able to bypass the lock).
4. **Older debt:** F7 in-place PCB construction; a `getcpu` syscall for an
   affinity oracle; stress process/block/combined profiles (`RLIMIT_NPROC`, `fsync`,
   `open` modes); `sigaltstack`, `rt_tgsigqueueinfo`.

## 3. How to continue

- **Disk bounds parallelism.** Each QEMU gate writes a `-d int` log of up to about 4 GB in
  `/tmp` and holds a ~900 s window. After the user-approved cleanup of stale trees
  (2026-10-21) nilix-dev has about 50 GB free, enough for ten guests at once.
- **Lane runner.** `/tmp/nilix-lane4.sh TREE LOG step cmd... ;; step cmd...` deletes each
  step's interrupt logs and gates guest steps on a host-wide slot count
  (`/tmp/nilix-maxq`) and free disk; host-only steps are named `pre-*` or after the
  build/lint/hosted checks. `make` returns 2 for a QUALIFIED gate and the stress gate 3,
  so read verdicts from the logs (`/tmp/nilix-verdicts.sh LOGDIR...`).
- **Syncing from macOS.** Build tarballs with `COPYFILE_DISABLE=1`: AppleDouble `._*.rs`
  stubs make the hosted `lsm-hook-census` suite fail on invalid UTF-8.
- **Python on nilix-dev.** Never run a Python helper from `/tmp`: a foreign
  `/tmp/bisect.py` shadows the standard library and runs `git checkout` in another
  checkout. Use `/tmp/nilix-tools/` and `python3 -I`.
- **Hang triage.** A guest with `-qmp unix:...` (trees h9/h10 patch `kernel_test.sh`) can
  be sampled with `info registers -a` and `x/Ngx`; the kernel slide is the IDTR base
  minus the `IDT` symbol. `/tmp/nilix-tools/r3-hang-catch.sh` samples a silent guest.
- **Trees.** Final sources (`src22`, 364 files in `/tmp/nilix-src22.sha`):
  `/tmp/nilix-{g1,g2,g3,h1..h10}`; h9/h10 are QMP diagnostic copies (only
  `kernel_test.sh` differs). h* are slim copies without hosted/clippy/fuzz targets.
  Logs `/tmp/nilix-Z{1..13}-logs`.
- **Soak stalls.** The stress-only futex trace and syscall-error logging that found the
  credential bug were removed; the instrumented diff is not kept in the tree. Start
  from the stall dump (`STALL-DUMP task`) and the syscall return values.
- **Pins.** Hosted total 515 (kernel-core 105, vfs 66, ipc `robust_ futex_parity_
  futex_pi_` 23 run / 17 filtered). ring3-mm pins 31 PASS lines.
- **Line endings.** Rust sources and the Makefile are CRLF; `kernel/Cargo.toml` and
  `kernel/kernel_core/Cargo.toml` are mixed. Edit byte-exactly and compare CR counts.

## 4. Amendment record

| Date | Change |
|---|---|
| 2026-10-20 | Written after the third GAP-5/6 batch. |
| 2026-10-20 | User decision on step 1: enable the thread flags by default only after every known gap is fixed (G7 shared pending set, G8, futex parity including true requeue, `FUTEX_WAKE_OP`, partial bitsets and requeue-PI, non-leader exec, clear-tid D4/D5 residue, firmware memory-type check). Work started the same day. |
| 2026-10-20 | Rewritten after the fourth batch: every listed gap is closed and the flags are enabled by default; the next stage is the security audit and review-fix pass over the uncommitted diff. |
| 2026-10-21 | Final ladder: extra thread soaks found the shared-credential admission bug (fixed, reviewed, hosted tests added); the stress-only diagnostics were removed; the final tree is `src22`. Every gate passed or qualified except musl-check at 8 CPUs (console interleaving, three of three). |
