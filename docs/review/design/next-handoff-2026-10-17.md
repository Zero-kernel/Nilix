# Next implementation handoff — GAP-5/6 threads, scheduler and soak, 2026-10-17

**Source:** `main` at `bd487f0` (the GAP-5/6 series `9ae1674..fec4178` plus the CI
repair `bd487f0`).
**Record:** [GAP-5/6 status](gap-5-6-threads-scheduler-status-2026-09-28.md) holds the
evidence for every item below; [slice 3](gap-5-slice3-files-handle-design.md) and
[slice 4](gap-5-slice4-thread-group-design.md) hold the designs.
**Plan:** gap plan §5/§6 (`docs/design/kernel-gap-implementation-plan-2026-09-13.md`) and the
[next-phase plan](../nextplan/next-phase-plan-2026-09-13.md) are local, untracked records.
**Status:** everything this round implemented passes its gates and is **verification
pending**: no independent review has run, so nothing is DONE. Thread clone flags are
still refused in default and production builds.

## 1. What landed

| Commit | Item | Gate evidence (QUALIFIED = zero failures, not a strict pass) |
| --- | --- | --- |
| `9ae1674` | F8: buddy metadata in boot-reserved frames | `-m 1G` boots; SMP 2/4/8/16 QUALIFIED |
| `0a42bd8` | GAP-6 W-3/W-4 selective wait, F4/F6 SCHED-TRAP + switch sentinel, F7 budget | ring3-mm, SMP 2-16 QUALIFIED |
| `91d4b87` | GAP-5 slices 1-4: `SignalTable`, `FsContextHandle`, `FilesTable`, thread groups G1-G7, review D1, behind `thread_preview` | ring3-mm thread legs on 1/2/4/8 CPUs |
| `e9a513d` | F13: a reschedule that did not switch is not a wake | musl-check 10/10 single-CPU runs (old kernel hung 4/5) |
| `b79e96b` | Linux futex ops (requeue served by wake, MATCH_ANY bitsets), musl pthreads | musl-check OK on 1/2/4/8 CPUs |
| `ddbccaf` | F10: PID reuse window, geometric process-table growth | cpu soak about 27,000 forks per window, no ENOMEM |
| `27f7ff3` | F14: stack demand growth retries on contention | ring3-mm 8/8 on 1/2/4/8 CPUs |
| `fba9904` | F15: reparent before the PID-namespace detach | same |
| `bf1b415` | F12: release builds trace only unresolved page faults | soaks print no trace, no split marker |
| `8c7f63b` | `/proc/schedstat` per-CPU switch/migration counters, RCU backlog | ring3-mm leg; retained in soak logs |
| `e65ca8b` | F11: work stealing tries every CPU; stress-only `stall_dump` | cpu soak 7,079 rounds, smp soak 6,630 rounds, no stall |
| `4d19e28` | Stress gate runnable; smp barrier and contention seed; live marker read | memory/cpu/smp soaks QUALIFIED |
| `559413a` | `KERNEL_TEST_CPUS` for SMP ring3-mm | found F14 and F15 |
| `bd487f0` | CI repair: musl harness fixture requires `MUSL-PTHREAD-OK`; syz executor starts its markers on a fresh line | outcome-caller unittests 12/12; qemu-fuzz executor gate PASS (3/3 completions) |

Final ladder on the final kernel (g60, g63): build, lint, hosted 468, `make test`
QUALIFIED 35/39/0, ring3-mm 23/0 on 1/2/2/4/4/8/8 CPUs, musl-check on 1/1/2/4/8 CPUs,
SMP 2/4/8/16 QUALIFIED 37/37/0, soaks memory 3,036 / cpu 7,079 / smp 6,630 rounds.

## 2. Unfinished work

Ordered by what blocks default enablement of threads first.

| # | Item | Why it is open | Owner / where |
| --- | --- | --- | --- |
| 1 | **Independent review of `cb503cf..HEAD`** | No reviewer has read G1/G2/G7, `FilesTable`, or F10-F15. A review started on 2026-10-17 was stopped before it reported. | `kernel-security-audit` (scoped), then `kernel-review-fix` |
| 2 | **Exec from a thread group** | `execve` with more than one member returns `EBUSY`; Linux kills the siblings, may take over the leader's PID, and unshares the fd table (`de_thread`, `unshare_files`). | Slice-4 design, "Open: exec from a thread group" |
| 3 | 16-CPU thread run and a thread workload under the pressure soak | Thread legs ran on 1/2/4/8 CPUs only; no soak profile creates threads. | `KERNEL_TEST_CPUS=16`; new stress profile or musl leg |
| 4 | Default enablement of the thread flags | Needs items 1-3, then `rf186_clone_contract_tests` updated and the `thread_preview` gate removed. | Slice-4 step 7 |
| 5 | `WaitQueue::finish_wait` | Same single-reschedule shape F13 removed from `finish_prepared` (pipes, `KMutex`, semaphore, condvar, PI futex). Callers re-check and re-queue, so no false wake was shown, but it was not reviewed. | `kernel/ipc/sync.rs` |
| 6 | Load balancing and `sched_setaffinity` | `balance_queues` still picks one busiest and one idlest CPU; `sched_setaffinity` does not move a task off a CPU it may no longer use. Stealing (F11) now covers both cases, but neither path changed. | `kernel/sched/enhanced_scheduler.rs` |
| 7 | Futex parity | `FUTEX_WAKE_OP`, requeue-PI and partial bitsets refused; requeue wakes instead of moving waiters (thundering herd on broadcast). | `sys_futex`, `ipc/futex.rs` |
| 8 | G8 thread semantics | Group-wide wait (any thread waits for any member's children), orphan reparent to a surviving sibling, namespace-init death with live siblings, LSM tgid, procfs thread listing, `get_robust_list`. | Slice-4 design G8 |
| 9 | Review D4/D5 residue | A COW clear-tid word is not cleared when the deferred kill drain runs from the idle loop (D4). The new kill-while-blocked leg covers the woken self-exit path, not the IRQ-kill drain (D5). | `terminate_process` clear-tid |
| 10 | F9 | Guests with 2 GiB of RAM or more panic in early boot (pre-existing; direct-map limit). | bootloader/mm, outside §6 |
| 11 | F7 | In-place PCB construction (the PCB temporary still lives on the kernel stack). | `try_new_pcb` |
| 12 | Stress process/block/combined profiles | Fail on `RLIMIT_NPROC`, `fsync` and `open` modes, outside §5/§6. | ST-K4 and rlimit work |

## 3. Next plan

1. **Review (stage 1).** Run `kernel-security-audit` scoped to `cb503cf..HEAD`. Ask for:
   lock order PROCESS_TABLE → PCB → leaf locks across clone, exit and reap; thread-group
   membership and the exactly-once report under concurrent exits; `FilesTable` owner
   count and charge return; `block_until_resolved` (busy-yield on one CPU, the
   interrupts-off branch); F14 retry (no livelock while the lock holder is preempted); F15
   ordering against the init-death cascade; `steal_from` try-lock use across many
   queues; the stall dump's try-locks; requeue-by-wake. Repairs then go through
   `kernel-review-fix`. **Acceptance:** no D0-D2 finding open.
2. **Leader exec (slice 4, open step 1).** An "exec in progress" group state, kill the
   other members without a group exit report, wait interruptibly until `members() == 1`,
   then run the existing exec path. A non-leader exec keeps returning `EBUSY` until the
   PID takeover is designed. **Acceptance:** a Ring-3 leg where a two-thread group's leader
   execs and is reaped once with the new image's status; gates on 1/2/4/8 CPUs.
3. **Scale and pressure for threads.** ring3-mm and musl-check at 16 CPUs; a soak or musl
   leg that creates and joins threads for a full window. **Acceptance:** QUALIFIED with
   0 failures and no stall dump.
4. **Enablement decision.** With 1-3 closed, decide whether default builds admit the
   thread flags; update `rf186_clone_contract_tests`, the README thread row and the
   roadmap.
5. **Debt in parallel:** item 5 (`finish_wait` review), item 6 (balancing/affinity), F9,
   F7, futex parity.

## 4. How to continue

- **Remote host.** `nilix-dev`, reached only through the SSH skill wrappers. Gate
  trees live in `/tmp/nilix-gap56-*`; `1017a` holds the committed tree with warm caches.
  Copy a tree per concurrent batch, upload only changed files, and compare sha256
  before running gates. Never overwrite a script a running batch is executing.
- **Disk.** `-d int` interrupt logs are 1-7 GB each. `MUSL_CHECK_LOG_DIR`, the ring3-mm
  oracle (`KERNEL_TEST_KEEP_LOGS=1`) and `STRESS_KEEP_ARTIFACTS=1` keep them. Eight
  parallel boots filled the 217 GB disk once; delete interrupt logs between waves.
- **Knobs.** `KERNEL_TEST_CPUS=1|2|4|8|16` (ring3-mm), `MUSL_CHECK_CPUS=1|2|4|8`,
  `STRESS_PROFILES=memory,cpu,smp STRESS_PROFILE_LIMIT=3 STRESS_KEEP_ARTIFACTS=1`.
  Stress builds include `stall_dump`: after 10 s of console silence the guest prints
  `STALL-DUMP` lines with task and per-CPU queue state.
- **Verdicts.** make reports QUALIFIED as exit 2/3. The generic boot classifier marks
  ring3-mm FAIL because of its deliberate faults; the oracle's own verdict decides.
- **Pins.** The hosted gate pins exact counts (kernel-core 90, mitigation filtered 90,
  mm 30, ipc-robust 4/18; 468 total). Adding a test means updating
  `scripts/tools/hosted_subcrate_tests.sh`, the `make help` text and the README.
- **Gate fixtures.** `scripts/tests/test_outcome_callers_test.py` mirrors the musl gate's
  required markers; add a marker there whenever `musl_check.sh` requires a new one.
  Host parsers for guest markers (`stress_protocol.py`, the syz executor parser) read
  markers only at the start of a line.
- **Local tooling.** The stress self-tests need Python 3.10 (run them on the host). Check
  Linux-target hosted code locally with `cargo +nightly-2025-12-08 check --target
  x86_64-unknown-linux-gnu --features host_harness --lib --tests` from the repository
  root, not from `kernel/` (whose cargo config forces `build-std`).
- **Kept artifacts.** Soak artifacts `/tmp/nilix-stress-v2.ZtePvW3j` (g60) and
  `.fnmqZjYc` (g63), the F11 stall dumps in `.wBEfSfdq`, `.dfjuWNoz` and `.Ropriken`,
  and the F13 bisect logs `/tmp/g56{r,q,p}-*`. The bisect trees `/tmp/nilix-gap56-1017b`
  to `1017i` can be deleted.

## 5. Acceptance and amendment record

| Date | Change |
| --- | --- |
| 2026-10-20 | Steps 2, 3 and parts of 5 executed; step 1 waived by the user (R190 full-tree audit). Superseded by [next-handoff-2026-10-20](next-handoff-2026-10-20.md). |
| 2026-10-17 | Handoff written after the GAP-5/6 series landed on `main`. The first CI run on `fec4178` failed two jobs: the quality harness test still fed `musl_check.sh` a guest log without `MUSL-PTHREAD-OK`, and the qemu-fuzz executor gate rejected its run because F12 removed the page-fault trace that used to end the shell-prompt line, leaving `NILIX_SYZ_V2_BEGIN` behind the prompt. Both are fixed in `bd487f0`, verified on nilix-dev before the push. |
