# ST-K3 — waitid, ROOT-INIT, F2 and Ring-3 lifecycle oracles

**Date:** 2026-09-25
**Status:** IMPLEMENTED for the scope below; hosted and guest oracles pass on
x86_64 Linux. Independent high-risk review of the changed kernel paths is still
pending, so this is verification-complete, not review-accepted.
**Plan section:** kernel gap plan §4 (process lifecycle, PID1, waiting), with
Ring-3 memory evidence for §3.
**Design rule:** Safety > Correctness > Efficiency > Performance.

This record replaces the §4 design sketch with what was actually built and
what actually executed. Line numbers refer to the tree this record is
committed with.

## 1. Scope

| Item | Before | After |
| --- | --- | --- |
| `waitid(2)` (syscall 247) | `ENOSYS` stub | Implemented for `P_ALL`/`P_PID`, `WEXITED`, `WNOHANG`, `WNOWAIT`, `siginfo_t` copyout |
| ROOT-INIT | Root namespace init never registered; orphan fallback trusted the bare constant `ROOT_INIT_PID = 1` | Root init registered through the normal PID chain; fallback resolves the registered, identity-checked init |
| F2 | A Ring-3 parent with no active syscall frame fell into the kernel-stack resume path | Refused with `ForkError::InvalidUserFrame` → `EFAULT` before publication |
| Syscall census | 247 dispatched but listed in `INTENTIONAL_UNDISPATCHED` | 247 in `DISPATCHED_PROMISED`; `MAX_EXEMPT` 8 → 7 |
| Hosted count pins | `kernel-core 73`, `mitigation-mappings 3/73`, Makefile help "169 tests" | `79`, `3/79`, "454 tests" — the numbers the gate enforces |

Out of scope and still fail-closed: `P_PGID`, `WUNTRACED`/`WCONTINUED` (this
kernel records no parent-visible stop/continue event), PID1 exit, reaper
races, and clone thread sharing.

## 2. waitid design

### 2.1 One reap engine

`sys_wait4` (`kernel/kernel_core/syscall.rs:7595`) and `sys_waitid` (`:23270`)
share `wait_reap_core` (`:7661`), extracted from the former wait4 body rather
than duplicated. The lost-wakeup protocol — publish `Blocked` and
`waiting_child` *before* scanning children, restore `Ready` on every exit edge
— therefore has one implementation. Two divergent copies of that protocol
would be the most likely place for a future lost wakeup.

The engine is parameterised by:

* `WaitTarget` (`:7633`) — `Any` or `Pid(n)`, where `n` is the pid in the
  caller's namespace;
* `nohang` / `nowait` flags;
* a `publish` closure that writes the caller's ABI: a packed `c_int` wstatus
  for wait4, a 128-byte `siginfo_t` for waitid.

### 2.2 Publication before commit

`publish` runs after a reapable zombie is selected and before it is unlinked
or passed to `cleanup_zombie`. If the copyout faults, the engine restores
`Ready`, clears `waiting_child` and returns `EFAULT` with the zombie still
reapable — the Linux contract, and the property the guest leg checks.

`WNOWAIT` (`:7885`) returns after `publish` without unlinking or cleaning up;
only the parent's own wait state is undone.

### 2.3 Argument contract

`waitid_validate_args` (`:23227`) is a pure function, extracted so the hosted
oracle drives the shipping code rather than a copy. It runs before any process
state is read:

* unknown option bits → `EINVAL`;
* `WUNTRACED`/`WCONTINUED` → `EINVAL`. Accepting them would promise a
  notification this kernel can never deliver and hang the caller. wait4 keeps
  ignoring them for backward compatibility only;
* `WEXITED` is required;
* `P_PID` with `id <= 0`, `P_PGID`, and unknown idtypes → `EINVAL`. `P_PGID` is
  refused rather than widened to "any child" because process-group membership
  is not a tracked relation.

With no children at all, the engine returns `ECHILD` even under `WNOHANG`: its
no-children check precedes the non-blocking branch.

### 2.4 siginfo_t

`waitid_encode_siginfo` (`:23256`) always produces the full 128 bytes, so no
stale user bytes survive in the padding or union tail. Fields: `si_signo =
SIGCHLD`, `si_code = CLD_EXITED`, `si_pid` (namespace pid), `si_uid`,
`si_status` (the raw exit code, not the packed wstatus). The nothing-ready
answer is fully zeroed so callers can test `si_pid == 0`.

`si_uid` is read with `try_read`, falling back to 0 on contention: a blocking
credential read while the wait path holds process state could deadlock
against a writer.

## 3. ROOT-INIT

`assign_pid_chain` already registered init for child namespaces but skipped
the root arm, so the root namespace never had a registered init.
`reparent_orphans` then fell back to the numeric constant `ROOT_INIT_PID`.

The root arm is now registered too (`kernel/kernel_core/pid_namespace.rs:1499`),
and `reparent_orphans` STEP 3 (`kernel/kernel_core/process.rs:9602`) resolves
its fallback from `ROOT_PID_NAMESPACE.init_global_pid()`, using the constant
only before pid 1 exists. The registration is identity-checked and cleared on
detach, so it cannot name a recycled pid; the constant can.

Two deliberate asymmetries:

* Root registration is best-effort (`let _ = set_init(..)`). Failing an entire
  PID allocation on `InitAlreadySet` would be strictly worse than keeping the
  existing mapping.
* Root is exempt from the init-death cascade (`handle_namespace_init_death`
  skips `is_root()`), so registering it starts no kill cascade.

An absent or Zombie root init takes `reparent_logged_leak` — a deterministic
ppid plus a logged leak — never a panic on the teardown path. This removes the
former `debug_assert!(false, "ROOT_INIT_PID must be a live reaper ...")`.

## 4. F2

`fork_inner` has two resume models. A Ring-3 parent inside a syscall resumes
the child at the syscall return point with the parent's user frame. A
kernel-context parent resumes the child from a rebased copy of its kernel
stack. The second arm used to be reached by *any* parent whose syscall-frame
window was absent, including a Ring-3 one, rebuilding the kernel-rsp-under-user
-selectors chimera that faults with `ud2` in `switch_to_user`.

The arm now requires `kernel_stack_resume_is_admissible(parent.memory_space)`
(`kernel/kernel_core/fork.rs:520`, used at `:660`), i.e. `memory_space == 0`,
this kernel's existing kernel-thread test. It is read from the PCB rather than
inferred from the frame window: the caller reached this arm *because* the
window was absent, so the window cannot also be the evidence. A user parent is
refused with `InvalidUserFrame` → `EFAULT`. `EFAULT` rather than
`ENOMEM`/`EAGAIN` is intentional; no retry can supply a missing frame.

The refusal precedes publication. `fork::sys_fork` (`fork.rs:289-302`) routes
every `fork_inner` error through child-link removal, cgroup detach, the
scheduler-permit drop and `cleanup_partial_child`.

## 5. Census and count pins

Syscall 247 had a live dispatch arm (`syscall.rs:4368`) while still listed in
`INTENTIONAL_UNDISPATCHED` as "dispatch deferred". The pledge parity oracle's
XOR check does not catch this — absent-from-dispatched plus present-in-exempt
still partitions cleanly — so the gate passed while documenting a pledged PROC
sandbox's `waitid` as `ENOSYS`. 247 now sits in `DISPATCHED_PROMISED`
(`:10317`) and `MAX_EXEMPT` drops to 7 (`:10356`), as that constant's comment
requires of every slice.

The hosted gate is exact-count. The six new kernel-core tests move
`run_suite kernel-core` 73 → 79, and `mitigation-mappings` filters the same
pool, so its `filtered out` count moves 73 → 79 as well. The previous run had
bumped only the first pin; the full script caught the second. The gate's own
summary line reports 454 (435 from `run_suite` plus 19 from
`run_standalone_rust_suite`); earlier prose carried 169, 433, 435, 438 and 439.

## 6. Oracles

### 6.1 Hosted (`make test-hosted-subcrates`)

* `st_k3_waitid_oracle_tests` (`syscall.rs:23527`) — selector resolution,
  option contract, `siginfo_t` field offsets, and both zeroing invariants.
* `f2_frameless_fork_tests` (`fork.rs:470`) — the predicate only. `fork_inner`
  needs a live address space that no hosted fixture provides.

These cannot compile on macOS/arm64 (the `drivers` crate uses x86-only inline
asm), so they run on x86_64 Linux.

### 6.2 Guest (`make test-ring3-mm`)

The fixture `userspace/src/syscall_test.rs` boots as root-namespace PID 1.
Four legs were added, each a named entry in the `ring3_mm_oracle.sh` leg
contract so removing or renaming one fails the gate. Every fork is reaped on
every failure path so a broken sub-check cannot leak a zombie into later legs.

| Leg | What it proves |
| --- | --- |
| `test_waitid` (`:1182`) | Six malformed shapes → `EINVAL`; `ECHILD` with no children under `WNOHANG`; a `WNOWAIT` peek writes `SIGCHLD`/`CLD_EXITED`/pid/`si_status=42` into a poisoned Ring-3 buffer; a faulting `infop` → `EFAULT`; the zombie survives both and a plain `WEXITED` wait still reaps it; a second reap → `ECHILD`; the tail past `si_status` reads zero; `P_ALL` reaps a second child with status 7 |
| `test_root_init_reparent` (`:1354`) | PID 1 forks a middle process that forks a grandchild and exits. PID 1 must reap the grandchild *by pid* — possible only with a real `children` link, not merely a `ppid` write — and the grandchild's exit code reports `getppid()` became 1. Skips, rather than passes, if the fixture is not PID 1 |
| `test_fork_pids_refusal` (`:1520`) | Four forks against `pids.max = 1` each return `EAGAIN`; `nr_tasks` is unchanged; nothing is reapable; the next fork after leaving the cgroup gets the next PID, so refusals consumed none |
| `test_user_stack_guard` (`:1677`) | With a fixed stack window, the lowest lazy page (`0x7fffffdff000`) demand-grows; writes at both ends of the guard page each kill the child with exit 139. Probing both ends catches an off-by-one that maps only the guard's top. Fails instead of probing if the fixture's own frame is outside the expected window |

A guard fault prints only `[PF ENTRY]` and takes the `USER_MODE` terminate
path, never the `[PAGE FAULT]` kernel branch, so the gate's `FATAL` regex is
not tripped.

## 7. Evidence (2026-09-25, x86_64 Linux, `nightly-2025-12-08`)

| Execution | Result |
| --- | --- |
| `cargo fmt --all -- --check`, `cargo clippy -p kernel_core --target x86_64-unknown-none` | Clean. Four remaining Clippy warnings are pre-existing, in `virtio`, `mm`, `net` and `fork.rs`, none in changed code |
| `make test-hosted-subcrates` | Exit 0, `454 unit tests`, 3 compile checks. kernel-core `79 passed; 0 failed` |
| `make build` | Exit 0 |
| `make test` | QUALIFIED, `passed=35 deferred=39 failed=0`; Ring-3 init exits 0. QUALIFIED comes from deferrals, not failures |
| `make test-ring3-mm` | `RING3-MM OK`, exit 0, `Results: 17 passed, 0 failed`, 30 `[PASS]` / 1 permitted `[SKIP]` / 0 `[FAIL]`, zero `FATAL` regex hits |

The first ROOT-INIT run failed (grandchild exit 93, "never orphaned") on a race
in the test, not the kernel: the grandchild sampled `getppid()` to learn its
original parent, and when scheduled after the middle process had exited that
sample was already 1. The middle process now records its own pid before
forking and the grandchild compares against it.

Two harness faults in the remote staging were environmental: a stray ancestor
`Cargo.toml` shadowing the real workspace, and `cargo` missing from the
non-login `PATH` inherited by `make`. The `kernel-tests` compile check also
needs the tracked guest ELF fixtures (`kernel/src/*.elf`) present.

## 8. Remaining limits

* **Independent high-risk review** of `wait_reap_core`, the ROOT-INIT
  registration and the F2 arm has not been done.
* **PID1 exit** cannot run in this fixture, which is itself PID 1.
* **Reaper races** and the **attach-time and fd-charge rollback** paths are not
  exercised. With one task in the cgroup, `check_fork_allowed` refuses before
  `attach_task`, so the fork-refusal leg covers the attach-time rollback only
  indirectly.
* **F2's refusal ordering** in a live fork is read from the source, not
  executed; only the predicate is tested.
* **Placeholder runtime cases.** `r23_1_cow_tlb_shootdown`,
  `r174_b4_brk_va_reservation_toctou` and `m0_7_stack_guard_page` in
  `kernel/src/runtime_tests/regression_tests_p0.rs` return `Deferred` on every
  path. The COW shootdown case changes only its deferral message on multiple
  CPUs, so a multi-core run does not verify it. Stack-guard behaviour is
  covered by the Ring-3 leg above; the other two are unverified.
