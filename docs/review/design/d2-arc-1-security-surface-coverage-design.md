# D2-ARC-1 - Declared-vs-Enforced Security Surface Coverage Design

**Date:** 2026-10-18
**Plan item / Finding:** D2-ARC-1 with R190-1 (HIGH), R190-4 (MEDIUM) and R190-10 (LOW) from [qa-2026-10-18.md](../audits/qa-2026-10-18.md)
**Status:** IMPLEMENTED (pending R190 review-fix). Code is applied. Two independent review lenses ran, plus a re-review of each repair, ending with a dispatcher-gate SAFE verdict and the last census gap repaired. Final-tree remote gates pass: build, lint, fmt, clippy, hosted 480 (including `lsm-hook-census` 3/3), musl and Ring-3 OK; runtime, boot and 4-core SMP are zero-failure QUALIFIED, the same as baseline. See the [R190 fix summary](../fixes/R190-fix-summary.md) §5.1. Stage-3 review-fix has not run.
**Scope and authorization:** the user asked on 2026-10-18 to fix all findings in the R190 audit (kernel-security-audit-fix stage).
**Designed by:** stage-2 fix, Claude (MODE S). This record was written during the repair, alongside the implementation, not before it. No earlier design existed, and none is backdated.
**Amendment mode:** normal
**Sources:** `main @ 427de57` plus the R190 working-tree diff.

## 1. Requirement and Threat Model

The LSM is the kernel's MAC layer. Two failure modes matter:

- A declared hook family with no caller. The policy appears to cover the surface while the kernel never consults it, and nothing alarms at compile time or runtime.
- A security-relevant API with no authorization layer at all (cpuset management), left to a future wrapper.

The attacker is an unprivileged local task, or a remote peer for the network control plane. Invariants:

- **INV-SEC-02:** every `pub fn hook_*` has a production caller, or is listed as feature-absent with the boundary that keeps its feature unreachable.
- **INV-SEC-03:** no policy documents enforcement for a dormant hook family.
- **New:** host-global isolation primitives require a privilege proof by construction.

## 2. Current-State Analysis (427de57)

- 54 `pub fn hook_*` exist in `kernel/lsm/lib.rs`. A comment-aware census finds 20 with no production caller. The audit's text grep counted 19, because comments mention `hook_kpatch_load`.
- **Live surfaces with an unwired hook:**
  - `pipe`/`pipe2` (via `ipc::pipe_create_callback`) and `futex` (syscall 202) had no `hook_ipc_pipe`/`hook_ipc_futex` call.
  - The network control plane (ARP learn and reply in `net/src/arp.rs`; ICMP echo reply and firewall-REJECT unreachable in `net/src/stack.rs`) bypasses the socket layer, and `hook_net_control` (R62-7) had never been called. RX is wired today through the process-context deferred drain.
  - VFS path resolution (`vfs/path.rs::resolve`) consulted DAC search permission but never `hook_file_lookup`.
- **Dormant surfaces:**
  - No syscall reaches IPC endpoint send/receive.
  - shm, setsockopt/getsockopt, ptrace and the setuid/setgid families have no dispatch arm.
  - chmod/fchmod (EOPNOTSUPP), chown/fchown/lchown (ENOSYS) and link (EPERM) are fixed-errno stubs.
  - File-backed mmap returns EOPNOTSUPP.
  - Livepatch has `SUPPORTED=false` and no production `KernelOps` implementor; the KernelOps defaults deny.
- `SecureBaselinePolicy` documented livepatch as "LIVE TODAY via the livepatch ops delegation". That was false: no delegation exists.
- `sched::cpuset::{cpuset_create, cpuset_destroy, cpuset_set_cpus}` were bare `pub fn`s with no privilege check. Only runtime tests call them.
- `cap_revoke_with_lsm` had no caller, and `CapTable::delegate` has no production caller.

## 3. Blast Radius

The hook calls sit in four places:

- kernel_core (`sys_futex`)
- ipc (`pipe_create_callback`)
- net (`process_arp`, `process_icmp`, `apply_firewall_verdict`)
- vfs (`path::resolve`, which every path-based operation uses)

The cpuset API signatures change: the management functions now take `&CpusetAdmin`. Their only callers are the runtime tests, which were updated.

Policy behavior today:

- PermissivePolicy and `SECURE_BASELINE` (the only policies ever installed) allow every newly wired hook, so default behavior is unchanged.
- `DenyAllPolicy` (test only) now also denies pipe creation, futex calls, path lookups, the ARP/ICMP control plane and cpuset management.

New errnos on denial:

- pipe and futex: EPERM
- lookup: EACCES (`FsError::PermDenied`)
- ARP: dropped as `ArpError::PolicyDenied`
- ICMP: dropped as `DropReason::PolicyDenied`
- cpuset: EPERM (`CpusetError::PermissionDenied`)

## 4. Candidate Approaches

1. **Wire every hook.** For the dormant families there is no call site that means anything (no syscall exists). Fake call sites would make the census green while mediating nothing, which is the same dishonesty the finding is about. Rejected.
2. **Delete the dormant hooks.** This would make the census trivially clean, but it removes reviewed policy semantics (SecureBaseline setuid/ptrace) that must exist the day those syscalls land. It is also an API decision outside this repair. Rejected.
3. **Wire the live surfaces, mechanically census the rest, and bind dormant families to their exposure points (chosen).** Every reachable surface is mediated. Dormant families are listed with the boundary that keeps them dormant. Two hosted gates fail when that boundary moves: the census, and the dispatcher check on each family's syscall numbers.

For cpuset, there were three options:

- A `#[cfg]` gate would hide the API from the runtime tests that exercise it.
- A check inside a future syscall wrapper is exactly the "forget the wrapper" failure mode.
- A non-forgeable proof token required by the API itself (chosen). Authorization becomes part of the type signature.

## 5. Decision Record

- **Wired:** `hook_ipc_pipe`, `hook_ipc_futex`, `hook_net_control` (4 emitters) and `hook_file_lookup`. Each runs before the side effect it mediates.
  - The ICMP-REJECT hook runs after the ICMP rate limiter. The reviewer showed that a denying policy could otherwise be driven into unthrottled audit records.
  - ARP and ICMP pass addresses oriented like the mediated action: a learn reports the received packet, a reply reports the reply we would send.
- **`lsm::FEATURE_ABSENT_HOOKS`:** a `FeatureAbsentHook { hook, syscalls, reason }` table with 16 entries and a cap of 16. The syscall lists include the ptrace-access syscalls (310, 311, 312, 438) and the SysV/POSIX message-queue syscalls (68–71, 240–245).
- **`kernel/tests/lsm_hook_census.rs`** (hosted, std only). It fails when:
  - an unlisted hook has no production call;
  - a listed hook is referenced from production code (calls, imports and fn pointers all count);
  - a production caller of `CapTable::delegate` or the IPC endpoint API does not name its hook.

  The scanner strips comments, strings and test-only items, and skips test directories. Stripping has two modes:
  - Broad (`cfg` mentioning `test`): only for "is this hook wired".
  - Exact (`#[test]`, `#[cfg(test)]`, `#[cfg(all(.., test))]`): for dormant-hook and guarded-API use, because `cfg(not(test))` and `cfg(any(test, feature))` code ships.

  Guarded APIs count any reference except plain (non-renaming) `pub use` facade re-exports, so aliases, renaming re-exports and fn pointers are caught.
- **Kernel-core `r190_11_dispatch_parity_tests`:**
  - Each listed syscall number must have no dispatcher arm, or only a probed stub returning its pinned errno (chmod/fchmod EOPNOTSUPP, chown family ENOSYS, link EPERM). A stub that gains a real body therefore fails.
  - Every dispatcher arm must be a single integer literal calling a `sys_` handler, so or-patterns, named constants and guards cannot hide an arm.
- **`sched::cpuset::CpusetAdmin`:** requires host root or `CapRights::ADMIN`, or kernel context when there is no current task. It carries the LSM subject for the new `lsm::hook_sched_cpuset` (`cpuset_op::{CREATE, DESTROY, SET_CPUS}`; the trait default allows and `DenyAllPolicy` denies).
- **R190-10:** `cap_revoke_with_lsm` was deleted. The cap crate's documentation now states the hook obligation for a future user-initiated revoke or delegate.
- **Documentation:** `SecureBaselinePolicy` states which families are dormant. The permissive default has a threat-model statement. The VFS mount-privilege comment now matches the stricter uid-0 implementation.

## 6. Defense in Depth

- The census and the dispatcher check guard different directions. A hook gaining a caller forces removal of its table entry. A syscall arm appearing for a dormant family forces removal of the entry, and the census then forces a caller.
- `CpusetAdmin` cannot be constructed outside `authorize()`: the field is private and the type is neither Clone nor Default.
- The hook path takes no lock. `policy()` is an atomic load, and denial audit takes only `AUDIT_RING` with IRQs masked, so no new lock-order edges exist.

## 7. Implementation Plan (applied)

| File | Change |
|---|---|
| `kernel/lsm/lib.rs` | `cpuset_op`, `FeatureAbsentHook`, `FEATURE_ABSENT_HOOKS`, `hook_sched_cpuset`, permissive-default threat model |
| `kernel/lsm/policy.rs` | `sched_cpuset` trait method (allow), `DenyAllPolicy` deny, SecureBaseline documentation |
| `kernel/ipc/lib.rs` | `hook_ipc_pipe` before any pipe/cap/fd is created |
| `kernel/kernel_core/syscall.rs` | `hook_ipc_futex` after validation; parity-list correction and dispatcher test; `cap_revoke_with_lsm` deleted |
| `kernel/net/src/arp.rs`, `stack.rs` | `hook_net_control` at learn/reply/echo/REJECT; `ArpError::PolicyDenied`, `DropReason::PolicyDenied` |
| `kernel/vfs/path.rs`, `manager.rs` | `hook_file_lookup` per component (`hash_path` made `pub(crate)`) |
| `kernel/sched/cpuset.rs`, `lib.rs`, `Cargo.toml` | `CpusetAdmin`, mediated management API, `lsm` dependency |
| `kernel/src/runtime_tests.rs` | cpuset test obtains `CpusetAdmin` |
| `kernel/cap/lib.rs` | revoke/delegate hook obligation documentation |
| `kernel/tests/lsm_hook_census.rs`, hosted script | new gate `lsm-hook-census` (3 tests) |

## 8. Test and Verification Plan

- **Census (3 tests).** Mutation-checked locally against a scratch tree. Each of these fails the gate:
  - removing a single-line or multi-line table entry;
  - deleting the futex hook call;
  - adding a fn-pointer reference to `hook_ptrace`;
  - adding an unguarded `receive_message` call.
- **Kernel-core dispatcher parity test.** Parses the real dispatcher, probes the fixed-errno stubs, and runs the boot parity self-test.
- **Runtime `cpuset_isolation` test** (boot, kernel context).
- **Gates:** build, lint, clippy, hosted (480), runtime, boot, SMP and musl, run on the final tree (see the fix summary).
- **Independent review:** two lenses (concurrency; security/ABI/resource), then a re-review of the repairs.

## 9. Open Questions and Limitations

- The census counts one call site as wired. Per-emitter completeness (for example, a new ICMP emitter that skips `hook_net_control`) is a review responsibility.
- The guarded-API hook requirement is file-granular. New wrappers defined inside an API's own file are not themselves guarded.
- Test-named files compiled into the kernel (`src/usermode_test.rs`, `src/integration_test.rs`, `src/test_framework.rs`, `src/runtime_tests/`, `security/tests.rs`) are not scanned. They run in kernel context, not from syscalls.
- The dispatcher check parses only the `syscall_dispatcher` match. A fast path added before the match (`if syscall_num == N { .. }`) would sit outside it. None exists: the code before the match uses `syscall_num` only for the signal, seccomp and LSM checks.
- `hook_file_mmap` and the livepatch families have no syscall numbers. Their boundaries (the `fd >= 0` check inside `sys_mmap`; `SUPPORTED=false` plus the KernelOps default-deny) are documented, not mechanically gated.
- Calls to a wired hook through a fn-pointer alias are not counted as calls.
- `hook_sched_cpuset` is wired into the cpuset API, whose only callers are the runtime tests. Authorization by construction is the point.
- **Surfaces with no hook family at all** were identified by the reviewer. They are outside R190-1's declared-vs-wired scope and carried as D2-ARC-1 residual leads:
  - `sched_setaffinity` (DAC only)
  - cgroup syscalls 500-516 (capability/host-root gated)
  - `/proc/<pid>/uid_map` and `gid_map` writes
  - `audit_export`, `fips_enable` and KCOV
- The pipe subject is snapshotted before the RF186 credential-authorization window. Credentials have no runtime mutator today; a future setuid must move the mediation inside `'install`.
- `hook_file_lookup` costs one SHA-256 per path component.
- The `CpusetAdmin` token is not bound to a task, so authorization must happen in the requesting task's own context.

## 10. References

- [R190 audit](../audits/qa-2026-10-18.md), [R190 fix summary](../fixes/R190-fix-summary.md)
- `kernel/tests/lsm_hook_census.rs`; `kernel/kernel_core/syscall.rs` `r190_11_dispatch_parity_tests`

## Deviation and Amendment Log

| Date | Section | Change and evidence | Safety impact | Review outcome | User decision if required |
|---|---|---|---|---|---|
| 2026-10-18 | 5, 8 | First census parsed only single-line table entries. rustfmt splits long entries, so the remote hosted gate failed with 9 false "unwired" reports. The parser is now layout-independent, with a regression assertion. | Gate correctness only | Confirmed by security reviewer; fixed tree passes | None |
| 2026-10-18 | 5, 6 | Security review found the census could stay green when a new syscall for a dormant family shipped without its hook. Added per-family syscall numbers with a dispatcher check, the any-reference rule, guarded-API callers, and test-dir and cfg stripping. | Closes the main bypass of INV-SEC-02 | Re-review requested | None |
| 2026-10-18 | 5 | ICMP-REJECT hook moved after the rate limiter; ArpReply address orientation aligned with ICMP; futex unreadable credentials return EPERM instead of ESRCH. | Throttles denial audit; consistent policy keys | Re-review: SAFE | None |
| 2026-10-18 | 5, 9 | Re-review showed, by injected code, four ways around the gates: missing ptrace-access and message-queue numbers; or-pattern or named-constant arms skipped by the parser; a stub given a real body still passing `is_err()`; `cfg(not(test))` and `cfg(any(test, ..))` code stripped from the dormant-hook and guarded-API checks; aliased API imports. Repaired: numbers added, strict arm parse, pinned stub errnos, two strip modes, reference-based guarded scan excluding `pub use`. Each injection now fails the census, re-verified locally. | Closes the reproduced bypasses of INV-SEC-02 | Repaired; final confirmation pass: dispatcher gate SAFE against 10 injected arm forms. One more census gap found: a renaming `pub use .. as alias` re-export hid the API. Repaired by keeping renaming re-exports visible, and the injection now fails. Remaining limits listed in §9 | None |
| 2026-10-22 | 5, 8, 9 | R191-3 / D4-SEC-1 ([R191 audit](../audits/qa-2026-10-22.md)): `get_robust_list` (274), added by the thread-group batch, reads another task's state but was in no hook family. It now calls `hook_ptrace(.., ptrace_op::READ)` for a target outside the caller's thread group, after the ADMIN/host-root DAC check, failing closed without a subject context. `hook_ptrace` left `FEATURE_ABSENT_HOOKS` (16 → 15 entries, census cap 15). The new `PARTIALLY_WIRED_HOOKS` table keeps 101/310/311/312/438 fenced: the dispatcher test requires each `wired` syscall's handler body to call the hook (`handler_calls`) and fences each `absent` one exactly like a feature-absent syscall. INV-SEC-05: every cross-task inspection syscall is mediated by its family or fenced. | Closes the policy-observability gap for privileged cross-group reads; no unprivileged path changed | Independent review and gates: [R191 fix summary](../fixes/R191-fix-summary.md) | None |
