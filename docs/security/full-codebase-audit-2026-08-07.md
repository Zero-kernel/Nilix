# Nilix Kernel — Standalone Full-Codebase Security Audit

**Date:** 2026-08-07
**Auditor:** Claude Code (Claude-solo orchestration + parallel adversarial verifier fleet)
**Scope:** Entire Nilix kernel tree — 26 kernel build units, 146 `.rs` files, ~205,745 LOC under `kernel/`, plus `bootloader/` (1,171 LOC), `userspace/` (~10.9k LOC), and `fuzz/`/`userspace/nilix-syz-fuzzer` (~1.9k LOC). **Full-codebase, line-by-line** — not an R-series delta audit.
**Document status:** **Standalone.** This is *not* part of the R-series audit timeline (`docs/review/audits/qa-*`), contributes *nothing* to the zero-HIGH streak, and carries *no* gate accounting. It is an independent, complete-tree security review under the binding design principle **Safety > Correctness > Efficiency > Performance** with mandatory defense-in-depth and fail-closed defaults.
**Remediation status (verified 2026-08-27):** All HIGH and MEDIUM findings and all
implementation-ready LOW/associated problem classes identified by this audit are fixed and
synchronized to `40c-devbox-ts`. The full remote build/lint/runtime/hosted ladder passes. U37-1
and U55-6 remain explicit architecture/boot-transition design work, while U29-3 is a non-live
future-feature lifecycle note; none is counted as fixed. See §13.
**Mode:** MODE S — Codex MCP and augment-context-engine-mcp were unavailable this session. The R184 false-positive guard (solo audits hit ~91% HIGH FP rate by ignoring enclosing lock scope/callers) was enforced structurally: every filed finding passed a second, independent adversarial verifier that re-read the cited code, traced callers and lock-holders, and defaulted to REFUTE.

---

## 1. Methodology

1. **Inventory.** Every `.rs` file under `kernel/`, `bootloader/`, `userspace/` was enumerated with LOC counts and grouped into **59 balanced audit units**. The largest files were split by line range so no single agent owned an unbounded slice (`syscall.rs` 21,565 LOC → 3 units; `socket.rs` 15,505 → 2; `process.rs` 10,315 → 2; `ext2.rs` 10,109 → 2).
2. **Design lens.** The 15 design documents in `docs/review/design/` (netns isolation, IOMMU domain, no-infallible-alloc-after-PONR, OOM re-entry, CPL3 entry-state, bounded scheduler, KCOV async/topology/authority/collision) were read first and attached to the relevant units, so code was judged against *stated invariants*, not just local logic.
3. **Line-by-line audit.** One reader agent per unit read its assigned files in full under the Safety-first lens (memory safety at unsafe boundaries; privilege/capability; info disclosure; resource exhaustion/DoS; concurrency/lock-ordering; input validation; ABI safety; fail-open; audit/LSM/seccomp gaps; defense-in-depth). **Every finding was required to state its caller and lock context** — the primary false-positive guard.
4. **Adversarial verification.** Each filed finding went to an independent verifier agent whose job was to **refute** it: re-read the cited code, trace the actual call sites and lock holders, check for upstream guards / fail-closed behavior / bounds checks the auditor missed, and default to REFUTED unless the bug was proven real *and reachable given the actual context*. The verifier could also adjust severity.
5. **Synthesis.** Confirmed findings were sorted by adjusted severity and grouped by subsystem for this document.

**Scale:** 257 agents (59 audit readers + per-finding verifiers), 3,437 tool uses, ~43 min, 0 agent errors, 0 empty results.

---

## 2. Executive Summary

| Severity | Confirmed | Notes |
|---|---:|---|
| CRITICAL | **0** | No release-blocking memory-corruption or direct privilege-escalation-to-root primitives found. |
| HIGH | **3** | One fail-open resource-accounting leak (U06-1); one signal-handler RFLAGS/ABI contract violation (U09-1); one missing robust-futex death-release (U34-1). |
| MEDIUM | **24** | Fail-open security gates, namespace isolation gaps, OOM-abort classes, confused-deputy VFS, ACPI/ELF input-validation, defense-in-depth gaps. |
| LOW | **101** | Dominated by `debug_assert!`-where-runtime-check-needed, dead test oracles, and single-layer defenses. |
| NONE (informational) | **3** | Real but unreachable / fail-closed-by-design / impact dominated by another finding. |
| **Total confirmed** | **131** | |
| Filed then refuted | 67 | 34% refutation rate — the verify pass earned its keep. |
| Uncertain | 0 | |

**Headline assessment.** Across 205k LOC the kernel is **substantially sound and heavily hardened** — the design-doc invariants (netns TX token gate, OOM try-lock/streaming resolution, CPL3 entry-state GS contract, bounded scheduler, KCOV async rejection) are largely upheld in code, and the recent R187 KCOV work (units U03/U47/U49) re-verified **clean** against its four design docs. The 3 HIGHs are isolated: a cgroup port-uncharge leak that defeats the delete-gate it exists to protect, a signal-delivery RFLAGS mask that contradicts the kernel's own SysV handler-entry contract, and a missing robust-futex exit walk (a gap the roadmap itself acknowledges). **No CRITICAL** and no broad memory-corruption class surfaced — consistent with the mature, audit-driven state of the tree.

**Two findings bear directly on the open 1.0-Preview gate** (R186-4 / `D1-RES-HEAP-ADMISSION-REOPENED`) and are flagged for cross-checking in §9: U23-1 and U23-2 allege the R186-4 commit-panic→error conversion is partly dead code and partly incomplete on sibling `AdmittedDeque`/`AdmittedMap` paths. These are verifier-confirmed LOWs but warrant reconciliation with the RF186 closure before the gate advances.

---

## 3. HIGH Severity Findings

### HIGH-1 · U06-1 · cgroup port-uncharge leak defeats the delete-gate (fail-open)
**File:** `kernel/kernel_core/cgroup.rs:4257-4285` · **Category:** fail-open · **Confidence:** high

`uncharge_ports` silently drops the uncharge when `CGROUP_REGISTRY` is write-contended: `try_lookup_cgroup` returns `None` and the function does `if cursor.is_none() { return; }`, with a comment claiming "next drain will retry." The claim is false. The only callers are the deferred-uncharge drain (`net/src/socket.rs:3178`) and direct close/connect-rollback teardown; the drain's `take_one()` *removes the entry from the queue before* calling `uncharge_ports`, and there is no re-enqueue path. When `try_lookup_cgroup` fails, the entry is already gone and the uncharge is lost forever.

`uncharge_ports` is documented process-context-only ("NEVER under a net-binding lock or from IRQ"), so a blocking `lookup_cgroup` would be safe and correct for every actual caller — the `try_lookup` was a misguided R173 "IRQ-safety defense-in-depth" that introduced a real leak on a non-IRQ path.

**Failure scenario.** Process P in cgroup C closes a socket while the admin concurrently runs `delete_cgroup(C')` (or `create_cgroup`), which holds `CGROUP_REGISTRY.write()` for an extended window. The drain calls `uncharge_ports(C, 1)`; `try_read()` fails; the function returns without unpinning `ports_pinned` or decrementing ancestor `ports_current`. The queue entry was already removed. Result: `ports_pinned` stays > 0 forever, so the delete-gate at `cgroup.rs:3070` refuses every later `delete_cgroup(C)` with `NotEmpty` — C is permanently un-deletable, consumes one of `MAX_CGROUPS=4096` slots, and ancestor `ports_current` stays inflated (a `ports.max` self-DoS of the surviving subtree). Each loss is permanent and cumulative; cgroup IDs are monotonic, never recycled. This is exactly the FA-04 leak class the delete-gate exists to prevent — a fail-open on a resource-accounting primitive.

**Recommended fix.** `uncharge_ports` is process-context-only, so revert the R173 `try_lookup_cgroup` to blocking `lookup_cgroup` (the IRQ-safety justification does not apply to its callers). If `try_lookup` is retained for defense-in-depth, the function MUST signal failure so the drain can re-enqueue: return `bool`, and have `drain_deferred_port_uncharges` re-enqueue (`enqueue_port_uncharge`) on contention instead of dropping the entry. Bound the retry and fall back to a blocking lookup after N tries. The silent `return;` is a fail-open on a resource primitive and must not stand.

---

### HIGH-2 · U09-1 · IRQ-return signal delivery preserves TF/DF, violating the SysV handler-entry contract
**File:** `kernel/kernel_core/syscall.rs:8938` · **Category:** correctness (ABI/memory-safety) · **Confidence:** high

The IRQ-context signal delivery path (`try_deliver_signal_on_irq_return`) computes the handler-entry RFLAGS with an ad-hoc mask `(interrupted_rflags & 0x00000DD5) | 0x00000202`. The mask `0x00000DD5 = 0b1101_1101_0101` has **bit 8 (TF, 0x100) = 1 and bit 10 (DF, 0x400) = 1**, so both flags pass through unchanged. The line's own comment ("RFLAGS: clear TF/DF, force IF=1, preserve the rest within the safe mask") directly contradicts the implemented mask. The sibling syscall-return path (`maybe_deliver_signal` Phase 3, `syscall.rs:8641`) correctly uses `signal_frame::sanitize_user_rflags`, whose mask `RFLAGS_SANITIZE_AND = 0xFFFF_FFFF_FFE2_CFFF & !0x100 & !0x400` explicitly clears TF and DF — so the two delivery paths disagree bit-for-bit. `signal_frame.rs:89-93` documents the load-bearing invariant: *"a freshly-entered SysV handler requires DF=0, and TF must never be force-set into a handler."*

**Failure scenario.** A user process executes `STD` (sets DF=1), then receives a signal (via `kill(2)`) while in pure userspace. Delivery happens on the next timer-IRQ return (not the syscall path). The handler is entered with DF=1 still set; any `rep movsb/stosb/cmpsb` in the handler or its libc trampoline that runs before an explicit `CLD` operates in the wrong direction, writing/comparing memory *before* the destination buffer — a user-mode memory-safety violation for raw (non-libc) handlers that rely on the SysV ABI guarantee. Likewise, if the interrupted context had TF=1 (single-step via `popfq` in Ring 3 or `ptrace` `PTRACE_SINGLESTEP`), the handler enters single-stepping, firing `#DB` on every instruction and terminating it via `SIGTRAP` before the user's logic runs. glibc/musl trampolines `CLD` early, limiting but not eliminating blast radius.

**Recommended fix.** Replace the ad-hoc mask with the single shared sanitizer so both paths agree bit-for-bit: `let new_rflags = crate::signal_frame::sanitize_user_rflags(interrupted_rflags);` Add a self-test (mirroring `signal_frame::selftest_mxcsr_and_rflags`) asserting a dirty input (`IOPL|TF|DF|CF`) yields IF=1 with TF/DF/IOPL cleared. Defense-in-depth: assert `(rflags & (0x100|0x400)) == 0` before redirecting in the IRQ path, deferring delivery (fail-closed) if not.

---

### HIGH-3 · U34-1 · robust-futex death-release walk is missing (permanent deadlock)
**File:** `kernel/ipc/futex.rs:1147-1366` (exit path); `syscall.rs:7721-7756` (registration) · **Category:** correctness (liveness) · **Confidence:** high

`sys_set_robust_list` stores `robust_list_head` and it is zeroed on fork (`fork.rs:760`), but **no exit path ever walks it**. `cleanup_process_futexes` releases only futexes where the kernel recorded the owner via `FUTEX_LOCK_PI` (`b.owner == Some(pid)`). Linux's robust-futex contract is that a thread can hold a robust mutex acquired purely with a userspace `cmpxchg` (no `FUTEX_LOCK_PI` syscall) — the kernel has *no* owner record for such locks, and the `robust_list_head` linked list is the *only* mechanism by which the kernel discovers and releases them on thread death (set `FUTEX_OWNER_DIED` in the user word, wake one waiter). A repo-wide grep for `robust_list_head|OWNER_DIED|walk.*robust` returns only storage sites. The existing `owner_dead`/`OwnerDied` plumbing fires only for kernel-tracked PI owners, so non-PI robust mutexes (the common glibc/NPTL `PTHREAD_MUTEX_ROBUST_NP` default) get no death release. The roadmap itself documents this gap (`docs/roadmap.md:289`).

**Failure scenario.** A multi-threaded process uses a non-PI robust pthread mutex (`PTHREAD_MUTEX_ROBUST_NP`). T1 acquires it via userspace `cmpxchg` and registers it via `sys_set_robust_list`. T1 crashes or is killed while holding it. `cleanup_process_futexes` runs, but since the kernel never recorded T1 as owner, the owner-transfer phase never matches. The `robust_list_head` walk that should discover the held lock and set `FUTEX_OWNER_DIED` does not exist. T2 then `FUTEX_WAIT`s and blocks forever — the mutex is permanently lost. This is exactly the deadlock robust futexes exist to prevent; musl/glibc programs relying on it will hang.

**Recommended fix.** Implement `exit_robust_futexes(pid, tgid, generation)` from `cleanup_process_futexes` (or the reaper before the TGID unlink). It must: (1) read the user `robust_list_head {list, futex_offset, list_op_pending}` via fault-tolerant usercopy, aborting the whole walk on `EFAULT` (fail-closed; Linux also stops); (2) bound the walk to a fixed count (e.g. 256) to prevent a malicious ring/long list DoS, also bounded by the per-TGID bucket budget; (3) for each entry, compute the futex word address `= entry_ptr - futex_offset`, validate 4-byte alignment and user-accessible mapping, atomically read the word, check the low 30 bits hold the owner TID — if so, atomically set bit 31 (`FUTEX_OWNER_DIED`) and clear the TID, then call a `futex.rs` release helper that marks the matching bucket `owner_dead=true` and wakes one waiter, mirroring the PI death path at `futex.rs:1310-1339`; (4) honor `list_op_pending` for the pending-acquire entry. The `robust_list_head` field, the registration syscall, and the `owner_dead` machinery are all already in place — only the walk and release helper are missing.

---

## 4. MEDIUM Severity Findings (24)

### MED-1 · U01-1 · LSM syscall-entry gate fails open on missing context
`kernel/kernel_core/syscall.rs:3852-3870` · fail-open · medium confidence

`lsm_ctx = SyscallCtx::from_current(...)` is guarded only by `debug_assert!` (a no-op in release); the dispatch gate is `if let Some(ref ctx) = lsm_ctx { ... hook_syscall_enter ... }`, so when `lsm_ctx` is `None` the entire LSM enter/exit check is skipped and the syscall executes ungated. `current_credentials()` uses `try_read()` on the credential RwLock; in an SMP multithreaded process, a `setuid`/`setgid` on thread A holding the write lock concurrent with a sibling thread B entering a syscall makes `try_read()` fail → `lsm_ctx` `None` → MAC gate skipped in release. The `lsm` feature is on and strict policies (`DenyAllPolicy`) exist, so this is a real enforcement point. **Fix:** when `lsm_ctx.is_none()` for a user syscall, emit an audit `Error` and return `EPERM` (or `ESRCH` if `current_pid()` is `None`) without dispatching; keep `debug_assert!` as the tripwire. (See also LOW U42-1 — the same gap from the LSM side — and LOW U42-3, exit hooks missing denial audit.)

### MED-2 · U02-2 · namespace init (PID-ns) not protected from same-namespace SIGKILL
`kernel/kernel_core/syscall.rs:7804-7810`, `kernel/kernel_core/signal.rs:658` · privilege-escalation (isolation/DoS) · medium confidence

`sys_kill` and `send_signal_inner` gate only the *global* PID 1. A PID-namespace init (global PID N ≠ 1) receives no special protection beyond the POSIX UID check. The comment at `syscall.rs:7805` ("namespace PID 1 is protected within that namespace") is false — it checks the *global* PID. Linux semantics: a PID-ns init can only be signaled by its parent-namespace process or a process with `CAP_SYS_ADMIN` in an ancestor namespace, and only by signals it cannot catch. A same-namespace, same-UID process (e.g. namespace-root mapping to a shared host UID) can deliver `SIGKILL` to the namespace init, triggering the namespace-wide init-death cascade (`signal.rs:624`) that `SIGKILL`s every member — a full container-kill DoS that Linux would deny. **Fix:** in `send_signal_inner` (the single delivery choke point), when the target is the init of its PID namespace (lowest `pid_ns_chain` entry has pid==1 in that ns), reject unless the sender is in an ancestor namespace OR has `CAP_SYS_ADMIN` in an ancestor user-namespace OR is the init itself; keep `sys_kill`'s pre-check as a fast-fail.

### MED-3 · U03-1 · cgroup governance syscalls emit no audit events
`kernel/kernel_core/syscall.rs:19404-19848` · audit-gap · high confidence

`sys_cgroup_create` / `_destroy` / `_attach` / `_set_limit` are gated only by a discretionary privilege check and emit **no** `audit::emit_*` — unlike `sys_cgroup_delegate` (which emits `emit_cgroup_delegation_event` at `:19514`, proving the project considers cgroup governance audit-worthy and the primitive exists). There are also no LSM `hook_cgroup_*` hooks anywhere, so the privilege gate is the *sole* control for operations that change isolation boundaries / resource quotas. Unauthorized callers are still denied (gate fails closed); the gap is forensics/detection of misuse by trusted/delegated actors. **Fix:** emit a cgroup-governance audit event on success of all four ops (subject pid/uid/gid, target cgroup_id, op type, old/new values — `from_id->to_id` for attach read under the held Process lock at `:19654/19719`; `limit_type + old/new` for set_limit; `parent_id + new child id` for create; deleted id for destroy). Separately evaluate adding `hook_cgroup_*` LSM hooks.

### MED-4 · U08-1 · UserNamespace::new_child uses infallible Arc::new (OOM→abort)
`kernel/kernel_core/user_namespace.rs:311-344` · resource-exhaustion · high confidence

`new_child` constructs the child via `Arc::new(Self { ... })` (line 328). With `panic="abort"` and the abort-on-OOM `alloc_error_handler`, this halts the kernel on allocation failure instead of returning `ENOMEM`. `UserNsError` has no `OutOfMemory` variant, so the syscall handler's `ENOMEM` branch (`syscall.rs:5131`) is dead code. This is the identical class R186-3 fixed for `net_namespace` (now `Arc::try_new` + `AdmittedMap` + reserve), but `user_namespace` was not aligned. `CLONE_NEWUSER` is explicitly *unprivileged* (`syscall.rs:4691`), so this is an unprivileged→kernel-abort path. The verifier downgraded HIGH→MEDIUM on reachability: the net namespace is created *before* the user namespace in the clone sequence and is now guarded, so once its budget is exhausted the clone fails at the net step; and a user-ns footprint is tiny (~150 B), so standalone exploitation requires the global heap already near exhaustion. **Fix:** mirror net_namespace: add `UserNsError::OutOfMemory`, `try_reserve_heap(HeapClass::CoreProcess, arc_charge_bytes::<UserNamespace>())`, `Arc::try_new`, commit `NsCountGuard` only after Arc success.

### MED-5 · U08-2 · IpcNamespace::new_child uses infallible Arc::new (OOM→abort)
`kernel/kernel_core/ipc_namespace.rs:219-248` · resource-exhaustion · high confidence

Same class as MED-4. `new_child` uses `Arc::new` (line 236); `IpcNsError` has no `OutOfMemory` variant; the R77-5 `NsCountGuard` rollback is defeated because abort does not unwind. `mount_namespace` (`Arc::try_new`, `:203`) and `net_namespace` (R186-3) already do this fallibly; `ipc_namespace` was not aligned. `CLONE_NEWIPC` requires `CAP_SYS_ADMIN`/host-root, so this is a privileged path (reduces blast radius). **Fix:** add `IpcNsError::OutOfMemory`, `try_reserve_heap(HeapClass::CoreProcess, arc_charge_bytes::<IpcNamespace>())`, `Arc::try_new`, commit guard after Arc success; map `OutOfMemory→ENOMEM`.

### MED-6 · U08-3 · User-namespace UID/GID mapping is non-functional (dead setters)
`kernel/kernel_core/user_namespace.rs:516-644` · correctness · high confidence

`set_uid_map` (`:516`) and `set_gid_map` (`:536`) are `pub` but have **zero callers** — no syscall and no procfs write handler invokes them (`vfs/procfs.rs` has no `uid_map`/`gid_map` write path). Child user namespaces are born with empty maps and stay that way, so `map_uid_from_ns`/`map_gid_from_ns` always return `None` for child-ns processes, which `unwrap_or` to `OVERFLOW_UID`/`OVERFLOW_GID` (nobody) at `process.rs:6817,6857,6966,6980` and `syscall.rs:7850-7857`. The "become root inside a user namespace" model documented at `user_namespace.rs:30-37` is not actually provided; `ensure_mapping_allowed` (`:567-608`) is unexercised. The failure is fail-*safe*/restrictive (unmapped uids collapse to nobody, not unintended privilege), so this is a completeness defect, not an escalation hole. **Fix:** wire `/proc/[pid]/uid_map` and `/proc/[pid]/gid_map` procfs write handlers (or a dedicated syscall) that parse extents, call the setters, and are themselves gated by `ensure_mapping_allowed`; until then, mark the feature non-functional so downstream claims don't rely on it. (See MED-2: this also weakens the namespace-init protection, since same-ns same-host-UID peers pass the POSIX check.)

### MED-7 · U15-2 · conntrack drain_ns leaks per-ns count rows
`kernel/net/src/conntrack.rs:2031-2075` · resource-exhaustion · medium confidence

`drain_ns()` removes live (non-provisional) entries for a destroyed namespace *without* decrementing `ns_entry_counts`. When `provisional_remains` is true (an egress transaction is mid-flight on one entry), the row is intentionally preserved — but the charges for the just-removed non-provisional entries are never decremented, so the row's count is inflated by N and can never return to 0 (ns ids are never reused). The global `current_entries` stat *is* decremented, so this is purely a per-ns count-map accounting divergence. Every other removal path (`remove`, `sweep`, `evict_lru_locked`, `rollback`, egress-create victim detach) correctly calls `dec_ns_entry_count`. **Failure:** a long-running container host that creates/destroys namespaces while TX is in-flight leaks one `AdmittedMap` row per destruction — unbounded over time, no global row cap. Trigger requires a narrow race (ns `Drop` landing inside the egress lock-free window while the ns holds ≥1 other live conntrack entry). **Fix:** call `dec_ns_entry_count_locked` for each removed entry inside the removal loop (acquire `ns_counts` once before the loop); the `provisional_remains` branch then leaves a row whose count equals exactly the live provisional entries, and the finalizer/rollback drives it to 0.

### MED-8 · U16-1 · global atomic serializes all fragment reassembly across namespaces
`kernel/net/src/fragment.rs:689-976` · resource-exhaustion (cross-ns DoS) · medium confidence

A single global `transaction_active: AtomicBool` serializes all `process_fragment` and the entire `cleanup_expired` sweep. An attacker flooding never-completing fragments from netns A keeps the gate contended, so fragments from netns B fail `try_transaction` and are dropped (`RateLimited`), conflated in telemetry with per-source rate-limit drops (`rate_limit_drops`). The per-ns budgets (R169-10) gate *after* the global gate, so the global gate is the first/binding bottleneck — defeating the deliberately-built per-ns isolation. `cleanup_expired` holds the gate across up to `GLOBAL_MAX_QUEUES=4096` detach-and-destroy iterations, blocking all reassembly during a mass-timeout event. The gate is non-blocking so it cannot deadlock an IRQ, but it drops work. **Fix:** make the gate per-namespace (or per-CPU) so one ns cannot deny another, with OOM-safety preserved by charging per-ns budgets before detached allocation; or keep a global gate but bound `cleanup_expired` to N queues/tick, use a distinct `TransactionBusy` drop reason (not `RateLimited`), and make per-ns budgets the primary admission gate.

### MED-9 · U17-1 · firewall lazy-init panics on OOM on the ingress packet path
`kernel/net/src/firewall.rs:638-659` · fail-open · medium confidence

`firewall_table_for_ns` is called directly from the RX ingress path (`stack.rs:728,794,1007,1105,1299,1922`). On the first packet to a namespace whose table is not yet cached, the slow path does `Arc::new(FirewallTable::new_with_rules(FirewallAction::Drop, default_rules()))` and `default_rules()` builds its vector with infallible `vec![...]` — both panic on OOM. This contradicts the crate's own fallible-publication discipline: `lib.rs::register_device` (`:345`) and `publish_probed_pci_device` (`:647`) use `Box::try_new`/`Arc::try_new` and map failure to `NetError::NoMemory`. Namespace creation is CAP-gated but does NOT pre-initialize the firewall table (lazy on first packet), so once an admin creates a namespace, any unprivileged peer sending the first IP packet during sustained heap pressure panics the kernel. The default policy is `Drop`, so the natural fail-closed behavior is to drop the packet. **Fix:** make the slow path fallible (`fn firewall_table_for_ns(ns_id) -> Option<Arc<FirewallTable>>`) with `Arc::try_new` + a fallible `default_rules_try()`; on OOM return `None` so the six `stack.rs` call sites DROP the packet (matching `FirewallAction::Drop`), or install a static const DROP-all sentinel that never allocates. Add a test injecting OOM at lazy-init asserting DROP rather than panic.

### MED-10 · U20-1 · VFS confused-deputy via string-based find_mount across symlink mount crossings
`kernel/vfs/manager.rs:1020-1022` (and `:1386,1460,1530,1658`) · correctness (integrity) · medium confidence

`lookup_symlink`/`create`/`unlink`/`symlink`/`rename` derive the operating filesystem from `find_mount(&parent_path)` (longest string-prefix match on the *original* path), while the parent inode is resolved via `lookup_path` which *follows symlinks and may cross mount boundaries*. When a symlink in the parent path resolves across a mount (e.g. `/link -> /sys`, where `/` and `/sys` are both RamFs mounts), `find_mount` returns the `/` ramfs while `parent` is the `/sys` ramfs root inode. `ramfs::downcast_inode` checks only the concrete Rust type (not the fs instance), so for same-type mounts the op proceeds using the *wrong* fs instance's `alloc_ino`/`fs_id`/bookkeeping on the right inode's children — breaking ino-uniqueness within the `/sys` tree and corrupting per-fs metadata identity. Cross-fs-type variants (e.g. `/link -> /proc`) fail *closed* with `EINVAL`. Notably `rename` already has a resolved-inode `fs_id` EXDEV check (`:1644`) whose comment acknowledges this pitfall — the other four sites were missed. Exploitation is root-gated (write+execute on the resolved parent) with no privilege escalation; impact is metadata-integrity corruption. **Fix:** make the filesystem follow the resolved inode, not the path string — add an `fs` accessor to the `Inode` trait (or carry the owning `Arc<dyn FileSystem>` on lookup results) and call the parent's own `fs` for the final op; keep `find_mount` only for initial mount selection and the EXDEV decision. Defense-in-depth: assert `fs_id() == parent.fs_id()` before the op and return `CrossDev`/`PermDenied` on mismatch.

### MED-11 · U21-1 · cgroupfs uses infallible Arc::new on runtime lookup/create (OOM→abort)
`kernel/vfs/cgroupfs.rs:405-450` (and `:246,253,311`) · resource-exhaustion · high confidence

`CgroupDirInode::lookup_child` (`:421,441`) and `CgroupFs::create` (`:311`) construct inodes with `Arc::new` rather than the admission-fallible pattern adopted by procfs (`try_new_procfs_arc`), devfs, and ramfs. R172-22 converted sibling-FS directory maps to `FallibleOrderedMap` and listed cgroupfs as a follow-on; R186-8 made cgroupfs *dirent-name* allocation fallible with the explicit rationale that "a 32-byte allocation still aborts the kernel on an exhausted heap, and unprivileged directory enumeration must return `ENOMEM`" — that rationale applies identically to the lookup-path `Arc::new` sites R186-8 did not touch. The cgroupfs root is 0o755 and `lookup_child` performs no privilege check, so an unprivileged process with `/sys/fs/cgroup` visible can trigger `Arc::new` per path component under heap pressure → kernel abort. **Fix:** introduce a cgroupfs admission helper mirroring procfs (`try_reserve_heap(HeapClass::Cgroup, arc_charge_bytes::<CgroupDirInode>())`, `Arc::try_new`, return `FsError::NoSpace`); convert all five `Arc::new` sites; `CgroupFs::new` may keep a boot-fatal `.expect` for the mount-time root, but runtime lookup/create must return `ENOSPC`.

### MED-12 · U21-2 · `cgroup.subtree_control` write is a silent success no-op (fail-open)
`kernel/vfs/cgroupfs.rs:945-950` · fail-open · high confidence

The `CtrlKind::SubtreeControl` arm of `write_content` discards `data` and returns `Ok(())` with the comment "return success (no-op since we don't have subtree_control field)". The file is *not* classified read-only (`is_readonly` does not include `SubtreeControl`, `:140`), so the VFS layer exposes it as writable; the manager's `open()` DAC admits writes for root/`CAP_SYS_ADMIN`/delegated owners; `write_at` forwards the bytes to `write_content`, which then lies about success. A delegated subtree manager writes `+memory` to enable the memory controller, then writes `memory.max` to the child — the `subtree_control` write returned success but the controller was never enabled, so the subsequent `memory.max` write is rejected with `ControllerDisabled`. Conversely `-memory` returns success while the controller stays enabled — a fail-open integrity violation that can mislead a container orchestrator into mis-sizing/mis-isolating a workload. **Fix (minimal, defense-in-depth):** classify `SubtreeControl` as read-only in `is_readonly()` (`:140`) so VFS rejects writes with `FsError::PermDenied` — fail CLOSED rather than lying. **Fix (complete):** implement the `+ctrl`/`-ctrl` grammar with CF-4 strict validation, the cgroup-v2 no-internal-constraint and subset rules, and a `cgroup::set_subtree_control` primitive that atomically updates the controller mask.

### MED-13 · U25-1 · UEFI memory-map descriptor_size not validated at two of three parse sites
`kernel/mm/memory.rs:746-807` (and `:603,661-665`) · input-validation · medium confidence

`select_region_from_bootinfo` (`:750`) and `heap_range_usable` (`:661`) only guard `descriptor_size == 0`, then cast `addr as *const EfiMemoryDescriptor` over `desc_count = size / descriptor_size` iterations. If `descriptor_size < size_of::<EfiMemoryDescriptor>()` (~40 B, align 8), the last 40-B read extends past the buffer (OOB read of adjacent boot memory); a non-8-multiple `descriptor_size` yields an unaligned `&*` deref (UB). The sibling `add_non_conventional_uefi_reservations` (`:1208`) *does* reject `descriptor_size < size_of::<EfiMemoryDescriptor>()`, proving the check is recognized but applied inconsistently. `descriptor_version` is never checked anywhere. The bootloader/firmware is TCB (an attacker controlling it already owns the kernel), so this is defense-in-depth against buggy/non-conformant firmware rather than a priv-esc primitive. **Fix:** extract a shared `validate_memory_map(map_info) -> Option<usize>` returning `desc_count`, enforcing `descriptor_size >= size_of` AND `descriptor_size % align_of == 0` AND `descriptor_version == 1`; call it at the top of all three parse sites so they cannot diverge.

### MED-14 · U31-1 · phys_slice bounds check wraps on near-u64::MAX ACPI physical address
`kernel/arch/smp.rs:1884-1890` · memory-safety · medium confidence

The guard `phys + len as u64 > MAX_PHYS_MAPPED` is plain u64 addition, which wraps in release. `phys` is read verbatim from firmware XSDT entries (`u64::from_le_bytes`, `:1862`). With `phys = 0xFFFF_FFFF_FFFF_F000` and `len = 0x2000`, `phys + len` wraps to `0x1000` ≤ `MAX_PHYS_MAPPED`, so the check passes; `virt = PHYSICAL_MEMORY_OFFSET + phys` also wraps to a non-canonical/wild address, and `core::slice::from_raw_parts(virt, len)` reads from an arbitrary kernel virtual address. The function is `pub(crate)` and consumed by `hpet.rs:323/334`, so blast radius is not limited to SMP. The file otherwise treats ACPI as untrusted (checksums, duplicate rejection, trailing-garbage rejection) — this is a gap in that contract. Only the XSDT (u64-entry) path is vulnerable (the RSDT u32 path cannot wrap). Realistic impact is a boot-time #PF/panic (DoS), not a controlled info leak, since the wrapped virt usually lands unmapped. **Fix:** `let end = phys.checked_add(len as u64)?; if end == 0 || end > MAX_PHYS_MAPPED { return None; }` and apply `checked_add` to the `PHYSICAL_MEMORY_OFFSET + phys` computation; mirror in `hpet.rs`.

### MED-15 · U31-3 · RSDT/XSDT entry-count arithmetic underflows on sub-header length
`kernel/arch/smp.rs:1830-1869` · input-validation · high confidence

`find_table_rsdt`/`find_table_xsdt` compute `entries = (total_len - size_of::<SdtHeader>()) / 4` (resp. `/8`) directly from the firmware `header.length` with no minimum-length check. A malformed RSDT/XSDT with `length < 36` (but a matching signature, since `read_sdt_header` reads 36 B unconditionally) makes the subtraction underflow to ~`u64::MAX` in release; the first loop iteration slices `body[36..40]` against a 20-byte body → panic → boot halt (panic=abort). The peer parsers already guard this: `parse_madt` (`:1670`) checks `total_len < size_of::<Madt>()` and `hpet.rs:329` checks `total_len < size_of::<HpetTable>()`. The malformed-MADT polarity is fail-closed-to-BSP-only (S-3/RF180-58); the RSDT/XSDT walkers instead panic, breaking that contract. **Fix:** `if total_len < size_of::<SdtHeader>() { return None; }` and require `(total_len - size_of::<SdtHeader>()) % entry_size == 0`; return `None` on violation so `enumerate_cpus` falls back to BSP-only.

### MED-16 · U33-1 · nested-syscall SWAPGS executes before the syscall_active detector
`kernel/arch/syscall.rs:1046-1101` · defense-in-depth · low confidence (not currently reachable)

In `syscall_entry_stub`, the unconditional `swapgs` (`:1046`), `mov gs:[percpu_user_rsp], rsp` (`:1051`), `mov rsp, gs:[percpu_scratch_top]` (`:1057`), and KPTI CR3 reads all run *before* the `lock cmpxchg gs:[percpu_syscall_active]` nested-syscall detector at `:1100`. The D1-ARC-ENTRY-STATE design mandates one-SWAPGS-per-transition. A nested re-entry (an IRQ/NMI handler issuing `syscall` while a syscall is active) executes a *second* `swapgs`, flipping GS_BASE to the user's value; subsequent `gs:[percpu_*]` accesses then resolve through user-controlled GS — `mov gs:[percpu_user_rsp], rsp` writes kernel RSP to a user-chosen address (kernel→user write), `mov rsp, gs:[percpu_scratch_top]` pivots the stack. `arch_prctl(ARCH_SET_GS)` does not validate the user half (`is_canonical` accepts both halves), so a user can set GS to a canonical *kernel* address, escalating from SMAP-DoS to a kernel-memory write. The `syscall_active` guard exists precisely for this but fires too late. **Reachability:** a repo-wide grep finds *zero* `syscall` instructions in any kernel naked/inline asm, so nested re-entry is NOT currently reachable — it requires a future buggy IRQ/NMI handler or a CPU erratum. The guard is an explicitly-maintained defense-in-depth net, which is why the ordering gap is a legitimate hardening finding. **Fix:** move `cmpxchg` immediately after `swapgs; lfence`; on the reject path execute a compensating `swapgs` (restore kernel GS), set `rax = SYSCALL_NESTED_ERROR`, and jump to the common exit *without* touching `percpu_user_rsp`/`percpu_scratch_top`/`percpu_kpti_*`.

### MED-17 · U40-1 · CPUSET_REGISTRY/ROOT_CPUSET absent from lockdep inventory
`kernel/sched/lock_ordering.rs:76-142`, `kernel/sched/cpuset.rs:161-164` · audit-gap · high confidence

The 9-level lock inventory in `lock_ordering.rs` claims to document "the global lock ordering" but omits `CPUSET_REGISTRY` (spin::RwLock) and `ROOT_CPUSET` (spin::Mutex), both acquired on the scheduler hot path and both plain spin locks *not* wrapped in `LockdepMutex`, so lockdep cannot detect ordering violations involving them. `cpuset::effective_cpus` (`:366`) takes a blocking `CPUSET_REGISTRY.read()`; it is reached from `steal_one` (`enhanced_scheduler.rs:1616`) while the source CPU's `READY_QUEUE` (L3) AND a candidate PCB (L5) are held, and from `reserve_process`/`migrate_one_ready` under a PCB lock. No reverse edge exists today (no cpuset path takes a ready-queue/PCB lock, and cpuset mutations aren't wired to any syscall), so this is latent — but the safety contract is unenforceable, and a future cpuset-mutation path that takes a PCB/ready-queue lock under `CPUSET_REGISTRY.write()` would form an undocumented ABBA with no detection. **Fix:** add both locks to the inventory (Level 5 next to `CGROUP_REGISTRY`) with the non-reentrant/IRQ-reader caveats; document the L3>L5>cpuset nesting as a sanctioned exception (mirroring J2-SHARED-CORE/RF178-12) or require readers in IRQ/scheduler context to use the `try_read` path (`try_effective_cpus`, already implemented); long-term wrap `CPUSET_REGISTRY` in `LockdepMutex`/`RwLock` so the graph records edges.

### MED-18 · U43-3 · livepatch in_flight decrement delegated to signed handler (permanent slot pin)
`kernel/livepatch/lib.rs:1819-1861` · defense-in-depth · high confidence

`breakpoint_dispatch` increments `in_flight` and rewrites RIP to the *bare* handler entry — not a call, so the handler receives no `slot_index` argument and is required by comment-contract only to call `kpatch_handler_return(slot_index)` before returning. The crate never decrements `in_flight` on the dispatch path and installs no kernel return trampoline. A correctly-signed handler that forgets the call (or passes the wrong `slot_index`) leaves `in_flight > 0`; `kpatch_unload` spin-waits with a bounded `MAX_QUIESCENCE_SPINS=10_000` timeout, then returns `EBUSY` *without* freeing exec (`:1603-1610`) — fail-safe against UAF, but the slot is left permanently pinned with no admin recovery (no other reset path touches `in_flight`). `slot_index` is assigned at load as the first free slot (`:1303`), so a handler cannot reliably hardcode it at build time, making the wrong-slot failure mode plausible. Loading requires both `CAP_SYS_MODULE` and a valid ECDSA signature, so a holder already gets arbitrary kernel code execution — this is a defense-in-depth/robustness concern for the buggy-legitimate-author scenario, not an escalation. **Fix:** install a per-slot kernel return trampoline: jump to a generated stub that calls the handler, then on return performs `slot.in_flight.fetch_sub(1)` with `slot_index` baked into the stub, then jumps back to `target+1` — removing reliance on handler cooperation and the need for the handler to know its `slot_index`.

### MED-19 · U46-1 · virtio pop_used forward-jump resync orphans descriptor chains (no recovery)
`kernel/virtio/src/queue.rs:285-295` (and `block/src/virtio/blk.rs:347`) · resource-exhaustion · medium confidence

When `available > self.size` and `used_idx >= last` (forward jump), the code does `self.last_used_idx.store(used_idx, Relaxed); return None;` — silently resyncing past every entry between old `last` and `used_idx` without consulting driver-side inflight tracking (`rx_inflight`/`rx_chain_next`), so those descriptors stay `alloc_bitmap=true` and out of `free_list` forever, and their posted buffers are orphaned. The invalid-id drop at `:311-313` and the `blk.rs:347` equivalent share the pattern. Because `pop_used` only ever advances forward, the skipped entries can never be reprocessed; once `available_descs() < 2`, `replenish_rx` breaks and the RX/TX queue stalls with no runtime re-init/inflight-drain path. The used ring is device-writable DMA, so a malicious/compromised PCI device (or rogue DMA) setting `used.idx = last + size + 1` deterministically triggers the resync — precisely the adversarial threat model the codebase adopts (R44-5/R48-*). The verifier refuted the "legitimate bursty device" sub-scenario (a legitimate device can only complete entries it was given, capped below `size`), so only the malicious-device vector is real — but that vector is in-scope. **Fix:** on the forward-jump resync path, do NOT silently advance past unprocessed entries — either process entries one at a time up to `used_idx` validating each id, or signal a fatal queue error so the driver quarantines and re-inits (mirroring `reset_and_await_ack`), explicitly draining/freeing all `rx_inflight`/`tx_inflight`. The invalid-id drop should free that ring slot's chain or mark the queue fatal instead of orphaning it.

### MED-20 · U46-2 · MMIO virtio config reads skip the bounds validation R186-6 added for PCI
`kernel/virtio/src/transport.rs:350-364` (file mislabeled as queue.rs in the finding) · defense-in-depth · medium confidence

`device_config_len()` returns `None` for `MmioTransport` (it stores only `base` and `version`, never the MMIO region length), so the `if let Some(window)` bound check is skipped and the loop `*byte = read_volatile(base.add(offset + i))` trusts caller-supplied `offset`/`buf.len()` with no overflow check on `offset + i` and no extent check. R186-6 explicitly scoped its bounding fix to PCI only; the doc comment claims `read_config_bytes` is "bounded against the validated device-config window," which is true for PCI but false for MMIO. Current callers all use compile-time-constant offsets (0, 20) and small fixed buffers (6/8 B), so the gap is latent — but the public `unsafe` API is reachable by any future virtio driver. **Fix:** store the validated MMIO region length in `MmioTransport` at probe time (known when mapped) and have `device_config_len()` return it for MMIO too, applying the same `offset.checked_add(buf.len()) <= window` check; use `offset.checked_add(i)` inside the loop.

### MED-21 · U48-1 · AES-GCM attested FIPS-approved without a KAT
`kernel/compliance/lib.rs:486-511` · defense-in-depth · medium confidence

`is_algorithm_permitted` (`:502-503`) unconditionally returns `true` for `Aes128Gcm`/`Aes256Gcm` under `FipsState::Enabled`, but `run_all()` (`:597`) only chains `kat_sha256() && kat_hmac_sha256() && kat_ecdsa_p256()` — the AES-GCM KAT is explicitly deferred (comment `:594-595`). FIPS 140-3 requires each approved algorithm in use to pass a KAT before entering Approved mode; the compliance surface attests approval without verification. No internal consumer uses AES-GCM today (grep shows only the allow-list + syscall decoder reference it), so this is a latent compliance-attestation gap — but the allow-list will silently permit an unverified/broken AES-GCM the moment a consumer is wired in. **Fix (fail-closed):** return `false` for AES-GCM under `FipsState::Enabled` until a KAT exists and passes (persistent `AES_KAT_PASSED` flag); or add the AES-GCM KAT to `run_all()` and only allow it once passed. State in the doc that approval is contingent on a passing KAT.

### MED-22 · U54-1 · R173 "Defense-in-Depth Layer 4" ABI compliance suite is dead, broken code
`kernel/src/abi_compliance_tests.rs:1-296` · audit-gap · high confidence

The file is never `mod`-declared (grep finds no `mod abi_compliance` — `main.rs:92-100` omits it), so it is never compiled. Even under `#![cfg(test)]`, every test calls local `unimplemented!()` mock syscalls (lines 266-295) that shadow the `use kernel_core::syscall::*` glob, so each test panics at the first syscall call before any `assert!` runs. The real `sys_pipe2`/`sys_fcntl`/`sys_pread64`/`sys_pwrite64`/`sys_link` are never exercised. Worse, the assertions are stale/wrong: `test_pipe2_rejects_unsupported_flags` expects `Err(EINVAL)` for `O_CLOEXEC`, but the real `sys_pipe2` now correctly *accepts and handles* `O_CLOEXEC` (R173-05 proper fix), so the suite is broken-from-inception. The "Layer 4: Regression Testing" claim is genuinely unenforced. The real runtime guards are present and functional, so this is a test-coverage/audit-trail-integrity gap, not a live vulnerability — but a misleading audit trail could cause planners to rely on a non-existent safeguard. **Fix:** delete the file (and drop the R173 Layer 4 claim) OR rewrite it as a real oracle: `#[cfg(test)]`-wire it as a host unit-test module importing the real validators (not raw `sys_*`), remove the local mocks, and add it to a `cargo test` target that actually runs in CI (or fold its assertions into boot `runtime_tests`).

### MED-23 · U55-2 · bootloader LOAD-segment copy not bounded by `file_size <= mem_size` (ring-0 OOB write)
`bootloader/src/main.rs:716-751` · memory-safety · medium confidence

The LOAD-segment copy at `:749` writes `file_size` bytes into a destination whose allocation is sized solely by `mem_size` (the first loop builds `max_addr` from `virt_addr + mem_size`). `file_size` is checked only against the *source* (`file_offset + file_size <= kernel_data.len()`, `:725`), never against `mem_size` or the destination allocation. A crafted LOAD segment with `file_size > mem_size` and `file_size - mem_size ≥ 0x1000` overruns `actual_phys_base + alloc_bytes` into adjacent UEFI LOADER_DATA/pool memory. xmas-elf does not validate `p_filesz <= p_memsz`, and the bootloader performs no signature verification of `kernel.elf`, so a crafted ELF reaches this path. The verifier downgraded HIGH→MEDIUM: the cited victim memory (page tables/boot_info) is allocated *later* in boot, so the realistic victim is whatever UEFI pool memory is physically adjacent; and an attacker who can replace `kernel.elf` already controls the ring-0 kernel binary that runs next, so the OOB write does not escalate beyond what kernel-binary control already grants — the genuine residual value is defense-in-depth (a malformed ELF should fail closed, not corrupt boot memory). **Fix:** before the copy, assert `file_size <= mem_size` AND `phys_addr.checked_add(file_size) <= actual_phys_base + alloc_bytes` AND `phys_addr.checked_add(mem_size) <= actual_phys_base + alloc_bytes`; reject the ELF on any violation. Independent of the unsigned-ESP issue.

### MED-24 · U58-1 · nilix-syz-fuzzer mutator generates programs the validator rejects (self-terminates)
`userspace/nilix-syz-fuzzer/src/mutator.rs:148-175` · correctness · high confidence

`generate_random_syscall` builds syscalls from a hard-coded table (numbers 1, 2, 3, 4, 200, 201, 12), none of which appear in `program.rs`'s non-destructive allowlist (`:175-241` bails "not in the non-destructive allowlist"). The mutator also bypasses validation entirely (manipulates `program.syscalls` directly, never calls `add_syscall`/`validate`), and `mutate_integer`/`mutate_buffer` can produce `capacity==0`, `capacity>MAX_BUFFER_CAPACITY`, or buffer length>4096 — all rejected. `encode_program` calls `program.validate()` up front, so any such program makes `executor.execute` return `Err`; `main.rs:110` propagates with `?`, exiting the process. Per-iteration crash probability ~15.6%, so the fuzzer dies within a handful of iterations and never reaches sustained coverage-guided fuzzing. This is a userspace testing tool, so the impact is the fuzzer's own utility (no kernel security impact), but it renders the Phase-7 syzkaller-style fuzzer effectively non-functional. **Fix:** drive `generate_random_syscall` from the same allowlist `program.rs` exports; after every mutation call `program.validate()` and repair (clamp capacities to `1..=MAX_BUFFER_CAPACITY`, clamp buffer lengths to `1..=4096`, re-roll disallowed numbers) or discard and re-mutate — never return an unvalidated program; in `main.rs`, wrap `executor.execute`/`corpus.add`/`save_to_file` in a recover path that logs and continues (see LOW U58-2). Add a regression test asserting every `mutate()` product passes `validate()`.

---

## 5. Notable LOW Findings (elevated treatment)

101 LOWs were confirmed. Most are `debug_assert!`-where-a-runtime-check-is-needed, single-layer defenses, or dead test oracles. The following are elevated here because they are high-confidence, defense-in-depth-significant, or bear on the open gate.

### LOW · U23-1 · R186-4 commit-panic→error conversion is dead code in `commit_pair` ⚠ gate-relevant
`kernel/mm/heap_admission.rs:373-384` · correctness · high confidence

The R186-4 fix that converts commit failures from panic to a propagated error is dead code: `commit_pair` panics unconditionally on any ledger error, so `HeapReservation::commit` can never return the error the conversion was meant to surface. If accurate, this means the gate-blocking R186-4 remediation is *partly non-functional* on the commit path. **This finding is verifier-confirmed but warrants explicit reconciliation with the RF186 closure before the 1.0-Preview gate advances** — see §9.

### LOW · U23-2 · R186-4 conversion not applied to AdmittedDeque / AdmittedMap install_prepared_deferred ⚠ gate-relevant
`kernel/mm/admitted.rs:686-696` · defense-in-depth · high confidence

The R186-4 commit-panic→error conversion was applied to `AdmittedVec` and `from_sorted_vec_charged` but *not* to `AdmittedDeque` or `AdmittedMap::install_prepared_deferred`, leaving those three paths still panic-on-error. Same gate-relevance caveat as U23-1.

### LOW · U07-3 · deprecated `find_pte` reads PTE flags without PT_LOCK (R114-class, dead but live `unsafe`)
`kernel/kernel_core/fork.rs:2110-2136` · concurrency · high confidence

`find_pte` is retained as `#[allow(dead_code)]` but constructs `&'static mut PageTableEntry` references and reads PTE flags *without* `PT_LOCK` — the exact R114 class. Dead code today, but a single un-`#[allow]` removal reactivates a data race on live page tables. **Fix:** delete it (the live path uses the locked walker).

### LOW · U53-1 · kernel stack canary is a compile-time constant
`kernel/src/main.rs:1596-1604` · defense-in-depth · high confidence

`__stack_chk_guard` is a compile-time constant (`0x595e_9fbd_94fd_a766`), identical across all boots, all functions, and recoverable from the kernel binary — defeating stack canaries against any attacker who can read the image (which a high-half KASLR that is verify-only does not prevent). **Fix:** initialize it at boot from the CSPRNG (`security::rng`) before any Ring-3 entry, per-boot random.

### LOW · U52-1 · sync_safe IRQ-safety probe inline asm is unsound (`nostack, nomem` but `pushfq; pop`)
`kernel/sync_safe/lib.rs:65` · memory-safety · high confidence

The probe declares `nostack, nomem` while executing `pushfq; pop`, both of which modify RSP and read/write stack memory — an unsound asm contract violation identical to a known LLVM issue. The compiler may elide the stack frame or reorder memory accesses around it, producing a wrong IRQ-state read. **Fix:** drop `nostack, nomem` (or use `readonly`/`preserves_flags` accurately), or read RFLAGS via a `lahf`/`pushf` sequence with a correct options contract.

### LOW · U33-2 · INVPCID pcid wrappers accept u16 with no bounds check (#GP in kernel)
`kernel/tlb_ops/lib.rs:132-166` · input-validation · high confidence

INVPCID pcid-taking wrappers accept `u16` (0–65535) with no bounds check; `pcid > 4095` causes `#GP` in kernel context. **Fix:** clamp/validate `pcid <= 4095` (or the architecture max) and return an error on overflow.

### LOW · U42-3 · LSM exit hooks do not emit denial audit events
`kernel/lsm/lib.rs:617-695` · audit-gap · high confidence

`hook_syscall_exit` and `hook_task_exit` do not emit denial audit events when the policy returns `Err`, unlike every other hook in the file — a denied exit-hook decision is silently unlogged. **Fix:** emit a denial audit event on `Err` from both hooks, matching the denial→audit bridge used elsewhere.

### LOW · U38-6 · RSB stuffing documented "always true" but skipped on early-return
`kernel/security/spectre.rs:156-159` · defense-in-depth · high confidence

`MitigationStatus::rsb_stuffing_enabled` is documented "Always true — implemented unconditionally in context switch," but `context_switch_barrier` returns early (skipping the RSB fill) on some paths. **Fix:** either fill RSB unconditionally or correct the status field to reflect the actual condition.

### LOW · U34-3 · PI chain propagation truncates at depth 64 without full boost
`kernel/ipc/futex.rs:1550-1610` · defense-in-depth · high confidence

PI chain propagation silently truncates at depth 64 (`kprintln` + `break`) without fully propagating the priority boost, leaving the actual CPU holder unboosted — a priority-inversion risk on pathological chains. **Fix:** document the bound, or propagate the boost to the CPU holder before truncating; at minimum emit an audit event.

### LOW · U10-2 · R120-5 kernel-space fault_ip/fixup_ip validation is debug_assert-only
`kernel/kernel_core/exception_table.rs:54-79` · defense-in-depth · high confidence

The kernel-space address validation on computed `fault_ip`/`fixup_ip` is `debug_assert`-only, so the stated defense-in-depth check is inert in release — a corrupted exception table entry would redirect to an unchecked kernel address. **Fix:** make it a runtime check (fail-closed) in release.

### LOW · U22-3 · FileHandle::clone_box panics on allocation/admission failure
`kernel/vfs/traits.rs:659-662` · fail-open · high confidence

`FileHandle::clone_box` (the infallible `FileOps` trait method) panics via `.expect()` when its descriptor/offset allocation or admission charge fails, instead of propagating the error — a kernel abort on an OOM path. **Fix:** move the fallible work out of the infallible trait method (allocate before `clone_box`), or return a sentinel and handle at the call site.

### LOW · U59-1 · `kernel/fuzz/mock_kernel.rs` is orphaned dead code that misrepresents its reuse
`kernel/fuzz/mock_kernel.rs:1-286` · audit-gap · medium confidence

Orphaned dead code (referenced nowhere — the live mock is `fuzz/src/mock_kernel.rs`) whose module doc comment falsely claims to reuse real kernel syscall/validation logic while reimplementing every syscall arg. **Fix:** delete it, so a stale mock doesn't masquerade as coverage.

---

## 6. Complete LOW Findings Table (101)

The 12 LOWs above are elevated for materiality. The full confirmed-LOW set follows (compact). `Conf` = auditor confidence.

| ID | Cat | File:Line | Summary | Conf |
|---|---|---|---|---|
| U01-2 | di | syscall.rs:6118-6124 | exec_from_bytes current-task-only contract guarded by debug_assert! alone; release performs no runtime validation | high |
| U01-4 | re | syscall.rs:3757-3794 | seccomp Kill/Trap fallback when current_pid() is None enters an unbounded spin_loop() (hard CPU hang) not a bounded halt | low |
| U02-1 | bo | syscall.rs:10308-10315 | sys_pread64 uses VFS callback return value to slice the staging buffer without clamping to count; callback returning >count overreads | high |
| U05-1 | co | process.rs:10237-10249 | oom_snapshot RSS sums mmap region LENGTHS incl. PROT_NONE reservations that never allocated frames | low |
| U06-2 | di | cgroup.rs:4164-4177 | try_charge_ports doesn't publish origin pin under the registry read lock nor check deleted, unlike hardened siblings | medium |
| U07-3 | co | fork.rs:2110-2136 | (elevated above) deprecated find_pte reads PTE flags without PT_LOCK — R114-class dead unsafe | high |
| U09-2 | co | syscall.rs:8892-8893 | try_deliver_signal_on_irq_return holds non-IRQ-safe spin::Mutex proc guard across faultable copy_to_user in hard timer-IRQ | medium |
| U09-3 | pe | signal.rs:655-692 | send_signal_inner POSIX check block wrapped in `if let Some(sender_pid)` — no current process skips all permission checks | medium |
| U10-1 | co | time.rs:121-214 | lost-update race on TCP_TIMER_DEFERRED flag: drain can clobber a concurrent timer-IRQ deferral | high |
| U10-2 | di | exception_table.rs:54-79 | (elevated) R120-5 kernel-space fault_ip/fixup_ip validation debug_assert-only — inert in release | high |
| U10-3 | re | scheduler_hook.rs:402-423 | deferred TCP timer work drained ONLY by reschedule_if_needed; yield/IRQ-return deliberately skip it | medium |
| U11-3 | re | socket.rs:2490-2510 | DeferredPortUncharges::enqueue panics (kernel crash) if all 4096 slots occupied, while a binding spinlock is held | low |
| U12-1 | di | socket.rs:11013-11202 | process_passive_final_ack (attacker-reachable ACK) uses .expect()/assert! that abort instead of rolling back the half-open txn | low |
| U13-1 | di | stack.rs:1979-1995 | build_frame_and_transmit allocates+copies the full wire frame BEFORE the netns device-ownership gate runs | medium |
| U14-1 | di | tcp.rs:1981-2038 | handle_ack trusts caller-enforced precondition (ack_num<=snd_nxt) with no in-function runtime defense | high |
| U14-3 | au | tcp.rs:2883-3004 | ISN_WEAK_CONNECTIONS counter tracks weak-entropy ISN connections but is never read/surfaced to any audit subsystem | high |
| U15-3 | co | conntrack.rs:2283-2328 | ct_process_icmp builds flow key from (icmp_type<<8|icmp_code,0), never uses icmp_id — echo req/reply produce different keys | high |
| U15-5 | di | conntrack.rs:1092-1168 | several attacker-reachable publication paths panic on capacity-admission invariants believed unreachable under capacity_permit | low |
| U16-2 | di | ipv4.rs:491-529 | build_ipv4_header is pub; total_len = HEADER_MIN + payload_len with unchecked u16 addition, no internal bound on payload_len | high |
| U16-3 | di | buffer.rs:545-571 | BufPool::free is pub with no provenance check; freeing a NetBuf not from this pool corrupts the in_use() ledger (usize underflow) | high |
| U16-4 | di | icmp.rs:315-405 | ICMP amplification rate limiting is caller-enforced, not enforced in the icmp module; builders don't consult ICMP_RATE_LIMIT | high |
| U16-7 | di | fragment.rs:463-493 | is_last/overlap checks cast stored_data.len() as u16 directly, inconsistent with R102-L1 checked-conversion on the incoming fragment | medium |
| U18-1 | re | ext2.rs:4659-4757 | mount-path FilesystemIo allocations (reserved vector up to ~16 MiB, journal vectors) use unbounded infallible alloc | low |
| U19-1 | di | ext2.rs:8573-8577 | inode_group_index computes (ino-1) without re-validating ino!=0; a future caller skipping the guard underflows | low |
| U20-2 | di | manager.rs:929-932 | symlink-target read (931) and readlink (1505) slice buf[..read_len] without verifying read_len<=buf.len() | medium |
| U20-3 | di | manager.rs:37-46 | LSM path/name identifiers use non-cryptographic FNV-1a (hash_path); a policy keying on hashes vs inodes is forgeable | low |
| U21-3 | co | initramfs.rs:647-657 | the `..` dirent in initramfs readdir always reports self.ino as parent for every dir — wrong parent pointer | medium |
| U21-4 | ef | initramfs.rs:659-676 | initramfs readdir uses iter().nth(real_offset) per getdents64 call — O(n²) full enumeration | medium |
| U22-1 | co | mount_namespace.rs:616-640 | copy_mounts takes read(from) then write(to) with no from!=to guard — self-deadlock + ABBA between two clones | medium |
| U22-2 | re | mount_namespace.rs:505-556 | normalize_mount_path enforces no max path length; copy_mounts/add_mount allocate path strings infallibly under the namespace write lock | medium |
| U22-3 | fo | traits.rs:659-662 | (elevated) FileHandle::clone_box panics via .expect() on allocation/admission failure | high |
| U23-1 | co | heap_admission.rs:373-384 | (elevated, ⚠gate) R186-4 commit-panic→error conversion is dead code — commit_pair panics unconditionally | high |
| U23-2 | di | admitted.rs:686-696 | (elevated, ⚠gate) R186-4 conversion not applied to AdmittedDeque / AdmittedMap install_prepared_deferred | high |
| U24-2 | au | page_cache.rs:807-1243 | dirty-page/writeback API exported but mark_dirty never invoked — no cached page is ever dirtied; writeback dead | high |
| U25-2 | di | page_table.rs:1059-1091 | public unsafe recursive_pdpt/pd/pt compute PT-frame vaddrs by raw index arithmetic with no idx<512 bounds assertion | medium |
| U26-2 | di | buddy_allocator.rs:646-648 | infallible free_pages/free_physical_pages silently discard every try_free_pages error — pages leak on misuse, no diagnostic | high |
| U26-3 | di | tlb_shootdown.rs:918-926 | flush_range_local page-alignment contract is debug_assert-only; a non-normalized release caller skips the unaligned tail page | medium |
| U26-5 | co | oom_killer.rs:294-301 | emit_audit truncates victim pid (usize) to u32 — wrong pid recorded if pid > u32::MAX | low |
| U28-1 | co | iommu/lib.rs:882-1068 | inconsistent lock ordering: attach/detach take IOMMU_UNITS then DOMAINS; map/unmap take DOMAINS then IOMMU_UNITS (ABBA latent) | medium |
| U28-2 | bo | iommu/dmar.rs:456-458 | RmrrEntry::size() computes limit-base+1 without overflow guard on firmware-controlled RMRR addresses | medium |
| U29-1 | ms | iommu/interrupt.rs:366-387 | IRT allocate validates only start phys against MAX_DIRECT_MAP_PHYS, not the end of the multi-page allocation | medium |
| U29-4 | di | iommu/domain.rs:600-608 | table_from_phys direct-map bounds invariant is debug_assert-only; a corrupted PTE addr derefs phys_to_virt unchecked in release | medium |
| U30-1 | di | cpu_local/lib.rs:92-101 | NMI nesting counter uses unchecked fetch_add/fetch_sub, inconsistent with R68-7 checked arith on the parallel IRQ FPU counter | high |
| U32-2 | bo | arch/apic.rs:1049-1155 | I/O APIC public unsafe API no bounds on IRQ; ioapic_max_entries() can wrap u8 (255+1→0 in release) | low |
| U32-3 | co | arch/apic.rs:792-852 | BSP and every AP write identical LDR value 1<<24 — all CPUs share logical APIC ID 1 in flat logical mode | high |
| U32-5 | fo | arch/cpu_protection.rs:114-180 | boot enforces SMAP as hard requirement; SMEP and UMIP are soft (warn-and-continue) when supported-but-not-enabled | medium |
| U33-2 | iv | tlb_ops/lib.rs:132-166 | (elevated) INVPCID pcid wrappers accept u16 with no bounds check; pcid>4095 → #GP in kernel | high |
| U34-2 | co | ipc/futex.rs:1298-1339 | cleanup_process_futexes owner-transfer selects successor via select_highest_waiter WITHOUT pruning zombie waiters first | medium |
| U34-3 | di | ipc/futex.rs:1550-1610 | (elevated) PI chain truncates at depth 64 without fully propagating the boost — holder unboosted | high |
| U35-2 | di | ipc/sync.rs:1135-1148 | KMutex::unlock owner verification is debug_assert, release-stripped; a non-owner unlock in production silently breaks mutual exclusion | medium |
| U36-2 | co | ipc/pipe.rs:501-510 | read_with_commit holds pipe inner spin::Mutex across the commit callback (a copyout to userspace); a user page fault extends the hold | low |
| U37-1 | au | security/kaslr.rs:732-900 | R103-I1 KPTI seqlock/PCID allocator/CR3-switch stubs are inert (KPTI single-CR3) but exported as if live | high |
| U38-3 | re | security/fips.rs:113-137 | set_fips_state busy-waits with no bound/timeout for active non-FIPS ops to drain; a stuck op hangs compliance init | medium |
| U38-5 | au | security/wxorx.rs:156-243 | validate_active never populates a Violation record (only increments a count); WxorxError::Violation arm is dead — no address/flag reported | high |
| U38-6 | di | security/spectre.rs:156-159 | (elevated) rsb_stuffing_enabled documented "always true" but context_switch_barrier returns early skipping RSB fill | high |
| U39-1 | bo | audit/lib.rs:677-680 | write_event_payload hashes event.args[i] for i in 0..arg_count without clamping to MAX_ARGS — arg_count>7 OOB read | medium |
| U39-2 | au | audit/lib.rs:1513-1522 | AuditExportRecord.args is [u64;6] but AuditEvent.args is [u64;7]; from_event copies min(arg_count,6), dropping the 6th syscall arg | high |
| U39-3 | di | audit/lib.rs:729-772 | hmac_sha256 R94-10 scrubbing zeroizes only explicit locals; Sha256 hashers' internal state[]/buffer[] retain key-derived material | medium |
| U39-4 | re | audit/lib.rs:2478-2547 | export()/snapshot() memcpy up to ~200 KiB while holding AUDIT_RING Mutex with IRQs disabled (bounded but long hold) | low |
| U40-2 | ef | enhanced_scheduler.rs:1596-1624 | steal_one holds source ready-queue spin lock across a BLOCKING CPUSET_REGISTRY.read(), unlike IRQ-return which uses the non-blocking path | high |
| U40-4 | di | sched/cpuset.rs:96-100 | CpusetNode::set_cpus is pub with a raw Release store, no validation, re-exported via lib.rs — any external caller can corrupt the cpuset | high |
| U41-1 | di | block/virtio/blk.rs:1655-1769 | VirtioBlkDevice::submit_bio ignores bio.sec_tag — the block layer's documented device-level LSM enforcement is unimplemented dead metadata | high |
| U41-3 | co | block/virtio/blk.rs:1267-1312 | reset_device re-negotiates features + re-publishes queue but never re-reads capacity/sector_size — subsequent I/O bounds use stale values | medium |
| U42-1 | fo | lsm/lib.rs:241-256 | SyscallCtx::from_current / ProcessCtx::from_current return Option; syscall.rs:3860 skips hook_syscall_enter when None, debug_assert-only (see MED-1) | medium |
| U42-3 | au | lsm/lib.rs:617-695 | (elevated) hook_syscall_exit and hook_task_exit don't emit denial audit events on Err, unlike every other hook | high |
| U44-1 | di | seccomp/types.rs:955-957 | add_filter panics if AdmittedVec::push_reserved fails after a succeeded prepare/install, instead of returning Err, on the attacker-reachable install path | medium |
| U45-1 | re | cap/lib.rs:965-971 | O(n) self.free.contains(&index) integrity assert in install_reserved (and cancel_reserved) under the per-process cap-table spinlock | medium |
| U45-2 | co | cap/lib.rs:785-803 | apply_cloexec drops revoked CapSlots (and their Arcs) INLINE under the cap-table spinlock — single-layer defense for non-fd Arc variants | low |
| U45-3 | di | cap/types.rs:552-559 | CapEntry::decrement_refcount panics (kernel halt) on double-decrement, but its test documents the intended behavior as saturating | medium |
| U46-3 | bo | virtio/queue.rs:227-241 | push_avail writes caller-supplied head into the avail ring with no head<size bounds check, unlike the blk.rs twin which asserts it | medium |
| U46-4 | di | virtio/queue.rs:327-350 | desc_mut/desc use debug_assert-only bounds (stripped in release); a release OOB index corrupts the descriptor table with no runtime guard | low |
| U50-4 | co | trace/profiler.rs:246-266 | drain_into() (cross-CPU snapshot) races with per-CPU push() on the ring tail — drain's tail.store can regress behind a concurrent push | medium |
| U51-2 | di | drivers/framebuffer.rs:100-165 | init() validates dims/size but doesn't cross-check info.base/size against the memory-map framebuffer region; >=1GB branch uses raw phys | medium |
| U51-3 | au | drivers/keyboard.rs:169-217 | process_scancode() ignores the return value of self.push() (incl. Ctrl+C/Ctrl+D) — drops on full buffer are never counted | high |
| U51-4 | di | drivers/keyboard.rs:345-381 | push_scancode/push_char acquire the plain spin::Mutex KEYBOARD_BUFFER without explicit irqsave (convention-only) | medium |
| U52-1 | ms | sync_safe/lib.rs:65 | (elevated) IRQ-safety probe asm declares nostack,nomem but runs pushfq;pop — unsound asm contract violation | high |
| U53-1 | di | src/main.rs:1596-1604 | (elevated) __stack_chk_guard is a compile-time constant — identical across boots, recoverable from the binary | high |
| U53-2b | di | src/main.rs:329-333 | bootloader-supplied boot_info_ptr cast to *const BootInfo and deref'd with no alignment/range/identity-map validation beyond non-zero | medium |
| U53-4 | co | src/shell.rs:450-457 | cmd_uptime divides raw TSC ticks by 1_000_000 assuming 1 MHz TSC — wildly misreports uptime on any modern CPU | high |
| U54-2 | au | tests/test_coverage.rs:13-286 | compile-time coverage enforcement lives in a tests/ integration target no build runs — doubly non-functional | high |
| U54-5 | di | src/runtime_tests.rs:1122-1246 | three NetworkLoopbackTest sub-oracles assert nothing despite names implying validation (test_tcp_syn accepts every variant) | high |
| U55-3 | di | bootloader/main.rs:181-308 | KASLR entropy drawn solely from RDRAND, no RDSEED/EFI_RNG_PROTOCOL/RDTSC mixing — degraded/virtualized RDRAND weakens the slide | medium |
| U55-4 | di | bootloader/main.rs:39-53 | KASLR slide space is 257 slots (0..512 MiB @ 2 MiB) — only ~8 bits of placement entropy, brute-forceable across reboots | medium |
| U55-6 | di | bootloader/main.rs:931-993 | low 4 GiB identity map + high-half kernel region mapped RWX (no NX) until kernel cleanup — wide W+X window during early boot | medium |
| U55-7 | re | bootloader/main.rs:1077-1107 | post-exit memory-map copy buffer hard-coded 64 pages (256 KiB); a larger firmware map panics at the assert — fail-closed but brittle | medium |
| U55-8 | di | bootloader/main.rs:922-1131 | NX/kernel-extent and BootInfo.kernel_phys_base use recomputed KERNEL_PHYS_BASE+kaslr_slide instead of authoritative actual_phys_base | medium |
| U56-1 | co | userspace/src/shell.rs:221-224 | `ls` command branch ordering reversed vs every other two-arg cmd — `ls <path>` lists cwd instead of the requested path | high |
| U56-2 | di | userspace/src/syscall.rs:728-824 | Stat (144B) and UtsName (390B) have no compile-time size/layout assertions despite comments warning the kernel writes exactly those sizes | high |
| U56-3 | co | userspace/src/libc.rs:386-388 | itoa (hence print_int) mishandles i64::MIN: value=-value overflows, digit loop never runs, only a bare '-' is emitted | high |
| U57-2 | fo | userspace/syscall_fuzzer.rs:84-196 | syscall_fuzzer ignores all KCOV control return values and dumps into a 1024-B buffer while KCOV was configured at 4096 | high |
| U57-4 | di | userspace/fuzzer/crash_triage.rs:270-275 | Phase 5/6/7 scaffold modules reference APIs that don't exist on the live corpus/executor/mutator | medium |
| U57-5 | co | userspace/fuzzer/corpus.rs:91-116 | Corpus::add inserts new-entry slots into the global union before culling, then truncates without removing evicted slots from global_slots | high |
| U58-2 | co | nilix-syz-fuzzer/src/main.rs:110-142 | main fuzzing loop propagates every per-iteration error with `?` — a single transient fault aborts the whole session | high |
| U58-3 | au | nilix-syz-fuzzer/src/main.rs:123-133 | crash filenames use second-granularity time + persist(overwrite) — two crashes in the same second silently clobber the earlier reproducer | high |
| U58-4 | co | nilix-syz-fuzzer/src/corpus.rs:44-63 | Corpus::add derives on-disk filename id from entries.len(), diverging from on-disk names after any gap → collisions that overwrite | medium |
| U58-5 | au | nilix-syz-fuzzer/src/corpus.rs:104-119 | load_from_disk silently skips entries whose JSON/validation fails with no log — masks corpus integrity loss from corruption/tampering | medium |
| U58-6 | re | nilix-syz-fuzzer/src/executor.rs:141-142 | read_bounded_text does std::fs::read of the entire uncapped qemu.stderr before discarding all but the last MAX_DIAGNOSTIC_LOG bytes | low |
| U58-7 | di | nilix-syz-fuzzer/src/protocol.rs:494-513 | HMAC-SHA256 implemented by hand instead of a vetted crate — textbook-correct but a single-layer crypto dependency | medium |
| U59-1 | au | kernel/fuzz/mock_kernel.rs:1-286 | (elevated) orphaned dead code whose doc falsely claims to reuse real kernel logic while reimplementing every syscall arg | medium |
| U59-2 | au | kernel/build.rs:312-315 | generate_registry_validation is a no-op stub — build purpose #3 ("verifies all tests are registered") unimplemented; test-registry drift undetected | high |
| U59-3 | co | kernel/build.rs:268-282 | parse_date computes an approximate epoch with i32 arithmetic cast to u64 — wrapped/huge values for years <1970, potential u64 overflow | medium |

**Category key:** ms memory-safety · pe privilege-escalation · re resource-exhaustion · co concurrency/correctness · bo bounds · iv input-validation · di defense-in-depth · fo fail-open · au audit-gap · ef efficiency

---

## 7. Informational / NONE Findings (3)

Confirmed as real code observations but with no reachable security impact (unreachable callers, fail-closed-by-design, or impact dominated by another finding).

- **U29-3** `iommu/interrupt.rs:189-209` — `assign_device_to_vm` allocates an IRTE, clears it to `empty` (not-present), returns a handle, but never calls `Irte::new_msi` to populate vector/destination/source-id. VM-passthrough device interrupts are fail-closed non-functional. A repo-wide grep shows `assign_device_to_vm`/`create_vm_domain` have *zero callers* (the crate carries `#![allow(dead_code)]`), and the D1-ISO-IOMMU-DOMAIN design marks VM passthrough future work, so this is a code-completeness note for when it is wired, not a live defect. **Fix when wiring:** add `populate_irte(handle, vector, dest_apic_id)` and require the caller to invoke it before enabling device MSI; document the handle as not-yet-present.
- **U48-2** `compliance/lib.rs:428-464` — `enable_fips_mode` holds the `FIPS_ENABLING` busy-wait spin across `run_fips_self_tests()` (1M-block SHA-256 + HMAC + ECDSA KATs) with no backoff. The monotonic state machine (sticky `Enabled`/`Failed`) means a waiter spins for at most *one* KAT run (sub-second, privileged-only, syscall context), so "indefinite stall" is unreachable. Residual: a one-time sub-second privileged busy-wait with no yield — below the LOW threshold. **Fix (hygiene):** move the KAT outside the critical section (the existing double-checked re-check guards the TOCTOU) or bound the spin.
- **U55-5** `bootloader/main.rs:569-571` — `kernel_data` is `vec![0; file_size]` from an unvalidated UEFI `FileInfo.file_size`; a malicious FAT entry claiming an enormous size triggers an unbounded allocation attempt (OOM/panic). Impact is fully dominated by the bootloader's lack of any `kernel.elf` integrity check (an attacker who can craft the ESP can replace the kernel outright), and the outcome is fail-closed DoS (boot halts, no attacker code runs). **Fix (hygiene):** cap `file_size` at a compile-time `KERNEL_MAX_SIZE` and use `try_with_capacity` so an oversized claim is rejected explicitly rather than panicking the allocator.

---

## 8. Areas Reviewed — Sound / No Findings

56 of 59 units reported a clean/sound callout; the following subsystems verified **sound** under the safety-first lens (listed where the audit explicitly confirmed a load-bearing invariant holds):

- **KCOV (U03, U47, U49) — CLEAN, 0 findings.** The R187 hardening conforms to all four design docs: `kcov_access_allowed` returns `is_host_root` only and ignores the reserved bit (R187-1); `require_kcov_access` is the single gate called first in all five arms (R187-1); the outer recorder rejects IRQ/NMI/IF-masked before pinning and rechecks after (R187-2); the NMI nesting counter is allocation-free (R187-2); modulo collision semantics documented + tested (R187-4); strict registered-and-online CPU pin + checked `.get()` + reciprocal LAPIC maps + duplicate-MADT rejection (R187-7). The recent R187 work re-verified clean.
- **OOM re-entry (U05) — CORRECTLY RESOLVED.** The R178-4 CRITICAL deadlock (PCB→allocator→OOM→PROCESS_TABLE/PCB re-entry) is resolved by the implemented `oom_snapshot` (try_lock + streaming + `Option`), matching the design. The R186-4 VMA/MM metadata admission migration is present. (But see U23-1/U23-2 in §9 for the commit-path caveat.)
- **CPL3 entry-state (U33) — CONFORMING.** `swapgs`+`lfence` on syscall entry; `assert_kernel_gs_base` on `force_reschedule*`/`reschedule_if_needed`; COW/demand-grow #PF return paths correctly do *not* swapgs. (U33-1 is a defense-in-depth ordering gap in the *nested*-rejection net, not a live nonconformance.)
- **VT-d driver (U27) — substantially sound, fail-closed.** Consistent lock order `table_lock -> ir_table -> irte_bitmap`; only one LOW defense-in-depth finding survived.
- **fork (U07) — mature hardening.** Lock order PCB(parent)→MmState→PT verified; two-phase clone OOM safety intact. The only finding is the dead `find_pte` (U07-3).
- **Net stack (U13) — mature (R48–R180+ lineage).** The D1-ISO `AuthorizedTxDevice` token gate and D3 pending-frame queue verified; only 3 LOWs.
- **IOMMU domain/interrupt/fault (U29), conntrack (U15), TLS/L4 (U16), VFS ext2 (U18/U19), VFS manager (U20), cap (U45), seccomp (U44), audit (U39), sched (U40), livepatch (U43), block (U41), virtio (U46), userspace core (U56), fuzzer family (U57)** — all read line-by-line and found substantially sound with only MEDIUM/LOW residuals.

**Coverage caveats (honest):**
- **U12 range labeling.** The `socket.rs` part-2 unit (7800–15505) did not contain the `listen`/`send_to_udp`/`recv_from_udp`/TCP-send/recv/accept/SCM handlers its title implied — those sit at 5949–6646, inside the part-1 unit (1–7800), which did read them. Both halves were read in full, so coverage is complete; only the unit *title* was imprecise.
- **U28/U27/U29 split.** `vtd.rs`, `interrupt.rs`, `fault.rs` were distributed across U27/U29 (not U28); all were read by some unit.
- **ACPI threat model (U31).** Two MEDIUMs (U31-1, U31-3) hinge on treating firmware ACPI tables as untrusted input — consistent with the S-3/RF180-58 fail-closed-to-BSP-only design the peer parsers already enforce.
- **Test oracles (U54).** Audited for *oracle correctness*, not just code safety — several dead/non-functional test suites flagged (U54-1, U54-2, U54-5) as audit-gaps, consistent with the project's documented "host `#[cfg(test)]` tests never run; boot suite is the real coverage" constraint.

---

## 9. Findings Bearing on the 1.0-Preview Gate (R186-4)

The gate is currently blocked on `R186-4` (VMA/MM metadata admission) and its design parent `D1-RES-HEAP-ADMISSION-REOPENED`, which require whole-heap aggregate admission so PROT_NONE and fork pressure cannot bypass the ledger. Two verifier-confirmed LOWs allege the R186-4 *remediation itself* is partly non-functional:

- **U23-1** — the R186-4 commit-panic→error conversion in `heap_admission.rs:373-384` is dead code because `commit_pair` panics unconditionally on any ledger error, so `HeapReservation::commit` can never return the error the conversion was meant to surface.
- **U23-2** — the same conversion was applied to `AdmittedVec` and `from_sorted_vec_charged` but *not* to `AdmittedDeque` or `AdmittedMap::install_prepared_deferred` (`admitted.rs:686-696`), leaving those paths still panic-on-error.

**Status:** These are single-pass verifier-confirmed findings (HIGH confidence) but were not cross-checked against the RF186 ReviewFix closure or the R186-4 design doc's intended scope. They may reflect (a) a genuine gap in the R186-4 fix that the RF186 pass missed, or (b) a misread of which paths `commit_pair`'s panic is reachable from (the panic may guard a genuinely-invariant-violating path that should never return an error). **Recommendation:** before advancing the zero-HIGH streak, reconcile U23-1/U23-2 against the R186-4 design and the `AdmittedMap` commit semantics — if `commit_pair`'s unconditional panic is *intentional* (a "this should never fail" invariant), the design doc should say so and U23-1/U23-2 become documentation findings; if it is *not* intentional, the R186-4 fix has a live hole and the gate does not advance. Either way this is a concrete, file:line-evidenced question the gate process should answer, not assume.

---

## 10. Cross-Cutting Themes

1. **`debug_assert!` as a security boundary (≈18 findings).** The single largest class — `debug_assert!` guarding safety-critical invariants (LSM gate U01-1, exec current-task U01-2, exception-table U10-2, KMutex owner U35-2, PT bounds U25-2, tlb alignment U26-3, iommu direct-map U29-4, RSB stuffing U38-6, queue bounds U46-4). In a `panic="abort"` release kernel, `debug_assert!` is a no-op, so these invariants are unenforced in the exact build that ships. **Systemic fix:** a lint or convention that any `debug_assert!` on a security/correctness invariant either becomes a runtime check or is documented as defense-in-depth-only with the rationale recorded.
2. **Infallible allocation on recoverable/OOM paths (≈11 findings).** `Arc::new`/`vec!`/`.expect()` on paths that should return `ENOMEM`/`ENOSPC` — namespaces (U08-1, U08-2), cgroupfs (U21-1), firewall lazy-init (U17-1), `FileHandle::clone_box` (U22-3), seccomp `add_filter` (U44-1), bootloader (U55-5, U55-2), `DeferredPortUncharges` (U11-3). The project has a mature fallible-allocation discipline (the D2-ERR-RECOVERY contract, the `try_reserve_heap`/`Arc::try_new`/`AdmittedMap` machinery) — these are the sites that discipline hasn't reached yet.
3. **Audit-gap on security-relevant operations (≈12 findings).** Cgroup governance (U03-1), LSM exit hooks (U42-3), ISN-weak counter (U14-3), page-cache writeback (U24-2), wxorx violation record (U38-5), audit export arg truncation (U39-2), dead ABI/test suites (U54-1, U54-2, U54-5, U59-1, U59-2). The audit subsystem is strong (hash chain, HMAC, mandatory-at-Secure) but several security decisions still go unlogged or are logged with data loss.
4. **Lockdep inventory / LockdepMutex coverage gaps (≈5 findings).** `CPUSET_REGISTRY`/`ROOT_CPUSET` untracked (U40-1); IOMMU `IOMMU_UNITS`/`DOMAINS` inconsistent ordering (U28-1); `copy_mounts` self-deadlock (U22-1). The 9-level lockdep is a real asset but its coverage is incomplete on the scheduler/IOMMU hot paths.
5. **Namespace isolation completeness (U02-2, U08-3, U08-1/2, MED-2/MED-4/MED-6).** The *isolation boundaries* (TX token gate, per-NS ARP/config/routing) are sound, but the *identity model* around them has gaps: namespace-init not protected from same-ns SIGKILL, user-namespace UID mapping non-functional, two namespaces still abort on OOM. These matter for the container target.
6. **Test-oracle integrity (U54-1, U54-2, U54-5, U59-1, U59-2).** Multiple test/coverage-enforcement suites are dead, unwired, or assert nothing — a misleading audit trail. The boot runtime suite is the real coverage; these orphaned files should be deleted or made real.

---

## 11. Remediation Priority (suggested, non-binding — this doc does not set the gate)

1. **HIGH-1 (U06-1)** cgroup port-uncharge leak — revert to blocking `lookup_cgroup` or re-enqueue on contention; this defeats the R169-3/R170-2 delete-gate.
2. **HIGH-2 (U09-1)** signal RFLAGS mask — one-line replace with `sanitize_user_rflags` + self-test; closes a SysV ABI contract violation.
3. **HIGH-3 (U34-1)** robust-futex exit walk — implement `exit_robust_futexes`; the roadmap already lists this gap.
4. **Gate reconciliation (U23-1/U23-2)** — resolve before the zero-HIGH streak advances (§9).
5. **MEDIUM cluster — fail-open security gates (U01-1, U17-1, U21-2, U22-3)** and **OOM-abort classes (U08-1, U08-2, U21-1)** — apply the existing fallible-allocation discipline; these are the highest-leverage MEDIUMs.
6. **MEDIUM cluster — namespace isolation (MED-2, MED-6)** and **input-validation (U25-1, U31-1, U31-3, U55-2)** — defense-in-depth at trust boundaries.
7. **Systemic LOW class — `debug_assert!`→runtime check** — a lint/convention pass; ~18 findings, mostly one-line each.
8. **Test-oracle cleanup (U54-1, U54-2, U54-5, U59-1, U59-2)** — delete or wire; removes a misleading audit trail.

---

## 12. Methodology Limitations

- **Solo mode (MODE S).** Codex MCP and augment-context-engine-mcp were unavailable, so there was no bidirectional peer review with Codex. The R184 false-positive guard was enforced *structurally* via the independent adversarial verifier pass (67/198 = 34% refuted), but a second counterparty (Codex) would further harden confidence — particularly for the 3 HIGHs and the §9 gate-relevant LOWs, which a future round should re-verify with Codex present.
- **Single-pass verification.** Each finding was verified by one verifier agent. High-severity findings (the 3 HIGHs) were verified with high confidence and detailed code traces, but a second independent verifier on the HIGHs would be ideal before any is treated as gate-blocking.
- **No remote build/test run during the original audit.** The audit itself was static
  (line-by-line read + caller/lock-context trace) and did not exercise the devbox. Findings reflect
  the source at HEAD (`f5805df` + the then-uncommitted working-tree changes), not a built artifact;
  the completed remediation's authoritative remote verification is recorded separately in §13.
- **Line-range splits.** The largest files were split by line range across two agents. Where a finding spans a split boundary it could be missed; the splits were chosen at function boundaries to minimize this, and U12's labeling imprecision (§8) did not cause a coverage gap.

---

## 13. R188 remediation status (2026-08-26; verified 2026-08-27)

This section records the implementation pass requested against this standalone audit. The
historical findings and severity counts above are preserved; this status section reports what is
actually present in the current source and tests. Codex MCP was unavailable, so the pass used
MODE S with independent fresh-context review lenses. No commit or push was created.

### Disposition summary

- **HIGH: 3/3 fixed.** U06-1 uses a blocking process-context cgroup lookup; U09-1/U09-2/U09-3
  share the canonical signal-RFLAGS sanitizer, release the PCB lock before faultable usercopy,
  and fail closed on missing sender identity; U34-1 performs a bounded, fault-tolerant robust-
  futex exit walk with checked offsets, OWNER_DIED publication, and waiter wake-up.
- **MEDIUM: 24/24 fixed.** This includes the procfs UID/GID map interface (U08-3) with direct
  creator/parent-namespace authorization and generation revalidation; per-namespace fragment
  transaction lanes (U16-1); ordered nested-SYSCALL active-bit detection (U33-1); Lockdep-
  tracked cpuset roots (U40-1); permanently retired livepatch slots with bounded executable
  quarantine (U43-3); and a build-wired ABI layout oracle replacing the dead mock suite (U54-1).
- **LOW/associated: all listed classes fixed except U37-1 and U55-6.** Runtime checks, bounded
  allocation, rollback, lock ordering, accounting, audit, and userspace/fuzzer hardening cover
  the complete LOW table. U37-1 (KPTI/PCID architecture stubs) remains feature/design work;
  U55-6 (the early-boot identity-map W+X transition) remains an explicit boot-transition design
  residual. U55-7 is now a bounded 512-page handoff with a release-build fail-closed check.
- **Informational:** U48-2 is bounded and returns `Busy` on contention; U55-5 has a capped,
  fallible kernel-image buffer. U29-3 remains non-functional by design until VM passthrough has
  a caller; it is fail-closed and carries no reachable security impact.

The repaired classes include the associated paths that the original line findings exposed:
conntrack replacement rollback and namespace charges, emergency-tier deferred port uncharges,
fallible admitted-container publication, strict user-namespace map parsing, framebuffer/map
containment, ICMP error-rate limiting, livepatch quarantine, and non-vacuous hosted test oracles.

### Verification record

Local checks and hosted suites passed:

- `cargo fmt --all -- --check`, `cargo check -p kernel`, bootloader check, and bare-metal arch
  build all pass.
- Hosted `kernel_core`: **29/29**; `ipc` robust-futex: **4/4**; `vfs`: **22/22**; `net`:
  **116/116**; `mm`: **25/25**; `audit`: **15/15**; `seccomp`: **14/14**; `block`: **9/9**.
- Userspace core: **4/4**; userspace/fuzzer workspace: **27/27** across unit, binary,
  integration, and scaffold targets; nilix-syz-fuzzer: **26/26**.
- Runtime-test discovery reports **73/73 implemented** tests and **27 P0** tests. The hosted
  sub-crate oracle is now **239 tests** plus three test-code compile checks under default
  parallelism (audit 15, MM 25, block 9, seccomp 14, cap-RF186 2, net 116, IPC robust 4, VFS
  22, kernel-core 29, coverage 3).

Authoritative Linux verification completed on `40c-devbox-ts` against the synchronized tree:

- `make build`: **PASS** (UEFI bootloader, bare-metal kernel, and ESP assembly).
- `make lint`: **PASS**, including the VFS fallibility fixtures (**22/22**) and ABI layout oracle
  (**11 structs, 100 values, 17 tripwires**).
- `make test`: **PASS** — **34 passed, 39 deferred, 0 failed**, with **0 panic** and **0 NX fault**.
- `make test-hosted-subcrates`: **PASS** — **239 tests** plus **3 test-code compile checks** under
  default parallelism.

The runtime gate contract treats the documented deferred syscall-infrastructure placeholders as
non-failures, while still requiring zero failures, zero panics, and zero NX faults.

Residual design work is intentionally explicit: U37-1 requires a reviewed KPTI trampoline/dual-
CR3 design, U55-6 requires a safe pre-kernel identity-map permission transition, and U29-3 needs
the VM passthrough caller/IRTE lifecycle before it can become executable feature code. These are
not silently counted as fixed.

This standalone document is not part of the R-series and makes no zero-HIGH streak claim. The
authoritative per-round status remains in `docs/review/audits/`; the live plan is in
`docs/review/nextplan/`.

---

## 14. Mode Record

**Cooperation mode:** MODE S (Claude-solo). Codex MCP and augment-context-engine-mcp unavailable this session.
**Substitution:** 59 line-by-line reader agents (one per audit unit) → independent adversarial verifier agent per filed finding (default REFUTE, re-read code + trace callers/lock-holders) → orchestrator synthesis. No fresh-context skeptic fleet was spawned beyond the verify pass; the verify pass *is* the R84 guard.
**Scale:** 257 agents total · 3,437 tool uses · ~43 min · 0 errors · 0 empty results · 198 filed · 131 confirmed · 67 refuted (34%) · 0 uncertain.
**Source snapshot:** `f5805df` (HEAD) + uncommitted working-tree changes (`kernel/cap/types.rs`, `kernel/coverage/lib.rs`, `kernel/kernel_core/syscall.rs`, `userspace/fuzzer/{corpus,executor,main}.rs` modified per `git status`).
**Dual-environment:** This document is written to both `D:\project\Zero-os\docs\security\full-codebase-audit-2026-08-07.md` (local Windows mirror) and `/home/dev/workspace/project/rsproject/Zero-os/docs/security/full-codebase-audit-2026-08-07.md` (remote devbox) with SHA-256 parity verified.
**Git:** No commits or pushes performed (manual-only per project policy).

*Authored 2026-08-07. Standalone full-codebase security audit of the Nilix kernel under Safety > Correctness > Efficiency > Performance with mandatory defense-in-depth and fail-closed defaults.*
