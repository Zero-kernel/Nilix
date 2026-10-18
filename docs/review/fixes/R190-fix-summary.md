# R190 full-tree audit remediation summary

**Date:** 2026-10-18
**Audit:** [`qa-2026-10-18.md`](../audits/qa-2026-10-18.md) (Round 190)
**Tree:** `main @ 427de57` plus the uncommitted R190 working-tree diff (36 source/test/script files and `Cargo.lock`). No commit or push was made.
**Status:** All 16 implementation findings and both design findings have repairs or documented dispositions. Applicable final-tree gates pass, with runtime, boot and SMP zero-failure QUALIFIED, the same as the baseline (§5). Required independent review completed with re-review of every repair. Items stay "fixed, pending stage-3 review-fix"; none is called VERIFIED here.
**Mode:** MODE S (Claude-native). Two independent general-purpose reviewer agents (one concurrency/IRQ lens, one security/ABI/resource lens) reviewed the diff, and then re-reviewed the repairs their findings prompted. No Codex session was used, so no session IDs exist.

## 1. Triage corrections to the audit

Current-source verification changed several premises. The repairs follow the source:

| Finding | Audit premise | Current source |
|---|---|---|
| R190-1 | 19 zero-caller hooks; IPC syscalls "exist and are reachable" | 20 zero-caller hooks: `hook_kpatch_load` only appears in comments. No syscall reaches IPC endpoint send/receive; only `pipe`/`pipe2` and `futex` are live. The audit missed one live gap: `hook_net_control`, which mediates ARP/ICMP on the now-wired RX path. chmod, chown and link have dispatch arms, but each is a fixed-errno stub. |
| R190-2 | One socket pins ~94 KiB of a "1 MiB heap" | The heap is 2 MiB; 1 MiB is the SocketPayload class budget. Reassembly admits 65,507-byte datagrams, so one socket could pin 64 × 64 KiB, more than the whole class. That starves TCP payload admission too. |
| R190-3 | Reader holds the IRQ-shared lock across copy_to_user | Worse: the reader also held IF=0 throughout, so a faultable usercopy ran with interrupts masked under the lock. |
| R190-6 | NMI and IRQ UART writes interleave | The NMI handler prints nothing. The live writer was the timer IRQ's `[T:X]` marker. |
| R190-7 | panic/NMI print self-deadlock | Any same-CPU IRQ print could also deadlock (the lock was taken with IRQs enabled). The panic handler already used raw serial. |
| R190-11 | No whitelist/dispatch cross-check | The M0-6 parity self-test existed, but its lists were hand-maintained and had drifted: 6 of 7 "undispatched" entries had live arms. |
| R190-14 | RX wiring not landed; `udp_bindings` → `rx_queue` nesting | RX is wired through the process-context deferred drain, and the bindings guard is released before `rx_queue`. The live hazard was `rx_queue` held across the receive copyout: not IRQ-safe, but bounded in process context. |
| R190-16 | close(0) may silently succeed | Console fds are ordinary fd-table entries; close removes them like any fd (EBADF when absent). The snapshot behaves like Linux `fdget`. |

## 2. Fix-to-file mapping and approach

| ID | Sev | Approach | Root cause and repair | Files |
|---|---|---|---|---|
| R190-1 | HIGH | Systemic | Declared hook families were never wired. Live surfaces are now wired: pipe, futex, ARP learn/reply, ICMP echo/REJECT, per-component path lookup. Dormant families are listed in `lsm::FEATURE_ABSENT_HOOKS` with their syscall numbers. Two hosted gates enforce INV-SEC-02 (see the [design](../design/d2-arc-1-security-surface-coverage-design.md)). SecureBaseline's false "livepatch LIVE TODAY" claim is corrected. | `lsm/lib.rs`, `lsm/policy.rs`, `ipc/lib.rs`, `kernel_core/syscall.rs`, `net/src/arp.rs`, `net/src/stack.rs`, `vfs/path.rs`, `vfs/manager.rs`, `tests/lsm_hook_census.rs` |
| R190-2 | MED | Targeted + budget reconcile | UDP was metered by count only. New per-socket byte cap of 128 KiB (`rx_queued_bytes`, written only under `rx_queue`; still admits one maximal datagram). The global cap moves from 16 MiB to SocketPayload/2 (512 KiB), with const asserts that caps fit the class (INV-RES-02, D3-RES-1). | `net/src/socket.rs` |
| R190-3 | MED | Structural | User copyout ran under the IRQ-shared `KEYBOARD_BUFFER` with IF=0. Now all buffer access goes through `with_buffer` (IRQs masked, bounded ring work only). A consumer-only `KEYBOARD_CONSUMER` lock is held across peek, copyout and consume, so the VFS commit runs exactly once. IRQ producers never contend for it. | `drivers/keyboard.rs` |
| R190-4 | MED | By construction | The cpuset API had no privilege layer. `CpusetAdmin` (host root or `CapRights::ADMIN`, or kernel context) is now required by create/destroy/set_cpus, and the new `hook_sched_cpuset` runs on every operation. | `sched/cpuset.rs`, `sched/lib.rs`, `lsm/*`, `src/runtime_tests.rs` |
| R190-5 | MED | Targeted | `arch_prctl(ARCH_SET_FS/GS)` returns EPERM for any base ≥ `USER_SPACE_TOP`, as Linux does. CR4.FSGSBASE is cleared and asserted clear at boot; APs inherit the BSP's CR4. | `kernel_core/syscall.rs`, `arch/cpu_protection.rs` |
| R190-6 | LOW | Remove | The timer-IRQ `[T:X]` UART emission is gone; nothing consumed it. | `arch/interrupts.rs` |
| R190-7 | LOW | Structural | Display access goes through `with_display`. The owner-CPU word is the lock: one compare-exchange acquires it and names the owner. A same-CPU re-entry (IRQ, exception, NMI) skips the display, and serial output is kept. Rendering keeps the caller's IRQ state. `framebuffer::is_initialized` is now an atomic. | `drivers/vga_buffer.rs`, `drivers/framebuffer.rs` |
| R190-8 | LOW | Targeted | New shared constant-time `kernel_crypto::ct_eq`. `verify_chain` and `verify_chain_hmac` compare both the hash and the link without a data-dependent early exit. | `crypto/lib.rs`, `audit/lib.rs` |
| R190-9 | LOW | Targeted | The trace metrics read guard denies when unregistered, and boot panics if guard installation fails. | `trace/lib.rs`, `src/main.rs` |
| R190-10 | LOW | Delete | Dead `cap_revoke_with_lsm` removed. The cap crate documents the hook obligation for future revoke/delegate syscalls, and the census guards `delegate` callers. | `kernel_core/syscall.rs`, `cap/lib.rs` |
| R190-11 | LOW | Mechanize | Corrected the drifted lists: mremap, link, symlink and readlink are dispatched, and chown/fchown are typed ENOSYS stubs. MAX_EXEMPT goes 7 → 3. A hosted test parses the real dispatcher and probes the stubs. | `kernel_core/syscall.rs` |
| R190-12 | LOW | Delete | Dead single-key `verify_prehash` removed; only `verify_prehash_any` remains. | `livepatch/ecdsa_p256.rs` |
| R190-13 | LOW | Targeted | Kernel diagnostics (`_print`) replace Unicode control characters other than `\n`/`\t` with `?` on serial. User stdout (`sys_write` console, devfs console) uses the raw `console_write_str`, as TTY data should. | `drivers/vga_buffer.rs`, `kernel_core/syscall.rs`, `vfs/devfs.rs` |
| R190-14 | LOW | Proof + check | Documented the process-context lock-chain proof. `deliver_udp` asserts it is not running in a hard IRQ (a per-CPU IRQ count; boot tests run before `sti`, so IF is not the predicate). | `net/src/socket.rs`, `net/Cargo.toml` |
| R190-15 | LOW | Targeted | `MAX_FIREWALL_RULES` = 4096. `replace_rules`/`new_with_rules` return `Result` and leave the old table in force on rejection. | `net/src/firewall.rs`, `net/src/lib.rs`, callers |
| R190-16 | LOW | Documentation | Console-fd snapshot semantics (fdget-equivalent) and the absence of a close(0/1/2) special case are documented in source. The misleading `sys_close` comment is removed. No ABI document exists in the tree. | `kernel_core/syscall.rs` |
| D2-ARC-1 | D2 | See R190-1/4/10 | Census plus wiring, a permissive-default threat-model statement, and the VFS mount comment aligned with the stricter uid-0 check. | `lsm/lib.rs`, `vfs/mount_namespace.rs` |
| D3-RES-1 | D3 | See R190-2 | Budgets reconciled with the admitting class; INV-RES-02 enforced by const asserts. | `net/src/socket.rs` |

## 3. Safety reasoning for the concurrency changes

- **Keyboard (R190-3).**
  - Lock order is `KEYBOARD_CONSUMER` → `KEYBOARD_BUFFER`. IRQ producers take only the latter, through `with_buffer`, with IRQs masked and bounded work.
  - Every consumer runs in process context: `sys_read` stdin, the devfs console and the kernel shell.
  - Holding the consumer spin lock across a faultable copyout is bounded. The kernel does not preempt kernel mode (the timer reschedules only when returning to user mode), and every page-fault resolution path is try-only.
  - Producers only append, so the consumer generation can only change through a consumer. It is kept as a debug assertion.
- **Display (R190-7).**
  - One `compare_exchange` takes the lock and names the owner; one store releases it. No interrupt, exception or NMI can observe a held lock without an owner.
  - Waiters spin with the caller's IRQ state, so they still take IPIs.
  - Contexts not yet registered with `cpu_local` share one owner token. An overlapping print among them skips the display rather than deadlocking.
- **UDP (R190-14).** The `rx_queue` hold across the receive copyout is safe only outside hard IRQs, so the new assert makes that a checked precondition. NMIs are not checked: the NMI counter is global, and the NMI handler never reaches the network stack.

## 4. Independent review

| Lens | Result | Disposition |
|---|---|---|
| Concurrency/IRQ (R190-3/6/7/14) | 2 defects. (1) The first R190-3 design retried `commit` on a generation mismatch, which duplicated bytes on the `/dev/console` VFS path; `ipc::fd_read_callback` enforces exactly one commit. (2) The R190-14 assert used the global `nmi_active()`, so an NMI on any CPU could panic delivery. Also one latent NMI window in the first display-lock design. | All confirmed against source and repaired: consumer serialization, assert narrowed to `in_irq`, owner word as the lock. **Re-review: all three SAFE** (exactly-once commit, no consumer bypass, no deadlock; no window, including NMI). |
| Security/ABI/resource, round 1 | Census red at the reviewed snapshot (rustfmt split table entries). The census could stay green when a new syscall for a dormant family shipped without its hook. ICMP-REJECT hook ran before rate limiting. ArpReply address orientation differed from ICMP. futex credential failure returned ESRCH. Two documentation inaccuracies. Residuals listed in §6. | Confirmed and repaired: layout-independent parser; syscall numbers per family with a dispatcher check; any-reference rule; guarded-API scan; test-dir and cfg stripping; hook after limiter; orientation; EPERM; docs. |
| Security/ABI/resource, round 2 | Net, futex and docs SAFE. Gates INCOMPLETE, shown by injected code: missing ptrace-access (310–312, 438) and message-queue (68–71, 240–245) numbers; or-pattern or named-constant arms skipped; a stub given a real body still passed `is_err()`; `cfg(not(test))` and `cfg(any(test, ..))` code stripped from the dormant-hook and guarded-API checks; aliased API imports. | All repaired: numbers added; strict arm parse (126 arms, all single-literal `sys_` calls); pinned stub errnos; Broad and Exact strip modes; reference-based guarded scan excluding `pub use`. Each injection now fails, verified locally. Remaining limits in §6. |
| Security, final confirmation | Dispatcher gate SAFE against 10 injected arm forms (literal, or-pattern, constant, range, guard, block, non-`sys_` handler, split line, 310, 69). Census: every round-1/2 injection fails. Remaining gap: a renaming `pub use .. as alias` re-export passed. | Repaired (renaming re-exports stay visible); the reviewer's G9 injection now fails locally. |

## 5. Validation

Remote host `nilix-dev`; the toolchain comes from the tree's `rust-toolchain.toml`.

- **First tree:** `/tmp/nilix-r190-1018`, pre-review sources, hash-verified against local.
  - build, lint, fmt-check and clippy: exit 0.
  - hosted: exit 2. The census failed on the rustfmt layout, a test-parser defect. Every other suite up to that point passed.
  - Rerun of hosted with the fixed census (`/tmp/nilix-r190-1018h`): **exit 0, 480 unit tests + CpuLocal doctests + 3 compile checks**.
  - `make test`: QUALIFIED, passed=35 deferred=39 failed=0 (gate status 3, make exit 2), the same as the 2026-09-21 baseline.
  - The batch was then stopped as superseded.
- **Intermediate trees:**
  - `/tmp/nilix-r190-1018f` (post-review v2): build, lint, fmt-check, clippy, hosted (480) and `make test` (35/39/0 QUALIFIED) passed. The batch was then superseded.
  - `/tmp/nilix-r190-1018v3` (v3): build, lint, fmt-check, clippy and hosted (480) passed. Its kernel ELF hash differed from v2, so QEMU results were not carried over.
- **Final tree (v4):** `/tmp/nilix-r190-1018v3` with the last census file. All 459 tracked non-doc sources hash-match local; the manifest's SHA-256 is `c85a9851…c7c39c`, identical on both hosts. The census is `0d4e5fcf…`, `syscall.rs` `ee2df56d…`, `lsm/lib.rs` `7d723614…`.

### 5.1 Final-tree gates (`/tmp/nilix-r190-1018v4-logs`)

| Gate | Exit | Result |
|---|---|---|
| `make build` | 0 | kernel + bootloader |
| `make lint` | 0 | release/SMAP/fetch-add/repr-C/fallible/ABI oracle |
| `make fmt-check` | 0 | workspace + userspace |
| `make clippy` | 0 | three build units |
| `make test-hosted-subcrates` | 0 | **480 unit tests** + CpuLocal doctests + 3 compile checks. New: audit 16, drivers 4, net 120, kernel-core 92, lsm-hook-census 3 |
| `make test` | 2 (gate 3) | QUALIFIED passed=35 deferred=39 failed=0 warning_markers=1 skipped_markers=39; Ring-3 syscall test passed. Identical to the 2026-09-25 baseline |
| `make boot-check` | 2 (gate 3) | QUALIFIED passed=28 deferred=46 failed=0. Baseline 28/46/0 |
| `make test-smp-4core` | 2 (gate 3) | QUALIFIED passed=37 deferred=37 failed=0; online_cpus=4; qemu_exceptions=0; smp_online and 3/3 R175 cross-CPU tests PASS. Baseline 37/37/0 |
| `make musl-check` | 0 | MUSL-CHECK OK: libc, poll, socket, stat/uname ABI, shared-mmap and **pthread** markers; clean exit; 0 NX faults |
| `make test-ring3-mm` | 0 | RING3-MM OK; leg contract passed. The only SKIP is the known pending shared-anon PTE-only preflight |

The QUALIFIED verdicts come from the pre-existing deferred and skipped runtime cases, with `failed=0`. They are not strict passes, matching the plan's existing qualification state.

## 6. Residual risks and verification gaps

- **D2-ARC-1 residual leads** (surfaces with no hook family at all): `sched_setaffinity`, cgroup syscalls 500-516, `/proc/<pid>/{uid,gid}_map` writes, `audit_export`, `fips_enable`, KCOV.
- **Census limits:**
  - One call site counts as wired.
  - Calls through fn-pointer aliases of wired hooks are not counted.
  - The guarded-API hook requirement is file-granular, and new wrappers inside an API's own file are not themselves guarded.
  - Test-named files compiled into the kernel are not scanned.
  - `hook_file_mmap` and livepatch boundaries are documented, not mechanically gated.
  - A dispatcher fast path added before the parsed match would not be checked. None exists today.
- The pipe LSM subject is taken before the RF186 credential window. This is safe while credentials have no runtime mutator.
- `hook_file_lookup` adds one SHA-256 per path component.
- Kernel diagnostics pass non-ASCII text, so an 8-bit (non-UTF-8) terminal can still receive C1 bytes inside UTF-8 sequences. The panic handler still prints `PanicInfo` raw in non-Secure profiles. User stdout is raw by design.
- **Pre-existing, unchanged:**
  - `clone(CLONE_SETTLS)` with a kernel-half TLS returns EINVAL (Linux returns EPERM).
  - `arch_prctl` accepts `0x7fff_ffff_f000`, which Linux rejects; this is harmless.
  - Display render hold time grows with output size (a full-frame scroll per newline).
- The `CpusetAdmin` token is not bound to a task; it must be authorized in the requesting task's context.
- Strict guest/musl/SMP qualification limits from the 2026-09-13 plan are unchanged. Runtime, boot and SMP gates remain QUALIFIED rather than strict PASS.

## 7. Handoff

Next stage: `kernel-review-fix` for R190. Inputs:

- this summary
- the [audit](../audits/qa-2026-10-18.md) (per-finding statuses)
- the [design](../design/d2-arc-1-security-surface-coverage-design.md)
- the R190 working-tree diff on `main @ 427de57`
- remote evidence in `/tmp/nilix-r190-1018f-logs` (final tree) and `/tmp/nilix-r190-1018-logs` (pre-review tree)
