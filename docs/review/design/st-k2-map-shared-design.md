# ST-K2 — MAP_SHARED Disposition: Fail-Closed Flags Validation + Shared-Anonymous Memory Design

**Date:** 2026-09-01 (restructured same-day after the lens round; user-confirmed)
**Plan item / Finding:** ST-K2 (P1, Preview-blocking; Phase 1 hoisted to directly after ST-K3's fix [user order repair]; Phase 2 blocks stress `smp`) — `docs/review/nextplan/next-phase-plan-2026-09-01.md`; origin `docs/stress-gate-status.md` §6 K2
**Status:** Phase 1 and the shared-anonymous demand path are implemented in the current tree (2026-09-13). Shared VMAs use an admitted side-map with bounded page slots; first user/usercopy faults charge and map a zeroed page; fork inherits region Arcs and writable shared leaves; munmap/exec/exit drop regions after page-table teardown. The exact final source is remotely verified on `40c-devbox-ts` in `/tmp/zero-os-codex-final-20260913`: MM 26/26, kernel-core 68/68, hosted allowlist, build and lint pass; runtime/boot/4-core SMP are zero-failure qualified. Guest usercopy/teardown/failure coverage and musl markers remain explicit limits.
**Current handoff:** [source refresh](next-handoff-2026-09-12.md#4-st-k2-p1--honest-mmap-flags-and-usable-stress-reports) preserves the two phases and first-toucher decision, while requiring the current RF180-20/COW/usercopy ownership paths to be reconciled before Phase 2.
**Mode:** MODE S (Codex MCP absent; premise/safety/edge lenses ran 2026-09-01; mechanism amendments folded in)
**Designed by:** stage 4 next-phase (grilling)
**User confirmation:** confirmed 2026-09-01 (Q-FINAL; Decision Record rows 1-4 individually confirmed same day)
**Amendment mode:** normal — decision-points only
**Sources:** `docs/stress-gate-status.md` §6 K2 + §9.2, plan v15.60, lens reports 2026-09-01, R121-4/R145-1/R149-6/RF178-12/R186-10 lineage, `sched/lock_ordering.rs`

## 1. Requirement & Threat Model

**Goal (user decisions 2026-09-01):**

- **Phase 1 (immediate; hoisted to directly after ST-K3's fix, ahead of ST-K4):** `sys_mmap`
  validates the ENTIRE flags word — accept exactly the implemented shape
  (`MAP_PRIVATE|MAP_ANONYMOUS`, addr-as-hint); **EOPNOTSUPP** for `MAP_SHARED`/
  `MAP_SHARED_VALIDATE`/`MAP_FIXED` and any unknown bit — placed AFTER the LSM hook so
  policy audit records persist. Guest report transport moves to pipes.
- **Phase 2 (P1 feature, after P0-A closure):** `MAP_SHARED|MAP_ANONYMOUS` shared-anonymous
  memory — fork-inherited, demand-faulted, **first-toucher per-page cgroup charging with the
  documented rmdir-EBUSY liveness consequence accepted** (user re-confirmation 2026-09-01).
  File-backed mmap stays EOPNOTSUPP.

**Invariants:** (1) no mapping ever has silently-wrong semantics — for ANY flag; (2) every
shared frame is charged before reachable and uncharged exactly once, to the recorded owner,
at true last-release (amount-symmetric); (3) shared ranges are never COW'd — in EITHER
direction (child skip AND parent no-write-protect); (4) all region metadata under admission
(P0-A invariant); (5) **frame lifetime is owned by `PAGE_REF_COUNT`**, never by a parallel
ledger (lens: two owners = N+1 frees).

**Threat model:** shared memory is isolation-sensitive — inheritance-only reachability (no
name/key surface); charge-before-install; W^X preserved; bounded kernel metadata per region;
fault-path lock discipline per RF178-12 (try-only from #PF); no user-triggerable panic via
kernel touches of unfaulted shared pages.

## 2. Current-State Analysis (re-derived 2026-09-01; lens-corrected)

- `_flags` has exactly one consumer: forwarded to the LSM hook (`syscall.rs:13629` →
  `lsm/lib.rs:1289`); all three policies discard it (`policy.rs:214/645/912`). No
  MAP_SHARED/MAP_FIXED/MAP_ANONYMOUS handling anywhere; anon-ness inferred from `fd >= 0`
  (`:13614`); `addr != 0` is a hint with EINVAL-on-overlap (`:13758-13766`) — NOT Linux
  MAP_FIXED replace. mremap is ENOSYS (`:21541-21551`).
- `MmapEntry` bits 0-6 used; bit 7 free and survives fork (`fork_stripped` clears only
  TRANSIENT_MASK, `:11859-11861`) and mprotect Path A (`committed_flags_excluding_prot`
  `:11838-11845`); `debug_validate` tolerates it (`:11865-11883`). →
  `MMAP_REGION_FLAG_SHARED = 1 << 7`.
- **Frame ownership:** `PAGE_REF_COUNT` decides free-vs-keep at EVERY release site —
  `should_free_unmapped()` frees `Untracked` (`fork.rs:1391-1397`); munmap Phase 2
  (`syscall.rs:14294-14305`), AS teardown `free_leaf_frame` (`process.rs:9747-9757`), COW
  resolve (`fork.rs:1341-1344`), mprotect Path B / brk (`:12495/:15218`).
- **Fault-path discipline (the binding precedents):** RF178-12 — hold Process→MmState
  across the fault, EVERY lower acquisition try-only (`lock_ordering.rs:106-113`;
  `try_demand_grow_user_stack` `syscall.rs:12747-12771`); `FaultMemoryCharge::try_new` is
  the #PF-legal cgroup charge (RAII rollback receipt; "No blocking acquire is permitted
  from #PF, including for the root cgroup", `cgroup.rs:425-459`); R186-10 — COW's
  `CowFaultResult::Busy` → return-and-re-fault exists because treating transient contention
  as fatal was a cross-process DoS (`interrupts.rs:1189-1219`); demand-grow's caller KILLS
  on every Err (`terminate_self_and_halt(pid,139)`, `interrupts.rs:1301-1326`) — an
  UNCATCHABLE kill, not SIGSEGV, and the WRONG disposition to copy for a contended shared
  page. Usercopy arm runs BEFORE the demand arms (`interrupts.rs:1239-1280`) and EFAULTs
  without consulting demand-faultable ranges; kernel-mode direct deref of a not-present
  user page outside a usercopy window panics (`interrupts.rs:1316-1358`).
- **Charging/teardown coupling:** fork hard-charges every non-PROT_NONE entry's FULL length
  (`fork.rs:604-610`, `vm_charged_bytes` `:673`); exit/exec uncharge by length with only a
  PROT_NONE skip (`process.rs:9299-9309`, `syscall.rs:6575-6583`);
  `compute_cgroup_charged_bytes` migration basis (`process.rs:9811-9832`); teardown of
  mmap regions is gated on `mm_shared`/`keep_address_space` (`process.rs:9249-9362`);
  `uncharge_memory` to a deleted id is a silent no-op BUT `delete_cgroup` refuses while
  `mem_pinned != 0` (`cgroup.rs:3065-3075`) — so first-toucher residency makes the owner
  cgroup un-rmdir-able while any holder lives (ACCEPTED, user 2026-09-01).
- **Fork COW walker:** pure PT recursion, no VA, no MmState access, lockstep dual traversal
  with panic-on-divergence (`fork.rs:1006-1101, 1644-1850`); `!PRESENT` leaves already
  skipped (`:1702`); `commit_parent_cow` write-protects PARENT PTEs (`:1837-1850`) — the
  parent-side desharing hazard.
- **Sweep results:** `stress_runner.c` is the ONLY MAP_SHARED caller in the tree; fuzzer
  corpus is hardcoded `0x22`; the syz grammar file (`fuzz/syscall_descriptions/mmap.toml`)
  is UNCONSUMED by any code. procfs: two sites hardcode private (`syscall.rs:11786-11793`,
  `:11919-11940`). Futex keys are TGID-scoped (`ipc/futex.rs:403-406`) — no cross-process
  futex on shared pages (documented limitation; the smp guest uses raw atomic spinlocks,
  `stress_runner.c:645-650`, unaffected). exec refuses on shared AS (`:6144-6161`);
  single-thread exec clears the map wholesale with NO transient discipline (`:6671`).

## 3. Blast Radius

**Phase 1:** one validation arm in `sys_mmap` (after `:13628-13634`) + KCOV tag;
`stress_runner.c` pipe transport; procfs comment fix (`:11919-11922` claim becomes
conditional). Only the stress guest is affected (lens-verified). **Phase 2:**
`kernel_core/{syscall,process,fork}.rs`, `arch/interrupts.rs` + `usercopy.rs` (fault arm +
usercopy extension), `PAGE_REF_COUNT` (`fork.rs` refcount table), the three by-length
uncharge sites + `compute_cgroup_charged_bytes`, procfs `s` bit (both sites), new region
module. mremap note: any future implementation inherits side-map relocation.

## 4. Candidate Approaches

### Approach 1 — Two-phase: full-flags fail-closed now; PAGE_REF_COUNT-integrated shared-anon later (CHOSEN, amended per lens round)

**Phase 1 implementation:** the allowlist arm runs after the LSM hook and accepts
`MAP_PRIVATE|MAP_ANONYMOUS` and the Phase 2 `MAP_SHARED|MAP_ANONYMOUS` shape; every
other combination (including MAP_FIXED, MAP_SHARED without MAP_ANONYMOUS,
MAP_SHARED_VALIDATE and unknown bits) returns EOPNOTSUPP before VMA/cgroup/PT mutation.
`run_in_cgroup_child` now uses a bounded pipe with EINTR-safe exact write/read and EOF
checking. CPU worker reports use one pipe per child; the SMP/combined shared counter
still reaches the explicit Phase 2 boundary.

**Phase 2 (amended mechanism — the lens-driven deltas are marked ►):**

The current implementation provides the demand-fault region object: shared mappings carry a persistent `FLAG_SHARED`, reserve admitted page-slot metadata, and publish no data PTEs at mmap time. A first user or usercopy fault charges its cgroup, zeroes a frame, records the owner and maps it; later faults acquire one mapping reference. Fork copies shared region Arcs and writable leaves without COW, while munmap/exec/exit release the region pin after PTE teardown. Shared `mprotect` and shared `PROT_NONE` remain fail-closed. This is source-level Phase 2 implementation; guest and remote qualification are pending.

- `SharedAnonRegion { pages: AdmittedVec<Option<SharedPage>>, prot, page_cap }`;
  `MmState.shared_regions: AdmittedMap<usize, Arc<SharedAnonRegion>>`;
  `mmap_regions` entry carries `FLAG_SHARED`. ► **Per-region page cap** at map time
  (metadata = `region_pages × 16 B` is NOT bounded by MAX_MAP_COUNT — cap chosen so
  worst-case side-table metadata stays inside the CoreProcess class; fork re-asserts the
  side-map count like `fork.rs:625`).
- ► **Frame ownership = `PAGE_REF_COUNT`** (invariant 5): install stages the frame with
  refcount 1 held BY THE REGION + 1 per mapping PTE (stage at install; `stage_clone_refs`
  covers fork for present shared leaves only if not excluded — see fork rules). Existing
  release sites then do the right thing unchanged: a mapper's teardown decrements to
  `Shared`, never `Untracked`; the REGION's last-Arc-drop releases its own pin and frees
  only on `Last`. The "Option slot is the single source of truth" clause is DELETED.
- **mmap(MAP_SHARED|MAP_ANONYMOUS):** three-phase as today; Phase 1 inserts side-map Arc +
  flagged entry; no frames, no memory charge at map time. ► All five by-length charge/
  uncharge/migrate sites gain a `FLAG_SHARED` skip alongside their PROT_NONE skip
  (fork `fork.rs:604-610/:673`; exit `process.rs:9299`; exec `syscall.rs:6575`;
  `compute_cgroup_charged_bytes` `process.rs:9811`) — shared bytes are accounted ONLY by
  the per-page fault charge and released ONLY by the region's teardown.
- **Fault path (first touch), RF178-12 shape:** ► HOLD Process→MmState across the whole
  fault (no drop-then-reacquire; kills the R145-1 migration window and the
  check-drop-act munmap race — `PENDING_UNMAP`/transients are re-read under the SAME lock
  that resolves the region); every lower acquisition try-only: region lock `try_lock`,
  `FaultMemoryCharge::try_new` (RAII rollback), `try_with_current_manager`,
  `try_with_allocator`. ► Contention/`Busy` → `SharedFaultResult::Busy` → bare return and
  re-fault (R186-10 shape), NEVER the demand-grow kill. Slot present → map existing frame
  (+1 ref), no charge. Slot absent → charge (receipt) → zeroed frame → stage refs →
  record `SharedPage{frame, owner}` → map → commit receipt.
- ► **Usercopy (MC-4):** `try_handle_usercopy_fault` gains a shared-region arm — a
  kernel-mode fault on a registered usercopy range that lands in an unfaulted shared page
  attempts the same try-only install before falling back to EFAULT. ► Kernel direct-deref
  of user shared pages outside usercopy windows remains a panic by kernel contract —
  DOCUMENTED constraint: kernel code touches user shared pages only via usercopy (futex/
  robust-list/signal-frame paths already comply; asserted in review).
- **fork:** ► shared-range list pre-snapshotted under MmState BEFORE PT_LOCK and passed
  into `copy_page_table_cow` (signature + VA-tracking extension of the recursion);
  exclusion applied in `plan_clone_level` (so `stage_clone_refs` and both traversals stay
  lockstep — same plan, no divergence panic); child PTEs for shared ranges: ► mapped
  DIRECTLY to the region frames (+1 ref each) rather than left absent — simpler than
  re-faulting and keeps `commit_parent_cow` from ever seeing them; ► parent PTEs in shared
  ranges are NEVER write-protected/COW-marked (invariant 3, both directions); debug assert:
  no `FLAG_SHARED` leaf carries `cow_flag()` after fork. Fallible parts hoisted above the
  `fork.rs:788` commit point.
- **munmap/exec/exit:** whole-region only (partial → EINVAL); ► teardown gated on
  `mm_shared`/`keep_address_space` exactly like the existing mmap-region teardown
  (`process.rs:9249/9297/9353/9362`); ► the region Arc is moved OUT of every
  Process/MmState/PT critical section into a named local and dropped after the block
  (explicit `drop(region)`); ► teardown from allocation-failure/OOM context (MC-9) is
  deferred to the reaper path (never inline under the faulter's own region lock);
  ► single-thread exec's wholesale clear arms the same transient discipline the fault path
  re-reads (exec sets a MmState-visible in-flight gate before clearing; the fault's
  under-lock re-read observes it — MC-8).
- **procfs:** both sites (`:11786-11793` perms byte, `:11919-11940` comment+decode).

**Safety proof (amended):** (a) isolation — naming leg unchanged (inheritance-only; no
ptrace/proc-mem surface exists, lens-verified); frame leg now single-owner
(`PAGE_REF_COUNT`): every release path decides via refcount, region pin prevents premature
`Last`, N+1-free is structurally impossible; (b) lock order — the fault follows RF178-12
verbatim (hold MmState, try-only below); no new lock appears in any inventory-violating
position; teardown frees outside critical sections by construction (named-drop);
(c) accounting — charge via receipt (auto-rollback on any early return), by-length sites
skip FLAG_SHARED, so charge/uncharge both happen exactly once per page at fault/teardown;
migration transfers exclude shared bytes (owner stays the first-toucher; EBUSY consequence
accepted and documented); (d) COW honesty — invariant 3 enforced on both sides + debug
assert; (e) DoS — page cap + admission bound metadata; Busy re-fault bounds forward
progress without kills.

**Edge cases (amended set):** (1) two CPUs fault one slot — MmState serializes resolution;
region try_lock loser → Busy re-fault; single charge; (2) charge failure → receipt
rollback, fault fails per demand semantics (no install); (3) fork vs in-flight fault —
fault holds MmState; fork's Phase-1 snapshot waits (fork_in_progress vs fault ordering
under the same lock — no window); (4) munmap racing fault — same-lock re-read of
PENDING_UNMAP (no drop window exists anymore); (5) exec/exit mid-fault — MC-8 gate,
same-lock visibility; (6) creator exits first — charge stays on owner; rmdir-EBUSY
documented; (7) OOM during install — receipt rollback; teardown-from-OOM deferred (MC-9);
(8) metadata admission failure at map — clean three-phase rollback; (9) PROT_NONE/mprotect
on shared, partial munmap, MAP_FIXED-over-shared — EINVAL slice boundaries (MAP_FIXED
already EOPNOTSUPP at Phase 1); (10) smp guest pattern — parent+children spin on one frame
via raw atomics; faults serialized per (1); `spins > 0` observable; (11) usercopy into
unfaulted shared page (read/waitpid/clock_gettime targets) — MC-4 arm installs then
copies; (12) region at cap / MAX_MAP_COUNT boundary — map-time rejection; (13) zombie
holds last Arc — teardown deferred to reap (safe direction; pins cgroup, accepted);
(14) CLONE_VM — one MmState ⇒ one side map ⇒ correct sharing + counting; teardown gate (6)
covers sibling exit.

### Approach 2 — Direct-to-feature / Approach 3 — Amend smp contract — REJECTED (unchanged)

### §4.1 Verification addendum (2026-09-01, BINDING — closes the verify lens's residuals)

1. **`PAGE_REF_COUNT` acquire API (A1/A2).** No acquire path exists today (`release` is the
   only public method, `fork.rs:1609-1614`; `stage_slot` rejects shared-shaped frames
   `:1434-1458`). Phase 2 ADDS a typed pin/acquire API: refuses `COW_UNIQUE_CLAIMED`;
   `checked_add` overflow ⇒ fail the install; `slot() == None` (outside the managed
   window, `:1410-1422`) ⇒ FAIL the install, never silently skip (a phantom pin is a
   permanent leak). Fork's direct-map refs join the fork transaction ledger
   (`rollback_clone_refs` extension or a parallel shared-ref ledger unwound on ANY
   post-pass failure — `create_kpti_user_pml4`/`stage_clone_refs`/`free_address_space`
   paths `fork.rs:1056-1078, 803-811`); region code uses ONLY the typed API (the raw
   `cow_refcount_slot` at `mm/memory.rs:1153` is out of bounds — invariant 5 enforced,
   not asserted). Recorded property: a mapped shared frame has refcount ≥ 2, so
   `claim_unique_slot` can only return `Shared` for it — `COW_UNIQUE_CLAIMED` is
   structurally unreachable on shared frames.
2. **Fork exclusion is DUAL-SITE + release-checked (A3/A4).** The exclusion predicate
   (pre-snapshotted shared-range list) applies identically in `plan_clone_level` AND
   `build_child_clone_level` (both need the VA tracking); the entry-pointer/addr
   divergence checks (`fork.rs:1776-1784, 1847`) are upgraded to release-build checks for
   shared-excluded ranges (a silent one-sided skip in release = wrong-frame child mapping,
   cross-AS disclosure). The child's direct-map pass for shared leaves is a third pass
   INSIDE the `with_pt_lock` closure, above `commit_parent_cow` (`fork.rs:1082-1084`).
3. **Region lock formalized (B1-B3).** `SharedAnonRegion` gains interior mutability
   (`pages` behind its own lock — the bare struct has none, so "region try_lock"
   currently names nothing); the lock gets a named inventory row + level in
   `sched/lock_ordering.rs` (below MmState, above PT in acquisition order; try-only from
   #PF), and `lock_ordering.rs:109-110` is amended to scope "Level-5 guards dropped
   before PT_LOCK" to the CGROUP guards (the demand-grow precedent at
   `syscall.rs:12806-12809` already holds PCB+MmState across PT). **Forbidden edge:**
   region-lock acquisition under PT_LOCK — shared-aware teardown never touches region
   slots inside `with_current_manager` blocks (munmap Phase 2 `syscall.rs:14265-14335`,
   Path B `:12484-12505` release refs per-PTE only).
4. **Munmap rollback + usercopy disposition (B4/B5).** The munmap rollback leg
   (`syscall.rs:14337-14350`) symmetrically RESTORES the side-map Arc if Phase 1 moved it
   out (no live FLAG_SHARED entry without a side-map Arc). MC-4's kernel-mode fallback is
   RETRY (return-and-re-fault / bounded ExecRetry at the syscall layer), NEVER EFAULT on
   transient contention (region try_lock loss, PT contention, `FaultChargeError::
   Contended`) — EFAULT on kernel-mode legs relocates the R186-10 kill class onto
   usercopy (the sigframe `copy_to_user` Err path terminates, `syscall.rs:8708-8713`).
   Same-CPU reentry guard analogous to `interrupts.rs:1204-1210` on the shared arm (first
   #PF path taking Process+MmState from kernel mode).
5. **Uncharge single-anchor + complete site inventory (C1-C3).** Shared bytes are
   uncharged ONLY by the region's last-Arc-drop — `mm_shared`/`keep_address_space` gates
   decide Arc RELEASE, never bytes (the `process.rs:9297` gate discriminates MmState
   sharing, not region sharing; forked parent+child each have strong_count==1 → a gated
   uncharge would run twice). FLAG_SHARED skips extend to the FULL by-length inventory:
   munmap Phase 3 `syscall.rs:14396-14399` (the constructible 1 MiB-uncharge-for-4 KiB-
   charge site), map-time charge+rollbacks `:13783/:13808/:14034` (shared arm charges
   nothing), exec `:6575`, exit `process.rs:9299`, migration basis `:9811`, brk
   `:15283`/ExecSpaceGuard `:6391` (reachability-checked at implement). mprotect on
   FLAG_SHARED gets a HARD early reject arm (implementation item, not just edge case 9 —
   Path A/B charge machinery `syscall.rs:14781-15099` must be unreachable for shared).
   The region Arc leaves `free_process_resources` via the R154-3 hand-back-to-caller
   pattern (`process.rs:9367-9369` precedent) — its Drop (buddy free + registry uncharge)
   never runs under the Process lock. Explicit invariant: the per-page shared charge
   folds into NO MmState scalar (keeps `compute_cgroup_charged_bytes` shared-free).
   `fork.rs:673` removed from the site list (scalar diagnostic copy, nothing to skip);
   the real fork lump is `:779-783` fed by `:604-610`.

## 5. Comparison Matrix, Decision Record & Recommendation

| Criterion | A1 two-phase (amended) | A2 direct | A3 amend contract |
|---|---|---|---|
| Safety | immediate honesty + single frame owner | delayed | weakened gate |
| Correctness | smp as specified | later | no |
| Efficiency | P1 unblocks 4 profiles' reporting | nothing early | cheapest, wrong |

**Decision Record (grilling loop, 2026-09-01):**

| # | Question | Recommended | User decision | Consequence |
|---|---|---|---|---|
| 1 | Disposition | Two-phase | **Two-phase** | Dep map: `memory` ← ST-K3 + K2-P1 (joint gate); `smp` ← K2-P2 |
| 2 | Charging (P2) | Charge creator at map | **First-toucher per page** | Demand-paged; per-page owner |
| 3 | Phase-1 scope (post-lens: whole flags word unvalidated; MAP_FIXED also lies) | Validate all flags | **Validate all flags** | Allowlist arm after LSM hook; only stress_runner affected |
| 4 | First-toucher liveness (post-lens: owner cgroup un-rmdir-able while holders live) | Keep + accept documented EBUSY | **Keep + accept EBUSY** | Documented limitation + follow-on re-homing row if it bites |

## 6. Defense-in-Depth Plan

1. Phase-1 allowlist — the silent-semantics class dies for EVERY flag, not one.
2. `PAGE_REF_COUNT` single ownership + region pin — double-free/UAF structurally closed.
3. Receipt-based charging (`FaultMemoryCharge`) — leak-free on every early return.
4. Same-lock transient re-reads (no drop window) + MC-8 exec gate — TOCTOU class closed.
5. Busy re-fault (R186-10 shape) — contention is never fatal.
6. Page cap + admission + fork re-assert — bounded metadata.
7. Slice-boundary EINVALs loud; debug assert on COW-marked shared leaves.

## 7. Implementation Plan

**Phase 1:** `syscall.rs` allowlist arm (+ KCOV, `// ST-K2 FIX:`); `stress_runner.c` pipes;
procfs comment. **Phase 2 (order):** region module + flag bit + page cap → mmap arm →
fault arm (interrupts.rs + usercopy.rs + syscall.rs handler, RF178-12 shape) → fork
snapshot/exclusion/direct-map → by-length site skips + migration basis → teardown gates +
named-drop + MC-8/MC-9 → procfs → tests. Premise re-verifications at implement:
`FaultMemoryCharge` API surface; `PAGE_REF_COUNT` staging entry points; exec-gate shape.

**Dependencies:** Phase 1 after ST-K3's fix (joint memory-profile gate; hoisted ahead of
ST-K4 — user order repair); Phase 2 after P0-A closure.

## 8. Test & Verification Plan

| Test | Oracle |
|---|---|
| Hosted MM tests (P2) | charge/uncharge delta symmetry across map→touch→fork→touch→unmap sequences; double-fault single-charge; teardown frees exactly N frames ONCE (refcount ledger assert); fork: no FLAG_SHARED leaf COW-marked |
| Runtime gating test (hard-FAIL polarity) | parent+child shared counter == sum via real fork (no COW divergence in EITHER direction); usercopy leg: `read()` into unfaulted shared page succeeds |
| Phase-1 guest run | memory/cpu/process profiles emit real counters via pipes (joint gate with ST-K3); MAP_FIXED and MAP_SHARED both fail-close with errno=95 |
| smp profile (P2 acceptance) | first validated `smp` PASS+HEARTBEAT with `spins > 0`, `validate-log` exit 0 captured |
| Full remote ladder + `make test-kcov` | PASS; new arms covered |

## 9. Open Questions

- Cross-process futex on shared pages — recommendation: out of scope (TGID-keyed futexes;
  smp guest needs none); future item when a consumer exists (non-blocking).
- Owner re-homing at last-drop (EBUSY mitigation) — recommendation: follow-on row only if
  operational pain materializes (non-blocking; accepted limitation).
- MAP_SHARED_VALIDATE distinct errno — recommendation: same EOPNOTSUPP (non-blocking).

## 10. References

`syscall.rs:6144-6161, 6575-6583, 6671, 11673-11940, 12747-12771, 13572-14167,
14294-14305, 21541-21551` · `fork.rs:84, 313-321, 375, 604-673, 788-803, 1006-1101,
1341-1397, 1558-1850` · `process.rs:9249-9362, 9747-9757, 9811-9832` · `cgroup.rs:425-459,
2986-3075, 3938-3965` · `interrupts.rs:1189-1358` · `usercopy.rs:1051-1081` ·
`ipc/futex.rs:403-406` · `lock_ordering.rs:61-113, 165-199` · `stress_runner.c:573-660` ·
lens reports 2026-09-01 · R121-4, R145-1, R149-6/R168-1, RF178-12, R186-10, R158-7, J.2

## Deviation & Amendment Log

| Date | Author stage | Section(s) | What changed & WHY | Safety impact | Counterparty verdict | User re-confirmation |
|---|---|---|---|---|---|---|
| 2026-09-01 | 4 next-phase (pre-READY) | §§1-8 | Lens round: Phase 1 widened to full-flags allowlist (user); Phase 2 mechanism amended — PAGE_REF_COUNT single frame ownership (was: region-owned frames, an N+1-free UAF), RF178-12 hold-MmState try-only fault with Busy re-fault (was: drop-and-block, a kill-on-contention + dangling-PTE race), FaultMemoryCharge receipts, FLAG_SHARED skips at all five by-length accounting sites, teardown gates + named-drop + MC-8 exec gate + MC-9 OOM deferral, usercopy arm, per-region page cap, fork direct-map exclusion with debug assert; first-toucher EBUSY consequence accepted (user). | closes 3 UNSAFE proofs (frame UAF, lock-order, accounting) + 9 missing cases | safety lens UNSAFE(a,b,c) + edge lens 9 MISSING → all dispositioned; naming-isolation leg and CLONE_VM counting verified SOUND | **Yes — 2026-09-01 (K2-P1 scope + K2 charging questions)** |
| 2026-09-01 | 4 next-phase (pre-READY) | §4.1 (new, binding) | Repair-verification lens: release arithmetic + munmap install-race closure + MC-8 + migration all CONFIRMED; residuals folded in as binding spec — PAGE_REF_COUNT acquire/pin API (none exists; fail-closed on unmanaged/claimed/overflow) + fork shared-ref ledger; dual-site release-checked fork exclusion + third-pass child mapping site; region lock formalized (interior mutability, inventory row, no-acquire-under-PT_LOCK, lock_ordering.rs:109-110 doc amendment); munmap-rollback side-map restore + kernel-mode retry-not-EFAULT + same-CPU guard; uncharge single-anchored to region last-Arc-drop with the COMPLETE site inventory (adds munmap Phase 3 :14396-14399 — constructible over-uncharge — and the mprotect hard-reject arm) + R154-3 hand-back. | closes a memory.max-bypass over-uncharge, a permanent-pin leak class, and a release-build cross-AS disclosure path | verify lens: 0 CLOSED → all residuals specified; direction confirmed | not required (technical spec completion; two-phase + first-toucher stand) |
| 2026-09-13 | 5 kernel-implement follow-up | §§4.1,7,8 | Current-source implementation added the eager shared flag/refcount/fork slice. A review of the child construction path corrected the remaining use of private `cloned_leaf_flags`: shared leaves now preserve their original writable flags, `apply_leaf` leaves the parent untouched, and the COW self-test asserts both properties. | Restores the dual-sided no-COW invariant for the implemented shared leaves without changing the refcount rollback ledger; first-touch, side-map, usercopy, migration and complete teardown remain pending. | Local kernel_core test/check and formatting PASS; independent full Phase-2 review and guest/remote qualification pending. | no new decision required |
| 2026-09-13 | 5 kernel-implement | §§4.1,7,8 | Implemented the admitted SharedAnonRegion side-map and first-touch fault path with fixed-storage PT allocator; fork inherits Arcs, teardown drops regions after PTE release, and the shared mmap arm is demand-paged. | Data charges are taken before PTE publication and retained by the region owner; contention returns Busy for retry; metadata and capability limits remain bounded. | Local kernel/MM checks PASS; guest SMP/usercopy and remote ladder pending. | no new decision required |
| 2026-09-14 | 5 kernel-implement follow-up | 4.1,7,8 | Synchronized the exact final `capabilities.rs` and revalidated the shared-fault cleanup hardening on `40c-devbox-ts` in `/tmp/zero-os-codex-final-20260913`; MM 26/26, kernel-core 68/68, build and lint pass, runtime/boot/4-core SMP are zero-failure qualified. | Final source identity is tied to `fork.rs` `d6ffc1e6076f8b4fae699aa3af66f35a19ebb19121fd29916e3bc2511a8b033c` and `capabilities.rs` `dd097a1d994b475219919a415e4513dc33c52686a89e9811f01501d9f4fa7061`; unsupported guest/platform contracts stay fail-closed. | final-tree remote verification PASS for implemented scope; guest usercopy/teardown/failure and musl qualification pending | no new decision required |
| 2026-09-14 | 5 kernel-implement follow-up | 3,8 | Added the first EXECUTED oracle for the shared-anonymous metadata/ownership model: `SharedAnonRegion` now has hosted tests for the page-count admission bound, the all-slots-empty initial state, out-of-range slot reads, and the `with_slots_try` window. Previously no gate executed any `SharedAnonRegion` assertion — the only coverage was the guest integration side-table self-test, which `make test-hosted-subcrates` compiles without running. | The bounded-length admission and the demand-paged "no frame before first touch" invariant are now falsifiable on every hosted CI run. Verified en route: the static `1 << 20` page cap is an UPPER bound, not a reachable size — the `CoreProcess` heap admission (`512 * 1024` soft, `heap_admission.rs:124`) refuses the ~16 MiB side table long before the cap binds. | Local `cargo test --features host_harness` 71/71 pass; remote hosted re-verification recorded with this revision. Guest usercopy/teardown/failure and musl markers remain pending. | not required (test-only addition; no mechanism change) |
| 2026-09-14 | 5 kernel-implement follow-up | 3,8 | Added the first GUEST-executed oracle for the shared-anonymous model: the Ring-3 fixture (`userspace/src/syscall_test.rs`) now maps a `MAP_SHARED\|MAP_ANONYMOUS` page, forks, has the child publish through it, and asserts the parent observes the write — plus the shared-VMA `mremap` refusal. Run by `make test-ring3-mm`. | The inheritance-only sharing property (child write visible in the parent, i.e. NOT COW) is now falsifiable on every run of that gate, not just by review. | Ring-3 oracle passes with `Results: 8 passed, 0 failed` and PID 1 exit 0. The gate is separate from `make test` because this workload demand-faults by design and the boot harness bans `[PF ENTRY]` outright. Open: the run emits two handled `[PF ENTRY]` lines (err=0x4, err=0x7); the second is the ordinary post-fork COW class (the write+protection-violation arm handles it first), the first is not attributed — no CR2 in a release build. Guest usercopy/teardown/failure and musl markers remain pending. | not required (test-only addition) |
| 2026-09-14 | 5 kernel-implement follow-up | 3,8,9 | The new Ring-3 teardown oracle found a real accounting defect in the shared-anonymous fault path. Measured on the final revision (`memory.current` read from the guest): one shared first touch charges THREE pages (1 data + 2 page-table), and `munmap` returns exactly ONE — the data page. The fault path parks its page-table charge in the per-AS `pt_inherited_bytes` basis (`fork.rs:1946-1953`), which is released only at process exit/exec (`free_process_resources`, `syscall.rs:6798` at exec), never at `munmap`: the munmap leg reconciles only the frame ledger (`pt_ledger_reconcile`), and the region `Drop` uncharges `0x1000` per materialized page — data only. The inline comment at `fork.rs:1948` says "reclaimed wholesale at munmap/exit"; only the exit arm exists. | Over-count and bounded, so it cannot bypass `memory.max` (fail-closed direction), but a long-lived process cycling shared mappings accrues unbounded `memory.current` drift until it exits, which can make unrelated allocations hit `memory.max`. Contradicts the §1 invariant "uncharged exactly once ... at true last-release (amount-symmetric)". | NOT FIXED in this pass: attributing the region page-table charge needs a per-owner model (a forked child can become a page first-toucher, so the region can span cgroups) plus an INVARIANT I reconciliation — a design change to the ST-K2-P2 ownership model requiring its own independent review. The oracle now BOUNDS the residue (`<= before + 3 pages`) and prints it, so a data-page regression still fails and the defect stays visible instead of being encoded as expected behavior. | no new decision required |
| 2026-09-14 | 5 kernel-implement follow-up | 3,4.1,8,9 | FIXED the SHARED-PT-RESIDUE accounting defect the Ring-3 teardown oracle found (user-authorized 2026-09-14, review to be recorded as pending). `SharedPage` gains `charged_bytes` — the page data frame plus the page-table frames that materialized it; the first-touch fault now stores `actual_charge` on the slot instead of parking the page-table part on the per-AS `pt_inherited_bytes` basis, and the region `Drop` releases `page.charged_bytes` rather than a constant 0x1000. A later toucher of an already-resident page adds its tables to the slot when it IS the page owner, and otherwise keeps the previous fixed-inherited-basis fallback (reachable only where fork did not pre-map the shared leaf writable), so INVARIANT I equalities hold on every branch and `mem_pinned` telescopes at region teardown rather than at process exit. | A shared mapping now returns everything it charged: measured 3 pages charged, **3** returned (was 1 of 3, with 2 resident until exit). Removes an unbounded-per-process `memory.current` drift that could trip `memory.max` for unrelated allocations in a long-lived process cycling shared mappings. `mm_state.pt_charged_bytes` no longer carries the shared page-table charge, so exit-time uncharge is consistent and nothing is double-released. | Ring-3 oracle tightened from a bounded residue to full release and prints the counter each run. **Independent review of this ownership change is pending** — the same posture the mremap slice carries. Local kernel check/format and the hosted suites pass | 2026-09-14 user decision: fix it, record review as pending |
