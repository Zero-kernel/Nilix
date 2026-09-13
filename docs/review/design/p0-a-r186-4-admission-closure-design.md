# P0-A — R186-4 / D1-RES-HEAP-ADMISSION-REOPENED Mechanism Re-Review & Closure Design

**Date:** 2026-09-01
**Plan item / Finding:** P0-A = R186-4 (HIGH, sole open gate blocker) + design parent D1-RES-HEAP-ADMISSION-REOPENED — `docs/review/nextplan/next-phase-plan-2026-09-01.md`
**Status:** IMPLEMENTED (final remote source verified, 2026-09-13); local and remote MM/kernel-core oracles pass, build/lint pass, and runtime/boot/SMP remain qualified; musl guest markers are incomplete. The induced COW/PT/child-publication cleanup oracle, map mismatch error path and constructor owner ordering pass with two independent U23 lenses; the intentional CorruptState fail-stop policy remains explicitly bounded.
**Current handoff:** [source refresh](next-handoff-2026-09-12.md#3-p0-a--r186-4--current-allocation-and-ownership-premises) preserves the accepted mechanism/charge decisions and reconciles the later KSA cleanup paths. The 2026-09-13 implementation reserves fork snapshot admission before allocation, transfers one reservation into the admitted map, removes infallible shrink, and hardens the VMA runtime oracles. The follow-through also makes map backing replacement return `CapacityInvariant` while preserving the live map and replacement charge. The exact final source is remotely verified in `/tmp/zero-os-codex-final-20260913` on `40c-devbox-ts`; strict release qualification remains pending only for the documented musl/guest marker and broader platform boundaries.
**Mode:** MODE S (Codex MCP absent; counterparty = three fresh-context lenses per doc)
**Designed by:** stage 4 next-phase (grilling)
**User confirmation:** confirmed 2026-09-01 (Q-FINAL; Decision Record rows 1-3 individually confirmed same day)
**Amendment mode:** normal — decision-points only
**Sources:** `next-phase-plan-2026-08-01.md` §P0-A (v15.59), R186 audit `qa-2026-07-28.md`, R188 audit `docs/security/full-codebase-audit-2026-08-07.md` (U23-1/U23-2), `reviewfix-2026-07-30.md` (FA-09/FA-04 lineage)

## 1. Requirement & Threat Model

**Goal:** close R186-4 — VMA/MM metadata (`mmap_regions`, `pt_charged_frames`) must sit inside
whole-heap aggregate admission — with a **re-verified mechanism** (user decision P0-A.1:
re-open the mechanism review rather than closure-only) plus the outstanding test/convergence
gates, so `D1-RES-HEAP-ADMISSION-REOPENED` resolves and the zero-HIGH streak can restart.

**Invariants:**
1. Every growth site of both maps is admission-gated (no unadmitted kernel-heap growth).
2. Charge/uncharge are **amount-symmetric** over any operation sequence (FA-09/FA-04: an
   amount-asymmetric charge family produces a PERMANENT resource block — strictly worse than
   the over-count it replaces).
3. Admission failure surfaces as an error to the caller — never a panic on a reachable path
   (U23-1/U23-2 class).
4. Gating tests for this mechanism are binary PASS/FAIL (P1-A polarity).

**Threat model:** a hostile or runaway process growing VMA metadata (R130-1 DoS lineage) must
hit the aggregate gate; a compromised charge path must fail closed without wedging global
accounting.

## 2. Current-State Analysis (re-derived 2026-09-01)

- `struct MmState` opens at `kernel_core/process.rs:1179`;
  `mmap_regions: mm::AdmittedMap<usize, MmapEntry>` at `process.rs:1212`;
  `pt_charged_frames: mm::AdmittedMap<u64, ()>` at `process.rs:1274` — keyed by the frame's
  physical address **as `u64`** (`frame.start_address().as_u64()`, call sites
  `syscall.rs:14103/:14140`), so per-entry charge sizing is `size_of::<(u64,())>() = 8`.
  P0-A-1..8 implementation record (traits, try_insert/remove, range_mut, fork
  `from_sorted_vec_charged` with the historical `shrink_to_fit` at `mm/admitted.rs:1011` — the shrink
  strictly precedes the `vec_charge_bytes(capacity)` computation at `:1013`, which is what
  makes the fork-amplification fix real) per plan v15.59 §P0-A — all sub-items
  COMPLETE/VERIFIED 2026-08-01.
- **R188 landed the U23 conversions (lens-verified 2026-09-01, all four lines exact):**
  `install_prepared_deferred` returns `Result<_, AdmittedAllocError>` on
  AdmittedVec/Deque/Map/Set (`mm/admitted.rs:246/675/1086/1358`); `mm/heap_admission.rs`
  helpers propagate `Result` (`:228/258/282/313/340/363`).
- **Full panic inventory (the re-review's explicit input):** `heap_admission.rs` retains 8
  panics — `:373/:379/:396/:399/:426/:429` (helper corruption fail-stops) **plus `:535`
  inside `Drop for HeapReservation` and `:609` inside `Drop for HeapCharge`** — panic-in-Drop
  is a distinct hazard class (teardown/unwind double-panic) the mechanism re-review must
  explicitly verdict, not just the callable-helper class. `admitted.rs` retains `:1102`
  (inside `AdmittedMap::install_prepared_deferred` — its failure condition
  `prepared.entries.capacity() < len` at `fallible_map.rs:234` is dominated by the guard at
  `admitted.rs:1090`, so it is argued unreachable; re-review re-verdicts), `:1130`, `:1247`.
- **Deliberate over-count (test-guard nuance):** `remove` to a non-empty map and
  `remove_retaining_capacity` (`admitted.rs:1187`) retain the FULL capacity charge by design —
  the safe direction vs the FA-09/FA-04 permanent-block class. §4's delta assertions must be
  modeled on CAPACITY, not per-entry counts, or the pressure test will false-fail on this.
- **2026-08-01 convergence history:** 2 fresh sessions, 6 issues → 2 real fixed
  (fork `shrink_to_fit`, `expect→Result` in commit), 3 refuted, 1 test gap filled
  (`VmaForkCombinedLoadTest`, `runtime_tests.rs:422`). Final sign-off + ladder never ran —
  the plan's four unchecked boxes.
- **Pre-implementation test baseline (registered names, 2026-09-01):**
  `vma_heap_admission_coexistence` (`runtime_tests.rs:223`), `vma_heap_admission_pressure`
  (`:303`), `vma_fork_combined_load` (struct `VmaForkCombinedLoadTest` `:422`, `name()`
  `:426`; all three registered `:2085-2087`). Polarity and FA-09/FA-04 guard status: NOT yet
  hardened (the two unchecked plan boxes).
- `make test` baseline: 34 passed / 39 deferred / 0 failed (R188 handoff, 2026-08-27).

2026-09-13 implementation revalidation: `fork.rs` now reserves the exact snapshot charge before
`Vec::try_reserve_exact`, and `from_sorted_vec_with_reservation` resizes to actual capacity,
checks sorted keys and commits one retained charge. The three registered VMA tests now exercise
live class lanes, pressure rejection and cleanup. The historical observations above remain the
pre-implementation rationale; the induced COW/PT/child-publication failure oracle is now covered by 搂8.

## 3. Blast Radius

- Mechanism re-review: READ-ONLY unless a CONFIRMED defect is found (then: amendment + fix
  under this item at HIGH floor).
- Test hardening: `kernel/src/runtime_tests.rs` only (three tests). No kernel ABI change.
- Shared files with ST-K3 Family B (admission publication at boot) — if ST-K3's diagnosis
  implicates site B, THIS item's mechanism verdict governs; sequence P0-A re-review first.

## 4. Candidate Approaches

### Approach 1 — Closure-only (tests + sign-off, no mechanism re-review) — REJECTED BY USER

Was the stage-4 recommendation (mechanism already R188-hardened and independently verdicted by
the upcoming R188 review-fix). **User decision P0-A.1 (2026-09-01): rejected** — the sole
gate-blocking HIGH warrants its own mechanism re-verdict inside this item rather than relying
on the R188 round's breadth. Recorded; no further argument carried.

### Approach 2 — Mechanism re-review + defect repair + closure — CHOSEN

**Round-1 re-review result (2026-09-01, fresh-context REFUTE lens):** the API surface is
structurally closed (no Deref, no raw map access, `insert_unique_reserved` refuses at
capacity, `:14345`'s discarded-Result re-insert is an in-place PENDING_UNMAP replace), and
exec/teardown amount-symmetry holds — but **three defects were CONFIRMED and are now IN
SCOPE at HIGH floor (user decision 2026-09-01):**

- **D1 — fork pre-admission allocation.** `fork.rs:628-631` builds the snapshot Vec with a
  raw `try_reserve_exact(region_count)` BEFORE `from_sorted_vec_charged` reserves admission
  (`:646-653`) — inverting the module contract (`admitted.rs:5-8`). Up to 64 KiB unadmitted
  growth per concurrent fork (R130-1 class). **Repair spec (edge-lens-refined):** add a
  hand-off constructor variant (`from_sorted_vec_with_reservation`) accepting the pre-held
  `HeapReservation` — the naive pre-reserve DOUBLE-reserves (the existing constructor
  reserves internally at `admitted.rs:1017`, and 65,552 B × 2 × 4 concurrent max-size forks
  == the whole 512 KiB CoreProcess class → wedge), and release-then-re-reserve inverts the
  bug into spurious ENOMEM under concurrency. The pre-reservation MUST be computed via
  `vec_charge_bytes::<(usize, MmapEntry)>(region_count)` (exact identity incl.
  `ALLOCATOR_LINK_SLACK` — any other formula is amount-asymmetric, an FA-09 defect inside
  the FA-09 repair); `region_count == 0` short-circuits BEFORE `try_reserve` (which errors
  `NotPublished` before its zero-return). Error-path dispositions enumerated and asserted:
  `try_reserve_exact` failure → armed-reservation Drop releases (note: under
  Process+MmState locks; `panic=abort` tree so the exposure is Drop-panic-on-corruption,
  NOT unwind double-panic — §2's framing corrected); constructor errors return the Vec and
  armed reservation together so callers drop backing before admission; later fork failures
  (charge/PT-clone) → charge owned
  by `child.mm`, released via `cleanup_partial_child` Drop chain (correct today,
  UNASSERTED — the D3 oracle adds an induced-PT-failure delta leg).
- **D2 — infallible realloc in the R186-4 fix itself.** `admitted.rs:1011`
  `entries.shrink_to_fit()` is the kernel's only `shrink_to_fit` → OOM diverges via
  `alloc_error_handler` (`main.rs:1497`) under the parent's MmState lock (AD-02 class).
  **Repair spec (refined):** delete the shrink; charge on the input's actual
  `entries.capacity()` (over-count-safe). Scope note: for the FORK caller capacity ==
  region_count exactly (`try_reserve_exact` + never-reaching-capacity extend, this
  allocator's shim returns exact sizes), so fork's charge is unchanged; the
  `runtime_tests.rs:479` caller deliberately passes 2× capacity and will now charge (and
  retain) 2× — the test is REWRITTEN under D3 to exact capacity, and the §4 fork-equality
  oracle becomes `child_charge == vec_charge_bytes::<(K,V)>(snap.capacity())` (parent-charge
  equality is structurally wrong: parents grow through doubling). Ride-along: the same
  test's `(0..100_000).collect()` leg is a latent 1.53 MiB infallible allocation against a
  ~2 MiB heap — converted to `try_reserve_exact` + `extend` (do not ship the abort class
  the repair removes).
- **D3 — dead test oracles + Warning-as-pass.** Const-vs-const assertions
  (`runtime_tests.rs:269-291/:509-513/:543-547` on `heap_budget_snapshot` consts); Warning
  at the fork-admission-failure leg (`:561`); dead pressure leg (`:331-342`); inverted
  reclamation oracle. **Repair spec (refined):** oracles on
  `mm::heap_class_snapshot(HeapClass::CoreProcess)` (pub, exported `mm/lib.rs:44`) with
  **lane-separated deltas** — `committed_bytes` and `reserved_bytes` asserted SEPARATELY,
  `reserved_delta == 0` at every leg boundary (commit/rollback are sum-preserving by
  construction, `heap_admission.rs:408`, so a sum oracle is blind to lane-mixing defects —
  the exact class that later fail-stops at `:535/:609`); **one-sided tolerance**
  (over-count legal, under-count fatal; symmetric ± windows recreate the unfalsifiable
  oracle) with negative-delta-safe arithmetic (no usize underflow); `:561` → Fail with a
  clean-baseline assertion at leg entry (registry-ordering guard); pressure leg sized past
  the 512 KiB cap WITH (i) an end-of-leg assertion that the class delta returns to 0
  before the test returns (the doubling window transiently needs ~1.5× and starves
  co-tenant CoreProcess consumers — `ProcessCreationTest` et al. run after it), (ii)
  clear/retain-on-full legs ordered against the retired-owner Drop (capacity legitimately
  stays charged between detach and drop); plus a `debug_assert` self-test leg for the
  composed `commit_pair`-fails + `rollback_commit`-fails path ("global committed ≥ own
  bytes at rollback" — written down instead of argued unreachable).

Then, on the repaired state:

1. **Mechanism re-review round 2:** two independent fresh-context REFUTE-prompted reviews of the
   admission stack as it stands post-R188 — `mm/admitted.rs`, `mm/heap_admission.rs`, and the
   consumer paths at their lens-verified sites: mmap `syscall.rs:13799` (+ pt_charged_frames
   insert loop `:14098-14123`), munmap (`fn sys_munmap` `:14168`; sites
   `:14217/:14245/:14345/:14392/:14410` — note `:14345`'s discarded-`Result` re-insert is an
   in-place PENDING_UNMAP replace that never grows, verified), mprotect (`fn sys_mprotect`
   `:14508-15400`; split gate `:14591`, classification reserve `:14600-14620`, entry writes
   `:14635-14692`, display-bit `range_mut` `:15391`), fork `fork.rs:646-654`, exec/teardown
   Drop chain (`admitted.rs:1224→1240→1250`) — against invariants §1.1-1.3, **plus the §2
   panic inventory (explicitly including the two panic-in-Drop sites
   `heap_admission.rs:535/:609` and the argued-unreachable `admitted.rs:1102`)**. Prompted to
   REFUTE "every growth site is gated and amount-symmetric"; CONFIRMED defects return to the
   user (decision point) and are fixed under this item at HIGH floor.
2. **Test hardening:** apply hard-FAIL polarity (P1-A rule) + FA-09/FA-04 guards to the three
   tests: assertions compare CHARGE DELTAS to UNCHARGE DELTAS over the operation sequence
   (never absolute exact-zero equality on live counters); missing preconditions (unpublished
   ledger, absent classes) FAIL rather than Warning.
3. **Convergence sign-off:** MODE S, 2 design + 2 review agents, REFUTE-prompted (plan-box
   protocol, user-confirmed P0-A.2), on the final mechanism+test state.
4. **Ladder:** full remote gates with all three tests in the passed set.

**Safety proof:** steps 1-4 are monotone — a re-review either confirms the invariants or
surfaces a defect that gets fixed and re-reviewed; test-guard changes cannot weaken the
mechanism (test-only files); amount-symmetric assertions specifically detect the FA-09/FA-04
hazard class (permanent block via asymmetric uncharge); polarity conversion turns silent
skips into visible FAILs.

**Edge cases (test legs):**
1. Coexistence: both maps growing under CoreProcess class near its cap — admission failures
   surface as Err; test asserts process survives and charges reconcile.
2. Pressure: reservation failure mid-sequence → symmetric rollback (delta assertion catches
   leaks in either direction).
3. Fork amplification: `from_sorted_vec_charged` capacity == entries (shrink_to_fit lineage);
   assert child charge == parent charge for equal content.
4. Exec clear + teardown: post-drop class counters return to the pre-test snapshot DELTA
   (baseline-relative, not absolute-zero — coexisting kernel activity is legal).
5. Concurrent interleave: existing multi-CPU legs remain D3 validation-breadth debt (carried
   P2 row) — explicitly OUT of this closure's scope (recorded; not silently narrowed).
6. Ledger unpublished (host harness): FAIL (polarity), matching RF187-6's publication-
   precondition lesson.

**Complexity/regression risk:** LOW-MEDIUM (test-only edits + reviews; risk concentrates in
"re-review finds something" — which is the point). **Performance:** none (tests + debug).

## 5. Comparison Matrix, Decision Record & Recommendation

| Criterion | A1 closure-only | A2 re-review + closure |
|---|---|---|
| Safety | relies on R188-RF breadth | **independent item-scoped verdict** |
| Correctness | tests hardened either way | same + mechanism re-verdict |
| Efficiency | fastest | +2 review passes |
| Performance | — | — |

**Recommendation stands as the user's choice: Approach 2.**

**Decision Record (grilling loop, 2026-09-01):**

| # | Question | Recommended | User decision | Consequence |
|---|---|---|---|---|
| 1 | Slice scope | Closure-only (A1) | **Re-open mechanism review (A2)** | Round-1 REFUTE review ran 2026-09-01 and CONFIRMED defects D1-D3 — the choice already paid for itself |
| 2 | Convergence protocol | 2+2 REFUTE MODE S + full ladder exit gate | **As recommended** | Sign-off recorded in this doc's amendment log; R186-4 flips CLOSED only after ladder green |
| 3 | Disposition of round-1 CONFIRMED defects D1-D3 | Fix all three under P0-A at HIGH floor | **Fix all 3 under P0-A** | fork admission-first snapshot, shrink_to_fit removal, live-delta test oracles + Warning→Fail all land in this slice |

## 6. Defense-in-Depth Plan

1. Mechanism gates themselves (admission + class caps + MAX_MAP_COUNT) — unchanged, re-verified.
2. Item-scoped REFUTE re-review (this doc) — catches what implementation-time convergence missed.
3. R188 Stage-3 review-fix (independent round) — second, breadth-scoped look at the same U23 paths.
4. Hardened tests — delta-symmetric + hard-FAIL polarity; regression-proof the class.
5. Next full audit round — R186-4's closure is re-checked before any streak credit (gate rule).

## 7. Implementation Plan

0. **Defect repairs (D1-D3, HIGH floor): APPLIED 2026-09-13.**
   - `kernel/kernel_core/fork.rs` reserves `vec_charge_bytes::<(usize, MmapEntry)>(region_count)` before the snapshot allocation and hands the armed reservation to the admitted-map constructor; zero-region forks bypass the ledger precondition.
   - `kernel/mm/admitted.rs` removes `shrink_to_fit`, validates sorted keys, resizes a transferred reservation to actual capacity, and commits it once as the retained charge.
   - `kernel/src/runtime_tests.rs` uses lane-separated one-sided deltas, hard-fail pressure rejection, retained-capacity checks, fallible oversized input and cleanup assertions.
1. Mechanism re-review round 2 (2 fresh-context REFUTE agents; inputs: §2 file list +
   invariants §1 + the §2 panic inventory incl. panic-in-Drop `:535/:609`, the composed
   commit_pair+rollback path, the `u32` ArithmeticOverflow precondition, and the per-class
   capacity-ratchet scenario [4 × retained ~128 KiB wedge CoreProcess]; output: findings
   ledger appended to this doc's log).
2. Convergence 2+2 (P0-A.2 protocol) on the final state.
3. Remote ladder: the exact final source in `/tmp/zero-os-codex-final-20260913` on `40c-devbox-ts` passes `make build`, `make lint`, MM 26/26, kernel-core 68/68, and the hosted allowlist (438 executions plus CpuLocal doctest and three compile checks); runtime 35/39/0, boot 28/46/0, and four-core SMP 37/37/0 are zero-failure qualified; `make musl-check` remains incomplete because required guest markers are absent.
4. Plan status sync: R186-4 and D1-RES are implementation-complete and remotely verified for the supported scope. The ledger `Drop` fail-stop boundary, musl guest markers, and strict platform qualification remain explicit limits.

**Dependency/ownership notes (extended 2026-09-01, user-confirmed):** runs AFTER the R188
Stage-3 review-fix. The single-owner rule covers `mm/admitted.rs` **and
`mm/heap_admission.rs` + its boot publication call sites**: if ST-K3's diagnosis lands in
the admission family, its fix waits for THIS item's verdict; if THIS item's reviews find the
boot-publication defect first, P0-A absorbs ST-K3's Family-B branch and retires it. **Any
post-closure edit to `admitted.rs`/`heap_admission.rs` REOPENS R186-4 pending a re-run of
§8** (false-gate-clear guard).

## 8. Test & Verification Plan

| Test/gate | Oracle |
|---|---|
| Mechanism re-review ×2 | Zero CONFIRMED unrefuted findings (else: user decision + fix + re-review); explicit verdicts on the two panic-in-Drop sites |
| Three hardened tests in `make test` (registered names `vma_heap_admission_coexistence` / `vma_heap_admission_pressure` / `vma_fork_combined_load`) | All in PASSED set; 0 failed suite-wide; deprived-precondition leg FAILs (polarity check, one host-harness run) |
| Convergence 2+2 | Four agents return no blocking objection; session IDs recorded in the log |
| Induced COW/PT/child-publication failure oracle | A malformed user leaf forces `copy_page_table_cow` to fail after child table preparation; parent flags stay unchanged, the child user half stays unpublished, and the buddy free-page count returns to baseline | PASS in integration boot gate; two independent focused reviews PASS; 0 failed tests |
| Remote ladder | Exact final source: build/lint/hosted/MM/core PASS; runtime, boot and 4-core SMP suites zero-failure qualified with documented deferred outcomes; musl incomplete because required guest markers are absent; strict release qualification remains pending |

## 9. Open Questions

No material choice blocks implementation. The induced COW/PT/child-publication cleanup oracle, map mismatch error path and constructor owner ordering pass locally and on the final remote source for the focused suites. Independent high and medium lenses agree that the ledger `Drop` paths can fail-stop only after prior counter corruption and are unreachable through the safe ownership API. Strict release qualification remains pending the documented musl/guest marker boundary.

## 10. References

`mm/admitted.rs` (:246/675/1086/1358/1018) · `mm/heap_admission.rs` (:228-400) ·
`kernel_core/syscall.rs` mmap/munmap/mprotect sites · `fork.rs:~646` ·
`runtime_tests.rs:272/342/424` · R186-4 spec (qa-2026-07-28.md) · U23-1/U23-2
(full-codebase-audit-2026-08-07.md §§9,13) · FA-09/FA-04 (fix-skills lineage) · RF187-6

## Deviation & Amendment Log

| Date | Author stage | Section(s) | What changed & WHY | Safety impact | Counterparty verdict | User re-confirmation |
|---|---|---|---|---|---|---|
| 2026-09-01 | 4 next-phase (pre-READY) | §4, §5, §7 | Round-1 REFUTE lens CONFIRMED three mechanism/test defects (D1 fork pre-admission alloc `fork.rs:628-631`; D2 infallible `shrink_to_fit` `admitted.rs:1011` = AD-02 abort class under MmState lock; D3 dead const-vs-const test oracles + Warning-as-pass `:561` + dead pressure leg + inverted reclamation oracle). User confirmed folding all three into P0-A at HIGH floor (Decision Record row 3). Single-owner rule extended to `heap_admission.rs` + boot publication; post-closure-edit reopen rule and ST-K3 Family-B absorption added. | mechanism fixes strictly strengthen fail-closed properties; test fixes make dead oracles live | safety-proof lens CONFIRMED (UNSAFE→scoped repairs); dependency lens G1-G3 CONFIRMED | **Yes — 2026-09-01 (Q P0-A defects + order repairs)** |
| 2026-09-01 | 4 next-phase (pre-READY) | §4 D1-D3 specs, §8 | Edge lens (rerun) refined the repair specs: D1 hand-off constructor (naive pre-reserve double-reserves → 4-fork class wedge; release-variant inverts to spurious ENOMEM; exact `vec_charge_bytes` identity; zero-region short-circuit; error-path disposition table; panic=abort corrects the unwind framing); D2 scoped to fork (test caller rewritten; fork-equality oracle corrected to `vec_charge_bytes(snap.capacity())`; 1.53 MiB infallible collect converted); D3 lane-separated one-sided negative-safe deltas + pressure-leg co-tenant/ordering guards + composed-rollback debug_assert. | repairs strictly tightened; two new wedge/starvation hazards closed pre-implementation | edge lens (rerun): 11 MISSING-CASE items → all dispositioned | not required (technical refinement below decided points) |
| 2026-09-13 | 5 kernel-implement | sec7-sec8 | Implemented admission-before-allocation fork snapshot, reservation handoff with actual-capacity resize, sorted-key validation, and the induced COW/PT/child-publication failure oracle with production `free_address_space` teardown; removed `shrink_to_fit`; hardened VMA admission tests. | no allocation occurs before CoreProcess admission; one reservation becomes one retained charge; failed child preparation leaves parent mappings unchanged and reclaims all private frames | independent source reviews and remote evidence: focused oracle verdicts PASS; build/lint/hosted/musl pass; runtime/boot/SMP qualified; CorruptState cleanup limits remain pending | no new decision required |
| 2026-09-13 | 5 kernel-implement | sec7-sec8 | Removed the remaining AdmittedMap replacement unwrap_or_else calls; a mismatch now returns CapacityInvariant and preserves the live map/charge or returns the original retired owner for rollback. | removes an allocation-free publication panic without weakening ownership; ledger Drop fail-stop behavior is unchanged and remains explicitly bounded to prior counter corruption | local fmt/check, kernel-core check and 25/25 MM tests pass; independent high-lens U23 mechanism review by `/root/r188_high_review` is PASS; a second lens found a charge-before-backing release order and the follow-up repair now drops backing first; map-path re-review PASS, constructor-owner re-review PASS, remote gates remain pending | no new decision required |
| 2026-09-13 | 5 kernel-implement follow-up | sec7-sec8 | Repaired the independent-review finding by dropping the detached replacement backing before releasing its committed charge on the map mismatch path. | preserves backing-before-charge accounting even when the guarded replacement invariant fails; no live map or old charge is displaced | local fmt/check and 25/25 MM tests pass; medium-lens map-path re-review PASS; remote gates remain pending | no new decision required |
| 2026-09-13 | 5 kernel-implement follow-up | sec7-sec8 | Updated map constructor errors to return the original Vec together with an armed reservation, and changed fork/runtime cleanup to drop backing before reservation. | closes the generic constructor backing-before-charge window without changing the successful handoff; high-lens API re-review PASS; remote gates remain pending | cargo check for kernel/kernel_core, cargo test kernel_core 67/67 and local MM 26/26 pass | no new decision required |

| 2026-09-14 | 5 kernel-implement follow-up | sec7-sec8 | Revalidated the exact final source in `/tmp/zero-os-codex-final-20260913` on `40c-devbox-ts`; synchronized the formatted capabilities source and reran MM 26/26, kernel-core 68/68, build, lint, runtime, boot and 4-core SMP. | The final hardening source is covered by remote evidence; runtime, boot and SMP have zero failures but retain deferred checks, and musl remains incomplete because guest markers are absent. | final-tree remote verification PASS for implemented scope; strict release qualification remains pending | no new decision required |