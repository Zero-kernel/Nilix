# ST-K4 — fsync/fdatasync/sync/sync_file_range: Device-Flush Durability Surface Design

**Date:** 2026-09-01 (v2 approach — device-flush; supersedes the same-day per-inode draft IN PLACE per the user's 2026-09-01 depth-flip decision; no separate -v2 file since the draft never reached READY)
**Plan item / Finding:** ST-K4 (P1, Preview-blocking via all-6-green gate; blocks stress `block` + `combined`) — `docs/review/nextplan/next-phase-plan-2026-09-01.md`; origin `docs/stress-gate-status.md` §6 K4
**Status:** DRAFT for the current tree (2026-09-12); historical September 1 design was READY FOR IMPLEMENTATION.
**Current handoff:** [source refresh](next-handoff-2026-09-12.md#5-st-k4--refresh-durability-against-file-objects-and-namespaces) supersedes the old numeric fd 0/1/2 and current-namespace lookup assumptions. Preserve the device-flush depth and four-syscall scope; update the full file-object/namespace/BIO contract and independent review before implementation acceptance.
**Mode:** MODE S (Codex MCP absent; counterparty = fresh-context lenses; safety + edge lenses ran 2026-09-01 against the per-inode draft and drove this rewrite; premise + verify lenses re-run on this version)
**Designed by:** stage 4 next-phase (grilling)
**User confirmation:** confirmed 2026-09-01 (Q-FINAL, incl. the guest-block-workload scope; Decision Record rows 1-3 individually confirmed same day)
**Amendment mode:** normal — decision-points only
**Sources:** `docs/stress-gate-status.md` §6 K4 + §9.3, plan v15.60, lens reports 2026-09-01 (safety: write-through/journal/lock-order; edge: M1-M12), ext3 series `e55e86d`, R188 mm commit `d6b2bb2`

The sections below retain the September 1 design and its historical line references.
In particular, `filesystem_for_inode`, numeric standard-fd treatment and the
single-effective-namespace assumption are obsolete. The September 12 handoff §5
is the controlling current-source amendment: bind flush to FileHandle/FileLifetime,
release process/registry locks before I/O and qualify the device's actual durability
capability. The four-syscall/device-flush decisions remain; current implementation
readiness is DRAFT until the full amended contract receives independent review.

## 1. Requirement & Threat Model

**Goal:** implement **74 `fsync`, 75 `fdatasync`, 162 `sync`, 277 `sync_file_range`** (user
ST-K4.1: all four) at **device-flush depth** (user 2026-09-01 depth-flip decision): a
successful return means the device's volatile cache holds no acknowledged data (flush
barrier) and the mount is not IO-poisoned. Page writeback is NOT part of this slice — under
this tree's write-through ext2 (§2), a dirty cache page is ALREADY durable, so there is
nothing pending for fsync to write.

**Invariants:**

1. `fsync(fd)` returning 0 ⇒ the fd's filesystem is IO-healthy AND a device flush barrier
   completed after the call began. (Data durability itself is guaranteed by the write path —
   §2; fsync's job here is the barrier + honest error reporting.)
2. fsync/fdatasync NEVER return 0 on a mount whose `io_faulted` poison is set (fail-closed).
3. A transient device-resource condition (virtio `Busy`/`NoMem`) is retried bounded and, if
   persistent, surfaces as EIO — it NEVER sets the mount poison from the fsync path (poison
   remains the write path's ambiguous-durability signal only).
4. No syscall in this family can bypass fd validation or reach another process's fds; all
   four are pledge/seccomp-dispositioned before they ship (M12).

**Threat model:** hostile fd values / non-file fds (EBADF/EINVAL, never panic or foreign
access); `sync_file_range` signedness + overflow arithmetic; flush-storm DoS (N concurrent
fsyncs exhausting virtio request slots must degrade to EIO, not poison the mount or wedge).

## 2. Current-State Analysis (re-derived 2026-09-01; lens-verified)

- **Slots 74/75/162/277 unbound** (flat match near `syscall.rs:3998`; ENOSYS fallback).
- **ext2 is write-THROUGH, not write-back.** `write_mutation` per chunk: data
  `write_block` (`ext2.rs:12277/12284`) → `flush_device()` (`:12281/12288`) →
  `commit_metadata_transaction` with the InodeUpdate (`:12286/12293`) → only THEN
  `publish_cached_write` → `PAGE_CACHE.mark_dirty` (`:12313/12140`). Ordered-data rule
  stated at `:12356-12357`. **A dirty page's bytes are already on the device**; the dirty
  bit means "recently written", not "pending".
- **The journal is inline and self-checkpointing.** `commit_metadata_transaction`
  (`ext2.rs:10176-10421`) journals, commits, checkpoints to home blocks, and clears the log
  synchronously before returning. There is no pending-transaction state for fsync to commit.
- **Poison model:** `io_faulted: AtomicBool` (`ext2.rs:5228`) / `ensure_io_healthy()`
  (`:5234-5241`), consulted by every data/metadata entry point; any `flush_device` error in
  the write path poisons the mount (`:12281-12284`).
- **Device flush:** `Ext2Fs::flush_device()` (`ext2.rs:9104-9106`) maps EVERY `BlockError`
  to `FsError::Io` — including virtio's transient `Busy` (no request slot,
  `virtio/blk.rs:1881`) and `NoMem` (DMA alloc, `:1896`). Flush serializes on the device
  lock (`blk.rs:1863`).
- **Existing writeback primitives have ZERO production callers** (`writeback_page*`,
  `writeback_dirty_pages` — only a self-test at `page_cache.rs:1565`); `mark_dirty` has
  exactly ONE caller (`ext2.rs:12140`); nothing in the tree clears dirty in production.
  Lens-flagged latent contract debt (filed as plan rows, NOT solved here): error-page
  silent refill while dirty (`page_cache.rs:1157` vs `:1106-1110`); LRU-detach window
  invisible to global writeback (`:849-863` vs `:1217-1229`); `WritebackStats` has no error
  channel (`:1188-1196`); umount does no sync/invalidation and `remove_from_cache` has no
  production caller (`manager.rs:697-711`, `page_cache.rs:764`); dirty pages are
  unreclaimable (`can_reclaim` `:263`) against a 256-page cap.
- **fd → (fs, inode) layering:** kernel_core's fd table yields opaque `FileOps`
  (`kernel_core/process.rs:397-460`); VFS syscalls go through registered callbacks
  (`VFS_* ` at `kernel_core/syscall.rs:2621-2649`) with the `FileHandle` downcast inside
  `vfs/manager.rs` — the working pattern is `vfs_truncate_callback` (`manager.rs:2800-2854`:
  get fd → downcast → clone inode → DROP process lock → act) + `filesystem_for_inode`
  (`manager.rs:1756-1773`, **current-mount-namespace scoped**, `CrossDev` on miss). There is
  no `VFS_SYNC` callback today — new callbacks + registration (`manager.rs:2379`,
  `kernel_core/lib.rs:215`) are part of this slice's blast radius.
- **fd 0/1/2 bypass:** read/write special-case std streams BEFORE fd-table lookup
  (`syscall.rs:10734-10772`; divergence rule documented `:20812-20815`).
- **Pledge/seccomp:** 74/75/162/277 appear in neither `DISPATCHED_PROMISED`
  (`syscall.rs:9935-9949`) nor the pledge filter; a pledged process calling an
  undispositioned arm is killed (`:3746-3770`); the R150-3 triple-edit rule is documented at
  `:9980-9991`.
- **Guest contract (lens-corrected):** `stress_runner.c` has NO fsync probe and NO block
  workload — `fail("fsync_unsupported", -ENOSYS, PROFILE_BLOCK)` (`:1160`) is a hardcoded
  `case …default:` arm keyed to a comment about kernel source (`:1156-1157`), not a runtime
  probe; no `NILIX_STRESS_V2_BLOCK` emitter exists in the guest. The validator's block
  oracle (`stress_protocol.py:900-905`, `:1037-1043`) requires `valid_slots == io_slots`,
  page-aligned `read_bytes`/`write_bytes`, `read_bytes ≥ io_slots × PAGE`; `io_ops` exists
  only in the `combined` marker (`:911`, sum≠0 gate `:1045-1049`). **Turning `block` green
  therefore requires a NEW guest block workload + host kill/recovery orchestration — IN
  SCOPE for this item as its acceptance component** (the plan's `block ← ST-K4` dependency
  is delivered by this item, both sides).
- **Poison scoping (corrected):** the mapped-block write path poisons on flush failure
  (`ext2.rs:12288-12291`); the hole/allocation path deliberately does NOT
  (`:12362-12367`, pre-commit unreachable block). Invariant 3 reads against the
  mapped-block path. Write-order cites: Path A `12284→12288→12293→12320`, Path B (hole)
  `12362→12365→12369→12391`; `mark_dirty :12140` and the ordered-data rule `:12356-12357`
  exact.
- **Flush semantics caveats:** on a device WITHOUT `VIRTIO_BLK_F_FLUSH` negotiated,
  `flush()` is a silent no-op returning Ok (`blk.rs:1859-1861`) — invariant 1's barrier is
  then vacuous; the ext2 fsync path surfaces the feature bit once (klog at first fsync)
  and §8 records it. Concurrent fsyncs CONVOY on the device mutex (`:1863`, also held by
  IO paths `:1448/:2042`) rather than exhausting `req_buffers` — the storm hazard is
  serialization latency, not Busy exhaustion (bounded retry stays for the reachable
  Busy/NoMem returns `:1881/:1896`).

## 3. Blast Radius

`kernel_core/syscall.rs` (4 arms + pledge/seccomp lists per R150-3 triple-edit),
`kernel/vfs/manager.rs` (new `vfs_fsync_callback`/`vfs_sync_callback` + registration),
`kernel/kernel_core/lib.rs` (callback exports), `kernel/vfs/traits.rs`
(`Inode::fsync(datasync)` default `Ok(())`), `kernel/vfs/ext2.rs` (fsync impl + `sync`
override + a transient-aware flush wrapper), `kernel/mm/page_cache.rs` (optional
clear-dirty-after-flush pass — see §4). Regions are disjoint from P0-A/ST-K3 edits; file
overlap with ST-K3 Phase D (`syscall.rs`) and R188's `d6b2bb2` (`page_cache.rs`) noted for
sequencing, not conflict. ABI strictly additive; volatile filesystems inherit the correct
`Ok(())` defaults.

## 4. Candidate Approaches

### Approach 1′ — Device-flush fsync (CHOSEN — user depth-flip 2026-09-01)

**fsync(fd) / fdatasync(fd)** (identical in this slice): syscall arm → std-stream gate
(fd 0/1/2 → EINVAL *without* fd-table lookup, agreeing with read/write's special-casing and
Linux's tty-EINVAL — kills the dup2-divergence hazard M11) → `VFS_FSYNC` callback →
truncate-pattern resolution (downcast `FileHandle`, clone inode, **drop process lock**;
downcast failure = EINVAL for pipe/socket kinds [not the truncate arm's ENOSYS — D5];
**O_RDONLY fds are VALID** [M10]; O_PATH → EBADF; directory fds VALID) →
`filesystem_for_inode` (namespace-scoped; `CrossDev` miss → EIO, documented Linux deviation
§9) → `Inode::fsync(datasync)`:

ext2 impl: `ensure_io_healthy()` (poisoned → EIO, invariant 2) → `flush_with_retry()`:
`dev.flush()` with `BlockError::Busy`/`NoMem` retried up to 4 attempts with spin-hint
backoff (bounded, RF187-5's four-attempt precedent); persistent → EIO **without setting
`io_faulted`** (invariant 3); other errors → EIO (poison stays the write path's call) →
optional per-inode clear-dirty pass (below). Nothing else is required: data + metadata are
durable at `write()` return (§2).

**Clear-dirty-after-flush pass (accounting hygiene, sound by construction):** because dirty
⇒ already-durable in this tree, after a successful flush fsync MAY clear the inode's dirty
bits via the ACCOUNTED `GlobalPageCache::clear_dirty` (`page_cache.rs:816` — never the
unaccounted entry method `:177`), using a bounded index range scan over the composite key
`(fs_id << 32) | ino` (`ext2.rs:11974` — the formula is reconstructed from
`Inode::fs_id()/ino()`, `traits.rs:141-144`; no IO and no fs lock under the index lock).
This makes fsync the suite's first production dirty-clearer, keeps `nr_dirty`/procfs honest,
and relieves the dirty-unreclaimable pressure on the 256-page cap. Skipped entirely when
`io_faulted` is set.

**sync()**: `VFS_SYNC` callback → for each mount in the CURRENT namespace
(`manager.rs` table; global-sync deviation documented §9): `FileSystem::sync()` (ext2
override = `ensure_io_healthy` + `flush_with_retry` + per-fs clear-dirty pass filtered by
`fs_id` key range — never the unfiltered global `writeback_dirty_pages`, which would hand
one fs's pages to another fs's writer [M1]). Per-fs errors are klogged and skipped; sync()
returns 0 (Linux contract), with the per-fs EIO observable via a subsequent fsync.

**sync_file_range(fd, offset, nbytes, flags)**: signedness gate FIRST —
`(offset as i64) < 0 || (nbytes as i64) < 0` → EINVAL (M9; `sys_ftruncate` precedent
`:17571-17578`) → flags allowlist ⊆ {WAIT_BEFORE=1, WRITE=2, WAIT_AFTER=4} else EINVAL →
`checked_add` overflow → EINVAL → fd resolution as fsync → under write-through, the range's
data is already durable: validate, then return 0 WITHOUT a device flush (documented Linux
semantics — sync_file_range is not a durability barrier and never flushes device caches).
KCOV tags on all four arms.

**Pledge/seccomp (M12):** add 74/75/162/277 to `DISPATCHED_PROMISED` + `pledge_to_filter` +
`promise_allows_syscall` under the `stdio` promise, per the R150-3 triple-edit rule — all
three lists in one commit.

**Safety proof:** (a) fail-closed — the two error classes are separated: poison → EIO
always (invariant 2); transient flush resource exhaustion → bounded retry → EIO without
poison (invariant 3), so a flush storm cannot fail-stop the filesystem (the acceptance
workload generates exactly this, M3); (b) no lock-order edge — the slice takes NO page IO
locks and NO fs write locks; `flush_device` uses only the device lock (leaf, `blk.rs:1863`),
and the clear-dirty pass holds only the cache index read lock + per-entry atomics (no IO,
no fs locks) — the AB-BA hazard of the per-inode draft is structurally absent;
(c) clear-dirty soundness — dirty is set strictly AFTER durable write (§2), so
clear-after-successful-flush cannot lose data by construction; the pass is skipped on
poisoned mounts where the durable-write invariant no longer holds; (d) fd surface — std
streams short-circuit before table lookup (agreement with read/write); the downcast
gate + O_PATH/O_RDONLY dispositions close the M10/M11 cases; the new VFS callbacks follow
the audited truncate registration pattern (the new kernel_core↔vfs edge is named, not
hidden); (e) arithmetic — signedness before overflow before use (M9).

**Edge cases:** (1) EBADF: invalid/closed fd, O_PATH; (2) EINVAL: fd 0/1/2, pipe/socket
kinds (downcast failure), bad 277 flags, negative offset/nbytes, offset+nbytes overflow;
(3) O_RDONLY file fd: VALID (M10); (4) directory fd: VALID — same flush barrier (dirs have
no cached data pages; ext2 opens them read-only `ext2.rs:12490-12492`); (5) unlinked-open
inode: VALID (flush is fs-level); (6) poisoned mount: EIO from fsync/fdatasync; sync skips
+ klogs (invariant 2); (7) virtio Busy/NoMem storm: bounded retry → EIO, no poison, no
wedge (M3); (8) fsync racing umount: `filesystem_for_inode` miss → EIO; the umount
no-sync/no-invalidation gap itself is FILED DEBT (M8), not this slice; (9) fsync racing a
concurrent `write_mutation`: no shared locks (fsync takes no fs write locks), so no spin
coupling; the flush barrier covers whatever the write path had flushed by then — POSIX only
requires coverage of writes completed before fsync began; (10) two mounts of one device /
fs_id ≥ 2³² key aliasing: clear-dirty passes filter by exact fs_id key range; the duplicate
mount gap is FILED DEBT (M1 note); (11) `sync` in a non-root mount namespace: current-ns
scope only, documented deviation (§9); (12) pledged caller: `stdio` promise admits all four
(M12) — no kill.

### Approach 1 (per-inode writeback) — SUPERSEDED IN PLACE (user depth-flip 2026-09-01)

The original same-day draft. Refuted against the tree by the safety + edge lenses: ext2 is
write-through with an inline self-checkpointing journal, so per-inode data writeback
re-writes already-durable blocks; the enumerator's `lock_io`-first shape is an AB-BA
deadlock against `write_mutation`'s `raw→meta→journal→lock_io` order (`ext2.rs:12172-12200`
vs `:12126`); hole-spanning pages force block allocation under page locks; and the §8
oracle could not distinguish a working fsync from the already-synchronous write path.
Becomes the RE-EVALUATION path only if/when a real write-back producer lands (ST-K2 msync,
file-backed mmap, or a write-path conversion) — at that point this doc gets a full `-v2`
redesign, not an amendment.

## 5. Comparison Matrix, Decision Record & Recommendation

| Criterion | A1′ device-flush | A1 per-inode writeback |
|---|---|---|
| Safety (lock order, poison honesty) | **no new lock edges; poison-honest** | AB-BA deadlock; poison ambiguity |
| Correctness (matches the tree's durability model) | **exact under write-through** | inverts the ordered-data rule |
| Efficiency | flush barrier + flag clears only | re-writes durable blocks |
| Performance | O(1) + bounded scan | O(dirty) redundant IO |

**Decision Record (grilling loop, 2026-09-01):**

| # | Question | Recommended | User decision | Consequence |
|---|---|---|---|---|
| 1 | Syscall surface | fsync+fdatasync only | **All four (74/75/162/277)** | sync + sync_file_range in-slice; 277 = validate + no-op under write-through |
| 2 | Depth (original) | Whole-FS flush | Per-inode writeback | superseded by row 3 |
| 3 | Depth flip after lens refutation (write-through + deadlock evidence) | Flip to device-flush | **Flip to device-flush** | This §4 A1′ is the binding approach; per-inode = future -v2 iff a write-back producer lands; M12 pledge lists + M9 signedness + M11 fd-0/1/2 + M10 O_RDONLY folded in |

## 6. Defense-in-Depth Plan

1. fd-kind + std-stream gates before any fs dispatch (EBADF/EINVAL taxonomy, M10/M11).
2. `ensure_io_healthy` poison gate — fsync can never green-light a faulted mount.
3. Transient/persistent flush error separation — bounded retry, EIO without poison; the
   write path remains the only poisoner (M3).
4. Signedness → allowlist → overflow ordering in 277 (M9).
5. Accounted-only dirty clearing, fs_id-filtered, skip-on-poison (M1/C2 hazards closed).
6. Pledge/seccomp triple-edit in the same commit (M12) — no fail-open window.
7. KCOV arm tags — fuzzer reaches the new surface; syz allowlist follow-on noted in plan.

## 7. Implementation Plan

1. `kernel/vfs/traits.rs` — `Inode::fsync(&self, datasync: bool) -> Result<(), FsError>`
   default `Ok(())`.
2. `kernel/vfs/ext2.rs` — `flush_with_retry()` (Busy/NoMem ×4 bounded, no poison);
   `Ext2Inode::fsync` = health gate → flush → clear-dirty range pass;
   `FileSystem::sync` override = health gate → flush → per-fs clear-dirty. `// ST-K4 FIX:`
   markers.
3. `kernel/mm/page_cache.rs` — `clear_dirty_range` over the tuple key space —
   per-inode `(inode_id, 0)..(inode_id, u64::MAX)`, per-fs `((fs_id<<32), 0)..
   (((fs_id+1)<<32), 0)` — via `FallibleOrderedMap::range` (`fallible_map.rs:396`,
   slice-backed, zero-allocation, `&self` under the index read guard; lens-verified) using
   `GlobalPageCache::clear_dirty` (`:816`).
4. `kernel/vfs/manager.rs` + `kernel/kernel_core/lib.rs` — `vfs_fsync_callback` /
   `vfs_sync_callback` on the truncate pattern (drop process lock before fs work; EINVAL on
   downcast failure; O_RDONLY admitted) + registration.
5. `kernel_core/syscall.rs` — arms 74/75/162/277 (std-stream EINVAL short-circuit; 277
   signedness/flags/overflow gates; KCOV tags) + `DISPATCHED_PROMISED` +
   `pledge_to_filter` + `promise_allows_syscall` (`stdio`) per R150-3.
6. **Guest block workload + orchestration (acceptance component, lens-mandated):**
   `userspace/stress_runner.c` — implement the `block` profile round: slot/generation
   write-fsync-read cycles over `/mnt/test`, emitting `NILIX_STRESS_V2_BLOCK
   run/seq/generation/valid_slots/read_bytes/write_bytes/checksum` to the validator's
   real oracle (`valid_slots == io_slots`; page-aligned byte counts;
   `read_bytes ≥ io_slots × PAGE` — `stress_protocol.py:1037-1043`); retire the
   hardcoded `fail("fsync_unsupported")` arm (`:1160`); `combined`'s `io_ops` leg goes
   live off the same rounds. Host-side kill/recovery orchestration per the harness's
   existing block-crash flags (flag 4 `block_crash_auto`).
7. Plan rows filed (not this slice): page-cache contract debt (error-refill C1, LRU-detach
   window M4, WritebackStats error channel M5, dirty-unreclaimable cap pressure), umount
   sync/invalidation gap (M8), duplicate-mount/fs_id-aliasing note (M1), syz allowlist for
   74/75/162/277.

**Order:** after P1-A and after the hoisted ST-K2-P1 (user order repair 2026-09-01);
`syscall.rs`/`page_cache.rs` region-disjoint from ST-K3/P0-A edits.

## 8. Test & Verification Plan

| Test | Oracle |
|---|---|
| Hosted VFS tests | fd matrix: EBADF (bad/closed/O_PATH), EINVAL (0/1/2, pipe kinds, 277 flags/signedness/overflow), O_RDONLY + dir fd accepted; 277 negative-offset EINVAL (would return 0 under the naive decode — discriminating) |
| Runtime gating test `st_k4_fsync` (hard-FAIL polarity) | (a) write → fsync=0 → per-inode `nr_dirty` == 0 (clear-dirty observable — discriminates from a no-op arm); (b) poison-injection leg (host-harness fault hook): `io_faulted` set ⇒ fsync == EIO AND dirty bits UNCHANGED; (c) pledged-process leg: fsync under `stdio` pledge returns (no kill) |
| `make test-kcov` | all four arm tags hit |
| Stress `block` profile (ACCEPTANCE — guest workload is §7 step 6 of THIS item) | first validated `block` `PASS`+`HEARTBEAT` against the REAL oracle (`valid_slots == io_slots`, page-aligned `read_bytes`/`write_bytes`, `read_bytes ≥ io_slots × PAGE`; `stress_protocol.py:1037-1043`) under concurrent-fsync load WITHOUT mount poison; `VIRTIO_BLK_F_FLUSH` negotiation state recorded in the run log; `validate-log` exit 0 captured |
| Full remote ladder | build/lint/test/boot/musl PASS, explicit exit codes |

## 9. Open Questions

- `sync()` namespace scope — recommendation: current-namespace in slice 1, deviation
  documented (single-effective-namespace OS today); global iteration when a mount registry
  exists (non-blocking).
- fdatasync divergence — recommendation: none under device-flush (identical); revisit only
  in a future write-back world (non-blocking).
- fsync-after-`setns` CrossDev EIO vs Linux's fd-pinned superblock — recommendation: accept
  as documented deviation with the namespace item above (non-blocking).

## 10. References

`ext2.rs:5228-5241, 9104-9106, 10176-10421, 12122-12395, 12490-12492` ·
`page_cache.rs:91-263, 764-831, 1067-1110, 1127-1262` · `virtio/blk.rs:1863-1896` ·
`manager.rs:697-711, 1756-1773, 2379, 2800-2854` · `syscall.rs:3682-3690, 3746-3770, 3998,
9935-9991, 10734-10772, 17571-17578, 20812-20815` · `traits.rs:130, 141-144, 222` · lens
reports 2026-09-01 · RF187-5 (bounded retry), R150-3 (pledge triple-edit), R129-1 (truncate
pattern)

## Deviation & Amendment Log

| Date | Author stage | Section(s) | What changed & WHY | Safety impact | Counterparty verdict | User re-confirmation |
|---|---|---|---|---|---|---|
| 2026-09-01 | 4 next-phase (pre-READY) | whole doc | Approach flipped per-inode-writeback → device-flush after the safety lens proved ext2 is write-through with an inline self-checkpointing journal (nothing pending for fsync) and the enumerator deadlocks AB-BA against `write_mutation`; edge lens M1-M12 folded in (cross-fs sync corruption, poison contract, virtio transient classes, signedness, fd-0/1/2, O_RDONLY, pledge lists); page-cache contract debt + umount gap filed as plan rows. | strictly safer: removes a deadlock and a stale-data window; poison honesty formalized | safety lens UNSAFE(a,b)/WEAK(c,d) → all four claims re-grounded; edge lens NOT-ADEQUATE → 12 cases dispositioned | **Yes — 2026-09-01 (depth-flip question)** |
| 2026-09-01 | 4 next-phase (pre-READY) | §§2,3,4,7,8 | Premise rerun: guest contract was WRONG — no fsync probe, no block workload, no `io_ops` field in the block oracle (hardcoded `fail` arm `:1160`; real validator fields `stress_protocol.py:1037-1043`) → guest block workload + orchestration folded IN as the item's acceptance component (§7 step 6; delivers the plan's `block ← ST-K4` edge both sides); poison claim scoped to the mapped-block path; `VIRTIO_BLK_F_FLUSH`-absent no-op + device-mutex convoy caveats added; −7 line drift + tuple-key signature fixed. Thesis + clear-dirty scan CONFIRMED (5/5 load-bearing premises exact). | acceptance can no longer report done while the gate profile stays red | premise lens (rerun): 2 CONFIRMED-WRONG + 5 IMPRECISE → dispositioned; core thesis verified | not required (scope serves the user's gate criterion; surfaced at Q-FINAL) |
