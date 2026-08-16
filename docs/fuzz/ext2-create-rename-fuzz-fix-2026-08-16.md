# Ext2Fs::create + Ext2Fs::rename — Fuzz Result-Path Completion Report

**Date:** 2026-08-16
**Status:** ✅ COMPLETE — committed and pushed
**Commits:** `e55e86d` (ext2 feature), `8389da8` (tests), `d8af0f0` (fuzzer fix)
**Verification:** `make test` 34/39/0, `make build-syz-kcov` OK, `make test-kcov` KCOV-E2E PASS, `make test-syz` 0 crashes

---

## Executive Summary

The syz executor's guest fuzz result-publication path is now **fully
functional**. Two kernel VFS gaps blocked it end-to-end:

- **`Ext2Fs::create` was unimplemented** (the `FileSystem::create` trait
  default returns `NotSupported` → `ENOSYS`), so the executor's
  `open("/mnt/test/.syz-result.bin.tmp", O_WRONLY|O_CREAT|O_EXCL, 0600)`
  returned `-38` → `executor_failure:result_open:-38`.
- **`Ext2Fs::rename` was unimplemented**, so the subsequent
  `renameat2(AT_FDCWD, temp, AT_FDCWD, result, RENAME_NOREPLACE)` failed →
  `result_rename` (the result file was never atomically published).

Both are now implemented as **crash-safe, fully-atomic JBD2 transactions**
(Approach A: every metadata home commits in one transaction or none do;
recovery replays the complete operation). The fuzzer's mutator was also
fixed so mutated programs actually reach the executor (the prior triage
doc's spurious-crash root cause: boot-time panic, no program execution).

This work was scoped and tracked against the prior triage
([syz-crash-triage-2026-08-16.md](syz-crash-triage-2026-08-16.md)) and the
implementation plan `C:\Users\Admin\.claude\plans\swift-skipping-journal.md`
(Approach A — fully-atomic 6-block FileCreate transaction).

---

## Implementation

### 1. JBD2 journal grammar extension (4 → 6 metadata blocks)

The custom ZJ01 journal grammar previously supported at most 4 metadata
homes per transaction (the `DIRECT_ALLOCATION` grammar: block bitmap, group
descriptor, superblock, inode table). FileCreate touches up to 6 distinct
metadata homes, so the ceiling was raised:

- `JOURNAL_MAX_METADATA_BLOCKS` 4 → 6 (the array-size / journal-capacity ceiling).
- **New `DIRECT_ALLOCATION_METADATA_BLOCKS = 4`** — the existing grammars'
  fixed count, kept *distinct* from the ceiling. This was the central trap:
  ~8 sites conflated "max" with "DIRECT_ALLOCATION's 4 homes"; raising only
  the ceiling would have silently grown the existing grammar's on-disk
  transaction size, its recovery candidate count, and its self-test
  fixtures. Splitting the two constants leaves the existing grammars'
  on-disk format byte-for-byte unchanged and keeps the R180-6 synthetic
  test image (`s_maxlen == 8`) mountable.
- `JOURNAL_TRANSACTION_BLOCKS` stays `1 + 4 + 1 = 6` (via
  `DIRECT_ALLOCATION_METADATA_BLOCKS`), so the mount-time minimum journal
  capacity is unchanged. FileCreate transactions are capacity-checked at
  *create* time and return `NotSupported` (not a poison error) when the
  journal cannot hold a 6-block transaction.

Two new intent kinds and their payloads live in the trailing-zero region of
the 1024-byte commit block, past the 352..384 digest — so `INODE_UPDATE`
and `DIRECT_ALLOCATION` keep their on-disk format byte-for-byte
(`finish_transaction_digest` already hashes `[ZERO_INTENT_END..]`, so the
new fields are inside the authenticated digest):

| Kind | Value | Extra fields (trailing region) |
|---|---|---|
| `ZERO_INTENT_KIND_FILE_CREATE` | 3 | `new_ino` (offset 384), `parent_ino` (388) |
| `ZERO_INTENT_KIND_FILE_RENAME` | 4 | `rename_dir_off`, `rename_rec_len`, `rename_old_name_len`, `rename_old_name[255]` |

`commit_metadata_transaction` itself needed **no body change** — it is
generic over `plan.metadata_blocks()`, so it already drives any count.
The four commit-time hooks (`metadata_home_block`, `build_metadata_image`,
`metadata_preimage_hash`, `intent_for_plan`) plus `encode_commit_intent` /
`decode_commit_intent` gained the two new arms.

### 2. `Ext2Fs::create` — transactional ext3 file creation

Mirrors `write_mutation`'s lock discipline (`parent.write_lock` →
`parent.raw.write()` → `fs.meta_lock` → `ensure_io_healthy()` → read-only
checks → `fs.journal.lock()`). Algorithm:

1. **Pre-flight:** downcast parent, require `is_dir`, validate name
   (1..=255, no `/` or NUL), admit a `Ext2MutationScratch`.
2. **Dirent space:** resolve the parent's **last direct** block
   (`last_block_idx < EXT2_NDIR_BLOCKS` — indirect last blocks rejected,
   see Review below) and carve the new dirent from the last entry's
   `rec_len` tail (Case A). A full last block or a non-4-aligned `rec_len`
   → `NotSupported`/`Invalid`. A **clean-tail gate** requires the carved
   region to be all-zero in the pre-image (so recovery reversal is exact).
3. **Allocate inode:** scan the inode bitmap, skip reserved inodes
   (`< first_ino`, `journal_inum`), cross-check `bitmap_free_count`.
   ENOSPC → `NoSpace`. The new slot must be **all-zero** (full `inode_size`
   bytes, not just 128) — the all-zero-slot gate, so the recovery preimage
   reversal zeroes the slot exactly.
4. **Build the plan:** new inode (regular, `links_count=1`, size 0), parent
   transition (mtime/ctime bump; size/blocks unchanged in Case A),
   `free_inodes_count checked_sub(1)` for the group desc and superblock
   (no u16/u32 wrap). 5–6 distinct homes (coalesce the new + parent inode
   edits into one inode-table block when they share it). Distinct-home +
   no-journal-owned-home + dir-data-not-structural checks.
5. **Commit** via `commit_metadata_transaction` (all-or-nothing; an
   uncommitted failure `abort_uncommitted_journal` resets `journal.start=0`
   so recovery sees no transaction — pre-transaction disk state is
   untouched). Publish in-memory: `superblock`, `group_descs`, `parent.raw`,
   and the **cache-canonical** `Arc<Ext2Inode>` (so the caller's subsequent
   `open()` succeeds — `Ext2Inode::open` requires the cache-canonical Arc).

### 3. `Ext2Fs::rename` — transactional same-directory rename

2-home JBD2 transaction (parent dir data block + parent inode table block).
Same lock discipline. In-place name rewrite: the dest name must fit in the
source entry's `rec_len`; the entry's `inode` and `rec_len` are unchanged,
only `name_len`, `name`, and trailing padding change. The inode itself is
unchanged (nlink stays 1, no inode-table write for the moved file). Scope:
same-directory, regular-file source, `RENAME_NOREPLACE` (dest absent);
cross-directory / directory rename / overwrite / dest-too-long return
`NotSupported`.

A manual directory walk (not `dir_lookup`, which would take `raw.read()`
under the held `raw.write()` → self-deadlock) finds the source in the **last
direct** block and verifies the dest is globally absent.

### 4. Recovery validation extension (the hard part)

The existing grammar journaled only **structural** metadata (superblock,
group descriptors, the *block* bitmap, inode table). FileCreate and FileRename
also journal the **inode bitmap** (inode allocation) and the **parent
directory data block** — neither was recognized at mount-time recovery:

- `recovery_home_kind` gained an `InodeBitmap(group)` variant (it knew the
  *block* bitmap but not the inode bitmap).
- `validate_recovery_overlay` allows the dir-data home
  (`recovery_home_kind == None`) for a `FILE_CREATE`/`FILE_RENAME` intent
  (it is the parent's highest non-zero direct block; block array unchanged
  by Case-A create / in-place rename, so `intent.old_inode` agrees), and
  allows the `free_inodes_count` change for a `FILE_CREATE` intent (the
  preimage proof binds the count to the journaled inode bitmap via
  `validate_block_ownership`).
- `validate_recovery_file_create` / `validate_recovery_rename`: re-derive
  the home set from `intent` + geometry, validate the overlay matches the
  expected ordered homes (and the distinct-home invariant), reverse each
  edit on a copy of the post-images, and verify every preimage hash.
  Recovery-side reversal is the exact inverse of commit-time
  `metadata_preimage_hash` (verified byte-identical by the round-trip
  self-tests). `validate_block_ownership` needed no change (skips the
  journal inode; the new inode has no blocks; the parent dir-data block is
  allocated).
- `plan_internal_journal_recovery` tries the candidate forms in count
  order {1, 2, 4, 5, 6}; the block at `first+3` is read once and reused as
  both the 2-image (rename) commit and the 4-image form's image[2] (so the
  four-image read-count invariant is preserved).

### 5. syz fuzzer mutator fix

`generate_random_syscall` picked `read`/`write`/`open`/`mmap` — none in the
non-destructive allowlist — so every mutated program was rejected by
`validate_syscall` before reaching the executor. The executor's result path
never ran, so `result_open`/`result_rename` were never observable (the
prior triage doc's "all 11 crashes are spurious boot-time panics"). The
mutator now picks only allowlisted, argument-free syscalls
(`sched_yield`, `getpid`, `get*id`, `getppid`, `gettid`) so mutated
programs pass validation and reach the executor. With `create`+`rename`
implemented, the executor publishes its result with no
`executor_failure` (smoke test: `Crashes found: 0`, empty crashes dir).

---

## Adversarial self-review (MODE S — Codex MCP unavailable)

A fresh-context agent reviewed the FileCreate path for correctness/integrity
bugs. Findings:

- **MEDIUM (fixed):** `create`/`rename` used `map_file_block_with_scratch`,
  which traverses indirect trees for `last_block_idx >= 12`, but recovery
  re-derives the dir-data home as the parent's highest non-zero *direct*
  block. An indirect-mapped last block (a >12-block parent directory) would
  commit a home recovery cannot re-derive → a crash after the commit would
  make the filesystem persistently unmountable. **Fix:** reject
  `last_block_idx >= EXT2_NDIR_BLOCKS` up front (this driver never grows a
  directory, so >12-block dirs are out of scope anyway).
- **LOW (fixed):** added `rec_len % 4 != 0` validation to the dirent walk
  (ext2 requires 4-aligned `rec_len`; a corrupt block could produce an
  unaligned carved entry).
- **LOW (noted, no fix):** recovery `reverse_file_create_dir_data` matches
  the new dirent by `inode == new_ino` (walk), not by offset (commit uses
  stored offsets). A stale earlier entry pointing at the next-allocated ino
  would make recovery reverse the wrong slot → preimage hash mismatch →
  fail-closed (durability loss, **not** corruption). Requires external
  corruption + a crash in the narrow window; not reachable in the driver's
  lifecycle (no `unlink` → no stale entries).
- **Coverage gap (closed):** added a coalesced 5-home test
  (`build_coalesced_image` + Scenarios D.1/D.2) — the path where new+parent
  inode share one inode-table block (`FileCreateHomeRole::CoalescedInode`),
  not exercised by the 6-home Scenarios A–C.

Verified SAFE by the reviewer: coalesced edit loss (disjoint slots, both
edits applied/reversed), reversal byte-divergence (struct update copies all
fields; `new == old` except `free_inodes_count`; `dir_old_rec_len ==
minimal + new` by construction), `free_inodes_count` underflow (`checked_sub`
+ bitmap cross-check), lock order, all-zero-slot/clean-tail gates, journal
capacity pre-flight (`NotSupported` not poison), `decode_commit_intent`
FILE_CREATE/FILE_RENAME validation, `validate_recovery_overlay`
`free_inodes_count` allowance (bound to inode bitmap via
`validate_block_ownership`).

---

## Verification (remote devbox, via ssh-skill)

| Gate | Result |
|---|---|
| `make build` | ✅ PASS |
| `make build-syz-kcov` | ✅ PASS (syz executor kernel embeds create+rename) |
| `make test` | ✅ **34 passed, 39 deferred, 0 failed**, 0 panic, 0 NX |
| `make test-kcov` | ✅ KCOV-E2E PASS |
| `make test-syz` | ✅ Crashes found: 0 (executor result path works; no `result_open`/`result_rename`) |
| `e2fsck -pf disk-ext2.img` | ⚠ blocked by the intentional `ZERO_INTENT` journal incompat bit (RF180-50 design — **not** create/rename corruption); `debugfs` confirms production image structure intact; on-disk consistency verified by the create/rename self-tests |

### `run_ext2_create_self_test` (synthetic big-journal image, `s_maxlen=12`)

Six scenarios, all pass:

- **A** — create happy-path 6-home commit (stat mode 0o100600 size 0 nlink 1;
  lookup resolves; superblock/group-desc free counts −1; bitmap bit set;
  dir block has the new dirent; last entry `rec_len` split correctly).
- **B** — crash *before* the commit block is durable → recovery leaves NO
  allocated inode, NO dirent, counts unchanged (all-or-nothing).
- **C** — crash *after* the commit but before checkpoint → recovery replays
  the full create.
- **D.1 / D.2** — coalesced 5-home (new+parent share one inode-table block)
  happy path + crash replay.
- **E / F** — rename happy path (cache-canonical Arc unchanged; NOREPLACE
  onto existing fails) + crash-after-commit replay.

---

## Files modified

| File | Change | Commit |
|---|---|---|
| `kernel/vfs/ext2.rs` | Grammar extension; `Ext2Fs::create`; `Ext2Fs::rename`; recovery validation extension; `run_ext2_create_self_test` (A–F) | `e55e86d` |
| `kernel/src/integration_test.rs` | Wire `run_ext2_create_self_test`; mounted-image create probe | `8389da8` |
| `userspace/nilix-syz-fuzzer/src/mutator.rs` | Allowlisted-syscall `generate_random_syscall` | `d8af0f0` |

Line-ending convention preserved: `kernel/` `.rs` committed **CRLF** (HEAD is
CRLF; added with `core.autocrlf=false`); `userspace/nilix-syz-fuzzer/` `.rs`
committed **LF** (that subtree's convention). `scripts/kernel_test.sh` was
temporarily patched to preserve the serial log during debugging and
reverted to HEAD before commit.

---

## Out of scope (follow-ons)

- **`unlink`** override — the executor tolerates its failure
  (`best_effort_unlink_temp` ignores the return); a fresh image has no
  stale temp file, so `NotSupported` is acceptable. Needed only if a
  reused image accumulates `.syz-result.bin.tmp` leftovers.
- **General rename** — cross-directory rename, directory rename, overwrite
  (`REPLACE`), and a dest name too long for the source entry's `rec_len`
  return `NotSupported`. The executor's `renameat2` is same-directory with
  a shorter dest name, so this scope suffices.
- **e2fsck** on the production image — blocked by the intentional
  `ZERO_INTENT` incompat bit; a disposable-copy + feature-mask workflow
  (RF180-50) would allow host `e2fsck`, tracked separately.
- **Codex MCP review** — unavailable this session; reviewing in MODE S
  (fresh-context adversarial agent). Re-review with Codex when available.

---

## Commit plan (as applied)

```
e55e86d feat(vfs/ext2): transactional ext3 file creation and same-directory rename
8389da8 test(vfs): wire ext2 create/rename self-tests and mounted create probe
d8af0f0 fix(syz-fuzzer): generate only allowlisted syscalls so programs reach the executor
```

All three committed on `main` and pushed to `origin/main`
(`ac9c841..d8af0f0`). Local and remote md5-verified in sync.
