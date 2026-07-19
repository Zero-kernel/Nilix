//! RAM Filesystem (RamFS)
//!
//! In-memory filesystem for temporary storage and boot files.
//! Supports file and directory creation, reading, writing, and deletion.
//!
//! # Resource Limits (V-3 fix)
//!
//! - MAX_FILE_SIZE: Maximum size of a single file (16 MiB)
//! - MAX_TOTAL_BYTES: Maximum total bytes across all ramfs instances (64 MiB)
//!
//! These limits prevent memory exhaustion DoS attacks.

// R172-22: ramfs directory entries use the allocation-fallible `FallibleOrderedMap`
// (mm/fallible_map.rs) instead of `BTreeMap` — stable no_std `BTreeMap::insert` allocates a
// B-tree node infallibly on leaf-split, so OOM aborts the kernel via `handle_alloc_error`.
// `FallibleOrderedMap::try_insert` returns `Err` (-> ENOSPC) instead. Read-side API is
// method-name-compatible (get/contains_key/remove/iter/values/len/range), so only the
// inserts change. (Sibling devfs/initramfs/manager/mount_namespace children maps are the
// SAME class — tracked as R172-22-FOLLOWON, out of this ramfs-scoped fix.)
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use mm::fallible_map::{FallibleOrderedMap, PreparedOrderedMapBacking};
use mm::{
    arc_charge_bytes, try_reserve_heap, vec_charge_bytes, HeapCharge, HeapClass, HeapReservation,
};
use spin::RwLock;

use crate::traits::{FileSystem, Inode, PreparedFileHandle};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use kernel_core::{current_credentials, FileDescriptor};

/// Global filesystem ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(100);

/// V-3 fix: Maximum allowed file size in ramfs (bytes)
///
/// Prevents memory exhaustion DoS by limiting individual file sizes.
/// 16 MiB is sufficient for typical boot files and temporary data while
/// protecting against unbounded kernel heap allocation.
const MAX_FILE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// Global quota: Maximum total bytes allowed across all ramfs instances
///
/// Provides defense-in-depth against memory exhaustion by limiting
/// the combined size of all files in all ramfs mounts.
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Global counter tracking total bytes used by all ramfs instances
static TOTAL_BYTES_USED: AtomicUsize = AtomicUsize::new(0);

/// Try to allocate bytes from the global quota
///
/// Returns true if allocation succeeded, false if would exceed quota.
fn quota_try_alloc(bytes: usize) -> bool {
    let mut current = TOTAL_BYTES_USED.load(Ordering::SeqCst);
    loop {
        let new_total = match current.checked_add(bytes) {
            Some(t) => t,
            None => return false, // overflow
        };
        if new_total > MAX_TOTAL_BYTES {
            return false; // would exceed quota
        }
        match TOTAL_BYTES_USED.compare_exchange_weak(
            current,
            new_total,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// Release bytes back to the global quota
fn quota_release(bytes: usize) {
    // Use fetch_update for atomic saturating subtraction to avoid race conditions
    let _ = TOTAL_BYTES_USED.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
        Some(current.saturating_sub(bytes))
    });
}

/// Transactional global quota charge.
///
/// R-MEDIUM-1 / R-MEDIUM-2 fix: RAMFS growth paths charge quota FIRST via this
/// guard, then perform fallible in-place capacity reservation. The guard automatically
/// releases its charge unless the reservation and resize succeed and `commit()` is called.
/// This ordering prevents quota leaks, OOM panics, and uncharged-capacity bypasses.
#[must_use = "the quota charge rolls back unless committed"]
struct QuotaGuard {
    bytes: usize,
    committed: bool,
}

impl QuotaGuard {
    fn try_new(bytes: usize) -> Result<Self, FsError> {
        if !quota_try_alloc(bytes) {
            return Err(FsError::NoSpace);
        }

        Ok(Self {
            bytes,
            committed: false,
        })
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for QuotaGuard {
    fn drop(&mut self) {
        if !self.committed {
            quota_release(self.bytes);
        }
    }
}

/// Get current total bytes used by ramfs
#[allow(dead_code)]
pub fn ramfs_bytes_used() -> usize {
    TOTAL_BYTES_USED.load(Ordering::SeqCst)
}

/// Get maximum allowed bytes for ramfs
#[allow(dead_code)]
pub fn ramfs_max_bytes() -> usize {
    MAX_TOTAL_BYTES
}

/// Inode metadata
struct Meta {
    mode: FileMode,
    nlink: u32,
    size: u64,
    uid: u32,
    gid: u32,
    atime: TimeSpec,
    mtime: TimeSpec,
    ctime: TimeSpec,
}

impl Meta {
    fn new(mode: FileMode, uid: u32, gid: u32) -> Self {
        let now = TimeSpec::now();
        let initial_nlink = if mode.is_dir() { 2 } else { 1 };
        Self {
            mode,
            nlink: initial_nlink,
            size: 0,
            uid,
            gid,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

type DirectoryMap = FallibleOrderedMap<String, Arc<RamFsInode>>;
type DirectoryBacking = PreparedOrderedMapBacking<String, Arc<RamFsInode>>;

/// Regular-file storage and the lifetime charge covering both the inode Arc
/// allocation and the allocator's actual data-vector capacity.
struct FileState {
    data: Vec<u8>,
    heap_charge: HeapCharge,
}

impl FileState {
    /// Resize file storage transactionally under the inode's state write lock.
    /// Detached replacement keeps the old bytes reachable and charged until
    /// the new allocation has been admitted, allocated, reconciled, and
    /// committed. This also compacts capacity on truncate, preventing churn
    /// from retaining an unbounded high-water allocation.
    fn resize_data(&mut self, new_len: usize) -> Result<(), FsError> {
        let old_len = self.data.len();
        if new_len == old_len {
            return Ok(());
        }

        let growth_quota = if new_len > old_len {
            Some(QuotaGuard::try_new(new_len - old_len)?)
        } else {
            None
        };

        // Growing inside already charged capacity requires no allocation.
        if new_len > old_len && new_len <= self.data.capacity() {
            self.data.resize(new_len, 0);
            growth_quota
                .expect("RAMFS growth quota guard missing")
                .commit();
            return Ok(());
        }

        let old_capacity = self.data.capacity();
        let old_charge = string_buffer_charge(old_capacity)?;

        let estimated_new = string_buffer_charge(new_len)?;
        let mut reservation = heap_no_space(try_reserve_heap(HeapClass::RamFs, estimated_new))?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(new_len)
            .map_err(|_| FsError::NoMem)?;
        let actual_new = string_buffer_charge(replacement.capacity())?;
        heap_no_space(reservation.resize(actual_new))?;
        replacement.resize(new_len, 0);
        let preserved = core::cmp::min(old_len, new_len);
        replacement[..preserved].copy_from_slice(&self.data[..preserved]);

        absorb_prepared(&mut self.heap_charge, reservation);
        let retired = core::mem::replace(&mut self.data, replacement);
        drop(retired);
        release_deallocated(&mut self.heap_charge, old_charge);

        if let Some(guard) = growth_quota {
            guard.commit();
        } else {
            quota_release(old_len - new_len);
        }
        Ok(())
    }
}

/// Directory storage and its aggregate lifetime charge. The charge covers the
/// inode Arc, the map backing Vec, and every retained String-key buffer.
struct DirectoryState {
    entries: DirectoryMap,
    heap_charge: HeapCharge,
}

/// Symlink target storage and the lifetime charge covering the inode Arc plus
/// the target String's actual allocator capacity.
struct SymlinkState {
    target: String,
    _heap_charge: HeapCharge,
}

/// Node kind: file, directory, or symlink.
enum NodeKind {
    File { state: RwLock<FileState> },
    Dir { state: RwLock<DirectoryState> },
    Symlink { state: RwLock<SymlinkState> },
}

#[inline]
fn heap_no_space<T>(result: Result<T, mm::HeapAdmissionError>) -> Result<T, FsError> {
    result.map_err(|_| FsError::NoSpace)
}

#[inline]
fn checked_charge_add(left: usize, right: usize) -> Result<usize, FsError> {
    left.checked_add(right).ok_or(FsError::NoSpace)
}

#[inline]
fn string_buffer_charge(capacity: usize) -> Result<usize, FsError> {
    heap_no_space(vec_charge_bytes::<u8>(capacity))
}

#[inline]
fn directory_backing_charge(capacity: usize) -> Result<usize, FsError> {
    heap_no_space(vec_charge_bytes::<(String, Arc<RamFsInode>)>(capacity))
}

/// A detached, admitted directory key. The reservation remains rollback-armed
/// until the caller has completed every fallible preparation step.
struct PreparedDirectoryKey {
    key: String,
    reservation: HeapReservation,
    charge_bytes: usize,
}

impl PreparedDirectoryKey {
    fn try_new(name: &str) -> Result<Self, FsError> {
        let estimated = string_buffer_charge(name.len())?;
        let mut reservation = heap_no_space(try_reserve_heap(HeapClass::RamFs, estimated))?;
        let mut key = String::new();
        key.try_reserve_exact(name.len())
            .map_err(|_| FsError::NoSpace)?;
        let actual = string_buffer_charge(key.capacity())?;
        heap_no_space(reservation.resize(actual))?;
        key.push_str(name);
        Ok(Self {
            key,
            reservation,
            charge_bytes: actual,
        })
    }
}

/// Detached replacement backing for a directory. The full new allocation is
/// reserved (rather than only the delta) because old and new backing vectors
/// coexist during preparation.
struct PreparedDirectoryCapacity {
    backing: DirectoryBacking,
    reservation: HeapReservation,
}

struct AdmittedDirectoryCapacity {
    backing: DirectoryBacking,
}

impl PreparedDirectoryCapacity {
    fn try_new(required_capacity: usize) -> Result<Self, FsError> {
        let estimated = directory_backing_charge(required_capacity)?;
        let mut reservation = heap_no_space(try_reserve_heap(HeapClass::RamFs, estimated))?;
        let backing = DirectoryMap::try_prepare_backing_exact(required_capacity)
            .map_err(|_| FsError::NoSpace)?;
        let actual = directory_backing_charge(backing.capacity())?;
        heap_no_space(reservation.resize(actual))?;
        Ok(Self {
            backing,
            reservation,
        })
    }
}

#[inline]
fn absorb_prepared(charge: &mut HeapCharge, reservation: HeapReservation) {
    // A same-class, successfully acquired reservation cannot fail to commit
    // unless the global ledger is corrupt. Continuing after that would make
    // every subsequent admission unsound, so fail closed as an invariant fault.
    charge
        .absorb(reservation)
        .expect("R180 RAMFS heap ledger corrupt during commit");
}

#[inline]
fn release_deallocated(charge: &mut HeapCharge, bytes: usize) {
    charge
        .release_after_deallocation(bytes)
        .expect("R180 RAMFS heap ledger corrupt during release");
}

/// Install already-admitted backing and release the old backing charge only
/// after its allocation has been deallocated by `replace_backing`.
fn admit_directory_backing(
    state: &mut DirectoryState,
    prepared: PreparedDirectoryCapacity,
) -> AdmittedDirectoryCapacity {
    absorb_prepared(&mut state.heap_charge, prepared.reservation);
    AdmittedDirectoryCapacity {
        backing: prepared.backing,
    }
}

fn install_admitted_backing(state: &mut DirectoryState, admitted: AdmittedDirectoryCapacity) {
    let expected_old_capacity = state.entries.capacity();
    let old_capacity = state
        .entries
        .replace_backing(admitted.backing)
        .unwrap_or_else(|_| panic!("R180 RAMFS prepared backing too small"));
    debug_assert_eq!(old_capacity, expected_old_capacity);
    let old_charge =
        directory_backing_charge(old_capacity).expect("R180 RAMFS old backing charge overflow");
    release_deallocated(&mut state.heap_charge, old_charge);
}

fn prepare_directory_insert(
    entry_len: usize,
    capacity: usize,
    name: &str,
) -> Result<(PreparedDirectoryKey, Option<PreparedDirectoryCapacity>), FsError> {
    let key = PreparedDirectoryKey::try_new(name)?;
    let target_len = entry_len.checked_add(1).ok_or(FsError::NoSpace)?;
    let backing = if capacity < target_len {
        Some(PreparedDirectoryCapacity::try_new(target_len)?)
    } else {
        None
    };
    Ok((key, backing))
}

/// Publish a fully prepared directory insertion. No allocation occurs here.
fn commit_directory_insert(
    state: &mut DirectoryState,
    prepared_key: PreparedDirectoryKey,
    prepared_backing: Option<PreparedDirectoryCapacity>,
    child: Arc<RamFsInode>,
) -> Result<(), FsError> {
    if let Some(prepared) = prepared_backing {
        let admitted = admit_directory_backing(state, prepared);
        install_admitted_backing(state, admitted);
    }

    let PreparedDirectoryKey {
        key,
        reservation,
        charge_bytes,
    } = prepared_key;
    absorb_prepared(&mut state.heap_charge, reservation);
    if let Err((key, child)) = state.entries.insert_unique_reserved(key, child) {
        drop(key);
        drop(child);
        release_deallocated(&mut state.heap_charge, charge_bytes);
        return Err(FsError::NoSpace);
    }
    Ok(())
}

/// Remove an entry without making deletion depend on fresh heap capacity.
///
/// A compact replacement is best-effort for non-empty directories: if its
/// detached allocation could not be admitted, the old high-water backing stays
/// live *and charged* until a later mutation can compact it. Empty-directory
/// compaction needs zero bytes and therefore always succeeds. This prevents a
/// full RAMFS class from refusing the unlink/rmdir operations needed to release
/// memory while retaining exact deallocation-before-uncharge ordering.
fn commit_directory_remove(
    state: &mut DirectoryState,
    name: &str,
    prepared: Option<PreparedDirectoryCapacity>,
) -> Arc<RamFsInode> {
    let admitted = prepared.map(|prepared| admit_directory_backing(state, prepared));
    let (key, child) = state
        .entries
        .remove_entry(name)
        .expect("R180 RAMFS remove precondition changed under write lock");
    let key_charge =
        string_buffer_charge(key.capacity()).expect("R180 RAMFS key charge overflow during remove");
    drop(key);
    if let Some(admitted) = admitted {
        install_admitted_backing(state, admitted);
    }
    release_deallocated(&mut state.heap_charge, key_charge);
    child
}

/// Prepare compaction without turning a resource-releasing mutation into an
/// allocation-dependent operation. A zero-entry backing performs no allocation
/// and must always be available once heap admission is published.
fn prepare_directory_compaction(target_len: usize) -> Option<PreparedDirectoryCapacity> {
    match PreparedDirectoryCapacity::try_new(target_len) {
        Ok(prepared) => Some(prepared),
        Err(_) if target_len == 0 => {
            panic!("R180 RAMFS zero-capacity compaction unexpectedly failed")
        }
        Err(_) => None,
    }
}

/// RAM filesystem inode
pub struct RamFsInode {
    fs_id: u64,
    ino: u64,
    meta: RwLock<Meta>,
    kind: NodeKind,
    /// RF178-16 FIX: A removed directory may remain alive through an open file
    /// description, but it is no longer a valid topology parent.
    detached: AtomicBool,
}

impl RamFsInode {
    /// Create a new directory inode
    pub fn new_dir(
        fs_id: u64,
        ino: u64,
        perm: u16,
        uid: u32,
        gid: u32,
    ) -> Result<Arc<Self>, FsError> {
        let mode = FileMode::directory(perm);
        let arc_bytes = heap_no_space(arc_charge_bytes::<Self>())?;
        let reservation = heap_no_space(try_reserve_heap(HeapClass::RamFs, arc_bytes))?;
        let charge = heap_no_space(reservation.commit())?;
        let inode = Arc::try_new(Self {
            fs_id,
            ino,
            meta: RwLock::new(Meta::new(mode, uid, gid)),
            kind: NodeKind::Dir {
                state: RwLock::new(DirectoryState {
                    entries: FallibleOrderedMap::new(),
                    heap_charge: charge,
                }),
            },
            detached: AtomicBool::new(false),
        })
        .map_err(|_| FsError::NoSpace)?;
        Ok(inode)
    }

    /// Create a new file inode
    pub fn new_file(
        fs_id: u64,
        ino: u64,
        perm: u16,
        uid: u32,
        gid: u32,
    ) -> Result<Arc<Self>, FsError> {
        let mode = FileMode::regular(perm);
        let arc_bytes = heap_no_space(arc_charge_bytes::<Self>())?;
        let reservation = heap_no_space(try_reserve_heap(HeapClass::RamFs, arc_bytes))?;
        let charge = heap_no_space(reservation.commit())?;
        let inode = Arc::try_new(Self {
            fs_id,
            ino,
            meta: RwLock::new(Meta::new(mode, uid, gid)),
            kind: NodeKind::File {
                state: RwLock::new(FileState {
                    data: Vec::new(),
                    heap_charge: charge,
                }),
            },
            detached: AtomicBool::new(false),
        })
        .map_err(|_| FsError::NoSpace)?;
        Ok(inode)
    }

    /// Create a new symlink inode
    pub fn new_symlink(
        fs_id: u64,
        ino: u64,
        perm: u16,
        uid: u32,
        gid: u32,
        target: &str,
    ) -> Result<Arc<Self>, FsError> {
        let mode = FileMode::symlink(perm);
        let target_len = target.len() as u64;
        let arc_bytes = heap_no_space(arc_charge_bytes::<Self>())?;
        let estimated_target = string_buffer_charge(target.len())?;
        let estimated_total = checked_charge_add(arc_bytes, estimated_target)?;
        let mut reservation = heap_no_space(try_reserve_heap(HeapClass::RamFs, estimated_total))?;
        let quota_guard = QuotaGuard::try_new(target.len())?;

        let mut target_owned = String::new();
        target_owned
            .try_reserve_exact(target.len())
            .map_err(|_| FsError::NoSpace)?;
        let actual_target = string_buffer_charge(target_owned.capacity())?;
        let actual_total = checked_charge_add(arc_bytes, actual_target)?;
        heap_no_space(reservation.resize(actual_total))?;
        target_owned.push_str(target);

        let charge = heap_no_space(reservation.commit())?;
        // From this point the inode value owns the quota charge. Arc failure
        // drops the value and releases both quota and heap charge exactly once.
        quota_guard.commit();
        let inode = Arc::try_new(Self {
            fs_id,
            ino,
            meta: RwLock::new(Meta::new(mode, uid, gid)),
            kind: NodeKind::Symlink {
                state: RwLock::new(SymlinkState {
                    target: target_owned,
                    _heap_charge: charge,
                }),
            },
            detached: AtomicBool::new(false),
        })
        .map_err(|_| FsError::NoSpace)?;
        // Set symlink size to target path length
        inode.meta.write().size = target_len;
        Ok(inode)
    }

    /// Look up a child entry in directory
    fn lookup_child(&self, name: &str) -> Result<Arc<RamFsInode>, FsError> {
        match &self.kind {
            NodeKind::Dir { state } => state
                .read()
                .entries
                .get(name)
                .cloned()
                .ok_or(FsError::NotFound),
            NodeKind::File { .. } | NodeKind::Symlink { .. } => Err(FsError::NotDir),
        }
    }

    /// Add a child entry to directory
    fn add_child(&self, name: &str, child: Arc<RamFsInode>) -> Result<(), FsError> {
        // Validate name
        if name.is_empty() || name.len() > 255 || name.contains('/') {
            return Err(FsError::NameTooLong);
        }
        if name == "." || name == ".." {
            return Err(FsError::Invalid);
        }

        match &self.kind {
            NodeKind::Dir { state } => {
                // R180-13 FIX: key bytes and any new map backing are reserved
                // and allocated while detached and without a directory spin
                // lock held. Revalidate under the write lock before the
                // allocation-free publication step; retry if a nonstandard
                // direct caller changed capacity outside the topology mutex.
                loop {
                    let (entry_len, capacity) = {
                        let state = state.read();
                        if state.entries.contains_key(name) {
                            return Err(FsError::Exists);
                        }
                        (state.entries.len(), state.entries.capacity())
                    };
                    let (prepared_key, prepared_backing) =
                        prepare_directory_insert(entry_len, capacity, name)?;

                    let mut state = state.write();
                    if state.entries.contains_key(name) {
                        return Err(FsError::Exists);
                    }
                    let current_target =
                        state.entries.len().checked_add(1).ok_or(FsError::NoSpace)?;
                    let prepared_is_sufficient = match prepared_backing.as_ref() {
                        Some(backing) => backing.backing.capacity() >= current_target,
                        None => state.entries.capacity() >= current_target,
                    };
                    if !prepared_is_sufficient {
                        drop(state);
                        drop(prepared_key);
                        drop(prepared_backing);
                        continue;
                    }

                    commit_directory_insert(&mut state, prepared_key, prepared_backing, child)?;
                    break;
                }

                // Update parent directory timestamps
                let mut meta = self.meta.write();
                let now = TimeSpec::now();
                meta.mtime = now;
                meta.ctime = now;

                Ok(())
            }
            NodeKind::File { .. } | NodeKind::Symlink { .. } => Err(FsError::NotDir),
        }
    }

    /// Get directory entry count
    fn child_count(&self) -> usize {
        match &self.kind {
            NodeKind::Dir { state } => state.read().entries.len(),
            NodeKind::File { .. } | NodeKind::Symlink { .. } => 0,
        }
    }

    /// Increment link count
    fn inc_nlink(&self) {
        let mut meta = self.meta.write();
        meta.nlink += 1;
        meta.ctime = TimeSpec::now();
    }

    /// Decrement link count
    fn dec_nlink(&self) {
        let mut meta = self.meta.write();
        if meta.nlink > 0 {
            meta.nlink -= 1;
        }
        meta.ctime = TimeSpec::now();
    }

    /// Update ctime without changing other metadata
    fn touch_ctime(&self) {
        self.meta.write().ctime = TimeSpec::now();
    }

    /// Update mtime+ctime (a directory was structurally modified). M0-6 slice 2: the
    /// atomic rename path mutates the raw `entries` map directly (bypassing
    /// add_child/remove_child), so it must touch the parent dir timestamps itself.
    fn touch_mtime_ctime(&self) {
        let mut meta = self.meta.write();
        let now = TimeSpec::now();
        meta.mtime = now;
        meta.ctime = now;
    }

    /// M0-6 slice 2: borrow the raw directory `entries` lock so the atomic rename can hold
    /// a SINGLE spanning write guard across the whole transaction (the self-locking
    /// add_child/remove_child each take their own lock — a two-lock atomicity gap that
    /// allowed a half-mutation when an insert failed after a remove). Returns None for files.
    fn dir_entries(&self) -> Option<&RwLock<DirectoryState>> {
        match &self.kind {
            NodeKind::Dir { state } => Some(state),
            NodeKind::File { .. } | NodeKind::Symlink { .. } => None,
        }
    }

    /// Reject mutations through an open handle to an unlinked directory.
    fn ensure_attached_dir(&self) -> Result<(), FsError> {
        if !self.is_dir() {
            return Err(FsError::NotDir);
        }
        if self.detached.load(Ordering::Acquire) {
            return Err(FsError::NotFound);
        }
        Ok(())
    }

    fn mark_detached_dir(&self) {
        debug_assert!(self.is_dir());
        self.detached.store(true, Ordering::Release);
    }
}

/// RF178-16 FIX: Serialize every RAMFS topology mutation. This is the authority
/// for directory emptiness, detach, and ancestry, so callers never need to nest
/// a child `entries` lock under a parent lock. It also linearizes the detached
/// tombstone with mutations through retained directory handles.
static RAMFS_TOPOLOGY_LOCK: spin::Mutex<()> = spin::Mutex::new(());

/// M0-6 slice 2: under the spanning lock, bind the manager's DAC/sticky/LSM decision (made
/// on `expected_src_ino` / `expected_dest_ino`) to the inode actually moved. A concurrent
/// create/unlink could swap a name between the manager's revalidation and this lock; if the
/// identity no longer matches, fail closed (PermDenied) rather than mutate an unauthorized
/// inode.
fn verify_rename_identity(
    inode: &Arc<RamFsInode>,
    dest: &Option<Arc<RamFsInode>>,
    expected_src_ino: u64,
    expected_dest_ino: Option<u64>,
) -> Result<(), FsError> {
    if inode.ino() != expected_src_ino {
        return Err(FsError::PermDenied);
    }
    match (dest.as_ref().map(|d| d.ino()), expected_dest_ino) {
        (Some(now), Some(exp)) if now == exp => Ok(()),
        (None, None) => Ok(()),
        _ => Err(FsError::PermDenied),
    }
}

/// M0-6 slice 2: the rename commit decision, computed UNDER the spanning lock from the
/// source inode + the (optional) destination inode, so the type/emptiness/noreplace checks
/// and the move are one atomic observation (no TOCTOU between the check and the mutation).
enum RenameDecision {
    /// Source and destination are the SAME inode — nothing to do.
    NoOp,
    /// Destination is absent — plain move.
    Move,
    /// Destination exists and will be overwritten (the victim is recovered from the
    /// commit insert's return value, under the same held lock).
    Replace,
}

/// Decide the rename outcome from the source inode and destination slot read under
/// the parent guard. Directory emptiness is the topology-locked preflight result.
fn rename_decide(
    inode: &Arc<RamFsInode>,
    inode_is_dir: bool,
    dest: Option<Arc<RamFsInode>>,
    dest_dir_empty: Option<bool>,
    noreplace: bool,
    old_parent: &RamFsInode,
    new_parent: &RamFsInode,
) -> Result<RenameDecision, FsError> {
    match dest {
        None => Ok(RenameDecision::Move),
        Some(existing) => {
            // R172-28 FIX: RENAME_NOREPLACE rejects ANY existing destination NAME, even the
            // same inode (Linux gates the flag in may_create/vfs_rename BEFORE the
            // source==target no-op). Hoisted ABOVE the ptr_eq no-op so a self-target
            // renameat2(RENAME_NOREPLACE) returns EEXIST, not 0.
            if noreplace {
                return Err(FsError::Exists);
            }
            // Renaming an entry onto itself (same inode) is a no-op (without NOREPLACE).
            if Arc::ptr_eq(inode, &existing) {
                return Ok(RenameDecision::NoOp);
            }
            // R172-14 FIX: overwriting either parent would orphan or cycle the
            // subtree. Reject it by identity, independent of lexical path checks.
            let ep: *const RamFsInode = Arc::as_ptr(&existing);
            if core::ptr::eq(ep, old_parent as *const RamFsInode)
                || core::ptr::eq(ep, new_parent as *const RamFsInode)
            {
                return Err(FsError::Invalid);
            }
            if existing.is_dir() {
                // A directory may only be replaced by a directory, and only if empty.
                if !inode_is_dir {
                    return Err(FsError::IsDir);
                }
                // RF178-16 FIX: Emptiness was sampled before parent write locks
                // under RAMFS_TOPOLOGY_LOCK. Do not nest a child read here.
                if dest_dir_empty != Some(true) {
                    return Err(FsError::NotEmpty);
                }
            } else if inode_is_dir {
                // A file may not be replaced by a directory.
                return Err(FsError::NotDir);
            }
            Ok(RenameDecision::Replace)
        }
    }
}

/// R172-15: does the directory `root` CONTAIN `target_ino` in its subtree (or IS it
/// `target_ino`)? Iterative DFS holding AT MOST ONE `entries` read-lock at a time
/// (snapshot-clone the child Arcs, DROP the lock, then descend) so it never lock-couples /
/// ABBAs with create/unlink (each takes a single parent write). ino-based: inos are unique
/// within the fs and never reused (`next_ino` is checked_add), so there is no ABA. Called
/// UNDER RAMFS_TOPOLOGY_LOCK (all topology mutators quiescent) to reject moving a
/// directory under its own subtree, which
/// would commit a mutual `Arc<RamFsInode>` cycle detached from root. Fails CLOSED to NoSpace
/// on heap exhaustion (a rename failing on genuine OOM is acceptable — never a panic, never a
/// false negative that would let the cycle through).
fn dir_subtree_contains_ino(root: &Arc<RamFsInode>, target_ino: u64) -> Result<bool, FsError> {
    if root.ino() == target_ino {
        return Ok(true);
    }
    let mut stack: alloc::vec::Vec<Arc<RamFsInode>> = alloc::vec::Vec::new();
    stack.try_reserve(1).map_err(|_| FsError::NoSpace)?;
    stack.push(root.clone());
    while let Some(node) = stack.pop() {
        // Snapshot this directory's children under a TRANSIENT read, then drop the lock before
        // descending (so at most one entries read is ever held).
        let children: alloc::vec::Vec<Arc<RamFsInode>> = match node.dir_entries() {
            Some(entries) => {
                let guard = entries.read();
                let mut v: alloc::vec::Vec<Arc<RamFsInode>> = alloc::vec::Vec::new();
                v.try_reserve(guard.entries.len())
                    .map_err(|_| FsError::NoSpace)?;
                for child in guard.entries.values() {
                    v.push(child.clone());
                }
                v // guard dropped here
            }
            None => continue,
        };
        for child in children {
            if child.ino() == target_ino {
                return Ok(true);
            }
            if child.dir_entries().is_some() {
                stack.try_reserve(1).map_err(|_| FsError::NoSpace)?;
                stack.push(child);
            }
        }
    }
    Ok(false)
}

/// Post-commit nlink / timestamp fixups (separate `meta` locks; run AFTER the spanning
/// `entries` guard(s) are released — lock order is always entries -> meta).
fn rename_apply_accounting(
    old_parent: &RamFsInode,
    new_parent: &RamFsInode,
    inode: &Arc<RamFsInode>,
    inode_is_dir: bool,
    victim: &Option<Arc<RamFsInode>>,
    same_parent: bool,
) {
    if let Some(victim) = victim {
        // An evicted directory removes its `..` link from the (new) parent.
        if victim.is_dir() {
            new_parent.dec_nlink();
        }
        victim.dec_nlink();
    }
    // A directory moved across parents re-homes its `..` link.
    if inode_is_dir && !same_parent {
        old_parent.dec_nlink();
        new_parent.inc_nlink();
    }
    inode.touch_ctime();
    old_parent.touch_mtime_ctime();
    if !same_parent {
        new_parent.touch_mtime_ctime();
    }
}

/// Release quota when file inode is dropped
impl Drop for RamFsInode {
    fn drop(&mut self) {
        // Release quota for file data when inode is freed
        match &self.kind {
            NodeKind::File { state } => {
                let state = state.read();
                if !state.data.is_empty() {
                    quota_release(state.data.len());
                }
            }
            NodeKind::Symlink { state } => {
                // SYM-QUOTA-BYPASS fix: symlink targets are charged at creation
                // (RamFs::symlink), so release symmetrically here. This also
                // reclaims the charge on the add_child-failure path, where the
                // freshly-built (never-linked) symlink Arc drops.
                let state = state.read();
                if !state.target.is_empty() {
                    quota_release(state.target.len());
                }
            }
            NodeKind::Dir { .. } => {}
        }
    }
}

impl Inode for RamFsInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let meta = self.meta.read();
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino,
            mode: meta.mode,
            nlink: meta.nlink,
            uid: meta.uid,
            gid: meta.gid,
            rdev: 0,
            size: meta.size,
            blksize: 4096,
            blocks: (meta.size + 511) / 512,
            atime: meta.atime,
            mtime: meta.mtime,
            ctime: meta.ctime,
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        // Directories can only be opened for read-only operations (getdents64)
        if matches!(self.kind, NodeKind::Dir { .. }) {
            if flags.is_writable() {
                return Err(FsError::IsDir);
            }
            let inode: Arc<dyn Inode> = self;
            return Ok(prepared.finalize(inode, flags, false));
        }

        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, true))
    }

    fn is_dir(&self) -> bool {
        matches!(self.kind, NodeKind::Dir { .. })
    }

    fn is_file(&self) -> bool {
        matches!(self.kind, NodeKind::File { .. })
    }

    fn is_symlink(&self) -> bool {
        matches!(self.kind, NodeKind::Symlink { .. })
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        match &self.kind {
            NodeKind::Dir { state } => {
                let state = state.read();
                let entries = &state.entries;

                // Handle "." and ".." at offsets 0 and 1
                if offset == 0 {
                    return Ok(Some((
                        1,
                        DirEntry {
                            name: ".".to_string(),
                            ino: self.ino,
                            file_type: FileType::Directory,
                        },
                    )));
                }
                if offset == 1 {
                    // ".." points to self for root, otherwise would need parent reference
                    return Ok(Some((
                        2,
                        DirEntry {
                            name: "..".to_string(),
                            ino: self.ino,
                            file_type: FileType::Directory,
                        },
                    )));
                }

                // Real entries start at offset 2
                let real_offset = offset - 2;
                let entry = entries.iter().nth(real_offset);

                match entry {
                    Some((name, inode)) => {
                        let file_type = if inode.is_dir() {
                            FileType::Directory
                        } else {
                            FileType::Regular
                        };
                        Ok(Some((
                            offset + 1,
                            DirEntry {
                                name: name.clone(),
                                ino: inode.ino,
                                file_type,
                            },
                        )))
                    }
                    None => Ok(None),
                }
            }
            NodeKind::File { .. } | NodeKind::Symlink { .. } => Err(FsError::NotDir),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        match &self.kind {
            NodeKind::File { state } => {
                let state = state.read();
                let data = &state.data;
                let offset = usize::try_from(offset).map_err(|_| FsError::Invalid)?;

                if offset >= data.len() {
                    return Ok(0); // EOF
                }

                let available = data.len() - offset;
                let to_read = buf.len().min(available);
                buf[..to_read].copy_from_slice(&data[offset..offset + to_read]);

                // Update atime (optional, can be skipped for performance)
                // self.meta.write().atime = TimeSpec::now();

                Ok(to_read)
            }
            NodeKind::Symlink { state } => {
                // Read symlink target (for readlink syscall)
                let state = state.read();
                let target_bytes = state.target.as_bytes();
                let offset = usize::try_from(offset).map_err(|_| FsError::Invalid)?;

                if offset >= target_bytes.len() {
                    return Ok(0); // EOF
                }

                let available = target_bytes.len() - offset;
                let to_read = buf.len().min(available);
                buf[..to_read].copy_from_slice(&target_bytes[offset..offset + to_read]);

                Ok(to_read)
            }
            NodeKind::Dir { .. } => Err(FsError::IsDir),
        }
    }

    fn write_at(&self, offset: u64, data_in: &[u8]) -> Result<usize, FsError> {
        match &self.kind {
            NodeKind::File { state } => {
                let mut state = state.write();
                let offset = usize::try_from(offset).map_err(|_| FsError::Invalid)?;
                let current_len = state.data.len();

                // Expand file if needed (with checked addition)
                let required_len = offset.checked_add(data_in.len()).ok_or(FsError::Invalid)?;

                // V-3 fix: Enforce maximum file size to prevent memory exhaustion DoS
                if required_len > MAX_FILE_SIZE {
                    return Err(FsError::NoSpace);
                }

                if required_len > current_len {
                    state.resize_data(required_len)?;
                }

                // Write data (in-place, no allocation)
                state.data[offset..offset + data_in.len()].copy_from_slice(data_in);

                // Update metadata
                let mut meta = self.meta.write();
                meta.size = state.data.len() as u64;
                let now = TimeSpec::now();
                meta.mtime = now;
                meta.ctime = now;

                Ok(data_in.len())
            }
            NodeKind::Dir { .. } => Err(FsError::IsDir),
            NodeKind::Symlink { .. } => Err(FsError::Invalid), // Symlinks are immutable
        }
    }

    // R178-21 FIX: Atomic append write with inode-level serialization
    fn append_write(&self, data_in: &[u8]) -> Result<(usize, u64), FsError> {
        match &self.kind {
            NodeKind::File { state } => {
                // Lock file data (inode-level) for atomic EOF + write
                let mut state = state.write();
                let offset = state.data.len();
                let required_len = offset.checked_add(data_in.len()).ok_or(FsError::Invalid)?;

                // V-3 fix: Enforce maximum file size
                if required_len > MAX_FILE_SIZE {
                    return Err(FsError::NoSpace);
                }

                if required_len > offset {
                    state.resize_data(required_len)?;
                }

                // Write data at EOF
                state.data[offset..required_len].copy_from_slice(data_in);

                // Update metadata
                let mut meta = self.meta.write();
                meta.size = state.data.len() as u64;
                let now = TimeSpec::now();
                meta.mtime = now;
                meta.ctime = now;

                Ok((data_in.len(), required_len as u64))
            }
            NodeKind::Dir { .. } => Err(FsError::IsDir),
            NodeKind::Symlink { .. } => Err(FsError::Invalid),
        }
    }

    fn truncate(&self, len: u64) -> Result<(), FsError> {
        match &self.kind {
            NodeKind::File { state } => {
                let new_len = usize::try_from(len).map_err(|_| FsError::Invalid)?;

                // V-3 fix: Enforce maximum file size to prevent memory exhaustion DoS
                if new_len > MAX_FILE_SIZE {
                    return Err(FsError::NoSpace);
                }

                let mut state = state.write();
                state.resize_data(new_len)?;

                // Update metadata
                let mut meta = self.meta.write();
                meta.size = len;
                let now = TimeSpec::now();
                meta.mtime = now;
                meta.ctime = now;

                Ok(())
            }
            NodeKind::Dir { .. } => Err(FsError::IsDir),
            NodeKind::Symlink { .. } => Err(FsError::Invalid), // Symlinks are immutable
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// RAM filesystem
pub struct RamFs {
    fs_id: u64,
    root: Arc<RamFsInode>,
    next_ino: AtomicU64,
    /// Charge for the RamFs Arc allocation itself. The charged root inode has
    /// its own independent lifetime charge.
    _heap_charge: HeapCharge,
}

impl RamFs {
    /// Create a new RAM filesystem with fully fallible, aggregate-admitted Arc
    /// publication. Boot callers may explicitly fail closed with `expect`.
    pub fn try_new() -> Result<Arc<Self>, FsError> {
        let fs_arc_bytes = heap_no_space(arc_charge_bytes::<Self>())?;
        let reservation = heap_no_space(try_reserve_heap(HeapClass::RamFs, fs_arc_bytes))?;
        // R112-2: overflow-safe ID allocation (standardized per R105-5 pattern)
        let fs_id = NEXT_FS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| FsError::NoSpace)?;
        // Root directory is owned by root (uid=0, gid=0)
        let root = RamFsInode::new_dir(fs_id, 1, 0o755, 0, 0)?;
        let charge = heap_no_space(reservation.commit())?;

        Arc::try_new(Self {
            fs_id,
            root,
            next_ino: AtomicU64::new(2),
            _heap_charge: charge,
        })
        .map_err(|_| FsError::NoSpace)
    }

    /// Allocate a new inode number (R112-2: overflow-safe)
    fn alloc_ino(&self) -> Result<u64, FsError> {
        self.next_ino
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| FsError::NoSpace)
    }

    /// Downcast an Inode to RamFsInode
    fn downcast_inode<'a>(&self, inode: &'a Arc<dyn Inode>) -> Result<&'a RamFsInode, FsError> {
        inode
            .as_any()
            .downcast_ref::<RamFsInode>()
            .ok_or(FsError::Invalid)
    }
}

impl FileSystem for RamFs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "ramfs"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let parent = self.downcast_inode(parent)?;
        let child = parent.lookup_child(name)?;
        Ok(child as Arc<dyn Inode>)
    }

    fn create(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        mode: FileMode,
    ) -> Result<Arc<dyn Inode>, FsError> {
        let parent = self.downcast_inode(parent)?;

        // Check if parent is a directory
        if !parent.is_dir() {
            return Err(FsError::NotDir);
        }

        // Allocate inode number
        let ino = self.alloc_ino()?;

        // Get current process credentials for file ownership
        // New files are owned by the effective uid of the creating process
        let creds = current_credentials();
        let uid = creds.as_ref().map(|c| c.euid).unwrap_or(0);

        // For gid: respect setgid bit on parent directory
        // If parent has setgid (mode 02000), new files inherit parent's gid
        // Otherwise, use creating process's effective gid
        let parent_meta = parent.meta.read();
        let gid = if parent_meta.mode.perm & 0o2000 != 0 {
            // Setgid directory: inherit parent's gid
            parent_meta.gid
        } else {
            // Normal: use creator's egid
            creds.as_ref().map(|c| c.egid).unwrap_or(0)
        };
        drop(parent_meta);

        // For directories in setgid parents, also set the setgid bit
        let final_perm = if mode.is_dir() {
            let parent_meta = parent.meta.read();
            if parent_meta.mode.perm & 0o2000 != 0 {
                mode.perm | 0o2000 // Propagate setgid bit to subdirectories
            } else {
                mode.perm
            }
        } else {
            mode.perm
        };

        // Create new inode based on type
        let new_inode = if mode.is_dir() {
            RamFsInode::new_dir(self.fs_id, ino, final_perm, uid, gid)?
        } else {
            RamFsInode::new_file(self.fs_id, ino, final_perm, uid, gid)?
        };

        // RF178-16 FIX: Publication is serialized with detach, and retained
        // handles to an unlinked directory cannot acquire new children.
        let _topology_guard = RAMFS_TOPOLOGY_LOCK.lock();
        parent.ensure_attached_dir()?;
        parent.add_child(name, new_inode.clone())?;

        // If creating a directory, increment parent's nlink
        if mode.is_dir() {
            parent.inc_nlink();
        }

        Ok(new_inode as Arc<dyn Inode>)
    }

    fn unlink(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        expected_ino: u64,
        must_be_dir: Option<bool>,
    ) -> Result<(), FsError> {
        let parent = self.downcast_inode(parent)?;

        // Check if parent is a directory
        if !parent.is_dir() {
            return Err(FsError::NotDir);
        }
        // remove_child rejected "."/".."; the inlined remove below must keep doing so.
        if name == "." || name == ".." {
            return Err(FsError::Invalid);
        }

        // RF178-16 FIX: Serialize emptiness validation and detach without
        // parent/child lock coupling; read locks can participate in ABBA too.
        let _topology_guard = RAMFS_TOPOLOGY_LOCK.lock();
        parent.ensure_attached_dir()?;
        let entries = parent.dir_entries().ok_or(FsError::NotDir)?;
        let current = entries
            .read()
            .entries
            .get(name)
            .cloned()
            .ok_or(FsError::NotFound)?;

        // Bind the manager's authorization and POSIX type decision to this inode.
        if current.ino() != expected_ino {
            return Err(FsError::PermDenied);
        }
        match must_be_dir {
            Some(true) if !current.is_dir() => return Err(FsError::NotDir),
            Some(false) if current.is_dir() => return Err(FsError::IsDir),
            _ => {}
        }

        // RF178-16 FIX: No topology mutator can add a child while the mutex is
        // held. Observe the child with a transient lock, release it, then detach
        // from the parent. No parent/child lock nesting is required.
        if let NodeKind::Dir { state } = &current.kind {
            if !state.read().entries.is_empty() {
                return Err(FsError::NotEmpty);
            }
        }

        // Try to compact before the destructive unlink, but never make a
        // resource-releasing operation depend on additional heap capacity.
        let target_len = entries
            .read()
            .entries
            .len()
            .checked_sub(1)
            .ok_or(FsError::NotFound)?;
        let prepared = prepare_directory_compaction(target_len);
        let mut parent_state = entries.write();
        let removed = commit_directory_remove(&mut parent_state, name, prepared);
        drop(parent_state);
        if removed.is_dir() {
            removed.mark_detached_dir();
        }

        // The raw-map remove bypassed remove_child (which updates the parent dir timestamps);
        // mirror it, exactly as the atomic rename path does (ramfs.rs ~:292).
        parent.touch_mtime_ctime();

        // If removing a directory, decrement parent's nlink
        if removed.is_dir() {
            parent.dec_nlink();
        }

        // Decrement the removed inode's nlink
        removed.dec_nlink();

        Ok(())
    }

    fn rename(
        &self,
        old_parent: &Arc<dyn Inode>,
        old_name: &str,
        new_parent: &Arc<dyn Inode>,
        new_name: &str,
        noreplace: bool,
        expected_src_ino: u64,
        expected_dest_ino: Option<u64>,
    ) -> Result<(), FsError> {
        let old_parent = self.downcast_inode(old_parent)?;
        let new_parent = self.downcast_inode(new_parent)?;

        // Both ends must be directories.
        if !old_parent.is_dir() || !new_parent.is_dir() {
            return Err(FsError::NotDir);
        }
        // '.'/'..' are never valid rename operands (defense-in-depth; the real
        // trailing-dot case is rejected at the manager BEFORE normalize_path collapses it).
        if old_name == "." || old_name == ".." || new_name == "." || new_name == ".." {
            return Err(FsError::Invalid);
        }
        // Pre-validate new_name against add_child's rules so the commit insert can never
        // fail on name grounds (the insert is the only would-be-fallible commit step).
        if new_name.is_empty() || new_name.len() > 255 || new_name.contains('/') {
            return Err(FsError::NameTooLong);
        }
        let old_entries = old_parent.dir_entries().ok_or(FsError::NotDir)?;
        let new_entries = new_parent.dir_entries().ok_or(FsError::NotDir)?;
        let same_parent = core::ptr::eq(old_parent, new_parent);
        debug_assert!(
            same_parent || old_parent.ino() != new_parent.ino(),
            "distinct ramfs parents must have distinct inode numbers"
        );

        // RF178-16 FIX: Rename participates in the same transaction as every
        // other topology mutator, making ancestry and victim emptiness stable.
        let _topology_guard = RAMFS_TOPOLOGY_LOCK.lock();
        old_parent.ensure_attached_dir()?;
        new_parent.ensure_attached_dir()?;

        // R172-15 FIX: under RAMFS_TOPOLOGY_LOCK, reject moving a DIRECTORY under its own
        // subtree (new_parent == source or a descendant of source). Committing that grafts a
        // mutual Arc<RamFsInode> cycle detached from root -> permanent subtree/data loss +
        // kernel-heap exhaustion via repeated cyclic renames. The manager's lexical guard
        // (manager.rs) is a path-string FAST-PATH that RACES two concurrent disjoint-subtree
        // renames against the original topology; this inode-identity walk UNDER the lock is the
        // authoritative check. Resolve the source transiently (its read-locks are all released
        // before the commit's write guards below, so no lock-coupling) for the cross-parent
        // directory case only (same-parent rename cannot change ancestry).
        if !same_parent {
            if let Ok(src) = old_parent.lookup_child(old_name) {
                if src.dir_entries().is_some() && dir_subtree_contains_ino(&src, new_parent.ino())?
                {
                    return Err(FsError::Invalid);
                }
            }
        }

        // RF178-16 FIX: Sample victim-directory emptiness without any parent
        // write lock. The topology mutex keeps it stable through the commit.
        let dest_dir_empty = match new_parent.lookup_child(new_name) {
            Ok(dest) if dest.is_dir() => Some(dest.child_count() == 0),
            _ => None,
        };

        // === Spanning critical section: prepare, then allocation-free commit ===
        // RAMFS_TOPOLOGY_LOCK keeps the preflight stable while all heap
        // reservations and detached backing/key allocations occur without a
        // directory spin lock held. Once preparation succeeds, commit performs
        // no allocation and cannot expose a half-rename.
        let (inode, inode_is_dir, victim) = if same_parent {
            let (inode, inode_is_dir, decision, parent_len) = {
                let g = old_entries.read();
                let inode = g.entries.get(old_name).cloned().ok_or(FsError::NotFound)?;
                let inode_is_dir = inode.is_dir();
                let dest = g.entries.get(new_name).cloned();
                verify_rename_identity(&inode, &dest, expected_src_ino, expected_dest_ino)?;
                let decision = rename_decide(
                    &inode,
                    inode_is_dir,
                    dest,
                    dest_dir_empty,
                    noreplace,
                    old_parent,
                    new_parent,
                )?;
                (inode, inode_is_dir, decision, g.entries.len())
            };

            match decision {
                RenameDecision::NoOp => return Ok(()),
                RenameDecision::Move => {
                    let prepared_key = PreparedDirectoryKey::try_new(new_name)?;
                    let mut g = old_entries.write();
                    let PreparedDirectoryKey {
                        key,
                        reservation,
                        charge_bytes,
                    } = prepared_key;
                    absorb_prepared(&mut g.heap_charge, reservation);
                    let (old_key, source) = g
                        .entries
                        .remove_entry(old_name)
                        .expect("R180 RAMFS same-parent source changed under topology lock");
                    let old_key_charge = string_buffer_charge(old_key.capacity())
                        .expect("R180 RAMFS old rename key charge overflow");
                    if let Err((key, source_for_insert)) =
                        g.entries.insert_unique_reserved(key, source.clone())
                    {
                        // Capacity is guaranteed after removing one entry. If
                        // the invariant is ever violated, restore the source
                        // allocation-free and release the unpublished key.
                        drop(key);
                        drop(source_for_insert);
                        release_deallocated(&mut g.heap_charge, charge_bytes);
                        g.entries
                            .insert_unique_reserved(old_key, source)
                            .unwrap_or_else(|_| panic!("R180 RAMFS rename rollback failed"));
                        return Err(FsError::NoSpace);
                    }
                    drop(old_key);
                    release_deallocated(&mut g.heap_charge, old_key_charge);
                    debug_assert_eq!(g.entries.len(), parent_len);
                    (inode, inode_is_dir, None)
                }
                RenameDecision::Replace => {
                    let target_len = parent_len.checked_sub(1).ok_or(FsError::NotFound)?;
                    let prepared = prepare_directory_compaction(target_len);
                    let mut g = old_entries.write();
                    let victim = core::mem::replace(
                        g.entries
                            .get_mut(new_name)
                            .expect("R180 RAMFS rename victim changed under topology lock"),
                        inode.clone(),
                    );
                    let removed_source = commit_directory_remove(&mut g, old_name, prepared);
                    debug_assert!(Arc::ptr_eq(&removed_source, &inode));
                    drop(removed_source);
                    (inode, inode_is_dir, Some(victim))
                }
            }
        } else {
            // Read-preflight both parents low-ino-first. The topology lock makes
            // the result stable while detached allocations are prepared.
            let (inode, inode_is_dir, decision, old_len, new_len, new_capacity) = {
                let (og, ng) = if old_parent.ino() < new_parent.ino() {
                    let og = old_entries.read();
                    let ng = new_entries.read();
                    (og, ng)
                } else {
                    let ng = new_entries.read();
                    let og = old_entries.read();
                    (og, ng)
                };
                let inode = og.entries.get(old_name).cloned().ok_or(FsError::NotFound)?;
                let inode_is_dir = inode.is_dir();
                let dest = ng.entries.get(new_name).cloned();
                verify_rename_identity(&inode, &dest, expected_src_ino, expected_dest_ino)?;
                let decision = rename_decide(
                    &inode,
                    inode_is_dir,
                    dest,
                    dest_dir_empty,
                    noreplace,
                    old_parent,
                    new_parent,
                )?;
                (
                    inode,
                    inode_is_dir,
                    decision,
                    og.entries.len(),
                    ng.entries.len(),
                    ng.entries.capacity(),
                )
            };

            match decision {
                RenameDecision::NoOp => return Ok(()),
                RenameDecision::Move => {
                    let old_compact = prepare_directory_compaction(
                        old_len.checked_sub(1).ok_or(FsError::NotFound)?,
                    );
                    let prepared_key = PreparedDirectoryKey::try_new(new_name)?;
                    let new_target = new_len.checked_add(1).ok_or(FsError::NoSpace)?;
                    let new_backing = if new_capacity < new_target {
                        Some(PreparedDirectoryCapacity::try_new(new_target)?)
                    } else {
                        None
                    };

                    let (mut og, mut ng) = if old_parent.ino() < new_parent.ino() {
                        let og = old_entries.write();
                        let ng = new_entries.write();
                        (og, ng)
                    } else {
                        let ng = new_entries.write();
                        let og = old_entries.write();
                        (og, ng)
                    };
                    commit_directory_insert(&mut ng, prepared_key, new_backing, inode.clone())?;
                    let removed_source = commit_directory_remove(&mut og, old_name, old_compact);
                    debug_assert!(Arc::ptr_eq(&removed_source, &inode));
                    drop(removed_source);
                    (inode, inode_is_dir, None)
                }
                RenameDecision::Replace => {
                    let old_compact = prepare_directory_compaction(
                        old_len.checked_sub(1).ok_or(FsError::NotFound)?,
                    );
                    let (mut og, mut ng) = if old_parent.ino() < new_parent.ino() {
                        let og = old_entries.write();
                        let ng = new_entries.write();
                        (og, ng)
                    } else {
                        let ng = new_entries.write();
                        let og = old_entries.write();
                        (og, ng)
                    };
                    let victim = core::mem::replace(
                        ng.entries
                            .get_mut(new_name)
                            .expect("R180 RAMFS cross-parent victim changed"),
                        inode.clone(),
                    );
                    let removed_source = commit_directory_remove(&mut og, old_name, old_compact);
                    debug_assert!(Arc::ptr_eq(&removed_source, &inode));
                    drop(removed_source);
                    (inode, inode_is_dir, Some(victim))
                }
            }
        };
        if let Some(ref evicted) = victim {
            if evicted.is_dir() {
                evicted.mark_detached_dir();
            }
        }
        // Guards released here -> nlink/timestamp fixups take only `meta` locks (entries
        // -> meta is the established lock order, so no inversion).
        rename_apply_accounting(
            old_parent,
            new_parent,
            &inode,
            inode_is_dir,
            &victim,
            same_parent,
        );
        Ok(())
    }

    fn symlink(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        target: &str,
    ) -> Result<Arc<dyn Inode>, FsError> {
        let parent = self.downcast_inode(parent)?;

        // Check if parent is a directory
        if !parent.is_dir() {
            return Err(FsError::NotDir);
        }

        // Validate target is not empty
        if target.is_empty() {
            return Err(FsError::Invalid);
        }

        // Validate target length. Linux PATH_MAX (4096) INCLUDES the NUL
        // terminator, so a symlink target caps at 4095 bytes; >= 4096 is
        // ENAMETOOLONG (SYM-PATH-MAX-DIVERGENCE fix).
        if target.len() >= 4096 {
            return Err(FsError::NameTooLong);
        }

        // Allocate inode number
        let ino = self.alloc_ino()?;

        // Get current process credentials for symlink ownership
        let creds = current_credentials();
        let uid = creds.as_ref().map(|c| c.euid).unwrap_or(0);

        // For gid: respect setgid bit on parent directory
        let parent_meta = parent.meta.read();
        let gid = if parent_meta.mode.perm & 0o2000 != 0 {
            parent_meta.gid
        } else {
            creds.as_ref().map(|c| c.egid).unwrap_or(0)
        };
        drop(parent_meta);

        // R180-13: target bytes, inode Arc, and quota are one private,
        // fallible construction transaction. Parent key/backing admission is
        // handled independently by `add_child`; failure drops this inode and
        // rolls both lifetime charges back exactly once.
        let inode = RamFsInode::new_symlink(self.fs_id, ino, 0o777, uid, gid, target)?;

        // RF178-16 FIX: Publication is serialized with directory detach.
        let _topology_guard = RAMFS_TOPOLOGY_LOCK.lock();
        parent.ensure_attached_dir()?;
        parent.add_child(name, inode.clone())?;

        Ok(inode as Arc<dyn Inode>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static HEAP_TEST_LOCK: spin::Mutex<()> = spin::Mutex::new(());

    fn publish_heap_admission() {
        mm::publish_heap_budgets();
    }

    #[test]
    fn create_rename_unlink_and_truncate_release_exact_charges() {
        let _serial = HEAP_TEST_LOCK.lock();
        publish_heap_admission();
        let class_before = mm::heap_class_snapshot(HeapClass::RamFs);
        let quota_before = ramfs_bytes_used();

        let fs = RamFs::try_new().expect("ramfs construction");
        let root = fs.root_inode();
        let fs_only = mm::heap_class_snapshot(HeapClass::RamFs);
        assert!(fs_only.committed_bytes > class_before.committed_bytes);

        let long_name = "r180-retained-key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let file = fs
            .create(&root, long_name, FileMode::new(FileType::Regular, 0o600))
            .expect("create admitted file");
        let ino = file.ino();
        let after_create = mm::heap_class_snapshot(HeapClass::RamFs);
        assert!(after_create.committed_bytes > fs_only.committed_bytes);

        let payload = [0xabu8; 16 * 1024];
        file.write_at(0, &payload).expect("grow admitted file");
        let after_write = mm::heap_class_snapshot(HeapClass::RamFs);
        assert!(after_write.committed_bytes > after_create.committed_bytes);
        assert_eq!(ramfs_bytes_used(), quota_before + payload.len());

        fs.rename(&root, long_name, &root, "x", false, ino, None)
            .expect("same-parent charged rename");
        let after_rename = mm::heap_class_snapshot(HeapClass::RamFs);
        assert!(
            after_rename.committed_bytes < after_write.committed_bytes,
            "old retained key capacity must be released after rename"
        );

        file.truncate(0).expect("truncate releases capacity");
        let after_truncate = mm::heap_class_snapshot(HeapClass::RamFs);
        assert!(after_truncate.committed_bytes < after_rename.committed_bytes);
        assert_eq!(ramfs_bytes_used(), quota_before);

        fs.unlink(&root, "x", ino, Some(false))
            .expect("unlink admitted file");
        let root_inode = fs.downcast_inode(&root).expect("ramfs root downcast");
        let root_state = root_inode.dir_entries().expect("root directory").read();
        assert_eq!(root_state.entries.len(), 0);
        assert_eq!(
            root_state.entries.capacity(),
            0,
            "unlink must compact retained map high-water capacity"
        );
        drop(root_state);

        // The open inode Arc deliberately keeps only its own Arc charge alive.
        let after_unlink = mm::heap_class_snapshot(HeapClass::RamFs);
        assert!(after_unlink.committed_bytes > fs_only.committed_bytes);
        drop(file);
        assert_eq!(mm::heap_class_snapshot(HeapClass::RamFs), fs_only);

        drop(root);
        drop(fs);
        assert_eq!(mm::heap_class_snapshot(HeapClass::RamFs), class_before);
        assert_eq!(ramfs_bytes_used(), quota_before);
    }

    #[test]
    fn admission_failure_rolls_back_inode_and_file_growth_transactions() {
        let _serial = HEAP_TEST_LOCK.lock();
        publish_heap_admission();
        let class_before = mm::heap_class_snapshot(HeapClass::RamFs);
        let quota_before = ramfs_bytes_used();

        let fs = RamFs::try_new().expect("ramfs construction");
        let root = fs.root_inode();
        let file = fs
            .create(&root, "held", FileMode::new(FileType::Regular, 0o600))
            .expect("fixture file");
        let ino = file.ino();
        let before_exhaustion = mm::heap_class_snapshot(HeapClass::RamFs);
        let remaining = before_exhaustion
            .capacity_bytes
            .checked_sub(before_exhaustion.committed_bytes + before_exhaustion.reserved_bytes)
            .expect("valid class snapshot");
        let exhaustion = mm::try_reserve_heap(HeapClass::RamFs, remaining)
            .expect("reserve remaining RAMFS class capacity");
        let exhausted_snapshot = mm::heap_class_snapshot(HeapClass::RamFs);

        match fs.create(
            &root,
            "must-not-publish",
            FileMode::new(FileType::Regular, 0o600),
        ) {
            Err(FsError::NoSpace) => {}
            Err(error) => panic!("unexpected inode admission error: {:?}", error),
            Ok(_) => panic!("inode Arc admission unexpectedly published"),
        }
        assert!(fs.lookup(&root, "must-not-publish").is_err());
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::RamFs),
            exhausted_snapshot
        );

        assert_eq!(
            file.write_at(0, &[0x11u8; 4096])
                .expect_err("file growth admission must fail"),
            FsError::NoSpace
        );
        assert_eq!(file.stat().expect("file stat").size, 0);
        assert_eq!(ramfs_bytes_used(), quota_before);
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::RamFs),
            exhausted_snapshot
        );

        drop(exhaustion);
        assert_eq!(mm::heap_class_snapshot(HeapClass::RamFs), before_exhaustion);
        fs.unlink(&root, "held", ino, Some(false))
            .expect("fixture unlink");
        drop(file);
        drop(root);
        drop(fs);
        assert_eq!(mm::heap_class_snapshot(HeapClass::RamFs), class_before);
        assert_eq!(ramfs_bytes_used(), quota_before);
    }

    #[test]
    fn unlink_remains_progress_making_when_compaction_cannot_be_admitted() {
        let _serial = HEAP_TEST_LOCK.lock();
        publish_heap_admission();
        let class_before = mm::heap_class_snapshot(HeapClass::RamFs);
        let quota_before = ramfs_bytes_used();

        let fs = RamFs::try_new().expect("ramfs construction");
        let root = fs.root_inode();
        let first = fs
            .create(&root, "first", FileMode::new(FileType::Regular, 0o600))
            .expect("first fixture");
        let second = fs
            .create(&root, "second", FileMode::new(FileType::Regular, 0o600))
            .expect("second fixture");

        let live = mm::heap_class_snapshot(HeapClass::RamFs);
        let remaining = live
            .capacity_bytes
            .checked_sub(live.committed_bytes + live.reserved_bytes)
            .expect("valid RAMFS class snapshot");
        let exhaustion = mm::try_reserve_heap(HeapClass::RamFs, remaining)
            .expect("reserve remaining RAMFS class capacity");

        // target_len=1 needs a detached replacement and cannot reserve it. The
        // unlink must still commit and retain the old backing under its charge.
        fs.unlink(&root, "first", first.ino(), Some(false))
            .expect("unlink must not depend on compaction allocation");
        assert!(matches!(fs.lookup(&root, "first"), Err(FsError::NotFound)));
        assert!(fs.lookup(&root, "second").is_ok());

        // target_len=0 uses an allocation-free empty backing and releases the
        // retained high-water capacity even while the exhaustion guard is live.
        fs.unlink(&root, "second", second.ino(), Some(false))
            .expect("last unlink must release retained backing");
        let root_inode = fs.downcast_inode(&root).expect("ramfs root");
        let root_state = root_inode.dir_entries().expect("root directory").read();
        assert_eq!(root_state.entries.capacity(), 0);
        drop(root_state);

        drop(exhaustion);
        drop(first);
        drop(second);
        drop(root);
        drop(fs);
        assert_eq!(mm::heap_class_snapshot(HeapClass::RamFs), class_before);
        assert_eq!(ramfs_bytes_used(), quota_before);
    }
}
