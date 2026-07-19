//! VFS trait definitions
//!
//! Core traits for filesystem and inode operations.

use crate::types::{DirEntry, FileMode, FsError, OpenFlags, Stat};
use alloc::alloc::{dealloc, Layout};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ops::Deref;
use core::ptr::NonNull;
use core::sync::atomic::{fence, AtomicUsize, Ordering};
use kernel_core::{FileDescriptor, FileOps, PreparedFileDescriptor, SyscallError, VfsStat};
use mm::{allocation_charge_bytes, try_reserve_heap, HeapCharge, HeapClass};

/// Filesystem trait
///
/// Each mounted filesystem implements this trait. The VFS uses these methods
/// for path resolution and metadata operations.
pub trait FileSystem: Send + Sync {
    /// Get unique filesystem ID
    fn fs_id(&self) -> u64;

    /// Get filesystem type name (e.g., "devfs", "ramfs")
    fn fs_type(&self) -> &'static str;

    /// Get root inode
    fn root_inode(&self) -> Arc<dyn Inode>;

    /// Look up a child entry by name
    ///
    /// # Arguments
    /// * `parent` - Parent inode (must be a directory)
    /// * `name` - Child entry name
    ///
    /// # Returns
    /// The child inode or FsError::NotFound
    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError>;

    /// Create a new file or directory
    ///
    /// # Arguments
    /// * `parent` - Parent directory inode
    /// * `name` - New entry name
    /// * `mode` - File mode (type + permissions)
    ///
    /// # Returns
    /// The new inode or error
    fn create(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        mode: FileMode,
    ) -> Result<Arc<dyn Inode>, FsError> {
        let _ = (parent, name, mode);
        Err(FsError::NotSupported)
    }

    /// Remove a file or empty directory.
    ///
    /// `expected_ino` / `must_be_dir` mirror `rename`'s identity-binding discipline
    /// (R172-X-F4-FOLLOWON). The fs MUST, under its directory lock, verify that `name` still
    /// resolves to `expected_ino` (else fail closed) AND that the revalidated entry satisfies
    /// `must_be_dir` (`None` = any type; `Some(true)` = must be a directory, else
    /// `FsError::NotDir`; `Some(false)` = must NOT be a directory, else `FsError::IsDir`) —
    /// atomically with the removal. This makes the rmdir-vs-unlink POSIX type gate immune to a
    /// concurrent file<->dir swap between the caller's resolution and the actual removal (the
    /// gate previously lived in a SEPARATE syscall-layer `stat()`).
    fn unlink(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        expected_ino: u64,
        must_be_dir: Option<bool>,
    ) -> Result<(), FsError> {
        let _ = (parent, name, expected_ino, must_be_dir);
        Err(FsError::NotSupported)
    }

    /// Rename an entry. `noreplace` (M0-6 slice 2, from renameat2 RENAME_NOREPLACE) makes
    /// an existing destination an error (EEXIST) instead of being overwritten.
    /// `expected_src_ino` / `expected_dest_ino` bind the caller's DAC/sticky/LSM decision to
    /// the inode actually moved: the fs MUST verify (under its rename lock) that the source
    /// name still maps to `expected_src_ino` and the destination still matches
    /// `expected_dest_ino` (same inode if Some, absent if None), else fail closed.
    #[allow(clippy::too_many_arguments)]
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
        let _ = (
            old_parent,
            old_name,
            new_parent,
            new_name,
            noreplace,
            expected_src_ino,
            expected_dest_ino,
        );
        Err(FsError::NotSupported)
    }

    /// Create a symbolic link
    ///
    /// # Arguments
    /// * `parent` - Parent directory inode
    /// * `name` - New symlink name
    /// * `target` - Symlink target path (not validated, stored as-is)
    ///
    /// # Returns
    /// The new symlink inode or error
    fn symlink(
        &self,
        parent: &Arc<dyn Inode>,
        name: &str,
        target: &str,
    ) -> Result<Arc<dyn Inode>, FsError> {
        let _ = (parent, name, target);
        Err(FsError::NotSupported)
    }

    /// Sync filesystem to storage (flush caches)
    fn sync(&self) -> Result<(), FsError> {
        Ok(())
    }
}

/// Inode trait
///
/// Represents an in-memory inode. Each filesystem creates its own inode type
/// implementing this trait.
pub trait Inode: Send + Sync {
    /// Get inode number (unique within filesystem)
    fn ino(&self) -> u64;

    /// Get filesystem ID this inode belongs to
    fn fs_id(&self) -> u64;

    /// Get file metadata
    fn stat(&self) -> Result<Stat, FsError>;

    /// Open the inode, returning a file operations handle
    ///
    /// # Arguments
    /// * `flags` - Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
    ///
    /// # Returns
    /// A FileOps implementation for read/write operations
    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError>;

    /// Check if this inode is a directory
    fn is_dir(&self) -> bool {
        self.stat().map(|s| s.mode.is_dir()).unwrap_or(false)
    }

    /// Check if this inode is a regular file
    fn is_file(&self) -> bool {
        self.stat().map(|s| s.mode.is_file()).unwrap_or(false)
    }

    /// Check if this inode is a symbolic link
    fn is_symlink(&self) -> bool {
        self.stat().map(|s| s.mode.is_symlink()).unwrap_or(false)
    }

    /// Read directory entries
    ///
    /// # Arguments
    /// * `offset` - Entry offset (0 for first entry)
    ///
    /// # Returns
    /// (next_offset, entry) or None if no more entries
    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        let _ = offset;
        Err(FsError::NotDir)
    }

    /// Read data at given offset
    ///
    /// Default implementation returns NotSupported. Regular files should override.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let _ = (offset, buf);
        Err(FsError::NotSupported)
    }

    /// R180-L1: transactional read hook for sources whose `read_at` consumes
    /// data (character devices, queues). The default is correct for ordinary
    /// files: fill the caller's staging buffer, run copyout, then let the open
    /// file description publish its offset. Consuming devices override this to
    /// peek, copy, and consume only after `commit` succeeds.
    fn read_at_with_commit(
        &self,
        offset: u64,
        buf: &mut [u8],
        commit: &mut dyn FnMut(&[u8]) -> Result<(), FsError>,
    ) -> Result<usize, FsError> {
        let count = self.read_at(offset, buf)?.min(buf.len());
        commit(&buf[..count])?;
        Ok(count)
    }

    /// Write data at given offset
    ///
    /// Default implementation returns NotSupported. Regular files should override.
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        let _ = (offset, data);
        Err(FsError::NotSupported)
    }

    /// Truncate file to given length
    fn truncate(&self, len: u64) -> Result<(), FsError> {
        let _ = len;
        Err(FsError::NotSupported)
    }

    /// R178-21 FIX: Atomic append write primitive
    ///
    /// Atomically selects EOF and writes data under inode-level serialization.
    /// This makes O_APPEND writes atomic across independent file handles.
    ///
    /// RF178-17 FIX: The default fails closed. A stat()+write_at() fallback is
    /// inherently racy across independent handles, so filesystems must provide
    /// explicit inode-level append serialization.
    ///
    /// Returns (bytes_written, final_offset_after_write)
    fn append_write(&self, data: &[u8]) -> Result<(usize, u64), FsError> {
        let _ = data;
        Err(FsError::NotSupported)
    }

    /// Get as Any for downcasting
    fn as_any(&self) -> &dyn Any;
}

/// File handle wrapper that implements FileOps
///
/// This wraps an inode with open state (offset, flags) and provides
/// the standard file operations.
const MAX_SHARED_OFFSET_REFS: usize = isize::MAX as usize;

struct SharedFileOffsetInner {
    strong: AtomicUsize,
    /// Explicit weak references plus one implicit weak reference while strong
    /// ownership is nonzero, matching Arc's reclamation discipline.
    weak: AtomicUsize,
    value: ManuallyDrop<spin::Mutex<u64>>,
    /// Initialized before publication and moved out only by the last weak
    /// owner, immediately before the backing allocation is deallocated.
    charge: MaybeUninit<HeapCharge>,
}

/// Exact-lifetime shared offset for one open file description.
///
/// RF180-37: an ordinary `Arc<Mutex<u64>>` cannot embed its admission charge in
/// the payload: the payload is destroyed when the last strong reference drops,
/// while the Arc allocation remains live until the last Weak drops. This small,
/// purpose-built Arc keeps the charge in the allocation and moves it to the
/// final weak drop, which deallocates first and releases admission second.
pub struct SharedFileOffset {
    ptr: NonNull<SharedFileOffsetInner>,
}

/// Non-owning offset reference. Its presence deliberately keeps the backing
/// allocation and admission charge alive after the last strong owner.
pub struct WeakSharedFileOffset {
    ptr: NonNull<SharedFileOffsetInner>,
}

unsafe impl Send for SharedFileOffset {}
unsafe impl Sync for SharedFileOffset {}
unsafe impl Send for WeakSharedFileOffset {}
unsafe impl Sync for WeakSharedFileOffset {}

impl SharedFileOffset {
    fn try_new() -> Result<Self, FsError> {
        let bytes = allocation_charge_bytes(
            core::mem::size_of::<SharedFileOffsetInner>(),
            core::mem::align_of::<SharedFileOffsetInner>(),
        )
        .map_err(|_| FsError::NoMem)?;
        let reservation = try_reserve_heap(HeapClass::Vfs, bytes).map_err(|_| FsError::NoMem)?;
        let mut inner = Box::try_new(SharedFileOffsetInner {
            strong: AtomicUsize::new(1),
            weak: AtomicUsize::new(1),
            value: ManuallyDrop::new(spin::Mutex::new(0)),
            charge: MaybeUninit::uninit(),
        })
        .map_err(|_| FsError::NoMem)?;
        let charge = match reservation.commit() {
            Ok(charge) => charge,
            Err(_) => {
                unsafe {
                    ManuallyDrop::drop(&mut inner.value);
                }
                return Err(FsError::NoMem);
            }
        };
        inner.charge.write(charge);
        let ptr = unsafe { NonNull::new_unchecked(Box::into_raw(inner)) };
        Ok(Self { ptr })
    }

    #[inline]
    pub fn downgrade(&self) -> WeakSharedFileOffset {
        increment_refcount(unsafe { &self.ptr.as_ref().weak }, "shared offset weak");
        WeakSharedFileOffset { ptr: self.ptr }
    }

    #[inline]
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        this.ptr == other.ptr
    }

    #[inline]
    pub fn strong_count(&self) -> usize {
        unsafe { self.ptr.as_ref().strong.load(Ordering::Acquire) }
    }

    #[inline]
    pub fn weak_count(&self) -> usize {
        let inner = unsafe { self.ptr.as_ref() };
        let implicit = usize::from(inner.strong.load(Ordering::Acquire) != 0);
        inner.weak.load(Ordering::Acquire).saturating_sub(implicit)
    }
}

impl Clone for SharedFileOffset {
    fn clone(&self) -> Self {
        increment_refcount(unsafe { &self.ptr.as_ref().strong }, "shared offset strong");
        Self { ptr: self.ptr }
    }
}

impl Deref for SharedFileOffset {
    type Target = spin::Mutex<u64>;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(&self.ptr.as_ref().value as *const ManuallyDrop<_> as *const spin::Mutex<u64>) }
    }
}

impl core::fmt::Debug for SharedFileOffset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedFileOffset")
            .field("strong", &self.strong_count())
            .field("weak", &self.weak_count())
            .finish_non_exhaustive()
    }
}

impl Drop for SharedFileOffset {
    fn drop(&mut self) {
        let inner = unsafe { self.ptr.as_ref() };
        if inner.strong.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        unsafe {
            ManuallyDrop::drop(&mut self.ptr.as_mut().value);
        }
        release_shared_offset_weak(self.ptr);
    }
}

impl WeakSharedFileOffset {
    pub fn upgrade(&self) -> Option<SharedFileOffset> {
        let strong = unsafe { &self.ptr.as_ref().strong };
        let mut current = strong.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return None;
            }
            if current >= MAX_SHARED_OFFSET_REFS {
                panic!("shared offset strong reference count overflow");
            }
            match strong.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(SharedFileOffset { ptr: self.ptr }),
                Err(observed) => current = observed,
            }
        }
    }

    #[inline]
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        this.ptr == other.ptr
    }
}

impl Clone for WeakSharedFileOffset {
    fn clone(&self) -> Self {
        increment_refcount(unsafe { &self.ptr.as_ref().weak }, "shared offset weak");
        Self { ptr: self.ptr }
    }
}

impl core::fmt::Debug for WeakSharedFileOffset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let inner = unsafe { self.ptr.as_ref() };
        f.debug_struct("WeakSharedFileOffset")
            .field("strong", &inner.strong.load(Ordering::Acquire))
            .field("weak_total", &inner.weak.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl Drop for WeakSharedFileOffset {
    fn drop(&mut self) {
        release_shared_offset_weak(self.ptr);
    }
}

#[inline]
fn increment_refcount(counter: &AtomicUsize, kind: &'static str) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current == 0 || current >= MAX_SHARED_OFFSET_REFS {
            panic!("{kind} reference count overflow or resurrection");
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn release_shared_offset_weak(ptr: NonNull<SharedFileOffsetInner>) {
    let inner = unsafe { ptr.as_ref() };
    if inner.weak.fetch_sub(1, Ordering::Release) != 1 {
        return;
    }
    fence(Ordering::Acquire);
    unsafe {
        let charge = ptr.as_ref().charge.as_ptr().read();
        dealloc(
            ptr.as_ptr().cast::<u8>(),
            Layout::new::<SharedFileOffsetInner>(),
        );
        drop(charge);
    }
}

/// Fully allocated open-file-description storage.
///
/// Construct this before path lookup/create. `finalize` performs no allocation,
/// so O_CREAT/O_TRUNC cannot become visible and then fail solely because the fd
/// object or shared offset could not be allocated.
pub struct PreparedFileHandle {
    descriptor: PreparedFileDescriptor<FileHandle>,
    offset: SharedFileOffset,
}

impl PreparedFileHandle {
    pub fn try_new() -> Result<Self, FsError> {
        let descriptor = FileDescriptor::try_prepare(HeapClass::Vfs).map_err(|_| FsError::NoMem)?;
        let offset = SharedFileOffset::try_new()?;
        Ok(Self { descriptor, offset })
    }

    pub fn finalize(
        self,
        inode: Arc<dyn Inode>,
        flags: OpenFlags,
        seekable: bool,
    ) -> FileDescriptor {
        self.descriptor.finalize(FileHandle {
            inode,
            offset: self.offset,
            flags,
            seekable,
        })
    }
}

#[non_exhaustive]
pub struct FileHandle {
    /// The underlying inode
    pub inode: Arc<dyn Inode>,
    /// Current file offset (shared via Arc for clone to share offset)
    pub offset: SharedFileOffset,
    /// Open flags
    pub flags: OpenFlags,
    /// Whether this handle supports seeking
    pub seekable: bool,
}

/// R41-3 FIX: Implement Clone for FileHandle to allow dropping process lock before I/O.
///
/// Cloning a FileHandle shares the same offset via Arc, ensuring that
/// reads/writes from a clone update the original handle's position.
/// This enables fd_read/fd_write to release the process lock before performing
/// potentially blocking I/O operations while maintaining correct file position.
impl Clone for FileHandle {
    fn clone(&self) -> Self {
        Self {
            inode: Arc::clone(&self.inode),
            offset: self.offset.clone(),
            flags: self.flags,
            seekable: self.seekable,
        }
    }
}

impl FileHandle {
    fn try_clone_descriptor(&self) -> Result<FileDescriptor, ()> {
        let prepared = FileDescriptor::try_prepare(HeapClass::Vfs)?;
        Ok(prepared.finalize(self.clone()))
    }

    /// Read from current offset
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, FsError> {
        if !self.flags.is_readable() {
            return Err(FsError::BadFd);
        }

        let mut offset = self.offset.lock();
        let n = self.inode.read_at(*offset, buf)?;
        *offset += n as u64;
        Ok(n)
    }

    /// Write to current offset (or end if append mode)
    pub fn write(&self, data: &[u8]) -> Result<usize, FsError> {
        if !self.flags.is_writable() {
            return Err(FsError::BadFd);
        }

        // R178-21 FIX: O_APPEND uses inode-level atomic append primitive
        if self.flags.is_append() {
            // RF178-17 FIX: Keep this open file description's offset lock across
            // EOF selection, I/O, and final offset publication. Independent
            // handles serialize at the inode; clones serialize here.
            let mut offset = self.offset.lock();
            let (n, final_offset) = self.inode.append_write(data)?;
            *offset = final_offset;
            return Ok(n);
        }

        let mut offset = self.offset.lock();
        let n = self.inode.write_at(*offset, data)?;
        *offset += n as u64;
        Ok(n)
    }

    /// Seek to new offset
    pub fn seek(&self, off: i64, whence: crate::types::SeekWhence) -> Result<u64, FsError> {
        if !self.seekable {
            return Err(FsError::Seek);
        }

        let mut offset = self.offset.lock();
        let new_offset = match whence {
            crate::types::SeekWhence::Set => {
                if off < 0 {
                    return Err(FsError::Invalid);
                }
                off as u64
            }
            crate::types::SeekWhence::Cur => {
                let cur = *offset as i64;
                let new = cur.checked_add(off).ok_or(FsError::Invalid)?;
                if new < 0 {
                    return Err(FsError::Invalid);
                }
                new as u64
            }
            crate::types::SeekWhence::End => {
                let stat = self.inode.stat()?;
                let size = stat.size as i64;
                let new = size.checked_add(off).ok_or(FsError::Invalid)?;
                if new < 0 {
                    return Err(FsError::Invalid);
                }
                new as u64
            }
        };

        *offset = new_offset;
        Ok(new_offset)
    }

    /// Get current offset
    pub fn current_offset(&self) -> u64 {
        *self.offset.lock()
    }

    /// Get file stat
    pub fn stat(&self) -> Result<Stat, FsError> {
        self.inode.stat()
    }
}

impl FileOps for FileHandle {
    fn clone_box(&self) -> FileDescriptor {
        self.try_clone_descriptor()
            .expect("FileHandle clone allocation/admission failed")
    }

    fn try_clone_box(&self) -> Result<FileDescriptor, ()> {
        self.try_clone_descriptor()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn type_name(&self) -> &'static str {
        "FileHandle"
    }

    /// R41-1 FIX: Return actual inode metadata for fstat.
    /// R154-1 FIX: MAC gate for fd-backed stat — prevents metadata probe
    /// via inherited/pre-policy fds that bypass path-based R153-2 check.
    fn stat(&self) -> Result<VfsStat, SyscallError> {
        let inode_stat = self.inode.stat().map_err(SyscallError::from)?;
        let vfs_stat = VfsStat::from(inode_stat);
        if let Some(task) = lsm::ProcessCtx::from_current() {
            lsm::hook_file_permission(&task, vfs_stat.ino, 0).map_err(|_| SyscallError::EACCES)?;
        }
        Ok(vfs_stat)
    }
}

#[cfg(test)]
mod rf180_37_tests {
    use super::*;
    use crate::types::{FileType, TimeSpec};

    static HEAP_TEST_LOCK: spin::Mutex<()> = spin::Mutex::new(());

    struct TestInode;

    impl Inode for TestInode {
        fn ino(&self) -> u64 {
            1
        }

        fn fs_id(&self) -> u64 {
            1
        }

        fn stat(&self) -> Result<Stat, FsError> {
            Ok(Stat {
                dev: 1,
                ino: 1,
                mode: FileMode::new(FileType::Regular, 0o600),
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                size: 0,
                blksize: 4096,
                blocks: 0,
                atime: TimeSpec::new(0, 0),
                mtime: TimeSpec::new(0, 0),
                ctime: TimeSpec::new(0, 0),
            })
        }

        fn open(
            self: Arc<Self>,
            flags: OpenFlags,
            prepared: PreparedFileHandle,
        ) -> Result<FileDescriptor, FsError> {
            let inode: Arc<dyn Inode> = self;
            Ok(prepared.finalize(inode, flags, true))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn rf180_37_descriptor_and_shared_offset_charges_have_exact_lifetimes() {
        let _serial = HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let before = mm::heap_class_snapshot(HeapClass::Vfs);

        let prepared = PreparedFileHandle::try_new().expect("prepare file handle");
        let prepared_snapshot = mm::heap_class_snapshot(HeapClass::Vfs);
        assert!(prepared_snapshot.committed_bytes > before.committed_bytes);
        assert_eq!(prepared_snapshot.reserved_bytes, before.reserved_bytes);
        drop(prepared);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Vfs), before);

        let inode = Arc::new(TestInode);
        let original = inode
            .clone()
            .open(
                OpenFlags::new(OpenFlags::O_RDWR),
                PreparedFileHandle::try_new().expect("prepare original descriptor"),
            )
            .expect("finalize original descriptor");
        let one_descriptor = mm::heap_class_snapshot(HeapClass::Vfs);
        let original_handle = original
            .as_any()
            .downcast_ref::<FileHandle>()
            .expect("original FileHandle");
        let weak = original_handle.offset.downgrade();

        let cloned = original.try_clone().expect("fallible descriptor clone");
        let two_descriptors = mm::heap_class_snapshot(HeapClass::Vfs);
        assert!(two_descriptors.committed_bytes > one_descriptor.committed_bytes);
        let cloned_handle = cloned
            .as_any()
            .downcast_ref::<FileHandle>()
            .expect("cloned FileHandle");
        assert!(SharedFileOffset::ptr_eq(
            &original_handle.offset,
            &cloned_handle.offset
        ));
        assert_eq!(cloned_handle.offset.strong_count(), 2);

        drop(original);
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::Vfs),
            one_descriptor,
            "dropping one descriptor must release exactly one outer allocation"
        );
        let cloned_handle = cloned
            .as_any()
            .downcast_ref::<FileHandle>()
            .expect("retained clone FileHandle");
        assert_eq!(cloned_handle.offset.strong_count(), 1);
        *cloned_handle.offset.lock() = 0x5a5a;
        assert_eq!(
            *weak.upgrade().expect("clone keeps offset live").lock(),
            0x5a5a
        );

        drop(cloned);
        let weak_only = mm::heap_class_snapshot(HeapClass::Vfs);
        assert!(weak_only.committed_bytes > before.committed_bytes);
        assert!(weak_only.committed_bytes < one_descriptor.committed_bytes);
        assert!(weak.upgrade().is_none());

        drop(weak);
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::Vfs),
            before,
            "the last Weak must deallocate backing before releasing its charge"
        );
    }
}
