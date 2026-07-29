//! Process filesystem (procfs)
//!
//! Provides /proc virtual filesystem with process information:
//! - /proc/self - Symlink to current process directory
//! - /proc/[pid]/ - Per-process directory
//! - /proc/[pid]/status - Process status
//! - /proc/[pid]/cmdline - Command line
//! - /proc/[pid]/stat - Process statistics
//! - /proc/meminfo - System memory information
//! - /proc/cpuinfo - CPU information

use crate::traits::{FileSystem, Inode, PreparedFileHandle};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::FileDescriptor;
// R29-1 FIX: Import process module for real process information
use kernel_core::process::{self, ProcessArc, ProcessState, ProcessWeak, PROCESS_TABLE};
// R36 FIX: Import time module for uptime and mm for memory stats
use kernel_core::time;
use mm::memory::FrameAllocator;
use mm::page_cache::PAGE_CACHE;
use mm::{arc_charge_bytes, try_reserve_heap, AdmittedString, AdmittedVec, HeapCharge, HeapClass};

/// Global procfs ID counter
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(200);
static FAIL_NEXT_PROCFS_ARC: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Build one procfs-owned Arc only after admitting its complete allocation.
/// The charge is embedded as the final payload field, matching the existing
/// ramfs/devfs inode discipline. Procfs never stores Weak inode references, so
/// the final strong drop immediately destroys the payload and then its control
/// block; process Arcs use the stronger allocator-owned lifetime below because
/// procfs deliberately retains `ProcessWeak` handles.
fn try_new_procfs_arc<T>(build: impl FnOnce(HeapCharge) -> T) -> Result<Arc<T>, FsError> {
    if FAIL_NEXT_PROCFS_ARC.swap(false, Ordering::AcqRel) {
        return Err(FsError::NoMem);
    }
    let bytes = arc_charge_bytes::<T>().map_err(|_| FsError::NoMem)?;
    let reservation = try_reserve_heap(HeapClass::Procfs, bytes).map_err(|_| FsError::NoMem)?;
    let charge = reservation.commit().map_err(|_| FsError::NoMem)?;
    Arc::try_new(build(charge)).map_err(|_| FsError::NoMem)
}

/// RF178-19 FIX: Stable identity and namespace view for every per-process
/// procfs inode. Holding the exact Process Arc prevents any later raw-PID
/// lookup from crossing a recycled table slot.
#[derive(Clone)]
struct ProcIdentity {
    /// A procfs descriptor must not retain an exited task's complete PCB/MM/FD
    /// graph indefinitely. Upgrade only while validating or snapshotting.
    process: ProcessWeak,
    pid: u32,
    generation: u64,
    display_pid: u32,
    viewer_ns: Option<kernel_core::PidNamespaceArc>,
}

type BoundProcess = ProcessArc;

// ============================================================================
// ProcFs
// ============================================================================

/// Process filesystem
pub struct ProcFs {
    fs_id: u64,
    root: Arc<ProcRootInode>,
    /// RF180-40: admission for the ProcFs Arc itself.
    _heap_charge: Option<HeapCharge>,
}

impl ProcFs {
    /// Create a new procfs through fully fallible, admitted Arc publication.
    pub fn try_new() -> Result<Arc<Self>, FsError> {
        // R112-2: overflow-safe ID allocation (standardized per R105-5 pattern)
        let fs_id = NEXT_FS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| FsError::NoMem)?;

        let root = try_new_procfs_arc(|charge| ProcRootInode {
            fs_id,
            _heap_charge: Some(charge),
        })?;

        try_new_procfs_arc(|charge| Self {
            fs_id,
            root,
            _heap_charge: Some(charge),
        })
    }

    /// RF180-40 deterministic production-path test: every procfs Arc is
    /// admitted, an injected allocation failure returns ENOMEM semantics with
    /// no ledger drift, and dropping the complete private filesystem releases
    /// all Procfs-class bytes.
    pub fn run_admission_self_test() {
        let before = mm::heap_class_snapshot(HeapClass::Procfs);
        let fs = Self::try_new().expect("RF180-40 procfs fixture");
        let root = fs.root_inode();
        let stable = mm::heap_class_snapshot(HeapClass::Procfs);

        FAIL_NEXT_PROCFS_ARC.store(true, Ordering::Release);
        assert!(matches!(fs.lookup(&root, "meminfo"), Err(FsError::NoMem)));
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::Procfs),
            stable,
            "RF180-40 failed procfs inode publication drifted admission"
        );

        for name in ["meminfo", "cpuinfo", "uptime", "version"] {
            let inode = fs
                .lookup(&root, name)
                .expect("RF180-40 admitted procfs inode publication");
            drop(inode);
            assert_eq!(
                mm::heap_class_snapshot(HeapClass::Procfs),
                stable,
                "RF180-40 dropped procfs inode retained admission"
            );
        }

        drop(root);
        drop(fs);
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::Procfs),
            before,
            "RF180-40 procfs fixture leaked admission"
        );
    }
}

impl FileSystem for ProcFs {
    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn fs_type(&self) -> &'static str {
        "proc"
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn lookup(&self, parent: &Arc<dyn Inode>, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // Check if parent is root
        if parent.ino() == 1 {
            return self.root.lookup_child(name);
        }

        // Check if parent is a PID directory
        if let Some(proc_dir) = parent.as_any().downcast_ref::<ProcPidDirInode>() {
            return proc_dir.lookup_child(name);
        }

        // Traverse /proc/self/<...> by delegating to the current PID directory
        if let Some(self_link) = parent.as_any().downcast_ref::<ProcSelfSymlink>() {
            let alias_dir = ProcPidDirInode {
                fs_id: self.fs_id,
                identity: self_link.identity.clone(),
                _heap_charge: None,
            };
            return alias_dir.lookup_child(name);
        }

        // Resolve entries under /proc/[pid]/fd
        if let Some(fd_dir) = parent.as_any().downcast_ref::<ProcPidFdDirInode>() {
            return fd_dir.lookup_child(name);
        }

        Err(FsError::NotFound)
    }
}

// ============================================================================
// Root Directory (/proc)
// ============================================================================

/// /proc root directory inode
struct ProcRootInode {
    fs_id: u64,
    _heap_charge: Option<HeapCharge>,
}

impl ProcRootInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "self" => {
                let identity = bind_current_proc_identity(get_current_pid())?;
                Ok(try_new_procfs_arc(|charge| ProcSelfSymlink {
                    fs_id: self.fs_id,
                    identity,
                    _heap_charge: Some(charge),
                })?)
            }
            "meminfo" => Ok(try_new_procfs_arc(|charge| ProcMeminfoInode {
                fs_id: self.fs_id,
                _heap_charge: Some(charge),
            })?),
            "cpuinfo" => Ok(try_new_procfs_arc(|charge| ProcCpuinfoInode {
                fs_id: self.fs_id,
                _heap_charge: Some(charge),
            })?),
            "uptime" => Ok(try_new_procfs_arc(|charge| ProcUptimeInode {
                fs_id: self.fs_id,
                _heap_charge: Some(charge),
            })?),
            "version" => Ok(try_new_procfs_arc(|charge| ProcVersionInode {
                fs_id: self.fs_id,
                _heap_charge: Some(charge),
            })?),
            _ => {
                // Try to parse as PID
                if let Ok(ns_pid) = name.parse::<u32>() {
                    let identity = bind_named_proc_identity(ns_pid)?;
                    return Ok(try_new_procfs_arc(|charge| ProcPidDirInode {
                        fs_id: self.fs_id,
                        identity,
                        _heap_charge: Some(charge),
                    })?);
                }
                Err(FsError::NotFound)
            }
        }
    }
}

impl Inode for ProcRootInode {
    fn ino(&self) -> u64 {
        1
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 1,
            mode: FileMode::directory(0o555),
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        // Directories can only be opened for read-only operations (getdents64)
        if flags.is_writable() {
            return Err(FsError::IsDir);
        }
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, false))
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        // Static entries
        let static_entries = ["self", "meminfo", "cpuinfo", "uptime", "version"];

        if offset < static_entries.len() {
            let name = static_entries[offset];
            let file_type = if name == "self" {
                FileType::Symlink
            } else {
                FileType::Regular
            };
            return Ok(Some((
                offset + 1,
                DirEntry {
                    // R186-8: was annotated BOUNDED and left infallible. Bounded is
                    // not fallible — a small allocation still aborts the kernel on
                    // an exhausted heap.
                    name: crate::types::try_dirent_name(name)?,
                    ino: (offset + 2) as u64,
                    file_type,
                },
            )));
        }

        // R31-1 FIX: List PIDs filtered by access control (self/root/same owner/gid)
        let pids = list_pids()?;
        let pid_offset = offset - static_entries.len();

        if let Some(global_pid) = pids
            .iter()
            .copied()
            .filter(|&pid| can_access_pid(pid))
            .nth(pid_offset)
        {
            // R141-5 FIX: Display namespace-local PID in directory names.
            // Without this, directory entries show global kernel PIDs that
            // don't match getpid() output in PID namespaces, breaking
            // open("/proc/" + getpid() + "/status") inside containers.
            let display_pid = caller_ns_local_pid(global_pid).unwrap_or(global_pid);

            return Ok(Some((
                offset + 1,
                DirEntry {
                    // R186-8: fallible decimal rendering (was infallible format!).
                    name: crate::types::try_dirent_name_from_u64(display_pid as u64)?,
                    // R142-3 FIX: Use namespace-local PID for inode number to
                    // prevent leaking global kernel PIDs via d_ino in getdents64().
                    ino: 1000 + display_pid as u64,
                    file_type: FileType::Directory,
                },
            )));
        }

        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/self Symlink
// ============================================================================

struct ProcSelfSymlink {
    fs_id: u64,
    identity: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

impl ProcSelfSymlink {
    fn pid_dir(&self) -> ProcPidDirInode {
        ProcPidDirInode {
            fs_id: self.fs_id,
            identity: self.identity.clone(),
            _heap_charge: None,
        }
    }

    /// Return the namespace-local PID captured with the stable identity.
    fn display_pid(&self) -> u32 {
        self.identity.display_pid
    }
}

impl Inode for ProcSelfSymlink {
    fn ino(&self) -> u64 {
        2
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        // R141-5 FIX: Use namespace-local PID for symlink target display.
        let target = format!("{}", self.display_pid());
        Ok(Stat {
            dev: self.fs_id,
            ino: 2,
            mode: FileMode::new(FileType::Symlink, 0o777),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: target.len() as u64,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        _flags: OpenFlags,
        _prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        Err(FsError::Invalid)
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // R141-5 FIX: Return namespace-local PID as symlink target.
        let target = format!("{}", self.display_pid());
        let bytes = target.as_bytes();
        let len = buf.len().min(bytes.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }

    fn is_dir(&self) -> bool {
        // M0-6 SLICE 3 FIX: /proc/self is a symlink, not a directory.
        // Now that symlink resolution is implemented, return false and rely
        // on the VFS manager to follow the symlink automatically.
        false
    }

    fn is_symlink(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        // R163-30 FIX: Check PID namespace visibility and access permission,
        // not just existence. A recycled PID might be visible but belong to a
        // different namespace than the caller expected.
        if validate_proc_identity(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        self.pid_dir().readdir(offset)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/ Directory
// ============================================================================

struct ProcPidDirInode {
    fs_id: u64,
    identity: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

impl ProcPidDirInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // R31-1 FIX: Check access permission before returning child entries
        if validate_proc_identity(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        match name {
            "status" => Ok(try_new_procfs_arc(|charge| ProcPidStatusInode {
                fs_id: self.fs_id,
                identity: self.identity.clone(),
                _heap_charge: Some(charge),
            })?),
            "cmdline" => Ok(try_new_procfs_arc(|charge| ProcPidCmdlineInode {
                fs_id: self.fs_id,
                identity: self.identity.clone(),
                _heap_charge: Some(charge),
            })?),
            "stat" => Ok(try_new_procfs_arc(|charge| ProcPidStatInode {
                fs_id: self.fs_id,
                identity: self.identity.clone(),
                _heap_charge: Some(charge),
            })?),
            "maps" => Ok(try_new_procfs_arc(|charge| ProcPidMapsInode {
                fs_id: self.fs_id,
                identity: self.identity.clone(),
                _heap_charge: Some(charge),
            })?),
            "fd" => Ok(try_new_procfs_arc(|charge| ProcPidFdDirInode {
                fs_id: self.fs_id,
                identity: self.identity.clone(),
                _heap_charge: Some(charge),
            })?),
            _ => Err(FsError::NotFound),
        }
    }
}

impl Inode for ProcPidDirInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Use namespace-local PID to prevent leaking global PIDs
        // via fstat()/getdents64() inode numbers on procfs PID directories.
        1000 + self.identity.display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::directory(0o555),
            nlink: 2,
            uid,
            gid,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        // Directories can only be opened for read-only operations (getdents64)
        if flags.is_writable() {
            return Err(FsError::IsDir);
        }
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, false))
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        // R31-1 FIX: Check access permission before listing entries
        if validate_proc_identity(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        let entries = ["status", "cmdline", "stat", "maps", "fd"];

        if offset < entries.len() {
            let name = entries[offset];
            let file_type = if name == "fd" {
                FileType::Directory
            } else {
                FileType::Regular
            };
            return Ok(Some((
                offset + 1,
                DirEntry {
                    // R186-8: bounded is not fallible (see the /proc root readdir).
                    name: crate::types::try_dirent_name(name)?,
                    ino: self.ino() * 10 + offset as u64,
                    file_type,
                },
            )));
        }

        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/status
// ============================================================================

// R178-23 FIX: Bind procfs authorization to process identity (generation).
// Prevents PID-reuse attacks where authorization check at open-time succeeds,
// but reads occur after the original process exits and a new process reuses the PID.
struct ProcPidStatusInode {
    fs_id: u64,
    identity: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcPidStatusInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        10000 + self.identity.display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        if validate_proc_identity(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, true))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // R178-23 FIX: Validate BOTH ownership and generation on every read.
        // Prevents PID-reuse attacks: if the original process exits and a new process
        // reuses the PID, generation mismatch blocks access even if UIDs match.
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let content = generate_status(&self.identity, &process)?;
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/cmdline
// ============================================================================

// R178-23 FIX: Bind procfs authorization to process identity (generation)
struct ProcPidCmdlineInode {
    fs_id: u64,
    identity: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcPidCmdlineInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        20000 + self.identity.display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        if validate_proc_identity(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, true))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // R178-23 FIX: Validate both ownership and generation
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let content = get_process_cmdline(&process)?;
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/stat
// ============================================================================

// R178-23 FIX: Bind procfs authorization to process identity (generation)
struct ProcPidStatInode {
    fs_id: u64,
    identity: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcPidStatInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        30000 + self.identity.display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        if validate_proc_identity(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, true))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // R178-23 FIX: Validate both ownership and generation
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let content = generate_stat(&self.identity, &process)?;
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/maps
// ============================================================================

// R178-23 FIX: Bind procfs authorization to process identity (generation)
struct ProcPidMapsInode {
    fs_id: u64,
    identity: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcPidMapsInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        40000 + self.identity.display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(0o400),
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        if validate_proc_identity(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, true))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // R178-23 FIX: Validate both ownership and generation
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let content = generate_maps(&process)?;
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/fd/ Directory
// ============================================================================

struct ProcPidFdDirInode {
    fs_id: u64,
    identity: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

impl ProcPidFdDirInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // R31-1 FIX: Check access permission before returning fd entries
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let fd: u32 = name.parse().map_err(|_| FsError::NotFound)?;
        let fds = list_process_fds(&process)?;
        if !fds.iter().any(|&n| n == fd) {
            return Err(FsError::NotFound);
        }
        Ok(try_new_procfs_arc(|charge| ProcPidFdSymlink {
            fs_id: self.fs_id,
            identity: self.identity.clone(),
            fd,
            _heap_charge: Some(charge),
        })?)
    }
}

impl Inode for ProcPidFdDirInode {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        50000 + self.identity.display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process);
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::directory(0o500),
            nlink: 2,
            uid,
            gid,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        flags: OpenFlags,
        prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        // Directories can only be opened for read-only operations (getdents64)
        if flags.is_writable() {
            return Err(FsError::IsDir);
        }
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, false))
    }

    fn is_dir(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        // R31-1 FIX: Defense-in-depth access check for fd listing
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let fds = list_process_fds(&process)?;
        if offset < fds.len() {
            let fd = fds[offset];
            return Ok(Some((
                offset + 1,
                DirEntry {
                    // R186-8: fallible decimal rendering (was infallible format!).
                    name: crate::types::try_dirent_name_from_u64(fd as u64)?,
                    ino: self.ino() * 1000 + fd as u64,
                    file_type: FileType::Symlink,
                },
            )));
        }
        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/fd/<n> Symlink
// ============================================================================

struct ProcPidFdSymlink {
    fs_id: u64,
    identity: ProcIdentity,
    fd: u32,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcPidFdSymlink {
    fn ino(&self) -> u64 {
        // R142-3 FIX: Namespace-local PID for inode number
        (50000 + self.identity.display_pid as u64) * 1000 + self.fd as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        // R42-1 FIX: Re-check access permission on each stat call to prevent
        // PID-reuse information leaks. If the original process exits and a new
        // process reuses the PID, we must not expose the new process's FD info.
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process);
        let target = get_fd_target(&process, self.fd)?;
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::new(FileType::Symlink, 0o777),
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: target.len() as u64,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
        })
    }

    fn open(
        self: Arc<Self>,
        _flags: OpenFlags,
        _prepared: PreparedFileHandle,
    ) -> Result<FileDescriptor, FsError> {
        Err(FsError::Invalid)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        // R42-1 FIX: Defense-in-depth access check for each read operation.
        // Handles race conditions where PID is reused between open and read.
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let target = get_fd_target(&process, self.fd)?;
        read_from_content(&target, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/meminfo
// ============================================================================

struct ProcMeminfoInode {
    fs_id: u64,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcMeminfoInode {
    fn ino(&self) -> u64 {
        3
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 3,
            mode: FileMode::regular(0o444),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
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

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_meminfo()?;
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/cpuinfo
// ============================================================================

struct ProcCpuinfoInode {
    fs_id: u64,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcCpuinfoInode {
    fn ino(&self) -> u64 {
        4
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 4,
            mode: FileMode::regular(0o444),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
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

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_cpuinfo()?;
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/uptime
// ============================================================================

struct ProcUptimeInode {
    fs_id: u64,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcUptimeInode {
    fn ino(&self) -> u64 {
        5
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 5,
            mode: FileMode::regular(0o444),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
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

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = generate_uptime()?;
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/version
// ============================================================================

struct ProcVersionInode {
    fs_id: u64,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcVersionInode {
    fn ino(&self) -> u64 {
        6
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 6,
            mode: FileMode::regular(0o444),
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec::now(),
            mtime: TimeSpec::now(),
            ctime: TimeSpec::now(),
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

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = "Zero-OS version 0.1.0 (rustc)\n";
        read_from_content(content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn read_from_content(content: &str, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
    let bytes = content.as_bytes();
    if offset >= bytes.len() as u64 {
        return Ok(0);
    }
    let start = offset as usize;
    let len = buf.len().min(bytes.len() - start);
    buf[..len].copy_from_slice(&bytes[start..start + len]);
    Ok(len)
}

/// Get current process ID
///
/// R29-1 FIX: Now returns the actual current PID from the scheduler
fn get_current_pid() -> u32 {
    process::current_pid().unwrap_or(0) as u32
}

/// R141-5 FIX: Translate a global PID to the namespace-local PID as seen by
/// the current caller. Returns `None` if the caller has no PID namespace
/// (kernel context) or the target is not visible.
///
/// Codex review: Drop PROCESS_TABLE lock before calling PID namespace methods
/// to avoid holding it across their internal Mutex acquisitions.
fn caller_ns_local_pid(global_pid: u32) -> Option<u32> {
    let caller_ns = {
        let table = PROCESS_TABLE.lock();
        process::current_pid()
            .and_then(|pid| table.get(pid))
            .and_then(|slot| slot.as_ref())
            .and_then(|proc_arc| {
                let p = proc_arc.lock();
                kernel_core::owning_namespace(&p.pid_ns_chain)
            })
    }?; // PROCESS_TABLE lock dropped here

    kernel_core::pid_in_namespace(&caller_ns, global_pid as usize).map(|p| p as u32)
}

/// R31-1 FIX: Access control for /proc/[pid] entries.
///
/// Allow access if any of the following conditions are met:
/// - Accessing own process (self)
/// - Caller is host root (host euid 0)
/// - Caller has same owner UID as target process (host-mapped)
///
/// R37-6 FIX: Removed same-GID check. Allowing same-GID access is a security
/// vulnerability that lets group members snoop on each other's process info.
/// Linux /proc only allows same-UID or root access for sensitive data.
fn can_access_pid(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let target = {
        let table = PROCESS_TABLE.lock();
        table
            .get(pid as usize)
            .and_then(|slot| slot.as_ref())
            .cloned()
    };
    target
        .as_ref()
        .map(|target| can_access_process(pid, target))
        .unwrap_or(false)
}

/// RF178-19 FIX: Authorize the exact process object captured by procfs, not
/// whichever process happens to occupy the numeric PID slot during a later
/// credentials lookup.
fn can_access_process(pid: u32, target: &BoundProcess) -> bool {
    let cur_pid = process::current_pid();
    // Self access is always allowed
    if let Some(cp) = cur_pid {
        if cp as u32 == pid {
            return true;
        }
    }
    // R134-1 FIX: Root check must use euid, not uid, matching POSIX semantics.
    // A process with euid==0 (via setuid) should have root-level /proc access.
    // R139-2 FIX: Use host-mapped euid for the root bypass. Namespace root
    // (ns-euid==0) must not get host-wide /proc access — same class as R135-1.
    let cur_host_euid = kernel_core::current_host_euid().unwrap_or(u32::MAX);
    if cur_host_euid == 0 {
        return true;
    }
    // R37-6 FIX: Only same UID can access; same GID is NOT sufficient
    // R140-5 FIX: Use host-mapped UIDs for both caller and target to prevent
    // cross-user-namespace collisions.  Two processes in different user namespaces
    // can have the same numeric UID (e.g., both mapped to 1000) but correspond to
    // completely different host users.
    // Codex review: use Option-based comparison — if either UID is unmapped,
    // deny access rather than risking a false match on OVERFLOW_UID.
    let cur_host_uid = cur_pid.and_then(|cp| get_process_host_uid_opt(cp as u32));
    let target_host_uid = get_bound_process_host_uid_opt(target);
    match (cur_host_uid, target_host_uid) {
        (Some(cur), Some(target)) => cur == target,
        _ => false, // Unmapped UID on either side → deny
    }
}

fn current_viewer_namespace() -> Option<kernel_core::PidNamespaceArc> {
    let table = PROCESS_TABLE.lock();
    process::current_pid()
        .and_then(|pid| table.get(pid))
        .and_then(|slot| slot.as_ref())
        .and_then(|proc| kernel_core::owning_namespace(&proc.lock().pid_ns_chain))
}

fn same_viewer_namespace(identity: &ProcIdentity) -> bool {
    match (current_viewer_namespace(), identity.viewer_ns.as_ref()) {
        (None, None) => true,
        (Some(current), Some(bound)) => Arc::ptr_eq(&current, bound),
        _ => false,
    }
}

/// RF178-19 FIX: Resolve a namespace-local name without the old global-PID
/// fallback, then bind it to the exact process object and viewer namespace.
fn bind_named_proc_identity(ns_pid: u32) -> Result<ProcIdentity, FsError> {
    let viewer_ns = current_viewer_namespace();
    let global_pid = match viewer_ns.as_ref() {
        Some(ns) => kernel_core::resolve_pid_in_namespace(ns, ns_pid as usize)
            .map(|pid| pid as u32)
            .ok_or(FsError::NotFound)?,
        None => ns_pid,
    };
    bind_proc_identity(global_pid, viewer_ns, Some(ns_pid))
}

fn bind_current_proc_identity(global_pid: u32) -> Result<ProcIdentity, FsError> {
    bind_proc_identity(global_pid, current_viewer_namespace(), None)
}

fn bind_proc_identity(
    pid: u32,
    viewer_ns: Option<kernel_core::PidNamespaceArc>,
    expected_display_pid: Option<u32>,
) -> Result<ProcIdentity, FsError> {
    if pid == 0 {
        return Err(FsError::PermDenied);
    }

    let process = {
        let table = PROCESS_TABLE.lock();
        table
            .get(pid as usize)
            .and_then(|slot| slot.as_ref())
            .cloned()
            .ok_or(FsError::NotFound)?
    };
    if !can_access_process(pid, &process) {
        return Err(FsError::PermDenied);
    }
    let (generation, display_pid, state) = {
        let target = process.lock();
        let display_pid = match viewer_ns.as_ref() {
            Some(ns) => target
                .pid_ns_chain
                .iter()
                .find(|membership| Arc::ptr_eq(&membership.ns, ns))
                .and_then(|membership| u32::try_from(membership.pid).ok())
                .ok_or(FsError::NotFound)?,
            None => pid,
        };
        (target.generation, display_pid, target.state)
    };
    if matches!(state, ProcessState::Zombie | ProcessState::Terminated) {
        return Err(FsError::NotFound);
    }
    if expected_display_pid
        .map(|expected| expected != display_pid)
        .unwrap_or(false)
    {
        return Err(FsError::NotFound);
    }
    let identity = ProcIdentity {
        process: Arc::downgrade(&process),
        pid,
        generation,
        display_pid,
        viewer_ns,
    };
    if validate_proc_identity(&identity).is_none() {
        return Err(FsError::NotFound);
    }
    Ok(identity)
}

/// Verify permission, namespace membership, generation, and table-slot
/// identity, returning the same exact process object the caller must snapshot.
fn validate_proc_identity(identity: &ProcIdentity) -> Option<BoundProcess> {
    if !same_viewer_namespace(identity) {
        return None;
    }
    let process = match identity.process.upgrade() {
        Some(process) => process,
        None => return None,
    };
    let attached = {
        let table = PROCESS_TABLE.lock();
        table
            .get(identity.pid as usize)
            .and_then(|slot| slot.as_ref())
            .map(|candidate| Arc::ptr_eq(candidate, &process))
            .unwrap_or(false)
    };
    if !attached {
        return None;
    }
    let namespace_matches = {
        let target = process.lock();
        if target.generation != identity.generation
            || matches!(
                target.state,
                ProcessState::Zombie | ProcessState::Terminated
            )
        {
            return None;
        }
        match identity.viewer_ns.as_ref() {
            Some(ns) => target.pid_ns_chain.iter().any(|membership| {
                Arc::ptr_eq(&membership.ns, ns)
                    && u32::try_from(membership.pid).ok() == Some(identity.display_pid)
            }),
            None => identity.display_pid == identity.pid,
        }
    };
    if !namespace_matches || !can_access_process(identity.pid, &process) {
        return None;
    }
    Some(process)
}

/// List all PIDs
///
/// R29-1 FIX: Now returns actual PIDs from the process table
/// R133-4 FIX: Filter by calling process's PID namespace for container isolation.
/// A process only sees PIDs that are visible from its owning PID namespace.
fn list_pids() -> Result<AdmittedVec<u32>, FsError> {
    let table = PROCESS_TABLE.lock();

    // R133-4 FIX: Determine the caller's owning PID namespace.
    let caller_ns = process::current_pid()
        .and_then(|pid| table.get(pid))
        .and_then(|slot| slot.as_ref())
        .and_then(|proc_arc| {
            let p = proc_arc.lock();
            kernel_core::owning_namespace(&p.pid_ns_chain)
        });

    let live = table.iter().filter(|slot| slot.is_some()).count();
    let mut snapshot = AdmittedVec::new(HeapClass::Procfs);
    snapshot
        .try_reserve_exact(live)
        .map_err(|_| FsError::NoSpace)?;
    for (pid, slot) in table.iter().enumerate().skip(1) {
        let Some(proc_arc) = slot.as_ref() else {
            continue;
        };
        let p = proc_arc.lock();
        if matches!(p.state, ProcessState::Zombie | ProcessState::Terminated) {
            continue;
        }
        if caller_ns
            .as_ref()
            .is_some_and(|ns| !kernel_core::is_visible_in_namespace(ns, &p.pid_ns_chain))
        {
            continue;
        }
        snapshot
            .push_reserved(pid as u32)
            .map_err(|_| FsError::NoSpace)?;
    }
    Ok(snapshot)
}

/// Get process owner (uid, gid)
///
/// R29-1 FIX: Now returns actual process credentials
fn get_process_owner(process: &BoundProcess) -> (u32, u32) {
    let process = process.lock();
    let creds = process.credentials.read();
    (creds.uid, creds.gid)
}

/// R140-5 FIX: Map a process's UID through its user namespace to obtain the host UID.
///
/// Returns `None` if the process doesn't exist or the UID has no mapping in the
/// user namespace.  Callers should treat `None` as "deny" rather than collapsing
/// to a sentinel value (Codex review: prevents false match on OVERFLOW_UID).
///
/// Drops PROCESS_TABLE lock before calling into user_ns to avoid lock ordering issues
/// (same pattern as current_host_euid() in process.rs:1918).
fn get_process_host_uid_opt(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    let table = PROCESS_TABLE.lock();
    let (ns_uid, user_ns) = match table.get(pid as usize) {
        Some(Some(proc)) => {
            let p = proc.lock();
            let ns_uid = p.credentials.read().uid;
            let user_ns = p.user_ns.clone();
            (ns_uid, user_ns)
        }
        _ => return None,
    };

    // Drop PROCESS_TABLE lock before mapping to avoid holding it across
    // user_ns operations (follows established lock ordering pattern).
    drop(table);

    user_ns.map_uid_from_ns(ns_uid)
}

fn get_bound_process_host_uid_opt(process: &BoundProcess) -> Option<u32> {
    let (ns_uid, user_ns) = {
        let process = process.lock();
        let ns_uid = process.credentials.read().uid;
        (ns_uid, process.user_ns.clone())
    };
    user_ns.map_uid_from_ns(ns_uid)
}

/// Get process command line
///
/// R29-1 FIX: Now returns actual process name from PCB
fn get_process_cmdline(process: &BoundProcess) -> Result<AdmittedString, FsError> {
    let process = process.lock();
    let mut output = AdmittedString::new(HeapClass::Procfs);
    output
        .try_reserve(process.name.len().saturating_add(1))
        .map_err(|_| FsError::NoSpace)?;
    output
        .try_push_str(process.name.as_str())
        .map_err(|_| FsError::NoSpace)?;
    output.try_push('\0').map_err(|_| FsError::NoSpace)?;
    Ok(output)
}

fn try_format_content(args: core::fmt::Arguments<'_>) -> Result<AdmittedString, FsError> {
    let mut content = AdmittedString::new(HeapClass::Procfs);
    content.write_fmt(args).map_err(|_| FsError::NoSpace)?;
    Ok(content)
}

/// List file descriptors for a process
///
/// R29-1 FIX: Now returns actual FD list from process
fn list_process_fds(process: &BoundProcess) -> Result<AdmittedVec<u32>, FsError> {
    let process = process.lock();
    let mut snapshot = AdmittedVec::new(HeapClass::Procfs);
    snapshot
        .try_reserve_exact(process.fd_table.len())
        .map_err(|_| FsError::NoSpace)?;
    for fd in process.fd_table.keys().copied() {
        snapshot
            .push_reserved(fd as u32)
            .map_err(|_| FsError::NoSpace)?;
    }
    Ok(snapshot)
}

/// Resolve a file descriptor target for /proc/[pid]/fd/<n>
///
/// R29-1 FIX: Now returns actual FD type from process
fn get_fd_target(process: &BoundProcess, fd: u32) -> Result<AdmittedString, FsError> {
    let process = process.lock();
    match process.fd_table.get(&(fd as i32)) {
        Some(fd_obj) => AdmittedString::try_from_str(HeapClass::Procfs, fd_obj.type_name())
            .map_err(|_| FsError::NoSpace),
        None => Ok(AdmittedString::new(HeapClass::Procfs)),
    }
}

/// Generate /proc/[pid]/status content
///
/// R29-1 FIX: Now uses real process data
fn generate_status(
    identity: &ProcIdentity,
    bound: &BoundProcess,
) -> Result<AdmittedString, FsError> {
    // RF178-19 FIX: Snapshot the bound process Arc, never a raw PID relookup.
    struct StatusSnap {
        name: AdmittedString,
        umask: u16,
        state_char: char,
        state_name: &'static str,
        tgid: usize,
        pid_val: usize,
        ppid: usize,
        uid: u32,
        euid: u32,
        gid: u32,
        egid: u32,
    }

    let snap = {
        let process = bound.lock();
        let (state_char, state_name) = match process.state {
            ProcessState::Zombie => ('Z', "zombie"),
            ProcessState::Terminated => ('X', "dead"),
            ProcessState::Stopped => ('T', "stopped"),
            _ if process.stopped => ('T', "stopped"),
            ProcessState::Ready | ProcessState::Running => ('R', "running"),
            ProcessState::Provisioning | ProcessState::Blocked | ProcessState::Sleeping => {
                ('S', "sleeping")
            }
        };
        let creds = process.credentials.read();
        StatusSnap {
            name: AdmittedString::try_from_str(HeapClass::Procfs, process.name.as_str())
                .map_err(|_| FsError::NoSpace)?,
            umask: process.umask,
            state_char,
            state_name,
            tgid: process.tgid,
            pid_val: process.pid,
            ppid: process.ppid,
            uid: creds.uid,
            euid: creds.euid,
            gid: creds.gid,
            egid: creds.egid,
        }
    };

    {
        let s = snap;
        let (ns_tgid, ns_ppid) = if let Some(ref ns) = identity.viewer_ns {
            (
                if s.tgid == s.pid_val {
                    identity.display_pid as usize
                } else {
                    kernel_core::pid_in_namespace(ns, s.tgid).unwrap_or(0)
                },
                kernel_core::pid_in_namespace(ns, s.ppid).unwrap_or(0),
            )
        } else {
            (s.tgid, s.ppid)
        };

        let mut output = AdmittedString::new(HeapClass::Procfs);
        write!(
            &mut output,
            "Name:\t{}\n\
                 Umask:\t{:04o}\n\
                 State:\t{} ({})\n\
                 Tgid:\t{}\n\
                 Pid:\t{}\n\
                 PPid:\t{}\n\
                 Uid:\t{}\t{}\t{}\t{}\n\
                 Gid:\t{}\t{}\t{}\t{}\n\
                 Threads:\t1\n",
            s.name,
            s.umask,
            s.state_char,
            s.state_name,
            ns_tgid,
            identity.display_pid,
            ns_ppid,
            s.uid,
            s.euid,
            s.uid,
            s.uid,
            s.gid,
            s.egid,
            s.gid,
            s.gid,
        )
        .map_err(|_| FsError::NoSpace)?;
        Ok(output)
    }
}

/// Generate /proc/[pid]/stat content
///
/// R29-1 FIX: Now uses real process data
fn generate_stat(identity: &ProcIdentity, bound: &BoundProcess) -> Result<AdmittedString, FsError> {
    // RF178-19 FIX: Snapshot the exact bound process object.
    let snapshot = {
        let process = bound.lock();
        let state_char = match process.state {
            ProcessState::Zombie => 'Z',
            ProcessState::Terminated => 'X',
            ProcessState::Stopped => 'T',
            _ if process.stopped => 'T',
            ProcessState::Ready | ProcessState::Running => 'R',
            ProcessState::Provisioning | ProcessState::Blocked | ProcessState::Sleeping => 'S',
        };
        (
            process.ppid,
            AdmittedString::try_from_str(HeapClass::Procfs, process.name.as_str())
                .map_err(|_| FsError::NoSpace)?,
            state_char,
            process.priority,
        )
    };

    let (raw_ppid, name, state_char, priority) = snapshot;

    let ns_ppid = if let Some(ref ns) = identity.viewer_ns {
        kernel_core::pid_in_namespace(ns, raw_ppid).unwrap_or(0)
    } else {
        raw_ppid
    };

    let mut output = AdmittedString::new(HeapClass::Procfs);
    write!(
        &mut output,
        "{} ({}) {} {} {} {} 0 -1 0 0 0 0 0 0 0 0 {} 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        identity.display_pid,
        name,
        state_char,
        ns_ppid,
        identity.display_pid,
        identity.display_pid,
        priority,
    )
    .map_err(|_| FsError::NoSpace)?;
    Ok(output)
}

/// R117-2 FIX: Maximum number of mmap entries to emit in /proc/[pid]/maps.
/// Prevents kernel OOM when a process has 100K+ mmap regions.
const MAX_MAPS_ENTRIES: usize = 1000;

/// R117-2 FIX: Maximum byte budget for /proc/[pid]/maps output.
/// 64 KiB is sufficient for ~1000 entries at ~60 bytes each.
const MAX_MAPS_OUTPUT: usize = 64 * 1024;

/// Generate /proc/[pid]/maps content
///
/// Shows the memory mappings for the process in Linux format:
/// address           perms offset  dev   inode   pathname
///
/// R117-2 FIX: Output is bounded by MAX_MAPS_ENTRIES and MAX_MAPS_OUTPUT
/// to prevent kernel OOM from processes with many mmap regions. When the
/// budget is exceeded, a `... (truncated)\n` marker is appended.
fn generate_maps(bound: &BoundProcess) -> Result<AdmittedString, FsError> {
    // R162-I2 FIX: Snapshot mmap_regions and user_stack under locks, then drop
    // all locks before string formatting. This eliminates triple-nested lock
    // hold (Process → MmState) during format! calls.
    let (regions, user_stack) = {
        let proc = bound.lock();
        let mm = proc.mm.lock();
        // D2 Phase 2: mmap_regions values are MmapEntry; snapshot the raw
        // packed word so the downstream formatting (len/flags decode) is
        // unchanged.
        let count = mm.mmap_regions.len().min(MAX_MAPS_ENTRIES);
        let mut regions = AdmittedVec::new(HeapClass::Procfs);
        regions
            .try_reserve_exact(count)
            .map_err(|_| FsError::NoSpace)?;
        for (&start, &entry) in mm.mmap_regions.iter().take(MAX_MAPS_ENTRIES) {
            regions
                .push_reserved((start, entry.raw()))
                .map_err(|_| FsError::NoSpace)?;
        }
        let stack = proc.user_stack.map(|s| s.as_u64());
        (regions, stack)
    };

    let mut result = AdmittedString::new(HeapClass::Procfs);
    result
        .try_reserve(MAX_MAPS_OUTPUT + 128)
        .map_err(|_| FsError::NoSpace)?;
    let mut entries = 0usize;
    let mut truncated = false;

    for &(start, size) in &regions {
        if entries >= MAX_MAPS_ENTRIES || result.len() > MAX_MAPS_OUTPUT {
            truncated = true;
            break;
        }
        let end = start.saturating_add(size & !0xfff);
        let perms = kernel_core::mmap_flags_to_perms(size & 0xfff);
        let perms_str = core::str::from_utf8(&perms).unwrap_or("rw-p");
        let before = result.len();
        write!(
            &mut result,
            "{:016x}-{:016x} {} 00000000 00:00 0    [anon]\n",
            start, end, perms_str
        )
        .map_err(|_| FsError::NoSpace)?;
        if result.len() > MAX_MAPS_OUTPUT {
            result.truncate(before);
            truncated = true;
            break;
        }
        entries += 1;
    }

    if !truncated {
        if let Some(stack_top) = user_stack {
            if entries < MAX_MAPS_ENTRIES {
                let stack_bottom = stack_top.saturating_sub(0x10000);
                let before = result.len();
                write!(
                    &mut result,
                    "{:016x}-{:016x} rw-p 00000000 00:00 0    [stack]\n",
                    stack_bottom, stack_top
                )
                .map_err(|_| FsError::NoSpace)?;
                if result.len() > MAX_MAPS_OUTPUT {
                    result.truncate(before);
                    truncated = true;
                }
            } else {
                truncated = true;
            }
        }
    }

    if result.is_empty() && !truncated {
        result
            .try_push_str("0000000000400000-0000000000401000 r-xp 00000000 00:00 0    [code]\n")
            .map_err(|_| FsError::NoSpace)?;
    }

    if truncated {
        result
            .try_push_str("... (truncated)\n")
            .map_err(|_| FsError::NoSpace)?;
    }

    Ok(result)
}

/// Generate /proc/meminfo content
///
/// Shows real memory statistics from the buddy allocator and page cache.
/// R140-8 FIX: When the calling process is in a non-root cgroup with a
/// configured memory.max, returns cgroup-relative totals instead of
/// host-global physical memory stats.  This prevents namespaced containers
/// from fingerprinting the host or detecting co-residency.
fn generate_meminfo() -> Result<AdmittedString, FsError> {
    // R140-8 FIX: Virtualize for cgroup-limited containers.
    if let Some(cgroup_id) = process::current_cgroup_id() {
        if cgroup_id != 0 {
            if let Some(cgroup) = kernel_core::cgroup::lookup_cgroup(cgroup_id) {
                let limits = cgroup.limits();
                if let Some(memory_max) = limits.memory_max {
                    // Treat u64::MAX as "no limit" (Linux cgroup2 "max" semantics).
                    if memory_max != u64::MAX {
                        let snap = cgroup.get_stats();
                        let memory_current = snap.memory_current;

                        let total_kb = (memory_max / 1024) as usize;
                        let used_kb = (memory_current / 1024) as usize;
                        let free_kb = (memory_max.saturating_sub(memory_current) / 1024) as usize;

                        return try_format_content(format_args!(
                            "MemTotal:       {:8} kB\n\
                             MemFree:        {:8} kB\n\
                             MemAvailable:   {:8} kB\n\
                             Buffers:        {:8} kB\n\
                             Cached:         {:8} kB\n\
                             SwapTotal:      {:8} kB\n\
                             SwapFree:       {:8} kB\n\
                             Active:         {:8} kB\n\
                             Inactive:       {:8} kB\n\
                             Dirty:          {:8} kB\n\
                             KernelHeap:     {:8} kB\n",
                            total_kb,
                            free_kb,
                            free_kb, // MemAvailable ~= MemFree in cgroup view
                            0,       // Buffers: not tracked per-cgroup
                            0,       // Cached: not tracked per-cgroup
                            0,       // SwapTotal
                            0,       // SwapFree
                            used_kb, // Active ~= memory.current
                            0,       // Inactive
                            0,       // Dirty
                            0,       // KernelHeap: host-global, not exposed
                        ));
                    }
                }
            }
        }
    }

    // Root cgroup or no memory limit: show host-global stats (original behavior).
    let mem_stats = FrameAllocator::new().stats();
    let cache_stats = PAGE_CACHE.stats();

    // Convert pages to KB (4KB pages)
    let total_kb = mem_stats.total_physical_pages * 4;
    let free_kb = mem_stats.free_physical_pages * 4;
    let used_kb = mem_stats.used_physical_pages * 4;
    let cached_kb = cache_stats.nr_pages as usize * 4;
    let buffers_kb = cache_stats.nr_dirty as usize * 4;
    let available_kb = free_kb + cached_kb;

    try_format_content(format_args!(
        "MemTotal:       {:8} kB\n\
         MemFree:        {:8} kB\n\
         MemAvailable:   {:8} kB\n\
         Buffers:        {:8} kB\n\
         Cached:         {:8} kB\n\
         SwapTotal:      {:8} kB\n\
         SwapFree:       {:8} kB\n\
         Active:         {:8} kB\n\
         Inactive:       {:8} kB\n\
         Dirty:          {:8} kB\n\
         KernelHeap:     {:8} kB\n",
        total_kb,
        free_kb,
        available_kb,
        buffers_kb,
        cached_kb,
        0,          // SwapTotal - no swap
        0,          // SwapFree - no swap
        used_kb,    // Active = used pages
        cached_kb,  // Inactive = cached pages
        buffers_kb, // Dirty = dirty pages in cache
        mem_stats.heap_used_bytes / 1024,
    ))
}

/// Generate /proc/cpuinfo content
fn generate_cpuinfo() -> Result<AdmittedString, FsError> {
    AdmittedString::try_from_str(
        HeapClass::Procfs,
        "processor\t: 0\n\
         vendor_id\t: Zero-OS\n\
         cpu family\t: 6\n\
         model\t\t: 0\n\
         model name\t: Zero-OS Virtual CPU\n\
         stepping\t: 0\n\
         cpu MHz\t\t: 1000.000\n\
         cache size\t: 0 KB\n\
         flags\t\t: fpu vme de pse tsc msr pae mce cx8\n\
         bogomips\t: 2000.00\n\n",
    )
    .map_err(|_| FsError::NoSpace)
}

/// Generate /proc/uptime content
///
/// Shows system uptime in seconds (timer tick count / 1000 assuming 1kHz timer).
/// Format: uptime_seconds idle_seconds
fn generate_uptime() -> Result<AdmittedString, FsError> {
    let ticks = time::get_ticks();
    // Assuming timer runs at 1000 Hz (1 tick = 1 ms)
    let uptime_secs = ticks / 1000;
    let uptime_frac = (ticks % 1000) / 10; // Two decimal places

    // Idle time is approximated as a portion of uptime (simplified)
    // In a real system, this would track actual CPU idle time
    let idle_secs = uptime_secs / 2; // Rough approximation
    let idle_frac = uptime_frac;

    try_format_content(format_args!(
        "{}.{:02} {}.{:02}\n",
        uptime_secs, uptime_frac, idle_secs, idle_frac
    ))
}
