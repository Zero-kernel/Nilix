//! Process filesystem (procfs)
//!
//! Provides /proc virtual filesystem with process information:
//! - /proc/self - Symlink to current process directory
//! - /proc/thread-self - Symlink to the calling task's `<tgid>/task/<tid>`
//! - /proc/[pid]/ - Per-process directory (listed for thread-group leaders;
//!   any task id resolves)
//! - /proc/[pid]/task/[tid]/ - Per-task directories of pid's thread group
//! - /proc/[pid]/status - Process status
//! - /proc/[pid]/cmdline - Command line
//! - /proc/[pid]/stat - Process statistics
//! - /proc/meminfo - System memory information
//! - /proc/cpuinfo - CPU information
//! - /proc/waitstat - wait4/waitid over-wake counter (GAP-6 W-3)

use crate::traits::{FileSystem, Inode, PreparedFileHandle};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, Stat, TimeSpec};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt::Write;
use core::sync::atomic::Ordering;
use kernel_core::user_namespace;
use kernel_core::FileDescriptor;
// R29-1 FIX: Import process module for real process information
use kernel_core::process::{self, ProcessArc, ProcessState, ProcessWeak, PROCESS_TABLE};
// R36 FIX: Import time module for uptime and mm for memory stats
use kernel_core::time;
use mm::memory::FrameAllocator;
use mm::page_cache::PAGE_CACHE;
use mm::{arc_charge_bytes, try_reserve_heap, AdmittedString, AdmittedVec, HeapCharge, HeapClass};

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
    /// A procfs lookup may be opened by the creator of a newly-created user
    /// namespace even though the target's UID is not mapped yet.  Keep the
    /// creator's generation so a recycled PID can never inherit that map-write
    /// authority.
    id_map_parent: Option<IdMapParentAuth>,
}

type BoundProcess = ProcessArc;

#[derive(Clone, Copy)]
struct IdMapParentAuth {
    pid: u32,
    generation: u64,
}

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
        let fs_id = crate::identity::allocate_fs_id()?;

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

        for name in [
            "meminfo",
            "cpuinfo",
            "uptime",
            "version",
            "waitstat",
            "schedstat",
        ] {
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
    fn directory_parent(
        &self,
        inode: &Arc<dyn Inode>,
    ) -> Result<Option<crate::traits::DirectoryParent>, FsError> {
        if inode.fs_id() != self.fs_id {
            return Err(FsError::CrossDev);
        }
        if inode.ino() == 1 {
            return Ok(None);
        }
        if let Some(directory) = inode.as_any().downcast_ref::<ProcPidDirInode>() {
            if validate_proc_identity_binding(&directory.identity).is_none() {
                return Err(FsError::NotFound);
            }
            return Ok(Some(crate::traits::DirectoryParent {
                inode: self.root.clone(),
                name: crate::types::try_dirent_name_from_u64(
                    directory.identity.display_pid as u64,
                )?,
                attached: true,
            }));
        }
        if let Some(directory) = inode.as_any().downcast_ref::<ProcPidFdDirInode>() {
            if validate_proc_identity_binding(&directory.identity).is_none() {
                return Err(FsError::NotFound);
            }
            let parent = try_new_procfs_arc(|charge| ProcPidDirInode {
                fs_id: self.fs_id,
                identity: directory.identity.clone(),
                _heap_charge: Some(charge),
            })?;
            return Ok(Some(crate::traits::DirectoryParent {
                inode: parent,
                name: crate::types::try_dirent_name("fd")?,
                attached: true,
            }));
        }
        // GAP-5 G8: /proc/[pid]/task → /proc/[pid]
        if let Some(directory) = inode.as_any().downcast_ref::<ProcPidTaskDirInode>() {
            if validate_proc_identity_binding(&directory.identity).is_none() {
                return Err(FsError::NotFound);
            }
            let parent = try_new_procfs_arc(|charge| ProcPidDirInode {
                fs_id: self.fs_id,
                identity: directory.identity.clone(),
                _heap_charge: Some(charge),
            })?;
            return Ok(Some(crate::traits::DirectoryParent {
                inode: parent,
                name: crate::types::try_dirent_name("task")?,
                attached: true,
            }));
        }
        // GAP-5 G8: /proc/[pid]/task/[tid] → /proc/[pid]/task
        if let Some(directory) = inode.as_any().downcast_ref::<ProcTaskTidDirInode>() {
            if validate_proc_identity_binding(&directory.task).is_none()
                || validate_proc_identity_binding(&directory.group).is_none()
            {
                return Err(FsError::NotFound);
            }
            let parent = try_new_procfs_arc(|charge| ProcPidTaskDirInode {
                fs_id: self.fs_id,
                identity: directory.group.clone(),
                _heap_charge: Some(charge),
            })?;
            return Ok(Some(crate::traits::DirectoryParent {
                inode: parent,
                name: crate::types::try_dirent_name_from_u64(directory.task.display_pid as u64)?,
                attached: true,
            }));
        }
        Err(FsError::NotDir)
    }
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

        // GAP-5 G8: /proc/[pid]/task and /proc/[pid]/task/[tid]
        if let Some(task_dir) = parent.as_any().downcast_ref::<ProcPidTaskDirInode>() {
            return task_dir.lookup_child(name);
        }
        if let Some(tid_dir) = parent.as_any().downcast_ref::<ProcTaskTidDirInode>() {
            return task_entry_lookup(self.fs_id, &tid_dir.task, name);
        }

        // Traverse /proc/thread-self/<...> like /proc/self above.
        if let Some(link) = parent.as_any().downcast_ref::<ProcThreadSelfSymlink>() {
            return task_entry_lookup(self.fs_id, &link.identity, name);
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
                // GAP-5 G8: Linux `/proc/self` names the caller's thread group
                // (getpid()), not the calling thread. A leader that cannot be
                // bound (already a zombie, or refused by DAC) falls back to the
                // calling task itself.
                let current = get_current_pid();
                let identity = match current_group_leader_pid() {
                    Some(leader) => bind_current_proc_identity(leader)
                        .or_else(|_| bind_current_proc_identity(current))?,
                    None => bind_current_proc_identity(current)?,
                };
                Ok(try_new_procfs_arc(|charge| ProcSelfSymlink {
                    fs_id: self.fs_id,
                    identity,
                    _heap_charge: Some(charge),
                })?)
            }
            "thread-self" => {
                let identity = bind_current_proc_identity(get_current_pid())?;
                let task = validate_proc_identity_binding(&identity).ok_or(FsError::NotFound)?;
                let group_display = task_group_fields(&identity, &task)?.ns_tgid;
                drop(task);
                let group_display = u32::try_from(group_display)
                    .ok()
                    .filter(|&id| id != 0)
                    .ok_or(FsError::NotFound)?;
                Ok(try_new_procfs_arc(|charge| ProcThreadSelfSymlink {
                    fs_id: self.fs_id,
                    identity,
                    group_display,
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
            "waitstat" => Ok(try_new_procfs_arc(|charge| ProcWaitstatInode {
                fs_id: self.fs_id,
                _heap_charge: Some(charge),
            })?),
            "schedstat" => Ok(try_new_procfs_arc(|charge| ProcSchedstatInode {
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
        // Static entries. `thread-self` is last so the older entries keep
        // their offsets and inode numbers (offset + 2).
        let static_entries = [
            "self",
            "meminfo",
            "cpuinfo",
            "uptime",
            "version",
            "waitstat",
            "schedstat",
            "thread-self",
        ];

        if offset < static_entries.len() {
            let name = static_entries[offset];
            let file_type = if matches!(name, "self" | "thread-self") {
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
        // GAP-5 G8: only thread-group leaders are listed; other task ids stay
        // reachable by lookup and are listed under /proc/<pid>/task.
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
// /proc/thread-self Symlink (GAP-5 G8)
// ============================================================================

/// `/proc/thread-self` → `<tgid>/task/<tid>` for the calling task, both ids
/// in the caller's PID namespace.
struct ProcThreadSelfSymlink {
    fs_id: u64,
    /// The calling task.
    identity: ProcIdentity,
    /// Its thread group's id, captured with `identity` in the same view.
    group_display: u32,
    _heap_charge: Option<HeapCharge>,
}

impl ProcThreadSelfSymlink {
    fn target(&self) -> Result<AdmittedString, FsError> {
        try_format_content(format_args!(
            "{}/task/{}",
            self.group_display, self.identity.display_pid
        ))
    }
}

impl Inode for ProcThreadSelfSymlink {
    fn ino(&self) -> u64 {
        // Offset 7 of the /proc root listing (offset + 2).
        9
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let target = self.target()?;
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
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

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let target = self.target()?;
        read_from_content(&target, offset, buf)
    }

    fn is_dir(&self) -> bool {
        false
    }

    fn is_symlink(&self) -> bool {
        true
    }

    fn readdir(&self, offset: usize) -> Result<Option<(usize, DirEntry)>, FsError> {
        // Same contract as /proc/self: revalidate, then list the task entries.
        if validate_proc_identity(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        pid_dir_readdir(
            task_tid_dir_ino(self.group_display, self.identity.display_pid),
            &TASK_TID_DIR_ENTRIES,
            offset,
        )
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

/// Entries of /proc/[pid]/. `task` is last so the older entries keep their
/// offsets.
const PID_DIR_ENTRIES: [&str; 8] = [
    "status", "cmdline", "stat", "maps", "uid_map", "gid_map", "fd", "task",
];

/// Entries of /proc/[pid]/task/[tid]/: the per-pid entries without `task`,
/// as on Linux.
const TASK_TID_DIR_ENTRIES: [&str; 7] = [
    "status", "cmdline", "stat", "maps", "uid_map", "gid_map", "fd",
];

/// One fixed entry of a per-pid or per-task directory.
fn pid_dir_readdir(
    dir_ino: u64,
    entries: &[&str],
    offset: usize,
) -> Result<Option<(usize, DirEntry)>, FsError> {
    let Some(&name) = entries.get(offset) else {
        return Ok(None);
    };
    let file_type = if matches!(name, "fd" | "task") {
        FileType::Directory
    } else {
        FileType::Regular
    };
    Ok(Some((
        offset + 1,
        DirEntry {
            // R186-8: bounded is not fallible (see the /proc root readdir).
            name: crate::types::try_dirent_name(name)?,
            ino: dir_ino.wrapping_mul(10).wrapping_add(offset as u64),
            file_type,
        },
    )))
}

struct ProcPidDirInode {
    fs_id: u64,
    identity: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

impl ProcPidDirInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        // A newly-created user namespace has no UID mapping yet, so its
        // creator cannot pass the normal host-UID /proc DAC check.  Permit the
        // two map files through the narrowly-scoped map validator; every
        // other child still uses the ordinary process-information check.
        let id_map = matches!(name, "uid_map" | "gid_map");
        if id_map {
            if validate_proc_identity_for_id_map(&self.identity).is_none() {
                return Err(FsError::PermDenied);
            }
        } else if validate_proc_identity(&self.identity).is_none() {
            // R31-1 FIX: Check access permission before returning child entries
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
            "uid_map" => Ok(try_new_procfs_arc(|charge| ProcPidIdMapInode {
                fs_id: self.fs_id,
                identity: self.identity.clone(),
                kind: IdMapKind::Uid,
                _heap_charge: Some(charge),
            })?),
            "gid_map" => Ok(try_new_procfs_arc(|charge| ProcPidIdMapInode {
                fs_id: self.fs_id,
                identity: self.identity.clone(),
                kind: IdMapKind::Gid,
                _heap_charge: Some(charge),
            })?),
            "fd" => Ok(try_new_procfs_arc(|charge| ProcPidFdDirInode {
                fs_id: self.fs_id,
                identity: self.identity.clone(),
                _heap_charge: Some(charge),
            })?),
            "task" => Ok(try_new_procfs_arc(|charge| ProcPidTaskDirInode {
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
        // Path traversal stats every intermediate directory before looking up
        // its final component.  A map-authorized parent therefore needs the
        // narrowly-scoped id-map validator here; readdir/open of the directory
        // itself remain protected by the ordinary validator below.
        let process =
            validate_proc_identity_for_id_map(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process)?;
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
        // A direct creator may need to enumerate the fixed map-file names
        // before opening one.  The map-aware validator exposes only these
        // names; lookup_child still applies ordinary DAC to every sensitive
        // entry other than uid_map/gid_map.
        if validate_proc_identity_for_id_map(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        pid_dir_readdir(self.ino(), &PID_DIR_ENTRIES, offset)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// /proc/[pid]/uid_map and gid_map
// ============================================================================

#[derive(Clone, Copy)]
enum IdMapKind {
    Uid,
    Gid,
}

struct ProcPidIdMapInode {
    fs_id: u64,
    identity: ProcIdentity,
    kind: IdMapKind,
    _heap_charge: Option<HeapCharge>,
}

impl ProcPidIdMapInode {
    fn mappings(&self) -> Result<(BoundProcess, Arc<kernel_core::UserNamespace>), FsError> {
        let process =
            validate_proc_identity_for_id_map(&self.identity).ok_or(FsError::PermDenied)?;
        let ns = process.lock().user_ns.clone();
        Ok((process, ns))
    }

    fn render(&self) -> Result<AdmittedString, FsError> {
        let (_process, ns) = self.mappings()?;
        let mappings = match self.kind {
            IdMapKind::Uid => ns.uid_mappings(),
            IdMapKind::Gid => ns.gid_mappings(),
        };
        let mut out = AdmittedString::new(HeapClass::Procfs);
        if mappings.is_empty() && ns.is_root() {
            // Root is an implicit identity map.  A u32 range cannot be
            // represented as count 2^32, so use the largest ABI value.
            out.try_push_str("0 0 4294967295\n")
                .map_err(|_| FsError::NoSpace)?;
        } else {
            for mapping in mappings {
                write!(
                    &mut out,
                    "{} {} {}\n",
                    mapping.ns_id, mapping.host_id, mapping.count
                )
                .map_err(|_| FsError::NoSpace)?;
            }
        }
        Ok(out)
    }
}

impl Inode for ProcPidIdMapInode {
    fn ino(&self) -> u64 {
        let base = match self.kind {
            // Keep the map files in their own inode-number bands.  40000 and
            // 50000 are already used by /proc/[pid]/maps and /proc/[pid]/fd;
            // reusing either band would make fstat/inode caches conflate
            // distinct procfs objects for the same PID.
            IdMapKind::Uid => 60000,
            IdMapKind::Gid => 70000,
        };
        base + self.identity.display_pid as u64
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let process =
            validate_proc_identity_for_id_map(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process)?;
        // Linux treats uid_map/gid_map as kernel-mediated write interfaces:
        // the direct creator may write even while the target UID is unmapped
        // (and therefore cannot be represented by ordinary inode ownership).
        // Advertise write permission to that already-authorized caller so the
        // generic VFS DAC check does not reject a valid parent; write_at still
        // repeats the authoritative relationship and namespace checks.
        let creator_write = id_map_parent_still_authorized(&self.identity, &process);
        let mode = if creator_write || kernel_core::current_is_host_root() {
            0o666
        } else {
            0o644
        };
        Ok(Stat {
            dev: self.fs_id,
            ino: self.ino(),
            mode: FileMode::regular(mode),
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
        if validate_proc_identity_for_id_map(&self.identity).is_none() {
            return Err(FsError::PermDenied);
        }
        let inode: Arc<dyn Inode> = self;
        Ok(prepared.finalize(inode, flags, true))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let content = self.render()?;
        read_from_content(&content, offset, buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        // Mapping files are single-write interfaces.  Reject append/partial
        // writes so a caller cannot bypass the parser by composing lines over
        // multiple offsets.
        if offset != 0 || data.is_empty() || data.len() > user_namespace::MAX_MAPPING_TEXT_BYTES {
            return Err(FsError::Invalid);
        }
        let (target, ns) = self.mappings()?;
        let (_, _, caller_is_host_root) = current_id_map_writer_snapshot(self.kind)?;
        // Only host root or the target's direct creator may publish a map.
        // The creator check is repeated at write time, including the parent
        // generation and exact parent user namespace, so opening a procfs
        // inode before a PID recycle cannot confer authority afterwards.
        if !caller_is_host_root && !id_map_parent_still_authorized(&self.identity, &target) {
            return Err(FsError::PermDenied);
        }
        let mappings = user_namespace::parse_mapping_text(data).map_err(|error| match error {
            user_namespace::UserNsError::OutOfMemory => FsError::NoSpace,
            user_namespace::UserNsError::PermissionDenied => FsError::PermDenied,
            _ => FsError::Invalid,
        })?;
        let result = match self.kind {
            // The public setters perform the same exact-parent namespace and
            // credential snapshot check internally.  Procfs has already
            // authenticated the direct creator above; using these canonical
            // setters keeps the production write path tied to the API named by
            // the user-namespace contract and closes future bypasses.
            IdMapKind::Uid => ns.set_uid_map(mappings),
            IdMapKind::Gid => ns.set_gid_map(mappings),
        };
        result.map(|_| data.len()).map_err(|error| match error {
            user_namespace::UserNsError::OutOfMemory => FsError::NoSpace,
            user_namespace::UserNsError::PermissionDenied => FsError::PermDenied,
            user_namespace::UserNsError::MappingAlreadySet => FsError::Busy,
            _ => FsError::Invalid,
        })
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
        let (uid, gid) = get_process_owner(&process)?;
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
        let (uid, gid) = get_process_owner(&process)?;
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
        let (uid, gid) = get_process_owner(&process)?;
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
        let (uid, gid) = get_process_owner(&process)?;
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
        let (uid, gid) = get_process_owner(&process)?;
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
        let (uid, gid) = get_process_owner(&process)?;
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
// /proc/[pid]/task/ and /proc/[pid]/task/[tid]/ (GAP-5 G8)
// ============================================================================

/// Inode numbers of the task directories sit at or above 2^48, clear of
/// every older procfs number (below 2^32 for ids under `PID_MAX`), so a task
/// directory never shares an inode number with a pid directory or file.
const TASK_DIR_INO_BASE: u64 = 1 << 48;
const TASK_TID_DIR_INO_BASE: u64 = 2 << 48;

fn task_dir_ino(group_display: u32) -> u64 {
    TASK_DIR_INO_BASE | u64::from(group_display)
}

/// Task ids are below `PID_MAX` (2^15), so 24 bits per id keep the pair
/// unique.
fn task_tid_dir_ino(group_display: u32, tid_display: u32) -> u64 {
    TASK_TID_DIR_INO_BASE | (u64::from(group_display) << 24) | u64::from(tid_display)
}

/// /proc/[pid]/task: one directory per live member of pid's thread group.
struct ProcPidTaskDirInode {
    fs_id: u64,
    /// The task named by [pid]; any member names the same group.
    identity: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

impl ProcPidTaskDirInode {
    fn lookup_child(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let group = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let ns_tid: u32 = name.parse().map_err(|_| FsError::NotFound)?;
        // The binding re-checks DAC and the viewer namespace for the member
        // itself, exactly as a /proc/[tid] lookup does.
        let task = bind_named_proc_identity(ns_tid)?;
        let bound = validate_proc_identity_binding(&task).ok_or(FsError::NotFound)?;
        // Membership is the identity of the shared group object; a tgid
        // number alone could name a recycled group.
        if !same_thread_group(&group, &bound) {
            return Err(FsError::NotFound);
        }
        drop(bound);
        drop(group);
        Ok(try_new_procfs_arc(|charge| ProcTaskTidDirInode {
            fs_id: self.fs_id,
            group: self.identity.clone(),
            task,
            _heap_charge: Some(charge),
        })?)
    }
}

impl Inode for ProcPidTaskDirInode {
    fn ino(&self) -> u64 {
        task_dir_ino(self.identity.display_pid)
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process)?;
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
        let process = validate_proc_identity(&self.identity).ok_or(FsError::PermDenied)?;
        // Snapshot per call, as the /proc root listing does: the cookie is
        // an index into the leader-first member order.
        let mut members = AdmittedVec::new(HeapClass::Procfs);
        scan_thread_group(
            &process,
            self.identity.viewer_ns.as_ref(),
            Some(&mut members),
        )?;
        drop(process);
        order_task_members(members.as_mut_slice());
        let Some(member) = members.get(offset).copied() else {
            return Ok(None);
        };
        Ok(Some((
            offset + 1,
            DirEntry {
                name: crate::types::try_dirent_name_from_u64(member.display_tid as u64)?,
                ino: task_tid_dir_ino(self.identity.display_pid, member.display_tid),
                file_type: FileType::Directory,
            },
        )))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// /proc/[pid]/task/[tid]: the per-pid files, describing thread [tid].
struct ProcTaskTidDirInode {
    fs_id: u64,
    /// The directory this one was found in (its `..`).
    group: ProcIdentity,
    /// The member this directory describes.
    task: ProcIdentity,
    _heap_charge: Option<HeapCharge>,
}

/// Look up one per-task file of `task` through the per-pid implementation;
/// a task directory has no nested `task` directory.
fn task_entry_lookup(
    fs_id: u64,
    task: &ProcIdentity,
    name: &str,
) -> Result<Arc<dyn Inode>, FsError> {
    if !TASK_TID_DIR_ENTRIES.contains(&name) {
        return Err(FsError::NotFound);
    }
    let alias_dir = ProcPidDirInode {
        fs_id,
        identity: task.clone(),
        _heap_charge: None,
    };
    alias_dir.lookup_child(name)
}

impl Inode for ProcTaskTidDirInode {
    fn ino(&self) -> u64 {
        task_tid_dir_ino(self.group.display_pid, self.task.display_pid)
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        // As /proc/[pid]: traversal to uid_map/gid_map stats this directory
        // under the narrowly-scoped map validator.
        let process = validate_proc_identity_for_id_map(&self.task).ok_or(FsError::PermDenied)?;
        let (uid, gid) = get_process_owner(&process)?;
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
        if validate_proc_identity_for_id_map(&self.task).is_none() {
            return Err(FsError::PermDenied);
        }
        pid_dir_readdir(self.ino(), &TASK_TID_DIR_ENTRIES, offset)
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
// /proc/waitstat
// ============================================================================

/// GAP-6 W-3: exposes the wait over-wake counter so the Ring-3 rubric can
/// bound it (a pid-targeted wait must not be woken by sibling exits).
struct ProcWaitstatInode {
    fs_id: u64,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcWaitstatInode {
    fn ino(&self) -> u64 {
        7
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 7,
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
        let content = try_format_content(format_args!(
            "over_wakes {}\n",
            process::wait_over_wake_count()
        ))?;
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
// /proc/schedstat
// ============================================================================

/// GAP-6: per-CPU scheduler counters and the RCU callback backlog, which
/// pressure runs sample so their retained logs carry migration and backlog
/// evidence.
struct ProcSchedstatInode {
    fs_id: u64,
    _heap_charge: Option<HeapCharge>,
}

impl Inode for ProcSchedstatInode {
    fn ino(&self) -> u64 {
        8
    }

    fn fs_id(&self) -> u64 {
        self.fs_id
    }

    fn stat(&self) -> Result<Stat, FsError> {
        Ok(Stat {
            dev: self.fs_id,
            ino: 8,
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
        let content = generate_schedstat()?;
        read_from_content(&content, offset, buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// One line per online CPU (`cpuN switches=S migrations_in=M`), then the RCU
/// callback backlog and the W-3 wait over-wake count. Every value is read
/// lock-free.
fn generate_schedstat() -> Result<AdmittedString, FsError> {
    let mut content = AdmittedString::new(HeapClass::Procfs);
    let online = process::sched_online_cpu_mask();
    content
        .write_fmt(format_args!("cpus_online {}\n", online.count_ones()))
        .map_err(|_| FsError::NoSpace)?;
    let mut remaining = online;
    while remaining != 0 {
        let cpu = remaining.trailing_zeros() as usize;
        remaining &= remaining - 1;
        let (switches, migrations_in) = process::cpu_sched_counters(cpu);
        content
            .write_fmt(format_args!(
                "cpu{} switches={} migrations_in={}\n",
                cpu, switches, migrations_in
            ))
            .map_err(|_| FsError::NoSpace)?;
    }
    content
        .write_fmt(format_args!(
            "rcu_backlog {}\nwait_over_wakes {}\n",
            kernel_core::rcu::callback_backlog(),
            process::wait_over_wake_count()
        ))
        .map_err(|_| FsError::NoSpace)?;
    Ok(content)
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
    let ordinary_access = can_access_process(pid, &process);
    let id_map_parent = id_map_parent_auth_for_target(pid, &process);
    if !ordinary_access && id_map_parent.is_none() {
        return Err(FsError::PermDenied);
    }
    let (generation, display_pid, visible) = {
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
        (target.generation, display_pid, proc_task_visible(&target))
    };
    if !visible {
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
        id_map_parent,
    };
    // Re-check only the stable binding here.  An authorized parent is
    // intentionally not required to pass ordinary /proc DAC while the child
    // namespace has an empty UID map; map-file access revalidates the parent
    // relationship on every operation below.
    if validate_proc_identity_binding(&identity).is_none() {
        return Err(FsError::NotFound);
    }
    Ok(identity)
}

/// Verify namespace membership, generation, and table-slot identity, returning
/// the same exact process object the caller must snapshot.  This deliberately
/// omits DAC; map files need a separate narrowly-scoped parent authorization
/// while a new child namespace's UID is still unmapped.
fn validate_proc_identity_binding(identity: &ProcIdentity) -> Option<BoundProcess> {
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
        if target.generation != identity.generation || !proc_task_visible(&target) {
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
    if !namespace_matches {
        return None;
    }
    Some(process)
}

/// Verify the ordinary /proc DAC policy for a bound identity.
fn validate_proc_identity(identity: &ProcIdentity) -> Option<BoundProcess> {
    let process = validate_proc_identity_binding(identity)?;
    if !can_access_process(identity.pid, &process) {
        return None;
    }
    Some(process)
}

/// Capture the direct creator relationship used to reach a newly-created
/// user-namespace map.  The caller's process generation is retained so a
/// recycled PID cannot inherit the authority.
fn id_map_parent_auth_for_target(pid: u32, target: &BoundProcess) -> Option<IdMapParentAuth> {
    let caller_pid = process::current_pid()? as u32;
    if caller_pid == pid {
        return None;
    }

    let caller = {
        let table = PROCESS_TABLE.lock();
        table
            .get(caller_pid as usize)
            .and_then(|slot| slot.as_ref())
            .cloned()?
    };
    let (caller_generation, caller_user_ns) = {
        let caller_guard = caller.lock();
        (caller_guard.generation, caller_guard.user_ns.clone())
    };
    let (target_ppid, target_parent_user_ns) = {
        let target_guard = target.lock();
        (target_guard.ppid, target_guard.user_ns.parent())
    };

    if target_ppid != caller_pid as usize {
        return None;
    }
    match target_parent_user_ns {
        Some(parent) if Arc::ptr_eq(&parent, &caller_user_ns) => Some(IdMapParentAuth {
            pid: caller_pid,
            generation: caller_generation,
        }),
        _ => None,
    }
}

/// Revalidate the creator relationship at map-write time.  This check is
/// intentionally independent of ordinary /proc DAC because the target UID may
/// still be unmapped.
fn id_map_parent_still_authorized(identity: &ProcIdentity, target: &BoundProcess) -> bool {
    let Some(auth) = identity.id_map_parent else {
        return false;
    };
    let Some(caller_pid) = process::current_pid().map(|pid| pid as u32) else {
        return false;
    };
    if caller_pid != auth.pid {
        return false;
    }

    let caller = {
        let table = PROCESS_TABLE.lock();
        match table
            .get(caller_pid as usize)
            .and_then(|slot| slot.as_ref())
            .cloned()
        {
            Some(caller) => caller,
            None => return false,
        }
    };
    let (caller_generation, caller_user_ns) = {
        let caller_guard = caller.lock();
        (caller_guard.generation, caller_guard.user_ns.clone())
    };
    if caller_generation != auth.generation {
        return false;
    }

    let target_guard = target.lock();
    if target_guard.ppid != caller_pid as usize
        || matches!(
            target_guard.state,
            ProcessState::Zombie | ProcessState::Terminated
        )
    {
        return false;
    }
    match target_guard.user_ns.parent() {
        Some(parent) => Arc::ptr_eq(&parent, &caller_user_ns),
        None => false,
    }
}

/// Validate a map inode for read/stat/open.  Ordinary DAC remains sufficient;
/// the creator exception is admitted only for the two id-map files.
fn validate_proc_identity_for_id_map(identity: &ProcIdentity) -> Option<BoundProcess> {
    let process = validate_proc_identity_binding(identity)?;
    if can_access_process(identity.pid, &process)
        || kernel_core::current_is_host_root()
        || id_map_parent_still_authorized(identity, &process)
    {
        Some(process)
    } else {
        None
    }
}

/// Snapshot the current map writer's namespace and effective ID.  The caller
/// namespace is passed explicitly to UserNamespace so namespace-local UID 0
/// cannot silently become a host-root bypass.
fn current_id_map_writer_snapshot(
    kind: IdMapKind,
) -> Result<(Arc<kernel_core::UserNamespace>, u32, bool), FsError> {
    let pid = process::current_pid().ok_or(FsError::PermDenied)? as u32;
    let caller = {
        let table = PROCESS_TABLE.lock();
        table
            .get(pid as usize)
            .and_then(|slot| slot.as_ref())
            .cloned()
            .ok_or(FsError::PermDenied)?
    };
    let (caller_user_ns, caller_euid, caller_egid) = {
        let caller_guard = caller.lock();
        let creds = caller_guard.try_credentials_read().ok_or(FsError::Busy)?;
        (caller_guard.user_ns.clone(), creds.euid, creds.egid)
    };
    let caller_id = match kind {
        IdMapKind::Uid => caller_euid,
        IdMapKind::Gid => caller_egid,
    };
    // Host-root status is derived from the same namespace/credential snapshot,
    // avoiding a second PID-table lookup that could observe a recycled slot.
    let caller_is_host_root = caller_user_ns.map_uid_from_ns(caller_euid) == Some(0);
    Ok((caller_user_ns, caller_id, caller_is_host_root))
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
        if !proc_task_visible(&p) {
            continue;
        }
        // GAP-5 G8: as on Linux, readdir of /proc lists thread-group leaders
        // only; a non-leader task id stays reachable by lookup.
        if !is_thread_group_leader(p.pid, p.tgid) {
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

// ============================================================================
// GAP-5 G8: thread-group membership for /proc/[pid]/task and Threads:
// ============================================================================

/// GAP-5 G8: whether procfs shows a task. A zombie is hidden, except a group
/// leader whose group still has live threads: as on Linux, its id keeps naming
/// the process (the kernel keeps its PID-namespace identity until then). A
/// task still being created is hidden too, as Linux attaches a new task's ids
/// only when it is complete.
fn proc_task_visible(task: &kernel_core::process::Process) -> bool {
    match task.state {
        ProcessState::Provisioning | ProcessState::Terminated => false,
        ProcessState::Zombie => {
            is_thread_group_leader(task.pid, task.tgid) && task.thread_group.live() > 0
        }
        _ => true,
    }
}

/// A task is listed in /proc when it leads its thread group.
fn is_thread_group_leader(pid: usize, tgid: usize) -> bool {
    pid == tgid
}

/// One live member of a thread group, named for one procfs viewer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TaskMember {
    /// Global (kernel) task id.
    tid: u32,
    /// Task id in the viewer's PID namespace.
    display_tid: u32,
    /// The member leads the group (`tgid == pid`).
    leader: bool,
}

/// Group-wide facts gathered by one `scan_thread_group` pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ThreadGroupFacts {
    /// Members procfs shows (`proc_task_visible`): the live ones, and a
    /// zombie leader while its group has live threads, which Linux still
    /// lists and counts.
    live: usize,
    /// Global pid of the leader's parent while the leader is in the table
    /// (a zombie leader stays there until its group is empty).
    leader_ppid: Option<usize>,
    /// The leader's id in the viewer's namespace while its PID chain is
    /// attached (the chain is detached when the leader exits).
    leader_display: Option<u32>,
}

/// Scan PROCESS_TABLE once for the members of `bound`'s thread group.
///
/// Lock order is PROCESS_TABLE, then one PCB at a time; no PCB lock is held
/// when PROCESS_TABLE is taken. A task is a member iff its `thread_group` is
/// the same `Arc` as `bound`'s (a tgid is a reusable number). The scan covers
/// at most the table length (`PID_MAX`). When `members` is given it receives
/// every live member visible in `viewer_ns`, in table (global id) order. Its
/// capacity is reserved, fallibly and before PROCESS_TABLE is taken, from the
/// group's reference count: every member PCB holds one reference, so the
/// count bounds the member PCBs. A group that grows before the scan only
/// makes the push below grow the vector, still fallibly.
fn scan_thread_group(
    bound: &BoundProcess,
    viewer_ns: Option<&kernel_core::PidNamespaceArc>,
    mut members: Option<&mut AdmittedVec<TaskMember>>,
) -> Result<ThreadGroupFacts, FsError> {
    if let Some(out) = members.as_deref_mut() {
        let references = Arc::strong_count(&bound.lock().thread_group);
        out.try_reserve_exact(references.min(process::PID_MAX))
            .map_err(|_| FsError::NoSpace)?;
    }
    let table = PROCESS_TABLE.lock();
    // Read under PROCESS_TABLE: the CLONE_THREAD commit installs a new
    // member's group while holding it.
    let group = Arc::clone(&bound.lock().thread_group);
    let mut facts = ThreadGroupFacts::default();
    for (pid, slot) in table.iter().enumerate().skip(1) {
        let Some(task) = slot.as_ref() else {
            continue;
        };
        let task = task.lock();
        if !Arc::ptr_eq(&task.thread_group, &group) {
            continue;
        }
        let display = match viewer_ns {
            Some(ns) => task
                .pid_ns_chain
                .iter()
                .find(|membership| Arc::ptr_eq(&membership.ns, ns))
                .and_then(|membership| u32::try_from(membership.pid).ok()),
            None => u32::try_from(pid).ok(),
        };
        let leader = is_thread_group_leader(task.pid, task.tgid);
        if leader {
            facts.leader_ppid = Some(task.ppid);
            facts.leader_display = display;
        }
        if !proc_task_visible(&task) {
            continue;
        }
        facts.live += 1;
        if let (Some(out), Some(display_tid)) = (members.as_deref_mut(), display) {
            let member = TaskMember {
                tid: u32::try_from(pid).map_err(|_| FsError::Invalid)?,
                display_tid,
                leader,
            };
            // Normally within the reservation; any growth stays fallible.
            out.try_push(member).map_err(|_| FsError::NoSpace)?;
        }
    }
    drop(table);
    drop(group);
    Ok(facts)
}

/// Order a task listing as Linux does: the leader first, then the other
/// members in their existing (table) order.
fn order_task_members(members: &mut [TaskMember]) {
    if let Some(leader) = members.iter().position(|member| member.leader) {
        members[..=leader].rotate_right(1);
    }
}

/// Whether two bound tasks share one thread group (`Arc` identity). The two
/// PCB locks are taken one after the other, never nested.
fn same_thread_group(a: &BoundProcess, b: &BoundProcess) -> bool {
    let group = Arc::clone(&a.lock().thread_group);
    let same = Arc::ptr_eq(&b.lock().thread_group, &group);
    drop(group);
    same
}

/// The group-derived identity of one task as its procfs viewer sees it. On
/// Linux a thread's Tgid is its group's id, its PPid is the group leader's
/// parent, and `Threads:` (stat field 20) counts the group's live members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TaskGroupFields {
    /// Thread-group id in the viewer's namespace (0 if it has no name there).
    ns_tgid: usize,
    /// The group's parent in the viewer's namespace (0 if none or hidden).
    ns_ppid: usize,
    /// Live members of the group.
    threads: usize,
}

fn task_group_fields(
    identity: &ProcIdentity,
    bound: &BoundProcess,
) -> Result<TaskGroupFields, FsError> {
    let viewer = identity.viewer_ns.as_ref();
    let (tgid, pid, own_ppid, cached_ns_tgid, owned_by_viewer, alone) = {
        let task = bound.lock();
        let owned_by_viewer = match (viewer, task.pid_ns_chain.last()) {
            (Some(ns), Some(owning)) => Arc::ptr_eq(ns, &owning.ns),
            _ => false,
        };
        (
            task.tgid,
            task.pid,
            task.ppid,
            task.ns_tgid,
            owned_by_viewer,
            // Each member PCB holds one reference to the group, so a count
            // of one proves no other task shares it; every single-threaded
            // process takes this path and skips the table scan.
            Arc::strong_count(&task.thread_group) == 1,
        )
    };
    let leader = is_thread_group_leader(pid, tgid);
    let (threads, group_ppid, leader_display) = if alone {
        (1, own_ppid, None)
    } else {
        let facts = scan_thread_group(bound, viewer, None)?;
        // A thread is outside the process tree (ppid 0); its group's parent
        // is the leader's.
        let group_ppid = if leader {
            own_ppid
        } else {
            facts.leader_ppid.unwrap_or(own_ppid)
        };
        (facts.live, group_ppid, facts.leader_display)
    };
    // PID-namespace lookups run with no PROCESS_TABLE or PCB lock held.
    let ns_tgid = match viewer {
        None => tgid,
        Some(_) if leader => identity.display_pid as usize,
        Some(ns) => leader_display
            .map(|id| id as usize)
            // G5 cache: the group id in the thread's own namespace.
            .or_else(|| (owned_by_viewer && cached_ns_tgid != 0).then_some(cached_ns_tgid))
            .or_else(|| kernel_core::pid_in_namespace(ns, tgid))
            .unwrap_or(0),
    };
    let ns_ppid = match viewer {
        Some(ns) => kernel_core::pid_in_namespace(ns, group_ppid).unwrap_or(0),
        None => group_ppid,
    };
    Ok(TaskGroupFields {
        ns_tgid,
        ns_ppid,
        threads,
    })
}

/// The global pid `/proc/self` should name for a non-leader caller: its
/// group's leader while that is still a live task of the caller's group.
/// `None` for a leader (it names itself) or when no live leader remains.
fn current_group_leader_pid() -> Option<u32> {
    let table = PROCESS_TABLE.lock();
    let current = process::current_pid()?;
    let task = table.get(current)?.as_ref()?;
    let (tgid, pid, group) = {
        let task = task.lock();
        (task.tgid, task.pid, Arc::clone(&task.thread_group))
    };
    if is_thread_group_leader(pid, tgid) {
        return None;
    }
    let leader = table.get(tgid)?.as_ref()?;
    let live_leader = {
        let leader = leader.lock();
        leader.pid == tgid
            && is_thread_group_leader(leader.pid, leader.tgid)
            && Arc::ptr_eq(&leader.thread_group, &group)
            && proc_task_visible(&leader)
    };
    drop(table);
    drop(group);
    if live_leader {
        u32::try_from(tgid).ok()
    } else {
        None
    }
}

/// Get process owner (uid, gid)
///
/// R29-1 FIX: Now returns actual process credentials
fn get_process_owner(process: &BoundProcess) -> Result<(u32, u32), FsError> {
    let process = process.lock();
    let creds = process.try_credentials_read().ok_or(FsError::Busy)?;
    Ok((creds.uid, creds.gid))
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
            let ns_uid = p.try_credentials_read()?.uid;
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
        let ns_uid = process.try_credentials_read()?.uid;
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
    let files = process.files.lock();
    let mut snapshot = AdmittedVec::new(HeapClass::Procfs);
    snapshot
        .try_reserve_exact(files.fd_table.len())
        .map_err(|_| FsError::NoSpace)?;
    for fd in files.fd_table.keys().copied() {
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
    let files = process.files.lock();
    match files.fd_table.get(&(fd as i32)) {
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
        let creds = process.try_credentials_read().ok_or(FsError::Busy)?;
        StatusSnap {
            name: AdmittedString::try_from_str(HeapClass::Procfs, process.name.as_str())
                .map_err(|_| FsError::NoSpace)?,
            umask: process.fs.umask(),
            state_char,
            state_name,
            uid: creds.uid,
            euid: creds.euid,
            gid: creds.gid,
            egid: creds.egid,
        }
    };
    // GAP-5 G8: Tgid, PPid and Threads describe the task's thread group.
    let group = task_group_fields(identity, bound)?;

    {
        let s = snap;
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
                 Threads:\t{}\n",
            s.name,
            s.umask,
            s.state_char,
            s.state_name,
            group.ns_tgid,
            identity.display_pid,
            group.ns_ppid,
            s.uid,
            s.euid,
            s.uid,
            s.uid,
            s.gid,
            s.egid,
            s.gid,
            s.gid,
            group.threads,
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
            AdmittedString::try_from_str(HeapClass::Procfs, process.name.as_str())
                .map_err(|_| FsError::NoSpace)?,
            state_char,
            process.priority,
        )
    };

    let (name, state_char, priority) = snapshot;
    // GAP-5 G8: the parent, process group and num_threads of a thread are
    // its group's.
    let group = task_group_fields(identity, bound)?;

    let mut output = AdmittedString::new(HeapClass::Procfs);
    write_stat_line(
        &mut output,
        &StatLine {
            pid: identity.display_pid as usize,
            comm: name.as_str(),
            state: state_char,
            ppid: group.ns_ppid,
            pgrp: group.ns_tgid,
            session: group.ns_tgid,
            priority,
            num_threads: group.threads,
        },
    )
    .map_err(|_| FsError::NoSpace)?;
    Ok(output)
}

/// The fields of one proc(5) `/proc/[pid]/stat` line this kernel tracks.
struct StatLine<'a> {
    pid: usize,
    comm: &'a str,
    state: char,
    ppid: usize,
    pgrp: usize,
    session: usize,
    priority: u8,
    num_threads: usize,
}

/// Fields 21..=52 of proc(5) (itrealvalue .. exit_code); none is tracked.
const STAT_UNTRACKED_TAIL_FIELDS: usize = 32;

/// Write one 52-field Linux stat line. Untracked fields are 0 (tpgid -1).
/// Fields 1-20: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt
/// cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads.
fn write_stat_line(out: &mut impl Write, line: &StatLine<'_>) -> core::fmt::Result {
    write!(
        out,
        "{} ({}) {} {} {} {} 0 -1 0 0 0 0 0 0 0 0 0 {} 0 {}",
        line.pid,
        line.comm,
        line.state,
        line.ppid,
        line.pgrp,
        line.session,
        line.priority,
        line.num_threads,
    )?;
    for _ in 0..STAT_UNTRACKED_TAIL_FIELDS {
        out.write_str(" 0")?;
    }
    out.write_char('\n')
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

#[cfg(test)]
mod id_map_tests {
    use super::*;
    use crate::HEAP_TEST_LOCK as TEST_LOCK;
    use alloc::string::ToString;
    use kernel_core::process::{Process, ProcessNameSnapshot};

    fn fixture() -> (ProcPidIdMapInode, ProcessArc) {
        let process = Process::try_new_pcb(
            1,
            0,
            ProcessNameSnapshot::from_parts("r188-id-map", ""),
            120,
        )
        .expect("id-map inode process fixture");
        let inode = ProcPidIdMapInode {
            fs_id: 1,
            identity: ProcIdentity {
                process: Arc::downgrade(&process),
                pid: 1,
                generation: 1,
                display_pid: 1,
                viewer_ns: None,
                id_map_parent: None,
            },
            kind: IdMapKind::Uid,
            _heap_charge: None,
        };
        (inode, process)
    }

    #[test]
    fn r188_id_map_write_is_single_bounded_record() {
        let (inode, _process) = fixture();
        assert_eq!(inode.write_at(1, b"0 1000 1\n"), Err(FsError::Invalid));
        assert_eq!(inode.write_at(0, &[]), Err(FsError::Invalid));
        let oversized = alloc::vec![b'0'; user_namespace::MAX_MAPPING_TEXT_BYTES + 1];
        assert_eq!(inode.write_at(0, &oversized), Err(FsError::Invalid));
    }

    #[test]
    fn r188_direct_parent_can_publish_unmapped_child_maps() {
        let _serial = TEST_LOCK.lock();
        let root_user_ns = user_namespace::root_user_namespace();
        let child_user_ns =
            user_namespace::UserNamespace::new_child(root_user_ns.clone()).expect("child ns");

        // Pick a small group of currently-unused table slots so this hosted
        // regression can coexist with a boot fixture that may already have an
        // init task at PID 1.
        let (parent_pid, target_pid, other_pid) = {
            let table = PROCESS_TABLE.lock();
            let mut found = None;
            for parent_pid in 64..(64 + 256) {
                let target_pid = parent_pid + 1;
                let other_pid = parent_pid + 2;
                if table.get(parent_pid).is_none_or(Option::is_none)
                    && table.get(target_pid).is_none_or(Option::is_none)
                    && table.get(other_pid).is_none_or(Option::is_none)
                {
                    found = Some((parent_pid, target_pid, other_pid));
                    break;
                }
            }
            found.expect("free process-table slots for id-map regression")
        };

        let parent = Process::try_new_pcb(
            parent_pid,
            0,
            ProcessNameSnapshot::from_parts("r188-map-parent", ""),
            120,
        )
        .expect("parent pcb");
        let target = Process::try_new_pcb(
            target_pid,
            parent_pid,
            ProcessNameSnapshot::from_parts("r188-map-target", ""),
            120,
        )
        .expect("target pcb");
        let other = Process::try_new_pcb(
            other_pid,
            0,
            ProcessNameSnapshot::from_parts("r188-map-other", ""),
            120,
        )
        .expect("other pcb");

        {
            let mut parent_guard = parent.lock();
            parent_guard.state = ProcessState::Ready;
            parent_guard.user_ns = root_user_ns.clone();
            parent_guard.user_ns_for_children = root_user_ns.clone();
        }
        {
            let mut target_guard = target.lock();
            target_guard.state = ProcessState::Ready;
            target_guard.user_ns = child_user_ns.clone();
            target_guard.user_ns_for_children = child_user_ns.clone();
        }
        {
            let mut other_guard = other.lock();
            other_guard.state = ProcessState::Ready;
            other_guard.user_ns = root_user_ns.clone();
            other_guard.user_ns_for_children = root_user_ns.clone();
        }

        {
            let mut table = PROCESS_TABLE.lock();
            let needed = other_pid + 1;
            if table.len() < needed {
                let missing = needed - table.len();
                table
                    .try_reserve_exact(missing)
                    .expect("process-table test capacity");
                while table.len() < needed {
                    table
                        .push_reserved(None)
                        .expect("reserved process-table test slot");
                }
            }
            assert!(table[parent_pid].is_none());
            assert!(table[target_pid].is_none());
            assert!(table[other_pid].is_none());
            table[parent_pid] = Some(parent.clone());
            table[target_pid] = Some(target.clone());
            table[other_pid] = Some(other.clone());
        }

        process::set_current_pid(Some(parent_pid));
        let fs = ProcFs::try_new().expect("procfs fixture");
        let proc_root = fs.root_inode();
        let target_dir = fs
            .lookup(&proc_root, &target_pid.to_string())
            .expect("parent can bind child proc directory for map access");
        let uid_map = fs
            .lookup(&target_dir, "uid_map")
            .expect("uid_map lookup for direct parent");
        let gid_map = fs
            .lookup(&target_dir, "gid_map")
            .expect("gid_map lookup for direct parent");

        let uid_text = b"0 65534 1\n";
        assert_eq!(uid_map.write_at(0, uid_text), Ok(uid_text.len()));
        assert_eq!(uid_map.write_at(0, uid_text), Err(FsError::Busy));
        let mut rendered = [0u8; 32];
        let rendered_len = uid_map
            .read_at(0, &mut rendered)
            .expect("read published uid map");
        assert_eq!(&rendered[..rendered_len], uid_text);

        let gid_text = b"0 65534 1\n";
        assert_eq!(gid_map.write_at(0, gid_text), Ok(gid_text.len()));

        // A same-UID process is allowed to inspect an already-mapped file, but
        // it is not the target's creator and must not gain write authority.
        process::set_current_pid(Some(other_pid));
        assert_eq!(uid_map.write_at(0, uid_text), Err(FsError::PermDenied));

        process::set_current_pid(None);
        drop(uid_map);
        drop(gid_map);
        drop(target_dir);
        drop(proc_root);
        drop(fs);

        // Remove the exact Arc identities before dropping the local strong refs;
        // no PID slot is left pointing at a test process.
        let detached = {
            let mut table = PROCESS_TABLE.lock();
            (
                table[parent_pid].take(),
                table[target_pid].take(),
                table[other_pid].take(),
            )
        };
        drop(detached);
        drop(parent);
        drop(target);
        drop(other);
        drop(child_user_ns);
    }
}

#[cfg(test)]
mod thread_listing_tests {
    use super::*;
    use crate::HEAP_TEST_LOCK as TEST_LOCK;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use kernel_core::process::{Process, ProcessNameSnapshot};

    fn member(tid: u32, leader: bool) -> TaskMember {
        TaskMember {
            tid,
            display_tid: tid,
            leader,
        }
    }

    #[test]
    fn gap5_g8_task_listing_puts_the_leader_first() {
        let mut members = [member(3, false), member(5, true), member(7, false)];
        order_task_members(&mut members);
        let expected = [member(5, true), member(3, false), member(7, false)];
        assert_eq!(members, expected);
        // A leader already first, or no live leader: table order is kept.
        order_task_members(&mut members);
        assert_eq!(members, expected);
        let mut orphans = [member(3, false), member(7, false)];
        order_task_members(&mut orphans);
        assert_eq!(orphans, [member(3, false), member(7, false)]);
        // Only a leader is listed in the /proc root.
        assert!(is_thread_group_leader(5, 5));
        assert!(!is_thread_group_leader(6, 5));
        // Task-directory inode numbers never alias each other.
        assert_ne!(task_tid_dir_ino(5, 6), task_tid_dir_ino(6, 5));
        assert_ne!(task_dir_ino(5), task_tid_dir_ino(5, 5));
    }

    #[test]
    fn gap5_g8_stat_line_reports_num_threads_as_field_20() {
        let mut line = String::new();
        write_stat_line(
            &mut line,
            &StatLine {
                pid: 6,
                comm: "worker",
                state: 'S',
                ppid: 1,
                pgrp: 5,
                session: 5,
                priority: 120,
                num_threads: 3,
            },
        )
        .expect("stat line");
        assert!(line.ends_with('\n'));
        let fields: Vec<&str> = line.trim_end().split(' ').collect();
        assert_eq!(fields.len(), 52, "proc(5) stat has 52 fields");
        assert_eq!(fields[0], "6");
        assert_eq!(fields[1], "(worker)");
        assert_eq!(fields[2], "S");
        assert_eq!(fields[3], "1", "field 4: ppid");
        assert_eq!(fields[4], "5", "field 5: pgrp");
        assert_eq!(fields[5], "5", "field 6: session");
        assert_eq!(fields[7], "-1", "field 8: tpgid");
        assert_eq!(fields[17], "120", "field 18: priority");
        assert_eq!(fields[18], "0", "field 19: nice");
        assert_eq!(fields[19], "3", "field 20: num_threads");
    }

    // lint-fallible-fn: INFALLIBLE-OK(hosted test helper; at most 512 bytes)
    fn read_all(inode: &Arc<dyn Inode>) -> String {
        let mut buf = [0u8; 512];
        let len = inode.read_at(0, &mut buf).expect("procfs read");
        String::from(core::str::from_utf8(&buf[..len]).expect("procfs text"))
    }

    // lint-fallible-fn: INFALLIBLE-OK(hosted test helper over a small fixture table)
    fn names(dir: &Arc<dyn Inode>) -> Vec<String> {
        let mut out = Vec::new();
        let mut offset = 0;
        while let Some((next, entry)) = dir.readdir(offset).expect("procfs readdir") {
            assert!(next > offset, "readdir cookies advance");
            out.push(entry.name);
            offset = next;
        }
        out
    }

    #[test]
    fn gap5_g8_root_lists_leaders_and_task_dir_lists_members() {
        let _serial = TEST_LOCK.lock();
        let root_user_ns = user_namespace::root_user_namespace();

        // Four free consecutive slots: a leader, two threads of its group, and
        // an unrelated task whose numeric tgid names the leader.
        let base = {
            let table = PROCESS_TABLE.lock();
            (64..(64 + 256))
                .find(|&base| {
                    (base..base + 4).all(|pid| table.get(pid).is_none_or(Option::is_none))
                })
                .expect("free process-table slots for the thread-listing fixture")
        };
        let (leader_pid, thread_pid, second_pid, impostor_pid) =
            (base, base + 1, base + 2, base + 3);
        let pcb = |pid: usize, ppid: usize, name: &str| {
            let process =
                Process::try_new_pcb(pid, ppid, ProcessNameSnapshot::from_parts(name, ""), 120)
                    .expect("thread-listing fixture pcb");
            {
                let mut guard = process.lock();
                guard.state = ProcessState::Ready;
                guard.user_ns = root_user_ns.clone();
                guard.user_ns_for_children = root_user_ns.clone();
            }
            process
        };
        let leader = pcb(leader_pid, 1, "g8-leader");
        let thread = pcb(thread_pid, 0, "g8-thread");
        let second = pcb(second_pid, 0, "g8-second");
        let impostor = pcb(impostor_pid, 1, "g8-impostor");
        let group = Arc::clone(&leader.lock().thread_group);
        for member in [&thread, &second] {
            let mut guard = member.lock();
            guard.tgid = leader_pid;
            guard.is_thread = true;
            guard.thread_group = Arc::clone(&group);
        }
        // Same tgid number, different group object: never a member.
        impostor.lock().tgid = leader_pid;

        {
            let mut table = PROCESS_TABLE.lock();
            let needed = impostor_pid + 1;
            if table.len() < needed {
                let missing = needed - table.len();
                table
                    .try_reserve_exact(missing)
                    .expect("process-table test capacity");
                while table.len() < needed {
                    table
                        .push_reserved(None)
                        .expect("reserved process-table test slot");
                }
            }
            for (pid, process) in [
                (leader_pid, &leader),
                (thread_pid, &thread),
                (second_pid, &second),
                (impostor_pid, &impostor),
            ] {
                assert!(table[pid].is_none());
                table[pid] = Some(process.clone());
            }
        }

        process::set_current_pid(Some(leader_pid));
        let fs = ProcFs::try_new().expect("procfs fixture");
        let root = fs.root_inode();

        // The root lists the leader, not its threads; a thread id resolves.
        let listed = names(&root);
        assert!(listed.contains(&leader_pid.to_string()));
        assert!(!listed.contains(&thread_pid.to_string()));
        assert!(!listed.contains(&second_pid.to_string()));
        assert!(listed.iter().any(|name| name == "thread-self"));
        let thread_dir = fs
            .lookup(&root, &thread_pid.to_string())
            .expect("a non-leader task id stays reachable by lookup");

        // /proc/<pid>/task lists every live member, leader first; any
        // member's directory names the same group.
        let leader_dir = fs
            .lookup(&root, &leader_pid.to_string())
            .expect("leader directory");
        assert!(names(&leader_dir).iter().any(|name| name == "task"));
        let task_dir = fs.lookup(&leader_dir, "task").expect("task directory");
        let all = [
            leader_pid.to_string(),
            thread_pid.to_string(),
            second_pid.to_string(),
        ];
        assert_eq!(names(&task_dir), all);
        let via_thread = fs.lookup(&thread_dir, "task").expect("thread's task dir");
        assert_eq!(names(&via_thread), all);
        assert!(matches!(
            fs.lookup(&task_dir, &impostor_pid.to_string()),
            Err(FsError::NotFound)
        ));

        // /proc/<pid>/task/<tid> describes the thread with group fields.
        let tid_dir = fs
            .lookup(&task_dir, &thread_pid.to_string())
            .expect("per-task directory");
        assert!(!names(&tid_dir).iter().any(|name| name == "task"));
        assert!(matches!(
            fs.lookup(&tid_dir, "task"),
            Err(FsError::NotFound)
        ));
        let status = read_all(&fs.lookup(&tid_dir, "status").expect("task status"));
        assert!(
            status.contains(&format!("Tgid:\t{leader_pid}\n")),
            "{status}"
        );
        assert!(
            status.contains(&format!("Pid:\t{thread_pid}\n")),
            "{status}"
        );
        assert!(status.contains("PPid:\t1\n"), "{status}");
        assert!(status.contains("Threads:\t3\n"), "{status}");
        let stat = read_all(&fs.lookup(&tid_dir, "stat").expect("task stat"));
        let fields: Vec<&str> = stat.trim_end().split(' ').collect();
        assert_eq!(fields[0], thread_pid.to_string());
        assert_eq!(fields[3], "1");
        assert_eq!(fields[4], leader_pid.to_string());
        assert_eq!(fields[19], "3");
        let leader_status = read_all(&fs.lookup(&leader_dir, "status").expect("status"));
        assert!(leader_status.contains("Threads:\t3\n"), "{leader_status}");

        // `..` walks back up the new directories.
        let up = fs
            .directory_parent(&tid_dir)
            .expect("task entry parent")
            .expect("attached");
        assert_eq!(up.name, thread_pid.to_string());
        assert_eq!(up.inode.ino(), task_dir.ino());
        let up = fs
            .directory_parent(&task_dir)
            .expect("task dir parent")
            .expect("attached");
        assert_eq!(up.name, "task");
        assert_eq!(up.inode.ino(), leader_dir.ino());

        // From the thread, /proc/self names the group and thread-self the task.
        process::set_current_pid(Some(thread_pid));
        let self_link = fs.lookup(&root, "self").expect("self");
        assert_eq!(read_all(&self_link), leader_pid.to_string());
        let thread_self = fs.lookup(&root, "thread-self").expect("thread-self");
        assert_eq!(
            read_all(&thread_self),
            format!("{leader_pid}/task/{thread_pid}")
        );

        // A zombie member leaves the listing and the count.
        process::set_current_pid(Some(leader_pid));
        second.lock().state = ProcessState::Zombie;
        assert_eq!(
            names(&task_dir),
            [leader_pid.to_string(), thread_pid.to_string()]
        );
        let leader_status = read_all(&fs.lookup(&leader_dir, "status").expect("status"));
        assert!(leader_status.contains("Threads:\t2\n"), "{leader_status}");

        // A member still being created is neither listed nor reachable.
        second.lock().state = ProcessState::Provisioning;
        assert_eq!(
            names(&task_dir),
            [leader_pid.to_string(), thread_pid.to_string()]
        );
        assert!(matches!(
            fs.lookup(&task_dir, &second_pid.to_string()),
            Err(FsError::NotFound)
        ));

        // A zombie leader whose thread lives on stays listed and counted, as
        // on Linux.
        leader.lock().state = ProcessState::Zombie;
        assert_eq!(
            names(&task_dir),
            [leader_pid.to_string(), thread_pid.to_string()]
        );
        let thread_status = read_all(&fs.lookup(&thread_dir, "status").expect("status"));
        assert!(thread_status.contains("Threads:\t2\n"), "{thread_status}");
        leader.lock().state = ProcessState::Ready;

        process::set_current_pid(None);
        drop((self_link, thread_self, up, tid_dir, via_thread, task_dir));
        drop((leader_dir, thread_dir, root, fs));
        let detached = {
            let mut table = PROCESS_TABLE.lock();
            [leader_pid, thread_pid, second_pid, impostor_pid].map(|pid| table[pid].take())
        };
        drop(detached);
        drop(group);
        drop((leader, thread, second, impostor));
    }
}
