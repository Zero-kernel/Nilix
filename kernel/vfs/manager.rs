//! VFS Manager
//!
//! Provides the central VFS operations including:
//! - Mount table management
//! - Path resolution
//! - Global file operations (open, stat, etc.)
//! - Syscall callback registration
//! - DAC (Discretionary Access Control) permission enforcement
//! - LSM (Linux Security Module) hook integration (R25-9 fix)

use crate::cgroupfs::CgroupFs;
use crate::devfs::DevFs;
use crate::procfs::ProcFs;
use crate::ramfs::RamFs;
use crate::traits::{FileHandle, FileSystem, Inode, PreparedFileHandle};
use crate::types::{DirEntry, FileMode, FileType, FsError, OpenFlags, ResolveFlags, Stat};
use alloc::collections::TryReserveError;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use block::BlockDevice;
use cap::NamespaceId;
use kernel_core::{FileDescriptor, MountNamespace, SyscallError, VfsStat, ROOT_MNT_NAMESPACE};
use mm::fallible_map::FallibleOrderedMap;
use spin::RwLock;

// R25-9 FIX: Import LSM hooks for MAC enforcement
use lsm::{FileCtx as LsmFileCtx, OpenFlags as LsmOpenFlags, ProcessCtx as LsmProcessCtx};

#[cfg(feature = "open_fault_probe")]
#[path = "open_fault_probe.rs"]
mod open_fault_probe;

/// Cryptographic path identifier for LSM contexts.  Policy decisions must not
/// be keyed by a forgeable FNV hash: an attacker who can choose a colliding
/// path could otherwise alias another policy entry.  The first eight bytes of
/// the canonical SHA-256 digest retain the existing u64 ABI while removing the
/// practical collision attack.
#[inline]
fn hash_path(path: &str) -> u64 {
    let digest = kernel_crypto::sha256::Sha256::digest(path.as_bytes());
    u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    )
}

// ============================================================================
// P2-C: fallible string / buffer helpers (D2-ERR-RECOVERY residual)
// ============================================================================
//
// Symlink resolution and readlink must not allocate infallibly after the
// lookup has begun (recoverable API → ENOMEM, not kernel OOM panic). These
// helpers mirror the try_clone_from key-copy pattern (manager.rs:239-241).

/// Fallibly allocate and zero a byte buffer of length `len` (at least 1).
fn try_zeroed_buf(len: usize) -> Result<Vec<u8>, FsError> {
    let n = len.max(1);
    let mut buf = Vec::new();
    buf.try_reserve_exact(n).map_err(|_| FsError::NoMem)?;
    buf.resize(n, 0u8);
    Ok(buf)
}

/// Fallibly copy UTF-8 bytes into an owned `String`.
fn try_string_from_utf8_slice(bytes: &[u8]) -> Result<String, FsError> {
    let s = core::str::from_utf8(bytes).map_err(|_| FsError::Invalid)?;
    try_string_from_str(s)
}

/// Fallibly clone a `&str` into an owned `String`.
fn try_string_from_str(s: &str) -> Result<String, FsError> {
    let mut out = String::new();
    out.try_reserve(s.len()).map_err(|_| FsError::NoMem)?;
    out.push_str(s);
    Ok(out)
}

/// Fallibly join path segments with a single leading `/` and `/` separators.
/// Empty `parts` yields `"/"`.
fn try_join_path_components(parts: &[&str]) -> Result<String, FsError> {
    try_join_path_iter(parts.iter().copied())
}

/// Allocation-fallible path joining directly from a cloneable component
/// iterator. This avoids first materializing attacker-controlled components in
/// an infallibly growing `Vec<&str>`.
fn try_join_path_iter<'a, I>(parts: I) -> Result<String, FsError>
where
    I: Iterator<Item = &'a str> + Clone,
{
    let mut need = 1usize; // leading '/'
    let mut count = 0usize;
    for p in parts.clone() {
        if count > 0 {
            need = need.checked_add(1).ok_or(FsError::NoMem)?;
        }
        need = need.checked_add(p.len()).ok_or(FsError::NoMem)?;
        count = count.checked_add(1).ok_or(FsError::NoMem)?;
    }
    let mut out = String::new();
    out.try_reserve(need).map_err(|_| FsError::NoMem)?;
    out.push('/');
    for (i, p) in parts.enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(p);
    }
    Ok(out)
}

/// Fallibly concatenate `a` + `b` with capacity pre-reserve.
fn try_concat_strs(a: &str, b: &str) -> Result<String, FsError> {
    let need = a.len().checked_add(b.len()).ok_or(FsError::NoMem)?;
    let mut out = String::new();
    out.try_reserve(need).map_err(|_| FsError::NoMem)?;
    out.push_str(a);
    out.push_str(b);
    Ok(out)
}

/// Fallibly build `prefix + '/' + rest` when prefix does not already end with `/`.
fn try_join_two(prefix: &str, rest: &str) -> Result<String, FsError> {
    if rest.is_empty() {
        return try_string_from_str(prefix);
    }
    if prefix.is_empty() || prefix == "/" {
        if rest.starts_with('/') {
            return try_string_from_str(rest);
        }
        return try_concat_strs("/", rest);
    }
    if prefix.ends_with('/') {
        return try_concat_strs(prefix, rest.trim_start_matches('/'));
    }
    let rest = rest.trim_start_matches('/');
    let need = prefix
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(rest.len()))
        .ok_or(FsError::NoMem)?;
    let mut out = String::new();
    out.try_reserve(need).map_err(|_| FsError::NoMem)?;
    out.push_str(prefix);
    out.push('/');
    out.push_str(rest);
    Ok(out)
}

/// Pure host-ID DAC decision. OperationContext supplies one stable, explicit
/// credential snapshot; missing credentials never select a root fallback.
pub(crate) fn permission_bits_allow(
    euid: u32,
    egid: u32,
    supplementary: &[u32],
    stat: &Stat,
    need_read: bool,
    need_write: bool,
    need_exec: bool,
) -> bool {
    // Host root (host-mapped euid == 0) bypasses all permission checks.
    if euid == 0 {
        return true;
    }

    let perm = stat.mode.perm;

    // Determine which permission bits to check based on uid/gid (supplementary groups too).
    let check_bits = if euid == stat.uid {
        (perm >> 6) & 0o7 // Owner: high bits (0o700)
    } else if egid == stat.gid || supplementary.iter().any(|&g| g == stat.gid) {
        (perm >> 3) & 0o7 // Group (primary or supplementary): middle bits (0o070)
    } else {
        perm & 0o7 // Others: low bits (0o007)
    };

    if need_read && (check_bits & 0o4) == 0 {
        return false;
    }
    if need_write && (check_bits & 0o2) == 0 {
        return false;
    }
    if need_exec && (check_bits & 0o1) == 0 {
        return false;
    }

    true
}

/// Global VFS registry; namespace identities own tables through their destruction hook.
pub struct Vfs {
    mount_tables: RwLock<mm::AdmittedMap<NamespaceId, Arc<crate::path::NamespaceMountTable>>>,
    devfs: RwLock<Option<Arc<DevFs>>>,
    retirement: RwLock<Option<Arc<crate::topology::Retirement<crate::path::Mount>>>>,
}

#[path = "operations.rs"]
mod operations;

#[cfg(feature = "namespace_probe")]
#[path = "resource_probe.rs"]
mod resource_probe;
#[cfg(feature = "namespace_probe")]
pub use resource_probe::run as run_resource_probe;

/// Global VFS instance
lazy_static::lazy_static! {
    pub static ref VFS: Vfs = Vfs::new();
}

/// Initialize the global VFS
pub fn init() {
    VFS.init();
    register_syscall_callbacks();
}

// ============================================================================
// Path utilities
// ============================================================================

/// Normalize a path (remove . and .., ensure leading /)
///
/// # Security (R32-VFS-1 fix)
///
/// Rejects paths that attempt to traverse above the root directory.
/// Paths like "/../../etc/passwd" will return PermDenied to prevent
/// sandbox/mount jail escapes.
///
/// P2-C: allocation-fallible (try_reserve on the component list and result
/// string). Recoverable callers map `NoMem` → ENOMEM instead of kernel OOM.
pub fn normalize_path(path: &str) -> Result<String, FsError> {
    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => {} // Skip empty and current dir
            ".." => {
                // R32-VFS-1 FIX: Reject attempts to traverse above root
                if components.pop().is_none() {
                    return Err(FsError::PermDenied);
                }
            }
            _ => {
                components.try_reserve(1).map_err(|_| FsError::NoMem)?;
                components.push(component);
            }
        }
    }

    if components.is_empty() {
        try_string_from_str("/")
    } else {
        try_join_path_components(&components)
    }
}

/// Split path into parent directory and filename
///
/// P2-C: parent ownership is fallible (`try_string_from_str`).
pub fn split_path(path: &str) -> Result<(String, &str), FsError> {
    let path = path.trim_end_matches('/');

    if path.is_empty() || path == "/" {
        return Err(FsError::Invalid);
    }

    match path.rfind('/') {
        Some(pos) => {
            let parent = if pos == 0 { "/" } else { &path[..pos] };
            let filename = &path[pos + 1..];
            if filename.is_empty() {
                Err(FsError::Invalid)
            } else {
                Ok((try_string_from_str(parent)?, filename))
            }
        }
        None => Ok((try_string_from_str("/")?, path)),
    }
}

// ============================================================================
// Convenience functions
// ============================================================================

/// Open a file by path (global convenience function)
///
/// # Arguments
/// * `path` - Path to the file
/// * `flags` - Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
/// * `mode` - Permission mode for file creation (only used with O_CREAT)
pub fn open(path: &str, flags: OpenFlags, mode: u16) -> Result<FileDescriptor, FsError> {
    VFS.open(path, flags, mode)
}

/// Get file status by path
pub fn stat(path: &str) -> Result<Stat, FsError> {
    VFS.stat(path)
}

/// Read directory entries
pub fn readdir(path: &str) -> Result<Vec<DirEntry>, FsError> {
    VFS.readdir(path)
}

/// Mount a filesystem
pub fn mount(path: &str, fs: Arc<dyn FileSystem>) -> Result<(), FsError> {
    VFS.mount(path, fs)
}

/// Unmount a filesystem
pub fn umount(path: &str) -> Result<(), FsError> {
    VFS.umount(path)
}

/// Register a block device in devfs
///
/// Creates a device node at /dev/{name} for the given block device.
/// This is the main entry point for drivers to register block devices.
///
/// # Arguments
/// * `name` - Device name (e.g., "vda" for first virtio-blk device)
/// * `device` - Block device implementation
///
/// # Example
/// ```ignore
/// let virtio_dev = VirtioBlkDevice::probe(mmio_addr, virt_offset, "vda")?;
/// vfs::register_block_device("vda", Arc::new(virtio_dev))?;
/// ```
pub fn register_block_device(name: &str, device: Arc<dyn BlockDevice>) -> Result<(), FsError> {
    VFS.register_block_device(name, device)
}

// ============================================================================
// Syscall callbacks
// ============================================================================

/// Convert VFS FsError to kernel SyscallError
fn fs_error_to_syscall(e: FsError) -> SyscallError {
    match e {
        FsError::NotFound => SyscallError::ENOENT,
        FsError::PermDenied => SyscallError::EACCES,
        FsError::NotPermitted => SyscallError::EPERM,
        FsError::Exists => SyscallError::EEXIST,
        FsError::NotDir => SyscallError::ENOTDIR,
        FsError::IsDir => SyscallError::EISDIR,
        // M0-6 slice 2: errno fidelity (mirror types.rs From<FsError> + to_errno) —
        // NotEmpty=>ENOTEMPTY, ReadOnly=>EROFS, NameTooLong=>ENAMETOOLONG. cgroup-rmdir's
        // EBUSY is preserved by its producer mapping CgroupError::NotEmpty=>FsError::Busy.
        FsError::NotEmpty => SyscallError::ENOTEMPTY,
        FsError::Busy => SyscallError::EBUSY,
        FsError::ReadOnly => SyscallError::EROFS,
        FsError::NoSpace | FsError::NoMem => SyscallError::ENOMEM,
        FsError::Io => SyscallError::EIO,
        FsError::NameTooLong => SyscallError::ENAMETOOLONG,
        FsError::Invalid | FsError::Seek => SyscallError::EINVAL,
        FsError::Again => SyscallError::EAGAIN,
        FsError::CrossDev => SyscallError::EXDEV,
        FsError::SymlinkLoop => SyscallError::ELOOP,
        FsError::NotSupported => SyscallError::ENOSYS,
        FsError::BadFd => SyscallError::EBADF,
        FsError::Pipe => SyscallError::EPIPE,
    }
}

/// VFS open callback for syscall registration
///
/// Called by sys_open to open a file through VFS
fn vfs_open_callback(
    path: &str,
    flags: u32,
    mode: u32,
    authorization: &kernel_core::process::CredentialAuthorization,
) -> Result<kernel_core::syscall::PreparedVfsOpen, SyscallError> {
    prepare_syscall_open(path, flags, mode, ResolveFlags::empty(), authorization)
}

/// VFS open with resolve flags callback (openat2 support)
///
/// Called by sys_openat2 to open a file with resolve flags through VFS
fn vfs_open_with_resolve_callback(
    path: &str,
    flags: u32,
    mode: u32,
    resolve: u64,
    authorization: &kernel_core::process::CredentialAuthorization,
) -> Result<kernel_core::syscall::PreparedVfsOpen, SyscallError> {
    prepare_syscall_open(
        path,
        flags,
        mode,
        ResolveFlags::from_bits(resolve),
        authorization,
    )
}

fn prepare_syscall_open(
    path: &str,
    flags: u32,
    mode: u32,
    resolve_flags: ResolveFlags,
    authorization: &kernel_core::process::CredentialAuthorization,
) -> Result<kernel_core::syscall::PreparedVfsOpen, SyscallError> {
    let open_flags = OpenFlags::from_bits(flags);
    let perm = (mode & 0o7777) as u16;
    #[cfg(feature = "open_fault_probe")]
    let probe = open_fault_probe::select(path, open_flags);
    #[cfg(feature = "open_fault_probe")]
    let prepare = || open_fault_probe::prepare(probe);
    #[cfg(not(feature = "open_fault_probe"))]
    let prepare = PreparedFileHandle::try_new;

    let descriptor = VFS
        .open_with_resolve_using(
            path,
            open_flags,
            perm,
            resolve_flags,
            prepare,
            crate::context::OperationContext::current_using(Some(authorization))
                .map_err(fs_error_to_syscall)?,
        )
        .map_err(fs_error_to_syscall)?;
    #[cfg(feature = "open_fault_probe")]
    let finalize = open_fault_probe::finalizer(probe);
    #[cfg(not(feature = "open_fault_probe"))]
    let finalize = finish_syscall_open;
    let prepared = kernel_core::syscall::PreparedVfsOpen::new(descriptor, finalize);
    #[cfg(feature = "open_fault_probe")]
    let prepared = prepared.with_fault_probe(probe);
    Ok(prepared)
}

fn finish_open(descriptor: &dyn kernel_core::process::FileOps) -> Result<(), FsError> {
    finish_open_using(descriptor, lsm::hook_file_truncate).map(|_| ())
}

/// The hook result is checked before the only mutation. The boolean identifies
/// actual truncation for the optional probe; ordinary callers discard it.
fn finish_open_using(
    descriptor: &dyn kernel_core::process::FileOps,
    truncate_hook: fn(&LsmProcessCtx, u64, u64) -> lsm::LsmResult,
) -> Result<bool, FsError> {
    let file = descriptor
        .as_any()
        .downcast_ref::<FileHandle>()
        .ok_or(FsError::BadFd)?;
    let context = file.pending_context.lock().take();
    if !file.flags().is_truncate() || !file.flags().is_writable() {
        return Ok(false);
    }
    let stat = file.inode.stat()?;
    if stat.mode.file_type != FileType::Regular {
        return Ok(false);
    }
    let context = context.ok_or(FsError::PermDenied)?;
    if !context.permits(&stat, file.flags().is_readable(), true, false) {
        return Err(FsError::PermDenied);
    }
    truncate_hook(&context.subject, stat.ino, 0).map_err(|_| FsError::PermDenied)?;
    file.inode.truncate(0)?;
    Ok(true)
}

fn finish_syscall_open(descriptor: &dyn kernel_core::process::FileOps) -> Result<(), SyscallError> {
    finish_open(descriptor).map_err(fs_error_to_syscall)
}

/// VFS stat callback for syscall registration
///
/// Called by sys_stat to get file status through VFS
fn vfs_stat_callback(path: &str) -> Result<VfsStat, SyscallError> {
    let stat = VFS.stat(path).map_err(fs_error_to_syscall)?;
    vfs_stat_from(stat)
}

/// VFS lstat callback (M0-6 SLICE 3) — stat the LINK itself, not its target.
///
/// Backs `sys_lstat` and `sys_fstatat(AT_SYMLINK_NOFOLLOW)`. Routes through
/// `Vfs::stat_nofollow` (no-follow final component).
fn vfs_stat_nofollow_callback(path: &str) -> Result<VfsStat, SyscallError> {
    let stat = VFS.stat_nofollow(path).map_err(fs_error_to_syscall)?;
    vfs_stat_from(stat)
}

/// Shared conversion from the VFS `Stat` to the ABI `VfsStat`.
///
/// D2-ABI-STAT-LAYOUT: targets the Linux x86-64 `struct stat` wire layout —
/// delegates to the single `TryFrom<Stat>` impl in types.rs (oversized
/// size/blocks fail closed as `EOVERFLOW`, matching Linux stat semantics).
fn vfs_stat_from(stat: Stat) -> Result<VfsStat, SyscallError> {
    VfsStat::try_from(stat)
}

/// VFS lseek callback for syscall registration
///
/// Called by sys_lseek to seek within a file
/// Receives a &dyn Any reference and attempts to downcast to FileHandle
fn vfs_lseek_callback(
    file_any: &dyn core::any::Any,
    offset: i64,
    whence: i32,
) -> Result<u64, SyscallError> {
    use crate::traits::FileHandle;
    use crate::types::SeekWhence;

    // Try to downcast to FileHandle
    if let Some(file_handle) = file_any.downcast_ref::<FileHandle>() {
        let seek_whence = match whence {
            0 => SeekWhence::Set,
            1 => SeekWhence::Cur,
            2 => SeekWhence::End,
            _ => return Err(SyscallError::EINVAL),
        };

        file_handle.seek(offset, seek_whence).map_err(|e| match e {
            FsError::Seek => SyscallError::EINVAL,
            FsError::Invalid => SyscallError::EINVAL,
            _ => SyscallError::EIO,
        })
    } else {
        // Not a VFS FileHandle (e.g., pipe), seek not supported
        Err(SyscallError::EINVAL)
    }
}

/// M0-4: VFS read-whole-file-for-exec callback for syscall registration.
///
/// Called by `sys_execve` (via `exec_read_file`) to load an executable's bytes
/// by path with a single +x/DAC/LSM-gated resolution. Trivial passthrough —
/// `read_file_for_exec` already returns a `SyscallError`.
fn vfs_read_file_callback(path: &str, max: usize) -> Result<Vec<u8>, SyscallError> {
    VFS.read_file_for_exec(path, max)
}

/// M0-4: self-test for the exec-read VFS leg (`read_file_for_exec`) — the new VFS
/// code the pure kernel_core helper tests cannot reach. Explicit boot authority
/// stages a file on the initialized root RAMFS and exercises the incremental
/// exec-read path, size cap, and pure host-ID permission decision.
pub fn run_exec_read_file_self_test() {
    assert!(matches!(
        VFS.read_file_for_exec_trusted("/zeroos_m04_definitely_absent", 4096),
        Err(SyscallError::ENOENT)
    ));
    assert!(matches!(
        VFS.read_file_for_exec_trusted("/", 4096),
        Err(SyscallError::EISDIR)
    ));

    let path = "/zeroos_m04_exec_read_test";
    let content: &[u8] = b"\x7FELF M0-4 exec-read self-test payload (one-chunk incremental read)";
    let create = OpenFlags::new(OpenFlags::O_CREAT | OpenFlags::O_WRONLY);
    let descriptor = VFS
        .open_trusted(path, create, 0o755)
        .expect("exec-read fixture open");
    assert_eq!(
        descriptor
            .as_any()
            .downcast_ref::<FileHandle>()
            .expect("VFS descriptor")
            .write(content)
            .expect("exec-read fixture payload"),
        content.len(),
    );
    drop(descriptor);
    {
        let got = VFS
            .read_file_for_exec_trusted(path, 1 << 20)
            .expect("read_file_for_exec happy path");
        assert_eq!(got.as_slice(), content);
        // Size cap => E2BIG.
        assert!(matches!(
            VFS.read_file_for_exec_trusted(path, content.len() - 1),
            Err(SyscallError::E2BIG)
        ));

        // R172-P6-F5: the pure host-ID DAC function covers unprivileged subjects
        // even though fixture setup uses explicit boot authority.
        {
            let xstat = VFS.stat_trusted(path).expect("exec-read fixture stat");
            let perm = xstat.mode.perm;
            let empty: &[u32] = &[];
            // Fabricated NON-root, NON-owner, NON-group creds => the "others" bits decide.
            let nobody_uid = xstat.uid.wrapping_add(0x4000) | 1;
            let nobody_gid = xstat.gid.wrapping_add(0x4000) | 1;
            // need_exec is allowed IFF the others class has +x (the motivating gate).
            assert_eq!(
                permission_bits_allow(nobody_uid, nobody_gid, empty, &xstat, false, false, true),
                (perm & 0o1) != 0,
                "P6-F5: others-exec decision must match the others +x bit"
            );
            // need_write IFF the others class has +w (a guaranteed deny on a 0o755 file).
            assert_eq!(
                permission_bits_allow(nobody_uid, nobody_gid, empty, &xstat, false, true, false),
                (perm & 0o2) != 0,
                "P6-F5: others-write decision must match the others +w bit"
            );
            // OWNER class uses the high bits.
            assert_eq!(
                permission_bits_allow(xstat.uid, nobody_gid, empty, &xstat, false, false, true),
                (perm >> 6 & 0o1) != 0,
                "P6-F5: owner-exec decision must match the owner +x bit"
            );
            // Host root (euid 0) ALWAYS bypasses DAC, even requesting all of r/w/x.
            assert!(
                permission_bits_allow(0, 0, empty, &xstat, true, true, true),
                "P6-F5: host root bypasses DAC"
            );
        }
        klog_always!(
            "    \u{2713} M0 #4 read_file_for_exec: ENOENT/EISDIR + staged read + E2BIG cap + DAC(R172-P6-F5)"
        );
    }
}

/// M0-6 slice 2 self-test with explicit boot authority. The errno-mapper assertions
/// and the HALF-MUTATION ATOMICITY GUARD are the load-bearing checks: they pin the dual-mapper
/// errno-fidelity fix and the insert-first/remove-after rewrite (the bug this slice fixes
/// removed the source BEFORE the add, losing the entry when the add failed).
pub fn run_rename_self_test() {
    // --- Pure errno-mapper fidelity (always runs; no staging needed) ---
    assert!(matches!(
        fs_error_to_syscall(FsError::NotEmpty),
        SyscallError::ENOTEMPTY
    ));
    assert!(matches!(
        fs_error_to_syscall(FsError::ReadOnly),
        SyscallError::EROFS
    ));
    assert!(matches!(
        fs_error_to_syscall(FsError::NameTooLong),
        SyscallError::ENAMETOOLONG
    ));
    // Absent source => ENOENT (holds regardless of staging).
    assert!(matches!(
        VFS.rename_trusted("/zeroos_m06_absent_src", "/zeroos_m06_dst", false),
        Err(FsError::NotFound)
    ));

    // --- Staged behavioral tests ---
    let da = "/zeroos_m06_rn_a";
    let db = "/zeroos_m06_rn_b";
    let staged = VFS.create_trusted(da, FileMode::directory(0o755)).is_ok()
        && VFS.create_trusted(db, FileMode::directory(0o755)).is_ok()
        && VFS
            .create_trusted(&(da.to_string() + "/f"), FileMode::regular(0o644))
            .is_ok();
    assert!(
        staged,
        "rename fixture must stage on initialized root RAMFS"
    );
    let src = da.to_string() + "/f";
    let dst = db.to_string() + "/f";

    // (1) HAPPY cross-dir move: old gone, new present.
    assert!(
        VFS.rename_trusted(&src, &dst, false).is_ok(),
        "happy rename"
    );
    assert!(
        matches!(VFS.stat_trusted(&src), Err(FsError::NotFound)),
        "source gone after rename"
    );
    assert!(
        VFS.stat_trusted(&dst).is_ok(),
        "destination present after rename"
    );

    // (2) HALF-MUTATION ATOMICITY GUARD (load-bearing): a rename to an over-long final
    // component fails BEFORE any mutation, so the source SURVIVES.
    let overlong = db.to_string() + "/" + &"x".repeat(256);
    assert!(
        VFS.rename_trusted(&dst, &overlong, false).is_err(),
        "over-long new name must fail"
    );
    assert!(
        VFS.stat_trusted(&dst).is_ok(),
        "source must SURVIVE a failed rename (atomicity)"
    );

    // (3) RENAME_NOREPLACE: rename onto an existing dest with noreplace => EEXIST; both survive.
    let g = db.to_string() + "/g";
    assert!(
        VFS.create_trusted(&g, FileMode::regular(0o644)).is_ok(),
        "stage g for NOREPLACE"
    );
    assert!(
        matches!(VFS.rename_trusted(&dst, &g, true), Err(FsError::Exists)),
        "NOREPLACE onto existing => EEXIST"
    );
    assert!(
        VFS.stat_trusted(&dst).is_ok() && VFS.stat_trusted(&g).is_ok(),
        "both survive a NOREPLACE rejection"
    );

    // (4) ENOTEMPTY: a directory cannot replace a NON-EMPTY directory.
    let d1 = db.to_string() + "/d1";
    let d2 = db.to_string() + "/d2";
    let ne_ok = VFS.create_trusted(&d1, FileMode::directory(0o755)).is_ok()
        && VFS
            .create_trusted(&(d1.clone() + "/c"), FileMode::regular(0o644))
            .is_ok()
        && VFS.create_trusted(&d2, FileMode::directory(0o755)).is_ok();
    assert!(ne_ok, "nonempty rename fixture must stage");
    {
        assert!(
            matches!(VFS.rename_trusted(&d2, &d1, false), Err(FsError::NotEmpty)),
            "dir over non-empty dir => NotEmpty"
        );
        assert!(
            VFS.stat_trusted(&d2).is_ok(),
            "source dir survives NotEmpty rejection"
        );
    }

    // (5) R172-22 SAME-PARENT move: exercises the same-parent `g.try_insert` grow arm of
    // the FallibleOrderedMap migration (test (1) exercised the cross-parent `ng.try_insert`
    // arm). Old name gone, new name present, same directory.
    let g2 = db.to_string() + "/g2";
    assert!(
        VFS.rename_trusted(&g, &g2, false).is_ok(),
        "same-parent rename"
    );
    assert!(
        matches!(VFS.stat_trusted(&g), Err(FsError::NotFound)),
        "same-parent rename: old name gone"
    );
    assert!(
        VFS.stat_trusted(&g2).is_ok(),
        "same-parent rename: new name present"
    );

    klog_always!(
        "    \u{2713} M0-6 rename: mapper(ENOTEMPTY/EROFS/ENAMETOOLONG) + happy move + atomicity guard + NOREPLACE + NotEmpty + same-parent(R172-22)"
    );
}

/// P2-C: pure structural self-test for fallible symlink-resolution helpers.
///
/// Does not touch VFS mounts or real symlinks — pins the helper arithmetic a
/// green boot cannot exercise (try_reserve capacity, join shapes, UTF-8 gate).
pub fn run_symlink_fallible_helpers_self_test() {
    // (1) try_zeroed_buf length + zero fill.
    let b = try_zeroed_buf(4).expect("zeroed buf");
    assert_eq!(b.len(), 4);
    assert!(b.iter().all(|&x| x == 0));
    let b1 = try_zeroed_buf(0).expect("len 0 => 1");
    assert_eq!(b1.len(), 1);

    // (2) try_string_from_str / utf8.
    let s = try_string_from_str("abc").expect("str clone");
    assert_eq!(s, "abc");
    assert!(matches!(
        try_string_from_utf8_slice(&[0xff, 0xfe]),
        Err(FsError::Invalid)
    ));
    let s2 = try_string_from_utf8_slice(b"hi").expect("utf8");
    assert_eq!(s2, "hi");

    // (3) path join shapes.
    assert_eq!(try_join_path_components(&[]).unwrap(), "/");
    assert_eq!(try_join_path_components(&["a"]).unwrap(), "/a");
    assert_eq!(try_join_path_components(&["a", "b"]).unwrap(), "/a/b");
    assert_eq!(try_join_two("/foo", "bar").unwrap(), "/foo/bar");
    assert_eq!(try_join_two("/foo/", "bar").unwrap(), "/foo/bar");
    assert_eq!(try_join_two("/", "bar").unwrap(), "/bar");
    assert_eq!(try_join_two("/foo", "").unwrap(), "/foo");
    assert_eq!(try_concat_strs("a", "b").unwrap(), "ab");
}

/// Register VFS callbacks with kernel_core
pub fn register_syscall_callbacks() {
    kernel_core::mount_namespace::register_destroy_callback(|id| VFS.remove_namespace_id(id));
    kernel_core::fs_context::register_callbacks(kernel_core::fs_context::FsCallbacks {
        access: |name, mode| VFS.access(name, mode).map_err(fs_error_to_syscall),
        getcwd: || VFS.getcwd().map_err(fs_error_to_syscall),
        change_directory: |name, root| {
            VFS.change_directory(name, root)
                .map_err(fs_error_to_syscall)
        },
        pivot_root: |new_root, put_old| {
            VFS.pivot_root(new_root, put_old)
                .map_err(fs_error_to_syscall)
        },
        namespace_bindings: |source, target, state| {
            VFS.namespace_bindings_valid(source, target, state)
                .map_err(fs_error_to_syscall)
        },
    });
    kernel_core::register_vfs_open_callback(vfs_open_callback);
    kernel_core::register_vfs_open_with_resolve_callback(vfs_open_with_resolve_callback);
    kernel_core::register_vfs_stat_callback(vfs_stat_callback);
    kernel_core::register_vfs_read_file_callback(vfs_read_file_callback); // M0-4
    kernel_core::register_vfs_lseek_callback(vfs_lseek_callback);
    kernel_core::register_vfs_create_callback(vfs_create_callback);
    kernel_core::register_vfs_unlink_callback(vfs_unlink_callback);
    kernel_core::register_vfs_rename_callback(vfs_rename_callback);
    kernel_core::register_vfs_readdir_callback(vfs_readdir_callback);
    kernel_core::register_vfs_truncate_callback(vfs_truncate_callback);
    kernel_core::register_vfs_pread_callback(vfs_pread_callback); // R173-07 proper fix
    kernel_core::register_vfs_pwrite_callback(vfs_pwrite_callback); // R173-07 proper fix
    kernel_core::syscall::register_vfs_symlink_callback(vfs_symlink_callback); // M0-6 SLICE 3
    kernel_core::syscall::register_vfs_readlink_callback(vfs_readlink_callback); // M0-6 SLICE 3
    kernel_core::syscall::register_vfs_stat_nofollow_callback(vfs_stat_nofollow_callback); // M0-6 SLICE 3 (lstat)

    // R74-2 FIX: Register mount namespace materialization callback.
    // This enables eager materialization when namespaces are created via
    // sys_clone(CLONE_NEWNS) or sys_unshare(CLONE_NEWNS), preventing
    // post-clone parent mounts from leaking into child namespaces.
    kernel_core::register_mount_ns_materialize_callback(mount_ns_materialize_callback);
    kernel_core::register_mount_ns_materialize_rollback_callback(
        mount_ns_materialize_rollback_callback,
    );

    klog_always!("VFS syscall callbacks registered (openat2 enabled, R74-2 materialize enabled, R173-07 pread64/pwrite64 enabled, M0-6 symlink enabled)");
}

/// R74-2 FIX: Mount namespace materialization callback.
///
/// Called by syscall layer when a new mount namespace is created to ensure
/// the mount table is eagerly materialized, preventing race conditions where
/// parent namespace mounts could leak into the child.
fn mount_ns_materialize_callback(
    ns: &alloc::sync::Arc<kernel_core::MountNamespace>,
) -> Result<(), ()> {
    VFS.materialize_namespace(ns).map_err(|_| ())
}

fn mount_ns_materialize_rollback_callback(ns: &alloc::sync::Arc<kernel_core::MountNamespace>) {
    VFS.rollback_materialized_namespace(ns);
}

/// VFS create callback for syscall registration
///
/// Called by sys_mkdir to create directories
fn vfs_create_callback(path: &str, mode: u32, is_dir: bool) -> Result<(), SyscallError> {
    let file_mode = if is_dir {
        FileMode::directory((mode & 0o7777) as u16)
    } else {
        FileMode::regular((mode & 0o7777) as u16)
    };

    VFS.create(path, file_mode)
        .map(|_| ())
        .map_err(fs_error_to_syscall)
}

/// VFS unlink callback for syscall registration
///
/// Called by sys_unlink/sys_rmdir to delete files/directories
fn vfs_unlink_callback(path: &str, must_be_dir: Option<bool>) -> Result<(), SyscallError> {
    VFS.unlink(path, must_be_dir).map_err(fs_error_to_syscall)
}

/// VFS rename callback for syscall registration (M0-6 slice 2).
///
/// Called by sys_rename / sys_renameat / sys_renameat2.
fn vfs_rename_callback(old: &str, new: &str, noreplace: bool) -> Result<(), SyscallError> {
    VFS.rename(old, new, noreplace).map_err(fs_error_to_syscall)
}

/// VFS readdir callback for syscall registration
///
/// Called by sys_getdents64 to read directory entries.
///
/// R114-2 FIX: Added `max_bytes` budget parameter. The callback estimates the serialized
/// dirent64 size for each entry (header + name + NUL + 8-byte alignment) and stops
/// collecting once the estimated total exceeds the budget. This prevents unbounded kernel
/// heap allocation from large directories, which would trigger OOM panic via
/// `alloc_error_handler`.
///
/// If the first entry alone exceeds the budget, returns `EINVAL` (Linux-compatible behavior
/// for buffer-too-small).
fn commit_readdir_copy_result(
    offset: &mut u64,
    entries: &[kernel_core::DirEntry],
    expected_bytes: usize,
    copy_result: Result<usize, SyscallError>,
) -> Result<usize, SyscallError> {
    let written = copy_result?;
    if written != expected_bytes {
        return Err(SyscallError::EIO);
    }
    if let Some(last) = entries.last() {
        *offset = u64::try_from(last.next_cookie).map_err(|_| SyscallError::EOVERFLOW)?;
    }
    Ok(written)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReaddirReserveAction {
    Append,
    FinishPartial,
}

/// RF180-38 FIX: distinguish true end-of-directory from staging allocation
/// failure. Before any entry is complete, OOM must be observable as ENOMEM;
/// after a complete prefix exists, Linux getdents semantics return that prefix
/// and leave the uncommitted entry for the next call.
fn classify_readdir_reserve(
    completed_entries: usize,
    reserve_result: Result<(), TryReserveError>,
) -> Result<ReaddirReserveAction, SyscallError> {
    match reserve_result {
        Ok(()) => Ok(ReaddirReserveAction::Append),
        Err(_) if completed_entries == 0 => Err(SyscallError::ENOMEM),
        Err(_) => Ok(ReaddirReserveAction::FinishPartial),
    }
}

/// R186-8 FIX: apply the SAME partial-result rule to an allocation failure raised
/// by `Inode::readdir` itself.
///
/// Making per-entry name construction fallible creates a second way for the
/// staging loop to hit OOM: the filesystem now returns `NoMem`/`NoSpace` instead
/// of aborting. The loop's only error leg returned immediately and dropped the
/// whole `entries` vector, so a failure on entry 500 of an enumeration threw away
/// 499 complete records — a violation of the getdents64 partial-result contract
/// and, worse, a silent one: userspace would see ENOMEM for a call that had
/// already consumed no cookie and could never make progress.
///
/// Allocation failure is therefore classified exactly like a staging-reservation
/// failure: ENOMEM only while nothing is complete, otherwise commit the prefix and
/// leave the failing entry for the next call (the cookie is not advanced past it,
/// and `commit_readdir_copy_result` only publishes after a successful copyout, so
/// the retry re-reads the same entry).
///
/// Errors that are NOT allocation failures keep propagating: an I/O error or
/// corrupt on-disk record must not be disguised as end-of-directory.
fn classify_readdir_error(
    completed_entries: usize,
    error: FsError,
) -> Result<ReaddirReserveAction, SyscallError> {
    let transient_alloc_failure = matches!(error, FsError::NoMem | FsError::NoSpace);
    if !transient_alloc_failure {
        return Err(fs_error_to_syscall(error));
    }
    if completed_entries == 0 {
        return Err(SyscallError::ENOMEM);
    }
    Ok(ReaddirReserveAction::FinishPartial)
}

fn vfs_readdir_callback(
    fd: i32,
    max_bytes: usize,
    user_dst: *mut u8,
    copyout: kernel_core::syscall::VfsDirCopyout,
) -> Result<usize, SyscallError> {
    use kernel_core::current_pid;
    use kernel_core::get_process;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Get inode and the shared offset object from the file handle.
    // FIX: Extract inode Arc and offset to release process lock before I/O
    let (inode, shared_offset, _owner) = {
        let proc = proc_arc.lock();
        let handle = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

        // Downcast to FileHandle
        let file_handle = handle
            .as_any()
            .downcast_ref::<FileHandle>()
            .ok_or(SyscallError::ENOTDIR)?;

        // R131-5 + R180-4 FIX: require a readable (non-O_PATH) description for
        // getdents64. O_PATH and residual non-readable access modes (O_WRONLY,
        // illegal mode 3 if any path skipped open validation) must not enumerate.
        if !file_handle.flags().allows_readdir() {
            return Err(SyscallError::EBADF);
        }

        (
            Arc::clone(&file_handle.inode),
            file_handle.offset.clone(),
            file_handle.clone(),
        )
    };
    // Process lock released here - safe for procfs operations
    if !inode.is_dir() {
        return Err(SyscallError::ENOTDIR);
    }

    // R37-4 FIX (Codex review): Add MAC check for sys_getdents64.
    let dir_stat = inode.stat().map_err(fs_error_to_syscall)?;
    let context = crate::context::OperationContext::current().map_err(fs_error_to_syscall)?;
    lsm::hook_file_permission(&context.subject, dir_stat.ino, 0x05)
        .map_err(|_| SyscallError::EACCES)?;

    // R180-L1: serialize concurrent operations on this open file description.
    // Hold the offset lock through enumeration and user copyout; publish the new
    // position only after copyout succeeds.
    let mut offset_guard = shared_offset.lock();
    let start_offset = usize::try_from(*offset_guard).map_err(|_| SyscallError::EOVERFLOW)?;

    // R114-2 + R180-25: budget against the exact Linux wire record. `d_name`
    // starts immediately after d_type at byte 19; the 24-byte Rust struct size
    // includes tail padding and must never be used as the flexible-tail offset.
    const DIRENT64_HEADER_SIZE: usize = kernel_core::syscall::LINUX_DIRENT64_NAME_OFFSET;
    let mut entries = Vec::new();
    let mut offset = start_offset;
    let mut estimated_bytes: usize = 0;

    loop {
        match inode.readdir(offset) {
            Ok(Some((next, entry))) => {
                let next_cookie = i64::try_from(next).map_err(|_| SyscallError::EOVERFLOW)?;
                // Estimate the serialized record length for this entry
                let reclen = (DIRENT64_HEADER_SIZE + entry.name.len() + 1 + 7) & !7;

                // R114-2 FIX: If the first entry alone exceeds the budget, return EINVAL
                // (Linux-compatible: buffer too small to fit even one record).
                if entries.is_empty() && reclen > max_bytes {
                    return Err(SyscallError::EINVAL);
                }

                // Stop collecting if adding this entry would exceed the budget.
                // The entries collected so far are within budget.
                // R114-2 FIX: Use saturating_add as defensive measure against overflow,
                // even though max_bytes is capped at 1MB making overflow impossible.
                if estimated_bytes.saturating_add(reclen) > max_bytes {
                    break;
                }
                // Convert VFS DirEntry to kernel_core DirEntry
                let file_type = match entry.file_type {
                    crate::types::FileType::Regular => kernel_core::FileType::Regular,
                    crate::types::FileType::Directory => kernel_core::FileType::Directory,
                    crate::types::FileType::CharDevice => kernel_core::FileType::CharDevice,
                    crate::types::FileType::BlockDevice => kernel_core::FileType::BlockDevice,
                    crate::types::FileType::Symlink => kernel_core::FileType::Symlink,
                    crate::types::FileType::Fifo => kernel_core::FileType::Fifo,
                    crate::types::FileType::Socket => kernel_core::FileType::Socket,
                };
                // R161-6 + RF180-38 FIX: growth remains fallible, but allocation
                // failure is not end-of-directory. With no completed record it
                // is ENOMEM; otherwise copy and commit only the completed prefix.
                let reserve_result = entries.try_reserve(1);
                match classify_readdir_reserve(entries.len(), reserve_result)? {
                    ReaddirReserveAction::Append => {}
                    ReaddirReserveAction::FinishPartial => break,
                }
                entries.push(kernel_core::DirEntry {
                    name: entry.name,
                    ino: entry.ino,
                    file_type,
                    next_cookie,
                });
                estimated_bytes += reclen;
                offset = next;
            }
            Ok(None) => break,
            Err(e) => {
                // R186-8 FIX: an allocation failure inside `readdir` must not
                // discard the completed prefix. Break BEFORE `estimated_bytes` is
                // advanced (it is only advanced on the append path), so the byte
                // count still matches `entries` exactly and
                // `commit_readdir_copy_result`'s equality check holds.
                match classify_readdir_error(entries.len(), e)? {
                    ReaddirReserveAction::FinishPartial => break,
                    // `classify_readdir_error` never returns Append; it either
                    // propagates the error or requests the partial commit.
                    ReaddirReserveAction::Append => break,
                }
            }
        }
    }

    // RF180-14 FIX: the helper publishes only after successful copyout and an
    // exact byte-count proof. EFAULT/EIO retries retain the original cookie.
    commit_readdir_copy_result(
        &mut offset_guard,
        &entries,
        estimated_bytes,
        copyout(user_dst, max_bytes, &entries),
    )
}

#[cfg(test)]
mod readdir_cookie_tests {
    use super::*;

    fn deterministic_reserve_failure() -> Result<(), TryReserveError> {
        let mut probe = Vec::<u8>::new();
        probe.try_reserve(usize::MAX)
    }

    #[test]
    fn rf180_14_copy_fault_preserves_cookie_then_retry_commits() {
        let entries = [kernel_core::DirEntry {
            name: "entry".into(),
            ino: 1,
            file_type: kernel_core::FileType::Regular,
            next_cookie: 0x1234_5678,
        }];
        let mut offset = 0x55u64;
        assert!(matches!(
            commit_readdir_copy_result(&mut offset, &entries, 24, Err(SyscallError::EFAULT)),
            Err(SyscallError::EFAULT)
        ));
        assert_eq!(offset, 0x55, "fault must not consume the resume cookie");
        assert_eq!(
            commit_readdir_copy_result(&mut offset, &entries, 24, Ok(24)).unwrap(),
            24
        );
        assert_eq!(offset, 0x1234_5678);
    }

    #[test]
    fn rf180_38_first_entry_reserve_failure_returns_enomem_not_false_eof() {
        let reserve_result = deterministic_reserve_failure();
        assert!(
            reserve_result.is_err(),
            "capacity overflow must be deterministic"
        );
        assert!(matches!(
            classify_readdir_reserve(0, reserve_result),
            Err(SyscallError::ENOMEM)
        ));
    }

    #[test]
    fn rf180_38_later_reserve_failure_commits_completed_prefix() {
        let entries = [kernel_core::DirEntry {
            name: "complete".into(),
            ino: 7,
            file_type: kernel_core::FileType::Regular,
            next_cookie: 0x4321,
        }];
        let reserve_result = deterministic_reserve_failure();
        assert!(
            reserve_result.is_err(),
            "capacity overflow must be deterministic"
        );
        assert_eq!(
            classify_readdir_reserve(entries.len(), reserve_result).unwrap(),
            ReaddirReserveAction::FinishPartial
        );

        let expected_bytes =
            (kernel_core::syscall::LINUX_DIRENT64_NAME_OFFSET + entries[0].name.len() + 1 + 7) & !7;
        let mut offset = 0x55u64;
        assert_eq!(
            commit_readdir_copy_result(&mut offset, &entries, expected_bytes, Ok(expected_bytes),)
                .unwrap(),
            expected_bytes
        );
        assert_eq!(offset, entries[0].next_cookie as u64);
    }
}

#[cfg(test)]
mod rf180_37_open_tests {
    use super::*;

    use crate::HEAP_TEST_LOCK as TEST_LOCK;

    #[test]
    fn ksa004_prepared_open_cancellation_preserves_contents_and_success_truncates() {
        let _serial = TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let vfs = Vfs::new();
        let fs = RamFs::try_new().unwrap();
        let root = fs.root_inode();
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/", fs.clone())
            .unwrap();
        let victim = fs
            .create(
                &root,
                "transaction-victim",
                FileMode::regular(0o600),
                &crate::topology::write().setup(0, 0),
            )
            .unwrap();
        let contents = b"preserve these bytes until publication is ready";
        victim.write_at(0, contents).unwrap();
        let flags = OpenFlags::new(OpenFlags::O_WRONLY | OpenFlags::O_TRUNC);
        let prepared = vfs
            .open_with_resolve_using(
                "/transaction-victim",
                flags,
                0,
                ResolveFlags::empty(),
                PreparedFileHandle::try_new,
                vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap(),
            )
            .unwrap();
        assert_eq!(victim.stat().unwrap().size, contents.len() as u64);
        drop(kernel_core::syscall::PreparedVfsOpen::new(
            prepared,
            finish_syscall_open,
        ));
        let mut observed = [0u8; 64];
        assert_eq!(victim.read_at(0, &mut observed).unwrap(), contents.len());
        assert_eq!(&observed[..contents.len()], contents);
        let prepared = vfs
            .open_with_resolve_using(
                "/transaction-victim",
                flags,
                0,
                ResolveFlags::empty(),
                PreparedFileHandle::try_new,
                vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap(),
            )
            .unwrap();
        assert_eq!(victim.stat().unwrap().size, contents.len() as u64);
        finish_open(prepared.as_ref()).unwrap();
        assert_eq!(victim.stat().unwrap().size, 0);
        assert_eq!(victim.read_at(0, &mut observed).unwrap(), 0);
        victim.write_at(0, contents).unwrap();
        drop(vfs.open_trusted("/transaction-victim", flags, 0).unwrap());
        assert_eq!(victim.stat().unwrap().size, 0);
    }

    #[test]
    fn ksa004_truncate_does_not_mutate_character_devices() {
        let _serial = TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let vfs = Vfs::new();
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/", DevFs::new())
            .unwrap();
        let descriptor = vfs
            .open_trusted(
                "/null",
                OpenFlags::new(OpenFlags::O_WRONLY | OpenFlags::O_TRUNC),
                0,
            )
            .unwrap();
        let file = descriptor.as_any().downcast_ref::<FileHandle>().unwrap();
        assert_eq!(file.stat().unwrap().mode.file_type, FileType::CharDevice);
        assert_eq!(file.write(b"discard").unwrap(), 7);
    }

    #[test]
    fn preparation_failure_precedes_create_and_truncate_without_vfs_ledger_drift() {
        let _serial = TEST_LOCK.lock();
        mm::publish_heap_budgets();

        let vfs = Vfs::new();
        let fs = RamFs::try_new().expect("RF180-37 ramfs fixture");
        let root = fs.root_inode();
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/", fs.clone())
            .expect("RF180-37 root mount");

        let victim = fs
            .create(
                &root,
                "victim",
                FileMode::new(FileType::Regular, 0o600),
                &crate::topology::write().setup(0, 0),
            )
            .expect("RF180-37 victim creation");
        let contents = b"must survive failed O_TRUNC";
        assert_eq!(
            victim.write_at(0, contents).expect("victim write"),
            contents.len()
        );

        let ledger_before = mm::heap_class_snapshot(mm::HeapClass::Vfs);
        assert!(matches!(
            vfs.open_with_resolve_using(
                "/must-not-exist",
                OpenFlags::new(OpenFlags::O_CREAT | OpenFlags::O_WRONLY),
                0o600,
                ResolveFlags::empty(),
                || Err(FsError::NoMem),
                vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap()
            ),
            Err(FsError::NoMem)
        ));
        assert!(matches!(
            fs.lookup(&root, "must-not-exist"),
            Err(FsError::NotFound)
        ));
        assert_eq!(mm::heap_class_snapshot(mm::HeapClass::Vfs), ledger_before);

        assert!(matches!(
            vfs.open_with_resolve_using(
                "/victim",
                OpenFlags::new(OpenFlags::O_WRONLY | OpenFlags::O_TRUNC),
                0,
                ResolveFlags::empty(),
                || Err(FsError::NoMem),
                vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap()
            ),
            Err(FsError::NoMem)
        ));
        assert_eq!(
            victim.stat().expect("victim stat").size,
            contents.len() as u64
        );
        let mut observed = [0u8; 64];
        assert_eq!(
            victim.read_at(0, &mut observed).expect("victim readback"),
            contents.len()
        );
        assert_eq!(&observed[..contents.len()], contents);
        assert_eq!(mm::heap_class_snapshot(mm::HeapClass::Vfs), ledger_before);
    }
}

/// VFS truncate callback for syscall registration
///
/// Called by sys_ftruncate to truncate a file
fn vfs_truncate_callback(fd: i32, length: u64) -> Result<(), SyscallError> {
    let context = crate::context::OperationContext::current().map_err(fs_error_to_syscall)?;
    let process = context.process.as_ref().ok_or(SyscallError::ESRCH)?;
    let file = {
        let proc = process.lock();
        let handle = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
        let file = handle
            .as_any()
            .downcast_ref::<FileHandle>()
            .ok_or(SyscallError::ENOSYS)?;
        if !file.flags().is_writable() {
            return Err(SyscallError::EINVAL);
        }
        file.clone()
    };
    let stat = file.inode.stat().map_err(fs_error_to_syscall)?;
    lsm::hook_file_truncate(&context.subject, stat.ino, length).map_err(|_| SyscallError::EPERM)?;
    file.inode.truncate(length).map_err(fs_error_to_syscall)
}

/// Shared access/seekability gate for pread64 and pwrite64.
#[inline]
fn positioned_io_gate(access_allowed: bool, seekable: bool) -> Result<(), SyscallError> {
    if !access_allowed {
        return Err(SyscallError::EBADF);
    }
    if !seekable {
        return Err(SyscallError::ESPIPE);
    }
    Ok(())
}

/// RF180-L1 executable state matrix for positioned I/O. In particular, a
/// readable character device such as `/dev/console` must fail with ESPIPE
/// before its consuming `read_at` implementation is reached.
pub fn run_positioned_io_gate_self_test() {
    assert_eq!(positioned_io_gate(false, false), Err(SyscallError::EBADF));
    assert_eq!(positioned_io_gate(true, false), Err(SyscallError::ESPIPE));
    assert_eq!(positioned_io_gate(true, true), Ok(()));
}

/// VFS positioned read callback for pread64 (R173-07 proper fix).
/// Reads from fd at offset without changing the fd's current offset.
fn vfs_pread_callback(fd: i32, buf: &mut [u8], offset: u64) -> Result<usize, SyscallError> {
    use kernel_core::{current_pid, get_process};

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Clone inode Arc under the process lock, drop before I/O (same R132-2/R41-3
    // pattern as vfs_truncate: procfs callbacks may touch PROCESS_TABLE, so
    // holding Process lock across inode.read_at() risks lock inversion).
    let file = {
        let proc = proc_arc.lock();
        let handle = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

        // Downcast to FileHandle
        let file_handle = handle
            .as_any()
            .downcast_ref::<FileHandle>()
            .ok_or(SyscallError::ESPIPE)?;

        // RF180-L1: reject pipes/sockets/character devices before read_at can
        // dequeue input. Console FileHandles are deliberately non-seekable.
        positioned_io_gate(file_handle.flags().is_readable(), file_handle.seekable)?;

        file_handle.clone()
    };
    // Process lock released before positioned read

    let count = file
        .inode
        .read_at(offset, buf)
        .map_err(fs_error_to_syscall)?;
    if count > buf.len() {
        return Err(SyscallError::EIO);
    }
    Ok(count)
}

/// VFS positioned write callback for pwrite64 (R173-07 proper fix).
///
/// Writes to fd at offset without changing the fd's current offset.
fn vfs_pwrite_callback(fd: i32, data: &[u8], offset: u64) -> Result<usize, SyscallError> {
    use kernel_core::{current_pid, get_process};

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Clone the shared description under Process, release the lock before I/O.
    let file = {
        let proc = proc_arc.lock();
        let handle = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;

        // Downcast to FileHandle
        let file_handle = handle
            .as_any()
            .downcast_ref::<FileHandle>()
            .ok_or(SyscallError::ESPIPE)?;

        // Keep positioned-write semantics congruent: non-seekable endpoints
        // reject before any externally visible device write.
        positioned_io_gate(file_handle.flags().is_writable(), file_handle.seekable)?;

        file_handle.clone()
    };
    // Process lock released before positioned write

    let count = file.pwrite(offset, data).map_err(fs_error_to_syscall)?;
    if count > data.len() {
        return Err(SyscallError::EIO);
    }
    Ok(count)
}

/// VFS symlink creation callback (M0-6 SLICE 3).
///
/// Creates a symbolic link at linkpath pointing to target. Delegates to
/// `Vfs::symlink`, which performs namespace-correct filesystem selection, DAC/LSM
/// gating, and C.4 revalidation.
fn vfs_symlink_callback(linkpath: &str, target: &str) -> Result<(), SyscallError> {
    VFS.symlink(linkpath, target).map_err(fs_error_to_syscall)
}

/// VFS readlink callback (M0-6 SLICE 3).
///
/// Reads the LITERAL target of a symbolic link WITHOUT following it. Delegates to
/// `Vfs::readlink`, which uses the no-follow `lookup_symlink` primitive so a link
/// to a file — or a dangling link — reads correctly.
fn vfs_readlink_callback(path: &str) -> Result<alloc::string::String, SyscallError> {
    VFS.readlink(path).map_err(fs_error_to_syscall)
}
