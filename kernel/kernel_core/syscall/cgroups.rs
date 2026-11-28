//! Syscall family module: `cgroup` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// F.2 Cgroup v2 Syscalls
// ============================================================================

/// Buffer for returning cgroup statistics to userspace.
///
/// Must match the layout expected by userspace cgroup tools.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CgroupStatsBuf {
    /// Cgroup ID
    pub id: u64,
    /// Depth in hierarchy (root = 0)
    pub depth: u32,
    /// Enabled controllers bitmap (CPU=1, MEMORY=2, PIDS=4, IO=8, FILES=0x10, NET=0x20)
    pub controllers: u32,
    /// Current number of attached tasks
    pub nr_tasks: u64,
    /// Cumulative CPU time in nanoseconds
    pub cpu_time_ns: u64,
    /// Current memory usage in bytes
    pub memory_current: u64,
    /// Number of memory.high exceeded events
    pub memory_events_high: u64,
    /// Number of memory.max (OOM) events
    pub memory_events_max: u64,
    /// Number of pids.max exceeded events
    pub pids_events_max: u32,
    /// Padding for alignment
    _padding: u32,
    // F.2: IO controller statistics
    /// Total bytes read via block I/O
    pub io_read_bytes: u64,
    /// Total bytes written via block I/O
    pub io_write_bytes: u64,
    /// Total read I/O operations completed
    pub io_read_ios: u64,
    /// Total write I/O operations completed
    pub io_write_ios: u64,
    /// Number of times I/O was throttled due to io.max limit
    pub io_throttle_events: u64,
    // J.2 items 7/8/10: per-cgroup FD / ephemeral-port / VFS-dir accounting.
    // APPENDED (offset-stable) so a caller declaring the old 104-byte length via
    // `buf_len` still receives the exact v1 prefix (statx-style negotiation in
    // sys_cgroup_get_stats). Order chosen for zero implicit padding: three u64
    // (8-aligned) then two u32. kmem (item 9) is intentionally OMITTED — its
    // counter is not yet wired (page-table frames charge `memory_current`, not
    // `kmem_current`), so exposing it would publish a permanent zero.
    /// J2-7: current open file-descriptor count (FILES controller)
    pub fds_current: u64,
    /// J2-8: current ephemeral-port count (NET controller)
    pub ports_current: u64,
    /// J2-10: current in-flight VFS dir-enumeration bytes (MEMORY controller)
    pub vfs_dir_current: u64,
    /// J2-7: number of files.max exceeded events
    pub fds_events_max: u32,
    /// J2-8: number of ports.max exceeded events
    pub ports_events_max: u32,
}

// H.0.1-3: Compile-time ABI size assertion (136 bytes, no implicit padding).
// J.2: grown from 104 → 136 (3×u64 + 2×u32 appended). The v2 entry point
// (sys_cgroup_get_stats2) negotiates the length via its `buf_len` argument; the
// kernel never writes past the declared buffer.
const _: [(); 136] = [(); core::mem::size_of::<CgroupStatsBuf>()];

/// J.2: Frozen v1 ABI size for syscall 504. CgroupStatsBuf may grow over time
/// (new fields are APPENDED), but syscall 504 ALWAYS writes exactly this many
/// bytes — the offset-stable v1 prefix — so its ABI is permanently stable. New
/// appended fields are read only via the negotiated v2 entry point (syscall 516).
pub(super) const CGROUP_STATS_V1_SIZE: usize = 104;

// Pin the first appended field to the v1 boundary: this guarantees the bytes
// syscall 504 writes (the [0, CGROUP_STATS_V1_SIZE) prefix) are EXACTLY the v1
// fields (id … io_throttle_events). If a future edit inserts a field before
// `fds_current`, this assertion fails — forcing a deliberate ABI decision.
const _: [(); CGROUP_STATS_V1_SIZE] = [(); core::mem::offset_of!(CgroupStatsBuf, fds_current)];

/// H.0.1-3: Copy CgroupStatsBuf to userspace via a zeroed byte buffer so that
/// any padding bytes (explicit `_padding` field) are guaranteed zero, preventing
/// kernel memory disclosure. Mirrors the VfsStat pattern (R113-1).
///
/// J.2: `copy_len` is the statx-style negotiated length (== min(caller buf_len,
/// sizeof)). The full struct is serialized into the zeroed buffer, then ONLY the
/// first `copy_len` bytes are written to userspace — the kernel never writes past
/// the caller's declared buffer. Appended fields are offset-stable, so a caller
/// declaring the old 104-byte length receives exactly the v1 prefix.
#[inline]
pub(super) fn copy_cgroup_stats_to_user(
    user_dst: *mut CgroupStatsBuf,
    stats: &CgroupStatsBuf,
    copy_len: usize,
) -> Result<(), SyscallError> {
    let mut buf = [0u8; mem::size_of::<CgroupStatsBuf>()];

    macro_rules! put {
        ($field:ident) => {
            let off = mem::offset_of!(CgroupStatsBuf, $field);
            let bytes = stats.$field.to_ne_bytes();
            buf[off..off + bytes.len()].copy_from_slice(&bytes);
        };
    }

    put!(id);
    put!(depth);
    put!(controllers);
    put!(nr_tasks);
    put!(cpu_time_ns);
    put!(memory_current);
    put!(memory_events_high);
    put!(memory_events_max);
    put!(pids_events_max);
    // `_padding` intentionally left as zeroes in the buffer.
    put!(io_read_bytes);
    put!(io_write_bytes);
    put!(io_read_ios);
    put!(io_write_ios);
    put!(io_throttle_events);
    // J.2 appended fields.
    put!(fds_current);
    put!(ports_current);
    put!(vfs_dir_current);
    put!(fds_events_max);
    put!(ports_events_max);

    // Negotiated length: never write past the caller's declared buffer.
    let n = copy_len.min(buf.len());
    copy_to_user(user_dst as *mut u8, &buf[..n])
}

/// P1-3: Returns `true` if the current process's host-mapped euid is a
/// delegated owner of `cgroup_id` (or any ancestor in the delegation chain).
///
/// R134-2 FIX: Use host-mapped euid for delegation identity matching.
/// Namespace-relative euid can collide across user namespaces, allowing
/// an attacker to assume another namespace's delegation identity.
pub(super) fn is_cgroup_delegated_to_caller(cgroup_id: u64) -> bool {
    let euid = match crate::process::current_host_euid() {
        Some(uid) => uid,
        None => return false,
    };
    cgroup::lookup_cgroup(cgroup_id)
        .map(|cg| cg.is_delegated_to(euid))
        .unwrap_or(false)
}

/// sys_cgroup_create - Create a child cgroup
///
/// # Arguments
/// * `parent_id` - ID of parent cgroup (0 for root)
/// * `controllers` - Bitmask of controllers to enable (CPU=1, MEMORY=2, PIDS=4)
///
/// # Returns
/// * On success: New cgroup ID (positive)
/// * On error: Negative errno
///
/// # Security
///
/// R93-17 FIX: Proper capability-based access control.
///
/// Requires CAP_SYS_ADMIN capability to create cgroups. Previously only
/// checked euid==0 which bypassed the capability model and didn't support
/// future namespace-aware delegation.
pub(super) fn sys_cgroup_create(parent_id: u64, controllers: u32) -> Result<usize, SyscallError> {
    // R93-17 FIX: Capability-based access control for cgroup creation
    // P1-3: Also allow delegated owners of the parent cgroup
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let _creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    let has_cap_admin = current_has_cap_rights(cap::CapRights::ADMIN);

    if !has_cap_admin && !crate::current_is_host_root() && !is_cgroup_delegated_to_caller(parent_id)
    {
        return Err(SyscallError::EPERM);
    }

    // Convert u32 controllers to CgroupControllers flags
    let ctrl_flags = cgroup::CgroupControllers::from_bits_truncate(controllers);
    if ctrl_flags.is_empty() {
        return Err(SyscallError::EINVAL);
    }

    match cgroup::create_cgroup(parent_id, ctrl_flags) {
        Ok(node) => {
            let _ = audit::emit_cgroup_governance_event(
                get_audit_subject(),
                audit::AuditCgroupGovernanceOp::Create,
                node.id(),
                parent_id,
                node.id(),
                controllers as u64,
                crate::time::get_ticks(),
            );
            Ok(node.id() as usize)
        }
        Err(cgroup::CgroupError::OutOfMemory) => Err(SyscallError::ENOMEM),
        Err(cgroup::CgroupError::NotFound) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::DepthLimit) => Err(SyscallError::ENOSPC),
        Err(cgroup::CgroupError::CgroupLimit) => Err(SyscallError::ENOSPC),
        Err(cgroup::CgroupError::ControllerDisabled) => Err(SyscallError::EINVAL),
        Err(_) => Err(SyscallError::EINVAL),
    }
}

/// sys_cgroup_destroy - Delete a cgroup
///
/// # Arguments
/// * `cgroup_id` - ID of cgroup to delete
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno
///
/// # Security
///
/// R93-17 FIX: Proper capability-based access control.
///
/// Requires CAP_SYS_ADMIN capability. Cgroup must be empty.
pub(super) fn sys_cgroup_destroy(cgroup_id: u64) -> Result<usize, SyscallError> {
    // R93-17 FIX: Capability-based access control for cgroup destruction
    // P1-3: Also allow delegated owners (delegation checked on the cgroup itself,
    // since delegation inherits from ancestors)
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let _creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    let has_cap_admin = current_has_cap_rights(cap::CapRights::ADMIN);

    if !has_cap_admin && !crate::current_is_host_root() && !is_cgroup_delegated_to_caller(cgroup_id)
    {
        return Err(SyscallError::EPERM);
    }

    match cgroup::delete_cgroup(cgroup_id) {
        Ok(()) => {
            let _ = audit::emit_cgroup_governance_event(
                get_audit_subject(),
                audit::AuditCgroupGovernanceOp::Destroy,
                cgroup_id,
                cgroup_id,
                0,
                0,
                crate::time::get_ticks(),
            );
            Ok(0)
        }
        Err(cgroup::CgroupError::NotFound) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::NotEmpty) => Err(SyscallError::EBUSY),
        Err(cgroup::CgroupError::PermissionDenied) => Err(SyscallError::EPERM),
        Err(_) => Err(SyscallError::EINVAL),
    }
}

/// sys_cgroup_delegate (513) — Delegate management of a cgroup subtree to a UID.
///
/// # Arguments
/// * `cgroup_id` - ID of cgroup to delegate
/// * `uid` - Target UID, or `u64::MAX` to revoke delegation
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno (EPERM, ENOENT, EINVAL)
///
/// # Security
///
/// Requires root (euid == 0), CAP_SYS_ADMIN, or delegated subtree ownership
/// (sub-delegation). Delegation allows the specified UID to create/delete
/// children, set limits (bounded by ancestor ceilings), and migrate owned tasks
/// within the cgroup and its descendants. Pass `uid = u64::MAX` to revoke.
pub(super) fn sys_cgroup_delegate(cgroup_id: u64, uid: u64) -> Result<usize, SyscallError> {
    let _creds = crate::process::current_credentials().ok_or(SyscallError::ESRCH)?;
    let has_cap_admin = current_has_cap_rights(cap::CapRights::ADMIN);

    // P1-3: Allow host root, CAP_SYS_ADMIN, or delegated subtree managers.
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let authorized =
        crate::current_is_host_root() || has_cap_admin || is_cgroup_delegated_to_caller(cgroup_id);

    let delegate_uid = if uid == u64::MAX {
        None
    } else {
        if uid > u32::MAX as u64 {
            return Err(SyscallError::EINVAL);
        }
        Some(uid as u32)
    };

    // Determine audit operation type.
    let op = if delegate_uid.is_some() {
        audit::AuditCgroupDelegationOp::Grant
    } else {
        audit::AuditCgroupDelegationOp::Revoke
    };

    match cgroup::delegate_cgroup(cgroup_id, delegate_uid, authorized) {
        Ok(old_uid) => {
            // P1-3: Emit audit event for delegation lifecycle.
            let timestamp = crate::time::get_ticks();
            let _ = audit::emit_cgroup_delegation_event(
                get_audit_subject(),
                cgroup_id,
                op,
                old_uid,
                delegate_uid,
                0,
                timestamp,
            );
            Ok(0)
        }
        Err(cgroup::CgroupError::NotFound) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::PermissionDenied) => Err(SyscallError::EPERM),
        Err(_) => Err(SyscallError::EINVAL),
    }
}

/// R93-5 FIX: Check if target cgroup is a descendant of ancestor cgroup.
///
/// Thin wrapper over the shared helper in `cgroup` (R180-3 dual-front-door parity).
pub(super) fn cgroup_is_descendant_of(target_id: u64, ancestor_id: u64) -> bool {
    cgroup::cgroup_is_descendant_of(target_id, ancestor_id)
}

/// sys_cgroup_attach - Attach current process to a cgroup
///
/// # Arguments
/// * `cgroup_id` - ID of target cgroup
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno
///
/// # Security
///
/// R93-5 FIX: Require privilege to migrate between cgroups.
///
/// To prevent unprivileged cgroup escape (moving to a less restricted parent):
/// 1. Require CAP_SYS_ADMIN or root (euid == 0) to attach
/// 2. Target cgroup must be a descendant of current cgroup (can only move deeper)
///
/// Root users can still move anywhere; non-root with CAP_SYS_ADMIN is restricted
/// to descendants to prevent accidental privilege escalation.
///
/// R180-3 FIX: delegated managers must own **both** source and destination
/// (shared with cgroupfs via `cgroup::authorize_cgroup_migrate`).
pub(super) fn sys_cgroup_attach(
    cgroup_id: u64,
    entry_proc: Option<&crate::process::ProcessArc>,
) -> Result<usize, SyscallError> {
    let pid = crate::process::current_pid().ok_or(SyscallError::ESRCH)?;
    let process = match entry_proc {
        Some(proc_arc) => proc_arc.clone(),
        None => crate::process::get_process(pid).ok_or(SyscallError::ESRCH)?,
    };

    let (old_cgroup_id, memory_space, mm_sole_owner) = {
        let proc = process.lock();
        (
            proc.cgroup_id,
            proc.memory_space,
            alloc::sync::Arc::strong_count(&proc.mm) == 1,
        )
    };

    // R133-1 + R134-2 FIX: Snapshot host-mapped root, CAP_ADMIN, and host euid
    // in a single PCB hold reusing `entry_proc` (falls back fail-closed if creds
    // are transiently busy).
    let (is_root, has_cap_admin, host_euid) =
        match crate::process::current_cgroup_governance_auth_with_proc(
            cap::CapRights::ADMIN,
            Some(&process),
        ) {
            Some(auth) => (auth.is_host_root, auth.has_cap_rights, auth.host_euid),
            None => (false, false, None),
        };

    // R180-3: preflight auth (cheap reject). Authoritative re-auth under Process
    // lock uses the locked `proc.cgroup_id` so concurrent re-homes cannot swap
    // the source after the check.
    cgroup::authorize_cgroup_migrate(old_cgroup_id, cgroup_id, host_euid, is_root, has_cap_admin)
        .map_err(|e| match e {
        cgroup::CgroupError::OutOfMemory => SyscallError::ENOMEM,
        cgroup::CgroupError::NotFound => SyscallError::ENOENT,
        cgroup::CgroupError::PermissionDenied => SyscallError::EPERM,
        _ => SyscallError::EPERM,
    })?;

    // R156-1 FIX: Read memory_space under brief lock, then call
    // address_space_share_count() OUTSIDE Process lock to avoid ABBA
    // deadlock. address_space_share_count() acquires PROCESS_TABLE then
    // iterates locking Process::inner — holding our Process::inner first
    // inverts the documented Level 5 ordering with create_process().
    if memory_space != 0
        && !mm_sole_owner
        && crate::process::address_space_share_count(memory_space) > 1
    {
        return Err(SyscallError::EBUSY);
    }

    // R155-5 + R156-1 + R181-3 FIX: Hold Process lock across the ENTIRE
    // migration window (recount + exec/fork/grow gates + migrate_task + charge
    // transfer + cgroup_id update). Authoritative share recount uses the
    // non-blocking `try_address_space_share_count_holding` (never ABBA-inverting
    // Level-5 `PROCESS_TABLE -> Process::inner`), dropping `proc` and backing
    // off over a bounded retry budget on transient sibling/table `try_lock`
    // contention so concurrent parent `waitpid()`/`write()` calls do not cause
    // spurious `EAGAIN` failures.
    let mut proc = crate::process::lock_for_exclusive_address_space(&process, pid, memory_space)
        .map_err(|err| match err {
            crate::process::ExclusiveAddressSpaceError::Shared(_) => SyscallError::EBUSY,
            crate::process::ExclusiveAddressSpaceError::MemorySpaceChanged
            | crate::process::ExclusiveAddressSpaceError::Contended => SyscallError::EAGAIN,
        })?;

    // R171 M2-1 SLICE-1 FIX: refuse to re-home a task that is mid-`sys_exec`.
    // exec HARD-charges the new image to its snapshot cgroup inside load_elf with
    // the Process lock DROPPED; migrating the task in that window would snapshot
    // compute_cgroup_charged_bytes WITHOUT the in-flight charge and strand it on the
    // snapshot cgroup. Checked here UNDER the held Process lock, BEFORE migrate_task,
    // so the membership move and the exec charge are mutually exclusive. The exec
    // window is bounded and self-clears → EAGAIN (retry) is the correct response.
    if proc.exec_in_progress {
        return Err(SyscallError::EAGAIN);
    }

    // M0-7 item7 SLICE 4: refuse to re-home a task whose address space is mid
    // `try_grow_user_stack`. The grow HARD-charges the grow DATA to its snapshot cgroup
    // with the Process lock DROPPED for page-table work; migrating in that window would
    // snapshot compute_cgroup_charged_bytes and could strand the in-flight lane on the
    // snapshot cgroup. Checked here UNDER the held Process lock (briefly locking the
    // MmState, canonical Process -> MmState order), BEFORE migrate_task, so the
    // membership move and the grow are mutually exclusive. Bounded + self-clearing →
    // EAGAIN (retry). Mirrors the exec_in_progress / brk reservation gates.
    //
    // NOTE: the cgroupfs `cgroup.procs` migration front-door (vfs/cgroupfs.rs) does NOT
    // carry this gate — like brk (which gates NEITHER attach path), it relies on the
    // pending lane: compute_cgroup_charged_bytes sums stack_grow_pending_bytes and the
    // grow's rollback re-reads the current cgroup_id, so a migration there transfers the
    // in-flight charge rather than stranding it (Codex SLICE-4: accounting-safe, only the
    // transient-state POLICY is asymmetric; SLICE 5 may unify both front doors).
    let mm_txn = proc.mm.lock();
    if mm_txn.fork_in_progress || mm_txn.stack_grow_in_progress {
        return Err(SyscallError::EAGAIN);
    }
    drop(mm_txn);

    // R180-3: authoritative source under the held lock (may differ from preflight).
    let from_id = proc.cgroup_id;
    cgroup::authorize_cgroup_migrate(from_id, cgroup_id, host_euid, is_root, has_cap_admin)
        .map_err(|e| match e {
            cgroup::CgroupError::OutOfMemory => SyscallError::ENOMEM,
            cgroup::CgroupError::NotFound => SyscallError::ENOENT,
            cgroup::CgroupError::PermissionDenied => SyscallError::EPERM,
            _ => SyscallError::EPERM,
        })?;

    if from_id == cgroup_id {
        return Ok(0);
    }

    let total_charged_bytes = crate::process::compute_cgroup_charged_bytes(&proc);
    let fd_count = proc.total_fd_charge_count();

    // RF180-45: precharge every movable destination resource before publishing
    // membership. A failed precharge leaves the source intact; a failed
    // membership commit rolls back only saturating destination uncharges, so no
    // fallible reverse migration can split membership from resource accounting.
    // Installed FDs and R180-23 in-flight reservations move together under the
    // Process lock. Port charges remain anchored to their stored binding cgroup.
    if let Err(error) = cgroup::try_charge_fds(cgroup_id, fd_count) {
        return Err(match error {
            cgroup::CgroupError::NotFound => SyscallError::ENOENT,
            cgroup::CgroupError::OutOfMemory => SyscallError::ENOMEM,
            _ => SyscallError::EAGAIN,
        });
    }
    if let Err(error) = cgroup::try_charge_memory(cgroup_id, total_charged_bytes) {
        cgroup::uncharge_fds(cgroup_id, fd_count);
        return Err(match error {
            cgroup::CgroupError::NotFound => SyscallError::ENOENT,
            _ => SyscallError::ENOMEM,
        });
    }

    if let Err(error) = cgroup::migrate_task(pid as u64, from_id, cgroup_id) {
        cgroup::uncharge_memory(cgroup_id, total_charged_bytes);
        cgroup::uncharge_fds(cgroup_id, fd_count);
        return match error {
            cgroup::CgroupError::OutOfMemory => Err(SyscallError::ENOMEM),
            cgroup::CgroupError::NotFound => Err(SyscallError::ENOENT),
            cgroup::CgroupError::Busy => Err(SyscallError::EAGAIN),
            cgroup::CgroupError::PidsLimitExceeded => Err(SyscallError::EAGAIN),
            cgroup::CgroupError::TaskNotAttached => Err(SyscallError::EIO),
            _ => Err(SyscallError::EINVAL),
        };
    }

    // Membership is committed. Release the source copies only now, keeping all
    // precommit windows conservative (over-counted) rather than permissive.
    cgroup::uncharge_memory(from_id, total_charged_bytes);
    cgroup::uncharge_fds(from_id, fd_count);

    // R170-3 FIX: land any contention-deferred CPU-quota debt on the old cgroup
    // before re-pointing the PCB.
    let quota_debt = (proc.cpu_quota_debt_cgid, proc.cpu_quota_debt_ns);
    proc.cpu_quota_debt_ns = 0;
    cgroup::flush_cpu_quota_debt(
        quota_debt.0,
        quota_debt.1,
        crate::current_timestamp_ms().saturating_mul(1_000_000),
    );

    proc.set_cgroup_id(cgroup_id);
    drop(proc);
    let _ = audit::emit_cgroup_governance_event(
        get_audit_subject(),
        audit::AuditCgroupGovernanceOp::Attach,
        cgroup_id,
        from_id,
        cgroup_id,
        pid as u64,
        crate::time::get_ticks(),
    );
    Ok(0)
}

/// Limit types for sys_cgroup_set_limit
pub(super) const CGROUP_LIMIT_CPU_WEIGHT: u32 = 1;
pub(super) const CGROUP_LIMIT_CPU_MAX: u32 = 2;
pub(super) const CGROUP_LIMIT_MEMORY_MAX: u32 = 3;
pub(super) const CGROUP_LIMIT_MEMORY_HIGH: u32 = 4;
pub(super) const CGROUP_LIMIT_PIDS_MAX: u32 = 5;
pub(super) const CGROUP_LIMIT_IO_MAX_BPS: u32 = 6;
pub(super) const CGROUP_LIMIT_IO_MAX_IOPS: u32 = 7;
/// J2-7: per-cgroup open-FD count limit (`files.max`). value = max fds (u64::MAX = unlimited).
pub(super) const CGROUP_LIMIT_FILES_MAX: u32 = 8;
/// J2-8: per-cgroup ephemeral-port count limit (`ports.max`). value = max ports (u64::MAX = unlimited).
pub(super) const CGROUP_LIMIT_PORTS_MAX: u32 = 9;
/// J2-10: per-cgroup VFS dir-enumeration byte limit (`vfs_dir.max`). value = max bytes (u64::MAX = unlimited).
pub(super) const CGROUP_LIMIT_VFS_DIR_MAX: u32 = 10;

/// sys_cgroup_set_limit - Set a resource limit on a cgroup
///
/// # Arguments
/// * `cgroup_id` - ID of target cgroup
/// * `limit_type` - Type of limit (1=cpu_weight, 2=cpu_max, 3=memory_max, etc.)
/// * `value` - Limit value (interpretation depends on limit_type)
///
/// For cpu_max: value encodes (max_us << 32) | period_us
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno
///
/// # Security
///
/// R93-17 FIX: Proper capability-based access control.
///
/// Requires CAP_SYS_ADMIN capability to set limits.
pub(super) fn sys_cgroup_set_limit(
    cgroup_id: u64,
    limit_type: u32,
    value: u64,
    entry_proc: Option<&crate::process::ProcessArc>,
) -> Result<usize, SyscallError> {
    // R93-17 FIX: Capability-based access control for setting limits
    // P1-3: Delegated owners may set limits bounded by parent ceilings
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    // Single PCB snapshot reusing `entry_proc` avoids PROCESS_TABLE roundtrips
    // and redundant Credentials Vec clones on the cgroup control hot path.
    let auth =
        crate::process::current_cgroup_governance_auth_with_proc(cap::CapRights::ADMIN, entry_proc)
            .ok_or(SyscallError::ESRCH)?;
    let has_cap_admin = auth.has_cap_rights;
    let is_host_root = auth.is_host_root;

    let is_delegated = !has_cap_admin && !is_host_root && is_cgroup_delegated_to_caller(cgroup_id);
    if !has_cap_admin && !is_host_root && !is_delegated {
        return Err(SyscallError::EPERM);
    }

    let cgroup_node = cgroup::lookup_cgroup(cgroup_id).ok_or(SyscallError::ENOENT)?;
    let previous_limits = cgroup_node.limits();
    let old_value = match limit_type {
        CGROUP_LIMIT_CPU_WEIGHT => previous_limits.cpu_weight.map(u64::from).unwrap_or(0),
        CGROUP_LIMIT_CPU_MAX => previous_limits
            .cpu_max
            .map(|(max_us, period_us)| {
                (max_us.min(u32::MAX as u64) << 32) | period_us.min(u32::MAX as u64)
            })
            .unwrap_or(0),
        CGROUP_LIMIT_MEMORY_MAX => previous_limits.memory_max.unwrap_or(0),
        CGROUP_LIMIT_MEMORY_HIGH => previous_limits.memory_high.unwrap_or(0),
        CGROUP_LIMIT_PIDS_MAX => previous_limits.pids_max.unwrap_or(0),
        CGROUP_LIMIT_IO_MAX_BPS => previous_limits.io_max_bytes_per_sec.unwrap_or(0),
        CGROUP_LIMIT_IO_MAX_IOPS => previous_limits.io_max_iops_per_sec.unwrap_or(0),
        CGROUP_LIMIT_FILES_MAX => previous_limits.fds_max.unwrap_or(u64::MAX),
        CGROUP_LIMIT_PORTS_MAX => previous_limits.ports_max.unwrap_or(u64::MAX),
        CGROUP_LIMIT_VFS_DIR_MAX => previous_limits.vfs_dir_max.unwrap_or(u64::MAX),
        _ => return Err(SyscallError::EINVAL),
    };

    let mut limits = cgroup::CgroupLimits::default();

    match limit_type {
        CGROUP_LIMIT_CPU_WEIGHT => {
            // value is the weight (1-10000)
            if value == 0 || value > 10000 {
                return Err(SyscallError::EINVAL);
            }
            limits.cpu_weight = Some(value as u32);
        }
        CGROUP_LIMIT_CPU_MAX => {
            // value encodes (max_us << 32) | period_us
            let max_us = (value >> 32) as u64;
            let period_us = (value & 0xFFFFFFFF) as u64;
            if max_us == 0 || period_us == 0 {
                return Err(SyscallError::EINVAL);
            }
            limits.cpu_max = Some((max_us, period_us));
        }
        CGROUP_LIMIT_MEMORY_MAX => {
            limits.memory_max = Some(value);
        }
        CGROUP_LIMIT_MEMORY_HIGH => {
            limits.memory_high = Some(value);
        }
        CGROUP_LIMIT_PIDS_MAX => {
            limits.pids_max = Some(value);
        }
        CGROUP_LIMIT_IO_MAX_BPS => {
            // value is bytes per second limit (0 means unlimited)
            if value == 0 {
                return Err(SyscallError::EINVAL);
            }
            limits.io_max_bytes_per_sec = Some(value);
        }
        CGROUP_LIMIT_IO_MAX_IOPS => {
            // value is IOPS limit (0 means unlimited)
            if value == 0 {
                return Err(SyscallError::EINVAL);
            }
            limits.io_max_iops_per_sec = Some(value);
        }
        CGROUP_LIMIT_FILES_MAX => {
            // J2-7: per-cgroup open-FD budget (value = max fds; u64::MAX = unlimited).
            // 0 is a valid limit (no fds allowed), mirroring pids.max semantics.
            limits.fds_max = Some(value);
        }
        CGROUP_LIMIT_PORTS_MAX => {
            // J2-8: stored now; enforced when the NET-port charge wiring lands.
            limits.ports_max = Some(value);
        }
        CGROUP_LIMIT_VFS_DIR_MAX => {
            // J2-10: stored now; enforced when the VFS dir-budget wiring lands.
            limits.vfs_dir_max = Some(value);
        }
        _ => return Err(SyscallError::EINVAL),
    }

    // P1-3: Delegated (non-root, non-admin) users must satisfy hierarchical
    // boundary checks — they cannot set limits that exceed their ancestors'
    // effective limits, preventing privilege escalation via delegation.
    if is_delegated {
        if let Err(_) = cgroup_node.check_limit_boundary(&limits) {
            return Err(SyscallError::EPERM);
        }
    }

    match cgroup_node.set_limit(limits) {
        Ok(()) => {
            let _ = audit::emit_cgroup_governance_event(
                AuditSubject::new(auth.pid as u32, auth.ns_euid, auth.ns_egid, None),
                audit::AuditCgroupGovernanceOp::SetLimit,
                cgroup_id,
                old_value,
                value,
                limit_type as u64,
                crate::time::get_ticks(),
            );
            Ok(0)
        }
        Err(cgroup::CgroupError::ControllerDisabled) => Err(SyscallError::ENOENT),
        Err(cgroup::CgroupError::InvalidLimit) => Err(SyscallError::EINVAL),
        Err(_) => Err(SyscallError::EINVAL),
    }
}

/// sys_cgroup_get_stats - Get cgroup statistics
///
/// # Arguments
/// * `cgroup_id` - ID of target cgroup
/// * `buf` - Pointer to a userspace CgroupStatsBuf to fill
///
/// # Returns
/// * On success: 0 (writes exactly the frozen `CGROUP_STATS_V1_SIZE` v1 prefix)
/// * On error: Negative errno
///
/// J.2 ABI NOTE: syscall 504 is FROZEN at the v1 layout. It always writes
/// `CGROUP_STATS_V1_SIZE` bytes (the offset-stable v1 prefix) and returns 0,
/// regardless of how CgroupStatsBuf grows. The appended fields (fds/ports/vfs_dir
/// current + events) are read via the negotiated v2 entry point
/// `sys_cgroup_get_stats2` (syscall 516) — 504's ABI never changes.
pub(super) fn sys_cgroup_get_stats(
    cgroup_id: u64,
    buf: *mut CgroupStatsBuf,
    entry_proc: Option<&crate::process::ProcessArc>,
) -> Result<usize, SyscallError> {
    cgroup_stats_collect_and_copy(cgroup_id, buf, CGROUP_STATS_V1_SIZE, entry_proc)?;
    Ok(0)
}

/// sys_cgroup_get_stats2 - Get cgroup statistics with statx-style size negotiation.
///
/// # Arguments
/// * `cgroup_id` - ID of target cgroup
/// * `buf` - Pointer to a userspace CgroupStatsBuf to fill
/// * `buf_len` - Caller-declared size of `buf` in bytes. The kernel writes EXACTLY
///   `min(buf_len, size_of::<CgroupStatsBuf>())` bytes and NEVER past the declared
///   length. Appended fields are offset-stable, so a caller declaring a smaller
///   buffer receives the matching prefix; a larger buffer is filled up to sizeof.
///
/// # Returns
/// * On success: number of bytes written (== `min(buf_len, sizeof)`; 0 when buf_len==0)
/// * On error: Negative errno
pub(super) fn sys_cgroup_get_stats2(
    cgroup_id: u64,
    buf: *mut CgroupStatsBuf,
    buf_len: usize,
    entry_proc: Option<&crate::process::ProcessArc>,
) -> Result<usize, SyscallError> {
    let copy_len = buf_len.min(core::mem::size_of::<CgroupStatsBuf>());
    cgroup_stats_collect_and_copy(cgroup_id, buf, copy_len, entry_proc)?;
    Ok(copy_len)
}

/// J.2: Shared collector for the cgroup-stats syscalls (v1 504 + v2 516).
///
/// Validates the caller, builds the full CgroupStatsBuf, and writes EXACTLY
/// `copy_len` bytes — the offset-stable prefix — never more. `copy_len == 0` is a
/// valid no-op (writes nothing): it must NOT call `validate_user_ptr_mut`, which
/// rejects a zero-length range (defense against NULL/zero-size confusion).
pub(super) fn cgroup_stats_collect_and_copy(
    cgroup_id: u64,
    buf: *mut CgroupStatsBuf,
    copy_len: usize,
    entry_proc: Option<&crate::process::ProcessArc>,
) -> Result<(), SyscallError> {
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    // R162-13 FIX: full range check (start + size) — but only over the bytes we
    // will actually write. Skip for the zero-length no-op (validate rejects len 0).
    if copy_len > 0 {
        validate_user_ptr_mut(buf as *mut u8, copy_len)?;
    }

    // P1-3: Stats access should respect delegation boundaries.
    // R133-1 FIX: Use host-mapped root check for cgroup governance gate.
    let auth =
        crate::process::current_cgroup_governance_auth_with_proc(cap::CapRights::ADMIN, entry_proc)
            .ok_or(SyscallError::ESRCH)?;
    if !auth.is_host_root && !auth.has_cap_rights && !is_cgroup_delegated_to_caller(cgroup_id) {
        return Err(SyscallError::EPERM);
    }

    let cgroup_node = cgroup::lookup_cgroup(cgroup_id).ok_or(SyscallError::ENOENT)?;
    let stats = cgroup_node.get_stats();

    let result = CgroupStatsBuf {
        id: cgroup_node.id(),
        depth: cgroup_node.depth(),
        controllers: cgroup_node.controllers().bits(),
        nr_tasks: stats.pids_current,
        cpu_time_ns: stats.cpu_time_ns,
        memory_current: stats.memory_current,
        memory_events_high: stats.memory_events_high,
        memory_events_max: stats.memory_events_max,
        pids_events_max: stats.pids_events_max,
        _padding: 0,
        // F.2: IO controller statistics
        io_read_bytes: stats.io_read_bytes,
        io_write_bytes: stats.io_write_bytes,
        io_read_ios: stats.io_read_ios,
        io_write_ios: stats.io_write_ios,
        io_throttle_events: stats.io_throttle_events,
        // J.2 items 7/8/10: FD / ephemeral-port / VFS-dir accounting.
        fds_current: stats.fds_current,
        ports_current: stats.ports_current,
        vfs_dir_current: stats.vfs_dir_current,
        fds_events_max: stats.fds_events_max,
        ports_events_max: stats.ports_events_max,
    };

    // H.0.1-3: Copy via zeroed byte buffer so padding bytes are guaranteed zero.
    if copy_len > 0 {
        copy_cgroup_stats_to_user(buf, &result, copy_len)?;
    }
    Ok(())
}
