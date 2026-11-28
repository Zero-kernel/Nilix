//! Syscall family module: `ns` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

/// sys_unshare - Unshare namespaces for the current process
///
/// F.1 PID Namespace: When CLONE_NEWPID is specified, the calling process's
/// pid_ns_for_children is set to a new child namespace. The process itself
/// remains in its original namespace, but its future children will be created
/// in the new namespace.
///
/// # Arguments
///
/// * `flags` - Namespace flags to unshare (CLONE_NEWPID, etc.)
///
/// # Returns
///
/// 0 on success, -EINVAL for unsupported flags, -ENOMEM on allocation failure
///
/// # Linux Semantics
///
/// Unlike clone(), unshare() affects only the namespace for children, not the
/// caller's own namespace membership (for PID namespace).
pub(super) fn sys_unshare(flags: u64) -> SyscallResult {
    // F.1: Currently CLONE_NEWPID and CLONE_NEWNS are supported.
    let supported = CLONE_NEWPID | CLONE_NEWNS;
    let unsupported = flags & !supported;

    if unsupported != 0 {
        kprintln!(
            "[sys_unshare] Unsupported flags: 0x{:x} (supported: CLONE_NEWPID | CLONE_NEWNS)",
            unsupported
        );
        return Err(SyscallError::EINVAL);
    }

    if flags == 0 {
        // No flags specified - nothing to do
        return Ok(0);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // R165-17 FIX: Invoke the dedicated task-level LSM hook for namespace
    // creation. Previously sys_unshare had only DAC cap/root gates and no MAC
    // mediation point. Evaluate after flag validation, before any cap check or
    // namespace mutation; deny => EPERM. Build ctx from the locked proc and drop
    // the lock before calling the hook (Process-mutex re-entrancy, R131-1 pattern).
    {
        let ctx = {
            let proc = proc_arc.lock();
            lsm_process_ctx_from(&proc)?
        };
        if lsm::hook_task_unshare(&ctx, flags).is_err() {
            return Err(SyscallError::EPERM);
        }
    }

    // R180-22 PREPARE: both supported namespace types have the same host-admin
    // gate.  Authorize the full requested flag set before constructing either
    // namespace so a mixed request cannot commit one leg and fail the other.
    let has_cap_admin = current_has_cap_rights(cap::CapRights::ADMIN);
    let is_root = crate::current_is_host_root();
    if !is_root && !has_cap_admin {
        kprintln!("[sys_unshare] permission denied: requires CAP_SYS_ADMIN or host root");
        return Err(SyscallError::EPERM);
    }

    // Snapshot every source under one PCB lock.  These Arcs pin the exact
    // parents used by the prepare phase until the atomic publication below.
    let (tgid, current_pid_children_ns, current_mount_ns) = {
        let proc = proc_arc.lock();
        (
            proc.tgid,
            proc.pid_ns_for_children.clone(),
            proc.mount_ns.clone(),
        )
    };
    let publication_sources = crate::pid_namespace::PidPublicationSources::from_leaf(Arc::clone(
        &current_pid_children_ns,
    ))
    .ok_or(SyscallError::EAGAIN)?;

    // R74-3: validate the NEWNS thread-group contract before allocating either
    // requested namespace.  A mixed NEWPID|NEWNS failure is therefore a pure
    // prepare failure with no visible state change.
    if flags & CLONE_NEWNS != 0 {
        let thread_count = crate::thread_group_size(tgid);
        if thread_count > 1 {
            kprintln!(
                "[sys_unshare] CLONE_NEWNS denied: thread group has {} threads (must be 1)",
                thread_count
            );
            return Err(SyscallError::EINVAL);
        }
    }

    let prepared_pid_ns = if flags & CLONE_NEWPID != 0 {
        Some(
            crate::pid_namespace::PidNamespace::new_child(current_pid_children_ns.clone())
                .map_err(|e| {
                    klog!(
                        Error,
                        "[sys_unshare] Failed to prepare PID namespace: {:?}",
                        e
                    );
                    match e {
                        crate::pid_namespace::PidNamespaceError::MaxDepthExceeded
                        | crate::pid_namespace::PidNamespaceError::MaxNamespaces
                        | crate::pid_namespace::PidNamespaceError::NamespaceShuttingDown
                        | crate::pid_namespace::PidNamespaceError::NamespaceIdOverflow => {
                            SyscallError::EAGAIN
                        }
                        _ => SyscallError::ENOMEM,
                    }
                })?,
        )
    } else {
        None
    };

    let (prepared_mount_ns, mut prepared_mount_table_guard) = if flags & CLONE_NEWNS != 0 {
        let new_ns =
            crate::mount_namespace::clone_namespace(current_mount_ns.clone()).map_err(|e| {
                klog!(
                    Error,
                    "[sys_unshare] Failed to prepare mount namespace: {:?}",
                    e
                );
                match e {
                    crate::mount_namespace::MountNsError::MaxDepthExceeded
                    | crate::mount_namespace::MountNsError::MaxCountExceeded
                    | crate::mount_namespace::MountNsError::NamespaceShuttingDown => {
                        SyscallError::EAGAIN
                    }
                    _ => SyscallError::ENOMEM,
                }
            })?;

        // R74-2: materialization is part of PREPARE.  If either snapshot fails,
        // both local namespace Arcs are dropped and the process remains unchanged.
        materialize_namespace(&current_mount_ns).map_err(|_| SyscallError::ENOMEM)?;
        materialize_namespace(&new_ns).map_err(|_| SyscallError::ENOMEM)?;
        let guard = PreparedMountTableGuard {
            ns: Arc::clone(&new_ns),
            armed: true,
        };
        (Some(new_ns), Some(guard))
    } else {
        (None, None)
    };

    // RF180-16 COMMIT: PID lifecycle source -> PCB is the canonical lock order.
    // Process publication takes the same source lock(s) before PROCESS_TABLE and
    // the parent PCB; taking the PCB first here would deadlock against a sibling
    // creator publishing under this process. Revalidate both prepared sources
    // only after acquiring the PCB so a concurrent unshare cannot commit stale
    // snapshots. No allocation/materialization remains after the first assignment.
    let publish = || -> Result<(), SyscallError> {
        // RF180-15 FIX: namespace sources -> PROCESS_TABLE -> PCB. The held
        // table makes same-tgid recount and namespace publication indivisible
        // with CLONE_THREAD identity publication.
        let table = crate::process::PROCESS_TABLE.lock();
        let live_slot = table
            .get(pid)
            .and_then(Option::as_ref)
            .is_some_and(|entry| Arc::ptr_eq(entry, &proc_arc));
        if !live_slot {
            return Err(SyscallError::ESRCH);
        }
        if flags & CLONE_NEWNS != 0 {
            let mut thread_count = 0usize;
            for entry in table.iter().flatten() {
                if entry.lock().tgid == tgid {
                    thread_count = thread_count.saturating_add(1);
                    if thread_count > 1 {
                        return Err(SyscallError::EINVAL);
                    }
                }
            }
            if thread_count != 1 {
                return Err(SyscallError::ESRCH);
            }
        }
        let mut proc = proc_arc.lock();
        let pid_source_changed = prepared_pid_ns.is_some()
            && !Arc::ptr_eq(&proc.pid_ns_for_children, &current_pid_children_ns);
        let mount_source_changed =
            prepared_mount_ns.is_some() && !Arc::ptr_eq(&proc.mount_ns, &current_mount_ns);
        if proc.tgid != tgid || pid_source_changed || mount_source_changed {
            return Err(SyscallError::EAGAIN);
        }
        if let Some(ref new_ns) = prepared_pid_ns {
            proc.pid_ns_for_children = new_ns.clone();
        }
        if let Some(ref new_ns) = prepared_mount_ns {
            proc.mount_ns = new_ns.clone();
            proc.mount_ns_for_children = new_ns.clone();
        }
        Ok(())
    };

    publication_sources
        .with_live_publication(publish)
        .map_err(|_| SyscallError::EAGAIN)??;

    if let Some(guard) = prepared_mount_table_guard.as_mut() {
        guard.commit();
    }

    // Logging/audit are best-effort observations after an infallible commit;
    // they never change the syscall result or roll back one namespace leg.
    if let Some(new_ns) = prepared_pid_ns {
        klog!(
            Info,
            "[sys_unshare] Process {} unshared PID namespace, children will use ns_id={}, level={}",
            pid,
            new_ns.id().raw(),
            new_ns.level()
        );
        let parent_id = new_ns.parent().map(|p| p.id().raw()).unwrap_or(0);
        let _ = audit::emit(
            AuditKind::Process,
            AuditOutcome::Success,
            get_audit_subject(),
            AuditObject::Namespace {
                ns_id: new_ns.id().raw(),
                ns_type: CLONE_NEWPID as u32,
                parent_id,
            },
            &[272, flags, CLONE_NEWPID],
            0,
            crate::time::current_timestamp_ms(),
        );
    }

    if let Some(new_ns) = prepared_mount_ns {
        klog!(Info,
            "[sys_unshare] Process {} unshared mount namespace, now using ns_id={}, level={} (eagerly materialized)",
            pid,
            new_ns.id().raw(),
            new_ns.level()
        );
        let parent_id = new_ns.parent().map(|p| p.id().raw()).unwrap_or(0);
        let _ = audit::emit(
            AuditKind::Process,
            AuditOutcome::Success,
            get_audit_subject(),
            AuditObject::Namespace {
                ns_id: new_ns.id().raw(),
                ns_type: CLONE_NEWNS as u32,
                parent_id,
            },
            &[272, flags, CLONE_NEWNS],
            0,
            crate::time::current_timestamp_ms(),
        );
    }

    Ok(0)
}

/// sys_setns - Switch to an existing mount namespace.
///
/// Allows a process to join an existing mount namespace referenced by
/// a file descriptor. This is used by container runtimes to enter
/// namespaces created by other processes.
///
/// # Arguments
///
/// * `fd` - File descriptor referencing a MountNamespaceFd
/// * `nstype` - Namespace type (must be 0 or CLONE_NEWNS for mount ns)
///
/// # Returns
///
/// 0 on success, -EINVAL for invalid namespace type, -EPERM if not root,
/// -EBADF for invalid fd, -EINVAL if fd is not a mount namespace fd
///
/// # Security
///
/// Requires root (euid == 0) or CAP_SYS_ADMIN equivalent.
pub(super) fn sys_setns(fd: i32, nstype: i32) -> SyscallResult {
    // Validate namespace type
    if nstype != 0 && (nstype as u64) != CLONE_NEWNS {
        kprintln!("[sys_setns] Invalid nstype: {}", nstype);
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: Require CAP_SYS_ADMIN (CapRights::ADMIN) or root
    let has_cap_admin = current_has_cap_rights(cap::CapRights::ADMIN);
    // R83-2 FIX: Fail-closed - if euid cannot be determined, deny access
    // Previously used unwrap_or(true) which would grant root access on None
    // R135-3 FIX: Use host-mapped root check. Namespace root must NOT be
    // able to join arbitrary mount namespaces.
    let is_root = crate::current_is_host_root();
    if !is_root && !has_cap_admin {
        kprintln!("[sys_setns] Permission denied: requires CAP_SYS_ADMIN or root");
        return Err(SyscallError::EPERM);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Snapshot tgid and current mount namespace before validation/LSM work
    let (tgid, current_mount_ns, fs_context) = {
        let proc = proc_arc.lock();
        (proc.tgid, proc.mount_ns.clone(), proc.fs.state())
    };

    // R74-3: Early thread-count validation (non-authoritative, just fail-fast)
    // The authoritative recount happens under PROCESS_TABLE lock at publication
    let thread_count = crate::thread_group_size(tgid);
    if thread_count > 1 {
        kprintln!(
            "[sys_setns] CLONE_NEWNS denied: thread group has {} threads (must be 1)",
            thread_count
        );
        return Err(SyscallError::EINVAL);
    }

    // Extract target mount namespace from fd
    let target_ns = {
        let proc = proc_arc.lock();
        let fd_entry = proc.get_fd(fd).ok_or(SyscallError::EBADF)?;
        if let Some(ns_fd) = fd_entry
            .as_any()
            .downcast_ref::<crate::mount_namespace::MountNamespaceFd>()
        {
            ns_fd.namespace()
        } else {
            kprintln!("[sys_setns] fd {} is not a mount namespace fd", fd);
            return Err(SyscallError::EINVAL);
        }
    };

    // R165-17 FIX: Invoke the dedicated task-level LSM hook for joining a
    // namespace. Previously sys_setns had only DAC cap/root gates and no MAC
    // mediation point. Evaluate after the cap + thread-group checks and target
    // resolution, before the namespace switch; deny => EPERM. Build ctx from the
    // locked proc and drop the lock before the hook (R131-1 re-entrancy pattern).
    {
        let ctx = {
            let proc = proc_arc.lock();
            lsm_process_ctx_from(&proc)?
        };
        if lsm::hook_task_setns(&ctx, CLONE_NEWNS as u64, target_ns.id().raw()).is_err() {
            return Err(SyscallError::EPERM);
        }
    }

    let bindings = (crate::fs_context::callbacks()?.namespace_bindings)(
        &current_mount_ns,
        &target_ns,
        &fs_context,
    )?;
    let binding_permit = bindings.permit;
    // Keep ownership outside the registry closure on every rejected transaction.
    // The successful publication takes it only after the last fallible check.
    let mut prepared_fs = Some(bindings.state);

    // Get old namespace for audit (from snapshot, avoids re-locking)
    let old_ns_id = current_mount_ns.id().raw();

    // R186-9 FIX: make the authoritative recount and the namespace publication ONE
    // transaction, using the sanctioned fail-closed registry primitive.
    //
    // The bug: `thread_group_size` above is advisory. It releases every lock before
    // the switch, so a concurrent `CLONE_THREAD` can publish a sibling into
    // PROCESS_TABLE in the gap and the group ends up with a SPLIT mount namespace —
    // exactly the isolation invariant (INV-ISO-01) this check exists to preserve.
    //
    // Why `with_process_registry_txn` and not `PROCESS_TABLE.lock()`: taking the
    // table lock and then BLOCKING on each `Process::inner` inverts the Level-5
    // order that other paths acquire in the opposite direction (R181-3 / D2-ARC),
    // which is an ABBA deadlock, not merely a style issue. The transaction is
    // try-only throughout and fails CLOSED — any contention aborts having mutated
    // nothing, and the caller reports EAGAIN so userspace retries.
    //
    // Fail-closed direction matters here: a skipped sibling could BE the thread we
    // exist to detect, so an incomplete observation must never be treated as
    // "single-threaded".
    //
    // The recount reproduces `thread_group_size` semantics EXACTLY — same tgid,
    // excluding Zombie and Terminated. Counting dead siblings would reject a
    // legitimate single-threaded `setns` merely because an earlier thread had not
    // yet been reaped.
    //
    // AUTHORIZATION: the cap/root gate above ran before this transaction, and it is
    // sound to rely on that snapshot BECAUSE of what the transaction proves. Nothing
    // outside this thread group can mutate this process's credentials or capability
    // table, and the recount proves the group contains exactly one live thread — the
    // caller, which is executing this syscall and therefore not concurrently changing
    // its own credentials. There is consequently no actor able to invalidate the
    // authorization between the check and the publication.
    //
    // The displaced namespace Arcs are moved OUT and dropped only after the
    // transaction returns: a last-reference drop inside the closure would run
    // arbitrary destructor code (and possibly allocate) while PROCESS_TABLE is held.
    let publication = crate::process::with_process_registry_txn(|txn| {
        // Identity. The caller is executing this syscall and `proc_arc` is a held
        // strong reference, so its PCB cannot be freed nor its pid recycled while
        // this transaction runs — the slot necessarily still holds the PCB we
        // authorized. `contains` plus the tgid/namespace revalidation below are
        // belt-and-braces against a future path that could violate that.
        if !txn.contains(pid) {
            return Ok(Err(SyscallError::ESRCH));
        }

        let mut proc = txn.try_lock_process(pid)?;

        // Authoritative recount, indivisible with CLONE_THREAD publication.
        // `try_visit_all_except` skips the pid whose guard we hold, so the caller
        // is counted separately; it is live by contract (running this syscall).
        let mut live_threads = 1usize;
        txn.try_visit_all_except(None, |_pid, sibling| {
            if sibling.tgid == tgid
                && !matches!(
                    sibling.state,
                    crate::process::ProcessState::Zombie | crate::process::ProcessState::Terminated
                )
            {
                live_threads = live_threads.saturating_add(1);
            }
        })?;
        if live_threads > 1 {
            return Ok(Err(SyscallError::EINVAL));
        }

        // Revalidate the source: identity and the namespace we authorized against.
        if proc.tgid != tgid || !Arc::ptr_eq(&proc.mount_ns, &current_mount_ns) {
            return Ok(Err(SyscallError::EAGAIN));
        }
        // GAP-5 slice 2: a root/cwd handle shared with another task (CLONE_FS)
        // would carry this switch into it, so refuse like Linux (fs->users > 1).
        if Arc::strong_count(&proc.fs) > 1 {
            return Ok(Err(SyscallError::EINVAL));
        }
        // Revalidate and publish root/cwd in one handle critical section
        // (PCB -> handle leaf), before any other field is touched.
        let displaced_fs = match proc.fs.replace_if_matches(
            &fs_context,
            prepared_fs.take().expect("prepared setns filesystem state"),
        ) {
            Ok(displaced) => displaced,
            Err(rejected) => {
                prepared_fs = Some(rejected);
                return Ok(Err(SyscallError::EAGAIN));
            }
        };

        // Publication. Infallible: `Arc::clone` only bumps a refcount, and the
        // displaced Arcs are handed back so their Drop runs outside the table lock.
        let displaced_self = core::mem::replace(&mut proc.mount_ns, target_ns.clone());
        let displaced_children =
            core::mem::replace(&mut proc.mount_ns_for_children, target_ns.clone());
        Ok(Ok((displaced_self, displaced_children, displaced_fs)))
    });

    // Contention aborted the observation with nothing mutated.
    let displaced = match publication {
        Ok(Ok(displaced)) => displaced,
        Ok(Err(err)) => return Err(err),
        Err(_) => return Err(SyscallError::EAGAIN),
    };
    drop(binding_permit);
    // Old namespace references released outside every registry lock.
    drop(displaced);

    klog!(
        Info,
        "[sys_setns] Process {} switched to mount namespace id={}, level={}",
        pid,
        target_ns.id().raw(),
        target_ns.level()
    );

    // F.1 Audit: Emit namespace switch event
    let parent_id = target_ns.parent().map(|p| p.id().raw()).unwrap_or(0);
    let _ = audit::emit(
        AuditKind::Process,
        AuditOutcome::Success,
        get_audit_subject(),
        AuditObject::Namespace {
            ns_id: target_ns.id().raw(),
            ns_type: CLONE_NEWNS as u32,
            parent_id,
        },
        &[308, fd as u64, old_ns_id], // syscall 308 = setns, fd, old_ns_id
        0,
        crate::time::current_timestamp_ms(),
    );

    Ok(0)
}

/// D3 NETNS-DATAPLANE-CONFIG: Move a network device between namespaces.
///
/// **HARD-GATED ENOSYS (2026-07-25, Codex round-2 finding):** the body below
/// is INCOMPLETE and is now explicitly disabled at the top of the function
/// rather than "unreachable by convention". Previously the only barrier was
/// that no `NetNamespaceFd` construction path exists (fd resolution always
/// fails EBADF) — but that is a property of TODAY's tree; the first commit
/// that constructs a `NetNamespaceFd` (e.g. wiring /proc/[pid]/ns/net) would
/// have silently armed this path with its known gaps. The explicit gate makes
/// un-arming a deliberate act tied to closing the blockers:
/// 1. No NetNamespaceFd construction path exists (fd resolution always fails EBADF)
/// 2. Root namespace device set is never seeded (can't move devices OUT of root)
/// 3. move_device() checks global CAP_ADMIN once, not per-namespace CAP_NET_ADMIN
/// 4. TX authorization revocation protocol not implemented (ownership generation deferred)
/// 5. Namespace Drop doesn't re-home devices (orphaning risk)
///
/// See D3 NETNS-DATAPLANE-CONFIG in plan v15.41 for full Phase I.3 requirements.
/// Adversarial review findings: 1 UNSAFE + 4 INCOMPLETE (2026-07-25).
///
/// Reassigns ownership of a network device from the current process's network
/// namespace to a target namespace identified by a file descriptor.
///
/// # Arguments
///
/// * `device_idx` - Network device index (from ifconfig or ip link)
/// * `target_netns_fd` - File descriptor referencing the target NetNamespace
///
/// # Returns
///
/// ENOSYS unconditionally until the Phase I.3 blockers above are closed.
/// Design-target errno contract once armed:
/// - EBADF: `target_netns_fd` is invalid or not a network namespace fd
/// - EPERM: Missing CAP_NET_ADMIN in source or target namespace
/// - ENODEV: Device not found or not owned by current namespace
/// - EINVAL: Source and target namespaces are the same
/// - EBUSY: Device is in use and cannot be moved
///
/// # Security
///
/// DOCUMENTED (not yet enforced): Requires CAP_NET_ADMIN in BOTH source and target namespaces.
/// ACTUAL: Checks global CAP_ADMIN once via move_device() (isolation gap).
/// LSM policies may impose additional restrictions.
///
/// # Safety
///
/// The device ownership transfer has a bounded in-flight window: one transmit
/// call may reach the driver queue after the move completes. Strong drain
/// semantics are not implemented (would require per-device ownership
/// generation synchronized with driver enqueue).
pub(super) fn sys_move_net_device(device_idx: u32, target_netns_fd: i32) -> SyscallResult {
    // D3 NETNS-DATAPLANE-CONFIG hard gate: the implementation below has a
    // known per-ns capability-model gap (blocker 3) and no revocation
    // protocol (blocker 4). Fail-closed with ENOSYS until Phase I.3 closes
    // them. Arming this syscall = flipping the const AFTER closing blockers
    // 2-5 above — a deliberate, reviewable act, not a side effect of adding
    // the first NetNamespaceFd constructor.
    const MOVE_NET_DEVICE_ARMED: bool = false;
    if !MOVE_NET_DEVICE_ARMED {
        return Err(SyscallError::ENOSYS);
    }

    // Get current process and validate single-threaded
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Network namespace operations require single-threaded process
    // (same constraint as setns - prevents thread-local divergence)
    let tgid = {
        let proc = proc_arc.lock();
        proc.tgid
    };
    let thread_count = crate::thread_group_size(tgid);
    if thread_count > 1 {
        kprintln!(
            "[sys_move_net_device] Denied: thread group has {} threads (must be 1)",
            thread_count
        );
        return Err(SyscallError::EINVAL);
    }

    // Get current (source) network namespace
    let source_ns = {
        let proc = proc_arc.lock();
        proc.net_ns.clone()
    };

    // Resolve target namespace from fd
    let target_ns = {
        let proc = proc_arc.lock();
        let fd_entry = proc.get_fd(target_netns_fd).ok_or(SyscallError::EBADF)?;
        if let Some(ns_fd) = fd_entry
            .as_any()
            .downcast_ref::<crate::net_namespace::NetNamespaceFd>()
        {
            ns_fd.namespace()
        } else {
            kprintln!(
                "[sys_move_net_device] fd {} is not a network namespace fd",
                target_netns_fd
            );
            return Err(SyscallError::EBADF);
        }
    };

    // Reject no-op moves
    if source_ns.id() == target_ns.id() {
        kprintln!(
            "[sys_move_net_device] Source and target are the same namespace (id={})",
            source_ns.id().raw()
        );
        return Err(SyscallError::EINVAL);
    }

    // LSM hook: gate device reassignment (after validation, before mutation)
    {
        let ctx = {
            let proc = proc_arc.lock();
            lsm_process_ctx_from(&proc)?
        };
        if lsm::hook_net_device_move(&ctx, device_idx, source_ns.id().raw(), target_ns.id().raw())
            .is_err()
        {
            kprintln!(
                "[sys_move_net_device] LSM denied device {} move from ns {} to ns {}",
                device_idx,
                source_ns.id().raw(),
                target_ns.id().raw()
            );
            return Err(SyscallError::EPERM);
        }
    }

    klog!(
        Info,
        "[sys_move_net_device] Process {} moving device {} from ns {} (level {}) to ns {} (level {})",
        pid,
        device_idx,
        source_ns.id().raw(),
        source_ns.level(),
        target_ns.id().raw(),
        target_ns.level()
    );

    // Perform the device move (checks CAP_NET_ADMIN internally)
    crate::net_namespace::move_device(device_idx, &source_ns, &target_ns).map_err(|e| {
        kprintln!("[sys_move_net_device] move_device failed: {:?}", e);
        match e {
            crate::net_namespace::NetNsError::DeviceNotFound => SyscallError::ENXIO,
            crate::net_namespace::NetNsError::DeviceExists => SyscallError::EBUSY,
            crate::net_namespace::NetNsError::PermissionDenied => SyscallError::EPERM,
            _ => SyscallError::EINVAL,
        }
    })?;

    // Audit: Device reassignment (security-relevant boundary change)
    let _ = audit::emit(
        AuditKind::Network,
        AuditOutcome::Success,
        get_audit_subject(),
        AuditObject::None,
        &[
            518,
            device_idx as u64,
            source_ns.id().raw(),
            target_ns.id().raw(),
        ],
        0,
        crate::time::current_timestamp_ms(),
    );

    Ok(0)
}
