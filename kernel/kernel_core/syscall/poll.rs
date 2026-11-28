//! Syscall family module: `poll` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// M0-6 poll/select: poll(7) / select(23) / pselect6(270) / ppoll(271)
//
// Level-triggered readiness SCAN + a bounded tick-granularity wait loop (the
// proven sys_nanosleep shape). No wake-infrastructure changes: latency is
// ~1ms-tick granularity (an efficiency cost only — Safety > Efficiency > Speed).
// The pure ABI/codec/timeout math lives in crate::poll; the stateful machinery
// (classify under the Process lock, probe without it, wait, ABI handlers) is
// here where the Process lock and per-kind probes are reachable.
//
// Design + 7-lens adversarial verify: docs/next-phase-plan.md (M0-6 poll/select).
// ============================================================================

/// Per-fd classification, produced under the Process lock (I1) and probed
/// WITHOUT it. `Socket` carries ONLY Copy ids — NEVER an `Arc<SocketState>`: its
/// `Drop` runs per-namespace uncharge, so parking one here would let that Drop
/// fire under the Process lock and would break the re-resolution-per-tick
/// lifetime rule (see the TEARDOWN/LIFETIME lens + lock_ordering strong-owner
/// enumeration). Re-resolution per tick is therefore mandatory, not a staleness
/// choice.
pub(super) enum FdKind {
    ConsoleDevice {
        readable: bool,
        writable: bool,
    },
    /// fd 0 — stdin (keyboard). Readiness = non-consuming keyboard byte count.
    Stdin,
    /// fd 1/2 — console. Always writable (matches sys_write routing).
    ConsoleOut,
    /// A cross-crate probe (pipe). `write_end` selects which end's status.
    Dyn {
        probe: crate::poll::OwnedPollProbe,
        write_end: bool,
    },
    /// A live socket fd (cap validated, ns snapshotted under the Process lock).
    Socket {
        socket_id: u64,
        caller_ns_id: cap::NamespaceId,
    },
    /// A socket fd whose capability no longer validates → report IN|ERR|HUP.
    SocketStale,
    /// Linux DEFAULT_POLLMASK (regular files, ns fds, unknown): always ready.
    AlwaysReady,
    /// No fd_table entry → POLLNVAL (poll) / whole-call EBADF (select).
    Nval,
    /// fd < 0 → skipped (revents 0, never counted).
    Skip,
}

/// One polled fd + its resolved readiness for the current scan tick.
pub(super) struct PollEntry {
    fd: i32,
    events: i16,
    revents: i16,
    kind: FdKind,
}

pub(super) fn poll_classify(p: &crate::process::Process, fd: i32) -> FdKind {
    if fd < 0 {
        return FdKind::Skip;
    }
    if let Some(console) = p.get_fd(fd).and_then(|ops| {
        ops.as_any()
            .downcast_ref::<crate::process::ConsoleFile>()
            .copied()
    }) {
        return if console.readable {
            FdKind::Stdin
        } else {
            FdKind::ConsoleOut
        };
    }
    match p.get_fd(fd) {
        None => FdKind::Nval,
        Some(ops) => match ops.poll_arm() {
            crate::poll::PollArm::Console { readable, writable } => {
                FdKind::ConsoleDevice { readable, writable }
            }
            crate::poll::PollArm::AlwaysReady => FdKind::AlwaysReady,
            crate::poll::PollArm::Dyn { probe, write_end } => FdKind::Dyn { probe, write_end },
            crate::poll::PollArm::Socket { cap_id, socket_id } => {
                // Validate the capability references this socket AND snapshot the
                // caller's net-ns id, all under this ONE Process lock — the probe
                // pass must never re-take the Process lock per socket fd (that
                // amplification defeats the IRQ try-lock-defer, R171-G5-1).
                match p.capability_lookup(cap_id) {
                    Ok(entry) => match &entry.object {
                        cap::CapObject::Socket(ref h) if h.socket_id == socket_id => {
                            FdKind::Socket {
                                socket_id,
                                caller_ns_id: p.net_ns.id(),
                            }
                        }
                        _ => FdKind::SocketStale,
                    },
                    Err(_) => FdKind::SocketStale,
                }
            }
        },
    }
}

/// Re-snapshot every entry's kind for one scan tick. Step 1 (NO LOCK) resets all
/// kinds to `Nval`, dropping any stale `Arc` probes lock-free. INVARIANT (I3):
/// this drop MUST complete before `get_process`/`proc.lock()` — do NOT merge into
/// the locked fill. It is safe today only because `Pipe` has NO `Drop` impl (a
/// last-`Arc<Pipe>` drop is a pure heap free); if `Pipe` ever gains a `Drop`,
/// revisit this site or a free could run under the Process lock.
pub(super) fn poll_snapshot_kinds(
    pid: ProcessId,
    entries: &mut [PollEntry],
) -> Result<(), SyscallError> {
    for e in entries.iter_mut() {
        e.kind = FdKind::Nval;
    }
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let p = proc_arc.lock();
    for e in entries.iter_mut() {
        e.kind = poll_classify(&p, e.fd);
    }
    Ok(())
}

/// Map a socket's readiness snapshot to pre-mask revents bits.
pub(super) fn sock_readiness_to_bits(r: net::SockPollReadiness) -> i16 {
    crate::poll::status_to_bits(&crate::poll::PollStatus {
        readable: r.readable,
        writable: r.writable,
        hup: r.hup,
        err: r.err,
        rdhup: r.rdhup,
    })
}

/// Compute pre-mask revents for one fd. Holds NO Process lock; at most ONE leaf
/// lock at any instant. For `Socket`, the `Arc<SocketState>` obtained here dies at
/// this call's scope end with no lock held (I2) — `SocketState::drop` runs per-ns
/// uncharge if this was the last ref, which is safe only because it takes leaf
/// locks and we hold none. Interest-masking is applied by the caller (poll_scan
/// via `mask_revents`), so this returns the full computed bits.
pub(super) fn poll_probe(kind: &FdKind) -> i16 {
    use crate::poll::*;
    match kind {
        FdKind::ConsoleDevice { readable, writable } => {
            let output = if *writable { POLLOUT | POLLWRNORM } else { 0 };
            output
                | if *readable {
                    poll_probe(&FdKind::Stdin)
                } else {
                    0
                }
        }
        FdKind::Stdin => {
            if !crate::process::console_input_allowed() {
                POLLERR
            } else if drivers::keyboard_available() > 0 {
                POLLIN | POLLRDNORM
            } else {
                0
            }
        }
        FdKind::ConsoleOut => POLLOUT | POLLWRNORM,
        FdKind::Dyn { probe, write_end } => {
            let st = if *write_end {
                probe.poll_status_write()
            } else {
                probe.poll_status_read()
            };
            status_to_bits(&st)
        }
        FdKind::Socket {
            socket_id,
            caller_ns_id,
        } => match net::socket_table().get(*socket_id) {
            // Gone (closed/recycled): report IN|ERR|HUP so the op fails fast.
            None => POLLIN | POLLERR | POLLHUP,
            Some(s) => {
                if s.net_ns_id != *caller_ns_id {
                    // ns mismatch (a sibling entered a new net ns): fail fast.
                    POLLIN | POLLERR | POLLHUP
                } else {
                    sock_readiness_to_bits(s.poll_readiness())
                }
            }
        },
        FdKind::SocketStale => POLLIN | POLLERR | POLLHUP,
        FdKind::AlwaysReady => POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM,
        FdKind::Nval => POLLNVAL,
        FdKind::Skip => 0,
    }
}

/// One readiness scan: re-snapshot kinds, probe each, mask against interest.
/// Returns the count of fds with non-zero revents.
pub(super) fn poll_scan(pid: ProcessId, entries: &mut [PollEntry]) -> Result<usize, SyscallError> {
    poll_snapshot_kinds(pid, entries)?;
    let mut n = 0usize;
    for e in entries.iter_mut() {
        let computed = poll_probe(&e.kind);
        e.revents = crate::poll::mask_revents(e.events, computed);
        if e.revents != 0 {
            n += 1;
        }
    }
    Ok(n)
}

/// The shared wait loop: scan, and if nothing is ready and the timeout has not
/// expired, drain deferred work + `hlt` to the next tick and re-scan. Linux
/// ordering: the EINTR gate fires BEFORE timeout expiry (a signal wins over a
/// just-expired timeout). `select_mode` maps a POLLNVAL (bad fd) to a whole-call
/// EBADF.
pub(super) fn poll_wait_loop(
    pid: ProcessId,
    entries: &mut [PollEntry],
    timeout_ms: Option<u64>,
    select_mode: bool,
) -> Result<usize, SyscallError> {
    let start = crate::time::get_ticks();
    loop {
        let n = poll_scan(pid, entries)?;
        if select_mode
            && entries
                .iter()
                .any(|e| e.revents & crate::poll::POLLNVAL != 0)
        {
            return Err(SyscallError::EBADF);
        }
        if n > 0 {
            return Ok(n);
        }
        // EINTR gate BEFORE the expiry check (Linux order): honor a pending kill
        // or a deliverable handler signal each tick — the handler delivers at the
        // syscall-return tail (ppoll/pselect6 leave the temp mask live for it).
        if wait_should_abort(pid) || crate::signal::has_deliverable_signal(pid) {
            return Err(SyscallError::EINTR);
        }
        match timeout_ms {
            Some(0) => return Ok(0),
            Some(t) if crate::time::get_ticks().saturating_sub(start) >= t => return Ok(0),
            _ => {}
        }
        // FULL blocking deferred-work drain (re-acquires sock.tcp/tcp_conns via
        // run_tcp_timers_blocking) + hlt. ZERO kernel locks may be held here
        // (R169-5); poll_scan returns all its guards before this point. Wake source
        // = the periodic 1kHz tick (PIT on the BSP, per-AP periodic LAPIC) — any
        // move to tickless/one-shot timers must first give poll/nanosleep a real
        // wake source, exactly like sys_nanosleep.
        crate::reschedule_if_needed();
        debug_assert!(
            x86_64::instructions::interrupts::are_enabled(),
            "poll wait loop must hlt with IRQs enabled"
        );
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Copy in `nfds` pollfd structs and build the entry vec (fallible). Validates +
/// preflights the array WRITABLE (revents are written back even on timeout/EINTR)
/// so a faulting buffer surfaces before the wait, and clears any garbage the
/// caller preset in `revents`.
pub(super) fn poll_copyin_pollfds(
    fds: u64,
    nfds: usize,
    bytes: usize,
) -> Result<AdmittedVec<PollEntry>, SyscallError> {
    // Both the retained PollEntry vector and the temporary wire-image vector
    // participate in the same aggregate class. The entry owner is returned and
    // remains charged through wait cancellation and final copyout.
    let mut entries = try_admitted_vec(mm::HeapClass::BlockingIo, nfds)?;
    if nfds == 0 {
        return Ok(entries);
    }
    validate_user_ptr(fds as *const u8, bytes)?;
    verify_user_memory(fds as *const u8, bytes, true)?;
    let mut pfds = try_admitted_vec::<crate::poll::PollFd>(mm::HeapClass::BlockingIo, nfds)?;
    pfds.resize(nfds, crate::poll::PollFd::default());
    // lint-repr-c-copy: allow (PollFd[] {i32,i16,i16} = 8 bytes, no padding; user→kernel)
    let dst = unsafe { core::slice::from_raw_parts_mut(pfds.as_mut_ptr() as *mut u8, bytes) };
    copy_from_user(dst, fds as *const u8)?;
    for pf in pfds.iter() {
        entries.push(PollEntry {
            fd: pf.fd,
            events: pf.events,
            revents: 0,
            kind: FdKind::Skip,
        });
    }
    Ok(entries)
}

/// Write each entry's `revents` back to the user pollfd array (Linux writes ONLY
/// the 2-byte revents field, never fd/events which a sibling thread may re-arm).
pub(super) fn poll_writeback_revents(fds: u64, entries: &[PollEntry]) -> Result<(), SyscallError> {
    for (i, e) in entries.iter().enumerate() {
        let dst = (fds as usize + i * 8 + 6) as *mut u8;
        // lint-repr-c-copy: allow (2-byte pollfd.revents write; kernel→user)
        copy_to_user(dst, &e.revents.to_ne_bytes())?;
    }
    Ok(())
}

/// Dispatcher-tail sigmask restore for ppoll/pselect6 (TIF_RESTORE_SIGMASK
/// analog). Covers every no-delivery path: when the temp mask was left live for a
/// signal that `maybe_deliver_signal` then did NOT deliver (in_signal_handler,
/// Ignored/Default disposition race, stale-frame defer), the original mask stashed
/// in `poll_restore_blocked` is restored here, including a pending default
/// signal in a process that has never installed a handler.
pub(super) fn poll_restore_sigmask_tail(pid: ProcessId) {
    if let Some(proc_arc) = get_process(pid) {
        let mut p = proc_arc.lock();
        if let Some(old) = p.poll_restore_blocked.take() {
            p.blocked = old & !crate::signal::uncatchable_mask();
        }
    }
}

/// poll timeout arg (ms, i32): negative = infinite, 0 = return immediately.
#[inline]
pub(super) fn poll_timeout_from_ms_arg(timeout: i32) -> Option<u64> {
    if timeout < 0 {
        None
    } else {
        Some(timeout as u64)
    }
}

/// Copy in a `struct timespec { i64 tv_sec; i64 tv_nsec }` from user (16 bytes).
pub(super) fn poll_copyin_timespec(ptr: *const u8) -> Result<(i64, i64), SyscallError> {
    let mut b = [0u8; 16];
    // lint-repr-c-copy: allow (timespec {i64,i64} = 16 bytes, no padding; user→kernel)
    copy_from_user(&mut b, ptr)?;
    let sec = i64::from_ne_bytes(b[0..8].try_into().unwrap());
    let nsec = i64::from_ne_bytes(b[8..16].try_into().unwrap());
    Ok((sec, nsec))
}

/// Copy in a `struct timeval { i64 tv_sec; i64 tv_usec }` from user (16 bytes).
pub(super) fn poll_copyin_timeval(ptr: *const u8) -> Result<(i64, i64), SyscallError> {
    let mut b = [0u8; 16];
    // lint-repr-c-copy: allow (timeval {i64,i64} = 16 bytes, no padding; user→kernel)
    copy_from_user(&mut b, ptr)?;
    let sec = i64::from_ne_bytes(b[0..8].try_into().unwrap());
    let usec = i64::from_ne_bytes(b[8..16].try_into().unwrap());
    Ok((sec, usec))
}

/// Write a `struct timespec` back to user (remaining-time write-back). Fault is
/// ignored by the caller (raw-Linux ppoll semantics).
pub(super) fn poll_writeback_timespec(
    ptr: *mut u8,
    sec: i64,
    nsec: i64,
) -> Result<(), SyscallError> {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&sec.to_ne_bytes());
    b[8..16].copy_from_slice(&nsec.to_ne_bytes());
    // lint-repr-c-copy: allow (timespec {i64,i64} = 16 bytes, no padding; kernel→user)
    copy_to_user(ptr, &b)
}

/// M0-6 poll/select: regression guard for the SocketFile poll classification.
///
/// A missing `SocketFile::poll_arm` override silently falls through to the FileOps
/// default (`AlwaysReady`), making every socket fd report spurious POLLIN/POLLOUT
/// and turning `SocketState::poll_readiness` into dead code — a bug a green boot
/// (which polls only stdin/pipe fds) cannot catch. This asserts the override is
/// present and carries the socket id, structurally, with no socket table needed.
pub fn run_poll_socket_arm_self_test() {
    use crate::process::FileOps;
    let sf = SocketFile::new(cap::CapId::INVALID, 0xC0FFEE);
    match sf.poll_arm() {
        crate::poll::PollArm::Socket { socket_id, .. } => {
            assert_eq!(
                socket_id, 0xC0FFEE,
                "SocketFile::poll_arm must carry its socket_id"
            );
        }
        _ => panic!(
            "SocketFile must classify as PollArm::Socket — a missing poll_arm override \
             falls through to AlwaysReady and reports spurious readiness every tick"
        ),
    }
}

/// Write a `struct timeval` back to user (remaining-time write-back).
pub(super) fn poll_writeback_timeval(
    ptr: *mut u8,
    sec: i64,
    usec: i64,
) -> Result<(), SyscallError> {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&sec.to_ne_bytes());
    b[8..16].copy_from_slice(&usec.to_ne_bytes());
    // lint-repr-c-copy: allow (timeval {i64,i64} = 16 bytes, no padding; kernel→user)
    copy_to_user(ptr, &b)
}

/// poll(2) — wait for events on a set of file descriptors.
pub(super) fn sys_poll(fds: u64, nfds: u64, timeout: u64) -> Result<usize, SyscallError> {
    // I5: bound the RAW nfds before any cast / alloc / user-memory validation.
    if nfds > crate::poll::POLL_MAX_NFDS as u64 {
        return Err(SyscallError::EINVAL);
    }
    let nfds = nfds as usize;
    if nfds > 0 && fds == 0 {
        return Err(SyscallError::EFAULT);
    }
    let timeout_ms = poll_timeout_from_ms_arg(timeout as i32);
    let bytes = nfds.checked_mul(8).ok_or(SyscallError::EINVAL)?;

    let mut entries = poll_copyin_pollfds(fds, nfds, bytes)?;
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let r = poll_wait_loop(pid, &mut entries, timeout_ms, false);
    match r {
        Ok(n) => {
            poll_writeback_revents(fds, &entries)?;
            Ok(n)
        }
        Err(SyscallError::EINTR) => {
            // Linux writes the (all-zero) revents back on EINTR.
            poll_writeback_revents(fds, &entries)?;
            Err(SyscallError::EINTR)
        }
        Err(e) => Err(e),
    }
}

/// ppoll(2) — poll with a temporary signal mask + timespec timeout.
pub(super) fn sys_ppoll(
    fds: u64,
    nfds: u64,
    tmo: *mut u8,
    sigmask: u64,
    sigsetsize: u64,
) -> Result<usize, SyscallError> {
    if nfds > crate::poll::POLL_MAX_NFDS as u64 {
        return Err(SyscallError::EINVAL);
    }
    let nfds = nfds as usize;
    if nfds > 0 && fds == 0 {
        return Err(SyscallError::EFAULT);
    }
    let bytes = nfds.checked_mul(8).ok_or(SyscallError::EINVAL)?;

    // All fallible copy-ins BEFORE the mask swap (I6): EINVAL/EFAULT/ENOMEM on
    // arguments never need a restore.
    let timeout_ms = if tmo.is_null() {
        None
    } else {
        let (sec, nsec) = poll_copyin_timespec(tmo as *const u8)?;
        crate::poll::timespec_to_ms(sec, nsec).map_err(|_| SyscallError::EINVAL)?
    };
    let new_mask: Option<u64> = if sigmask != 0 {
        if sigsetsize as usize != LINUX_KERNEL_SIGSET_SIZE {
            return Err(SyscallError::EINVAL);
        }
        let mut b = [0u8; LINUX_KERNEL_SIGSET_SIZE];
        copy_from_user(&mut b, sigmask as *const u8)?;
        Some(u64::from_ne_bytes(b))
    } else {
        None
    };
    let mut entries = poll_copyin_pollfds(fds, nfds, bytes)?;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Mask swap = the LAST op before the wait; hold this Arc across the wait
    // (never re-lookup by pid — a None lookup would silently skip the restore).
    let old_mask: Option<u64> = new_mask.map(|m| {
        let (old, retarget) = {
            let mut p = proc_arc.lock();
            let old = p.blocked;
            p.blocked = crate::signal::apply_sigprocmask(old, SIG_SETMASK, m);
            // GAP-5 G7 (review D2): a group signal the temporary mask lets
            // through ends the wait at once, as Linux set_user_sigmask does.
            let retarget = p
                .recalc_shared_signals(true)
                .then(|| Arc::clone(&p.thread_group));
            (old, retarget)
        };
        if let Some(group) = retarget {
            crate::process::retarget_shared_signals(pid, &group);
        }
        old
    });

    let start = crate::time::get_ticks();
    let r = poll_wait_loop(pid, &mut entries, timeout_ms, false);

    // Restore-or-stash the original mask, BEFORE any write-back. Deliverability is
    // computed FROM the already-held guard `p` (has_deliverable_signal_locked) —
    // calling the pid-keyed has_deliverable_signal here would re-lock this same
    // non-reentrant Process mutex on the same CPU and self-deadlock.
    if let Some(old) = old_mask {
        let mut p = proc_arc.lock();
        if matches!(r, Err(SyscallError::EINTR)) && crate::signal::has_deliverable_signal_locked(&p)
        {
            // TIF_RESTORE_SIGMASK: leave the temp mask live so the just-woken
            // signal delivers under it at the dispatcher tail; stash the original
            // for maybe_deliver_signal / poll_restore_sigmask_tail to restore.
            p.poll_restore_blocked = Some(old);
        } else {
            p.blocked = old;
        }
    }

    // Remaining-time write-back on EVERY return path (raw-Linux ppoll; ignore fault).
    if !tmo.is_null() {
        if let Some(total) = timeout_ms {
            let elapsed = crate::time::get_ticks().saturating_sub(start);
            let (sec, nsec) = crate::poll::ms_to_timespec(total.saturating_sub(elapsed));
            let _ = poll_writeback_timespec(tmo, sec, nsec);
        }
    }

    match r {
        Ok(n) => {
            poll_writeback_revents(fds, &entries)?;
            Ok(n)
        }
        Err(SyscallError::EINTR) => {
            poll_writeback_revents(fds, &entries)?;
            Err(SyscallError::EINTR)
        }
        Err(e) => Err(e),
    }
}

/// N2.1: number of `u64` words required to hold `MAX_FD` select fd_set bits
/// (16 words = 1024 bits = Linux `FD_SETSIZE`).
const SELECT_FD_SET_WORDS: usize = (crate::process::MAX_FD as usize + 63) / 64;

/// Copy in the three select fd_sets into fixed `[u64; SELECT_FD_SET_WORDS]`
/// buffers (nb ≤ MAX_FD ⇒ words ≤ SELECT_FD_SET_WORDS), trimming stale bits ≥ nb.
/// Preflights each non-NULL set WRITABLE (they are written back). Returns
/// `(words, rset, wset, eset, has_r, has_w, has_e)`.
#[allow(clippy::type_complexity)]
pub(super) fn select_copyin_sets(
    readfds: *mut u8,
    writefds: *mut u8,
    exceptfds: *mut u8,
    nb: usize,
) -> Result<
    (
        usize,
        [u64; SELECT_FD_SET_WORDS],
        [u64; SELECT_FD_SET_WORDS],
        [u64; SELECT_FD_SET_WORDS],
        bool,
        bool,
        bool,
    ),
    SyscallError,
> {
    let words = crate::poll::fd_set_words(nb);
    let mut rset = [0u64; SELECT_FD_SET_WORDS];
    let mut wset = [0u64; SELECT_FD_SET_WORDS];
    let mut eset = [0u64; SELECT_FD_SET_WORDS];
    let bytes = words * 8;
    let mut copy_one = |ptr: *mut u8, dst: &mut [u64]| -> Result<bool, SyscallError> {
        if ptr.is_null() {
            return Ok(false);
        }
        if words == 0 {
            return Ok(true);
        }
        validate_user_ptr(ptr as *const u8, bytes)?;
        verify_user_memory(ptr as *const u8, bytes, true)?;
        // lint-repr-c-copy: allow (fd_set u64[words] copy; user→kernel)
        let db = unsafe { core::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u8, bytes) };
        copy_from_user(db, ptr as *const u8)?;
        crate::poll::fd_set_trim(&mut dst[..words], nb);
        Ok(true)
    };
    let has_r = copy_one(readfds, &mut rset)?;
    let has_w = copy_one(writefds, &mut wset)?;
    let has_e = copy_one(exceptfds, &mut eset)?;
    Ok((words, rset, wset, eset, has_r, has_w, has_e))
}

/// Build one PollEntry per fd in `[0, nb)` that has any bit set across the three
/// input sets (events = union of requested directions).
pub(super) fn select_build_entries(
    words: usize,
    rset: &[u64],
    wset: &[u64],
    eset: &[u64],
    nb: usize,
) -> Result<AdmittedVec<PollEntry>, SyscallError> {
    // Count only active bits before reserving so `select(1024, ...)` with a
    // handful of watched descriptors charges only the exact entries needed.
    let mut active = 0usize;
    for w in 0..words {
        active += (rset[w] | wset[w] | eset[w]).count_ones() as usize;
    }
    let active = core::cmp::min(active, nb);
    let mut entries = try_admitted_vec(mm::HeapClass::BlockingIo, active)?;
    for fd in 0..nb {
        let r = crate::poll::fd_set_test(&rset[..words], fd);
        let w = crate::poll::fd_set_test(&wset[..words], fd);
        let x = crate::poll::fd_set_test(&eset[..words], fd);
        if r || w || x {
            let mut events = 0i16;
            if r {
                events |= crate::poll::POLLIN;
            }
            if w {
                events |= crate::poll::POLLOUT;
            }
            if x {
                events |= crate::poll::POLLPRI;
            }
            entries.push(PollEntry {
                fd: fd as i32,
                events,
                revents: 0,
                kind: FdKind::Skip,
            });
        }
    }
    Ok(entries)
}

/// Build + copy out the three result fd_sets from the scanned entries. A bit is
/// set only if the direction is ready AND its fd was in that INPUT set. Returns
/// the total number of set bits (an fd ready for read+write counts twice, per
/// Linux). Copy-out order is fixed read, write, except; a fault returns EFAULT
/// immediately with earlier sets already written (no rollback — POSIX-undefined
/// on error, matching Linux).
#[allow(clippy::too_many_arguments)]
pub(super) fn select_writeback_sets(
    entries: &[PollEntry],
    words: usize,
    rset: &[u64],
    wset: &[u64],
    eset: &[u64],
    has_r: bool,
    has_w: bool,
    has_e: bool,
    readfds: *mut u8,
    writefds: *mut u8,
    exceptfds: *mut u8,
) -> Result<usize, SyscallError> {
    let mut orset = [0u64; SELECT_FD_SET_WORDS];
    let mut owset = [0u64; SELECT_FD_SET_WORDS];
    let mut oeset = [0u64; SELECT_FD_SET_WORDS];
    let mut total = 0usize;
    for e in entries {
        let (rd, wr, ex) = crate::poll::select_bits(e.revents);
        let fd = e.fd as usize;
        if rd && has_r && crate::poll::fd_set_test(&rset[..words], fd) {
            crate::poll::fd_set_mark(&mut orset[..words], fd);
            total += 1;
        }
        if wr && has_w && crate::poll::fd_set_test(&wset[..words], fd) {
            crate::poll::fd_set_mark(&mut owset[..words], fd);
            total += 1;
        }
        if ex && has_e && crate::poll::fd_set_test(&eset[..words], fd) {
            crate::poll::fd_set_mark(&mut oeset[..words], fd);
            total += 1;
        }
    }
    let bytes = words * 8;
    let mut copy_out = |ptr: *mut u8, src: &[u64]| -> Result<(), SyscallError> {
        if bytes == 0 {
            return Ok(());
        }
        // lint-repr-c-copy: allow (fd_set u64[words] copy; kernel→user)
        let sb = unsafe { core::slice::from_raw_parts(src.as_ptr() as *const u8, bytes) };
        copy_to_user(ptr, sb)
    };
    if has_r {
        copy_out(readfds, &orset)?;
    }
    if has_w {
        copy_out(writefds, &owset)?;
    }
    if has_e {
        copy_out(exceptfds, &oeset)?;
    }
    Ok(total)
}

/// select(2) — synchronous I/O multiplexing over fd_set bitmaps.
pub(super) fn sys_select(
    nfds_raw: i32,
    readfds: *mut u8,
    writefds: *mut u8,
    exceptfds: *mut u8,
    tv: *mut u8,
) -> Result<usize, SyscallError> {
    if nfds_raw < 0 {
        return Err(SyscallError::EINVAL);
    }
    // Clamp to MAX_FD (Linux clamps nfds to the fdtable size BEFORE sizing) — bits
    // in [MAX_FD, nfds) are never read or written (structural), matching Linux.
    let nb = core::cmp::min(nfds_raw as usize, crate::process::MAX_FD as usize);
    let timeout_ms = if tv.is_null() {
        None
    } else {
        let (sec, usec) = poll_copyin_timeval(tv as *const u8)?;
        crate::poll::timeval_to_ms(sec, usec).map_err(|_| SyscallError::EINVAL)?
    };

    let (words, rset, wset, eset, has_r, has_w, has_e) =
        select_copyin_sets(readfds, writefds, exceptfds, nb)?;
    let mut entries = select_build_entries(words, &rset, &wset, &eset, nb)?;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let start = crate::time::get_ticks();
    let r = poll_wait_loop(pid, &mut entries, timeout_ms, true);

    // Remaining-time write-back on EVERY return path (raw-Linux; ignore fault).
    if !tv.is_null() {
        if let Some(total) = timeout_ms {
            let elapsed = crate::time::get_ticks().saturating_sub(start);
            let (sec, usec) = crate::poll::ms_to_timeval(total.saturating_sub(elapsed));
            let _ = poll_writeback_timeval(tv, sec, usec);
        }
    }

    match r {
        Ok(_) => select_writeback_sets(
            &entries, words, &rset, &wset, &eset, has_r, has_w, has_e, readfds, writefds, exceptfds,
        ),
        // EINTR / EBADF: NO set write-back (Linux).
        Err(e) => Err(e),
    }
}

/// pselect6(2) — select with a timespec timeout + a temporary signal mask.
///
/// The 6th argument is a pointer to `{ const sigset_t* ss; size_t ss_len }`.
pub(super) fn sys_pselect6(
    nfds_raw: i32,
    readfds: *mut u8,
    writefds: *mut u8,
    exceptfds: *mut u8,
    ts: *mut u8,
    sigpack: u64,
) -> Result<usize, SyscallError> {
    if nfds_raw < 0 {
        return Err(SyscallError::EINVAL);
    }
    let nb = core::cmp::min(nfds_raw as usize, crate::process::MAX_FD as usize);

    // All fallible copy-ins BEFORE the mask swap (I6).
    let timeout_ms = if ts.is_null() {
        None
    } else {
        let (sec, nsec) = poll_copyin_timespec(ts as *const u8)?;
        crate::poll::timespec_to_ms(sec, nsec).map_err(|_| SyscallError::EINVAL)?
    };
    // sigpack: { ss: u64 ptr, ss_len: u64 }.
    let new_mask: Option<u64> = if sigpack != 0 {
        let mut pack = [0u8; 16];
        copy_from_user(&mut pack, sigpack as *const u8)?;
        let ss = u64::from_ne_bytes(pack[0..8].try_into().unwrap());
        let ss_len = u64::from_ne_bytes(pack[8..16].try_into().unwrap());
        if ss == 0 {
            None
        } else {
            if ss_len as usize != LINUX_KERNEL_SIGSET_SIZE {
                return Err(SyscallError::EINVAL);
            }
            let mut b = [0u8; LINUX_KERNEL_SIGSET_SIZE];
            copy_from_user(&mut b, ss as *const u8)?;
            Some(u64::from_ne_bytes(b))
        }
    } else {
        None
    };

    let (words, rset, wset, eset, has_r, has_w, has_e) =
        select_copyin_sets(readfds, writefds, exceptfds, nb)?;
    let mut entries = select_build_entries(words, &rset, &wset, &eset, nb)?;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    let old_mask: Option<u64> = new_mask.map(|m| {
        let (old, retarget) = {
            let mut p = proc_arc.lock();
            let old = p.blocked;
            p.blocked = crate::signal::apply_sigprocmask(old, SIG_SETMASK, m);
            // GAP-5 G7 (review D2): a group signal the temporary mask lets
            // through ends the wait at once, as Linux set_user_sigmask does.
            let retarget = p
                .recalc_shared_signals(true)
                .then(|| Arc::clone(&p.thread_group));
            (old, retarget)
        };
        if let Some(group) = retarget {
            crate::process::retarget_shared_signals(pid, &group);
        }
        old
    });

    let start = crate::time::get_ticks();
    let r = poll_wait_loop(pid, &mut entries, timeout_ms, true);

    // Restore-or-stash the original mask (see sys_ppoll): compute deliverability
    // from the held guard `p`, never the pid-keyed helper (self-deadlock).
    if let Some(old) = old_mask {
        let mut p = proc_arc.lock();
        if matches!(r, Err(SyscallError::EINTR)) && crate::signal::has_deliverable_signal_locked(&p)
        {
            p.poll_restore_blocked = Some(old);
        } else {
            p.blocked = old;
        }
    }

    // Remaining-time write-back on EVERY path, AFTER the mask restore.
    if !ts.is_null() {
        if let Some(total) = timeout_ms {
            let elapsed = crate::time::get_ticks().saturating_sub(start);
            let (sec, nsec) = crate::poll::ms_to_timespec(total.saturating_sub(elapsed));
            let _ = poll_writeback_timespec(ts, sec, nsec);
        }
    }

    match r {
        Ok(_) => select_writeback_sets(
            &entries, words, &rset, &wset, &eset, has_r, has_w, has_e, readfds, writefds, exceptfds,
        ),
        Err(e) => Err(e),
    }
}
