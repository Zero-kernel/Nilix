//! Syscall family module: `helpers` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// R23-5 fix: stdin 阻塞等待支持
// ============================================================================

pub(super) use alloc::collections::VecDeque;
pub(super) use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

/// stdin 等待队列
///
/// 当 sys_read(fd=0) 没有数据时，进程会被加入此队列并阻塞。
/// 键盘/串口中断通过 wake_stdin_waiters() 唤醒等待者。
pub(super) static STDIN_WAITERS: spin::Mutex<VecDeque<ProcessId>> =
    spin::Mutex::new(VecDeque::new());

/// D1-RES R2 (LEG-2): bound on live entries in each blocking-wait registry
/// (STDIN_WAITERS, SocketWaiters). Chosen for the unledgered-waiter byte budget
/// (see the SocketWaiters `const _` assertion): 96 × 320 B = 30,720 B, strictly
/// under NORMAL_UNADMITTED_RESERVE_BYTES/2 = 32 KiB. Each registry dedups per pid,
/// so live entries are bounded by resident tasks (each PCB charges
/// `arc_charge_bytes::<Mutex<Process>>()` to CoreProcess via `try_new_pcb`, so the
/// resident count is CoreProcess-admission-bounded). Beyond this cap the gates
/// degrade to a SAFE bounded spurious-wake / busy-retry — never a lost wakeup or
/// unbounded memory.
pub(crate) const WAITER_REGISTRY_MAX_ENTRIES: usize = 96;

/// D1-RES R2: outcome of `stdin_prepare_to_wait`. Replaces the old `bool` so the
/// registry-full case can decline to publish Blocked (a Blocked publish without a
/// queue entry would be a lost wakeup → hang).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StdinWaitPrepare {
    /// Enqueued (or already present) and Blocked published — proceed to wait.
    Enqueued,
    /// No current process — the caller returns EOF (RISK-1 contract preserved).
    NoProcess,
    /// Registry at capacity for a NEW pid — NOT enqueued, NOT blocked; the caller
    /// busy-retries. Unreachable while resident tasks <= WAITER_REGISTRY_MAX_ENTRIES.
    RegistryFull,
}

/// D1-RES R2: boot-time pre-reservation of the blocking-wait registries. Builds a
/// `VecDeque` with `WAITER_REGISTRY_MAX_ENTRIES` capacity OUTSIDE the lock, then
/// swaps it in under the lock (swap is allocation-free). After this, `push_back`
/// up to the cap is allocation-free forever — closing both the unledgered-drift
/// residual and the alloc-under-spinlock hard-rule tension for stdin. Boot-only,
/// called once pre-scheduler; failure is a broken-partition condition (fail-closed).
pub fn init_blocking_waiter_registries() -> Result<(), ()> {
    let mut fresh: VecDeque<ProcessId> = VecDeque::new();
    fresh
        .try_reserve_exact(WAITER_REGISTRY_MAX_ENTRIES)
        .map_err(|_| ())?;
    let mut guard = STDIN_WAITERS.lock();
    core::mem::swap(&mut *guard, &mut fresh);
    Ok(())
}

/// R149-1 FIX: Deferred stdin wake flag for IRQ handlers.
///
/// Keyboard/serial IRQ handlers must NOT acquire PROCESS_TABLE or Process
/// locks (deterministic deadlock if the interrupted context holds them).
/// Instead, the IRQ handler sets this global flag and the actual wake is
/// drained in process context by `drain_deferred_stdin_wakes()`.
///
/// Global (not per-CPU) because: (a) keyboard IRQ may fire on any CPU,
/// (b) the blocked process may call stdin_finish_wait() on a different CPU,
/// (c) any CPU's reschedule_if_needed() should be able to drain the wake.
pub(super) static STDIN_WAKE_PENDING: AtomicBool = AtomicBool::new(false);

/// 准备等待 stdin 输入（第一阶段）
///
/// 在检查缓冲区为空后调用此函数，将当前进程加入等待队列。
/// 必须在持有键盘缓冲区检查的同一临界区内调用，以避免丢失唤醒。
///
/// # Returns
///
/// `Enqueued` on success, `NoProcess` if there is no current process, or
/// `RegistryFull` if the registry is at capacity for a NEW pid (D1-RES R2).
pub(super) fn stdin_prepare_to_wait() -> StdinWaitPrepare {
    let pid = match current_pid() {
        Some(p) => p,
        None => return StdinWaitPrepare::NoProcess,
    };

    // 在关中断状态下操作
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut waiters = STDIN_WAITERS.lock();

        // 避免重复添加：检查是否已经在等待队列中
        // 这防止了当 force_reschedule 返回（因没有其他进程）时
        // 进程在循环中反复将自己添加到队列导致内存耗尽
        if !waiters.iter().any(|&p| p == pid) {
            // D1-RES R2: bound + allocation-free (capacity was pre-reserved to
            // WAITER_REGISTRY_MAX_ENTRIES). Refuse a NEW pid at the cap WITHOUT
            // publishing Blocked — the caller busy-retries; never a lost wakeup.
            if waiters.len() >= WAITER_REGISTRY_MAX_ENTRIES {
                debug_assert!(false, "stdin waiter registry full (resident tasks > cap)");
                return StdinWaitPrepare::RegistryFull;
            }
            waiters.push_back(pid);
        }

        // 将进程状态设为阻塞
        if let Some(proc_arc) = get_process(pid) {
            let mut proc = proc_arc.lock();
            // R172-12 FIX: close the gate->commit lost-wakeup window — do NOT publish Blocked
            // if a kill/handler-signal raced in under the proc lock the wakers take (the bare
            // state-flip wake fires only on state==Blocked, so it would be lost). Leaving the
            // task Running makes stdin_finish_wait's HLT loop recheck wait_should_abort /
            // has_deliverable_signal on its first iteration and return EINTR. Keeping the
            // `Enqueued` return preserves the EOF/EINTR distinction at the caller (a `NoProcess`
            // return is EOF, not EINTR — RISK-1).
            if !crate::signal::should_abort_pending_block(&proc) {
                proc.enter_blocked_at(crate::get_ticks());
            }
        }

        StdinWaitPrepare::Enqueued
    })
}

/// R158-8 FIX: Cancel a prepared wait when data arrives on the double-check path.
/// Removes PID from STDIN_WAITERS and resets state to Ready.
pub(super) fn stdin_cancel_wait() {
    if let Some(pid) = current_pid() {
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut waiters = STDIN_WAITERS.lock();
            waiters.retain(|&p| p != pid);

            if let Some(proc_arc) = get_process(pid) {
                let mut proc = proc_arc.lock();
                if proc.state == ProcessState::Blocked {
                    proc.enter_ready_at(crate::get_ticks());
                }
            }
        });
    }
}

/// 完成等待（第二阶段）
///
/// 在 prepare_to_wait 后调用，实际让出 CPU。
/// 如果没有其他进程可调度，会进入 HLT 循环等待中断唤醒。
pub(super) fn stdin_finish_wait() -> bool {
    // 尝试切换到其他进程
    crate::force_reschedule();

    // R171-F3: true if a pending kill ended the wait (the caller returns EINTR).
    let mut aborted = false;

    // 如果 force_reschedule 返回，说明没有其他进程可运行
    // 当前进程已被标记为 Blocked，需要等待中断（键盘/串口）唤醒
    // 进入 HLT 循环，避免忙等消耗 CPU
    loop {
        // R149-1 FIX: Drain deferred stdin wakes before checking state.
        // This handles the case where the system is idle (no other runnable
        // processes) and force_reschedule returned without switching — the
        // only progress path is draining the flag here after HLT returns.
        drain_deferred_stdin_wakes();

        // 必须在关中断状态下检查进程状态，避免与中断处理程序竞争
        // enable_and_hlt 后中断是开启的，需要先关闭再检查
        let should_continue = x86_64::instructions::interrupts::without_interrupts(|| {
            // R171-F3 FIX: a pending kill interrupts the blocking stdin read.
            // Dequeue from STDIN_WAITERS + mark Ready, flag aborted, and break so
            // the caller returns EINTR instead of HLT-looping unkillably.
            if let Some(pid) = current_pid() {
                if wait_should_abort(pid) {
                    STDIN_WAITERS.lock().retain(|&p| p != pid);
                    if let Some(proc_arc) = get_process(pid) {
                        let mut proc = proc_arc.lock();
                        if proc.state == ProcessState::Blocked {
                            proc.enter_ready_at(crate::get_ticks());
                        }
                    }
                    aborted = true;
                    return false;
                }
                // M0-5 sub-slice 1b: same EINTR cleanup for a deliverable handler signal
                // (the canonical Ctrl-C-during-read site). SEPARATE from the kill gate
                // (kill-first); the caller already maps `aborted` -> EINTR.
                if crate::signal::has_deliverable_signal(pid) {
                    STDIN_WAITERS.lock().retain(|&p| p != pid);
                    if let Some(proc_arc) = get_process(pid) {
                        let mut proc = proc_arc.lock();
                        if proc.state == ProcessState::Blocked {
                            proc.enter_ready_at(crate::get_ticks());
                        }
                    }
                    aborted = true;
                    return false;
                }
            }
            if let Some(pid) = current_pid() {
                if let Some(proc_arc) = get_process(pid) {
                    let proc = proc_arc.lock();
                    if proc.state != ProcessState::Blocked {
                        // 已被唤醒（可能是键盘中断），退出等待
                        return false;
                    }
                }
            }
            true // 继续等待
        });

        if !should_continue {
            break;
        }

        // 启用中断并等待（HLT 会在下一个中断时唤醒）
        // 键盘/串口中断会调用 wake_stdin_waiters() 将进程设为 Ready
        x86_64::instructions::interrupts::enable_and_hlt();
    }

    aborted
}

/// 唤醒一个等待 stdin 的进程 (IRQ-safe fast path).
///
/// 由键盘/串口中断处理器调用。
/// R149-1 FIX: No locks acquired — just sets a deferred flag. The actual
/// wake (which requires PROCESS_TABLE + Process locks) is performed by
/// `drain_deferred_stdin_wakes()` in process context.
pub fn wake_stdin_waiters() {
    STDIN_WAKE_PENDING.store(true, AtomicOrdering::Release);
}

/// R149-1 FIX: Drain deferred stdin wakeups in safe (non-IRQ) process context.
///
/// Called from:
/// - `scheduler_hook::reschedule_if_needed()` on syscall return
/// - `stdin_finish_wait()` HLT loop (handles idle-system case)
///
/// Uses wake_one semantics to avoid thundering herd.
///
/// R173 IRQ-SAFETY FIX: Use try_lock pattern throughout to prevent same-CPU
/// deadlock if process context holds any lock with IRQs enabled, then timer IRQ
/// fires and reaches this drain via reschedule_if_needed(). Matches the proven
/// SOCKET_WAITERS pattern (lines 724-843).
pub fn drain_deferred_stdin_wakes() {
    // Fast path: no wake pending (read-before-swap avoids cross-CPU RMW traffic)
    if !STDIN_WAKE_PENDING.load(AtomicOrdering::Acquire)
        || !STDIN_WAKE_PENDING.swap(false, AtomicOrdering::AcqRel)
    {
        return;
    }

    // R173: Use try_lock instead of blocking lock to avoid IRQ deadlock
    let mut waiters = match STDIN_WAITERS.try_lock() {
        Some(w) => w,
        None => {
            // Contended - re-set flag and defer to next reschedule
            STDIN_WAKE_PENDING.store(true, AtomicOrdering::Release);
            return;
        }
    };

    // 清理已退出的进程并唤醒第一个有效等待者
    while let Some(pid) = waiters.pop_front() {
        // R173: Use try_get_process to avoid blocking on PROCESS_TABLE
        match crate::process::try_get_process(pid) {
            Some(Some(proc_arc)) => {
                // R173: Use try_lock on PCB to avoid deadlock
                if let Some(mut proc) = proc_arc.try_lock() {
                    if proc.state == ProcessState::Blocked {
                        proc.enter_ready_at(crate::get_ticks());
                        return; // 只唤醒一个
                    }
                }
                // PCB contended - skip this waiter, continue to next
            }
            Some(None) => {
                // Process gone - continue to next waiter
            }
            None => {
                // PROCESS_TABLE contended - re-queue this PID and defer
                waiters.push_front(pid);
                STDIN_WAKE_PENDING.store(true, AtomicOrdering::Release);
                return;
            }
        }
    }
}

/// no-ops and no process/cap table is touched.
pub fn run_fileops_cap_id_self_test() {
    use crate::process::FileOps;

    // (1) SocketFile MUST override cap_id() with its live CapId (a socket fd
    // always carries the cap allocated at sys_socket/sys_accept).
    let cid = cap::CapId::from_parts(7, 42);
    let sock = SocketFile::new(cid, u64::MAX);
    let desc: &dyn FileOps = &sock;
    assert!(
        desc.cap_id() == Some(cid),
        "U.S3-B: SocketFile must override FileOps::cap_id() with its CapId — \
         a default-None fallback makes every close/exec/exit decrement a no-op \
         (cap slot leak → TableFull DoS)"
    );

    // (2) clone_box is PURE w.r.t. cap accounting (U.S3-A2) and the copy
    // carries the SAME CapId (shared entry, not a fresh allocation) — the
    // explicit call-site bump (U.S3-A3) relies on both.
    let cloned = desc
        .try_clone_box()
        .expect("self-test descriptor clone allocation");
    assert!(
        cloned.cap_id() == Some(cid),
        "U.S3-A2/A3: a dup/fork copy must reference the SAME CapId; the \
         refcount bump happens at the install site, never inside clone_box"
    );

    // (3) A non-bearing fd kind keeps the default None (namespace fds today;
    // pipe/file fds keep None until U.S2 SLICE-3 wires their caps).
    struct NoCapFile;
    impl FileOps for NoCapFile {
        fn clone_box(&self) -> Result<crate::process::FileDescriptor, ()> {
            self.try_clone_box()
        }
        fn try_clone_box(&self) -> Result<crate::process::FileDescriptor, ()> {
            crate::process::FileDescriptor::try_new(NoCapFile, mm::HeapClass::CoreProcess)
        }
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
            self
        }
        fn type_name(&self) -> &'static str {
            "NoCapFile"
        }
    }
    let plain: &dyn FileOps = &NoCapFile;
    assert!(
        plain.cap_id().is_none(),
        "U.S3-B: the FileOps::cap_id() default must stay None for \
         non-cap-bearing fd kinds"
    );
}

/// R186-1: self-test for the open/openat publication transaction.
///
/// The CRITICAL bug was that `sys_open_internal` held `process.lock()` across
/// `FdPublicationReservation::install`, which re-acquired the same non-reentrant
/// mutex — every successful `open(2)` self-deadlocked. The adversarial review of
/// the first repair then found a second defect: a capability allocated and
/// attached before a failing publication was never released.
///
/// Both are structural, so this test asserts the structural invariants rather
/// than trying to reproduce a hang (a real deadlock would wedge the gate instead
/// of failing it):
///
/// 1. A reserved capability slot is INVISIBLE until published — the leak-free
///    half of the two-phase commit. Dropping the reservation must return the
///    reservation rather than strand a live-but-unreferenced capability; if it
///    was the table's sole use, the empty backing is reclaimed.
/// 2. `PreparedCapAllocation::cap_id()` returns exactly the id `install` later
///    publishes. The publication path binds that id into the FileHandle BEFORE
///    the descriptor is installed, so if these ever diverged, every opened file
///    would carry a capability id that addresses a different slot.
/// 3. Reserve→drop→reserve never reuses the complete identity. Empty-table
///    reclamation may change the slot index; monotonic generations ensure a
///    stale id from an abandoned transaction cannot resolve to the next one.
///
/// PURE: operates on a standalone `CapTable`; no process or VFS state is touched.
pub fn run_fd_publication_transaction_self_test() {
    let table = cap::CapTable::new();

    let entry = || {
        cap::CapEntry::new(
            cap::CapObject::RegularFile(cap::RegularFile {
                inode_id: 4242,
                fs_id: 7,
            }),
            cap::CapRights::READ,
        )
    };

    // (1) A reservation that is dropped instead of installed publishes nothing.
    let abandoned_id = {
        let reservation = table
            .prepare_allocation()
            .expect("R186-1 self-test: capability reservation");
        let id = reservation.cap_id();
        assert!(
            table.lookup(id).is_err(),
            "R186-1: a RESERVED capability must not be visible to lookup — if it \
             were, a failed publication would leave a live capability that no \
             file descriptor references (the accounting leak the first repair \
             attempt left behind)"
        );
        id
        // reservation drops here → reservation cancelled; empty backing reclaimed
    };
    assert!(
        table.lookup(abandoned_id).is_err(),
        "R186-1: dropping a prepared capability must cancel it, not publish it"
    );

    // (2) cap_id() must equal the id install() publishes. The open path attaches
    // cap_id() to the FileHandle before publishing, so a mismatch would hand
    // userspace a descriptor pointing at the wrong capability slot.
    let reservation = table
        .prepare_allocation()
        .expect("R186-1 self-test: second capability reservation");
    let predicted = reservation.cap_id();
    let published = reservation.install(entry());
    assert!(
        predicted == published,
        "R186-1: PreparedCapAllocation::cap_id() must be the identity install() \
         publishes; the open path binds it into the FileHandle before publication"
    );
    assert!(
        table.lookup(published).is_ok(),
        "R186-1: an installed capability must be visible to lookup"
    );

    // (3) The abandoned transaction's id must not alias the published one. A
    // sole cancelled reservation reclaims empty backing, so the next slot index
    // is intentionally not part of the public identity contract.
    assert!(
        abandoned_id != published,
        "R186-1: a cancelled reservation must not share an identity with the \
         next publication — generations are consumed at reservation time and \
         are never recycled"
    );
    assert!(
        table.lookup(abandoned_id).is_err(),
        "R186-1: a stale id from a cancelled transaction must not resolve to the \
         capability published by a later transaction"
    );

    table
        .revoke(published)
        .expect("R186-1 self-test: revoke published capability");
}

/// U.S3-SLICE-2: self-test for fork reconciliation of thread-shared cap_table.
///
/// When a CLONE_THREAD thread (sharing its cap_table Arc with siblings) calls
/// fork(), CapSlot::clone copies refcounts VERBATIM including sibling-held
/// references, but the child only gets the forking thread's fds → over-count.
/// The reconcile_refcounts_after_fork method fixes this by counting the child's
/// actual fd references and overwriting each CapEntry.refcount. This test
/// simulates the scenario: create a cap_table with over-counted refcounts,
/// build a child-fd histogram, call reconcile, and assert the corrected counts.
/// PURE: no process/socket state touched (fabricated CapIds + empty CapObjects).
///
/// U.S2-SLICE-3 extensions (CRITICAL-9 + BV-3):
/// - an fd-backed cap with child_fd_count==0 must be REVOKED (slot reclaimed),
///   not parked at refcount=0 forever (the child-local slot-leak class);
/// - the Pipe variant rides the same reconcile as Socket (fd-backed class);
/// - a NON-fd-backed cap (Endpoint) must stay VERBATIM — its refcount is not
///   an fd count, so the fd histogram must neither rewrite nor revoke it.
pub fn run_fork_reconcile_refcount_self_test() {
    // (1) Create a cap_table simulating a CLONE_THREAD parent whose refcounts
    // include sibling-held references. Allocate 3 caps with initial refcount=1
    // each, then manually bump them to simulate: cap A held by 2 threads (parent
    // + sibling), cap B held by 3 threads, cap C held by 1 thread (parent only).
    let parent_table = cap::CapTable::new();
    let cap_a = parent_table
        .allocate(cap::CapEntry::new(
            cap::CapObject::Socket(cap::Socket::new(999, 0)),
            cap::CapRights::READ | cap::CapRights::WRITE,
        ))
        .expect("allocate cap A");
    let cap_b = parent_table
        .allocate(cap::CapEntry::new(
            cap::CapObject::Socket(cap::Socket::new(998, 0)),
            cap::CapRights::READ,
        ))
        .expect("allocate cap B");
    let cap_c = parent_table
        .allocate(cap::CapEntry::new(
            cap::CapObject::Socket(cap::Socket::new(997, 0)),
            cap::CapRights::WRITE,
        ))
        .expect("allocate cap C");
    // U.S2-SLICE-3: cap D = NON-fd-backed (Endpoint) — reconcile must leave it
    // VERBATIM (BV-3 scoping): no refcount rewrite, no revoke.
    let cap_d = parent_table
        .allocate(cap::CapEntry::new(
            cap::CapObject::Endpoint(4242),
            cap::CapRights::READ,
        ))
        .expect("allocate cap D (Endpoint)");
    // U.S2-SLICE-3: cap E = fd-backed Pipe variant, parent/sibling-only (child
    // holds 0 fds) — must be REVOKED by reconcile exactly like a Socket orphan.
    let cap_e = parent_table
        .allocate(cap::CapEntry::new(
            cap::CapObject::Pipe(cap::Pipe {
                pipe_id: 996,
                end_type: cap::PipeEndType::Read,
            }),
            cap::CapRights::READ,
        ))
        .expect("allocate cap E (Pipe)");

    // Simulate sibling-held references: A=2 (parent+1 sibling), B=3 (parent+2
    // siblings), C=1 (parent only). The initial allocate() set refcount=1; bump
    // the shared ones.
    parent_table.increment_refcount(cap_a).expect("bump A");
    parent_table.increment_refcount(cap_b).expect("bump B to 2");
    parent_table.increment_refcount(cap_b).expect("bump B to 3");
    // C stays at 1 (parent-only). D (Endpoint) stays at 1. E (Pipe) stays at 1.

    assert!(
        parent_table.get_refcount(cap_a) == Some(2),
        "pre-fork: cap A should have refcount=2 (parent+sibling)"
    );
    assert!(
        parent_table.get_refcount(cap_b) == Some(3),
        "pre-fork: cap B should have refcount=3 (parent+2 siblings)"
    );
    assert!(
        parent_table.get_refcount(cap_c) == Some(1),
        "pre-fork: cap C should have refcount=1 (parent-only)"
    );

    // (2) Simulate fork: try_clone_for_fork copies the table VERBATIM (refcounts
    // 2/3/1 for A/B/C), but the child only gets the forking thread's fds.
    // Build the child-fd histogram: child holds A once, B once, and does NOT
    // hold C (C was a sibling-only cap in this simulation).
    let mut child_table = parent_table.try_clone_for_fork().expect("fork clone table");

    // Before reconciliation, the child's verbatim-copied refcounts are wrong:
    assert!(
        child_table.get_refcount(cap_a) == Some(2),
        "pre-reconcile: child's cap A refcount is verbatim-copied = 2 (WRONG, child holds 1 fd)"
    );
    assert!(
        child_table.get_refcount(cap_b) == Some(3),
        "pre-reconcile: child's cap B refcount is verbatim-copied = 3 (WRONG, child holds 1 fd)"
    );
    assert!(
        child_table.get_refcount(cap_c) == Some(1),
        "pre-reconcile: child's cap C refcount is verbatim-copied = 1 (WRONG, child holds 0 fds)"
    );

    // Build the child-fd histogram: A→1 fd, B→1 fd, C→0 fds (not in map).
    let child_counts = [(cap_a, 1usize), (cap_b, 1usize)];
    // C and E are omitted (child has no fds carrying them); D is non-fd-backed
    // and never appears in an fd histogram.

    // (3) Call reconcile_refcounts_after_fork to fix the over-counts.
    child_table.reconcile_refcounts_after_fork(&child_counts);

    // After reconciliation, the child's refcounts must match its fd histogram:
    assert!(
        child_table.get_refcount(cap_a) == Some(1),
        "U.S3-SLICE-2: reconciled cap A refcount must equal child's fd count (1, not 2)"
    );
    assert!(
        child_table.get_refcount(cap_b) == Some(1),
        "U.S3-SLICE-2: reconciled cap B refcount must equal child's fd count (1, not 3)"
    );
    // U.S2-SLICE-3 (CRITICAL-9): fd-backed orphans (child_fd_count==0) are
    // REVOKED, not parked at refcount=0 — the CapId must now be invalid.
    assert!(
        child_table.get_refcount(cap_c).is_none(),
        "U.S2-SLICE-3: orphan Socket cap C (0 child fds) must be REVOKED by \
         reconcile — a refcount=0 slot parked forever is the child-local slot \
         leak class (TableFull DoS)"
    );
    assert!(
        child_table.get_refcount(cap_e).is_none(),
        "U.S2-SLICE-3: orphan Pipe cap E (0 child fds) must be REVOKED by \
         reconcile — the Pipe variant rides the same fd-backed class as Socket"
    );
    assert!(
        child_table.lookup(cap_c).is_err() && child_table.lookup(cap_e).is_err(),
        "U.S2-SLICE-3: revoked orphan CapIds must fail lookup in the child \
         (generation guard keeps stale ids invalid)"
    );
    // U.S2-SLICE-3 (BV-3): the NON-fd-backed Endpoint cap must be untouched —
    // neither rewritten to the (absent) histogram count nor revoked.
    assert!(
        child_table.get_refcount(cap_d) == Some(1),
        "U.S2-SLICE-3: non-fd-backed Endpoint cap D must stay VERBATIM \
         (refcount=1) — its refcount is not an fd count (BV-3 scoping)"
    );

    // (4) Verify the parent table is UNCHANGED (fork does NOT touch the parent).
    assert!(
        parent_table.get_refcount(cap_a) == Some(2),
        "post-reconcile: parent cap A refcount must stay 2 (fork reconciles child only)"
    );
    assert!(
        parent_table.get_refcount(cap_b) == Some(3),
        "post-reconcile: parent cap B refcount must stay 3 (fork reconciles child only)"
    );
    assert!(
        parent_table.get_refcount(cap_c) == Some(1),
        "post-reconcile: parent cap C refcount must stay 1 (fork reconciles child only)"
    );
    // U.S2-SLICE-3: the child-side orphan revoke must NOT leak into the parent
    // (separate table object), and the parent's non-fd-backed cap is untouched.
    assert!(
        parent_table.get_refcount(cap_e) == Some(1),
        "post-reconcile: parent Pipe cap E must stay allocated (child revoke is child-local)"
    );
    assert!(
        parent_table.get_refcount(cap_d) == Some(1),
        "post-reconcile: parent Endpoint cap D must stay allocated at refcount=1"
    );
}

/// 最大参数总字节数（argv + envp 字符串总大小上限）
pub(super) const MAX_ARG_TOTAL: usize = 128 * 1024;

/// 单个参数最大长度
pub(super) const MAX_ARG_STRLEN: usize = 4096;

/// 最大单次读写长度（X-2 安全修复：防止内核堆耗尽 DoS）
///
/// 用户可请求任意大小的 count，如果不限制会导致：
/// - 内核尝试分配 GB 级别的 Vec
/// - OOM panic 或堆耗尽
/// - 任意用户进程可 DoS 整个系统
///
/// R180-10 FIX: preserve the historical 1 MiB per-call contract, while every
/// live buffer is aggregate-admitted below. Per-thread-group total and blocking
/// I/O budgets additionally reject requests that would monopolize the shared
/// pool; a syntactically valid size can therefore return ENOMEM.
pub(super) const MAX_RW_SIZE: usize = {
    let residual = mm::general_residual_bytes();
    if residual < 4096 {
        4096
    } else if residual > 1024 * 1024 {
        1024 * 1024
    } else {
        residual
    }
};

/// A transient Vec whose allocator backing and heap-ledger reservation have one
/// owner. Field declaration order is intentional and guaranteed by Rust: the
/// Vec is deallocated before `_reservation` returns its bytes to admission, so
/// a competing allocation can never be admitted against memory that is still
/// physically live.
pub(super) struct AdmittedVec<T> {
    pub(super) values: Vec<T>,
    pub(super) _reservation: mm::HeapReservation,
}

impl<T> AdmittedVec<T> {
    #[inline]
    pub(super) fn admitted_bytes(&self) -> usize {
        self._reservation.bytes()
    }
}

impl<T> core::ops::Deref for AdmittedVec<T> {
    type Target = Vec<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T> core::ops::DerefMut for AdmittedVec<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

pub(super) fn try_admitted_vec<T>(
    class: mm::HeapClass,
    capacity: usize,
) -> Result<AdmittedVec<T>, SyscallError> {
    let estimated = mm::vec_charge_bytes::<T>(capacity).map_err(|_| SyscallError::ENOMEM)?;
    let mut reservation =
        mm::try_reserve_heap(class, estimated).map_err(|_| SyscallError::ENOMEM)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| SyscallError::ENOMEM)?;
    let actual = mm::vec_charge_bytes::<T>(values.capacity()).map_err(|_| SyscallError::ENOMEM)?;
    reservation
        .resize(actual)
        .map_err(|_| SyscallError::ENOMEM)?;
    Ok(AdmittedVec {
        values,
        _reservation: reservation,
    })
}

pub(super) fn try_admitted_zeroed_buffer(
    class: mm::HeapClass,
    len: usize,
) -> Result<AdmittedVec<u8>, SyscallError> {
    let mut bytes = try_admitted_vec(class, len)?;
    bytes.resize(len, 0);
    Ok(bytes)
}

#[inline]
pub(super) fn try_admitted_zeroed_io_buffer(len: usize) -> Result<AdmittedVec<u8>, SyscallError> {
    try_admitted_zeroed_buffer(mm::HeapClass::BlockingIo, len)
}

/// Maximum I/O size serviced from a per-call stack scratch buffer instead of
/// allocating an admitted `BlockingIo` heap vector. Uses zero kernel heap
/// bytes, so it cannot contribute to heap exhaustion while avoiding allocator
/// and admission contention on small pipe/console transfers.
pub(super) const SMALL_IO_STACK_BUF: usize = 256;

/// Stack-or-heap scratch buffer for `sys_read`/`sys_write`/`sys_writev_console`.
pub(super) enum IoScratchBuffer {
    Stack {
        buf: [u8; SMALL_IO_STACK_BUF],
        len: usize,
    },
    Heap(AdmittedVec<u8>),
}

impl IoScratchBuffer {
    #[inline]
    pub(super) fn try_zeroed(len: usize) -> Result<Self, SyscallError> {
        if len <= SMALL_IO_STACK_BUF {
            Ok(Self::Stack {
                buf: [0u8; SMALL_IO_STACK_BUF],
                len,
            })
        } else {
            Ok(Self::Heap(try_admitted_zeroed_io_buffer(len)?))
        }
    }

    #[inline]
    pub(super) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Stack { buf, len } => &buf[..*len],
            Self::Heap(vec) => vec.as_slice(),
        }
    }

    #[inline]
    pub(super) fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Stack { buf, len } => &mut buf[..*len],
            Self::Heap(vec) => vec.as_mut_slice(),
        }
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Stack { len, .. } => *len,
            Self::Heap(vec) => vec.len(),
        }
    }
}

/// R180-10 executable regression probe: independently live blocking buffers
/// accumulate in the authoritative byte ledger and release exactly, including
/// the deallocation-before-uncharge owner ordering above.
pub fn run_transient_io_admission_self_test() {
    let before = mm::heap_class_snapshot(mm::HeapClass::BlockingIo);

    // Preserve the public 1 MiB read/write contract together with the largest
    // legal iovec descriptor array. Allocator metadata is part of the proof;
    // a nominal 1 MiB class limit would reject the historical maximum.
    let worst_rw = mm::vec_charge_bytes::<u8>(MAX_RW_SIZE).expect("max rw charge");
    let worst_iov = mm::vec_charge_bytes::<Iovec>(IOV_MAX).expect("max iovec charge");
    let worst_transaction = worst_rw
        .checked_add(worst_iov)
        .expect("max I/O transaction charge overflow");
    assert!(
        mm::HeapClass::BlockingIo.limit_bytes() >= worst_transaction,
        "BlockingIo ceiling must preserve the 1 MiB + IOV_MAX contract"
    );

    let first = try_admitted_zeroed_io_buffer(4096).expect("first admitted I/O buffer");
    let first_bytes = first.admitted_bytes();
    let after_first = mm::heap_class_snapshot(mm::HeapClass::BlockingIo);
    assert_eq!(
        after_first.reserved_bytes,
        before.reserved_bytes + first_bytes
    );

    let second =
        try_admitted_vec::<u64>(mm::HeapClass::BlockingIo, 64).expect("second admitted buffer");
    let second_bytes = second.admitted_bytes();
    let after_second = mm::heap_class_snapshot(mm::HeapClass::BlockingIo);
    assert_eq!(
        after_second.reserved_bytes,
        after_first.reserved_bytes + second_bytes
    );

    drop(second);
    assert_eq!(
        mm::heap_class_snapshot(mm::HeapClass::BlockingIo),
        after_first
    );
    drop(first);
    assert_eq!(mm::heap_class_snapshot(mm::HeapClass::BlockingIo), before);
}

#[cfg(all(test, feature = "host_harness", not(target_os = "none")))]
mod io_scratch_buffer_tests {
    use super::*;

    #[test]
    fn small_io_scratch_buffer_uses_stack_without_blocking_io_charge() {
        let before = mm::heap_class_snapshot(mm::HeapClass::BlockingIo);

        let mut small = IoScratchBuffer::try_zeroed(SMALL_IO_STACK_BUF)
            .expect("256-byte scratch buffer must use stack");
        assert_eq!(small.len(), SMALL_IO_STACK_BUF);
        assert!(small.as_slice().iter().all(|&b| b == 0));
        small.as_mut_slice()[0] = 0x5a;
        assert_eq!(small.as_slice()[0], 0x5a);
        assert_eq!(
            mm::heap_class_snapshot(mm::HeapClass::BlockingIo),
            before,
            "stack scratch buffer must consume zero BlockingIo heap admission"
        );
        drop(small);

        let large_len = SMALL_IO_STACK_BUF + 1;
        let large = IoScratchBuffer::try_zeroed(large_len)
            .expect("buffer above stack threshold must use admitted heap");
        assert_eq!(large.len(), large_len);
        assert!(large.as_slice().iter().all(|&b| b == 0));
        let during_large = mm::heap_class_snapshot(mm::HeapClass::BlockingIo);
        assert!(
            during_large.reserved_bytes > before.reserved_bytes,
            "buffer above stack threshold must reserve BlockingIo heap admission"
        );
        drop(large);
        assert_eq!(mm::heap_class_snapshot(mm::HeapClass::BlockingIo), before);
    }
}

// ============================================================================
// Syscall 帧访问（供 clone/fork 使用）
// ============================================================================

/// Syscall 帧结构（与 arch::syscall 中的布局一致）
///
/// 表示 syscall_entry_stub 保存到内核栈上的寄存器帧。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallFrame {
    pub rax: u64, // 0x00: 系统调用号 / 返回值
    pub rcx: u64, // 0x08: 用户 RIP (syscall 保存)
    pub rdx: u64, // 0x10: arg2
    pub rbx: u64, // 0x18: callee-saved
    pub rsp: u64, // 0x20: 用户 RSP
    pub rbp: u64, // 0x28: callee-saved
    pub rsi: u64, // 0x30: arg1
    pub rdi: u64, // 0x38: arg0
    pub r8: u64,  // 0x40: arg4
    pub r9: u64,  // 0x48: arg5
    pub r10: u64, // 0x50: arg3
    pub r11: u64, // 0x58: 用户 RFLAGS (syscall 保存)
    pub r12: u64, // 0x60: callee-saved
    pub r13: u64, // 0x68: callee-saved
    pub r14: u64, // 0x70: callee-saved
    pub r15: u64, // 0x78: callee-saved
}

/// 获取当前 syscall 帧的回调类型
///
/// 由 arch 模块注册，用于 clone/fork 读取调用者的寄存器状态
pub type GetSyscallFrameCallback = fn() -> Option<&'static SyscallFrame>;

/// 全局 syscall 帧回调
pub(super) static SYSCALL_FRAME_CALLBACK: spin::Mutex<Option<GetSyscallFrameCallback>> =
    spin::Mutex::new(None);

/// 注册获取 syscall 帧的回调
///
/// 由 arch 模块在初始化时调用
pub fn register_syscall_frame_callback(cb: GetSyscallFrameCallback) {
    *SYSCALL_FRAME_CALLBACK.lock() = Some(cb);
}

/// 获取当前 syscall 帧
///
/// 仅在 syscall 处理期间有效，用于 clone/fork
pub(super) fn get_current_syscall_frame() -> Option<&'static SyscallFrame> {
    if let Some(cb) = *SYSCALL_FRAME_CALLBACK.lock() {
        cb()
    } else {
        None
    }
}

/// R102-6 FIX: Execute a closure with the current syscall frame.
///
/// Prevents the frame reference from escaping the active syscall window.
/// The internal callback still returns `&'static SyscallFrame` for ABI
/// compatibility, but this wrapper ensures callers cannot store the reference.
///
/// # Arguments
///
/// * `f` - Closure receiving `&SyscallFrame`, executed only if a frame is active.
///
/// # Returns
///
/// `Some(R)` with the closure's return value, or `None` if no frame is active.
pub fn with_current_syscall_frame<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&SyscallFrame) -> R,
{
    get_current_syscall_frame().map(f)
}

// ============================================================================
// M0 item 5: MUTABLE syscall-frame access (signal-handler delivery)
// ============================================================================

/// The 512-byte FXSAVE area lives immediately ABOVE the `SyscallFrame` on the
/// kernel stack (the syscall entry stub `fxsave64`s the user FPU there). The frame
/// is exactly `size_of::<SyscallFrame>()` (128) bytes.
pub(super) const SYSCALL_FRAME_BYTES: usize = core::mem::size_of::<SyscallFrame>();

/// Callback (registered by arch): MUTABLE access to the current syscall frame, gated
/// by the owner PID. Returns the raw frame pointer or `None` (fail-closed).
pub type GetSyscallFrameMutCallback = fn(expected_pid: u64) -> Option<*mut SyscallFrame>;
/// Callback (registered by arch): record the PID owning the current frame.
pub type SetFrameOwnerCallback = fn(pid: u64);
/// Callback (registered by arch): read this CPU's raw `(frame_ptr, owner_pid)` binding.
pub type GetFrameBindingCallback = fn() -> (u64, u64);
/// Callback (registered by arch): write this CPU's raw `(frame_ptr, owner_pid)` binding.
pub type SetFrameBindingCallback = fn(frame_ptr: u64, owner_pid: u64);

// LOCK-FREE callback storage. `set_syscall_frame_owner` runs on EVERY syscall entry,
// so a `Mutex` here would be per-syscall global contention under SMP. The callbacks
// are registered exactly once during arch boot init and never change, so `spin::Once`
// (a lock-free atomic-state read after init, no fn-ptr-to-int cast / transmute) fits.
pub(super) static SYSCALL_FRAME_MUT_CALLBACK: spin::Once<GetSyscallFrameMutCallback> =
    spin::Once::new();
pub(super) static SET_FRAME_OWNER_CALLBACK: spin::Once<SetFrameOwnerCallback> = spin::Once::new();
// M0 item 5 (1b-2): raw frame-binding get/set (snapshot at entry, republish on resume).
pub(super) static GET_FRAME_BINDING_CALLBACK: spin::Once<GetFrameBindingCallback> =
    spin::Once::new();
pub(super) static SET_FRAME_BINDING_CALLBACK: spin::Once<SetFrameBindingCallback> =
    spin::Once::new();

/// Register the mutable-frame accessor (arch → kernel_core). Called once at boot.
pub fn register_syscall_frame_mut_callback(cb: GetSyscallFrameMutCallback) {
    SYSCALL_FRAME_MUT_CALLBACK.call_once(|| cb);
}
/// Register the frame-owner setter (arch → kernel_core). Called once at boot.
pub fn register_set_frame_owner_callback(cb: SetFrameOwnerCallback) {
    SET_FRAME_OWNER_CALLBACK.call_once(|| cb);
}
/// Register the raw frame-binding reader (arch → kernel_core). Called once at boot.
pub fn register_get_frame_binding_callback(cb: GetFrameBindingCallback) {
    GET_FRAME_BINDING_CALLBACK.call_once(|| cb);
}
/// Register the raw frame-binding writer (arch → kernel_core). Called once at boot.
pub fn register_set_frame_binding_callback(cb: SetFrameBindingCallback) {
    SET_FRAME_BINDING_CALLBACK.call_once(|| cb);
}

/// R172-04: callback (registered by arch) staging this CPU's pending FS/GS bases that
/// the SYSRET epilogue commits to the MSRs. Used by arch_prctl (W3) and exec TLS reset
/// (W4); kernel_core cannot depend on `arch` directly.
pub type StagePendingTlsBasesCallback = fn(fs_base: u64, gs_base: u64);
pub(super) static STAGE_PENDING_TLS_BASES_CALLBACK: spin::Once<StagePendingTlsBasesCallback> =
    spin::Once::new();
/// Register the FS/GS staging writer (arch → kernel_core). Called once at boot.
pub fn register_stage_pending_tls_bases_callback(cb: StagePendingTlsBasesCallback) {
    STAGE_PENDING_TLS_BASES_CALLBACK.call_once(|| cb);
}
/// R172-04: stage and commit the running task's FS/GS bases (returns `true` if
/// the arch callback ran and committed the live MSRs; `false` only before arch
/// registers the callback).
#[inline]
pub(crate) fn stage_pending_tls_bases(fs_base: u64, gs_base: u64) -> bool {
    if let Some(&cb) = STAGE_PENDING_TLS_BASES_CALLBACK.get() {
        cb(fs_base, gs_base);
        true
    } else {
        false
    }
}

/// M0 item 5 (1b-2): read this CPU's live `(frame_ptr, owner_pid)` binding (or `(0, 0)`
/// if the callback is unregistered). Used to snapshot the binding at syscall entry.
#[inline]
pub(super) fn current_syscall_frame_binding() -> (u64, u64) {
    GET_FRAME_BINDING_CALLBACK.get().map_or((0, 0), |&cb| cb())
}

/// M0 item 5 (1b-2): republish this CPU's `(frame_ptr, owner_pid)` binding from a
/// PCB-saved pair, so the owner-checked mutable accessor yields the live frame after a
/// blocked syscall has resumed (the block zeroed the per-CPU `frame_ptr`).
#[inline]
pub(super) fn publish_syscall_frame_binding(frame_ptr: u64, owner_pid: u64) {
    if let Some(&cb) = SET_FRAME_BINDING_CALLBACK.get() {
        cb(frame_ptr, owner_pid);
    }
}

/// M0 item 5 (1b-2): a frame binding is usable iff the pointer is non-null AND owned by
/// the expected task. Shared by the entry-snapshot gate and the return-tail republish so
/// the two can never diverge.
#[inline]
pub(super) fn is_valid_frame_binding(
    frame_ptr: u64,
    owner_pid: u64,
    expected_pid: ProcessId,
) -> bool {
    frame_ptr != 0 && owner_pid == expected_pid as u64
}

/// M0 #5 (1b-2) self-test: the frame-binding validity predicate AND the arch
/// get/set-binding callback wiring. The republish path only matters on the
/// blocked-resume return tail — which a green boot / musl gate never exercises — so a
/// silent mis-registration of either callback would be invisible to build/test/boot.
/// This exercises both directions of the predicate and a live per-CPU round-trip,
/// restoring the original binding BEFORE asserting so a failure can never strand a
/// bogus per-CPU `frame_ptr`.
pub fn run_saved_frame_binding_self_test() {
    // Predicate: a null pointer never binds (fail-closed defer); an owner mismatch
    // never binds (no cross-task frame redirect); a non-null pointer owned by the
    // expected task binds.
    assert!(
        !is_valid_frame_binding(0, 7, 7),
        "1b-2: null frame_ptr must not bind"
    );
    assert!(
        !is_valid_frame_binding(0x1000, 8, 7),
        "1b-2: owner mismatch must not bind"
    );
    assert!(
        is_valid_frame_binding(0x1000, 7, 7),
        "1b-2: matching non-null binding must bind"
    );

    // Arch round-trip: the get/set-binding callbacks must be registered and write BOTH
    // fields on this CPU. Snapshot the live binding (0 in the boot self-test context),
    // round-trip a sentinel, then RESTORE — the whole snapshot→sentinel→restore window is
    // held under `without_interrupts` so no IRQ on this CPU can ever observe the sentinel
    // in the live per-CPU slot (defense even though no IRQ path reads `frame_ptr`).
    let (rt_ptr, rt_owner) = x86_64::instructions::interrupts::without_interrupts(|| {
        let (orig_ptr, orig_owner) = current_syscall_frame_binding();
        publish_syscall_frame_binding(0xFACE_F00D, 4242);
        let rt = current_syscall_frame_binding();
        publish_syscall_frame_binding(orig_ptr, orig_owner);
        rt
    });
    assert_eq!(rt_ptr, 0xFACE_F00D, "1b-2: frame_ptr binding round-trip");
    assert_eq!(rt_owner, 4242, "1b-2: frame_owner binding round-trip");
}

/// Record `pid` as the owner of the current syscall frame. Called once at the top of
/// the dispatcher so the mutable accessor can reject a stale cross-task frame.
/// Lock-free (a `spin::Once::get` is an atomic-state load after init).
pub fn set_syscall_frame_owner(pid: ProcessId) {
    if let Some(&cb) = SET_FRAME_OWNER_CALLBACK.get() {
        cb(pid as u64);
    }
}

/// Execute a closure with MUTABLE access to the current syscall frame AND its FPU
/// save area, but ONLY when the frame is live and owned by `expected_pid`.
///
/// **R175 D0-CROSS-1 FIX:** This accessor now reads the frame pointer from the PCB's
/// `saved_frame_ptr`/`saved_frame_owner` fields (task-bound storage) rather than
/// from the per-CPU `SYSCALL_PERCPU[current_cpu_id()]` slot. This eliminates the
/// cross-CPU corruption risk: if the target task migrates to a different CPU, the
/// PCB-stored pointer remains correct, whereas the old per-CPU accessor would index
/// the wrong CPU's slot and potentially corrupt an unrelated task's frame.
///
/// Returns `None` when no valid frame is present (task not in syscall, or frame_owner
/// validation fails), safely deferring signal delivery to the next syscall return.
///
/// The closure receives `(&mut SyscallFrame, &mut [u8; 512] fxsave_area)`.
///
/// # Safety
/// The frame pointer must remain valid for the closure's duration. All call sites
/// are from syscall-return paths where the task is actively executing the syscall.
pub fn with_current_syscall_frame_mut<F, R>(expected_pid: ProcessId, f: F) -> Option<R>
where
    F: FnOnce(&mut SyscallFrame, &mut [u8; 512]) -> R,
{
    // R175 D0-CROSS-1 FIX: Read frame pointer from PCB (task-bound), not per-CPU slot.
    // This requires locking the Process, which all call sites can do safely.
    let proc_arc = crate::process::get_process(expected_pid)?;
    let proc = proc_arc.lock();

    let frame_ptr = proc.saved_frame_ptr;
    let owner = proc.saved_frame_owner;

    // Validate: frame must be live (ptr != 0) and owned by the expected task.
    if frame_ptr == 0 || owner != expected_pid as u64 {
        return None;
    }

    // Drop lock before accessing frame (frame is on kernel stack, stable during syscall).
    drop(proc);

    // SAFETY: We validated `frame_ptr` is non-zero and owned by `expected_pid`.
    // The frame is on the task's kernel stack and remains valid during syscall execution.
    // The FPU area is the 512 bytes immediately above the 128-byte frame.
    unsafe {
        let frame = &mut *(frame_ptr as *mut SyscallFrame);
        let fx = &mut *((frame_ptr as usize + SYSCALL_FRAME_BYTES) as *mut [u8; 512]);
        Some(f(frame, fx))
    }
}

/// 管道创建回调类型
///
/// 由 ipc 模块注册，返回 (read_fd, write_fd) 或错误
pub type PipeCreateCallback =
    fn(flags: u32, entry_proc: Option<&ProcessArc>) -> Result<(i32, i32), SyscallError>;

/// 文件描述符读取回调类型
///
/// 由 ipc 模块注册，处理管道等文件描述符的读取
/// R180-L1: the callback owns source commit ordering. It must copy the produced
/// bytes through `copyout` and advance/dequeue the source only after copyout
/// succeeds. This closes sibling-unmap races that bounds preflight cannot pin.
pub type FdReadCallback = fn(
    i32,
    &mut [u8],
    &mut dyn FnMut(&[u8]) -> Result<(), SyscallError>,
    Option<&ProcessArc>,
) -> Result<usize, SyscallError>;

/// 文件描述符写入回调类型
///
/// 由 ipc 模块注册，处理管道等文件描述符的写入
/// 参数: (fd, buf, entry_proc) -> bytes_written 或错误
pub type FdWriteCallback = fn(i32, &[u8], Option<&ProcessArc>) -> Result<usize, SyscallError>;

/// 文件描述符关闭回调类型
///
/// 由 ipc 模块注册，处理文件描述符的关闭
pub type FdCloseCallback = fn(i32, Option<&ProcessArc>) -> Result<(), SyscallError>;

/// Futex 操作回调类型
///
/// 由 ipc 模块注册。参数: (uaddr, request) -> result 或错误。
/// GAP-5 futex parity: `sys_futex` decodes the Linux op word into one
/// [`FutexRequest`] (see the futex section below) and hands it over whole.
pub type FutexCallback = fn(usize, FutexRequest) -> Result<usize, SyscallError>;

/// VFS 打开文件回调类型
///
/// 由 vfs 模块注册，处理文件打开
/// 参数: (path, flags, mode) -> FileOps box 或错误
/// 返回的 FileOps 由 syscall 模块存入 fd_table
#[cfg(feature = "open_fault_probe")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpenFaultProbe {
    None,
    DescriptorAllocation,
    CapabilityAllocation,
    LsmDenial,
    StaleCredentials,
    Success,
}

pub struct PreparedVfsOpen {
    pub(super) descriptor: FileDescriptor,
    pub(super) finalize: fn(&dyn crate::process::FileOps) -> Result<(), SyscallError>,
    #[cfg(feature = "open_fault_probe")]
    pub(super) probe: OpenFaultProbe,
}

impl PreparedVfsOpen {
    pub fn new(
        descriptor: FileDescriptor,
        finalize: fn(&dyn crate::process::FileOps) -> Result<(), SyscallError>,
    ) -> Self {
        Self {
            descriptor,
            finalize,
            #[cfg(feature = "open_fault_probe")]
            probe: OpenFaultProbe::None,
        }
    }

    #[cfg(feature = "open_fault_probe")]
    pub fn with_fault_probe(mut self, probe: OpenFaultProbe) -> Self {
        self.probe = probe;
        self
    }

    pub(super) fn finish_after<Prepared>(
        self,
        preflight: impl FnOnce(&FileDescriptor) -> Result<Prepared, SyscallError>,
    ) -> Result<(FileDescriptor, Prepared), SyscallError> {
        let publication = preflight(&self.descriptor)?;
        (self.finalize)(self.descriptor.as_ref())?;
        Ok((self.descriptor, publication))
    }
}

pub type VfsOpenCallback = fn(
    &str,
    u32,
    u32,
    &crate::process::CredentialAuthorization,
) -> Result<PreparedVfsOpen, SyscallError>;

/// VFS 打开文件回调类型（带 resolve 标志，用于 openat2）
///
/// 由 vfs 模块注册，处理带 resolve 标志的文件打开
/// 参数: (path, flags, mode, resolve_flags) -> FileOps box 或错误
pub type VfsOpenWithResolveCallback = fn(
    &str,
    u32,
    u32,
    u64,
    &crate::process::CredentialAuthorization,
) -> Result<PreparedVfsOpen, SyscallError>;

/// VFS 获取文件状态回调类型
///
/// 由 vfs 模块注册，处理 stat 系统调用
/// 参数: (path) -> (size, mode, ino, dev, nlink, uid, gid, rdev, atime, mtime, ctime) 或错误
pub type VfsStatCallback = fn(&str) -> Result<VfsStat, SyscallError>;

/// M0-4: VFS read-whole-file-by-path-for-exec callback.
///
/// Registered by the vfs module. Resolves `path` to ONE inode (following
/// symlinks + per-component +x traverse), rejects directories (EISDIR) and
/// non-regular files (EACCES), runs the LSM `hook_file_open` MAC gate, enforces
/// a DAC permission check requiring BOTH read AND execute (closing the gap where
/// `open()` only checks read), then reads up to `max` bytes from that SAME inode
/// into a `try_reserve`'d Vec, capped incrementally at `max` (E2BIG on overrun).
/// The single resolution feeds the identical bytes to both the LSM hash and
/// `load_elf`, foreclosing the stat-then-open symlink-swap TOCTOU.
///
/// CONTRACT: the caller MUST hold NO Process / PROCESS_TABLE / page-table / COW
/// lock — this callback acquires those internally (LSM `from_current`, DAC euid).
/// Absent (unregistered) => ENOSYS; it never panics.
/// 参数: (path, max_bytes) -> 文件字节 或错误
pub type VfsReadFileCallback = fn(&str, usize) -> Result<alloc::vec::Vec<u8>, SyscallError>;

/// VFS lseek 回调类型
///
/// 由 vfs 模块注册，处理文件 seek 操作
/// 参数: (file_ops_ref, offset, whence) -> 新偏移位置 或错误
/// file_ops_ref 是通过 as_any 获取的引用
pub type VfsLseekCallback = fn(&dyn core::any::Any, i64, i32) -> Result<u64, SyscallError>;

/// VFS 创建文件/目录回调类型
///
/// 由 vfs 模块注册，处理文件和目录创建
/// 参数: (path, mode, is_dir) -> () 或错误
pub type VfsCreateCallback = fn(&str, u32, bool) -> Result<(), SyscallError>;

/// VFS 删除文件/目录回调类型
///
/// 由 vfs 模块注册，处理文件和目录删除。
/// 参数: (path, must_be_dir) -> () 或错误。
/// must_be_dir: None = 任意类型, Some(true) = 必须是目录 (rmdir), Some(false) = 必须不是目录 (unlink)。
pub type VfsUnlinkCallback = fn(&str, Option<bool>) -> Result<(), SyscallError>;

/// VFS 重命名回调类型 (M0-6 slice 2)
///
/// 由 vfs 模块注册；参数: (old_path, new_path, noreplace) -> () 或错误。
/// `noreplace` 来自 renameat2 的 RENAME_NOREPLACE 标志。
pub type VfsRenameCallback = fn(&str, &str, bool) -> Result<(), SyscallError>;

/// VFS 读取目录项回调类型
///
/// 由 vfs 模块注册，处理目录内容读取
/// R114-2 FIX: Added `max_bytes` parameter to enforce kernel-side memory budget.
/// The callback MUST stop collecting entries once the estimated serialized size
/// (header + name + NUL + alignment) exceeds `max_bytes`. This prevents unbounded
/// kernel heap allocation from large directories, which could trigger OOM panic.
/// R180-L1: the VFS callback keeps the shared directory offset uncommitted
/// until this serializer/copyout callback succeeds.
pub type VfsDirCopyout = fn(*mut u8, usize, &[DirEntry]) -> Result<usize, SyscallError>;
pub type VfsReaddirCallback = fn(i32, usize, *mut u8, VfsDirCopyout) -> Result<usize, SyscallError>;

/// VFS 截断文件回调类型
///
/// 由 vfs 模块注册，处理文件截断操作
/// 参数: (fd, length) -> () 或错误
pub type VfsTruncateCallback = fn(i32, u64) -> Result<(), SyscallError>;

/// ST-K4 durability callbacks, registered together by the VFS.
#[derive(Clone, Copy)]
pub(super) struct VfsDurabilityCallbacks {
    pub(super) fsync: fn(i32) -> Result<(), SyscallError>,
    pub(super) sync: fn() -> Result<(), SyscallError>,
    pub(super) sync_file_range: fn(i32, i64, i64, u32) -> Result<(), SyscallError>,
}

/// VFS positioned read callback type (pread64).
/// Reads from fd at offset without changing the fd's offset.
pub type VfsPreadCallback = fn(i32, &mut [u8], u64) -> Result<usize, SyscallError>;

/// VFS positioned write callback type (pwrite64).
/// Writes to fd at offset without changing the fd's offset.
pub type VfsPwriteCallback = fn(i32, &[u8], u64) -> Result<usize, SyscallError>;

/// VFS symlink creation callback type (M0-6 SLICE 3).
/// Creates a symbolic link at linkpath pointing to target.
pub type VfsSymlinkCallback = fn(&str, &str) -> Result<(), SyscallError>;

/// VFS readlink callback type (M0-6 SLICE 3).
/// Reads the target path of a symbolic link.
/// Returns the target string (not null-terminated).
pub type VfsReadlinkCallback = fn(&str) -> Result<alloc::string::String, SyscallError>;

/// VFS lstat callback type (M0-6 SLICE 3).
/// Stat the LINK itself (no-follow) — backs lstat / fstatat(AT_SYMLINK_NOFOLLOW).
pub type VfsStatNofollowCallback = fn(&str) -> Result<VfsStat, SyscallError>;

/// R74-2 FIX: Mount namespace materialization callback type.
///
/// Registered by vfs module to force eager materialization of mount tables.
/// This prevents security vulnerabilities where lazy materialization allows
/// parent namespace mounts to leak into child namespaces.
///
/// Parameter: Arc<MountNamespace> to materialize
pub type MountNsMaterializeCallback =
    fn(&alloc::sync::Arc<crate::mount_namespace::MountNamespace>) -> Result<(), ()>;
/// R180-22: remove an eagerly materialized table for a namespace that never
/// reached PCB publication. Namespace IDs are globally unique and are the VFS
/// table identity, so rollback cannot target a successor.
pub type MountNsMaterializeRollbackCallback =
    fn(&alloc::sync::Arc<crate::mount_namespace::MountNamespace>);

/// 文件类型枚举(本地定义避免循环依赖)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    CharDevice,
    BlockDevice,
    Symlink,
    Fifo,
    Socket,
}

/// 目录项结构(本地定义避免循环依赖)
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: alloc::string::String,
    pub ino: u64,
    pub file_type: FileType,
    /// RF180-14: filesystem-provided resume cookie for the next readdir call.
    /// Stored in the exact signed Linux ABI domain before serialization.
    pub next_cookie: i64,
}

/// VFS 文件状态信息
///
/// D2-ABI-STAT-LAYOUT FIX: this IS the Linux x86-64 `struct stat` wire layout
/// (arch/x86/include/uapi/asm/stat.h, 144 bytes): dev@0, ino@8, nlink(u64)@16,
/// mode@24, uid@28, gid@32, pad0@36, rdev(u64)@40, size(i64)@48,
/// blksize(i64)@56, blocks(i64)@64, atim@72, mtim@88, ctim@104, unused@120.
/// musl reads these exact offsets — the former 112-byte private layout
/// misparsed under every musl `stat()`/`fstat()` caller (st_mode was read from
/// what the kernel wrote as uid). The layout has ZERO implicit padding:
/// `pad0`/`unused*` are explicit fields, always written as 0
/// (`copy_vfs_stat_to_user` serializes into a zeroed buffer). Enforced by
/// `make abi-check` (Leg-B reference table + Leg-C gcc offsetof cross-check)
/// and the Ring-3 `MUSL-STAT-OK` smoke.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VfsStat {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub pad0: u32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub unused0: i64,
    pub unused1: i64,
    pub unused2: i64,
}

// D2-ABI-STAT-LAYOUT: Linux x86-64 struct stat is exactly 144 bytes, align 8,
// with no implicit padding (the two former gaps are explicit fields now).
const _: [(); 144] = [(); core::mem::size_of::<VfsStat>()];
const _: [(); 8] = [(); core::mem::align_of::<VfsStat>()];

/// Lock-free hot-path syscall callbacks (registered once at boot by `ipc::init`;
/// read via single Acquire load on every pipe/read/write/close syscall).
pub(super) static PIPE_CREATE_CALLBACK: spin::Once<PipeCreateCallback> = spin::Once::new();
pub(super) static FD_READ_CALLBACK: spin::Once<FdReadCallback> = spin::Once::new();
pub(super) static FD_WRITE_CALLBACK: spin::Once<FdWriteCallback> = spin::Once::new();
pub(super) static FD_CLOSE_CALLBACK: spin::Once<FdCloseCallback> = spin::Once::new();

#[inline]
pub(super) fn get_pipe_create_callback() -> Option<PipeCreateCallback> {
    PIPE_CREATE_CALLBACK.get().copied()
}

#[inline]
pub(super) fn get_fd_read_callback() -> Option<FdReadCallback> {
    FD_READ_CALLBACK.get().copied()
}

#[inline]
pub(super) fn get_fd_write_callback() -> Option<FdWriteCallback> {
    FD_WRITE_CALLBACK.get().copied()
}

#[inline]
pub(super) fn get_fd_close_callback() -> Option<FdCloseCallback> {
    FD_CLOSE_CALLBACK.get().copied()
}

lazy_static::lazy_static! {
    /// Futex 操作回调
    pub(super) static ref FUTEX_CALLBACK: spin::Mutex<Option<FutexCallback>> = spin::Mutex::new(None);
    /// VFS 打开文件回调
    pub(super) static ref VFS_OPEN_CALLBACK: spin::Mutex<Option<VfsOpenCallback>> = spin::Mutex::new(None);
    /// VFS 带 resolve 标志的打开文件回调 (openat2)
    pub(super) static ref VFS_OPEN_WITH_RESOLVE_CALLBACK: spin::Mutex<Option<VfsOpenWithResolveCallback>> = spin::Mutex::new(None);
    /// VFS stat 回调
    pub(super) static ref VFS_STAT_CALLBACK: spin::Mutex<Option<VfsStatCallback>> = spin::Mutex::new(None);
    /// M0-4: VFS read-whole-file-for-exec 回调
    pub(super) static ref VFS_READ_FILE_CALLBACK: spin::Mutex<Option<VfsReadFileCallback>> = spin::Mutex::new(None);
    /// VFS lseek 回调
    pub(super) static ref VFS_LSEEK_CALLBACK: spin::Mutex<Option<VfsLseekCallback>> = spin::Mutex::new(None);
    /// VFS 创建回调
    pub(super) static ref VFS_CREATE_CALLBACK: spin::Mutex<Option<VfsCreateCallback>> = spin::Mutex::new(None);
    /// VFS 删除回调
    pub(super) static ref VFS_UNLINK_CALLBACK: spin::Mutex<Option<VfsUnlinkCallback>> = spin::Mutex::new(None);
    /// VFS 重命名回调 (M0-6 slice 2)
    pub(super) static ref VFS_RENAME_CALLBACK: spin::Mutex<Option<VfsRenameCallback>> = spin::Mutex::new(None);
    /// VFS 读取目录回调
    pub(super) static ref VFS_READDIR_CALLBACK: spin::Mutex<Option<VfsReaddirCallback>> = spin::Mutex::new(None);
    /// VFS 截断回调
    pub(super) static ref VFS_TRUNCATE_CALLBACK: spin::Mutex<Option<VfsTruncateCallback>> = spin::Mutex::new(None);
    /// ST-K4 durability callbacks
    pub(super) static ref VFS_DURABILITY_CALLBACKS: spin::Mutex<Option<VfsDurabilityCallbacks>> = spin::Mutex::new(None);
    /// VFS positioned read callback (pread64)
    pub(super) static ref VFS_PREAD_CALLBACK: spin::Mutex<Option<VfsPreadCallback>> = spin::Mutex::new(None);
    /// VFS positioned write callback (pwrite64)
    pub(super) static ref VFS_PWRITE_CALLBACK: spin::Mutex<Option<VfsPwriteCallback>> = spin::Mutex::new(None);
    /// VFS symlink creation callback (M0-6 SLICE 3)
    pub(super) static ref VFS_SYMLINK_CALLBACK: spin::Mutex<Option<VfsSymlinkCallback>> = spin::Mutex::new(None);
    /// VFS readlink callback (M0-6 SLICE 3)
    pub(super) static ref VFS_READLINK_CALLBACK: spin::Mutex<Option<VfsReadlinkCallback>> = spin::Mutex::new(None);
    /// VFS lstat (no-follow) callback (M0-6 SLICE 3)
    pub(super) static ref VFS_STAT_NOFOLLOW_CALLBACK: spin::Mutex<Option<VfsStatNofollowCallback>> = spin::Mutex::new(None);
    /// R74-2 FIX: Mount namespace materialization callback
    pub(super) static ref MOUNT_NS_MATERIALIZE_CALLBACK: spin::Mutex<Option<MountNsMaterializeCallback>> = spin::Mutex::new(None);
    pub(super) static ref MOUNT_NS_MATERIALIZE_ROLLBACK_CALLBACK: spin::Mutex<Option<MountNsMaterializeRollbackCallback>> = spin::Mutex::new(None);
}

/// 注册管道创建回调
pub fn register_pipe_callback(cb: PipeCreateCallback) {
    PIPE_CREATE_CALLBACK.call_once(|| cb);
}

/// 注册文件描述符读取回调
pub fn register_fd_read_callback(cb: FdReadCallback) {
    FD_READ_CALLBACK.call_once(|| cb);
}

/// 注册文件描述符写入回调
pub fn register_fd_write_callback(cb: FdWriteCallback) {
    FD_WRITE_CALLBACK.call_once(|| cb);
}

/// 注册文件描述符关闭回调
pub fn register_fd_close_callback(cb: FdCloseCallback) {
    FD_CLOSE_CALLBACK.call_once(|| cb);
}

/// 注册 Futex 操作回调
pub fn register_futex_callback(cb: FutexCallback) {
    *FUTEX_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 打开文件回调
pub fn register_vfs_open_callback(cb: VfsOpenCallback) {
    *VFS_OPEN_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 带 resolve 标志的打开文件回调 (openat2)
pub fn register_vfs_open_with_resolve_callback(cb: VfsOpenWithResolveCallback) {
    *VFS_OPEN_WITH_RESOLVE_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS stat 回调
pub fn register_vfs_stat_callback(cb: VfsStatCallback) {
    *VFS_STAT_CALLBACK.lock() = Some(cb);
}

/// M0-4: 注册 VFS read-whole-file-for-exec 回调
pub fn register_vfs_read_file_callback(cb: VfsReadFileCallback) {
    *VFS_READ_FILE_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS lseek 回调
pub fn register_vfs_lseek_callback(cb: VfsLseekCallback) {
    *VFS_LSEEK_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 创建回调
pub fn register_vfs_create_callback(cb: VfsCreateCallback) {
    *VFS_CREATE_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 删除回调
pub fn register_vfs_unlink_callback(cb: VfsUnlinkCallback) {
    *VFS_UNLINK_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 重命名回调 (M0-6 slice 2)
pub fn register_vfs_rename_callback(cb: VfsRenameCallback) {
    *VFS_RENAME_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 读取目录回调
pub fn register_vfs_readdir_callback(cb: VfsReaddirCallback) {
    *VFS_READDIR_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS 截断回调
pub fn register_vfs_truncate_callback(cb: VfsTruncateCallback) {
    *VFS_TRUNCATE_CALLBACK.lock() = Some(cb);
}

/// ST-K4: register fsync/fdatasync, sync and sync_file_range.
pub fn register_vfs_durability_callbacks(
    fsync: fn(i32) -> Result<(), SyscallError>,
    sync: fn() -> Result<(), SyscallError>,
    sync_file_range: fn(i32, i64, i64, u32) -> Result<(), SyscallError>,
) {
    *VFS_DURABILITY_CALLBACKS.lock() = Some(VfsDurabilityCallbacks {
        fsync,
        sync,
        sync_file_range,
    });
}

/// 注册 VFS positioned read 回调 (pread64)
pub fn register_vfs_pread_callback(cb: VfsPreadCallback) {
    *VFS_PREAD_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS positioned write 回调 (pwrite64)
pub fn register_vfs_pwrite_callback(cb: VfsPwriteCallback) {
    *VFS_PWRITE_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS symlink 创建回调 (M0-6 SLICE 3)
pub fn register_vfs_symlink_callback(cb: VfsSymlinkCallback) {
    *VFS_SYMLINK_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS readlink 回调 (M0-6 SLICE 3)
pub fn register_vfs_readlink_callback(cb: VfsReadlinkCallback) {
    *VFS_READLINK_CALLBACK.lock() = Some(cb);
}

/// 注册 VFS lstat (no-follow) 回调 (M0-6 SLICE 3)
pub fn register_vfs_stat_nofollow_callback(cb: VfsStatNofollowCallback) {
    *VFS_STAT_NOFOLLOW_CALLBACK.lock() = Some(cb);
}

/// R74-2 FIX: Register mount namespace materialization callback.
///
/// The VFS module **must** call this at initialization to register the function
/// that materializes mount namespace tables. This forces eager table creation
/// to prevent parent namespace mounts from leaking into child namespaces.
///
/// # R74-2 Enhancement
///
/// Missing registration will panic during namespace creation to avoid silent
/// isolation bypasses. This enforces proper initialization order: VFS callbacks
/// must be registered before any namespace operations (clone/unshare with CLONE_NEWNS).
pub fn register_mount_ns_materialize_callback(cb: MountNsMaterializeCallback) {
    *MOUNT_NS_MATERIALIZE_CALLBACK.lock() = Some(cb);
}

pub fn register_mount_ns_materialize_rollback_callback(cb: MountNsMaterializeRollbackCallback) {
    *MOUNT_NS_MATERIALIZE_ROLLBACK_CALLBACK.lock() = Some(cb);
}

/// R74-2 Test Helper: Check if mount namespace materialization callback is registered.
///
/// Used by runtime tests to verify the R74-2 fix is properly initialized.
/// Returns true if the callback is registered, false otherwise.
pub fn test_is_mount_ns_callback_registered() -> bool {
    MOUNT_NS_MATERIALIZE_CALLBACK.lock().is_some()
}

/// R74-2 FIX: Mandatory mount namespace materialization.
///
/// Private helper used by sys_clone and sys_unshare to ensure mount tables are
/// eagerly materialized when namespaces are created.
///
/// # R74-2 Enhancement: Panic if Callback Absent
///
/// This function will panic if the VFS has not registered the materialization
/// callback. This prevents silent isolation bypasses where namespace operations
/// could proceed without proper mount table snapshots, potentially leaking
/// parent namespace mounts to child namespaces.
///
/// # Returns
///
/// `Err(())` if the VFS callback could not materialize the table (OOM); the caller maps it to
/// ENOMEM (R172-22-FOLLOWON). A silently-dropped failure would reintroduce the R74-2
/// lazy-materialization namespace mount-leak, so the error MUST propagate.
///
/// # Panics
///
/// Panics with a critical error if `register_mount_ns_materialize_callback()`
/// was not called before this function is invoked.
pub(super) fn materialize_namespace(
    ns: &Arc<crate::mount_namespace::MountNamespace>,
) -> Result<(), ()> {
    // R74-2 Enhancement: Mandatory callback - panic if not registered.
    // Copy the fn pointer out immediately to avoid holding lock during callback.
    // MountNsMaterializeCallback is `fn(...)` which is Copy, so we dereference
    // to copy the pointer and release the mutex before invoking.
    let cb = *MOUNT_NS_MATERIALIZE_CALLBACK.lock().as_ref().expect(
        "CRITICAL: Mount namespace materialization callback not registered! \
         VFS must call register_mount_ns_materialize_callback() before any \
         namespace operations (clone/unshare with CLONE_NEWNS). This is a \
         kernel initialization bug.",
    );
    cb(ns)
}

pub(super) fn rollback_materialized_namespace(ns: &Arc<crate::mount_namespace::MountNamespace>) {
    let cb = *MOUNT_NS_MATERIALIZE_ROLLBACK_CALLBACK
        .lock()
        .as_ref()
        .expect("CRITICAL: mount namespace materialization rollback callback not registered");
    cb(ns);
}

/// Owns the VFS table of a newly-created mount namespace until the namespace
/// is published into a live PCB. Every pre-publication error removes the exact
/// globally-unique namespace ID from the VFS registry.
pub(super) struct PreparedMountTableGuard {
    pub(super) ns: Arc<crate::mount_namespace::MountNamespace>,
    pub(super) armed: bool,
}

impl PreparedMountTableGuard {
    pub(super) fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for PreparedMountTableGuard {
    fn drop(&mut self) {
        if self.armed {
            rollback_materialized_namespace(&self.ns);
        }
    }
}

// ============================================================================
// VFS 辅助函数
// ============================================================================

/// S_IFDIR 常量 - 目录类型标识
pub(super) const S_IFDIR: u32 = 0o040000;
/// S_IFMT 常量 - 文件类型掩码
pub(super) const S_IFMT: u32 = 0o170000;

/// 检查 mode 是否表示目录
#[inline]
pub(super) fn is_directory_mode(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
}

/// 用户空间地址上界
///
/// x86_64 规范地址空间中，用户空间使用低半区（0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF）
/// 内核空间使用高半区（0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF）
pub(super) const USER_SPACE_TOP: usize = 0x0000_8000_0000_0000;

/// sys_exec 允许的最大 ELF 映像大小（P2-A transient peak = HEAP/4 = 256 KiB）
///
/// R151-1 FIX: Reduced from 16 MiB because the kernel heap is only 1 MiB
/// (HEAP_SIZE); a large limit allowed infallible vec! allocation to exhaust the
/// heap and trigger the alloc_error_handler panic — a deterministic kernel crash
/// from unprivileged userspace. P2-A further binds this to the heap-budget
/// arbiter's `ExecImagePeak` slot (HEAP/4) so the peak coexists with retained
/// hard floors + reserved headroom without over-commit. Concurrent exec paths
/// must hold `mm::TransientPeakGuard` while the staging buffer is live.
pub(super) const MAX_EXEC_IMAGE_SIZE: usize = mm::budget_bytes(mm::HeapBudgetId::ExecImagePeak);

// M0-4 (exec disambiguation) limits.
/// First-line scan window for a `#!` shebang (Linux BINPRM_BUF_SIZE-class).
pub(super) const MAX_SHEBANG_LINE: usize = 256;
/// Interpreter-chain depth cap for nested shebangs; exceeding it returns ELOOP.
pub(super) const MAX_SHEBANG_DEPTH: usize = 4;
/// Hard cap (PATH_MAX-class) on an execve pathname / shebang interpreter token.
pub(super) const MAX_EXEC_PATH_LEN: usize = 4096;

/// R41-4 FIX: 用于 LSM 策略检查的 ELF 前缀哈希长度
///
/// 对 ELF 二进制内容的前 4KB 计算 SHA-256 哈希，替代使用 argv[0] 路径。
/// 这防止了攻击者通过伪造 argv[0] 绕过 LSM 策略。
pub(super) const EXEC_HASH_WINDOW: usize = 4096;

// mmap 跟踪已移至 Process 结构体的 mmap_regions 和 next_mmap_addr 字段

/// 验证用户空间指针
///
/// 检查指针是否：
/// 1. 非空
/// 2. 长度有效（非零）
/// 3. 地址范围在用户空间内（不会访问内核内存）
/// 4. 不会发生地址回绕
///
/// # Arguments
/// * `ptr` - 用户提供的指针
/// * `len` - 要访问的字节数
///
/// # Returns
/// 如果指针有效返回 Ok(()), 否则返回 EFAULT 错误
pub(super) fn validate_user_ptr(ptr: *const u8, len: usize) -> Result<(), SyscallError> {
    // 空指针检查
    if ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // 零长度检查
    if len == 0 {
        return Err(SyscallError::EFAULT);
    }

    let start = ptr as usize;

    // R101-7 FIX: Reject pointers below MMAP_MIN_ADDR to prevent NULL dereference
    // exploitation. If a kernel NULL pointer dereference bug exists and a user can
    // map page 0 through a path that bypasses sys_mmap(), validate_user_ptr() would
    // otherwise accept the low address. This provides defense-in-depth matching the
    // MMAP_MIN_ADDR enforcement already in sys_mmap() and usercopy::is_user_range().
    if start < crate::usercopy::MMAP_MIN_ADDR {
        return Err(SyscallError::EFAULT);
    }

    // 地址回绕检查
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(SyscallError::EFAULT),
    };

    // 用户空间边界检查：确保整个缓冲区都在用户空间内
    // R154-I5 FIX: This uses `>` (end > USER_SPACE_TOP) while usercopy::validate_user_range()
    // uses `<` (end < USER_SPACE_TOP). The difference is intentional:
    //   - validate_user_ptr: `end > USER_SPACE_TOP` rejects end == TOP+1 but allows end == TOP.
    //     Since len >= 1 is enforced above, end == TOP means the last byte is at TOP-1 (valid).
    //   - validate_user_range: `end < USER_SPACE_TOP` is stricter, rejecting end == TOP.
    //     This is conservative for usercopy where USER_SPACE_TOP itself is never a valid byte.
    // Both are safe: the canonical hole starts at USER_SPACE_TOP, so the strictest correct
    // bound is `end <= USER_SPACE_TOP` (which `end > TOP` implements via negation).
    if end > USER_SPACE_TOP {
        return Err(SyscallError::EFAULT);
    }

    Ok(())
}

/// 验证用户空间可写指针
///
/// 与 validate_user_ptr 相同的检查，用于写入操作
#[inline]
pub(super) fn validate_user_ptr_mut(ptr: *mut u8, len: usize) -> Result<(), SyscallError> {
    validate_user_ptr(ptr as *const u8, len)
}

/// Get audit subject from current process context
///
/// Returns AuditSubject with pid, uid, gid from current process credentials.
/// Falls back to kernel subject (pid 0) if no current process.
#[inline]
pub(super) fn get_audit_subject() -> AuditSubject {
    if let Some(pid) = current_pid() {
        if let Some(creds) = crate::process::current_credentials() {
            AuditSubject::new(pid as u32, creds.euid, creds.egid, None)
        } else {
            // Process exists but credentials unavailable
            AuditSubject::new(pid as u32, 0, 0, None)
        }
    } else {
        AuditSubject::kernel()
    }
}

// ============================================================================
// LSM Integration Helpers
// ============================================================================

/// Map LSM errors to syscall errno values.
#[inline]
/// U.S2-SLICE-3: `pub` for the same reason as `lsm_process_ctx_from` — one
/// canonical LsmError→errno mapping shared with out-of-crate cap-install sites.
pub fn lsm_error_to_syscall(err: lsm::LsmError) -> SyscallError {
    match err {
        lsm::LsmError::Denied => SyscallError::EPERM,
        lsm::LsmError::Internal => SyscallError::EPERM,
    }
}

/// R26-6 FIX: Map capability errors to syscall errno values.
///
/// This ensures proper error reporting when capability operations fail,
/// rather than silently swallowing errors.
///
/// U.S2-SLICE-3: `pub` — the pipe cap-install site (ipc crate) maps CapError
/// through this same canonical table (TableFull→EMFILE, OutOfMemory→ENOMEM).
#[inline]
pub fn cap_error_to_syscall(err: cap::CapError) -> SyscallError {
    match err {
        cap::CapError::TableFull => SyscallError::EMFILE,
        cap::CapError::GenerationExhausted => SyscallError::ERANGE, // No EOVERFLOW, use ERANGE
        cap::CapError::InvalidCapId => SyscallError::EBADF,
        cap::CapError::DelegationDenied => SyscallError::EPERM,
        cap::CapError::InsufficientRights => SyscallError::EPERM,
        cap::CapError::InvalidOperation => SyscallError::EINVAL,
        cap::CapError::NoCurrentProcess => SyscallError::ESRCH,
        // R172-06: table-grow OOM is memory pressure (ENOMEM), distinct from the EMFILE
        // MAX_CAP_SLOTS ceiling.
        cap::CapError::OutOfMemory => SyscallError::ENOMEM,
    }
}

/// Map socket layer errors to syscall errno values.
///
/// Used by sys_socket/sys_bind/sys_sendto/sys_recvfrom to convert
/// SocketError into appropriate Linux errno codes.
#[inline]
pub(super) fn socket_error_to_syscall(err: net::SocketError) -> SyscallError {
    match err {
        net::SocketError::InvalidDomain => SyscallError::EAFNOSUPPORT,
        net::SocketError::InvalidType => SyscallError::EPROTOTYPE,
        net::SocketError::InvalidProtocol => SyscallError::EPROTONOSUPPORT,
        net::SocketError::PermissionDenied | net::SocketError::PrivilegedPort => {
            SyscallError::EACCES
        }
        net::SocketError::PortInUse => SyscallError::EADDRINUSE,
        net::SocketError::NoPorts => SyscallError::EAGAIN,
        net::SocketError::NotBound => SyscallError::EDESTADDRREQ,
        net::SocketError::Closed | net::SocketError::NotFound => SyscallError::EBADF,
        net::SocketError::Timeout => SyscallError::ETIMEDOUT,
        net::SocketError::MessageTooLarge => SyscallError::EMSGSIZE,
        net::SocketError::NoProcess => SyscallError::ESRCH,
        net::SocketError::AlreadyConnected => SyscallError::EISCONN,
        net::SocketError::InProgress => SyscallError::EINPROGRESS,
        net::SocketError::WouldBlock => SyscallError::EAGAIN,
        net::SocketError::InvalidState => SyscallError::ENOTCONN,
        // R76-3 FIX: Per-namespace socket quota exceeded maps to EAGAIN (retriable)
        net::SocketError::QuotaExceeded => SyscallError::EAGAIN,
        net::SocketError::Udp(net::UdpError::PayloadTooLarge) => SyscallError::EMSGSIZE,
        net::SocketError::Udp(_) => SyscallError::EINVAL,
        // R107-5 FIX: Socket ID counter overflow (u64 exhaustion) maps to ENOSPC
        net::SocketError::IdExhausted => SyscallError::ENOSPC,
        net::SocketError::Lsm(e) => lsm_error_to_syscall(e),
        net::SocketError::NoMemory => SyscallError::ENOMEM,
        // R171-F3: a blocking socket op interrupted by a pending kill -> EINTR.
        net::SocketError::Interrupted => SyscallError::EINTR,
    }
}

/// Map network TX errors to syscall errno values.
///
/// Used when transmitting TCP segments or UDP datagrams via the network device.
#[inline]
pub(super) fn tx_error_to_syscall(err: net::TxError) -> SyscallError {
    match err {
        net::TxError::QueueFull => SyscallError::EAGAIN,
        net::TxError::LinkDown => SyscallError::ENETDOWN,
        net::TxError::FirewallDenied => SyscallError::EPERM,
        // D3 NETNS-ROUTING: Local (until TX-loopback delivers) and
        // Unroutable destinations fail closed as network-unreachable.
        net::TxError::Unreachable => SyscallError::ENETUNREACH,
        // D3 PENDING-FRAME v2: an unresolved on-link neighbor is
        // host-unreachable (Linux neighbor-resolution-failure errno). The
        // production TX path parks instead of returning this; it surfaces
        // only through resolution seams and the pre-registration window.
        net::TxError::NeighborUnresolved => SyscallError::EHOSTUNREACH,
        net::TxError::InvalidBuffer => SyscallError::EINVAL,
        net::TxError::NoMemory => SyscallError::ENOMEM,
        net::TxError::NoBuffers => SyscallError::ENOBUFS,
        net::TxError::IoError => SyscallError::EIO,
    }
}

/// Build an LSM ProcessCtx from current process state.
/// Returns None if no current process is available.
#[inline]
pub(super) fn lsm_current_process_ctx() -> Option<lsm::ProcessCtx> {
    lsm::ProcessCtx::from_current()
}

/// Build an LSM ProcessCtx from a locked Process struct.
#[inline]
/// U.S2-SLICE-3: `pub` so cap-allocating fd-install sites OUTSIDE kernel_core
/// (ipc::pipe_create_callback) build the LSM subject from the SAME canonical
/// constructor as the in-crate sites (sys_socket/sys_accept) — a locked-proc
/// snapshot of the CURRENT credentials (CRITICAL-3: never VFS-cached values).
pub fn lsm_process_ctx_from(
    proc: &crate::process::Process,
) -> Result<lsm::ProcessCtx, SyscallError> {
    let creds = proc.try_credentials_read().ok_or(SyscallError::EAGAIN)?;
    Ok(lsm_process_ctx_from_credentials(proc, &creds))
}

/// Build an LSM subject from credentials whose read guard is already held.
///
/// R186 review-fix: authorization transactions use this form so the same
/// credential state remains immutable through capability/FD publication.
#[inline]
pub fn lsm_process_ctx_from_credentials(
    proc: &crate::process::Process,
    creds: &crate::process::Credentials,
) -> lsm::ProcessCtx {
    lsm::ProcessCtx::new(
        proc.pid, proc.tgid, creds.uid, creds.gid, creds.euid, creds.egid,
    )
}

/// Enforce task_fork LSM hook after fork/clone succeeds.
/// On denial, cleans up the child process and returns EPERM.
///
/// # H.0.9 Restriction
///
/// This function uses `cleanup_unscheduled_process()` which skips cpuset/cgroup
/// teardown. It is ONLY safe to call on children created via `create_process()`
/// that were never passed through `fork_inner()` (i.e., the CLONE_VM main path
/// in sys_clone). For fork-based children where fork_inner ran (cpuset joined,
/// cgroup attached), callers must inline the LSM check and use
/// `request_process_exit()` + scheduler enqueue instead.
pub(super) fn enforce_lsm_task_fork(
    parent_pid: ProcessId,
    child_pid: ProcessId,
    child_credentials: &Arc<crate::process::SharedCredentials>,
) -> Result<(), SyscallError> {
    enforce_lsm_task_fork_with(parent_pid, child_pid, child_credentials, |parent, child| {
        lsm::hook_task_fork(parent, child).map_err(lsm_error_to_syscall)
    })
}

pub(super) fn enforce_lsm_task_fork_with(
    parent_pid: ProcessId,
    child_pid: ProcessId,
    child_credentials: &Arc<crate::process::SharedCredentials>,
    hook: impl FnOnce(&lsm::ProcessCtx, &lsm::ProcessCtx) -> Result<(), SyscallError>,
) -> Result<(), SyscallError> {
    // KSA-010: the prepared Arc is the exact identity installed after scheduler
    // reservation. Before that boundary the child's default credentials must
    // neither authorize the clone nor be replaced while its state is Ready.
    // Every lookup/read/hook error shares the same post-lock cleanup envelope.
    let result = (|| {
        let parent_arc = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;
        let child_arc = get_process(child_pid).ok_or(SyscallError::ESRCH)?;
        let (parent_ctx, child_ctx) = {
            let parent = parent_arc.lock();
            let child = child_arc.lock();
            let credentials = child_credentials.try_read().ok_or(SyscallError::EAGAIN)?;
            (
                lsm_process_ctx_from(&parent)?,
                lsm_process_ctx_from_credentials(&child, &credentials),
            )
        };
        hook(&parent_ctx, &child_ctx)
    })();

    if result.is_err() {
        // Rollback: remove child from parent's children list and terminate
        if let Some(parent) = get_process(parent_pid) {
            let mut parent = parent.lock();
            parent.children.retain(|&pid| pid != child_pid);
        }
        // Use exit code 128 + signal (SIGSYS=31) to indicate security termination
        // H.0.9 FIX: Child was never scheduled — use cleanup_unscheduled_process to
        // avoid cgroup/cpuset/IPC detach on never-joined subsystems.
        cleanup_unscheduled_process(child_pid);
    }
    result
}

#[cfg(all(test, feature = "host_harness", not(target_os = "none")))]
mod clone_credential_lsm_tests {
    use super::*;
    use crate::process::{child_creation_test_support::Fixture, Credentials, SharedCredentials};

    fn prospective() -> Arc<SharedCredentials> {
        Arc::new(SharedCredentials::new(Credentials {
            uid: 70001,
            gid: 70002,
            euid: 70001,
            egid: 70002,
            supplementary_groups: mm::AdmittedVec::new(mm::HeapClass::CoreProcess),
        }))
    }

    #[test]
    fn credential_lifecycle_lsm_checks_prospective_identity() {
        let fixture = Fixture::new();
        let (parent_pid, child_pid) = fixture.pids();
        let selected = prospective();
        let called = core::cell::Cell::new(false);
        enforce_lsm_task_fork_with(parent_pid, child_pid, &selected, |parent, child| {
            assert_eq!((parent.pid, parent.uid), (parent_pid, 65534));
            assert_eq!((child.pid, child.uid, child.gid), (child_pid, 70001, 70002));
            assert_eq!(
                fixture.child.lock().try_credentials_read().unwrap().uid,
                65534
            );
            called.set(true);
            Ok(())
        })
        .unwrap();
        assert!(called.get());
        assert!(get_process(child_pid).is_some());
        assert!(fixture.parent.lock().children.contains(&child_pid));
        assert_eq!(fixture.child.lock().state, ProcessState::Ready);
    }

    #[test]
    fn credential_lifecycle_lsm_denial_and_contention_cleanup() {
        for busy in 0..3 {
            let fixture = Fixture::new();
            let (parent_pid, child_pid) = fixture.pids();
            let selected = prospective();
            let parent_identity = fixture.parent.lock().shared_credentials();
            let called = core::cell::Cell::new(false);
            let check = || {
                enforce_lsm_task_fork_with(parent_pid, child_pid, &selected, |_, child| {
                    assert_eq!(child.uid, 70001);
                    called.set(true);
                    Err(SyscallError::EPERM)
                })
            };
            let result = match busy {
                1 => parent_identity.with_hosted_pending_writer(check),
                2 => selected.with_hosted_pending_writer(check),
                _ => check(),
            };
            assert_eq!(
                result,
                Err(if busy == 0 {
                    SyscallError::EPERM
                } else {
                    SyscallError::EAGAIN
                })
            );
            assert_eq!(called.get(), busy == 0);
            fixture.assert_child_removed();
        }
    }
}

// ============================================================================
// R65-13 FIX: Capability Operation Wrappers with LSM/Audit Integration
// ============================================================================

/// Allocate a capability with LSM check and audit logging.
///
/// # Security
///
/// 1. Calls LSM hook_task_cap_modify before allocation
/// 2. If LSM denies, returns EPERM without allocating
/// 3. On success, emits audit event for tracking
///
/// # Arguments
///
/// * `cap_table` - The capability table to allocate in
/// * `entry` - The capability entry to allocate
/// * `proc_ctx` - Process context for LSM check
///
/// # Returns
///
/// * `Ok(CapId)` - The allocated capability ID
/// * `Err(SyscallError)` - LSM denied or allocation failed
/// U.S2-SLICE-3: `pub` — the pipe cap-install site (ipc::pipe_create_callback)
/// allocates both pipe-end caps through this same LSM-gated, audit-emitting
/// composition instead of hand-rolling the hook/allocate/audit sequence.
/// Opaque two-phase capability mint. The reservation owns the authorization
/// token and canonical LSM subject, so callers cannot mix a subject from one
/// process with another process's capability table or outlive the credential
/// state that was mediated.
pub struct AuthorizedCapReservation<'a> {
    pub(super) capability: cap::PreparedCapAllocation<'a>,
    pub(super) proc_ctx: lsm::ProcessCtx,
    pub(super) _authorization: crate::process::CredentialAuthorization,
}

impl<'a> AuthorizedCapReservation<'a> {
    pub(crate) fn new(
        capability: cap::PreparedCapAllocation<'a>,
        proc_ctx: lsm::ProcessCtx,
        authorization: crate::process::CredentialAuthorization,
    ) -> Self {
        Self {
            capability,
            proc_ctx,
            _authorization: authorization,
        }
    }

    #[inline]
    pub fn cap_id(&self) -> cap::CapId {
        self.capability.cap_id()
    }

    #[inline]
    pub(super) fn process_context(&self) -> &lsm::ProcessCtx {
        &self.proc_ctx
    }

    pub fn install(self, entry: cap::CapEntry) -> AuthorizedCapGrant {
        let Self {
            capability,
            proc_ctx,
            _authorization,
        } = self;
        let cap_id = capability.install(entry);
        AuthorizedCapGrant {
            pending_audit: PendingCapAllocationAudit::new(
                cap_id,
                proc_ctx,
                _authorization,
                KernelCapAllocationAuditEmitter,
            ),
        }
    }
}

/// Cross-crate broker entry point. The capability-table authority is obtained
/// from the exact locked Process and never exposed to the caller; the returned
/// reservation still owns the credential authorization through publication.
pub(super) fn prepare_cap_allocation_authorized<'a>(
    process: &crate::process::Process,
    authority: &'a crate::process::CapabilityTableAuthority,
    authorization: crate::process::CredentialAuthorization,
) -> Result<AuthorizedCapReservation<'a>, SyscallError> {
    process.prepare_capability_allocation_authorized(authority, authorization)
}

pub fn prepare_process_cap_allocation_authorized<'a>(
    process: &crate::process::Process,
    authority: &'a crate::process::CapabilityTableAuthority,
    authorization: crate::process::CredentialAuthorization,
) -> Result<AuthorizedCapReservation<'a>, SyscallError> {
    prepare_cap_allocation_authorized(process, authority, authorization)
}

#[must_use = "installed capability grants must complete allocation audit"]
pub struct AuthorizedCapGrant {
    // This RAII object also owns the credential authorization. Its Drop runs
    // the audit fallback before any field (including the authorization token)
    // is released, preserving the mediated subject through observation.
    pub(super) pending_audit: PendingCapAllocationAudit<
        KernelCapAllocationAuditEmitter,
        crate::process::CredentialAuthorization,
    >,
}

pub(super) trait CapAllocationAuditEmitter {
    fn emit(&self, proc_ctx: &lsm::ProcessCtx, cap_id: cap::CapId);
}

pub(super) struct KernelCapAllocationAuditEmitter;

impl CapAllocationAuditEmitter for KernelCapAllocationAuditEmitter {
    #[inline]
    fn emit(&self, proc_ctx: &lsm::ProcessCtx, cap_id: cap::CapId) {
        emit_cap_allocate_audit(proc_ctx, cap_id);
    }
}

/// Exactly-once audit owner for one already-published capability. The
/// authorization proof is deliberately retained inside this Drop-bearing
/// object, so both explicit completion and fallback emission observe the exact
/// credential identity that was mediated through publication.
pub(super) struct PendingCapAllocationAudit<E: CapAllocationAuditEmitter, A> {
    pub(super) cap_id: cap::CapId,
    pub(super) proc_ctx: lsm::ProcessCtx,
    pub(super) _authorization: A,
    pub(super) emitter: E,
    pub(super) pending: bool,
}

impl<E: CapAllocationAuditEmitter, A> PendingCapAllocationAudit<E, A> {
    pub(super) fn new(
        cap_id: cap::CapId,
        proc_ctx: lsm::ProcessCtx,
        authorization: A,
        emitter: E,
    ) -> Self {
        Self {
            cap_id,
            proc_ctx,
            _authorization: authorization,
            emitter,
            pending: true,
        }
    }

    #[inline]
    pub(super) fn emit_once(&mut self) {
        if self.pending {
            // Disarm first. Audit emission is currently non-panicking, but this
            // ordering also prevents a future re-entrant/unwinding path from
            // reporting the same successful allocation twice.
            self.pending = false;
            self.emitter.emit(&self.proc_ctx, self.cap_id);
        }
    }

    pub(super) fn complete(mut self) -> cap::CapId {
        let cap_id = self.cap_id;
        self.emit_once();
        cap_id
    }
}

impl<E: CapAllocationAuditEmitter, A> Drop for PendingCapAllocationAudit<E, A> {
    fn drop(&mut self) {
        self.emit_once();
    }
}

impl AuthorizedCapGrant {
    pub fn audit(self) -> cap::CapId {
        self.pending_audit.complete()
    }
}

/// RF186 review-fix regression for mandatory allocation audit completion.
/// Uses the exact generic RAII owner embedded in `AuthorizedCapGrant`, with an
/// allocation-free probe emitter, so explicit completion and Drop fallback are
/// both deterministic and independent of the global audit ring.
pub fn run_authorized_cap_grant_audit_self_test() {
    use core::cell::Cell;

    struct AuthorizationDropProbe<'a>(&'a Cell<bool>);

    impl Drop for AuthorizationDropProbe<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    struct CountingEmitter<'a> {
        count: &'a Cell<usize>,
        authorization_dropped: &'a Cell<bool>,
        expected_pid: usize,
        expected_cap: cap::CapId,
    }

    impl CapAllocationAuditEmitter for CountingEmitter<'_> {
        fn emit(&self, proc_ctx: &lsm::ProcessCtx, cap_id: cap::CapId) {
            assert_eq!(proc_ctx.pid, self.expected_pid);
            assert_eq!(cap_id, self.expected_cap);
            assert!(
                !self.authorization_dropped.get(),
                "cap allocation audit ran after authorization proof was released"
            );
            self.count.set(self.count.get() + 1);
        }
    }

    let count = Cell::new(0usize);
    let authorization_dropped = Cell::new(false);
    let proc_ctx = lsm::ProcessCtx::new(0x186_5002, 0x186_5002, 1000, 1000, 1000, 1000);
    let explicit_cap = cap::CapId::from_parts(17, 186);
    let explicit = PendingCapAllocationAudit::new(
        explicit_cap,
        proc_ctx,
        AuthorizationDropProbe(&authorization_dropped),
        CountingEmitter {
            count: &count,
            authorization_dropped: &authorization_dropped,
            expected_pid: proc_ctx.pid,
            expected_cap: explicit_cap,
        },
    );
    assert_eq!(explicit.complete(), explicit_cap);
    assert_eq!(
        count.get(),
        1,
        "explicit grant audit must emit exactly once"
    );
    assert!(authorization_dropped.get());

    authorization_dropped.set(false);
    let fallback_cap = cap::CapId::from_parts(18, 186);
    {
        let _fallback = PendingCapAllocationAudit::new(
            fallback_cap,
            proc_ctx,
            AuthorizationDropProbe(&authorization_dropped),
            CountingEmitter {
                count: &count,
                authorization_dropped: &authorization_dropped,
                expected_pid: proc_ctx.pid,
                expected_cap: fallback_cap,
            },
        );
    }
    assert_eq!(count.get(), 2, "Drop fallback must emit exactly once");
    assert!(authorization_dropped.get());
}
