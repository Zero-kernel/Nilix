//! Fork系统调用实现
//!
//! 实现完整的进程复制功能，包含写时复制(COW)机制

use crate::process::{
    create_process, current_pid, free_address_space, free_kernel_stack, get_process,
    FileDescriptor, ProcessArc, ProcessId,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use mm::memory::FrameAllocator;
use mm::page_table::with_pt_lock;
use mm::{arc_charge_bytes, try_reserve_heap, AdmittedMap, HeapClass};
use spin::Mutex;
// G.1 Observability: Watchdog handle type for cleanup_partial_child
use trace::watchdog::{unregister_watchdog, WatchdogHandle};
use x86_64::{
    registers::control::Cr3,
    structures::paging::{
        page_table::PageTableEntry, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

/// Fork系统调用的结果
pub enum ForkResult {
    /// 父进程返回值：子进程的PID
    Parent(ProcessId),
    /// 子进程返回值：0
    Child,
    /// 错误
    Error(ForkError),
}

/// Fork错误类型
#[derive(Debug, Clone, Copy)]
pub enum ForkError {
    /// 没有当前进程
    NoCurrentProcess,
    /// 无法获取进程信息
    ProcessNotFound,
    /// 内存分配失败
    MemoryAllocationFailed,
    /// 页表复制失败
    PageTableCopyFailed,
    /// 子进程创建失败（内核栈分配等）
    ProcessCreationFailed,
    /// F.2: Cgroup pids.max limit exceeded
    CgroupPidsLimitExceeded,
    /// J2-7: Cgroup files.max limit exceeded — the child's inherited fd count
    /// would exceed the cgroup's FD budget. Mapped to EAGAIN (fork(2) must never
    /// return EMFILE), matching the pids.max behavior.
    CgroupFilesLimitExceeded,
    /// R122-1 FIX: mmap_regions contains in-flight PENDING_MAP/PENDING_UNMAP entries;
    /// fork must be retried after the concurrent mmap/munmap completes.
    MmapTransientState,
    /// A credential writer has closed reader admission; retry after it commits.
    CredentialBusy,
    /// R180-19: LSM rejected the prospective child during PREPARE.
    SecurityDenied,
    /// R180-19: the child's PID namespace membership cannot be represented to
    /// the parent; fail before parent PTE commit.
    NamespaceTranslationFailed,
    /// R180-19: the scheduler could not reserve an exact pre-COW queue slot.
    SchedulerAdmissionFailed,
}

/// R180-19: shared-MM transaction reservation spanning metadata snapshot
/// through the parent-PTE COW commit.  Mutators observe `fork_in_progress`
/// before arming their own transient state; Drop closes every error path.
struct ForkMmReservation {
    mm: Arc<Mutex<crate::process::MmState>>,
}

impl ForkMmReservation {
    fn acquire(mm: Arc<Mutex<crate::process::MmState>>) -> Result<Self, ForkError> {
        {
            let mut state = mm.lock();
            if state.fork_in_progress
                || state
                    .mmap_regions
                    .values()
                    .any(|entry: &crate::syscall::MmapEntry| entry.has_transient())
                || state.brk_in_progress
                || state.stack_grow_in_progress
            {
                return Err(ForkError::MmapTransientState);
            }
            state.fork_in_progress = true;
        }
        Ok(Self { mm })
    }
}

impl Drop for ForkMmReservation {
    fn drop(&mut self) {
        self.mm.lock().fork_in_progress = false;
    }
}

/// PREPARE-phase cgroup reservations.  Until `commit`, dropping the guard
/// returns every acquired charge, including errors from later page-table/KPTI
/// preparation.  The type makes it impossible to add a new `?` before COW
/// commit without also inheriting exact rollback.
struct ForkChargeGuard {
    cgroup_id: crate::cgroup::CgroupId,
    fd_count: u64,
    memory_bytes: u64,
    committed: bool,
}

impl ForkChargeGuard {
    fn new(cgroup_id: crate::cgroup::CgroupId) -> Self {
        Self {
            cgroup_id,
            fd_count: 0,
            memory_bytes: 0,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for ForkChargeGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if self.memory_bytes != 0 {
            crate::cgroup::uncharge_memory(self.cgroup_id, self.memory_bytes);
        }
        if self.fd_count != 0 {
            crate::cgroup::uncharge_fds(self.cgroup_id, self.fd_count);
        }
    }
}

/// 执行fork系统调用
///
/// 创建当前进程的完整副本，包括：
/// - 进程控制块（PCB）
/// - CPU上下文
/// - 内存空间（使用写时复制COW）
/// - 文件描述符表
///
/// # 返回值
///
/// - 成功：返回 `(全局子 PID, 父命名空间可见 PID)`
/// - 子进程：返回0
/// - 错误：返回错误码
pub fn sys_fork() -> Result<(ProcessId, ProcessId), ForkError> {
    let current = current_pid().ok_or(ForkError::NoCurrentProcess)?;
    let parent_process = get_process(current).ok_or(ForkError::ProcessNotFound)?;

    // F.2: Check cgroup pids.max limit BEFORE creating any resources
    // This prevents fork bombs and ensures cgroup limits are enforced
    {
        let parent = parent_process.lock();
        if !crate::cgroup::check_fork_allowed(parent.cgroup_id) {
            return Err(ForkError::CgroupPidsLimitExceeded);
        }
    }

    // 捕获父进程信息后释放锁，避免 create_process 再次获取锁导致潜在问题
    let (parent_root, parent_pid, parent_prio, child_name) = {
        let parent = parent_process.lock();
        let root = if parent.memory_space == 0 {
            let (cr3, _) = Cr3::read();
            cr3.start_address().as_u64() as usize
        } else {
            parent.memory_space
        };
        (
            root,
            parent.pid,
            parent.priority,
            crate::process::ProcessNameSnapshot::from_parts(&parent.name, "-child"),
        )
    };

    // 创建子进程（此时未持有父进程锁，避免死锁）
    // Z-7: create_process 现在返回 Result，失败时正确传播错误
    let child_pid = create_process(child_name, parent_pid, parent_prio)
        .map_err(|_| ForkError::ProcessCreationFailed)?;

    // R180-19 PREPARE: policy and PID-namespace visibility used to be checked
    // by syscall.rs only after fork_inner had COW-committed the parent.  Build
    // immutable contexts from the prospective child now and reject/clean up
    // before any cgroup charge or page-table mutation.
    let child_process = match get_process(child_pid) {
        Some(process) => process,
        None => {
            parent_process
                .lock()
                .children
                .retain(|&pid| pid != child_pid);
            cleanup_partial_child(child_pid);
            return Err(ForkError::ProcessCreationFailed);
        }
    };
    let prepared_identity = {
        let parent = parent_process.lock();
        let visible_pid = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain)
            .map(|ns| crate::pid_namespace::pid_in_namespace(&ns, child_pid))
            .unwrap_or(Some(child_pid));
        let parent_creds = parent
            .try_credentials_read()
            .ok_or(ForkError::CredentialBusy)?;
        let parent_ctx = lsm::ProcessCtx::new(
            parent.pid,
            parent.tgid,
            parent_creds.uid,
            parent_creds.gid,
            parent_creds.euid,
            parent_creds.egid,
        );
        if let Ok(supplementary_groups) = mm::AdmittedVec::try_copy_from_slice(
            HeapClass::CoreProcess,
            &parent_creds.supplementary_groups,
        ) {
            let child_credentials = crate::process::Credentials {
                uid: parent_creds.uid,
                gid: parent_creds.gid,
                euid: parent_creds.euid,
                egid: parent_creds.egid,
                supplementary_groups,
            };
            let child_ctx = lsm::ProcessCtx::new(
                child_pid,
                child_pid,
                child_credentials.uid,
                child_credentials.gid,
                child_credentials.euid,
                child_credentials.egid,
            );
            Some((parent_ctx, child_ctx, visible_pid, child_credentials))
        } else {
            None
        }
    };
    let Some((parent_ctx, child_ctx, parent_view_pid, child_credentials)) = prepared_identity
    else {
        parent_process
            .lock()
            .children
            .retain(|&pid| pid != child_pid);
        cleanup_partial_child(child_pid);
        return Err(ForkError::MemoryAllocationFailed);
    };
    let Some(parent_view_pid) = parent_view_pid else {
        parent_process
            .lock()
            .children
            .retain(|&pid| pid != child_pid);
        cleanup_partial_child(child_pid);
        return Err(ForkError::NamespaceTranslationFailed);
    };
    if lsm::hook_task_fork(&parent_ctx, &child_ctx).is_err() {
        parent_process
            .lock()
            .children
            .retain(|&pid| pid != child_pid);
        cleanup_partial_child(child_pid);
        return Err(ForkError::SecurityDenied);
    }

    // Scheduler placement consumes affinity + cpuset before taking any queue
    // lock. Snapshot them under the parent PCB, release it, then initialize the
    // unpublished child. This preserves fork inheritance while keeping the
    // canonical READY_QUEUE -> PCB order (never parent PCB -> READY_QUEUE).
    let (child_allowed_cpus, child_cpuset_id) = {
        let parent = parent_process.lock();
        (parent.allowed_cpus, parent.cpuset_id)
    };
    {
        let mut child = child_process.lock();
        child.allowed_cpus = child_allowed_cpus;
        child.cpuset_id = child_cpuset_id;
    }

    // R180-19 / review-fix: reserve before taking the parent PCB lock.
    // Scheduler operations use READY_QUEUE -> PCB; doing this from inside
    // fork_inner while the parent PCB was held inverted that order against a
    // scheduler scan of the queued parent.  The permit remains non-runnable
    // and owns exact rollback across every later PREPARE failure.
    let scheduler_permit =
        match crate::process::prepare_scheduler_add_process(Arc::clone(&child_process)) {
            Ok(permit) => permit,
            Err(_) => {
                parent_process
                    .lock()
                    .children
                    .retain(|&pid| pid != child_pid);
                cleanup_partial_child(child_pid);
                return Err(ForkError::SchedulerAdmissionFailed);
            }
        };

    // 重新获取父进程锁执行真正的 fork
    let mut parent = parent_process.lock();

    // F.2: Get parent's cgroup_id for child attachment
    let parent_cgroup_id = parent.cgroup_id;
    // R152-5 FIX: Attach child to cgroup BEFORE the expensive fork_inner() PT copy.
    // This eliminates the pids.max TOCTOU window where multiple concurrent forks
    // all pass check_fork_allowed but waste kernel resources (kernel stack, PID,
    // page table copy) before attach_task() serially rejects them.
    let mut cgroup_attached = false;
    if let Some(cgroup) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
        if let Err(_) = cgroup.attach_task(child_pid as u64) {
            parent.children.retain(|&pid| pid != child_pid);
            drop(parent);
            // READY_QUEUE -> child PCB cancellation must run with no parent
            // PCB held (canonical scheduler lock order).
            drop(scheduler_permit);
            cleanup_partial_child(child_pid);
            return Err(ForkError::CgroupPidsLimitExceeded);
        }
        cgroup_attached = true;
    }

    match fork_inner(&mut parent, child_pid, parent_root, child_credentials) {
        Ok(()) => {}
        Err(error) => {
            parent.children.retain(|&pid| pid != child_pid);
            if cgroup_attached {
                if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                    let _ = cg.detach_task(child_pid as u64);
                }
            }
            drop(parent);
            drop(scheduler_permit);
            cleanup_partial_child(child_pid);
            return Err(error);
        }
    }

    // Publication is infallible and centralized here so syscall wrappers have
    // no post-COW lookup/failure window.  Drop the parent PCB lock first; the
    // scheduler may inspect process state through independent locks.
    drop(parent);
    scheduler_permit.commit();
    Ok((child_pid, parent_view_pid))
}

/// Fork 的内部实现，便于错误处理和回滚
fn fork_inner(
    parent: &mut crate::process::Process,
    child_pid: ProcessId,
    parent_root: usize,
    child_credentials: crate::process::Credentials,
) -> Result<(), ForkError> {
    // R122-1 FIX: Reject fork() while any mmap/munmap operation is in-flight.
    //
    // The three-phase mmap/munmap protocol (R121-4) encodes transient state in
    // the low 12 bits of each mmap_regions entry (PENDING_MAP / PENDING_UNMAP).
    // Committed entries always store page-aligned lengths (low 12 bits = 0).
    //
    // If a sibling thread (CLONE_VM) is between Phase 1 (reserve with PENDING
    // flag) and Phase 3 (commit by clearing flag), copying the entry into the
    // child — even after stripping the flag — produces an inconsistent child
    // address space: the region record says "mapped" but the page table may be
    // partially populated (PENDING_MAP) or partially torn down (PENDING_UNMAP).
    //
    // Returning MmapTransientState (mapped to EAGAIN) lets userspace retry.
    // This is fail-closed: any non-zero low bits block fork, covering future
    // transient flags as well.
    //
    // D3-ARC-MM-SHARED: mmap_regions now lives inside MmState behind parent.mm.
    // Lock ordering: Process (held) → MmState — never reverse.
    let _mm_fork_reservation = ForkMmReservation::acquire(Arc::clone(&parent.mm))?;

    if let Some(child_process) = get_process(child_pid) {
        let mut child = child_process.lock();

        // 复制 CPU 上下文（RAX 在下方置 0）
        child.context = parent.context;
        // Lazy FPU: inherit parent's FPU usage flag
        // If parent used FPU, the state in context.fx is valid and child inherits it
        child.fpu_used = parent.fpu_used;
        child.user_stack = parent.user_stack;
        // SMP affinity and cpuset were snapshotted before scheduler admission.
        // R163-4 FIX: Defer notify_cpuset_task_joined until after all fallible
        // operations complete. If fork_inner fails after the notification,
        // the counter is incremented but never decremented (cpuset DoS).

        // 子进程使用自己的内核栈（由 create_process -> allocate_kernel_stack 分配）
        // 复制父进程内核栈内容以保持返回路径一致
        let parent_top = parent.kernel_stack_top.as_u64();
        let parent_rsp = parent.context.rsp;
        let child_top = child.kernel_stack_top.as_u64();

        // 计算父进程已使用的栈空间
        let used = parent_top.saturating_sub(parent_rsp);
        let parent_stack_size = parent_top.saturating_sub(parent.kernel_stack.as_u64());

        if child_top != 0 && used > 0 && used <= parent_stack_size {
            // 子进程栈顶减去相同使用量 = 子进程 RSP
            let child_rsp = child_top - used;

            // 复制父栈内容到子栈
            unsafe {
                core::ptr::copy_nonoverlapping(
                    parent_rsp as *const u8,
                    child_rsp as *mut u8,
                    used as usize,
                );
            }

            child.context.rsp = child_rsp;

            // 调整 RBP（如果它指向父栈范围内）
            if parent.context.rbp >= parent_rsp && parent.context.rbp <= parent_top {
                // RBP 相对偏移保持不变
                let rbp_offset = parent.context.rbp - parent_rsp;
                child.context.rbp = child_rsp + rbp_offset;
            } else {
                // RBP 不在栈范围内，直接使用子栈顶
                child.context.rbp = child_rsp;
            }
        } else if child_top != 0 {
            // 无法复制栈，使用子栈顶作为起点
            child.context.rsp = child_top;
            child.context.rbp = child_top;
        }
        // 如果 child_top == 0，保持父进程的 rsp/rbp（回退到共享栈）

        // R162-7 FIX: Clone fd_table with bounded fallibility.
        // clone_box() is still infallible (Box::new), but we pre-validate
        // the fd count fits in memory. With MAX_FD=256, total alloc is ~128KB.
        // If fd_table is excessively large, fail early.
        if parent.fd_table.len() > crate::process::MAX_FD as usize {
            return Err(ForkError::MemoryAllocationFailed);
        }
        child
            .fd_table
            .ensure_capacity_for(parent.fd_table.len())
            .map_err(|_| ForkError::MemoryAllocationFailed)?;
        child
            .cloexec_fds
            .ensure_capacity_for(parent.cloexec_fds.len())
            .map_err(|_| ForkError::MemoryAllocationFailed)?;
        for (&fd, desc) in parent.fd_table.iter() {
            let cloned = desc
                .try_clone_box()
                .map_err(|_| ForkError::MemoryAllocationFailed)?;
            if child.fd_table.insert_unique_reserved(fd, cloned).is_err() {
                panic!("fork FD snapshot violated unique reserved publication");
            }
        }

        // R39-4 FIX: 克隆 close-on-exec 标记集合
        // R162-14 FIX: BTreeSet::clone() is infallible but bounded by MAX_FD=256
        // (~12KB worst case). Accepted risk documented.
        for &fd in parent.cloexec_fds.iter() {
            if child.cloexec_fds.insert_reserved(fd).is_err() {
                panic!("fork CLOEXEC snapshot exceeded prepared capacity");
            }
        }

        // M0-6: inherit POSIX resource limits across fork (POSIX: child inherits
        // the parent's rlimits). `[RLimit; N]` is Copy — a trivial value copy.
        child.rlimits = parent.rlimits;

        // M0 item 5: inherit signal dispositions + blocked mask across fork (POSIX).
        // `[SigAction; NSIG]` and `u64` are Copy. `saved_blocked`/`in_signal_handler`
        // are handler scratch state and intentionally stay born-clean in the child
        // (a fork inside a handler does NOT carry the parent's live frame state). The
        // "any handler installed" fast-path hint is a monotonic global, so the child
        // inheriting a parent's handler needs no per-task bookkeeping here.
        child.sigactions = parent.sigactions;
        child.blocked = parent.blocked;

        // 克隆能力表（尊重 CLOFORK 标志）
        //
        // clone_for_fork() 会过滤掉带有 CLOFORK 标志的能力条目，
        // 并保持生成计数器的单调性以防止 wrap 攻击。
        // R161-4 FIX: Use fallible try_clone_for_fork to avoid OOM panic
        //
        // U.S3-SLICE-2 FIX: reconcile the child cap_table refcounts to match the
        // child's ACTUAL fd count when the parent is a CLONE_THREAD thread sharing
        // its cap_table Arc with siblings. CapSlot::clone copies refcounts VERBATIM
        // (U.S3-A1), but fork's fd_table copy (loop above) copies ONLY the forking
        // thread's fds, not sibling fds. So the child's cap refcounts include
        // sibling-held references → over-count → child-local slot leak (TableFull
        // DoS class, fail-safe: revoke-too-late, never premature). Reconciliation:
        // COUNT the child's actual per-cap fd references and OVERWRITE each
        // CapEntry.refcount to match. Safe under parent lock; child not visible yet.
        // Reconcile only if parent's cap_table Arc::strong_count > 1 (shared).
        // A non-shared parent (standalone process or the last survivor of a thread
        // group) has cap refcounts that already equal its own fd count, so the
        // verbatim copy is correct. Checking `> 1` avoids the O(fds × caps) scan
        // on the common non-threaded fork path.
        let cap_table = if parent.capability_table_is_shared() {
            // Build a histogram: CapId → count of child fds carrying it.
            let mut child_cap_counts =
                [(cap::CapId::INVALID, 0usize); crate::process::MAX_FD as usize];
            let mut child_cap_count_len = 0usize;
            for desc in child.fd_table.values() {
                if let Some(cid) = desc.cap_id() {
                    let Some(slot) = child_cap_counts.get_mut(child_cap_count_len) else {
                        return Err(ForkError::MemoryAllocationFailed);
                    };
                    *slot = (cid, 1);
                    child_cap_count_len += 1;
                }
            }
            child_cap_counts[..child_cap_count_len].sort_unstable_by_key(|entry| entry.0);
            let mut unique_len = 0usize;
            for index in 0..child_cap_count_len {
                let (cid, count) = child_cap_counts[index];
                if unique_len != 0 && child_cap_counts[unique_len - 1].0 == cid {
                    child_cap_counts[unique_len - 1].1 = child_cap_counts[unique_len - 1]
                        .1
                        .checked_add(count)
                        .ok_or(ForkError::MemoryAllocationFailed)?;
                } else {
                    child_cap_counts[unique_len] = (cid, count);
                    unique_len += 1;
                }
            }
            parent
                .try_clone_capability_table_for_fork(Some(&child_cap_counts[..unique_len]))
                .map_err(|_| ForkError::MemoryAllocationFailed)?
        } else {
            parent
                .try_clone_capability_table_for_fork(None)
                .map_err(|_| ForkError::MemoryAllocationFailed)?
        };

        child.install_capability_table(cap_table);

        child.time_slice = parent.time_slice;
        child.cpu_time = 0;

        // E.4 Priority Inheritance: 继承基础动态优先级
        //
        // 子进程继承父进程的 base_dynamic_priority（未应用 PI 的优先级基线）。
        // 但不继承 pi_boosts（父进程持有的 futex 相关），子进程从空开始。
        // waiting_on_futex 也不继承（子进程未阻塞在任何 futex 上）。
        child.base_dynamic_priority = parent.base_dynamic_priority;
        // pi_boosts 和 waiting_on_futex 在 Process::new() 中已初始化为空

        // R39-3 FIX: 继承父进程的凭证（fork 创建独立副本）
        //
        // fork() 创建的子进程获得父进程凭证的克隆副本（独立 Arc）。
        // 这意味着子进程后续的 setuid/setgid 不会影响父进程。
        // 对于 CLONE_THREAD，sys_clone 中会处理共享凭证。
        let credential_arc_reservation = try_reserve_heap(
            HeapClass::CoreProcess,
            arc_charge_bytes::<crate::process::SharedCredentials>()
                .map_err(|_| ForkError::MemoryAllocationFailed)?,
        )
        .map_err(|_| ForkError::MemoryAllocationFailed)?;
        let credentials = Arc::try_new(crate::process::SharedCredentials::new(child_credentials))
            .map_err(|_| ForkError::MemoryAllocationFailed)?;
        child.install_shared_credentials_for_clone(credentials);
        drop(credential_arc_reservation);
        child.umask = parent.umask;

        // D3-ARC-MM-SHARED: Build the child's independent MmState from the
        // parent's shared mm. This replaces the old per-field copies of
        // brk_start, brk, elf_charged_bytes, mmap_regions, and next_mmap_addr.
        //
        // R138-1 FIX: Inherit parent's ELF loader charges so the child's cgroup
        // accounting is complete under worst-case COW semantics.  The exact
        // charge is derived from this same locked snapshot and reserved below,
        // before the parent-PTE commit.
        //
        // R122-1 FIX: Strip transient PENDING_* flags when cloning committed
        // regions into the child, preserving persistent per-region flags (e.g.
        // PROT_NONE) so the child inherits correct region metadata.
        //
        // R157-3 FIX: Fallible pre-allocation — BTreeMap::collect() uses
        // infallible allocation; 65536 entries can exhaust the 1 MiB kernel heap.
        // We pre-allocate into a Vec first to detect OOM early.
        //
        // Lock ordering: Process (held) → MmState — never reverse.
        let fork_charge_bytes = {
            let parent_mm = parent.mm.lock();

            // Re-check every transient at the actual snapshot point.  The early
            // check rejects quickly; this one prevents a CLONE_VM sibling from
            // opening a prepare window before the metadata/charge snapshot.
            if parent_mm
                .mmap_regions
                .values()
                .any(|entry: &crate::syscall::MmapEntry| entry.has_transient())
                || parent_mm.brk_in_progress
                || parent_mm.stack_grow_in_progress
            {
                return Err(ForkError::MmapTransientState);
            }
            debug_assert!(
                parent_mm.fork_in_progress,
                "fork snapshot must own the shared-MM reservation"
            );

            let mut charge_bytes = 0u64;
            for (_base, entry) in parent_mm.mmap_regions.iter() {
                let entry: &crate::syscall::MmapEntry = entry;
                if !entry.is_prot_none() {
                    charge_bytes =
                        charge_bytes.saturating_add(crate::syscall::mmap_region_len(*entry) as u64);
                }
            }
            const PAGE_SIZE: usize = 0x1000;
            let brk_aligned = parent_mm.brk.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            let brk_start_aligned =
                parent_mm.brk_start.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            charge_bytes = charge_bytes
                .saturating_add(brk_aligned.saturating_sub(brk_start_aligned) as u64)
                .saturating_add(parent_mm.elf_charged_bytes)
                .saturating_add(parent_mm.pt_charged_bytes);

            let region_count = parent_mm.mmap_regions.len();
            // R165-14: Re-assert the MAX_MAP_COUNT bound before cloning. mmap()
            // already enforces it on insert, but checking here keeps the child's
            // infallible BTreeMap build (below) bounded even if a future path
            // grows mmap_regions past the limit.
            if region_count > crate::syscall::MAX_MAP_COUNT {
                return Err(ForkError::MemoryAllocationFailed);
            }
            let mut snap: Vec<(usize, crate::syscall::MmapEntry)> = Vec::new();
            if snap.try_reserve_exact(region_count).is_err() {
                return Err(ForkError::MemoryAllocationFailed);
            }
            // D2 Phase 2: strip transient flags via the typed accessor (clears
            // PENDING_*, preserves PROT_NONE + prot bits — load-bearing for the
            // child's cgroup-charge skip).
            snap.extend(parent_mm.mmap_regions.iter().map(
                |(&base, len_with_flags): (&usize, &crate::syscall::MmapEntry)| {
                    (base, len_with_flags.fork_stripped())
                },
            ));

            // R186-4 FIX: Construct child's mmap_regions with charged admission.
            // The snap Vec is already allocated and populated; from_sorted_vec_charged
            // charges the Vec's capacity (not len) to CoreProcess heap class before
            // constructing the AdmittedMap. On admission failure, the Vec is returned
            // for cleanup and we return ENOMEM to the fork caller.
            let child_mmap_regions =
                match mm::AdmittedMap::from_sorted_vec_charged(snap, mm::HeapClass::CoreProcess) {
                    Ok(map) => map,
                    Err((snap, _error)) => {
                        drop(snap);
                        return Err(ForkError::MemoryAllocationFailed);
                    }
                };

            let child_mm = crate::process::MmState {
                // next-phase #11 / R165-14 (CLOSED, was AD-02 tech-debt): the
                // child's region map is now a `FallibleOrderedMap`, adopted in
                // O(1) with NO allocation from the already-sorted, already
                // try_reserve'd `snap` Vec. The prior infallible
                // `BTreeMap::collect()` (which could abort under OOM with up to
                // MAX_MAP_COUNT entries) is eliminated: every allocation on this
                // path is now the fallible `try_reserve_exact` on `snap` above,
                // and `from_sorted_vec` consumes that Vec verbatim. `snap` is
                // strictly key-sorted because it is built from the parent's
                // ordered `mmap_regions.iter()` (debug-asserted by from_sorted_vec).
                //
                // R186-4 FIX: Migrated to AdmittedMap with from_sorted_vec_charged,
                // which charges the Vec capacity to CoreProcess before adoption.
                mmap_regions: child_mmap_regions,
                brk_start: parent_mm.brk_start,
                brk: parent_mm.brk,
                next_mmap_addr: parent_mm.next_mmap_addr,
                vm_charged_bytes: parent_mm.vm_charged_bytes,
                elf_charged_bytes: parent_mm.elf_charged_bytes,
                // J2-9 FIX: inherit the page-table-frame kmem charge. The child
                // builds its OWN page tables (so the value, like elf, is a copy of
                // the parent's) and its last-exit uncharges this; the matching
                // charge to the parent cgroup is folded into fork_charge_bytes.
                pt_charged_bytes: parent_mm.pt_charged_bytes,
                // R171-CG1x0 FIX (M2-1 SLICE-0): the child's whole inherited PT
                // basis lives in `pt_inherited_bytes` with an EMPTY frame ledger —
                // the child's page tables are freshly built at DIFFERENT physical
                // addresses, so cloning the parent's frame keys would risk a
                // cross-AS uncharge. Non-authoritative until the child's first own
                // mmap. INVARIANT I' holds at birth: pt_charged_bytes(=P) ==
                // pt_inherited_bytes(=P) + 0. The child's munmap of an inherited
                // region therefore uncharges 0 (the basis rides to last-exit,
                // over-count-safe), preserving today's +P(parent)/-P(child exit)
                // fork balance with zero new fork PT-recording surface.
                //
                // R186-4 FIX: Migrated to AdmittedMap; child starts with empty ledger
                // (AdmittedMap::new charges nothing for zero capacity).
                pt_charged_frames: mm::AdmittedMap::new(mm::HeapClass::CoreProcess),
                pt_inherited_bytes: parent_mm.pt_charged_bytes,
                pt_ledger_authoritative: false,
                // Transient pending counters reset for child — no in-flight
                // operations can be inherited across fork.
                brk_pending_growth: 0,
                mprotect_pending_bytes: 0,
                exec_pending_bytes: 0,
                // R165-1 FIX: child starts with no brk reservation (fork is
                // rejected above while a brk is in flight).
                brk_in_progress: false,
                // R172-16: child inherits no brk-grow VA reservation — fork EAGAINs while
                // brk_in_progress, so this path is never reached mid-grow; zero defensively.
                brk_grow_resv_lo: 0,
                brk_grow_resv_hi: 0,
                // M0-7 item7 SLICE 4: the child inherits no in-flight stack grow nor its
                // reservation — fork EAGAINs while stack_grow_in_progress, so this path is
                // never reached mid-grow; zero defensively. The COMMITTED watermark IS
                // copied: the grown stack region is COW-inherited (this is an independent
                // address space built by copying the parent's page tables), so the child's
                // committed floor matches the parent's, and the inherited grow DATA already
                // rides in elf_charged_bytes (copied above + charged to the parent cgroup
                // via fork_charge_bytes), so the child's last-exit uncharges it symmetrically.
                stack_grow_pending_bytes: 0,
                stack_floor_committed: parent_mm.stack_floor_committed,
                stack_grow_in_progress: false,
                fork_in_progress: false,
            };
            child.mm = Arc::try_new(Mutex::new(child_mm))
                .map_err(|_| ForkError::MemoryAllocationFailed)?;
            charge_bytes
        };

        // 复制 TLS 状态（FS/GS base）
        child.fs_base = parent.fs_base;
        child.gs_base = parent.gs_base;

        // F.2: 继承 Cgroup 成员关系
        // 子进程继承父进程的 cgroup，并注册到 cgroup 的任务列表
        child.cgroup_id = parent.cgroup_id;
        // Note: cgroup task tracking is done after process is fully created

        // R93-1 FIX: 继承 IPC/Network/User 命名空间（以及 for_children 默认值）
        // 防止 fork() 产生的子进程意外回落到 root namespace 造成隔离逃逸
        // 注：PID namespace 和 Mount namespace 已在 create_process() 中继承
        child.ipc_ns = parent.ipc_ns.clone();
        child.ipc_ns_for_children = parent.ipc_ns_for_children.clone();
        child.net_ns = parent.net_ns.clone();
        child.net_ns_for_children = parent.net_ns_for_children.clone();
        child.user_ns = parent.user_ns.clone();
        child.user_ns_for_children = parent.user_ns_for_children.clone();

        // 继承 Seccomp/Pledge 沙箱状态
        // - SeccompState.filters: Vec<Arc<SeccompFilter>> 通过 Arc 共享，避免深拷贝
        // - no_new_privs: 粘滞标志，一旦设置不可清除，必须继承
        // - pledge_state: 包含 promises 和 exec_promises（exec 后生效）
        // R162-6 FIX: Use fallible try_clone to avoid OOM panic (R161-3 regression)
        child.seccomp_state = parent
            .seccomp_state
            .try_clone()
            .map_err(|_| ForkError::MemoryAllocationFailed)?;
        child.pledge_state = parent.pledge_state.clone();

        // Finish every infallible PCB field before scheduler admission. The
        // reserved queue entry is non-runnable until its permit is committed.
        child.clear_child_tid = 0;
        child.set_child_tid = 0;
        child.robust_list_head = 0;
        child.robust_list_len = 0;
        child.socket_timeout_marker.store(0, Ordering::Relaxed);
        child.wq_timeout_marker.store(0, Ordering::Relaxed);
        child.active_wait_seq.store(0, Ordering::Relaxed);
        child.context.rax = 0;

        // R180-19 PREPARE: reserve the exact resources represented by the
        // already-built child state.  The RAII guard rolls both controllers back
        // on root-frame, KPTI, or COW-plan failure; after this point there is no
        // unguarded charge and no mismatch between the cloned MmState and its
        // memory.max amount.
        let child_fd_count = child.fd_table.len() as u64;
        let mut charge_guard = ForkChargeGuard::new(parent.cgroup_id);
        if child_fd_count != 0 {
            crate::cgroup::try_charge_fds(parent.cgroup_id, child_fd_count)
                .map_err(|_| ForkError::CgroupFilesLimitExceeded)?;
            charge_guard.fd_count = child_fd_count;
        }
        if fork_charge_bytes != 0 {
            crate::cgroup::try_charge_memory(parent.cgroup_id, fork_charge_bytes)
                .map_err(|_| ForkError::MemoryAllocationFailed)?;
            charge_guard.memory_bytes = fork_charge_bytes;
        }

        let child_cpuset_id = child.cpuset_id;
        drop(child);

        // R180-19 FIX: the parent-PTE COW transition is the COMMIT point.
        // Every heap allocation, namespace/capability/credential clone, cgroup
        // charge, and child metadata build above has already succeeded.  The
        // page-table transaction also prepares KPTI before touching the parent,
        // so nothing below this call can return an error after parent PTEs have
        // become read-only.
        let mut frame_alloc = FrameAllocator::new();
        let child_root_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;
        unsafe {
            zero_table(child_root_frame);
        }
        let child_memory_space = child_root_frame.start_address().as_u64() as usize;
        let child_user_memory_space = unsafe {
            match copy_page_table_cow(parent_root, child_memory_space) {
                Ok(user_memory_space) => user_memory_space,
                Err(error) => {
                    // copy_page_table_cow guarantees the root's user half is
                    // empty on failure, so the generic teardown releases only
                    // the private root and never touches parent-owned leaves.
                    free_address_space(child_memory_space);
                    return Err(error);
                }
            }
        };
        let mut child = child_process.lock();
        child.memory_space = child_memory_space;
        child.user_memory_space = child_user_memory_space;

        // The admission charge becomes owned by the child at the same commit.
        // No error path exists below this assignment; normal exit now performs
        // the exact matching uncharge.
        child.fds_charged_count = child_fd_count;
        charge_guard.commit();

        // R163-4 FIX: All fallible operations above have succeeded. Safe to
        // commit the cpuset counter increment now — no error path can leak it.
        let committed_child_pid = child.pid;
        drop(child);
        crate::process::notify_cpuset_task_joined(child_cpuset_id);
        kprintln!(
            "Fork: parent={}, child={}, COW enabled",
            parent.pid,
            committed_child_pid
        );
        Ok(())
    } else {
        Err(ForkError::ProcessNotFound)
    }
}

/// 清理失败的 fork 创建的部分子进程
fn cleanup_partial_child(child_pid: ProcessId) {
    use crate::process::PROCESS_TABLE;

    // 预先收集需要释放的资源，避免长时间持有 PROCESS_TABLE 锁
    // G.1: Also extract watchdog handle for unregistration
    // H.0.9: Also extract PID namespace chain for detachment outside lock
    let (
        kstack,
        addr_space,
        user_addr_space,
        watchdog_handle,
        pid_ns_chain,
        fds_to_drop,
        process_to_drop,
    ): (
        Option<(VirtAddr, PhysFrame<Size4KiB>, crate::rcu::RcuCallbackPermit)>,
        usize,
        usize,
        Option<WatchdogHandle>,
        mm::AdmittedVec<crate::pid_namespace::PidNamespaceMembership>,
        AdmittedMap<i32, FileDescriptor>,
        Option<ProcessArc>,
    ) = {
        let mut table = PROCESS_TABLE.lock();
        if let Some(slot) = table.get_mut(child_pid) {
            if let Some(process) = slot.take() {
                let mut proc = process.lock();
                (
                    if proc.kernel_stack.as_u64() != 0 {
                        Some((
                            proc.kernel_stack,
                            proc.kernel_stack_phys
                                .take()
                                .expect("live kernel stack missing physical block identity"),
                            proc.kernel_stack_rcu
                                .take()
                                .expect("live kernel stack missing RCU reclaim permit"),
                        ))
                    } else {
                        None
                    },
                    proc.memory_space,
                    proc.user_memory_space, // H.3 KPTI: capture for cleanup
                    // G.1: Take watchdog handle to unregister outside lock
                    proc.watchdog_handle.take(),
                    // H.0.9: Capture PID namespace chain for detachment outside lock.
                    // create_process() calls assign_pid_chain(), so the chain is populated
                    // even for partially-constructed children. Without detachment, the
                    // namespace PID slots leak and are never reclaimed.
                    // R180-19: cleanup is itself an OOM path. Transfer the
                    // already-owned chain instead of cloning/allocating while
                    // rolling back a failed fork.
                    core::mem::replace(
                        &mut proc.pid_ns_chain,
                        mm::AdmittedVec::new(HeapClass::CoreProcess),
                    ),
                    // R171-F5 FIX: take the fd_table OUT so FileDescriptor
                    // destructors run explicitly after PROCESS_TABLE is released.
                    core::mem::replace(
                        &mut proc.fd_table,
                        AdmittedMap::new(HeapClass::CoreProcess),
                    ),
                    // RF180-16 defense-in-depth: retain the whole PCB across the
                    // table unlock. Process field destructors include namespace
                    // Arcs whose final Drop may take lifecycle/parent locks; PID
                    // publication takes those locks before PROCESS_TABLE, so the
                    // final PCB drop must never occur under PROCESS_TABLE.
                    Some(Arc::clone(&process)),
                )
            } else {
                (
                    None,
                    0,
                    0,
                    None,
                    mm::AdmittedVec::new(HeapClass::CoreProcess),
                    AdmittedMap::new(HeapClass::CoreProcess),
                    None,
                )
            }
        } else {
            (
                None,
                0,
                0,
                None,
                mm::AdmittedVec::new(HeapClass::CoreProcess),
                AdmittedMap::new(HeapClass::CoreProcess),
                None,
            )
        }
    };
    let retired_process_table = {
        let mut table = PROCESS_TABLE.lock();
        crate::process::reclaim_empty_process_table(&mut table)
    };
    // RF180-44: the detached allocation and its admission charge must outlive
    // the PROCESS_TABLE guard and be destroyed only after the global lock drops.
    drop(retired_process_table);

    // G.1 Observability: Unregister watchdog before releasing other resources
    // This prevents false hung-task alerts for the partially-created process
    if let Some(handle) = watchdog_handle {
        if unregister_watchdog(&handle).is_err() {
            debug_assert!(false, "partial child carried a stale watchdog handle");
        }
    }

    // H.0.9: Detach PID namespace chain to reclaim namespace PID slots.
    // Must be done outside PROCESS_TABLE lock to avoid lock ordering violation.
    if !pid_ns_chain.is_empty() {
        crate::pid_namespace::detach_pid_chain(&pid_ns_chain, child_pid);
    }

    // 在 PROCESS_TABLE 锁外释放资源
    if let Some((stack_base, stack_phys, permit)) = kstack {
        free_kernel_stack(child_pid, stack_base, stack_phys, permit);
    }
    // H.3 KPTI: Free user PML4 root BEFORE kernel PML4.
    // User-half entries are shared pointers into the kernel PML4's sub-tables,
    // so the root must be deallocated before those sub-tables are freed.
    if user_addr_space != 0 {
        free_kpti_user_pml4(user_addr_space);
    }
    if addr_space != 0 {
        free_address_space(addr_space);
    }

    // R171-F5 FIX: drop the taken fd_table now — PROCESS_TABLE is released, so
    // each FileDescriptor close (socket/pipe wake_all -> get_process ->
    // PROCESS_TABLE) runs lock-free. (No-op when the table was already empty.)
    drop(fds_to_drop);
    // Drop all remaining PCB-owned resources only after every global/table lock
    // and the explicitly ordered cleanup above have completed.
    drop(process_to_drop);

    kprintln!("Fork failed: cleaned up partial child PID {}", child_pid);
}

/// 实现写时复制(Copy-On-Write)的页表复制
///
/// 这是fork的关键优化：
/// 1. 将父进程的所有可写页标记为只读
/// 2. 子进程共享这些页
/// 3. 当任一进程尝试写入时，触发页错误
/// 4. 页错误处理程序复制该页并更新页表
///
/// # Z-8 fix: 两阶段 COW 实现
///
/// 为防止内存分配失败时父进程 PTE 残留 COW 修改，采用两阶段处理：
/// 1. **规划阶段**：遍历页表收集叶子修改计划和所需中间页表帧数量
/// 2. **预分配阶段**：预分配所有中间页表帧（若失败，父进程未被修改）
/// 3. **应用阶段**：使用预分配帧应用所有 COW 修改（保证不会失败）
///
/// # R67-6 FIX: Cross-CPU Serialization
///
/// Acquires the global page table lock (PT_LOCK) to prevent concurrent
/// mmap/munmap/pagefault operations from racing with COW setup. This ensures
/// no parent thread can modify the address space while fork is flipping flags.
///
/// # Safety
///
/// 此函数直接操作页表，必须确保：
/// - 页表结构有效
/// - 有足够的物理内存
pub unsafe fn copy_page_table_cow(
    parent_page_table: usize,
    child_page_table: usize,
) -> Result<usize, ForkError> {
    // R67-6 FIX: Hold PT_LOCK during entire COW setup to prevent concurrent
    // mmap/munmap/pagefault from racing with parent PTE modifications.
    with_pt_lock(|| {
        let mut frame_alloc = FrameAllocator::new();
        let parent_root: PhysFrame<Size4KiB> =
            PhysFrame::containing_address(PhysAddr::new(parent_page_table as u64));
        let child_root: PhysFrame<Size4KiB> =
            PhysFrame::containing_address(PhysAddr::new(child_page_table as u64));

        let parent_pml4 = phys_to_virt_table(parent_root.start_address());
        let child_pml4 = phys_to_virt_table(child_root.start_address());

        // 复制内核高半区映射（索引 256-511）
        for i in 256..512 {
            child_pml4[i] = parent_pml4[i].clone();
        }

        // Z-8 fix: 两阶段 COW
        // 阶段 1: 规划 - 收集叶子修改计划和所需中间页表帧数量
        let mut plan = CowClonePlan::new();
        plan_clone_level(parent_pml4, 4, &mut plan)?;

        // 阶段 2: 预分配所有中间页表帧
        // 若分配失败，此时父进程未被修改，直接返回错误即可
        let mut table_frames = preallocate_table_frames(plan.tables_needed, &mut frame_alloc)?;

        // R180-19 PREPARE: build the complete child tree without modifying the
        // parent.  Keep the exact frame vector alive as a rollback ledger; a
        // PhysFrame value is non-owning, so dropping the Vec after COMMIT is safe.
        let mut leaf_cursor = 0usize;
        let mut frame_iter = table_frames.iter().copied();
        build_child_clone_level(
            parent_pml4,
            child_pml4,
            &mut frame_iter,
            &plan,
            &mut leaf_cursor,
            4,
        );
        debug_assert_eq!(leaf_cursor, plan.leaf_updates.len());
        debug_assert!(frame_iter.next().is_none());

        // R180-19 PREPARE: KPTI construction used to happen after parent PTEs
        // were committed.  Build it over the unpublished child tree now.  Any
        // failure clears the child root and returns every private table frame;
        // the parent and COW refcount table are still byte-for-byte unchanged.
        let user_memory_space = if security::is_kpti_enabled() {
            match create_kpti_user_pml4(child_page_table) {
                Ok((_user_frame, user_phys)) => user_phys,
                Err(error) => {
                    rollback_prepared_child_clone(child_pml4, &mut table_frames, &mut frame_alloc);
                    return Err(error);
                }
            }
        } else {
            0
        };

        // RF178-6 / RF178-31: refcount metadata is staged only after the child
        // and KPTI roots are complete, but still before parent mutation.  The
        // staging helper rolls back its exact prefix on failure; we then discard
        // the unpublished child structures without releasing shared leaf frames.
        if let Err(error) = PAGE_REF_COUNT.stage_clone_refs(&mut plan) {
            if user_memory_space != 0 {
                free_kpti_user_pml4(user_memory_space);
            }
            rollback_prepared_child_clone(child_pml4, &mut table_frames, &mut frame_alloc);
            return Err(error);
        }

        // R180-19 COMMIT: no allocation or fallible operation remains.  Parent
        // leaves are changed from their locked plan in one bounded pass.
        unsafe {
            commit_parent_cow(&plan);
        }

        // R23-1 fix: 父进程页表被改成只读+BIT_9，需要刷新 TLB 才能生效
        // 使用 TLB shootdown 机制，为 SMP 支持做准备
        // 当前单核模式下，只做本地 flush
        mm::flush_current_as_all();

        kprintln!(
            "COW page table copy: parent=0x{:x}, child=0x{:x}, leaves={}, tables={}",
            parent_page_table,
            child_page_table,
            plan.leaf_updates.len(),
            plan.tables_needed
        );

        Ok(user_memory_space)
    })
}

/// 处理写时复制的页错误
///
/// 当进程尝试写入COW页时调用
///
/// # R186-10 FIX: remove the redundant global lock; classify the outcome exactly
///
/// Two defects were fixed here.
///
/// **1. Contention killed valid tasks.** `COW_FAULT_LOCK.try_lock()` failure
/// returned `Err(ProcessNotFound)`, and the sole `#PF` caller treats every `Err`
/// as fatal — so any process able to create global COW contention could terminate
/// unrelated, entirely valid writers.
///
/// The repair is not to translate that error better but to delete its cause.
/// `COW_FAULT_LOCK` was **strictly redundant**: every mutation below runs inside
/// `with_current_manager`, which holds the single global `PT_LOCK`
/// (`mm/page_table.rs`) across the whole closure — translate, refcount claim,
/// frame allocation, copy, unmap, remap, shootdown and release. Two concurrent
/// COW faults were therefore already serialized by `PT_LOCK` before this lock was
/// ever consulted; it added a second contention point and no ordering. It is gone,
/// which eliminates the DoS class rather than mitigating it.
///
/// **2. Spinning on `PT_LOCK` from `#PF` can deadlock.** `#PF` is an interrupt
/// gate (IF=0), and the `PT_LOCK` holder issues cross-CPU TLB shootdown IPIs and
/// waits for acknowledgement. A faulting CPU that blocks on `PT_LOCK` with
/// interrupts disabled can never acknowledge, so the holder waits on us while we
/// wait on the holder. This now uses the non-blocking `try_with_current_manager`
/// (whose own contract states an exception path must never spin on that lock) and
/// reports `Busy`.
///
/// Retrying on `Busy` is safe *because* it goes through `IRETQ`, which restores
/// `IF=1`: the shootdown IPI is serviced between attempts, so the holder always
/// makes progress and the retry terminates. This is a genuine progress argument,
/// not an optimistic one. There is no user-fatal contention budget: the handler
/// uses PT-lock owner identity to panic only on true same-CPU re-entry, which is a
/// kernel invariant violation rather than ordinary cross-CPU contention.
///
/// # Disposition taxonomy
///
/// The previous shape collapsed every `Err` into `NotCow`, so an out-of-memory or
/// corrupt-metadata failure on a page that genuinely *is* COW was reported as "not
/// a COW page" — indistinguishable from a real protection violation, and therefore
/// undiagnosable in the field. Each outcome is now distinct:
///
/// - `Handled` — resolved (or already resolved by another CPU); resume.
/// - `Busy` — `PT_LOCK` contended; re-execute the faulting instruction.
/// - `NotCow` — genuinely not a COW page; fall through to normal fault handling.
/// - `Fatal` — a COW page that could not be resolved; the task cannot continue,
///   but the reason is recorded rather than disguised as `NotCow`.
///
/// # Arguments
///
/// * `pid` - 触发页错误的进程ID
/// * `fault_addr` - 导致错误的虚拟地址
///
/// # Safety
///
/// 此函数分配新的物理页并更新页表
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowFaultResult {
    /// COW fault successfully handled, resume execution
    Handled,
    /// Page-table lock contended; re-execute the faulting instruction
    Busy,
    /// Not a COW fault (page absent, or present and not COW-marked)
    NotCow,
    /// A COW page that could not be resolved. Not recoverable for this task.
    Fatal(CowFaultFailure),
}

/// R186-10: why an otherwise-valid COW resolution could not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowFaultFailure {
    /// No physical frame available for the private copy.
    OutOfMemory,
    /// COW marker present without consistent refcount metadata, or the
    /// ownership ledger could not be advanced. Never guess at ownership.
    MetadataCorrupt,
    /// The page-table update (unmap/remap/flag change) failed; the previous
    /// mapping was restored where possible.
    MappingFailed,
}

pub unsafe fn handle_cow_page_fault(pid: ProcessId, fault_addr: usize) -> CowFaultResult {
    use mm::page_table::try_with_current_manager;

    let virt = VirtAddr::new(fault_addr as u64);
    let page = Page::containing_address(virt);

    // R114-3 FIX: ALL PTE flag reads are now performed under PT_LOCK inside
    // `with_current_manager()`. Previously, `find_pte()` read flags outside the lock,
    // creating a TOCTOU race on SMP with CLONE_THREAD|CLONE_VM: another thread
    // could `munmap`/`mprotect` the page between the unlocked `find_pte()` read and
    // the locked `with_current_manager()` use, leading to stale-flags decisions
    // and potential use-after-free or wrong-frame deallocation.

    // 使用基于当前 CR3 的页表管理器，确保操作正确的地址空间
    let mut frame_alloc = FrameAllocator::new();

    // R186-10 FIX: non-blocking acquisition (see the deadlock rationale above).
    // `None` means PT_LOCK is contended, which is transient and retryable — it is
    // NOT a property of the faulting page and must never terminate the task.
    let outcome = try_with_current_manager(VirtAddr::new(0), |manager| -> CowFaultResult {
        // R114-3 FIX: Read PTE flags UNDER PT_LOCK via translate_with_flags().
        // This eliminates the TOCTOU window that existed when find_pte() was called
        // outside the lock scope.
        let Some((old_phys, flags)) = manager.translate_with_flags(virt) else {
            // Nothing mapped here at all: this is an ordinary access violation,
            // not a COW resolution failure.
            return CowFaultResult::NotCow;
        };

        // R65-21 FIX: After acquiring the lock, re-check if the page is still COW.
        // Another thread may have resolved this COW fault while we were waiting for the lock.
        // If COW flag is no longer set, check if the page is now writable:
        // - If writable: another thread resolved it, flush TLB and return Ok
        // - If not writable: this was never a COW page, return error to let caller handle it
        if !flags.contains(cow_flag()) {
            if flags.contains(PageTableFlags::WRITABLE) {
                // COW already resolved by another thread, just ensure TLB is consistent
                // R68-4 FIX: Use cross-CPU shootdown to ensure all CPUs see the resolution.
                // On SMP, other CPUs sharing this address space may have stale TLB entries.
                mm::flush_current_as_page(virt);
                return CowFaultResult::Handled;
            } else {
                // Page is not COW and not writable - this is NOT a COW fault
                // Let the caller handle it appropriately (e.g., SIGSEGV)
                return CowFaultResult::NotCow;
            }
        }

        let old_frame = PhysFrame::containing_address(old_phys);

        // R180-19 defense in depth: a failed/denied fork (and the ordinary
        // "child exited first" case) can leave this process as the sole COW
        // owner.  Requiring a fresh frame in that state turns recoverable memory
        // pressure into SIGSEGV.  Atomically consume refcount==1 and restore
        // writability in place; PT_LOCK excludes a concurrent fork publication.
        match PAGE_REF_COUNT.claim_unique(old_frame.start_address().as_u64() as usize) {
            CowUniqueClaim::Claimed => {
                let mut unique_flags = flags;
                unique_flags.remove(cow_flag());
                unique_flags.remove(cow_readonly_flag());
                unique_flags.insert(PageTableFlags::WRITABLE);
                if manager.update_flags(page, unique_flags).is_err() {
                    let restored = PAGE_REF_COUNT
                        .restore_unique_claim(old_frame.start_address().as_u64() as usize);
                    debug_assert!(restored, "failed to restore unique COW claim");
                    return CowFaultResult::Fatal(CowFaultFailure::MappingFailed);
                }
                if !PAGE_REF_COUNT.finish_unique_claim(old_frame.start_address().as_u64() as usize)
                {
                    // Metadata corruption: restore the read-only PTE and the
                    // tracking reference if possible.  Never leave a writable
                    // mapping paired with an ambiguous ownership count.
                    let _ = manager.update_flags(page, flags);
                    let restored = PAGE_REF_COUNT
                        .restore_unique_claim(old_frame.start_address().as_u64() as usize);
                    debug_assert!(restored, "failed to unwind unique COW finalization");
                    mm::flush_current_as_page(virt);
                    return CowFaultResult::Fatal(CowFaultFailure::MetadataCorrupt);
                }
                mm::flush_current_as_page(virt);
                kprintln!(
                    "COW page fault: pid={}, addr=0x{:x} upgraded unique owner",
                    pid,
                    fault_addr
                );
                return CowFaultResult::Handled;
            }
            CowUniqueClaim::Shared => {}
            CowUniqueClaim::Invalid => {
                // A COW marker without tracking metadata cannot be repaired
                // safely: do not allocate/copy and then guess at ownership.
                return CowFaultResult::Fatal(CowFaultFailure::MetadataCorrupt);
            }
        }

        // 分配新物理页
        let Some(new_frame) = frame_alloc.allocate_frame() else {
            // R186-10: a genuine COW page we cannot satisfy under memory
            // pressure. Reported as OutOfMemory, NOT as "not a COW page" —
            // the previous collapse made allocator exhaustion look identical
            // to an ordinary protection violation in every diagnostic.
            return CowFaultResult::Fatal(CowFaultFailure::OutOfMemory);
        };

        // 复制页内容（使用高半区直映访问物理内存）
        let old_virt = mm::phys_to_virt(old_frame.start_address());
        let new_virt = mm::phys_to_virt(new_frame.start_address());
        core::ptr::copy_nonoverlapping(old_virt.as_ptr::<u8>(), new_virt.as_mut_ptr::<u8>(), 4096);

        // H-35 fix: Check unmap result - if it fails, deallocate the new frame and return error
        if manager.unmap_page(page).is_err() {
            frame_alloc.deallocate_frame(new_frame);
            return CowFaultResult::Fatal(CowFaultFailure::MappingFailed);
        }

        // 设置新标志：移除 COW，添加 WRITABLE
        // R114-3 FIX: `flags` is guaranteed fresh — read under PT_LOCK above.
        let mut new_flags = flags;
        new_flags.remove(cow_flag());
        new_flags.remove(cow_readonly_flag());
        new_flags.insert(PageTableFlags::WRITABLE);

        // H-35 fix: If map fails, try to restore the old mapping to avoid page loss
        if let Err(_) = manager.map_page(page, new_frame, new_flags, &mut frame_alloc) {
            // Attempt to restore the old mapping
            let _ = manager.map_page(page, old_frame, flags, &mut frame_alloc);
            // R68-4 FIX: Flush TLB on all CPUs sharing this address space.
            // Use cross-CPU shootdown to ensure the restored mapping is visible.
            mm::flush_current_as_page(virt);
            // Deallocate the new frame we allocated
            frame_alloc.deallocate_frame(new_frame);
            return CowFaultResult::Fatal(CowFaultFailure::MappingFailed);
        }

        // H-35 & R68-4 FIX: Flush TLB on ALL CPUs to ensure the new writable mapping is effective.
        //
        // On SMP, other CPUs in the same address space may have the old COW (read-only) TLB
        // entry cached. Without cross-CPU shootdown, they would continue to trigger COW faults
        // or write to the old frame, causing memory corruption or use-after-free.
        mm::flush_current_as_page(virt);

        // 减少原页引用计数
        // R114-3 FIX (Codex review): Use page-aligned frame address for refcount key,
        // not the offset-adjusted `old_phys`. `translate_with_flags()` returns
        // `frame.start_address() + offset`, but refcount keys are page-aligned
        // (staged transactionally by `PhysicalPageRefCount::stage_clone_refs` in fork).
        // Using unaligned `old_phys` would miss the entry and return 0, causing
        // premature frame deallocation.
        // R153-I2 FIX: Assert alignment to catch future misuse of the refcount API.
        debug_assert!(
            old_frame.start_address().as_u64() % 4096 == 0,
            "COW refcount key must be page-aligned"
        );
        // RF178-31: a COW PTE must already be tracked. Missing/invalid metadata
        // fails leak-safe; only a confirmed tracked last reference may be freed.
        let release = PAGE_REF_COUNT.release(old_frame.start_address().as_u64() as usize);
        if release == CowPageRelease::Last {
            frame_alloc.deallocate_frame(old_frame);
        }

        kprintln!(
            "COW page fault: pid={}, addr=0x{:x} resolved",
            pid,
            fault_addr
        );
        CowFaultResult::Handled
    });

    // R186-10 FIX: `None` is PT_LOCK contention only — transient, and a property
    // of the system rather than of this page or this task. It must never be
    // conflated with a resolution failure.
    outcome.unwrap_or(CowFaultResult::Busy)
}

// RF178-31 FIX: COW refcount storage is a boot-reserved physical-frame table
// sized from the discovered managed window (see mm::memory::publish_cow_refcount_table).
// It is NOT a static array sized by an artificial 256 MiB RAM cap, and it is NOT
// allocated from the 1 MiB heap. Lookups remain O(1) and allocation-free.

/// Result of atomically releasing one leaf mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowPageRelease {
    /// This frame never entered COW tracking; the removed leaf owned it directly.
    Untracked,
    /// Other tracked mappings still own the frame.
    Remaining(u32),
    /// This was the last tracked mapping.
    Last,
    /// The address is malformed or outside the buddy-owned window. Never free it.
    Invalid,
}

/// Result of trying to convert the only tracked COW mapping back to ordinary
/// writable ownership without allocating a replacement frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CowUniqueClaim {
    Claimed,
    Shared,
    Invalid,
}

/// Transient refcount value owned by the PT_LOCK-held unique-upgrade path.
/// Teardown treats it as invalid/leak-safe rather than as an untracked frame.
const COW_UNIQUE_CLAIMED: u32 = u32::MAX;

impl CowPageRelease {
    /// Ordinary unmap/teardown frees both exclusive untracked pages and the last
    /// tracked page. Invalid metadata fails leak-safe rather than risking a UAF.
    #[inline]
    pub const fn should_free_unmapped(self) -> bool {
        matches!(self, Self::Untracked | Self::Last)
    }
}

pub struct PhysicalPageRefCount {
    _fixed_table: (),
}

impl PhysicalPageRefCount {
    pub const fn new() -> Self {
        PhysicalPageRefCount { _fixed_table: () }
    }

    #[inline]
    fn slot(phys_addr: usize) -> Option<&'static AtomicU32> {
        let (base, page_count) = mm::memory::managed_physical_page_window()?;
        if phys_addr & 0xfff != 0 {
            return None;
        }
        let offset = (phys_addr as u64).checked_sub(base)?;
        let index = usize::try_from(offset / 4096).ok()?;
        if index >= page_count {
            return None;
        }
        // RF178-31: index into the boot-reserved frame-backed table.
        mm::memory::cow_refcount_slot(index)
    }

    /// Atomically add this fork's exact mapping delta to one frame.
    fn stage_slot(slot: &AtomicU32, flags: PageTableFlags) -> Result<u32, ForkError> {
        if !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
            return Ok(0);
        }
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            return Err(ForkError::PageTableCopyFailed);
        }
        let write_cow = flags.contains(cow_flag());
        let readonly_cow = flags.contains(cow_readonly_flag());
        if (write_cow && readonly_cow)
            || ((write_cow || readonly_cow) && flags.contains(PageTableFlags::WRITABLE))
        {
            return Err(ForkError::PageTableCopyFailed);
        }

        let mut old = slot.load(Ordering::Acquire);
        loop {
            if old == COW_UNIQUE_CLAIMED {
                return Err(ForkError::PageTableCopyFailed);
            }
            let delta = if old == 0 {
                // A COW marker proves the parent was already tracked. Losing
                // that metadata cannot be repaired from one PTE; fail leak-safe.
                if write_cow || readonly_cow {
                    return Err(ForkError::PageTableCopyFailed);
                }
                2 // materialize the existing parent plus the new child
            } else {
                // Every successfully cloned user leaf is COW-marked below.
                // A tracked non-COW state is contradictory (or an alias the
                // current metadata cannot count safely), so do not guess.
                if !write_cow && !readonly_cow {
                    return Err(ForkError::PageTableCopyFailed);
                }
                1 // the tracked parent exists; add only the new child
            };
            let new = old
                .checked_add(delta)
                .ok_or(ForkError::PageTableCopyFailed)?;
            if new == COW_UNIQUE_CLAIMED {
                return Err(ForkError::PageTableCopyFailed);
            }
            match slot.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(delta),
                Err(actual) => old = actual,
            }
        }
    }

    fn rollback_slot(slot: &AtomicU32, delta: u32) {
        let mut current = slot.load(Ordering::Acquire);
        loop {
            let Some(new) = current.checked_sub(delta) else {
                debug_assert!(false, "staged COW refcount rollback underflow");
                return;
            };
            match slot.compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    fn release_slot(slot: &AtomicU32) -> CowPageRelease {
        let mut old = slot.load(Ordering::Acquire);
        loop {
            if old == COW_UNIQUE_CLAIMED {
                return CowPageRelease::Invalid;
            }
            if old == 0 {
                return CowPageRelease::Untracked;
            }
            let new = old - 1;
            match slot.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) if new == 0 => return CowPageRelease::Last,
                Ok(_) => return CowPageRelease::Remaining(new),
                Err(actual) => old = actual,
            }
        }
    }

    /// Atomically consume the final tracking reference.  PT_LOCK prevents a
    /// concurrent fork from adding a mapping while the caller updates its PTE;
    /// teardown may only move a shared count downward, which is safely retried.
    fn claim_unique_slot(slot: &AtomicU32) -> CowUniqueClaim {
        let mut current = slot.load(Ordering::Acquire);
        loop {
            match current {
                0 => return CowUniqueClaim::Invalid,
                1 => match slot.compare_exchange_weak(
                    1,
                    COW_UNIQUE_CLAIMED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return CowUniqueClaim::Claimed,
                    Err(actual) => current = actual,
                },
                _ => return CowUniqueClaim::Shared,
            }
        }
    }

    fn claim_unique(&self, phys_addr: usize) -> CowUniqueClaim {
        match Self::slot(phys_addr) {
            Some(slot) => Self::claim_unique_slot(slot),
            None => CowUniqueClaim::Invalid,
        }
    }

    /// Undo a unique claim if the in-place PTE flag update unexpectedly fails.
    /// Failure indicates metadata corruption; the caller remains fail-closed.
    fn restore_unique_claim(&self, phys_addr: usize) -> bool {
        let Some(slot) = Self::slot(phys_addr) else {
            return false;
        };
        slot.compare_exchange(COW_UNIQUE_CLAIMED, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn finish_unique_claim(&self, phys_addr: usize) -> bool {
        let Some(slot) = Self::slot(phys_addr) else {
            return false;
        };
        slot.compare_exchange(COW_UNIQUE_CLAIMED, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Fallibly stage every refcount delta required by a COW clone.
    ///
    /// The caller holds PT_LOCK, so the leaf plan is stable. Each checked atomic
    /// delta is recorded in its leaf; any failure rolls back the staged prefix
    /// before a parent PTE has been changed.
    fn stage_clone_refs(&self, plan: &mut CowClonePlan) -> Result<(), ForkError> {
        debug_assert!(plan.leaf_updates.iter().all(|leaf| leaf.ref_delta == 0));

        for index in 0..plan.leaf_updates.len() {
            let (phys_addr, flags) = {
                let leaf = &plan.leaf_updates[index];
                (leaf.phys_addr.as_u64() as usize, leaf.original_flags)
            };

            // Supervisor identity-map leaves are copied unchanged. Only actual
            // user mappings consume COW references or become write-protected.
            if !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
                continue;
            }

            let Some(slot) = Self::slot(phys_addr) else {
                self.rollback_clone_refs(&mut plan.leaf_updates[..index]);
                return Err(ForkError::PageTableCopyFailed);
            };
            let delta = match Self::stage_slot(slot, flags) {
                Ok(delta) => delta,
                Err(error) => {
                    self.rollback_clone_refs(&mut plan.leaf_updates[..index]);
                    return Err(error);
                }
            };
            plan.leaf_updates[index].ref_delta = delta;
        }

        Ok(())
    }

    /// Undo a staged prefix without allocation or lookup-container mutation.
    fn rollback_clone_refs(&self, leaves: &mut [LeafUpdate]) {
        for leaf in leaves.iter_mut().rev() {
            let delta = core::mem::replace(&mut leaf.ref_delta, 0);
            if delta == 0 {
                continue;
            }

            let phys_addr = leaf.phys_addr.as_u64() as usize;
            let Some(slot) = Self::slot(phys_addr) else {
                debug_assert!(false, "staged COW refcount address left managed window");
                continue;
            };
            Self::rollback_slot(slot, delta);
        }
    }

    /// Atomically remove one mapping reference. Zero is a stable table value,
    /// so no allocation, removal, cleanup scan, or split get/decrement race exists.
    pub fn release(&self, phys_addr: usize) -> CowPageRelease {
        match Self::slot(phys_addr) {
            Some(slot) => Self::release_slot(slot),
            None => CowPageRelease::Invalid,
        }
    }
}

/// 全局物理页引用计数器
pub static PAGE_REF_COUNT: PhysicalPageRefCount = PhysicalPageRefCount::new();

// ============================================================================
// COW 辅助函数
// ============================================================================

/// COW 标志位（使用 BIT_9，这是 x86_64 页表中可供软件使用的位）
#[inline]
pub(crate) const fn cow_flag() -> PageTableFlags {
    PageTableFlags::BIT_9
}

/// Shared read-only COW tracking without write entitlement. Unlike BIT_9,
/// write faults and copy-to-user validation must never treat this bit as writable.
#[inline]
pub(crate) const fn cow_readonly_flag() -> PageTableFlags {
    PageTableFlags::BIT_10
}

// ============================================================================
// Z-8 fix: 两阶段 COW 实现
// ============================================================================

/// 记录叶子节点需要应用的 COW 修改
///
/// 存储父 PTE 指针、原始标志和物理地址，用于应用阶段
struct LeafUpdate {
    /// 父进程页表项指针
    entry_ptr: *mut PageTableEntry,
    /// 原始标志
    original_flags: PageTableFlags,
    /// 物理地址
    phys_addr: PhysAddr,
    /// RF178-6: exact delta already staged in PAGE_REF_COUNT. Zero until
    /// staging succeeds; used to transactionally unwind a failed prefix.
    ref_delta: u32,
}

/// 记录 COW 复制计划
///
/// 包含所有叶子修改和需要的中间页表帧数量
struct CowClonePlan {
    /// 叶子节点修改列表
    leaf_updates: Vec<LeafUpdate>,
    /// 需要的中间页表帧数量
    tables_needed: usize,
}

impl CowClonePlan {
    fn new() -> Self {
        CowClonePlan {
            leaf_updates: Vec::new(),
            tables_needed: 0,
        }
    }

    // R163-36 FIX: Fallible push to prevent OOM panic during COW planning.
    fn record_leaf(&mut self, entry: &mut PageTableEntry) -> Result<(), ForkError> {
        if self.leaf_updates.try_reserve(1).is_err() {
            return Err(ForkError::MemoryAllocationFailed);
        }
        self.leaf_updates.push(LeafUpdate {
            entry_ptr: entry as *mut PageTableEntry,
            original_flags: entry.flags(),
            phys_addr: entry.addr(),
            ref_delta: 0,
        });
        Ok(())
    }
}

/// 第一阶段：规划 - 遍历收集叶子修改计划并统计需要的新页表帧数量
///
/// 此阶段不修改任何页表项，仅收集信息
fn plan_clone_level(
    parent: &mut PageTable,
    level: u8,
    plan: &mut CowClonePlan,
) -> Result<(), ForkError> {
    // 只处理用户空间（PML4 的索引 0-255）
    let idx_range = if level == 4 { 0..256 } else { 0..512 };

    for idx in idx_range {
        let entry = &mut parent[idx];
        if entry.is_unused() || !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }

        if level == 1 || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // 叶子节点：记录到计划中
            plan.record_leaf(entry)?;
        } else {
            // 中间节点：计数并递归
            plan.tables_needed += 1;
            let parent_next = unsafe { phys_to_virt_table(entry.addr()) };
            plan_clone_level(parent_next, level - 1, plan)?;
        }
    }
    Ok(())
}

/// 第二阶段：预分配所有需要的中间页表帧
///
/// 若分配失败，此时父进程未被修改，直接返回错误即可
///
/// # Z-8b fix: 部分分配失败时回收已分配的帧
///
/// 当分配第 N 个帧失败时，回收已分配的 0..N-1 个帧，
/// 避免物理帧泄漏导致内存 DoS。
fn preallocate_table_frames(
    count: usize,
    frame_alloc: &mut FrameAllocator,
) -> Result<Vec<PhysFrame<Size4KiB>>, ForkError> {
    // R163-5 FIX: Fallible allocation to prevent OOM panic during fork.
    let mut frames = Vec::new();
    if frames.try_reserve_exact(count).is_err() {
        return Err(ForkError::MemoryAllocationFailed);
    }
    for _ in 0..count {
        match frame_alloc.allocate_frame() {
            Some(frame) => frames.push(frame),
            None => {
                // Z-8b fix: 回收已分配的帧，避免部分失败导致物理帧泄漏
                for frame in frames.drain(..) {
                    frame_alloc.deallocate_frame(frame);
                }
                return Err(ForkError::MemoryAllocationFailed);
            }
        }
    }
    Ok(frames)
}

/// R180-19 PREPARE: build the unpublished child page-table tree.
///
/// This consumes only preallocated frames and never changes a parent entry.
/// Keeping parent mutation out of this traversal is what permits KPTI and all
/// other fallible setup to complete before the transaction's commit point.
fn build_child_clone_level(
    parent: &mut PageTable,
    child: &mut PageTable,
    frames: &mut impl Iterator<Item = PhysFrame<Size4KiB>>,
    plan: &CowClonePlan,
    leaf_cursor: &mut usize,
    level: u8,
) {
    // 只处理用户空间（PML4 的索引 0-255）
    let idx_range = if level == 4 { 0..256 } else { 0..512 };

    for idx in idx_range {
        let entry = &mut parent[idx];
        if entry.is_unused() || !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }

        if level == 1 || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // Leaf: prepare only the child's COW view.  The parent is committed
            // later from the stable plan after KPTI and refcounts are ready.
            let planned = plan
                .leaf_updates
                .get(*leaf_cursor)
                .expect("COW prepare traversal must match its locked plan");
            *leaf_cursor += 1;
            debug_assert_eq!(
                planned.entry_ptr, entry as *mut PageTableEntry,
                "COW prepare plan pointer mismatch"
            );
            build_child_leaf(&mut child[idx], planned);
        } else {
            // 中间节点：使用预分配帧
            let frame = frames
                .next()
                .expect("COW apply must have one preallocated frame per planned table");
            unsafe {
                zero_table(frame);
            }

            child[idx].set_addr(frame.start_address(), entry.flags());

            let parent_next = unsafe { phys_to_virt_table(entry.addr()) };
            let child_next = unsafe { phys_to_virt_table(frame.start_address()) };
            build_child_clone_level(
                parent_next,
                child_next,
                frames,
                plan,
                leaf_cursor,
                level - 1,
            );
        }
    }
}

#[inline]
fn cloned_leaf_flags(planned: &LeafUpdate) -> PageTableFlags {
    let mut flags = planned.original_flags;

    if flags.contains(PageTableFlags::USER_ACCESSIBLE) {
        if flags.contains(PageTableFlags::WRITABLE) || flags.contains(cow_flag()) {
            flags.remove(PageTableFlags::WRITABLE);
            flags.remove(cow_readonly_flag());
            flags.insert(cow_flag());
        } else {
            flags.remove(cow_flag());
            flags.insert(cow_readonly_flag());
        }
    }
    flags
}

/// Populate one unpublished child leaf.  Parent state and refcounts are not
/// touched, so this is safe to discard on any later PREPARE failure.
fn build_child_leaf(child_entry: &mut PageTableEntry, planned: &LeafUpdate) {
    child_entry.set_addr(planned.phys_addr, cloned_leaf_flags(planned));
}

/// R180-19 COMMIT: apply all parent COW protections from the PT_LOCK-stable
/// plan.  The caller has already staged exact refcounts and owns every child
/// resource; this pass performs no allocation and has no failure branch.
unsafe fn commit_parent_cow(plan: &CowClonePlan) {
    for planned in plan.leaf_updates.iter() {
        if !planned
            .original_flags
            .contains(PageTableFlags::USER_ACCESSIBLE)
        {
            continue;
        }
        debug_assert!(!planned.entry_ptr.is_null());
        let parent_entry = &mut *planned.entry_ptr;
        debug_assert_eq!(parent_entry.addr(), planned.phys_addr);
        parent_entry.set_addr(planned.phys_addr, cloned_leaf_flags(planned));
    }
}

/// Discard an unpublished child clone without walking/releasing leaf mappings.
/// The exact intermediate-frame ledger is authoritative; clearing the PML4
/// first prevents generic cleanup from following frames after they are returned.
fn rollback_prepared_child_clone(
    child_pml4: &mut PageTable,
    table_frames: &mut Vec<PhysFrame<Size4KiB>>,
    frame_alloc: &mut FrameAllocator,
) {
    for index in 0..256 {
        child_pml4[index].set_unused();
    }
    for frame in table_frames.drain(..).rev() {
        frame_alloc.deallocate_frame(frame);
    }
}

/// Combined leaf helper retained for the boot-time COW regression probes.
/// Production uses the explicit prepare/commit helpers above.
fn apply_leaf(
    parent_entry: &mut PageTableEntry,
    child_entry: &mut PageTableEntry,
    planned: &LeafUpdate,
) {
    debug_assert_eq!(
        planned.entry_ptr, parent_entry as *mut PageTableEntry,
        "COW plan mismatch: entry pointer doesn't match"
    );
    build_child_leaf(child_entry, planned);
    if planned
        .original_flags
        .contains(PageTableFlags::USER_ACCESSIBLE)
    {
        parent_entry.set_addr(planned.phys_addr, cloned_leaf_flags(planned));
    }
}

/// Boot-time RF178-31 regression probes. These use one local atomic slot and
/// never perturb the production COW table.
pub fn run_cow_refcount_self_test() {
    // R180-19: unique-owner recovery must be allocation-free and exact.
    let unique = AtomicU32::new(1);
    assert_eq!(
        PhysicalPageRefCount::claim_unique_slot(&unique),
        CowUniqueClaim::Claimed
    );
    assert_eq!(unique.load(Ordering::Acquire), COW_UNIQUE_CLAIMED);
    assert_eq!(
        PhysicalPageRefCount::release_slot(&unique),
        CowPageRelease::Invalid
    );
    assert!(unique
        .compare_exchange(COW_UNIQUE_CLAIMED, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok());
    let shared = AtomicU32::new(2);
    assert_eq!(
        PhysicalPageRefCount::claim_unique_slot(&shared),
        CowUniqueClaim::Shared
    );
    assert_eq!(shared.load(Ordering::Acquire), 2);
    let missing = AtomicU32::new(0);
    assert_eq!(
        PhysicalPageRefCount::claim_unique_slot(&missing),
        CowUniqueClaim::Invalid
    );

    let user_writable =
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE;
    let user_readonly = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    let slot = AtomicU32::new(0);

    assert_eq!(
        PhysicalPageRefCount::stage_slot(
            &slot,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
        .expect("supervisor stage"),
        0
    );
    assert_eq!(slot.load(Ordering::Acquire), 0);
    assert!(matches!(
        PhysicalPageRefCount::stage_slot(&slot, user_writable | PageTableFlags::HUGE_PAGE),
        Err(ForkError::PageTableCopyFailed)
    ));
    assert!(matches!(
        PhysicalPageRefCount::stage_slot(&slot, user_readonly | cow_flag()),
        Err(ForkError::PageTableCopyFailed)
    ));
    assert!(matches!(
        PhysicalPageRefCount::stage_slot(&slot, user_readonly | cow_readonly_flag()),
        Err(ForkError::PageTableCopyFailed)
    ));
    assert_eq!(slot.load(Ordering::Acquire), 0);

    let first =
        PhysicalPageRefCount::stage_slot(&slot, user_writable).expect("first writable COW stage");
    assert_eq!(first, 2);
    assert!(matches!(
        PhysicalPageRefCount::stage_slot(&slot, user_readonly),
        Err(ForkError::PageTableCopyFailed)
    ));
    assert_eq!(slot.load(Ordering::Acquire), 2);
    let child = PhysicalPageRefCount::stage_slot(&slot, user_readonly | cow_readonly_flag())
        .expect("existing COW stage");
    assert_eq!(child, 1);
    assert_eq!(slot.load(Ordering::Acquire), 3);
    assert_eq!(
        PhysicalPageRefCount::release_slot(&slot),
        CowPageRelease::Remaining(2)
    );
    assert_eq!(
        PhysicalPageRefCount::release_slot(&slot),
        CowPageRelease::Remaining(1)
    );
    assert_eq!(
        PhysicalPageRefCount::release_slot(&slot),
        CowPageRelease::Last
    );
    assert_eq!(
        PhysicalPageRefCount::release_slot(&slot),
        CowPageRelease::Untracked
    );

    let readonly_first =
        PhysicalPageRefCount::stage_slot(&slot, user_readonly).expect("first read-only COW stage");
    assert_eq!(readonly_first, 2);
    slot.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        value.checked_add(1)
    })
    .expect("unrelated checked increment");
    PhysicalPageRefCount::rollback_slot(&slot, readonly_first);
    assert_eq!(slot.load(Ordering::Acquire), 1);

    slot.store(u32::MAX, Ordering::Release);
    assert!(matches!(
        PhysicalPageRefCount::stage_slot(&slot, user_readonly | cow_readonly_flag()),
        Err(ForkError::PageTableCopyFailed)
    ));
    assert_eq!(slot.load(Ordering::Acquire), u32::MAX);

    let (base, pages) = mm::memory::managed_physical_page_window()
        .expect("buddy physical window must precede integration tests");
    let base = usize::try_from(base).expect("physical base fits usize");
    // RF178-31: the boot-reserved table must cover the full managed window
    // (including the last page index) and reject addresses outside it.
    assert!(
        mm::memory::cow_refcount_slot(0).is_some(),
        "COW refcount table must be published before self-test"
    );
    assert!(
        mm::memory::cow_refcount_slot(pages - 1).is_some(),
        "COW refcount table must cover last managed page"
    );
    assert!(
        mm::memory::cow_refcount_slot(pages).is_none(),
        "COW refcount table must not over-claim past managed pages"
    );
    assert!(PhysicalPageRefCount::slot(base).is_some());
    assert!(PhysicalPageRefCount::slot(base + (pages - 1) * 4096).is_some());
    assert!(PhysicalPageRefCount::slot(base + pages * 4096).is_none());
    assert!(PhysicalPageRefCount::slot(base + 1).is_none());
    if base >= 4096 {
        assert!(PhysicalPageRefCount::slot(base - 4096).is_none());
    }

    // Exercise the production transaction through two deltas for the same
    // frame followed by an invalid address. Rollback must restore both the
    // fixed slot and every receipt before any PTE apply.
    let production_slot = PhysicalPageRefCount::slot(base).expect("first managed slot");
    assert_eq!(production_slot.load(Ordering::Acquire), 0);
    let mut plan = CowClonePlan::new();
    plan.leaf_updates
        .try_reserve_exact(3)
        .expect("three-leaf rollback plan");
    let invalid_phys = base
        .checked_add(pages * 4096)
        .expect("managed-window end fits usize");
    for (phys, flags) in [
        (base, user_writable),
        (base, user_readonly | cow_readonly_flag()),
        (invalid_phys, user_writable),
    ] {
        plan.leaf_updates.push(LeafUpdate {
            entry_ptr: core::ptr::null_mut(),
            original_flags: flags,
            phys_addr: PhysAddr::new(phys as u64),
            ref_delta: 0,
        });
    }
    let staged = x86_64::instructions::interrupts::without_interrupts(|| {
        PAGE_REF_COUNT.stage_clone_refs(&mut plan)
    });
    assert!(matches!(staged, Err(ForkError::PageTableCopyFailed)));
    assert_eq!(production_slot.load(Ordering::Acquire), 0);
    assert!(plan.leaf_updates.iter().all(|leaf| leaf.ref_delta == 0));

    let supervisor_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let mut supervisor_parent = PageTableEntry::new();
    let mut supervisor_child = PageTableEntry::new();
    supervisor_parent.set_addr(PhysAddr::new(base as u64), supervisor_flags);
    let supervisor_plan = LeafUpdate {
        entry_ptr: &mut supervisor_parent,
        original_flags: supervisor_flags,
        phys_addr: PhysAddr::new(base as u64),
        ref_delta: 0,
    };
    apply_leaf(
        &mut supervisor_parent,
        &mut supervisor_child,
        &supervisor_plan,
    );
    assert!(supervisor_parent.flags().contains(PageTableFlags::WRITABLE));
    assert!(!supervisor_parent.flags().contains(cow_flag()));
    assert!(supervisor_child.flags().contains(PageTableFlags::WRITABLE));

    let mut readonly_parent = PageTableEntry::new();
    let mut readonly_child = PageTableEntry::new();
    readonly_parent.set_addr(PhysAddr::new(base as u64), user_readonly);
    let readonly_plan = LeafUpdate {
        entry_ptr: &mut readonly_parent,
        original_flags: user_readonly,
        phys_addr: PhysAddr::new(base as u64),
        ref_delta: 2,
    };
    // R180-19 PREPARE must construct the child view without touching parent
    // flags; only the explicit commit helper may add the parent's COW marker.
    build_child_leaf(&mut readonly_child, &readonly_plan);
    assert!(!readonly_parent.flags().contains(cow_readonly_flag()));
    assert!(readonly_child.flags().contains(cow_readonly_flag()));
    apply_leaf(&mut readonly_parent, &mut readonly_child, &readonly_plan);
    assert!(readonly_parent.flags().contains(cow_readonly_flag()));
    assert!(readonly_child.flags().contains(cow_readonly_flag()));
    assert!(!readonly_parent.flags().contains(cow_flag()));
    assert!(!readonly_child.flags().contains(cow_flag()));
    assert!(!readonly_parent.flags().contains(PageTableFlags::WRITABLE));

    let write_cow_flags = user_readonly | cow_flag();
    let mut refork_parent = PageTableEntry::new();
    let mut refork_child = PageTableEntry::new();
    refork_parent.set_addr(PhysAddr::new(base as u64), write_cow_flags);
    let refork_plan = LeafUpdate {
        entry_ptr: &mut refork_parent,
        original_flags: write_cow_flags,
        phys_addr: PhysAddr::new(base as u64),
        ref_delta: 1,
    };
    apply_leaf(&mut refork_parent, &mut refork_child, &refork_plan);
    assert!(refork_parent.flags().contains(cow_flag()));
    assert!(refork_child.flags().contains(cow_flag()));
    assert!(!refork_parent.flags().contains(cow_readonly_flag()));
    assert!(!refork_child.flags().contains(cow_readonly_flag()));
}

/// 将物理地址转换为页表引用
///
/// # Safety
///
/// 调用者必须确保物理地址指向有效的页表
unsafe fn phys_to_virt_table(phys: PhysAddr) -> &'static mut PageTable {
    // 使用高半区直映访问物理内存
    let virt = mm::phys_to_virt(phys);
    let ptr = virt.as_mut_ptr::<PageTable>();
    &mut *ptr
}

/// 将物理帧清零
unsafe fn zero_table(frame: PhysFrame) {
    let virt = mm::phys_to_virt(frame.start_address());
    core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 4096);
}

/// RF178-15 FIX: private-frame rollback ledger for fresh address spaces.
/// Copied identity-map leaves are shared and must never be recursively freed.
/// The constructor allocates at most root + PDPT + PD + PT.
struct FreshSpaceGuard {
    frames: [Option<PhysFrame<Size4KiB>>; 4],
    len: usize,
    committed: bool,
}

impl FreshSpaceGuard {
    fn new(root: PhysFrame<Size4KiB>) -> Self {
        let mut frames = [None; 4];
        frames[0] = Some(root);
        Self {
            frames,
            len: 1,
            committed: false,
        }
    }

    fn track(&mut self, frame: PhysFrame<Size4KiB>) -> Result<(), ForkError> {
        if self.len >= self.frames.len() {
            let mut allocator = FrameAllocator::new();
            allocator.deallocate_frame(frame);
            return Err(ForkError::PageTableCopyFailed);
        }
        self.frames[self.len] = Some(frame);
        self.len += 1;
        Ok(())
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for FreshSpaceGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut allocator = FrameAllocator::new();
        for index in (0..self.len).rev() {
            if let Some(frame) = self.frames[index].take() {
                allocator.deallocate_frame(frame);
            }
        }
    }
}

/// 创建新的用户地址空间
///
/// 分配新的 PML4 页表并复制内核高半区映射（索引 256-511）。
/// 用户空间（索引 0-255）为空，供后续 ELF 加载使用。
///
/// # Returns
///
/// 成功返回新 PML4 的物理帧和物理地址，失败返回 ForkError
///
/// # Safety
///
/// 返回的页表必须在使用完毕后释放，否则会内存泄漏。
pub fn create_fresh_address_space() -> Result<(PhysFrame<Size4KiB>, usize), ForkError> {
    let mut frame_alloc = FrameAllocator::new();

    // 分配新的 PML4 帧
    let new_pml4_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;

    // R178-17 / RF178-15: arm private-frame rollback immediately after root
    // allocation, before any subsequent fallible table construction.
    let mut construction_guard = FreshSpaceGuard::new(new_pml4_frame);

    // 清零新页表
    unsafe {
        zero_table(new_pml4_frame);
    }

    // 获取当前页表根（复制内核映射）
    let (current_frame, _) = Cr3::read();

    // 递归页表槽索引 (PML4[510] 指向 PML4 自身)
    const RECURSIVE_INDEX: usize = 510;

    unsafe {
        let current_pml4 = phys_to_virt_table(current_frame.start_address());
        let new_pml4 = phys_to_virt_table(new_pml4_frame.start_address());

        // 【关键修复】深拷贝 PML4[0] 并为用户空间准备 4KB 页映射
        //
        // PML4[0] 包含恒等映射（0-4GB），使用 2MB 大页。
        // 用户空间需要 4KB 页映射，所以我们需要：
        // 1. 深拷贝 PML4[0] 路径上的页表（避免影响内核的恒等映射）
        // 2. 将用户空间区域（0x400000 附近）的 2MB 大页拆分为 4KB 页
        if !current_pml4[0].is_unused() {
            deep_copy_identity_for_user(
                current_pml4,
                new_pml4,
                &mut frame_alloc,
                &mut construction_guard,
            )?;
        }

        // 复制内核高半区映射（索引 256-511）
        // 这些映射在所有进程间共享
        // R94-5 FIX: Explicitly clear USER_ACCESSIBLE on kernel high-half entries.
        // Defense-in-depth: even if parent entries are corrupted with U/S bit,
        // child address space must not inherit user-accessibility to kernel space.
        for i in 256..512 {
            new_pml4[i] = current_pml4[i].clone();
            if !new_pml4[i].is_unused() {
                let addr = new_pml4[i].addr();
                let mut flags = new_pml4[i].flags();
                flags.remove(PageTableFlags::USER_ACCESSIBLE);
                new_pml4[i].set_addr(addr, flags);
            }
        }

        // 【关键修复】设置新页表的递归映射
        // PML4[510] 必须指向新的 PML4 帧自身，而不是从 boot 页表复制的旧值
        // 这样 recursive_pml4() 等函数才能正确访问新页表的条目
        let recursive_flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        new_pml4[RECURSIVE_INDEX].set_frame(new_pml4_frame, recursive_flags);
    }

    // R178-17 FIX: Commit the guard — construction succeeded, no rollback needed.
    construction_guard.commit();

    let phys_addr = new_pml4_frame.start_address().as_u64() as usize;
    Ok((new_pml4_frame, phys_addr))
}

/// H.3 KPTI: Create a user-mode PML4 root for KPTI dual page tables.
///
/// The user PML4 provides the address space visible under the user CR3:
/// - **User half (PML4[0..255])**: Shares the same sub-table pointers as the
///   kernel PML4. Both roots see identical user-space mappings without duplicating
///   page table frames below PML4 level.
/// - **Kernel half (PML4[256..510])**: Empty — kernel text/data/heap is NOT mapped.
///   This is the core KPTI isolation property.
/// - **Entry island (PML4[511])**: Copied from the kernel PML4 to ensure the
///   syscall/interrupt entry stubs, GS-based per-CPU data, IDT, GDT, and TSS
///   remain accessible before the CR3 switch to kernel mode. Mapped as
///   supervisor-only (USER_ACCESSIBLE cleared).
/// - **Recursive slot (PML4[510])**: Explicitly empty — user CR3 must not have
///   self-referencing page table access.
///
/// # Bring-Up Note
///
/// The current PML4[511] copy is a coarse mapping that exposes more kernel pages
/// than strictly necessary (the entire high-half direct-map region covered by that
/// single PML4 entry). A production KPTI implementation should replace this with a
/// page-granular trampoline island. However, all entries remain supervisor-only,
/// so user-mode code cannot access them — the exposure is only to Meltdown-class
/// speculative reads, which KPTI is designed to mitigate.
///
/// # Lifetime
///
/// The user PML4 root frame is privately owned. User-half entries are shared
/// pointers into the kernel PML4's sub-tables and MUST NOT be recursively freed.
/// Call `free_kpti_user_pml4()` to release only the root frame.
///
/// # Arguments
///
/// * `kernel_pml4_phys` - Physical address of the kernel PML4 root
///
/// # Returns
///
/// `(PhysFrame, usize)` — the user PML4 frame and its physical address
pub fn create_kpti_user_pml4(
    kernel_pml4_phys: usize,
) -> Result<(PhysFrame<Size4KiB>, usize), ForkError> {
    let mut frame_alloc = FrameAllocator::new();

    // Mask low 12 bits defensively (PCID bits may be present in raw CR3 values)
    let kernel_pml4_phys = kernel_pml4_phys & !0xFFF;
    if kernel_pml4_phys == 0 {
        return Err(ForkError::PageTableCopyFailed);
    }

    // Allocate user PML4 root
    let user_pml4_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;
    unsafe {
        zero_table(user_pml4_frame);
    }

    // R118-5 FIX: Allocate a dedicated PDPT for the entry island (PML4[511]).
    //
    // Instead of copying the kernel's full PML4[511] (which maps 512 GiB),
    // we create a fresh PDPT and copy only the top 4 GiB (PDPT[508..=511]).
    // This limits speculative Meltdown-style exposure from 512 GiB to 4 GiB,
    // covering only the regions actually needed by the trampoline:
    //   - Kernel text/data (.text at 0xffffffff80100000)
    //   - Per-CPU syscall metadata (SyscallPerCpu)
    //   - IDT/GDT/TSS and scratch stacks
    let entry_island_pdpt_frame = match frame_alloc.allocate_frame() {
        Some(f) => f,
        None => {
            // Roll back: free the PML4 frame that was already allocated above.
            frame_alloc.deallocate_frame(user_pml4_frame);
            return Err(ForkError::MemoryAllocationFailed);
        }
    };
    unsafe {
        zero_table(entry_island_pdpt_frame);
    }

    let kernel_pml4_frame: PhysFrame<Size4KiB> =
        PhysFrame::containing_address(PhysAddr::new(kernel_pml4_phys as u64));

    /// User-half boundary: PML4 indices 0..255
    const USER_HALF_END: usize = 256;
    /// Recursive page table slot — must be empty in user PML4
    const RECURSIVE_INDEX: usize = 510;
    /// Entry island slot — contains kernel text/entry stubs/IDT/GDT/TSS
    const ENTRY_ISLAND_INDEX: usize = 511;

    unsafe {
        let kernel_pml4 = phys_to_virt_table(kernel_pml4_frame.start_address());
        let user_pml4 = phys_to_virt_table(user_pml4_frame.start_address());

        // ── Share user-half entries (PML4[0..255]) ──
        //
        // These are raw pointer copies — the user PML4 shares the same PDPT/PD/PT
        // frames as the kernel PML4. Any PML4-level change to user mappings must
        // update both roots (currently only create_fresh_address_space modifies
        // PML4[0], and we mirror it here).
        for i in 0..USER_HALF_END {
            user_pml4[i] = kernel_pml4[i].clone();
        }

        // ── Ensure no recursive mapping ──
        user_pml4[RECURSIVE_INDEX].set_unused();

        // ── Map entry island (PML4[511]) ──
        //
        // R118-5 FIX: Instead of copying the kernel's PML4[511] verbatim (512 GiB),
        // point to a dedicated PDPT that only maps the top 4 GiB (PDPT[508..=511]).
        //
        // R121-2 NOTE: All four PDPT entries are currently required:
        //   - PDPT[508]: Per-process kernel stacks (KSTACK_BASE = 0xffff_ffff_0000_0000)
        //                TSS.RSP0 points here; must be mapped during Ring 3→0 transitions.
        //   - PDPT[509]: stack_guard guarded RSP0/IST stacks mapped during boot.
        //   - PDPT[510]: Kernel .text/.rodata/.data/.bss + statics (GDT, TSS,
        //                SYSCALL_PERCPU, scratch stacks).
        //   - PDPT[511]: Heap allocations (IDT via lazy_static, etc.)
        //
        // A tighter island (R121-2 final) requires relocating kernel stacks
        // into PDPT[510..=511] or using a dedicated entry stack in the island,
        // plus moving IDT/GDT/TSS into dedicated linker sections at known
        // page-aligned addresses — deferred to dedicated KPTI hardening cycle.
        //
        // All entries are supervisor-only (USER_ACCESSIBLE removed at both PML4
        // and PDPT levels) to prevent normal Ring 3 access and limit Meltdown-style
        // speculative exposure to 4 GiB instead of 512 GiB.
        if !kernel_pml4[ENTRY_ISLAND_INDEX].is_unused() {
            let mut island_flags = kernel_pml4[ENTRY_ISLAND_INDEX].flags();
            island_flags.remove(PageTableFlags::USER_ACCESSIBLE);
            user_pml4[ENTRY_ISLAND_INDEX].set_frame(entry_island_pdpt_frame, island_flags);

            let kernel_pdpt = phys_to_virt_table(kernel_pml4[ENTRY_ISLAND_INDEX].addr());
            let island_pdpt = phys_to_virt_table(entry_island_pdpt_frame.start_address());

            // Copy only PDPT[508..=511] (top 4 GiB) from kernel's PDPT.
            // PDPT[0..508] remain absent (not present) in the user PDPT.
            for i in 508..512 {
                island_pdpt[i] = kernel_pdpt[i].clone();
                if !island_pdpt[i].is_unused() {
                    let addr = island_pdpt[i].addr();
                    let mut flags = island_pdpt[i].flags();
                    flags.remove(PageTableFlags::USER_ACCESSIBLE);
                    island_pdpt[i].set_addr(addr, flags);
                }
            }
        }
    }

    let phys_addr = user_pml4_frame.start_address().as_u64() as usize;
    Ok((user_pml4_frame, phys_addr))
}

/// H.3 KPTI: Free a user PML4 root created by `create_kpti_user_pml4()`.
///
/// Deallocates the root PML4 frame and its dedicated entry-island PDPT frame.
/// User-half entries (PML4[0..255]) are shared pointers into the kernel PML4's
/// sub-tables and MUST NOT be freed here (they are freed when
/// `free_address_space()` is called on the kernel PML4).
///
/// # Safety
///
/// The caller must ensure the user PML4 is not loaded in any CPU's CR3.
pub fn free_kpti_user_pml4(user_memory_space: usize) {
    if user_memory_space == 0 {
        return;
    }

    let mut frame_alloc = FrameAllocator::new();
    let root_frame: PhysFrame<Size4KiB> =
        PhysFrame::containing_address(PhysAddr::new(user_memory_space as u64));

    // R118-5 FIX: Free the privately-owned entry-island PDPT frame (PML4[511]).
    unsafe {
        const ENTRY_ISLAND_INDEX: usize = 511;
        let user_pml4 = phys_to_virt_table(root_frame.start_address());
        if !user_pml4[ENTRY_ISLAND_INDEX].is_unused() {
            let pdpt_phys = user_pml4[ENTRY_ISLAND_INDEX].addr();
            user_pml4[ENTRY_ISLAND_INDEX].set_unused();
            let pdpt_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(pdpt_phys);
            frame_alloc.deallocate_frame(pdpt_frame);
        }
    }

    frame_alloc.deallocate_frame(root_frame);
}

/// 深拷贝恒等映射 PML4[0]，并为用户空间准备 4KB 页映射
///
/// 用户空间起始地址 0x400000 (4MB) 落在：
/// - PML4[0] (0-512GB)
/// - PDPT[0] (0-1GB)
/// - PD[2] (4MB-6MB，因为每个 PD entry 覆盖 2MB)
///
/// 我们需要：
/// 1. 为新页表分配独立的 PDPT（深拷贝）
/// 2. 为 PDPT[0] 分配独立的 PD（深拷贝）
/// 3. 将 PD[2] 的 2MB 大页拆分为 4KB PT（如果需要）
///
/// 这样用户空间可以使用 4KB 页，而内核的恒等映射不受影响。
///
/// # R93-7 FIX: USER_ACCESSIBLE Propagation
///
/// When copying page table entries, we must ensure USER_ACCESSIBLE is set on
/// all entries in the path from PML4 down to the leaf page tables that user
/// space might traverse. Previously, only specific indices were modified,
/// leaving other entries as supervisor-only which caused spurious #PF.
unsafe fn deep_copy_identity_for_user(
    current_pml4: &mut PageTable,
    new_pml4: &mut PageTable,
    frame_alloc: &mut FrameAllocator,
    construction_guard: &mut FreshSpaceGuard,
) -> Result<(), ForkError> {
    // 用户空间起始地址对应的页表索引
    const USER_BASE: usize = 0x400000; // 4MB
    const PDPT_IDX: usize = 0; // 0-1GB 在 PDPT[0]
    const PD_IDX: usize = 2; // 4MB-6MB 在 PD[2] (4MB / 2MB = 2)

    let current_pml4_0 = &current_pml4[0];
    if current_pml4_0.is_unused() {
        return Ok(()); // 没有恒等映射，无需处理
    }

    // Step 1: 分配新的 PDPT
    let new_pdpt_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;
    construction_guard.track(new_pdpt_frame)?;
    zero_table(new_pdpt_frame);

    // 复制 PDPT 条目
    // R93-7 FIX (revised): Only PDPT[0] needs USER_ACCESSIBLE for user space.
    // Other PDPT entries (1-511) are identity map for physical memory beyond 1GB.
    // Setting USER_ACCESSIBLE on those would expose kernel memory and break SMAP.
    // We copy them as supervisor-only to maintain isolation.
    // R94-5 FIX: Explicitly clear USER_ACCESSIBLE on all non-PDPT_IDX entries.
    // Defense-in-depth: prevent propagation even if parent has corrupted flags.
    let current_pdpt = phys_to_virt_table(current_pml4_0.addr());
    let new_pdpt = phys_to_virt_table(new_pdpt_frame.start_address());
    for i in 0..512 {
        new_pdpt[i] = current_pdpt[i].clone();
        // R94-5 FIX: Explicitly clear USER_ACCESSIBLE except for PDPT_IDX
        if i != PDPT_IDX && !new_pdpt[i].is_unused() {
            let addr = new_pdpt[i].addr();
            let mut flags = new_pdpt[i].flags();
            flags.remove(PageTableFlags::USER_ACCESSIBLE);
            new_pdpt[i].set_addr(addr, flags);
        }
    }

    // 更新新 PML4[0] 指向新 PDPT
    // 【关键修复】添加 USER_ACCESSIBLE 以允许用户态访问
    let mut pml4_flags = current_pml4_0.flags();
    pml4_flags.insert(PageTableFlags::USER_ACCESSIBLE);
    new_pml4[0].set_addr(new_pdpt_frame.start_address(), pml4_flags);

    // Step 2: 检查 PDPT[0]（0-1GB 区域）
    let current_pdpt_0 = &current_pdpt[PDPT_IDX];
    if current_pdpt_0.is_unused() {
        return Ok(()); // 0-1GB 未映射
    }

    // 如果 PDPT[0] 是 1GB 大页，我们不支持拆分（太复杂）
    if current_pdpt_0.flags().contains(PageTableFlags::HUGE_PAGE) {
        kprintln!("WARNING: 1GB huge page at PDPT[0], cannot split for user space");
        return Err(ForkError::PageTableCopyFailed);
    }

    // Step 3: 分配新的 PD
    let new_pd_frame = frame_alloc
        .allocate_frame()
        .ok_or(ForkError::MemoryAllocationFailed)?;
    construction_guard.track(new_pd_frame)?;
    zero_table(new_pd_frame);

    // 复制 PD 条目
    // R93-7 FIX (revised): Only PD[2] (4MB-6MB region) needs USER_ACCESSIBLE.
    // Other PD entries are identity-mapped kernel memory (0-4MB, 6MB-1GB).
    // Setting USER_ACCESSIBLE on those would:
    // 1. Break SMAP - kernel can't access "user" pages without STAC
    // 2. Expose kernel memory to user space
    // We copy them as supervisor-only; USER_ACCESSIBLE is set on PD[2] below.
    // R94-5 FIX: Explicitly clear USER_ACCESSIBLE on all non-PD_IDX entries.
    // Defense-in-depth: prevent propagation even if parent has corrupted flags.
    let current_pd = phys_to_virt_table(current_pdpt_0.addr());
    let new_pd = phys_to_virt_table(new_pd_frame.start_address());
    for i in 0..512 {
        new_pd[i] = current_pd[i].clone();
        // R94-5 FIX: Explicitly clear USER_ACCESSIBLE except for PD_IDX
        if i != PD_IDX && !new_pd[i].is_unused() {
            let addr = new_pd[i].addr();
            let mut flags = new_pd[i].flags();
            flags.remove(PageTableFlags::USER_ACCESSIBLE);
            new_pd[i].set_addr(addr, flags);
        }
    }

    // 更新新 PDPT[0] 指向新 PD
    // 【关键修复】添加 USER_ACCESSIBLE 以允许用户态访问
    let mut pdpt_flags = current_pdpt_0.flags();
    pdpt_flags.insert(PageTableFlags::USER_ACCESSIBLE);
    new_pdpt[PDPT_IDX].set_addr(new_pd_frame.start_address(), pdpt_flags);

    // Step 4: 检查并拆分 PD[2]（4MB-6MB 区域）的 2MB 大页
    let current_pd_entry = &new_pd[PD_IDX];
    if current_pd_entry.is_unused() {
        return Ok(()); // 4MB-6MB 未映射
    }

    if current_pd_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        // 这是 2MB 大页，需要拆分为 4KB PT
        // 但我们不填充 PT 条目，而是留空让 ELF loader 创建新映射
        // 用户进程不需要 identity mapping，它会有自己的物理帧

        // 分配新的 PT
        let new_pt_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;
        construction_guard.track(new_pt_frame)?;
        zero_table(new_pt_frame); // PT 保持为空，不填充 identity mapping

        // 更新 PD[2] 指向新的空 PT（不再是大页）
        // 【关键修复】添加 USER_ACCESSIBLE，移除 NO_EXECUTE 以允许用户代码执行
        // NX 位会被 ELF loader 在 PT 级别按需设置
        let mut pd_flags = current_pd_entry.flags();
        pd_flags.remove(PageTableFlags::HUGE_PAGE);
        pd_flags.remove(PageTableFlags::DIRTY); // DIRTY 是叶子页专有
        pd_flags.remove(PageTableFlags::NO_EXECUTE); // 允许子页按需设置执行权限
        pd_flags.insert(PageTableFlags::USER_ACCESSIBLE);
        new_pd[PD_IDX].set_addr(new_pt_frame.start_address(), pd_flags);
    } else {
        // R94-5 FIX: Always allocate a fresh empty PT for the user base region.
        //
        // Even if the boot mapping already uses a 4KB PT at PD[2], reusing it risks
        // sharing page-table pages with the kernel identity map (cross-process corruption
        // and potential USER_ACCESSIBLE flag escalation).
        //
        // Previous code: reused pd_addr from current_pd_entry, which shared the PT
        // page with the kernel. Now we allocate a fresh empty PT instead.
        //
        // Leave the PT empty: ELF loader will populate user mappings.
        let new_pt_frame = frame_alloc
            .allocate_frame()
            .ok_or(ForkError::MemoryAllocationFailed)?;
        construction_guard.track(new_pt_frame)?;
        zero_table(new_pt_frame); // PT 保持为空，不填充 identity mapping

        // 【关键修复】添加 USER_ACCESSIBLE，移除 NO_EXECUTE 以允许用户代码执行
        // NX 位会被 ELF loader 在 PT 级别按需设置
        let mut pd_flags = current_pd_entry.flags();
        pd_flags.remove(PageTableFlags::NO_EXECUTE); // 允许子页按需设置执行权限
        pd_flags.insert(PageTableFlags::USER_ACCESSIBLE);
        new_pd[PD_IDX].set_addr(new_pt_frame.start_address(), pd_flags);
    }

    Ok(())
}
