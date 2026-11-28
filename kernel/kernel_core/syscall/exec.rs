//! Syscall family module: `exec` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

/// Keeps a thread group closed to new threads from the exec drain until
/// `exec_from_bytes` returns, on success and on every rollback.
pub(super) struct ExecDrainGuard(Arc<crate::process::ThreadGroup>);

impl Drop for ExecDrainGuard {
    fn drop(&mut self) {
        self.0.end_exec_drain();
    }
}

impl ExecDrainGuard {
    /// GAP-5 exec step 2: pass the claim to the leader's exec, whose own guard
    /// releases it, without releasing it here.
    fn hand_over(self) {
        let guard = core::mem::ManuallyDrop::new(self);
        // SAFETY: `guard` is never used or dropped again, so the group handle
        // is moved out exactly once.
        drop(unsafe { core::ptr::read(&guard.0) });
    }
}

/// GAP-5 slice 4, exec step 1 (leader exec): end every other member of the
/// caller's thread group before exec replaces its image, as Linux `de_thread`
/// does. A lone task returns `Ok(None)`. Otherwise:
/// - a non-leader gets `EBUSY` (it would have to take over the group's PID);
/// - a task outside the group that shares the address space (a `CLONE_VM`
///   child that is not a thread) gets `EBUSY` before anyone is ended;
/// - in a group that is already exiting, or when a fatal exit is posted to
///   the caller while it waits, the caller waits for its own posted exit and
///   gets `EINTR`; the syscall epilogue then ends it.
///
/// The wait holds no lock and is interrupted only by a fatal exit, like
/// Linux's killable wait. It ends once the caller is the only member, owns the
/// fd table alone, and no reaped sibling is still in its Phase-2 cleanup,
/// which releases the fd table and reads the shared `MmState` that exec then
/// rewrites. Siblings ran their clear-tid writes and robust-list walks before
/// their reap, while the old address space was still live.
///
/// GAP-5 exec step 2: with `via_handoff` the leader runs an exec a non-leader
/// handed it. That thread already holds the drain claim, which this guard now
/// owns and releases even if the group is already down to this task.
pub(super) fn drain_thread_group_for_exec(
    process: &crate::process::ProcessArc,
    pid: ProcessId,
    via_handoff: bool,
) -> Result<Option<ExecDrainGuard>, SyscallError> {
    use crate::process::{
        address_space_foreign_sharers, request_exit_group_atomic, tgid_reap_in_flight,
    };

    let (tgid, memory_space, group, files) = {
        let proc = process.lock();
        (
            proc.tgid,
            proc.memory_space,
            Arc::clone(&proc.thread_group),
            Arc::clone(&proc.files),
        )
    };
    let guard = if via_handoff {
        ExecDrainGuard(Arc::clone(&group))
    } else {
        if group.members() <= 1 {
            return Ok(None);
        }
        if tgid != pid {
            // Non-leaders hand their exec to the leader before reaching here.
            return Err(SyscallError::EBUSY);
        }
        wait_for_posted_group_exit(&group, pid)?;
        claim_exec_drain(&group, pid)?
    };
    wait_for_posted_group_exit(&group, pid)?;

    // Claimed before this scan: a non-thread CLONE_VM clone checks the claim
    // under the child lock that publishes the child's address space, so either
    // the scan sees that child or the clone sees the claim and aborts.
    if address_space_foreign_sharers(memory_space, &group) > 0 {
        return Err(SyscallError::EBUSY);
    }

    // The drain flag is published before this scan takes PROCESS_TABLE, and
    // clone checks it at publication under the same lock: a thread published
    // earlier is a member this scan ends, a later one aborts its clone.
    let _ = request_exit_group_atomic(
        pid,
        &group,
        crate::signal::signal_exit_code(crate::signal::Signal::SIGKILL),
    );

    loop {
        crate::process::run_blocked_wait_drains();
        if wait_should_abort(pid) {
            return Err(SyscallError::EINTR);
        }
        if group.members() == 1 && files.lock().owners() == 1 && !tgid_reap_in_flight(tgid) {
            return Ok(Some(guard));
        }
        yield_and_halt();
    }
}

/// exit_group and a group-fatal exit publish `exiting` before they post the
/// exit to this task; wait for that post rather than return EINTR to user
/// mode first (the syscall epilogue then ends the task).
pub(super) fn wait_for_posted_group_exit(
    group: &crate::process::ThreadGroup,
    pid: ProcessId,
) -> Result<(), SyscallError> {
    if !group.exiting.load(core::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }
    loop {
        if wait_should_abort(pid) {
            return Err(SyscallError::EINTR);
        }
        yield_and_halt();
    }
}

/// Take the group's exec drain claim. While another exec holds it, wait
/// (killably) until it is released: that exec either ends this task or fails
/// and lets this one proceed. A leader whose wait ends for a handoff returns
/// `EINTR`, and its syscall return runs the handed-over exec instead.
pub(super) fn claim_exec_drain(
    group: &Arc<crate::process::ThreadGroup>,
    pid: ProcessId,
) -> Result<ExecDrainGuard, SyscallError> {
    loop {
        if group.try_begin_exec_drain() {
            return Ok(ExecDrainGuard(Arc::clone(group)));
        }
        if wait_should_abort(pid) {
            return Err(SyscallError::EINTR);
        }
        yield_and_halt();
    }
}

/// GAP-5 exec step 2: the trampoline a leader with a pending handoff is sent
/// to from a timer interrupt: `mov eax, 39; syscall; ud2`. Any syscall entry
/// takes the handoff, so the `getpid` never runs; the `ud2` is reached only if
/// the handoff vanished, which no path does without a fatal exit.
pub(super) const EXEC_STUB_CODE: [u8; 9] = [0xB8, 0x27, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x0F, 0x0B];

/// The page just above the main stack. Its page table always exists (the
/// eager stack pages share it), the KPTI user root shares it, and `mmap` and
/// `mremap` never place a user mapping there (`user_mapping_reserved_window`),
/// so a present page there is a stub left by an earlier, abandoned handoff.
pub(super) const EXEC_STUB_VA: u64 = crate::elf_loader::USER_STACK_TOP;

/// Make sure the stub is mapped read-only and executable at `EXEC_STUB_VA` in
/// the current (shared) address space. A newly mapped frame is an ordinary
/// untracked user page: teardown and exec free it, fork copies it like any
/// read-only page. Fails without side effects.
pub(super) fn ensure_exec_stub() -> Result<(), SyscallError> {
    use x86_64::structures::paging::{FrameAllocator, Page, PhysFrame, Size4KiB};

    // The page table exists, so a map that needs a table frame is refused.
    struct NoTableFrames;
    // SAFETY: never hands out a frame.
    unsafe impl FrameAllocator<Size4KiB> for NoTableFrames {
        fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
            None
        }
    }

    let frame = mm::memory::FrameAllocator::new()
        .allocate_frame()
        .ok_or(SyscallError::ENOMEM)?;
    // SAFETY: a fresh frame owned by this function, reached through the
    // direct map.
    unsafe {
        let page = mm::phys_to_virt(frame.start_address()).as_mut_ptr::<u8>();
        core::ptr::write_bytes(page, 0, 0x1000);
        // lint-repr-c-copy: allow (a byte array of code, no struct padding)
        core::ptr::copy_nonoverlapping(EXEC_STUB_CODE.as_ptr(), page, EXEC_STUB_CODE.len());
    }
    let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(EXEC_STUB_VA));
    let flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    // SAFETY: PT_LOCK-guarded walk and edit of the current address space; the
    // page is not mapped, and a not-present entry has no TLB entry to flush on
    // other CPUs.
    let mapped = unsafe {
        mm::page_table::with_current_manager(VirtAddr::new(0), |mgr| {
            if mgr.translate_addr(page.start_address()).is_some() {
                return Ok(false);
            }
            if mgr
                .translate_addr(VirtAddr::new(EXEC_STUB_VA - 0x1000))
                .is_none()
            {
                return Err(SyscallError::EBUSY);
            }
            mgr.map_page(page, frame, flags, &mut NoTableFrames)
                .map(|()| true)
                .map_err(|_| SyscallError::EBUSY)
        })
    };
    if mapped != Ok(true) {
        mm::memory::FrameAllocator::new().deallocate_frame(frame);
    }
    mapped.map(|_| ())
}

/// How `exec_from_bytes` was entered.
pub(super) enum ExecEntry {
    /// `execve`/`spawn_image` by the calling task, with the front-end's staging
    /// admission (held until the exec returns, or handed to the leader).
    Caller(mm::TransientPeakGuard),
    /// The group leader running an exec a non-leader handed it.
    Handoff,
}

/// GAP-5 exec step 2, the exec'ing non-leader T (design: "Non-leader exec
/// design"). Claims the drain, maps the trampoline, hands the image, its
/// staging admission and T's own state to the leader, ends the other members
/// and waits until the leader has taken the handoff. Past the point of no
/// return it posts its own exit and returns `EINTR`, so the syscall return
/// path ends it after every caller has unwound; `EBUSY` if the leader died
/// before taking the handoff.
pub(super) fn begin_exec_handoff(
    process: &crate::process::ProcessArc,
    pid: ProcessId,
    elf_data: Vec<u8>,
    argv_vec: Vec<Vec<u8>>,
    envp_vec: Vec<Vec<u8>>,
    execfn: Vec<u8>,
    peak: mm::TransientPeakGuard,
) -> SyscallResult {
    use crate::process::{
        address_space_foreign_sharers, discard_exec_handoff, poll_exec_handoff,
        publish_exec_handoff, ExecHandoff, HandoffPoll, HandoffRefusal, HandoffThreadState,
    };
    use crate::signal::{signal_exit_code, Signal};

    let (tgid, memory_space, group) = {
        let proc = process.lock();
        (proc.tgid, proc.memory_space, Arc::clone(&proc.thread_group))
    };
    wait_for_posted_group_exit(&group, pid)?;
    let claim = claim_exec_drain(&group, pid)?;
    if address_space_foreign_sharers(memory_space, &group) > 0 {
        return Err(SyscallError::EBUSY);
    }
    // A zombie or exiting leader cannot take the exec (a deviation: Linux
    // would take over its PID). The publish re-checks under the lock.
    let leader = get_process(tgid).ok_or(SyscallError::EBUSY)?;
    let (leader_files, leader_fs) = {
        let leader = leader.lock();
        if !Arc::ptr_eq(&leader.thread_group, &group)
            || !leader.group_live
            || matches!(
                leader.state,
                ProcessState::Zombie | ProcessState::Terminated
            )
        {
            return Err(SyscallError::EBUSY);
        }
        (Arc::clone(&leader.files), Arc::clone(&leader.fs))
    };
    // Mapped before the point of no return; a stub left in place by a failed
    // attempt is harmless (only this code maps that page) and is reused.
    ensure_exec_stub()?;
    let thread = {
        let mut proc = process.lock();
        // GAP-5 G7 (review D3): group signals this task claimed but has not
        // delivered stay with the group (the leader takes them after the
        // exec); only its own thread-directed signals travel in the handoff,
        // so its exit cannot return them a second time.
        let _ = proc.return_claimed_signals(u64::MAX);
        let seccomp_state = proc
            .seccomp_state
            .try_clone()
            .map_err(|_| SyscallError::ENOMEM)?;
        let files = (!Arc::ptr_eq(&proc.files, &leader_files)).then(|| {
            // The handoff's own owner count (see HandoffThreadState::files).
            proc.files.lock().add_owner();
            Arc::clone(&proc.files)
        });
        HandoffThreadState {
            blocked: proc.blocked,
            pending: proc.pending_signals.bits(),
            rlimits: proc.rlimits,
            allowed_cpus: proc.allowed_cpus,
            seccomp_state,
            seccomp_generation: proc.seccomp_generation,
            pledge_state: proc.pledge_state.clone(),
            pid_ns_for_children: proc.pid_ns_for_children.clone(),
            files,
            fs: (!Arc::ptr_eq(&proc.fs, &leader_fs)).then(|| Arc::clone(&proc.fs)),
        }
    };
    drop(leader_files);
    drop(leader_fs);
    let owned_files = thread.files.clone();
    let handoff = match ExecHandoff::try_new(
        elf_data,
        argv_vec,
        envp_vec,
        execfn,
        thread,
        Some(peak),
        EXEC_STUB_VA,
    ) {
        Ok(handoff) => handoff,
        Err(_) => {
            // The owner count taken above goes back with the table handle.
            if let Some(files) = owned_files {
                crate::process::give_back_files_owner(process, &files);
            }
            return Err(SyscallError::ENOMEM);
        }
    };
    drop(owned_files);

    // Point of no return: the leader holds the handoff and every other member
    // has a posted fatal exit.
    let leader = match publish_exec_handoff(
        pid,
        tgid,
        &group,
        handoff,
        signal_exit_code(Signal::SIGKILL),
    ) {
        Ok(leader) => leader,
        Err((handoff, refusal)) => {
            discard_exec_handoff(process, handoff);
            drop(claim);
            if refusal == HandoffRefusal::GroupExiting {
                wait_for_posted_group_exit(&group, pid)?;
            }
            return Err(SyscallError::EBUSY);
        }
    };
    // Wait until the leader has taken the handoff, or this task is killed.
    loop {
        match poll_exec_handoff(&leader) {
            HandoffPoll::Taken => break,
            HandoffPoll::Abandoned(handoff) => {
                // The leader exited first. The other members stay ended.
                if let Some(handoff) = handoff {
                    discard_exec_handoff(process, handoff);
                }
                drop(claim);
                return Err(SyscallError::EBUSY);
            }
            HandoffPoll::Pending => {}
        }
        if wait_should_abort(pid) {
            break;
        }
        yield_and_halt();
    }
    // The leader's exec owns the claim now; its guard releases it.
    claim.hand_over();
    // Exit through the syscall return safe point rather than from here, so the
    // callers' frames unwind first (this task's PCB handle and anything else a
    // front-end holds). A fatal exit posted meanwhile keeps its own code.
    let _ = crate::process::request_process_exit_if_unposted(process, 0);
    Err(SyscallError::EINTR)
}

/// GAP-5 exec step 2, the leader: run the exec a non-leader handed over, on
/// this syscall's frame (bound at entry), under the exec'ing thread's staging
/// admission. It is audited as an `execve`. A failure after the point of no
/// return ends the group: a posted fatal exit wins with its own code,
/// otherwise `SIGSEGV`, as Linux `force_fatal_sig` does past `de_thread`.
pub(super) fn run_exec_handoff() -> SyscallResult {
    use crate::signal::{signal_exit_code, Signal};

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
    // Only this task takes its handoff, and the publisher reclaims it only
    // from a dead leader, so the gate's report still holds. Stay defensive:
    // without it the skipped call simply reports EINTR.
    let Some(taken) = crate::process::take_exec_handoff(&process) else {
        return Err(SyscallError::EINTR);
    };
    let peak = taken.peak;
    let result = exec_from_bytes(
        process,
        taken.elf_data,
        taken.argv,
        taken.envp,
        taken.execfn,
        ExecEntry::Handoff,
    );
    drop(peak);
    let (outcome, errno) = match &result {
        Ok(_) => (AuditOutcome::Success, 0),
        Err(e) => (AuditOutcome::Error, e.as_i64() as i32),
    };
    let _ = audit::emit(
        AuditKind::Syscall,
        outcome,
        get_audit_subject(),
        AuditObject::None,
        &[59, 0, 0, 0, 0, 0, 0],
        errno,
        crate::time::get_ticks(),
    );
    if let Some(exit_code) = crate::process::take_pending_process_exit(pid) {
        terminate_self_and_halt(pid, exit_code);
    }
    if result.is_err() {
        crate::process::terminate_group_self_and_halt(pid, signal_exit_code(Signal::SIGSEGV));
    }
    result
}

/// One step of a killable kernel-side wait: yield, then halt until the next
/// interrupt (the `nanosleep` pattern).
pub(super) fn yield_and_halt() {
    yield_with_deferred_work();
    if x86_64::instructions::interrupts::are_enabled() {
        x86_64::instructions::hlt();
    } else {
        core::hint::spin_loop();
    }
}

/// sys_exec - 执行新程序
///
/// 将当前进程的地址空间替换为新的 ELF 可执行映像
///
/// # Arguments
///
/// * `image` - 指向用户态 ELF 映像的指针
/// * `image_len` - ELF 映像长度（字节数）
/// * `argv` - 命令行参数数组（NULL 结尾）
/// * `envp` - 环境变量数组（NULL 结尾）
///
/// # Safety
///
/// 用户指针在切换 CR3 前必须先复制到内核堆，否则地址失效
/// exec_from_bytes — the shared address-space-replacement core for `execve`(59)
/// and `sys_spawn_image`(517) (M0-4 exec disambiguation).
///
/// Receives the FINAL ELF image bytes + kernel-owned argv/envp + the AT_EXECFN
/// bytes; the two front-ends differ only in how they obtain those (a VFS path
/// read + shebang resolution for execve; a raw user-image copy for spawn_image).
/// The front-half user-pointer copy is therefore NOT performed here.
///
/// CONTRACT (current-task-only): this REPLACES THE CURRENT TASK's address space —
/// it switches the running CPU's CR3 (`activate_memory_space`) and reads the
/// current LSM context (`lsm_current_process_ctx`). `process` MUST be the `Arc`
/// of the running task; a non-current process would corrupt the live CR3.
///
/// R172-X-F5: the two front-ends differ in OBJECT-NESS — execve(59) has a FILE (so the
/// file-object DAC/MAC live in `read_file_for_exec`, manager.rs), spawn_image(517) has NONE
/// (anonymous caller-owned bytes). The `hook_task_exec(bin_hash)` call below is the SINGLE
/// shared content-keyed exec-deny seam covering BOTH paths. A future W^X-anonymous-exec /
/// no-anon-exec LSM policy MUST key off that existing content hook (it already receives the
/// anon bytes' hash) — never fabricate a file-object check on the spawn_image path, and
/// never add a divergent second exec-deny seam. If a dedicated discriminator is ever
/// required, the correct shape is an EXPLICIT default-ALLOW anon-exec policy seam, NOT a
/// fail-open VFS file-gate.
pub(super) fn exec_from_bytes(
    process: crate::process::ProcessArc,
    elf_data: Vec<u8>,
    argv_vec: Vec<Vec<u8>>,
    envp_vec: Vec<Vec<u8>>,
    execfn: Vec<u8>,
    entry: ExecEntry,
) -> SyscallResult {
    use crate::elf_loader::load_elf;
    use crate::fork::create_fresh_address_space;
    use crate::process::{
        activate_memory_space, address_space_share_count, current_pid, free_address_space,
        thread_group_size, ProcessState,
    };

    // M0-4 (Codex Fix A): enforce the current-task-only contract. The body below
    // switches the running CPU's CR3 and uses lsm_current_process_ctx(); a caller
    // passing a non-running process would corrupt the live address space.
    let process_pid = process.lock().pid;
    let is_current = current_pid() == Some(process_pid);
    debug_assert!(is_current, "exec_from_bytes must run on the current task");
    if !is_current {
        // R188-U01-2 FIX: this core switches the live CR3 and therefore cannot
        // safely operate on an arbitrary PCB supplied by a future caller.
        return Err(SyscallError::ESRCH);
    }

    // The live return frame is on this task's kernel stack, which survives exec
    // and migration. Reject missing ownership before replacing any user state.
    if with_current_syscall_frame_mut(process_pid, |_, _| ()).is_none() {
        return Err(SyscallError::EINVAL);
    }

    // R41-4 FIX: LSM hook uses SHA-256 of ELF content instead of argv[0]
    //
    // SECURITY: Previously used argv[0] (user-controlled) for policy checks,
    // allowing attackers to bypass MAC by setting argv[0] to an allowed program.
    // Now we hash the actual binary content to ensure policy is checked against
    // what will actually be executed.
    //
    // GAP-5 leader exec: this and the two checks below run before the thread
    // group drain, so an LSM denial, a name allocation failure or a header
    // pre-flight failure ends no sibling. Segment checks (range, filesz/memsz,
    // stack overlap) run in load_elf, after the drain.
    let bin_hash = audit::hash_binary_prefix(&elf_data, EXEC_HASH_WINDOW);

    // GAP-5 exec step 2 (review F4): a handed-over exec was already checked
    // by the exec'ing thread for this image and the group's shared
    // credentials; the hook runs once per exec, as on Linux.
    let via_handoff = matches!(entry, ExecEntry::Handoff);
    if !via_handoff {
        // R192-5 / TD-LSM-1 FIX: a missing subject fails closed, never skips.
        let exec_ctx = lsm_current_process_ctx().ok_or(SyscallError::EPERM)?;
        if let Err(err) = lsm::hook_task_exec(&exec_ctx, bin_hash) {
            return Err(lsm_error_to_syscall(err));
        }
    }

    // M0-4 (gap g1, Codex Fix): build the comm-style process name HERE — BEFORE
    // the point of no return — so its fallible allocation can fail cleanly
    // (ENOMEM) rather than panic in the post-CR3 "no fallible ops" commit window.
    // It is moved (no allocation) into proc.name during the commit.
    let comm_name = crate::process::PreparedProcessName::try_new(exec_comm_name(&execfn))
        .map_err(|_| SyscallError::ENOMEM)?;

    // The loader's pure header and program-header pre-flight (load_elf repeats it).
    crate::elf_loader::validate_elf_image(&elf_data).map_err(|_| SyscallError::ENOEXEC)?;

    // GAP-5 exec step 2: a non-leader hands the exec to its group leader, which
    // runs it under the group's PID (`ExecEntry::Handoff`).
    let _peak = match entry {
        ExecEntry::Caller(peak) if process.lock().tgid != process_pid => {
            drop(comm_name);
            return begin_exec_handoff(
                &process,
                process_pid,
                elf_data,
                argv_vec,
                envp_vec,
                execfn,
                peak,
            );
        }
        ExecEntry::Caller(peak) => Some(peak),
        ExecEntry::Handoff => None,
    };

    // GAP-5 slice 4 (exec step 1): a group leader ends every other member first,
    // as Linux de_thread does. The guard keeps the group closed to new threads
    // until this function returns; it drops after the exec guards below.
    let _exec_drain = drain_thread_group_for_exec(&process, process_pid, via_handoff)?;

    // R33-1 FIX: Refuse exec while other threads share this address space.
    // Calling exec in a multithreaded process would free the page tables while
    // sibling threads are still executing, causing UAF/memory corruption.
    // The drain above already ended a leader's siblings; these gates refuse a
    // non-drained share (a non-leader's group or a racing CLONE_VM child).
    let (tgid, current_memory_space, files_owners) = {
        let proc = process.lock();
        let files_owners = proc.files.lock().owners();
        (proc.tgid, proc.memory_space, files_owners)
    };
    // GAP-5 slice 3: exec drains close-on-exec descriptors from the fd table;
    // a table another task still holds must not change under it. Linux would
    // unshare it; until that copy exists, refuse like the thread case below.
    if files_owners > 1 {
        return Err(SyscallError::EBUSY);
    }
    let thread_count = thread_group_size(tgid);
    if thread_count > 1 {
        kprintln!(
            "exec_from_bytes: refusing exec in multithreaded process (tgid={}, threads={})",
            tgid,
            thread_count
        );
        return Err(SyscallError::EBUSY);
    }

    // R118-1 FIX: Refuse exec when other tasks share this address space (CLONE_VM).
    //
    // thread_group_size(tgid) only counts CLONE_THREAD siblings (same tgid).
    // A process created via CLONE_VM without CLONE_THREAD has a different tgid
    // but shares the same memory_space.  If exec freed the old page tables,
    // that CLONE_VM sibling would still reference the freed CR3 → UAF.
    //
    // R136-1 FIX: address_space_share_count() now counts ALL non-Terminated
    // processes (including Zombies) that share the same memory_space. A Zombie
    // retains its memory_space reference until reaped by cleanup_zombie(), so
    // it must be counted to prevent double-free of CR3 page tables.
    //
    // P1-D FIX: arm `exec_in_progress` in the SAME Process-lock critical section
    // as the share_count recheck (count under PROCESS_TABLE, then re-lock Process
    // and re-validate). A concurrent sys_clone(CLONE_VM) either:
    //   - publishes child.memory_space first → share_count > 1 → EBUSY here, or
    //   - sees exec_in_progress after this arm → EBUSY on the clone recheck.
    // The previous ordering (share_count, then long unlocked work, then arm)
    // left a window where clone could attach mid-exec and observe a rewritten
    // MmState / freed CR3.
    let share_count = address_space_share_count(current_memory_space);
    if share_count > 1 {
        kprintln!(
            "exec_from_bytes: refusing exec with {} CLONE_VM sibling(s) sharing address space (cr3=0x{:x})",
            share_count - 1,
            current_memory_space
        );
        return Err(SyscallError::EBUSY);
    }

    // M0-4: `elf_data` / `argv_vec` / `envp_vec` arrive as parameters. The
    // front-half user-pointer validation + copy now lives in the per-syscall
    // front-ends (sys_spawn_image copies a raw user image; sys_execve reads the
    // file via VFS + resolves `#!` shebangs), so the confused-deputy where
    // arg0 could be EITHER a path or an image is gone — arg0's type is fixed per
    // syscall number.

    // H.3 KPTI: User PML4 creation is deferred until AFTER load_elf() and stack
    // setup populate user-space page table entries. create_kpti_user_pml4() snapshots
    // PML4[0..255], so it must run after all user mappings (code, data, BSS, stack
    // at PML4[255]) are established. See the "Phase 4: KPTI" block below.

    // 保存旧地址空间以便失败时恢复或成功时释放
    // R149-3 FIX: Capture cgroup_id under process lock once. This single
    // snapshot is used for both load_elf() charging and ExecSpaceGuard
    // rollback, eliminating the TOCTOU where concurrent cgroup migration
    // could cause the guard to uncharge a different cgroup than was charged.
    // R171 M2-1 SLICE-1 FIX: a RAII guard that clears `exec_in_progress` on EVERY
    // exit from sys_exec after the snapshot below (success commit OR any rollback).
    // Declared BEFORE `ExecSpaceGuard` so it drops AFTER the guard's rollback
    // uncharge — i.e. migration stays blocked through the entire exec window
    // including the rollback path. Clears under the Process lock (the only mutator).
    struct ExecInProgressGuard {
        process: crate::process::ProcessArc,
    }
    impl Drop for ExecInProgressGuard {
        fn drop(&mut self) {
            self.process.lock().exec_in_progress = false;
        }
    }

    // P1-D: arm exec_in_progress FIRST under the Process lock, then re-validate
    // sole ownership. Order matters:
    //   1. Arm under Process lock → concurrent CLONE_VM recheck sees the flag
    //      and EBUSYs (cannot publish child.memory_space against this AS).
    //   2. Drop Process, call address_space_share_count (needs PROCESS_TABLE;
    //      Level-5 ordering forbids holding Process across that scan).
    //   3. If a sibling already published before the arm, share_count > 1 →
    //      EBUSY (guard Drop clears the flag).
    //   4. Re-lock and confirm memory_space is still the counted one.
    //   5. ONLY THEN allocate the new address space (no free-on-EBUSY path).
    // The previous ordering (unlocked share_count → long work → arm) left a
    // window where clone could attach mid-exec and observe a rewritten MmState
    // or a freed CR3.
    let (old_memory_space, old_user_memory_space, exec_cgroup_id) = {
        let mut proc = process.lock();
        let ms = proc.memory_space;
        let ums = proc.user_memory_space;
        let cg = proc.cgroup_id;
        if ms == 0 {
            return Err(SyscallError::ENOMEM);
        }
        // R171 M2-1 SLICE-1 FIX: arm the migration block under the Process lock,
        // BEFORE the lock is dropped for load_elf's lock-dropped charge window.
        // P1-D: this arm is also the mutual-exclusion edge against concurrent
        // sys_clone(CLONE_VM) attach (clone rechecks exec_in_progress).
        proc.exec_in_progress = true;
        proc.mm.lock().exec_pending_bytes = 0; // Clear any stale value
        (ms, ums, cg)
    };
    // Armed: from here every sys_exec exit clears the flag.
    let _exec_progress_guard = ExecInProgressGuard {
        process: process.clone(),
    };

    // Re-check sole ownership after arming. Any CLONE_VM that published before
    // the arm is visible to the count; any that races after the arm fails its
    // recheck on exec_in_progress.
    if address_space_share_count(old_memory_space) > 1 {
        kprintln!(
            "exec_from_bytes: refusing exec — CLONE_VM sibling appeared before arm (cr3=0x{:x})",
            old_memory_space
        );
        return Err(SyscallError::EBUSY);
    }
    // Defensive: memory_space must not have changed under us (exec is single-
    // threaded per task, but keep the R156-1 style re-verify).
    {
        let proc = process.lock();
        if proc.memory_space != old_memory_space {
            return Err(SyscallError::EAGAIN);
        }
    }

    // 创建新的地址空间 — only after the P1-D arm+recheck so a mid-window
    // EBUSY cannot leak a freshly allocated PML4.
    let (_new_pml4_frame, new_memory_space) =
        create_fresh_address_space().map_err(|_| SyscallError::ENOMEM)?;

    // S-7 fix: RAII guard to rollback address space on error
    //
    // After switching CR3, any error must restore the old address space
    // and free the new one. This guard ensures automatic rollback.
    // R118-I1 FIX: ExecSpaceGuard now tracks new_user_space so that KPTI user
    // PML4 frames are freed on rollback (previously leaked on exec failure).
    struct ExecSpaceGuard {
        /// R149-3 FIX: Process handle for clearing exec_pending_bytes and
        /// re-reading cgroup_id on rollback (migration may have moved the
        /// charge to a different cgroup).
        process: crate::process::ProcessArc,
        old_space: usize,
        old_user_space: usize,
        new_space: usize,
        new_user_space: usize,
        /// R125-1 FIX: Cgroup to uncharge on rollback (may be overridden by
        /// re-read in Drop if migration occurred).
        cgroup_id: cgroup::CgroupId,
        /// R125-1 FIX: Total bytes charged by load_elf() (segments + stack).
        charged_bytes: u64,
        committed: bool,
    }

    impl ExecSpaceGuard {
        fn new(
            process: crate::process::ProcessArc,
            old_space: usize,
            old_user_space: usize,
            new_space: usize,
        ) -> Self {
            Self {
                process,
                old_space,
                old_user_space,
                new_space,
                new_user_space: 0,
                cgroup_id: 0,
                charged_bytes: 0,
                committed: false,
            }
        }

        /// R118-I1 FIX: Track KPTI user PML4 for rollback cleanup.
        fn set_new_user_space(&mut self, user_space: usize) {
            self.new_user_space = user_space;
        }

        /// R125-1 FIX: Record cgroup charges made by load_elf() so that
        /// drop() can uncharge them if exec fails after load_elf() succeeds.
        fn set_cgroup_charge(&mut self, cgroup_id: cgroup::CgroupId, charged_bytes: u64) {
            self.cgroup_id = cgroup_id;
            self.charged_bytes = charged_bytes;
        }

        /// Mark the exec as successful, preventing rollback on drop
        fn commit(&mut self) {
            self.committed = true;
        }
    }

    impl Drop for ExecSpaceGuard {
        fn drop(&mut self) {
            if !self.committed {
                // R149-3 FIX: Clear exec_pending_bytes and re-read cgroup_id
                // under lock. If cgroup migration occurred after load_elf()
                // charged exec_cgroup_id, the charge was transferred by the
                // Process-locked cgroup migration transaction. We must uncharge
                // the current (post-migration) cgroup_id, not the stale one.
                if self.charged_bytes > 0 {
                    let rollback_cgroup_id = {
                        let proc = self.process.lock();
                        proc.mm.lock().exec_pending_bytes = 0;
                        proc.cgroup_id
                    };
                    // Use fresh cgroup_id from process (post-migration safe).
                    self.cgroup_id = rollback_cgroup_id;
                }

                // Rollback: restore old address space and free new one
                crate::process::activate_memory_space(self.old_space, Some(self.old_user_space));
                // R118-I1 FIX: Free KPTI user PML4 before kernel PML4
                // (user PML4 contains shared sub-table pointers)
                if self.new_user_space != 0 {
                    crate::fork::free_kpti_user_pml4(self.new_user_space);
                }
                crate::process::free_address_space(self.new_space);
                // R125-1 FIX: Uncharge cgroup memory that load_elf() charged
                if self.charged_bytes > 0 {
                    cgroup::uncharge_memory(self.cgroup_id, self.charged_bytes);
                }
            }
        }
    }

    // Create the guard before switching CR3
    let mut space_guard = ExecSpaceGuard::new(
        process.clone(),
        old_memory_space,
        old_user_memory_space,
        new_memory_space,
    );

    // 切换到新地址空间 (KPTI user PML4 not yet created — pass 0)
    activate_memory_space(new_memory_space, Some(0));

    // 加载 ELF 映像
    // S-7 fix: Let the guard handle rollback on error
    // R149-3 FIX: Pass exec_cgroup_id captured under lock, not re-read.
    let load_result = load_elf(&elf_data, exec_cgroup_id).map_err(|e| {
        klog!(Error, "exec_from_bytes: ELF load failed: {:?}", e);
        SyscallError::ENOEXEC
    })?;
    // R180-10: load_elf has consumed every byte it needs. Release the image
    // allocation before building argv/envp/auxv staging so the admitted peak is
    // a conservative bound rather than an unnecessarily simultaneous footprint.
    drop(elf_data);

    // R125-1 FIX: Record cgroup charges from load_elf() in the guard.  If
    // any subsequent step (copy_to_user, KPTI PML4 creation, etc.) fails,
    // ExecSpaceGuard::drop() will uncharge these bytes, preventing permanent
    // inflation of cgroup memory_current on exec rollback.
    // R149-3 FIX: Use the same exec_cgroup_id for guard (not re-read).
    // Also set exec_pending_bytes so compute_cgroup_charged_bytes() includes
    // these in-flight charges during any concurrent migration.
    {
        let proc = process.lock();
        proc.mm.lock().exec_pending_bytes = load_result.charged_bytes;
    }
    space_guard.set_cgroup_charge(exec_cgroup_id, load_result.charged_bytes);

    // =========================================================================
    // M0 #1 (auxv + SysV entry stack): build the System V AMD64 initial user
    // stack — argc/argv/envp + a full auxiliary vector (auxv) — and copy it into
    // the freshly-mapped, already-charged user stack. This replaces the old
    // hand-rolled argv/envp-only layout (which also had the inverted RSP%16==8
    // alignment bug) with the shared `crate::user_stack::build_initial_user_stack`
    // builder, used identically by the boot Ring-3 diagnostic (usermode_test).
    //
    // PRECONDITION: we are on the NEW process CR3 (activate_memory_space above)
    // and hold NO Process / page-table / COW lock here — the builder does
    // copy_to_user (faultable) + security::fill_random (RNG lock); a fault while
    // holding the Process lock would invert the lock order against the page-fault
    // handler. The credential snapshot below takes a SCOPED lock that DROPS before
    // the builder call.
    // =========================================================================

    // Snapshot credentials for the identity auxv entries (AT_UID/EUID/GID/EGID/
    // SECURE) under a scoped lock released before the builder runs.
    let stack_creds = {
        let proc = process.lock();
        let creds = proc.try_credentials_read().ok_or(SyscallError::EAGAIN)?;
        crate::user_stack::StackCreds {
            uid: creds.uid,
            euid: creds.euid,
            gid: creds.gid,
            egid: creds.egid,
            // AT_SECURE reflects an exec-time privilege delta. No setuid/setgid-exec
            // path is wired yet, so this is 0 in practice; (euid!=uid)||(egid!=gid)
            // is the forward-compatible, over-conservative (=SAFE) seam.
            at_secure: (creds.euid != creds.uid) || (creds.egid != creds.gid),
        }
    };

    // M0-4: AT_EXECFN is the caller-supplied `execfn` (the ORIGINAL execve
    // pathname, or argv[0]/"/exec" for a raw-image spawn) — threaded UNCHANGED
    // into the builder, which treats it as an opaque, NUL-free byte sink. The
    // builder contract is unchanged (shared with the boot Ring-3 / musl gate).
    let execfn_ref: &[u8] = &execfn;

    let stack_layout = crate::user_stack::build_initial_user_stack(
        &load_result,
        &argv_vec,
        &envp_vec,
        &stack_creds,
        execfn_ref,
    )?;

    // ── Phase 4: KPTI user PML4 creation ──
    //
    // Now that load_elf() and stack setup have populated all user-space page table
    // entries (code/data at PML4[0], stack at PML4[255], etc.), snapshot the kernel
    // PML4's user half into the KPTI user PML4. create_kpti_user_pml4() copies
    // PML4[0..255] by value; entries created after the dual activation reach the
    // user root through `mm::page_table`'s mirror (LEAD-KPTI-PML4-1), and nothing
    // maps between this snapshot and that activation.
    let new_user_memory_space = if security::is_kpti_enabled() {
        let (_user_frame, user_phys) = crate::fork::create_kpti_user_pml4(new_memory_space)
            .map_err(|_| SyscallError::ENOMEM)?;
        user_phys
    } else {
        0
    };
    // R118-I1 FIX: Register user PML4 with guard so rollback frees it.
    space_guard.set_new_user_space(new_user_memory_space);

    // Entry RSP points at argc (lowest address of the on-stack control block),
    // 16-byte aligned (SysV AMD64: RSP%16==0 at _start). Delivered by the builder.
    let final_rsp = stack_layout.rsp;

    // 更新进程 PCB
    let (
        old_space,
        old_user_space,
        cloexec_removed,
        cloexec_cgroup_id,
        cloexec_closed,
        old_shared_regions,
        exec_tgid,
    ) = {
        let mut proc = process.lock();

        // R169-4 FIX: Reserve the close-on-exec drop buffer to the CURRENT
        // cloexec-fd count BEFORE any irreversible exec mutation (capability
        // revocation at cap_table.apply_cloexec(), fd close). On allocation
        // failure we return ENOMEM here — nothing has been mutated yet, so the
        // exec rolls back cleanly via space_guard. The fd table is private
        // (a future shared table is unshared before this; GAP-5 slice 3) and nothing in this lock
        // hold adds cloexec marks, so this capacity is EXACTLY sufficient for
        // take_cloexec_fds_into() below: every push fits without realloc,
        // guaranteeing no FileDescriptor ever drops inline under the Process
        // lock (the R169-4 lock-inversion class) — with no fatal-OOM residual.
        let mut cloexec_removed: Vec<crate::process::FileDescriptor> = Vec::new();
        if cloexec_removed
            .try_reserve(proc.files.lock().cloexec_fds.len())
            .is_err()
        {
            return Err(SyscallError::ENOMEM);
        }

        let old_space = proc.memory_space;
        let old_user_space = proc.user_memory_space;
        let old_shared_regions;

        proc.memory_space = new_memory_space;
        // H.3 KPTI: Set user PML4 root (0 if KPTI disabled)
        proc.user_memory_space = new_user_memory_space;
        // M0 #1: store the actual entry stack pointer (matches the CLONE-with-stack
        // convention at sys_clone, and what procfs reports), not the loader's top.
        proc.user_stack = Some(VirtAddr::new(final_rsp));

        // 设置上下文
        proc.context.rip = load_result.entry;
        proc.context.rsp = final_rsp;
        proc.context.rbp = final_rsp;

        // R133-6 FIX: Correct user CS/SS selectors (Ring 3)
        // USER_CS = 0x23, USER_SS = 0x1B (previously swapped)
        proc.context.cs = 0x23;
        proc.context.ss = 0x1B;
        proc.context.rflags = 0x202;

        // M0 #1: argc/argv/envp/auxv are delivered ON THE STACK at RSP (SysV AMD64),
        // not in registers. Drop the legacy RDI=argc / RSI=argv handoff — a real libc
        // crt1 (musl/glibc) reads argc from [RSP] and ignores these. The native
        // userspace `_start()` takes no args, so it is unaffected.
        proc.context.rdi = 0;
        proc.context.rsi = 0;

        // 清零其他寄存器
        proc.context.rax = 0;
        proc.context.rbx = 0;
        proc.context.rcx = 0;
        proc.context.rdx = 0;
        proc.context.r8 = 0;
        proc.context.r9 = 0;
        proc.context.r10 = 0;
        proc.context.r11 = 0;
        proc.context.r12 = 0;
        proc.context.r13 = 0;
        proc.context.r14 = 0;
        proc.context.r15 = 0;

        // R124-1 FIX: Uncharge the old image's cgroup memory before clearing
        // mmap_regions. exec() replaces the entire userspace image; the old
        // regions' cgroup charges must be released or memory_current leaks
        // monotonically across every execve(), eventually blocking all
        // allocations in the cgroup (container DoS).
        //
        // Skip PROT_NONE reservations: never allocated frames or charged
        // memory (R123-1 invariant INV-MM-PROT-NONE).
        //
        // D3-ARC-MM-SHARED: Lock MmState once for all mm field accesses in
        // this block. The mm lock is held inside the proc lock scope.
        {
            let cgroup_id = proc.cgroup_id;
            let mut mm = proc.mm.lock();
            for (&_base, &len_with_flags) in mm.mmap_regions.iter() {
                if len_with_flags.is_prot_none() || len_with_flags.is_shared() {
                    continue;
                }
                let len = mmap_region_len(len_with_flags) as u64;
                if len > 0 {
                    cgroup::uncharge_memory(cgroup_id, len);
                }
            }

            // R127-3 FIX: Uncharge brk heap from the old image before resetting
            // brk_start/brk. Without this, the old image's heap charges remain
            // permanently in the cgroup, leaking memory_current across every exec.
            let heap_bytes =
                page_align_up(mm.brk).saturating_sub(page_align_up(mm.brk_start)) as u64;
            if heap_bytes > 0 {
                cgroup::uncharge_memory(cgroup_id, heap_bytes);
            }

            // R137-1 FIX: Uncharge the old image's ELF loader charges (PT_LOAD
            // segments + user stack). These bytes were charged by load_elf() and
            // are not represented in mmap_regions or brk bookkeeping.
            let elf_bytes = mm.elf_charged_bytes;
            if elf_bytes > 0 {
                cgroup::uncharge_memory(cgroup_id, elf_bytes);
            }

            // J2-9 FIX: Uncharge the old image's page-table-frame kmem. exec()
            // replaces the whole address space; free_address_space(old_space)
            // below (~line 4518) SYNCHRONOUSLY frees the old AS's entire
            // page-table hierarchy, so a stale pt_charged_bytes would leak
            // memory_current monotonically across every execve() (container DoS)
            // AND propagate phantom bytes cross-cgroup on a later migration. exec
            // already rejected shared/CLONE_VM address spaces, so this runs
            // ungated (the last and only holder).
            let pt_bytes = mm.pt_charged_bytes;
            if pt_bytes > 0 {
                cgroup::uncharge_memory(cgroup_id, pt_bytes);
            }
            mm.pt_charged_bytes = 0;
            // R171-CG1x0 FIX (M2-1 SLICE-0): the wholesale uncharge above drained
            // both lanes (INVARIANT I'); clear the frame-identity ledger and reset
            // the basis so the fresh image starts authoritative with no stale frame
            // keys (a reused physical frame in the new AS cannot collide).
            mm.pt_charged_frames.clear();
            mm.shared_fault_pt_frames.clear();
            mm.pt_inherited_bytes = 0;
            mm.pt_ledger_authoritative = true;
            // M2-1 SLICE-4d: charge + ledger the NEW image's page-table-frame kmem — the
            // intermediate PT/PD/PDPT frames load_elf built for this fresh AS (recorded by
            // RecordingFrameAllocator). SOFT/forced charge: the count is knowable only
            // after load_elf ran (a hard reject would orphan already-built tables uncharged
            // = a worse bypass). Folded HERE, right after the old image's ledger is cleared,
            // onto the now-fresh authoritative ledger, under this same Process+MmState
            // commit (exec_in_progress also blocks migration across the whole exec window).
            // PT is charged ONLY on this success commit; any earlier exec failure tears down
            // the new AS via ExecSpaceGuard with PT never charged. record_pt_charge bumps
            // pt_charged_bytes and preserves INVARIANT I'.
            let new_pt_bytes = (load_result.pt_frames.len() as u64).saturating_mul(0x1000);
            if new_pt_bytes > 0 {
                cgroup::charge_memory_forced(cgroup_id, new_pt_bytes);
                mm.record_pt_charge(&load_result.pt_frames);
            }

            // R131-6 FIX: Reset per-task charge counter — the old image's charges
            // were fully uncharged above; new ELF image starts with a clean slate.
            mm.vm_charged_bytes = 0;
            mm.brk_pending_growth = 0; // R144-1 FIX: Clear pending brk growth on exec
                                       // R165-1 FIX: clear any brk reservation on exec image replacement.
                                       // exec already rejects multithreaded/shared-VM callers, so no sibling
                                       // brk can be in flight here; reset defensively for a clean slate.
            mm.brk_in_progress = false;
            mm.fork_in_progress = false;
            // R172-16: clear the brk-grow VA reservation on exec too (clean slate).
            mm.brk_grow_resv_lo = 0;
            mm.brk_grow_resv_hi = 0;
            // M0-7 item7 SLICE 4: clear any stack-grow reservation / in-flight lane on
            // exec image replacement (exec already rejects multithreaded/shared-VM, so no
            // sibling grow can be in flight; reset defensively). The watermark is set to
            // the fresh image's mapped floor below, after elf_charged_bytes.
            mm.stack_grow_pending_bytes = 0;
            mm.stack_grow_in_progress = false;
            mm.mprotect_pending_bytes = 0; // R147-1 FIX: Clear pending mprotect charges on exec
            mm.mremap_uncharged_reserve_bytes = 0; // LEAD-MREMAP-MIGRATE-1: no mremap survives exec
            mm.exec_pending_bytes = 0; // R149-3 FIX: Charge now reflected in elf_charged_bytes
                                       // R137-1 FIX: Record the new ELF image's cgroup charges (segments + stack)
                                       // so that process exit and subsequent exec can uncharge them. The old
                                       // image's elf_charged_bytes were already uncharged above alongside
                                       // mmap_regions and brk. Safe to set before space_guard.commit() because
                                       // no fallible operations remain between lock release and commit(); if the
                                       // guard were to roll back, it uncharges via its own charged_bytes field.
            mm.elf_charged_bytes = load_result.charged_bytes;
            // M0-7 item7 SLICE 4: the fresh image's eager stack is mapped down to the
            // architectural mapped floor (allocate_user_stack_tracked maps the whole
            // window minus the guard), so the demand-grow watermark starts there. A
            // future SLICE-5 grow lowers it; a fork COPIES it (the grown region is
            // COW-inherited). Charged DATA below this floor goes to elf_charged_bytes.
            mm.stack_floor_committed = crate::elf_loader::user_stack_mapped_floor() as usize;
            old_shared_regions = core::mem::replace(
                &mut mm.shared_regions,
                mm::AdmittedMap::new(mm::HeapClass::CoreProcess),
            );
            // exec replaces the whole userspace image, so every VMA the old
            // image owned must be dropped: the uncharge loop above already
            // released their cgroup bytes. Leaving the entries behind lets a
            // stale region describe an address the new image now uses, which
            // makes sys_brk refuse to grow (overlap check) and makes sys_mmap
            // fail its Phase-1 overlap test with a spurious ENOMEM. It also
            // re-uncharges those same bytes on every later exec. `clear()`
            // drops the entries and returns their admission capacity.
            mm.mmap_regions.clear();
            // H.2 Partial KASLR: Re-randomize mmap base on exec for ASLR
            // ST-K3 FIX: use the shared constant (was a duplicated 0x4000_0000
            // literal — the old 1 GiB window collided with the inherited
            // identity map's huge pages; see process.rs DEFAULT_MMAP_BASE).
            mm.next_mmap_addr = security::randomized_mmap_base(crate::process::DEFAULT_MMAP_BASE);

            // 初始化堆管理（brk）
            // brk_start 和 brk 初始化为 ELF 最高段末尾（页对齐）
            // 这确保 brk(0) 返回正确的初始值，malloc 才能正常工作
            mm.brk_start = load_result.brk_start;
            mm.brk = load_result.brk_start;
        }

        // 重置 TLS 状态（新程序需要重新设置）
        proc.fs_base = 0;
        proc.gs_base = 0;

        // R172-04 W4: exec must reset the SYSRET-epilogue staged pair AND the LIVE MSRs to
        // 0 as well — not just the PCB. The dispatcher tail runs reschedule_if_needed, so:
        // (a) on the no-switch return, the epilogue would otherwise commit the STALE
        // switch-in pending pair (the pre-exec FS/GS); and (b) on a pre-SYSRET switch, the
        // unconditional switch-out save would read the STALE live MSRs back into the PCB,
        // resurrecting the pre-exec TLS. Writing all three (PCB above + pending + live MSR)
        // closes both. Runs in the exec'ing task's own syscall context (its own CPU).
        if !stage_pending_tls_bases(0, 0) {
            unsafe {
                use x86_64::registers::model_specific::Msr;
                Msr::new(0xC000_0100u32).write(0); // IA32_FS_BASE
                Msr::new(0xC000_0102u32).write(0); // IA32_KERNEL_GS_BASE (user GS via SWAPGS)
            }
        }

        // OpenBSD Pledge 语义：exec 后应用 exec_promises
        // 如果进程设置了 exec_promises，则在 exec 成功后将其替换为当前 promises
        // 这允许进程在 exec 前声明一组更宽松的权限（用于加载程序），
        // exec 后自动收紧到更严格的权限集
        if let Some(ref mut pledge) = proc.pledge_state {
            if let Some(exec_promises) = pledge.exec_promises.take() {
                pledge.promises = exec_promises;
            }
        }
        proc.sync_seccomp_or_pledge_flag();

        // Seccomp 过滤器在 exec 后保持不变（Linux 语义）
        // no_new_privs 仍然有效，防止特权提升
        // R163-12 FIX: Clear stale seccomp_installing flag on exec.
        proc.seccomp_installing = false;

        // 应用 CLOEXEC 能力：撤销带有 CLOEXEC 标志的能力条目
        //
        // 新加载的程序不应继承标记为 CLOEXEC 的能力，这与文件描述符
        // 的 CLOEXEC 语义一致。apply_cloexec() 会将这些条目撤销并
        // 返回到空闲列表，同时递增生成计数器防止旧 CapId 被复用。
        proc.apply_capability_cloexec();

        // R39-4 FIX: 应用 FD_CLOEXEC：关闭带有 close-on-exec 标志的文件描述符
        //
        // POSIX 语义：exec 成功后，所有标记为 O_CLOEXEC/FD_CLOEXEC 的文件描述符
        // 必须被关闭。这防止敏感句柄（如特权设备、安全令牌）泄漏到新程序。
        //
        // 典型攻击场景：
        // 1. 父进程以 root 权限打开 /dev/vda 但忘记设置 CLOEXEC
        // 2. exec 不可信程序后，该程序意外获得块设备访问权限
        //
        // 注意：此操作必须在 commit 之前执行，确保 exec 回滚时 fd 不变
        //
        // R169-4 FIX: Drain the removed CLOEXEC descriptors into the
        // pre-reserved buffer (no inline drop) and capture the closed count +
        // owning cgroup, but DEFER the actual FileDescriptor drops and the L5
        // per-cgroup FD-budget uncharge to OUTSIDE this block (below the `};`).
        let cloexec_cgroup_id = proc.fd_charge_cgroup();
        let cloexec_closed = proc.take_cloexec_fds_into(&mut cloexec_removed);

        proc.enter_ready_at(crate::get_ticks());

        // M0 item 5: POSIX exec signal semantics. Caught signals (a real handler)
        // reset to SIG_DFL; SIG_IGN dispositions are PRESERVED; the blocked mask and
        // the pending set are PRESERVED. The handler scratch state
        // (saved_blocked / in_signal_handler) is cleared — a live handler frame can
        // never survive the address-space replacement. (The monotonic global
        // any-handler hint is intentionally not reset; a stale-true hint only costs a
        // redundant pending scan, never incorrect delivery.)
        // R172-X-F1: EXEC-SIGNAL-SAFEPOINT-CONJUNCTION leg (b) — the SOLE handler-reset path,
        // extracted to `reset_sigactions_for_exec` so its self-test is a TRUE witness of the
        // production reset, and the maybe_deliver_signal `exec_in_progress` tripwire (legs a/c
        // enforcement) can rely on it. See `reset_sigactions_for_exec`.
        // GAP-5: CLONE_SIGHAND implies CLONE_VM, and exec already refused any
        // other task (zombies included) sharing this address space, so no live
        // task shares the disposition table here. After the leader-exec drain
        // a reaped sibling's PCB may still hold the table during its final
        // drop; it never reads it again, so the table is reset in place.
        debug_assert_eq!(proc.thread_group.members(), 1);
        {
            let mut actions = proc.sigactions.lock();
            reset_sigactions_for_exec(&mut actions);
        }
        proc.sigactions.note_mutation();
        proc.saved_blocked = 0;
        // Keep the active task-owned kernel-stack frame. Exec replaces user
        // memory, but SYSRET and return-time signal delivery still consume it.
        proc.in_signal_handler = false;
        // M0-6 poll/select: a live ppoll/pselect6 mask stash cannot survive the
        // address-space replacement (the syscall that set it is being replaced).
        proc.poll_restore_blocked = None;
        // N2.6a: POSIX/Linux execve(2) disables any established alternate signal stack.
        proc.sigaltstack = crate::signal::SigAltStack::disabled();
        // N2.5: Mark process as having executed a new image (POSIX setpgid EACCES rule).
        proc.thread_group.mark_execed();
        let exec_tgid = proc.tgid;
        // Robust-list registration is address-space-local. Clear the old
        // image's pointer before publishing the replacement so exit cleanup
        // cannot dereference stale or newly-reused virtual memory.
        proc.robust_list_head = 0;
        proc.robust_list_len = 0;
        // The set_tid_address word is address-space-local too (Linux clears
        // it in exec_mm_release). Without this, an exit after an exec that did
        // not re-register zeroes and futex-wakes an address in the new image.
        proc.clear_child_tid = 0;

        // M0-4 (gap g1): refresh the process name to the exec'd program's
        // basename (Linux `comm` semantics, <=15 chars). The pre-M0-4 exec path
        // never updated this, so /proc would report the pre-exec name forever.
        // The name was built fallibly BEFORE the point of no return; this is a
        // pure move (no allocation) under this same already-held Process lock.
        proc.commit_prepared_name(comm_name);

        (
            old_space,
            old_user_space,
            cloexec_removed,
            cloexec_cgroup_id,
            cloexec_closed,
            old_shared_regions,
            exec_tgid,
        )
    };

    // N2.6b: POSIX execve(2) deletes POSIX timer_create timers while preserving
    // ITIMER_REAL / alarm. Run outside the Process lock.
    crate::time::cleanup_posix_timers_for_exec(exec_tgid);

    // R169-4 FIX (HIGH, lock inversion): Drop the closed CLOEXEC
    // FileDescriptors and uncharge the per-cgroup FD budget OUTSIDE the Process
    // lock. SocketFile::Drop → socket close → wake_all (re-locks PROCESS_TABLE +
    // a foreign Process::inner) and uncharge_fds → CGROUP_REGISTRY (L5); running
    // either under the Process lock is a lock inversion (R154-3/R155-3) and an
    // L5-under-Process-lock acquire (D1-CGROUP-IRQ-L5).
    if cloexec_closed > 0 {
        crate::cgroup::uncharge_fds(cloexec_cgroup_id, cloexec_closed);
    }
    drop(cloexec_removed);

    // S-7 fix: Commit the exec - prevent guard from rolling back
    // This must be called after all error-prone operations are complete.
    space_guard.commit();

    // R118-6 FIX: Update per-CPU KPTI CR3 pair now that the user PML4 exists.
    //
    // The initial activate_memory_space() ran before Phase 4 and installed a
    // single-root context (user PML4 wasn't created yet).  Now that the user
    // PML4 is committed to the PCB, re-invoke with the correct user_memory_space
    // to install the dual-root KPTI context.  This replaces the previous
    // sync_kpti_cr3() call that scanned PROCESS_TABLE.
    activate_memory_space(new_memory_space, Some(new_user_memory_space));

    // 释放旧地址空间
    // H.3 KPTI: Free old user PML4 before old kernel PML4 (shared sub-tables).
    // R162-4 FIX: Re-verify that no CLONE_VM sibling was created during the
    // lock-free exec window (ELF loading, CR3 switch). If a concurrent
    // sys_clone(CLONE_VM) created a new sibling referencing old_space after
    // the initial share_count check at line ~3848, freeing old_space here
    // would cause UAF of the sibling's page tables.
    if old_space != 0 && address_space_share_count(old_space) == 0 {
        if old_user_space != 0 {
            crate::fork::free_kpti_user_pml4(old_user_space);
        }
        free_address_space(old_space);
    }
    // Shared-region pins and first-toucher charges outlive the old page-table
    // walk and are released only after every leaf has been detached.
    drop(old_shared_regions);

    // GAP-5 futex parity (review F7): the old image's futex buckets go with it.
    let futex_space = Arc::as_ptr(&process.lock().mm) as usize;
    crate::process::notify_futex_exec(futex_space);

    // R101-2 FIX: Gate exec entry/rsp/argc debug print behind debug_assertions.
    // These leak user entry point and stack pointer addresses.
    kprintln!(
        "exec_from_bytes: entry=0x{:x}, rsp=0x{:x}, argc={}",
        load_result.entry,
        final_rsp,
        stack_layout.argc
    );

    // The syscall stub restores this frame, not proc.context. Returning through
    // the old RCX/RSP would resume the previous image on the replacement stack.
    let redirected = with_current_syscall_frame_mut(process_pid, |frame, fx| {
        *frame = SyscallFrame {
            rax: 0,
            rcx: load_result.entry,
            rdx: 0,
            rbx: 0,
            rsp: final_rsp,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0x202,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };
        *fx = default_fxsave_area();
    });
    assert!(
        redirected.is_some(),
        "exec lost its prevalidated return frame"
    );

    // RF178-38 FIX: exec replaces the current task's trust domain without a
    // scheduler context switch, so explicitly flush predictor and RSB state
    // after the new image is committed and the old address space is gone.
    security::spectre::context_switch_barrier(true);

    Ok(0)
}

// ============================================================================
// M0-4: exec front-ends + pure helpers (exec disambiguation)
// ============================================================================

/// M0-4: fallibly clone bytes (no infallible `to_vec`/`clone`, per the kernel's
/// OOM-no-panic policy — the global alloc_error_handler panics).
pub(super) fn try_clone_bytes(src: &[u8]) -> Result<Vec<u8>, SyscallError> {
    let mut v = Vec::new();
    v.try_reserve(src.len()).map_err(|_| SyscallError::ENOMEM)?;
    v.extend_from_slice(src);
    Ok(v)
}

/// M0-4: derive a Linux-`comm`-style process name (basename, <=15 bytes) from
/// the AT_EXECFN bytes. Fully FALLIBLE (try_reserve) and panic-free: any byte that
/// is not printable ASCII is replaced with '?', so the result is always valid
/// UTF-8 with no infallible lossy allocation and no char-boundary hazard.
pub(super) fn exec_comm_name(execfn: &[u8]) -> crate::process::ProcessNameSnapshot {
    let base = match execfn.iter().rposition(|&b| b == b'/') {
        Some(i) => &execfn[i + 1..],
        None => execfn,
    };
    // Linux comm is 16 bytes including the NUL terminator => 15 usable.
    let cap = core::cmp::min(base.len(), 15);
    crate::process::ProcessNameSnapshot::from_sanitized_ascii(&base[..cap])
}

/// M0-4: validate NUL-free bytes (from `copy_user_cstring`) as a UTF-8 path and
/// fallibly copy them into an owned String. Non-UTF-8 => EINVAL; allocation
/// failure => ENOMEM. Never panics.
pub(super) fn utf8_path(b: &[u8]) -> Result<alloc::string::String, SyscallError> {
    let s = core::str::from_utf8(b).map_err(|_| SyscallError::EINVAL)?;
    let mut out = alloc::string::String::new();
    out.try_reserve(s.len()).map_err(|_| SyscallError::ENOMEM)?;
    out.push_str(s);
    Ok(out)
}

/// M0-4: read an entire file by path for exec, via the registered VFS callback.
/// The callback resolves once, enforces +x/DAC/LSM, and bounds the read to
/// MAX_EXEC_IMAGE_SIZE. MUST be called with NO Process/PT/COW lock held.
pub(super) fn exec_read_file(path: &str) -> Result<Vec<u8>, SyscallError> {
    if path.is_empty() {
        return Err(SyscallError::ENOENT);
    }
    if path.len() > MAX_EXEC_PATH_LEN {
        return Err(SyscallError::EINVAL);
    }
    // The callback fn pointer is `Copy`: dereference it and DROP the table lock
    // BEFORE the call, so the faultable, lock-taking callback never runs under
    // the callback-table spinlock.
    let cb = {
        let guard = VFS_READ_FILE_CALLBACK.lock();
        *guard.as_ref().ok_or(SyscallError::ENOSYS)?
    };
    cb(path, MAX_EXEC_IMAGE_SIZE)
}

/// Strip leading spaces/tabs.
pub(super) fn strip_leading_blanks(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    &s[i..]
}

/// Strip trailing spaces/tabs.
pub(super) fn strip_trailing_blanks(s: &[u8]) -> &[u8] {
    let mut j = s.len();
    while j > 0 && (s[j - 1] == b' ' || s[j - 1] == b'\t') {
        j -= 1;
    }
    &s[..j]
}

/// M0-4: parse a `#!` interpreter line (Linux fs/binfmt_script.c semantics).
///
/// Only the first `MAX_SHEBANG_LINE` bytes are scanned. Returns
/// (interpreter, optional single argument): the interpreter is the first
/// blank-delimited token after `#!`; the remainder (blanks stripped on both
/// ends) is ONE argument with internal spaces preserved, or None if empty.
/// ENOEXEC if not `#!`, no newline within the scan window, or empty interpreter.
pub(super) fn parse_shebang_line(bytes: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), SyscallError> {
    let window = &bytes[..core::cmp::min(bytes.len(), MAX_SHEBANG_LINE)];
    if !window.starts_with(b"#!") {
        return Err(SyscallError::ENOEXEC);
    }
    // Require a newline within the scanned window (else the line is too long /
    // truncated — reject rather than guess).
    let nl = window
        .iter()
        .position(|&b| b == b'\n')
        .ok_or(SyscallError::ENOEXEC)?;
    let line = strip_leading_blanks(&window[2..nl]);
    let interp_end = line
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(line.len());
    let interp = &line[..interp_end];
    if interp.is_empty() {
        return Err(SyscallError::ENOEXEC);
    }
    let rest = strip_trailing_blanks(strip_leading_blanks(&line[interp_end..]));
    let optarg = if rest.is_empty() {
        None
    } else {
        let mut v = Vec::new();
        v.try_reserve(rest.len())
            .map_err(|_| SyscallError::ENOMEM)?;
        v.extend_from_slice(rest);
        Some(v)
    };
    let mut iv = Vec::new();
    iv.try_reserve(interp.len())
        .map_err(|_| SyscallError::ENOMEM)?;
    iv.extend_from_slice(interp);
    Ok((iv, optarg))
}

/// M0-4: rebuild argv for one shebang hop:
///   [interp, optarg?, script_path] ++ orig[1..]
/// The original argv[0] is dropped (Linux); an EMPTY `orig` adds no tail.
/// Re-enforces MAX_ARG_COUNT / MAX_ARG_TOTAL / MAX_ARG_STRLEN (Codex Fix B) — this
/// path BYPASSES `copy_user_str_array`'s caps — and rejects any embedded NUL
/// (gap g6: an on-stack NUL would silently truncate an argv entry).
pub(super) fn reconstruct_argv(
    interp: &[u8],
    optarg: Option<&[u8]>,
    script_path: &[u8],
    orig: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, SyscallError> {
    fn push_entry(out: &mut Vec<Vec<u8>>, total: &mut usize, e: &[u8]) -> Result<(), SyscallError> {
        if e.len() > MAX_ARG_STRLEN {
            return Err(SyscallError::E2BIG); // Codex Fix B: per-string cap
        }
        if e.contains(&0) {
            return Err(SyscallError::EINVAL); // gap g6: embedded NUL
        }
        if out.len() + 1 > MAX_ARG_COUNT {
            return Err(SyscallError::E2BIG);
        }
        *total = total.checked_add(e.len() + 1).ok_or(SyscallError::E2BIG)?;
        if *total > MAX_ARG_TOTAL {
            return Err(SyscallError::E2BIG);
        }
        out.try_reserve(1).map_err(|_| SyscallError::ENOMEM)?;
        let mut v = Vec::new();
        v.try_reserve(e.len()).map_err(|_| SyscallError::ENOMEM)?;
        v.extend_from_slice(e);
        out.push(v);
        Ok(())
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;
    push_entry(&mut out, &mut total, interp)?;
    if let Some(a) = optarg {
        push_entry(&mut out, &mut total, a)?;
    }
    push_entry(&mut out, &mut total, script_path)?;
    for e in orig.iter().skip(1) {
        push_entry(&mut out, &mut total, e)?;
    }
    Ok(out)
}

/// sys_spawn_image (syscall 517) — Zero-OS-private native raw in-memory-image
/// spawn (the pre-M0-4 `execve` behavior). For native code that legitimately
/// passes an in-memory ELF image; a real path-based program uses `execve`(59).
/// `arg0` is ALWAYS an image pointer here (never a path) — the confused-deputy
/// is gone because the type is fixed per syscall number.
///
/// R172-X-F5 SECURITY INVARIANT — ANONYMOUS self-exec: 517 copies the CALLER's OWN bytes
/// into the CALLER's OWN address space under the CALLER's OWN creds. There is NO file, no
/// inode, no DAC object, no pathname, and NO privilege boundary crossed. The VFS exec gate
/// `read_file_for_exec` (manager.rs — hook_file_open inode/mode/path-hash MAC + DAC
/// need_exec) does NOT and MUST NOT apply: there is no object to check, and a path lookup on
/// fabricated bytes is meaningless. DO NOT "fix" this asymmetry by routing spawn_image
/// through a VFS file-gate — that would either fail-closed (bricking the musl-check /
/// usermode_test boot path) or require a fabricated fake inode (a worse, fail-open design).
/// The exec coverage that DOES apply here: the content-keyed exec MAC `hook_task_exec`
/// (bin_hash, inside `exec_from_bytes`) + the unbypassable EBUSY multithread / CLONE_VM
/// share-count gates. A future W^X-anonymous-exec / no-anon-exec LSM policy MUST key off
/// that existing content hook, NOT a fabricated file check.
pub(super) fn sys_spawn_image(
    image: *const u8,
    image_len: usize,
    argv: *const *const u8,
    envp: *const *const u8,
) -> SyscallResult {
    use crate::process::{current_pid, get_process};
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Raw-image validation (the verbatim pre-M0-4 sys_exec front-half).
    if image.is_null() || image_len == 0 {
        return Err(SyscallError::EINVAL);
    }
    if image_len > MAX_EXEC_IMAGE_SIZE {
        kprintln!(
            "sys_spawn_image: ELF size {} exceeds limit {}",
            image_len,
            MAX_EXEC_IMAGE_SIZE
        );
        return Err(SyscallError::E2BIG);
    }
    // P2-A: single-holder transient-peak admission — concurrent exec staging
    // must not stack N * EXEC_IMAGE_PEAK_BYTES on top of full hard floors.
    let peak = mm::TransientPeakGuard::try_acquire().map_err(|_| SyscallError::ENOMEM)?;
    // R151-1 FIX: fallible allocation (the global alloc_error_handler panics).
    let mut elf_data: Vec<u8> = Vec::new();
    elf_data
        .try_reserve_exact(image_len)
        .map_err(|_| SyscallError::ENOMEM)?;
    elf_data.resize(image_len, 0);
    copy_from_user(&mut elf_data, image)?;

    let argv_vec = copy_user_str_array(argv)?;
    let envp_vec = copy_user_str_array(envp)?;

    // execfn = argv[0] when present, else "/exec" (no pathname for a raw image).
    // Fallibly cloned (no infallible `cloned()`/`to_vec()`).
    let execfn: Vec<u8> = match argv_vec.get(0) {
        Some(a0) => try_clone_bytes(a0)?,
        None => try_clone_bytes(b"/exec")?,
    };

    // The EBUSY multithread/CLONE_VM gate runs INSIDE exec_from_bytes (first work),
    // so it is unbypassable on every entry path. Peak guard lives until this
    // function returns (staging buffer moved into exec_from_bytes and dropped
    // after load, or on error).
    exec_from_bytes(
        process,
        elf_data,
        argv_vec,
        envp_vec,
        execfn,
        ExecEntry::Caller(peak),
    )
}

/// sys_execve (syscall 59) — real path-based `execve(pathname, argv, envp)`.
///
/// Reads the file via VFS (single-resolution, +x/DAC/LSM-gated), resolves `#!`
/// shebang interpreters ITERATIVELY (depth cap `MAX_SHEBANG_DEPTH`), then
/// replaces the address space EXACTLY ONCE at the resolved ELF leaf. This kills
/// the confused-deputy where the old `execve(59)` treated `arg0` as a raw ELF
/// image instead of a path. AT_EXECFN is the ORIGINAL pathname.
pub(super) fn sys_execve(
    pathname: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1080); // sys_execve entry
    }

    use crate::process::{current_pid, get_process};
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Preserve EFAULT precedence without allocating, then reserve the complete
    // transaction BEFORE pathname, argv, or envp can allocate. The guard spans
    // shebang resolution and the post-load stack/commit work.
    if pathname.is_null() {
        return Err(SyscallError::EFAULT);
    }
    validate_user_ptr(pathname, 1)?;
    let peak = mm::TransientPeakGuard::try_acquire().map_err(|_| SyscallError::ENOMEM)?;

    // FRONT-HALF user copy — runs EXACTLY ONCE; after this, kernel buffers only.
    let path_bytes = copy_user_cstring(pathname)?; // NULL ptr => EFAULT
    let orig_path = utf8_path(&path_bytes)?; // non-UTF-8 => EINVAL
    if orig_path.is_empty() {
        return Err(SyscallError::ENOENT);
    }
    if orig_path.len() > MAX_EXEC_PATH_LEN {
        return Err(SyscallError::EINVAL);
    }
    // Preserve relative bytes: VFS resolves them through the process's owned
    // cwd/root handles, and exec retains those bindings after image replacement.
    let argv_vec = copy_user_str_array(argv)?;
    let envp_vec = copy_user_str_array(envp)?;
    // AT_EXECFN = the ORIGINAL pathname, threaded UNCHANGED through any shebang.
    let execfn: Vec<u8> = path_bytes;

    // Resolve the entire shebang chain to the FINAL ELF bytes BEFORE touching the
    // address space, so a mid-chain error (ENOENT/EACCES/ELOOP/parse) returns to
    // the caller with its image INTACT (Linux semantics). exec_from_bytes — the
    // point of no return — is reached EXACTLY ONCE, at the leaf.
    // R172-P6-F5: resolve the shebang chain via the extracted, boot-testable helper. The
    // point of no return (exec_from_bytes) stays the caller's job here, reached EXACTLY ONCE
    // at the leaf — so the PONR-once-at-leaf discipline is unchanged.
    let (elf_bytes, cur_argv) = resolve_exec_chain(orig_path, argv_vec, exec_read_file)?;

    exec_from_bytes(
        process,
        elf_bytes,
        cur_argv,
        envp_vec,
        execfn,
        ExecEntry::Caller(peak),
    )
}

/// R172-P6-F5: resolve the `#!` shebang interpreter chain to the FINAL image bytes + the
/// rebuilt argv, BEFORE any address-space mutation, so a mid-chain error
/// (ENOENT/EACCES/ELOOP/parse) returns with the caller's image INTACT. Parameterized by a
/// `read` callback so the depth-cap (`MAX_SHEBANG_DEPTH` -> ELOOP) and argv-threading logic —
/// which a green boot cannot exercise — is unit-testable with a mock path->bytes map. The
/// PONR (`exec_from_bytes`) is the SOLE caller's job AFTER this returns, kept out of the loop
/// so the point of no return stays exactly-once-at-the-leaf.
pub(super) fn resolve_exec_chain<F: FnMut(&str) -> Result<Vec<u8>, SyscallError>>(
    orig_path: alloc::string::String,
    orig_argv: Vec<Vec<u8>>,
    mut read: F,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), SyscallError> {
    let mut cur_path = orig_path;
    let mut cur_argv = orig_argv;
    let mut depth: usize = 0;
    let elf_bytes: Vec<u8> = loop {
        let bytes = read(&cur_path)?;
        if bytes.starts_with(b"\x7FELF") {
            break bytes; // ELF leaf
        }
        if !bytes.starts_with(b"#!") {
            // Not a shebang and not ELF — let load_elf reject it (ENOEXEC) inside the core,
            // after a single clean entry.
            break bytes;
        }
        depth += 1;
        if depth > MAX_SHEBANG_DEPTH {
            return Err(SyscallError::ELOOP);
        }
        let (interp, optarg) = parse_shebang_line(&bytes)?;
        let interp_path = utf8_path(&interp)?;
        if interp_path.is_empty() || interp_path.len() > MAX_EXEC_PATH_LEN {
            return Err(SyscallError::EINVAL);
        }
        // argv = [interp, optarg?, cur_path] ++ cur_argv[1..]; drop cur_argv[0].
        cur_argv = reconstruct_argv(&interp, optarg.as_deref(), cur_path.as_bytes(), &cur_argv)?;
        cur_path = interp_path; // next hop reads the interpreter file
                                // `bytes` drops here => at most one MAX_EXEC_IMAGE_SIZE buffer is live.
    };
    Ok((elf_bytes, cur_argv))
}

/// M0-4: pure self-test for the exec-disambiguation helpers. Covers the logic a
/// green boot cannot exercise: the `#!` shebang parser, argv reconstruction (the
/// re-enforced MAX_ARG_* caps + embedded-NUL rejection), the UTF-8 path
/// validator, and the comm-name basename truncation. A failure panics the boot
/// (caught by the serial "Test Summary" gate, not the make-test exit code).
pub fn run_exec_disambiguation_self_test() {
    // --- parse_shebang_line (Linux fs/binfmt_script.c semantics) ---
    let (i, a) = parse_shebang_line(b"#!/bin/sh\n").expect("shebang: simple");
    assert_eq!(i, b"/bin/sh".to_vec());
    assert_eq!(a, None);

    let (i, a) = parse_shebang_line(b"#!/bin/sh -x\n").expect("shebang: one arg");
    assert_eq!(i, b"/bin/sh".to_vec());
    assert_eq!(a, Some(b"-x".to_vec()));

    let (i, a) = parse_shebang_line(b"#!  /usr/bin/env python3\n").expect("shebang: env");
    assert_eq!(i, b"/usr/bin/env".to_vec());
    assert_eq!(a, Some(b"python3".to_vec()));

    // single argument keeps internal spaces, strips trailing blanks.
    let (i, a) = parse_shebang_line(b"#!/x  a b   \n").expect("shebang: internal space");
    assert_eq!(i, b"/x".to_vec());
    assert_eq!(a, Some(b"a b".to_vec()));

    assert!(parse_shebang_line(b"#!\n").is_err()); // empty interpreter
    assert!(parse_shebang_line(b"#!   \n").is_err()); // blanks-only interpreter
    assert!(parse_shebang_line(b"#!/bin/sh").is_err()); // no newline in window
    assert!(parse_shebang_line(b"#x\n").is_err()); // not a shebang
    assert!(parse_shebang_line(b"\x7FELF").is_err()); // ELF magic, not a shebang

    // --- reconstruct_argv ---
    let orig = alloc::vec![b"prog".to_vec(), b"a1".to_vec(), b"a2".to_vec()];
    let out = reconstruct_argv(b"/bin/sh", None, b"/script", &orig).expect("rebuild: basic");
    assert_eq!(
        out,
        alloc::vec![
            b"/bin/sh".to_vec(),
            b"/script".to_vec(),
            b"a1".to_vec(),
            b"a2".to_vec()
        ]
    );

    let out =
        reconstruct_argv(b"/bin/sh", Some(b"-x"), b"/script", &orig).expect("rebuild: optarg");
    assert_eq!(
        out,
        alloc::vec![
            b"/bin/sh".to_vec(),
            b"-x".to_vec(),
            b"/script".to_vec(),
            b"a1".to_vec(),
            b"a2".to_vec()
        ]
    );

    // empty original argv => no argv[0] drop, no tail (gap g9).
    let out = reconstruct_argv(b"/bin/sh", None, b"/script", &[]).expect("rebuild: empty orig");
    assert_eq!(out, alloc::vec![b"/bin/sh".to_vec(), b"/script".to_vec()]);

    // embedded NUL => EINVAL (gap g6).
    assert!(reconstruct_argv(b"/bin/sh", None, b"/scr\0ipt", &[]).is_err());
    // per-string cap (Codex Fix B) => E2BIG.
    let big = alloc::vec![b'a'; MAX_ARG_STRLEN + 1];
    assert!(reconstruct_argv(&big, None, b"/script", &[]).is_err());

    // --- utf8_path ---
    assert_eq!(utf8_path(b"/bin/sh").expect("utf8: ok"), "/bin/sh");
    assert!(utf8_path(&[0xff, 0xfe]).is_err());

    // --- exec_comm_name (basename, <=15 bytes, ASCII-sanitized) ---
    assert_eq!(exec_comm_name(b"/usr/bin/python3").as_str(), "python3");
    assert_eq!(exec_comm_name(b"noslash").as_str(), "noslash");
    assert_eq!(
        exec_comm_name(b"/a/abcdefghijklmnopqrstuvwxyz")
            .as_str()
            .len(),
        15
    );
    // non-printable / non-ASCII byte => '?' (never a lossy alloc or a panic).
    assert_eq!(exec_comm_name(&[b'/', 0xff, b'a']).as_str(), "?a");

    // --- R172-P6-F5: resolve_exec_chain (the shebang LOOP + ELOOP depth cap, mock-read) ---
    // The loop a green boot cannot exercise; driven by a fixed path->bytes mock (no VFS).
    let elf = || alloc::vec![0x7Fu8, b'E', b'L', b'F', 0, 0, 0, 0];
    // (i) ELF leaf at hop 0 => bytes returned, argv untouched.
    {
        let argv = alloc::vec![b"prog".to_vec()];
        let (bytes, out) =
            resolve_exec_chain(String::from("/bin/elf"), argv.clone(), |_p| Ok(elf()))
                .expect("ELF leaf at hop 0");
        assert!(bytes.starts_with(b"\x7FELF"));
        assert_eq!(out, argv, "ELF leaf must leave argv untouched");
    }
    // (ii) 4-deep #! chain terminating in ELF => Ok (depth == MAX_SHEBANG_DEPTH succeeds).
    {
        let read = |p: &str| -> Result<Vec<u8>, SyscallError> {
            match p {
                "/s" => Ok(b"#!/i1\n".to_vec()),
                "/i1" => Ok(b"#!/i2\n".to_vec()),
                "/i2" => Ok(b"#!/i3\n".to_vec()),
                "/i3" => Ok(b"#!/elf\n".to_vec()),
                "/elf" => Ok(elf()),
                _ => Err(SyscallError::ENOENT),
            }
        };
        assert!(
            resolve_exec_chain(String::from("/s"), alloc::vec![b"s".to_vec()], read).is_ok(),
            "4-deep shebang chain (== MAX_SHEBANG_DEPTH) must succeed"
        );
    }
    // (iii) 5-deep #! chain exceeds the cap => ELOOP.
    {
        let read = |p: &str| -> Result<Vec<u8>, SyscallError> {
            match p {
                "/s" => Ok(b"#!/i1\n".to_vec()),
                "/i1" => Ok(b"#!/i2\n".to_vec()),
                "/i2" => Ok(b"#!/i3\n".to_vec()),
                "/i3" => Ok(b"#!/i4\n".to_vec()),
                "/i4" => Ok(b"#!/elf\n".to_vec()),
                "/elf" => Ok(elf()),
                _ => Err(SyscallError::ENOENT),
            }
        };
        assert!(
            matches!(
                resolve_exec_chain(String::from("/s"), alloc::vec![b"s".to_vec()], read),
                Err(SyscallError::ELOOP)
            ),
            "5-deep shebang chain must ELOOP (depth > MAX_SHEBANG_DEPTH)"
        );
    }
    // (iv) a non-ELF, non-#! leaf returns its bytes (load_elf rejects later — must NOT loop).
    {
        let (bytes, _argv) =
            resolve_exec_chain(String::from("/data"), alloc::vec![b"d".to_vec()], |_p| {
                Ok(b"plain data".to_vec())
            })
            .expect("non-ELF non-#! leaf returns bytes");
        assert_eq!(bytes, b"plain data".to_vec());
    }
    // (v) argv reconstruction across one hop: /s (#!/i -a) with argv [s,x] => [/i,-a,/s,x].
    {
        let read = |p: &str| -> Result<Vec<u8>, SyscallError> {
            match p {
                "/s" => Ok(b"#!/i -a\n".to_vec()),
                "/i" => Ok(elf()),
                _ => Err(SyscallError::ENOENT),
            }
        };
        let (_b, argv) = resolve_exec_chain(
            String::from("/s"),
            alloc::vec![b"s".to_vec(), b"x".to_vec()],
            read,
        )
        .expect("one-hop argv reconstruction");
        assert_eq!(
            argv,
            alloc::vec![
                b"/i".to_vec(),
                b"-a".to_vec(),
                b"/s".to_vec(),
                b"x".to_vec()
            ]
        );
    }
}
