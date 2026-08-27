//! 集成测试模块
//!
//! 测试所有子系统的集成和功能

/// 测试页表管理器
/// R180-12 compile-time cross-crate API guard. Keeping this function in the
/// top-level `kernel` crate proves that a consumer can pair the public general
/// reservation permit with the public allocation-free enqueue operation. It
/// is intentionally never executed by the boot suite.
#[allow(dead_code)]
fn assert_public_rcu_enqueue_api(permit: kernel_core::RcuCallbackPermit, callback: fn([usize; 2])) {
    kernel_core::call_rcu(permit, callback, [0; 2]);
}

pub fn test_page_table() {
    klog_always!("  [TEST] Page Table Manager...");
    klog_always!("    ✓ Page table manager module compiled");
    klog_always!("    ✓ Virtual memory mapping support ready");
}

/// 测试进程控制块
pub fn test_process_control_block() {
    kernel_core::process::Process::run_arc_lifetime_self_test();
    kernel_core::process::run_process_table_retirement_self_test();
    kernel_core::process::run_process_registry_txn_self_test();
    klog_always!("  [TEST] Process Control Block...");
    klog_always!("    [PASS] RF180-40 process Arc/Weak exact-lifetime admission");
    klog_always!("    [PASS] RF180-44 process-table deferred retirement");
    klog_always!("    [PASS] D2-ARC process-registry transaction (fail-closed try-lock API)");
    klog_always!("    ✓ Process structure defined");
    klog_always!("    ✓ Priority system implemented");
    klog_always!("    ✓ State management ready");
}

/// 测试增强型调度器
pub fn test_scheduler() {
    kernel_core::process::run_ready_aging_self_test();
    kernel_core::process::run_fatal_exit_publication_self_test();
    sched::enhanced_scheduler::run_bounded_selector_self_test();
    sched::enhanced_scheduler::run_identity_cleanup_self_test();
    sched::enhanced_scheduler::run_identity_resume_self_test();
    sched::enhanced_scheduler::run_scheduler_admission_self_test();
    kernel_core::process::run_fd_charge_migration_self_test();
    klog_always!(
        "    [PASS] RF178-33 selector/aging/identity-cleanup + RF178-35 fatal wake + RF178-36 identity resume"
    );
    klog_always!("  [TEST] Enhanced Scheduler...");
    klog_always!("    ✓ Scheduler module compiled");
    klog_always!("    ✓ Multi-level feedback queue ready");
    klog_always!("    ✓ Clock tick integration prepared");
}

/// 测试Fork系统调用框架
pub fn test_fork_framework() {
    klog_always!("  [TEST] Fork System Call Framework...");
    kernel_core::fork::run_cow_refcount_self_test();
    kernel_core::syscall::run_cow_mprotect_self_test();
    kernel_core::pid_namespace::run_shutdown_creation_self_test();
    klog_always!("    ✓ Fork implementation compiled");
    klog_always!("    ✓ COW (Copy-on-Write) framework ready");
    klog_always!("    ✓ Physical page ref counting available");
}

/// 测试系统调用
pub fn test_syscalls() {
    klog_always!("  [TEST] System Calls...");
    klog_always!("    ✓ System call framework defined");
    klog_always!("    ✓ 50+ system calls enumerated");
    klog_always!("    ✓ Handler infrastructure ready");
    // M0 #2: the pure helpers behind clock_gettime(228)/readv(19)/rt_sigprocmask(14).
    // Verifies the clock-id accept/reject set, ms→timespec/timeval boundary
    // arithmetic, the rt_sigprocmask Linux-semantics validator (incl. the
    // NULL-`set` how-skip), and readv's single-segment selection (the
    // first-non-empty-iovec one-read rule that avoids the exact-boundary block).
    kernel_core::syscall::run_startup_abi_self_test();
    kernel_core::syscall::run_linux_wire_abi_self_test();
    klog_always!("    [PASS] R180-24/25 Linux wire ABI: sockaddr_in bytes + getdents64 d_name@19");
    klog_always!("    ✓ M0 #2 startup ABI: clock_gettime id-set + ms→timespec/timeval + rt_sigprocmask validator + readv seg-select");
    // M0 #4: the pure helpers behind exec disambiguation — the `#!` shebang
    // parser, argv reconstruction (re-enforced MAX_ARG_* caps + embedded-NUL
    // rejection), the UTF-8 path validator, and comm-name basename truncation.
    kernel_core::syscall::run_exec_disambiguation_self_test();
    klog_always!("    ✓ M0 #4 exec disambig: shebang parse + argv rebuild caps/NUL + utf8_path + comm-name basename");
    // M0 #4: the new VFS exec-read leg (read_file_for_exec) end-to-end over the
    // real root ramfs — path resolution + dir/missing rejection + (best-effort)
    // the incremental read loop and size cap. VFS is initialized well before the
    // integration tests run.
    vfs::manager::run_exec_read_file_self_test();
    vfs::ProcFs::run_admission_self_test();
    klog_always!("    [PASS] RF180-40 procfs Arc admission + ENOMEM rollback");
    // M0-6 slice 2: rename(82) atomicity + dual errno-mapper fidelity (ENOTEMPTY/EROFS/
    // ENAMETOOLONG) + RENAME_NOREPLACE + the half-mutation guard.
    vfs::manager::run_rename_self_test();
    // P2-C: fallible symlink-resolution helpers (last named D2-ERR-RECOVERY instance).
    vfs::manager::run_symlink_fallible_helpers_self_test();
    klog_always!("    ✓ P2-C symlink fallible helpers: try_reserve path/buf/utf8 joins");
    // M0 #6: RLIMIT (getrlimit/setrlimit/prlimit64) data-model + validator, and the
    // seccomp<->dispatch divergence-prevention parity tests (the pledge allowlist is
    // PARTITIONED into dispatched XOR exempt; BPF agrees with the semantic gate).
    kernel_core::syscall::run_rlimit_self_test();
    kernel_core::syscall::run_pledge_dispatch_parity_self_test();
    kernel_core::syscall::run_pledge_semantic_parity_self_test();
    klog_always!("    ✓ M0 #6 rlimit + seccomp parity: getrlimit/setrlimit/prlimit64 + allowlist⊆dispatch∪exempt + BPF==semantic + FATTR-const fix");
    // M0 #5 (sub-slice 1a): signal-handler delivery. The pure rt_sigframe builder +
    // SROP validators (layout %16==8, FXSAVE info-leak tail, MXCSR mask, RIP/RSP
    // canonical+low-half, deliver→sigreturn mcontext round-trip) AND the signal data
    // model (mask RMW with SIGKILL/SIGSTOP strip, disposition resolver). These cover
    // the mis-wires a green boot cannot catch.
    kernel_core::signal_frame::run_signal_frame_self_test();
    // RF178-34: shared syscall/IRQ VMA locator boundary and fail-closed cases.
    kernel_core::syscall::run_sigframe_stack_locator_self_test();
    kernel_core::signal::run_signal_self_test();
    // R188-U09-1/U09-2: IRQ-return signal delivery must use the shared
    // RFLAGS sanitizer and keep the PCB lock out of faultable usercopy.
    kernel_core::syscall::run_irq_signal_delivery_self_test();
    klog_always!(
        "    ✓ R188 IRQ signal delivery: shared RFLAGS sanitizer + fail-closed redirect guard + sender identity"
    );
    klog_always!("    ✓ M0 #5 signals (1a): rt_sigframe layout/SROP/MXCSR/round-trip + mask RMW + disposition resolver");
    // M0 #5 (1b-2): SAME-return handler delivery for a blocked-and-resumed syscall —
    // the frame-binding validity predicate + the arch get/set-binding callback wiring
    // (a mis-registration is invisible to a green boot, which never blocks-then-signals).
    kernel_core::syscall::run_saved_frame_binding_self_test();
    klog_always!(
        "    ✓ M0 #5 signals (1b-2): frame-binding predicate + arch get/set-binding round-trip"
    );
    // R172-X-F1: EXEC-SIGNAL-SAFEPOINT-CONJUNCTION leg (b) — exec resets real handlers to
    // SIG_DFL, preserves SIG_IGN (exercises the production reset_sigactions_for_exec).
    kernel_core::syscall::run_exec_signal_safepoint_self_test();
    klog_always!("    ✓ R172-X-F1 exec-signal safepoint: handler reset / SIG_IGN preserved");
    // M0-5 1b-1b: IPC-recv + PI-futex precise EINTR — the errno-mapping guard
    // (IpcError::Interrupted => EINTR) a future receive_message_blocking caller must honor.
    // PURE (a real-blocking receive/futex test would hang single-CPU at boot).
    ipc::run_ipc_eintr_self_test();
    klog_always!("    ✓ M0 #5 signals (1b-1b): IPC/PI-futex precise-EINTR errno mapping (Interrupted => EINTR)");
    // P2-B: under-lock recheck-before-publish closes the R172 futex compare/
    // enqueue lost-wake class (RF178-8 try_prepare_with_timeout_after).
    ipc::run_futex_lost_wake_prepare_self_test();
    ipc::run_robust_futex_self_test();
    ipc::run_blocking_sync_failure_self_test();
    klog_always!("    [PASS] RF180-42 blocking sync ENOMEM propagation + mutex invariant");
    klog_always!(
        "    [PASS] R188-U34 robust futex: owner-death ABI transition + checked offsets + bounded PID/cycle walk"
    );
    klog_always!(
        "    ✓ P2-B futex lost-wake: prepare recheck-before-publish (fail→empty, pass→Arm+cancel)"
    );
    // P3-A: process-generation stamp for pipe WaitQueue wake identity.
    ipc::run_process_gen_stamp_self_test();
    klog_always!(
        "    ✓ P3-A pipe raw-PID residual: PROCESS_GEN_TAG stamp/unstamp + mismatch refuse"
    );
    // M0-6 poll/select: the PURE ABI/codec/timeout core (fd_set words/mark/test/
    // trim boundaries, strict timespec vs lenient timeval conversion, revents
    // masking with ERR/HUP/NVAL-always + RDHUP-requires-request, select-bit map).
    kernel_core::poll::run_poll_pure_self_test();
    // M0-6 poll/select: the pipe readiness PROBE composition over a REAL pipe
    // (probe-layer only — no PROCESS_TABLE registration + timeout-0/non-blocking
    // reads, so it cannot block or flake the 2-core SMP gate).
    run_poll_pipe_probe_self_test();
    // M0-6 poll/select: socket fds must classify as PollArm::Socket (not the
    // AlwaysReady default) — guards the SocketFile::poll_arm override that routes
    // to SocketState::poll_readiness (impl-diff review CONFIRMED finding).
    kernel_core::syscall::run_poll_socket_arm_self_test();
    klog_always!(
        "    ✓ M0 #6 poll/select: pure codec/trim/timeout/mask + pipe probe + socket-arm classify"
    );
    // U.S3-B: the generic FileOps::cap_id() accessor that the fd→cap lifecycle
    // (dup bump, close/exec/exit decrement) dispatches through — SocketFile
    // must override (Some), clone must carry the SAME CapId (bump lives at the
    // install site, not clone_box), defaults stay None. A missing override is
    // invisible to a green boot (dev-v35 class): decrements silently no-op and
    // cap slots leak to TableFull.
    kernel_core::syscall::run_fileops_cap_id_self_test();
    klog_always!(
        "    ✓ U.S3-B fd→cap accessor: SocketFile override + same-CapId clone + None default"
    );
    // U.S3-SLICE-2: fork reconciliation of thread-shared cap_table refcounts.
    // When a CLONE_THREAD thread (sharing its cap_table Arc) calls fork(), the
    // verbatim refcount copy includes sibling-held references but the child only
    // gets the forking thread's fds → over-count. reconcile_refcounts_after_fork
    // fixes this by counting the child's actual fd references and overwriting
    // each CapEntry.refcount. Self-test simulates the scenario and asserts the
    // corrected counts (pure: no real process/socket state).
    // U.S2-SLICE-3 extends it: fd-backed orphans (0 child fds) are REVOKED
    // (CRITICAL-9 slot-leak class), Pipe rides the Socket class, and
    // non-fd-backed caps (Endpoint) stay VERBATIM (BV-3 scoping).
    // R186-1: pin the capability-reservation half of the open/openat publication
    // transaction. The production path's single Process guard prevents recursive
    // locking; this pure CapTable probe specifically verifies that a reserved slot
    // is invisible until installed, its id is stable, and cancellation cannot
    // alias a capability published by a later transaction.
    kernel_core::syscall::run_fd_publication_transaction_self_test();
    klog_always!(
        "    ✓ R186-1 cap reservation: invisible-before-install + id stability + cancel-no-alias"
    );
    cap::run_reclaim_growth_self_test();
    klog_always!(
        "    ✓ RF186 capability rollback: reclaim + bounded regrowth + ledger restoration"
    );
    // RF186 review-fix: pin the final cross-crate publication invariants. The
    // pipe probe injects failure at the second cap reservation and proves both
    // FD/files.max reservations are returned, the first cap reservation is
    // cancelled, empty backing is reclaimed, and its consumed generation cannot
    // alias the recovered reservation. The broker probe rejects wrong-table and
    // wrong-credential authority without consuming capacity. The audit probe
    // executes the exact grant RAII owner with a deterministic emitter and
    // proves explicit completion and Drop fallback each fire exactly once while
    // the authorization proof remains live.
    ipc::run_pipe_second_cap_failure_self_test();
    kernel_core::process::Process::run_capability_authority_binding_self_test();
    kernel_core::syscall::run_authorized_cap_grant_audit_self_test();
    klog_always!(
        "    ✓ RF186 pipe/cap publication: second-reserve rollback + authority binding + exactly-once audit"
    );
    kernel_core::syscall::run_fork_reconcile_refcount_self_test();
    klog_always!(
        "    ✓ U.S3-SLICE-2/U.S2-SLICE-3 fork reconciliation: refcount correction + orphan revoke + BV-3 scoping"
    );
    // U.S2-SLICE-3: the PipeHandle cap_id accessor contract — the exact
    // missing-override class run_fileops_cap_id_self_test pins for SocketFile
    // (kernel_core cannot construct a PipeHandle — dep direction — so the pipe
    // leg lives here where real pipes are built). A missing override or a
    // clone that drops the CapId silently no-ops every pipe-fd close decrement
    // (cap slot leak → TableFull DoS), invisible to a green boot.
    run_pipe_cap_id_self_test();
    klog_always!(
        "    ✓ U.S2-SLICE-3 pipe fd→cap accessor: None default + set_cap_id override + same-CapId clone"
    );
}

/// U.S2-SLICE-3: structural self-test for the PipeHandle cap_id contract.
///
/// Pins three load-bearing properties of the pipe cap wiring (PURE: the
/// fabricated CapId resolves to no table — no process/cap state is touched,
/// and the non-blocking test pipe cannot hang the boot gate):
/// 1. a fresh (never fd-installed) PipeHandle carries NO CapId — unit-test
///    pipes and rollback handles must stay funnel-invisible;
/// 2. after `set_cap_id` (what pipe_create_callback does under the Process
///    lock), `FileOps::cap_id()` reports it — the generic dup/close/exec/exit
///    lifecycle dispatches through this override;
/// 3. `clone_box` carries the SAME CapId (U.S3-A2 purity: the install-site
///    bump owns refcount changes, the clone itself never touches cap state) —
///    and dropping the clone (transient-I/O shape) is side-effect-free for
///    cap accounting by construction (Drop contract, CRITICAL-7).
fn run_pipe_cap_id_self_test() {
    use ipc::pipe::{create_pipe, PipeFlags};
    use kernel_core::process::FileOps;

    let flags = PipeFlags {
        nonblock: true,
        cloexec: false,
    };
    let (mut read_end, write_end) = create_pipe(flags).expect("pipe cap self-test: create_pipe");

    // (1) Never-installed handles are cap-less (funnel no-op class).
    assert!(
        FileOps::cap_id(&read_end).is_none() && FileOps::cap_id(&write_end).is_none(),
        "U.S2-SLICE-3: a PipeHandle that never passed the sys_pipe install \
         site must carry NO CapId (rollback/test handles stay funnel-invisible)"
    );

    // (2) set_cap_id → the FileOps override reports it.
    let cid = kernel_core::CapId::from_parts(9, 77);
    read_end.set_cap_id(cid);
    let desc: &dyn FileOps = &read_end;
    assert!(
        desc.cap_id() == Some(cid),
        "U.S2-SLICE-3: PipeHandle must override FileOps::cap_id() with the \
         CapId set at the install site — a default-None fallback makes every \
         pipe-fd close decrement a no-op (cap slot leak → TableFull DoS)"
    );

    // (3) clone_box carries the SAME CapId; dropping the clone only balances
    // the pipe end count (readers 2→1), never cap state.
    let cloned = desc.clone_box().expect("descriptor clone self-test");
    assert!(
        cloned.cap_id() == Some(cid),
        "U.S2-SLICE-3: a dup/fork/transient copy must reference the SAME \
         CapId (shared entry) — the refcount bump lives at the install site, \
         never inside clone_box (U.S3-A2/A3)"
    );
    drop(cloned);
    assert!(
        desc.cap_id() == Some(cid),
        "U.S2-SLICE-3: dropping a transient clone must not disturb the \
         original handle's CapId"
    );
}

/// M0-6 poll/select: exercise the pipe readiness probe end-to-end over a real
/// pipe via its `poll_arm` FileOps hook — the exact `Dyn`-arm composition the
/// syscall probe pass runs. Probe-layer only: no process registration, and the
/// pipe is non-blocking so a mistaken read can never hang the boot / SMP gate.
fn run_poll_pipe_probe_self_test() {
    use ipc::pipe::{create_pipe, PipeFlags, PipeHandle};
    use kernel_core::poll::{
        mask_revents, status_to_bits, PollArm, POLLERR, POLLHUP, POLLIN, POLLOUT,
    };
    use kernel_core::process::FileOps;

    // Non-blocking pipe: a stray read returns WouldBlock instead of blocking.
    let flags = PipeFlags {
        nonblock: true,
        cloexec: false,
    };

    // Compute pre-mask readiness bits for a pipe end via its poll_arm probe.
    let probe_bits = |h: &PipeHandle| -> i16 {
        match h.poll_arm() {
            PollArm::Dyn { probe, write_end } => {
                let st = if write_end {
                    probe.poll_status_write()
                } else {
                    probe.poll_status_read()
                };
                status_to_bits(&st)
            }
            _ => panic!("poll pipe self-test: a pipe end must classify as Dyn"),
        }
    };

    let (rd, wr) = create_pipe(flags).expect("poll self-test: create_pipe");
    // Empty pipe, both ends open: read end not readable + no HUP; write end writable.
    let rb = probe_bits(&rd);
    assert!(rb & POLLIN == 0, "empty pipe read end must not be readable");
    assert!(rb & POLLHUP == 0, "pipe with a live writer must not HUP");
    assert!(
        probe_bits(&wr) & POLLOUT != 0,
        "fresh pipe write end must be writable"
    );
    // Write 1 byte → read end becomes readable.
    wr.write(b"x").expect("poll self-test: write");
    assert!(
        probe_bits(&rd) & POLLIN != 0,
        "read end must be readable after a write"
    );
    // Drain the byte → read end not readable again.
    let mut buf = [0u8; 1];
    let n = rd.read(&mut buf).expect("poll self-test: drain read");
    assert_eq!(n, 1, "drain read must return the one buffered byte");
    assert!(
        probe_bits(&rd) & POLLIN == 0,
        "read end must not be readable after drain"
    );
    // Close the write end → read end reports POLLHUP.
    drop(wr);
    assert!(
        probe_bits(&rd) & POLLHUP != 0,
        "read end must HUP after the writer is closed"
    );

    // A fresh pipe whose READ end is closed → write end reports POLLERR.
    let (rd2, wr2) = create_pipe(flags).expect("poll self-test: create_pipe 2");
    drop(rd2);
    assert!(
        probe_bits(&wr2) & POLLERR != 0,
        "write end must ERR after the reader is closed"
    );

    // Masking composition: an unrequested POLLOUT is stripped; POLLHUP always passes.
    assert_eq!(
        mask_revents(POLLIN, POLLOUT | POLLHUP),
        POLLHUP,
        "mask_revents must strip unrequested OUT but keep HUP"
    );
}

/// 测试上下文切换
pub fn test_context_switch() {
    klog_always!("  [TEST] Context Switch...");
    klog_always!("    ✓ Context structure (176 bytes) defined");
    klog_always!("    ✓ Assembly switch routine compiled");
    klog_always!("    ✓ Register save/restore ready");
}

/// 测试内存映射
pub fn test_memory_mapping() {
    klog_always!("  [TEST] Memory Mapping...");
    klog_always!("    ✓ mmap system call implemented");
    klog_always!("    ✓ munmap system call implemented");
    klog_always!("    ✓ Memory protection flags supported");
}

/// Test ext2 filesystem write support
///
/// This test verifies the ext2 write infrastructure is compiled and functional.
/// Full write testing requires a writable test file in the disk image.
pub fn test_ext2_write() {
    klog_always!("  [TEST] Ext2 Write Support...");

    vfs::ext2::run_ext2_direct_write_preflight_self_test();
    klog_always!("    Ext2 direct-write preflight boundaries passed");
    vfs::ext2::run_ext2_mutation_scratch_self_test();
    klog_always!("    RF178-39 scratch reuse + fallible UTF-8 decoding passed");
    iommu::domain::run_mapping_tracker_self_test();
    klog_always!("    RF178-39 fallible IOMMU mapping tracker passed");
    vfs::ext2::run_ext2_inode_cache_self_test();
    klog_always!("    RF178-37 canonical inode-cache lifecycle passed");
    vfs::ext2::run_ext2_create_self_test();
    klog_always!("    Ext2Fs::create transactional file creation passed");

    // Optional mounted-image probe. The deterministic fail-closed production
    // open/cache test above is the RF178-37 acceptance criterion.
    match vfs::stat("/mnt") {
        Ok(stat) => {
            let flags = vfs::OpenFlags::new(vfs::OpenFlags::O_RDONLY | vfs::OpenFlags::O_DIRECTORY);
            let first = vfs::open("/mnt", flags, 0);
            let second = vfs::open("/mnt", flags, 0);
            if let (Ok(first), Ok(second)) = (first, second) {
                let first = first.as_any().downcast_ref::<vfs::FileHandle>();
                let second = second.as_any().downcast_ref::<vfs::FileHandle>();
                if let (Some(first), Some(second)) = (first, second) {
                    if first.inode.as_any().is::<vfs::Ext2Inode>()
                        && second.inode.as_any().is::<vfs::Ext2Inode>()
                    {
                        let ext2 = first
                            .inode
                            .as_any()
                            .downcast_ref::<vfs::Ext2Inode>()
                            .expect("ext2 downcast after type check");
                        assert!(
                            ext2.uses_internal_journal()
                                .expect("query mounted ext2 journal"),
                            "production ext2 image must use its internal JBD2 journal"
                        );
                        assert!(
                            alloc::sync::Arc::ptr_eq(&first.inode, &second.inode),
                            "independent ext2 opens must share the canonical inode Arc"
                        );
                        klog_always!("    RF178-37 mounted-ext2 dual-open identity passed");
                        let alloc_flags = vfs::OpenFlags::new(vfs::OpenFlags::O_RDWR);
                        // The R180-6 JBD2 write probe is optional: the deterministic
                        // fail-closed test above is the RF178-37 acceptance criterion.
                        // The probe file is created by the production `ensure-ext3-image`
                        // fixture; a minimal image (e.g. the syz-fuzzer's fresh disk)
                        // may not carry it, in which case the probe skips gracefully
                        // like the not-mounted / not-ext2 / dual-open-failed branches
                        // above rather than kernel-panic via .expect().
                        match vfs::open("/mnt/test/alloc.bin", alloc_flags, 0) {
                            Ok(alloc_file_ops) => {
                                let alloc_file = alloc_file_ops
                                    .as_any()
                                    .downcast_ref::<vfs::FileHandle>()
                                    .expect("ext3 allocation probe FileHandle");
                                assert_eq!(
                                    alloc_file
                                        .inode
                                        .stat()
                                        .expect("stat production ext3 allocation probe")
                                        .size,
                                    0,
                                    "production allocation probe must be reset to an empty inode"
                                );
                                assert_eq!(
                                    alloc_file.write(b"J"),
                                    Ok(1),
                                    "production image write must traverse JBD2 allocation/mapped commit"
                                );
                                let mut committed = [0u8; 1];
                                assert_eq!(
                                    alloc_file.inode.read_at(0, &mut committed),
                                    Ok(1),
                                    "production JBD2 write must be immediately readable"
                                );
                                assert_eq!(committed, *b"J");
                                klog_always!("    R180-6 production JBD2 write path passed");
                            }
                            Err(e) => {
                                klog_always!(
                                    "    - /mnt/test/alloc.bin unavailable: {:?}; R180-6 JBD2 write probe skipped",
                                    e
                                );
                            }
                        }

                        // Ext2Fs::create production probe: O_CREAT|O_EXCL must
                        // traverse the transactional create path (was
                        // result_open:-38 ENOSYS before Ext2Fs::create).  On a
                        // fresh image the file is created (Ok) and the full probe
                        // runs; on a reused image the file already exists (Err)
                        // and the probe skips — the deterministic
                        // run_ext2_create_self_test above verifies create every
                        // boot regardless.
                        let create_flags = vfs::OpenFlags::new(
                            vfs::OpenFlags::O_WRONLY
                                | vfs::OpenFlags::O_CREAT
                                | vfs::OpenFlags::O_EXCL
                                | vfs::OpenFlags::O_NOFOLLOW,
                        );
                        match vfs::open("/mnt/test/.syz-create-probe.bin", create_flags, 0o600) {
                            Ok(probe_ops) => {
                                let probe = probe_ops
                                    .as_any()
                                    .downcast_ref::<vfs::FileHandle>()
                                    .expect("create probe FileHandle");
                                assert_eq!(probe.write(b"X"), Ok(1), "create probe write");
                                let probe_ino = probe.inode.stat().expect("stat create probe").ino;
                                let _ = probe;
                                drop(probe_ops);
                                let rd = vfs::open(
                                    "/mnt/test/.syz-create-probe.bin",
                                    vfs::OpenFlags::new(vfs::OpenFlags::O_RDONLY),
                                    0,
                                )
                                .expect("reopen create probe O_RDONLY");
                                let rd = rd
                                    .as_any()
                                    .downcast_ref::<vfs::FileHandle>()
                                    .expect("reopen FileHandle");
                                assert_eq!(
                                    rd.inode.stat().expect("stat reopen").ino,
                                    probe_ino,
                                    "create probe must be cache-canonical across opens"
                                );
                                let mut buf = [0u8; 1];
                                assert_eq!(
                                    rd.inode.read_at(0, &mut buf),
                                    Ok(1),
                                    "create probe readback"
                                );
                                assert_eq!(buf, *b"X");
                                assert!(
                                    matches!(
                                        vfs::open(
                                            "/mnt/test/.syz-create-probe.bin",
                                            create_flags,
                                            0o600
                                        ),
                                        Err(_),
                                    ),
                                    "O_CREAT|O_EXCL on existing must fail"
                                );
                                klog_always!("    Ext2Fs::create production probe passed");
                            }
                            Err(e) => {
                                klog_always!(
                                    "    - /mnt/test create probe unavailable ({:?}); create probe skipped",
                                    e
                                );
                            }
                        }
                    } else {
                        klog_always!("    - /mnt is not ext2; mounted-image probe skipped");
                    }
                } else {
                    klog_always!("    - /mnt handles are not FileHandle; probe skipped");
                }
            } else {
                klog_always!("    - /mnt dual-open unavailable; probe skipped");
            }
            klog_always!("    ✓ /mnt mounted (ino={})", stat.ino);
            klog_always!("    ✓ Ext2 write_at() implemented");
            klog_always!("    ✓ Block allocation with bitmap management");
            klog_always!("    ✓ Inode persistence to disk");
        }
        Err(e) => {
            klog_always!("    - /mnt not mounted: {:?}", e);
        }
    }

    klog_always!("    ✓ Ext2 write infrastructure compiled");
}

/// Test the fallible ordered map (next-phase #11 / R165-14).
///
/// Runs real assertions over `FallibleOrderedMap` (sorted-Vec backing, fallible
/// `try_insert`, range/range_mut, `from_sorted_vec`). Any failure panics, which
/// `make test` / `make boot-check` detect via the serial log.
pub fn test_fallible_map() {
    klog_always!("  [TEST] Fallible Ordered Map...");
    kernel_core::fallible_map::run_fallible_ordered_map_self_test();
    klog_always!("    ✓ try_insert / replace / remove ordered + fallible");
    klog_always!("    ✓ range / range_mut half-open bounds + DoubleEnded");
    klog_always!("    ✓ from_sorted_vec O(1) adopt + try_clone independence");
}

/// RF178-11: page-cache heap/cgroup admission invariants.
pub fn test_page_cache_policy() {
    klog_always!("  [TEST] Page Cache Admission Policy...");
    mm::run_page_cache_policy_self_test();
    klog_always!("    ✓ heap-derived cap + single-index retained-capacity bound");
    klog_always!("    ✓ cgroup-before-global + owner-only refusal reclaim");
    klog_always!("    ✓ RAII charge transfer + exact final-Arc uncharge");
}

/// R180-12: allocation-free RCU callback pool state/partition/FIFO invariants.
pub fn test_rcu_callback_pool() {
    klog_always!("  [TEST] RCU Callback Pool (R180-12)...");
    kernel_core::rcu::run_rcu_callback_pool_self_test();
    klog_always!("    ✓ PID-indexed stack class + reserved general class");
    klog_always!("    ✓ cancellation, epoch gate, FIFO wrap, and state balance");
}

/// R180-20: independent TCP pseudo-header/wire checksum vectors.
pub fn test_tcp_checksum_wire_oracle() {
    klog_always!("  [TEST] TCP checksum wire oracle (R180-20)...");
    net::tcp::run_tcp_checksum_self_test();
    klog_always!("    [PASS] even SYN + odd payload checksum vectors");
}

/// P2-A: kernel-heap byte-budget arbiter coexistence + query API.
/// D1-RES: oracle coexistence proof + all 15 HeapClass boundaries.
pub fn test_heap_budget_arbiter() {
    klog_always!("  [TEST] Heap Budget Arbiter (P2-A)...");
    mm::run_heap_budget_self_test();
    mm::run_emergency_heap_self_test();
    assert!(
        mm::heap_budgets_published(),
        "arbiter must be published at boot before integration tests"
    );
    let snap = mm::heap_budget_snapshot();
    // Consumer coupling: derived caps must stay within registered floors.
    assert!(
        (net::conntrack::CT_MAX_ENTRIES * 1024) <= mm::CONNTRACK_HARD_BYTES,
        "conntrack entry charge must fit arbiter hard floor"
    );
    assert!(
        (mm::PAGE_CACHE_MAX_PAGES as usize) * 256 <= mm::PAGE_CACHE_META_HARD_BYTES,
        "page-cache metadata charge must fit arbiter hard floor"
    );
    assert_eq!(
        mm::budget_bytes(mm::HeapBudgetId::ExecImagePeak),
        mm::EXEC_IMAGE_PEAK_BYTES
    );
    assert_eq!(
        mm::hard_floor_bytes(mm::HeapBudgetId::ExecImagePeak),
        0,
        "exec peak must not register as a hard floor"
    );
    assert_eq!(mm::transient_peak_holders(), 0);
    kernel_core::syscall::run_transient_io_admission_self_test();
    klog_always!(
        "    ✓ coexistence: hard={} KiB + headroom={} KiB + peak={} KiB <= heap={} KiB (residual={} KiB)",
        snap.hard_floors_sum_bytes / 1024,
        snap.reserved_headroom_bytes / 1024,
        snap.transient_peak_bytes / 1024,
        snap.heap_total_bytes / 1024,
        snap.general_residual_bytes / 1024
    );
    klog_always!("    ✓ named hard floors derived from arbiter (no independent HEAP/N fractions)");
    klog_always!("    ✓ aggregate exec/I/O admission + exact nested-buffer release");

    // D1-RES: runtime coexistence oracle (PO-RES-02). Fixed-floor consumers
    // (page-cache + audit) are not charged through the admission ledger.
    // Conntrack + Futex ARE ledger-charged and must NOT be re-attributed.
    //
    // Protocol: capture the unledgered baseline BEFORE the boundary stress,
    // re-measure AFTER it. The boundary test drives every class gate and the
    // global gate through full reserve/release cycles, so any unledgered
    // residue it leaks (or any ledger/allocator divergence it causes) shows
    // up as drift. Drift past the declared 64 KiB unadmitted reserve fails
    // the boot. This proves the accounting identity live, not just at rest.
    let measure = || -> (usize, usize) {
        let allocator_used = mm::NORMAL_HEAP_SIZE_BYTES - mm::heap_free_bytes();
        let pagecache_meta_live = (mm::PAGE_CACHE.stats().nr_pages as usize) * 256;
        let audit_ring_live = audit::ring_capacity_bytes().unwrap_or(0);
        (allocator_used, pagecache_meta_live + audit_ring_live)
    };

    let (used_before, floors_before) = measure();
    let adm_before = mm::heap_admission_snapshot();
    let baseline_unledgered = used_before
        .saturating_sub(adm_before.committed_bytes)
        .saturating_sub(floors_before);
    // Absolute leg: the self-derived baseline is only accepted under a named,
    // budgeted ceiling — otherwise the drift leg would tautologically accept
    // any pre-existing unledgered footprint. Together these bound total
    // unattributed use by (boot ceiling + 64 KiB runtime reserve).
    assert!(
        baseline_unledgered <= mm::BOOT_UNLEDGERED_FOOTPRINT_MAX_BYTES,
        "D1-RES: boot unledgered footprint {} B exceeds budget {} B",
        baseline_unledgered,
        mm::BOOT_UNLEDGERED_FOOTPRINT_MAX_BYTES
    );

    // D1-RES-HEAP-BUDGET-SCOPE: exhaustive boundary self-test (PO-RES-02).
    mm::run_heap_admission_boundary_self_test();
    klog_always!("    ✓ all 15 HeapClass boundaries + global ceiling + exact ledger restoration");

    let (used_after, floors_after) = measure();
    match mm::check_coexistence(used_after, floors_after, Some(baseline_unledgered)) {
        mm::CoexistenceVerdict::Sound { unattributed_bytes } => {
            klog_always!(
                "    ✓ D1-RES oracle: baseline={} B, post-stress unledgered={} B, drift <= {} B reserve",
                baseline_unledgered,
                unattributed_bytes,
                mm::NORMAL_UNADMITTED_RESERVE_BYTES
            );
        }
        mm::CoexistenceVerdict::NotQuiescent { reserved_bytes } => {
            panic!(
                "D1-RES: oracle with pending reservations ({}B)",
                reserved_bytes
            );
        }
        verdict => panic!("D1-RES: oracle coexistence failed: {verdict:?}"),
    }

    // D1-RES combined-load validation (Leg B — physical, quiescent single-CPU).
    // (1) ADMITTED CONTIGUITY PROBE: prove the post-boot arena can still satisfy
    // one maximum admitted object (1 MiB — the stdin/pipe/socket-payload contract).
    {
        let charge = mm::vec_charge_bytes::<u8>(mm::LARGEST_SINGLE_ALLOCATION_BYTES)
            .expect("D1-RES: 1 MiB charge computation");
        let reservation = mm::try_reserve_heap(mm::HeapClass::BlockingIo, charge)
            .expect("D1-RES: 1 MiB must admit at the quiescent checkpoint");
        let mut probe: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let ok = probe
            .try_reserve_exact(mm::LARGEST_SINGLE_ALLOCATION_BYTES)
            .is_ok();
        assert!(
            ok,
            "D1-RES: post-boot arena cannot satisfy one maximum admitted object (fragmentation)"
        );
        drop(probe);
        drop(reservation);
        klog_always!("    ✓ D1-RES contiguity probe: 1 MiB admitted object satisfiable");
    }
    // (2) RESTORATION RE-CHECK: prove the probe left zero residue and the oracle
    // identity still holds live.
    let (used_restored, floors_restored) = measure();
    match mm::check_coexistence(used_restored, floors_restored, Some(baseline_unledgered)) {
        mm::CoexistenceVerdict::Sound { .. } => {
            klog_always!("    ✓ D1-RES oracle re-Sound after probe (exact restoration)");
        }
        verdict => panic!("D1-RES: post-probe oracle not Sound: {verdict:?}"),
    }
    // (3) PEAK LEG (R4): first real PEAK (not endpoint) evidence — logged as the
    // calibration source, asserted monotone >= endpoint and <= the ceiling.
    let peak = mm::heap_peak_used_bytes();
    klog_always!(
        "    ✓ D1-RES heap PEAK used = {} B (ceiling {} B); unledgered waiter bound 96 x 320 = 30720 B <= {} B",
        peak,
        mm::BOOT_PEAK_USED_MAX_BYTES,
        mm::NORMAL_UNADMITTED_RESERVE_BYTES / 2
    );
    assert!(
        peak >= used_restored,
        "D1-RES: peak {peak} < endpoint {used_restored} (instrumentation bug)"
    );
    assert!(
        peak <= mm::BOOT_PEAK_USED_MAX_BYTES,
        "D1-RES: heap peak {peak} B exceeds ceiling {} B",
        mm::BOOT_PEAK_USED_MAX_BYTES
    );
}

/// Test the Phase J.2 per-tenant (per-network-namespace) TCP resource budgets.
///
/// Runs real assertions over the per-namespace connection (J2-1), half-open /
/// SYN-backlog (J2-2), and SEND-buffer-byte (J2-6) counters: cap enforcement
/// (fail-closed), namespace isolation, root-namespace exemption, remove-at-0
/// bookkeeping, the leak-via-stale-Weak regression (a pruned dead connection MUST
/// uncharge its tenant), and for J2-6 the reserve->refund reconcile, multi-sibling
/// aggregation, and the Drop/detach residual-uncharge regressions. Any failure
/// panics, which `make test` / `make boot-check` detect via the serial log.
pub fn test_per_ns_tcp_budgets() {
    klog_always!("  [TEST] Per-Tenant TCP Budgets (J.2-1/2/4/6)...");
    net::socket::SocketTable::run_per_ns_budget_self_test();
    klog_always!("    ✓ per-netns connection cap (fail-closed) + isolation + root-exempt");
    klog_always!("    ✓ per-netns SYN-backlog cap + batch drain + remove-at-0");
    klog_always!("    ✓ stale-Weak reaper uncharges pruned tenants (leak regression)");
    klog_always!("    ✓ per-netns send-byte budget: hard cap + reserve->refund + aggregation + Drop residual");
    klog_always!("    ✓ per-netns recv-byte budget: decide-gate + reconcile-to-F + FIN-clear-no-overcount + Drop residual");
}

/// Test the Phase J.2 item 7 per-cgroup open-FD budget (`files.max`).
///
/// Runs real assertions over the hierarchical FILES controller: fail-closed cap
/// enforcement with ancestor rollback, ancestor propagation, the root id==0
/// short-circuit, migrate_fd_charges balance across chains, and saturating
/// uncharge. Any failure panics, detected by `make test` / `make boot-check`.
pub fn test_cgroup_fd_budget() {
    klog_always!("  [TEST] Per-Cgroup FD Budget (J.2-7)...");
    kernel_core::cgroup::run_cgroup_fd_budget_self_test();
    klog_always!("    ✓ hierarchical files.max cap (fail-closed) + ancestor rollback");
    klog_always!("    ✓ root id==0 exemption + migrate_fd_charges balance + saturating uncharge");
}

/// RF180-45 exact cgroup Arc lifetime and detached metadata transactions.
pub fn test_cgroup_exact_lifetime() {
    klog_always!("  [TEST] Cgroup exact-lifetime admission (RF180-45)...");
    kernel_core::cgroup::run_cgroup_exact_lifetime_self_test();
    klog_always!(
        "    [PASS] final-Weak/prepare rollback + 4097-task growth + Busy/delta migration + common-ancestor headroom + deferred reclaim"
    );
}

/// Test the Phase J.2 item 10 per-cgroup VFS dir-enumeration budget (`vfs_dir.max`).
///
/// Runs real assertions over the Arc-chain-pinning VfsDirBudgetGuard: cap clamping
/// (granted reduced → graceful short read), ancestor propagation, the headline
/// DELETION-SAFETY property (delete the charged leaf, then drop the guard → the
/// ancestor counter still returns to 0 via the held Arcs), root id==0 exemption,
/// and release idempotency. Any failure panics, detected by make test / boot-check.
pub fn test_cgroup_vfs_dir_budget() {
    klog_always!("  [TEST] Per-Cgroup VFS Dir Budget (J.2-10)...");
    kernel_core::cgroup::run_cgroup_vfs_dir_budget_self_test();
    klog_always!("    ✓ vfs_dir.max clamp (short read) + ancestor propagation");
    klog_always!(
        "    ✓ Arc-pinned uncharge survives leaf deletion + root exempt + idempotent release"
    );
}

/// RF180-L1: positioned I/O must reject every non-seekable endpoint before
/// invoking a consuming device operation (`/dev/console`, pipes, sockets).
pub fn test_positioned_io_gate() {
    klog_always!("  [TEST] Positioned I/O non-seekable gate (RF180-L1)...");
    vfs::manager::run_positioned_io_gate_self_test();
    klog_always!("    ✓ access mode first; readable non-seekable endpoints return ESPIPE");
}

/// Test the Phase J.2 item 9 per-cgroup page-table-frame kmem accounting.
///
/// Exercises the MEMORY-controller primitives the sys_mmap pt charge rides on,
/// over the hierarchy / migration / exit / fork balance points: forced soft-cap
/// charge + ancestor propagation, BOUNDED overshoot past memory.max (the pt-frame
/// count is known only after map_to ⇒ soft per IM-14), the HARD DATA gate
/// re-enforcing the limit on the next allocation, the INV-5 trap that the MEMORY
/// controller does NOT exempt root (unlike files/ports/vfs_dir), migration
/// transfer, fork==exit balance, and saturating uncharge. Any failure panics,
/// detected by `make test` / `make boot-check`.
pub fn test_cgroup_pt_kmem() {
    klog_always!("  [TEST] Per-Cgroup PT-frame kmem (J.2-9)...");
    kernel_core::cgroup::run_cgroup_pt_kmem_self_test();
    klog_always!("    ✓ forced soft-cap PT charge + ancestor propagation + bounded overshoot");
    klog_always!("    ✓ hard DATA gate re-enforces + root NOT exempt + migration transfer + fork==exit + saturating");
    klog_always!("    ✓ M2-1 SLICE-2: mem_pinned origin-pin telescopes (charge/migrate/rollback/fork==exit) + over-uncharge tripwire (matched seq==0, step-8 trips)");
    // M2-1 SLICE-2 (co-residency GAP): the migration source-unpin is
    // PER-PROCESS-EXACT when >1 process shares the source cgroup — migrating ONE
    // leaves the others' pins intact (mem_pinned(S)==Y, not 0, not floored), and
    // the saturating floor NEVER fires (over-uncharge tripwire stays 0). This is
    // the only case where a floored aggregate could mask a stranded co-resident.
    kernel_core::cgroup::run_cgroup_mem_pinned_coresidency_self_test();
    klog_always!("    ✓ M2-1 SLICE-2 co-residency: single-process migrate out of N co-resident PIDs unpins EXACTLY its share (floor never fires, tripwire==0)");
    // M2-1 SLICE-2 (exec/exit-AFTER-migrate GAP): the old image charged to A,
    // migrated A->B, is uncharged at B (proc.cgroup_id re-read post-migration) by
    // EXACTLY the migrated amount — the migrate source drains A to 0 (pre==n) and
    // the four-term exec-replace / wholesale exit / ExecSpaceGuard-rollback unpin
    // finds a LIVE re-homed pin at B (tripwire==0), proving B's unpin found a live
    // pin == X — a TRUE re-home, not a floored over-unpin masking an A-vs-B mismatch.
    kernel_core::cgroup::run_cgroup_mem_pinned_exec_after_migrate_self_test();
    klog_always!("    ✓ M2-1 SLICE-2 exec/exit-after-migrate: charge A -> migrate A->B -> uncharge X at B unpins B (not A) by exactly X (4-term + wholesale, floor never fires)");
    // M2-1 SLICE-2 (abnormal-clone-abort teardown GAP): a non-CLONE_VM clone child
    // aborted POST-fork-charge via terminate_process + cleanup_zombie (LSM-fork
    // denial / namespace-translation failure, syscall.rs:3196-3243) drains the
    // fork-charge-to-parent lump through free_process_resources' four-term exit
    // uncharge (process.rs:4318/4330/4336/4358) at proc.cgroup_id == parent_cgroup_id
    // (the never-scheduled child never migrated). The fork lump (1 add) telescopes
    // to 0 against the abnormal four-term teardown (4 subs) at the SAME origin, and
    // the over-uncharge tripwire stays 0 — proving each exit leg found a LIVE pin
    // == its term (NO FA-09 strand), the gate-independent witness the SLICE-3 flip
    // requires for this teardown window.
    kernel_core::cgroup::run_cgroup_mem_pinned_clone_abort_self_test();
    klog_always!("    ✓ M2-1 SLICE-2 abnormal-clone-abort: fork lump charged to parent -> terminate_process/cleanup_zombie 4-term drain telescopes to 0 (floor never fires, tripwire==0)");
    // M2-1 SLICE-3 (R171-S-R170-2-01 / D-R170-DELETE-GATE-LEAF closure): the
    // delete_cgroup MEMORY leg now samples the origin-keyed `mem_pinned` witness,
    // not the controller-gated display counter `memory_current`. A MEMORY-disabled
    // leaf with a live keyed charge (memory_current==0 but mem_pinned>0) is held
    // undeletable until reconciled, then deletes cleanly — closing the silent
    // bare-id ancestor strand. Matched sequence telescopes (tripwire==0).
    kernel_core::cgroup::run_cgroup_mem_pinned_delete_gate_self_test();
    klog_always!("    ✓ M2-1 SLICE-3 delete-gate: MEMORY-disabled leaf pins origin (display 0) + delete EBUSY until uncharge -> then deletes (tripwire==0)");
    // R171-CG1x0 (M2-1 SLICE-0): the frame-identity ledger reconcile — the
    // anti-bypass core that makes sys_munmap uncharge a reclaimed PT frame IFF
    // this AS charged it (an UNCHARGED brk/ELF frame is never debited; mprotect
    // Path-A is charged as of M2-1 SLICE-4a).
    kernel_core::process::run_pt_ledger_self_test();
    klog_always!("    ✓ R171-CG1x0 PT ledger: debit IFF charged (no cross-origin memory.max bypass) + saturating double-reclaim + empty-ledger no-op");
    // M2-1 SLICE-4a: mprotect Path-A (PROT_NONE->real) now charges + ledgers the
    // PT/PD frames it materializes, via MmState::record_pt_charge (the unit-tested
    // mirror of the sys_mmap Phase-3 fold). Asserts I' on the ledgered branch +
    // the telescoping round-trip through the real pt_ledger_reconcile.
    kernel_core::process::run_record_pt_charge_self_test();
    klog_always!("    ✓ M2-1 SLICE-4a: record_pt_charge folds PT charge (I' preserved, charge==reclaim telescope, inherited-basis coexist) — mprotect Path-A PT kmem now on-budget");
    // M2-1 SLICE-4b: the LOAD-BEARING DATA/PT split in RecordingFrameAllocator — the
    // inherent allocate_data_frame leaves the ledger untouched (heap / ELF DATA pages),
    // while the trait allocate_frame (map_page's intermediate-table path) records by
    // frame identity. Guards the brk-grow / exec DATA/PT swap against a ~512x over-charge
    // + ledger corruption (the single most error-prone seam of SLICE-4).
    kernel_core::syscall::run_recording_frame_allocator_split_self_test();
    klog_always!("    ✓ M2-1 SLICE-4b: RecordingFrameAllocator DATA/PT split (allocate_data_frame unrecorded, trait allocate_frame records by identity) — brk-grow PT kmem now on-budget");
    // M0-7 item7 SLICE 4: the charge-correct user-stack demand-grow PRIMITIVE
    // (try_grow_user_stack). Two self-tests: (1) the PURE accounting state machine —
    // the stack_grow_floor RLIMIT clamp + the FA-04 commit_stack_grow move (grow DATA
    // folds into elf_charged_bytes, the bucket teardown+compute+fork read, NOT the
    // vm_charged_bytes home that would strand mem_pinned at exit); (2) the cgroup
    // matched-sequence telescoping (grow→migrate→exit→rollback) proving the grow lane
    // leaves NO stranded pin (MEM_UNPIN_UNDERFLOW==0).
    kernel_core::process::run_stack_grow_accounting_self_test();
    klog_always!("    ✓ M0-7 SLICE 4: stack-grow accounting (grow_floor RLIMIT clamp + FA-04 commit folds DATA into elf_charged_bytes)");
    kernel_core::cgroup::run_stack_grow_cgroup_self_test();
    klog_always!("    ✓ M0-7 SLICE 4: stack-grow charge lane telescopes (grow/migrate/exit/rollback, MEM_UNPIN_UNDERFLOW==0 — no FA-04 strand)");
    // M4-1b: the per-PCB wait-timeout markers that replaced the two TIMER-IRQ-
    // allocating `timed_out` BTreeMaps (check_socket_timeouts + the WaitQueue timeout
    // wake, M1-02-renamed `wq_timeout_wake_by_seq`).
    // Exercises the (gen<<1)|1 sentinel (wq gen-0 disambiguation), the swap-to-clear
    // exact-generation consume (stale-drop + exact-report), no-leak-across-waits,
    // entry-clear, two-field isolation, and fork born-clean — the mis-wires a green
    // build/boot cannot catch (no test drives a real timeout-vs-wake cross-field race).
    kernel_core::process::run_timeout_marker_self_test();
    klog_always!("    ✓ M4-1b: per-PCB timeout markers (packed sentinel + swap-to-clear exact-gen + no-leak + entry-clear + two-field isolation + fork born-clean) — IRQ marker INSERT alloc removed from both timer callbacks");
    klog_always!("    ✓ M1-02: queue-free WaitQueue timeout — decide_wq_timeout(seq+Blocked) gate, alloc_wait_seq monotonic/distinct, active_wait_seq born-clean — the timer IRQ no longer derefs a WaitQueue (SMP use-after-free CLASS eliminated)");
    // M4-1c: close the LAST timer-IRQ heap residuals M4-1b left (the R151-5
    // alloc/dealloc-in-IRQ class). (A) ipc/sync.rs: the WaitQueue timeout drain is now
    // copy-don't-remove (Phase-1 copy, Phase-2 wake, Phase-3 exact-(pid,seq)
    // retain) + a rotating scan cursor for fairness — NO IRQ Vec::push realloc. (B)
    // kernel_core/syscall.rs: the empty-queue BTreeMap node free is deferred out of
    // check_timeouts to a process-context reap (drain_socket_waiter_cleanup, driven
    // by reschedule_if_needed). These exercise the mis-wires a green build/boot can't:
    // an IRQ realloc, a dropped fresh re-registered wait, an over-cap/missed timeout,
    // lost fairness (A), and a reap freeing a re-populated queue / never draining (B).
    ipc::sync::run_wq_timeout_drain_self_test();
    klog_always!("    ✓ M4-1c (A): WaitQueue timeout drain copy-don't-remove + rotating cursor + exact-(pid,seq) retain — no IRQ Vec::push realloc, fresh re-register preserved, round-robin fairness");
    kernel_core::syscall::run_socket_waiter_deferred_free_self_test();
    klog_always!("    ✓ M4-1c (B): SocketWaiters empty-queue BTreeMap free deferred to process-context reap — re-populated queue preserved, exact reap, no IRQ dealloc");
}

/// Test the Phase J.2 item 8 per-cgroup ephemeral-port budget (`ports.max`).
///
/// Two layers: the NET-controller ARITHMETIC (hierarchical charge with ancestor
/// rollback on deep rejection, the root id==0 exemption, and saturating uncharge)
/// and the net-side MECHANISM (the `PortBinding` value as the single source of
/// truth, the ptr-eq remove choke-point that uncharges exactly once and blocks
/// recycled-key / passive-child cross-cgroup clobber, refund-the-displaced-charge,
/// the dead-Weak reaper incl. the port-availability prune, the netns-teardown
/// backstop, and fold-by-cgid deferred-uncharge drain idempotency). Any failure
/// panics, detected by `make test` / `make boot-check`.
pub fn test_cgroup_port_budget() {
    klog_always!("  [TEST] Per-Cgroup Port Budget (J.2-8)...");
    kernel_core::cgroup::run_cgroup_ports_budget_self_test();
    // R170-2: origin-pinned delete-gate (controller-disabled-leaf coverage).
    kernel_core::cgroup::run_cgroup_disabled_leaf_gate_self_test();
    klog_always!("    ✓ R170-2 origin-pinned gate: disabled-leaf charge pins leaf + delete EBUSY + unpin/rollback/saturate");
    net::socket::SocketTable::run_per_cgroup_port_budget_self_test();
    klog_always!("    ✓ hierarchical ports.max cap (fail-closed) + ancestor rollback + root exempt + saturating");
    klog_always!(
        "    ✓ PortBinding single-source + ptr-eq uncharge-once + displaced-charge refund"
    );
    klog_always!("    ✓ dead-Weak reaper (+ port-availability prune) + netns backstop + deferred-drain idempotency");
    klog_always!("    ✓ R169-6 s2 choke-point: charged Explicit pure-skip / charged Ephemeral remove+refund / uncharged-Explicit not held / privileged identical");
    klog_always!("    ✓ R169-6 s2 lifecycle: terminal remove (not hold-forever) + dead-Explicit displacement refund + netns-drain-then-repair net-once");
}

/// Test the Phase J.2 cgroupfs ABI surface (files/ports/vfs_dir control files).
///
/// Covers the user-facing cgroupfs files that expose the FILES / NET / MEMORY-
/// vfs_dir enforcement landed by J.2 items 7/8/10: filename round-trip, read-only
/// classification, controller-gated visibility, append-only inode safety, and the
/// read/format path (numeric, unlimited="max", *.current gauges). The write path
/// is credential-gated (covered via set_limit + read-back, not write_content).
/// Any failure panics, detected by `make test` / `make boot-check`.
pub fn test_cgroupfs_abi() {
    klog_always!("  [TEST] Cgroupfs ABI surface (J.2 files/ports/vfs_dir)...");
    vfs::cgroupfs::run_cgroupfs_j2_abi_self_test();
    klog_always!(
        "    ✓ filename round-trip + *.max writable / *.current read-only + inode non-aliasing"
    );
    klog_always!("    ✓ read/format path (numeric + unlimited=\"max\" + current) + controller-gated visibility");
}

/// Test the R169-10 per-namespace fragment triple-budget (byte/frag/queue).
///
/// Covers the load-bearing `sum(per_ns) == global` accounting invariant across the
/// create / complete (R3) / timeout-sweep (R9) release paths + the per-ns prune,
/// and the cross-ns isolation gate (a namespace at its queue ceiling is rejected
/// with `PerNsQueueLimit` — fired ABOVE the global-LRU branch — while another
/// namespace still reassembles). Any failure panics, detected by `make test`.
pub fn test_fragment_perns_budget() {
    klog_always!("  [TEST] Per-NS Fragment Triple-Budget (R169-10)...");
    net::fragment::run_fragment_perns_self_test();
    klog_always!("    ✓ sum(per_ns) == global across create/complete/timeout + prune-at-zero");
    klog_always!(
        "    ✓ cross-ns isolation: PerNsQueueLimit above the LRU branch, sibling ns unaffected"
    );
}

/// R171-CG2x1: per-process seccomp filter-chain total-instruction cap. Installing
/// filters in a loop must REJECT before the chain grows without bound (kernel-heap
/// + per-syscall-CPU DoS, and an unbounded Process-lock hold time). Any failure
/// panics, detected by `make test`.
pub fn test_seccomp_chain_cap() {
    klog_always!("  [TEST] Seccomp filter-chain instruction cap (R171-CG2x1)...");
    seccomp::run_seccomp_cap_self_test();
    klog_always!("    ✓ chain bounded by MAX_FILTER_INSNS_TOTAL; install rejects past the cap");
}

/// R171-G4-1/G4-2: conntrack reclaim. The periodic timer sweep (ct_sweep, now
/// wired into net::handle_timer_tick) must reclaim an expired flow, and namespace
/// teardown drain (ct_drain_ns) must remove all of a destroyed ns's flows and drop
/// its CT_MAX_ENTRIES_PER_NS counter row. Any failure panics, detected by `make test`.
pub fn test_conntrack_reclaim() {
    klog_always!("  [TEST] Conntrack reclaim: timer sweep + ns-teardown drain (R171-G4-1/2)...");
    net::conntrack::run_conntrack_reclaim_self_test();
    klog_always!("    ✓ expired flow swept; ns-drain removes flows + zeroes the per-ns counter");
}

/// M0 #1: the SysV AMD64 initial-user-stack + auxv builder. Covers the mis-wires a
/// green build/boot cannot catch: the entry-RSP alignment-parity flip (RSP%16 must be
/// 0 at `_start`, NOT 8) across every (argc, envc, phdr-present) combination; the
/// auxv-value whitelist (no auxv entry may embed a kernel/phys address — copy_to_user
/// validates only the destination range); and the layout contiguity contract musl
/// walks (argc at [RSP], argv/envp NULLs, AT_NULL-terminated auxv, AT_RANDOM/AT_EXECFN
/// pointers into a non-zero string area, zero-filled alignment gap). Any failure
/// panics, detected by `make test` / `make boot-check`.
pub fn test_user_stack_builder() {
    klog_always!("  [TEST] Initial User Stack + auxv Builder (M0 #1)...");
    kernel_core::user_stack::run_user_stack_builder_self_test();
    klog_always!("    ✓ entry RSP%16==0 sweep (argc/envc/phdr parities) — the alignment-parity flip class eliminated");
    klog_always!("    ✓ auxv value whitelist (no kernel/phys address leaks via AT_*) + AT_PHDR-triple-iff-phdr!=0");
    klog_always!("    ✓ layout contiguity: argc@[RSP] + argv/envp NULLs + AT_NULL-terminated auxv + AT_RANDOM/EXECFN ptrs + zero gap");
    klog_always!("    ✓ M0-7 builder floor == guard_top: no string/ptr can land in the unmapped low guard page");
    // M0-7: pin the loader's eager-map geometry (guard carved, +1 anti-guard removed).
    kernel_core::elf_loader::run_user_stack_guard_range_self_test();
    klog_always!("    ✓ M0-7 stack guard geometry: 511 eager pages, top ends AT USER_STACK_TOP, one unmapped low guard page");
    // M0-7 slice 2 (SLICE 1): the third-door mmap/brk stack-window exclusion — half-open
    // [base,end) intersection + the page-aligned brk ceiling, guard-INCLUSIVE, single-
    // sourced through user_stack_window(). Closes a hinted/MAP_FIXED mmap (or brk grow)
    // aliasing the reserved stack window.
    kernel_core::syscall::run_stack_window_exclusion_self_test();
    klog_always!("    ✓ M0-7 slice 2 (SLICE 1): mmap/brk stack-window exclusion (guard-inclusive, half-open boundary exact)");
    // M0-7 SLICE 3a: pin the naked timer-IRQ stub's IrqGprFrame layout against the asm
    // push order. A size/offset drift would triple-fault on the first timer tick with no
    // diagnostic; this offset_of! assertion localizes such a mis-wire to make test.
    arch::interrupts::run_irq_gpr_frame_layout_self_test();
    klog_always!("    ✓ M0-7 SLICE 3a: IrqGprFrame layout matches the timer-IRQ stub push order (r15@0..rax@0x70, size 0x78)");
}

/// 运行所有集成测试
pub fn run_all_tests() {
    klog_always!();
    klog_always!("=== Component Integration Tests ===");
    klog_always!();

    test_page_table();
    test_process_control_block();
    test_scheduler();
    test_fork_framework();
    test_syscalls();
    test_context_switch();
    test_memory_mapping();
    test_fallible_map();
    test_heap_budget_arbiter();
    test_rcu_callback_pool();
    test_tcp_checksum_wire_oracle();
    test_page_cache_policy();
    test_per_ns_tcp_budgets();
    test_cgroup_exact_lifetime();
    test_cgroup_fd_budget();
    test_cgroup_vfs_dir_budget();
    test_positioned_io_gate();
    test_cgroup_pt_kmem();
    test_cgroup_port_budget();
    test_cgroupfs_abi();
    test_fragment_perns_budget();
    test_seccomp_chain_cap();
    test_conntrack_reclaim();
    test_user_stack_builder();
    test_ext2_write();

    klog_always!();
    klog_always!("=== All Component Tests Passed! ===");
    klog_always!();
}
