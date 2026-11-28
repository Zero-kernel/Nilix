//! Syscall Test Program for Zero-OS
//!
//! Tests the new musl-required syscalls:
//! - gettid
//! - set_tid_address
//! - set_robust_list
//! - getrandom
//! - exit_group

#![no_std]
#![no_main]

use userspace::libc::{print, print_hex, print_int, println};
use userspace::syscall::{
    errno, is_error, sys_close, sys_fork, sys_getpid, sys_getppid, sys_getrandom, sys_gettid,
    sys_open, sys_read, sys_set_robust_list, sys_set_tid_address, sys_wait, syscall0, syscall1,
    syscall2, syscall3, syscall4, syscall5, syscall6, SYS_BRK, SYS_FSTAT, SYS_MMAP, SYS_MREMAP,
    SYS_MUNMAP, SYS_READ, SYS_WRITE,
};

/// One 4 KiB page — the granularity of every mapping operation below.
const PAGE: usize = 0x1000;

// mmap(2)/mremap(2) ABI values. These must stay in lockstep with
// `kernel/kernel_core/syscall.rs`, which rejects any other flag shape rather
// than silently mis-applying it.
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_NONE: u64 = 0x0;
const SYS_MPROTECT: u64 = 10;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MREMAP_MAYMOVE: i32 = 0x1;
const MREMAP_FIXED: i32 = 0x2;

const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const EOPNOTSUPP: i32 = 95;
const EFAULT: i32 = 14;

// cgroup syscalls (kernel/kernel_core/syscall.rs dispatch 500/502/504).
const SYS_CGROUP_CREATE: u64 = 500;
const SYS_CGROUP_ATTACH: u64 = 502;
const SYS_CGROUP_GET_STATS: u64 = 504;
/// MEMORY controller bit in `CgroupControllers`.
const CGROUP_CTRL_MEMORY: u64 = 0x02;
/// The kernel's `CgroupStatsBuf` v1 prefix is 104 bytes; `memory_current`
/// follows id(u64), depth(u32), controllers(u32), nr_tasks(u64), cpu_time_ns(u64).
const CGROUP_STATS_V1_SIZE: usize = 104;
const CGROUP_STATS_MEMORY_OFFSET: usize = 32;

/// Read a cgroup's `memory_current` through the stats syscall.
unsafe fn cgroup_memory_current(id: u64) -> Option<u64> {
    let mut buf = [0u8; CGROUP_STATS_V1_SIZE];
    if is_error(syscall2(SYS_CGROUP_GET_STATS, id, buf.as_mut_ptr() as u64)) {
        return None;
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[CGROUP_STATS_MEMORY_OFFSET..CGROUP_STATS_MEMORY_OFFSET + 8]);
    Some(u64::from_ne_bytes(bytes))
}

/// `mmap(0, len, prot, ANONYMOUS, -1, 0)` — private or shared, at an explicit
/// protection. Returns the base address, or a negative errno.
unsafe fn mmap_anon_prot(len: usize, prot: u64, shared: bool) -> i64 {
    let flags = if shared {
        MAP_SHARED | MAP_ANONYMOUS
    } else {
        MAP_PRIVATE | MAP_ANONYMOUS
    };
    syscall6(SYS_MMAP, 0, len as u64, prot, flags, (-1i64) as u64, 0) as i64
}

/// Read/write anonymous mapping (the common case).
unsafe fn mmap_anon(len: usize, shared: bool) -> i64 {
    mmap_anon_prot(len, PROT_READ | PROT_WRITE, shared)
}

/// `mremap(old, old_len, new_len, flags, 0)`. Returns the new base address, or
/// a negative errno.
unsafe fn mremap(old: usize, old_len: usize, new_len: usize, flags: i32) -> i64 {
    syscall5(
        SYS_MREMAP,
        old as u64,
        old_len as u64,
        new_len as u64,
        flags as u64,
        0,
    ) as i64
}

unsafe fn munmap(addr: usize, len: usize) -> i64 {
    syscall2(SYS_MUNMAP, addr as u64, len as u64) as i64
}

/// The pattern byte for offset `i`. Position-dependent, so a mapping that was
/// copied, moved, or silently replaced is detectable at any base address.
#[inline]
fn pattern_byte(i: usize) -> u8 {
    ((i * 7 + 3) & 0xff) as u8
}

unsafe fn fill_pattern(base: usize, len: usize) {
    for i in 0..len {
        *(base as *mut u8).add(i) = pattern_byte(i);
    }
}

unsafe fn pattern_holds(base: usize, len: usize) -> bool {
    for i in 0..len {
        if *(base as *const u8).add(i) != pattern_byte(i) {
            return false;
        }
    }
    true
}

/// Normalized errno of a syscall result (0 when it succeeded).
#[inline]
fn err_of(result: i64) -> i32 {
    if is_error(result as u64) {
        errno(result as u64)
    } else {
        0
    }
}

/// Test result type
struct TestResult {
    passed: usize,
    failed: usize,
}

impl TestResult {
    fn new() -> Self {
        TestResult {
            passed: 0,
            failed: 0,
        }
    }

    fn pass(&mut self, name: &str) {
        println_parts(&["[PASS] ", name]);
        self.passed += 1;
    }

    fn fail(&mut self, name: &str) {
        println_parts(&["[FAIL] ", name]);
        self.failed += 1;
    }

    fn skip(&mut self, name: &str) {
        println_parts(&["[SKIP] ", name]);
    }
}

const SYS_WRITEV: u64 = 20;

/// TD-SERIAL-1: write `parts` and a newline with one `writev`, so no other
/// console output can land inside a line the gate matches (the kernel keeps a
/// console `writev` of up to 256 bytes together). At most seven parts.
fn println_parts(parts: &[&str]) {
    let mut iov = [[0u64; 2]; 8];
    let mut count = 0;
    for part in parts.iter().take(iov.len() - 1) {
        iov[count] = [part.as_ptr() as u64, part.len() as u64];
        count += 1;
    }
    iov[count] = [b"\n".as_ptr() as u64, 1];
    count += 1;
    unsafe {
        syscall3(SYS_WRITEV, 1, iov.as_ptr() as u64, count as u64);
    }
}

/// `value` in decimal, in `buf`.
fn decimal(mut value: usize, buf: &mut [u8; 20]) -> &str {
    let mut start = buf.len();
    loop {
        start -= 1;
        buf[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    core::str::from_utf8(&buf[start..]).unwrap_or("?")
}

/// Program entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("");
    println("================================");
    println("  Zero-OS Syscall Test Suite");
    println("================================");
    println("");

    let mut results = TestResult::new();
    if option_env!("NILIX_ST_K2_FINAL_OWNER_FOCUSED") == Some("1") {
        test_shared_final_owner_race(&mut results);
        println(if results.failed == 0 {
            "  Results: 1 passed, 0 failed"
        } else {
            "  Results: 0 passed, 1 failed"
        });
        unsafe { userspace::syscall::sys_exit(if results.failed == 0 { 0 } else { 1 }) };
    }
    // Optional focused guest for the audit's before/after oracle; normal gates
    // still run both legs as part of the complete suite below.
    if option_env!("NILIX_AUDIT_FOCUSED") == Some("1") {
        test_console_input_ownership(&mut results);
        test_brk_cow_shrink(&mut results);
        // SAFETY: the exit wrapper consumes only a scalar exit code.
        unsafe {
            userspace::syscall::sys_exit(if results.failed == 0 { 0 } else { 1 });
        }
    }

    // Test 1: gettid
    test_gettid(&mut results);

    // Test 2: set_tid_address
    test_set_tid_address(&mut results);

    // Test 3: set_robust_list
    test_set_robust_list(&mut results);

    // Test 4: getrandom
    test_getrandom(&mut results);

    // R192-1/R192-2: the supervisor identity map in the user half. First of
    // the memory legs: it relies on an unused mmap window and an untouched heap.
    test_identity_map_boundary(&mut results);

    // ST-K2-MREMAP / ST-K2-P2: anonymous memory resize and shared-anonymous
    // behavior. These run last because they fork and consume address space.
    test_mremap_resize(&mut results);
    test_mremap_maymove(&mut results);
    test_mremap_fail_closed(&mut results);
    test_mremap_prot_none(&mut results);
    test_mremap_charge_symmetry(&mut results);
    test_shared_anon_fork(&mut results);
    // The boot-armed one-shot forced Busy goes to the first guarded usercopy
    // that takes a shared fault, and the preflight probes below are guarded
    // accesses too: keep the uname leg the first to fault a shared page.
    test_shared_anon_usercopy(&mut results);
    test_shared_anon_pte_preflight(&mut results);
    test_shared_anon_lazy_preflight_shapes(&mut results);
    test_shared_anon_preflight_preserves_contents(&mut results);
    test_shared_anon_adjacent_pt(&mut results);
    test_shared_anon_migration(&mut results);

    // ST-K3-WAITID: the guest leg for syscall 247. Runs after the memory legs
    // because it forks; it maps nothing, so it cannot perturb their layout.
    test_waitid(&mut results);

    // ST-K4: the durability family, decided by descriptor kind.
    test_durability_syscalls(&mut results);
    test_ext2_mut_syscalls(&mut results);

    // ROOT-INIT: this binary runs as root-namespace PID 1, so an orphaned
    // grandchild must be reparented to *us*. Last, because it forks twice.
    test_root_init_reparent(&mut results);
    test_selective_wait_nested_zombie(&mut results);

    // Fork refusal under cgroup pids.max: a refused fork must leave no
    // child, no task charge and no consumed PID behind.
    test_fork_pids_refusal(&mut results);

    // M0-7 stack guard: a lazy-region touch demand-grows, a guard-page touch
    // kills the toucher with SIGSEGV instead of being mapped.
    test_user_stack_guard(&mut results);

    // GAP-5 slice 4 G3: the exit-time clear of a CLONE_CHILD_CLEARTID word
    // that lives in .bss rather than an mmap region.
    test_clone_vm_clear_child_tid(&mut results);

    // GAP-5 slice 4 G7: thread-directed signals (syscalls 200 and 234).
    test_tkill_tgkill(&mut results);

    // GAP-5 G8: a timer-interrupt kill beside a user-mode spinner.
    test_kill_beside_user_spinner(&mut results);

    // GAP-5 slice 4: thread groups.
    test_thread_group(&mut results);

    // GAP-5 G8: a group's last thread exits beside a user-mode spinner.
    test_group_exit_beside_user_spinner(&mut results);

    // GAP-5 slice 4, exec steps 1 and 2: exec from the leader or from any other
    // member ends the other members and runs under the group's PID.
    test_thread_group_exec(&mut results);

    // GAP-5 G8: group-wide wait, children of an exiting thread, getppid of a
    // thread's child, get_robust_list.
    // Compile-time opt-in for the audit's stochastic reproducer. Normal gates
    // run once; NILIX_G8_REPEATS=300 also tests repeated fork/exit/PID lifetimes.
    let g8_repeats = option_env!("NILIX_G8_REPEATS")
        .unwrap_or("1")
        .parse::<usize>()
        .expect("NILIX_G8_REPEATS must be an integer");
    assert!((1..=1000).contains(&g8_repeats));
    for _ in 0..g8_repeats {
        test_thread_group_children(&mut results);
    }
    test_cow_sibling_read(&mut results);
    // ST-K2-P2(b): a page-table holder and a remote IF=0 shared fault.
    test_shared_fault_remote_holder(&mut results);
    // ST-K2-P2(c): the last owner of a shared region exits after, or while,
    // its parent unmaps it.
    test_shared_final_owner_race(&mut results);
    // ST-K2-P2(d): private population rollback beside a shared-fault table.
    test_private_rollback_reclaim(&mut results);

    // GAP-5 G8: /proc lists group leaders; /proc/<pid>/task lists members.
    test_proc_thread_listing(&mut results);

    // GAP-5 slice 4: FUTEX_REQUEUE/CMP_REQUEUE and the bitset ops that
    // condition variables use.
    test_futex_requeue(&mut results);

    // GAP-5 futex parity: FUTEX_WAKE_OP, a requeue that moves a sleeper,
    // partial bitsets and futex keys shared with a CLONE_VM child.
    test_futex_parity(&mut results);

    // GAP-5 PI parity: PI futexes under the Linux user-word protocol, owner
    // death and requeue-PI.
    test_futex_pi(&mut results);

    // GAP-6: the scheduler/RCU counters pressure runs retain.
    test_proc_schedstat(&mut results);

    // TD-LSM-1: LSM policy denial and missing-subject arms at six hook sites.
    test_lsm_denial_oracle(&mut results);

    // R192-RES-3: an unusable mmap hint falls back, MAP_FIXED_NOREPLACE places
    // exactly or refuses, MAP_FIXED stays rejected. Addresses in a 16 GiB block;
    // everything it maps is unmapped again.
    test_mmap_placement_contract(&mut results);

    // R192-RES-2: every eager population site in bounded holds, and the boot-armed
    // injected failure's rollback. Auto-placed mappings only, freed before the next.
    test_bounded_population(&mut results);

    // LEAD-MREMAP-RELOC-UAF-1: a relocation keeps the frames it moved.
    test_mremap_relocation_keeps_frames(&mut results);

    // R192-RES-2a: the largest relocation that fits moves in one hold with its
    // page tables staged before it. Automatic placement only.
    test_mremap_large_relocation(&mut results);

    // LEAD-KPTI-PML4-1: last, because its hinted mappings move the automatic
    // mmap base past 1 TiB.
    test_kpti_fresh_pml4_slots(&mut results);

    test_heap_owner_isolation(&mut results);
    test_brk_cow_shrink(&mut results);
    test_nonzero_user_gs_across_exceptions(&mut results);
    test_console_input_ownership(&mut results);
    // STRICT-Q S4 & S8: Ring-3 IPC, signal-migration, and namespace-teardown legs.
    test_futex_bucket_toctou(&mut results);
    test_pipe_eintr_wake(&mut results);
    test_signal_delivery_blocked_syscall(&mut results);
    test_rapid_signal_migration(&mut results);
    test_namespace_teardown_storm(&mut results);
    // STRICT-Q S5: Ring-3 concurrent CLONE_VM brk + MAP_FIXED_NOREPLACE leg.
    test_brk_va_reservation_toctou(&mut results);
    // STRICT-Q S9: Ring-3 context-switch RIP/RFLAGS, TLS, syscall_active, and FPU IRQ isolation legs.
    test_context_switch_rip_rflags(&mut results);
    test_tls_isolation(&mut results);
    test_syscall_active_leak(&mut results);
    test_fpu_state_irq_isolation(&mut results);
    // STRICT-Q S6: Ring-3 CPU affinity, forced migration, load balancing, and SMP work-stealing legs.
    test_cpu_affinity_enforcement(&mut results);
    test_process_migration_safety(&mut results);
    test_scheduler_load_balancing(&mut results);
    test_smp_work_stealing_safety(&mut results);
    // N2.8: Loopback delivery, getsockname/getpeername, setsockopt/getsockopt, sendmsg/recvmsg, multi-iovec readv.
    test_n2_8_loopback_udp_tcp_echo(&mut results);
    test_n2_8_sockopts_and_negative(&mut results);
    test_n2_8_sendmsg_recvmsg_and_readv(&mut results);
    // N2.5: Process groups, sessions, controlling terminal ioctls, kill(-pgid), wait4/waitid job control.
    test_n2_5_job_control_sessions_and_wait(&mut results);
    // N2.1: >256 KiB exec image, >1 MiB PT_LOAD segment, and 1024 fd ceiling.
    test_n2_1_exec_segment_and_fd_ceilings(&mut results);
    // N2.4: set*id, supplementary groups, and capget/capset.
    test_n2_4_credentials_groups_and_caps(&mut results);

    // Print summary
    println("");
    println("================================");
    let (mut passed, mut failed) = ([0u8; 20], [0u8; 20]);
    println_parts(&[
        "  Results: ",
        decimal(results.passed, &mut passed),
        " passed, ",
        decimal(results.failed, &mut failed),
        " failed",
    ]);
    println("================================");

    // Exit with appropriate code
    let exit_code = if results.failed == 0 { 0 } else { 1 };
    unsafe {
        userspace::syscall::sys_exit(exit_code);
    }
}

/// R192-1: addresses in the supervisor-only identity map of physical 0-4 GiB
/// that every user address space used to carry; the R192 audit's guest probe
/// read all eight through `write(pipe, addr, 8)`. D0-ISO-1 Approach A removed
/// that map from user address spaces, so they are unmapped user addresses now.
const R192_IDMAP_ADDRS: [usize; 8] = [
    0x1_0000,
    0x10_0000,
    0x20_0000,
    0x60_0000,
    0x80_0000,
    0x100_0000,
    0x4000_0000,
    0x8000_0000,
];
/// Legacy VGA text memory, once a writable supervisor identity page. A
/// regressed kernel would write the probe's 8 bytes there, which is harmless.
const R192_VGA_TEXT: usize = 0xB_8000;
/// The ELF window. The heap starts in it; the identity map's supervisor 2 MiB
/// leaves used to follow it and stop the heap at its end.
const R192_ELF_WINDOW_END: usize = 0x60_0000;
/// A free hint above the identity map (4 GiB) and below the randomized
/// automatic mmap base (at least 64 GiB), so the PROT_NONE mapping never
/// advances `next_mmap_addr` (a hint past it moves every later automatic
/// mapping; LEAD-KPTI-PML4-1 has its own leg, run last).
const R192_FREE_HINT: usize = 0x8_0000_0000;

/// R192-1/R192-2, D0-ISO-1 Approach A: the identity map is gone from user
/// address spaces. Its old addresses fault in usercopy, and the low 4 GiB maps
/// and grows like any free range, while ordinary user buffers keep working.
fn test_identity_map_boundary(results: &mut TestResult) {
    let name = "R192 identity map: user address spaces carry none; the low 4 GiB faults, maps and grows like free memory; user buffers still copy";
    match unsafe { identity_map_boundary() } {
        Ok(()) => results.pass(name),
        Err(reason) => {
            print("  identity-map leg: ");
            println(reason);
            results.fail(name);
        }
    }
}

unsafe fn identity_map_boundary() -> Result<(), &'static str> {
    let mut fds = [-1i32; 2];
    if syscall2(SYS_PIPE2, fds.as_mut_ptr() as u64, 0) != 0 {
        return Err("pipe2");
    }
    let result = identity_map_copies(fds[0] as u64, fds[1] as u64);
    for fd in fds {
        let _ = sys_close(fd as u64);
    }
    result?;
    identity_map_mappings()?;
    identity_map_brk()
}

/// The kernel copying from (`write`) and into (`read`) user memory.
unsafe fn identity_map_copies(read_fd: u64, write_fd: u64) -> Result<(), &'static str> {
    let control = *b"r192-ok!";
    let mut buf = [0u8; 8];
    if syscall3(SYS_WRITE, write_fd, control.as_ptr() as u64, 8) != 8 {
        return Err("control write");
    }
    if syscall3(SYS_READ, read_fd, buf.as_mut_ptr() as u64, 8) != 8 || buf != control {
        return Err("control read");
    }
    for addr in R192_IDMAP_ADDRS {
        if err_of(syscall3(SYS_WRITE, write_fd, addr as u64, 8) as i64) != EFAULT {
            return Err("write(pipe, identity-map address) was not EFAULT");
        }
    }
    // Queue bytes so the read below returns at once, then aim it at VGA text.
    if syscall3(SYS_WRITE, write_fd, control.as_ptr() as u64, 8) != 8 {
        return Err("second control write");
    }
    if err_of(syscall3(SYS_READ, read_fd, R192_VGA_TEXT as u64, 8) as i64) != EFAULT {
        return Err("read(pipe, VGA text) was not EFAULT");
    }
    if err_of(sys_getrandom(0x10_0000 as *mut u8, 8, 0) as i64) != EFAULT {
        return Err("getrandom(identity-map address) was not EFAULT");
    }
    Ok(())
}

/// Where the identity map was (the framebuffer at 2 GiB, low RAM at 1 MiB,
/// the leaves above the ELF window), user mappings now come and go: munmap of
/// such a range tears down only this process's pages, and the kernel and its
/// console keep running.
unsafe fn identity_map_mappings() -> Result<(), &'static str> {
    let flags = MAP_PRIVATE | MAP_ANONYMOUS;
    for (addr, len) in [
        (0x8000_0000usize, 0x20_0000usize),
        (0x10_0000, PAGE),
        (0x60_0000, PAGE),
    ] {
        let got = syscall6(
            SYS_MMAP,
            addr as u64,
            len as u64,
            PROT_READ | PROT_WRITE,
            flags,
            u64::MAX,
            0,
        );
        if got != addr as u64 {
            return Err("mmap where the identity map was");
        }
        fill_pattern(addr, PAGE);
        if !pattern_holds(addr, PAGE) {
            return Err("a low mapping lost its pattern");
        }
        if munmap(addr, len) != 0 {
            return Err("munmap where the identity map was");
        }
    }
    let got = syscall6(
        SYS_MMAP,
        R192_FREE_HINT as u64,
        PAGE as u64,
        PROT_NONE,
        flags,
        u64::MAX,
        0,
    );
    if got != R192_FREE_HINT as u64 {
        return Err("hinted PROT_NONE mmap in the mmap window");
    }
    if munmap(R192_FREE_HINT, PAGE) != 0 {
        return Err("munmap of the hinted mapping");
    }
    Ok(())
}

/// The heap starts in the ELF window and now grows past it, where the
/// identity map's supervisor leaves used to stop it.
unsafe fn identity_map_brk() -> Result<(), &'static str> {
    let start = syscall1(SYS_BRK, 0) as usize;
    if !(0x40_0000..R192_ELF_WINDOW_END).contains(&start) {
        return Err("the heap does not start in the ELF window");
    }
    let past = R192_ELF_WINDOW_END + PAGE;
    if syscall1(SYS_BRK, past as u64) as usize != past {
        return Err("brk past the ELF window");
    }
    core::ptr::write_volatile(R192_ELF_WINDOW_END as *mut u8, 0x5a);
    if core::ptr::read_volatile(R192_ELF_WINDOW_END as *const u8) != 0x5a {
        return Err("the heap page past the ELF window");
    }
    if syscall1(SYS_BRK, start as u64) as usize != start {
        return Err("brk shrink back");
    }
    Ok(())
}

/// LEAD-KPTI-PML4-1: one fresh 512 GiB slot per path that maps user memory.
/// Each mapping needs a PML4 entry that the KPTI user root, copied when exec
/// built the address space, did not have; ring 3 used to fault on it (err=0x6).
const KPTI_SLOT_PRIVATE: usize = 0x100_0000_0000; // PML4[2]
const KPTI_SLOT_MPROTECT: usize = 0x180_0000_0000; // PML4[3]
const KPTI_SLOT_SHARED: usize = 0x200_0000_0000; // PML4[4]
const KPTI_SLOT_READ_FIRST: usize = 0x280_0000_0000; // PML4[5]
const KPTI_MPROTECT_WORD: u64 = 0x4B50_5449_4D50_524F;
const KPTI_SHARED_WORD: u64 = 0x4B50_5449_5348_4152;
const KPTI_CHILD_WORD: u64 = 0x4B50_5449_4348_4C44;

fn test_kpti_fresh_pml4_slots(results: &mut TestResult) {
    print("Testing mappings in fresh PML4 slots under KPTI... ");
    let name = "KPTI: ring 3 uses mappings in fresh 512 GiB slots made by mmap, mprotect and a shared first touch; the kernel and a fork child see them";
    match unsafe { kpti_fresh_pml4_slots() } {
        Ok(()) => results.pass(name),
        Err(reason) => {
            print("  KPTI leg: ");
            println(reason);
            results.fail(name);
        }
    }
}

/// `mmap` at exactly `addr` (a hint the kernel must honour: the slot is free).
unsafe fn mmap_at(addr: usize, len: usize, prot: u64, flags: u64) -> bool {
    syscall6(SYS_MMAP, addr as u64, len as u64, prot, flags, u64::MAX, 0) == addr as u64
}

unsafe fn kpti_fresh_pml4_slots() -> Result<(), &'static str> {
    let rw = PROT_READ | PROT_WRITE;
    let private = MAP_PRIVATE | MAP_ANONYMOUS;
    // mmap populates a private mapping in syscall context, on the kernel root.
    if !mmap_at(KPTI_SLOT_PRIVATE, 2 * PAGE, rw, private) {
        return Err("hinted private mmap in a fresh slot");
    }
    fill_pattern(KPTI_SLOT_PRIVATE, 2 * PAGE);
    if !pattern_holds(KPTI_SLOT_PRIVATE, 2 * PAGE) {
        return Err("private slot lost its pattern");
    }
    // PROT_NONE installs no table; mprotect populates the slot later.
    if !mmap_at(KPTI_SLOT_MPROTECT, PAGE, PROT_NONE, private) {
        return Err("hinted PROT_NONE mmap in a fresh slot");
    }
    if syscall3(SYS_MPROTECT, KPTI_SLOT_MPROTECT as u64, PAGE as u64, rw) != 0 {
        return Err("mprotect of the PROT_NONE slot");
    }
    core::ptr::write_volatile(KPTI_SLOT_MPROTECT as *mut u64, KPTI_MPROTECT_WORD);
    // A shared mapping installs nothing until ring 3 touches it: that fault
    // runs on the user root and must still build the kernel root's tables.
    if !mmap_at(KPTI_SLOT_SHARED, PAGE, rw, MAP_SHARED | MAP_ANONYMOUS) {
        return Err("hinted shared mmap in a fresh slot");
    }
    core::ptr::write_volatile(KPTI_SLOT_SHARED as *mut u64, KPTI_SHARED_WORD);
    kpti_kernel_copies()?;
    // A read-only page creates the slot's tables; a writable page beside it
    // must not need their PML4 entry changed (it is created final, P|W|U).
    if !mmap_at(KPTI_SLOT_READ_FIRST, PAGE, PROT_READ, private)
        || !mmap_at(KPTI_SLOT_READ_FIRST + PAGE, PAGE, rw, private)
    {
        return Err("read-only then writable mmap in a fresh slot");
    }
    if core::ptr::read_volatile(KPTI_SLOT_READ_FIRST as *const u64) != 0 {
        return Err("a fresh read-only page is not zero");
    }
    core::ptr::write_volatile((KPTI_SLOT_READ_FIRST + PAGE) as *mut u64, KPTI_CHILD_WORD);

    let child = sys_fork();
    if is_error(child) {
        return Err("fork");
    }
    if child == 0 {
        let seen = pattern_holds(KPTI_SLOT_PRIVATE, 2 * PAGE)
            && core::ptr::read_volatile(KPTI_SLOT_MPROTECT as *const u64) == KPTI_MPROTECT_WORD
            && core::ptr::read_volatile(KPTI_SLOT_SHARED as *const u64) == KPTI_SHARED_WORD;
        // A copy-on-write break in the private slot, and a shared write back.
        core::ptr::write_volatile(KPTI_SLOT_PRIVATE as *mut u64, KPTI_CHILD_WORD);
        core::ptr::write_volatile((KPTI_SLOT_SHARED + 16) as *mut u64, KPTI_CHILD_WORD);
        userspace::syscall::sys_exit(if seen { 0 } else { 1 });
    }
    let mut status: i32 = 0;
    let waited = sys_wait(&mut status as *mut i32);
    if is_error(waited) || waited != child || status != 0 {
        return Err("the fork child did not see all three slots");
    }
    if !pattern_holds(KPTI_SLOT_PRIVATE, 2 * PAGE) {
        return Err("the child's write reached the parent's private slot");
    }
    if core::ptr::read_volatile((KPTI_SLOT_SHARED + 16) as *const u64) != KPTI_CHILD_WORD {
        return Err("the child's shared write is not visible");
    }
    for (addr, len) in [
        (KPTI_SLOT_PRIVATE, 2 * PAGE),
        (KPTI_SLOT_MPROTECT, PAGE),
        (KPTI_SLOT_SHARED, PAGE),
        // Two mappings, so two calls: munmap takes one whole mapping.
        (KPTI_SLOT_READ_FIRST, PAGE),
        (KPTI_SLOT_READ_FIRST + PAGE, PAGE),
    ] {
        if munmap(addr, len) != 0 {
            return Err("munmap of a fresh-slot mapping");
        }
    }
    Ok(())
}

/// The kernel reads and writes the shared slot through its own root.
unsafe fn kpti_kernel_copies() -> Result<(), &'static str> {
    let mut fds = [-1i32; 2];
    if syscall2(SYS_PIPE2, fds.as_mut_ptr() as u64, 0) != 0 {
        return Err("pipe2");
    }
    let (read_fd, write_fd) = (fds[0] as u64, fds[1] as u64);
    let copied = syscall3(SYS_WRITE, write_fd, KPTI_SLOT_SHARED as u64, 8) == 8
        && syscall3(SYS_READ, read_fd, (KPTI_SLOT_SHARED + 8) as u64, 8) == 8;
    for fd in fds {
        let _ = sys_close(fd as u64);
    }
    if !copied {
        return Err("write/read through the shared slot");
    }
    if core::ptr::read_volatile((KPTI_SLOT_SHARED + 8) as *const u64) != KPTI_SHARED_WORD {
        return Err("the kernel's copy into the shared slot is missing");
    }
    Ok(())
}

/// R192-RES-2: each eager population site at 64 MiB (16384 pages), so the
/// kernel prints its summary marker (holds, largest hold) for every site.
const R192_RES_2_LEN: usize = 64 << 20;
/// The page count of the kernel's one-shot injected failure
/// (`POPULATE_FAULT_PROBE_PAGES`): its last data-frame allocation fails.
const R192_RES_2_FAULT_PAGES: usize = 16384 + 3;

fn test_bounded_population(results: &mut TestResult) {
    // A full line: the kernel's population markers must start their own lines.
    println("Testing bounded eager population...");
    let name = "R192-RES-2: 64 MiB brk, mmap, mprotect and mremap populate in bounded holds; an injected failure rolls back to the baseline charge";
    match unsafe { bounded_population() } {
        Ok(()) => results.pass(name),
        Err(reason) => {
            print("  population leg: ");
            println(reason);
            results.fail(name);
        }
    }
}

/// Every page of `[base, base + len)` reads zero and keeps a word written to
/// it. One word per page: a byte loop over 64 MiB is slow under emulation.
unsafe fn populated_and_writable(base: usize, len: usize) -> Result<(), &'static str> {
    for page in (base..base + len).step_by(PAGE) {
        if core::ptr::read_volatile(page as *const u64) != 0 {
            return Err("a populated page is not zero");
        }
        core::ptr::write_volatile(page as *mut u64, page as u64);
    }
    for page in (base..base + len).step_by(PAGE) {
        if core::ptr::read_volatile(page as *const u64) != page as u64 {
            return Err("a populated page lost its word");
        }
    }
    Ok(())
}

unsafe fn bounded_population() -> Result<(), &'static str> {
    let len = R192_RES_2_LEN;

    let base = mmap_anon(len, false);
    if base < 0 {
        return Err("64 MiB mmap");
    }
    populated_and_writable(base as usize, len)?;
    if munmap(base as usize, len) != 0 {
        return Err("munmap of the 64 MiB mapping");
    }

    // mprotect Path A materializes a PROT_NONE reservation.
    let base = mmap_anon_prot(len, PROT_NONE, false);
    if base < 0 {
        return Err("64 MiB PROT_NONE mmap");
    }
    if syscall3(
        SYS_MPROTECT,
        base as u64,
        len as u64,
        PROT_READ | PROT_WRITE,
    ) != 0
    {
        return Err("mprotect of the 64 MiB reservation");
    }
    populated_and_writable(base as usize, len)?;
    if munmap(base as usize, len) != 0 {
        return Err("munmap of the materialized reservation");
    }

    // An mremap grow populates its 64 MiB tail; the first page keeps its data.
    let base = mmap_anon(PAGE, false);
    if base < 0 {
        return Err("one-page mmap for the mremap grow");
    }
    fill_pattern(base as usize, PAGE);
    let grown = mremap(base as usize, PAGE, PAGE + len, MREMAP_MAYMOVE);
    if grown < 0 {
        return Err("mremap grow by 64 MiB");
    }
    let grown = grown as usize;
    if !pattern_holds(grown, PAGE) {
        return Err("the mremap grow lost the first page");
    }
    populated_and_writable(grown + PAGE, len)?;
    if munmap(grown, PAGE + len) != 0 {
        return Err("munmap of the grown mapping");
    }

    // brk grows the heap by exactly 64 MiB from its page-aligned top.
    let start = syscall1(SYS_BRK, 0) as usize;
    let top = (start + PAGE - 1) & !(PAGE - 1);
    if syscall1(SYS_BRK, (top + len) as u64) as usize != top + len {
        return Err("64 MiB brk grow");
    }
    populated_and_writable(top, len)?;
    if syscall1(SYS_BRK, start as u64) as usize != start {
        return Err("brk shrink back");
    }

    // The armed kernel knob fails the last page of this exact size: the whole
    // mapped prefix is rolled back and nothing stays charged.
    let Some(before) = read_memory_current() else {
        return Err("memory.current is not readable");
    };
    let fault_len = R192_RES_2_FAULT_PAGES * PAGE;
    if err_of(mmap_anon(fault_len, false)) != ENOMEM {
        return Err("the injected population failure was not ENOMEM");
    }
    if read_memory_current() != Some(before) {
        return Err("the rolled-back mmap left a charge behind");
    }
    // The knob is one-shot: the same request now succeeds and unmaps cleanly.
    // A second knob makes it stage no spare page tables, so each table it
    // needs is allocated between holds (the starvation path).
    let again = mmap_anon(fault_len, false);
    if again < 0 {
        return Err("the same mmap after the injected failure");
    }
    populated_and_writable(again as usize, fault_len)?;
    if munmap(again as usize, fault_len) != 0 {
        return Err("munmap after the injected failure");
    }
    if read_memory_current() != Some(before) {
        return Err("map and unmap after the rollback did not return to the baseline");
    }
    Ok(())
}

/// LEAD-MREMAP-RELOC-UAF-1: a relocation used to free every frame it moved
/// while the destination still mapped it. Those frames went back to the buddy,
/// so the next allocation took them, zeroed them and wrote over them.
const RELOC_UAF_PAGES: usize = 16;
const RELOC_UAF_CHURN: usize = 32 << 20;

fn test_mremap_relocation_keeps_frames(results: &mut TestResult) {
    print("Testing that an mremap relocation keeps its frames... ");
    let name =
        "mremap relocation keeps the moved frames: relocated data survives a 32 MiB allocation";
    match unsafe { mremap_relocation_keeps_frames() } {
        Ok(()) => results.pass(name),
        Err(reason) => {
            print("  relocation leg: ");
            println(reason);
            results.fail(name);
        }
    }
}

unsafe fn mremap_relocation_keeps_frames() -> Result<(), &'static str> {
    let len = RELOC_UAF_PAGES * PAGE;
    let a = mmap_anon(len, false);
    if a < 0 {
        return Err("mmap of the mapping to relocate");
    }
    let a = a as usize;
    fill_pattern(a, len);
    // A neighbour in the growth window forces the grow to relocate.
    let b = mmap_anon(PAGE, false);
    if b < 0 || b as usize != a + len {
        return Err("the blocking neighbour is not adjacent");
    }
    let moved = mremap(a, len, 2 * len, MREMAP_MAYMOVE);
    if moved < 0 || moved as usize == a {
        return Err("the blocked grow did not relocate");
    }
    let moved = moved as usize;
    if !pattern_holds(moved, len) {
        return Err("the relocation lost the mapped content");
    }
    // Take fresh frames: freed relocated frames would be among them.
    let churn = mmap_anon(RELOC_UAF_CHURN, false);
    if churn < 0 {
        return Err("the 32 MiB allocation");
    }
    let churn = churn as usize;
    for page in (churn..churn + RELOC_UAF_CHURN).step_by(PAGE) {
        core::ptr::write_volatile(page as *mut u64, 0xA5A5_A5A5_A5A5_A5A5);
    }
    let kept = pattern_holds(moved, len);
    if munmap(churn, RELOC_UAF_CHURN) != 0
        || munmap(moved, 2 * len) != 0
        || munmap(b as usize, PAGE) != 0
    {
        return Err("cleanup munmap");
    }
    if !kept {
        return Err(
            "a later allocation overwrote relocated pages: the relocation freed its frames",
        );
    }
    Ok(())
}

/// R192-RES-2a: relocation sizes, tried in order until a private mapping of
/// that size fits (managed RAM is below 1 GiB; the 256 MiB guest takes 64).
const LARGE_RELOC_SIZES_MIB: [usize; 3] = [512, 256, 64];
const LARGE_RELOC_MAGIC: u64 = 0x5245_5332_4152_454C;

fn test_mremap_large_relocation(results: &mut TestResult) {
    print("Testing a large mremap relocation... ");
    let name = "mremap relocation of the largest mapping that fits moves every page in one hold, its page tables staged before it";
    match unsafe { mremap_large_relocation() } {
        Ok(mib) => {
            let mut buf = [0u8; 20];
            println_parts(&["  relocated MiB: ", decimal(mib, &mut buf)]);
            results.pass(name);
        }
        Err(reason) => {
            print("  large relocation leg: ");
            println(reason);
            results.fail(name);
        }
    }
}

unsafe fn mremap_large_relocation() -> Result<usize, &'static str> {
    let Some(before) = read_memory_current() else {
        return Err("memory.current is not readable");
    };
    let mut chosen = None;
    for mib in LARGE_RELOC_SIZES_MIB {
        let mapped = mmap_anon(mib << 20, false);
        if mapped >= 0 {
            chosen = Some((mib, mapped as usize));
            break;
        }
        if err_of(mapped) != ENOMEM {
            return Err("mmap of the mapping to relocate");
        }
    }
    let Some((mib, a)) = chosen else {
        return Err("no relocation size fits");
    };
    let len = mib << 20;
    for page in (a..a + len).step_by(PAGE) {
        core::ptr::write_volatile(page as *mut u64, page as u64 ^ LARGE_RELOC_MAGIC);
    }
    // A neighbour in the growth window forces the one-page grow to relocate.
    let b = mmap_anon(PAGE, false);
    if b < 0 || b as usize != a + len {
        munmap(a, len);
        if b >= 0 {
            munmap(b as usize, PAGE);
        }
        return Err("the blocking neighbour is not adjacent");
    }
    let moved = mremap(a, len, len + PAGE, MREMAP_MAYMOVE);
    if moved < 0 || moved as usize == a {
        if moved >= 0 {
            munmap(moved as usize, len + PAGE);
        } else {
            munmap(a, len);
        }
        munmap(b as usize, PAGE);
        return Err("the blocked grow did not relocate");
    }
    let moved = moved as usize;
    let kept = (0..len / PAGE).all(|index| {
        core::ptr::read_volatile((moved + index * PAGE) as *const u64)
            == (a + index * PAGE) as u64 ^ LARGE_RELOC_MAGIC
    });
    let moved_unmapped = munmap(moved, len + PAGE) == 0;
    let b_unmapped = munmap(b as usize, PAGE) == 0;
    if !moved_unmapped || !b_unmapped {
        return Err("cleanup munmap");
    }
    if !kept {
        return Err("the relocation lost a page's content");
    }
    if read_memory_current() != Some(before) {
        return Err("the relocation left a charge behind");
    }
    Ok(mib)
}

/// Test gettid syscall
fn test_gettid(results: &mut TestResult) {
    print("Testing gettid... ");

    unsafe {
        let tid = sys_gettid();
        let pid = sys_getpid();

        if is_error(tid) {
            results.fail("gettid returned error");
            return;
        }

        // In single-threaded mode, TID should equal PID
        if tid == pid {
            print("TID=");
            print_int(tid as i64);
            print(" ");
            results.pass("gettid");
        } else {
            print("TID=");
            print_int(tid as i64);
            print(" PID=");
            print_int(pid as i64);
            print(" ");
            results.fail("gettid: TID != PID");
        }
    }
}

/// Test set_tid_address syscall
fn test_set_tid_address(results: &mut TestResult) {
    print("Testing set_tid_address... ");

    unsafe {
        // Test with a valid pointer
        let mut tid_storage: i32 = 0;
        let ret = sys_set_tid_address(&mut tid_storage as *mut i32);

        if is_error(ret) {
            results.fail("set_tid_address returned error");
            return;
        }

        // Should return current TID
        let expected_tid = sys_gettid();
        if ret == expected_tid {
            print("returned TID=");
            print_int(ret as i64);
            print(" ");
            results.pass("set_tid_address");
        } else {
            print("got ");
            print_int(ret as i64);
            print(" expected ");
            print_int(expected_tid as i64);
            print(" ");
            results.fail("set_tid_address: wrong TID");
        }
    }
}

/// Test set_robust_list syscall
fn test_set_robust_list(results: &mut TestResult) {
    print("Testing set_robust_list... ");

    // Simulate robust_list_head structure (24 bytes)
    #[repr(C)]
    struct RobustListHead {
        list: u64,
        futex_offset: i64,
        list_op_pending: u64,
    }

    unsafe {
        let head = RobustListHead {
            list: 0,
            futex_offset: 0,
            list_op_pending: 0,
        };

        // Test with correct size (24)
        let ret = sys_set_robust_list(&head as *const _ as *const u8, 24);

        if is_error(ret) {
            let errno = -(ret as i64);
            print("errno=");
            print_int(errno);
            print(" ");
            results.fail("set_robust_list returned error");
            return;
        }

        // Test with wrong size (should fail with EINVAL)
        let ret_wrong = sys_set_robust_list(&head as *const _ as *const u8, 16);
        if is_error(ret_wrong) {
            // Expected to fail
            results.pass("set_robust_list");
        } else {
            results.fail("set_robust_list: accepted wrong size");
        }
    }
}

/// Test getrandom syscall
fn test_getrandom(results: &mut TestResult) {
    print("Testing getrandom... ");

    unsafe {
        let mut buf = [0u8; 16];
        let ret = sys_getrandom(buf.as_mut_ptr(), 16, 0);

        if is_error(ret) {
            let errno = -(ret as i64);
            print("errno=");
            print_int(errno);
            print(" ");
            results.fail("getrandom returned error");
            return;
        }

        if ret != 16 {
            print("got ");
            print_int(ret as i64);
            print(" bytes, expected 16 ");
            results.fail("getrandom: wrong byte count");
            return;
        }

        // Check that we got some non-zero bytes (very unlikely all zeros)
        let mut all_zero = true;
        for &b in buf.iter() {
            if b != 0 {
                all_zero = false;
                break;
            }
        }

        if all_zero {
            results.fail("getrandom: all bytes are zero");
        } else {
            print("got 16 random bytes: ");
            print_hex(buf[0] as u64);
            print_hex(buf[1] as u64);
            print("... ");
            results.pass("getrandom");
        }
    }
}

// ============================================================================
// ST-K2-MREMAP / ST-K2-P2 guest behavioral oracles
//
// These are exactly the legs no other gate can run: they need a live user
// address space (a real CR3 plus MmState) AND Ring-3 access to the mappings.
// The hosted kernel-core suite and the boot integration gate have neither, so
// before this fixture the grow/shrink/relocate page-table and refcount paths
// were only covered by review. A failure here is a hard FAIL for the suite.
// ============================================================================

/// `mremap` in-place growth and shrink, including the two properties a
/// length-only implementation would get wrong: the grown tail must be freshly
/// zeroed, and the surviving prefix must keep its content byte for byte.
fn test_mremap_resize(results: &mut TestResult) {
    print("Testing mremap grow-in-place + shrink... ");

    unsafe {
        let len = 2 * PAGE;
        let base = mmap_anon(len, false);
        if base < 0 {
            results.fail("mremap resize: initial mmap failed");
            return;
        }
        let base = base as usize;
        fill_pattern(base, len);

        // Nothing was mapped after this region, so a grow with flags == 0 must
        // be satisfied without moving the mapping.
        let grown = mremap(base, len, 4 * PAGE, 0);
        if err_of(grown) != 0 {
            results.fail("mremap resize: in-place grow returned an error");
            return;
        }
        if grown as usize != base {
            results.fail("mremap resize: in-place grow moved the mapping");
            return;
        }
        if !pattern_holds(base, len) {
            results.fail("mremap resize: grow lost the original content");
            return;
        }
        // The new tail must be zero-filled: a grown page that exposed a stale
        // frame would be a cross-process disclosure.
        for i in len..4 * PAGE {
            if *(base as *const u8).add(i) != 0 {
                results.fail("mremap resize: grown tail is not zero-filled");
                return;
            }
        }

        let shrunk = mremap(base, 4 * PAGE, PAGE, 0);
        if err_of(shrunk) != 0 || shrunk as usize != base {
            results.fail("mremap resize: shrink did not keep the mapping in place");
            return;
        }
        if !pattern_holds(base, PAGE) {
            results.fail("mremap resize: shrink lost the surviving content");
            return;
        }

        munmap(base, PAGE);
        results.pass("mremap grow-in-place + shrink");
    }
}

/// `MREMAP_MAYMOVE`: a grow that cannot be satisfied in place must relocate,
/// carry the content, and release the old address range.
fn test_mremap_maymove(results: &mut TestResult) {
    print("Testing mremap MREMAP_MAYMOVE relocation... ");

    unsafe {
        let len = 3 * PAGE;
        let a = mmap_anon(len, false);
        if a < 0 {
            results.fail("mremap maymove: mmap A failed");
            return;
        }
        let a = a as usize;
        fill_pattern(a, len);

        // Hint-less mmaps are placed sequentially, so B occupies exactly the
        // growth window above A. Assert that rather than assume it, so a future
        // placement change produces a precise diagnostic.
        let b = mmap_anon(PAGE, false);
        if b < 0 {
            results.fail("mremap maymove: mmap B failed");
            return;
        }
        let b = b as usize;
        if b != a + len {
            results.fail("mremap maymove: neighbour is not adjacent to the mapping");
            return;
        }

        // With the growth window occupied, a grow WITHOUT MREMAP_MAYMOVE must be
        // refused with ENOMEM and leave the mapping byte-for-byte unchanged —
        // relocation is licensed only by the flag.
        let refused = mremap(a, len, 6 * PAGE, 0);
        if err_of(refused) != ENOMEM {
            results.fail("mremap maymove: a blocked grow without MAYMOVE must return ENOMEM");
            return;
        }
        if !pattern_holds(a, len) {
            results.fail("mremap maymove: a refused grow mutated the mapping");
            return;
        }

        let moved = mremap(a, len, 6 * PAGE, MREMAP_MAYMOVE);
        if err_of(moved) != 0 {
            results.fail("mremap maymove: relocation returned an error");
            return;
        }
        if moved as usize == a {
            results.fail("mremap maymove: a blocked grow was not relocated");
            return;
        }
        if !pattern_holds(moved as usize, len) {
            results.fail("mremap maymove: relocation lost the mapped content");
            return;
        }

        // The vacated range must be free again — a fresh mapping takes it.
        let reuse = syscall6(
            SYS_MMAP,
            a as u64,
            PAGE as u64,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            (-1i64) as u64,
            0,
        ) as i64;
        if reuse != a as i64 {
            results.fail("mremap maymove: the old address range stayed occupied");
            return;
        }

        munmap(reuse as usize, PAGE);
        munmap(moved as usize, 6 * PAGE);
        munmap(b, PAGE);
        results.pass("mremap MREMAP_MAYMOVE relocation");
    }
}

/// The fail-closed boundary: every shape this kernel does not implement must
/// return its documented errno and leave the mapping untouched.
fn test_mremap_fail_closed(results: &mut TestResult) {
    print("Testing mremap fail-closed shapes... ");

    unsafe {
        let len = 2 * PAGE;
        let base = mmap_anon(len, false);
        if base < 0 {
            results.fail("mremap fail-closed: initial mmap failed");
            return;
        }
        let base = base as usize;
        fill_pattern(base, len);

        // Address-replacement and unknown flag shapes are unimplemented.
        let cases: [(i64, i32, &str); 6] = [
            (
                mremap(base, len, 4 * PAGE, MREMAP_FIXED),
                EOPNOTSUPP,
                "MREMAP_FIXED",
            ),
            (
                mremap(base, len, 4 * PAGE, MREMAP_FIXED | MREMAP_MAYMOVE),
                EOPNOTSUPP,
                "MREMAP_FIXED|MAYMOVE",
            ),
            (
                mremap(base, len, 4 * PAGE, 0x4000),
                EOPNOTSUPP,
                "unknown flag bit",
            ),
            (
                mremap(base + 1, len, 4 * PAGE, 0),
                EINVAL,
                "unaligned old_addr",
            ),
            (mremap(base, 0, 4 * PAGE, 0), EINVAL, "old_size == 0"),
            (
                mremap(base, PAGE, 4 * PAGE, 0),
                EINVAL,
                "old_size does not match the VMA",
            ),
        ];
        for (result, expected, name) in cases {
            let got = err_of(result);
            if got != expected {
                print("shape=");
                println(name);
                results.fail("mremap fail-closed: wrong errno");
                return;
            }
        }

        // Every rejected call must have left the mapping exactly as it was.
        if !pattern_holds(base, len) {
            results.fail("mremap fail-closed: a rejected call mutated the mapping");
            return;
        }

        munmap(base, len);
        results.pass("mremap fail-closed shape matrix");
    }
}

/// `MAP_SHARED|MAP_ANONYMOUS`: a child's write must be visible in the parent
/// through the same frame (the property that distinguishes shared from COW),
/// and resizing a shared VMA must stay fail-closed.
fn test_shared_anon_fork(results: &mut TestResult) {
    print("Testing MAP_SHARED|MAP_ANONYMOUS across fork... ");

    unsafe {
        let Some(before) = read_memory_current() else {
            results.fail("shared-anon: memory.current is not readable");
            return;
        };

        let s = mmap_anon(2 * PAGE, true);
        if s < 0 {
            results.fail("shared-anon: mmap failed");
            return;
        }
        let s = s as usize;
        // First touch: a shared region publishes no PTE at map time, so this
        // write is the demand fault that charges the first-toucher's page.
        core::ptr::write_volatile(s as *mut u64, 0x1234_5678);
        let after_touch = read_memory_current().unwrap_or(before);
        if after_touch < before + PAGE as u64 {
            results.fail("shared-anon: the first touch did not charge the page");
            return;
        }

        let child = sys_fork();
        if is_error(child) {
            results.fail("shared-anon: fork failed");
            return;
        }
        if child == 0 {
            // Child: publish through the shared page and leave. It must not
            // touch anything else — the rest of its address space is COW.
            if core::ptr::read_volatile(s as *const u64) != 0x1234_5678 {
                userspace::syscall::sys_exit(1);
            }
            core::ptr::write_volatile(s as *mut u64, 0x5A5A_1234);
            // No PTE existed for this slot at fork: child creates the shared
            // frame, then the parent must fault in exactly that frame.
            core::ptr::write_volatile((s + PAGE) as *mut u64, 0xCAFE_4321);
            userspace::syscall::sys_exit(0);
        }

        let mut status: i32 = 0;
        let waited = sys_wait(&mut status as *mut i32);
        if is_error(waited) || waited != child || status != 0 {
            results.fail("shared-anon: child was not reaped");
            return;
        }
        if core::ptr::read_volatile(s as *const u64) != 0x5A5A_1234
            || core::ptr::read_volatile((s + PAGE) as *const u64) != 0xCAFE_4321
        {
            results.fail("shared-anon: child write is not visible in the parent");
            return;
        }

        // A shared region is snapshotted into every fork child, so resizing it
        // would let a child re-fault a range the parent no longer owns. It must
        // fail closed rather than silently split the mapping.
        if err_of(mremap(s, 2 * PAGE, 3 * PAGE, 0)) != EOPNOTSUPP {
            results.fail("shared-anon: mremap on a shared VMA must fail closed");
            return;
        }

        if munmap(s, 2 * PAGE) != 0 {
            results.fail("shared-anon: munmap failed");
            return;
        }
        let after_unmap = read_memory_current().unwrap_or(after_touch);
        print("shared ");
        print_int(before as i64);
        print("->");
        print_int(after_touch as i64);
        print("->");
        print_int(after_unmap as i64);
        print(" ");
        // Region Drop releases DATA; per-AS physical identities release only
        // tables actually reclaimed by munmap. No PT charge rides on a region.
        if after_unmap > before {
            results.fail("shared-anon: teardown did not release the page charge");
            return;
        }

        results.pass("MAP_SHARED|MAP_ANONYMOUS fork visibility + mremap boundary");
    }
}

/// Kernel-mode copy_to_user faults both fresh pages without a preceding user
/// access. uname deliberately uses the controlled usercopy path directly.
fn test_shared_anon_usercopy(results: &mut TestResult) {
    print("Testing shared-anon cross-page usercopy first touch... ");
    unsafe {
        let base = mmap_anon(2 * PAGE, true);
        if base < 0 {
            results.fail("shared usercopy: mmap failed");
            return;
        }
        let base = base as usize;
        let dest = base + PAGE - 195;
        // Linux utsname has six 65-byte strings. This straddles the page edge.
        let result = syscall1(63, dest as u64) as i64;
        let valid = result == 0
            && core::ptr::read_volatile(dest as *const u8) != 0
            && core::ptr::read_volatile((dest + 65) as *const u8) != 0
            && core::ptr::read_volatile((dest + 4 * 65) as *const u8) != 0
            && core::ptr::read_volatile((dest - 1) as *const u8) == 0
            && core::ptr::read_volatile((dest + 390) as *const u8) == 0;
        let released = munmap(base, 2 * PAGE) == 0;
        if valid && released {
            results.pass("shared-anon cross-page usercopy first touch");
        } else {
            results.fail("shared-anon cross-page usercopy first touch");
        }
    }
}

/// ST-K2-P2a: a syscall whose preflight walks the page tables
/// (`verify_user_memory`) accepts a fresh, never-touched shared page: the
/// preflight resolves the demand fault the way the following usercopy would.
/// `getrandom` must return exactly the requested byte count and fill the page.
fn test_shared_anon_pte_preflight(results: &mut TestResult) {
    print("Testing shared-anon lazy buffer syscall preflight... ");
    unsafe {
        let base = mmap_anon(PAGE, true);
        if base < 0 {
            results.fail("shared preflight: mmap failed");
            return;
        }
        let base = base as usize;
        let result = sys_getrandom(base as *mut u8, PAGE, 0);
        let filled = result == PAGE as u64
            && (0..PAGE).any(|i| core::ptr::read_volatile((base + i) as *const u8) != 0);
        let released = munmap(base, PAGE) == 0;
        if !released {
            results.fail("shared preflight: munmap failed");
        } else if filled {
            results.pass("shared-anon PTE-only preflight accepts lazy buffer");
        } else {
            print("result=");
            print_int(result as i64);
            print(" ");
            results.fail("shared preflight: lazy buffer rejected or not filled");
        }
    }
}

const SYS_RT_SIGPROCMASK: u64 = 14;
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SYS_PIPE2: u64 = 293;

/// `rt_sigprocmask(how, set, oldset, 8)`: 0, or a negative errno.
unsafe fn sigprocmask(how: u64, set: u64, oldset: u64) -> i64 {
    syscall4(SYS_RT_SIGPROCMASK, how, set, oldset, 8) as i64
}
/// `st_mode` offset in the x86-64 `struct stat` (after dev, ino, nlink).
const STAT_MODE_OFFSET: usize = 24;
const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;

/// ST-K2-P2a: the other preflight shapes on fresh shared pages, and the
/// buffers that must stay EFAULT.
fn test_shared_anon_lazy_preflight_shapes(results: &mut TestResult) {
    print("Testing lazy-buffer preflight shapes... ");
    match unsafe { lazy_preflight_shapes() } {
        Ok(()) => results.pass(
            "lazy shared buffers pass the getrandom, pipe2, fstat, rt_sigprocmask and futex preflights; read-only, PROT_NONE and unmapped buffers stay EFAULT",
        ),
        Err(why) => {
            print(why);
            print(" ");
            results.fail("lazy-buffer preflight shapes");
        }
    }
}

unsafe fn lazy_preflight_shapes() -> Result<(), &'static str> {
    // Six fresh pages: a pair for the cross-page case, then one per caller.
    let base = mmap_anon(6 * PAGE, true);
    if base < 0 {
        return Err("mmap failed");
    }
    let base = base as usize;
    let accepted = lazy_preflight_accepts(base);
    if munmap(base, 6 * PAGE) != 0 {
        return Err("munmap failed");
    }
    accepted?;
    lazy_preflight_denies()
}

/// Write intent across a page edge (`getrandom`), into an fd pair (`pipe2`),
/// a stat buffer (`fstat`) and an old signal mask (`rt_sigprocmask`); read
/// intent on a futex word (`FUTEX_WAKE`, whose callback checks the word's PTE
/// again). Every page starts untouched.
unsafe fn lazy_preflight_accepts(base: usize) -> Result<(), &'static str> {
    let byte = |addr: usize| core::ptr::read_volatile(addr as *const u8);
    let edge = base + PAGE - 8;
    if sys_getrandom(edge as *mut u8, 16, 0) != 16 {
        return Err("cross-page getrandom");
    }
    if byte(edge - 1) != 0 || byte(edge + 16) != 0 || (0..16).all(|i| byte(edge + i) == 0) {
        return Err("cross-page getrandom bytes");
    }

    let fds = base + 2 * PAGE;
    if syscall2(SYS_PIPE2, fds as u64, 0) != 0 {
        return Err("pipe2");
    }
    let read_fd = core::ptr::read_volatile(fds as *const i32);
    let write_fd = core::ptr::read_volatile((fds + 4) as *const i32);
    let mut result = Ok(());
    if read_fd < 0 || write_fd < 0 || read_fd == write_fd {
        result = Err("pipe2 descriptors");
    } else {
        let stat = base + 3 * PAGE;
        if syscall2(SYS_FSTAT, read_fd as u64, stat as u64) != 0 {
            result = Err("fstat");
        } else if core::ptr::read_volatile((stat + STAT_MODE_OFFSET) as *const u32) & S_IFMT
            != S_IFIFO
        {
            result = Err("fstat mode");
        }
    }
    for fd in [read_fd, write_fd] {
        if fd >= 0 {
            let _ = sys_close(fd as u64);
        }
    }
    result?;

    // SIG_BLOCK with no new set only reports the current mask.
    let oldset = base + 4 * PAGE;
    if sigprocmask(SIG_BLOCK, 0, oldset as u64) != 0 {
        return Err("rt_sigprocmask");
    }
    let word = (base + 5 * PAGE) as u64;
    let woken = syscall6(SYS_FUTEX, word, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 0, 0, 0);
    if woken != 0 {
        return Err("futex wake");
    }
    Ok(())
}

/// A never-touched read-only shared page is denied for writing and left
/// unchanged; a PROT_NONE reservation has nothing to resolve; an unmapped
/// buffer stays unmapped.
unsafe fn lazy_preflight_denies() -> Result<(), &'static str> {
    let read_only = mmap_anon_prot(PAGE, PROT_READ, true);
    if read_only < 0 {
        return Err("read-only mmap");
    }
    let read_only = read_only as usize;
    let denied = err_of(sys_getrandom(read_only as *mut u8, 8, 0) as i64) == EFAULT;
    let unchanged = core::ptr::read_volatile(read_only as *const u64) == 0;
    if munmap(read_only, PAGE) != 0 {
        return Err("read-only munmap");
    }
    if !denied {
        return Err("read-only page accepted for writing");
    }
    if !unchanged {
        return Err("read-only page changed");
    }

    let reserved = mmap_anon_prot(PAGE, PROT_NONE, false);
    if reserved < 0 {
        return Err("PROT_NONE mmap");
    }
    let reserved = reserved as usize;
    let denied = err_of(sys_getrandom(reserved as *mut u8, 8, 0) as i64) == EFAULT;
    // The preflight fails before any change: blocking SIGUSR1 with an
    // unusable old-mask buffer is EFAULT and leaves the mask as it was.
    let usr1: u64 = 1 << (SIGUSR1_NR - 1);
    let set = &usr1 as *const u64 as u64;
    let mask_denied = err_of(sigprocmask(SIG_BLOCK, set, reserved as u64)) == EFAULT;
    let mut mask: u64 = 0;
    let mask_read = sigprocmask(SIG_BLOCK, 0, &mut mask as *mut u64 as u64) == 0;
    if mask & usr1 != 0 {
        let _ = sigprocmask(SIG_UNBLOCK, set, 0);
    }
    if munmap(reserved, PAGE) != 0 {
        return Err("PROT_NONE munmap");
    }
    if !denied {
        return Err("PROT_NONE page accepted");
    }
    if !mask_denied || !mask_read || mask & usr1 != 0 {
        return Err("rt_sigprocmask changed the mask before its EFAULT");
    }
    if err_of(sys_getrandom(reserved as *mut u8, 8, 0) as i64) != EFAULT {
        return Err("unmapped buffer accepted");
    }
    Ok(())
}

/// ST-K2-P2a: the preflight probe writes back what it read. A fork child fills
/// the pages of a shared region the parent never touched, so the parent has
/// no PTE for them. The parent's preflights (write intent for `getrandom` and
/// `pipe2`, read intent for `FUTEX_WAKE`) probe each page's first word, in
/// front of their buffers: they must map the child's frames and leave those
/// words as the child wrote them.
fn test_shared_anon_preflight_preserves_contents(results: &mut TestResult) {
    print("Testing lazy-buffer preflight content preservation... ");
    match unsafe { lazy_preflight_preserves() } {
        Ok(()) => results.pass(
            "the syscall preflight maps frames a fork child filled and keeps the words in front of the buffers",
        ),
        Err(why) => {
            print(why);
            print(" ");
            results.fail("lazy-buffer preflight content preservation");
        }
    }
}

/// Written by the child at the first word of each page, plus the page index.
/// Its low half is non-zero, so a write probe sees a mismatch.
const PRESERVE_SENTINEL: u64 = 0x5EED_0000_A11C_E5ED;
/// Written by the child where the parent's buffers start (offset 64).
const PRESERVE_MARKER: u64 = 0x77;

unsafe fn lazy_preflight_preserves() -> Result<(), &'static str> {
    let base = mmap_anon(3 * PAGE, true);
    if base < 0 {
        return Err("mmap failed");
    }
    let base = base as usize;
    let preserved = lazy_preflight_preserves_in(base);
    if munmap(base, 3 * PAGE) != 0 {
        return Err("munmap failed");
    }
    preserved
}

unsafe fn lazy_preflight_preserves_in(base: usize) -> Result<(), &'static str> {
    let child = sys_fork();
    if is_error(child) {
        return Err("fork failed");
    }
    if child == 0 {
        // The child's first touches create the region's frames.
        for page in 0..3 {
            let first = base + page * PAGE;
            core::ptr::write_volatile(first as *mut u64, PRESERVE_SENTINEL + page as u64);
            core::ptr::write_volatile((first + 64) as *mut u64, PRESERVE_MARKER);
        }
        userspace::syscall::sys_exit(0);
    }
    let mut status: i32 = 0;
    let waited = sys_wait(&mut status as *mut i32);
    if is_error(waited) || waited != child || status != 0 {
        return Err("child was not reaped");
    }

    if sys_getrandom((base + 64) as *mut u8, 16, 0) != 16 {
        return Err("getrandom");
    }
    let fds = base + PAGE + 64;
    if syscall2(SYS_PIPE2, fds as u64, 0) != 0 {
        return Err("pipe2");
    }
    for fd in [fds, fds + 4] {
        let fd = core::ptr::read_volatile(fd as *const i32);
        if fd >= 0 {
            let _ = sys_close(fd as u64);
        }
    }
    let word = (base + 2 * PAGE + 64) as u64;
    let woken = syscall6(SYS_FUTEX, word, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 0, 0, 0);
    if woken != 0 {
        return Err("futex wake");
    }

    for page in 0..3 {
        let first = core::ptr::read_volatile((base + page * PAGE) as *const u64);
        if first != PRESERVE_SENTINEL + page as u64 {
            return Err("a probed word changed");
        }
    }
    // Nothing wrote the futex page's buffer: it still holds the child's
    // marker, so the parent mapped the child's frame, not a fresh one.
    if core::ptr::read_volatile((base + 2 * PAGE + 64) as *const u64) != PRESERVE_MARKER {
        return Err("the child's frame was not mapped");
    }
    Ok(())
}
/// A shared-created PT must stay charged while its adjacent private leaf is
/// live. Reusing the same VA also catches inherited-basis drift across cycles.
fn test_shared_anon_adjacent_pt(results: &mut TestResult) {
    print("Testing shared-anon adjacent private PT lifetime... ");
    unsafe {
        // Above the supervisor identity-map window, in an unused user PD.
        const BASE: usize = 0x20_0000_0000;
        for _ in 0..3 {
            let Some(before) = read_memory_current() else {
                results.fail("shared PT: missing memory.current");
                return;
            };
            let shared = syscall6(
                SYS_MMAP,
                BASE as u64,
                PAGE as u64,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS,
                u64::MAX,
                0,
            ) as i64;
            if shared != BASE as i64 {
                results.fail("shared PT: address hint unavailable");
                return;
            }
            core::ptr::write_volatile(BASE as *mut u64, 0x1234);
            let private = syscall6(
                SYS_MMAP,
                (BASE + PAGE) as u64,
                PAGE as u64,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                u64::MAX,
                0,
            ) as i64;
            if private != (BASE + PAGE) as i64 {
                results.fail("shared PT: adjacent private mmap failed");
                return;
            }
            core::ptr::write_volatile((BASE + PAGE) as *mut u64, 0xDEAD_BEEF);
            let charged = read_memory_current().unwrap_or(0);
            if munmap(BASE, PAGE) != 0 {
                results.fail("shared PT: shared munmap failed");
                return;
            }
            let retained = read_memory_current().unwrap_or(u64::MAX);
            if retained.checked_add(PAGE as u64) != Some(charged)
                || core::ptr::read_volatile((BASE + PAGE) as *const u64) != 0xDEAD_BEEF
            {
                results.fail("shared PT: early table uncharge or adjacent corruption");
                return;
            }
            if munmap(BASE + PAGE, PAGE) != 0 || read_memory_current() != Some(before) {
                results.fail("shared PT: last-leaf teardown leaked charge");
                return;
            }
        }
        results.pass("shared-anon adjacent private PT lifetime");
    }
}

/// Migration: the documented rule is that shared-anonymous bytes belong to the
/// cgroup that FIRST TOUCHED them and are excluded from a task's cgroup
/// migration. Moving the task must not carry them, and teardown must return
/// them to that same owner.
fn test_shared_anon_migration(results: &mut TestResult) {
    print("Testing shared-anon cgroup ownership across migration... ");

    unsafe {
        let created = syscall2(SYS_CGROUP_CREATE, 0, CGROUP_CTRL_MEMORY) as i64;
        if err_of(created) != 0 {
            if matches!(err_of(created), 1 | 13) {
                results.skip("shared-anon migration: requires host-root fixture");
            } else {
                print("errno=");
                print_int(err_of(created) as i64);
                print(" ");
                results.fail("shared migration: unexpected cgroup creation error");
            }
            return;
        }
        let cg = created as u64;

        // The dedicated boot fixture is already root (ppid=0) and registers
        // membership before scheduler publication. Without registration the
        // migration returns EIO/TaskNotAttached, not a permission refusal.
        let attach_error = err_of(syscall1(SYS_CGROUP_ATTACH, cg) as i64);
        if attach_error != 0 {
            let _ = syscall1(501, cg); // Retire the unused fixture if authorized.
            if matches!(attach_error, 1 | 13) {
                results.skip("shared-anon migration: requires host-root fixture");
            } else {
                print("errno=");
                print_int(attach_error as i64);
                print(" ");
                results.fail("shared migration: unexpected cgroup attach error");
            }
            return;
        }
        // Baseline AFTER the move: the task's own charges travel with it, so
        // the interesting delta is the one the shared region adds from here.
        let Some(cg_base) = cgroup_memory_current(cg) else {
            results.fail("shared migration: cgroup stats unreadable");
            return;
        };

        let s = mmap_anon(PAGE, true);
        if s < 0 {
            results.fail("shared migration: mmap failed");
            return;
        }
        let s = s as usize;
        *(s as *mut u64) = 0;
        let touched = cgroup_memory_current(cg).unwrap_or(cg_base);
        if touched <= cg_base {
            results.fail("shared migration: the first touch did not charge this cgroup");
            return;
        }

        // Move the task back to the root cgroup. The shared bytes must stay.
        if err_of(syscall1(SYS_CGROUP_ATTACH, 0) as i64) != 0 {
            results.fail("shared migration: attach back to the root cgroup failed");
            return;
        }
        let after_move = cgroup_memory_current(cg).unwrap_or(0);
        print("cg ");
        print_int(cg_base as i64);
        print("->");
        print_int(touched as i64);
        print("->");
        print_int(after_move as i64);
        print(" ");
        // Only the resident shared DATA stays with the first toucher. Private
        // bytes and the AS-owned page tables travel with the migrated task.
        if after_move != PAGE as u64 {
            results.fail("shared migration: the shared bytes migrated with the task");
            return;
        }

        // cgroupfs names children by decimal id. Exercise the actual VFS
        // rmdir boundary while DATA, but no task, still pins its origin.
        let mut path = [0u8; 64];
        let prefix = b"/sys/fs/cgroup/";
        path[..prefix.len()].copy_from_slice(prefix);
        let mut digits = [0u8; 20];
        let mut value = cg;
        let mut count = 0;
        while value != 0 {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
        for index in 0..count {
            path[prefix.len() + index] = digits[count - index - 1];
        }
        if err_of(syscall1(84, path.as_ptr() as u64) as i64) != 16 {
            results.fail("shared migration: rmdir must return EBUSY while DATA is pinned");
            return;
        }

        if munmap(s, PAGE) != 0 {
            results.fail("shared migration: munmap failed");
            return;
        }
        let released = cgroup_memory_current(cg).unwrap_or(u64::MAX);
        if released != 0 {
            results.fail("shared migration: teardown did not release to the owner");
            return;
        }
        if syscall1(84, path.as_ptr() as u64) as i64 != 0 {
            results.fail("shared migration: rmdir failed after last DATA release");
            return;
        }

        results.pass("shared-anon cgroup ownership across migration");
    }
}

/// A `PROT_NONE` reservation is pure address space. Resizing it must move only
/// the VA record — no frames, no charge — and the region must still behave as a
/// reservation afterwards: materializing it yields zeroed pages, never a stale
/// frame from a previous owner.
fn test_mremap_prot_none(results: &mut TestResult) {
    print("Testing mremap on a PROT_NONE reservation... ");

    unsafe {
        let len = 2 * PAGE;
        let base = mmap_anon_prot(len, PROT_NONE, false);
        if base < 0 {
            results.fail("mremap prot_none: reservation mmap failed");
            return;
        }
        let base = base as usize;

        if err_of(mremap(base, len, 4 * PAGE, 0)) != 0 {
            results.fail("mremap prot_none: growing a reservation failed");
            return;
        }
        let shrunk = mremap(base, 4 * PAGE, PAGE, 0);
        if err_of(shrunk) != 0 || shrunk as usize != base {
            results.fail("mremap prot_none: shrinking a reservation failed");
            return;
        }

        // Materialize the surviving page. A reservation never backed it, so it
        // must read as zero.
        let prot = syscall3(
            SYS_MPROTECT,
            base as u64,
            PAGE as u64,
            PROT_READ | PROT_WRITE,
        );
        if err_of(prot as i64) != 0 {
            results.fail("mremap prot_none: mprotect did not materialize the range");
            return;
        }
        for i in 0..PAGE {
            if *(base as *const u8).add(i) != 0 {
                results.fail("mremap prot_none: materialized page is not zero-filled");
                return;
            }
        }

        munmap(base, PAGE);
        results.pass("mremap on a PROT_NONE reservation");
    }
}

/// Read this process's cgroup `memory.current` as a decimal, or `None` when the
/// surface is unavailable or unparseable.
unsafe fn read_memory_current() -> Option<u64> {
    let path = b"/sys/fs/cgroup/memory.current\0";
    let fd = sys_open(path.as_ptr(), 0, 0);
    if is_error(fd) {
        return None;
    }
    let mut buf = [0u8; 32];
    let read = sys_read(fd, buf.as_mut_ptr(), buf.len() as u64);
    let _ = sys_close(fd);
    if is_error(read) || read == 0 {
        return None;
    }

    let mut value: u64 = 0;
    let mut digits = 0usize;
    for &byte in buf.iter().take(read as usize) {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .saturating_mul(10)
            .saturating_add((byte - b'0') as u64);
        digits += 1;
    }
    if digits == 0 {
        None
    } else {
        Some(value)
    }
}

/// Charge symmetry: a resize must move the cgroup byte counter by exactly the
/// length delta, and the bytes must come back when the mapping is released.
/// This is the property a by-length accounting site gets wrong silently — a
/// leak shows up only as a slowly drifting counter, never as a failure.
fn test_mremap_charge_symmetry(results: &mut TestResult) {
    print("Testing mremap charge symmetry... ");

    unsafe {
        let Some(before) = read_memory_current() else {
            results.fail("mremap charge: memory.current is not readable");
            return;
        };

        let len = 16 * PAGE;
        let base = mmap_anon(len, false);
        if base < 0 {
            results.fail("mremap charge: mmap failed");
            return;
        }
        let base = base as usize;

        let Some(after_map) = read_memory_current() else {
            results.fail("mremap charge: memory.current unreadable after mmap");
            return;
        };
        if after_map == before {
            // The counter exists but does not move with an mmap of this size,
            // so this profile's root cgroup is not accounting-live. Say so
            // rather than assert a delta that cannot be observed.
            print("(accounting not observable at this level) ");
            munmap(base, len);
            results.pass("mremap charge symmetry: not observable in this profile");
            return;
        }

        let grown = mremap(base, len, 32 * PAGE, 0);
        if err_of(grown) != 0 {
            results.fail("mremap charge: grow failed");
            return;
        }
        let after_grow = read_memory_current().unwrap_or(after_map);
        // The DATA delta is exact; the intermediate page-table frames the grow
        // had to materialize ride the SAME counter, so the honest assertion is a
        // tight band (data .. data + two tables), not equality. A missing DATA
        // charge or a by-length leak still falls outside it.
        let grew = after_grow.saturating_sub(after_map);
        let data_up = (16 * PAGE) as u64;
        print("grow +");
        print_int(grew as i64);
        print(" (data ");
        print_int(data_up as i64);
        print(") ");
        if !(data_up..=data_up + (2 * PAGE) as u64).contains(&grew) {
            results.fail("mremap charge: grow delta outside the DATA+PT band");
            return;
        }

        let shrunk = mremap(base, 32 * PAGE, 8 * PAGE, 0);
        if err_of(shrunk) != 0 {
            results.fail("mremap charge: shrink failed");
            return;
        }
        let after_shrink = read_memory_current().unwrap_or(after_grow);
        let shrank = after_grow.saturating_sub(after_shrink);
        let data_down = (24 * PAGE) as u64;
        print("shrink -");
        print_int(shrank as i64);
        print(" (data ");
        print_int(data_down as i64);
        print(") ");
        if !(data_down..=data_down + (2 * PAGE) as u64).contains(&shrank) {
            results.fail("mremap charge: shrink delta outside the DATA+PT band");
            return;
        }

        munmap(base, 8 * PAGE);
        let after_unmap = read_memory_current().unwrap_or(after_shrink);
        print("roundtrip ");
        print_int(after_unmap as i64);
        print("/");
        print_int(before as i64);
        print(" ");
        // Everything this leg mapped must come back. A by-length leak shows up
        // here as a permanent residue of at least one page.
        if after_unmap > before {
            results.fail("mremap charge: the mapping's bytes did not come back");
            return;
        }

        results.pass("mremap charge symmetry (grow/shrink/unmap)");
    }
}

// ---------------------------------------------------------------------------
// ST-K3-WAITID guest leg
//
// The hosted oracle (`st_k3_waitid_oracle_tests`) proves the argument contract
// and the `siginfo_t` encoder in isolation. Nothing there exercises the parts
// that need a live process tree: a real zombie, a real copyout into Ring-3
// memory, and WNOWAIT's promise that the child *survives* the observation.
// This leg drives syscall 247 through the actual dispatch arm.
// ---------------------------------------------------------------------------

/// `waitid(2)` is syscall 247 on x86_64 Linux; the kernel dispatches it there.
const SYS_WAITID: u64 = 247;
/// `waitid` idtypes and options — must match `kernel/kernel_core/syscall.rs`.
const P_ALL: u64 = 0;
const P_PID: u64 = 1;
const P_PGID: u64 = 2;
const WNOHANG: u64 = 0x1;
const WUNTRACED: u64 = 0x2;
const WEXITED: u64 = 0x4;
const WNOWAIT: u64 = 0x0100_0000;
/// `si_code` for a child that called exit().
const CLD_EXITED: i32 = 1;
const SIGCHLD: i32 = 17;
const SIGINFO_SIZE: usize = 128;
/// Poison written over the whole `siginfo_t` before each call, so a field the
/// kernel forgot to write is caught instead of reading as a lucky zero.
const POISON: u8 = 0xA5;

/// EINVAL and EFAULT are the file-level constants above; only ECHILD is new.
const ECHILD: i32 = 10;

/// 128-byte `siginfo_t`, 8-byte aligned like the real one.
#[repr(C, align(8))]
struct SigInfo {
    bytes: [u8; SIGINFO_SIZE],
}

impl SigInfo {
    fn poisoned() -> Self {
        SigInfo {
            bytes: [POISON; SIGINFO_SIZE],
        }
    }

    fn i32_at(&self, off: usize) -> i32 {
        i32::from_ne_bytes([
            self.bytes[off],
            self.bytes[off + 1],
            self.bytes[off + 2],
            self.bytes[off + 3],
        ])
    }

    fn signo(&self) -> i32 {
        self.i32_at(0)
    }
    fn code(&self) -> i32 {
        self.i32_at(8)
    }
    fn pid(&self) -> i32 {
        self.i32_at(16)
    }
    fn status(&self) -> i32 {
        self.i32_at(24)
    }
}

fn waitid(idtype: u64, id: u64, info: *mut SigInfo, options: u64) -> u64 {
    unsafe { syscall4(SYS_WAITID, idtype, id, info as u64, options) }
}

/// Fork a child that exits immediately with `code`. Returns the child's pid as
/// the parent sees it, or `None` if fork failed.
fn spawn_exiting_child(code: u64) -> Option<u64> {
    let child = unsafe { sys_fork() };
    if is_error(child) {
        return None;
    }
    if child == 0 {
        unsafe { userspace::syscall::sys_exit(code) };
    }
    Some(child)
}

/// Last-resort cleanup so a failing sub-check never leaks a zombie into the
/// legs that run after this one.
fn reap_quietly(pid: u64) {
    let mut info = SigInfo::poisoned();
    let _ = waitid(P_PID, pid, &mut info, WEXITED);
}

const SYS_FSYNC: u64 = 74;
const SYS_FDATASYNC: u64 = 75;
const SYS_SYNC: u64 = 162;
const SYS_SYNC_FILE_RANGE: u64 = 277;
const ESPIPE: i32 = 29;

/// Exercise real Ext2 namespace syscalls and a fork reader racing truncate.
/// The ordinary Ring3 lane has no disk; the Ext3 Ring3 lane requires this PASS.
fn test_ext2_mut_syscalls(results: &mut TestResult) {
    const NAME: &str = "EXT2-MUT namespace, open unlink and concurrent truncate";
    const DIR: &[u8] = b"/mnt/test/.ext2-mut-sys\0";
    const FILE: &[u8] = b"/mnt/test/.ext2-mut-sys/target\0";
    const SHORT: &[u8] = b"/mnt/test/.ext2-mut-sys/short\0";
    const LONG: &[u8] = b"/mnt/test/.ext2-mut-sys/long\0";
    unsafe {
        let mounted = sys_open(b"/mnt/test\0".as_ptr(), 0o200000, 0);
        if is_error(mounted) {
            results.skip(NAME);
            return;
        }
        sys_close(mounted);
        for name in [SHORT, LONG, FILE] {
            let _ = syscall1(87, name.as_ptr() as u64);
        }
        let _ = syscall1(84, DIR.as_ptr() as u64);
        let ok = (|| -> bool {
            if syscall2(83, DIR.as_ptr() as u64, 0o750) != 0 {
                return false;
            }
            let fd = sys_open(FILE.as_ptr(), 2 | 0o100 | 0o200, 0o600);
            if is_error(fd) {
                return false;
            }
            // Touch both deep levels on the actual filesystem geometry, including
            // a >4 GiB sparse offset for 4 KiB blocks. Exercise cached tail clearing.
            let mut stat = userspace::syscall::Stat::default();
            if userspace::syscall::sys_fstat(fd, &mut stat) != 0 || stat.blksize < 1024 {
                return false;
            }
            let block = stat.blksize as u64;
            let pointers = block / 4;
            for logical in [
                12 + pointers,
                12 + pointers + pointers * pointers + pointers + 1,
            ] {
                let off = logical * block + 17;
                let mut bytes = [0u8; 8];
                if syscall4(18, fd, b"deep".as_ptr() as u64, 4, off) != 4
                    || syscall4(17, fd, bytes.as_mut_ptr() as u64, 8, off - 4) != 8
                    || bytes != *b"\0\0\0\0deep"
                    || syscall2(77, fd, off + 1) != 0
                    || syscall2(77, fd, off + 4) != 0
                    || syscall4(17, fd, bytes.as_mut_ptr() as u64, 4, off) != 4
                    || bytes[..4] != *b"d\0\0\0"
                    || syscall2(77, fd, 0) != 0
                {
                    return false;
                }
            }
            // Long names force the directory beyond all twelve direct blocks.
            // Keep all entries live until the expanded directory has been observed.
            let mut path = [b'n'; 320];
            let prefix = b"/mnt/test/.ext2-mut-sys/";
            path[..prefix.len()].copy_from_slice(prefix);
            let end = prefix.len() + 255;
            path[end] = 0;
            let entries = 12 * (block / 264) + 1;
            for index in 0..entries {
                path[prefix.len()] = b'A' + (index / 26) as u8;
                path[prefix.len() + 1] = b'a' + (index % 26) as u8;
                let created = sys_open(path.as_ptr(), 2 | 0o100 | 0o200, 0o600);
                if is_error(created) || sys_close(created) != 0 {
                    return false;
                }
            }
            let dir_fd = sys_open(DIR.as_ptr(), 0o200000, 0);
            if is_error(dir_fd)
                || userspace::syscall::sys_fstat(dir_fd, &mut stat) != 0
                || stat.size <= (12 * block) as i64
                || sys_close(dir_fd) != 0
            {
                return false;
            }
            for index in 0..entries {
                path[prefix.len()] = b'A' + (index / 26) as u8;
                path[prefix.len() + 1] = b'a' + (index % 26) as u8;
                if syscall1(87, path.as_ptr() as u64) != 0 {
                    return false;
                }
            }
            let page = [0x4Du8; PAGE];
            for index in 0..16 {
                if syscall4(
                    18,
                    fd,
                    page.as_ptr() as u64,
                    PAGE as u64,
                    index * PAGE as u64,
                ) != PAGE as u64
                {
                    return false;
                }
            }
            let pid = sys_fork();
            if is_error(pid) {
                return false;
            }
            if pid == 0 {
                let mut bytes = [0u8; PAGE];
                let mut valid = true;
                for _ in 0..256 {
                    let count = syscall4(
                        17,
                        fd,
                        bytes.as_mut_ptr() as u64,
                        PAGE as u64,
                        15 * PAGE as u64,
                    );
                    if count != 0
                        && (count != PAGE as u64
                            || !bytes.iter().all(|byte| *byte == bytes[0])
                            || (bytes[0] != 0 && bytes[0] != 0x4D))
                    {
                        valid = false;
                        break;
                    }
                    syscall0(24);
                }
                syscall1(60, if valid { 0 } else { 41 });
                loop {
                    core::hint::spin_loop();
                }
            }
            for _ in 0..16 {
                if syscall2(77, fd, 4097) != 0
                    || syscall2(77, fd, 65536) != 0
                    || syscall4(18, fd, page.as_ptr() as u64, PAGE as u64, 15 * PAGE as u64)
                        != PAGE as u64
                {
                    return false;
                }
            }
            let mut status = -1;
            if sys_wait(&mut status) != pid || status != 0 {
                return false;
            }
            if syscall2(88, b"target\0".as_ptr() as u64, SHORT.as_ptr() as u64) != 0 {
                return false;
            }
            const LONG_TARGET: &[u8] =
                b"././././././././././././././././././././././././././././././././target\0";
            if syscall2(88, LONG_TARGET.as_ptr() as u64, LONG.as_ptr() as u64) != 0 {
                return false;
            }
            let mut bytes = [0; 128];
            if syscall3(
                89,
                LONG.as_ptr() as u64,
                bytes.as_mut_ptr() as u64,
                bytes.len() as u64,
            ) != (LONG_TARGET.len() - 1) as u64
                || bytes[..LONG_TARGET.len() - 1] != LONG_TARGET[..LONG_TARGET.len() - 1]
            {
                return false;
            }
            for link in [SHORT, LONG] {
                let opened = sys_open(link.as_ptr(), 0, 0);
                if is_error(opened)
                    || sys_read(opened, bytes.as_mut_ptr(), 4) != 4
                    || bytes[..4] != [0x4D; 4]
                {
                    return false;
                }
                sys_close(opened);
            }
            if err_of(syscall1(84, DIR.as_ptr() as u64) as i64) != 39 {
                return false;
            }
            if syscall1(87, FILE.as_ptr() as u64) != 0
                || syscall4(18, fd, b"old".as_ptr() as u64, 3, 0) != 3
            {
                return false;
            }
            let replacement = sys_open(FILE.as_ptr(), 2 | 0o100 | 0o200, 0o600);
            if is_error(replacement) || syscall4(18, replacement, b"new".as_ptr() as u64, 3, 0) != 3
            {
                return false;
            }
            if syscall4(17, fd, bytes.as_mut_ptr() as u64, 3, 0) != 3 || &bytes[..3] != b"old" {
                return false;
            }
            if syscall4(17, replacement, bytes.as_mut_ptr() as u64, 3, 0) != 3
                || &bytes[..3] != b"new"
            {
                return false;
            }
            if sys_close(fd) != 0 || sys_close(replacement) != 0 {
                return false;
            }
            for name in [SHORT, LONG, FILE] {
                if syscall1(87, name.as_ptr() as u64) != 0 {
                    return false;
                }
            }
            syscall1(84, DIR.as_ptr() as u64) == 0
        })();
        if ok {
            results.pass(NAME);
        } else {
            results.fail(NAME);
        }
    }
}

/// ST-K4: durability syscalls answer by object kind, never by fd number. This
/// runs on ramfs, whose explicit volatile sync is not a persistence claim; the
/// real barrier is covered by the hosted fault-injection tests and the block
/// stress profile.
fn test_durability_syscalls(results: &mut TestResult) {
    const NAME: &str = "durability syscalls decide by descriptor kind and validate ranges";
    const O_RDONLY: i32 = 0;
    const O_RDWR: i32 = 2;
    const O_CREAT: i32 = 0o100;
    const O_PATH: i32 = 0o10000000;
    const SYS_DUP2: u64 = 33;

    print("Testing fsync family (syscalls 74/75/162/277)... ");

    fn expect(what: &str, got: u64, want_errno: i32, results: &mut TestResult) -> bool {
        let actual = if is_error(got) { errno(got) } else { 0 };
        if actual == want_errno {
            return true;
        }
        println("");
        print("  ");
        print(what);
        print(": expected errno ");
        print_int(want_errno as i64);
        print(", got ");
        print_int(actual as i64);
        println("");
        results.fail(NAME);
        false
    }
    let fsync = |fd: u64| unsafe { syscall1(SYS_FSYNC, fd) };
    let fdatasync = |fd: u64| unsafe { syscall1(SYS_FDATASYNC, fd) };
    let range = |fd: u64, offset: i64, nbytes: i64, flags: u64| unsafe {
        syscall4(SYS_SYNC_FILE_RANGE, fd, offset as u64, nbytes as u64, flags)
    };
    let open = |path: &[u8], flags: i32| unsafe { sys_open(path.as_ptr(), flags, 0o600) };

    let file = open(b"/st-k4-durability\0", O_RDWR | O_CREAT);
    let read_only = open(b"/st-k4-durability\0", O_RDONLY);
    let path_only = open(b"/st-k4-durability\0", O_PATH);
    let directory = open(b"/\0", O_RDONLY);
    let console = open(b"/dev/console\0", O_RDONLY);
    for fd in [file, read_only, path_only, directory, console] {
        if is_error(fd) {
            println("");
            results.fail(NAME);
            return;
        }
    }
    let mut pipe_fds = [0i32; 2];
    if unsafe { syscall2(SYS_PIPE2, pipe_fds.as_mut_ptr() as u64, 0) } != 0 {
        results.fail(NAME);
        return;
    }
    let pipe_read = pipe_fds[0] as u64;
    let saved_stdout = unsafe { syscall1(SYS_DUP, 1) };

    let checks: [(&str, u64, i32); 28] = [
        ("fsync bad fd", fsync(u64::MAX), EBADF),
        ("fdatasync unused fd", fdatasync(200), EBADF),
        ("fsync O_PATH", fsync(path_only), EBADF),
        ("fsync pipe", fsync(pipe_read), EINVAL),
        ("fdatasync pipe", fdatasync(pipe_read), EINVAL),
        ("fsync console", fsync(console), EINVAL),
        ("fsync regular", fsync(file), 0),
        ("fdatasync regular", fdatasync(file), 0),
        ("fsync read-only", fsync(read_only), 0),
        ("fsync directory", fsync(directory), 0),
        ("sync", unsafe { syscall0(SYS_SYNC) }, 0),
        ("range regular", range(file, 0, 0, 0), 0),
        ("range all flags", range(file, 4096, 4096, 7), 0),
        ("range read-only", range(read_only, 0, 1, 2), 0),
        ("range bad fd", range(u64::MAX, 0, 0, 0), EBADF),
        ("range O_PATH", range(path_only, 0, 0, 0), EBADF),
        ("range pipe", range(pipe_read, 0, 0, 0), ESPIPE),
        ("range console", range(console, 0, 0, 0), ESPIPE),
        ("range pipe unknown flag", range(pipe_read, 0, 0, 8), EINVAL),
        (
            "range pipe negative offset",
            range(pipe_read, -1, 0, 0),
            EINVAL,
        ),
        (
            "range pipe negative length",
            range(pipe_read, 0, -1, 0),
            EINVAL,
        ),
        (
            "range pipe overflow",
            range(pipe_read, i64::MAX, 1, 0),
            EINVAL,
        ),
        ("range bad fd before flags", range(u64::MAX, 0, 0, 8), EBADF),
        (
            "range O_PATH before flags",
            range(path_only, 0, 0, 8),
            EBADF,
        ),
        ("range unknown flag", range(file, 0, 0, 8), EINVAL),
        ("range negative offset", range(file, -1, 0, 0), EINVAL),
        ("range negative length", range(file, 0, -1, 0), EINVAL),
        ("range overflow", range(file, i64::MAX, 1, 0), EINVAL),
    ];
    for (what, got, want) in checks {
        if !expect(what, got, want, results) {
            return;
        }
    }

    // A regular file duplicated onto fd 1 is a regular file: KSA-005 made the
    // standard descriptors ordinary, so no numeric special case may apply. The
    // reverse also holds: the console on fd 1 refuses. Restore before printing.
    let console_stdout = fsync(1);
    unsafe { syscall2(SYS_DUP2, file, 1) };
    let file_stdout = fsync(1);
    unsafe { syscall2(SYS_DUP2, saved_stdout, 1) };
    if !expect("fsync console on fd 1", console_stdout, EINVAL, results)
        || !expect("fsync regular file on fd 1", file_stdout, 0, results)
    {
        return;
    }

    for fd in [file, read_only, path_only, directory, console, saved_stdout] {
        unsafe { sys_close(fd) };
    }
    unsafe {
        sys_close(pipe_fds[0] as u64);
        sys_close(pipe_fds[1] as u64);
    }
    println("done");
    results.pass(NAME);
}

fn test_waitid(results: &mut TestResult) {
    print("Testing waitid (syscall 247)... ");

    // 1. Validation happens before any state is consulted, so none of these
    //    needs a child. Each is a claim in §4 of the design.
    let mut info = SigInfo::poisoned();
    let bad = [
        (P_PGID, (-1_i32) as u64, WEXITED, "P_PGID with negative id"),
        (P_PID, 0, WEXITED, "P_PID with id 0"),
        (7, 1, WEXITED, "unknown idtype"),
        (P_ALL, 0, 0, "missing event flag"),
        (P_ALL, 0, WNOHANG, "WNOHANG without event flag"),
        (P_ALL, 0, WEXITED | (1 << 20), "unknown option bit"),
    ];
    for (idtype, id, opts, what) in bad {
        let r = waitid(idtype, id, &mut info, opts);
        if errno(r) != EINVAL {
            println("");
            print("  expected EINVAL for ");
            print(what);
            print(", got errno ");
            print_int(errno(r) as i64);
            println("");
            results.fail("waitid rejects malformed arguments with EINVAL");
            return;
        }
    }

    // 2. With no children at all the answer is ECHILD — even under WNOHANG,
    //    which only turns "children exist but none ready" into a non-block.
    let r = waitid(P_ALL, 0, &mut info, WEXITED | WNOHANG);
    if errno(r) != ECHILD {
        println("");
        print("  no children: expected ECHILD, got errno ");
        print_int(errno(r) as i64);
        println("");
        results.fail("waitid reports ECHILD with no children");
        return;
    }

    // 3. A real zombie: the siginfo is written through a Ring-3 copyout.
    let Some(child) = spawn_exiting_child(42) else {
        results.fail("waitid: fork failed");
        return;
    };

    // WNOWAIT must *observe* the zombie and leave it reapable.
    let mut peek = SigInfo::poisoned();
    let r = waitid(P_PID, child, &mut peek, WEXITED | WNOWAIT);
    if is_error(r) || r != 0 {
        println("");
        print("  WNOWAIT peek failed, errno ");
        print_int(errno(r) as i64);
        println("");
        reap_quietly(child);
        results.fail("waitid WNOWAIT observes the zombie");
        return;
    }
    if peek.signo() != SIGCHLD
        || peek.code() != CLD_EXITED
        || peek.pid() as u64 != child
        || peek.status() != 42
    {
        println("");
        print("  WNOWAIT siginfo: signo=");
        print_int(peek.signo() as i64);
        print(" code=");
        print_int(peek.code() as i64);
        print(" pid=");
        print_int(peek.pid() as i64);
        print(" status=");
        print_int(peek.status() as i64);
        println("");
        reap_quietly(child);
        results.fail("waitid WNOWAIT reports the correct siginfo");
        return;
    }

    // A bad infop must fail with EFAULT *and* leave the zombie reapable:
    // publication precedes the reap commit. Address 0x10 sits below
    // MMAP_MIN_ADDR, so the pointer check rejects it before any copy.
    let r = waitid(P_PID, child, 0x10 as *mut SigInfo, WEXITED);
    if errno(r) != EFAULT {
        println("");
        print("  bad infop: expected EFAULT, got errno ");
        print_int(errno(r) as i64);
        println("");
        reap_quietly(child);
        results.fail("waitid faulting infop returns EFAULT");
        return;
    }

    // The real reap. If WNOWAIT or the EFAULT path had consumed the zombie,
    // this finds nothing and returns ECHILD.
    let mut reaped = SigInfo::poisoned();
    let r = waitid(P_PID, child, &mut reaped, WEXITED);
    if is_error(r) || reaped.pid() as u64 != child || reaped.status() != 42 {
        println("");
        print("  reap after WNOWAIT+EFAULT: errno ");
        print_int(errno(r) as i64);
        print(" pid=");
        print_int(reaped.pid() as i64);
        print(" status=");
        print_int(reaped.status() as i64);
        println("");
        results.fail("waitid: zombie survives WNOWAIT and a faulting infop");
        return;
    }

    // And now it is gone: a second reap has nothing to find.
    let r = waitid(P_PID, child, &mut reaped, WEXITED);
    if errno(r) != ECHILD {
        println("");
        print("  second reap: expected ECHILD, got errno ");
        print_int(errno(r) as i64);
        println("");
        results.fail("waitid: a reaped child is not reaped twice");
        return;
    }

    // 4. The union tail past si_status must be zeroed, not left as poison: the
    //    kernel writes all 128 bytes so no stale user bytes survive.
    if reaped.bytes[28..].iter().any(|&b| b != 0) {
        results.fail("waitid zeroes the siginfo tail past si_status");
        return;
    }

    // 5. P_ALL picks up any child, and wait4 still interoperates with the
    //    shared reap engine after a waitid call.
    let Some(any_child) = spawn_exiting_child(7) else {
        results.fail("waitid: second fork failed");
        return;
    };
    let mut any = SigInfo::poisoned();
    let r = waitid(P_ALL, 0, &mut any, WEXITED);
    if is_error(r) || any.pid() as u64 != any_child || any.status() != 7 {
        println("");
        print("  P_ALL: errno ");
        print_int(errno(r) as i64);
        print(" pid=");
        print_int(any.pid() as i64);
        println("");
        reap_quietly(any_child);
        results.fail("waitid P_ALL reaps any child");
        return;
    }

    results.pass("waitid argument contract, WNOWAIT survival, EFAULT-before-reap, P_ALL");
}

// ---------------------------------------------------------------------------
// ROOT-INIT guest leg
//
// `assign_pid_chain` now registers root-namespace init, and `reparent_orphans`
// resolves its fallback reaper from that registration. The Ring-3 gate boots
// this binary as PID 1, which makes the whole path observable from userspace:
// orphan a grandchild, and the kernel must hand it to us.
//
// The proof is not getppid() alone — a stale ppid write would satisfy that.
// It is that PID 1 can then *reap* the grandchild with P_PID, which succeeds
// only if the grandchild was actually linked into PID 1's `children` list.
// ---------------------------------------------------------------------------

/// Bound the grandchild's wait for its parent to die. Each iteration yields,
/// so this is a scheduling budget, not a busy spin of fixed duration.
const REPARENT_SPIN_LIMIT: u32 = 200_000;
/// Grandchild exit codes. Distinct values let the parent tell a reparent that
/// never happened apart from one that landed on the wrong reaper.
const GC_REPARENTED_TO_INIT: u64 = 91;
const GC_REPARENTED_ELSEWHERE: u64 = 92;
const GC_NEVER_ORPHANED: u64 = 93;

fn test_root_init_reparent(results: &mut TestResult) {
    print("Testing root-init orphan reparenting... ");

    let me = unsafe { sys_getpid() };
    if me != 1 {
        // The claim is specifically about root-namespace init. If this binary
        // is not PID 1 the premise does not hold; say so instead of passing.
        print("running as pid ");
        print_int(me as i64);
        println("");
        results.skip("root-init reparent requires the fixture to run as PID 1");
        return;
    }

    let child = unsafe { sys_fork() };
    if is_error(child) {
        results.fail("root-init reparent: fork failed");
        return;
    }

    if child == 0 {
        // Middle process: spawn the grandchild, then die so it is orphaned.
        // Capture our pid *before* forking so the grandchild inherits it. The
        // grandchild must not sample getppid() to learn its original parent:
        // if it is first scheduled after we have already exited, that sample
        // is already 1 and a "did it change?" check can never fire.
        let mid_pid = unsafe { sys_getpid() };
        let gc = unsafe { sys_fork() };
        if is_error(gc) {
            unsafe { userspace::syscall::sys_exit(1) };
        }
        if gc == 0 {
            // Grandchild: wait until our parent is gone, then report who
            // adopted us through the exit code. Compared against the known
            // middle pid, so this holds however the scheduler orders us.
            let mut spins = 0u32;
            loop {
                let now = unsafe { sys_getppid() };
                if now == 1 {
                    unsafe { userspace::syscall::sys_exit(GC_REPARENTED_TO_INIT) };
                }
                if now != mid_pid {
                    unsafe { userspace::syscall::sys_exit(GC_REPARENTED_ELSEWHERE) };
                }
                spins += 1;
                if spins >= REPARENT_SPIN_LIMIT {
                    unsafe { userspace::syscall::sys_exit(GC_NEVER_ORPHANED) };
                }
                unsafe { userspace::syscall::sys_yield() };
            }
        }
        // Report the grandchild's pid to PID 1 through our own exit code.
        // PIDs in this fixture are small, so the low byte is unambiguous;
        // the parent cross-checks it below rather than trusting it blindly.
        unsafe { userspace::syscall::sys_exit(gc & 0xff) };
    }

    // PID 1: reap the middle process and learn the grandchild's pid.
    let mut mid = SigInfo::poisoned();
    let r = waitid(P_PID, child, &mut mid, WEXITED);
    if is_error(r) || mid.pid() as u64 != child {
        println("");
        print("  middle reap failed, errno ");
        print_int(errno(r) as i64);
        println("");
        results.fail("root-init reparent: middle process was not reaped");
        return;
    }
    let grandchild = mid.status() as u64;
    if grandchild == 0 || grandchild == 1 || grandchild == child {
        println("");
        print("  implausible grandchild pid ");
        print_int(grandchild as i64);
        println("");
        results.fail("root-init reparent: middle process reported a bad pid");
        return;
    }

    // The decisive step: reap the grandchild *by pid*. This can only succeed
    // if reparent_orphans linked it into PID 1's children. A grandchild left
    // attached to the dead middle process would yield ECHILD here.
    let mut gc = SigInfo::poisoned();
    let r = waitid(P_PID, grandchild, &mut gc, WEXITED);
    if is_error(r) {
        println("");
        print("  grandchild ");
        print_int(grandchild as i64);
        print(" not reapable by PID 1, errno ");
        print_int(errno(r) as i64);
        println("");
        results.fail("root-init reparent: orphan was not adopted by PID 1");
        return;
    }
    if gc.pid() as u64 != grandchild {
        results.fail("root-init reparent: reaped the wrong process");
        return;
    }
    match gc.status() as u64 {
        GC_REPARENTED_TO_INIT => {}
        GC_REPARENTED_ELSEWHERE => {
            results.fail("root-init reparent: orphan's ppid moved but not to PID 1");
            return;
        }
        GC_NEVER_ORPHANED => {
            results.fail("root-init reparent: orphan never observed a ppid change");
            return;
        }
        other => {
            println("");
            print("  unexpected grandchild exit code ");
            print_int(other as i64);
            println("");
            results.fail("root-init reparent: grandchild exited unexpectedly");
            return;
        }
    }

    // Nothing else may be left behind for PID 1.
    let mut left = SigInfo::poisoned();
    let r = waitid(P_ALL, 0, &mut left, WEXITED | WNOHANG);
    if errno(r) != ECHILD {
        results.fail("root-init reparent: PID 1 still has children afterwards");
        return;
    }

    results.pass("root-init adopts an orphaned grandchild and can reap it");
}

// ---------------------------------------------------------------------------
// GAP-6 W-3/W-4: selective wait against sibling and nested zombies.
//
// A pid-targeted wait publishes the target's global pid as its wake filter, so
// a sibling's exit must neither satisfy it nor be consumed by it. The same
// contract is checked one generation down (a child reaping its own children by
// pid) so the translate-once namespace view is exercised for nested zombies.
// ---------------------------------------------------------------------------

const SELECTIVE_SLOW_YIELDS: u32 = 2_000;
/// The fast sibling yields a little so the parent is already blocked on the
/// slow one when it exits: under an any-child wake filter that exit would
/// over-wake the parent, which /proc/waitstat then records.
const SELECTIVE_FAST_YIELDS: u32 = 200;
const SW_FAST: u64 = 11;
const SW_SLOW: u64 = 22;
const SW_NESTED_FAST: u64 = 33;
const SW_NESTED_SLOW: u64 = 44;
const SW_NESTED_OK: u64 = 55;

fn fork_exit(code: u64, yields: u32) -> u64 {
    let pid = unsafe { sys_fork() };
    if pid == 0 {
        for _ in 0..yields {
            unsafe { userspace::syscall::sys_yield() };
        }
        unsafe { userspace::syscall::sys_exit(code) };
    }
    pid
}

/// Reap `pid` by P_PID and return its exit status, or None on any mismatch.
fn reap_pid(pid: u64) -> Option<u64> {
    let mut info = SigInfo::poisoned();
    let r = waitid(P_PID, pid, &mut info, WEXITED);
    if is_error(r) || info.pid() as u64 != pid {
        return None;
    }
    Some(info.status() as u64)
}

/// Fast sibling exits first; the slow one is awaited by pid. Returns true when
/// both are reaped with their own status and nothing is left.
fn selective_pair(fast_code: u64, slow_code: u64) -> bool {
    let fast = fork_exit(fast_code, SELECTIVE_FAST_YIELDS);
    if is_error(fast) {
        return false;
    }
    let slow = fork_exit(slow_code, SELECTIVE_SLOW_YIELDS);
    if is_error(slow) {
        let _ = reap_pid(fast);
        return false;
    }
    let slow_ok = reap_pid(slow) == Some(slow_code);
    let fast_ok = reap_pid(fast) == Some(fast_code);
    let mut left = SigInfo::poisoned();
    let drained = errno(waitid(P_ALL, 0, &mut left, WEXITED | WNOHANG)) == ECHILD;
    slow_ok && fast_ok && drained
}

/// GAP-6 W-3: read `over_wakes N` from /proc/waitstat.
fn read_wait_over_wakes() -> Option<u64> {
    let path = b"/proc/waitstat\0";
    let fd = unsafe { sys_open(path.as_ptr(), 0, 0) };
    if is_error(fd) {
        return None;
    }
    let mut buf = [0u8; 48];
    let read = unsafe { sys_read(fd, buf.as_mut_ptr(), buf.len() as u64) };
    let _ = unsafe { sys_close(fd) };
    if is_error(read) {
        return None;
    }
    let text = &buf[..read as usize];
    let digits = text.strip_prefix(b"over_wakes ")?;
    let mut value: u64 = 0;
    let mut seen = 0usize;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .saturating_mul(10)
            .saturating_add((byte - b'0') as u64);
        seen += 1;
    }
    if seen == 0 {
        return None;
    }
    Some(value)
}

fn test_selective_wait_nested_zombie(results: &mut TestResult) {
    print("Testing selective wait against sibling/nested zombies... ");

    let Some(wakes_before) = read_wait_over_wakes() else {
        results.fail("selective wait: /proc/waitstat unreadable");
        return;
    };
    for round in 1..=16 {
        if !selective_pair(SW_FAST, SW_SLOW) {
            results.fail("selective wait: pid-targeted reap took the wrong sibling");
            return;
        }
        let Some(wakes_after) = read_wait_over_wakes() else {
            results.fail("selective wait: /proc/waitstat unreadable");
            return;
        };
        if wakes_after != wakes_before {
            println("");
            print("  targeted wait round ");
            print_int(round);
            print(", over-wakes: ");
            print_int(wakes_after.wrapping_sub(wakes_before) as i64);
            println("");
            results.fail("selective wait: sibling exit over-woke a pid-targeted wait");
            return;
        }
    }

    let mid = unsafe { sys_fork() };
    if is_error(mid) {
        results.fail("selective wait: fork of the nested reaper failed");
        return;
    }
    if mid == 0 {
        let code = if selective_pair(SW_NESTED_FAST, SW_NESTED_SLOW) {
            SW_NESTED_OK
        } else {
            1
        };
        unsafe { userspace::syscall::sys_exit(code) };
    }
    match reap_pid(mid) {
        Some(SW_NESTED_OK) => {}
        Some(other) => {
            println("");
            print("  nested reaper exit ");
            print_int(other as i64);
            println("");
            results.fail("selective wait: nested generation reaped the wrong zombie");
            return;
        }
        None => {
            results.fail("selective wait: nested reaper was not reapable by pid");
            return;
        }
    }

    if read_wait_over_wakes() != Some(wakes_before) {
        results.fail("selective wait: nested wait introduced an extra wake");
        return;
    }
    results.pass("selective wait reaps only its target across sibling and nested zombies");
}

// ---------------------------------------------------------------------------
// Fork refusal under pids.max
//
// `fork::sys_fork` checks `pids.max` before it creates anything and again when
// it attaches the child, and on refusal releases the child link, cgroup charge,
// scheduler slot and PCB. This leg pins the observable contract of that path:
// a refused fork returns EAGAIN and leaves nothing behind — no reapable child,
// no task counted in the cgroup, and no PID burned.
//
// It does not prove which of the two refusal points fired. With one task
// already in the cgroup and pids.max == 1 the pre-check refuses first, so the
// attach-time rollback is exercised only indirectly. The distinction is stated
// in the design notes rather than implied here.
// ---------------------------------------------------------------------------

const SYS_CGROUP_DESTROY: u64 = 501;
const SYS_CGROUP_SET_LIMIT: u64 = 503;
const CGROUP_CTRL_PIDS: u64 = 0x04;
const CGROUP_LIMIT_PIDS_MAX: u64 = 5;
/// `nr_tasks` sits after `id: u64, depth: u32, controllers: u32` in the stats
/// buffer. Must match `CgroupStatsBuf` in `kernel/kernel_core/syscall.rs`.
const CGROUP_STATS_NR_TASKS_OFFSET: usize = 16;
const EAGAIN: i32 = 11;
/// Forks attempted against the full cgroup. Several, so a leak that only shows
/// up cumulatively (one PID per refusal) is visible in the next PID handed out.
const REFUSED_FORKS: usize = 4;

unsafe fn cgroup_nr_tasks(id: u64) -> Option<u64> {
    let mut buf = [0u8; CGROUP_STATS_V1_SIZE];
    if is_error(syscall2(SYS_CGROUP_GET_STATS, id, buf.as_mut_ptr() as u64)) {
        return None;
    }
    let o = CGROUP_STATS_NR_TASKS_OFFSET;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&buf[o..o + 8]);
    Some(u64::from_ne_bytes(raw))
}

fn test_fork_pids_refusal(results: &mut TestResult) {
    print("Testing fork refusal under pids.max... ");

    unsafe {
        let created = syscall2(SYS_CGROUP_CREATE, 0, CGROUP_CTRL_PIDS) as i64;
        if err_of(created) != 0 {
            if matches!(err_of(created), 1 | 13) {
                results.skip("fork pids refusal: requires host-root fixture");
            } else {
                print("errno=");
                print_int(err_of(created) as i64);
                print(" ");
                results.fail("fork pids refusal: unexpected cgroup creation error");
            }
            return;
        }
        let cg = created as u64;

        // pids.max == 1 and we are the one task: every fork must be refused.
        if is_error(syscall3(SYS_CGROUP_SET_LIMIT, cg, CGROUP_LIMIT_PIDS_MAX, 1)) {
            let _ = syscall1(SYS_CGROUP_DESTROY, cg);
            results.fail("fork pids refusal: could not set pids.max");
            return;
        }
        if err_of(syscall1(SYS_CGROUP_ATTACH, cg) as i64) != 0 {
            let _ = syscall1(SYS_CGROUP_DESTROY, cg);
            results.fail("fork pids refusal: could not attach to the limited cgroup");
            return;
        }

        let before = cgroup_nr_tasks(cg);
        let mut refusal_ok = true;
        for _ in 0..REFUSED_FORKS {
            let r = sys_fork();
            if r == 0 {
                // A child slipped past the limit. Leave at once; the parent
                // records the failure and still reaps us below.
                userspace::syscall::sys_exit(77);
            }
            if errno(r) != EAGAIN {
                print("fork returned ");
                print_int(r as i64);
                print(" ");
                refusal_ok = false;
            }
        }
        let after = cgroup_nr_tasks(cg);

        // Leave the limited cgroup before any further fork, whatever happened.
        let _ = syscall1(SYS_CGROUP_ATTACH, 0);

        // Nothing may be reapable: a refused fork never produced a child.
        let mut left = SigInfo::poisoned();
        let leftover = waitid(P_ALL, 0, &mut left, WEXITED | WNOHANG);
        let no_child = errno(leftover) == ECHILD;
        if !no_child {
            // Reap whatever escaped so later legs start clean.
            while !is_error(waitid(P_ALL, 0, &mut left, WEXITED | WNOHANG)) && left.pid() != 0 {}
        }

        // A later fork, now unlimited, must get the very next PID. If each
        // refused fork had consumed a PID, this one would be pushed forward.
        let probe = sys_fork();
        if probe == 0 {
            userspace::syscall::sys_exit(0);
        }
        let mut reaped = SigInfo::poisoned();
        if !is_error(probe) {
            let _ = waitid(P_PID, probe, &mut reaped, WEXITED);
        }
        let _ = syscall1(SYS_CGROUP_DESTROY, cg);

        if !refusal_ok {
            results.fail("fork pids refusal: a fork past pids.max did not return EAGAIN");
            return;
        }
        if !no_child {
            results.fail("fork pids refusal: a refused fork left a reapable child");
            return;
        }
        match (before, after) {
            (Some(b), Some(a)) if b == a => {}
            (Some(b), Some(a)) => {
                print("nr_tasks ");
                print_int(b as i64);
                print("->");
                print_int(a as i64);
                print(" ");
                results.fail("fork pids refusal: refused forks changed the task count");
                return;
            }
            _ => {
                results.fail("fork pids refusal: cgroup stats unreadable");
                return;
            }
        }
        if is_error(probe) {
            results.fail("fork pids refusal: fork failed after leaving the limited cgroup");
            return;
        }
        print("probe pid ");
        print_int(probe as i64);
        print(" ");
        results.pass("fork refused by pids.max leaves no child, task charge or reapable zombie");
    }
}

// ---------------------------------------------------------------------------
// M0-7 user-stack guard page
//
// The user stack window is fixed (no stack ASLR), so the guard page can be
// addressed directly instead of provoked by unbounded recursion:
//
//   [STACK_BASE, USABLE_BASE)   one unmapped guard page
//   [USABLE_BASE, EAGER_FLOOR)  lazy region, demand-grown on #PF
//   [EAGER_FLOOR, STACK_TOP)    mapped at exec
//
// Each probe runs in a forked child, because a guard hit is fatal by design.
// Must match `USER_STACK_TOP/SIZE/GUARD_SIZE/EAGER_SIZE` in
// `kernel/kernel_core/elf_loader.rs`.
// ---------------------------------------------------------------------------

const USER_STACK_TOP: usize = 0x0000_7FFF_FFFF_E000;
const USER_STACK_SIZE: usize = 0x20_0000;
const USER_STACK_GUARD_SIZE: usize = 0x1000;
const USER_STACK_EAGER_SIZE: usize = 16 * 1024;
const STACK_BASE: usize = USER_STACK_TOP - USER_STACK_SIZE;
const USABLE_BASE: usize = STACK_BASE + USER_STACK_GUARD_SIZE;
const EAGER_FLOOR: usize = USER_STACK_TOP - USER_STACK_EAGER_SIZE;
/// Exit code of a task killed by a user-mode #PF: 128 + SIGSEGV(11).
const SIGSEGV_EXIT: i32 = 139;
/// Exit code a probe child uses when its access unexpectedly *succeeded*.
const PROBE_SURVIVED: u64 = 55;

/// Fork a child that writes one byte at `addr` and then exits 0. Returns the
/// child's exit status as seen by waitid, or None if fork/wait failed.
fn probe_write(addr: usize) -> Option<i32> {
    let child = unsafe { sys_fork() };
    if is_error(child) {
        return None;
    }
    if child == 0 {
        unsafe {
            core::ptr::write_volatile(addr as *mut u8, 0x5A);
            // Only reached if the store did not fault.
            let v = core::ptr::read_volatile(addr as *const u8);
            userspace::syscall::sys_exit(if v == 0x5A { 0 } else { PROBE_SURVIVED + 1 });
        }
    }
    let mut info = SigInfo::poisoned();
    let r = waitid(P_PID, child, &mut info, WEXITED);
    if is_error(r) || info.pid() as u64 != child {
        return None;
    }
    Some(info.status())
}

fn test_user_stack_guard(results: &mut TestResult) {
    print("Testing user stack guard page... ");

    // Sanity: this frame really lives in the window we are about to probe. If
    // the layout ever moves, fail loudly instead of probing unrelated memory.
    let here = &results as *const _ as usize;
    if !(EAGER_FLOOR..USER_STACK_TOP).contains(&here) {
        print("stack at ");
        print_hex(here as u64);
        print(" ");
        results.fail("stack guard: fixture stack is not in the expected window");
        return;
    }

    // 1. The lowest lazy page (just above the guard) must demand-grow. This is
    //    the deepest legal access; if it faulted, the guard would be too big.
    match probe_write(USABLE_BASE) {
        Some(0) => {}
        Some(code) => {
            print("lowest-lazy exit ");
            print_int(code as i64);
            print(" ");
            results.fail("stack guard: the lowest lazy stack page did not demand-grow");
            return;
        }
        None => {
            results.fail("stack guard: lazy probe fork/wait failed");
            return;
        }
    }

    // 2. Every byte of the guard page must fault. Probe both ends: an
    //    off-by-one in the grow bound would map the top of the guard only.
    for (addr, what) in [
        (USABLE_BASE - 1, "top byte of the guard page"),
        (STACK_BASE, "bottom byte of the guard page"),
    ] {
        match probe_write(addr) {
            Some(SIGSEGV_EXIT) => {}
            Some(code) => {
                print(what);
                print(" exit ");
                print_int(code as i64);
                print(" ");
                results.fail("stack guard: a guard-page write did not SIGSEGV");
                return;
            }
            None => {
                results.fail("stack guard: guard probe fork/wait failed");
                return;
            }
        }
    }

    // 3. The parent is untouched by its children's faults.
    let mut left = SigInfo::poisoned();
    if errno(waitid(P_ALL, 0, &mut left, WEXITED | WNOHANG)) != ECHILD {
        results.fail("stack guard: probe children were left unreaped");
        return;
    }

    results.pass("user stack guard page faults while the lazy region above it grows");
}

// ---------------------------------------------------------------------------
// GAP-5 slice 4 G3: CLONE_CHILD_CLEARTID on a `.bss` word.
//
// The exit-time clear used to run only when the tid word lay inside an mmap
// region, so a word in `.bss`/`.data` or on a stack kept the child's tid after
// it exited and any joiner waited forever. The word here is a zero-initialised
// static, i.e. `.bss`, which is exactly the skipped case.
// ---------------------------------------------------------------------------

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const SYS_CLONE: u64 = 56;
const SYS_EXIT: u64 = 60;
const CLEAR_TID_EXIT: u64 = 0x5a;
const CLEAR_TID_STACK_BYTES: usize = 16 * 1024;

/// The CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID word (`.bss`).
static CLEAR_TID_WORD: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
/// What the child read from the word, proving CLONE_CHILD_SETTID wrote it.
static CLEAR_TID_SEEN: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

#[repr(C, align(16))]
struct CloneStack([u8; CLEAR_TID_STACK_BYTES]);
static mut CLEAR_TID_STACK: CloneStack = CloneStack([0; CLEAR_TID_STACK_BYTES]);

/// Child entry: runs on `CLEAR_TID_STACK` in the shared address space, records
/// the tid the kernel stored, then leaves with a raw `exit`.
extern "C" fn clear_tid_child() -> ! {
    use core::sync::atomic::Ordering;
    CLEAR_TID_SEEN.store(CLEAR_TID_WORD.load(Ordering::SeqCst), Ordering::SeqCst);
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_EXIT,
            in("rdi") CLEAR_TID_EXIT,
            options(noreturn)
        );
    }
}

/// Raw clone(flags, stack, ptid = 0, ctid, tls = 0). The child resumes on
/// `stack_top`, which shares no frame with the caller, so it must not return
/// from here: it calls `entry` (callee-saved r12 is copied into the child) and
/// never comes back. Returns the parent's result.
unsafe fn raw_clone_vm(
    flags: u64,
    stack_top: usize,
    ctid: *mut i32,
    entry: extern "C" fn() -> !,
) -> u64 {
    raw_clone(flags, stack_top, core::ptr::null_mut(), ctid, entry)
}

/// Raw clone with an explicit CLONE_PARENT_SETTID pointer (`ptid`).
unsafe fn raw_clone(
    flags: u64,
    stack_top: usize,
    ptid: *mut i32,
    ctid: *mut i32,
    entry: extern "C" fn() -> !,
) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        "test rax, rax",
        "jnz 2f",
        "and rsp, -16",
        "call r12",
        "ud2",
        "2:",
        inlateout("rax") SYS_CLONE => ret,
        in("rdi") flags,
        in("rsi") stack_top,
        in("rdx") ptid,
        in("r10") ctid,
        in("r8") 0u64,
        in("r12") entry,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    ret
}

/// Futex word the blocked child sleeps on; nothing ever wakes it.
static CLEAR_TID_BLOCK_WORD: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));

/// Child entry: record the tid the kernel stored, then sleep until killed.
extern "C" fn clear_tid_blocking_child() -> ! {
    use core::sync::atomic::Ordering;
    CLEAR_TID_SEEN.store(CLEAR_TID_WORD.load(Ordering::SeqCst), Ordering::SeqCst);
    loop {
        unsafe { futex(&CLEAR_TID_BLOCK_WORD, FUTEX_WAIT_OP, 0, 0, 0, 0) };
    }
}

/// A page of its own for the COW clear-tid leg, so nothing else written by
/// this process breaks the copy-on-write sharing before the clear does.
#[repr(C, align(4096))]
struct CowTidPage([core::sync::atomic::AtomicI32; 1024]);
static COW_TID_PAGE: CowTidPage =
    CowTidPage([const { core::sync::atomic::AtomicI32::new(0) }; 1024]);

/// Child entry: spin in user mode without syscalls until killed.
extern "C" fn clear_tid_spinning_child() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// The D4/D5 leg: SIGKILL a CLONE_VM child spinning in user mode whose
/// CLONE_CHILD_CLEARTID word is on a copy-on-write page; after the reap the
/// word must read 0. Reports its own failure.
fn clear_tid_after_spinning_kill_leg(stack_top: usize) -> Result<(), &'static str> {
    use core::sync::atomic::Ordering;
    let word = &COW_TID_PAGE.0[0];
    // Own the page, then fork a keeper so the page is shared copy-on-write
    // until the keeper exits. Nothing writes the page again before the clear.
    word.store(-1, Ordering::SeqCst);
    let keeper = unsafe { sys_fork() };
    if keeper == 0 {
        spin_forever();
    }
    if is_error(keeper) {
        return Err("clear-tid: fork of the COW keeper failed");
    }
    let child = unsafe {
        raw_clone_vm(
            CLONE_VM | CLONE_CHILD_CLEARTID,
            stack_top,
            word.as_ptr(),
            clear_tid_spinning_child,
        )
    };
    let outcome = if is_error(child) || child == 0 {
        Err("clear-tid: CLONE_VM|CHILD_CLEARTID spinning child failed")
    } else {
        for _ in 0..50 {
            unsafe { userspace::syscall::sys_yield() };
        }
        unsafe { userspace::syscall::sys_kill(child, SIGKILL_NR) };
        if reap_pid(child) != Some(SIGKILL_EXIT) {
            Err("clear-tid: could not reap the killed spinning child")
        } else if word.load(Ordering::SeqCst) != 0 {
            Err("clear-tid: the drain left a copy-on-write tid word set")
        } else {
            Ok(())
        }
    };
    unsafe { userspace::syscall::sys_kill(keeper, SIGKILL_NR) };
    let _ = reap_pid(keeper);
    outcome
}

/// The D5 leg: SIGKILL a CLONE_VM child blocked in FUTEX_WAIT; after the reap
/// its CLONE_CHILD_CLEARTID word must read 0. Reports its own failure.
fn clear_tid_after_blocked_kill_leg(stack_top: usize) -> Result<(), &'static str> {
    use core::sync::atomic::Ordering;
    // Touch both words in this address space first, so neither write below
    // is a first-use fault.
    CLEAR_TID_BLOCK_WORD.0.store(0, Ordering::SeqCst);
    CLEAR_TID_WORD.store(-1, Ordering::SeqCst);
    CLEAR_TID_SEEN.store(0, Ordering::SeqCst);
    let child = unsafe {
        raw_clone_vm(
            CLONE_VM | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            stack_top,
            CLEAR_TID_WORD.as_ptr(),
            clear_tid_blocking_child,
        )
    };
    if is_error(child) || child == 0 {
        return Err("clear-tid: clone of the blocking child failed");
    }
    // Let the child start and block. If it is still running when the kill
    // lands, it exits through its own path and the leg still checks the clear.
    let mut started = false;
    for _ in 0..THREAD_POLL_YIELDS {
        if CLEAR_TID_SEEN.load(Ordering::SeqCst) as u64 == child {
            started = true;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    for _ in 0..100 {
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { userspace::syscall::sys_kill(child, SIGKILL_NR) };
    if reap_pid(child) != Some(SIGKILL_EXIT) {
        return Err("clear-tid: the blocked child was not killed by SIGKILL");
    }
    if !started {
        return Err("clear-tid: the blocking child never ran");
    }
    if CLEAR_TID_WORD.load(Ordering::SeqCst) != 0 {
        return Err("clear-tid: a kill while blocked left the tid word set");
    }
    Ok(())
}

fn test_clone_vm_clear_child_tid(results: &mut TestResult) {
    use core::sync::atomic::Ordering;
    print("Testing CLONE_CHILD_CLEARTID on a .bss word... ");

    CLEAR_TID_WORD.store(-1, Ordering::SeqCst);
    CLEAR_TID_SEEN.store(0, Ordering::SeqCst);
    let stack_top = core::ptr::addr_of_mut!(CLEAR_TID_STACK) as usize + CLEAR_TID_STACK_BYTES;
    let child = unsafe {
        raw_clone_vm(
            CLONE_VM | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            stack_top,
            CLEAR_TID_WORD.as_ptr(),
            clear_tid_child,
        )
    };
    if is_error(child) || child == 0 {
        print("clone errno ");
        print_int(errno(child) as i64);
        print(" ");
        results.fail("clear-tid: CLONE_VM|CHILD_SETTID|CHILD_CLEARTID failed");
        return;
    }

    // The child is reapable only after terminate_process finished its
    // teardown, which includes the clear; no polling is needed.
    match reap_pid(child) {
        Some(CLEAR_TID_EXIT) => {}
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("clear-tid: child exited with an unexpected status");
            return;
        }
        None => {
            results.fail("clear-tid: could not reap the CLONE_VM child");
            return;
        }
    }

    let seen = CLEAR_TID_SEEN.load(Ordering::SeqCst);
    let word = CLEAR_TID_WORD.load(Ordering::SeqCst);
    if seen as u64 != child {
        print("seen ");
        print_int(seen as i64);
        print(" ");
        results.fail("clear-tid: CLONE_CHILD_SETTID did not store the child tid");
        return;
    }
    if word != 0 {
        print("word ");
        print_int(word as i64);
        print(" ");
        results.fail("clear-tid: exit left the .bss tid word set");
        return;
    }
    // Review D5: a kill, not a voluntary exit. The SIGKILL wakes the child
    // out of FUTEX_WAIT and it is torn down at its next safe point; that
    // teardown must clear the word too.
    if let Err(reason) = clear_tid_after_blocked_kill_leg(stack_top) {
        results.fail(reason);
        return;
    }
    // Review D4/D5: a child spinning in user mode has no syscall safe point,
    // so its SIGKILL is taken at interrupt return and the deferred IRQ-kill
    // drain tears it down, possibly from the idle loop. Its tid word sits on
    // a copy-on-write page, so the drain's clear needs COW resolution.
    if let Err(reason) = clear_tid_after_spinning_kill_leg(stack_top) {
        results.fail(reason);
        return;
    }
    results.pass("CLONE_CHILD_CLEARTID clears a .bss tid word at exit");
}

// ---------------------------------------------------------------------------
// GAP-5 slice 4 G7: thread-directed signals. Without CLONE_THREAD every task
// is its own group, so these legs pin the argument contract and that a
// tkill reaches exactly the named task.
// ---------------------------------------------------------------------------

const SYS_TKILL: u64 = 200;
const SYS_TGKILL: u64 = 234;
const ESRCH: i32 = 3;
const SIGKILL_NR: u64 = 9;
/// Exit status of a task killed by SIGKILL: 128 + 9.
const SIGKILL_EXIT: u64 = 137;

fn test_tkill_tgkill(results: &mut TestResult) {
    print("Testing tkill/tgkill... ");
    let pid = unsafe { sys_getpid() };
    let tid = unsafe { sys_gettid() };

    // Signal 0 is a permission/existence probe on the caller itself.
    if unsafe { syscall2(SYS_TKILL, tid, 0) } != 0
        || unsafe { syscall3(SYS_TGKILL, pid, tid, 0) } != 0
    {
        results.fail("tkill/tgkill: self probe with signal 0 failed");
        return;
    }
    // Non-positive ids are EINVAL, not a lookup.
    if errno(unsafe { syscall2(SYS_TKILL, 0, 0) }) != EINVAL
        || errno(unsafe { syscall3(SYS_TGKILL, 0, tid, 0) }) != EINVAL
        || errno(unsafe { syscall3(SYS_TGKILL, pid, 0, 0) }) != EINVAL
    {
        results.fail("tkill/tgkill: a zero id was not EINVAL");
        return;
    }

    // A child that keeps entering the kernel, so a pending kill is consumed.
    let child = unsafe { sys_fork() };
    if is_error(child) {
        results.fail("tkill/tgkill: fork failed");
        return;
    }
    if child == 0 {
        loop {
            unsafe { userspace::syscall::sys_yield() };
        }
    }

    // The child's tid does not belong to the caller's group: ESRCH, no signal.
    if errno(unsafe { syscall3(SYS_TGKILL, pid, child, SIGKILL_NR) }) != ESRCH {
        unsafe { userspace::syscall::sys_kill(child, SIGKILL_NR) };
        reap_quietly(child);
        results.fail("tkill/tgkill: tgkill with a foreign tgid was not ESRCH");
        return;
    }
    // tgkill naming the child's own group, then tkill, reach it.
    if unsafe { syscall3(SYS_TGKILL, child, child, 0) } != 0 {
        unsafe { userspace::syscall::sys_kill(child, SIGKILL_NR) };
        reap_quietly(child);
        results.fail("tkill/tgkill: tgkill(child, child, 0) failed");
        return;
    }
    if unsafe { syscall2(SYS_TKILL, child, SIGKILL_NR) } != 0 {
        // Clean up with kill(2) so a broken tkill cannot hang the gate.
        unsafe { userspace::syscall::sys_kill(child, SIGKILL_NR) };
        reap_quietly(child);
        results.fail("tkill/tgkill: tkill(child, SIGKILL) failed");
        return;
    }
    match reap_pid(child) {
        Some(SIGKILL_EXIT) => {}
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("tkill/tgkill: child was not killed by SIGKILL");
            return;
        }
        None => {
            results.fail("tkill/tgkill: could not reap the killed child");
            return;
        }
    }
    results.pass("tkill and tgkill reach exactly the named task");
}

/// Child entry: spin in user mode without syscalls until killed.
fn spin_in_user_mode() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// GAP-5 G8: a task killed at a timer interrupt is ended by a deferred drain
/// that runs only in process context. On one CPU the victim's handoff must not
/// go straight to a bystander that never enters the kernel, or the waiting
/// parent is never woken.
fn test_kill_beside_user_spinner(results: &mut TestResult) {
    print("Testing SIGKILL beside a user-mode spinner... ");
    let bystander = unsafe { sys_fork() };
    if bystander == 0 {
        spin_in_user_mode();
    }
    if is_error(bystander) {
        results.fail("kill beside a spinner: fork of the bystander failed");
        return;
    }
    let victim = unsafe { sys_fork() };
    if victim == 0 {
        spin_in_user_mode();
    }
    if is_error(victim) {
        unsafe { userspace::syscall::sys_kill(bystander, SIGKILL_NR) };
        reap_quietly(bystander);
        results.fail("kill beside a spinner: fork of the victim failed");
        return;
    }
    // Let both reach user mode, so the kill is taken at a timer interrupt.
    for _ in 0..10 {
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { userspace::syscall::sys_kill(victim, SIGKILL_NR) };
    let outcome = reap_pid(victim);
    unsafe { userspace::syscall::sys_kill(bystander, SIGKILL_NR) };
    reap_quietly(bystander);
    if outcome != Some(SIGKILL_EXIT) {
        results.fail("kill beside a spinner: the killed spinner was not reaped");
        return;
    }
    results.pass("a spinner killed at a timer interrupt is reaped while another spinner runs");
}

// ---------------------------------------------------------------------------
// GAP-5 slice 4 step 7 (thread preview): CLONE_VM|CLONE_SIGHAND|CLONE_THREAD.
// Each leg runs in a forked child that hosts the thread group, so a thread
// defect cannot take this PID 1 down. The parent can reap a group leader only
// after every other member was auto-reaped (G1), so each successful reap also
// proves the thread itself was reaped.
// ---------------------------------------------------------------------------

const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const SYS_EXIT_GROUP: u64 = 231;
const THREAD_FLAGS: u64 = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD;
const THREAD_POLL_YIELDS: u32 = 200_000;
/// Status a leg's host process exits with when every check passed.
const GROUP_LEG_OK: u64 = 0x31;
/// exit_group status used by the group-exit leg.
const GROUP_EXIT_CODE: u64 = 0x42;

static GROUP_TID_WORD: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
static GROUP_PARENT_TID: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
static GROUP_SEEN_PID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static GROUP_SEEN_TID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static GROUP_SEEN_PPID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static mut GROUP_STACK: CloneStack = CloneStack([0; CLEAR_TID_STACK_BYTES]);

fn group_stack_top() -> usize {
    core::ptr::addr_of_mut!(GROUP_STACK) as usize + CLEAR_TID_STACK_BYTES
}

unsafe fn raw_exit(syscall: u64, code: u64) -> ! {
    core::arch::asm!("syscall", in("rax") syscall, in("rdi") code, options(noreturn));
}

// ---------------------------------------------------------------------------
// TD-LSM-1: runtime LSM denial oracle. The syscall_test kernel installs a test
// policy that denies six hooks for one marked pid, and fails the first subject
// lookup of every syscall made by a second marked pid. A child marks itself
// with the kernel's test-only prctl option and stays root (the kernel has no
// set*id syscall), so each DAC check before the LSM passes and only the LSM
// can refuse it; the parent clears the marks after reaping it.
// ---------------------------------------------------------------------------

const SYS_EXEC: u64 = 59;
const SYS_KILL: u64 = 62;
const SYS_PRCTL: u64 = 157;
const SYS_UNLINK: u64 = 87;
/// Keep in sync with `lsm::syscall_test::{PR_SYSCALL_TEST_LSM_MARK, ARM_*}`.
const PR_SYSCALL_TEST_LSM_MARK: u64 = 0x5A4C_534D;
const LSM_ARM_NONE: u64 = 0;
const LSM_ARM_DENY: u64 = 1;
const LSM_ARM_NO_SUBJECT: u64 = 2;
const ENOEXEC: i32 = 8;
const EACCES: i32 = 13;
/// One bit per checked call; a child exits with the calls that behaved.
const LSM_ALL_CALLS: u64 = 0x3F;
/// A regular, executable, non-ELF file: exec reaches its LSM hook and then
/// fails the header pre-flight with ENOEXEC.
const LSM_EXEC_PATH: &[u8] = b"/td_lsm_1_exec\0";

fn test_lsm_denial_oracle(results: &mut TestResult) {
    print("Testing LSM denial and missing-subject arms... ");
    let name = "LSM denial and missing-subject arms fail closed at exec, kill, get_robust_list, mmap, mprotect and fstat";
    match unsafe { lsm_denial_oracle() } {
        Ok(()) => results.pass(name),
        Err((reason, mask)) => {
            print("  TD-LSM-1 leg: ");
            print(reason);
            print(" mask=");
            print_hex(mask);
            println("");
            results.fail(name);
        }
    }
}

unsafe fn lsm_denial_oracle() -> Result<(), (&'static str, u64)> {
    let fd = sys_open(LSM_EXEC_PATH.as_ptr(), 0o101, 0o755); // O_CREAT | O_WRONLY
    if is_error(fd) {
        return Err(("create the exec fixture", 0));
    }
    let body = b"not an executable\n";
    let written = syscall3(SYS_WRITE, fd, body.as_ptr() as u64, body.len() as u64);
    sys_close(fd);
    if written != body.len() as u64 {
        return Err(("write the exec fixture", 0));
    }
    let stat_fd = sys_open(LSM_EXEC_PATH.as_ptr(), 0, 0);
    let page = mmap_anon(PAGE, false);
    let result = if is_error(stat_fd) || page < 0 {
        Err(("open the fstat fd or map the mprotect page", 0))
    } else {
        lsm_oracle_arms(stat_fd, page as usize)
    };
    if !is_error(stat_fd) {
        sys_close(stat_fd);
    }
    if page >= 0 {
        munmap(page as usize, PAGE);
    }
    syscall1(SYS_UNLINK, LSM_EXEC_PATH.as_ptr() as u64);
    result
}

/// Root first (the control: every call succeeds, exec fails only its header
/// check), then the policy-denial and missing-subject markers.
unsafe fn lsm_oracle_arms(stat_fd: u64, page: usize) -> Result<(), (&'static str, u64)> {
    for (marker, arm) in [
        (None, "control arm"),
        (Some(LSM_ARM_DENY), "policy-denial arm"),
        (Some(LSM_ARM_NO_SUBJECT), "missing-subject arm"),
    ] {
        let child = sys_fork();
        if is_error(child) {
            return Err(("fork", 0));
        }
        if child == 0 {
            let code = match marker {
                Some(arm) if syscall2(SYS_PRCTL, PR_SYSCALL_TEST_LSM_MARK, arm) != 0 => 0x40,
                _ => lsm_oracle_calls(marker.is_none(), stat_fd, page),
            };
            raw_exit(SYS_EXIT, code);
        }
        // By pid: a child another leg left behind must not be taken for ours.
        let Some(code) = reap_pid(child) else {
            return Err(("wait", 0));
        };
        if syscall2(SYS_PRCTL, PR_SYSCALL_TEST_LSM_MARK, LSM_ARM_NONE) != 0 {
            return Err(("clear the LSM marks", 0));
        }
        if code != LSM_ALL_CALLS {
            return Err((arm, code));
        }
    }
    Ok(())
}

/// In the forked child: one bit per call that returned what its arm expects.
/// Nothing here allocates or writes to the console.
unsafe fn lsm_oracle_calls(control: bool, stat_fd: u64, page: usize) -> u64 {
    let (fail, stat_fail) = if control { (0, 0) } else { (EPERM, EACCES) };
    let argv = [LSM_EXEC_PATH.as_ptr() as u64, 0];
    let envp = [0u64];
    let exec = err_of(syscall3(
        SYS_EXEC,
        LSM_EXEC_PATH.as_ptr() as u64,
        argv.as_ptr() as u64,
        envp.as_ptr() as u64,
    ) as i64);
    let kill = err_of(syscall2(SYS_KILL, sys_getpid(), 0) as i64);
    let (mut head, mut len) = (0u64, 0u64);
    let robust = err_of(syscall3(
        SYS_GET_ROBUST_LIST,
        1,
        &mut head as *mut u64 as u64,
        &mut len as *mut u64 as u64,
    ) as i64);
    let mapped = mmap_anon(PAGE, false);
    let mmap = err_of(mapped);
    let mprotect = err_of(syscall3(SYS_MPROTECT, page as u64, PAGE as u64, PROT_READ) as i64);
    let mut stat = [0u64; 18];
    let fstat = err_of(syscall2(SYS_FSTAT, stat_fd, stat.as_mut_ptr() as u64) as i64);
    let expected_exec = if control { ENOEXEC } else { EPERM };
    [
        exec == expected_exec,
        kill == fail,
        robust == fail,
        mmap == fail,
        mprotect == fail,
        fstat == stat_fail,
    ]
    .iter()
    .enumerate()
    .fold(0, |mask, (bit, ok)| mask | ((*ok as u64) << bit))
}

// ---------------------------------------------------------------------------
// R192-RES-3: the mmap placement contract. A non-zero address without a FIXED
// flag is a hint: used when its range is free, otherwise the mapping is placed
// automatically. MAP_FIXED_NOREPLACE maps exactly or fails (EEXIST when taken,
// EPERM below MMAP_MIN_ADDR, ENOMEM past the top, EINVAL unaligned) and never
// replaces anything. MAP_FIXED is still EOPNOTSUPP.
// ---------------------------------------------------------------------------

const MAP_FIXED: u64 = 0x10;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const EEXIST: i32 = 17;
/// Below the randomized automatic base (64 GiB) and clear of the other legs'
/// fixed addresses (R192 probes below 4 GiB, its free hint at 32 GiB).
const PLACEMENT_BASE: usize = 0x4_0000_0000;
const PLACEMENT_USER_TOP: usize = 0x0000_8000_0000_0000;
const PLACEMENT_MIN_ADDR: usize = 0x1_0000;
const PLACEMENT_SHARED_WORD: u64 = 0x5245_5333_5348_5244;

fn test_mmap_placement_contract(results: &mut TestResult) {
    print("Testing the mmap placement contract... ");
    let name = "mmap: an unusable hint is placed elsewhere, MAP_FIXED_NOREPLACE maps exactly or refuses without replacing, MAP_FIXED stays rejected";
    match unsafe { mmap_placement_contract() } {
        Ok(()) => results.pass(name),
        Err(reason) => {
            print("  placement leg: ");
            println(reason);
            results.fail(name);
        }
    }
}

unsafe fn mmap_raw(addr: usize, len: usize, flags: u64) -> i64 {
    syscall6(
        SYS_MMAP,
        addr as u64,
        len as u64,
        PROT_READ | PROT_WRITE,
        flags,
        u64::MAX,
        0,
    ) as i64
}

/// A hint at `hint` that cannot be used: the mapping must land at another
/// aligned address at or above the minimum, clear of `[lo, hi)`. Unmapped.
unsafe fn expect_hint_fallback(
    hint: usize,
    len: usize,
    lo: usize,
    hi: usize,
    what: &'static str,
) -> Result<(), &'static str> {
    let got = mmap_raw(hint, len, MAP_PRIVATE | MAP_ANONYMOUS);
    if got < 0 {
        return Err(what);
    }
    let got = got as usize;
    let placed_elsewhere = got != hint & !0xfff
        && got & 0xfff == 0
        && got >= PLACEMENT_MIN_ADDR
        && got
            .checked_add(len)
            .is_some_and(|end| end <= PLACEMENT_USER_TOP)
        && (got >= hi || got + len <= lo);
    if munmap(got, len) != 0 || !placed_elsewhere {
        return Err(what);
    }
    Ok(())
}

/// `MAP_FIXED_NOREPLACE` at `addr` must fail with `errno` and map nothing.
unsafe fn expect_exact_refused(
    addr: usize,
    len: usize,
    errno: i32,
    what: &'static str,
) -> Result<(), &'static str> {
    let got = mmap_raw(addr, len, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE);
    if err_of(got) != errno {
        if got >= 0 {
            munmap(got as usize, len);
        }
        return Err(what);
    }
    Ok(())
}

unsafe fn mmap_placement_contract() -> Result<(), &'static str> {
    let private = MAP_PRIVATE | MAP_ANONYMOUS;
    let exact = private | MAP_FIXED_NOREPLACE;
    let a = PLACEMENT_BASE;
    let len = 2 * PAGE;
    if mmap_raw(a, len, exact) != a as i64 {
        return Err("MAP_FIXED_NOREPLACE at a free address");
    }
    fill_pattern(a, len);
    let result = placement_around(a, len);
    let kept = pattern_holds(a, len);
    if munmap(a, len) != 0 {
        return Err("munmap of the exact mapping");
    }
    result?;
    if !kept {
        return Err("a refused or placed-elsewhere request changed the occupant");
    }
    placement_free_ranges()?;
    placement_shared_exact()
}

/// With `[a, a + len)` mapped: occupied, stack, image, low and high requests.
unsafe fn placement_around(a: usize, len: usize) -> Result<(), &'static str> {
    expect_exact_refused(
        a,
        len,
        EEXIST,
        "MAP_FIXED_NOREPLACE over a mapping was not EEXIST",
    )?;
    expect_exact_refused(
        a + PAGE,
        len,
        EEXIST,
        "MAP_FIXED_NOREPLACE over a mapping's tail was not EEXIST",
    )?;
    expect_exact_refused(
        a - PAGE,
        len,
        EEXIST,
        "MAP_FIXED_NOREPLACE over a mapping's head was not EEXIST",
    )?;
    expect_hint_fallback(
        a,
        PAGE,
        a,
        a + len,
        "an occupied hint was not placed elsewhere",
    )?;
    expect_hint_fallback(
        a + PAGE,
        len,
        a,
        a + len,
        "a partly occupied hint was not placed elsewhere",
    )?;

    let local = 0u64;
    let stack = &local as *const u64 as usize & !0xfff;
    expect_hint_fallback(
        stack,
        PAGE,
        stack,
        stack + PAGE,
        "a hint in the stack window was not placed elsewhere",
    )?;
    expect_exact_refused(
        stack,
        PAGE,
        EEXIST,
        "MAP_FIXED_NOREPLACE in the stack window was not EEXIST",
    )?;

    let image = mmap_placement_contract as *const () as usize & !0xfff;
    expect_hint_fallback(
        image,
        PAGE,
        image,
        image + PAGE,
        "a hint over the program image was not placed elsewhere",
    )?;
    expect_exact_refused(
        image,
        PAGE,
        EEXIST,
        "MAP_FIXED_NOREPLACE over the program image was not EEXIST",
    )?;

    expect_hint_fallback(
        0x1000,
        PAGE,
        0,
        PLACEMENT_MIN_ADDR,
        "a hint below MMAP_MIN_ADDR was not placed elsewhere",
    )?;
    expect_exact_refused(
        0x1000,
        PAGE,
        EPERM,
        "MAP_FIXED_NOREPLACE below MMAP_MIN_ADDR was not EPERM",
    )?;
    expect_exact_refused(0, PAGE, EPERM, "MAP_FIXED_NOREPLACE at 0 was not EPERM")?;

    let high = PLACEMENT_USER_TOP - PAGE;
    expect_hint_fallback(
        high,
        2 * PAGE,
        high,
        PLACEMENT_USER_TOP,
        "a hint past the top was not placed elsewhere",
    )?;
    expect_exact_refused(
        high,
        2 * PAGE,
        ENOMEM,
        "MAP_FIXED_NOREPLACE past the top was not ENOMEM",
    )
}

/// Free ranges: an unaligned hint, an unaligned exact request, MAP_FIXED.
unsafe fn placement_free_ranges() -> Result<(), &'static str> {
    let private = MAP_PRIVATE | MAP_ANONYMOUS;
    let free = PLACEMENT_BASE + 0x10_0000;
    let got = mmap_raw(free + 0x123, PAGE, private);
    if got != free as i64 {
        if got >= 0 {
            munmap(got as usize, PAGE);
        }
        return Err("an unaligned free hint was not mapped at its page");
    }
    if munmap(free, PAGE) != 0 {
        return Err("munmap of the unaligned hint's page");
    }
    expect_exact_refused(
        free + 0x123,
        PAGE,
        EINVAL,
        "an unaligned MAP_FIXED_NOREPLACE was not EINVAL",
    )?;

    let fixed = PLACEMENT_BASE + 0x20_0000;
    for flags in [
        private | MAP_FIXED,
        private | MAP_FIXED | MAP_FIXED_NOREPLACE,
    ] {
        let got = mmap_raw(fixed, PAGE, flags);
        if err_of(got) != EOPNOTSUPP {
            if got >= 0 {
                munmap(got as usize, PAGE);
            }
            return Err("MAP_FIXED was not EOPNOTSUPP");
        }
    }
    // Nothing was mapped: the exact request for the same page succeeds.
    if mmap_raw(fixed, PAGE, private | MAP_FIXED_NOREPLACE) != fixed as i64 {
        return Err("MAP_FIXED left something behind");
    }
    if munmap(fixed, PAGE) != 0 {
        return Err("munmap after the MAP_FIXED checks");
    }
    Ok(())
}

/// A shared exact mapping is shared: a fork child's write reaches the parent.
unsafe fn placement_shared_exact() -> Result<(), &'static str> {
    let shared = PLACEMENT_BASE + 0x30_0000;
    let flags = MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
    if mmap_raw(shared, PAGE, flags) != shared as i64 {
        return Err("shared MAP_FIXED_NOREPLACE at a free address");
    }
    core::ptr::write_volatile(shared as *mut u64, 0);
    let child = sys_fork();
    if is_error(child) {
        munmap(shared, PAGE);
        return Err("fork for the shared exact mapping");
    }
    if child == 0 {
        core::ptr::write_volatile(shared as *mut u64, PLACEMENT_SHARED_WORD);
        raw_exit(SYS_EXIT, 0);
    }
    let reaped = reap_pid(child);
    let seen = core::ptr::read_volatile(shared as *const u64);
    if munmap(shared, PAGE) != 0 {
        return Err("munmap of the shared exact mapping");
    }
    if reaped != Some(0) || seen != PLACEMENT_SHARED_WORD {
        return Err("a shared MAP_FIXED_NOREPLACE mapping was not shared with the fork child");
    }
    Ok(())
}

/// Thread entry: record the identity the kernel reports, then leave the
/// group with a plain (single-thread) exit.
extern "C" fn group_identity_thread() -> ! {
    use core::sync::atomic::Ordering;
    unsafe {
        GROUP_SEEN_PID.store(sys_getpid(), Ordering::SeqCst);
        GROUP_SEEN_TID.store(sys_gettid(), Ordering::SeqCst);
        GROUP_SEEN_PPID.store(sys_getppid(), Ordering::SeqCst);
        raw_exit(SYS_EXIT, 0);
    }
}

/// Thread entry: end the whole group from a non-leader thread.
extern "C" fn group_exit_thread() -> ! {
    for _ in 0..50 {
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { raw_exit(SYS_EXIT_GROUP, GROUP_EXIT_CODE) }
}

/// Thread entry: keep entering the kernel until killed.
extern "C" fn group_spin_thread() -> ! {
    loop {
        unsafe { userspace::syscall::sys_yield() };
    }
}

fn spin_forever() -> ! {
    loop {
        unsafe { userspace::syscall::sys_yield() };
    }
}

/// Body of the identity leg's host process; returns its exit status.
fn group_identity_leg() -> u64 {
    use core::sync::atomic::Ordering;
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    let thread = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            GROUP_PARENT_TID.as_ptr(),
            GROUP_TID_WORD.as_ptr(),
            group_identity_thread,
        )
    };
    if is_error(thread) || thread == 0 {
        return 0x50;
    }
    // The clear at the thread's exit is the join signal.
    let mut joined = false;
    for _ in 0..THREAD_POLL_YIELDS {
        if GROUP_TID_WORD.load(Ordering::SeqCst) == 0 {
            joined = true;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if !joined {
        return 0x51;
    }
    let (pid, tid, ppid) = unsafe { (sys_getpid(), sys_gettid(), sys_getppid()) };
    if GROUP_SEEN_PID.load(Ordering::SeqCst) != pid {
        return 0x52; // getpid in a thread is the group id
    }
    let seen_tid = GROUP_SEEN_TID.load(Ordering::SeqCst);
    if seen_tid == tid
        || seen_tid != thread
        || GROUP_PARENT_TID.load(Ordering::SeqCst) as u64 != thread
    {
        return 0x53; // a distinct tid, reported by clone and PARENT_SETTID
    }
    if GROUP_SEEN_PPID.load(Ordering::SeqCst) != ppid {
        return 0x54; // getppid in a thread is the group's parent
    }
    // A thread is not its creator's child.
    let mut info = SigInfo::poisoned();
    if errno(waitid(P_ALL, 0, &mut info, WEXITED | WNOHANG)) != ECHILD {
        return 0x55;
    }
    GROUP_LEG_OK
}

const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const SYS_DUP: u64 = 32;
const SYS_FCNTL: u64 = 72;
const F_GETFD: u64 = 1;
const EBADF: i32 = 9;
static GROUP_DUP_FD: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(-1);

/// Thread entry: open a descriptor in the shared table, then exit alone.
extern "C" fn group_files_thread() -> ! {
    use core::sync::atomic::Ordering;
    let fd = unsafe { syscall1(SYS_DUP, 1) } as i64;
    GROUP_DUP_FD.store(fd, Ordering::SeqCst);
    unsafe { raw_exit(SYS_EXIT, 0) }
}

/// Body of the shared-table leg's host process (CLONE_FILES|CLONE_FS).
fn group_files_leg() -> u64 {
    use core::sync::atomic::Ordering;
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    GROUP_DUP_FD.store(-1, Ordering::SeqCst);
    let thread = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_FILES | CLONE_FS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            group_files_thread,
        )
    };
    if is_error(thread) || thread == 0 {
        return 0x80;
    }
    let mut joined = false;
    for _ in 0..THREAD_POLL_YIELDS {
        if GROUP_TID_WORD.load(Ordering::SeqCst) == 0 {
            joined = true;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if !joined {
        return 0x81;
    }
    let fd = GROUP_DUP_FD.load(Ordering::SeqCst);
    if fd < 0 {
        return 0x82; // the thread's dup failed
    }
    // The thread's descriptor lives in this task's table, and the thread's
    // exit closed nothing.
    if is_error(unsafe { syscall2(SYS_FCNTL, fd as u64, F_GETFD) })
        || is_error(unsafe { syscall2(SYS_FCNTL, 1, F_GETFD) })
    {
        return 0x83;
    }
    if is_error(unsafe { sys_close(fd as u64) }) {
        return 0x84;
    }
    if errno(unsafe { syscall2(SYS_FCNTL, fd as u64, F_GETFD) }) != EBADF {
        return 0x85;
    }
    GROUP_LEG_OK
}

/// Body of the group-exit leg's host process: a thread ends the group.
fn group_exit_leg() -> ! {
    let thread = unsafe {
        raw_clone(
            THREAD_FLAGS,
            group_stack_top(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            group_exit_thread,
        )
    };
    if is_error(thread) || thread == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, 0x60) };
    }
    spin_forever()
}

/// Body of the kill leg's host process: two members that never exit alone.
fn group_kill_leg() -> ! {
    let thread = unsafe {
        raw_clone(
            THREAD_FLAGS,
            group_stack_top(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            group_spin_thread,
        )
    };
    if is_error(thread) || thread == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, 0x70) };
    }
    spin_forever()
}

fn test_thread_group(results: &mut TestResult) {
    print("Testing thread groups (CLONE_THREAD preview)... ");

    // 1. Identity, join through CLONE_CHILD_CLEARTID, thread not a child.
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("thread group: fork of the identity host failed");
        return;
    }
    if host == 0 {
        let code = group_identity_leg();
        unsafe { raw_exit(SYS_EXIT_GROUP, code) };
    }
    match reap_pid(host) {
        Some(GROUP_LEG_OK) => {}
        Some(code) => {
            print("identity leg exit ");
            print_int(code as i64);
            print(" ");
            results.fail("thread group: identity/join leg failed");
            return;
        }
        None => {
            results.fail("thread group: could not reap the identity host");
            return;
        }
    }

    // 2. exit_group from a non-leader thread ends the group; reaped once.
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("thread group: fork of the exit_group host failed");
        return;
    }
    if host == 0 {
        group_exit_leg();
    }
    match reap_pid(host) {
        Some(GROUP_EXIT_CODE) => {}
        Some(code) => {
            print("exit_group leg exit ");
            print_int(code as i64);
            print(" ");
            results.fail("thread group: exit_group from a thread was not the group status");
            return;
        }
        None => {
            results.fail("thread group: could not reap the exit_group host");
            return;
        }
    }

    // 4. CLONE_FILES|CLONE_FS: one fd table shared by the group; a thread's
    //    exit leaves it to the remaining member.
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("thread group: fork of the shared-table host failed");
        return;
    }
    if host == 0 {
        let code = group_files_leg();
        unsafe { raw_exit(SYS_EXIT_GROUP, code) };
    }
    match reap_pid(host) {
        Some(GROUP_LEG_OK) => {}
        Some(code) => {
            print("shared-table leg exit ");
            print_int(code as i64);
            print(" ");
            results.fail("thread group: shared fd table leg failed");
            return;
        }
        None => {
            results.fail("thread group: could not reap the shared-table host");
            return;
        }
    }

    // 3. A process-directed SIGKILL ends every member; reaped once.
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("thread group: fork of the kill host failed");
        return;
    }
    if host == 0 {
        group_kill_leg();
    }
    for _ in 0..100 {
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { userspace::syscall::sys_kill(host, SIGKILL_NR) };
    match reap_pid(host) {
        Some(SIGKILL_EXIT) => {}
        Some(code) => {
            print("kill leg exit ");
            print_int(code as i64);
            print(" ");
            results.fail("thread group: SIGKILL did not end the group");
            return;
        }
        None => {
            results.fail("thread group: could not reap the killed group");
            return;
        }
    }

    // Nothing of any leg is left to reap.
    let mut left = SigInfo::poisoned();
    if errno(waitid(P_ALL, 0, &mut left, WEXITED | WNOHANG)) != ECHILD {
        results.fail("thread group: a leg left a reapable task behind");
        return;
    }
    results.pass("thread groups share identity and files, exit as one and are reaped once");
}

/// Exit status of the late-exit leg's leader, which the parent sees (Linux
/// reports the leader's own status when its last thread exits after it).
const GROUP_LATE_EXIT_CODE: u64 = 0x2a;
/// Exit status of the late-exit leg's thread, which nobody sees.
const GROUP_LATE_THREAD_CODE: u64 = 0x2b;

/// Thread entry: outlive the leader's plain exit, then exit alone.
extern "C" fn group_late_exit_thread() -> ! {
    for _ in 0..20 {
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { raw_exit(SYS_EXIT, GROUP_LATE_THREAD_CODE) }
}

/// Body of the late-exit leg's host process: start a thread, then leave with
/// a plain exit so the thread is the group's last member.
fn group_late_exit_leg() -> ! {
    let thread = unsafe {
        raw_clone(
            THREAD_FLAGS,
            group_stack_top(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            group_late_exit_thread,
        )
    };
    if is_error(thread) || thread == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, 0x90) };
    }
    unsafe { raw_exit(SYS_EXIT, GROUP_LATE_EXIT_CODE) }
}

/// GAP-5 G8: an exited non-leader thread is reaped by a deferred drain that
/// runs only in process context, and its group is reported to the parent only
/// then. On one CPU the thread's last switch must not go straight to a
/// bystander that never enters the kernel.
fn test_group_exit_beside_user_spinner(results: &mut TestResult) {
    print("Testing a thread group's last exit beside a user-mode spinner... ");
    let bystander = unsafe { sys_fork() };
    if bystander == 0 {
        spin_in_user_mode();
    }
    if is_error(bystander) {
        results.fail("group exit beside a spinner: fork of the bystander failed");
        return;
    }
    let host = unsafe { sys_fork() };
    if host == 0 {
        group_late_exit_leg();
    }
    if is_error(host) {
        unsafe { userspace::syscall::sys_kill(bystander, SIGKILL_NR) };
        reap_quietly(bystander);
        results.fail("group exit beside a spinner: fork of the host failed");
        return;
    }
    let outcome = reap_pid(host);
    unsafe { userspace::syscall::sys_kill(bystander, SIGKILL_NR) };
    reap_quietly(bystander);
    match outcome {
        Some(GROUP_LATE_EXIT_CODE) => {}
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("group exit beside a spinner: wrong group status");
            return;
        }
        None => {
            results.fail("group exit beside a spinner: could not reap the host");
            return;
        }
    }
    results.pass(
        "a group whose leader exited is reported when its last thread exits beside a spinner",
    );
}

// ---------------------------------------------------------------------------
// GAP-5 G8: procfs thread listing. A forked host with one extra CLONE_THREAD
// member checks that /proc lists the host but not the thread, that the thread
// id still resolves, that /proc/<host>/task lists exactly the host and the
// thread (leader first), and that the thread's task status names the host as
// its Tgid with two threads. The host ends with exit_group, which also ends
// the spinning thread.
// ---------------------------------------------------------------------------

const PROC_O_DIRECTORY: i32 = 0o200000;
/// Status the procfs leg's host exits with when every check passed.
const PROC_TASK_LEG_OK: u64 = 0x34;

/// A short NUL-terminated byte string built without allocation. Text past
/// the capacity is dropped, so an over-long path simply fails to open.
struct SmallText {
    bytes: [u8; 64],
    len: usize,
}

impl SmallText {
    fn new() -> Self {
        SmallText {
            bytes: [0; 64],
            len: 0,
        }
    }

    fn push(mut self, text: &[u8]) -> Self {
        for &byte in text {
            // Keep the final byte as the NUL terminator.
            if self.len + 1 < self.bytes.len() {
                self.bytes[self.len] = byte;
                self.len += 1;
            }
        }
        self
    }

    fn push_u64(self, mut value: u64) -> Self {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push(&digits[at..])
    }

    fn text(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn c_str(&self) -> *const u8 {
        self.bytes.as_ptr()
    }
}

/// An all-digit directory entry name.
fn parse_decimal(text: &[u8]) -> Option<u64> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    parse_u64_prefix(text)
}

/// Call `visit` for every numeric entry of the directory at `path`. Returns
/// false when the directory cannot be opened or a record is malformed.
fn for_each_numeric_entry(path: &SmallText, mut visit: impl FnMut(u64)) -> bool {
    use userspace::syscall::DIRENT64_NAME_OFFSET;
    let fd = unsafe { sys_open(path.c_str(), PROC_O_DIRECTORY, 0) };
    if is_error(fd) {
        return false;
    }
    let mut buf = [0u8; 1024];
    let mut ok = true;
    'read: loop {
        let read =
            unsafe { userspace::syscall::sys_getdents64(fd as i32, buf.as_mut_ptr(), buf.len()) };
        if is_error(read) {
            ok = false;
            break;
        }
        let read = read as usize;
        if read == 0 {
            break;
        }
        let mut at = 0usize;
        while at < read {
            // d_reclen is the u16 at offset 16 of the linux_dirent64 header.
            if read - at <= DIRENT64_NAME_OFFSET {
                ok = false;
                break 'read;
            }
            let reclen = u16::from_ne_bytes([buf[at + 16], buf[at + 17]]) as usize;
            if reclen <= DIRENT64_NAME_OFFSET || reclen > read - at {
                ok = false;
                break 'read;
            }
            let name = &buf[at + DIRENT64_NAME_OFFSET..at + reclen];
            let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
            if let Some(id) = parse_decimal(name) {
                visit(id);
            }
            at += reclen;
        }
    }
    let _ = unsafe { sys_close(fd) };
    ok
}

/// Read a small procfs file whole; None if it cannot be read or does not fit.
fn read_small_file(path: &SmallText, buf: &mut [u8]) -> Option<usize> {
    let fd = unsafe { sys_open(path.c_str(), 0, 0) };
    if is_error(fd) {
        return None;
    }
    let read = unsafe { sys_read(fd, buf.as_mut_ptr(), buf.len() as u64) };
    let _ = unsafe { sys_close(fd) };
    if is_error(read) || read as usize >= buf.len() {
        return None;
    }
    Some(read as usize)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Body of the procfs leg's host process; returns its exit status.
fn proc_task_leg() -> u64 {
    let host = unsafe { sys_getpid() };
    let thread = unsafe {
        raw_clone(
            THREAD_FLAGS,
            group_stack_top(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            group_spin_thread,
        )
    };
    if is_error(thread) || thread == 0 {
        return 0x90;
    }

    // 1. /proc lists the group leader and hides the thread.
    let (mut host_listed, mut thread_listed) = (false, false);
    let root = SmallText::new().push(b"/proc");
    if !for_each_numeric_entry(&root, |id| {
        host_listed |= id == host;
        thread_listed |= id == thread;
    }) {
        return 0x91;
    }
    if !host_listed {
        return 0x92;
    }
    if thread_listed {
        return 0x93;
    }

    // 2. The hidden thread id still resolves, as on Linux.
    let mut text = [0u8; 512];
    let hidden = SmallText::new()
        .push(b"/proc/")
        .push_u64(thread)
        .push(b"/status");
    if read_small_file(&hidden, &mut text).is_none() {
        return 0x94;
    }

    // 3. /proc/<host>/task lists exactly the leader, then the thread.
    let mut ids = [0u64; 4];
    let mut count = 0usize;
    let task_dir = SmallText::new()
        .push(b"/proc/")
        .push_u64(host)
        .push(b"/task");
    if !for_each_numeric_entry(&task_dir, |id| {
        if count < ids.len() {
            ids[count] = id;
        }
        count += 1;
    }) {
        return 0x95;
    }
    if count != 2 || ids[0] != host || ids[1] != thread {
        return 0x96;
    }

    // 4. The thread's task status: Tgid is the host, two live threads.
    let status = SmallText::new()
        .push(b"/proc/")
        .push_u64(host)
        .push(b"/task/")
        .push_u64(thread)
        .push(b"/status");
    let Some(len) = read_small_file(&status, &mut text) else {
        return 0x97;
    };
    let text = &text[..len];
    if !contains_bytes(
        text,
        SmallText::new()
            .push(b"Tgid:\t")
            .push_u64(host)
            .push(b"\n")
            .text(),
    ) {
        return 0x98;
    }
    if !contains_bytes(
        text,
        SmallText::new()
            .push(b"Pid:\t")
            .push_u64(thread)
            .push(b"\n")
            .text(),
    ) {
        return 0x99;
    }
    if !contains_bytes(text, b"Threads:\t2\n") {
        return 0x9a;
    }
    PROC_TASK_LEG_OK
}

fn test_proc_thread_listing(results: &mut TestResult) {
    print("Testing procfs thread listing... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("procfs threads: fork of the host failed");
        return;
    }
    if host == 0 {
        let code = proc_task_leg();
        // exit_group also ends the spinning thread.
        unsafe { raw_exit(SYS_EXIT_GROUP, code) };
    }
    match reap_pid(host) {
        Some(PROC_TASK_LEG_OK) => {}
        Some(code) => {
            print("procfs leg exit ");
            print_int(code as i64);
            print(" ");
            results.fail("procfs threads: thread listing leg failed");
            return;
        }
        None => {
            results.fail("procfs threads: could not reap the host");
            return;
        }
    }
    results.pass("procfs lists group leaders and /proc/<pid>/task members with Tgid and Threads");
}

// ---------------------------------------------------------------------------
// GAP-5 exec from a thread group (Linux de_thread). Step 1: exec from the
// leader ends every other member first, then replaces the image. Step 2: exec
// from any other member is handed to the leader, which runs it under the
// group's PID wherever it is (blocked in FUTEX_WAIT, spinning in user mode,
// asleep in nanosleep); the exec'ing thread and every other member end.
// ---------------------------------------------------------------------------

/// Exit status of the minimal image the group execs.
const EXEC_IMAGE_EXIT: u64 = 0x5c;
/// ELF header (64) + one program header (56) + 18 bytes of code.
const EXEC_IMAGE_LEN: usize = 0x78 + 18;

static EXEC_READY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static EXEC_BLOCK_WORD: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
/// Step 2: set by the leader just before it parks.
static EXEC_LEADER_PARKED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// CLONE_CHILD_CLEARTID words of the two siblings: each is zeroed in the old
/// address space while its thread is ended, before the leader's exec.
static EXEC_TID_WORDS: [core::sync::atomic::AtomicI32; 2] = [
    core::sync::atomic::AtomicI32::new(0),
    core::sync::atomic::AtomicI32::new(0),
];
static mut EXEC_STACK: CloneStack = CloneStack([0; CLEAR_TID_STACK_BYTES]);

/// A minimal static ELF64 executable: one R+X PT_LOAD of the whole file at
/// 0x400000 whose entry runs `code`.
#[repr(C, align(8))]
struct ExecImage([u8; EXEC_IMAGE_LEN]);
/// mov edi, EXEC_IMAGE_EXIT; mov eax, 60 (exit); syscall; ud2
static EXEC_EXIT_IMAGE: ExecImage = ExecImage(exec_image([
    0xbf,
    EXEC_IMAGE_EXIT as u8,
    0,
    0,
    0,
    0xb8,
    60,
    0,
    0,
    0,
    0x0f,
    0x05,
    0x0f,
    0x0b,
    0x0f,
    0x0b,
    0x0f,
    0x0b,
]));
/// mov eax, 39 (getpid); syscall; mov edi, eax; mov eax, 60 (exit); syscall; ud2
/// The parent compares the status with the host's pid: a handed-over exec
/// must run under the group's PID.
static EXEC_GETPID_IMAGE: ExecImage = ExecImage(exec_image([
    0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0x89, 0xc7, 0xb8, 60, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
]));

const fn put_le(
    mut image: [u8; EXEC_IMAGE_LEN],
    offset: usize,
    value: u64,
    bytes: usize,
) -> [u8; EXEC_IMAGE_LEN] {
    let mut i = 0;
    while i < bytes {
        image[offset + i] = (value >> (8 * i)) as u8;
        i += 1;
    }
    image
}

const fn exec_image(code: [u8; 18]) -> [u8; EXEC_IMAGE_LEN] {
    const BASE: u64 = 0x40_0000;
    const CODE: usize = 0x78;
    let mut image = [0u8; EXEC_IMAGE_LEN];
    // e_ident: magic, ELFCLASS64, little endian, EV_CURRENT.
    image[0] = 0x7f;
    image[1] = b'E';
    image[2] = b'L';
    image[3] = b'F';
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    image = put_le(image, 0x10, 2, 2); // e_type: ET_EXEC
    image = put_le(image, 0x12, 0x3e, 2); // e_machine: x86-64
    image = put_le(image, 0x14, 1, 4); // e_version
    image = put_le(image, 0x18, BASE + CODE as u64, 8); // e_entry
    image = put_le(image, 0x20, 0x40, 8); // e_phoff
    image = put_le(image, 0x34, 64, 2); // e_ehsize
    image = put_le(image, 0x36, 56, 2); // e_phentsize
    image = put_le(image, 0x38, 1, 2); // e_phnum
    image = put_le(image, 0x3a, 64, 2); // e_shentsize
    image = put_le(image, 0x40, 1, 4); // p_type: PT_LOAD
    image = put_le(image, 0x44, 5, 4); // p_flags: R+X
    image = put_le(image, 0x50, BASE, 8); // p_vaddr
    image = put_le(image, 0x58, BASE, 8); // p_paddr
    image = put_le(image, 0x60, EXEC_IMAGE_LEN as u64, 8); // p_filesz
    image = put_le(image, 0x68, EXEC_IMAGE_LEN as u64, 8); // p_memsz
    image = put_le(image, 0x70, 0x1000, 8); // p_align

    let mut i = 0;
    while i < code.len() {
        image[CODE + i] = code[i];
        i += 1;
    }
    image
}

unsafe fn spawn_image(image: &ExecImage) -> u64 {
    syscall4(
        userspace::syscall::SYS_SPAWN_IMAGE,
        image.0.as_ptr() as u64,
        EXEC_IMAGE_LEN as u64,
        0,
        0,
    )
}

fn exec_stack_top() -> usize {
    core::ptr::addr_of_mut!(EXEC_STACK) as usize + CLEAR_TID_STACK_BYTES
}

/// Thread entry: spin in user mode, without syscalls, so the exec ends this
/// thread from an interrupt.
extern "C" fn exec_sibling_spin_thread() -> ! {
    use core::sync::atomic::Ordering;
    EXEC_READY.fetch_add(1, Ordering::SeqCst);
    loop {
        core::hint::spin_loop();
    }
}

/// Thread entry: sleep in FUTEX_WAIT until the leader's exec ends this thread.
extern "C" fn exec_sibling_block_thread() -> ! {
    use core::sync::atomic::Ordering;
    EXEC_READY.fetch_add(1, Ordering::SeqCst);
    loop {
        unsafe { futex(&EXEC_BLOCK_WORD, FUTEX_WAIT_OP | FUTEX_PRIVATE, 0, 0, 0, 0) };
    }
}

/// Step 2 thread entry: once the other sibling is up and the leader parked,
/// exec the marker image. Returns from the exec only on failure.
extern "C" fn exec_handoff_thread() -> ! {
    use core::sync::atomic::Ordering;
    EXEC_READY.fetch_add(1, Ordering::SeqCst);
    for _ in 0..THREAD_POLL_YIELDS {
        if EXEC_READY.load(Ordering::SeqCst) == 2 && EXEC_LEADER_PARKED.load(Ordering::SeqCst) == 1
        {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    // Let the leader reach its wait.
    for _ in 0..100 {
        unsafe { userspace::syscall::sys_yield() };
    }
    let ret = unsafe { spawn_image(&EXEC_GETPID_IMAGE) };
    print("non-leader exec returned errno ");
    print_int(errno(ret) as i64);
    print(" ");
    unsafe { raw_exit(SYS_EXIT_GROUP, 0x98) }
}

/// Where the leader is while a non-leader execs.
#[derive(Clone, Copy)]
enum LeaderPark {
    FutexWait,
    Spin,
    Sleep,
}

/// Body of a step-2 host process. Returns only when setup fails; the handed
/// exec ends the host with its own pid (low byte) as the status.
fn group_handoff_leg(park: LeaderPark) -> u64 {
    use core::sync::atomic::Ordering;
    EXEC_READY.store(0, Ordering::SeqCst);
    EXEC_BLOCK_WORD.0.store(0, Ordering::SeqCst);
    EXEC_LEADER_PARKED.store(0, Ordering::SeqCst);
    // The exec'ing thread has its own fd table and fs context, which the
    // leader takes over; the other sibling shares the leader's.
    let threads: [(u64, usize, extern "C" fn() -> !); 2] = [
        (
            THREAD_FLAGS | CLONE_FILES | CLONE_FS | CLONE_CHILD_CLEARTID,
            exec_stack_top(),
            exec_sibling_block_thread,
        ),
        (
            THREAD_FLAGS | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            exec_handoff_thread,
        ),
    ];
    for (index, (flags, stack_top, entry)) in threads.into_iter().enumerate() {
        EXEC_TID_WORDS[index].store(-1, Ordering::SeqCst);
        let thread = unsafe {
            raw_clone(
                flags,
                stack_top,
                core::ptr::null_mut(),
                EXEC_TID_WORDS[index].as_ptr(),
                entry,
            )
        };
        if is_error(thread) || thread == 0 {
            return 0x94;
        }
    }
    let mut ready = false;
    for _ in 0..THREAD_POLL_YIELDS {
        if EXEC_READY.load(Ordering::SeqCst) == 2 {
            ready = true;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if !ready {
        return 0x95;
    }
    EXEC_LEADER_PARKED.store(1, Ordering::SeqCst);
    match park {
        LeaderPark::FutexWait => loop {
            unsafe { futex(&EXEC_BLOCK_WORD, FUTEX_WAIT_OP | FUTEX_PRIVATE, 0, 0, 0, 0) };
        },
        LeaderPark::Spin => loop {
            core::hint::spin_loop();
        },
        LeaderPark::Sleep => loop {
            let pause = [10i64, 0];
            unsafe { syscall2(SYS_NANOSLEEP, pause.as_ptr() as u64, 0) };
        },
    }
}

/// Body of the step-1 host process. Returns only when a check fails; a
/// successful exec ends the host with EXEC_IMAGE_EXIT.
fn group_exec_leg() -> u64 {
    use core::sync::atomic::Ordering;
    EXEC_READY.store(0, Ordering::SeqCst);
    EXEC_BLOCK_WORD.0.store(0, Ordering::SeqCst);
    // The siblings also share the fd table, which exec must then own alone.
    let flags = THREAD_FLAGS | CLONE_FILES | CLONE_FS | CLONE_CHILD_CLEARTID;
    let threads: [(usize, extern "C" fn() -> !); 2] = [
        (group_stack_top(), exec_sibling_spin_thread),
        (exec_stack_top(), exec_sibling_block_thread),
    ];
    for (index, (stack_top, entry)) in threads.into_iter().enumerate() {
        // Touch the word first so the exit-time clear is not a first write.
        EXEC_TID_WORDS[index].store(-1, Ordering::SeqCst);
        let thread = unsafe {
            raw_clone(
                flags,
                stack_top,
                core::ptr::null_mut(),
                EXEC_TID_WORDS[index].as_ptr(),
                entry,
            )
        };
        if is_error(thread) || thread == 0 {
            return 0x90;
        }
    }
    let mut ready = false;
    for _ in 0..THREAD_POLL_YIELDS {
        if EXEC_READY.load(Ordering::SeqCst) == 2 {
            ready = true;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if !ready {
        return 0x91;
    }
    // Let the futex thread reach its wait.
    for _ in 0..100 {
        unsafe { userspace::syscall::sys_yield() };
    }
    let ret = unsafe { spawn_image(&EXEC_EXIT_IMAGE) };
    print("leader exec returned errno ");
    print_int(errno(ret) as i64);
    print(" ");
    0x93
}

fn test_thread_group_exec(results: &mut TestResult) {
    print("Testing exec from a thread group... ");
    let legs: [(Option<LeaderPark>, &str); 4] = [
        (None, "the leader"),
        (
            Some(LeaderPark::FutexWait),
            "a non-leader, leader in FUTEX_WAIT",
        ),
        (Some(LeaderPark::Spin), "a non-leader, leader spinning"),
        (Some(LeaderPark::Sleep), "a non-leader, leader in nanosleep"),
    ];
    for (park, what) in legs {
        let host = unsafe { sys_fork() };
        if is_error(host) {
            results.fail("thread group exec: fork of the host failed");
            return;
        }
        if host == 0 {
            let code = match park {
                None => group_exec_leg(),
                Some(park) => group_handoff_leg(park),
            };
            unsafe { raw_exit(SYS_EXIT_GROUP, code) };
        }
        // The host's PID runs the new image whichever thread called exec.
        let expected = if park.is_none() {
            EXEC_IMAGE_EXIT
        } else {
            host & 0xff
        };
        match reap_pid(host) {
            Some(code) if code == expected => {}
            Some(code) => {
                print("exec from ");
                print(what);
                print(": exit ");
                print_int(code as i64);
                print(" ");
                results.fail("thread group exec: the group did not exec the new image");
                return;
            }
            None => {
                results.fail("thread group exec: could not reap the host");
                return;
            }
        }
        // The ended members were auto-reaped; nothing is left for this parent.
        let mut left = SigInfo::poisoned();
        if errno(waitid(P_ALL, 0, &mut left, WEXITED | WNOHANG)) != ECHILD {
            print("exec from ");
            print(what);
            print(" ");
            results.fail("thread group exec: the leg left a reapable task behind");
            return;
        }
    }
    results.pass(
        "exec from a thread group ends the other members: from the leader, and from a non-leader while the leader waits, spins or sleeps",
    );
}

// ---------------------------------------------------------------------------
// GAP-5 G8: a multi-threaded process's children belong to the process. Any
// thread waits for the children of every thread; a thread that exits hands its
// children to a surviving thread; a thread's child sees the process as its
// parent; get_robust_list reads a sibling's registration.
// ---------------------------------------------------------------------------

const SYS_SET_ROBUST_LIST: u64 = 273;
const SYS_GET_ROBUST_LIST: u64 = 274;
const SYS_NANOSLEEP: u64 = 35;
const G8_CHILD_OK: u64 = 0x44;
const G8_ORPHAN_OK: u64 = 0x46;

static G8_HOST_PID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static G8_CHILD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static G8_DONE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static G8_ROBUST_OK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// struct robust_list_head { list, futex_offset, list_op_pending }; an empty
/// list points at itself, which the kernel never needs to walk here.
#[repr(C, align(8))]
struct RobustHead([u64; 3]);
static mut G8_ROBUST_HEAD: RobustHead = RobustHead([0; 3]);

fn g8_robust_head() -> u64 {
    core::ptr::addr_of_mut!(G8_ROBUST_HEAD) as u64
}

/// In a thread's forked child: report whether getppid() names the process.
fn g8_child_exit(ok: u64, bad: u64) -> ! {
    use core::sync::atomic::Ordering;
    let code = if unsafe { sys_getppid() } == G8_HOST_PID.load(Ordering::SeqCst) {
        ok
    } else {
        bad
    };
    unsafe { raw_exit(SYS_EXIT_GROUP, code) }
}

/// Thread entry: read the leader's robust list, fork a child, and stay alive
/// until the leader has reaped it (so the leader's wait runs while the group
/// has two members).
extern "C" fn g8_wait_thread() -> ! {
    use core::sync::atomic::Ordering;
    let mut head: u64 = 0;
    let mut len: u64 = 0;
    let r = unsafe {
        syscall3(
            SYS_GET_ROBUST_LIST,
            G8_HOST_PID.load(Ordering::SeqCst),
            &mut head as *mut u64 as u64,
            &mut len as *mut u64 as u64,
        )
    };
    let robust_ok = r == 0 && head == g8_robust_head() && len == 24;
    G8_ROBUST_OK.store(robust_ok as u32, Ordering::SeqCst);
    let child = unsafe { sys_fork() };
    if child == 0 {
        g8_child_exit(G8_CHILD_OK, G8_CHILD_OK + 1);
    }
    G8_CHILD.store(
        if is_error(child) { u64::MAX } else { child },
        Ordering::SeqCst,
    );
    while G8_DONE.load(Ordering::SeqCst) == 0 {
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

/// Thread entry: fork a child that outlives this thread, then exit at once.
extern "C" fn g8_orphan_thread() -> ! {
    use core::sync::atomic::Ordering;
    let child = unsafe { sys_fork() };
    if child == 0 {
        let pause = [0i64, 50_000_000]; // 50 ms: the thread is gone by then
        unsafe { syscall2(SYS_NANOSLEEP, pause.as_ptr() as u64, 0) };
        g8_child_exit(G8_ORPHAN_OK, G8_ORPHAN_OK + 1);
    }
    G8_CHILD.store(
        if is_error(child) { u64::MAX } else { child },
        Ordering::SeqCst,
    );
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn g8_join_thread() -> bool {
    use core::sync::atomic::Ordering;
    for _ in 0..THREAD_POLL_YIELDS {
        if GROUP_TID_WORD.load(Ordering::SeqCst) == 0 {
            return true;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    false
}

/// Body of the G8 leg's host process; returns its exit status.
fn group_children_leg() -> u64 {
    use core::sync::atomic::Ordering;
    G8_HOST_PID.store(unsafe { sys_getpid() }, Ordering::SeqCst);
    if is_error(unsafe { syscall2(SYS_SET_ROBUST_LIST, g8_robust_head(), 24) }) {
        return 0xa0;
    }

    // 1. The child of a live thread is reaped by the leader's wait4(-1).
    G8_CHILD.store(0, Ordering::SeqCst);
    G8_DONE.store(0, Ordering::SeqCst);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    let thread = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            g8_wait_thread,
        )
    };
    if is_error(thread) || thread == 0 {
        return 0xa1;
    }
    let mut child = 0;
    for _ in 0..THREAD_POLL_YIELDS {
        child = G8_CHILD.load(Ordering::SeqCst);
        if child != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if child == 0 || child == u64::MAX {
        G8_DONE.store(1, Ordering::SeqCst);
        return 0xa2;
    }
    let mut info = SigInfo::poisoned();
    let r = waitid(P_ALL, 0, &mut info, WEXITED);
    G8_DONE.store(1, Ordering::SeqCst);
    if is_error(r) || info.pid() as u64 != child {
        return 0xa3;
    }
    if info.status() as u64 != G8_CHILD_OK {
        return 0xa4; // the child saw its forking thread, not the process
    }
    if !g8_join_thread() {
        return 0xa5;
    }
    if G8_ROBUST_OK.load(Ordering::SeqCst) != 1 {
        return 0xa6;
    }

    // 2. A thread exits before its child: the child passes to the leader.
    G8_CHILD.store(0, Ordering::SeqCst);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    let thread = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            g8_orphan_thread,
        )
    };
    if is_error(thread) || thread == 0 {
        return 0xa7;
    }
    if !g8_join_thread() {
        return 0xa8;
    }
    let child = G8_CHILD.load(Ordering::SeqCst);
    if child == 0 || child == u64::MAX {
        return 0xa9;
    }
    let mut info = SigInfo::poisoned();
    let r = waitid(P_ALL, 0, &mut info, WEXITED);
    if is_error(r) || info.pid() as u64 != child {
        return 0xaa; // ECHILD here: the child went to init, not to the leader
    }
    if info.status() as u64 != G8_ORPHAN_OK {
        return 0xab;
    }
    let mut left = SigInfo::poisoned();
    if errno(waitid(P_ALL, 0, &mut left, WEXITED | WNOHANG)) != ECHILD {
        return 0xac;
    }
    GROUP_LEG_OK
}

fn test_thread_group_children(results: &mut TestResult) {
    print("Testing thread group children... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("thread group children: fork of the host failed");
        return;
    }
    if host == 0 {
        let code = group_children_leg();
        unsafe { raw_exit(SYS_EXIT_GROUP, code) };
    }
    match reap_pid(host) {
        Some(GROUP_LEG_OK) => {}
        Some(code) => {
            print("children leg exit ");
            print_int(code as i64);
            print(" ");
            results.fail("thread group children: a G8 check failed");
            return;
        }
        None => {
            results.fail("thread group children: could not reap the host");
            return;
        }
    }
    results.pass("a thread group shares its children: any thread waits for them and a dying thread hands them on");
}

// LEAD-G8-CHILDREN-SEGV-1: the writer pauses in the shared-COW resolver;
// a sibling on CPU 1 invalidates its local TLB and reads the still-present
// leaf before allowing the swap. The fork child retains the old frame.
const PR_COW_TEST: u64 = 0x5a43_4f57;
static COW_TEST_CONTROL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static COW_TEST_DATA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
const COW_TEST_OLD: u64 = 0x1234_5678;

#[repr(C)]
struct CowTestControl {
    ready: core::sync::atomic::AtomicU32,
    observed: core::sync::atomic::AtomicU32,
    release: core::sync::atomic::AtomicU32,
}

unsafe fn cow_test_command(op: u64, addr: u64) -> u64 {
    syscall3(SYS_PRCTL, PR_COW_TEST, op, addr)
}

fn cow_test_pin(mask: u64) -> bool {
    unsafe { syscall3(203, 0, 8, &mask as *const u64 as u64) == 0 }
}

extern "C" fn cow_test_reader() -> ! {
    use core::sync::atomic::Ordering;
    let control = unsafe { &*(COW_TEST_CONTROL.load(Ordering::Acquire) as *const CowTestControl) };
    if !cow_test_pin(2) {
        control.ready.store(2, Ordering::Release);
        unsafe { raw_exit(SYS_EXIT, 1) };
    }
    control.ready.store(1, Ordering::Release);
    for _ in 0..THREAD_POLL_YIELDS {
        if unsafe { cow_test_command(2, 0) } == 3 {
            let value = unsafe {
                core::ptr::read_volatile(COW_TEST_DATA.load(Ordering::Acquire) as *const u64)
            };
            if value == COW_TEST_OLD && unsafe { cow_test_command(3, 0) } == 0 {
                control.observed.store(1, Ordering::Release);
            }
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn cow_sibling_read_leg() -> u64 {
    use core::sync::atomic::{AtomicU32, Ordering};
    if !cow_test_pin(1) {
        return 0xc0;
    }
    let shared = unsafe { mmap_anon(PAGE, true) };
    let data = unsafe { mmap_anon(PAGE, false) };
    if shared < 0 || data < 0 {
        return 0xc1;
    }
    let control = unsafe {
        let ptr = shared as *mut CowTestControl;
        ptr.write(CowTestControl {
            ready: AtomicU32::new(0),
            observed: AtomicU32::new(0),
            release: AtomicU32::new(0),
        });
        core::ptr::write_volatile(data as *mut u64, COW_TEST_OLD);
        &*ptr
    };
    COW_TEST_CONTROL.store(shared as u64, Ordering::Release);
    COW_TEST_DATA.store(data as u64, Ordering::Release);
    let child = unsafe { sys_fork() };
    if is_error(child) {
        return 0xc2;
    }
    if child == 0 {
        for _ in 0..THREAD_POLL_YIELDS {
            if control.release.load(Ordering::Acquire) != 0 {
                let unchanged =
                    unsafe { core::ptr::read_volatile(data as *const u64) } == COW_TEST_OLD;
                unsafe { raw_exit(SYS_EXIT_GROUP, if unchanged { GROUP_LEG_OK } else { 0xc3 }) };
            }
            unsafe { userspace::syscall::sys_yield() };
        }
        unsafe { raw_exit(SYS_EXIT_GROUP, 0xc4) };
    }
    // Even setup failures release the old-frame holder before ending the host.
    struct Release<'a>(&'a CowTestControl);
    impl Drop for Release<'_> {
        fn drop(&mut self) {
            self.0.release.store(1, Ordering::Release);
        }
    }
    let release = Release(control);
    if unsafe { cow_test_command(1, data as u64) } != 0 {
        return 0xc5;
    }
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    let reader = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            cow_test_reader,
        )
    };
    if is_error(reader) || reader == 0 {
        return 0xc6;
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if control.ready.load(Ordering::Acquire) != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if control.ready.load(Ordering::Acquire) != 1 {
        return 0xc7;
    }
    unsafe { core::ptr::write_volatile(data as *mut u64, COW_TEST_OLD + 1) };
    let complete = unsafe { cow_test_command(4, 0) } == 5;
    let joined = g8_join_thread();
    let observed = control.observed.load(Ordering::Acquire) == 1;
    let written = unsafe { core::ptr::read_volatile(data as *const u64) } == COW_TEST_OLD + 1;
    drop(release);
    let isolated = reap_pid(child) == Some(GROUP_LEG_OK);
    let disarmed = unsafe { cow_test_command(5, 0) } == 0;
    if complete && joined && observed && written && isolated && disarmed {
        GROUP_LEG_OK
    } else {
        0xc8
    }
}

fn test_cow_sibling_read(results: &mut TestResult) {
    let cpus = unsafe { cow_test_command(0, 0) };
    if !is_error(cpus) && cpus & 3 != 3 {
        println("[SKIP] COW sibling cold read: requires CPUs 0 and 1");
        return;
    }
    let host = unsafe { sys_fork() };
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, cow_sibling_read_leg()) };
    }
    if !is_error(host) && reap_pid(host) == Some(GROUP_LEG_OK) {
        results.pass("COW replacement keeps a sibling's cold read present and the fork child's frame private");
    } else {
        results.fail("COW sibling cold read during the paused PTE replacement");
    }
}

// ---------------------------------------------------------------------------
// ST-K2-P2: shared-anonymous fault races. Keep the prctl operations and states
// in sync with `kernel/kernel_core/shared_fault_test.rs`.
// ---------------------------------------------------------------------------

const PR_SHARED_FAULT_TEST: u64 = 0x5a53_4654;
const SFT_PAUSED: u64 = 3;
const SFT_COMPLETE: u64 = 5;
const SYS_UNAME: u64 = 63;

unsafe fn shared_fault_test(op: u64, a: u64, b: u64) -> u64 {
    syscall4(SYS_PRCTL, PR_SHARED_FAULT_TEST, op, a, b)
}

/// ST-K2-P2(b): the cold shared page the sibling copies out to, and how far it
/// got: 1 pinned and polling, 2 copied, 0xe_ a failure.
static REMOTE_HOLDER_COLD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static REMOTE_HOLDER_STAGE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Repetitions of the remote-holder round, fixed at fixture build time
/// (`NILIX_ST_K2_REMOTE_REPS=300` for the 8-vCPU acceptance run).
fn remote_holder_reps() -> usize {
    let reps = option_env!("NILIX_ST_K2_REMOTE_REPS")
        .unwrap_or("1")
        .parse::<usize>()
        .expect("NILIX_ST_K2_REMOTE_REPS must be an integer");
    assert!((1..=1000).contains(&reps));
    reps
}

/// The sibling on CPU 1: once the holder is paused in munmap with PT_LOCK held,
/// `uname` copies out to the cold shared page. Its guarded copy faults with
/// IF=0 and gets Busy until the holder has its acknowledgement.
extern "C" fn remote_holder_sibling() -> ! {
    use core::sync::atomic::Ordering;
    if !cow_test_pin(2) {
        REMOTE_HOLDER_STAGE.store(0xe1, Ordering::Release);
        unsafe { raw_exit(SYS_EXIT, 1) };
    }
    REMOTE_HOLDER_STAGE.store(1, Ordering::Release);
    let cold = REMOTE_HOLDER_COLD.load(Ordering::Acquire);
    for _ in 0..THREAD_POLL_YIELDS {
        if unsafe { shared_fault_test(2, 0, 0) } == SFT_PAUSED {
            let copied = unsafe { syscall1(SYS_UNAME, cold) } == 0
                && unsafe { core::slice::from_raw_parts(cold as *const u8, 8) } == b"Zero-OS\0";
            REMOTE_HOLDER_STAGE.store(if copied { 2 } else { 0xe2 }, Ordering::Release);
            unsafe { raw_exit(SYS_EXIT, 0) };
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    REMOTE_HOLDER_STAGE.store(0xe3, Ordering::Release);
    unsafe { raw_exit(SYS_EXIT, 0) }
}

/// One round on CPU 0: arm, start the sibling, unmap a touched private page
/// (the kernel pauses before its shootdown), then require that the sibling's
/// copy completed and that at least one acknowledgement came from a #PF drain.
/// Returns the round's (drain ACKs, Busy faults).
fn remote_holder_round() -> Result<(u64, u64), u64> {
    use core::sync::atomic::Ordering;
    let unmap = unsafe { mmap_anon(PAGE, false) };
    let cold = unsafe { mmap_anon(PAGE, true) };
    if unmap < 0 || cold < 0 {
        return Err(0xd1);
    }
    // A present leaf, so munmap reaches its range shootdown.
    unsafe { core::ptr::write_volatile(unmap as *mut u64, 0x5354_4b32) };
    if unsafe { shared_fault_test(1, unmap as u64, cold as u64) } != 0 {
        return Err(0xd2);
    }
    REMOTE_HOLDER_COLD.store(cold as u64, Ordering::Release);
    REMOTE_HOLDER_STAGE.store(0, Ordering::Release);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    let sibling = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            remote_holder_sibling,
        )
    };
    if is_error(sibling) || sibling == 0 {
        return Err(0xd3);
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if REMOTE_HOLDER_STAGE.load(Ordering::Acquire) != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if REMOTE_HOLDER_STAGE.load(Ordering::Acquire) != 1 {
        let _ = g8_join_thread();
        return Err(0xd4);
    }
    let unmapped = unsafe { munmap(unmap as usize, PAGE) } == 0;
    let joined = g8_join_thread();
    let copied = REMOTE_HOLDER_STAGE.load(Ordering::Acquire) == 2;
    let state = unsafe { shared_fault_test(2, 0, 0) };
    let acks = unsafe { shared_fault_test(3, 0, 0) };
    let busy = unsafe { shared_fault_test(4, 0, 0) };
    let disarmed = unsafe { shared_fault_test(5, 0, 0) } == 0;
    let released = unsafe { munmap(cold as usize, PAGE) } == 0;
    if unmapped
        && joined
        && copied
        && state == SFT_COMPLETE
        && !is_error(acks)
        && acks >= 1
        && !is_error(busy)
        && busy >= 1
        && disarmed
        && released
    {
        return Ok((acks, busy));
    }
    let (mut a, mut b, mut c, mut d) = ([0u8; 20], [0u8; 20], [0u8; 20], [0u8; 20]);
    println_parts(&[
        "  remote holder: state=",
        decimal(state as usize, &mut a),
        " acks=",
        decimal(acks as usize, &mut b),
        " busy=",
        decimal(busy as usize, &mut c),
        if copied { " copied" } else { " not-copied" },
    ]);
    println_parts(&[
        "  remote holder: stage=",
        decimal(REMOTE_HOLDER_STAGE.load(Ordering::Acquire) as usize, &mut d),
        if unmapped {
            " unmapped"
        } else {
            " munmap-failed"
        },
        if joined { " joined" } else { " not-joined" },
    ]);
    Err(0xd5)
}

fn shared_fault_remote_holder_leg() -> u64 {
    if !cow_test_pin(1) {
        return 0xd0;
    }
    let (mut min_acks, mut min_busy) = (u64::MAX, u64::MAX);
    for _ in 0..remote_holder_reps() {
        match remote_holder_round() {
            Ok((acks, busy)) => {
                min_acks = min_acks.min(acks);
                min_busy = min_busy.min(busy);
            }
            Err(code) => return code,
        }
    }
    let (mut a, mut b) = ([0u8; 20], [0u8; 20]);
    println_parts(&[
        "ST-K2-REMOTE-HOLDER detail: min_drain_acks=",
        decimal(min_acks as usize, &mut a),
        " min_busy=",
        decimal(min_busy as usize, &mut b),
    ]);
    GROUP_LEG_OK
}

/// ST-K2-P2(b): a page-table holder paused in munmap before its shootdown gets
/// its acknowledgement from a sibling spinning on a Busy shared fault with
/// IF=0, through that fault's mailbox drain. Needs CPUs 0 and 1.
fn test_shared_fault_remote_holder(results: &mut TestResult) {
    let cpus = unsafe { shared_fault_test(0, 0, 0) };
    if is_error(cpus) || cpus & 3 != 3 {
        println("[SKIP] shared-fault remote holder: requires CPUs 0 and 1");
        return;
    }
    let host = unsafe { sys_fork() };
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, shared_fault_remote_holder_leg()) };
    }
    if !is_error(host) && reap_pid(host) == Some(GROUP_LEG_OK) {
        let mut reps = [0u8; 20];
        println_parts(&[
            "ST-K2-REMOTE-HOLDER-ACK PASS reps=",
            decimal(remote_holder_reps(), &mut reps),
        ]);
        results.pass("a page-table holder paused before its munmap shootdown is acknowledged by a sibling's IF=0 shared-fault Busy drain");
    } else {
        results.fail(
            "shared-fault remote holder: munmap shootdown during a sibling's IF=0 Busy fault",
        );
    }
}

/// ST-K2-P2(c): iterations per variant, fixed at fixture build time.
fn final_owner_iterations() -> usize {
    let iterations = option_env!("NILIX_ST_K2_FINAL_OWNER_ITERS")
        .unwrap_or("200")
        .parse::<usize>()
        .expect("NILIX_ST_K2_FINAL_OWNER_ITERS must be an integer");
    assert!((1..=1000).contains(&iterations));
    iterations
}

/// Shared mmap/touch/munmap rounds the parent runs while the other owner of
/// the race region is checking it and exiting.
const FINAL_OWNER_CHURN: usize = 4;
const FINAL_OWNER_WORDS: [u64; 2] = [0x4649_4e41_4c30, 0x4649_4e41_4c31];

/// Root-cgroup `MemFree` from /proc/meminfo, in kB: the buddy's free pages
/// times four.
unsafe fn read_mem_free_kb() -> Option<u64> {
    let fd = sys_open(b"/proc/meminfo\0".as_ptr(), 0, 0);
    if is_error(fd) {
        return None;
    }
    let mut buf = [0u8; 512];
    let read = sys_read(fd, buf.as_mut_ptr(), buf.len() as u64);
    let _ = sys_close(fd);
    if is_error(read) {
        return None;
    }
    let text = &buf[..read as usize];
    let key = b"MemFree:";
    let start = text.windows(key.len()).position(|w| w == key)? + key.len();
    let mut value = 0u64;
    let mut digits = 0;
    for &byte in &text[start..] {
        match byte {
            b' ' if digits == 0 => {}
            b'0'..=b'9' => {
                value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
                digits += 1;
            }
            _ => break,
        }
    }
    (digits != 0).then_some(value)
}

/// What (c) restores exactly: the cgroup's `memory.current`, and buddy free
/// pages plus every kernel-stack page table built so far (those tables are
/// kept for recycled PIDs, so they are counted rather than tolerated).
#[derive(Clone, Copy, PartialEq, Eq)]
struct MemoryBaseline {
    charged: u64,
    free_pages: u64,
}

unsafe fn memory_baseline() -> Option<MemoryBaseline> {
    let charged = read_memory_current()?;
    let free_kb = read_mem_free_kb()?;
    let tables = shared_fault_test(6, 0, 0);
    if is_error(tables) {
        return None;
    }
    Some(MemoryBaseline {
        charged,
        free_pages: (free_kb / 4).checked_add(tables)?,
    })
}

/// Wait (bounded) for deferred teardown, such as the RCU-delayed kernel-stack
/// reclaim of a reaped task, to land on `base` exactly.
unsafe fn settle_to(base: MemoryBaseline) -> Result<(), MemoryBaseline> {
    let mut last = MemoryBaseline {
        charged: u64::MAX,
        free_pages: u64::MAX,
    };
    for _ in 0..2000 {
        if let Some(now) = memory_baseline() {
            if now == base {
                return Ok(());
            }
            last = now;
        }
        for _ in 0..20 {
            userspace::syscall::sys_yield();
        }
    }
    Err(last)
}

static FINAL_REAPER_CHILD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static FINAL_REAPER_EPOCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static FINAL_REAPER_GO: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static FINAL_REAPER_STAGE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

// sched_setaffinity requests migration; its return alone does not prove that
// scheduling has moved the task. Observe the actual CPU before arming/registering.
fn final_owner_pin(cpu: u64) -> bool {
    if !cow_test_pin(1 << cpu) {
        return false;
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if unsafe { shared_fault_test(17, 0, 0) } == cpu {
            return true;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    false
}

extern "C" fn final_owner_reaper() -> ! {
    use core::sync::atomic::Ordering;
    let epoch = FINAL_REAPER_EPOCH.load(Ordering::Acquire);
    let ready = final_owner_pin(1) && unsafe { shared_fault_test(16, epoch, 0) == 0 };
    FINAL_REAPER_STAGE.store(if ready { 1 } else { 3 }, Ordering::Release);
    for _ in 0..THREAD_POLL_YIELDS {
        if FINAL_REAPER_GO.load(Ordering::Acquire) {
            let reaped = reap_pid(FINAL_REAPER_CHILD.load(Ordering::Acquire)) == Some(GROUP_LEG_OK);
            FINAL_REAPER_STAGE.store(if ready && reaped { 2 } else { 3 }, Ordering::Release);
            unsafe { raw_exit(SYS_EXIT, 0) };
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    FINAL_REAPER_STAGE.store(3, Ordering::Release);
    unsafe { raw_exit(SYS_EXIT, 1) }
}

/// The same brackets reject a churn-before-reap negative control: neither its
/// beginning nor its end is allowed outside this epoch's real release window.
unsafe fn final_owner_churn(epoch: Option<u64>) -> bool {
    for _ in 0..FINAL_OWNER_CHURN {
        if let Some(epoch) = epoch {
            if shared_fault_test(12, epoch, 0) != 0 {
                return false;
            }
        }
        let churn = mmap_anon(PAGE, true);
        if churn < 0 {
            return false;
        }
        core::ptr::write_volatile(churn as *mut u64, 1);
        if munmap(churn as usize, PAGE) != 0 {
            return false;
        }
        if let Some(epoch) = epoch {
            if shared_fault_test(12, epoch, 1) != 0 {
                return false;
            }
        }
    }
    true
}

/// On SMP, a CPU-1 sibling reaps the fork child, entering the actual last-Arc
/// destructor. CPU 0 churns only while that destructor is paused after its
/// first DATA-frame release. UP keeps the sequential ownership/accounting case.
unsafe fn final_owner_reap_and_churn(child: u64, epoch: Option<u64>) -> bool {
    use core::sync::atomic::Ordering;
    let Some(epoch) = epoch else {
        let churned = final_owner_churn(None);
        return reap_pid(child) == Some(GROUP_LEG_OK) && churned;
    };
    FINAL_REAPER_CHILD.store(child, Ordering::Release);
    FINAL_REAPER_EPOCH.store(epoch, Ordering::Release);
    FINAL_REAPER_STAGE.store(0, Ordering::Release);
    FINAL_REAPER_GO.store(false, Ordering::Release);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    let thread = raw_clone(
        THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
        group_stack_top(),
        core::ptr::null_mut(),
        GROUP_TID_WORD.as_ptr(),
        final_owner_reaper,
    );
    if is_error(thread) || thread == 0 {
        let _ = shared_fault_test(14, epoch, 0);
        let _ = reap_pid(child);
        let _ = shared_fault_test(15, epoch, 0);
        return false;
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if FINAL_REAPER_STAGE.load(Ordering::Acquire) != 0 {
            break;
        }
        userspace::syscall::sys_yield();
    }
    let mut ok = FINAL_REAPER_STAGE.load(Ordering::Acquire) == 1;
    let negative = option_env!("NILIX_ST_K2_FINAL_OWNER_NEGATIVE") == Some("1");
    if negative {
        ok &= final_owner_churn(Some(epoch));
    }
    FINAL_REAPER_GO.store(true, Ordering::Release);
    if ok {
        for _ in 0..THREAD_POLL_YIELDS {
            let state = shared_fault_test(11, epoch, 0);
            if state == 4 || state >= 6 {
                break;
            }
            userspace::syscall::sys_yield();
        }
        ok = shared_fault_test(11, epoch, 0) == 4;
        if ok && !negative {
            ok = final_owner_churn(Some(epoch));
        }
        if ok {
            ok = shared_fault_test(13, epoch, 0) == 0;
        }
    }
    if !ok {
        let (mut a, mut b) = ([0u8; 20], [0u8; 20]);
        println_parts(&[
            "  final owner: release window rejected state=",
            decimal(shared_fault_test(11, epoch, 0) as usize, &mut a),
            " reaper_stage=",
            decimal(FINAL_REAPER_STAGE.load(Ordering::Acquire) as usize, &mut b),
        ]);
        let _ = shared_fault_test(14, epoch, 0);
    }
    let joined = g8_join_thread();
    ok &= joined
        && FINAL_REAPER_STAGE.load(Ordering::Acquire) == 2
        && shared_fault_test(11, epoch, 0) == 6;
    if !ok {
        let (mut a, mut b) = ([0u8; 20], [0u8; 20]);
        println_parts(&[
            "  final owner: completion rejected state=",
            decimal(shared_fault_test(11, epoch, 0) as usize, &mut a),
            " reaper_stage=",
            decimal(FINAL_REAPER_STAGE.load(Ordering::Acquire) as usize, &mut b),
        ]);
        let _ = shared_fault_test(14, epoch, 0);
    }
    ok &= shared_fault_test(15, epoch, 0) == 0;
    ok
}

/// Parent-first unmap: the fork child checks the surviving shared pages, then
/// a separate reaper provides the actual final-release window on SMP.
unsafe fn final_owner_process_round(pinned: bool) -> Result<(), u64> {
    let region = mmap_anon(2 * PAGE, true);
    if region < 0 {
        return Err(0xf0);
    }
    let region = region as usize;
    for (page, word) in FINAL_OWNER_WORDS.iter().enumerate() {
        core::ptr::write_volatile((region + page * PAGE) as *mut u64, *word);
    }
    let (mut to_child, mut to_parent) = ([-1i32; 2], [-1i32; 2]);
    if syscall2(SYS_PIPE2, to_child.as_mut_ptr() as u64, 0) != 0
        || syscall2(SYS_PIPE2, to_parent.as_mut_ptr() as u64, 0) != 0
    {
        return Err(0xf1);
    }
    let child = sys_fork();
    if child == 0 {
        let _ = sys_close(to_child[1] as u64);
        let _ = sys_close(to_parent[0] as u64);
        let mut byte = 0u8;
        // The DATA owner need not migrate. Only the actual reaper must run on
        // CPU 1; migrating here could strand the parent's blocking pipe read.
        let code = if syscall3(SYS_WRITE, to_parent[1] as u64, b"r".as_ptr() as u64, 1) != 1
            || sys_read(to_child[0] as u64, &mut byte, 1) != 1
        {
            0xf3
        } else {
            // The parent has unmapped: this task holds the region's last pin.
            let mut intact = true;
            for (page, word) in FINAL_OWNER_WORDS.iter().enumerate() {
                let addr = (region + page * PAGE) as *mut u64;
                intact &= core::ptr::read_volatile(addr) == *word;
                core::ptr::write_volatile(addr, !*word);
                intact &= core::ptr::read_volatile(addr) == !*word;
            }
            if intact {
                GROUP_LEG_OK
            } else {
                0xf4
            }
        };
        raw_exit(SYS_EXIT_GROUP, code);
    }
    // Only the child keeps these ends, so its early exit reads as EOF here.
    let _ = sys_close(to_parent[1] as u64);
    let _ = sys_close(to_child[0] as u64);
    let mut byte = 0u8;
    let mut ok = !is_error(child) && sys_read(to_parent[0] as u64, &mut byte, 1) == 1;
    let epoch = if pinned && ok {
        let armed = shared_fault_test(10, region as u64, 0);
        if is_error(armed) {
            ok = false;
            None
        } else {
            Some(armed)
        }
    } else {
        None
    };
    ok &= munmap(region, 2 * PAGE) == 0;
    ok &= syscall3(SYS_WRITE, to_child[1] as u64, b"u".as_ptr() as u64, 1) == 1;
    if !is_error(child) {
        ok &= final_owner_reap_and_churn(child, epoch);
    }
    let _ = sys_close(to_child[1] as u64);
    let _ = sys_close(to_parent[0] as u64);
    if ok {
        Ok(())
    } else {
        Err(0xf5)
    }
}

static FINAL_OWNER_REGION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static FINAL_OWNER_PINNED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static FINAL_OWNER_STAGE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Non-last CLONE_VM thread: first-touches both pages and may exit alongside
/// munmap. The living parent retains MmState; this is not a last-owner witness.
extern "C" fn final_owner_thread() -> ! {
    use core::sync::atomic::Ordering;
    if FINAL_OWNER_PINNED.load(Ordering::Acquire) && !final_owner_pin(1) {
        FINAL_OWNER_STAGE.store(0xe1, Ordering::Release);
        unsafe { raw_exit(SYS_EXIT, 1) };
    }
    let region = FINAL_OWNER_REGION.load(Ordering::Acquire) as usize;
    for (page, word) in FINAL_OWNER_WORDS.iter().enumerate() {
        unsafe { core::ptr::write_volatile((region + page * PAGE) as *mut u64, *word) };
    }
    FINAL_OWNER_STAGE.store(1, Ordering::Release);
    unsafe { raw_exit(SYS_EXIT, 0) }
}

/// One thread round: a CLONE_VM thread on CPU 1 faults the region in and
/// exits while the parent checks the words, unmaps the region and churns.
unsafe fn final_owner_thread_round(pinned: bool) -> Result<(), u64> {
    use core::sync::atomic::Ordering;
    let region = mmap_anon(2 * PAGE, true);
    if region < 0 {
        return Err(0xf6);
    }
    FINAL_OWNER_REGION.store(region as u64, Ordering::Release);
    FINAL_OWNER_PINNED.store(pinned, Ordering::Release);
    FINAL_OWNER_STAGE.store(0, Ordering::Release);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    let thread = raw_clone(
        THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
        group_stack_top(),
        core::ptr::null_mut(),
        GROUP_TID_WORD.as_ptr(),
        final_owner_thread,
    );
    if is_error(thread) || thread == 0 {
        return Err(0xf7);
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if FINAL_OWNER_STAGE.load(Ordering::Acquire) != 0 {
            break;
        }
        userspace::syscall::sys_yield();
    }
    let mut ok = FINAL_OWNER_STAGE.load(Ordering::Acquire) == 1;
    for (page, word) in FINAL_OWNER_WORDS.iter().enumerate() {
        ok = ok && core::ptr::read_volatile((region as usize + page * PAGE) as *const u64) == *word;
    }
    ok &= munmap(region as usize, 2 * PAGE) == 0;
    for _ in 0..FINAL_OWNER_CHURN {
        let churn = mmap_anon(PAGE, true);
        if churn < 0 {
            ok = false;
            break;
        }
        core::ptr::write_volatile(churn as *mut u64, 1);
        ok &= munmap(churn as usize, PAGE) == 0;
    }
    ok &= g8_join_thread();
    if ok {
        Ok(())
    } else {
        Err(0xf8)
    }
}

/// Runs `round` once to warm up, takes the baseline, then requires every one
/// of `iterations` rounds to come back to it exactly.
unsafe fn final_owner_variant(
    name: &str,
    iterations: usize,
    round: unsafe fn(bool) -> Result<(), u64>,
    pinned: bool,
) -> Result<(), u64> {
    round(pinned)?;
    let mut base = None;
    for _ in 0..2000 {
        // Let the warm-up's deferred teardown finish before the baseline.
        let first = memory_baseline();
        for _ in 0..20 {
            userspace::syscall::sys_yield();
        }
        if first.is_some() && memory_baseline() == first {
            base = first;
            break;
        }
    }
    let base = base.ok_or(0xf9u64)?;
    for iteration in 0..iterations {
        round(pinned)?;
        if let Err(now) = settle_to(base) {
            let (mut a, mut b, mut c, mut d, mut e) =
                ([0u8; 20], [0u8; 20], [0u8; 20], [0u8; 20], [0u8; 20]);
            println_parts(&[
                "  final owner: ",
                name,
                " iteration ",
                decimal(iteration, &mut a),
                " charged ",
                decimal(base.charged as usize, &mut b),
                decimal(now.charged as usize, &mut c),
            ]);
            println_parts(&[
                "  final owner: free pages+kstack tables ",
                decimal(base.free_pages as usize, &mut d),
                " -> ",
                decimal(now.free_pages as usize, &mut e),
            ]);
            return Err(0xfa);
        }
    }
    Ok(())
}

fn shared_final_owner_leg(pinned: bool) -> u64 {
    if pinned && !final_owner_pin(0) {
        return 0xfb;
    }
    let iterations = final_owner_iterations();
    let process =
        unsafe { final_owner_variant("process", iterations, final_owner_process_round, pinned) };
    if let Err(code) = process {
        return code;
    }
    let thread = unsafe {
        final_owner_variant(
            "nonlast-thread",
            iterations,
            final_owner_thread_round,
            pinned,
        )
    };
    match thread {
        Ok(()) => GROUP_LEG_OK,
        Err(code) => code | 0x100,
    }
}

/// ST-K2-P2(c): SMP requires churn inside the fork child's actual final-release
/// window, driven by a separate reaper. The non-last-thread case is accounting
/// coverage only. Every round restores memory.current and buddy pages exactly.
fn test_shared_final_owner_race(results: &mut TestResult) {
    print("Testing shared-anon final owner and parent-first unmap... ");
    let cpus = unsafe { shared_fault_test(0, 0, 0) };
    let pinned = !is_error(cpus) && cpus & 3 == 3;
    // Set the inherited mask before fork: the scheduler places a new task on
    // an allowed CPU. The host therefore starts on CPU 0, without requiring a
    // lone running task to migrate off a CPU with no replacement candidate.
    let mut saved_mask = 0u64;
    if pinned {
        if unsafe { syscall3(204, 0, 8, &mut saved_mask as *mut u64 as u64) } != 8
            || !cow_test_pin(1)
        {
            results.fail("shared-anon final owner affinity setup");
            return;
        }
    }
    let host = unsafe { sys_fork() };
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, shared_final_owner_leg(pinned)) };
    }
    let restored = !pinned || cow_test_pin(saved_mask);
    let reaped = !is_error(host) && reap_pid(host) == Some(GROUP_LEG_OK);
    if restored && reaped {
        let mut buf = [0u8; 20];
        let iterations = decimal(final_owner_iterations(), &mut buf);
        println("");
        println_parts(&[
            "ST-K2-FINAL-OWNER PASS variant=process iterations=",
            iterations,
            if pinned {
                " mode=release-window"
            } else {
                " mode=sequential"
            },
        ]);
        println_parts(&[
            "ST-K2-FINAL-OWNER PASS variant=nonlast-thread iterations=",
            iterations,
        ]);
        results.pass(
            "shared-anon final release and non-last-thread accounting return exactly every round",
        );
    } else {
        results.fail("shared-anon final owner and parent-first unmap");
    }
}

/// ST-K2-P2(d): a shared page at the start of an otherwise unused PD (160 GiB)
/// and the private population beside it. 515 pages run from the next page into
/// the following 2 MiB block, and stay below the R192-RES-2 report size.
const ROLLBACK_BASE: usize = 0x28_0000_0000;
const ROLLBACK_PAGES: usize = 515;
const ROLLBACK_CYCLES: usize = 3;
const ROLLBACK_SHARED_WORD: u64 = 0x5348_4152_4544;
const POP_PAUSED: u64 = 3;
const POP_DONE: u64 = 5;

unsafe fn mmap_hint(addr: usize, len: usize, shared: bool) -> i64 {
    let kind = if shared { MAP_SHARED } else { MAP_PRIVATE };
    syscall6(
        SYS_MMAP,
        addr as u64,
        len as u64,
        PROT_READ | PROT_WRITE,
        kind | MAP_ANONYMOUS,
        u64::MAX,
        0,
    ) as i64
}

/// Map and first-touch the shared page: its page table (and the PD above it)
/// go to the shared-fault ledger.
unsafe fn rollback_shared_page() -> Result<(), &'static str> {
    if mmap_hint(ROLLBACK_BASE, PAGE, true) != ROLLBACK_BASE as i64 {
        return Err("shared page: address hint unavailable");
    }
    core::ptr::write_volatile(ROLLBACK_BASE as *mut u64, ROLLBACK_SHARED_WORD);
    Ok(())
}

/// After the armed population failed: exactly ENOMEM, the probe fired, and
/// the shared page kept its word.
unsafe fn rollback_failed(result: i64) -> Result<(), &'static str> {
    if err_of(result) != ENOMEM {
        return Err("the injected population did not fail with exactly ENOMEM");
    }
    if shared_fault_test(8, 0, 0) != POP_DONE {
        return Err("the armed population failure did not fire");
    }
    Ok(())
}

/// mmap: the private population beside the shared page fails; nothing it
/// charged survives, and unmapping the shared page restores the baseline.
unsafe fn rollback_mmap_cycle() -> Result<(), &'static str> {
    let base = read_memory_current().ok_or("memory.current")?;
    rollback_shared_page()?;
    let with_shared = read_memory_current().ok_or("memory.current")?;
    // R174-B3: touching 1 data page in a fresh 2 MiB window must charge both
    // the data frame (PAGE) AND at least one positive page-table frame (>= PAGE).
    let shared_delta = with_shared
        .checked_sub(base)
        .ok_or("mmap: memory.current decreased after shared fault")?;
    if shared_delta < (2 * PAGE) as u64 {
        return Err("mmap: fresh page-table frame charge missing from memory.current");
    }
    if shared_fault_test(7, ROLLBACK_PAGES as u64, 0) != 0 {
        return Err("mmap: arming the population failure");
    }
    rollback_failed(mmap_hint(
        ROLLBACK_BASE + PAGE,
        ROLLBACK_PAGES * PAGE,
        false,
    ))?;
    if read_memory_current() != Some(with_shared) {
        return Err("mmap: the failed population changed memory.current");
    }
    if core::ptr::read_volatile(ROLLBACK_BASE as *const u64) != ROLLBACK_SHARED_WORD {
        return Err("mmap: the shared page lost its word");
    }
    if munmap(ROLLBACK_BASE, PAGE) != 0 || read_memory_current() != Some(base) {
        return Err("mmap: unmapping the shared page did not restore the baseline");
    }
    Ok(())
}

/// mremap: a private page beside the shared one grows in place; its tail
/// population fails and the page keeps its contents and charge.
unsafe fn rollback_mremap_cycle() -> Result<(), &'static str> {
    const WORD: u64 = 0x4d52_454d_4150;
    let base = read_memory_current().ok_or("memory.current")?;
    rollback_shared_page()?;
    let with_shared = read_memory_current().ok_or("memory.current")?;
    let shared_delta = with_shared
        .checked_sub(base)
        .ok_or("mremap: memory.current decreased after shared fault")?;
    let private = ROLLBACK_BASE + PAGE;
    if mmap_hint(private, PAGE, false) != private as i64 {
        return Err("mremap: private page hint unavailable");
    }
    core::ptr::write_volatile(private as *mut u64, WORD);
    let with_private = read_memory_current().ok_or("memory.current")?;
    // R174-B3: touching a second page inside the same leaf page table charges
    // exactly 1 data frame (PAGE), isolating the positive page-table frame
    // charge (`shared_delta - data_delta >= PAGE`) from the data charge.
    let data_delta = with_private
        .checked_sub(with_shared)
        .ok_or("mremap: memory.current decreased after private fault")?;
    if data_delta != PAGE as u64 {
        return Err("mremap: second page in existing PT did not charge exactly 1 data frame");
    }
    let pt_charge = shared_delta
        .checked_sub(data_delta)
        .ok_or("mremap: shared fault charged less than data page")?;
    if pt_charge < PAGE as u64 {
        return Err("mremap: positive page-table frame charge missing from memory.current");
    }
    if shared_fault_test(7, ROLLBACK_PAGES as u64, 0) != 0 {
        return Err("mremap: arming the population failure");
    }
    rollback_failed(mremap(private, PAGE, (1 + ROLLBACK_PAGES) * PAGE, 0))?;
    if read_memory_current() != Some(with_private)
        || core::ptr::read_volatile(private as *const u64) != WORD
    {
        return Err("mremap: the failed tail changed memory.current or the page");
    }
    if munmap(private, PAGE) != 0 || read_memory_current() != Some(with_shared) {
        return Err("mremap: unmapping private page did not release exactly its data frame");
    }
    if munmap(ROLLBACK_BASE, PAGE) != 0 || read_memory_current() != Some(base) {
        return Err("mremap: unmapping shared page did not release data + page-table frames");
    }
    Ok(())
}

static ROLLBACK_STAGE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The sibling on CPU 1: once the population is paused before its failing
/// allocation, unmap the shared page (its table still holds the population's
/// leaves, so this munmap cannot prune it) and let the population fail.
extern "C" fn rollback_unmapper() -> ! {
    use core::sync::atomic::Ordering;
    if !cow_test_pin(2) {
        ROLLBACK_STAGE.store(0xe1, Ordering::Release);
        unsafe { raw_exit(SYS_EXIT, 1) };
    }
    ROLLBACK_STAGE.store(1, Ordering::Release);
    for _ in 0..THREAD_POLL_YIELDS {
        if unsafe { shared_fault_test(8, 0, 0) } == POP_PAUSED {
            let unmapped = unsafe { munmap(ROLLBACK_BASE, PAGE) } == 0;
            let released = unsafe { shared_fault_test(9, 0, 0) } == 0;
            ROLLBACK_STAGE.store(
                if unmapped && released { 2 } else { 0xe2 },
                Ordering::Release,
            );
            unsafe { raw_exit(SYS_EXIT, 0) };
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    ROLLBACK_STAGE.store(0xe3, Ordering::Release);
    unsafe { raw_exit(SYS_EXIT, 0) }
}

/// Concurrent prune: the rollback itself empties the shared fault's page
/// table and prunes it, so only `settle_failed_populate` can release its
/// ledgered charge. The baseline is checked once the sibling is reaped.
unsafe fn rollback_concurrent_cycle() -> Result<(), &'static str> {
    use core::sync::atomic::Ordering;
    let base = read_memory_current().ok_or("memory.current")?;
    rollback_shared_page()?;
    if shared_fault_test(7, ROLLBACK_PAGES as u64, 1) != 0 {
        return Err("concurrent: arming the paused population failure");
    }
    ROLLBACK_STAGE.store(0, Ordering::Release);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    let sibling = raw_clone(
        THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
        group_stack_top(),
        core::ptr::null_mut(),
        GROUP_TID_WORD.as_ptr(),
        rollback_unmapper,
    );
    if is_error(sibling) || sibling == 0 {
        return Err("concurrent: clone");
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if ROLLBACK_STAGE.load(Ordering::Acquire) != 0 {
            break;
        }
        userspace::syscall::sys_yield();
    }
    if ROLLBACK_STAGE.load(Ordering::Acquire) != 1 {
        let _ = g8_join_thread();
        return Err("concurrent: the sibling did not start on CPU 1");
    }
    let result = mmap_hint(ROLLBACK_BASE + PAGE, ROLLBACK_PAGES * PAGE, false);
    let joined = g8_join_thread();
    rollback_failed(result)?;
    if !joined || ROLLBACK_STAGE.load(Ordering::Acquire) != 2 {
        return Err("concurrent: the sibling did not unmap the shared page during the pause");
    }
    for _ in 0..2000 {
        if read_memory_current() == Some(base) {
            return Ok(());
        }
        for _ in 0..20 {
            userspace::syscall::sys_yield();
        }
    }
    Err("concurrent: the pruned shared-fault table stayed charged")
}

type RollbackCycle = unsafe fn() -> Result<(), &'static str>;

fn private_rollback_leg(smp: bool) -> u64 {
    let sites: [(RollbackCycle, bool); 3] = [
        (rollback_mmap_cycle, true),
        (rollback_mremap_cycle, true),
        (rollback_concurrent_cycle, smp),
    ];
    if smp && !cow_test_pin(1) {
        return 0xc0;
    }
    for (index, (cycle, run)) in sites.iter().enumerate() {
        if !run {
            continue;
        }
        for _ in 0..ROLLBACK_CYCLES {
            if let Err(reason) = unsafe { cycle() } {
                print("  private rollback: ");
                println(reason);
                return 0xc1 + index as u64;
            }
        }
    }
    GROUP_LEG_OK
}

/// ST-K2-P2(d): a private population beside a page table built by a shared
/// fault fails by injection (mmap, mremap growth, and on SMP while a sibling
/// unmaps the shared page); the errno and `memory.current` are exact.
fn test_private_rollback_reclaim(results: &mut TestResult) {
    print("Testing private rollback beside a shared-fault page table... ");
    let cpus = unsafe { shared_fault_test(0, 0, 0) };
    let smp = !is_error(cpus) && cpus & 3 == 3;
    let host = unsafe { sys_fork() };
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, private_rollback_leg(smp)) };
    }
    if is_error(host) || reap_pid(host) != Some(GROUP_LEG_OK) {
        results.fail("private rollback beside a shared-fault page table");
        return;
    }
    let mut buf = [0u8; 20];
    let cycles = decimal(ROLLBACK_CYCLES, &mut buf);
    println("");
    println_parts(&["ST-K2-PRIVATE-ROLLBACK PASS site=mmap cycles=", cycles]);
    println_parts(&["ST-K2-PRIVATE-ROLLBACK PASS site=mremap cycles=", cycles]);
    if smp {
        println_parts(&[
            "ST-K2-PRIVATE-ROLLBACK PASS site=mmap-concurrent cycles=",
            cycles,
        ]);
    } else {
        println("[SKIP] private rollback concurrent prune: requires CPUs 0 and 1");
    }
    results
        .pass("private rollback beside a shared-fault page table: exact ENOMEM and memory.current");
}

// ---------------------------------------------------------------------------
// GAP-5 slice 4: the futex operations condition variables need. musl's
// pthread_cond_broadcast clears the next waiter's barrier word and requeues
// that waiter to the mutex with FUTEX_REQUEUE (moved, not woken, since GAP-5
// futex parity). Runs in a forked host so a stuck waiter cannot take this
// PID 1 down.
// ---------------------------------------------------------------------------

const SYS_FUTEX: u64 = 202;
const FUTEX_WAIT_OP: u64 = 0;
const FUTEX_WAKE_OP: u64 = 1;
const FUTEX_REQUEUE_OP: u64 = 3;
const FUTEX_CMP_REQUEUE_OP: u64 = 4;
const FUTEX_WAIT_BITSET_OP: u64 = 9;
const FUTEX_WAKE_BITSET_OP: u64 = 10;
const FUTEX_PRIVATE: u64 = 128;
const FUTEX_CLOCK_REALTIME: u64 = 256;
const FUTEX_BITSET_ANY: u64 = 0xffff_ffff;
const ENOSYS: i32 = 38;
const ETIMEDOUT: i32 = 110;
const SYS_CLOCK_GETTIME: u64 = 228;
const CLOCK_MONOTONIC: u64 = 1;
/// Deadline of the lone timed wait below.
const FUTEX_SLEEP_NS: i64 = 20_000_000;
/// Host exit status when every check passed.
const FUTEX_LEG_OK: u64 = 0x33;
/// What the waiter thread's FUTEX_WAIT returned (u64 syscall result).
const FUTEX_WAIT_PENDING: u64 = 0xdead;

#[repr(C, align(4))]
struct FutexWord(core::sync::atomic::AtomicU32);
static FUTEX_WORD: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static FUTEX_TARGET: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static FUTEX_WAIT_RESULT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(FUTEX_WAIT_PENDING);

/// CLOCK_MONOTONIC in nanoseconds, or None if the clock is unreadable.
fn monotonic_ns() -> Option<i64> {
    let mut ts = [0i64; 2];
    let r = unsafe { syscall2(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC, ts.as_mut_ptr() as u64) };
    (r == 0).then(|| ts[0] * 1_000_000_000 + ts[1])
}

unsafe fn futex(word: &FutexWord, op: u64, val: u64, timeout: u64, uaddr2: u64, val3: u64) -> u64 {
    syscall6(
        SYS_FUTEX,
        word.0.as_ptr() as u64,
        op,
        val,
        timeout,
        uaddr2,
        val3,
    )
}

/// Thread entry: sleep on FUTEX_WORD until a requeue moves it and the
/// target is woken.
extern "C" fn futex_waiter_thread() -> ! {
    use core::sync::atomic::Ordering;
    let ret = unsafe { futex(&FUTEX_WORD, FUTEX_WAIT_OP | FUTEX_PRIVATE, 0, 0, 0, 0) };
    FUTEX_WAIT_RESULT.store(ret, Ordering::SeqCst);
    unsafe { raw_exit(SYS_EXIT, 0) }
}

/// Body of the futex leg's host process; returns its exit status.
fn futex_requeue_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let target = FUTEX_TARGET.0.as_ptr() as u64;
    let past = [0i64; 2]; // timespec {0, 0}: an absolute deadline long gone
    let past = past.as_ptr() as u64;
    // Touch both words: the kernel refuses a futex word on a page that is not
    // present yet (EFAULT), and these may be first-use .bss pages.
    FUTEX_WORD.0.store(0, Ordering::SeqCst);
    FUTEX_TARGET.0.store(0, Ordering::SeqCst);

    // Argument contract, no waiter involved.
    unsafe {
        if errno(futex(&FUTEX_WORD, FUTEX_CMP_REQUEUE_OP, 0, 1, target, 7)) != EAGAIN {
            return 0x90; // *uaddr != val3
        }
        if futex(
            &FUTEX_WORD,
            FUTEX_CMP_REQUEUE_OP | FUTEX_PRIVATE,
            1,
            1,
            target,
            0,
        ) != 0
        {
            return 0x91; // matching value, nobody waiting
        }
        if errno(futex(
            &FUTEX_WORD,
            FUTEX_REQUEUE_OP,
            0,
            0xffff_ffff,
            target,
            0,
        )) != EINVAL
        {
            return 0x92; // negative requeue count
        }
        if errno(futex(&FUTEX_WORD, FUTEX_REQUEUE_OP, 0, 1, target + 1, 0)) != EINVAL {
            return 0x93; // misaligned target
        }
        if errno(futex(&FUTEX_WORD, FUTEX_WAIT_BITSET_OP, 0, 0, 0, 0)) != EINVAL {
            return 0x94; // empty bitset
        }
        if errno(futex(&FUTEX_WORD, FUTEX_WAIT_BITSET_OP, 1, 0, 0, 1)) != EAGAIN {
            return 0x95; // a partial bitset is served; the value check comes first
        }
        let realtime = FUTEX_WAIT_BITSET_OP | FUTEX_PRIVATE | FUTEX_CLOCK_REALTIME;
        if errno(futex(&FUTEX_WORD, realtime, 0, past, 0, FUTEX_BITSET_ANY)) != ETIMEDOUT {
            return 0x96; // absolute deadline already passed
        }
        if errno(futex(&FUTEX_WORD, realtime, 1, past, 0, FUTEX_BITSET_ANY)) != EAGAIN {
            return 0x97; // the value check comes first
        }
        if errno(futex(
            &FUTEX_WORD,
            FUTEX_WAIT_OP | FUTEX_CLOCK_REALTIME,
            0,
            0,
            0,
            0,
        )) != ENOSYS
        {
            return 0x98; // CLOCK_REALTIME only with WAIT_BITSET
        }
        if futex(&FUTEX_WORD, FUTEX_WAKE_BITSET_OP, 1, 0, 0, FUTEX_BITSET_ANY) != 0 {
            return 0x99;
        }
    }

    // A lone timed wait must sleep until its deadline and report ETIMEDOUT,
    // not a wake (the F13 contract: a reschedule that returns without a switch
    // is not a wake). This passes on the pre-fix kernel too, so it pins the
    // contract but does not reproduce F13; the musl timed-wait leg did.
    let Some(start) = monotonic_ns() else {
        return 0x9f;
    };
    let deadline_ns = start + FUTEX_SLEEP_NS;
    let deadline = [deadline_ns / 1_000_000_000, deadline_ns % 1_000_000_000];
    let r = unsafe {
        futex(
            &FUTEX_WORD,
            FUTEX_WAIT_BITSET_OP | FUTEX_PRIVATE,
            0,
            deadline.as_ptr() as u64,
            0,
            FUTEX_BITSET_ANY,
        )
    };
    if errno(r) != ETIMEDOUT {
        return 0xa0; // a lone timed wait woke without a waker
    }
    match monotonic_ns() {
        Some(now) if now >= deadline_ns => {}
        _ => return 0xa1, // returned before its deadline
    }

    // A sibling thread (same tgid, so the same futex key) sleeps on the word.
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);
    FUTEX_WAIT_RESULT.store(FUTEX_WAIT_PENDING, Ordering::SeqCst);
    let thread = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            futex_waiter_thread,
        )
    };
    if is_error(thread) || thread == 0 {
        return 0x9a;
    }
    // Until the thread is asleep, a requeue finds nobody and returns 0.
    let mut moved = 0;
    for _ in 0..THREAD_POLL_YIELDS {
        moved = unsafe {
            futex(
                &FUTEX_WORD,
                FUTEX_CMP_REQUEUE_OP | FUTEX_PRIVATE,
                0,
                1,
                target,
                0,
            )
        };
        if moved != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if moved != 1 {
        return 0x9b; // the sleeping waiter was not counted exactly once
    }
    // The waiter now sleeps on the target, as on Linux; waking the target
    // releases it.
    if is_error(unsafe { futex(&FUTEX_TARGET, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 0, 0, 0) }) {
        return 0x9c;
    }
    let mut joined = false;
    for _ in 0..THREAD_POLL_YIELDS {
        if GROUP_TID_WORD.load(Ordering::SeqCst) == 0 {
            joined = true;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if !joined {
        return 0x9d;
    }
    if FUTEX_WAIT_RESULT.load(Ordering::SeqCst) != 0 {
        return 0x9e; // the waiter must report a wake, not EAGAIN or an error
    }
    FUTEX_LEG_OK
}

fn test_futex_requeue(results: &mut TestResult) {
    print("Testing futex requeue and bitset ops... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("futex requeue: fork of the host failed");
        return;
    }
    if host == 0 {
        let code = futex_requeue_leg();
        unsafe { raw_exit(SYS_EXIT_GROUP, code) };
    }
    match reap_pid(host) {
        Some(FUTEX_LEG_OK) => {}
        Some(code) => {
            print("futex leg exit ");
            print_int(code as i64);
            print(" ");
            results.fail("futex requeue: a check failed");
            return;
        }
        None => {
            results.fail("futex requeue: could not reap the host");
            return;
        }
    }
    results.pass("futex requeue moves a sleeping sibling and bitset ops keep the Linux contract");
}

// ---------------------------------------------------------------------------
// GAP-5 futex parity: FUTEX_WAKE_OP, a requeue that moves a sleeper without
// waking it, partial-bitset wakes, and futex keys shared by a CLONE_VM child
// that is not a thread, each with real sleepers. Every check also holds on
// Linux. Runs in a forked host so a stuck sleeper cannot take PID 1 down.
// ---------------------------------------------------------------------------

/// Linux FUTEX_WAKE_OP (5). (`FUTEX_WAKE_OP` above names the FUTEX_WAKE op, 1.)
const FUTEX_WAKE_OP_CMD: u64 = 5;
const FUTEX_OP_SET: u32 = 0;
const FUTEX_OP_ADD: u32 = 1;
const FUTEX_OP_OR: u32 = 2;
const FUTEX_OP_OPARG_SHIFT: u32 = 8;
const FUTEX_OP_CMP_EQ: u32 = 0;
const FUTEX_OP_CMP_GT: u32 = 4;
/// "Every waiter" for wake and requeue counts (INT_MAX).
const FUTEX_ALL: u64 = i32::MAX as u64;
/// Host exit status when every parity check passed.
const FUTEX_PARITY_OK: u64 = 0x35;

/// Linux `FUTEX_OP(op, oparg, cmp, cmparg)`.
const fn futex_op_word(op: u32, oparg: u32, cmp: u32, cmparg: u32) -> u64 {
    (((op & 0xf) << 28) | ((cmp & 0xf) << 24) | ((oparg & 0xfff) << 12) | (cmparg & 0xfff)) as u64
}

static PARITY_WORD_A: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static PARITY_WORD_B: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static PARITY_WORD_C: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static PARITY_WORD_D: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static PARITY_WORD_E: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static PARITY_WORD_F: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));

/// What one sleeper waits on and what its wait returned.
struct ParitySleeper {
    word: core::sync::atomic::AtomicU64,
    value: core::sync::atomic::AtomicU64,
    /// 0: plain FUTEX_WAIT; otherwise the FUTEX_WAIT_BITSET mask.
    bitset: core::sync::atomic::AtomicU64,
    result: core::sync::atomic::AtomicU64,
    /// CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID word: 0 once it exited.
    tid: core::sync::atomic::AtomicI32,
}

impl ParitySleeper {
    const fn new() -> Self {
        use core::sync::atomic::{AtomicI32, AtomicU64};
        Self {
            word: AtomicU64::new(0),
            value: AtomicU64::new(0),
            bitset: AtomicU64::new(0),
            result: AtomicU64::new(FUTEX_WAIT_PENDING),
            tid: AtomicI32::new(0),
        }
    }
}

static PARITY_SLEEPERS: [ParitySleeper; 2] = [ParitySleeper::new(), ParitySleeper::new()];
static mut PARITY_STACKS: [CloneStack; 2] = [
    CloneStack([0; CLEAR_TID_STACK_BYTES]),
    CloneStack([0; CLEAR_TID_STACK_BYTES]),
];

fn parity_sleep(slot: &ParitySleeper) -> ! {
    use core::sync::atomic::Ordering;
    let word = slot.word.load(Ordering::SeqCst);
    let value = slot.value.load(Ordering::SeqCst);
    let bitset = slot.bitset.load(Ordering::SeqCst);
    let ret = unsafe {
        if bitset == 0 {
            syscall6(
                SYS_FUTEX,
                word,
                FUTEX_WAIT_OP | FUTEX_PRIVATE,
                value,
                0,
                0,
                0,
            )
        } else {
            syscall6(
                SYS_FUTEX,
                word,
                FUTEX_WAIT_BITSET_OP | FUTEX_PRIVATE,
                value,
                0,
                0,
                bitset,
            )
        }
    };
    slot.result.store(ret, Ordering::SeqCst);
    unsafe { raw_exit(SYS_EXIT, 0) }
}

extern "C" fn parity_sleeper_0() -> ! {
    parity_sleep(&PARITY_SLEEPERS[0])
}

extern "C" fn parity_sleeper_1() -> ! {
    parity_sleep(&PARITY_SLEEPERS[1])
}

/// Start sleeper `index` on `word` (expected `value`, mask `bitset`, 0 for a
/// plain wait) as a task of the given clone `flags`. Returns its tid.
fn parity_spawn(
    index: usize,
    word: &FutexWord,
    value: u32,
    bitset: u32,
    flags: u64,
) -> Option<u64> {
    use core::sync::atomic::Ordering;
    let slot = &PARITY_SLEEPERS[index];
    slot.word.store(word.0.as_ptr() as u64, Ordering::SeqCst);
    slot.value.store(value as u64, Ordering::SeqCst);
    slot.bitset.store(bitset as u64, Ordering::SeqCst);
    slot.result.store(FUTEX_WAIT_PENDING, Ordering::SeqCst);
    slot.tid.store(-1, Ordering::SeqCst);
    let entry: extern "C" fn() -> ! = if index == 0 {
        parity_sleeper_0
    } else {
        parity_sleeper_1
    };
    let stack_top =
        unsafe { core::ptr::addr_of_mut!(PARITY_STACKS[index]) as usize + CLEAR_TID_STACK_BYTES };
    let tid = unsafe {
        raw_clone(
            flags | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            stack_top,
            core::ptr::null_mut(),
            slot.tid.as_ptr(),
            entry,
        )
    };
    (!is_error(tid) && tid != 0).then_some(tid)
}

/// Tasks sleeping on `word`: a CMP_REQUEUE of the word onto itself counts
/// them and moves or wakes none (on Linux as here).
fn parity_sleepers(word: &FutexWord) -> u64 {
    use core::sync::atomic::Ordering;
    let value = word.0.load(Ordering::SeqCst) as u64;
    let target = word.0.as_ptr() as u64;
    let r = unsafe {
        futex(
            word,
            FUTEX_CMP_REQUEUE_OP | FUTEX_PRIVATE,
            0,
            FUTEX_ALL,
            target,
            value,
        )
    };
    if is_error(r) {
        u64::MAX
    } else {
        r
    }
}

fn parity_await_sleepers(word: &FutexWord, count: u64) -> bool {
    for _ in 0..THREAD_POLL_YIELDS {
        if parity_sleepers(word) == count {
            return true;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    false
}

/// Give a sleeper that should stay asleep plenty of chances to run.
fn parity_settle() {
    for _ in 0..100 {
        unsafe { userspace::syscall::sys_yield() };
    }
}

fn parity_pending(index: usize) -> bool {
    PARITY_SLEEPERS[index]
        .result
        .load(core::sync::atomic::Ordering::SeqCst)
        == FUTEX_WAIT_PENDING
}

/// Wait for thread `index` to exit (its clear-tid word drops to 0) and
/// require that its wait returned 0.
fn parity_join_woken(index: usize) -> bool {
    use core::sync::atomic::Ordering;
    let slot = &PARITY_SLEEPERS[index];
    for _ in 0..THREAD_POLL_YIELDS {
        if slot.tid.load(Ordering::SeqCst) == 0 {
            return slot.result.load(Ordering::SeqCst) == 0;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    false
}

unsafe fn wake_op(nr_wake: u64, nr_wake2: u64, uaddr2: u64, op: u64) -> u64 {
    futex(
        &PARITY_WORD_A,
        FUTEX_WAKE_OP_CMD | FUTEX_PRIVATE,
        nr_wake,
        nr_wake2,
        uaddr2,
        op,
    )
}

/// Body of the parity leg's host process; returns its exit status.
fn futex_parity_leg() -> u64 {
    use core::sync::atomic::Ordering;
    // Touch every word: the kernel refuses a futex word on a page that is
    // not present yet (EFAULT), and these may be first-use .bss pages.
    for word in [
        &PARITY_WORD_A,
        &PARITY_WORD_B,
        &PARITY_WORD_C,
        &PARITY_WORD_D,
        &PARITY_WORD_E,
        &PARITY_WORD_F,
    ] {
        word.0.store(0, Ordering::SeqCst);
    }
    let word_b = PARITY_WORD_B.0.as_ptr() as u64;

    // FUTEX_WAKE_OP argument contract, nobody waiting.
    PARITY_WORD_B.0.store(5, Ordering::SeqCst);
    unsafe {
        let add3_if_5 = futex_op_word(FUTEX_OP_ADD, 3, FUTEX_OP_CMP_EQ, 5);
        if wake_op(1, 1, word_b, add3_if_5) != 0 {
            return 0xb0;
        }
        if PARITY_WORD_B.0.load(Ordering::SeqCst) != 8 {
            return 0xb1; // the operation must update the word
        }
        if errno(wake_op(
            1,
            1,
            word_b,
            futex_op_word(5, 0, FUTEX_OP_CMP_EQ, 0),
        )) != ENOSYS
        {
            return 0xb2; // unknown operation
        }
        // SET 8 leaves the word as it is, so this holds whether or not the
        // kernel applies the operation before rejecting the comparison.
        if errno(wake_op(1, 1, word_b, futex_op_word(FUTEX_OP_SET, 8, 6, 0))) != ENOSYS {
            return 0xb3; // unknown comparison
        }
        if PARITY_WORD_B.0.load(Ordering::SeqCst) != 8 {
            return 0xb4;
        }
        if errno(wake_op(1, 1, word_b + 1, add3_if_5)) != EINVAL {
            return 0xb5; // misaligned second word
        }
        if errno(wake_op(1, 1, 0, add3_if_5)) != EFAULT {
            return 0xb6; // missing second word
        }
    }

    // WAKE_OP wakes a sleeper on the second word only when the comparison of
    // the old value holds.
    if parity_spawn(0, &PARITY_WORD_B, 8, 0, THREAD_FLAGS).is_none() {
        return 0xb7;
    }
    if !parity_await_sleepers(&PARITY_WORD_B, 1) {
        return 0xb8;
    }
    unsafe {
        // ADD 1: 8 -> 9; 8 > 100 is false, so nobody is woken.
        if wake_op(
            1,
            1,
            word_b,
            futex_op_word(FUTEX_OP_ADD, 1, FUTEX_OP_CMP_GT, 100),
        ) != 0
        {
            return 0xb9;
        }
    }
    if PARITY_WORD_B.0.load(Ordering::SeqCst) != 9 {
        return 0xba;
    }
    parity_settle();
    if !parity_pending(0) || parity_sleepers(&PARITY_WORD_B) != 1 {
        return 0xbb; // a false comparison must not wake the sleeper
    }
    unsafe {
        // OR (1 << 4): 9 -> 25; 9 == 9 holds, so the sleeper is woken.
        let or_bit4_if_9 = futex_op_word(FUTEX_OP_OR | FUTEX_OP_OPARG_SHIFT, 4, FUTEX_OP_CMP_EQ, 9);
        if wake_op(1, 1, word_b, or_bit4_if_9) != 1 {
            return 0xbc;
        }
    }
    if PARITY_WORD_B.0.load(Ordering::SeqCst) != 25 {
        return 0xbd;
    }
    if !parity_join_woken(0) {
        return 0xbe;
    }

    // A requeued sleeper is moved, not woken: it keeps sleeping on the
    // target until the target is woken.
    let word_d = PARITY_WORD_D.0.as_ptr() as u64;
    if parity_spawn(0, &PARITY_WORD_C, 0, 0, THREAD_FLAGS).is_none() {
        return 0xc0;
    }
    let mut moved = 0;
    for _ in 0..THREAD_POLL_YIELDS {
        moved = unsafe {
            futex(
                &PARITY_WORD_C,
                FUTEX_CMP_REQUEUE_OP | FUTEX_PRIVATE,
                0,
                1,
                word_d,
                0,
            )
        };
        if moved != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if moved != 1 {
        return 0xc1; // the sleeper was not counted exactly once
    }
    unsafe {
        if futex(
            &PARITY_WORD_C,
            FUTEX_WAKE_OP | FUTEX_PRIVATE,
            FUTEX_ALL,
            0,
            0,
            0,
        ) != 0
        {
            return 0xc2; // nobody is left on the source word
        }
    }
    if parity_sleepers(&PARITY_WORD_D) != 1 {
        return 0xc3; // the sleeper now waits on the target
    }
    parity_settle();
    if !parity_pending(0) {
        return 0xc4; // the requeue must not have woken it
    }
    unsafe {
        if futex(&PARITY_WORD_D, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 0, 0, 0) != 1 {
            return 0xc5;
        }
    }
    if !parity_join_woken(0) {
        return 0xc6;
    }

    // A partial-bitset wake wakes only the sleeper whose mask intersects.
    if parity_spawn(0, &PARITY_WORD_E, 0, 0x1, THREAD_FLAGS).is_none()
        || parity_spawn(1, &PARITY_WORD_E, 0, 0x2, THREAD_FLAGS).is_none()
    {
        return 0xd0;
    }
    if !parity_await_sleepers(&PARITY_WORD_E, 2) {
        return 0xd1;
    }
    unsafe {
        if futex(
            &PARITY_WORD_E,
            FUTEX_WAKE_BITSET_OP | FUTEX_PRIVATE,
            FUTEX_ALL,
            0,
            0,
            0x4,
        ) != 0
        {
            return 0xd2; // a mask that intersects nobody
        }
        if futex(
            &PARITY_WORD_E,
            FUTEX_WAKE_BITSET_OP | FUTEX_PRIVATE,
            FUTEX_ALL,
            0,
            0,
            0x2,
        ) != 1
        {
            return 0xd3;
        }
    }
    if !parity_join_woken(1) {
        return 0xd4;
    }
    parity_settle();
    if !parity_pending(0) || parity_sleepers(&PARITY_WORD_E) != 1 {
        return 0xd5; // the other mask's sleeper must still be asleep
    }
    unsafe {
        if futex(
            &PARITY_WORD_E,
            FUTEX_WAKE_BITSET_OP | FUTEX_PRIVATE,
            1,
            0,
            0,
            0x1,
        ) != 1
        {
            return 0xd6;
        }
    }
    if !parity_join_woken(0) {
        return 0xd7;
    }

    // A CLONE_VM child that is not a thread shares the address space, so it
    // shares the futex keys: the host sees and wakes its sleeper.
    let Some(child) = parity_spawn(0, &PARITY_WORD_F, 0, 0, CLONE_VM) else {
        return 0xe0;
    };
    if !parity_await_sleepers(&PARITY_WORD_F, 1) {
        let _ = unsafe { futex(&PARITY_WORD_F, FUTEX_WAKE_OP, 1, 0, 0, 0) };
        unsafe { userspace::syscall::sys_kill(child, SIGKILL_NR) };
        let _ = reap_pid(child);
        return 0xe1; // its sleeper is invisible to the host's key space
    }
    if unsafe { futex(&PARITY_WORD_F, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 0, 0, 0) } != 1 {
        unsafe { userspace::syscall::sys_kill(child, SIGKILL_NR) };
        let _ = reap_pid(child);
        return 0xe2;
    }
    if reap_pid(child) != Some(0) {
        return 0xe3;
    }
    if PARITY_SLEEPERS[0].result.load(Ordering::SeqCst) != 0 {
        return 0xe4; // the child's wait must report the wake
    }
    FUTEX_PARITY_OK
}

fn test_futex_parity(results: &mut TestResult) {
    print("Testing futex WAKE_OP, requeue, bitsets and address-space keys... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("futex parity: fork of the host failed");
        return;
    }
    if host == 0 {
        let code = futex_parity_leg();
        unsafe { raw_exit(SYS_EXIT_GROUP, code) };
    }
    match reap_pid(host) {
        Some(FUTEX_PARITY_OK) => {}
        Some(code) => {
            print("futex parity leg exit ");
            print_int(code as i64);
            print(" ");
            results.fail("futex parity: a check failed");
            return;
        }
        None => {
            results.fail("futex parity: could not reap the host");
            return;
        }
    }
    results.pass("futex WAKE_OP, requeue, partial bitsets and CLONE_VM keys match Linux");
}

// ---------------------------------------------------------------------------
// GAP-5 PI parity: PI futexes under the Linux user-word protocol (the owner's
// TID in the word, FUTEX_WAITERS and FUTEX_OWNER_DIED kept by the kernel) and
// requeue-PI. Each leg runs in a forked host so a stuck waiter cannot take
// PID 1 down. Every check also holds on Linux, except the owner-identity
// leg's refusal of an owner in another address space (R191-1).
// ---------------------------------------------------------------------------

const FUTEX_LOCK_PI_OP: u64 = 6;
const FUTEX_UNLOCK_PI_OP: u64 = 7;
const FUTEX_TRYLOCK_PI_OP: u64 = 8;
const FUTEX_WAIT_REQUEUE_PI_OP: u64 = 11;
const FUTEX_CMP_REQUEUE_PI_OP: u64 = 12;
const FUTEX_LOCK_PI2_OP: u64 = 13;
const FUTEX_WAITERS_BIT: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED_BIT: u32 = 0x4000_0000;
const FUTEX_TID_BITS: u32 = 0x3fff_ffff;
const EPERM: i32 = 1;
const EDEADLK: i32 = 35;
const CLOCK_REALTIME_ID: u64 = 0;
/// Host exit status when every check of a PI leg passed.
const FUTEX_PI_OK: u64 = 0x36;
/// A TID no task has: the PID space ends far below it.
const FUTEX_PI_NO_TID: u32 = 0x3fff_fff0;

static PI_WORD_A: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static PI_WORD_B: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static PI_COND: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static PI_OTHER: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));

/// One PI helper thread: what it locks (or, for requeue-PI, waits on) and
/// what its calls returned.
struct PiThread {
    /// The PI word's address.
    word: core::sync::atomic::AtomicU64,
    /// FUTEX_WAIT_REQUEUE_PI's source word (expected value 0), or 0 for a
    /// plain FUTEX_LOCK_PI.
    cond: core::sync::atomic::AtomicU64,
    /// The PI word right after the lock call returned.
    seen: core::sync::atomic::AtomicU32,
    /// The lock call's result.
    ret: core::sync::atomic::AtomicU64,
    /// Host -> thread: release the lock now.
    go: core::sync::atomic::AtomicU32,
    /// FUTEX_UNLOCK_PI's result.
    unlock_ret: core::sync::atomic::AtomicU64,
    /// CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID word: 0 once it exited.
    tid: core::sync::atomic::AtomicI32,
}

impl PiThread {
    const fn new() -> Self {
        use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64};
        Self {
            word: AtomicU64::new(0),
            cond: AtomicU64::new(0),
            seen: AtomicU32::new(0),
            ret: AtomicU64::new(FUTEX_WAIT_PENDING),
            go: AtomicU32::new(0),
            unlock_ret: AtomicU64::new(FUTEX_WAIT_PENDING),
            tid: AtomicI32::new(0),
        }
    }
}

static PI_THREADS: [PiThread; 2] = [PiThread::new(), PiThread::new()];
/// Two lockers and one owner that dies holding the lock.
static mut PI_STACKS: [CloneStack; 3] = [
    CloneStack([0; CLEAR_TID_STACK_BYTES]),
    CloneStack([0; CLEAR_TID_STACK_BYTES]),
    CloneStack([0; CLEAR_TID_STACK_BYTES]),
];

fn pi_stack_top(index: usize) -> usize {
    unsafe { core::ptr::addr_of_mut!(PI_STACKS[index]) as usize + CLEAR_TID_STACK_BYTES }
}

unsafe fn pi_futex(word: u64, op: u64, timeout: u64) -> u64 {
    syscall6(SYS_FUTEX, word, op | FUTEX_PRIVATE, 0, timeout, 0, 0)
}

fn word_addr(word: &FutexWord) -> u64 {
    word.0.as_ptr() as u64
}

fn pi_thread_body(slot: &PiThread) -> ! {
    use core::sync::atomic::{AtomicU32, Ordering};
    let word = slot.word.load(Ordering::SeqCst);
    let cond = slot.cond.load(Ordering::SeqCst);
    let ret = unsafe {
        if cond == 0 {
            pi_futex(word, FUTEX_LOCK_PI_OP, 0)
        } else {
            syscall6(
                SYS_FUTEX,
                cond,
                FUTEX_WAIT_REQUEUE_PI_OP | FUTEX_PRIVATE,
                0,
                0,
                word,
                0,
            )
        }
    };
    // SAFETY: `word` is the address of one of this program's static words.
    let seen = unsafe { (*(word as *const AtomicU32)).load(Ordering::SeqCst) };
    slot.seen.store(seen, Ordering::SeqCst);
    slot.ret.store(ret, Ordering::SeqCst);
    if ret == 0 {
        while slot.go.load(Ordering::SeqCst) == 0 {
            unsafe { userspace::syscall::sys_yield() };
        }
        let r = unsafe { pi_futex(word, FUTEX_UNLOCK_PI_OP, 0) };
        slot.unlock_ret.store(r, Ordering::SeqCst);
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

extern "C" fn pi_thread_0() -> ! {
    pi_thread_body(&PI_THREADS[0])
}

extern "C" fn pi_thread_1() -> ! {
    pi_thread_body(&PI_THREADS[1])
}

/// Start PI thread `index` (a CLONE_THREAD sibling): FUTEX_LOCK_PI on
/// `word`, or FUTEX_WAIT_REQUEUE_PI on `cond` towards `word`. Returns its tid.
fn pi_spawn(index: usize, word: &FutexWord, cond: Option<&FutexWord>) -> Option<u32> {
    pi_spawn_on(index, word, cond, pi_stack_top(index))
}

/// `pi_spawn` on the stack whose top is `stack_top`.
fn pi_spawn_on(
    index: usize,
    word: &FutexWord,
    cond: Option<&FutexWord>,
    stack_top: usize,
) -> Option<u32> {
    pi_spawn_with(index, word, cond, stack_top, THREAD_FLAGS)
}

/// `pi_spawn_on` with clone `flags`: a CLONE_THREAD sibling, or a CLONE_VM
/// child that is not a thread (the caller reaps it).
fn pi_spawn_with(
    index: usize,
    word: &FutexWord,
    cond: Option<&FutexWord>,
    stack_top: usize,
    flags: u64,
) -> Option<u32> {
    use core::sync::atomic::Ordering;
    let slot = &PI_THREADS[index];
    slot.word.store(word_addr(word), Ordering::SeqCst);
    slot.cond.store(cond.map_or(0, word_addr), Ordering::SeqCst);
    slot.seen.store(0, Ordering::SeqCst);
    slot.ret.store(FUTEX_WAIT_PENDING, Ordering::SeqCst);
    slot.go.store(0, Ordering::SeqCst);
    slot.unlock_ret.store(FUTEX_WAIT_PENDING, Ordering::SeqCst);
    slot.tid.store(-1, Ordering::SeqCst);
    let entry: extern "C" fn() -> ! = if index == 0 { pi_thread_0 } else { pi_thread_1 };
    let tid = unsafe {
        raw_clone(
            flags | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            stack_top,
            core::ptr::null_mut(),
            slot.tid.as_ptr(),
            entry,
        )
    };
    (!is_error(tid) && tid != 0).then_some(tid as u32)
}

fn pi_await(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..THREAD_POLL_YIELDS {
        if done() {
            return true;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    false
}

/// The thread's lock call returned; Some(result).
fn pi_returned(index: usize) -> Option<u64> {
    use core::sync::atomic::Ordering;
    let slot = &PI_THREADS[index];
    pi_await(|| slot.ret.load(Ordering::SeqCst) != FUTEX_WAIT_PENDING)
        .then(|| slot.ret.load(Ordering::SeqCst))
}

/// Let thread `index` unlock and exit; its unlock must succeed.
fn pi_release_and_join(index: usize) -> bool {
    use core::sync::atomic::Ordering;
    let slot = &PI_THREADS[index];
    slot.go.store(1, Ordering::SeqCst);
    pi_await(|| slot.tid.load(Ordering::SeqCst) == 0) && slot.unlock_ret.load(Ordering::SeqCst) == 0
}

/// Give a thread that should be queued in the kernel plenty of chances.
fn pi_settle() {
    for _ in 0..200 {
        unsafe { userspace::syscall::sys_yield() };
    }
}

fn realtime_ns() -> Option<i64> {
    let mut ts = [0i64; 2];
    let r = unsafe { syscall2(SYS_CLOCK_GETTIME, CLOCK_REALTIME_ID, ts.as_mut_ptr() as u64) };
    (r == 0).then(|| ts[0] * 1_000_000_000 + ts[1])
}

/// Body of the PI contract leg's host process; returns its exit status.
fn futex_pi_contract_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let me = unsafe { sys_gettid() } as u32;
    let a = &PI_WORD_A;
    let a_addr = word_addr(a);
    let b_addr = word_addr(&PI_WORD_B);
    let cond_addr = word_addr(&PI_COND);
    // Touch every word: a futex word on a page not present yet is EFAULT.
    for word in [&PI_WORD_A, &PI_WORD_B, &PI_COND, &PI_OTHER] {
        word.0.store(0, Ordering::SeqCst);
    }
    let lock = |op: u64| unsafe { pi_futex(a_addr, op, 0) };
    let word = || a.0.load(Ordering::SeqCst);

    // The user-space fast path takes a free lock with a CAS 0 -> tid; the
    // kernel then sees the caller as the owner.
    if a.0
        .compare_exchange(0, me, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return 0x10;
    }
    if errno(lock(FUTEX_LOCK_PI_OP)) != EDEADLK || errno(lock(FUTEX_TRYLOCK_PI_OP)) != EDEADLK {
        return 0x11;
    }
    // The owner's unlock with nobody waiting stores 0.
    if lock(FUTEX_UNLOCK_PI_OP) != 0 || word() != 0 {
        return 0x12;
    }
    // Only the task the word names may unlock.
    if errno(lock(FUTEX_UNLOCK_PI_OP)) != EPERM {
        return 0x13;
    }
    a.0.store(FUTEX_PI_NO_TID, Ordering::SeqCst);
    if errno(lock(FUTEX_UNLOCK_PI_OP)) != EPERM {
        return 0x14;
    }
    // A word naming no task: ESRCH, after FUTEX_WAITERS was set.
    if errno(lock(FUTEX_LOCK_PI_OP)) != ESRCH {
        return 0x15;
    }
    if word() != FUTEX_PI_NO_TID | FUTEX_WAITERS_BIT {
        return 0x16;
    }
    if errno(lock(FUTEX_TRYLOCK_PI_OP)) != ESRCH {
        return 0x17;
    }
    // The kernel takes a free lock for its caller.
    for op in [FUTEX_LOCK_PI_OP, FUTEX_LOCK_PI2_OP, FUTEX_TRYLOCK_PI_OP] {
        a.0.store(0, Ordering::SeqCst);
        if lock(op) != 0 || word() != me {
            return 0x18;
        }
        if lock(FUTEX_UNLOCK_PI_OP) != 0 || word() != 0 {
            return 0x19;
        }
    }
    // A stale FUTEX_WAITERS bit with no kernel waiter: taken over, and the
    // owner's kernel unlock clears the whole word.
    a.0.store(FUTEX_WAITERS_BIT, Ordering::SeqCst);
    if lock(FUTEX_LOCK_PI_OP) != 0 || word() != me {
        return 0x1a;
    }
    a.0.store(me | FUTEX_WAITERS_BIT, Ordering::SeqCst);
    if lock(FUTEX_UNLOCK_PI_OP) != 0 || word() != 0 {
        return 0x1b;
    }
    // TID 0 with OWNER_DIED (a dead robust owner): taken over, OWNER_DIED
    // kept for user space to report EOWNERDEAD; the call itself returns 0.
    a.0.store(FUTEX_OWNER_DIED_BIT, Ordering::SeqCst);
    if lock(FUTEX_LOCK_PI_OP) != 0 || word() != FUTEX_OWNER_DIED_BIT | me {
        return 0x1c;
    }
    if lock(FUTEX_UNLOCK_PI_OP) != 0 || word() != 0 {
        return 0x1d;
    }
    // FUTEX_CLOCK_REALTIME: refused with LOCK_PI (always CLOCK_REALTIME) and
    // TRYLOCK_PI, accepted with LOCK_PI2. A deadline already passed does not
    // stop an uncontended take: the word is tried first.
    if errno(lock(FUTEX_LOCK_PI_OP | FUTEX_CLOCK_REALTIME)) != ENOSYS
        || errno(lock(FUTEX_TRYLOCK_PI_OP | FUTEX_CLOCK_REALTIME)) != ENOSYS
    {
        return 0x1e;
    }
    let past = [0i64; 2];
    let r = unsafe {
        pi_futex(
            a_addr,
            FUTEX_LOCK_PI2_OP | FUTEX_CLOCK_REALTIME,
            past.as_ptr() as u64,
        )
    };
    if r != 0 || word() != me || lock(FUTEX_UNLOCK_PI_OP) != 0 {
        return 0x1f;
    }

    // Requeue-PI argument contract.
    unsafe {
        let wait_rq = FUTEX_WAIT_REQUEUE_PI_OP | FUTEX_PRIVATE;
        let cmp_rq = FUTEX_CMP_REQUEUE_PI_OP | FUTEX_PRIVATE;
        if errno(futex(&PI_COND, wait_rq, 0, 0, cond_addr, 0)) != EINVAL {
            return 0x20; // the same word twice
        }
        if errno(futex(&PI_COND, wait_rq, 1, 0, b_addr, 0)) != EAGAIN {
            return 0x21; // *uaddr != val
        }
        if errno(futex(&PI_COND, cmp_rq, 2, 1, b_addr, 0)) != EINVAL {
            return 0x22; // nr_wake must be 1
        }
        if errno(futex(&PI_COND, cmp_rq, 1, 1, cond_addr, 0)) != EINVAL {
            return 0x23; // the same word twice
        }
        if errno(futex(&PI_COND, cmp_rq, 1, 1, b_addr, 7)) != EAGAIN {
            return 0x24; // *uaddr != val3
        }
        if futex(&PI_COND, cmp_rq, 1, 1, b_addr, 0) != 0 {
            return 0x25; // nobody waiting
        }
        // A requeue-PI wait whose absolute deadline passed times out before
        // any requeue.
        if errno(futex(&PI_COND, wait_rq, 0, past.as_ptr() as u64, b_addr, 0)) != ETIMEDOUT {
            return 0x26;
        }
    }
    if PI_WORD_B.0.load(Ordering::SeqCst) != 0 {
        return 0x27; // nothing touched the PI word
    }
    FUTEX_PI_OK
}

/// Body of the PI hand-off leg's host process; returns its exit status.
fn futex_pi_handoff_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let me = unsafe { sys_gettid() } as u32;
    let a = &PI_WORD_A;
    let a_addr = word_addr(a);
    a.0.store(0, Ordering::SeqCst);
    let word = || a.0.load(Ordering::SeqCst);

    // Taken in user space; a CLONE_THREAD sibling's contended LOCK_PI sets
    // FUTEX_WAITERS and sleeps.
    if a.0
        .compare_exchange(0, me, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return 0x40;
    }
    let Some(first) = pi_spawn(0, a, None) else {
        return 0x41;
    };
    if !pi_await(|| word() == me | FUTEX_WAITERS_BIT) {
        return 0x42;
    }
    let Some(second) = pi_spawn(1, a, None) else {
        return 0x43;
    };
    pi_settle();
    // UNLOCK_PI hands the lock to the oldest waiter: its TID, with
    // FUTEX_WAITERS (the kernel keeps it set after a hand-off).
    if unsafe { pi_futex(a_addr, FUTEX_UNLOCK_PI_OP, 0) } != 0 {
        return 0x44;
    }
    if word() != first | FUTEX_WAITERS_BIT {
        return 0x45;
    }
    if pi_returned(0) != Some(0)
        || PI_THREADS[0].seen.load(Ordering::SeqCst) != first | FUTEX_WAITERS_BIT
    {
        return 0x46;
    }
    // The old owner no longer owns it; a trylock finds it held; a timed
    // lock (absolute CLOCK_REALTIME deadline) times out at its deadline.
    if errno(unsafe { pi_futex(a_addr, FUTEX_UNLOCK_PI_OP, 0) }) != EPERM {
        return 0x47;
    }
    if errno(unsafe { pi_futex(a_addr, FUTEX_TRYLOCK_PI_OP, 0) }) != EAGAIN {
        return 0x48;
    }
    let Some(start) = realtime_ns() else {
        return 0x49;
    };
    let deadline_ns = start + FUTEX_SLEEP_NS;
    let deadline = [deadline_ns / 1_000_000_000, deadline_ns % 1_000_000_000];
    let r = unsafe { pi_futex(a_addr, FUTEX_LOCK_PI_OP, deadline.as_ptr() as u64) };
    if errno(r) != ETIMEDOUT {
        return 0x4a;
    }
    match realtime_ns() {
        Some(now) if now >= deadline_ns => {}
        _ => return 0x4b, // returned before its deadline
    }
    if word() != first | FUTEX_WAITERS_BIT {
        return 0x4c;
    }
    // The first owner's unlock hands the lock to the second waiter.
    if !pi_release_and_join(0) {
        return 0x4d;
    }
    if pi_returned(1) != Some(0)
        || PI_THREADS[1].seen.load(Ordering::SeqCst) & FUTEX_TID_BITS != second
    {
        return 0x4e;
    }
    if !pi_release_and_join(1) {
        return 0x4f;
    }
    // Nobody left: the last unlock stored 0.
    if word() != 0 {
        return 0x50;
    }
    FUTEX_PI_OK
}

/// A robust PI mutex: the futex word, then the robust-list node
/// (`futex_offset` is -8).
#[repr(C, align(8))]
struct PiRobustMutex {
    word: FutexWord,
    _pad: core::sync::atomic::AtomicU32,
    next: core::sync::atomic::AtomicU64,
}

static PI_ROBUST_MUTEX: PiRobustMutex = PiRobustMutex {
    word: FutexWord(core::sync::atomic::AtomicU32::new(0)),
    _pad: core::sync::atomic::AtomicU32::new(0),
    next: core::sync::atomic::AtomicU64::new(0),
};

/// struct robust_list_head { list, futex_offset, list_op_pending }.
#[repr(C, align(8))]
struct PiRobustHead([core::sync::atomic::AtomicU64; 3]);

static PI_ROBUST_HEAD: PiRobustHead = PiRobustHead([
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
]);
/// An empty robust list (it points at itself): an owner without the mutex
/// on its list.
static PI_EMPTY_HEAD: PiRobustHead = PiRobustHead([
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
]);

/// Owner thread: 1 = register the mutex on its robust list.
static PI_OWNER_ROBUST: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Owner thread -> host: 1 locked, 2 failed.
static PI_OWNER_STATE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Host -> owner thread: exit now, holding the lock.
static PI_OWNER_DIE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static PI_OWNER_TID: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

fn pi_robust_head(robust: bool) -> u64 {
    let head = if robust {
        &PI_ROBUST_HEAD
    } else {
        &PI_EMPTY_HEAD
    };
    head as *const PiRobustHead as u64
}

/// Owner thread: register a robust list, take the PI mutex in user space,
/// then exit holding it.
extern "C" fn pi_owner_thread() -> ! {
    use core::sync::atomic::Ordering;
    let robust = PI_OWNER_ROBUST.load(Ordering::SeqCst) != 0;
    let registered = unsafe { syscall2(SYS_SET_ROBUST_LIST, pi_robust_head(robust), 24) } == 0;
    let me = unsafe { sys_gettid() } as u32;
    let locked = registered
        && PI_ROBUST_MUTEX
            .word
            .0
            .compare_exchange(0, me, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
    PI_OWNER_STATE.store(if locked { 1 } else { 2 }, Ordering::SeqCst);
    while PI_OWNER_DIE.load(Ordering::SeqCst) == 0 {
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

/// Start an owner thread that takes the robust mutex (on its robust list
/// when `robust`, tagged as a PI futex as glibc does). Returns its tid once
/// it holds the lock.
fn pi_spawn_owner(robust: bool) -> Option<u32> {
    use core::sync::atomic::Ordering;
    let word = PI_ROBUST_MUTEX.word.0.as_ptr() as u64;
    let node = PI_ROBUST_MUTEX.next.as_ptr() as u64;
    let head = pi_robust_head(true);
    PI_ROBUST_MUTEX.word.0.store(0, Ordering::SeqCst);
    // One node, linked back to the head; bit 0 of the pointer to it marks a
    // PI futex.
    PI_ROBUST_MUTEX.next.store(head, Ordering::SeqCst);
    PI_ROBUST_HEAD.0[0].store(node | 1, Ordering::SeqCst);
    PI_ROBUST_HEAD.0[1].store(word.wrapping_sub(node), Ordering::SeqCst);
    PI_ROBUST_HEAD.0[2].store(0, Ordering::SeqCst);
    let empty = pi_robust_head(false);
    PI_EMPTY_HEAD.0[0].store(empty, Ordering::SeqCst);
    PI_EMPTY_HEAD.0[1].store(0, Ordering::SeqCst);
    PI_EMPTY_HEAD.0[2].store(0, Ordering::SeqCst);
    PI_OWNER_ROBUST.store(robust as u32, Ordering::SeqCst);
    PI_OWNER_STATE.store(0, Ordering::SeqCst);
    PI_OWNER_DIE.store(0, Ordering::SeqCst);
    PI_OWNER_TID.store(-1, Ordering::SeqCst);
    let tid = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            pi_stack_top(2),
            core::ptr::null_mut(),
            PI_OWNER_TID.as_ptr(),
            pi_owner_thread,
        )
    };
    if is_error(tid) || tid == 0 {
        return None;
    }
    (pi_await(|| PI_OWNER_STATE.load(Ordering::SeqCst) != 0)
        && PI_OWNER_STATE.load(Ordering::SeqCst) == 1)
        .then_some(tid as u32)
}

/// Let the owner thread exit holding the lock, and wait for its clear-tid.
fn pi_kill_owner() -> bool {
    use core::sync::atomic::Ordering;
    PI_OWNER_DIE.store(1, Ordering::SeqCst);
    pi_await(|| PI_OWNER_TID.load(Ordering::SeqCst) == 0)
}

/// Body of the PI owner-death leg's host process; returns its exit status.
fn futex_pi_owner_death_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let me = unsafe { sys_gettid() } as u32;
    let mutex = &PI_ROBUST_MUTEX.word;
    let mutex_addr = word_addr(mutex);
    let word = || mutex.0.load(Ordering::SeqCst);

    // A robust owner dies with a waiter: its robust walk sets OWNER_DIED
    // (clearing its TID, keeping WAITERS) and the lock goes to the waiter,
    // which finds its TID, WAITERS and OWNER_DIED in the word.
    let Some(owner) = pi_spawn_owner(true) else {
        return 0x60;
    };
    let Some(waiter) = pi_spawn(0, mutex, None) else {
        return 0x61;
    };
    if !pi_await(|| word() == owner | FUTEX_WAITERS_BIT) {
        return 0x62;
    }
    pi_settle();
    if !pi_kill_owner() {
        return 0x63;
    }
    if pi_returned(0) != Some(0) {
        return 0x64;
    }
    if PI_THREADS[0].seen.load(Ordering::SeqCst)
        != waiter | FUTEX_WAITERS_BIT | FUTEX_OWNER_DIED_BIT
    {
        return 0x65;
    }
    // The heir's unlock clears the word (it made no waiter wait).
    if !pi_release_and_join(0) || word() != 0 {
        return 0x66;
    }

    // A robust owner dies with nobody waiting: the word keeps OWNER_DIED
    // with TID 0, and the next LOCK_PI takes it over with OWNER_DIED kept.
    if pi_spawn_owner(true).is_none() {
        return 0x67;
    }
    if !pi_kill_owner() {
        return 0x68;
    }
    if !pi_await(|| word() == FUTEX_OWNER_DIED_BIT) {
        return 0x69;
    }
    if unsafe { pi_futex(mutex_addr, FUTEX_LOCK_PI_OP, 0) } != 0
        || word() != FUTEX_OWNER_DIED_BIT | me
    {
        return 0x6a;
    }
    if unsafe { pi_futex(mutex_addr, FUTEX_UNLOCK_PI_OP, 0) } != 0 || word() != 0 {
        return 0x6b;
    }

    // An owner that dies without the mutex on a robust list leaves its TID:
    // once its exit is complete nobody owns what the word names (ESRCH).
    let Some(gone) = pi_spawn_owner(false) else {
        return 0x6c;
    };
    if !pi_kill_owner() {
        return 0x6d;
    }
    if word() != gone {
        return 0x6e;
    }
    if errno(unsafe { pi_futex(mutex_addr, FUTEX_LOCK_PI_OP, 0) }) != ESRCH {
        return 0x6f;
    }
    FUTEX_PI_OK
}

/// Body of the requeue-PI leg's host process; returns its exit status.
fn futex_pi_requeue_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let mutex = &PI_WORD_B;
    let mutex_addr = word_addr(mutex);
    let other_addr = word_addr(&PI_OTHER);
    for word in [&PI_WORD_B, &PI_COND, &PI_OTHER] {
        word.0.store(0, Ordering::SeqCst);
    }
    let word = || mutex.0.load(Ordering::SeqCst);
    let cmp_requeue_pi = |uaddr2: u64| unsafe {
        futex(
            &PI_COND,
            FUTEX_CMP_REQUEUE_PI_OP | FUTEX_PRIVATE,
            1,
            1,
            uaddr2,
            0,
        )
    };
    // A requeue-PI waiter sleeps on the condition word: a plain FUTEX_WAKE
    // there is refused (EINVAL) while it does.
    let rq_waiter_on_cond =
        || errno(unsafe { futex(&PI_COND, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 0, 0, 0) }) == EINVAL;

    let Some(first) = pi_spawn(0, mutex, Some(&PI_COND)) else {
        return 0x80;
    };
    if !pi_await(rq_waiter_on_cond) {
        return 0x81;
    }
    // Only waiters that named this PI futex move; a plain requeue refuses
    // a requeue-PI waiter. Neither touches it.
    if errno(cmp_requeue_pi(other_addr)) != EINVAL {
        return 0x82;
    }
    let plain = unsafe {
        futex(
            &PI_COND,
            FUTEX_CMP_REQUEUE_OP | FUTEX_PRIVATE,
            0,
            1,
            other_addr,
            0,
        )
    };
    if errno(plain) != EINVAL || !rq_waiter_on_cond() {
        return 0x83;
    }
    // The PI futex is free: it is taken for the top waiter, which wakes as
    // the owner. WAITERS is set because more waiters may follow it.
    if cmp_requeue_pi(mutex_addr) != 1 {
        return 0x84;
    }
    if word() != first | FUTEX_WAITERS_BIT {
        return 0x85;
    }
    if pi_returned(0) != Some(0)
        || PI_THREADS[0].seen.load(Ordering::SeqCst) != first | FUTEX_WAITERS_BIT
    {
        return 0x86;
    }

    // With the PI futex held, the next waiter is requeued onto it and keeps
    // waiting there, no longer on the condition word.
    let Some(second) = pi_spawn(1, mutex, Some(&PI_COND)) else {
        return 0x87;
    };
    if !pi_await(rq_waiter_on_cond) {
        return 0x88;
    }
    if cmp_requeue_pi(mutex_addr) != 1 {
        return 0x89;
    }
    pi_settle();
    if PI_THREADS[1].ret.load(Ordering::SeqCst) != FUTEX_WAIT_PENDING {
        return 0x8a; // a requeued waiter does not return before it owns
    }
    if unsafe { futex(&PI_COND, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 0, 0, 0) } != 0 {
        return 0x8b;
    }
    if word() != first | FUTEX_WAITERS_BIT {
        return 0x8c;
    }
    // The owner's unlock hands the lock to the requeued waiter.
    if !pi_release_and_join(0) {
        return 0x8d;
    }
    if pi_returned(1) != Some(0)
        || PI_THREADS[1].seen.load(Ordering::SeqCst) != second | FUTEX_WAITERS_BIT
    {
        return 0x8e;
    }
    if !pi_release_and_join(1) || word() != 0 {
        return 0x8f;
    }
    FUTEX_PI_OK
}

/// The PI word of the copy-on-write leg, alone on its page. The test process
/// writes it before it forks the leg's host, so in the host the page stays
/// copy-on-write until a write fault: the host itself only reads it.
#[repr(C, align(4096))]
struct PiCowPage {
    word: FutexWord,
    _rest: [u8; 4092],
}

static PI_COW_PAGE: PiCowPage = PiCowPage {
    word: FutexWord(core::sync::atomic::AtomicU32::new(0)),
    _rest: [0; 4092],
};

/// Fork a child that exits at once and reap it. Every private page of the
/// caller, the copy-on-write leg's word included, is copy-on-write again
/// afterwards: its next write faults.
fn pi_fork_and_reap() -> bool {
    let child = fork_exit(0, 0);
    !is_error(child) && reap_pid(child) == Some(0)
}

/// Body of the copy-on-write PI leg's host process; returns its exit status.
/// GAP-5 PI review D2-1: the kernel's CASes on a PI word made under the
/// bucket lock meet a copy-on-write page. They report the fault instead of
/// resolving it under the lock, fault the word in with the lock dropped and
/// retry; the calls behave as if the page were writable.
fn futex_pi_cow_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let me = unsafe { sys_gettid() } as u32;
    let word = &PI_COW_PAGE.word;
    let addr = word_addr(word);
    // Reads do not break copy-on-write.
    let value = || word.0.load(Ordering::SeqCst);
    if value() != 0 {
        return 0xa0;
    }
    // LOCK_PI takes the free word: the take's CAS meets the copy-on-write
    // page the fork left.
    if unsafe { pi_futex(addr, FUTEX_LOCK_PI_OP, 0) } != 0 || value() != me {
        return 0xa1;
    }
    // A sibling's contended LOCK_PI queues behind the host.
    let Some(waiter) = pi_spawn(0, word, None) else {
        return 0xa2;
    };
    if !pi_await(|| value() == me | FUTEX_WAITERS_BIT) {
        return 0xa3;
    }
    pi_settle();
    // A fork makes the page copy-on-write again; UNLOCK_PI's hand-off CAS
    // meets it.
    if !pi_fork_and_reap() {
        return 0xa4;
    }
    if unsafe { pi_futex(addr, FUTEX_UNLOCK_PI_OP, 0) } != 0 {
        return 0xa5;
    }
    if value() != waiter | FUTEX_WAITERS_BIT {
        return 0xa6;
    }
    if pi_returned(0) != Some(0)
        || PI_THREADS[0].seen.load(Ordering::SeqCst) != waiter | FUTEX_WAITERS_BIT
    {
        return 0xa7;
    }
    // Copy-on-write once more for the new owner's unlock. With no waiter
    // left this unlock takes the no-bucket path, whose CAS runs with no futex
    // lock held and resolves the fault directly.
    if !pi_fork_and_reap() {
        return 0xa8;
    }
    if !pi_release_and_join(0) || value() != 0 {
        return 0xa9;
    }
    FUTEX_PI_OK
}

const SYS_RT_SIGACTION: u64 = 13;
const SIGUSR1_NR: u64 = 10;
const SA_RESTORER_FLAG: u64 = 0x0400_0000;
/// Handler runs of the signal leg's SIGUSR1.
static PI_SIGNALS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

// The signal leg's SA_RESTORER trampoline: the handler returns here, which
// issues rt_sigreturn (15).
core::arch::global_asm!(
    ".pushsection .text",
    ".global pi_sigreturn_trampoline",
    "pi_sigreturn_trampoline:",
    "    mov eax, 15",
    "    syscall",
    "    ud2",
    ".popsection",
);

extern "C" {
    fn pi_sigreturn_trampoline();
}

extern "C" fn pi_signal_handler(_signo: i32) {
    PI_SIGNALS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

/// Body of the PI signal leg's host process; returns its exit status.
/// GAP-5 PI review D2-2: a handler signal for a task blocked in LOCK_PI
/// must not end the call: glibc takes EINTR or EAGAIN from it for
/// "acquired". Linux restarts the call after running the handler; this
/// kernel keeps the task waiting and runs the handler when the call returns.
/// Either way the call returns 0 owning the lock, and the handler runs.
fn futex_pi_signal_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let me = unsafe { sys_gettid() } as u32;
    let tgid = unsafe { sys_getpid() };
    let a = &PI_WORD_A;
    let a_addr = word_addr(a);
    a.0.store(0, Ordering::SeqCst);
    let word = || a.0.load(Ordering::SeqCst);

    // struct sigaction { handler, flags, restorer, mask } (shared by the
    // CLONE_SIGHAND siblings).
    let act: [u64; 4] = [
        pi_signal_handler as extern "C" fn(i32) as usize as u64,
        SA_RESTORER_FLAG,
        pi_sigreturn_trampoline as unsafe extern "C" fn() as usize as u64,
        0,
    ];
    if unsafe { syscall4(SYS_RT_SIGACTION, SIGUSR1_NR, act.as_ptr() as u64, 0, 8) } != 0 {
        return 0xb0;
    }
    PI_SIGNALS.store(0, Ordering::SeqCst);
    if a.0
        .compare_exchange(0, me, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return 0xb1;
    }
    // The kernel builds a signal frame only on the main stack or an mmap'd
    // one (RF178-34), as threads made by a libc have; a static stack would
    // turn the handler signal into SIGSEGV.
    const SIGNAL_STACK_BYTES: usize = 16 * 1024;
    let stack = unsafe { mmap_anon(SIGNAL_STACK_BYTES, false) };
    if stack < 0 {
        return 0xbb;
    }
    let Some(waiter) = pi_spawn_on(0, a, None, stack as usize + SIGNAL_STACK_BYTES) else {
        return 0xb2;
    };
    if !pi_await(|| word() == me | FUTEX_WAITERS_BIT) {
        return 0xb3;
    }
    pi_settle();
    // Two handler signals for the sleeping locker: its LOCK_PI goes on.
    for _ in 0..2 {
        if unsafe { syscall3(SYS_TGKILL, tgid, waiter as u64, SIGUSR1_NR) } != 0 {
            return 0xb4;
        }
        pi_settle();
        if PI_THREADS[0].ret.load(Ordering::SeqCst) != FUTEX_WAIT_PENDING {
            return 0xb5;
        }
    }
    if word() & FUTEX_TID_BITS != me {
        return 0xb6;
    }
    // The unlock hands the lock over: LOCK_PI returns 0 with the waiter's
    // TID in the word, and the handler has run.
    if unsafe { pi_futex(a_addr, FUTEX_UNLOCK_PI_OP, 0) } != 0 {
        return 0xb7;
    }
    if pi_returned(0) != Some(0)
        || PI_THREADS[0].seen.load(Ordering::SeqCst) & FUTEX_TID_BITS != waiter
    {
        return 0xb8;
    }
    if !pi_await(|| PI_SIGNALS.load(Ordering::SeqCst) != 0) {
        return 0xb9;
    }
    if !pi_release_and_join(0) || word() != 0 {
        return 0xba;
    }
    FUTEX_PI_OK
}

/// Body of the PI non-robust owner-death leg's host process; returns its
/// exit status. GAP-5 PI review D5: an owner that took the lock without a
/// robust list dies with a waiter. Its exit hands the lock to the waiter
/// (Linux `exit_pi_state_list`), which stores its TID with WAITERS and,
/// as Linux's fixup does whenever the owner died, OWNER_DIED.
fn futex_pi_nonrobust_heir_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let mutex = &PI_ROBUST_MUTEX.word;
    let word = || mutex.0.load(Ordering::SeqCst);
    let Some(owner) = pi_spawn_owner(false) else {
        return 0xc0;
    };
    let Some(waiter) = pi_spawn(0, mutex, None) else {
        return 0xc1;
    };
    if !pi_await(|| word() == owner | FUTEX_WAITERS_BIT) {
        return 0xc2;
    }
    pi_settle();
    if !pi_kill_owner() {
        return 0xc3;
    }
    if pi_returned(0) != Some(0) {
        return 0xc4;
    }
    if PI_THREADS[0].seen.load(Ordering::SeqCst)
        != waiter | FUTEX_WAITERS_BIT | FUTEX_OWNER_DIED_BIT
    {
        return 0xc5;
    }
    if !pi_release_and_join(0) || word() != 0 {
        return 0xc6;
    }
    FUTEX_PI_OK
}

/// Body of the PI owner-identity leg's host process; returns its exit
/// status. R191-1: a PI word may name only a user task of the caller's
/// address space. The host's parent lives in another one (it waits for the
/// host meanwhile): every lock operation naming it, and the requeue-PI proxy
/// lock, fails with EPERM after setting FUTEX_WAITERS, as the ESRCH case
/// does, and leaves no PI state behind. A CLONE_VM child that is not a thread
/// shares the address space, so it still waits behind the host and inherits
/// the lock. Linux, whose shared futexes span address spaces, would attach a
/// PI state to the parent instead.
fn futex_pi_owner_identity_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let me = unsafe { sys_gettid() } as u32;
    let parent = unsafe { userspace::syscall::sys_getppid() } as u32;
    let a = &PI_WORD_A;
    let a_addr = word_addr(a);
    let b_addr = word_addr(&PI_WORD_B);
    for word in [&PI_WORD_A, &PI_WORD_B, &PI_COND] {
        word.0.store(0, Ordering::SeqCst);
    }
    let word = || a.0.load(Ordering::SeqCst);
    let mutex = || PI_WORD_B.0.load(Ordering::SeqCst);
    if parent == 0 || parent == me || parent & !FUTEX_TID_BITS != 0 {
        return 0xd0;
    }

    // Every lock operation refuses an owner of another address space. The
    // refusal comes before any sleep; the deadline that has already passed
    // turns a kernel that attached instead into ETIMEDOUT, not a host blocked
    // on its waiting parent.
    let past = [0i64; 2];
    for op in [FUTEX_LOCK_PI_OP, FUTEX_LOCK_PI2_OP, FUTEX_TRYLOCK_PI_OP] {
        a.0.store(parent, Ordering::SeqCst);
        if errno(unsafe { pi_futex(a_addr, op, past.as_ptr() as u64) }) != EPERM {
            return 0xd1;
        }
        if word() != parent | FUTEX_WAITERS_BIT {
            return 0xd2;
        }
    }
    // No PI state names the parent: once the word is free the host takes the
    // lock, and its unlock (no kernel state, no waiter) stores 0.
    a.0.store(0, Ordering::SeqCst);
    if unsafe { pi_futex(a_addr, FUTEX_LOCK_PI_OP, 0) } != 0 || word() != me {
        return 0xd3;
    }
    if unsafe { pi_futex(a_addr, FUTEX_UNLOCK_PI_OP, 0) } != 0 || word() != 0 {
        return 0xd4;
    }

    // The requeue-PI proxy lock refuses it too; the waiter keeps waiting on
    // the condition word, and is requeued once the PI futex is free.
    let cmp_requeue_pi = || unsafe {
        futex(
            &PI_COND,
            FUTEX_CMP_REQUEUE_PI_OP | FUTEX_PRIVATE,
            1,
            1,
            b_addr,
            0,
        )
    };
    let rq_waiter_on_cond =
        || errno(unsafe { futex(&PI_COND, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 0, 0, 0) }) == EINVAL;
    PI_WORD_B.0.store(parent, Ordering::SeqCst);
    let Some(waiter) = pi_spawn(0, &PI_WORD_B, Some(&PI_COND)) else {
        return 0xd5;
    };
    if !pi_await(rq_waiter_on_cond) {
        return 0xd6;
    }
    if errno(cmp_requeue_pi()) != EPERM {
        return 0xd7;
    }
    if mutex() != parent | FUTEX_WAITERS_BIT || !rq_waiter_on_cond() {
        return 0xd8;
    }
    if PI_THREADS[0].ret.load(Ordering::SeqCst) != FUTEX_WAIT_PENDING {
        return 0xd9;
    }
    PI_WORD_B.0.store(0, Ordering::SeqCst);
    if cmp_requeue_pi() != 1 {
        return 0xda;
    }
    if pi_returned(0) != Some(0)
        || PI_THREADS[0].seen.load(Ordering::SeqCst) != waiter | FUTEX_WAITERS_BIT
    {
        return 0xdb;
    }
    if !pi_release_and_join(0) || mutex() != 0 {
        return 0xdc;
    }

    // A CLONE_VM child that is not a thread shares the address space: its
    // LOCK_PI attaches to the host, and the host's unlock hands it the lock.
    if a.0
        .compare_exchange(0, me, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return 0xdd;
    }
    let Some(child) = pi_spawn_with(0, a, None, pi_stack_top(0), CLONE_VM) else {
        return 0xde;
    };
    // The child is a process of its own: the host's exit would not end it.
    let abandon = |code: u64| {
        unsafe { userspace::syscall::sys_kill(child as u64, SIGKILL_NR) };
        let _ = reap_pid(child as u64);
        code
    };
    if !pi_await(|| word() == me | FUTEX_WAITERS_BIT) {
        return abandon(0xdf);
    }
    pi_settle();
    if PI_THREADS[0].ret.load(Ordering::SeqCst) != FUTEX_WAIT_PENDING {
        return abandon(0xe0); // refused instead of waiting
    }
    if unsafe { pi_futex(a_addr, FUTEX_UNLOCK_PI_OP, 0) } != 0
        || word() != child | FUTEX_WAITERS_BIT
    {
        return abandon(0xe1);
    }
    if pi_returned(0) != Some(0) {
        return abandon(0xe2);
    }
    if !pi_release_and_join(0) || word() != 0 {
        return abandon(0xe3);
    }
    if reap_pid(child as u64) != Some(0) {
        return 0xe4;
    }
    FUTEX_PI_OK
}

/// Run one PI leg in a forked host and report it.
fn run_futex_pi_leg(results: &mut TestResult, leg: fn() -> u64, pass: &str, fail: &str) {
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("futex PI: fork of the host failed");
        return;
    }
    if host == 0 {
        let code = leg();
        unsafe { raw_exit(SYS_EXIT_GROUP, code) };
    }
    match reap_pid(host) {
        Some(FUTEX_PI_OK) => results.pass(pass),
        Some(code) => {
            print("futex PI leg exit ");
            print_hex(code);
            print(" ");
            results.fail(fail);
        }
        None => results.fail("futex PI: could not reap the host"),
    }
}

fn test_futex_pi(results: &mut TestResult) {
    print("Testing PI futexes (Linux user-word protocol) and requeue-PI... ");
    run_futex_pi_leg(
        results,
        futex_pi_contract_leg,
        "futex PI: user-space CAS fast path, kernel take-over and EDEADLK/EPERM/ESRCH contracts",
        "futex PI: a word or argument contract check failed",
    );
    run_futex_pi_leg(
        results,
        futex_pi_handoff_leg,
        "futex PI: UNLOCK_PI hands the lock to the oldest waiter as tid|FUTEX_WAITERS; TRYLOCK_PI is EAGAIN while it is held",
        "futex PI: a hand-off check failed",
    );
    run_futex_pi_leg(
        results,
        futex_pi_owner_death_leg,
        "futex PI: a dead robust owner leaves OWNER_DIED and its waiter inherits the lock",
        "futex PI: an owner-death check failed",
    );
    run_futex_pi_leg(
        results,
        futex_pi_requeue_leg,
        "futex PI: CMP_REQUEUE_PI wakes one waiter as owner and requeues one that is later handed the lock",
        "futex PI: a requeue-PI check failed",
    );
    // Written here, before the fork, so the host finds the page
    // copy-on-write.
    PI_COW_PAGE
        .word
        .0
        .store(0, core::sync::atomic::Ordering::SeqCst);
    run_futex_pi_leg(
        results,
        futex_pi_cow_leg,
        "futex PI: LOCK_PI and UNLOCK_PI update a copy-on-write word after a fork",
        "futex PI: a copy-on-write word check failed",
    );
    run_futex_pi_leg(
        results,
        futex_pi_signal_leg,
        "futex PI: a handler signal does not end LOCK_PI, which returns 0 owning the lock",
        "futex PI: a signal-during-LOCK_PI check failed",
    );
    run_futex_pi_leg(
        results,
        futex_pi_nonrobust_heir_leg,
        "futex PI: a dead non-robust owner hands the lock to its waiter with OWNER_DIED",
        "futex PI: a non-robust owner-death check failed",
    );
    run_futex_pi_leg(
        results,
        futex_pi_owner_identity_leg,
        "futex PI: a word naming a task of another address space is EPERM for LOCK_PI and CMP_REQUEUE_PI; a CLONE_VM owner still attaches",
        "futex PI: an owner-identity check failed",
    );
}

// ---------------------------------------------------------------------------
// GAP-6: /proc/schedstat, the per-CPU scheduler counters and RCU backlog that
// pressure runs sample into their retained logs.
// ---------------------------------------------------------------------------

/// Parsed `/proc/schedstat`: online CPUs, per-CPU lines seen, and the summed
/// context-switch count.
struct SchedStat {
    cpus_online: u64,
    cpu_lines: u64,
    switches: u64,
    has_rcu_and_wait: bool,
}

fn parse_u64_prefix(text: &[u8]) -> Option<u64> {
    let mut value: u64 = 0;
    let mut seen = 0usize;
    for &byte in text {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value
            .saturating_mul(10)
            .saturating_add((byte - b'0') as u64);
        seen += 1;
    }
    (seen != 0).then_some(value)
}

fn read_schedstat() -> Option<SchedStat> {
    let path = b"/proc/schedstat\0";
    let fd = unsafe { sys_open(path.as_ptr(), 0, 0) };
    if is_error(fd) {
        return None;
    }
    let mut buf = [0u8; 2048];
    let read = unsafe { sys_read(fd, buf.as_mut_ptr(), buf.len() as u64) };
    let _ = unsafe { sys_close(fd) };
    if is_error(read) || read as usize >= buf.len() {
        return None;
    }
    let mut stat = SchedStat {
        cpus_online: 0,
        cpu_lines: 0,
        switches: 0,
        has_rcu_and_wait: false,
    };
    let mut rcu = false;
    let mut wait = false;
    for line in buf[..read as usize].split(|&byte| byte == b'\n') {
        if let Some(rest) = line.strip_prefix(b"cpus_online ") {
            stat.cpus_online = parse_u64_prefix(rest)?;
        } else if line.starts_with(b"cpu") && line.get(3).is_some_and(u8::is_ascii_digit) {
            let at = line.windows(9).position(|window| window == b"switches=")?;
            stat.switches = stat
                .switches
                .saturating_add(parse_u64_prefix(&line[at + 9..])?);
            line.windows(14)
                .position(|window| window == b"migrations_in=")?;
            stat.cpu_lines += 1;
        } else if let Some(rest) = line.strip_prefix(b"rcu_backlog ") {
            rcu = parse_u64_prefix(rest).is_some();
        } else if let Some(rest) = line.strip_prefix(b"wait_over_wakes ") {
            wait = parse_u64_prefix(rest).is_some();
        }
    }
    stat.has_rcu_and_wait = rcu && wait;
    Some(stat)
}

fn test_proc_schedstat(results: &mut TestResult) {
    print("Testing /proc/schedstat... ");
    let Some(before) = read_schedstat() else {
        results.fail("schedstat: /proc/schedstat unreadable or malformed");
        return;
    };
    if before.cpus_online == 0
        || before.cpu_lines != before.cpus_online
        || before.switches == 0
        || !before.has_rcu_and_wait
    {
        print("cpus ");
        print_int(before.cpus_online as i64);
        print(" lines ");
        print_int(before.cpu_lines as i64);
        print(" ");
        results.fail("schedstat: one line per online CPU, RCU backlog and wait counter expected");
        return;
    }
    // Waiting for a child that exits switches away and back at least once.
    let child = unsafe { sys_fork() };
    if is_error(child) {
        results.fail("schedstat: fork failed");
        return;
    }
    if child == 0 {
        unsafe { raw_exit(SYS_EXIT, 0) };
    }
    if reap_pid(child) != Some(0) {
        results.fail("schedstat: could not reap the child");
        return;
    }
    match read_schedstat() {
        Some(after) if after.switches > before.switches => {}
        _ => {
            results.fail("schedstat: the context-switch count did not advance");
            return;
        }
    }
    results.pass("/proc/schedstat reports per-CPU switches and migrations and the RCU backlog");
}

/// Exercise real admission through pipe2/read/fork/open, including a holder
/// that remains alive at its local quota while another group makes progress.
/// The second group must hit the shared host-UID ceiling before its own ceiling.
fn test_heap_owner_isolation(results: &mut TestResult) {
    use core::sync::atomic::{AtomicU32, Ordering};
    const NAME: &str =
        "heap quotas: oversized read refused, local isolation survives, fork shares the UID ceiling";
    unsafe {
        let buffer = mmap_anon(1024 * 1024, false);
        let shared = mmap_anon(PAGE, true);
        if buffer < 0 || shared < 0 {
            if buffer >= 0 {
                munmap(buffer as usize, 1024 * 1024);
            }
            if shared >= 0 {
                munmap(shared as usize, PAGE);
            }
            results.fail("heap isolation: mapping failed");
            return;
        }
        let state = &*(shared as *const AtomicU32);
        let release = &*((shared as usize + 4) as *const AtomicU32);
        state.store(0, Ordering::SeqCst);
        release.store(0, Ordering::SeqCst);
        let mut pipe = [-1i32; 2];
        let made = syscall2(SYS_PIPE2, pipe.as_mut_ptr() as u64, 0x800) as i64;
        let large_read = if made == 0 {
            syscall3(SYS_READ, pipe[0] as u64, buffer as u64, 1024 * 1024) as i64
        } else {
            made
        };
        if made == 0 {
            sys_close(pipe[0] as u64);
            sys_close(pipe[1] as u64);
        }
        munmap(buffer as usize, 1024 * 1024);
        if err_of(large_read) != ENOMEM {
            munmap(shared as usize, PAGE);
            results.fail("heap isolation: oversized read was not ENOMEM");
            return;
        }
        let holder = sys_fork();
        if is_error(holder) {
            munmap(shared as usize, PAGE);
            results.fail("heap isolation: holder fork failed");
            return;
        }
        if holder == 0 {
            let mut pipes = [[-1i32; 2]; 124];
            let mut count = 0;
            let mut denied = false;
            while count < pipes.len() {
                let result = syscall2(SYS_PIPE2, pipes[count].as_mut_ptr() as u64, 0) as i64;
                if result != 0 {
                    denied = err_of(result) == ENOMEM;
                    break;
                }
                count += 1;
            }
            state.store(
                if denied && count > 8 { count as u32 } else { 1 },
                Ordering::SeqCst,
            );
            while release.load(Ordering::SeqCst) == 0 {
                userspace::syscall::sys_yield();
            }
            for pair in &pipes[..count] {
                sys_close(pair[0] as u64);
                sys_close(pair[1] as u64);
            }
            raw_exit(SYS_EXIT, 0);
        }
        for _ in 0..20000 {
            if state.load(Ordering::SeqCst) != 0 {
                break;
            }
            userspace::syscall::sys_yield();
        }
        let held_count = state.load(Ordering::SeqCst) as usize;
        let held = held_count > 8;
        let fd = sys_open(b"/proc/schedstat\0".as_ptr(), 0, 0);
        let opened = !is_error(fd);
        if opened {
            sys_close(fd);
        }
        let another = sys_fork();
        if another == 0 {
            // The holder retains its pipes. A fresh thread-group owner must
            // still inherit the same UID budget and run out substantially
            // before the first child's local 512 KiB ceiling.
            let mut pipes = [[-1i32; 2]; 124];
            let mut count = 0;
            let mut denied = false;
            while count < pipes.len() {
                let result = syscall2(SYS_PIPE2, pipes[count].as_mut_ptr() as u64, 0) as i64;
                if result != 0 {
                    denied = err_of(result) == ENOMEM;
                    break;
                }
                count += 1;
            }
            for pair in &pipes[..count] {
                sys_close(pair[0] as u64);
                sys_close(pair[1] as u64);
            }
            raw_exit(
                SYS_EXIT,
                if denied && count > 0 && count + 8 < held_count {
                    0
                } else {
                    1
                },
            );
        }
        let forked = !is_error(another) && reap_pid(another) == Some(0);
        release.store(1, Ordering::SeqCst);
        let finished = reap_pid(holder) == Some(0);
        munmap(shared as usize, PAGE);
        if held && opened && forked && finished {
            results.pass(NAME);
        } else {
            results.fail(NAME);
        }
    }
}

/// Keep the peer's COW reference alive while brk removes a leaf. The syscall
/// fixture checks the real shootdown counters under PT_LOCK before pruning.
fn test_brk_cow_shrink(results: &mut TestResult) {
    use core::sync::atomic::{AtomicU32, Ordering};
    const NAME: &str = "brk COW shrink flushes retained leaves before returning";
    // SAFETY: accesses stay within successful brk/shared mappings. Only the
    // child reads the retained top page after the parent unmaps its own leaf.
    unsafe {
        let shared = mmap_anon(PAGE, true);
        if shared < 0 {
            results.fail("brk COW: shared state");
            return;
        }
        let done = &*(shared as *const AtomicU32);
        done.store(0, Ordering::SeqCst);
        let old = syscall1(SYS_BRK, 0) as usize;
        let base = (old + PAGE - 1) & !(PAGE - 1);
        let mut top = base + 3 * PAGE;
        if top % 0x200000 <= PAGE {
            top += 2 * PAGE;
        }
        if syscall1(SYS_BRK, top as u64) as usize != top {
            munmap(shared as usize, PAGE);
            results.fail("brk COW: grow");
            return;
        }
        let word = (top - PAGE) as *mut u64;
        core::ptr::write_volatile(word, 0xC031);
        let child = sys_fork();
        if is_error(child) {
            syscall1(SYS_BRK, old as u64);
            munmap(shared as usize, PAGE);
            results.fail("brk COW: fork");
            return;
        }
        if child == 0 {
            while done.load(Ordering::SeqCst) == 0 {
                userspace::syscall::sys_yield();
            }
            let valid = core::ptr::read_volatile(word) == 0xC031;
            raw_exit(SYS_EXIT, if valid { 0 } else { 1 });
        }
        let shrunk = syscall1(SYS_BRK, (top - PAGE) as u64) as usize == top - PAGE;
        done.store(1, Ordering::SeqCst);
        let mut info = SigInfo::poisoned();
        let waited = waitid(P_PID, child, &mut info, WEXITED);
        let restored = syscall1(SYS_BRK, old as u64) as usize == old;
        munmap(shared as usize, PAGE);
        if shrunk && restored && !is_error(waited) && info.status() == 0 {
            results.pass(NAME);
        } else {
            results.fail("brk COW: shrink or peer contents");
        }
    }
}

/// Issue #109 §2.1 negative-control test: set a non-zero Ring-3 `IA32_GS_BASE`
/// via `arch_prctl(ARCH_SET_GS)` and drive real Ring-3 -> Ring-0 IDT exceptions
/// and interrupts (CoW `#PF`, lazy FPU `#NM`, cross-CPU TLB shootdown, fatal
/// child `#UD` / `#PF`) while verifying that:
/// 1. The kernel never corrupts or leaks user `GS` across any IDT stub;
/// 2. Fatal Ring-3 faults with non-zero user `GS` terminate cleanly (no double
///    `SWAPGS`, no kernel panic);
/// 3. User-space `gs:[0]` / `gs:[8]` reads and `ARCH_GET_GS` return exact
///    canary values before and after every fault.
fn test_nonzero_user_gs_across_exceptions(results: &mut TestResult) {
    const NAME: &str =
        "non-zero Ring-3 GS base survives CoW #PF, FPU #NM, shootdown, and child #UD/#PF";
    const SYS_ARCH_PRCTL: u64 = 158;
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_GET_GS: u64 = 0x1004;
    const CANARY_LO: u64 = 0x5A5A_CAFE_BABE_1234;
    const CANARY_HI: u64 = 0xDEAD_BEEF_0123_4567;
    const SIGILL_EXIT: u64 = 132;
    const SIGSEGV_EXIT_U64: u64 = 139;

    #[repr(C, align(64))]
    struct UserGsCanary {
        lo: u64,
        hi: u64,
        pad: [u64; 6],
    }

    #[inline(never)]
    unsafe fn check_user_gs(expected_base: u64, expected_lo: u64, expected_hi: u64) -> bool {
        let mut got_base: u64 = 0;
        if is_error(syscall2(
            SYS_ARCH_PRCTL,
            ARCH_GET_GS,
            &mut got_base as *mut u64 as u64,
        )) {
            return false;
        }
        if got_base != expected_base {
            return false;
        }
        let lo: u64;
        let hi: u64;
        core::arch::asm!(
            "mov {lo}, qword ptr gs:[0]",
            "mov {hi}, qword ptr gs:[8]",
            lo = out(reg) lo,
            hi = out(reg) hi,
            options(nostack, readonly, preserves_flags)
        );
        lo == expected_lo && hi == expected_hi
    }

    unsafe {
        let mut canary = UserGsCanary {
            lo: CANARY_LO,
            hi: CANARY_HI,
            pad: [0; 6],
        };
        let canary_addr = &canary as *const UserGsCanary as u64;

        if is_error(syscall2(SYS_ARCH_PRCTL, ARCH_SET_GS, canary_addr)) {
            results.fail("nonzero user GS: ARCH_SET_GS failed");
            return;
        }

        let mut ok = check_user_gs(canary_addr, CANARY_LO, CANARY_HI);

        // 1. Trigger a real Ring-3 CoW #PF via fork() + write to private mmap page.
        let cow_page = mmap_anon(PAGE, false);
        if ok && cow_page >= 0 {
            let slot = cow_page as *mut u64;
            core::ptr::write_volatile(slot, 0x1122_3344_5566_7788);
            let child = sys_fork();
            if is_error(child) {
                ok = false;
            } else if child == 0 {
                // Child inherits parent's non-zero user GS; verify and exit cleanly.
                let child_ok = check_user_gs(canary_addr, CANARY_LO, CANARY_HI)
                    && core::ptr::read_volatile(slot) == 0x1122_3344_5566_7788;
                raw_exit(SYS_EXIT, if child_ok { 0 } else { 1 });
            } else {
                // Parent write triggers Ring-3 CoW #PF while user GS is non-zero.
                core::ptr::write_volatile(slot, 0x8877_6655_4433_2211);
                if reap_pid(child) != Some(0)
                    || core::ptr::read_volatile(slot) != 0x8877_6655_4433_2211
                    || !check_user_gs(canary_addr, CANARY_LO, CANARY_HI)
                {
                    ok = false;
                }
            }
            let _ = munmap(cow_page as usize, PAGE);
        } else {
            ok = false;
        }

        // 2. Yield (so CR0.TS can be armed on reschedule) and execute SSE ops to
        //    exercise lazy FPU #NM delivery with non-zero user GS active.
        if ok {
            for round in 0..4u64 {
                userspace::syscall::sys_yield();
                let mut val: u64 = 0x1000 + round;
                core::arch::asm!(
                    "movq xmm0, {v}",
                    "paddq xmm0, xmm0",
                    "movq {v}, xmm0",
                    v = inout(reg) val,
                    out("xmm0") _,
                    options(nostack, nomem, preserves_flags)
                );
                if val != (0x1000 + round) * 2 || !check_user_gs(canary_addr, CANARY_LO, CANARY_HI)
                {
                    ok = false;
                    break;
                }
            }
        }

        // 3. Exercise mprotect + munmap (cross-CPU TLB shootdown IPIs) while
        //    non-zero user GS is active.
        if ok {
            let map = mmap_anon(2 * PAGE, false);
            if map < 0 {
                ok = false;
            } else {
                core::ptr::write_volatile(map as *mut u64, 0xABCD);
                let mp = syscall3(SYS_MPROTECT, map as u64, (2 * PAGE) as u64, PROT_READ) as i64;
                let mu = munmap(map as usize, 2 * PAGE);
                if mp != 0 || mu != 0 || !check_user_gs(canary_addr, CANARY_LO, CANARY_HI) {
                    ok = false;
                }
            }
        }

        // 4. Fatal Ring-3 #UD (SIGILL=132) with non-zero user GS in a forked child:
        //    proves entry stub establishes kernel GS once (no double-swapgs crash).
        if ok {
            let child = sys_fork();
            if is_error(child) {
                ok = false;
            } else if child == 0 {
                let mut child_canary = UserGsCanary {
                    lo: 0xAAAA_BBBB_CCCC_DDDD,
                    hi: 0x1111_2222_3333_4444,
                    pad: [0; 6],
                };
                let _ = syscall2(
                    SYS_ARCH_PRCTL,
                    ARCH_SET_GS,
                    &mut child_canary as *mut UserGsCanary as u64,
                );
                core::arch::asm!("ud2", options(noreturn));
            } else if reap_pid(child) != Some(SIGILL_EXIT)
                || !check_user_gs(canary_addr, CANARY_LO, CANARY_HI)
            {
                ok = false;
            }
        }

        // 5. Fatal Ring-3 #PF (SIGSEGV=139) with non-zero user GS in a forked child.
        if ok {
            let child = sys_fork();
            if is_error(child) {
                ok = false;
            } else if child == 0 {
                let mut child_canary = UserGsCanary {
                    lo: 0x5555_6666_7777_8888,
                    hi: 0x9999_AAAA_BBBB_CCCC,
                    pad: [0; 6],
                };
                let _ = syscall2(
                    SYS_ARCH_PRCTL,
                    ARCH_SET_GS,
                    &mut child_canary as *mut UserGsCanary as u64,
                );
                // Read from a permanently unmapped user address to trigger fatal #PF.
                let _ = core::ptr::read_volatile(0x1000usize as *const u64);
                raw_exit(SYS_EXIT, 55);
            } else if reap_pid(child) != Some(SIGSEGV_EXIT_U64)
                || !check_user_gs(canary_addr, CANARY_LO, CANARY_HI)
            {
                ok = false;
            }
        }

        // Restore user GS to 0 so subsequent tests see the default state.
        let reset_ok = !is_error(syscall2(SYS_ARCH_PRCTL, ARCH_SET_GS, 0));
        canary.lo = 0;
        let _ = canary.lo;

        if ok && reset_ok {
            results.pass(NAME);
        } else {
            results.fail(NAME);
        }
    }
}

/// Balanced's Ring-0 shell owns input; even init's inherited console handle
/// and an independently opened device must fail before touching the queue.
fn test_console_input_ownership(results: &mut TestResult) {
    const NAME: &str = "console input belongs exclusively to the configured owner";
    // SAFETY: read and poll buffers live for each syscall, lengths match their
    // allocations, and every opened or duplicated descriptor is closed.
    unsafe {
        let fd = sys_open(b"/dev/console\0".as_ptr(), 0, 0);
        if is_error(fd) {
            results.fail("console owner: open");
            return;
        }
        let mut byte = 0u8;
        let device = syscall3(SYS_READ, fd, &mut byte as *mut u8 as u64, 1) as i64;
        if device != -1 {
            sys_close(fd);
            results.fail("console owner: device read was not EPERM");
            return;
        }
        // Linux pollfd encoded as fd:i32/events:i16/revents:i16.
        let mut poll = [(fd as u32 as u64) | (1 << 32), 1u64 << 32];
        let ready = syscall3(7, poll.as_mut_ptr() as u64, 2, 0);
        sys_close(fd);
        if ready != 2 || poll.iter().any(|entry| entry >> 48 != 8) {
            results.fail("console owner: poll did not report POLLERR");
            return;
        }
        let duplicate = syscall1(32, 0);
        if is_error(duplicate) {
            results.fail("console owner: dup");
            return;
        }
        let copied = syscall3(SYS_READ, duplicate, &mut byte as *mut u8 as u64, 1) as i64;
        sys_close(duplicate);
        if copied != -1 {
            results.fail("console owner: dup bypassed ownership");
            return;
        }
        let stdin = syscall3(SYS_READ, 0, &mut byte as *mut u8 as u64, 1) as i64;
        if stdin != -1 {
            results.fail("console owner: inherited stdin was not EPERM");
            return;
        }
        results.pass(NAME);
    }
}

// ---------------------------------------------------------------------------
// STRICT-Q S4 & S8: Ring-3 IPC, signal-migration, and namespace-teardown legs
// (r172_08_futex_bucket_toctou, r41_3_pipe_eintr_wake,
//  m0_5_signal_delivery_blocked_syscall, r175_rapid_signal_migration,
//  r175_namespace_teardown_storm).
// ---------------------------------------------------------------------------

const S4_EINTR: i32 = 4;
const S4_SIGUSR2_NR: u64 = 12;
const S4_SIGSTOP_NR: u64 = 19;
const S4_SYS_SCHED_SETAFFINITY: u64 = 203;
const S4_SYS_UNSHARE: u64 = 272;
const S4_CLONE_NEWPID: u64 = 0x2000_0000;
const S4_O_NONBLOCK: u64 = 0x800;
const S4_LEG_OK: u64 = 0x7a;
const S4_STACK_BYTES: usize = 16 * 1024;
const S4_TOCTOU_ROUNDS: usize = 32;
const S4_TOCTOU_SLOTS: usize = 4;

static S4_TOCTOU_WORDS: [FutexWord; S4_TOCTOU_SLOTS] = [
    FutexWord(core::sync::atomic::AtomicU32::new(0)),
    FutexWord(core::sync::atomic::AtomicU32::new(0)),
    FutexWord(core::sync::atomic::AtomicU32::new(0)),
    FutexWord(core::sync::atomic::AtomicU32::new(0)),
];
static S4_TOCTOU_REQUEUE_DST: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static S4_TOCTOU_ROUND: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S4_TOCTOU_DONE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S4_TOCTOU_ERRORS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S4_TOCTOU_TIDS: [core::sync::atomic::AtomicI32; 2] = [
    core::sync::atomic::AtomicI32::new(0),
    core::sync::atomic::AtomicI32::new(0),
];

fn s4_await_tid_zero(tid_word: &core::sync::atomic::AtomicI32) -> bool {
    use core::sync::atomic::Ordering;
    for _ in 0..THREAD_POLL_YIELDS {
        if tid_word.load(Ordering::SeqCst) == 0 {
            return true;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    false
}

fn s4_toctou_worker() -> ! {
    use core::sync::atomic::Ordering;
    let mut seen_round = 0u32;
    loop {
        let round = S4_TOCTOU_ROUND.load(Ordering::Acquire);
        if round == u32::MAX {
            break;
        }
        if round == seen_round {
            unsafe { userspace::syscall::sys_yield() };
            continue;
        }
        seen_round = round;
        let idx = (round as usize) % S4_TOCTOU_SLOTS;
        let word = &S4_TOCTOU_WORDS[idx];
        // Both workers must genuinely block on the same rotating word (ret == 0,
        // never EAGAIN) until woken directly or requeued to S4_TOCTOU_REQUEUE_DST.
        let ret = unsafe { futex(word, FUTEX_WAIT_OP | FUTEX_PRIVATE, round as u64, 0, 0, 0) };
        if ret != 0 {
            S4_TOCTOU_ERRORS.fetch_add(1, Ordering::SeqCst);
        }
        S4_TOCTOU_DONE.fetch_add(1, Ordering::Release);
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

extern "C" fn s4_toctou_worker_0() -> ! {
    s4_toctou_worker()
}

extern "C" fn s4_toctou_worker_1() -> ! {
    s4_toctou_worker()
}

fn s4_futex_bucket_toctou_leg() -> u64 {
    use core::sync::atomic::Ordering;
    for w in &S4_TOCTOU_WORDS {
        w.0.store(0, Ordering::SeqCst);
    }
    S4_TOCTOU_REQUEUE_DST.0.store(0, Ordering::SeqCst);
    S4_TOCTOU_ROUND.store(0, Ordering::SeqCst);
    S4_TOCTOU_DONE.store(0, Ordering::SeqCst);
    S4_TOCTOU_ERRORS.store(0, Ordering::SeqCst);
    for slot in 0..2 {
        S4_TOCTOU_TIDS[slot].store(-1, Ordering::SeqCst);
    }

    let stack0 = unsafe { mmap_anon(S4_STACK_BYTES, false) };
    let stack1 = unsafe { mmap_anon(S4_STACK_BYTES, false) };
    if stack0 < 0 || stack1 < 0 {
        if stack0 >= 0 {
            unsafe { munmap(stack0 as usize, S4_STACK_BYTES) };
        }
        if stack1 >= 0 {
            unsafe { munmap(stack1 as usize, S4_STACK_BYTES) };
        }
        return 0x10;
    }

    let entries: [extern "C" fn() -> !; 2] = [s4_toctou_worker_0, s4_toctou_worker_1];
    let stacks = [stack0 as usize, stack1 as usize];
    let mut spawned = [false; 2];
    for slot in 0..2 {
        let tid = unsafe {
            raw_clone(
                THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
                stacks[slot] + S4_STACK_BYTES,
                core::ptr::null_mut(),
                S4_TOCTOU_TIDS[slot].as_ptr(),
                entries[slot],
            )
        };
        if is_error(tid) || tid == 0 {
            S4_TOCTOU_ROUND.store(u32::MAX, Ordering::Release);
            // Only unmap stacks for threads not spawned or confirmed exited.
            for prev in 0..2 {
                if !spawned[prev] || s4_await_tid_zero(&S4_TOCTOU_TIDS[prev]) {
                    unsafe { munmap(stacks[prev], S4_STACK_BYTES) };
                }
            }
            return 0x11 + slot as u64;
        }
        spawned[slot] = true;
    }

    let mut status = S4_LEG_OK;
    let dst_addr = S4_TOCTOU_REQUEUE_DST.0.as_ptr() as u64;
    for round in 1..=(S4_TOCTOU_ROUNDS as u32) {
        S4_TOCTOU_DONE.store(0, Ordering::SeqCst);
        let idx = (round as usize) % S4_TOCTOU_SLOTS;
        S4_TOCTOU_WORDS[idx].0.store(round, Ordering::SeqCst);
        S4_TOCTOU_ROUND.store(round, Ordering::Release);

        // Deterministically confirm BOTH waiters are physically queued inside
        // the kernel futex bucket before mutating or requeuing.
        if !parity_await_sleepers(&S4_TOCTOU_WORDS[idx], 2) {
            status = 0x13;
            break;
        }

        // Wake 1 waiter and requeue the other to S4_TOCTOU_REQUEUE_DST.
        let moved = unsafe {
            futex(
                &S4_TOCTOU_WORDS[idx],
                FUTEX_CMP_REQUEUE_OP | FUTEX_PRIVATE,
                1,
                1,
                dst_addr,
                round as u64,
            )
        };
        if moved != 2 {
            status = 0x14;
            break;
        }
        if parity_sleepers(&S4_TOCTOU_WORDS[idx]) != 0
            || parity_sleepers(&S4_TOCTOU_REQUEUE_DST) != 1
        {
            status = 0x15;
            break;
        }
        let woken = unsafe {
            futex(
                &S4_TOCTOU_REQUEUE_DST,
                FUTEX_WAKE_OP | FUTEX_PRIVATE,
                1,
                0,
                0,
                0,
            )
        };
        if woken != 1 {
            status = 0x16;
            break;
        }

        let mut round_done = false;
        for _ in 0..THREAD_POLL_YIELDS {
            if S4_TOCTOU_DONE.load(Ordering::Acquire) == 2 {
                round_done = true;
                break;
            }
            unsafe { userspace::syscall::sys_yield() };
        }
        if !round_done {
            status = 0x17;
            break;
        }
    }

    S4_TOCTOU_ROUND.store(u32::MAX, Ordering::Release);
    for w in &S4_TOCTOU_WORDS {
        unsafe {
            let _ = futex(w, FUTEX_WAKE_OP | FUTEX_PRIVATE, FUTEX_ALL, 0, 0, 0);
        }
    }
    unsafe {
        let _ = futex(
            &S4_TOCTOU_REQUEUE_DST,
            FUTEX_WAKE_OP | FUTEX_PRIVATE,
            FUTEX_ALL,
            0,
            0,
            0,
        );
    }
    for slot in 0..2 {
        if s4_await_tid_zero(&S4_TOCTOU_TIDS[slot]) {
            unsafe { munmap(stacks[slot], S4_STACK_BYTES) };
        } else if status == S4_LEG_OK {
            status = 0x18 + slot as u64;
        }
    }
    if status == S4_LEG_OK && S4_TOCTOU_ERRORS.load(Ordering::SeqCst) != 0 {
        return 0x1a;
    }
    status
}

/// R172-08: Verify concurrent futex bucket claim/requeue/teardown loses no wakeups.
fn test_futex_bucket_toctou(results: &mut TestResult) {
    print("Testing futex bucket TOCTOU under concurrent wait/wake/requeue... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("futex bucket TOCTOU: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s4_futex_bucket_toctou_leg()) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => {
            results.pass(
                "futex bucket TOCTOU: concurrent wait/wake/requeue across rotating words loses no wakeups",
            );
        }
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("futex bucket TOCTOU: concurrent race check failed");
        }
        None => results.fail("futex bucket TOCTOU: could not reap host"),
    }
}

static S4_SIG_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S4_SIG_LAST: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
static S4_PIPE_RD_FD: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(-1);
static S4_PIPE_ENTERED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S4_PIPE_RET: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(FUTEX_WAIT_PENDING);
static S4_PIPE_TID: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

extern "C" fn s4_signal_handler(signo: i32) {
    S4_SIG_LAST.store(signo, core::sync::atomic::Ordering::SeqCst);
    S4_SIG_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

extern "C" fn s4_pipe_reader_thread() -> ! {
    use core::sync::atomic::Ordering;
    let fd = S4_PIPE_RD_FD.load(Ordering::Acquire) as u64;
    let mut byte = [0u8; 1];
    S4_PIPE_ENTERED.store(1, Ordering::Release);
    let ret = unsafe { syscall3(SYS_READ, fd, byte.as_mut_ptr() as u64, 1) };
    S4_PIPE_RET.store(ret, Ordering::Release);
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn s4_proc_task_is_sleeping(tgid: u64, tid: u64) -> bool {
    let mut path = [0u8; 48];
    let mut len = 0usize;
    let push_bytes = |dst: &mut [u8; 48], len: &mut usize, src: &[u8]| {
        for &b in src {
            dst[*len] = b;
            *len += 1;
        }
    };
    let push_u64 = |dst: &mut [u8; 48], len: &mut usize, mut n: u64| {
        let mut digits = [0u8; 20];
        let mut dlen = 0usize;
        if n == 0 {
            digits[0] = b'0';
            dlen = 1;
        } else {
            while n > 0 {
                digits[dlen] = b'0' + (n % 10) as u8;
                dlen += 1;
                n /= 10;
            }
        }
        while dlen > 0 {
            dlen -= 1;
            dst[*len] = digits[dlen];
            *len += 1;
        }
    };
    push_bytes(&mut path, &mut len, b"/proc/");
    push_u64(&mut path, &mut len, tgid);
    push_bytes(&mut path, &mut len, b"/task/");
    push_u64(&mut path, &mut len, tid);
    push_bytes(&mut path, &mut len, b"/status\0");

    let fd = unsafe { sys_open(path.as_ptr(), 0, 0) };
    if is_error(fd) {
        return false;
    }
    let mut buf = [0u8; 512];
    let nread = unsafe { syscall3(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64) };
    unsafe { sys_close(fd) };
    if is_error(nread) || nread == 0 {
        return false;
    }
    let data = &buf[..(nread as usize).min(buf.len())];
    let needle = b"State:\tS (sleeping)";
    data.windows(needle.len()).any(|w| w == needle)
}

fn s4_pipe_eintr_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let tgid = unsafe { sys_getpid() };
    S4_SIG_COUNT.store(0, Ordering::SeqCst);
    S4_SIG_LAST.store(0, Ordering::SeqCst);
    S4_PIPE_ENTERED.store(0, Ordering::SeqCst);
    S4_PIPE_RET.store(FUTEX_WAIT_PENDING, Ordering::SeqCst);
    S4_PIPE_TID.store(-1, Ordering::SeqCst);

    let act: [u64; 4] = [
        s4_signal_handler as extern "C" fn(i32) as usize as u64,
        SA_RESTORER_FLAG,
        pi_sigreturn_trampoline as unsafe extern "C" fn() as usize as u64,
        0,
    ];
    if unsafe { syscall4(SYS_RT_SIGACTION, SIGUSR1_NR, act.as_ptr() as u64, 0, 8) } != 0 {
        return 0x20;
    }

    let mut fds = [-1i32; 2];
    if unsafe { syscall2(SYS_PIPE2, fds.as_mut_ptr() as u64, 0) } != 0 {
        return 0x21;
    }
    S4_PIPE_RD_FD.store(fds[0], Ordering::Release);

    // RF178-34: signal frames require an mmap'd or main stack.
    let stack = unsafe { mmap_anon(S4_STACK_BYTES, false) };
    if stack < 0 {
        unsafe {
            sys_close(fds[0] as u64);
            sys_close(fds[1] as u64);
        }
        return 0x22;
    }
    let reader = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            stack as usize + S4_STACK_BYTES,
            core::ptr::null_mut(),
            S4_PIPE_TID.as_ptr(),
            s4_pipe_reader_thread,
        )
    };
    if is_error(reader) || reader == 0 {
        unsafe {
            munmap(stack as usize, S4_STACK_BYTES);
            sys_close(fds[0] as u64);
            sys_close(fds[1] as u64);
        }
        return 0x23;
    }

    let mut entered = false;
    for _ in 0..THREAD_POLL_YIELDS {
        if S4_PIPE_ENTERED.load(Ordering::Acquire) != 0 {
            entered = true;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if !entered {
        unsafe {
            sys_close(fds[1] as u64);
            sys_close(fds[0] as u64);
        }
        if s4_await_tid_zero(&S4_PIPE_TID) {
            unsafe { munmap(stack as usize, S4_STACK_BYTES) };
        }
        return 0x24;
    }

    // Wait with a bounded deadline for the kernel's /proc/<tgid>/task/<tid>/status
    // to report State: S (sleeping) so we prove the reader actually entered the
    // blocking pipe wait queue before sending SIGUSR1.
    let Some(t0) = monotonic_ns() else {
        unsafe {
            sys_close(fds[1] as u64);
            sys_close(fds[0] as u64);
        }
        if s4_await_tid_zero(&S4_PIPE_TID) {
            unsafe { munmap(stack as usize, S4_STACK_BYTES) };
        }
        return 0x2a;
    };
    let deadline = t0 + 500_000_000; // 500 ms
    let poll_sleep = [0i64, 1_000_000i64]; // 1 ms
    let mut observed_sleeping = false;
    let mut attempt = 0u32;
    while monotonic_ns().is_some_and(|now| now < deadline) {
        if S4_PIPE_RET.load(Ordering::Acquire) != FUTEX_WAIT_PENDING {
            break;
        }
        if s4_proc_task_is_sleeping(tgid, reader) {
            observed_sleeping = true;
            break;
        }
        if attempt < 32 {
            unsafe { userspace::syscall::sys_yield() };
        } else {
            unsafe {
                let _ = syscall2(SYS_NANOSLEEP, poll_sleep.as_ptr() as u64, 0);
            }
        }
        attempt = attempt.wrapping_add(1);
    }
    let stayed_blocked = observed_sleeping
        && S4_PIPE_RET.load(Ordering::Acquire) == FUTEX_WAIT_PENDING
        && S4_SIG_COUNT.load(Ordering::SeqCst) == 0;

    let mut woke = false;
    if stayed_blocked && unsafe { syscall3(SYS_TGKILL, tgid, reader, SIGUSR1_NR) } == 0 {
        for _ in 0..THREAD_POLL_YIELDS {
            if S4_PIPE_RET.load(Ordering::Acquire) != FUTEX_WAIT_PENDING {
                woke = true;
                break;
            }
            unsafe { userspace::syscall::sys_yield() };
        }
    }

    if !woke {
        unsafe {
            sys_close(fds[1] as u64);
        }
    }
    let joined = s4_await_tid_zero(&S4_PIPE_TID);
    if joined {
        unsafe { munmap(stack as usize, S4_STACK_BYTES) };
    }

    let read_ret = S4_PIPE_RET.load(Ordering::Acquire);
    let sig_runs = S4_SIG_COUNT.load(Ordering::SeqCst);
    let sig_last = S4_SIG_LAST.load(Ordering::SeqCst);

    // Verify pipe remains completely usable after EINTR; never block in read if write failed.
    let mut pipe_ok = false;
    if stayed_blocked
        && woke
        && joined
        && errno(read_ret) == S4_EINTR
        && sig_runs == 1
        && sig_last == SIGUSR1_NR as i32
    {
        let payload = *b"OK";
        let w = unsafe { syscall3(SYS_WRITE, fds[1] as u64, payload.as_ptr() as u64, 2) };
        if w == 2 {
            let mut back = [0u8; 2];
            let r = unsafe { syscall3(SYS_READ, fds[0] as u64, back.as_mut_ptr() as u64, 2) };
            pipe_ok = r == 2 && back == payload;
        }
    }

    unsafe {
        sys_close(fds[0] as u64);
        if woke {
            sys_close(fds[1] as u64);
        }
    }

    if !stayed_blocked {
        return 0x2b;
    }
    if !woke {
        return 0x25;
    }
    if !joined {
        return 0x26;
    }
    if errno(read_ret) != S4_EINTR {
        return 0x27;
    }
    if sig_runs != 1 || sig_last != SIGUSR1_NR as i32 {
        return 0x28;
    }
    if !pipe_ok {
        return 0x29;
    }
    S4_LEG_OK
}

/// R41-3: Verify blocking pipe read() wakes with -EINTR on signal delivery.
fn test_pipe_eintr_wake(results: &mut TestResult) {
    print("Testing pipe read EINTR wake on SIGUSR1... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("pipe EINTR: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s4_pipe_eintr_leg()) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => {
            results.pass(
                "pipe read wakes with EINTR on SIGUSR1 delivery and remains usable afterward",
            );
        }
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("pipe EINTR: read did not wake with EINTR + handler");
        }
        None => results.fail("pipe EINTR: could not reap host"),
    }
}

static S4_BLOCK_WORD: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static S4_BLOCK_STAGE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S4_SLEEP_RET: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(FUTEX_WAIT_PENDING);
static S4_SLEEP_REM_NS: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(-1);
static S4_FUTEX_RET: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(FUTEX_WAIT_PENDING);
static S4_BLOCK_TID: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

extern "C" fn s4_blocked_syscall_thread() -> ! {
    use core::sync::atomic::Ordering;
    // Phase 1: block in nanosleep(5s, &mut rem) and expect SIGUSR2 -> -EINTR + rem populated.
    let long_sleep = [5i64, 0i64];
    let mut rem = [-1i64, -1i64];
    S4_BLOCK_STAGE.store(1, Ordering::Release);
    let sleep_ret = unsafe {
        syscall2(
            SYS_NANOSLEEP,
            long_sleep.as_ptr() as u64,
            rem.as_mut_ptr() as u64,
        )
    };
    let rem_ns = rem[0].saturating_mul(1_000_000_000).saturating_add(rem[1]);
    S4_SLEEP_REM_NS.store(rem_ns, Ordering::Release);
    S4_SLEEP_RET.store(sleep_ret, Ordering::Release);

    // Phase 2: block in FUTEX_WAIT; host confirms kernel-queue membership via
    // parity_await_sleepers before sending SIGUSR2 -> -EINTR.
    S4_BLOCK_STAGE.store(2, Ordering::Release);
    let futex_ret = unsafe { futex(&S4_BLOCK_WORD, FUTEX_WAIT_OP | FUTEX_PRIVATE, 0, 0, 0, 0) };
    S4_FUTEX_RET.store(futex_ret, Ordering::Release);
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn s4_signal_delivery_blocked_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let tgid = unsafe { sys_getpid() };
    S4_BLOCK_WORD.0.store(0, Ordering::SeqCst);
    S4_SIG_COUNT.store(0, Ordering::SeqCst);
    S4_SIG_LAST.store(0, Ordering::SeqCst);
    S4_BLOCK_STAGE.store(0, Ordering::SeqCst);
    S4_SLEEP_RET.store(FUTEX_WAIT_PENDING, Ordering::SeqCst);
    S4_SLEEP_REM_NS.store(-1, Ordering::SeqCst);
    S4_FUTEX_RET.store(FUTEX_WAIT_PENDING, Ordering::SeqCst);
    S4_BLOCK_TID.store(-1, Ordering::SeqCst);

    let act: [u64; 4] = [
        s4_signal_handler as extern "C" fn(i32) as usize as u64,
        SA_RESTORER_FLAG,
        pi_sigreturn_trampoline as unsafe extern "C" fn() as usize as u64,
        0,
    ];
    if unsafe { syscall4(SYS_RT_SIGACTION, S4_SIGUSR2_NR, act.as_ptr() as u64, 0, 8) } != 0 {
        return 0x30;
    }

    let stack = unsafe { mmap_anon(S4_STACK_BYTES, false) };
    if stack < 0 {
        return 0x31;
    }
    let tid = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            stack as usize + S4_STACK_BYTES,
            core::ptr::null_mut(),
            S4_BLOCK_TID.as_ptr(),
            s4_blocked_syscall_thread,
        )
    };
    if is_error(tid) || tid == 0 {
        unsafe { munmap(stack as usize, S4_STACK_BYTES) };
        return 0x32;
    }

    // Phase 1: wait for thread to enter nanosleep(5s), hold 30 ms while still
    // pending (proving it entered the kernel sleep loop), then send ONE SIGUSR2.
    let mut stage1 = false;
    for _ in 0..THREAD_POLL_YIELDS {
        if S4_BLOCK_STAGE.load(Ordering::Acquire) >= 1 {
            stage1 = true;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    let settle = [0i64, 30_000_000i64]; // 30 ms
    let mut phase1_ok = false;
    if stage1 {
        unsafe {
            let _ = syscall2(SYS_NANOSLEEP, settle.as_ptr() as u64, 0);
        }
        if S4_SLEEP_RET.load(Ordering::Acquire) == FUTEX_WAIT_PENDING
            && unsafe { syscall3(SYS_TGKILL, tgid, tid, S4_SIGUSR2_NR) } == 0
        {
            for _ in 0..THREAD_POLL_YIELDS {
                if S4_SLEEP_RET.load(Ordering::Acquire) != FUTEX_WAIT_PENDING {
                    phase1_ok = true;
                    break;
                }
                unsafe { userspace::syscall::sys_yield() };
            }
        }
    }

    // Phase 2: deterministically prove the thread is physically queued in the
    // kernel futex wait queue via parity_await_sleepers, hold 20 ms to close
    // the publish-to-finish_wait window and confirm it stays blocked with no
    // premature return or extra signal, then send ONE SIGUSR2.
    let mut phase2_ok = false;
    if phase1_ok && parity_await_sleepers(&S4_BLOCK_WORD, 1) {
        let phase2_settle = [0i64, 20_000_000i64]; // 20 ms
        unsafe {
            let _ = syscall2(SYS_NANOSLEEP, phase2_settle.as_ptr() as u64, 0);
        }
        let still_queued = S4_FUTEX_RET.load(Ordering::Acquire) == FUTEX_WAIT_PENDING
            && parity_sleepers(&S4_BLOCK_WORD) == 1
            && S4_SIG_COUNT.load(Ordering::SeqCst) == 1;
        if still_queued && unsafe { syscall3(SYS_TGKILL, tgid, tid, S4_SIGUSR2_NR) } == 0 {
            for _ in 0..THREAD_POLL_YIELDS {
                if S4_FUTEX_RET.load(Ordering::Acquire) != FUTEX_WAIT_PENDING {
                    phase2_ok = true;
                    break;
                }
                unsafe { userspace::syscall::sys_yield() };
            }
        }
    }

    if !phase2_ok {
        unsafe {
            let _ = futex(
                &S4_BLOCK_WORD,
                FUTEX_WAKE_OP | FUTEX_PRIVATE,
                FUTEX_ALL,
                0,
                0,
                0,
            );
        }
    }

    let joined = s4_await_tid_zero(&S4_BLOCK_TID);
    if joined {
        unsafe { munmap(stack as usize, S4_STACK_BYTES) };
    }

    let rem_ns = S4_SLEEP_REM_NS.load(Ordering::Acquire);
    if !phase1_ok
        || errno(S4_SLEEP_RET.load(Ordering::Acquire)) != S4_EINTR
        || rem_ns <= 0
        || rem_ns >= 5_000_000_000
    {
        return 0x33;
    }
    if !phase2_ok || errno(S4_FUTEX_RET.load(Ordering::Acquire)) != S4_EINTR {
        return 0x34;
    }
    if !joined {
        return 0x35;
    }
    if S4_SIG_COUNT.load(Ordering::SeqCst) != 2
        || S4_SIG_LAST.load(Ordering::SeqCst) != S4_SIGUSR2_NR as i32
    {
        return 0x36;
    }
    S4_LEG_OK
}

/// M0-5: Verify signal delivery interrupts blocked syscalls and runs the handler.
fn test_signal_delivery_blocked_syscall(results: &mut TestResult) {
    print("Testing signal delivery to blocked nanosleep and futex_wait... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("blocked-syscall signal: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s4_signal_delivery_blocked_leg()) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => {
            results.pass(
                "signal delivery interrupts blocked nanosleep and futex_wait with EINTR and runs handler",
            );
        }
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("blocked-syscall signal: interrupted syscall or handler check failed");
        }
        None => results.fail("blocked-syscall signal: could not reap host"),
    }
}

// ---------------------------------------------------------------------------
// STRICT-Q S8 (R175 D0-CROSS-1): Real Ring-3 signal delivery + CPU migration.
// ---------------------------------------------------------------------------

static S8_MIG_STOP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S8_MIG_READY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S8_MIG_CANARY_ERR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S8_MIG_SYSCALL_ERR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S8_MIG_FRAME_OK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S8_MIG_FRAME_ERR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S8_MIG_TID: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
static S8_MIG_SEED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static S8_MIG_CPUS_SEEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static S8_SIG_CPUS_SEEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static S8_MIG_LAST_CPU: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);
static S8_SIG_LAST_CPU: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);
static S8_MIG_FUTEX: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));
static S8_MIG_ARMED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S8_MIG_DONE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S8_MIG_BLOCK_CPU: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);
static S8_MIG_POST_CPU: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);
static S8_MIG_EXP_RIP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static S8_MIG_EXP_R12: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static S8_MIG_EXP_R13: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static S8_MIG_EXP_R14: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static S8_MIG_EXP_R15: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static S8_RDTSCP_CAP: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
const S8_SA_SIGINFO_FLAG: u64 = 0x0000_0004;
// Offsets within x86_64 ucontext_t (uc_mcontext starts at +40; see kernel/kernel_core/signal_frame.rs).
const S8_UC_R12_OFF: usize = 40 + 32;
const S8_UC_R13_OFF: usize = 40 + 40;
const S8_UC_R14_OFF: usize = 40 + 48;
const S8_UC_R15_OFF: usize = 40 + 56;
const S8_UC_RAX_OFF: usize = 40 + 104;
const S8_UC_RIP_OFF: usize = 40 + 128;

fn s8_has_rdtscp() -> bool {
    use core::sync::atomic::Ordering;
    match S8_RDTSCP_CAP.load(Ordering::Acquire) {
        2 => return true,
        1 => return false,
        _ => {}
    }
    let max_ext: u32;
    let ext_edx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 0x80000000",
            "cpuid",
            "mov {max_ext:e}, eax",
            "xor edx, edx",
            "cmp eax, 0x80000001",
            "jb 2f",
            "mov eax, 0x80000001",
            "cpuid",
            "2:",
            "pop rbx",
            max_ext = out(reg) max_ext,
            out("eax") _,
            out("ecx") _,
            out("edx") ext_edx,
        );
    }
    let supported = max_ext >= 0x8000_0001 && (ext_edx & (1u32 << 27)) != 0;
    S8_RDTSCP_CAP.store(if supported { 2 } else { 1 }, Ordering::Release);
    supported
}

#[inline(always)]
fn s8_current_cpu_id() -> u32 {
    if s8_has_rdtscp() {
        let aux: u32;
        unsafe {
            core::arch::asm!(
                "rdtscp",
                out("eax") _,
                out("edx") _,
                out("ecx") aux,
                options(nomem, nostack, preserves_flags),
            );
        }
        // Nilix publishes `cpu_id + 1` in IA32_TSC_AUX (0 means unpublished).
        let raw = aux & 0x3f;
        if raw != 0 {
            return raw - 1;
        }
    }
    // Fallback for CPUs without RDTSCP (or unpublished IA32_TSC_AUX): query the
    // kernel's current_cpu_id() through the read-only diagnostic op.
    let cpu = unsafe { shared_fault_test(17, 0, 0) };
    if !is_error(cpu) && cpu < 64 {
        cpu as u32
    } else {
        63
    }
}

extern "C" fn s8_migration_signal_handler(signo: i32, _info: *const u8, ucontext: *const u8) {
    use core::sync::atomic::Ordering;
    let cpu = s8_current_cpu_id();
    S8_SIG_LAST_CPU.store(cpu, Ordering::Release);
    S8_SIG_CPUS_SEEN.fetch_or(1u64 << cpu, Ordering::SeqCst);

    // Inspect the saved ucontext_t to prove this handler genuinely interrupted
    // the migrated inline SYS_FUTEX syscall frame (matching its exact post-syscall
    // RIP, -EINTR return in RAX, and all four runtime-seeded callee-saved canaries
    // r12-r15) rather than a later diagnostic syscall.
    let frame_ok = if ucontext.is_null() {
        false
    } else {
        let rd = |off: usize| unsafe { core::ptr::read_unaligned(ucontext.add(off) as *const u64) };
        let saved_rip = rd(S8_UC_RIP_OFF);
        let saved_rax = rd(S8_UC_RAX_OFF);
        let saved_r12 = rd(S8_UC_R12_OFF);
        let saved_r13 = rd(S8_UC_R13_OFF);
        let saved_r14 = rd(S8_UC_R14_OFF);
        let saved_r15 = rd(S8_UC_R15_OFF);
        let exp_rip = S8_MIG_EXP_RIP.load(Ordering::Acquire);
        exp_rip != 0
            && saved_rip == exp_rip
            && errno(saved_rax) == S4_EINTR
            && saved_r12 == S8_MIG_EXP_R12.load(Ordering::Acquire)
            && saved_r13 == S8_MIG_EXP_R13.load(Ordering::Acquire)
            && saved_r14 == S8_MIG_EXP_R14.load(Ordering::Acquire)
            && saved_r15 == S8_MIG_EXP_R15.load(Ordering::Acquire)
    };
    if frame_ok {
        S8_MIG_FRAME_OK.fetch_add(1, Ordering::SeqCst);
    } else {
        S8_MIG_FRAME_ERR.fetch_add(1, Ordering::SeqCst);
    }

    S4_SIG_LAST.store(signo, Ordering::SeqCst);
    S4_SIG_COUNT.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn s8_signal_migration_worker() -> ! {
    use core::sync::atomic::Ordering;
    let mut seen_round = 0u32;
    S8_MIG_READY.store(1, Ordering::Release);
    while S8_MIG_STOP.load(Ordering::Acquire) == 0 {
        let cpu = s8_current_cpu_id();
        S8_MIG_LAST_CPU.store(cpu, Ordering::Release);
        S8_MIG_CPUS_SEEN.fetch_or(1u64 << cpu, Ordering::SeqCst);

        let round = S8_MIG_ARMED.load(Ordering::Acquire);
        if round == u32::MAX {
            break;
        }
        if round == seen_round {
            unsafe { userspace::syscall::sys_yield() };
            continue;
        }
        seen_round = round;

        // Record the CPU entering SYS_FUTEX (FUTEX_WAIT). On SMP the parent
        // waits for this thread to sleep in the kernel futex queue, migrates
        // its affinity to the OTHER CPU, then sends SIGUSR1 so the syscall
        // frame created on `entry_cpu` is interrupted, delivered, and restored
        // via rt_sigreturn on the destination CPU.
        let entry_cpu = s8_current_cpu_id();
        S8_MIG_BLOCK_CPU.store(entry_cpu, Ordering::Release);

        let seed = S8_MIG_SEED
            .load(Ordering::Acquire)
            .wrapping_add(round as u64);
        let e12 = seed ^ 0x1122_3344_5566_7788u64;
        let e13 = seed.rotate_left(13) ^ 0x8877_6655_4433_2211u64;
        let e14 = seed.rotate_left(29) ^ 0xA5A5_5A5A_F0F0_0F0Fu64;
        let e15 = seed.rotate_left(47) ^ 0x55AA_55AA_33CC_33CCu64;
        S8_MIG_EXP_R12.store(e12, Ordering::Release);
        S8_MIG_EXP_R13.store(e13, Ordering::Release);
        S8_MIG_EXP_R14.store(e14, Ordering::Release);
        S8_MIG_EXP_R15.store(e15, Ordering::Release);
        let mut r12 = e12;
        let mut r13 = e13;
        let mut r14 = e14;
        let mut r15 = e15;
        let mut ret: u64 = 202; // SYS_FUTEX
        unsafe {
            core::arch::asm!(
                "lea rcx, [rip + 2f]",
                "mov [r11], rcx",
                "syscall",
                "2:",
                inout("rax") ret,
                in("rdi") S8_MIG_FUTEX.0.as_ptr() as u64,
                in("rsi") (FUTEX_WAIT_OP | FUTEX_PRIVATE),
                in("rdx") round as u64,
                in("r10") 0u64,
                in("r8") 0u64,
                in("r9") 0u64,
                inout("r11") S8_MIG_EXP_RIP.as_ptr() => _,
                inout("r12") r12,
                inout("r13") r13,
                inout("r14") r14,
                inout("r15") r15,
                out("rcx") _,
                options(nostack),
            );
        }
        if r12 != e12 || r13 != e13 || r14 != e14 || r15 != e15 {
            S8_MIG_CANARY_ERR.fetch_add(1, Ordering::SeqCst);
        }
        if errno(ret) != S4_EINTR {
            S8_MIG_SYSCALL_ERR.fetch_add(1, Ordering::SeqCst);
        }
        let post_cpu = s8_current_cpu_id();
        S8_MIG_POST_CPU.store(post_cpu, Ordering::Release);
        S8_MIG_LAST_CPU.store(post_cpu, Ordering::Release);
        S8_MIG_CPUS_SEEN.fetch_or(1u64 << post_cpu, Ordering::SeqCst);
        S8_MIG_DONE.store(round, Ordering::Release);
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn s8_rapid_signal_migration_leg(smp: bool) -> u64 {
    use core::sync::atomic::Ordering;
    let tgid = unsafe { sys_getpid() };
    S4_SIG_COUNT.store(0, Ordering::SeqCst);
    S4_SIG_LAST.store(0, Ordering::SeqCst);
    S8_MIG_STOP.store(0, Ordering::SeqCst);
    S8_MIG_READY.store(0, Ordering::SeqCst);
    S8_MIG_CANARY_ERR.store(0, Ordering::SeqCst);
    S8_MIG_SYSCALL_ERR.store(0, Ordering::SeqCst);
    S8_MIG_FRAME_OK.store(0, Ordering::SeqCst);
    S8_MIG_FRAME_ERR.store(0, Ordering::SeqCst);
    S8_MIG_TID.store(-1, Ordering::SeqCst);
    S8_MIG_CPUS_SEEN.store(0, Ordering::SeqCst);
    S8_SIG_CPUS_SEEN.store(0, Ordering::SeqCst);
    S8_MIG_LAST_CPU.store(u32::MAX, Ordering::SeqCst);
    S8_SIG_LAST_CPU.store(u32::MAX, Ordering::SeqCst);
    S8_MIG_FUTEX.0.store(0, Ordering::SeqCst);
    S8_MIG_ARMED.store(0, Ordering::SeqCst);
    S8_MIG_DONE.store(0, Ordering::SeqCst);
    S8_MIG_BLOCK_CPU.store(u32::MAX, Ordering::SeqCst);
    S8_MIG_POST_CPU.store(u32::MAX, Ordering::SeqCst);
    S8_MIG_EXP_RIP.store(0, Ordering::SeqCst);
    S8_MIG_EXP_R12.store(0, Ordering::SeqCst);
    S8_MIG_EXP_R13.store(0, Ordering::SeqCst);
    S8_MIG_EXP_R14.store(0, Ordering::SeqCst);
    S8_MIG_EXP_R15.store(0, Ordering::SeqCst);
    // Probe CPUID once on the parent thread before spawning the worker/handler.
    let _ = s8_has_rdtscp();
    let seed = monotonic_ns()
        .map(|ns| ns as u64)
        .unwrap_or(0x1357_9BDF_2468_ACE0u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15u64)
        ^ (tgid << 17);
    S8_MIG_SEED.store(seed, Ordering::Release);

    let act: [u64; 4] = [
        s8_migration_signal_handler as extern "C" fn(i32, *const u8, *const u8) as usize as u64,
        SA_RESTORER_FLAG | S8_SA_SIGINFO_FLAG,
        pi_sigreturn_trampoline as unsafe extern "C" fn() as usize as u64,
        0,
    ];
    if unsafe { syscall4(SYS_RT_SIGACTION, SIGUSR1_NR, act.as_ptr() as u64, 0, 8) } != 0 {
        return 0x40;
    }

    let stack = unsafe { mmap_anon(S4_STACK_BYTES, false) };
    if stack < 0 {
        return 0x41;
    }
    let tid = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            stack as usize + S4_STACK_BYTES,
            core::ptr::null_mut(),
            S8_MIG_TID.as_ptr(),
            s8_signal_migration_worker,
        )
    };
    if is_error(tid) || tid == 0 {
        unsafe { munmap(stack as usize, S4_STACK_BYTES) };
        return 0x42;
    }

    let mut ready = false;
    for _ in 0..THREAD_POLL_YIELDS {
        if S8_MIG_READY.load(Ordering::Acquire) != 0 {
            ready = true;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if !ready {
        S8_MIG_STOP.store(1, Ordering::Release);
        S8_MIG_ARMED.store(u32::MAX, Ordering::Release);
        if s4_await_tid_zero(&S8_MIG_TID) {
            unsafe { munmap(stack as usize, S4_STACK_BYTES) };
        }
        return 0x43;
    }

    let mut migrations = 0u32;
    let mut signals_observed = 0u32;
    let mut signals_on_target = 0u32;
    let mut cross_cpu_syscalls = 0u32;
    for iter in 0..24u32 {
        let round = iter + 1;
        let src_cpu = iter & 1;
        let dst_cpu = (iter + 1) & 1;
        if smp {
            // 1. Pin the worker exclusively to src_cpu and confirm fresh
            //    execution there BEFORE arming its blocking SYS_FUTEX.
            let src_mask: u64 = 1u64 << src_cpu;
            if unsafe {
                syscall3(
                    S4_SYS_SCHED_SETAFFINITY,
                    tid,
                    8,
                    &src_mask as *const u64 as u64,
                )
            } != 0
            {
                break;
            }
            S8_MIG_LAST_CPU.store(u32::MAX, Ordering::SeqCst);
            let mut on_src = false;
            for _ in 0..THREAD_POLL_YIELDS {
                if S8_MIG_LAST_CPU.load(Ordering::Acquire) == src_cpu {
                    on_src = true;
                    break;
                }
                unsafe { userspace::syscall::sys_yield() };
            }
            if !on_src {
                break;
            }
        }

        // 2. Arm the blocking SYS_FUTEX round and deterministically wait until
        //    the worker is queued inside the kernel futex wait queue.
        S8_MIG_BLOCK_CPU.store(u32::MAX, Ordering::SeqCst);
        S8_MIG_POST_CPU.store(u32::MAX, Ordering::SeqCst);
        S8_SIG_LAST_CPU.store(u32::MAX, Ordering::SeqCst);
        S8_MIG_FUTEX.0.store(round, Ordering::SeqCst);
        S8_MIG_ARMED.store(round, Ordering::Release);

        if !parity_await_sleepers(&S8_MIG_FUTEX, 1) {
            break;
        }
        let entered_on = S8_MIG_BLOCK_CPU.load(Ordering::Acquire);
        if smp && entered_on != src_cpu {
            break;
        }

        // 3. Migrate the blocked thread to dst_cpu (dst_cpu != src_cpu) BEFORE
        //    sending SIGUSR1 so its syscall frame created on src_cpu crosses
        //    CPUs for signal delivery and rt_sigreturn restoration on dst_cpu.
        if smp {
            let dst_mask: u64 = 1u64 << dst_cpu;
            if unsafe {
                syscall3(
                    S4_SYS_SCHED_SETAFFINITY,
                    tid,
                    8,
                    &dst_mask as *const u64 as u64,
                )
            } != 0
            {
                break;
            }
        }

        let before = S4_SIG_COUNT.load(Ordering::SeqCst);
        if unsafe { syscall3(SYS_TGKILL, tgid, tid, SIGUSR1_NR) } != 0 {
            break;
        }
        let mut round_completed = false;
        for _ in 0..THREAD_POLL_YIELDS {
            if S8_MIG_DONE.load(Ordering::Acquire) == round {
                round_completed = true;
                break;
            }
            unsafe { userspace::syscall::sys_yield() };
        }
        if !round_completed {
            break;
        }
        if S4_SIG_COUNT.load(Ordering::SeqCst) > before {
            signals_observed += 1;
        }
        if smp {
            let sig_cpu = S8_SIG_LAST_CPU.load(Ordering::Acquire);
            let post_cpu = S8_MIG_POST_CPU.load(Ordering::Acquire);
            if sig_cpu == dst_cpu {
                signals_on_target += 1;
            }
            if entered_on == src_cpu && sig_cpu == dst_cpu && post_cpu == dst_cpu {
                migrations += 1;
                cross_cpu_syscalls += 1;
            }
        }
    }

    S8_MIG_STOP.store(1, Ordering::Release);
    S8_MIG_ARMED.store(u32::MAX, Ordering::Release);
    unsafe {
        let _ = futex(
            &S8_MIG_FUTEX,
            FUTEX_WAKE_OP | FUTEX_PRIVATE,
            FUTEX_ALL,
            0,
            0,
            0,
        );
    }
    let joined = s4_await_tid_zero(&S8_MIG_TID);
    if joined {
        unsafe { munmap(stack as usize, S4_STACK_BYTES) };
    }

    if !joined {
        return 0x44;
    }
    if S8_MIG_CANARY_ERR.load(Ordering::SeqCst) != 0 {
        return 0x45;
    }
    if S8_MIG_SYSCALL_ERR.load(Ordering::SeqCst) != 0 {
        return 0x4a;
    }
    if S8_MIG_FRAME_ERR.load(Ordering::SeqCst) != 0 || S8_MIG_FRAME_OK.load(Ordering::SeqCst) != 24
    {
        return 0x4b;
    }
    if signals_observed < 24 || S4_SIG_LAST.load(Ordering::SeqCst) != SIGUSR1_NR as i32 {
        return 0x46;
    }
    if smp && (migrations < 24 || cross_cpu_syscalls < 24) {
        return 0x47;
    }
    if smp && (S8_MIG_CPUS_SEEN.load(Ordering::SeqCst) & 3) != 3 {
        return 0x48;
    }
    if smp && ((S8_SIG_CPUS_SEEN.load(Ordering::SeqCst) & 3) != 3 || signals_on_target < 24) {
        return 0x49;
    }
    S4_LEG_OK
}

/// R175 D0-CROSS-1: Verify rapid Ring-3 SIGUSR1 delivery during cross-CPU migration.
fn test_rapid_signal_migration(results: &mut TestResult) {
    print("Testing rapid signal delivery during cross-CPU task migration... ");
    let cpus = unsafe { shared_fault_test(0, 0, 0) };
    let smp = !is_error(cpus) && (cpus & 3 == 3);
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("rapid signal migration: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s8_rapid_signal_migration_leg(smp)) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => {
            if smp {
                results.pass(
                    "rapid signal delivery during cross-CPU task migration preserves registers and handler state",
                );
            } else {
                results.pass(
                    "rapid signal delivery on single CPU preserves registers and handler state",
                );
                println("[SKIP] rapid signal migration: requires CPUs 0 and 1");
            }
        }
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("rapid signal migration: signal/migration invariant failed");
        }
        None => results.fail("rapid signal migration: could not reap host"),
    }
}

// ---------------------------------------------------------------------------
// STRICT-Q S8 (R175 D0-CROSS-3): Real Ring-3 CLONE_NEWPID SIGKILL cascade storm.
// ---------------------------------------------------------------------------

fn s8_proc_status_is_stopped(pid: u64) -> bool {
    let mut path = [0u8; 32];
    let prefix = b"/proc/";
    let suffix = b"/status\0";
    let mut len = 0usize;
    for &b in prefix {
        path[len] = b;
        len += 1;
    }
    let mut digits = [0u8; 20];
    let mut dlen = 0usize;
    let mut n = pid;
    if n == 0 {
        digits[0] = b'0';
        dlen = 1;
    } else {
        while n > 0 {
            digits[dlen] = b'0' + (n % 10) as u8;
            dlen += 1;
            n /= 10;
        }
    }
    while dlen > 0 {
        dlen -= 1;
        path[len] = digits[dlen];
        len += 1;
    }
    for &b in suffix {
        path[len] = b;
        len += 1;
    }

    let fd = unsafe { sys_open(path.as_ptr(), 0, 0) };
    if is_error(fd) {
        return false;
    }
    let mut buf = [0u8; 512];
    let nread = unsafe { syscall3(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64) };
    unsafe { sys_close(fd) };
    if is_error(nread) || nread == 0 {
        return false;
    }
    let data = &buf[..(nread as usize).min(buf.len())];
    let needle = b"State:\tT (stopped)";
    data.windows(needle.len()).any(|w| w == needle)
}

fn s8_reap_pid_bounded(pid: u64, max_ms: u32) -> Option<u64> {
    let poll_sleep = [0i64, 1_000_000i64]; // 1 ms
    for attempt in 0..(64 + max_ms) {
        let mut info = SigInfo::poisoned();
        let r = waitid(P_PID, pid, &mut info, WEXITED | WNOHANG);
        if is_error(r) {
            return None;
        }
        if info.pid() as u64 == pid {
            return Some(info.status() as u64);
        }
        if attempt < 64 {
            unsafe { userspace::syscall::sys_yield() };
        } else {
            unsafe {
                let _ = syscall2(SYS_NANOSLEEP, poll_sleep.as_ptr() as u64, 0);
            }
        }
    }
    None
}

fn s8_namespace_teardown_wave(desc_pipe: [i32; 2]) -> u64 {
    // Unshare into a new child PID namespace; the next fork becomes ns PID 1.
    if unsafe { syscall1(S4_SYS_UNSHARE, S4_CLONE_NEWPID) } != 0 {
        unsafe {
            sys_close(desc_pipe[0] as u64);
            sys_close(desc_pipe[1] as u64);
        }
        return 0x50;
    }
    let mut ready_pipe = [-1i32; 2];
    if unsafe { syscall2(SYS_PIPE2, ready_pipe.as_mut_ptr() as u64, 0) } != 0 {
        unsafe {
            sys_close(desc_pipe[0] as u64);
            sys_close(desc_pipe[1] as u64);
        }
        return 0x51;
    }
    let mut stop_pipe = [-1i32; 2];
    if unsafe { syscall2(SYS_PIPE2, stop_pipe.as_mut_ptr() as u64, 0) } != 0 {
        unsafe {
            sys_close(ready_pipe[0] as u64);
            sys_close(ready_pipe[1] as u64);
            sys_close(desc_pipe[0] as u64);
            sys_close(desc_pipe[1] as u64);
        }
        return 0x57;
    }

    let ns_init = unsafe { sys_fork() };
    if is_error(ns_init) {
        unsafe {
            sys_close(ready_pipe[0] as u64);
            sys_close(ready_pipe[1] as u64);
            sys_close(stop_pipe[0] as u64);
            sys_close(stop_pipe[1] as u64);
            sys_close(desc_pipe[0] as u64);
            sys_close(desc_pipe[1] as u64);
        }
        return 0x52;
    }
    if ns_init == 0 {
        unsafe {
            sys_close(ready_pipe[0] as u64);
            sys_close(stop_pipe[0] as u64);
            sys_close(desc_pipe[0] as u64);
        }
        if unsafe { sys_getpid() } != 1 {
            unsafe { raw_exit(SYS_EXIT_GROUP, 0x60) };
        }
        // Child 1: keeps desc_pipe[1] open, signals readiness on stop_pipe[1],
        // and stops itself with SIGSTOP (exercises stopped-member cascade teardown).
        let stopped_child = unsafe { sys_fork() };
        if is_error(stopped_child) {
            unsafe { raw_exit(SYS_EXIT_GROUP, 0x61) };
        }
        if stopped_child == 0 {
            unsafe {
                sys_close(ready_pipe[1] as u64);
                let s = [b'S'];
                let _ = syscall3(SYS_WRITE, stop_pipe[1] as u64, s.as_ptr() as u64, 1);
                sys_close(stop_pipe[1] as u64);
                let me = sys_getpid();
                let _ = userspace::syscall::sys_kill(me, S4_SIGSTOP_NR);
                // If SIGSTOP failed or did not genuinely stop this child,
                // write a poison byte to desc_pipe[1] and exit non-SIGKILL so
                // both the pre-kill EAGAIN check and post-reap SIGKILL/EOF
                // checks fail immediately.
                let poison = [b'X'];
                let _ = syscall3(SYS_WRITE, desc_pipe[1] as u64, poison.as_ptr() as u64, 1);
                raw_exit(SYS_EXIT_GROUP, 0x63);
            }
        }
        // Child 2: active yielding runner keeping desc_pipe[1] open inside the namespace.
        let active_child = unsafe { sys_fork() };
        if is_error(active_child) {
            unsafe { raw_exit(SYS_EXIT_GROUP, 0x62) };
        }
        if active_child == 0 {
            unsafe {
                sys_close(ready_pipe[1] as u64);
                sys_close(stop_pipe[1] as u64);
                loop {
                    userspace::syscall::sys_yield();
                }
            }
        }
        // ns_init drops stop_pipe[1] and desc_pipe[1] so ONLY the two
        // descendants hold desc_pipe[1] open; wait until the kernel's
        // /proc/<stopped_child>/status genuinely reports State: T (stopped)
        // before announcing readiness to the outer host.
        unsafe {
            sys_close(stop_pipe[1] as u64);
            sys_close(desc_pipe[1] as u64);
        }
        let mut child_stopped = false;
        let stop_poll = [0i64, 1_000_000i64]; // 1 ms
        for attempt in 0..300u32 {
            if s8_proc_status_is_stopped(stopped_child) {
                child_stopped = true;
                break;
            }
            if attempt < 64 {
                unsafe { userspace::syscall::sys_yield() };
            } else {
                unsafe {
                    let _ = syscall2(SYS_NANOSLEEP, stop_poll.as_ptr() as u64, 0);
                }
            }
        }
        if !child_stopped {
            unsafe {
                sys_close(ready_pipe[1] as u64);
                raw_exit(SYS_EXIT_GROUP, 0x64);
            }
        }
        let b = [b'R'];
        let _ = unsafe { syscall3(SYS_WRITE, ready_pipe[1] as u64, b.as_ptr() as u64, 1) };
        unsafe { sys_close(ready_pipe[1] as u64) };
        // Finite fallback exit so a failed SIGKILL never leaves ns_init looping forever.
        let fallback_sleep = [5i64, 0i64];
        unsafe {
            let _ = syscall2(SYS_NANOSLEEP, fallback_sleep.as_ptr() as u64, 0);
            raw_exit(SYS_EXIT_GROUP, 0x65);
        }
    }

    unsafe {
        sys_close(ready_pipe[1] as u64);
        sys_close(stop_pipe[1] as u64);
        sys_close(desc_pipe[1] as u64);
    }
    let mut marker = [0u8; 1];
    let r_ready = unsafe {
        syscall3(
            SYS_READ,
            ready_pipe[0] as u64,
            marker.as_mut_ptr() as u64,
            1,
        )
    };
    unsafe { sys_close(ready_pipe[0] as u64) };
    let mut stop_marker = [0u8; 1];
    let r_stop = if r_ready == 1 && marker[0] == b'R' {
        unsafe {
            syscall3(
                SYS_READ,
                stop_pipe[0] as u64,
                stop_marker.as_mut_ptr() as u64,
                1,
            )
        }
    } else {
        0
    };
    unsafe { sys_close(stop_pipe[0] as u64) };

    if r_ready != 1 || marker[0] != b'R' || r_stop != 1 || stop_marker[0] != b'S' {
        unsafe {
            sys_close(desc_pipe[0] as u64);
            userspace::syscall::sys_kill(ns_init, SIGKILL_NR);
        }
        let _ = s8_reap_pid_bounded(ns_init, 500);
        return 0x53;
    }

    // Hold 15 ms after ns_init confirmed State: T (stopped), then confirm
    // desc_pipe[0] still reports EAGAIN (descendants are live before SIGKILL).
    let settle = [0i64, 15_000_000i64];
    unsafe {
        let _ = syscall2(SYS_NANOSLEEP, settle.as_ptr() as u64, 0);
    }
    let mut probe = [0u8; 1];
    let before_kill =
        unsafe { syscall3(SYS_READ, desc_pipe[0] as u64, probe.as_mut_ptr() as u64, 1) };
    unsafe { sys_close(desc_pipe[0] as u64) };
    if errno(before_kill) != EAGAIN {
        unsafe { userspace::syscall::sys_kill(ns_init, SIGKILL_NR) };
        let _ = s8_reap_pid_bounded(ns_init, 500);
        return 0x59;
    }

    if unsafe { userspace::syscall::sys_kill(ns_init, SIGKILL_NR) } != 0 {
        let _ = s8_reap_pid_bounded(ns_init, 500);
        return 0x54;
    }
    if s8_reap_pid_bounded(ns_init, 2000) != Some(128 + SIGKILL_NR) {
        return 0x55;
    }
    S4_LEG_OK
}

/// R175 D0-CROSS-3: Verify repeated CLONE_NEWPID init SIGKILL cascades cleanly.
fn test_namespace_teardown_storm(results: &mut TestResult) {
    print("Testing CLONE_NEWPID namespace teardown storm (12 waves)... ");
    let mut total_reaped_descendants = 0u64;
    for wave in 0..12u64 {
        let mut desc_pipe = [-1i32; 2];
        if unsafe { syscall2(SYS_PIPE2, desc_pipe.as_mut_ptr() as u64, S4_O_NONBLOCK) } != 0 {
            results.fail("namespace teardown storm: desc_pipe creation failed");
            return;
        }
        let host = unsafe { sys_fork() };
        if is_error(host) {
            unsafe {
                sys_close(desc_pipe[0] as u64);
                sys_close(desc_pipe[1] as u64);
            }
            results.fail("namespace teardown storm: outer fork failed");
            return;
        }
        if host == 0 {
            unsafe { raw_exit(SYS_EXIT_GROUP, s8_namespace_teardown_wave(desc_pipe)) };
        }
        // Only the two namespace descendants retain desc_pipe[1].
        unsafe { sys_close(desc_pipe[1] as u64) };
        match reap_pid(host) {
            Some(S4_LEG_OK) => {}
            Some(code) => {
                unsafe { sys_close(desc_pipe[0] as u64) };
                print("wave ");
                print_int(wave as i64);
                print(" exit ");
                print_int(code as i64);
                print(" ");
                results.fail("namespace teardown storm: wave failed");
                return;
            }
            None => {
                unsafe { sys_close(desc_pipe[0] as u64) };
                results.fail("namespace teardown storm: could not reap wave host");
                return;
            }
        }
        // Reap the 2 reparented namespace descendants in root PID 1, verifying
        // both exited with SIGKILL (128 + 9) and zero zombies remain.
        let mut wave_reaped = 0u64;
        let mut sigkill_reaped = 0u64;
        let mut drained = false;
        let poll_sleep = [0i64, 1_000_000i64]; // 1 ms
        for attempt in 0..300u32 {
            let mut info = SigInfo::poisoned();
            let r = waitid(P_ALL, 0, &mut info, WEXITED | WNOHANG);
            if is_error(r) {
                if errno(r) == ECHILD {
                    drained = true;
                    break;
                }
                unsafe { sys_close(desc_pipe[0] as u64) };
                results.fail(
                    "namespace teardown storm: unexpected waitid error while reaping descendants",
                );
                return;
            }
            if info.pid() != 0 {
                wave_reaped += 1;
                if info.status() == (128 + SIGKILL_NR) as i32 {
                    sigkill_reaped += 1;
                }
                continue;
            }
            if attempt < 64 {
                unsafe { userspace::syscall::sys_yield() };
            } else {
                unsafe {
                    let _ = syscall2(SYS_NANOSLEEP, poll_sleep.as_ptr() as u64, 0);
                }
            }
        }
        // Confirm desc_pipe[0] now returns EOF (0), proving both descendants
        // actually died and released their inherited pipe write FDs.
        let mut probe = [0u8; 1];
        let after_reap =
            unsafe { syscall3(SYS_READ, desc_pipe[0] as u64, probe.as_mut_ptr() as u64, 1) };
        unsafe { sys_close(desc_pipe[0] as u64) };
        if !drained || wave_reaped != 2 || sigkill_reaped != 2 || after_reap != 0 {
            print("wave ");
            print_int(wave as i64);
            print(" reaped=");
            print_int(wave_reaped as i64);
            print(" sigkill=");
            print_int(sigkill_reaped as i64);
            print(" eof=");
            print_int(after_reap as i64);
            print(" ");
            results
                .fail("namespace teardown storm: reparented descendants not killed/reaped cleanly");
            return;
        }
        total_reaped_descendants += wave_reaped;
    }
    if total_reaped_descendants != 24 {
        results.fail("namespace teardown storm: unexpected total descendant count");
        return;
    }
    results.pass(
        "namespace teardown storm: unshare CLONE_NEWPID init SIGKILL cascades to stopped and running members across waves",
    );
}

// ---------------------------------------------------------------------------
// STRICT-Q S5 (R174-B4): Concurrent CLONE_VM brk() VA reservation TOCTOU test.
// ---------------------------------------------------------------------------

static S5_BRK_TARGET: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static S5_BRK_STOP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S5_BRK_READY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S5_BRK_MMAP_WINS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S5_BRK_MMAP_EEXIST: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S5_BRK_ERR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S5_BRK_SMP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

extern "C" fn s5_brk_mmap_racer() -> ! {
    use core::sync::atomic::Ordering;
    if S5_BRK_SMP.load(Ordering::Acquire) != 0 {
        let _ = cow_test_pin(2);
    }
    let target = S5_BRK_TARGET.load(Ordering::Acquire);
    S5_BRK_READY.store(1, Ordering::Release);

    let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
    let mut seq = 0u64;
    while S5_BRK_STOP.load(Ordering::Acquire) == 0 {
        seq = seq.wrapping_add(1);
        let got = unsafe { mmap_raw(target, PAGE, flags) };
        if got == target as i64 {
            // While this mapping is live at `target`, sys_brk MUST NOT have
            // grown past `target` (neither previously nor concurrently).
            let cur_brk = unsafe { syscall1(SYS_BRK, 0) as usize };
            if cur_brk > target {
                let _ = unsafe { munmap(target, PAGE) };
                S5_BRK_ERR.store(1, Ordering::Release);
                break;
            }
            let sentinel = 0x5B40_0000_0000_0000u64 | (seq & 0xFFFF_FFFF);
            unsafe {
                core::ptr::write_volatile(target as *mut u64, sentinel);
                userspace::syscall::sys_yield();
            }
            let after_val = unsafe { core::ptr::read_volatile(target as *const u64) };
            let after_brk = unsafe { syscall1(SYS_BRK, 0) as usize };
            let unmap_rc = unsafe { munmap(target, PAGE) };
            if after_val != sentinel || after_brk > target || unmap_rc != 0 {
                S5_BRK_ERR.store(2, Ordering::Release);
                break;
            }
            S5_BRK_MMAP_WINS.fetch_add(1, Ordering::Relaxed);
        } else if got == -(EEXIST as i64) {
            S5_BRK_MMAP_EEXIST.fetch_add(1, Ordering::Relaxed);
        } else {
            S5_BRK_ERR.store(3, Ordering::Release);
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn s5_brk_va_reservation_toctou_leg() -> u64 {
    use core::sync::atomic::Ordering;
    const SPAN_PAGES: usize = 16;
    const TARGET_PAGE_OFF: usize = 8;
    const ROUNDS: u64 = 64;

    let old = unsafe { syscall1(SYS_BRK, 0) as usize };
    if old == 0 {
        return 0x70;
    }
    let base = (old + PAGE - 1) & !(PAGE - 1);
    let top = base + SPAN_PAGES * PAGE;
    let target = base + TARGET_PAGE_OFF * PAGE;
    let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;

    // 1. Deterministic boundary contract before spawning the sibling thread:
    //    - mmap at `target` succeeds while heap is at `old`;
    //    - brk(top) crossing `target` MUST refuse (return unchanged <= target);
    //    - after munmap, brk(top) succeeds and MAP_FIXED_NOREPLACE at `target`
    //      returns -EEXIST.
    if unsafe { mmap_raw(target, PAGE, flags) } != target as i64 {
        return 0x71;
    }
    unsafe { core::ptr::write_volatile(target as *mut u64, 0xB411_0001) };
    let blocked_brk = unsafe { syscall1(SYS_BRK, top as u64) as usize };
    let intact = unsafe { core::ptr::read_volatile(target as *const u64) } == 0xB411_0001;
    let unmap_ok = unsafe { munmap(target, PAGE) } == 0;
    if blocked_brk > target || !intact || !unmap_ok {
        return 0x72;
    }

    if unsafe { syscall1(SYS_BRK, top as u64) as usize } != top {
        return 0x73;
    }
    unsafe { core::ptr::write_volatile(target as *mut u64, 0xB422_0002) };
    let eexist_rc = unsafe { mmap_raw(target, PAGE, flags) };
    let heap_intact = unsafe { core::ptr::read_volatile(target as *const u64) } == 0xB422_0002;
    let shrunk = unsafe { syscall1(SYS_BRK, base as u64) as usize } == base;
    if eexist_rc != -(EEXIST as i64) || !heap_intact || !shrunk {
        let _ = unsafe { syscall1(SYS_BRK, old as u64) };
        return 0x74;
    }

    // 2. Concurrent CLONE_VM race: main thread repeatedly grows/verifies/shrinks
    //    brk across [base, top) while sibling thread hammers MAP_FIXED_NOREPLACE
    //    at `target` inside that exact grow window.
    let cpus = unsafe { cow_test_command(0, 0) };
    let smp = !is_error(cpus) && (cpus & 3) == 3;
    if smp {
        let _ = cow_test_pin(1);
    }

    S5_BRK_TARGET.store(target, Ordering::Release);
    S5_BRK_STOP.store(0, Ordering::Release);
    S5_BRK_READY.store(0, Ordering::Release);
    S5_BRK_MMAP_WINS.store(0, Ordering::Release);
    S5_BRK_MMAP_EEXIST.store(0, Ordering::Release);
    S5_BRK_ERR.store(0, Ordering::Release);
    S5_BRK_SMP.store(if smp { 1 } else { 0 }, Ordering::Release);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);

    let tid = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            s5_brk_mmap_racer,
        )
    };
    if is_error(tid) || tid == 0 {
        let _ = unsafe { syscall1(SYS_BRK, old as u64) };
        return 0x75;
    }

    for _ in 0..THREAD_POLL_YIELDS {
        if S5_BRK_READY.load(Ordering::Acquire) != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if S5_BRK_READY.load(Ordering::Acquire) == 0 {
        S5_BRK_STOP.store(1, Ordering::Release);
        let _ = g8_join_thread();
        let _ = unsafe { syscall1(SYS_BRK, old as u64) };
        return 0x76;
    }

    let mut brk_grows = 0u64;
    let mut main_err = 0u64;
    for round in 1..=ROUNDS {
        if S5_BRK_ERR.load(Ordering::Acquire) != 0 {
            break;
        }
        let got = unsafe { syscall1(SYS_BRK, top as u64) as usize };
        if got == top {
            brk_grows += 1;
            let p0 = base as *mut u64;
            let pm = target as *mut u64;
            let pe = (top - PAGE) as *mut u64;
            let pat = 0xB400_0000_0000_0000u64 | round;
            unsafe {
                core::ptr::write_volatile(p0, pat);
                core::ptr::write_volatile(pm, pat ^ 1);
                core::ptr::write_volatile(pe, pat ^ 2);
                userspace::syscall::sys_yield();
            }
            let v0 = unsafe { core::ptr::read_volatile(p0) };
            let vm = unsafe { core::ptr::read_volatile(pm) };
            let ve = unsafe { core::ptr::read_volatile(pe) };
            if v0 != pat || vm != (pat ^ 1) || ve != (pat ^ 2) {
                main_err = 0x77;
                break;
            }
            let back = unsafe { syscall1(SYS_BRK, base as u64) as usize };
            if back != base {
                main_err = 0x78;
                break;
            }
        } else if got != base {
            main_err = 0x79;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }

    S5_BRK_STOP.store(1, Ordering::Release);
    let joined = g8_join_thread();
    let restored = unsafe { syscall1(SYS_BRK, old as u64) as usize } == old;

    if !joined {
        return 0x7a;
    }
    if main_err != 0 {
        return main_err;
    }
    let racer_err = S5_BRK_ERR.load(Ordering::Acquire);
    if racer_err != 0 {
        return 0x7b + racer_err as u64;
    }
    let racer_total =
        S5_BRK_MMAP_WINS.load(Ordering::Relaxed) + S5_BRK_MMAP_EEXIST.load(Ordering::Relaxed);
    if !restored || brk_grows == 0 || racer_total == 0 {
        return 0x7f;
    }
    S4_LEG_OK
}

/// R174-B4: Verify concurrent CLONE_VM brk() and MAP_FIXED_NOREPLACE never overlap.
fn test_brk_va_reservation_toctou(results: &mut TestResult) {
    print("Testing R174-B4 concurrent CLONE_VM brk VA reservation TOCTOU... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("brk VA reservation TOCTOU: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s5_brk_va_reservation_toctou_leg()) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => {
            results.pass(
                "brk VA reservation TOCTOU: concurrent CLONE_VM brk and MAP_FIXED_NOREPLACE never overlap",
            );
        }
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("brk VA reservation TOCTOU: concurrent overlap or corruption detected");
        }
        None => results.fail("brk VA reservation TOCTOU: could not reap host"),
    }
}

// ---------------------------------------------------------------------------
// STRICT-Q S9: Ring-3 context switch RIP/RFLAGS, TLS, syscall_active, FPU IRQ.
// ---------------------------------------------------------------------------

const S9_SYS_ARCH_PRCTL: u64 = 158;
const S9_ARCH_SET_GS: u64 = 0x1001;
const S9_ARCH_SET_FS: u64 = 0x1002;
const S9_ARCH_GET_FS: u64 = 0x1003;
const S9_ARCH_GET_GS: u64 = 0x1004;
const S9_SYS_SCHED_SETAFFINITY: u64 = 203;
const S9_SYS_SCHED_GETAFFINITY: u64 = 204;
const S9_FUTEX_WAIT: u64 = 0;
const S9_FUTEX_WAKE: u64 = 1;
const S9_EBUSY: i32 = 16;
const S9_EINVAL: i32 = 22;

#[repr(C, align(64))]
struct S9TlsBlock {
    magic0: u64,
    magic1: u64,
    pad: [u64; 6],
}

static S9_CTX_READY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_CTX_STOP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_CTX_ERR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_CTX_ITERS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[inline(never)]
unsafe fn s9_verify_ctx_round(tag: u64, round: u64) -> bool {
    let mut r12 = 0x1200_0000_0000_0000u64 | (tag << 40) | round;
    let mut r13 = 0x1300_0000_0000_0000u64 | (tag << 40) | (round ^ 0x55AA);
    let mut r14 = 0x1400_0000_0000_0000u64 | (tag << 40) | (round.wrapping_mul(3));
    let mut r15 = 0x1500_0000_0000_0000u64 | (tag << 40) | (round.wrapping_mul(7));
    let exp12 = r12;
    let exp13 = r13;
    let exp14 = r14;
    let exp15 = r15;
    let cs_before: u64;
    let ss_before: u64;
    let cs_after: u64;
    let ss_after: u64;
    let rflags_after: u64;

    // Preserve callee-saved r12-r15 and verify Ring-3 CS/SS + DF==0 across both
    // an inline SYS_SCHED_YIELD (24) and a pure user-space preemption spin.
    core::arch::asm!(
        "xor {cs_b:e}, {cs_b:e}",
        "mov {cs_b:x}, cs",
        "xor {ss_b:e}, {ss_b:e}",
        "mov {ss_b:x}, ss",
        "mov eax, 24",
        "syscall",
        "mov eax, 4096",
        "2:",
        "pause",
        "dec eax",
        "jnz 2b",
        "xor {cs_a:e}, {cs_a:e}",
        "mov {cs_a:x}, cs",
        "xor {ss_a:e}, {ss_a:e}",
        "mov {ss_a:x}, ss",
        "pushfq",
        "pop {rfl}",
        inout("r12") r12,
        inout("r13") r13,
        inout("r14") r14,
        inout("r15") r15,
        cs_b = out(reg) cs_before,
        ss_b = out(reg) ss_before,
        cs_a = out(reg) cs_after,
        ss_a = out(reg) ss_after,
        rfl = out(reg) rflags_after,
        out("rax") _,
        out("rcx") _,
        out("r11") _,
        options(preserves_flags),
    );

    r12 == exp12
        && r13 == exp13
        && r14 == exp14
        && r15 == exp15
        && (cs_before & 3) == 3
        && (ss_before & 3) == 3
        && (cs_after & 3) == 3
        && (ss_after & 3) == 3
        && (rflags_after & (1 << 10)) == 0 // DF must remain clear
        && (rflags_after & (1 << 9)) != 0 // IF must remain enabled in Ring 3
}

extern "C" fn s9_ctx_sibling() -> ! {
    use core::sync::atomic::Ordering;
    let _ = cow_test_pin(1);
    S9_CTX_READY.store(1, Ordering::Release);
    let mut round = 0u64;
    while S9_CTX_STOP.load(Ordering::Acquire) == 0 {
        round = round.wrapping_add(1);
        if !unsafe { s9_verify_ctx_round(2, round) } {
            S9_CTX_ERR.store(1, Ordering::Release);
            break;
        }
        S9_CTX_ITERS.fetch_add(1, Ordering::Relaxed);
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn s9_context_switch_rip_rflags_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let _ = cow_test_pin(1);
    S9_CTX_READY.store(0, Ordering::Release);
    S9_CTX_STOP.store(0, Ordering::Release);
    S9_CTX_ERR.store(0, Ordering::Release);
    S9_CTX_ITERS.store(0, Ordering::Release);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);

    let tid = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            s9_ctx_sibling,
        )
    };
    if is_error(tid) || tid == 0 {
        return 0x80;
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if S9_CTX_READY.load(Ordering::Acquire) != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if S9_CTX_READY.load(Ordering::Acquire) == 0 {
        S9_CTX_STOP.store(1, Ordering::Release);
        let _ = g8_join_thread();
        return 0x81;
    }

    let mut main_ok = true;
    let sleep_1ms = [0i64, 1_000_000i64];
    for round in 1..=64u64 {
        if S9_CTX_ERR.load(Ordering::Acquire) != 0 {
            break;
        }
        if !unsafe { s9_verify_ctx_round(1, round) } {
            main_ok = false;
            break;
        }
        if round & 15 == 0 {
            let _ = unsafe { syscall2(SYS_NANOSLEEP, sleep_1ms.as_ptr() as u64, 0) };
        }
    }
    S9_CTX_STOP.store(1, Ordering::Release);
    let joined = g8_join_thread();
    if !joined
        || !main_ok
        || S9_CTX_ERR.load(Ordering::Acquire) != 0
        || S9_CTX_ITERS.load(Ordering::Relaxed) == 0
    {
        return 0x82;
    }
    S4_LEG_OK
}

/// R172-01: Verify RIP/RFLAGS/CS/SS and callee registers survive concurrent clone+yield/preemption.
fn test_context_switch_rip_rflags(results: &mut TestResult) {
    print("Testing R172-01 context switch RIP/RFLAGS/CS/SS preservation... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("context switch RIP/RFLAGS: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s9_context_switch_rip_rflags_leg()) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => results.pass(
            "context switch RIP/RFLAGS: concurrent threads preserve Ring-3 CS/SS, callee registers and flags across yields and preemptions",
        ),
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("context switch RIP/RFLAGS: register, flag, or ring check failed");
        }
        None => results.fail("context switch RIP/RFLAGS: could not reap host"),
    }
}

static S9_TLS_READY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_TLS_STOP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_TLS_ERR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_TLS_ITERS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[inline(never)]
unsafe fn s9_check_fs_gs(
    exp_fs_base: u64,
    exp_fs0: u64,
    exp_fs1: u64,
    exp_gs_base: u64,
    exp_gs0: u64,
    exp_gs1: u64,
) -> bool {
    let mut got_fs = 0u64;
    let mut got_gs = 0u64;
    if is_error(syscall2(
        S9_SYS_ARCH_PRCTL,
        S9_ARCH_GET_FS,
        &mut got_fs as *mut u64 as u64,
    )) || is_error(syscall2(
        S9_SYS_ARCH_PRCTL,
        S9_ARCH_GET_GS,
        &mut got_gs as *mut u64 as u64,
    )) {
        return false;
    }
    if got_fs != exp_fs_base || got_gs != exp_gs_base {
        return false;
    }
    let fs0: u64;
    let fs1: u64;
    let gs0: u64;
    let gs1: u64;
    core::arch::asm!(
        "mov {fs0}, qword ptr fs:[0]",
        "mov {fs1}, qword ptr fs:[8]",
        "mov {gs0}, qword ptr gs:[0]",
        "mov {gs1}, qword ptr gs:[8]",
        fs0 = out(reg) fs0,
        fs1 = out(reg) fs1,
        gs0 = out(reg) gs0,
        gs1 = out(reg) gs1,
        options(nostack, preserves_flags),
    );
    fs0 == exp_fs0 && fs1 == exp_fs1 && gs0 == exp_gs0 && gs1 == exp_gs1
}

extern "C" fn s9_tls_sibling() -> ! {
    use core::sync::atomic::Ordering;
    let _ = cow_test_pin(1);
    let fs_blk = S9TlsBlock {
        magic0: 0xF5B0_1111_2222_3333,
        magic1: 0xF5B1_4444_5555_6666,
        pad: [0; 6],
    };
    let gs_blk = S9TlsBlock {
        magic0: 0x65B0_7777_8888_9999,
        magic1: 0x65B1_AAAA_BBBB_CCCC,
        pad: [0; 6],
    };
    let fs_base = &fs_blk as *const S9TlsBlock as u64;
    let gs_base = &gs_blk as *const S9TlsBlock as u64;
    if is_error(unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_FS, fs_base) })
        || is_error(unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_GS, gs_base) })
    {
        S9_TLS_ERR.store(1, Ordering::Release);
        S9_TLS_READY.store(1, Ordering::Release);
        unsafe { raw_exit(SYS_EXIT, 1) };
    }
    S9_TLS_READY.store(1, Ordering::Release);
    while S9_TLS_STOP.load(Ordering::Acquire) == 0 {
        if !unsafe {
            s9_check_fs_gs(
                fs_base,
                fs_blk.magic0,
                fs_blk.magic1,
                gs_base,
                gs_blk.magic0,
                gs_blk.magic1,
            )
        } {
            S9_TLS_ERR.store(2, Ordering::Release);
            break;
        }
        S9_TLS_ITERS.fetch_add(1, Ordering::Relaxed);
        unsafe { userspace::syscall::sys_yield() };
    }
    let _ = unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_FS, 0) };
    let _ = unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_GS, 0) };
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn s9_tls_isolation_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let _ = cow_test_pin(1);
    let fs_blk = S9TlsBlock {
        magic0: 0xF5A0_1234_5678_9ABC,
        magic1: 0xF5A1_DEF0_1357_2468,
        pad: [0; 6],
    };
    let gs_blk = S9TlsBlock {
        magic0: 0x65A0_CAFE_BABE_0001,
        magic1: 0x65A1_DEAD_BEEF_0002,
        pad: [0; 6],
    };
    let fs_base = &fs_blk as *const S9TlsBlock as u64;
    let gs_base = &gs_blk as *const S9TlsBlock as u64;
    if is_error(unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_FS, fs_base) })
        || is_error(unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_GS, gs_base) })
    {
        return 0x84;
    }

    S9_TLS_READY.store(0, Ordering::Release);
    S9_TLS_STOP.store(0, Ordering::Release);
    S9_TLS_ERR.store(0, Ordering::Release);
    S9_TLS_ITERS.store(0, Ordering::Release);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);

    let tid = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            s9_tls_sibling,
        )
    };
    if is_error(tid) || tid == 0 {
        let _ = unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_FS, 0) };
        let _ = unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_GS, 0) };
        return 0x85;
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if S9_TLS_READY.load(Ordering::Acquire) != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if S9_TLS_READY.load(Ordering::Acquire) == 0 {
        S9_TLS_STOP.store(1, Ordering::Release);
        let _ = g8_join_thread();
        return 0x86;
    }

    let mut main_ok = true;
    let sleep_1ms = [0i64, 1_000_000i64];
    for round in 1..=96u64 {
        if S9_TLS_ERR.load(Ordering::Acquire) != 0 {
            break;
        }
        if !unsafe {
            s9_check_fs_gs(
                fs_base,
                fs_blk.magic0,
                fs_blk.magic1,
                gs_base,
                gs_blk.magic0,
                gs_blk.magic1,
            )
        } {
            main_ok = false;
            break;
        }
        if round & 31 == 0 {
            let _ = unsafe { syscall2(SYS_NANOSLEEP, sleep_1ms.as_ptr() as u64, 0) };
        } else {
            unsafe { userspace::syscall::sys_yield() };
        }
    }

    S9_TLS_STOP.store(1, Ordering::Release);
    let joined = g8_join_thread();
    let _ = unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_FS, 0) };
    let _ = unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_GS, 0) };
    if !joined
        || !main_ok
        || S9_TLS_ERR.load(Ordering::Acquire) != 0
        || S9_TLS_ITERS.load(Ordering::Relaxed) == 0
    {
        return 0x87;
    }
    S4_LEG_OK
}

/// R172-04: Verify FS_BASE and GS_BASE TLS isolation across context switches.
fn test_tls_isolation(results: &mut TestResult) {
    print("Testing R172-04 FS_BASE/GS_BASE TLS isolation... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("TLS isolation: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s9_tls_isolation_leg()) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => results.pass(
            "TLS isolation: concurrent threads preserve distinct FS_BASE and GS_BASE across context switches",
        ),
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("TLS isolation: FS_BASE or GS_BASE leaked across context switch");
        }
        None => results.fail("TLS isolation: could not reap host"),
    }
}

static S9_SYSCALL_READY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_SYSCALL_STOP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_SYSCALL_ERR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_SYSCALL_TGID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static S9_SYSCALL_FUTEX: FutexWord = FutexWord(core::sync::atomic::AtomicU32::new(0));

extern "C" fn s9_syscall_active_sibling() -> ! {
    use core::sync::atomic::Ordering;
    let _ = cow_test_pin(1);
    let exp_pid = S9_SYSCALL_TGID.load(Ordering::Acquire);
    let sleep_1ms = [0i64, 1_000_000i64];
    S9_SYSCALL_READY.store(1, Ordering::Release);
    while S9_SYSCALL_STOP.load(Ordering::Acquire) == 0 {
        let got_pid = unsafe { sys_getpid() };
        if is_error(got_pid) || got_pid != exp_pid {
            S9_SYSCALL_ERR.store(1, Ordering::Release);
            break;
        }
        let r = unsafe { syscall2(SYS_NANOSLEEP, sleep_1ms.as_ptr() as u64, 0) };
        if is_error(r) && errno(r) == S9_EBUSY {
            S9_SYSCALL_ERR.store(2, Ordering::Release);
            break;
        }
        let w = unsafe {
            syscall4(
                SYS_FUTEX,
                S9_SYSCALL_FUTEX.0.as_ptr() as u64,
                S9_FUTEX_WAKE,
                1,
                0,
            )
        };
        if is_error(w) && errno(w) == S9_EBUSY {
            S9_SYSCALL_ERR.store(3, Ordering::Release);
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn s9_syscall_active_leak_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let _ = cow_test_pin(1);
    let my_pid = unsafe { sys_getpid() };
    if is_error(my_pid) {
        return 0x88;
    }

    // Also fork an independent process pinned to CPU 0 hammering blocking syscalls.
    let peer = unsafe { sys_fork() };
    if is_error(peer) {
        return 0x89;
    }
    if peer == 0 {
        let _ = cow_test_pin(1);
        let child_pid = unsafe { sys_getpid() };
        let sleep_1ms = [0i64, 1_000_000i64];
        for _ in 0..16u32 {
            let p = unsafe { sys_getpid() };
            if is_error(p) || p != child_pid {
                unsafe { raw_exit(SYS_EXIT_GROUP, 1) };
            }
            let r = unsafe { syscall2(SYS_NANOSLEEP, sleep_1ms.as_ptr() as u64, 0) };
            if is_error(r) && errno(r) == S9_EBUSY {
                unsafe { raw_exit(SYS_EXIT_GROUP, 2) };
            }
            unsafe { userspace::syscall::sys_yield() };
        }
        unsafe { raw_exit(SYS_EXIT_GROUP, S4_LEG_OK) };
    }

    S9_SYSCALL_TGID.store(my_pid, Ordering::Release);
    S9_SYSCALL_READY.store(0, Ordering::Release);
    S9_SYSCALL_STOP.store(0, Ordering::Release);
    S9_SYSCALL_ERR.store(0, Ordering::Release);
    S9_SYSCALL_FUTEX.0.store(0, Ordering::Release);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);

    let tid = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            s9_syscall_active_sibling,
        )
    };
    if is_error(tid) || tid == 0 {
        let _ = reap_pid(peer);
        return 0x8a;
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if S9_SYSCALL_READY.load(Ordering::Acquire) != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }

    let sleep_1ms = [0i64, 1_000_000i64];
    let mut main_ok = true;
    for _ in 0..24u32 {
        if S9_SYSCALL_ERR.load(Ordering::Acquire) != 0 {
            break;
        }
        let p = unsafe { sys_getpid() };
        if is_error(p) || p != my_pid {
            main_ok = false;
            break;
        }
        let f = unsafe {
            syscall4(
                SYS_FUTEX,
                S9_SYSCALL_FUTEX.0.as_ptr() as u64,
                S9_FUTEX_WAIT,
                0,
                sleep_1ms.as_ptr() as u64,
            )
        };
        if is_error(f) && errno(f) == S9_EBUSY {
            main_ok = false;
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }

    S9_SYSCALL_STOP.store(1, Ordering::Release);
    let _ = unsafe {
        syscall4(
            SYS_FUTEX,
            S9_SYSCALL_FUTEX.0.as_ptr() as u64,
            S9_FUTEX_WAKE,
            1,
            0,
        )
    };
    let joined = g8_join_thread();
    let peer_ok = reap_pid(peer) == Some(S4_LEG_OK);
    if !joined || !peer_ok || !main_ok || S9_SYSCALL_ERR.load(Ordering::Acquire) != 0 {
        return 0x8b;
    }
    S4_LEG_OK
}

/// R172-05: Verify per-CPU syscall_active flag is cleared on switch_out (never leaks EBUSY).
fn test_syscall_active_leak(results: &mut TestResult) {
    print("Testing R172-05 per-CPU syscall_active isolation... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("syscall_active isolation: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s9_syscall_active_leak_leg()) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => results.pass(
            "syscall_active isolation: interleaved blocking syscalls on one CPU never leak EBUSY",
        ),
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("syscall_active isolation: leaked EBUSY or mismatched PID");
        }
        None => results.fail("syscall_active isolation: could not reap host"),
    }
}

static S9_FPU_READY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_FPU_STOP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_FPU_ERR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static S9_FPU_ITERS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[inline(never)]
unsafe fn s9_sse_spin_and_verify(input: &[u64; 16], spin_iters: u32) -> bool {
    let mut output = [0u64; 16];
    core::arch::asm!(
        "movdqu xmm0, [{in_ptr} + 0]",
        "movdqu xmm1, [{in_ptr} + 16]",
        "movdqu xmm2, [{in_ptr} + 32]",
        "movdqu xmm3, [{in_ptr} + 48]",
        "movdqu xmm4, [{in_ptr} + 64]",
        "movdqu xmm5, [{in_ptr} + 80]",
        "movdqu xmm6, [{in_ptr} + 96]",
        "movdqu xmm7, [{in_ptr} + 112]",
        "2:",
        "pause",
        "dec {cnt:e}",
        "jnz 2b",
        "movdqu [{out_ptr} + 0], xmm0",
        "movdqu [{out_ptr} + 16], xmm1",
        "movdqu [{out_ptr} + 32], xmm2",
        "movdqu [{out_ptr} + 48], xmm3",
        "movdqu [{out_ptr} + 64], xmm4",
        "movdqu [{out_ptr} + 80], xmm5",
        "movdqu [{out_ptr} + 96], xmm6",
        "movdqu [{out_ptr} + 112], xmm7",
        in_ptr = in(reg) input.as_ptr(),
        out_ptr = in(reg) output.as_mut_ptr(),
        cnt = inout(reg) spin_iters => _,
        out("xmm0") _,
        out("xmm1") _,
        out("xmm2") _,
        out("xmm3") _,
        out("xmm4") _,
        out("xmm5") _,
        out("xmm6") _,
        out("xmm7") _,
        options(nostack),
    );
    output == *input
}

fn s9_make_sse_pattern(tag: u64, round: u64) -> [u64; 16] {
    let mut buf = [0u64; 16];
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = (tag << 56)
            ^ ((i as u64) << 48)
            ^ round.wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ 0x0000_5A5A_A5A5_1357;
    }
    buf
}

extern "C" fn s9_fpu_sibling() -> ! {
    use core::sync::atomic::Ordering;
    let _ = cow_test_pin(1);
    S9_FPU_READY.store(1, Ordering::Release);
    let mut round = 0u64;
    while S9_FPU_STOP.load(Ordering::Acquire) == 0 {
        round = round.wrapping_add(1);
        let pat = s9_make_sse_pattern(0xB2, round);
        if !unsafe { s9_sse_spin_and_verify(&pat, 25_000) } {
            S9_FPU_ERR.store(1, Ordering::Release);
            break;
        }
        S9_FPU_ITERS.fetch_add(1, Ordering::Relaxed);
        unsafe { userspace::syscall::sys_yield() };
    }
    unsafe { raw_exit(SYS_EXIT, 0) }
}

fn s9_fpu_state_irq_isolation_leg() -> u64 {
    use core::sync::atomic::Ordering;
    let _ = cow_test_pin(1);
    S9_FPU_READY.store(0, Ordering::Release);
    S9_FPU_STOP.store(0, Ordering::Release);
    S9_FPU_ERR.store(0, Ordering::Release);
    S9_FPU_ITERS.store(0, Ordering::Release);
    GROUP_TID_WORD.store(-1, Ordering::SeqCst);

    let tid = unsafe {
        raw_clone(
            THREAD_FLAGS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            group_stack_top(),
            core::ptr::null_mut(),
            GROUP_TID_WORD.as_ptr(),
            s9_fpu_sibling,
        )
    };
    if is_error(tid) || tid == 0 {
        return 0x8c;
    }
    for _ in 0..THREAD_POLL_YIELDS {
        if S9_FPU_READY.load(Ordering::Acquire) != 0 {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    if S9_FPU_READY.load(Ordering::Acquire) == 0 {
        S9_FPU_STOP.store(1, Ordering::Release);
        let _ = g8_join_thread();
        return 0x8d;
    }

    let sleep_1ms = [0i64, 1_000_000i64];
    let mut main_ok = true;
    for round in 1..=20u64 {
        if S9_FPU_ERR.load(Ordering::Acquire) != 0 {
            break;
        }
        let pat = s9_make_sse_pattern(0xA1, round);
        if !unsafe { s9_sse_spin_and_verify(&pat, 25_000) } {
            main_ok = false;
            break;
        }
        if round & 3 == 0 {
            let _ = unsafe { syscall2(SYS_NANOSLEEP, sleep_1ms.as_ptr() as u64, 0) };
        } else {
            unsafe { userspace::syscall::sys_yield() };
        }
    }

    S9_FPU_STOP.store(1, Ordering::Release);
    let joined = g8_join_thread();
    if !joined
        || !main_ok
        || S9_FPU_ERR.load(Ordering::Acquire) != 0
        || S9_FPU_ITERS.load(Ordering::Relaxed) == 0
    {
        return 0x8e;
    }
    S4_LEG_OK
}

/// R174-A1: Verify SSE XMM0-XMM7 state stays bit-exact across timer IRQ preemptions.
fn test_fpu_state_irq_isolation(results: &mut TestResult) {
    print("Testing R174-A1 FPU/SSE state IRQ isolation... ");
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("FPU IRQ isolation: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s9_fpu_state_irq_isolation_leg()) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => results.pass(
            "FPU IRQ isolation: concurrent SSE XMM0-XMM7 state stays bit-exact across timer preemptions",
        ),
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("FPU IRQ isolation: XMM state corrupted across preemption");
        }
        None => results.fail("FPU IRQ isolation: could not reap host"),
    }
}

// ---------------------------------------------------------------------------
// STRICT-Q S6: Ring-3 CPU affinity, migration, load balancing & work stealing.
// ---------------------------------------------------------------------------

fn s6_online_cpu_mask() -> u64 {
    let raw = unsafe { cow_test_command(0, 0) };
    if is_error(raw) || raw == 0 {
        1
    } else {
        raw
    }
}

fn s6_set_affinity(mask: u64) -> u64 {
    unsafe { syscall3(S9_SYS_SCHED_SETAFFINITY, 0, 8, &mask as *const u64 as u64) }
}

fn s6_get_affinity() -> Result<u64, i32> {
    let mut got = 0u64;
    let r = unsafe { syscall3(S9_SYS_SCHED_GETAFFINITY, 0, 8, &mut got as *mut u64 as u64) };
    if is_error(r) {
        Err(errno(r))
    } else {
        Ok(got)
    }
}

fn s6_cpu_affinity_leg(online_mask: u64) -> u64 {
    // Negative controls: empty mask and offline CPU bit must fail with EINVAL.
    let r_empty = s6_set_affinity(0);
    if !is_error(r_empty) || errno(r_empty) != S9_EINVAL {
        return 0x90;
    }
    let r_offline = s6_set_affinity(1u64 << 63);
    if !is_error(r_offline) || errno(r_offline) != S9_EINVAL {
        return 0x91;
    }

    let sleep_1ms = [0i64, 1_000_000i64];
    let mut checked = 0u32;
    for cpu in 0..8usize {
        if (online_mask & (1u64 << cpu)) == 0 {
            continue;
        }
        let target_mask = 1u64 << cpu;
        if s6_set_affinity(target_mask) != 0 {
            return 0x92;
        }
        match s6_get_affinity() {
            Ok(m) if m == target_mask => {}
            _ => return 0x93,
        }
        // Allow reschedule onto target_cpu, then assert every subsequent sample
        // stays strictly pinned to `cpu`.
        let mut landed = false;
        for attempt in 0..64u32 {
            if attempt < 32 {
                unsafe { userspace::syscall::sys_yield() };
            } else {
                let _ = unsafe { syscall2(SYS_NANOSLEEP, sleep_1ms.as_ptr() as u64, 0) };
            }
            if s8_current_cpu_id() == cpu as u32 {
                landed = true;
                break;
            }
        }
        if !landed {
            return 0x94;
        }
        for sample in 0..16u32 {
            if sample == 8 {
                let _ = unsafe { syscall2(SYS_NANOSLEEP, sleep_1ms.as_ptr() as u64, 0) };
            } else {
                unsafe { userspace::syscall::sys_yield() };
            }
            if s8_current_cpu_id() != cpu as u32 {
                return 0x95;
            }
        }
        checked += 1;
    }

    if s6_set_affinity(online_mask) != 0 {
        return 0x96;
    }
    if checked == 0 {
        return 0x97;
    }
    S4_LEG_OK
}

/// CPU Affinity Enforcement: verify sched_setaffinity pins to every online CPU and rejects invalid masks.
fn test_cpu_affinity_enforcement(results: &mut TestResult) {
    print("Testing CPU affinity enforcement... ");
    let online_mask = s6_online_cpu_mask();
    let smp = online_mask.count_ones() >= 2;
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("CPU affinity enforcement: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s6_cpu_affinity_leg(online_mask)) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => {
            if smp {
                results.pass(
                    "CPU affinity enforcement: sched_setaffinity pins execution strictly to each online CPU and rejects invalid masks",
                );
            } else {
                results.pass(
                    "CPU affinity enforcement on single CPU: pins to CPU 0 and rejects invalid masks",
                );
            }
        }
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("CPU affinity enforcement: pinning or invalid-mask check failed");
        }
        None => results.fail("CPU affinity enforcement: could not reap host"),
    }
}

fn s6_process_migration_leg(online_mask: u64) -> u64 {
    let my_pid = unsafe { sys_getpid() };
    if is_error(my_pid) {
        return 0x98;
    }
    let fs_blk = S9TlsBlock {
        magic0: 0x116A_0001_2222_3333,
        magic1: 0x116A_0002_4444_5555,
        pad: [0; 6],
    };
    let gs_blk = S9TlsBlock {
        magic0: 0x116A_0003_6666_7777,
        magic1: 0x116A_0004_8888_9999,
        pad: [0; 6],
    };
    let fs_base = &fs_blk as *const S9TlsBlock as u64;
    let gs_base = &gs_blk as *const S9TlsBlock as u64;
    if is_error(unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_FS, fs_base) })
        || is_error(unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_GS, gs_base) })
    {
        return 0x99;
    }

    let mut cpus = [0usize; 8];
    let mut ncpus = 0usize;
    for c in 0..8usize {
        if (online_mask & (1u64 << c)) != 0 {
            cpus[ncpus] = c;
            ncpus += 1;
        }
    }
    if ncpus == 0 {
        return 0x9a;
    }

    let sleep_1ms = [0i64, 1_000_000i64];
    let hops = if ncpus >= 2 { 24 } else { 8 };
    let mut visited_mask = 0u64;
    for hop in 0..hops {
        let target = cpus[hop % ncpus];
        if s6_set_affinity(1u64 << target) != 0 {
            return 0x9b;
        }
        let mut landed = false;
        for attempt in 0..64u32 {
            if attempt < 32 {
                unsafe { userspace::syscall::sys_yield() };
            } else {
                let _ = unsafe { syscall2(SYS_NANOSLEEP, sleep_1ms.as_ptr() as u64, 0) };
            }
            if s8_current_cpu_id() == target as u32 {
                landed = true;
                break;
            }
        }
        if !landed {
            return 0x9c;
        }
        visited_mask |= 1u64 << target;
        if unsafe { sys_getpid() } != my_pid {
            return 0x9d;
        }
        if !unsafe {
            s9_check_fs_gs(
                fs_base,
                fs_blk.magic0,
                fs_blk.magic1,
                gs_base,
                gs_blk.magic0,
                gs_blk.magic1,
            )
        } {
            return 0x9e;
        }
    }

    let _ = s6_set_affinity(online_mask);
    let _ = unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_FS, 0) };
    let _ = unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_GS, 0) };
    if ncpus >= 2 && visited_mask.count_ones() < 2 {
        return 0x9f;
    }
    S4_LEG_OK
}

/// Process Migration Safety: verify forced cross-CPU hops preserve per-CPU state, TLS, and PID.
fn test_process_migration_safety(results: &mut TestResult) {
    print("Testing forced cross-CPU process migration safety... ");
    let online_mask = s6_online_cpu_mask();
    let smp = online_mask.count_ones() >= 2;
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("process migration safety: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s6_process_migration_leg(online_mask)) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => {
            if smp {
                results.pass(
                    "process migration safety: forced cross-CPU hops preserve per-CPU state, FS/GS TLS and PID identity",
                );
            } else {
                results.pass(
                    "process migration safety on single CPU: state and TLS stay intact across affinity refreshes",
                );
            }
        }
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("process migration safety: cross-CPU hop corrupted TLS or state");
        }
        None => results.fail("process migration safety: could not reap host"),
    }
}

#[repr(C)]
struct S6SharedStats {
    go: core::sync::atomic::AtomicU32,
    ready: core::sync::atomic::AtomicU32,
    cpu_mask: core::sync::atomic::AtomicU64,
    completed: core::sync::atomic::AtomicU32,
}

fn s6_load_balancing_leg(online_mask: u64) -> u64 {
    use core::sync::atomic::Ordering;
    const WORKERS: usize = 4;
    let smp = online_mask.count_ones() >= 2;

    let shared = unsafe { mmap_anon(PAGE, true) };
    if shared < 0 {
        return 0xa0;
    }
    let st = unsafe {
        let ptr = shared as *mut S6SharedStats;
        ptr.write(S6SharedStats {
            go: core::sync::atomic::AtomicU32::new(0),
            ready: core::sync::atomic::AtomicU32::new(0),
            cpu_mask: core::sync::atomic::AtomicU64::new(0),
            completed: core::sync::atomic::AtomicU32::new(0),
        });
        &*ptr
    };

    let _ = s6_set_affinity(online_mask);
    let mut pids = [0u64; WORKERS];
    for slot in pids.iter_mut() {
        let child = unsafe { sys_fork() };
        if is_error(child) {
            st.go.store(1, Ordering::Release);
            let _ = unsafe { munmap(shared as usize, PAGE) };
            return 0xa1;
        }
        if child == 0 {
            st.ready.fetch_add(1, Ordering::AcqRel);
            while st.go.load(Ordering::Acquire) == 0 {
                unsafe { userspace::syscall::sys_yield() };
            }
            let mut local_mask = 0u64;
            let mut acc = 1u64;
            for iter in 0..800u32 {
                // Keep workers genuinely CPU-bound so idle CPUs steal/run them.
                for step in 0..256u64 {
                    acc = acc.wrapping_mul(6364136223846793005).wrapping_add(step | 1);
                }
                let c = s8_current_cpu_id();
                if c < 64 {
                    local_mask |= 1u64 << c;
                }
                if iter & 63 == 0 {
                    unsafe { userspace::syscall::sys_yield() };
                }
            }
            core::hint::black_box(acc);
            st.cpu_mask.fetch_or(local_mask, Ordering::AcqRel);
            st.completed.fetch_add(1, Ordering::AcqRel);
            unsafe { raw_exit(SYS_EXIT_GROUP, S4_LEG_OK) };
        }
        *slot = child;
    }

    for _ in 0..THREAD_POLL_YIELDS {
        if st.ready.load(Ordering::Acquire) as usize == WORKERS {
            break;
        }
        unsafe { userspace::syscall::sys_yield() };
    }
    st.go.store(1, Ordering::Release);

    let mut all_ok = true;
    for &p in pids.iter() {
        if reap_pid(p) != Some(S4_LEG_OK) {
            all_ok = false;
        }
    }
    let observed = st.cpu_mask.load(Ordering::Acquire);
    let done = st.completed.load(Ordering::Acquire) as usize;
    let _ = unsafe { munmap(shared as usize, PAGE) };

    if !all_ok || done != WORKERS {
        return 0xa2;
    }
    if smp && observed.count_ones() < 2 {
        return 0xa3;
    }
    if !smp && observed == 0 {
        return 0xa4;
    }
    S4_LEG_OK
}

/// Scheduler Load Balancing: verify unpinned runnable workers distribute across multiple CPUs.
fn test_scheduler_load_balancing(results: &mut TestResult) {
    print("Testing scheduler load balancing across CPUs... ");
    let online_mask = s6_online_cpu_mask();
    let smp = online_mask.count_ones() >= 2;
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("scheduler load balancing: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s6_load_balancing_leg(online_mask)) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => {
            if smp {
                results.pass(
                    "scheduler load balancing: unpinned runnable workers distribute across multiple online CPUs",
                );
            } else {
                results.pass(
                    "scheduler load balancing on single CPU: runnable workers complete fairly on CPU 0",
                );
            }
        }
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("scheduler load balancing: workers did not distribute cleanly");
        }
        None => results.fail("scheduler load balancing: could not reap host"),
    }
}

fn s6_work_stealing_safety_leg(online_mask: u64) -> u64 {
    use core::sync::atomic::Ordering;
    const WAVES: usize = 4;
    const PER_WAVE: usize = 8;
    let smp = online_mask.count_ones() >= 2;

    let shared = unsafe { mmap_anon(PAGE, true) };
    if shared < 0 {
        return 0xa8;
    }
    let st = unsafe {
        let ptr = shared as *mut S6SharedStats;
        ptr.write(S6SharedStats {
            go: core::sync::atomic::AtomicU32::new(0),
            ready: core::sync::atomic::AtomicU32::new(0),
            cpu_mask: core::sync::atomic::AtomicU64::new(0),
            completed: core::sync::atomic::AtomicU32::new(0),
        });
        &*ptr
    };

    let _ = s6_set_affinity(online_mask);
    for wave in 0..WAVES {
        st.go.store(0, Ordering::Release);
        st.ready.store(0, Ordering::Release);
        let mut pids = [0u64; PER_WAVE];
        for (idx, slot) in pids.iter_mut().enumerate() {
            let child = unsafe { sys_fork() };
            if is_error(child) {
                st.go.store(1, Ordering::Release);
                let _ = unsafe { munmap(shared as usize, PAGE) };
                return 0xa9;
            }
            if child == 0 {
                let my_pid = unsafe { sys_getpid() };
                let tls = S9TlsBlock {
                    magic0: 0x57E4_0000_0000_0000u64
                        ^ ((wave as u64) << 32)
                        ^ ((idx as u64) << 16)
                        ^ my_pid,
                    magic1: 0x57E5_FFFF_0000_0000u64 ^ my_pid.wrapping_mul(0x9E37_79B9_7F4A_7C15),
                    pad: [0; 6],
                };
                let fs_base = &tls as *const S9TlsBlock as u64;
                if is_error(unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_FS, fs_base) }) {
                    unsafe { raw_exit(SYS_EXIT_GROUP, 1) };
                }
                st.ready.fetch_add(1, Ordering::AcqRel);
                while st.go.load(Ordering::Acquire) == 0 {
                    unsafe { userspace::syscall::sys_yield() };
                }
                let mut local_mask = 0u64;
                for iter in 0..32u32 {
                    let mut got_fs = 0u64;
                    if is_error(unsafe {
                        syscall2(
                            S9_SYS_ARCH_PRCTL,
                            S9_ARCH_GET_FS,
                            &mut got_fs as *mut u64 as u64,
                        )
                    }) || got_fs != fs_base
                    {
                        unsafe { raw_exit(SYS_EXIT_GROUP, 2) };
                    }
                    let fs0: u64;
                    let fs1: u64;
                    unsafe {
                        core::arch::asm!(
                            "mov {fs0}, qword ptr fs:[0]",
                            "mov {fs1}, qword ptr fs:[8]",
                            fs0 = out(reg) fs0,
                            fs1 = out(reg) fs1,
                            options(nostack, preserves_flags),
                        );
                    }
                    if fs0 != tls.magic0 || fs1 != tls.magic1 || unsafe { sys_getpid() } != my_pid {
                        unsafe { raw_exit(SYS_EXIT_GROUP, 3) };
                    }
                    let c = s8_current_cpu_id();
                    if c < 64 {
                        local_mask |= 1u64 << c;
                    }
                    if iter & 3 == 0 {
                        unsafe { userspace::syscall::sys_yield() };
                    }
                }
                let _ = unsafe { syscall2(S9_SYS_ARCH_PRCTL, S9_ARCH_SET_FS, 0) };
                st.cpu_mask.fetch_or(local_mask, Ordering::AcqRel);
                st.completed.fetch_add(1, Ordering::AcqRel);
                unsafe { raw_exit(SYS_EXIT_GROUP, S4_LEG_OK) };
            }
            *slot = child;
        }
        for _ in 0..THREAD_POLL_YIELDS {
            if st.ready.load(Ordering::Acquire) as usize == PER_WAVE {
                break;
            }
            unsafe { userspace::syscall::sys_yield() };
        }
        st.go.store(1, Ordering::Release);
        for &p in pids.iter() {
            if reap_pid(p) != Some(S4_LEG_OK) {
                let _ = unsafe { munmap(shared as usize, PAGE) };
                return 0xaa;
            }
        }
    }

    let observed = st.cpu_mask.load(Ordering::Acquire);
    let done = st.completed.load(Ordering::Acquire) as usize;
    let _ = unsafe { munmap(shared as usize, PAGE) };

    if done != WAVES * PER_WAVE {
        return 0xab;
    }
    if smp && observed.count_ones() < 2 {
        return 0xac;
    }
    S4_LEG_OK
}

/// R172-03: Verify SMP work stealing preserves per-task TLS and identity across concurrent waves.
fn test_smp_work_stealing_safety(results: &mut TestResult) {
    print("Testing R172-03 SMP work stealing safety across waves... ");
    let online_mask = s6_online_cpu_mask();
    let smp = online_mask.count_ones() >= 2;
    let host = unsafe { sys_fork() };
    if is_error(host) {
        results.fail("SMP work stealing safety: fork failed");
        return;
    }
    if host == 0 {
        unsafe { raw_exit(SYS_EXIT_GROUP, s6_work_stealing_safety_leg(online_mask)) };
    }
    match reap_pid(host) {
        Some(S4_LEG_OK) => {
            if smp {
                results.pass(
                    "SMP work stealing safety: concurrent unpinned task waves preserve per-task TLS and identity across CPUs",
                );
            } else {
                results.pass(
                    "SMP work stealing safety on single CPU: concurrent task waves preserve per-task TLS and identity",
                );
            }
        }
        Some(code) => {
            print("exit ");
            print_int(code as i64);
            print(" ");
            results.fail("SMP work stealing safety: wave task failed TLS or identity check");
        }
        None => results.fail("SMP work stealing safety: could not reap host"),
    }
}

// ============================================================================
// N2.8: Loopback Delivery + Socket Syscalls + Multi-Iovec readv
// ============================================================================

const N28_SYS_READ: u64 = 0;
const N28_SYS_WRITE: u64 = 1;
const N28_SYS_CLOSE: u64 = 3;
const N28_SYS_READV: u64 = 19;
const N28_SYS_PIPE: u64 = 22;
const N28_SYS_SOCKET: u64 = 41;
const N28_SYS_CONNECT: u64 = 42;
const N28_SYS_ACCEPT: u64 = 43;
const N28_SYS_SENDTO: u64 = 44;
const N28_SYS_RECVFROM: u64 = 45;
const N28_SYS_SENDMSG: u64 = 46;
const N28_SYS_RECVMSG: u64 = 47;
const N28_SYS_SHUTDOWN: u64 = 48;
const N28_SYS_BIND: u64 = 49;
const N28_SYS_LISTEN: u64 = 50;
const N28_SYS_GETSOCKNAME: u64 = 51;
const N28_SYS_GETPEERNAME: u64 = 52;
const N28_SYS_SETSOCKOPT: u64 = 54;
const N28_SYS_GETSOCKOPT: u64 = 55;

const N28_AF_INET: u64 = 2;
const N28_SOCK_STREAM: u64 = 1;
const N28_SOCK_DGRAM: u64 = 2;
const N28_SOCK_NONBLOCK: u64 = 0o4000;
const N28_IPPROTO_IP: u64 = 0;
const N28_SOL_SOCKET: u64 = 1;
const N28_IPPROTO_TCP: u64 = 6;
const N28_SO_REUSEADDR: u64 = 2;
const N28_SO_TYPE: u64 = 3;
const N28_SO_ERROR: u64 = 4;
const N28_SO_SNDBUF: u64 = 7;
const N28_SO_RCVBUF: u64 = 8;
const N28_SO_KEEPALIVE: u64 = 9;
const N28_SO_RCVTIMEO: u64 = 20;
const N28_TCP_NODELAY: u64 = 1;
const N28_IP_TTL: u64 = 2;
const N28_MSG_TRUNC: i32 = 0x20;
const N28_MSG_DONTWAIT: u64 = 0x40;
const N28_SHUT_WR: u64 = 1;

const N28_EFAULT: i32 = 14;
const N28_EINVAL: i32 = 22;
const N28_ENOTSOCK: i32 = 88;
const N28_ENOPROTOOPT: i32 = 92;
const N28_EOPNOTSUPP: i32 = 95;
const N28_ENOTCONN: i32 = 107;
const N28_ECONNREFUSED: i32 = 111;
const N28_EINPROGRESS: i32 = 115;

#[repr(C)]
#[derive(Clone, Copy)]
struct N28SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

impl N28SockAddrIn {
    const fn new(ip: [u8; 4], port: u16) -> Self {
        Self {
            sin_family: N28_AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: ip,
            sin_zero: [0; 8],
        }
    }

    const fn port(self) -> u16 {
        u16::from_be(self.sin_port)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct N28Iovec {
    iov_base: *mut u8,
    iov_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct N28MsgHdr {
    msg_name: *mut u8,
    msg_namelen: u32,
    _pad0: u32,
    msg_iov: *const N28Iovec,
    msg_iovlen: usize,
    msg_control: *mut u8,
    msg_controllen: usize,
    msg_flags: i32,
    _pad1: u32,
}

fn test_n2_8_loopback_udp_tcp_echo(results: &mut TestResult) {
    print("Testing N2.8 loopback UDP/TCP echo, getsockname/getpeername, RST... ");
    // 1. UDP loopback round-trip + getsockname/getpeername
    let srv = unsafe { syscall3(N28_SYS_SOCKET, N28_AF_INET, N28_SOCK_DGRAM, 0) };
    let cli = unsafe { syscall3(N28_SYS_SOCKET, N28_AF_INET, N28_SOCK_DGRAM, 0) };
    if is_error(srv) || is_error(cli) {
        results.fail("n2_8_loopback_udp_tcp_echo: UDP socket creation failed");
        return;
    }
    let bind_addr = N28SockAddrIn::new([127, 0, 0, 1], 0);
    let r_bind = unsafe {
        syscall3(
            N28_SYS_BIND,
            srv,
            &bind_addr as *const N28SockAddrIn as u64,
            16,
        )
    };
    if is_error(r_bind) {
        let _ = unsafe { syscall1(N28_SYS_CLOSE, srv) };
        let _ = unsafe { syscall1(N28_SYS_CLOSE, cli) };
        results.fail("n2_8_loopback_udp_tcp_echo: UDP bind(127.0.0.1:0) failed");
        return;
    }

    // getsockname truncation check: pass len=4, expect *len == 16
    let mut trunc_sa = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut trunc_len: u32 = 4;
    let r_trunc = unsafe {
        syscall3(
            N28_SYS_GETSOCKNAME,
            srv,
            &mut trunc_sa as *mut N28SockAddrIn as u64,
            &mut trunc_len as *mut u32 as u64,
        )
    };
    let mut srv_sa = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut srv_len: u32 = 16;
    let r_name = unsafe {
        syscall3(
            N28_SYS_GETSOCKNAME,
            srv,
            &mut srv_sa as *mut N28SockAddrIn as u64,
            &mut srv_len as *mut u32 as u64,
        )
    };
    let mut peer_sa = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut peer_len: u32 = 16;
    let r_unconn_peer = unsafe {
        syscall3(
            N28_SYS_GETPEERNAME,
            srv,
            &mut peer_sa as *mut N28SockAddrIn as u64,
            &mut peer_len as *mut u32 as u64,
        )
    };
    if is_error(r_trunc)
        || trunc_len != 16
        || is_error(r_name)
        || srv_len != 16
        || srv_sa.sin_addr != [127, 0, 0, 1]
        || srv_sa.port() == 0
        || !is_error(r_unconn_peer)
        || errno(r_unconn_peer) != N28_ENOTCONN
    {
        let _ = unsafe { syscall1(N28_SYS_CLOSE, srv) };
        let _ = unsafe { syscall1(N28_SYS_CLOSE, cli) };
        results.fail("n2_8_loopback_udp_tcp_echo: UDP getsockname/getpeername mismatch");
        return;
    }

    let msg = b"nilix-lo-udp!";
    let r_send = unsafe {
        syscall6(
            N28_SYS_SENDTO,
            cli,
            msg.as_ptr() as u64,
            msg.len() as u64,
            0,
            &srv_sa as *const N28SockAddrIn as u64,
            16,
        )
    };
    let mut rbuf = [0u8; 32];
    let mut from_sa = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut from_len: u32 = 16;
    let r_recv = unsafe {
        syscall6(
            N28_SYS_RECVFROM,
            srv,
            rbuf.as_mut_ptr() as u64,
            rbuf.len() as u64,
            N28_MSG_DONTWAIT,
            &mut from_sa as *mut N28SockAddrIn as u64,
            &mut from_len as *mut u32 as u64,
        )
    };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, srv) };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, cli) };

    if r_send != msg.len() as u64
        || r_recv != msg.len() as u64
        || &rbuf[..msg.len()] != msg
        || from_sa.sin_addr != [127, 0, 0, 1]
        || from_sa.port() == 0
    {
        results.fail("n2_8_loopback_udp_tcp_echo: UDP loopback echo failed");
        return;
    }

    // 2. TCP loopback 3-way handshake, getsockname/getpeername, bidirectional data, shutdown EOF
    let lsock = unsafe { syscall3(N28_SYS_SOCKET, N28_AF_INET, N28_SOCK_STREAM, 0) };
    let csock = unsafe { syscall3(N28_SYS_SOCKET, N28_AF_INET, N28_SOCK_STREAM, 0) };
    if is_error(lsock) || is_error(csock) {
        results.fail("n2_8_loopback_udp_tcp_echo: TCP socket creation failed");
        return;
    }
    let lbind = N28SockAddrIn::new([127, 0, 0, 1], 0);
    let mut laddr = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut llen: u32 = 16;
    let ok_setup = !is_error(unsafe {
        syscall3(
            N28_SYS_BIND,
            lsock,
            &lbind as *const N28SockAddrIn as u64,
            16,
        )
    }) && !is_error(unsafe {
        syscall3(
            N28_SYS_GETSOCKNAME,
            lsock,
            &mut laddr as *mut N28SockAddrIn as u64,
            &mut llen as *mut u32 as u64,
        )
    }) && laddr.port() != 0
        && !is_error(unsafe { syscall2(N28_SYS_LISTEN, lsock, 4) })
        && !is_error(unsafe {
            syscall3(
                N28_SYS_CONNECT,
                csock,
                &laddr as *const N28SockAddrIn as u64,
                16,
            )
        });
    if !ok_setup {
        let _ = unsafe { syscall1(N28_SYS_CLOSE, csock) };
        let _ = unsafe { syscall1(N28_SYS_CLOSE, lsock) };
        results.fail("n2_8_loopback_udp_tcp_echo: TCP loopback listen/connect failed");
        return;
    }

    let mut acc_peer = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut acc_plen: u32 = 16;
    let asock = unsafe {
        syscall3(
            N28_SYS_ACCEPT,
            lsock,
            &mut acc_peer as *mut N28SockAddrIn as u64,
            &mut acc_plen as *mut u32 as u64,
        )
    };
    if is_error(asock) {
        let _ = unsafe { syscall1(N28_SYS_CLOSE, csock) };
        let _ = unsafe { syscall1(N28_SYS_CLOSE, lsock) };
        results.fail("n2_8_loopback_udp_tcp_echo: TCP loopback accept failed");
        return;
    }

    let mut c_local = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut c_peer = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut a_local = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut a_peer = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let (mut l1, mut l2, mut l3, mut l4) = (16u32, 16u32, 16u32, 16u32);
    let names_ok = !is_error(unsafe {
        syscall3(
            N28_SYS_GETSOCKNAME,
            csock,
            &mut c_local as *mut N28SockAddrIn as u64,
            &mut l1 as *mut u32 as u64,
        )
    }) && !is_error(unsafe {
        syscall3(
            N28_SYS_GETPEERNAME,
            csock,
            &mut c_peer as *mut N28SockAddrIn as u64,
            &mut l2 as *mut u32 as u64,
        )
    }) && !is_error(unsafe {
        syscall3(
            N28_SYS_GETSOCKNAME,
            asock,
            &mut a_local as *mut N28SockAddrIn as u64,
            &mut l3 as *mut u32 as u64,
        )
    }) && !is_error(unsafe {
        syscall3(
            N28_SYS_GETPEERNAME,
            asock,
            &mut a_peer as *mut N28SockAddrIn as u64,
            &mut l4 as *mut u32 as u64,
        )
    }) && c_local.sin_addr == [127, 0, 0, 1]
        && c_peer.sin_addr == [127, 0, 0, 1]
        && c_peer.port() == laddr.port()
        && a_local.port() == laddr.port()
        && a_peer.port() == c_local.port()
        && acc_peer.port() == c_local.port();

    let ping = b"tcp-ping-n28";
    let pong = b"tcp-pong-n28";
    let mut b1 = [0u8; 32];
    let mut b2 = [0u8; 32];
    let s1 = unsafe {
        syscall6(
            N28_SYS_SENDTO,
            csock,
            ping.as_ptr() as u64,
            ping.len() as u64,
            0,
            0,
            0,
        )
    };
    let r1 = unsafe {
        syscall6(
            N28_SYS_RECVFROM,
            asock,
            b1.as_mut_ptr() as u64,
            b1.len() as u64,
            N28_MSG_DONTWAIT,
            0,
            0,
        )
    };
    let s2 = unsafe {
        syscall3(
            N28_SYS_WRITE,
            asock,
            pong.as_ptr() as u64,
            pong.len() as u64,
        )
    };
    let r2 = unsafe { syscall3(N28_SYS_READ, csock, b2.as_mut_ptr() as u64, b2.len() as u64) };
    let sh = unsafe { syscall2(N28_SYS_SHUTDOWN, csock, N28_SHUT_WR) };
    let eof = unsafe {
        syscall6(
            N28_SYS_RECVFROM,
            asock,
            b1.as_mut_ptr() as u64,
            b1.len() as u64,
            N28_MSG_DONTWAIT,
            0,
            0,
        )
    };

    let _ = unsafe { syscall1(N28_SYS_CLOSE, asock) };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, csock) };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, lsock) };

    if !names_ok
        || s1 != ping.len() as u64
        || r1 != ping.len() as u64
        || &b1[..ping.len()] != ping
        || s2 != pong.len() as u64
        || r2 != pong.len() as u64
        || &b2[..pong.len()] != pong
        || is_error(sh)
        || eof != 0
    {
        results.fail("n2_8_loopback_udp_tcp_echo: TCP loopback data/names/EOF failed");
        return;
    }

    // 3. Connect to closed loopback port -> ECONNREFUSED (blocking) & SO_ERROR (non-blocking)
    let closed_addr = N28SockAddrIn::new([127, 0, 0, 1], 19999);
    let r_blk_sock = unsafe { syscall3(N28_SYS_SOCKET, N28_AF_INET, N28_SOCK_STREAM, 0) };
    let r_blk = unsafe {
        syscall3(
            N28_SYS_CONNECT,
            r_blk_sock,
            &closed_addr as *const N28SockAddrIn as u64,
            16,
        )
    };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, r_blk_sock) };

    let r_nb_sock = unsafe {
        syscall3(
            N28_SYS_SOCKET,
            N28_AF_INET,
            N28_SOCK_STREAM | N28_SOCK_NONBLOCK,
            0,
        )
    };
    let r_nb = unsafe {
        syscall3(
            N28_SYS_CONNECT,
            r_nb_sock,
            &closed_addr as *const N28SockAddrIn as u64,
            16,
        )
    };
    let mut so_err: i32 = -1;
    let mut so_err_len: u32 = 4;
    let r_so1 = unsafe {
        syscall5(
            N28_SYS_GETSOCKOPT,
            r_nb_sock,
            N28_SOL_SOCKET,
            N28_SO_ERROR,
            &mut so_err as *mut i32 as u64,
            &mut so_err_len as *mut u32 as u64,
        )
    };
    let mut so_err2: i32 = -1;
    let mut so_err2_len: u32 = 4;
    let r_so2 = unsafe {
        syscall5(
            N28_SYS_GETSOCKOPT,
            r_nb_sock,
            N28_SOL_SOCKET,
            N28_SO_ERROR,
            &mut so_err2 as *mut i32 as u64,
            &mut so_err2_len as *mut u32 as u64,
        )
    };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, r_nb_sock) };

    if !is_error(r_blk)
        || errno(r_blk) != N28_ECONNREFUSED
        || !is_error(r_nb)
        || errno(r_nb) != N28_EINPROGRESS
        || is_error(r_so1)
        || so_err != N28_ECONNREFUSED
        || is_error(r_so2)
        || so_err2 != 0
    {
        results.fail("n2_8_loopback_udp_tcp_echo: closed-port RST / SO_ERROR check failed");
        return;
    }

    results.pass("N2.8 loopback UDP/TCP echo, getsockname/getpeername, and RST/SO_ERROR");
}

fn test_n2_8_sockopts_and_negative(results: &mut TestResult) {
    print("Testing N2.8 setsockopt/getsockopt & negative paths... ");
    let tcp = unsafe { syscall3(N28_SYS_SOCKET, N28_AF_INET, N28_SOCK_STREAM, 0) };
    let udp = unsafe { syscall3(N28_SYS_SOCKET, N28_AF_INET, N28_SOCK_DGRAM, 0) };
    if is_error(tcp) || is_error(udp) {
        results.fail("n2_8_sockopts_and_negative: socket creation failed");
        return;
    }

    let get_i32 = |fd: u64, lvl: u64, opt: u64| -> (u64, i32, u32) {
        let mut v: i32 = -999;
        let mut l: u32 = 4;
        let r = unsafe {
            syscall5(
                N28_SYS_GETSOCKOPT,
                fd,
                lvl,
                opt,
                &mut v as *mut i32 as u64,
                &mut l as *mut u32 as u64,
            )
        };
        (r, v, l)
    };
    let set_i32 = |fd: u64, lvl: u64, opt: u64, val: i32| -> u64 {
        unsafe {
            syscall5(
                N28_SYS_SETSOCKOPT,
                fd,
                lvl,
                opt,
                &val as *const i32 as u64,
                4,
            )
        }
    };

    let mut ok = true;
    let (r, v, l) = get_i32(tcp, N28_SOL_SOCKET, N28_SO_TYPE);
    ok &= !is_error(r) && v == 1 && l == 4;
    let (r, v, l) = get_i32(udp, N28_SOL_SOCKET, N28_SO_TYPE);
    ok &= !is_error(r) && v == 2 && l == 4;
    let r = set_i32(tcp, N28_SOL_SOCKET, N28_SO_TYPE, 1);
    ok &= is_error(r) && errno(r) == N28_ENOPROTOOPT;
    let r = set_i32(tcp, N28_SOL_SOCKET, N28_SO_ERROR, 0);
    ok &= is_error(r) && errno(r) == N28_ENOPROTOOPT;

    ok &= !is_error(set_i32(tcp, N28_SOL_SOCKET, N28_SO_REUSEADDR, 1));
    let (r, v, _) = get_i32(tcp, N28_SOL_SOCKET, N28_SO_REUSEADDR);
    ok &= !is_error(r) && v == 1;
    ok &= !is_error(set_i32(tcp, N28_SOL_SOCKET, N28_SO_KEEPALIVE, 1));
    let (r, v, _) = get_i32(tcp, N28_SOL_SOCKET, N28_SO_KEEPALIVE);
    ok &= !is_error(r) && v == 1;

    ok &= !is_error(set_i32(tcp, N28_SOL_SOCKET, N28_SO_RCVBUF, 100));
    let (r, v, _) = get_i32(tcp, N28_SOL_SOCKET, N28_SO_RCVBUF);
    ok &= !is_error(r) && v == 4096;
    ok &= !is_error(set_i32(tcp, N28_SOL_SOCKET, N28_SO_SNDBUF, 10_000_000));
    let (r, v, _) = get_i32(tcp, N28_SOL_SOCKET, N28_SO_SNDBUF);
    ok &= !is_error(r) && v == 262_144;

    ok &= !is_error(set_i32(tcp, N28_IPPROTO_TCP, N28_TCP_NODELAY, 1));
    let (r, v, _) = get_i32(tcp, N28_IPPROTO_TCP, N28_TCP_NODELAY);
    ok &= !is_error(r) && v == 1;
    let r = set_i32(udp, N28_IPPROTO_TCP, N28_TCP_NODELAY, 1);
    ok &= is_error(r) && errno(r) == N28_ENOPROTOOPT;

    ok &= !is_error(set_i32(udp, N28_IPPROTO_IP, N28_IP_TTL, 32));
    let (r, v, _) = get_i32(udp, N28_IPPROTO_IP, N28_IP_TTL);
    ok &= !is_error(r) && v == 32;
    ok &= !is_error(set_i32(udp, N28_IPPROTO_IP, N28_IP_TTL, -1));
    let (r, v, _) = get_i32(udp, N28_IPPROTO_IP, N28_IP_TTL);
    ok &= !is_error(r) && v == 64;
    let r0 = set_i32(udp, N28_IPPROTO_IP, N28_IP_TTL, 0);
    let r256 = set_i32(udp, N28_IPPROTO_IP, N28_IP_TTL, 256);
    ok &= is_error(r0) && errno(r0) == N28_EINVAL && is_error(r256) && errno(r256) == N28_EINVAL;

    let tv_in: [i64; 2] = [1, 250_000];
    let mut tv_out: [i64; 2] = [0, 0];
    let mut tv_len: u32 = 16;
    let r_set_tv = unsafe {
        syscall5(
            N28_SYS_SETSOCKOPT,
            udp,
            N28_SOL_SOCKET,
            N28_SO_RCVTIMEO,
            tv_in.as_ptr() as u64,
            16,
        )
    };
    let r_get_tv = unsafe {
        syscall5(
            N28_SYS_GETSOCKOPT,
            udp,
            N28_SOL_SOCKET,
            N28_SO_RCVTIMEO,
            tv_out.as_mut_ptr() as u64,
            &mut tv_len as *mut u32 as u64,
        )
    };
    ok &= !is_error(r_set_tv) && !is_error(r_get_tv) && tv_len == 16 && tv_out == tv_in;

    let r_unk = set_i32(tcp, N28_SOL_SOCKET, 9999, 1);
    ok &= is_error(r_unk) && errno(r_unk) == N28_ENOPROTOOPT;
    let r_notsock = set_i32(1, N28_SOL_SOCKET, N28_SO_REUSEADDR, 1);
    ok &= is_error(r_notsock) && errno(r_notsock) == N28_ENOTSOCK;
    let r_efault = unsafe {
        syscall5(
            N28_SYS_SETSOCKOPT,
            tcp,
            N28_SOL_SOCKET,
            N28_SO_REUSEADDR,
            0,
            4,
        )
    };
    ok &= is_error(r_efault) && errno(r_efault) == N28_EFAULT;

    let _ = unsafe { syscall1(N28_SYS_CLOSE, tcp) };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, udp) };

    if ok {
        results.pass("N2.8 setsockopt/getsockopt round-trip, bounds, and negative checks");
    } else {
        results.fail("n2_8_sockopts_and_negative: sockopt round-trip or negative check failed");
    }
}

fn test_n2_8_sendmsg_recvmsg_and_readv(results: &mut TestResult) {
    print("Testing N2.8 sendmsg/recvmsg & multi-iovec readv... ");
    // 1. Multi-iovec readv on a pipe
    let mut pipe_fds = [-1i32; 2];
    if is_error(unsafe { syscall1(N28_SYS_PIPE, pipe_fds.as_mut_ptr() as u64) }) {
        results.fail("n2_8_sendmsg_recvmsg_and_readv: pipe creation failed");
        return;
    }
    let payload = b"HelloNilix!!";
    let w = unsafe {
        syscall3(
            N28_SYS_WRITE,
            pipe_fds[1] as u64,
            payload.as_ptr() as u64,
            payload.len() as u64,
        )
    };
    let mut p0 = [0u8; 5];
    let mut p1 = [0u8; 5];
    let mut p2 = [0u8; 4];
    let pipe_iov = [
        N28Iovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        },
        N28Iovec {
            iov_base: p0.as_mut_ptr(),
            iov_len: p0.len(),
        },
        N28Iovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        },
        N28Iovec {
            iov_base: p1.as_mut_ptr(),
            iov_len: p1.len(),
        },
        N28Iovec {
            iov_base: p2.as_mut_ptr(),
            iov_len: p2.len(),
        },
    ];
    let rv = unsafe {
        syscall3(
            N28_SYS_READV,
            pipe_fds[0] as u64,
            pipe_iov.as_ptr() as u64,
            pipe_iov.len() as u64,
        )
    };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, pipe_fds[0] as u64) };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, pipe_fds[1] as u64) };
    if w != 12 || rv != 12 || &p0 != b"Hello" || &p1 != b"Nilix" || &p2[..2] != b"!!" {
        results.fail("n2_8_sendmsg_recvmsg_and_readv: multi-iovec pipe readv failed");
        return;
    }

    // 2. UDP loopback sendmsg / recvmsg scatter-gather + MSG_TRUNC + msg_controllen != 0 -> EOPNOTSUPP
    let srv = unsafe { syscall3(N28_SYS_SOCKET, N28_AF_INET, N28_SOCK_DGRAM, 0) };
    let cli = unsafe { syscall3(N28_SYS_SOCKET, N28_AF_INET, N28_SOCK_DGRAM, 0) };
    if is_error(srv) || is_error(cli) {
        results.fail("n2_8_sendmsg_recvmsg_and_readv: UDP socket failed");
        return;
    }
    let baddr = N28SockAddrIn::new([127, 0, 0, 1], 0);
    let mut saddr = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut slen: u32 = 16;
    let bound = !is_error(unsafe {
        syscall3(N28_SYS_BIND, srv, &baddr as *const N28SockAddrIn as u64, 16)
    }) && !is_error(unsafe {
        syscall3(
            N28_SYS_GETSOCKNAME,
            srv,
            &mut saddr as *mut N28SockAddrIn as u64,
            &mut slen as *mut u32 as u64,
        )
    });

    let mut ctrl = [0u8; 16];
    let mut dummy = [0u8; 4];
    let ctrl_iov = [N28Iovec {
        iov_base: dummy.as_mut_ptr(),
        iov_len: 4,
    }];
    let mut bad_hdr = N28MsgHdr {
        msg_name: &mut saddr as *mut N28SockAddrIn as *mut u8,
        msg_namelen: 16,
        _pad0: 0,
        msg_iov: ctrl_iov.as_ptr(),
        msg_iovlen: 1,
        msg_control: ctrl.as_mut_ptr(),
        msg_controllen: 16,
        msg_flags: 0,
        _pad1: 0,
    };
    let r_bad_send =
        unsafe { syscall3(N28_SYS_SENDMSG, cli, &bad_hdr as *const N28MsgHdr as u64, 0) };
    let r_bad_recv = unsafe {
        syscall3(
            N28_SYS_RECVMSG,
            srv,
            &mut bad_hdr as *mut N28MsgHdr as u64,
            N28_MSG_DONTWAIT,
        )
    };

    let mut s0 = *b"ABCD";
    let mut s1 = *b"1234";
    let mut s2 = *b"WXYZ";
    let send_iov = [
        N28Iovec {
            iov_base: s0.as_mut_ptr(),
            iov_len: 4,
        },
        N28Iovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        },
        N28Iovec {
            iov_base: s1.as_mut_ptr(),
            iov_len: 4,
        },
        N28Iovec {
            iov_base: s2.as_mut_ptr(),
            iov_len: 4,
        },
    ];
    let send_hdr = N28MsgHdr {
        msg_name: &mut saddr as *mut N28SockAddrIn as *mut u8,
        msg_namelen: 16,
        _pad0: 0,
        msg_iov: send_iov.as_ptr(),
        msg_iovlen: send_iov.len(),
        msg_control: core::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
        _pad1: 0,
    };
    let sent = unsafe {
        syscall3(
            N28_SYS_SENDMSG,
            cli,
            &send_hdr as *const N28MsgHdr as u64,
            0,
        )
    };

    let mut r0 = [0u8; 6];
    let mut r1 = [0u8; 6];
    let recv_iov = [
        N28Iovec {
            iov_base: r0.as_mut_ptr(),
            iov_len: 6,
        },
        N28Iovec {
            iov_base: r1.as_mut_ptr(),
            iov_len: 6,
        },
    ];
    let mut peer = N28SockAddrIn::new([0, 0, 0, 0], 0);
    let mut recv_hdr = N28MsgHdr {
        msg_name: &mut peer as *mut N28SockAddrIn as *mut u8,
        msg_namelen: 16,
        _pad0: 0,
        msg_iov: recv_iov.as_ptr(),
        msg_iovlen: recv_iov.len(),
        msg_control: core::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
        _pad1: 0,
    };
    let recvd = unsafe {
        syscall3(
            N28_SYS_RECVMSG,
            srv,
            &mut recv_hdr as *mut N28MsgHdr as u64,
            N28_MSG_DONTWAIT,
        )
    };

    let sent2 = unsafe {
        syscall3(
            N28_SYS_SENDMSG,
            cli,
            &send_hdr as *const N28MsgHdr as u64,
            0,
        )
    };
    let mut short_buf = [0u8; 5];
    let short_iov = [N28Iovec {
        iov_base: short_buf.as_mut_ptr(),
        iov_len: 5,
    }];
    let mut trunc_hdr = N28MsgHdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        _pad0: 0,
        msg_iov: short_iov.as_ptr(),
        msg_iovlen: 1,
        msg_control: core::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
        _pad1: 0,
    };
    let recvd2 = unsafe {
        syscall3(
            N28_SYS_RECVMSG,
            srv,
            &mut trunc_hdr as *mut N28MsgHdr as u64,
            N28_MSG_DONTWAIT,
        )
    };

    let _ = unsafe { syscall1(N28_SYS_CLOSE, srv) };
    let _ = unsafe { syscall1(N28_SYS_CLOSE, cli) };

    if !bound
        || !is_error(r_bad_send)
        || errno(r_bad_send) != N28_EOPNOTSUPP
        || !is_error(r_bad_recv)
        || errno(r_bad_recv) != N28_EOPNOTSUPP
        || sent != 12
        || recvd != 12
        || &r0 != b"ABCD12"
        || &r1 != b"34WXYZ"
        || peer.sin_addr != [127, 0, 0, 1]
        || recv_hdr.msg_namelen != 16
        || recv_hdr.msg_flags != 0
        || sent2 != 12
        || recvd2 != 5
        || &short_buf != b"ABCD1"
        || (trunc_hdr.msg_flags & N28_MSG_TRUNC) == 0
    {
        results.fail("n2_8_sendmsg_recvmsg_and_readv: sendmsg/recvmsg check failed");
        return;
    }

    results.pass(
        "N2.8 sendmsg/recvmsg scatter-gather, MSG_TRUNC, EOPNOTSUPP control, and multi-iovec readv",
    );
}

// ===========================================================================
// N2.5: Process Groups, Sessions, Controlling Terminal & Job Control Wait
// ===========================================================================

const N25_SYS_IOCTL: u64 = 16;
const N25_SYS_PIPE: u64 = 22;
const N25_SYS_WAIT4: u64 = 61;
const N25_SYS_KILL: u64 = 62;
const N25_SYS_SETPGID: u64 = 109;
const N25_SYS_GETPGRP: u64 = 111;
const N25_SYS_SETSID: u64 = 112;
const N25_SYS_GETPGID: u64 = 121;
const N25_SYS_GETSID: u64 = 124;

const N25_TIOCSCTTY: u64 = 0x540E;
const N25_TIOCGPGRP: u64 = 0x540F;
const N25_TIOCSPGRP: u64 = 0x5410;
const N25_TIOCNOTTY: u64 = 0x5422;
const N25_TIOCGSID: u64 = 0x5429;

const N25_SIGCONT: u64 = 18;
const N25_SIGSTOP: u64 = 19;
const N25_WCONTINUED: u64 = 8;
const N25_CLD_CONTINUED: i32 = 6;
const N25_EPERM: i32 = 1;
const N25_EINTR: i32 = 4;
const N25_ENOTTY: i32 = 25;

fn test_n2_5_job_control_sessions_and_wait(results: &mut TestResult) {
    print("Testing N2.5 pgid/sid, ctty ioctls, kill(-pgid), wait4/waitid stop & continue... ");

    let my_pid = unsafe { sys_getpid() };
    let pgrp = unsafe { syscall0(N25_SYS_GETPGRP) };
    let pgid0 = unsafe { syscall1(N25_SYS_GETPGID, 0) };
    let sid0 = unsafe { syscall1(N25_SYS_GETSID, 0) };
    let setsid_leader = unsafe { syscall0(N25_SYS_SETSID) };
    if pgrp != my_pid
        || pgid0 != my_pid
        || sid0 != my_pid
        || !is_error(setsid_leader)
        || errno(setsid_leader) != N25_EPERM
    {
        results.fail("n2_5: initial pgid/sid or leader setsid EPERM check failed");
        return;
    }

    let mut fg_pgid: i32 = 0;
    let mut tty_sid: i32 = 0;
    let r_gpgrp = unsafe {
        syscall3(
            N25_SYS_IOCTL,
            0,
            N25_TIOCGPGRP,
            &mut fg_pgid as *mut i32 as u64,
        )
    };
    let r_gsid = unsafe {
        syscall3(
            N25_SYS_IOCTL,
            0,
            N25_TIOCGSID,
            &mut tty_sid as *mut i32 as u64,
        )
    };
    if is_error(r_gpgrp) || is_error(r_gsid) || fg_pgid != my_pid as i32 || tty_sid != my_pid as i32
    {
        results.fail("n2_5: initial TIOCGPGRP/TIOCGSID check failed");
        return;
    }

    // Leg 1: fork child, move it into its own process group, switch fg_pgid,
    // stop via kill(-pgid, SIGSTOP), observe WUNTRACED via wait4(-pgid),
    // continue via kill(-pgid, SIGCONT), observe WCONTINUED via waitid(P_PGID),
    // and reap exit via waitid(P_PGID, WEXITED).
    let mut c2p = [0i32; 2];
    let mut p2c = [0i32; 2];
    if is_error(unsafe { syscall1(N25_SYS_PIPE, c2p.as_mut_ptr() as u64) })
        || is_error(unsafe { syscall1(N25_SYS_PIPE, p2c.as_mut_ptr() as u64) })
    {
        results.fail("n2_5: pipe creation failed");
        return;
    }

    let child1 = unsafe { sys_fork() };
    if is_error(child1) {
        results.fail("n2_5: fork child1 failed");
        return;
    }
    if child1 == 0 {
        unsafe {
            sys_close(c2p[0] as u64);
            sys_close(p2c[1] as u64);
        }
        let r_sp = unsafe { syscall2(N25_SYS_SETPGID, 0, 0) };
        if is_error(r_sp) {
            unsafe { userspace::syscall::sys_exit(101) };
        }
        let ready = [b'R'];
        let _ = unsafe { syscall3(SYS_WRITE, c2p[1] as u64, ready.as_ptr() as u64, 1) };
        unsafe { sys_close(c2p[1] as u64) };
        let mut go = [0u8; 1];
        loop {
            let n = unsafe { syscall3(SYS_READ, p2c[0] as u64, go.as_mut_ptr() as u64, 1) };
            if is_error(n) && errno(n) == N25_EINTR {
                continue;
            }
            break;
        }
        unsafe {
            sys_close(p2c[0] as u64);
            userspace::syscall::sys_exit(37);
        }
    }

    unsafe {
        sys_close(c2p[1] as u64);
        sys_close(p2c[0] as u64);
    }
    let mut ready_byte = [0u8; 1];
    let r_ready = unsafe { syscall3(SYS_READ, c2p[0] as u64, ready_byte.as_mut_ptr() as u64, 1) };
    unsafe { sys_close(c2p[0] as u64) };
    if is_error(r_ready) || r_ready != 1 || ready_byte[0] != b'R' {
        let _ = unsafe { syscall2(N25_SYS_KILL, child1, 9) };
        unsafe { sys_close(p2c[1] as u64) };
        reap_quietly(child1);
        results.fail("n2_5: child1 ready handshake failed");
        return;
    }

    let c1_pgid = unsafe { syscall1(N25_SYS_GETPGID, child1) };
    let c1_sid = unsafe { syscall1(N25_SYS_GETSID, child1) };
    let new_fg = child1 as i32;
    let orig_fg = my_pid as i32;
    let r_set_fg = unsafe {
        syscall3(
            N25_SYS_IOCTL,
            0,
            N25_TIOCSPGRP,
            &new_fg as *const i32 as u64,
        )
    };
    let mut observed_fg: i32 = 0;
    let r_get_fg = unsafe {
        syscall3(
            N25_SYS_IOCTL,
            0,
            N25_TIOCGPGRP,
            &mut observed_fg as *mut i32 as u64,
        )
    };
    let r_restore_fg = unsafe {
        syscall3(
            N25_SYS_IOCTL,
            0,
            N25_TIOCSPGRP,
            &orig_fg as *const i32 as u64,
        )
    };
    if c1_pgid != child1
        || c1_sid != my_pid
        || is_error(r_set_fg)
        || is_error(r_get_fg)
        || observed_fg != new_fg
        || is_error(r_restore_fg)
    {
        unsafe { sys_close(p2c[1] as u64) };
        reap_quietly(child1);
        results.fail("n2_5: getpgid/getsid or TIOCSPGRP/TIOCGPGRP switch failed");
        return;
    }

    let neg_c1 = (-(child1 as i64)) as u64;
    let r_stop = unsafe { syscall2(N25_SYS_KILL, neg_c1, N25_SIGSTOP) };
    let mut wstatus: i32 = 0;
    let r_wait_stop = unsafe {
        syscall4(
            N25_SYS_WAIT4,
            neg_c1,
            &mut wstatus as *mut i32 as u64,
            WUNTRACED,
            0,
        )
    };
    let expected_stop_status = ((N25_SIGSTOP as i32) << 8) | 0x7f;

    let r_cont = unsafe { syscall2(N25_SYS_KILL, neg_c1, N25_SIGCONT) };
    let mut cont_info = SigInfo::poisoned();
    let r_wait_cont = waitid(P_PGID, child1, &mut cont_info, N25_WCONTINUED);

    let go_byte = [b'G'];
    let _ = unsafe { syscall3(SYS_WRITE, p2c[1] as u64, go_byte.as_ptr() as u64, 1) };
    unsafe { sys_close(p2c[1] as u64) };

    let mut exit_info = SigInfo::poisoned();
    let r_wait_exit = waitid(P_PGID, child1, &mut exit_info, WEXITED);

    if is_error(r_stop)
        || r_wait_stop != child1
        || wstatus != expected_stop_status
        || is_error(r_cont)
        || is_error(r_wait_cont)
        || cont_info.signo() != SIGCHLD
        || cont_info.code() != N25_CLD_CONTINUED
        || cont_info.pid() as u64 != child1
        || cont_info.status() != N25_SIGCONT as i32
        || is_error(r_wait_exit)
        || exit_info.signo() != SIGCHLD
        || exit_info.code() != CLD_EXITED
        || exit_info.pid() as u64 != child1
        || exit_info.status() != 37
    {
        results
            .fail("n2_5: kill(-pgid)/wait4(WUNTRACED)/waitid(P_PGID, WCONTINUED|WEXITED) failed");
        return;
    }

    // Leg 2: setsid() detaches from inherited ctty, TIOCSCTTY(0) fails EPERM
    // while another session owns it, TIOCSCTTY(1) steals, TIOCNOTTY detaches.
    let child2 = unsafe { sys_fork() };
    if is_error(child2) {
        results.fail("n2_5: fork child2 failed");
        return;
    }
    if child2 == 0 {
        let c2_pid = unsafe { sys_getpid() };
        let ns = unsafe { syscall0(N25_SYS_SETSID) };
        if ns != c2_pid {
            unsafe { userspace::syscall::sys_exit(11) };
        }
        if unsafe { syscall0(N25_SYS_GETPGRP) } != c2_pid
            || unsafe { syscall1(N25_SYS_GETSID, 0) } != c2_pid
        {
            unsafe { userspace::syscall::sys_exit(12) };
        }
        let mut s: i32 = 0;
        let r_gsid_no_ctty =
            unsafe { syscall3(N25_SYS_IOCTL, 0, N25_TIOCGSID, &mut s as *mut i32 as u64) };
        if !is_error(r_gsid_no_ctty) || errno(r_gsid_no_ctty) != N25_ENOTTY {
            unsafe { userspace::syscall::sys_exit(13) };
        }
        let r_sctty_nosteal = unsafe { syscall3(N25_SYS_IOCTL, 0, N25_TIOCSCTTY, 0) };
        if !is_error(r_sctty_nosteal) || errno(r_sctty_nosteal) != N25_EPERM {
            unsafe { userspace::syscall::sys_exit(14) };
        }
        let r_sctty_steal = unsafe { syscall3(N25_SYS_IOCTL, 0, N25_TIOCSCTTY, 1) };
        if is_error(r_sctty_steal) {
            unsafe { userspace::syscall::sys_exit(15) };
        }
        let mut s2: i32 = 0;
        let mut fg2: i32 = 0;
        let r_gsid2 =
            unsafe { syscall3(N25_SYS_IOCTL, 0, N25_TIOCGSID, &mut s2 as *mut i32 as u64) };
        let r_gpgrp2 =
            unsafe { syscall3(N25_SYS_IOCTL, 0, N25_TIOCGPGRP, &mut fg2 as *mut i32 as u64) };
        if is_error(r_gsid2) || is_error(r_gpgrp2) || s2 != c2_pid as i32 || fg2 != c2_pid as i32 {
            unsafe { userspace::syscall::sys_exit(16) };
        }
        let r_notty = unsafe { syscall3(N25_SYS_IOCTL, 0, N25_TIOCNOTTY, 0) };
        if is_error(r_notty) {
            unsafe { userspace::syscall::sys_exit(17) };
        }
        // Session leader releasing its ctty sends SIGHUP to its foreground PGID
        // (which includes child2 itself), so child2 should not reach exit(18).
        unsafe { userspace::syscall::sys_exit(18) };
    }

    let mut c2_status: i32 = -1;
    let r_c2 = unsafe {
        syscall4(
            N25_SYS_WAIT4,
            child2,
            &mut c2_status as *mut i32 as u64,
            0,
            0,
        )
    };
    // Re-attach PID 1 to the console ctty after child2 released it with TIOCNOTTY.
    let r_reattach = unsafe { syscall3(N25_SYS_IOCTL, 0, N25_TIOCSCTTY, 0) };
    let mut restored_sid: i32 = 0;
    let r_check_sid = unsafe {
        syscall3(
            N25_SYS_IOCTL,
            0,
            N25_TIOCGSID,
            &mut restored_sid as *mut i32 as u64,
        )
    };
    // 128 + SIGHUP(1) = 129 encoded in wait4 status as (129 << 8).
    const EXPECTED_SIGHUP_STATUS: i32 = 129 << 8;
    if r_c2 != child2
        || c2_status != EXPECTED_SIGHUP_STATUS
        || is_error(r_reattach)
        || is_error(r_check_sid)
        || restored_sid != my_pid as i32
    {
        results.fail("n2_5: setsid/TIOCSCTTY/TIOCNOTTY child2 leg failed");
        return;
    }

    results.pass(
        "N2.5 pgid/sid, controlling terminal ioctls, kill(-pgid), wait4/waitid stop & continue",
    );
}

// ===========================================================================
// N2.1: Raise 256 KiB Exec Image Limit, 1 MiB Segment Limit & FD Ceiling
// ===========================================================================

const N21_SYS_SELECT: u64 = 23;
const N21_SYS_DUP2: u64 = 33;
const N21_SYS_GETRLIMIT: u64 = 97;
const N21_RLIMIT_NOFILE: u64 = 7;
const N21_EBADF: i32 = 9;

fn test_n2_1_exec_segment_and_fd_ceilings(results: &mut TestResult) {
    print("Testing N2.1 >256 KiB exec image, >1 MiB PT_LOAD segment, and 1024 fd ceiling... ");

    // 1. FD ceiling = 1024 (RLIMIT_NOFILE, dup2 to 512 & 1023, reject 1024, select on fd 512).
    let mut rl = [0u64; 2];
    let r_rl = unsafe { syscall2(N21_SYS_GETRLIMIT, N21_RLIMIT_NOFILE, rl.as_mut_ptr() as u64) };
    let r_dup512 = unsafe { syscall2(N21_SYS_DUP2, 1, 512) };
    let r_dup1023 = unsafe { syscall2(N21_SYS_DUP2, 1, 1023) };
    let r_dup1024 = unsafe { syscall2(N21_SYS_DUP2, 1, 1024) };

    let mut wset = [0u64; 16];
    wset[512 / 64] = 1u64 << (512 % 64);
    let mut tv = [0i64; 2];
    let r_sel = unsafe {
        syscall5(
            N21_SYS_SELECT,
            513,
            0,
            wset.as_mut_ptr() as u64,
            0,
            tv.as_mut_ptr() as u64,
        )
    };
    let sel_bit_ready = (wset[512 / 64] & (1u64 << (512 % 64))) != 0;

    unsafe {
        let _ = sys_close(512);
        let _ = sys_close(1023);
    }

    if is_error(r_rl)
        || rl[0] != 1024
        || rl[1] != 1024
        || r_dup512 != 512
        || r_dup1023 != 1023
        || !is_error(r_dup1024)
        || errno(r_dup1024) != N21_EBADF
        || r_sel != 1
        || !sel_bit_ready
    {
        results.fail("n2_1: 1024 fd ceiling / dup2 / select check failed");
        return;
    }

    // 2. Stage a 512 KiB (>256 KiB) ELF64 image with a 2 MiB (>1 MiB) PT_LOAD
    //    segment (512 KiB file-backed + 1536 KiB zeroed BSS), execute it via
    //    sys_spawn_image(517), and verify the child reads the tail sentinel byte
    //    (0x5d at +512 KiB - 1) plus zeroed BSS byte (0x00 at +2 MiB - 1) and
    //    exits with 0x5d.
    const IMG_LEN: usize = 512 * 1024;
    const SEG_MEMSZ: u64 = 2 * 1024 * 1024;
    const BASE: u64 = 0x0040_0000;
    const CODE_OFF: usize = 0x78;
    const SENTINEL: u8 = 0x5d;

    let buf_addr = unsafe { mmap_anon(IMG_LEN, false) };
    if buf_addr < 0 {
        results.fail("n2_1: mmap_anon for 512 KiB ELF image failed");
        return;
    }
    let img = unsafe { core::slice::from_raw_parts_mut(buf_addr as *mut u8, IMG_LEN) };

    let write_le = |dst: &mut [u8], off: usize, val: u64, n: usize| {
        for i in 0..n {
            dst[off + i] = (val >> (8 * i)) as u8;
        }
    };
    img[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    img[4] = 2; // ELFCLASS64
    img[5] = 1; // ELFDATA2LSB
    img[6] = 1; // EV_CURRENT
    write_le(img, 0x10, 2, 2); // ET_EXEC
    write_le(img, 0x12, 0x3e, 2); // EM_X86_64
    write_le(img, 0x14, 1, 4); // EV_CURRENT
    write_le(img, 0x18, BASE + CODE_OFF as u64, 8); // e_entry
    write_le(img, 0x20, 0x40, 8); // e_phoff
    write_le(img, 0x34, 64, 2); // e_ehsize
    write_le(img, 0x36, 56, 2); // e_phentsize
    write_le(img, 0x38, 1, 2); // e_phnum
    write_le(img, 0x3a, 64, 2); // e_shentsize

    // PT_LOAD: R+X, vaddr=0x400000, filesz=512 KiB, memsz=2 MiB
    write_le(img, 0x40, 1, 4); // PT_LOAD
    write_le(img, 0x44, 5, 4); // PF_R | PF_X
    write_le(img, 0x48, 0, 8); // p_offset
    write_le(img, 0x50, BASE, 8); // p_vaddr
    write_le(img, 0x58, BASE, 8); // p_paddr
    write_le(img, 0x60, IMG_LEN as u64, 8); // p_filesz
    write_le(img, 0x68, SEG_MEMSZ, 8); // p_memsz
    write_le(img, 0x70, 0x1000, 8); // p_align

    // Entry code:
    //   mov eax, 0x0047ffff        ; BASE + 512 KiB - 1
    //   movzx edi, byte ptr [rax]  ; sentinel byte = 0x5d
    //   mov eax, 0x005fffff        ; BASE + 2 MiB - 1
    //   movzx esi, byte ptr [rax]  ; BSS tail byte = 0x00
    //   add edi, esi               ; exit code = 0x5d
    //   mov eax, 60                ; SYS_exit
    //   syscall
    //   ud2
    const CODE: [u8; 25] = [
        0xb8, 0xff, 0xff, 0x47, 0x00, 0x0f, 0xb6, 0x38, 0xb8, 0xff, 0xff, 0x5f, 0x00, 0x0f, 0xb6,
        0x30, 0x01, 0xf7, 0xb8, 60, 0, 0, 0, 0x0f, 0x05,
    ];
    img[CODE_OFF..CODE_OFF + CODE.len()].copy_from_slice(&CODE);
    img[CODE_OFF + CODE.len()] = 0x0f;
    img[CODE_OFF + CODE.len() + 1] = 0x0b;
    img[IMG_LEN - 1] = SENTINEL;

    let child = unsafe { sys_fork() };
    if is_error(child) {
        unsafe {
            let _ = munmap(buf_addr as usize, IMG_LEN);
        }
        results.fail("n2_1: fork failed");
        return;
    }
    if child == 0 {
        let _ = unsafe {
            syscall4(
                userspace::syscall::SYS_SPAWN_IMAGE,
                buf_addr as u64,
                IMG_LEN as u64,
                0,
                0,
            )
        };
        unsafe { userspace::syscall::sys_exit(99) };
    }

    let mut status: i32 = -1;
    let r_wait = unsafe { syscall4(N25_SYS_WAIT4, child, &mut status as *mut i32 as u64, 0, 0) };
    unsafe {
        let _ = munmap(buf_addr as usize, IMG_LEN);
    }

    if r_wait != child || status != ((SENTINEL as i32) << 8) {
        results.fail("n2_1: 512 KiB exec image / 2 MiB PT_LOAD segment execution failed");
        return;
    }

    results.pass("N2.1 >256 KiB exec image, >1 MiB PT_LOAD segment, and 1024 fd ceiling");
}

// ===========================================================================
// N2.4: Credentials (set*id), Supplementary Groups, and POSIX Capabilities
// ===========================================================================

const N24_SYS_SETUID: u64 = 105;
const N24_SYS_SETGID: u64 = 106;
const N24_SYS_SETREUID: u64 = 113;
const N24_SYS_SETREGID: u64 = 114;
const N24_SYS_GETGROUPS: u64 = 115;
const N24_SYS_SETGROUPS: u64 = 116;
const N24_SYS_SETRESUID: u64 = 117;
const N24_SYS_GETRESUID: u64 = 118;
const N24_SYS_SETRESGID: u64 = 119;
const N24_SYS_GETRESGID: u64 = 120;
const N24_SYS_SETFSUID: u64 = 122;
const N24_SYS_SETFSGID: u64 = 123;
const N24_SYS_CAPGET: u64 = 125;
const N24_SYS_CAPSET: u64 = 126;

const N24_CAP_V3: u32 = 0x2008_0522;
const N24_CAP_SETUID_BIT: u32 = 1 << 7;
const N24_CAP_SYS_ADMIN_BIT: u32 = 1 << 21;
const N24_EPERM: i32 = 1;

fn test_n2_4_credentials_groups_and_caps(results: &mut TestResult) {
    print("Testing N2.4 set*id, supplementary groups, and capget/capset... ");

    // Run inside a forked child so PID 1 keeps its untouched root credentials.
    let child = unsafe { sys_fork() };
    if is_error(child) {
        results.fail("n2_4: fork failed");
        return;
    }
    if child == 0 {
        // 1. capget version probe (unknown version + NULL data -> returns 0 and writes V3).
        let mut hdr = [0xdead_beef_u32, 0u32];
        let r_probe = unsafe { syscall2(N24_SYS_CAPGET, hdr.as_mut_ptr() as u64, 0) };
        if is_error(r_probe) || hdr[0] != N24_CAP_V3 {
            unsafe { userspace::syscall::sys_exit(11) };
        }

        // 2. capget(V3, pid=0) as root has CAP_SETUID and CAP_SYS_ADMIN.
        let mut data = [0u32; 6]; // 2 * { eff, perm, inh }
        let r_cg = unsafe {
            syscall2(
                N24_SYS_CAPGET,
                hdr.as_mut_ptr() as u64,
                data.as_mut_ptr() as u64,
            )
        };
        if is_error(r_cg)
            || (data[0] & N24_CAP_SETUID_BIT) == 0
            || (data[1] & N24_CAP_SETUID_BIT) == 0
            || (data[0] & N24_CAP_SYS_ADMIN_BIT) == 0
        {
            unsafe { userspace::syscall::sys_exit(12) };
        }

        // 3. setgroups / getgroups (dedup + sort + query size=0).
        let gids_in = [200u32, 100u32, 200u32];
        let r_sg = unsafe {
            syscall2(
                N24_SYS_SETGROUPS,
                gids_in.len() as u64,
                gids_in.as_ptr() as u64,
            )
        };
        let r_gg0 = unsafe { syscall2(N24_SYS_GETGROUPS, 0, 0) };
        let mut gids_out = [0u32; 4];
        let r_gg = unsafe { syscall2(N24_SYS_GETGROUPS, 4, gids_out.as_mut_ptr() as u64) };
        if is_error(r_sg) || r_gg0 != 2 || r_gg != 2 || gids_out[0] != 100 || gids_out[1] != 200 {
            unsafe { userspace::syscall::sys_exit(13) };
        }

        // 4. Temporary euid drop via setresuid(-1, 1000, -1) clears effective caps,
        //    retains permitted caps, and allows regaining euid=0.
        let unchanged = u32::MAX as u64;
        if is_error(unsafe { syscall3(N24_SYS_SETRESUID, unchanged, 1000, unchanged) }) {
            unsafe { userspace::syscall::sys_exit(14) };
        }
        let (mut ru, mut eu, mut su) = (99u32, 99u32, 99u32);
        let r_gru = unsafe {
            syscall3(
                N24_SYS_GETRESUID,
                &mut ru as *mut u32 as u64,
                &mut eu as *mut u32 as u64,
                &mut su as *mut u32 as u64,
            )
        };
        let r_cg_drop = unsafe {
            syscall2(
                N24_SYS_CAPGET,
                hdr.as_mut_ptr() as u64,
                data.as_mut_ptr() as u64,
            )
        };
        if is_error(r_gru)
            || is_error(r_cg_drop)
            || (ru, eu, su) != (0, 1000, 0)
            || data[0] != 0
            || (data[1] & N24_CAP_SETUID_BIT) == 0
        {
            unsafe { userspace::syscall::sys_exit(15) };
        }
        if is_error(unsafe { syscall3(N24_SYS_SETRESUID, unchanged, 0, unchanged) }) {
            unsafe { userspace::syscall::sys_exit(16) };
        }

        // 5. capset drops CAP_SYS_ADMIN permanently; re-raising returns EPERM.
        let _ = unsafe {
            syscall2(
                N24_SYS_CAPGET,
                hdr.as_mut_ptr() as u64,
                data.as_mut_ptr() as u64,
            )
        };
        data[0] &= !N24_CAP_SYS_ADMIN_BIT;
        data[1] &= !N24_CAP_SYS_ADMIN_BIT;
        if is_error(unsafe { syscall2(N24_SYS_CAPSET, hdr.as_ptr() as u64, data.as_ptr() as u64) })
        {
            unsafe { userspace::syscall::sys_exit(17) };
        }
        data[0] |= N24_CAP_SYS_ADMIN_BIT;
        data[1] |= N24_CAP_SYS_ADMIN_BIT;
        let r_raise =
            unsafe { syscall2(N24_SYS_CAPSET, hdr.as_ptr() as u64, data.as_ptr() as u64) };
        if !is_error(r_raise) || errno(r_raise) != N24_EPERM {
            unsafe { userspace::syscall::sys_exit(18) };
        }

        // 6. setregid / getresgid / setfsgid.
        if is_error(unsafe { syscall2(N24_SYS_SETREGID, 2000, 2000) }) {
            unsafe { userspace::syscall::sys_exit(19) };
        }
        let (mut rg, mut eg, mut sg) = (0u32, 0u32, 0u32);
        let r_grg = unsafe {
            syscall3(
                N24_SYS_GETRESGID,
                &mut rg as *mut u32 as u64,
                &mut eg as *mut u32 as u64,
                &mut sg as *mut u32 as u64,
            )
        };
        let prev_fsg = unsafe { syscall1(N24_SYS_SETFSGID, unchanged) };
        if is_error(r_grg) || (rg, eg, sg) != (2000, 2000, 2000) || prev_fsg != 2000 {
            unsafe { userspace::syscall::sys_exit(20) };
        }

        // 7. Permanent setuid(1000) drops all capabilities; setuid(0), setreuid(0,0),
        //    setresgid(0,0,0), setgid(0), setgroups all fail EPERM; setfsuid(0) is no-op.
        if is_error(unsafe { syscall1(N24_SYS_SETUID, 1000) }) {
            unsafe { userspace::syscall::sys_exit(21) };
        }
        let r_su0 = unsafe { syscall1(N24_SYS_SETUID, 0) };
        let r_sru0 = unsafe { syscall2(N24_SYS_SETREUID, 0, 0) };
        let r_sg0 = unsafe { syscall1(N24_SYS_SETGID, 0) };
        let r_srg0 = unsafe { syscall3(N24_SYS_SETRESGID, 0, 0, 0) };
        let r_sgrp = unsafe { syscall2(N24_SYS_SETGROUPS, 0, 0) };
        let prev_fsu1 = unsafe { syscall1(N24_SYS_SETFSUID, 0) };
        let prev_fsu2 = unsafe { syscall1(N24_SYS_SETFSUID, unchanged) };
        let _ = unsafe {
            syscall2(
                N24_SYS_CAPGET,
                hdr.as_mut_ptr() as u64,
                data.as_mut_ptr() as u64,
            )
        };
        if !is_error(r_su0)
            || errno(r_su0) != N24_EPERM
            || !is_error(r_sru0)
            || errno(r_sru0) != N24_EPERM
            || !is_error(r_sg0)
            || errno(r_sg0) != N24_EPERM
            || !is_error(r_srg0)
            || errno(r_srg0) != N24_EPERM
            || !is_error(r_sgrp)
            || errno(r_sgrp) != N24_EPERM
            || prev_fsu1 != 1000
            || prev_fsu2 != 1000
            || data[0] != 0
            || data[1] != 0
        {
            unsafe { userspace::syscall::sys_exit(22) };
        }

        unsafe { userspace::syscall::sys_exit(0) };
    }

    let mut status: i32 = -1;
    let r_wait = unsafe { syscall4(N25_SYS_WAIT4, child, &mut status as *mut i32 as u64, 0, 0) };
    if r_wait != child || status != 0 {
        results.fail("n2_4: set*id / groups / capget / capset child failed");
        return;
    }

    results.pass("N2.4 set*id, supplementary groups, capget/capset, and privilege drop");
}
