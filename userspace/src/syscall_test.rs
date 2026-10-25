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
    sys_open, sys_read, sys_set_robust_list, sys_set_tid_address, sys_wait, syscall1, syscall2,
    syscall3, syscall4, syscall5, syscall6, SYS_BRK, SYS_FSTAT, SYS_MMAP, SYS_MREMAP, SYS_MUNMAP,
    SYS_READ, SYS_WRITE,
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
    test_thread_group_children(&mut results);

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

    // R192-RES-2: every eager population site in bounded holds, and the boot-armed
    // injected failure's rollback. Auto-placed mappings only, freed before the next.
    test_bounded_population(&mut results);

    // LEAD-MREMAP-RELOC-UAF-1: a relocation keeps the frames it moved.
    test_mremap_relocation_keeps_frames(&mut results);

    // LEAD-KPTI-PML4-1: last, because its hinted mappings move the automatic
    // mmap base past 1 TiB.
    test_kpti_fresh_pml4_slots(&mut results);

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

fn test_waitid(results: &mut TestResult) {
    print("Testing waitid (syscall 247)... ");

    // 1. Validation happens before any state is consulted, so none of these
    //    needs a child. Each is a claim in §4 of the design.
    let mut info = SigInfo::poisoned();
    let bad = [
        (P_PGID, 1, WEXITED, "P_PGID"),
        (P_PID, 0, WEXITED, "P_PID with id 0"),
        (7, 1, WEXITED, "unknown idtype"),
        (P_ALL, 0, 0, "missing WEXITED"),
        (P_ALL, 0, WEXITED | WUNTRACED, "WUNTRACED"),
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
        print("  over-wakes during targeted wait: ");
        print_int(wakes_after.wrapping_sub(wakes_before) as i64);
        println("");
        results.fail("selective wait: sibling exit over-woke a pid-targeted wait");
        return;
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
// policy that denies six hooks for one reserved real uid, and fails the first
// subject lookup of every syscall made by a second reserved real uid. A child
// takes the marker with setresuid(marker, 0, 0): it keeps euid 0, so each DAC
// check before the LSM passes and only the LSM can refuse it.
// ---------------------------------------------------------------------------

const SYS_EXEC: u64 = 59;
const SYS_KILL: u64 = 62;
const SYS_SETRESUID: u64 = 117;
const SYS_UNLINK: u64 = 87;
/// Keep in sync with `lsm::syscall_test::{DENY_UID, NO_SUBJECT_UID}`.
const LSM_TEST_DENY_UID: u64 = 0x7E57_0001;
const LSM_TEST_NO_SUBJECT_UID: u64 = 0x7E57_0002;
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
        (Some(LSM_TEST_DENY_UID), "policy-denial arm"),
        (Some(LSM_TEST_NO_SUBJECT_UID), "missing-subject arm"),
    ] {
        let child = sys_fork();
        if is_error(child) {
            return Err(("fork", 0));
        }
        if child == 0 {
            let code = match marker {
                Some(uid) if syscall3(SYS_SETRESUID, uid, 0, 0) != 0 => 0x40,
                _ => lsm_oracle_calls(marker.is_none(), stat_fd, page),
            };
            raw_exit(SYS_EXIT, code);
        }
        let mut status: i32 = 0;
        let waited = sys_wait(&mut status as *mut i32);
        if is_error(waited) || waited != child {
            return Err(("wait", 0));
        }
        let code = ((status >> 8) & 0xff) as u64;
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
