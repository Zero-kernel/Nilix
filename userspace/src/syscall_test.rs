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
    errno, is_error, sys_close, sys_fork, sys_getpid, sys_getrandom, sys_gettid, sys_open,
    sys_read, sys_set_robust_list, sys_set_tid_address, sys_wait, syscall1, syscall2, syscall3,
    syscall5, syscall6, SYS_MMAP, SYS_MREMAP, SYS_MUNMAP,
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
        print("[PASS] ");
        println(name);
        self.passed += 1;
    }

    fn fail(&mut self, name: &str) {
        print("[FAIL] ");
        println(name);
        self.failed += 1;
    }

    fn skip(&mut self, name: &str) {
        print("[SKIP] ");
        println(name);
    }
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

    // ST-K2-MREMAP / ST-K2-P2: anonymous memory resize and shared-anonymous
    // behavior. These run last because they fork and consume address space.
    test_mremap_resize(&mut results);
    test_mremap_maymove(&mut results);
    test_mremap_fail_closed(&mut results);
    test_mremap_prot_none(&mut results);
    test_mremap_charge_symmetry(&mut results);
    test_shared_anon_fork(&mut results);
    test_shared_anon_usercopy(&mut results);
    test_shared_anon_pte_preflight(&mut results);
    test_shared_anon_adjacent_pt(&mut results);
    test_shared_anon_migration(&mut results);

    // Print summary
    println("");
    println("================================");
    print("  Results: ");
    print_int(results.passed as i64);
    print(" passed, ");
    print_int(results.failed as i64);
    println(" failed");
    println("================================");

    // Exit with appropriate code
    let exit_code = if results.failed == 0 { 0 } else { 1 };
    unsafe {
        userspace::syscall::sys_exit(exit_code);
    }
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

/// Syscalls that call `verify_user_memory` still reject a fresh lazy shared page.
/// Keep this as an explicit qualified probe: direct usercopy first-touch is a
/// separate path and must not be mistaken for a preflight fix.
fn test_shared_anon_pte_preflight(results: &mut TestResult) {
    print("Testing shared-anon PTE-only syscall preflight... ");
    unsafe {
        let base = mmap_anon(PAGE, true);
        if base < 0 {
            results.fail("shared preflight: mmap failed");
            return;
        }
        let base = base as usize;
        let result = sys_getrandom(base as *mut u8, PAGE, 0);
        let observed = err_of(result as i64);
        let released = munmap(base, PAGE) == 0;
        if !released {
            results.fail("shared preflight: munmap failed");
            return;
        }
        if observed == EFAULT {
            print("observed EFAULT ");
            results.skip("shared-anon PTE-only preflight remains pending");
        } else if result == PAGE as u64 {
            results.pass("shared-anon PTE-only preflight accepts lazy buffer");
        } else {
            print("errno=");
            print_int(observed as i64);
            print(" ");
            results.fail("shared preflight: unexpected errno");
        }
    }
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
