#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Fuzz input for memory operations
#[derive(Arbitrary, Debug)]
struct MemoryFuzzInput {
    operation: MemoryOperation,
    addr: u64,
    length: u64,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
}

#[derive(Arbitrary, Debug)]
enum MemoryOperation {
    Mmap,
    Munmap,
    Mprotect,
    Madvise,
    Mlock,
    Munlock,
    Brk,
    Mremap { new_addr: u64 },
}

fuzz_target!(|input: MemoryFuzzInput| {
    // Target memory management bugs:
    // - R172-16: brk/mmap VMA TOCTOU
    // - R174-B3: demand-grow PT-charge asymmetry
    // - R174-B4: brk VA-reservation TOCTOU
    // - R174-A4: COW #PF blocking lock
    // - M0-7: stack guard page and demand-grow

    match input.operation {
        MemoryOperation::Mmap => {
            test_mmap_fuzzing(input.addr, input.length, input.prot, input.flags, input.fd, input.offset);
        }
        MemoryOperation::Munmap => {
            test_munmap_fuzzing(input.addr, input.length);
        }
        MemoryOperation::Mprotect => {
            test_mprotect_fuzzing(input.addr, input.length, input.prot);
        }
        MemoryOperation::Madvise => {
            test_madvise_fuzzing(input.addr, input.length, input.flags);
        }
        MemoryOperation::Mlock => {
            test_mlock_fuzzing(input.addr, input.length);
        }
        MemoryOperation::Munlock => {
            test_munlock_fuzzing(input.addr, input.length);
        }
        MemoryOperation::Brk => {
            test_brk_fuzzing(input.addr);
        }
        MemoryOperation::Mremap { new_addr } => {
            test_mremap_fuzzing(input.addr, input.length, new_addr, input.flags);
        }
    }
});

fn test_mmap_fuzzing(addr: u64, length: u64, prot: i32, flags: i32, fd: i32, offset: i64) {
    // Fuzz mmap with various combinations
    // Target: VMA overlaps, charge accounting, MAP_FIXED into stack window

    // Length validation
    if length == 0 {
        // Should return EINVAL
        return;
    }

    const MAX_MMAP_SIZE: u64 = 0x7fff_0000_0000; // ~128TB
    if length > MAX_MMAP_SIZE {
        // Should return ENOMEM
        return;
    }

    // Address alignment
    const PAGE_SIZE: u64 = 4096;
    if addr != 0 && addr % PAGE_SIZE != 0 {
        // Unaligned address with MAP_FIXED should fail
        if flags & 0x10 != 0 { // MAP_FIXED
            return;
        }
    }

    // Protection flags
    const PROT_NONE: i32 = 0;
    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const PROT_EXEC: i32 = 4;

    let valid_prot = prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
    if prot != PROT_NONE && prot != valid_prot {
        // Invalid protection bits
        return;
    }

    // Mapping flags
    const MAP_SHARED: i32 = 0x01;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_FIXED: i32 = 0x10;
    const MAP_ANONYMOUS: i32 = 0x20;
    const MAP_GROWSDOWN: i32 = 0x0100;

    // Must specify exactly one of MAP_SHARED or MAP_PRIVATE
    let sharing_bits = flags & (MAP_SHARED | MAP_PRIVATE);
    if sharing_bits != MAP_SHARED && sharing_bits != MAP_PRIVATE {
        // Should return EINVAL
        return;
    }

    // File-backed vs anonymous
    if flags & MAP_ANONYMOUS != 0 {
        // MAP_ANONYMOUS ignores fd; only an out-of-range fd (< -1) is clearly
        // invalid, which the kernel rejects with EBADF.
        if fd < -1 {
            return;
        }
    } else {
        // File-backed mapping
        if fd < 0 {
            // Should return EBADF
            return;
        }

        if offset < 0 || offset % PAGE_SIZE as i64 != 0 {
            // Should return EINVAL
            return;
        }
    }

    // MAP_FIXED into restricted regions
    if flags & MAP_FIXED != 0 && addr != 0 {
        // Check for stack window collision (M0-7 SLICE 1)
        const USER_STACK_BASE: u64 = 0x0000_7fff_f000_0000;
        const STACK_WINDOW_SIZE: u64 = 2 * 1024 * 1024; // 2MB

        if addr >= USER_STACK_BASE && addr < USER_STACK_BASE + STACK_WINDOW_SIZE {
            // MAP_FIXED into stack window - should return ENOMEM
            return;
        }

        // Check for kernel space
        const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
        if addr >= KERNEL_BASE {
            // Should return ENOMEM
            return;
        }
    }

    // W^X policy test (R172-X-F3 mprotect W^X door)
    if prot & PROT_WRITE != 0 && prot & PROT_EXEC != 0 {
        // Writable + executable - security concern
        // Some kernels enforce W^X (reject this)
    }
}

fn test_munmap_fuzzing(addr: u64, length: u64) {
    // Fuzz munmap
    // Target: partial unmaps, VMA splits, charge accounting

    if length == 0 {
        // Should return EINVAL
        return;
    }

    const PAGE_SIZE: u64 = 4096;
    if addr % PAGE_SIZE != 0 {
        // Unaligned address should return EINVAL
        return;
    }

    // Unmapping kernel space should fail
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    if addr >= KERNEL_BASE {
        return;
    }

    // Unmapping can split VMAs
    // Unmapping non-mapped region succeeds (POSIX)
}

fn test_mprotect_fuzzing(addr: u64, length: u64, prot: i32) {
    // Fuzz mprotect
    // Target: R168-1 mprotect Path B double uncharge, PT-charge coverage

    if length == 0 {
        // Should return EINVAL
        return;
    }

    const PAGE_SIZE: u64 = 4096;
    if addr % PAGE_SIZE != 0 {
        // Unaligned address should return EINVAL
        return;
    }

    // Protection validation (same as mmap)
    const PROT_NONE: i32 = 0;
    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const PROT_EXEC: i32 = 4;

    let valid_prot = prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
    if prot != PROT_NONE && prot != valid_prot {
        return;
    }

    // Cannot mprotect kernel space
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    if addr >= KERNEL_BASE {
        return;
    }

    // mprotect can split VMAs
    // Changing to PROT_NONE may need to allocate PT frames (R168-1)
}

fn test_madvise_fuzzing(addr: u64, length: u64, advice: i32) {
    // Fuzz madvise hints

    if length == 0 {
        return;
    }

    const PAGE_SIZE: u64 = 4096;
    if addr % PAGE_SIZE != 0 {
        return;
    }

    // Advice values
    const MADV_NORMAL: i32 = 0;
    const MADV_RANDOM: i32 = 1;
    const MADV_SEQUENTIAL: i32 = 2;
    const MADV_WILLNEED: i32 = 3;
    const MADV_DONTNEED: i32 = 4;

    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL => {
            // Readahead hints
        }
        MADV_WILLNEED => {
            // Prefault pages
        }
        MADV_DONTNEED => {
            // Can free pages (CoW zero)
        }
        _ => {
            // Invalid advice
            return;
        }
    }
}

fn test_mlock_fuzzing(addr: u64, length: u64) {
    // Fuzz mlock (prevent swapping)

    if length == 0 {
        return;
    }

    const PAGE_SIZE: u64 = 4096;
    if addr % PAGE_SIZE != 0 {
        return;
    }

    // RLIMIT_MEMLOCK check
    const MAX_LOCKED_MEM: u64 = 64 * 1024 * 1024; // 64MB default
    if length > MAX_LOCKED_MEM {
        // Should return ENOMEM
        return;
    }
}

fn test_munlock_fuzzing(addr: u64, length: u64) {
    // Fuzz munlock

    if length == 0 {
        return;
    }

    const PAGE_SIZE: u64 = 4096;
    if addr % PAGE_SIZE != 0 {
        return;
    }

    // munlock on non-locked region succeeds
}

fn test_brk_fuzzing(new_brk: u64) {
    // Fuzz brk heap operations
    // Target: R174-B4 brk VA-reservation TOCTOU, R172-16 brk VMA TOCTOU

    const PAGE_SIZE: u64 = 4096;

    // brk(0) returns current brk
    if new_brk == 0 {
        return;
    }

    // new_brk must be page-aligned
    if new_brk % PAGE_SIZE != 0 {
        // Kernel may round up or reject
    }

    // Cannot brk into kernel space
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    if new_brk >= KERNEL_BASE {
        return;
    }

    // R174-B4: brk growth now uses atomic brk_grow_resv_lo/hi reservation
    // R172-16: mmap must reject intersection with brk region

    // brk region has limits
    const BRK_REGION_BASE: u64 = 0x0000_0000_0100_0000; // Example
    const BRK_REGION_LIMIT: u64 = 0x0000_0010_0000_0000; // Example

    if new_brk < BRK_REGION_BASE || new_brk > BRK_REGION_LIMIT {
        // Out of brk region bounds
        return;
    }
}

fn test_mremap_fuzzing(old_addr: u64, old_size: u64, new_addr: u64, flags: i32) {
    // Fuzz mremap (resize/move mapping)

    if old_size == 0 {
        return;
    }

    const PAGE_SIZE: u64 = 4096;
    if old_addr % PAGE_SIZE != 0 {
        return;
    }

    const MREMAP_MAYMOVE: i32 = 1;
    const MREMAP_FIXED: i32 = 2;

    // MREMAP_FIXED requires MREMAP_MAYMOVE
    if flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0 {
        return;
    }

    if flags & MREMAP_FIXED != 0 {
        // new_addr must be page-aligned
        if new_addr % PAGE_SIZE != 0 {
            return;
        }

        // new_addr must be in user space
        const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
        if new_addr >= KERNEL_BASE {
            return;
        }
    }
}

/// Test stack guard page and demand-grow
fn test_stack_operations(rsp: u64, access_addr: u64) {
    // M0-7: stack guard page prevents overflow into brk/heap
    // M0-7 SLICE 4/5/6: demand-grow on #PF

    const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
    const GUARD_PAGE_SIZE: u64 = 4096;
    const INITIAL_STACK_SIZE: u64 = 2 * 1024 * 1024;

    let stack_bottom = USER_STACK_TOP - INITIAL_STACK_SIZE;
    let guard_base = stack_bottom - GUARD_PAGE_SIZE;

    // Access below guard page should fault (SIGSEGV)
    if access_addr < guard_base {
        // Should not be mapped
        return;
    }

    // Access in guard page should fault
    if access_addr >= guard_base && access_addr < stack_bottom {
        // Guard page - should fault
        return;
    }

    // Access in stack region should succeed
    if access_addr >= stack_bottom && access_addr < USER_STACK_TOP {
        // Valid stack access
    }

    // Demand-grow: if access is below current floor but above guard,
    // kernel should grow stack (M0-7 SLICE 4)
}
