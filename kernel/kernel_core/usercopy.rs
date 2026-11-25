//! Fault-tolerant user-space memory copy
//!
//! This module provides safe copy operations between kernel and user space
//! that can recover from page faults (TOCTOU protection).
//!
//! # Design (H-26 FIX: Exception Table EFAULT Semantics)
//!
//! Uses a per-CPU state to track when a user copy is in progress.
//! If a page fault occurs during a user copy:
//! 1. User memory accesses go through small x86_64 assembly helpers
//! 2. Each faulting instruction has an exception-table entry mapping to a fixup label
//! 3. The page_fault_handler consults the exception table; on match, rewrites RIP to fixup
//! 4. The helper returns an error code, and the copy routine returns `Err(())` (EFAULT)
//!
//! This allows syscalls to return EFAULT instead of terminating the process.
//!
//! # Type-Safe API (A.1 Security Hardening)
//!
//! This module provides type-safe user pointer wrappers:
//! - `UserPtr<T>`: Single object pointer with alignment validation
//! - `UserSlice<T>`: Slice pointer with bounds and alignment validation
//!
//! These wrappers enforce:
//! - Non-null pointers
//! - User-space address range validation
//! - Type alignment requirements
//! - Overflow-safe arithmetic
//!
//! # SMAP Guard Nesting (S-5 fix)
//!
//! UserAccessGuard supports nesting via a depth counter. Only the outermost
//! guard executes STAC/CLAC, preventing premature SMAP re-enablement when
//! guards are nested (e.g., copy_user_str_array calling copy_user_cstring).
//!
//! # PID Binding (H-36 fix)
//!
//! Usercopy state is bound to the owning process PID to prevent cross-process
//! false positive fault detection in future SMP scenarios.
//!
//! # Per-CPU State (V-5 fix)
//!
//! Both usercopy state and SMAP guard depth are now per-CPU via CpuLocal<T>.
//! This ensures correct behavior in SMP environments where multiple CPUs may
//! be performing user copies concurrently.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicUsize, Ordering};
use cpu_local::{current_cpu_id, CpuLocal};

// ============================================================================
// H-26 FIX: Exception-table assisted user accesses (x86_64)
// ============================================================================
//
// x86 has variable-length instructions, so on a fault we can't reliably advance RIP.
// Instead, we emit a Linux-style exception table that maps the faulting instruction
// address to a fixup address inside the same helper. The page fault handler rewrites
// RIP to the fixup, and the helper returns an error to the caller.
//
// Assembly helpers use the System V AMD64 ABI:
// - rdi = first argument (dst for get_u8, dst for put_u8)
// - rsi = second argument (src for get_u8, val for put_u8)
// - rax = return value (0 = success, 1 = fault)
//
// NOTE: Uses Intel syntax (default for Rust inline assembly on x86_64)
core::arch::global_asm!(
    r#"
    .text

    // Copy one byte from user space [rsi] to kernel space [rdi]
    // Returns 0 on success, 1 on fault
    .global __zero_os_usercopy_get_u8
__zero_os_usercopy_get_u8:
.Lget_u8_access:
    mov al, [rsi]           // Read byte from user space - may fault here
    mov [rdi], al           // Write to kernel buffer
    xor eax, eax            // Return 0 (success)
    ret
.Lget_u8_fixup:
    mov eax, 1              // Return 1 (fault)
    ret

    // Exception table entry for get_u8 (PC-relative for PIE/KASLR compatibility)
    // Each .long is a signed 32-bit offset from its own address to the target.
    .pushsection .ex_table,"a"
    .balign 8
.Lex_get_u8_fault:  .long .Lget_u8_access - .Lex_get_u8_fault
.Lex_get_u8_fixup:  .long .Lget_u8_fixup - .Lex_get_u8_fixup
    .popsection

    // RF178-8: Atomically copy one aligned u32 from user space [rsi] to
    // kernel space [rdi]. One dword load is required for futex comparison;
    // four byte loads can synthesize a value that never existed concurrently.
    // Returns 0 on success, 1 on fault.
    .global __zero_os_usercopy_get_u32
__zero_os_usercopy_get_u32:
    .global __zero_os_usercopy_get_u32_access
__zero_os_usercopy_get_u32_access:
.Lget_u32_access:
    mov eax, dword ptr [rsi] // Aligned atomic user load - may fault here
    mov dword ptr [rdi], eax
    xor eax, eax
    ret
.Lget_u32_fixup:
    mov eax, 1
    ret

    .pushsection .ex_table,"a"
    .balign 8
.Lex_get_u32_fault: .long .Lget_u32_access - .Lex_get_u32_fault
.Lex_get_u32_fixup: .long .Lget_u32_fixup - .Lex_get_u32_fixup
    .popsection

    // RF187-U34: Atomically copy one aligned u64 from user space [rsi] to
    // kernel space [rdi].  Robust-list pointers and the signed futex offset
    // are naturally word-sized on the x86_64 ABI; a single load prevents a
    // concurrent userspace update from being synthesized from torn halves.
    // Returns 0 on success, 1 on fault.
    .global __zero_os_usercopy_get_u64
__zero_os_usercopy_get_u64:
.Lget_u64_access:
    mov rax, qword ptr [rsi] // Aligned atomic user load - may fault here
    mov qword ptr [rdi], rax
    xor eax, eax
    ret
.Lget_u64_fixup:
    mov eax, 1
    ret

    .pushsection .ex_table,"a"
    .balign 8
.Lex_get_u64_fault: .long .Lget_u64_access - .Lex_get_u64_fault
.Lex_get_u64_fixup: .long .Lget_u64_fixup - .Lex_get_u64_fixup
    .popsection

    // Write one byte (sil) to user space [rdi]
    // Returns 0 on success, 1 on fault
    .global __zero_os_usercopy_put_u8
__zero_os_usercopy_put_u8:
.Lput_u8_access:
    mov [rdi], sil          // Write byte to user space - may fault here
    xor eax, eax            // Return 0 (success)
    ret
.Lput_u8_fixup:
    mov eax, 1              // Return 1 (fault)
    ret

    // Exception table entry for put_u8 (PC-relative for PIE/KASLR compatibility)
    .pushsection .ex_table,"a"
    .balign 8
.Lex_put_u8_fault:  .long .Lput_u8_access - .Lex_put_u8_fault
.Lex_put_u8_fixup:  .long .Lput_u8_fixup - .Lex_put_u8_fixup
    .popsection

    // One naturally aligned 32-bit store to user memory.
    .global __zero_os_usercopy_put_u32
__zero_os_usercopy_put_u32:
.Lput_u32_access:
    mov dword ptr [rdi], esi
    xor eax, eax
    ret
.Lput_u32_fixup:
    mov eax, 1
    ret

    .pushsection .ex_table,"a"
    .balign 8
.Lex_put_u32_fault: .long .Lput_u32_access - .Lex_put_u32_fault
.Lex_put_u32_fixup: .long .Lput_u32_fixup - .Lex_put_u32_fixup
    .popsection

    // RF187-U34: fault-tolerant atomic compare-and-exchange of one aligned
    // user u32.  Arguments are (addr=rdi, expected=rsi, desired=rdx).  The
    // low 32 bits of the return value contain the value observed by cmpxchg;
    // bit 32 is set only when the user access faulted.  This lets robust-futex
    // teardown distinguish a racing owner update from an unmapped word and
    // fail closed on the latter.
    .global __zero_os_usercopy_cmpxchg_u32
__zero_os_usercopy_cmpxchg_u32:
    mov eax, esi
.Lcmpxchg_u32_access:
    .global __zero_os_usercopy_cmpxchg_u32_access
__zero_os_usercopy_cmpxchg_u32_access:
    lock cmpxchg dword ptr [rdi], edx
    ret
.Lcmpxchg_u32_fixup:
    mov rax, 0x100000000
    ret

    .pushsection .ex_table,"a"
    .balign 8
.Lex_cmpxchg_u32_fault: .long .Lcmpxchg_u32_access - .Lex_cmpxchg_u32_fault
.Lex_cmpxchg_u32_fixup: .long .Lcmpxchg_u32_fixup - .Lex_cmpxchg_u32_fixup
    .popsection

    // Issue #109 §4.2: Hardware-accelerated bulk usercopy (x86_64 ERMS/FSRM).
    // System V AMD64 ABI:
    //   rdi = dst (kernel dst for copy_from_user, user dst for copy_to_user)
    //   rsi = src (user src for copy_from_user, kernel src for copy_to_user)
    //   rdx = len (bytes to copy)
    // Returns:
    //   rax = remaining uncopied byte count (0 = complete success, >0 = faulted)
    .global __zero_os_usercopy_copy_bytes
__zero_os_usercopy_copy_bytes:
    mov rcx, rdx            // rcx = byte count for rep movsb
    cld                     // R65-17: guarantee forward copy (DF=0)
.Lcopy_bytes_access:
    .global __zero_os_usercopy_copy_bytes_access
__zero_os_usercopy_copy_bytes_access:
    rep movsb               // Hardware bulk copy; on #PF, RIP stays here and rcx = remaining
    xor eax, eax            // Return 0 (all bytes copied)
    ret
.Lcopy_bytes_fixup:
    mov rax, rcx            // Return remaining uncopied bytes (> 0)
    ret

    .pushsection .ex_table,"a"
    .balign 8
.Lex_copy_bytes_fault:  .long .Lcopy_bytes_access - .Lex_copy_bytes_fault
.Lex_copy_bytes_fixup:  .long .Lcopy_bytes_fixup - .Lex_copy_bytes_fixup
    .popsection

"#
);

extern "C" {
    /// Copy one byte from user space to kernel buffer.
    /// Returns 0 on success, 1 on fault.
    fn __zero_os_usercopy_get_u8(dst: *mut u8, src: *const u8) -> u32;

    /// Copy one aligned u32 from user space with one atomic load.
    /// Returns 0 on success, 1 on fault.
    fn __zero_os_usercopy_get_u32(dst: *mut u32, src: *const u32) -> u32;

    /// Copy one aligned u64 from user space with one atomic load.
    /// Returns 0 on success, 1 on fault.
    fn __zero_os_usercopy_get_u64(dst: *mut u64, src: *const u64) -> u32;

    /// Atomically compare-and-exchange one aligned user u32.
    /// Returns the observed old value in bits 0..31 and sets bit 32 on fault.
    fn __zero_os_usercopy_cmpxchg_u32(dst: *mut u32, expected: u32, desired: u32) -> u64;

    /// Write one byte to user space.
    /// Returns 0 on success, 1 on fault.
    #[allow(dead_code)]
    fn __zero_os_usercopy_put_u8(dst: *mut u8, val: u8) -> u32;

    /// Store one aligned user u32. Returns 0 on success and 1 on fault.
    fn __zero_os_usercopy_put_u32(dst: *mut u32, val: u32) -> u32;

    /// Issue #109 §4.2: Hardware-accelerated bulk copy between kernel and user memory.
    /// Returns 0 on complete copy, or remaining uncopied byte count (> 0) on fault.
    fn __zero_os_usercopy_copy_bytes(dst: *mut u8, src: *const u8, len: usize) -> usize;

    /// TD-USERCOPY-1: the user-access instructions of the two helpers the
    /// no-fault readers run (labels inside the helpers; never read or called).
    static __zero_os_usercopy_get_u32_access: u8;
    static __zero_os_usercopy_cmpxchg_u32_access: u8;
}

/// TD-USERCOPY-1 FIX: whether `ip` is the user-access instruction of
/// `__zero_os_usercopy_get_u32` or `__zero_os_usercopy_cmpxchg_u32`, the only
/// helpers that run with `nofault` set.
fn nofault_access_ip(ip: usize) -> bool {
    nofault_access_ips().contains(&ip)
}

/// One binding list for the handler, hosted test and linked-ELF verifier.
fn nofault_access_ips() -> [usize; 2] {
    [
        core::ptr::addr_of!(__zero_os_usercopy_get_u32_access) as usize,
        core::ptr::addr_of!(__zero_os_usercopy_cmpxchg_u32_access) as usize,
    ]
}

/// Exercise the Rust symbol bindings in the booted, relocated kernel too.
#[cfg(feature = "syscall_test")]
pub fn verify_nofault_bindings() {
    for access in nofault_access_ips() {
        assert!(nofault_access_ip(access));
        assert!(crate::exception_table::lookup(access).is_some());
        assert!(!nofault_access_ip(access - 1) && !nofault_access_ip(access + 1));
    }
    klog_always!("TD-USERCOPY-1: runtime nofault bindings verified");
}

/// H-26 FIX: Exception-safe byte read from user space
#[inline(always)]
unsafe fn copy_byte_from_user(dst: *mut u8, src: *const u8) -> Result<(), ()> {
    if __zero_os_usercopy_get_u8(dst, src) == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// Issue #109 §4.2: Boot-latched CR4.SMAP status shared by `UserAccessGuard`.
///
/// Published once by the BSP in `enable_protections()` and fail-closed verified
/// on every AP before online publication. Eliminates per-access `mov rax, cr4`
/// privileged reads on hot futex/syscall paths while staying safe in `--features kcov`
/// environments without SMAP.
static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Publish the BSP's latched CR4.SMAP enablement state for `UserAccessGuard`.
pub fn publish_smap_enabled(enabled: bool) {
    SMAP_ENABLED.store(enabled, Ordering::Release);
}

/// Return the boot-latched CR4.SMAP enablement state.
#[inline(always)]
pub fn smap_enabled_cached() -> bool {
    SMAP_ENABLED.load(Ordering::Relaxed)
}

/// User-copy state with PID binding for SMP safety (V-5 fix)
///
/// Each CPU maintains its own copy state via CpuLocal<T>, ensuring that
/// concurrent user copies on different CPUs do not interfere with each other.
///
/// H-26 FIX: Removed the `faulted` flag. Exception table fixups now handle
/// fault recovery directly in the assembly helpers.
/// Issue #109 §4.2: Removed write-only `remaining` field and downgraded per-CPU
/// stores from `SeqCst` (`LOCK XCHG`) to `Relaxed` payload + `Release`/`Acquire`
/// `active` gate with `compiler_fence(SeqCst)`.
struct UserCopyState {
    /// True if currently executing a user copy operation
    active: AtomicBool,
    /// PID that owns the active user copy (0 = none/kernel)
    pid: AtomicUsize,
    /// Inclusive start address of the current user buffer
    start: AtomicUsize,
    /// Exclusive end address of the current user buffer
    end: AtomicUsize,
    /// GAP-5 PI parity (review D2-1): the active access must not have its
    /// fault resolved (Linux `pagefault_disable`); see [`nofault_usercopy_fault`].
    nofault: AtomicBool,
}

impl UserCopyState {
    /// Create a new zeroed UserCopyState
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            pid: AtomicUsize::new(0),
            start: AtomicUsize::new(0),
            end: AtomicUsize::new(0),
            nofault: AtomicBool::new(false),
        }
    }
}

/// Per-CPU user copy state (V-5 fix)
///
/// Each CPU has its own UserCopyState, ensuring SMP-safe operation.
static USER_COPY_STATE: CpuLocal<UserCopyState> = CpuLocal::new(UserCopyState::new);

/// Per-CPU SMAP guard nesting depth counter (S-5 + V-5 fix)
///
/// Tracks how many UserAccessGuard instances are currently active on this CPU.
/// STAC is only executed when depth transitions 0→1.
/// CLAC is only executed when depth transitions 1→0.
///
/// Per-CPU storage ensures correct nesting behavior in SMP environments.
static SMAP_GUARD_DEPTH: CpuLocal<AtomicUsize> = CpuLocal::new(|| AtomicUsize::new(0));

#[inline(always)]
fn with_usercopy_state<R>(cpu_id: usize, f: impl FnOnce(&UserCopyState) -> R) -> R {
    // Fast path: after `force_init_usercopy_locals()`, direct index avoids a
    // redundant `current_cpu_id()` lookup. Falls back cleanly in hosted tests.
    let mut f = Some(f);
    if let Some(res) = USER_COPY_STATE.with_cpu(cpu_id, |s| (f.take().unwrap())(s)) {
        res
    } else {
        USER_COPY_STATE.with(|s| (f.take().unwrap())(s))
    }
}

#[inline(always)]
fn with_smap_depth<R>(cpu_id: usize, f: impl FnOnce(&AtomicUsize) -> R) -> R {
    let mut f = Some(f);
    if let Some(res) = SMAP_GUARD_DEPTH.with_cpu(cpu_id, |d| (f.take().unwrap())(d)) {
        res
    } else {
        SMAP_GUARD_DEPTH.with(|d| (f.take().unwrap())(d))
    }
}

/// R162-22 FIX: Force-initialize per-CPU usercopy locals before interrupts are
/// enabled. Without this, the first usercopy call from an IRQ context could
/// deadlock inside CpuLocal's lazy heap allocation.
pub fn force_init_usercopy_locals() {
    SMAP_GUARD_DEPTH.force_init();
    // R163-6 FIX: Also force-init USER_COPY_STATE, which is accessed from
    // the page fault handler (try_handle_usercopy_fault). Without this,
    // a page fault during the first usercopy triggers lazy heap allocation
    // inside exception context — potential deadlock if the allocator lock
    // is already held by the faulting path.
    USER_COPY_STATE.force_init();
}

/// Helper to get current process PID (0 if none)
#[inline]
fn current_pid_raw() -> usize {
    crate::process::current_pid().unwrap_or(0)
}

/// RAII guard to temporarily lift SMAP for intentional user memory access
///
/// When SMAP (Supervisor Mode Access Prevention) is enabled, the kernel cannot
/// directly read/write user memory. This guard uses STAC (Set AC flag) to
/// temporarily allow kernel access to user pages, and CLAC (Clear AC flag)
/// on drop to restore protection.
///
/// # Nesting Support (S-5 fix)
///
/// This guard supports nesting: only the outermost guard executes STAC/CLAC.
/// Nested guards simply increment/decrement a depth counter without affecting
/// the AC flag. This prevents the bug where nested guard drops would clear AC
/// prematurely (e.g., when `copy_user_str_array` calls `copy_user_cstring`).
///
/// # Interrupt Safety (R25-10 fix)
///
/// The outermost guard disables interrupts before executing STAC and restores
/// them after CLAC. This prevents interrupt handlers from running with the AC
/// flag set, which could allow unintended access to user memory.
///
/// # Safety
///
/// This guard should only be used around intentional user memory accesses
/// in controlled contexts (e.g., copy_from_user, copy_to_user).
#[must_use]
pub struct UserAccessGuard {
    /// Whether SMAP was active when the guard was created
    smap_active: bool,
    /// CPU this guard was created on (per-CPU depth must be balanced on same CPU)
    cpu_id: usize,
    /// Whether interrupts were enabled when the guard was created (R25-10 fix)
    /// Only meaningful for the outermost guard (when smap_active && is_outermost)
    interrupts_were_enabled: bool,
}

impl UserAccessGuard {
    /// Create a new guard that temporarily disables SMAP if active
    ///
    /// # Nesting Behavior
    ///
    /// - First guard (depth 0→1): Disables interrupts, executes STAC to disable SMAP
    /// - Nested guards (depth >1): Only increments counter, no STAC/interrupt change
    ///
    /// # R25-10 Fix
    ///
    /// Interrupts are disabled before STAC to prevent interrupt handlers from
    /// running with AC=1 (user access allowed).
    #[inline]
    pub fn new() -> Self {
        let smap_active = smap_enabled_cached();

        if smap_active {
            // R25-10 FIX: Disable interrupts before reading cpu_id or setting AC.
            let mut interrupts_were_enabled = x86_64::instructions::interrupts::are_enabled();
            if interrupts_were_enabled {
                x86_64::instructions::interrupts::disable();
            }
            let cpu_id = current_cpu_id();
            // Only execute STAC when this is the outermost guard (depth 0→1)
            // V-5 fix: Use per-CPU depth counter
            let prev_depth = with_smap_depth(cpu_id, |d| d.fetch_add(1, Ordering::Relaxed)); // lint-fetch-add: allow (per-CPU depth counter); R161-I5: Relaxed suffices (per-CPU, IRQ-disabled)
            if prev_depth == 0 {
                // Set AC flag to allow supervisor access to user pages
                unsafe {
                    core::arch::asm!("stac", options(nostack, nomem));
                }
            } else {
                interrupts_were_enabled = false;
            }
            UserAccessGuard {
                smap_active: true,
                cpu_id,
                interrupts_were_enabled,
            }
        } else {
            UserAccessGuard {
                smap_active: false,
                cpu_id: current_cpu_id(),
                interrupts_were_enabled: false,
            }
        }
    }

    /// Issue #109 §4.2: Acquire SMAP guard for usercopy only after proving the
    /// pinned CPU is running on a user address space (`active_cr3 != boot_cr3`).
    ///
    /// Interrupts are disabled BEFORE reading `cpu_id` and checking CR3 so no
    /// task migration can interpose between the check and `STAC`. On failure,
    /// interrupts are restored and `None` is returned without ever setting `AC`.
    #[inline]
    fn try_new_for_usercopy() -> Option<Self> {
        let smap_active = smap_enabled_cached();

        if smap_active {
            let mut interrupts_were_enabled = x86_64::instructions::interrupts::are_enabled();
            if interrupts_were_enabled {
                x86_64::instructions::interrupts::disable();
            }
            let cpu_id = current_cpu_id();
            if !ensure_user_address_space_active(cpu_id) {
                if interrupts_were_enabled {
                    x86_64::instructions::interrupts::enable();
                }
                return None;
            }
            let prev_depth = with_smap_depth(cpu_id, |d| d.fetch_add(1, Ordering::Relaxed)); // lint-fetch-add: allow (per-CPU depth counter); R161-I5: Relaxed suffices (per-CPU, IRQ-disabled)
            if prev_depth == 0 {
                unsafe {
                    core::arch::asm!("stac", options(nostack, nomem));
                }
            } else {
                interrupts_were_enabled = false;
            }
            Some(UserAccessGuard {
                smap_active: true,
                cpu_id,
                interrupts_were_enabled,
            })
        } else {
            let cpu_id = current_cpu_id();
            if !ensure_user_address_space_active(cpu_id) {
                return None;
            }
            Some(UserAccessGuard {
                smap_active: false,
                cpu_id,
                interrupts_were_enabled: false,
            })
        }
    }
}

impl Default for UserAccessGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UserAccessGuard {
    /// Drop the guard, restoring SMAP protection if this is the outermost guard
    ///
    /// # Nesting Behavior
    ///
    /// - Outermost guard (depth 1→0): Executes CLAC to re-enable SMAP, restores interrupts
    /// - Inner guards (depth >1): Only decrements counter, no CLAC/interrupt change
    ///
    /// # R25-10 Fix
    ///
    /// Interrupts are restored after CLAC to maintain the interrupt-disabled window
    /// around the AC=1 period.
    #[inline]
    fn drop(&mut self) {
        let current_cpu = current_cpu_id();

        // R106-7 FIX: Detect CPU migration and apply corrective CLAC instead of panicking.
        // In a non-preemptible kernel this should never happen, but if preemption is added
        // in the future, a panic here would be fatal. Instead, issue a corrective CLAC on
        // the current CPU to guarantee SMAP is re-enabled, and log a warning.
        if current_cpu != self.cpu_id {
            if self.smap_active {
                // Corrective: ensure SMAP is re-enabled on the current CPU regardless
                // of depth counter state. This may leave the original CPU's depth counter
                // incremented, but that's safer than leaving SMAP disabled anywhere.
                unsafe {
                    core::arch::asm!("clac", options(nostack, nomem));
                }
                // Best-effort: decrement the *current* CPU's depth counter if possible.
                // This is imprecise but prevents underflow assertion on subsequent guards.
                let cur_depth = SMAP_GUARD_DEPTH.with(|d| d.load(Ordering::Relaxed));
                if cur_depth > 0 {
                    SMAP_GUARD_DEPTH.with(|d| d.fetch_sub(1, Ordering::Relaxed));
                }
                if self.interrupts_were_enabled {
                    x86_64::instructions::interrupts::enable();
                }
            }
            kprintln!(
                "[usercopy] R106-7 WARNING: UserAccessGuard created on CPU {} dropped on CPU {}; \
                 corrective CLAC issued",
                self.cpu_id,
                current_cpu
            );
            return;
        }

        if self.smap_active {
            // Only execute CLAC when this is the outermost guard (depth 1→0)
            // V-5 fix: Use per-CPU depth counter
            // R163-I4 FIX: Check BEFORE atomic sub to avoid leaving the counter
            // at usize::MAX on underflow. The assert after fetch_sub would panic
            // anyway, but the counter state would be corrupted.
            let prev_depth = with_smap_depth(current_cpu, |d| {
                let cur_depth = d.load(Ordering::Relaxed);
                assert!(cur_depth > 0, "SMAP guard depth underflow");
                d.fetch_sub(1, Ordering::Relaxed)
            });
            if prev_depth == 1 {
                // Clear AC flag to restore SMAP protection
                unsafe {
                    core::arch::asm!("clac", options(nostack, nomem));
                }
                // R25-10 FIX: Restore interrupts after clearing AC flag
                // Only if they were enabled when we started
                if self.interrupts_were_enabled {
                    x86_64::instructions::interrupts::enable();
                }
            }
        }
    }
}

/// Check if a user copy is currently in progress for the current process
///
/// # PID Binding (H-36 fix)
///
/// Returns true only if:
/// 1. A usercopy is active, AND
/// 2. The active usercopy belongs to the current process
///
/// This prevents false positive fault detection in SMP scenarios where
/// one CPU might fault while another CPU is doing a usercopy.
///
/// # V-5 fix
///
/// Now uses per-CPU state, so each CPU only checks its own usercopy status.
#[inline]
pub fn is_in_usercopy() -> bool {
    let pid = current_pid_raw();
    USER_COPY_STATE
        .with(|s| s.active.load(Ordering::Acquire) && s.pid.load(Ordering::Relaxed) == pid)
}

// H-26 FIX: Removed set_usercopy_fault() and check_and_clear_fault()
// Exception table fixups now handle fault recovery directly in assembly helpers.

/// RAII guard for user copy state with PID binding
struct UserCopyGuard {
    /// CPU this guard was created on (per-CPU state lives in that CPU's slot)
    cpu_id: usize,
    /// PID that owns this usercopy operation.
    ///
    /// R108-2 FIX: Stored so migration-tolerant drop can clear the originating
    /// CPU's per-CPU state only if it still belongs to the same process.
    pid: usize,
}

impl UserCopyGuard {
    /// Create a new UserCopyGuard on `cpu_id`, registering the current copy operation.
    ///
    /// Issue #109 §4.2: Uses `Relaxed` stores for payload fields followed by
    /// `active.store(true, Release)` + `compiler_fence(SeqCst)` — zero `LOCK XCHG`
    /// hardware fences while preserving strict program-order visibility for
    /// same-CPU `#PF` and Release/Acquire visibility for cross-CPU cleanup.
    #[inline]
    fn new_on_cpu(cpu_id: usize, buffer_start: usize, len: usize, nofault: bool) -> Self {
        let pid = current_pid_raw();
        with_usercopy_state(cpu_id, |s| {
            s.pid.store(pid, Ordering::Relaxed);
            s.start.store(buffer_start, Ordering::Relaxed);
            s.end
                .store(buffer_start.saturating_add(len), Ordering::Relaxed);
            // GAP-5 PI review D2-1: faults resolve unless the helper opts out.
            s.nofault.store(nofault, Ordering::Relaxed);
            s.active.store(true, Ordering::Release);
        });
        compiler_fence(Ordering::SeqCst);
        UserCopyGuard { cpu_id, pid }
    }
}

impl Drop for UserCopyGuard {
    #[inline]
    fn drop(&mut self) {
        compiler_fence(Ordering::SeqCst);
        let current_cpu = current_cpu_id();

        // R108-2 FIX: Detect CPU migration and perform best-effort cleanup instead
        // of panicking.  Follows the same pattern as UserAccessGuard (R106-7 FIX).
        if current_cpu != self.cpu_id {
            let cleared = USER_COPY_STATE
                .with_cpu(self.cpu_id, |s| {
                    if !s.active.load(Ordering::Acquire)
                        || s.pid.load(Ordering::Relaxed) != self.pid
                    {
                        return false;
                    }
                    s.active.store(false, Ordering::Release);
                    s.pid.store(0, Ordering::Relaxed);
                    s.start.store(0, Ordering::Relaxed);
                    s.end.store(0, Ordering::Relaxed);
                    s.nofault.store(false, Ordering::Release);
                    true
                })
                .unwrap_or(false);

            kprintln!(
                "[usercopy] R108-2 WARNING: UserCopyGuard created on CPU {} dropped on CPU {} \
                 (pid={}); {}",
                self.cpu_id,
                current_cpu,
                self.pid,
                if cleared {
                    "stale per-CPU state cleared"
                } else {
                    "state not cleared (pid mismatch or CPU out of range)"
                }
            );
            return;
        }

        with_usercopy_state(current_cpu, |s| {
            s.active.store(false, Ordering::Release);
            s.pid.store(0, Ordering::Relaxed);
            s.start.store(0, Ordering::Relaxed);
            s.end.store(0, Ordering::Relaxed);
            s.nofault.store(false, Ordering::Relaxed);
        });
    }
}

/// User space address boundary (canonical lower half on x86_64)
pub const USER_SPACE_TOP: usize = 0x0000_8000_0000_0000;

/// R65-11 FIX: Minimum user-space mapping address.
///
/// Prevents NULL pointer dereference exploitation by disallowing mappings
/// at low addresses. A kernel NULL pointer bug can be exploited if user
/// space can map page 0 with controlled content.
///
/// 64KB is the Linux default (vm.mmap_min_addr). This prevents:
/// - Direct NULL dereference exploitation
/// - Near-NULL dereference exploitation (struct member access)
/// - Integer overflow to near-zero addresses
///
/// This should be enforced in both mmap and pointer validation.
pub const MMAP_MIN_ADDR: usize = 0x10000; // 64KB

/// R65-10 FIX: Maximum bytes to copy before yielding to interrupts.
///
/// When copying large buffers with interrupts disabled (SMAP mode), we risk
/// starving timer interrupts and causing scheduler/watchdog timeouts.
/// Copy in chunks and briefly re-enable interrupts between chunks.
///
/// 4KB (page size) is a good balance:
/// - Small enough to not noticeably delay timer interrupts (~1ms @ 1GHz)
/// - Large enough to amortize the interrupt enable/disable overhead
const USERCOPY_CHUNK_SIZE: usize = 4096;

/// P1-7: Smaller chunk size for user-string copy helpers.
///
/// String copies are byte-by-byte and run in hot syscall paths (open, exec).
/// Using a smaller SMAP window (256 bytes vs. 4KB) reduces the time spent
/// with interrupts disabled and SMAP bypassed.  Between chunks, interrupts
/// are re-enabled and per-CPU state is cleared, making migration safe.
const USERCOPY_STR_CHUNK_SIZE: usize = 256;

/// Check if a pointer is properly aligned for type T
#[inline]
fn is_aligned(ptr: usize, align: usize) -> bool {
    // Alignment must be power of 2; 0 or 1 means no alignment requirement
    if align <= 1 {
        return true;
    }
    debug_assert!(align.is_power_of_two(), "alignment must be power of two");
    ptr & (align - 1) == 0
}

/// Validate that an address range is in user space
///
/// # Arguments
/// * `ptr` - Starting address
/// * `len` - Length in bytes
///
/// # Returns
/// * `true` if the range [ptr, ptr+len) is entirely in valid user space
/// * `false` if null, below MMAP_MIN_ADDR, in kernel space, or would overflow
///
/// # Zero Length Handling
///
/// When `len == 0`, returns `true` if `ptr` is a valid non-null user-space
/// address. This allows validation of pointer-only operations where no
/// actual memory access will occur.
///
/// # R65-11 FIX: Minimum Address Check
///
/// Rejects pointers below MMAP_MIN_ADDR to prevent NULL dereference
/// exploitation attacks.
#[inline]
fn validate_user_range(ptr: usize, len: usize) -> bool {
    // Null pointer is always invalid
    if ptr == 0 {
        return false;
    }
    // R65-11 FIX: Reject pointers below MMAP_MIN_ADDR
    // This prevents NULL dereference exploitation
    if ptr < MMAP_MIN_ADDR {
        return false;
    }
    // Pointer must be in user space (below canonical hole)
    if ptr >= USER_SPACE_TOP {
        return false;
    }
    // Zero-length is valid if pointer itself is in user space
    // This enables pointer validation without actual access
    if len == 0 {
        return true;
    }
    // Check for overflow and ensure end is within user space
    // Note: end is exclusive, and USER_SPACE_TOP marks the start of
    // the canonical hole, so end must be strictly less than USER_SPACE_TOP
    match ptr.checked_add(len) {
        Some(end) => end < USER_SPACE_TOP, // Strict less-than (exclusive end)
        None => false,
    }
}

/// Validate that an address range is in user space with alignment check
///
/// Like `validate_user_range` but also checks alignment requirements.
#[inline]
fn validate_user_range_aligned(ptr: usize, len: usize, align: usize) -> bool {
    validate_user_range(ptr, len) && is_aligned(ptr, align)
}

/// Issue #109 §4.2 (Invariant S2): pure predicate checking that the active CR3
/// is a tracked user address space rather than the boot PML4 template (which
/// retains the 0-4 GiB supervisor identity map in PML4[0]).
#[inline(always)]
fn is_user_address_space_active(active_cr3: u64, boot_cr3: u64) -> bool {
    active_cr3 != 0 && boot_cr3 != 0 && active_cr3 != boot_cr3
}

/// Issue #109 §4.2 (Invariant S2): O(1) fail-closed non-boot-CR3 guard.
///
/// D0-ISO-1 Approach A removed all lower-half supervisor mappings from user
/// address spaces (verified by `PageTableManager` guards, `mitigation_probe`,
/// and Ring-3 `test_identity_map_boundary`), and `CR0.WP=1` is enforced on BSP
/// and every AP (R171-G1-1). Refusing `boot_cr3` (and untracked CR3 `0`) before
/// `STAC` replaces per-page 4-level software page-table walks on hot usercopy
/// paths while closing the only address space that retains a lower-half
/// supervisor identity map.
#[inline(always)]
fn ensure_user_address_space_active(cpu_id: usize) -> bool {
    let active_cr3 = mm::tlb_shootdown::tracked_cr3_for_cpu(cpu_id);
    let boot_cr3 = crate::process::boot_cr3_phys();
    is_user_address_space_active(active_cr3, boot_cr3)
}

// ============================================================================
// R102-I4 FIX: UserAddr — Provenance-Safe User-Space Address Wrapper
// ============================================================================

/// Provenance-safe user-space address wrapper.
///
/// Wraps a `usize` instead of a raw pointer to avoid Rust pointer provenance UB
/// when performing arithmetic on user-space addresses. User addresses are not
/// within any Rust allocation, so `ptr.add(offset)` is technically undefined
/// behavior under Rust's provenance model. `UserAddr` uses integer arithmetic
/// exclusively, side-stepping the issue.
///
/// # Design
///
/// `UserAddr` is intentionally minimal — it holds an untrusted address and
/// provides safe offset arithmetic. Validation (null checks, user-space range
/// checks, alignment) is performed by the usercopy functions that consume it,
/// not by `UserAddr` itself. This keeps the type lightweight and composable.
///
/// # Example
///
/// ```ignore
/// let addr = UserAddr::new(user_buf_ptr as usize);
/// let offset_addr = addr.checked_add(42).ok_or(())?;
/// copy_from_user_addr(&mut kernel_buf, addr)?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UserAddr(usize);

impl UserAddr {
    /// Create a new `UserAddr` from a raw address.
    ///
    /// No validation is performed here; the usercopy functions that consume
    /// this value will validate range and alignment as needed.
    #[inline]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    /// Return the underlying address as `usize`.
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Convert to a const raw pointer (for passing to assembly helpers).
    ///
    /// The returned pointer has no Rust provenance; it is manufactured from
    /// an integer. This is intentional — user addresses should never carry
    /// kernel provenance.
    #[inline]
    pub const fn as_const_ptr(self) -> *const u8 {
        self.0 as *const u8
    }

    /// Convert to a mut raw pointer (for passing to assembly helpers).
    #[inline]
    pub const fn as_mut_ptr(self) -> *mut u8 {
        self.0 as *mut u8
    }

    /// Checked offset: returns `None` on integer overflow.
    #[inline]
    pub const fn checked_add(self, offset: usize) -> Option<Self> {
        match self.0.checked_add(offset) {
            Some(addr) => Some(Self(addr)),
            None => None,
        }
    }

    /// R103-L1 FIX: Checked offset that returns `None` on overflow or if the
    /// result would land outside user-space.  Callers that need overflow detection
    /// (e.g., buffer-end computation) should use this instead of `wrapping_offset`.
    #[inline]
    pub fn checked_offset(self, off: usize) -> Option<Self> {
        let addr = self.0.checked_add(off)?;
        if addr >= USER_SPACE_TOP {
            return None;
        }
        Some(Self(addr))
    }

    /// Wrapping offset (matches the existing `wrapping_add` pattern in usercopy).
    ///
    /// R103-L1 FIX: Renamed from `offset` to `wrapping_offset` to clearly
    /// communicate the wrapping semantics. The old name `offset` is retained
    /// as a deprecated alias to avoid breaking existing callers.
    #[inline]
    pub const fn wrapping_offset(self, offset: usize) -> Self {
        Self(self.0.wrapping_add(offset))
    }

    /// Deprecated: use `wrapping_offset` (wrapping) or `checked_offset` (safe).
    #[deprecated(note = "R103-L1: use checked_offset() or wrapping_offset() instead")]
    #[inline]
    pub const fn offset(self, offset: usize) -> Self {
        self.wrapping_offset(offset)
    }
}

impl core::fmt::LowerHex for UserAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

/// Copy from user space to a kernel buffer using a provenance-safe `UserAddr`.
///
/// This is the recommended API for new code. It delegates to `copy_from_user_safe`
/// internally, converting the `UserAddr` to a raw pointer only at the FFI boundary.
#[inline]
pub fn copy_from_user_addr(dst: &mut [u8], src: UserAddr) -> Result<(), ()> {
    copy_from_user_safe(dst, src.as_const_ptr())
}

/// Copy from a kernel buffer to user space using a provenance-safe `UserAddr`.
///
/// This is the recommended API for new code. It delegates to `copy_to_user_safe`
/// internally, converting the `UserAddr` to a raw pointer only at the FFI boundary.
#[inline]
pub fn copy_to_user_addr(dst: UserAddr, src: &[u8]) -> Result<(), ()> {
    copy_to_user_safe(dst.as_mut_ptr(), src)
}

/// RF178-8: fault-tolerant, atomic-width futex-word read.
///
/// The aligned x86 dword load is a single-copy atomic observation. This helper
/// performs no page-table lookup and takes no blocking lock, so callers may use
/// it while holding a futex wait-queue lock with interrupts already disabled.
pub fn read_user_u32_atomic(src: UserAddr) -> Result<u32, ()> {
    read_user_u32_atomic_inner(src, false)
}

/// GAP-5 PI parity (review D2-1): [`read_user_u32_atomic`] whose fault is
/// never resolved (Linux `pagefault_disable` around `get_futex_value_locked`).
/// A futex holding its bucket lock, or `FUTEX_TABLE`, must not run the
/// copy-on-write or demand-fault paths (PT_LOCK, frame allocation, TLB
/// shootdown waits). Any fault returns `Err(())`; the caller drops its futex
/// locks, faults the page in with [`read_user_u32_atomic`] or
/// [`compare_exchange_user_u32`], and retries.
pub fn read_user_u32_atomic_nofault(src: UserAddr) -> Result<u32, ()> {
    read_user_u32_atomic_inner(src, true)
}

fn read_user_u32_atomic_inner(src: UserAddr, nofault: bool) -> Result<u32, ()> {
    let addr = src.as_usize();
    if addr & (core::mem::align_of::<u32>() - 1) != 0
        || !validate_user_range(addr, core::mem::size_of::<u32>())
    {
        return Err(());
    }

    let smap_guard = UserAccessGuard::try_new_for_usercopy().ok_or(())?;
    let _guard = UserCopyGuard::new_on_cpu(
        smap_guard.cpu_id,
        addr,
        core::mem::size_of::<u32>(),
        nofault,
    );

    let mut value = 0u32;
    let status =
        unsafe { __zero_os_usercopy_get_u32(&mut value, src.as_const_ptr().cast::<u32>()) };
    if status == 0 {
        Ok(value)
    } else {
        Err(())
    }
}

/// RF187-U34: fault-tolerant, atomic-width robust-list pointer read.
///
/// Robust-list pointers and the futex offset are 64-bit fields on x86_64.  A
/// single aligned load is required here for the same reason as the u32 futex
/// helper above: two narrower loads could observe a value that userspace never
/// published.  Mapping faults are converted to `Err(())` by the exception
/// table, so callers can abort the complete walk without risking a kernel fault.
pub fn read_user_u64_atomic(src: UserAddr) -> Result<u64, ()> {
    let addr = src.as_usize();
    if addr & (core::mem::align_of::<u64>() - 1) != 0
        || !validate_user_range(addr, core::mem::size_of::<u64>())
    {
        return Err(());
    }

    let smap_guard = UserAccessGuard::try_new_for_usercopy().ok_or(())?;
    let _guard =
        UserCopyGuard::new_on_cpu(smap_guard.cpu_id, addr, core::mem::size_of::<u64>(), false);

    let mut value = 0u64;
    let status =
        unsafe { __zero_os_usercopy_get_u64(&mut value, src.as_const_ptr().cast::<u64>()) };
    if status == 0 {
        Ok(value)
    } else {
        Err(())
    }
}

/// RF187-U34: fault-tolerant atomic compare-and-exchange of a user futex word.
///
/// `Ok(true)` means the word was replaced, `Ok(false)` means another thread
/// changed it before the exchange, and `Err(())` means the address faulted or
/// failed the range/alignment checks.  Callers must bound retries on `false` and
/// abort their walk on `Err(())`.
pub fn compare_exchange_user_u32(dst: UserAddr, expected: u32, desired: u32) -> Result<bool, ()> {
    compare_exchange_user_u32_inner(dst, expected, desired, false)
}

/// GAP-5 PI parity (review D2-1): [`compare_exchange_user_u32`] whose fault
/// (a copy-on-write word, a page not present) is never resolved, for use under
/// a futex lock (Linux `cmpxchg_futex_value_locked`). `Err(())` on any fault;
/// see [`read_user_u32_atomic_nofault`].
pub fn compare_exchange_user_u32_nofault(
    dst: UserAddr,
    expected: u32,
    desired: u32,
) -> Result<bool, ()> {
    compare_exchange_user_u32_inner(dst, expected, desired, true)
}

fn compare_exchange_user_u32_inner(
    dst: UserAddr,
    expected: u32,
    desired: u32,
    nofault: bool,
) -> Result<bool, ()> {
    let addr = dst.as_usize();
    if addr & (core::mem::align_of::<u32>() - 1) != 0
        || !validate_user_range(addr, core::mem::size_of::<u32>())
    {
        return Err(());
    }

    let smap_guard = UserAccessGuard::try_new_for_usercopy().ok_or(())?;
    let _guard = UserCopyGuard::new_on_cpu(
        smap_guard.cpu_id,
        addr,
        core::mem::size_of::<u32>(),
        nofault,
    );

    let observed = unsafe {
        __zero_os_usercopy_cmpxchg_u32(dst.as_mut_ptr().cast::<u32>(), expected, desired)
    };
    if observed & 0x1_0000_0000 != 0 {
        Err(())
    } else {
        Ok(observed as u32 == expected)
    }
}

/// Publish an aligned user word with one x86 store. A sibling can update the
/// word concurrently without changing the width or success of this store.
/// Copy-on-write and demand faults take the ordinary usercopy fault path.
pub fn write_user_u32_atomic(dst: UserAddr, value: u32) -> Result<(), ()> {
    let addr = dst.as_usize();
    let len = size_of::<u32>();
    if !validate_user_range_aligned(addr, len, align_of::<u32>()) {
        return Err(());
    }

    let smap_guard = UserAccessGuard::try_new_for_usercopy().ok_or(())?;
    let _guard = UserCopyGuard::new_on_cpu(smap_guard.cpu_id, addr, len, false);
    // SAFETY: the aligned word fits in one validated user page. The assembly
    // store has an exception-table fixup for a mapping that changes or faults.
    let status = unsafe { __zero_os_usercopy_put_u32(dst.as_mut_ptr().cast(), value) };
    if status == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// ST-K2-P2a: make the user page holding `addr` present for a later read or,
/// with `write`, write access, without changing its contents.
///
/// One guarded access to the page's first word goes through the ordinary #PF
/// path, which demand-installs a shared-anonymous page or breaks copy-on-write
/// exactly as it would for the caller's own copy; a fault it cannot resolve
/// returns `Err(())` through the exception table. A write uses
/// `lock cmpxchg` of 0 with 0 (as `fault_in_word` in the futex code does): it
/// needs write permission like any store, stores back the value it read, and is
/// atomic against concurrent user writers. The word is in the same page as
/// `addr`, so the same mapping and permissions govern it.
///
/// The caller must hold no lock that fault resolution takes (`PROCESS_TABLE`,
/// the current PCB, `MmState`, a shared region's slots, `PT_LOCK`, the buddy
/// allocator, a cgroup charge): a contended resolution is retried until it
/// succeeds, so a lock held on this CPU would never be released.
pub fn fault_in_user_page(addr: UserAddr, write: bool) -> Result<(), ()> {
    debug_assert_ne!(mm::pt_lock_owner_cpu(), Some(current_cpu_id()));
    let page = UserAddr::new(addr.as_usize() & !0xfff);
    if write {
        compare_exchange_user_u32(page, 0, 0).map(|_| ())
    } else {
        read_user_u32_atomic(page).map(|_| ())
    }
}

/// Fault-tolerant copy from user space to kernel buffer
///
/// This function handles page faults gracefully by returning EFAULT
/// instead of panicking. It copies one byte at a time to ensure
/// we can detect faults at any point.
///
/// # R65-10 FIX: Chunked Copy
///
/// For large buffers, copy in USERCOPY_CHUNK_SIZE chunks and briefly
/// re-enable interrupts between chunks. This prevents timer starvation
/// and scheduler delays during large copies.
///
/// # H-26 FIX: Exception Table EFAULT
///
/// Uses exception-safe assembly helpers that return error on fault instead
/// of terminating the process. The page fault handler rewrites RIP to the
/// fixup label when a fault occurs in the helper.
///
/// # Arguments
/// * `dst` - Destination kernel buffer
/// * `src` - Source user space pointer
///
/// # Returns
/// * `Ok(())` - Copy succeeded
/// * `Err(())` - Page fault occurred (EFAULT)
///
/// # Safety
/// The caller must ensure `dst` is a valid kernel buffer.
pub fn copy_from_user_safe(dst: &mut [u8], src: *const u8) -> Result<(), ()> {
    let len = dst.len();
    if len == 0 {
        return Ok(());
    }

    // Validate user pointer range
    let src_base = src as usize;
    if !validate_user_range(src_base, len) {
        return Err(());
    }

    let dst_ptr = dst.as_mut_ptr();

    // R65-10 FIX: Copy in chunks to allow interrupt servicing.
    // Issue #109 §4.2: Each 4 KiB chunk uses hardware-accelerated `rep movsb`
    // with exact `.ex_table` fault recovery and O(1) non-boot-CR3 verification.
    let mut offset = 0usize;
    while offset < len {
        let chunk_end = (offset + USERCOPY_CHUNK_SIZE).min(len);
        let chunk_len = chunk_end - offset;
        let user_chunk_start = src_base.wrapping_add(offset);

        let smap_guard = UserAccessGuard::try_new_for_usercopy().ok_or(())?;
        let _guard =
            UserCopyGuard::new_on_cpu(smap_guard.cpu_id, user_chunk_start, chunk_len, false);

        // SAFETY: user range validated in [MMAP_MIN_ADDR, USER_SPACE_TOP);
        // dst is a disjoint kernel slice; `.ex_table` recovers any user #PF.
        let remaining = unsafe {
            __zero_os_usercopy_copy_bytes(
                dst_ptr.add(offset),
                user_chunk_start as *const u8,
                chunk_len,
            )
        };
        if remaining != 0 {
            return Err(());
        }

        offset = chunk_end;

        // R65-10 FIX: SMAP guard and UserCopyGuard dropped here, clearing per-CPU
        // state before interrupts are re-enabled.  Migration is now safe.
    }

    Ok(())
}

/// Fault-tolerant copy from kernel buffer to user space
///
/// # R65-10 FIX: Chunked Copy
///
/// For large buffers, copy in USERCOPY_CHUNK_SIZE chunks and briefly
/// re-enable interrupts between chunks. This prevents timer starvation
/// and scheduler delays during large copies.
///
/// # H-26 FIX: Exception Table EFAULT
///
/// Uses exception-safe assembly helpers that return error on fault instead
/// of terminating the process.
///
/// # Arguments
/// * `dst` - Destination user space pointer
/// * `src` - Source kernel buffer
///
/// # Returns
/// * `Ok(())` - Copy succeeded
/// * `Err(())` - Page fault occurred (EFAULT)
pub fn copy_to_user_safe(dst: *mut u8, src: &[u8]) -> Result<(), ()> {
    let len = src.len();
    if len == 0 {
        return Ok(());
    }

    // Validate user pointer range
    let dst_base = dst as usize;
    if !validate_user_range(dst_base, len) {
        return Err(());
    }

    let src_ptr = src.as_ptr();

    // R65-10 FIX: Copy in chunks to allow interrupt servicing.
    // Issue #109 §4.2: Each 4 KiB chunk uses hardware-accelerated `rep movsb`
    // with CR0.WP=1 write protection, CoW/shared-anon #PF resume, and `.ex_table`
    // recovery on unmapped or non-COW read-only pages.
    let mut offset = 0usize;
    while offset < len {
        let chunk_end = (offset + USERCOPY_CHUNK_SIZE).min(len);
        let chunk_len = chunk_end - offset;
        let user_chunk_start = dst_base.wrapping_add(offset);

        let smap_guard = UserAccessGuard::try_new_for_usercopy().ok_or(())?;
        let _guard =
            UserCopyGuard::new_on_cpu(smap_guard.cpu_id, user_chunk_start, chunk_len, false);

        // SAFETY: user range validated in [MMAP_MIN_ADDR, USER_SPACE_TOP);
        // src is a disjoint kernel slice; `.ex_table` recovers any user #PF.
        let remaining = unsafe {
            __zero_os_usercopy_copy_bytes(
                user_chunk_start as *mut u8,
                src_ptr.add(offset),
                chunk_len,
            )
        };
        if remaining != 0 {
            return Err(());
        }

        offset = chunk_end;

        // R65-10 FIX: SMAP guard and UserCopyGuard dropped here, clearing per-CPU
        // state before interrupts are re-enabled.  Migration is now safe.
    }

    Ok(())
}

/// Try to handle a page fault that occurred during user copy
///
/// This should be called AFTER COW handling in the page_fault_handler.
///
/// # Arguments
/// * `fault_addr` - The address that caused the fault
///
/// # Returns
/// * `true` - Fault was in usercopy range; page_fault_handler may apply exception-table fixup
/// * `false` - Not a user copy fault, handle normally
///
/// # PID Binding (H-36 fix)
///
/// Only returns true if the faulting process owns the active usercopy.
/// This prevents incorrect fault attribution in SMP scenarios.
///
/// # V-5 fix
///
/// Uses per-CPU state, ensuring each CPU checks only its own usercopy status.
///
/// # H-26 FIX: Exception Table EFAULT
///
/// When this returns true, the page fault handler should consult the exception table
/// using the faulting RIP. If a fixup entry is found, rewrite RIP to the fixup and
/// return so the usercopy helper can return `Err(())` to the syscall layer (EFAULT).
pub fn try_handle_usercopy_fault(fault_addr: usize) -> bool {
    // Only handle user-space addresses
    if fault_addr >= USER_SPACE_TOP {
        return false;
    }

    let current = current_pid_raw();
    USER_COPY_STATE.with(|s| {
        if !s.active.load(Ordering::Acquire) {
            return false;
        }
        if s.pid.load(Ordering::Relaxed) != current {
            return false;
        }
        let start = s.start.load(Ordering::Relaxed);
        let end = s.end.load(Ordering::Relaxed);
        start != 0 && fault_addr >= start && fault_addr < end
    })
}

/// GAP-5 PI parity (review D2-1): whether a kernel-mode fault at `fault_addr`
/// belongs to this CPU's active no-fault user access
/// ([`read_user_u32_atomic_nofault`], [`compare_exchange_user_u32_nofault`]).
/// The page-fault handler then takes the exception-table fixup at once,
/// without resolving copy-on-write or demand faults.
///
/// TD-USERCOPY-1 FIX: only a fault raised by those helpers' access
/// instruction (`fault_ip`) qualifies. Another exception-table instruction
/// faulting on the range while the flag is set takes the ordinary path, so its
/// fault is resolved instead of turned into a spurious `EFAULT`.
pub fn nofault_usercopy_fault(fault_addr: usize, fault_ip: usize) -> bool {
    nofault_access_ip(fault_ip)
        && try_handle_usercopy_fault(fault_addr)
        && USER_COPY_STATE.with(|s| s.nofault.load(Ordering::Relaxed))
}

/// Maximum length for user-space C strings (paths, arguments)
pub const MAX_CSTRING_LEN: usize = 4096;

/// Fault-tolerant copy of a NUL-terminated string from user space
///
/// Copies bytes from user space until a NUL terminator is found or
/// MAX_CSTRING_LEN is reached. Returns the string bytes WITHOUT the NUL.
///
/// # Arguments
/// * `src` - Source user space pointer to NUL-terminated string
///
/// # Returns
/// * `Ok(Vec<u8>)` - String bytes (not including NUL terminator)
/// * `Err(())` - Page fault occurred, null pointer, or string too long
///
/// # Security (Z-3 fix)
///
/// This function uses fault-tolerant byte-by-byte copy to safely handle:
/// - Unmapped user memory (returns EFAULT instead of kernel panic)
/// - TOCTOU attacks where memory is unmapped during copy
/// - Overly long strings (bounded by MAX_CSTRING_LEN)
pub fn copy_user_cstring(src: *const u8) -> Result<alloc::vec::Vec<u8>, ()> {
    use alloc::vec::Vec;

    if src.is_null() {
        return Err(());
    }

    // Validate that starting address is in user space
    let start_addr = src as usize;
    // R159-10 FIX: Reject addresses below MMAP_MIN_ADDR, matching
    // validate_user_range. Prevents reads near address zero with SMAP bypassed.
    if start_addr < MMAP_MIN_ADDR || start_addr >= USER_SPACE_TOP {
        return Err(());
    }

    // R160-18 FIX: Fallible allocation (with_capacity is infallible).
    let mut result = Vec::new();
    if result.try_reserve(256).is_err() {
        return Err(());
    }
    let mut offset = 0usize;

    // P1-7: Chunked SMAP windows for string copies.  Each chunk scopes its
    // own UserAccessGuard (STAC/CLAC) and UserCopyGuard (per-CPU fault state).
    // Between chunks, interrupts are re-enabled and per-CPU state is cleared,
    // making task migration safe (same pattern as R109-1 fix for bulk copies).
    //
    // R181-2 CONTRACT: this chunked copy is NOT an atomic snapshot of user
    // memory. A concurrent thread that munmap/mmap-races or plain-stores into
    // the source range can make later chunks observe different content than
    // earlier chunks (a "hybrid" string). This is the same contract as Linux
    // strncpy_from_user: NO copy-from-user primitive is atomic against other
    // user threads — even a single-chunk copy races byte-by-byte with stores
    // from another CPU, so holding SMAP/IRQ-off across the whole string would
    // not close the window (and would trade an integrity non-issue for an
    // unbounded IRQ-off DoS, violating Safety > Efficiency > Speed). Kernel
    // safety is preserved unconditionally: every chunk re-validates its own
    // mapping (EFAULT on unmap), bounds are checked per byte, and the result
    // is treated as untrusted userspace bytes by every consumer. Consumers
    // that need semantic validity (e.g. exec's argv/envp) MUST validate the
    // COPIED buffer, never re-read user memory (single-fetch rule).
    //
    // R110-1 FIX: Copy bytes into a stack-local buffer inside the SMAP window,
    // then extend the Vec *outside* the window.  This avoids heap allocation
    // (Vec growth/realloc) while interrupts are disabled and SMAP is bypassed.
    while offset < MAX_CSTRING_LEN {
        let chunk_end = (offset + USERCOPY_STR_CHUNK_SIZE).min(MAX_CSTRING_LEN);
        let chunk_start = match start_addr.checked_add(offset) {
            Some(addr) if addr < USER_SPACE_TOP => addr,
            _ => return Err(()),
        };

        let chunk_len = chunk_end - offset;
        let mut chunk_buf = [0u8; USERCOPY_STR_CHUNK_SIZE];
        let mut chunk_count = 0usize;
        let mut found_nul = false;

        // Scoped: SMAP guard + fault-tracking state live only for this chunk.
        // No heap allocation occurs inside this block.
        {
            let smap_guard = UserAccessGuard::try_new_for_usercopy().ok_or(())?;
            let _guard =
                UserCopyGuard::new_on_cpu(smap_guard.cpu_id, chunk_start, chunk_len, false);

            for i in offset..chunk_end {
                // Validate each byte address is still in user space
                let byte_addr = match start_addr.checked_add(i) {
                    Some(addr) if addr < USER_SPACE_TOP => addr,
                    _ => return Err(()),
                };

                // H-26 FIX: Read using exception-safe helper
                let mut byte = 0u8;
                unsafe { copy_byte_from_user(&mut byte as *mut u8, byte_addr as *const u8) }?;

                // NUL terminator found - done
                if byte == 0 {
                    found_nul = true;
                    break;
                }

                chunk_buf[chunk_count] = byte;
                chunk_count += 1;
            }
            // Guards dropped here: CLAC executed, interrupts re-enabled.
        }

        // R161-5 FIX: Fallible allocation before extend. The initial
        // try_reserve(256) only covers the first 256 bytes; strings up to
        // MAX_CSTRING_LEN (4096) caused infallible Vec growth via
        // extend_from_slice, which panics under OOM.
        if chunk_count > 0 {
            if result.try_reserve(chunk_count).is_err() {
                return Err(());
            }
            result.extend_from_slice(&chunk_buf[..chunk_count]);
        }

        if found_nul {
            return Ok(result);
        }

        offset = chunk_end;
    }

    // String too long (no NUL found within MAX_CSTRING_LEN)
    Err(())
}

// ============================================================================
// Type-Safe User Pointer API (A.1 Security Hardening)
// ============================================================================

/// Error type for usercopy operations
///
/// This is a simple unit error type. Callers should convert to appropriate
/// syscall error codes (typically EFAULT) at the syscall boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsercopyError;

/// Type-safe wrapper for a single user-space object pointer
///
/// `UserPtr<T>` enforces:
/// - Non-null pointer
/// - Address within user space bounds
/// - Proper alignment for type T
/// - T must be Copy (safe to bitwise copy)
///
/// # Example
///
/// ```ignore
/// // In syscall handler:
/// let user_ptr = UserPtr::<u64>::new(arg as *mut u64)?;
/// let mut value: u64 = 0;
/// copy_from_user(&mut value, user_ptr)?;
/// ```
///
/// # Security
///
/// This type prevents common user pointer bugs:
/// - Null pointer dereference (validated at construction)
/// - Kernel pointer confusion (must be below USER_SPACE_TOP)
/// - Alignment violations (checked against align_of::<T>())
/// - Type confusion (enforced by generic parameter)
#[derive(Debug)]
pub struct UserPtr<T: Copy> {
    ptr: *mut T,
    _marker: PhantomData<T>,
}

// SAFETY: UserPtr only holds a user-space address, not actual data.
// The pointer is validated to be in user space at construction.
// Sending the address between threads is safe; actual access requires
// proper synchronization through the copy functions.
unsafe impl<T: Copy> Send for UserPtr<T> {}
unsafe impl<T: Copy> Sync for UserPtr<T> {}

impl<T: Copy> Clone for UserPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Copy> Copy for UserPtr<T> {}

impl<T: Copy> UserPtr<T> {
    /// Create a new UserPtr from a mutable raw pointer
    ///
    /// Validates that the pointer is:
    /// - Non-null
    /// - Within user space address range
    /// - Properly aligned for type T
    /// - Has room for size_of::<T>() bytes
    ///
    /// # Errors
    ///
    /// Returns `UsercopyError` if validation fails.
    pub fn new(ptr: *mut T) -> Result<Self, UsercopyError> {
        if ptr.is_null() {
            return Err(UsercopyError);
        }

        let addr = ptr as usize;
        let size = size_of::<T>();
        let align = align_of::<T>();

        // Validate address range and alignment
        // For ZSTs (size == 0), we still validate the pointer is in user space
        if !validate_user_range_aligned(addr, size, align) {
            return Err(UsercopyError);
        }

        Ok(Self {
            ptr,
            _marker: PhantomData,
        })
    }

    /// Create a UserPtr from a const raw pointer (read-only access)
    ///
    /// This is useful when you only need to read from user space.
    /// The internal representation is mutable for API uniformity,
    /// but the source being const signals read-only intent.
    pub fn from_const(ptr: *const T) -> Result<Self, UsercopyError> {
        Self::new(ptr as *mut T)
    }

    /// Get the underlying pointer as const
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr as *const T
    }

    /// Get the underlying pointer as mutable
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr
    }

    /// Get the address as usize
    #[inline]
    pub fn addr(&self) -> usize {
        self.ptr as usize
    }

    /// Offset the pointer by a given number of elements
    ///
    /// Returns `UsercopyError` if the result would overflow or
    /// exceed user space bounds.
    pub fn offset(&self, count: isize) -> Result<Self, UsercopyError> {
        let elem_size = size_of::<T>();
        let offset_bytes = (count as isize)
            .checked_mul(elem_size as isize)
            .ok_or(UsercopyError)?;

        // R161-I1 FIX: Use checked_neg to avoid overflow on isize::MIN
        let new_addr = if offset_bytes >= 0 {
            self.addr().checked_add(offset_bytes as usize)
        } else {
            let pos = offset_bytes.checked_neg().ok_or(UsercopyError)? as usize;
            self.addr().checked_sub(pos)
        }
        .ok_or(UsercopyError)?;

        Self::new(new_addr as *mut T)
    }
}

/// Type-safe wrapper for a user-space slice pointer
///
/// `UserSlice<T>` enforces:
/// - Non-null base pointer
/// - Base address within user space bounds
/// - Proper alignment for type T
/// - Total byte count doesn't overflow
/// - Entire range is within user space
///
/// # Example
///
/// ```ignore
/// // In syscall handler:
/// let user_buf = UserSlice::<u8>::new(buf as *mut u8, len)?;
/// let mut kernel_buf = vec![0u8; len];
/// let copied = copy_from_user_slice(&mut kernel_buf, user_buf)?;
/// ```
#[derive(Debug)]
pub struct UserSlice<T: Copy> {
    ptr: *mut T,
    len: usize,
    _marker: PhantomData<T>,
}

unsafe impl<T: Copy> Send for UserSlice<T> {}
unsafe impl<T: Copy> Sync for UserSlice<T> {}

impl<T: Copy> Clone for UserSlice<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Copy> Copy for UserSlice<T> {}

impl<T: Copy> UserSlice<T> {
    /// Create a new UserSlice from a raw pointer and element count
    ///
    /// Validates that:
    /// - Base pointer is non-null
    /// - Base is within user space and properly aligned
    /// - Total byte size (len * size_of::<T>()) doesn't overflow
    /// - Entire range [ptr, ptr + len*sizeof(T)) is in user space
    ///
    /// # Arguments
    /// * `ptr` - Base pointer to the slice
    /// * `len` - Number of elements (not bytes)
    ///
    /// # Errors
    ///
    /// Returns `UsercopyError` if validation fails.
    pub fn new(ptr: *mut T, len: usize) -> Result<Self, UsercopyError> {
        if ptr.is_null() {
            return Err(UsercopyError);
        }

        let addr = ptr as usize;
        let elem_size = size_of::<T>();
        let align = align_of::<T>();

        // Calculate total byte size, checking for overflow
        let byte_len = elem_size.checked_mul(len).ok_or(UsercopyError)?;

        // Validate the entire range
        if !validate_user_range_aligned(addr, byte_len, align) {
            return Err(UsercopyError);
        }

        Ok(Self {
            ptr,
            len,
            _marker: PhantomData,
        })
    }

    /// Create a UserSlice from const pointers (read-only access)
    pub fn from_const(ptr: *const T, len: usize) -> Result<Self, UsercopyError> {
        Self::new(ptr as *mut T, len)
    }

    /// Get the number of elements
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the slice is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the total byte size
    ///
    /// This is guaranteed not to overflow because the constructor validates
    /// that `len * size_of::<T>()` fits within user space bounds.
    #[inline]
    pub fn byte_len(&self) -> usize {
        // Use saturating_mul as defense-in-depth, though the constructor
        // already validated this won't overflow
        self.len.saturating_mul(size_of::<T>())
    }

    /// Get the base pointer as const
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr as *const T
    }

    /// Get the base pointer as mutable
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr
    }

    /// Get the base address as usize
    #[inline]
    pub fn addr(&self) -> usize {
        self.ptr as usize
    }
}

// ============================================================================
// Generic Copy Functions
// ============================================================================

/// Copy a single typed value from user space
///
/// # Type Safety
///
/// The `UserPtr<T>` wrapper ensures:
/// - The pointer is properly aligned for T
/// - The pointer is in user space
/// - There is room for size_of::<T>() bytes
///
/// # Arguments
/// * `dst` - Destination kernel buffer
/// * `src` - Source user space pointer (validated)
///
/// # Errors
///
/// Returns `UsercopyError` if:
/// - A page fault occurs during the copy
/// - The user memory is not mapped or readable
pub fn copy_from_user<T: Copy>(dst: &mut T, src: UserPtr<T>) -> Result<(), UsercopyError> {
    let size = size_of::<T>();
    if size == 0 {
        // ZST: nothing to copy
        return Ok(());
    }

    // SAFETY: dst is a valid kernel reference, size matches T
    // lint-repr-c-copy: allow (generic typed usercopy; user→kernel direction, no kernel info leak)
    let dst_bytes = unsafe { core::slice::from_raw_parts_mut(dst as *mut T as *mut u8, size) };

    copy_from_user_safe(dst_bytes, src.as_ptr() as *const u8).map_err(|_| UsercopyError)
}

/// Copy a single typed value to user space
///
/// # Type Safety
///
/// The `UserPtr<T>` wrapper ensures:
/// - The pointer is properly aligned for T
/// - The pointer is in user space
/// - There is room for size_of::<T>() bytes
///
/// # Arguments
/// * `dst` - Destination user space pointer (validated)
/// * `src` - Source kernel value
///
/// # Errors
///
/// Returns `UsercopyError` if:
/// - A page fault occurs during the copy
/// - The user memory is not mapped or writable
/// - COW page could not be resolved
pub fn copy_to_user<T: Copy>(dst: UserPtr<T>, src: &T) -> Result<(), UsercopyError> {
    let size = size_of::<T>();
    if size == 0 {
        // ZST: nothing to copy
        return Ok(());
    }

    // SAFETY: src is a valid kernel reference, size matches T
    // lint-repr-c-copy: allow (generic typed usercopy; callers must ensure T has no uninitialized padding for kernel→user)
    let src_bytes = unsafe { core::slice::from_raw_parts(src as *const T as *const u8, size) };

    copy_to_user_safe(dst.as_mut_ptr() as *mut u8, src_bytes).map_err(|_| UsercopyError)
}

/// Copy bytes from user space slice to kernel buffer
///
/// Copies up to `min(dst.len(), src.len())` bytes.
///
/// # Arguments
/// * `dst` - Destination kernel buffer
/// * `src` - Source user space slice (validated)
///
/// # Returns
/// * `Ok(n)` - Number of bytes successfully copied
/// * `Err(UsercopyError)` - Copy failed (page fault, unmapped, etc.)
pub fn copy_from_user_slice(dst: &mut [u8], src: UserSlice<u8>) -> Result<usize, UsercopyError> {
    if dst.is_empty() || src.is_empty() {
        return Ok(0);
    }

    let to_copy = dst.len().min(src.len());

    copy_from_user_safe(&mut dst[..to_copy], src.as_ptr() as *const u8)
        .map(|_| to_copy)
        .map_err(|_| UsercopyError)
}

/// Copy bytes from kernel buffer to user space slice
///
/// Copies up to `min(dst.len(), src.len())` bytes.
///
/// # Arguments
/// * `dst` - Destination user space slice (validated)
/// * `src` - Source kernel buffer
///
/// # Returns
/// * `Ok(n)` - Number of bytes successfully copied
/// * `Err(UsercopyError)` - Copy failed (page fault, unmapped, etc.)
pub fn copy_to_user_slice(dst: UserSlice<u8>, src: &[u8]) -> Result<usize, UsercopyError> {
    if dst.is_empty() || src.is_empty() {
        return Ok(0);
    }

    let to_copy = dst.len().min(src.len());

    copy_to_user_safe(dst.as_mut_ptr() as *mut u8, &src[..to_copy])
        .map(|_| to_copy)
        .map_err(|_| UsercopyError)
}

/// Copy a NUL-terminated string from user space into a fixed-size kernel buffer
///
/// Unlike `copy_user_cstring`, this function:
/// - Copies into a caller-provided buffer (no heap allocation)
/// - Returns the number of bytes copied (excluding NUL)
/// - Writes NUL terminator to dst if found within bounds
///
/// # Arguments
/// * `dst` - Destination kernel buffer
/// * `src` - Source user space pointer to start of string
///
/// # Returns
/// * `Ok(n)` - `n` bytes copied (excluding NUL); dst[n] == 0 if NUL was found
/// * `Err(UsercopyError)` - Page fault or other error
///
/// # Behavior
///
/// - Copies at most `min(dst.len() - 1, MAX_CSTRING_LEN)` bytes (DoS protection)
/// - If NUL is found within the limit, dst is NUL-terminated
/// - If NUL is not found, all copied bytes are in dst without NUL
///   (caller should check if result == max_copy)
///
/// # Security
///
/// This function is safe against:
/// - TOCTOU attacks (fault-tolerant byte-by-byte copy)
/// - Buffer overflow (bounded by dst.len())
/// - DoS attacks (bounded by MAX_CSTRING_LEN)
/// - Kernel pointer confusion (UserPtr validation)
pub fn strncpy_from_user(dst: &mut [u8], src: UserPtr<u8>) -> Result<usize, UsercopyError> {
    if dst.is_empty() {
        return Ok(0);
    }

    // Reserve space for NUL and cap at MAX_CSTRING_LEN to prevent DoS
    let max_copy = dst.len().saturating_sub(1).min(MAX_CSTRING_LEN);
    if max_copy == 0 {
        dst[0] = 0;
        return Ok(0);
    }

    let start_addr = src.addr();
    let mut copied = 0usize;
    let dst_ptr = dst.as_mut_ptr();
    let mut offset = 0usize;

    // P1-7: Chunked SMAP windows for string copies.  Each chunk scopes its
    // own UserAccessGuard (STAC/CLAC) and UserCopyGuard (per-CPU fault state).
    // Between chunks, interrupts are re-enabled and per-CPU state is cleared,
    // making task migration safe (same pattern as R109-1 fix for bulk copies).
    while offset < max_copy {
        let chunk_end = (offset + USERCOPY_STR_CHUNK_SIZE).min(max_copy);
        let chunk_start = match start_addr.checked_add(offset) {
            Some(addr) if addr < USER_SPACE_TOP => addr,
            _ => return Err(UsercopyError),
        };

        // Scoped: SMAP guard + fault-tracking state live only for this chunk.
        let smap_guard = UserAccessGuard::try_new_for_usercopy().ok_or(UsercopyError)?;
        let _guard =
            UserCopyGuard::new_on_cpu(smap_guard.cpu_id, chunk_start, chunk_end - offset, false);

        for i in offset..chunk_end {
            // Calculate byte address with overflow check
            let byte_addr = match start_addr.checked_add(i) {
                Some(addr) if addr < USER_SPACE_TOP => addr,
                _ => return Err(UsercopyError),
            };

            // H-26 FIX: Read using exception-safe helper
            unsafe { copy_byte_from_user(dst_ptr.add(i), byte_addr as *const u8) }
                .map_err(|_| UsercopyError)?;

            // NUL terminator found
            if dst[i] == 0 {
                return Ok(copied);
            }

            copied += 1;
        }
        // Guards dropped here: CLAC executed, interrupts re-enabled.
        // Migration between chunks is safe (no active per-CPU state).

        offset = chunk_end;
    }

    // Reached max_copy without finding NUL
    // Do NOT write NUL - caller should check if returned == max_copy
    Ok(copied)
}

#[cfg(test)]
mod robust_usercopy_tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn ksa002_cmpxchg_mapped_success_and_mismatch() {
        let mut word = u32::MAX;
        let observed = unsafe { __zero_os_usercopy_cmpxchg_u32(&mut word, u32::MAX, 17) };
        assert_eq!(observed, u64::from(u32::MAX));
        assert_eq!(word, 17);
        let observed = unsafe { __zero_os_usercopy_cmpxchg_u32(&mut word, 18, u32::MAX) };
        assert_eq!(observed, 17);
        assert_eq!(word, 17);
        let observed = unsafe { __zero_os_usercopy_cmpxchg_u32(&mut word, 17, 0) };
        assert_eq!(observed, 17);
        assert_eq!(word, 0);
    }

    #[test]
    fn td_usercopy_1_nofault_arm_matches_only_the_access_instructions() {
        let get_u32 = __zero_os_usercopy_get_u32 as *const () as usize;
        let cmpxchg_u32 = __zero_os_usercopy_cmpxchg_u32 as *const () as usize;
        // Bind to assembler labels rather than an assumed instruction length.
        for access in nofault_access_ips() {
            assert!(nofault_access_ip(access));
            assert!(!nofault_access_ip(access - 1));
            assert!(!nofault_access_ip(access + 1));
        }
        assert!(!nofault_access_ip(cmpxchg_u32));
        for other in [
            __zero_os_usercopy_get_u8 as *const () as usize,
            __zero_os_usercopy_get_u64 as *const () as usize,
            __zero_os_usercopy_put_u8 as *const () as usize,
            __zero_os_usercopy_put_u32 as *const () as usize,
            get_u32 + 1,
        ] {
            assert!(!nofault_access_ip(other));
        }
    }

    #[test]
    fn robust_atomic_helpers_reject_invalid_ranges_before_assembly() {
        // Below MMAP_MIN_ADDR and misaligned addresses must be rejected without
        // touching the exception-table helpers. This is the cheap first layer;
        // mapped-but-faulting addresses are covered by the no-fault assembly in
        // the target/boot test suite.
        assert!(read_user_u64_atomic(UserAddr::new(MMAP_MIN_ADDR - 8)).is_err());
        assert!(read_user_u64_atomic(UserAddr::new(MMAP_MIN_ADDR + 1)).is_err());
        assert!(compare_exchange_user_u32(UserAddr::new(MMAP_MIN_ADDR + 1), 1, 2).is_err());
        assert!(write_user_u32_atomic(UserAddr::new(MMAP_MIN_ADDR - 8), 0).is_err());
        assert!(write_user_u32_atomic(UserAddr::new(MMAP_MIN_ADDR + 1), 0).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn c3_put_u32_writes_only_the_destination_word() {
        for value in [0, 0x501, u32::MAX] {
            let mut words = [17u32, !value, 23];
            // SAFETY: the destination is a live, aligned, writable u32.
            assert_eq!(
                unsafe { __zero_os_usercopy_put_u32(&mut words[1], value) },
                0
            );
            assert_eq!(words, [17, value, 23]);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn c3_put_u32_publishes_whole_words_under_contention() {
        extern crate std;
        use core::sync::atomic::AtomicU32;
        use std::{sync::Barrier, thread};

        const TID: u32 = 0x0101_0501;
        const CLEARS: usize = 200_000;
        let word = AtomicU32::new(TID);
        let ready = Barrier::new(2);
        thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let first = word.load(Ordering::Relaxed);
                ready.wait();
                for _ in 0..CLEARS {
                    // Inspect the previous value and race the next kernel store.
                    let value = word.swap(TID, Ordering::Relaxed);
                    assert!(value == TID || value == 0, "read a partial TID {value:#x}");
                }
                first
            });
            ready.wait();
            for _ in 0..CLEARS {
                // SAFETY: the shared atomic stays aligned and live through the join.
                assert_eq!(unsafe { __zero_os_usercopy_put_u32(word.as_ptr(), 0) }, 0);
            }
            assert_eq!(reader.join().expect("reader thread"), TID);
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn issue109_4_2_copy_bytes_mapped_sizes_and_alignments() {
        let mut src = [0u8; 4096 + 31];
        for (i, byte) in src.iter_mut().enumerate() {
            *byte = ((i * 73) ^ (i >> 3) ^ 0x5A) as u8;
        }
        for &(src_off, dst_off, len) in &[
            (0usize, 0usize, 0usize),
            (0, 0, 1),
            (3, 5, 7),
            (1, 7, 64),
            (13, 2, 255),
            (0, 0, 4096),
            (7, 11, 4096),
        ] {
            let mut dst = [0xCCu8; 4096 + 31];
            let rem = unsafe {
                __zero_os_usercopy_copy_bytes(
                    dst.as_mut_ptr().add(dst_off),
                    src.as_ptr().add(src_off),
                    len,
                )
            };
            assert_eq!(rem, 0, "mapped copy_bytes must return 0 remaining");
            assert_eq!(&dst[dst_off..dst_off + len], &src[src_off..src_off + len]);
            assert!(dst[..dst_off].iter().all(|&b| b == 0xCC));
            assert!(dst[dst_off + len..].iter().all(|&b| b == 0xCC));
        }
        // Also verify copy_bytes is NOT matched by nofault_access_ip (TD-USERCOPY-1).
        assert!(!nofault_access_ip(
            __zero_os_usercopy_copy_bytes as *const () as usize
        ));
    }

    #[test]
    fn issue109_4_2_boot_root_guard_rejects_boot_and_untracked_cr3() {
        assert!(!is_user_address_space_active(0, 0));
        assert!(!is_user_address_space_active(0, 0x10_0000));
        assert!(!is_user_address_space_active(0x10_0000, 0));
        assert!(!is_user_address_space_active(0x10_0000, 0x10_0000));
        assert!(is_user_address_space_active(0x20_0000, 0x10_0000));
        // In hosted tests without a tracked user CR3, bulk copies fail closed
        // before attempting any memory access.
        let mut buf = [0u8; 8];
        assert!(copy_from_user_safe(&mut buf, MMAP_MIN_ADDR as *const u8).is_err());
        assert!(copy_to_user_safe(MMAP_MIN_ADDR as *mut u8, &buf).is_err());
    }

    #[test]
    fn issue109_4_2_validate_user_range_rejects_boundaries_and_overflow() {
        assert!(!validate_user_range(0, 1));
        assert!(!validate_user_range(MMAP_MIN_ADDR - 1, 1));
        assert!(validate_user_range(MMAP_MIN_ADDR, 0));
        assert!(validate_user_range(MMAP_MIN_ADDR, 4096));
        assert!(validate_user_range(USER_SPACE_TOP - 1, 0));
        assert!(!validate_user_range(USER_SPACE_TOP - 1, 1));
        assert!(!validate_user_range(USER_SPACE_TOP, 1));
        assert!(!validate_user_range(USER_SPACE_TOP - 8, 16));
        assert!(!validate_user_range(MMAP_MIN_ADDR, usize::MAX));
    }
}
