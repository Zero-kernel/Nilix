//! Seccomp/Pledge types and data structures.
//!
//! This module defines the core types for syscall filtering:
//! - BPF-like instruction set for flexible filtering
//! - Pledge promises for OpenBSD-style sandboxing
//! - Filter state management

#![allow(dead_code)]

extern crate alloc;

use alloc::alloc::Global;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::bitflags;
use core::alloc::{AllocError, Allocator, Layout};
use core::fmt;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use mm::{
    arc_charge_bytes, try_reserve_heap, vec_charge_bytes, AdmittedVec, HeapCharge, HeapClass,
};
use spin::Mutex;

// ============================================================================
// Charged Seccomp Filter Arc Allocator (RF180-28)
// ============================================================================

/// Every Arc charge is at least the two Arc counters plus allocator-link slack,
/// or four machine words. Consequently this table can represent every filter
/// Arc that the CoreProcess byte gate could admit; it does not impose a smaller
/// object-count limit than the authoritative byte ledger.
const SECCOMP_ARC_CHARGE_SLOTS: usize =
    HeapClass::CoreProcess.limit_bytes() / (4 * size_of::<usize>());

struct SeccompArcChargeSlot {
    generation: u64,
    allocated: bool,
    charge: HeapCharge,
}

static SECCOMP_ARC_CHARGES: Mutex<[Option<SeccompArcChargeSlot>; SECCOMP_ARC_CHARGE_SLOTS]> =
    Mutex::new([const { None }; SECCOMP_ARC_CHARGE_SLOTS]);
static NEXT_SECCOMP_ARC_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Allocator capability carried by every strong and weak filter handle.
///
/// RF180-28 FIX: `SeccompFilter` is destroyed at the last strong reference,
/// but the Arc control block remains allocated while any Weak exists. Keeping
/// the charge in this fixed slot until `Allocator::deallocate` accounts for the
/// complete physical lifetime without allocating bookkeeping recursively.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SeccompArcAllocator {
    slot: u16,
    generation: u64,
}

impl SeccompArcAllocator {
    fn try_install(charge: HeapCharge) -> Result<Self, HeapCharge> {
        let generation = match NEXT_SECCOMP_ARC_GENERATION.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(generation) => generation,
            Err(_) => return Err(charge),
        };

        let mut charge = Some(charge);
        let mut slots = SECCOMP_ARC_CHARGES.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(SeccompArcChargeSlot {
                    generation,
                    allocated: false,
                    charge: charge.take().expect("seccomp Arc charge moved once"),
                });
                return Ok(Self {
                    slot: index as u16,
                    generation,
                });
            }
        }
        Err(charge.expect("seccomp Arc slot scan retained charge"))
    }

    fn take_charge(self) -> HeapCharge {
        let mut slots = SECCOMP_ARC_CHARGES.lock();
        let slot = slots
            .get_mut(self.slot as usize)
            .expect("RF180-28 seccomp Arc allocator slot out of range");
        match slot.as_ref() {
            Some(entry) if entry.generation == self.generation => {}
            Some(_) => panic!("RF180-28 stale seccomp Arc allocator generation"),
            None => panic!("RF180-28 seccomp Arc charge released twice"),
        }
        slot.take()
            .expect("validated seccomp Arc charge disappeared")
            .charge
    }

    fn cancel_failed_allocation(self) {
        drop(self.take_charge());
    }

    #[cfg(test)]
    pub(crate) fn charge_bytes_for_test(self) -> usize {
        SECCOMP_ARC_CHARGES
            .lock()
            .get(self.slot as usize)
            .and_then(Option::as_ref)
            .filter(|entry| entry.generation == self.generation)
            .map_or(0, |entry| entry.charge.bytes())
    }
}

unsafe impl Allocator for SeccompArcAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        {
            let mut slots = SECCOMP_ARC_CHARGES.lock();
            let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) else {
                return Err(AllocError);
            };
            if entry.generation != self.generation || entry.allocated {
                return Err(AllocError);
            }
            entry.allocated = true;
        }

        match Global.allocate(layout) {
            Ok(allocation) => Ok(allocation),
            Err(error) => {
                let mut slots = SECCOMP_ARC_CHARGES.lock();
                if let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) {
                    if entry.generation == self.generation {
                        entry.allocated = false;
                    }
                }
                Err(error)
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // Release physical memory before returning the corresponding capacity
        // to the admission ledger.
        unsafe { Global.deallocate(ptr, layout) };
        drop(self.take_charge());
    }
}

pub(crate) type SeccompFilterArc = Arc<SeccompFilter, SeccompArcAllocator>;

fn try_new_filter_arc(value: SeccompFilter) -> Result<SeccompFilterArc, ()> {
    let bytes = arc_charge_bytes::<SeccompFilter>().map_err(|_| ())?;
    let reservation = try_reserve_heap(HeapClass::CoreProcess, bytes).map_err(|_| ())?;
    let charge = reservation.commit().map_err(|_| ())?;
    let allocator = SeccompArcAllocator::try_install(charge).map_err(|charge| {
        drop(charge);
    })?;
    match Arc::try_new_in(value, allocator) {
        Ok(value) => Ok(value),
        Err(_) => {
            allocator.cancel_failed_allocation();
            Err(())
        }
    }
}

// ============================================================================
// N2.0b: Syscall number constants are sourced from `crate::syscall_table`.
// ============================================================================
#[allow(unused_imports)]
pub(crate) use crate::syscall_table::*;

// ============================================================================
// Seccomp Actions
// ============================================================================

/// Action to take when a seccomp filter matches.
///
/// Actions have a severity ordering: Kill > Trap > Errno > Log > Allow.
/// When multiple filters are stacked, the most restrictive action wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    /// Allow the syscall to proceed.
    Allow,
    /// Log the syscall but allow it.
    Log,
    /// Return an error without executing the syscall.
    Errno(i32),
    /// Trigger a trap (SIGSYS with handler).
    Trap,
    /// Kill the process with SIGSYS.
    Kill,
}

impl SeccompAction {
    /// Get the severity level of this action (higher = more restrictive).
    #[inline]
    pub const fn severity(&self) -> u8 {
        match self {
            SeccompAction::Allow => 0,
            SeccompAction::Log => 1,
            SeccompAction::Errno(_) => 2,
            SeccompAction::Trap => 3,
            SeccompAction::Kill => 4,
        }
    }

    /// Check if this action is more restrictive than another.
    #[inline]
    pub fn more_restrictive_than(&self, other: &SeccompAction) -> bool {
        self.severity() > other.severity()
    }
}

impl Default for SeccompAction {
    fn default() -> Self {
        SeccompAction::Allow
    }
}

/// Result of evaluating a seccomp filter.
#[derive(Debug, Clone, Copy)]
pub struct SeccompVerdict {
    /// The action to take.
    pub action: SeccompAction,
    /// Filter ID that produced this verdict (for logging).
    pub filter_id: u64,
}

impl SeccompVerdict {
    /// Create an allow verdict.
    #[inline]
    pub const fn allow() -> Self {
        Self {
            action: SeccompAction::Allow,
            filter_id: 0,
        }
    }

    /// Create a kill verdict.
    #[inline]
    pub const fn kill(filter_id: u64) -> Self {
        Self {
            action: SeccompAction::Kill,
            filter_id,
        }
    }

    /// Create an errno verdict.
    #[inline]
    pub const fn errno(errno: i32, filter_id: u64) -> Self {
        Self {
            action: SeccompAction::Errno(errno),
            filter_id,
        }
    }
}

// ============================================================================
// BPF-like Instructions
// ============================================================================

/// BPF-like instruction for seccomp filters.
///
/// This is a simplified instruction set that provides:
/// - Load syscall arguments (read-only)
/// - Arithmetic and logical operations
/// - Comparisons with conditional jumps
/// - Return actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompInsn {
    /// Load syscall number into accumulator.
    LdSyscallNr,
    /// Load syscall argument (index 0-5) into accumulator.
    LdArg(u8),
    /// Load constant into accumulator.
    LdConst(u64),
    /// Bitwise AND accumulator with constant.
    And(u64),
    /// Bitwise OR accumulator with constant.
    Or(u64),
    /// Right shift accumulator by constant.
    Shr(u8),
    /// Jump if accumulator equals constant.
    JmpEq(u64, u8, u8), // (value, true_offset, false_offset)
    /// Jump if accumulator not equals constant.
    JmpNe(u64, u8, u8),
    /// Jump if accumulator less than constant.
    JmpLt(u64, u8, u8),
    /// Jump if accumulator less than or equal to constant.
    JmpLe(u64, u8, u8),
    /// Jump if accumulator greater than constant.
    JmpGt(u64, u8, u8),
    /// Jump if accumulator greater than or equal to constant.
    JmpGe(u64, u8, u8),
    /// Unconditional jump (relative offset).
    Jmp(u8),
    /// Return with action.
    Ret(SeccompAction),
}

/// Maximum program length to prevent DoS.
pub const MAX_INSNS: usize = 64;

/// R169-12 FIX: Instruction bound for TRUSTED, kernel-generated filters
/// (`pledge_to_filter` / `strict_filter`).
///
/// `MAX_INSNS` (64) is a DoS guard for UNTRUSTED, user-supplied programs copied
/// in via `sys_seccomp` (arbitrary attacker-controlled length). It was wrongly
/// applied to in-kernel generators, whose length is a FIXED compile-time
/// function of the promise vocabulary (worst case `1 + 2*N + 1` with the full
/// deduped pledge union `N <= 48` → 98 insns), so a broad-but-legitimate pledge
/// set hit the 64 bound and the generator `.expect()`ed → kernel panic on valid
/// input. Decoupling the trusted bound keeps the untrusted DoS guard at 64 while
/// letting generators emit their (bounded) worst case. 256 leaves comfortable
/// headroom above 98 for future promise growth (enforced by the const-assert in
/// the seccomp crate's lib.rs).
pub const MAX_TRUSTED_INSNS: usize = 256;

/// R171-CG2x1 FIX: hard cap on the TOTAL number of BPF instructions across a
/// process's ENTIRE seccomp filter chain (all installed filters combined).
///
/// `MAX_INSNS` bounds a SINGLE filter, but `seccomp(SET_MODE_FILTER)` stacks
/// filters (most-restrictive-wins) and `SeccompState::evaluate()` runs EVERY
/// filter on EVERY syscall — while the per-process lock is held. Without a
/// chain-total bound a process could loop `seccomp(SET_MODE_FILTER)` to grow the
/// filter `Vec` without limit (kernel-heap exhaustion) AND inflate the per-syscall
/// O(total-insns) evaluation cost (CPU DoS + an unbounded Process-lock hold time).
/// 32 maximal filters' worth of instructions; Linux likewise rejects with ENOMEM
/// once a process's cumulative filter instruction count is exceeded.
///
/// LOCK-CLUSTER NOTE: this value is also the documented worst-case Process-lock
/// hold-time bound (`evaluate()` runs under `proc.lock()`), which the IRQ-path
/// `try_lock`-skip-and-retry convergence in the R171 proctable-tick / waitloop
/// fixes relies on for forward progress.
pub const MAX_FILTER_INSNS_TOTAL: usize = MAX_INSNS * 32; // = 2048

// ============================================================================
// Seccomp Filter
// ============================================================================

bitflags! {
    /// Seccomp filter flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SeccompFlags: u32 {
        /// Log violations but don't enforce.
        const LOG = 1 << 0;
        /// Synchronize with all threads in thread group.
        const TSYNC = 1 << 1;
        /// Apply filter only to new threads.
        const NEW_THREADS = 1 << 2;
    }
}

/// A compiled seccomp filter.
// R171-CG1x2 FIX: the fields are PRIVATE so a `SeccompFilter` can ONLY be built
// via `new`/`new_trusted` (which run `validate_program` / `validate_program_with_limit`).
// Previously every field was `pub` and the struct is re-exported (lib.rs), so an
// out-of-crate caller could assemble a filter via a struct literal carrying an
// arbitrary `prog`, bypassing the MAX_INSNS validation entirely — voiding the
// R170-I1 `new_trusted` seal at the construction boundary. The two fields read
// out-of-crate (id, flags) are exposed through the `id()`/`flags()` accessors below.
#[derive(Debug)]
pub struct SeccompFilter {
    /// Default action when no rule matches.
    default_action: SeccompAction,
    /// BPF-like program.
    prog: Arc<Vec<SeccompInsn>>,
    /// Fast allow bitmap for common syscalls (syscall_nr < 512).
    /// If bit N is set, syscall N is unconditionally allowed.
    fast_allow: FastAllowSet,
    /// Unique filter ID (hash) for logging/dedup.
    id: u64,
    /// Filter flags.
    flags: SeccompFlags,
    /// Complete lifetime charge for the program Vec backing and its Arc.
    _prog_heap_charge: Option<HeapCharge>,
}

impl SeccompFilter {
    /// Create a new filter from a program.
    pub fn new(
        prog: Vec<SeccompInsn>,
        default_action: SeccompAction,
        flags: SeccompFlags,
    ) -> Result<Self, SeccompError> {
        Self::new_from_slice(&prog, default_action, flags)
    }

    /// RF180-18 FIX: construct an admitted retained program from stack or
    /// caller-owned bytes. Admission precedes both Vec and Arc allocation.
    pub fn new_from_slice(
        prog: &[SeccompInsn],
        default_action: SeccompAction,
        flags: SeccompFlags,
    ) -> Result<Self, SeccompError> {
        validate_program(prog)?;
        Self::new_validated_from_slice(prog, default_action, flags)
    }

    /// R169-12 FIX: Create a filter from a TRUSTED, kernel-generated program,
    /// validating its length against `MAX_TRUSTED_INSNS` instead of the
    /// untrusted `MAX_INSNS`. Use ONLY for in-kernel generators
    /// (`pledge_to_filter`, `strict_filter`) whose length is bounded by the
    /// fixed promise vocabulary; NEVER for user-supplied programs — those must
    /// use [`SeccompFilter::new`], which keeps the `MAX_INSNS` DoS guard.
    ///
    /// R170-I1 FIX: sealed `pub(crate)` so the trusted/untrusted split is
    /// TYPE-enforced, not doc-convention: an out-of-crate caller (e.g. a future
    /// syscall path) physically cannot route a user-supplied program past the
    /// `MAX_INSNS` guard. All legitimate callers are this crate's generators
    /// (`deny_all_filter`, `strict_filter`, `pledge_to_filter`).
    pub(crate) fn new_trusted(
        prog: Vec<SeccompInsn>,
        default_action: SeccompAction,
        flags: SeccompFlags,
    ) -> Result<Self, SeccompError> {
        Self::new_trusted_from_slice(&prog, default_action, flags)
    }

    pub(crate) fn new_trusted_from_slice(
        prog: &[SeccompInsn],
        default_action: SeccompAction,
        flags: SeccompFlags,
    ) -> Result<Self, SeccompError> {
        validate_program_with_limit(prog, MAX_TRUSTED_INSNS)?;
        Self::new_validated_from_slice(prog, default_action, flags)
    }

    fn new_validated_from_slice(
        prog: &[SeccompInsn],
        default_action: SeccompAction,
        flags: SeccompFlags,
    ) -> Result<Self, SeccompError> {
        #[cfg(test)]
        {
            static TEST_ADMISSION: spin::Once<()> = spin::Once::new();
            TEST_ADMISSION.call_once(mm::publish_heap_budgets);
        }
        let arc_bytes =
            arc_charge_bytes::<Vec<SeccompInsn>>().map_err(|_| SeccompError::OutOfMemory)?;
        let vec_bytes =
            vec_charge_bytes::<SeccompInsn>(prog.len()).map_err(|_| SeccompError::OutOfMemory)?;
        let total = arc_bytes
            .checked_add(vec_bytes)
            .ok_or(SeccompError::OutOfMemory)?;
        let mut reservation = try_reserve_heap(HeapClass::CoreProcess, total)
            .map_err(|_| SeccompError::OutOfMemory)?;

        let mut owned = Vec::new();
        owned
            .try_reserve_exact(prog.len())
            .map_err(|_| SeccompError::OutOfMemory)?;
        let actual = arc_bytes
            .checked_add(
                vec_charge_bytes::<SeccompInsn>(owned.capacity())
                    .map_err(|_| SeccompError::OutOfMemory)?,
            )
            .ok_or(SeccompError::OutOfMemory)?;
        reservation
            .resize(actual)
            .map_err(|_| SeccompError::OutOfMemory)?;
        owned.extend_from_slice(prog);
        let owned = Arc::try_new(owned).map_err(|_| SeccompError::OutOfMemory)?;

        let fast_allow = compute_fast_allow(prog, default_action);
        let id = compute_filter_id(prog);
        let charge = reservation
            .commit()
            .map_err(|_| SeccompError::OutOfMemory)?;
        Ok(Self {
            default_action,
            prog: owned,
            fast_allow,
            id,
            flags,
            _prog_heap_charge: Some(charge),
        })
    }

    pub(crate) fn program_id(prog: &[SeccompInsn]) -> u64 {
        compute_filter_id(prog)
    }

    /// R171-CG1x2 FIX: public accessors for the now-private sealed fields that
    /// out-of-crate code legitimately reads — `id` (seccomp-mode detection) and
    /// `flags` (the LOG bit). Read-only by construction; there is no setter, so
    /// the validated `prog`/`fast_allow` cannot be swapped after construction.
    #[inline]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Filter flags (e.g. `SeccompFlags::LOG`).
    #[inline]
    pub fn flags(&self) -> SeccompFlags {
        self.flags
    }

    /// Number of BPF instructions in this filter's validated program.
    #[inline]
    pub fn prog_len(&self) -> usize {
        self.prog.len()
    }

    /// Evaluate this filter against a syscall.
    ///
    /// R180-2: the fast_allow bit is set only when the full interpreter proves
    /// `Allow` for every arg vector (or for zeros when the program never reads
    /// args). The bit is never a second, looser policy.
    pub fn evaluate(&self, syscall_nr: u64, args: &[u64; 6]) -> SeccompAction {
        // Fast path: sound only under INV-SEC-01 (see compute_fast_allow).
        if syscall_nr < 512 && self.fast_allow.get(syscall_nr as usize) {
            return SeccompAction::Allow;
        }
        interpret_program(self.prog.as_slice(), self.default_action, syscall_nr, args)
    }

    /// R180-2 test/oracle: true iff the install-time fast_allow bit is set.
    #[cfg(test)]
    pub fn fast_allows(&self, syscall_nr: u64) -> bool {
        syscall_nr < 512 && self.fast_allow.get(syscall_nr as usize)
    }
}

/// Single source of truth for seccomp BPF evaluation (no fast_allow).
///
/// R180-2 FIX: extracted from `SeccompFilter::evaluate` so install-time
/// `compute_fast_allow` and runtime evaluation cannot diverge.
fn interpret_program(
    prog: &[SeccompInsn],
    default_action: SeccompAction,
    syscall_nr: u64,
    args: &[u64; 6],
) -> SeccompAction {
    let mut acc: u64 = 0;
    let mut pc: usize = 0;

    while pc < prog.len() {
        match prog[pc] {
            SeccompInsn::LdSyscallNr => {
                acc = syscall_nr;
                pc += 1;
            }
            SeccompInsn::LdArg(idx) => {
                acc = if (idx as usize) < 6 {
                    args[idx as usize]
                } else {
                    0
                };
                pc += 1;
            }
            SeccompInsn::LdConst(val) => {
                acc = val;
                pc += 1;
            }
            SeccompInsn::And(val) => {
                acc &= val;
                pc += 1;
            }
            SeccompInsn::Or(val) => {
                acc |= val;
                pc += 1;
            }
            SeccompInsn::Shr(shift) => {
                let Some(shifted) = acc.checked_shr(shift as u32) else {
                    // RF186-11 defense in depth: trusted construction bugs must
                    // fail closed even if validation was accidentally bypassed.
                    return SeccompAction::Trap;
                };
                acc = shifted;
                pc += 1;
            }
            // R32-SECCOMP-2 FIX: All jump instructions must validate pc bounds
            // after increment. If pc escapes program bounds, fail-closed with Trap.
            SeccompInsn::JmpEq(val, t, f) => {
                pc += 1 + if acc == val { t as usize } else { f as usize };
                if pc >= prog.len() {
                    return SeccompAction::Trap;
                }
            }
            SeccompInsn::JmpNe(val, t, f) => {
                pc += 1 + if acc != val { t as usize } else { f as usize };
                if pc >= prog.len() {
                    return SeccompAction::Trap;
                }
            }
            SeccompInsn::JmpLt(val, t, f) => {
                pc += 1 + if acc < val { t as usize } else { f as usize };
                if pc >= prog.len() {
                    return SeccompAction::Trap;
                }
            }
            SeccompInsn::JmpLe(val, t, f) => {
                pc += 1 + if acc <= val { t as usize } else { f as usize };
                if pc >= prog.len() {
                    return SeccompAction::Trap;
                }
            }
            SeccompInsn::JmpGt(val, t, f) => {
                pc += 1 + if acc > val { t as usize } else { f as usize };
                if pc >= prog.len() {
                    return SeccompAction::Trap;
                }
            }
            SeccompInsn::JmpGe(val, t, f) => {
                pc += 1 + if acc >= val { t as usize } else { f as usize };
                if pc >= prog.len() {
                    return SeccompAction::Trap;
                }
            }
            SeccompInsn::Jmp(offset) => {
                pc += 1 + offset as usize;
                if pc >= prog.len() {
                    return SeccompAction::Trap;
                }
            }
            SeccompInsn::Ret(action) => {
                return action;
            }
        }
    }

    default_action
}

/// True if any instruction reads syscall args (breaks arg-independence).
#[inline]
fn program_reads_args(prog: &[SeccompInsn]) -> bool {
    prog.iter().any(|i| matches!(i, SeccompInsn::LdArg(_)))
}

// ============================================================================
// Fast Allow Bitmap
// ============================================================================

/// Bitmap for fast syscall allow checks.
#[derive(Debug, Clone)]
pub struct FastAllowSet {
    /// 512 bits = 8 u64s
    bits: [u64; 8],
}

impl FastAllowSet {
    /// Create an empty set.
    pub const fn empty() -> Self {
        Self { bits: [0; 8] }
    }

    /// Set bit at index.
    pub fn set(&mut self, idx: usize) {
        if idx < 512 {
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    /// Get bit at index.
    #[inline]
    pub fn get(&self, idx: usize) -> bool {
        if idx < 512 {
            (self.bits[idx / 64] >> (idx % 64)) & 1 != 0
        } else {
            false
        }
    }
}

impl Default for FastAllowSet {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Pledge Promises
// ============================================================================

bitflags! {
    /// Pledge promise set (OpenBSD-style).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PledgePromises: u32 {
        /// Basic I/O: read, write, close, fstat, lseek, getpid, etc.
        const STDIO = 1 << 0;
        /// Read-only filesystem access: open(RD), stat, readdir.
        const RPATH = 1 << 1;
        /// Write filesystem access: open(WR|CREAT), write, rename, unlink.
        const WPATH = 1 << 2;
        /// Create files: open(O_CREAT), mkdir, mknod.
        const CPATH = 1 << 3;
        /// Temp files: tmpfile, unlink of temp.
        const TMPPATH = 1 << 4;
        /// Process operations: fork, clone, exec, wait, kill.
        const PROC = 1 << 5;
        /// Thread operations: clone(THREAD), futex.
        const THREAD = 1 << 6;
        /// Execute programs: exec*.
        const EXEC = 1 << 7;
        /// Unix sockets.
        const UNIX = 1 << 8;
        /// Internet sockets.
        const INET = 1 << 9;
        /// DNS resolution.
        const DNS = 1 << 10;
        /// Change file attributes: chmod, chown, utime.
        const FATTR = 1 << 11;
        /// Get/set resource limits: getrlimit, setrlimit.
        const RLIMIT = 1 << 12;
        /// Get current time.
        const TIME = 1 << 13;
        /// Send signals to own process group.
        const SENDSIG = 1 << 14;
        /// Ptrace (for debuggers).
        const PTRACE = 1 << 15;
        /// Memory mapping with EXEC.
        const PROT_EXEC = 1 << 16;
        /// Virtual memory: mmap, mprotect, munmap.
        const VM = 1 << 17;
    }
}

impl PledgePromises {
    /// Parse promise string (space-separated).
    pub fn parse(s: &str) -> Result<Self, SeccompError> {
        let mut promises = PledgePromises::empty();
        for word in s.split_whitespace() {
            match word {
                "stdio" => promises |= PledgePromises::STDIO,
                "rpath" => promises |= PledgePromises::RPATH,
                "wpath" => promises |= PledgePromises::WPATH,
                "cpath" => promises |= PledgePromises::CPATH,
                "tmppath" => promises |= PledgePromises::TMPPATH,
                "proc" => promises |= PledgePromises::PROC,
                "thread" => promises |= PledgePromises::THREAD,
                "exec" => promises |= PledgePromises::EXEC,
                "unix" => promises |= PledgePromises::UNIX,
                "inet" => promises |= PledgePromises::INET,
                "dns" => promises |= PledgePromises::DNS,
                "fattr" => promises |= PledgePromises::FATTR,
                "rlimit" => promises |= PledgePromises::RLIMIT,
                "time" => promises |= PledgePromises::TIME,
                "sendsig" => promises |= PledgePromises::SENDSIG,
                "ptrace" => promises |= PledgePromises::PTRACE,
                "prot_exec" => promises |= PledgePromises::PROT_EXEC,
                "vm" => promises |= PledgePromises::VM,
                _ => return Err(SeccompError::InvalidPromise),
            }
        }
        Ok(promises)
    }
}

/// Pledge state for a process.
#[derive(Debug, Clone)]
pub struct PledgeState {
    /// Current active promises.
    pub promises: PledgePromises,
    /// Promises to apply after exec (if Some).
    pub exec_promises: Option<PledgePromises>,
}

impl PledgeState {
    /// Create a new pledge state with given promises.
    pub fn new(promises: PledgePromises) -> Self {
        Self {
            promises,
            exec_promises: None,
        }
    }

    /// Check if a syscall is allowed by current promises.
    pub fn allows(&self, syscall_nr: u64, args: &[u64; 6]) -> bool {
        promise_allows_syscall(self.promises, syscall_nr, args)
    }
}

// ============================================================================
// Seccomp State
// ============================================================================

/// Per-process seccomp state.
#[derive(Debug)]
pub struct SeccompState {
    /// Stack of filters (evaluated in order, most restrictive wins).
    ///
    /// R171-CG2x1 FIX: PRIVATE so the only way to grow the chain is through
    /// `add_filter`, which enforces `MAX_FILTER_INSNS_TOTAL`. Were this `pub`, an
    /// out-of-crate caller could `state.filters.push(..)` directly and bypass the
    /// per-process chain-instruction cap (the bound is now type-enforced, not just
    /// convention). Read access is via the `filters()` accessor below.
    filters: AdmittedVec<SeccompFilterArc>,
    /// PR_SET_NO_NEW_PRIVS flag.
    pub no_new_privs: bool,
    /// Log all violations.
    pub log_violations: bool,
}

impl SeccompState {
    /// Create empty seccomp state.
    pub fn new() -> Self {
        Self {
            filters: AdmittedVec::new(HeapClass::CoreProcess),
            no_new_privs: false,
            log_violations: false,
        }
    }

    /// Evaluate all filters against a syscall.
    ///
    /// Returns the most restrictive verdict across all filters.
    /// Severity ordering: Kill > Trap > Errno > Log > Allow.
    pub fn evaluate(&self, syscall_nr: u64, args: &[u64; 6]) -> SeccompVerdict {
        let mut result = SeccompVerdict::allow();

        for filter in &self.filters {
            let action = filter.evaluate(syscall_nr, args);

            // Track the most restrictive action seen
            if action.more_restrictive_than(&result.action) {
                result = SeccompVerdict {
                    action,
                    filter_id: filter.id,
                };
            }

            // Early exit on Kill (can't be more restrictive)
            if matches!(result.action, SeccompAction::Kill) {
                break;
            }
        }

        result
    }

    // R159-6 FIX: Fallible filter addition. The old infallible push + Arc::new
    // could panic under OOM when a user installs many seccomp filters.
    //
    // R171-CG2x1 FIX: enforce the per-process TOTAL-instruction cap BEFORE
    // committing the filter, so the chain can never grow without bound (heap DoS)
    // and the per-syscall `evaluate()` cost / Process-lock hold time stay bounded.
    // The sum is O(chain), but the chain is itself bounded by this very cap and
    // installs are rare. `Err(())` maps to ENOMEM at both call sites — matching
    // Linux, which returns -ENOMEM when a process's cumulative filter instruction
    // count is exceeded.
    pub fn add_filter(&mut self, filter: SeccompFilter) -> Result<(), ()> {
        let current_total: usize = self.filters.iter().map(|f| f.prog_len()).sum();
        if current_total.saturating_add(filter.prog_len()) > MAX_FILTER_INSNS_TOTAL {
            return Err(());
        }
        // RF180-18/RF180-28 FIX: reserve the chain backing and outer Arc before
        // either becomes visible. The Arc allocator owns its charge until the
        // final strong and weak handle release the control block.
        let prepared = self.filters.prepare_capacity_for(1).map_err(|_| ())?;
        let filter = try_new_filter_arc(filter)?;
        if let Some(prepared) = prepared {
            self.filters.install_prepared(prepared).map_err(|_| ())?;
        }
        if let Err(filter) = self.filters.push_reserved(filter) {
            // U44-1 FIX: a stale/corrupt capacity token is a recoverable
            // publication failure. Drop the newly admitted filter and return
            // ENOMEM to the syscall caller; never abort while installing a
            // user-controlled filter chain.
            drop(filter);
            return Err(());
        }
        Ok(())
    }

    /// Check if any filters are active.
    pub fn has_filters(&self) -> bool {
        !self.filters.is_empty()
    }

    /// R171-CG2x1 FIX: read-only view of the installed filter chain. The backing
    /// `Vec` is private (see the field doc) so the only mutation path is
    /// `add_filter`, which enforces `MAX_FILTER_INSNS_TOTAL`.
    #[inline]
    pub(crate) fn filters(&self) -> &[SeccompFilterArc] {
        &self.filters
    }

    /// Number of installed filters without exposing the ownership-bearing Arc.
    #[inline]
    pub fn filter_count(&self) -> usize {
        self.filters.len()
    }

    /// ID of the only filter, if the chain contains exactly one entry.
    #[inline]
    pub fn single_filter_id(&self) -> Option<u64> {
        if self.filters.len() == 1 {
            self.filters.first().map(|filter| filter.id())
        } else {
            None
        }
    }

    // R161-3 FIX: Fallible clone for fork/clone path. The derived Clone
    // uses infallible Vec::clone which panics under OOM. Arc<SeccompFilter>
    // clone is just a refcount bump (cheap), but the Vec growth is the issue.
    pub fn try_clone(&self) -> Result<Self, ()> {
        let filters = AdmittedVec::try_copy_from_slice(HeapClass::CoreProcess, &self.filters)
            .map_err(|_| ())?;
        Ok(Self {
            filters,
            no_new_privs: self.no_new_privs,
            log_violations: self.log_violations,
        })
    }
}

impl Default for SeccompState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Seccomp errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompError {
    /// Program is too long.
    ProgramTooLong,
    /// Program has invalid instruction.
    InvalidInstruction,
    /// Program has out-of-bounds jump.
    InvalidJump,
    /// Program doesn't terminate with RET.
    NoTerminator,
    /// Program accesses invalid argument index.
    InvalidArgIndex,
    /// Invalid pledge promise string.
    InvalidPromise,
    /// Retained filter storage could not be admitted or allocated.
    OutOfMemory,
    /// Operation not permitted (no_new_privs).
    NotPermitted,
    /// Memory fault copying from user.
    Fault,
}

impl fmt::Display for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeccompError::ProgramTooLong => write!(f, "seccomp: program too long"),
            SeccompError::InvalidInstruction => write!(f, "seccomp: invalid instruction"),
            SeccompError::InvalidJump => write!(f, "seccomp: invalid jump"),
            SeccompError::NoTerminator => write!(f, "seccomp: program doesn't terminate"),
            SeccompError::InvalidArgIndex => write!(f, "seccomp: invalid argument index"),
            SeccompError::InvalidPromise => write!(f, "seccomp: invalid pledge promise"),
            SeccompError::OutOfMemory => write!(f, "seccomp: out of memory"),
            SeccompError::NotPermitted => write!(f, "seccomp: operation not permitted"),
            SeccompError::Fault => write!(f, "seccomp: memory fault"),
        }
    }
}

// ============================================================================
// Validation and Helpers
// ============================================================================

/// Validate a seccomp program.
///
/// # Security (R32-SECCOMP-1 fix)
///
/// Jump targets must be strictly less than prog.len() to ensure they
/// land on a valid instruction. Allowing target == prog.len() enables
/// policy bypass by falling through to the default action.
fn validate_program(prog: &[SeccompInsn]) -> Result<(), SeccompError> {
    validate_program_with_limit(prog, MAX_INSNS)
}

/// R169-12 FIX: Validate a program against a caller-chosen instruction limit so
/// trusted kernel generators can validate against `MAX_TRUSTED_INSNS` while the
/// untrusted `sys_seccomp` path keeps the `MAX_INSNS` DoS guard. All other
/// checks (terminator, jump-target bounds, argument indices) are identical.
fn validate_program_with_limit(prog: &[SeccompInsn], max_insns: usize) -> Result<(), SeccompError> {
    if prog.is_empty() {
        return Err(SeccompError::NoTerminator);
    }
    if prog.len() > max_insns {
        return Err(SeccompError::ProgramTooLong);
    }

    // Check for valid argument indices and jump targets
    for (i, insn) in prog.iter().enumerate() {
        match insn {
            SeccompInsn::LdArg(idx) if *idx >= 6 => {
                return Err(SeccompError::InvalidArgIndex);
            }
            SeccompInsn::Shr(shift) if *shift >= 64 => {
                return Err(SeccompError::InvalidInstruction);
            }
            SeccompInsn::JmpEq(_, t, f)
            | SeccompInsn::JmpNe(_, t, f)
            | SeccompInsn::JmpLt(_, t, f)
            | SeccompInsn::JmpLe(_, t, f)
            | SeccompInsn::JmpGt(_, t, f)
            | SeccompInsn::JmpGe(_, t, f) => {
                let true_target = i + 1 + *t as usize;
                let false_target = i + 1 + *f as usize;
                // R32-SECCOMP-1 FIX: Use >= instead of > to prevent jumping past program end
                if true_target >= prog.len() || false_target >= prog.len() {
                    return Err(SeccompError::InvalidJump);
                }
            }
            SeccompInsn::Jmp(offset) => {
                let target = i + 1 + *offset as usize;
                // R32-SECCOMP-1 FIX: Use >= instead of > to prevent jumping past program end
                if target >= prog.len() {
                    return Err(SeccompError::InvalidJump);
                }
            }
            _ => {}
        }
    }

    // All jumps are forward and in bounds. Requiring the last instruction to
    // return therefore proves every path terminates, rather than accepting an
    // early RET beside a reachable fall-through to the caller's default action.
    if !matches!(prog.last(), Some(SeccompInsn::Ret(_))) {
        return Err(SeccompError::NoTerminator);
    }

    Ok(())
}

/// Compute fast_allow bitmap from program.
///
/// # R180-2 FIX (class-eliminating semantic equivalence)
///
/// INV-SEC-01: `fast_allow.get(n)` ⇒ `∀args. interpret(n, args) == Allow`.
///
/// Prior walker set a bit when *any* false-branch-chain `JmpEq(n)` true target
/// was `Ret(Allow)`, even if an earlier same-`n` arm returned `Kill`. That made
/// the fast path a second, looser policy (sandbox bypass).
///
/// Construction:
/// 1. If the program contains any `LdArg`, return empty (cannot cheaply prove
///    ∀args; Safety > Efficiency).
/// 2. Else, by ISA arg-independence, `interpret(n, zeros)` is the action for
///    all args; set bit `n` iff that action is exactly `Allow`.
///
/// Pledge/strict generators emit pure nr whitelists (no `LdArg`), so every
/// Allowed `nr < 512` still receives a bit and keeps the hot-path optimization.
fn compute_fast_allow(prog: &[SeccompInsn], default_action: SeccompAction) -> FastAllowSet {
    let mut set = FastAllowSet::empty();
    if prog.is_empty() || program_reads_args(prog) {
        return set;
    }
    let zero = [0u64; 6];
    for nr in 0u64..512 {
        if matches!(
            interpret_program(prog, default_action, nr, &zero),
            SeccompAction::Allow
        ) {
            set.set(nr as usize);
        }
    }
    set
}

/// Compute filter ID from program.
///
/// R100-6 FIX: Uses structured field hashing instead of raw enum byte slicing
/// to avoid undefined behavior from uninitialized padding bytes.
fn compute_filter_id(prog: &[SeccompInsn]) -> u64 {
    /// FNV-1a byte fold
    #[inline]
    fn fnv_byte(hash: &mut u64, byte: u8) {
        *hash ^= byte as u64;
        *hash = hash.wrapping_mul(0x100000001b3);
    }

    #[inline]
    fn fnv_u64(hash: &mut u64, v: u64) {
        for b in v.to_le_bytes() {
            fnv_byte(hash, b);
        }
    }

    #[inline]
    fn fnv_i32(hash: &mut u64, v: i32) {
        for b in v.to_le_bytes() {
            fnv_byte(hash, b);
        }
    }

    fn hash_action(hash: &mut u64, action: SeccompAction) {
        match action {
            SeccompAction::Allow => fnv_byte(hash, 0),
            SeccompAction::Log => fnv_byte(hash, 1),
            SeccompAction::Errno(e) => {
                fnv_byte(hash, 2);
                fnv_i32(hash, e);
            }
            SeccompAction::Trap => fnv_byte(hash, 3),
            SeccompAction::Kill => fnv_byte(hash, 4),
        }
    }

    let mut hash: u64 = 0xcbf29ce484222325;

    for insn in prog {
        match *insn {
            SeccompInsn::LdSyscallNr => fnv_byte(&mut hash, 0),
            SeccompInsn::LdArg(idx) => {
                fnv_byte(&mut hash, 1);
                fnv_byte(&mut hash, idx);
            }
            SeccompInsn::LdConst(v) => {
                fnv_byte(&mut hash, 2);
                fnv_u64(&mut hash, v);
            }
            SeccompInsn::And(v) => {
                fnv_byte(&mut hash, 3);
                fnv_u64(&mut hash, v);
            }
            SeccompInsn::Or(v) => {
                fnv_byte(&mut hash, 4);
                fnv_u64(&mut hash, v);
            }
            SeccompInsn::Shr(s) => {
                fnv_byte(&mut hash, 5);
                fnv_byte(&mut hash, s);
            }
            SeccompInsn::JmpEq(v, t, f) => {
                fnv_byte(&mut hash, 6);
                fnv_u64(&mut hash, v);
                fnv_byte(&mut hash, t);
                fnv_byte(&mut hash, f);
            }
            SeccompInsn::JmpNe(v, t, f) => {
                fnv_byte(&mut hash, 7);
                fnv_u64(&mut hash, v);
                fnv_byte(&mut hash, t);
                fnv_byte(&mut hash, f);
            }
            SeccompInsn::JmpLt(v, t, f) => {
                fnv_byte(&mut hash, 8);
                fnv_u64(&mut hash, v);
                fnv_byte(&mut hash, t);
                fnv_byte(&mut hash, f);
            }
            SeccompInsn::JmpLe(v, t, f) => {
                fnv_byte(&mut hash, 9);
                fnv_u64(&mut hash, v);
                fnv_byte(&mut hash, t);
                fnv_byte(&mut hash, f);
            }
            SeccompInsn::JmpGt(v, t, f) => {
                fnv_byte(&mut hash, 10);
                fnv_u64(&mut hash, v);
                fnv_byte(&mut hash, t);
                fnv_byte(&mut hash, f);
            }
            SeccompInsn::JmpGe(v, t, f) => {
                fnv_byte(&mut hash, 11);
                fnv_u64(&mut hash, v);
                fnv_byte(&mut hash, t);
                fnv_byte(&mut hash, f);
            }
            SeccompInsn::Jmp(off) => {
                fnv_byte(&mut hash, 12);
                fnv_byte(&mut hash, off);
            }
            SeccompInsn::Ret(action) => {
                fnv_byte(&mut hash, 13);
                hash_action(&mut hash, action);
            }
        }
    }

    hash
}

/// Check if a pledge promise set allows a syscall (N2.0b: driven directly from
/// `crate::syscall_table::SYSCALL_TABLE`).
///
/// Membership is resolved from the same single table that generates
/// `pledge_syscall_list()` / `pledge_to_filter()`, eliminating R150-3 BPF vs.
/// semantic divergence by construction. Entries marked `PledgePolicy::Guarded`
/// additionally enforce argument-sensitive checks (`open`/`openat` flags,
/// `mmap`/`mprotect` `PROT_EXEC`, `clone` flags).
fn promise_allows_syscall(promises: PledgePromises, syscall_nr: u64, args: &[u64; 6]) -> bool {
    use crate::syscall_table::PledgePolicy;

    let Some(spec) = crate::syscall_table::lookup(syscall_nr) else {
        return false;
    };

    match spec.pledge {
        PledgePolicy::Always => true,
        PledgePolicy::Promises(bits) => promises.intersects(bits),
        PledgePolicy::Guarded(bits) => {
            if !promises.intersects(bits) {
                return false;
            }
            check_guarded_syscall_args(promises, syscall_nr, args)
        }
        PledgePolicy::Unpledged | PledgePolicy::PrivateNeverPledged => false,
    }
}

/// Argument-sensitive semantic checks for `PledgePolicy::Guarded` syscalls.
fn check_guarded_syscall_args(promises: PledgePromises, syscall_nr: u64, args: &[u64; 6]) -> bool {
    // File open flag bits (must match VFS)
    const O_ACCMODE: u64 = 0x3;
    const O_WRONLY: u64 = 0x1;
    const O_RDWR: u64 = 0x2;
    const O_CREAT: u64 = 0o100;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;

    // Memory protection flags
    const PROT_EXEC: i32 = 0x4;

    // Clone flags
    const CLONE_VM: u64 = 0x0000_0100;
    const CLONE_SIGHAND: u64 = 0x0000_0800;
    const CLONE_THREAD: u64 = 0x0001_0000;
    const CLONE_NEWNS: u64 = 0x0002_0000;
    const CLONE_NEWUTS: u64 = 0x0400_0000;
    const CLONE_NEWIPC: u64 = 0x0800_0000;
    const CLONE_NEWUSER: u64 = 0x1000_0000;
    const CLONE_NEWPID: u64 = 0x2000_0000;
    const CLONE_NEWNET: u64 = 0x4000_0000;
    const NS_DISALLOWED: u64 =
        CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;
    const THREAD_REQUIRED: u64 = CLONE_THREAD | CLONE_VM | CLONE_SIGHAND;

    match syscall_nr {
        SYS_OPEN | SYS_OPENAT => {
            let flags = if syscall_nr == SYS_OPEN {
                args[1]
            } else {
                args[2]
            };
            let accmode = flags & O_ACCMODE;
            let wants_write = accmode == O_WRONLY || accmode == O_RDWR;
            let wants_create = (flags & (O_CREAT | O_TRUNC)) != 0;
            let wants_append = (flags & O_APPEND) != 0;

            // Writing (including append/truncate) requires WPATH/CPATH/TMPPATH
            if (wants_write || wants_append)
                && !promises.intersects(
                    PledgePromises::WPATH | PledgePromises::CPATH | PledgePromises::TMPPATH,
                )
            {
                return false;
            }

            // Creation/truncate requires CPATH or TMPPATH
            if wants_create && !promises.intersects(PledgePromises::CPATH | PledgePromises::TMPPATH)
            {
                return false;
            }

            true
        }
        SYS_MMAP | SYS_MPROTECT => {
            let prot = args[2] as i32;
            (prot & PROT_EXEC) == 0 || promises.contains(PledgePromises::PROT_EXEC)
        }
        SYS_CLONE => {
            let clone_flags = args[0];
            // R147-2 / R154-11: Always reject namespace-creating flags under PROC/THREAD.
            if (clone_flags & NS_DISALLOWED) != 0 {
                return false;
            }
            // R151-2: CLONE_VM requires THREAD plus full thread-sharing flags.
            if (clone_flags & CLONE_VM) != 0 {
                return promises.contains(PledgePromises::THREAD)
                    && (clone_flags & THREAD_REQUIRED) == THREAD_REQUIRED;
            }
            // Fork-like clone (no CLONE_VM, no namespace flags) requires PROC.
            promises.contains(PledgePromises::PROC)
        }
        // Fail closed if a new Guarded entry is added to SYSCALL_TABLE without
        // wiring its semantic argument check here.
        _ => false,
    }
}

/// M0-6: public probe of the semantic pledge gate for the divergence-prevention
/// parity self-test. Uses all-zero args (a permissive probe for the unconditional
/// allow paths). Arg-sensitive gating (open flags, mmap PROT_EXEC) is approximated
/// at args=0; the headline parity check is over the arg-insensitive BPF union.
pub fn promise_allows_syscall_probe(promises: PledgePromises, syscall_nr: u64) -> bool {
    promise_allows_syscall(promises, syscall_nr, &[0u64; 6])
}

/// Hosted test helper exposing argument-aware pledge evaluation.
#[cfg(test)]
pub(crate) fn promise_allows_syscall_with_args(
    promises: PledgePromises,
    syscall_nr: u64,
    args: &[u64; 6],
) -> bool {
    promise_allows_syscall(promises, syscall_nr, args)
}

#[cfg(test)]
mod invariant_tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn rejects_a_reachable_fallthrough_even_with_an_earlier_return() {
        let program = [
            SeccompInsn::LdSyscallNr,
            SeccompInsn::JmpEq(7, 0, 1),
            SeccompInsn::Ret(SeccompAction::Kill),
            SeccompInsn::LdConst(0),
        ];
        assert_eq!(validate_program(&program), Err(SeccompError::NoTerminator));
        assert_eq!(
            validate_program_with_limit(&program, MAX_TRUSTED_INSNS),
            Err(SeccompError::NoTerminator)
        );
        let valid = [
            SeccompInsn::LdSyscallNr,
            SeccompInsn::JmpEq(7, 0, 1),
            SeccompInsn::Ret(SeccompAction::Kill),
            SeccompInsn::Ret(SeccompAction::Allow),
        ];
        assert_eq!(validate_program(&valid), Ok(()));
    }

    #[test]
    fn rf186_11_shift_range_is_central_and_interpreter_is_fail_closed() {
        let invalid = vec![
            SeccompInsn::LdConst(u64::MAX),
            SeccompInsn::Shr(64),
            SeccompInsn::Ret(SeccompAction::Allow),
        ];
        assert_eq!(
            validate_program_with_limit(&invalid, MAX_INSNS),
            Err(SeccompError::InvalidInstruction)
        );
        assert_eq!(
            validate_program_with_limit(&invalid, MAX_TRUSTED_INSNS),
            Err(SeccompError::InvalidInstruction)
        );
        assert_eq!(
            interpret_program(&invalid, SeccompAction::Kill, 0, &[0; 6]),
            SeccompAction::Trap,
            "a trusted-construction bug must trap rather than panic or mask"
        );

        let valid = vec![
            SeccompInsn::LdConst(u64::MAX),
            SeccompInsn::Shr(63),
            SeccompInsn::JmpEq(1, 0, 1),
            SeccompInsn::Ret(SeccompAction::Allow),
            SeccompInsn::Ret(SeccompAction::Kill),
        ];
        assert!(validate_program(&valid).is_ok());
        assert_eq!(
            interpret_program(&valid, SeccompAction::Kill, 0, &[0; 6]),
            SeccompAction::Allow
        );
    }
}
