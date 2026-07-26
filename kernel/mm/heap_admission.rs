//! Whole-kernel heap admission and lifetime accounting.
//!
//! R180-7/10/11/13 exposed the difference between a collection-specific cap
//! and a proof over all concurrently live heap consumers.  This module is the
//! common transaction layer for user-reachable retained objects and transient
//! buffers:
//!
//! * reservations are acquired before allocation or externally visible work;
//! * reservations convert to committed charges without changing aggregate use;
//! * both states are released by RAII on every error and lifetime end;
//! * global and per-class limits are enforced with checked lock-free CAS loops;
//! * no bookkeeping path allocates from the heap it protects.
//!
//! The ledger is deliberately conservative.  It accounts requested allocator
//! layouts plus alignment/bookkeeping slack.  Physical exhaustion or
//! fragmentation can still make a fallible allocation fail after admission;
//! callers must propagate that failure and let the reservation roll back.

use core::fmt;
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::memory::NORMAL_HEAP_SIZE_BYTES;

/// Space left to boot-only and not-yet-migrated kernel internals in the normal
/// arena.  It is separate from the physically isolated emergency arena.
pub const NORMAL_UNADMITTED_RESERVE_BYTES: usize = 64 * 1024;

/// Existing registered subsystems whose own fixed-capacity accounting is
/// conservatively withheld from the shared runtime ledger.
///
/// This must equal `heap_budget::HARD_FLOORS_SUM_BYTES`; the latter asserts the
/// equality at compile time so the two registries cannot silently diverge.
pub const REGISTERED_FIXED_RESERVE_BYTES: usize = 512 * 1024;

/// Runtime-admitted capacity shared by all classes below.
pub const ADMITTED_HEAP_BYTES: usize =
    NORMAL_HEAP_SIZE_BYTES - NORMAL_UNADMITTED_RESERVE_BYTES - REGISTERED_FIXED_RESERVE_BYTES;

const COUNTER_BITS: u32 = 32;
const COUNTER_MASK: u64 = u32::MAX as u64;
const _: () = assert!(ADMITTED_HEAP_BYTES > 0);
const _: () = assert!(ADMITTED_HEAP_BYTES <= u32::MAX as usize);

/// Ownership classes for runtime heap reservations.
///
/// Per-class ceilings prevent one object family from consuming the complete
/// shared budget.  The global ledger remains authoritative, so ceilings may
/// intentionally overlap without weakening the coexistence proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HeapClass {
    CoreProcess = 0,
    Capability = 1,
    Scheduler = 2,
    Cgroup = 3,
    Procfs = 4,
    BlockingIo = 5,
    Exec = 6,
    SocketObject = 7,
    SocketPayload = 8,
    RamFs = 9,
    Pipe = 10,
    Vfs = 11,
    Device = 12,
    /// Transient filesystem mutation/preflight state.  Kept separate from
    /// retained VFS handles so a hostile sparse write cannot consume the
    /// complete descriptor/object budget while it is holding user I/O memory.
    FilesystemIo = 13,
    /// Futex buckets, PI metadata, wait queues, and their sole production
    /// timed-wait registry.  This class mirrors the named 128 KiB futex floor
    /// so hostile futex churn cannot consume Scheduler admission.
    Futex = 14,
    /// D3-NETNS-DATAPLANE: Per-namespace network configuration state.
    /// Includes per-ns ARP cache, routing tables, and dataplane metadata.
    /// 512 KiB ceiling allows ~256 ARP entries + routing state per namespace.
    /// NOTE (Codex round-2): the ceiling is CLASS-GLOBAL — all namespaces
    /// share it, bounded per-ns only by each structure's own cap (e.g. the
    /// 256-entry ARP cache). Per-namespace sub-accounting is a Phase I.3
    /// leg; until then heavy population of many namespaces can cause
    /// cross-ns admission failures inside this class (fail-closed, no
    /// spillover into other classes).
    NetnsConfig = 15,
}

pub const HEAP_CLASS_COUNT: usize = 16;

impl HeapClass {
    /// D1-RES: authoritative class table for exhaustive boundary tests and
    /// snapshot iteration. Order matches the discriminants; the const assert
    /// below keeps the table in lock-step with `HEAP_CLASS_COUNT`.
    pub const ALL: [HeapClass; HEAP_CLASS_COUNT] = [
        Self::CoreProcess,
        Self::Capability,
        Self::Scheduler,
        Self::Cgroup,
        Self::Procfs,
        Self::BlockingIo,
        Self::Exec,
        Self::SocketObject,
        Self::SocketPayload,
        Self::RamFs,
        Self::Pipe,
        Self::Vfs,
        Self::Device,
        Self::FilesystemIo,
        Self::Futex,
        Self::NetnsConfig,
    ];

    #[inline]
    const fn index(self) -> usize {
        self as usize
    }

    /// Maximum bytes this class may retain or reserve concurrently.
    pub const fn limit_bytes(self) -> usize {
        match self {
            Self::CoreProcess => 512 * 1024,
            Self::Capability => 256 * 1024,
            Self::Scheduler => 256 * 1024,
            Self::Cgroup => 256 * 1024,
            Self::Procfs => 512 * 1024,
            // Preserve the historical 1 MiB payload contract plus the complete
            // allocator charge for a 1024-entry iovec staging vector. The
            // global ledger, rather than an artificial per-call reduction,
            // remains authoritative for concurrent blocked callers.
            Self::BlockingIo => 1024 * 1024 + 32 * 1024,
            // One exec transaction includes the image, pathname, argv/envp,
            // pointer arrays, loader scratch, and initial-stack staging.
            Self::Exec => 1024 * 1024,
            Self::SocketObject => 256 * 1024,
            Self::SocketPayload => 1024 * 1024,
            Self::RamFs => 512 * 1024,
            // The public pipe contract permits a full 1 MiB ring. Include
            // allocator/control-object slack so that valid maximum is not
            // rejected by a fairness ceiling before the global ledger runs.
            Self::Pipe => 1024 * 1024 + 16 * 1024,
            Self::Vfs => 512 * 1024,
            Self::Device => 256 * 1024,
            // RF180-34 FIX: the exact worst collection phase is 352,320 bytes:
            // one 64 KiB block scratch, 65,536 compact target IDs, 4,096
            // mapping-node IDs, and 4,096 packed u16 branch indices, including
            // allocator slack.  The 352 KiB ceiling leaves 8,128 bytes for
            // allocator capacity rounding; validation is smaller and disjoint.
            Self::FilesystemIo => 352 * 1024,
            Self::Futex => 128 * 1024,
            // D3-NETNS-DATAPLANE: Per-namespace dataplane state.
            // 512 KiB supports ~256 ARP entries (28 bytes each) + routing tables
            // + per-ns firewall metadata + allocator slack.
            Self::NetnsConfig => 512 * 1024,
        }
    }
}

const _: () = assert!(
    HeapClass::BlockingIo.limit_bytes() + HeapClass::FilesystemIo.limit_bytes()
        <= ADMITTED_HEAP_BYTES
);
// D1-RES: the class table must enumerate every discriminant exactly once.
// Index-match proves bijection (ALL[i].index()==i ∧ |ALL|==HEAP_CLASS_COUNT
// ⇒ all indices [0,HEAP_CLASS_COUNT) appear once, no duplicates).
const _: () = {
    let mut i = 0;
    while i < HEAP_CLASS_COUNT {
        assert!(HeapClass::ALL[i].index() == i);
        i += 1;
    }
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeapAdmissionError {
    NotPublished,
    ArithmeticOverflow,
    GlobalLimit,
    ClassLimit,
    CorruptState,
}

/// Packed `(committed, reserved)` counters.  A single CAS makes the global
/// coexistence check atomic instead of racing two independent atomics.
#[inline]
const fn pack(committed: u32, reserved: u32) -> u64 {
    ((committed as u64) << COUNTER_BITS) | reserved as u64
}

#[inline]
const fn unpack(state: u64) -> (u32, u32) {
    (
        (state >> COUNTER_BITS) as u32,
        (state & COUNTER_MASK) as u32,
    )
}

static PUBLISHED: AtomicBool = AtomicBool::new(false);
static GLOBAL_STATE: AtomicU64 = AtomicU64::new(0);
/// Host tests share the process-global ledger and run in parallel by default.
/// Serialize exact snapshot assertions without weakening their invariants.
#[cfg(test)]
pub(crate) static TEST_LEDGER_LOCK: spin::Mutex<()> = spin::Mutex::new(());
static CLASS_STATES: [AtomicU64; HEAP_CLASS_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[inline]
fn add_reserved(cell: &AtomicU64, bytes: usize, limit: usize) -> Result<(), HeapAdmissionError> {
    let bytes = u32::try_from(bytes).map_err(|_| HeapAdmissionError::ArithmeticOverflow)?;
    loop {
        let old = cell.load(Ordering::Acquire);
        let (committed, reserved) = unpack(old);
        let next_reserved = reserved
            .checked_add(bytes)
            .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
        let total = (committed as usize)
            .checked_add(next_reserved as usize)
            .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
        if total > limit {
            return Err(HeapAdmissionError::GlobalLimit);
        }
        if cell
            .compare_exchange_weak(
                old,
                pack(committed, next_reserved),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return Ok(());
        }
        core::hint::spin_loop();
    }
}

#[inline]
fn subtract_reserved(cell: &AtomicU64, bytes: usize) -> Result<(), HeapAdmissionError> {
    let bytes = u32::try_from(bytes).map_err(|_| HeapAdmissionError::ArithmeticOverflow)?;
    loop {
        let old = cell.load(Ordering::Acquire);
        let (committed, reserved) = unpack(old);
        let next_reserved = reserved
            .checked_sub(bytes)
            .ok_or(HeapAdmissionError::CorruptState)?;
        if cell
            .compare_exchange_weak(
                old,
                pack(committed, next_reserved),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return Ok(());
        }
        core::hint::spin_loop();
    }
}

#[inline]
fn commit_reserved(cell: &AtomicU64, bytes: usize) -> Result<(), HeapAdmissionError> {
    let bytes = u32::try_from(bytes).map_err(|_| HeapAdmissionError::ArithmeticOverflow)?;
    loop {
        let old = cell.load(Ordering::Acquire);
        let (committed, reserved) = unpack(old);
        let next_reserved = reserved
            .checked_sub(bytes)
            .ok_or(HeapAdmissionError::CorruptState)?;
        let next_committed = committed
            .checked_add(bytes)
            .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
        if cell
            .compare_exchange_weak(
                old,
                pack(next_committed, next_reserved),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return Ok(());
        }
        core::hint::spin_loop();
    }
}

#[inline]
fn subtract_committed(cell: &AtomicU64, bytes: usize) -> Result<(), HeapAdmissionError> {
    let bytes = u32::try_from(bytes).map_err(|_| HeapAdmissionError::ArithmeticOverflow)?;
    loop {
        let old = cell.load(Ordering::Acquire);
        let (committed, reserved) = unpack(old);
        let next_committed = committed
            .checked_sub(bytes)
            .ok_or(HeapAdmissionError::CorruptState)?;
        if cell
            .compare_exchange_weak(
                old,
                pack(next_committed, reserved),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return Ok(());
        }
        core::hint::spin_loop();
    }
}

fn reserve_pair(class: HeapClass, bytes: usize) -> Result<(), HeapAdmissionError> {
    if bytes == 0 {
        return Ok(());
    }
    add_reserved(&GLOBAL_STATE, bytes, ADMITTED_HEAP_BYTES)?;
    match add_reserved(&CLASS_STATES[class.index()], bytes, class.limit_bytes()) {
        Ok(()) => Ok(()),
        Err(HeapAdmissionError::GlobalLimit) => {
            // The second gate is the class gate; retain a precise public error.
            subtract_reserved(&GLOBAL_STATE, bytes).unwrap_or_else(|error| {
                panic!("heap admission global rollback failed after class limit: {error:?}")
            });
            Err(HeapAdmissionError::ClassLimit)
        }
        Err(error) => {
            subtract_reserved(&GLOBAL_STATE, bytes).unwrap_or_else(|rollback_error| {
                panic!(
                    "heap admission global rollback failed after class error {error:?}: \
                     {rollback_error:?}"
                )
            });
            Err(error)
        }
    }
}

fn release_reserved_pair(class: HeapClass, bytes: usize) -> Result<(), HeapAdmissionError> {
    if bytes == 0 {
        return Ok(());
    }
    // Class first is conservative: the global gate still withholds the bytes
    // until both counters have been updated.
    subtract_reserved(&CLASS_STATES[class.index()], bytes).unwrap_or_else(|error| {
        panic!("heap admission class reservation release corrupt: {error:?}")
    });
    subtract_reserved(&GLOBAL_STATE, bytes).unwrap_or_else(|error| {
        panic!("heap admission global reservation release corrupt: {error:?}")
    });
    Ok(())
}

fn commit_pair(class: HeapClass, bytes: usize) -> Result<(), HeapAdmissionError> {
    if bytes == 0 {
        return Ok(());
    }
    // Neither transition changes total admitted bytes.  Global first ensures a
    // concurrent global snapshot never observes the bytes as absent.
    commit_reserved(&GLOBAL_STATE, bytes)
        .unwrap_or_else(|error| panic!("heap admission global commit corrupt: {error:?}"));
    commit_reserved(&CLASS_STATES[class.index()], bytes)
        .unwrap_or_else(|error| panic!("heap admission class commit corrupt: {error:?}"));
    Ok(())
}

fn release_committed_pair(class: HeapClass, bytes: usize) -> Result<(), HeapAdmissionError> {
    if bytes == 0 {
        return Ok(());
    }
    subtract_committed(&CLASS_STATES[class.index()], bytes).unwrap_or_else(|error| {
        panic!("heap admission class committed release corrupt: {error:?}")
    });
    subtract_committed(&GLOBAL_STATE, bytes).unwrap_or_else(|error| {
        panic!("heap admission global committed release corrupt: {error:?}")
    });
    Ok(())
}

/// Publish the runtime ledger after the normal and emergency arenas exist.
pub(crate) fn publish() {
    assert!(
        REGISTERED_FIXED_RESERVE_BYTES + NORMAL_UNADMITTED_RESERVE_BYTES + ADMITTED_HEAP_BYTES
            <= NORMAL_HEAP_SIZE_BYTES,
        "R180 heap admission partition exceeds normal arena"
    );
    PUBLISHED.store(true, Ordering::Release);
}

#[inline]
pub fn is_published() -> bool {
    PUBLISHED.load(Ordering::Acquire)
}

/// Reserve bytes before a fallible allocation or side effect.
pub fn try_reserve(class: HeapClass, bytes: usize) -> Result<HeapReservation, HeapAdmissionError> {
    if !is_published() {
        return Err(HeapAdmissionError::NotPublished);
    }
    reserve_pair(class, bytes)?;
    Ok(HeapReservation {
        class,
        bytes,
        armed: true,
    })
}

#[must_use = "dropping a reservation rolls admission back"]
pub struct HeapReservation {
    class: HeapClass,
    bytes: usize,
    armed: bool,
}

impl HeapReservation {
    #[inline]
    pub fn class(&self) -> HeapClass {
        self.class
    }

    #[inline]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Reconcile an estimate with the allocator's actual resulting capacity.
    /// Increasing remains fallible; decreasing releases the excess immediately.
    pub fn resize(&mut self, new_bytes: usize) -> Result<(), HeapAdmissionError> {
        if !self.armed {
            return Err(HeapAdmissionError::CorruptState);
        }
        match new_bytes.cmp(&self.bytes) {
            core::cmp::Ordering::Equal => Ok(()),
            core::cmp::Ordering::Greater => {
                let additional = new_bytes
                    .checked_sub(self.bytes)
                    .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
                reserve_pair(self.class, additional)?;
                self.bytes = new_bytes;
                Ok(())
            }
            core::cmp::Ordering::Less => {
                let excess = self
                    .bytes
                    .checked_sub(new_bytes)
                    .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
                release_reserved_pair(self.class, excess)?;
                self.bytes = new_bytes;
                Ok(())
            }
        }
    }

    /// Convert the reservation into a lifetime charge after successful private
    /// construction and immediately before publication.
    pub fn commit(mut self) -> Result<HeapCharge, HeapAdmissionError> {
        commit_pair(self.class, self.bytes)?;
        self.armed = false;
        Ok(HeapCharge {
            class: self.class,
            bytes: self.bytes,
            armed: true,
        })
    }
}

impl Drop for HeapReservation {
    fn drop(&mut self) {
        if self.armed {
            release_reserved_pair(self.class, self.bytes)
                .unwrap_or_else(|error| panic!("heap reservation accounting corrupt: {error:?}"));
            self.armed = false;
        }
    }
}

impl fmt::Debug for HeapReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeapReservation")
            .field("class", &self.class)
            .field("bytes", &self.bytes)
            .field("armed", &self.armed)
            .finish()
    }
}

/// A committed charge embedded in, or owned alongside, the retained object.
#[must_use = "a HeapCharge must live exactly as long as the charged allocation"]
pub struct HeapCharge {
    class: HeapClass,
    bytes: usize,
    armed: bool,
}

impl HeapCharge {
    #[inline]
    pub fn class(&self) -> HeapClass {
        self.class
    }

    #[inline]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn try_reserve_more(&self, bytes: usize) -> Result<HeapReservation, HeapAdmissionError> {
        try_reserve(self.class, bytes)
    }

    /// Merge a successfully allocated growth reservation into this object's
    /// lifetime charge immediately before the new capacity becomes reachable.
    pub fn absorb(&mut self, reservation: HeapReservation) -> Result<(), HeapAdmissionError> {
        if !self.armed || reservation.class != self.class {
            return Err(HeapAdmissionError::CorruptState);
        }
        let new_total = self
            .bytes
            .checked_add(reservation.bytes)
            .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
        let _additional = reservation.commit()?;
        // `_additional` must not run Drop: its bytes are now owned by `self`.
        let mut additional = core::mem::ManuallyDrop::new(_additional);
        additional.armed = false;
        self.bytes = new_total;
        Ok(())
    }

    /// Release accounting only after the corresponding capacity has actually
    /// been deallocated.  This ordering prevents another admission from racing
    /// memory that is still live.
    pub fn release_after_deallocation(&mut self, bytes: usize) -> Result<(), HeapAdmissionError> {
        if !self.armed || bytes > self.bytes {
            return Err(HeapAdmissionError::CorruptState);
        }
        release_committed_pair(self.class, bytes)?;
        self.bytes -= bytes;
        Ok(())
    }
}

impl Drop for HeapCharge {
    fn drop(&mut self) {
        if self.armed {
            release_committed_pair(self.class, self.bytes)
                .unwrap_or_else(|error| panic!("heap charge accounting corrupt: {error:?}"));
            self.armed = false;
        }
    }
}

impl fmt::Debug for HeapCharge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeapCharge")
            .field("class", &self.class)
            .field("bytes", &self.bytes)
            .field("armed", &self.armed)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeapAdmissionSnapshot {
    pub committed_bytes: usize,
    pub reserved_bytes: usize,
    pub capacity_bytes: usize,
}

#[inline]
fn snapshot_cell(cell: &AtomicU64, capacity_bytes: usize) -> HeapAdmissionSnapshot {
    let (committed, reserved) = unpack(cell.load(Ordering::Acquire));
    HeapAdmissionSnapshot {
        committed_bytes: committed as usize,
        reserved_bytes: reserved as usize,
        capacity_bytes,
    }
}

pub fn snapshot() -> HeapAdmissionSnapshot {
    snapshot_cell(&GLOBAL_STATE, ADMITTED_HEAP_BYTES)
}

pub fn class_snapshot(class: HeapClass) -> HeapAdmissionSnapshot {
    snapshot_cell(&CLASS_STATES[class.index()], class.limit_bytes())
}

const ALLOCATOR_LINK_SLACK: usize = 2 * size_of::<usize>();

#[inline]
fn checked_align_up(value: usize, align: usize) -> Result<usize, HeapAdmissionError> {
    if !align.is_power_of_two() {
        return Err(HeapAdmissionError::ArithmeticOverflow);
    }
    value
        .checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .ok_or(HeapAdmissionError::ArithmeticOverflow)
}

/// Conservative charge for one allocator request.
pub fn allocation_charge_bytes(
    payload_bytes: usize,
    alignment: usize,
) -> Result<usize, HeapAdmissionError> {
    if payload_bytes == 0 {
        return Ok(0);
    }
    let alignment = alignment.max(align_of::<usize>());
    let with_links = payload_bytes
        .checked_add(ALLOCATOR_LINK_SLACK)
        .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
    checked_align_up(with_links, alignment)
}

pub fn arc_charge_bytes<T>() -> Result<usize, HeapAdmissionError> {
    // ArcInner carries strong and weak counters before T.
    let payload = size_of::<T>()
        .checked_add(2 * size_of::<usize>())
        .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
    allocation_charge_bytes(payload, align_of::<T>().max(align_of::<usize>()))
}

pub fn vec_charge_bytes<T>(capacity: usize) -> Result<usize, HeapAdmissionError> {
    if size_of::<T>() == 0 || capacity == 0 {
        return Ok(0);
    }
    let payload = size_of::<T>()
        .checked_mul(capacity)
        .ok_or(HeapAdmissionError::ArithmeticOverflow)?;
    allocation_charge_bytes(payload, align_of::<T>())
}

pub fn vec_growth_charge_bytes<T>(
    old_capacity: usize,
    new_capacity: usize,
) -> Result<usize, HeapAdmissionError> {
    if new_capacity < old_capacity {
        return Err(HeapAdmissionError::ArithmeticOverflow);
    }
    let old = vec_charge_bytes::<T>(old_capacity)?;
    let new = vec_charge_bytes::<T>(new_capacity)?;
    new.checked_sub(old)
        .ok_or(HeapAdmissionError::ArithmeticOverflow)
}

/// Allocation-free boot/runtime invariant test.
pub fn run_heap_admission_self_test() {
    assert!(is_published());
    let before = snapshot();
    assert!(before.committed_bytes + before.reserved_bytes <= before.capacity_bytes);

    let mut reservation = try_reserve(HeapClass::Device, 4096).expect("admission reserve");
    assert_eq!(snapshot().reserved_bytes, before.reserved_bytes + 4096);
    reservation.resize(6144).expect("admission grow");
    reservation.resize(2048).expect("admission shrink");
    let charge = reservation.commit().expect("admission commit");
    assert_eq!(charge.bytes(), 2048);
    assert_eq!(snapshot().committed_bytes, before.committed_bytes + 2048);
    drop(charge);
    assert_eq!(snapshot(), before);

    // Published single-operation maxima must fit their class gates after the
    // conservative allocator charge is included. Per-class fairness may
    // overlap, but it must not silently narrow a public API contract.
    let max_blocking_io = vec_charge_bytes::<u8>(1024 * 1024)
        .and_then(|payload| {
            vec_charge_bytes::<[usize; 2]>(1024).and_then(|iovecs| {
                payload
                    .checked_add(iovecs)
                    .ok_or(HeapAdmissionError::ArithmeticOverflow)
            })
        })
        .expect("blocking-I/O maximum charge overflow");
    assert!(max_blocking_io <= HeapClass::BlockingIo.limit_bytes());
    assert!(
        HeapClass::BlockingIo.limit_bytes() + HeapClass::FilesystemIo.limit_bytes()
            <= ADMITTED_HEAP_BYTES,
        "maximum user I/O and filesystem-internal transaction must coexist"
    );
    let max_pipe_payload =
        vec_charge_bytes::<u8>(1024 * 1024).expect("pipe maximum payload charge overflow");
    assert!(
        max_pipe_payload + 4096 <= HeapClass::Pipe.limit_bytes(),
        "Pipe class must preserve the public 1 MiB capacity plus object slack"
    );

    assert_eq!(
        try_reserve(HeapClass::Device, HeapClass::Device.limit_bytes() + 1)
            .expect_err("class over-limit must fail"),
        HeapAdmissionError::ClassLimit
    );
    assert_eq!(snapshot(), before);
}

// ============================================================================
// D1-RES: whole-heap coexistence oracle (PO-RES-02)
// ============================================================================

/// D1-RES: budget ceiling for the boot-time unledgered allocation footprint
/// (boot statics, subsystem initialization structures, allocator
/// normalization slack). Measured 156,920 B at the integration-test
/// checkpoint on 2026-07-20; the 192 KiB ceiling is 25% above that
/// measurement. The coexistence oracle fails the boot when the measured
/// baseline exceeds this ceiling, so unledgered boot-allocation growth is
/// caught absolutely — the drift leg alone would otherwise accept an
/// arbitrarily large self-derived baseline. Together the two legs bound
/// total unattributed use by
/// `BOOT_UNLEDGERED_FOOTPRINT_MAX_BYTES + NORMAL_UNADMITTED_RESERVE_BYTES`.
///
/// Physical coexistence (asserted in `heap_budget.rs`): this ceiling is
/// carved from the conntrack/futex share of `REGISTERED_FIXED_RESERVE_BYTES`
/// — those two subsystems charge their real allocations through the runtime
/// ledger (inside `ADMITTED_HEAP_BYTES`), so their 384 KiB withholding is
/// double-protection slack the boot footprint may physically occupy.
/// The boot footprint was measured at 156,920 B (default kernel, Balanced
/// profile, single-core QEMU) and 211,792 B (musl_test feature). Set to
/// 224 KiB (~8% headroom above the musl_test measurement, rounded) to
/// accommodate both profiles under one global ceiling.
///
/// PHASE 2 KCOV+FUZZ_RUNNER: The fuzz_runner feature adds ~30 KB of boot footprint
/// (coverage infrastructure + larger userspace binary embedded + executor runtime).
/// Budget raised to 256 KiB to accommodate this legitimate instrumentation overhead
/// while maintaining the fail-closed discipline for production builds.
#[cfg(feature = "fuzz_runner")]
pub const BOOT_UNLEDGERED_FOOTPRINT_MAX_BYTES: usize = 256 * 1024;

#[cfg(not(feature = "fuzz_runner"))]
pub const BOOT_UNLEDGERED_FOOTPRINT_MAX_BYTES: usize = 224 * 1024;

/// D1-RES R4: fail-closed ceiling on `mm::heap_peak_used_bytes()` at the boot
/// integration checkpoint — the first PEAK (not endpoint) bound for the boot
/// residual. CALIBRATED (measured + ~25%, rounded to 32 KiB, same provenance
/// protocol as BOOT_UNLEDGERED_FOOTPRINT_MAX_BYTES): the default runtime-suite
/// boot measured a peak of 1,239,112 B (≈1210 KiB, incl. the transient 1 MiB
/// contiguity probe); 1210 KiB × 1.27 ≈ 1536 KiB. fuzz_runner carries larger
/// boot instrumentation → 1792 KiB. Must exceed the endpoint carve-out and stay
/// under the arena. Re-measure and re-pin if the boot allocation profile changes.
#[cfg(feature = "fuzz_runner")]
pub const BOOT_PEAK_USED_MAX_BYTES: usize = 1792 * 1024;

#[cfg(not(feature = "fuzz_runner"))]
pub const BOOT_PEAK_USED_MAX_BYTES: usize = 1536 * 1024;

const _: () = assert!(BOOT_PEAK_USED_MAX_BYTES >= BOOT_UNLEDGERED_FOOTPRINT_MAX_BYTES);
const _: () = assert!(BOOT_PEAK_USED_MAX_BYTES < NORMAL_HEAP_SIZE_BYTES);

/// D1-RES: the largest single contiguous object any consumer may request — the
/// stdin/pipe/socket-payload 1 MiB contract. Used by the combined-load contiguity
/// probe. Must fit a single admitted `BlockingIo` charge and the admitted arena.
pub const LARGEST_SINGLE_ALLOCATION_BYTES: usize = 1024 * 1024;

const _: () = assert!(LARGEST_SINGLE_ALLOCATION_BYTES <= ADMITTED_HEAP_BYTES);

/// D1-RES coexistence-oracle outcome.
///
/// The oracle proves the admission ledger and the live allocator cannot
/// silently diverge past the declared partition: every allocator-consumed
/// byte is attributable to (a) the runtime admission ledger, (b) a registered
/// fixed-floor subsystem's own bounded storage, or (c) the 64 KiB unadmitted
/// reserve. Fragmentation/normalization slack is part of (c) by definition —
/// it is NOT granted its own tolerance, so the check cannot be weakened by an
/// unproven fudge factor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoexistenceVerdict {
    /// Every invariant held; `unattributed_bytes` fit the unadmitted reserve.
    Sound { unattributed_bytes: usize },
    /// Reservations were in flight; the authoritative check requires a
    /// quiescent ledger (reserved == 0). Callers at a boot checkpoint must
    /// treat this as a sequencing bug; diagnostic callers may retry.
    NotQuiescent { reserved_bytes: usize },
    /// Allocator-used bytes exceed ledger + fixed floors + unadmitted reserve:
    /// an unadmitted consumer (or accounting bug) escaped the partition.
    UnattributedOverrun {
        allocator_used_bytes: usize,
        ledger_bytes: usize,
        unattributed_bytes: usize,
    },
    /// The admission ledger claims more committed+floor bytes than the
    /// allocator has handed out — a ledger accounting inconsistency (charges
    /// released from memory that was never deallocated, or double-charging).
    LedgerExceedsAllocator {
        allocator_used_bytes: usize,
        attributed_bytes: usize,
    },
}

/// D1-RES: authoritative coexistence check (PO-RES-02).
///
/// `allocator_used_bytes` is the caller-supplied live normal-arena usage
/// (`NORMAL_HEAP_SIZE_BYTES - heap_free_bytes()`), passed in rather than read
/// here so this module keeps zero dependency on the allocator lock and the
/// caller controls the snapshot window. `fixed_floor_live_bytes` is the live
/// retained usage of floor subsystems NOT charged through this ledger
/// (page-cache metadata + audit ring; conntrack/futex charge through the
/// ledger and must NOT be re-attributed here — double subtraction would mask
/// real unadmitted growth).
///
/// The oracle captures a boot-time baseline of the unledgered allocation
/// footprint (boot statics, subsystem initialization structures, allocator
/// metadata). The `baseline_unledgered_bytes` parameter records this
/// one-time snapshot; the oracle verifies that unledgered growth since the
/// baseline stays within the declared 64 KiB unadmitted reserve. This
/// separates "boot cost" (known, constant, measured) from "runtime drift"
/// (the actual design defect D1-RES is meant to detect).
///
/// Quiescence contract: the verdict is authoritative only with no concurrent
/// heap mutation. Call from single-threaded boot checkpoints or diagnostics
/// that tolerate `NotQuiescent`. Never call from IRQ context (the caller's
/// allocator snapshot takes the allocator lock).
pub fn check_coexistence(
    allocator_used_bytes: usize,
    fixed_floor_live_bytes: usize,
    baseline_unledgered_bytes: Option<usize>,
) -> CoexistenceVerdict {
    let ledger = snapshot();
    if ledger.reserved_bytes != 0 {
        return CoexistenceVerdict::NotQuiescent {
            reserved_bytes: ledger.reserved_bytes,
        };
    }
    let attributed = ledger
        .committed_bytes
        .saturating_add(fixed_floor_live_bytes);
    let Some(unattributed) = allocator_used_bytes.checked_sub(attributed) else {
        return CoexistenceVerdict::LedgerExceedsAllocator {
            allocator_used_bytes,
            attributed_bytes: attributed,
        };
    };
    // When a baseline is provided, the oracle checks that runtime drift
    // (growth since the baseline) stays within the declared unadmitted
    // reserve. Without a baseline, use the full unattributed total — this
    // is conservative and will naturally be larger than the reserve during
    // boot, so callers without a baseline should treat the result as
    // diagnostic, not fail-closed.
    let drift = match baseline_unledgered_bytes {
        Some(base) => unattributed.saturating_sub(base),
        None => unattributed,
    };
    if drift > NORMAL_UNADMITTED_RESERVE_BYTES {
        return CoexistenceVerdict::UnattributedOverrun {
            allocator_used_bytes,
            ledger_bytes: ledger.committed_bytes,
            unattributed_bytes: unattributed,
        };
    }
    CoexistenceVerdict::Sound {
        unattributed_bytes: unattributed,
    }
}

/// D1-RES boundary self-test (PO-RES-02): drive EVERY class gate and the
/// global gate to rejection and prove clean, allocation-free, panic-free
/// error paths with exact ledger restoration.
///
/// Runs against the production ledger; tolerates ambient boot charges by
/// working with each class's *remaining* headroom instead of assuming an
/// empty ledger. Allocation-free by construction (reservations only — no
/// heap memory is allocated or freed).
pub fn run_heap_admission_boundary_self_test() {
    assert!(is_published());

    let global_before = snapshot();

    // 1) Per-class gate: for all 15 classes, fill the remaining class
    //    headroom exactly, prove the next byte is rejected with ClassLimit
    //    (not a panic), then release and prove exact restoration.
    for class in HeapClass::ALL {
        let class_before = class_snapshot(class);
        let used = class_before.committed_bytes + class_before.reserved_bytes;
        let headroom = class_before.capacity_bytes - used;
        // Global headroom can be smaller than class headroom; reserve only
        // what the global gate can grant. The class-limit probe below is
        // valid as long as the class is exactly full.
        let g = snapshot();
        let global_headroom = g.capacity_bytes - g.committed_bytes - g.reserved_bytes;
        if headroom > global_headroom {
            // Cannot fill this class without tripping the global gate first;
            // prove the GLOBAL gate instead for this class's request shape.
            let verdict = try_reserve(class, headroom)
                .expect_err("class fill above global headroom must fail");
            assert_eq!(
                verdict,
                HeapAdmissionError::GlobalLimit,
                "global gate must reject before class capacity for {class:?}"
            );
            assert_eq!(class_snapshot(class), class_before);
            continue;
        }
        let fill = try_reserve(class, headroom)
            .unwrap_or_else(|e| panic!("exact class fill must admit for {class:?}: {e:?}"));
        // reserve_pair gates global FIRST: if the fill consumed the last
        // global byte too (headroom == global_headroom), the probe is
        // rejected by the global gate; otherwise by the class gate.
        let expected = if headroom == global_headroom {
            HeapAdmissionError::GlobalLimit
        } else {
            HeapAdmissionError::ClassLimit
        };
        assert_eq!(
            try_reserve(class, 1).expect_err("full class must reject one byte"),
            expected,
            "one byte past the {class:?} ceiling must be rejected by the correct gate"
        );
        // Failed probe must not have changed any counter.
        let during = class_snapshot(class);
        assert_eq!(during.committed_bytes, class_before.committed_bytes);
        assert_eq!(
            during.reserved_bytes,
            class_before.reserved_bytes + headroom
        );
        drop(fill);
        assert_eq!(
            class_snapshot(class),
            class_before,
            "{class:?} not restored"
        );
    }

    // 2) Global gate: fill the remaining global headroom across classes
    //    (largest class headroom first), then prove the next byte fails with
    //    GlobalLimit even though at least one class still has headroom.
    {
        let g = snapshot();
        let mut remaining = g.capacity_bytes - g.committed_bytes - g.reserved_bytes;
        assert!(remaining > 0, "boot must leave admitted headroom");
        let mut holds: [Option<HeapReservation>; HEAP_CLASS_COUNT] =
            [const { None }; HEAP_CLASS_COUNT];
        for (i, class) in HeapClass::ALL.into_iter().enumerate() {
            if remaining == 0 {
                break;
            }
            let cs = class_snapshot(class);
            let class_headroom = cs.capacity_bytes - cs.committed_bytes - cs.reserved_bytes;
            // Leave one byte of class headroom so the final probe is decided
            // by the GLOBAL gate, not this class's gate.
            let take = class_headroom.saturating_sub(1).min(remaining);
            if take == 0 {
                continue;
            }
            holds[i] = Some(
                try_reserve(class, take)
                    .unwrap_or_else(|e| panic!("global fill via {class:?} failed: {e:?}")),
            );
            remaining -= take;
        }
        assert_eq!(
            remaining, 0,
            "class ceilings must be able to cover the global pool"
        );
        let probe = HeapClass::ALL
            .into_iter()
            .find(|&c| {
                let cs = class_snapshot(c);
                cs.capacity_bytes > cs.committed_bytes + cs.reserved_bytes
            })
            .expect("at least one class must retain headroom for the global probe");
        assert_eq!(
            try_reserve(probe, 1).expect_err("exhausted global pool must reject"),
            HeapAdmissionError::GlobalLimit,
            "probe must be rejected by the GLOBAL gate"
        );
        for hold in &mut holds {
            drop(hold.take());
        }
    }

    // 3) Zero-byte and overflow edges are gate-free / fail-closed.
    let zero = try_reserve(HeapClass::Device, 0).expect("zero-byte reserve is a no-op");
    drop(zero);
    assert_eq!(
        try_reserve(HeapClass::Device, usize::MAX).expect_err("usize::MAX must be rejected"),
        HeapAdmissionError::ArithmeticOverflow
    );

    // 4) Full lifecycle leg: reserved -> committed -> released must restore
    //    the exact baseline (the class legs above only exercise
    //    reserve/rollback; commit is the state production objects live in).
    //    Both the class cell AND the global cell are asserted at every stage.
    {
        let dev_before = class_snapshot(HeapClass::Device);
        let g_before = snapshot();
        let reservation =
            try_reserve(HeapClass::Device, 4096).expect("lifecycle reserve must admit");
        let g_reserved = snapshot();
        assert_eq!(g_reserved.reserved_bytes, g_before.reserved_bytes + 4096);
        assert_eq!(g_reserved.committed_bytes, g_before.committed_bytes);
        let charge = reservation.commit().expect("lifecycle commit must succeed");
        let committed = class_snapshot(HeapClass::Device);
        assert_eq!(committed.committed_bytes, dev_before.committed_bytes + 4096);
        assert_eq!(committed.reserved_bytes, dev_before.reserved_bytes);
        let g_committed = snapshot();
        assert_eq!(g_committed.committed_bytes, g_before.committed_bytes + 4096);
        assert_eq!(g_committed.reserved_bytes, g_before.reserved_bytes);
        drop(charge);
        assert_eq!(class_snapshot(HeapClass::Device), dev_before);
        assert_eq!(snapshot(), g_before);
    }

    // 5) Exact whole-ledger restoration.
    assert_eq!(
        snapshot(),
        global_before,
        "boundary test must not drift the ledger"
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn admitted_reservations_round_trip_without_drift() {
        let _guard = super::TEST_LEDGER_LOCK.lock();
        super::publish();
        super::run_heap_admission_self_test();
    }
}
