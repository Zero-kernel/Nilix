//! Cgroup v2 Resource Controller
//!
//! This module implements a minimal Cgroup v2 style resource controller for Zero-OS.
//! It provides hierarchical resource governance with three controllers:
//! - **CPU**: Weight-based scheduling and quota limits
//! - **Memory**: Hard and soft memory limits
//! - **PIDs**: Maximum process/thread count per cgroup
//!
//! # Architecture
//!
//! ```text
//! ROOT_CGROUP (id=0, depth=0, all controllers)
//!   ├── system.slice (id=1, depth=1)
//!   │   └── sshd.service (id=2, depth=2)
//!   └── user.slice (id=3, depth=1)
//!       └── user-1000.slice (id=4, depth=2)
//! ```
//!
//! # Security Considerations
//!
//! - **Depth Limit (MAX_CGROUP_DEPTH=8)**: Prevents deeply nested hierarchies that could
//!   cause stack overflow during traversal or excessive lock contention.
//! - **Count Limit (MAX_CGROUPS=4096)**: Prevents DoS via unbounded cgroup creation.
//! - **Controller Inheritance**: Child cgroups can only enable a subset of parent's controllers.
//! - **PID Quota Enforcement**: Tasks are rejected when cgroup's pids_max is reached.
//!
//! # References
//!
//! - Linux cgroup v2 documentation: Documentation/admin-guide/cgroup-v2.rst
//! - Phase F.2 in roadmap-enterprise.md

#![allow(dead_code)]

extern crate alloc;

use alloc::{
    alloc::{AllocError, Allocator, Global},
    sync::{Arc, Weak},
};
use core::{
    alloc::Layout,
    fmt,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use spin::{Lazy, Mutex, RwLock};

use bitflags::bitflags;
use mm::{
    arc_charge_bytes, try_reserve_heap, AdmittedMap, AdmittedSet, AdmittedVec, HeapCharge,
    HeapClass, PreparedAdmittedMapCapacity, PreparedAdmittedSetCapacity,
    PreparedAdmittedVecCapacity, RetiredAdmittedMapCapacity, RetiredAdmittedSetCapacity,
};

// ============================================================================
// Type Definitions
// ============================================================================

/// Unique identifier for a cgroup node.
///
/// The root cgroup always has ID 0. Child cgroups are assigned
/// monotonically increasing IDs starting from 1.
pub type CgroupId = u64;

/// Identifier for a task/process attached to a cgroup.
///
/// This maps to ProcessId from the process module.
pub type TaskId = u64;

/// Maximum allowed depth for the cgroup hierarchy.
///
/// Root is depth 0, so max depth 8 allows 9 levels total.
/// This prevents stack overflow during recursive operations
/// and limits lock contention in deep hierarchies.
pub const MAX_CGROUP_DEPTH: u32 = 8;

/// Maximum number of cgroups that can exist simultaneously.
///
/// This prevents DoS attacks where an adversary creates
/// unlimited cgroups to exhaust kernel memory.
pub const MAX_CGROUPS: usize = 4096;

// ============================================================================
// Exact-lifetime cgroup Arc admission (RF180-45)
// ============================================================================

/// The slot table is the physical cgroup-Arc bound, not merely the registry
/// bound. Deleted payloads whose Arc control blocks remain pinned by stale Weak
/// handles therefore continue consuming one slot and one admitted charge.
const CGROUP_ARC_SLOTS: usize = MAX_CGROUPS;
const _: () = assert!(CGROUP_ARC_SLOTS <= u16::MAX as usize + 1);

struct CgroupArcChargeSlot {
    generation: u64,
    allocated: bool,
    _charge: HeapCharge,
}

static CGROUP_ARC_CHARGES: Mutex<[Option<CgroupArcChargeSlot>; CGROUP_ARC_SLOTS]> =
    Mutex::new([const { None }; CGROUP_ARC_SLOTS]);
static NEXT_CGROUP_ARC_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Default)]
struct CgroupCreateFault {
    fail_arc_allocation: bool,
    fail_registry_prepare: bool,
    fail_children_prepare: bool,
    fail_after_children_insert: bool,
    interleave_sibling_once: bool,
    check_prepare_unlocked: bool,
    check_deallocate_unlocked: bool,
}

struct CgroupArcInstallError {
    _charge: HeapCharge,
}

/// Allocator carried by every cgroup strong and weak handle.
///
/// The generation-tagged static slot owns the whole-heap charge until `Arc`
/// invokes `deallocate` after the final strong and weak handles disappear.
/// Deallocation releases physical memory first and admission second.
#[derive(Clone, Copy, Debug)]
pub struct CgroupArcAllocator {
    slot: u16,
    generation: u64,
    fail_allocation: bool,
    check_deallocate_unlocked: bool,
}

impl CgroupArcAllocator {
    fn try_install(
        charge: HeapCharge,
        fail_allocation: bool,
        check_deallocate_unlocked: bool,
    ) -> Result<Self, CgroupArcInstallError> {
        let generation = match NEXT_CGROUP_ARC_GENERATION.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(generation) => generation,
            Err(_) => return Err(CgroupArcInstallError { _charge: charge }),
        };

        let mut charge = Some(charge);
        let mut slots = CGROUP_ARC_CHARGES.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(CgroupArcChargeSlot {
                    generation,
                    allocated: false,
                    _charge: charge.take().expect("cgroup Arc charge moved once"),
                });
                return Ok(Self {
                    slot: index as u16,
                    generation,
                    fail_allocation,
                    check_deallocate_unlocked,
                });
            }
        }
        Err(CgroupArcInstallError {
            _charge: charge.expect("cgroup Arc slot scan retained charge"),
        })
    }

    fn take_slot(self, expected_allocated: bool) -> CgroupArcChargeSlot {
        let mut slots = CGROUP_ARC_CHARGES.lock();
        let slot = slots
            .get_mut(self.slot as usize)
            .expect("RF180-45 cgroup Arc slot out of range");
        match slot.as_ref() {
            Some(entry)
                if entry.generation == self.generation && entry.allocated == expected_allocated => {
            }
            Some(entry) if entry.generation == self.generation => {
                panic!("RF180-45 cgroup Arc allocator state mismatch")
            }
            Some(_) => panic!("RF180-45 stale cgroup Arc allocator generation"),
            None => panic!("RF180-45 cgroup Arc slot released twice"),
        }
        slot.take()
            .expect("validated cgroup Arc charge disappeared")
    }

    fn cancel_failed_allocation(self) {
        drop(self.take_slot(false));
    }
}

unsafe impl Allocator for CgroupArcAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        {
            let mut slots = CGROUP_ARC_CHARGES.lock();
            let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) else {
                return Err(AllocError);
            };
            if entry.generation != self.generation || entry.allocated {
                return Err(AllocError);
            }
            entry.allocated = true;
        }

        if self.fail_allocation {
            let mut slots = CGROUP_ARC_CHARGES.lock();
            if let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) {
                if entry.generation == self.generation {
                    entry.allocated = false;
                }
            }
            return Err(AllocError);
        }

        match Global.allocate(layout) {
            Ok(allocation) => Ok(allocation),
            Err(error) => {
                let mut slots = CGROUP_ARC_CHARGES.lock();
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
        if self.check_deallocate_unlocked {
            assert!(
                CGROUP_REGISTRY.try_write().is_some(),
                "RF180-45 cgroup Arc deallocated under registry lock"
            );
        }
        unsafe { Global.deallocate(ptr, layout) };
        drop(self.take_slot(true));
    }
}

fn active_cgroup_arc_slots() -> usize {
    CGROUP_ARC_CHARGES
        .lock()
        .iter()
        .filter(|slot| slot.is_some())
        .count()
}

pub type CgroupArc = Arc<CgroupNode, CgroupArcAllocator>;
pub type CgroupWeak = Weak<CgroupNode, CgroupArcAllocator>;

const CGROUP_CHAIN_CAPACITY: usize = MAX_CGROUP_DEPTH as usize + 1;
const CGROUP_TASK_CAPACITY: usize = crate::process::PID_MAX as usize;

fn bounded_growth_target(
    current_capacity: usize,
    required: usize,
    domain_capacity: usize,
) -> Option<usize> {
    if required > domain_capacity {
        return None;
    }
    let amortized = current_capacity
        .max(4)
        .checked_mul(2)
        .unwrap_or(domain_capacity)
        .min(domain_capacity);
    Some(required.max(amortized))
}

fn cgroup_metadata_growth_target(
    current_capacity: usize,
    required: usize,
) -> Result<usize, CgroupError> {
    bounded_growth_target(current_capacity, required, MAX_CGROUPS).ok_or(CgroupError::CgroupLimit)
}

fn cgroup_task_growth_target(
    current_capacity: usize,
    required: usize,
) -> Result<usize, CgroupError> {
    bounded_growth_target(current_capacity, required, CGROUP_TASK_CAPACITY)
        .ok_or(CgroupError::PidsLimitExceeded)
}

fn prepare_set_capacity_with_fallback<K: Ord>(
    preferred: usize,
    required: usize,
) -> Result<PreparedAdmittedSetCapacity<K>, CgroupError> {
    match PreparedAdmittedSetCapacity::try_new(HeapClass::Cgroup, preferred) {
        Ok(prepared) => Ok(prepared),
        Err(_) if preferred != required => {
            PreparedAdmittedSetCapacity::try_new(HeapClass::Cgroup, required)
                .map_err(|_| CgroupError::OutOfMemory)
        }
        Err(_) => Err(CgroupError::OutOfMemory),
    }
}

fn prepare_map_capacity_with_fallback<K: Ord, V>(
    preferred: usize,
    required: usize,
) -> Result<PreparedAdmittedMapCapacity<K, V>, CgroupError> {
    match PreparedAdmittedMapCapacity::try_new(HeapClass::Cgroup, preferred) {
        Ok(prepared) => Ok(prepared),
        Err(_) if preferred != required => {
            PreparedAdmittedMapCapacity::try_new(HeapClass::Cgroup, required)
                .map_err(|_| CgroupError::OutOfMemory)
        }
        Err(_) => Err(CgroupError::OutOfMemory),
    }
}

struct CgroupArcChain {
    nodes: [Option<CgroupArc>; CGROUP_CHAIN_CAPACITY],
    len: usize,
}

impl CgroupArcChain {
    fn empty() -> Self {
        Self {
            nodes: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    fn push(&mut self, node: CgroupArc) -> Result<(), CgroupError> {
        if self.len == self.nodes.len() {
            return Err(CgroupError::DepthLimit);
        }
        self.nodes[self.len] = Some(node);
        self.len += 1;
        Ok(())
    }

    fn get(&self, index: usize) -> Option<&CgroupArc> {
        self.nodes.get(index).and_then(Option::as_ref)
    }

    fn iter(&self) -> impl Iterator<Item = &CgroupArc> {
        self.nodes[..self.len].iter().filter_map(Option::as_ref)
    }

    fn index_of(&self, candidate: &CgroupArc) -> Option<usize> {
        self.iter().position(|node| Arc::ptr_eq(node, candidate))
    }
}

fn collect_cgroup_ancestry(origin: &CgroupArc) -> Result<CgroupArcChain, CgroupError> {
    let mut chain = CgroupArcChain::empty();
    let mut cursor = Some(origin.clone());
    for _ in 0..CGROUP_CHAIN_CAPACITY {
        let Some(node) = cursor else {
            return Ok(chain);
        };
        cursor = node.parent();
        chain.push(node)?;
    }
    if cursor.is_some() {
        Err(CgroupError::DepthLimit)
    } else {
        Ok(chain)
    }
}

fn collect_controller_chain(
    origin: &CgroupArc,
    controller: CgroupControllers,
) -> Result<CgroupArcChain, CgroupError> {
    let ancestry = collect_cgroup_ancestry(origin)?;
    let mut selected = CgroupArcChain::empty();
    for node in ancestry.iter() {
        if node.controllers.contains(controller) {
            selected.push(node.clone())?;
        }
    }
    Ok(selected)
}

/// M2-1 SLICE-2: process-wide MEMORY over-uncharge tripwire (in bytes).
///
/// Incremented (by the clamped surplus) whenever an origin MEMORY unpin
/// (`CgroupStats::unpin_origin_mem`) finds its pre-value `< n` and the saturating
/// floor therefore silently absorbs `n - pre` bytes — i.e. an over-uncharge
/// (Σunpin > Σpin). It exists because the SLICE-3 delete-gate witness
/// (`mem_pinned == 0`) is, under saturating unpin, satisfiable by BOTH a true
/// telescope AND an over-uncharge bug; this counter distinguishes the two. It
/// MUST read 0 across every MATCHED charge/uncharge sequence. Production behavior
/// is unchanged — the unpin still saturates; this is a pure observability /
/// proof-artifact aid (asserted by `run_cgroup_pt_kmem_self_test`). It is NEVER
/// sampled by the delete-gate and is reset by the self-test via
/// `mem_unpin_underflow_take`.
static MEM_UNPIN_UNDERFLOW: AtomicU64 = AtomicU64::new(0);

/// M2-1 SLICE-2: read-and-clear the MEMORY over-uncharge tripwire. Used by the
/// self-test to assert a matched sequence left it 0 (true telescope) before the
/// deliberate saturation demonstration. Returns the absorbed-surplus byte total
/// accumulated since the last take.
pub fn mem_unpin_underflow_take() -> u64 {
    MEM_UNPIN_UNDERFLOW.swap(0, Ordering::SeqCst)
}

/// M2-1 SLICE-2: read the MEMORY over-uncharge tripwire WITHOUT clearing it.
pub fn mem_unpin_underflow_peek() -> u64 {
    MEM_UNPIN_UNDERFLOW.load(Ordering::SeqCst)
}

// ============================================================================
// RF178-12 FIX: synchronous, allocation-free #PF memory charging
// ============================================================================

const FAULT_CHARGE_CHAIN_CAPACITY: usize = MAX_CGROUP_DEPTH as usize + 1;

/// Failure modes for the try-only stack-fault charge transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultChargeError {
    Contended,
    NotFound,
    Invalid,
    LimitExceeded,
    Overflow,
    Invariant,
}

/// A hard cgroup charge owned by one synchronous user-stack fault.
///
/// Construction snapshots a fixed ancestry and its memory limits under try-only
/// guards, then charges the complete DATA batch before any PTE can be published.
/// Later PT-frame additions use only the captured Arcs, snapshots, and atomics,
/// so the page-table critical section never reaches a Level-5 lock. Dropping an
/// armed receipt rolls back every unpublished byte without allocating.
pub struct FaultMemoryCharge {
    origin: CgroupArc,
    chain: [Option<CgroupArc>; FAULT_CHARGE_CHAIN_CAPACITY],
    limits: [(Option<u64>, Option<u64>); FAULT_CHARGE_CHAIN_CAPACITY],
    chain_len: usize,
    charged_bytes: u64,
    armed: bool,
}

impl FaultMemoryCharge {
    pub fn try_new(cgroup_id: CgroupId, initial_bytes: u64) -> Result<Self, FaultChargeError> {
        if initial_bytes == 0 || initial_bytes & 0xfff != 0 {
            return Err(FaultChargeError::Invalid);
        }

        // The registry guard pins deletion safety until the origin pin and the
        // initial display charges are visible. No blocking acquire is permitted
        // from #PF, including for the root cgroup.
        let registry = CGROUP_REGISTRY
            .try_read()
            .ok_or(FaultChargeError::Contended)?;
        let origin = registry
            .get(&cgroup_id)
            .cloned()
            .ok_or(FaultChargeError::NotFound)?;
        if origin.deleted.load(Ordering::Acquire) {
            return Err(FaultChargeError::NotFound);
        }

        let mut chain: [Option<CgroupArc>; FAULT_CHARGE_CHAIN_CAPACITY] =
            core::array::from_fn(|_| None);
        let mut limits = [(None, None); FAULT_CHARGE_CHAIN_CAPACITY];
        let mut chain_len = 0usize;
        let mut depth = 0u32;
        let mut cursor = Some(origin.clone());
        while let Some(node) = cursor {
            if node.controllers.contains(CgroupControllers::MEMORY) {
                if chain_len == FAULT_CHARGE_CHAIN_CAPACITY {
                    return Err(FaultChargeError::Invalid);
                }
                let snapshot = node.limits.try_lock().ok_or(FaultChargeError::Contended)?;
                limits[chain_len] = (snapshot.memory_max, snapshot.memory_high);
                drop(snapshot);
                chain[chain_len] = Some(node.clone());
                chain_len += 1;
            }
            if depth >= MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
            cursor = node.parent();
        }

        let mut receipt = Self {
            origin,
            chain,
            limits,
            chain_len,
            charged_bytes: 0,
            armed: true,
        };
        receipt.try_add(initial_bytes)?;
        drop(registry);
        Ok(receipt)
    }

    /// Hard-charge an additional PT-frame delta using the transaction snapshot.
    pub fn try_add(&mut self, bytes: u64) -> Result<(), FaultChargeError> {
        if bytes == 0 {
            return Ok(());
        }
        if bytes & 0xfff != 0 {
            return Err(FaultChargeError::Invalid);
        }
        let new_total = self
            .charged_bytes
            .checked_add(bytes)
            .ok_or(FaultChargeError::Overflow)?;

        self.origin
            .stats
            .mem_pinned
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                current.checked_add(bytes)
            })
            .map_err(|_| FaultChargeError::Overflow)?;

        let mut charged_len = 0usize;
        for index in 0..self.chain_len {
            let Some(node) = self.chain[index].as_ref() else {
                self.rollback_delta(bytes, charged_len);
                return Err(FaultChargeError::Invariant);
            };
            let (max, high) = self.limits[index];
            match node.stats.memory_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |current| {
                    let next = current.checked_add(bytes)?;
                    if max.is_some_and(|limit| next > limit) {
                        return None;
                    }
                    Some(next)
                },
            ) {
                Ok(old) => {
                    charged_len += 1;
                    if high.is_some_and(|limit| old.saturating_add(bytes) > limit) {
                        node.stats.record_memory_high();
                    }
                }
                Err(_) => {
                    node.stats.record_memory_max();
                    self.rollback_delta(bytes, charged_len);
                    return Err(FaultChargeError::LimitExceeded);
                }
            }
        }

        self.charged_bytes = new_total;
        Ok(())
    }

    /// Return a known-unpublished suffix of the DATA reservation.
    pub fn refund(&mut self, bytes: u64) -> Result<(), FaultChargeError> {
        if bytes == 0 {
            return Ok(());
        }
        if bytes & 0xfff != 0 || bytes > self.charged_bytes {
            return Err(FaultChargeError::Invalid);
        }
        self.release_bytes(bytes)
    }

    #[inline]
    pub fn charged_bytes(&self) -> u64 {
        self.charged_bytes
    }

    /// Transfer ownership of every remaining byte to the address-space ledger.
    pub fn commit(mut self) {
        self.armed = false;
        self.charged_bytes = 0;
    }

    fn rollback_delta(&self, bytes: u64, charged_len: usize) {
        let mut released_len = 0usize;
        for index in 0..charged_len {
            let Some(node) = self.chain[index].as_ref() else {
                self.restore_display(bytes, released_len);
                return;
            };
            if node
                .stats
                .memory_current
                .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                    current.checked_sub(bytes)
                })
                .is_err()
            {
                self.restore_display(bytes, released_len);
                return;
            }
            released_len += 1;
        }
        if self
            .origin
            .stats
            .mem_pinned
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                current.checked_sub(bytes)
            })
            .is_err()
        {
            // Preserve the origin pin and restore display counters. This leaves
            // fail-closed over-accounting if a pre-existing invariant is broken.
            self.restore_display(bytes, released_len);
        }
    }

    fn release_bytes(&mut self, bytes: u64) -> Result<(), FaultChargeError> {
        let mut released_len = 0usize;
        for index in 0..self.chain_len {
            let Some(node) = self.chain[index].as_ref() else {
                self.restore_display(bytes, released_len);
                return Err(FaultChargeError::Invariant);
            };
            if node
                .stats
                .memory_current
                .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                    current.checked_sub(bytes)
                })
                .is_err()
            {
                self.restore_display(bytes, released_len);
                return Err(FaultChargeError::Invariant);
            }
            released_len += 1;
        }

        if self
            .origin
            .stats
            .mem_pinned
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                current.checked_sub(bytes)
            })
            .is_err()
        {
            self.restore_display(bytes, released_len);
            return Err(FaultChargeError::Invariant);
        }
        self.charged_bytes = self
            .charged_bytes
            .checked_sub(bytes)
            .ok_or(FaultChargeError::Invariant)?;
        Ok(())
    }

    fn restore_display(&self, bytes: u64, released_len: usize) {
        for index in 0..released_len {
            if let Some(node) = self.chain[index].as_ref() {
                let result = node.stats.memory_current.fetch_update(
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                    |current| current.checked_add(bytes),
                );
                debug_assert!(result.is_ok(), "fault charge rollback restore overflow");
            }
        }
    }
}

impl Drop for FaultMemoryCharge {
    fn drop(&mut self) {
        if self.armed && self.charged_bytes != 0 {
            // A failed exact rollback deliberately leaves the origin pin armed:
            // fail-closed over-accounting is safer than a silent limit bypass.
            let _ = self.release_bytes(self.charged_bytes);
        }
    }
}

// ============================================================================
// Controller Flags
// ============================================================================

bitflags! {
    /// Bitflags describing enabled controllers on a cgroup node.
    ///
    /// Controllers can only be enabled if the parent cgroup has them enabled.
    /// This enforces the "no internal processes" rule from cgroup v2.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CgroupControllers: u32 {
        /// CPU controller: weight-based scheduling and quota limits.
        const CPU    = 0x01;
        /// Memory controller: hard/soft limits and OOM configuration.
        const MEMORY = 0x02;
        /// PIDs controller: maximum number of tasks in the cgroup.
        const PIDS   = 0x04;
        /// IO controller: bandwidth and IOPS limits.
        const IO     = 0x08;
        /// J2-7: FILES controller — per-cgroup open file-descriptor count limit.
        const FILES  = 0x10;
        /// J2-8: NET controller — per-cgroup ephemeral-port count limit.
        /// (Bit reserved here so FILES/NET never alias; wired in J.2 item 8.)
        const NET    = 0x20;
    }
}

// ============================================================================
// Resource Limits
// ============================================================================

/// Resource limits supported by the cgroup controllers.
///
/// Each field is optional; `None` denotes "no limit" (inherited from parent
/// or unlimited). Limits are checked at task attach time and during resource
/// consumption.
#[derive(Debug, Clone, Default)]
pub struct CgroupLimits {
    /// CPU weight in the range 1-10000 (default: 100).
    ///
    /// Higher weight means more CPU time relative to siblings.
    /// Maps to `cpu.weight` in cgroup v2.
    pub cpu_weight: Option<u32>,

    /// CPU quota as `(max_microseconds, period_microseconds)`.
    ///
    /// The cgroup can use at most `max` microseconds of CPU time
    /// per `period` microseconds. Maps to `cpu.max` in cgroup v2.
    pub cpu_max: Option<(u64, u64)>,

    /// Hard memory limit in bytes.
    ///
    /// If exceeded, OOM killer is invoked. Maps to `memory.max`.
    pub memory_max: Option<u64>,

    /// Soft memory limit in bytes.
    ///
    /// If exceeded, reclaim is triggered but no OOM. Maps to `memory.high`.
    pub memory_high: Option<u64>,

    /// Maximum number of tasks (processes + threads) in the cgroup.
    ///
    /// fork/clone fails with EAGAIN when limit is reached.
    /// Maps to `pids.max` in cgroup v2.
    pub pids_max: Option<u64>,

    /// Aggregate I/O bandwidth limit in bytes per second (read + write).
    ///
    /// When exceeded, I/O operations are throttled until tokens refill.
    /// Uses token bucket algorithm with 4-second burst window.
    /// Maps to `io.max` (bps) in cgroup v2.
    pub io_max_bytes_per_sec: Option<u64>,

    /// Aggregate I/O operations per second limit (read + write).
    ///
    /// When exceeded, I/O operations are throttled until tokens refill.
    /// Uses token bucket algorithm with 4-second burst window.
    /// Maps to `io.max` (iops) in cgroup v2.
    pub io_max_iops_per_sec: Option<u64>,

    /// J2-7: Maximum number of open file descriptors in the cgroup (FILES controller).
    /// Hierarchical, in addition to per-process `RLIMIT_NOFILE`. `None` = unlimited.
    pub fds_max: Option<u64>,

    /// J2-8: Maximum number of ephemeral ports reserved in the cgroup (NET controller).
    /// `None` = unlimited. (Field reserved here; charge wiring lands in J.2 item 8.)
    pub ports_max: Option<u64>,

    /// J2-10: Maximum bytes of kernel memory for per-tenant VFS directory enumeration
    /// (MEMORY controller). `None` = unlimited. (Field reserved here; charge wiring
    /// lands in J.2 item 10.)
    pub vfs_dir_max: Option<u64>,
}

// ============================================================================
// Statistics
// ============================================================================

/// Lock-free statistics for a cgroup node.
///
/// Uses atomic operations to allow updates from interrupt context
/// and non-preemptible scheduler paths without taking locks.
#[derive(Debug)]
pub struct CgroupStats {
    /// Cumulative CPU time consumed in nanoseconds.
    pub cpu_time_ns: AtomicU64,

    /// Current memory usage in bytes (updated by memory controller).
    pub memory_current: AtomicU64,

    /// Number of times memory.high was exceeded.
    pub memory_events_high: AtomicU64,

    /// Number of times memory.max was hit (OOM events).
    pub memory_events_max: AtomicU64,

    /// Current number of attached tasks.
    pub pids_current: AtomicU64,

    /// Number of times pids.max was hit (fork failures).
    pub pids_events_max: AtomicU32,

    // IO controller statistics
    /// Total bytes read via block I/O.
    pub io_read_bytes: AtomicU64,
    /// Total bytes written via block I/O.
    pub io_write_bytes: AtomicU64,
    /// Total read I/O operations completed.
    pub io_read_ios: AtomicU64,
    /// Total write I/O operations completed.
    pub io_write_ios: AtomicU64,
    /// Number of times I/O was throttled due to io.max limit.
    pub io_throttle_events: AtomicU64,

    /// J2-7: Current number of open file descriptors charged to this cgroup.
    pub fds_current: AtomicU64,
    /// J2-7: Number of times fds.max was hit (EMFILE / fork-EAGAIN events).
    pub fds_events_max: AtomicU32,
    /// J2-8: Current number of ephemeral ports charged to this cgroup.
    pub ports_current: AtomicU64,
    /// J2-8: Number of times ports.max was hit.
    pub ports_events_max: AtomicU32,
    /// R170-2 FIX: number of live FD charges KEYED to this cgroup id —
    /// controller-INDEPENDENT (incremented at the charge ORIGIN even when
    /// this node has the FILES controller disabled and the display counter
    /// `fds_current` therefore stays 0). The `delete_cgroup` gate samples
    /// THIS, not the display counter: the charge walkers push display
    /// counters only to controller-bearing nodes while the stored uncharge
    /// key is the bare origin id, so a FILES-disabled leaf could be deleted
    /// with live ancestor charges keyed to it — the later uncharge then found
    /// no node and silently stranded the ancestors (the R170-2 leak class).
    /// NOT exposed in cgroupfs / the stats snapshot (display semantics are
    /// byte-identical to pre-R170-2). Mutated ONLY by
    /// `try_charge_fds`/`uncharge_fds` (and their migrate composition), so it
    /// cannot drift against a separate mirror (FA-04 inapplicable); a
    /// double-uncharge saturates DOWNWARD → the gate goes transiently
    /// lenient, never permanently blocked.
    pub fds_pinned: AtomicU64,
    /// R170-2 FIX: number of live ephemeral-port charges KEYED to this cgroup
    /// id — controller-independent twin of `fds_pinned` for the NET family
    /// (see its doc). This is the LIVE R170-2 instance: `PortBinding.
    /// charged_cgroup` stores the bare leaf id while a NET-disabled leaf's
    /// `ports_current` is permanently 0.
    pub ports_pinned: AtomicU64,
    /// M2-1 SLICE-2: number of live MEMORY charges (in bytes) KEYED to this
    /// cgroup id — controller-INDEPENDENT origin pin (twin of `fds_pinned`/
    /// `ports_pinned`). Incremented at the charge ORIGIN by every
    /// `try_charge_memory`/`charge_memory_forced` and decremented by every
    /// `uncharge_memory`, REGARDLESS of this node's MEMORY controller bit — so a
    /// MEMORY-disabled leaf whose display counter `memory_current` is permanently
    /// 0 still records its live keyed charges here. Pinning EVERY mutation inside
    /// the three primitives (not just the fork lump) makes the pin telescope on
    /// SUM equality (Σpin == Σunpin), defeating the historical FA-04 objection
    /// recorded at the delete-gate (which assumed a naive fork-only pin).
    ///
    /// NOT exposed in cgroupfs / the stats snapshot (display semantics stay
    /// byte-identical, exactly like `fds_pinned`/`ports_pinned`).
    ///
    /// SLICE-3 (DONE): the `delete_cgroup` resource gate NOW samples THIS field
    /// (origin-keyed, controller-independent — exactly like `fds_pinned`/
    /// `ports_pinned`), NOT the display counter `memory_current`. HARD
    /// `memory.max` enforcement still rides `memory_current`; `mem_pinned` is the
    /// delete-gate witness only (display / cgroupfs stay byte-identical). The flip
    /// was justified by the telescoping proof in `run_cgroup_pt_kmem_self_test`
    /// (Σpin == Σunpin with `MEM_UNPIN_UNDERFLOW == 0` across every matched
    /// charge/uncharge sequence) — see `run_cgroup_mem_pinned_delete_gate_self_test`
    /// for the gate behavior itself.
    ///
    /// SATURATION CAVEAT (M2-1 SLICE-2, lens "SATURATING-UNPIN-MASKING"):
    /// unpin is `saturating_sub`, so `mem_pinned == 0` is NECESSARY but NOT
    /// SUFFICIENT to prove reconciliation — it is satisfied by BOTH a true
    /// telescope (Σpin == Σunpin) AND an over-uncharge bug (Σunpin > Σpin), whose
    /// surplus the floor silently absorbs. Saturation is the SAFE (transiently
    /// LENIENT / never-permanently-blocked) direction for the gate, so it stays
    /// in production; but to make `mem_pinned == 0` a SOUND witness the
    /// debug-only `MEM_UNPIN_UNDERFLOW` tripwire (see `unpin_origin_mem`) fires
    /// whenever an unpin's pre-value `< n`. The SLICE-3 gate flip (DONE) was
    /// gated on the self-test asserting that tripwire stayed 0 across every
    /// MATCHED charge/uncharge sequence — NOT merely on observing
    /// `mem_pinned == 0`.
    pub mem_pinned: AtomicU64,
    /// J2-10: Current bytes of VFS directory-enumeration memory charged to this cgroup.
    pub vfs_dir_current: AtomicU64,
    /// J2-9: Current bytes of kernel memory charged to this cgroup (observability;
    /// hard enforcement remains via `memory_current`).
    pub kmem_current: AtomicU64,
}

impl CgroupStats {
    /// Creates a new zeroed statistics block.
    pub const fn new() -> Self {
        Self {
            cpu_time_ns: AtomicU64::new(0),
            memory_current: AtomicU64::new(0),
            memory_events_high: AtomicU64::new(0),
            memory_events_max: AtomicU64::new(0),
            pids_current: AtomicU64::new(0),
            pids_events_max: AtomicU32::new(0),
            io_read_bytes: AtomicU64::new(0),
            io_write_bytes: AtomicU64::new(0),
            io_read_ios: AtomicU64::new(0),
            io_write_ios: AtomicU64::new(0),
            io_throttle_events: AtomicU64::new(0),
            // J2-7/8/9/10: per-cgroup FD / port / VFS-dir / kmem counters.
            fds_current: AtomicU64::new(0),
            fds_events_max: AtomicU32::new(0),
            ports_current: AtomicU64::new(0),
            ports_events_max: AtomicU32::new(0),
            // R170-2: origin-keyed pinned counters (delete-gate, not display).
            fds_pinned: AtomicU64::new(0),
            ports_pinned: AtomicU64::new(0),
            // M2-1 SLICE-2: origin-keyed MEMORY pin (delete-gate, not display).
            mem_pinned: AtomicU64::new(0),
            vfs_dir_current: AtomicU64::new(0),
            kmem_current: AtomicU64::new(0),
        }
    }

    /// Produces a consistent point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> CgroupStatsSnapshot {
        CgroupStatsSnapshot {
            cpu_time_ns: self.cpu_time_ns.load(Ordering::Relaxed),
            memory_current: self.memory_current.load(Ordering::Relaxed),
            memory_events_high: self.memory_events_high.load(Ordering::Relaxed),
            memory_events_max: self.memory_events_max.load(Ordering::Relaxed),
            pids_current: self.pids_current.load(Ordering::Relaxed),
            pids_events_max: self.pids_events_max.load(Ordering::Relaxed),
            io_read_bytes: self.io_read_bytes.load(Ordering::Relaxed),
            io_write_bytes: self.io_write_bytes.load(Ordering::Relaxed),
            io_read_ios: self.io_read_ios.load(Ordering::Relaxed),
            io_write_ios: self.io_write_ios.load(Ordering::Relaxed),
            io_throttle_events: self.io_throttle_events.load(Ordering::Relaxed),
            fds_current: self.fds_current.load(Ordering::Relaxed),
            fds_events_max: self.fds_events_max.load(Ordering::Relaxed),
            ports_current: self.ports_current.load(Ordering::Relaxed),
            ports_events_max: self.ports_events_max.load(Ordering::Relaxed),
            vfs_dir_current: self.vfs_dir_current.load(Ordering::Relaxed),
            kmem_current: self.kmem_current.load(Ordering::Relaxed),
        }
    }

    /// Records additional CPU time consumed by this cgroup.
    #[inline]
    pub fn add_cpu_time(&self, delta_ns: u64) {
        self.cpu_time_ns.fetch_add(delta_ns, Ordering::Relaxed);
    }

    // R77-2 FIX: Removed set_memory_current() which used bare store().
    // Memory accounting is now exclusively through try_charge_memory()/uncharge_memory()
    // to prevent CAS overwrites. Use get_memory_current() for read-only access.

    /// Returns current memory usage (read-only snapshot).
    ///
    /// # R77-2 FIX
    ///
    /// This replaces the old `set_memory_current()` which used bare `store()`
    /// and could overwrite in-flight CAS updates from `try_charge_memory()`.
    /// Memory accounting should only be modified through:
    /// - `try_charge_memory()` for allocations (atomic CAS)
    /// - `uncharge_memory()` for deallocations (atomic fetch_update)
    #[inline]
    pub fn get_memory_current(&self) -> u64 {
        self.memory_current.load(Ordering::Relaxed)
    }

    /// Records a memory.high exceeded event.
    #[inline]
    pub fn record_memory_high(&self) {
        self.memory_events_high.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }

    /// Records a memory.max (OOM) event.
    #[inline]
    pub fn record_memory_max(&self) {
        self.memory_events_max.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }

    /// Increments the attached task count.
    #[inline]
    fn increment_pids(&self) {
        self.pids_current.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }

    /// Decrements the attached task count (saturating at zero).
    ///
    /// # R110-1 FIX: Saturating decrement via `fetch_update`
    ///
    /// Bare `fetch_sub(1)` could wrap `pids_current` to `u64::MAX` if called
    /// when the counter is already 0 (double-exit race, cgroup migration during
    /// exit).  This matches the `uncharge_memory` pattern used elsewhere.
    #[inline]
    fn decrement_pids(&self) {
        let _ = self
            .pids_current
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            });
    }

    /// Records a pids.max exceeded event.
    #[inline]
    fn record_pids_max_event(&self) {
        self.pids_events_max.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }

    /// J2-7: Decrements the FD count (saturating at zero), mirroring
    /// `decrement_pids` (R110-1) so a double-uncharge / migration race can never
    /// wrap `fds_current` to `u64::MAX`.
    #[inline]
    fn decrement_fds(&self, n: u64) {
        let _ = self
            .fds_current
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(n))
            });
    }

    /// J2-7: Records an fds.max exceeded event.
    #[inline]
    fn record_fds_max_event(&self) {
        self.fds_events_max.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }

    /// J2-8: Decrements the ephemeral-port count (saturating at zero), mirroring
    /// `decrement_fds` so a double-uncharge / teardown race (the deferred-uncharge
    /// queue can fold the same charge twice if a remove and a reaper both observe
    /// the entry) can never wrap `ports_current` to `u64::MAX`.
    #[inline]
    fn decrement_ports(&self, n: u64) {
        let _ = self
            .ports_current
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(n))
            });
    }

    /// R170-2: pin/unpin `n` origin-keyed charges of the given family on THIS
    /// node (controller-independent; saturating on unpin — see the field docs).
    #[inline]
    fn pin_origin(&self, pinned: &AtomicU64, n: u64) {
        let _ = pinned.fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
            Some(current.saturating_add(n))
        });
    }

    /// R170-2: saturating unpin (see `pin_origin`).
    #[inline]
    fn unpin_origin(&self, pinned: &AtomicU64, n: u64) {
        let _ = pinned.fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(n))
        });
    }

    /// M2-1 SLICE-2: saturating unpin for the MEMORY family with an over-uncharge
    /// TRIPWIRE. Production behavior is IDENTICAL to `unpin_origin` (saturating —
    /// the safe, transiently-lenient direction the delete-gate relies on), but in
    /// addition it observes — in the SAME atomic CAS as the subtract — whether the
    /// pre-value was `< n` (i.e. the saturating floor actually clamped, silently
    /// absorbing `n - pre` bytes of unpin). When it did, `MEM_UNPIN_UNDERFLOW` is
    /// incremented by the clamped surplus.
    ///
    /// WHY a dedicated MEMORY wrapper (not a generic tripwire in `unpin_origin`):
    /// for the fds/ports families a saturating over-uncharge IS the documented,
    /// accepted leniency direction and would trip spuriously. The MEMORY pin is
    /// the one whose `== 0` value is the SLICE-3 delete-gate
    /// witness, and under saturation `mem_pinned == 0` is satisfiable by BOTH a
    /// true telescope (Σpin == Σunpin) AND an over-uncharge bug (Σunpin > Σpin).
    /// This tripwire is what distinguishes the two: across any MATCHED
    /// charge/uncharge sequence it MUST stay 0; a nonzero value is an accounting
    /// regression (e.g. a future double-uncharge) that `mem_pinned == 0` alone
    /// would mask. It does NOT change the production floor — saturation still
    /// protects against permanent un-deletability (FA-04).
    #[inline]
    fn unpin_origin_mem(&self, n: u64) {
        let res = self
            .mem_pinned
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(n))
            });
        if let Ok(pre) = res {
            if pre < n {
                // The subtract clamped at 0: `n - pre` bytes of unpin had no live
                // pin to cancel ⇒ over-uncharge. Record the absorbed surplus so a
                // matched-sequence self-test can prove Σunpin == Σpin (tripwire 0)
                // rather than merely Σunpin >= Σpin (mem_pinned floored to 0).
                MEM_UNPIN_UNDERFLOW.fetch_add(n - pre, Ordering::Relaxed); // lint-fetch-add: allow (debug tripwire)
            }
        }
    }

    /// J2-8: Records a ports.max exceeded event.
    #[inline]
    fn record_ports_max_event(&self) {
        self.ports_events_max.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
    }
}

fn try_increment_pids(stats: &CgroupStats, limit: Option<u64>) -> Result<(), ()> {
    stats
        .pids_current
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            let next = current.checked_add(1)?;
            if limit.is_some_and(|maximum| next > maximum) {
                None
            } else {
                Some(next)
            }
        })
        .map(|_| ())
        .map_err(|_| ())
}

/// Point-in-time copy of `CgroupStats`.
///
/// This is returned by `CgroupNode::get_stats()` for safe reading
/// without holding any locks.
#[derive(Debug, Clone, Copy)]
pub struct CgroupStatsSnapshot {
    pub cpu_time_ns: u64,
    pub memory_current: u64,
    pub memory_events_high: u64,
    pub memory_events_max: u64,
    pub pids_current: u64,
    pub pids_events_max: u32,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub io_read_ios: u64,
    pub io_write_ios: u64,
    pub io_throttle_events: u64,
    pub fds_current: u64,
    pub fds_events_max: u32,
    pub ports_current: u64,
    pub ports_events_max: u32,
    pub vfs_dir_current: u64,
    pub kmem_current: u64,
}

// ============================================================================
// F.2: CPU Quota Tracking (cpu.max enforcement)
// ============================================================================

/// Per-cgroup CPU quota state for cpu.max enforcement.
///
/// Tracks per-period CPU usage and throttle state using lock-free atomics.
/// The quota is enforced by the scheduler: when usage exceeds max within a
/// period, the cgroup is throttled until the next period.
///
/// # Fields
///
/// * `period_start_ns` - Start time of the current accounting period
/// * `period_usage_ns` - Accumulated CPU time used in the current period
/// * `throttled_until_ns` - End of throttle window (0 = not throttled)
/// * `throttle_events` - Counter of throttle events for statistics
/// * `refreshing` - R110-2 FIX: Lock that serializes window refresh with charging
#[derive(Debug)]
struct CpuQuotaState {
    /// Start of the current quota period in nanoseconds since boot
    period_start_ns: AtomicU64,
    /// CPU time consumed in the current period
    period_usage_ns: AtomicU64,
    /// If non-zero, the cgroup is throttled until this time
    throttled_until_ns: AtomicU64,
    /// Number of times this cgroup has been throttled
    throttle_events: AtomicU64,
    /// R110-2 FIX: True while the CAS winner is resetting per-period counters.
    /// Chargers that observe `refreshing == true` skip charging for this tick
    /// (fail-closed: the tick is lost, which is the same behavior as lock
    /// contention on the limits mutex — documented as safe in charge_cpu_quota).
    refreshing: AtomicBool,
}

impl CpuQuotaState {
    /// Creates a new quota state with all fields zeroed.
    const fn new() -> Self {
        Self {
            period_start_ns: AtomicU64::new(0),
            period_usage_ns: AtomicU64::new(0),
            throttled_until_ns: AtomicU64::new(0),
            throttle_events: AtomicU64::new(0),
            refreshing: AtomicBool::new(false),
        }
    }

    /// Refresh the quota window if the period has elapsed.
    ///
    /// Called before charging or checking throttle state to ensure
    /// we're accounting against the correct period.
    ///
    /// # R110-2 FIX: SMP-safe window refresh via refresh lock + CAS
    ///
    /// The refresh lock (`refreshing: AtomicBool`) is acquired **before** the
    /// CAS on `period_start_ns`.  This ensures that:
    ///
    /// 1. Only one CPU can enter the refresh critical section at a time.
    /// 2. `period_start_ns` is only updated **after** `period_usage_ns` and
    ///    `throttled_until_ns` have been reset to 0.
    /// 3. Concurrent chargers that observe `refreshing == true` skip the tick
    ///    (fail-closed, same as limits-lock contention — documented as safe).
    ///
    /// The new period start is published last, so any CPU that observes the
    /// fresh `period_start_ns` is guaranteed to see zeroed usage counters.
    #[inline]
    fn refresh_window(&self, now_ns: u64, period_ns: u64) {
        let start = self.period_start_ns.load(Ordering::Acquire);

        // Fast-path: still within the current accounting window.
        if start != 0 && now_ns.saturating_sub(start) < period_ns {
            return;
        }

        // Try to acquire the refresh lock (non-blocking, single-winner).
        if self
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            // Another CPU is already refreshing — this tick is skipped
            // (fail-closed: chargers also check `is_refreshing()`).
            return;
        }

        // We hold the refresh lock.  Re-check the window under the lock
        // (another CPU may have completed a refresh between our initial
        // check and the lock acquisition).
        let start = self.period_start_ns.load(Ordering::Acquire);
        if start != 0 && now_ns.saturating_sub(start) < period_ns {
            self.refreshing.store(false, Ordering::Release);
            return;
        }

        // Reset per-period counters BEFORE publishing the new start time.
        // Any concurrent charger will see `refreshing == true` and skip.
        self.period_usage_ns.store(0, Ordering::Release);
        self.throttled_until_ns.store(0, Ordering::Release);

        // Publish the new window start — chargers that observe this value
        // are guaranteed to see zeroed usage/throttle counters above.
        self.period_start_ns.store(now_ns, Ordering::Release);

        // Release the refresh lock — chargers may resume.
        self.refreshing.store(false, Ordering::Release);
    }

    /// Returns true if a window refresh is currently in progress.
    ///
    /// Callers (charge_cpu_quota) should skip charging when this is true
    /// to avoid racing with the usage counter reset.
    #[inline]
    fn is_refreshing(&self) -> bool {
        self.refreshing.load(Ordering::Acquire)
    }

    /// Returns the number of throttle events.
    #[inline]
    fn throttle_count(&self) -> u64 {
        self.throttle_events.load(Ordering::Relaxed)
    }
}

/// Result of charging CPU quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuQuotaStatus {
    /// No CPU controller or cpu.max is unlimited.
    Unlimited,
    /// Quota available, time has been charged.
    Allowed,
    /// Quota exceeded; cgroup is throttled until the specified time (ns).
    /// The delta WAS accumulated (or coasted inside a live throttle window).
    Throttled(u64),
    /// R170-3 FIX: NOTHING was accumulated — the registry lookup or a
    /// per-node `limits` lock was contended and `charge_cpu_quota` bailed
    /// BEFORE any `period_usage_ns` motion (guaranteed by its snapshot-first
    /// phase structure). The payload is a retry hint like `Throttled`'s.
    /// Distinct from `Throttled` so the tick handler folds the un-accumulated
    /// delta into the per-PCB quota debt ONLY in this case — folding on a
    /// genuine `Throttled` would double-count a delta that already landed.
    ContentionDeferred(u64),
}

// ============================================================================
// F.2: IO Throttling (io.max enforcement)
// ============================================================================

/// I/O direction for bandwidth and IOPS accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDirection {
    /// Block read operation.
    Read,
    /// Block write operation.
    Write,
}

/// Result of charging I/O bandwidth tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoThrottleStatus {
    /// No IO controller or limits configured.
    Unlimited,
    /// Tokens available, I/O request permitted.
    Allowed,
    /// Tokens exhausted; caller should wait until `until_ns` before retrying.
    Throttled(u64),
}

/// Maximum burst window for IO token bucket (seconds).
///
/// Allows short bursts of up to 4 seconds worth of tokens, smoothing
/// out bursty workloads while still enforcing long-term average limits.
const IO_BURST_SECS: u64 = 4;

/// Nanoseconds per second constant.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Internal token bucket state for IO bandwidth and IOPS throttling.
///
/// Each cgroup has one of these, tracking both bytes/sec and IOPS tokens.
/// Protected by a mutex in `IoThrottleState`.
#[derive(Debug)]
struct IoBucketState {
    /// Last time tokens were refilled (nanoseconds since boot).
    last_refill_ns: u64,
    /// Current available byte tokens (decremented on IO, refilled over time).
    byte_tokens: u64,
    /// Current available IOPS tokens (decremented on IO, refilled over time).
    iops_tokens: u64,
    /// If non-zero, throttled until this time (nanoseconds since boot).
    throttle_until_ns: u64,
}

impl IoBucketState {
    /// Refill tokens based on elapsed time since last refill.
    ///
    /// Token bucket algorithm: tokens accumulate at the configured rate,
    /// normally capped at `rate * IO_BURST_SECS` to allow bounded bursts.
    ///
    /// # CODEX FIX: Stale Token Clamping
    ///
    /// When limits change from unlimited to limited, tokens may be at u64::MAX.
    /// This function now clamps tokens to the cap to prevent limit bypass.
    ///
    /// # CODEX FIX: Oversized I/O Support
    ///
    /// A single I/O larger than the burst capacity would deadlock because refill
    /// caps at `rate * burst`. To prevent this, `requested_bytes` extends the
    /// effective cap so large I/Os can eventually accumulate enough tokens.
    fn refill(&mut self, limits: &CgroupLimits, now_ns: u64, requested_bytes: u64) {
        let elapsed = if self.last_refill_ns == 0 {
            0
        } else {
            now_ns.saturating_sub(self.last_refill_ns)
        };

        // Refill byte tokens
        if let Some(bps) = limits.io_max_bytes_per_sec {
            let burst_cap = bps.saturating_mul(IO_BURST_SECS);
            // Allow cap to grow to requested_bytes to prevent deadlock on large I/O
            let effective_cap = burst_cap.max(requested_bytes);

            if self.last_refill_ns == 0 {
                // First refill: grant full burst capacity (not request-extended)
                self.byte_tokens = burst_cap;
            } else {
                // CODEX FIX: Clamp stale tokens when limit tightened or toggled on
                if self.byte_tokens > effective_cap {
                    self.byte_tokens = effective_cap;
                }
                if elapsed > 0 && self.byte_tokens < effective_cap {
                    // Proportional refill: tokens = elapsed_secs * rate
                    let add = ((elapsed as u128 * bps as u128) / NS_PER_SEC as u128) as u64;
                    self.byte_tokens =
                        core::cmp::min(effective_cap, self.byte_tokens.saturating_add(add));
                }
            }
        } else {
            self.byte_tokens = u64::MAX;
        }

        // Refill IOPS tokens
        if let Some(iops) = limits.io_max_iops_per_sec {
            let cap = iops.saturating_mul(IO_BURST_SECS);
            if self.last_refill_ns == 0 {
                self.iops_tokens = cap;
            } else {
                // CODEX FIX: Clamp stale tokens when limit tightened or toggled on
                if self.iops_tokens > cap {
                    self.iops_tokens = cap;
                }
                if elapsed > 0 && self.iops_tokens < cap {
                    let add = ((elapsed as u128 * iops as u128) / NS_PER_SEC as u128) as u64;
                    self.iops_tokens = core::cmp::min(cap, self.iops_tokens.saturating_add(add));
                }
            }
        } else {
            self.iops_tokens = u64::MAX;
        }

        // Clear expired throttle
        if self.throttle_until_ns != 0 && now_ns >= self.throttle_until_ns {
            self.throttle_until_ns = 0;
        }

        self.last_refill_ns = now_ns;
    }
}

/// Per-cgroup IO throttle state.
///
/// Wraps `IoBucketState` in a mutex for thread-safe access.
/// The mutex is only held during token accounting (microsecond-scale),
/// never while waiting for IO or rescheduling, avoiding deadlock with
/// the block layer's device locks.
#[derive(Debug)]
struct IoThrottleState {
    state: Mutex<IoBucketState>,
}

impl IoThrottleState {
    const fn new() -> Self {
        Self {
            state: Mutex::new(IoBucketState {
                last_refill_ns: 0,
                byte_tokens: 0,
                iops_tokens: 0,
                throttle_until_ns: 0,
            }),
        }
    }

    /// Charge IO tokens for a single operation.
    ///
    /// Refills tokens based on elapsed time, then attempts to consume tokens
    /// for the given operation. If insufficient tokens are available, computes
    /// the time until enough tokens will have accumulated and returns
    /// `Throttled(until_ns)`.
    ///
    /// # Arguments
    ///
    /// * `limits` - Current cgroup limits (must be locked by caller)
    /// * `bytes` - Number of bytes in this I/O operation
    /// * `now_ns` - Current time in nanoseconds since boot
    /// * `stats` - Cgroup stats for recording throttle events
    fn charge(
        &self,
        limits: &CgroupLimits,
        bytes: u64,
        now_ns: u64,
        stats: &CgroupStats,
    ) -> IoThrottleStatus {
        let mut bucket = self.state.lock();
        bucket.refill(limits, now_ns, bytes);

        // If still in a throttle window, return immediately
        if bucket.throttle_until_ns != 0 && now_ns < bucket.throttle_until_ns {
            return IoThrottleStatus::Throttled(bucket.throttle_until_ns);
        }

        let mut throttle_until = 0u64;

        // Check byte budget
        if let Some(bps) = limits.io_max_bytes_per_sec {
            if bucket.byte_tokens < bytes {
                // Not enough tokens: compute wait time for deficit to refill
                let deficit = bytes - bucket.byte_tokens;
                let wait_ns =
                    ((deficit as u128 * NS_PER_SEC as u128) + (bps as u128 - 1)) / bps as u128;
                throttle_until = now_ns.saturating_add(wait_ns as u64);
            } else {
                bucket.byte_tokens = bucket.byte_tokens.saturating_sub(bytes);
            }
        }

        // Check IOPS budget
        if let Some(iops) = limits.io_max_iops_per_sec {
            if bucket.iops_tokens == 0 {
                // No IOPS tokens: wait for one token to refill
                let nanos_per_io = NS_PER_SEC.checked_div(iops.max(1)).unwrap_or(NS_PER_SEC);
                throttle_until = throttle_until.max(now_ns.saturating_add(nanos_per_io));
            } else {
                bucket.iops_tokens = bucket.iops_tokens.saturating_sub(1);
            }
        }

        if throttle_until != 0 {
            bucket.throttle_until_ns = throttle_until;
            stats.io_throttle_events.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
            return IoThrottleStatus::Throttled(throttle_until);
        }

        IoThrottleStatus::Allowed
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors returned by cgroup operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupError {
    /// Creating child would exceed MAX_CGROUP_DEPTH.
    DepthLimit,
    /// Creating cgroup would exceed MAX_CGROUPS.
    CgroupLimit,
    /// Whole-heap admission or a fallible allocator request rejected metadata.
    OutOfMemory,
    /// An endpoint is pinned by another non-blocking migration transaction.
    Busy,
    /// Requested cgroup ID does not exist.
    NotFound,
    /// Task is already attached to this cgroup.
    TaskAlreadyAttached,
    /// Task is not attached to this cgroup.
    TaskNotAttached,
    /// Provided limit value is invalid (e.g., zero period).
    InvalidLimit,
    /// Requested controller is not enabled on this cgroup.
    ControllerDisabled,
    /// PID limit exceeded - cannot attach more tasks.
    PidsLimitExceeded,
    /// Memory limit exceeded - operation would cause OOM.
    MemoryLimitExceeded,
    /// Permission denied - requires CAP_SYS_ADMIN or cgroup ownership.
    PermissionDenied,
    /// Cannot delete non-empty cgroup (has children or tasks).
    NotEmpty,
    /// J2-7: FD limit exceeded - cannot open/install more file descriptors.
    FdsLimitExceeded,
    /// J2-8: Ephemeral-port limit exceeded - cannot reserve more ports.
    PortsLimitExceeded,
}

impl fmt::Display for CgroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CgroupError::DepthLimit => write!(
                f,
                "cgroup depth exceeds MAX_CGROUP_DEPTH ({})",
                MAX_CGROUP_DEPTH
            ),
            CgroupError::CgroupLimit => {
                write!(f, "cgroup count exceeds MAX_CGROUPS ({})", MAX_CGROUPS)
            }
            CgroupError::OutOfMemory => write!(f, "out of memory for cgroup metadata"),
            CgroupError::Busy => write!(f, "cgroup transaction is busy; retry"),
            CgroupError::NotFound => write!(f, "cgroup not found"),
            CgroupError::TaskAlreadyAttached => write!(f, "task already attached to this cgroup"),
            CgroupError::TaskNotAttached => write!(f, "task not attached to this cgroup"),
            CgroupError::InvalidLimit => write!(f, "invalid resource limit value"),
            CgroupError::ControllerDisabled => write!(f, "controller not enabled on this cgroup"),
            CgroupError::PidsLimitExceeded => write!(f, "pids.max limit exceeded"),
            CgroupError::MemoryLimitExceeded => write!(f, "memory.max limit exceeded"),
            CgroupError::PermissionDenied => write!(f, "permission denied"),
            CgroupError::NotEmpty => write!(f, "cgroup has children or attached tasks"),
            CgroupError::FdsLimitExceeded => write!(f, "files.max limit exceeded"),
            CgroupError::PortsLimitExceeded => write!(f, "ports.max limit exceeded"),
        }
    }
}

// ============================================================================
// Cgroup Node
// ============================================================================

/// A node in the cgroup hierarchy.
///
/// Each node represents a control group with:
/// - Hierarchy metadata (id, parent, children, depth)
/// - Enabled controllers (subset of parent's controllers)
/// - Resource limits (optional per-controller)
/// - Live statistics (lock-free atomics)
/// - Attached processes (protected by mutex)
#[derive(Debug)]
pub struct CgroupNode {
    /// Unique identifier for this cgroup.
    id: CgroupId,

    /// Weak reference to parent (None for root).
    parent: Option<CgroupWeak>,

    /// IDs of direct children.
    children: Mutex<AdmittedSet<CgroupId>>,

    /// Depth in hierarchy (root = 0).
    depth: u32,

    /// Enabled controllers (subset of parent's).
    controllers: CgroupControllers,

    /// Resource limits for enabled controllers.
    limits: Mutex<CgroupLimits>,

    /// Lock-free statistics.
    stats: CgroupStats,

    /// Set of attached task IDs.
    processes: Mutex<AdmittedSet<TaskId>>,

    /// Allocation-free pin for a two-cgroup migration transaction.
    /// It excludes overlapping migrations and deletion; ordinary attach/detach
    /// operations continue to serialize on the endpoint task-set mutexes.
    membership_frozen: AtomicBool,

    /// Manual reference count for external tracking.
    ref_count: AtomicU32,

    /// R77-1 FIX: Deletion flag to block late attaches after removal is initiated.
    ///
    /// This prevents the race where a thread holds an old Arc<CgroupNode> and
    /// attempts to attach_task() after delete_cgroup() has verified emptiness
    /// but before removing from the registry. Without this flag, such late
    /// attaches could create orphaned tasks in an unregistered cgroup.
    deleted: AtomicBool,

    /// P1-3: Delegated owner UID for this cgroup subtree.
    ///
    /// When set, the specified UID may manage this cgroup and all its
    /// descendants (create/delete children, set limits, migrate tasks)
    /// without requiring root.  Delegation is set by root via
    /// `delegate_cgroup()` and inherits downward: `is_delegated_to(uid)`
    /// walks the ancestor chain.
    delegate_uid: Mutex<Option<u32>>,

    /// F.2: CPU quota tracking state for cpu.max enforcement.
    ///
    /// Tracks per-period CPU usage and throttle state for the CPU controller.
    cpu_quota: CpuQuotaState,

    /// F.2: IO throttle state for io.max enforcement.
    ///
    /// Tracks IO bandwidth and IOPS tokens for the IO controller.
    io_throttle: IoThrottleState,
}

impl CgroupNode {
    /// Creates the root cgroup node with all controllers enabled.
    fn try_new_root() -> Result<CgroupArc, CgroupError> {
        let bytes = arc_charge_bytes::<CgroupNode>().map_err(|_| CgroupError::OutOfMemory)?;
        let reservation =
            try_reserve_heap(HeapClass::Cgroup, bytes).map_err(|_| CgroupError::OutOfMemory)?;
        let charge = reservation.commit().map_err(|_| CgroupError::OutOfMemory)?;
        let allocator = CgroupArcAllocator::try_install(charge, false, false)
            .map_err(|_| CgroupError::OutOfMemory)?;
        match Arc::try_new_in(
            Self {
                id: 0,
                parent: None,
                children: Mutex::new(AdmittedSet::new(HeapClass::Cgroup)),
                depth: 0,
                controllers: CgroupControllers::all(),
                limits: Mutex::new(CgroupLimits::default()),
                stats: CgroupStats::new(),
                processes: Mutex::new(AdmittedSet::new(HeapClass::Cgroup)),
                membership_frozen: AtomicBool::new(false),
                ref_count: AtomicU32::new(1),
                deleted: AtomicBool::new(false),     // R77-1 FIX
                delegate_uid: Mutex::new(None),      // P1-3
                cpu_quota: CpuQuotaState::new(),     // F.2: CPU quota tracking
                io_throttle: IoThrottleState::new(), // F.2: IO throttle state
            },
            allocator,
        ) {
            Ok(root) => Ok(root),
            Err(_) => {
                allocator.cancel_failed_allocation();
                Err(CgroupError::OutOfMemory)
            }
        }
    }

    /// Returns this cgroup's unique identifier.
    #[inline]
    pub fn id(&self) -> CgroupId {
        self.id
    }

    /// Returns the depth in the hierarchy (root = 0).
    #[inline]
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Returns the enabled controllers for this cgroup.
    #[inline]
    pub fn controllers(&self) -> CgroupControllers {
        self.controllers
    }

    /// Returns a copy of the current limits.
    pub fn limits(&self) -> CgroupLimits {
        self.limits.lock().clone()
    }

    /// Returns the parent cgroup, if any.
    pub fn parent(&self) -> Option<CgroupArc> {
        self.parent.as_ref().and_then(|w| w.upgrade())
    }

    /// Returns the IDs of direct children.
    pub fn children(&self) -> Result<AdmittedVec<CgroupId>, CgroupError> {
        let mut target = self.children.lock().len();
        loop {
            let mut snapshot = AdmittedVec::new(HeapClass::Cgroup);
            if target != 0 {
                let prepared = PreparedAdmittedVecCapacity::try_new(HeapClass::Cgroup, target)
                    .map_err(|_| CgroupError::OutOfMemory)?;
                snapshot
                    .install_prepared(prepared)
                    .map_err(|_| CgroupError::OutOfMemory)?;
            }

            let children = self.children.lock();
            if snapshot.capacity() < children.len() {
                target = children.len();
                drop(children);
                drop(snapshot);
                continue;
            }
            for child in children.iter().copied() {
                snapshot
                    .push_reserved(child)
                    .unwrap_or_else(|_| panic!("prepared cgroup child snapshot capacity vanished"));
            }
            drop(children);
            return Ok(snapshot);
        }
    }

    // ==================================================================
    // P1-3: Cgroup Delegation
    // ==================================================================

    /// Returns the delegate UID for this cgroup, if any.
    pub fn delegate_uid(&self) -> Option<u32> {
        *self.delegate_uid.lock()
    }

    /// Returns `true` if this cgroup (or any ancestor) is delegated to `uid`.
    ///
    /// Walks the ancestor chain upward; stops at the first match.
    pub fn is_delegated_to(&self, uid: u32) -> bool {
        if self.delegate_uid() == Some(uid) {
            return true;
        }
        // R169-L4 FIX: Bound the ancestor walk by MAX_CGROUP_DEPTH — the backstop
        // every other cgroup ancestor walk uses — so a corrupted/cyclic parent
        // chain cannot spin forever. The hierarchy is depth-capped at create time
        // (MAX_CGROUP_DEPTH), so this never truncates a legitimate chain.
        let mut depth: u32 = 0;
        let mut cursor = self.parent();
        while let Some(node) = cursor {
            if node.delegate_uid() == Some(uid) {
                return true;
            }
            if depth >= MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
            cursor = node.parent();
        }
        false
    }

    /// P1-3: Validate that `updated` limits do not exceed the effective ancestor limits.
    ///
    /// Called when a delegated (non-root) user sets limits.  Walks the full
    /// ancestor chain and finds the tightest (most restrictive) configured
    /// limit for each resource.  The delegated user's requested limits must
    /// not exceed those boundaries, preventing privilege escalation through
    /// the delegation mechanism.
    ///
    /// For resources where no ancestor has a configured limit, the check is
    /// skipped (unlimited parent means no boundary constraint).
    pub fn check_limit_boundary(&self, updated: &CgroupLimits) -> Result<(), CgroupError> {
        // Collect effective (tightest) ancestor limits by walking up the chain.
        let mut eff_cpu_max: Option<(u64, u64)> = None;
        let mut eff_memory_max: Option<u64> = None;
        let mut eff_memory_high: Option<u64> = None;
        let mut eff_pids_max: Option<u64> = None;
        let mut eff_io_bps: Option<u64> = None;
        let mut eff_io_iops: Option<u64> = None;
        let mut eff_fds_max: Option<u64> = None;
        let mut eff_ports_max: Option<u64> = None;
        let mut eff_vfs_dir_max: Option<u64> = None;

        // R169-L4 FIX: bound the ancestor walk by MAX_CGROUP_DEPTH (mirrors the
        // other cgroup ancestor walks) so a corrupted/cyclic parent chain cannot
        // spin forever. Depth-capped at create time, so legitimate chains fit.
        let mut depth: u32 = 0;
        let mut cursor = self.parent();
        while let Some(ancestor) = cursor {
            let al = ancestor.limits();

            // cpu.max: keep the tightest ratio (lowest max/period)
            if let Some((amax, aperiod)) = al.cpu_max {
                if amax != u64::MAX && aperiod != 0 {
                    eff_cpu_max = Some(match eff_cpu_max {
                        None => (amax, aperiod),
                        Some((emax, eperiod)) => {
                            // Compare ratios: amax/aperiod vs emax/eperiod
                            // via cross-multiplication to avoid floating point.
                            let a_val = (amax as u128) * (eperiod as u128);
                            let e_val = (emax as u128) * (aperiod as u128);
                            if a_val < e_val {
                                (amax, aperiod) // ancestor is tighter
                            } else {
                                (emax, eperiod) // existing is tighter
                            }
                        }
                    });
                }
            }

            // Scalar limits: take the minimum non-MAX value
            if let Some(v) = al.memory_max {
                if v != u64::MAX {
                    eff_memory_max = Some(eff_memory_max.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.memory_high {
                if v != u64::MAX {
                    eff_memory_high = Some(eff_memory_high.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.pids_max {
                if v != u64::MAX {
                    eff_pids_max = Some(eff_pids_max.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.io_max_bytes_per_sec {
                eff_io_bps = Some(eff_io_bps.map_or(v, |e: u64| e.min(v)));
            }
            if let Some(v) = al.io_max_iops_per_sec {
                eff_io_iops = Some(eff_io_iops.map_or(v, |e: u64| e.min(v)));
            }
            if let Some(v) = al.fds_max {
                if v != u64::MAX {
                    eff_fds_max = Some(eff_fds_max.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.ports_max {
                if v != u64::MAX {
                    eff_ports_max = Some(eff_ports_max.map_or(v, |e: u64| e.min(v)));
                }
            }
            if let Some(v) = al.vfs_dir_max {
                if v != u64::MAX {
                    eff_vfs_dir_max = Some(eff_vfs_dir_max.map_or(v, |e: u64| e.min(v)));
                }
            }

            if depth >= MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
            cursor = ancestor.parent();
        }

        // --- Validate updated limits against effective boundaries ---

        // cpu.max: compare bandwidth ratio
        if let Some((max, period)) = updated.cpu_max {
            if max == 0 || period == 0 {
                return Err(CgroupError::InvalidLimit);
            }
            if let Some((emax, eperiod)) = eff_cpu_max {
                // Child cannot be unlimited if any ancestor is finite.
                if max == u64::MAX {
                    return Err(CgroupError::PermissionDenied);
                }
                // child_ratio = max/period ≤ eff_ratio = emax/eperiod
                let lhs = (max as u128) * (eperiod as u128);
                let rhs = (emax as u128) * (period as u128);
                if lhs > rhs {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // memory.max
        if let Some(max) = updated.memory_max {
            if let Some(emax) = eff_memory_max {
                if max == u64::MAX || max > emax {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // memory.high
        if let Some(high) = updated.memory_high {
            if let Some(ehigh) = eff_memory_high {
                if high == u64::MAX || high > ehigh {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // pids.max
        if let Some(max) = updated.pids_max {
            if let Some(emax) = eff_pids_max {
                if max == u64::MAX || max > emax {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // io.max bytes per sec
        if let Some(bps) = updated.io_max_bytes_per_sec {
            if let Some(ebps) = eff_io_bps {
                if bps > ebps {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // io.max IOPS
        if let Some(iops) = updated.io_max_iops_per_sec {
            if let Some(eiops) = eff_io_iops {
                if iops > eiops {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        // J2-7 files.max / J2-8 net.ports.max / J2-10 vfs_dir.max: a delegated
        // child cannot exceed (or be unlimited beyond) the tightest ancestor cap.
        if let Some(max) = updated.fds_max {
            if let Some(emax) = eff_fds_max {
                if max == u64::MAX || max > emax {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }
        if let Some(max) = updated.ports_max {
            if let Some(emax) = eff_ports_max {
                if max == u64::MAX || max > emax {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }
        if let Some(max) = updated.vfs_dir_max {
            if let Some(emax) = eff_vfs_dir_max {
                if max == u64::MAX || max > emax {
                    return Err(CgroupError::PermissionDenied);
                }
            }
        }

        Ok(())
    }

    /// Returns the number of attached tasks.
    pub fn task_count(&self) -> usize {
        self.processes.lock().len()
    }

    /// Checks if a specific task is attached to this cgroup.
    pub fn has_task(&self, task: TaskId) -> bool {
        self.processes.lock().contains(&task)
    }

    /// Creates a new child cgroup under this parent.
    ///
    /// # Arguments
    ///
    /// * `parent` - Arc reference to the parent cgroup
    /// * `controllers` - Controllers to enable (must be subset of parent's)
    ///
    /// # Errors
    ///
    /// * `ControllerDisabled` - Requested controllers not enabled on parent
    /// * `DepthLimit` - Would exceed MAX_CGROUP_DEPTH
    /// * `CgroupLimit` - Would exceed MAX_CGROUPS
    pub fn new_child(
        parent: &CgroupArc,
        controllers: CgroupControllers,
    ) -> Result<CgroupArc, CgroupError> {
        Self::new_child_with_fault(parent, controllers, CgroupCreateFault::default())
    }

    fn new_child_with_fault(
        parent: &CgroupArc,
        controllers: CgroupControllers,
        fault: CgroupCreateFault,
    ) -> Result<CgroupArc, CgroupError> {
        // Validate controllers are subset of parent's
        if controllers.is_empty() || !parent.controllers.contains(controllers) {
            return Err(CgroupError::ControllerDisabled);
        }

        // Check depth limit
        let next_depth = parent.depth.saturating_add(1);
        if next_depth > MAX_CGROUP_DEPTH {
            return Err(CgroupError::DepthLimit);
        }

        // R111-1 FIX: Use fetch_update + checked_add to prevent wrapping to 0
        // on u64 overflow.  A bare fetch_add wraps the counter past 0 (root cgroup
        // ID), which would shadow the root cgroup in the registry.  This follows the
        // R105-5 pattern established for IPC endpoint IDs and socket IDs.
        let id = NEXT_CGROUP_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map_err(|_| CgroupError::CgroupLimit)?;

        // Create the detached node under an Arc reservation. It is not visible
        // until both registry and parent-membership backing are prepared.
        let node_bytes = arc_charge_bytes::<CgroupNode>().map_err(|_| CgroupError::OutOfMemory)?;
        let node_reservation = try_reserve_heap(HeapClass::Cgroup, node_bytes)
            .map_err(|_| CgroupError::OutOfMemory)?;
        let node_charge = node_reservation
            .commit()
            .map_err(|_| CgroupError::OutOfMemory)?;
        let allocator = CgroupArcAllocator::try_install(
            node_charge,
            fault.fail_arc_allocation,
            fault.check_deallocate_unlocked,
        )
        .map_err(|_| CgroupError::OutOfMemory)?;
        let node = match Arc::try_new_in(
            CgroupNode {
                id,
                parent: Some(Arc::downgrade(parent)),
                children: Mutex::new(AdmittedSet::new(HeapClass::Cgroup)),
                depth: next_depth,
                controllers,
                limits: Mutex::new(CgroupLimits::default()),
                stats: CgroupStats::new(),
                processes: Mutex::new(AdmittedSet::new(HeapClass::Cgroup)),
                membership_frozen: AtomicBool::new(false),
                ref_count: AtomicU32::new(1),
                deleted: AtomicBool::new(false),     // R77-1 FIX
                delegate_uid: Mutex::new(None),      // P1-3
                cpu_quota: CpuQuotaState::new(),     // F.2: CPU quota tracking
                io_throttle: IoThrottleState::new(), // F.2: IO throttle state
            },
            allocator,
        ) {
            Ok(node) => node,
            Err(_) => {
                allocator.cancel_failed_allocation();
                return Err(CgroupError::OutOfMemory);
            }
        };

        enum PublishOutcome {
            Retry {
                registry_target: Option<(usize, usize)>,
                children_target: Option<(usize, usize)>,
            },
            Published {
                retired_registry: Option<RetiredAdmittedMapCapacity<CgroupId, CgroupArc>>,
                retired_children: Option<RetiredAdmittedSetCapacity<CgroupId>>,
            },
            Failed {
                retired_registry: Option<RetiredAdmittedMapCapacity<CgroupId, CgroupArc>>,
                retired_children: Option<RetiredAdmittedSetCapacity<CgroupId>>,
                rejected_node: Option<CgroupArc>,
            },
        }

        // RF180-45: prepare both detached backings with no cgroup lock held,
        // then revalidate and publish under canonical registry -> children
        // order. Concurrent creators may stale either prepared capacity; the
        // loop retries without mutating membership or dropping an owner under a
        // lock. Publication itself is allocation-free.
        let mut prepared_registry: Option<PreparedAdmittedMapCapacity<CgroupId, CgroupArc>> = None;
        let mut prepared_children: Option<PreparedAdmittedSetCapacity<CgroupId>> = None;
        let mut interleave_sibling = fault.interleave_sibling_once;

        loop {
            let outcome = {
                let mut registry = CGROUP_REGISTRY.write();
                if registry.len() >= MAX_CGROUPS {
                    return Err(CgroupError::CgroupLimit);
                }
                let registered_parent = registry
                    .get(&parent.id)
                    .filter(|candidate| Arc::ptr_eq(candidate, parent))
                    .ok_or(CgroupError::NotFound)?;
                if registered_parent.deleted.load(Ordering::Acquire) {
                    return Err(CgroupError::NotFound);
                }
                let mut children = parent.children.lock();
                if children.contains(&id) || registry.contains_key(&id) {
                    return Err(CgroupError::CgroupLimit);
                }

                let registry_required = registry
                    .len()
                    .checked_add(1)
                    .ok_or(CgroupError::CgroupLimit)?;
                let children_required = children
                    .len()
                    .checked_add(1)
                    .ok_or(CgroupError::CgroupLimit)?;
                let registry_needs_backing = registry.capacity() < registry_required;
                let children_need_backing = children.capacity() < children_required;
                let registry_ready = !registry_needs_backing
                    || prepared_registry
                        .as_ref()
                        .map(|prepared| prepared.capacity() >= registry_required)
                        .unwrap_or(false);
                let children_ready = !children_need_backing
                    || prepared_children
                        .as_ref()
                        .map(|prepared| prepared.capacity() >= children_required)
                        .unwrap_or(false);

                if !registry_ready || !children_ready {
                    PublishOutcome::Retry {
                        registry_target: if !registry_ready {
                            Some((
                                cgroup_metadata_growth_target(
                                    registry.capacity(),
                                    registry_required,
                                )?,
                                registry_required,
                            ))
                        } else {
                            None
                        },
                        children_target: if !children_ready {
                            Some((
                                cgroup_metadata_growth_target(
                                    children.capacity(),
                                    children_required,
                                )?,
                                children_required,
                            ))
                        } else {
                            None
                        },
                    }
                } else {
                    let mut retired_registry = None;
                    let mut retired_children = None;
                    if registry_needs_backing {
                        let prepared = prepared_registry
                            .take()
                            .expect("validated cgroup registry backing disappeared");
                        retired_registry = Some(
                            registry
                                .install_prepared_deferred(prepared)
                                .expect("validated cgroup registry backing rejected"),
                        );
                    }
                    if children_need_backing {
                        let prepared = prepared_children
                            .take()
                            .expect("validated cgroup children backing disappeared");
                        retired_children = Some(
                            children
                                .install_prepared_deferred(prepared)
                                .expect("validated cgroup children backing rejected"),
                        );
                    }

                    children
                        .insert_reserved(id)
                        .unwrap_or_else(|_| panic!("prepared cgroup child slot vanished"));

                    let mut rejected_node = None;
                    let publication_failed = if fault.fail_after_children_insert {
                        true
                    } else {
                        match registry.insert_unique_reserved(id, node.clone()) {
                            Ok(()) => false,
                            Err((_id, rejected)) => {
                                rejected_node = Some(rejected);
                                true
                            }
                        }
                    };

                    if publication_failed {
                        assert!(
                            children.remove_retaining_capacity(&id),
                            "cgroup child rollback lost published id"
                        );
                        let retired_children = retired_children.map(|retired| {
                            children
                                .restore_retired_deferred(retired)
                                .unwrap_or_else(|_| panic!("cgroup child backing rollback failed"))
                        });
                        let retired_registry = retired_registry.map(|retired| {
                            registry
                                .restore_retired_deferred(retired)
                                .unwrap_or_else(|_| {
                                    panic!("cgroup registry backing rollback failed")
                                })
                        });
                        PublishOutcome::Failed {
                            retired_registry,
                            retired_children,
                            rejected_node,
                        }
                    } else {
                        PublishOutcome::Published {
                            retired_registry,
                            retired_children,
                        }
                    }
                }
            };

            match outcome {
                PublishOutcome::Retry {
                    registry_target,
                    children_target,
                } => {
                    if let Some((target, required)) = registry_target {
                        drop(prepared_registry.take());
                        if fault.check_prepare_unlocked {
                            assert!(
                                CGROUP_REGISTRY.try_write().is_some(),
                                "RF180-45 registry backing prepared under registry lock"
                            );
                            assert!(
                                parent.children.try_lock().is_some(),
                                "RF180-45 registry backing prepared under children lock"
                            );
                        }
                        if fault.fail_registry_prepare {
                            return Err(CgroupError::OutOfMemory);
                        }
                        prepared_registry =
                            Some(prepare_map_capacity_with_fallback(target, required)?);
                    }
                    if let Some((target, required)) = children_target {
                        drop(prepared_children.take());
                        if fault.check_prepare_unlocked {
                            assert!(
                                CGROUP_REGISTRY.try_write().is_some(),
                                "RF180-45 child backing prepared under registry lock"
                            );
                            assert!(
                                parent.children.try_lock().is_some(),
                                "RF180-45 child backing prepared under children lock"
                            );
                        }
                        if fault.fail_children_prepare {
                            return Err(CgroupError::OutOfMemory);
                        }
                        prepared_children =
                            Some(prepare_set_capacity_with_fallback(target, required)?);
                    }

                    if interleave_sibling {
                        interleave_sibling = false;
                        // Fill the just-observed child capacity completely.
                        // The outer candidate is then provably stale and must
                        // take the retry leg on its next revalidation.
                        let sibling_count = prepared_children
                            .as_ref()
                            .map(|prepared| prepared.capacity())
                            .unwrap_or(1)
                            .max(1);
                        for _ in 0..sibling_count {
                            let sibling = Self::new_child_with_fault(
                                parent,
                                controllers,
                                CgroupCreateFault::default(),
                            )?;
                            drop(sibling);
                        }
                    }
                }
                PublishOutcome::Published {
                    retired_registry,
                    retired_children,
                } => {
                    drop(prepared_registry.take());
                    drop(prepared_children.take());
                    drop(retired_registry);
                    drop(retired_children);
                    return Ok(node);
                }
                PublishOutcome::Failed {
                    retired_registry,
                    retired_children,
                    rejected_node,
                } => {
                    drop(prepared_registry.take());
                    drop(prepared_children.take());
                    drop(retired_registry);
                    drop(retired_children);
                    drop(rejected_node);
                    return Err(CgroupError::OutOfMemory);
                }
            }
        }
    }

    /// Attaches a task to this cgroup.
    ///
    /// Enforces the pids.max limit if the PIDs controller is enabled.
    ///
    /// # Errors
    ///
    /// * `NotFound` - Cgroup is being deleted (R77-1 FIX)
    /// * `TaskAlreadyAttached` - Task is already in this cgroup
    /// * `PidsLimitExceeded` - Would exceed pids.max
    ///
    /// # R90-3 FIX: Atomic pids.max enforcement
    ///
    /// Uses fetch_update CAS to atomically check-and-increment pids counters,
    /// preventing concurrent attach bypassing pids.max limits.
    pub fn attach_task(&self, task: TaskId) -> Result<(), CgroupError> {
        self.attach_task_impl(task)
    }

    fn attach_task_impl(&self, task: TaskId) -> Result<(), CgroupError> {
        let mut prepared_membership: Option<PreparedAdmittedSetCapacity<TaskId>> = None;
        loop {
            // R77-1 FIX: Block attaches once deletion has started. Rechecked
            // under the membership lock after every detached prepare.
            if self.deleted.load(Ordering::Acquire) {
                return Err(CgroupError::NotFound);
            }

            let mut procs = self.processes.lock();
            if self.deleted.load(Ordering::Acquire) {
                return Err(CgroupError::NotFound);
            }
            if procs.contains(&task) {
                return Err(CgroupError::TaskAlreadyAttached);
            }
            let required = procs
                .len()
                .checked_add(1)
                .ok_or(CgroupError::PidsLimitExceeded)?;
            if required > CGROUP_TASK_CAPACITY {
                self.stats.record_pids_max_event();
                return Err(CgroupError::PidsLimitExceeded);
            }
            if procs.capacity() < required
                && !prepared_membership
                    .as_ref()
                    .map(|prepared| prepared.capacity() >= required)
                    .unwrap_or(false)
            {
                let target = cgroup_task_growth_target(procs.capacity(), required)?;
                drop(procs);
                drop(prepared_membership.take());
                prepared_membership = Some(prepare_set_capacity_with_fallback(target, required)?);
                continue;
            }

            // R83-3 + R90-3 FIX: hierarchical PIDs enforcement with atomic
            // charging. The fixed ancestor storage and all limit snapshots are
            // allocation-free while membership is serialized.
            let mut ancestors: [Option<CgroupArc>; MAX_CGROUP_DEPTH as usize + 1] =
                core::array::from_fn(|_| None);
            let mut ancestor_count = 0usize;
            let mut depth: u32 = 0;
            let mut cursor = self.parent();
            while let Some(parent) = cursor {
                if ancestor_count == ancestors.len() {
                    drop(procs);
                    return Err(CgroupError::DepthLimit);
                }
                ancestors[ancestor_count] = Some(parent.clone());
                ancestor_count += 1;
                if depth >= MAX_CGROUP_DEPTH {
                    break;
                }
                depth = depth.saturating_add(1);
                cursor = parent.parent();
            }

            let self_limit = if self.controllers.contains(CgroupControllers::PIDS) {
                self.limits.lock().pids_max
            } else {
                None
            };
            let mut ancestor_limits = [None; MAX_CGROUP_DEPTH as usize + 1];
            for (index, ancestor) in ancestors[..ancestor_count].iter().enumerate() {
                let Some(ancestor) = ancestor.as_ref() else {
                    drop(procs);
                    return Err(CgroupError::OutOfMemory);
                };
                ancestor_limits[index] = if ancestor.controllers.contains(CgroupControllers::PIDS) {
                    ancestor.limits.lock().pids_max
                } else {
                    None
                };
            }

            if try_increment_pids(&self.stats, self_limit).is_err() {
                self.stats.record_pids_max_event();
                drop(procs);
                return Err(CgroupError::PidsLimitExceeded);
            }

            let mut charged_ancestors = 0usize;
            for index in 0..ancestor_count {
                let Some(ancestor) = ancestors[index].as_ref() else {
                    self.stats.decrement_pids();
                    for rollback in 0..charged_ancestors {
                        if let Some(node) = ancestors[rollback].as_ref() {
                            node.stats.decrement_pids();
                        }
                    }
                    drop(procs);
                    return Err(CgroupError::OutOfMemory);
                };
                if try_increment_pids(&ancestor.stats, ancestor_limits[index]).is_err() {
                    ancestor.stats.record_pids_max_event();
                    self.stats.decrement_pids();
                    for rollback in 0..charged_ancestors {
                        if let Some(node) = ancestors[rollback].as_ref() {
                            node.stats.decrement_pids();
                        }
                    }
                    drop(procs);
                    return Err(CgroupError::PidsLimitExceeded);
                }
                charged_ancestors += 1;
            }

            let mut retired = None;
            if procs.capacity() < required {
                retired = Some(
                    procs
                        .install_prepared_deferred(
                            prepared_membership
                                .take()
                                .expect("validated cgroup task backing disappeared"),
                        )
                        .expect("validated cgroup task backing rejected"),
                );
            }
            if procs.insert_reserved(task).is_err() {
                self.stats.decrement_pids();
                for index in 0..charged_ancestors {
                    if let Some(node) = ancestors[index].as_ref() {
                        node.stats.decrement_pids();
                    }
                }
                let retired = retired.map(|old| {
                    procs
                        .restore_retired_deferred(old)
                        .unwrap_or_else(|_| panic!("cgroup task backing rollback failed"))
                });
                drop(procs);
                drop(retired);
                return Err(CgroupError::OutOfMemory);
            }

            drop(procs);
            drop(retired);
            drop(prepared_membership.take());
            return Ok(());
        }
    }

    /// Detaches a task from this cgroup.
    ///
    /// # Errors
    ///
    /// * `TaskNotAttached` - Task is not in this cgroup
    pub fn detach_task(&self, task: TaskId) -> Result<(), CgroupError> {
        self.detach_task_impl(task)
    }

    fn detach_task_impl(&self, task: TaskId) -> Result<(), CgroupError> {
        // R83-3 FIX: Collect ancestors before detaching for hierarchical count update
        let mut ancestors: [Option<CgroupArc>; MAX_CGROUP_DEPTH as usize + 1] =
            core::array::from_fn(|_| None);
        let mut ancestor_count = 0usize;
        // R169-L4 FIX: bound the ancestor collection by MAX_CGROUP_DEPTH (mirrors
        // the other cgroup ancestor walks) so a corrupted/cyclic parent chain
        // cannot spin forever. Depth-capped at create time, so legitimate chains fit.
        let mut depth: u32 = 0;
        let mut cursor = self.parent();
        while let Some(p) = cursor {
            if ancestor_count == ancestors.len() {
                return Err(CgroupError::DepthLimit);
            }
            ancestors[ancestor_count] = Some(p.clone());
            ancestor_count += 1;
            if depth >= MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
            cursor = p.parent();
        }

        let mut procs = self.processes.lock();

        if !procs.remove_retaining_capacity(&task) {
            return Err(CgroupError::TaskNotAttached);
        }
        let retired = procs.take_empty_capacity();

        self.stats.decrement_pids();

        // R83-3 FIX: Decrement ancestor counts for hierarchical tracking
        for ancestor in ancestors[..ancestor_count].iter().flatten() {
            ancestor.stats.decrement_pids();
        }

        drop(procs);
        drop(retired);
        Ok(())
    }

    /// Updates resource limits for this cgroup.
    ///
    /// Only fields that are `Some` in the input are updated.
    ///
    /// # Errors
    ///
    /// * `ControllerDisabled` - Limit requires a controller not enabled
    /// * `InvalidLimit` - Value is invalid (e.g., zero weight/period)
    pub fn set_limit(&self, updated: CgroupLimits) -> Result<(), CgroupError> {
        // Validate controller availability
        if updated.cpu_weight.is_some() || updated.cpu_max.is_some() {
            if !self.controllers.contains(CgroupControllers::CPU) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        if updated.memory_max.is_some() || updated.memory_high.is_some() {
            if !self.controllers.contains(CgroupControllers::MEMORY) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        if updated.pids_max.is_some() {
            if !self.controllers.contains(CgroupControllers::PIDS) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        if updated.io_max_bytes_per_sec.is_some() || updated.io_max_iops_per_sec.is_some() {
            if !self.controllers.contains(CgroupControllers::IO) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        // J2-7/8/10: new resource limits require their controllers to be enabled.
        if updated.fds_max.is_some() {
            if !self.controllers.contains(CgroupControllers::FILES) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        if updated.ports_max.is_some() {
            if !self.controllers.contains(CgroupControllers::NET) {
                return Err(CgroupError::ControllerDisabled);
            }
        }
        if updated.vfs_dir_max.is_some() {
            if !self.controllers.contains(CgroupControllers::MEMORY) {
                return Err(CgroupError::ControllerDisabled);
            }
        }

        // Validate CPU weight (1-10000)
        if let Some(weight) = updated.cpu_weight {
            if weight == 0 || weight > 10000 {
                return Err(CgroupError::InvalidLimit);
            }
        }

        // Validate CPU quota (period > 0, max > 0, no overflow when converting to ns)
        if let Some((max, period)) = updated.cpu_max {
            if period == 0 || max == 0 {
                return Err(CgroupError::InvalidLimit);
            }
            // P1-3 FIX: Cap values to prevent saturating_mul(1_000) overflow
            // in the enforcement path (charge_cpu_quota). u64::MAX is exempt
            // as it means "unlimited".  1_000_000_000_000 µs ≈ 11.5 days.
            const MAX_CPU_US: u64 = 1_000_000_000_000;
            if max != u64::MAX && max > MAX_CPU_US {
                return Err(CgroupError::InvalidLimit);
            }
            if period > MAX_CPU_US {
                return Err(CgroupError::InvalidLimit);
            }
        }

        // Validate IO limits (must be non-zero if provided)
        if let Some(bps) = updated.io_max_bytes_per_sec {
            if bps == 0 {
                return Err(CgroupError::InvalidLimit);
            }
        }
        if let Some(iops) = updated.io_max_iops_per_sec {
            if iops == 0 {
                return Err(CgroupError::InvalidLimit);
            }
        }

        // Apply updates
        let mut limits = self.limits.lock();
        if let Some(v) = updated.cpu_weight {
            limits.cpu_weight = Some(v);
        }
        if let Some(v) = updated.cpu_max {
            limits.cpu_max = Some(v);
        }
        if let Some(v) = updated.memory_max {
            limits.memory_max = Some(v);
        }
        if let Some(v) = updated.memory_high {
            limits.memory_high = Some(v);
        }
        if let Some(v) = updated.pids_max {
            limits.pids_max = Some(v);
        }
        if let Some(v) = updated.io_max_bytes_per_sec {
            limits.io_max_bytes_per_sec = Some(v);
        }
        if let Some(v) = updated.io_max_iops_per_sec {
            limits.io_max_iops_per_sec = Some(v);
        }
        if let Some(v) = updated.fds_max {
            limits.fds_max = Some(v);
        }
        if let Some(v) = updated.ports_max {
            limits.ports_max = Some(v);
        }
        if let Some(v) = updated.vfs_dir_max {
            limits.vfs_dir_max = Some(v);
        }

        Ok(())
    }

    /// Returns a snapshot of current statistics.
    pub fn get_stats(&self) -> CgroupStatsSnapshot {
        self.stats.snapshot()
    }

    /// Increments the manual reference count (R112-2: overflow-safe).
    pub fn inc_ref(&self) {
        self.ref_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .expect("CgroupNode refcount overflow");
    }

    /// Decrements the manual reference count.
    pub fn dec_ref(&self) -> u32 {
        self.ref_count.fetch_sub(1, Ordering::SeqCst)
    }

    /// Returns the current reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count.load(Ordering::SeqCst)
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Global registry of all cgroups, keyed by CgroupId.
pub static CGROUP_REGISTRY: Lazy<RwLock<AdmittedMap<CgroupId, CgroupArc>>> =
    Lazy::new(|| RwLock::new(AdmittedMap::new(HeapClass::Cgroup)));

/// The root cgroup (id=0, all controllers enabled).
pub static ROOT_CGROUP: Lazy<CgroupArc> = Lazy::new(|| {
    let root = CgroupNode::try_new_root().expect("root cgroup heap admission failed");
    let prepared = PreparedAdmittedMapCapacity::try_new(HeapClass::Cgroup, 1)
        .expect("root cgroup registry admission failed");
    let (retired, rejected) = {
        let mut registry = CGROUP_REGISTRY.write();
        let retired = registry
            .install_prepared_deferred(prepared)
            .expect("prepared root cgroup registry backing rejected");
        let rejected = registry
            .insert_unique_reserved(root.id, root.clone())
            .err()
            .map(|(_id, root)| root);
        (retired, rejected)
    };
    drop(retired);
    if let Some(rejected) = rejected {
        drop(rejected);
        panic!("duplicate root cgroup publication");
    }
    root
});

/// Monotonic ID generator for cgroups (starts at 1, root is 0).
static NEXT_CGROUP_ID: AtomicU64 = AtomicU64::new(1);

/// Global cgroup count for quota enforcement.
static CGROUP_COUNT: AtomicU32 = AtomicU32::new(1); // Root counts as 1

/// Exclusive, allocation-free pin for one membership migration.
///
/// Construction runs under `CGROUP_REGISTRY.read()`, so deletion cannot pass
/// between identity validation and publication of the freeze. Once armed, the
/// registry guard is released; delete and overlapping migrations fail closed,
/// while endpoint attach/detach serialize normally on their task-set locks.
struct CgroupMembershipFreeze {
    first: CgroupArc,
    second: Option<CgroupArc>,
}

impl CgroupMembershipFreeze {
    fn try_new(from: &CgroupArc, to: &CgroupArc) -> Option<Self> {
        let same = Arc::ptr_eq(from, to);
        let (first, second) = if same || from.id() <= to.id() {
            (from, (!same).then_some(to))
        } else {
            (to, Some(from))
        };

        first
            .membership_frozen
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        if let Some(second) = second {
            if second
                .membership_frozen
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                first.membership_frozen.store(false, Ordering::Release);
                return None;
            }
        }

        Some(Self {
            first: first.clone(),
            second: second.cloned(),
        })
    }
}

impl Drop for CgroupMembershipFreeze {
    fn drop(&mut self) {
        if let Some(second) = self.second.as_ref() {
            second.membership_frozen.store(false, Ordering::Release);
        }
        self.first.membership_frozen.store(false, Ordering::Release);
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initializes the cgroup subsystem.
///
/// This forces initialization of the root cgroup and registry.
/// Should be called during kernel initialization.
pub fn init() {
    // Force lazy initialization
    let _ = ROOT_CGROUP.id();
    klog_always!("[cgroup] Cgroup v2 subsystem initialized (root id=0)");
}

/// Looks up a cgroup by its ID.
///
/// Returns `None` if the cgroup doesn't exist.
pub fn lookup_cgroup(id: CgroupId) -> Option<CgroupArc> {
    if id == 0 {
        return Some(ROOT_CGROUP.clone());
    }
    CGROUP_REGISTRY.read().get(&id).cloned()
}

/// R180-3: true if `target_id` is `ancestor_id` or a descendant of it.
///
/// Shared by both migration front doors (syscall 502 and cgroupfs `cgroup.procs`).
pub fn cgroup_is_descendant_of(target_id: CgroupId, ancestor_id: CgroupId) -> bool {
    if target_id == ancestor_id {
        return true;
    }
    let target = match lookup_cgroup(target_id) {
        Some(cg) => cg,
        None => return false,
    };
    let mut depth: u32 = 0;
    let mut cursor = target.parent();
    while let Some(parent) = cursor {
        if parent.id() == ancestor_id {
            return true;
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = parent.parent();
    }
    false
}

/// R180-3 CLASS FIX: authorize a task migration from `from_id` → `to_id`.
///
/// Single policy for both front doors (`sys_cgroup_attach` and cgroupfs
/// `cgroup.procs`). Identity is host-mapped (R134-2).
///
/// Rules (Safety > Efficiency):
/// 1. host root → Allow
/// 2. CAP_SYS_ADMIN (non-root): dest must be descendant-or-self of source (R93-5)
/// 3. delegated manager: **both** endpoints must be `is_delegated_to(euid)`
/// 4. else → PermissionDenied
///
/// Callers must re-invoke under the Process lock with the locked `from_id`
/// immediately before `migrate_task` (TOCTOU class).
pub fn authorize_cgroup_migrate(
    from_id: CgroupId,
    to_id: CgroupId,
    host_euid: Option<u32>,
    is_host_root: bool,
    has_cap_sys_admin: bool,
) -> Result<(), CgroupError> {
    if is_host_root {
        // Host root may re-home anywhere; still require nodes to exist so we
        // do not paper over NotFound with a later migrate_task error.
        let _ = lookup_cgroup(from_id).ok_or(CgroupError::NotFound)?;
        let _ = lookup_cgroup(to_id).ok_or(CgroupError::NotFound)?;
        return Ok(());
    }

    let from = lookup_cgroup(from_id).ok_or(CgroupError::NotFound)?;
    let to = lookup_cgroup(to_id).ok_or(CgroupError::NotFound)?;

    if has_cap_sys_admin {
        if cgroup_is_descendant_of(to_id, from_id) {
            return Ok(());
        }
        // RF180-2 FIX: capabilities and delegation are independent grants.
        // A caller that happens to hold CAP_SYS_ADMIN must not lose a valid
        // delegated source+destination authorization merely because the CAP
        // descendant rule does not apply.
    }

    let euid = host_euid.ok_or(CgroupError::PermissionDenied)?;
    // R180-3: BOTH endpoints must lie in the caller's delegated forest.
    // Destination-only checks allowed pulling a task from outside the forest
    // into a looser delegated sibling (isolation escape).
    if to.is_delegated_to(euid) && from.is_delegated_to(euid) {
        return Ok(());
    }
    Err(CgroupError::PermissionDenied)
}

/// R169-2 FIX (D1-CGROUP-IRQ-L5): Non-blocking sibling of `lookup_cgroup` for
/// IRQ / IRQ-disabled contexts (the timer-tick CPU accounting at
/// `on_clock_tick`, and the scheduler pick path via `cpu_quota_is_throttled`).
///
/// `lookup_cgroup` takes a BLOCKING `CGROUP_REGISTRY.read()` on a non-reentrant
/// `spin::RwLock`. If a same-CPU process-context writer (`create_cgroup` 1202 /
/// `delete_cgroup` 1639 / `migrate_task` 1708, all IRQs-enabled) is interrupted
/// mid-hold by the timer, the IRQ's blocking read spins forever on the lock the
/// suspended writer can never release → deterministic self-deadlock.
///
/// `try_read()` returns `None` immediately (never spins) on writer contention,
/// so this CANNOT block in an IRQ-off context regardless of writer discipline —
/// eliminating the deadlock class at the single chokepoint every IRQ-unsafe
/// registry read flows through. Mirrors the existing `cgroup.limits.try_lock()`
/// IRQ-safety pattern (2589). Root (id 0) short-circuits to `ROOT_CGROUP` and
/// never touches the registry, so it always resolves even in IRQ context.
pub fn try_lookup_cgroup(id: CgroupId) -> Option<CgroupArc> {
    if id == 0 {
        return Some(ROOT_CGROUP.clone());
    }
    CGROUP_REGISTRY.try_read().and_then(|g| g.get(&id).cloned())
}

/// Creates a new child cgroup under the specified parent.
///
/// This is a convenience wrapper around `CgroupNode::new_child()`.
pub fn create_cgroup(
    parent_id: CgroupId,
    controllers: CgroupControllers,
) -> Result<CgroupArc, CgroupError> {
    let parent = lookup_cgroup(parent_id).ok_or(CgroupError::NotFound)?;
    CgroupNode::new_child(&parent, controllers)
}

/// P1-3: Delegate management of a cgroup subtree to `uid`.
///
/// Root (euid 0), holders of CAP_SYS_ADMIN, or existing delegated managers
/// of this cgroup's subtree may call this.  Delegated managers may sub-delegate
/// within their delegated scope.
///
/// Once delegated, the specified UID may create/delete children, set limits
/// (bounded by the parent), and migrate tasks within this cgroup and all its
/// descendants.
///
/// Pass `uid = None` to revoke delegation.
///
/// # Returns
///
/// On success, returns the previous `delegate_uid` value for audit trail.
///
/// # Errors
///
/// * `PermissionDenied` - Caller lacks root, CAP_SYS_ADMIN, or delegation
/// * `NotFound` - Cgroup ID does not exist
pub fn delegate_cgroup(
    id: CgroupId,
    uid: Option<u32>,
    caller_authorized: bool,
) -> Result<Option<u32>, CgroupError> {
    if !caller_authorized {
        return Err(CgroupError::PermissionDenied);
    }
    let node = lookup_cgroup(id).ok_or(CgroupError::NotFound)?;
    let old_uid = core::mem::replace(&mut *node.delegate_uid.lock(), uid);
    Ok(old_uid)
}

/// Deletes a cgroup by ID.
///
/// The cgroup must be empty (no children, no attached tasks).
///
/// # Errors
///
/// * `NotFound` - Cgroup doesn't exist
/// * `NotEmpty` - Cgroup has children or attached tasks
/// * `PermissionDenied` - Cannot delete root cgroup
///
/// # CODEX FIX: Atomicity
///
/// Previously there was a TOCTOU race between checking emptiness and removing
/// from the registry. Now we hold the registry write lock throughout the operation,
/// preventing new tasks from being attached between the check and removal.
///
/// # R77-1 FIX: Deletion Flag
///
/// Additionally, we set the `deleted` flag before checking emptiness to block
/// any late attaches from threads holding old Arc<CgroupNode> references.
/// The attach_task() method checks this flag and rejects attaches to deleted cgroups.
pub fn delete_cgroup(id: CgroupId) -> Result<(), CgroupError> {
    if id == 0 {
        return Err(CgroupError::PermissionDenied);
    }

    // R169-3 / R169-L9/L10/L11 FIX (D2-J2-CHARGE-LIFETIME): BEFORE taking the
    // registry write lock, FIRST sweep dead-`Weak` bindings across ALL namespaces,
    // THEN flush the deferred per-cgroup port-uncharge queue in process context.
    // The sweep reclaims a charge stranded by a socket dropped without close() /
    // in a quiescent sibling netns (which the rate-gated reschedule sweep may not
    // have visited yet) so it stops inflating `ports_current` at the emptiness
    // gate below; the drain then applies every enqueued (swept + just-exited)
    // uncharge so the gate samples the true live count. A genuinely LIVE charge
    // (its `Weak` still upgrades) is left intact and correctly fails the delete
    // closed (the R169-3 loud-strand guarantee). BOTH steps MUST run before
    // `CGROUP_REGISTRY.write()` is held: the sweep takes the L8 binding locks and
    // only enqueues (no L5), but the drain acquires the L5 read path
    // (`uncharge_ports` -> `lookup_cgroup`) and the non-reentrant spin::RwLock
    // would self-deadlock under a held write guard. `delete_cgroup` runs in
    // process context (cgroupfs rmdir / sys path) with IRQs enabled, so the
    // blocking sweep+drain is safe here.
    net::socket_table().sweep_stranded_port_charges();
    net::socket_table().drain_deferred_port_uncharges();

    // CODEX FIX: Hold registry write lock throughout to prevent TOCTOU race
    // This blocks lookup_cgroup() used by attach_task(), ensuring no new
    // tasks can be attached between the emptiness check and removal.
    let mut registry = CGROUP_REGISTRY.write();

    let node = registry.get(&id).cloned().ok_or(CgroupError::NotFound)?;

    // RF180-45: migration publishes this allocation-free freeze while holding
    // a registry reader, then releases the registry before any detached heap
    // preparation. A writer that arrives afterward must fail closed until the
    // membership transaction commits or rolls back.
    if node.membership_frozen.load(Ordering::Acquire) {
        drop(registry);
        drop(node);
        return Err(CgroupError::NotEmpty);
    }

    // R77-1 FIX: Mark as deleting BEFORE checking emptiness to block any racing
    // attach_task() callers who hold old Arc<CgroupNode> references.
    // The deleted flag uses Acquire/Release ordering to ensure proper visibility.
    node.deleted.store(true, Ordering::Release);

    // Check if empty while holding registry write lock
    // No new tasks can attach because:
    // 1. lookup_cgroup needs registry read lock (which we hold as write)
    // 2. attach_task() checks deleted flag (which we just set)
    if !node.children.lock().is_empty() {
        // Rollback deleted flag since deletion failed
        node.deleted.store(false, Ordering::Release);
        drop(registry);
        drop(node);
        return Err(CgroupError::NotEmpty);
    }
    if !node.processes.lock().is_empty() {
        // Rollback deleted flag since deletion failed
        node.deleted.store(false, Ordering::Release);
        drop(registry);
        drop(node);
        return Err(CgroupError::NotEmpty);
    }

    // R169-3 FIX (D2-J2-CHARGE-LIFETIME): Reject deletion while the cgroup still
    // carries LIVE per-cgroup resource charges. These charges are keyed by a
    // bare `cgid` (e.g. `PortBinding.charged_cgroup`, and the memory/fd ancestor
    // walks); if the node leaves the registry while a charge still references
    // its id, the later `uncharge_*()` -> `lookup_cgroup(id) == None` becomes a
    // SILENT no-op and the `+N` applied to every ancestor at charge time is
    // NEVER reversed → permanent ancestor over-count → eventual
    // ports.max / files.max / memory.max self-DoS of the surviving subtree (the
    // R169-3 leak; ids are monotonic and never recycled, 1537, so there is no
    // misapply — only the leak). Gating the delete on the live counters (read
    // under the held write lock, `Acquire` to pair with the `SeqCst` charge
    // stores) keeps the id registry-resident until every charge is reconciled,
    // so each uncharge is guaranteed to find the node and actually decrement.
    // The `deleted` flag is already set (blocking new attach_task), and the
    // lifecycle guarantees no NEW charge lands after this gate samples zero:
    // migration is serialized under the Process lock and exit detaches the task
    // before its deferred uncharges, so the only post-gate counter motion is
    // DECREMENTS (the charge helpers themselves do not consult `deleted` — the
    // safety here is lifecycle-based, not flag-enforced).
    //
    // R170-2 FIX: the PORT and FD legs of the gate sample the origin-keyed
    // PINNED counters, NOT the display counters. The display counters are
    // controller-gated (the charge walkers skip controller-disabled nodes,
    // cgroup.rs try_charge_ports/try_charge_fds), while the stored uncharge
    // key is the bare ORIGIN id — so a NET/FILES-disabled leaf's display
    // counter stayed permanently 0, this gate passed, the leaf was deleted
    // with live ancestor charges keyed to it, and the later uncharge found no
    // node and silently stranded the ancestor chain (the R170-2 reopened
    // leak). `ports_pinned`/`fds_pinned` are incremented at the origin node
    // by every charge REGARDLESS of controller bits and decremented by every
    // uncharge of that key, so "gate passes ⇒ no live charge references this
    // id" now holds by construction for both families.
    //
    // M2-1 SLICE-3 FIX (closes R171-S-R170-2-01 / D-R170-DELETE-GATE-LEAF): the
    // MEMORY leg now ALSO samples the origin-keyed PINNED counter `mem_pinned`,
    // the twin of `ports_pinned`/`fds_pinned`. The identical leak class applied:
    // `memory_current` is the controller-gated DISPLAY counter (the charge walk
    // pushes it only to MEMORY-controller ancestors), so a MEMORY-DISABLED leaf's
    // `memory_current` is permanently 0 while live charges are keyed to its bare
    // origin id — the gate passed, the leaf was removed, and the later
    // `uncharge_memory(id, ..) -> lookup_cgroup(id) == None` became a SILENT
    // no-op, permanently stranding the ancestor over-count (eventual memory.max
    // self-DoS). `mem_pinned` is incremented at the ORIGIN by every
    // `try_charge_memory`/`charge_memory_forced` (rolled back on rejection),
    // decremented by every `uncharge_memory`, and re-homed by
    // `migrate_memory_charges` (= charge-dest + uncharge-source) REGARDLESS of any
    // node's MEMORY controller bit — so "gate passes ⇒ no live memory charge
    // references this id" now holds by construction.
    //
    // Why this is NOW safe (the historical FA-04 objection is DEFEATED): the old
    // worry was that the memory tally is amount/origin-asymmetric (fork charges
    // one aggregated lump to the parent's cgroup; the child's exit uncharges four
    // recomputed sums; migration re-snapshots compute_cgroup_charged_bytes), so a
    // NAIVE fork-only pin would drift nonzero on an empty cgroup → permanently
    // un-deletable. SLICE-2 pins EVERY mutation INSIDE the three primitives (not
    // just the fork lump) and SLICE-1 made the exec charge migration-atomic, so
    // for a reconciled cgroup the pin TELESCOPES exactly (Σpin == Σunpin) — proven
    // by the matched-sequence self-tests that assert `MEM_UNPIN_UNDERFLOW == 0`
    // (run_cgroup_pt_kmem / _coresidency / _exec_after_migrate / _clone_abort).
    // Saturation on unpin only ever floors `mem_pinned` DOWNWARD (the lenient,
    // transiently-leaky direction shared with ports/fds) — it can NEVER drive the
    // witness above true usage, so it cannot manufacture a stuck-positive →
    // permanent un-deletability is impossible. The only residual false-delete now
    // requires a saturating OVER-uncharge (Σunpin > Σpin) to mask a real residual,
    // strictly narrower than today's no-bug-required disabled-leaf strand.
    //
    // EXCLUDED from the gate: `kmem_current` (a currently-unwired/dead stat
    // field, always 0; J2-9 page-table kmem rides `memory_current`) and
    // `vfs_dir_current` (RAII `VfsDirBudgetGuard` Arc-pins the node, so its
    // uncharge always reaches the same node it charged and self-reconciles).
    //
    // Fail-CLOSED: a transient `NotEmpty`/EBUSY (the CAP_SYS_ADMIN / delegated
    // owner retries once in-flight teardown + uncharge settles — promptly,
    // because the deferred port queue was force-drained above and exit-path
    // uncharges run on every syscall-return/idle drain) is strictly safer than
    // a silent, unrecoverable over-count. ids are never recycled, so a deferred
    // delete can never misapply to a different cgroup. A saturating
    // double-uncharge can only under-count a pinned counter (transient
    // leniency, today's risk direction) — never permanently block deletion.
    let live_ports = node.stats.ports_pinned.load(Ordering::Acquire);
    let live_fds = node.stats.fds_pinned.load(Ordering::Acquire);
    // M2-1 SLICE-3: MEMORY leg now samples the origin-keyed pinned witness
    // (`mem_pinned`), not the controller-gated display counter `memory_current`.
    let live_mem = node.stats.mem_pinned.load(Ordering::Acquire);
    if live_ports != 0 || live_fds != 0 || live_mem != 0 {
        node.deleted.store(false, Ordering::Release);
        drop(registry);
        drop(node);
        return Err(CgroupError::NotEmpty);
    }

    // RF180-45: validate and remove under canonical registry -> children order,
    // but retain both backings until the transaction commits. Every obsolete
    // backing and every removed CgroupArc owner is destroyed after both locks.
    let Some(parent) = node.parent() else {
        node.deleted.store(false, Ordering::Release);
        drop(registry);
        drop(node);
        return Err(CgroupError::NotFound);
    };
    let mut children = parent.children.lock();
    if !children.contains(&id) {
        node.deleted.store(false, Ordering::Release);
        drop(children);
        drop(registry);
        drop(parent);
        drop(node);
        return Err(CgroupError::NotFound);
    }
    assert!(
        children.remove_retaining_capacity(&id),
        "validated cgroup child disappeared during deletion"
    );
    let removed = match registry.remove_retaining_capacity(&id) {
        Some(removed) => removed,
        None => {
            children
                .insert_reserved(id)
                .unwrap_or_else(|_| panic!("cgroup deletion rollback slot vanished"));
            node.deleted.store(false, Ordering::Release);
            drop(children);
            drop(registry);
            drop(parent);
            drop(node);
            return Err(CgroupError::NotFound);
        }
    };
    let retired_children = children.take_empty_capacity();
    let retired_registry = registry.take_empty_capacity();
    drop(children);
    drop(registry);
    drop(retired_children);
    drop(retired_registry);
    drop(removed);
    drop(parent);
    drop(node);
    Ok(())
}

/// Returns the root cgroup.
pub fn root_cgroup() -> CgroupArc {
    ROOT_CGROUP.clone()
}

/// Returns the total number of cgroups.
pub fn cgroup_count() -> usize {
    CGROUP_REGISTRY.read().len()
}

struct CgroupMigrationProbe<'a> {
    sibling: &'a CgroupArc,
    task: TaskId,
}

enum LockedMigrationOutcome {
    Retry {
        preferred: usize,
        required: usize,
    },
    Complete {
        retired_target: Option<RetiredAdmittedSetCapacity<TaskId>>,
        retired_source: Option<RetiredAdmittedSetCapacity<TaskId>>,
    },
    Failed {
        error: CgroupError,
        retired_target: Option<RetiredAdmittedSetCapacity<TaskId>>,
    },
}

fn migration_exclusive_lengths(
    source: &CgroupArcChain,
    target: &CgroupArcChain,
) -> Result<(usize, usize), CgroupError> {
    for target_index in 0..target.len {
        let Some(target_node) = target.get(target_index) else {
            return Err(CgroupError::DepthLimit);
        };
        if let Some(source_index) = source.index_of(target_node) {
            return Ok((source_index, target_index));
        }
    }
    Err(CgroupError::DepthLimit)
}

fn rollback_migration_target_reservations(chain: &CgroupArcChain, charged_len: usize) {
    for index in 0..charged_len {
        if let Some(node) = chain.get(index) {
            node.stats.decrement_pids();
        }
    }
}

fn migrate_task_locked(
    task: TaskId,
    from_procs: &mut AdmittedSet<TaskId>,
    to_procs: &mut AdmittedSet<TaskId>,
    source_chain: &CgroupArcChain,
    target_chain: &CgroupArcChain,
    source_exclusive_len: usize,
    target_exclusive_len: usize,
    prepared_target: &mut Option<PreparedAdmittedSetCapacity<TaskId>>,
    probe: Option<&CgroupMigrationProbe<'_>>,
) -> LockedMigrationOutcome {
    if !from_procs.contains(&task) {
        return LockedMigrationOutcome::Failed {
            error: CgroupError::TaskNotAttached,
            retired_target: None,
        };
    }
    if to_procs.contains(&task) {
        return LockedMigrationOutcome::Failed {
            error: CgroupError::TaskAlreadyAttached,
            retired_target: None,
        };
    }

    let required = match to_procs.len().checked_add(1) {
        Some(required) if required <= CGROUP_TASK_CAPACITY => required,
        _ => {
            return LockedMigrationOutcome::Failed {
                error: CgroupError::PidsLimitExceeded,
                retired_target: None,
            }
        }
    };
    if to_procs.capacity() < required
        && !prepared_target
            .as_ref()
            .map(|prepared| prepared.capacity() >= required)
            .unwrap_or(false)
    {
        let preferred = match cgroup_task_growth_target(to_procs.capacity(), required) {
            Ok(preferred) => preferred,
            Err(error) => {
                return LockedMigrationOutcome::Failed {
                    error,
                    retired_target: None,
                }
            }
        };
        return LockedMigrationOutcome::Retry {
            preferred,
            required,
        };
    }

    let mut reserved_target = 0usize;
    for index in 0..target_exclusive_len {
        let Some(node) = target_chain.get(index) else {
            rollback_migration_target_reservations(target_chain, reserved_target);
            return LockedMigrationOutcome::Failed {
                error: CgroupError::DepthLimit,
                retired_target: None,
            };
        };
        let limit = if node.controllers.contains(CgroupControllers::PIDS) {
            node.limits.lock().pids_max
        } else {
            None
        };
        if try_increment_pids(&node.stats, limit).is_err() {
            node.stats.record_pids_max_event();
            rollback_migration_target_reservations(target_chain, reserved_target);
            return LockedMigrationOutcome::Failed {
                error: CgroupError::PidsLimitExceeded,
                retired_target: None,
            };
        }
        reserved_target += 1;
    }

    if let Some(probe) = probe {
        let has_spare_capacity = {
            let sibling = probe.sibling.processes.lock();
            sibling.capacity() > sibling.len()
        };
        assert!(
            has_spare_capacity,
            "RF180-45 sibling migration probe must be allocation-free"
        );
        assert_eq!(
            probe.sibling.attach_task(probe.task),
            Err(CgroupError::PidsLimitExceeded),
            "RF180-45 common ancestor must expose no transient migration credit"
        );
    }

    let mut retired_target = None;
    if to_procs.capacity() < required {
        retired_target = Some(
            to_procs
                .install_prepared_deferred(
                    prepared_target
                        .take()
                        .expect("validated migration target backing disappeared"),
                )
                .expect("validated migration target backing rejected"),
        );
    }

    assert!(
        from_procs.remove_retaining_capacity(&task),
        "validated migration source task disappeared"
    );
    match to_procs.insert_reserved(task) {
        Ok(true) => {}
        Ok(false) => panic!("validated migration target task appeared during commit"),
        Err(rejected_task) => {
            assert!(
                from_procs
                    .insert_reserved(rejected_task)
                    .unwrap_or_else(|_| panic!("migration source rollback slot vanished")),
                "migration source rollback found an unexpected duplicate"
            );
            rollback_migration_target_reservations(target_chain, reserved_target);
            let retired_target = retired_target.map(|retired| {
                to_procs
                    .restore_retired_deferred(retired)
                    .unwrap_or_else(|_| panic!("migration target backing rollback failed"))
            });
            return LockedMigrationOutcome::Failed {
                error: CgroupError::OutOfMemory,
                retired_target,
            };
        }
    }

    for index in 0..source_exclusive_len {
        if let Some(node) = source_chain.get(index) {
            node.stats.decrement_pids();
        }
    }
    let retired_source = from_procs.take_empty_capacity();
    LockedMigrationOutcome::Complete {
        retired_target,
        retired_source,
    }
}

/// Migrates a task from one cgroup to another.
///
/// This is an atomic operation that detaches from the old cgroup
/// and attaches to the new cgroup.
///
/// # R90-4 FIX: Migration/Deletion Race
///
/// Validates both identities and publishes an allocation-free membership
/// freeze under `CGROUP_REGISTRY.read()`. Deletion then fails closed while the
/// registry is released for detached capacity preparation and publication.
///
/// # Errors
///
/// * `NotFound` - Source or target cgroup doesn't exist
/// * `TaskNotAttached` - Task is not in source cgroup
/// * `TaskAlreadyAttached` - Task is already present in the target cgroup
/// * `PidsLimitExceeded` - Target cgroup's pids.max exceeded
/// * `Busy` - Another migration involving either endpoint is active
///
/// # Caller obligations (R169-L12)
///
/// This migrates ONLY the task's cgroup MEMBERSHIP and the hierarchical **pids**
/// accounting (`detach_task`/`attach_task`). It does NOT transfer the per-cgroup
/// **FD** or **memory** charges — a caller that re-homes a task between cgroups
/// MUST migrate those separately (see `sys_cgroup_attach`, which moves fd +
/// memory charges under the Process lock); omitting that strands them on the
/// source ancestor chain. Ephemeral-**port** charges are NOT task-migratable by
/// design: each is bound at allocation to the socket's owning cgroup via
/// `PortBinding.charged_cgroup` (and uncharged against that stored id), and
/// deliberately does NOT move on cgroup attach (the J2-8 self-test asserts this).
/// Re-homing the task therefore leaves the port charge with the original cgroup —
/// whether that SHOULD change is the open D2-J2-CHARGE-LIFETIME / R169-7 question,
/// not a caller obligation of this function.
///
/// Historical R90-4 lock discipline held the **non-reentrant** registry reader
/// for the whole window. Callers therefore had to run any
/// charge/uncharge primitive (each does `lookup_cgroup` → a registry read) AFTER
/// `migrate_task` returns. RF180-45 removes that hidden lock from preparation.
/// Callers MUST
/// NOT fold `address_space_share_count()` (which takes PROCESS_TABLE then foreign
/// Process locks) into a "hold the target Process lock across `migrate_task`"
/// obligation — that is the R156-1 child→parent ABBA / self-deadlock footgun.
///
/// RF180-45: any required target backing is prepared with endpoint freezes
/// released, then publication revalidates and pins both endpoints. It locks both task sets in
/// cgroup-id order, reserves only target-exclusive hierarchical PID deltas,
/// leaves every common ancestor unchanged, commits membership allocation-free,
/// and only then releases source-exclusive accounting. Freeze contention returns
/// [`CgroupError::Busy`] immediately; no caller spins.
pub fn migrate_task(task: TaskId, from_id: CgroupId, to_id: CgroupId) -> Result<(), CgroupError> {
    migrate_task_impl(task, from_id, to_id, None)
}

fn migrate_task_impl(
    task: TaskId,
    from_id: CgroupId,
    to_id: CgroupId,
    probe: Option<&CgroupMigrationProbe<'_>>,
) -> Result<(), CgroupError> {
    let _ = ROOT_CGROUP.id();
    let registry = CGROUP_REGISTRY.read();
    let from = match registry.get(&from_id).cloned() {
        Some(from) => from,
        None => return Err(CgroupError::NotFound),
    };
    let to = match registry.get(&to_id).cloned() {
        Some(to) => to,
        None => {
            drop(registry);
            drop(from);
            return Err(CgroupError::NotFound);
        }
    };
    if from.deleted.load(Ordering::Acquire) || to.deleted.load(Ordering::Acquire) {
        drop(registry);
        drop(to);
        drop(from);
        return Err(CgroupError::NotFound);
    }
    if Arc::ptr_eq(&from, &to) {
        let attached = from.processes.lock().contains(&task);
        drop(registry);
        return if attached {
            Ok(())
        } else {
            Err(CgroupError::TaskNotAttached)
        };
    }
    drop(registry);

    let mut prepared_target: Option<PreparedAdmittedSetCapacity<TaskId>> = None;
    loop {
        let registry = CGROUP_REGISTRY.read();
        let registered_from = registry
            .get(&from_id)
            .filter(|candidate| Arc::ptr_eq(candidate, &from))
            .ok_or(CgroupError::NotFound)?;
        let registered_to = registry
            .get(&to_id)
            .filter(|candidate| Arc::ptr_eq(candidate, &to))
            .ok_or(CgroupError::NotFound)?;
        if registered_from.deleted.load(Ordering::Acquire)
            || registered_to.deleted.load(Ordering::Acquire)
        {
            return Err(CgroupError::NotFound);
        }
        let freeze = CgroupMembershipFreeze::try_new(&from, &to).ok_or(CgroupError::Busy)?;
        drop(registry);

        let source_chain = collect_cgroup_ancestry(&from)?;
        let target_chain = collect_cgroup_ancestry(&to)?;
        let (source_exclusive_len, target_exclusive_len) =
            migration_exclusive_lengths(&source_chain, &target_chain)?;

        let outcome = if from.id() < to.id() {
            let mut from_procs = from.processes.lock();
            let mut to_procs = to.processes.lock();
            migrate_task_locked(
                task,
                &mut from_procs,
                &mut to_procs,
                &source_chain,
                &target_chain,
                source_exclusive_len,
                target_exclusive_len,
                &mut prepared_target,
                probe,
            )
        } else {
            let mut to_procs = to.processes.lock();
            let mut from_procs = from.processes.lock();
            migrate_task_locked(
                task,
                &mut from_procs,
                &mut to_procs,
                &source_chain,
                &target_chain,
                source_exclusive_len,
                target_exclusive_len,
                &mut prepared_target,
                probe,
            )
        };

        drop(source_chain);
        drop(target_chain);
        drop(freeze);

        match outcome {
            LockedMigrationOutcome::Retry {
                preferred,
                required,
            } => {
                drop(prepared_target.take());
                prepared_target = Some(prepare_set_capacity_with_fallback(preferred, required)?);
            }
            LockedMigrationOutcome::Complete {
                retired_target,
                retired_source,
            } => {
                drop(prepared_target.take());
                drop(retired_target);
                drop(retired_source);
                return Ok(());
            }
            LockedMigrationOutcome::Failed {
                error,
                retired_target,
            } => {
                drop(prepared_target.take());
                drop(retired_target);
                return Err(error);
            }
        }
    }
}

// ============================================================================
// Scheduler Integration
// ============================================================================

/// Returns the effective CPU weight for a task in the given cgroup.
///
/// If no explicit weight is set, returns the default (100).
///
/// # R170-1 FIX (D-R170-CPU-L5; the 4th IRQ-off L5 reader R169-2 missed)
///
/// Reached in TRUE timer-IRQ context on every time-slice expiry
/// (`on_clock_tick` → `reset_time_slice` → `calculate_time_slice_with_cgroup`),
/// from the scheduler pick paths (`select_next_process`/`steal_one` →
/// `reset_time_slice`, under `without_interrupts`), and from the futex-PI
/// `recompute_effective_priority` chain (FutexBucket + Process locks held).
/// The original BLOCKING `lookup_cgroup` (`CGROUP_REGISTRY.read()`, L5) AND
/// BLOCKING `limits.lock()` here each self-deadlock against a same-CPU
/// process-context holder with IRQs enabled (`create/delete/migrate_cgroup`
/// hold the registry write lock; `set_limits`/`sys_cgroup_set_limit` hold the
/// per-node `limits` mutex) — both acquisitions must be non-blocking, not
/// just the registry read the QA report cited.
///
/// Fail direction: OPEN to `DEFAULT_WEIGHT` on either contention. This is
/// deliberately the OPPOSITE of `charge_cpu_quota` (which fails CLOSED on the
/// same contention): cpu_weight is an advisory slice-length heuristic whose
/// one-tick default-weight slice self-corrects at the next expiry (this also
/// holds for the PI-boost reacher — the recomputed slice is re-derived on
/// every subsequent boost/clear and tick), while cpu.max is a hard
/// enforcement gate that must never be bypassable by induced contention
/// (FX-09 fail-direction rule).
pub fn get_effective_cpu_weight(cgroup_id: CgroupId) -> u32 {
    const DEFAULT_WEIGHT: u32 = 100;

    if let Some(cgroup) = try_lookup_cgroup(cgroup_id) {
        match cgroup.limits.try_lock() {
            Some(limits) => limits.cpu_weight.unwrap_or(DEFAULT_WEIGHT),
            None => DEFAULT_WEIGHT,
        }
    } else {
        DEFAULT_WEIGHT
    }
}

/// Checks if a task can be forked based on cgroup pids.max limit.
///
/// R111-2 FIX: Walks the ancestor chain (up to MAX_CGROUP_DEPTH levels) so that
/// a parent or grandparent `pids.max` limit is also checked.  This is a best-effort
/// pre-check — the authoritative hierarchical CAS-based check remains in `attach_task()`.
/// Using `Ordering::Acquire` ensures visibility of concurrent PID counter increments.
///
/// Returns `true` if fork is allowed, `false` if pids.max would be exceeded.
pub fn check_fork_allowed(cgroup_id: CgroupId) -> bool {
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::PIDS) {
            let limits = cgroup.limits.lock();
            if let Some(max) = limits.pids_max {
                let current = cgroup.stats.pids_current.load(Ordering::Acquire);
                if current >= max {
                    cgroup.stats.record_pids_max_event();
                    return false;
                }
            }
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
    true
}

/// Records CPU time for a cgroup (called from scheduler).
///
/// R169-2 FIX (D1-CGROUP-IRQ-L5): Invoked from `on_clock_tick` in true timer-IRQ
/// context (IRQs disabled), so it MUST NOT take the blocking registry lock. Uses
/// `try_lookup_cgroup` and FAILS OPEN on registry contention: a dropped tick is
/// harmless because CPU-time accounting is monotonic-add-only (no paired
/// uncharge), so it can never underflow, orphan a charge, or breach a limit —
/// the missing tick self-corrects on the next one.
pub fn account_cpu_time(cgroup_id: CgroupId, delta_ns: u64) {
    if let Some(cgroup) = try_lookup_cgroup(cgroup_id) {
        cgroup.stats.add_cpu_time(delta_ns);
    }
}

// ============================================================================
// Memory Controller Integration
// ============================================================================

/// Returns current memory usage for a cgroup (read-only snapshot).
///
/// # R77-2 FIX
///
/// This replaces the old `update_memory_usage()` which used bare `store()` and
/// could overwrite in-flight `try_charge_memory()` CAS operations. The memory
/// accounting model is now exclusively charge/uncharge based:
///
/// - **Allocations** (mmap, etc.): Use `try_charge_memory()` with atomic CAS
/// - **Deallocations** (munmap, etc.): Use `uncharge_memory()` with fetch_update
/// - **Monitoring**: Use this function for read-only snapshots
///
/// This eliminates the race where a background sampler's `store()` would
/// overwrite concurrent CAS updates, potentially bypassing memory limits.
pub fn get_memory_usage(cgroup_id: CgroupId) -> Option<u64> {
    lookup_cgroup(cgroup_id).map(|cgroup| cgroup.stats.get_memory_current())
}

/// Checks if memory allocation would exceed cgroup limit.
///
/// P2-9 FIX: Walks the ancestor chain (up to MAX_CGROUP_DEPTH levels) so that
/// a parent or grandparent `memory.max` limit is also checked.  This is a
/// best-effort pre-check — the authoritative hierarchical CAS-based enforcement
/// is in `try_charge_memory()`.  Uses `Ordering::Acquire` to ensure visibility
/// of concurrent memory counter increments.
///
/// Returns `true` if allocation is allowed.
pub fn check_memory_allowed(cgroup_id: CgroupId, allocation_bytes: u64) -> bool {
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            let limits = cgroup.limits.lock();
            if let Some(max) = limits.memory_max {
                let current = cgroup.stats.memory_current.load(Ordering::Acquire);
                if current.saturating_add(allocation_bytes) > max {
                    cgroup.stats.record_memory_max();
                    return false;
                }
            }
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
    true
}

/// Atomically charges memory usage to a cgroup, enforcing memory.max.
///
/// P2-9 FIX: Hierarchical memory.max enforcement.
///
/// In cgroups v2, ancestor `memory.max` limits apply to all descendants.
/// This function charges `memory_current` on the target cgroup **and** every
/// ancestor with the MEMORY controller enabled.  On failure at any level,
/// all previously charged ancestors are rolled back (saturating subtract).
///
/// This follows the same charge-then-rollback pattern as hierarchical
/// `pids.max` enforcement in `attach_task()` (R83-3 + R90-3).
///
/// Uses CAS (`fetch_update`) for each cgroup to atomically check the limit
/// and increment the counter, closing the TOCTOU race between concurrent
/// mmap callers (CODEX FIX).
///
/// # Errors
///
/// * `MemoryLimitExceeded` - Adding `allocation_bytes` would exceed memory.max
///   at this cgroup or any ancestor.
/// * `NotFound` - The origin cgroup no longer exists.
pub fn try_charge_memory(cgroup_id: CgroupId, allocation_bytes: u64) -> Result<(), CgroupError> {
    if allocation_bytes == 0 {
        return Ok(());
    }

    // Collect the chain: target cgroup + ancestors with MEMORY controller.
    let mut depth: u32 = 0;
    // M2-1 SLICE-2: pin at the ORIGIN node FIRST, controller-independent — twin
    // of try_charge_fds' pin (see CgroupStats::mem_pinned). Captured BEFORE the
    // chain walk consumes `cursor`, and BEFORE any display CAS, so the gate can
    // never observe display motion without the matching pin. The MEMORY family
    // is NOT root-exempt (unlike fds/ports): root.mem_pinned moves too — matching
    // the display counter, which also charges root.
    // Fail closed for a stale/deleting origin. For non-root nodes, keep the
    // registry read guard through the origin pin: otherwise delete_cgroup can
    // take the writer lock after lookup returns but before the pin, sample zero,
    // remove the node, and strand an unaccounted charge on a detached Arc.
    let origin: CgroupArc = if cgroup_id == 0 {
        let root = ROOT_CGROUP.clone();
        root.stats
            .pin_origin(&root.stats.mem_pinned, allocation_bytes);
        root
    } else {
        let registry = CGROUP_REGISTRY.read();
        let node = registry
            .get(&cgroup_id)
            .cloned()
            .ok_or(CgroupError::NotFound)?;
        if node.deleted.load(Ordering::Acquire) {
            return Err(CgroupError::NotFound);
        }
        node.stats
            .pin_origin(&node.stats.mem_pinned, allocation_bytes);
        drop(registry);
        node
    };
    let mut cursor = Some(origin.clone());
    // RF178-11 FIX: page-cache admission reaches this function before its own
    // Arc/map births, so the accounting gate itself must not allocate
    // infallibly. The hierarchy depth is hard-bounded; keep the chain and
    // rollback ledger in fixed storage instead of three heap Vecs.
    const CHAIN_CAPACITY: usize = MAX_CGROUP_DEPTH as usize + 1;
    let mut chain: [Option<CgroupArc>; CHAIN_CAPACITY] = core::array::from_fn(|_| None);
    let mut chain_len = 0usize;
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            debug_assert!(chain_len < CHAIN_CAPACITY);
            if chain_len >= CHAIN_CAPACITY {
                origin.stats.unpin_origin_mem(allocation_bytes);
                return Err(CgroupError::InvalidLimit);
            }
            chain[chain_len] = Some(cgroup.clone());
            chain_len += 1;
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }

    if chain_len == 0 {
        // No MEMORY controller anywhere in the chain: the PIN STAYS (the
        // per-process tally's exit/migrate uncharge keys to this id and unpins
        // it symmetrically — uncharge_memory unpins the origin BEFORE its own
        // controller walk). Mirrors try_charge_fds' controller-less chain.
        return Ok(());
    }

    // Snapshot limits to avoid holding multiple locks during CAS charging.
    let mut limits_snapshot = [(None, None); CHAIN_CAPACITY];
    for idx in 0..chain_len {
        let Some(cgroup) = chain[idx].as_ref() else {
            debug_assert!(false, "cgroup charge chain must be contiguous");
            origin.stats.unpin_origin_mem(allocation_bytes);
            return Err(CgroupError::NotFound);
        };
        let limits = cgroup.limits.lock();
        limits_snapshot[idx] = (limits.memory_max, limits.memory_high);
    }

    // Successful charges are always a prefix, so one count is a complete,
    // allocation-free rollback ledger.
    let mut charged_len = 0usize;

    for idx in 0..chain_len {
        let Some(cgroup) = chain[idx].as_ref() else {
            debug_assert!(false, "cgroup charge chain must be contiguous");
            for charged_idx in 0..charged_len {
                if let Some(charged) = chain[charged_idx].as_ref() {
                    let _ = charged.stats.memory_current.fetch_update(
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                        |current| Some(current.saturating_sub(allocation_bytes)),
                    );
                }
            }
            origin.stats.unpin_origin_mem(allocation_bytes);
            return Err(CgroupError::NotFound);
        };
        let (max, high) = limits_snapshot[idx];

        match cgroup.stats.memory_current.fetch_update(
            Ordering::SeqCst,
            Ordering::Relaxed,
            |current| {
                let new = current.saturating_add(allocation_bytes);
                if let Some(max) = max {
                    if new > max {
                        return None; // Reject: would exceed limit
                    }
                }
                Some(new)
            },
        ) {
            Ok(old) => {
                // Check high watermark event
                let new = old.saturating_add(allocation_bytes);
                if let Some(high) = high {
                    if new > high {
                        cgroup.stats.record_memory_high();
                    }
                }
                charged_len += 1;
            }
            Err(_) => {
                // Limit exceeded at this level — record event and rollback.
                cgroup.stats.record_memory_max();

                // R110-1 pattern: Rollback with saturating decrement to
                // prevent underflow if a concurrent uncharge raced.
                for j in 0..charged_len {
                    if let Some(charged) = chain[j].as_ref() {
                        let _ = charged.stats.memory_current.fetch_update(
                            Ordering::SeqCst,
                            Ordering::Relaxed,
                            |current| Some(current.saturating_sub(allocation_bytes)),
                        );
                    }
                }

                // M2-1 SLICE-2: roll back the ORIGIN pin too (the whole charge is
                // rejected, nothing was keyed). Omitting this would strand a
                // permanent pin on every rejected charge (FA-04 undeletability).
                // Mirrors try_charge_fds:2402-2405. The matched-rollback unpin
                // routes through the tripwire so a concurrent over-uncharge that
                // raced our pin below allocation_bytes is still caught.
                origin.stats.unpin_origin_mem(allocation_bytes);

                return Err(CgroupError::MemoryLimitExceeded);
            }
        }
    }

    Ok(())
}

/// Atomically uncharges memory from a cgroup (saturating at zero).
///
/// P2-9 FIX: Walks the same ancestor chain as `try_charge_memory()` to
/// uncharge `memory_current` at each level.  Without this, ancestor counters
/// would permanently leak, eventually DoS-ing the subtree by "stuck" usage.
///
/// Called when memory is released (munmap, process exit, etc.).
/// Uses fetch_update for atomic subtract-with-floor-at-zero.
pub fn uncharge_memory(cgroup_id: CgroupId, bytes: u64) {
    if bytes == 0 {
        return;
    }

    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    // M2-1 SLICE-2: unpin at the ORIGIN node FIRST, controller-independent,
    // symmetric with the try_charge_memory / charge_memory_forced origin pin
    // (saturating; the tripwire variant records any over-uncharge surplus). This
    // single unpin reverses BOTH primitives' pins (one shared mem_pinned key).
    // Placed BEFORE the controller walk so a controller-less / MEMORY-disabled
    // origin still telescopes (mirrors uncharge_fds:2426-2428).
    if let Some(o) = &cursor {
        o.stats.unpin_origin_mem(bytes);
    }
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            let _ = cgroup.stats.memory_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(bytes)),
            );
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
}

/// J2-9: Force-charges `bytes` of kernel memory to a cgroup + every
/// MEMORY-controller ancestor WITHOUT rejecting on `memory.max` (saturating add
/// over the same chain `uncharge_memory` walks). This is the SOFT-cap charge for
/// the page-table-frame kmem allocated by `map_to`: that frame count is knowable
/// only AFTER the mapping is built (IM-14 "delta known only after the mutation ⇒
/// soft cap"), and the frames physically exist by then — so accounting must
/// record them even if they push `memory_current` transiently past `memory.max`.
/// The overshoot is bounded by ONE mmap's page-table delta (~1/512 of the data,
/// itself already capped by the HARD Phase-1 DATA gate) and the HARD gate on the
/// NEXT allocation re-enforces the limit. Thus this is the over-count-safe /
/// never-under-count direction — it cannot create a `memory.max` bypass (unlike a
/// reject-then-rollback, which would orphan the already-allocated PT frames
/// uncharged). Root cgroup (id 0) is NOT exempt: page-table memory is real kernel
/// memory and rides `memory.current` exactly like the DATA charge.
pub fn charge_memory_forced(cgroup_id: CgroupId, bytes: u64) {
    if bytes == 0 {
        return;
    }

    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    // M2-1 SLICE-2: pin at the ORIGIN node FIRST, controller-independent —
    // unconditional saturating add matching the unconditional saturating display
    // charge. The FORCED primitive NEVER rejects, so there is no rollback path
    // and hence NO rollback-unpin here. Its symmetric unpin is supplied by the
    // ordinary uncharge_memory of the same pt lane (munmap / exit). MUST pin, or
    // that later unpin saturates the pin to 0 and under-counts.
    if let Some(o) = &cursor {
        o.stats.pin_origin(&o.stats.mem_pinned, bytes);
    }
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::MEMORY) {
            // fetch_update (never fetch_add — lint-fetch-add) with a closure that
            // always returns Some never fails: an unconditional saturating add.
            let _ = cgroup.stats.memory_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |current| Some(current.saturating_add(bytes)),
            );
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
}

/// Atomically transfers cgroup memory charges from one cgroup to another.
///
/// R143-1 FIX: When a process is migrated between cgroups, its existing memory
/// charges must be transferred so that exit-time uncharge targets the correct
/// cgroup. Without this transfer, the source cgroup permanently leaks
/// `memory_current` and the destination under-counts, enabling `memory.max`
/// bypass.
///
/// R148-1 FIX: Charge-destination-first protocol. The previous uncharge-first
/// protocol could permanently lose charges when the destination charge failed
/// and the rollback re-charge also failed under contention (source cgroup's
/// freed budget consumed by concurrent allocators). The new protocol:
///
/// 1. Try to charge `bytes` to destination hierarchy
/// 2. Uncharge `bytes` from source hierarchy (saturating, cannot fail)
///
/// Shared ancestors are transiently over-counted (both source and destination
/// charged) but never under-counted. Over-count is safe (conservative); under-
/// count enables `memory.max` bypass.
///
/// # Errors
///
/// * `NotFound` - Source or target cgroup doesn't exist
/// * `MemoryLimitExceeded` - Destination cgroup (or ancestor) would exceed `memory.max`
pub fn migrate_memory_charges(
    bytes: u64,
    from_id: CgroupId,
    to_id: CgroupId,
) -> Result<(), CgroupError> {
    if bytes == 0 || from_id == to_id {
        return Ok(());
    }

    // Validate both cgroups exist. The returned Arc keeps them alive for the
    // duration of this function even without holding CGROUP_REGISTRY — the Arc
    // prevents deallocation even if a concurrent delete_cgroup removes them
    // from the registry. We intentionally do NOT hold the registry read lock
    // because uncharge_memory/try_charge_memory internally call lookup_cgroup
    // which acquires the same spin::RwLock, and spin::RwLock does not support
    // re-entrant readers on the same CPU (would deadlock on uniprocessor).
    let _from_arc = lookup_cgroup(from_id).ok_or(CgroupError::NotFound)?;
    let _to_arc = lookup_cgroup(to_id).ok_or(CgroupError::NotFound)?;

    // Phase 1: Charge destination hierarchy first. If this fails (memory.max
    // exceeded), return error — source is unchanged, no rollback needed.
    try_charge_memory(to_id, bytes)?;

    // Phase 2: Uncharge source hierarchy (saturating, cannot fail).
    uncharge_memory(from_id, bytes);

    Ok(())
}

// ============================================================================
// J2-7: FILES Controller Integration (files.max enforcement)
// ============================================================================

/// Atomically charges `count` open file descriptors to a cgroup, enforcing
/// `files.max` hierarchically (target cgroup + every ancestor with the FILES
/// controller), mirroring `try_charge_memory` (CAS + ancestor rollback).
///
/// Root cgroup (id 0) is EXEMPT via the canonical id-based rule: root is created
/// with `CgroupControllers::all()`, so a controller-based exemption would NOT
/// skip it; the `cgroup_id == 0` short-circuit keeps root counters at 0
/// uniformly across all per-cgroup quota controllers.
///
/// # Errors
/// * `FdsLimitExceeded` - charging `count` would exceed `files.max` at this
///   cgroup or any ancestor. Nothing is charged: every partial charge is rolled
///   back before returning (fail-closed).
/// * `NotFound` / `DepthLimit` - the origin or its bounded ancestry is invalid.
pub fn try_charge_fds(cgroup_id: CgroupId, count: u64) -> Result<(), CgroupError> {
    if count == 0 || cgroup_id == 0 {
        return Ok(());
    }

    // RF180-45 REVIEW FIX: publish the origin pin while the registry read lock
    // still prevents deletion. A lookup followed by a later pin lets delete_cgroup observe
    // zero, remove the node, and strand ancestor charges keyed to its ID.
    let origin = {
        let registry = CGROUP_REGISTRY.read();
        let node = registry
            .get(&cgroup_id)
            .cloned()
            .ok_or(CgroupError::NotFound)?;
        if node.deleted.load(Ordering::Acquire) {
            return Err(CgroupError::NotFound);
        }
        // R170-2 FIX: pin at the ORIGIN node first, controller-independent —
        // twin of try_charge_ports' pin (see CgroupStats::fds_pinned).
        node.stats.pin_origin(&node.stats.fds_pinned, count);
        node
    };
    // Collect the chain after publication; the pin now keeps the origin
    // registry-resident. Roll it back if the bounded ancestry is invalid.
    let chain = match collect_controller_chain(&origin, CgroupControllers::FILES) {
        Ok(chain) => chain,
        Err(error) => {
            origin.stats.unpin_origin(&origin.stats.fds_pinned, count);
            return Err(error);
        }
    };

    if chain.len == 0 {
        // No FILES controller anywhere: the PIN stays (the per-process FD
        // tallies key their exit/migrate uncharge to this id, which unpins
        // symmetrically) — keeps the delete-gate sound for a controller-less
        // chain. See try_charge_ports.
        return Ok(());
    }

    // Snapshot per-node limits (lock each briefly; never hold two at once).
    let mut limits_snapshot = [None; CGROUP_CHAIN_CAPACITY];
    for index in 0..chain.len {
        let Some(node) = chain.get(index) else {
            origin.stats.unpin_origin(&origin.stats.fds_pinned, count);
            return Err(CgroupError::DepthLimit);
        };
        limits_snapshot[index] = node.limits.lock().fds_max;
    }

    // Successful charges are a prefix, so one count is the rollback ledger.
    let mut charged_len = 0usize;
    for index in 0..chain.len {
        let Some(cgroup) = chain.get(index) else {
            for rollback in 0..charged_len {
                if let Some(node) = chain.get(rollback) {
                    node.stats.decrement_fds(count);
                }
            }
            origin.stats.unpin_origin(&origin.stats.fds_pinned, count);
            return Err(CgroupError::DepthLimit);
        };
        let max = limits_snapshot[index];
        match cgroup.stats.fds_current.fetch_update(
            Ordering::SeqCst,
            Ordering::Relaxed,
            |current| {
                let new = current.saturating_add(count);
                if let Some(max) = max {
                    if new > max {
                        return None; // would exceed files.max
                    }
                }
                Some(new)
            },
        ) {
            Ok(_) => charged_len += 1,
            Err(_) => {
                cgroup.stats.record_fds_max_event();
                // R110-1 pattern: rollback previously charged levels (saturating).
                for rollback in 0..charged_len {
                    if let Some(node) = chain.get(rollback) {
                        node.stats.decrement_fds(count);
                    }
                }
                // R170-2: roll back the origin pin too (nothing was keyed).
                origin.stats.unpin_origin(&origin.stats.fds_pinned, count);
                return Err(CgroupError::FdsLimitExceeded);
            }
        }
    }

    Ok(())
}

/// Atomically uncharges `count` file descriptors from a cgroup (saturating at
/// zero), walking the same ancestor chain as `try_charge_fds`. Root (id 0) is
/// exempt. Called on fd close / cloexec / exec / process exit / migration.
pub fn uncharge_fds(cgroup_id: CgroupId, count: u64) {
    if count == 0 || cgroup_id == 0 {
        return;
    }

    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    // R170-2 FIX: unpin at the ORIGIN node (controller-independent, symmetric
    // with try_charge_fds' pin; saturating).
    if let Some(o) = &cursor {
        o.stats.unpin_origin(&o.stats.fds_pinned, count);
    }
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::FILES) {
            cgroup.stats.decrement_fds(count);
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
}

/// Transfers `count` FD charges from one cgroup to another on task migration.
///
/// Charge-destination-first protocol (mirrors `migrate_memory_charges`, R148-1):
/// a failed destination charge leaves the source intact, so no charge is ever
/// lost. Shared ancestors are transiently over-counted but never under-counted
/// (over-count is safe; under-count would enable a `files.max` bypass).
///
/// The returned `Arc`s keep both nodes alive without holding `CGROUP_REGISTRY`
/// across the inner `try_charge_fds`/`uncharge_fds` calls (which re-`lookup`),
/// since `spin::RwLock` is not re-entrant on the same CPU.
///
/// # Errors
/// * `NotFound` - source or destination cgroup doesn't exist.
/// * `FdsLimitExceeded` - destination (or ancestor) would exceed `files.max`.
pub fn migrate_fd_charges(
    count: u64,
    from_id: CgroupId,
    to_id: CgroupId,
) -> Result<(), CgroupError> {
    if count == 0 || from_id == to_id {
        return Ok(());
    }
    let _from_arc = lookup_cgroup(from_id).ok_or(CgroupError::NotFound)?;
    let _to_arc = lookup_cgroup(to_id).ok_or(CgroupError::NotFound)?;

    try_charge_fds(to_id, count)?; // destination first
    uncharge_fds(from_id, count); // source (saturating, cannot fail)
    Ok(())
}

// ============================================================================
// J2-8: NET controller — per-cgroup ephemeral-port budget (ports.max)
// ============================================================================

/// Atomically charges `count` ephemeral ports against a cgroup and its NET
/// ancestors, hierarchically enforcing `ports.max`. Root (id 0) is exempt.
///
/// This is the verbatim structural twin of `try_charge_fds` (FILES -> NET=0x20,
/// fds_* -> ports_*): it walks the target + ancestors carrying the NET
/// controller, snapshots each node's `ports_max`, then does a saturating
/// `fetch_update` per level and ROLLS BACK every already-charged level on the
/// first rejection (so a deep-ancestor cap never strands a charge at a shallower
/// level). Hierarchical by design: an ancestor's `ports_current` aggregates all
/// descendants' charges, so the leaf invariant "ports_current(leaf) == count of
/// live PortBinding entries charged to leaf" holds per-leaf and the uncharge
/// walks the SAME chain (symmetry).
///
/// # Lock context (J2-SHARED-CORE invariant, lock_ordering.rs)
/// Acquires CGROUP_REGISTRY (L5, via `lookup_cgroup`) + per-node `limits` (L5).
/// MUST NOT be called while any net-binding lock (L8) is held or from IRQ
/// context — the net layer resolves the cgroup and charges BEFORE taking a
/// binding lock, and routes every teardown uncharge through the process-context
/// deferred-uncharge drain.
///
/// # Errors
/// * `PortsLimitExceeded` - the target or an ancestor would exceed `ports.max`.
/// * `NotFound` / `DepthLimit` - the origin or its bounded ancestry is invalid.
pub fn try_charge_ports(cgroup_id: CgroupId, count: u64) -> Result<(), CgroupError> {
    if count == 0 || cgroup_id == 0 {
        return Ok(());
    }

    // Collect the chain: target cgroup + ancestors with the NET controller.
    let origin = lookup_cgroup(cgroup_id).ok_or(CgroupError::NotFound)?;
    let chain = collect_controller_chain(&origin, CgroupControllers::NET)?;
    // R170-2 FIX: pin the charge at the ORIGIN node (the node whose id the
    // caller stores as the uncharge key) FIRST, controller-INDEPENDENT — see
    // `CgroupStats::ports_pinned`. Pinned before the display charges so the
    // delete-gate can never observe display motion without the pin; unpinned
    // on rejection below.
    origin.stats.pin_origin(&origin.stats.ports_pinned, count);

    if chain.len == 0 {
        // No NET controller anywhere: nothing to enforce or display-count,
        // but the PIN stays — the caller still stores this id and the later
        // uncharge_ports(id) unpins symmetrically, keeping the delete-gate
        // sound even for a controller-less chain (and immune to controller
        // flags being enabled between charge and uncharge).
        return Ok(());
    }

    // Snapshot per-node limits (lock each briefly; never hold two at once).
    let mut limits_snapshot = [None; CGROUP_CHAIN_CAPACITY];
    for index in 0..chain.len {
        let Some(node) = chain.get(index) else {
            origin.stats.unpin_origin(&origin.stats.ports_pinned, count);
            return Err(CgroupError::DepthLimit);
        };
        limits_snapshot[index] = node.limits.lock().ports_max;
    }

    let mut charged_len = 0usize;
    for index in 0..chain.len {
        let Some(cgroup) = chain.get(index) else {
            for rollback in 0..charged_len {
                if let Some(node) = chain.get(rollback) {
                    node.stats.decrement_ports(count);
                }
            }
            origin.stats.unpin_origin(&origin.stats.ports_pinned, count);
            return Err(CgroupError::DepthLimit);
        };
        let max = limits_snapshot[index];
        match cgroup.stats.ports_current.fetch_update(
            Ordering::SeqCst,
            Ordering::Relaxed,
            |current| {
                let new = current.saturating_add(count);
                if let Some(max) = max {
                    if new > max {
                        return None; // would exceed ports.max
                    }
                }
                Some(new)
            },
        ) {
            Ok(_) => charged_len += 1,
            Err(_) => {
                cgroup.stats.record_ports_max_event();
                // Rollback previously charged levels (saturating, cannot fail).
                for rollback in 0..charged_len {
                    if let Some(node) = chain.get(rollback) {
                        node.stats.decrement_ports(count);
                    }
                }
                // R170-2: roll back the origin pin too (nothing was keyed).
                origin.stats.unpin_origin(&origin.stats.ports_pinned, count);
                return Err(CgroupError::PortsLimitExceeded);
            }
        }
    }

    Ok(())
}

/// Atomically uncharges `count` ephemeral ports from a cgroup (saturating at
/// zero), walking the same NET ancestor chain as `try_charge_ports`. Root (id 0)
/// is exempt. Called from the process-context deferred-uncharge drain and the
/// direct (close / connect-rollback) teardown sites — NEVER under a net-binding
/// lock or from IRQ.
///
/// "Uncharge what you charged": the net layer passes the STORED `charged_cgroup`
/// recorded in the `PortBinding` value at allocation time, never the current
/// task's cgroup (which may have migrated, or whose lookup would re-enter
/// PROCESS_TABLE on the exec/cloexec teardown path).
///
/// R173 IRQ-SAFETY FIX: Use try_lookup_cgroup to avoid blocking on CGROUP_REGISTRY.
/// This is called from reschedule_if_needed() -> drain_deferred_port_uncharges(),
/// which is process-context with IRQs enabled (debug_assert guards it), but
/// defense-in-depth suggests using the try variant to prevent same-CPU deadlock.
pub fn uncharge_ports(cgroup_id: CgroupId, count: u64) {
    if count == 0 || cgroup_id == 0 {
        return;
    }

    let mut depth: u32 = 0;
    // R173: Use try_lookup_cgroup for IRQ-safety defense-in-depth
    let mut cursor = try_lookup_cgroup(cgroup_id);
    if cursor.is_none() {
        // Registry contended - defer uncharge (safe: charges are origin-pinned,
        // so the cgroup can't be deleted while charges exist; next drain will retry)
        return;
    }
    // R170-2 FIX: unpin at the ORIGIN node (controller-independent, symmetric
    // with try_charge_ports' pin; saturating).
    if let Some(o) = &cursor {
        o.stats.unpin_origin(&o.stats.ports_pinned, count);
    }
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::NET) {
            cgroup.stats.decrement_ports(count);
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
}

// ============================================================================
// F.2: IO Controller Integration (io.max enforcement)
// ============================================================================

/// Charge IO tokens for a cgroup and return throttle status.
///
/// Called before issuing a block I/O operation. If the cgroup has io.max
/// configured and is out of tokens, returns `Throttled(until_ns)` indicating
/// when the caller should retry.
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup to charge
/// * `bytes` - Number of bytes in this I/O operation
/// * `op` - Read or Write direction
/// * `now_ns` - Current time in nanoseconds since boot
///
/// # Returns
///
/// * `Unlimited` - No IO controller or io.max not configured
/// * `Allowed` - Tokens available, operation permitted
/// * `Throttled(until_ns)` - Tokens exhausted, retry after specified time
pub fn charge_io(
    cgroup_id: CgroupId,
    bytes: u64,
    _op: IoDirection,
    now_ns: u64,
) -> IoThrottleStatus {
    if bytes == 0 {
        return IoThrottleStatus::Allowed;
    }

    // P2-9 FIX: Hierarchical io.max enforcement.
    //
    // In cgroups v2, ancestor io.max limits apply to all descendants.
    // Walk the ancestor chain and charge each level's IO token bucket.
    // If any level is throttled, return the most restrictive deadline.
    //
    // Two-phase approach to avoid partial token consumption:
    //   Phase 1: Query all ancestors to determine if any are throttled,
    //            WITHOUT consuming tokens.
    //   Phase 2: If none are throttled, commit token consumption at
    //            every level.
    //
    // This prevents "token leakage" where a child's tokens are consumed
    // but the IO is not issued because an ancestor is throttled.
    let Some(origin) = lookup_cgroup(cgroup_id) else {
        return IoThrottleStatus::Unlimited;
    };
    let chain = match collect_controller_chain(&origin, CgroupControllers::IO) {
        Ok(chain) => chain,
        Err(_) => return IoThrottleStatus::Throttled(u64::MAX),
    };
    let mut limits_snapshot: [Option<CgroupLimits>; CGROUP_CHAIN_CAPACITY] =
        core::array::from_fn(|_| None);
    let mut active = 0usize;
    for index in 0..chain.len {
        let Some(cgroup) = chain.get(index) else {
            return IoThrottleStatus::Throttled(u64::MAX);
        };
        let limits = cgroup.limits.lock().clone();
        if limits.io_max_bytes_per_sec.is_some() || limits.io_max_iops_per_sec.is_some() {
            limits_snapshot[index] = Some(limits);
            active += 1;
        }
    }

    if active == 0 {
        return IoThrottleStatus::Unlimited;
    }

    // Phase 1: Check all levels for throttle status WITHOUT consuming tokens.
    // We use the IoThrottleState's existing throttle_until_ns window to detect
    // active throttling, and check token availability without decrementing.
    let mut overall_throttle_until: u64 = 0;

    for index in 0..chain.len {
        let Some(limits) = limits_snapshot[index].as_ref() else {
            continue;
        };
        let Some(cgroup) = chain.get(index) else {
            return IoThrottleStatus::Throttled(u64::MAX);
        };
        let bucket = cgroup.io_throttle.state.lock();

        // Check if currently in a throttle window.
        if bucket.throttle_until_ns != 0 && now_ns < bucket.throttle_until_ns {
            overall_throttle_until = overall_throttle_until.max(bucket.throttle_until_ns);
            continue;
        }

        // Check byte budget (without consuming).
        if let Some(bps) = limits.io_max_bytes_per_sec {
            if bucket.byte_tokens < bytes {
                let deficit = bytes - bucket.byte_tokens;
                let wait_ns =
                    ((deficit as u128 * 1_000_000_000u128) + (bps as u128 - 1)) / bps as u128;
                let until = now_ns.saturating_add(wait_ns as u64);
                overall_throttle_until = overall_throttle_until.max(until);
            }
        }

        // Check IOPS budget (without consuming).
        if let Some(iops) = limits.io_max_iops_per_sec {
            if bucket.iops_tokens == 0 {
                let nanos_per_io = 1_000_000_000u64
                    .checked_div(iops.max(1))
                    .unwrap_or(1_000_000_000);
                let until = now_ns.saturating_add(nanos_per_io);
                overall_throttle_until = overall_throttle_until.max(until);
            }
        }
    }

    // If any level would throttle, return the most restrictive deadline
    // WITHOUT consuming any tokens.
    if overall_throttle_until != 0 {
        return IoThrottleStatus::Throttled(overall_throttle_until);
    }

    // Phase 2: All levels have sufficient tokens.  Commit consumption at
    // every level by calling the existing charge() method.
    //
    // R143-4 NOTE: The return value from charge() is intentionally discarded.
    // A narrow TOCTOU race exists: an ancestor could transition to Throttled
    // between Phase 1 check and Phase 2 commit (due to a concurrent IO charge
    // on another CPU). If this occurs, one IO operation exceeds the throttle
    // deadline. This is self-correcting: the next charge_io() call will see
    // the throttle state and wait. The performance cost of full rollback +
    // retry outweighs the impact of a single leaked IO in this microsecond
    // race window.
    for index in 0..chain.len {
        let Some(limits) = limits_snapshot[index].as_ref() else {
            continue;
        };
        let Some(cgroup) = chain.get(index) else {
            return IoThrottleStatus::Throttled(u64::MAX);
        };
        let _ = cgroup
            .io_throttle
            .charge(limits, bytes, now_ns, &cgroup.stats);
    }

    IoThrottleStatus::Allowed
}

/// Block until IO tokens are available (process context only).
///
/// Called by the block layer before issuing I/O. This function will yield
/// the CPU and retry until tokens become available. **Must not be called
/// from IRQ context** as it may reschedule.
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup to throttle against
/// * `bytes` - Number of bytes in this I/O operation
/// * `op` - Read or Write direction
///
/// # Returns
///
/// Always returns `Allowed` once tokens are available.
pub fn wait_for_io_window(cgroup_id: CgroupId, bytes: u64, op: IoDirection) -> IoThrottleStatus {
    let mut now_ns = crate::current_timestamp_ms().saturating_mul(1_000_000);

    loop {
        match charge_io(cgroup_id, bytes, op, now_ns) {
            IoThrottleStatus::Allowed | IoThrottleStatus::Unlimited => {
                return IoThrottleStatus::Allowed
            }
            IoThrottleStatus::Throttled(until) => {
                // Yield CPU to allow other tasks to run while we wait for tokens.
                // SAFETY: This is only called from process context (block layer)
                // where rescheduling is safe.
                crate::scheduler_hook::force_reschedule();

                // Update timestamp for next check
                let next = crate::current_timestamp_ms().saturating_mul(1_000_000);
                now_ns = core::cmp::max(next, now_ns.saturating_add(1_000_000));

                if now_ns < until {
                    continue;
                }
            }
        }
    }
}

/// Record IO completion statistics after a successful transfer.
///
/// Called by the block layer after an I/O operation completes successfully.
/// Updates the read/write byte counters for the cgroup.
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup that performed the I/O
/// * `bytes` - Number of bytes transferred
/// * `op` - Read or Write direction
///
/// # WARNING (R170-1 sweep): process-context ONLY — blocking L5 read below.
///
/// This uses the BLOCKING `lookup_cgroup` (`CGROUP_REGISTRY.read()`). Every
/// current caller is the block layer's process-context completion path, so it
/// is safe today — but if I/O completion ever moves into an IRQ handler or an
/// IRQs-disabled bottom half, this becomes a 5th instance of the R169-2/R170-1
/// same-CPU writer-vs-IRQ self-deadlock and MUST be converted to
/// `try_lookup_cgroup` (fail-open: a dropped statistics sample is benign).
pub fn record_io_completion(cgroup_id: CgroupId, bytes: u64, op: IoDirection) {
    if bytes == 0 {
        return;
    }

    if let Some(cgroup) = lookup_cgroup(cgroup_id) {
        if cgroup.controllers.contains(CgroupControllers::IO) {
            match op {
                IoDirection::Read => {
                    cgroup
                        .stats
                        .io_read_bytes
                        .fetch_add(bytes, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
                    cgroup.stats.io_read_ios.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
                }
                IoDirection::Write => {
                    cgroup
                        .stats
                        .io_write_bytes
                        .fetch_add(bytes, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
                    cgroup.stats.io_write_ios.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
                }
            }
        }
    }
}

// ============================================================================
// F.2: CPU Controller Integration (cpu.max enforcement)
// ============================================================================

/// Charge CPU time and enforce cpu.max quota.
///
/// Called from the scheduler's tick handler to account CPU usage against
/// the cgroup's quota and check for throttling.
///
/// # Safety Note (R169-2 + R170-3)
///
/// This function is called in IRQ context (timer interrupt handler), so it
/// uses `try_lookup_cgroup` for the registry and `try_lock()` on every
/// `limits` mutex (a blocking acquisition would self-deadlock against a
/// same-CPU IRQs-enabled holder). It also must NOT heap-allocate (the
/// allocator lock may be held by the interrupted context) — the chain
/// snapshot below is a fixed `MAX_CGROUP_DEPTH`-bounded stack array.
///
/// # Phase structure (R170-3 FIX — contention can never drop accounting)
///
/// The old single-pass walk could return its contention fallback MID-WALK,
/// after some nodes had already accumulated, and that fallback was
/// indistinguishable from a genuine throttle — so the tick handler silently
/// LOST the tick's delta on every induced registry/limits contention
/// (the R170-3 cpu.max evasion; the prior comment's claim that contention
/// "preserves isolation" was false — it preserved the PREEMPT but dropped
/// the ACCOUNTING). Now:
///
/// * **Phase A** — non-blocking entry lookup; contention ⇒
///   `ContentionDeferred` (nothing accumulated).
/// * **Phase B** — collect the CPU-controller chain (`parent()` Weak
///   upgrades, no registry) and snapshot every `cpu.max` via `try_lock`
///   BEFORE any accumulation; any contention ⇒ `ContentionDeferred`
///   (still nothing accumulated).
/// * **Phase C** — accumulate per node with NO early returns.
///
/// `ContentionDeferred` therefore GUARANTEES zero accumulation, and the tick
/// handler re-folds the delta into the per-PCB quota debt to land on a later
/// tick (see `Process::cpu_quota_debt_ns` / `flush_cpu_quota_debt`), while
/// still preempting exactly like `Throttled`. Residual (documented): a
/// deferred delta can land one quota period later (per-period windows do not
/// carry debt across refresh, mirroring Linux cpu.max semantics), so
/// SUSTAINED multi-period adversarial contention still under-enforces within
/// the contended periods — the durable fix is removing L5 from the tick path
/// entirely (D-R170-CPU-L5 cached `Arc<CgroupNode>` on the PCB).
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup to charge
/// * `delta_ns` - CPU time consumed (nanoseconds)
/// * `now_ns` - Current time (nanoseconds since boot)
///
/// # Returns
///
/// * `Unlimited` - No CPU controller or cpu.max configured
/// * `Allowed` - Quota available, time has been charged
/// * `Throttled(until_ns)` - Quota exceeded/coasting; the delta was accumulated
/// * `ContentionDeferred(retry_ns)` - lock contention; NOTHING was accumulated
pub fn charge_cpu_quota(cgroup_id: CgroupId, delta_ns: u64, now_ns: u64) -> CpuQuotaStatus {
    if delta_ns == 0 {
        return CpuQuotaStatus::Allowed;
    }

    // P2-9 FIX: Hierarchical cpu.max enforcement — ancestor quotas apply to
    // all descendants; the overall result is the most restrictive throttle
    // deadline among all levels.
    const LOCK_CONTENTION_THROTTLE_NS: u64 = 10_000_000; // 10ms retry hint

    // Phase A (R169-2 FIX, D1-CGROUP-IRQ-L5): NON-blocking entry lookup.
    let origin = match try_lookup_cgroup(cgroup_id) {
        Some(c) => c,
        None => {
            return CpuQuotaStatus::ContentionDeferred(
                now_ns.saturating_add(LOCK_CONTENTION_THROTTLE_NS),
            );
        }
    };

    // Phase B (R170-3 FIX): collect the quota-bearing chain and snapshot every
    // cpu.max BEFORE any accumulation. Fixed-size stack storage — IRQ context,
    // no heap. Slots [0..chain_len) are Some.
    let mut chain: [Option<(CgroupArc, u64, u64)>; (MAX_CGROUP_DEPTH as usize) + 1] =
        core::array::from_fn(|_| None);
    let mut chain_len: usize = 0;
    {
        let mut depth: u32 = 0;
        let mut cursor = Some(origin);
        while let Some(cgroup) = cursor {
            if cgroup.controllers.contains(CgroupControllers::CPU) {
                // IRQ-safe: try_lock (R83-5 fail-direction now lives in the
                // ContentionDeferred contract — the caller preempts AND defers
                // the delta instead of dropping it).
                let cpu_max = match cgroup.limits.try_lock() {
                    Some(limits) => limits.cpu_max,
                    None => {
                        return CpuQuotaStatus::ContentionDeferred(
                            now_ns.saturating_add(LOCK_CONTENTION_THROTTLE_NS),
                        );
                    }
                };
                if let Some((max_us, period_us)) = cpu_max {
                    // u64::MAX means "max" (no quota) - mirrors Linux semantics
                    if max_us != u64::MAX {
                        chain[chain_len] = Some((cgroup.clone(), max_us, period_us));
                        chain_len += 1;
                    }
                }
            }
            if depth >= MAX_CGROUP_DEPTH {
                break;
            }
            depth = depth.saturating_add(1);
            cursor = cgroup.parent();
        }
    }

    if chain_len == 0 {
        return CpuQuotaStatus::Unlimited;
    }

    // Phase C: accumulate. No locks taken, NO early returns — once Phase B
    // succeeds the delta ALWAYS lands at every quota-bearing level (or coasts
    // inside that level's live throttle window, exactly as before).
    let mut overall_throttle_until: u64 = 0;
    for slot in chain.iter().take(chain_len) {
        let Some((cgroup, max_us, period_us)) = slot else {
            continue;
        };
        let period_ns = period_us.saturating_mul(1_000);
        let max_ns = max_us.saturating_mul(1_000);
        let quota = &cgroup.cpu_quota;

        // Refresh the window if the period has elapsed
        quota.refresh_window(now_ns, period_ns);

        // Check if currently throttled
        let throttle_until = quota.throttled_until_ns.load(Ordering::Acquire);
        let mut should_charge = true;
        if throttle_until != 0 {
            if now_ns < throttle_until {
                // Still in throttle window
                overall_throttle_until = overall_throttle_until.max(throttle_until);
                should_charge = false;
            } else {
                // R110-2 FIX: Throttle expired — delegate to CAS-serialized
                // refresh_window().
                quota.refresh_window(now_ns, period_ns);
            }
        }

        // R110-2 FIX: Skip charging while a refresh is in progress.
        if should_charge && !quota.is_refreshing() {
            let used = quota
                .period_usage_ns
                .fetch_add(delta_ns, Ordering::SeqCst)
                .saturating_add(delta_ns);

            if used > max_ns {
                // Quota exceeded — throttle until end of current period
                let until = quota
                    .period_start_ns
                    .load(Ordering::Relaxed)
                    .saturating_add(period_ns);
                quota.throttled_until_ns.store(until, Ordering::SeqCst);
                quota.throttle_events.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
                overall_throttle_until = overall_throttle_until.max(until);
            }
        }
    }

    if overall_throttle_until != 0 {
        CpuQuotaStatus::Throttled(overall_throttle_until)
    } else {
        CpuQuotaStatus::Allowed
    }
}

/// R170-3 FIX: synchronously land a contention-deferred CPU-quota debt on its
/// ORIGIN cgroup's quota windows. PROCESS-CONTEXT ONLY — uses the blocking
/// `lookup_cgroup` and blocking `limits.lock()` (legal under a held Process
/// lock: the established Process → cgroup order).
///
/// Called from the three places a PCB's debt tag would otherwise go stale,
/// each AFTER taking (read + zero) the debt fields under the held Process
/// lock so a concurrent `on_clock_tick` can never re-fold the same ns:
/// `sys_cgroup_attach` and the cgroupfs `cgroup.procs` migration (both before
/// re-pointing `proc.cgroup_id`), and `terminate_process` (exit).
///
/// The debt is accumulated unconditionally at every quota-bearing level
/// (modulo the R110-2 `is_refreshing` guard) — it represents time the task
/// actually RAN, so a live throttle window must not suppress it. A missing
/// node (cgroup deleted concurrently — only reachable once emptied) drops the
/// debt, bounded by one contention window.
pub fn flush_cpu_quota_debt(cgroup_id: CgroupId, debt_ns: u64, now_ns: u64) {
    if debt_ns == 0 {
        return;
    }
    let mut depth: u32 = 0;
    let mut cursor = lookup_cgroup(cgroup_id);
    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::CPU) {
            let cpu_max = cgroup.limits.lock().cpu_max;
            if let Some((max_us, period_us)) = cpu_max {
                if max_us != u64::MAX {
                    let period_ns = period_us.saturating_mul(1_000);
                    let max_ns = max_us.saturating_mul(1_000);
                    let quota = &cgroup.cpu_quota;
                    quota.refresh_window(now_ns, period_ns);
                    if !quota.is_refreshing() {
                        let used = quota
                            .period_usage_ns
                            .fetch_add(debt_ns, Ordering::SeqCst)
                            .saturating_add(debt_ns);
                        if used > max_ns {
                            let until = quota
                                .period_start_ns
                                .load(Ordering::Relaxed)
                                .saturating_add(period_ns);
                            quota.throttled_until_ns.store(until, Ordering::SeqCst);
                            // lint-fetch-add: allow (statistics counter)
                            quota.throttle_events.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }
}

/// Fast-path check if a cgroup is currently throttled.
///
/// Used by the scheduler before selecting a task to avoid scheduling
/// tasks from throttled cgroups.
///
/// # Safety Note
///
/// This function may be called with interrupts disabled (scheduler context).
/// Uses `try_lock()` on the limits mutex to avoid deadlock.
/// If the lock is contended, returns `None` (not throttled) - this is
/// conservative but safe, as the throttle will be detected on the next check.
///
/// # Arguments
///
/// * `cgroup_id` - The cgroup to check
/// * `now_ns` - Current time (nanoseconds since boot)
///
/// # Returns
///
/// * `Some(until_ns)` - Cgroup is throttled until the specified time
/// * `None` - Cgroup is not throttled (or no CPU controller/quota)
pub fn cpu_quota_is_throttled(cgroup_id: CgroupId, now_ns: u64) -> Option<u64> {
    // P2-9 FIX: Walk ancestors so parent throttling also blocks descendants.
    let mut depth: u32 = 0;
    // R169-2 FIX (D1-CGROUP-IRQ-L5): This is reached from select_next_locked
    // (the scheduler pick path) inside without_interrupts — a THIRD IRQ-off
    // registry reader the original finding missed. Use the non-blocking
    // try_lookup_cgroup; on registry contention it yields None, the walk is
    // skipped, and we return None (not throttled) — exactly this function's
    // already-documented conservative contended-limits behavior (the throttle
    // is detected on the next check). The ancestor walk uses parent()
    // (Weak::upgrade, no registry), so only the entry lookup changes.
    let mut cursor = try_lookup_cgroup(cgroup_id);
    let mut overall_until: u64 = 0;

    while let Some(cgroup) = cursor {
        if cgroup.controllers.contains(CgroupControllers::CPU) {
            // IRQ-safe: Use try_lock() to avoid deadlock in scheduler context.
            // If contended, return None (existing conservative behavior).
            let cpu_max = match cgroup.limits.try_lock() {
                Some(limits) => limits.cpu_max,
                None => return None,
            };

            if let Some((max_us, period_us)) = cpu_max {
                if max_us != u64::MAX {
                    let period_ns = period_us.saturating_mul(1_000);
                    let quota = &cgroup.cpu_quota;

                    // Refresh window first to check if throttle has expired
                    quota.refresh_window(now_ns, period_ns);

                    let until = quota.throttled_until_ns.load(Ordering::Acquire);
                    if until != 0 {
                        if now_ns < until {
                            // Still throttled at this level
                            overall_until = overall_until.max(until);
                        } else {
                            // R110-2 FIX: Throttle expired — delegate to
                            // CAS-serialized refresh_window().
                            quota.refresh_window(now_ns, period_ns);
                        }
                    }
                }
            }
        }

        if depth >= MAX_CGROUP_DEPTH {
            break;
        }
        depth = depth.saturating_add(1);
        cursor = cgroup.parent();
    }

    if overall_until != 0 {
        Some(overall_until)
    } else {
        None
    }
}

// ============================================================================
// J2-7: FILES Controller Self-Test (wired into the boot integration suite)
// ============================================================================

/// In-kernel assertions for the per-cgroup FD budget (`files.max`). Panics on any
/// failure, which `make test` / `make boot-check` detect via the serial log.
///
/// Covers: hierarchical cap enforcement (fail-closed) + ancestor rollback on a
/// deep-level rejection, ancestor propagation, the root `id==0` short-circuit
/// (a root-TARGETED charge is a no-op — note descendant charges still aggregate
/// at root per cgroup-v2 semantics), `migrate_fd_charges` balance across chains,
/// and saturating uncharge. Exercises `try_charge_fds`/`uncharge_fds` directly
/// (no real fd_table) so the engine is validated independently of syscall wiring.
pub fn run_cgroup_fd_budget_self_test() {
    let fds = |n: &CgroupArc| n.stats.fds_current.load(Ordering::SeqCst);

    // Fresh, empty, task-less cgroups under root: A(fds_max=10) ⊃ B(fds_max=4),
    // plus sibling C(fds_max=20). Their counters start at 0 (isolated from any
    // real boot processes in root).
    let a = create_cgroup(0, CgroupControllers::FILES).expect("create A");
    let a_id = a.id();
    a.set_limit(CgroupLimits {
        fds_max: Some(10),
        ..Default::default()
    })
    .expect("set A.files.max");
    let b = create_cgroup(a_id, CgroupControllers::FILES).expect("create B");
    let b_id = b.id();
    b.set_limit(CgroupLimits {
        fds_max: Some(4),
        ..Default::default()
    })
    .expect("set B.files.max");
    let c = create_cgroup(0, CgroupControllers::FILES).expect("create C");
    let c_id = c.id();
    c.set_limit(CgroupLimits {
        fds_max: Some(20),
        ..Default::default()
    })
    .expect("set C.files.max");

    // 1) Charge 3 under B (within B's cap): B and ancestor A both increment.
    try_charge_fds(b_id, 3).expect("charge 3 under B");
    assert_eq!(fds(&b), 3, "B after charge 3");
    assert_eq!(fds(&a), 3, "A (ancestor) after charge 3 under B");

    // 2) Over B's cap (3+2 > 4) → FdsLimitExceeded, and A is NOT left over-charged
    //    (deep-level rejection rolls back the already-charged ancestor).
    assert_eq!(
        try_charge_fds(b_id, 2),
        Err(CgroupError::FdsLimitExceeded),
        "B over-cap must fail-closed"
    );
    assert_eq!(fds(&b), 3, "B unchanged after rejected charge");
    assert_eq!(fds(&a), 3, "A rolled back after B rejection");

    // 3) Charge exactly to B's cap.
    try_charge_fds(b_id, 1).expect("charge 1 to B's cap");
    assert_eq!(fds(&b), 4, "B at cap");
    assert_eq!(fds(&a), 4, "A after B at cap");

    // 4) Root id==0 short-circuit: a root-TARGETED charge changes nothing.
    let root = lookup_cgroup(0).expect("root");
    let root_before = root.stats.fds_current.load(Ordering::SeqCst);
    try_charge_fds(0, 100).expect("root-targeted charge is Ok");
    uncharge_fds(0, 100);
    assert_eq!(
        root.stats.fds_current.load(Ordering::SeqCst),
        root_before,
        "root id=0 charge/uncharge are no-ops"
    );

    // 5) migrate_fd_charges B -> C: move the 4 fds. B's chain (B, A) drops by 4;
    //    C's chain (C) gains 4. (Both chains share root, so root nets 0.)
    migrate_fd_charges(4, b_id, c_id).expect("migrate B->C");
    assert_eq!(fds(&b), 0, "B drained after migrate");
    assert_eq!(fds(&a), 0, "A (B's ancestor) drained after migrate");
    assert_eq!(fds(&c), 4, "C charged after migrate");

    // 6) Saturating uncharge: uncharging more than charged floors at 0.
    uncharge_fds(c_id, 999);
    assert_eq!(fds(&c), 0, "C saturates at 0");

    // Cleanup: delete children before parents (no tasks attached).
    let _ = delete_cgroup(b_id);
    let _ = delete_cgroup(a_id);
    let _ = delete_cgroup(c_id);
}

/// J2-8: in-kernel self-test for the per-cgroup ephemeral-port budget ARITHMETIC
/// (NET controller, ports.max): hierarchical charge, deep-rejection rollback of
/// the already-charged ancestor, root id==0 exemption, and saturating uncharge.
/// Mirrors the FILES test minus migration — port charges deliberately do NOT
/// migrate on cgroup_attach (they stick to the alloc-time cgroup via
/// "uncharge what you charged"; the net-side MECHANISM is tested in
/// `net::SocketTable::run_per_cgroup_port_budget_self_test`).
pub fn run_cgroup_ports_budget_self_test() {
    let ports = |n: &CgroupArc| n.stats.ports_current.load(Ordering::SeqCst);

    // Fresh, task-less NET cgroups under root: A(ports_max=10) ⊃ B(ports_max=4).
    let a = create_cgroup(0, CgroupControllers::NET).expect("create A");
    let a_id = a.id();
    a.set_limit(CgroupLimits {
        ports_max: Some(10),
        ..Default::default()
    })
    .expect("set A.ports.max");
    let b = create_cgroup(a_id, CgroupControllers::NET).expect("create B");
    let b_id = b.id();
    b.set_limit(CgroupLimits {
        ports_max: Some(4),
        ..Default::default()
    })
    .expect("set B.ports.max");

    // 1) Charge 3 under B (within cap): B and ancestor A both increment.
    try_charge_ports(b_id, 3).expect("charge 3 under B");
    assert_eq!(ports(&b), 3, "B after charge 3");
    assert_eq!(ports(&a), 3, "A (ancestor) after charge 3 under B");

    // 2) Over B's cap (3+2 > 4) -> PortsLimitExceeded; A is NOT left over-charged
    //    (deep-level rejection rolls back the already-charged ancestor).
    assert_eq!(
        try_charge_ports(b_id, 2),
        Err(CgroupError::PortsLimitExceeded),
        "B over-cap must fail-closed"
    );
    assert_eq!(ports(&b), 3, "B unchanged after rejected charge");
    assert_eq!(ports(&a), 3, "A rolled back after B rejection");

    // 3) Charge exactly to B's cap.
    try_charge_ports(b_id, 1).expect("charge 1 to B's cap");
    assert_eq!(ports(&b), 4, "B at cap");
    assert_eq!(ports(&a), 4, "A after B at cap");

    // 4) Root id==0 short-circuit: a root-TARGETED charge/uncharge is a no-op.
    let root = lookup_cgroup(0).expect("root");
    let root_before = root.stats.ports_current.load(Ordering::SeqCst);
    try_charge_ports(0, 100).expect("root-targeted charge is Ok");
    uncharge_ports(0, 100);
    assert_eq!(
        root.stats.ports_current.load(Ordering::SeqCst),
        root_before,
        "root id=0 port charge/uncharge are no-ops"
    );

    // 5) Uncharge what you charged: drop B's 4 — B and ancestor A both decrement.
    uncharge_ports(b_id, 4);
    assert_eq!(ports(&b), 0, "B drained");
    assert_eq!(ports(&a), 0, "A (B's ancestor) drained");

    // 6) Saturating uncharge: over-uncharge floors at 0 (never wraps).
    uncharge_ports(b_id, 999);
    assert_eq!(ports(&b), 0, "B saturates at 0");

    // Cleanup: delete children before parents (no tasks attached).
    let _ = delete_cgroup(b_id);
    let _ = delete_cgroup(a_id);
}

/// R170-2: in-kernel self-test for the ORIGIN-PINNED delete-gate counters
/// (`ports_pinned`/`fds_pinned`) — the controller-DISABLED-leaf configuration
/// the R169-3 display-counter gate was blind to.
///
/// Covers: (1) a charge keyed to a NET/FILES-disabled leaf pins the LEAF
/// (controller-independent) while the display counters land only on the
/// controller-bearing parent (display semantics unchanged); (2) the
/// delete-gate REJECTS the pinned leaf (`NotEmpty`) even though every display
/// counter on it is 0 — the exact R170-2 leak interleaving, now fail-closed;
/// (3) uncharge keyed to the leaf unpins it and drains the parent's display
/// counters; (4) the drained leaf then deletes cleanly; (5) a rejected charge
/// rolls its pin back; (6) saturating unpin never wraps.
pub fn run_cgroup_disabled_leaf_gate_self_test() {
    let ports_disp = |n: &CgroupArc| n.stats.ports_current.load(Ordering::SeqCst);
    let fds_disp = |n: &CgroupArc| n.stats.fds_current.load(Ordering::SeqCst);
    let ports_pin = |n: &CgroupArc| n.stats.ports_pinned.load(Ordering::SeqCst);
    let fds_pin = |n: &CgroupArc| n.stats.fds_pinned.load(Ordering::SeqCst);

    // P carries NET+FILES+PIDS (with limits); C is a NET/FILES-DISABLED leaf
    // under P — it enables only the PIDS subset (new_child rejects an empty
    // controller set, so "controller-disabled" here means disabled for the
    // NET/FILES families the gate samples — exactly the blind configuration).
    let p = create_cgroup(
        0,
        CgroupControllers::NET | CgroupControllers::FILES | CgroupControllers::PIDS,
    )
    .expect("create P");
    let p_id = p.id();
    p.set_limit(CgroupLimits {
        ports_max: Some(10),
        fds_max: Some(10),
        ..Default::default()
    })
    .expect("set P limits");
    let c = create_cgroup(p_id, CgroupControllers::PIDS).expect("create C");
    let c_id = c.id();

    // 1) Charges keyed to C: display lands on P only; the PIN lands on C.
    try_charge_ports(c_id, 2).expect("charge 2 ports keyed to C");
    try_charge_fds(c_id, 3).expect("charge 3 fds keyed to C");
    assert_eq!(ports_disp(&c), 0, "C display ports stay 0 (controller off)");
    assert_eq!(fds_disp(&c), 0, "C display fds stay 0 (controller off)");
    assert_eq!(ports_disp(&p), 2, "P (NET ancestor) display ports");
    assert_eq!(fds_disp(&p), 3, "P (FILES ancestor) display fds");
    assert_eq!(ports_pin(&c), 2, "C pinned ports (origin-keyed)");
    assert_eq!(fds_pin(&c), 3, "C pinned fds (origin-keyed)");
    assert_eq!(ports_pin(&p), 0, "P not pinned by a C-keyed charge");

    // 2) The delete-gate must REJECT C while pinned (every display counter on
    //    C is 0 — this exact configuration silently leaked before R170-2).
    assert_eq!(
        delete_cgroup(c_id),
        Err(CgroupError::NotEmpty),
        "pinned controller-disabled leaf must be undeletable"
    );
    assert!(lookup_cgroup(c_id).is_some(), "C still registry-resident");

    // 3) Uncharge keyed to C: unpins C and drains P's display counters —
    //    exactly what the pre-R170-2 gate let the delete skip forever.
    uncharge_ports(c_id, 2);
    uncharge_fds(c_id, 3);
    assert_eq!(ports_pin(&c), 0, "C unpinned after port uncharge");
    assert_eq!(fds_pin(&c), 0, "C unpinned after fd uncharge");
    assert_eq!(ports_disp(&p), 0, "P display ports drained");
    assert_eq!(fds_disp(&p), 0, "P display fds drained");

    // 4) The drained leaf deletes cleanly.
    delete_cgroup(c_id).expect("delete drained C");

    // 5) A REJECTED charge rolls its pin back (overcharge through a fresh
    //    NET-disabled leaf: P's ports_max=10 rejects 11).
    let d = create_cgroup(p_id, CgroupControllers::PIDS).expect("create D");
    let d_id = d.id();
    assert_eq!(
        try_charge_ports(d_id, 11),
        Err(CgroupError::PortsLimitExceeded),
        "over-cap charge keyed to D fails closed"
    );
    assert_eq!(ports_pin(&d), 0, "D pin rolled back on rejection");
    assert_eq!(ports_disp(&p), 0, "P display rolled back on rejection");
    delete_cgroup(d_id).expect("delete D");

    // 6) Saturating unpin: over-uncharge floors at 0 (never wraps).
    uncharge_ports(p_id, 999);
    assert_eq!(ports_pin(&p), 0, "P pin saturates at 0");

    let _ = delete_cgroup(p_id);
}

/// M2-1 SLICE-3: in-kernel self-test for the MEMORY delete-gate flip — the
/// memory twin of `run_cgroup_disabled_leaf_gate_self_test` (ports/fds).
///
/// Proves the `delete_cgroup` resource gate now keys deletion on the
/// origin-pinned `mem_pinned` witness, NOT the controller-gated display counter
/// `memory_current`. The decisive configuration is a MEMORY-controller-DISABLED
/// leaf C under a MEMORY-bearing parent P: a charge keyed to C lands its DISPLAY
/// on P (and root) but its PIN on C, so `memory_current(C)` stays permanently 0.
/// Under the OLD gate (`live_mem = memory_current`) the delete of C would have
/// SUCCEEDED while a live ancestor charge was still keyed to C's bare id — the
/// later `uncharge_memory(C, ..)` would then find no node and silently strand
/// P's `+N` forever (the R171-S-R170-2-01 / D-R170-DELETE-GATE-LEAF leak). Under
/// the SLICE-3 gate (`live_mem = mem_pinned`) the leaf is held undeletable until
/// every keyed charge is reconciled, then deletes cleanly. The matched
/// charge/uncharge sequence telescopes exactly, so `MEM_UNPIN_UNDERFLOW` stays 0
/// (a SOUND `mem_pinned == 0` witness, not a saturating-floored one).
pub fn run_cgroup_mem_pinned_delete_gate_self_test() {
    const PAGE: u64 = 0x1000;
    let mem = |n: &CgroupArc| n.stats.memory_current.load(Ordering::SeqCst);
    let pin = |n: &CgroupArc| n.stats.mem_pinned.load(Ordering::SeqCst);

    // Clear the shared tripwire so any over-uncharge surplus is attributable to
    // THIS test's matched sequence.
    let _ = mem_unpin_underflow_take();

    // P carries MEMORY (with a generous memory.max) + PIDS; C is a MEMORY-DISABLED
    // leaf under P (new_child rejects an empty controller set, so PIDS-only =
    // "MEMORY-disabled for the family the gate samples" — the exact blind config).
    let p =
        create_cgroup(0, CgroupControllers::MEMORY | CgroupControllers::PIDS).expect("create P");
    let p_id = p.id();
    p.set_limit(CgroupLimits {
        memory_max: Some(4096 * PAGE),
        ..Default::default()
    })
    .expect("set P.memory.max");
    let c = create_cgroup(p_id, CgroupControllers::PIDS).expect("create C");
    let c_id = c.id();
    let bytes = 7 * PAGE;

    // 1) Charge keyed to C: the DISPLAY lands on P (the MEMORY ancestor) only;
    //    the PIN lands on the ORIGIN node C. C's own display stays 0.
    try_charge_memory(c_id, bytes).expect("charge bytes keyed to MEMORY-disabled leaf C");
    assert_eq!(
        mem(&c),
        0,
        "C display memory stays 0 (MEMORY controller off)"
    );
    assert_eq!(
        pin(&c),
        bytes,
        "C mem_pinned tracks the live origin-keyed charge"
    );
    assert_eq!(
        mem(&p),
        bytes,
        "P (MEMORY ancestor) display absorbs C's charge"
    );
    assert_eq!(
        pin(&p),
        0,
        "P is NOT origin-pinned by a C-keyed charge (pin is origin-keyed)"
    );

    // 2) THE SLICE-3 FIX: the delete-gate must REJECT C while it is pinned, even
    //    though every display counter on C is 0 — the exact configuration that
    //    silently leaked under the pre-SLICE-3 `memory_current` gate.
    assert_eq!(
        delete_cgroup(c_id),
        Err(CgroupError::NotEmpty),
        "pinned MEMORY-disabled leaf must be undeletable (gate keys on mem_pinned)"
    );
    assert!(
        lookup_cgroup(c_id).is_some(),
        "C still registry-resident after refused delete"
    );

    // 3) Uncharge keyed to C: unpins the ORIGIN C and drains P's display — exactly
    //    the reconciliation the pre-SLICE-3 gate let the delete skip forever.
    uncharge_memory(c_id, bytes);
    assert_eq!(pin(&c), 0, "C unpinned after memory uncharge");
    assert_eq!(
        mem(&p),
        0,
        "P display memory drained after C's charge is uncharged"
    );
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "matched charge/uncharge telescopes exactly (Σpin == Σunpin, floor never fires)"
    );

    // 4) The reconciled leaf now deletes cleanly; P (never origin-pinned, now
    //    childless) deletes after it.
    delete_cgroup(c_id).expect("delete reconciled C");
    delete_cgroup(p_id).expect("delete P");
    let _ = mem_unpin_underflow_take();
}

/// J2-9: in-kernel self-test for the page-table-frame kmem accounting. The pt
/// charge rides the MEMORY controller (try_charge_memory / uncharge_memory /
/// migrate_memory_charges) EXACTLY like the mmap DATA charge, so this exercises
/// those primitives over the same hierarchy / migration / exit / fork balance
/// points that sys_mmap's pt charge, compute_cgroup_charged_bytes (migration),
/// free_process_resources (exit), and fork_inner (fork) depend on — including the
/// INV-5 trap that the MEMORY controller (unlike files/ports/vfs_dir) does NOT
/// exempt the root cgroup. Root counters carry live boot charges, so root
/// assertions use DELTAS; fresh task-less children start at 0 (absolute).
///
/// M2-1 SLICE-2 EXTENSION: every step now ALSO asserts the origin-keyed
/// `mem_pinned` (the controller-independent delete-gate counter) telescopes in
/// lockstep — origin-only on charge, re-homed on migrate, telescoped to 0 on the
/// fork-lump↔child-exit pair and on rollback, root-non-exempt. The PROOF artifact
/// that gated the SLICE-3 gate flip was the over-uncharge TRIPWIRE assertion: steps
/// 1-7 (all MATCHED sequences) must leave `MEM_UNPIN_UNDERFLOW == 0`, proving
/// Σunpin == Σpin (a SOUND `mem_pinned == 0` witness) rather than merely
/// Σunpin >= Σpin (which saturating unpin would otherwise mask); step 8's
/// deliberate over-uncharge then MUST trip it, proving the tripwire detects the
/// masking it guards against.
pub fn run_cgroup_pt_kmem_self_test() {
    const PAGE: u64 = 0x1000;
    let mem = |n: &CgroupArc| n.stats.memory_current.load(Ordering::SeqCst);
    // M2-1 SLICE-2: origin-pin reader (controller-independent delete-gate
    // counter, twin of fds_pinned/ports_pinned).
    let pin = |n: &CgroupArc| n.stats.mem_pinned.load(Ordering::SeqCst);

    // M2-1 SLICE-2 (lens SATURATING-UNPIN-MASKING): clear the process-wide
    // over-uncharge tripwire so this test's MATCHED charge/uncharge sequences can
    // PROVE Σunpin == Σpin (tripwire stays 0), not merely Σunpin >= Σpin (which
    // mem_pinned == 0 alone admits under saturating unpin). A nonzero tripwire at
    // any matched-step assertion below is an over-uncharge accounting regression.
    let _ = mem_unpin_underflow_take();

    // Fresh, empty, task-less MEMORY cgroups under root:
    // A(memory.max=64 pages) ⊃ B(memory.max=8 pages), sibling C(memory.max=64 pages).
    let a = create_cgroup(0, CgroupControllers::MEMORY).expect("create A");
    let a_id = a.id();
    a.set_limit(CgroupLimits {
        memory_max: Some(64 * PAGE),
        ..Default::default()
    })
    .expect("set A.memory.max");
    let b = create_cgroup(a_id, CgroupControllers::MEMORY).expect("create B");
    let b_id = b.id();
    b.set_limit(CgroupLimits {
        memory_max: Some(8 * PAGE),
        ..Default::default()
    })
    .expect("set B.memory.max");
    let c = create_cgroup(a_id, CgroupControllers::MEMORY).expect("create C");
    let c_id = c.id();
    c.set_limit(CgroupLimits {
        memory_max: Some(64 * PAGE),
        ..Default::default()
    })
    .expect("set C.memory.max");

    // 1) FORCED PT charge + ANCESTOR propagation. charge_memory_forced is how
    //    sys_mmap records the page-table-frame kmem (the frame count is known only
    //    AFTER map_to runs ⇒ soft cap per IM-14). Charge 6 PT pages under B.
    charge_memory_forced(b_id, 6 * PAGE);
    assert_eq!(mem(&b), 6 * PAGE, "B after forced PT charge");
    assert_eq!(
        mem(&a),
        6 * PAGE,
        "A (ancestor) after forced PT charge under B"
    );
    // M2-1 SLICE-2: the forced charge PINS the ORIGIN (B) — and ONLY the origin,
    // controller-independently. The pin does NOT propagate to the ancestor A
    // (unlike the display counter, which the controller walk pushes up the
    // chain). This is the origin-keyed semantics the delete-gate now samples.
    assert_eq!(
        pin(&b),
        6 * PAGE,
        "B mem_pinned after forced PT charge (origin)"
    );
    assert_eq!(
        pin(&a),
        0,
        "A mem_pinned stays 0 (pin is origin-keyed, not hierarchical)"
    );

    // 2) SOFT overshoot: a forced PT charge NEVER rejects, even past memory.max.
    //    6 + 4 = 10 > B.max(8) is ALLOWED — the frames physically exist, and
    //    over-count is the safe direction (bounded by one mmap's tiny pt delta in
    //    practice). Both B and the ancestor A rise.
    charge_memory_forced(b_id, 4 * PAGE);
    assert_eq!(
        mem(&b),
        10 * PAGE,
        "B forced past memory.max (soft, over-count-safe)"
    );
    assert_eq!(mem(&a), 10 * PAGE, "A after forced overshoot under B");
    assert_eq!(
        pin(&b),
        10 * PAGE,
        "B mem_pinned tracks the soft overshoot (origin)"
    );

    // 3) The HARD gate RE-ENFORCES on the NEXT data-style allocation: now that B is
    //    over its max, try_charge_memory (the Phase-1 DATA gate) rejects — so the
    //    soft pt overshoot cannot be parlayed into an unbounded bypass.
    assert_eq!(
        try_charge_memory(b_id, PAGE),
        Err(CgroupError::MemoryLimitExceeded),
        "hard DATA gate re-enforces memory.max after pt overshoot",
    );
    assert_eq!(mem(&b), 10 * PAGE, "B unchanged after rejected hard charge");
    // M2-1 SLICE-2: ROLLBACK-UNPIN proof. The rejected hard charge pinned the
    // origin FIRST, then unpinned the full allocation in its Err arm — so B's pin
    // is UNCHANGED (10 pages), NOT 11. Omitting the rollback-unpin would leave a
    // permanent +1-page pin here (FA-04 undeletability) — caught by this assert.
    assert_eq!(
        pin(&b),
        10 * PAGE,
        "B mem_pinned unchanged after rejected hard charge (rollback-unpin)"
    );

    // 4) ROOT NOT EXEMPT (INV-5 trap): unlike files/ports/vfs_dir, the MEMORY
    //    controller charges the root cgroup. A root-targeted forced charge MUST
    //    move root.memory_current — asserted via delta (root carries live charges).
    let root = lookup_cgroup(0).expect("root");
    let root_before = mem(&root);
    // M2-1 SLICE-2: root mem_pinned carries permanent boot pins, so use a DELTA.
    // The MEMORY pin (unlike fds/ports, which short-circuit id==0) MUST move for
    // root too — both pin AND unpin are id==0-non-exempt, so root telescopes.
    let root_pin_before = pin(&root);
    charge_memory_forced(0, 5 * PAGE);
    assert_eq!(
        mem(&root),
        root_before + 5 * PAGE,
        "root IS charged (no exemption)"
    );
    assert_eq!(
        pin(&root),
        root_pin_before + 5 * PAGE,
        "root mem_pinned moves (no id==0 exemption)"
    );
    uncharge_memory(0, 5 * PAGE);
    assert_eq!(
        mem(&root),
        root_before,
        "root PT uncharge restores baseline"
    );
    assert_eq!(
        pin(&root),
        root_pin_before,
        "root mem_pinned telescopes back (no id==0 exemption)"
    );

    // 5) MIGRATION TRANSFER (compute_cgroup_charged_bytes path): move B's 10 PT
    //    pages B → C. B's chain (B, A) drops by 10; C's chain (C, A) gains 10. The
    //    shared ancestor A nets 0; B ends at 0, C ends at 10.
    migrate_memory_charges(10 * PAGE, b_id, c_id).expect("migrate PT B→C");
    assert_eq!(mem(&b), 0, "B drained after PT migrate");
    assert_eq!(mem(&c), 10 * PAGE, "C charged after PT migrate");
    assert_eq!(
        mem(&a),
        10 * PAGE,
        "A (shared ancestor) net unchanged by sibling migrate"
    );
    // M2-1 SLICE-2: the pin RE-HOMES via the primitive composition
    // (try_charge_memory(C) pins C, uncharge_memory(B) unpins B) — no bespoke
    // migrate-level pin code. Source pin telescopes to EXACTLY 0 (the migrated
    // `bytes` == B's entire live pin), destination gains it. The shared ancestor
    // A was never pinned (origin-keyed), so it stays 0 across the sibling move.
    assert_eq!(
        pin(&b),
        0,
        "B mem_pinned drained to 0 by migrate source-unpin"
    );
    assert_eq!(
        pin(&c),
        10 * PAGE,
        "C mem_pinned gained by migrate dest-pin"
    );
    assert_eq!(
        pin(&a),
        0,
        "A mem_pinned stays 0 (origin-keyed, not hierarchical)"
    );

    // 6) EXIT BALANCE: last-exit uncharge of C's PT returns the chain to baseline.
    uncharge_memory(c_id, 10 * PAGE);
    assert_eq!(mem(&c), 0, "C drained after exit uncharge");
    assert_eq!(mem(&a), 0, "A drained after C exit uncharge");
    assert_eq!(
        pin(&c),
        0,
        "C mem_pinned telescopes to 0 after exit uncharge"
    );

    // 7) FORK == EXIT balance (per-process +X / -X): fork charges the inherited
    //    child PT to the PARENT cgroup with the HARD gate (the value is known
    //    pre-fork ⇒ hard per IM-14); the child's last-exit uncharge cancels it.
    try_charge_memory(a_id, 6 * PAGE).expect("fork: charge inherited child PT to parent cgroup");
    assert_eq!(mem(&a), 6 * PAGE, "A after fork PT charge");
    // M2-1 SLICE-2: the fork lump pins the PARENT-cgroup origin (here a_id).
    assert_eq!(
        pin(&a),
        6 * PAGE,
        "A mem_pinned after fork PT charge (parent-cgroup origin)"
    );
    uncharge_memory(a_id, 6 * PAGE); // child last-exit
    assert_eq!(
        mem(&a),
        0,
        "A back to baseline: fork PT charge cancelled by child exit"
    );
    // M2-1 SLICE-2: the fork-lump pin telescopes to 0 against the child's exit
    // uncharge AT THE SAME ORIGIN — proving the amount-asymmetry (1 lump add vs
    // N exit subs) is harmless for a COUNTER (telescopes on Σ equality), refuting
    // the historical FA-04 objection at the delete-gate (cgroup.rs:1822-1833).
    assert_eq!(
        pin(&a),
        0,
        "A mem_pinned telescopes to 0: fork lump cancelled by child exit"
    );

    // ── M2-1 SLICE-2 PROOF CHECKPOINT (lens SATURATING-UNPIN-MASKING) ──
    // EVERY step above (1-7) was a MATCHED charge/uncharge sequence. If the pin
    // truly telescopes (Σunpin == Σpin) then NO unpin ever clamped at the floor,
    // so the over-uncharge tripwire MUST read 0. This distinguishes a genuine
    // telescope from a masked over-uncharge — which `mem_pinned == 0` alone
    // CANNOT do under saturating unpin. Assert-then-CLEAR so the deliberate
    // step-8 saturation below starts from a known-zero tripwire.
    //
    // The tripwire is process-wide; like the absolute `mem(&x)==0` assertions on
    // fresh cgroups already in this test, it relies on the boot-quiescent
    // single-CPU init context (no concurrent memory uncharge from userspace,
    // which has not started yet). This is the same contract every cgroup
    // self-test here already assumes.
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "M2-1 SLICE-2: matched charge/uncharge sequences (steps 1-7) telescoped \
         WITHOUT any saturating over-uncharge — mem_pinned==0 is a SOUND witness, \
         not merely a saturation artifact",
    );

    // 8) SATURATING uncharge (DELIBERATE over-uncharge): over-uncharge floors
    //    memory_current AND mem_pinned at 0 (never drives them below true usage →
    //    never a downstream memory.max bypass; for the pin, the transiently-LENIENT
    //    direction — never the FA-04 permanently-blocked direction). A starts
    //    reconciled at 0, so uncharging 999 pages is a pure saturation demo.
    uncharge_memory(a_id, 999 * PAGE);
    assert_eq!(mem(&a), 0, "A saturates at 0 on over-uncharge");
    assert_eq!(
        pin(&a),
        0,
        "A mem_pinned saturates at 0 on over-uncharge (lenient direction)"
    );
    // M2-1 SLICE-2: and CRUCIALLY — the tripwire FIRED on this deliberate
    // over-uncharge (pre-value 0 < 999 pages ⇒ the whole amount was absorbed by
    // the floor). This proves the tripwire actually DETECTS the masking that
    // step-8 demonstrates: had a real double-uncharge bug existed in steps 1-7 it
    // would have been caught above, NOT silently floored to mem_pinned==0.
    assert_eq!(
        mem_unpin_underflow_take(),
        999 * PAGE,
        "M2-1 SLICE-2: the tripwire detects the deliberate step-8 over-uncharge \
         (mem_pinned==0 ALONE would have masked it)",
    );

    // Cleanup: delete children before parents (no tasks attached).
    let _ = delete_cgroup(b_id);
    let _ = delete_cgroup(c_id);
    let _ = delete_cgroup(a_id);
}

/// M0-7 item7 SLICE 4: matched-sequence telescoping self-test for the user-stack
/// demand-grow charge lane — the cgroup-level proof that `try_grow_user_stack`'s
/// accounting leaves NO stranded `mem_pinned` (the FA-04 failure mode: a grow charged
/// to a bucket teardown/compute never read would strand `mem_pinned>0` at exit and wedge
/// `delete_cgroup` forever).
///
/// The grow primitive HARD-charges the grow DATA (`try_charge_memory`, committed into
/// `elf_charged_bytes`) and SOFT-charges the page-table-frame kmem (`charge_memory_forced`
/// + `record_pt_charge`); a process exit uncharges BOTH lanes via `uncharge_memory` (the
/// DATA via the `elf_charged_bytes` teardown leg at `free_process_resources:4992`). This
/// drives those EXACT primitives over the grow → migrate → exit → rollback lifecycle and
/// asserts the origin-keyed pin telescopes to 0 with `MEM_UNPIN_UNDERFLOW == 0` (a SOUND
/// witness — Σunpin == Σpin — not a saturating-floored one). Panics on failure.
pub fn run_stack_grow_cgroup_self_test() {
    run_fault_memory_charge_self_test();

    const PAGE: u64 = 0x1000;
    let mem = |n: &CgroupArc| n.stats.memory_current.load(Ordering::SeqCst);
    let pin = |n: &CgroupArc| n.stats.mem_pinned.load(Ordering::SeqCst);

    // Clear the process-wide over-uncharge tripwire so the matched sequences below PROVE
    // Σunpin == Σpin (tripwire stays 0), not merely Σunpin >= Σpin.
    let _ = mem_unpin_underflow_take();

    // A(memory.max=256 pages) ⊃ B(leaf), sibling C — all fresh, task-less.
    let a = create_cgroup(0, CgroupControllers::MEMORY).expect("create A");
    let a_id = a.id();
    a.set_limit(CgroupLimits {
        memory_max: Some(256 * PAGE),
        ..Default::default()
    })
    .expect("set A.memory.max");
    let b = create_cgroup(a_id, CgroupControllers::MEMORY).expect("create B");
    let b_id = b.id();
    let c = create_cgroup(a_id, CgroupControllers::MEMORY).expect("create C");
    let c_id = c.id();

    // A grow of 4 DATA pages whose page-table materialization pulled 1 PT-frame page.
    const DATA: u64 = 4 * PAGE;
    const PT: u64 = PAGE;

    // 1) GROW: HARD DATA charge (try_charge_memory — committed into elf_charged_bytes by
    //    commit_stack_grow) + SOFT PT charge (charge_memory_forced). Both lanes pin B's
    //    origin and propagate the display counter to the ancestor A.
    try_charge_memory(b_id, DATA).expect("grow: HARD DATA charge within memory.max");
    charge_memory_forced(b_id, PT);
    assert_eq!(mem(&b), DATA + PT, "B after grow DATA+PT charge");
    assert_eq!(mem(&a), DATA + PT, "A (ancestor) after grow under B");
    assert_eq!(pin(&b), DATA + PT, "B mem_pinned after grow (origin-keyed)");
    assert_eq!(
        pin(&a),
        0,
        "A mem_pinned stays 0 (origin-keyed, not hierarchical)"
    );

    // 2) MIGRATE B→C (compute_cgroup_charged_bytes path): the grown footprint moves with
    //    the task. B drains to 0; C gains DATA+PT; shared ancestor A nets unchanged.
    migrate_memory_charges(DATA + PT, b_id, c_id).expect("migrate grown footprint B→C");
    assert_eq!(mem(&b), 0, "B drained after migrate");
    assert_eq!(mem(&c), DATA + PT, "C charged after migrate");
    assert_eq!(mem(&a), DATA + PT, "A net unchanged by sibling migrate");
    assert_eq!(
        pin(&b),
        0,
        "B mem_pinned drained to 0 by migrate source-unpin"
    );
    assert_eq!(
        pin(&c),
        DATA + PT,
        "C mem_pinned gained by migrate dest-pin"
    );

    // 3) EXIT/TEARDOWN: last-exit uncharges BOTH lanes — the DATA via the elf_charged_bytes
    //    teardown leg, the PT via free_process_resources' pt leg. Both route through
    //    uncharge_memory; the pin telescopes to EXACTLY 0 (FA-04 closed: no stranded pin).
    uncharge_memory(c_id, DATA); // elf_charged_bytes teardown uncharge
    uncharge_memory(c_id, PT); // pt teardown uncharge
    assert_eq!(mem(&c), 0, "C drained after exit uncharge");
    assert_eq!(mem(&a), 0, "A drained after C exit uncharge");
    assert_eq!(
        pin(&c),
        0,
        "C mem_pinned telescopes to 0 after exit — the FA-04 property: a stack-growing \
         exit strands NO pin, so delete_cgroup stays openable"
    );

    // 4) ROLLBACK (map-failure / ENOMEM after the DATA charge): the grow charged DATA then
    //    its error arm uncharged it to the CURRENT cgroup — a matched +DATA/-DATA pair that
    //    must telescope with no residual pin.
    try_charge_memory(b_id, DATA).expect("rollback: provisional DATA charge");
    assert_eq!(
        pin(&b),
        DATA,
        "B pinned by the provisional grow DATA charge"
    );
    uncharge_memory(b_id, DATA); // map-fail rollback uncharge
    assert_eq!(mem(&b), 0, "B drained after rollback uncharge");
    assert_eq!(pin(&b), 0, "B mem_pinned telescopes to 0 after rollback");

    // PROOF CHECKPOINT: every step above was a MATCHED charge/uncharge sequence, so if the
    // grow lane truly telescopes NO unpin ever clamped at the floor ⇒ the tripwire reads 0.
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "M0-7 SLICE 4: the stack-grow charge lane telescopes WITHOUT any saturating \
         over-uncharge — mem_pinned==0 is a SOUND witness (no FA-04 strand)",
    );

    // Cleanup: delete children before parents (no tasks attached).
    let _ = delete_cgroup(b_id);
    let _ = delete_cgroup(c_id);
    let _ = delete_cgroup(a_id);
}

/// RF178-12: focused receipt tests for rollback, limit rejection, partial DATA
/// refund, PT ownership transfer, and try-lock contention.
fn run_fault_memory_charge_self_test() {
    const PAGE: u64 = 0x1000;
    let mem = |node: &CgroupArc| node.stats.memory_current.load(Ordering::SeqCst);
    let pin = |node: &CgroupArc| node.stats.mem_pinned.load(Ordering::SeqCst);
    let _ = mem_unpin_underflow_take();

    let parent = create_cgroup(0, CgroupControllers::MEMORY).expect("fault charge parent");
    parent
        .set_limit(CgroupLimits {
            memory_max: Some(64 * PAGE),
            ..Default::default()
        })
        .expect("fault charge parent limit");
    let leaf = create_cgroup(parent.id(), CgroupControllers::MEMORY).expect("fault charge leaf");

    // An armed receipt owns the complete charge and Drop rolls it back exactly.
    {
        let receipt = FaultMemoryCharge::try_new(leaf.id(), 4 * PAGE).expect("initial DATA charge");
        assert_eq!(receipt.charged_bytes(), 4 * PAGE);
        assert_eq!(mem(&leaf), 4 * PAGE);
        assert_eq!(mem(&parent), 4 * PAGE);
        assert_eq!(pin(&leaf), 4 * PAGE);
    }
    assert_eq!(mem(&leaf), 0, "Drop rolls back leaf DATA");
    assert_eq!(mem(&parent), 0, "Drop rolls back ancestor DATA");
    assert_eq!(pin(&leaf), 0, "Drop rolls back the origin pin");

    // A contended limit lock fails before any counter or origin pin changes.
    let held_limit = leaf.limits.lock();
    assert!(matches!(
        FaultMemoryCharge::try_new(leaf.id(), PAGE),
        Err(FaultChargeError::Contended)
    ));
    assert_eq!(mem(&leaf), 0);
    assert_eq!(mem(&parent), 0);
    assert_eq!(pin(&leaf), 0);
    drop(held_limit);

    // PT addition rejection rolls back only that delta and preserves the DATA
    // reservation already owned by the transaction.
    leaf.set_limit(CgroupLimits {
        memory_max: Some(6 * PAGE),
        ..Default::default()
    })
    .expect("tight fault charge limit");
    {
        let mut receipt =
            FaultMemoryCharge::try_new(leaf.id(), 4 * PAGE).expect("DATA below tight limit");
        assert_eq!(
            receipt.try_add(3 * PAGE),
            Err(FaultChargeError::LimitExceeded)
        );
        assert_eq!(receipt.charged_bytes(), 4 * PAGE);
        assert_eq!(mem(&leaf), 4 * PAGE);
        assert_eq!(mem(&parent), 4 * PAGE);
        assert_eq!(pin(&leaf), 4 * PAGE);
    }
    assert_eq!(mem(&leaf), 0);
    assert_eq!(mem(&parent), 0);
    assert_eq!(pin(&leaf), 0);

    // Model 8 DATA + 2 PT pages, then a five-page unused DATA suffix. The
    // committed owner is exactly 3 DATA + 2 PT pages and teardown telescopes it.
    leaf.set_limit(CgroupLimits {
        memory_max: Some(32 * PAGE),
        ..Default::default()
    })
    .expect("raise fault charge limit");
    let mut receipt = FaultMemoryCharge::try_new(leaf.id(), 8 * PAGE).expect("eight DATA pages");
    receipt.try_add(2 * PAGE).expect("two PT pages");
    receipt.refund(5 * PAGE).expect("unused DATA suffix");
    assert_eq!(receipt.charged_bytes(), 5 * PAGE);
    assert_eq!(mem(&leaf), 5 * PAGE);
    assert_eq!(mem(&parent), 5 * PAGE);
    assert_eq!(pin(&leaf), 5 * PAGE);
    receipt.commit();
    uncharge_memory(leaf.id(), 5 * PAGE);
    assert_eq!(mem(&leaf), 0);
    assert_eq!(mem(&parent), 0);
    assert_eq!(pin(&leaf), 0);
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "fault receipt matched sequences never trigger the underflow tripwire"
    );

    let _ = delete_cgroup(leaf.id());
    let _ = delete_cgroup(parent.id());
}

/// M2-1 SLICE-2 (co-residency GAP closure): in-kernel self-test that the
/// origin-keyed `mem_pinned` aggregate is PER-PROCESS-EXACT under MULTI-PROCESS
/// CO-RESIDENCY, and that the saturating-unpin floor NEVER fires when ONE of N
/// co-resident processes migrates out.
///
/// WHY THIS IS THE LOAD-BEARING CASE the rest of the suite does NOT cover:
/// `run_cgroup_pt_kmem_self_test` migrates a cgroup that holds EXACTLY the
/// migrated amount (one notional process), so its source unpin drains the source
/// to 0 — it can never reveal whether the migration unpin is *bounded by the
/// migrating process's share* or whether it over-unpins and floors. The ONLY
/// configuration where the saturating floor (`saturating_sub` in
/// `unpin_origin_mem`) could MASK a real residual is `mem_pinned(S) > 0` AFTER a
/// migration: if migration unpinned MORE than the migrating process's
/// `compute(P)`, it would clamp S's aggregate LOW and silently strand the
/// co-resident processes' pins — and (post SLICE-3 gate flip) let S be deleted
/// while live charges keyed to it remain (the FA-09-adjacent under-count
/// failure). This test proves that does NOT happen: migration unpins EXACTLY
/// `compute(P)` (== the `bytes` arg, `<= mem_pinned(S)`), so `mem_pinned(S)`
/// lands on the precise residual `Σ_{j≠i} compute(proc_j)`, the floor never
/// fires, and the `MEM_UNPIN_UNDERFLOW` tripwire stays 0.
///
/// MODEL: two "processes" X and Y co-resident in source S (two independent
/// `try_charge_memory(s_id, ·)` calls, exactly as two live PIDs each charge their
/// own footprint to their shared current cgroup). Migrate ONLY X to D, then drain
/// each surviving process via its own last-exit `uncharge_memory`. Every step
/// asserts the origin pin, the controller-walked display counter, AND the
/// over-uncharge tripwire, so a future implementation that over-unpins on
/// migration (the masked-residual bug) FAILS here instead of silently passing a
/// `mem_pinned == 0` witness.
pub fn run_cgroup_mem_pinned_coresidency_self_test() {
    const PAGE: u64 = 0x1000;
    let mem = |n: &CgroupArc| n.stats.memory_current.load(Ordering::SeqCst);
    let pin = |n: &CgroupArc| n.stats.mem_pinned.load(Ordering::SeqCst);

    // Clear the shared tripwire so any over-uncharge surplus is attributable to
    // THIS test (read-and-cleared at each matched-sequence checkpoint below).
    let _ = mem_unpin_underflow_take();

    // Fresh, task-less MEMORY hierarchy under root:
    //   A (parent, generous memory.max) ⊃ { S (source), D (dest) }  — siblings.
    // A is the SHARED ancestor: every charge to S or D also moves A's display, so
    // A is exactly where a co-resident over-unpin would corrupt the shared total.
    let a = create_cgroup(0, CgroupControllers::MEMORY).expect("create A");
    let a_id = a.id();
    a.set_limit(CgroupLimits {
        memory_max: Some(1024 * PAGE),
        ..Default::default()
    })
    .expect("set A.memory.max");
    let s = create_cgroup(a_id, CgroupControllers::MEMORY).expect("create S");
    let s_id = s.id();
    s.set_limit(CgroupLimits {
        memory_max: Some(512 * PAGE),
        ..Default::default()
    })
    .expect("set S.memory.max");
    let d = create_cgroup(a_id, CgroupControllers::MEMORY).expect("create D");
    let d_id = d.id();
    d.set_limit(CgroupLimits {
        memory_max: Some(512 * PAGE),
        ..Default::default()
    })
    .expect("set D.memory.max");

    // Two DISTINCT per-process footprints (X != Y so a residual of the WRONG
    // process is detectable — a same-size pair could alias an over-unpin).
    let x: u64 = 7 * PAGE; // "process X" compute
    let y: u64 = 11 * PAGE; // "process Y" compute (co-resident with X in S)

    // 1) CO-RESIDENCY: charge BOTH processes to S (two separate charges, exactly
    //    as two live PIDs in one cgroup each charge their own footprint). The
    //    origin pin AGGREGATES: mem_pinned(S) == x + y.
    try_charge_memory(s_id, x).expect("charge process X to S");
    try_charge_memory(s_id, y).expect("charge process Y to S");
    assert_eq!(
        pin(&s),
        x + y,
        "S pin AGGREGATES both co-resident processes"
    );
    assert_eq!(mem(&s), x + y, "S display aggregates both processes");
    assert_eq!(
        mem(&a),
        x + y,
        "A (shared ancestor) display aggregates both"
    );
    assert_eq!(pin(&d), 0, "D not yet pinned");
    assert_eq!(mem(&d), 0, "D display still 0");
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "no over-uncharge during co-resident charge"
    );

    // 2) MIGRATE ONLY PROCESS X: S -> D, transferring exactly compute(X) == x.
    //    migrate_memory_charges(x, s, d) = try_charge_memory(d, x) +
    //    uncharge_memory(s, x). The source unpin subtracts x from S's AGGREGATE
    //    pin (x + y). Because x <= x + y, the saturating floor does NOT engage:
    //    mem_pinned(S) lands on EXACTLY y.
    migrate_memory_charges(x, s_id, d_id).expect("migrate process X: S -> D");

    // THE GAP ASSERTIONS — per-process-exact unpin, floor never fires:
    assert_eq!(
        pin(&s),
        y,
        "S pin == Y: the co-resident process's share SURVIVES (NOT 0, NOT floored)"
    );
    assert_ne!(
        pin(&s),
        0,
        "S must NOT be drained to 0 by a single-process migrate"
    );
    assert_eq!(
        pin(&d),
        x,
        "D pin == X (exactly the migrated process's share)"
    );
    // Display counters telescope identically (S loses x, D gains x; shared A
    // unchanged — a sibling migrate nets 0 on the common ancestor).
    assert_eq!(mem(&s), y, "S display drops to Y after X migrates out");
    assert_eq!(mem(&d), x, "D display rises to X after X migrates in");
    assert_eq!(
        mem(&a),
        x + y,
        "A (shared ancestor) net unchanged by sibling migrate"
    );
    // THE FLOOR-NEVER-FIRED PROOF: the migration's source unpin
    // (uncharge_memory(s, x)) saw pre-value x + y >= x, so unpin_origin_mem never
    // clamped. The tripwire (fires IFF a saturating unpin absorbed a surplus) is
    // 0 — so mem_pinned(S) == y is a TRUE residual, not a floored one. This is
    // the exact distinction the `mem_pinned == 0` witness alone CANNOT make.
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "single-process migrate out of a co-resident cgroup NEVER over-unpins (floor never fires)"
    );

    // 3) DRAIN PROCESS Y (its last-exit) from S: uncharge_memory(s, y) unpins the
    //    EXACT residual. S telescopes to 0 cleanly — and only NOW, because Y's pin
    //    was preserved across X's migration. A floored S in step 2 would have made
    //    this exit a NO-OP and stranded Y's display on the ancestor; instead it
    //    reconciles.
    uncharge_memory(s_id, y);
    assert_eq!(
        pin(&s),
        0,
        "S fully reconciled after its last process (Y) exits"
    );
    assert_eq!(mem(&s), 0, "S display drained after Y exits");
    assert_eq!(
        mem(&a),
        x,
        "A retains only the migrated process X (now keyed to D)"
    );

    // 4) DRAIN PROCESS X (its last-exit) from D: uncharge_memory(d, x).
    uncharge_memory(d_id, x);
    assert_eq!(pin(&d), 0, "D reconciled after migrated process X exits");
    assert_eq!(mem(&d), 0, "D display drained");
    assert_eq!(
        mem(&a),
        0,
        "A (shared ancestor) fully drained: every process exited"
    );
    // Σpin (x + y for the two charges, + x for the migrate dest charge) ==
    // Σunpin (x migrate source + y Y-exit + x X-exit). Tripwire confirms NO
    // saturating clamp anywhere in the matched sequence.
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "co-residency charge/migrate/dual-exit telescopes exactly (Σpin == Σunpin, no floor)"
    );

    // 5) EXACT-RESIDUAL BOUNDARY: re-charge two co-resident processes to S, then
    //    migrate BOTH out one at a time. After the SECOND migrate the source unpin
    //    is uncharge_memory(s, y) with pre-value EXACTLY y — the boundary case
    //    where residual == unpin amount, which must still NOT trip the floor
    //    (pre == n, not pre < n).
    try_charge_memory(s_id, x).expect("re-charge X to S");
    try_charge_memory(s_id, y).expect("re-charge Y to S");
    assert_eq!(pin(&s), x + y, "S re-aggregates both processes");
    migrate_memory_charges(x, s_id, d_id).expect("migrate X out (1st)");
    assert_eq!(pin(&s), y, "S == Y after first co-resident migrate");
    migrate_memory_charges(y, s_id, d_id).expect("migrate Y out (2nd, exact-residual boundary)");
    assert_eq!(
        pin(&s),
        0,
        "S == 0 after BOTH migrate out (exact telescope, pre == n)"
    );
    assert_eq!(pin(&d), x + y, "D now holds both migrated processes");
    assert_eq!(mem(&a), x + y, "A still holds both (both now keyed to D)");
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "exact-residual boundary migrate (pre == n) does NOT trip the floor"
    );
    // Drain D of both and confirm full reconciliation.
    uncharge_memory(d_id, x + y);
    assert_eq!(pin(&d), 0, "D drained of both migrated processes");
    assert_eq!(mem(&a), 0, "A fully drained again");
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "final drain telescopes exactly (no floor)"
    );

    // Cleanup: children before parent (no tasks attached). Leave the shared
    // tripwire as we found it (0).
    let _ = delete_cgroup(s_id);
    let _ = delete_cgroup(d_id);
    let _ = delete_cgroup(a_id);
    let _ = mem_unpin_underflow_take();
}

/// M2-1 SLICE-2 (exec/exit-AFTER-migrate GAP closure): in-kernel self-test that
/// the exec image-replace OLD-image uncharge (syscall.rs:4562-4602), the
/// ExecSpaceGuard rollback (syscall.rs:4247), and the process-exit uncharge
/// (process.rs:4318-4358) — all of which unpin at the CURRENT `proc.cgroup_id`
/// re-read under the Process lock — land on the cgroup the prior migration
/// RE-HOMED the old image's pin TO, by EXACTLY the migrated amount, with the
/// saturating floor NEVER firing.
///
/// WHY THIS IS THE LOAD-BEARING CASE the rest of the suite does NOT cover:
/// the production exec-replace path reads `cgroup_id = proc.cgroup_id` (a single
/// re-read under the held Process lock) and issues FOUR origin uncharges
/// (mmap-data / heap / elf / pt) against it. Its correctness rests on the
/// invariant that EVERY prior migration re-homed the old image's pin to that id
/// (migrate's `try_charge_memory(to) + uncharge_memory(from)` composition). The
/// existing suite proves the COMPONENTS but never the COMPOSED cross-origin
/// round in isolation:
///   * `run_cgroup_pt_kmem_self_test` step 5-6 migrates then uncharges at the
///     DESTINATION, but only on the FORCED pt lane (not the `try_charge_memory`
///     DATA/ELF origin the exec image-replace and ExecSpaceGuard actually use),
///     and it never reads the tripwire IMMEDIATELY after the destination uncharge
///     — the only matched-sequence tripwire read lumps steps 1-7 together, so an
///     over-unpin localized to the destination-exit would be diluted.
///   * `run_cgroup_mem_pinned_coresidency_self_test` migrates ONE of two
///     co-resident processes, so its migrate SOURCE always retains the other
///     (pre-value `x + y > x`, a STRICT-inequality case) — it never exercises the
///     SINGLE-process source that telescopes to EXACTLY 0 (pre == n on the
///     migrate-source), which is the precise boundary the exec/exit-after-migrate
///     path hits when the old image is the whole footprint.
///
/// So no test proves the CLEAN, ISOLATED `charge X to A -> migrate(X, A->B) ->
/// exec/exit-uncharge X at B` round where (a) A telescopes to EXACTLY 0 via the
/// migrate source-unpin (pre == n), (b) B is then unpinned to EXACTLY 0 by the
/// four-term old-image uncharge keyed to B, and (c) the over-uncharge tripwire is
/// read == 0 IMMEDIATELY after the destination uncharge — proving B's unpin found
/// a LIVE pin == X (the re-home LANDED on B), NOT a floored over-unpin masking an
/// A-vs-B origin mismatch. That distinction (true re-home vs masked over-unpin at
/// B) is exactly what `mem_pinned == 0` ALONE cannot make under saturating unpin,
/// and it was the precondition that gated the SLICE-3 delete-gate flip for the
/// cross-origin exec/exit case.
///
/// MODEL: ONE notional process whose OLD image is a FOUR-TERM footprint
/// (mmap-data via `try_charge_memory`, heap via `try_charge_memory`, elf via
/// `try_charge_memory`, pt via `charge_memory_forced` — exactly the production
/// charge primitives per lane). It is charged to A, MIGRATED A->B by the
/// aggregated `compute` lump (the single `migrate_memory_charges(total, A, B)`
/// call the real migration makes), and then the OLD image is uncharged at B as
/// the production exec image-replace does (FOUR separate `uncharge_memory`
/// calls at `proc.cgroup_id == B`). Asserts pin(A)==0 and pin(B)==0 at each
/// boundary and the tripwire == 0 at each checkpoint.
pub fn run_cgroup_mem_pinned_exec_after_migrate_self_test() {
    const PAGE: u64 = 0x1000;
    let mem = |n: &CgroupArc| n.stats.memory_current.load(Ordering::SeqCst);
    let pin = |n: &CgroupArc| n.stats.mem_pinned.load(Ordering::SeqCst);

    // Clear the shared tripwire so any over-uncharge surplus is attributable to
    // THIS test (read-and-cleared at each matched-sequence checkpoint below).
    let _ = mem_unpin_underflow_take();

    // Fresh, task-less MEMORY hierarchy under root:
    //   ROOT-OF-TEST (RT, generous memory.max) ⊃ { A (source), B (dest) } — siblings.
    // RT is the SHARED ancestor; A and B are the two distinct origins the old
    // image's pin must move BETWEEN (A == charge origin, B == post-migration
    // exec/exit-uncharge origin). Using siblings (not ancestor/descendant) makes
    // the shared-ancestor display net 0 across the move, isolating the A->B pin
    // re-home as the ONLY origin-keyed motion.
    let rt = create_cgroup(0, CgroupControllers::MEMORY).expect("create RT");
    let rt_id = rt.id();
    rt.set_limit(CgroupLimits {
        memory_max: Some(4096 * PAGE),
        ..Default::default()
    })
    .expect("set RT.memory.max");
    let a = create_cgroup(rt_id, CgroupControllers::MEMORY).expect("create A");
    let a_id = a.id();
    a.set_limit(CgroupLimits {
        memory_max: Some(2048 * PAGE),
        ..Default::default()
    })
    .expect("set A.memory.max");
    let b = create_cgroup(rt_id, CgroupControllers::MEMORY).expect("create B");
    let b_id = b.id();
    b.set_limit(CgroupLimits {
        memory_max: Some(2048 * PAGE),
        ..Default::default()
    })
    .expect("set B.memory.max");

    // OLD-image FOUR-TERM footprint, each term a DISTINCT size so a swapped /
    // mis-keyed lane is detectable (an aliased equal-size set could hide a
    // partial over-unpin). These mirror the four production exec-replace
    // uncharge terms at syscall.rs:4562-4602.
    let data: u64 = 13 * PAGE; // Σ non-PROT_NONE mmap region lengths (try_charge_memory)
    let heap: u64 = 5 * PAGE; // page_align(brk) - page_align(brk_start) (try_charge_memory)
    let elf: u64 = 9 * PAGE; // mm.elf_charged_bytes — PT_LOAD segs + stack (try_charge_memory)
    let pt: u64 = 3 * PAGE; // mm.pt_charged_bytes — page-table-frame kmem (charge_memory_forced)
    let total: u64 = data + heap + elf + pt; // == compute_cgroup_charged_bytes(proc)

    // 1) BUILD the old image AT A, lane-by-lane through the PRODUCTION primitives:
    //    three HARD `try_charge_memory` legs (data/heap/elf) + one FORCED
    //    `charge_memory_forced` leg (pt). The origin pin AGGREGATES across all four
    //    onto A — exactly as a live process's four charge lanes pin its current
    //    cgroup. (This is the charge side of "charged to cgroup A".)
    try_charge_memory(a_id, data).expect("old-image mmap-data charge to A");
    try_charge_memory(a_id, heap).expect("old-image heap charge to A");
    try_charge_memory(a_id, elf).expect("old-image elf charge to A");
    charge_memory_forced(a_id, pt); // forced (soft) — pt frame count known post-map_to
    assert_eq!(
        pin(&a),
        total,
        "A pin AGGREGATES the old image's four lanes (charge origin)"
    );
    assert_eq!(mem(&a), total, "A display holds the whole old image");
    assert_eq!(
        mem(&rt),
        total,
        "RT (shared ancestor) display holds it via the chain"
    );
    assert_eq!(pin(&b), 0, "B not yet touched");
    assert_eq!(mem(&b), 0, "B display still 0");
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "building the old image (pure charges) never unpins — tripwire clean"
    );

    // 2) MIGRATE A -> B by the AGGREGATED compute lump (the SINGLE
    //    migrate_memory_charges(total, A, B) call the real sys_cgroup_attach /
    //    cgroupfs path makes — bytes == compute_cgroup_charged_bytes(proc) ==
    //    total here). This is "migrated to cgroup B before the exec uncharge".
    //
    //    migrate = try_charge_memory(B, total) + uncharge_memory(A, total). The
    //    SOURCE unpin sees pre-value EXACTLY `total` (A's entire pin == the whole
    //    old image == the migrated amount), so it telescopes to EXACTLY 0 with
    //    pre == n — the boundary case the co-residency test (pre == x + y > n)
    //    never reaches for a single process. The DEST pin gains exactly `total`.
    migrate_memory_charges(total, a_id, b_id).expect("migrate old image A -> B (whole footprint)");

    // THE RE-HOME ASSERTIONS — A drains to EXACTLY 0, B gains the whole image:
    assert_eq!(
        pin(&a),
        0,
        "A pin telescopes to EXACTLY 0 by the migrate source-unpin (pre == n)"
    );
    assert_eq!(
        pin(&b),
        total,
        "B pin == total: the old image's pin RE-HOMED to B"
    );
    assert_eq!(mem(&a), 0, "A display drained by the migrate");
    assert_eq!(mem(&b), total, "B display holds the re-homed old image");
    assert_eq!(
        mem(&rt),
        total,
        "RT (shared ancestor) net unchanged by the sibling A->B move"
    );
    // FLOOR-NEVER-FIRED on the SOURCE migrate: uncharge_memory(A, total) saw
    // pre-value total >= total, so unpin_origin_mem never clamped. A telescoping
    // to 0 here is a TRUE re-home, not a floored over-unpin of an aggregate that
    // happened to already be low.
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "migrate source-unpin (pre == n == total) does NOT trip the floor — true re-home"
    );

    // 3) EXEC IMAGE-REPLACE at B (the syscall.rs:4562-4602 path): the old image is
    //    uncharged as FOUR SEPARATE uncharge_memory calls keyed to
    //    `cgroup_id = proc.cgroup_id`, which the migration MOVED to B. Each leg
    //    unpins B; together they must drain B's pin to EXACTLY 0. Because the
    //    re-home in step 2 landed the FULL `total` on B, every one of the four
    //    unpins finds a LIVE pin to cancel (pre >= n at each step) — the floor
    //    never fires. THIS is the proof that "the exec uncharge at the CURRENT
    //    cgroup unpins B (not A) by exactly the migrated amount."
    uncharge_memory(b_id, data); // exec-replace mmap-data leg (syscall.rs:4570)
    uncharge_memory(b_id, heap); // exec-replace heap leg (syscall.rs:4580)
    uncharge_memory(b_id, elf); // exec-replace elf leg (syscall.rs:4588)
    uncharge_memory(b_id, pt); // exec-replace pt leg (syscall.rs:4601)

    // THE GAP ASSERTIONS — the destination is fully reconciled, the source stays 0:
    assert_eq!(
        pin(&b),
        0,
        "B pin telescopes to EXACTLY 0: exec-uncharge at B cancelled the re-homed image"
    );
    assert_eq!(
        pin(&a),
        0,
        "A pin STAYS 0: the exec-uncharge did NOT touch the original charge origin"
    );
    assert_eq!(
        mem(&b),
        0,
        "B display drained by the exec image-replace uncharge"
    );
    assert_eq!(mem(&a), 0, "A display still 0");
    assert_eq!(
        mem(&rt),
        0,
        "RT (shared ancestor) fully drained: the whole old image released"
    );
    // THE DISTINGUISHING PROOF — true re-home vs masked over-unpin at B:
    // if the migration had FAILED to re-home the pin to B (the hazard the gap
    // flags: the exec uncharge relying on a re-home that didn't happen), B's pin
    // would have been < total when the four exec-uncharges ran, the saturating
    // floor would have absorbed the shortfall, and THIS tripwire would be NONZERO.
    // It reads 0 ⇒ each B-unpin found a LIVE pin == its term ⇒ the re-home landed
    // on B. mem_pinned(B) == 0 ALONE could not distinguish this from a floored
    // over-unpin; the tripwire does.
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "M2-1 SLICE-2: every exec-uncharge leg at B found a LIVE re-homed pin == its term \
         (floor never fired) — the old image's pin TRULY re-homed A -> B, the exec uncharge \
         at the CURRENT cgroup unpins B by exactly the migrated amount, NOT A"
    );

    // 4) EXIT-AFTER-MIGRATE variant (process.rs:4318-4358) AND the ExecSpaceGuard
    //    ROLLBACK variant (syscall.rs:4247) share the identical property: a single
    //    aggregated uncharge at the post-migration cgroup. Re-run the round with a
    //    WHOLESALE single uncharge_memory(B, total) (the shape exit / guard-drop
    //    take after re-reading proc.cgroup_id) to prove the four-vs-one partition
    //    of the uncharge is irrelevant for a COUNTER (telescopes on Σ equality).
    try_charge_memory(a_id, data).expect("re-build: mmap-data to A");
    try_charge_memory(a_id, heap).expect("re-build: heap to A");
    try_charge_memory(a_id, elf).expect("re-build: elf to A");
    charge_memory_forced(a_id, pt);
    assert_eq!(pin(&a), total, "A re-pins the whole image");
    migrate_memory_charges(total, a_id, b_id).expect("re-migrate A -> B");
    assert_eq!(pin(&a), 0, "A drains to 0 on re-migrate (pre == n)");
    assert_eq!(pin(&b), total, "B holds the re-homed image again");
    // Exit / ExecSpaceGuard-rollback wholesale uncharge at the CURRENT (migrated) id:
    uncharge_memory(b_id, total);
    assert_eq!(
        pin(&b),
        0,
        "B telescopes to 0 on the wholesale exit/rollback uncharge at the migrated id"
    );
    assert_eq!(pin(&a), 0, "A untouched by the exit/rollback uncharge");
    assert_eq!(
        mem(&rt),
        0,
        "RT fully drained after the exit/rollback variant"
    );
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "exit/ExecSpaceGuard wholesale uncharge at the post-migration cgroup telescopes \
         exactly (pre == n == total, floor never fires) — same re-home property as exec-replace"
    );

    // Cleanup: children before parent (no tasks attached). Leave the shared
    // tripwire as we found it (0).
    let _ = delete_cgroup(a_id);
    let _ = delete_cgroup(b_id);
    let _ = delete_cgroup(rt_id);
    let _ = mem_unpin_underflow_take();
}

/// M2-1 SLICE-2 (ABNORMAL-CLONE-ABORT teardown GAP closure): in-kernel self-test
/// that the fork-charge-to-parent pin (fork.rs:240) telescopes to 0 when a
/// non-CLONE_VM clone child is aborted POST-charge-success via the ABNORMAL
/// teardown — `terminate_process(child) + cleanup_zombie(child)` — rather than the
/// ordinary process exit.
///
/// THE SEAM (verified by construction at the source):
/// `sys_clone` without CLONE_VM delegates the AS-creating charge to
/// `fork::sys_fork()`, which charges `fork_charge_bytes` to `parent_cgroup_id`
/// (fork.rs:240), pinning the PARENT-cgroup origin. fork_inner already joined the
/// cpuset and attached the cgroup, so the two POST-charge-success failure arms —
/// (1) LSM `hook_task_fork` denial (syscall.rs:3196-3205) and (2) namespace-
/// translation failure (syscall.rs:3216-3243) — deliberately abort the child with
/// `terminate_process(child_pid, …) + cleanup_zombie(child_pid)` (NOT
/// `cleanup_unscheduled_process`, whose callers ZERO `memory_space` to suppress
/// uncharge). `cleanup_zombie` reaps the Zombie through `free_process_resources`
/// (process.rs:4115), whose uncharge block (process.rs:4310) fires for an
/// independent-AS clone child because all three gate terms hold:
///   * `keep_address_space == false` — the COW-forked child has its OWN page-table
///     root; no other non-Terminated process shares its `memory_space`
///     (process.rs:4051-4066), so the share scan returns false.
///   * `mm_shared == false` — `fork_inner` gives the child an INDEPENDENT MmState
///     Arc (strong_count == 1; process.rs:4270).
///   * `memory_space != 0` — UNLIKE the `cleanup_unscheduled_process` error paths,
///     the `terminate_process`/`cleanup_zombie` path does NOT zero `memory_space`.
/// The four uncharge legs (process.rs:4318/4330/4336/4358) key to
/// `proc.cgroup_id`, and `child.cgroup_id == parent.cgroup_id == parent_cgroup_id`
/// (fork.rs:561). Because the child is NEVER scheduled before the abort
/// (the reserved scheduler admission is committed only on the success arm),
/// it can never migrate, so its uncharge origin is still EXACTLY the fork-charge
/// origin. The fork lump therefore telescopes to 0 — NO FA-09 strand, telescoping
/// NOT broken.
///
/// WHY THIS IS THE LOAD-BEARING CASE the rest of the suite does NOT cover:
/// `run_cgroup_pt_kmem_self_test` step 7 (cgroup.rs:3642-3652) is the ONLY existing
/// model of the fork-lump↔child-exit pair, and it drains the lump with a BARE
/// single `uncharge_memory(a_id, 6*PAGE)` comment-labeled "child last-exit" — the
/// shape of the NORMAL exit, NOT the ABNORMAL `terminate_process`/`cleanup_zombie`
/// teardown, and (being at the cgroup-primitive layer) it cannot construct a real
/// Process/clone fixture. So no test exercises the abnormal-abort SITE-PAIR
/// (fork.rs:240 pin ↔ `free_process_resources` unpin reached via
/// terminate_process/cleanup_zombie). Identically to the migration-while-pending
/// gap-fill, the property is closed BY CONSTRUCTION but UNPROVEN by a runtime
/// assertion — a latent pin!=compute divergence in this teardown window that would
/// surface under the SLICE-3 gate flip, which relies on `mem_pinned == 0` as the
/// witness. This test lands that gate-INDEPENDENT runtime witness.
///
/// MODEL: charge the inherited fork lump to PARENT cgroup A as the production
/// `fork::sys_fork()` does (`try_charge_memory(a_id, fork_charge_bytes)`), then
/// drain it via the EXACT multi-term uncharge shape `free_process_resources` runs
/// on the abnormal teardown — FOUR separate `uncharge_memory(a_id, ·)` legs
/// (mmap-data / heap / elf / pt), the same four-call partition as
/// process.rs:4318/4330/4336/4358 — keyed to the SAME origin (no migration: an
/// aborted, never-scheduled child cannot migrate). Assert pin(A) telescopes to
/// EXACTLY 0 AND the over-uncharge tripwire reads 0 IMMEDIATELY after the drain —
/// proving the four exit unpins found a LIVE pin == the fork lump (the floor never
/// fired), distinguishing a TRUE telescope from a masked over-unpin that
/// `mem_pinned == 0` alone cannot tell apart under saturating unpin.
pub fn run_cgroup_mem_pinned_clone_abort_self_test() {
    const PAGE: u64 = 0x1000;
    let mem = |n: &CgroupArc| n.stats.memory_current.load(Ordering::SeqCst);
    let pin = |n: &CgroupArc| n.stats.mem_pinned.load(Ordering::SeqCst);

    // Clear the shared tripwire so any over-uncharge surplus is attributable to
    // THIS test (read-and-cleared at each matched-sequence checkpoint below).
    let _ = mem_unpin_underflow_take();

    // Fresh, task-less MEMORY hierarchy under root:
    //   PARENT (P, generous memory.max) ⊃ CHILD-DIAG (CD) — CD is unused here but
    //   makes the parent a non-leaf, matching the realistic shape where the
    //   forking parent has descendants. P is the PARENT cgroup the fork charge
    //   keys to (== parent_cgroup_id == the aborted child's cgroup_id).
    let p = create_cgroup(0, CgroupControllers::MEMORY).expect("create P");
    let p_id = p.id();
    p.set_limit(CgroupLimits {
        memory_max: Some(4096 * PAGE),
        ..Default::default()
    })
    .expect("set P.memory.max");
    let cd = create_cgroup(p_id, CgroupControllers::MEMORY).expect("create CD");
    let cd_id = cd.id();
    cd.set_limit(CgroupLimits {
        memory_max: Some(2048 * PAGE),
        ..Default::default()
    })
    .expect("set CD.memory.max");

    // The inherited child footprint, by lane, each a DISTINCT size so a swapped /
    // mis-keyed exit-uncharge lane is detectable (an aliased equal-size set could
    // hide a partial over-unpin). These mirror the four terms `fork_charge_bytes`
    // aggregates (fork.rs:193-237) AND the four `free_process_resources` exit
    // uncharge legs (process.rs:4318/4330/4336/4358).
    let data: u64 = 11 * PAGE; // Σ non-PROT_NONE mmap regions (fork.rs:200-207 / process.rs:4312-4320)
    let heap: u64 = 7 * PAGE; // page_align(brk) - page_align(brk_start) (fork.rs:209-217 / process.rs:4322-4331)
    let elf: u64 = 4 * PAGE; // parent_mm.elf_charged_bytes (fork.rs:220 / process.rs:4334-4338)
    let pt: u64 = 2 * PAGE; // parent_mm.pt_charged_bytes (fork.rs:233 / process.rs:4356-4360)
                            // fork_charge_bytes is ONE aggregated lump (the single try_charge_memory call
                            // at fork.rs:240) — the amount-asymmetry seed: 1 charge add vs 4 exit subs.
    let fork_charge_bytes: u64 = data + heap + elf + pt;

    // 1) FORK CHARGE: `fork::sys_fork()` charges the inherited footprint as ONE
    //    aggregated lump to the PARENT cgroup (fork.rs:240). The child inherits the
    //    four MmState fields verbatim and `child.cgroup_id = parent.cgroup_id`
    //    (fork.rs:561), so the child's compute == fork_charge_bytes and its exit
    //    origin == this charge origin (P). The lump PINS P.
    try_charge_memory(p_id, fork_charge_bytes)
        .expect("fork: charge inherited child footprint to PARENT cgroup (fork.rs:240)");
    assert_eq!(
        pin(&p),
        fork_charge_bytes,
        "P pin == the fork lump (parent-cgroup origin)"
    );
    assert_eq!(mem(&p), fork_charge_bytes, "P display holds the fork lump");
    assert_eq!(
        pin(&cd),
        0,
        "sibling/descendant CD untouched by the fork charge (origin-keyed)"
    );
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "the fork charge (pure add) never unpins — tripwire clean"
    );

    // 2) ABNORMAL ABORT TEARDOWN: an LSM `hook_task_fork` denial
    //    (syscall.rs:3196-3205) or a namespace-translation failure
    //    (syscall.rs:3216-3243) aborts the never-scheduled child via
    //    `terminate_process(child) + cleanup_zombie(child)`. `cleanup_zombie` reaps
    //    through `free_process_resources` (process.rs:4115), whose uncharge gate
    //    FIRES (keep_address_space == false, mm_shared == false, memory_space != 0
    //    for an independent-AS, never-`cleanup_unscheduled_process`'d child). The
    //    four uncharge legs (process.rs:4318/4330/4336/4358) key to
    //    `proc.cgroup_id == P` (the never-scheduled child never migrated). Model
    //    the EXACT four-call partition the abnormal teardown runs.
    //
    //    THIS is the distinguishing coverage vs step 7 of the pt-kmem self-test:
    //    that drains the lump with ONE bare uncharge (normal-exit shape); HERE the
    //    drain is the FOUR-TERM `free_process_resources` shape the abnormal
    //    terminate_process/cleanup_zombie teardown actually hits, asserted with the
    //    tripwire read IMMEDIATELY after — so a future regression that mis-keys or
    //    over-unpins ANY exit leg on the abnormal path fails HERE, not silently at
    //    the SLICE-3 gate flip.
    uncharge_memory(p_id, data); // free_process_resources mmap-data leg (process.rs:4318)
    uncharge_memory(p_id, heap); // free_process_resources heap leg (process.rs:4330)
    uncharge_memory(p_id, elf); // free_process_resources elf leg (process.rs:4336)
    uncharge_memory(p_id, pt); // free_process_resources pt leg (process.rs:4358)

    // THE GAP ASSERTIONS — the fork lump telescopes to EXACTLY 0 at the parent
    // origin via the ABNORMAL four-term teardown drain:
    assert_eq!(
        pin(&p),
        0,
        "P pin telescopes to EXACTLY 0: the fork lump (1 add) is cancelled by the abnormal \
         four-term terminate_process/cleanup_zombie teardown drain (4 subs) at the SAME origin \
         — amount-asymmetry harmless for a COUNTER (Σadd == Σsub)"
    );
    assert_eq!(
        mem(&p),
        0,
        "P display drained by the abnormal teardown uncharge"
    );
    // THE DISTINGUISHING PROOF — true telescope vs masked over-unpin:
    // if ANY exit leg had mis-keyed (e.g. uncharged a cgroup the child had NOT
    // charged, the FA-09 cross-origin hazard) or the lump had been under-pinned,
    // some unpin would have found pre-value < its term, the saturating floor would
    // have absorbed the shortfall, and THIS tripwire would be NONZERO. It reads 0
    // ⇒ each leg found a LIVE pin == its term ⇒ the abnormal teardown unpinned the
    // SAME live fork-lump pin. mem_pinned(P) == 0 ALONE could not distinguish this
    // from a floored over-unpin; the tripwire does. This is the gate-INDEPENDENT
    // witness the SLICE-3 flip requires for the abnormal-clone-abort window.
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "M2-1 SLICE-2: every abnormal-teardown exit leg found a LIVE fork-lump pin == its term \
         (floor never fired) — the fork-charge-to-parent pin telescopes to 0 across the \
         terminate_process/cleanup_zombie teardown, NO FA-09 strand"
    );

    // 3) WHOLESALE-DRAIN VARIANT: the four-vs-one partition of the exit uncharge is
    //    irrelevant for a COUNTER. Re-run with the lump charged then drained by a
    //    SINGLE aggregated uncharge (the degenerate shape an empty-mmap child with
    //    only a heap/elf footprint would collapse to), proving telescoping on Σ
    //    equality regardless of leg count.
    try_charge_memory(p_id, fork_charge_bytes).expect("re-charge fork lump to P");
    assert_eq!(pin(&p), fork_charge_bytes, "P re-pins the whole fork lump");
    uncharge_memory(p_id, fork_charge_bytes); // wholesale abnormal-teardown drain
    assert_eq!(
        pin(&p),
        0,
        "P telescopes to 0 on the wholesale abnormal-teardown drain (pre == n)"
    );
    assert_eq!(
        mem(&p),
        0,
        "P display fully drained by the wholesale variant"
    );
    assert_eq!(
        mem_unpin_underflow_take(),
        0,
        "wholesale abnormal-teardown drain (pre == n == fork_charge_bytes) telescopes exactly — \
         floor never fires; the 4-vs-1 uncharge partition is irrelevant for a COUNTER"
    );

    // Cleanup: children before parent (no tasks attached). Leave the shared
    // tripwire as we found it (0).
    let _ = delete_cgroup(cd_id);
    let _ = delete_cgroup(p_id);
    let _ = mem_unpin_underflow_take();
}

// ============================================================================
// J2-10: VFS Directory-Enumeration Budget (vfs_dir.max, MEMORY controller)
// ============================================================================

/// Minimum bytes a single directory-enumeration syscall is granted even when the
/// cgroup's `vfs_dir.max` headroom is below it, so enumeration always makes
/// forward progress (never a false end-of-directory). The resulting over-count
/// is bounded by (concurrent getdents in the cgroup) × this value — safe, since
/// over-count restricts further, it never bypasses (Safety > Efficiency).
pub const MIN_VFS_DIR_BUDGET: usize = 4096;

/// RAII budget for ONE directory-enumeration syscall (`getdents64`). Charges
/// `vfs_dir_current` on the target cgroup + every MEMORY-controller ancestor at
/// construction, and uncharges the SAME held `Arc<CgroupNode>` set on drop —
/// NEVER re-resolving the registry. Because the held Arcs keep each charged node
/// alive past `delete_cgroup` (which only removes the node from the registry and
/// its parent's child list — the object survives while an Arc exists, see
/// `migrate_memory_charges`), the uncharge-set == charge-set BY CONSTRUCTION:
/// migration- AND deletion-safe with no transfer needed (J2-10 mustFix A). The
/// cap is HARD (per-node CAS reservation, not a read-then-add soft cap, so
/// concurrent chargers cannot overshoot `vfs_dir.max`); it still degrades
/// gracefully by GRANTING the largest amount that fits (a getdents64 short read)
/// instead of failing the syscall. The only bounded over-count is a small
/// progress `floor` granted when the cgroup is already at its cap, so enumeration
/// never deadlocks — over-count restricts further, it never bypasses.
///
/// SCOPE: this bounds the per-tenant ACCUMULATED getdents64 kernel buffer (the
/// `entries` Vec + per-entry serialization, held across the syscall) — the
/// dominant, sustained, tenant-controllable allocation. A backend's TRANSIENT
/// per-`readdir(offset)` internal scratch (e.g. procfs rebuilding a PID listing)
/// is freed each call, is pre-existing, and is a separate cross-filesystem
/// concern not addressed here.
#[must_use = "the guard must outlive the directory enumeration it bounds"]
pub struct VfsDirBudgetGuard {
    chain: CgroupArcChain,
    bytes: u64,
    granted: usize,
}

impl VfsDirBudgetGuard {
    /// Charge up to `want` bytes, clamped to the tightest `vfs_dir.max` headroom
    /// in the chain but never below `min(MIN_VFS_DIR_BUDGET, want)` (bounded
    /// over-count for forward progress) and never above `want`. Root cgroup
    /// (id 0) is EXEMPT: no charge, full `want` granted. MUST be called with NO
    /// Process lock held — it acquires CGROUP_REGISTRY (Level 5).
    pub fn charge(cgroup_id: CgroupId, want: usize) -> Self {
        if cgroup_id == 0 || want == 0 {
            return Self {
                chain: CgroupArcChain::empty(),
                bytes: 0,
                granted: want,
            };
        }
        let Some(origin) = lookup_cgroup(cgroup_id) else {
            return Self {
                chain: CgroupArcChain::empty(),
                bytes: 0,
                granted: want,
            };
        };
        let chain = match collect_controller_chain(&origin, CgroupControllers::MEMORY) {
            Ok(chain) => chain,
            Err(_) => {
                return Self {
                    chain: CgroupArcChain::empty(),
                    bytes: 0,
                    granted: 0,
                }
            }
        };
        if chain.len == 0 {
            return Self {
                chain,
                bytes: 0,
                granted: want,
            };
        }
        let want_u = want as u64;
        let floor = (MIN_VFS_DIR_BUDGET as u64).min(want_u);
        // Snapshot each node's vfs_dir.max once (None = unlimited).
        let mut caps = [None; CGROUP_CHAIN_CAPACITY];
        for index in 0..chain.len {
            let Some(node) = chain.get(index) else {
                return Self {
                    chain,
                    bytes: 0,
                    granted: 0,
                };
            };
            caps[index] = node.limits.lock().vfs_dir_max;
        }

        // HARD reservation (NOT a soft read-then-add): grant the largest amount in
        // [floor, want] that fits EVERY node's vfs_dir.max right now, charged
        // atomically per node via CAS so concurrent chargers cannot all observe the
        // same headroom and overshoot (that would make the cap advisory, defeating
        // the memory bound). On a per-node CAS rejection (a concurrent charger
        // shrank the headroom between read and commit) roll back and retry a bounded
        // number of times. Fallback: when not even `floor` fits, force `floor` so
        // enumeration still makes forward progress — a BOUNDED over-count (≤ floor
        // per concurrent call) that restricts further, never bypasses.
        for _attempt in 0..4 {
            let mut headroom: u64 = u64::MAX;
            for (index, node) in chain.iter().enumerate() {
                if let Some(max) = caps[index] {
                    let cur = node.stats.vfs_dir_current.load(Ordering::Acquire);
                    headroom = headroom.min(max.saturating_sub(cur));
                }
            }
            if headroom < floor {
                for node in chain.iter() {
                    node.stats
                        .vfs_dir_current
                        .fetch_add(floor, Ordering::SeqCst); // lint-fetch-add: allow (statistics counter)
                }
                return Self {
                    chain,
                    bytes: floor,
                    granted: floor as usize,
                };
            }
            let grant = want_u.min(headroom); // in [floor, want]
            let mut charged_len = 0usize;
            let mut committed = true;
            for (index, node) in chain.iter().enumerate() {
                let max = caps[index];
                let res = node.stats.vfs_dir_current.fetch_update(
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                    |cur| {
                        let new = cur.saturating_add(grant);
                        if let Some(m) = max {
                            if new > m {
                                return None; // would exceed vfs_dir.max
                            }
                        }
                        Some(new)
                    },
                );
                if res.is_ok() {
                    charged_len += 1;
                } else {
                    committed = false;
                    break;
                }
            }
            if committed {
                return Self {
                    chain,
                    bytes: grant,
                    granted: grant as usize,
                };
            }
            // Roll back the partial reservation (saturating) and retry.
            for rollback in 0..charged_len {
                if let Some(node) = chain.get(rollback) {
                    let _ = node.stats.vfs_dir_current.fetch_update(
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                        |c| Some(c.saturating_sub(grant)),
                    );
                }
            }
        }
        // Retries exhausted under pathological contention. One FINAL attempt to
        // reserve exactly `floor` honoring the cap (CAS) — so the forced path
        // below is taken ONLY when not even `floor` fits, matching the design.
        let mut charged_len = 0usize;
        let mut committed = true;
        for (index, node) in chain.iter().enumerate() {
            let max = caps[index];
            let res = node.stats.vfs_dir_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |cur| {
                    let new = cur.saturating_add(floor);
                    if let Some(m) = max {
                        if new > m {
                            return None;
                        }
                    }
                    Some(new)
                },
            );
            if res.is_ok() {
                charged_len += 1;
            } else {
                committed = false;
                break;
            }
        }
        if committed {
            return Self {
                chain,
                bytes: floor,
                granted: floor as usize,
            };
        }
        for rollback in 0..charged_len {
            if let Some(node) = chain.get(rollback) {
                let _ = node.stats.vfs_dir_current.fetch_update(
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                    |c| Some(c.saturating_sub(floor)),
                );
            }
        }
        // Even `floor` does not fit under the cap → force it (bounded over-count
        // ≤ floor per concurrent call) so enumeration still makes forward progress.
        for node in chain.iter() {
            node.stats
                .vfs_dir_current
                .fetch_add(floor, Ordering::SeqCst); // lint-fetch-add: allow (statistics counter)
        }
        Self {
            chain,
            bytes: floor,
            granted: floor as usize,
        }
    }

    /// The byte budget granted to the caller (use as the readdir allocation cap).
    #[inline]
    pub fn granted(&self) -> usize {
        self.granted
    }

    /// Idempotently uncharge the held chain (saturating). Safe to call repeatedly
    /// — a second call (or Drop after an explicit release) uncharges nothing.
    pub fn release(&mut self) {
        if self.bytes == 0 {
            return;
        }
        let bytes = self.bytes;
        self.bytes = 0;
        for node in self.chain.iter() {
            let _ = node.stats.vfs_dir_current.fetch_update(
                Ordering::SeqCst,
                Ordering::Relaxed,
                |cur| Some(cur.saturating_sub(bytes)),
            );
        }
    }
}

impl Drop for VfsDirBudgetGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// In-kernel assertions for the per-cgroup VFS dir-enumeration budget. Panics on
/// failure; detected by `make test` / `make boot-check` via the serial log.
///
/// Covers: cap clamping (granted reduced to headroom, short read), ancestor
/// propagation, the headline DELETION-SAFETY property (charge under a leaf, then
/// delete the leaf, then drop the guard → the ancestor counter still returns to
/// 0 because the guard uncharges the held Arcs, not a re-resolved id), root
/// id==0 exemption, and release idempotency.
pub fn run_cgroup_vfs_dir_budget_self_test() {
    let vdir = |n: &CgroupArc| n.stats.vfs_dir_current.load(Ordering::SeqCst);

    // P(vfs_dir_max=10000) ⊃ A(vfs_dir_max unlimited): fresh, task-less.
    let p = create_cgroup(0, CgroupControllers::MEMORY).expect("create P");
    let p_id = p.id();
    p.set_limit(CgroupLimits {
        vfs_dir_max: Some(10_000),
        ..Default::default()
    })
    .expect("set P.vfs_dir_max");
    let a = create_cgroup(p_id, CgroupControllers::MEMORY).expect("create A");
    let a_id = a.id();

    // 1) Charge 3000 under A: A and ancestor P both reflect it; granted == want.
    {
        let g = VfsDirBudgetGuard::charge(a_id, 3000);
        assert_eq!(g.granted(), 3000, "full grant within headroom");
        assert_eq!(vdir(&a), 3000, "A vfs_dir_current");
        assert_eq!(vdir(&p), 3000, "P (ancestor) vfs_dir_current");
    } // guard drops → uncharge
    assert_eq!(vdir(&a), 0, "A uncharged on drop");
    assert_eq!(vdir(&p), 0, "P uncharged on drop");

    // 2) Cap clamping: want 50000 but P.headroom is 10000 → granted 10000 (short read).
    {
        let g = VfsDirBudgetGuard::charge(a_id, 50_000);
        assert_eq!(g.granted(), 10_000, "granted clamped to P's headroom");
        assert_eq!(vdir(&p), 10_000, "P at cap");
    }
    assert_eq!(vdir(&p), 0, "P back to 0 after clamped guard drop");

    // 3) DELETION SAFETY: charge under A, delete A, then drop the guard — the
    //    ancestor P counter MUST still return to 0 (guard uncharges held Arcs).
    {
        let g = VfsDirBudgetGuard::charge(a_id, 2000);
        assert_eq!(vdir(&p), 2000, "P charged via A");
        // Delete A out from under the live guard (no tasks/children on A).
        let _ = delete_cgroup(a_id);
        assert!(lookup_cgroup(a_id).is_none(), "A removed from registry");
        // g drops here → uncharges the HELD [A_arc, P_arc], not lookup(a_id).
    }
    assert_eq!(
        vdir(&p),
        0,
        "P uncharged despite A deletion (Arc-pinned uncharge)"
    );

    // 4) Root id==0 exemption: no charge, full grant.
    {
        let root = lookup_cgroup(0).expect("root");
        let before = root.stats.vfs_dir_current.load(Ordering::SeqCst);
        let g = VfsDirBudgetGuard::charge(0, 1234);
        assert_eq!(g.granted(), 1234, "root grants full want");
        assert_eq!(
            root.stats.vfs_dir_current.load(Ordering::SeqCst),
            before,
            "root id=0 not charged"
        );
    }

    // 5) Release idempotency: explicit release then Drop uncharges only once.
    {
        let mut g = VfsDirBudgetGuard::charge(p_id, 1000);
        assert_eq!(vdir(&p), 1000);
        g.release();
        assert_eq!(vdir(&p), 0, "released");
        g.release(); // no-op
        assert_eq!(vdir(&p), 0, "double release is a no-op");
    } // Drop after release → also a no-op
    assert_eq!(vdir(&p), 0, "no underflow after release+drop");

    let _ = delete_cgroup(p_id);
}

// ============================================================================
// Test Helpers
// ============================================================================

/// RF180-45 executable probe for exact physical Arc lifetime and detached
/// cgroup metadata publication.
pub fn run_cgroup_exact_lifetime_self_test() {
    init();
    let root = root_cgroup();
    let parent = CgroupNode::new_child(&root, CgroupControllers::PIDS)
        .expect("RF180-45 lifetime-test parent");

    // Prime registry growth before taking exact heap snapshots. Parent-child
    // backing is reclaimed when the primer is deleted, while the nonempty
    // global registry intentionally retains its bounded high-water backing.
    let primer = CgroupNode::new_child(&parent, CgroupControllers::PIDS)
        .expect("RF180-45 lifetime-test primer");
    let primer_id = primer.id();
    delete_cgroup(primer_id).expect("RF180-45 delete lifetime-test primer");
    drop(primer);

    let outer_bytes =
        arc_charge_bytes::<CgroupNode>().expect("RF180-45 cgroup Arc charge must be representable");
    let lifetime_before = mm::heap_class_snapshot(HeapClass::Cgroup);
    let slots_before = active_cgroup_arc_slots();
    let lifetime_child = CgroupNode::new_child_with_fault(
        &parent,
        CgroupControllers::PIDS,
        CgroupCreateFault {
            check_prepare_unlocked: true,
            check_deallocate_unlocked: true,
            ..CgroupCreateFault::default()
        },
    )
    .expect("RF180-45 lifetime-test child");
    let lifetime_id = lifetime_child.id();
    let lifetime_weak: CgroupWeak = Arc::downgrade(&lifetime_child);
    delete_cgroup(lifetime_id).expect("RF180-45 unregister lifetime-test child");
    drop(lifetime_child);
    assert!(lifetime_weak.upgrade().is_none());
    assert_eq!(active_cgroup_arc_slots(), slots_before + 1);
    let after_strong = mm::heap_class_snapshot(HeapClass::Cgroup);
    assert_eq!(after_strong.reserved_bytes, lifetime_before.reserved_bytes);
    assert_eq!(
        after_strong.committed_bytes,
        lifetime_before
            .committed_bytes
            .checked_add(outer_bytes)
            .expect("RF180-45 lifetime snapshot arithmetic"),
        "RF180-45 final Weak must retain exactly the outer Arc charge"
    );
    drop(lifetime_weak);
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::Cgroup),
        lifetime_before,
        "RF180-45 ArcInner must deallocate before admission release"
    );
    assert_eq!(active_cgroup_arc_slots(), slots_before);

    // Forced Arc allocation failure must drop the payload Weak, release its
    // generation slot exactly once, and leave both hierarchy publications and
    // heap accounting untouched.
    let arc_failure_before = mm::heap_class_snapshot(HeapClass::Cgroup);
    let arc_failure_slots = active_cgroup_arc_slots();
    let arc_failure_count = cgroup_count();
    assert!(matches!(
        CgroupNode::new_child_with_fault(
            &parent,
            CgroupControllers::PIDS,
            CgroupCreateFault {
                fail_arc_allocation: true,
                ..CgroupCreateFault::default()
            },
        ),
        Err(CgroupError::OutOfMemory)
    ));
    assert_eq!(parent.children().expect("RF180-45 child snapshot").len(), 0);
    assert_eq!(cgroup_count(), arc_failure_count);
    assert_eq!(active_cgroup_arc_slots(), arc_failure_slots);
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::Cgroup),
        arc_failure_before
    );

    // Force the nonempty registry to exact live capacity so the next creation
    // must execute its detached registry-prepare path. The old backing is
    // retired only after the registry writer is released.
    let exact_registry_len = cgroup_count();
    let exact_registry =
        PreparedAdmittedMapCapacity::try_new(HeapClass::Cgroup, exact_registry_len)
            .expect("RF180-45 exact registry backing");
    let retired_registry = {
        let mut registry = CGROUP_REGISTRY.write();
        registry
            .install_prepared_deferred(exact_registry)
            .expect("RF180-45 install exact registry backing")
    };
    drop(retired_registry);
    assert_eq!(CGROUP_REGISTRY.read().capacity(), exact_registry_len);

    let registry_failure_before = mm::heap_class_snapshot(HeapClass::Cgroup);
    let registry_failure_slots = active_cgroup_arc_slots();
    assert!(matches!(
        CgroupNode::new_child_with_fault(
            &parent,
            CgroupControllers::PIDS,
            CgroupCreateFault {
                fail_registry_prepare: true,
                check_prepare_unlocked: true,
                check_deallocate_unlocked: true,
                ..CgroupCreateFault::default()
            },
        ),
        Err(CgroupError::OutOfMemory)
    ));
    assert_eq!(active_cgroup_arc_slots(), registry_failure_slots);
    assert_eq!(cgroup_count(), exact_registry_len);
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::Cgroup),
        registry_failure_before
    );

    // The registry candidate succeeds, then child backing preparation fails.
    // Both the unused detached registry allocation and the node Arc telescope.
    let children_failure_before = mm::heap_class_snapshot(HeapClass::Cgroup);
    let children_failure_slots = active_cgroup_arc_slots();
    assert!(matches!(
        CgroupNode::new_child_with_fault(
            &parent,
            CgroupControllers::PIDS,
            CgroupCreateFault {
                fail_children_prepare: true,
                check_prepare_unlocked: true,
                check_deallocate_unlocked: true,
                ..CgroupCreateFault::default()
            },
        ),
        Err(CgroupError::OutOfMemory)
    ));
    assert_eq!(active_cgroup_arc_slots(), children_failure_slots);
    assert_eq!(cgroup_count(), exact_registry_len);
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::Cgroup),
        children_failure_before
    );

    // Fail after parent membership publication. Both prepared backings are
    // restored exactly and the detached node is destroyed only after locks.
    let rollback_before = mm::heap_class_snapshot(HeapClass::Cgroup);
    let rollback_slots = active_cgroup_arc_slots();
    let rollback_count = cgroup_count();
    assert!(matches!(
        CgroupNode::new_child_with_fault(
            &parent,
            CgroupControllers::PIDS,
            CgroupCreateFault {
                fail_after_children_insert: true,
                check_prepare_unlocked: true,
                check_deallocate_unlocked: true,
                ..CgroupCreateFault::default()
            },
        ),
        Err(CgroupError::OutOfMemory)
    ));
    assert_eq!(
        parent.children().expect("RF180-45 rollback snapshot").len(),
        0
    );
    assert_eq!(cgroup_count(), rollback_count);
    assert_eq!(active_cgroup_arc_slots(), rollback_slots);
    assert_eq!(mm::heap_class_snapshot(HeapClass::Cgroup), rollback_before);

    // Cross the former MAX_CGROUPS task-set clamp with real production attach /
    // detach entry points and valid process-domain IDs. Growth must reach 4097,
    // every hierarchical counter must move exactly, and the final empty backing
    // must retire outside the task-set lock.
    const TASK_BOUNDARY_COUNT: usize = MAX_CGROUPS + 1;
    const TASK_BOUNDARY_FIRST: TaskId =
        crate::process::PID_MAX as TaskId - TASK_BOUNDARY_COUNT as TaskId + 1;
    let membership_before = mm::heap_class_snapshot(HeapClass::Cgroup);
    let parent_pids_before = parent.stats.pids_current.load(Ordering::SeqCst);
    let root_pids_before = root.stats.pids_current.load(Ordering::SeqCst);
    for offset in 0..TASK_BOUNDARY_COUNT {
        parent
            .attach_task(TASK_BOUNDARY_FIRST + offset as TaskId)
            .expect("RF180-45 boundary attach task membership");
    }
    assert_eq!(parent.task_count(), TASK_BOUNDARY_COUNT);
    assert_eq!(
        parent.stats.pids_current.load(Ordering::SeqCst),
        parent_pids_before + TASK_BOUNDARY_COUNT as u64
    );
    assert_eq!(
        root.stats.pids_current.load(Ordering::SeqCst),
        root_pids_before + TASK_BOUNDARY_COUNT as u64
    );
    for offset in 0..TASK_BOUNDARY_COUNT {
        parent
            .detach_task(TASK_BOUNDARY_FIRST + offset as TaskId)
            .expect("RF180-45 boundary detach task membership");
    }
    assert_eq!(parent.task_count(), 0);
    assert_eq!(
        parent.stats.pids_current.load(Ordering::SeqCst),
        parent_pids_before
    );
    assert_eq!(
        root.stats.pids_current.load(Ordering::SeqCst),
        root_pids_before
    );
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::Cgroup),
        membership_before,
        "RF180-45 task-set backing must retire outside its lock"
    );

    // A deeper target-exclusive ancestor rejects after the target leaf has
    // already reserved +1. The reservation must roll back before any source
    // membership/counter mutation, and freeze contention is retryable Busy.
    let migration_source =
        CgroupNode::new_child(&parent, CgroupControllers::PIDS).expect("RF180-45 migration source");
    let migration_branch =
        CgroupNode::new_child(&parent, CgroupControllers::PIDS).expect("RF180-45 migration branch");
    let migration_target = CgroupNode::new_child(&migration_branch, CgroupControllers::PIDS)
        .expect("RF180-45 migration target");
    let migration_task: TaskId = 0x4501;
    migration_source
        .attach_task(migration_task)
        .expect("RF180-45 migration source attach");
    assert_eq!(
        migrate_task(migration_task, migration_source.id(), migration_source.id()),
        Ok(()),
        "RF180-45 same-endpoint migration is a membership-preserving no-op"
    );
    migration_source
        .membership_frozen
        .store(true, Ordering::Release);
    let lifecycle_task: TaskId = 0x4505;
    migration_source
        .attach_task(lifecycle_task)
        .expect("RF180-45 endpoint attach must serialize during migration pin");
    migration_source
        .detach_task(lifecycle_task)
        .expect("RF180-45 endpoint detach must not strand exit membership");
    assert_eq!(
        migrate_task(migration_task, migration_source.id(), migration_target.id()),
        Err(CgroupError::Busy)
    );
    migration_source
        .membership_frozen
        .store(false, Ordering::Release);
    migration_branch
        .set_limit(CgroupLimits {
            pids_max: Some(0),
            ..CgroupLimits::default()
        })
        .expect("RF180-45 rejecting branch limit");
    let migration_before = mm::heap_class_snapshot(HeapClass::Cgroup);
    let parent_migration_pids = parent.stats.pids_current.load(Ordering::SeqCst);
    let root_migration_pids = root.stats.pids_current.load(Ordering::SeqCst);
    assert_eq!(
        migrate_task(migration_task, migration_source.id(), migration_target.id()),
        Err(CgroupError::PidsLimitExceeded)
    );
    assert!(migration_source.has_task(migration_task));
    assert!(!migration_target.has_task(migration_task));
    assert_eq!(
        migration_source.stats.pids_current.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        migration_target.stats.pids_current.load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        migration_branch.stats.pids_current.load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        parent.stats.pids_current.load(Ordering::SeqCst),
        parent_migration_pids
    );
    assert_eq!(
        root.stats.pids_current.load(Ordering::SeqCst),
        root_migration_pids
    );
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::Cgroup),
        migration_before,
        "RF180-45 precommit migration rejection must telescope exactly"
    );
    migration_source
        .detach_task(migration_task)
        .expect("RF180-45 failed-migration cleanup detach");
    let migration_source_id = migration_source.id();
    let migration_branch_id = migration_branch.id();
    let migration_target_id = migration_target.id();
    delete_cgroup(migration_target_id).expect("RF180-45 delete migration target");
    delete_cgroup(migration_branch_id).expect("RF180-45 delete migration branch");
    delete_cgroup(migration_source_id).expect("RF180-45 delete migration source");
    drop(migration_target);
    drop(migration_branch);
    drop(migration_source);

    // At a full common ancestor, the migration must never publish temporary
    // headroom. A deterministic sibling attach uses existing spare backing, so
    // the probe itself is allocation-free while endpoint task locks are held.
    let delta_source = CgroupNode::new_child(&parent, CgroupControllers::PIDS)
        .expect("RF180-45 delta migration source");
    let delta_target = CgroupNode::new_child(&parent, CgroupControllers::PIDS)
        .expect("RF180-45 delta migration target");
    let delta_sibling = CgroupNode::new_child(&parent, CgroupControllers::PIDS)
        .expect("RF180-45 delta migration sibling");
    let delta_task: TaskId = 0x4502;
    let sibling_primer: TaskId = 0x4503;
    let sibling_probe_task: TaskId = 0x4504;
    delta_source
        .attach_task(delta_task)
        .expect("RF180-45 delta source attach");
    delta_sibling
        .attach_task(sibling_primer)
        .expect("RF180-45 sibling primer attach");
    parent
        .set_limit(CgroupLimits {
            pids_max: Some(2),
            ..CgroupLimits::default()
        })
        .expect("RF180-45 common ancestor pids limit");
    let delta_heap_before = mm::heap_class_snapshot(HeapClass::Cgroup);
    let delta_parent_before = parent.stats.pids_current.load(Ordering::SeqCst);
    let delta_root_before = root.stats.pids_current.load(Ordering::SeqCst);
    let sibling_probe = CgroupMigrationProbe {
        sibling: &delta_sibling,
        task: sibling_probe_task,
    };
    migrate_task_impl(
        delta_task,
        delta_source.id(),
        delta_target.id(),
        Some(&sibling_probe),
    )
    .expect("RF180-45 common-ancestor delta migration");
    assert!(!delta_source.has_task(delta_task));
    assert!(delta_target.has_task(delta_task));
    assert!(!delta_sibling.has_task(sibling_probe_task));
    assert_eq!(delta_source.stats.pids_current.load(Ordering::SeqCst), 0);
    assert_eq!(delta_target.stats.pids_current.load(Ordering::SeqCst), 1);
    assert_eq!(delta_sibling.stats.pids_current.load(Ordering::SeqCst), 1);
    assert_eq!(
        parent.stats.pids_current.load(Ordering::SeqCst),
        delta_parent_before,
        "RF180-45 common ancestor must remain unchanged across migration"
    );
    assert_eq!(
        root.stats.pids_current.load(Ordering::SeqCst),
        delta_root_before
    );
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::Cgroup),
        delta_heap_before,
        "RF180-45 source/target task backing transfer must telescope"
    );
    delta_target
        .detach_task(delta_task)
        .expect("RF180-45 delta target cleanup detach");
    delta_sibling
        .detach_task(sibling_primer)
        .expect("RF180-45 sibling primer cleanup detach");
    let delta_source_id = delta_source.id();
    let delta_target_id = delta_target.id();
    let delta_sibling_id = delta_sibling.id();
    delete_cgroup(delta_source_id).expect("RF180-45 delete delta source");
    delete_cgroup(delta_target_id).expect("RF180-45 delete delta target");
    delete_cgroup(delta_sibling_id).expect("RF180-45 delete delta sibling");
    drop(delta_source);
    drop(delta_target);
    drop(delta_sibling);

    // Deterministically interleave a complete sibling creation between
    // detached preparation and publication. The outer creator must revalidate
    // both live capacities and publish without losing either child.
    let interleave_count = cgroup_count();
    let interleaved = CgroupNode::new_child_with_fault(
        &parent,
        CgroupControllers::PIDS,
        CgroupCreateFault {
            interleave_sibling_once: true,
            check_prepare_unlocked: true,
            check_deallocate_unlocked: true,
            ..CgroupCreateFault::default()
        },
    )
    .expect("RF180-45 interleaved child creation");
    let interleaved_id = interleaved.id();
    let children = parent
        .children()
        .expect("RF180-45 interleaved child snapshot");
    assert!(
        children.len() > 1,
        "RF180-45 interleave must stale the first prepared capacity"
    );
    assert_eq!(cgroup_count(), interleave_count + children.len());
    for child_id in children.iter().copied() {
        delete_cgroup(child_id).expect("RF180-45 delete interleaved child");
    }
    drop(children);
    drop(interleaved);
    assert!(lookup_cgroup(interleaved_id).is_none());
    assert_eq!(parent.children().expect("RF180-45 final snapshot").len(), 0);

    let parent_id = parent.id();
    delete_cgroup(parent_id).expect("RF180-45 delete lifetime-test parent");
    drop(parent);
    drop(root);
}

/// Returns true if the cgroup subsystem is initialized.
#[cfg(test)]
pub fn test_is_initialized() -> bool {
    CGROUP_REGISTRY.read().contains_key(&0)
}
