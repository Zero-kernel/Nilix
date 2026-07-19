//! PID Namespace Support
//!
//! Implements Linux-compatible PID namespaces for process isolation.
//!
//! # Overview
//!
//! PID namespaces provide isolated PID number spaces. Each namespace has:
//! - Its own PID numbering starting from 1
//! - A hierarchical relationship with parent namespaces
//! - An "init" process (PID 1) that owns the namespace
//!
//! # Linux Compatibility
//!
//! - Processes have a PID in each ancestor namespace (root has global PID)
//! - Parent namespaces can see child namespace processes (with parent's PID)
//! - Child namespaces cannot see parent namespace processes
//! - When namespace init (PID 1) dies, all processes in namespace are killed
//!
//! # Usage
//!
//! ```rust,ignore
//! // Create a new child namespace
//! let child_ns = PidNamespace::new_child(parent_ns);
//!
//! // Allocate PID chain for a new process
//! let chain = assign_pid_chain(child_ns, global_pid)?;
//!
//! // Translate PID between namespaces
//! let ns_pid = pid_in_namespace(&ns, global_pid);
//! let global = resolve_pid_in_namespace(&ns, ns_pid);
//! ```

use alloc::alloc::{AllocError, Allocator, Global};
use alloc::sync::{Arc, Weak};
use cap::NamespaceId;
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use mm::{
    arc_charge_bytes, try_reserve_heap, AdmittedMap, AdmittedVec, HeapCharge, HeapClass,
    PreparedAdmittedMapCapacity, PreparedAdmittedVecCapacity, RetiredAdmittedMapCapacity,
    RetiredAdmittedVecCapacity,
};
use spin::Mutex;

use crate::process::{ProcessId, MAX_PID};

// ============================================================================
// Constants
// ============================================================================

/// Maximum PID namespace nesting depth (Linux default is 32)
pub const MAX_PID_NS_LEVEL: u8 = 32;
const PID_PATH_SLOTS: usize = MAX_PID_NS_LEVEL as usize + 1;

/// R76-2 FIX: Maximum number of PID namespaces allowed system-wide (including root).
/// Prevents DoS via namespace exhaustion. Value chosen to allow reasonable containerization
/// while preventing memory exhaustion attacks.
pub const MAX_PID_NS_COUNT: u32 = 1024;

/// R76-2 FIX: Current PID namespace count (root starts at 1).
/// Atomic counter to enforce MAX_PID_NS_COUNT limit.
static PID_NS_COUNT: AtomicU32 = AtomicU32::new(1);

/// RF180-43: a child namespace owns exactly one live-count permit. The permit
/// is moved into the payload before Arc allocation, so every failure path and
/// normal payload destruction decrements the quota exactly once.
#[derive(Debug)]
struct PidNamespaceCountPermit;

impl PidNamespaceCountPermit {
    fn try_acquire() -> Result<Self, PidNamespaceError> {
        let mut current = PID_NS_COUNT.load(Ordering::SeqCst);
        loop {
            if current >= MAX_PID_NS_COUNT {
                return Err(PidNamespaceError::MaxNamespaces);
            }
            match PID_NS_COUNT.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(Self),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for PidNamespaceCountPermit {
    fn drop(&mut self) {
        let previous = PID_NS_COUNT.fetch_sub(1, Ordering::SeqCst);
        assert!(previous > 1, "PID namespace live-count permit underflow");
    }
}

// ============================================================================
// Exact-lifetime PID namespace Arc admission (RF180-43)
// ============================================================================

const PID_NAMESPACE_ARC_SLOTS: usize = MAX_PID_NS_COUNT as usize;
const _: () = assert!(PID_NAMESPACE_ARC_SLOTS <= u16::MAX as usize + 1);

struct PidNamespaceArcChargeSlot {
    generation: u64,
    allocated: bool,
    _charge: Option<HeapCharge>,
}

static PID_NAMESPACE_ARC_CHARGES: Mutex<
    [Option<PidNamespaceArcChargeSlot>; PID_NAMESPACE_ARC_SLOTS],
> = Mutex::new([const { None }; PID_NAMESPACE_ARC_SLOTS]);
static NEXT_PID_NAMESPACE_ARC_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Default)]
struct PidNamespaceCreateFault {
    fail_arc_allocation: bool,
    fail_child_registry_growth: bool,
    check_child_prepare_unlocked: bool,
}

#[derive(Default)]
struct PidMappingPrepareFault {
    fail_second_map: bool,
    check_prepare_unlocked: bool,
}

struct PidNamespaceArcInstallError {
    charge: Option<HeapCharge>,
}

/// Allocator carried by every PID namespace Arc and Weak handle.
///
/// The static slot owns the optional admission charge. `Arc` invokes
/// `deallocate` only after the final strong and weak handles disappear, and the
/// implementation frees the ArcInner first and releases admission second. The
/// root uses a private uncharged slot but the identical allocator type.
#[derive(Clone, Copy, Debug)]
pub struct PidNamespaceArcAllocator {
    slot: u16,
    generation: u64,
    fail_allocation: bool,
}

impl PidNamespaceArcAllocator {
    fn try_install(
        charge: Option<HeapCharge>,
        fail_allocation: bool,
    ) -> Result<Self, PidNamespaceArcInstallError> {
        let generation = match NEXT_PID_NAMESPACE_ARC_GENERATION.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(generation) => generation,
            Err(_) => return Err(PidNamespaceArcInstallError { charge }),
        };

        let mut charge = Some(charge);
        let mut slots = PID_NAMESPACE_ARC_CHARGES.lock();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(PidNamespaceArcChargeSlot {
                    generation,
                    allocated: false,
                    _charge: charge.take().expect("PID namespace Arc charge moved once"),
                });
                return Ok(Self {
                    slot: index as u16,
                    generation,
                    fail_allocation,
                });
            }
        }
        Err(PidNamespaceArcInstallError {
            charge: charge.expect("PID namespace Arc slot scan retained charge"),
        })
    }

    fn take_slot(self, expected_allocated: bool) -> PidNamespaceArcChargeSlot {
        let mut slots = PID_NAMESPACE_ARC_CHARGES.lock();
        let slot = slots
            .get_mut(self.slot as usize)
            .expect("RF180-43 PID namespace Arc slot out of range");
        match slot.as_ref() {
            Some(entry)
                if entry.generation == self.generation && entry.allocated == expected_allocated => {
            }
            Some(entry) if entry.generation == self.generation => {
                panic!("RF180-43 PID namespace Arc allocator state mismatch")
            }
            Some(_) => panic!("RF180-43 stale PID namespace Arc allocator generation"),
            None => panic!("RF180-43 PID namespace Arc slot released twice"),
        }
        slot.take()
            .expect("validated PID namespace Arc charge disappeared")
    }

    fn cancel_failed_allocation(self) {
        drop(self.take_slot(false));
    }
}

unsafe impl Allocator for PidNamespaceArcAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        {
            let mut slots = PID_NAMESPACE_ARC_CHARGES.lock();
            let Some(entry) = slots.get_mut(self.slot as usize).and_then(Option::as_mut) else {
                return Err(AllocError);
            };
            if entry.generation != self.generation || entry.allocated {
                return Err(AllocError);
            }
            entry.allocated = true;
        }

        if self.fail_allocation {
            let mut slots = PID_NAMESPACE_ARC_CHARGES.lock();
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
                let mut slots = PID_NAMESPACE_ARC_CHARGES.lock();
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
        // Physical memory first, whole-heap admission second.
        unsafe { Global.deallocate(ptr, layout) };
        drop(self.take_slot(true));
    }
}

fn active_pid_namespace_arc_slots() -> usize {
    PID_NAMESPACE_ARC_CHARGES
        .lock()
        .iter()
        .filter(|slot| slot.is_some())
        .count()
}

pub type PidNamespaceArc = Arc<PidNamespace, PidNamespaceArcAllocator>;
pub type PidNamespaceWeak = Weak<PidNamespace, PidNamespaceArcAllocator>;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during PID namespace operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidNamespaceError {
    /// PID space exhausted in namespace
    PidExhausted,
    /// Init process already set for namespace
    InitAlreadySet,
    /// Maximum namespace nesting depth exceeded
    MaxDepthExceeded,
    /// R76-2 FIX: Maximum system-wide namespace count exceeded
    MaxNamespaces,
    /// Namespace is shutting down
    NamespaceShuttingDown,
    /// Invalid operation on root namespace
    InvalidOnRoot,
    /// R112-2 FIX: Namespace ID counter overflow (u64 exhausted)
    NamespaceIdOverflow,
    /// Whole-heap admission or fallible allocation failed.
    OutOfMemory,
    /// Existing map state conflicts with the requested global/local identity.
    MappingConflict,
}

// ============================================================================
// PID Namespace Membership
// ============================================================================

/// Represents a process's membership in a PID namespace.
///
/// Each process has a membership entry for every namespace in its hierarchy,
/// from the root namespace down to its owning namespace.
#[derive(Clone)]
pub struct PidNamespaceMembership {
    /// The namespace this membership is in
    pub ns: PidNamespaceArc,
    /// The PID as seen from this namespace
    pub pid: ProcessId,
}

impl core::fmt::Debug for PidNamespaceMembership {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PidNamespaceMembership")
            .field("ns_id", &self.ns.id().raw())
            .field("pid", &self.pid)
            .finish()
    }
}

/// RF180-16: allocation-free snapshot of every non-root namespace whose
/// lifecycle must remain live until a mapped PID is published in PROCESS_TABLE.
///
/// `assign_pid_chain` necessarily installs namespace PID mappings before the
/// PCB can be inserted.  Without a shared linearization lock, namespace init
/// teardown can enumerate that mapping while `get_process(global_pid)` is still
/// absent, skip the victim, and then let the creator publish after the cascade.
/// This fixed-size snapshot pins the exact namespace identities and acquires
/// their `children` locks root-to-leaf around the final PCB publication.  The
/// same locks serialize `mark_shutting_down` and descendant creation.
pub struct PidPublicationSources {
    namespaces: [Option<PidNamespaceArc>; MAX_PID_NS_LEVEL as usize],
    len: usize,
}

impl PidPublicationSources {
    /// Snapshot a canonical root-to-leaf membership chain without heap growth.
    /// Returns `None` for malformed/over-depth input rather than publishing a
    /// PCB under an incomplete lifecycle guard set.
    pub fn from_chain(chain: &[PidNamespaceMembership]) -> Option<Self> {
        let mut namespaces = core::array::from_fn(|_| None);
        let mut len = 0usize;
        let mut previous_level: Option<u8> = None;

        for (index, membership) in chain.iter().enumerate() {
            let level = membership.ns.level();
            if index == 0 {
                if !membership.ns.is_root() || level != 0 {
                    return None;
                }
                previous_level = Some(0);
                continue;
            }
            let Some(previous) = previous_level else {
                return None;
            };
            if membership.ns.is_root()
                || level != previous.saturating_add(1)
                || len >= namespaces.len()
            {
                return None;
            }
            namespaces[len] = Some(Arc::clone(&membership.ns));
            len += 1;
            previous_level = Some(level);
        }

        if chain.is_empty() {
            return None;
        }
        Some(Self { namespaces, len })
    }

    /// Build the canonical root-to-leaf lifecycle lock set for a namespace
    /// that may not yet appear in the caller's own membership chain (the
    /// `unshare(CLONE_NEWPID)` for-children case).
    pub fn from_leaf(leaf: PidNamespaceArc) -> Option<Self> {
        let mut reverse: [Option<PidNamespaceArc>; MAX_PID_NS_LEVEL as usize] =
            core::array::from_fn(|_| None);
        let mut len = 0usize;
        let mut cursor = Some(leaf);
        while let Some(namespace) = cursor {
            if namespace.is_root() {
                let mut namespaces = core::array::from_fn(|_| None);
                for target in 0..len {
                    namespaces[target] = reverse[len - 1 - target].take();
                }
                return Some(Self { namespaces, len });
            }
            if len == reverse.len() {
                return None;
            }
            cursor = namespace.parent();
            reverse[len] = Some(namespace);
            len += 1;
        }
        None
    }

    /// Run the actual PROCESS_TABLE publication while every source namespace
    /// is live. Locks are nested in canonical root-to-leaf order and no PCB or
    /// PROCESS_TABLE lock is held on entry. Once the closure inserts the PCB,
    /// any later init-death cascade waits, then observes both mapping and PCB;
    /// if shutdown won first, the closure never runs.
    pub fn with_live_publication<R>(
        &self,
        publish: impl FnOnce() -> R,
    ) -> Result<R, PidNamespaceError> {
        fn descend<R, F: FnOnce() -> R>(
            sources: &[Option<PidNamespaceArc>],
            index: usize,
            publish: &mut Option<F>,
        ) -> Result<R, PidNamespaceError> {
            if index == sources.len() {
                return Ok((publish
                    .take()
                    .expect("PID publication callback consumed exactly once"))(
                ));
            }

            let ns = sources[index]
                .as_ref()
                .expect("PID publication source prefix must be dense");
            let _children = ns.children.lock();
            if ns.shutting_down.load(Ordering::Acquire) {
                return Err(PidNamespaceError::NamespaceShuttingDown);
            }
            descend(sources, index + 1, publish)
        }

        let mut publish = Some(publish);
        descend(&self.namespaces[..self.len], 0, &mut publish)
    }
}

/// Append a stable snapshot of every live direct child while holding the
/// parent's lifecycle mutex. Capacity is reserved for the complete pruned Weak
/// set before the first upgrade, so an allocation failure cannot drop a newly
/// upgraded last Arc and re-enter `PidNamespace::drop` on the same mutex.
fn append_live_children_with_reservation<E>(
    parent: &PidNamespace,
    stack: &mut AdmittedVec<PidNamespaceArc>,
    mut reserve: impl FnMut(&mut AdmittedVec<PidNamespaceArc>, usize) -> Result<(), E>,
) -> Result<(), E> {
    loop {
        let upper_bound = parent.children.lock().len();
        reserve(stack, upper_bound)?;

        let children = parent.children.lock();
        let available = stack.capacity().saturating_sub(stack.len());
        if available < children.len() {
            drop(children);
            continue;
        }
        for weak in children.iter() {
            if let Some(child) = weak.upgrade() {
                stack
                    .push_reserved(child)
                    .unwrap_or_else(|_| panic!("reserved PID child snapshot capacity vanished"));
            }
        }
        return Ok(());
    }
}

#[inline]
fn append_live_children(
    parent: &PidNamespace,
    stack: &mut AdmittedVec<PidNamespaceArc>,
) -> Result<(), PidNamespaceError> {
    append_live_children_with_reservation(parent, stack, |stack, additional| {
        stack
            .try_reserve(additional)
            .map_err(|_| PidNamespaceError::OutOfMemory)
    })
}

const PID_NAMESPACE_WEAK_BYTES: usize = core::mem::size_of::<PidNamespaceWeak>();
const PID_NAMESPACE_WEAK_VEC_OVERHEAD: usize =
    2 * core::mem::size_of::<usize>() + core::mem::align_of::<PidNamespaceWeak>() - 1;
const MAX_CHILDREN_BY_CLASS_BYTES: usize = (HeapClass::CoreProcess.limit_bytes()
    - PID_NAMESPACE_WEAK_VEC_OVERHEAD)
    / PID_NAMESPACE_WEAK_BYTES;
const MAX_CHILDREN_ENTRIES: usize = if MAX_CHILDREN_BY_CLASS_BYTES < (MAX_PID_NS_COUNT as usize - 1)
{
    MAX_CHILDREN_BY_CLASS_BYTES
} else {
    MAX_PID_NS_COUNT as usize - 1
};
const _: () = assert!(PID_NAMESPACE_WEAK_BYTES > 0);
const _: () = assert!(MAX_CHILDREN_ENTRIES > 0);

/// Register one child through snapshot/allocate/recheck publication. Detached
/// backing is prepared without the lifecycle mutex, installed allocation-free,
/// and obsolete backing is dropped only after the mutex is released.
fn register_child_namespace(
    parent: &PidNamespace,
    child: &PidNamespaceArc,
    fault: PidNamespaceCreateFault,
) -> Result<(), PidNamespaceError> {
    let mut weak = Some(Arc::downgrade(child));
    let mut prepared: Option<PreparedAdmittedVecCapacity<PidNamespaceWeak>> = None;

    loop {
        let mut retired: Option<RetiredAdmittedVecCapacity<PidNamespaceWeak>> = None;
        let mut required_capacity = None;
        let mut failure = None;

        {
            let mut children = parent.children.lock();
            if parent.shutting_down.load(Ordering::Acquire) {
                failure = Some(PidNamespaceError::NamespaceShuttingDown);
            } else if children.len() >= MAX_CHILDREN_ENTRIES {
                failure = Some(PidNamespaceError::MaxNamespaces);
            } else {
                let required = children
                    .len()
                    .checked_add(1)
                    .ok_or(PidNamespaceError::OutOfMemory)?;
                if children.capacity() < required {
                    match prepared.take() {
                        Some(candidate) if candidate.capacity() >= required => {
                            retired = Some(
                                children
                                    .install_prepared_deferred(candidate)
                                    .expect("validated PID child backing rejected"),
                            );
                        }
                        Some(candidate) => {
                            prepared = Some(candidate);
                            let amortized = children
                                .capacity()
                                .max(4)
                                .checked_mul(2)
                                .unwrap_or(MAX_CHILDREN_ENTRIES);
                            required_capacity =
                                Some(required.max(amortized).min(MAX_CHILDREN_ENTRIES));
                        }
                        None => {
                            let amortized = children
                                .capacity()
                                .max(4)
                                .checked_mul(2)
                                .unwrap_or(MAX_CHILDREN_ENTRIES);
                            required_capacity =
                                Some(required.max(amortized).min(MAX_CHILDREN_ENTRIES));
                        }
                    }
                }

                if required_capacity.is_none() {
                    children
                        .push_reserved(weak.take().expect("PID child Weak published exactly once"))
                        .unwrap_or_else(|_| panic!("prepared PID child capacity vanished"));
                }
            }
        }

        // Both owners can invoke allocator deallocation; keep them outside the
        // parent lifecycle mutex on every success and failure path.
        drop(retired);
        if let Some(error) = failure {
            return Err(error);
        }
        if weak.is_none() {
            return Ok(());
        }

        let target = required_capacity.expect("PID child registration needs detached backing");
        drop(prepared.take());
        if fault.check_child_prepare_unlocked {
            assert!(
                parent.children.try_lock().is_some(),
                "RF180-43 child backing preparation ran under lifecycle lock"
            );
        }
        if fault.fail_child_registry_growth {
            return Err(PidNamespaceError::OutOfMemory);
        }
        prepared = Some(
            PreparedAdmittedVecCapacity::try_new(HeapClass::CoreProcess, target)
                .map_err(|_| PidNamespaceError::OutOfMemory)?,
        );
    }
}

// ============================================================================
// PID Namespace
// ============================================================================

/// A PID namespace providing isolated process ID numbering.
///
/// # Hierarchy
///
/// PID namespaces form a tree structure:
/// - Root namespace (level 0) has no parent and uses global PIDs
/// - Child namespaces have their own PID counters starting from 1
/// - Processes are visible to all ancestor namespaces with different PIDs
///
/// # Init Process
///
/// The first process in a namespace becomes its init (PID 1).
/// When init exits, all processes in the namespace are killed.
#[derive(Debug)]
pub struct PidNamespace {
    /// Unique namespace identifier
    id: NamespaceId,

    /// Parent namespace (None for root)
    parent: Option<PidNamespaceArc>,

    /// Nesting level (0 = root)
    level: u8,

    /// Next PID to allocate in this namespace
    next_pid: Mutex<ProcessId>,

    /// Namespace PID -> Global PID mapping
    pid_by_ns: Mutex<AdmittedMap<ProcessId, ProcessId>>,

    /// Global PID -> Namespace PID mapping
    pid_by_global: Mutex<AdmittedMap<ProcessId, ProcessId>>,

    /// Init process global PID (PID 1 in this namespace)
    init_global_pid: Mutex<Option<ProcessId>>,

    /// Whether namespace is shutting down (init died)
    shutting_down: AtomicBool,

    /// R73-2 FIX: Child namespaces for cascade kill traversal
    children: Mutex<AdmittedVec<PidNamespaceWeak>>,

    /// Exactly-once live namespace quota ownership (None only for static root).
    _count_permit: Option<PidNamespaceCountPermit>,
}

// ============================================================================
// Global State
// ============================================================================

lazy_static::lazy_static! {
    /// The root PID namespace (level 0, no parent)
    ///
    /// All processes start in the root namespace unless CLONE_NEWPID is used.
    /// The root namespace uses global PIDs directly (no translation needed).
    pub static ref ROOT_PID_NAMESPACE: PidNamespaceArc = {
        let allocator = PidNamespaceArcAllocator::try_install(None, false)
            .unwrap_or_else(|_| panic!("unable to reserve static PID namespace Arc slot"));
        match Arc::try_new_in(PidNamespace::new_root(), allocator) {
            Ok(root) => root,
            Err(_) => {
                allocator.cancel_failed_allocation();
                panic!("unable to allocate static root PID namespace")
            }
        }
    };

    /// Counter for generating unique namespace IDs
    static ref NEXT_NS_ID: AtomicU64 = AtomicU64::new(1);

    /// Serializes capacity preparation and allocation-free publication across
    /// both PID maps. This is never taken with PROCESS_TABLE or a PCB lock.
    static ref PID_MAPPING_TRANSACTION: Mutex<()> = Mutex::new(());
}

type PreparedPidMap = PreparedAdmittedMapCapacity<ProcessId, ProcessId>;
type RetiredPidMap = RetiredAdmittedMapCapacity<ProcessId, ProcessId>;

struct PreparedPidMappingCapacity {
    by_global: Option<PreparedPidMap>,
    by_ns: Option<PreparedPidMap>,
}

struct RetiredPidMappingCapacity {
    by_global: Option<RetiredPidMap>,
    by_ns: Option<RetiredPidMap>,
}

impl RetiredPidMappingCapacity {
    const fn empty() -> Self {
        Self {
            by_global: None,
            by_ns: None,
        }
    }
}

fn pid_mapping_growth_target(
    map: &AdmittedMap<ProcessId, ProcessId>,
) -> Result<Option<usize>, PidNamespaceError> {
    if map.len() < map.capacity() {
        return Ok(None);
    }
    let required = map
        .len()
        .checked_add(1)
        .ok_or(PidNamespaceError::OutOfMemory)?;
    let amortized = map
        .capacity()
        .max(4)
        .checked_mul(2)
        .ok_or(PidNamespaceError::OutOfMemory)?;
    Ok(Some(required.max(amortized)))
}

// ============================================================================
// PidNamespace Implementation
// ============================================================================

impl PidNamespace {
    /// Create the root PID namespace.
    ///
    /// The root namespace:
    /// - Has level 0
    /// - Has no parent
    /// - Uses global PIDs directly (no translation)
    fn new_root() -> Self {
        PidNamespace {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            next_pid: Mutex::new(1),
            pid_by_ns: Mutex::new(AdmittedMap::new(HeapClass::CoreProcess)),
            pid_by_global: Mutex::new(AdmittedMap::new(HeapClass::CoreProcess)),
            init_global_pid: Mutex::new(None),
            shutting_down: AtomicBool::new(false),
            children: Mutex::new(AdmittedVec::new(HeapClass::CoreProcess)),
            _count_permit: None,
        }
    }

    /// Create a new child namespace.
    ///
    /// The child namespace:
    /// - Has its own PID numbering starting from 1
    /// - Can be nested up to MAX_PID_NS_LEVEL deep
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent namespace
    ///
    /// # Returns
    ///
    /// New namespace or error if max depth exceeded
    pub fn new_child(parent: PidNamespaceArc) -> Result<PidNamespaceArc, PidNamespaceError> {
        Self::new_child_with_fault(parent, PidNamespaceCreateFault::default())
    }

    fn new_child_with_fault(
        parent: PidNamespaceArc,
        fault: PidNamespaceCreateFault,
    ) -> Result<PidNamespaceArc, PidNamespaceError> {
        if parent.shutting_down.load(Ordering::Acquire) {
            return Err(PidNamespaceError::NamespaceShuttingDown);
        }
        // Check nesting depth
        if parent.level >= MAX_PID_NS_LEVEL {
            return Err(PidNamespaceError::MaxDepthExceeded);
        }

        let count_permit = PidNamespaceCountPermit::try_acquire()?;

        // Generate unique namespace ID (R112-2: overflow-safe allocation)
        let id = NEXT_NS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| PidNamespaceError::NamespaceIdOverflow)?;

        // RF180-16 FIX: reserve and fallibly allocate the namespace Arc. Empty
        // PID maps allocate only when assign_pid_chain prepares a publication.
        let arc_bytes =
            arc_charge_bytes::<PidNamespace>().map_err(|_| PidNamespaceError::OutOfMemory)?;
        let arc_reservation = try_reserve_heap(HeapClass::CoreProcess, arc_bytes)
            .map_err(|_| PidNamespaceError::OutOfMemory)?;
        let charge = arc_reservation
            .commit()
            .map_err(|_| PidNamespaceError::OutOfMemory)?;
        let allocator =
            PidNamespaceArcAllocator::try_install(Some(charge), fault.fail_arc_allocation)
                .map_err(|error| {
                    drop(error.charge);
                    PidNamespaceError::OutOfMemory
                })?;
        let child_value = PidNamespace {
            id: NamespaceId::new(id),
            parent: Some(Arc::clone(&parent)),
            level: parent.level.saturating_add(1),
            next_pid: Mutex::new(1),
            pid_by_ns: Mutex::new(AdmittedMap::new(HeapClass::CoreProcess)),
            pid_by_global: Mutex::new(AdmittedMap::new(HeapClass::CoreProcess)),
            init_global_pid: Mutex::new(None),
            shutting_down: AtomicBool::new(false),
            children: Mutex::new(AdmittedVec::new(HeapClass::CoreProcess)),
            _count_permit: Some(count_permit),
        };
        let child = match Arc::try_new_in(child_value, allocator) {
            Ok(child) => child,
            Err(_) => {
                allocator.cancel_failed_allocation();
                return Err(PidNamespaceError::OutOfMemory);
            }
        };

        register_child_namespace(&parent, &child, fault)?;

        Ok(child)
    }

    /// Get the namespace identifier.
    #[inline]
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Get the parent namespace.
    #[inline]
    pub fn parent(&self) -> Option<PidNamespaceArc> {
        self.parent.as_ref().map(Arc::clone)
    }

    /// Get the nesting level (0 = root).
    #[inline]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Check if this is the root namespace.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.level == 0
    }

    /// Allocate a namespace-local PID for the given global PID.
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The process's global PID
    ///
    /// # Returns
    ///
    /// The namespace-local PID or error if exhausted
    pub fn alloc_pid(&self, global_pid: ProcessId) -> Result<ProcessId, PidNamespaceError> {
        self.alloc_pid_with_fault(global_pid, PidMappingPrepareFault::default())
    }

    fn alloc_pid_with_fault(
        &self,
        global_pid: ProcessId,
        fault: PidMappingPrepareFault,
    ) -> Result<ProcessId, PidNamespaceError> {
        self.with_prepared_mapping_capacity(fault, || self.alloc_pid_reserved(global_pid))
    }

    /// Attach a global PID to the root namespace.
    ///
    /// In the root namespace, global PID == namespace PID (identity mapping).
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The process's global PID
    pub fn attach_root_pid(&self, global_pid: ProcessId) -> Result<(), PidNamespaceError> {
        debug_assert!(
            self.is_root(),
            "attach_root_pid called on non-root namespace"
        );
        self.with_prepared_mapping_capacity(PidMappingPrepareFault::default(), || {
            self.attach_root_pid_reserved(global_pid)
        })
    }

    /// Snapshot and allocate both possible map-growth legs without any
    /// namespace or mapping-transaction lock held.
    fn prepare_mapping_capacity_detached(
        &self,
        fault: &mut PidMappingPrepareFault,
    ) -> Result<PreparedPidMappingCapacity, PidNamespaceError> {
        let (global_target, ns_target) = {
            let by_global = self.pid_by_global.lock();
            let by_ns = self.pid_by_ns.lock();
            if by_global.len() != by_ns.len() {
                return Err(PidNamespaceError::MappingConflict);
            }
            let global_target = pid_mapping_growth_target(&by_global)?;
            let ns_target = pid_mapping_growth_target(&by_ns)?;
            (global_target, ns_target)
        };

        if fault.check_prepare_unlocked {
            fault.check_prepare_unlocked = false;
            let global = self.pid_by_global.try_lock();
            let ns = self.pid_by_ns.try_lock();
            assert!(
                global.is_some() && ns.is_some(),
                "RF180-43 PID map backing prepared under map lock"
            );
        }

        let by_global = match global_target {
            Some(target) => Some(
                PreparedAdmittedMapCapacity::try_new(HeapClass::CoreProcess, target)
                    .map_err(|_| PidNamespaceError::OutOfMemory)?,
            ),
            None => None,
        };

        if ns_target.is_some() && fault.fail_second_map {
            fault.fail_second_map = false;
            return Err(PidNamespaceError::OutOfMemory);
        }
        let by_ns = match ns_target {
            Some(target) => Some(
                PreparedAdmittedMapCapacity::try_new(HeapClass::CoreProcess, target)
                    .map_err(|_| PidNamespaceError::OutOfMemory)?,
            ),
            None => None,
        };

        Ok(PreparedPidMappingCapacity { by_global, by_ns })
    }

    /// Called with PID_MAPPING_TRANSACTION held. It only reads protected map
    /// metadata and never allocates or releases backing.
    fn prepared_mapping_capacity_is_current(&self, prepared: &PreparedPidMappingCapacity) -> bool {
        let by_global = self.pid_by_global.lock();
        let by_ns = self.pid_by_ns.lock();
        if by_global.len() != by_ns.len() {
            return false;
        }
        let global_ready = by_global.len() < by_global.capacity()
            || prepared.by_global.as_ref().is_some_and(|candidate| {
                candidate.capacity() > by_global.len()
                    && candidate.class() == HeapClass::CoreProcess
            });
        let ns_ready = by_ns.len() < by_ns.capacity()
            || prepared.by_ns.as_ref().is_some_and(|candidate| {
                candidate.capacity() > by_ns.len() && candidate.class() == HeapClass::CoreProcess
            });
        global_ready && ns_ready
    }

    /// Allocation-free install after aggregate validation. Obsolete backing is
    /// returned for commit-time drop or failure-time restoration.
    fn install_prepared_mapping_capacity(
        &self,
        prepared: &mut PreparedPidMappingCapacity,
    ) -> RetiredPidMappingCapacity {
        let mut retired = RetiredPidMappingCapacity::empty();
        let mut by_global = self.pid_by_global.lock();
        let mut by_ns = self.pid_by_ns.lock();
        if by_global.len() == by_global.capacity() {
            retired.by_global = Some(
                by_global
                    .install_prepared_deferred(
                        prepared
                            .by_global
                            .take()
                            .expect("validated global PID map preparation disappeared"),
                    )
                    .expect("validated global PID map backing rejected"),
            );
        }
        if by_ns.len() == by_ns.capacity() {
            retired.by_ns = Some(
                by_ns
                    .install_prepared_deferred(
                        prepared
                            .by_ns
                            .take()
                            .expect("validated namespace PID map preparation disappeared"),
                    )
                    .expect("validated namespace PID map backing rejected"),
            );
        }
        retired
    }

    /// Restore exact pre-transaction backing after semantic publication fails.
    /// The newly installed allocations are returned for out-of-lock drop.
    fn restore_mapping_capacity(
        &self,
        retired: RetiredPidMappingCapacity,
    ) -> RetiredPidMappingCapacity {
        let mut displaced = RetiredPidMappingCapacity::empty();
        let mut by_global = self.pid_by_global.lock();
        let mut by_ns = self.pid_by_ns.lock();
        if let Some(old) = retired.by_global {
            displaced.by_global = Some(
                by_global
                    .restore_retired_deferred(old)
                    .unwrap_or_else(|_| panic!("global PID map rollback backing rejected")),
            );
        }
        if let Some(old) = retired.by_ns {
            displaced.by_ns = Some(
                by_ns
                    .restore_retired_deferred(old)
                    .unwrap_or_else(|_| panic!("namespace PID map rollback backing rejected")),
            );
        }
        displaced
    }

    fn take_empty_mapping_capacity(&self) -> RetiredPidMappingCapacity {
        let mut by_global = self.pid_by_global.lock();
        let mut by_ns = self.pid_by_ns.lock();
        RetiredPidMappingCapacity {
            by_global: by_global.take_empty_capacity(),
            by_ns: by_ns.take_empty_capacity(),
        }
    }

    fn with_prepared_mapping_capacity<R>(
        &self,
        mut fault: PidMappingPrepareFault,
        operation: impl FnOnce() -> Result<R, PidNamespaceError>,
    ) -> Result<R, PidNamespaceError> {
        let mut operation = Some(operation);
        loop {
            let mut prepared = self.prepare_mapping_capacity_detached(&mut fault)?;
            let transaction = PID_MAPPING_TRANSACTION.lock();
            if !self.prepared_mapping_capacity_is_current(&prepared) {
                drop(transaction);
                drop(prepared);
                continue;
            }

            let retired = self.install_prepared_mapping_capacity(&mut prepared);
            let result = operation
                .take()
                .expect("PID mapping operation executed exactly once")();
            let retired = if result.is_err() {
                self.restore_mapping_capacity(retired)
            } else {
                retired
            };
            drop(transaction);
            drop(retired);
            drop(prepared);
            return result;
        }
    }

    fn alloc_pid_reserved(&self, global_pid: ProcessId) -> Result<ProcessId, PidNamespaceError> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(PidNamespaceError::NamespaceShuttingDown);
        }
        let mut next = self.next_pid.lock();
        if *next > MAX_PID {
            return Err(PidNamespaceError::PidExhausted);
        }
        let ns_pid = *next;
        let following_pid = ns_pid
            .checked_add(1)
            .ok_or(PidNamespaceError::PidExhausted)?;
        let mut by_global = self.pid_by_global.lock();
        let mut by_ns = self.pid_by_ns.lock();
        if by_global.contains_key(&global_pid) || by_ns.contains_key(&ns_pid) {
            return Err(PidNamespaceError::MappingConflict);
        }
        by_global
            .insert_unique_reserved(global_pid, ns_pid)
            .map_err(|_| PidNamespaceError::OutOfMemory)?;
        if by_ns.insert_unique_reserved(ns_pid, global_pid).is_err() {
            by_global.remove_retaining_capacity(&global_pid);
            return Err(PidNamespaceError::OutOfMemory);
        }
        *next = following_pid;
        Ok(ns_pid)
    }

    fn attach_root_pid_reserved(&self, global_pid: ProcessId) -> Result<(), PidNamespaceError> {
        let mut by_global = self.pid_by_global.lock();
        let mut by_ns = self.pid_by_ns.lock();
        if by_global.contains_key(&global_pid) || by_ns.contains_key(&global_pid) {
            return Err(PidNamespaceError::MappingConflict);
        }
        by_global
            .insert_unique_reserved(global_pid, global_pid)
            .map_err(|_| PidNamespaceError::OutOfMemory)?;
        if by_ns
            .insert_unique_reserved(global_pid, global_pid)
            .is_err()
        {
            by_global.remove_retaining_capacity(&global_pid);
            return Err(PidNamespaceError::OutOfMemory);
        }
        Ok(())
    }

    /// Remove a process from this namespace.
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The process's global PID
    pub fn remove_pid(&self, global_pid: ProcessId) {
        let transaction = PID_MAPPING_TRANSACTION.lock();
        self.remove_pid_reserved(global_pid);
        let retired = self.take_empty_mapping_capacity();
        drop(transaction);
        drop(retired);
    }

    fn remove_pid_reserved(&self, global_pid: ProcessId) {
        // Lock in same order as alloc_pid to avoid deadlock
        let mut by_global = self.pid_by_global.lock();
        let mut by_ns = self.pid_by_ns.lock();
        if let Some(ns_pid) = by_global.remove_retaining_capacity(&global_pid) {
            by_ns.remove_retaining_capacity(&ns_pid);
        }
    }

    /// Lookup global PID from namespace-local PID.
    ///
    /// # Arguments
    ///
    /// * `ns_pid` - The namespace-local PID
    ///
    /// # Returns
    ///
    /// The global PID if found
    pub fn lookup_global(&self, ns_pid: ProcessId) -> Option<ProcessId> {
        self.pid_by_ns.lock().get(&ns_pid).copied()
    }

    /// Lookup namespace-local PID from global PID.
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The global PID
    ///
    /// # Returns
    ///
    /// The namespace-local PID if the process is visible in this namespace
    pub fn lookup_ns_pid(&self, global_pid: ProcessId) -> Option<ProcessId> {
        self.pid_by_global.lock().get(&global_pid).copied()
    }

    /// Set the init process for this namespace.
    ///
    /// The first process (PID 1) in a namespace becomes its init.
    /// This can only be set once.
    ///
    /// # Arguments
    ///
    /// * `global_pid` - The init process's global PID
    pub fn set_init(&self, global_pid: ProcessId) -> Result<(), PidNamespaceError> {
        let mut init = self.init_global_pid.lock();
        if init.is_some() {
            return Err(PidNamespaceError::InitAlreadySet);
        }
        *init = Some(global_pid);
        Ok(())
    }

    /// Get the init process's global PID.
    #[inline]
    pub fn init_global_pid(&self) -> Option<ProcessId> {
        *self.init_global_pid.lock()
    }

    /// R171-S-R170-5-01 FIX (SLICE 3): Clear this namespace's init mapping iff it
    /// currently names `global_pid` (identity-checked; no-op otherwise).
    ///
    /// Called from `detach_pid_chain` on process teardown — which runs AFTER
    /// `handle_namespace_init_death` in `terminate_process`, so the init-death
    /// cascade's init-filter still observes the dying init before this clears it.
    /// Clearing on detach closes the stale-`init_global_pid` ABA window: once a
    /// (non-root) init detaches, a later recycled PID can never be mis-resolved as
    /// this dead namespace's reaper by `reparent_orphans`.
    pub fn clear_init(&self, global_pid: ProcessId) {
        let mut init = self.init_global_pid.lock();
        if *init == Some(global_pid) {
            *init = None;
        }
    }

    /// Check if the given global PID is the init process of this namespace.
    #[inline]
    pub fn is_init(&self, global_pid: ProcessId) -> bool {
        *self.init_global_pid.lock() == Some(global_pid)
    }

    /// Mark the namespace as shutting down.
    ///
    /// Called when init exits. Returns true if this call triggered the transition.
    pub fn mark_shutting_down(&self) -> bool {
        let _children = self.children.lock();
        !self.shutting_down.swap(true, Ordering::SeqCst)
    }

    /// Run a publication step while this namespace is still a valid source
    /// for child creation. The children mutex is the shared linearization lock
    /// with `new_child` and `mark_shutting_down`.
    pub fn with_live_child_source<R>(
        &self,
        publish: impl FnOnce() -> R,
    ) -> Result<R, PidNamespaceError> {
        let _children = self.children.lock();
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(PidNamespaceError::NamespaceShuttingDown);
        }
        Ok(publish())
    }

    /// Check if namespace is shutting down.
    #[inline]
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// R171-S-R170-5-01 FIX (SLICE 3): Mark every DESCENDANT namespace
    /// shutting-down (this namespace is already marked by the caller's
    /// `mark_shutting_down`). Run at the start of the init-death cascade so a
    /// member that joins a nested namespace mid-teardown is never adopted as a
    /// reaper by `reparent_orphans`, which skips `is_shutting_down` namespaces.
    ///
    /// Best-effort and allocation-fallible: the traversal stack uses `try_reserve`;
    /// OOM skips only the branch whose children could not be snapshotted while
    /// already-queued siblings are still marked. This runs inside teardown, where
    /// a panic would abandon the dying task. Touches only namespace leaf mutexes —
    /// holds no PCB or `PROCESS_TABLE` lock.
    pub fn mark_descendants_shutting_down(&self) {
        let mut stack = AdmittedVec::new(HeapClass::CoreProcess);
        if append_live_children(self, &mut stack).is_err() {
            return;
        }
        while let Some(cur) = stack.pop() {
            cur.shutting_down.store(true, Ordering::SeqCst);
            // OOM may prevent discovering this node's children, but must not
            // abandon siblings already queued from earlier snapshots.
            if append_live_children(&cur, &mut stack).is_err() {
                continue;
            }
        }
    }

    /// Get all global PIDs of processes in this namespace.
    ///
    /// Used for cascade killing when init exits.
    pub fn members(&self) -> Result<AdmittedVec<ProcessId>, PidNamespaceError> {
        let mut out = AdmittedVec::new(HeapClass::CoreProcess);
        self.members_into(&mut out)?;
        Ok(out)
    }

    /// R171-S-R170-5-01 FIX (SLICE 3): Fallible sibling of `members()` — appends
    /// every member's global PID into `out` using `try_reserve`, so an OOM during
    /// the init-death cascade cannot panic the dying task before it reaches
    /// `teardown_done` (the abandonment class this slice eliminates).
    fn members_into(&self, out: &mut AdmittedVec<ProcessId>) -> Result<(), PidNamespaceError> {
        loop {
            let upper_bound = self.pid_by_ns.lock().len();
            out.try_reserve(upper_bound)
                .map_err(|_| PidNamespaceError::OutOfMemory)?;

            let transaction = PID_MAPPING_TRANSACTION.lock();
            let map = self.pid_by_ns.lock();
            if out.capacity().saturating_sub(out.len()) < map.len() {
                drop(map);
                drop(transaction);
                continue;
            }
            for &g in map.values() {
                out.push_reserved(g)
                    .map_err(|_| PidNamespaceError::OutOfMemory)?;
            }
            return Ok(());
        }
    }

    /// Get the number of processes in this namespace.
    pub fn member_count(&self) -> usize {
        self.pid_by_ns.lock().len()
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Assign PID chain for a new process.
///
/// Creates membership entries for every namespace from root to the target,
/// allocating namespace-local PIDs in each.
///
/// # Arguments
///
/// * `leaf` - The owning namespace (deepest in hierarchy)
/// * `global_pid` - The process's global PID
///
/// # Returns
///
/// Vec of memberships from root to leaf, or error if PID allocation fails
///
/// # Linux Semantics
///
/// A process is visible in all ancestor namespaces with different PIDs.
/// Example: Process in level-2 namespace has 3 PIDs (root, level-1, level-2).
pub fn assign_pid_chain(
    leaf: PidNamespaceArc,
    global_pid: ProcessId,
) -> Result<AdmittedVec<PidNamespaceMembership>, PidNamespaceError> {
    // RF180-16 FIX: hierarchy discovery is bounded and heap-free. The retained
    // membership chain is admitted before the first PID-map mutation.
    let mut path: [Option<PidNamespaceArc>; PID_PATH_SLOTS] = core::array::from_fn(|_| None);
    let mut path_len = 0usize;
    let mut cursor = Some(leaf);
    while let Some(ns) = cursor {
        if path_len == path.len() {
            return Err(PidNamespaceError::MaxDepthExceeded);
        }
        cursor = ns.parent();
        path[path_len] = Some(ns);
        path_len += 1;
    }
    if path_len == 0
        || !path[path_len - 1]
            .as_ref()
            .is_some_and(|namespace| namespace.is_root())
    {
        return Err(PidNamespaceError::MappingConflict);
    }

    let mut chain: AdmittedVec<PidNamespaceMembership> = AdmittedVec::new(HeapClass::CoreProcess);
    chain
        .try_reserve_exact(path_len)
        .map_err(|_| PidNamespaceError::OutOfMemory)?;

    // Prepare every dual-map growth leg outside PID/map locks, then validate
    // the complete root-to-leaf set under one writer transaction. If a writer
    // changed a capacity snapshot, discard detached preparation after unlocking
    // and retry; no partial capacity publication is visible.
    let (mut prepared, transaction) = loop {
        let mut candidates: [Option<PreparedPidMappingCapacity>; PID_PATH_SLOTS] =
            core::array::from_fn(|_| None);
        for index in (0..path_len).rev() {
            let ns = path[index].as_ref().expect("PID path prefix must be dense");
            let mut no_fault = PidMappingPrepareFault::default();
            candidates[index] = Some(ns.prepare_mapping_capacity_detached(&mut no_fault)?);
        }

        let transaction = PID_MAPPING_TRANSACTION.lock();
        let all_current = (0..path_len).all(|index| {
            let ns = path[index].as_ref().expect("PID path prefix must be dense");
            ns.prepared_mapping_capacity_is_current(
                candidates[index]
                    .as_ref()
                    .expect("PID map candidate prefix must be dense"),
            )
        });
        if all_current {
            break (candidates, transaction);
        }
        drop(transaction);
        drop(candidates);
    };

    let mut retired: [Option<RetiredPidMappingCapacity>; PID_PATH_SLOTS] =
        core::array::from_fn(|_| None);
    for index in (0..path_len).rev() {
        let ns = path[index].as_ref().expect("PID path prefix must be dense");
        retired[index] = Some(
            ns.install_prepared_mapping_capacity(
                prepared[index]
                    .as_mut()
                    .expect("PID map candidate prefix must be dense"),
            ),
        );
    }

    let mut mapped = [false; PID_PATH_SLOTS];
    let mut prior_next: [Option<ProcessId>; PID_PATH_SLOTS] = [None; PID_PATH_SLOTS];

    let rollback =
        |mapped: &[bool; PID_PATH_SLOTS],
         prior_next: &[Option<ProcessId>; PID_PATH_SLOTS],
         retired: &mut [Option<RetiredPidMappingCapacity>; PID_PATH_SLOTS]| {
            for index in 0..path_len {
                if !mapped[index] {
                    continue;
                }
                let ns = path[index].as_ref().expect("PID path prefix must be dense");
                ns.clear_init(global_pid);
                ns.remove_pid_reserved(global_pid);
                if let Some(previous) = prior_next[index] {
                    *ns.next_pid.lock() = previous;
                }
            }
            for index in (0..path_len).rev() {
                let ns = path[index].as_ref().expect("PID path prefix must be dense");
                let old = retired[index]
                    .take()
                    .expect("installed PID map retirement prefix must be dense");
                retired[index] = Some(ns.restore_mapping_capacity(old));
            }
        };

    for index in (0..path_len).rev() {
        let ns = Arc::clone(path[index].as_ref().expect("PID path prefix must be dense"));
        if !ns.is_root() {
            prior_next[index] = Some(*ns.next_pid.lock());
        }
        let allocation = if ns.is_root() {
            ns.attach_root_pid_reserved(global_pid).map(|()| global_pid)
        } else {
            ns.alloc_pid_reserved(global_pid)
        };
        let ns_pid = match allocation {
            Ok(pid) => pid,
            Err(error) => {
                rollback(&mapped, &prior_next, &mut retired);
                drop(transaction);
                drop(retired);
                drop(prepared);
                return Err(error);
            }
        };
        mapped[index] = true;
        if let Err(unpublished_membership) =
            chain.push_reserved(PidNamespaceMembership { ns, pid: ns_pid })
        {
            rollback(&mapped, &prior_next, &mut retired);
            drop(transaction);
            drop(retired);
            drop(prepared);
            drop(unpublished_membership);
            return Err(PidNamespaceError::OutOfMemory);
        }
    }

    // Now that the full chain succeeded, set init for any namespace where this is PID 1.
    //
    // This ensures we don't leave init_global_pid set for a namespace whose process
    // failed to allocate PIDs further down the chain.
    for membership in &chain {
        if !membership.ns.is_root() && membership.pid == 1 {
            // Ignore error if init already set (shouldn't happen for fresh namespace)
            if let Err(error) = membership.ns.set_init(global_pid) {
                rollback(&mapped, &prior_next, &mut retired);
                drop(transaction);
                drop(retired);
                drop(prepared);
                return Err(error);
            }
        }
    }

    drop(transaction);
    drop(retired);
    drop(prepared);
    Ok(chain)
}

/// Remove a process from all namespaces it belongs to.
///
/// # Arguments
///
/// * `chain` - The process's namespace membership chain
/// * `global_pid` - The process's global PID
pub fn detach_pid_chain(chain: &[PidNamespaceMembership], global_pid: ProcessId) {
    let transaction = PID_MAPPING_TRANSACTION.lock();
    let mut retired: [Option<RetiredPidMappingCapacity>; PID_PATH_SLOTS] =
        core::array::from_fn(|_| None);
    for (index, membership) in chain.iter().enumerate() {
        // R171-S-R170-5-01 FIX (SLICE 3): clear this namespace's init mapping if it
        // named the departing PID, BEFORE removing the PID. ORDERING DEPENDENCY:
        // `terminate_process` runs `handle_namespace_init_death` (whose init-filter
        // reads `init_global_pid`) STRICTLY BEFORE calling `detach_pid_chain`, so
        // clearing here never blinds the cascade. Clearing closes the stale-init
        // ABA window so a recycled PID can never be mis-resolved as this (now-dead)
        // namespace's reaper by `reparent_orphans`. (No-op for the root namespace,
        // whose init mapping is never set.)
        membership.ns.clear_init(global_pid);
        membership.ns.remove_pid_reserved(global_pid);
        if index < retired.len() {
            retired[index] = Some(membership.ns.take_empty_mapping_capacity());
        }
    }
    drop(transaction);
    drop(retired);
}

/// Translate a namespace-local PID to global PID.
///
/// # Arguments
///
/// * `ns` - The namespace to resolve in
/// * `ns_pid` - The namespace-local PID
///
/// # Returns
///
/// The global PID if the process is visible in the namespace
pub fn resolve_pid_in_namespace(ns: &PidNamespaceArc, ns_pid: ProcessId) -> Option<ProcessId> {
    ns.lookup_global(ns_pid)
}

/// Translate a global PID to namespace-local PID.
///
/// # Arguments
///
/// * `ns` - The namespace to translate for
/// * `global_pid` - The global PID
///
/// # Returns
///
/// The namespace-local PID if the process is visible
pub fn pid_in_namespace(ns: &PidNamespaceArc, global_pid: ProcessId) -> Option<ProcessId> {
    ns.lookup_ns_pid(global_pid)
}

/// Get the owning namespace for a process (deepest/leaf namespace).
///
/// # Arguments
///
/// * `chain` - The process's namespace membership chain
///
/// # Returns
///
/// The owning namespace (last in chain)
pub fn owning_namespace(chain: &[PidNamespaceMembership]) -> Option<PidNamespaceArc> {
    chain.last().map(|m| m.ns.clone())
}

/// Get the PID as seen from the process's owning namespace.
///
/// # Arguments
///
/// * `chain` - The process's namespace membership chain
///
/// # Returns
///
/// The namespace-local PID in the owning namespace
pub fn pid_in_owning_namespace(chain: &[PidNamespaceMembership]) -> Option<ProcessId> {
    chain.last().map(|m| m.pid)
}

/// Check if a process is visible from a namespace.
///
/// Processes are visible in their owning namespace and all ancestors.
///
/// # Arguments
///
/// * `target_ns` - The namespace to check visibility from
/// * `chain` - The process's namespace membership chain
pub fn is_visible_in_namespace(
    target_ns: &PidNamespaceArc,
    chain: &[PidNamespaceMembership],
) -> bool {
    chain.iter().any(|m| Arc::ptr_eq(&m.ns, target_ns))
}

/// Get all namespaces that need cascade kill when init exits.
///
/// When init of a namespace exits, all processes in that namespace
/// and its descendants must be killed.
///
/// # Arguments
///
/// * `ns` - The namespace whose init is exiting
///
/// # Returns
///
/// Global PIDs of all processes to kill
pub fn get_cascade_kill_pids(ns: &PidNamespaceArc) -> AdmittedVec<ProcessId> {
    // Keep the legacy best-effort API, but route it through the fallible
    // traversal so no allocation or upgraded-Arc drop can occur under a
    // namespace lifecycle lock. Production teardown uses the Result form.
    get_cascade_kill_pids_fallible(ns).unwrap_or_else(|_| AdmittedVec::new(HeapClass::CoreProcess))
}

/// R171-S-R170-5-01 FIX (SLICE 3): Fallible sibling of `get_cascade_kill_pids`.
///
/// Identical subtree traversal and init-filter, but every `Vec` growth uses
/// `try_reserve`, so enumerating the victims of an init-death cascade can never
/// panic on OOM. A panic here would unwind out of `terminate_process` BEFORE
/// `teardown_done` is published — precisely the teardown-abandonment class this
/// slice eliminates. On allocation failure the caller logs and skips the cascade
/// (a logged leak of un-cascaded members) rather than abandoning teardown.
pub fn get_cascade_kill_pids_fallible(
    ns: &PidNamespaceArc,
) -> Result<AdmittedVec<ProcessId>, PidNamespaceError> {
    let mut pids = AdmittedVec::new(HeapClass::CoreProcess);
    let mut stack = AdmittedVec::new(HeapClass::CoreProcess);
    stack
        .try_reserve(1)
        .map_err(|_| PidNamespaceError::OutOfMemory)?;
    stack
        .push_reserved(Arc::clone(ns))
        .map_err(|_| PidNamespaceError::OutOfMemory)?;

    while let Some(cur) = stack.pop() {
        // Get all members of this namespace (except init itself) — same @595 filter.
        let init_pid = cur.init_global_pid();
        let mut tmp = AdmittedVec::new(HeapClass::CoreProcess);
        cur.members_into(&mut tmp)?;
        for g in tmp {
            if init_pid != Some(g) {
                pids.try_reserve(1)
                    .map_err(|_| PidNamespaceError::OutOfMemory)?;
                pids.push_reserved(g)
                    .map_err(|_| PidNamespaceError::OutOfMemory)?;
            }
        }

        // Traverse child namespaces through the reserve-before-upgrade helper.
        append_live_children(&cur, &mut stack)?;
    }

    Ok(pids)
}

// ============================================================================
// Debug Helpers
// ============================================================================

/// Print namespace hierarchy for debugging.
pub fn print_namespace_info(ns: &PidNamespaceArc) {
    kprintln!(
        "[PID NS] id={}, level={}, members={}, init={:?}, shutting_down={}",
        ns.id().raw(),
        ns.level(),
        ns.member_count(),
        ns.init_global_pid(),
        ns.is_shutting_down()
    );
}

/// Print a process's namespace chain for debugging.
pub fn print_pid_chain(chain: &[PidNamespaceMembership]) {
    print!("[PID chain] ");
    for (i, m) in chain.iter().enumerate() {
        if i > 0 {
            print!(" -> ");
        }
        print!("ns{}:pid{}", m.ns.id().raw(), m.pid);
    }
    kprintln!();
}

/// R180-22 executable probe for the child-creation/shutdown linearization
/// contract. Once shutdown wins, neither construction nor commit publication
/// may treat the namespace as a live source.
pub fn run_shutdown_creation_self_test() {
    // RF180-43: an external Weak must retain exactly the outer Arc charge after
    // payload destruction, and the charge may be released only after the Weak
    // triggers physical ArcInner deallocation.
    let lifetime_parent =
        PidNamespace::new_child(ROOT_PID_NAMESPACE.clone()).expect("RF180-43 lifetime-test parent");
    let lifetime_before = mm::heap_class_snapshot(HeapClass::CoreProcess);
    let count_before = PID_NS_COUNT.load(Ordering::SeqCst);
    let slots_before = active_pid_namespace_arc_slots();
    let outer_bytes = arc_charge_bytes::<PidNamespace>()
        .expect("RF180-43 PID namespace Arc charge must be representable");
    let lifetime_child = PidNamespace::new_child(Arc::clone(&lifetime_parent))
        .expect("RF180-43 lifetime-test child");
    let lifetime_weak: PidNamespaceWeak = Arc::downgrade(&lifetime_child);
    drop(lifetime_child);
    assert!(lifetime_weak.upgrade().is_none());
    assert!(lifetime_parent.children.lock().is_empty());
    assert_eq!(PID_NS_COUNT.load(Ordering::SeqCst), count_before);
    assert_eq!(active_pid_namespace_arc_slots(), slots_before + 1);
    let after_strong = mm::heap_class_snapshot(HeapClass::CoreProcess);
    assert_eq!(after_strong.reserved_bytes, lifetime_before.reserved_bytes);
    assert_eq!(
        after_strong.committed_bytes,
        lifetime_before
            .committed_bytes
            .checked_add(outer_bytes)
            .expect("RF180-43 lifetime snapshot arithmetic"),
        "RF180-43 final Weak must retain exactly the outer Arc charge"
    );
    drop(lifetime_weak);
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::CoreProcess),
        lifetime_before,
        "RF180-43 final Weak must deallocate before releasing admission"
    );
    assert_eq!(active_pid_namespace_arc_slots(), slots_before);

    // A forced outer allocation failure exercises the old double-decrement
    // edge twice. Count, allocator slots, registry, and ledger must remain exact.
    let arc_failure_parent =
        PidNamespace::new_child(ROOT_PID_NAMESPACE.clone()).expect("RF180-43 Arc-failure parent");
    let arc_failure_before = mm::heap_class_snapshot(HeapClass::CoreProcess);
    let arc_failure_count = PID_NS_COUNT.load(Ordering::SeqCst);
    let arc_failure_slots = active_pid_namespace_arc_slots();
    for _ in 0..2 {
        assert!(matches!(
            PidNamespace::new_child_with_fault(
                Arc::clone(&arc_failure_parent),
                PidNamespaceCreateFault {
                    fail_arc_allocation: true,
                    ..PidNamespaceCreateFault::default()
                },
            ),
            Err(PidNamespaceError::OutOfMemory)
        ));
        assert_eq!(PID_NS_COUNT.load(Ordering::SeqCst), arc_failure_count);
        assert_eq!(active_pid_namespace_arc_slots(), arc_failure_slots);
        assert!(arc_failure_parent.children.lock().is_empty());
        assert_eq!(
            mm::heap_class_snapshot(HeapClass::CoreProcess),
            arc_failure_before
        );
    }

    // Registry backing failure occurs with the lifecycle mutex available and
    // rolls the fully constructed child Arc/count/charge back exactly.
    let registry_parent = PidNamespace::new_child(ROOT_PID_NAMESPACE.clone())
        .expect("RF180-43 registry-failure parent");
    let registry_before = mm::heap_class_snapshot(HeapClass::CoreProcess);
    let registry_count = PID_NS_COUNT.load(Ordering::SeqCst);
    let registry_slots = active_pid_namespace_arc_slots();
    assert!(matches!(
        PidNamespace::new_child_with_fault(
            Arc::clone(&registry_parent),
            PidNamespaceCreateFault {
                fail_child_registry_growth: true,
                check_child_prepare_unlocked: true,
                ..PidNamespaceCreateFault::default()
            },
        ),
        Err(PidNamespaceError::OutOfMemory)
    ));
    assert!(registry_parent.children.lock().is_empty());
    assert_eq!(PID_NS_COUNT.load(Ordering::SeqCst), registry_count);
    assert_eq!(active_pid_namespace_arc_slots(), registry_slots);
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::CoreProcess),
        registry_before
    );

    // Fail the second detached PID-map leg. Neither first-leg backing nor map,
    // counter, init, or heap state may change.
    let map_failure_ns = PidNamespace::new_child(ROOT_PID_NAMESPACE.clone())
        .expect("RF180-43 map-failure namespace");
    let map_failure_before = mm::heap_class_snapshot(HeapClass::CoreProcess);
    let next_before = *map_failure_ns.next_pid.lock();
    assert_eq!(
        map_failure_ns.alloc_pid_with_fault(
            0x180_4301,
            PidMappingPrepareFault {
                fail_second_map: true,
                check_prepare_unlocked: true,
            },
        ),
        Err(PidNamespaceError::OutOfMemory)
    );
    assert_eq!(*map_failure_ns.next_pid.lock(), next_before);
    assert_eq!(map_failure_ns.pid_by_global.lock().len(), 0);
    assert_eq!(map_failure_ns.pid_by_global.lock().capacity(), 0);
    assert_eq!(map_failure_ns.pid_by_ns.lock().len(), 0);
    assert_eq!(map_failure_ns.pid_by_ns.lock().capacity(), 0);
    assert_eq!(map_failure_ns.init_global_pid(), None);
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::CoreProcess),
        map_failure_before
    );

    let parent = PidNamespace::new_child(ROOT_PID_NAMESPACE.clone())
        .expect("pid namespace self-test parent");
    assert!(parent.mark_shutting_down());
    assert!(matches!(
        PidNamespace::new_child(Arc::clone(&parent)),
        Err(PidNamespaceError::NamespaceShuttingDown)
    ));
    assert!(matches!(
        parent.with_live_child_source(|| ()),
        Err(PidNamespaceError::NamespaceShuttingDown)
    ));

    // RF180-16: a mapped PID may be published only while every non-root
    // namespace source lock is held. Prove both deterministic orderings:
    // publication-first owns the same mutex shutdown needs, while
    // shutdown-first prevents the publication callback from running.
    let live = PidNamespace::new_child(ROOT_PID_NAMESPACE.clone())
        .expect("pid namespace publication self-test");
    let global_pid = 0x180_2201;
    let chain =
        assign_pid_chain(Arc::clone(&live), global_pid).expect("pid namespace publication chain");
    let sources =
        PidPublicationSources::from_chain(&chain).expect("canonical publication source snapshot");
    let mut published = false;
    sources
        .with_live_publication(|| {
            assert!(
                live.children.try_lock().is_none(),
                "publication must own the shutdown linearization lock"
            );
            published = true;
        })
        .expect("live namespace must permit publication");
    assert!(published);
    assert!(live.mark_shutting_down());
    let mut escaped = false;
    assert!(matches!(
        sources.with_live_publication(|| escaped = true),
        Err(PidNamespaceError::NamespaceShuttingDown)
    ));
    assert!(!escaped, "shutdown-first creator must not publish a PCB");
    detach_pid_chain(&chain, global_pid);

    // RF180-43: reserve failure occurs outside the parent lifecycle mutex and
    // before any Weak upgrade. Dropping the last child Arc after that failure
    // must therefore never re-enter a lock held by the snapshot path.
    let drop_parent = PidNamespace::new_child(ROOT_PID_NAMESPACE.clone())
        .expect("pid namespace drop-order parent");
    let drop_child =
        PidNamespace::new_child(Arc::clone(&drop_parent)).expect("pid namespace drop-order child");
    let mut snapshot = AdmittedVec::new(HeapClass::CoreProcess);
    let forced_failure =
        append_live_children_with_reservation(&drop_parent, &mut snapshot, |_stack, additional| {
            assert_eq!(additional, 1);
            assert!(drop_parent.children.try_lock().is_some());
            assert_eq!(Arc::strong_count(&drop_child), 1);
            Err::<(), ()>(())
        });
    assert_eq!(forced_failure, Err(()));
    assert!(snapshot.is_empty());
    assert_eq!(Arc::strong_count(&drop_child), 1);
    assert!(drop_parent.children.try_lock().is_some());
    drop(drop_child);
    assert!(drop_parent.children.lock().is_empty());
}

// ============================================================================
// R76-2 FIX: Namespace Resource Cleanup
// ============================================================================

/// RF180-43: detach the exact child Weak and any now-empty registry backing
/// while protected, then perform all destructors and allocator work after the
/// parent lifecycle mutex is released. The count permit is a payload field and
/// drops exactly once after this custom destructor returns.
impl Drop for PidNamespace {
    fn drop(&mut self) {
        let self_ptr = self as *const PidNamespace;
        if let Some(parent) = self.parent.as_ref() {
            let (removed, retired) = {
                let mut children = parent.children.lock();
                let removed = children
                    .iter()
                    .position(|weak| weak.as_ptr() == self_ptr)
                    .and_then(|index| children.remove_retaining_capacity(index));
                let retired = children.take_empty_capacity();
                (removed, retired)
            };
            drop(removed);
            drop(retired);
        }
    }
}
