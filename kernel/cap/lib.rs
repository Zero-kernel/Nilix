//! Capability subsystem for Zero-OS
//!
//! This module implements a capability-based access control system, providing:
//!
//! - **Non-forgeable Handles**: CapId with generation counters prevent use-after-free
//! - **Rights Restriction**: Capabilities can only delegate reduced rights (monotonic)
//! - **Fork/Exec Semantics**: CLOEXEC/CLOFORK flags control inheritance
//! - **IRQ-Safe**: All operations use spinlocks with interrupt disable
//!
//! # Security Note (R66-9)
//!
//! The `CapTable` methods (`allocate`, `revoke`, `delegate`) are low-level APIs
//! that do NOT call LSM hooks or emit audit events directly. This is intentional:
//!
//! 1. **Fork inheritance**: Capability duplication during fork must bypass policy checks
//!    (the policy was already checked when the parent acquired the capability).
//!
//! 2. **Separation of concerns**: LSM and audit integration lives in the syscall layer
//!    (`kernel_core/syscall.rs`), not in the capability table implementation.
//!
//! **Callers MUST:**
//! - Call `lsm::hook_task_cap_modify()` BEFORE capability operations for user-initiated requests
//! - Call `audit::emit_capability_event()` AFTER successful operations
//!
//! The syscall handlers (`sys_cap_allocate`, `sys_cap_revoke`, etc.) already do this.
//! Internal kernel paths (fork, exec) are allowed to bypass these hooks.
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+
//! | User Space       |     | CapId (u64)      |
//! | (holds CapId)    | --> | gen:32 | idx:32  |
//! +------------------+     +------------------+
//!                                  |
//!                                  v
//! +--------------------------------------------------+
//! | Per-Process CapTable                             |
//! | +----------------------------------------------+ |
//! | | Slot 0: None                                 | |
//! | | Slot 1: Some(gen=5, CapEntry{File, RW})      | |
//! | | Slot 2: Some(gen=3, CapEntry{Endpoint, R})   | |
//! | | ...                                          | |
//! | +----------------------------------------------+ |
//! | Free list: [0, 3, 4, ...]                        |
//! +--------------------------------------------------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // Allocate a capability for a file object
//! let cap_id = table.allocate(CapEntry::new(
//!     CapObject::File(file_arc),
//!     CapRights::RW,
//! ))?;
//!
//! // Lookup and validate
//! let entry = table.lookup(cap_id)?;
//! if entry.allows(CapRights::WRITE) {
//!     // Perform write operation
//! }
//!
//! // Revoke when done
//! table.revoke(cap_id)?;
//! ```
//!
//! # Security Design
//!
//! 1. **Generation Counter**: Each slot has a generation counter that increments
//!    on revocation. A CapId is only valid if its generation matches the slot.
//!
//! 2. **Monotonic Rights**: During delegation, rights can only be reduced.
//!    `new_rights = old_rights & mask`
//!
//! 3. **Audit Integration**: All capability operations are logged to the audit
//!    subsystem for security monitoring (via syscall layer hooks).

#![no_std]
#![allow(clippy::collapsible_if)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::result_unit_err)]
#![feature(allocator_api)]

extern crate alloc;

extern crate drivers;
#[macro_use]
extern crate klog;

use alloc::{sync::Arc, vec::Vec};
use mm::{
    arc_charge_bytes, try_reserve_heap, vec_charge_bytes, HeapCharge, HeapClass, HeapReservation,
};
use spin::Mutex;
use x86_64::instructions::interrupts;

pub mod types;

pub use types::{
    CapEntry, CapError, CapFlags, CapId, CapObject, CapRights, EndpointId, FileOps, NamespaceId,
    Pipe, PipeEndType, ProcessId, RegularFile, Shm, Socket, Timer,
};

// ============================================================================
// Configuration
// ============================================================================

/// Default slot reservation when creating a capability table.
pub const DEFAULT_CAP_SLOTS: usize = 64;

/// Maximum slots per capability table (prevents memory exhaustion).
/// R30-1 FIX: Reduced from 65536 to 65535 to match u16 index range (0..65535).
pub const MAX_CAP_SLOTS: usize = 65535;

// ============================================================================
// Capability Table
// ============================================================================

/// Per-process capability table protected by a spinlock for IRQ safety.
///
/// Each process has its own CapTable. The table maps CapId slot indices
/// to CapEntry objects. Generation counters prevent use-after-free.
///
/// # U.S3 Refcount Invariant (relaxed for U.S2-SLICE-3, CRITICAL-8)
///
/// For fd-BACKED caps (`CapObject::is_fd_backed()`: Socket/Pipe/RegularFile):
/// - **During allocation:** `refcount >= fd-count` — the cap is allocated
///   under the owning `Process` lock BEFORE its fd is installed (sys_socket,
///   sys_pipe), so a concurrent CLONE_THREAD sibling inspecting the SHARED
///   table can observe a cap with refcount=1 and no fd yet. This in-flight
///   window (microseconds, bounded by the Process lock hold) is INTENTIONAL
///   and SAFE: any future cap-introspection surface must tolerate
///   `refcount > fd-count` as a normal allocation window, not an error.
/// - **Post-install:** `refcount == fd-count` — one reference per fd carrying
///   the CapId (dup/F_DUPFD/CLONE_THREAD bump; close/exec/exit decrement via
///   the `decrement_fd_cap` funnel, revoke at 0).
/// - **During I/O:** transient FileOps clones do NOT bump refcount (U.S3-A2
///   clone purity); a cap may be revoked while a transient clone is in flight
///   (see the FileOps trait contract in kernel_core::process).
///
/// # Panic Safety (U.S2-SLICE-3, CRITICAL-14)
///
/// If a panic occurred between cap allocation and fd installation, the slot
/// would remain allocated with refcount=1 and no fd — an orphan that no
/// funnel would ever revoke. The workspace root Cargo.toml enforces
/// `panic = "abort"` for BOTH dev and release profiles, so unwinding past
/// the allocation window cannot happen in any build configuration: a panic
/// is an unrecoverable kernel halt and the leak class cannot materialize.
#[derive(Debug)]
pub struct CapTable {
    inner: Mutex<CapTableInner>,
    /// Charge for the `Arc<CapTable>` allocation used by production process
    /// tables. Declared after `inner`, so all vector backing is destroyed first.
    _arc_charge: Option<HeapCharge>,
}

/// Internal table state guarded by the CapTable lock.
#[derive(Debug)]
struct CapTableInner {
    /// Slots holding capability entries.
    slots: Vec<Option<CapSlot>>,

    /// Free slot indices for fast allocation.
    /// R29-4 FIX: Changed from u32 to u16 to match new CapId encoding.
    free: Vec<u16>,

    /// Lifetime charges for the exact retained vector capacities. The vectors
    /// are declared first so their allocations are deallocated before uncharge.
    slots_charge: Option<HeapCharge>,
    free_charge: Option<HeapCharge>,

    /// Next generation counter (monotonically increasing).
    /// R29-4 FIX: Extended from u32 to u64 (48 bits used, ~281 trillion allocations).
    /// Starts at 1; generation 0 is reserved for INVALID.
    next_generation: u64,

    /// RF180-37: capability identities removed from `free` but not yet
    /// published in `slots`. A prepared socket/accept transaction owns each
    /// reservation and either installs it allocation-free or returns it through
    /// Drop. Empty-table backing must not be reclaimed while this is non-zero.
    reserved_allocations: usize,
}

/// Detached ownership of one unpublished capability-table slot.
///
/// RF180-37: socket and accept publication reserve capability capacity and a
/// generation before creating/dequeuing network state. The slot remains absent
/// from lookup/iteration until [`PreparedCapAllocation::install`], and Drop
/// returns it to the free list without publishing an entry.
#[must_use = "dropping a prepared capability allocation cancels its unpublished slot"]
pub struct PreparedCapAllocation<'a> {
    table: &'a CapTable,
    index: u16,
    generation: u64,
    active: bool,
}

impl PreparedCapAllocation<'_> {
    /// R186-1 FIX: the exact identity this reservation will publish.
    ///
    /// `reserve_allocation` consumes both the slot index and the generation up
    /// front, and `install_reserved` derives the published id from precisely
    /// those two values, so this is the same `CapId` that [`Self::install`]
    /// returns — a read of committed reservation state, not a prediction.
    ///
    /// Exposing it lets a caller bind the id into the object being published
    /// (for example `FileOps::set_cap_id`) while the reservation is still
    /// rollback-armed, so every fallible step of a publication transaction can
    /// precede every irreversible one.
    #[inline]
    pub fn cap_id(&self) -> CapId {
        CapId::from_parts(self.index, self.generation)
    }

    /// Publish into the already-reserved identity. This performs no allocation
    /// and cannot return a recoverable error; a mismatch is table corruption.
    pub fn install(mut self, entry: CapEntry) -> CapId {
        let cap_id = interrupts::without_interrupts(|| {
            let mut inner = self.table.inner.lock();
            inner.install_reserved(self.index, self.generation, entry)
        });
        self.active = false;
        cap_id
    }
}

impl Drop for PreparedCapAllocation<'_> {
    fn drop(&mut self) {
        if self.active {
            interrupts::without_interrupts(|| {
                let mut inner = self.table.inner.lock();
                inner.cancel_reserved(self.index);
            });
        }
    }
}

struct PreparedCapVec<T> {
    values: Vec<T>,
    reservation: HeapReservation,
}

fn prepare_cap_vec<T>(capacity: usize) -> Result<PreparedCapVec<T>, CapError> {
    let estimated = vec_charge_bytes::<T>(capacity).map_err(|_| CapError::OutOfMemory)?;
    let mut reservation =
        try_reserve_heap(HeapClass::Capability, estimated).map_err(|_| CapError::OutOfMemory)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| CapError::OutOfMemory)?;
    let actual = vec_charge_bytes::<T>(values.capacity()).map_err(|_| CapError::OutOfMemory)?;
    reservation
        .resize(actual)
        .map_err(|_| CapError::OutOfMemory)?;
    Ok(PreparedCapVec {
        values,
        reservation,
    })
}

fn install_cap_vec<T>(
    live: &mut Vec<T>,
    charge: &mut Option<HeapCharge>,
    mut prepared: PreparedCapVec<T>,
) {
    assert!(
        prepared.values.capacity() >= live.len(),
        "R180-7 capability replacement backing too small"
    );
    let replacement_charge = prepared
        .reservation
        .commit()
        .expect("R180-7 capability heap ledger corrupt during commit");
    let mut old = core::mem::take(live);
    for value in old.drain(..) {
        prepared.values.push(value);
    }
    // R180-7 FIX: deallocate the old allocator backing before releasing its
    // lifetime charge. No table mutation can allocate after this handoff.
    drop(old);
    let old_charge = charge.take();
    *live = prepared.values;
    *charge = Some(replacement_charge);
    drop(old_charge);
}

/// RF186-24 FIX: choose bounded amortized backing without doubling the default
/// floor itself. Empty-table regrowth must retain the same default capacity as
/// a fresh production table (64, not 128), while established tables still grow
/// geometrically and all paths remain capped by the u16 slot domain.
#[inline]
fn cap_growth_target(current_capacity: usize, required: usize) -> usize {
    debug_assert!(required <= MAX_CAP_SLOTS);
    current_capacity
        .checked_mul(2)
        .unwrap_or(MAX_CAP_SLOTS)
        .clamp(DEFAULT_CAP_SLOTS, MAX_CAP_SLOTS)
        .max(required)
}

/// Slot ties a capability entry to its generation counter.
#[derive(Debug)]
struct CapSlot {
    /// R29-4 FIX: Generation counter for this slot (matches CapId.generation).
    /// Extended to u64 to support 48-bit generation space.
    generation: u64,

    /// The actual capability entry.
    entry: CapEntry,
}

impl Clone for CapSlot {
    /// U.S3-A1 FIX: VERBATIM-copy the refcount; do NOT touch the source entry.
    ///
    /// `try_clone_for_fork` deep-copies the parent's cap_table into a SEPARATE
    /// table with its OWN `Arc` (fork / non-thread CLONE_FILES). The child slot's
    /// refcount must equal the number of CHILD fds that reference it — which,
    /// immediately post-fork, equals the parent's CURRENT count, because the child
    /// `fd_table` is a 1:1 copy of the parent's (fork.rs deep-copy loop) and
    /// `clone_box` no longer bumps the cap (U.S3-A2). So we copy the parent's
    /// current refcount into the child's fresh `AtomicUsize` and leave the parent
    /// entry UNCHANGED.
    ///
    /// The prior U.S2-SLICE-2 code called `self.entry.increment_refcount()` here,
    /// which (a) bumped the PARENT entry (→ parent slot never reaches 0 on last
    /// close → permanent leak) AND (b) seeded the child from the post-increment
    /// value (→ child over-count). Combined with the (now-removed) `clone_box`
    /// bump, a single forked socket fd reached parent=3/child=3 for 1 fd each,
    /// so last-close revocation could never fire → `TableFull` DoS. This is the
    /// SOLE fork-side refcount edge; per-fd dup/thread increments are explicit at
    /// the call sites (U.S3-A3).
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            // Shallow copy of the object handle (Arc clone) + a fresh refcount
            // atomic seeded with the source's CURRENT (un-incremented) value.
            entry: CapEntry {
                object: self.entry.object.clone(),
                rights: self.entry.rights,
                flags: self.entry.flags,
                refcount: core::sync::atomic::AtomicUsize::new(self.entry.refcount()),
            },
        }
    }
}

impl CapTable {
    /// Create an empty capability table with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAP_SLOTS)
    }

    /// Fallible production constructor. The table's two retained vectors and
    /// outer Arc are admitted before allocation and charged for exact capacity.
    pub fn try_new_arc() -> Result<Arc<Self>, CapError> {
        let arc_bytes = arc_charge_bytes::<CapTable>().map_err(|_| CapError::OutOfMemory)?;
        let arc_reservation = try_reserve_heap(HeapClass::Capability, arc_bytes)
            .map_err(|_| CapError::OutOfMemory)?;
        let inner = CapTableInner::try_with_capacity(DEFAULT_CAP_SLOTS)?;
        let arc_charge = arc_reservation
            .commit()
            .map_err(|_| CapError::OutOfMemory)?;
        Arc::try_new(Self {
            inner: Mutex::new(inner),
            _arc_charge: Some(arc_charge),
        })
        .map_err(|_| CapError::OutOfMemory)
    }

    /// Create an empty capability table with explicit initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.min(MAX_CAP_SLOTS);
        Self {
            inner: Mutex::new(CapTableInner::with_capacity(capacity)),
            _arc_charge: None,
        }
    }

    /// Allocate a new capability, returning its CapId.
    ///
    /// # Arguments
    ///
    /// * `entry` - The capability entry to store
    ///
    /// # Returns
    ///
    /// * `Ok(CapId)` - The allocated capability identifier
    /// * `Err(CapError::TableFull)` - No more slots available
    pub fn allocate(&self, entry: CapEntry) -> Result<CapId, CapError> {
        interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();
            inner.allocate(entry)
        })
    }

    /// RF180-37: reserve all capability-table resources before an external
    /// object is published. The returned token is invisible to lookup and
    /// guarantees that `install` is allocation-free and infallible.
    pub fn prepare_allocation(&self) -> Result<PreparedCapAllocation<'_>, CapError> {
        let (index, generation) = interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();
            inner.reserve_allocation()
        })?;
        Ok(PreparedCapAllocation {
            table: self,
            index,
            generation,
            active: true,
        })
    }

    /// Look up a capability by its ID.
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The capability identifier to look up
    ///
    /// # Returns
    ///
    /// * `Ok(&CapEntry)` - Reference to the capability entry
    /// * `Err(CapError::InvalidCapId)` - CapId is invalid or revoked
    pub fn lookup(&self, cap_id: CapId) -> Result<CapEntry, CapError> {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            let entry = inner.lookup(cap_id)?;
            // U.S2-SLICE-2: Manually copy CapEntry fields since AtomicUsize isn't Clone.
            // This creates a snapshot with the current refcount value (no increment).
            Ok(CapEntry {
                object: entry.object.clone(),
                rights: entry.rights,
                flags: entry.flags,
                refcount: core::sync::atomic::AtomicUsize::new(entry.refcount()),
            })
        })
    }

    /// Revoke a capability, making its CapId invalid.
    ///
    /// The slot is returned to the free list with an incremented
    /// generation counter, preventing any stale CapId from being used.
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The capability identifier to revoke
    ///
    /// # Returns
    ///
    /// * `Ok(CapEntry)` - The revoked capability entry
    /// * `Err(CapError::InvalidCapId)` - CapId is invalid or already revoked
    pub fn revoke(&self, cap_id: CapId) -> Result<CapEntry, CapError> {
        interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();
            inner.revoke(cap_id)
        })
    }

    /// Delegate a capability with restricted rights.
    ///
    /// Creates a new capability pointing to the same object but with
    /// rights masked (reduced). The original capability remains valid.
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The source capability to delegate from
    /// * `rights_mask` - Rights to retain (AND with existing rights)
    /// * `flags` - Flags for the new capability
    ///
    /// # Returns
    ///
    /// * `Ok(CapId)` - The new delegated capability
    /// * `Err(CapError::InvalidCapId)` - Source CapId is invalid
    /// * `Err(CapError::DelegationDenied)` - Source has NOXFER flag
    /// * `Err(CapError::TableFull)` - No slots available
    pub fn delegate(
        &self,
        cap_id: CapId,
        rights_mask: CapRights,
        flags: CapFlags,
    ) -> Result<CapId, CapError> {
        interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();
            inner.delegate(cap_id, rights_mask, flags)
        })
    }

    /// Check if a capability has the required rights.
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The capability to check
    /// * `required` - The rights required for the operation
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Capability has all required rights
    /// * `Ok(false)` - Capability lacks some required rights
    /// * `Err(CapError::InvalidCapId)` - CapId is invalid
    pub fn check_rights(&self, cap_id: CapId, required: CapRights) -> Result<bool, CapError> {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            let entry = inner.lookup(cap_id)?;
            Ok(entry.allows(required))
        })
    }

    /// U.S2-SLICE-2: Increment refcount for a capability (dup/fork).
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The capability to increment
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Refcount incremented successfully
    /// * `Err(CapError::InvalidCapId)` - CapId is invalid or revoked
    pub fn increment_refcount(&self, cap_id: CapId) -> Result<(), CapError> {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            let entry = inner.lookup(cap_id)?;
            entry.increment_refcount();
            Ok(())
        })
    }

    /// U.S2-SLICE-2: Decrement refcount for a capability (close).
    /// Returns true if refcount reached 0 (caller should revoke).
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The capability to decrement
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Refcount reached 0, should revoke
    /// * `Ok(false)` - Refcount > 0, do not revoke yet
    /// * `Err(CapError::InvalidCapId)` - CapId is invalid or revoked
    pub fn decrement_refcount(&self, cap_id: CapId) -> Result<bool, CapError> {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            let entry = inner.lookup(cap_id)?;
            Ok(entry.decrement_refcount())
        })
    }

    /// U.S3-SLICE-2: Get the current refcount for a capability (self-test only).
    ///
    /// # Arguments
    ///
    /// * `cap_id` - The capability to query
    ///
    /// # Returns
    ///
    /// * `Some(count)` - The current refcount
    /// * `None` - CapId is invalid or revoked
    pub fn get_refcount(&self, cap_id: CapId) -> Option<usize> {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            let entry = inner.lookup(cap_id).ok()?;
            Some(entry.refcount())
        })
    }

    /// Check if any capability in the table grants the required rights.
    ///
    /// Used by ambient gates such as audit snapshot export to check if
    /// the current process has CAP_AUDIT_READ or similar rights.
    ///
    /// # Arguments
    ///
    /// * `required` - The rights to check for
    ///
    /// # Returns
    ///
    /// true if any capability in the table grants the required rights
    pub fn has_rights(&self, required: CapRights) -> bool {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            inner
                .slots
                .iter()
                .flatten()
                .any(|slot| slot.entry.allows(required))
        })
    }

    /// Get the number of active capabilities.
    pub fn len(&self) -> usize {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            inner.slots.iter().filter(|s| s.is_some()).count()
        })
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clone capabilities for fork, respecting CLOFORK flags.
    ///
    /// Returns a new CapTable with copies of all capabilities that
    /// should be inherited (those without CLOFORK flag).
    ///
    /// # Generation Counter Preservation
    ///
    /// The child table inherits the parent's `next_generation` counter
    /// to maintain the monotonic property across fork. This prevents
    /// early generation wrap in the child process.
    // R161-4 FIX: Return Result instead of infallible Self. The old
    // with_capacity used vec![None; capacity] which panics under OOM
    // with up to MAX_CAP_SLOTS=65535 entries.
    pub fn try_clone_for_fork(&self) -> Result<Self, ()> {
        interrupts::without_interrupts(|| {
            let inner = self.inner.lock();
            let capacity = inner.slots.len().min(MAX_CAP_SLOTS);
            let arc_bytes = arc_charge_bytes::<CapTable>().map_err(|_| ())?;
            let arc_reservation =
                try_reserve_heap(HeapClass::Capability, arc_bytes).map_err(|_| ())?;
            let mut slots_prepared =
                prepare_cap_vec::<Option<CapSlot>>(capacity).map_err(|_| ())?;
            for _ in 0..capacity {
                slots_prepared.values.push(None);
            }
            let free_prepared = prepare_cap_vec::<u16>(capacity).map_err(|_| ())?;

            let mut new_inner = CapTableInner {
                slots: slots_prepared.values,
                free: free_prepared.values,
                slots_charge: Some(slots_prepared.reservation.commit().map_err(|_| ())?),
                free_charge: Some(free_prepared.reservation.commit().map_err(|_| ())?),
                next_generation: inner.next_generation,
                reserved_allocations: 0,
            };

            for (idx, slot_opt) in inner.slots.iter().enumerate() {
                if let Some(slot) = slot_opt {
                    if slot.entry.inherits_on_fork() {
                        new_inner.slots[idx] = Some(slot.clone());
                    }
                }
            }

            new_inner.rebuild_free_list();

            // A CLOFORK-only parent can yield a completely empty child table.
            // Return all unused backing rather than retaining a high-water
            // allocation that no child capability owns.
            new_inner.reclaim_if_unused();

            let arc_charge = arc_reservation.commit().map_err(|_| ())?;

            Ok(Self {
                inner: Mutex::new(new_inner),
                _arc_charge: Some(arc_charge),
            })
        })
    }

    /// U.S3-SLICE-2: reconcile child cap_table refcounts after fork to match the
    /// child's ACTUAL fd count (fixes the thread-shared parent over-count).
    ///
    /// When the parent is a CLONE_THREAD thread sharing its cap_table Arc with
    /// siblings, CapSlot::clone copies refcounts VERBATIM (U.S3-A1) including
    /// sibling-held references, but fork's fd_table copy gives the child ONLY
    /// the forking thread's fds → over-count → child-local slot leak. This
    /// method OVERWRITES each fd-backed CapEntry.refcount to equal
    /// `child_counts[cid]` (the histogram fork.rs built from the child's
    /// fd_table).
    ///
    /// # Contract (single call site: fork.rs)
    ///
    /// Called on the child's PRIVATE table (fresh from `try_clone_for_fork`,
    /// not yet wrapped in Arc, not visible to any other task) while the parent
    /// Process lock is held. There is NO thread-shared caller: a CLONE_THREAD
    /// child shares the parent's table Arc and pays explicit per-fd increments
    /// at its install site instead (U.S3-A3) — it never reconciles. Because
    /// the table is private, no concurrent decrement can race the overwrite
    /// (the design-v3 CRITICAL-9 race is structurally absent here).
    ///
    /// # U.S2-SLICE-3 (CRITICAL-9 fix): revoke fd-backed orphans
    ///
    /// A cap the child does NOT hold any fd for (`child_fd_count == 0`,
    /// parent/sibling-only) previously kept its slot with refcount=0 forever:
    /// no child fd will ever funnel a decrement through it, so the slot was
    /// permanently lost (child-local slot leak → TableFull DoS class). Now it
    /// is REVOKED immediately — safe in-lock because the revoke scope is
    /// limited to PLAIN-DATA fd-backed variants (`CapObject::is_fd_backed()`:
    /// Socket/Pipe/RegularFile — dropping them has zero side effects), and
    /// safe semantically because generation monotonicity keeps any stale
    /// parent CapId invalid in the child even after slot reuse
    /// (`next_generation` was inherited from the parent).
    ///
    /// # BV-3 scoping: NON-fd-backed caps stay VERBATIM
    ///
    /// Endpoint/Process/Namespace/Shm/Timer (and the construction-less
    /// `File(Arc<dyn FileOps>)`) refcounts are NOT fd counts — overwriting
    /// them from an fd histogram (the pre-SLICE-3 behavior zeroed them) or
    /// revoking them would corrupt their independent lifecycle the moment a
    /// non-fd allocation site lands. They are left untouched: the child
    /// inherits them exactly as `try_clone_for_fork` copied them.
    pub fn reconcile_refcounts_after_fork(&mut self, child_counts: &[(CapId, usize)]) {
        interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();
            // Index loop (the apply_cloexec style) — ZERO allocation under the
            // lock: a collect-then-revoke Vec would infallibly push under the
            // table spinlock on the FORK path, re-introducing the fatal-OOM
            // class R161-4/R157-3 eliminated from fork. `revoke`'s `free.push`
            // is allocation-free by INV-CAP-FREELIST-CAP (R172-06).
            for idx in 0..inner.slots.len() {
                let action = match &inner.slots[idx] {
                    // BV-3: only fd-lifecycle-managed caps are reconciled.
                    Some(slot) if slot.entry.object.is_fd_backed() => {
                        let cid = CapId::from_parts(idx as u16, slot.generation);
                        let child_fd_count = child_counts
                            .binary_search_by_key(&cid, |entry| entry.0)
                            .ok()
                            .map(|index| child_counts[index].1)
                            .unwrap_or(0);
                        if child_fd_count == 0 {
                            // CRITICAL-9: no child fd references this cap →
                            // orphan → revoke (below, outside this borrow).
                            Some((cid, 0))
                        } else {
                            Some((cid, child_fd_count))
                        }
                    }
                    _ => None,
                };
                match action {
                    Some((cid, 0)) => {
                        // Revoke in-lock: the table is private (no observer
                        // can race) and the fd-backed scope guarantees a
                        // plain-data drop — no wakeup/re-lock side effect
                        // (the design-v3 Fix 2b "revoke outside lock" concern
                        // does not apply to a private table).
                        let _ = inner.revoke_retaining_capacity(cid);
                    }
                    Some((_, child_fd_count)) => {
                        // Overwrite the verbatim-copied refcount with the
                        // child's actual count.
                        if let Some(slot) = &mut inner.slots[idx] {
                            slot.entry
                                .refcount
                                .store(child_fd_count, core::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    None => {}
                }
            }
            // RF180-37 defense in depth: reclaim only after the fixed-range
            // index walk. Reclaiming from the final in-loop revoke would empty
            // `slots` and make the next loop index panic; live reservations also
            // veto reclamation through `reclaim_if_unused`.
            inner.reclaim_if_unused();
        });
    }

    /// Revoke all capabilities with CLOEXEC flag (for exec).
    ///
    /// Called during exec() to close capabilities that should not
    /// survive across program replacement.
    ///
    /// # Security Note
    ///
    /// Revoked slots are returned to the free list. When reused,
    /// they will get a new (higher) generation counter, preventing
    /// stale CapId references from becoming valid again.
    pub fn apply_cloexec(&self) {
        // Remove one revoked slot at a time, but destroy the detached
        // `CapSlot` only after the cap-table lock is released.  CapEntry
        // variants may own Arcs whose destructors can allocate or take other
        // locks; dropping them under this spinlock was the last single-layer
        // CLOEXEC teardown hazard.
        loop {
            let revoked = interrupts::without_interrupts(|| {
                let mut inner = self.inner.lock();

                // R172-06: INV-CAP-FREELIST-CAP. allocate() now keeps
                // free.capacity() >= slots.len(), so every free.push below
                // is allocation-free past exec's point of no return.
                debug_assert!(
                    inner.free.capacity() >= inner.slots.len(),
                    "R172-06: capability free-list capacity invariant violated"
                );

                let revoked = (0..inner.slots.len()).find_map(|idx| {
                    let revoke = inner.slots[idx]
                        .as_ref()
                        .is_some_and(|slot| !slot.entry.inherits_on_exec());
                    if !revoke {
                        return None;
                    }
                    let old_slot = inner.slots[idx].take()?;
                    inner.free.push(idx as u16);
                    Some(old_slot)
                });
                revoked
            });

            let Some(old_slot) = revoked else { break };
            drop(old_slot);
        }

        // Reclaim empty backing in a second phase, outside the lock that owns
        // the vectors.  This keeps allocator/destructor work out of the cap
        // table critical section while preserving the existing high-water
        // reclamation policy.
        self.reclaim_if_unused_outside_lock();
    }

    fn reclaim_if_unused_outside_lock(&self) {
        let retired = interrupts::without_interrupts(|| {
            let mut inner = self.inner.lock();
            if inner.reserved_allocations != 0 || inner.slots.iter().any(Option::is_some) {
                return None;
            }
            Some((
                core::mem::take(&mut inner.slots),
                core::mem::take(&mut inner.free),
                inner.slots_charge.take(),
                inner.free_charge.take(),
            ))
        });
        drop(retired);
    }
}

impl Default for CapTable {
    fn default() -> Self {
        Self::new()
    }
}

impl CapTableInner {
    fn try_with_capacity(capacity: usize) -> Result<Self, CapError> {
        let capacity = capacity.min(MAX_CAP_SLOTS);
        let mut slots = prepare_cap_vec::<Option<CapSlot>>(capacity)?;
        for _ in 0..capacity {
            slots.values.push(None);
        }
        let mut free = prepare_cap_vec::<u16>(capacity)?;
        free.values.extend((0..capacity).map(|i| i as u16));
        Ok(Self {
            slots: slots.values,
            free: free.values,
            slots_charge: Some(
                slots
                    .reservation
                    .commit()
                    .expect("R180-7 capability slots ledger corrupt"),
            ),
            free_charge: Some(
                free.reservation
                    .commit()
                    .expect("R180-7 capability free-list ledger corrupt"),
            ),
            next_generation: 1,
            reserved_allocations: 0,
        })
    }

    /// Initialize the table state with preallocated slots.
    fn with_capacity(capacity: usize) -> Self {
        // R30-1 FIX: Avoid u16 truncation - capacity limited to MAX_CAP_SLOTS (65535)
        // which is the maximum valid u16 index range (0..65535)
        let capacity = capacity.min(MAX_CAP_SLOTS);
        let slots = alloc::vec![None; capacity];
        // R29-4/R30-1 FIX: Build free list safely without u16 overflow
        let free: Vec<u16> = (0..capacity).map(|i| i as u16).collect();

        Self {
            slots,
            free,
            slots_charge: None,
            free_charge: None,
            next_generation: 1, // Start at 1; 0 is reserved for INVALID
            reserved_allocations: 0,
        }
    }

    /// Allocate a new capability.
    fn allocate(&mut self, entry: CapEntry) -> Result<CapId, CapError> {
        let (index, generation) = self.reserve_allocation()?;
        Ok(self.install_reserved(index, generation, entry))
    }

    /// Reserve one unpublished capability identity and every backing resource
    /// needed to install it. No state visible through lookup is changed.
    fn reserve_allocation(&mut self) -> Result<(u16, u64), CapError> {
        // R29-4/R25-2: consume a unique generation at reservation time so the
        // later publication has no fallible work. Cancellation deliberately
        // does not recycle generations: another allocation may have committed
        // in between, and monotonic stale-ID protection wins over reuse.
        const MAX_GENERATION: u64 = 0x0000_FFFF_FFFF_FFFF;
        if self.next_generation >= MAX_GENERATION {
            return Err(CapError::GenerationExhausted);
        }
        let next_reserved = self
            .reserved_allocations
            .checked_add(1)
            .ok_or(CapError::OutOfMemory)?;

        // Try to get a slot from the free list
        // R29-4 FIX: index is now u16
        let index: u16 = if let Some(idx) = self.free.pop() {
            idx
        } else {
            // Try to grow the table
            if self.slots.len() >= MAX_CAP_SLOTS {
                return Err(CapError::TableFull);
            }
            // R172-06 FIX: grow BOTH `slots` and `free` FALLIBLY before mutating, restoring
            // the invariant INV-CAP-FREELIST-CAP: free.capacity() >= slots.len(). The old
            // `slots.push(None)` was an infallible grow (panic on OOM) AND it never reserved
            // `free`, so after draining the initial 64-slot free list a later
            // `apply_cloexec`/`revoke` `free.push` could reallocate and PANIC — and
            // apply_cloexec runs PAST exec's point-of-no-return (proc.memory_space already
            // overwritten), so the alloc_error_handler abort is an unrecoverable kernel halt.
            // With this, every `free.push` for an existing slot is allocation-free by
            // construction (free already has room for all slots). Both reserves run BEFORE the
            // push, so an OOM leaves the table in its exact prior state (no half-grow).
            let new_len = self
                .slots
                .len()
                .checked_add(1)
                .ok_or(CapError::OutOfMemory)?;
            let current_capacity = self.slots.capacity().max(self.free.capacity());
            let preferred = cap_growth_target(current_capacity, new_len);
            let needs_slots = self.slots.capacity() < new_len;
            let needs_free = self.free.capacity() < new_len;
            let prepare_growth = |capacity| {
                let slots = if needs_slots {
                    Some(prepare_cap_vec::<Option<CapSlot>>(capacity)?)
                } else {
                    None
                };
                let free = if needs_free {
                    Some(prepare_cap_vec::<u16>(capacity)?)
                } else {
                    None
                };
                Ok::<_, CapError>((slots, free))
            };
            // RF186-24 FIX: spare amortized capacity is optional. If the class
            // ledger cannot admit `preferred`, retry the complete detached pair
            // at the exact required size before reporting OOM. Both attempts are
            // transaction-neutral because no live backing changes until the
            // complete pair has succeeded.
            let (slots_prepared, free_prepared) = match prepare_growth(preferred) {
                Ok(prepared) => prepared,
                Err(_) if preferred != new_len => prepare_growth(new_len)?,
                Err(error) => return Err(error),
            };

            // Both detached allocations succeeded before either live backing
            // changes, so allocation failure is transaction-neutral.
            if let Some(prepared) = slots_prepared {
                install_cap_vec(&mut self.slots, &mut self.slots_charge, prepared);
            }
            if let Some(prepared) = free_prepared {
                install_cap_vec(&mut self.free, &mut self.free_charge, prepared);
            }
            let new_idx = self.slots.len() as u16;
            self.slots.push(None); // within reserved capacity -> cannot realloc
            new_idx
        };

        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(CapError::GenerationExhausted)?;
        // Skip 0 if we somehow reach it (defensive)
        if self.next_generation == 0 {
            self.next_generation = 1;
        }

        self.reserved_allocations = next_reserved;
        Ok((index, generation))
    }

    /// Commit a previously reserved identity. The reservation owns an exact
    /// vacant slot, so any mismatch is a fatal internal invariant violation.
    fn install_reserved(&mut self, index: u16, generation: u64, entry: CapEntry) -> CapId {
        let index_usize = index as usize;
        assert!(
            self.reserved_allocations != 0
                && index_usize < self.slots.len()
                && self.slots[index_usize].is_none(),
            "RF180-37: corrupt prepared capability at install"
        );
        // Membership is a diagnostic invariant only; the reservation path
        // removes exactly one index from the free stack.  Keep the O(n) scan
        // out of the production cap-table lock hold time.
        #[cfg(debug_assertions)]
        debug_assert!(!self.free.contains(&index));
        self.slots[index as usize] = Some(CapSlot { generation, entry });
        self.reserved_allocations -= 1;

        CapId::from_parts(index, generation)
    }

    /// Cancel a prepared identity without publishing a capability.
    fn cancel_reserved(&mut self, index: u16) {
        let index_usize = index as usize;
        assert!(
            self.reserved_allocations != 0
                && index_usize < self.slots.len()
                && self.slots[index_usize].is_none(),
            "RF180-37: corrupt prepared capability at rollback"
        );
        #[cfg(debug_assertions)]
        debug_assert!(!self.free.contains(&index));
        debug_assert!(self.free.capacity() >= self.slots.len());
        self.free.push(index);
        self.reserved_allocations -= 1;
        self.reclaim_if_unused();
    }

    /// Look up a capability by ID.
    fn lookup(&self, cap_id: CapId) -> Result<&CapEntry, CapError> {
        if !cap_id.is_valid() {
            return Err(CapError::InvalidCapId);
        }

        // R29-4 FIX: index() now returns u16
        let index = cap_id.index() as usize;
        if index >= self.slots.len() {
            return Err(CapError::InvalidCapId);
        }

        match &self.slots[index] {
            Some(slot) if slot.generation == cap_id.generation() => Ok(&slot.entry),
            _ => Err(CapError::InvalidCapId),
        }
    }

    /// Revoke a capability.
    fn revoke(&mut self, cap_id: CapId) -> Result<CapEntry, CapError> {
        let entry = self.revoke_retaining_capacity(cap_id)?;
        self.reclaim_if_unused();
        Ok(entry)
    }

    /// Revoke without changing vector identity/capacity. Callers walking slot
    /// indices use this form and perform one reclamation after the walk.
    fn revoke_retaining_capacity(&mut self, cap_id: CapId) -> Result<CapEntry, CapError> {
        if !cap_id.is_valid() {
            return Err(CapError::InvalidCapId);
        }

        // R29-4 FIX: index() now returns u16
        let index = cap_id.index() as usize;
        if index >= self.slots.len() {
            return Err(CapError::InvalidCapId);
        }

        match &self.slots[index] {
            Some(slot) if slot.generation == cap_id.generation() => {
                let old_slot = self.slots[index].take().unwrap();
                debug_assert!(self.free.capacity() >= self.slots.len());
                self.free.push(index as u16);
                Ok(old_slot.entry)
            }
            _ => Err(CapError::InvalidCapId),
        }
    }

    /// Delegate a capability with restricted rights.
    fn delegate(
        &mut self,
        cap_id: CapId,
        rights_mask: CapRights,
        flags: CapFlags,
    ) -> Result<CapId, CapError> {
        // Look up the source capability and extract its fields
        let source_entry = self.lookup(cap_id)?;
        let source_object = source_entry.object.clone();
        let source_rights = source_entry.rights;
        let source_flags = source_entry.flags;

        // Check if delegation is allowed
        if source_flags.contains(CapFlags::NOXFER) {
            return Err(CapError::DelegationDenied);
        }

        // R162-9-2 FIX: Namespace capabilities are non-transferable by default
        // to prevent cross-namespace capability leaks.
        if matches!(source_object, CapObject::Namespace(_)) {
            return Err(CapError::DelegationDenied);
        }

        // R25-1 FIX: Enforce source restrictions on delegated capability
        // Source flags (CLOEXEC, CLOFORK, O_PATH, NOXFER) must be inherited to prevent
        // privilege escalation via flag stripping attacks
        let enforced_flags = flags | source_flags;

        // Create new entry with restricted rights and enforced flags
        // U.S2-SLICE-2: New CapEntry starts with refcount=1 (not shared with source)
        let new_entry = CapEntry::with_flags(
            source_object,
            source_rights.restrict(rights_mask),
            enforced_flags,
        );

        // Allocate a new slot for the delegated capability
        self.allocate(new_entry)
    }

    /// Rebuild the free list based on current slot occupancy.
    fn rebuild_free_list(&mut self) {
        self.free.clear();
        for (idx, slot) in self.slots.iter().enumerate() {
            if slot.is_none() {
                // R29-4 FIX: Changed from u32 to u16
                self.free.push(idx as u16);
            }
        }
    }

    fn reclaim_if_unused(&mut self) {
        if self.reserved_allocations != 0 || self.slots.iter().any(Option::is_some) {
            return;
        }
        let slots = core::mem::take(&mut self.slots);
        let free = core::mem::take(&mut self.free);
        drop(slots);
        drop(free);
        let slots_charge = self.slots_charge.take();
        let free_charge = self.free_charge.take();
        drop(slots_charge);
        drop(free_charge);
    }
}

/// RF186-23/RF186-24 boot regression: exercise real charged production backing
/// after the heap-admission ledger is published. Sole cancellation must reclaim
/// both vectors and their charges; recovery must use bounded default backing,
/// consume exactly one new generation, and restore the class ledger on drop.
pub fn run_reclaim_growth_self_test() {
    let before = mm::heap_class_snapshot(HeapClass::Capability);
    {
        let table = CapTable::try_new_arc().expect("RF186 charged capability table");
        let initial_capacity = interrupts::without_interrupts(|| {
            let inner = table.inner.lock();
            assert_eq!(inner.slots.len(), DEFAULT_CAP_SLOTS);
            assert_eq!(inner.free.len(), DEFAULT_CAP_SLOTS);
            assert!(inner.slots_charge.is_some() && inner.free_charge.is_some());
            (inner.slots.capacity(), inner.free.capacity())
        });

        let abandoned = table
            .prepare_allocation()
            .expect("RF186 sole capability reservation");
        let abandoned_id = abandoned.cap_id();
        drop(abandoned);
        interrupts::without_interrupts(|| {
            let inner = table.inner.lock();
            assert_eq!(inner.reserved_allocations, 0);
            assert!(inner.slots.is_empty() && inner.free.is_empty());
            assert_eq!((inner.slots.capacity(), inner.free.capacity()), (0, 0));
            assert!(inner.slots_charge.is_none() && inner.free_charge.is_none());
        });

        let recovered = table
            .prepare_allocation()
            .expect("RF186 capability regrowth after reclaim");
        let recovered_id = recovered.cap_id();
        assert_eq!(recovered_id.index(), 0);
        assert_eq!(
            recovered_id.generation(),
            abandoned_id
                .generation()
                .checked_add(1)
                .expect("RF186 capability generation must be incrementable")
        );
        assert_ne!(recovered_id, abandoned_id);
        interrupts::without_interrupts(|| {
            let inner = table.inner.lock();
            assert_eq!(inner.reserved_allocations, 1);
            assert_eq!(
                (inner.slots.capacity(), inner.free.capacity()),
                initial_capacity,
                "empty capability regrowth must not double default backing"
            );
            assert!(inner.slots_charge.is_some() && inner.free_charge.is_some());
        });

        drop(recovered);
        interrupts::without_interrupts(|| {
            let inner = table.inner.lock();
            assert_eq!(inner.reserved_allocations, 0);
            assert!(inner.slots.is_empty() && inner.free.is_empty());
            assert!(inner.slots_charge.is_none() && inner.free_charge.is_none());
        });
    }
    assert_eq!(
        mm::heap_class_snapshot(HeapClass::Capability),
        before,
        "RF186 capability reclaim/regrowth leaked class admission"
    );
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the capability subsystem.
///
/// Must be called during kernel boot after heap initialization.
pub fn init() {
    klog_always!("  Capability subsystem initialized");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use types::FileOps;

    // Mock FileOps for testing
    #[allow(dead_code)]
    struct MockFile;

    impl FileOps for MockFile {
        fn clone_box(&self) -> alloc::boxed::Box<dyn FileOps> {
            alloc::boxed::Box::new(MockFile)
        }
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn type_name(&self) -> &'static str {
            "MockFile"
        }
    }

    #[test]
    fn test_cap_id_encoding() {
        let cap_id = CapId::from_parts(42, 7);
        assert_eq!(cap_id.index(), 42);
        assert_eq!(cap_id.generation(), 7);
        assert!(cap_id.is_valid());

        let invalid = CapId::INVALID;
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_cap_rights_restrict() {
        let full = CapRights::RWX;
        let read_only = CapRights::READ;

        let restricted = full.restrict(read_only);
        assert!(restricted.contains(CapRights::READ));
        assert!(!restricted.contains(CapRights::WRITE));
        assert!(!restricted.contains(CapRights::EXEC));
    }

    #[test]
    fn test_cap_table_allocate_revoke() {
        let table = CapTable::new();

        let entry = CapEntry::new(CapObject::Process(1), CapRights::SIGNAL);

        let cap_id = table.allocate(entry).unwrap();
        assert!(cap_id.is_valid());

        let looked_up = table.lookup(cap_id).unwrap();
        assert!(looked_up.allows(CapRights::SIGNAL));

        let revoked = table.revoke(cap_id).unwrap();
        assert!(revoked.allows(CapRights::SIGNAL));

        // Should fail now
        assert!(table.lookup(cap_id).is_err());
    }

    #[test]
    fn capability_growth_rejection_is_transaction_neutral() {
        // Unit tests do not publish the runtime heap ledger. The first slot is
        // pre-existing; the second allocation must therefore reject at detached
        // admission without changing either live vector or generation state.
        let mut inner = CapTableInner::with_capacity(1);
        let first = inner
            .allocate(CapEntry::new(CapObject::Process(1), CapRights::SIGNAL))
            .expect("preallocated capability slot");
        let before = (
            inner.slots.len(),
            inner.slots.capacity(),
            inner.free.len(),
            inner.free.capacity(),
            inner.next_generation,
        );

        assert_eq!(
            inner.allocate(CapEntry::new(CapObject::Process(2), CapRights::SIGNAL)),
            Err(CapError::OutOfMemory)
        );
        assert_eq!(
            (
                inner.slots.len(),
                inner.slots.capacity(),
                inner.free.len(),
                inner.free.capacity(),
                inner.next_generation,
            ),
            before,
            "rejected detached growth must leave both vectors and generation exact"
        );
        assert!(inner.lookup(first).is_ok());
    }

    #[test]
    fn rf180_37_prepared_capability_is_invisible_and_rollback_exact() {
        // Exercise the locked inner transaction directly so this remains a
        // true hosted test (x86 interrupt masking is privileged in user mode).
        let mut inner = CapTableInner::with_capacity(1);
        let before_generation = inner.next_generation;
        let (index, _generation) = inner
            .reserve_allocation()
            .expect("preallocate capability identity");
        assert_eq!(inner.reserved_allocations, 1);
        assert!(inner.free.is_empty());
        assert!(inner.slots.iter().all(Option::is_none));

        inner.cancel_reserved(index);
        assert_eq!(inner.reserved_allocations, 0);
        assert!(inner.slots.is_empty(), "empty rollback reclaims backing");
        assert!(
            inner.free.is_empty(),
            "reclaimed table has no stale free IDs"
        );
        assert_eq!(
            inner.next_generation,
            before_generation + 1,
            "cancelled identities still consume generations"
        );
    }

    #[test]
    fn rf186_23_empty_rollback_reclaims_and_growth_target_is_bounded() {
        // RF186-23 FIX: pin the distinction that the boot self-test missed.
        // A sole reservation cancellation reclaims all empty backing; it does
        // not promise that the next reservation reuses the old slot index.
        let mut inner = CapTableInner::with_capacity(DEFAULT_CAP_SLOTS);
        let (abandoned_index, abandoned_generation) = inner
            .reserve_allocation()
            .expect("reserve sole capability identity");
        assert_eq!(abandoned_index as usize, DEFAULT_CAP_SLOTS - 1);

        inner.cancel_reserved(abandoned_index);
        assert_eq!(inner.reserved_allocations, 0);
        assert!(inner.slots.is_empty(), "sole rollback must reclaim slots");
        assert!(inner.free.is_empty(), "sole rollback must reclaim free IDs");
        assert_eq!(
            inner.next_generation,
            abandoned_generation + 1,
            "cancelled identities consume generations monotonically"
        );

        // Hosted cap tests deliberately leave the global heap ledger
        // unpublished, so actual charged regrowth is covered by the boot
        // self-test. Keep the pure target policy executable here.
        assert_eq!(cap_growth_target(0, 1), DEFAULT_CAP_SLOTS);
        assert_eq!(
            cap_growth_target(DEFAULT_CAP_SLOTS, DEFAULT_CAP_SLOTS + 1),
            DEFAULT_CAP_SLOTS * 2
        );
        assert_eq!(
            cap_growth_target(MAX_CAP_SLOTS, MAX_CAP_SLOTS),
            MAX_CAP_SLOTS
        );
    }

    #[test]
    fn rf186_23_pinned_backing_reuses_slot_with_new_generation() {
        // Exact index reuse is a conditional internal behavior only while a
        // live capability pins the backing. Keep that case separate from the
        // empty-table reclamation contract above.
        let mut inner = CapTableInner::with_capacity(2);
        let live = inner
            .allocate(CapEntry::new(CapObject::Process(1), CapRights::SIGNAL))
            .expect("allocate backing pin");
        let (abandoned_index, abandoned_generation) = inner
            .reserve_allocation()
            .expect("reserve pinned capability identity");

        inner.cancel_reserved(abandoned_index);
        assert_eq!(inner.slots.len(), 2, "live capability must pin backing");
        let (recovered_index, recovered_generation) = inner
            .reserve_allocation()
            .expect("reuse cancelled slot while backing remains pinned");
        assert_eq!(recovered_index, abandoned_index);
        assert_eq!(recovered_generation, abandoned_generation + 1);
        assert_ne!(
            CapId::from_parts(recovered_index, recovered_generation),
            CapId::from_parts(abandoned_index, abandoned_generation)
        );

        inner.cancel_reserved(recovered_index);
        inner.revoke(live).expect("release backing pin");
        assert_eq!(inner.reserved_allocations, 0);
        assert!(inner.slots.is_empty() && inner.free.is_empty());
    }

    #[test]
    fn rf180_37_prepared_capability_survives_last_live_revoke() {
        let mut inner = CapTableInner::with_capacity(2);
        let live = inner
            .allocate(CapEntry::new(CapObject::Process(1), CapRights::SIGNAL))
            .expect("initial live capability");
        let (index, generation) = inner
            .reserve_allocation()
            .expect("reserve second capability");

        inner.revoke(live).expect("revoke last published slot");
        assert_eq!(inner.reserved_allocations, 1);
        assert_eq!(inner.slots.len(), 2, "reservation pins exact backing");

        let installed = inner.install_reserved(
            index,
            generation,
            CapEntry::new(CapObject::Process(2), CapRights::SIGNAL),
        );
        assert!(inner.lookup(installed).is_ok());
        assert_eq!(inner.slots.iter().filter(|slot| slot.is_some()).count(), 1);
    }

    #[test]
    fn rf180_37_index_walk_revoke_defers_backing_reclamation() {
        let mut inner = CapTableInner::with_capacity(2);
        let first = inner
            .allocate(CapEntry::new(CapObject::Process(1), CapRights::SIGNAL))
            .expect("first capability");
        let second = inner
            .allocate(CapEntry::new(CapObject::Process(2), CapRights::SIGNAL))
            .expect("second capability");

        inner
            .revoke_retaining_capacity(first)
            .expect("revoke first while iterating");
        inner
            .revoke_retaining_capacity(second)
            .expect("revoke final while iterating");
        assert_eq!(inner.slots.len(), 2, "fixed index range must stay valid");
        assert!(inner.slots.iter().all(Option::is_none));

        inner.reclaim_if_unused();
        assert!(inner.slots.is_empty());
        assert!(inner.free.is_empty());
    }

    /// R177-1 FIX: Test that decrement_refcount saturates at 0 (no underflow wrap).
    ///
    /// This test verifies defense-in-depth hardening: while no reachable double-decrement
    /// exists in the current tree (generation monotonicity + single-lock decrement close
    /// the class), saturating arithmetic prevents a future double-decrement bug from
    /// wrapping the refcount to usize::MAX (which would permanently leak the slot).
    #[test]
    fn test_refcount_saturating_decrement() {
        let table = CapTable::new();

        // Allocate a capability with refcount=1
        let entry = CapEntry::new(CapObject::Process(1), CapRights::SIGNAL);
        let cap_id = table.allocate(entry).unwrap();

        // Verify initial refcount
        assert_eq!(table.get_refcount(cap_id), Some(1));

        // First decrement: refcount 1 → 0, should return true (revoke)
        let should_revoke = table.decrement_refcount(cap_id).unwrap();
        assert!(should_revoke, "First decrement from 1 should return true");
        assert_eq!(table.get_refcount(cap_id), Some(0));

        // Verify the slot is revocable after reaching 0
        let revoked = table.revoke(cap_id);
        assert!(revoked.is_ok(), "Slot should be revocable at refcount 0");
    }

    // R177-1-CODEX: Split test — the debug_assert!(prev != 0) will panic on
    // double-decrement in debug builds, so test saturation behavior separately
    // in release or with #[should_panic] in debug.
    #[test]
    #[should_panic(expected = "refcount underflow")]
    fn test_refcount_underflow_detection() {
        let table = CapTable::new();

        // Allocate a capability with refcount=1
        let entry = CapEntry::new(CapObject::Process(1), CapRights::SIGNAL);
        let cap_id = table.allocate(entry).unwrap();

        // Decrement to 0
        let _ = table.decrement_refcount(cap_id).unwrap();
        assert_eq!(table.get_refcount(cap_id), Some(0));

        let _ = table.decrement_refcount(cap_id);
    }
}
