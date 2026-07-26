//! Aggregate-admitted retained containers for the socket subsystem.
//!
//! Stable `no_std` `BTreeMap`/`VecDeque` growth is infallible.  R180-11
//! requires every user-reachable retained socket allocation to reserve from
//! the whole-kernel heap ledger *before* allocation and before publication.
//! These containers grow detached backing storage under a reservation, then
//! replace the live backing without another allocation.  The old allocation
//! is destroyed before its lifetime charge is released.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::Borrow;
#[cfg(test)]
use core::cell::Cell;
use core::ops::{Deref, DerefMut, Index, IndexMut, RangeBounds};

#[cfg(test)]
extern crate std;

use mm::fallible_map::{FallibleOrderedMap, PreparedOrderedMapBacking};
use mm::{
    try_reserve_heap, vec_charge_bytes, HeapAdmissionError, HeapCharge, HeapClass, HeapReservation,
    NsBudgetLease, NsByteBudget,
};

/// Allocation/admission failure for retained socket containers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmittedAllocError {
    NoMemory,
    Arithmetic,
    Duplicate,
    CapacityInvariant,
}

/// Reserved, aggregate-admitted prefix space carried by every non-empty wire
/// owner. It covers Ethernet II plus the maximum IPv4 header (including one
/// VLAN tag) so a stateful L4 response can be encapsulated without a second
/// allocator request after TCP state becomes durable.
const WIRE_ENCAPSULATION_HEADROOM: usize = 80;

#[cfg(test)]
std::thread_local! {
    /// RF180-41 REVIEW FIX: fault injection is scoped to the invoking test
    /// thread. A process-global flag let parallel builders consume another
    /// test's injected failure and made both positive and negative assertions
    /// nondeterministic.
    static FAIL_NEXT_WIRE_ADMISSION: Cell<bool> = const { Cell::new(false) };
}

/// An owned serialized packet whose allocator backing remains aggregate-admitted
/// for its exact lifetime.
///
/// RF180-41 FIX: production protocol builders must not return a merely fallible
/// `Vec<u8>`. A successful allocator request is charged to `SocketPayload`
/// before allocation, and the nested [`AdmittedVec`] destroys its backing before
/// releasing that charge. The type intentionally does not implement `Clone`:
/// every additional wire owner must pass through a fallible admitted copy.
pub struct WirePacket {
    bytes: AdmittedVec<u8>,
    start: usize,
}

impl WirePacket {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: AdmittedVec::new(HeapClass::SocketPayload),
            start: 0,
        }
    }

    fn test_admission_gate() -> Result<(), AdmittedAllocError> {
        #[cfg(test)]
        {
            // Hosted protocol tests predate the boot-time publisher. Keep the
            // production requirement unchanged while making each unit test
            // independently runnable.
            mm::publish_heap_budgets();
            if FAIL_NEXT_WIRE_ADMISSION.with(|fail_next| fail_next.replace(false)) {
                return Err(AdmittedAllocError::NoMemory);
            }
        }
        Ok(())
    }

    pub(crate) fn try_zeroed(len: usize) -> Result<Self, AdmittedAllocError> {
        Self::test_admission_gate()?;
        if len == 0 {
            return Ok(Self::new());
        }
        let allocation_len = WIRE_ENCAPSULATION_HEADROOM
            .checked_add(len)
            .ok_or(AdmittedAllocError::Arithmetic)?;
        Ok(Self {
            bytes: AdmittedVec::try_zeroed(HeapClass::SocketPayload, allocation_len)?,
            start: WIRE_ENCAPSULATION_HEADROOM,
        })
    }

    pub(crate) fn try_copy_from_slice(source: &[u8]) -> Result<Self, AdmittedAllocError> {
        let mut packet = Self::try_zeroed(source.len())?;
        packet.as_mut_slice().copy_from_slice(source);
        Ok(packet)
    }

    /// Allocate one exact packet and copy all parts into it without any later
    /// heap growth. Arithmetic overflow and admission failure both fail closed.
    pub(crate) fn try_from_slices(parts: &[&[u8]]) -> Result<Self, AdmittedAllocError> {
        let total = parts.iter().try_fold(0usize, |total, part| {
            total
                .checked_add(part.len())
                .ok_or(AdmittedAllocError::Arithmetic)
        })?;
        let mut packet = Self::try_zeroed(total)?;
        let mut offset = 0usize;
        for part in parts {
            let end = offset + part.len();
            packet.as_mut_slice()[offset..end].copy_from_slice(part);
            offset = end;
        }
        Ok(packet)
    }

    /// Prepend discontiguous protocol headers into the already admitted
    /// encapsulation reserve. This method performs no allocation and therefore
    /// cannot invalidate an L4 transaction that committed after constructing
    /// this packet.
    pub(crate) fn try_prepend_from_slices(
        &mut self,
        parts: &[&[u8]],
    ) -> Result<(), AdmittedAllocError> {
        let prefix_len = parts.iter().try_fold(0usize, |total, part| {
            total
                .checked_add(part.len())
                .ok_or(AdmittedAllocError::Arithmetic)
        })?;
        if prefix_len > self.start {
            return Err(AdmittedAllocError::CapacityInvariant);
        }
        let new_start = self.start - prefix_len;
        let mut offset = new_start;
        for part in parts {
            let end = offset + part.len();
            self.bytes.as_mut_slice()[offset..end].copy_from_slice(part);
            offset = end;
        }
        self.start = new_start;
        Ok(())
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes.as_slice()[self.start..]
    }

    #[inline]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes.as_mut_slice()[self.start..]
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len().saturating_sub(self.start)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    pub(crate) fn fail_next_admission_for_test() {
        FAIL_NEXT_WIRE_ADMISSION.with(|fail_next| fail_next.set(true));
    }

    #[cfg(test)]
    pub(crate) fn charged_bytes_for_test(&self) -> usize {
        self.bytes.charged_bytes_for_test()
    }
}

impl Default for WirePacket {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for WirePacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for WirePacket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for WirePacket {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::fmt::Debug for WirePacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("WirePacket").field(&self.as_slice()).finish()
    }
}

impl PartialEq for WirePacket {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for WirePacket {}

impl From<HeapAdmissionError> for AdmittedAllocError {
    fn from(error: HeapAdmissionError) -> Self {
        match error {
            HeapAdmissionError::ArithmeticOverflow => Self::Arithmetic,
            HeapAdmissionError::NotPublished
            | HeapAdmissionError::GlobalLimit
            | HeapAdmissionError::ClassLimit => Self::NoMemory,
            HeapAdmissionError::CorruptState => Self::CapacityInvariant,
        }
    }
}

#[inline]
fn growth_target(current: usize, required: usize) -> Result<usize, AdmittedAllocError> {
    if required <= current {
        return Ok(current);
    }
    // Amortize normal growth, but callers retry the exact requirement if the
    // larger reservation is rejected.  Admission therefore never reduces the
    // logical socket/backlog/window contract merely to obtain spare capacity.
    let doubled = current
        .max(4)
        .checked_mul(2)
        .ok_or(AdmittedAllocError::Arithmetic)?;
    Ok(required.max(doubled))
}

fn reserve_vec<T>(
    class: HeapClass,
    capacity: usize,
) -> Result<HeapReservation, AdmittedAllocError> {
    let bytes = vec_charge_bytes::<T>(capacity)?;
    Ok(try_reserve_heap(class, bytes)?)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CapacityPlan {
    class: HeapClass,
    required: usize,
    preferred: usize,
}

impl CapacityPlan {
    #[inline]
    pub(crate) fn required(self) -> usize {
        self.required
    }

    #[inline]
    pub(crate) fn preferred(self) -> usize {
        self.preferred
    }

    #[inline]
    pub(crate) fn class(self) -> HeapClass {
        self.class
    }
}

fn capacity_plan(
    class: HeapClass,
    len: usize,
    capacity: usize,
    additional: usize,
) -> Result<Option<CapacityPlan>, AdmittedAllocError> {
    let required = len
        .checked_add(additional)
        .ok_or(AdmittedAllocError::Arithmetic)?;
    if required <= capacity {
        return Ok(None);
    }
    Ok(Some(CapacityPlan {
        class,
        required,
        preferred: growth_target(capacity, required)?,
    }))
}

/// Detached aggregate-admitted `Vec` capacity. Allocation and ledger
/// reservation happen before the live owner is borrowed; installation only
/// moves elements and swaps already-owned backing.
///
/// D3 NETNS-SUBBUDGET-1: when the owning [`AdmittedVec`] carries a per-owner
/// [`NsByteBudget`], the matching [`NsBudgetLease`] is attached here BEFORE
/// installation, so a rejected lease drops the whole prepared object and its
/// class reservation rolls back with it (failure-atomic dual admission).
pub(crate) struct PreparedAdmittedVecCapacity<T> {
    values: Vec<T>,
    reservation: HeapReservation,
    ns_lease: Option<NsBudgetLease>,
}

/// Obsolete `Vec` backing and its matching charge. Callers that install under a
/// spin lock retain this owner until every relevant lock/IRQ guard is gone.
#[must_use = "retired admitted Vec backing must be dropped outside metadata locks"]
pub(crate) struct RetiredAdmittedVecCapacity<T> {
    _values: Vec<T>,
    _charge: Option<HeapCharge>,
    _ns_lease: Option<NsBudgetLease>,
}

impl<T> PreparedAdmittedVecCapacity<T> {
    pub(crate) fn try_from_plan(plan: CapacityPlan) -> Result<Self, AdmittedAllocError> {
        match Self::try_new(plan.class(), plan.preferred()) {
            Ok(prepared) => Ok(prepared),
            Err(error) if plan.preferred() != plan.required() => {
                Self::try_new(plan.class(), plan.required()).map_err(|_| error)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn try_new(class: HeapClass, target: usize) -> Result<Self, AdmittedAllocError> {
        let mut reservation = reserve_vec::<T>(class, target)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(target)
            .map_err(|_| AdmittedAllocError::NoMemory)?;
        reservation.resize(vec_charge_bytes::<T>(values.capacity())?)?;
        Ok(Self {
            values,
            reservation,
            ns_lease: None,
        })
    }

    /// D3 NETNS-SUBBUDGET-1: attach the per-owner lease mirroring this
    /// prepared backing's class reservation. Must cover exactly
    /// `self.reservation.bytes()`; installation rejects a budgeted owner
    /// whose prepared capacity arrives without a lease.
    pub(crate) fn attach_ns_lease(&mut self, lease: NsBudgetLease) {
        debug_assert!(
            self.ns_lease.is_none(),
            "prepared admitted Vec capacity double-leased"
        );
        self.ns_lease = Some(lease);
    }
}

/// Detached aggregate-admitted ordered-map capacity.
pub(crate) struct PreparedAdmittedMapCapacity<K: Ord, V> {
    backing: PreparedOrderedMapBacking<K, V>,
    reservation: HeapReservation,
}

/// Obsolete ordered-map backing and its matching charge.
#[must_use = "retired admitted map backing must be dropped outside metadata locks"]
pub(crate) struct RetiredAdmittedMapCapacity<K: Ord, V> {
    _backing: PreparedOrderedMapBacking<K, V>,
    _charge: Option<HeapCharge>,
}

impl<K: Ord, V> PreparedAdmittedMapCapacity<K, V> {
    pub(crate) fn try_from_plan(plan: CapacityPlan) -> Result<Self, AdmittedAllocError> {
        match Self::try_new(plan.class(), plan.preferred()) {
            Ok(prepared) => Ok(prepared),
            Err(error) if plan.preferred() != plan.required() => {
                Self::try_new(plan.class(), plan.required()).map_err(|_| error)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn try_new(class: HeapClass, target: usize) -> Result<Self, AdmittedAllocError> {
        let mut reservation = reserve_vec::<(K, V)>(class, target)?;
        let backing = FallibleOrderedMap::try_prepare_backing_exact(target)
            .map_err(|_| AdmittedAllocError::NoMemory)?;
        reservation.resize(vec_charge_bytes::<(K, V)>(backing.capacity())?)?;
        Ok(Self {
            backing,
            reservation,
        })
    }

    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.backing.capacity()
    }
}

/// A retained `Vec` whose backing allocation owns a whole-heap charge.
///
/// `values` is deliberately declared before `charge` and `ns_lease`: Rust
/// drops fields in declaration order, so the allocator backing is gone before
/// either ledger (class charge, per-owner budget lease) releases its bytes on
/// final destruction.
pub struct AdmittedVec<T> {
    values: Vec<T>,
    charge: Option<HeapCharge>,
    class: HeapClass,
    /// D3 NETNS-SUBBUDGET-1: optional per-owner byte budget. When present,
    /// every growth takes a dual lease (class reservation + owner budget)
    /// and the live backing keeps the lease in `ns_lease`.
    budget: Option<Arc<NsByteBudget>>,
    ns_lease: Option<NsBudgetLease>,
    #[cfg(test)]
    fail_next_growth: bool,
}

impl<T> AdmittedVec<T> {
    pub(crate) const fn new(class: HeapClass) -> Self {
        Self {
            values: Vec::new(),
            charge: None,
            class,
            budget: None,
            ns_lease: None,
            #[cfg(test)]
            fail_next_growth: false,
        }
    }

    /// D3 NETNS-SUBBUDGET-1: a Vec whose growth charges BOTH the shared
    /// class ledger and the given per-owner byte budget. The budget limit is
    /// a ceiling, not an entitlement — class exhaustion can still reject
    /// growth below the owner's limit.
    pub(crate) fn with_ns_budget(class: HeapClass, budget: Arc<NsByteBudget>) -> Self {
        Self {
            values: Vec::new(),
            charge: None,
            class,
            budget: Some(budget),
            ns_lease: None,
            #[cfg(test)]
            fail_next_growth: false,
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Snapshot a detached growth request without allocating. This is the only
    /// part called while a metadata lock is held; preparation follows after the
    /// lock is released and publication revalidates the live length/capacity.
    pub(crate) fn capacity_plan_for(
        &mut self,
        additional: usize,
    ) -> Result<Option<CapacityPlan>, AdmittedAllocError> {
        #[cfg(test)]
        if core::mem::take(&mut self.fail_next_growth) {
            return Err(AdmittedAllocError::NoMemory);
        }
        capacity_plan(
            self.class,
            self.values.len(),
            self.values.capacity(),
            additional,
        )
    }

    /// Install prepared backing without freeing the obsolete allocation.
    pub(crate) fn install_prepared_deferred(
        &mut self,
        mut prepared: PreparedAdmittedVecCapacity<T>,
    ) -> Result<RetiredAdmittedVecCapacity<T>, PreparedAdmittedVecCapacity<T>> {
        // D3 NETNS-SUBBUDGET-1: a budgeted owner only accepts backing that
        // carries its matching lease, and an unbudgeted owner never accepts
        // a leased one — either mismatch means the dual accounting would
        // diverge, so refuse the install (fail-closed).
        if prepared.values.capacity() < self.values.len()
            || prepared.reservation.class() != self.class
            || self.budget.is_some() != prepared.ns_lease.is_some()
        {
            return Err(prepared);
        }
        let replacement_charge = prepared
            .reservation
            .commit()
            .expect("RF180-41 admitted Vec ledger invariant");
        let mut old_values = core::mem::take(&mut self.values);
        for value in old_values.drain(..) {
            prepared.values.push(value);
        }
        self.values = prepared.values;
        let old_charge = self.charge.replace(replacement_charge);
        // The retiring lease must outlive the retiring backing exactly like
        // the retiring class charge does: both ride in the Retired owner and
        // release together once every relevant lock/IRQ guard is gone.
        let old_ns_lease = core::mem::replace(&mut self.ns_lease, prepared.ns_lease.take());
        Ok(RetiredAdmittedVecCapacity {
            _values: old_values,
            _charge: old_charge,
            _ns_lease: old_ns_lease,
        })
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[T] {
        &self.values
    }

    #[inline]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.values
    }

    #[inline]
    pub(crate) fn iter(&self) -> core::slice::Iter<'_, T> {
        self.values.iter()
    }

    #[inline]
    pub(crate) fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.values.iter_mut()
    }

    #[inline]
    pub(crate) fn front(&self) -> Option<&T> {
        self.values.first()
    }

    #[inline]
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.values.get_mut(index)
    }

    /// Ensure `additional` elements can be published without allocation.
    pub(crate) fn ensure_capacity_for(
        &mut self,
        additional: usize,
    ) -> Result<(), AdmittedAllocError> {
        let Some(plan) = self.capacity_plan_for(additional)? else {
            return Ok(());
        };
        let mut prepared = PreparedAdmittedVecCapacity::try_from_plan(plan)?;
        if let Some(budget) = &self.budget {
            // D3 NETNS-SUBBUDGET-1: dual lease — the per-owner budget
            // mirrors the class reservation byte-for-byte. On rejection
            // `prepared` drops here and its reservation Drop rolls the class
            // ledger back, so neither ledger retains a phantom charge
            // (failure-atomic). Realloc peak (old charge + new reservation
            // coexisting until the Retired owner drops) is charged to the
            // budget the same way it is to the class.
            //
            // Deliberate fail-closed asymmetry (round-6 review): the class
            // path retries at plan.required() when preferred fails, but a
            // budget rejection of the realized (preferred) capacity is NOT
            // retried at required — growth near the budget edge rejects
            // slightly early rather than adding a second lease path. This
            // only ever rejects MORE, never over-admits.
            let lease = budget
                .try_lease(prepared.reservation.bytes())
                .map_err(|_| AdmittedAllocError::NoMemory)?;
            prepared.attach_ns_lease(lease);
        }
        match self.install_prepared_deferred(prepared) {
            Ok(retired) => {
                drop(retired);
                Ok(())
            }
            Err(_) => Err(AdmittedAllocError::CapacityInvariant),
        }
    }

    /// Publish one element after `ensure_capacity_for(1)`.
    pub(crate) fn push_reserved(&mut self, value: T) -> Result<(), T> {
        if self.values.len() == self.values.capacity() {
            return Err(value);
        }
        self.values.push(value);
        Ok(())
    }

    pub(crate) fn try_push(&mut self, value: T) -> Result<(), (AdmittedAllocError, T)> {
        if let Err(error) = self.ensure_capacity_for(1) {
            return Err((error, value));
        }
        self.push_reserved(value)
            .map_err(|value| (AdmittedAllocError::CapacityInvariant, value))
    }

    /// Publish at a sorted/queue position after capacity preparation.
    pub(crate) fn insert_reserved(&mut self, index: usize, value: T) -> Result<(), T> {
        if index > self.values.len() || self.values.len() == self.values.capacity() {
            return Err(value);
        }
        self.values.insert(index, value);
        Ok(())
    }

    #[inline]
    pub(crate) fn remove(&mut self, index: usize) -> Option<T> {
        if index < self.values.len() {
            Some(self.values.remove(index))
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn pop_front(&mut self) -> Option<T> {
        self.remove(0)
    }

    #[inline]
    pub(crate) fn pop(&mut self) -> Option<T> {
        self.values.pop()
    }

    #[inline]
    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }

    #[inline]
    pub(crate) fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.values.retain(keep);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_growth_for_test(&mut self) {
        self.fail_next_growth = true;
    }

    #[cfg(test)]
    pub(crate) fn charged_bytes_for_test(&self) -> usize {
        self.charge.as_ref().map_or(0, HeapCharge::bytes)
    }
}

impl<T: Copy> AdmittedVec<T> {
    pub(crate) fn try_copy_from_slice(
        class: HeapClass,
        source: &[T],
    ) -> Result<Self, AdmittedAllocError> {
        let mut out = Self::new(class);
        out.ensure_capacity_for(source.len())?;
        out.values.extend_from_slice(source);
        Ok(out)
    }

    pub(crate) fn try_extend_from_slice(&mut self, source: &[T]) -> Result<(), AdmittedAllocError> {
        self.ensure_capacity_for(source.len())?;
        self.values.extend_from_slice(source);
        Ok(())
    }
}

impl AdmittedVec<u8> {
    pub(crate) fn try_zeroed(class: HeapClass, len: usize) -> Result<Self, AdmittedAllocError> {
        let mut out = Self::new(class);
        out.ensure_capacity_for(len)?;
        out.values.resize(len, 0);
        Ok(out)
    }
}

impl<T> Deref for AdmittedVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T> Index<usize> for AdmittedVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}

impl<T> IndexMut<usize> for AdmittedVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.values[index]
    }
}

impl<'a, T> IntoIterator for &'a AdmittedVec<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut AdmittedVec<T> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter_mut()
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for AdmittedVec<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdmittedVec")
            .field("values", &self.values)
            .field("capacity", &self.values.capacity())
            .field("class", &self.class)
            .finish()
    }
}

/// A fallible ordered map with aggregate-admitted detached capacity growth.
///
/// As with `AdmittedVec`, map backing is declared before its charge so final
/// destruction deallocates before releasing admission.
pub(crate) struct AdmittedMap<K: Ord, V> {
    map: FallibleOrderedMap<K, V>,
    charge: Option<HeapCharge>,
    class: HeapClass,
    #[cfg(test)]
    fail_next_growth: bool,
}

impl<K: Ord, V> AdmittedMap<K, V> {
    pub(crate) const fn new(class: HeapClass) -> Self {
        Self {
            map: FallibleOrderedMap::new(),
            charge: None,
            class,
            #[cfg(test)]
            fail_next_growth: false,
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub(crate) fn capacity_plan_for(
        &mut self,
        additional: usize,
    ) -> Result<Option<CapacityPlan>, AdmittedAllocError> {
        #[cfg(test)]
        if core::mem::take(&mut self.fail_next_growth) {
            return Err(AdmittedAllocError::NoMemory);
        }
        capacity_plan(self.class, self.map.len(), self.map.capacity(), additional)
    }

    pub(crate) fn install_prepared_deferred(
        &mut self,
        prepared: PreparedAdmittedMapCapacity<K, V>,
    ) -> Result<RetiredAdmittedMapCapacity<K, V>, PreparedAdmittedMapCapacity<K, V>> {
        if prepared.backing.capacity() < self.map.len()
            || prepared.reservation.class() != self.class
        {
            return Err(prepared);
        }
        let replacement_charge = prepared
            .reservation
            .commit()
            .expect("RF180-41 admitted map ledger invariant");
        let retired_backing = self
            .map
            .replace_backing_deferred(prepared.backing)
            .unwrap_or_else(|_| panic!("validated admitted map backing rejected"));
        let old_charge = self.charge.replace(replacement_charge);
        Ok(RetiredAdmittedMapCapacity {
            _backing: retired_backing,
            _charge: old_charge,
        })
    }

    #[inline]
    pub(crate) fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get(key)
    }

    #[inline]
    pub(crate) fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get_mut(key)
    }

    #[inline]
    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.contains_key(key)
    }

    #[inline]
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        self.map.iter()
    }

    #[inline]
    pub(crate) fn values(&self) -> impl DoubleEndedIterator<Item = &V> {
        self.map.values()
    }

    #[inline]
    pub(crate) fn keys(&self) -> impl DoubleEndedIterator<Item = &K> {
        self.map.keys()
    }

    #[inline]
    pub(crate) fn range<R>(&self, range: R) -> impl DoubleEndedIterator<Item = (&K, &V)>
    where
        R: RangeBounds<K>,
    {
        self.map.range(range)
    }

    #[inline]
    pub(crate) fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.remove(key)
    }

    #[inline]
    pub(crate) fn clear(&mut self) {
        self.map.clear();
    }

    #[inline]
    pub(crate) fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&K, &V) -> bool,
    {
        self.map.retain(keep);
    }

    /// Prepare/install backing for `additional` allocation-free publications.
    pub(crate) fn ensure_capacity_for(
        &mut self,
        additional: usize,
    ) -> Result<(), AdmittedAllocError> {
        let Some(plan) = self.capacity_plan_for(additional)? else {
            return Ok(());
        };
        let prepared = PreparedAdmittedMapCapacity::try_from_plan(plan)?;
        match self.install_prepared_deferred(prepared) {
            Ok(retired) => {
                drop(retired);
                Ok(())
            }
            Err(_) => Err(AdmittedAllocError::CapacityInvariant),
        }
    }

    /// Allocation-free unique insertion after capacity preparation.
    pub(crate) fn insert_unique_reserved(&mut self, key: K, value: V) -> Result<(), (K, V)> {
        self.map.insert_unique_reserved(key, value)
    }

    /// Fallible insertion for sites with no preceding external side effects.
    pub(crate) fn try_insert(
        &mut self,
        key: K,
        value: V,
    ) -> Result<Option<V>, (AdmittedAllocError, K, V)> {
        if self.map.contains_key(&key) {
            return self
                .map
                .try_insert(key, value)
                .map_err(|_| unreachable!("replacement cannot allocate"));
        }
        if let Err(error) = self.ensure_capacity_for(1) {
            return Err((error, key, value));
        }
        match self.map.insert_unique_reserved(key, value) {
            Ok(()) => Ok(None),
            Err((key, value)) => Err((AdmittedAllocError::Duplicate, key, value)),
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_growth_for_test(&mut self) {
        self.fail_next_growth = true;
    }

    #[cfg(test)]
    pub(crate) fn charged_bytes_for_test(&self) -> usize {
        self.charge.as_ref().map_or(0, HeapCharge::bytes)
    }
}

impl<K: Ord + core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug for AdmittedMap<K, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdmittedMap")
            .field("map", &self.map)
            .field("capacity", &self.map.capacity())
            .field("class", &self.class)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rf180_41_wire_owner_reports_charge_and_fault_is_retryable() {
        mm::publish_heap_budgets();

        let packet = WirePacket::try_copy_from_slice(&[0x5a; 128])
            .expect("wire packet admission must succeed");
        let charged = packet.charged_bytes_for_test();
        assert!(
            charged > 128 + WIRE_ENCAPSULATION_HEADROOM,
            "allocator charge includes encapsulation reserve and bookkeeping slack"
        );
        assert_eq!(packet.as_slice(), &[0x5a; 128]);

        drop(packet);

        WirePacket::fail_next_admission_for_test();
        assert!(matches!(
            WirePacket::try_copy_from_slice(&[1, 2, 3, 4]),
            Err(AdmittedAllocError::NoMemory)
        ));
        assert_eq!(
            WirePacket::try_copy_from_slice(&[1, 2, 3, 4])
                .expect("one-shot admission fault must be retryable")
                .as_slice(),
            &[1, 2, 3, 4]
        );
    }

    #[test]
    fn rf180_41_multipart_bytes_and_in_place_prepend_are_exact() {
        let mut packet = WirePacket::try_from_slices(&[&[1, 2], &[3, 4, 5]])
            .expect("multipart packet admission");
        assert_eq!(packet.as_slice(), &[1, 2, 3, 4, 5]);

        packet
            .try_prepend_from_slices(&[&[0xaa, 0xbb], &[0xcc]])
            .expect("reserved-headroom prepend");
        assert_eq!(packet.as_slice(), &[0xaa, 0xbb, 0xcc, 1, 2, 3, 4, 5]);
    }
}
