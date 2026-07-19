//! Whole-heap-admitted retained containers.
//!
//! Stable `no_std` collection growth is either infallible (`BTreeMap` /
//! `BTreeSet`) or only fallible at the allocator boundary (`Vec`). Neither is
//! sufficient for the whole-kernel coexistence proof: an allocation must first
//! reserve its complete allocator footprint from [`crate::heap_admission`], and
//! retained capacity must keep that charge until the backing allocation has
//! actually been destroyed.
//!
//! These wrappers implement that prepare/allocate/publish lifecycle. Growth is
//! performed into detached backing under a rollback-armed reservation. The old
//! backing is destroyed before its charge is released, and an empty container
//! returns all retained capacity without another allocation.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;
use core::ops::{Deref, DerefMut, Index, IndexMut, RangeBounds};

use crate::fallible_map::{FallibleOrderedMap, PreparedOrderedMapBacking};
use crate::heap_admission::{
    try_reserve, vec_charge_bytes, HeapAdmissionError, HeapCharge, HeapClass, HeapReservation,
};

/// Failure returned by an admitted collection operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmittedAllocError {
    Admission(HeapAdmissionError),
    AllocationFailed,
    CapacityInvariant,
}

impl From<HeapAdmissionError> for AdmittedAllocError {
    #[inline]
    fn from(error: HeapAdmissionError) -> Self {
        Self::Admission(error)
    }
}

#[inline]
fn growth_target(current: usize, required: usize) -> Result<usize, AdmittedAllocError> {
    if required <= current {
        return Ok(current);
    }
    let doubled = current
        .max(4)
        .checked_mul(2)
        .ok_or(AdmittedAllocError::Admission(
            HeapAdmissionError::ArithmeticOverflow,
        ))?;
    Ok(required.max(doubled))
}

#[inline]
fn reserve_vec<T>(
    class: HeapClass,
    capacity: usize,
) -> Result<HeapReservation, AdmittedAllocError> {
    Ok(try_reserve(class, vec_charge_bytes::<T>(capacity)?)?)
}

/// Detached backing plus its rollback-armed whole-heap reservation.
pub struct PreparedAdmittedVecCapacity<T> {
    values: Vec<T>,
    reservation: HeapReservation,
}

/// Detached obsolete `Vec` backing. Its allocation is deliberately declared
/// before its charge so dropping this owner frees memory before releasing the
/// corresponding whole-heap admission.
#[must_use = "retired admitted backing must be dropped outside protected locks"]
pub struct RetiredAdmittedVecCapacity<T> {
    _values: Vec<T>,
    _charge: Option<HeapCharge>,
    _class: HeapClass,
}

impl<T> PreparedAdmittedVecCapacity<T> {
    /// Prepare exact detached capacity without borrowing a live collection.
    pub fn try_new(class: HeapClass, target: usize) -> Result<Self, AdmittedAllocError> {
        let mut reservation = reserve_vec::<T>(class, target)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(target)
            .map_err(|_| AdmittedAllocError::AllocationFailed)?;
        reservation.resize(vec_charge_bytes::<T>(values.capacity())?)?;
        Ok(Self {
            values,
            reservation,
        })
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.values.capacity()
    }

    #[inline]
    pub fn class(&self) -> HeapClass {
        self.reservation.class()
    }
}

/// A retained `Vec` whose complete backing capacity is whole-heap admitted.
///
/// `values` is declared before `charge`, so Rust's field drop order destroys
/// the backing allocation before the ledger releases its lifetime charge.
pub struct AdmittedVec<T> {
    values: Vec<T>,
    charge: Option<HeapCharge>,
    class: HeapClass,
}

impl<T> AdmittedVec<T> {
    pub const fn new(class: HeapClass) -> Self {
        Self {
            values: Vec::new(),
            charge: None,
            class,
        }
    }

    #[inline]
    pub fn class(&self) -> HeapClass {
        self.class
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.values.capacity()
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.values.as_slice()
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.values.as_mut_slice()
    }

    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.values.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.values.iter_mut()
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.values.get(index)
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.values.get_mut(index)
    }

    /// Adopt already-allocated backing before it becomes retained/public.
    /// New allocation paths should prefer detached preparation so admission
    /// precedes the allocator request as well as publication.
    pub fn try_adopt(values: Vec<T>, class: HeapClass) -> Result<Self, AdmittedAllocError> {
        let reservation = reserve_vec::<T>(class, values.capacity())?;
        let charge = reservation.commit()?;
        Ok(Self {
            values,
            charge: Some(charge),
            class,
        })
    }

    fn prepare_target(
        &self,
        target: usize,
    ) -> Result<PreparedAdmittedVecCapacity<T>, AdmittedAllocError> {
        if target < self.values.len() {
            return Err(AdmittedAllocError::CapacityInvariant);
        }
        PreparedAdmittedVecCapacity::try_new(self.class, target)
    }

    /// Prepare detached backing for `additional` future elements. The live
    /// vector is unchanged until [`AdmittedVec::install_prepared`].
    pub fn prepare_capacity_for(
        &self,
        additional: usize,
    ) -> Result<Option<PreparedAdmittedVecCapacity<T>>, AdmittedAllocError> {
        let required =
            self.values
                .len()
                .checked_add(additional)
                .ok_or(AdmittedAllocError::Admission(
                    HeapAdmissionError::ArithmeticOverflow,
                ))?;
        if required <= self.values.capacity() {
            return Ok(None);
        }
        let preferred = growth_target(self.values.capacity(), required)?;
        match self.prepare_target(preferred) {
            Ok(prepared) => Ok(Some(prepared)),
            Err(_) if preferred != required => self.prepare_target(required).map(Some),
            Err(error) => Err(error),
        }
    }

    /// Prepare exact detached capacity rather than amortized spare capacity.
    pub fn prepare_exact_capacity(
        &self,
        required: usize,
    ) -> Result<Option<PreparedAdmittedVecCapacity<T>>, AdmittedAllocError> {
        if required <= self.values.capacity() {
            Ok(None)
        } else {
            self.prepare_target(required).map(Some)
        }
    }

    /// Publish detached backing without allocation.
    pub fn install_prepared(
        &mut self,
        prepared: PreparedAdmittedVecCapacity<T>,
    ) -> Result<(), AdmittedAllocError> {
        let retired = self.install_prepared_deferred(prepared)?;
        drop(retired);
        Ok(())
    }

    /// Allocation-free publication that returns obsolete backing for an
    /// out-of-lock physical deallocation.
    pub fn install_prepared_deferred(
        &mut self,
        mut prepared: PreparedAdmittedVecCapacity<T>,
    ) -> Result<RetiredAdmittedVecCapacity<T>, AdmittedAllocError> {
        if prepared.values.capacity() < self.values.len()
            || prepared.reservation.class() != self.class
        {
            return Err(AdmittedAllocError::CapacityInvariant);
        }
        // Resource admission already succeeded during detached preparation;
        // commit can fail only if the global ledger is corrupt.
        let replacement_charge = prepared
            .reservation
            .commit()
            .expect("RF180-43 admitted vec commit invariant");
        let mut old_values = core::mem::take(&mut self.values);
        for value in old_values.drain(..) {
            prepared.values.push(value);
        }
        let old_charge = self.charge.take();
        self.values = prepared.values;
        self.charge = Some(replacement_charge);
        Ok(RetiredAdmittedVecCapacity {
            _values: old_values,
            _charge: old_charge,
            _class: self.class,
        })
    }

    pub fn try_reserve(&mut self, additional: usize) -> Result<(), AdmittedAllocError> {
        if let Some(prepared) = self.prepare_capacity_for(additional)? {
            self.install_prepared(prepared)?;
        }
        Ok(())
    }

    pub fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AdmittedAllocError> {
        let required =
            self.values
                .len()
                .checked_add(additional)
                .ok_or(AdmittedAllocError::Admission(
                    HeapAdmissionError::ArithmeticOverflow,
                ))?;
        if let Some(prepared) = self.prepare_exact_capacity(required)? {
            self.install_prepared(prepared)?;
        }
        Ok(())
    }

    /// Allocation-free publication after capacity preparation.
    pub fn push_reserved(&mut self, value: T) -> Result<(), T> {
        if self.values.len() == self.values.capacity() {
            return Err(value);
        }
        self.values.push(value);
        Ok(())
    }

    pub fn try_push(&mut self, value: T) -> Result<(), (AdmittedAllocError, T)> {
        if let Err(error) = self.try_reserve(1) {
            return Err((error, value));
        }
        self.push_reserved(value)
            .map_err(|value| (AdmittedAllocError::CapacityInvariant, value))
    }

    #[inline]
    pub fn remove(&mut self, index: usize) -> Option<T> {
        if index >= self.values.len() {
            return None;
        }
        let value = self.values.remove(index);
        self.reclaim_if_empty();
        Some(value)
    }

    /// Indexed removal retaining backing and admission for lock-safe callers.
    #[inline]
    pub fn remove_retaining_capacity(&mut self, index: usize) -> Option<T> {
        if index >= self.values.len() {
            None
        } else {
            Some(self.values.remove(index))
        }
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        let value = self.values.pop();
        self.reclaim_if_empty();
        value
    }

    pub fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.values.retain(keep);
        self.reclaim_if_empty();
    }

    /// Retain elements without reclaiming an empty allocation under the caller's
    /// lock. Use [`AdmittedVec::take_empty_capacity`] after mutation.
    pub fn retain_capacity<F>(&mut self, keep: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.values.retain(keep);
    }

    pub fn clear(&mut self) {
        self.values.clear();
        self.reclaim_if_empty();
    }

    /// Clear elements while deliberately retaining the already-admitted
    /// capacity for an immediate allocation-free rebuild.
    pub fn clear_retaining_capacity(&mut self) {
        self.values.clear();
    }

    fn reclaim_if_empty(&mut self) {
        drop(self.take_empty_capacity());
    }

    /// Detach an empty retained allocation without allocating or deallocating.
    pub fn take_empty_capacity(&mut self) -> Option<RetiredAdmittedVecCapacity<T>> {
        if !self.values.is_empty() || self.values.capacity() == 0 {
            return None;
        }
        Some(RetiredAdmittedVecCapacity {
            _values: core::mem::take(&mut self.values),
            _charge: self.charge.take(),
            _class: self.class,
        })
    }
}

impl<T: Clone> AdmittedVec<T> {
    pub fn try_copy_from_slice(class: HeapClass, source: &[T]) -> Result<Self, AdmittedAllocError> {
        let mut out = Self::new(class);
        if let Some(prepared) = out.prepare_exact_capacity(source.len())? {
            out.install_prepared(prepared)?;
        }
        out.values.extend_from_slice(source);
        Ok(out)
    }

    pub fn try_extend_from_slice(&mut self, source: &[T]) -> Result<(), AdmittedAllocError> {
        self.try_reserve_exact(source.len())?;
        self.values.extend_from_slice(source);
        Ok(())
    }
}

impl<T> Deref for AdmittedVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.values.as_slice()
    }
}

impl<T> DerefMut for AdmittedVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.values.as_mut_slice()
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

/// Owning iterator that keeps the capacity charge until `Vec::IntoIter` has
/// released its backing allocation (including a partially-consumed iterator).
pub struct AdmittedVecIntoIter<T> {
    iter: alloc::vec::IntoIter<T>,
    _charge: Option<HeapCharge>,
}

impl<T> Iterator for AdmittedVecIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<T> DoubleEndedIterator for AdmittedVecIntoIter<T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back()
    }
}

impl<T> ExactSizeIterator for AdmittedVecIntoIter<T> {}

impl<T> IntoIterator for AdmittedVec<T> {
    type Item = T;
    type IntoIter = AdmittedVecIntoIter<T>;

    fn into_iter(mut self) -> Self::IntoIter {
        let values = core::mem::take(&mut self.values);
        let charge = self.charge.take();
        AdmittedVecIntoIter {
            iter: values.into_iter(),
            _charge: charge,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for AdmittedVec<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmittedVec")
            .field("values", &self.values)
            .field("capacity", &self.values.capacity())
            .field("class", &self.class)
            .finish()
    }
}

/// Detached `VecDeque` backing plus its rollback-armed whole-heap reservation.
///
/// RF180-42 uses this two-phase owner to allocate outside resource/IRQ locks,
/// then install capacity without allocating once the blocking condition has
/// been rechecked.
pub struct PreparedAdmittedDequeCapacity<T> {
    values: VecDeque<T>,
    reservation: HeapReservation,
}

/// Detached obsolete `VecDeque` backing whose allocation and lifetime charge
/// must be destroyed after the caller has left any IRQ-disabled or resource-
/// lock critical section.
///
/// The backing field deliberately precedes the charge field.  Rust therefore
/// frees the allocator storage before returning its bytes to the whole-heap
/// admission ledger when this owner is dropped.
#[must_use = "retired admitted backing must be dropped in a safe process context"]
pub struct RetiredAdmittedDequeCapacity<T> {
    _values: VecDeque<T>,
    _charge: Option<HeapCharge>,
}

impl<T> PreparedAdmittedDequeCapacity<T> {
    /// Prepare detached ring backing without borrowing or locking a live queue.
    /// This is the primitive WaitQueue uses for its snapshot/allocate/recheck
    /// transaction.
    pub fn try_new(class: HeapClass, target: usize) -> Result<Self, AdmittedAllocError> {
        let mut reservation = reserve_vec::<T>(class, target)?;
        let mut values = VecDeque::new();
        values
            .try_reserve_exact(target)
            .map_err(|_| AdmittedAllocError::AllocationFailed)?;
        reservation.resize(vec_charge_bytes::<T>(values.capacity())?)?;
        Ok(Self {
            values,
            reservation,
        })
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.values.capacity()
    }

    #[inline]
    pub fn class(&self) -> HeapClass {
        self.reservation.class()
    }
}

/// A retained FIFO whose ring backing is admitted against the whole-heap
/// ledger. The underlying `VecDeque` uses one `RawVec` allocation, so the same
/// allocator-layout charge used by [`AdmittedVec`] is conservative here too.
///
/// `values` precedes `charge`: replacing or reclaiming backing always destroys
/// the allocation before releasing its committed bytes. IRQ-facing consumers
/// use the explicit `*_retaining_capacity` operations and defer
/// [`AdmittedDeque::reclaim_empty_capacity`] to process context.
pub struct AdmittedDeque<T> {
    values: VecDeque<T>,
    charge: Option<HeapCharge>,
    class: HeapClass,
}

impl<T> AdmittedDeque<T> {
    pub const fn new(class: HeapClass) -> Self {
        Self {
            values: VecDeque::new(),
            charge: None,
            class,
        }
    }

    #[inline]
    pub fn class(&self) -> HeapClass {
        self.class
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.values.capacity()
    }

    #[inline]
    pub fn front(&self) -> Option<&T> {
        self.values.front()
    }

    #[inline]
    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.values.front_mut()
    }

    #[inline]
    pub fn back(&self) -> Option<&T> {
        self.values.back()
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.values.get(index)
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.values.get_mut(index)
    }

    #[inline]
    pub fn iter(&self) -> alloc::collections::vec_deque::Iter<'_, T> {
        self.values.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> alloc::collections::vec_deque::IterMut<'_, T> {
        self.values.iter_mut()
    }

    fn prepare_target(
        &self,
        target: usize,
    ) -> Result<PreparedAdmittedDequeCapacity<T>, AdmittedAllocError> {
        if target < self.values.len() {
            return Err(AdmittedAllocError::CapacityInvariant);
        }
        PreparedAdmittedDequeCapacity::try_new(self.class, target)
    }

    pub fn prepare_capacity_for(
        &self,
        additional: usize,
    ) -> Result<Option<PreparedAdmittedDequeCapacity<T>>, AdmittedAllocError> {
        let required =
            self.values
                .len()
                .checked_add(additional)
                .ok_or(AdmittedAllocError::Admission(
                    HeapAdmissionError::ArithmeticOverflow,
                ))?;
        if required <= self.values.capacity() {
            return Ok(None);
        }
        let preferred = growth_target(self.values.capacity(), required)?;
        match self.prepare_target(preferred) {
            Ok(prepared) => Ok(Some(prepared)),
            Err(_) if preferred != required => self.prepare_target(required).map(Some),
            Err(error) => Err(error),
        }
    }

    pub fn prepare_exact_capacity(
        &self,
        required: usize,
    ) -> Result<Option<PreparedAdmittedDequeCapacity<T>>, AdmittedAllocError> {
        if required <= self.values.capacity() {
            Ok(None)
        } else {
            self.prepare_target(required).map(Some)
        }
    }

    /// Allocation-free publication of detached backing.
    pub fn install_prepared(
        &mut self,
        prepared: PreparedAdmittedDequeCapacity<T>,
    ) -> Result<(), AdmittedAllocError> {
        let retired = self.install_prepared_deferred(prepared)?;
        drop(retired);
        Ok(())
    }

    /// Allocation-free publication that returns the obsolete backing instead
    /// of freeing it under the caller's lock/IRQ context.
    ///
    /// Moving the live FIFO into detached backing does not allocate.  The
    /// returned owner is empty of elements but still owns the old allocator
    /// capacity and its exact lifetime charge; callers may carry it out of a
    /// critical section and drop it there.
    pub fn install_prepared_deferred(
        &mut self,
        mut prepared: PreparedAdmittedDequeCapacity<T>,
    ) -> Result<RetiredAdmittedDequeCapacity<T>, AdmittedAllocError> {
        if prepared.values.capacity() < self.values.len()
            || prepared.reservation.class() != self.class
        {
            return Err(AdmittedAllocError::CapacityInvariant);
        }
        // `HeapReservation::commit` only converts already-reserved bytes and
        // panics on ledger corruption.  It cannot fail for resource pressure.
        let replacement_charge = prepared
            .reservation
            .commit()
            .expect("RF180-42 admitted deque commit invariant");
        let mut old_values = core::mem::take(&mut self.values);
        while let Some(value) = old_values.pop_front() {
            prepared.values.push_back(value);
        }
        let old_charge = self.charge.take();
        self.values = prepared.values;
        self.charge = Some(replacement_charge);
        Ok(RetiredAdmittedDequeCapacity {
            _values: old_values,
            _charge: old_charge,
        })
    }

    pub fn try_reserve(&mut self, additional: usize) -> Result<(), AdmittedAllocError> {
        if let Some(prepared) = self.prepare_capacity_for(additional)? {
            self.install_prepared(prepared)?;
        }
        Ok(())
    }

    pub fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AdmittedAllocError> {
        let required =
            self.values
                .len()
                .checked_add(additional)
                .ok_or(AdmittedAllocError::Admission(
                    HeapAdmissionError::ArithmeticOverflow,
                ))?;
        if let Some(prepared) = self.prepare_exact_capacity(required)? {
            self.install_prepared(prepared)?;
        }
        Ok(())
    }

    pub fn push_back_reserved(&mut self, value: T) -> Result<(), T> {
        if self.values.len() == self.values.capacity() {
            return Err(value);
        }
        self.values.push_back(value);
        Ok(())
    }

    pub fn push_front_reserved(&mut self, value: T) -> Result<(), T> {
        if self.values.len() == self.values.capacity() {
            return Err(value);
        }
        self.values.push_front(value);
        Ok(())
    }

    pub fn try_push_back(&mut self, value: T) -> Result<(), (AdmittedAllocError, T)> {
        if let Err(error) = self.try_reserve(1) {
            return Err((error, value));
        }
        self.push_back_reserved(value)
            .map_err(|value| (AdmittedAllocError::CapacityInvariant, value))
    }

    pub fn try_push_front(&mut self, value: T) -> Result<(), (AdmittedAllocError, T)> {
        if let Err(error) = self.try_reserve(1) {
            return Err((error, value));
        }
        self.push_front_reserved(value)
            .map_err(|value| (AdmittedAllocError::CapacityInvariant, value))
    }

    /// IRQ-safe removal: no allocation, deallocation, or admission update.
    #[inline]
    pub fn pop_front_retaining_capacity(&mut self) -> Option<T> {
        self.values.pop_front()
    }

    /// IRQ-safe removal: no allocation, deallocation, or admission update.
    #[inline]
    pub fn pop_back_retaining_capacity(&mut self) -> Option<T> {
        self.values.pop_back()
    }

    /// IRQ-safe indexed removal retaining admitted backing.
    #[inline]
    pub fn remove_retaining_capacity(&mut self, index: usize) -> Option<T> {
        self.values.remove(index)
    }

    /// Remove elements without shrinking or releasing the admitted backing.
    pub fn retain_capacity<F>(&mut self, keep: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.values.retain(keep);
    }

    /// Clear elements without deallocating; intended for allocation-free IRQ
    /// drains followed by process-context reclamation.
    pub fn clear_retaining_capacity(&mut self) {
        self.values.clear();
    }

    /// Process-context reclamation for an already-empty queue.
    pub fn reclaim_empty_capacity(&mut self) {
        drop(self.take_empty_capacity());
    }

    /// Detach empty retained backing without allocating or deallocating.
    ///
    /// This is the lock-safe half of process-context reclamation: remove the
    /// owner while the collection is protected, then drop the returned value
    /// after releasing that protection.
    pub fn take_empty_capacity(&mut self) -> Option<RetiredAdmittedDequeCapacity<T>> {
        if !self.values.is_empty() || self.values.capacity() == 0 {
            return None;
        }
        Some(RetiredAdmittedDequeCapacity {
            _values: core::mem::take(&mut self.values),
            _charge: self.charge.take(),
        })
    }
}

impl<T: fmt::Debug> fmt::Debug for AdmittedDeque<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmittedDeque")
            .field("values", &self.values)
            .field("capacity", &self.values.capacity())
            .field("class", &self.class)
            .finish()
    }
}

impl<T> Index<usize> for AdmittedDeque<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}

impl<T> IndexMut<usize> for AdmittedDeque<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.values[index]
    }
}

impl<'a, T> IntoIterator for &'a AdmittedDeque<T> {
    type Item = &'a T;
    type IntoIter = alloc::collections::vec_deque::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut AdmittedDeque<T> {
    type Item = &'a mut T;
    type IntoIter = alloc::collections::vec_deque::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter_mut()
    }
}

/// Detached backing plus its rollback-armed whole-heap reservation.
pub struct PreparedAdmittedMapCapacity<K: Ord, V> {
    backing: PreparedOrderedMapBacking<K, V>,
    reservation: HeapReservation,
}

/// Detached obsolete map backing and its already-committed charge. This owner
/// can either be dropped after releasing locks or restored to roll back a
/// capacity publication without allocation.
#[must_use = "retired admitted map backing must be dropped or restored"]
pub struct RetiredAdmittedMapCapacity<K: Ord, V> {
    backing: PreparedOrderedMapBacking<K, V>,
    charge: Option<HeapCharge>,
    class: HeapClass,
}

impl<K: Ord, V> PreparedAdmittedMapCapacity<K, V> {
    /// Prepare exact detached capacity without borrowing the live map.
    pub fn try_new(class: HeapClass, target: usize) -> Result<Self, AdmittedAllocError> {
        let mut reservation = reserve_vec::<(K, V)>(class, target)?;
        let backing = FallibleOrderedMap::try_prepare_backing_exact(target)
            .map_err(|_| AdmittedAllocError::AllocationFailed)?;
        reservation.resize(vec_charge_bytes::<(K, V)>(backing.capacity())?)?;
        Ok(Self {
            backing,
            reservation,
        })
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.backing.capacity()
    }

    #[inline]
    pub fn class(&self) -> HeapClass {
        self.reservation.class()
    }
}

/// A sorted, fallible map with admitted retained backing.
pub struct AdmittedMap<K: Ord, V> {
    map: FallibleOrderedMap<K, V>,
    charge: Option<HeapCharge>,
    class: HeapClass,
}

impl<K: Ord, V> AdmittedMap<K, V> {
    pub const fn new(class: HeapClass) -> Self {
        Self {
            map: FallibleOrderedMap::new(),
            charge: None,
            class,
        }
    }

    #[inline]
    pub fn class(&self) -> HeapClass {
        self.class
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    #[inline]
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get(key)
    }

    #[inline]
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.get_mut(key)
    }

    #[inline]
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.contains_key(key)
    }

    #[inline]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        self.map.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = (&K, &mut V)> {
        self.map.iter_mut()
    }

    #[inline]
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &K> {
        self.map.keys()
    }

    #[inline]
    pub fn values(&self) -> impl DoubleEndedIterator<Item = &V> {
        self.map.values()
    }

    #[inline]
    pub fn values_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut V> {
        self.map.values_mut()
    }

    #[inline]
    pub fn range<R: RangeBounds<K>>(&self, range: R) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        self.map.range(range)
    }

    fn prepare_target(
        &self,
        target: usize,
    ) -> Result<PreparedAdmittedMapCapacity<K, V>, AdmittedAllocError> {
        if target < self.map.len() {
            return Err(AdmittedAllocError::CapacityInvariant);
        }
        PreparedAdmittedMapCapacity::try_new(self.class, target)
    }

    pub fn prepare_capacity_for(
        &self,
        additional: usize,
    ) -> Result<Option<PreparedAdmittedMapCapacity<K, V>>, AdmittedAllocError> {
        let required =
            self.map
                .len()
                .checked_add(additional)
                .ok_or(AdmittedAllocError::Admission(
                    HeapAdmissionError::ArithmeticOverflow,
                ))?;
        if required <= self.map.capacity() {
            return Ok(None);
        }
        let preferred = growth_target(self.map.capacity(), required)?;
        match self.prepare_target(preferred) {
            Ok(prepared) => Ok(Some(prepared)),
            Err(_) if preferred != required => self.prepare_target(required).map(Some),
            Err(error) => Err(error),
        }
    }

    pub fn install_prepared(
        &mut self,
        prepared: PreparedAdmittedMapCapacity<K, V>,
    ) -> Result<(), AdmittedAllocError> {
        let retired = self.install_prepared_deferred(prepared)?;
        drop(retired);
        Ok(())
    }

    /// Publish detached backing without physically freeing the obsolete map
    /// allocation under the caller's lock.
    pub fn install_prepared_deferred(
        &mut self,
        prepared: PreparedAdmittedMapCapacity<K, V>,
    ) -> Result<RetiredAdmittedMapCapacity<K, V>, AdmittedAllocError> {
        if prepared.backing.capacity() < self.map.len()
            || prepared.reservation.class() != self.class
        {
            return Err(AdmittedAllocError::CapacityInvariant);
        }
        let replacement_charge = prepared
            .reservation
            .commit()
            .expect("RF180-43 admitted map commit invariant");
        let retired_backing = self
            .map
            .replace_backing_deferred(prepared.backing)
            .unwrap_or_else(|_| panic!("validated admitted map backing rejected"));
        let old_charge = self.charge.take();
        self.charge = Some(replacement_charge);
        Ok(RetiredAdmittedMapCapacity {
            backing: retired_backing,
            charge: old_charge,
            class: self.class,
        })
    }

    /// Restore previously retired backing and return the currently installed
    /// allocation for deferred destruction. This is the rollback half of a
    /// lock-safe prepare/publish transaction.
    pub fn restore_retired_deferred(
        &mut self,
        retired: RetiredAdmittedMapCapacity<K, V>,
    ) -> Result<RetiredAdmittedMapCapacity<K, V>, RetiredAdmittedMapCapacity<K, V>> {
        if retired.backing.capacity() < self.map.len() || retired.class != self.class {
            return Err(retired);
        }
        let RetiredAdmittedMapCapacity {
            backing,
            charge,
            class: _,
        } = retired;
        let displaced_backing = self
            .map
            .replace_backing_deferred(backing)
            .unwrap_or_else(|_| panic!("validated rollback backing rejected"));
        let displaced_charge = core::mem::replace(&mut self.charge, charge);
        Ok(RetiredAdmittedMapCapacity {
            backing: displaced_backing,
            charge: displaced_charge,
            class: self.class,
        })
    }

    pub fn ensure_capacity_for(&mut self, additional: usize) -> Result<(), AdmittedAllocError> {
        if let Some(prepared) = self.prepare_capacity_for(additional)? {
            self.install_prepared(prepared)?;
        }
        Ok(())
    }

    pub fn insert_unique_reserved(&mut self, key: K, value: V) -> Result<(), (K, V)> {
        self.map.insert_unique_reserved(key, value)
    }

    pub fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, AdmittedAllocError> {
        if self.map.contains_key(&key) {
            return self
                .map
                .try_insert(key, value)
                .map_err(|_| AdmittedAllocError::CapacityInvariant);
        }
        self.ensure_capacity_for(1)?;
        self.map
            .insert_unique_reserved(key, value)
            .map(|()| None)
            .map_err(|_| AdmittedAllocError::CapacityInvariant)
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let value = self.remove_retaining_capacity(key);
        self.reclaim_empty_capacity();
        value
    }

    /// Remove one value without releasing the admitted backing allocation.
    ///
    /// Transactional users use this when a later publication step may fail and
    /// must be able to restore the exact entry without allocating.  Once the
    /// transaction commits, call [`AdmittedMap::reclaim_empty_capacity`] to
    /// return an otherwise-empty backing allocation to the whole-heap ledger.
    #[inline]
    pub fn remove_retaining_capacity<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.remove(key)
    }

    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let value = self.remove_entry_retaining_capacity(key);
        self.reclaim_empty_capacity();
        value
    }

    /// Remove an owned key/value pair while retaining admitted capacity for a
    /// possible allocation-free rollback.
    #[inline]
    pub fn remove_entry_retaining_capacity<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.remove_entry(key)
    }

    pub fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&K, &V) -> bool,
    {
        self.map.retain(keep);
        self.reclaim_empty_capacity();
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.reclaim_empty_capacity();
    }

    /// Release retained backing iff the map is empty.
    ///
    /// This is deliberately explicit for prepare/remove/publish transactions:
    /// a failed publish restores into the retained slot, while a successful
    /// publish calls this method after it no longer needs rollback capacity.
    pub fn reclaim_empty_capacity(&mut self) {
        drop(self.take_empty_capacity());
    }

    /// Detach empty backing without allocation, deallocation, or admission
    /// release. The returned owner must be dropped after protected locks.
    pub fn take_empty_capacity(&mut self) -> Option<RetiredAdmittedMapCapacity<K, V>> {
        if !self.map.is_empty() || self.map.capacity() == 0 {
            return None;
        }
        let retired_backing = self
            .map
            .replace_backing_deferred(PreparedOrderedMapBacking::empty())
            .unwrap_or_else(|_| panic!("empty admitted map rejected empty backing"));
        Some(RetiredAdmittedMapCapacity {
            backing: retired_backing,
            charge: self.charge.take(),
            class: self.class,
        })
    }
}

impl<K: Ord + fmt::Debug, V: fmt::Debug> fmt::Debug for AdmittedMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmittedMap")
            .field("map", &self.map)
            .field("capacity", &self.map.capacity())
            .field("class", &self.class)
            .finish()
    }
}

pub struct PreparedAdmittedSetCapacity<K: Ord> {
    prepared: PreparedAdmittedMapCapacity<K, ()>,
}

/// Detached obsolete set backing and its committed whole-heap charge.
///
/// Cgroup and other lock-owning users keep this owner alive until after their
/// protected lock is released, so replacing or reclaiming a set never invokes
/// the global allocator from inside the critical section.
#[must_use = "retired admitted set backing must be dropped or restored"]
pub struct RetiredAdmittedSetCapacity<K: Ord> {
    retired: RetiredAdmittedMapCapacity<K, ()>,
}

impl<K: Ord> PreparedAdmittedSetCapacity<K> {
    /// Prepare exact detached set capacity without borrowing a live set.
    pub fn try_new(class: HeapClass, target: usize) -> Result<Self, AdmittedAllocError> {
        PreparedAdmittedMapCapacity::try_new(class, target).map(|prepared| Self { prepared })
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.prepared.capacity()
    }

    #[inline]
    pub fn class(&self) -> HeapClass {
        self.prepared.class()
    }
}

/// An admitted sorted set implemented over [`AdmittedMap`].
pub struct AdmittedSet<K: Ord> {
    map: AdmittedMap<K, ()>,
}

impl<K: Ord> AdmittedSet<K> {
    pub const fn new(class: HeapClass) -> Self {
        Self {
            map: AdmittedMap::new(class),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    #[inline]
    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.contains_key(key)
    }

    #[inline]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &K> {
        self.map.keys()
    }

    pub fn prepare_capacity_for(
        &self,
        additional: usize,
    ) -> Result<Option<PreparedAdmittedSetCapacity<K>>, AdmittedAllocError> {
        self.map
            .prepare_capacity_for(additional)
            .map(|prepared| prepared.map(|prepared| PreparedAdmittedSetCapacity { prepared }))
    }

    pub fn install_prepared(
        &mut self,
        prepared: PreparedAdmittedSetCapacity<K>,
    ) -> Result<(), AdmittedAllocError> {
        let retired = self.install_prepared_deferred(prepared)?;
        drop(retired);
        Ok(())
    }

    /// Publish detached backing without freeing the obsolete allocation under
    /// the caller's lock.
    pub fn install_prepared_deferred(
        &mut self,
        prepared: PreparedAdmittedSetCapacity<K>,
    ) -> Result<RetiredAdmittedSetCapacity<K>, AdmittedAllocError> {
        self.map
            .install_prepared_deferred(prepared.prepared)
            .map(|retired| RetiredAdmittedSetCapacity { retired })
    }

    /// Restore retired backing for allocation-free transactional rollback.
    pub fn restore_retired_deferred(
        &mut self,
        retired: RetiredAdmittedSetCapacity<K>,
    ) -> Result<RetiredAdmittedSetCapacity<K>, RetiredAdmittedSetCapacity<K>> {
        match self.map.restore_retired_deferred(retired.retired) {
            Ok(current) => Ok(RetiredAdmittedSetCapacity { retired: current }),
            Err(original) => Err(RetiredAdmittedSetCapacity { retired: original }),
        }
    }

    pub fn ensure_capacity_for(&mut self, additional: usize) -> Result<(), AdmittedAllocError> {
        self.map.ensure_capacity_for(additional)
    }

    pub fn insert_reserved(&mut self, key: K) -> Result<bool, K> {
        if self.map.contains_key(&key) {
            return Ok(false);
        }
        self.map
            .insert_unique_reserved(key, ())
            .map(|()| true)
            .map_err(|(key, ())| key)
    }

    pub fn try_insert(&mut self, key: K) -> Result<bool, AdmittedAllocError> {
        self.map.try_insert(key, ()).map(|old| old.is_none())
    }

    pub fn remove<Q>(&mut self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.remove(key).is_some()
    }

    /// Remove while retaining the admitted slot for allocation-free rollback.
    #[inline]
    pub fn remove_retaining_capacity<Q>(&mut self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.map.remove_retaining_capacity(key).is_some()
    }

    /// Release retained backing iff the set is empty.
    #[inline]
    pub fn reclaim_empty_capacity(&mut self) {
        drop(self.take_empty_capacity());
    }

    /// Detach empty backing without allocation, deallocation, or admission
    /// release. The returned owner must be destroyed after protected locks.
    #[inline]
    pub fn take_empty_capacity(&mut self) -> Option<RetiredAdmittedSetCapacity<K>> {
        self.map
            .take_empty_capacity()
            .map(|retired| RetiredAdmittedSetCapacity { retired })
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }
}

impl<K: Ord + fmt::Debug> fmt::Debug for AdmittedSet<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// A retained UTF-8 buffer with admitted allocator capacity.
pub struct AdmittedString {
    value: String,
    charge: Option<HeapCharge>,
    class: HeapClass,
}

impl AdmittedString {
    pub const fn new(class: HeapClass) -> Self {
        Self {
            value: String::new(),
            charge: None,
            class,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.value.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.value.capacity()
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    fn replace_capacity(&mut self, target: usize) -> Result<(), AdmittedAllocError> {
        if target < self.value.len() {
            return Err(AdmittedAllocError::CapacityInvariant);
        }
        let mut reservation = reserve_vec::<u8>(self.class, target)?;
        let mut replacement = String::new();
        replacement
            .try_reserve_exact(target)
            .map_err(|_| AdmittedAllocError::AllocationFailed)?;
        reservation.resize(vec_charge_bytes::<u8>(replacement.capacity())?)?;
        let replacement_charge = reservation.commit()?;
        replacement.push_str(self.value.as_str());
        let old_value = core::mem::replace(&mut self.value, replacement);
        drop(old_value);
        let old_charge = self.charge.take();
        self.charge = Some(replacement_charge);
        drop(old_charge);
        Ok(())
    }

    pub fn try_reserve(&mut self, additional: usize) -> Result<(), AdmittedAllocError> {
        let required =
            self.value
                .len()
                .checked_add(additional)
                .ok_or(AdmittedAllocError::Admission(
                    HeapAdmissionError::ArithmeticOverflow,
                ))?;
        if required <= self.value.capacity() {
            return Ok(());
        }
        let preferred = growth_target(self.value.capacity(), required)?;
        match self.replace_capacity(preferred) {
            Ok(()) => Ok(()),
            Err(_) if preferred != required => self.replace_capacity(required),
            Err(error) => Err(error),
        }
    }

    pub fn try_push_str(&mut self, value: &str) -> Result<(), AdmittedAllocError> {
        self.try_reserve(value.len())?;
        self.value.push_str(value);
        Ok(())
    }

    pub fn try_push(&mut self, value: char) -> Result<(), AdmittedAllocError> {
        self.try_reserve(value.len_utf8())?;
        self.value.push(value);
        Ok(())
    }

    pub fn clear(&mut self) {
        self.value.clear();
        if self.value.capacity() != 0 {
            let old_value = core::mem::take(&mut self.value);
            drop(old_value);
            let old_charge = self.charge.take();
            drop(old_charge);
        }
    }

    /// Shorten without changing allocator capacity or admission.
    pub fn truncate(&mut self, new_len: usize) {
        self.value.truncate(new_len);
    }

    pub fn try_from_str(class: HeapClass, value: &str) -> Result<Self, AdmittedAllocError> {
        let mut out = Self::new(class);
        out.try_push_str(value)?;
        Ok(out)
    }
}

impl fmt::Write for AdmittedString {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.try_push_str(value).map_err(|_| fmt::Error)
    }

    fn write_char(&mut self, value: char) -> fmt::Result {
        self.try_push(value).map_err(|_| fmt::Error)
    }
}

impl Deref for AdmittedString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.value.as_str()
    }
}

impl fmt::Display for AdmittedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.value.as_str())
    }
}

impl fmt::Debug for AdmittedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmittedString")
            .field("value", &self.value)
            .field("capacity", &self.value.capacity())
            .field("class", &self.class)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_containers_reclaim_empty_backing() {
        let _guard = crate::heap_admission::TEST_LEDGER_LOCK.lock();
        crate::heap_admission::publish();
        let before = crate::heap_admission::class_snapshot(HeapClass::Procfs);

        let mut values = AdmittedVec::new(HeapClass::Procfs);
        values.try_push(7usize).expect("admitted Vec push");
        assert!(values.capacity() >= 1);
        assert_eq!(values.pop(), Some(7));
        assert_eq!(values.capacity(), 0);

        let mut map = AdmittedMap::new(HeapClass::Procfs);
        assert_eq!(map.try_insert(3usize, 9usize), Ok(None));
        let retained_capacity = map.capacity();
        assert_eq!(map.remove_retaining_capacity(&3), Some(9));
        assert_eq!(map.capacity(), retained_capacity);
        map.reclaim_empty_capacity();
        assert_eq!(map.capacity(), 0);

        let mut queue = AdmittedDeque::new(HeapClass::Procfs);
        queue.try_push_back(1usize).expect("admitted deque push");
        queue.try_push_back(2usize).expect("admitted deque push");
        let retained_capacity = queue.capacity();
        let retained_charge = crate::heap_admission::class_snapshot(HeapClass::Procfs);
        assert_eq!(queue.pop_front_retaining_capacity(), Some(1));
        assert_eq!(queue.pop_front_retaining_capacity(), Some(2));
        assert_eq!(queue.capacity(), retained_capacity);
        assert_eq!(
            crate::heap_admission::class_snapshot(HeapClass::Procfs),
            retained_charge,
            "IRQ-style drain must retain both backing and its charge"
        );
        queue.reclaim_empty_capacity();
        assert_eq!(queue.capacity(), 0);

        let mut text = AdmittedString::new(HeapClass::Procfs);
        use core::fmt::Write;
        write!(&mut text, "{}:{}", 1, 2).expect("admitted format");
        assert_eq!(text.as_str(), "1:2");
        text.clear();
        assert_eq!(text.capacity(), 0);

        assert_eq!(
            crate::heap_admission::class_snapshot(HeapClass::Procfs),
            before,
            "empty-container reclamation must return every committed byte"
        );
    }

    #[test]
    fn admitted_deque_preparation_is_detached_and_fifo_preserving() {
        let _guard = crate::heap_admission::TEST_LEDGER_LOCK.lock();
        crate::heap_admission::publish();
        let before = crate::heap_admission::class_snapshot(HeapClass::BlockingIo);

        let mut queue = AdmittedDeque::new(HeapClass::BlockingIo);
        queue.try_push_back(10usize).expect("first queue element");
        queue.try_push_back(20usize).expect("second queue element");
        let live = crate::heap_admission::class_snapshot(HeapClass::BlockingIo);

        let prepared = queue
            .prepare_exact_capacity(queue.capacity() + 8)
            .expect("detached queue preparation")
            .expect("larger capacity requires preparation");
        let with_reservation = crate::heap_admission::class_snapshot(HeapClass::BlockingIo);
        assert_eq!(with_reservation.committed_bytes, live.committed_bytes);
        assert!(with_reservation.reserved_bytes > live.reserved_bytes);
        assert_eq!(
            queue.iter().copied().collect::<alloc::vec::Vec<_>>(),
            [10, 20]
        );
        drop(prepared);
        assert_eq!(
            crate::heap_admission::class_snapshot(HeapClass::BlockingIo),
            live,
            "abandoned preparation must roll its reservation back"
        );

        let prepared = queue
            .prepare_exact_capacity(queue.capacity() + 8)
            .expect("detached queue preparation")
            .expect("larger capacity requires preparation");
        queue
            .install_prepared(prepared)
            .expect("allocation-free queue installation");
        assert_eq!(queue.pop_front_retaining_capacity(), Some(10));
        assert_eq!(queue.pop_front_retaining_capacity(), Some(20));
        queue.reclaim_empty_capacity();
        assert_eq!(
            crate::heap_admission::class_snapshot(HeapClass::BlockingIo),
            before,
            "installed queue backing must be released exactly after deallocation"
        );
    }

    #[test]
    fn admitted_deque_deferred_retirement_keeps_charge_until_safe_drop() {
        let _guard = crate::heap_admission::TEST_LEDGER_LOCK.lock();
        crate::heap_admission::publish();
        let before = crate::heap_admission::class_snapshot(HeapClass::Scheduler);

        let mut queue = AdmittedDeque::new(HeapClass::Scheduler);
        queue.try_push_back(7usize).expect("initial queue backing");
        let old_live = crate::heap_admission::class_snapshot(HeapClass::Scheduler);
        let prepared = queue
            .prepare_exact_capacity(queue.capacity() + 8)
            .expect("detached replacement preparation")
            .expect("larger capacity requires replacement");

        let retired = queue
            .install_prepared_deferred(prepared)
            .expect("deferred replacement installation");
        let both_live = crate::heap_admission::class_snapshot(HeapClass::Scheduler);
        assert!(both_live.committed_bytes > old_live.committed_bytes);
        assert_eq!(queue.front(), Some(&7));

        drop(retired);
        let replacement_only = crate::heap_admission::class_snapshot(HeapClass::Scheduler);
        assert!(replacement_only.committed_bytes < both_live.committed_bytes);
        assert_eq!(replacement_only.reserved_bytes, old_live.reserved_bytes);

        assert_eq!(queue.pop_front_retaining_capacity(), Some(7));
        let retired_empty = queue
            .take_empty_capacity()
            .expect("empty backing must detach without freeing");
        assert_eq!(queue.capacity(), 0);
        assert_eq!(
            crate::heap_admission::class_snapshot(HeapClass::Scheduler),
            replacement_only,
            "detaching under a lock must not release admission early"
        );
        drop(retired_empty);
        assert_eq!(
            crate::heap_admission::class_snapshot(HeapClass::Scheduler),
            before,
            "safe-context retirement must return the exact lifetime charge"
        );
    }
}
