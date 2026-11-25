//! ST-K2-P2(a): a spin mutex that records which CPU holds it.
//!
//! Exception context reads the record to tell its own CPU's hold apart from
//! another CPU's. A guard held by the interrupted context on the same CPU can
//! never be released before the handler returns, so a try-only fault path that
//! keeps retrying it livelocks; a hold on another CPU is ordinary contention
//! that resolves on retry. This mirrors `PT_LOCK_OWNER_CPU` for the global
//! page-table lock (`mm::pt_lock_owner_cpu`).
//!
//! The test is sound because kernel mode is not preemptible and no guard of
//! these locks is held across a task switch: while a CPU runs an exception
//! handler, a guard recorded for that CPU belongs to the context it
//! interrupted.
//!
//! The record is a per-CPU token, the address of the CPU's `SYSCALL_PERCPU`
//! slot, read from the GS base MSRs. `cpu_local::current_cpu_id` would read the
//! LAPIC ID over MMIO on every acquisition of these hot locks; under TCG each
//! such read serializes on QEMU's global lock, which slowed 16-vCPU guests
//! enough to change their behavior.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const NO_OWNER: usize = usize::MAX;

/// Start of the kernel half. A user GS base is always below the user-half
/// top (`validate_user_segment_base`); every `SYSCALL_PERCPU` slot is above.
#[cfg(target_os = "none")]
const KERNEL_HALF: u64 = 0xffff_8000_0000_0000;

/// This CPU's owner token: the address of its `SYSCALL_PERCPU` slot. Kernel
/// context has it in `IA32_GS_BASE`. An exception or IRQ taken from Ring 3
/// runs before any SWAPGS, with the user's base there and the slot in
/// `IA32_KERNEL_GS_BASE`. Both read 0 before the CPU installs its slot, which
/// is before any shared-anonymous fault can run on it.
#[inline]
fn cpu_token() -> usize {
    #[cfg(target_os = "none")]
    {
        use x86_64::registers::model_specific::Msr;
        // SAFETY: reading IA32_GS_BASE and IA32_KERNEL_GS_BASE has no side
        // effects, and both MSRs exist on every x86-64 CPU.
        unsafe {
            let gs = Msr::new(0xC000_0101).read();
            if gs >= KERNEL_HALF {
                gs as usize
            } else {
                Msr::new(0xC000_0102).read() as usize
            }
        }
    }
    // Hosted tests run as an ordinary process, where `rdmsr` faults. They can
    // reach these locks through any dependent crate, whichever harness feature
    // that crate enables, so the target decides rather than a feature.
    #[cfg(not(target_os = "none"))]
    {
        cpu_local::current_cpu_id()
    }
}

/// Spin mutex with the holding CPU's token recorded while a guard is live.
///
/// Issue #109 §3.1: owns `locked: AtomicBool` and `data: UnsafeCell<T>`
/// directly so callers can construct large payloads (such as `Process`) in
/// place inside `MaybeUninit<OwnerCpuMutex<T>>` via [`Self::init_in_place`]
/// without staging a `T` temporary on the kernel stack.
pub struct OwnerCpuMutex<T: ?Sized> {
    owner: AtomicUsize,
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: Synchronizes mutable access to `T` via `locked` with Acquire/Release
// ordering, identical to `spin::Mutex<T>`.
unsafe impl<T: ?Sized + Send> Send for OwnerCpuMutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for OwnerCpuMutex<T> {}

/// Guard of an [`OwnerCpuMutex`]; dropping it clears the owner record before
/// the lock is released.
pub struct OwnerCpuMutexGuard<'a, T: ?Sized + 'a> {
    lock: &'a OwnerCpuMutex<T>,
}

// Guards must be released on the same CPU/thread that acquired them.
impl<T: ?Sized> !Send for OwnerCpuMutexGuard<'_, T> {}
unsafe impl<T: ?Sized + Sync> Sync for OwnerCpuMutexGuard<'_, T> {}

impl<T> OwnerCpuMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            owner: AtomicUsize::new(NO_OWNER),
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    /// Initialize an `OwnerCpuMutex<T>` directly in uninitialized storage
    /// without staging a `T` value on the caller's stack.
    ///
    /// # Safety
    ///
    /// - `slot` must point to valid, aligned, writable storage for
    ///   `OwnerCpuMutex<T>`.
    /// - `init_data` must completely initialize the `T` at the pointer it
    ///   receives (and must not unwind leaving partial state unless the caller
    ///   never assumes initialization).
    #[inline]
    pub unsafe fn init_in_place(slot: *mut Self, init_data: impl FnOnce(*mut T)) {
        core::ptr::addr_of_mut!((*slot).owner).write(AtomicUsize::new(NO_OWNER));
        core::ptr::addr_of_mut!((*slot).locked).write(AtomicBool::new(false));
        let data_ptr = UnsafeCell::raw_get(core::ptr::addr_of!((*slot).data));
        init_data(data_ptr);
    }
}

impl<T: ?Sized> OwnerCpuMutex<T> {
    #[inline]
    pub fn lock(&self) -> OwnerCpuMutexGuard<'_, T> {
        // Test-and-test-and-set spin loop avoids dirtying the lock cache line
        // while contended.
        loop {
            if self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.owner.store(cpu_token(), Ordering::Release);
                return OwnerCpuMutexGuard { lock: self };
            }
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    #[inline]
    pub fn try_lock(&self) -> Option<OwnerCpuMutexGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.owner.store(cpu_token(), Ordering::Release);
            Some(OwnerCpuMutexGuard { lock: self })
        } else {
            None
        }
    }

    /// Whether the calling CPU holds this lock: a try-lock failure the caller
    /// can never wait out from exception context.
    #[inline]
    pub fn held_by_current_cpu(&self) -> bool {
        match self.owner.load(Ordering::Acquire) {
            NO_OWNER => false,
            owner => owner == cpu_token(),
        }
    }

    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

impl<T: ?Sized + core::fmt::Debug> core::fmt::Debug for OwnerCpuMutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.try_lock() {
            Some(guard) => f
                .debug_struct("OwnerCpuMutex")
                .field("data", &&*guard)
                .finish(),
            None => f
                .debug_struct("OwnerCpuMutex")
                .field("data", &"<locked>")
                .finish(),
        }
    }
}

impl<T: ?Sized> Drop for OwnerCpuMutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // Clear owner record strictly before releasing the lock, so the record
        // never names a CPU that has already released the lock.
        self.lock.owner.store(NO_OWNER, Ordering::Release);
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<T: ?Sized> Deref for OwnerCpuMutexGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: Guard holds exclusive access to `self.lock.data`.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for OwnerCpuMutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Guard holds exclusive access to `self.lock.data`.
        unsafe { &mut *self.lock.data.get() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn st_k2_p2_owner_is_recorded_while_held_and_cleared_on_release() {
        let lock = OwnerCpuMutex::new(7u32);
        assert!(!lock.held_by_current_cpu());
        {
            let mut guard = lock.lock();
            *guard += 1;
            assert!(lock.held_by_current_cpu());
        }
        assert!(!lock.held_by_current_cpu());
        let guard = lock.try_lock().expect("an unheld lock is available");
        assert_eq!(*guard, 8);
        assert!(lock.held_by_current_cpu());
        drop(guard);
        assert!(!lock.is_locked());
    }

    #[test]
    fn st_k2_p2_nested_try_lock_fails_and_names_this_cpu() {
        // The reentry signature the shared-fault path diagnoses: a try-lock
        // that fails while the record names the CPU that is asking.
        let lock = OwnerCpuMutex::new(());
        let held = lock.lock();
        assert!(lock.try_lock().is_none());
        assert!(lock.held_by_current_cpu());
        drop(held);
        assert!(lock.try_lock().is_some());
        assert!(!lock.held_by_current_cpu());
        assert!(!lock.is_locked());
    }

    #[test]
    fn init_in_place_initializes_mutex_without_staging_payload() {
        let mut storage: MaybeUninit<OwnerCpuMutex<[u64; 16]>> = MaybeUninit::uninit();
        unsafe {
            OwnerCpuMutex::init_in_place(storage.as_mut_ptr(), |arr_ptr| {
                let elem = arr_ptr as *mut u64;
                for i in 0..16usize {
                    elem.add(i).write((i as u64) * 3 + 1);
                }
            });
            let mutex = storage.assume_init();
            assert!(!mutex.is_locked());
            assert!(!mutex.held_by_current_cpu());
            {
                let mut g = mutex.lock();
                assert!(mutex.held_by_current_cpu());
                assert_eq!(g[0], 1);
                assert_eq!(g[15], 46);
                g[3] = 99;
            }
            assert!(!mutex.is_locked());
            assert!(!mutex.held_by_current_cpu());
            assert_eq!(mutex.lock()[3], 99);
        }
    }
}
