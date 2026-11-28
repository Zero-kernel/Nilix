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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

const NO_OWNER: usize = usize::MAX;

/// Start of the kernel half. A user GS base is always below the user-half
/// top (`validate_user_segment_base`); every `SYSCALL_PERCPU` slot is above.
#[cfg(target_os = "none")]
const KERNEL_HALF: u64 = 0xffff_8000_0000_0000;

/// Fast Ring-0 owner token: this CPU's logical ID via Issue #109 §2.1 GS-base
/// single-instruction fast path (`gs:[80]`), avoiding `rdmsr(IA32_GS_BASE)` on
/// every `OwnerCpuMutex::lock()` / `try_lock()`.
#[inline]
fn cpu_token_ring0() -> usize {
    cpu_local::current_cpu_id()
}

/// Exception-safe owner token for `held_by_current_cpu()`.
///
/// Kernel context already has the `SYSCALL_PERCPU` slot in `IA32_GS_BASE` so
/// `cpu_local::current_cpu_id()` resolves directly. An exception or IRQ taken
/// from Ring 3 before `SWAPGS` has the user GS base in `IA32_GS_BASE` and the
/// `SYSCALL_PERCPU` slot in `IA32_KERNEL_GS_BASE`, so we decode
/// `encoded_cpu_id` (`GS_CPU_ID_OFFSET`) from `IA32_KERNEL_GS_BASE` directly.
#[inline]
fn cpu_token_exception() -> usize {
    #[cfg(target_os = "none")]
    {
        use x86_64::registers::model_specific::Msr;
        // SAFETY: reading IA32_GS_BASE and IA32_KERNEL_GS_BASE has no side
        // effects, and both MSRs exist on every x86-64 CPU.
        unsafe {
            let gs = Msr::new(0xC000_0101).read();
            if gs >= KERNEL_HALF {
                cpu_local::current_cpu_id()
            } else {
                let kgs = Msr::new(0xC000_0102).read();
                if kgs >= KERNEL_HALF {
                    let encoded = core::ptr::read_volatile(
                        (kgs as usize + cpu_local::GS_CPU_ID_OFFSET) as *const u64,
                    );
                    if encoded > 0 && (encoded as usize) <= cpu_local::max_cpus() {
                        return (encoded - 1) as usize;
                    }
                }
                cpu_local::current_cpu_id()
            }
        }
    }
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
                self.owner.store(cpu_token_ring0(), Ordering::Release);
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
            self.owner.store(cpu_token_ring0(), Ordering::Release);
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
            owner => owner == cpu_token_exception(),
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

/// Cache-line-isolated per-CPU reader state for [`OwnerCpuRwLock`].
///
/// Keeping each CPU's reader counters on its own 64-byte cache line prevents
/// cross-CPU cache-line bouncing on concurrent read-only `PROCESS_TABLE`
/// lookups (every syscall entry, scheduler switch, waitpid check, and cgroup
/// stat read).
///
/// `count` tracks speculative + admitted readers for the Dekker handshake with
/// writers; `admitted` tracks only guards that already passed `!writer_active`
/// (decremented before `count` on `Drop`), so a bare-metal nested/IRQ reader
/// can bypass a waiting writer iff an outer guard on the same CPU is genuinely
/// admitted and never when a speculative `read()` races an active writer.
#[repr(align(64))]
struct AlignedReaderSlot {
    count: AtomicU32,
    admitted: AtomicU32,
}

impl AlignedReaderSlot {
    const fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
            admitted: AtomicU32::new(0),
        }
    }
}

/// Per-CPU big-reader spinlock (`brlock`) with writer-CPU ownership tracking.
///
/// - **Readers (`read` / `try_read`)**: disable preemption on bare metal so the
///   task stays pinned to one CPU for the duration of the guard, increment only
///   this CPU's cache-line-aligned counter with `SeqCst`, and verify
///   `!writer_active`. Zero cross-CPU bus traffic while no writer is active.
/// - **Writers (`lock` / `try_lock`)**: acquire the inner [`OwnerCpuMutex<()>`],
///   publish `writer_active = true` with `SeqCst` (preventing reader starvation
///   of writers), and drain every online CPU's reader counter to 0.
/// - **Exception re-entry (`held_by_current_cpu`)**: reports `true` whenever
///   this CPU holds either the write lock or an active read guard.
pub struct OwnerCpuRwLock<T: ?Sized> {
    writer_lock: OwnerCpuMutex<()>,
    writer_active: AtomicBool,
    readers: [AlignedReaderSlot; cpu_local::max_cpus()],
    data: UnsafeCell<T>,
}

// SAFETY: Synchronizes shared `&T` access across concurrent readers and
// exclusive `&mut T` access for a single writer via Dekker `SeqCst` ordering.
unsafe impl<T: ?Sized + Send + Sync> Send for OwnerCpuRwLock<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for OwnerCpuRwLock<T> {}

pub struct OwnerCpuRwReadGuard<'a, T: ?Sized + 'a> {
    lock: &'a OwnerCpuRwLock<T>,
    cpu: usize,
}

impl<T: ?Sized> !Send for OwnerCpuRwReadGuard<'_, T> {}
unsafe impl<T: ?Sized + Sync> Sync for OwnerCpuRwReadGuard<'_, T> {}

pub struct OwnerCpuRwWriteGuard<'a, T: ?Sized + 'a> {
    lock: &'a OwnerCpuRwLock<T>,
    _writer_guard: OwnerCpuMutexGuard<'a, ()>,
}

impl<T: ?Sized> !Send for OwnerCpuRwWriteGuard<'_, T> {}
unsafe impl<T: ?Sized + Sync> Sync for OwnerCpuRwWriteGuard<'_, T> {}

#[inline]
fn rwlock_reader_cpu() -> usize {
    let cpu = cpu_token_ring0();
    if cpu < cpu_local::max_cpus() {
        cpu
    } else {
        0
    }
}

#[inline]
fn rwlock_drain_mask() -> u64 {
    let online = cpu_local::online_cpu_mask();
    let self_bit = 1u64 << rwlock_reader_cpu();
    if online == 0 {
        1u64 | self_bit
    } else {
        online | self_bit
    }
}

impl<T> OwnerCpuRwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            writer_lock: OwnerCpuMutex::new(()),
            writer_active: AtomicBool::new(false),
            readers: [const { AlignedReaderSlot::new() }; cpu_local::max_cpus()],
            data: UnsafeCell::new(value),
        }
    }
}

impl<T: ?Sized> OwnerCpuRwLock<T> {
    /// Acquire a shared read guard (local cache-line only when uncontended).
    #[inline]
    pub fn read(&self) -> OwnerCpuRwReadGuard<'_, T> {
        #[cfg(target_os = "none")]
        cpu_local::current_cpu().preempt_disable();

        let cpu = rwlock_reader_cpu();
        // On bare metal with preemption disabled, `admitted != 0` proves an
        // outer guard on this exact CPU already passed `!writer_active` and
        // holds `count >= 1`, so no writer can be in the critical section.
        // Bypassing `writer_active` here prevents outer-read -> waiting-writer
        // -> nested-read deadlock. Hosted builds share logical CPU 0 across
        // threads and always use the full Dekker handshake below.
        #[cfg(target_os = "none")]
        if self.readers[cpu].admitted.load(Ordering::Acquire) != 0 {
            // Bounded by nested read depth on one CPU; paired 1:1 with Drop. lint-fetch-add: allow
            self.readers[cpu].count.fetch_add(1, Ordering::AcqRel);
            // Bounded by nested read depth on one CPU; paired 1:1 with Drop. lint-fetch-add: allow
            self.readers[cpu].admitted.fetch_add(1, Ordering::Release);
            return OwnerCpuRwReadGuard { lock: self, cpu };
        }

        loop {
            while self.writer_active.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
            // Dekker store-load ordering: SeqCst increment before SeqCst load of
            // writer_active. Bounded by active read depth; paired 1:1 with Drop.
            // lint-fetch-add: allow
            self.readers[cpu].count.fetch_add(1, Ordering::SeqCst);
            if !self.writer_active.load(Ordering::SeqCst) {
                // Bounded by active read depth; paired 1:1 with Drop. lint-fetch-add: allow
                self.readers[cpu].admitted.fetch_add(1, Ordering::Release);
                return OwnerCpuRwReadGuard { lock: self, cpu };
            }
            self.readers[cpu].count.fetch_sub(1, Ordering::Release);
            core::hint::spin_loop();
        }
    }

    /// Non-blocking shared read guard acquisition for IRQ / timer contexts.
    #[inline]
    pub fn try_read(&self) -> Option<OwnerCpuRwReadGuard<'_, T>> {
        #[cfg(target_os = "none")]
        cpu_local::current_cpu().preempt_disable();

        let cpu = rwlock_reader_cpu();
        #[cfg(target_os = "none")]
        if self.readers[cpu].admitted.load(Ordering::Acquire) != 0 {
            // Bounded by nested read depth on one CPU; paired 1:1 with Drop. lint-fetch-add: allow
            self.readers[cpu].count.fetch_add(1, Ordering::AcqRel);
            // Bounded by nested read depth on one CPU; paired 1:1 with Drop. lint-fetch-add: allow
            self.readers[cpu].admitted.fetch_add(1, Ordering::Release);
            return Some(OwnerCpuRwReadGuard { lock: self, cpu });
        }

        if self.writer_active.load(Ordering::Acquire) {
            #[cfg(target_os = "none")]
            cpu_local::current_cpu().preempt_enable();
            return None;
        }
        // Dekker store-load ordering. Bounded by active read depth; paired 1:1
        // with Drop. lint-fetch-add: allow
        self.readers[cpu].count.fetch_add(1, Ordering::SeqCst);
        if !self.writer_active.load(Ordering::SeqCst) {
            // Bounded by active read depth; paired 1:1 with Drop. lint-fetch-add: allow
            self.readers[cpu].admitted.fetch_add(1, Ordering::Release);
            return Some(OwnerCpuRwReadGuard { lock: self, cpu });
        }
        self.readers[cpu].count.fetch_sub(1, Ordering::Release);
        #[cfg(target_os = "none")]
        cpu_local::current_cpu().preempt_enable();
        None
    }

    /// Acquire the exclusive write guard (keeps `.lock()` naming for mutators).
    #[inline]
    pub fn lock(&self) -> OwnerCpuRwWriteGuard<'_, T> {
        let writer_guard = self.writer_lock.lock();
        // Dekker store-load ordering: publish writer_active before scanning readers.
        self.writer_active.store(true, Ordering::SeqCst);
        let mut mask = rwlock_drain_mask();
        while mask != 0 {
            let cpu = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            while self.readers[cpu].count.load(Ordering::SeqCst) != 0 {
                core::hint::spin_loop();
            }
        }
        OwnerCpuRwWriteGuard {
            lock: self,
            _writer_guard: writer_guard,
        }
    }

    /// Non-blocking exclusive write guard acquisition.
    #[inline]
    pub fn try_lock(&self) -> Option<OwnerCpuRwWriteGuard<'_, T>> {
        let writer_guard = self.writer_lock.try_lock()?;
        self.writer_active.store(true, Ordering::SeqCst);
        let mut mask = rwlock_drain_mask();
        while mask != 0 {
            let cpu = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            if self.readers[cpu].count.load(Ordering::SeqCst) != 0 {
                self.writer_active.store(false, Ordering::Release);
                drop(writer_guard);
                return None;
            }
        }
        Some(OwnerCpuRwWriteGuard {
            lock: self,
            _writer_guard: writer_guard,
        })
    }

    /// Whether the calling CPU currently holds either the write lock or an
    /// admitted read guard.
    #[inline]
    pub fn held_by_current_cpu(&self) -> bool {
        if self.writer_lock.held_by_current_cpu() {
            return true;
        }
        let cpu = cpu_token_exception();
        cpu < self.readers.len() && self.readers[cpu].admitted.load(Ordering::Acquire) != 0
    }
}

impl<T: ?Sized> Drop for OwnerCpuRwReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // Clear `admitted` BEFORE releasing `count` so an interrupting IRQ
        // cannot treat a departing guard as admitted after `count` reaches 0.
        self.lock.readers[self.cpu]
            .admitted
            .fetch_sub(1, Ordering::Release);
        self.lock.readers[self.cpu]
            .count
            .fetch_sub(1, Ordering::Release);
        #[cfg(target_os = "none")]
        cpu_local::current_cpu().preempt_enable();
    }
}

impl<T: ?Sized> Deref for OwnerCpuRwReadGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: Read guard guarantees no writer holds exclusive access.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for OwnerCpuRwWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        // Clear writer_active before `_writer_guard` releases `writer_lock`.
        self.lock.writer_active.store(false, Ordering::Release);
    }
}

impl<T: ?Sized> Deref for OwnerCpuRwWriteGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: Write guard guarantees exclusive access to `self.lock.data`.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for OwnerCpuRwWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Write guard guarantees exclusive access to `self.lock.data`.
        unsafe { &mut *self.lock.data.get() }
    }
}

/// Common exception-context re-entry query shared by [`OwnerCpuMutex`] and
/// [`OwnerCpuRwLock`].
pub trait OwnerCpuLock {
    fn held_by_current_cpu(&self) -> bool;
}

impl<T: ?Sized> OwnerCpuLock for OwnerCpuMutex<T> {
    #[inline]
    fn held_by_current_cpu(&self) -> bool {
        OwnerCpuMutex::held_by_current_cpu(self)
    }
}

impl<T: ?Sized> OwnerCpuLock for OwnerCpuRwLock<T> {
    #[inline]
    fn held_by_current_cpu(&self) -> bool {
        OwnerCpuRwLock::held_by_current_cpu(self)
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

    #[test]
    fn owner_cpu_rwlock_tracks_readers_writers_and_reentry() {
        let lock = OwnerCpuRwLock::new(10u32);
        assert!(!lock.held_by_current_cpu());
        {
            let r1 = lock.read();
            let r2 = lock.try_read().expect("concurrent readers allowed");
            assert_eq!(*r1, 10);
            assert_eq!(*r2, 10);
            assert!(lock.held_by_current_cpu());
            assert!(lock.try_lock().is_none());
        }
        assert!(!lock.held_by_current_cpu());
        {
            let mut w = lock.lock();
            *w = 42;
            assert!(lock.held_by_current_cpu());
            assert!(lock.try_read().is_none());
            assert!(lock.try_lock().is_none());
        }
        assert!(!lock.held_by_current_cpu());
        assert_eq!(*lock.read(), 42);
    }
}
