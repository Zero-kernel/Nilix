// kernel/sync_safe/lib.rs
//
// Safe synchronization primitives with IRQ-context safety checks
//
// Defense-in-Depth Layer 2: Runtime Detection
// Part of R173 defense strategy to prevent IRQ-context deadlocks

#![no_std]

extern crate alloc;

use core::fmt;
use core::ops::{Deref, DerefMut};

/// Re-export spin primitives with safety wrappers
pub use spin::RwLock;

/// Wrapper around spin::Mutex that checks for IRQ-context violations in debug mode
pub struct Mutex<T: ?Sized> {
    inner: spin::Mutex<T>,
}

impl<T> Mutex<T> {
    /// Create a new mutex
    pub const fn new(value: T) -> Self {
        Self {
            inner: spin::Mutex::new(value),
        }
    }

    /// Acquire the lock (blocking)
    ///
    /// # Safety Check (Debug Mode)
    ///
    /// In debug builds, panics if called with interrupts disabled.
    /// This catches R173-01/02 class deadlocks at runtime.
    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        #[cfg(debug_assertions)]
        {
            self.assert_irq_safe("Mutex::lock()");
        }

        MutexGuard {
            inner: self.inner.lock(),
        }
    }

    /// Try to acquire the lock without blocking
    ///
    /// Safe to call from IRQ context (returns None if contended)
    #[inline]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.inner
            .try_lock()
            .map(|guard| MutexGuard { inner: guard })
    }

    /// Check if interrupts are enabled (debug helper)
    #[cfg(debug_assertions)]
    fn assert_irq_safe(&self, context: &str) {
        // Check if interrupts are disabled
        let rflags: u64;
        unsafe {
            core::arch::asm!("pushfq; pop {}", out(reg) rflags, options(nomem, nostack));
        }

        const RFLAGS_IF: u64 = 1 << 9; // Interrupt Flag
        let interrupts_enabled = (rflags & RFLAGS_IF) != 0;

        if !interrupts_enabled {
            panic!(
                "FATAL: {} called with interrupts disabled (RFLAGS.IF=0)\n\
                 This is a R173-01/02 class deadlock!\n\
                 Use try_lock() instead in IRQ context.",
                context
            );
        }
    }
}

impl<T: ?Sized + Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.try_lock() {
            Some(guard) => write!(f, "Mutex {{ data: {:?} }}", &*guard),
            None => write!(f, "Mutex {{ <locked> }}"),
        }
    }
}

/// Guard returned by Mutex::lock() and Mutex::try_lock()
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    inner: spin::MutexGuard<'a, T>,
}

impl<'a, T: ?Sized> Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &*self.inner
    }
}

impl<'a, T: ?Sized> DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.inner
    }
}

impl<'a, T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: ?Sized + fmt::Display> fmt::Display for MutexGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutex_basic() {
        let mutex = Mutex::new(42);

        {
            let guard = mutex.lock();
            assert_eq!(*guard, 42);
        }

        {
            let mut guard = mutex.lock();
            *guard = 100;
        }

        let guard = mutex.lock();
        assert_eq!(*guard, 100);
    }

    #[test]
    fn test_mutex_try_lock() {
        let mutex = Mutex::new(42);

        let guard1 = mutex.lock();
        assert_eq!(*guard1, 42);

        // Should fail to acquire (already held)
        assert!(mutex.try_lock().is_none());

        drop(guard1);

        // Should succeed now
        assert!(mutex.try_lock().is_some());
    }
}
