use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub(crate) struct NamespaceCountPermit {
    counter: &'static AtomicU32,
}

impl NamespaceCountPermit {
    pub(crate) fn try_acquire(counter: &'static AtomicU32, limit: u32) -> Result<Self, ()> {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                if count < limit {
                    count.checked_add(1)
                } else {
                    None
                }
            })
            .map_err(|_| ())?;
        Ok(Self { counter })
    }
}

impl Drop for NamespaceCountPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NamespaceCreateError {
    MaxCount,
    IdOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NamespaceCreateStage {
    RootPath,
    ArcLayout,
    HeapReserve,
    ArcAllocation,
    HeapCommit,
}

#[derive(Clone, Copy)]
pub(crate) struct NamespaceCreateContext {
    counter: &'static AtomicU32,
    next_id: &'static AtomicU64,
    limit: u32,
    #[cfg(any(test, feature = "namespace_probe"))]
    fault: Option<NamespaceCreateStage>,
    #[cfg(feature = "namespace_probe")]
    fault_observed: Option<&'static core::sync::atomic::AtomicBool>,
}

impl NamespaceCreateContext {
    pub(crate) const fn new(
        counter: &'static AtomicU32,
        next_id: &'static AtomicU64,
        limit: u32,
    ) -> Self {
        Self {
            counter,
            next_id,
            limit,
            #[cfg(any(test, feature = "namespace_probe"))]
            fault: None,
            #[cfg(feature = "namespace_probe")]
            fault_observed: None,
        }
    }

    #[cfg(feature = "namespace_probe")]
    pub(crate) fn with_fault(
        mut self,
        stage: NamespaceCreateStage,
        observed: &'static core::sync::atomic::AtomicBool,
    ) -> Self {
        self.fault = Some(stage);
        self.fault_observed = Some(observed);
        self
    }

    #[cfg(any(test, feature = "namespace_probe"))]
    fn observe_injection(&self) {
        #[cfg(feature = "namespace_probe")]
        if let Some(observed) = self.fault_observed {
            observed.store(true, Ordering::Release);
        }
    }

    #[cfg(feature = "namespace_probe")]
    pub(crate) fn with_id_source(mut self, next_id: &'static AtomicU64) -> Self {
        self.next_id = next_id;
        self
    }

    pub(crate) fn reserve_id(&self) -> Result<(NamespaceCountPermit, u64), NamespaceCreateError> {
        let permit = NamespaceCountPermit::try_acquire(self.counter, self.limit)
            .map_err(|_| NamespaceCreateError::MaxCount)?;
        let id = self
            .next_id
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |next| {
                next.checked_add(1)
            })
            .map_err(|_| NamespaceCreateError::IdOverflow)?;
        Ok((permit, id))
    }

    #[inline]
    pub(crate) fn check(&self, _stage: NamespaceCreateStage) -> Result<(), ()> {
        #[cfg(any(test, feature = "namespace_probe"))]
        if self.fault == Some(_stage) {
            self.observe_injection();
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn try_arc<T>(&self, value: T) -> Result<Arc<T>, ()> {
        #[cfg(any(test, feature = "namespace_probe"))]
        if self.fault == Some(NamespaceCreateStage::ArcAllocation) {
            let failed = Arc::try_new_in(value, RejectAllocation);
            assert!(failed.is_err());
            self.observe_injection();
            return Err(());
        }
        Arc::try_new(value).map_err(|_| ())
    }
}

#[cfg(any(test, feature = "namespace_probe"))]
struct RejectAllocation;

#[cfg(any(test, feature = "namespace_probe"))]
unsafe impl core::alloc::Allocator for RejectAllocation {
    fn allocate(
        &self,
        _layout: core::alloc::Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        Err(core::alloc::AllocError)
    }

    unsafe fn deallocate(&self, _ptr: core::ptr::NonNull<u8>, _layout: core::alloc::Layout) {
        unreachable!()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use std::sync::Barrier;
    use std::thread;

    fn test_context(limit: u32) -> NamespaceCreateContext {
        NamespaceCreateContext::new(
            Box::leak(Box::new(AtomicU32::new(1))),
            Box::leak(Box::new(AtomicU64::new(1))),
            limit,
        )
    }

    pub(crate) fn check_constructor<T, Error: core::fmt::Debug + PartialEq>(
        create: impl Fn(&NamespaceCreateContext) -> Result<Arc<T>, Error>,
        no_memory: Error,
        max_count: Error,
        id_overflow: Error,
        stages: &[NamespaceCreateStage],
    ) {
        let context = test_context(3);
        let live = create(&context).expect("live sibling");
        assert_eq!(context.counter.load(Ordering::SeqCst), 2);
        for &stage in stages {
            let failing = NamespaceCreateContext {
                fault: Some(stage),
                ..context
            };
            for _attempt in 0..4 {
                assert_eq!(create(&failing).err().as_ref(), Some(&no_memory));
                assert_eq!(context.counter.load(Ordering::SeqCst), 2, "{stage:?}");
            }
        }
        let last_slot = create(&context).expect("last slot");
        assert_eq!(context.counter.load(Ordering::SeqCst), 3);
        assert_eq!(create(&context).err().as_ref(), Some(&max_count));
        assert_eq!(context.counter.load(Ordering::SeqCst), 3);
        let retained = Arc::clone(&last_slot);
        drop(last_slot);
        assert_eq!(context.counter.load(Ordering::SeqCst), 3);
        drop(retained);
        assert_eq!(context.counter.load(Ordering::SeqCst), 2);
        context.next_id.store(u64::MAX, Ordering::SeqCst);
        assert_eq!(create(&context).err().as_ref(), Some(&id_overflow));
        assert_eq!(context.counter.load(Ordering::SeqCst), 2);
        drop(live);
        assert_eq!(context.counter.load(Ordering::SeqCst), 1);
    }

    pub(crate) fn check_depth<T, Error: core::fmt::Debug + PartialEq>(
        root: Arc<T>,
        depth: u8,
        create: impl Fn(Arc<T>, &NamespaceCreateContext) -> Result<Arc<T>, Error>,
        max_depth: Error,
    ) {
        let context = test_context(u32::from(depth) + 2);
        let mut parent = Arc::clone(&root);
        for _level in 0..depth {
            parent = create(parent, &context).expect("child within depth limit");
        }
        assert_eq!(context.counter.load(Ordering::SeqCst), u32::from(depth) + 1);
        assert_eq!(
            create(Arc::clone(&parent), &context).err().as_ref(),
            Some(&max_depth)
        );
        assert_eq!(context.counter.load(Ordering::SeqCst), u32::from(depth) + 1);
        drop(parent);
        assert_eq!(context.counter.load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&root), 1);
    }

    pub(crate) fn check_concurrent<T: Send + Sync, Error: core::fmt::Debug>(
        create: impl Fn(&NamespaceCreateContext) -> Result<Arc<T>, Error> + Sync,
    ) {
        const WORKERS: usize = 16;
        const LIMIT: u32 = 4;
        let context = test_context(LIMIT);
        let barrier = Barrier::new(WORKERS + 1);
        let successes = AtomicU32::new(0);
        thread::scope(|scope| {
            for _worker in 0..WORKERS {
                scope.spawn(|| {
                    barrier.wait();
                    let child = create(&context);
                    if child.is_ok() {
                        successes
                            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                                count.checked_add(1)
                            })
                            .expect("bounded test success counter");
                    }
                    barrier.wait();
                    barrier.wait();
                    drop(child);
                });
            }
            barrier.wait();
            barrier.wait();
            let observed_count = context.counter.load(Ordering::SeqCst);
            let observed_successes = successes.load(Ordering::SeqCst);
            barrier.wait();
            assert_eq!(observed_count, LIMIT);
            assert_eq!(observed_successes, LIMIT - 1);
        });
        assert_eq!(context.counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ksa003_permit_rejects_full_counter_without_wrap() {
        let counter = Box::leak(Box::new(AtomicU32::new(u32::MAX)));
        assert!(NamespaceCountPermit::try_acquire(counter, u32::MAX).is_err());
        assert_eq!(counter.load(Ordering::SeqCst), u32::MAX);
    }
}
