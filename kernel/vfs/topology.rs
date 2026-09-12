//! Admitted ownership edges with bounded-stack, allocation-free retirement.
use alloc::boxed::Box;
use alloc::sync::Arc;
use mm::{allocation_charge_bytes, arc_charge_bytes, try_reserve_heap, HeapCharge, HeapClass};
use spin::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::context::OperationContext;
use crate::types::FsError;

static TOPOLOGY: RwLock<()> = RwLock::new(());

pub(crate) fn read() -> RwLockReadGuard<'static, ()> {
    TOPOLOGY.read()
}

pub(crate) struct WriteGuard {
    lock: Option<RwLockWriteGuard<'static, ()>>,
    deferred: Mutex<[Option<(usize, Arc<dyn DeferredDrain>)>; 8]>,
}

pub(crate) fn write() -> WriteGuard {
    WriteGuard {
        lock: Some(TOPOLOGY.write()),
        deferred: Mutex::new(core::array::from_fn(|_| None)),
    }
}

trait DeferredDrain: Send + Sync {
    fn hold(&self);
    fn release(&self);
}

/// Only a VFS write transaction can construct this token. Filesystem metadata
/// mutators use its prepared host IDs; none reread ambient credentials.
pub struct MutationContext<'a> {
    _guard: &'a WriteGuard,
    pub uid: u32,
    pub gid: u32,
}

impl WriteGuard {
    pub(crate) fn context<'a>(&'a self, authority: &OperationContext) -> MutationContext<'a> {
        MutationContext {
            _guard: self,
            uid: authority.uid,
            gid: authority.gid,
        }
    }

    /// Explicit construction for boot and isolated filesystem fixtures.
    pub(crate) fn setup(&self, uid: u32, gid: u32) -> MutationContext<'_> {
        MutationContext {
            _guard: self,
            uid,
            gid,
        }
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        drop(self.lock.take());
        for owner in self.deferred.get_mut().iter_mut() {
            if let Some((_, owner)) = owner.take() {
                owner.release();
            }
        }
    }
}

impl MutationContext<'_> {
    pub(crate) fn defer<T: ?Sized + Send + Sync + 'static>(
        &self,
        retirement: &Arc<Retirement<T>>,
    ) -> Result<(), FsError> {
        let key = Arc::as_ptr(retirement) as usize;
        let mut deferred = self._guard.deferred.lock();
        if deferred
            .iter()
            .flatten()
            .any(|(existing, _)| *existing == key)
        {
            return Ok(());
        }
        let slot = deferred
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(FsError::NoMem)?;
        retirement.hold();
        *slot = Some((key, retirement.clone()));
        Ok(())
    }
}

struct Link<T: ?Sized> {
    target: Option<Arc<T>>,
    next: Option<Box<Link<T>>>,
    charge: Option<HeapCharge>,
}

struct State<T: ?Sized> {
    head: Option<Box<Link<T>>>,
    draining: bool,
    holds: usize,
}

pub(crate) struct Retirement<T: ?Sized> {
    state: Mutex<State<T>>,
    class: HeapClass,
    _charge: HeapCharge,
}

impl<T: ?Sized> Retirement<T> {
    pub(crate) fn try_new(class: HeapClass) -> Result<Arc<Self>, FsError> {
        let bytes = arc_charge_bytes::<Self>().map_err(|_| FsError::NoMem)?;
        let reservation = try_reserve_heap(class, bytes).map_err(|_| FsError::NoMem)?;
        let charge = reservation.commit().map_err(|_| FsError::NoMem)?;
        Arc::try_new(Self {
            state: Mutex::new(State {
                head: None,
                draining: false,
                holds: 0,
            }),
            class,
            _charge: charge,
        })
        .map_err(|_| FsError::NoMem)
    }

    fn retire(&self, mut link: Box<Link<T>>) {
        {
            let mut state = self.state.lock();
            link.next = state.head.take();
            state.head = Some(link);
            if state.draining || state.holds != 0 {
                return;
            }
            state.draining = true;
        }
        self.drain();
    }

    fn drain(&self) {
        // This strong borrow keeps the coordinator alive through every nested
        // node Drop. A nested retirement only enqueues into this drainer.
        loop {
            let mut link = {
                let mut state = self.state.lock();
                if state.holds != 0 {
                    state.draining = false;
                    break;
                }
                match state.head.take() {
                    Some(mut link) => {
                        state.head = link.next.take();
                        link
                    }
                    None => {
                        state.draining = false;
                        break;
                    }
                }
            };
            // Moving fields out of *Box does not free its backing allocation
            // until the Box scope ends. Empty it, then explicitly deallocate
            // before making either the target or its charge available to Drop.
            let target = link.target.take();
            let charge = link
                .charge
                .take()
                .expect("retired VFS edge lost its charge");
            debug_assert!(link.next.is_none());
            drop(link);
            drop(target);
            drop(charge);
        }
    }
}

impl<T: ?Sized + Send + Sync + 'static> DeferredDrain for Retirement<T> {
    fn hold(&self) {
        let mut state = self.state.lock();
        state.holds = state
            .holds
            .checked_add(1)
            .expect("VFS retirement hold overflow");
    }

    fn release(&self) {
        {
            let mut state = self.state.lock();
            state.holds = state
                .holds
                .checked_sub(1)
                .expect("VFS retirement hold underflow");
            if state.holds != 0 || state.draining || state.head.is_none() {
                return;
            }
            state.draining = true;
        }
        self.drain();
    }
}

/// Every strong topology edge owns the worklist allocation needed by its final
/// drop. No Vec growth, recursive Arc-chain drain, or strong-count guess occurs.
pub(crate) struct Edge<T: ?Sized> {
    link: Option<Box<Link<T>>>,
    retirement: Arc<Retirement<T>>,
}

impl<T: ?Sized> Edge<T> {
    pub(crate) fn try_new(
        target: Arc<T>,
        retirement: &Arc<Retirement<T>>,
    ) -> Result<Self, FsError> {
        let bytes = allocation_charge_bytes(
            core::mem::size_of::<Link<T>>(),
            core::mem::align_of::<Link<T>>(),
        )
        .map_err(|_| FsError::NoMem)?;
        let reservation = try_reserve_heap(retirement.class, bytes).map_err(|_| FsError::NoMem)?;
        let charge = reservation.commit().map_err(|_| FsError::NoMem)?;
        let link = Box::try_new(Link {
            target: Some(target),
            next: None,
            charge: Some(charge),
        })
        .map_err(|_| FsError::NoMem)?;
        Ok(Self {
            link: Some(link),
            retirement: retirement.clone(),
        })
    }

    pub(crate) fn target(&self) -> &Arc<T> {
        self.link.as_ref().unwrap().target.as_ref().unwrap()
    }

    /// A detached directory reuses its former downward edge as an upward edge.
    /// Caller pins the old target independently until after topology unlock.
    pub(crate) fn replace_target(&mut self, target: Arc<T>) -> Arc<T> {
        self.link.as_mut().unwrap().target.replace(target).unwrap()
    }
}

impl<T: ?Sized> Drop for Edge<T> {
    fn drop(&mut self) {
        if let Some(link) = self.link.take() {
            self.retirement.retire(link);
        }
    }
}

impl<T: ?Sized> core::ops::Deref for Edge<T> {
    type Target = Arc<T>;
    fn deref(&self) -> &Self::Target {
        self.target()
    }
}

#[cfg(all(test, feature = "host_harness"))]
mod tests {
    use super::*;
    use crate::allocation_probe::{CHARGED_AT_FREE, FREED, TRACKED};
    use core::sync::atomic::Ordering;

    struct Target;
    impl Drop for Target {
        fn drop(&mut self) {
            assert_eq!(
                FREED.load(Ordering::Acquire),
                1,
                "actual edge allocation must be freed before target destruction"
            );
        }
    }

    #[test]
    fn edge_box_is_deallocated_before_target_and_admission_release() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        mm::publish_heap_budgets();
        let baseline = mm::heap_class_snapshot(HeapClass::Vfs);
        let retirement = Retirement::try_new(HeapClass::Vfs).unwrap();
        let edge = Edge::try_new(Arc::new(Target), &retirement).unwrap();
        let live = mm::heap_class_snapshot(HeapClass::Vfs);
        FREED.store(0, Ordering::Release);
        CHARGED_AT_FREE.store(0, Ordering::Release);
        TRACKED.store(
            edge.link.as_deref().unwrap() as *const Link<Target> as usize,
            Ordering::Release,
        );
        drop(edge);
        TRACKED.store(0, Ordering::Release);
        assert_eq!(
            CHARGED_AT_FREE.load(Ordering::Acquire),
            live.committed_bytes,
            "edge credit must still be reserved when the actual allocator frees its storage"
        );
        drop(retirement);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Vfs), baseline);
    }
}
