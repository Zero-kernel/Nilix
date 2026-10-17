//! Process-owned filesystem bindings without a dependency on the VFS crate.
use alloc::sync::Arc;
use alloc::{boxed::Box, string::String};
use core::any::Any;

/// An owned directory identity. The VFS implementation pins the inode and its
/// mount/filesystem. It never contains a borrowed path or a raw PCB pointer.
pub trait FsDirectoryHandle: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
}

#[derive(Clone)]
pub struct FsContextState {
    pub root: Option<Arc<dyn FsDirectoryHandle>>,
    pub cwd: Option<Arc<dyn FsDirectoryHandle>>,
    pub generation: u64,
}

static INITIAL_DIRECTORY: spin::Once<Arc<dyn FsDirectoryHandle>> = spin::Once::new();

pub struct FsCallbacks {
    pub access: fn(&str, i32) -> Result<(), crate::SyscallError>,
    pub getcwd: fn() -> Result<String, crate::SyscallError>,
    pub change_directory: fn(&str, bool) -> Result<(), crate::SyscallError>,
    pub pivot_root: fn(&str, &str) -> Result<(), crate::SyscallError>,
    /// The returned owner keeps topology stable through namespace publication.
    pub namespace_bindings: fn(
        &Arc<crate::MountNamespace>,
        &Arc<crate::MountNamespace>,
        &FsContextState,
    ) -> Result<NamespaceBindings, crate::SyscallError>,
}

/// Prepared source-normalized filesystem state and a topology publication span.
pub struct NamespaceBindings {
    pub state: FsContextState,
    pub permit: Box<dyn Any>,
}

static CALLBACKS: spin::Once<FsCallbacks> = spin::Once::new();

pub fn register_callbacks(callbacks: FsCallbacks) {
    CALLBACKS.call_once(|| callbacks);
}

pub fn callbacks() -> Result<&'static FsCallbacks, crate::SyscallError> {
    CALLBACKS.get().ok_or(crate::SyscallError::ENOSYS)
}

/// Boot installs the initial directory after the root mount exists. Earlier
/// kernel PCBs remain explicitly unbound; absence is never implicit authority.
pub fn install_initial_directory(directory: Arc<dyn FsDirectoryHandle>) {
    assert!(
        INITIAL_DIRECTORY.get().is_none(),
        "initial filesystem root replaced"
    );
    INITIAL_DIRECTORY.call_once(|| directory);
}

impl Default for FsContextState {
    fn default() -> Self {
        let root = INITIAL_DIRECTORY.get().cloned();
        Self {
            cwd: root.clone(),
            root,
            generation: 0,
        }
    }
}

impl FsContextState {
    /// Compare the exact snapshot used to authorize a root/cwd publication.
    pub fn matches(&self, previous: &Self) -> bool {
        fn same(
            left: &Option<Arc<dyn FsDirectoryHandle>>,
            right: &Option<Arc<dyn FsDirectoryHandle>>,
        ) -> bool {
            match (left, right) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
        }
        self.generation == previous.generation
            && same(&self.root, &previous.root)
            && same(&self.cwd, &previous.cwd)
    }
}

impl core::fmt::Debug for FsContextState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FsContextState")
            .field("root_bound", &self.root.is_some())
            .field("cwd_bound", &self.cwd.is_some())
            .field("generation", &self.generation)
            .finish()
    }
}

struct FsShared {
    state: FsContextState,
    umask: u16,
}

/// GAP-5 slice 2: the root/cwd/umask bundle as an explicit handle. Shared by
/// `Arc` under CLONE_FS, deep-copied otherwise. Lock order PCB -> handle
/// (leaf); nothing is acquired while the handle is held and no IRQ path
/// touches it. Displaced directory handles are returned to the caller so their
/// final drop never runs under the handle lock.
pub struct FsContextHandle {
    inner: spin::Mutex<FsShared>,
}

impl FsContextHandle {
    pub fn new(state: FsContextState, umask: u16) -> Self {
        Self {
            inner: spin::Mutex::new(FsShared { state, umask }),
        }
    }

    /// Coherent root/cwd/umask snapshot for one operation.
    pub fn snapshot(&self) -> (FsContextState, u16) {
        let shared = self.inner.lock();
        (shared.state.clone(), shared.umask)
    }

    pub fn state(&self) -> FsContextState {
        self.inner.lock().state.clone()
    }

    pub fn umask(&self) -> u16 {
        self.inner.lock().umask
    }

    /// Install `umask`, returning the previous value.
    pub fn set_umask(&self, umask: u16) -> u16 {
        core::mem::replace(&mut self.inner.lock().umask, umask)
    }

    pub fn matches(&self, previous: &FsContextState) -> bool {
        self.inner.lock().state.matches(previous)
    }

    /// Publish `replacement` only if the bindings still equal `expected`. The
    /// check and the store share one critical section, so a sharer's chdir
    /// cannot slip between them. Returns the displaced state, or hands the
    /// rejected replacement back.
    pub fn replace_if_matches(
        &self,
        expected: &FsContextState,
        replacement: FsContextState,
    ) -> Result<FsContextState, FsContextState> {
        let mut shared = self.inner.lock();
        if !shared.state.matches(expected) {
            return Err(replacement);
        }
        Ok(core::mem::replace(&mut shared.state, replacement))
    }

    /// Unconditional publication (boot and hosted fixtures).
    pub fn replace(&self, replacement: FsContextState) -> FsContextState {
        core::mem::replace(&mut self.inner.lock().state, replacement)
    }

    /// Copy another handle's bindings into this private handle (fork, and a
    /// clone without CLONE_FS). Source and destination are never held together.
    pub fn copy_from(&self, source: &FsContextHandle) {
        if core::ptr::eq(self, source) {
            return;
        }
        let (state, umask) = source.snapshot();
        let displaced = {
            let mut shared = self.inner.lock();
            shared.umask = umask;
            core::mem::replace(&mut shared.state, state)
        };
        drop(displaced);
    }
}

impl core::fmt::Debug for FsContextHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FsContextHandle").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod handle_tests {
    use super::*;

    struct Dir;
    impl FsDirectoryHandle for Dir {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    fn bound(generation: u64) -> FsContextState {
        let dir: Arc<dyn FsDirectoryHandle> = Arc::new(Dir);
        FsContextState {
            root: Some(dir.clone()),
            cwd: Some(dir),
            generation,
        }
    }

    #[test]
    fn shared_handle_publishes_to_every_sharer() {
        let handle = Arc::new(FsContextHandle::new(bound(0), 0o022));
        let sibling = Arc::clone(&handle);
        let before = handle.state();
        let next = bound(1);
        assert!(handle.replace_if_matches(&before, next.clone()).is_ok());
        assert!(sibling.matches(&next));
        assert_eq!(sibling.set_umask(0o077), 0o022);
        assert_eq!(handle.umask(), 0o077);
    }

    #[test]
    fn stale_snapshot_is_rejected_without_mutation() {
        let handle = FsContextHandle::new(bound(0), 0o022);
        let stale = handle.state();
        let current = bound(1);
        assert!(handle.replace_if_matches(&stale, current.clone()).is_ok());
        let rejected = handle.replace_if_matches(&stale, bound(2));
        assert!(matches!(rejected, Err(ref state) if state.generation == 2));
        assert!(handle.matches(&current));
    }

    #[test]
    fn copy_is_private_to_the_destination() {
        let parent = FsContextHandle::new(bound(3), 0o027);
        let child = FsContextHandle::new(FsContextState::default(), 0o022);
        child.copy_from(&parent);
        child.copy_from(&child);
        assert!(child.matches(&parent.state()));
        assert_eq!(child.umask(), 0o027);
        let next = bound(4);
        assert!(child.replace_if_matches(&child.state(), next).is_ok());
        assert_eq!(child.set_umask(0o002), 0o027);
        assert_eq!(parent.state().generation, 3);
        assert_eq!(parent.umask(), 0o027);
    }
}
