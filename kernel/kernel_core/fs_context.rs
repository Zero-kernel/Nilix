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
