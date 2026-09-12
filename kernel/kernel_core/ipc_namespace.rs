//! IPC Namespace Implementation for Zero-OS
//!
//! Provides isolated System V IPC resources (message queues, semaphores, shared memory)
//! for containerization support. Each IPC namespace maintains its own set of IPC
//! identifiers, preventing processes in different namespaces from accessing each
//! other's IPC resources.
//!
//! # Design
//!
//! Follows the same hierarchical model as PID and Mount namespaces:
//! - Root namespace at level 0 (shared by default)
//! - Child namespaces created via CLONE_NEWIPC or unshare(CLONE_NEWIPC)
//! - Maximum nesting depth of 32 levels
//!
//! # Security
//!
//! - All IPC namespace operations require CAP_SYS_ADMIN or root (euid == 0)
//! - Namespace switching (setns) requires single-threaded process
//! - IPC resources are isolated: processes can only access IPC in their namespace
//!
//! # Usage
//!
//! ```rust,ignore
//! // Create child namespace
//! let child_ns = clone_ipc_namespace(parent_ns)?;
//!
//! // Check if endpoint is visible in namespace
//! let visible = is_endpoint_visible(endpoint_id, &ns);
//! ```

extern crate alloc;

use crate::mount_namespace::namespace_accounting::{
    NamespaceCountPermit, NamespaceCreateContext, NamespaceCreateError, NamespaceCreateStage,
};
use alloc::string::String;
use alloc::sync::Arc;
use cap::NamespaceId;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use mm::{arc_charge_bytes, try_reserve_heap, HeapCharge, HeapClass};
use spin::RwLock;

// ============================================================================
// Constants
// ============================================================================

/// Maximum IPC namespace nesting depth (same as PID/Mount namespaces)
pub const MAX_IPC_NS_LEVEL: u8 = 32;

/// CLONE_NEWIPC flag for clone/unshare
pub const CLONE_NEWIPC: u64 = 0x0800_0000;

/// R76-2 FIX: Maximum number of IPC namespaces allowed system-wide.
/// Prevents DoS via namespace exhaustion.
pub const MAX_IPC_NS_COUNT: u32 = 1024;

/// R76-2 FIX: Current IPC namespace count (root starts at 1).
static IPC_NS_COUNT: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// Error Types
// ============================================================================

/// IPC namespace operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcNsError {
    /// Maximum namespace depth exceeded
    MaxDepthExceeded,
    /// R76-2 FIX: Maximum system-wide namespace count exceeded
    MaxNamespaces,
    /// Namespace not found
    NotFound,
    /// Permission denied
    PermissionDenied,
    /// Invalid namespace state
    InvalidState,
    /// R112-2 FIX: Namespace ID counter overflow (u64 exhausted)
    NamespaceIdOverflow,
    /// R112-2 FIX: IPC key counter overflow (u64 exhausted)
    KeyOverflow,
    /// Namespace object admission/allocation failed.
    OutOfMemory,
}

// ============================================================================
// Global State
// ============================================================================

lazy_static::lazy_static! {
    /// Root IPC namespace - shared by all processes by default
    pub static ref ROOT_IPC_NAMESPACE: Arc<IpcNamespace> = Arc::new(IpcNamespace::new_root());
}

/// Next available namespace ID (starts at 1, 0 is reserved for root)
static NEXT_IPC_NS_ID: AtomicU64 = AtomicU64::new(1);

// ============================================================================
// IPC Namespace
// ============================================================================

/// An IPC namespace providing isolated IPC resources.
///
/// Each namespace has its own set of:
/// - Message queue identifiers
/// - Semaphore identifiers
/// - Shared memory identifiers
///
/// IPC resources created in one namespace are invisible to processes in other
/// namespaces, even if they use the same numeric identifier.
pub struct IpcNamespace {
    /// Unique namespace identifier
    id: NamespaceId,

    /// Parent namespace (None for root)
    parent: Option<Arc<IpcNamespace>>,

    /// Nesting level (0 = root)
    level: u8,

    /// Reference count of processes using this namespace
    refcount: AtomicU32,

    /// Next available IPC key within this namespace
    next_key: AtomicU64,

    _count_permit: Option<NamespaceCountPermit>,

    /// Exact heap charge for the namespace Arc allocation.
    _arc_heap_charge: Option<HeapCharge>,
}

impl fmt::Debug for IpcNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcNamespace")
            .field("id", &self.id.raw())
            .field("level", &self.level)
            .field("refcount", &self.refcount.load(Ordering::Relaxed))
            .finish()
    }
}

impl IpcNamespace {
    /// Create the root IPC namespace.
    fn new_root() -> Self {
        Self {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            refcount: AtomicU32::new(1),
            next_key: AtomicU64::new(1),
            _count_permit: None,
            _arc_heap_charge: None,
        }
    }

    /// Create a new child namespace.
    ///
    /// The payload owns its count permit before fallible Arc allocation.
    pub fn new_child(parent: Arc<IpcNamespace>) -> Result<Arc<Self>, IpcNsError> {
        Self::new_child_with_context(
            parent,
            &NamespaceCreateContext::new(&IPC_NS_COUNT, &NEXT_IPC_NS_ID, MAX_IPC_NS_COUNT),
        )
    }

    fn new_child_with_context(
        parent: Arc<IpcNamespace>,
        context: &NamespaceCreateContext,
    ) -> Result<Arc<Self>, IpcNsError> {
        if parent.level >= MAX_IPC_NS_LEVEL {
            return Err(IpcNsError::MaxDepthExceeded);
        }

        let (count_permit, id) = context.reserve_id().map_err(|error| match error {
            NamespaceCreateError::MaxCount => IpcNsError::MaxNamespaces,
            NamespaceCreateError::IdOverflow => IpcNsError::NamespaceIdOverflow,
        })?;

        context
            .check(NamespaceCreateStage::ArcLayout)
            .map_err(|_| IpcNsError::OutOfMemory)?;
        let arc_bytes = arc_charge_bytes::<IpcNamespace>().map_err(|_| IpcNsError::OutOfMemory)?;
        context
            .check(NamespaceCreateStage::HeapReserve)
            .map_err(|_| IpcNsError::OutOfMemory)?;
        let arc_reservation = try_reserve_heap(HeapClass::CoreProcess, arc_bytes)
            .map_err(|_| IpcNsError::OutOfMemory)?;
        let mut child = context
            .try_arc(Self {
                id: NamespaceId::new(id),
                parent: Some(parent.clone()),
                level: parent.level.saturating_add(1),
                refcount: AtomicU32::new(1),
                next_key: AtomicU64::new(1),
                _count_permit: Some(count_permit),
                _arc_heap_charge: None,
            })
            .map_err(|_| IpcNsError::OutOfMemory)?;

        context
            .check(NamespaceCreateStage::HeapCommit)
            .map_err(|_| IpcNsError::OutOfMemory)?;
        let charge = arc_reservation
            .commit()
            .map_err(|_| IpcNsError::OutOfMemory)?;
        Arc::get_mut(&mut child)
            .expect("fresh IPC namespace Arc must be unique")
            ._arc_heap_charge = Some(charge);

        Ok(child)
    }

    #[cfg(feature = "namespace_probe")]
    pub(crate) fn probe_child(context: NamespaceCreateContext) -> Result<Arc<Self>, IpcNsError> {
        Self::new_child_with_context(
            ROOT_IPC_NAMESPACE.clone(),
            &context.with_id_source(&NEXT_IPC_NS_ID),
        )
    }

    /// Get the namespace identifier.
    #[inline]
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Get the parent namespace.
    #[inline]
    pub fn parent(&self) -> Option<Arc<IpcNamespace>> {
        self.parent.clone()
    }

    /// Get the nesting level.
    #[inline]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Check if this is the root namespace.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Get current reference count.
    #[inline]
    pub fn ref_count(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Increment reference count (R112-2: overflow-safe).
    #[inline]
    pub fn inc_ref(&self) {
        self.refcount
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .expect("IpcNamespace refcount overflow");
    }

    /// Decrement reference count.
    #[inline]
    pub fn dec_ref(&self) {
        self.refcount.fetch_sub(1, Ordering::AcqRel);
    }

    /// Allocate a new IPC key within this namespace.
    ///
    /// Returns `Err(KeyOverflow)` if the key counter is exhausted (u64::MAX).
    pub fn alloc_key(&self) -> Result<u64, IpcNsError> {
        self.next_key
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| IpcNsError::KeyOverflow)
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize the IPC namespace subsystem.
///
/// Called during kernel initialization to set up the root namespace.
pub fn init() -> Arc<IpcNamespace> {
    ROOT_IPC_NAMESPACE.clone()
}

/// Create a new child IPC namespace (for CLONE_NEWIPC).
///
/// # Arguments
///
/// * `parent` - Parent namespace to clone from
///
/// # Returns
///
/// New child namespace with isolated IPC resources
///
/// # Errors
///
/// * `MaxDepthExceeded` - Maximum nesting depth reached
pub fn clone_ipc_namespace(parent: Arc<IpcNamespace>) -> Result<Arc<IpcNamespace>, IpcNsError> {
    IpcNamespace::new_child(parent)
}

/// Print namespace information for debugging.
pub fn print_ipc_namespace_info(ns: &Arc<IpcNamespace>) {
    kprintln!(
        "[IPC NS] id={}, level={}, refcount={}",
        ns.id().raw(),
        ns.level(),
        ns.ref_count()
    );
}

/// Get the root IPC namespace.
#[inline]
pub fn root_ipc_namespace() -> Arc<IpcNamespace> {
    ROOT_IPC_NAMESPACE.clone()
}

// ============================================================================
// IPC Namespace File Descriptor (for sys_setns)
// ============================================================================

use crate::{FileDescriptor, FileOps, SyscallError};

/// File descriptor wrapper for IPC namespace (used by sys_setns).
///
/// When a process opens /proc/[pid]/ns/ipc, it gets this file descriptor
/// that references the target process's IPC namespace.
pub struct IpcNamespaceFd {
    ns: Arc<IpcNamespace>,
}

impl IpcNamespaceFd {
    /// Create a new IPC namespace file descriptor.
    pub fn new(ns: Arc<IpcNamespace>) -> Self {
        ns.inc_ref();
        Self { ns }
    }

    /// Get the underlying namespace.
    pub fn namespace(&self) -> Arc<IpcNamespace> {
        self.ns.clone()
    }
}

impl Drop for IpcNamespaceFd {
    fn drop(&mut self) {
        self.ns.dec_ref();
    }
}

impl FileOps for IpcNamespaceFd {
    fn clone_box(&self) -> Result<FileDescriptor, ()> {
        self.try_clone_box()
    }

    fn try_clone_box(&self) -> Result<FileDescriptor, ()> {
        // Allocate/admit first. The manual namespace ownership change then
        // cannot be stranded by an outer descriptor allocation failure.
        let prepared = FileDescriptor::try_prepare(HeapClass::CoreProcess)?;
        self.ns.inc_ref();
        Ok(prepared.finalize(Self {
            ns: Arc::clone(&self.ns),
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    /// U.S2-SLICE-3B: IPC namespace fds are NOT cap-bearing (default None is correct).
    fn cap_id(&self) -> Option<cap::CapId> {
        None
    }

    /// U.S2-SLICE-3B: IPC namespace fds are NOT cap-bearing (no-op is correct).
    fn set_cap_id(&self, _id: cap::CapId) {
        // No-op: namespace fds don't carry capabilities
    }

    fn type_name(&self) -> &'static str {
        "ipc_namespace_fd"
    }

    fn stat(&self) -> Result<crate::VfsStat, SyscallError> {
        // Return minimal stat info for namespace fd
        Ok(crate::VfsStat {
            dev: 0,
            ino: self.ns.id().raw(),
            nlink: 1,
            mode: 0o444, // read-only
            uid: 0,
            gid: 0,
            pad0: 0,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
            unused0: 0,
            unused1: 0,
            unused2: 0,
        })
    }
}

// ============================================================================
// Test Support
// ============================================================================

/// Test helper: Check if IPC namespace callback is registered.
///
/// Used by runtime tests to verify IPC namespace subsystem initialization.
pub fn test_is_ipc_ns_initialized() -> bool {
    // The root namespace exists if the lazy_static was initialized
    ROOT_IPC_NAMESPACE.id().raw() == 0 && ROOT_IPC_NAMESPACE.is_root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount_namespace::namespace_accounting::tests::{
        check_concurrent, check_constructor, check_depth,
    };

    #[test]
    fn ksa003_ipc_constructor_failures_and_lifetime() {
        let root = Arc::new(IpcNamespace::new_root());
        check_constructor(
            |context| IpcNamespace::new_child_with_context(Arc::clone(&root), context),
            IpcNsError::OutOfMemory,
            IpcNsError::MaxNamespaces,
            IpcNsError::NamespaceIdOverflow,
            &[
                NamespaceCreateStage::ArcLayout,
                NamespaceCreateStage::HeapReserve,
                NamespaceCreateStage::ArcAllocation,
                NamespaceCreateStage::HeapCommit,
            ],
        );
        assert_eq!(Arc::strong_count(&root), 1);
    }

    #[test]
    fn ksa003_ipc_depth_retains_and_releases_parents() {
        check_depth(
            Arc::new(IpcNamespace::new_root()),
            MAX_IPC_NS_LEVEL,
            IpcNamespace::new_child_with_context,
            IpcNsError::MaxDepthExceeded,
        );
    }

    #[test]
    fn ksa003_ipc_concurrent_limit() {
        let root = Arc::new(IpcNamespace::new_root());
        check_concurrent(|context| {
            IpcNamespace::new_child_with_context(Arc::clone(&root), context)
        });
        assert_eq!(Arc::strong_count(&root), 1);
    }

    #[test]
    fn test_root_namespace() {
        let root = ROOT_IPC_NAMESPACE.clone();
        assert!(root.is_root());
        assert_eq!(root.level(), 0);
        assert_eq!(root.id().raw(), 0);
    }

    #[test]
    fn test_child_namespace() {
        let root = ROOT_IPC_NAMESPACE.clone();
        let child = clone_ipc_namespace(root.clone()).unwrap();

        assert!(!child.is_root());
        assert_eq!(child.level(), 1);
        assert!(child.parent().is_some());
        assert_eq!(child.parent().unwrap().id(), root.id());
    }

    #[test]
    fn test_max_depth() {
        let mut current = ROOT_IPC_NAMESPACE.clone();

        // Create namespaces up to max depth
        for level in 1..=MAX_IPC_NS_LEVEL {
            match clone_ipc_namespace(current.clone()) {
                Ok(child) => {
                    assert_eq!(child.level(), level);
                    current = child;
                }
                Err(IpcNsError::MaxDepthExceeded) => {
                    assert_eq!(level, MAX_IPC_NS_LEVEL + 1);
                    break;
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }
    }
}
