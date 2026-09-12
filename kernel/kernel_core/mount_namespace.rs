//! Mount Namespace Support
//!
//! Implements Linux-compatible mount namespaces for filesystem isolation.
//!
//! # Overview
//!
//! Mount namespaces provide isolated filesystem views. Each namespace has:
//! - Its own mount table (independent of parent after CLONE_NEWNS)
//! - A hierarchical relationship with parent namespaces (for depth limiting)
//! - Copy-on-write semantics: CLONE_NEWNS copies the entire mount table
//!
//! # Architecture
//!
//! The MountNamespace structure is defined here in kernel_core to avoid
//! circular dependencies. The actual mount table with FileSystem references
//! is managed by the VFS layer, which uses the namespace ID as a key.
//!
//! # Key Differences from PID Namespace
//!
//! Unlike PID namespaces:
//! - No cross-namespace visibility (parent cannot see child's mounts)
//! - No PID translation (paths are always resolved in current namespace)
//! - No init/cascade-kill semantics
//! - Full copy of mount table on CLONE_NEWNS (not shared references)

use alloc::sync::Arc;
use cap::NamespaceId;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use mm::{arc_charge_bytes, try_reserve_heap, AdmittedString, HeapCharge, HeapClass};
use spin::RwLock;

use crate::process::{FileDescriptor, FileOps};

#[path = "namespace_accounting.rs"]
pub(crate) mod namespace_accounting;
use namespace_accounting::{
    NamespaceCountPermit, NamespaceCreateContext, NamespaceCreateError, NamespaceCreateStage,
};

// ============================================================================
// Constants
// ============================================================================

/// Maximum mount namespace nesting depth (Linux default is 32)
pub const MAX_MNT_NS_LEVEL: u8 = 32;

/// R140-3 FIX: Maximum number of mount namespaces allowed system-wide.
/// Prevents DoS via unbounded flat fan-out namespace creation exhausting kernel
/// heap (each namespace eagerly materializes a VFS mount table clone). Matches
/// the limit used by PID/IPC/NET/USER namespaces.
pub const MAX_MNT_NS_COUNT: u32 = 1024;

/// R140-3 FIX: Current mount namespace count (root namespace starts at 1).
static MNT_NS_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

// ============================================================================
// Mount Flags
// ============================================================================

bitflags::bitflags! {
    /// Mount flags controlling filesystem behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct MountFlags: u64 {
        /// Mount read-only (MS_RDONLY)
        const RDONLY  = 1 << 0;
        /// Ignore setuid/setgid bits (MS_NOSUID)
        const NOSUID  = 1 << 1;
        /// Disallow access to device special files (MS_NODEV)
        const NODEV   = 1 << 2;
        /// Disallow program execution (MS_NOEXEC)
        const NOEXEC  = 1 << 3;
        /// Do not update access times (MS_NOATIME)
        const NOATIME = 1 << 4;
        /// Update atime only if mtime/ctime changed (MS_RELATIME)
        const RELATIME = 1 << 5;
        /// Perform a bind mount (MS_BIND)
        const BIND    = 1 << 12;
        /// Recursively apply to submounts (MS_REC)
        const REC     = 1 << 14;
        /// Make mount private (MS_PRIVATE)
        const PRIVATE = 1 << 18;
        /// Make mount shared (MS_SHARED)
        const SHARED  = 1 << 20;
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during mount namespace operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountNsError {
    /// Maximum namespace nesting depth exceeded
    MaxDepthExceeded,
    /// R140-3 FIX: Maximum system-wide namespace count exceeded
    MaxCountExceeded,
    /// Namespace is shutting down
    NamespaceShuttingDown,
    /// Mount point already exists at the specified path
    MountExists,
    /// Mount point not found at the specified path
    MountNotFound,
    /// Mount is busy (open files or submounts)
    MountBusy,
    /// Invalid mount path (must be absolute)
    InvalidPath,
    /// Operation requires elevated privileges
    PermissionDenied,
    /// Filesystem type not supported
    FsTypeNotSupported,
    /// Out of memory
    NoMemory,
}

// ============================================================================
// Mount Namespace
// ============================================================================

/// A mount namespace providing isolated filesystem views.
///
/// This structure contains only the namespace identity and hierarchy.
/// The actual mount table is managed by the VFS layer using the namespace ID.
///
/// # Lifecycle
///
/// Lifecycle management is handled by `Arc` reference counting.
/// No manual refcount is needed — `Arc::strong_count()` serves this role.
pub struct MountNamespace {
    /// Unique namespace identifier
    id: NamespaceId,

    /// Parent namespace (None for root)
    parent: Option<Arc<MountNamespace>>,

    /// Nesting level (0 = root)
    level: u8,

    /// Root mount path for this namespace (usually "/")
    root_path: RwLock<AdmittedString>,

    _count_permit: Option<NamespaceCountPermit>,

    /// Lifetime charge for this namespace's Arc allocation.
    _arc_heap_charge: Option<HeapCharge>,
}

impl MountNamespace {
    /// Create the root mount namespace.
    fn new_root() -> Self {
        Self {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            root_path: RwLock::new(
                AdmittedString::try_from_str(HeapClass::CoreProcess, "/")
                    .expect("root mount namespace path admission"),
            ),
            _count_permit: None,
            _arc_heap_charge: None,
        }
    }

    /// Create a new child namespace.
    pub fn new_child(parent: Arc<MountNamespace>) -> Result<Arc<Self>, MountNsError> {
        Self::new_child_with_context(
            parent,
            &NamespaceCreateContext::new(&MNT_NS_COUNT, &NEXT_MNT_NS_ID, MAX_MNT_NS_COUNT),
        )
    }

    fn new_child_with_context(
        parent: Arc<MountNamespace>,
        context: &NamespaceCreateContext,
    ) -> Result<Arc<Self>, MountNsError> {
        if parent.level >= MAX_MNT_NS_LEVEL {
            return Err(MountNsError::MaxDepthExceeded);
        }

        let (count_permit, id) = context.reserve_id().map_err(|error| match error {
            NamespaceCreateError::MaxCount => MountNsError::MaxCountExceeded,
            NamespaceCreateError::IdOverflow => MountNsError::NoMemory,
        })?;

        // RF180-16 FIX: clone the path through admitted storage and reserve
        // the namespace Arc before either allocation becomes public.
        context
            .check(NamespaceCreateStage::RootPath)
            .map_err(|_| MountNsError::NoMemory)?;
        let root_path = {
            let path = parent.root_path.read();
            AdmittedString::try_from_str(HeapClass::CoreProcess, path.as_str())
                .map_err(|_| MountNsError::NoMemory)?
        };
        context
            .check(NamespaceCreateStage::ArcLayout)
            .map_err(|_| MountNsError::NoMemory)?;
        let arc_bytes = arc_charge_bytes::<MountNamespace>().map_err(|_| MountNsError::NoMemory)?;
        context
            .check(NamespaceCreateStage::HeapReserve)
            .map_err(|_| MountNsError::NoMemory)?;
        let arc_reservation = try_reserve_heap(HeapClass::CoreProcess, arc_bytes)
            .map_err(|_| MountNsError::NoMemory)?;
        let mut child = context
            .try_arc(Self {
                id: NamespaceId::new(id),
                parent: Some(Arc::clone(&parent)),
                level: parent.level.saturating_add(1),
                root_path: RwLock::new(root_path),
                _count_permit: Some(count_permit),
                _arc_heap_charge: None,
            })
            .map_err(|_| MountNsError::NoMemory)?;
        context
            .check(NamespaceCreateStage::HeapCommit)
            .map_err(|_| MountNsError::NoMemory)?;
        let charge = arc_reservation
            .commit()
            .map_err(|_| MountNsError::NoMemory)?;
        Arc::get_mut(&mut child)
            .expect("fresh mount namespace Arc must be unique")
            ._arc_heap_charge = Some(charge);

        Ok(child)
    }

    #[cfg(feature = "namespace_probe")]
    pub(crate) fn probe_child(context: NamespaceCreateContext) -> Result<Arc<Self>, MountNsError> {
        Self::new_child_with_context(
            ROOT_MNT_NAMESPACE.clone(),
            &context.with_id_source(&NEXT_MNT_NS_ID),
        )
    }

    /// Get the namespace identifier.
    #[inline]
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Get the parent namespace.
    #[inline]
    pub fn parent(&self) -> Option<Arc<MountNamespace>> {
        self.parent.as_ref().map(Arc::clone)
    }

    /// Get the nesting level (0 = root).
    #[inline]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Check if this is the root namespace.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.level == 0
    }

    /// Get the namespace root path.
    #[inline]
    pub fn root_path(&self) -> Result<AdmittedString, MountNsError> {
        let path = self.root_path.read();
        AdmittedString::try_from_str(HeapClass::CoreProcess, path.as_str())
            .map_err(|_| MountNsError::NoMemory)
    }

    /// Set the namespace root path (for pivot_root/chroot).
    pub fn set_root_path(&self, path: &str) -> Result<(), MountNsError> {
        let replacement = AdmittedString::try_from_str(HeapClass::CoreProcess, path)
            .map_err(|_| MountNsError::NoMemory)?;
        let old = core::mem::replace(&mut *self.root_path.write(), replacement);
        drop(old);
        Ok(())
    }
}

impl core::fmt::Debug for MountNamespace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MountNamespace")
            .field("id", &self.id.raw())
            .field("level", &self.level)
            .finish()
    }
}

// ============================================================================
// Global State
// ============================================================================

lazy_static::lazy_static! {
    /// The root mount namespace (level 0, no parent).
    pub static ref ROOT_MNT_NAMESPACE: Arc<MountNamespace> = Arc::new(MountNamespace::new_root());

    /// Counter for generating unique namespace IDs.
    static ref NEXT_MNT_NS_ID: AtomicU64 = AtomicU64::new(1);
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Initialize and return the root mount namespace.
pub fn init() -> Arc<MountNamespace> {
    ROOT_MNT_NAMESPACE.clone()
}

/// Create a new child namespace (for CLONE_NEWNS).
pub fn clone_namespace(parent: Arc<MountNamespace>) -> Result<Arc<MountNamespace>, MountNsError> {
    MountNamespace::new_child(parent)
}

/// Print namespace information for debugging.
pub fn print_namespace_info(ns: &Arc<MountNamespace>) {
    kprintln!(
        "[MNT NS] id={}, level={}, arc_refs={}",
        ns.id().raw(),
        ns.level(),
        Arc::strong_count(ns)
    );
}

// ============================================================================
// Mount Namespace File Descriptor
// ============================================================================

/// File descriptor wrapper for a mount namespace (used by setns).
///
/// This allows a mount namespace to be referenced via a file descriptor,
/// enabling sys_setns to switch to a different mount namespace.
pub struct MountNamespaceFd {
    ns: Arc<MountNamespace>,
}

impl MountNamespaceFd {
    /// Create a new file descriptor wrapper for a mount namespace.
    pub fn new(ns: Arc<MountNamespace>) -> Self {
        Self { ns }
    }

    /// Get the underlying mount namespace.
    pub fn namespace(&self) -> Arc<MountNamespace> {
        self.ns.clone()
    }
}

impl FileOps for MountNamespaceFd {
    fn clone_box(&self) -> Result<FileDescriptor, ()> {
        self.try_clone_box()
    }

    fn try_clone_box(&self) -> Result<FileDescriptor, ()> {
        FileDescriptor::try_new(
            Self {
                ns: Arc::clone(&self.ns),
            },
            HeapClass::CoreProcess,
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    /// U.S2-SLICE-3B: Mount namespace fds are NOT cap-bearing (default None is correct).
    fn cap_id(&self) -> Option<cap::CapId> {
        None
    }

    /// U.S2-SLICE-3B: Mount namespace fds are NOT cap-bearing (no-op is correct).
    fn set_cap_id(&self, _id: cap::CapId) {
        // No-op: namespace fds don't carry capabilities
    }

    fn type_name(&self) -> &'static str {
        "mount_namespace_fd"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use namespace_accounting::tests::{check_concurrent, check_constructor, check_depth};

    #[test]
    fn ksa003_mount_constructor_failures_and_lifetime() {
        let root = Arc::new(MountNamespace::new_root());
        check_constructor(
            |context| MountNamespace::new_child_with_context(Arc::clone(&root), context),
            MountNsError::NoMemory,
            MountNsError::MaxCountExceeded,
            MountNsError::NoMemory,
            &[
                NamespaceCreateStage::RootPath,
                NamespaceCreateStage::ArcLayout,
                NamespaceCreateStage::HeapReserve,
                NamespaceCreateStage::ArcAllocation,
                NamespaceCreateStage::HeapCommit,
            ],
        );
        assert_eq!(Arc::strong_count(&root), 1);
        assert_eq!(root.root_path().unwrap().as_str(), "/");
    }

    #[test]
    fn ksa003_mount_depth_retains_and_releases_parents() {
        check_depth(
            Arc::new(MountNamespace::new_root()),
            MAX_MNT_NS_LEVEL,
            MountNamespace::new_child_with_context,
            MountNsError::MaxDepthExceeded,
        );
    }

    #[test]
    fn ksa003_mount_concurrent_limit() {
        let root = Arc::new(MountNamespace::new_root());
        check_concurrent(|context| {
            MountNamespace::new_child_with_context(Arc::clone(&root), context)
        });
        assert_eq!(Arc::strong_count(&root), 1);
    }
}
