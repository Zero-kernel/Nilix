//! User Namespace Implementation for Zero-OS
//!
//! Provides Linux-compatible user namespaces (CLONE_NEWUSER) with UID/GID
//! mapping support. User namespaces virtualize user/group identities so that
//! processes can appear as root (uid/gid 0) inside the namespace while still
//! retaining their host credentials for security isolation.
//!
//! # Design
//!
//! Follows the same hierarchical model as other namespaces (PID, Mount, IPC, Net):
//! - Root namespace at level 0 (shared by default, identity mapping)
//! - Child namespaces created via CLONE_NEWUSER or unshare(CLONE_NEWUSER)
//! - Maximum nesting depth of 32 levels (MAX_USER_NS_LEVEL)
//!
//! # UID/GID Mapping
//!
//! Each user namespace maintains separate UID and GID mapping tables:
//! - Up to MAX_MAPPINGS (5) mapping extents per table
//! - Single-write semantics (mirrors Linux /proc/[pid]/uid_map behavior)
//! - Mappings translate between host IDs and namespace-local IDs
//!
//! ```text
//! Host System:        User Namespace:
//! uid=1000 --------> uid=0 (root in namespace)
//! gid=1000 --------> gid=0 (root in namespace)
//! ```
//!
//! # Security
//!
//! Unlike other namespace types, CLONE_NEWUSER does NOT require CAP_SYS_ADMIN
//! or root privileges. This is by design - user namespaces enable unprivileged
//! container creation. However:
//!
//! - Namespace depth is limited to prevent resource exhaustion
//! - Total namespace count is limited (MAX_USER_NS_COUNT)
//! - Mapping must be valid (no overlaps, no overflow, non-zero count)
//! - Mappings can only be written once (single-write semantics)
//!
//! # References
//!
//! - Linux user_namespaces(7) man page
//! - Phase F.1 in roadmap.md

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use cap::NamespaceId;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use mm::{arc_charge_bytes, try_reserve_heap, HeapCharge, HeapClass};
use spin::{Lazy, RwLock};

use crate::{FileDescriptor, FileOps, SyscallError, VfsStat};

// ============================================================================
// Constants
// ============================================================================

/// Maximum nesting depth for user namespaces.
///
/// This matches the Linux default of 32 levels. Prevents stack overflow
/// during recursive operations and limits resource consumption.
pub const MAX_USER_NS_LEVEL: u8 = 32;

/// Maximum UID/GID mapping extents per namespace.
///
/// Linux uses 5 mapping lines per uid_map/gid_map file.
/// This is sufficient for most container use cases:
/// - Map single user to root (1 extent)
/// - Map user range + nobody (2-3 extents)
/// - Complex multi-tenant scenarios (up to 5 extents)
pub const MAX_MAPPINGS: usize = 5;

/// Maximum bytes accepted by the procfs uid_map/gid_map writers.  The map
/// itself is capped at five extents; this bound also prevents a malformed
/// writer from retaining an arbitrarily large staging buffer in the VFS.
pub const MAX_MAPPING_TEXT_BYTES: usize = 4096;

/// Maximum number of user namespaces system-wide.
///
/// Prevents DoS via unbounded namespace creation.
pub const MAX_USER_NS_COUNT: u32 = 1024;

/// CLONE_NEWUSER flag value (Linux x86_64 ABI).
///
/// This flag is used with clone(2) or unshare(2) to create a new user namespace.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;

// ============================================================================
// Global State
// ============================================================================

/// Root user namespace (level 0, identity mapping).
///
/// All processes start in this namespace unless CLONE_NEWUSER is used.
/// The root namespace provides identity mapping: uid/gid values are unchanged.
pub static ROOT_USER_NAMESPACE: Lazy<Arc<UserNamespace>> =
    Lazy::new(|| Arc::new(UserNamespace::new_root()));

/// Next available namespace ID (0 reserved for root).
static NEXT_USER_NS_ID: AtomicU64 = AtomicU64::new(1);

/// Current user namespace count (root counts as 1).
static USER_NS_COUNT: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// Types
// ============================================================================

/// UID/GID mapping extent.
///
/// Represents a contiguous range of IDs mapped between namespace and host.
///
/// # Example
///
/// A mapping of `{ ns_id: 0, host_id: 1000, count: 1 }` means:
/// - namespace UID 0 maps to host UID 1000
/// - Only one ID is covered by this extent
///
/// For a range: `{ ns_id: 1000, host_id: 100000, count: 65536 }` means:
/// - namespace UIDs 1000-66535 map to host UIDs 100000-165535
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UidGidMapping {
    /// UID/GID inside the namespace (start of range).
    pub ns_id: u32,
    /// Corresponding host UID/GID (start of range).
    pub host_id: u32,
    /// Number of contiguous IDs covered by this extent.
    pub count: u32,
}

/// Parse the Linux uid_map/gid_map text representation.
///
/// Parsing is kept in the kernel-core namespace module so every future writer
/// (procfs or a dedicated syscall) gets the same strict grammar and bounds.
pub fn parse_mapping_text(data: &[u8]) -> Result<Vec<UidGidMapping>, UserNsError> {
    if data.is_empty() || data.len() > MAX_MAPPING_TEXT_BYTES {
        return Err(UserNsError::InvalidMapping);
    }
    let text = core::str::from_utf8(data).map_err(|_| UserNsError::InvalidMapping)?;
    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(MAX_MAPPINGS)
        .map_err(|_| UserNsError::OutOfMemory)?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            return Err(UserNsError::InvalidMapping);
        }
        let mut fields = line.split_ascii_whitespace();
        let ns_id = fields
            .next()
            .ok_or(UserNsError::InvalidMapping)?
            .parse::<u32>()
            .map_err(|_| UserNsError::InvalidMapping)?;
        let host_id = fields
            .next()
            .ok_or(UserNsError::InvalidMapping)?
            .parse::<u32>()
            .map_err(|_| UserNsError::InvalidMapping)?;
        let count = fields
            .next()
            .ok_or(UserNsError::InvalidMapping)?
            .parse::<u32>()
            .map_err(|_| UserNsError::InvalidMapping)?;
        if fields.next().is_some()
            || mappings.len() >= MAX_MAPPINGS
            || count == 0
            || ns_id.checked_add(count - 1).is_none()
            || host_id.checked_add(count - 1).is_none()
        {
            return Err(if mappings.len() >= MAX_MAPPINGS {
                UserNsError::TooManyMappings
            } else {
                UserNsError::InvalidMapping
            });
        }
        mappings.push(UidGidMapping {
            ns_id,
            host_id,
            count,
        });
    }
    if mappings.is_empty() {
        return Err(UserNsError::InvalidMapping);
    }
    Ok(mappings)
}

/// User namespace operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserNsError {
    /// Maximum namespace depth exceeded (MAX_USER_NS_LEVEL).
    MaxDepthExceeded,
    /// Maximum system-wide namespace count exceeded (MAX_USER_NS_COUNT).
    MaxNamespaces,
    /// Too many mapping extents (exceeds MAX_MAPPINGS).
    TooManyMappings,
    /// Invalid mapping (overlap, overflow, or empty count).
    InvalidMapping,
    /// Mapping already set (single-write semantics).
    MappingAlreadySet,
    /// Permission denied for mapping operation.
    PermissionDenied,
    /// R112-2 FIX: Namespace ID counter overflow (u64 exhausted)
    NamespaceIdOverflow,
    /// Namespace object admission/allocation failed.
    OutOfMemory,
}

impl fmt::Display for UserNsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserNsError::MaxDepthExceeded => {
                write!(
                    f,
                    "user namespace depth exceeds MAX_USER_NS_LEVEL ({})",
                    MAX_USER_NS_LEVEL
                )
            }
            UserNsError::MaxNamespaces => {
                write!(
                    f,
                    "user namespace count exceeds MAX_USER_NS_COUNT ({})",
                    MAX_USER_NS_COUNT
                )
            }
            UserNsError::TooManyMappings => {
                write!(f, "too many mapping extents (max {})", MAX_MAPPINGS)
            }
            UserNsError::InvalidMapping => write!(f, "invalid mapping (overlap/overflow/empty)"),
            UserNsError::MappingAlreadySet => write!(f, "mapping already set (single-write)"),
            UserNsError::PermissionDenied => write!(f, "permission denied"),
            UserNsError::NamespaceIdOverflow => write!(f, "namespace ID counter overflow"),
            UserNsError::OutOfMemory => write!(f, "insufficient memory"),
        }
    }
}

/// Mapping kind for permission checks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MappingKind {
    Uid,
    Gid,
}

/// RAII guard for atomic namespace count management.
///
/// Ensures the namespace count is decremented if creation fails,
/// preventing count leaks on error paths.
///
/// Uses CAS loop to avoid race conditions where multiple concurrent
/// creators could exceed MAX_USER_NS_COUNT.
struct NsCountGuard {
    committed: bool,
}

impl NsCountGuard {
    /// Try to increment the namespace count, returning an error if at limit.
    ///
    /// Uses compare_exchange loop to atomically check and increment,
    /// preventing TOCTOU race conditions that could exceed the limit.
    fn try_new() -> Result<Self, UserNsError> {
        loop {
            let current = USER_NS_COUNT.load(Ordering::SeqCst);
            if current >= MAX_USER_NS_COUNT {
                return Err(UserNsError::MaxNamespaces);
            }
            // Try to atomically increment from current to current+1
            match USER_NS_COUNT.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(Self { committed: false }),
                Err(_) => continue, // Another thread modified count, retry
            }
        }
    }

    /// Mark the guard as committed (namespace successfully created).
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for NsCountGuard {
    fn drop(&mut self) {
        if !self.committed {
            USER_NS_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

// ============================================================================
// User Namespace
// ============================================================================

/// A user namespace providing UID/GID isolation with mapping tables.
///
/// User namespaces allow processes to have different privilege levels
/// inside and outside the namespace. A process can be UID 0 (root) inside
/// its user namespace while being an unprivileged user on the host.
pub struct UserNamespace {
    /// Unique namespace identifier.
    id: NamespaceId,

    /// Parent namespace (None for root).
    parent: Option<Arc<UserNamespace>>,

    /// Nesting level (0 = root).
    level: u8,

    /// Manual reference count (for namespace file descriptors).
    refcount: AtomicU32,

    /// UID mapping table (namespace ID -> host ID).
    uid_map: RwLock<Vec<UidGidMapping>>,

    /// GID mapping table (namespace ID -> host ID).
    gid_map: RwLock<Vec<UidGidMapping>>,

    /// Flag indicating UID map has been written (single-write semantics).
    uid_map_set: AtomicBool,

    /// Flag indicating GID map has been written (single-write semantics).
    gid_map_set: AtomicBool,

    /// Exact heap charge for the namespace Arc allocation.
    _arc_heap_charge: Option<HeapCharge>,
}

impl fmt::Debug for UserNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserNamespace")
            .field("id", &self.id.raw())
            .field("level", &self.level)
            .field("refcount", &self.refcount.load(Ordering::Relaxed))
            .field("uid_map_set", &self.uid_map_set.load(Ordering::Relaxed))
            .field("gid_map_set", &self.gid_map_set.load(Ordering::Relaxed))
            .finish()
    }
}

impl UserNamespace {
    /// Create the root user namespace (identity mapping).
    ///
    /// The root namespace has no mapping tables - all UIDs/GIDs pass through
    /// unchanged (identity mapping).
    fn new_root() -> Self {
        Self {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            refcount: AtomicU32::new(1),
            uid_map: RwLock::new(Vec::new()),
            gid_map: RwLock::new(Vec::new()),
            // Root mapping is implicitly fixed (identity)
            uid_map_set: AtomicBool::new(true),
            gid_map_set: AtomicBool::new(true),
            _arc_heap_charge: None,
        }
    }

    /// Create a new child user namespace.
    ///
    /// # Arguments
    ///
    /// * `parent` - Parent namespace to derive from
    ///
    /// # Returns
    ///
    /// New child namespace with empty mapping tables (to be configured later)
    ///
    /// # Errors
    ///
    /// * `MaxDepthExceeded` - Maximum nesting depth reached
    /// * `MaxNamespaces` - System-wide namespace limit reached
    pub fn new_child(parent: Arc<UserNamespace>) -> Result<Arc<Self>, UserNsError> {
        // Check depth limit
        if parent.level >= MAX_USER_NS_LEVEL {
            return Err(UserNsError::MaxDepthExceeded);
        }

        // Check and increment namespace count atomically
        let guard = NsCountGuard::try_new()?;

        // Allocate unique ID (R112-2: overflow-safe allocation)
        let id = NEXT_USER_NS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| {
                // guard will auto-rollback on drop (R77-5 pattern)
                UserNsError::NamespaceIdOverflow
            })?;

        let arc_bytes =
            arc_charge_bytes::<UserNamespace>().map_err(|_| UserNsError::OutOfMemory)?;
        let arc_reservation = try_reserve_heap(HeapClass::CoreProcess, arc_bytes)
            .map_err(|_| UserNsError::OutOfMemory)?;
        let mut child = Arc::try_new(Self {
            id: NamespaceId::new(id),
            parent: Some(parent.clone()),
            level: parent.level.saturating_add(1),
            refcount: AtomicU32::new(1),
            uid_map: RwLock::new(Vec::new()),
            gid_map: RwLock::new(Vec::new()),
            // Child starts with unset mappings
            uid_map_set: AtomicBool::new(false),
            gid_map_set: AtomicBool::new(false),
            _arc_heap_charge: None,
        })
        .map_err(|_| UserNsError::OutOfMemory)?;

        let charge = arc_reservation
            .commit()
            .map_err(|_| UserNsError::OutOfMemory)?;
        Arc::get_mut(&mut child)
            .expect("fresh user namespace Arc must be unique")
            ._arc_heap_charge = Some(charge);

        // Commit the count increment (won't be rolled back)
        guard.commit();

        Ok(child)
    }

    /// Get namespace identifier.
    #[inline]
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Get parent namespace.
    #[inline]
    pub fn parent(&self) -> Option<Arc<UserNamespace>> {
        self.parent.clone()
    }

    /// Get nesting level.
    #[inline]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Check if this is the root namespace.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Get reference count.
    #[inline]
    pub fn ref_count(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Increment reference count (R112-2: overflow-safe).
    #[inline]
    pub fn inc_ref(&self) {
        self.refcount
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .expect("UserNamespace refcount overflow");
    }

    /// Decrement reference count.
    #[inline]
    pub fn dec_ref(&self) {
        self.refcount.fetch_sub(1, Ordering::AcqRel);
    }

    /// Check if UID mapping has been configured.
    #[inline]
    pub fn uid_map_is_set(&self) -> bool {
        self.uid_map_set.load(Ordering::Acquire)
    }

    /// Check if GID mapping has been configured.
    #[inline]
    pub fn gid_map_is_set(&self) -> bool {
        self.gid_map_set.load(Ordering::Acquire)
    }

    /// Translate a host UID into this namespace's UID.
    ///
    /// # Arguments
    ///
    /// * `host_uid` - UID on the host system
    ///
    /// # Returns
    ///
    /// The corresponding UID in this namespace, or None if unmapped.
    /// Root namespace always returns identity (input = output).
    pub fn map_uid_to_ns(&self, host_uid: u32) -> Option<u32> {
        if self.is_root() {
            return Some(host_uid);
        }

        // A child map's outside ID is expressed in the parent namespace.  Map
        // the global host ID through the parent chain first, then apply this
        // namespace's extent.
        let parent_uid = self.parent.as_ref()?.map_uid_to_ns(host_uid)?;
        let map = self.uid_map.read();
        for m in map.iter() {
            let end = m.host_id.checked_add(m.count)?;
            if parent_uid >= m.host_id && parent_uid < end {
                return m.ns_id.checked_add(parent_uid.saturating_sub(m.host_id));
            }
        }
        None
    }

    /// Translate a namespace UID back to host UID.
    ///
    /// # Arguments
    ///
    /// * `ns_uid` - UID inside this namespace
    ///
    /// # Returns
    ///
    /// The corresponding host UID, or None if unmapped.
    /// Root namespace always returns identity (input = output).
    pub fn map_uid_from_ns(&self, ns_uid: u32) -> Option<u32> {
        if self.is_root() {
            return Some(ns_uid);
        }

        let parent_uid = {
            let map = self.uid_map.read();
            let mut mapped = None;
            for m in map.iter() {
                let end = m.ns_id.checked_add(m.count)?;
                if ns_uid >= m.ns_id && ns_uid < end {
                    mapped = Some(m.host_id.checked_add(ns_uid - m.ns_id)?);
                    break;
                }
            }
            mapped?
        };
        self.parent.as_ref()?.map_uid_from_ns(parent_uid)
    }

    /// Translate a host GID into this namespace's GID.
    ///
    /// # Arguments
    ///
    /// * `host_gid` - GID on the host system
    ///
    /// # Returns
    ///
    /// The corresponding GID in this namespace, or None if unmapped.
    /// Root namespace always returns identity (input = output).
    pub fn map_gid_to_ns(&self, host_gid: u32) -> Option<u32> {
        if self.is_root() {
            return Some(host_gid);
        }

        let parent_gid = self.parent.as_ref()?.map_gid_to_ns(host_gid)?;
        let map = self.gid_map.read();
        for m in map.iter() {
            let end = m.host_id.checked_add(m.count)?;
            if parent_gid >= m.host_id && parent_gid < end {
                return m.ns_id.checked_add(parent_gid.saturating_sub(m.host_id));
            }
        }
        None
    }

    /// Translate a namespace GID back to host GID.
    ///
    /// # Arguments
    ///
    /// * `ns_gid` - GID inside this namespace
    ///
    /// # Returns
    ///
    /// The corresponding host GID, or None if unmapped.
    /// Root namespace always returns identity (input = output).
    pub fn map_gid_from_ns(&self, ns_gid: u32) -> Option<u32> {
        if self.is_root() {
            return Some(ns_gid);
        }

        let parent_gid = {
            let map = self.gid_map.read();
            let mut mapped = None;
            for m in map.iter() {
                let end = m.ns_id.checked_add(m.count)?;
                if ns_gid >= m.ns_id && ns_gid < end {
                    mapped = Some(m.host_id.checked_add(ns_gid - m.ns_id)?);
                    break;
                }
            }
            mapped?
        };
        self.parent.as_ref()?.map_gid_from_ns(parent_gid)
    }

    /// Set UID mapping table.
    ///
    /// This can only be called once (single-write semantics, matching Linux).
    ///
    /// # Arguments
    ///
    /// * `mappings` - Vector of UID mapping extents
    ///
    /// # Errors
    ///
    /// * `MappingAlreadySet` - UID mapping was already written
    /// * `InvalidMapping` - Mapping has overlaps, overflow, or empty count
    /// * `TooManyMappings` - More than MAX_MAPPINGS extents
    /// * `PermissionDenied` - Caller lacks permission to set this mapping
    pub fn set_uid_map(&self, mappings: Vec<UidGidMapping>) -> Result<(), UserNsError> {
        // Check permission before attempting to set mapping
        self.ensure_mapping_allowed(&mappings, MappingKind::Uid)?;
        set_mapping(&self.uid_map, &self.uid_map_set, mappings)
    }

    /// Set the UID map on behalf of the process that created this namespace.
    ///
    /// Procfs keeps the process-relationship check (the writer must be the
    /// target's direct parent, or host root) at the VFS boundary.  This method
    /// performs the namespace-side half of that check and, importantly, does
    /// not consult the ambient `current_euid()`: the caller snapshot captured
    /// by procfs is passed in explicitly.  That prevents a namespace-local
    /// UID 0 from being mistaken for host root when a caller races a setns or
    /// credential change.
    ///
    /// `caller_is_namespace_root` must be derived from the caller's effective
    /// UID (not the GID used for a gid_map write); it is supplied separately so
    /// an egid of zero cannot grant UID/GID administration by accident.
    pub fn set_uid_map_from_parent(
        &self,
        mappings: Vec<UidGidMapping>,
        caller_user_ns: &Arc<UserNamespace>,
        caller_id: u32,
        caller_is_namespace_root: bool,
        caller_is_host_root: bool,
    ) -> Result<(), UserNsError> {
        self.ensure_parent_mapping_allowed(
            &mappings,
            MappingKind::Uid,
            caller_user_ns,
            caller_id,
            caller_is_namespace_root,
            caller_is_host_root,
        )?;
        set_mapping(&self.uid_map, &self.uid_map_set, mappings)
    }

    /// Set GID mapping table.
    ///
    /// This can only be called once (single-write semantics, matching Linux).
    ///
    /// # Arguments
    ///
    /// * `mappings` - Vector of GID mapping extents
    ///
    /// # Errors
    ///
    /// * `MappingAlreadySet` - GID mapping was already written
    /// * `InvalidMapping` - Mapping has overlaps, overflow, or empty count
    /// * `TooManyMappings` - More than MAX_MAPPINGS extents
    /// * `PermissionDenied` - Caller lacks permission to set this mapping
    pub fn set_gid_map(&self, mappings: Vec<UidGidMapping>) -> Result<(), UserNsError> {
        // Check permission before attempting to set mapping
        self.ensure_mapping_allowed(&mappings, MappingKind::Gid)?;
        set_mapping(&self.gid_map, &self.gid_map_set, mappings)
    }

    /// Set the GID map on behalf of the process that created this namespace.
    ///
    /// See [`Self::set_uid_map_from_parent`] for the authorization contract.
    pub fn set_gid_map_from_parent(
        &self,
        mappings: Vec<UidGidMapping>,
        caller_user_ns: &Arc<UserNamespace>,
        caller_id: u32,
        caller_is_namespace_root: bool,
        caller_is_host_root: bool,
    ) -> Result<(), UserNsError> {
        self.ensure_parent_mapping_allowed(
            &mappings,
            MappingKind::Gid,
            caller_user_ns,
            caller_id,
            caller_is_namespace_root,
            caller_is_host_root,
        )?;
        set_mapping(&self.gid_map, &self.gid_map_set, mappings)
    }

    /// Get current UID mappings (for procfs display).
    pub fn uid_mappings(&self) -> Vec<UidGidMapping> {
        self.uid_map.read().clone()
    }

    /// Get current GID mappings (for procfs display).
    pub fn gid_mappings(&self) -> Vec<UidGidMapping> {
        self.gid_map.read().clone()
    }

    /// Ensure the caller has permission to set mappings in this namespace.
    ///
    /// Linux permission model (user_namespaces(7)):
    /// - Process must have CAP_SETUID/CAP_SETGID in parent namespace, OR
    /// - Process can only map its own UID/GID (single-extent mapping to self)
    /// - Mapped host IDs must be within parent namespace's mapped range
    ///
    /// # Arguments
    ///
    /// * `mappings` - The proposed mapping extents
    /// * `kind` - Whether this is a UID or GID mapping
    ///
    /// # Returns
    ///
    /// Ok(()) if the caller has permission, Err(PermissionDenied) otherwise
    fn ensure_mapping_allowed(
        &self,
        mappings: &[UidGidMapping],
        kind: MappingKind,
    ) -> Result<(), UserNsError> {
        // Resolve the complete caller snapshot, including its user namespace.
        // Looking only at the numeric euid would let UID 0 in an unrelated
        // descendant namespace configure this target (the original dead-setter
        // implementation had exactly that flaw).
        let caller_pid = crate::process::current_pid().ok_or(UserNsError::PermissionDenied)?;
        let caller = {
            let table = crate::process::PROCESS_TABLE.lock();
            table
                .get(caller_pid)
                .and_then(|slot| slot.as_ref())
                .cloned()
                .ok_or(UserNsError::PermissionDenied)?
        };
        let (caller_user_ns, caller_euid, caller_egid) = {
            let caller_guard = caller.lock();
            if matches!(
                caller_guard.state,
                crate::process::ProcessState::Zombie | crate::process::ProcessState::Terminated
            ) {
                return Err(UserNsError::PermissionDenied);
            }
            let creds = caller_guard
                .try_credentials_read()
                .ok_or(UserNsError::PermissionDenied)?;
            (caller_guard.user_ns.clone(), creds.euid, creds.egid)
        };
        let caller_id = match kind {
            MappingKind::Uid => caller_euid,
            MappingKind::Gid => caller_egid,
        };
        let caller_is_namespace_root = caller_euid == 0;
        let caller_is_host_root = caller_user_ns.map_uid_from_ns(caller_euid) == Some(0);
        self.ensure_parent_mapping_allowed(
            mappings,
            kind,
            &caller_user_ns,
            caller_id,
            caller_is_namespace_root,
            caller_is_host_root,
        )
    }

    /// Validate the namespace-side authorization for a procfs map writer.
    ///
    /// A non-root caller must be in the *exact* parent user namespace.  Merely
    /// being UID 0 in a descendant namespace is not sufficient: capabilities
    /// are scoped to the namespace that owns the target map.  Host root is a
    /// deliberate exception, but even it remains subject to parent-range
    /// containment so nested mappings cannot name IDs invisible to the parent.
    fn ensure_parent_mapping_allowed(
        &self,
        mappings: &[UidGidMapping],
        kind: MappingKind,
        caller_user_ns: &Arc<UserNamespace>,
        caller_id: u32,
        caller_is_namespace_root: bool,
        caller_is_host_root: bool,
    ) -> Result<(), UserNsError> {
        if self.is_root() {
            return Err(UserNsError::PermissionDenied);
        }

        let parent = self.parent.as_ref().ok_or(UserNsError::PermissionDenied)?;
        if !caller_is_host_root && !Arc::ptr_eq(parent, caller_user_ns) {
            return Err(UserNsError::PermissionDenied);
        }

        if !caller_is_host_root && !caller_is_namespace_root {
            // A non-root writer may only map its own parent-namespace ID to a
            // single namespace ID.  This is the unprivileged user-namespace
            // rule and also prevents arbitrary range grants by a same-UID
            // procfs peer.
            if mappings.len() != 1 {
                return Err(UserNsError::PermissionDenied);
            }
            let mapping = &mappings[0];
            if mapping.count != 1 || mapping.host_id != caller_id {
                return Err(UserNsError::PermissionDenied);
            }
        }

        self.validate_parent_containment(mappings, kind)
    }

    /// Validate that all IDs supplied in a child mapping are visible in the
    /// parent namespace.
    ///
    /// The `host_id` field of a child map is an ID in the *parent namespace*,
    /// not a host-global ID.  Therefore containment is checked against the
    /// parent's `ns_id` ranges.  Checking the parent's `host_id` ranges would
    /// reject valid nested maps (and could make the accepted set depend on an
    /// unrelated outer mapping offset).
    fn validate_parent_containment(
        &self,
        mappings: &[UidGidMapping],
        kind: MappingKind,
    ) -> Result<(), UserNsError> {
        let parent = match &self.parent {
            Some(p) => p,
            None => return Ok(()), // Root has no restrictions
        };

        // Root parent has identity mapping - all IDs are valid
        if parent.is_root() {
            return Ok(());
        }

        // Get parent's mapping table
        let parent_mappings = match kind {
            MappingKind::Uid => parent.uid_mappings(),
            MappingKind::Gid => parent.gid_mappings(),
        };

        // Each child extent's parent-namespace range must be fully contained in
        // one of the parent's namespace-ID ranges.
        for m in mappings {
            if !range_within_parent(&parent_mappings, m.host_id, m.count) {
                return Err(UserNsError::PermissionDenied);
            }
        }

        Ok(())
    }
}

/// Validate and store UID/GID mappings with overlap/overflow checks.
fn set_mapping(
    table: &RwLock<Vec<UidGidMapping>>,
    flag: &AtomicBool,
    mappings: Vec<UidGidMapping>,
) -> Result<(), UserNsError> {
    // Fast path for the common repeated-write case.  Do not set the flag yet:
    // readers use it as the publication bit, so setting it before the table
    // write would expose a transient "set but empty" mapping.
    if flag.load(Ordering::Acquire) {
        return Err(UserNsError::MappingAlreadySet);
    }

    // Validate mapping
    if mappings.is_empty() {
        return Err(UserNsError::InvalidMapping);
    }

    if mappings.len() > MAX_MAPPINGS {
        return Err(UserNsError::TooManyMappings);
    }

    if let Err(e) = validate_mappings(&mappings) {
        return Err(e);
    }

    // Serialize the final single-write decision with the table publication.
    // A concurrent writer that won the race re-checks the flag while holding
    // the same lock and cannot overwrite the first committed map.
    let mut guard = table.write();
    if flag.load(Ordering::Acquire) {
        return Err(UserNsError::MappingAlreadySet);
    }
    *guard = mappings;
    flag.store(true, Ordering::Release);
    Ok(())
}

/// Validate mapping extents for correctness.
fn validate_mappings(mappings: &[UidGidMapping]) -> Result<(), UserNsError> {
    for m in mappings {
        // Count must be non-zero
        if m.count == 0 {
            return Err(UserNsError::InvalidMapping);
        }

        // Check for overflow in namespace range
        m.ns_id
            .checked_add(m.count)
            .ok_or(UserNsError::InvalidMapping)?;

        // Check for overflow in host range
        m.host_id
            .checked_add(m.count)
            .ok_or(UserNsError::InvalidMapping)?;
    }

    // Check for overlapping extents
    for i in 0..mappings.len() {
        for j in (i + 1)..mappings.len() {
            let a = &mappings[i];
            let b = &mappings[j];

            // Check namespace ID range overlap
            if ranges_overlap(a.ns_id, a.count, b.ns_id, b.count) {
                return Err(UserNsError::InvalidMapping);
            }

            // Check host ID range overlap
            if ranges_overlap(a.host_id, a.count, b.host_id, b.count) {
                return Err(UserNsError::InvalidMapping);
            }
        }
    }

    Ok(())
}

/// Check if two ranges overlap.
#[inline]
fn ranges_overlap(start_a: u32, count_a: u32, start_b: u32, count_b: u32) -> bool {
    let end_a = start_a.saturating_add(count_a);
    let end_b = start_b.saturating_add(count_b);
    start_a < end_b && start_b < end_a
}

/// Check if a parent-namespace ID range is fully contained within any of the
/// parent's namespace-ID extents.
///
/// For a child namespace to map [parent_id_start, parent_id_start + count), the
/// entire range must fall within one of the parent's `ns_id` ranges. This
/// prevents a child from naming IDs that are unmapped in its parent.
///
/// # Arguments
///
/// * `parent_mappings` - Parent namespace's mapping table
/// * `parent_id_start` - Start of the parent-namespace ID range to check
/// * `count` - Number of IDs in the range
///
/// # Returns
///
/// true if the range is fully contained in some parent extent, false otherwise
fn range_within_parent(
    parent_mappings: &[UidGidMapping],
    parent_id_start: u32,
    count: u32,
) -> bool {
    let parent_id_end = match parent_id_start.checked_add(count) {
        Some(e) => e,
        None => return false, // Overflow means invalid range
    };

    // Check if any parent namespace-ID extent fully contains this range.
    for pm in parent_mappings {
        let Some(pm_end) = pm.ns_id.checked_add(pm.count) else {
            return false;
        };
        if parent_id_start >= pm.ns_id && parent_id_end <= pm_end {
            return true;
        }
    }

    false
}

impl Drop for UserNamespace {
    fn drop(&mut self) {
        // Decrement global count for non-root namespaces
        if self.level > 0 {
            USER_NS_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize the user namespace subsystem.
///
/// Returns the root user namespace. Should be called during kernel initialization.
#[inline]
pub fn init() -> Arc<UserNamespace> {
    ROOT_USER_NAMESPACE.clone()
}

/// Create a new child user namespace (for CLONE_NEWUSER).
///
/// # Arguments
///
/// * `parent` - Parent namespace to clone from
///
/// # Returns
///
/// New child namespace with isolated user/group ID space
///
/// # Errors
///
/// * `MaxDepthExceeded` - Maximum nesting depth reached
/// * `MaxNamespaces` - System-wide namespace limit reached
pub fn clone_user_namespace(parent: Arc<UserNamespace>) -> Result<Arc<UserNamespace>, UserNsError> {
    UserNamespace::new_child(parent)
}

/// Get the root user namespace.
#[inline]
pub fn root_user_namespace() -> Arc<UserNamespace> {
    ROOT_USER_NAMESPACE.clone()
}

/// Print namespace information for debugging.
pub fn print_user_namespace_info(ns: &Arc<UserNamespace>) {
    kprintln!(
        "[USER NS] id={}, level={}, refcount={}, uid_map_set={}, gid_map_set={}",
        ns.id().raw(),
        ns.level(),
        ns.ref_count(),
        ns.uid_map_is_set(),
        ns.gid_map_is_set()
    );
}

/// Get the current user namespace count.
#[inline]
pub fn user_ns_count() -> u32 {
    USER_NS_COUNT.load(Ordering::Relaxed)
}

// ============================================================================
// User Namespace File Descriptor
// ============================================================================

/// File descriptor wrapper for user namespace.
///
/// Used by setns(2) to switch a process's user namespace by holding
/// an open file descriptor to a namespace.
pub struct UserNamespaceFd {
    ns: Arc<UserNamespace>,
}

impl UserNamespaceFd {
    /// Create a new user namespace file descriptor.
    pub fn new(ns: Arc<UserNamespace>) -> Self {
        ns.inc_ref();
        Self { ns }
    }

    /// Access the underlying namespace.
    pub fn namespace(&self) -> Arc<UserNamespace> {
        self.ns.clone()
    }
}

impl Drop for UserNamespaceFd {
    fn drop(&mut self) {
        self.ns.dec_ref();
    }
}

impl FileOps for UserNamespaceFd {
    fn clone_box(&self) -> Result<FileDescriptor, ()> {
        self.try_clone_box()
    }

    fn try_clone_box(&self) -> Result<FileDescriptor, ()> {
        let prepared = FileDescriptor::try_prepare(mm::HeapClass::CoreProcess)?;
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

    fn type_name(&self) -> &'static str {
        "user_namespace_fd"
    }

    fn stat(&self) -> Result<VfsStat, SyscallError> {
        Ok(VfsStat {
            dev: 0,
            ino: self.ns.id().raw(),
            nlink: 1,
            mode: 0o444,
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_root_namespace_identity() {
        let root = ROOT_USER_NAMESPACE.clone();
        assert!(root.is_root());
        assert_eq!(root.level(), 0);
        assert_eq!(root.map_uid_to_ns(1000), Some(1000));
        assert_eq!(root.map_uid_from_ns(0), Some(0));
    }

    #[test]
    fn test_mapping_validation() {
        let mappings = vec![
            UidGidMapping {
                ns_id: 0,
                host_id: 1000,
                count: 1,
            },
            UidGidMapping {
                ns_id: 1,
                host_id: 1001,
                count: 1,
            },
        ];
        assert!(validate_mappings(&mappings).is_ok());

        // Overlapping ns_id
        let bad_mappings = vec![
            UidGidMapping {
                ns_id: 0,
                host_id: 1000,
                count: 2,
            },
            UidGidMapping {
                ns_id: 1,
                host_id: 2000,
                count: 1,
            },
        ];
        assert!(validate_mappings(&bad_mappings).is_err());
    }

    #[test]
    fn test_ranges_overlap() {
        assert!(ranges_overlap(0, 10, 5, 10));
        assert!(!ranges_overlap(0, 5, 5, 5));
        assert!(!ranges_overlap(10, 5, 0, 5));
    }

    #[test]
    fn r188_mapping_text_parser_is_strict_and_bounded() {
        let parsed = parse_mapping_text(b"0 1000 1\n10 2000 5\n").expect("valid map");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].host_id, 2000);
        assert!(parse_mapping_text(b"0 1000").is_err());
        assert!(parse_mapping_text(b"0 1000 0").is_err());
        assert!(parse_mapping_text(b"0 1000 1 extra").is_err());
        let too_many = b"0 1000 1\n1 1001 1\n2 1002 1\n3 1003 1\n4 1004 1\n5 1005 1\n";
        assert_eq!(
            parse_mapping_text(too_many),
            Err(UserNsError::TooManyMappings)
        );
        assert!(parse_mapping_text(b"\xff").is_err());
        assert!(parse_mapping_text(&[b'1'; MAX_MAPPING_TEXT_BYTES + 1]).is_err());
    }

    #[test]
    fn r188_mapping_validation_rejects_zero_and_overflow_ranges() {
        assert!(validate_mappings(&[UidGidMapping {
            ns_id: 0,
            host_id: 0,
            count: 0,
        }])
        .is_err());
        assert!(validate_mappings(&[UidGidMapping {
            ns_id: u32::MAX,
            host_id: 0,
            count: 2,
        }])
        .is_err());
    }

    #[test]
    fn r188_parent_mapping_authorization_is_namespace_scoped() {
        let root = ROOT_USER_NAMESPACE.clone();
        let target = UserNamespace::new_child(root.clone()).expect("target namespace");
        let mapping = vec![UidGidMapping {
            ns_id: 0,
            host_id: 1000,
            count: 1,
        }];

        // An unprivileged writer in the exact parent may map only its own ID.
        assert_eq!(
            target.set_uid_map_from_parent(mapping.clone(), &root, 1000, false, false),
            Ok(())
        );

        // The single-write rule remains enforced after authorization succeeds.
        assert_eq!(
            target.set_uid_map_from_parent(mapping.clone(), &root, 1000, false, false),
            Err(UserNsError::MappingAlreadySet)
        );

        // A caller in a different user namespace cannot configure this child,
        // even when its numeric UID is the same.
        let other_parent = UserNamespace::new_child(root.clone()).expect("other namespace");
        let other_target = UserNamespace::new_child(root.clone()).expect("other target");
        assert_eq!(
            other_target.set_uid_map_from_parent(
                mapping.clone(),
                &other_parent,
                1000,
                false,
                false,
            ),
            Err(UserNsError::PermissionDenied)
        );

        // Host root is allowed to configure a child through a different view,
        // but still cannot mutate the root namespace itself.
        assert_eq!(
            other_target.set_uid_map_from_parent(mapping, &root, 0, true, true),
            Ok(())
        );
        assert_eq!(
            root.set_uid_map_from_parent(
                vec![UidGidMapping {
                    ns_id: 0,
                    host_id: 0,
                    count: 1,
                }],
                &root,
                0,
                true,
                true,
            ),
            Err(UserNsError::PermissionDenied)
        );

        // Validation failures do not consume the one-shot publication slot.
        let retry_target = UserNamespace::new_child(root.clone()).expect("retry target");
        assert_eq!(
            retry_target.set_uid_map_from_parent(
                vec![UidGidMapping {
                    ns_id: u32::MAX,
                    host_id: 1000,
                    count: 1,
                }],
                &root,
                1000,
                false,
                false,
            ),
            Err(UserNsError::InvalidMapping)
        );
        assert_eq!(
            retry_target.set_uid_map_from_parent(
                vec![UidGidMapping {
                    ns_id: 0,
                    host_id: 1000,
                    count: 1,
                }],
                &root,
                1000,
                false,
                false,
            ),
            Ok(())
        );
    }

    #[test]
    fn r188_nested_parent_mapping_requires_containment() {
        let root = ROOT_USER_NAMESPACE.clone();
        let parent = UserNamespace::new_child(root.clone()).expect("parent namespace");
        parent
            .set_uid_map_from_parent(
                vec![UidGidMapping {
                    ns_id: 0,
                    host_id: 1000,
                    count: 10,
                }],
                &root,
                0,
                true,
                true,
            )
            .expect("seed parent map");
        parent
            .set_gid_map_from_parent(
                vec![UidGidMapping {
                    ns_id: 0,
                    host_id: 1000,
                    count: 10,
                }],
                &root,
                0,
                true,
                true,
            )
            .expect("seed parent gid map");
        let target = UserNamespace::new_child(parent.clone()).expect("nested namespace");

        assert_eq!(
            target.set_uid_map_from_parent(
                vec![UidGidMapping {
                    ns_id: 0,
                    // Child outside-IDs are parent-namespace IDs, so 5 is
                    // covered by the parent's ns_id range 0..10.
                    host_id: 5,
                    count: 1,
                }],
                &parent,
                0,
                true,
                false,
            ),
            Ok(())
        );
        target
            .set_gid_map_from_parent(
                vec![UidGidMapping {
                    ns_id: 0,
                    host_id: 5,
                    count: 1,
                }],
                &parent,
                0,
                true,
                false,
            )
            .expect("nested gid map");
        assert_eq!(target.map_uid_from_ns(0), Some(1005));
        assert_eq!(target.map_uid_to_ns(1005), Some(0));
        assert_eq!(target.map_gid_from_ns(0), Some(1005));
        assert_eq!(target.map_gid_to_ns(1005), Some(0));

        let rejected = UserNamespace::new_child(parent.clone()).expect("second nested namespace");
        assert_eq!(
            rejected.set_uid_map_from_parent(
                vec![UidGidMapping {
                    ns_id: 0,
                    host_id: 2000,
                    count: 1,
                }],
                &parent,
                0,
                true,
                false,
            ),
            Err(UserNsError::PermissionDenied)
        );

        // The containment check is against the parent's namespace IDs, not
        // its outer host IDs: the parent map is 0..10 -> 1000..1010.
        assert!(range_within_parent(
            &[UidGidMapping {
                ns_id: 0,
                host_id: 1000,
                count: 10,
            }],
            5,
            1,
        ));
        assert!(!range_within_parent(
            &[UidGidMapping {
                ns_id: 0,
                host_id: 1000,
                count: 10,
            }],
            1005,
            1,
        ));
    }
}
