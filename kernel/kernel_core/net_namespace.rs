//! Network Namespace Implementation for Zero-OS
//!
//! Provides isolated network stack for containerization support. Each network
//! namespace maintains its own:
//! - Network interfaces (devices)
//! - IP addresses and routing tables
//! - Socket bindings
//! - Firewall rules
//!
//! # Design
//!
//! Follows the same hierarchical model as other namespaces:
//! - Root namespace at level 0 (contains physical devices by default)
//! - Child namespaces created via CLONE_NEWNET or unshare(CLONE_NEWNET)
//! - Maximum nesting depth of 32 levels
//!
//! # Security
//!
//! - All network namespace operations require CAP_NET_ADMIN or CAP_SYS_ADMIN
//! - Namespace switching (setns) requires single-threaded process
//! - Network resources are isolated: sockets in different namespaces can bind same ports
//!
//! # Usage
//!
//! ```rust,ignore
//! // Create child namespace
//! let child_ns = clone_net_namespace(parent_ns)?;
//!
//! // Check socket visibility
//! let visible = is_socket_in_namespace(socket_id, &ns);
//! ```

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use cap::NamespaceId;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use mm::HeapClass;
use spin::{Mutex, RwLock};

// D3-NETNS-DATAPLANE: per-namespace dataplane state (ARP cache) lives in the
// net crate; kernel_core owns the namespace objects and serves lookups to the
// net crate through the `NetNsDeviceHooks` trait (net cannot depend on
// kernel_core — dependency cycle).
use net::arp::ArpCache;

// ============================================================================
// Constants
// ============================================================================

/// Maximum network namespace nesting depth
pub const MAX_NET_NS_LEVEL: u8 = 32;

/// CLONE_NEWNET flag for clone/unshare
pub const CLONE_NEWNET: u64 = 0x4000_0000;

/// R76-2 FIX: Maximum number of network namespaces allowed system-wide.
/// Prevents DoS via namespace exhaustion.
pub const MAX_NET_NS_COUNT: u32 = 1024;

/// R76-2 FIX: Current network namespace count (root starts at 1).
static NET_NS_COUNT: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// Error Types
// ============================================================================

/// Network namespace operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetNsError {
    /// Maximum namespace depth exceeded
    MaxDepthExceeded,
    /// R76-2 FIX: Maximum system-wide namespace count exceeded
    MaxNamespaces,
    /// Namespace not found
    NotFound,
    /// Permission denied
    PermissionDenied,
    /// Device already exists in namespace
    DeviceExists,
    /// Device not found
    DeviceNotFound,
    /// Invalid namespace state
    InvalidState,
    /// R112-2 FIX: Namespace ID counter overflow (u64 exhausted)
    NamespaceIdOverflow,
}

// ============================================================================
// R77-5 FIX: Namespace Count Guard
// ============================================================================

/// Guard for atomic namespace count management.
///
/// # R77-5 FIX
///
/// This guard ensures that the global namespace count is correctly maintained
/// even if `Arc::new()` fails (OOM) after the count has been incremented.
/// The guard automatically decrements the count on drop unless `commit()` is called.
///
/// ## Problem
///
/// Previously, the count was incremented before `Arc::new()`:
/// ```ignore
/// let prev = NET_NS_COUNT.fetch_add(1, ...);  // Count incremented
/// let child = Arc::new(Self { ... });          // If OOM here, count leaks!
/// ```
///
/// ## Solution
///
/// Use RAII pattern to ensure automatic rollback:
/// ```ignore
/// let guard = NsCountGuard::new(&NET_NS_COUNT)?;  // Count incremented
/// let child = Arc::new(Self { ... });              // If OOM, guard drops and rolls back
/// guard.commit();                                  // Success - prevent rollback
/// ```
struct NsCountGuard {
    counter: &'static AtomicU32,
    committed: bool,
}

impl NsCountGuard {
    /// Create a new guard, incrementing the counter.
    ///
    /// Returns error if the count would exceed the limit.
    fn new(counter: &'static AtomicU32, max_count: u32) -> Result<Self, NetNsError> {
        let prev = counter.fetch_add(1, Ordering::SeqCst); // lint-fetch-add: allow (count guard with immediate rollback)
        if prev >= max_count {
            counter.fetch_sub(1, Ordering::SeqCst);
            return Err(NetNsError::MaxNamespaces);
        }
        Ok(Self {
            counter,
            committed: false,
        })
    }

    /// Commit the count increment, preventing rollback on drop.
    ///
    /// Call this after the namespace has been successfully created.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for NsCountGuard {
    fn drop(&mut self) {
        if !self.committed {
            // Allocation failed - roll back the count increment
            self.counter.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

lazy_static::lazy_static! {
    /// Root network namespace - contains physical devices by default
    pub static ref ROOT_NET_NAMESPACE: Arc<NetNamespace> = Arc::new(NetNamespace::new_root());

    /// D1-ISO-NETNS-DATAPLANE FIX: id -> namespace lookup for the TX
    /// device-ownership gate. Holds Weak so the registry never extends a
    /// namespace's lifetime (Drop still fires when the last process exits);
    /// rows are removed in NetNamespace::drop, so the map size tracks LIVE
    /// child namespaces (bounded by MAX_NET_NS_COUNT), not cumulative ids.
    static ref NET_NS_BY_ID: RwLock<BTreeMap<u64, Weak<NetNamespace>>> =
        RwLock::new(BTreeMap::new());
}

/// Next available namespace ID (starts at 1, 0 is reserved for root)
static NEXT_NET_NS_ID: AtomicU64 = AtomicU64::new(1);

// ============================================================================
// Network Namespace
// ============================================================================

/// A network namespace providing isolated network stack.
///
/// Each namespace has its own:
/// - Set of network devices (interfaces)
/// - IP address assignments
/// - Routing table
/// - Socket bindings (same port can be used in different namespaces)
/// - Firewall rules
/// - D3-NETNS-DATAPLANE: Per-namespace ARP cache
/// state charged to `HeapClass::NetnsConfig`.
///
/// Sizing: the only consumer today is the per-ns ARP cache (256 entries of
/// ~24 bytes). Its worst transient is the final doubling, where the old
/// 128-entry backing and the new 256-entry backing coexist until the retired
/// owner drops: 128*24 + 256*24 = 9216 bytes. 16 KiB covers that peak with
/// ~70% slack for entry-layout drift. The limit is a CEILING, not an
/// entitlement — the shared 512 KiB class can exhaust first (by design:
/// budgets bound per-ns blast radius, they do not guarantee availability).
pub struct NetNamespace {
    /// Unique namespace identifier
    id: NamespaceId,

    /// Parent namespace (None for root)
    parent: Option<Arc<NetNamespace>>,

    /// Nesting level (0 = root)
    level: u8,

    /// Reference count of processes using this namespace
    refcount: AtomicU32,

    /// Network devices assigned to this namespace (by device index)
    devices: RwLock<BTreeSet<u32>>,

    /// Loopback interface is always present (127.0.0.1)
    has_loopback: bool,

    /// D3-NETNS-DATAPLANE FIRST-SLICE: Per-namespace ARP cache.
    ///
    /// Each namespace (including root) owns isolated IP->MAC mappings; entry
    /// storage is heap-admitted to `HeapClass::NetnsConfig`. Held behind an
    /// `Arc` so the net crate's hook accessor can hand the cache out WITHOUT
    /// handing out a namespace reference — ARP processing then never holds
    /// anything whose drop could run `NetNamespace::Drop` teardown.
    ///
    /// The global cache in the net crate remains only as the TX fallback for
    /// the pre-hook-registration window (early boot / host tests), where the
    /// TX ownership gate restricts traffic to the root namespace.
    arp_cache: Arc<Mutex<ArpCache>>,

    /// (today: `arp_cache`'s entry storage) holds an `Arc` clone and takes a
    /// dual lease (shared class + this budget) on growth. Root is NOT
    /// exempt. `Drop` closes it to NEW leases; usage is never zeroed —
    /// orphaned allocations release when they really drop.
}

impl fmt::Debug for NetNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetNamespace")
            .field("id", &self.id.raw())
            .field("level", &self.level)
            .field("refcount", &self.refcount.load(Ordering::Relaxed))
            .field("has_loopback", &self.has_loopback)
            .finish()
    }
}

impl NetNamespace {
    /// Create the root network namespace.
    fn new_root() -> Self {
        Self {
            id: NamespaceId::new(0),
            parent: None,
            level: 0,
            refcount: AtomicU32::new(1),
            devices: RwLock::new(BTreeSet::new()),
            has_loopback: true,
            // D3-NETNS-DATAPLANE: bounded per-ns cache (256 entries), entry
            // storage dual-leased against the NetnsConfig class ceiling AND
            // this namespace's config budget.
                mm::HeapClass::NetnsConfig,
        }
    }

    /// Create a new child namespace.
    ///
    /// Child namespaces start with only a loopback interface.
    /// Physical devices must be explicitly moved into child namespaces.
    ///
    /// # R77-5 FIX
    ///
    /// Uses `NsCountGuard` to ensure the global namespace count is correctly
    /// maintained even if `Arc::new()` fails (OOM). The guard automatically
    /// rolls back the count increment on failure.
    pub fn new_child(parent: Arc<NetNamespace>) -> Result<Arc<Self>, NetNsError> {
        if parent.level >= MAX_NET_NS_LEVEL {
            return Err(NetNsError::MaxDepthExceeded);
        }

        // R77-5 FIX: Use guard pattern to ensure count rollback on allocation failure.
        // The guard increments the count and will auto-decrement on drop unless committed.
        let count_guard = NsCountGuard::new(&NET_NS_COUNT, MAX_NET_NS_COUNT)?;

        // R112-2: overflow-safe namespace ID allocation
        let id = NEXT_NET_NS_ID
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| {
                // count_guard will auto-rollback on drop (R77-5 pattern)
                NetNsError::NamespaceIdOverflow
            })?;

        let child = Arc::new(Self {
            id: NamespaceId::new(id),
            parent: Some(parent.clone()),
            level: parent.level.saturating_add(1),
            refcount: AtomicU32::new(1),
            devices: RwLock::new(BTreeSet::new()), // Empty - only loopback
            has_loopback: true,
            // D3-NETNS-DATAPLANE: bounded per-ns cache (256 entries), entry
            // storage dual-leased against the NetnsConfig class ceiling AND
            // this namespace's config budget.
                mm::HeapClass::NetnsConfig,
        });

        // R77-5 FIX: Arc allocation succeeded - commit the guard to prevent rollback.
        count_guard.commit();

        // D1-ISO-NETNS-DATAPLANE FIX: publish the id -> namespace row consumed
        // by the TX device-ownership gate. Weak: the registry must never keep a
        // dead namespace alive. Published AFTER commit so a row always refers to
        // a fully constructed, counted namespace; the matching remove is in Drop.
        NET_NS_BY_ID.write().insert(id, Arc::downgrade(&child));

        Ok(child)
    }

    /// Get the namespace identifier.
    #[inline]
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Get the parent namespace.
    #[inline]
    pub fn parent(&self) -> Option<Arc<NetNamespace>> {
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
            .expect("NetNamespace refcount overflow");
    }

    /// Decrement reference count.
    #[inline]
    pub fn dec_ref(&self) {
        self.refcount.fetch_sub(1, Ordering::AcqRel);
    }

    /// Check if namespace has loopback interface.
    #[inline]
    pub fn has_loopback(&self) -> bool {
        self.has_loopback
    }

    /// Add a device to this namespace.
    ///
    /// Note: Device must be removed from its current namespace first.
    pub fn add_device(&self, device_idx: u32) -> Result<(), NetNsError> {
        let mut devices = self.devices.write();
        if devices.contains(&device_idx) {
            return Err(NetNsError::DeviceExists);
        }
        devices.insert(device_idx);
        Ok(())
    }

    /// Remove a device from this namespace.
    pub fn remove_device(&self, device_idx: u32) -> Result<(), NetNsError> {
        let mut devices = self.devices.write();
        if devices.remove(&device_idx) {
            Ok(())
        } else {
            Err(NetNsError::DeviceNotFound)
        }
    }

    /// Check if device is in this namespace.
    pub fn has_device(&self, device_idx: u32) -> bool {
        self.devices.read().contains(&device_idx)
    }

    /// Get list of devices in this namespace.
    pub fn devices(&self) -> Vec<u32> {
        self.devices.read().iter().copied().collect()
    }

    /// Get number of devices in this namespace.
    pub fn device_count(&self) -> usize {
        self.devices.read().len()
    }

    /// D3-NETNS-DATAPLANE: Get this namespace's ARP cache.
    ///
    /// Returns a clone of the cache `Arc`, NOT a namespace reference: the
    /// caller (ultimately the net crate's RX/TX paths, via the
    /// `NetNsDeviceHooks::ns_arp_cache` hook) can lock and use the cache
    /// while holding nothing that pins this namespace, so dropping what it
    /// holds can never run `NetNamespace::Drop` teardown. A clone held
    /// across namespace destruction merely delays freeing the cache
    /// allocation itself — per-ns entries are private to the namespace and
    /// no registry row is affected.
    #[inline]
    pub fn arp_cache(&self) -> Arc<Mutex<ArpCache>> {
        Arc::clone(&self.arp_cache)
    }

}

// ============================================================================
// Public API
// ============================================================================

/// Initialize the network namespace subsystem.
///
/// Called during kernel initialization to set up the root namespace.
pub fn init() -> Arc<NetNamespace> {
    ROOT_NET_NAMESPACE.clone()
}

/// Create a new child network namespace (for CLONE_NEWNET).
///
/// # Arguments
///
/// * `parent` - Parent namespace to derive from
///
/// # Returns
///
/// New child namespace with isolated network stack (only loopback)
///
/// # Errors
///
/// * `MaxDepthExceeded` - Maximum nesting depth reached
pub fn clone_net_namespace(parent: Arc<NetNamespace>) -> Result<Arc<NetNamespace>, NetNsError> {
    NetNamespace::new_child(parent)
}

/// Print namespace information for debugging.
pub fn print_net_namespace_info(ns: &Arc<NetNamespace>) {
    kprintln!(
        "[NET NS] id={}, level={}, refcount={}, devices={}",
        ns.id().raw(),
        ns.level(),
        ns.ref_count(),
        ns.device_count()
    );
}

/// Get the root network namespace.
#[inline]
pub fn root_net_namespace() -> Arc<NetNamespace> {
    ROOT_NET_NAMESPACE.clone()
}

/// D1-ISO-NETNS-DATAPLANE FIX: does namespace `ns_id` own device `device_idx`?
///
/// Ownership truth for the net crate's TX gate (via `NetNsDeviceHooks`):
/// - ns 0 (root) owns every registered physical device by default — physical
///   devices live in the root namespace unless explicitly moved out;
/// - a child namespace owns exactly the devices in its `devices` set
///   (populated only by `add_device` / `move_device`, which require
///   CAP_NET_ADMIN or host root);
/// - an unknown or already-destroyed ns id owns nothing (fail-closed: the
///   Weak row is gone or upgrades to None).
///
/// Lock context: takes only NET_NS_BY_ID (read) then the namespace's own
/// `devices` RwLock (read) — both leaf locks, never held together with any
/// process/socket/device-registry lock. Callable from any TX context.
///
/// D1ISO mint-time contract (TX-gate callers, via `NetNsDeviceHooks`): both
/// physical TX sinks mint their `AuthorizedTxDevice` token — i.e. call this —
/// BEFORE taking the per-socket `operation` spinlock. Process-driven send
/// paths may hold per-socket send locks here, but a send implies a live
/// process whose PCB pins the namespace Arc, so the Weak upgrade below can
/// never hold the LAST strong reference on those paths. On the RX-reply path
/// no socket lock is held at mint, and a last-reference teardown triggered by
/// dropping the upgraded Arc is lock-safe: the NET_NS_BY_ID read guard is
/// released (scoped block below) before `ns` drops, so `NetNamespace::Drop`'s
/// NET_NS_BY_ID.write() cannot self-deadlock.
pub fn net_ns_owns_device(ns_id: u64, device_idx: u32) -> bool {
    if ns_id == 0 {
        return true;
    }
    let ns = {
        let map = NET_NS_BY_ID.read();
        match map.get(&ns_id) {
            Some(weak) => weak.upgrade(),
            None => None,
        }
    };
    match ns {
        Some(ns) => ns.has_device(device_idx),
        None => false,
    }
}

/// D3-NETNS-DATAPLANE: Look up a network namespace by ID.
///
/// Returns the root namespace for ID 0, or looks up child namespaces
/// in the registry. Returns None if the namespace ID is unknown or
/// the namespace has been destroyed.
///
/// # Lock context
///
/// Takes NET_NS_BY_ID (read) — a leaf lock. Safe to call from any context.
pub fn lookup_net_ns(ns_id: u64) -> Option<Arc<NetNamespace>> {
    if ns_id == 0 {
        return Some(ROOT_NET_NAMESPACE.clone());
    }
    let map = NET_NS_BY_ID.read();
    map.get(&ns_id).and_then(|weak| weak.upgrade())
}

/// Move a device from one namespace to another.
///
/// # Security
///
/// This operation requires CAP_NET_ADMIN in both the source and
/// destination namespaces.
///
/// # R75-3 FIX
///
/// Added permission check: requires CAP_ADMIN (CAP_NET_ADMIN equivalent)
/// or root (euid == 0) to move devices between namespaces. Without this
/// check, unprivileged processes could hijack network devices from the
/// host namespace or inject devices into other namespaces.
///
/// # D1-ISO-NETNS-DATAPLANE: TX revocation contract
///
/// TX authorization linearizes at the ownership CHECK (`net_ns_owns_device`
/// inside the net crate's `resolve_authorized_tx_device`), not at device
/// enqueue. A transmit that passed the check before `move_device` returns may
/// still hit the driver queue afterwards; the window is bounded by one
/// in-flight `build_frame_and_transmit` / `transmit_prepared_reply` call (no
/// handle caching across calls). Strong drain-before-return semantics would
/// require a per-device ownership generation synchronized with driver
/// enqueue — deliberately NOT implemented; do not claim drain semantics here.
pub fn move_device(
    device_idx: u32,
    from: &Arc<NetNamespace>,
    to: &Arc<NetNamespace>,
) -> Result<(), NetNsError> {
    // R75-3 FIX: Security check - require CAP_NET_ADMIN (mapped to ADMIN) or root
    let has_cap_admin =
        crate::process::with_current_cap_table(|tbl| tbl.has_rights(cap::CapRights::ADMIN))
            .unwrap_or(false);
    // R133-1 FIX: Host-global gates must check host-mapped identity.
    // Fail-closed: if we can't determine host identity, assume non-root.
    let is_root = crate::current_is_host_root();
    if !is_root && !has_cap_admin {
        return Err(NetNsError::PermissionDenied);
    }

    // Remove from source namespace
    from.remove_device(device_idx)?;

    // Add to destination namespace
    match to.add_device(device_idx) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Rollback: put device back in source
            let _ = from.add_device(device_idx);
            Err(e)
        }
    }
}

// ============================================================================
// R76-2 FIX: Namespace Resource Cleanup
// ============================================================================

/// R76-2 FIX: Decrement global namespace counter when namespace is destroyed.
impl Drop for NetNamespace {
    fn drop(&mut self) {
        if self.level > 0 {
            // D1-ISO-NETNS-DATAPLANE FIX: remove the id -> namespace row so the
            // registry tracks live namespaces only. A stale Weak would upgrade
            // to None anyway (fail-closed at the gate), but removing keeps the
            // map bounded by live count, matching the firewall-table contract.
            NET_NS_BY_ID.write().remove(&self.id.0);
            // R121-1 FIX: Clean up per-namespace firewall table to prevent
            // unbounded growth of the global FIREWALL_TABLES map.
            net::firewall::firewall_remove_ns(self.id.0);
            // J2-8: backstop the per-cgroup ephemeral-port budget — once this
            // namespace is destroyed, nothing ever allocates an ephemeral port in
            // it again, so the alloc-time reaper would never run and any still
            // -charged binding for this ns would leak forever. Remove all (ns,*)
            // bindings and enqueue their charges (Drop runs in arbitrary context,
            // so this is enqueue-only; the Level-5 uncharge happens at the next
            // process-context drain).
            net::socket_table().drain_ns_port_bindings(self.id);
            // R170-7 FIX: also drain the five per-ns COUNTER maps (socket /
            // conn / syn counts, send / recv byte budgets). They self-prune
            // at zero on the decrement paths, but a namespace destroyed with
            // any counter still non-zero leaked its row forever (ns ids are
            // never reused). Pure-leaf mutexes, locked one at a time — see
            // the lock-context proof on `drain_ns_counters` itself.
            net::socket_table().drain_ns_counters(self.id);
            // R171-G4-2 FIX: drain the 6th per-ns map the R170-7 backstop missed —
            // conntrack's per-namespace flow rows + entry-count. `ct_drain_ns`
            // removes every (ns, *) flow and drops the ns's CT_MAX_ENTRIES_PER_NS
            // counter row, so a destroyed namespace reclaims its conntrack budget +
            // global table slots immediately (ns ids are never reused; otherwise
            // the row + flows leak until each flow individually times out).
            net::conntrack::ct_drain_ns(self.id.0);
            NET_NS_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

// ============================================================================
// Network Namespace File Descriptor (for sys_setns)
// ============================================================================

use crate::{FileDescriptor, FileOps, SyscallError};

/// File descriptor wrapper for network namespace (used by sys_setns).
///
/// When a process opens /proc/[pid]/ns/net, it gets this file descriptor
/// that references the target process's network namespace.
pub struct NetNamespaceFd {
    ns: Arc<NetNamespace>,
}

impl NetNamespaceFd {
    /// Create a new network namespace file descriptor.
    pub fn new(ns: Arc<NetNamespace>) -> Self {
        ns.inc_ref();
        Self { ns }
    }

    /// Get the underlying namespace.
    pub fn namespace(&self) -> Arc<NetNamespace> {
        self.ns.clone()
    }
}

impl Drop for NetNamespaceFd {
    fn drop(&mut self) {
        self.ns.dec_ref();
    }
}

impl FileOps for NetNamespaceFd {
    fn clone_box(&self) -> FileDescriptor {
        self.try_clone_box()
            .expect("network namespace fd clone allocation/admission failed")
    }

    fn try_clone_box(&self) -> Result<FileDescriptor, ()> {
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

    fn type_name(&self) -> &'static str {
        "net_namespace_fd"
    }

    fn stat(&self) -> Result<crate::VfsStat, SyscallError> {
        Ok(crate::VfsStat {
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
// Test Support
// ============================================================================

/// Test helper: Check if network namespace subsystem is initialized.
pub fn test_is_net_ns_initialized() -> bool {
    ROOT_NET_NAMESPACE.id().raw() == 0 && ROOT_NET_NAMESPACE.is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_namespace() {
        let root = ROOT_NET_NAMESPACE.clone();
        assert!(root.is_root());
        assert_eq!(root.level(), 0);
        assert_eq!(root.id().raw(), 0);
        assert!(root.has_loopback());
    }

    #[test]
    fn test_child_namespace() {
        let root = ROOT_NET_NAMESPACE.clone();
        let child = clone_net_namespace(root.clone()).unwrap();

        assert!(!child.is_root());
        assert_eq!(child.level(), 1);
        assert!(child.parent().is_some());
        assert_eq!(child.parent().unwrap().id(), root.id());
        assert!(child.has_loopback());
        assert_eq!(child.device_count(), 0); // Only loopback, no physical devices
    }

    #[test]
    fn test_device_management() {
        let ns = clone_net_namespace(ROOT_NET_NAMESPACE.clone()).unwrap();

        // Add device
        assert!(ns.add_device(1).is_ok());
        assert!(ns.has_device(1));
        assert_eq!(ns.device_count(), 1);

        // Duplicate add fails
        assert!(matches!(ns.add_device(1), Err(NetNsError::DeviceExists)));

        // Remove device
        assert!(ns.remove_device(1).is_ok());
        assert!(!ns.has_device(1));
        assert_eq!(ns.device_count(), 0);

        // Remove non-existent fails
        assert!(matches!(
            ns.remove_device(1),
            Err(NetNsError::DeviceNotFound)
        ));
    }

    #[test]
    fn test_max_depth() {
        let mut current = ROOT_NET_NAMESPACE.clone();

        for level in 1..=MAX_NET_NS_LEVEL {
            match clone_net_namespace(current.clone()) {
                Ok(child) => {
                    assert_eq!(child.level(), level);
                    current = child;
                }
                Err(NetNsError::MaxDepthExceeded) => {
                    assert_eq!(level, MAX_NET_NS_LEVEL + 1);
                    break;
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }
    }
}
