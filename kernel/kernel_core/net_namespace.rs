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
use mm::{arc_charge_bytes, try_reserve_heap, HeapCharge, HeapClass};
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
    /// R186-3 FIX: a required allocation for the namespace, its ARP cache, its
    /// config budget, or the id registry row could not be satisfied.
    ///
    /// `MAX_NET_NS_COUNT` is a CARDINALITY bound, not a byte reservation, so a
    /// count check cannot stand in for admission: an unprivileged
    /// `CLONE_NEWUSER|CLONE_NEWNET` reaches namespace construction and must be
    /// able to fail with ENOMEM rather than reach the allocator's panic handler.
    OutOfMemory,
}

/// D3 NETNS-CONFIG: Errors from [`NetNamespace::set_net_config`].
///
/// A dedicated enum (not `NetNsError`): these are the validation contracts
/// the future netns-admin syscall surface will map to errnos, and they must
/// not disturb existing exhaustive matches on `NetNsError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetConfigError {
    /// Root's addressing authority is the net crate's global config
    /// (single source of truth, delegated to by the `ns_net_config` hook);
    /// mutating it through the per-ns seam is not a valid operation this
    /// slice (Codex round-9: a root setter would let root config and the
    /// pre-registration fallback drift).
    RootImmutable,
    /// Prefix length outside 1..=32. /0 would put every address on-link,
    /// which is not host addressing.
    InvalidPrefix,
    /// Source MAC is zero, multicast, or broadcast. Zero means
    /// "autodetect pending" and is a ROOT-ONLY state — a child config must
    /// carry a concrete unicast MAC.
    InvalidSourceMac,
    /// Gateway MAC is zero, multicast, or broadcast.
    InvalidGatewayMac,
    /// Source IP fails the prefix-independent validity check (broadcast,
    /// multicast, unspecified, loopback, 0/8), or — for /1../30 prefixes —
    /// its host part is all-zeros (the subnet's network address) or
    /// all-ones (its directed broadcast). Exact subnet-relative rejection
    /// replaces the wire path's prefix-blind .255 heuristic (rounds
    /// 10-11).
    InvalidSourceIp,
    /// Gateway IP fails the same prefix-independent validity check, or —
    /// for /1../30 prefixes — is the subnet's network or directed-
    /// broadcast address.
    InvalidGatewayIp,
    /// Gateway is not on the configured subnet — this slice has no routing
    /// module, so an off-link gateway could never be reached. (A /32
    /// prefix therefore admits no gateway at all: point-to-point configs
    /// need the routing leg's on-link logic.)
    GatewayOffSubnet,
    /// Gateway equals the source address.
    GatewayIsSelf,
}

/// D3 NETNS-CONFIG: a MAC a namespace may be CONFIGURED with — a concrete
/// unicast address only. Zero (autodetect-pending) is a root-only state,
/// and any address with the I/G bit set (multicast, including broadcast)
/// can never source a frame.
#[inline]
fn is_configurable_unicast_mac(mac: net::EthAddr) -> bool {
    mac.0 != [0u8; 6] && (mac.0[0] & 0x01) == 0
}

/// D3 NETNS-CONFIG (round-11): configuration-time IP validity — the
/// prefix-INDEPENDENT half of `Ipv4Addr::is_valid_source`. The wire-path
/// "last octet 255" heuristic is deliberately OMITTED here: with the
/// configured prefix in hand, `set_net_config`'s exact subnet-relative
/// check decides broadcast-ness (R44-3's own TODO anticipated exactly this
/// call site). A .255 address that is NOT the configured subnet's
/// broadcast — an RFC 3021 /31 upper endpoint (x.y.z.254/31 ↔ x.y.z.255),
/// or a mid-subnet host like x.y.0.255/16 — is a legitimate host; one
/// that IS the broadcast is rejected exactly. The WIRE path keeps the
/// blunt prefix-blind heuristic unchanged (it validates untrusted remote
/// sources, where no prefix is known).
#[inline]
fn is_configurable_host_ip(ip: net::Ipv4Addr) -> bool {
    !(ip.is_broadcast() || ip.is_multicast() || ip.is_unspecified() || ip.is_loopback())
        && ip.octets()[0] != 0
}

// ============================================================================
// R77-5 FIX: Namespace Count Guard
// ============================================================================

/// Guard for atomic namespace count management.
///
/// # R77-5 FIX
///
/// This guard owns the global namespace count until ownership is transferred to
/// a constructed `NetNamespace`. Before that point it automatically decrements
/// on failure. Afterwards `NetNamespace::drop` is the sole decrement owner,
/// including when `Arc::try_new` drops its input after an allocation failure.
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
/// let guard = NsCountGuard::new(&NET_NS_COUNT)?; // Count incremented
/// let child = Self { ... };                       // NetNamespace::drop can now roll back
/// guard.commit();                                 // Transfer count ownership to child
/// let child = Arc::try_new(child)?;               // On OOM, child drops exactly once
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
    /// Call immediately after constructing the namespace value and before any
    /// operation that may drop it.
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
    ///
    /// R186-3 FIX: was `BTreeMap`, whose `insert` is INFALLIBLE — an unprivileged
    /// namespace creation under memory pressure aborted the kernel while growing
    /// this map. `AdmittedMap` makes the growth both fallible (`try_insert`) and
    /// charged against the aggregate heap ledger, so the registry participates in
    /// admission instead of merely being bounded by a count.
    static ref NET_NS_BY_ID: RwLock<mm::AdmittedMap<u64, Weak<NetNamespace>>> =
        RwLock::new(mm::AdmittedMap::new(mm::HeapClass::NetnsConfig));
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
/// D3 NETNS-SUBBUDGET-1: per-namespace byte ceiling for dataplane CONFIG
/// state charged to `HeapClass::NetnsConfig`.
///
/// Sizing: the only consumer today is the per-ns ARP cache (256 entries of
/// ~24 bytes). Its worst transient is the final doubling, where the old
/// 128-entry backing and the new 256-entry backing coexist until the retired
/// owner drops: 128*24 + 256*24 = 9216 bytes. 16 KiB covers that peak with
/// ~70% slack for entry-layout drift. The limit is a CEILING, not an
/// entitlement — the shared 512 KiB class can exhaust first (by design:
/// budgets bound per-ns blast radius, they do not guarantee availability).
pub const NETNS_CONFIG_BUDGET_BYTES: usize = 16 * 1024;

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

    /// D3 NETNS-SUBBUDGET-1: this namespace's config byte budget, shared as
    /// a capability — every allocation-owning object charged against it
    /// (today: `arp_cache`'s entry storage) holds an `Arc` clone and takes a
    /// dual lease (shared class + this budget) on growth. Root is NOT
    /// exempt. `Drop` closes it to NEW leases; usage is never zeroed —
    /// orphaned allocations release when they really drop.
    config_budget: Arc<mm::NsByteBudget>,

    /// D3 NETNS-CONFIG: this namespace's network addressing (PO-NET-01
    /// §4.3 Phase 2). `None` = unconfigured — TX in this namespace fails
    /// closed (`TxError::LinkDown`) BEFORE firewall/conntrack evaluation,
    /// so a child can never borrow the root's identity.
    ///
    /// ROOT'S FIELD IS ALWAYS `None`: the root namespace's addressing
    /// authority is the net crate's global config, DELEGATED to by the
    /// `ns_net_config` hook — storing a root copy here would create a
    /// second authority that could drift from the pre-registration
    /// fallback (Codex round-9). Mutation is child-only via
    /// [`Self::set_net_config`]; nothing mutates the global config.
    ///
    /// Tiny inline `Copy` value behind a leaf mutex — no heap, no
    /// `config_budget` interaction.
    net_config: Mutex<Option<net::NetConfigSnapshot>>,

    /// RF186-2: exact-lifetime charge for this namespace's Arc allocation.
    /// Root is constructed before runtime admission is published and stores
    /// `None`; every user-reachable child stores `Some`.
    _arc_heap_charge: Option<HeapCharge>,
}

fn reserve_netns_arc_charge<T>() -> Result<HeapCharge, NetNsError> {
    let bytes = arc_charge_bytes::<T>().map_err(|_| NetNsError::OutOfMemory)?;
    try_reserve_heap(HeapClass::NetnsConfig, bytes)
        .map_err(|_| NetNsError::OutOfMemory)?
        .commit()
        .map_err(|_| NetNsError::OutOfMemory)
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
        // D3 NETNS-SUBBUDGET-1: root gets the same ceiling as children —
        // no exemption, so a root-ns dataplane leak is bounded identically.
        let config_budget = Arc::new(mm::NsByteBudget::new(NETNS_CONFIG_BUDGET_BYTES));
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
            arp_cache: Arc::new(Mutex::new(ArpCache::with_defaults_budgeted(
                mm::HeapClass::NetnsConfig,
                Arc::clone(&config_budget),
            ))),
            config_budget,
            // D3 NETNS-CONFIG: root NEVER stores a config here — the
            // ns_net_config hook delegates ns 0 to the net crate's global
            // config (single authority, see the field doc).
            net_config: Mutex::new(None),
            _arc_heap_charge: None,
        }
    }

    /// Create a new child namespace.
    ///
    /// Child namespaces start with only a loopback interface.
    /// Physical devices must be explicitly moved into child namespaces.
    ///
    /// # R77-5 FIX
    ///
    /// Uses `NsCountGuard` to own the global namespace count until a concrete
    /// `NetNamespace` exists; ownership then transfers to `NetNamespace::drop`.
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

        // R186-3 FIX: every allocation on this path is fallible. The count guard
        // owns rollback until a concrete NetNamespace exists; its Drop owns
        // rollback from that point through registry publication.
        //
        // Before, `Arc::new` (three times) and `BTreeMap::insert` were infallible:
        // an unprivileged `CLONE_NEWUSER|CLONE_NEWNET` under memory pressure
        // reached the allocator's panic handler instead of returning ENOMEM.
        // `MAX_NET_NS_COUNT` did not prevent this — it bounds how MANY namespaces
        // exist, not how many BYTES each one needs.
        //
        // Ordering: allocate subordinate objects, construct the namespace,
        // transfer count ownership to its Drop, then publish the weak registry
        // row. Every failure therefore has exactly one rollback owner.

        // D3 NETNS-SUBBUDGET-1: per-child config budget, created before the
        // child so the cache can hold its clone from birth.
        let config_budget_charge = reserve_netns_arc_charge::<mm::NsByteBudget>()?;
        let config_budget = Arc::try_new(
            mm::NsByteBudget::new(NETNS_CONFIG_BUDGET_BYTES)
                .retain_arc_heap_charge(config_budget_charge),
        )
        .map_err(|_| NetNsError::OutOfMemory)?;

        // D3-NETNS-DATAPLANE: bounded per-ns cache (256 entries), entry storage
        // dual-leased against the NetnsConfig class ceiling AND this namespace's
        // config budget.
        let arp_cache_charge = reserve_netns_arc_charge::<Mutex<ArpCache>>()?;
        let arp_cache = Arc::try_new(Mutex::new(
            ArpCache::with_defaults_budgeted(
                mm::HeapClass::NetnsConfig,
                Arc::clone(&config_budget),
            )
            .retain_arc_heap_charge(arp_cache_charge),
        ))
        .map_err(|_| NetNsError::OutOfMemory)?;

        let namespace_charge = reserve_netns_arc_charge::<NetNamespace>()?;

        let child = Self {
            id: NamespaceId::new(id),
            parent: Some(parent.clone()),
            level: parent.level.saturating_add(1),
            refcount: AtomicU32::new(1),
            devices: RwLock::new(BTreeSet::new()), // Empty - only loopback
            has_loopback: true,
            arp_cache,
            config_budget,
            // D3 NETNS-CONFIG: children are born UNCONFIGURED — TX fails
            // closed (LinkDown) until set_net_config gives this namespace
            // its own identity. No inherited addressing: inheriting the
            // parent's IP/MAC is exactly the identity-borrowing class the
            // per-ns config exists to close.
            net_config: Mutex::new(None),
            _arc_heap_charge: Some(namespace_charge),
        };

        // Count ownership transfers to NetNamespace::drop before Arc allocation.
        // Arc::try_new drops its input on OOM, so keeping the guard armed across
        // that call would decrement once from NetNamespace::drop and once again
        // from NsCountGuard::drop. From this point every failure drops `child`,
        // which performs the one authoritative rollback.
        count_guard.commit();
        let child = Arc::try_new(child).map_err(|_| NetNsError::OutOfMemory)?;

        // D1-ISO-NETNS-DATAPLANE FIX: publish the id -> namespace row consumed
        // by the TX device-ownership gate. Weak: the registry must never keep a
        // dead namespace alive; the matching remove is in Drop.
        //
        // R186-3: fallible insert. On failure the row is absent and `child`
        // drops, rolling the namespace count back exactly once.
        if NET_NS_BY_ID
            .write()
            .try_insert(id, Arc::downgrade(&child))
            .is_err()
        {
            return Err(NetNsError::OutOfMemory);
        }

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

    /// D3 NETNS-SUBBUDGET-1: shared handle to this namespace's config byte
    /// budget. Same capability the namespace's own consumers hold — used
    /// for observability (`snapshot`) and by future budgeted config state
    /// (routing tables, firewall stores). Holding it across namespace
    /// destruction is safe: `Drop` only closes the budget to NEW leases.
    ///
    /// CAPABILITY CONTRACT (round-6 review): the returned `Arc` carries
    /// accounting authority (`try_lease`) and close authority (`close`).
    /// Kernel-internal only — never derivable from a user-controlled
    /// surface. Pass it ONLY to consumers owned by THIS namespace; charging
    /// another namespace's state against it mis-attributes consumption
    /// (accounting confusion / per-ns DoS) even though neither ledger can
    /// be corrupted and the shared class ceiling still binds.
    #[inline]
    pub fn config_budget(&self) -> Arc<mm::NsByteBudget> {
        Arc::clone(&self.config_budget)
    }

    /// D3 NETNS-CONFIG: this namespace's stored addressing, or `None` when
    /// unconfigured. Root always reads `None` here — its authority is the
    /// net crate's global config (see the field doc); the `ns_net_config`
    /// hook performs that delegation, so dataplane callers never see the
    /// asymmetry. `Copy` snapshot out from under a leaf mutex; no lock is
    /// held across the return.
    #[inline]
    pub fn net_config(&self) -> Option<net::NetConfigSnapshot> {
        *self.net_config.lock()
    }

    /// D3 NETNS-CONFIG: configure (or reconfigure) this CHILD namespace's
    /// addressing. This is the seam the future netns-admin syscall will
    /// call — validation therefore lives HERE, not at the (future) ABI
    /// layer (Codex round-9 Q4: validate before it becomes a syscall seam).
    ///
    /// # Validation (fail-closed, all checks precede any state change)
    ///
    /// - Child namespaces only — root's authority is the global config
    ///   ([`NetConfigError::RootImmutable`]).
    /// - `subnet_prefix_len` in 1..=32.
    /// - Source and gateway MACs: concrete unicast (zero = the root-only
    ///   autodetect state; I/G-bit addresses can never source a frame).
    /// - Source and gateway IPs: prefix-independent validity
    ///   (`is_configurable_host_ip` — broadcast/multicast/unspecified/
    ///   loopback/0-net) plus the EXACT subnet-relative network/
    ///   directed-broadcast rejection for /1../30 below. The wire path's
    ///   prefix-blind .255 heuristic is deliberately not used here
    ///   (round-11: it would block RFC 3021 /31 endpoints and mid-subnet
    ///   .255 hosts that are genuinely valid for the configured prefix).
    /// - Gateway distinct from the source and ON the configured subnet —
    ///   no routing module exists this slice, so an off-link gateway could
    ///   never be reached.
    ///
    /// # Reconfiguration semantics
    ///
    /// On success the namespace's ARP cache is cleared — static AND
    /// dynamic: every prior mapping was learned under the old addressing,
    /// and the static gateway seed maps the OLD gateway. Reconfiguration
    /// is NOT a quiescence barrier: a send that already acquired its
    /// config snapshot completes with the old identity, bounded by one
    /// in-flight send (the same envelope as the move_device TX-revocation
    /// contract).
    ///
    /// # Lock context
    ///
    /// Takes the config mutex, releases it, THEN takes the ARP-cache mutex
    /// — strictly sequential leaf locks, never nested.
    pub fn set_net_config(&self, cfg: net::NetConfigSnapshot) -> Result<(), NetConfigError> {
        if self.level == 0 {
            return Err(NetConfigError::RootImmutable);
        }
        if cfg.subnet_prefix_len == 0 || cfg.subnet_prefix_len > 32 {
            return Err(NetConfigError::InvalidPrefix);
        }
        if !is_configurable_unicast_mac(cfg.our_mac) {
            return Err(NetConfigError::InvalidSourceMac);
        }
        if !is_configurable_unicast_mac(cfg.gateway_mac) {
            return Err(NetConfigError::InvalidGatewayMac);
        }
        // Round-11: prefix-independent validity only — the exact
        // subnet-relative check below owns broadcast/network rejection
        // (the wire path's prefix-blind .255 heuristic would wrongly
        // block RFC 3021 /31 endpoints and mid-subnet .255 hosts).
        if !is_configurable_host_ip(cfg.our_ip) {
            return Err(NetConfigError::InvalidSourceIp);
        }
        if !is_configurable_host_ip(cfg.gateway_ip) {
            return Err(NetConfigError::InvalidGatewayIp);
        }
        if cfg.gateway_ip == cfg.our_ip {
            return Err(NetConfigError::GatewayIsSelf);
        }
        // On-link check. Prefix is 1..=32 here, so the shift is 0..=31 —
        // never the undefined 32-bit shift.
        let mask: u32 = u32::MAX << (32 - u32::from(cfg.subnet_prefix_len));
        let our = u32::from_be_bytes(cfg.our_ip.octets());
        let gw = u32::from_be_bytes(cfg.gateway_ip.octets());
        if (our ^ gw) & mask != 0 {
            return Err(NetConfigError::GatewayOffSubnet);
        }
        // D3 round-10 FIX: prefix-relative validation — `is_valid_source`
        // has no prefix, so it cannot see subnet-specific special
        // addresses (e.g. 10.83.0.63/26 is a directed broadcast and
        // 10.83.0.0/26 a network address, both generically "valid"). For
        // ordinary subnets (/1../30) the all-zeros host part is the
        // network address and the all-ones host part the directed
        // broadcast — neither is a host. /31 (RFC 3021 point-to-point:
        // both values ARE hosts) and /32 are deliberately exempt.
        if cfg.subnet_prefix_len <= 30 {
            let host_mask = !mask;
            let our_host = our & host_mask;
            if our_host == 0 || our_host == host_mask {
                return Err(NetConfigError::InvalidSourceIp);
            }
            let gw_host = gw & host_mask;
            if gw_host == 0 || gw_host == host_mask {
                return Err(NetConfigError::InvalidGatewayIp);
            }
        }

        {
            *self.net_config.lock() = Some(cfg);
        }
        // Reconfiguration flush (config mutex already released; see the
        // lock-context doc). Capacity and its budget charge are retained.
        // A bounded in-flight send from the OLD configuration generation
        // may re-seed the old gateway mapping after this flush — that is
        // self-healing, not persistent: every send re-asserts its own
        // snapshot's gateway via ArpCache::seed_static_gateway (round-10).
        // D3 PENDING-FRAME v2: parked frames embed the old identity — the
        // flush RETURNS them and their heap-releasing drop runs strictly
        // after the cache mutex (the guard is a temporary that ends with
        // the statement).
        let flushed = self.arp_cache.lock().clear_all();
        drop(flushed);
        Ok(())
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
    let has_cap_admin = crate::process::current_has_cap_rights(cap::CapRights::ADMIN);
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
        // D3 NETNS-SUBBUDGET-1: a dying namespace stops admitting config
        // bytes immediately. close() only blocks NEW leases — outstanding
        // ones (e.g. an ARP cache Arc still held by an in-flight RX path)
        // release when their allocations really drop, so usage stays
        // truthful and the class ledger never double-releases. Lock-free
        // atomic store: safe in this arbitrary drop context. (Root is
        // immortal — a static Arc — so this fires for children only.)
        self.config_budget.close();
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
    fn clone_box(&self) -> Result<FileDescriptor, ()> {
        self.try_clone_box()
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
