//! Zero-OS Network Primitives
//!
//! This crate provides core networking infrastructure for Zero-OS, including:
//! - DMA-compatible packet buffers with headroom/tailroom support
//! - Buffer pools for efficient packet allocation
//! - Network device trait abstraction (future)
//!
//! # Design
//!
//! Network buffers are designed for zero-copy DMA operations:
//! - Physical addresses are tracked for device DMA
//! - Headroom allows prepending protocol headers without copying
//! - Tailroom allows appending trailers (checksums, padding)
//!
//! # Example
//!
//! ```ignore
//! let pool = BufPool::new(64); // Preallocate 64 buffers
//! let mut buf = pool.alloc().expect("out of buffers");
//!
//! // Receive data into buffer
//! let data = buf.push_tail(1500).unwrap();
//! // ... DMA fills data ...
//!
//! // Process and prepend header
//! let hdr = buf.push_head(14).unwrap(); // Ethernet header
//! hdr.copy_from_slice(&eth_header);
//! ```

#![no_std]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::unusual_byte_groupings)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::new_without_default)]
#![allow(clippy::manual_inspect)]
#![allow(clippy::type_complexity)]
#![allow(clippy::result_unit_err)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::manual_strip)]
#![allow(clippy::comparison_chain)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::needless_return)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::missing_safety_doc)]
#![allow(dead_code)]
#![allow(clippy::bool_comparison)]
#![allow(clippy::result_large_err)]
#![allow(clippy::unreachable)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::ptr_arg)]
#![allow(unused_assignments)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::question_mark)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::manual_abs_diff)]
#![allow(clippy::len_zero)]
#![allow(clippy::misnamed_getters)]
#![allow(clippy::drop_non_drop)]
#![allow(unused_variables)]
#![allow(clippy::nonminimal_bool)]
#![allow(unreachable_patterns)]
#![allow(clippy::doc_overindented_list_items)]
// R180-11: Arc::try_new for fallible socket publication.
#![feature(allocator_api)]

extern crate alloc;
extern crate security;
#[macro_use]
extern crate klog;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

mod admitted;
use spin::{Mutex, Once, RwLock};
use x86_64::{PhysAddr, VirtAddr};

pub mod arp;
pub mod buffer;
pub mod conntrack;
pub mod device;
pub mod ethernet;
pub mod firewall;
pub mod fragment;
pub mod icmp;
pub mod ipv4;
mod pci;
pub mod socket;
pub mod stack;
pub mod tcp;
pub mod udp;
pub mod virtio_net;

pub use admitted::WirePacket;

pub use arp::{
    build_arp_reply, build_arp_request, build_gratuitous_arp, parse_arp, process_arp,
    serialize_arp, ArpCache, ArpEntry, ArpEntryKind, ArpError, ArpOp, ArpPacket, ArpResult,
    ArpStats, PendingFrameCounters, ARP_RX_RATE_LIMITER, ARP_TX_RATE_LIMITER, PENDING_FRAME_SLOTS,
    PENDING_FRAME_TTL_MS,
};
pub use buffer::{BufPool, NetBuf};
pub use device::{
    DeviceCaps, LinkStatus, MacAddress, NetDevice, NetError, OperatingMode, RxError, TxError,
};
pub use ethernet::{
    build_ethernet_frame, parse_ethernet, try_build_ethernet_frame_from_parts, EthAddr, EthError,
    EthHeader, ETHERTYPE_ARP, ETHERTYPE_IPV4,
};
pub use firewall::{
    firewall_default_rules, firewall_remove_ns, firewall_table, firewall_table_for_ns, log_match,
    try_firewall_table_for_ns, CtStateMask, FirewallAction, FirewallPacket, FirewallRule,
    FirewallRuleBuilder, FirewallStats, FirewallStatsSnapshot, FirewallTable, FirewallVerdict,
    IpCidrMatch, PortRange,
};
pub use fragment::{
    cleanup_expired_fragments, fragment_cache, process_fragment, FragmentCache, FragmentDropReason,
    FragmentKey, FragmentStats, FRAG_TIMEOUT_MS, MAX_FRAGS_PER_QUEUE, MAX_PACKET_SIZE,
};
pub use icmp::{
    build_dest_unreachable_limited, build_echo_reply, build_time_exceeded_limited, parse_icmp,
    IcmpError, IcmpHeader, TokenBucket, ICMP_RATE_LIMITER, ICMP_TYPE_DEST_UNREACHABLE,
    ICMP_TYPE_ECHO_REPLY, ICMP_TYPE_ECHO_REQUEST, ICMP_TYPE_TIME_EXCEEDED,
};
pub use ipv4::{
    build_ipv4_header, compute_checksum, parse_ipv4, try_build_ipv4_header, Ipv4Addr, Ipv4Error,
    Ipv4Header, Ipv4Proto,
};
pub use socket::{
    register_cgroup_port_hooks, register_netns_device_hooks, register_socket_wait_hooks,
    socket_table, BindCharge, CgroupPortHooks, NetNsDeviceHooks, PendingDatagram,
    RecvTransactionError, SerializedTcpPacket, SockPollReadiness, SocketArc, SocketArcAllocator,
    SocketDomain, SocketError, SocketLabel, SocketProtocol, SocketState, SocketStats, SocketTable,
    SocketType, SocketWaitHooks, TableStats, TcpConnectResult, WaitOutcome, WaitQueue,
    WaitQueueArc,
};
pub use stack::{
    drain_parked_ready, handle_timer_tick, network_config, next_hop, prepare_arp_probe,
    process_frame, quiesce_rx_ingress_background, resolve_dst_mac, rx_ingress_counters,
    rx_ingress_net_stats, rx_ingress_poll, rx_ingress_poll_filtered, rx_ingress_poll_throttled,
    rx_ingress_pool_stats, transmit_prepared_reply, transmit_tcp_connect, transmit_tcp_segment,
    transmit_udp_datagram, tx_net_config, DropReason, NetConfigSnapshot, NetStats, NextHop,
    PreparedReply, PreparedReplyTxError, ProcessResult, RxIngressCounters, RxIngressQuiesceGuard,
    RxPoolStats, RX_BUF_POOL_SIZE, RX_DEVICE_OUTSTANDING_CAP, RX_INGRESS_POLL_BUDGET,
};
pub use tcp::{
    build_tcp_segment, build_tcp_segment_with_options, calc_wscale, compute_tcp_checksum,
    decode_window, encode_window, generate_isn, generate_syn_cookie_isn, handle_ack,
    handle_retransmission_timeout, initial_cwnd, parse_tcp_header, parse_tcp_options, seq_ge,
    seq_gt, seq_in_window, seq_le, seq_lt, serialize_tcp_option, serialize_tcp_options,
    syn_cookie_select_mss, try_build_tcp_segment, try_build_tcp_segment_with_options,
    try_compute_tcp_checksum, update_congestion_control, update_rtt, validate_cwnd_after_idle,
    validate_syn_cookie, verify_tcp_checksum, AckUpdate, CongestionAction, SynCookieData,
    TcpCongestionState, TcpConnKey, TcpControlBlock, TcpError, TcpHeader, TcpOptionKind,
    TcpOptions, TcpResult, TcpSegment, TcpState, TcpStats, TCP_DEFAULT_MSS,
    TCP_DEFAULT_RCV_WINDOW_BYTES, TCP_DEFAULT_WINDOW, TCP_ETHERNET_MSS, TCP_FIN_TIMEOUT_MS,
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG,
    TCP_HEADER_MAX_LEN, TCP_HEADER_MIN_LEN, TCP_INITIAL_SSTHRESH, TCP_MAX_ACCEPT_BACKLOG,
    TCP_MAX_FIN_RETRIES, TCP_MAX_RETRIES, TCP_MAX_RTO_MS, TCP_MAX_SCALED_WINDOW, TCP_MAX_SEND_SIZE,
    TCP_MAX_SYN_BACKLOG, TCP_MAX_WINDOW_SCALE, TCP_PROTO, TCP_SYN_COOKIE_MAX_AGE_MS,
    TCP_SYN_COOKIE_MSS_TABLE, TCP_TIME_WAIT_MS,
};
pub use udp::{
    build_udp_datagram, compute_udp_checksum, parse_udp, parse_udp_header, verify_udp_checksum,
    UdpError, UdpHeader, UdpResult, UdpStats, UDP_HEADER_LEN, UDP_PROTO,
};
pub use virtio_net::VirtioNetDevice;

// ============================================================================
// Network Constants
// ============================================================================

/// Default Maximum Transmission Unit for Ethernet payloads.
pub const DEFAULT_MTU: usize = 1500;

/// Default headroom reserved for protocol headers (Ethernet + IP + TCP/UDP).
/// 14 (Ethernet) + 20 (IP) + 20 (TCP) = 54, rounded up to 64 for alignment.
pub const DEFAULT_HEADROOM: usize = 64;

/// Default tailroom reserved for trailers (checksums, padding, VLAN tags).
pub const DEFAULT_TAILROOM: usize = 64;

/// Size of the VirtIO network header prepended by virtio-net devices.
/// This header contains checksum and segmentation offload information.
pub const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Ethernet header size (6 dst + 6 src + 2 ethertype).
pub const ETH_HEADER_SIZE: usize = 14;

/// Minimum Ethernet frame size (excluding FCS).
pub const ETH_MIN_FRAME_SIZE: usize = 60;

/// Maximum Ethernet frame size (excluding FCS, including header).
pub const ETH_MAX_FRAME_SIZE: usize = 1514;

/// Maximum number of network devices supported.
pub const MAX_NET_DEVICES: usize = 8;

// ============================================================================
// Network Device Registry
// ============================================================================

/// Handle type for registered network devices.
///
/// D1-ISO-NETNS-DATAPLANE: demoted to `pub(crate)` so a transmit-capable device
/// handle can NEVER egress the `net` crate. The only sanctioned way to reach the
/// driver `transmit` is via `stack::tx_auth::AuthorizedTxDevice`, minted by the
/// namespace-gated resolver. (No out-of-crate user existed.)
/// D3-NETNS-DATAPLANE RX-INGRESS: the only sanctioned way to reach the driver
/// `receive` is likewise `stack::rx_auth::AuthorizedRxDevice` — raw handles stay
/// confined to those two audited in-crate resolvers.
pub(crate) type NetDeviceHandle = Arc<Mutex<Box<dyn NetDevice>>>;

/// A registered network device entry.
struct RegisteredDevice {
    name: String,
    index: usize,
    device: NetDeviceHandle,
}

/// Global network device registry.
struct NetDeviceRegistry {
    devices: RwLock<Vec<RegisteredDevice>>,
    next_index: AtomicUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryAllocationPoint {
    DeviceName,
    DeviceVector,
}

impl NetDeviceRegistry {
    fn new() -> Self {
        Self {
            devices: RwLock::new(Vec::new()),
            next_index: AtomicUsize::new(0),
        }
    }

    fn register_handle(&self, device: NetDeviceHandle) -> Result<usize, NetError> {
        self.register_handle_with_fault(device, |_| false)
    }

    /// Single implementation of registry publication, with a private fault
    /// boundary used by deterministic rollback tests. Production always passes
    /// a closure that returns false, which is inlined away.
    fn register_handle_with_fault(
        &self,
        device: NetDeviceHandle,
        mut fail_allocation: impl FnMut(RegistryAllocationPoint) -> bool,
    ) -> Result<usize, NetError> {
        let mut name = String::new();
        {
            let guard = device.lock();
            if fail_allocation(RegistryAllocationPoint::DeviceName) {
                return Err(NetError::NoMemory);
            }
            name.try_reserve_exact(guard.name().len())
                .map_err(|_| NetError::NoMemory)?;
            name.push_str(guard.name());
        }

        let mut devices = self.devices.write();

        if devices.len() >= MAX_NET_DEVICES {
            return Err(NetError::InvalidState);
        }

        if devices.iter().any(|d| d.name == name) {
            return Err(NetError::InvalidConfig);
        }

        if fail_allocation(RegistryAllocationPoint::DeviceVector) {
            return Err(NetError::NoMemory);
        }
        devices.try_reserve(1).map_err(|_| NetError::NoMemory)?;

        let index = self.next_index.fetch_add(1, Ordering::SeqCst);

        devices.push(RegisteredDevice {
            name,
            index,
            device,
        });

        Ok(index)
    }

    /// D1-ISO-NETNS-DATAPLANE FIX: resolve a device together with its stable
    /// registry index in ONE read-lock critical section, so ownership gating
    /// checks the SAME device object the caller will transmit on (no
    /// name→handle / name→index split-lookup drift).
    fn get_by_name_with_index(&self, name: &str) -> Option<(NetDeviceHandle, usize)> {
        let devices = self.devices.read();
        devices
            .iter()
            .find(|d| d.name == name)
            .map(|d| (d.device.clone(), d.index))
    }

    /// D3-NETNS-DATAPLANE RX-INGRESS: snapshot every registered device handle in
    /// ONE read-lock critical section. Registration order is preserved and the
    /// registry lock is released before ANY per-device mutex is taken (the RX
    /// poll must never nest device locks under the registry lock — root
    /// `network_config()` re-enters this registry for its lazy MAC autodetect).
    /// Heap-free: registration is capped at `MAX_NET_DEVICES`, so a fixed array
    /// suffices and the poll path allocates nothing.
    fn snapshot_handles(&self) -> ([Option<NetDeviceHandle>; MAX_NET_DEVICES], usize) {
        let devices = self.devices.read();
        let mut out: [Option<NetDeviceHandle>; MAX_NET_DEVICES] = [const { None }; MAX_NET_DEVICES];
        let mut count = 0;
        for entry in devices.iter().take(MAX_NET_DEVICES) {
            out[count] = Some(entry.device.clone());
            count += 1;
        }
        (out, count)
    }

    fn count(&self) -> usize {
        self.devices.read().len()
    }

    fn list(&self) -> Vec<String> {
        let devices = self.devices.read();
        devices.iter().map(|d| d.name.clone()).collect()
    }
}

static NET_REGISTRY: Once<NetDeviceRegistry> = Once::new();

#[inline]
fn registry() -> &'static NetDeviceRegistry {
    NET_REGISTRY.call_once(NetDeviceRegistry::new)
}

/// Register a network device in the global registry.
pub fn register_device<D: NetDevice + 'static>(device: D) -> Result<usize, NetError> {
    let boxed: Box<dyn NetDevice> = Box::try_new(device).map_err(|_| NetError::NoMemory)?;
    let handle = Arc::try_new(Mutex::new(boxed)).map_err(|_| NetError::NoMemory)?;
    registry().register_handle(handle)
}

/// D1-ISO-NETNS-DATAPLANE: resolve (handle, stable index) for the SOLE sanctioned
/// consumer — `stack::tx_auth::resolve_authorized_tx_device`. Demoted to
/// `pub(crate)` and contract-pinned: a transmit-capable handle may egress the
/// registry ONLY into that resolver (or the tx_auth host tests). Adding any other
/// NON-TEST caller re-opens the ungated-TX bypass this closes — treat as a
/// security regression (grep gate: exactly one non-test caller). The RX side has
/// its OWN sibling seam below (`rx_device_handles`) with its own one-caller gate;
/// do NOT widen this one for ingress.
pub(crate) fn get_device_with_index(name: &str) -> Option<(NetDeviceHandle, usize)> {
    registry().get_by_name_with_index(name)
}

/// D3-NETNS-DATAPLANE RX-INGRESS: snapshot ALL registered device handles for the
/// SOLE sanctioned consumer — `stack::rx_auth::resolve_rx_devices`. Contract-pinned
/// exactly like `get_device_with_index` above: a device handle may egress the
/// registry ONLY into the rx_auth resolver, which wraps it in a poll-scoped
/// receive-only capability. Adding any other NON-TEST caller re-opens the
/// raw-device-handle bypass the tx_auth/rx_auth split closes — treat as a
/// security regression (grep gate: exactly one non-test caller).
pub(crate) fn rx_device_handles() -> ([Option<NetDeviceHandle>; MAX_NET_DEVICES], usize) {
    registry().snapshot_handles()
}

/// D1-ISO-NETNS-DATAPLANE: metadata-only MAC accessor. Returns the device MAC
/// WITHOUT handing out a transmit-capable handle (transmit authority and metadata
/// reads are now distinct capabilities). The registry read-lock is released before
/// the per-device Mutex is taken (never nested).
pub(crate) fn device_mac(name: &str) -> Option<[u8; 6]> {
    let handle = registry().get_by_name_with_index(name)?.0;
    let mac = handle.lock().mac_address();
    Some(mac)
}

/// D1-ISO-NETNS-DATAPLANE: metadata-only stable-registry-index accessor. The
/// index is an EPHEMERAL IDENTIFIER for diagnostics/tests (it is what the
/// per-namespace ownership sets key on), NOT a capability: holding an index
/// grants no transmit authority — the tx_auth resolver re-derives (handle,
/// index) in one registry critical section and performs the ownership check
/// itself.
pub fn device_index(name: &str) -> Option<usize> {
    registry()
        .get_by_name_with_index(name)
        .map(|(_, index)| index)
}

/// One coherent TX-side stats snapshot of a registered device (numbers only,
/// never a handle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceTxStats {
    /// Packets whose transmission COMPLETED (drivers increment this at
    /// descriptor reclaim, not at enqueue).
    pub tx_packets: u64,
    /// Driver-reported TX errors.
    pub tx_errors: u64,
    /// Free TX descriptor slots, in whole-packet units.
    pub tx_queue_space: usize,
}

/// D1-ISO-NETNS-DATAPLANE: metadata-only TX-stats accessor for diagnostics and
/// the `net_ns_tx_isolation` boot test.
///
/// Lock contract: clones the device Arc under the registry read lock, RELEASES
/// it, then takes the per-device Mutex for ONE coherent three-field snapshot
/// (registry and device locks are never nested). Callers must not hold locks
/// that rank below the per-device (Level-8) lock.
pub fn device_tx_stats(name: &str) -> Option<DeviceTxStats> {
    let handle = registry().get_by_name_with_index(name)?.0;
    let device = handle.lock();
    Some(DeviceTxStats {
        tx_packets: device.tx_packets(),
        tx_errors: device.tx_errors(),
        tx_queue_space: device.tx_queue_space(),
    })
}

/// Get the number of registered devices.
pub fn device_count() -> usize {
    registry().count()
}

/// List names of all registered network devices.
pub fn list_devices() -> Vec<String> {
    registry().list()
}

// ============================================================================
// MMIO Mapping for PCI Devices
// ============================================================================

/// Base virtual address for network MMIO regions.
/// Uses a separate range from block driver to avoid conflicts.
const NET_MMIO_VIRT_BASE: u64 = 0xffff_ffff_5000_0000;

/// Maximum size of the network MMIO virtual address region (64 MB).
const NET_MMIO_VIRT_SIZE: u64 = 64 * 1024 * 1024;

/// Serialized bump allocator. Holding this lock through device probe makes a
/// failed reservation rewindable without racing a later device allocation.
static NET_MMIO_OFFSET: Mutex<u64> = Mutex::new(0);

#[derive(Clone, Copy, Debug, Default)]
struct MmioPageWindow {
    phys: u64,
    len: usize,
}

struct PciMmioMapping {
    allocator: Option<spin::MutexGuard<'static, u64>>,
    reservation_start: u64,
    phys_anchor: u64,
    virt_anchor: u64,
    windows: [MmioPageWindow; 4],
    window_count: usize,
    virt_offset: u64,
    committed: bool,
    #[cfg(test)]
    lifecycle_log: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl PciMmioMapping {
    fn commit(mut self) {
        self.committed = true;
        drop(self.allocator.take());
        #[cfg(test)]
        self.record_lifecycle("mapping-commit");
    }

    /// Preserve VA/PTE ownership for hardware whose DMA quiescence is not
    /// proven, while releasing allocator serialization for later devices.
    fn quarantine(mut self) {
        self.committed = true;
        drop(self.allocator.take());
        #[cfg(test)]
        self.record_lifecycle("mapping-quarantine");
    }

    #[cfg(test)]
    fn record_lifecycle(&self, event: &'static str) {
        if let Some(log) = &self.lifecycle_log {
            log.lock().push(event);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnpublishedRollbackProof {
    reset_acked: bool,
    contained: bool,
}

impl UnpublishedRollbackProof {
    #[inline]
    const fn ownership_can_be_released(self) -> bool {
        self.reset_acked && self.contained
    }
}

/// Ready PCI device not yet published in the global registry. Drop is the sole
/// rollback authority: it proves reset + command-bit containment before freeing
/// DMA or unmapping MMIO, otherwise quarantines both owners.
struct ProbedPciNetDevice {
    slot: pci::PciSlot,
    device: Option<NetDeviceHandle>,
    mapping: Option<PciMmioMapping>,
    #[cfg(test)]
    containment_hook: Option<Arc<dyn Fn(&pci::PciSlot) -> bool + Send + Sync>>,
}

impl ProbedPciNetDevice {
    fn new(slot: pci::PciSlot, device: NetDeviceHandle, mapping: PciMmioMapping) -> Self {
        Self {
            slot,
            device: Some(device),
            mapping: Some(mapping),
            #[cfg(test)]
            containment_hook: None,
        }
    }

    fn handle(&self) -> NetDeviceHandle {
        Arc::clone(self.device.as_ref().expect("probed net device committed"))
    }

    fn commit(mut self) {
        if let Some(mapping) = self.mapping.take() {
            mapping.commit();
        }
        drop(
            self.device
                .take()
                .expect("probed net device committed twice"),
        );
    }

    #[cfg(test)]
    fn with_containment_hook(
        mut self,
        hook: Arc<dyn Fn(&pci::PciSlot) -> bool + Send + Sync>,
    ) -> Self {
        self.containment_hook = Some(hook);
        self
    }

    #[inline]
    fn contain_pci_command(&self) -> bool {
        #[cfg(test)]
        if let Some(hook) = &self.containment_hook {
            return hook(&self.slot);
        }
        pci::try_disable_memory_and_bus_master(&self.slot)
    }

    /// Consume every unpublished owner according to the reset/readback proof.
    /// The safe path drops the device before MMIO is unmapped. Either failed
    /// proof quarantines both owners and releases only allocator serialization.
    fn rollback_owners(&mut self) -> Option<UnpublishedRollbackProof> {
        let device = self.device.take()?;
        assert!(
            self.mapping.is_some(),
            "RF186-4: unpublished PCI device lost its MMIO rollback owner"
        );

        let reset_acked = device.lock().rollback_unpublished();
        let contained = self.contain_pci_command();
        let proof = UnpublishedRollbackProof {
            reset_acked,
            contained,
        };

        if proof.ownership_can_be_released() {
            // The final DMA owner must die before its register mapping is
            // removed. This ordering is explicit rather than relying on field
            // drop order after `Drop::drop` returns.
            drop(device);
            drop(
                self.mapping
                    .take()
                    .expect("unpublished PCI device MMIO rollback owner"),
            );
        } else {
            // Losing either proof forbids releasing DMA-backed ownership or
            // unmapping registers. Keep both alive, but never retain the global
            // MMIO allocator mutex while a device is quarantined.
            core::mem::forget(device);
            self.mapping
                .take()
                .expect("unpublished PCI device MMIO quarantine owner")
                .quarantine();
        }

        Some(proof)
    }
}

impl Drop for ProbedPciNetDevice {
    fn drop(&mut self) {
        let Some(proof) = self.rollback_owners() else {
            return;
        };
        if proof.ownership_can_be_released() {
            return;
        }
        // RF186-21 FIX: the forced kernel logger performs VGA/serial I/O that
        // is valid in the kernel but faults in the hosted `cargo test`
        // process before `catch_unwind` can observe the fail-stop panic.
        // Suppress only that diagnostic in the crate's host-test build; real
        // kernel builds retain the log, and quarantine plus panic semantics
        // remain identical in every build.
        #[cfg(not(test))]
        klog_force!(
            "RF186-4: virtio-net {:02x}:{:02x}.{} rollback reset_acked={} contained={}; quarantined device and MMIO ownership",
            self.slot.bus,
            self.slot.device,
            self.slot.function,
            proof.reset_acked,
            proof.contained
        );
        if !proof.contained {
            panic!("RF186-4: PCI network device refused MSE/BME containment");
        }
    }
}

/// Registry insertion is the final fallible publication step. Returning an
/// error drops the still-armed probe guard; success immediately disarms it.
fn publish_probed_pci_device(
    registry: &NetDeviceRegistry,
    probed: ProbedPciNetDevice,
) -> Result<usize, NetError> {
    publish_probed_pci_device_with_fault(registry, probed, |_| false)
}

fn publish_probed_pci_device_with_fault(
    registry: &NetDeviceRegistry,
    probed: ProbedPciNetDevice,
    fail_allocation: impl FnMut(RegistryAllocationPoint) -> bool,
) -> Result<usize, NetError> {
    let index = registry.register_handle_with_fault(probed.handle(), fail_allocation)?;
    probed.commit();
    Ok(index)
}

fn rollback_inactive_pci_mapping(slot: &pci::PciSlot, mapping: PciMmioMapping) {
    if pci::try_disable_memory_and_bus_master(slot) {
        drop(mapping);
        return;
    }
    mapping.quarantine();
    panic!(
        "RF186-4: inactive PCI network probe refused MSE/BME containment at {:02x}:{:02x}.{}",
        slot.bus, slot.device, slot.function
    );
}

impl Drop for PciMmioMapping {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut frame_allocator = mm::FrameAllocator::new();
        for window in self.windows[..self.window_count].iter().rev() {
            let virt = self
                .virt_anchor
                .checked_add(window.phys - self.phys_anchor)
                .expect("validated virtio-net MMIO reservation overflowed");
            unsafe {
                mm::unmap_mmio(VirtAddr::new(virt), window.len, &mut frame_allocator)
                    .unwrap_or_else(|_| panic!("RF186-4: virtio-net MMIO rollback failed"));
            }
        }
        if let Some(mut offset) = self.allocator.take() {
            *offset = self.reservation_start;
            drop(offset);
        }
        #[cfg(test)]
        self.record_lifecycle("mapping-release");
    }
}

fn merged_mmio_windows(
    addrs: &virtio::VirtioPciAddrs,
) -> Result<([MmioPageWindow; 4], usize), NetError> {
    let declared = [addrs.common_cfg, addrs.notify, addrs.isr, addrs.device_cfg];
    let mut pages = [MmioPageWindow::default(); 4];
    let mut count = 0usize;
    for authority in declared {
        if !authority.is_present() {
            continue;
        }
        let (page_start, page_len) = authority.page_cover().ok_or(NetError::NotSupported)?;
        mm::checked_physical_range(page_start, page_len).ok_or(NetError::NotSupported)?;
        let page_len = usize::try_from(page_len)
            .ok()
            .filter(|value| *value != 0)
            .ok_or(NetError::NotSupported)?;
        pages[count] = MmioPageWindow {
            phys: page_start,
            len: page_len,
        };
        count += 1;
    }
    if count == 0 {
        return Err(NetError::NotSupported);
    }
    for left in 0..count {
        for right in (left + 1)..count {
            if pages[right].phys < pages[left].phys {
                pages.swap(left, right);
            }
        }
    }
    let mut merged = [MmioPageWindow::default(); 4];
    let mut merged_count = 0usize;
    for window in pages[..count].iter().copied() {
        if merged_count != 0 {
            let previous = &mut merged[merged_count - 1];
            let previous_end = previous
                .phys
                .checked_add(previous.len as u64)
                .ok_or(NetError::NotSupported)?;
            if window.phys <= previous_end {
                let window_end = window
                    .phys
                    .checked_add(window.len as u64)
                    .ok_or(NetError::NotSupported)?;
                previous.len = usize::try_from(previous_end.max(window_end) - previous.phys)
                    .map_err(|_| NetError::NotSupported)?;
                continue;
            }
        }
        merged[merged_count] = window;
        merged_count += 1;
    }
    Ok((merged, merged_count))
}

/// Map only pages intersecting validated capability windows. The virtual span
/// preserves one uniform physical-to-virtual offset, but physical holes between
/// BAR windows remain unmapped.
unsafe fn map_virtio_pci_regions(
    addrs: &virtio::VirtioPciAddrs,
) -> Result<PciMmioMapping, NetError> {
    let (windows, window_count) = merged_mmio_windows(addrs)?;
    let phys_anchor = windows[0].phys;
    let last = windows[window_count - 1];
    let span_end = last
        .phys
        .checked_add(last.len as u64)
        .ok_or(NetError::NotSupported)?;
    let span = span_end
        .checked_sub(phys_anchor)
        .ok_or(NetError::NotSupported)?;
    let allocator = NET_MMIO_OFFSET.lock();
    let reservation_start = *allocator;
    let reservation_end = reservation_start
        .checked_add(span)
        .filter(|end| *end <= NET_MMIO_VIRT_SIZE)
        .ok_or(NetError::IoError)?;
    let virt_anchor = NET_MMIO_VIRT_BASE
        .checked_add(reservation_start)
        .ok_or(NetError::IoError)?;
    NET_MMIO_VIRT_BASE
        .checked_add(reservation_end)
        .ok_or(NetError::IoError)?;
    let virt_offset = virt_anchor
        .checked_sub(phys_anchor)
        .ok_or(NetError::NotSupported)?;
    let mut transaction = PciMmioMapping {
        allocator: Some(allocator),
        reservation_start,
        phys_anchor,
        virt_anchor,
        windows,
        window_count: 0,
        virt_offset,
        committed: false,
        #[cfg(test)]
        lifecycle_log: None,
    };
    let mut frame_allocator = mm::FrameAllocator::new();
    for window in windows[..window_count].iter().copied() {
        let virt = virt_anchor
            .checked_add(window.phys - phys_anchor)
            .ok_or(NetError::IoError)?;
        let phys = PhysAddr::try_new(window.phys).map_err(|_| NetError::IoError)?;
        let last_phys = window
            .phys
            .checked_add(window.len.saturating_sub(1) as u64)
            .ok_or(NetError::IoError)?;
        PhysAddr::try_new(last_phys).map_err(|_| NetError::IoError)?;
        mm::map_mmio(VirtAddr::new(virt), phys, window.len, &mut frame_allocator).map_err(
            |error| {
                klog!(Error, "      [NET MMIO] mapping failed: {:?}", error);
                NetError::IoError
            },
        )?;
        transaction.windows[transaction.window_count] = window;
        transaction.window_count += 1;
    }
    **transaction
        .allocator
        .as_mut()
        .expect("MMIO allocator guard") = reservation_end;
    Ok(transaction)
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the network subsystem.
///
/// This probes for network devices (currently virtio-net via PCI) and
/// registers them in the global device registry.
///
/// Returns the number of devices successfully initialized.
pub fn init(iommu_required: bool) -> usize {
    klog_always!("  Network subsystem initialized");
    klog_always!("      Probing for network devices...");

    let mut registered = 0;

    // Probe PCI for virtio-net devices (R171-G5-01-C: iommu_required => Secure
    // refuses bus-master for a device that cannot be IOMMU-isolated).
    let pci_devices = pci::probe_virtio_net(iommu_required);

    if pci_devices.is_empty() {
        klog_always!("      No virtio-net devices found");
    } else {
        for (idx, pci_dev) in pci_devices.iter().enumerate() {
            let name = alloc::format!("eth{}", idx);

            // Map the MMIO regions for this device.
            // After security hardening, identity mapping is read-only,
            // so we must create explicit writable mappings.
            let mapping = match unsafe { map_virtio_pci_regions(&pci_dev.addrs) } {
                Ok(mapping) => mapping,
                Err(e) => {
                    // R82-4 FIX: Disable bus mastering on MMIO mapping failure
                    pci::disable_bus_master(&pci_dev.slot);
                    klog!(Error,
                        "      ! MMIO mapping failed for {:02x}:{:02x}.{}: {:?} (bus master disabled)",
                        pci_dev.slot.bus,
                        pci_dev.slot.device,
                        pci_dev.slot.function,
                        e
                    );
                    continue;
                }
            };

            if !pci::enable_memory_space(&pci_dev.slot) {
                rollback_inactive_pci_mapping(&pci_dev.slot, mapping);
                klog!(Error, "      ! virtio-net MSE activation failed");
                continue;
            }

            let virt_offset = mapping.virt_offset;
            let device = match unsafe {
                VirtioNetDevice::probe_pci(pci_dev.addrs, virt_offset, &name)
            } {
                Ok(device) => device,
                Err(e) => {
                    rollback_inactive_pci_mapping(&pci_dev.slot, mapping);
                    klog!(Error,
                        "      ! virtio-net probe @ {:02x}:{:02x}.{} failed: {:?} (MSE/BME disabled)",
                        pci_dev.slot.bus,
                        pci_dev.slot.device,
                        pci_dev.slot.function,
                        e
                    );
                    continue;
                }
            };

            let boxed: Box<dyn NetDevice> = match Box::try_new(device) {
                Ok(device) => device,
                Err(_) => {
                    rollback_inactive_pci_mapping(&pci_dev.slot, mapping);
                    klog!(Error, "      ! virtio-net owner allocation failed");
                    continue;
                }
            };
            let handle = match Arc::try_new(Mutex::new(boxed)) {
                Ok(handle) => handle,
                Err(_) => {
                    rollback_inactive_pci_mapping(&pci_dev.slot, mapping);
                    klog!(Error, "      ! virtio-net shared owner allocation failed");
                    continue;
                }
            };
            let probed = ProbedPciNetDevice::new(pci_dev.slot, handle, mapping);

            if !pci::enable_bus_master(&pci_dev.slot) {
                drop(probed);
                klog!(Error, "      ! virtio-net BME activation failed");
                continue;
            }
            let activation = unsafe { probed.handle().lock().activate_unpublished() };
            if let Err(error) = activation {
                drop(probed);
                klog!(Error, "      ! virtio-net DRIVER_OK failed: {:?}", error);
                continue;
            }

            let (mac, link) = {
                let device = probed.handle();
                let device = device.lock();
                (device.mac_address(), device.link_status())
            };
            match publish_probed_pci_device(registry(), probed) {
                Ok(_) => {
                    klog!(Info,
                        "      ✓ {} @ {:02x}:{:02x}.{} MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={}",
                        name,
                        pci_dev.slot.bus,
                        pci_dev.slot.device,
                        pci_dev.slot.function,
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        if link.up { "up" } else { "down" }
                    );
                    registered += 1;
                }
                Err(e) => {
                    klog!(
                        Error,
                        "      ! Failed to register {}: {:?} (device rolled back or quarantined)",
                        name,
                        e
                    );
                }
            }
        }
    }

    if registered > 0 {
        klog_always!("      ✓ {} network device(s) registered", registered);
    }

    registered
}

// ============================================================================
// D3-NETNS-DATAPLANE: RX Ingress Lifecycle Contract
// ============================================================================

/// D3-NETNS-DATAPLANE RX-WIRING CONTRACT (Phase I.3 revocation leg): any
/// production RX loop (IRQ handler, polling task, or otherwise) that will call
/// `process_frame` with non-root namespace IDs MUST:
///
/// 1. **Start ONLY after `netns_device_hooks_registered()` returns true.**
///    Call `assert_netns_hooks_for_rx()` at wiring time (e.g., after IRQ
///    registration, before the first poll). This ensures the per-ns ARP path
///    never runs before kernel_core has seeded the namespace registry.
///
/// 2. **Pin namespace liveness for the frame's entire processing lifetime**
///    OR revalidate before emitting replies. The current `ns_arp_cache` hook
///    contract proves liveness AT LOOKUP only — a namespace may be destroyed
///    while RX processing still holds its cache Arc. An orphaned cache stays
///    memory-safe and never becomes another namespace's, so ARP learning/reply
///    generation complete without unsafety. A loop that must not emit replies
///    for destroyed namespaces has two options:
///    - Hold a namespace `Arc<NetNamespace>` (upgraded from the registry's
///      Weak, proving liveness) for the frame's entire lifetime, OR
///    - Revalidate liveness immediately before calling the driver's `transmit`
///      (drop the reply if the lookup now fails).
///
/// The current RX surface (`process_frame` in runtime_tests.rs boot tests)
/// satisfies #1 trivially — hook registration precedes the test suite. It does
/// NOT satisfy #2, but that is safe because the boot-test namespaces are torn
/// down synchronously at the end of each test leg with no concurrent RX, so no
/// frame can be in-flight when a namespace drops. A FUTURE concurrent RX loop
/// (IRQ-driven or polling) wired for multi-namespace traffic must implement one
/// of the #2 strategies above.
///
/// **Why this contract exists:**
/// - Without #1, `process_frame`'s ARP arm would call `ns_arp_cache(ns_id)`
///   before the hook is registered → `None` → `NetNsUnavailable` drop for ALL
///   frames (including root-ns ARP) until userspace starts. The boot-time hook
///   registration (kernel_core::init, line ~377) closes that window.
/// - Without #2, a reply ARP packet could be emitted "from" a namespace that
///   was destroyed between learning and transmission. The packet itself is
///   memory-safe (its cache Arc is private, never another ns's), but its source
///   IP/namespace attribution would be stale. Whether that is acceptable depends
///   on the system's revocation semantics (best-effort vs strict).
///
/// This function enforces #1 at the call site; #2 is a future RX-loop
/// implementation obligation documented here for when that loop is wired.
#[inline]
pub fn assert_netns_hooks_for_rx() {
    assert!(
        crate::socket::netns_device_hooks_registered(),
        "D3-NETNS-DATAPLANE RX-WIRING CONTRACT: production RX loop started \
         before netns_device_hooks were registered — ARP per-ns cache lookups \
         would fail-closed, breaking root-ns ARP until userspace init"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use self::std::panic::{catch_unwind, AssertUnwindSafe};

    static PCI_TRANSACTION_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct FaultInjectedNetDevice {
        name: &'static str,
        reset_acked: bool,
        lifecycle_log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Drop for FaultInjectedNetDevice {
        fn drop(&mut self) {
            self.lifecycle_log.lock().push("device-drop");
        }
    }

    impl NetDevice for FaultInjectedNetDevice {
        fn rollback_unpublished(&mut self) -> bool {
            self.lifecycle_log.lock().push("reset");
            self.reset_acked
        }

        fn name(&self) -> &str {
            self.name
        }

        fn mac_address(&self) -> MacAddress {
            [0; 6]
        }

        fn set_mac_address(&mut self, _mac: MacAddress) -> Result<(), NetError> {
            Err(NetError::NotSupported)
        }

        fn capabilities(&self) -> DeviceCaps {
            DeviceCaps::minimal()
        }

        fn link_status(&self) -> LinkStatus {
            LinkStatus::DOWN
        }

        fn operating_mode(&self) -> OperatingMode {
            OperatingMode::Polling
        }

        fn set_operating_mode(&mut self, _mode: OperatingMode) -> Result<(), NetError> {
            Ok(())
        }

        fn enable_interrupts(&mut self) -> Result<(), NetError> {
            Ok(())
        }

        fn disable_interrupts(&mut self) -> Result<(), NetError> {
            Ok(())
        }

        fn transmit(&mut self, buf: NetBuf) -> Result<(), (TxError, NetBuf)> {
            Err((TxError::IoError, buf))
        }

        fn reclaim_tx(&mut self) -> usize {
            0
        }

        fn tx_queue_space(&self) -> usize {
            0
        }

        fn receive(&mut self) -> Result<Option<NetBuf>, RxError> {
            Ok(None)
        }

        fn replenish_rx(&mut self, _pool: &BufPool, _count: usize) -> usize {
            0
        }

        fn rx_owned_rx_buffers(&self) -> usize {
            0
        }

        fn supports_rx_replenishment(&self) -> bool {
            false
        }

        fn poll(&mut self) -> bool {
            false
        }

        fn handle_interrupt(&mut self) {}
    }

    fn lifecycle_log() -> Arc<Mutex<Vec<&'static str>>> {
        Arc::new(Mutex::new(Vec::with_capacity(8)))
    }

    fn fault_device(
        name: &'static str,
        reset_acked: bool,
        log: Arc<Mutex<Vec<&'static str>>>,
    ) -> NetDeviceHandle {
        let device: Box<dyn NetDevice> = Box::new(FaultInjectedNetDevice {
            name,
            reset_acked,
            lifecycle_log: log,
        });
        Arc::new(Mutex::new(device))
    }

    fn test_mapping(
        log: Arc<Mutex<Vec<&'static str>>>,
        reservation_start: u64,
        allocated_offset: u64,
    ) -> PciMmioMapping {
        let mut allocator = NET_MMIO_OFFSET.lock();
        *allocator = allocated_offset;
        PciMmioMapping {
            allocator: Some(allocator),
            reservation_start,
            phys_anchor: 0,
            virt_anchor: 0,
            windows: [MmioPageWindow::default(); 4],
            window_count: 0,
            virt_offset: 0,
            committed: false,
            lifecycle_log: Some(log),
        }
    }

    fn test_probed_device(
        name: &'static str,
        reset_acked: bool,
        contained: bool,
        log: Arc<Mutex<Vec<&'static str>>>,
        reservation_start: u64,
        allocated_offset: u64,
    ) -> ProbedPciNetDevice {
        // Allocate every test owner before taking the synthetic MMIO allocator
        // guard, mirroring the production rule that the guard must not be held
        // across unrelated fallible setup.
        let device = fault_device(name, reset_acked, Arc::clone(&log));
        let containment_log = Arc::clone(&log);
        let containment_hook: Arc<dyn Fn(&pci::PciSlot) -> bool + Send + Sync> =
            Arc::new(move |_slot| {
                containment_log.lock().push("contain");
                contained
            });
        let mapping = test_mapping(Arc::clone(&log), reservation_start, allocated_offset);
        ProbedPciNetDevice::new(
            pci::PciSlot {
                bus: 0,
                device: 1,
                function: 0,
            },
            device,
            mapping,
        )
        .with_containment_hook(containment_hook)
    }

    fn assert_allocator_released(expected_offset: u64) {
        let mut allocator = NET_MMIO_OFFSET
            .try_lock()
            .expect("rollback retained the network MMIO allocator mutex");
        assert_eq!(*allocator, expected_offset);
        *allocator = 0;
    }

    fn assert_events(log: &Arc<Mutex<Vec<&'static str>>>, expected: &[&'static str]) {
        let events = log.lock();
        assert_eq!(events.as_slice(), expected);
    }

    #[test]
    fn net_mmio_preflight_rejects_page_above_architectural_width() {
        let above_width = 1u64 << 52;
        let window = virtio::VirtioPciBarWindow::try_new(
            above_width,
            0x1000,
            0,
            8,
            virtio::VirtioPciWindowAccess::Device,
        )
        .expect("synthetic window is internally BAR-contained");
        let addrs = virtio::VirtioPciAddrs {
            device_cfg: window,
            ..virtio::VirtioPciAddrs::default()
        };
        assert!(matches!(
            merged_mmio_windows(&addrs),
            Err(NetError::NotSupported)
        ));
    }

    #[test]
    fn unpublished_rollback_orders_reset_containment_owner_drop_then_unmap() {
        let _serial = PCI_TRANSACTION_TEST_LOCK.lock();
        let log = lifecycle_log();
        let probed = test_probed_device("eth-rf186", true, true, Arc::clone(&log), 0x1000, 0x3000);

        drop(probed);

        assert_events(
            &log,
            &["reset", "contain", "device-drop", "mapping-release"],
        );
        assert_allocator_released(0x1000);
    }

    #[test]
    fn reset_timeout_quarantines_dma_and_mmio_but_releases_allocator_guard() {
        let _serial = PCI_TRANSACTION_TEST_LOCK.lock();
        let log = lifecycle_log();
        let mut probed =
            test_probed_device("eth-rf186", false, true, Arc::clone(&log), 0x1000, 0x3000);

        let proof = probed
            .rollback_owners()
            .expect("armed unpublished rollback transaction");

        assert_eq!(
            proof,
            UnpublishedRollbackProof {
                reset_acked: false,
                contained: true,
            }
        );
        assert!(!proof.ownership_can_be_released());
        assert_events(&log, &["reset", "contain", "mapping-quarantine"]);
        assert_allocator_released(0x3000);
        drop(probed);
    }

    #[test]
    fn command_containment_failure_quarantines_before_fail_stop_decision() {
        let _serial = PCI_TRANSACTION_TEST_LOCK.lock();
        let log = lifecycle_log();
        let probed = test_probed_device("eth-rf186", true, false, Arc::clone(&log), 0x1000, 0x3000);

        let fail_stop = catch_unwind(AssertUnwindSafe(|| drop(probed)));
        assert!(
            fail_stop.is_err(),
            "PCI command-containment refusal did not reach the production Drop fail-stop"
        );
        assert_events(&log, &["reset", "contain", "mapping-quarantine"]);
        assert_allocator_released(0x3000);
    }

    #[test]
    fn registry_allocation_faults_rollback_without_consuming_index() {
        let _serial = PCI_TRANSACTION_TEST_LOCK.lock();

        for fault in [
            RegistryAllocationPoint::DeviceName,
            RegistryAllocationPoint::DeviceVector,
        ] {
            let registry = NetDeviceRegistry::new();
            let log = lifecycle_log();
            let probed =
                test_probed_device("eth-rf186", true, true, Arc::clone(&log), 0x1000, 0x3000);

            let result =
                publish_probed_pci_device_with_fault(&registry, probed, |point| point == fault);

            assert_eq!(result, Err(NetError::NoMemory));
            assert_eq!(registry.count(), 0);
            assert_eq!(registry.next_index.load(Ordering::SeqCst), 0);
            assert_events(
                &log,
                &["reset", "contain", "device-drop", "mapping-release"],
            );
            assert_allocator_released(0x1000);
        }
    }

    #[test]
    fn duplicate_registry_failure_rolls_back_and_preserves_registry_identity() {
        let _serial = PCI_TRANSACTION_TEST_LOCK.lock();
        let registry = NetDeviceRegistry::new();
        let existing_log = lifecycle_log();
        registry
            .register_handle(fault_device("eth-rf186", true, existing_log))
            .expect("seed duplicate registry entry");

        let log = lifecycle_log();
        let probed = test_probed_device("eth-rf186", true, true, Arc::clone(&log), 0x1000, 0x3000);

        let result = publish_probed_pci_device(&registry, probed);

        assert_eq!(result, Err(NetError::InvalidConfig));
        assert_eq!(registry.count(), 1);
        assert_eq!(registry.next_index.load(Ordering::SeqCst), 1);
        assert_events(
            &log,
            &["reset", "contain", "device-drop", "mapping-release"],
        );
        assert_allocator_released(0x1000);
    }

    #[test]
    fn successful_registry_publication_commits_without_rollback() {
        let _serial = PCI_TRANSACTION_TEST_LOCK.lock();
        let registry = NetDeviceRegistry::new();
        let log = lifecycle_log();
        let probed = test_probed_device("eth-rf186", true, true, Arc::clone(&log), 0x1000, 0x3000);

        let index = publish_probed_pci_device(&registry, probed).expect("publish synthetic device");

        assert_eq!(index, 0);
        assert_eq!(registry.count(), 1);
        assert_eq!(registry.next_index.load(Ordering::SeqCst), 1);
        assert_events(&log, &["mapping-commit"]);
        assert_allocator_released(0x3000);

        drop(registry);
        assert_events(&log, &["mapping-commit", "device-drop"]);
    }
}
