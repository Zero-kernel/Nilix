//! Ethernet frame parsing and building for Zero-OS (Phase D.2)
//!
//! This module provides Ethernet II frame handling with basic validation.
//!
//! # Frame Format
//!
//! ```text
//! +------------------+------------------+------------+-------------+
//! | Destination MAC  |   Source MAC     | EtherType  |   Payload   |
//! |    (6 bytes)     |   (6 bytes)      | (2 bytes)  | (46-1500)   |
//! +------------------+------------------+------------+-------------+
//! ```
//!
//! # References
//! - IEEE 802.3 Ethernet

use crate::admitted::WirePacket;

/// Ethernet header size (6 + 6 + 2 = 14 bytes)
pub const ETH_HEADER_LEN: usize = 14;

/// Minimum Ethernet frame payload size
pub const ETH_MIN_PAYLOAD: usize = 46;

/// Maximum Ethernet frame payload size (standard MTU)
pub const ETH_MAX_PAYLOAD: usize = 1500;

// ============================================================================
// EtherType Constants
// ============================================================================

/// IPv4 protocol
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// ARP (Address Resolution Protocol)
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// IPv6 protocol
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// VLAN-tagged frame (802.1Q)
pub const ETHERTYPE_VLAN: u16 = 0x8100;

// ============================================================================
// MAC Address
// ============================================================================

/// A 6-byte Ethernet MAC address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAddr(pub [u8; 6]);

impl EthAddr {
    /// Create a new MAC address from bytes
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        EthAddr([a, b, c, d, e, f])
    }

    /// Broadcast address (ff:ff:ff:ff:ff:ff)
    pub const BROADCAST: EthAddr = EthAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

    /// Zero address (00:00:00:00:00:00)
    pub const ZERO: EthAddr = EthAddr::new(0, 0, 0, 0, 0, 0);

    /// Check if this is the broadcast address
    #[inline]
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    }

    /// Check if this is a multicast address (least significant bit of first byte is 1)
    #[inline]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Check if this is a unicast address
    #[inline]
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Check if this is a locally administered address
    #[inline]
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Get the raw bytes
    #[inline]
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl From<[u8; 6]> for EthAddr {
    fn from(bytes: [u8; 6]) -> Self {
        EthAddr(bytes)
    }
}

// ============================================================================
// Ethernet Header
// ============================================================================

/// Parsed Ethernet frame header
#[derive(Debug, Clone, Copy)]
pub struct EthHeader {
    /// Destination MAC address
    pub dst: EthAddr,
    /// Source MAC address
    pub src: EthAddr,
    /// EtherType (protocol identifier)
    pub ethertype: u16,
}

impl EthHeader {
    /// Check if this frame is for IPv4
    #[inline]
    pub fn is_ipv4(&self) -> bool {
        self.ethertype == ETHERTYPE_IPV4
    }

    /// Check if this frame is for ARP
    #[inline]
    pub fn is_arp(&self) -> bool {
        self.ethertype == ETHERTYPE_ARP
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; ETH_HEADER_LEN] {
        let mut bytes = [0u8; ETH_HEADER_LEN];
        bytes[0..6].copy_from_slice(&self.dst.0);
        bytes[6..12].copy_from_slice(&self.src.0);
        bytes[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
        bytes
    }
}

// ============================================================================
// Ethernet Errors
// ============================================================================

/// Errors that can occur while parsing or constructing an Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthError {
    /// Frame is too short
    Truncated,
    /// Unsupported EtherType
    UnsupportedProtocol,
    /// Header plus payload length overflowed the address space.
    FrameTooLarge,
    /// Aggregate admission or allocator backing was unavailable.
    AllocationFailed,
}

// ============================================================================
// Ethernet Parsing
// ============================================================================

/// Parse an Ethernet frame.
///
/// # Arguments
/// * `frame` - Raw frame bytes
///
/// # Returns
/// On success: (header, payload_slice)
/// On failure: EthError describing the problem
pub fn parse_ethernet(frame: &[u8]) -> Result<(EthHeader, &[u8]), EthError> {
    if frame.len() < ETH_HEADER_LEN {
        return Err(EthError::Truncated);
    }

    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    let header = EthHeader {
        dst: EthAddr(dst),
        src: EthAddr(src),
        ethertype,
    };

    let payload = &frame[ETH_HEADER_LEN..];

    Ok((header, payload))
}

// ============================================================================
// Ethernet Frame Building
// ============================================================================

/// Build an Ethernet frame with the given header and payload.
///
/// # Arguments
/// * `dst` - Destination MAC address
/// * `src` - Source MAC address
/// * `ethertype` - Protocol identifier
/// * `payload` - Frame payload
///
/// # Returns
/// Complete Ethernet frame including header and payload
// RF180-41 FIX: the returned wire owner holds aggregate admission until its
// Ethernet backing allocation has actually been destroyed.
pub fn build_ethernet_frame(
    dst: EthAddr,
    src: EthAddr,
    ethertype: u16,
    payload: &[u8],
) -> WirePacket {
    build_ethernet_frame_from_parts(dst, src, ethertype, &[payload])
}

/// Checked multi-part frame builder.
///
/// The complete frame is admitted before its one allocator request. Callers
/// that need to distinguish pressure from an intentionally empty value should
/// use this API instead of the compatibility wrapper.
pub fn try_build_ethernet_frame_from_parts(
    dst: EthAddr,
    src: EthAddr,
    ethertype: u16,
    payload_parts: &[&[u8]],
) -> Result<WirePacket, EthError> {
    let payload_len = payload_parts
        .iter()
        .try_fold(0usize, |len, part| len.checked_add(part.len()))
        .ok_or(EthError::FrameTooLarge)?;
    let total = ETH_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(EthError::FrameTooLarge)?;
    let mut frame = WirePacket::try_zeroed(total).map_err(|_| EthError::AllocationFailed)?;
    frame.as_mut_slice()[0..6].copy_from_slice(&dst.0);
    frame.as_mut_slice()[6..12].copy_from_slice(&src.0);
    frame.as_mut_slice()[12..14].copy_from_slice(&ethertype.to_be_bytes());
    let mut offset = ETH_HEADER_LEN;
    for part in payload_parts {
        let end = offset + part.len();
        frame.as_mut_slice()[offset..end].copy_from_slice(part);
        offset = end;
    }
    Ok(frame)
}

/// Build a frame from discontiguous payload parts with one admitted allocation.
/// This prevents IPv4 response paths from retaining a temporary concatenation
/// at the same time as the final Ethernet frame.
pub(crate) fn build_ethernet_frame_from_parts(
    dst: EthAddr,
    src: EthAddr,
    ethertype: u16,
    payload_parts: &[&[u8]],
) -> WirePacket {
    try_build_ethernet_frame_from_parts(dst, src, ethertype, payload_parts).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rf180_41_ethernet_admission_failure_never_emits_a_runt_frame() {
        WirePacket::fail_next_admission_for_test();
        assert_eq!(
            try_build_ethernet_frame_from_parts(
                EthAddr::BROADCAST,
                EthAddr::ZERO,
                ETHERTYPE_IPV4,
                &[&[1, 2], &[3, 4]],
            ),
            Err(EthError::AllocationFailed)
        );

        WirePacket::fail_next_admission_for_test();
        let failed = build_ethernet_frame(
            EthAddr::BROADCAST,
            EthAddr::ZERO,
            ETHERTYPE_IPV4,
            &[1, 2, 3, 4],
        );
        assert!(failed.is_empty());

        let frame = try_build_ethernet_frame_from_parts(
            EthAddr::BROADCAST,
            EthAddr::ZERO,
            ETHERTYPE_IPV4,
            &[&[1, 2], &[3, 4]],
        )
        .expect("multi-part Ethernet admission");
        assert_eq!(frame.len(), ETH_HEADER_LEN + 4);
        assert_eq!(&frame[..6], &EthAddr::BROADCAST.0);
        assert_eq!(&frame[12..14], &ETHERTYPE_IPV4.to_be_bytes());
        assert_eq!(&frame[ETH_HEADER_LEN..], &[1, 2, 3, 4]);
    }
}
