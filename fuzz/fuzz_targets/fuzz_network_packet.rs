#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct NetworkFuzzInput {
    protocol: u8,
    packet_size: usize,
    flags: u32,
    data: Vec<u8>,
}

fuzz_target!(|input: NetworkFuzzInput| {
    // Target network packet handling
    // - Malformed packets
    // - Protocol violations
    // - Buffer overflows

    if input.data.len() > 65535 {
        return;
    }

    match input.protocol {
        6 => test_tcp_packet(&input.data),
        17 => test_udp_packet(&input.data),
        1 => test_icmp_packet(&input.data),
        _ => return,
    }
});

fn test_tcp_packet(data: &[u8]) {
    if data.len() < 20 {
        return; // Too small for TCP header
    }

    // TCP header validation
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    if src_port == 0 || dst_port == 0 {
        // Invalid port
        return;
    }

    // Flags validation
    let flags = data[13];
    const TCP_FIN: u8 = 0x01;
    const TCP_SYN: u8 = 0x02;
    const TCP_RST: u8 = 0x04;
    const TCP_ACK: u8 = 0x10;

    // SYN+RST is invalid
    if flags & TCP_SYN != 0 && flags & TCP_RST != 0 {
        return;
    }
}

fn test_udp_packet(data: &[u8]) {
    if data.len() < 8 {
        return; // Too small for UDP header
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);

    if length < 8 || length as usize > data.len() {
        return; // Invalid length
    }
}

fn test_icmp_packet(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let icmp_type = data[0];
    let icmp_code = data[1];

    // Validate type/code combinations
    match icmp_type {
        0 => {
            // Echo Reply
            assert!(icmp_code == 0, "Echo Reply with non-zero code");
        }
        8 => {
            // Echo Request
            assert!(icmp_code == 0, "Echo Request with non-zero code");
        }
        _ => {}
    }
}
