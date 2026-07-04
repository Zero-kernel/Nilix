#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Fuzz input for the network packet parsers.
#[derive(Arbitrary, Debug)]
struct NetworkFuzzInput {
    /// Selects which transport parser to exercise on the raw bytes directly.
    protocol: u8,
    /// Raw packet bytes handed to the real kernel parsers.
    data: Vec<u8>,
}

// Drives the REAL kernel packet parsers in `kernel/net` — the pure, host-safe
// header decoders run on every received frame. The goal is to prove no crafted
// packet can panic the parse path (all bounds/length/checksum handling must
// return Err, never abort). A crash here is a real finding.
fuzz_target!(|input: NetworkFuzzInput| {
    let data = &input.data[..];

    // Link + network layer entry points (each parses the buffer independently).
    let _ = net::parse_ethernet(data);
    let _ = net::parse_arp(data);

    // If the bytes parse as IPv4, feed the returned L4 payload to the transport
    // parsers exactly as the stack would.
    if let Ok((_hdr, _opts, payload)) = net::parse_ipv4(data) {
        let _ = net::parse_tcp_header(payload);
        let _ = net::parse_udp_header(payload);
        let _ = net::parse_icmp(payload);
    }

    // Also exercise the transport parsers directly on the raw bytes, selected by
    // a fuzzer-controlled protocol byte, so they get coverage independent of a
    // well-formed IPv4 wrapper.
    match input.protocol {
        6 => {
            if let Ok(hdr) = net::parse_tcp_header(data) {
                let _ = net::parse_tcp_options(data, &hdr);
            }
        }
        17 => {
            let _ = net::parse_udp_header(data);
        }
        1 => {
            let _ = net::parse_icmp(data);
            let _ = net::icmp::parse_icmp_unchecked(data);
        }
        _ => {}
    }
});
