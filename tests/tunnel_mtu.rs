//! Integration tests for tunnel MTU handling.
//!
//! **Requires root or CAP_NET_ADMIN** - tests are skipped otherwise.

use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd};

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

fn make_ipv4_packet(total_len: usize, ttl: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    assert!(total_len >= IPV4_HEADER_LEN);
    let mut pkt = vec![0xAAu8; total_len];
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&[0x00, 0x00]);
    pkt[6..8].copy_from_slice(&[0x40, 0x00]);
    pkt[8] = ttl;
    pkt[9] = 17;
    pkt[10..12].copy_from_slice(&[0x00, 0x00]);
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);

    // Compute IP header checksum
    let cksum = ipv4_checksum(&pkt[..IPV4_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

fn make_ipv6_packet(total_len: usize, hop_limit: u8, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    assert!(total_len >= IPV6_HEADER_LEN);
    let mut pkt = vec![0xBBu8; total_len];
    pkt[0] = 0x60;
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    let payload_len = (total_len - IPV6_HEADER_LEN) as u16;
    pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
    pkt[6] = 17;
    pkt[7] = hop_limit;
    pkt[8..24].copy_from_slice(&src);
    pkt[24..40].copy_from_slice(&dst);
    pkt
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < header.len() {
        if i == 10 {
            i += 2;
            continue;
        }
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += word as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn verify_ipv4_checksum(header: &[u8]) -> bool {
    let mut sum: u32 = (0..IPV4_HEADER_LEN)
        .step_by(2)
        .map(|i| u16::from_be_bytes([header[i], header[i + 1]]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16 == 0xFFFF
}

fn try_create_tun(name: &str, mtu: u16) -> Option<tun::Device> {
    use tun::AbstractDevice;

    let mut config = tun::Configuration::default();
    config.layer(tun::Layer::L3);
    config.tun_name(name);

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let mut dev = match tun::create(&config) {
        Ok(d) => d,
        Err(e) => {
            assert!(std::env::var_os("USQUE_REQUIRE_TUN").is_none(), "required TUN unavailable: {e}");
            eprintln!("Skipping TUN test (no permission): {e}");
            return None;
        }
    };

    if let Err(e) = dev.set_mtu(mtu) {
        assert!(std::env::var_os("USQUE_REQUIRE_TUN").is_none(), "required MTU setup failed: {e}");
        eprintln!("Failed to set MTU: {e}");
        return None;
    }

    if let Err(e) = dev.enabled(true) {
        assert!(std::env::var_os("USQUE_REQUIRE_TUN").is_none(), "required link setup failed: {e}");
        eprintln!("Failed to bring device UP: {e}");
        return None;
    }

    Some(dev)
}

// ---- TUN device tests ----

#[test]
fn tun_device_small_mtu_ipv4_write() {
    let dev = match try_create_tun("usqt0", 576) {
        Some(d) => d,
        None => return, // skip if no permissions
    };

    let fd = dev.as_raw_fd();
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    let pkt = make_ipv4_packet(100, 64, [10, 200, 0, 1], [10, 200, 0, 2]);
    let result = file.write(&pkt);
    assert!(result.is_ok(), "should be able to write small IPv4 to TUN");
    assert_eq!(result.unwrap(), 100);

    // Don't let File close the fd (owned by Device)
    std::mem::forget(file);
}

#[test]
fn tun_device_large_mtu_ipv4_write() {
    let dev = match try_create_tun("usqt1", 9000) {
        Some(d) => d,
        None => return,
    };

    let fd = dev.as_raw_fd();
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    let pkt = make_ipv4_packet(8000, 64, [10, 200, 0, 1], [10, 200, 0, 2]);
    let result = file.write(&pkt);
    assert!(result.is_ok(), "should be able to write jumbo IPv4 to TUN");
    assert_eq!(result.unwrap(), 8000);

    std::mem::forget(file);
}

#[test]
fn tun_device_small_mtu_ipv6_write() {
    let dev = match try_create_tun("usqt2", 1280) {
        Some(d) => d,
        None => return,
    };

    let fd = dev.as_raw_fd();
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let pkt = make_ipv6_packet(1280, 64, src, dst);
    let result = file.write(&pkt);
    assert!(
        result.is_ok(),
        "should be able to write 1280-byte IPv6 to TUN"
    );

    std::mem::forget(file);
}

#[test]
fn tun_device_jumbo_mtu_ipv6_write() {
    let dev = match try_create_tun("usqt3", 9000) {
        Some(d) => d,
        None => return,
    };

    let fd = dev.as_raw_fd();
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let pkt = make_ipv6_packet(8000, 64, src, dst);
    let result = file.write(&pkt);
    assert!(result.is_ok(), "should be able to write jumbo IPv6 to TUN");

    std::mem::forget(file);
}

// ---- Full pipeline tests ----
// These don't require root.

mod pipeline {
    use super::*;
    use usque_rs::{datagram::parse_datagram, icmp::compose_icmp_too_large,
        packet::{prepare_outgoing, validate_incoming}};

    fn encode_varint(val: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let mut b = octets::OctetsMut::with_slice(&mut tmp);
        b.put_varint(val).unwrap();
        let len = b.off();
        tmp[..len].to_vec()
    }

    struct TestResult {
        datagram: Vec<u8>,
        ttl_after: u8,
        version: u8,
    }

    fn pipeline_ipv4(packet_size: usize, flow_id: u64) -> TestResult {
        let mut pkt = make_ipv4_packet(packet_size, 64, [10, 0, 0, 1], [10, 0, 0, 2]);
        let version = prepare_outgoing(&mut pkt).expect("should prepare OK");

        let flow_prefix = encode_varint(flow_id);
        let ctx_prefix = encode_varint(0);
        let mut dgram = Vec::with_capacity(flow_prefix.len() + ctx_prefix.len() + pkt.len());
        dgram.extend_from_slice(&flow_prefix);
        dgram.extend_from_slice(&ctx_prefix);
        dgram.extend_from_slice(&pkt);

        TestResult {
            datagram: dgram,
            ttl_after: pkt[8],
            version,
        }
    }

    fn pipeline_ipv6(packet_size: usize, flow_id: u64) -> TestResult {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut pkt = make_ipv6_packet(packet_size, 64, src, dst);
        let version = prepare_outgoing(&mut pkt).expect("should prepare OK");

        let flow_prefix = encode_varint(flow_id);
        let ctx_prefix = encode_varint(0);
        let mut dgram = Vec::with_capacity(flow_prefix.len() + ctx_prefix.len() + pkt.len());
        dgram.extend_from_slice(&flow_prefix);
        dgram.extend_from_slice(&ctx_prefix);
        dgram.extend_from_slice(&pkt);

        TestResult {
            datagram: dgram,
            ttl_after: pkt[7],
            version,
        }
    }

    #[test]
    fn ipv4_576_outgoing_pipeline() {
        let r = pipeline_ipv4(576, 0);
        assert_eq!(r.version, 4);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).expect("should parse");
        assert_eq!(payload.len(), 576);
        assert_eq!(validate_incoming(payload).unwrap(), 4);
        assert!(verify_ipv4_checksum(&payload[..IPV4_HEADER_LEN]));
    }

    #[test]
    fn ipv4_68_minimum_outgoing_pipeline() {
        let r = pipeline_ipv4(68, 0);
        assert_eq!(r.version, 4);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).expect("should parse");
        assert_eq!(payload.len(), 68);
    }

    #[test]
    fn ipv4_1280_outgoing_pipeline() {
        let r = pipeline_ipv4(1280, 0);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).expect("should parse");
        assert_eq!(payload.len(), 1280);
        assert!(verify_ipv4_checksum(&payload[..IPV4_HEADER_LEN]));
    }

    #[test]
    fn ipv4_1500_outgoing_pipeline() {
        let r = pipeline_ipv4(1500, 0);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).expect("should parse");
        assert_eq!(payload.len(), 1500);
    }

    #[test]
    fn ipv4_9000_jumbo_outgoing_pipeline() {
        let r = pipeline_ipv4(9000, 0);
        assert_eq!(r.version, 4);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).expect("should parse");
        assert_eq!(payload.len(), 9000);
        assert!(verify_ipv4_checksum(&payload[..IPV4_HEADER_LEN]));
    }

    #[test]
    fn ipv6_1280_minimum_outgoing_pipeline() {
        let r = pipeline_ipv6(1280, 0);
        assert_eq!(r.version, 6);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).expect("should parse");
        assert_eq!(payload.len(), 1280);
    }

    #[test]
    fn ipv6_1500_outgoing_pipeline() {
        let r = pipeline_ipv6(1500, 0);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).expect("should parse");
        assert_eq!(payload.len(), 1500);
    }

    #[test]
    fn ipv6_9000_jumbo_outgoing_pipeline() {
        let r = pipeline_ipv6(9000, 0);
        assert_eq!(r.version, 6);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).expect("should parse");
        assert_eq!(payload.len(), 9000);
    }

    #[test]
    fn round_trip_ipv4_small() {
        let r = pipeline_ipv4(100, 42);
        let payload = parse_datagram(&r.datagram, 42).expect("should parse");
        assert_eq!(validate_incoming(payload).unwrap(), 4);
        assert_eq!(payload[8], 63);
    }

    #[test]
    fn round_trip_ipv4_large() {
        let r = pipeline_ipv4(4000, 42);
        let payload = parse_datagram(&r.datagram, 42).expect("should parse");
        assert_eq!(validate_incoming(payload).unwrap(), 4);
    }

    #[test]
    fn round_trip_ipv6_small() {
        let r = pipeline_ipv6(100, 7);
        let payload = parse_datagram(&r.datagram, 7).expect("should parse");
        assert_eq!(validate_incoming(payload).unwrap(), 6);
        assert_eq!(payload[7], 63);
    }

    #[test]
    fn round_trip_ipv6_large() {
        let r = pipeline_ipv6(5000, 7);
        let payload = parse_datagram(&r.datagram, 7).expect("should parse");
        assert_eq!(validate_incoming(payload).unwrap(), 6);
    }

    #[test]
    fn wrong_flow_id_rejected() {
        let r = pipeline_ipv4(200, 0);
        assert!(parse_datagram(&r.datagram, 999).is_none());
    }

    #[test]
    fn ttl_1_rejected() {
        let mut pkt = make_ipv4_packet(100, 1, [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(prepare_outgoing(&mut pkt).is_err());
    }

    #[test]
    fn hop_limit_1_rejected() {
        let src = [0; 16];
        let dst = [1; 16];
        let mut pkt = make_ipv6_packet(100, 1, src, dst);
        assert!(prepare_outgoing(&mut pkt).is_err());
    }

    #[test]
    fn icmp_too_large_ipv4_small_mtu() {
        let original = make_ipv4_packet(1500, 64, [10, 0, 0, 1], [10, 0, 0, 2]);
        let icmp = compose_icmp_too_large(&original, 1280);
        assert!(icmp.is_some());

        let resp = icmp.unwrap();
        assert_eq!(resp[0] >> 4, 4);
        assert_eq!(resp[9], 1);
        let icmp_hdr = &resp[IPV4_HEADER_LEN..];
        assert_eq!(icmp_hdr[0], 3);
        assert_eq!(icmp_hdr[1], 4);
        let mtu = u16::from_be_bytes([icmp_hdr[6], icmp_hdr[7]]);
        assert_eq!(mtu, 1280);
    }

    #[test]
    fn icmp_too_large_ipv6_small_mtu() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let original = make_ipv6_packet(1500, 64, src, dst);
        let icmp = compose_icmp_too_large(&original, 1280);
        assert!(icmp.is_some());

        let resp = icmp.unwrap();
        assert_eq!(resp[0] >> 4, 6);
        assert_eq!(resp[6], 58);
        let icmp_hdr = &resp[IPV6_HEADER_LEN..];
        assert_eq!(icmp_hdr[0], 2);
        let mtu = u32::from_be_bytes([icmp_hdr[4], icmp_hdr[5], icmp_hdr[6], icmp_hdr[7]]);
        assert_eq!(mtu, 1280);
    }

    #[test]
    fn icmp_too_large_ipv4_jumbo_to_standard() {
        let original = make_ipv4_packet(9000, 64, [172, 16, 0, 1], [8, 8, 8, 8]);
        let icmp = compose_icmp_too_large(&original, 1500);
        assert!(icmp.is_some());

        let resp = icmp.unwrap();
        let icmp_hdr = &resp[IPV4_HEADER_LEN..];
        let mtu = u16::from_be_bytes([icmp_hdr[6], icmp_hdr[7]]);
        assert_eq!(mtu, 1500);
    }

    #[test]
    fn icmp_too_large_ipv6_jumbo_to_minimum() {
        let src = [0; 16];
        let dst = [1; 16];
        let original = make_ipv6_packet(9000, 64, src, dst);
        let icmp = compose_icmp_too_large(&original, 1280);
        assert!(icmp.is_some());

        let resp = icmp.unwrap();
        let icmp_hdr = &resp[IPV6_HEADER_LEN..];
        let mtu = u32::from_be_bytes([icmp_hdr[4], icmp_hdr[5], icmp_hdr[6], icmp_hdr[7]]);
        assert_eq!(mtu, 1280);
    }

}
