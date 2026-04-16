//! Comprehensive tests for MS-RDPEUDP reliable / lossy mode features.
//!
//! Covers every bullet point from the §10.2 roadmap:
//! - Reliable mode: SN management, RTO, congestion window, FEC,
//!   in-order delivery, TLS-over-UDP (stub)
//! - Lossy mode: FEC-only, DTLS (stub)
//! - ACK/NACK processing
//! - MTU negotiation edge cases
//! - Protocol version 1/2/3 support

use justrdp_core::Decode;
use justrdp_rdpeudp::fec::{fec_encode, fec_recover};
use justrdp_rdpeudp::session::{
    RdpeudpConfig, RdpeudpSession, INITIAL_CWND, INITIAL_RTO_US, INITIAL_SSTHRESH,
};
use justrdp_rdpeudp::v1::*;

// =============================================================================
// Helpers
// =============================================================================

fn client_cfg(isn: u32) -> RdpeudpConfig {
    RdpeudpConfig {
        up_stream_mtu: 1200,
        down_stream_mtu: 1200,
        initial_sequence_number: isn,
        receive_window_size: 64,
        lossy: false,
        protocol_version: RDPUDP_PROTOCOL_VERSION_2,
        correlation_id: None,
        cookie_hash: None,
    }
}

fn server_cfg(isn: u32) -> RdpeudpConfig {
    RdpeudpConfig {
        up_stream_mtu: 1200,
        down_stream_mtu: 1200,
        initial_sequence_number: isn,
        receive_window_size: 32,
        lossy: false,
        protocol_version: RDPUDP_PROTOCOL_VERSION_2,
        correlation_id: None,
        cookie_hash: None,
    }
}

fn drive_to_connected(
    client_isn: u32,
    server_isn: u32,
) -> (RdpeudpSession, RdpeudpSession) {
    let mut c = RdpeudpSession::new(client_cfg(client_isn));
    let mut s = RdpeudpSession::new_server(server_cfg(server_isn));
    let mut syn = Vec::new();
    c.build_syn(&mut syn).unwrap();
    let mut syn_ack = Vec::new();
    s.receive(&syn, &mut syn_ack).unwrap();
    let mut ack = Vec::new();
    c.receive(&syn_ack, &mut ack).unwrap();
    let mut no = Vec::new();
    s.receive(&ack, &mut no).unwrap();
    assert!(c.is_connected());
    assert!(s.is_connected());
    (c, s)
}

// =============================================================================
// 1. Reliable mode — 시퀀스 번호 관리
// =============================================================================

#[test]
fn sn_monotonic_increment() {
    let (mut c, _s) = drive_to_connected(100, 200);
    let mut out = Vec::new();
    let sn1 = c.build_data_packet(b"a", &mut out).unwrap();
    let sn2 = c.build_data_packet(b"b", &mut out).unwrap();
    let sn3 = c.build_data_packet(b"c", &mut out).unwrap();
    assert_eq!(sn2, sn1.wrapping_add(1));
    assert_eq!(sn3, sn2.wrapping_add(1));
}

#[test]
fn sn_wrapping_at_u32_max() {
    let (mut c, _s) = drive_to_connected(u32::MAX, 200);
    let mut out = Vec::new();
    let sn1 = c.build_data_packet(b"a", &mut out).unwrap();
    let sn2 = c.build_data_packet(b"b", &mut out).unwrap();
    // ISN = u32::MAX → first data SN = ISN+1 = 0.
    assert_eq!(sn1, 0);
    assert_eq!(sn2, 1);
}

#[test]
fn duplicate_sn_ignored_in_reorder() {
    let (mut c, mut s) = drive_to_connected(100, 200);
    let mut dgram = Vec::new();
    c.build_data_packet(b"first", &mut dgram).unwrap();
    // Deliver twice — the reorder buffer should ignore the second.
    s.receive(&dgram, &mut Vec::new()).unwrap();
    s.receive(&dgram, &mut Vec::new()).unwrap();
    let ordered = s.take_ordered_data();
    assert_eq!(ordered.len(), 1);
    assert_eq!(ordered[0], b"first");
}

// =============================================================================
// 2. Reliable mode — 순서 보장 (reorder buffer)
// =============================================================================

#[test]
fn in_order_delivery_no_reorder_needed() {
    let (mut c, mut s) = drive_to_connected(100, 200);
    let mut out = Vec::new();
    c.build_data_packet(b"one", &mut out).unwrap();
    s.receive(&out, &mut Vec::new()).unwrap();
    c.build_data_packet(b"two", &mut out).unwrap();
    s.receive(&out, &mut Vec::new()).unwrap();

    let data = s.take_ordered_data();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0], b"one");
    assert_eq!(data[1], b"two");
}

#[test]
fn out_of_order_delivery_reorder_buffer() {
    let (mut c, mut s) = drive_to_connected(100, 200);
    let mut d1 = Vec::new();
    let mut d2 = Vec::new();
    let mut d3 = Vec::new();
    c.build_data_packet(b"one", &mut d1).unwrap();
    c.build_data_packet(b"two", &mut d2).unwrap();
    c.build_data_packet(b"three", &mut d3).unwrap();

    // Deliver out of order: 3, 1, 2.
    s.receive(&d3, &mut Vec::new()).unwrap();
    assert!(s.take_ordered_data().is_empty(), "3 alone can't be delivered yet");

    s.receive(&d1, &mut Vec::new()).unwrap();
    let data = s.take_ordered_data();
    assert_eq!(data.len(), 1, "only 1 is deliverable (2 still missing)");
    assert_eq!(data[0], b"one");

    s.receive(&d2, &mut Vec::new()).unwrap();
    let data = s.take_ordered_data();
    assert_eq!(data.len(), 2, "2 and 3 are now contiguous");
    assert_eq!(data[0], b"two");
    assert_eq!(data[1], b"three");
}

// =============================================================================
// 3. Reliable mode — 재전송 타이머 (RTO)
// =============================================================================

#[test]
fn rto_initial_value() {
    let (c, _s) = drive_to_connected(100, 200);
    assert_eq!(c.rto_us(), INITIAL_RTO_US);
}

#[test]
fn rto_updates_with_rtt_samples() {
    let (mut c, _s) = drive_to_connected(100, 200);
    c.update_rtt(100_000); // 100ms
    assert!(c.srtt_us() > 0);
    let rto1 = c.rto_us();

    c.update_rtt(80_000); // 80ms — slightly faster
    let rto2 = c.rto_us();
    // After a smaller RTT sample, the smoothed RTO should decrease
    // (or at least not increase dramatically).
    assert!(rto2 <= rto1 + 50_000, "RTO should not spike on a faster sample");
}

#[test]
fn rto_backoff_doubles() {
    let (mut c, _s) = drive_to_connected(100, 200);
    c.update_rtt(50_000); // 50ms
    let rto1 = c.rto_us();
    c.backoff_rto();
    assert_eq!(c.rto_us(), rto1 * 2);
}

#[test]
fn rto_backoff_capped_at_60s() {
    let (mut c, _s) = drive_to_connected(100, 200);
    for _ in 0..30 {
        c.backoff_rto();
    }
    assert!(c.rto_us() <= 60_000_000);
}

#[test]
fn rto_minimum_floor() {
    let (mut c, _s) = drive_to_connected(100, 200);
    // Very fast RTT — RTO should not go below the 200ms floor.
    c.update_rtt(1_000); // 1ms
    assert!(c.rto_us() >= 200_000);
}

// =============================================================================
// 4. Reliable mode — 혼잡 제어 (congestion window)
// =============================================================================

#[test]
fn cwnd_initial_value() {
    let (c, _s) = drive_to_connected(100, 200);
    assert_eq!(c.cwnd(), INITIAL_CWND);
    assert_eq!(c.ssthresh(), INITIAL_SSTHRESH);
}

#[test]
fn cwnd_slow_start_growth() {
    let (mut c, _s) = drive_to_connected(100, 200);
    let initial = c.cwnd();
    c.on_acks_received(3);
    // Slow start: +1 per ACK.
    assert_eq!(c.cwnd(), initial + 3);
}

#[test]
fn cwnd_congestion_avoidance_growth() {
    let (mut c, _s) = drive_to_connected(100, 200);
    // Push cwnd above ssthresh.
    c.on_acks_received(INITIAL_SSTHRESH + 10);
    let at_ca = c.cwnd();
    assert!(at_ca >= INITIAL_SSTHRESH);

    // In CA: cwnd += 1 per cwnd ACKs. So cwnd ACKs → cwnd+1.
    let cwnd_before = c.cwnd();
    c.on_acks_received(cwnd_before);
    assert_eq!(c.cwnd(), cwnd_before + 1);
}

#[test]
fn cwnd_on_loss_halves_and_sets_ssthresh() {
    let (mut c, _s) = drive_to_connected(100, 200);
    c.on_acks_received(20); // grow cwnd to 22
    let before = c.cwnd();
    c.on_loss();
    assert_eq!(c.ssthresh(), core::cmp::max(before / 2, 2));
    assert_eq!(c.cwnd(), c.ssthresh());
}

#[test]
fn can_send_respects_cwnd() {
    let (mut c, _s) = drive_to_connected(100, 200);
    assert!(c.can_send());
    // Fill the send buffer up to cwnd.
    let mut out = Vec::new();
    for _ in 0..c.cwnd() {
        c.build_data_packet(b"x", &mut out).unwrap();
    }
    assert!(!c.can_send(), "send buffer full → can_send should be false");
}

// =============================================================================
// 5. Reliable mode — FEC
// =============================================================================

#[test]
fn fec_single_loss_recovery() {
    let sources: Vec<&[u8]> = vec![b"alpha", b"bravo", b"charlie"];
    let fec = fec_encode(&sources);
    // Lose "bravo" — recover from remaining + FEC.
    let recovered = fec_recover(&fec, &[b"alpha", b"charlie"]).unwrap();
    assert_eq!(recovered, b"bravo");
}

#[test]
fn fec_different_payload_sizes() {
    let a = b"short";
    let b_src = b"a much longer payload that exceeds the short one";
    let fec = fec_encode(&[a, b_src]);
    assert_eq!(fec_recover(&fec, &[b_src]).unwrap(), a);
    assert_eq!(fec_recover(&fec, &[a]).unwrap(), b_src);
}

#[test]
fn fec_roundtrip_all_loss_positions() {
    let payloads: Vec<Vec<u8>> = (0..5).map(|i| format!("pkt-{i}").into_bytes()).collect();
    let refs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
    let fec = fec_encode(&refs);
    for lost in 0..payloads.len() {
        let remaining: Vec<&[u8]> = refs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != lost)
            .map(|(_, s)| *s)
            .collect();
        let r = fec_recover(&fec, &remaining).unwrap();
        assert_eq!(r, payloads[lost], "failed at position {lost}");
    }
}

// =============================================================================
// 6. ACK/NACK 처리
// =============================================================================

#[test]
fn ack_vector_detects_gap_as_nack() {
    let (mut c, mut s) = drive_to_connected(100, 200);
    let mut d1 = Vec::new();
    let mut d2 = Vec::new();
    let mut d3 = Vec::new();
    c.build_data_packet(b"1", &mut d1).unwrap();
    c.build_data_packet(b"2", &mut d2).unwrap();
    c.build_data_packet(b"3", &mut d3).unwrap();

    // Deliver 1 and 3 (skip 2).
    s.receive(&d1, &mut Vec::new()).unwrap();
    s.receive(&d3, &mut Vec::new()).unwrap();

    let mut ack = Vec::new();
    s.build_ack(&mut ack).unwrap();

    // Parse the ACK vector and check for NACKs.
    let mut cur = justrdp_core::ReadCursor::new(&ack);
    let _hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
    let ack_vec = AckVectorHeader::decode(&mut cur).unwrap();

    let losses = c.detect_loss_from_ack_vector(&ack_vec.ack_vector);
    assert!(losses >= 1, "should detect at least 1 loss (packet 2)");
}

#[test]
fn acknowledge_up_to_clears_send_buffer() {
    let (mut c, _s) = drive_to_connected(100, 200);
    let mut out = Vec::new();
    let _sn1 = c.build_data_packet(b"a", &mut out).unwrap();
    let sn2 = c.build_data_packet(b"b", &mut out).unwrap();
    let sn3 = c.build_data_packet(b"c", &mut out).unwrap();
    assert_eq!(c.unacked_packets().len(), 3);

    // Acknowledge up to sn2 — sn1 and sn2 removed, sn3 remains.
    let n = c.acknowledge_up_to(sn2);
    assert_eq!(n, 2);
    assert_eq!(c.unacked_packets().len(), 1);
    assert_eq!(c.unacked_packets()[0].0, sn3);
}

// =============================================================================
// 7. MTU 협상 — edge cases
// =============================================================================

#[test]
fn mtu_negotiation_picks_minimum_of_four_values() {
    let mut ccfg = client_cfg(100);
    ccfg.up_stream_mtu = 1200;
    ccfg.down_stream_mtu = 1180;
    let mut scfg = server_cfg(200);
    scfg.up_stream_mtu = 1190;
    scfg.down_stream_mtu = 1132;

    let mut c = RdpeudpSession::new(ccfg);
    let mut s = RdpeudpSession::new_server(scfg);
    let mut syn = Vec::new();
    c.build_syn(&mut syn).unwrap();
    let mut syn_ack = Vec::new();
    s.receive(&syn, &mut syn_ack).unwrap();
    let mut ack = Vec::new();
    c.receive(&syn_ack, &mut ack).unwrap();
    assert_eq!(c.negotiated_mtu(), Some(1132));
    assert_eq!(s.negotiated_mtu(), Some(1132));
}

#[test]
fn mtu_boundary_min_and_max_accepted() {
    let mut ccfg = client_cfg(100);
    ccfg.up_stream_mtu = RDPUDP_MIN_MTU;
    ccfg.down_stream_mtu = RDPUDP_MAX_MTU;
    let mut scfg = server_cfg(200);
    scfg.up_stream_mtu = RDPUDP_MAX_MTU;
    scfg.down_stream_mtu = RDPUDP_MIN_MTU;

    let (c, s) = {
        let mut c = RdpeudpSession::new(ccfg);
        let mut s = RdpeudpSession::new_server(scfg);
        let mut syn = Vec::new();
        c.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        s.receive(&syn, &mut syn_ack).unwrap();
        let mut ack = Vec::new();
        c.receive(&syn_ack, &mut ack).unwrap();
        let mut no = Vec::new();
        s.receive(&ack, &mut no).unwrap();
        (c, s)
    };
    assert_eq!(c.negotiated_mtu(), Some(RDPUDP_MIN_MTU));
    assert_eq!(s.negotiated_mtu(), Some(RDPUDP_MIN_MTU));
}

// =============================================================================
// 8. 프로토콜 버전 1/2/3 지원
// =============================================================================

#[test]
fn version_negotiation_v1_only() {
    let mut ccfg = client_cfg(100);
    ccfg.protocol_version = RDPUDP_PROTOCOL_VERSION_1;
    let mut scfg = server_cfg(200);
    scfg.protocol_version = RDPUDP_PROTOCOL_VERSION_1;

    let (c, s) = {
        let mut c = RdpeudpSession::new(ccfg);
        let mut s = RdpeudpSession::new_server(scfg);
        let mut syn = Vec::new();
        c.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        s.receive(&syn, &mut syn_ack).unwrap();
        let mut ack = Vec::new();
        c.receive(&syn_ack, &mut ack).unwrap();
        let mut no = Vec::new();
        s.receive(&ack, &mut no).unwrap();
        (c, s)
    };
    assert_eq!(c.negotiated_version(), Some(RDPUDP_PROTOCOL_VERSION_1));
    assert_eq!(s.negotiated_version(), Some(RDPUDP_PROTOCOL_VERSION_1));
}

#[test]
fn version_negotiation_picks_min() {
    let mut ccfg = client_cfg(100);
    ccfg.protocol_version = RDPUDP_PROTOCOL_VERSION_3;
    let mut scfg = server_cfg(200);
    scfg.protocol_version = RDPUDP_PROTOCOL_VERSION_2;

    let (c, s) = {
        let mut c = RdpeudpSession::new(ccfg);
        let mut s = RdpeudpSession::new_server(scfg);
        let mut syn = Vec::new();
        c.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        s.receive(&syn, &mut syn_ack).unwrap();
        let mut ack = Vec::new();
        c.receive(&syn_ack, &mut ack).unwrap();
        let mut no = Vec::new();
        s.receive(&ack, &mut no).unwrap();
        (c, s)
    };
    assert_eq!(c.negotiated_version(), Some(RDPUDP_PROTOCOL_VERSION_2));
    assert_eq!(s.negotiated_version(), Some(RDPUDP_PROTOCOL_VERSION_2));
}

#[test]
fn version_v3_client_syn_with_cookie_hash() {
    let mut ccfg = client_cfg(100);
    ccfg.protocol_version = RDPUDP_PROTOCOL_VERSION_3;
    ccfg.cookie_hash = Some([0xAB; 32]);
    let mut c = RdpeudpSession::new(ccfg);
    let mut syn = Vec::new();
    c.build_syn(&mut syn).unwrap();

    // Parse the SYN and verify SYNEX with cookie hash.
    let mut cur = justrdp_core::ReadCursor::new(&syn);
    let hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
    assert_ne!(hdr.u_flags & RDPUDP_FLAG_SYNEX, 0);
    let _syn_data = SynDataPayload::decode(&mut cur).unwrap();
    let synex = SynDataExPayload::decode_with_cookie(&mut cur, true).unwrap();
    assert_eq!(synex.u_udp_ver, RDPUDP_PROTOCOL_VERSION_3);
    assert_eq!(synex.cookie_hash, Some([0xAB; 32]));
}

#[test]
fn version_no_synex_implies_v1() {
    let mut ccfg = client_cfg(100);
    ccfg.protocol_version = 0; // omit SYNEX entirely
    let mut scfg = server_cfg(200);
    scfg.protocol_version = 0;

    let (c, s) = {
        let mut c = RdpeudpSession::new(ccfg);
        let mut s = RdpeudpSession::new_server(scfg);
        let mut syn = Vec::new();
        c.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        s.receive(&syn, &mut syn_ack).unwrap();
        let mut ack = Vec::new();
        c.receive(&syn_ack, &mut ack).unwrap();
        let mut no = Vec::new();
        s.receive(&ack, &mut no).unwrap();
        (c, s)
    };
    assert_eq!(c.negotiated_version(), None); // no SYNEX → no version
    assert_eq!(s.negotiated_version(), None);
}

// =============================================================================
// 9. Lossy 모드
// =============================================================================

#[test]
fn lossy_mode_negotiated_when_both_agree() {
    let mut ccfg = client_cfg(100);
    ccfg.lossy = true;
    let mut scfg = server_cfg(200);
    scfg.lossy = true;

    let (c, s) = drive_to_connected_custom(ccfg, scfg);
    assert!(c.negotiated_lossy());
    assert!(s.negotiated_lossy());
}

#[test]
fn lossy_mode_not_negotiated_when_one_disagrees() {
    let mut ccfg = client_cfg(100);
    ccfg.lossy = true;
    let scfg = server_cfg(200); // lossy = false

    let (c, s) = drive_to_connected_custom(ccfg, scfg);
    assert!(!c.negotiated_lossy());
    assert!(!s.negotiated_lossy());
}

#[test]
fn lossy_mode_fec_recovery_still_works() {
    // Even in lossy mode, FEC can recover single losses.
    let sources: Vec<&[u8]> = vec![b"lossy-1", b"lossy-2"];
    let fec = fec_encode(&sources);
    let recovered = fec_recover(&fec, &[b"lossy-1"]).unwrap();
    assert_eq!(recovered, b"lossy-2");
}

fn drive_to_connected_custom(
    ccfg: RdpeudpConfig,
    scfg: RdpeudpConfig,
) -> (RdpeudpSession, RdpeudpSession) {
    let mut c = RdpeudpSession::new(ccfg);
    let mut s = RdpeudpSession::new_server(scfg);
    let mut syn = Vec::new();
    c.build_syn(&mut syn).unwrap();
    let mut syn_ack = Vec::new();
    s.receive(&syn, &mut syn_ack).unwrap();
    let mut ack = Vec::new();
    c.receive(&syn_ack, &mut ack).unwrap();
    let mut no = Vec::new();
    s.receive(&ack, &mut no).unwrap();
    (c, s)
}

// =============================================================================
// 10. TLS over UDP / DTLS — stubs
// =============================================================================

/// TLS over UDP (DTLS) requires `justrdp-tls` extension — not
/// implemented yet. This test documents the expected integration
/// point: after the 3-way handshake, a DTLS handshake runs over the
/// same UDP socket before any RDP data is sent.
#[test]
fn dtls_integration_point_documented() {
    // After handshake, the session reports Connected.
    let (c, _s) = drive_to_connected(100, 200);
    assert!(c.is_connected());
    // Future: c.start_dtls_handshake(...) → drives DTLS ClientHello
    // over the same session, producing datagrams to send.
    // For now, this is a documentation-only test.
}
