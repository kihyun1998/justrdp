//! Differential oracle (ADR-0001 / ADR-0003): decode/encode the same X.224 negotiation PDUs with
//! both `justrdp-pdu` and `ironrdp-pdu` and assert the parsed protocol fields agree. This guards
//! our hand-rolled TPKT/X.224/NEG wire code against an independently-written reference.

use justrdp_pdu::nego::{NegRequest, NegResponse, SecurityProtocol};

use ironrdp_pdu::decode as ironrdp_decode;
use ironrdp_pdu::nego::{
    ConnectionConfirm as IronConfirm, ConnectionRequest as IronRequest,
    SecurityProtocol as IronProtocol,
};
use ironrdp_pdu::x224::X224;

/// Build a full Connection Request frame (TPKT + X.224 CR + RDP_NEG_REQ) the way justrdp emits it.
fn our_connection_request(protocols: SecurityProtocol) -> Vec<u8> {
    let neg = NegRequest::new(protocols).encode();
    let tpdu = justrdp_pdu::x224::encode_connection_request(&neg);
    justrdp_pdu::tpkt::encode(&tpdu)
}

/// Build a Connection Confirm frame (TPKT + X.224 CC + RDP_NEG_RSP) selecting `selected`.
fn confirm_frame(selected: SecurityProtocol) -> Vec<u8> {
    let [s0, s1, s2, s3] = selected.bits().to_le_bytes();
    let mut cc = vec![0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00];
    cc.extend_from_slice(&[0x02, 0x00, 0x08, 0x00, s0, s1, s2, s3]);
    justrdp_pdu::tpkt::encode(&cc)
}

#[test]
fn our_connection_request_decodes_identically_in_ironrdp() {
    let protocols = SecurityProtocol::SSL | SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX;
    let frame = our_connection_request(protocols);

    // ironrdp parses the bytes justrdp produced; the advertised protocol bitmask must match.
    let parsed: X224<IronRequest> = ironrdp_decode(&frame).expect("ironrdp decodes our CR");
    let expected = IronProtocol::SSL | IronProtocol::HYBRID | IronProtocol::HYBRID_EX;
    assert_eq!(parsed.0.protocol, expected);
    assert_eq!(parsed.0.protocol.bits(), protocols.bits());
}

#[test]
fn connection_confirm_selected_protocol_matches_ironrdp() {
    // HYBRID_EX (0x08) — the protocol the real test VM selected.
    let frame = confirm_frame(SecurityProtocol::HYBRID_EX);

    // justrdp decode.
    let ours = {
        let tpdu = justrdp_pdu::tpkt::decode(&frame).unwrap();
        let variable = justrdp_pdu::x224::decode_connection_confirm(tpdu).unwrap();
        NegResponse::decode(variable).unwrap()
    };

    // ironrdp decode.
    let theirs: X224<IronConfirm> = ironrdp_decode(&frame).expect("ironrdp decodes the CC");

    match (ours, theirs.0) {
        (NegResponse::Selected(ours_proto), IronConfirm::Response { protocol, .. }) => {
            assert_eq!(ours_proto.bits(), protocol.bits(), "selected protocol differs");
        }
        (ours, theirs) => panic!("decode shape mismatch: justrdp={ours:?}, ironrdp={theirs:?}"),
    }
}
