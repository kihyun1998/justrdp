//! Differential oracle (ADR-0001 / ADR-0003): decode/encode the same X.224 negotiation PDUs with
//! both `justrdp-pdu` and `ironrdp-pdu` and assert the parsed protocol fields agree. This guards
//! our hand-rolled TPKT/X.224/NEG wire code against an independently-written reference.

use justrdp_pdu::nego::{NegRequest, NegResponse, SecurityProtocol};
use justrdp_pdu::{gcc, mcs};

use ironrdp_pdu::decode as ironrdp_decode;
use ironrdp_pdu::encode_vec as ironrdp_encode_vec;
use ironrdp_pdu::gcc as iron_gcc;
use ironrdp_pdu::mcs as iron_mcs;
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

/// A representative client GCC block set: distinctive values in every caller-policy field so a
/// byte-offset slip shows up as a field mismatch on the other side.
fn our_gcc_blocks() -> gcc::ClientGccBlocks {
    gcc::ClientGccBlocks {
        core: gcc::ClientCoreData {
            version: gcc::RDP_VERSION_10_12,
            desktop_width: 1920,
            desktop_height: 1080,
            keyboard_layout: 0x0412,
            client_build: 23456,
            client_name: "DIFFTEST".to_string(),
            keyboard_type: gcc::KEYBOARD_TYPE_IBM_ENHANCED,
            keyboard_subtype: 3,
            keyboard_functional_keys_count: 12,
            ime_file_name: String::new(),
            post_beta2_color_depth: gcc::COLOR_DEPTH_8BPP,
            client_product_id: 1,
            serial_number: 0,
            high_color_depth: gcc::HIGH_COLOR_DEPTH_24BPP,
            supported_color_depths: gcc::SUPPORTED_COLOR_DEPTH_24BPP
                | gcc::SUPPORTED_COLOR_DEPTH_16BPP
                | gcc::SUPPORTED_COLOR_DEPTH_32BPP,
            // All twelve early-capability flags set — the caller-controlled EGFX gate included.
            early_capability_flags: gcc::ClientEarlyCapabilityFlags::from_bits(0x0FFF),
            dig_product_id: String::new(),
            connection_type: gcc::CONNECTION_TYPE_LAN,
            server_selected_protocol: SecurityProtocol::HYBRID_EX,
        },
        security: gcc::ClientSecurityData::default(),
        network: gcc::ClientNetworkData {
            channels: vec![
                gcc::ChannelDef::new("cliprdr", gcc::CHANNEL_OPTION_INITIALIZED).unwrap(),
                gcc::ChannelDef::new("drdynvc", gcc::CHANNEL_OPTION_INITIALIZED).unwrap(),
            ],
        },
    }
}

#[test]
fn our_connect_initial_decodes_identically_in_ironrdp() {
    // justrdp encodes the full MCS Connect-Initial (BER + T.124 PER wrapper + GCC blocks);
    // ironrdp must parse back every caller-policy field bit-for-bit.
    let body = mcs::encode_connect_initial(&our_gcc_blocks());

    let parsed: iron_mcs::ConnectInitial =
        ironrdp_decode(&body).expect("ironrdp decodes our Connect-Initial");

    let gcc_blocks = parsed.conference_create_request.gcc_blocks();
    let core = &gcc_blocks.core;
    assert_eq!(core.version.0, gcc::RDP_VERSION_10_12);
    assert_eq!(core.desktop_width, 1920);
    assert_eq!(core.desktop_height, 1080);
    assert_eq!(core.keyboard_layout, 0x0412);
    assert_eq!(core.client_build, 23456);
    assert_eq!(core.client_name, "DIFFTEST");
    let optional = &core.optional_data;
    assert_eq!(
        optional.early_capability_flags.unwrap().bits(),
        0x0FFF,
        "earlyCapabilityFlags must reach the wire verbatim — the EGFX gate (plan.md §0)"
    );
    assert_eq!(
        optional.server_selected_protocol.unwrap().bits(),
        SecurityProtocol::HYBRID_EX.bits()
    );
    assert_eq!(optional.high_color_depth.unwrap() as u16, 0x0018);

    let channels = gcc_blocks.network.as_ref().unwrap();
    let names: Vec<_> = channels
        .channels
        .iter()
        .map(|c| c.name.as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["cliprdr", "drdynvc"]);

    assert_eq!(parsed.calling_domain_selector, vec![0x01]);
    assert!(parsed.upward_flag);
    assert_eq!(parsed.target_parameters.max_mcs_pdu_size, 65535);
}

/// Build a realistic server Connect-Response with ironrdp's encoder.
fn iron_connect_response(skip_channel_join: bool) -> Vec<u8> {
    let flags = if skip_channel_join {
        iron_gcc::ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED
    } else {
        iron_gcc::ServerEarlyCapabilityFlags::empty()
    };
    let blocks = iron_gcc::ServerGccBlocks {
        core: iron_gcc::ServerCoreData {
            version: iron_gcc::RdpVersion::V10_12,
            optional_data: iron_gcc::ServerCoreOptionalData {
                client_requested_protocols: Some(IronProtocol::HYBRID_EX),
                early_capability_flags: Some(flags),
            },
        },
        network: iron_gcc::ServerNetworkData {
            io_channel: 1003,
            channel_ids: vec![1004, 1005],
        },
        security: iron_gcc::ServerSecurityData::no_security(),
        message_channel: None,
        multi_transport_channel: None,
    };
    let response = iron_mcs::ConnectResponse {
        conference_create_response: iron_gcc::ConferenceCreateResponse::new(1002, blocks)
            .expect("blocks fit"),
        called_connect_id: 0,
        domain_parameters: iron_mcs::DomainParameters::target(),
    };
    ironrdp_encode_vec(&response).expect("ironrdp encodes the Connect-Response")
}

#[test]
fn ironrdp_connect_response_decodes_identically_in_justrdp() {
    let bytes = iron_connect_response(true);

    let ours = mcs::decode_connect_response(&bytes).expect("justrdp decodes their response");

    assert_eq!(ours.result, 0);
    assert_eq!(ours.conference.node_id, 1002);
    let blocks = &ours.conference.blocks;
    assert_eq!(blocks.network.io_channel, 1003);
    assert_eq!(blocks.network.channel_ids, vec![1004, 1005]);
    assert!(
        blocks
            .core
            .early_capability_flags
            .unwrap()
            .contains(gcc::ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED)
    );
    assert_eq!(
        blocks.core.client_requested_protocols.unwrap().bits(),
        SecurityProtocol::HYBRID_EX.bits()
    );
    assert_eq!(blocks.security.encryption_method, 0);
    assert_eq!(blocks.security.encryption_level, 0);
}

#[test]
fn ironrdp_attach_user_and_channel_join_confirms_decode_in_justrdp() {
    // ironrdp encodes the full TPKT + X.224 DT + MCS frames; justrdp peels each layer with its
    // own code and decodes the confirms.
    let attach = ironrdp_encode_vec(&X224(iron_mcs::AttachUserConfirm {
        result: 0,
        initiator_id: 1007,
    }))
    .unwrap();
    let payload = justrdp_pdu::tpkt::decode(&attach).unwrap();
    let mcs_body = justrdp_pdu::x224::decode_data(payload).unwrap();
    let confirm = mcs::AttachUserConfirm::decode(mcs_body).unwrap();
    assert_eq!(confirm.result, 0);
    assert_eq!(confirm.initiator_id, 1007);

    let join = ironrdp_encode_vec(&X224(iron_mcs::ChannelJoinConfirm {
        result: 0,
        initiator_id: 1007,
        requested_channel_id: 1004,
        channel_id: 1004,
    }))
    .unwrap();
    let payload = justrdp_pdu::tpkt::decode(&join).unwrap();
    let mcs_body = justrdp_pdu::x224::decode_data(payload).unwrap();
    let confirm = mcs::ChannelJoinConfirm::decode(mcs_body).unwrap();
    assert_eq!(confirm.result, 0);
    assert_eq!(confirm.initiator_id, 1007);
    assert_eq!(confirm.requested_channel_id, 1004);
    assert_eq!(confirm.channel_id, 1004);
}

#[test]
fn our_erect_domain_and_channel_join_requests_decode_in_ironrdp() {
    // Wrap our raw MCS bytes in TPKT + X.224 DT and let ironrdp's full X224<McsMessage>
    // decoder parse them.
    let erect = justrdp_pdu::tpkt::encode(&justrdp_pdu::x224::encode_data(
        &mcs::encode_erect_domain_request(),
    ));
    let parsed: X224<iron_mcs::McsMessage<'_>> =
        ironrdp_decode(&erect).expect("ironrdp decodes our ErectDomainRequest");
    assert!(matches!(
        parsed.0,
        iron_mcs::McsMessage::ErectDomainRequest(iron_mcs::ErectDomainPdu {
            sub_height: 0,
            sub_interval: 0,
        })
    ));

    let join = justrdp_pdu::tpkt::encode(&justrdp_pdu::x224::encode_data(
        &mcs::encode_channel_join_request(1007, 1003),
    ));
    let parsed: X224<iron_mcs::McsMessage<'_>> =
        ironrdp_decode(&join).expect("ironrdp decodes our ChannelJoinRequest");
    match parsed.0 {
        iron_mcs::McsMessage::ChannelJoinRequest(req) => {
            assert_eq!(req.initiator_id, 1007);
            assert_eq!(req.channel_id, 1003);
        }
        other => panic!("expected ChannelJoinRequest, got {other:?}"),
    }
}
