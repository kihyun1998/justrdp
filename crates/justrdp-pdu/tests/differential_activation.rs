//! Differential oracle for slice-5 wire formats (ADR-0001): licensing (MS-RDPELE), Demand /
//! Confirm Active capability sets, and the finalization PDUs, cross-checked against
//! `ironrdp-pdu` — our encoder against their decoder and vice versa, never our own bytes
//! against ourselves.

use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::{capability, client_info, finalization, gcc, license, share};

use ironrdp_pdu::decode as ironrdp_decode;
use ironrdp_pdu::encode_vec as ironrdp_encode_vec;
use ironrdp_pdu::rdp::capability_sets as iron_caps;
use ironrdp_pdu::rdp::headers as iron_headers;
use ironrdp_pdu::rdp::server_license as iron_license;

/// The GCC core data our default Confirm Active capabilities derive from.
fn sample_core() -> gcc::ClientCoreData {
    gcc::ClientCoreData {
        version: gcc::RDP_VERSION_10_12,
        desktop_width: 1280,
        desktop_height: 800,
        keyboard_layout: 0x0412,
        client_build: 1,
        client_name: "diff-test".to_string(),
        keyboard_type: gcc::KEYBOARD_TYPE_IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        post_beta2_color_depth: gcc::COLOR_DEPTH_8BPP,
        client_product_id: 1,
        serial_number: 0,
        high_color_depth: gcc::HIGH_COLOR_DEPTH_24BPP,
        supported_color_depths: gcc::SUPPORTED_COLOR_DEPTH_24BPP,
        early_capability_flags: gcc::ClientEarlyCapabilityFlags::empty(),
        dig_product_id: String::new(),
        connection_type: gcc::CONNECTION_TYPE_LAN,
        server_selected_protocol: justrdp_pdu::nego::SecurityProtocol::from_bits(0),
    }
}

// ───────────────────────────────────── licensing ─────────────────────────────────────────────

#[test]
fn our_new_license_request_decodes_identically_in_ironrdp() {
    let client_random = [0x11u8; 32];
    let encrypted_premaster = vec![0xEE; 72];
    let ours = license::encode_new_license_request(
        license::PLATFORM_ID_NT_POST_52_MICROSOFT,
        &client_random,
        &encrypted_premaster,
        "diff-user",
        "diff-host",
    );

    let theirs: iron_license::LicensePdu =
        ironrdp_decode(&ours).expect("ironrdp decodes our New License Request");
    let iron_license::LicensePdu::ClientNewLicenseRequest(parsed) = theirs else {
        panic!("ironrdp parsed a different message type: {theirs:?}");
    };
    assert_eq!(parsed.client_random, client_random);
    assert_eq!(parsed.encrypted_premaster_secret, encrypted_premaster);
    assert_eq!(parsed.client_username, "diff-user");
    assert_eq!(parsed.client_machine_name, "diff-host");
}

#[test]
fn ironrdp_valid_client_error_alert_decodes_as_our_short_circuit() {
    let theirs: iron_license::LicensePdu = iron_license::LicensingErrorMessage::new_valid_client()
        .expect("ironrdp builds the STATUS_VALID_CLIENT alert")
        .into();
    let bytes = ironrdp_encode_vec(&theirs).unwrap();

    let mut cur = ReadCursor::new(&bytes, "alert");
    let flags = client_info::decode_basic_security_header(&mut cur).unwrap();
    assert_ne!(flags & client_info::SEC_LICENSE_PKT, 0);
    let preamble = license::LicensePreamble::decode(&mut cur).unwrap();
    assert_eq!(preamble.msg_type, license::MSG_ERROR_ALERT);
    let alert = license::LicenseError::decode(&mut cur).unwrap();
    assert_eq!(alert.error_code, license::STATUS_VALID_CLIENT);
    assert_eq!(alert.state_transition, license::ST_NO_TRANSITION);
}

/// A synthetic Server License Request with a proprietary certificate, in raw bytes (the same
/// builder the state-machine tests use).
fn server_license_request_bytes(modulus_be: &[u8], exponent: u32) -> Vec<u8> {
    let bitlen = modulus_be.len() * 8;
    let keylen = modulus_be.len() + 8;
    let mut key = Vec::new();
    key.extend_from_slice(&0x3141_5352u32.to_le_bytes());
    key.extend_from_slice(&(keylen as u32).to_le_bytes());
    key.extend_from_slice(&(bitlen as u32).to_le_bytes());
    key.extend_from_slice(&((bitlen / 8 - 1) as u32).to_le_bytes());
    key.extend_from_slice(&exponent.to_le_bytes());
    let mut le = modulus_be.to_vec();
    le.reverse();
    key.extend_from_slice(&le);
    key.extend_from_slice(&[0u8; 8]);

    let mut cert = Vec::new();
    cert.extend_from_slice(&1u32.to_le_bytes());
    cert.extend_from_slice(&1u32.to_le_bytes());
    cert.extend_from_slice(&1u32.to_le_bytes());
    cert.extend_from_slice(&0x0006u16.to_le_bytes());
    cert.extend_from_slice(&(key.len() as u16).to_le_bytes());
    cert.extend_from_slice(&key);
    // Signature blob — present on the wire (ironrdp's decoder requires it); neither stack
    // verifies it (licensing rides inside the authenticated TLS session).
    cert.extend_from_slice(&0x0008u16.to_le_bytes());
    cert.extend_from_slice(&72u16.to_le_bytes());
    cert.extend_from_slice(&[0x51; 72]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x5A; 32]); // server random
    body.extend_from_slice(&0x0006_0000u32.to_le_bytes());
    body.extend_from_slice(&4u32.to_le_bytes());
    body.extend_from_slice(b"M\0S\0");
    body.extend_from_slice(&2u32.to_le_bytes());
    body.extend_from_slice(b"A\0");
    body.extend_from_slice(&0x000Du16.to_le_bytes());
    body.extend_from_slice(&4u16.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&0x0003u16.to_le_bytes());
    body.extend_from_slice(&(cert.len() as u16).to_le_bytes());
    body.extend_from_slice(&cert);
    body.extend_from_slice(&0u32.to_le_bytes()); // ScopeCount

    let mut msg = Vec::new();
    client_info::encode_basic_security_header(&mut msg, client_info::SEC_LICENSE_PKT);
    msg.push(license::MSG_LICENSE_REQUEST);
    msg.push(0x03);
    msg.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
    msg.extend_from_slice(&body);
    msg
}

#[test]
fn server_license_request_parses_to_the_same_rsa_key_in_both_stacks() {
    let modulus_be = {
        let mut m = vec![0xC3u8; 64];
        m[0] = 0xF1; // top bit set, distinct leading byte
        m
    };
    let bytes = server_license_request_bytes(&modulus_be, 65537);

    // Ours.
    let mut cur = ReadCursor::new(&bytes, "request");
    client_info::decode_basic_security_header(&mut cur).unwrap();
    license::LicensePreamble::decode(&mut cur).unwrap();
    let ours = license::ServerLicenseRequest::decode(&mut cur).unwrap();
    assert_eq!(ours.server_random, [0x5A; 32]);
    let license::ServerCertificate::Proprietary(our_key) = ours.certificate.unwrap() else {
        panic!("expected a proprietary certificate");
    };

    assert_eq!(our_key.modulus, modulus_be);
    assert_eq!(our_key.exponent, 65537);

    // Theirs: get_public_key() yields a PKCS#1 RSAPublicKey DER. Oracle caveat: ironrdp 0.8
    // copies the proprietary blob's integers into the DER **verbatim** — but the wire stores
    // them little-endian (MS-RDPBCGR 2.2.1.4.3.1.1.1), so their DER holds byte-reversed
    // values (a known ironrdp endianness defect; FreeRDP reverses, we reverse). The
    // differential assertion is therefore on the relationship: both stacks must have read the
    // same wire bytes, theirs unreversed with the 8 padding bytes still attached.
    let theirs: iron_license::LicensePdu =
        ironrdp_decode(&bytes).expect("ironrdp decodes the License Request");
    let iron_license::LicensePdu::ServerLicenseRequest(parsed) = theirs else {
        panic!("ironrdp parsed a different message type");
    };
    assert_eq!(parsed.server_random, [0x5A; 32]);
    let der = parsed
        .get_public_key()
        .expect("ironrdp extracts the key")
        .expect("certificate present");
    let their_key = license::RsaPublicKey::from_pkcs1_der(&der).unwrap();
    let mut their_modulus_reversed = their_key.modulus.clone();
    their_modulus_reversed.reverse();
    // Reversing their (wire-LE) modulus and dropping the now-leading padding yields ours.
    assert_eq!(their_modulus_reversed[..8], [0u8; 8]);
    assert_eq!(their_modulus_reversed[8..], our_key.modulus[..]);
    // Their exponent bytes are wire-LE read as BE; swapping restores the real value.
    assert_eq!(their_key.exponent.swap_bytes(), our_key.exponent);
}

#[test]
fn our_platform_challenge_response_decodes_identically_in_ironrdp() {
    let encrypted_response = vec![0x21; 23];
    let encrypted_hwid = vec![0x42; 20];
    let mac = [0x77u8; 16];
    let ours =
        license::encode_platform_challenge_response(&encrypted_response, &encrypted_hwid, &mac);

    let theirs: iron_license::LicensePdu =
        ironrdp_decode(&ours).expect("ironrdp decodes our Platform Challenge Response");
    let iron_license::LicensePdu::ClientPlatformChallengeResponse(parsed) = theirs else {
        panic!("ironrdp parsed a different message type");
    };
    assert_eq!(parsed.encrypted_challenge_response_data, encrypted_response);
    assert_eq!(parsed.encrypted_hwid, encrypted_hwid);
    assert_eq!(parsed.mac_data, mac);
}

// ─────────────────────────────── capability exchange ─────────────────────────────────────────

#[test]
fn ironrdp_demand_active_decodes_to_the_same_capability_fields() {
    let their_sets = vec![
        iron_caps::CapabilitySet::General(iron_caps::General {
            major_platform_type: iron_caps::MajorPlatformType::WINDOWS,
            minor_platform_type: iron_caps::MinorPlatformType::WINDOWS_NT,
            protocol_version: iron_caps::PROTOCOL_VER,
            extra_flags: iron_caps::GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED
                | iron_caps::GeneralExtraFlags::NO_BITMAP_COMPRESSION_HDR,
            refresh_rect_support: true,
            suppress_output_support: true,
        }),
        iron_caps::CapabilitySet::Bitmap(iron_caps::Bitmap {
            pref_bits_per_pix: 32,
            desktop_width: 1920,
            desktop_height: 1080,
            desktop_resize_flag: true,
            drawing_flags: iron_caps::BitmapDrawingFlags::empty(),
        }),
        iron_caps::CapabilitySet::Input(iron_caps::Input {
            input_flags: iron_caps::InputFlags::SCANCODES | iron_caps::InputFlags::FASTPATH_INPUT,
            keyboard_layout: 0x0412,
            keyboard_type: Some(ironrdp_pdu::gcc::KeyboardType::IbmEnhanced),
            keyboard_subtype: 0,
            keyboard_function_key: 12,
            keyboard_ime_filename: String::new(),
        }),
        iron_caps::CapabilitySet::Pointer(iron_caps::Pointer {
            color_pointer_cache_size: 25,
            pointer_cache_size: 25,
        }),
        iron_caps::CapabilitySet::BitmapCodecs(iron_caps::BitmapCodecs(vec![iron_caps::Codec {
            id: 3,
            property: iron_caps::CodecProperty::NsCodec(iron_caps::NsCodec {
                is_dynamic_fidelity_allowed: true,
                is_subsampling_allowed: true,
                color_loss_level: 3,
            }),
        }])),
    ];
    let frame = ironrdp_encode_vec(&iron_headers::ShareControlHeader {
        share_control_pdu: iron_headers::ShareControlPdu::ServerDemandActive(
            iron_caps::ServerDemandActive {
                pdu: iron_caps::DemandActive {
                    source_descriptor: "RDP".to_string(),
                    capability_sets: their_sets,
                },
            },
        ),
        pdu_source: 1002,
        share_id: 0x0001_03EA,
    })
    .unwrap();

    let mut cur = ReadCursor::new(&frame, "demand active");
    let header = share::ShareControlHeader::decode(&mut cur).unwrap();
    assert_eq!(header.pdu_type, share::PDU_TYPE_DEMAND_ACTIVE);
    assert_eq!(header.pdu_source, 1002);
    assert_eq!(header.share_id, 0x0001_03EA);
    let demand = capability::DemandActive::decode(&mut cur).unwrap();
    assert_eq!(cur.remaining(), 0, "sessionId consumed");
    assert_eq!(demand.capability_sets.len(), 5);

    // Spot-checks per the issue's differential criterion: General extraFlags, Bitmap color
    // depth + size, Input flags, BitmapCodecs identity.
    let general = demand
        .capability_sets
        .iter()
        .find_map(|c| match c {
            capability::CapabilitySet::General(g) => Some(g),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        general.extra_flags,
        capability::GENERAL_FASTPATH_OUTPUT_SUPPORTED
            | capability::GENERAL_NO_BITMAP_COMPRESSION_HDR
    );
    assert_eq!((general.refresh_rect_support, general.suppress_output_support), (1, 1));

    let bitmap = demand.bitmap().unwrap();
    assert_eq!(bitmap.preferred_bits_per_pixel, 32);
    assert_eq!((bitmap.desktop_width, bitmap.desktop_height), (1920, 1080));
    assert_eq!(bitmap.desktop_resize_flag, 1);

    let input = demand
        .capability_sets
        .iter()
        .find_map(|c| match c {
            capability::CapabilitySet::Input(i) => Some(i),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        input.input_flags,
        capability::INPUT_FLAG_SCANCODES | capability::INPUT_FLAG_FASTPATH_INPUT
    );
    assert_eq!(input.keyboard_layout, 0x0412);

    let pointer = demand
        .capability_sets
        .iter()
        .find_map(|c| match c {
            capability::CapabilitySet::Pointer(p) => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(pointer.color_pointer_cache_size, 25);

    let codecs = demand
        .capability_sets
        .iter()
        .find_map(|c| match c {
            capability::CapabilitySet::BitmapCodecs(b) => Some(b),
            _ => None,
        })
        .unwrap();
    assert_eq!(codecs.codecs.len(), 1);
    assert_eq!(codecs.codecs[0].id, 3);
    // The NSCodec GUID in wire order (Data1/2/3 little-endian, Data4 verbatim).
    assert_eq!(
        codecs.codecs[0].guid,
        [
            0xb9, 0x1b, 0x8d, 0xca, 0x0f, 0x00, 0x4f, 0x15, //
            0x58, 0x9f, 0xae, 0x2d, 0x1a, 0x87, 0xe2, 0xd6
        ]
    );
    assert_eq!(codecs.codecs[0].properties.len(), 3);
}

#[test]
fn our_confirm_active_with_default_capabilities_decodes_in_ironrdp() {
    let core = sample_core();
    let caps = capability::default_client_capabilities(&core);
    let frame = share::encode_share_control(
        share::PDU_TYPE_CONFIRM_ACTIVE,
        1007,
        0x0001_03EA,
        &capability::encode_confirm_active(1002, b"justrdp\0", &caps),
    );

    let theirs: iron_headers::ShareControlHeader =
        ironrdp_decode(&frame).expect("ironrdp decodes our Confirm Active");
    assert_eq!(theirs.pdu_source, 1007);
    assert_eq!(theirs.share_id, 0x0001_03EA);
    let iron_headers::ShareControlPdu::ClientConfirmActive(confirm) = theirs.share_control_pdu
    else {
        panic!("ironrdp parsed a different share PDU");
    };
    assert_eq!(confirm.originator_id, 1002);
    assert_eq!(confirm.pdu.capability_sets.len(), caps.len());

    // The fields the server actually negotiates on must survive their parse.
    for set in &confirm.pdu.capability_sets {
        match set {
            iron_caps::CapabilitySet::Bitmap(bitmap) => {
                assert_eq!(bitmap.pref_bits_per_pix, gcc::HIGH_COLOR_DEPTH_24BPP);
                assert_eq!((bitmap.desktop_width, bitmap.desktop_height), (1280, 800));
                assert!(bitmap.desktop_resize_flag);
            }
            iron_caps::CapabilitySet::Input(input) => {
                assert!(input.input_flags.contains(iron_caps::InputFlags::SCANCODES));
                assert!(input.input_flags.contains(iron_caps::InputFlags::UNICODE));
                assert_eq!(input.keyboard_layout, 0x0412);
                assert_eq!(input.keyboard_function_key, 12);
            }
            // Order's fields are private in ironrdp 0.8; its successful strict parse (84-byte
            // fixed layout) is the differential signal, and our own unit tests pin the bytes.
            iron_caps::CapabilitySet::Order(_) => {}
            _ => {}
        }
    }
}

// ───────────────────────────────────── finalization ──────────────────────────────────────────

/// One finalization case: the frame our encoder built, and the assertion ironrdp's parse of it
/// must satisfy.
type FinalizationCase = (Vec<u8>, fn(&iron_headers::ShareDataPdu));

#[test]
fn our_finalization_batch_decodes_identically_in_ironrdp() {
    let cases: Vec<FinalizationCase> = vec![
        (
            share::encode_share_data(
                1007,
                7,
                share::STREAM_MED,
                share::PDU_TYPE2_SYNCHRONIZE,
                &finalization::Synchronize { target_user: 1002 }.encode(),
            ),
            |pdu| {
                let iron_headers::ShareDataPdu::Synchronize(sync) = pdu else {
                    panic!("expected Synchronize, got {pdu:?}");
                };
                assert_eq!(sync.target_user_id, 1002);
            },
        ),
        (
            share::encode_share_data(
                1007,
                7,
                share::STREAM_MED,
                share::PDU_TYPE2_CONTROL,
                &finalization::Control::new(finalization::CTRLACTION_COOPERATE).encode(),
            ),
            |pdu| {
                let iron_headers::ShareDataPdu::Control(control) = pdu else {
                    panic!("expected Control, got {pdu:?}");
                };
                assert_eq!(
                    control.action,
                    ironrdp_pdu::rdp::finalization_messages::ControlAction::Cooperate
                );
            },
        ),
        (
            share::encode_share_data(
                1007,
                7,
                share::STREAM_MED,
                share::PDU_TYPE2_CONTROL,
                &finalization::Control::new(finalization::CTRLACTION_REQUEST_CONTROL).encode(),
            ),
            |pdu| {
                let iron_headers::ShareDataPdu::Control(control) = pdu else {
                    panic!("expected Control, got {pdu:?}");
                };
                assert_eq!(
                    control.action,
                    ironrdp_pdu::rdp::finalization_messages::ControlAction::RequestControl
                );
            },
        ),
        (
            share::encode_share_data(
                1007,
                7,
                share::STREAM_MED,
                share::PDU_TYPE2_FONT_LIST,
                &finalization::encode_font_list(),
            ),
            |pdu| {
                let iron_headers::ShareDataPdu::FontList(fonts) = pdu else {
                    panic!("expected FontList, got {pdu:?}");
                };
                assert_eq!(fonts.number, 0);
                assert_eq!(fonts.total_number, 0);
                assert_eq!(fonts.entry_size, 0x32);
            },
        ),
    ];

    for (frame, check) in cases {
        let theirs: iron_headers::ShareControlHeader =
            ironrdp_decode(&frame).expect("ironrdp decodes our finalization PDU");
        let iron_headers::ShareControlPdu::Data(data) = theirs.share_control_pdu else {
            panic!("expected a data PDU");
        };
        check(&data.share_data_pdu);
    }
}

#[test]
fn ironrdp_font_map_decodes_as_our_session_active_gate() {
    let frame = ironrdp_encode_vec(&iron_headers::ShareControlHeader {
        share_control_pdu: iron_headers::ShareControlPdu::Data(iron_headers::ShareDataHeader {
            share_data_pdu: iron_headers::ShareDataPdu::FontMap(
                ironrdp_pdu::rdp::finalization_messages::FontPdu {
                    number: 0,
                    total_number: 0,
                    flags: ironrdp_pdu::rdp::finalization_messages::SequenceFlags::FIRST
                        | ironrdp_pdu::rdp::finalization_messages::SequenceFlags::LAST,
                    entry_size: 4,
                },
            ),
            stream_priority: iron_headers::StreamPriority::Medium,
            compression_flags: iron_headers::CompressionFlags::empty(),
            compression_type: ironrdp_pdu::rdp::client_info::CompressionType::K8,
        }),
        pdu_source: 1002,
        share_id: 0x0001_03EA,
    })
    .unwrap();

    let mut cur = ReadCursor::new(&frame, "font map");
    let header = share::ShareControlHeader::decode(&mut cur).unwrap();
    assert_eq!(header.pdu_type, share::PDU_TYPE_DATA);
    let data = share::ShareDataHeader::decode(&mut cur).unwrap();
    assert_eq!(data.pdu_type2, share::PDU_TYPE2_FONT_MAP);
    let map = finalization::FontMap::decode(&mut cur).unwrap();
    assert_eq!(map.map_flags, 0x0003);
}
