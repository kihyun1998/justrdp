//! PDU roundtrip and spec wire-vector tests for MS-RDPEPNP §2.2.

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};

use crate::constants::{custom_flag, version, PNP_CAP_DYNAMIC_DEVICE_ADDITION};
use crate::pdu::{
    AuthenticatedClientMsg, ClientDeviceAdditionMsg, ClientDeviceRemovalMsg, ClientVersionMsg,
    PnpDeviceDescription, ServerVersionMsg, AUTHENTICATED_CLIENT_MSG_SIZE,
    DEVICE_REMOVAL_MSG_SIZE, VERSION_MSG_SIZE,
};

fn encode_to_vec<E: Encode>(pdu: &E) -> Vec<u8> {
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).unwrap();
    buf
}

fn decode<'a, D: Decode<'a>>(bytes: &'a [u8]) -> D {
    let mut cur = ReadCursor::new(bytes);
    let out = D::decode(&mut cur).unwrap();
    assert_eq!(cur.remaining(), 0, "trailing bytes");
    out
}

// ── ServerVersionMsg ──

#[test]
fn server_version_windows_default_roundtrip() {
    let msg = ServerVersionMsg::new_server_windows_default();
    assert_eq!(msg.major_version, version::SERVER_MAJOR);
    assert_eq!(msg.minor_version, version::SERVER_MINOR);
    assert_eq!(msg.capabilities, PNP_CAP_DYNAMIC_DEVICE_ADDITION);

    let bytes = encode_to_vec(&msg);
    assert_eq!(bytes.len(), VERSION_MSG_SIZE);
    // Header: Size=20 (LE), PacketId=0x65 (LE).
    assert_eq!(&bytes[0..4], &[0x14, 0x00, 0x00, 0x00]);
    assert_eq!(&bytes[4..8], &[0x65, 0x00, 0x00, 0x00]);
    // Payload: 1, 5, 1.
    assert_eq!(&bytes[8..12], &[0x01, 0x00, 0x00, 0x00]);
    assert_eq!(&bytes[12..16], &[0x05, 0x00, 0x00, 0x00]);
    assert_eq!(&bytes[16..20], &[0x01, 0x00, 0x00, 0x00]);

    let decoded: ServerVersionMsg = decode(&bytes);
    assert_eq!(decoded, msg);
}

#[test]
fn server_version_rejects_wrong_packet_id() {
    let mut bytes = encode_to_vec(&ServerVersionMsg::new_server_windows_default());
    bytes[4] = 0x66; // Clobber PacketId to IRPDR_ID_REDIRECT_DEVICES.
    let mut cur = ReadCursor::new(&bytes);
    assert!(ServerVersionMsg::decode(&mut cur).is_err());
}

#[test]
fn server_version_rejects_short_size() {
    let mut bytes = encode_to_vec(&ServerVersionMsg::new_server_windows_default());
    bytes[0] = 0x08; // Size = 8, too small for this payload.
    let mut cur = ReadCursor::new(&bytes);
    assert!(ServerVersionMsg::decode(&mut cur).is_err());
}

// ── ClientVersionMsg ──

#[test]
fn client_version_windows_default_roundtrip() {
    let msg = ClientVersionMsg::new_client_windows_default();
    let bytes = encode_to_vec(&msg);
    assert_eq!(bytes.len(), VERSION_MSG_SIZE);
    // Header is the same shape as ServerVersion (same PacketId).
    assert_eq!(&bytes[4..8], &[0x65, 0x00, 0x00, 0x00]);
    let decoded: ClientVersionMsg = decode(&bytes);
    assert_eq!(decoded.major_version, version::CLIENT_MAJOR);
    assert_eq!(decoded.minor_version, version::CLIENT_MINOR);
    assert_eq!(decoded.capabilities, PNP_CAP_DYNAMIC_DEVICE_ADDITION);
}

// ── AuthenticatedClientMsg ──

#[test]
fn authenticated_client_is_header_only() {
    let msg = AuthenticatedClientMsg;
    let bytes = encode_to_vec(&msg);
    assert_eq!(bytes.len(), AUTHENTICATED_CLIENT_MSG_SIZE);
    // Size = 8, PacketId = 0x67.
    assert_eq!(bytes, vec![0x08, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00]);
    let _: AuthenticatedClientMsg = decode(&bytes);
}

// ── ClientDeviceRemovalMsg — spec §4 wire trace #2 ──

#[test]
fn client_device_removal_matches_spec_wire_trace() {
    // Exact bytes from MS-RDPEPNP §4 trace #2.
    let expected = vec![
        0x0c, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    ];
    let msg = ClientDeviceRemovalMsg {
        client_device_id: 0x00000004,
    };
    let bytes = encode_to_vec(&msg);
    assert_eq!(bytes, expected);
    assert_eq!(bytes.len(), DEVICE_REMOVAL_MSG_SIZE);

    let decoded: ClientDeviceRemovalMsg = decode(&bytes);
    assert_eq!(decoded, msg);
}

// ── PnpDeviceDescription ──

fn sample_device(id: u32) -> PnpDeviceDescription {
    PnpDeviceDescription {
        client_device_id: id,
        interface_guid_array: vec![0u8; 16], // one all-zero GUID
        hardware_id: b"HWID".to_vec(),
        compatibility_id: b"COMP".to_vec(),
        device_description: b"Desc".to_vec(),
        custom_flag: custom_flag::REDIRECTABLE_ALT,
        container_id: None,
        device_caps: None,
    }
}

#[test]
fn addition_msg_roundtrip_single_minimal_device() {
    let msg = ClientDeviceAdditionMsg::new(vec![sample_device(7)]);
    let bytes = encode_to_vec(&msg);
    // Header + DeviceCount + 32 (min desc) + 16 guid + 4 hw + 4 compat + 4 desc.
    let expected_len = 8 + 4 + 32 + 16 + 4 + 4 + 4;
    assert_eq!(bytes.len(), expected_len);
    // PacketId byte.
    assert_eq!(bytes[4], 0x66);

    let decoded: ClientDeviceAdditionMsg = decode(&bytes);
    assert_eq!(decoded, msg);
}

#[test]
fn addition_msg_roundtrip_with_container_and_caps() {
    let mut d = sample_device(42);
    d.container_id = Some([0x11; 16]);
    d.device_caps = Some(
        crate::constants::device_caps::PNP_DEVCAPS_REMOVABLE
            | crate::constants::device_caps::PNP_DEVCAPS_SURPRISEREMOVALOK,
    );
    let msg = ClientDeviceAdditionMsg::new(vec![d.clone()]);
    let bytes = encode_to_vec(&msg);
    let decoded: ClientDeviceAdditionMsg = decode(&bytes);
    assert_eq!(decoded.devices[0], d);
}

#[test]
fn addition_msg_roundtrip_device_caps_only() {
    // Boundary: DeviceCaps present without ContainerId — the decoder must
    // pick the right optional tail by remaining-byte count.
    let mut d = sample_device(1);
    d.device_caps = Some(crate::constants::device_caps::PNP_DEVCAPS_REMOVABLE);
    let msg = ClientDeviceAdditionMsg::new(vec![d.clone()]);
    let bytes = encode_to_vec(&msg);
    let decoded: ClientDeviceAdditionMsg = decode(&bytes);
    assert_eq!(decoded.devices[0].device_caps, Some(4));
    assert_eq!(decoded.devices[0].container_id, None);
}

#[test]
fn decode_rejects_oversize_hardware_id() {
    // Craft a ClientDeviceAdditionMsg wire image whose `cbHardwareId`
    // exceeds MAX_HARDWARE_ID_BYTES. The decoder must refuse to allocate.
    //
    // Layout: header(8) + DeviceCount(4) + ClientDeviceID(4) + DataSize(4)
    //   + cbInterface(4)=0 + cbHw(4)=huge + hw bytes + ...
    // We don't need to supply the huge body; the cap check triggers
    // before read_vec tries to read it.
    let cap = crate::constants::MAX_HARDWARE_ID_BYTES as u32;
    let too_big = cap + 1;
    // Build a minimal prefix with the oversize cb_hw field; the cap
    // rejection runs before any data-slice read, so the actual length
    // of the payload after cb_hw does not need to be correct.
    let data_size: u32 = 32; // min desc, so body_remaining == 24
    let mut bytes = vec![];
    bytes.extend_from_slice(&0x24_u32.to_le_bytes()); // Size=36 hdr+count+ClientDeviceID+DataSize — not used before cap check
    bytes.extend_from_slice(&0x66_u32.to_le_bytes()); // PacketId
    bytes.extend_from_slice(&1_u32.to_le_bytes()); // DeviceCount
    bytes.extend_from_slice(&7_u32.to_le_bytes()); // ClientDeviceID
    bytes.extend_from_slice(&data_size.to_le_bytes()); // DataSize
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // cbInterface
    bytes.extend_from_slice(&too_big.to_le_bytes()); // cbHardwareId — TOO BIG
    // Pad out so body_remaining check at decode() doesn't trigger first.
    bytes.resize(bytes.len() + 64, 0);
    // Patch the header Size so the outer addition-msg body length check
    // accepts the buffer before reaching the cap check.
    let size_val = bytes.len() as u32;
    bytes[0..4].copy_from_slice(&size_val.to_le_bytes());
    let mut cur = ReadCursor::new(&bytes);
    assert!(ClientDeviceAdditionMsg::decode(&mut cur).is_err());
}

#[test]
fn decode_rejects_huge_device_count() {
    // Forge a bogus addition message with DeviceCount = MAX_DEVICES + 1.
    // The hard cap runs before any per-device decoding, so a short body
    // is enough to exercise the rejection.
    let mut bytes = vec![];
    bytes.extend_from_slice(&0x10_u32.to_le_bytes()); // placeholder Size
    bytes.extend_from_slice(&0x66_u32.to_le_bytes()); // PacketId
    let too_many = (crate::constants::MAX_DEVICES as u32) + 1;
    bytes.extend_from_slice(&too_many.to_le_bytes()); // DeviceCount
    let size_val = bytes.len() as u32;
    bytes[0..4].copy_from_slice(&size_val.to_le_bytes());
    let mut cur = ReadCursor::new(&bytes);
    assert!(ClientDeviceAdditionMsg::decode(&mut cur).is_err());
}

#[test]
fn addition_msg_roundtrip_container_only() {
    // Boundary: the decoder must handle ContainerId present without DeviceCaps.
    let mut d = sample_device(1);
    d.container_id = Some([0x22; 16]);
    let msg = ClientDeviceAdditionMsg::new(vec![d.clone()]);
    let bytes = encode_to_vec(&msg);
    let decoded: ClientDeviceAdditionMsg = decode(&bytes);
    assert_eq!(decoded.devices[0].container_id, Some([0x22; 16]));
    assert_eq!(decoded.devices[0].device_caps, None);
}

#[test]
fn addition_msg_rejects_unaligned_interface_guid() {
    let bad = PnpDeviceDescription {
        interface_guid_array: vec![0u8; 15],
        ..sample_device(3)
    };
    let msg = ClientDeviceAdditionMsg::new(vec![bad]);
    let mut buf = vec![0u8; msg.size()];
    let mut cur = WriteCursor::new(&mut buf);
    assert!(msg.encode(&mut cur).is_err());
}

#[test]
fn addition_msg_zero_device_count() {
    let msg = ClientDeviceAdditionMsg::default();
    let bytes = encode_to_vec(&msg);
    // Header + u32 DeviceCount only.
    assert_eq!(bytes.len(), 12);
    let decoded: ClientDeviceAdditionMsg = decode(&bytes);
    assert_eq!(decoded.devices.len(), 0);
}

#[test]
fn addition_msg_multiple_devices_roundtrip() {
    let msg = ClientDeviceAdditionMsg::new(vec![
        sample_device(1),
        sample_device(2),
        sample_device(3),
    ]);
    let bytes = encode_to_vec(&msg);
    let decoded: ClientDeviceAdditionMsg = decode(&bytes);
    assert_eq!(decoded, msg);
}

#[test]
fn addition_msg_rejects_huge_device_count_vs_size() {
    // Build a legitimate zero-device addition, then manually bump
    // DeviceCount to a value that cannot possibly fit in the declared Size.
    let legit = encode_to_vec(&ClientDeviceAdditionMsg::default());
    let mut bytes = legit.clone();
    bytes[8] = 0xff;
    bytes[9] = 0xff;
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    let mut cur = ReadCursor::new(&bytes);
    assert!(ClientDeviceAdditionMsg::decode(&mut cur).is_err());
}

#[test]
fn device_description_decode_rejects_bad_custom_flag_length() {
    let msg = ClientDeviceAdditionMsg::new(vec![sample_device(9)]);
    let mut bytes = encode_to_vec(&msg);
    // CustomFlagLength lives at a known fixed offset past the variable
    // prefix: header(8) + DeviceCount(4) + ClientDeviceID(4) + DataSize(4)
    // + cbInterface(4) + iface(16) + cbHw(4) + hw(4) + cbCompat(4) +
    // compat(4) + cbDesc(4) + desc(4) = 64.
    bytes[64] = 0x05; // Clobber CustomFlagLength low byte to 5.
    let mut cur = ReadCursor::new(&bytes);
    assert!(ClientDeviceAdditionMsg::decode(&mut cur).is_err());
}

#[test]
fn header_size_inclusive_check() {
    // A fixed-size PDU whose header Size mismatches its body byte count
    // must be rejected.
    let mut bytes = encode_to_vec(&ClientDeviceRemovalMsg {
        client_device_id: 1,
    });
    bytes[0] = 0x10; // Size = 16, but body is only 12 bytes.
    let mut cur = ReadCursor::new(&bytes);
    assert!(ClientDeviceRemovalMsg::decode(&mut cur).is_err());
}
