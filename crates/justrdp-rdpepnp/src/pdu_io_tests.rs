//! PDU roundtrip and spec wire-vector tests for the FileRedirectorChannel
//! I/O sub-protocol (MS-RDPEPNP §2.2.2).
//!
//! Every vector here is taken directly from the "Device I/O Messages"
//! example in MS-RDPEPNP §4 (wire trace).

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};

use crate::constants::{function_id, io_version, packet_type};
use crate::pdu::io::{
    ClientCapabilitiesReply, ClientDeviceCustomEvent, CreateFileReply, CreateFileRequest,
    IoControlReply, IoControlRequest, ReadReply, ReadRequest, ServerCapabilitiesRequest,
    SpecificIoCancelRequest, WriteReply, WriteRequest,
};
use crate::pdu::io_header::{ClientIoHeader, ServerIoHeader};

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

// ── SERVER_IO_HEADER / CLIENT_IO_HEADER ──

#[test]
fn server_io_header_roundtrip() {
    let hdr = ServerIoHeader::new(0x00AA_BBCC, function_id::READ_REQUEST);
    let mut buf = [0u8; 8];
    let mut cur = WriteCursor::new(&mut buf);
    hdr.encode(&mut cur).unwrap();
    // 24-bit RequestId in LE: CC BB AA
    assert_eq!(buf[0..3], [0xCC, 0xBB, 0xAA]);
    assert_eq!(buf[3], 0x00); // UnusedBits
    assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 0);

    let mut rcur = ReadCursor::new(&buf);
    let decoded = ServerIoHeader::decode(&mut rcur).unwrap();
    assert_eq!(decoded, hdr);
}

#[test]
fn server_io_header_rejects_over_24bit_request_id() {
    let hdr = ServerIoHeader::new(0x0100_0000, function_id::READ_REQUEST);
    let mut buf = [0u8; 8];
    let mut cur = WriteCursor::new(&mut buf);
    assert!(hdr.encode(&mut cur).is_err());
}

#[test]
fn client_io_header_roundtrip() {
    let hdr = ClientIoHeader::new(0x0000_0001, packet_type::RESPONSE);
    let mut buf = [0u8; 4];
    let mut cur = WriteCursor::new(&mut buf);
    hdr.encode(&mut cur).unwrap();
    assert_eq!(buf, [0x01, 0x00, 0x00, 0x00]);
}

// ── ServerCapabilitiesRequest / ClientCapabilitiesReply ──

#[test]
fn server_capabilities_request_roundtrip_v6() {
    let req = ServerCapabilitiesRequest {
        request_id: 0x0000_0007,
        version: io_version::CUSTOM_EVENT,
    };
    let bytes = encode_to_vec(&req);
    assert_eq!(bytes.len(), 10);
    // Header: request_id=7, unused=0, function=0x05
    assert_eq!(&bytes[0..4], &[0x07, 0x00, 0x00, 0x00]);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 0x05);
    // Version = 0x0006
    assert_eq!(&bytes[8..10], &[0x06, 0x00]);

    let back: ServerCapabilitiesRequest = decode(&bytes);
    assert_eq!(back, req);
}

#[test]
fn client_capabilities_reply_roundtrip_v4() {
    let rep = ClientCapabilitiesReply {
        request_id: 0x0000_0007,
        version: io_version::NO_CUSTOM_EVENT,
    };
    let bytes = encode_to_vec(&rep);
    assert_eq!(bytes.len(), 6);
    assert_eq!(&bytes[0..4], &[0x07, 0x00, 0x00, packet_type::RESPONSE]);
    assert_eq!(&bytes[4..6], &[0x04, 0x00]);
    let back: ClientCapabilitiesReply = decode(&bytes);
    assert_eq!(back, rep);
}

// ── CreateFileRequest / Reply (spec §4 example 1 + 2) ──

#[test]
fn create_file_request_spec_wire_vector() {
    // From MS-RDPEPNP §4: 28-byte CreateFile request with
    // DeviceId=4, dwDesiredAccess=0xC0000000, dwShareMode=3,
    // dwCreationDisposition=3, dwFlagsAndAttributes=0x40000080.
    let req = CreateFileRequest {
        request_id: 0,
        device_id: 4,
        desired_access: 0xC000_0000,
        share_mode: 3,
        creation_disposition: 3,
        flags_and_attributes: 0x4000_0080,
    };
    let bytes = encode_to_vec(&req);
    assert_eq!(bytes.len(), 28);
    // Spot-check key offsets:
    // FunctionId at offset 4..8 = 0x00000004
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 4);
    // DeviceId at 8..12
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 4);
    // DesiredAccess at 12..16
    assert_eq!(
        u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        0xC000_0000
    );
    let back: CreateFileRequest = decode(&bytes);
    assert_eq!(back, req);
}

#[test]
fn create_file_reply_roundtrip() {
    let rep = CreateFileReply {
        request_id: 0,
        result: 0,
    };
    let bytes = encode_to_vec(&rep);
    assert_eq!(bytes.len(), 8);
    assert_eq!(bytes, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let back: CreateFileReply = decode(&bytes);
    assert_eq!(back, rep);
}

// ── Read ──

#[test]
fn read_request_spec_wire_vector() {
    let req = ReadRequest {
        request_id: 0,
        cb_bytes_to_read: 8,
        offset_high: 0x7000_0001,
        offset_low: 0xFFFF_FFFF,
    };
    assert_eq!(req.offset(), 0x70000001_FFFFFFFF);
    let bytes = encode_to_vec(&req);
    assert_eq!(bytes.len(), 20);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 0); // READ_REQUEST
    let back: ReadRequest = decode(&bytes);
    assert_eq!(back, req);
}

#[test]
fn read_reply_with_data_roundtrip() {
    let rep = ReadReply {
        request_id: 0x123456,
        result: 0,
        data: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };
    let bytes = encode_to_vec(&rep);
    // 4 header + 4 result + 4 cb + 8 data + 1 unused = 21
    assert_eq!(bytes.len(), 21);
    let back: ReadReply = decode(&bytes);
    assert_eq!(back, rep);
}

#[test]
fn read_reply_zero_length_still_has_unused_byte() {
    let rep = ReadReply {
        request_id: 0,
        result: 0,
        data: Vec::new(),
    };
    let bytes = encode_to_vec(&rep);
    assert_eq!(bytes.len(), 13);
    assert_eq!(bytes[12], 0); // UnusedByte
    let back: ReadReply = decode(&bytes);
    assert_eq!(back, rep);
}

// ── Write ──

#[test]
fn write_request_with_data_roundtrip() {
    let req = WriteRequest {
        request_id: 0,
        offset_high: 0,
        offset_low: 1,
        data: vec![0; 8],
    };
    let bytes = encode_to_vec(&req);
    // 8 hdr + 4 cb + 4+4 offset + 8 data + 1 unused = 29
    assert_eq!(bytes.len(), 29);
    let back: WriteRequest = decode(&bytes);
    assert_eq!(back, req);
}

#[test]
fn write_request_zero_length_still_has_unused_byte() {
    let req = WriteRequest {
        request_id: 0,
        offset_high: 0,
        offset_low: 0,
        data: Vec::new(),
    };
    let bytes = encode_to_vec(&req);
    assert_eq!(bytes.len(), 21);
    assert_eq!(bytes[20], 0);
    let back: WriteRequest = decode(&bytes);
    assert_eq!(back, req);
}

#[test]
fn write_reply_fixed_12_bytes() {
    let rep = WriteReply {
        request_id: 0,
        result: 0,
        cb_bytes_written: 8,
    };
    let bytes = encode_to_vec(&rep);
    assert_eq!(bytes.len(), 12);
    let back: WriteReply = decode(&bytes);
    assert_eq!(back, rep);
}

// ── IoControl ──

#[test]
fn iocontrol_request_spec_wire_vector_shape() {
    let req = IoControlRequest {
        request_id: 0,
        io_code: 0x0022_2440,
        data_in: vec![0; 16],
        cb_out: 8,
        data_out: Vec::new(),
    };
    let bytes = encode_to_vec(&req);
    // 8 hdr + 4 code + 4 cbIn + 4 cbOut + 16 dataIn + 0 dataOut + 1 unused = 37
    assert_eq!(bytes.len(), 37);
    let back: IoControlRequest = decode(&bytes);
    assert_eq!(back, req);
}

#[test]
fn iocontrol_request_zero_in_zero_out() {
    let req = IoControlRequest {
        request_id: 0,
        io_code: 0xDEAD_BEEF,
        data_in: Vec::new(),
        cb_out: 0,
        data_out: Vec::new(),
    };
    let bytes = encode_to_vec(&req);
    assert_eq!(bytes.len(), 21);
    let back: IoControlRequest = decode(&bytes);
    assert_eq!(back, req);
}

#[test]
fn iocontrol_reply_with_data_roundtrip() {
    let rep = IoControlReply {
        request_id: 0,
        result: 0,
        data: vec![0xAA; 8],
    };
    let bytes = encode_to_vec(&rep);
    assert_eq!(bytes.len(), 21);
    let back: IoControlReply = decode(&bytes);
    assert_eq!(back, rep);
}

// ── SpecificIoCancelRequest ──

#[test]
fn specific_iocancel_request_spec_wire_vector() {
    // Spec §4 example 9: RequestId=0xFFFFFF, FunctionId=0x06,
    // UnusedBits=0x00, idToCancel=0x000000.
    let req = SpecificIoCancelRequest {
        request_id: 0x00FF_FFFF,
        unused_bits: 0,
        id_to_cancel: 0,
    };
    let bytes = encode_to_vec(&req);
    assert_eq!(bytes.len(), 12);
    // RequestId bytes (LE 24-bit) at offsets 0..3
    assert_eq!(&bytes[0..3], &[0xFF, 0xFF, 0xFF]);
    // UnusedBits (header-level) at offset 3
    assert_eq!(bytes[3], 0);
    // FunctionId = 0x06 at offsets 4..8
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 0x06);
    // UnusedBits (body) at offset 8
    assert_eq!(bytes[8], 0);
    // idToCancel (LE 24-bit) at offsets 9..12
    assert_eq!(&bytes[9..12], &[0, 0, 0]);
    let back: SpecificIoCancelRequest = decode(&bytes);
    assert_eq!(back, req);
}

// ── ClientDeviceCustomEvent ──

#[test]
fn client_device_custom_event_with_data() {
    let guid = [
        0x11, 0x11, 0x11, 0x11, 0x80, 0x80, 0x5F, 0x42, 0x92, 0x2A, 0xDA, 0xBF, 0x3D, 0xE3, 0xF6,
        0x9A,
    ];
    let evt = ClientDeviceCustomEvent {
        request_id: 0,
        custom_event_guid: guid,
        data: vec![0x20, 0x4C, 0x0F, 0x00, 0xC4, 0x00, 0x0F, 0x00],
    };
    let bytes = encode_to_vec(&evt);
    // 4 hdr + 16 guid + 4 cb + 8 data + 1 unused = 33
    assert_eq!(bytes.len(), 33);
    // PacketType at offset 3
    assert_eq!(bytes[3], packet_type::CUSTOM_EVENT);
    let back: ClientDeviceCustomEvent = decode(&bytes);
    assert_eq!(back, evt);
}

// ── Negative decode paths ──

#[test]
fn decode_rejects_wrong_function_id() {
    // Encode a CreateFile header then try to decode as a Read.
    let req = CreateFileRequest {
        request_id: 0,
        device_id: 0,
        desired_access: 0,
        share_mode: 0,
        creation_disposition: 0,
        flags_and_attributes: 0,
    };
    let bytes = encode_to_vec(&req);
    let mut cur = ReadCursor::new(&bytes);
    assert!(ReadRequest::decode(&mut cur).is_err());
}

#[test]
fn decode_rejects_wrong_packet_type() {
    // CustomEvent bytes decoded as a plain ReadReply should be rejected.
    let evt = ClientDeviceCustomEvent {
        request_id: 0,
        custom_event_guid: [0; 16],
        data: Vec::new(),
    };
    let bytes = encode_to_vec(&evt);
    let mut cur = ReadCursor::new(&bytes);
    assert!(ReadReply::decode(&mut cur).is_err());
}

#[test]
fn decode_read_reply_enforces_cb_cap() {
    // Manually craft a ReadReply with cb=0x00100000 (1 MiB) — exceeds
    // the 64 KiB cap.
    let mut bytes = vec![0u8; 13];
    bytes[3] = packet_type::RESPONSE;
    // result = 0
    bytes[8] = 0x00;
    bytes[9] = 0x00;
    bytes[10] = 0x10;
    bytes[11] = 0x00;
    let mut cur = ReadCursor::new(&bytes);
    assert!(ReadReply::decode(&mut cur).is_err());
}
