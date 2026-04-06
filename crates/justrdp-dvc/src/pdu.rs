#![forbid(unsafe_code)]

//! Dynamic Virtual Channel PDU types -- MS-RDPEDYC 2.2

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

// ── Cmd constants (MS-RDPEDYC 2.2) ──

pub const CMD_CREATE: u8 = 0x01;
pub const CMD_DATA_FIRST: u8 = 0x02;
pub const CMD_DATA: u8 = 0x03;
pub const CMD_CLOSE: u8 = 0x04;
pub const CMD_CAPS: u8 = 0x05;
pub const CMD_DATA_FIRST_COMPRESSED: u8 = 0x06;
pub const CMD_DATA_COMPRESSED: u8 = 0x07;
// Soft-Sync commands (MS-RDPEDYC 2.2.4). Not yet implemented — decoded
// as unsupported so the client returns an explicit error rather than
// falling into the "unknown command" path.
pub(crate) const CMD_SOFT_SYNC_REQUEST: u8 = 0x08;
pub(crate) const CMD_SOFT_SYNC_RESPONSE: u8 = 0x09;

// ── Version constants ──

pub const CAPS_VERSION_1: u16 = 0x0001;
pub const CAPS_VERSION_2: u16 = 0x0002;
pub const CAPS_VERSION_3: u16 = 0x0003;

/// Successful channel creation (HRESULT S_OK).
/// MS-RDPEDYC 2.2.2.2 declares this as UINT32 but it carries HRESULT values
/// (signed convention). Wire format is identical for i32/u32.
pub const CREATION_STATUS_OK: i32 = 0x00000000;

// ── Header byte helpers ──

/// Encode a DVC header byte: `(cmd[7:4] | sp[3:2] | cb_id[1:0])`.
/// MS-RDPEDYC 2.2
pub fn encode_header(cmd: u8, sp: u8, cb_id: u8) -> u8 {
    ((cmd & 0x0F) << 4) | ((sp & 0x03) << 2) | (cb_id & 0x03)
}

/// Decode a DVC header byte into `(cmd, sp, cb_id)`.
pub fn decode_header(byte: u8) -> (u8, u8, u8) {
    let cb_id = byte & 0x03;
    let sp = (byte >> 2) & 0x03;
    let cmd = (byte >> 4) & 0x0F;
    (cmd, sp, cb_id)
}

// ── Variable-width integer helpers (MS-RDPEDYC 2.2) ──
//
// Both ChannelId and Length fields use the same 2-bit width selector
// (0x00 → u8, 0x01 → u16, 0x02 → u32). The helpers below are shared.

/// Determine the minimum 2-bit width selector for a value.
///
/// Used for both `cbId` (channel ID) and `Len` (length) fields.
fn varint_width(value: u32) -> u8 {
    if value <= 0xFF {
        0x00
    } else if value <= 0xFFFF {
        0x01
    } else {
        0x02
    }
}

/// Number of bytes for a given 2-bit width selector.
///
/// Returns 0 for invalid selector (0x03). Callers should reject this case.
fn varint_size(selector: u8) -> usize {
    match selector {
        0x00 => 1,
        0x01 => 2,
        0x02 => 4,
        _ => 0, // invalid per MS-RDPEDYC 2.2
    }
}

/// Read a variable-width integer from the cursor.
fn read_varint(src: &mut ReadCursor<'_>, selector: u8, field: &'static str) -> DecodeResult<u32> {
    match selector {
        0x00 => Ok(src.read_u8(field)? as u32),
        0x01 => Ok(src.read_u16_le(field)? as u32),
        0x02 => Ok(src.read_u32_le(field)?),
        _ => Err(DecodeError::unexpected_value("DVC", field, "invalid width selector 0x03")),
    }
}

/// Write a variable-width integer to the cursor.
fn write_varint(dst: &mut WriteCursor<'_>, value: u32, selector: u8, field: &'static str) -> EncodeResult<()> {
    match selector {
        0x00 => dst.write_u8(value as u8, field),
        0x01 => dst.write_u16_le(value as u16, field),
        0x02 => dst.write_u32_le(value, field),
        _ => Err(justrdp_core::EncodeError::invalid_value(field, "invalid width selector 0x03")),
    }
}

/// Determine the smallest `cbId` value for a channel ID.
pub fn cb_id_for(channel_id: u32) -> u8 { varint_width(channel_id) }

/// Number of bytes for a given `cbId` value.
pub fn cb_id_size(cb_id: u8) -> usize { varint_size(cb_id) }

/// Read a channel ID of the given `cbId` width.
pub fn read_channel_id(src: &mut ReadCursor<'_>, cb_id: u8) -> DecodeResult<u32> {
    read_varint(src, cb_id, "DVC::channelId")
}

/// Write a channel ID with the given `cbId` width.
pub fn write_channel_id(dst: &mut WriteCursor<'_>, channel_id: u32, cb_id: u8) -> EncodeResult<()> {
    write_varint(dst, channel_id, cb_id, "DVC::channelId")
}

/// Determine the smallest `Len` value for a length field.
pub fn len_id_for(length: u32) -> u8 { varint_width(length) }

/// Number of bytes for a given `Len` value.
pub fn len_id_size(len_id: u8) -> usize { varint_size(len_id) }

/// Read a length field of the given `Len` width.
pub fn read_length(src: &mut ReadCursor<'_>, len_id: u8) -> DecodeResult<u32> {
    read_varint(src, len_id, "DVC::length")
}

/// Write a length field with the given `Len` width.
pub fn write_length(dst: &mut WriteCursor<'_>, length: u32, len_id: u8) -> EncodeResult<()> {
    write_varint(dst, length, len_id, "DVC::length")
}

// ── PDU types ──

/// Parsed DVC PDU from server (server → client direction).
///
/// The DVC protocol uses the same Cmd value for both directions (e.g., Cmd=0x05
/// for both Caps Request and Caps Response). This decoder assumes server→client
/// direction, which is the primary use case for `DrdynvcClient`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DvcPdu {
    /// Server → Client: capability advertisement.
    CapabilitiesRequest {
        version: u16,
        /// Priority charges (v2/v3 only, 4 values).
        charges: Option<[u16; 4]>,
    },
    /// Server → Client: create a dynamic virtual channel.
    CreateRequest {
        channel_id: u32,
        channel_name: String,
        priority: u8,
    },
    /// Data with total length (first fragment or single message).
    DataFirst {
        channel_id: u32,
        total_length: u32,
        data: Vec<u8>,
    },
    /// Data continuation/complete.
    Data {
        channel_id: u32,
        data: Vec<u8>,
    },
    /// Close a dynamic virtual channel.
    Close { channel_id: u32 },
}

/// Decode a server→client DVC PDU from bytes.
///
/// This decoder assumes the PDU originates from the server.
/// Server sends: CapabilitiesRequest, CreateRequest, DataFirst, Data, Close.
pub fn decode_dvc_pdu(src: &mut ReadCursor<'_>) -> DecodeResult<DvcPdu> {
    let header_byte = src.read_u8("DVC::header")?;
    let (cmd, sp, cb_id) = decode_header(header_byte);

    match cmd {
        CMD_CAPS => {
            // Server → Client: DYNVC_CAPS_VERSION1/2/3 (MS-RDPEDYC 2.2.1.1)
            let _pad = src.read_u8("DVC::capsPad")?;
            let version = src.read_u16_le("DVC::capsVersion")?;
            // MS-RDPEDYC 2.2.1.1: v2/v3 MUST include 4 priority charge fields (8 bytes).
            let charges = if version >= CAPS_VERSION_2 {
                Some([
                    src.read_u16_le("DVC::priorityCharge0")?,
                    src.read_u16_le("DVC::priorityCharge1")?,
                    src.read_u16_le("DVC::priorityCharge2")?,
                    src.read_u16_le("DVC::priorityCharge3")?,
                ])
            } else {
                None
            };
            Ok(DvcPdu::CapabilitiesRequest { version, charges })
        }
        CMD_CREATE => {
            // Server → Client: DYNVC_CREATE_REQ (MS-RDPEDYC 2.2.2.1)
            // Wire: Header + ChannelId + ChannelName (null-terminated)
            let channel_id = read_channel_id(src, cb_id)?;
            let remaining = src.peek_remaining();
            // MS-RDPEDYC 2.2.2.1: channel name MUST be null-terminated.
            let name_end = remaining.iter().position(|&b| b == 0)
                .ok_or_else(|| DecodeError::unexpected_value("DVC", "channelName", "missing null terminator"))?;
            let name_bytes = &remaining[..name_end];
            let channel_name = core::str::from_utf8(name_bytes)
                .map_err(|_| DecodeError::unexpected_value("DVC", "channelName", "invalid UTF-8"))?;
            let channel_name = String::from(channel_name);
            let skip = name_end + 1; // include the null terminator
            src.skip(skip, "DVC::channelName")?;
            Ok(DvcPdu::CreateRequest {
                channel_id,
                channel_name,
                priority: sp,
            })
        }
        CMD_DATA_FIRST => {
            let channel_id = read_channel_id(src, cb_id)?;
            let total_length = read_length(src, sp)?;
            let data = src.peek_remaining().to_vec();
            src.skip(data.len(), "DVC::dataFirstPayload")?;
            Ok(DvcPdu::DataFirst {
                channel_id,
                total_length,
                data,
            })
        }
        CMD_DATA => {
            let channel_id = read_channel_id(src, cb_id)?;
            let data = src.peek_remaining().to_vec();
            src.skip(data.len(), "DVC::dataPayload")?;
            Ok(DvcPdu::Data { channel_id, data })
        }
        CMD_CLOSE => {
            let channel_id = read_channel_id(src, cb_id)?;
            Ok(DvcPdu::Close { channel_id })
        }
        // Compressed variants (v3) — not yet supported.
        // Silently decoding compressed payload as plain data would corrupt the stream.
        CMD_DATA_FIRST_COMPRESSED | CMD_DATA_COMPRESSED => {
            Err(DecodeError::unsupported("DVC", "compressed DVC data is not yet supported"))
        }
        // Soft-Sync (MS-RDPEDYC 2.2.4) — not yet supported.
        CMD_SOFT_SYNC_REQUEST | CMD_SOFT_SYNC_RESPONSE => {
            Err(DecodeError::unsupported("DVC", "Soft-Sync is not yet supported"))
        }
        _ => Err(DecodeError::unexpected_value("DVC", "Cmd", "unknown DVC command")),
    }
}

// ── Encoding functions ──

/// Encode a DYNVC_CAPS_RSP.
pub fn encode_caps_response(version: u16) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; 4];
    buf[0] = encode_header(CMD_CAPS, 0, 0);
    buf[1] = 0x00; // pad
    buf[2..4].copy_from_slice(&version.to_le_bytes());
    buf
}

/// Encode a DYNVC_CREATE_RSP.
pub fn encode_create_response(channel_id: u32, creation_status: i32) -> Vec<u8> {
    let cb_id = cb_id_for(channel_id);
    let size = 1 + cb_id_size(cb_id) + 4;
    let mut buf = alloc::vec![0u8; size];
    let mut cursor = WriteCursor::new(&mut buf);
    cursor.write_u8(encode_header(CMD_CREATE, 0, cb_id), "DVC::header").expect("pre-sized buffer");
    write_channel_id(&mut cursor, channel_id, cb_id).expect("pre-sized buffer");
    cursor.write_i32_le(creation_status, "DVC::creationStatus").expect("pre-sized buffer");
    buf
}

/// Encode a DYNVC_DATA (single message or continuation).
pub fn encode_data(channel_id: u32, data: &[u8]) -> Vec<u8> {
    let cb_id = cb_id_for(channel_id);
    let size = 1 + cb_id_size(cb_id) + data.len();
    let mut buf = alloc::vec![0u8; size];
    let mut cursor = WriteCursor::new(&mut buf);
    cursor.write_u8(encode_header(CMD_DATA, 0, cb_id), "DVC::header").expect("pre-sized buffer");
    write_channel_id(&mut cursor, channel_id, cb_id).expect("pre-sized buffer");
    cursor.write_slice(data, "DVC::data").expect("pre-sized buffer");
    buf
}

/// Encode a DYNVC_DATA_FIRST.
pub fn encode_data_first(channel_id: u32, total_length: u32, data: &[u8]) -> Vec<u8> {
    let cb_id = cb_id_for(channel_id);
    let len_id = len_id_for(total_length);
    let size = 1 + cb_id_size(cb_id) + len_id_size(len_id) + data.len();
    let mut buf = alloc::vec![0u8; size];
    let mut cursor = WriteCursor::new(&mut buf);
    cursor.write_u8(encode_header(CMD_DATA_FIRST, len_id, cb_id), "DVC::header").expect("pre-sized buffer");
    write_channel_id(&mut cursor, channel_id, cb_id).expect("pre-sized buffer");
    write_length(&mut cursor, total_length, len_id).expect("pre-sized buffer");
    cursor.write_slice(data, "DVC::data").expect("pre-sized buffer");
    buf
}

/// Encode a DYNVC_CLOSE.
pub fn encode_close(channel_id: u32) -> Vec<u8> {
    let cb_id = cb_id_for(channel_id);
    let size = 1 + cb_id_size(cb_id);
    let mut buf = alloc::vec![0u8; size];
    let mut cursor = WriteCursor::new(&mut buf);
    cursor.write_u8(encode_header(CMD_CLOSE, 0, cb_id), "DVC::header").expect("pre-sized buffer");
    write_channel_id(&mut cursor, channel_id, cb_id).expect("pre-sized buffer");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_encode_decode_roundtrip() {
        for cmd in 0x01..=0x09u8 {
            for sp in 0..=3u8 {
                for cb_id in 0..=2u8 {
                    let byte = encode_header(cmd, sp, cb_id);
                    let (d_cmd, d_sp, d_cb_id) = decode_header(byte);
                    assert_eq!(d_cmd, cmd);
                    assert_eq!(d_sp, sp);
                    assert_eq!(d_cb_id, cb_id);
                }
            }
        }
    }

    #[test]
    fn cb_id_selection() {
        assert_eq!(cb_id_for(0xFF), 0x00);
        assert_eq!(cb_id_for(0x100), 0x01);
        assert_eq!(cb_id_for(0xFFFF), 0x01);
        assert_eq!(cb_id_for(0x10000), 0x02);
    }

    #[test]
    fn caps_v1_wire_format() {
        let buf = encode_caps_response(CAPS_VERSION_1);
        assert_eq!(&buf, &[0x50, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn caps_v3_wire_format() {
        let buf = encode_caps_response(CAPS_VERSION_3);
        assert_eq!(&buf, &[0x50, 0x00, 0x03, 0x00]);
    }

    #[test]
    fn caps_v1_roundtrip() {
        let buf = [0x50, 0x00, 0x01, 0x00];
        let mut src = ReadCursor::new(&buf);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(pdu, DvcPdu::CapabilitiesRequest {
            version: 1,
            charges: None,
        });
    }

    #[test]
    fn caps_v2_roundtrip() {
        let buf: [u8; 12] = [
            0x50, 0x00, 0x02, 0x00,
            0xA8, 0x03, 0xCC, 0x0C,
            0xA2, 0x24, 0x55, 0x55,
        ];
        let mut src = ReadCursor::new(&buf);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(pdu, DvcPdu::CapabilitiesRequest {
            version: 2,
            charges: Some([936, 3276, 9378, 21845]),
        });
    }

    #[test]
    fn create_req_spec_test_vector() {
        // MS-RDPEDYC section 4.1.1
        let buf = [0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x00];
        let mut src = ReadCursor::new(&buf);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(pdu, DvcPdu::CreateRequest {
            channel_id: 3,
            channel_name: String::from("testdvc"),
            priority: 0,
        });
    }

    #[test]
    fn create_response_roundtrip() {
        let buf = encode_create_response(3, CREATION_STATUS_OK);
        assert_eq!(&buf, &[0x10, 0x03, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn data_single_roundtrip() {
        let encoded = encode_data(3, b"hello");
        assert_eq!(&encoded, &[0x30, 0x03, b'h', b'e', b'l', b'l', b'o']);

        let mut src = ReadCursor::new(&encoded);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(pdu, DvcPdu::Data {
            channel_id: 3,
            data: b"hello".to_vec(),
        });
    }

    #[test]
    fn data_first_roundtrip() {
        let encoded = encode_data_first(3, 2000, b"chunk1");
        let mut src = ReadCursor::new(&encoded);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        match pdu {
            DvcPdu::DataFirst { channel_id, total_length, data } => {
                assert_eq!(channel_id, 3);
                assert_eq!(total_length, 2000);
                assert_eq!(data, b"chunk1");
            }
            _ => panic!("expected DataFirst"),
        }
    }

    #[test]
    fn close_roundtrip() {
        let encoded = encode_close(3);
        assert_eq!(&encoded, &[0x40, 0x03]);

        let mut src = ReadCursor::new(&encoded);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(pdu, DvcPdu::Close { channel_id: 3 });
    }

    #[test]
    fn large_channel_id_uses_u32() {
        let encoded = encode_close(0x12345);
        let (_, _, cb_id) = decode_header(encoded[0]);
        assert_eq!(cb_id, 0x02); // u32
        let mut src = ReadCursor::new(&encoded);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(pdu, DvcPdu::Close { channel_id: 0x12345 });
    }

    #[test]
    fn data_first_length_encoding() {
        // Length=200 → len_id=0 (1 byte)
        let encoded = encode_data_first(1, 200, b"x");
        let (_, sp, _) = decode_header(encoded[0]);
        assert_eq!(sp, 0x00); // Len=0, 1-byte length

        // Length=500 → len_id=1 (2 bytes)
        let encoded = encode_data_first(1, 500, b"x");
        let (_, sp, _) = decode_header(encoded[0]);
        assert_eq!(sp, 0x01); // Len=1, 2-byte length

        // Length=70000 → len_id=2 (4 bytes)
        let encoded = encode_data_first(1, 70000, b"x");
        let (_, sp, _) = decode_header(encoded[0]);
        assert_eq!(sp, 0x02); // Len=2, 4-byte length
    }
}
