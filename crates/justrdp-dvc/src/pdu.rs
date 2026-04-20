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
/// `DYNVC_SOFT_SYNC_REQUEST` — Cmd field. MS-RDPEDYC §2.2.5.1
pub const CMD_SOFT_SYNC_REQUEST: u8 = 0x08;
/// `DYNVC_SOFT_SYNC_RESPONSE` — Cmd field. MS-RDPEDYC §2.2.5.2
pub const CMD_SOFT_SYNC_RESPONSE: u8 = 0x09;

// ── Soft-Sync flags (MS-RDPEDYC §2.2.5.1) ──

/// Server has flushed all DVC data on the DRDYNVC SVC; subsequent data
/// for the listed channels will be sent via multitransport tunnels.
/// MUST be set in every Soft-Sync Request.
pub const SOFT_SYNC_TCP_FLUSHED: u16 = 0x0001;
/// Indicates that `SoftSyncChannelLists` is present and `NumberOfTunnels`
/// may be non-zero.
pub const SOFT_SYNC_CHANNEL_LIST_PRESENT: u16 = 0x0002;

// ── Tunnel types (MS-RDPEDYC §2.2.5.1.1, §2.2.5.2) ──
//
// NOTE: these values differ from MS-RDPBCGR §2.2.15.1 `requestProtocol`
// (TRANSPORTTYPE_UDPFECR=0x01, TRANSPORTTYPE_UDPFECL=0x04). RDPEDYC uses
// 0x01 / 0x03 instead.

/// RDP-UDP FEC reliable multitransport tunnel.
pub const TUNNELTYPE_UDPFECR: u32 = 0x0000_0001;
/// RDP-UDP FEC lossy multitransport tunnel. (Note: 0x03, *not* 0x02.)
pub const TUNNELTYPE_UDPFECL: u32 = 0x0000_0003;

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

// ── Soft-Sync supporting types (MS-RDPEDYC §2.2.5.1.1) ──

/// `DYNVC_SOFT_SYNC_CHANNEL_LIST` — group of DVC channel IDs assigned to a
/// single multitransport tunnel. Carried inside a Soft-Sync Request.
/// MS-RDPEDYC §2.2.5.1.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftSyncChannelList {
    /// `TUNNELTYPE_UDPFECR` (0x01) or `TUNNELTYPE_UDPFECL` (0x03).
    pub tunnel_type: u32,
    /// DVC channel IDs to route over `tunnel_type` after Soft-Sync.
    pub dvc_ids: Vec<u32>,
}

impl SoftSyncChannelList {
    fn encoded_size(&self) -> usize {
        // TunnelType(4) + NumberOfDVCs(2) + ListOfDVCIds(4 * N)
        4 + 2 + self.dvc_ids.len() * 4
    }
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
    /// Compressed first data fragment (v3, RDP8 Lite).
    DataFirstCompressed {
        channel_id: u32,
        total_length: u32,
        data: Vec<u8>,
    },
    /// Compressed data continuation/complete (v3, RDP8 Lite).
    DataCompressed {
        channel_id: u32,
        data: Vec<u8>,
    },
    /// Close a dynamic virtual channel.
    Close { channel_id: u32 },
    /// Server → Client: switch a set of DVCs from the DRDYNVC SVC to one or
    /// more multitransport tunnels. MS-RDPEDYC §2.2.5.1
    SoftSyncRequest {
        /// `SOFT_SYNC_TCP_FLUSHED` and/or `SOFT_SYNC_CHANNEL_LIST_PRESENT`.
        flags: u16,
        /// One entry per target tunnel. Empty when
        /// `SOFT_SYNC_CHANNEL_LIST_PRESENT` is unset.
        channel_lists: Vec<SoftSyncChannelList>,
    },
    /// Client → Server: ack which tunnels the client will write DVC data to.
    /// MS-RDPEDYC §2.2.5.2 — produced by `decode_dvc_pdu` when bytes arrive
    /// for symmetry/testing; the `DrdynvcClient` rejects this on receive
    /// since the server should never send it.
    SoftSyncResponse {
        /// `TUNNELTYPE_UDPFECR` / `TUNNELTYPE_UDPFECL` values.
        tunnels_to_switch: Vec<u32>,
    },
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
        CMD_DATA_FIRST_COMPRESSED => {
            // Same layout as CMD_DATA_FIRST, but data is RDP8 Lite compressed.
            // MS-RDPEDYC 2.2.3.3: Sp field encodes Len (length-field width).
            let channel_id = read_channel_id(src, cb_id)?;
            let total_length = read_length(src, sp)?;
            let data = src.peek_remaining().to_vec();
            src.skip(data.len(), "DVC::dataFirstCompressedPayload")?;
            Ok(DvcPdu::DataFirstCompressed {
                channel_id,
                total_length,
                data,
            })
        }
        CMD_DATA_COMPRESSED => {
            // Same layout as CMD_DATA, but data is RDP8 Lite compressed.
            // MS-RDPEDYC 2.2.3.4: Sp field is unused (ignore).
            let channel_id = read_channel_id(src, cb_id)?;
            let data = src.peek_remaining().to_vec();
            src.skip(data.len(), "DVC::dataCompressedPayload")?;
            Ok(DvcPdu::DataCompressed { channel_id, data })
        }
        CMD_SOFT_SYNC_REQUEST => {
            // MS-RDPEDYC §2.2.5.1: Sp + cbId MUST be 0 (header byte == 0x80).
            if sp != 0 || cb_id != 0 {
                return Err(DecodeError::unexpected_value(
                    "DVC", "softSyncRequest::header", "Sp/cbId must be 0",
                ));
            }
            let _pad = src.read_u8("DVC::softSyncRequest::pad")?;
            let length = src.read_u32_le("DVC::softSyncRequest::length")?;
            // Length is self-inclusive; remaining must equal Length - 4.
            let expected_remaining = (length as usize)
                .checked_sub(4)
                .ok_or_else(|| DecodeError::unexpected_value(
                    "DVC", "softSyncRequest::length", "must be >= 4 (self-inclusive)",
                ))?;
            if src.remaining() < expected_remaining {
                return Err(DecodeError::unexpected_value(
                    "DVC", "softSyncRequest::length", "exceeds available bytes",
                ));
            }
            let flags = src.read_u16_le("DVC::softSyncRequest::flags")?;
            // SOFT_SYNC_TCP_FLUSHED MUST be set (§2.2.5.1).
            if flags & SOFT_SYNC_TCP_FLUSHED == 0 {
                return Err(DecodeError::unexpected_value(
                    "DVC", "softSyncRequest::flags", "SOFT_SYNC_TCP_FLUSHED required",
                ));
            }
            let number_of_tunnels = src.read_u16_le("DVC::softSyncRequest::numberOfTunnels")?;
            // List-present flag and tunnel count must agree.
            let list_present = flags & SOFT_SYNC_CHANNEL_LIST_PRESENT != 0;
            if !list_present && number_of_tunnels != 0 {
                return Err(DecodeError::unexpected_value(
                    "DVC", "softSyncRequest", "CHANNEL_LIST_PRESENT unset but NumberOfTunnels > 0",
                ));
            }
            // Bound channel-list reads to the Length-declared region. Without
            // this, a server-sent Length that's smaller than the actual lists
            // would cause us to over-read into the next SVC PDU.
            let lists_budget = expected_remaining
                .checked_sub(4) // Flags(2) + NumberOfTunnels(2) already consumed.
                .ok_or_else(|| DecodeError::unexpected_value(
                    "DVC", "softSyncRequest::length", "too small for header fields",
                ))?;
            // DoS guard: each list is at minimum 6 bytes (TunnelType=4 +
            // NumberOfDVCs=2). Reject up front if NumberOfTunnels couldn't
            // physically fit even with empty channel lists — otherwise a
            // server-supplied number_of_tunnels=65535 would cause
            // `Vec::with_capacity(65535)` allocation before any byte is
            // read.
            if (number_of_tunnels as usize).saturating_mul(6) > lists_budget {
                return Err(DecodeError::unexpected_value(
                    "DVC", "softSyncRequest::numberOfTunnels",
                    "exceeds Length budget (would over-allocate)",
                ));
            }
            let before_lists = src.remaining();
            let mut channel_lists = Vec::with_capacity(number_of_tunnels as usize);
            for _ in 0..number_of_tunnels {
                let tunnel_type = src.read_u32_le("DVC::softSyncRequest::tunnelType")?;
                let n_dvcs = src.read_u16_le("DVC::softSyncRequest::numberOfDVCs")?;
                // DoS guard: each DVC ID is 4 bytes; refuse to allocate if
                // the declared count couldn't fit in the remaining bytes.
                if (n_dvcs as usize).saturating_mul(4) > src.remaining() {
                    return Err(DecodeError::unexpected_value(
                        "DVC", "softSyncRequest::numberOfDVCs",
                        "exceeds remaining bytes (would over-allocate)",
                    ));
                }
                let mut dvc_ids = Vec::with_capacity(n_dvcs as usize);
                for _ in 0..n_dvcs {
                    dvc_ids.push(src.read_u32_le("DVC::softSyncRequest::dvcId")?);
                }
                channel_lists.push(SoftSyncChannelList { tunnel_type, dvc_ids });
            }
            let consumed = before_lists - src.remaining();
            if consumed != lists_budget {
                return Err(DecodeError::unexpected_value(
                    "DVC", "softSyncRequest::length",
                    "channel lists do not match Length-declared region",
                ));
            }
            Ok(DvcPdu::SoftSyncRequest { flags, channel_lists })
        }
        CMD_SOFT_SYNC_RESPONSE => {
            // MS-RDPEDYC §2.2.5.2: Sp + cbId MUST be 0 (header byte == 0x90).
            if sp != 0 || cb_id != 0 {
                return Err(DecodeError::unexpected_value(
                    "DVC", "softSyncResponse::header", "Sp/cbId must be 0",
                ));
            }
            let _pad = src.read_u8("DVC::softSyncResponse::pad")?;
            // RESPONSE uses u32 NumberOfTunnels (REQUEST uses u16) — §2.2.5.2.
            let number_of_tunnels = src.read_u32_le("DVC::softSyncResponse::numberOfTunnels")?;
            // DoS guard: each entry is 4 bytes; reject if the declared
            // count couldn't possibly fit in the remaining bytes — without
            // this, `number_of_tunnels = u32::MAX` would request a 16 GB
            // allocation before reading the first entry.
            if (number_of_tunnels as usize).saturating_mul(4) > src.remaining() {
                return Err(DecodeError::unexpected_value(
                    "DVC", "softSyncResponse::numberOfTunnels",
                    "exceeds remaining bytes (would over-allocate)",
                ));
            }
            let mut tunnels_to_switch = Vec::with_capacity(number_of_tunnels as usize);
            for _ in 0..number_of_tunnels {
                tunnels_to_switch.push(src.read_u32_le("DVC::softSyncResponse::tunnelType")?);
            }
            Ok(DvcPdu::SoftSyncResponse { tunnels_to_switch })
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

/// Encode a `DYNVC_SOFT_SYNC_REQUEST` (server side; mostly useful for
/// loopback tests). MS-RDPEDYC §2.2.5.1
///
/// Returns `Err` if any input would silently truncate on the wire:
///   - >65 535 channel lists (won't fit in `NumberOfTunnels: u16`)
///   - >65 535 DVC IDs in a single list (`NumberOfDVCs: u16`)
///   - serialized payload exceeding `u32::MAX` (`Length: u32`)
pub fn encode_soft_sync_request(
    flags: u16,
    channel_lists: &[SoftSyncChannelList],
) -> Result<Vec<u8>, justrdp_core::EncodeError> {
    let n_tunnels = u16::try_from(channel_lists.len()).map_err(|_| {
        justrdp_core::EncodeError::invalid_value(
            "DVC::softSyncRequest::numberOfTunnels",
            "exceeds u16::MAX",
        )
    })?;
    for list in channel_lists {
        u16::try_from(list.dvc_ids.len()).map_err(|_| {
            justrdp_core::EncodeError::invalid_value(
                "DVC::softSyncRequest::numberOfDVCs",
                "exceeds u16::MAX",
            )
        })?;
    }
    let lists_size: usize = channel_lists.iter().map(SoftSyncChannelList::encoded_size).sum();
    // Length is self-inclusive: Length(4) + Flags(2) + NumberOfTunnels(2) + lists.
    let length_usize = 4 + 2 + 2 + lists_size;
    let length = u32::try_from(length_usize).map_err(|_| {
        justrdp_core::EncodeError::invalid_value(
            "DVC::softSyncRequest::length",
            "exceeds u32::MAX",
        )
    })?;
    let total = 1 + 1 + length_usize; // Cmd + Pad + Length-covered region.
    let mut buf = alloc::vec![0u8; total];
    let mut cursor = WriteCursor::new(&mut buf);
    cursor.write_u8(encode_header(CMD_SOFT_SYNC_REQUEST, 0, 0), "DVC::header")?;
    cursor.write_u8(0x00, "DVC::softSyncRequest::pad")?;
    cursor.write_u32_le(length, "DVC::softSyncRequest::length")?;
    cursor.write_u16_le(flags, "DVC::softSyncRequest::flags")?;
    cursor.write_u16_le(n_tunnels, "DVC::softSyncRequest::numberOfTunnels")?;
    for list in channel_lists {
        cursor.write_u32_le(list.tunnel_type, "DVC::softSyncRequest::tunnelType")?;
        cursor.write_u16_le(list.dvc_ids.len() as u16, "DVC::softSyncRequest::numberOfDVCs")?;
        for &id in &list.dvc_ids {
            cursor.write_u32_le(id, "DVC::softSyncRequest::dvcId")?;
        }
    }
    Ok(buf)
}

/// Encode a `DYNVC_SOFT_SYNC_RESPONSE`. MS-RDPEDYC §2.2.5.2
///
/// Returns `Err` if `tunnels_to_switch.len()` exceeds `u32::MAX`.
pub fn encode_soft_sync_response(
    tunnels_to_switch: &[u32],
) -> Result<Vec<u8>, justrdp_core::EncodeError> {
    let n_tunnels = u32::try_from(tunnels_to_switch.len()).map_err(|_| {
        justrdp_core::EncodeError::invalid_value(
            "DVC::softSyncResponse::numberOfTunnels",
            "exceeds u32::MAX",
        )
    })?;
    let total = 1 + 1 + 4 + tunnels_to_switch.len() * 4;
    let mut buf = alloc::vec![0u8; total];
    let mut cursor = WriteCursor::new(&mut buf);
    cursor.write_u8(encode_header(CMD_SOFT_SYNC_RESPONSE, 0, 0), "DVC::header")?;
    cursor.write_u8(0x00, "DVC::softSyncResponse::pad")?;
    // RESPONSE NumberOfTunnels is u32 (REQUEST is u16) — §2.2.5.2.
    cursor.write_u32_le(n_tunnels, "DVC::softSyncResponse::numberOfTunnels")?;
    for &t in tunnels_to_switch {
        cursor.write_u32_le(t, "DVC::softSyncResponse::tunnelType")?;
    }
    Ok(buf)
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
    use alloc::vec;

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

    // ── Soft-Sync (MS-RDPEDYC §2.2.5) ──

    #[test]
    fn soft_sync_request_minimal_wire() {
        // SOFT_SYNC_TCP_FLUSHED only, no channel lists.
        let buf = encode_soft_sync_request(SOFT_SYNC_TCP_FLUSHED, &[]).unwrap();
        assert_eq!(
            &buf,
            &[
                0x80,                   // Cmd=8, Sp=0, cbId=0
                0x00,                   // Pad
                0x08, 0x00, 0x00, 0x00, // Length=8 (self-inclusive)
                0x01, 0x00,             // Flags = SOFT_SYNC_TCP_FLUSHED
                0x00, 0x00,             // NumberOfTunnels=0
            ],
        );
        let mut src = ReadCursor::new(&buf);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(
            pdu,
            DvcPdu::SoftSyncRequest {
                flags: SOFT_SYNC_TCP_FLUSHED,
                channel_lists: vec![],
            },
        );
    }

    #[test]
    fn soft_sync_request_with_channels_wire() {
        let lists = vec![SoftSyncChannelList {
            tunnel_type: TUNNELTYPE_UDPFECR,
            dvc_ids: vec![3],
        }];
        let buf = encode_soft_sync_request(
            SOFT_SYNC_TCP_FLUSHED | SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &lists,
        )
        .unwrap();
        assert_eq!(
            &buf,
            &[
                0x80,
                0x00,
                // Length = 4 + 2 + 2 + (4 + 2 + 4) = 18 = 0x12
                0x12, 0x00, 0x00, 0x00,
                0x03, 0x00,             // Flags = TCP_FLUSHED | CHANNEL_LIST_PRESENT
                0x01, 0x00,             // NumberOfTunnels=1
                0x01, 0x00, 0x00, 0x00, // TunnelType = UDPFECR
                0x01, 0x00,             // NumberOfDVCs=1
                0x03, 0x00, 0x00, 0x00, // ChannelId=3
            ],
        );
        let mut src = ReadCursor::new(&buf);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(
            pdu,
            DvcPdu::SoftSyncRequest {
                flags: SOFT_SYNC_TCP_FLUSHED | SOFT_SYNC_CHANNEL_LIST_PRESENT,
                channel_lists: lists,
            },
        );
    }

    #[test]
    fn soft_sync_request_two_tunnels_roundtrip() {
        let lists = vec![
            SoftSyncChannelList { tunnel_type: TUNNELTYPE_UDPFECR, dvc_ids: vec![3, 7] },
            SoftSyncChannelList { tunnel_type: TUNNELTYPE_UDPFECL, dvc_ids: vec![11] },
        ];
        let buf = encode_soft_sync_request(
            SOFT_SYNC_TCP_FLUSHED | SOFT_SYNC_CHANNEL_LIST_PRESENT,
            &lists,
        )
        .unwrap();
        let mut src = ReadCursor::new(&buf);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        match pdu {
            DvcPdu::SoftSyncRequest { flags, channel_lists } => {
                assert_eq!(flags, SOFT_SYNC_TCP_FLUSHED | SOFT_SYNC_CHANNEL_LIST_PRESENT);
                assert_eq!(channel_lists, lists);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn soft_sync_request_missing_tcp_flushed_rejected() {
        // Hand-craft a request without SOFT_SYNC_TCP_FLUSHED set.
        let buf = [
            0x80, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, // Flags = 0 (missing required bit)
            0x00, 0x00,
        ];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn soft_sync_request_inconsistent_list_present_rejected() {
        // CHANNEL_LIST_PRESENT unset but NumberOfTunnels=1.
        let buf = [
            0x80, 0x00, 0x12, 0x00, 0x00, 0x00,
            0x01, 0x00, // Flags = TCP_FLUSHED only
            0x01, 0x00, // NumberOfTunnels = 1
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn soft_sync_request_bad_header_byte_rejected() {
        // Sp=1 (non-zero) — byte0 should be 0x84 instead of 0x80.
        let buf = [
            0x84, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn soft_sync_request_length_too_small_rejected() {
        // Length = 3 (< 4, so Length - 4 underflows).
        let buf = [
            0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn soft_sync_request_huge_number_of_tunnels_rejected() {
        // DoS guard: NumberOfTunnels=0xFFFF would cause a 64K Vec
        // allocation before any list bytes are read. The guard rejects
        // before the alloc when number_of_tunnels * 6 > lists_budget.
        let buf = [
            0x80, 0x00,
            0x08, 0x00, 0x00, 0x00, // Length = 8 (no room for any list)
            0x03, 0x00,             // Flags = TCP_FLUSHED | LIST_PRESENT
            0xFF, 0xFF,             // NumberOfTunnels = 65535 (would OOM)
        ];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn soft_sync_request_huge_number_of_dvcs_rejected() {
        // DoS guard: per-list NumberOfDVCs=0xFFFF would cause a 256K
        // Vec allocation. Rejected when n_dvcs * 4 > src.remaining().
        let buf = [
            0x80, 0x00,
            0x10, 0x00, 0x00, 0x00, // Length = 16
            0x03, 0x00,             // Flags
            0x01, 0x00,             // NumberOfTunnels = 1
            0x01, 0x00, 0x00, 0x00, // TunnelType = UDPFECR
            0xFF, 0xFF,             // NumberOfDVCs = 65535 (would OOM)
        ];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn soft_sync_response_huge_number_of_tunnels_rejected() {
        // DoS guard: u32 NumberOfTunnels=0xFFFFFFFF would request
        // 16 GB of allocation. Rejected when count * 4 > remaining.
        let buf = [
            0x90, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, // NumberOfTunnels = u32::MAX
        ];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn soft_sync_request_length_exceeds_buffer_rejected() {
        // Length=0xFFFFFFFF but only ~10 bytes remain → over-read guard fires.
        let buf = [
            0x80, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00,
        ];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn soft_sync_request_length_smaller_than_lists_rejected() {
        // Length claims 8 bytes (Length+Flags+NumberOfTunnels only), but a
        // channel list follows on the wire — server lied about Length.
        let buf = [
            0x80, 0x00,
            0x08, 0x00, 0x00, 0x00, // Length = 8 (no lists declared)
            0x03, 0x00,             // Flags = TCP_FLUSHED | CHANNEL_LIST_PRESENT
            0x01, 0x00,             // NumberOfTunnels = 1 (contradicts Length)
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // a list anyway
        ];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn soft_sync_response_minimal_wire() {
        let buf = encode_soft_sync_response(&[]).unwrap();
        assert_eq!(&buf, &[0x90, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut src = ReadCursor::new(&buf);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(pdu, DvcPdu::SoftSyncResponse { tunnels_to_switch: vec![] });
    }

    #[test]
    fn soft_sync_response_single_tunnel_wire() {
        let buf = encode_soft_sync_response(&[TUNNELTYPE_UDPFECR]).unwrap();
        assert_eq!(
            &buf,
            &[
                0x90,
                0x00,
                0x01, 0x00, 0x00, 0x00, // NumberOfTunnels = 1 (u32)
                0x01, 0x00, 0x00, 0x00, // UDPFECR
            ],
        );
        let mut src = ReadCursor::new(&buf);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(
            pdu,
            DvcPdu::SoftSyncResponse { tunnels_to_switch: vec![TUNNELTYPE_UDPFECR] },
        );
    }

    #[test]
    fn soft_sync_response_two_tunnels_roundtrip() {
        let buf = encode_soft_sync_response(&[TUNNELTYPE_UDPFECR, TUNNELTYPE_UDPFECL]).unwrap();
        let mut src = ReadCursor::new(&buf);
        let pdu = decode_dvc_pdu(&mut src).unwrap();
        assert_eq!(
            pdu,
            DvcPdu::SoftSyncResponse {
                tunnels_to_switch: vec![TUNNELTYPE_UDPFECR, TUNNELTYPE_UDPFECL],
            },
        );
    }

    #[test]
    fn soft_sync_response_bad_header_byte_rejected() {
        // cbId=1 — byte0 should be 0x91.
        let buf = [0x91, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut src = ReadCursor::new(&buf);
        assert!(decode_dvc_pdu(&mut src).is_err());
    }

    #[test]
    fn tunneltype_constants_distinct_from_rdpbcgr() {
        // RDPEDYC uses 1 / 3 (NOT 1 / 4 like RDPBCGR §2.2.15.1).
        assert_eq!(TUNNELTYPE_UDPFECR, 0x01);
        assert_eq!(TUNNELTYPE_UDPFECL, 0x03);
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
