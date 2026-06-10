//! Dynamic virtual channel transport PDUs (MS-RDPEDYC) — the `drdynvc` static channel's
//! payload format. One byte of header packs `Cmd` (bits 4–7), `Sp` (bits 2–3, command-specific)
//! and `cbId` (bits 0–1, the ChannelId field width); the messages that exist are Capabilities
//! (0x05), Create (0x01), DataFirst (0x02), Data (0x03), Close (0x04) and the compressed /
//! soft-sync variants justrdp never negotiates (it answers capabilities with version 1).
//!
//! Channels are **server-created**: the server sends a Create Request naming the channel and
//! the client accepts or refuses it in the Create Response — there is no "Open" PDU and the
//! client cannot create channels (MS-RDPEDYC 1.3). Message reassembly (DataFirst + Data) is
//! stateful and lives in the session machine; this module is the pure codec.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// `Cmd` — Create Request / Create Response (MS-RDPEDYC 2.2.2.1/2.2.2.2).
pub const CMD_CREATE: u8 = 0x01;
/// `Cmd` — Data First (2.2.3.1): opens a fragmented message, carrying its total length.
pub const CMD_DATA_FIRST: u8 = 0x02;
/// `Cmd` — Data (2.2.3.2): a complete message, or a continuation after Data First.
pub const CMD_DATA: u8 = 0x03;
/// `Cmd` — Close (2.2.4), either direction.
pub const CMD_CLOSE: u8 = 0x04;
/// `Cmd` — Capabilities Request (server→client) / Response (client→server) (2.2.1).
pub const CMD_CAPABILITIES: u8 = 0x05;

/// The largest data block carried by a single Data / Data First PDU; longer messages are
/// fragmented (MS-RDPEDYC 3.1.5.1.2). With the worst-case 6-byte DVC header this stays within
/// one 1600-byte SVC chunk.
pub const MAX_DATA_CHUNK: usize = 1590;

/// The capabilities version justrdp answers with: version 3 (capped at the server's offer).
/// The server-side Graphics channel manager refuses to run over a version-1 transport
/// (proven on the real VM: a V1 caps response gets the connection reset right after the EGFX
/// caps advertise; V3 proceeds). The V3 features stay dormant in practice: compressed data
/// PDUs are not used for EGFX (its payload is already zgfx-compressed end to end), and
/// soft-sync only occurs when GCC multitransport is advertised, which justrdp does not send.
/// Both arrive as `Unsupported` and are skipped if a server violates that.
pub const CAPS_VERSION: u16 = 3;

/// One decoded drdynvc message (the server→client direction plus the fields shared by both).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DvcMessage<'a> {
    /// Capabilities Request: the server's maximum supported version.
    CapabilitiesRequest {
        /// `Version` (1, 2 or 3); version 2/3 priority-charge fields are ignored.
        version: u16,
    },
    /// Create Request: the server asks to open `name` as channel `channel_id`.
    CreateRequest {
        /// The server-assigned dynamic channel ID.
        channel_id: u32,
        /// The channel name (bytes before the terminating NUL).
        name: &'a str,
    },
    /// Data First: opens a message of `total_length` bytes; `data` is its first fragment.
    DataFirst {
        /// The dynamic channel the message belongs to.
        channel_id: u32,
        /// The complete message length across all fragments.
        total_length: u32,
        /// The first fragment.
        data: &'a [u8],
    },
    /// Data: a complete message (no Data First in flight) or the next fragment of one.
    Data {
        /// The dynamic channel the data belongs to.
        channel_id: u32,
        /// The payload bytes.
        data: &'a [u8],
    },
    /// Close: the peer is closing `channel_id`.
    Close {
        /// The dynamic channel being closed.
        channel_id: u32,
    },
    /// A command justrdp never negotiates (compressed data, soft-sync) or does not know.
    /// Well-formed-but-unknown: the session machine skips it (plan.md §11c).
    Unsupported {
        /// The header's `Cmd` value.
        cmd: u8,
    },
}

/// Read a `cbId`/`Sp`-coded variable-width integer: 0 → u8, 1 → u16 LE, 2 → u32 LE.
fn read_var(cur: &mut ReadCursor<'_>, code: u8, field: &'static str) -> Result<u32, DecodeError> {
    match code {
        0 => Ok(u32::from(cur.read_u8()?)),
        1 => Ok(u32::from(cur.read_u16_le()?)),
        2 => cur.read_u32_le(),
        _ => Err(DecodeError::InvalidField {
            field,
            reason: "field-width code 3 is invalid (MS-RDPEDYC 2.2)",
        }),
    }
}

/// The minimal `cbId`/`Sp` width code for `value`, and the encoder for it.
fn push_var(out: &mut Vec<u8>, value: u32) -> u8 {
    if value <= 0xFF {
        out.push(value as u8);
        0
    } else if value <= 0xFFFF {
        out.extend_from_slice(&(value as u16).to_le_bytes());
        1
    } else {
        out.extend_from_slice(&value.to_le_bytes());
        2
    }
}

impl<'a> DvcMessage<'a> {
    /// Decode one complete (SVC-reassembled) drdynvc PDU.
    pub fn decode(pdu: &'a [u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(pdu, "drdynvc pdu");
        let header = cur.read_u8()?;
        let cb_id = header & 0x03;
        let cmd = header >> 4;
        match cmd {
            CMD_CAPABILITIES => {
                cur.read_u8()?; // Pad
                let version = cur.read_u16_le()?;
                // Version 2/3 append four priority-charge u16s; irrelevant to a version-1
                // responder, so they are deliberately not decoded.
                Ok(DvcMessage::CapabilitiesRequest { version })
            }
            CMD_CREATE => {
                let channel_id = read_var(&mut cur, cb_id, "DYNVC_CREATE_REQ.ChannelId")?;
                let rest = cur.read_slice(cur.remaining())?;
                let name_bytes = rest.split(|&b| b == 0).next().unwrap_or(rest);
                let name = core::str::from_utf8(name_bytes).map_err(|_| {
                    DecodeError::InvalidField {
                        field: "DYNVC_CREATE_REQ.ChannelName",
                        reason: "channel name is not valid UTF-8",
                    }
                })?;
                Ok(DvcMessage::CreateRequest { channel_id, name })
            }
            CMD_DATA_FIRST => {
                let sp = (header >> 2) & 0x03;
                let channel_id = read_var(&mut cur, cb_id, "DYNVC_DATA_FIRST.ChannelId")?;
                let total_length = read_var(&mut cur, sp, "DYNVC_DATA_FIRST.Length")?;
                let data = cur.read_slice(cur.remaining())?;
                Ok(DvcMessage::DataFirst {
                    channel_id,
                    total_length,
                    data,
                })
            }
            CMD_DATA => {
                let channel_id = read_var(&mut cur, cb_id, "DYNVC_DATA.ChannelId")?;
                let data = cur.read_slice(cur.remaining())?;
                Ok(DvcMessage::Data { channel_id, data })
            }
            CMD_CLOSE => {
                let channel_id = read_var(&mut cur, cb_id, "DYNVC_CLOSE.ChannelId")?;
                Ok(DvcMessage::Close { channel_id })
            }
            cmd => Ok(DvcMessage::Unsupported { cmd }),
        }
    }
}

/// Encode the Capabilities Response (client→server, MS-RDPEDYC 2.2.1.2).
pub fn encode_capabilities_response(version: u16) -> Vec<u8> {
    let mut out = vec![CMD_CAPABILITIES << 4, 0x00];
    out.extend_from_slice(&version.to_le_bytes());
    out
}

/// Encode the Create Response (client→server, 2.2.2.2). `creation_status` is an HRESULT:
/// zero accepts the channel, a negative value (high bit set) refuses it.
pub fn encode_create_response(channel_id: u32, creation_status: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    let cb_id = push_var(&mut body, channel_id);
    let mut out = Vec::with_capacity(1 + body.len() + 4);
    out.push((CMD_CREATE << 4) | cb_id);
    out.extend_from_slice(&body);
    out.extend_from_slice(&creation_status.to_le_bytes());
    out
}

/// Encode the Close PDU (client→server, 2.2.4).
pub fn encode_close(channel_id: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(4);
    let cb_id = push_var(&mut body, channel_id);
    let mut out = Vec::with_capacity(1 + body.len());
    out.push((CMD_CLOSE << 4) | cb_id);
    out.extend_from_slice(&body);
    out
}

/// Encode `message` as Data / Data First (+ Data) PDUs, fragmenting at [`MAX_DATA_CHUNK`]
/// per MS-RDPEDYC 3.1.5.1.2. Each returned PDU still needs SVC chunking + MCS wrapping.
pub fn encode_data(channel_id: u32, message: &[u8]) -> Vec<Vec<u8>> {
    if message.len() <= MAX_DATA_CHUNK {
        let mut body = Vec::with_capacity(4);
        let cb_id = push_var(&mut body, channel_id);
        let mut out = Vec::with_capacity(1 + body.len() + message.len());
        out.push((CMD_DATA << 4) | cb_id);
        out.extend_from_slice(&body);
        out.extend_from_slice(message);
        return vec![out];
    }
    let mut pdus = Vec::new();
    let mut chunks = message.chunks(MAX_DATA_CHUNK);
    let first = chunks.next().expect("message is longer than one chunk");
    let mut id_bytes = Vec::with_capacity(4);
    let cb_id = push_var(&mut id_bytes, channel_id);
    let mut len_bytes = Vec::with_capacity(4);
    let sp = push_var(&mut len_bytes, message.len() as u32);
    let mut out = Vec::with_capacity(1 + id_bytes.len() + len_bytes.len() + first.len());
    out.push((CMD_DATA_FIRST << 4) | (sp << 2) | cb_id);
    out.extend_from_slice(&id_bytes);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(first);
    pdus.push(out);
    for chunk in chunks {
        let mut out = Vec::with_capacity(1 + id_bytes.len() + chunk.len());
        out.push((CMD_DATA << 4) | cb_id);
        out.extend_from_slice(&id_bytes);
        out.extend_from_slice(chunk);
        pdus.push(out);
    }
    pdus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_request_decodes_all_versions() {
        // Version 1: header, pad, version. Versions 2/3 trail priority charges (ignored).
        for (version, trailer) in [(1u16, &[][..]), (2, &[0u8; 8][..]), (3, &[0u8; 8][..])] {
            let mut pdu = vec![0x50, 0x00];
            pdu.extend_from_slice(&version.to_le_bytes());
            pdu.extend_from_slice(trailer);
            assert_eq!(
                DvcMessage::decode(&pdu).unwrap(),
                DvcMessage::CapabilitiesRequest { version }
            );
        }
    }

    #[test]
    fn capabilities_response_wire_shape() {
        assert_eq!(encode_capabilities_response(1), vec![0x50, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn create_request_decodes_id_and_name() {
        let mut pdu = vec![0x10, 0x07]; // cbId=0 (1-byte id), channel 7
        pdu.extend_from_slice(b"Microsoft::Windows::RDS::DisplayControl\0");
        assert_eq!(
            DvcMessage::decode(&pdu).unwrap(),
            DvcMessage::CreateRequest {
                channel_id: 7,
                name: "Microsoft::Windows::RDS::DisplayControl",
            }
        );
        // A two-byte channel id (cbId=1).
        let mut pdu = vec![0x11];
        pdu.extend_from_slice(&0x1234u16.to_le_bytes());
        pdu.extend_from_slice(b"x\0");
        assert!(matches!(
            DvcMessage::decode(&pdu).unwrap(),
            DvcMessage::CreateRequest { channel_id: 0x1234, name: "x" }
        ));
    }

    #[test]
    fn create_response_encodes_status() {
        assert_eq!(
            encode_create_response(7, 0),
            vec![0x10, 0x07, 0x00, 0x00, 0x00, 0x00]
        );
        let refused = encode_create_response(0x1234, 0x8000_4005);
        assert_eq!(refused[0], 0x11); // cbId=1
        assert_eq!(&refused[1..3], &0x1234u16.to_le_bytes());
        assert_eq!(&refused[3..7], &0x8000_4005u32.to_le_bytes());
    }

    #[test]
    fn small_data_is_one_data_pdu() {
        let pdus = encode_data(3, &[0xAA, 0xBB]);
        assert_eq!(pdus, vec![vec![0x30, 0x03, 0xAA, 0xBB]]);
        assert_eq!(
            DvcMessage::decode(&pdus[0]).unwrap(),
            DvcMessage::Data {
                channel_id: 3,
                data: &[0xAA, 0xBB],
            }
        );
    }

    #[test]
    fn large_data_fragments_into_data_first_plus_data() {
        let message = vec![9u8; MAX_DATA_CHUNK * 2 + 10];
        let pdus = encode_data(3, &message);
        assert_eq!(pdus.len(), 3);
        let DvcMessage::DataFirst {
            channel_id,
            total_length,
            data,
        } = DvcMessage::decode(&pdus[0]).unwrap()
        else {
            panic!("expected DataFirst");
        };
        assert_eq!(channel_id, 3);
        assert_eq!(total_length as usize, message.len());
        assert_eq!(data.len(), MAX_DATA_CHUNK);
        let mut reassembled = data.to_vec();
        for pdu in &pdus[1..] {
            let DvcMessage::Data { channel_id: 3, data } = DvcMessage::decode(pdu).unwrap() else {
                panic!("expected Data on channel 3");
            };
            assert!(data.len() <= MAX_DATA_CHUNK);
            reassembled.extend_from_slice(data);
        }
        assert_eq!(reassembled, message);
    }

    #[test]
    fn close_round_trips() {
        let pdu = encode_close(0x0001_0000); // forces the 4-byte id form
        assert_eq!(pdu[0], 0x42); // Cmd=4, cbId=2
        assert_eq!(
            DvcMessage::decode(&pdu).unwrap(),
            DvcMessage::Close {
                channel_id: 0x0001_0000,
            }
        );
    }

    #[test]
    fn compressed_and_soft_sync_commands_surface_as_unsupported() {
        for cmd in [0x06u8, 0x07, 0x08, 0x09, 0x0F] {
            assert_eq!(
                DvcMessage::decode(&[cmd << 4, 0x01]).unwrap(),
                DvcMessage::Unsupported { cmd }
            );
        }
    }

    #[test]
    fn truncated_pdus_are_typed_errors() {
        assert!(DvcMessage::decode(&[]).is_err());
        assert!(DvcMessage::decode(&[0x12]).is_err()); // create, 2-byte id, no id bytes
        assert!(DvcMessage::decode(&[0x50, 0x00]).is_err()); // caps without version
    }
}
