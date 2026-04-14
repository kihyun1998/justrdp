//! Miscellaneous TSMF PDUs that didn't fit into the larger families:
//! volume notifications, allocator hints, and client-originated event
//! notifications. Together with `pdu::control` and `pdu::geometry`,
//! this finishes the §9.10 PDU layer.
//!
//! - [`OnStreamVolume`] (§2.2.5.5.1) — server pushes master volume.
//! - [`OnChannelVolume`] (§2.2.5.5.2) — server pushes per-channel volume.
//! - [`SetAllocator`] (§2.2.5.3.1) — server hints buffer pool layout.
//! - [`ClientEventNotification`] (§2.2.6.2) — client sends an opaque
//!   event blob on the **Client Notifications** interface (the only
//!   client→server PDU on that interface besides PlaybackAck).
//!
//! All four are fire-and-forget: no responses, no correlation table.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{FunctionId, InterfaceValue, Mask};
use crate::pdu::guid::{decode_guid, encode_guid, Guid, GUID_SIZE};
use crate::pdu::header::{
    decode_request_header, encode_header, SharedMsgHeader, REQUEST_HEADER_SIZE,
};

// ── DoS cap (checklist §10) ─────────────────────────────────────────

/// Maximum bytes in a [`ClientEventNotification`] `p_blob`. Real
/// client events carry trivial scalar payloads; 4 KiB is generous
/// headroom that still bounds allocation.
pub const MAX_EVENT_BLOB_BYTES: usize = 4096;

// ── OnStreamVolume (§2.2.5.5.1) — 24B payload ───────────────────────

/// Server pushes a presentation's master volume / mute state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnStreamVolume {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub new_volume: u32,
    /// 0 = not muted, 1 = muted.
    pub b_muted: u32,
}

impl OnStreamVolume {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 4 + 4;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for OnStreamVolume {
    fn name(&self) -> &'static str {
        "MS-RDPEV::OnStreamVolume"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::OnStreamVolume,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.new_volume, self.name())?;
        dst.write_u32_le(self.b_muted, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for OnStreamVolume {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::OnStreamVolume";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::OnStreamVolume)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let new_volume = src.read_u32_le(CTX)?;
        let b_muted = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            new_volume,
            b_muted,
        })
    }
}

// ── OnChannelVolume (§2.2.5.5.2) — 24B payload ──────────────────────

/// Server pushes a single audio channel's volume within a presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnChannelVolume {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub channel_volume: u32,
    /// Identifier of the channel whose volume changed.
    pub changed_channel: u32,
}

impl OnChannelVolume {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 4 + 4;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for OnChannelVolume {
    fn name(&self) -> &'static str {
        "MS-RDPEV::OnChannelVolume"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::OnChannelVolume,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.channel_volume, self.name())?;
        dst.write_u32_le(self.changed_channel, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for OnChannelVolume {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::OnChannelVolume";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::OnChannelVolume)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let channel_volume = src.read_u32_le(CTX)?;
        let changed_channel = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            channel_volume,
            changed_channel,
        })
    }
}

// ── SetAllocator (§2.2.5.3.1) — 36B payload ─────────────────────────

/// Buffer-pool hint. Server suggests how the client should pre-
/// allocate sample buffers; the client SHOULD honour the hint but
/// MUST NOT require it (per spec §3.3.5.3.1, MAY be omitted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetAllocator {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub stream_id: u32,
    pub c_buffers: u32,
    /// Bytes per buffer, excluding `cb_prefix`.
    pub cb_buffer: u32,
    /// Buffer alignment in bytes.
    pub cb_align: u32,
    /// Header-prefix bytes before each buffer.
    pub cb_prefix: u32,
}

impl SetAllocator {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 4 * 5;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for SetAllocator {
    fn name(&self) -> &'static str {
        "MS-RDPEV::SetAllocator"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::SetAllocator,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.stream_id, self.name())?;
        dst.write_u32_le(self.c_buffers, self.name())?;
        dst.write_u32_le(self.cb_buffer, self.name())?;
        dst.write_u32_le(self.cb_align, self.name())?;
        dst.write_u32_le(self.cb_prefix, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SetAllocator {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::SetAllocator";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::SetAllocator)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let stream_id = src.read_u32_le(CTX)?;
        let c_buffers = src.read_u32_le(CTX)?;
        let cb_buffer = src.read_u32_le(CTX)?;
        let cb_align = src.read_u32_le(CTX)?;
        let cb_prefix = src.read_u32_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            stream_id,
            c_buffers,
            cb_buffer,
            cb_align,
            cb_prefix,
        })
    }
}

// ── ClientEventNotification (§2.2.6.2) — variable ───────────────────

/// Client-originated event notification on the Client Notifications
/// interface (`InterfaceValue=0x1`, `FunctionId=0x101`). Carries an
/// opaque event blob; the host trait layer interprets `event_id` /
/// `p_blob` according to whatever the application protocol expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEventNotification {
    pub message_id: u32,
    pub stream_id: u32,
    pub event_id: u32,
    /// Opaque event payload; bounded by [`MAX_EVENT_BLOB_BYTES`].
    pub p_blob: Vec<u8>,
}

impl ClientEventNotification {
    fn payload_size(&self) -> usize {
        4 + 4 + 4 + self.p_blob.len()
    }
}

impl Encode for ClientEventNotification {
    fn name(&self) -> &'static str {
        "MS-RDPEV::ClientEventNotification"
    }
    fn size(&self) -> usize {
        REQUEST_HEADER_SIZE + self.payload_size()
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.p_blob.len() > MAX_EVENT_BLOB_BYTES {
            return Err(EncodeError::invalid_value(self.name(), "cbData too large"));
        }
        let header = SharedMsgHeader::request(
            InterfaceValue::ClientNotifications,
            self.message_id,
            FunctionId::ClientEventNotification,
        );
        encode_header(dst, &header)?;
        dst.write_u32_le(self.stream_id, self.name())?;
        dst.write_u32_le(self.event_id, self.name())?;
        dst.write_u32_le(self.p_blob.len() as u32, self.name())?;
        dst.write_slice(&self.p_blob, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for ClientEventNotification {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::ClientEventNotification";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ClientNotifications
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::ClientEventNotification)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let stream_id = src.read_u32_le(CTX)?;
        let event_id = src.read_u32_le(CTX)?;
        let cb_data = src.read_u32_le(CTX)? as usize;
        if cb_data > MAX_EVENT_BLOB_BYTES {
            return Err(DecodeError::invalid_value(CTX, "cbData too large"));
        }
        if cb_data > src.remaining() {
            return Err(DecodeError::invalid_value(CTX, "cbData underflow"));
        }
        let p_blob = src.read_slice(cb_data, CTX)?.to_vec();
        Ok(Self {
            message_id: header.message_id,
            stream_id,
            event_id,
            p_blob,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn encode_to_vec<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        pdu.encode(&mut cur).unwrap();
        assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
        buf
    }

    const G: Guid = Guid([
        0x9f, 0x04, 0x86, 0xe0, 0x26, 0xd9, 0xae, 0x45, 0x8c, 0x0f, 0x3e, 0x05, 0x6a, 0xf3, 0xf7,
        0xd4,
    ]);

    // ── OnStreamVolume / OnChannelVolume ──────────────────────────

    #[test]
    fn on_stream_volume_roundtrip_and_function_id() {
        let pdu = OnStreamVolume {
            message_id: 0,
            presentation_id: G,
            new_volume: 0x8000_0000,
            b_muted: 1,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), OnStreamVolume::WIRE_SIZE);
        // FunctionId = ON_STREAM_VOLUME (0x10F)
        assert_eq!(&bytes[8..12], &[0x0f, 0x01, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(OnStreamVolume::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn on_channel_volume_roundtrip_and_function_id() {
        let pdu = OnChannelVolume {
            message_id: 0,
            presentation_id: G,
            channel_volume: 0xFFFF,
            changed_channel: 2,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), OnChannelVolume::WIRE_SIZE);
        // FunctionId = ON_CHANNEL_VOLUME (0x110)
        assert_eq!(&bytes[8..12], &[0x10, 0x01, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        assert_eq!(OnChannelVolume::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn volume_pdus_reject_each_others_function_ids() {
        let bytes = encode_to_vec(&OnStreamVolume {
            message_id: 0,
            presentation_id: G,
            new_volume: 0,
            b_muted: 0,
        });
        let mut r = ReadCursor::new(&bytes);
        assert!(OnChannelVolume::decode(&mut r).is_err());
    }

    // ── SetAllocator ──────────────────────────────────────────────

    #[test]
    fn set_allocator_matches_spec_wire_vector() {
        // Spec §4 §11.8, total 48 bytes (without GUID swap):
        //   00 00 00 40  PROXY
        //   00 00 00 00  MessageId
        //   12 01 00 00  SET_ALLOCATOR (0x112)
        //   <16B GUID = {8b844079-b70e-450f-8793-3d7ffa31d053}>
        //   01 00 00 00  StreamId = 1
        //   64 00 00 00  cBuffers = 100
        //   05 00 01 00  cbBuffer = 0x10005 = 65541
        //   01 00 00 00  cbAlign = 1
        //   00 00 00 00  cbPrefix = 0
        let pres = Guid([
            0x79, 0x40, 0x84, 0x8b, 0x0e, 0xb7, 0x0f, 0x45, 0x87, 0x93, 0x3d, 0x7f, 0xfa, 0x31,
            0xd0, 0x53,
        ]);
        let pdu = SetAllocator {
            message_id: 0,
            presentation_id: pres,
            stream_id: 1,
            c_buffers: 100,
            cb_buffer: 0x1_0005,
            cb_align: 1,
            cb_prefix: 0,
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 48);
        assert_eq!(bytes.len(), SetAllocator::WIRE_SIZE);
        assert_eq!(
            &bytes[..12],
            &[
                0x00, 0x00, 0x00, 0x40, // PROXY
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x12, 0x01, 0x00, 0x00, // FunctionId
            ]
        );
        assert_eq!(&bytes[12..28], pres.as_bytes());
        assert_eq!(&bytes[28..32], &1u32.to_le_bytes()); // StreamId
        assert_eq!(&bytes[32..36], &100u32.to_le_bytes()); // cBuffers
        assert_eq!(&bytes[36..40], &[0x05, 0x00, 0x01, 0x00]); // cbBuffer = 0x10005
        assert_eq!(&bytes[40..44], &1u32.to_le_bytes()); // cbAlign
        assert_eq!(&bytes[44..48], &0u32.to_le_bytes()); // cbPrefix

        let mut r = ReadCursor::new(&bytes);
        assert_eq!(SetAllocator::decode(&mut r).unwrap(), pdu);
    }

    // ── ClientEventNotification ───────────────────────────────────

    #[test]
    fn client_event_notification_full_layout_and_interface() {
        let pdu = ClientEventNotification {
            message_id: 0,
            stream_id: 1,
            event_id: 0xCAFE,
            p_blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = encode_to_vec(&pdu);
        // 12 hdr + 4 stream + 4 event + 4 cb + 4 blob = 28
        assert_eq!(bytes.len(), 28);
        // ClientEventNotification rides on InterfaceValue=1, opcode 0x101
        // → InterfaceId = 0x40000001, FunctionId = 0x101
        assert_eq!(
            &bytes[..12],
            &[
                0x01, 0x00, 0x00, 0x40, // InterfaceId = PROXY | ClientNotifications
                0x00, 0x00, 0x00, 0x00, // MessageId
                0x01, 0x01, 0x00, 0x00, // FunctionId = 0x101
            ]
        );
        assert_eq!(&bytes[12..16], &1u32.to_le_bytes());
        assert_eq!(&bytes[16..20], &0xCAFEu32.to_le_bytes());
        assert_eq!(&bytes[20..24], &4u32.to_le_bytes());
        assert_eq!(&bytes[24..28], &[0xDE, 0xAD, 0xBE, 0xEF]);

        let mut r = ReadCursor::new(&bytes);
        assert_eq!(ClientEventNotification::decode(&mut r).unwrap(), pdu);
    }

    #[test]
    fn client_event_notification_zero_blob_is_legal() {
        let pdu = ClientEventNotification {
            message_id: 0,
            stream_id: 0,
            event_id: 0,
            p_blob: vec![],
        };
        let bytes = encode_to_vec(&pdu);
        assert_eq!(bytes.len(), 24);
        let mut r = ReadCursor::new(&bytes);
        assert!(ClientEventNotification::decode(&mut r).is_ok());
    }

    #[test]
    fn client_event_notification_encode_rejects_oversize_blob() {
        let pdu = ClientEventNotification {
            message_id: 0,
            stream_id: 0,
            event_id: 0,
            p_blob: vec![0u8; MAX_EVENT_BLOB_BYTES + 1],
        };
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(pdu.encode(&mut cur).is_err());
    }

    #[test]
    fn client_event_notification_decode_rejects_oversize_blob() {
        // Hand-roll a header claiming cbData > MAX.
        let mut bytes: Vec<u8> = vec![
            0x01, 0x00, 0x00, 0x40, // PROXY | ClientNotifications
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x01, 0x01, 0x00, 0x00, // FunctionId = CLIENT_EVENT_NOTIFICATION
            0x00, 0x00, 0x00, 0x00, // StreamId
            0x00, 0x00, 0x00, 0x00, // EventId
        ];
        bytes.extend_from_slice(&((MAX_EVENT_BLOB_BYTES as u32) + 1).to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        assert!(ClientEventNotification::decode(&mut r).is_err());
    }

    #[test]
    fn client_event_notification_rejects_server_data_interface() {
        // Same payload but InterfaceValue=0 → FunctionId 0x101 means
        // SET_CHANNEL_PARAMS on Server Data, not ClientEventNotification.
        let bytes = [
            0x00, 0x00, 0x00, 0x40, // ServerData PROXY (wrong)
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x01, 0x01, 0x00, 0x00, // FunctionId
            0x00, 0x00, 0x00, 0x00, // StreamId
            0x00, 0x00, 0x00, 0x00, // EventId
            0x00, 0x00, 0x00, 0x00, // cbData
        ];
        let mut r = ReadCursor::new(&bytes);
        assert!(ClientEventNotification::decode(&mut r).is_err());
    }
}
