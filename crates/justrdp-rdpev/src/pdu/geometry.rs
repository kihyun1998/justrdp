//! Window placement and geometry update PDUs (MS-RDPEV §2.2.5.2.10,
//! §2.2.5.2.11, §2.2.5.2.12) plus their substructures `GeometryInfo`
//! (§2.2.11) and `TsRect` (§2.2.12).
//!
//! These messages move server-side window state down to the client so
//! it can position video output relative to the remote desktop's
//! coordinate system. None of them require a response.
//!
//! ## Wire-format quirks
//!
//! - `GeometryInfo` exists in **two** sizes: 44 bytes (no `Padding`)
//!   and 48 bytes (4-byte `Padding` field). Which one is on the wire
//!   is signalled out-of-band by the enclosing `numGeometryInfo`
//!   length prefix in `UpdateGeometryInfo`. The decoder accepts both.
//! - `TsRect` has the unusual field order `(Top, Left, Bottom, Right)`
//!   per spec §2.2.12 -- not the typical `(Left, Top, Right, Bottom)`.
//!   Calls to the rect helpers must pass values in that order.
//! - `SetSourceVideoRect` carries 4 × `f32` normalized coordinates
//!   ([0.0, 1.0]); we serialise via `to_bits()` to preserve every bit.
//! - `SetVideoWindow` carries two **u64** HWND values that are only
//!   meaningful on the server.

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{FunctionId, InterfaceValue, Mask};
use crate::pdu::guid::{decode_guid, encode_guid, Guid, GUID_SIZE};
use crate::pdu::header::{
    decode_request_header, encode_header, SharedMsgHeader, REQUEST_HEADER_SIZE,
};

// ── DoS caps (checklist §10) ────────────────────────────────────────

/// Maximum number of `TsRect` entries in an `UpdateGeometryInfo`
/// `pVisibleRect` array. 256 entries × 16 bytes = 4 KiB worst case.
pub const MAX_VISIBLE_RECTS: usize = 256;

// ── TsRect (§2.2.12) — 16 bytes fixed ───────────────────────────────

/// Visible-region rectangle. **Field order on the wire is
/// `(Top, Left, Bottom, Right)`**, not the conventional
/// `(Left, Top, Right, Bottom)`; the field names below match the spec
/// exactly so call sites can't accidentally permute the order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsRect {
    pub top: u32,
    pub left: u32,
    pub bottom: u32,
    pub right: u32,
}

impl TsRect {
    pub const WIRE_SIZE: usize = 16;

    fn encode_inner(&self, dst: &mut WriteCursor<'_>, ctx: &'static str) -> EncodeResult<()> {
        dst.write_u32_le(self.top, ctx)?;
        dst.write_u32_le(self.left, ctx)?;
        dst.write_u32_le(self.bottom, ctx)?;
        dst.write_u32_le(self.right, ctx)?;
        Ok(())
    }

    fn decode_inner(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<Self> {
        Ok(Self {
            top: src.read_u32_le(ctx)?,
            left: src.read_u32_le(ctx)?,
            bottom: src.read_u32_le(ctx)?,
            right: src.read_u32_le(ctx)?,
        })
    }
}

// ── GeometryInfo (§2.2.11) — 44 or 48 bytes ─────────────────────────

/// Wire size of a `GeometryInfo` without the optional `Padding` field.
pub const GEOMETRY_INFO_SIZE_NO_PAD: usize = 44;

/// Wire size of a `GeometryInfo` with the optional `Padding` field.
pub const GEOMETRY_INFO_SIZE_WITH_PAD: usize = 48;

/// Per-window geometry block carried inside [`UpdateGeometryInfo`].
///
/// The `Padding` field at offset 44 is optional: present iff the
/// enclosing `numGeometryInfo` length prefix is 48. We store it as
/// `Option<u32>` so encoders can choose either form and the decoder
/// can faithfully round-trip whichever the server sent.
///
/// `Reserved` is "MUST be ignored" per spec but we still pass it
/// through so a strict roundtrip test catches accidental zeroing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeometryInfo {
    pub video_window_id: u64,
    /// `TS_WNDFLAG_*` bitmask -- see [`crate::constants::window_flags`].
    pub video_window_state: u32,
    pub width: u32,
    pub height: u32,
    pub left: u32,
    pub top: u32,
    /// MUST be ignored per spec §2.2.11; passed through verbatim.
    pub reserved: u64,
    pub client_left: u32,
    pub client_top: u32,
    /// Optional 4-byte padding. `Some(_)` produces the 48-byte form,
    /// `None` produces the 44-byte form.
    pub padding: Option<u32>,
}

impl GeometryInfo {
    /// Wire size of this instance (44 if `padding == None`, 48 otherwise).
    pub fn wire_size(&self) -> usize {
        if self.padding.is_some() {
            GEOMETRY_INFO_SIZE_WITH_PAD
        } else {
            GEOMETRY_INFO_SIZE_NO_PAD
        }
    }

    fn encode_inner(&self, dst: &mut WriteCursor<'_>, ctx: &'static str) -> EncodeResult<()> {
        dst.write_u64_le(self.video_window_id, ctx)?;
        dst.write_u32_le(self.video_window_state, ctx)?;
        dst.write_u32_le(self.width, ctx)?;
        dst.write_u32_le(self.height, ctx)?;
        dst.write_u32_le(self.left, ctx)?;
        dst.write_u32_le(self.top, ctx)?;
        dst.write_u64_le(self.reserved, ctx)?;
        dst.write_u32_le(self.client_left, ctx)?;
        dst.write_u32_le(self.client_top, ctx)?;
        if let Some(pad) = self.padding {
            dst.write_u32_le(pad, ctx)?;
        }
        Ok(())
    }

    /// Decodes a `GeometryInfo` of either size. The caller passes the
    /// `numGeometryInfo` length prefix from the enclosing PDU; only
    /// 44 and 48 are valid.
    fn decode_inner(
        src: &mut ReadCursor<'_>,
        size: usize,
        ctx: &'static str,
    ) -> DecodeResult<Self> {
        if size != GEOMETRY_INFO_SIZE_NO_PAD && size != GEOMETRY_INFO_SIZE_WITH_PAD {
            return Err(DecodeError::invalid_value(ctx, "numGeometryInfo not 44/48"));
        }
        let video_window_id = src.read_u64_le(ctx)?;
        let video_window_state = src.read_u32_le(ctx)?;
        let width = src.read_u32_le(ctx)?;
        let height = src.read_u32_le(ctx)?;
        let left = src.read_u32_le(ctx)?;
        let top = src.read_u32_le(ctx)?;
        let reserved = src.read_u64_le(ctx)?;
        let client_left = src.read_u32_le(ctx)?;
        let client_top = src.read_u32_le(ctx)?;
        let padding = if size == GEOMETRY_INFO_SIZE_WITH_PAD {
            Some(src.read_u32_le(ctx)?)
        } else {
            None
        };
        Ok(Self {
            video_window_id,
            video_window_state,
            width,
            height,
            left,
            top,
            reserved,
            client_left,
            client_top,
            padding,
        })
    }
}

// ── SetVideoWindow (§2.2.5.2.10) — 32B payload ──────────────────────

/// Server-side video window association. Both HWND values are
/// meaningful only on the server -- the client uses them as opaque
/// identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetVideoWindow {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub video_window_id: u64,
    pub hwnd_parent: u64,
}

impl SetVideoWindow {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 8 + 8;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for SetVideoWindow {
    fn name(&self) -> &'static str {
        "MS-RDPEV::SetVideoWindow"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::SetVideoWindow,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u64_le(self.video_window_id, self.name())?;
        dst.write_u64_le(self.hwnd_parent, self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SetVideoWindow {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::SetVideoWindow";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::SetVideoWindow)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let video_window_id = src.read_u64_le(CTX)?;
        let hwnd_parent = src.read_u64_le(CTX)?;
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            video_window_id,
            hwnd_parent,
        })
    }
}

// ── UpdateGeometryInfo (§2.2.5.2.11) — variable ─────────────────────

/// Server pushes a window's current geometry plus its visible region
/// (a list of clipping rectangles) to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateGeometryInfo {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub geometry: GeometryInfo,
    pub visible_rects: Vec<TsRect>,
}

impl UpdateGeometryInfo {
    fn payload_size(&self) -> usize {
        GUID_SIZE
            + 4 // numGeometryInfo
            + self.geometry.wire_size()
            + 4 // cbVisibleRect
            + self.visible_rects.len() * TsRect::WIRE_SIZE
    }
}

impl Encode for UpdateGeometryInfo {
    fn name(&self) -> &'static str {
        "MS-RDPEV::UpdateGeometryInfo"
    }
    fn size(&self) -> usize {
        REQUEST_HEADER_SIZE + self.payload_size()
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.visible_rects.len() > MAX_VISIBLE_RECTS {
            return Err(EncodeError::invalid_value(self.name(), "too many visible rects"));
        }
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::UpdateGeometryInfo,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.geometry.wire_size() as u32, self.name())?;
        self.geometry.encode_inner(dst, self.name())?;
        let cb_visible_rect = self.visible_rects.len() * TsRect::WIRE_SIZE;
        dst.write_u32_le(cb_visible_rect as u32, self.name())?;
        for r in &self.visible_rects {
            r.encode_inner(dst, self.name())?;
        }
        Ok(())
    }
}

impl<'de> Decode<'de> for UpdateGeometryInfo {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::UpdateGeometryInfo";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::UpdateGeometryInfo)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let num_geometry_info = src.read_u32_le(CTX)? as usize;
        let geometry = GeometryInfo::decode_inner(src, num_geometry_info, CTX)?;
        let cb_visible_rect = src.read_u32_le(CTX)? as usize;
        if cb_visible_rect % TsRect::WIRE_SIZE != 0 {
            return Err(DecodeError::invalid_value(
                CTX,
                "cbVisibleRect not multiple of 16",
            ));
        }
        let n_rects = cb_visible_rect / TsRect::WIRE_SIZE;
        if n_rects > MAX_VISIBLE_RECTS {
            return Err(DecodeError::invalid_value(CTX, "too many visible rects"));
        }
        if cb_visible_rect > src.remaining() {
            return Err(DecodeError::invalid_value(CTX, "cbVisibleRect underflow"));
        }
        let mut visible_rects = Vec::with_capacity(n_rects);
        for _ in 0..n_rects {
            visible_rects.push(TsRect::decode_inner(src, CTX)?);
        }
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            geometry,
            visible_rects,
        })
    }
}

// ── SetSourceVideoRect (§2.2.5.2.12) — 32B payload ──────────────────

/// Source-rectangle crop, expressed in normalized [0.0, 1.0]
/// coordinates. Stored as `f32` and serialised via `to_bits` to
/// preserve every bit.
///
/// AMBIGUITY: spec §2.2.5.2.12 says `FunctionId MUST be set to
/// REMOVE_STREAM (0x00000116)` -- this is a documentation error in
/// the spec. The function name is `SET_SOURCE_VIDEO_RECT` and the
/// value is 0x116, while `REMOVE_STREAM` is 0x115. We use the
/// numerically correct value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetSourceVideoRect {
    pub message_id: u32,
    pub presentation_id: Guid,
    pub left: f32,
    pub top: f32,
    pub right: f32,
    pub bottom: f32,
}

impl SetSourceVideoRect {
    pub const PAYLOAD_SIZE: usize = GUID_SIZE + 4 * 4;
    pub const WIRE_SIZE: usize = REQUEST_HEADER_SIZE + Self::PAYLOAD_SIZE;
}

impl Encode for SetSourceVideoRect {
    fn name(&self) -> &'static str {
        "MS-RDPEV::SetSourceVideoRect"
    }
    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = SharedMsgHeader::request(
            InterfaceValue::ServerData,
            self.message_id,
            FunctionId::SetSourceVideoRect,
        );
        encode_header(dst, &header)?;
        encode_guid(dst, &self.presentation_id, self.name())?;
        dst.write_u32_le(self.left.to_bits(), self.name())?;
        dst.write_u32_le(self.top.to_bits(), self.name())?;
        dst.write_u32_le(self.right.to_bits(), self.name())?;
        dst.write_u32_le(self.bottom.to_bits(), self.name())?;
        Ok(())
    }
}

impl<'de> Decode<'de> for SetSourceVideoRect {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        const CTX: &str = "MS-RDPEV::SetSourceVideoRect";
        let header = decode_request_header(src)?;
        if header.interface_value != InterfaceValue::ServerData
            || header.mask != Mask::Proxy
            || header.function_id != Some(FunctionId::SetSourceVideoRect)
        {
            return Err(DecodeError::invalid_value(CTX, "header dispatch"));
        }
        let presentation_id = decode_guid(src, CTX)?;
        let left = f32::from_bits(src.read_u32_le(CTX)?);
        let top = f32::from_bits(src.read_u32_le(CTX)?);
        let right = f32::from_bits(src.read_u32_le(CTX)?);
        let bottom = f32::from_bits(src.read_u32_le(CTX)?);
        Ok(Self {
            message_id: header.message_id,
            presentation_id,
            left,
            top,
            right,
            bottom,
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

    fn dummy_geometry(with_padding: bool) -> GeometryInfo {
        GeometryInfo {
            video_window_id: 0x1122_3344_5566_7788,
            video_window_state: 0x1001, // NEW | VISRGN
            width: 1920,
            height: 1080,
            left: 100,
            top: 200,
            reserved: 0xDEAD_BEEF_CAFE_BABE,
            client_left: 0,
            client_top: 0,
            padding: if with_padding { Some(0xFFFF_FFFF) } else { None },
        }
    }

    // ── TsRect ────────────────────────────────────────────────────

    #[test]
    fn ts_rect_field_order_is_top_left_bottom_right() {
        // Spec §2.2.12 specifies (Top, Left, Bottom, Right). Verify
        // the bytes literally come out in that order.
        let r = TsRect {
            top: 0x11,
            left: 0x22,
            bottom: 0x33,
            right: 0x44,
        };
        let mut buf: Vec<u8> = vec![0u8; TsRect::WIRE_SIZE];
        let mut cur = WriteCursor::new(&mut buf);
        r.encode_inner(&mut cur, "test").unwrap();
        assert_eq!(
            buf,
            [
                0x11, 0, 0, 0, // Top
                0x22, 0, 0, 0, // Left
                0x33, 0, 0, 0, // Bottom
                0x44, 0, 0, 0, // Right
            ]
        );

        let mut rd = ReadCursor::new(&buf);
        let back = TsRect::decode_inner(&mut rd, "test").unwrap();
        assert_eq!(back, r);
    }

    // ── GeometryInfo ──────────────────────────────────────────────

    #[test]
    fn geometry_info_44_byte_form_round_trips() {
        let g = dummy_geometry(false);
        assert_eq!(g.wire_size(), 44);
        let mut buf: Vec<u8> = vec![0u8; g.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        g.encode_inner(&mut cur, "test").unwrap();
        let mut rd = ReadCursor::new(&buf);
        let back = GeometryInfo::decode_inner(&mut rd, 44, "test").unwrap();
        assert_eq!(back, g);
        assert!(back.padding.is_none());
    }

    #[test]
    fn geometry_info_48_byte_form_round_trips() {
        let g = dummy_geometry(true);
        assert_eq!(g.wire_size(), 48);
        let mut buf: Vec<u8> = vec![0u8; g.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        g.encode_inner(&mut cur, "test").unwrap();
        let mut rd = ReadCursor::new(&buf);
        let back = GeometryInfo::decode_inner(&mut rd, 48, "test").unwrap();
        assert_eq!(back, g);
        assert_eq!(back.padding, Some(0xFFFF_FFFF));
    }

    #[test]
    fn geometry_info_decode_rejects_invalid_size() {
        let g = dummy_geometry(false);
        let mut buf: Vec<u8> = vec![0u8; g.wire_size()];
        let mut cur = WriteCursor::new(&mut buf);
        g.encode_inner(&mut cur, "t").unwrap();
        for &bad in &[0, 1, 43, 45, 47, 49, 100] {
            let mut rd = ReadCursor::new(&buf);
            assert!(GeometryInfo::decode_inner(&mut rd, bad, "t").is_err());
        }
    }

    // ── SetVideoWindow ────────────────────────────────────────────

    #[test]
    fn set_video_window_full_layout() {
        let pdu = SetVideoWindow {
            message_id: 0,
            presentation_id: G,
            video_window_id: 0x1111_2222_3333_4444,
            hwnd_parent: 0x5555_6666_7777_8888,
        };
        let bytes = encode_to_vec(&pdu);
        // 12 hdr + 16 guid + 8 + 8 = 44
        assert_eq!(bytes.len(), 44);
        // FunctionId = SET_VIDEO_WINDOW (0x104)
        assert_eq!(&bytes[8..12], &[0x04, 0x01, 0x00, 0x00]);
        let mut r = ReadCursor::new(&bytes);
        let decoded = SetVideoWindow::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    // ── UpdateGeometryInfo ────────────────────────────────────────

    #[test]
    fn update_geometry_info_44b_form_with_rects_round_trips() {
        let pdu = UpdateGeometryInfo {
            message_id: 0,
            presentation_id: G,
            geometry: dummy_geometry(false),
            visible_rects: vec![
                TsRect {
                    top: 1,
                    left: 2,
                    bottom: 3,
                    right: 4,
                },
                TsRect {
                    top: 10,
                    left: 20,
                    bottom: 30,
                    right: 40,
                },
            ],
        };
        let bytes = encode_to_vec(&pdu);
        // 12 hdr + 16 guid + 4 numGeo + 44 geo + 4 cbRect + 32 rects = 112
        assert_eq!(bytes.len(), 12 + 16 + 4 + 44 + 4 + 32);
        // FunctionId = UPDATE_GEOMETRY_INFO (0x114)
        assert_eq!(&bytes[8..12], &[0x14, 0x01, 0x00, 0x00]);
        // numGeometryInfo at [28..32] = 44
        assert_eq!(&bytes[28..32], &44u32.to_le_bytes());
        // cbVisibleRect at [76..80] = 32
        assert_eq!(&bytes[76..80], &32u32.to_le_bytes());

        let mut r = ReadCursor::new(&bytes);
        let decoded = UpdateGeometryInfo::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn update_geometry_info_48b_form_round_trips() {
        let pdu = UpdateGeometryInfo {
            message_id: 0,
            presentation_id: G,
            geometry: dummy_geometry(true),
            visible_rects: vec![],
        };
        let bytes = encode_to_vec(&pdu);
        let mut r = ReadCursor::new(&bytes);
        let decoded = UpdateGeometryInfo::decode(&mut r).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(decoded.geometry.padding, Some(0xFFFF_FFFF));
    }

    #[test]
    fn update_geometry_info_zero_rects_is_legal() {
        // Empty visible region = window hidden (boundary case §12).
        let pdu = UpdateGeometryInfo {
            message_id: 0,
            presentation_id: G,
            geometry: dummy_geometry(false),
            visible_rects: vec![],
        };
        let bytes = encode_to_vec(&pdu);
        let mut r = ReadCursor::new(&bytes);
        assert!(UpdateGeometryInfo::decode(&mut r).is_ok());
    }

    #[test]
    fn update_geometry_info_decode_rejects_misaligned_cb_visible_rect() {
        // Build a valid PDU, then bump cbVisibleRect by 1 (no longer
        // a multiple of 16). Decoder must refuse.
        let pdu = UpdateGeometryInfo {
            message_id: 0,
            presentation_id: G,
            geometry: dummy_geometry(false),
            visible_rects: vec![TsRect {
                top: 0,
                left: 0,
                bottom: 0,
                right: 0,
            }],
        };
        let mut bytes = encode_to_vec(&pdu);
        // cbVisibleRect lives at offset 12+16+4+44 = 76.
        let claimed = u32::from_le_bytes([bytes[76], bytes[77], bytes[78], bytes[79]]) + 1;
        bytes[76..80].copy_from_slice(&claimed.to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        assert!(UpdateGeometryInfo::decode(&mut r).is_err());
    }

    #[test]
    fn update_geometry_info_decode_rejects_invalid_num_geometry_info() {
        let pdu = UpdateGeometryInfo {
            message_id: 0,
            presentation_id: G,
            geometry: dummy_geometry(false),
            visible_rects: vec![],
        };
        let mut bytes = encode_to_vec(&pdu);
        // numGeometryInfo at [28..32]; force it to 47.
        bytes[28..32].copy_from_slice(&47u32.to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        assert!(UpdateGeometryInfo::decode(&mut r).is_err());
    }

    #[test]
    fn update_geometry_info_encode_rejects_too_many_rects() {
        let pdu = UpdateGeometryInfo {
            message_id: 0,
            presentation_id: G,
            geometry: dummy_geometry(false),
            visible_rects: vec![
                TsRect {
                    top: 0,
                    left: 0,
                    bottom: 0,
                    right: 0
                };
                MAX_VISIBLE_RECTS + 1
            ],
        };
        let mut buf: Vec<u8> = vec![0u8; pdu.size()];
        let mut cur = WriteCursor::new(&mut buf);
        assert!(pdu.encode(&mut cur).is_err());
    }

    #[test]
    fn update_geometry_info_decode_rejects_too_many_rects() {
        // Hand-roll a header claiming 257 visible rects (way over cap).
        let mut bytes: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x14, 0x01, 0x00, 0x00, // UPDATE_GEOMETRY_INFO
        ];
        bytes.extend_from_slice(G.as_bytes());
        bytes.extend_from_slice(&44u32.to_le_bytes()); // numGeometryInfo
        bytes.extend_from_slice(&[0u8; 44]); // bogus geometry
        // cbVisibleRect = (MAX + 1) * 16
        let oversized_cb = ((MAX_VISIBLE_RECTS as u32) + 1) * 16;
        bytes.extend_from_slice(&oversized_cb.to_le_bytes());
        let mut r = ReadCursor::new(&bytes);
        assert!(UpdateGeometryInfo::decode(&mut r).is_err());
    }

    // ── SetSourceVideoRect ────────────────────────────────────────

    #[test]
    fn set_source_video_rect_full_layout_and_function_id() {
        let pdu = SetSourceVideoRect {
            message_id: 0,
            presentation_id: G,
            left: 0.0,
            top: 0.25,
            right: 1.0,
            bottom: 0.75,
        };
        let bytes = encode_to_vec(&pdu);
        // 12 hdr + 16 guid + 16 floats = 44
        assert_eq!(bytes.len(), 44);
        assert_eq!(bytes.len(), SetSourceVideoRect::WIRE_SIZE);
        // FunctionId = SET_SOURCE_VIDEO_RECT (0x116, NOT 0x115 -- spec doc bug)
        assert_eq!(&bytes[8..12], &[0x16, 0x01, 0x00, 0x00]);

        let mut r = ReadCursor::new(&bytes);
        let decoded = SetSourceVideoRect::decode(&mut r).unwrap();
        assert_eq!(decoded.left, 0.0);
        assert_eq!(decoded.top, 0.25);
        assert_eq!(decoded.right, 1.0);
        assert_eq!(decoded.bottom, 0.75);
    }

    #[test]
    fn set_source_video_rect_uses_0x116_not_remove_stream_0x115() {
        // Catch the spec doc bug regression: REMOVE_STREAM is 0x115,
        // SET_SOURCE_VIDEO_RECT is 0x116. The encoder must use 0x116.
        use crate::constants::function_id;
        assert_eq!(function_id::SET_SOURCE_VIDEO_RECT, 0x116);
        assert_eq!(function_id::REMOVE_STREAM, 0x115);
        assert_ne!(
            function_id::SET_SOURCE_VIDEO_RECT,
            function_id::REMOVE_STREAM
        );
    }

    #[test]
    fn set_source_video_rect_rejects_remove_stream_function_id() {
        // Same payload but FunctionId = 0x115 -- decoder must reject.
        let mut bytes: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x40, // PROXY
            0x00, 0x00, 0x00, 0x00, // MessageId
            0x15, 0x01, 0x00, 0x00, // FunctionId = REMOVE_STREAM (wrong)
        ];
        bytes.extend_from_slice(G.as_bytes());
        bytes.extend_from_slice(&[0u8; 16]); // 4 floats
        let mut r = ReadCursor::new(&bytes);
        assert!(SetSourceVideoRect::decode(&mut r).is_err());
    }
}
