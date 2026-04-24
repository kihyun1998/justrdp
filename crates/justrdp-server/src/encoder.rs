#![forbid(unsafe_code)]

//! Server-side fast-path output encoders.
//!
//! Encoders here build complete fast-path PDU byte streams (TPKT-less,
//! the fast-path framing is its own envelope) ready to flush to the wire.
//! Each helper returns `Vec<Vec<u8>>` -- one buffer per PDU -- because a
//! large bitmap update may need to be split across multiple fast-path
//! PDUs to honour the 15-bit length field cap (MS-RDPBCGR §2.2.9.1.2).

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Encode, WriteCursor};
use justrdp_pdu::mcs::{
    DisconnectProviderUltimatum, DisconnectReason, SendDataIndication,
};
use justrdp_pdu::rdp::bitmap::{TsBitmapData, TsUpdateBitmapData};
use justrdp_pdu::rdp::error_info::ErrorInfoCode;
use justrdp_pdu::rdp::fast_path::{
    FastPathOutputHeader, FastPathOutputUpdate, FastPathUpdateType, Fragmentation,
    FASTPATH_OUTPUT_ACTION_FASTPATH,
};
use justrdp_pdu::rdp::finalization::{DeactivateAllPdu, SetErrorInfoPdu};
use justrdp_pdu::rdp::headers::{
    ShareControlHeader, ShareControlPduType, ShareDataHeader, ShareDataPduType,
    SHARE_CONTROL_HEADER_SIZE, SHARE_DATA_HEADER_SIZE,
};
use justrdp_pdu::rdp::redirection::ServerRedirectionPdu;
use justrdp_pdu::rdp::pointer::{
    TsCachedPointerAttribute, TsColorPointerAttribute, TsPoint16, TsPointerAttribute,
    and_mask_row_stride, validate_color_pointer_dimensions, xor_mask_row_stride,
};
use justrdp_pdu::rdp::surface_commands::{
    BitmapDataEx, FrameMarkerCmd, SetSurfaceBitsCmd,
};
use justrdp_pdu::rdp::svc::{
    ChannelPduHeader, CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST, CHANNEL_PDU_HEADER_SIZE,
};
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

use crate::active::ServerActiveStage;
use crate::config::RdpServerConfig;
use crate::error::{ServerError, ServerResult};
use crate::handler::{
    BitmapUpdate, DisplayUpdate, PointerColorUpdate, PointerNewUpdate, SurfaceBitsUpdate,
};

/// Stream priority on outbound `ShareDataHeader.streamId`.
/// `STREAM_LOW = 1` matches what acceptor finalization emits.
const STREAM_LOW: u8 = 1;

// ── Server-direction framing (slow-path + SVC + disconnect) ──
//
// These methods are conceptually outbound encoders -- they share the
// same TPKT + X.224 DT + MCS SDI envelope as the bitmap / pointer
// fast-path encoders defined below -- and live here rather than in
// active.rs to keep that file focused on the inbound dispatch loop.

impl ServerActiveStage {
    /// Wrap an inner ShareData body in ShareData + ShareControl + MCS
    /// SDI + X.224 DT + TPKT and return the wire bytes (single PDU).
    ///
    /// `pub(crate)` because both the inbound dispatch path
    /// (`handle_shutdown_request`, `handle_control`) and the disconnect
    /// encoder below share this helper. External callers should use
    /// the higher-level wrappers (`encode_disconnect`, etc.).
    pub(crate) fn encode_share_data<E: Encode>(
        &self,
        pdu_type2: ShareDataPduType,
        inner: &E,
    ) -> ServerResult<Vec<u8>> {
        let inner_size = inner.size();
        if inner_size > u16::MAX as usize {
            return Err(ServerError::protocol(
                "ShareData inner body exceeds u16 uncompressedLength",
            ));
        }
        let sd_total = SHARE_DATA_HEADER_SIZE + inner_size;
        let sc_total = SHARE_CONTROL_HEADER_SIZE + sd_total;
        if sc_total > u16::MAX as usize {
            return Err(ServerError::protocol(
                "ShareControl payload exceeds u16 totalLength",
            ));
        }

        let mut sc_payload = vec![0u8; sc_total];
        {
            let mut cursor = WriteCursor::new(&mut sc_payload);
            ShareControlHeader {
                total_length: sc_total as u16,
                pdu_type: ShareControlPduType::Data,
                pdu_source: self.user_channel_id(),
            }
            .encode(&mut cursor)?;
            ShareDataHeader {
                share_id: self.share_id(),
                stream_id: STREAM_LOW,
                // MS-RDPBCGR §2.2.8.1.1.1.2: uncompressedLength excludes
                // the ShareDataHeader itself -- matches the acceptor's
                // finalization-side convention.
                uncompressed_length: inner_size as u16,
                pdu_type2,
                compressed_type: 0,
                compressed_length: 0,
            }
            .encode(&mut cursor)?;
            inner.encode(&mut cursor)?;
        }

        let sdi = SendDataIndication {
            initiator: self.user_channel_id(),
            channel_id: self.io_channel_id(),
            user_data: &sc_payload,
        };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut cursor = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size)?.encode(&mut cursor)?;
            DataTransfer.encode(&mut cursor)?;
            sdi.encode(&mut cursor)?;
        }
        Ok(buf)
    }

    /// Encode an outbound SVC payload as one or more wire-ready frames
    /// (TPKT + X.224 DT + MCS SDI + ChannelPduHeader + chunk).
    ///
    /// Splits `payload` into chunks of at most
    /// `config.channel_chunk_length` bytes per
    /// [`MAX_CHANNEL_CHUNK_LENGTH`] (MS-RDPBCGR §2.2.7.1.10). The
    /// `ChannelPduHeader.length` field carries the **total uncompressed
    /// message length** in every chunk; `flags` carries
    /// `CHANNEL_FLAG_FIRST` on the first chunk, `CHANNEL_FLAG_LAST` on
    /// the last, both on a single-chunk message.
    ///
    /// `channel_id` MUST be a negotiated SVC channel; otherwise the
    /// helper returns `ServerError::protocol(_)`.
    ///
    /// [`MAX_CHANNEL_CHUNK_LENGTH`]: crate::MAX_CHANNEL_CHUNK_LENGTH
    pub fn encode_svc_send(
        &self,
        channel_id: u16,
        payload: &[u8],
    ) -> ServerResult<Vec<Vec<u8>>> {
        if !self.channel_ids().iter().any(|(_, id)| *id == channel_id) {
            return Err(ServerError::protocol(
                "encode_svc_send target channel is not in the negotiated VC list",
            ));
        }
        let total = payload.len();
        if total > u32::MAX as usize {
            return Err(ServerError::protocol(
                "SVC payload exceeds u32 ChannelPduHeader.length",
            ));
        }
        let chunk_size = self.config().channel_chunk_length;

        if total == 0 {
            // Empty messages still need to declare presence with a
            // FIRST|LAST chunk carrying zero data bytes.
            return Ok(alloc::vec![self.frame_one_svc_chunk(
                channel_id,
                CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST,
                0,
                &[],
            )?]);
        }

        let mut frames = Vec::with_capacity(total.div_ceil(chunk_size));
        let mut offset = 0usize;
        while offset < total {
            let end = (offset + chunk_size).min(total);
            let mut flags = 0u32;
            if offset == 0 {
                flags |= CHANNEL_FLAG_FIRST;
            }
            if end == total {
                flags |= CHANNEL_FLAG_LAST;
            }
            frames.push(self.frame_one_svc_chunk(
                channel_id,
                flags,
                total as u32,
                &payload[offset..end],
            )?);
            offset = end;
        }
        Ok(frames)
    }

    fn frame_one_svc_chunk(
        &self,
        channel_id: u16,
        flags: u32,
        total_length: u32,
        chunk: &[u8],
    ) -> ServerResult<Vec<u8>> {
        let header = ChannelPduHeader {
            length: total_length,
            flags,
        };
        let body_size = CHANNEL_PDU_HEADER_SIZE + chunk.len();
        let mut body = vec![0u8; body_size];
        {
            let mut c = WriteCursor::new(&mut body);
            header.encode(&mut c)?;
            c.write_slice(chunk, "svc::chunkData")?;
        }
        let sdi = SendDataIndication {
            initiator: self.user_channel_id(),
            channel_id,
            user_data: &body,
        };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size)?.encode(&mut c)?;
            DataTransfer.encode(&mut c)?;
            sdi.encode(&mut c)?;
        }
        Ok(buf)
    }

    /// Encode a clean-disconnect sequence: `SetErrorInfoPdu` (wrapped
    /// in ShareData on the I/O channel) followed by a top-level MCS
    /// `DisconnectProviderUltimatum` (TPKT + X.224 DT + 2-byte PER).
    ///
    /// Returns the two frames in order. The caller MUST flush both
    /// before closing the underlying transport so the client can
    /// surface a coherent disconnect reason rather than seeing only a
    /// half-open TCP close.
    ///
    /// The MCS reason is fixed at `UserRequested` (3) for the
    /// server-initiated path; the actual cause of the disconnect is
    /// carried by the preceding `SetErrorInfoPdu`'s
    /// [`ErrorInfoCode`].
    pub fn encode_disconnect(&self, code: ErrorInfoCode) -> ServerResult<Vec<Vec<u8>>> {
        let info = SetErrorInfoPdu::new(code);
        let info_frame = self.encode_share_data(ShareDataPduType::SetErrorInfo, &info)?;
        let ult_frame = self.encode_disconnect_ultimatum(DisconnectReason::UserRequested)?;
        Ok(alloc::vec![info_frame, ult_frame])
    }

    /// Encode a `DeactivateAllPdu` (MS-RDPBCGR §2.2.3.1) wrapped in
    /// ShareControl + MCS SDI + X.224 DT + TPKT.
    ///
    /// `DeactivateAllPdu` is itself a ShareControl PDU
    /// (`pdu_type = DeactivateAllPdu` = `0x0006`) -- it does NOT live
    /// inside a `ShareData` envelope, which is why the existing
    /// [`encode_share_data`](Self::encode_share_data) helper cannot be
    /// reused here.
    ///
    /// The body carries the current `share_id` (so the client knows
    /// which share is being torn down) and a zero-length
    /// `sourceDescriptor` field (we do not advertise a server name to
    /// the client mid-session).
    pub(crate) fn encode_deactivate_all(&self) -> ServerResult<Vec<u8>> {
        let body = DeactivateAllPdu {
            share_id: self.share_id(),
            length_source_descriptor: 0,
        };
        let body_size = body.size();
        let sc_total = SHARE_CONTROL_HEADER_SIZE + body_size;
        if sc_total > u16::MAX as usize {
            return Err(ServerError::protocol(
                "ShareControl payload exceeds u16 totalLength",
            ));
        }

        let mut sc_payload = vec![0u8; sc_total];
        {
            let mut cursor = WriteCursor::new(&mut sc_payload);
            ShareControlHeader {
                total_length: sc_total as u16,
                pdu_type: ShareControlPduType::DeactivateAllPdu,
                pdu_source: self.user_channel_id(),
            }
            .encode(&mut cursor)?;
            body.encode(&mut cursor)?;
        }

        let sdi = SendDataIndication {
            initiator: self.user_channel_id(),
            channel_id: self.io_channel_id(),
            user_data: &sc_payload,
        };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut cursor = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size)?.encode(&mut cursor)?;
            DataTransfer.encode(&mut cursor)?;
            sdi.encode(&mut cursor)?;
        }
        Ok(buf)
    }

    /// Encode a stand-alone `DisconnectProviderUltimatum` frame
    /// (TPKT + X.224 DT + 2-byte PER body). Use this when no
    /// `SetErrorInfoPdu` is needed (e.g. fatal protocol error mid-handshake).
    pub fn encode_disconnect_ultimatum(
        &self,
        reason: DisconnectReason,
    ) -> ServerResult<Vec<u8>> {
        let ult = DisconnectProviderUltimatum { reason };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + ult.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size)?.encode(&mut c)?;
            DataTransfer.encode(&mut c)?;
            ult.encode(&mut c)?;
        }
        Ok(buf)
    }

    /// Encode a Server Redirection PDU (MS-RDPBCGR §2.2.13.3.1
    /// Enhanced Security form) ready to flush to the client.
    ///
    /// Wire layout:
    ///
    /// ```text
    /// TPKT + X.224 DT + MCS SDI on io_channel_id + [
    ///   ShareControlHeader (totalLength, pduType=0x000A RAW, pduSource),
    ///   pad2Octets (u16 = 0x0000),
    ///   RDP_SERVER_REDIRECTION_PACKET,
    /// ]
    /// ```
    ///
    /// The `pduType` field is written as `0x000A` (the raw
    /// `ShareControlPduType::ServerRedirect` discriminant) -- NOT
    /// `ShareControlPduType::to_u16()` which would OR in the `0x0010`
    /// PDUVersion bit. Per MS-RDPBCGR §2.2.13.3.1 "the PDUVersion
    /// subfield MUST be set to zero" for Server Redirection PDUs, and
    /// both Appendix A test vectors confirm `0x0A 0x00` on the wire.
    ///
    /// The Standard Security form (MS-RDPBCGR §2.2.13.2.1), which
    /// prefixes the body with a Non-FIPS security header and
    /// RC4-encrypts the payload, is NOT emitted here. That path
    /// requires the key-derivation work tracked under §11.2a-stdsec
    /// (Appendix G.2). In the meantime the Enhanced Security wire
    /// form above is what the existing `ClientConnector` decoder
    /// expects in its finalization loop, so this helper is sufficient
    /// for end-to-end loopback testing against that client.
    pub(crate) fn encode_redirection(
        &self,
        pdu: &ServerRedirectionPdu,
    ) -> ServerResult<Vec<u8>> {
        let body_size = pdu.size();
        // ShareControl header (6) + pad2Octets (2) + redirection body.
        let sc_total = SHARE_CONTROL_HEADER_SIZE
            .checked_add(2)
            .and_then(|n| n.checked_add(body_size))
            .ok_or_else(|| ServerError::protocol(
                "ServerRedirection payload size overflow",
            ))?;
        if sc_total > u16::MAX as usize {
            return Err(ServerError::protocol(
                "ServerRedirection ShareControl totalLength exceeds u16",
            ));
        }

        let mut sc_payload = vec![0u8; sc_total];
        {
            let mut c = WriteCursor::new(&mut sc_payload);
            // ShareControlHeader is emitted manually because
            // `ShareControlHeader::encode` goes through
            // `ShareControlPduType::to_u16()` which always sets bit
            // `0x0010` -- wrong for this PDU (spec mandates PDUVersion = 0).
            c.write_u16_le(sc_total as u16, "ShareControlHeader::totalLength")?;
            c.write_u16_le(
                ShareControlPduType::ServerRedirect as u16,
                "ShareControlHeader::pduType",
            )?;
            c.write_u16_le(
                self.user_channel_id(),
                "ShareControlHeader::pduSource",
            )?;
            // pad2Octets -- 2 bytes of alignment padding, receiver ignores.
            c.write_u16_le(0, "ServerRedirection::pad2Octets")?;
            pdu.encode(&mut c)?;
        }

        let sdi = SendDataIndication {
            initiator: self.user_channel_id(),
            channel_id: self.io_channel_id(),
            user_data: &sc_payload,
        };
        let payload_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let total = TPKT_HEADER_SIZE + payload_size;
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            TpktHeader::try_for_payload(payload_size)?.encode(&mut c)?;
            DataTransfer.encode(&mut c)?;
            sdi.encode(&mut c)?;
        }
        Ok(buf)
    }
}

/// Maximum total size of a single fast-path PDU. Set by the 15-bit
/// length field defined in MS-RDPBCGR §2.2.9.1.2 (`encode_length` in
/// `justrdp-pdu/src/rdp/fast_path.rs` chooses 1- or 2-byte form for
/// values up to `0x7FFF`).
pub const MAX_FAST_PATH_PDU_LENGTH: usize = 0x7FFF;

/// Encode a single uncompressed bitmap update as one or more fast-path
/// PDU frames.
///
/// The encoder always builds a single `TS_UPDATE_BITMAP_DATA` (with one
/// `TS_BITMAP_DATA` rectangle) from `update`, then either emits it in
/// one fast-path PDU (when the inner payload is small enough) or splits
/// the byte stream across multiple `FastPathOutputUpdate` fragments
/// using the `Fragmentation::First`/`Next`/`Last` markers per
/// MS-RDPBCGR §2.2.9.1.2.1.
///
/// The fragment-size threshold comes from `config.max_bitmap_fragment_size`,
/// which is bounded by `MAX_BITMAP_FRAGMENT_SIZE_LIMIT` so that any
/// chosen value can fit inside a fast-path PDU together with the outer
/// headers.
///
/// **Caller contract on `update.data`:** rows in bottom-to-top order,
/// each row padded to a 4-byte boundary per MS-RDPBCGR §2.2.9.1.1.3.1.2.1
/// (use `justrdp_pdu::rdp::bitmap::uncompressed_row_stride` to size the
/// buffer correctly).
pub fn encode_bitmap_update(
    config: &RdpServerConfig,
    update: &BitmapUpdate,
) -> ServerResult<Vec<Vec<u8>>> {
    let row_stride = ((usize::from(update.width) * usize::from(update.bits_per_pixel) + 7) / 8 + 3)
        & !3;
    let expected_data_len = row_stride
        .checked_mul(usize::from(update.height))
        .ok_or_else(|| ServerError::protocol("bitmap dimensions overflow usize"))?;
    if update.data.len() != expected_data_len {
        return Err(ServerError::protocol(
            "BitmapUpdate.data length does not match width*height*bpp/8 \
             padded to a 4-byte boundary",
        ));
    }
    if update.bits_per_pixel != 8
        && update.bits_per_pixel != 15
        && update.bits_per_pixel != 16
        && update.bits_per_pixel != 24
        && update.bits_per_pixel != 32
    {
        return Err(ServerError::protocol(
            "BitmapUpdate.bits_per_pixel must be one of 8/15/16/24/32",
        ));
    }
    if update.width == 0 || update.height == 0 {
        return Err(ServerError::protocol(
            "BitmapUpdate width/height must be non-zero",
        ));
    }

    let dest_right = update
        .dest_left
        .checked_add(update.width.saturating_sub(1))
        .ok_or_else(|| ServerError::protocol("BitmapUpdate destLeft+width overflows u16"))?;
    let dest_bottom = update
        .dest_top
        .checked_add(update.height.saturating_sub(1))
        .ok_or_else(|| ServerError::protocol("BitmapUpdate destTop+height overflows u16"))?;

    let rect = TsBitmapData {
        dest_left: update.dest_left,
        dest_top: update.dest_top,
        dest_right,
        dest_bottom,
        width: update.width,
        height: update.height,
        bits_per_pixel: update.bits_per_pixel,
        flags: 0, // uncompressed
        compr_hdr: None,
        bitmap_data: update.data.clone(),
    };
    if rect.bitmap_length() > u16::MAX as usize {
        return Err(ServerError::protocol(
            "single bitmap rectangle exceeds u16 bitmapLength cap",
        ));
    }

    let upd = TsUpdateBitmapData { rectangles: vec![rect] };

    // Serialise the inner fast-path payload (numberRectangles +
    // TS_BITMAP_DATA[]) once, then chunk if it does not fit in one
    // fast-path PDU. The outer FastPathOutputUpdate adds 3 bytes
    // (updateHeader + size:u16) per fragment, and the FastPathOutputHeader
    // adds 1-3 bytes; both subtracted from the 15-bit cap to find the
    // safe per-fragment payload size.
    let mut inner_payload = vec![0u8; upd.fast_path_size()];
    {
        let mut c = WriteCursor::new(&mut inner_payload);
        upd.encode_fast_path(&mut c)?;
    }

    chunk_into_fast_path_frames(
        FastPathUpdateType::Bitmap,
        &inner_payload,
        config.max_bitmap_fragment_size,
    )
}

/// Split `payload` into a sequence of fast-path PDU frames carrying the
/// given `update_code`. Sets `Fragmentation` to `Single` (one PDU),
/// `First`/`Next`/`Last` (multiple), per MS-RDPBCGR §2.2.9.1.2.1.
///
/// Each chunk is at most `chunk_limit` bytes of inner payload, which
/// MUST fit (together with the per-PDU 6-byte overhead) inside a
/// fast-path PDU bounded by [`MAX_FAST_PATH_PDU_LENGTH`].
fn chunk_into_fast_path_frames(
    update_code: FastPathUpdateType,
    payload: &[u8],
    chunk_limit: usize,
) -> ServerResult<Vec<Vec<u8>>> {
    if chunk_limit == 0 {
        return Err(ServerError::protocol(
            "fast-path chunk limit must be non-zero",
        ));
    }
    // Per-PDU overhead: 1 (updateHeader) + 2 (size LE u16) + 3 (worst-case
    // 1 + 2-byte length encoding). 32_767 - 6 = 32_761 hard ceiling.
    if chunk_limit > MAX_FAST_PATH_PDU_LENGTH - 6 {
        return Err(ServerError::protocol(
            "fast-path chunk limit exceeds 15-bit length field minus header overhead",
        ));
    }

    if payload.is_empty() {
        return Ok(Vec::new());
    }

    let total = payload.len();
    let mut frames = Vec::with_capacity(total.div_ceil(chunk_limit));
    let mut offset = 0;
    let single = total <= chunk_limit;
    while offset < total {
        let end = (offset + chunk_limit).min(total);
        let chunk = &payload[offset..end];
        let fragmentation = if single {
            Fragmentation::Single
        } else if offset == 0 {
            Fragmentation::First
        } else if end == total {
            Fragmentation::Last
        } else {
            Fragmentation::Next
        };
        frames.push(encode_one_fast_path_pdu(update_code, fragmentation, chunk)?);
        offset = end;
    }
    Ok(frames)
}

/// Encode a surface-bits update as one or more fast-path
/// `SurfaceCommands` PDU frames.
///
/// Builds a single `TS_SURFCMD_SET_SURF_BITS` (MS-RDPBCGR §2.2.9.2.1)
/// from `update`, wraps it in a `TS_BITMAP_DATA_EX` (§2.2.9.2.1.1) and
/// emits the bytes through `chunk_into_fast_path_frames` so that
/// payloads exceeding `config.max_bitmap_fragment_size` are split with
/// `Fragmentation::First`/`Next`/`Last` per §2.2.9.1.2.1.
///
/// `width`/`height` from `SurfaceBitsUpdate` are authoritative; the
/// wire `destRight` / `destBottom` are written as `dest_left + width`
/// / `dest_top + height` (exclusive bounds per spec Remarks).
pub fn encode_surface_bits_update(
    config: &RdpServerConfig,
    update: &SurfaceBitsUpdate,
) -> ServerResult<Vec<Vec<u8>>> {
    if update.width == 0 || update.height == 0 {
        return Err(ServerError::protocol(
            "SurfaceBitsUpdate width/height must be non-zero",
        ));
    }
    if update.bitmap_data.len() > u32::MAX as usize {
        return Err(ServerError::protocol(
            "SurfaceBitsUpdate.bitmap_data length exceeds u32::MAX",
        ));
    }

    let dest_right = update
        .dest_left
        .checked_add(update.width)
        .ok_or_else(|| {
            ServerError::protocol("SurfaceBitsUpdate destLeft+width overflows u16")
        })?;
    let dest_bottom = update
        .dest_top
        .checked_add(update.height)
        .ok_or_else(|| {
            ServerError::protocol("SurfaceBitsUpdate destTop+height overflows u16")
        })?;

    let cmd = SetSurfaceBitsCmd {
        dest_left: update.dest_left,
        dest_top: update.dest_top,
        dest_right,
        dest_bottom,
        bitmap_data: BitmapDataEx {
            bpp: update.bpp,
            codec_id: update.codec_id,
            width: update.width,
            height: update.height,
            ex_header: update.ex_header,
            bitmap_data: update.bitmap_data.clone(),
        },
    };

    // Serialise the single TS_SURFCMD into the inner SURFCMDS payload
    // bytes. The fast-path container is just a raw concatenation of
    // TS_SURFCMD structures with no count prefix
    // (MS-RDPBCGR §2.2.9.1.2.1.10).
    let mut inner_payload = vec![0u8; cmd.size()];
    {
        let mut c = WriteCursor::new(&mut inner_payload);
        cmd.encode(&mut c)?;
    }

    chunk_into_fast_path_frames(
        FastPathUpdateType::SurfaceCommands,
        &inner_payload,
        config.max_bitmap_fragment_size,
    )
}

/// Encode a single `TS_FRAME_MARKER` (MS-RDPBCGR §2.2.9.2.3) wrapped
/// in a fast-path `SurfaceCommands` update PDU.
///
/// `begin == true` emits `SURFACECMD_FRAMEACTION_BEGIN`, `false` emits
/// `_END`. The payload is always 8 bytes (`cmdType + frameAction +
/// frameId`) plus the 3-byte fast-path overhead, so the result is
/// always a single un-fragmented PDU regardless of `frame_id` value.
pub fn encode_frame_marker(begin: bool, frame_id: u32) -> ServerResult<Vec<u8>> {
    let cmd = if begin {
        FrameMarkerCmd::begin(frame_id)
    } else {
        FrameMarkerCmd::end(frame_id)
    };
    let mut inner_payload = vec![0u8; cmd.size()];
    {
        let mut c = WriteCursor::new(&mut inner_payload);
        cmd.encode(&mut c)?;
    }
    encode_one_fast_path_pdu(
        FastPathUpdateType::SurfaceCommands,
        Fragmentation::Single,
        &inner_payload,
    )
}

/// Encode a fast-path pointer update (any of the
/// `Position`/`Hidden`/`Default`/`Color`/`New`/`Cached` variants of
/// [`DisplayUpdate`]) into a single fast-path PDU.
///
/// Pointer updates always fit comfortably inside a single fast-path
/// PDU -- the largest payload is a 96x96 [`PointerNewUpdate`] at 32 bpp
/// (~37 KiB) which still sits well below the 15-bit length cap. The
/// encoder therefore emits only `Fragmentation::Single` frames.
///
/// Non-pointer variants (`Bitmap`, `Palette`, `Reset`, `SurfaceBits`,
/// `FrameMarker`) MUST be routed to their own encoders; this function
/// returns `ServerError::protocol(...)` for them.
pub fn encode_pointer_update(update: &DisplayUpdate) -> ServerResult<Vec<u8>> {
    match update {
        DisplayUpdate::PointerPosition(p) => {
            encode_pointer_position(p)
        }
        DisplayUpdate::PointerHidden => encode_pointer_empty(FastPathUpdateType::PointerHidden),
        DisplayUpdate::PointerDefault => encode_pointer_empty(FastPathUpdateType::PointerDefault),
        DisplayUpdate::PointerCached { cache_index } => {
            encode_pointer_cached(*cache_index)
        }
        DisplayUpdate::PointerColor(c) => encode_pointer_color(c),
        DisplayUpdate::PointerNew(n) => encode_pointer_new(n),
        DisplayUpdate::Bitmap(_)
        | DisplayUpdate::Palette(_)
        | DisplayUpdate::Reset { .. }
        | DisplayUpdate::SurfaceBits(_)
        | DisplayUpdate::FrameMarker { .. } => Err(ServerError::protocol(
            "encode_pointer_update called on a non-pointer DisplayUpdate variant",
        )),
    }
}

/// Encode a [`FASTPATH_UPDATETYPE_PTR_POSITION`] PDU
/// (MS-RDPBCGR §2.2.9.1.2.1.5). Payload is a 4-byte `TS_POINT16`.
pub fn encode_pointer_position(p: &TsPoint16) -> ServerResult<Vec<u8>> {
    let mut payload = vec![0u8; p.size()];
    {
        let mut c = WriteCursor::new(&mut payload);
        p.encode(&mut c)?;
    }
    encode_one_fast_path_pdu(FastPathUpdateType::PointerPosition, Fragmentation::Single, &payload)
}

/// Encode either [`FASTPATH_UPDATETYPE_PTR_NULL`] (MS-RDPBCGR
/// §2.2.9.1.2.1.6) or [`FASTPATH_UPDATETYPE_PTR_DEFAULT`] (§2.2.9.1.2.1.7).
/// Both have an empty payload.
fn encode_pointer_empty(code: FastPathUpdateType) -> ServerResult<Vec<u8>> {
    debug_assert!(matches!(
        code,
        FastPathUpdateType::PointerHidden | FastPathUpdateType::PointerDefault
    ));
    encode_one_fast_path_pdu(code, Fragmentation::Single, &[])
}

/// Encode a [`FASTPATH_UPDATETYPE_PTR_CACHED`] PDU
/// (MS-RDPBCGR §2.2.9.1.2.1.11). Payload is a 2-byte `cacheIndex`.
pub fn encode_pointer_cached(cache_index: u16) -> ServerResult<Vec<u8>> {
    let attr = TsCachedPointerAttribute { cache_index };
    let mut payload = vec![0u8; attr.size()];
    {
        let mut c = WriteCursor::new(&mut payload);
        attr.encode(&mut c)?;
    }
    encode_one_fast_path_pdu(FastPathUpdateType::PointerCached, Fragmentation::Single, &payload)
}

/// Validate that XOR / AND mask buffers have the exact byte count
/// implied by `width × height` and the per-bpp stride formulas from
/// MS-RDPBCGR §2.2.9.1.1.4.4 / §2.2.9.1.1.4.5. Used by both color and
/// new-style pointer encoders so a single source of truth handles the
/// stride padding rules. Returns a [`ServerError::protocol`] whose
/// message includes the actual vs expected byte counts to make
/// debugging mismatched masks straightforward.
fn validate_pointer_mask_lengths(
    ctx: &'static str,
    width: u16,
    height: u16,
    xor_bpp: u16,
    xor_mask_data: &[u8],
    and_mask_data: &[u8],
) -> ServerResult<()> {
    let expected_xor = xor_mask_row_stride(width, xor_bpp) * usize::from(height);
    let expected_and = and_mask_row_stride(width) * usize::from(height);
    if xor_mask_data.len() != expected_xor {
        return Err(ServerError::protocol_owned(alloc::format!(
            "{ctx}: xor_mask_data length {got} does not match \
             width * xor_bpp / 8 padded to 2-byte boundary * height \
             (expected {expected_xor})",
            got = xor_mask_data.len(),
        )));
    }
    if and_mask_data.len() != expected_and {
        return Err(ServerError::protocol_owned(alloc::format!(
            "{ctx}: and_mask_data length {got} does not match \
             ceil(width / 8) padded to 2-byte boundary * height \
             (expected {expected_and})",
            got = and_mask_data.len(),
        )));
    }
    Ok(())
}

/// Encode a [`FASTPATH_UPDATETYPE_PTR_COLOR`] PDU
/// (MS-RDPBCGR §2.2.9.1.2.1.9). Validates the 32x32 limit and the
/// 2-byte AND/XOR mask scan-line padding from §2.2.9.1.1.4.4.
pub fn encode_pointer_color(c: &PointerColorUpdate) -> ServerResult<Vec<u8>> {
    validate_color_pointer_dimensions(c.width, c.height).map_err(ServerError::from)?;
    validate_pointer_mask_lengths(
        "PointerColorUpdate",
        c.width,
        c.height,
        24,
        &c.xor_mask_data,
        &c.and_mask_data,
    )?;
    let attr = TsColorPointerAttribute {
        cache_index: c.cache_index,
        hot_spot: c.hot_spot,
        width: c.width,
        height: c.height,
        xor_mask_data: c.xor_mask_data.clone(),
        and_mask_data: c.and_mask_data.clone(),
    };
    let mut payload = vec![0u8; attr.size()];
    {
        let mut cur = WriteCursor::new(&mut payload);
        attr.encode(&mut cur)?;
    }
    encode_one_fast_path_pdu(FastPathUpdateType::PointerColor, Fragmentation::Single, &payload)
}

/// Encode a [`FASTPATH_UPDATETYPE_PTR_NEW`] PDU
/// (MS-RDPBCGR §2.2.9.1.2.1.10). Validates `xor_bpp ∈ {1,4,8,16,24,32}`
/// and the per-bpp 2-byte XOR / AND mask scan-line padding.
pub fn encode_pointer_new(p: &PointerNewUpdate) -> ServerResult<Vec<u8>> {
    if !matches!(p.xor_bpp, 1 | 4 | 8 | 16 | 24 | 32) {
        return Err(ServerError::protocol(
            "PointerNewUpdate.xor_bpp must be one of 1/4/8/16/24/32",
        ));
    }
    validate_pointer_mask_lengths(
        "PointerNewUpdate",
        p.width,
        p.height,
        p.xor_bpp,
        &p.xor_mask_data,
        &p.and_mask_data,
    )?;
    let attr = TsPointerAttribute {
        xor_bpp: p.xor_bpp,
        color_ptr_attr: TsColorPointerAttribute {
            cache_index: p.cache_index,
            hot_spot: p.hot_spot,
            width: p.width,
            height: p.height,
            xor_mask_data: p.xor_mask_data.clone(),
            and_mask_data: p.and_mask_data.clone(),
        },
    };
    let mut payload = vec![0u8; attr.size()];
    {
        let mut cur = WriteCursor::new(&mut payload);
        attr.encode(&mut cur)?;
    }
    encode_one_fast_path_pdu(FastPathUpdateType::PointerNew, Fragmentation::Single, &payload)
}

/// Build a single fast-path PDU containing one `FastPathOutputUpdate`.
fn encode_one_fast_path_pdu(
    update_code: FastPathUpdateType,
    fragmentation: Fragmentation,
    chunk: &[u8],
) -> ServerResult<Vec<u8>> {
    let update = FastPathOutputUpdate {
        update_code,
        fragmentation,
        compression: 0,
        compression_flags: None,
        update_data: chunk.to_vec(),
    };
    let body_size = update.size();
    // Compute total length the outer header will report. The header
    // length field is itself sized differently for short/long form, so
    // we have to iterate once: assume long form (3 bytes), build, and
    // shrink if the value fits in the short form (1 byte).
    let provisional_len = body_size + 3;
    if provisional_len > MAX_FAST_PATH_PDU_LENGTH {
        return Err(ServerError::protocol(
            "single fast-path PDU exceeds 15-bit length field",
        ));
    }
    let length = if provisional_len <= 0x7F {
        // Short form is in play; recompute precisely.
        body_size + 2
    } else {
        provisional_len
    };
    let header = FastPathOutputHeader {
        action: FASTPATH_OUTPUT_ACTION_FASTPATH,
        flags: 0,
        length: length as u16,
    };
    let mut buf = vec![0u8; header.size() + body_size];
    {
        let mut c = WriteCursor::new(&mut buf);
        header.encode(&mut c)?;
        update.encode(&mut c)?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_core::{Decode, ReadCursor};
    use justrdp_pdu::rdp::bitmap::uncompressed_row_stride;

    fn config(max_fragment: usize) -> RdpServerConfig {
        RdpServerConfig::builder()
            .max_bitmap_fragment_size(max_fragment)
            .build()
            .unwrap()
    }

    fn build_update(width: u16, height: u16, bpp: u16) -> BitmapUpdate {
        let stride = uncompressed_row_stride(width, bpp);
        BitmapUpdate {
            dest_left: 10,
            dest_top: 20,
            width,
            height,
            bits_per_pixel: bpp,
            data: vec![0xCD; stride * usize::from(height)],
        }
    }

    /// Decode a list of fast-path frames back to the underlying
    /// `TsUpdateBitmapData` for assertions.
    fn reassemble(frames: &[Vec<u8>]) -> TsUpdateBitmapData {
        let mut payload = Vec::new();
        for frame in frames {
            let mut c = ReadCursor::new(frame);
            let _hdr = FastPathOutputHeader::decode(&mut c).unwrap();
            let upd = FastPathOutputUpdate::decode(&mut c).unwrap();
            assert_eq!(upd.update_code, FastPathUpdateType::Bitmap);
            payload.extend_from_slice(&upd.update_data);
        }
        let mut c = ReadCursor::new(&payload);
        TsUpdateBitmapData::decode_fast_path(&mut c).unwrap()
    }

    #[test]
    fn small_bitmap_emits_single_frame() {
        let cfg = config(16_364);
        let upd = build_update(8, 8, 32);
        let frames = encode_bitmap_update(&cfg, &upd).unwrap();
        assert_eq!(frames.len(), 1);
        let decoded = reassemble(&frames);
        assert_eq!(decoded.rectangles.len(), 1);
        let r = &decoded.rectangles[0];
        assert_eq!(r.dest_left, 10);
        assert_eq!(r.dest_top, 20);
        assert_eq!(r.dest_right, 10 + 7); // inclusive
        assert_eq!(r.dest_bottom, 20 + 7);
        assert_eq!(r.width, 8);
        assert_eq!(r.height, 8);
        assert_eq!(r.bits_per_pixel, 32);
        assert_eq!(r.flags, 0);
        assert_eq!(r.bitmap_data.len(), 8 * 8 * 4);
    }

    #[test]
    fn large_bitmap_fragments_across_frames() {
        // 128 x 32 x 32bpp = 16_384 bytes pixel data (fits in u16 bitmapLength)
        // + 18 bytes TS_BITMAP_DATA prefix + 2 bytes numberRectangles
        // = 16_404 bytes inner payload. With a 4_096-byte chunk limit
        // it MUST split into 5 frames (4_096 + 4_096 + 4_096 + 4_096 + 20).
        let cfg = config(4_096);
        let upd = build_update(128, 32, 32);
        let frames = encode_bitmap_update(&cfg, &upd).unwrap();
        assert!(
            frames.len() > 1,
            "expected fragmentation, got {} frames",
            frames.len()
        );
        // First frame Fragmentation == First, last == Last, middle == Next.
        let mut c = ReadCursor::new(&frames[0]);
        let _ = FastPathOutputHeader::decode(&mut c).unwrap();
        let first = FastPathOutputUpdate::decode(&mut c).unwrap();
        assert_eq!(first.fragmentation, Fragmentation::First);
        let mut c = ReadCursor::new(frames.last().unwrap());
        let _ = FastPathOutputHeader::decode(&mut c).unwrap();
        let last = FastPathOutputUpdate::decode(&mut c).unwrap();
        assert_eq!(last.fragmentation, Fragmentation::Last);
        if frames.len() > 2 {
            let mut c = ReadCursor::new(&frames[1]);
            let _ = FastPathOutputHeader::decode(&mut c).unwrap();
            let middle = FastPathOutputUpdate::decode(&mut c).unwrap();
            assert_eq!(middle.fragmentation, Fragmentation::Next);
        }
        // Reassembly produces the original single-rect TS_UPDATE_BITMAP_DATA.
        let decoded = reassemble(&frames);
        assert_eq!(decoded.rectangles.len(), 1);
        let r = &decoded.rectangles[0];
        assert_eq!(r.width, 128);
        assert_eq!(r.height, 32);
        assert_eq!(r.bitmap_data.len(), 128 * 32 * 4);
    }

    #[test]
    fn rejects_oversized_single_rectangle() {
        // 256 x 256 x 32bpp = 262_144 bytes; bitmapLength is u16 (max
        // 65_535) so the encoder must reject before fragmenting (a
        // single TS_BITMAP_DATA cannot represent it).
        let cfg = config(16_364);
        let upd = build_update(256, 256, 32);
        let err = encode_bitmap_update(&cfg, &upd).unwrap_err();
        let msg = alloc::format!("{err}");
        assert!(msg.contains("u16 bitmapLength"), "got: {msg}");
    }

    #[test]
    fn rejects_wrong_data_length() {
        let cfg = config(16_364);
        let mut upd = build_update(8, 8, 32);
        upd.data.pop();
        assert!(encode_bitmap_update(&cfg, &upd).is_err());
    }

    #[test]
    fn rejects_invalid_bpp() {
        let cfg = config(16_364);
        let upd = BitmapUpdate {
            dest_left: 0,
            dest_top: 0,
            width: 1,
            height: 1,
            bits_per_pixel: 64, // not a valid RDP bpp
            data: vec![0; 8],
        };
        assert!(encode_bitmap_update(&cfg, &upd).is_err());
    }

    #[test]
    fn rejects_zero_dimensions() {
        let cfg = config(16_364);
        let upd = BitmapUpdate {
            dest_left: 0,
            dest_top: 0,
            width: 0,
            height: 1,
            bits_per_pixel: 32,
            data: vec![],
        };
        assert!(encode_bitmap_update(&cfg, &upd).is_err());
    }

    #[test]
    fn rejects_overflow_dest_right() {
        let cfg = config(16_364);
        let upd = BitmapUpdate {
            dest_left: u16::MAX,
            dest_top: 0,
            width: 2, // dest_left + width - 1 overflows
            height: 1,
            bits_per_pixel: 32,
            data: vec![0; 8],
        };
        assert!(encode_bitmap_update(&cfg, &upd).is_err());
    }

    #[test]
    fn frame_length_field_matches_actual_pdu_size() {
        let cfg = config(16_364);
        let upd = build_update(64, 64, 32);
        let frames = encode_bitmap_update(&cfg, &upd).unwrap();
        for frame in &frames {
            let mut c = ReadCursor::new(frame);
            let hdr = FastPathOutputHeader::decode(&mut c).unwrap();
            assert_eq!(usize::from(hdr.length), frame.len(),
                "header length must equal actual PDU length");
        }
    }

    #[test]
    fn chunk_limit_exact_boundary_emits_single_frame() {
        // Inner payload size for an 8x8x32 bitmap:
        //   2 (numberRectangles) + 18 (TS_BITMAP_DATA fixed) + 256 = 276
        let cfg = config(276);
        let upd = build_update(8, 8, 32);
        let frames = encode_bitmap_update(&cfg, &upd).unwrap();
        assert_eq!(frames.len(), 1);
        let mut c = ReadCursor::new(&frames[0]);
        let _ = FastPathOutputHeader::decode(&mut c).unwrap();
        let single = FastPathOutputUpdate::decode(&mut c).unwrap();
        assert_eq!(single.fragmentation, Fragmentation::Single);
    }

    fn decode_pointer_payload(frame: &[u8]) -> (FastPathUpdateType, Vec<u8>) {
        let mut c = ReadCursor::new(frame);
        let _hdr = FastPathOutputHeader::decode(&mut c).unwrap();
        let upd = FastPathOutputUpdate::decode(&mut c).unwrap();
        assert_eq!(upd.fragmentation, Fragmentation::Single);
        (upd.update_code, upd.update_data)
    }

    #[test]
    fn pointer_position_encodes_ts_point16() {
        let p = TsPoint16 { x_pos: 0x1234, y_pos: 0x5678 };
        let frame = encode_pointer_update(&DisplayUpdate::PointerPosition(p)).unwrap();
        let (code, payload) = decode_pointer_payload(&frame);
        assert_eq!(code, FastPathUpdateType::PointerPosition);
        assert_eq!(payload, vec![0x34, 0x12, 0x78, 0x56]);
    }

    #[test]
    fn pointer_hidden_emits_empty_payload() {
        let frame = encode_pointer_update(&DisplayUpdate::PointerHidden).unwrap();
        let (code, payload) = decode_pointer_payload(&frame);
        assert_eq!(code, FastPathUpdateType::PointerHidden);
        assert!(payload.is_empty());
    }

    #[test]
    fn pointer_default_emits_empty_payload() {
        let frame = encode_pointer_update(&DisplayUpdate::PointerDefault).unwrap();
        let (code, payload) = decode_pointer_payload(&frame);
        assert_eq!(code, FastPathUpdateType::PointerDefault);
        assert!(payload.is_empty());
    }

    #[test]
    fn pointer_cached_encodes_index_le() {
        let frame =
            encode_pointer_update(&DisplayUpdate::PointerCached { cache_index: 0x00AB })
                .unwrap();
        let (code, payload) = decode_pointer_payload(&frame);
        assert_eq!(code, FastPathUpdateType::PointerCached);
        assert_eq!(payload, vec![0xAB, 0x00]);
    }

    #[test]
    fn pointer_color_roundtrip_through_encoded_payload() {
        // 8x8 color cursor: AND mask = 2 bytes/row * 8 rows = 16; XOR
        // 24bpp = 24 bytes/row * 8 rows = 192.
        let c = PointerColorUpdate {
            cache_index: 3,
            hot_spot: TsPoint16 { x_pos: 4, y_pos: 4 },
            width: 8,
            height: 8,
            xor_mask_data: vec![0xCC; 24 * 8],
            and_mask_data: vec![0xAA; 2 * 8],
        };
        let frame = encode_pointer_update(&DisplayUpdate::PointerColor(c.clone())).unwrap();
        let (code, payload) = decode_pointer_payload(&frame);
        assert_eq!(code, FastPathUpdateType::PointerColor);
        let mut rc = ReadCursor::new(&payload);
        let attr = TsColorPointerAttribute::decode(&mut rc).unwrap();
        assert_eq!(attr.cache_index, c.cache_index);
        assert_eq!(attr.hot_spot, c.hot_spot);
        assert_eq!(attr.width, c.width);
        assert_eq!(attr.height, c.height);
        assert_eq!(attr.xor_mask_data, c.xor_mask_data);
        assert_eq!(attr.and_mask_data, c.and_mask_data);
    }

    #[test]
    fn pointer_color_rejects_oversize() {
        let c = PointerColorUpdate {
            cache_index: 0,
            hot_spot: TsPoint16::default(),
            width: 33, // > 32 cap from MS-RDPBCGR §2.2.9.1.1.4.4
            height: 8,
            xor_mask_data: vec![0; xor_mask_row_stride(33, 24) * 8],
            and_mask_data: vec![0; and_mask_row_stride(33) * 8],
        };
        assert!(encode_pointer_update(&DisplayUpdate::PointerColor(c)).is_err());
    }

    #[test]
    fn pointer_color_rejects_wrong_xor_length() {
        let c = PointerColorUpdate {
            cache_index: 0,
            hot_spot: TsPoint16::default(),
            width: 8,
            height: 8,
            xor_mask_data: vec![0; 100], // wrong: should be 192
            and_mask_data: vec![0; 16],
        };
        assert!(encode_pointer_update(&DisplayUpdate::PointerColor(c)).is_err());
    }

    #[test]
    fn pointer_new_32bpp_roundtrip() {
        // 16x16x32bpp: XOR = 64 bytes/row * 16 rows = 1024; AND = 2*16 = 32
        let n = PointerNewUpdate {
            xor_bpp: 32,
            cache_index: 1,
            hot_spot: TsPoint16 { x_pos: 8, y_pos: 8 },
            width: 16,
            height: 16,
            xor_mask_data: vec![0x11; 64 * 16],
            and_mask_data: vec![0x22; 2 * 16],
        };
        let frame = encode_pointer_update(&DisplayUpdate::PointerNew(n.clone())).unwrap();
        let (code, payload) = decode_pointer_payload(&frame);
        assert_eq!(code, FastPathUpdateType::PointerNew);
        let mut rc = ReadCursor::new(&payload);
        let attr = TsPointerAttribute::decode(&mut rc).unwrap();
        assert_eq!(attr.xor_bpp, 32);
        assert_eq!(attr.color_ptr_attr.width, 16);
        assert_eq!(attr.color_ptr_attr.height, 16);
        assert_eq!(attr.color_ptr_attr.xor_mask_data.len(), 1024);
    }

    #[test]
    fn pointer_new_rejects_invalid_bpp() {
        let n = PointerNewUpdate {
            xor_bpp: 64,
            cache_index: 0,
            hot_spot: TsPoint16::default(),
            width: 1,
            height: 1,
            xor_mask_data: vec![0; 8],
            and_mask_data: vec![0; 2],
        };
        assert!(encode_pointer_update(&DisplayUpdate::PointerNew(n)).is_err());
    }

    #[test]
    fn pointer_new_rejects_wrong_mask_length() {
        let n = PointerNewUpdate {
            xor_bpp: 1,
            cache_index: 0,
            hot_spot: TsPoint16::default(),
            width: 32,
            height: 32,
            xor_mask_data: vec![0; 100], // wrong: needs 4*32 = 128
            and_mask_data: vec![0; 4 * 32],
        };
        assert!(encode_pointer_update(&DisplayUpdate::PointerNew(n)).is_err());
    }

    #[test]
    fn pointer_update_rejects_non_pointer_variant() {
        let upd = DisplayUpdate::Reset { width: 800, height: 600 };
        assert!(encode_pointer_update(&upd).is_err());
        let bm = DisplayUpdate::Bitmap(BitmapUpdate {
            dest_left: 0,
            dest_top: 0,
            width: 1,
            height: 1,
            bits_per_pixel: 32,
            data: vec![0; 4],
        });
        assert!(encode_pointer_update(&bm).is_err());
    }

    #[test]
    fn fragments_8bpp_bitmap_with_padded_stride() {
        // 7 px wide @ 8 bpp: row_bytes = 7 → stride padded to 8.
        let cfg = config(16_364);
        let upd = BitmapUpdate {
            dest_left: 0,
            dest_top: 0,
            width: 7,
            height: 4,
            bits_per_pixel: 8,
            data: vec![0xAB; 8 * 4], // 8-byte stride * 4 rows
        };
        let frames = encode_bitmap_update(&cfg, &upd).unwrap();
        let decoded = reassemble(&frames);
        let r = &decoded.rectangles[0];
        assert_eq!(r.width, 7);
        assert_eq!(r.height, 4);
        assert_eq!(r.bitmap_data.len(), 32);
    }

    // ── SURFCMDS encoder tests ────────────────────────────────────

    use justrdp_pdu::rdp::surface_commands::{
        CompressedBitmapHeaderEx, FrameMarkerCmd, SetSurfaceBitsCmd, SurfaceCommand,
        SURFACECMD_FRAMEACTION_BEGIN, SURFACECMD_FRAMEACTION_END,
    };

    /// Reassemble fast-path frames carrying SURFCMDS into the inner
    /// payload bytes (a concatenated `TS_SURFCMD` stream).
    fn reassemble_surfcmds(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for frame in frames {
            let mut c = ReadCursor::new(frame);
            let _hdr = FastPathOutputHeader::decode(&mut c).unwrap();
            let upd = FastPathOutputUpdate::decode(&mut c).unwrap();
            assert_eq!(upd.update_code, FastPathUpdateType::SurfaceCommands);
            payload.extend_from_slice(&upd.update_data);
        }
        payload
    }

    fn sample_surface_bits(width: u16, height: u16, payload_len: usize) -> SurfaceBitsUpdate {
        SurfaceBitsUpdate {
            dest_left: 100,
            dest_top: 200,
            width,
            height,
            bpp: 32,
            codec_id: 0,
            bitmap_data: vec![0xCD; payload_len],
            ex_header: None,
        }
    }

    #[test]
    fn frame_marker_begin_emits_single_pdu() {
        let frame = encode_frame_marker(true, 0).unwrap();
        let mut c = ReadCursor::new(&frame);
        let hdr = FastPathOutputHeader::decode(&mut c).unwrap();
        assert_eq!(hdr.length as usize, frame.len());
        let upd = FastPathOutputUpdate::decode(&mut c).unwrap();
        assert_eq!(upd.update_code, FastPathUpdateType::SurfaceCommands);
        assert!(matches!(upd.fragmentation, Fragmentation::Single));
        let mut payload_cur = ReadCursor::new(&upd.update_data);
        let cmd = FrameMarkerCmd::decode(&mut payload_cur).unwrap();
        assert_eq!(cmd.frame_action, SURFACECMD_FRAMEACTION_BEGIN);
        assert_eq!(cmd.frame_id, 0);
    }

    #[test]
    fn frame_marker_end_max_frame_id_roundtrip() {
        let frame = encode_frame_marker(false, u32::MAX).unwrap();
        let mut c = ReadCursor::new(&frame);
        let _ = FastPathOutputHeader::decode(&mut c).unwrap();
        let upd = FastPathOutputUpdate::decode(&mut c).unwrap();
        let mut payload_cur = ReadCursor::new(&upd.update_data);
        let cmd = FrameMarkerCmd::decode(&mut payload_cur).unwrap();
        assert_eq!(cmd.frame_action, SURFACECMD_FRAMEACTION_END);
        assert_eq!(cmd.frame_id, u32::MAX);
    }

    #[test]
    fn frame_marker_via_dispatch_enum_decodes() {
        let frame = encode_frame_marker(true, 7).unwrap();
        let payload = reassemble_surfcmds(&[frame]);
        let mut c = ReadCursor::new(&payload);
        match SurfaceCommand::decode(&mut c).unwrap() {
            SurfaceCommand::FrameMarker(m) => {
                assert_eq!(m.frame_action, SURFACECMD_FRAMEACTION_BEGIN);
                assert_eq!(m.frame_id, 7);
            }
            other => panic!("expected FrameMarker variant, got {other:?}"),
        }
    }

    #[test]
    fn surface_bits_small_payload_single_frame() {
        let cfg = config(16_364);
        let upd = sample_surface_bits(8, 8, 256);
        let frames = encode_surface_bits_update(&cfg, &upd).unwrap();
        assert_eq!(frames.len(), 1);
        let mut c = ReadCursor::new(&frames[0]);
        let hdr = FastPathOutputHeader::decode(&mut c).unwrap();
        assert_eq!(hdr.length as usize, frames[0].len());
        let fp_upd = FastPathOutputUpdate::decode(&mut c).unwrap();
        assert_eq!(fp_upd.update_code, FastPathUpdateType::SurfaceCommands);
        assert!(matches!(fp_upd.fragmentation, Fragmentation::Single));
        let payload = reassemble_surfcmds(&frames);
        let mut p = ReadCursor::new(&payload);
        let cmd = SetSurfaceBitsCmd::decode(&mut p).unwrap();
        assert_eq!(cmd.dest_left, 100);
        assert_eq!(cmd.dest_top, 200);
        // destRight / destBottom are exclusive: dest_left + width.
        assert_eq!(cmd.dest_right, 108);
        assert_eq!(cmd.dest_bottom, 208);
        assert_eq!(cmd.bitmap_data.width, 8);
        assert_eq!(cmd.bitmap_data.height, 8);
        assert_eq!(cmd.bitmap_data.bpp, 32);
        assert_eq!(cmd.bitmap_data.codec_id, 0);
        assert_eq!(cmd.bitmap_data.bitmap_data.len(), 256);
        assert!(cmd.bitmap_data.ex_header.is_none());
    }

    #[test]
    fn surface_bits_with_ex_header_roundtrip() {
        let cfg = config(16_364);
        let mut upd = sample_surface_bits(4, 4, 64);
        upd.ex_header = Some(CompressedBitmapHeaderEx {
            high_unique_id: 0xDEADBEEF,
            low_unique_id: 0xCAFEBABE,
            tm_milliseconds: 999,
            tm_seconds: 8888,
        });
        let frames = encode_surface_bits_update(&cfg, &upd).unwrap();
        let payload = reassemble_surfcmds(&frames);
        let mut p = ReadCursor::new(&payload);
        let cmd = SetSurfaceBitsCmd::decode(&mut p).unwrap();
        let ex = cmd.bitmap_data.ex_header.expect("ex_header preserved");
        assert_eq!(ex.high_unique_id, 0xDEADBEEF);
        assert_eq!(ex.low_unique_id, 0xCAFEBABE);
        assert_eq!(ex.tm_milliseconds, 999);
        assert_eq!(ex.tm_seconds, 8888);
    }

    #[test]
    fn surface_bits_zero_length_payload_accepted() {
        let cfg = config(16_364);
        let upd = sample_surface_bits(1, 1, 0);
        let frames = encode_surface_bits_update(&cfg, &upd).unwrap();
        let payload = reassemble_surfcmds(&frames);
        let mut p = ReadCursor::new(&payload);
        let cmd = SetSurfaceBitsCmd::decode(&mut p).unwrap();
        assert!(cmd.bitmap_data.bitmap_data.is_empty());
    }

    #[test]
    fn surface_bits_zero_dimensions_rejected() {
        let cfg = config(16_364);
        let mut upd = sample_surface_bits(8, 8, 256);
        upd.width = 0;
        assert!(encode_surface_bits_update(&cfg, &upd).is_err());
        upd.width = 8;
        upd.height = 0;
        assert!(encode_surface_bits_update(&cfg, &upd).is_err());
    }

    #[test]
    fn surface_bits_dest_overflow_rejected() {
        let cfg = config(16_364);
        let mut upd = sample_surface_bits(8, 8, 256);
        upd.dest_left = u16::MAX;
        upd.width = 2; // u16::MAX + 2 overflows
        assert!(encode_surface_bits_update(&cfg, &upd).is_err());
    }

    #[test]
    fn surface_bits_large_payload_fragments() {
        // 1024-byte chunk limit forces splitting; payload comfortably
        // exceeds it. Each fragment carries SURFCMDS bytes; reassembled
        // bytes MUST decode as a single SetSurfaceBitsCmd identical to
        // the input.
        let cfg = config(1_024);
        let upd = SurfaceBitsUpdate {
            dest_left: 50,
            dest_top: 60,
            width: 32,
            height: 32,
            bpp: 32,
            codec_id: 0,
            bitmap_data: (0..4096).map(|i| (i & 0xFF) as u8).collect(),
            ex_header: None,
        };
        let frames = encode_surface_bits_update(&cfg, &upd).unwrap();
        assert!(
            frames.len() > 1,
            "expected fragmentation, got {} frames",
            frames.len()
        );
        // Verify First / Next* / Last fragmentation tags.
        let mut tags = Vec::new();
        for f in &frames {
            let mut c = ReadCursor::new(f);
            let hdr = FastPathOutputHeader::decode(&mut c).unwrap();
            assert_eq!(hdr.length as usize, f.len());
            let fp = FastPathOutputUpdate::decode(&mut c).unwrap();
            assert_eq!(fp.update_code, FastPathUpdateType::SurfaceCommands);
            tags.push(fp.fragmentation);
        }
        assert!(matches!(tags.first(), Some(Fragmentation::First)));
        assert!(matches!(tags.last(), Some(Fragmentation::Last)));
        for tag in &tags[1..tags.len() - 1] {
            assert!(matches!(tag, Fragmentation::Next));
        }
        // Reassemble and decode round-trips back to the input.
        let payload = reassemble_surfcmds(&frames);
        let mut p = ReadCursor::new(&payload);
        let cmd = SetSurfaceBitsCmd::decode(&mut p).unwrap();
        assert_eq!(cmd.bitmap_data.bitmap_data, upd.bitmap_data);
        assert_eq!(cmd.bitmap_data.width, upd.width);
        assert_eq!(cmd.bitmap_data.height, upd.height);
    }

    #[test]
    fn surface_bits_chunk_limit_exact_boundary_single_frame() {
        // Compute the exact inner SURFCMDS payload size for a small
        // SetSurfaceBits and use that as the chunk limit so the payload
        // fits in exactly one frame with Fragmentation::Single.
        let upd = sample_surface_bits(2, 2, 16);
        let inner_size = TS_SURFCMD_SURF_BITS_HEADER_SIZE_LOCAL
            + TS_BITMAP_DATA_EX_FIXED_SIZE_LOCAL
            + 16;
        let cfg = config(inner_size);
        let frames = encode_surface_bits_update(&cfg, &upd).unwrap();
        assert_eq!(frames.len(), 1);
        let mut c = ReadCursor::new(&frames[0]);
        let _ = FastPathOutputHeader::decode(&mut c).unwrap();
        let fp = FastPathOutputUpdate::decode(&mut c).unwrap();
        assert!(matches!(fp.fragmentation, Fragmentation::Single));
    }

    // Local mirrors of the surface_commands constants used in the
    // boundary test above; pulling them in as named consts keeps the
    // arithmetic readable while documenting which spec sections feed it.
    const TS_SURFCMD_SURF_BITS_HEADER_SIZE_LOCAL: usize = 10; // §2.2.9.2.1
    const TS_BITMAP_DATA_EX_FIXED_SIZE_LOCAL: usize = 12; // §2.2.9.2.1.1

    #[test]
    fn frame_marker_size_matches_pdu_length_field() {
        for begin in [true, false] {
            let frame = encode_frame_marker(begin, 12345).unwrap();
            let mut c = ReadCursor::new(&frame);
            let hdr = FastPathOutputHeader::decode(&mut c).unwrap();
            assert_eq!(hdr.length as usize, frame.len());
        }
    }
}
