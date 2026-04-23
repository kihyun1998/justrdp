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
use justrdp_pdu::rdp::bitmap::{TsBitmapData, TsUpdateBitmapData};
use justrdp_pdu::rdp::fast_path::{
    FastPathOutputHeader, FastPathOutputUpdate, FastPathUpdateType, Fragmentation,
    FASTPATH_OUTPUT_ACTION_FASTPATH,
};

use crate::config::RdpServerConfig;
use crate::error::{ServerError, ServerResult};
use crate::handler::BitmapUpdate;

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
}
