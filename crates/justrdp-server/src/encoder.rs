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
use justrdp_pdu::rdp::pointer::{
    TsCachedPointerAttribute, TsColorPointerAttribute, TsPoint16, TsPointerAttribute,
    and_mask_row_stride, validate_color_pointer_dimensions, xor_mask_row_stride,
};

use crate::config::RdpServerConfig;
use crate::error::{ServerError, ServerResult};
use crate::handler::{BitmapUpdate, DisplayUpdate, PointerColorUpdate, PointerNewUpdate};

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

/// Encode a fast-path pointer update (any of the
/// `Position`/`Hidden`/`Default`/`Color`/`New`/`Cached` variants of
/// [`DisplayUpdate`]) into a single fast-path PDU.
///
/// Pointer updates always fit comfortably inside a single fast-path
/// PDU -- the largest payload is a 96x96 [`PointerNewUpdate`] at 32 bpp
/// (~37 KiB) which still sits well below the 15-bit length cap. The
/// encoder therefore emits only `Fragmentation::Single` frames.
///
/// Non-pointer variants (`Bitmap`, `Palette`, `Reset`) MUST be routed
/// to their own encoders; this function returns
/// `ServerError::protocol(...)` for them.
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
        DisplayUpdate::Bitmap(_) | DisplayUpdate::Palette(_) | DisplayUpdate::Reset { .. } => {
            Err(ServerError::protocol(
                "encode_pointer_update called on a non-pointer DisplayUpdate variant",
            ))
        }
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
}
