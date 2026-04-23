#![forbid(unsafe_code)]

//! Bitmap Update PDU types -- MS-RDPBCGR 2.2.9.1.1.3.1.2 (slow-path) and
//! 2.2.9.1.2.1.2 (fast-path payload).

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

// ── Constants (MS-RDPBCGR 2.2.9.1.1.3.1.2 / 2.2.9.1.1.3.1.2.1) ──

/// `UPDATETYPE_BITMAP` -- the inner update type for both slow-path and
/// fast-path bitmap updates. MS-RDPBCGR 2.2.9.1.1.3.1.2.
pub const UPDATETYPE_BITMAP: u16 = 0x0001;

/// `BITMAP_COMPRESSION` flag in `TS_BITMAP_DATA::flags`. MS-RDPBCGR 2.2.9.1.1.3.1.2.1.
pub const BITMAP_COMPRESSION: u16 = 0x0001;

/// `NO_BITMAP_COMPRESSION_HDR` flag -- when set together with
/// `BITMAP_COMPRESSION`, the 8-byte `TS_CD_HEADER` is omitted from the wire.
/// MS-RDPBCGR 2.2.9.1.1.3.1.2.1.
pub const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;

/// Fixed wire size of `TS_CD_HEADER`. MS-RDPBCGR 2.2.9.1.1.3.1.2.2.
pub const TS_CD_HEADER_SIZE: usize = 8;

/// Wire size of the fixed prefix of a `TS_BITMAP_DATA` record (everything
/// before the optional `bitmapComprHdr` and the variable `bitmapDataStream`).
pub const TS_BITMAP_DATA_FIXED_SIZE: usize = 18;

// ── TS_CD_HEADER ──

/// Compressed bitmap header. MS-RDPBCGR 2.2.9.1.1.3.1.2.2.
///
/// Present only when `TS_BITMAP_DATA::flags` has `BITMAP_COMPRESSION` set
/// **and** `NO_BITMAP_COMPRESSION_HDR` not set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TsCdHeader {
    /// `cbCompFirstRowSize` -- MUST be `0x0000` per the spec.
    pub cb_comp_first_row_size: u16,
    /// `cbCompMainBodySize` -- size in bytes of the compressed `bitmapDataStream`.
    pub cb_comp_main_body_size: u16,
    /// `cbScanWidth` -- width of the bitmap scanline in bytes (4-byte aligned).
    pub cb_scan_width: u16,
    /// `cbUncompressedSize` -- size in bytes of the uncompressed bitmap data.
    pub cb_uncompressed_size: u16,
}

impl Encode for TsCdHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.cb_comp_first_row_size, "TsCdHeader::cbCompFirstRowSize")?;
        dst.write_u16_le(self.cb_comp_main_body_size, "TsCdHeader::cbCompMainBodySize")?;
        dst.write_u16_le(self.cb_scan_width, "TsCdHeader::cbScanWidth")?;
        dst.write_u16_le(self.cb_uncompressed_size, "TsCdHeader::cbUncompressedSize")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TsCdHeader"
    }

    fn size(&self) -> usize {
        TS_CD_HEADER_SIZE
    }
}

impl<'de> Decode<'de> for TsCdHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self {
            cb_comp_first_row_size: src.read_u16_le("TsCdHeader::cbCompFirstRowSize")?,
            cb_comp_main_body_size: src.read_u16_le("TsCdHeader::cbCompMainBodySize")?,
            cb_scan_width: src.read_u16_le("TsCdHeader::cbScanWidth")?,
            cb_uncompressed_size: src.read_u16_le("TsCdHeader::cbUncompressedSize")?,
        })
    }
}

// ── TS_BITMAP_DATA ──

/// A single bitmap rectangle within a bitmap update. MS-RDPBCGR 2.2.9.1.1.3.1.2.1.
///
/// The wire `bitmapLength` field is computed from `compr_hdr` + `bitmap_data`
/// and is therefore not stored explicitly. The caller must keep `flags`
/// consistent with `compr_hdr`:
///
/// - Uncompressed: `flags == 0`, `compr_hdr == None`.
/// - Compressed with header: `flags & BITMAP_COMPRESSION != 0`,
///   `flags & NO_BITMAP_COMPRESSION_HDR == 0`, `compr_hdr == Some(_)`.
/// - Compressed without header: `flags & BITMAP_COMPRESSION != 0`,
///   `flags & NO_BITMAP_COMPRESSION_HDR != 0`, `compr_hdr == None`.
///
/// `dest_right` and `dest_bottom` are inclusive boundaries
/// (`dest_left + width - 1` / `dest_top + height - 1`) per the spec Remarks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsBitmapData {
    pub dest_left: u16,
    pub dest_top: u16,
    pub dest_right: u16,
    pub dest_bottom: u16,
    pub width: u16,
    pub height: u16,
    pub bits_per_pixel: u16,
    pub flags: u16,
    pub compr_hdr: Option<TsCdHeader>,
    pub bitmap_data: Vec<u8>,
}

impl TsBitmapData {
    /// Wire value of the `bitmapLength` field
    /// (size of `bitmapComprHdr` + `bitmapDataStream`).
    pub fn bitmap_length(&self) -> usize {
        let hdr_len = if self.compr_hdr.is_some() { TS_CD_HEADER_SIZE } else { 0 };
        hdr_len + self.bitmap_data.len()
    }
}

impl Encode for TsBitmapData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let bitmap_length = self.bitmap_length();
        if bitmap_length > u16::MAX as usize {
            return Err(EncodeError::other(
                "TsBitmapData",
                "bitmapLength exceeds u16::MAX",
            ));
        }
        dst.write_u16_le(self.dest_left, "TsBitmapData::destLeft")?;
        dst.write_u16_le(self.dest_top, "TsBitmapData::destTop")?;
        dst.write_u16_le(self.dest_right, "TsBitmapData::destRight")?;
        dst.write_u16_le(self.dest_bottom, "TsBitmapData::destBottom")?;
        dst.write_u16_le(self.width, "TsBitmapData::width")?;
        dst.write_u16_le(self.height, "TsBitmapData::height")?;
        dst.write_u16_le(self.bits_per_pixel, "TsBitmapData::bitsPerPixel")?;
        dst.write_u16_le(self.flags, "TsBitmapData::flags")?;
        dst.write_u16_le(bitmap_length as u16, "TsBitmapData::bitmapLength")?;
        if let Some(hdr) = self.compr_hdr {
            hdr.encode(dst)?;
        }
        dst.write_slice(&self.bitmap_data, "TsBitmapData::bitmapDataStream")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TsBitmapData"
    }

    fn size(&self) -> usize {
        TS_BITMAP_DATA_FIXED_SIZE
            + if self.compr_hdr.is_some() { TS_CD_HEADER_SIZE } else { 0 }
            + self.bitmap_data.len()
    }
}

impl<'de> Decode<'de> for TsBitmapData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let dest_left = src.read_u16_le("TsBitmapData::destLeft")?;
        let dest_top = src.read_u16_le("TsBitmapData::destTop")?;
        let dest_right = src.read_u16_le("TsBitmapData::destRight")?;
        let dest_bottom = src.read_u16_le("TsBitmapData::destBottom")?;
        let width = src.read_u16_le("TsBitmapData::width")?;
        let height = src.read_u16_le("TsBitmapData::height")?;
        let bits_per_pixel = src.read_u16_le("TsBitmapData::bitsPerPixel")?;
        let flags = src.read_u16_le("TsBitmapData::flags")?;
        let bitmap_length = src.read_u16_le("TsBitmapData::bitmapLength")? as usize;

        let has_compr_hdr =
            (flags & BITMAP_COMPRESSION) != 0 && (flags & NO_BITMAP_COMPRESSION_HDR) == 0;

        let (compr_hdr, data_len) = if has_compr_hdr {
            if bitmap_length < TS_CD_HEADER_SIZE {
                return Err(DecodeError::invalid_value(
                    "TsBitmapData",
                    "bitmapLength",
                ));
            }
            let hdr = TsCdHeader::decode(src)?;
            (Some(hdr), bitmap_length - TS_CD_HEADER_SIZE)
        } else {
            (None, bitmap_length)
        };

        let data = src.read_slice(data_len, "TsBitmapData::bitmapDataStream")?;
        Ok(Self {
            dest_left,
            dest_top,
            dest_right,
            dest_bottom,
            width,
            height,
            bits_per_pixel,
            flags,
            compr_hdr,
            bitmap_data: data.to_vec(),
        })
    }
}

// ── TS_UPDATE_BITMAP_DATA ──

/// Bitmap Update PDU body -- MS-RDPBCGR 2.2.9.1.1.3.1.2 (slow-path) and
/// 2.2.9.1.2.1.2 (fast-path payload).
///
/// In **slow-path** the body is preceded by a `updateType` field (`u16 LE`)
/// equal to [`UPDATETYPE_BITMAP`]; this is what [`Encode`]/[`Decode`] handle.
///
/// In **fast-path** the update type is implicit (encoded in the
/// `FastPathOutputUpdate::update_code` field), so callers must use
/// [`TsUpdateBitmapData::encode_fast_path`] /
/// [`TsUpdateBitmapData::decode_fast_path`], which omit the `updateType` field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TsUpdateBitmapData {
    pub rectangles: Vec<TsBitmapData>,
}

impl TsUpdateBitmapData {
    /// Encode the fast-path payload form (omits leading `updateType`).
    pub fn encode_fast_path(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if self.rectangles.len() > u16::MAX as usize {
            return Err(EncodeError::other(
                "TsUpdateBitmapData",
                "numberRectangles exceeds u16::MAX",
            ));
        }
        dst.write_u16_le(
            self.rectangles.len() as u16,
            "TsUpdateBitmapData::numberRectangles",
        )?;
        for r in &self.rectangles {
            r.encode(dst)?;
        }
        Ok(())
    }

    /// Wire size of the fast-path payload (no leading `updateType`).
    pub fn fast_path_size(&self) -> usize {
        2 + self.rectangles.iter().map(|r| r.size()).sum::<usize>()
    }

    /// Decode the fast-path payload form (no leading `updateType`).
    pub fn decode_fast_path(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let count = src.read_u16_le("TsUpdateBitmapData::numberRectangles")?;
        let mut rectangles = Vec::with_capacity(count as usize);
        for _ in 0..count {
            rectangles.push(TsBitmapData::decode(src)?);
        }
        Ok(Self { rectangles })
    }
}

impl Encode for TsUpdateBitmapData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(UPDATETYPE_BITMAP, "TsUpdateBitmapData::updateType")?;
        self.encode_fast_path(dst)
    }

    fn name(&self) -> &'static str {
        "TsUpdateBitmapData"
    }

    fn size(&self) -> usize {
        2 + self.fast_path_size()
    }
}

impl<'de> Decode<'de> for TsUpdateBitmapData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let update_type = src.read_u16_le("TsUpdateBitmapData::updateType")?;
        if update_type != UPDATETYPE_BITMAP {
            return Err(DecodeError::unexpected_value(
                "TsUpdateBitmapData",
                "updateType",
                "expected UPDATETYPE_BITMAP (0x0001)",
            ));
        }
        Self::decode_fast_path(src)
    }
}

// ── Helpers ──

/// Per-row stride (in bytes) for an uncompressed bitmap rectangle, padded up
/// to a 4-byte boundary per MS-RDPBCGR 2.2.9.1.1.3.1.2.1 Remarks.
pub fn uncompressed_row_stride(width: u16, bits_per_pixel: u16) -> usize {
    let row_bytes = (usize::from(width) * usize::from(bits_per_pixel) + 7) / 8;
    (row_bytes + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn encode_to_vec<E: Encode>(v: &E) -> Vec<u8> {
        let mut buf = vec![0u8; v.size()];
        let mut c = WriteCursor::new(&mut buf);
        v.encode(&mut c).unwrap();
        buf
    }

    #[test]
    fn ts_cd_header_roundtrip() {
        let hdr = TsCdHeader {
            cb_comp_first_row_size: 0,
            cb_comp_main_body_size: 256,
            cb_scan_width: 64,
            cb_uncompressed_size: 4096,
        };
        let buf = encode_to_vec(&hdr);
        assert_eq!(buf.len(), TS_CD_HEADER_SIZE);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsCdHeader::decode(&mut c).unwrap(), hdr);
    }

    #[test]
    fn ts_bitmap_data_uncompressed_roundtrip() {
        let data = vec![0xAB; 64];
        let pdu = TsBitmapData {
            dest_left: 0,
            dest_top: 0,
            dest_right: 7,
            dest_bottom: 7,
            width: 8,
            height: 8,
            bits_per_pixel: 8,
            flags: 0,
            compr_hdr: None,
            bitmap_data: data.clone(),
        };
        assert_eq!(pdu.bitmap_length(), data.len());
        let buf = encode_to_vec(&pdu);
        assert_eq!(buf.len(), TS_BITMAP_DATA_FIXED_SIZE + data.len());
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsBitmapData::decode(&mut c).unwrap(), pdu);
    }

    #[test]
    fn ts_bitmap_data_compressed_with_hdr_roundtrip() {
        let data = vec![0xEE; 32];
        let pdu = TsBitmapData {
            dest_left: 10,
            dest_top: 20,
            dest_right: 25,
            dest_bottom: 35,
            width: 16,
            height: 16,
            bits_per_pixel: 16,
            flags: BITMAP_COMPRESSION,
            compr_hdr: Some(TsCdHeader {
                cb_comp_first_row_size: 0,
                cb_comp_main_body_size: 32,
                cb_scan_width: 32,
                cb_uncompressed_size: 512,
            }),
            bitmap_data: data.clone(),
        };
        assert_eq!(pdu.bitmap_length(), TS_CD_HEADER_SIZE + data.len());
        let buf = encode_to_vec(&pdu);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsBitmapData::decode(&mut c).unwrap(), pdu);
    }

    #[test]
    fn ts_bitmap_data_compressed_no_hdr_roundtrip() {
        let data = vec![0x55; 40];
        let pdu = TsBitmapData {
            dest_left: 0,
            dest_top: 0,
            dest_right: 31,
            dest_bottom: 7,
            width: 32,
            height: 8,
            bits_per_pixel: 32,
            flags: BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR,
            compr_hdr: None,
            bitmap_data: data.clone(),
        };
        assert_eq!(pdu.bitmap_length(), data.len());
        let buf = encode_to_vec(&pdu);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsBitmapData::decode(&mut c).unwrap(), pdu);
    }

    #[test]
    fn ts_update_bitmap_data_slow_path_roundtrip() {
        let r = TsBitmapData {
            dest_left: 0,
            dest_top: 0,
            dest_right: 7,
            dest_bottom: 7,
            width: 8,
            height: 8,
            bits_per_pixel: 8,
            flags: 0,
            compr_hdr: None,
            bitmap_data: vec![0xCC; 64],
        };
        let upd = TsUpdateBitmapData { rectangles: vec![r.clone(), r] };
        let buf = encode_to_vec(&upd);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsUpdateBitmapData::decode(&mut c).unwrap(), upd);
    }

    #[test]
    fn ts_update_bitmap_data_fast_path_roundtrip() {
        let r = TsBitmapData {
            dest_left: 0,
            dest_top: 0,
            dest_right: 7,
            dest_bottom: 7,
            width: 8,
            height: 8,
            bits_per_pixel: 8,
            flags: 0,
            compr_hdr: None,
            bitmap_data: vec![0x11; 64],
        };
        let upd = TsUpdateBitmapData { rectangles: vec![r] };
        let mut buf = vec![0u8; upd.fast_path_size()];
        let mut c = WriteCursor::new(&mut buf);
        upd.encode_fast_path(&mut c).unwrap();
        let mut rc = ReadCursor::new(&buf);
        assert_eq!(TsUpdateBitmapData::decode_fast_path(&mut rc).unwrap(), upd);
    }

    #[test]
    fn ts_update_bitmap_data_empty_roundtrip() {
        let upd = TsUpdateBitmapData { rectangles: vec![] };
        let buf = encode_to_vec(&upd);
        // 2 (updateType) + 2 (numberRectangles=0)
        assert_eq!(buf.len(), 4);
        let mut c = ReadCursor::new(&buf);
        assert_eq!(TsUpdateBitmapData::decode(&mut c).unwrap(), upd);
    }

    #[test]
    fn ts_update_bitmap_data_rejects_wrong_update_type() {
        let bytes = [0x02u8, 0x00, 0x00, 0x00]; // updateType=0x0002
        let mut c = ReadCursor::new(&bytes);
        assert!(TsUpdateBitmapData::decode(&mut c).is_err());
    }

    #[test]
    fn ts_bitmap_data_rejects_bitmap_length_below_compr_hdr() {
        // BITMAP_COMPRESSION set, NO_BITMAP_COMPRESSION_HDR clear → comprHdr
        // (8 bytes) is required, but bitmapLength=4 leaves no room for it.
        let mut buf = vec![0u8; TS_BITMAP_DATA_FIXED_SIZE];
        let mut c = WriteCursor::new(&mut buf);
        c.write_u16_le(0, "destLeft").unwrap();
        c.write_u16_le(0, "destTop").unwrap();
        c.write_u16_le(0, "destRight").unwrap();
        c.write_u16_le(0, "destBottom").unwrap();
        c.write_u16_le(1, "width").unwrap();
        c.write_u16_le(1, "height").unwrap();
        c.write_u16_le(8, "bitsPerPixel").unwrap();
        c.write_u16_le(BITMAP_COMPRESSION, "flags").unwrap();
        c.write_u16_le(4, "bitmapLength").unwrap();
        let mut rc = ReadCursor::new(&buf);
        assert!(TsBitmapData::decode(&mut rc).is_err());
    }

    #[test]
    fn uncompressed_row_stride_padding() {
        assert_eq!(uncompressed_row_stride(100, 32), 400); // 4-aligned already
        assert_eq!(uncompressed_row_stride(17, 24), 52); // 51 → 52
        assert_eq!(uncompressed_row_stride(5, 8), 8); // 5 → 8
        assert_eq!(uncompressed_row_stride(100, 8), 100);
        assert_eq!(uncompressed_row_stride(33, 1), 8); // ceil(33/8)=5 → 8
    }

    #[test]
    fn ts_bitmap_data_size_matches_encoded_len() {
        let pdu = TsBitmapData {
            dest_left: 0,
            dest_top: 0,
            dest_right: 31,
            dest_bottom: 31,
            width: 32,
            height: 32,
            bits_per_pixel: 32,
            flags: 0,
            compr_hdr: None,
            bitmap_data: vec![0u8; 32 * 32 * 4],
        };
        let buf = encode_to_vec(&pdu);
        assert_eq!(buf.len(), pdu.size());
    }
}
