#![forbid(unsafe_code)]

//! H.264/AVC Codec Wire Format -- MS-RDPEGFX 2.2.4.4 – 2.2.4.6
//!
//! Structures carried inside `WireToSurface1Pdu::bitmap_data` when `codec_id`
//! is one of `RDPGFX_CODECID_AVC420`, `RDPGFX_CODECID_AVC444`, or
//! `RDPGFX_CODECID_AVC444V2`.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, ReadCursor};

use super::GfxRect16;

// ── Constants ──

/// Maximum number of region rectangles in a metablock.
/// The spec does not define a limit; we use 4096 as a defensive bound.
const MAX_REGION_RECTS: u32 = 4096;

/// Maximum quality value -- MS-RDPEGFX 2.2.4.4.2
pub const AVC420_QUALITY_MAX: u8 = 100;

/// Lower 6 bits of `qpVal` contain the quantization parameter.
pub const AVC420_QUANT_QP_MASK: u8 = 0x3F;

/// Bit 7 of `qpVal`: progressive encoding flag.
pub const AVC420_QUANT_PROGRESSIVE_FLAG: u8 = 0x80;

/// 30-bit mask for `cbAvc420EncodedBitstream1` in the AVC444 info field.
pub const AVC444_BITSTREAM1_SIZE_MASK: u32 = 0x3FFF_FFFF;

/// Bit shift for the LC field in `avc420EncodedBitstreamInfo`.
pub const AVC444_LC_SHIFT: u32 = 30;

// ── LC mode -- MS-RDPEGFX 2.2.4.5 ──

/// AVC444 / AVC444v2 chroma mode selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Avc444LcMode {
    /// Both luma and chroma sub-streams may be present; individual streams
    /// can be `None` if `cbAvc420EncodedBitstream1 == 0` or the data is empty.
    Both = 0,
    /// Luma (YUV420) stream only; chroma deferred to a future frame.
    LumaOnly = 1,
    /// Chroma stream only; combine with previously decoded luma.
    ChromaOnly = 2,
}

impl Avc444LcMode {
    fn from_bits(bits: u8) -> DecodeResult<Self> {
        match bits {
            0 => Ok(Self::Both),
            1 => Ok(Self::LumaOnly),
            2 => Ok(Self::ChromaOnly),
            _ => Err(DecodeError::invalid_value("Avc444LcMode", "LC == 3 is invalid")),
        }
    }
}

// ── RDPGFX_AVC420_QUANT_QUALITY -- MS-RDPEGFX 2.2.4.4.2 ──

/// Quantization and quality metadata for one region rectangle.
///
/// ```text
/// Offset  Size  Field
/// 0       1     qpVal    (bits [5:0] = qp, bit [6] = reserved, bit [7] = progressive)
/// 1       1     qualityVal (0..=100)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Avc420QuantQuality {
    /// Raw qpVal byte.
    pub qp_val: u8,
    /// Quality value, 0..=100.
    pub quality_val: u8,
}

impl Avc420QuantQuality {
    /// 6-bit quantization parameter.
    pub fn qp(&self) -> u8 {
        self.qp_val & AVC420_QUANT_QP_MASK
    }

    /// Whether the region is progressively encoded (bit 7).
    pub fn is_progressive(&self) -> bool {
        self.qp_val & AVC420_QUANT_PROGRESSIVE_FLAG != 0
    }
}

// ── RFX_AVC420_METABLOCK -- MS-RDPEGFX 2.2.4.4.1 ──

/// AVC420 metablock describing dirty rectangles and quantization metadata.
///
/// ```text
/// Offset     Size    Field
/// 0          4       numRegionRects (u32 LE)
/// 4          8*N     regionRects    (N × RDPGFX_RECT16)
/// 4+8*N      2*N     quantQualityVals (N × RDPGFX_AVC420_QUANT_QUALITY)
/// ```
///
/// Total wire size: `4 + 10*N` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avc420MetaBlock {
    /// Dirty rectangles in surface coordinates.
    pub region_rects: Vec<GfxRect16>,
    /// Per-rectangle quantization / quality metadata.
    pub quant_quality_vals: Vec<Avc420QuantQuality>,
}

impl Avc420MetaBlock {
    /// Wire size in bytes.
    pub fn wire_size(&self) -> usize {
        debug_assert_eq!(self.region_rects.len(), self.quant_quality_vals.len());
        4usize.saturating_add(10usize.saturating_mul(self.region_rects.len()))
    }
}

impl<'de> Decode<'de> for Avc420MetaBlock {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let num = src.read_u32_le("Avc420MetaBlock::numRegionRects")?;
        if num > MAX_REGION_RECTS {
            return Err(DecodeError::invalid_value(
                "Avc420MetaBlock",
                "numRegionRects exceeds maximum",
            ));
        }

        let mut region_rects = Vec::with_capacity(num as usize);
        for _ in 0..num {
            let rect = GfxRect16::decode(src)?;
            if rect.right < rect.left || rect.bottom < rect.top {
                return Err(DecodeError::invalid_value(
                    "Avc420MetaBlock",
                    "inverted rectangle coordinates",
                ));
            }
            region_rects.push(rect);
        }

        let mut quant_quality_vals = Vec::with_capacity(num as usize);
        for _ in 0..num {
            let qp_val = src.read_u8("Avc420QuantQuality::qpVal")?;
            let quality_val = src.read_u8("Avc420QuantQuality::qualityVal")?;
            if quality_val > AVC420_QUALITY_MAX {
                return Err(DecodeError::invalid_value(
                    "Avc420QuantQuality",
                    "qualityVal > 100",
                ));
            }
            quant_quality_vals.push(Avc420QuantQuality {
                qp_val,
                quality_val,
            });
        }

        Ok(Self {
            region_rects,
            quant_quality_vals,
        })
    }
}

// ── RFX_AVC420_BITMAP_STREAM -- MS-RDPEGFX 2.2.4.4 ──

/// Parsed AVC420 bitmap stream: metablock + raw H.264 Annex B bitstream.
///
/// Carried in `WireToSurface1Pdu::bitmap_data` when `codec_id == RDPGFX_CODECID_AVC420`.
/// Also used as a sub-stream within AVC444 / AVC444v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avc420BitmapStream {
    /// Region rectangles and quantization metadata.
    pub meta: Avc420MetaBlock,
    /// Raw H.264 Annex B byte stream (NAL units).
    pub bitstream: Vec<u8>,
}

/// Decode an `Avc420BitmapStream` from a byte slice.
///
/// The entire `data` slice is consumed: the metablock is at the front,
/// and the remainder is the H.264 Annex B bitstream.
pub fn decode_avc420_bitmap_stream(data: &[u8]) -> DecodeResult<Avc420BitmapStream> {
    if data.len() < 4 {
        return Err(DecodeError::invalid_value(
            "Avc420BitmapStream",
            "data too short for metablock",
        ));
    }

    let mut src = ReadCursor::new(data);
    let meta = Avc420MetaBlock::decode(&mut src)?;
    let remaining = src.remaining();
    let bitstream = src
        .read_slice(remaining, "Avc420BitmapStream::bitstream")?
        .to_vec();

    Ok(Avc420BitmapStream { meta, bitstream })
}

// ── RFX_AVC444_BITMAP_STREAM -- MS-RDPEGFX 2.2.4.5 ──

/// Parsed AVC444 bitmap stream.
///
/// Contains one or two `Avc420BitmapStream` sub-streams depending on `lc_mode`.
///
/// ```text
/// Offset  Size  Field
/// 0       4     avc420EncodedBitstreamInfo (u32 LE)
/// 4       var   avc420EncodedBitstream1 (if present)
/// 4+sz1   var   avc420EncodedBitstream2 (if present)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avc444BitmapStream {
    /// Chroma mode selector.
    pub lc_mode: Avc444LcMode,
    /// Main AVC420 stream (luma planes for LC=0/1; chroma auxiliary planes for LC=2).
    pub stream1: Option<Avc420BitmapStream>,
    /// Auxiliary-view AVC420 stream (present only when LC=0).
    pub stream2: Option<Avc420BitmapStream>,
}

/// Decode an `Avc444BitmapStream` from a byte slice.
///
/// Used for both `RDPGFX_CODECID_AVC444 (0x000E)` and
/// `RDPGFX_CODECID_AVC444V2 (0x000F)` — the wire format is identical;
/// the difference is in downstream YUV444 plane combination.
pub fn decode_avc444_bitmap_stream(data: &[u8]) -> DecodeResult<Avc444BitmapStream> {
    if data.len() < 4 {
        return Err(DecodeError::invalid_value(
            "Avc444BitmapStream",
            "data too short for bitstreamInfo",
        ));
    }

    let mut src = ReadCursor::new(data);
    let info = src.read_u32_le("Avc444::avc420EncodedBitstreamInfo")?;

    let cb1 = (info & AVC444_BITSTREAM1_SIZE_MASK) as usize;
    let lc_bits = ((info >> AVC444_LC_SHIFT) & 0x3) as u8;
    let lc_mode = Avc444LcMode::from_bits(lc_bits)?;

    let remaining = src.remaining();

    let (stream1, stream2) = match lc_mode {
        Avc444LcMode::Both => {
            // Both sub-streams present.
            if cb1 > remaining {
                return Err(DecodeError::invalid_value(
                    "Avc444BitmapStream",
                    "cbAvc420EncodedBitstream1 exceeds remaining data",
                ));
            }
            let s1_data = src.read_slice(cb1, "Avc444::bitstream1")?;
            let s2_remaining = src.remaining();
            let s2_data = src.read_slice(s2_remaining, "Avc444::bitstream2")?;

            let s1 = if cb1 > 0 {
                Some(decode_avc420_bitmap_stream(s1_data)?)
            } else {
                None
            };
            let s2 = if !s2_data.is_empty() {
                Some(decode_avc420_bitmap_stream(s2_data)?)
            } else {
                None
            };
            (s1, s2)
        }
        Avc444LcMode::LumaOnly | Avc444LcMode::ChromaOnly => {
            // Only bitstream1 is present.
            if cb1 > remaining {
                return Err(DecodeError::invalid_value(
                    "Avc444BitmapStream",
                    "cbAvc420EncodedBitstream1 exceeds remaining data",
                ));
            }
            let s1 = if cb1 > 0 {
                let s1_data = src.read_slice(cb1, "Avc444::bitstream1")?;
                Some(decode_avc420_bitmap_stream(s1_data)?)
            } else {
                None
            };
            (s1, None)
        }
    };

    Ok(Avc444BitmapStream {
        lc_mode,
        stream1,
        stream2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avc420_quant_quality_accessors() {
        let qq = Avc420QuantQuality {
            qp_val: 0xB3, // qp=51 (0x33), progressive=1
            quality_val: 80,
        };
        assert_eq!(qq.qp(), 51);
        assert!(qq.is_progressive());
    }

    #[test]
    fn avc420_metablock_zero_rects() {
        let data = [0x00, 0x00, 0x00, 0x00];
        let mut src = ReadCursor::new(&data);
        let meta = Avc420MetaBlock::decode(&mut src).unwrap();
        assert!(meta.region_rects.is_empty());
        assert!(meta.quant_quality_vals.is_empty());
        assert_eq!(meta.wire_size(), 4);
    }

    #[test]
    fn avc420_metablock_one_rect() {
        // numRegionRects=1, rect={0,0,64,64}, qpVal=0x1A, qualityVal=80
        let data: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, // numRegionRects
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00, // rect
            0x1A, 0x50, // quant quality
        ];
        let mut src = ReadCursor::new(data);
        let meta = Avc420MetaBlock::decode(&mut src).unwrap();
        assert_eq!(meta.region_rects.len(), 1);
        assert_eq!(meta.region_rects[0].right, 64);
        assert_eq!(meta.quant_quality_vals[0].qp(), 26);
        assert_eq!(meta.quant_quality_vals[0].quality_val, 80);
        assert!(!meta.quant_quality_vals[0].is_progressive());
        assert_eq!(meta.wire_size(), 14);
    }

    #[test]
    fn reject_quality_over_100() {
        let data: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, // numRegionRects
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00, // rect
            0x1A, 0x65, // qualityVal = 101 — invalid
        ];
        let mut src = ReadCursor::new(data);
        assert!(Avc420MetaBlock::decode(&mut src).is_err());
    }

    #[test]
    fn avc420_bitmap_stream_decode() {
        // metablock with 0 rects + 4-byte fake bitstream
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // numRegionRects=0
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // fake NAL start code
        let stream = decode_avc420_bitmap_stream(&data).unwrap();
        assert!(stream.meta.region_rects.is_empty());
        assert_eq!(stream.bitstream, &[0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn avc420_bitmap_stream_empty_bitstream() {
        let data = [0x00, 0x00, 0x00, 0x00]; // metablock only
        let stream = decode_avc420_bitmap_stream(&data).unwrap();
        assert!(stream.bitstream.is_empty());
    }

    #[test]
    fn avc444_lc_both() {
        // info: LC=0, cb1=4 → 0x0000_0004
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000_0004u32.to_le_bytes()); // info
        // stream1: 4 bytes = metablock(4 bytes, 0 rects) + 0-byte bitstream
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // stream2: metablock(4 bytes, 0 rects) + 2-byte bitstream
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0xAA, 0xBB]);

        let stream = decode_avc444_bitmap_stream(&data).unwrap();
        assert_eq!(stream.lc_mode, Avc444LcMode::Both);
        assert!(stream.stream1.is_some());
        assert!(stream.stream2.is_some());
        assert_eq!(stream.stream2.as_ref().unwrap().bitstream, &[0xAA, 0xBB]);
    }

    #[test]
    fn avc444_lc_luma_only() {
        // info: LC=1, cb1=4 → (1 << 30) | 4 = 0x4000_0004
        let mut data = Vec::new();
        data.extend_from_slice(&0x4000_0004u32.to_le_bytes());
        // stream1: metablock with 0 rects
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let stream = decode_avc444_bitmap_stream(&data).unwrap();
        assert_eq!(stream.lc_mode, Avc444LcMode::LumaOnly);
        assert!(stream.stream1.is_some());
        assert!(stream.stream2.is_none());
    }

    #[test]
    fn avc444_lc_chroma_only() {
        // info: LC=2, cb1=4 → (2 << 30) | 4 = 0x8000_0004
        let mut data = Vec::new();
        data.extend_from_slice(&0x8000_0004u32.to_le_bytes());
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let stream = decode_avc444_bitmap_stream(&data).unwrap();
        assert_eq!(stream.lc_mode, Avc444LcMode::ChromaOnly);
        assert!(stream.stream1.is_some());
        assert!(stream.stream2.is_none());
    }

    #[test]
    fn avc444_lc_invalid() {
        // info: LC=3 → (3 << 30) = 0xC000_0000
        let data = 0xC000_0000u32.to_le_bytes();
        assert!(decode_avc444_bitmap_stream(&data).is_err());
    }

    #[test]
    fn avc444_cb1_exceeds_data() {
        // info: LC=0, cb1=9999 — but only 4 bytes of data follow
        let mut data = Vec::new();
        data.extend_from_slice(&9999u32.to_le_bytes()); // LC=0, cb1=9999
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert!(decode_avc444_bitmap_stream(&data).is_err());
    }

    #[test]
    fn avc444_lc_both_cb1_zero() {
        // LC=0, cb1=0 → stream1 absent, stream2 = rest
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000_0000u32.to_le_bytes()); // LC=0, cb1=0
        // stream2: metablock with 0 rects
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let stream = decode_avc444_bitmap_stream(&data).unwrap();
        assert_eq!(stream.lc_mode, Avc444LcMode::Both);
        assert!(stream.stream1.is_none());
        assert!(stream.stream2.is_some());
    }

    #[test]
    fn avc444_lc_luma_cb1_zero() {
        // LC=1, cb1=0 → stream1 absent
        let data = 0x4000_0000u32.to_le_bytes(); // LC=1, cb1=0
        let stream = decode_avc444_bitmap_stream(&data).unwrap();
        assert_eq!(stream.lc_mode, Avc444LcMode::LumaOnly);
        assert!(stream.stream1.is_none());
        assert!(stream.stream2.is_none());
    }

    #[test]
    fn reject_too_many_region_rects() {
        let mut data = Vec::new();
        data.extend_from_slice(&(MAX_REGION_RECTS + 1).to_le_bytes());
        let mut src = ReadCursor::new(&data);
        assert!(Avc420MetaBlock::decode(&mut src).is_err());
    }

    #[test]
    fn avc420_bitmap_stream_too_short() {
        let data = [0x00, 0x00]; // < 4 bytes
        assert!(decode_avc420_bitmap_stream(&data).is_err());
    }

    #[test]
    fn avc444_data_too_short() {
        let data = [0x00, 0x00]; // < 4 bytes
        assert!(decode_avc444_bitmap_stream(&data).is_err());
    }

    #[test]
    fn avc444_lc_both_both_absent() {
        // LC=0, cb1=0, no remaining data → both streams None
        let data = 0x0000_0000u32.to_le_bytes(); // LC=0, cb1=0
        let stream = decode_avc444_bitmap_stream(&data).unwrap();
        assert_eq!(stream.lc_mode, Avc444LcMode::Both);
        assert!(stream.stream1.is_none());
        assert!(stream.stream2.is_none());
    }

    #[test]
    fn reject_inverted_rect() {
        // numRegionRects=1, rect with right < left
        let data: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, // numRegionRects
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, // left=64, top=0, right=0, bottom=64
            0x1A, 0x50, // quant quality
        ];
        let mut src = ReadCursor::new(data);
        assert!(Avc420MetaBlock::decode(&mut src).is_err());
    }

    #[test]
    fn avc444_info_encoding() {
        // Verify the bitfield encoding matches spec test vectors
        // LC=0, cb1=1000 → 0x000003E8
        let info: u32 = 1000 & AVC444_BITSTREAM1_SIZE_MASK;
        assert_eq!(info.to_le_bytes(), [0xE8, 0x03, 0x00, 0x00]);

        // LC=1, cb1=512 → 0x40000200
        let info: u32 = 512 | (1 << AVC444_LC_SHIFT);
        assert_eq!(info.to_le_bytes(), [0x00, 0x02, 0x00, 0x40]);

        // LC=2, cb1=256 → 0x80000100
        let info: u32 = 256 | (2 << AVC444_LC_SHIFT);
        assert_eq!(info.to_le_bytes(), [0x00, 0x01, 0x00, 0x80]);
    }
}
