//! Slow-path graphics Update PDUs (MS-RDPBCGR 2.2.9.1.1.3.1) — the Share Data PDU bodies
//! (`pduType2` = [`crate::share::PDU_TYPE2_UPDATE`]) that carry bitmap rectangles and palette
//! changes. Decode only: these flow server → client.

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `updateType`: orders (drawing orders — skipped until the orders epic).
pub const UPDATETYPE_ORDERS: u16 = 0x0000;
/// `updateType`: bitmap rectangles.
pub const UPDATETYPE_BITMAP: u16 = 0x0001;
/// `updateType`: palette.
pub const UPDATETYPE_PALETTE: u16 = 0x0002;
/// `updateType`: synchronize (no payload; a no-op for clients).
pub const UPDATETYPE_SYNCHRONIZE: u16 = 0x0003;

/// `TS_BITMAP_DATA.flags`: the bitmap data is compressed.
pub const BITMAP_COMPRESSION: u16 = 0x0001;
/// `TS_BITMAP_DATA.flags`: no `TS_CD_HEADER` precedes the compressed data (set by servers
/// when the client advertised `NO_BITMAP_COMPRESSION_HDR` in its General capability set).
pub const NO_BITMAP_COMPRESSION_HDR: u16 = 0x0400;

/// One bitmap rectangle (TS_BITMAP_DATA, 2.2.9.1.1.3.1.2.2). The destination rectangle is
/// inclusive (`right`/`bottom` are the last column/row); `width`/`height` are the dimensions
/// of the carried bitmap, which may overhang the destination by up to 3 pixels of padding on
/// the right/bottom (legacy 4-pixel alignment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapData {
    /// `destLeft`.
    pub left: u16,
    /// `destTop`.
    pub top: u16,
    /// `destRight` (inclusive).
    pub right: u16,
    /// `destBottom` (inclusive).
    pub bottom: u16,
    /// `width` of the carried bitmap.
    pub width: u16,
    /// `height` of the carried bitmap.
    pub height: u16,
    /// `bitsPerPixel` of the carried bitmap (8/15/16/24/32).
    pub bits_per_pixel: u16,
    /// True when [`BITMAP_COMPRESSION`] is set: 8–24 bpp data is interleaved RLE, 32 bpp is
    /// RDP6 planar (MS-RDPBCGR 2.2.9.1.1.3.1.2.2 `bitmapDataStream`).
    pub compressed: bool,
    /// The bitmap bytes (any `TS_CD_HEADER` already stripped — its fields are redundant).
    pub data: Vec<u8>,
}

/// A decoded Bitmap Update (TS_UPDATE_BITMAP_DATA, 2.2.9.1.1.3.1.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapUpdate {
    /// `rectangles`, in wire order (the server paints them first to last).
    pub rectangles: Vec<BitmapData>,
}

impl BitmapUpdate {
    /// Decode the body following the `updateType` field (which the caller has already read
    /// and matched against [`UPDATETYPE_BITMAP`]).
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let count = cur.read_u16_le()? as usize;
        let mut rectangles = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let left = cur.read_u16_le()?;
            let top = cur.read_u16_le()?;
            let right = cur.read_u16_le()?;
            let bottom = cur.read_u16_le()?;
            let width = cur.read_u16_le()?;
            let height = cur.read_u16_le()?;
            let bits_per_pixel = cur.read_u16_le()?;
            let flags = cur.read_u16_le()?;
            let mut length = cur.read_u16_le()? as usize;

            let compressed = flags & BITMAP_COMPRESSION != 0;
            if compressed && flags & NO_BITMAP_COMPRESSION_HDR == 0 {
                // TS_CD_HEADER (8 bytes): all four fields restate what the bitmap header
                // already says, so it is validated for size and dropped.
                if length < 8 {
                    return Err(DecodeError::InvalidField {
                        field: "TS_BITMAP_DATA.bitmapLength",
                        reason: "compressed data shorter than its TS_CD_HEADER",
                    });
                }
                cur.read_u16_le()?; // cbCompFirstRowSize (MUST be 0)
                let main_body = cur.read_u16_le()? as usize;
                cur.read_u16_le()?; // cbScanWidth
                cur.read_u16_le()?; // cbUncompressedSize
                length = main_body.min(length - 8);
            }
            let data = cur.read_slice(length)?.to_vec();
            if width == 0 || height == 0 {
                return Err(DecodeError::InvalidField {
                    field: "TS_BITMAP_DATA",
                    reason: "zero-sized bitmap rectangle",
                });
            }
            rectangles.push(BitmapData {
                left,
                top,
                right,
                bottom,
                width,
                height,
                bits_per_pixel,
                compressed,
                data,
            });
        }
        Ok(Self { rectangles })
    }
}

/// A decoded Palette Update (TS_UPDATE_PALETTE_DATA, 2.2.9.1.1.3.1.1): 256 RGB entries that
/// replace the current palette for subsequent 8-bpp bitmap data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaletteUpdate {
    /// `paletteEntries` as `[r, g, b]`.
    pub entries: [[u8; 3]; 256],
}

impl PaletteUpdate {
    /// Decode the body following the `updateType` field.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        cur.read_u16_le()?; // pad2Octets
        let count = cur.read_u32_le()? as usize;
        if count != 256 {
            return Err(DecodeError::InvalidField {
                field: "TS_UPDATE_PALETTE_DATA.numberColors",
                reason: "palette updates must carry exactly 256 colors",
            });
        }
        let mut entries = [[0u8; 3]; 256];
        for entry in &mut entries {
            entry.copy_from_slice(cur.read_slice(3)?);
        }
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect_bytes(flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for v in [0u16, 0, 3, 1, 4, 2, 16, flags, payload.len() as u16] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn bitmap_update_without_compression_header() {
        let mut body = 1u16.to_le_bytes().to_vec(); // numberRectangles
        body.extend_from_slice(&rect_bytes(
            BITMAP_COMPRESSION | NO_BITMAP_COMPRESSION_HDR,
            &[0xAA; 10],
        ));
        let mut cur = ReadCursor::new(&body, "test");
        let update = BitmapUpdate::decode(&mut cur).unwrap();
        assert_eq!(cur.remaining(), 0);
        let rect = &update.rectangles[0];
        assert_eq!((rect.right, rect.bottom), (3, 1));
        assert_eq!((rect.width, rect.height, rect.bits_per_pixel), (4, 2, 16));
        assert!(rect.compressed);
        assert_eq!(rect.data, vec![0xAA; 10]);
    }

    #[test]
    fn bitmap_update_strips_the_cd_header() {
        // TS_CD_HEADER: firstRow 0, mainBody 6, scanWidth 8, uncompressed 16 — then 6 bytes.
        let mut payload = Vec::new();
        for v in [0u16, 6, 8, 16] {
            payload.extend_from_slice(&v.to_le_bytes());
        }
        payload.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend_from_slice(&rect_bytes(BITMAP_COMPRESSION, &payload));
        let mut cur = ReadCursor::new(&body, "test");
        let update = BitmapUpdate::decode(&mut cur).unwrap();
        assert_eq!(update.rectangles[0].data, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn uncompressed_rectangle_keeps_raw_bytes() {
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend_from_slice(&rect_bytes(0, &[7; 16]));
        let mut cur = ReadCursor::new(&body, "test");
        let update = BitmapUpdate::decode(&mut cur).unwrap();
        assert!(!update.rectangles[0].compressed);
        assert_eq!(update.rectangles[0].data.len(), 16);
    }

    #[test]
    fn palette_update_decodes_256_entries() {
        let mut body = 0u16.to_le_bytes().to_vec();
        body.extend_from_slice(&256u32.to_le_bytes());
        for i in 0..256usize {
            body.extend_from_slice(&[i as u8, 1, 2]);
        }
        let mut cur = ReadCursor::new(&body, "test");
        let palette = PaletteUpdate::decode(&mut cur).unwrap();
        assert_eq!(palette.entries[0], [0, 1, 2]);
        assert_eq!(palette.entries[255], [255, 1, 2]);
    }

    #[test]
    fn malformed_updates_are_typed_errors() {
        // Palette with the wrong color count.
        let mut body = 0u16.to_le_bytes().to_vec();
        body.extend_from_slice(&16u32.to_le_bytes());
        let mut cur = ReadCursor::new(&body, "test");
        assert!(matches!(
            PaletteUpdate::decode(&mut cur),
            Err(DecodeError::InvalidField { .. })
        ));
        // Bitmap rectangle whose length overruns the buffer.
        let mut body = 1u16.to_le_bytes().to_vec();
        let mut rect = rect_bytes(0, &[1, 2, 3]);
        rect.truncate(rect.len() - 2); // cut payload short
        body.extend_from_slice(&rect);
        let mut cur = ReadCursor::new(&body, "test");
        assert!(BitmapUpdate::decode(&mut cur).is_err());
    }
}
