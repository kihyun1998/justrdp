#![forbid(unsafe_code)]

//! Rendering: [`FrameSink`] trait + bitmap fast-path dispatcher.
//!
//! Supported bitmap inputs:
//! * Uncompressed 32 bpp BGRA (S3b).
//! * Uncompressed and **Interleaved RLE** compressed 24 bpp (BGR), 16 bpp
//!   (RGB565), and 15 bpp (RGB555) — added in S3c via
//!   [`justrdp_graphics::RleDecompressor`]. After decompression each bpp
//!   variant is converted to top-down RGBA in a single pass.
//! * 8 bpp (palette-indexed) and Planar/RemoteFX/NSCodec/AVC are still
//!   surfaced as typed errors and left for later steps.
//!
//! # Wire → sink conversions, in one pass
//!
//! RDP fast-path bitmap rectangles are **bottom-up DIBs** — the first
//! `width * (bpp/8)` bytes of the wire data describe the *bottom* row of
//! the destination rectangle. The wire byte order is **BGRA**, while the
//! `ImageData` API used by `<canvas>` expects **RGBA**.
//! [`decode_bitmap_update_fast_path`] does both — row flip and B/R swap —
//! in a single pass so [`FrameSink`] implementors get top-down RGBA
//! pixels ready to hand to a Canvas/WebGL/wgpu surface without an extra
//! conversion stage.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::ReadCursor;
use justrdp_graphics::{BitsPerPixel, RleDecompressor, RleError};
use justrdp_pdu::rdp::bitmap::{
    TsBitmapData, TsUpdateBitmapData, BITMAP_COMPRESSION,
};
use justrdp_pdu::rdp::fast_path::FastPathUpdateType;

use crate::session::SessionEvent;

/// Render-side failure modes.
#[derive(Debug)]
pub enum RenderError {
    /// The wire payload could not be decoded.
    Decode(justrdp_core::DecodeError),
    /// The fast-path update type isn't handled yet.
    Unsupported { update_code: FastPathUpdateType },
    /// The bitmap announced a color depth this crate does not convert.
    UnsupportedBpp { bits_per_pixel: u16 },
    /// `width * height * bpp` does not match `bitmap_data.len()` for the
    /// uncompressed path, or a Palette PDU was malformed.
    SizeMismatch(String),
    /// RLE decompression failed.
    Rle(RleError),
    /// An 8 bpp Bitmap arrived before a Palette update — the renderer
    /// has no table to convert the indices with.
    PaletteMissing,
}

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "render decode: {e}"),
            Self::Unsupported { update_code } => {
                write!(f, "unsupported fast-path update type: {update_code:?}")
            }
            Self::UnsupportedBpp { bits_per_pixel } => {
                write!(f, "unsupported bits_per_pixel: {bits_per_pixel}")
            }
            Self::SizeMismatch(msg) => write!(f, "size mismatch: {msg}"),
            Self::Rle(e) => write!(f, "RLE decompress: {e}"),
            Self::PaletteMissing => f.write_str("8 bpp bitmap arrived before any Palette update"),
        }
    }
}

impl core::error::Error for RenderError {}

impl From<justrdp_core::DecodeError> for RenderError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<RleError> for RenderError {
    fn from(e: RleError) -> Self {
        Self::Rle(e)
    }
}

/// One decoded rectangle, ready to hand to a [`FrameSink`].
///
/// `pixels_rgba` is top-down packed RGBA, length = `width * height * 4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRect {
    pub dest_left: u16,
    pub dest_top: u16,
    pub width: u16,
    pub height: u16,
    pub pixels_rgba: Vec<u8>,
}

/// Render target.
///
/// `blit_rgba` receives top-down packed RGBA, the same byte order
/// `<canvas>` `ImageData` and most GPU APIs (WebGL `RGBA`/`UNSIGNED_BYTE`,
/// wgpu `Rgba8Unorm`, vulkan `R8G8B8A8_UNORM`) expect. `(dest_left,
/// dest_top)` is the inclusive top-left corner in desktop coordinates;
/// the blit covers `(dest_left .. dest_left + width)` ×
/// `(dest_top .. dest_top + height)`.
///
/// All methods default-impl as no-ops *except* `blit_rgba`, so a sink
/// that only cares about pixels can elide the rest.
pub trait FrameSink {
    /// Optional: server announced new desktop dimensions.
    fn resize(&mut self, _width: u16, _height: u16) {}

    /// Blit a top-down RGBA rectangle into the surface.
    fn blit_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        pixels_rgba: &[u8],
    );

    /// Optional: end of an update batch — useful for sinks that buffer
    /// blits to amortize draw calls.
    fn flush(&mut self) {}
}

/// Number of palette entries in a TS_UPDATE_PALETTE PDU (always 256 per
/// MS-RDPBCGR 2.2.9.1.1.3.1.1.1).
const PALETTE_ENTRY_COUNT: usize = 256;

/// Stateful renderer.
///
/// Holds protocol state that survives across update batches — currently
/// the 8 bpp palette table; later steps will add codec contexts (RFX
/// tile cache, NSCodec quantization tables, …). Use one instance per
/// session; reusing across sessions risks decoding new traffic against
/// stale palette/codec state.
#[derive(Debug, Clone)]
pub struct BitmapRenderer {
    palette: Option<[(u8, u8, u8); PALETTE_ENTRY_COUNT]>,
}

impl Default for BitmapRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl BitmapRenderer {
    pub const fn new() -> Self {
        Self { palette: None }
    }

    /// Whether the server has sent a Palette update yet. 8 bpp bitmaps
    /// before the first palette will fail with [`RenderError::PaletteMissing`].
    pub fn has_palette(&self) -> bool {
        self.palette.is_some()
    }

    /// Apply one [`SessionEvent`] to a [`FrameSink`], updating internal
    /// state as needed. Returns `Ok(true)` if any pixels were drawn,
    /// `Ok(false)` for plumbing-only events (palette/synchronize/etc.).
    pub fn render<S: FrameSink>(
        &mut self,
        event: &SessionEvent,
        sink: &mut S,
    ) -> Result<bool, RenderError> {
        let SessionEvent::Graphics { update_code, data } = event else {
            return Ok(false);
        };

        match update_code {
            FastPathUpdateType::Palette => {
                self.update_palette(data)?;
                Ok(false)
            }
            FastPathUpdateType::Bitmap => {
                let rects = self.decode_bitmap_rects(data)?;
                let any = !rects.is_empty();
                for r in rects {
                    sink.blit_rgba(
                        r.dest_left,
                        r.dest_top,
                        r.width,
                        r.height,
                        &r.pixels_rgba,
                    );
                }
                if any {
                    sink.flush();
                }
                Ok(any)
            }
            // Surface Commands and the Synchronize tick are accepted but
            // not yet rendered (Surface Commands lands in S3d-2). They
            // are *not* errors — the embedder generally just keeps
            // pumping events.
            FastPathUpdateType::Synchronize | FastPathUpdateType::SurfaceCommands => Ok(false),
            other => Err(RenderError::Unsupported {
                update_code: *other,
            }),
        }
    }

    fn decode_bitmap_rects(&self, payload: &[u8]) -> Result<Vec<DecodedRect>, RenderError> {
        let mut cursor = ReadCursor::new(payload);
        let update = TsUpdateBitmapData::decode_fast_path(&mut cursor)?;
        let mut out: Vec<DecodedRect> = Vec::with_capacity(update.rectangles.len());
        for rect in &update.rectangles {
            out.push(decode_rect(rect, self.palette.as_ref())?);
        }
        Ok(out)
    }

    /// Decode a fast-path Palette update body and cache the result.
    ///
    /// Wire layout (MS-RDPBCGR 2.2.9.1.2.1.1.1):
    ///   pad2Octets   : u16 (skipped)
    ///   numberColors : u32 LE (must be 256)
    ///   paletteData  : 256 × 3 bytes (R, G, B per entry)
    fn update_palette(&mut self, data: &[u8]) -> Result<(), RenderError> {
        const HEADER_SIZE: usize = 2 + 4;
        if data.len() < HEADER_SIZE {
            return Err(RenderError::SizeMismatch(format!(
                "palette PDU truncated: got {} bytes, need at least {}",
                data.len(),
                HEADER_SIZE
            )));
        }
        let n = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
        if n != PALETTE_ENTRY_COUNT {
            return Err(RenderError::SizeMismatch(format!(
                "palette numberColors = {n}, expected {PALETTE_ENTRY_COUNT}"
            )));
        }
        let body_size = PALETTE_ENTRY_COUNT * 3;
        if data.len() < HEADER_SIZE + body_size {
            return Err(RenderError::SizeMismatch(format!(
                "palette body short: got {} bytes, need {}",
                data.len() - HEADER_SIZE,
                body_size
            )));
        }
        let mut pal = [(0u8, 0u8, 0u8); PALETTE_ENTRY_COUNT];
        for (i, slot) in pal.iter_mut().enumerate() {
            let off = HEADER_SIZE + i * 3;
            *slot = (data[off], data[off + 1], data[off + 2]);
        }
        self.palette = Some(pal);
        Ok(())
    }
}

/// Decode the fast-path Bitmap Update payload (everything *after* the
/// `updateCode` and `size` fields) into a flat list of top-down RGBA
/// rectangles. Stateless — for 8 bpp bitmaps you must use
/// [`BitmapRenderer`] instead so a Palette update can be cached first.
pub fn decode_bitmap_update_fast_path(
    payload: &[u8],
) -> Result<Vec<DecodedRect>, RenderError> {
    let mut cursor = ReadCursor::new(payload);
    let update = TsUpdateBitmapData::decode_fast_path(&mut cursor)?;
    let mut out: Vec<DecodedRect> = Vec::with_capacity(update.rectangles.len());
    for rect in &update.rectangles {
        out.push(decode_rect(rect, None)?);
    }
    Ok(out)
}

fn decode_rect(
    rect: &TsBitmapData,
    palette: Option<&[(u8, u8, u8); PALETTE_ENTRY_COUNT]>,
) -> Result<DecodedRect, RenderError> {
    let compressed = rect.flags & BITMAP_COMPRESSION != 0;

    // Stage 1: get raw bottom-up pixels at the source bpp.
    let raw_pixels: Vec<u8>;
    let raw_slice: &[u8];
    if compressed {
        let bpp = BitsPerPixel::from_raw(rect.bits_per_pixel).ok_or(
            RenderError::UnsupportedBpp {
                bits_per_pixel: rect.bits_per_pixel,
            },
        )?;
        let mut out = Vec::new();
        RleDecompressor::new()
            .decompress(&rect.bitmap_data, rect.width, rect.height, bpp, &mut out)?;
        raw_pixels = out;
        raw_slice = &raw_pixels;
    } else {
        let bpp_bytes = bpp_byte_size(rect.bits_per_pixel)?;
        let stride = rect.width as usize * bpp_bytes;
        let expected = stride * rect.height as usize;
        if rect.bitmap_data.len() != expected {
            return Err(RenderError::SizeMismatch(format!(
                "expected {} bytes for {}x{} @ {}bpp, got {}",
                expected,
                rect.width,
                rect.height,
                rect.bits_per_pixel,
                rect.bitmap_data.len()
            )));
        }
        raw_slice = &rect.bitmap_data;
    }

    // Stage 2: bottom-up source bpp → top-down RGBA, single pass.
    let pixels_rgba = match rect.bits_per_pixel {
        32 => flip_and_swap_32bpp(raw_slice, rect.width, rect.height),
        24 => flip_and_swap_24bpp(raw_slice, rect.width, rect.height),
        16 => flip_and_convert_rgb565(raw_slice, rect.width, rect.height),
        15 => flip_and_convert_rgb555(raw_slice, rect.width, rect.height),
        8 => {
            let pal = palette.ok_or(RenderError::PaletteMissing)?;
            flip_and_apply_palette(raw_slice, rect.width, rect.height, pal)
        }
        other => {
            return Err(RenderError::UnsupportedBpp {
                bits_per_pixel: other,
            });
        }
    };

    Ok(DecodedRect {
        dest_left: rect.dest_left,
        dest_top: rect.dest_top,
        width: rect.width,
        height: rect.height,
        pixels_rgba,
    })
}

/// Source-bpp byte width. Only the bpps we render here are accepted; the
/// rest are surfaced via `UnsupportedBpp` upstream.
fn bpp_byte_size(bpp: u16) -> Result<usize, RenderError> {
    match bpp {
        8 => Ok(1),
        15 | 16 => Ok(2),
        24 => Ok(3),
        32 => Ok(4),
        other => Err(RenderError::UnsupportedBpp {
            bits_per_pixel: other,
        }),
    }
}

/// Bottom-up 8 bpp indexed → top-down RGBA via the cached palette.
fn flip_and_apply_palette(
    src: &[u8],
    width: u16,
    height: u16,
    palette: &[(u8, u8, u8); PALETTE_ENTRY_COUNT],
) -> Vec<u8> {
    let stride = width as usize;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for &idx in row_bytes {
            let (r, g, b) = palette[idx as usize];
            out.push(r);
            out.push(g);
            out.push(b);
            out.push(0xFF);
        }
    }
    out
}

/// Bottom-up BGRA → top-down RGBA.
fn flip_and_swap_32bpp(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 4;
    let mut out = Vec::with_capacity(stride * height as usize);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(4) {
            out.push(px[2]); // R ← wire B
            out.push(px[1]); // G
            out.push(px[0]); // B ← wire R
            out.push(px[3]); // A
        }
    }
    out
}

/// Bottom-up BGR → top-down RGBA (alpha = 0xFF).
fn flip_and_swap_24bpp(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 3;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(3) {
            out.push(px[2]); // R ← wire B
            out.push(px[1]); // G
            out.push(px[0]); // B ← wire R
            out.push(0xFF);
        }
    }
    out
}

/// Bottom-up RGB565 (LE u16) → top-down RGBA (alpha = 0xFF).
///
/// Bit layout per spec: `RRRRR GGGGGG BBBBB` packed into a little-endian
/// 16-bit word. Channel expansion uses bit replication so the brightest
/// 5/6-bit value maps exactly to 0xFF.
fn flip_and_convert_rgb565(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 2;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(2) {
            let v = u16::from_le_bytes([px[0], px[1]]);
            let r5 = ((v >> 11) & 0x1F) as u8;
            let g6 = ((v >> 5) & 0x3F) as u8;
            let b5 = (v & 0x1F) as u8;
            out.push((r5 << 3) | (r5 >> 2));
            out.push((g6 << 2) | (g6 >> 4));
            out.push((b5 << 3) | (b5 >> 2));
            out.push(0xFF);
        }
    }
    out
}

/// Bottom-up RGB555 (LE u16) → top-down RGBA (alpha = 0xFF).
fn flip_and_convert_rgb555(src: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stride = width as usize * 2;
    let mut out = Vec::with_capacity(width as usize * height as usize * 4);
    for row in (0..height as usize).rev() {
        let row_bytes = &src[row * stride..(row + 1) * stride];
        for px in row_bytes.chunks_exact(2) {
            let v = u16::from_le_bytes([px[0], px[1]]);
            let r5 = ((v >> 10) & 0x1F) as u8;
            let g5 = ((v >> 5) & 0x1F) as u8;
            let b5 = (v & 0x1F) as u8;
            out.push((r5 << 3) | (r5 >> 2));
            out.push((g5 << 3) | (g5 >> 2));
            out.push((b5 << 3) | (b5 >> 2));
            out.push(0xFF);
        }
    }
    out
}

/// Apply one [`SessionEvent`] to a [`FrameSink`].
///
/// Returns `Ok(true)` if the event produced any output (Bitmap update),
/// `Ok(false)` if the event was non-graphical or has no rectangles. Errors
/// surface as-is so the embedder can decide whether to log+drop or abort.
pub fn render_event<S: FrameSink>(
    event: &SessionEvent,
    sink: &mut S,
) -> Result<bool, RenderError> {
    let SessionEvent::Graphics { update_code, data } = event else {
        return Ok(false);
    };

    match update_code {
        FastPathUpdateType::Bitmap => {
            let rects = decode_bitmap_update_fast_path(data)?;
            let any = !rects.is_empty();
            for r in rects {
                sink.blit_rgba(
                    r.dest_left,
                    r.dest_top,
                    r.width,
                    r.height,
                    &r.pixels_rgba,
                );
            }
            if any {
                sink.flush();
            }
            Ok(any)
        }
        // Synchronize / Surface / Orders / Pointer / etc. — silently
        // accepted as "no pixels to draw"; the embedder doesn't need a
        // separate "ignored" surface yet.
        FastPathUpdateType::Synchronize | FastPathUpdateType::SurfaceCommands => Ok(false),
        other => Err(RenderError::Unsupported {
            update_code: *other,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_core::WriteCursor;

    /// Build a fast-path bitmap-update payload with one rectangle.
    fn build_payload(rect: TsBitmapData) -> Vec<u8> {
        let upd = TsUpdateBitmapData {
            rectangles: vec![rect],
        };
        // Worst-case allocation: number_rectangles (u16) + per-rect fixed
        // header (18 bytes) + comp-hdr (8 bytes) + variable bitmap_data.
        let mut buf = vec![0u8; 2 + 32 + upd.rectangles[0].bitmap_data.len() + 16];
        let mut cursor = WriteCursor::new(&mut buf);
        upd.encode_fast_path(&mut cursor).unwrap();
        let written = cursor.pos();
        buf.truncate(written);
        buf
    }

    fn uncompressed_32bpp_rect(width: u16, height: u16, fill: u8) -> TsBitmapData {
        let stride = width as usize * 4;
        let bytes = stride * height as usize;
        let mut data = vec![fill; bytes];
        // Tag the bottom row so we can verify the flip.
        for col in 0..stride.min(8) {
            data[col] = 0xAA;
        }
        TsBitmapData {
            dest_left: 10,
            dest_top: 20,
            dest_right: 10 + width - 1,
            dest_bottom: 20 + height - 1,
            width,
            height,
            bits_per_pixel: 32,
            flags: 0,
            compr_hdr: None,
            bitmap_data: data,
        }
    }

    /// Capture-only [`FrameSink`] used in tests.
    struct Capture {
        resizes: Vec<(u16, u16)>,
        blits: Vec<(u16, u16, u16, u16, Vec<u8>)>,
        flushes: u32,
    }

    impl Capture {
        fn new() -> Self {
            Self {
                resizes: Vec::new(),
                blits: Vec::new(),
                flushes: 0,
            }
        }
    }

    impl FrameSink for Capture {
        fn resize(&mut self, w: u16, h: u16) {
            self.resizes.push((w, h));
        }
        fn blit_rgba(
            &mut self,
            x: u16,
            y: u16,
            w: u16,
            h: u16,
            pixels: &[u8],
        ) {
            self.blits.push((x, y, w, h, pixels.to_vec()));
        }
        fn flush(&mut self) {
            self.flushes += 1;
        }
    }

    #[test]
    fn decodes_uncompressed_32bpp_flips_and_swaps_to_rgba() {
        // Build a 2×3 rect where every wire pixel has a distinct B value
        // so we can spot a missed B/R swap. Wire layout BGRA, all rows
        // pre-filled with [0x11, 0x22, 0x33, 0xFF] = (B,G,R,A).
        let mut rect = uncompressed_32bpp_rect(2, 3, 0x00);
        let pattern = [0x11u8, 0x22, 0x33, 0xFF];
        for px in rect.bitmap_data.chunks_exact_mut(4) {
            px.copy_from_slice(&pattern);
        }
        // Tag the *bottom* wire row (first on the wire) so we can
        // verify the row flip put it at the top-down bottom.
        let stride_bytes = rect.width as usize * 4;
        for col in 0..stride_bytes {
            rect.bitmap_data[col] = 0xAA;
        }

        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        let r = &rects[0];
        assert_eq!((r.dest_left, r.dest_top, r.width, r.height), (10, 20, 2, 3));

        // RGBA byte-order check on a non-tagged row: wire BGRA = (0x11,
        // 0x22, 0x33, 0xFF) must arrive as RGBA = (0x33, 0x22, 0x11, 0xFF).
        // Pick the *first* top-down row (which on the wire was the *last*).
        assert_eq!(&r.pixels_rgba[0..4], &[0x33, 0x22, 0x11, 0xFF]);
        // The last top-down row has the wire-bottom tag (all 0xAA bytes),
        // and 0xAA is symmetric under the B↔R swap.
        let last_row = stride_bytes * (3 - 1);
        for col in 0..stride_bytes {
            assert_eq!(r.pixels_rgba[last_row + col], 0xAA);
        }
    }

    /// The stateless `decode_bitmap_update_fast_path` cannot resolve 8
    /// bpp pixels because it has no palette table. Confirm the typed
    /// error so the embedder can route the caller to BitmapRenderer
    /// instead.
    #[test]
    fn stateless_decode_8bpp_reports_palette_missing() {
        let mut rect = uncompressed_32bpp_rect(1, 1, 0xCC);
        rect.bits_per_pixel = 8;
        rect.bitmap_data = vec![0]; // 1 px @ 8bpp = 1 byte
        let payload = build_payload(rect);
        let err = decode_bitmap_update_fast_path(&payload).unwrap_err();
        assert!(
            matches!(err, RenderError::PaletteMissing),
            "expected PaletteMissing, got {err:?}"
        );
    }

    /// Uncompressed RGB565: a single pixel with all five red bits set,
    /// no green, no blue. Round-trip the bit-replication expansion so a
    /// regression in the bit-shift order would flip the channel.
    #[test]
    fn decodes_uncompressed_rgb565_with_bit_replication() {
        // RGB565 wire word = 0xF800 (LE: 0x00, 0xF8) = R=0x1F, G=0, B=0
        // Bit-replicated 5→8: r5=0x1F → (0x1F<<3) | (0x1F>>2) = 0xFF
        let mut rect = uncompressed_32bpp_rect(1, 1, 0);
        rect.bits_per_pixel = 16;
        rect.bitmap_data = vec![0x00, 0xF8];
        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        assert_eq!(&rects[0].pixels_rgba, &[0xFF, 0x00, 0x00, 0xFF]);
    }

    /// Uncompressed RGB555 + alpha pin to 0xFF.
    #[test]
    fn decodes_uncompressed_rgb555() {
        // RGB555 wire word = 0x7C00 (LE: 0x00, 0x7C) = R=0x1F, G=0, B=0
        let mut rect = uncompressed_32bpp_rect(1, 1, 0);
        rect.bits_per_pixel = 15;
        rect.bitmap_data = vec![0x00, 0x7C];
        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        assert_eq!(&rects[0].pixels_rgba, &[0xFF, 0x00, 0x00, 0xFF]);
    }

    /// Uncompressed 24 bpp BGR — one pixel, channel-distinguishable.
    #[test]
    fn decodes_uncompressed_24bpp_swaps_b_and_r() {
        let mut rect = uncompressed_32bpp_rect(1, 1, 0);
        rect.bits_per_pixel = 24;
        rect.bitmap_data = vec![0x11, 0x22, 0x33]; // wire BGR
        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        assert_eq!(&rects[0].pixels_rgba, &[0x33, 0x22, 0x11, 0xFF]);
    }

    /// Round-trip through `RleDecompressor`: encode a 2×1 16 bpp pattern
    /// as a single FOREGROUND/BACKGROUND run via the SPECIAL_WHITE order
    /// and verify the renderer threads it through the RLE branch and
    /// out the RGB565 converter.
    ///
    /// The simplest RLE program that fills a row is the WHITE single-byte
    /// special order (0xFD) which writes one *white* pixel. Two of them
    /// fill a 2×1 row.
    #[test]
    fn decodes_compressed_rle_16bpp_via_white_special_orders() {
        // RLE program: [WHITE, WHITE]. Each pushes one bpp16 white pixel
        // (= 0xFFFF). bitmap_length is omitted: NO_BITMAP_COMPRESSION_HDR
        // keeps the on-wire shape minimal so the test isn't tied to the
        // 8-byte compression header layout.
        let mut rect = uncompressed_32bpp_rect(2, 1, 0);
        rect.bits_per_pixel = 16;
        rect.flags = BITMAP_COMPRESSION | justrdp_pdu::rdp::bitmap::NO_BITMAP_COMPRESSION_HDR;
        rect.compr_hdr = None;
        rect.bitmap_data = vec![0xFD, 0xFD];
        let payload = build_payload(rect);
        let rects = decode_bitmap_update_fast_path(&payload).unwrap();
        assert_eq!(rects.len(), 1);
        // 0xFFFF in RGB565 → R=0x1F, G=0x3F, B=0x1F → (0xFF, 0xFF, 0xFF) RGBA.
        assert_eq!(
            &rects[0].pixels_rgba,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    /// Compressed bitmaps with malformed RLE streams must surface as
    /// `RenderError::Rle(...)`, *not* as a panic or generic decode error.
    #[test]
    fn surfaces_rle_decompression_errors() {
        let mut rect = uncompressed_32bpp_rect(2, 1, 0);
        rect.bits_per_pixel = 16;
        rect.flags = BITMAP_COMPRESSION | justrdp_pdu::rdp::bitmap::NO_BITMAP_COMPRESSION_HDR;
        rect.compr_hdr = None;
        // 0xFC is reserved and the decompressor flags it as
        // UnknownOrderCode — perfect canary for the error path.
        rect.bitmap_data = vec![0xFC];
        let payload = build_payload(rect);
        let err = decode_bitmap_update_fast_path(&payload).unwrap_err();
        assert!(
            matches!(err, RenderError::Rle(_)),
            "expected RenderError::Rle, got {err:?}"
        );
    }

    #[test]
    fn render_event_drives_sink_for_bitmap_updates() {
        let rect = uncompressed_32bpp_rect(2, 1, 0x77);
        let payload = build_payload(rect);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Bitmap,
            data: payload,
        };
        let mut sink = Capture::new();
        let any = render_event(&event, &mut sink).unwrap();
        assert!(any);
        assert_eq!(sink.blits.len(), 1);
        assert_eq!(sink.flushes, 1);
        let (x, y, w, h, _) = &sink.blits[0];
        assert_eq!((*x, *y, *w, *h), (10, 20, 2, 1));
    }

    #[test]
    fn render_event_silently_ignores_synchronize() {
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Synchronize,
            data: Vec::new(),
        };
        let mut sink = Capture::new();
        let any = render_event(&event, &mut sink).unwrap();
        assert!(!any, "synchronize is not a draw event");
        assert!(sink.blits.is_empty());
        assert_eq!(sink.flushes, 0);
    }

    #[test]
    fn render_event_returns_false_for_non_graphics_events() {
        let event = SessionEvent::Pointer(crate::PointerEvent::Hidden);
        let mut sink = Capture::new();
        let any = render_event(&event, &mut sink).unwrap();
        assert!(!any);
    }

    #[test]
    fn render_event_surfaces_unsupported_update_type() {
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Orders,
            data: Vec::new(),
        };
        let mut sink = Capture::new();
        let err = render_event(&event, &mut sink).unwrap_err();
        assert!(
            matches!(err, RenderError::Unsupported {
                update_code: FastPathUpdateType::Orders
            }),
            "expected Unsupported(Orders), got {err:?}"
        );
    }

    // ── BitmapRenderer / Palette / 8 bpp ────────────────────────────────

    /// Build a fast-path Palette PDU (TS_FP_UPDATE_PALETTE) where every
    /// entry is `(idx, idx, idx)` — a grayscale ramp — so a 8 bpp test
    /// can map back from any chosen index trivially.
    fn build_grayscale_palette_pdu() -> Vec<u8> {
        let mut data = Vec::with_capacity(2 + 4 + PALETTE_ENTRY_COUNT * 3);
        data.extend_from_slice(&[0, 0]); // pad2Octets
        data.extend_from_slice(&(PALETTE_ENTRY_COUNT as u32).to_le_bytes());
        for i in 0..PALETTE_ENTRY_COUNT {
            data.push(i as u8);
            data.push(i as u8);
            data.push(i as u8);
        }
        data
    }

    fn palette_event() -> SessionEvent {
        SessionEvent::Graphics {
            update_code: FastPathUpdateType::Palette,
            data: build_grayscale_palette_pdu(),
        }
    }

    /// 8 bpp uncompressed bitmap with a known per-row index pattern, plus
    /// a separate row 0 (bottom on the wire) tagged with index 0xCC so
    /// the row flip can be observed.
    fn uncompressed_8bpp_rect(width: u16, height: u16) -> TsBitmapData {
        let total = width as usize * height as usize;
        let mut data = Vec::with_capacity(total);
        // Bottom row (wire row 0) tagged with 0xCC; subsequent rows fill
        // with their wire row index for easy assertions.
        for row in 0..height as usize {
            let value = if row == 0 { 0xCC } else { row as u8 };
            for _ in 0..width as usize {
                data.push(value);
            }
        }
        TsBitmapData {
            dest_left: 0,
            dest_top: 0,
            dest_right: width - 1,
            dest_bottom: height - 1,
            width,
            height,
            bits_per_pixel: 8,
            flags: 0,
            compr_hdr: None,
            bitmap_data: data,
        }
    }

    #[test]
    fn renderer_caches_palette_and_decodes_8bpp_uncompressed() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();

        // Palette first; no draws.
        assert!(!renderer.has_palette());
        let drew = renderer.render(&palette_event(), &mut sink).unwrap();
        assert!(!drew);
        assert!(renderer.has_palette());
        assert!(sink.blits.is_empty());

        // Now an 8 bpp 2×2 bitmap. Wire row 0 (bottom) = 0xCC, wire row
        // 1 (top) = 0x01. Top-down output: row 0 from index 0x01, row 1
        // from index 0xCC. Grayscale palette → R=G=B=index, A=0xFF.
        let rect = uncompressed_8bpp_rect(2, 2);
        let payload = build_payload(rect);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Bitmap,
            data: payload,
        };
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1);
        let (_, _, _, _, pixels) = &sink.blits[0];
        // First top-down pixel comes from index 0x01.
        assert_eq!(&pixels[0..4], &[0x01, 0x01, 0x01, 0xFF]);
        // Last top-down pixel comes from index 0xCC.
        assert_eq!(&pixels[pixels.len() - 4..], &[0xCC, 0xCC, 0xCC, 0xFF]);
    }

    #[test]
    fn renderer_8bpp_without_palette_errors_with_palette_missing() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let rect = uncompressed_8bpp_rect(1, 1);
        let payload = build_payload(rect);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Bitmap,
            data: payload,
        };
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(matches!(err, RenderError::PaletteMissing));
    }

    /// Compressed 8 bpp via the WHITE special order (single-byte 0xFD).
    /// At 8 bpp, "white" is `0xFF`. With the grayscale palette built in
    /// `build_grayscale_palette_pdu`, palette[0xFF] = (0xFF, 0xFF, 0xFF).
    #[test]
    fn renderer_decodes_compressed_8bpp_via_palette() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        renderer.render(&palette_event(), &mut sink).unwrap();

        let mut rect = uncompressed_8bpp_rect(2, 1);
        rect.flags = BITMAP_COMPRESSION | justrdp_pdu::rdp::bitmap::NO_BITMAP_COMPRESSION_HDR;
        rect.compr_hdr = None;
        rect.bitmap_data = vec![0xFD, 0xFD]; // two WHITE specials = 0xFF, 0xFF
        let payload = build_payload(rect);
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Bitmap,
            data: payload,
        };
        let drew = renderer.render(&event, &mut sink).unwrap();
        assert!(drew);
        assert_eq!(sink.blits.len(), 1);
        let pixels = &sink.blits[0].4;
        assert_eq!(
            pixels,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn renderer_rejects_truncated_palette() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let truncated = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Palette,
            data: vec![0, 0, 0, 0], // missing numberColors high bytes + body
        };
        let err = renderer.render(&truncated, &mut sink).unwrap_err();
        assert!(matches!(err, RenderError::SizeMismatch(_)));
        assert!(!renderer.has_palette());
    }

    #[test]
    fn renderer_rejects_palette_with_wrong_color_count() {
        let mut renderer = BitmapRenderer::new();
        let mut sink = Capture::new();
        let mut data = Vec::with_capacity(2 + 4 + 3);
        data.extend_from_slice(&[0, 0]); // pad
        data.extend_from_slice(&1u32.to_le_bytes()); // wrong count
        data.extend_from_slice(&[0, 0, 0]); // 1 entry
        let event = SessionEvent::Graphics {
            update_code: FastPathUpdateType::Palette,
            data,
        };
        let err = renderer.render(&event, &mut sink).unwrap_err();
        assert!(matches!(err, RenderError::SizeMismatch(_)));
    }
}
