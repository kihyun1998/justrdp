#![forbid(unsafe_code)]

//! Rendering: [`FrameSink`] trait + bitmap fast-path dispatcher.
//!
//! S3b ships the rendering surface contract and a minimal decoder for
//! uncompressed 32-bit fast-path bitmap updates — enough to put pixels on
//! a Canvas/WebGL/native target end-to-end. Compressed bitmaps (RLE) and
//! non-32-bit color depths are explicitly surfaced as
//! [`RenderError::Unsupported`] / [`RenderError::CompressedNotSupported`]
//! so embedders see a clean failure mode rather than silent corruption;
//! S3c will plug in `justrdp-graphics::RleDecompressor` and the lower
//! color depths.
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
    /// The fast-path update type isn't handled yet (S3b: only Bitmap).
    Unsupported { update_code: FastPathUpdateType },
    /// `BITMAP_COMPRESSION` is set but the decoder doesn't run RLE yet
    /// (S3c). The embedder can drop the rectangle and continue.
    CompressedNotSupported,
    /// The bitmap announced a color depth other than 32. Lower depths
    /// (15/16/24) need an additional conversion stage that lands in S3c.
    UnsupportedBpp { bits_per_pixel: u16 },
    /// `width * height * bpp` does not match `bitmap_data.len()`.
    SizeMismatch(String),
}

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "render decode: {e}"),
            Self::Unsupported { update_code } => {
                write!(f, "unsupported fast-path update type: {update_code:?}")
            }
            Self::CompressedNotSupported => f.write_str("compressed bitmap (RLE) not yet supported"),
            Self::UnsupportedBpp { bits_per_pixel } => {
                write!(f, "unsupported bits_per_pixel: {bits_per_pixel}")
            }
            Self::SizeMismatch(msg) => write!(f, "size mismatch: {msg}"),
        }
    }
}

impl core::error::Error for RenderError {}

impl From<justrdp_core::DecodeError> for RenderError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Decode(e)
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

/// Decode the fast-path Bitmap Update payload (everything *after* the
/// `updateCode` and `size` fields) into a flat list of top-down BGRA
/// rectangles.
pub fn decode_bitmap_update_fast_path(
    payload: &[u8],
) -> Result<Vec<DecodedRect>, RenderError> {
    let mut cursor = ReadCursor::new(payload);
    let update = TsUpdateBitmapData::decode_fast_path(&mut cursor)?;
    let mut out: Vec<DecodedRect> = Vec::with_capacity(update.rectangles.len());
    for rect in &update.rectangles {
        out.push(decode_rect(rect)?);
    }
    Ok(out)
}

fn decode_rect(rect: &TsBitmapData) -> Result<DecodedRect, RenderError> {
    if rect.flags & BITMAP_COMPRESSION != 0 {
        return Err(RenderError::CompressedNotSupported);
    }
    if rect.bits_per_pixel != 32 {
        return Err(RenderError::UnsupportedBpp {
            bits_per_pixel: rect.bits_per_pixel,
        });
    }
    let bpp_bytes = 4usize;
    let stride = rect.width as usize * bpp_bytes;
    let expected = stride * rect.height as usize;
    if rect.bitmap_data.len() != expected {
        return Err(RenderError::SizeMismatch(format!(
            "expected {} bytes for {}x{} @ 32bpp, got {}",
            expected,
            rect.width,
            rect.height,
            rect.bitmap_data.len()
        )));
    }

    // Single pass: walk wire rows from bottom to top, copying each pixel
    // with B and R swapped (BGRA → RGBA). One memory read pass, one
    // write pass — same cost as a plain copy + flip.
    let mut top_down = Vec::with_capacity(expected);
    for row in (0..rect.height as usize).rev() {
        let row_start = row * stride;
        let row_bytes = &rect.bitmap_data[row_start..row_start + stride];
        for px in row_bytes.chunks_exact(4) {
            top_down.push(px[2]); // R ← wire B-position
            top_down.push(px[1]); // G
            top_down.push(px[0]); // B ← wire R-position
            top_down.push(px[3]); // A
        }
    }

    Ok(DecodedRect {
        dest_left: rect.dest_left,
        dest_top: rect.dest_top,
        width: rect.width,
        height: rect.height,
        pixels_rgba: top_down,
    })
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
    use justrdp_core::{Encode, WriteCursor};
    use justrdp_pdu::rdp::bitmap::TsCdHeader;

    /// Build a fast-path bitmap-update payload with one rectangle.
    fn build_payload(rect: TsBitmapData) -> Vec<u8> {
        let upd = TsUpdateBitmapData {
            rectangles: vec![rect],
        };
        let size = 2 + 14 + upd.rectangles[0].size() - 14; // computed below
        let _ = size; // silence; we use upd.size() via Encode
        // Use the type's own encode_fast_path for safety.
        let mut buf = Vec::new();
        // worst-case allocation
        buf.resize(2 + 64 + upd.rectangles[0].bitmap_data.len() + 16, 0);
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

    #[test]
    fn rejects_compressed_bitmap_until_s3c() {
        let mut rect = uncompressed_32bpp_rect(1, 1, 0x00);
        rect.flags |= BITMAP_COMPRESSION;
        // Compressed flag set with no comp-hdr-omitted flag → wire format
        // requires a TsCdHeader before bitmap_data. We're not actually
        // trying to decode this payload, just confirm the renderer
        // refuses it cleanly. So fabricate the minimal valid wire shape
        // and feed it through.
        rect.compr_hdr = Some(TsCdHeader {
            cb_comp_first_row_size: 0,
            cb_comp_main_body_size: 0,
            cb_scan_width: 0,
            cb_uncompressed_size: 0,
        });
        rect.bitmap_data = vec![]; // empty body; the renderer rejects before parsing it
        let payload = build_payload(rect);
        let err = decode_bitmap_update_fast_path(&payload).unwrap_err();
        assert!(
            matches!(err, RenderError::CompressedNotSupported),
            "expected CompressedNotSupported, got {err:?}"
        );
    }

    #[test]
    fn rejects_non_32bpp() {
        let mut rect = uncompressed_32bpp_rect(1, 1, 0xCC);
        rect.bits_per_pixel = 16;
        rect.bitmap_data = vec![0; 2]; // 1 px @ 16bpp = 2 bytes
        let payload = build_payload(rect);
        let err = decode_bitmap_update_fast_path(&payload).unwrap_err();
        assert!(
            matches!(err, RenderError::UnsupportedBpp { bits_per_pixel: 16 }),
            "expected UnsupportedBpp(16), got {err:?}"
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
}
