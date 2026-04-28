#![forbid(unsafe_code)]

//! Canvas 2D reference [`FrameSink`] implementation.
//!
//! Wasm32 only. Uses `CanvasRenderingContext2d::put_image_data` — the
//! browser path that is universally supported, GPU-accelerated on most
//! platforms, and doesn't require setting up WebGL state. WebGL/WebGPU
//! sinks for high-FPS scenarios are out of scope for S3b but follow the
//! same trait, so they can be added without touching the rest of the
//! crate.
//!
//! `put_image_data` expects RGBA, which is exactly what
//! [`decode_bitmap_update_fast_path`] produces (B↔R swap is handled in
//! the decoder), so blits are a single allocation + JS call per
//! rectangle.
//!
//! [`decode_bitmap_update_fast_path`]: crate::decode_bitmap_update_fast_path
//! [`FrameSink`]: crate::FrameSink

use alloc::vec::Vec;

use wasm_bindgen::{Clamped, JsCast, JsValue};
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement, ImageData};

use crate::render::FrameSink;

/// `<canvas>`-backed [`FrameSink`].
pub struct CanvasFrameSink {
    ctx: CanvasRenderingContext2d,
    /// Re-used scratch buffer so each blit allocates only when the
    /// rectangle is larger than any seen before.
    scratch: Vec<u8>,
    /// Whether to resize the underlying `<canvas>` element when
    /// `resize()` is called. Defaults to `true` — uncommon to want this
    /// off, but JS embedders that style the canvas themselves can flip
    /// it via [`Self::set_auto_resize`].
    auto_resize: bool,
}

impl CanvasFrameSink {
    /// Wrap an existing 2D rendering context.
    pub fn from_context(ctx: CanvasRenderingContext2d) -> Self {
        Self {
            ctx,
            scratch: Vec::new(),
            auto_resize: true,
        }
    }

    /// Convenience: pull a 2D context out of an `<canvas>` element.
    pub fn from_canvas(canvas: &HtmlCanvasElement) -> Result<Self, JsValue> {
        let raw = canvas
            .get_context("2d")?
            .ok_or_else(|| JsValue::from_str("canvas 2d context unavailable"))?;
        let ctx = raw
            .dyn_into::<CanvasRenderingContext2d>()
            .map_err(|_| JsValue::from_str("get_context returned a non-2d context"))?;
        Ok(Self::from_context(ctx))
    }

    pub fn set_auto_resize(&mut self, enabled: bool) {
        self.auto_resize = enabled;
    }
}

impl FrameSink for CanvasFrameSink {
    fn resize(&mut self, width: u16, height: u16) {
        if !self.auto_resize {
            return;
        }
        if let Some(canvas) = self.ctx.canvas() {
            canvas.set_width(width as u32);
            canvas.set_height(height as u32);
        }
    }

    fn blit_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        pixels_rgba: &[u8],
    ) {
        // ImageData::new_with_u8_clamped_array_and_sh wants `&mut [u8]`
        // because the JS side creates a Uint8ClampedArray view that may
        // alias the buffer; copying into our scratch keeps the public
        // FrameSink contract (`&[u8]`) clean.
        self.scratch.clear();
        self.scratch.extend_from_slice(pixels_rgba);
        match ImageData::new_with_u8_clamped_array_and_sh(
            Clamped(&mut self.scratch[..]),
            width as u32,
            height as u32,
        ) {
            Ok(image) => {
                // Failures here are non-fatal — log on the JS console
                // would be intrusive; the embedder can detect a missed
                // blit visually. Returning Result from blit_rgba would
                // force every caller to handle errors that are almost
                // never actionable, so we deliberately swallow.
                let _ =
                    self.ctx
                        .put_image_data(&image, dest_left as f64, dest_top as f64);
            }
            Err(_e) => {
                // ImageData construction can fail only on length/size
                // mismatches; the decoder guarantees those line up, so
                // arriving here means a logic bug in our pipeline. Same
                // rationale as above for not returning the error.
            }
        }
    }
}
