//! Tauri-side [`FrameSink`] adapter.
//!
//! [`render_event`](justrdp_web::render_event) calls `blit_rgba` once
//! per damaged rectangle in a single `SessionEvent::Graphics`. Naively
//! emitting one Tauri event per rectangle would saturate the IPC
//! bridge under heavy redraw, so this sink **buffers** all rectangles
//! into [`pending`](TauriFrameSink::pending) and the caller drains
//! them with [`drain_blits`](TauriFrameSink::drain_blits) into a
//! single `Window::emit("rdp:event", Frame { blits })`.
//!
//! The sink also keeps a **shadow framebuffer** so [`peek_rgba`]
//! works — without it, MemBlt with non-`SRCCOPY` ROPs and DstBlt
//! `DSTINVERT` would silently drop their pixels (per the FrameSink
//! trait docs).

use justrdp_web::FrameSink;
use serde::Serialize;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// One damaged rectangle, base64-encoded for JSON transport over the
/// Tauri IPC bridge. Mirrored on the TS side as `BlitPayload` in
/// `App.tsx`.
#[derive(Debug, Clone, Serialize)]
pub struct BlitRecord {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    /// Top-down RGBA8 (`putImageData` layout). Length is `w * h * 4`
    /// bytes pre-base64.
    pub rgba_b64: String,
}

pub struct TauriFrameSink {
    width: u16,
    height: u16,
    /// Top-down RGBA8 shadow framebuffer. Required so `peek_rgba`
    /// can serve read-back for non-SRCCOPY ROPs.
    pixels: Vec<u8>,
    pending: Vec<BlitRecord>,
}

impl TauriFrameSink {
    pub fn new(width: u16, height: u16) -> Self {
        let mut pixels = vec![0u8; width as usize * height as usize * 4];
        // Opaque black so the canvas isn't transparent before the
        // first server-side paint arrives.
        for px in pixels.chunks_exact_mut(4) {
            px[3] = 0xFF;
        }
        Self {
            width,
            height,
            pixels,
            pending: Vec::new(),
        }
    }

    /// Take all rectangles accumulated since the last drain. Returns
    /// an empty `Vec` if nothing was blitted.
    pub fn drain_blits(&mut self) -> Vec<BlitRecord> {
        std::mem::take(&mut self.pending)
    }
}

impl FrameSink for TauriFrameSink {
    fn resize(&mut self, width: u16, height: u16) {
        if width == self.width && height == self.height {
            return;
        }
        self.width = width;
        self.height = height;
        self.pixels = vec![0u8; width as usize * height as usize * 4];
        for px in self.pixels.chunks_exact_mut(4) {
            px[3] = 0xFF;
        }
        // Pending blits target the previous surface — drop them, the
        // next paint will redraw against the new size.
        self.pending.clear();
    }

    fn blit_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        pixels_rgba: &[u8],
    ) {
        let dx = dest_left as usize;
        let dy = dest_top as usize;
        let w = width as usize;
        let h = height as usize;
        let surface_w = self.width as usize;
        let surface_h = self.height as usize;
        // Clip — RDP servers occasionally push rectangles past the
        // negotiated desktop size; ignoring overflow is safer than
        // panicking. Same approach as `native_render_demo`.
        let copy_w = w.min(surface_w.saturating_sub(dx));
        let copy_h = h.min(surface_h.saturating_sub(dy));
        if copy_w == 0 || copy_h == 0 {
            return;
        }

        // Update shadow buffer row-by-row, simultaneously building a
        // tightly-packed `clipped_rgba` for the IPC payload (so we
        // don't re-encode the whole source rectangle when the server
        // overflowed the surface).
        let mut clipped_rgba = Vec::with_capacity(copy_w * copy_h * 4);
        for row in 0..copy_h {
            let src_off = row * w * 4;
            let src_slice = &pixels_rgba[src_off..src_off + copy_w * 4];
            let dst_off = ((dy + row) * surface_w + dx) * 4;
            self.pixels[dst_off..dst_off + copy_w * 4].copy_from_slice(src_slice);
            clipped_rgba.extend_from_slice(src_slice);
        }

        self.pending.push(BlitRecord {
            x: dest_left,
            y: dest_top,
            w: copy_w as u16,
            h: copy_h as u16,
            rgba_b64: B64.encode(&clipped_rgba),
        });
    }

    fn peek_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        out: &mut Vec<u8>,
    ) -> bool {
        let dx = dest_left as usize;
        let dy = dest_top as usize;
        let w = width as usize;
        let h = height as usize;
        let surface_w = self.width as usize;
        let surface_h = self.height as usize;
        if dx + w > surface_w || dy + h > surface_h {
            return false;
        }
        out.clear();
        out.reserve(w * h * 4);
        for row in 0..h {
            let off = ((dy + row) * surface_w + dx) * 4;
            out.extend_from_slice(&self.pixels[off..off + w * 4]);
        }
        true
    }
}
