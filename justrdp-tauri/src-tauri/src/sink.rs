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

use std::sync::{Arc, Mutex};

use justrdp_web::FrameSink;
use serde::Serialize;
use tokio::sync::Notify;

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

// ── Binary IPC frame packing (#31) ──────────────────────────────────

/// One damaged rectangle staged for binary IPC transport. Carries raw
/// RGBA bytes (no base64, no JSON) — `pack_frame` serialises a slice
/// of these into a single packed `Vec<u8>` for `tauri::ipc::Channel`
/// delivery to the frontend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBlit {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    /// Top-down RGBA8 pixels, length = `w * h * 4`.
    pub rgba: Vec<u8>,
}

/// Pack a list of blits into a single binary frame for IPC transport.
///
/// Wire layout (little-endian, no padding):
/// ```text
/// [u32 blit_count]
/// for each blit:
///   [u16 x] [u16 y] [u16 w] [u16 h] [u32 byte_len] [byte_len bytes raw RGBA]
/// ```
///
/// `byte_len` is redundant with `w * h * 4` but explicit so a frontend
/// parser can validate without relying on the dimension math.
pub fn pack_frame(blits: &[RawBlit]) -> Vec<u8> {
    // Pre-size: 4-byte count + per-blit (12-byte header + pixels).
    let total: usize = 4 + blits.iter().map(|b| 12 + b.rgba.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(blits.len() as u32).to_le_bytes());
    for b in blits {
        out.extend_from_slice(&b.x.to_le_bytes());
        out.extend_from_slice(&b.y.to_le_bytes());
        out.extend_from_slice(&b.w.to_le_bytes());
        out.extend_from_slice(&b.h.to_le_bytes());
        out.extend_from_slice(&(b.rgba.len() as u32).to_le_bytes());
        out.extend_from_slice(&b.rgba);
    }
    out
}

#[cfg(test)]
mod packing_tests {
    use super::*;

    /// Tracer: one 2×2 blit at (10, 20) with a known RGBA pattern packs
    /// to a bit-exact 32-byte buffer (4 count + 12 header + 16 pixels).
    /// The `count` field at offset 0 is mandatory even for one blit;
    /// `byte_len` (16) is mandatory even though it equals w*h*4.
    #[test]
    fn pack_frame_one_blit_bit_exact_layout() {
        let blit = RawBlit {
            x: 10,
            y: 20,
            w: 2,
            h: 2,
            rgba: vec![
                0x10, 0x11, 0x12, 0xFF,
                0x20, 0x21, 0x22, 0xFF,
                0x30, 0x31, 0x32, 0xFF,
                0x40, 0x41, 0x42, 0xFF,
            ],
        };
        let bytes = pack_frame(&[blit]);
        let expected: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, // count = 1
            0x0A, 0x00,             // x = 10
            0x14, 0x00,             // y = 20
            0x02, 0x00,             // w = 2
            0x02, 0x00,             // h = 2
            0x10, 0x00, 0x00, 0x00, // byte_len = 16
            0x10, 0x11, 0x12, 0xFF,
            0x20, 0x21, 0x22, 0xFF,
            0x30, 0x31, 0x32, 0xFF,
            0x40, 0x41, 0x42, 0xFF,
        ];
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 32);
    }

    /// Empty blit list still produces a valid 4-byte frame (count=0).
    /// Frontend parser must handle this without overrunning.
    #[test]
    fn pack_frame_empty_blits_yields_four_zero_bytes() {
        let bytes = pack_frame(&[]);
        assert_eq!(bytes, vec![0x00, 0x00, 0x00, 0x00]);
    }

    /// Multi-blit roundtrip: pack → manual unpack reproduces the input.
    /// Pins the per-blit offset arithmetic so a future stride bug shows
    /// up immediately.
    #[test]
    fn pack_frame_multi_blit_roundtrip() {
        let blits = vec![
            RawBlit { x: 0, y: 0, w: 1, h: 1, rgba: vec![0xAA, 0xBB, 0xCC, 0xFF] },
            RawBlit { x: 100, y: 200, w: 1, h: 2, rgba: vec![1, 2, 3, 4, 5, 6, 7, 8] },
            RawBlit { x: 50, y: 50, w: 2, h: 1, rgba: vec![9, 9, 9, 9, 8, 8, 8, 8] },
        ];
        let bytes = pack_frame(&blits);

        // Manually parse and compare.
        let count = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(count, blits.len());

        let mut off = 4;
        for original in &blits {
            let x = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
            let y = u16::from_le_bytes([bytes[off + 2], bytes[off + 3]]);
            let w = u16::from_le_bytes([bytes[off + 4], bytes[off + 5]]);
            let h = u16::from_le_bytes([bytes[off + 6], bytes[off + 7]]);
            let byte_len = u32::from_le_bytes([
                bytes[off + 8], bytes[off + 9], bytes[off + 10], bytes[off + 11],
            ]) as usize;
            let pixels = &bytes[off + 12..off + 12 + byte_len];
            assert_eq!((x, y, w, h), (original.x, original.y, original.w, original.h));
            assert_eq!(pixels, &original.rgba[..]);
            off += 12 + byte_len;
        }
        assert_eq!(off, bytes.len(), "all bytes consumed exactly");
    }
}

/// Shared `FrameSink` handle that both the EGFX SVC pump and
/// `run_session` hold. The `Mutex` lets two async tasks write into the
/// same `TauriFrameSink` (canvas pixels + pending blits); the `Notify`
/// wakes `run_session` whenever blits accumulate so the IPC drain loop
/// runs even when no fast-path event is incoming (pure-EGFX sessions).
///
/// PRD #20 / issue #29.
#[derive(Clone)]
pub struct SharedSink {
    inner: Arc<Mutex<TauriFrameSink>>,
    notify: Arc<Notify>,
}

impl SharedSink {
    pub fn new(inner: Arc<Mutex<TauriFrameSink>>, notify: Arc<Notify>) -> Self {
        Self { inner, notify }
    }
}

impl FrameSink for SharedSink {
    fn resize(&mut self, width: u16, height: u16) {
        if let Ok(mut s) = self.inner.lock() {
            s.resize(width, height);
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
        if let Ok(mut s) = self.inner.lock() {
            s.blit_rgba(dest_left, dest_top, width, height, pixels_rgba);
        }
        // Idempotent: notify_one stores at most one permit, so multiple
        // back-to-back blits coalesce into a single drain wake.
        self.notify.notify_one();
    }

    fn peek_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        out: &mut Vec<u8>,
    ) -> bool {
        match self.inner.lock() {
            Ok(mut s) => s.peek_rgba(dest_left, dest_top, width, height, out),
            Err(_) => false,
        }
    }

    fn flush(&mut self) {
        // No-op: TauriFrameSink::flush is itself a no-op (drains happen
        // explicitly via drain_blits()), but we still notify so the
        // EGFX pump's `on_end_frame` flush call wakes the drain loop.
        self.notify.notify_one();
    }
}
