//! The client-side framebuffer: an RGBA8888, top-down pixel buffer at the negotiated desktop
//! size (stride = width × 4). Decoded bitmap rectangles are blitted in; each blit yields the
//! [`FrameUpdate`] the host's frame sink receives. Mirrors the decode-complete reference
//! model of ironrdp-session's image buffer (plan.md §7).

/// One rectangle of fresh pixels for the host: position, size, and RGBA8888 data (top-down,
/// stride = `width × 4`, little-endian byte order R,G,B,A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameUpdate {
    /// Left edge in framebuffer coordinates.
    pub x: u16,
    /// Top edge in framebuffer coordinates.
    pub y: u16,
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
    /// `width × height × 4` RGBA bytes.
    pub pixels: Vec<u8>,
}

/// The desktop-sized RGBA8888 pixel buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framebuffer {
    width: u16,
    height: u16,
    pixels: Vec<u8>,
}

impl Framebuffer {
    /// A black framebuffer of the given size.
    pub fn new(width: u16, height: u16) -> Self {
        let mut fb = Self {
            width: 0,
            height: 0,
            pixels: Vec::new(),
        };
        fb.resize(width, height);
        fb
    }

    /// Rebuild at a new size (Deactivation–Reactivation, the resize trap of plan.md §0).
    /// Existing content is discarded — the server repaints after reactivation.
    pub fn resize(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
        self.pixels = vec![0; width as usize * height as usize * 4];
        // Opaque black, not transparent black.
        for alpha in self.pixels.iter_mut().skip(3).step_by(4) {
            *alpha = 255;
        }
    }

    /// Current width in pixels.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Current height in pixels.
    pub fn height(&self) -> u16 {
        self.height
    }

    /// The whole buffer, RGBA8888 top-down.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Copy a `copy_width × copy_height` region out of `src` (an RGBA image `src_stride_px`
    /// pixels wide) to `(x, y)`, clipped to the framebuffer bounds, and return the resulting
    /// [`FrameUpdate`] — `None` when the region lies entirely outside the framebuffer.
    pub fn blit(
        &mut self,
        x: u16,
        y: u16,
        copy_width: u16,
        copy_height: u16,
        src: &[u8],
        src_stride_px: usize,
    ) -> Option<FrameUpdate> {
        let width = usize::from(copy_width)
            .min(usize::from(self.width).saturating_sub(usize::from(x)))
            .min(src_stride_px);
        let height = usize::from(copy_height)
            .min(usize::from(self.height).saturating_sub(usize::from(y)))
            .min(src.len() / (src_stride_px * 4).max(1));
        if width == 0 || height == 0 {
            return None;
        }

        let fb_stride = usize::from(self.width) * 4;
        let mut pixels = Vec::with_capacity(width * height * 4);
        for row in 0..height {
            let src_off = row * src_stride_px * 4;
            let src_row = &src[src_off..src_off + width * 4];
            let dst_off = (usize::from(y) + row) * fb_stride + usize::from(x) * 4;
            self.pixels[dst_off..dst_off + width * 4].copy_from_slice(src_row);
            pixels.extend_from_slice(src_row);
        }
        Some(FrameUpdate {
            x,
            y,
            width: width as u16,
            height: height as u16,
            pixels,
        })
    }

    /// The whole framebuffer as one [`FrameUpdate`] (the full-screen re-emit after
    /// reactivation).
    pub fn full_frame(&self) -> FrameUpdate {
        FrameUpdate {
            x: 0,
            y: 0,
            width: self.width,
            height: self.height,
            pixels: self.pixels.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blit_writes_at_offset_and_returns_the_region() {
        let mut fb = Framebuffer::new(4, 4);
        // A 2×2 red square from a source image 3 pixels wide (extra column ignored).
        let mut src = Vec::new();
        for _ in 0..2 {
            src.extend_from_slice(&[255, 0, 0, 255, 255, 0, 0, 255, 9, 9, 9, 9]);
        }
        let update = fb.blit(1, 2, 2, 2, &src, 3).unwrap();
        assert_eq!((update.x, update.y, update.width, update.height), (1, 2, 2, 2));
        assert_eq!(&update.pixels[..4], &[255, 0, 0, 255]);
        // Framebuffer row 2, col 1 holds red; col 0 stays black.
        let stride = 4 * 4;
        assert_eq!(&fb.pixels()[2 * stride..2 * stride + 4], &[0, 0, 0, 255]);
        assert_eq!(&fb.pixels()[2 * stride + 4..2 * stride + 8], &[255, 0, 0, 255]);
    }

    #[test]
    fn blit_clips_to_the_framebuffer_edge() {
        let mut fb = Framebuffer::new(4, 4);
        let src = vec![7u8; 4 * 4 * 4];
        // Destination starts at (3,3): only 1×1 fits.
        let update = fb.blit(3, 3, 4, 4, &src, 4).unwrap();
        assert_eq!((update.width, update.height), (1, 1));
        // Entirely outside → no update.
        assert!(fb.blit(4, 0, 2, 2, &src, 4).is_none());
    }

    #[test]
    fn resize_rebuilds_black_opaque() {
        let mut fb = Framebuffer::new(2, 2);
        fb.blit(0, 0, 2, 2, &[9; 16], 2);
        fb.resize(3, 1);
        assert_eq!((fb.width(), fb.height()), (3, 1));
        assert_eq!(fb.pixels(), &[0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255]);
    }
}
