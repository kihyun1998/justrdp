//! The client-side framebuffer: an RGBA8888, top-down pixel buffer at the negotiated desktop
//! size (stride = width × 4). Decoded bitmap rectangles are blitted in; each blit yields the
//! [`FrameUpdate`] the host's frame sink receives. Mirrors the decode-complete reference
//! model of ironrdp-session's image buffer (plan.md §7).

/// One rectangle of the framebuffer that changed: position and size only. The pixels live in
/// the retained [`Framebuffer`] (ADR-0010) — the host reads them by borrow via
/// [`Framebuffer::copy_rect_into`] (or [`Framebuffer::pixels`] + the rect), inside the
/// synchronous frame sink. Coordinates are top-down framebuffer pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameUpdate {
    /// Left edge in framebuffer coordinates.
    pub x: u16,
    /// Top edge in framebuffer coordinates.
    pub y: u16,
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
}

/// Per-axis cap on a desktop dimension. **The same 16384 `justrdp::egfx` caps a surface at**,
/// and for the same reason — an EGFX surface tracks the desktop, so two different ceilings
/// would only differ by accident.
///
/// It is not decoration. `width * height * 4` is computed in `usize`, and `usize` is 32 bits on
/// i686 and wasm32: at the type's own maximum, `65535 * 65535 * 4` is 17_179_344_900, which
/// exceeds `u32::MAX`. **Reproduced** on `i686-pc-windows-msvc` before this cap existed —
/// *"attempt to multiply with overflow"* in debug, and in release a wrapped, undersized `Vec`
/// while `self.width`/`self.height` keep the declared values, so every later `blit` writes past
/// the end. On x86-64 the same call merely allocates 17 GiB and succeeds, which is why every
/// other gate was green over it ([the invariant](../../../docs/map/invariant/decoder-dimension-overflow-32bit.md)).
/// At the cap the product is exactly 1 GiB, so it fits a 32-bit `usize` by construction rather
/// than by a check that could be forgotten.
pub const MAX_DESKTOP_DIM: u16 = 16384;

/// Why building or resizing a framebuffer failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramebufferError {
    /// A desktop dimension exceeds [`MAX_DESKTOP_DIM`].
    ///
    /// Reachable from the wire: `session.rs` drives the resize from `DemandActive`'s
    /// `desktopWidth`/`desktopHeight` and from a Display Control `OutputResized`, neither of
    /// which is clamped before it arrives.
    DesktopTooLarge {
        /// The declared width.
        width: u16,
        /// The declared height.
        height: u16,
    },
    /// A read-back rectangle is not wholly inside the framebuffer.
    RectOutOfBounds {
        /// The requested rectangle, `(x, y, width, height)`.
        rect: (u16, u16, u16, u16),
        /// The framebuffer's size, `(width, height)`.
        framebuffer: (u16, u16),
    },
    /// The destination buffer is smaller than the rectangle needs.
    DestinationTooSmall {
        /// Bytes the rectangle requires.
        needed: usize,
        /// Bytes the destination has.
        got: usize,
    },
}

impl core::fmt::Display for FramebufferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FramebufferError::DesktopTooLarge { width, height } => write!(
                f,
                "declared desktop {width}x{height} exceeds the {MAX_DESKTOP_DIM} per-axis cap"
            ),
            FramebufferError::RectOutOfBounds {
                rect: (x, y, w, h),
                framebuffer: (fw, fh),
            } => write!(
                f,
                "rect {w}x{h} at ({x},{y}) is not inside the {fw}x{fh} framebuffer"
            ),
            FramebufferError::DestinationTooSmall { needed, got } => {
                write!(f, "destination holds {got} bytes, the rect needs {needed}")
            }
        }
    }
}

impl core::error::Error for FramebufferError {}

/// The desktop-sized RGBA8888 pixel buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framebuffer {
    width: u16,
    height: u16,
    pixels: Vec<u8>,
}

impl Framebuffer {
    /// A black framebuffer of the given size, or [`FramebufferError::DesktopTooLarge`].
    pub fn new(width: u16, height: u16) -> Result<Self, FramebufferError> {
        let mut fb = Self {
            width: 0,
            height: 0,
            pixels: Vec::new(),
        };
        fb.resize(width, height)?;
        Ok(fb)
    }

    /// Rebuild at a new size (Deactivation–Reactivation, the resize trap of plan.md §0).
    /// Existing content is discarded — the server repaints after reactivation.
    ///
    /// Fallible in place rather than split into a validating step and an infallible apply
    /// ([ADR-0012](../../../docs/adr/0012-consumption-site-totality.md) §4). The split exists so a
    /// *per-element loop* need not thread a `Result`; this allocates once per reactivation, so
    /// there is no loop to keep total and nothing to buy by separating them.
    pub fn resize(&mut self, width: u16, height: u16) -> Result<(), FramebufferError> {
        if width > MAX_DESKTOP_DIM || height > MAX_DESKTOP_DIM {
            return Err(FramebufferError::DesktopTooLarge { width, height });
        }
        self.width = width;
        self.height = height;
        // Total by construction now: both factors are <= MAX_DESKTOP_DIM, so the product is at
        // most 1 GiB and fits a 32-bit `usize`.
        self.pixels = vec![0; width as usize * height as usize * 4];
        // Opaque black, not transparent black.
        for alpha in self.pixels.iter_mut().skip(3).step_by(4) {
            *alpha = 255;
        }
        Ok(())
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
    /// dirty [`FrameUpdate`] rect — `None` when the region lies entirely outside the framebuffer.
    /// The pixels are written into the retained framebuffer only; the host reads them back via
    /// [`Self::copy_rect_into`] (ADR-0010 — no owned per-region copy).
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
            // `saturating_mul`, not `*`: `src_stride_px` is a bare `usize` parameter, so the
            // signature admits a stride whose byte width overflows — on **every** target, not
            // only 32-bit ones (ADR-0012 §1; the wire cannot reach it, which sets the priority
            // and not the contract). Saturating is also the right answer rather than merely a
            // total one: a stride wider than the whole source yields no complete row, and
            // `src.len() / usize::MAX` is 0, so the blit correctly reports nothing to draw.
            .min(src.len() / src_stride_px.saturating_mul(4).max(1));
        if width == 0 || height == 0 {
            return None;
        }

        let fb_stride = usize::from(self.width) * 4;
        for row in 0..height {
            let src_off = row * src_stride_px * 4;
            let src_row = &src[src_off..src_off + width * 4];
            let dst_off = (usize::from(y) + row) * fb_stride + usize::from(x) * 4;
            self.pixels[dst_off..dst_off + width * 4].copy_from_slice(src_row);
        }
        Some(FrameUpdate {
            x,
            y,
            width: width as u16,
            height: height as u16,
        })
    }

    /// The whole framebuffer as one [`FrameUpdate`] rect (the full-screen re-emit after
    /// reactivation). The pixels stay in the framebuffer; the host reads them via
    /// [`Self::pixels`] / [`Self::copy_rect_into`].
    pub fn full_frame(&self) -> FrameUpdate {
        FrameUpdate {
            x: 0,
            y: 0,
            width: self.width,
            height: self.height,
        }
    }

    /// Copy the `width × height` region at `(x, y)` out of the framebuffer into `dst` (tightly
    /// packed top-down RGBA8888, exactly `width × height × 4` bytes), handling the framebuffer
    /// stride. This is how a host materializes a [`FrameUpdate`]'s pixels (ADR-0010): the region
    /// is strided inside the retained framebuffer, so it is not a single contiguous slice — a
    /// host uploading a dirty rect to a GPU texture instead copies it out row by row here.
    ///
    /// A [`FrameUpdate`] this framebuffer produced always satisfies the two conditions below, so
    /// the errors are unreachable through the intended flow. They exist anyway because this is a
    /// `pub fn` a host calls with values it chose: the parser-side guarantee is evidence about
    /// **reachability**, which sets the priority, and never about **totality**, which is the
    /// contract ([ADR-0012](../../../docs/adr/0012-consumption-site-totality.md) §1). Before this
    /// returned a `Result` it panicked — *"range end index 48940 out of range for slice of length
    /// 433"*, found by the property below, not by a caller.
    ///
    /// Fails when the rectangle is not wholly inside the framebuffer, or when `dst` holds fewer
    /// than `width × height × 4` bytes.
    pub fn copy_rect_into(
        &self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        dst: &mut [u8],
    ) -> Result<(), FramebufferError> {
        if usize::from(x) + usize::from(width) > usize::from(self.width)
            || usize::from(y) + usize::from(height) > usize::from(self.height)
        {
            return Err(FramebufferError::RectOutOfBounds {
                rect: (x, y, width, height),
                framebuffer: (self.width, self.height),
            });
        }
        let needed = usize::from(width) * usize::from(height) * 4;
        if dst.len() < needed {
            return Err(FramebufferError::DestinationTooSmall {
                needed,
                got: dst.len(),
            });
        }
        let fb_stride = usize::from(self.width) * 4;
        let row_bytes = usize::from(width) * 4;
        for row in 0..usize::from(height) {
            let src_off = (usize::from(y) + row) * fb_stride + usize::from(x) * 4;
            let dst_off = row * row_bytes;
            dst[dst_off..dst_off + row_bytes]
                .copy_from_slice(&self.pixels[src_off..src_off + row_bytes]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blit_writes_at_offset_and_returns_the_region() {
        let mut fb =
            Framebuffer::new(4, 4).expect("the test desktop size is within MAX_DESKTOP_DIM");
        // A 2×2 red square from a source image 3 pixels wide (extra column ignored).
        let mut src = Vec::new();
        for _ in 0..2 {
            src.extend_from_slice(&[255, 0, 0, 255, 255, 0, 0, 255, 9, 9, 9, 9]);
        }
        let update = fb.blit(1, 2, 2, 2, &src, 3).unwrap();
        assert_eq!(
            (update.x, update.y, update.width, update.height),
            (1, 2, 2, 2)
        );
        // The host reads the region back out of the retained framebuffer (ADR-0010).
        let mut region = vec![0u8; 2 * 2 * 4];
        fb.copy_rect_into(update.x, update.y, update.width, update.height, &mut region)
            .expect("a FrameUpdate this framebuffer produced is in bounds");
        assert_eq!(&region[..4], &[255, 0, 0, 255]);
        // Framebuffer row 2, col 1 holds red; col 0 stays black.
        let stride = 4 * 4;
        assert_eq!(&fb.pixels()[2 * stride..2 * stride + 4], &[0, 0, 0, 255]);
        assert_eq!(
            &fb.pixels()[2 * stride + 4..2 * stride + 8],
            &[255, 0, 0, 255]
        );
    }

    #[test]
    fn blit_clips_to_the_framebuffer_edge() {
        let mut fb =
            Framebuffer::new(4, 4).expect("the test desktop size is within MAX_DESKTOP_DIM");
        let src = vec![7u8; 4 * 4 * 4];
        // Destination starts at (3,3): only 1×1 fits.
        let update = fb.blit(3, 3, 4, 4, &src, 4).unwrap();
        assert_eq!((update.width, update.height), (1, 1));
        // Entirely outside → no update.
        assert!(fb.blit(4, 0, 2, 2, &src, 4).is_none());
    }

    #[test]
    fn resize_rebuilds_black_opaque() {
        let mut fb =
            Framebuffer::new(2, 2).expect("the test desktop size is within MAX_DESKTOP_DIM");
        fb.blit(0, 0, 2, 2, &[9; 16], 2);
        fb.resize(3, 1).expect("3x1 is within MAX_DESKTOP_DIM");
        assert_eq!((fb.width(), fb.height()), (3, 1));
        assert_eq!(fb.pixels(), &[0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255]);
    }
}

#[cfg(test)]
mod dimension_bounds {
    use super::*;
    use proptest::prelude::*;

    /// **Regression, and it was reproduced rather than reasoned about.** `resize` computed
    /// `width as usize * height as usize * 4` unguarded. `usize` is 32 bits on i686 and wasm32,
    /// and at the parameter type's own maximum that product is 17_179_344_900 — past `u32::MAX`.
    ///
    /// Measured on `i686-pc-windows-msvc` before [`MAX_DESKTOP_DIM`] existed: *"attempt to
    /// multiply with overflow"* at the `vec![0; ..]`. In release, where `overflow-checks` is off,
    /// it wraps instead and allocates a short buffer while `self.width`/`self.height` keep the
    /// declared values, so every later `blit` indexes past the end. On x86-64 the same call
    /// simply allocates 17 GiB and succeeds — which is why the whole suite, the fuzz lane and the
    /// real VM were green over it
    /// ([the invariant](../../../docs/map/invariant/decoder-dimension-overflow-32bit.md)).
    ///
    /// Wire-reachable: `session.rs` drives `resize` from `DemandActive`'s declared desktop size
    /// and from a Display Control `OutputResized`, neither clamped before arrival.
    #[test]
    fn the_widest_declarable_desktop_is_refused_not_allocated() {
        assert_eq!(
            Framebuffer::new(u16::MAX, u16::MAX),
            Err(FramebufferError::DesktopTooLarge {
                width: u16::MAX,
                height: u16::MAX
            })
        );
        // The boundary, both sides. At the cap the product is exactly 1 GiB, which is the
        // largest value that still fits a 32-bit `usize`; one past it on either axis is refused.
        assert!(Framebuffer::new(MAX_DESKTOP_DIM, MAX_DESKTOP_DIM).is_ok());
        assert!(Framebuffer::new(MAX_DESKTOP_DIM + 1, 1).is_err());
        assert!(Framebuffer::new(1, MAX_DESKTOP_DIM + 1).is_err());
        assert_eq!(
            usize::from(MAX_DESKTOP_DIM) * usize::from(MAX_DESKTOP_DIM) * 4,
            1 << 30,
            "the cap is what makes the product fit a 32-bit usize by construction"
        );
    }

    /// A refused resize must not leave the recorded size ahead of the buffer — that is the
    /// release-mode shape of the same defect, where `width`/`height` describe a buffer that was
    /// never allocated.
    #[test]
    fn a_refused_resize_leaves_the_framebuffer_untouched() {
        let mut fb = Framebuffer::new(4, 4).expect("4x4 is within the cap");
        let before = fb.clone();
        assert!(fb.resize(u16::MAX, u16::MAX).is_err());
        assert_eq!(fb, before, "a refused resize must be a no-op");
        assert_eq!(
            fb.pixels().len(),
            usize::from(fb.width()) * usize::from(fb.height()) * 4
        );
    }

    proptest! {
        /// [untrusted decode never panics](../../../docs/map/invariant/untrusted-decode-never-panics.md)
        /// over the whole parameter type, not the subset a server realistically sends — which is
        /// the distinction ADR-0012 §1 draws, and the one that hid this defect: every hand-written
        /// vector used a plausible desktop.
        ///
        /// The generator is deliberately biased toward the boundary; uniform `u16`s would reach
        /// `MAX_DESKTOP_DIM` about once in four, and the interesting inputs are the ones near it.
        #[test]
        fn resize_is_total_over_every_declarable_desktop(
            width in prop_oneof![0u16..=64, 16_300u16..=16_500, any::<u16>()],
            height in prop_oneof![0u16..=64, 16_300u16..=16_500, any::<u16>()],
        ) {
            let mut fb = Framebuffer::new(1, 1).expect("1x1 is within the cap");
            match fb.resize(width, height) {
                Ok(()) => {
                    prop_assert!(width <= MAX_DESKTOP_DIM && height <= MAX_DESKTOP_DIM);
                    prop_assert_eq!(
                        fb.pixels().len(),
                        usize::from(width) * usize::from(height) * 4
                    );
                }
                Err(FramebufferError::DesktopTooLarge { .. }) => {
                    prop_assert!(width > MAX_DESKTOP_DIM || height > MAX_DESKTOP_DIM);
                }
                // Not a catch-all: `resize` has exactly one way to fail, and an arm that
                // silently accepted a read-back error would make this property assert less
                // than it reads as asserting.
                Err(other) => prop_assert!(false, "resize returned {other:?}"),
            }
        }

        /// `blit` takes `src_stride_px` as a bare `usize` and multiplies it by 4, so the same
        /// 32-bit question applies to a parameter no server sends but the signature admits.
        #[test]
        fn blit_is_total_over_arbitrary_geometry(
            x in any::<u16>(),
            y in any::<u16>(),
            copy_width in any::<u16>(),
            copy_height in any::<u16>(),
            stride in prop_oneof![0usize..=8, Just(usize::MAX), Just(usize::MAX / 4), any::<usize>()],
            src_len in 0usize..=256,
        ) {
            let mut fb = Framebuffer::new(8, 8).expect("8x8 is within the cap");
            let src = vec![7u8; src_len];
            let _ = fb.blit(x, y, copy_width, copy_height, &src, stride);
        }

        /// The readback half. Its doc records preconditions a `FrameUpdate` this framebuffer
        /// produced always satisfies — which is evidence about reachability, and ADR-0012 §1 is
        /// explicit that reachability governs priority and never the contract. It is `pub`.
        #[test]
        fn copy_rect_into_is_total_over_arbitrary_rects(
            x in any::<u16>(),
            y in any::<u16>(),
            width in any::<u16>(),
            height in any::<u16>(),
            dst_len in 0usize..=512,
        ) {
            let fb = Framebuffer::new(8, 8).expect("8x8 is within the cap");
            let mut dst = vec![0u8; dst_len];
            let _ = fb.copy_rect_into(x, y, width, height, &mut dst);
        }
    }
}
