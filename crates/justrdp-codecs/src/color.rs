//! Pixel-format conversion to the framebuffer's RGBA8888 — the single seam every decoded
//! bitmap passes through (MS-RDPBCGR slow-path color depths: 8-bit palettized, 15/16-bit
//! high color, 24/32-bit true color).
//!
//! Source conventions (the GDI DIB lineage all slow-path bitmaps share):
//! - 8 bpp: palette indices; the palette arrives separately (Palette Update PDU).
//! - 15 bpp: little-endian `u16`, `0RRRRRGG GGGBBBBB` (5/5/5, red high).
//! - 16 bpp: little-endian `u16`, `RRRRRGGG GGGBBBBB` (5/6/5, red high).
//! - 24 bpp: `B G R` byte order.
//! - 32 bpp: `B G R X` byte order (the server's X/alpha byte is ignored; output alpha is 255).

/// A 256-entry RGB palette (Palette Update PDU, MS-RDPBCGR 2.2.9.1.1.3.1.1). Entries default
/// to black until the server's first palette update — the server always sends one before any
/// 8-bpp bitmap it expects rendered faithfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Palette {
    /// `paletteEntries` as `[r, g, b]`.
    pub entries: [[u8; 3]; 256],
}

impl Default for Palette {
    fn default() -> Self {
        Self {
            entries: [[0; 3]; 256],
        }
    }
}

/// Why a conversion failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColorError {
    /// The source bits-per-pixel is not a slow-path depth (8/15/16/24/32).
    UnsupportedBitsPerPixel {
        /// The offending `bitsPerPixel`.
        bits_per_pixel: u16,
    },
    /// The source buffer does not hold `width × height` pixels at the given depth.
    SourceTooShort {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        got: usize,
    },
    /// A `width × height`-derived buffer size overflows `usize` on this target — only reachable on
    /// a **32-bit** target (notably **wasm32**, a stated reach goal — ADR-0002 amendment / #100),
    /// where the `usize` params can make `width × bpp × height` or `width × height × 4` exceed
    /// `u32::MAX`. Returned instead of a debug panic / release wrap. Sibling of #151 (#155).
    ///
    /// **It covers two ceilings, not one (#263).** A `checked_mul` stops at `usize::MAX` while
    /// `Vec` refuses above `isize::MAX`, and in that band [`to_rgba`] panicked with *capacity
    /// overflow* instead of returning this — reproduced on `i686-pc-windows-msvc` with
    /// `to_rgba(&vec![0u8; 558_000_000], 30_000, 18_600, 8, .., false)`, requesting
    /// 2_232_000_000. The source-length check bounds the request only by the 4x amplification
    /// of a 1-byte-per-pixel source. The reserve now narrows through [`crate::allocatable`],
    /// which is the family's one answer to that threshold. See
    /// [the invariant](../../../docs/map/invariant/decoder-dimension-overflow-32bit.md).
    DimensionsOverflow {
        /// The requested width.
        width: usize,
        /// The requested height.
        height: usize,
    },
}

impl core::fmt::Display for ColorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ColorError::UnsupportedBitsPerPixel { bits_per_pixel } => {
                write!(f, "unsupported source depth: {bits_per_pixel} bpp")
            }
            ColorError::SourceTooShort { needed, got } => {
                write!(
                    f,
                    "source pixel buffer too short: need {needed}, have {got}"
                )
            }
            ColorError::DimensionsOverflow { width, height } => {
                write!(f, "{width}x{height} pixels overflow usize on this target")
            }
        }
    }
}

impl core::error::Error for ColorError {}

/// Bytes per pixel for a slow-path depth (15 bpp rides in 2 bytes).
pub fn bytes_per_pixel(bits_per_pixel: u16) -> Result<usize, ColorError> {
    match bits_per_pixel {
        8 => Ok(1),
        15 | 16 => Ok(2),
        24 => Ok(3),
        32 => Ok(4),
        bits_per_pixel => Err(ColorError::UnsupportedBitsPerPixel { bits_per_pixel }),
    }
}

/// Convert `src` (one of the slow-path source formats above) into top-down RGBA8888.
///
/// `bottom_up` says the source scanlines run bottom-to-top — true for uncompressed and
/// interleaved-RLE-decompressed slow-path bitmap data (the GDI legacy layout) — and makes
/// this function flip them. The source stride is assumed to be exactly
/// `width × bytes-per-pixel`. MS-RDPBCGR 2.2.9.1.1.3.1.2.2 pads each uncompressed row to a
/// multiple of four *bytes*; real servers satisfy that by 4-aligning the `width` field itself
/// (the up-to-3-pixel overhang), which makes the tight stride hold at every supported depth.
/// A spec-legal but non-4-aligned width at 8/24 bpp would carry per-row pad bytes this
/// function does not skip.
///
/// **A zero `width` or `height` is `Ok` with no pixels**, whatever `src` and `bottom_up` hold —
/// a zero-extent rectangle is zero work, not a malformed input, and `[MS-RDPEGFX]` 2.2.1.2
/// makes one spec-legal (`RDPGFX_RECT16` is exclusive, so `right == left` is expressible).
/// The check sits *after* the depth check, so an unsupported `bits_per_pixel` is still
/// `UnsupportedBitsPerPixel` at any extent. Note the sibling *stream* decoders answer the
/// other way — `rle::decompress` and `planar::decompress` refuse a zero extent as malformed
/// input — so a caller switching between them sees two answers for one geometry, deliberately.
pub fn to_rgba(
    src: &[u8],
    width: usize,
    height: usize,
    bits_per_pixel: u16,
    palette: &Palette,
    bottom_up: bool,
) -> Result<Vec<u8>, ColorError> {
    let bpp = bytes_per_pixel(bits_per_pixel)?;
    // A zero extent is zero work, and saying so is what makes this function total on its own
    // terms. Every guard below passes at `width == 0` — `0 * bpp` and `0 * height` are 0, and
    // `src.len() < 0` is false — so nothing refuses and the row loop still runs `height` times
    // over empty rows, with `height` a bare `usize` (#262). The arithmetic was never the
    // undefined part; the loop's trip count was. This discharges
    // [ADR-0012](../../../docs/adr/0012-consumption-site-totality.md) **§5** — a public function
    // consuming a wire-derived value as arithmetic carries its totality argument in the same
    // change. Not §3: that one is titled *one **undefined** input, one answer*, and a zero extent
    // is not undefined for anybody — `rle` and `planar` know exactly what it means and refuse it
    // as **policy**, where this bounds a **loop**. Same line `nscodec::reconstruct` draws for its
    // own parameter ("would duplicate the parser's *policy* rather than close the totality hole").
    //
    // **`Ok` here is a deliberate divergence from FreeRDP, not agreement with it.** The reference
    // splits on *who owns the destination*, not on decoder-versus-converter: everything writing
    // into a caller-supplied buffer returns success at a zero extent (`freerdp_image_copy`
    // `color.c:1155`, `_no_overlap`, `_overlap`, `freerdp_image_fill`), and everything that
    // *allocates and returns* refuses — including `freerdp_glyph_convert_ex` (`color.c:265-267`,
    // `if ((len == 0) || (width == 0) || (height == 0)) return nullptr;`), which is a converter of
    // exactly this shape. `to_rgba` allocates and returns, so that axis puts it with the refusers.
    //
    // We go the other way because of what the one reachable consumption site does with the error.
    // `[MS-RDPEGFX]` 2.2.1.2 makes `RDPGFX_RECT16` **exclusive** with no non-zero requirement, so
    // `right == left` is spec-legal and `Rect16::width()` yields 0 — and `justrdp::egfx`'s
    // uncompressed WTS1 arm propagates a `ColorError` with `?`, which is **fatal for the channel**,
    // where every other codec arm there warn-and-skips. Refusing would drop a healthy session over
    // a legal empty rectangle: the receive-path strictness [ADR-0009](../../../docs/adr/0009-tolerant-negotiation-posture.md)
    // calls a defect rather than rigor. `pointer::decode_pointer` reaches `Ok(Vec::new())` too, but
    // it is **not** the precedent — its rationale is a protocol semantic ("a zero-sized shape,
    // which servers use as 'no shape'") that a bitmap has no counterpart for.
    //
    // Placed **after** the depth check, which is `rle::decompress`'s order rather than
    // `pointer::decode_pointer`'s: an unsupported depth stays `UnsupportedBitsPerPixel` at any
    // extent, so this adds a return without removing a typed error. It is total either way.
    if width == 0 || height == 0 {
        return Ok(Vec::new());
    }
    // width/height are usize, so on a 32-bit target a caller can make width × bpp × height (the
    // source length) or width × height × 4 (the output) exceed usize (#155). Check both before
    // allocating rather than panic (debug) / wrap-then-OOB (release).
    let overflow = || ColorError::DimensionsOverflow { width, height };
    let row_bytes = width.checked_mul(bpp).ok_or_else(overflow)?;
    let needed = row_bytes.checked_mul(height).ok_or_else(overflow)?;
    if src.len() < needed {
        return Err(ColorError::SourceTooShort {
            needed,
            got: src.len(),
        });
    }

    let out_cap = width
        .checked_mul(height)
        .and_then(|n| n.checked_mul(4))
        .and_then(crate::allocatable)
        .ok_or_else(overflow)?;
    let mut out = Vec::with_capacity(out_cap);
    for out_row in 0..height {
        let src_row = if bottom_up {
            height - 1 - out_row
        } else {
            out_row
        };
        let row = &src[src_row * row_bytes..(src_row + 1) * row_bytes];
        match bits_per_pixel {
            8 => {
                for &index in row {
                    let [r, g, b] = palette.entries[index as usize];
                    out.extend_from_slice(&[r, g, b, 255]);
                }
            }
            15 => {
                for px in row.as_chunks::<2>().0 {
                    let v = u16::from_le_bytes([px[0], px[1]]);
                    let r = scale5((v >> 10) as u8 & 0x1F);
                    let g = scale5((v >> 5) as u8 & 0x1F);
                    let b = scale5(v as u8 & 0x1F);
                    out.extend_from_slice(&[r, g, b, 255]);
                }
            }
            16 => {
                for px in row.as_chunks::<2>().0 {
                    let v = u16::from_le_bytes([px[0], px[1]]);
                    let r = scale5((v >> 11) as u8 & 0x1F);
                    let g = scale6((v >> 5) as u8 & 0x3F);
                    let b = scale5(v as u8 & 0x1F);
                    out.extend_from_slice(&[r, g, b, 255]);
                }
            }
            24 => {
                for px in row.as_chunks::<3>().0 {
                    out.extend_from_slice(&[px[2], px[1], px[0], 255]);
                }
            }
            32 => {
                for px in row.as_chunks::<4>().0 {
                    out.extend_from_slice(&[px[2], px[1], px[0], 255]);
                }
            }
            _ => unreachable!("bytes_per_pixel validated the depth"),
        }
    }
    Ok(out)
}

/// RemoteFX inverse color transform (ICT, MS-RDPRFX 3.1.8.1.3): per-pixel YCbCr → RGBA8888,
/// alpha 255. Inputs are the planes exactly as the inverse DWT leaves them — pixel-domain
/// fixed point, each sample ≈ `(channel − 128) · 32` — so the level shift folds in here
/// (`+4096 = 128 · 32`) and the final shift drops both the ×32 and the coefficient scale.
///
/// The coefficients are the spec's constants in `f32`, and the per-pixel arithmetic mirrors
/// the differential oracle's fixed-point form bit for bit (ADR-0007) — a "nicer" rounding
/// here would be a permanent 1-LSB diff against every interoperable decoder. Accumulation is
/// `i64` so hostile out-of-range samples saturate at the clamp instead of overflowing.
pub fn rfx_ycbcr_to_rgba(y: &[i16], cb: &[i16], cr: &[i16], out: &mut [u8]) {
    const PRECISION: i64 = 1 << 16;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "spec constants scaled to 16-bit fixed point; exact f32 product fits i64"
    )]
    const CR_R: i64 = (1.402_525_f32 * PRECISION as f32) as i64;
    #[expect(clippy::cast_possible_truncation, reason = "as above")]
    const CB_G: i64 = (0.343_730_f32 * PRECISION as f32) as i64;
    #[expect(clippy::cast_possible_truncation, reason = "as above")]
    const CR_G: i64 = (0.714_401_f32 * PRECISION as f32) as i64;
    #[expect(clippy::cast_possible_truncation, reason = "as above")]
    const CB_B: i64 = (1.769_905_f32 * PRECISION as f32) as i64;

    debug_assert_eq!(y.len(), cb.len());
    debug_assert_eq!(y.len(), cr.len());
    debug_assert_eq!(out.len(), y.len() * 4);

    // The clamp to 0..=255 makes the cast lossless, and clippy knows it.
    fn clamp8(v: i64) -> u8 {
        (v >> 21).clamp(0, 255) as u8
    }

    for (((&y, &cb), &cr), px) in y
        .iter()
        .zip(cb.iter())
        .zip(cr.iter())
        .zip(out.as_chunks_mut::<4>().0)
    {
        let yy = (i64::from(y) + 4096) * PRECISION;
        px[0] = clamp8(yy + CR_R * i64::from(cr));
        px[1] = clamp8(yy - CR_G * i64::from(cr) - CB_G * i64::from(cb));
        px[2] = clamp8(yy + CB_B * i64::from(cb));
        px[3] = 255;
    }
}

/// Widen a 5-bit channel to 8 bits, replicating the high bits into the low ones so full
/// intensity maps to 255 (not 248).
fn scale5(c: u8) -> u8 {
    c << 3 | c >> 2
}

/// Widen a 6-bit channel to 8 bits.
fn scale6(c: u8) -> u8 {
    c << 2 | c >> 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Dimensions whose product overflows `usize` are a typed error, never a panic or wrap (#155,
    // sibling of #151). Only reachable on a 32-bit `usize`: 100_000 × 100_000 = 1e10 > u32::MAX but
    // fits 64-bit — hence the target gate. The checked source-length product fires before the
    // output buffer is allocated. Proven on i686-pc-windows-msvc.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn overflowing_dimensions_are_a_typed_error_not_a_panic() {
        assert_eq!(
            to_rgba(&[], 100_000, 100_000, 8, &Palette::default(), false),
            Err(ColorError::DimensionsOverflow {
                width: 100_000,
                height: 100_000,
            })
        );
        // The `isize::MAX` half is **deliberately not asserted here**, and the reason is a
        // measurement rather than a preference. `out_cap`'s band needs `width * height > 2^29`,
        // and `src.len() < needed` sits above it — so any input that reaches the reserve carries
        // at least ~536 MB of source. Reproduced at 30_000 x 18_600 x 8bpp with a real 558 MB
        // buffer (#263); allocating that inside a 32-bit test process to assert one comparison
        // is not a trade worth making, and a cheaper input returns `SourceTooShort` instead —
        // which is what this test would have silently asserted.
        //
        // So the threshold itself is pinned once, on `crate::allocatable`, and what stays
        // untested here is the *wiring*. Said out loud because a chain nobody reddens is exactly
        // what this file's siblings assumed about themselves until #263 measured them.
        assert_eq!(
            to_rgba(&[], 30_000, 18_600, 8, &Palette::default(), false),
            Err(ColorError::SourceTooShort {
                needed: 558_000_000,
                got: 0
            }),
            "a short source is refused above the reserve, so the reserve's own ceiling is              unreachable from here"
        );
    }

    #[test]
    fn palette_lookup_converts_8bpp() {
        let mut palette = Palette::default();
        palette.entries[7] = [10, 20, 30];
        palette.entries[255] = [200, 100, 50];
        let out = to_rgba(&[7, 255], 2, 1, 8, &palette, false).unwrap();
        assert_eq!(out, [10, 20, 30, 255, 200, 100, 50, 255]);
    }

    #[test]
    fn high_color_channels_scale_to_full_range() {
        // 16 bpp pure red / pure green / pure blue / white.
        let red = 0xF800u16.to_le_bytes();
        let green = 0x07E0u16.to_le_bytes();
        let blue = 0x001Fu16.to_le_bytes();
        let white = 0xFFFFu16.to_le_bytes();
        let src = [red, green, blue, white].concat();
        let out = to_rgba(&src, 4, 1, 16, &Palette::default(), false).unwrap();
        assert_eq!(
            out,
            [
                255, 0, 0, 255, //
                0, 255, 0, 255, //
                0, 0, 255, 255, //
                255, 255, 255, 255
            ]
        );

        // 15 bpp white: 0x7FFF must also reach 255 on every channel.
        let out = to_rgba(
            &0x7FFFu16.to_le_bytes(),
            1,
            1,
            15,
            &Palette::default(),
            false,
        )
        .unwrap();
        assert_eq!(out, [255, 255, 255, 255]);
    }

    #[test]
    fn true_color_swaps_bgr_and_flips_bottom_up() {
        // Two rows of one 24-bpp pixel each, bottom-up: source row 0 is the screen's bottom.
        let src = [
            1, 2, 3, // bottom row (B=1 G=2 R=3)
            4, 5, 6, // top row
        ];
        let out = to_rgba(&src, 1, 2, 24, &Palette::default(), true).unwrap();
        assert_eq!(
            out,
            [
                6, 5, 4, 255, // top row first
                3, 2, 1, 255
            ]
        );
    }

    #[test]
    fn xrgb32_ignores_the_server_alpha_byte() {
        let out = to_rgba(&[9, 8, 7, 0], 1, 1, 32, &Palette::default(), false).unwrap();
        assert_eq!(out, [7, 8, 9, 255]);
    }

    /// The supported depths, as a strategy. **The bias is the point.** `bytes_per_pixel` is an
    /// exact-match gate on `{8, 15, 16, 24, 32}`, so a uniform `u16` clears it about **5 times in
    /// 65536** and everything past the gate — the `checked_mul` guards, the per-bpp row walks, the
    /// `bottom_up` flip — would go unexercised while the property still ran green. This repo has
    /// already shipped that exact defect once: `nscodec`'s no-panic property documented itself as
    /// covering *"any colour-loss level"*, generated `1u8..=7`, and passed over a live panic
    /// ([ADR-0012](../../../../docs/adr/0012-consumption-site-totality.md) Consequences).
    fn depth() -> impl Strategy<Value = u16> {
        prop_oneof![
            9 => prop::sample::select(vec![8u16, 15, 16, 24, 32]),
            1 => any::<u16>(),
        ]
    }

    /// Dimensions biased toward the two places the arithmetic changes behaviour: small values
    /// that produce a real conversion, and values whose product overflows a **32-bit** `usize`
    /// (#155). The second range does nothing on x86-64 — `checked_mul` succeeds and the
    /// source-length check refuses — which is why the `overflow-32bit` CI job runs this crate.
    ///
    /// **The arm that bit was `any::<usize>()`, and the sentence above is why nobody looked at
    /// it** (#262). It is true only for `width > 0`: at `width == 0` the source-length check
    /// *passes* rather than refusing, because `needed` is 0 — so the draw that reached ~1.8e19
    /// rows was never the overflow arm this comment was watching. The arm stays unbounded on
    /// purpose. Narrowing it would restore the green by removing the reach, and this file's own
    /// [`the_generator_reaches_past_the_depth_gate`] exists because a property that never
    /// reaches its subject asserts nothing; the guard belongs in `to_rgba`, and is there.
    fn dimension() -> impl Strategy<Value = usize> {
        prop_oneof![
            6 => 0usize..=32,
            2 => 60_000usize..=70_000,
            1 => any::<usize>(),
        ]
    }

    proptest! {
        /// [untrusted decode never panics](../../../../docs/map/invariant/untrusted-decode-never-panics.md).
        /// `to_rgba` takes `width`, `height` and `bits_per_pixel` straight off the wire — a bitmap
        /// update rectangle (`session.rs`) or an EGFX surface/cache command (`egfx.rs`) — and
        /// sizes two buffers from their products. It is the third member of ADR-0012's class and
        /// the one that had neither artifact (#238).
        #[test]
        fn to_rgba_is_total_over_arbitrary_dimensions(
            bits in depth(),
            width in dimension(),
            height in dimension(),
            src_len in 0usize..=1024,
            bottom_up in any::<bool>(),
        ) {
            let src = vec![0xA5u8; src_len];
            let _ = to_rgba(&src, width, height, bits, &Palette::default(), bottom_up);
        }

        /// The guard on its own, over the whole parameter type rather than the five values a
        /// server sends.
        #[test]
        fn bytes_per_pixel_is_total_over_every_depth(bits in any::<u16>()) {
            match bytes_per_pixel(bits) {
                Ok(n) => prop_assert!(matches!((bits, n), (8, 1) | (15 | 16, 2) | (24, 3) | (32, 4))),
                Err(ColorError::UnsupportedBitsPerPixel { .. }) => {
                    prop_assert!(!matches!(bits, 8 | 15 | 16 | 24 | 32));
                }
                Err(other) => prop_assert!(false, "bytes_per_pixel returned {other:?}"),
            }
        }
    }

    /// **The generator's reach, asserted rather than assumed** — the bar the `nscodec` property
    /// failed. A no-panic property that never gets past the depth gate asserts the gate, and
    /// nothing about a green run says which it did. This walks the same strategy space
    /// deterministically and requires that it produces both real conversions and refusals.
    #[test]
    fn the_generator_reaches_past_the_depth_gate() {
        let mut converted = 0usize;
        let mut refused = 0usize;
        for (w, h, bits) in [
            (2usize, 2usize, 8u16),
            (2, 2, 15),
            (2, 2, 16),
            (2, 2, 24),
            (2, 2, 32),
            (0, 0, 32),
            (70_000, 70_000, 32),
            (2, 2, 7),
        ] {
            let src = vec![0xA5u8; 1024];
            match to_rgba(&src, w, h, bits, &Palette::default(), false) {
                Ok(_) => converted += 1,
                Err(_) => refused += 1,
            }
        }
        assert!(
            converted >= 5,
            "only {converted} of the supported depths converted"
        );
        assert!(
            refused >= 2,
            "only {refused} refusals — the guards are not being reached"
        );
    }

    #[test]
    fn short_source_is_a_typed_error() {
        assert_eq!(
            to_rgba(&[0; 5], 2, 1, 24, &Palette::default(), false),
            Err(ColorError::SourceTooShort { needed: 6, got: 5 })
        );
        assert!(matches!(
            to_rgba(&[], 1, 1, 12, &Palette::default(), false),
            Err(ColorError::UnsupportedBitsPerPixel { bits_per_pixel: 12 })
        ));
    }

    /// **A hang is not a red.** `to_rgba_is_total_over_arbitrary_dimensions` above cannot
    /// observe non-termination — a seed that does not terminate makes the property *hang*
    /// rather than fail, which is how a `width == 0` draw cost four `test.yml` runs six
    /// runner-hours each before anyone read the cancelled log (#262). So the bound is
    /// asserted here explicitly instead of being left to the harness: the call is driven on
    /// a worker thread and this test fails at the deadline rather than waiting with it.
    #[test]
    fn to_rgba_returns_promptly_for_a_zero_extent_of_any_height() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // `width == 0` passes every guard rather than tripping one: `0 * bpp` is 0,
            // `0 * height` is 0, and `src.len() < 0` is false, so the source-length check
            // *succeeds* where the 60_000..=70_000 arm's comment assumed it refuses. Only
            // the row loop is unbounded, and `height` is a bare `usize`.
            let _ = tx.send(to_rgba(&[], 0, usize::MAX, 32, &Palette::default(), false));
        });
        let out = rx
            .recv_timeout(core::time::Duration::from_secs(5))
            .expect("to_rgba did not return within 5s for a zero-width rectangle");
        assert_eq!(out, Ok(Vec::new()));

        // **A second witness below `usize::MAX`, because the extreme is the point that lies.**
        // `nscodec::reconstruct` has this same hole, and probing it at `usize::MAX` alone reports
        // "returns promptly" — an unchecked multiply in its `temp_dims` panics before its loop is
        // reached, so the extreme masks the hang that lives one bit down. Nothing in `to_rgba`
        // does arithmetic ahead of the guard today; this pins that it stays that way, and keeps
        // the assertion shape transferable to the sibling. `1 << 30` rather than `1 << 34` so the
        // witness is a legal `usize` on the 32-bit target the overflow gate runs.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(to_rgba(
                &[],
                0,
                1usize << 30,
                32,
                &Palette::default(),
                false,
            ));
        });
        assert_eq!(
            rx.recv_timeout(core::time::Duration::from_secs(5)),
            Ok(Ok(Vec::new()))
        );

        // A non-empty source at a zero extent: the guard returns before reading `src`, so no
        // source byte reaches the output. Unasserted otherwise — every case above passes `&[]`,
        // which cannot tell "returned early" from "read nothing because there was nothing".
        assert_eq!(
            to_rgba(&[1, 2, 3, 4], 0, 8, 32, &Palette::default(), false),
            Ok(Vec::new())
        );
        // …and on the flipping path, which takes a different branch inside the loop.
        assert_eq!(
            to_rgba(&[1, 2, 3, 4], 0, 8, 32, &Palette::default(), true),
            Ok(Vec::new())
        );

        // The guard sits **after** the depth check, so an unsupported depth is still reported at
        // a zero extent. That is the one consequence of the placement a caller can observe, and
        // it is pinned here because the opposite order is equally total and was the tempting one:
        // `pointer::decode_pointer` guards first, but its zero case is a protocol semantic a
        // bitmap does not share. Moving the guard above `bytes_per_pixel` turns this red.
        assert!(matches!(
            to_rgba(&[], 5, 0, 999, &Palette::default(), false),
            Err(ColorError::UnsupportedBitsPerPixel {
                bits_per_pixel: 999
            })
        ));
    }
}
