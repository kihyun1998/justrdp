//! Differential oracle for the slow-path codecs (ADR-0003): identical bytes through our
//! decoders and `ironrdp-graphics`' must produce byte-identical pixels. Inputs come from a
//! seeded synthetic stream generator (interleaved RLE — every order code, all four depths),
//! from ironrdp's own RDP6 encoder, and from hand-built RDP6 streams covering the AYCoCg and
//! subsampling variants.

use justrdp_codecs::{planar, rle};

/// A tiny deterministic LCG so the generator needs no RNG dependency (and no wall clock).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        // Numerical Recipes constants.
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Build a syntactically valid interleaved-RLE stream that fills exactly `width × height`
/// pixels, exercising a seeded mix of order codes (including MEGA/LITE/SPECIAL forms).
fn generate_rle_stream(seed: u64, width: usize, height: usize, pixel_size: usize) -> Vec<u8> {
    let mut lcg = Lcg(seed);
    let total = width * height;
    let mut emitted = 0usize;
    let mut out = Vec::new();
    let mut wrote_non_bg = false;

    let push_pixel = |out: &mut Vec<u8>, lcg: &mut Lcg| {
        for _ in 0..pixel_size {
            out.push(lcg.next() as u8);
        }
    };

    while emitted < total {
        let remaining = total - emitted;
        match lcg.below(10) {
            // Background run (regular). On a fresh stream this writes black / copies above.
            0 | 1 => {
                let run = 1 + lcg.below(remaining.min(31));
                out.push((run & 0x1F) as u8); // code 0 << 5 | run
                emitted += run;
            }
            // Foreground run (regular), always paired with a color run: the oracle requires
            // one pixel's worth of bytes to remain in the stream right after a regular FG run
            // header (it sizes the read before distinguishing the SET variants), so the
            // color-run header + pixel that follows keeps ironrdp satisfied.
            2 if remaining >= 2 => {
                let run = 1 + lcg.below((remaining - 1).min(31));
                out.push(0x20 | (run & 0x1F) as u8); // code 1 << 5
                emitted += run;
                let pair = 1 + lcg.below((total - emitted).min(31));
                out.push(0x60 | (pair & 0x1F) as u8);
                push_pixel(&mut out, &mut lcg);
                emitted += pair;
                wrote_non_bg = true;
            }
            // Lite SET-FG foreground run.
            3 => {
                let run = 1 + lcg.below(remaining.min(15));
                out.push(0xC0 | (run & 0x0F) as u8);
                push_pixel(&mut out, &mut lcg);
                emitted += run;
                wrote_non_bg = true;
            }
            // Color run (regular).
            4 => {
                let run = 1 + lcg.below(remaining.min(31));
                out.push(0x60 | (run & 0x1F) as u8); // code 3 << 5
                push_pixel(&mut out, &mut lcg);
                emitted += run;
                wrote_non_bg = true;
            }
            // Color image (MEGA_MEGA form to cover the 16-bit length path).
            5 => {
                let run = 1 + lcg.below(remaining.min(300));
                out.push(0xF4);
                out.extend_from_slice(&(run as u16).to_le_bytes());
                for _ in 0..run {
                    push_pixel(&mut out, &mut lcg);
                }
                emitted += run;
                wrote_non_bg = true;
            }
            // Dithered run (lite): writes pixel pairs.
            6 if remaining >= 2 => {
                let pairs = 1 + lcg.below((remaining / 2).min(15));
                out.push(0xE0 | (pairs & 0x0F) as u8);
                push_pixel(&mut out, &mut lcg);
                push_pixel(&mut out, &mut lcg);
                emitted += pairs * 2;
                wrote_non_bg = true;
            }
            // FGBG image (regular, multiple-of-8 form).
            7 if remaining >= 8 => {
                let octets = 1 + lcg.below((remaining / 8).min(31));
                out.push(0x40 | (octets & 0x1F) as u8); // code 2 << 5, run = octets * 8
                for _ in 0..octets {
                    out.push(lcg.next() as u8);
                }
                emitted += octets * 8;
                wrote_non_bg = true;
            }
            // Special white/black single pixels.
            8 => {
                out.push(if lcg.below(2) == 0 { 0xFD } else { 0xFE });
                emitted += 1;
                wrote_non_bg = true;
            }
            // Special FGBG orders (8 fixed pixels).
            _ if remaining >= 8 && wrote_non_bg => {
                out.push(if lcg.below(2) == 0 { 0xF9 } else { 0xFA });
                emitted += 8;
            }
            _ => {
                // Fallback: single-pixel color run keeps the budget exact.
                out.push(0x61);
                push_pixel(&mut out, &mut lcg);
                emitted += 1;
                wrote_non_bg = true;
            }
        }
    }
    assert_eq!(emitted, total, "generator must fill the image exactly");
    out
}

#[test]
fn interleaved_rle_matches_ironrdp_on_generated_streams() {
    for (bpp, pixel_size) in [(8u16, 1usize), (15, 2), (16, 2), (24, 3)] {
        for seed in 0..32u64 {
            let width = 8 + (seed as usize % 5) * 13; // 8..60, not byte-aligned friendly
            let height = 1 + (seed as usize % 7) * 9; // 1..55
            let stream = generate_rle_stream(seed * 4 + u64::from(bpp), width, height, pixel_size);

            let ours = rle::decompress(&stream, width, height, bpp)
                .unwrap_or_else(|e| panic!("ours failed (bpp {bpp} seed {seed}): {e}"));

            let mut theirs = Vec::new();
            ironrdp_graphics::rle::decompress(&stream, &mut theirs, width, height, bpp as usize)
                .unwrap_or_else(|e| panic!("oracle failed (bpp {bpp} seed {seed}): {e:?}"));

            assert_eq!(
                ours, theirs,
                "pixel divergence at bpp {bpp}, seed {seed}, {width}x{height}"
            );
        }
    }
}

#[test]
fn interleaved_rle_rejects_what_the_oracle_rejects() {
    // A stream that overruns the image must fail in both stacks (no silent truncation).
    let stream = [0x7F, 0xAB]; // COLOR_RUN of 31 pixels into a 4-pixel image
    assert!(rle::decompress(&stream, 4, 1, 8).is_err());
    let mut theirs = Vec::new();
    assert!(ironrdp_graphics::rle::decompress(&stream, &mut theirs, 4, 1, 8).is_err());
}

/// Build a deterministic RGB24 test image with gradients and hard edges.
fn test_image(width: usize, height: usize, seed: u64) -> Vec<u8> {
    let mut lcg = Lcg(seed);
    let mut img = Vec::with_capacity(width * height * 3);
    for y in 0..height {
        for x in 0..width {
            if (x / 8 + y / 8) % 2 == 0 {
                img.extend_from_slice(&[(x * 4) as u8, (y * 4) as u8, ((x + y) * 2) as u8]);
            } else {
                // Noise blocks defeat trivial RLE so raw segments appear too.
                img.extend_from_slice(&[lcg.next() as u8, lcg.next() as u8, lcg.next() as u8]);
            }
        }
    }
    img
}

#[test]
fn rdp6_planar_decodes_ironrdp_encoder_output_identically() {
    use ironrdp_graphics::rdp6::{BitmapStreamDecoder, BitmapStreamEncoder, RgbChannels};

    for (width, height, rle_mode, seed) in [
        (32usize, 64usize, false, 1u64),
        (32, 64, true, 2),
        (64, 24, true, 3),
        (33, 17, true, 4), // odd dimensions
        (33, 17, false, 5),
    ] {
        let image = test_image(width, height, seed);
        let mut stream = vec![0u8; width * height * 4 + 2];
        let written = BitmapStreamEncoder::new(width, height)
            .encode_bitmap::<RgbChannels>(&image, &mut stream, rle_mode)
            .expect("ironrdp encodes the test image");
        let stream = &stream[..written];

        // Their decoder (RGB24) on their encoder's bytes…
        let mut theirs = Vec::new();
        BitmapStreamDecoder::default()
            .decode_bitmap_stream_to_rgb24(stream, &mut theirs, width, height)
            .expect("oracle decodes its own stream");

        // …and ours (BGR24) on the same bytes: identical pixels modulo the documented
        // channel order of each API.
        let ours = planar::decompress(stream, width, height).expect("ours decodes the stream");
        let ours_as_rgb: Vec<u8> = ours
            .chunks_exact(3)
            .flat_map(|bgr| [bgr[2], bgr[1], bgr[0]])
            .collect();
        assert_eq!(
            ours_as_rgb, theirs,
            "planar divergence at {width}x{height} rle={rle_mode}"
        );
    }
}

#[test]
fn rdp6_aycocg_variants_match_the_oracle_decoder() {
    use ironrdp_graphics::rdp6::BitmapStreamDecoder;

    // Hand-built raw AYCoCg streams (CLL 1..3, with and without subsampling/alpha) — the
    // encoder above only emits the ARGB definition, so these cover the color-transform path.
    for (cll, subsample, alpha) in [
        (1u8, false, false),
        (2, false, false),
        (3, false, false),
        (1, true, false),
        (2, true, true),
    ] {
        let (width, height) = (6usize, 4usize);
        let (cw, ch) = if subsample {
            (width.div_ceil(2), height.div_ceil(2))
        } else {
            (width, height)
        };
        let mut header = cll;
        if subsample {
            header |= 0x08;
        }
        if !alpha {
            header |= 0x20;
        }
        let mut lcg = Lcg(u64::from(cll) * 100 + u64::from(subsample));
        let mut stream = vec![header];
        if alpha {
            stream.extend(std::iter::repeat_n(0xFF, width * height));
        }
        for _ in 0..width * height {
            stream.push(lcg.next() as u8); // Y
        }
        for _ in 0..2 * cw * ch {
            // Keep chroma small so the (lossy) shift-back stays in the same range for any
            // decoder interpretation.
            stream.push((lcg.next() % 32) as u8);
        }
        stream.push(0); // pad

        let mut theirs = Vec::new();
        BitmapStreamDecoder::default()
            .decode_bitmap_stream_to_rgb24(&stream, &mut theirs, width, height)
            .expect("oracle decodes the AYCoCg stream");
        let ours = planar::decompress(&stream, width, height).expect("ours decodes it too");
        let ours_as_rgb: Vec<u8> = ours
            .chunks_exact(3)
            .flat_map(|bgr| [bgr[2], bgr[1], bgr[0]])
            .collect();
        assert_eq!(
            ours_as_rgb, theirs,
            "AYCoCg divergence at cll={cll} cs={subsample} alpha={alpha}"
        );
    }
}
