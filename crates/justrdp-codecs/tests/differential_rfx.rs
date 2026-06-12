//! Differential oracle for the self-owned WireToSurface1 RemoteFX decoder (issue #58,
//! ADR-0007). `ironrdp-graphics` exposes no assembled RemoteFX decoder — only the transform
//! *primitives* — so correctness is proven two complementary ways instead of one end-to-end
//! byte-diff (the ClearCodec recipe):
//!
//! - **(A) stage-boundary**: each inverse stage of our pipeline (RLGR → LL3 delta →
//!   dequantize → inverse DWT → ICT) is fed the same intermediate buffer as the matching
//!   oracle primitive and must produce byte-identical output;
//! - **(B) composed reference**: the oracle's primitives are glued in spec order into a
//!   reference decoder, and our full-payload RGBA must match it byte for byte on synthetic
//!   TS_RFX streams (container encoded by `ironrdp-pdu`, tile payloads by
//!   `rfx_encode_component`).
//!
//! The real VM never emits CAVIDEO (V8+ servers prefer Progressive), so synthetic streams
//! are the corpus — and a corpus only tests what it generates, hence the coverage guards:
//! every test asserts both RLGR1 and RLGR3 were actually exercised.

use ironrdp_graphics::color_conversion::{self, YCbCrBuffer};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_graphics::{dwt, quantization, rfx_encode_component, rlgr, subband_reconstruction};
use ironrdp_pdu::codecs::rfx as oracle_rfx;
use ironrdp_pdu::{ReadCursor, decode_cursor, encode_vec};

use justrdp_codecs::color;
use justrdp_codecs::rfx as ours;

const TILE_PIXELS: usize = 64 * 64;

/// Both entropy modes, paired across the two crates' types.
const MODES: [(oracle_rfx::EntropyAlgorithm, &str); 2] = [
    (oracle_rfx::EntropyAlgorithm::Rlgr1, "RLGR1"),
    (oracle_rfx::EntropyAlgorithm::Rlgr3, "RLGR3"),
];

// ---------------------------------------------------------------- input patterns

fn flat(r: u8, g: u8, b: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(TILE_PIXELS * 4);
    for _ in 0..TILE_PIXELS {
        out.extend_from_slice(&[r, g, b, 255]);
    }
    out
}

fn gradient() -> Vec<u8> {
    let mut out = Vec::with_capacity(TILE_PIXELS * 4);
    for y in 0..64u16 {
        for x in 0..64u16 {
            out.extend_from_slice(&[(x * 4) as u8, (y * 4) as u8, ((x + y) * 2) as u8, 255]);
        }
    }
    out
}

/// Deterministic xorshift noise — exercises the RLGR Golomb-Rice paths that smooth
/// patterns never reach.
fn noise(mut seed: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(TILE_PIXELS * 4);
    for _ in 0..TILE_PIXELS {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let [r, g, b, _] = seed.to_le_bytes();
        out.extend_from_slice(&[r, g, b, 255]);
    }
    out
}

fn patterns() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("flat", flat(40, 180, 220)),
        ("gradient", gradient()),
        ("noise", noise(0x1234_5678)),
        ("noise2", noise(0xCAFE_F00D)),
    ]
}

// ---------------------------------------------------------------- shared helpers

/// RGBA tile → the three pixel-domain YCbCr planes the encoder consumes.
fn to_planes(rgba: &[u8]) -> ([i16; TILE_PIXELS], [i16; TILE_PIXELS], [i16; TILE_PIXELS]) {
    let mut y = [0i16; TILE_PIXELS];
    let mut cb = [0i16; TILE_PIXELS];
    let mut cr = [0i16; TILE_PIXELS];
    color_conversion::to_64x64_ycbcr_tile(
        rgba,
        64,
        64,
        64 * 4,
        PixelFormat::RgbA32,
        &mut y,
        &mut cb,
        &mut cr,
    )
    .expect("oracle forward color transform");
    (y, cb, cr)
}

// ------------------------------------------------- the harness's spec-correct RLGR encoder
//
// The oracle's RLGR1 *encoder* is defective: in Golomb-Rice mode it adapts `kp` by `UP_GR`
// (4) on a zero value where MS-RDPRFX 3.1.8.1.7 — and FreeRDP's encoder *and* decoder, and
// the oracle's own decoder — use `UQ_GR` (3). The k-state desyncs after the first GR-coded
// zero, and the stream decodes to garbage on every spec-correct decoder including ironrdp's
// own (`oracle_rlgr1_encoder_defect_still_present` below pins this down). So the stream
// factory entropy stage is this harness encoder: the forward transforms stay the oracle's,
// and `harness_encoder_is_faithful_by_the_oracles_own_decoder` proves the factory honest
// with the oracle's *decoder* as the judge — not self-referentially.

const KP_MAX: u32 = 80;
const LS_GR: u32 = 3;
const UP_GR: u32 = 4;
const DN_GR: u32 = 6;
const UQ_GR: u32 = 3;
const DQ_GR: u32 = 3;

/// An MSB-first bit accumulator.
#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    used: usize,
}

impl BitWriter {
    fn push_bit(&mut self, bit: bool) {
        if self.used.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit {
            let last = self.bytes.last_mut().unwrap();
            *last |= 1 << (7 - (self.used % 8));
        }
        self.used += 1;
    }

    fn push_bits(&mut self, n: usize, val: u32) {
        for i in (0..n).rev() {
            self.push_bit((val >> i) & 1 != 0);
        }
    }
}

fn two_mag_sign(v: i16) -> u32 {
    u32::from(v.unsigned_abs()) * 2 - u32::from(v < 0)
}

fn write_gr(w: &mut BitWriter, krp: &mut u32, val: u32) {
    let kr = *krp >> LS_GR;
    let vk = val >> kr;
    for _ in 0..vk {
        w.push_bit(true);
    }
    w.push_bit(false);
    if kr != 0 {
        w.push_bits(kr as usize, val & ((1 << kr) - 1));
    }
    if vk == 0 {
        *krp = krp.saturating_sub(2);
    } else if vk > 1 {
        *krp = (*krp + vk).min(KP_MAX);
    }
}

fn harness_rlgr_encode(mode: oracle_rfx::EntropyAlgorithm, input: &[i16]) -> Vec<u8> {
    let mut k: u32 = 1;
    let mut kp: u32 = k << LS_GR;
    let mut krp: u32 = 1 << LS_GR;
    let mut w = BitWriter::default();
    let mut i = 0usize;
    while i < input.len() {
        if k != 0 {
            // Run-length mode.
            let mut nz: u32 = 0;
            while i < input.len() && input[i] == 0 {
                nz += 1;
                i += 1;
            }
            let mut runmax = 1u32 << k;
            while nz >= runmax {
                w.push_bit(false);
                nz -= runmax;
                kp = (kp + UP_GR).min(KP_MAX);
                k = kp >> LS_GR;
                runmax = 1 << k;
            }
            w.push_bit(true);
            w.push_bits(k as usize, nz);
            if i < input.len() {
                let val = input[i];
                i += 1;
                w.push_bit(val < 0);
                write_gr(&mut w, &mut krp, u32::from(val.unsigned_abs()) - 1);
            }
            kp = kp.saturating_sub(DN_GR);
            k = kp >> LS_GR;
        } else {
            match mode {
                oracle_rfx::EntropyAlgorithm::Rlgr1 => {
                    let two_ms = two_mag_sign(input[i]);
                    i += 1;
                    write_gr(&mut w, &mut krp, two_ms);
                    if two_ms == 0 {
                        kp = (kp + UQ_GR).min(KP_MAX); // the spec's UQ_GR — not UP_GR
                    } else {
                        kp = kp.saturating_sub(DQ_GR);
                    }
                    k = kp >> LS_GR;
                }
                oracle_rfx::EntropyAlgorithm::Rlgr3 => {
                    let m1 = two_mag_sign(input[i]);
                    i += 1;
                    let m2 = if i < input.len() {
                        let m = two_mag_sign(input[i]);
                        i += 1;
                        m
                    } else {
                        1
                    };
                    let sum = m1 + m2;
                    write_gr(&mut w, &mut krp, sum);
                    let n = 32 - sum.leading_zeros();
                    if n != 0 {
                        w.push_bits(n as usize, m1);
                    }
                    if m1 != 0 && m2 != 0 {
                        kp = kp.saturating_sub(2 * DQ_GR);
                        k = kp >> LS_GR;
                    } else if m1 == 0 && m2 == 0 {
                        kp = (kp + 2 * UQ_GR).min(KP_MAX);
                        k = kp >> LS_GR;
                    }
                }
            }
        }
    }
    w.bytes
}

/// The oracle's forward transforms up to the entropy stage.
fn forward_coefficients(
    plane: &[i16; TILE_PIXELS],
    quant: &oracle_rfx::Quant,
) -> [i16; TILE_PIXELS] {
    let mut work = *plane;
    let mut temp = [0i16; TILE_PIXELS];
    dwt::encode(&mut work, &mut temp);
    quantization::encode(&mut work, quant);
    subband_reconstruction::encode(&mut work[4032..]);
    work
}

/// Encode one component plane into its RLGR byte stream: oracle forward transforms +
/// the harness's spec-correct entropy coder (see the block comment above).
fn encode_component(
    plane: &[i16; TILE_PIXELS],
    quant: &oracle_rfx::Quant,
    mode: oracle_rfx::EntropyAlgorithm,
) -> Vec<u8> {
    harness_rlgr_encode(mode, &forward_coefficients(plane, quant))
}

fn our_quant(q: &oracle_rfx::Quant) -> justrdp_pdu::rfx::Quant {
    justrdp_pdu::rfx::Quant {
        ll3: q.ll3,
        lh3: q.lh3,
        hl3: q.hl3,
        hh3: q.hh3,
        lh2: q.lh2,
        hl2: q.hl2,
        hh2: q.hh2,
        lh1: q.lh1,
        hl1: q.hl1,
        hh1: q.hh1,
    }
}

fn our_mode(mode: oracle_rfx::EntropyAlgorithm) -> justrdp_pdu::rfx::EntropyAlgorithm {
    match mode {
        oracle_rfx::EntropyAlgorithm::Rlgr1 => justrdp_pdu::rfx::EntropyAlgorithm::Rlgr1,
        oracle_rfx::EntropyAlgorithm::Rlgr3 => justrdp_pdu::rfx::EntropyAlgorithm::Rlgr3,
    }
}

/// A second, stronger quant table so the dequantize stage sees more than the default.
fn strong_quant() -> oracle_rfx::Quant {
    oracle_rfx::Quant {
        ll3: 8,
        lh3: 9,
        hl3: 9,
        hh3: 10,
        lh2: 10,
        hl2: 10,
        hh2: 11,
        lh1: 11,
        hl1: 11,
        hh1: 12,
    }
}

// ----------------------------------------------- stream-factory honesty (see block comment)

/// The harness encoder must be faithful with the **oracle's decoder** as the judge: for
/// both modes and every pattern, oracle-decode(harness-encode(x)) == x. This is what makes
/// the synthetic corpus a valid stream factory rather than a self-fulfilling fixture.
#[test]
fn harness_encoder_is_faithful_by_the_oracles_own_decoder() {
    for (mode, mode_name) in MODES {
        for (pattern_name, rgba) in patterns() {
            let (y, _, _) = to_planes(&rgba);
            let coefficients = forward_coefficients(&y, &oracle_rfx::Quant::default());
            let encoded = harness_rlgr_encode(mode, &coefficients);
            let mut decoded = [0i16; TILE_PIXELS];
            rlgr::decode(mode, &encoded, &mut decoded).expect("oracle decodes harness streams");
            assert_eq!(
                decoded, coefficients,
                "harness encoder unfaithful ({mode_name}/{pattern_name})"
            );
        }
    }
}

/// Canary for the oracle defect the harness encoder works around: `ironrdp-graphics` 0.8's
/// RLGR1 *encoder* adapts `kp` by `UP_GR` where the spec (and its own decoder, and FreeRDP's
/// encoder and decoder) use `UQ_GR`, so its RLGR1 round-trip desyncs — while RLGR3 stays
/// exact. When an oracle upgrade makes this test fail, the defect is fixed upstream: drop
/// `harness_rlgr_encode` and feed `rfx_encode_component` directly (the #56 pattern).
#[test]
fn oracle_rlgr1_encoder_defect_still_present() {
    let (y, _, _) = to_planes(&noise(0x1234_5678));
    let quant = oracle_rfx::Quant::default();
    let mut mismatches = [0usize; 2];
    for (idx, (mode, _)) in MODES.into_iter().enumerate() {
        let mut work = y;
        let mut encoded = vec![0u8; 4 * TILE_PIXELS];
        let len = rfx_encode_component(&mut work, &mut encoded, &quant, mode)
            .expect("oracle encoder runs");
        encoded.truncate(len);
        let mut decoded = [0i16; TILE_PIXELS];
        rlgr::decode(mode, &encoded, &mut decoded).expect("oracle decodes its own stream");
        let expected = forward_coefficients(&y, &quant);
        mismatches[idx] = expected
            .iter()
            .zip(decoded.iter())
            .filter(|(a, b)| a != b)
            .count();
    }
    assert!(
        mismatches[0] > 0,
        "the oracle's RLGR1 encoder round-trips now — defect fixed upstream, simplify the harness"
    );
    assert_eq!(
        mismatches[1], 0,
        "the oracle's RLGR3 round-trip must stay exact"
    );
}

// ---------------------------------------------------------------- (A) stage-boundary

/// Walk every (mode × quant × pattern × component) through the inverse chain, comparing our
/// stage output with the oracle primitive's at **every** boundary. A mismatch names the
/// stage that diverged — the whole point of ADR-0007's shape (an end-to-end diff alone
/// cannot localize the failing transform).
#[test]
fn every_inverse_stage_matches_the_oracle_primitive_at_its_boundary() {
    let mut exercised = [0usize; 2];
    for (mode_idx, (mode, mode_name)) in MODES.into_iter().enumerate() {
        for quant in [oracle_rfx::Quant::default(), strong_quant()] {
            for (pattern_name, rgba) in patterns() {
                let (y, cb, cr) = to_planes(&rgba);
                for (component_name, plane) in [("Y", &y), ("Cb", &cb), ("Cr", &cr)] {
                    let ctx = format!("{mode_name}/{pattern_name}/{component_name}");
                    let encoded = encode_component(plane, &quant, mode);

                    // Stage 1: RLGR entropy decode.
                    let mut theirs = [0i16; TILE_PIXELS];
                    rlgr::decode(mode, &encoded, &mut theirs).expect("oracle rlgr");
                    let mut mine = [0i16; TILE_PIXELS];
                    ours::rlgr::decode(our_mode(mode), &encoded, &mut mine).expect("our rlgr");
                    assert_eq!(mine, theirs, "RLGR diverged ({ctx})");

                    // Stage 2: LL3 delta reconstruction.
                    subband_reconstruction::decode(&mut theirs[4032..]);
                    ours::quant::ll3_delta_decode(&mut mine[ours::quant::LL3_OFFSET..]);
                    assert_eq!(mine, theirs, "LL3 delta diverged ({ctx})");

                    // Stage 3: dequantization.
                    quantization::decode(&mut theirs, &quant);
                    ours::quant::dequantize(&mut mine, &our_quant(&quant));
                    assert_eq!(mine, theirs, "dequantize diverged ({ctx})");

                    // Stage 4: inverse DWT.
                    let mut their_temp = [0i16; TILE_PIXELS];
                    dwt::decode(&mut theirs, &mut their_temp);
                    let mut my_temp = [0i16; TILE_PIXELS];
                    ours::dwt::decode(&mut mine, &mut my_temp);
                    assert_eq!(mine, theirs, "inverse DWT diverged ({ctx})");

                    exercised[mode_idx] += 1;
                }
            }
        }
    }
    // Coverage guard: a corpus change must not silently drop an entropy mode.
    assert!(
        exercised.iter().all(|&n| n > 0),
        "both RLGR modes must be exercised, got {exercised:?}"
    );
}

/// Stage 5 (ICT) separately: it consumes all three planes at once, so it does not fit the
/// per-component walk above. Same inputs → byte-identical RGBA.
#[test]
fn the_ict_color_stage_matches_the_oracle_on_reconstructed_planes() {
    for (mode, mode_name) in MODES {
        for (pattern_name, rgba) in patterns() {
            let quant = oracle_rfx::Quant::default();
            let (y, cb, cr) = to_planes(&rgba);
            // Round-trip each plane through the oracle pipeline so the ICT sees realistic
            // (lossy-reconstructed) samples, not the pristine forward output.
            let reconstruct = |plane: &[i16; TILE_PIXELS]| {
                let encoded = encode_component(plane, &quant, mode);
                let mut buf = [0i16; TILE_PIXELS];
                rlgr::decode(mode, &encoded, &mut buf).expect("oracle rlgr");
                subband_reconstruction::decode(&mut buf[4032..]);
                quantization::decode(&mut buf, &quant);
                let mut temp = [0i16; TILE_PIXELS];
                dwt::decode(&mut buf, &mut temp);
                buf
            };
            let (ry, rcb, rcr) = (reconstruct(&y), reconstruct(&cb), reconstruct(&cr));

            let mut theirs = vec![0u8; TILE_PIXELS * 4];
            color_conversion::ycbcr_to_rgba(
                YCbCrBuffer {
                    y: &ry,
                    cb: &rcb,
                    cr: &rcr,
                },
                &mut theirs,
            )
            .expect("oracle ICT");
            let mut mine = vec![0u8; TILE_PIXELS * 4];
            color::rfx_ycbcr_to_rgba(&ry, &rcb, &rcr, &mut mine);
            assert_eq!(mine, theirs, "ICT diverged ({mode_name}/{pattern_name})");
        }
    }
}

// ---------------------------------------------------------------- (B) composed reference

/// One synthetic tile: grid position plus the three encoded component streams.
type EncodedTile = (u16, u16, Vec<u8>, Vec<u8>, Vec<u8>);

/// Encode a complete TS_RFX stream — headers plus one frame — with the oracle's encoders.
fn build_stream(
    mode: oracle_rfx::EntropyAlgorithm,
    quant: &oracle_rfx::Quant,
    rects: &[(u16, u16, u16, u16)],
    tiles: &[EncodedTile],
) -> Vec<u8> {
    use oracle_rfx::{
        Block, ChannelsPdu, CodecChannel, CodecVersionsPdu, ContextPdu, FrameBeginPdu, FrameEndPdu,
        OperatingMode, RegionPdu, RfxChannel, RfxRectangle, SyncPdu, Tile, TileSetPdu,
    };
    let mut out = Vec::new();
    let mut push = |block: Block<'_>| {
        out.extend_from_slice(&encode_vec(&block).expect("oracle encodes its own block"));
    };
    push(Block::Sync(SyncPdu));
    push(Block::CodecVersions(CodecVersionsPdu));
    push(Block::Channels(ChannelsPdu(vec![RfxChannel {
        width: 128,
        height: 128,
    }])));
    push(Block::CodecChannel(CodecChannel::Context(ContextPdu {
        flags: OperatingMode::IMAGE_MODE,
        entropy_algorithm: mode,
    })));
    push(Block::CodecChannel(CodecChannel::FrameBegin(
        FrameBeginPdu {
            index: 0,
            number_of_regions: 1,
        },
    )));
    push(Block::CodecChannel(CodecChannel::Region(RegionPdu {
        rectangles: rects
            .iter()
            .map(|&(x, y, width, height)| RfxRectangle {
                x,
                y,
                width,
                height,
            })
            .collect(),
    })));
    push(Block::CodecChannel(CodecChannel::TileSet(TileSetPdu {
        entropy_algorithm: mode,
        quants: vec![quant.clone()],
        tiles: tiles
            .iter()
            .map(|(x_idx, y_idx, y, cb, cr)| Tile {
                y_quant_index: 0,
                cb_quant_index: 0,
                cr_quant_index: 0,
                x: *x_idx,
                y: *y_idx,
                y_data: y,
                cb_data: cb,
                cr_data: cr,
            })
            .collect(),
    })));
    push(Block::CodecChannel(CodecChannel::FrameEnd(FrameEndPdu)));
    out
}

/// The reference decoder: the oracle's primitives glued in spec order — parse with
/// `ironrdp-pdu`, per tile RLGR → LL3 → dequantize → iDWT → ICT, composited with the same
/// region-clipped blit semantics our decoder implements.
fn reference_decode(data: &[u8], w: usize, h: usize) -> Vec<u8> {
    use oracle_rfx::{Block, CodecChannel};
    let mut out = vec![0u8; w * h * 4];
    for px in out.chunks_exact_mut(4) {
        px[3] = 255;
    }
    let mut cursor = ReadCursor::new(data);
    let mut region: Vec<(usize, usize, usize, usize)> = Vec::new();
    while !cursor.is_empty() {
        let block: Block<'_> = decode_cursor(&mut cursor).expect("oracle parses its own bytes");
        match block {
            Block::CodecChannel(CodecChannel::Region(r)) => {
                region = r
                    .rectangles
                    .iter()
                    .map(|rect| {
                        (
                            usize::from(rect.x),
                            usize::from(rect.y),
                            usize::from(rect.width),
                            usize::from(rect.height),
                        )
                    })
                    .collect();
            }
            Block::CodecChannel(CodecChannel::TileSet(ts)) => {
                let quant = &ts.quants[0];
                for tile in &ts.tiles {
                    let decode_plane = |bytes: &[u8]| {
                        let mut buf = [0i16; TILE_PIXELS];
                        rlgr::decode(ts.entropy_algorithm, bytes, &mut buf).expect("oracle rlgr");
                        subband_reconstruction::decode(&mut buf[4032..]);
                        quantization::decode(&mut buf, quant);
                        let mut temp = [0i16; TILE_PIXELS];
                        dwt::decode(&mut buf, &mut temp);
                        buf
                    };
                    let y = decode_plane(tile.y_data);
                    let cb = decode_plane(tile.cb_data);
                    let cr = decode_plane(tile.cr_data);
                    let mut rgba = vec![0u8; TILE_PIXELS * 4];
                    color_conversion::ycbcr_to_rgba(
                        YCbCrBuffer {
                            y: &y,
                            cb: &cb,
                            cr: &cr,
                        },
                        &mut rgba,
                    )
                    .expect("oracle ICT");
                    let (tx, ty) = (usize::from(tile.x) * 64, usize::from(tile.y) * 64);
                    for &(cx, cy, cw, ch) in &region {
                        let left = tx.max(cx).min(w);
                        let top = ty.max(cy).min(h);
                        let right = (tx + 64).min(cx + cw).min(w);
                        let bottom = (ty + 64).min(cy + ch).min(h);
                        for row in top..bottom {
                            if right <= left {
                                break;
                            }
                            let src = ((row - ty) * 64 + (left - tx)) * 4;
                            let dst = (row * w + left) * 4;
                            let len = (right - left) * 4;
                            out[dst..dst + len].copy_from_slice(&rgba[src..src + len]);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// (B): our full decoder against the composed reference, across both entropy modes, a 2×2
/// multi-tile frame, and a clipping region that cuts into the tiles — byte-identical RGBA.
#[test]
fn full_payload_rgba_matches_the_composed_oracle_reference() {
    let mut exercised = [0usize; 2];
    for (mode_idx, (mode, mode_name)) in MODES.into_iter().enumerate() {
        let quant = oracle_rfx::Quant::default();
        // Four distinct tiles in a 2×2 grid.
        let tile_patterns = [
            flat(200, 30, 30),
            gradient(),
            noise(0xBEEF_BABE),
            flat(0, 0, 0),
        ];
        let tiles: Vec<EncodedTile> = tile_patterns
            .iter()
            .enumerate()
            .map(|(i, rgba)| {
                let (y, cb, cr) = to_planes(rgba);
                (
                    (i % 2) as u16,
                    (i / 2) as u16,
                    encode_component(&y, &quant, mode),
                    encode_component(&cb, &quant, mode),
                    encode_component(&cr, &quant, mode),
                )
            })
            .collect();

        for (case, rects) in [
            ("full region", vec![(0u16, 0u16, 128u16, 128u16)]),
            // A region that cuts into the tiles: clipping must agree byte for byte.
            ("clipped region", vec![(10, 10, 80, 100)]),
            // Two overlapping rects: double-blit of identical pixels, same both sides.
            ("overlapping rects", vec![(0, 0, 70, 70), (50, 50, 78, 78)]),
        ] {
            let stream = build_stream(mode, &quant, &rects, &tiles);
            let mut decoder = ours::RemoteFx::new();
            let mine = decoder
                .decode_to_rgba(&stream, 128, 128)
                .expect("our decoder accepts the oracle's stream")
                .expect("a tileset paints");
            let theirs = reference_decode(&stream, 128, 128);
            assert_eq!(
                mine, theirs,
                "composed reference diverged ({mode_name}, {case})"
            );
            exercised[mode_idx] += 1;
        }
    }
    assert!(
        exercised.iter().all(|&n| n > 0),
        "both RLGR modes must be exercised, got {exercised:?}"
    );
}
