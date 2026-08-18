//! RemoteFX dequantization and LL3 delta reconstruction (MS-RDPRFX 3.1.8.1.4 / 3.1.8.1.5) —
//! the two cheap inverse stages between RLGR entropy decode and the inverse DWT. Self-owned
//! (ADR-0003 phase-2); equivalence with the `ironrdp-graphics` `quantization` and
//! `subband_reconstruction` primitives is proven by the ADR-0007 stage-boundary tests.
//!
//! The 4096-coefficient component buffer is laid out linearly per subband, the spec's
//! coefficient order: `HL1 LH1 HH1` (1024 each), `HL2 LH2 HH2` (256 each), then
//! `HL3 LH3 HH3 LL3` (64 each).

use justrdp_pdu::rfx::Quant;

/// The coefficient count of one tile component (64×64).
pub const COMPONENT_LEN: usize = 64 * 64;
/// Offset of the LL3 subband — the last 64 coefficients.
pub const LL3_OFFSET: usize = COMPONENT_LEN - 64;

/// The ten subbands of one tile component as `(offset, length)`, in the order every
/// `RFX_COMPONENT_CODEC_QUANT` packs its nibbles: `HL1 LH1 HH1 HL2 LH2 HH2 HL3 LH3 HH3 LL3`.
///
/// This is the **classic / non-extrapolate** layout — symmetric bands, `LL3` last at
/// [`LL3_OFFSET`]. WireToSurface1 always uses it; Progressive uses it only for a region that
/// omits `RFX_DWT_REDUCE_EXTRAPOLATE` (`progressive.c:876-899`).
pub const BANDS_STANDARD: [(usize, usize); 10] = [
    (0, 1024),
    (1024, 1024),
    (2048, 1024),
    (3072, 256),
    (3328, 256),
    (3584, 256),
    (3840, 64),
    (3904, 64),
    (3968, 64),
    (4032, 64),
];

/// The same ten subbands under **reduce-extrapolate** (`progressive.c:901-921`), which is the
/// live Progressive layout: every real region in the corpus sets `RFX_DWT_REDUCE_EXTRAPOLATE`.
///
/// The bands are asymmetric because an `n`-sample line splits `low = (n + 2) / 2`,
/// `high = n - low` rather than in half — 64 → 33/31, 33 → 17/16, 17 → 9/8 — so **every band
/// differs from [`BANDS_STANDARD`], not only `LL3`**. Reading one layout's coefficients with
/// the other's offsets still produces plausible pixels, which is why the two tables are named
/// rather than computed at each call site (#167's recorded failure mode).
pub const BANDS_EXTRAPOLATE: [(usize, usize); 10] = [
    (0, 1023),
    (1023, 1023),
    (2046, 961),
    (3007, 272),
    (3279, 272),
    (3551, 256),
    (3807, 72),
    (3879, 72),
    (3951, 64),
    (4015, 81),
];

/// Undo scalar quantization in place: each subband's coefficients shift left by its quant
/// exponent − 1 (an exponent of 0 or 1 leaves the band untouched).
pub fn dequantize(buffer: &mut [i16], quant: &Quant) {
    debug_assert_eq!(buffer.len(), COMPONENT_LEN);
    let bands: [(usize, usize, u8); 10] = [
        (0, 1024, quant.hl1),
        (1024, 1024, quant.lh1),
        (2048, 1024, quant.hh1),
        (3072, 256, quant.hl2),
        (3328, 256, quant.lh2),
        (3584, 256, quant.hh2),
        (3840, 64, quant.hl3),
        (3904, 64, quant.lh3),
        (3968, 64, quant.hh3),
        (4032, 64, quant.ll3),
    ];
    for (offset, len, q) in bands {
        let factor = i16::from(q) - 1;
        if factor > 0 {
            for value in &mut buffer[offset..offset + len] {
                *value <<= factor;
            }
        }
    }
}

/// Undo the LL3 band's differential coding in place: a running (wrapping) prefix sum over
/// the lowpass coefficients, which the encoder stored as successive deltas.
pub fn ll3_delta_decode(ll3: &mut [i16]) {
    for i in 1..ll3.len() {
        ll3[i] = ll3[i].wrapping_add(ll3[i - 1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dequantize_shifts_each_band_by_its_own_exponent() {
        let quant = Quant {
            ll3: 6,
            lh3: 1,
            hl3: 0,
            hh3: 2,
            lh2: 7,
            hl2: 1,
            hh2: 8,
            lh1: 8,
            hl1: 1,
            hh1: 9,
        };
        let mut buffer = vec![1i16; COMPONENT_LEN];
        dequantize(&mut buffer, &quant);
        assert_eq!(buffer[0], 1); // HL1, exponent 1 → untouched
        assert_eq!(buffer[1024], 1 << 7); // LH1, exponent 8
        assert_eq!(buffer[2048], 1 << 8); // HH1, exponent 9
        assert_eq!(buffer[3072], 1); // HL2, exponent 1
        assert_eq!(buffer[3328], 1 << 6); // LH2, exponent 7
        assert_eq!(buffer[3584], 1 << 7); // HH2, exponent 8
        assert_eq!(buffer[3840], 1); // HL3, exponent 0
        assert_eq!(buffer[3904], 1); // LH3, exponent 1
        assert_eq!(buffer[3968], 1 << 1); // HH3, exponent 2
        assert_eq!(buffer[LL3_OFFSET], 1 << 5); // LL3, exponent 6
    }

    #[test]
    fn both_band_layouts_tile_the_component_exactly_once() {
        // A silently transposed or short band is this territory's recorded failure mode
        // (#167): the wrong reading still decodes. Pin that each table covers 0..4096 with
        // no gap and no overlap, in the order the quant nibbles are packed.
        for (name, bands) in [
            ("standard", BANDS_STANDARD),
            ("extrapolate", BANDS_EXTRAPOLATE),
        ] {
            let mut next = 0usize;
            for (offset, length) in bands {
                assert_eq!(offset, next, "{name} band starts at a gap or an overlap");
                next += length;
            }
            assert_eq!(next, COMPONENT_LEN, "{name} bands must tile the component");
        }
    }

    #[test]
    fn the_two_layouts_disagree_in_every_band_but_the_first() {
        // The reason both tables exist. HL1 is the only band that starts at the same offset,
        // and even it has a different length — so a decoder that picks the wrong table is
        // wrong everywhere, not just in LL3 (which is the half the epic originally recorded).
        assert_eq!(BANDS_STANDARD[0].0, BANDS_EXTRAPOLATE[0].0);
        for band in 0..10 {
            assert_ne!(
                BANDS_STANDARD[band], BANDS_EXTRAPOLATE[band],
                "band {band} must differ between the layouts"
            );
        }
        assert_eq!(BANDS_STANDARD[9], (LL3_OFFSET, 64));
        assert_eq!(BANDS_EXTRAPOLATE[9], (4015, 81));
    }

    #[test]
    fn ll3_delta_decode_is_a_wrapping_prefix_sum() {
        let mut band = [1i16, 2, 3, 4];
        ll3_delta_decode(&mut band);
        assert_eq!(band, [1, 3, 6, 10]);
        let mut extremes = [i16::MIN, i16::MIN];
        ll3_delta_decode(&mut extremes);
        assert_eq!(extremes, [i16::MIN, 0]);
    }
}
