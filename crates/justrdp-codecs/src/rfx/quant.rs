//! RemoteFX dequantization and LL3 delta reconstruction (MS-RDPRFX 3.1.8.1.4 / 3.1.8.1.5) —
//! the two cheap inverse stages between RLGR entropy decode and the inverse DWT. Self-owned
//! (ADR-0003 phase-2); equivalence with the `ironrdp-graphics` `quantization` and
//! `subband_reconstruction` primitives is proven by the ADR-0007 stage-boundary tests.
//!
//! The 4096-coefficient component buffer is laid out linearly per subband, the spec's
//! coefficient order: `HL1 LH1 HH1` (1024 each), `HL2 LH2 HH2` (256 each), then
//! `HL3 LH3 HH3 LL3` (64 each).

use justrdp_pdu::rfx::Quant;

use super::RfxError;

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

/// The ten per-band left shifts a [`Quant`] asks for, in [`BANDS_STANDARD`] order — derived and
/// validated as a **table**, before [`dequantize`] touches a coefficient.
///
/// `shift = exponent - 1`, and an exponent of 0 or 1 leaves its band untouched.
///
/// **The refusal is here rather than at the shift, and it is written on the shift rather than
/// on the nibble** ([ADR-0012](../../../../docs/adr/0012-consumption-site-totality.md) §1–§2).
/// `Quant::decode` masks every field to `0..=15`, so no server can reach the error — but the
/// guarantee lives in the parser and the fields are plain `pub u8`, so it does not reach this
/// function's contract. The threshold is `shift >= 16` because that is where `i16 <<` is
/// undefined; stating it as "the exponent exceeds 15" would be off by one (an exponent of 16
/// shifts by 15, which is well defined) and would refuse a different set of inputs than the
/// sibling Progressive dequantizer does for the same stated reason
/// (`super::progressive::first_pass_shift`).
///
/// FreeRDP refuses the same width in the shift primitive itself — `-1` from
/// `general_lShiftC_16s_inplace` (`prim_shift.c:38-39`) — and then **discards** it: all ten
/// `rfx_quantization_decode_block` calls drop the status and `rfx_quantization_decode` returns
/// `TRUE` regardless (`rfx_quantization.c:73-83`), leaving the band unshifted. We fail the
/// component instead, which is a deliberate divergence from FreeRDP's *handling* rather than
/// from its threshold — the same split `super::progressive`'s first pass already records.
///
/// An exponent of **0** is refused, and this is the one refusal here a server can actually
/// reach — a `0x00` byte is two zero nibbles. `shift = exponent - 1` names no shift at `0`, so
/// unlike the width above this is not a value we dislike but the absence of one; FreeRDP takes
/// the same view and in the same shape, validating all ten before touching a coefficient
/// (`if (val < 1) return FALSE`, `rfx_quantization.c:66-71`) and propagating it through
/// `rfx_decode.c:66-67` to `rfx.c:1082-1086`. The oracle disagrees — `decode_block`'s
/// `if factor > 0` makes `0` and `1` alike no-ops (`quantization.rs`) — but it shares this
/// decoder's lineage and carries #211's unbounded shift besides, so it is not a second opinion
/// here.
///
/// The reason it is refused rather than skipped is **not** that FreeRDP refuses: it is that
/// `super::progressive::first_pass_shift` already refused the identically undefined
/// `bitPos == 0`, and one quantity gets one answer across a codec family
/// ([ADR-0012](../../../../docs/adr/0012-consumption-site-totality.md) §3). #233 settled it;
/// the two functions now differ only in their error type.
///
/// `exponent == 1` is untouched by that and must stay so — it shifts by 0, which is a band the
/// spec asks to leave alone. `saturating_sub` could not tell the two apart, which is the whole
/// of what was wrong.
pub fn shifts(quant: &Quant) -> Result<[u8; 10], RfxError> {
    let exponents = [
        quant.hl1, quant.lh1, quant.hh1, quant.hl2, quant.lh2, quant.hh2, quant.hl3, quant.lh3,
        quant.hh3, quant.ll3,
    ];
    let mut out = [0u8; 10];
    for (slot, exponent) in out.iter_mut().zip(exponents) {
        let shift = exponent.checked_sub(1).ok_or(RfxError::ZeroQuantExponent)?;
        if shift >= 16 {
            return Err(RfxError::ShiftOutOfRange(shift));
        }
        *slot = shift;
    }
    Ok(out)
}

/// Undo scalar quantization in place: each subband's coefficients shift left by the amount
/// [`shifts`] derived for it. A shift of 0 leaves the band untouched.
///
/// Infallible by construction: every shift came from [`shifts`], which refused anything `i16 <<`
/// cannot take. Splitting the two is what lets the per-coefficient loop stay total without the
/// caller threading a `Result` through it (ADR-0012 §4) — the shape
/// `super::progressive::{first_pass_shift, dequantize_first_pass}` already uses.
pub fn dequantize(buffer: &mut [i16], shifts: &[u8; 10]) {
    debug_assert_eq!(buffer.len(), COMPONENT_LEN);
    for (&(offset, len), &shift) in BANDS_STANDARD.iter().zip(shifts) {
        debug_assert!(shift < 16, "shifts() rejects a wider shift");
        if shift == 0 {
            continue;
        }
        for value in &mut buffer[offset..offset + len] {
            *value <<= shift;
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
            hl3: 3,
            hh3: 2,
            lh2: 7,
            hl2: 1,
            hh2: 8,
            lh1: 8,
            hl1: 1,
            hh1: 9,
        };
        let mut buffer = vec![1i16; COMPONENT_LEN];
        dequantize(
            &mut buffer,
            &shifts(&quant).expect("every exponent is in range"),
        );
        assert_eq!(buffer[0], 1); // HL1, exponent 1 → untouched
        assert_eq!(buffer[1024], 1 << 7); // LH1, exponent 8
        assert_eq!(buffer[2048], 1 << 8); // HH1, exponent 9
        assert_eq!(buffer[3072], 1); // HL2, exponent 1
        assert_eq!(buffer[3328], 1 << 6); // LH2, exponent 7
        assert_eq!(buffer[3584], 1 << 7); // HH2, exponent 8
        assert_eq!(buffer[3840], 1 << 2); // HL3, exponent 3
        assert_eq!(buffer[3904], 1); // LH3, exponent 1
        assert_eq!(buffer[3968], 1 << 1); // HH3, exponent 2
        assert_eq!(buffer[LL3_OFFSET], 1 << 5); // LL3, exponent 6
    }

    /// The same exponent in every band.
    fn uniform(exponent: u8) -> Quant {
        Quant {
            ll3: exponent,
            lh3: exponent,
            hl3: exponent,
            hh3: exponent,
            lh2: exponent,
            hl2: exponent,
            hh2: exponent,
            lh1: exponent,
            hl1: exponent,
            hh1: exponent,
        }
    }

    /// **Regression, #211.** `dequantize` used to take the `Quant` itself and shift by
    /// `exponent - 1` with no bound, so a hand-constructed exponent of 17 or more panicked with
    /// *"attempt to shift left with overflow"* — and in release, where `overflow-checks` is off,
    /// silently wrapped the shift amount modulo 16 instead (exponent 200 shifted by 7).
    ///
    /// The contract is totality over the *parameter type*, not over the subset the parser
    /// produces (ADR-0012 §1): `Quant`'s fields are plain `pub u8`, so every one of the 256
    /// values is constructible by a caller even though no server can send one above 15.
    #[test]
    fn shifts_is_total_for_every_exponent_the_type_permits() {
        for exponent in 0u8..=255 {
            match shifts(&uniform(exponent)) {
                Ok(table) => {
                    assert!(
                        (1..=16).contains(&exponent),
                        "exponent {exponent} should have been refused"
                    );
                    // Whatever it accepted, applying it must also be total.
                    let mut buffer = vec![i16::MAX; COMPONENT_LEN];
                    dequantize(&mut buffer, &table);
                }
                Err(RfxError::ShiftOutOfRange(shift)) => {
                    assert!(
                        exponent >= 17,
                        "exponent {exponent} should have been accepted"
                    );
                    assert_eq!(u32::from(shift), u32::from(exponent) - 1);
                }
                // #233. The two refusals partition the refused set with no overlap, which is
                // what makes each one's message true: 0 has no shift, 17 and up have one that
                // `i16 <<` cannot take.
                Err(RfxError::ZeroQuantExponent) => {
                    assert_eq!(exponent, 0, "only a zero exponent names no shift");
                }
                Err(other) => panic!("unexpected error for exponent {exponent}: {other:?}"),
            }
        }
    }

    /// **The off-by-one this issue was filed with, pinned.** #211's body reads "a `Quant` whose
    /// nibbles exceed 15", and the boundary is one higher: an exponent of 16 shifts by 15, which
    /// `i16 <<` is perfectly happy with. Writing the guard on the nibble rather than on the
    /// shift would refuse a different set of inputs than the sibling Progressive dequantizer
    /// does for the same stated reason (`first_pass_shift`'s `if shift >= 16`), which is the
    /// whole point of ADR-0012 §2.
    #[test]
    fn the_refusal_threshold_is_the_shift_not_the_nibble() {
        assert_eq!(shifts(&uniform(15)).expect("15 is in range")[0], 14);
        assert_eq!(shifts(&uniform(16)).expect("16 shifts by 15")[0], 15);
        assert_eq!(shifts(&uniform(17)), Err(RfxError::ShiftOutOfRange(16)));

        // And the accepted edge really does shift: 1 << 15 is i16::MIN, not a no-op.
        let mut buffer = vec![1i16; COMPONENT_LEN];
        dequantize(&mut buffer, &shifts(&uniform(16)).expect("16 shifts by 15"));
        assert_eq!(buffer[0], i16::MIN);
    }

    /// The validity condition under which the **width** refusal is unreachable, asserted rather
    /// than asserted-in-prose: `Quant::decode` masks every field with `& 0x0F` / `>> 4`, so the
    /// widest exponent a server can send is 15. If that ever stops holding, this goes red before
    /// anything else does.
    ///
    /// The range starts at 1, not 0, and that is the part worth reading. Since #233 the parser's
    /// range is **not** entirely accepted: a zero nibble is reachable and refused, so this stage
    /// has one wire-reachable refusal and one unreachable one. Writing the loop from 0 would
    /// conflate them and quietly assert the opposite of what #233 decided.
    #[test]
    fn no_exponent_the_parser_can_produce_is_refused_for_its_width() {
        for exponent in 1u8..=15 {
            shifts(&uniform(exponent)).expect("the parser's defined range must decode");
        }
    }

    /// Each of the ten bands carries the refusal independently — a table validated in nine
    /// places and not the tenth would be the silent shape this territory keeps finding.
    #[test]
    fn every_band_carries_its_own_refusal() {
        let mut quants = [uniform(1); 10];
        quants[0].hl1 = 17;
        quants[1].lh1 = 17;
        quants[2].hh1 = 17;
        quants[3].hl2 = 17;
        quants[4].lh2 = 17;
        quants[5].hh2 = 17;
        quants[6].hl3 = 17;
        quants[7].lh3 = 17;
        quants[8].hh3 = 17;
        quants[9].ll3 = 17;
        for (band, quant) in quants.iter().enumerate() {
            assert_eq!(
                shifts(quant),
                Err(RfxError::ShiftOutOfRange(16)),
                "band {band} did not carry the refusal"
            );
        }

        // And the same for #233's refusal, because the loop that carries one carries both only
        // if it is really a loop — a table validated in nine places and not the tenth is this
        // territory's recorded failure mode.
        let mut zeroed = [uniform(6); 10];
        zeroed[0].hl1 = 0;
        zeroed[1].lh1 = 0;
        zeroed[2].hh1 = 0;
        zeroed[3].hl2 = 0;
        zeroed[4].lh2 = 0;
        zeroed[5].hh2 = 0;
        zeroed[6].hl3 = 0;
        zeroed[7].lh3 = 0;
        zeroed[8].hh3 = 0;
        zeroed[9].ll3 = 0;
        for (band, quant) in zeroed.iter().enumerate() {
            assert_eq!(
                shifts(quant),
                Err(RfxError::ZeroQuantExponent),
                "band {band} did not carry the zero refusal"
            );
        }
    }

    /// **#233.** An exponent of 0 asks for `shift = -1`, which is not a value this stage
    /// dislikes — it is the absence of one. The sibling Progressive dequantizer already refused
    /// the identically undefined `bitPos == 0` (`progressive::first_pass_shift` →
    /// `ZeroBitPosition`), and ADR-0012 §3 requires one answer per quantity across a family.
    ///
    /// Unlike [`RfxError::ShiftOutOfRange`], this one **is** reachable from the wire: a `0x00`
    /// byte produces two zero nibbles, so `Quant::decode` hands one straight through. It is
    /// still outside what any conforming encoder emits — `[MS-RDPRFX]` constrains the encoder
    /// to 6..=15 — which is why refusing it is not strictness about what a server may say.
    #[test]
    fn a_zero_exponent_is_refused() {
        assert_eq!(shifts(&uniform(0)), Err(RfxError::ZeroQuantExponent));

        // One is enough: a single zero band refuses the whole table, before any coefficient
        // is touched, exactly as the shift-width refusal does.
        let mut quant = uniform(6);
        quant.hl3 = 0;
        assert_eq!(shifts(&quant), Err(RfxError::ZeroQuantExponent));
    }

    /// The neighbour that must **not** move with it. `shift = q - 1` is perfectly defined at
    /// `q == 1` — it is zero, a band the spec asks to leave alone — so an implementation that
    /// refused "everything `saturating_sub` used to flatten" would take this with it. The old
    /// code could not tell the two apart; that is the whole defect.
    #[test]
    fn an_exponent_of_one_is_still_an_untouched_band() {
        assert_eq!(shifts(&uniform(1)).expect("1 is defined")[0], 0);
        let mut buffer = vec![7i16; COMPONENT_LEN];
        dequantize(&mut buffer, &shifts(&uniform(1)).expect("1 is defined"));
        assert_eq!(buffer[0], 7);
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
