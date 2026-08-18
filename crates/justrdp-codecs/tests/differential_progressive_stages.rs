//! Stage-boundary differentials for the RemoteFX **Progressive** inverse pipeline (ADR-0007),
//! against the `ironrdp-graphics` primitives — and *only* the primitives.
//!
//! **The assembled oracle is disqualified here and this file must not grow toward it.**
//! ADR-0011 / #194 established that `ironrdp_graphics::progressive` decodes 2 of 52 real
//! payloads, and #168 established that its upgrade pass restarts both bit readers inside the
//! per-band loop (`progressive.rs:139`) where FreeRDP threads one cursor across all ten bands.
//! What remains usable is the *pure-math* stage this slice adds: `dwt_extrapolate`, which is a
//! self-contained transform with no stream state to get wrong.
//!
//! Even there, agreement is weaker evidence than it looks — the oracle shares justrdp's code
//! lineage (memory `ironrdp_oracle_shares_lineage`,
//! `docs/map/invariant/oracle-agreement-is-not-independence.md`), so this file is a
//! *cross-check* on a transform derived from FreeRDP, not the definition of correct. The
//! definition is `progressive.c:600-807`; where the two disagree, FreeRDP wins
//! (`docs/agents/theflow.md`, codec byte-exactness row).
//!
//! # And they do disagree — on exactly one thing
//!
//! The oracle narrows every lifting tap with `t(value) = value as i16`
//! (`dwt_extrapolate.rs:420-422`), which **wraps**. FreeRDP narrows with `clampi16`
//! (`progressive.c:591-598`), which **saturates**. Structurally the two are the same transform
//! — same band offsets, same lifting, same truncating-toward-zero `/ 2`, same two tail arms —
//! so on any input whose taps stay inside `i16` they agree coefficient for coefficient, and
//! that agreement is what makes this file a useful check on the structure. The moment a tap
//! overflows they part by up to a full `u16` and every later coefficient of that line inherits
//! it, so "how many coefficients differ" is not a measure of how far apart they are.
//!
//! We follow FreeRDP. The two tests below split on that seam deliberately: one asserts
//! byte-identity where the seam cannot be reached, the other asserts the seam is real rather
//! than letting a silent near-match stand in for a proof.

use justrdp_codecs::rfx::dwt_extrapolate as ours;
use justrdp_codecs::rfx::quant::{BANDS_EXTRAPOLATE, COMPONENT_LEN};

/// A deterministic xorshift spectrum — coefficients, not pixels, so the full `i16` range is
/// in scope rather than the narrow band a real DWT output occupies.
fn spectrum(mut seed: u32, scale: i32) -> Vec<i16> {
    (0..COMPONENT_LEN)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let v = (seed as i32 % (2 * scale + 1)) - scale;
            v.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
        })
        .collect()
}

/// Inputs whose lifting taps provably stay inside `i16`, so the wrapping/saturating seam is
/// unreachable and the two implementations must agree exactly. Amplitudes are kept small
/// enough that three levels of `x1 = mean(x0, x2) + 2*h0` growth cannot leave the range.
fn in_range_cases() -> Vec<(&'static str, Vec<i16>)> {
    let mut out: Vec<(&'static str, Vec<i16>)> = Vec::new();

    let mut dc = vec![0i16; COMPONENT_LEN];
    for v in &mut dc[BANDS_EXTRAPOLATE[9].0..] {
        *v = 4000;
    }
    out.push(("dc-only", dc));

    let mut impulses = vec![0i16; COMPONENT_LEN];
    for (band, &(offset, length)) in BANDS_EXTRAPOLATE.iter().enumerate() {
        impulses[offset] = 1000 + band as i16;
        impulses[offset + length - 1] = -(1000 + band as i16);
    }
    out.push(("band-edge-impulses", impulses));

    out.push(("noise-tiny", spectrum(0x1234_5678, 16)));
    out.push(("noise-small", spectrum(0x9E37_79B9, 64)));
    out.push(("noise-moderate", spectrum(0x0BAD_F00D, 256)));
    out.push(("noise-alt-seed", spectrum(0x5DEE_CE66, 100)));

    out
}

/// The structural gate for this slice's new transform: wherever the narrowing seam cannot be
/// reached, our reduce-extrapolate inverse DWT and the oracle's primitive agree coefficient
/// for coefficient.
///
/// This is the test that can go red — the module's own unit tests (all-zero, DC-flat, the
/// geometry derivation) pass against several *wrong* implementations, because a DC-only
/// spectrum exercises no highpass tap at all and the geometry assertions never run the
/// arithmetic. Mutating a single tap, the `/ 2` rounding, a band offset or a tail arm is
/// invisible to them and immediately visible here.
///
/// **Validity condition, and its exact limit.** The guard below asserts that no *output*
/// landed on a saturation bound. That is not the same as "no tap overflowed": the horizontal
/// pass writes into scratch the guard never inspects, and a value saturated at level 3 is
/// consumed as level 2's lowpass, where `x0 = clamp16(low - h0)` moves it back off the bound.
/// A spectrum with saturating intermediates and no saturated outputs exists, and on one of
/// those this test would still go red — but it would report a "first divergence at
/// coefficient N", i.e. diagnose a seam case as a structural bug. The amplitudes here are
/// small enough that the measured intermediate-saturation count is zero, so the guard is
/// sound for this case set; it is a tripwire on the case set, not a proof about the inputs.
#[test]
fn the_reduce_extrapolate_inverse_dwt_matches_the_oracle_primitive_in_range() {
    for (name, input) in in_range_cases() {
        let mut mine = input.clone();
        let mut my_temp = vec![0i16; COMPONENT_LEN];
        ours::decode(&mut mine, &mut my_temp);

        assert!(
            !mine.contains(&i16::MAX) && !mine.contains(&i16::MIN),
            "case {name} reached a saturation bound, so it no longer isolates the structure \n             from the narrowing seam — lower its amplitude or move it to the seam test"
        );

        let mut theirs = input.clone();
        let mut their_temp = vec![0i16; COMPONENT_LEN];
        ironrdp_graphics::dwt_extrapolate::decode(&mut theirs, &mut their_temp);

        if mine != theirs {
            let first = mine
                .iter()
                .zip(theirs.iter())
                .position(|(a, b)| a != b)
                .expect("a difference exists");
            panic!(
                "case {name}: first divergence at coefficient {first}: ours {} vs oracle {}",
                mine[first], theirs[first]
            );
        }
    }
}

/// **The deliberate divergence, asserted rather than described.** On a spectrum whose taps
/// overflow, we saturate (FreeRDP `clampi16`) and the oracle wraps (`value as i16`).
///
/// Without this test the divergence is a claim in a doc comment, and the suite would stay
/// green if someone "fixed" the disagreement by adopting the oracle's wrap — which is the
/// change this test exists to catch, because a wrapped tap turns an overflowing highlight
/// into its photographic negative rather than into a clipped one.
#[test]
fn we_saturate_where_the_oracle_wraps() {
    let input = spectrum(0xDEAD_BEEF, i32::from(i16::MAX));

    let mut mine = input.clone();
    let mut my_temp = vec![0i16; COMPONENT_LEN];
    ours::decode(&mut mine, &mut my_temp);

    let mut theirs = input;
    let mut their_temp = vec![0i16; COMPONENT_LEN];
    ironrdp_graphics::dwt_extrapolate::decode(&mut theirs, &mut their_temp);

    assert_ne!(mine, theirs, "the seam must be reachable on this input");

    // At least one coefficient where we clamped to a bound and the oracle came out with the
    // wrapped value of the same overflowing tap — opposite sign, which is the whole reason
    // FreeRDP clamps.
    let wrapped = mine
        .iter()
        .zip(theirs.iter())
        .filter(|&(&m, &t)| (m == i16::MAX && t < 0) || (m == i16::MIN && t > 0))
        .count();
    assert!(
        wrapped > 0,
        "expected at least one tap where saturation and wrapping give opposite signs"
    );
}

/// The two transforms are not interchangeable, and nothing else in the suite says so out
/// loud. If a future edit pointed the Progressive path at the classic DWT — the reuse the
/// epic originally assumed was possible — every test above would still pass on a DC tile.
#[test]
fn the_classic_and_extrapolate_transforms_disagree_on_real_coefficients() {
    let input = spectrum(0x0BAD_F00D, 2048);

    let mut extrapolate = input.clone();
    let mut temp = vec![0i16; COMPONENT_LEN];
    ours::decode(&mut extrapolate, &mut temp);

    let mut classic = input;
    let mut temp = vec![0i16; COMPONENT_LEN];
    justrdp_codecs::rfx::dwt::decode(&mut classic, &mut temp);

    assert_ne!(
        extrapolate, classic,
        "the two band layouts must not reconstruct identically — if they do, one of them is \
         not doing what its name says"
    );
}
