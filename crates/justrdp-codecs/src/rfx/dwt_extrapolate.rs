//! Inverse **reduce-extrapolate** DWT (`RFX_DWT_REDUCE_EXTRAPOLATE`) — the three-level 5/3
//! reconstruction RemoteFX **Progressive** uses, and the one every region in the real-server
//! corpus asks for (52 of 52, #194).
//!
//! # Why this is a second transform and not [`super::dwt`] with different offsets
//!
//! The sibling module is the classic WireToSurface1 inverse DWT, where each level splits an
//! `n`-sample line into two halves of `n/2`. Reduce-extrapolate splits it into
//! `low = (n + 2) / 2` and `high = n - low` — one *extra* lowpass sample, extrapolated — so
//! 64 → 33/31, 33 → 17/16, 17 → 9/8. Three consequences, and only the first is the one the
//! epic originally recorded:
//!
//! 1. **Every subband offset and length changes**, not only `LL3`
//!    ([`super::quant::BANDS_EXTRAPOLATE`]).
//! 2. **The lifting steps change.** With unequal counts the synthesis cannot mirror at both
//!    ends, so the tail of each line takes one of two shapes depending on whether the line
//!    length was odd or even — see [`idwt_x`].
//! 3. **The taps saturate where the classic ones wrap.** FreeRDP's `clampi16`
//!    (`progressive.c:591-598`) against [`super::dwt`]'s deliberate 16-bit truncation. On a
//!    tap that overflows the two differ by ~65536, so this is not a detail that washes out.
//!
//! Transcribed from `progressive_rfx_idwt_x` / `_y` / `progressive_rfx_dwt_2d_decode_block`
//! (`progressive.c:600-807`), because `docs/agents/thegraph.md`'s codec byte-exactness row
//! names the oracle *with FreeRDP as the tie-break* and ADR-0011 / #194 disqualify the oracle
//! for Progressive. `ironrdp-graphics::dwt_extrapolate` is a stage-boundary cross-check only
//! (ADR-0007), never the definition.
//!
//! # The band-count branch, and why one of FreeRDP's three tail arms is unreachable
//!
//! FreeRDP's line tail has three arms, selected by `nLowCount` against `nHighCount`. Only two
//! are reachable at the three levels this decoder runs, and the derivation is short:
//! `low = (n + 2) / 2` and `high = n - low`, so for even `n`, `low = high + 2`, and for odd
//! `n`, `low = high + 1`. `low <= high` is therefore false for every `n >= 2`, and the levels
//! are `n = 64` (even), `n = 33` and `n = 17` (odd). The unreachable arm is omitted rather
//! than transcribed-and-never-exercised.
//!
//! **The derivation is about the formula above, not about FreeRDP's.** FreeRDP parameterizes
//! the same split through `progressive_rfx_get_band_l_count` / `_h_count`
//! (`progressive.c:744-755`), which agree with `(n + 2) / 2` at every level it runs but
//! **diverge at level 7**: `L = (64 >> 7) + 1 = 1` and `H = (64 + 64) >> 7 = 1`, so `low <= high`
//! and the omitted arm *would* be reachable. Nothing runs level 7 — a 64-sample tile has three
//! — so the claim holds where it is used; it would stop holding if a deeper transform were
//! added using FreeRDP's band-count formulas rather than these.

use super::quant::{BANDS_EXTRAPOLATE, COMPONENT_LEN};

/// Low-pass sample count for an `n`-sample line under reduce-extrapolate — the extra
/// (extrapolated) sample is what the mode is named for.
const fn low_count(n: usize) -> usize {
    (n + 2) / 2
}

/// High-pass sample count: whatever the low-pass half did not take.
const fn high_count(n: usize) -> usize {
    n - low_count(n)
}

/// Saturating narrow to `i16` — FreeRDP's `clampi16` (`progressive.c:591-598`).
///
/// Deliberately **not** [`super::dwt`]'s `trunc16`, which wraps. The classic transform's wrap
/// is load-bearing there (it matches every interoperable WireToSurface1 decoder); here the
/// reference saturates, and the two disagree by a full `u16` on any tap that overflows.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the value is bounded to i16's range on the branch above the cast"
)]
fn clamp16(value: i32) -> i16 {
    if value < i16::MIN as i32 {
        i16::MIN
    } else if value > i16::MAX as i32 {
        i16::MAX
    } else {
        value as i16
    }
}

/// Reconstruct one 64×64 component in place from its reduce-extrapolate subbands. `temp` is
/// caller-provided scratch, reused across the three components of a tile.
///
/// The level offsets are read out of [`BANDS_EXTRAPOLATE`] rather than written a second time:
/// a level's block begins at its `HL` band, so level 3 starts at `HL3` and level 2 at `HL2`.
/// One table, three readers (here, the dequantizer, and the upgrade walk in
/// [`super::srl`]).
pub fn decode(buffer: &mut [i16], temp: &mut [i16]) {
    debug_assert_eq!(buffer.len(), COMPONENT_LEN);
    debug_assert!(temp.len() >= COMPONENT_LEN);

    let (l1, h1) = (low_count(64), high_count(64));
    let (l2, h2) = (low_count(l1), high_count(l1));
    let (l3, h3) = (low_count(l2), high_count(l2));

    // Inner level first: each level's output *is* the next one's lowpass band.
    decode_block(&mut buffer[BANDS_EXTRAPOLATE[6].0..], temp, l3, h3);
    decode_block(&mut buffer[BANDS_EXTRAPOLATE[3].0..], temp, l2, h2);
    decode_block(buffer, temp, l1, h1);
}

/// One level: `HL LH HH LL` (in that buffer order) become a `(band_l + band_h)` square.
fn decode_block(buffer: &mut [i16], temp: &mut [i16], band_l: usize, band_h: usize) {
    let dst_step = band_l + band_h;
    let (l_temp, h_temp) = temp.split_at_mut(band_l * dst_step);

    {
        let (hl, rest) = buffer.split_at(band_h * band_l);
        let (lh, rest) = rest.split_at(band_l * band_h);
        let (hh, ll) = rest.split_at(band_h * band_h);
        // horizontal: LL + HL -> L (band_l rows), LH + HH -> H (band_h rows)
        idwt_x(
            ll, band_l, hl, band_h, l_temp, dst_step, band_l, band_h, band_l,
        );
        idwt_x(
            lh, band_l, hh, band_h, h_temp, dst_step, band_l, band_h, band_h,
        );
    }
    // vertical: L + H -> the reconstructed square, written back over the whole block
    idwt_y(
        l_temp, dst_step, h_temp, dst_step, buffer, dst_step, band_l, band_h, dst_step,
    );
}

/// Horizontal synthesis: one line per `dst_count`, each interleaving `low_count` lowpass and
/// `high_count` highpass samples into `low_count + high_count` outputs.
///
/// The body is the 5/3 inverse lifting FreeRDP writes at `progressive.c:600-664`: an even
/// output subtracts the mean of its two neighbouring highpass taps, an odd output adds twice
/// its highpass tap to the mean of its two even neighbours. What is specific to
/// reduce-extrapolate is the **tail**, which produces one extra sample when the line length
/// was even.
#[expect(
    clippy::too_many_arguments,
    reason = "the band geometry is eight independent values; bundling them into a struct \
              would hide which of low/high/dst each stride belongs to"
)]
fn idwt_x(
    low: &[i16],
    low_step: usize,
    high: &[i16],
    high_step: usize,
    dst: &mut [i16],
    dst_step: usize,
    low_count: usize,
    high_count: usize,
    dst_count: usize,
) {
    debug_assert!(
        high_count >= 1,
        "a line with no highpass sample has no first tap"
    );
    for line in 0..dst_count {
        let low = &low[line * low_step..];
        let high = &high[line * high_step..];
        let dst = &mut dst[line * dst_step..];

        let mut h0 = i32::from(high[0]);
        let mut x0 = clamp16(i32::from(low[0]) - h0);
        let mut x2 = x0;
        let mut xi = 0usize;

        for j in 1..high_count {
            let h1 = i32::from(high[j]);
            x2 = clamp16(i32::from(low[j]) - (h0 + h1) / 2);
            let x1 = clamp16((i32::from(x0) + i32::from(x2)) / 2 + 2 * h0);
            dst[xi] = x0;
            dst[xi + 1] = x1;
            xi += 2;
            x0 = x2;
            h0 = h1;
        }

        if low_count == high_count + 1 {
            // Odd line length: one trailing lowpass sample, mirrored against the last tap.
            x0 = clamp16(i32::from(low[high_count]) - h0);
            dst[xi] = x2;
            dst[xi + 1] = clamp16((i32::from(x0) + i32::from(x2)) / 2 + 2 * h0);
            dst[xi + 2] = x0;
        } else {
            // Even line length: two trailing lowpass samples. The second is the extrapolated
            // one the mode is named for, and the final output is their mean, not a tap.
            x0 = clamp16(i32::from(low[high_count]) - h0 / 2);
            dst[xi] = x2;
            dst[xi + 1] = clamp16((i32::from(x0) + i32::from(x2)) / 2 + 2 * h0);
            dst[xi + 2] = x0;
            dst[xi + 3] = clamp16((i32::from(x0) + i32::from(low[high_count + 1])) / 2);
        }
    }
}

/// Vertical synthesis — [`idwt_x`] column-wise (`progressive.c:669-742`). Identical lifting;
/// the steps walk down a column instead of along a row, and the destination is the block
/// itself rather than scratch.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors idwt_x's signature; see the note there"
)]
fn idwt_y(
    low: &[i16],
    low_step: usize,
    high: &[i16],
    high_step: usize,
    dst: &mut [i16],
    dst_step: usize,
    low_count: usize,
    high_count: usize,
    dst_count: usize,
) {
    debug_assert!(
        high_count >= 1,
        "a column with no highpass sample has no first tap"
    );
    for column in 0..dst_count {
        let mut h0 = i32::from(high[column]);
        let mut x0 = clamp16(i32::from(low[column]) - h0);
        let mut x2 = x0;
        let mut xi = column;

        for j in 1..high_count {
            let h1 = i32::from(high[column + j * high_step]);
            x2 = clamp16(i32::from(low[column + j * low_step]) - (h0 + h1) / 2);
            let x1 = clamp16((i32::from(x0) + i32::from(x2)) / 2 + 2 * h0);
            dst[xi] = x0;
            dst[xi + dst_step] = x1;
            xi += 2 * dst_step;
            x0 = x2;
            h0 = h1;
        }

        if low_count == high_count + 1 {
            x0 = clamp16(i32::from(low[column + high_count * low_step]) - h0);
            dst[xi] = x2;
            dst[xi + dst_step] = clamp16((i32::from(x0) + i32::from(x2)) / 2 + 2 * h0);
            dst[xi + 2 * dst_step] = x0;
        } else {
            x0 = clamp16(i32::from(low[column + high_count * low_step]) - h0 / 2);
            dst[xi] = x2;
            dst[xi + dst_step] = clamp16((i32::from(x0) + i32::from(x2)) / 2 + 2 * h0);
            dst[xi + 2 * dst_step] = x0;
            let tail = i32::from(low[column + (high_count + 1) * low_step]);
            dst[xi + 3 * dst_step] = clamp16((i32::from(x0) + tail) / 2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation the module doc rests on: **this module's** split never produces
    /// `low <= high`, so the omitted tail arm cannot be reached at any level driven through
    /// `low_count`/`high_count`. It is *not* a statement about FreeRDP's band-count formulas,
    /// which give `L == H` at level 7 — see the module doc.
    #[test]
    fn the_line_split_never_reaches_freerdps_third_tail_arm() {
        for n in 2..=1024usize {
            let (low, high) = (low_count(n), high_count(n));
            assert_eq!(low + high, n, "the split must be exhaustive for n = {n}");
            assert!(
                low > high,
                "low <= high at n = {n} would need the omitted arm"
            );
            let expected = if n.is_multiple_of(2) { 2 } else { 1 };
            assert_eq!(low - high, expected, "unexpected tail shape at n = {n}");
        }
    }

    /// The three levels' geometry lines up with the band table the dequantizer and the
    /// upgrade walk read — a level's block starts at its `HL` band and its output is exactly
    /// the next level's lowpass.
    #[test]
    fn the_level_geometry_agrees_with_the_band_table() {
        let (l1, h1) = (low_count(64), high_count(64));
        let (l2, h2) = (low_count(l1), high_count(l1));
        let (l3, h3) = (low_count(l2), high_count(l2));
        assert_eq!(((l1, h1), (l2, h2), (l3, h3)), ((33, 31), (17, 16), (9, 8)));

        // level 3: HL3 LH3 HH3 LL3 at the table's offsets, output 17x17 filling to the end
        assert_eq!(BANDS_EXTRAPOLATE[6], (3807, h3 * l3));
        assert_eq!(BANDS_EXTRAPOLATE[7], (3807 + h3 * l3, l3 * h3));
        assert_eq!(BANDS_EXTRAPOLATE[8], (3807 + 2 * h3 * l3, h3 * h3));
        assert_eq!(
            BANDS_EXTRAPOLATE[9],
            (3807 + 2 * h3 * l3 + h3 * h3, l3 * l3)
        );
        assert_eq!(3807 + (l3 + h3) * (l3 + h3), COMPONENT_LEN);

        // level 2's output is level 1's lowpass band, and level 3's is level 2's
        assert_eq!(
            BANDS_EXTRAPOLATE[3].0 + (l2 + h2) * (l2 + h2),
            COMPONENT_LEN
        );
        assert_eq!(BANDS_EXTRAPOLATE[3].0, 3007);
        assert_eq!((l1 + h1) * (l1 + h1), COMPONENT_LEN);
    }

    #[test]
    fn an_all_zero_spectrum_reconstructs_to_an_all_zero_tile() {
        let mut buffer = vec![0i16; COMPONENT_LEN];
        let mut temp = vec![0i16; COMPONENT_LEN];
        decode(&mut buffer, &mut temp);
        assert!(buffer.iter().all(|&v| v == 0));
    }

    /// A constant lowpass with every highpass band at zero must synthesize a constant tile:
    /// the lifting's highpass taps all see zero, so each output collapses to its lowpass
    /// sample. This is the cheapest end-to-end check that the three levels chain — it fails
    /// if any level reads or writes the wrong window.
    #[test]
    fn a_pure_dc_spectrum_reconstructs_to_a_flat_tile() {
        let mut buffer = vec![0i16; COMPONENT_LEN];
        let (offset, length) = BANDS_EXTRAPOLATE[9];
        for v in &mut buffer[offset..offset + length] {
            *v = 100;
        }
        let mut temp = vec![0i16; COMPONENT_LEN];
        decode(&mut buffer, &mut temp);
        assert!(
            buffer.iter().all(|&v| v == 100),
            "DC-only spectrum must stay flat, got {:?}…",
            &buffer[..8]
        );
    }

    /// The tap arithmetic saturates rather than wrapping — the one behaviour that separates
    /// this transform from [`super::dwt`] at the same input. A lowpass of `i16::MIN` against
    /// a highpass of `i16::MAX` overflows the even tap by more than a full `i16`.
    #[test]
    fn an_overflowing_tap_saturates_where_the_classic_transform_wraps() {
        assert_eq!(clamp16(i32::from(i16::MIN) - i32::from(i16::MAX)), i16::MIN);
        assert_eq!(clamp16(i32::from(i16::MAX) * 4), i16::MAX);

        let mut ours = vec![0i16; COMPONENT_LEN];
        ours[BANDS_EXTRAPOLATE[9].0] = i16::MIN;
        ours[BANDS_EXTRAPOLATE[8].0] = i16::MAX;
        let mut temp = vec![0i16; COMPONENT_LEN];
        decode(&mut ours, &mut temp);
        // Saturation keeps every output inside the range by construction; the value that
        // matters is that the corner did not wrap around to a large positive number.
        assert!(
            ours[0] < 0,
            "the saturating tap must stay negative, got {}",
            ours[0]
        );
    }
}
