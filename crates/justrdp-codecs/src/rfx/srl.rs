//! SRL (Simplified Run-Length) entropy decoding and the upgrade-pass accumulate — the
//! Progressive-specific half of RemoteFX's entropy layer (`[MS-RDPEGFX]` 2.2.4.x, epic #158
//! slice 2). Self-owned (ADR-0003 phase-2).
//!
//! An upgrade pass refines a tile that a previous pass already decoded: each coefficient gains
//! `numBits` more bits of precision, added into the persistent coefficient store at the band's
//! `shift`. Two bit streams feed one pass, and which one a coefficient reads from is decided by
//! the tri-state sign array carried across passes — a coefficient that was non-zero reads its
//! refinement from the **raw** stream, one that was zero reads it from the **SRL** stream, whose
//! run-length coding is cheap for the long stretches of still-zero coefficients.
//!
//! # Verification basis — FreeRDP, not the oracle
//!
//! This stage is **not** gated on the `ironrdp-graphics` differential (ADR-0003/0007's usual
//! method). The oracle's SRL is measured to disagree with FreeRDP on every count listed below,
//! and its own tests round-trip against its own encoder, so it cannot arbitrate (#194,
//! ADR-0011). (No count in this sentence on purpose — the list is the authority, and a
//! hand-copied number beside a derived list is the drift `lessons.md` records for #200.)
//! `docs/agents/theflow.md`'s tie-breaker for codec byte-exactness names the **oracle**, *with
//! FreeRDP as the tie-break when the oracle and we disagree* — and here the oracle is
//! disqualified outright, so what remains is FreeRDP. This module is therefore derived from
//! `progressive.c` and gated on the hand-derived vectors in `tests/progressive_srl_freerdp.rs`.
//! The divergences, each measured:
//!
//! 1. **Initial `kp` is 8**, not 0 (`progressive.c:1272`, unchanged across 2.11.7 / 3.0.0 /
//!    master). So `k = kp / 8` is **1** for the first symbol of every component, and the
//!    zero-encoding phase reads one run-length bit that a `kp = 0` decoder never reads. The
//!    oracle starts at 0 (`srl.rs:26`), which desynchronises the two from the first symbol on.
//! 2. **Magnitude coding is truncated unary from 1**, with no remainder bits and a hard cap at
//!    `(1 << numBits) - 1` (`:1145-1157`). The oracle reads a Golomb-Rice quotient plus
//!    `numBits - 1` remainder bits, uncapped.
//! 3. **`mode` persists across calls** (`:1113`, `:1130`): the call that drains a `k`-bit zero
//!    run leaves `mode = 1`, so the next value skips the zero-encoding phase entirely.
//! 4. **One bit stream per component, threaded across all ten bands** (`:1268-1277`), carrying
//!    `nz` / `kp` / `mode` with it. The oracle recreates both readers inside its band loop, so
//!    bands 1..9 re-read bytes band 0 already spent.
//!
//! Two further differences from `progressive.c`, neither reachable through the parser and both
//! recorded here because this module's own argument is that the source types do not carry the
//! parser's guarantees:
//!
//! - `raw_read` returns [`SrlError::ValueOverflow`] for a read too wide to fit a coefficient,
//!   where `rawShift` (`:1192-1201`) uses a plain C cast. Same family as the `i16` overflow row
//!   in `docs/agents/theflow.md`, and covered by the same reasoning.
//! - [`Bits::bits`] consumes `n` bits for any `n`, where winpr's `BitStream_Shift` warns and
//!   consumes **nothing** for `n >= 32` (`bitstream.h`). Unreachable here: the only call passes
//!   `k <= 10`.
//!
//! # A hazard this module cannot close, for slice 3 (#169)
//!
//! [`BANDS`] is the extrapolate layout and [`upgrade_component`] takes no flag to select
//! another, because the upgrade path has none to select (`progressive.c:1281-1321`). The
//! *first-pass* decoder does branch (`:877`), so a region without
//! `RFX_DWT_REDUCE_EXTRAPOLATE` gets its first pass written at one set of band offsets and its
//! refinements applied at another — plausible pixels, no error, which is the silent shape
//! `docs/map/territory/bitmap-codecs.md` records for #167. The capture cannot see it (52 of 52
//! regions set the flag). Whichever way #169 resolves it — one layout for both halves, or a
//! flag on this entry point and a refusal on mismatch — it is that slice's call, and doing
//! neither is the outcome to avoid.
//!
//! # What this module deliberately does not do
//!
//! `progressive_rfx_upgrade_state_finish` (`:1164-1190`) pads both streams to a byte boundary
//! and drops a trailing all-zero SRL byte. It is omitted here because it has no observable
//! effect: both streams are per-component slices handed in by the caller and dropped when the
//! pass ends, so no later read can see the position it leaves behind. **Validity condition:**
//! this holds only while one component's streams are never continued into another's — the shape
//! `UpgradeTile` gives us, which carries six separate runs.

use justrdp_pdu::rfx::progressive::ProgressiveQuant;

use super::quant::COMPONENT_LEN;

/// Why an upgrade pass failed to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrlError {
    /// A refinement cannot be represented. FreeRDP truncates here
    /// (`WINPR_ASSERTING_INT_CAST`, an assert in debug and a plain cast in release); we refuse,
    /// because the coefficient store survives across passes — a wrapped value corrupts every
    /// later refinement of the tile rather than one pixel of this one.
    ///
    /// Also returned when a raw read is too wide to fit a coefficient, or when the band's
    /// `shift` would discard a bit of the refinement. All three are one condition stated three
    /// ways — *this refinement cannot be represented* — so they share a variant.
    ///
    /// **Reachability is not established, and the claim is narrower than it looks.** The
    /// corpus bounds the *addend*: base quant bands 6..=10 and progressive bit positions
    /// {0, 1, 2} give `shift` in 5..=11 against a magnitude of at most 3, so no single
    /// refinement exceeds 6144. It says nothing about the *sum*, because the coefficient it is
    /// added to is whatever the previous pass left — and no gate in this repo yet drives a pass
    /// against a non-zero store. #169 is where that becomes measurable.
    ///
    /// **The caller's obligation on this error is to discard the tile's coefficient store, not
    /// merely to skip the tile.** [`upgrade_component`] refines in place and returns after
    /// having already mutated an arbitrary prefix, so a skipped tile whose store is retained
    /// carries a half-applied pass into every later refinement — the same corruption the choice
    /// to error rather than truncate exists to prevent.
    ValueOverflow,
}

impl core::fmt::Display for SrlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SrlError::ValueOverflow => write!(f, "upgraded coefficient exceeds i16"),
        }
    }
}

impl core::error::Error for SrlError {}

/// `kp` never exceeds this (`progressive.c:1103-1104`).
const KP_MAX: u32 = 80;
/// The value `kp` starts at for every component (`progressive.c:1272`).
const KP_INIT: u32 = 8;

/// The largest value a band's bit position can take, and with it the ceiling on both
/// [`upgrade_component`] quant arguments.
///
/// **This is 30, not 15, and the difference is load-bearing.** A bit position is
/// `quant + prog_quant` (`progressive_rfx_quant_add`, `progressive.c:81-94`) — the *sum* of two
/// 4-bit nibbles. `num_bits` is then the difference of two such positions
/// (`progressive_rfx_quant_sub`, `:1442-1447`) and `shift` is one of them minus one (`:1448`),
/// so `num_bits` ranges over `0..=30` and `shift` over `0..=29`.
///
/// An earlier revision of this module asserted these were 4-bit nibbles bounded by 15 and sized
/// the magnitude cap accordingly, which silently desynchronised the SRL stream for every
/// `num_bits >= 16`. Recorded as a constant rather than a comment so the next reader meets the
/// derivation and not the conclusion — and made public because slice 3 (#169) is what computes
/// these values, so it needs the ceiling rather than a second derivation of it.
///
/// Nothing here *enforces* it: [`upgrade_component`] is total for every `u8`, so a value above
/// this is decoded rather than rejected. It is a statement about what a well-formed stream can
/// produce, not a validation rule.
pub const MAX_BIT_POS: u32 = 30;

/// An MSB-first bit cursor that reads **zero bits past the end** of its data.
///
/// That end-of-stream contract is the reason this is not [`super::rlgr::BitReader`], which
/// answers `None` instead: winpr's `wBitStream` zero-fills its accumulator and prefetch beyond
/// `capacity` (`winpr/include/winpr/bitstream.h`, the bounds-checked `BitStream_Fetch` /
/// `BitStream_Prefetch`), and the SRL magnitude loop depends on it — a truncated stream must
/// still terminate at the `(1 << numBits) - 1` cap rather than stop mid-symbol. Unifying the two
/// readers is #91's business, not this slice's.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn bit(&mut self) -> u32 {
        let byte = self.data.get(self.pos / 8).copied().unwrap_or(0);
        let value = (byte >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        u32::from(value)
    }

    /// Whether every remaining read will yield a zero-filled bit.
    fn exhausted(&self) -> bool {
        self.pos >= self.data.len() * 8
    }

    /// Advance without reading — only ever called past the end, where the bits are zero-fill.
    /// Saturating because `n` can be up to `u32::MAX` and `usize` is 32 bits on the targets
    /// [`decoder-dimension-overflow-32bit`](../../../../docs/map/invariant/decoder-dimension-overflow-32bit.md)
    /// covers.
    fn skip(&mut self, n: u32) {
        self.pos = self.pos.saturating_add(n as usize);
    }

    /// Read `n` bits big-endian. `n == 0` reads nothing and yields 0.
    fn bits(&mut self, n: u32) -> u32 {
        let mut acc = 0u32;
        for _ in 0..n {
            acc = (acc << 1) | self.bit();
        }
        acc
    }
}

/// The extrapolate band layout an upgrade pass walks, as `(offset, length)` in the order
/// FreeRDP drives them: `HL1 LH1 HH1 HL2 LH2 HH2 HL3 LH3 HH3` and finally `LL3`.
///
/// **There is no non-extrapolate variant here** — unlike the first-pass component decoder,
/// which branches on it (`progressive.c:876-921`), the upgrade path hardcodes this one layout
/// (`:1281-1321`). Consistent with the capture: all 52 payloads declare
/// `RFX_DWT_REDUCE_EXTRAPOLATE` (#194).
const BANDS: [(usize, usize); 10] = [
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

/// The per-band nibbles of a [`ProgressiveQuant`] in [`BANDS`] order.
fn band_values(q: &ProgressiveQuant) -> [u8; 10] {
    [
        q.hl1, q.lh1, q.hh1, q.hl2, q.lh2, q.hh2, q.hl3, q.lh3, q.hh3, q.ll3,
    ]
}

/// One component's upgrade-pass entropy state: both bit streams plus the SRL run state that is
/// carried across every band of the component (`RFX_PROGRESSIVE_UPGRADE_STATE`).
struct UpgradeState<'a> {
    srl: Bits<'a>,
    raw: Bits<'a>,
    /// Zeros still owed from the run in progress.
    nz: u32,
    /// The adaptive run-length exponent, scaled by 8.
    kp: u32,
    /// `true` once a `1` bit has opened unary coding and the next value must skip the
    /// zero-encoding phase.
    mode: bool,
}

impl<'a> UpgradeState<'a> {
    fn new(srl: &'a [u8], raw: &'a [u8]) -> Self {
        Self {
            srl: Bits::new(srl),
            raw: Bits::new(raw),
            nz: 0,
            kp: KP_INIT,
            mode: false,
        }
    }

    /// One SRL-coded value (`progressive_rfx_srl_read`, `progressive.c:1075-1162`).
    fn srl_read(&mut self, num_bits: u32) -> i16 {
        if self.nz > 0 {
            self.nz -= 1;
            return 0;
        }

        let k = self.kp / 8;

        if !self.mode {
            // Zero encoding: a `0` opens a run of `1 << k`, a `1` opens unary coding and the
            // next `k` bits carry a shorter run.
            if self.bit_srl() == 0 {
                self.nz = 1u32 << k;
                self.kp = (self.kp + 4).min(KP_MAX);
                self.nz -= 1;
                return 0;
            }
            self.nz = 0;
            self.mode = true;
            if k > 0 {
                self.nz = self.srl.bits(k);
            }
            if self.nz > 0 {
                self.nz -= 1;
                return 0;
            }
        }

        self.mode = false;
        let sign = self.bit_srl();
        self.kp = self.kp.saturating_sub(6);

        if num_bits == 1 {
            return if sign != 0 { -1 } else { 1 };
        }

        // Truncated unary from 1: a `1` bit ends the magnitude, and reaching the cap ends it
        // without consuming a terminator. The cap is FreeRDP's `(1 << numBits) - 1` (`:1145`),
        // written so it is total for every `u8`.
        //
        // **The cap may not be lowered to `i16::MAX`**, however tempting, because `num_bits`
        // ranges to 30 rather than to 15 — see [`MAX_BIT_POS`]. At `num_bits >= 16` a lowered
        // cap stops the loop early, leaves the shared bit cursor in the wrong place, and every
        // later coefficient of the component decodes to a plausible wrong value with no error:
        // the silent failure `untrusted-decode-never-panics` calls worse than a panic. The
        // magnitude is still clamped to `i16::MAX` on the way out, exactly as FreeRDP clamps it
        // (`:1159-1160`) — that is a clamp on the *value*, not on the bits consumed.
        //
        // Bounding the loop is therefore done by the stream instead: past the end every bit
        // reads 0, so the remaining iterations can only run to the cap and are jumped rather
        // than counted. Iterations are then bounded by the SRL run's own length, and the decode
        // is identical — position past the end is unobservable, since every later read yields 0
        // regardless of where the cursor sits.
        let mut mag = 1u32;
        let max = 1u32.checked_shl(num_bits).map_or(u32::MAX, |v| v - 1);
        while mag < max {
            if self.srl.exhausted() {
                self.srl.skip(max - mag);
                mag = max;
                break;
            }
            if self.bit_srl() != 0 {
                break;
            }
            mag += 1;
        }

        let mag = mag.min(i16::MAX as u32) as i16;
        if sign != 0 { -mag } else { mag }
    }

    fn bit_srl(&mut self) -> u32 {
        self.srl.bit()
    }

    /// `numBits` raw bits as an unsigned magnitude (`rawShift`, `progressive.c:1192-1201`).
    fn raw_read(&mut self, num_bits: u32) -> Result<i16, SrlError> {
        i16::try_from(self.raw.bits(num_bits)).map_err(|_| SrlError::ValueOverflow)
    }

    /// Refine one band in place (`progressive_rfx_upgrade_block`, `progressive.c:1203-1256`).
    ///
    /// `non_ll` is false only for `LL3`, whose coefficients are never zero-coded and so read
    /// entirely from the raw stream — the SRL stream is not touched for that band at all.
    fn upgrade_block(
        &mut self,
        buffer: &mut [i16],
        sign: &mut [i16],
        shift: u32,
        num_bits: u32,
        non_ll: bool,
    ) -> Result<(), SrlError> {
        // A band whose quality did not advance consumes no bits from either stream.
        if num_bits < 1 {
            return Ok(());
        }

        // Two loops rather than one branch per coefficient, mirroring FreeRDP's own early
        // return for the lowpass band (`:1215-1227`). Merging them would read as a lowpass
        // coefficient being "a coefficient whose sign happens to be positive", which is a
        // different statement: LL3's signs are never consulted *or written*, whatever they hold.
        if !non_ll {
            for coefficient in buffer.iter_mut() {
                let input = self.raw_read(num_bits)?;
                accumulate(coefficient, input, shift)?;
            }
            return Ok(());
        }

        for (coefficient, sign) in buffer.iter_mut().zip(sign.iter_mut()) {
            let input = match *sign {
                s if s > 0 => self.raw_read(num_bits)?,
                s if s < 0 => -self.raw_read(num_bits)?,
                _ => {
                    let value = self.srl_read(num_bits);
                    *sign = value;
                    value
                }
            };
            accumulate(coefficient, input, shift)?;
        }

        Ok(())
    }
}

/// Add one refinement into the coefficient store at the band's shift.
///
/// Widened to `i64` before the shift, not after: `i32` is wide enough for every reachable
/// `shift` (see [`MAX_BIT_POS`]) but not for an out-of-range one, where `i32::checked_shl` still
/// permits `shift == 31` and the *addition* then overflows.
///
/// `checked_shl` alone is **not** enough even at `i64`, and the difference is a silent one: it
/// rejects an out-of-range shift *amount* and says nothing about the *value*, so `2 << 63` is
/// `Some(0)` and a real refinement is accepted as a no-op. The round-trip below is what actually
/// detects a lost bit; `try_from` then rejects anything that will not fit a coefficient. Both
/// are needed, and neither subsumes the other.
fn accumulate(coefficient: &mut i16, input: i16, shift: u32) -> Result<(), SrlError> {
    let shifted = i64::from(input)
        .checked_shl(shift)
        .ok_or(SrlError::ValueOverflow)?;
    if shifted >> shift != i64::from(input) {
        return Err(SrlError::ValueOverflow);
    }
    let refined = i64::from(*coefficient) + shifted;
    *coefficient = i16::try_from(refined).map_err(|_| SrlError::ValueOverflow)?;
    Ok(())
}

/// Refine one tile component across all ten bands
/// (`progressive_rfx_upgrade_component`, `progressive.c:1258-1330`), leaving `current` and
/// `sign` ready for the next pass.
///
/// `shift` and `num_bits` are per-band values the caller derives from the region's quant tables
/// and the tile's previous bit positions. They are **not** 4-bit nibbles, whatever their source
/// type suggests — see [`MAX_BIT_POS`] for the derivation and for why assuming otherwise
/// silently desynchronises the stream. `srl` and `raw` are this component's two runs — threaded
/// across every band, which is what makes the adaptive state meaningful.
pub fn upgrade_component(
    srl: &[u8],
    raw: &[u8],
    shift: &ProgressiveQuant,
    num_bits: &ProgressiveQuant,
    current: &mut [i16; COMPONENT_LEN],
    sign: &mut [i16; COMPONENT_LEN],
) -> Result<(), SrlError> {
    let mut state = UpgradeState::new(srl, raw);
    let shifts = band_values(shift);
    let widths = band_values(num_bits);

    for (band, &(offset, length)) in BANDS.iter().enumerate() {
        // LL3 is the last band and the only one that reads every coefficient from raw bits.
        let non_ll = band < BANDS.len() - 1;
        state.upgrade_block(
            &mut current[offset..offset + length],
            &mut sign[offset..offset + length],
            u32::from(shifts[band]),
            u32::from(widths[band]),
            non_ll,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quant(v: u8) -> ProgressiveQuant {
        ProgressiveQuant {
            ll3: v,
            hl3: v,
            lh3: v,
            hh3: v,
            hl2: v,
            lh2: v,
            hh2: v,
            hl1: v,
            lh1: v,
            hh1: v,
        }
    }

    /// The bit cursor is MSB-first and zero-fills past the end — the harness proof the vector
    /// tests rest on, asserted without reference to either implementation.
    #[test]
    fn bits_read_msb_first_and_zero_fill_past_the_end() {
        let mut bits = Bits::new(&[0b1011_0010]);
        assert_eq!(bits.bit(), 1);
        assert_eq!(bits.bits(3), 0b011);
        assert_eq!(bits.bits(4), 0b0010);
        // Past the end: zeros, not a panic and not a wrap to the first byte.
        assert_eq!(bits.bits(8), 0);
        assert_eq!(bits.bit(), 0);
    }

    /// `bits(0)` consumes nothing — the `k == 0` case in the zero-encoding phase.
    #[test]
    fn reading_zero_bits_consumes_nothing() {
        let mut bits = Bits::new(&[0b1000_0000]);
        assert_eq!(bits.bits(0), 0);
        assert_eq!(bits.bit(), 1);
    }

    /// The state every component starts from — `kp = 8`, so the first symbol's `k` is 1.
    #[test]
    fn a_component_starts_at_kp_eight() {
        let state = UpgradeState::new(&[], &[]);
        assert_eq!(state.kp, KP_INIT);
        assert_eq!(state.kp / 8, 1, "the first symbol reads one run-length bit");
        assert!(!state.mode);
        assert_eq!(state.nz, 0);
    }

    /// A band with `num_bits == 0` is skipped without consuming a bit from either stream.
    #[test]
    fn a_zero_width_band_consumes_nothing() {
        let mut state = UpgradeState::new(&[0xFF], &[0xFF]);
        let mut buffer = [5i16; 4];
        let mut sign = [0i16; 4];
        state
            .upgrade_block(&mut buffer, &mut sign, 0, 0, true)
            .expect("a zero-width band is not an error");
        assert_eq!(buffer, [5; 4], "coefficients untouched");
        assert_eq!(state.srl.pos, 0, "no SRL bits consumed");
        assert_eq!(state.raw.pos, 0, "no raw bits consumed");
    }

    /// `LL3` reads every coefficient from the raw stream, whatever the sign array says.
    #[test]
    fn the_ll_band_never_touches_the_srl_stream() {
        let mut state = UpgradeState::new(&[0xFF], &[0b1010_1100]);
        let mut buffer = [0i16; 4];
        // Signs that would route to SRL, to raw, and to negated raw on a non-LL band.
        let mut sign = [0i16, 1, -1, 0];
        state
            .upgrade_block(&mut buffer, &mut sign, 0, 2, false)
            .expect("decodes");
        assert_eq!(state.srl.pos, 0, "the SRL stream must be untouched");
        assert_eq!(state.raw.pos, 8, "four two-bit reads");
        assert_eq!(buffer, [0b10, 0b10, 0b11, 0b00]);
        assert_eq!(sign, [0, 1, -1, 0], "LL3 does not write the sign array");
    }

    /// On a non-LL band the sign array routes each coefficient, and a zero entry is filled in
    /// with the value SRL produced.
    #[test]
    fn the_sign_array_routes_each_coefficient_and_srl_fills_the_zero_entries() {
        // raw `01 10` feeds the two signed entries; srl `1 0 0` is one +1 at num_bits == 1.
        let mut state = UpgradeState::new(&[0b1000_0000], &[0b0110_0000]);
        let mut buffer = [0i16; 3];
        let mut sign = [1i16, -1, 0];
        state
            .upgrade_block(&mut buffer, &mut sign, 0, 1, true)
            .expect("decodes");
        assert_eq!(buffer, [0, -1, 1]);
        assert_eq!(
            sign,
            [1, -1, 1],
            "the zero entry now carries its decoded value"
        );
        assert_eq!(
            state.raw.pos, 2,
            "only the two signed entries read raw bits"
        );
    }

    /// The refinement is added into the existing coefficient at the band's shift, not written
    /// over it — the accumulate that makes a pass a *refinement*.
    #[test]
    fn a_refinement_accumulates_into_the_existing_coefficient() {
        let mut state = UpgradeState::new(&[], &[0b1100_0000]);
        let mut buffer = [100i16, -100];
        let mut sign = [1i16, 1];
        state
            .upgrade_block(&mut buffer, &mut sign, 3, 1, true)
            .expect("decodes");
        // raw bits `1` and `1` → magnitude 1 each, shifted left by 3 → +8.
        assert_eq!(buffer, [108, -92]);
    }

    /// A refinement that pushes a coefficient past `i16` is a typed error, never a wrap and
    /// never a panic.
    #[test]
    fn an_overflowing_refinement_is_a_typed_error() {
        let mut state = UpgradeState::new(&[], &[0xFF]);
        let mut buffer = [i16::MAX];
        let mut sign = [1i16];
        assert_eq!(
            state.upgrade_block(&mut buffer, &mut sign, 8, 4, true),
            Err(SrlError::ValueOverflow)
        );
    }

    /// **The threading property**, asserted on our own decoder: one raw stream is consumed
    /// across all ten bands, so two distinctive bytes appear exactly once — at the start of the
    /// first band — and never again at a later band's offset.
    ///
    /// This is the mirror of `oracle_still_restarts_both_streams_at_every_band` in
    /// `tests/progressive_srl_freerdp.rs`, which measures the oracle failing it at ten offsets.
    #[test]
    fn one_raw_stream_is_threaded_across_every_band() {
        let mut current = [0i16; COMPONENT_LEN];
        // Every sign non-zero, so every coefficient reads raw and SRL is never consulted.
        let mut sign = [1i16; COMPONENT_LEN];
        upgrade_component(
            &[],
            &[0xAA, 0xBB],
            &quant(0),
            &quant(8),
            &mut current,
            &mut sign,
        )
        .expect("decodes");

        let hits: Vec<usize> = (0..current.len() - 1)
            .filter(|&i| current[i] == 0xAA && current[i + 1] == 0xBB)
            .collect();
        assert_eq!(
            hits,
            vec![0],
            "the stream must not restart at a band boundary"
        );
        assert!(
            current[2..].iter().all(|&v| v == 0),
            "everything past the two supplied bytes reads as zero"
        );
    }

    /// **`LL3` is the only band the walk marks as lowpass**, and it must stay that way through
    /// [`upgrade_component`] — not merely through [`UpgradeState::upgrade_block`], which is
    /// handed the flag rather than deciding it.
    ///
    /// Every sign is 0, which on any *other* band routes the coefficient to SRL. If the walk
    /// misclassified `LL3`, these 81 coefficients would come out of the SRL stream and the sign
    /// array would be written; instead they come out of raw and the signs stay 0.
    #[test]
    fn only_the_last_band_is_treated_as_lowpass() {
        let mut num_bits = ProgressiveQuant {
            ll3: 2,
            hl3: 0,
            lh3: 0,
            hh3: 0,
            hl2: 0,
            lh2: 0,
            hh2: 0,
            hl1: 0,
            lh1: 0,
            hh1: 0,
        };
        num_bits.ll3 = 2;

        let mut current = [0i16; COMPONENT_LEN];
        let mut sign = [0i16; COMPONENT_LEN];
        // SRL bytes that would decode to something, so routing there is visible, and raw bytes
        // whose two-bit groups are 3, 1, 2, 0.
        upgrade_component(
            &[0xFF, 0xFF],
            &[0b1101_1000],
            &quant(0),
            &num_bits,
            &mut current,
            &mut sign,
        )
        .expect("decodes");

        assert_eq!(
            &current[4015..4019],
            &[3, 1, 2, 0],
            "LL3 must read the raw stream"
        );
        assert!(
            sign[4015..4096].iter().all(|&s| s == 0),
            "LL3 must never write the sign array"
        );
        assert!(
            current[..4015].iter().all(|&c| c == 0),
            "the zero-width bands must consume nothing"
        );
    }

    /// **The adaptive state — `kp`, `nz`, `mode` — survives a band boundary**, not just the bit
    /// cursors.
    ///
    /// [`one_raw_stream_is_threaded_across_every_band`] proves the *readers* are threaded, and
    /// that is only half of divergence 4. A decoder that threads both readers but restarts
    /// `kp`/`nz`/`mode` at every band passes it, passes all nine FreeRDP vectors (they drive one
    /// band), passes the corpus gate (it asserts no error, never a value) and passes both
    /// properties (they carry no expected values) — while decoding real captured data
    /// differently in the large majority of cases. This test is what fails it.
    ///
    /// Hand-derived, so it is checkable without running anything. On an all-zero SRL stream at
    /// `num_bits = 1` every symbol is a zero run: each run start costs one bit, emits `1 << k`
    /// zeros and raises `kp` by 4.
    ///
    /// | `kp` | `k` | run | symbols |
    /// |---|---|---|---|
    /// | 8 | 1 | 2 | 1–2 |
    /// | 12 | 1 | 2 | 3–4 |
    /// | 16 | 2 | 4 | 5–8 |
    /// | 20 | 2 | 4 | 9–12 |
    /// | 24 | 3 | 8 | 13–20 |
    /// | 28 | 3 | 8 | 21–28 |
    /// | 32 | 4 | 16 | 29–44 |
    /// | 36 | 4 | 16 | 45–60 |
    /// | 40 | 5 | 32 | 61–92 |
    ///
    /// A 72-symbol band therefore stops **inside** the run spanning 61–92, leaving `kp = 44`,
    /// `nz = 92 - 72 = 20`, `mode = false`, and nine run-start bits consumed.
    #[test]
    fn the_adaptive_state_survives_a_band_boundary() {
        let srl = [0u8; 4];
        let mut state = UpgradeState::new(&srl, &[]);
        let mut buffer = [0i16; 72];
        let mut sign = [0i16; 72];
        state
            .upgrade_block(&mut buffer, &mut sign, 0, 1, true)
            .expect("decodes");

        assert_eq!(buffer, [0; 72], "an all-zero SRL stream is all zero runs");
        assert_eq!(state.kp, 44, "kp after nine run starts");
        assert_eq!(state.nz, 20, "the run spanning symbols 61-92, cut at 72");
        assert!(!state.mode);
        assert_eq!(state.srl.pos, 9, "one bit per run start, nine of them");
    }

    /// The same property through the real entry point, where a single decoded value pins it.
    ///
    /// Two bands are given a width (`HL3` and `LH3`, 72 coefficients each) and the SRL stream
    /// carries exactly one `1` bit, at index 9 — the first bit band 2 would read. Carrying
    /// `nz = 20` across the boundary means band 2 spends its first 20 symbols draining that run
    /// and only *then* reads the `1`, so the refinement lands at band-2 index **20**. A decoder
    /// that restarts the adaptive state reads the `1` immediately and lands it at index **0**.
    ///
    /// One value, two possible places, and the difference is exactly the carried state.
    #[test]
    fn a_carried_zero_run_moves_the_refinement_20_coefficients_downstream() {
        let mut widths = quant(0);
        widths.hl3 = 1;
        widths.lh3 = 1;

        let mut current = [0i16; COMPONENT_LEN];
        let mut sign = [0i16; COMPONENT_LEN];
        upgrade_component(
            &[0x00, 0x40, 0x00, 0x00],
            &[],
            &quant(0),
            &widths,
            &mut current,
            &mut sign,
        )
        .expect("decodes");

        let (hl3, lh3) = (BANDS[6].0, BANDS[7].0);
        assert!(
            current[hl3..hl3 + 72].iter().all(|&v| v == 0),
            "band 1 is all zero runs"
        );
        assert_eq!(
            current[lh3 + 20],
            1,
            "the refinement must land where the carried run ends"
        );
        assert_eq!(
            current[lh3], 0,
            "landing at band-2 index 0 means the adaptive state was restarted"
        );
    }

    /// The band table covers the component exactly once, with no gap and no overlap — the
    /// property that makes the offsets above meaningful.
    #[test]
    fn the_band_table_tiles_the_component_exactly() {
        let mut next = 0usize;
        for (offset, length) in BANDS {
            assert_eq!(offset, next, "band table has a gap or an overlap");
            next += length;
        }
        assert_eq!(next, COMPONENT_LEN);
    }

    /// **Regression, #168 completeness pass.** [`ProgressiveQuant`]'s fields are `pub u8`, so a
    /// caller can hand over a value the parser could never produce — and this is a `pub fn` that
    /// slice 3 (#169) will call. All three of these panicked before the pass: a shift overflow in
    /// the magnitude cap, and an `i32` addition overflowing after a `shift` of 31 that
    /// `i32::checked_shl` had waved through.
    ///
    /// They are separate cases rather than one, because they fail in different arithmetic and a
    /// single fix could plausibly close one and leave the other.
    #[test]
    fn out_of_range_quant_nibbles_are_errors_not_panics() {
        let drive = |shift: u8, width: u8, seed: i16, sign_seed: i16| {
            let mut current = [seed; COMPONENT_LEN];
            let mut sign = [sign_seed; COMPONENT_LEN];
            upgrade_component(
                &[0xFF; 8],
                &[0xFF; 8],
                &quant(shift),
                &quant(width),
                &mut current,
                &mut sign,
            )
        };

        // num_bits past a u32 shift: the magnitude cap must stay bounded, and the values still
        // fit a coefficient, so this is a clean decode rather than an error.
        assert_eq!(drive(0, 200, 0, 0), Ok(()));
        // shift past a u32 shift: rejected by the shift itself.
        assert_eq!(drive(200, 15, 0, 1), Err(SrlError::ValueOverflow));
        // shift == 31 — inside `checked_shl`'s range, so only the accumulate can catch it.
        assert_eq!(drive(31, 15, i16::MIN, -1), Err(SrlError::ValueOverflow));
    }

    /// **Regression, #168 completeness pass (second round).** A shift wide enough to push every
    /// bit of the refinement out of an `i64` must be rejected, not silently applied as a no-op.
    ///
    /// `checked_shl` does not catch this: it rejects an out-of-range shift *amount* and says
    /// nothing about the *value*, so `2i64 << 63` is `Some(0)`, the sum equals the original
    /// coefficient, and `try_from` is happy. The whole component then reports success having
    /// refined nothing — worse than an error, because nothing signals it.
    #[test]
    fn a_shift_that_discards_the_whole_refinement_is_an_error_not_a_no_op() {
        for shift in [32u8, 48, 62, 63, 64, 255] {
            let mut widths = quant(0);
            widths.hl1 = 2;
            let mut shifts = quant(0);
            shifts.hl1 = shift;

            let mut current = [1234i16; COMPONENT_LEN];
            let mut sign = [1i16; COMPONENT_LEN]; // route to the raw stream
            assert_eq!(
                upgrade_component(
                    &[],
                    &[0b1000_0000],
                    &shifts,
                    &widths,
                    &mut current,
                    &mut sign
                ),
                Err(SrlError::ValueOverflow),
                "shift {shift} was accepted"
            );
        }
    }

    /// **Regression, #168 completeness pass (second round).** At `num_bits >= 16` the
    /// truncated-unary magnitude loop must run to the real `(1 << num_bits) - 1` cap, because
    /// `num_bits` reaches 30 rather than 15 ([`MAX_BIT_POS`]). Capping the *loop* at `i16::MAX`
    /// — as opposed to clamping the resulting value, which FreeRDP also does — leaves the shared
    /// bit cursor short and every later coefficient of the component decodes to a plausible
    /// wrong value with no error.
    ///
    /// The stream below opens a magnitude, then supplies a long zero run before a terminator, so
    /// a decoder that stops early lands the *next* symbol in the wrong place.
    #[test]
    fn a_wide_num_bits_runs_the_magnitude_loop_to_its_real_cap() {
        let mut data = vec![0b1000_0000u8];
        data.extend(std::iter::repeat_n(0u8, 5000));
        data.push(0xFF);

        let mut widths = quant(0);
        widths.hl1 = 16;
        let mut current = [0i16; COMPONENT_LEN];
        let mut sign = [0i16; COMPONENT_LEN];
        upgrade_component(&data, &[], &quant(0), &widths, &mut current, &mut sign)
            .expect("decodes");

        // Hand-checkable: the first magnitude exhausts 5000 bytes of zero run and clamps to
        // i16::MAX; the two that follow are `-1`s produced once the 0xFF terminator is reached;
        // the fourth clamps again. A loop capped at i16::MAX yields [32767, 0, 0, 0] instead,
        // because it stops 32768 bits early and reads only zero-fill thereafter.
        assert_eq!(
            &current[..4],
            &[32767, -1, -1, 32767],
            "the magnitude loop stopped short and desynchronised the stream"
        );
    }

    /// **A wide `num_bits` must not cost time proportional to `1 << num_bits`.**
    ///
    /// A liveness property, so it is asserted on the clock — the only instrument that can see
    /// it. Every value test in this module passes with the exhausted-stream jump removed,
    /// because skipping the jump changes no output: the loop still terminates at the cap, it
    /// just walks there one zero-filled bit at a time. What it changes is how long that takes.
    ///
    /// Measured on this machine, one magnitude at `num_bits = 30` against a one-byte stream:
    /// **1.6 µs** with the jump, **745 ms** without (release; 18.6 µs vs the same 745 ms in
    /// debug, which is where this test runs). A tile is 3 components × 10 bands, so a single
    /// malformed PDU buys ~22 seconds of CPU, and a region carries many tiles — the unbounded
    /// loop that
    /// [`untrusted decode never panics`](../../../../docs/map/invariant/untrusted-decode-never-panics.md)
    /// names alongside the panic and the wrong-pixels case.
    ///
    /// The bound is two seconds against an 18 µs expectation: five orders of magnitude of
    /// headroom, so it cannot flake on a loaded runner, and still four orders below the
    /// unguarded cost.
    #[test]
    fn a_wide_num_bits_costs_time_proportional_to_the_stream_not_to_the_cap() {
        let mut widths = quant(0);
        widths.hl1 = MAX_BIT_POS as u8;
        let mut current = [0i16; COMPONENT_LEN];
        let mut sign = [0i16; COMPONENT_LEN];

        let started = std::time::Instant::now();
        upgrade_component(
            &[0b1000_0000],
            &[],
            &quant(0),
            &widths,
            &mut current,
            &mut sign,
        )
        .expect("decodes");
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "the magnitude loop walked its cap instead of its stream ({elapsed:?})"
        );
    }

    /// `k` is `kp / 8` and `kp` is capped at 80, so the `1 << k` run length can never overflow.
    /// Asserted rather than reasoned, because it is the bound that keeps that shift total.
    #[test]
    fn kp_stays_within_its_cap_so_the_run_shift_is_bounded() {
        let mut state = UpgradeState::new(&[0x00; 64], &[]);
        // An all-zero SRL stream is an unbroken chain of zero runs, which is what drives kp up.
        for _ in 0..4096 {
            let _ = state.srl_read(1);
            assert!(state.kp <= KP_MAX, "kp escaped its cap: {}", state.kp);
            assert!(
                state.kp / 8 <= 10,
                "k escaped the range 1 << k is total over"
            );
        }
        assert_eq!(
            state.kp, KP_MAX,
            "the cap must actually be reached, or this proves nothing"
        );
    }

    /// The generator for a per-band quant value in the properties below.
    ///
    /// **Weighted rather than uniform over `u8`, and the weighting is load-bearing.** A uniform
    /// `u8` puts 87.5% of its mass at or above 32, where `checked_shl` rejects the very first
    /// band — so nearly every case returned an error before reaching any of the arithmetic the
    /// property exists to stress, and the property was vacuous exactly where it looked widest.
    /// The three arms are: everything a derived bit position can actually hold
    /// ([`MAX_BIT_POS`]), the band just outside it where 32-bit shifts stop being total, and the
    /// whole range.
    fn quant_nibble() -> impl proptest::strategy::Strategy<Value = u8> {
        const MAX: u8 = MAX_BIT_POS as u8;
        proptest::prop_oneof![
            6 => 0u8..=MAX,
            3 => (MAX + 1)..=40u8,
            1 => proptest::num::u8::ANY,
        ]
    }

    proptest::proptest! {
        /// [`untrusted decode never panics`](../../../../docs/map/invariant/untrusted-decode-never-panics.md):
        /// both bit streams come off the wire, and `shift` / `num_bits` are wire quant nibbles.
        /// Arbitrary values of all four must yield a value or a typed error — never a panic,
        /// an overflow, or an unbounded loop.
        ///
        /// The values are generated over the **full `u8` range**, well past the `0..=30` a
        /// derived bit position can hold ([`MAX_BIT_POS`]). That is deliberate and it is not
        /// theatre: [`ProgressiveQuant`]'s fields are plain `pub u8`, so the bound lives in the
        /// arithmetic that produces them and not in the type, and this is a `pub fn` that
        /// slice 3 will call.
        ///
        /// The first revision of this property bounded them to `0..=15` — and so could not
        /// reach the two panics the #168 completeness pass then found by hand (`1 << num_bits`
        /// at `num_bits >= 32`, and an `i32` addition overflowing at `shift == 31`). A property
        /// generated inside the guarantee it is meant to be independent of asserts nothing about
        /// the guarantee.
        #[test]
        fn upgrade_component_never_panics_on_arbitrary_input(
            srl in proptest::collection::vec(proptest::num::u8::ANY, 0..512),
            raw in proptest::collection::vec(proptest::num::u8::ANY, 0..512),
            shift_nibbles in proptest::array::uniform10(quant_nibble()),
            width_nibbles in proptest::array::uniform10(quant_nibble()),
            seed in proptest::num::i16::ANY,
            sign_seed in proptest::num::i16::ANY,
        ) {
            let to_quant = |n: [u8; 10]| ProgressiveQuant {
                hl1: n[0], lh1: n[1], hh1: n[2],
                hl2: n[3], lh2: n[4], hh2: n[5],
                hl3: n[6], lh3: n[7], hh3: n[8],
                ll3: n[9],
            };
            // Seeded, not zeroed: an upgrade pass always runs against the coefficients and signs
            // a *previous* pass wrote, and starting from zero makes the accumulate unable to
            // overflow at all — which is exactly why the first revision of this property missed
            // the `shift == 31` panic that the completeness pass found by hand.
            let mut current = [seed; COMPONENT_LEN];
            let mut sign = [sign_seed; COMPONENT_LEN];
            let _ = upgrade_component(
                &srl,
                &raw,
                &to_quant(shift_nibbles),
                &to_quant(width_nibbles),
                &mut current,
                &mut sign,
            );
        }

        /// A pass that errors partway leaves the coefficient store *partially* refined, which
        /// is fine — but it must not leave it torn in a way a later pass cannot describe: every
        /// entry is still a valid `i16` and the sign array still only ever holds values SRL or
        /// the caller put there. Stated as: two identical runs agree, so the failure is
        /// deterministic and re-drivable rather than dependent on uninitialised state.
        #[test]
        fn an_upgrade_pass_is_deterministic(
            srl in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
            raw in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
            width in quant_nibble(),
        ) {
            let run = || {
                let mut current = [0i16; COMPONENT_LEN];
                let mut sign = [0i16; COMPONENT_LEN];
                let outcome = upgrade_component(
                    &srl, &raw, &quant(1), &quant(width), &mut current, &mut sign,
                );
                (outcome, current, sign)
            };
            let (a_out, a_cur, a_sign) = run();
            let (b_out, b_cur, b_sign) = run();
            proptest::prop_assert_eq!(a_out, b_out);
            proptest::prop_assert!(a_cur == b_cur);
            proptest::prop_assert!(a_sign == b_sign);
        }
    }
}
