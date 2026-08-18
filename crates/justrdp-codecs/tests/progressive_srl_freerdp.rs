//! FreeRDP-derived SRL expectations — the owned basis for Progressive's upgrade-pass entropy
//! layer (issue #194), and the gate for slice 2 (#168).
//!
//! # Why these vectors are hand-computed instead of captured or diffed
//!
//! Three things rule out every cheaper option, and each is measured rather than assumed:
//!
//! 1. **The oracle cannot arbitrate.** `ironrdp-graphics`'s SRL tests round-trip against its
//!    *own* `encode_srl`, so they are self-consistent by construction and say nothing about the
//!    wire — the tautological-proof shape ADR-0007's #118 amendment exists to route around.
//! 2. **The two references disagree with each other**, so "match the reference" is not a single
//!    instruction. `docs/agents/theflow.md` names **FreeRDP** as the tie-breaker for codec
//!    byte-exactness, so FreeRDP is what these vectors encode.
//! 3. **A real-server corpus cannot settle it either.** `fixtures/progressive/replay.bin` does
//!    carry genuine SRL bytes, but a captured stream proves a decoder only once you already
//!    know the pixels it should produce — which is the thing in question. The corpus is the
//!    gate for *acceptance*; these vectors are the gate for *values*.
//!
//! # Correction, 2026-08-18 (#168) — the first revision derived these at the oracle's `kp`
//!
//! The revision of this file that landed with #194 computed every expectation with an initial
//! `kp` of **0**. FreeRDP's is **8**, and it is not set in the function these vectors cite: it
//! is set by that function's only caller, `progressive_rfx_upgrade_component`
//! (`progressive.c:1272`), 110 lines past the end of the cited `:1075-1162` range. The value is
//! unchanged across FreeRDP 2.11.7 (`:1249`), 3.0.0 (`:1230`) and master.
//!
//! Five of the eight expectations were wrong as a result, and the `kp = 0` column reproduced
//! all eight exactly — which is what identifies the cause rather than merely the symptom. `kp`
//! of 0 is `ironrdp-graphics`'s initial value (`srl.rs:26`), so the owned basis had silently
//! inherited the state of the implementation it exists to be independent of. That is
//! [`oracle-agreement-is-not-independence`](../../../docs/map/invariant/oracle-agreement-is-not-independence.md)
//! reaching one level deeper than the invariant's own examples: not a decoder agreeing with the
//! oracle, but a *hand-derived expectation* agreeing with it.
//!
//! The vector set below is re-derived, and re-designed — the old set's three "positive
//! controls" were controls only under the wrong initial state (see the harness note below), and
//! two cases it could not reach at `kp = 0` are now covered: `k` growing past 1, and the `kp`
//! decrement observed on the symbol *after* the one that caused it.
//!
//! # The algorithm, as FreeRDP implements it
//!
//! `progressive_rfx_srl_read` (`progressive.c:1075-1162`), state `{ nz, kp, mode }` **created
//! by `progressive_rfx_upgrade_component` at `kp = 8, mode = 0, nz = 0`** and persisting across
//! every call for that component. All bit reads MSB-first:
//!
//! ```text
//! if nz > 0            { nz -= 1; return 0 }              // :1081-1085
//! k = kp / 8                                              // :1087   -- k == 1 on the first call
//! if mode == 0 {                                          // :1089
//!     bit = read(1)
//!     if bit == 0 { nz = 1 << k; kp = min(kp + 4, 80); nz -= 1; return 0 }   // :1096-1107
//!     else        { nz = 0; mode = 1                                        // :1111-1112
//!                   if k > 0 { nz = read(k) }                               // :1114-1120
//!                   if nz > 0 { nz -= 1; return 0 } }                       // :1122-1126
//! }
//! mode = 0                                                // :1130
//! sign = read(1)                                          // :1133
//! kp = if kp < 6 { 0 } else { kp - 6 }                    // :1136-1139
//! if numBits == 1 { return if sign { -1 } else { 1 } }    // :1141
//! mag = 1; max = (1 << numBits) - 1                       // :1143-1144
//! while mag < max { if read(1) == 1 { break }; mag += 1 } // :1146-1155
//! return if sign { -mag } else { mag }                    // :1159-1161
//! ```
//!
//! # Four divergences from `ironrdp-graphics`, not three
//!
//! #194 and #168 both describe the divergence as three things. Correcting the initial state
//! adds a fourth, and it is the one that fires earliest:
//!
//! - **Initial `kp`: 8 vs 0.** `k = kp / 8` is therefore 1 for the first symbol of every
//!   component, so FreeRDP reads a run-length bit the oracle never reads, and the two
//!   desynchronise from the first symbol on — before either of the next two can apply.
//! - **The magnitude is truncated unary starting at 1, with no remainder bits** and a hard cap
//!   at `(1 << numBits) - 1`. `ironrdp-graphics` (`srl.rs:86-101`) instead reads a Golomb-Rice
//!   quotient plus `numBits - 1` remainder bits. They coincide **only** at `numBits == 1`.
//! - **`mode` persists across calls.** After a `1` bit opens a `k`-bit zero run, the call that
//!   exhausts that run leaves `mode == 1`, so the *next* value skips the zero-encoding phase
//!   and goes straight to a magnitude. `ironrdp-graphics` keeps no such state.
//! - **One bit stream per component, threaded across all ten bands.** Measured by
//!   [`oracle_still_restarts_both_streams_at_every_band`] below.
//!
//! **The divergence is worst on the commonest input.** The corpus's progressive-quant bit
//! positions are `{0, 1, 2}`, so a real upgrade pass's `numBits = prev_bitpos - curr_bitpos` is
//! **1 or 2**, and at `numBits == 2` a magnitude of 1 — the smallest possible refinement, and
//! the one a refinement pass is mostly made of — comes out of FreeRDP as `+1` and out of the
//! oracle as `+2` (vector E).
//!
//! # How the harness proves itself, now that there are no positive controls
//!
//! The previous revision proved the bit plumbing with vectors on which the two implementations
//! agreed: *"a disagreement there would mean the harness feeds bits wrongly, not that the
//! algorithms differ."* At FreeRDP's real initial state that construction is not available —
//! the two desynchronise on the first symbol of every component, so agreement is coincidental
//! where it survives at all (vector A agrees while the two read **different bits**: FreeRDP
//! spends one on the `k`-bit run, the oracle does not, and both happen to land on a `0` sign).
//! Exactly one of the nine now agrees, and it is not evidence of anything.
//!
//! So the harness is proven directly instead, and without reference to either implementation:
//! `rfx::srl`'s own `bits_read_msb_first_and_zero_fill_past_the_end` and
//! `reading_zero_bits_consumes_nothing` pin the bit cursor's order and its end-of-stream
//! behaviour as unit tests. That is a stronger proof than the old controls were, because it
//! cannot be satisfied by two implementations sharing a mistake.

use justrdp_codecs::rfx::quant::COMPONENT_LEN;
use justrdp_codecs::rfx::srl;
use justrdp_pdu::rfx::progressive::ProgressiveQuant;

/// A hand-derived SRL vector: input bits, and what FreeRDP's machine yields for them.
struct Vector {
    name: &'static str,
    /// The SRL byte stream, MSB-first.
    data: &'static [u8],
    num_values: usize,
    num_bits: u8,
    /// Hand-computed from `progressive.c:1075-1162` at the initial state its caller sets
    /// (`kp = 8`). See each vector's trace below.
    freerdp: &'static [i16],
    /// Whether `ironrdp-graphics::srl::decode_srl` happens to land on the same values.
    /// **Measured, and not a control** — see the harness note in the module docs.
    oracle_agrees: bool,
}

/// The vectors. Traces are written against the pseudocode in this file's module doc, and every
/// one starts from `nz = 0, kp = 8, mode = 0`, so the first call has `k = kp / 8 = 1`.
const VECTORS: &[Vector] = &[
    //   call 1: nz=0, k=1, mode=0 → bit `1` → mode=1; k=1 → nz = read(1) = `0` = 0
    //           nz == 0 → fall through
    //           mode=0, sign=`0` → +, kp = 8-6 = 2, numBits==1 → +1
    // Bits `1 0 0`, padded → 0b1000_0000.
    Vector {
        name: "numBits=1, single positive",
        data: &[0b1000_0000],
        num_values: 1,
        num_bits: 1,
        freerdp: &[1],
        oracle_agrees: true,
    },
    // As above with the sign bit set. Bits `1 0 1` → 0b1010_0000.
    //
    // The oracle reads `1`, then — having no `k`-bit run to consume — takes the **second** bit
    // as the sign. That bit is `0`, so it yields +1 where FreeRDP yields -1: the same three
    // bits, read with a one-bit offset. This is the initial-`kp` divergence in its smallest
    // form.
    Vector {
        name: "numBits=1, single negative",
        data: &[0b1010_0000],
        num_values: 1,
        num_bits: 1,
        freerdp: &[-1],
        oracle_agrees: false,
    },
    //   call 1: k=1, mode=0 → bit `0` → nz = 1<<1 = 2, kp = 12, nz-- → 1, emit 0
    //   call 2: nz=1 → nz-- → 0, emit 0
    //   call 3: nz=0, k = 12/8 = 1, mode=0 → bit `1` → mode=1; nz = read(1) = `0` = 0
    //           → fall through; sign = `0` → +, kp = 12-6 = 6, numBits==1 → +1
    // Bits `0 1 0 0` → 0b0100_0000.
    Vector {
        name: "numBits=1, a zero run and the kp adaptation 8→12→6",
        data: &[0b0100_0000],
        num_values: 3,
        num_bits: 1,
        freerdp: &[0, 0, 1],
        oracle_agrees: false,
    },
    // **The `mode` state machine**, isolated at numBits=1 so the magnitude coding cannot be
    // what separates the two.
    //   call 1: k=1, mode=0 → bit `1` → mode=1; nz = read(1) = `1` = 1
    //           nz > 0 → nz-- → 0, emit 0   (mode stays 1)
    //   call 2: nz=0, mode==1 → **skip the zero-encoding phase entirely**
    //           mode=0, sign = `0` → +, kp = 8-6 = 2, numBits==1 → +1
    // Bits `1 1 0` → 0b1100_0000.
    //
    // The oracle keeps no `mode`: it reads `1`, no run bits, then takes `1` as the sign → -1,
    // and its second value re-enters zero-run mode on the `0` → 0. So `[-1, 0]` against
    // `[0, 1]` — the values, their signs and their order all differ.
    Vector {
        name: "numBits=1, mode persists across the call that drains a k-bit run",
        data: &[0b1100_0000],
        num_values: 2,
        num_bits: 1,
        freerdp: &[0, 1],
        oracle_agrees: false,
    },
    // **The realistic case.** The corpus's progressive-quant bit positions are {0, 1, 2}, so a
    // real upgrade pass's numBits is 1 or 2. At numBits=2 the two diverge on the *commonest*
    // refinement there is, a magnitude of 1:
    //   call 1: k=1 → bit `1` → mode=1; nz = read(1) = `0` = 0 → fall through
    //           sign = `0` → +, kp=2; numBits=2 → max = 3
    //           mag=1: read `1` → break immediately → +1
    // Bits `1 0 0 1` → 0b1001_0000.
    //
    // The oracle reads `1`, sign = `0` → +, then a Golomb-Rice quotient: `0` then `1`
    // terminates it at 1, and extra_bits = numBits-1 = 1 more bit (`0`) is the remainder →
    // magnitude = (1 << 1) | 0 = **2**. A +1 refinement is reported as +2.
    Vector {
        name: "numBits=2, magnitude 1 — the commonest real refinement",
        data: &[0b1001_0000],
        num_values: 1,
        num_bits: 2,
        freerdp: &[1],
        oracle_agrees: false,
    },
    // The magnitude cap — the loop exits on `mag == max` without a terminating 1 bit.
    //   call 1: k=1 → bit `1` → mode=1; nz = read(1) = `0` → fall through
    //           sign = `0` → +, kp=2; numBits=2 → max = 3
    //           mag=1: read `0` → mag=2; read `0` → mag=3; `mag < max` false → stop → +3
    // Bits `1 0 0 0 0` → 0b1000_0000.
    //
    // The oracle has no cap: it counts 0-bits past the end of the stream (its reader yields
    // zeros) until its 0x8000 guard, so the magnitude saturates to 32767.
    Vector {
        name: "numBits=2, magnitude truncated at (1<<numBits)-1",
        data: &[0b1000_0000],
        num_values: 1,
        num_bits: 2,
        freerdp: &[3],
        oracle_agrees: false,
    },
    // The same truncated-unary shape at a wider numBits, where the divergence is largest.
    //   call 1: k=1 → bit `1` → mode=1; nz = read(1) = `0` → fall through
    //           sign = `0` → +, kp=2; numBits=3 → max = 7
    //           mag=1: read `0` → 2; read `0` → 3; read `1` → break → +3
    // Bits `1 0 0 0 0 1` → 0b1000_0100.
    //
    // The oracle: quotient counts `0 0 0` to the terminating `1` (→ 3), then reads
    // extra_bits = 2 remainder bits (`0 0`) → magnitude = (3 << 2) | 0 = 12.
    Vector {
        name: "numBits=3, truncated-unary magnitude 3",
        data: &[0b1000_0100],
        num_values: 1,
        num_bits: 3,
        freerdp: &[3],
        oracle_agrees: false,
    },
    // `k` growing past 1, so the `1` branch reads a **multi-bit** run length. Reaching k=2
    // needs kp ≥ 16, i.e. two zero runs first — which is why no vector in the previous revision
    // reached it: at kp=0 the adaptation had further to climb.
    //   call 1: k=1, bit `0` → nz = 2, kp = 12, nz-- → 1, emit 0
    //   call 2: nz=1 → 0, emit 0
    //   call 3: k=1, bit `0` → nz = 2, kp = 16, nz-- → 1, emit 0
    //   call 4: nz=1 → 0, emit 0
    //   call 5: k = 16/8 = 2, bit `1` → mode=1; nz = read(2) = `10` = 2; nz-- → 1, emit 0
    //   call 6: nz=1 → 0, emit 0
    //   call 7: nz=0, mode==1 → skip the zero phase; sign = `0` → +, kp = 16-6 = 10 → +1
    // Bits `0 0 1 1 0 0` → 0b0011_0000.
    Vector {
        name: "numBits=1, k grows to 2 and the run length is read as two bits",
        data: &[0b0011_0000],
        num_values: 7,
        num_bits: 1,
        freerdp: &[0, 0, 0, 0, 0, 0, 1],
        oracle_agrees: false,
    },
    // `kp` shrinking, observed on the value *after* the one that shrank it — which none of the
    // vectors above can see, since each ends on the decrementing value itself.
    //   call 1: k=1 → bit `1` → mode=1; nz = read(1) = `0` → fall through
    //           sign = `0` → +, kp = 8-6 = 2 → +1
    //   call 2: k = 2/8 = **0**, so the `1` branch reads **no** run-length bits at all
    //           bit `1` → mode=1; k==0 → nz stays 0 → fall through
    //           sign = `1` → -, kp = 0 (2 < 6) → -1
    // Bits `1 0 0 1 1` → 0b1001_1000.
    //
    // Had `kp` stayed at 8, call 2 would have read a run bit and emitted 0 instead of -1 — the
    // decrement is load-bearing for the *next* symbol, not this one.
    Vector {
        name: "numBits=1, the kp decrement drops k to 0 for the next symbol",
        data: &[0b1001_1000],
        num_values: 2,
        num_bits: 1,
        freerdp: &[1, -1],
        oracle_agrees: false,
    },
];

/// A [`ProgressiveQuant`] with every band at `v`.
fn uniform(v: u8) -> ProgressiveQuant {
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

/// Drive **our** decoder over a vector, through its real public entry point.
///
/// Only `HL1` is given a non-zero width, so every other band is skipped without consuming a bit
/// (`progressive_rfx_upgrade_block`'s `numBits < 1` early return) and the whole SRL stream is
/// spent on the first band. Every sign starts at 0, which is what routes each coefficient to
/// SRL rather than to the raw stream, and a shift of 0 leaves the decoded values unscaled — so
/// the first `num_values` coefficients are the SRL output verbatim.
fn decode_vector(v: &Vector) -> Vec<i16> {
    let mut num_bits = uniform(0);
    num_bits.hl1 = v.num_bits;

    let mut current = [0i16; COMPONENT_LEN];
    let mut sign = [0i16; COMPONENT_LEN];
    srl::upgrade_component(v.data, &[], &uniform(0), &num_bits, &mut current, &mut sign)
        .expect("a well-formed vector decodes");

    current[..v.num_values].to_vec()
}

/// **The gate for #168.** Our decoder reproduces the hand-derived FreeRDP values exactly.
#[test]
fn our_decoder_matches_the_freerdp_derived_vectors() {
    for v in VECTORS {
        assert_eq!(
            decode_vector(v),
            v.freerdp,
            "{}: our SRL decoder diverged from the hand-derived FreeRDP expectation",
            v.name
        );
    }
}

/// The sign array is the other half of the SRL output: a coefficient it routed to SRL keeps the
/// value SRL produced, which is what a later pass reads to route the same coefficient to the
/// raw stream instead.
#[test]
fn a_decoded_value_is_written_back_into_the_sign_array() {
    let v = &VECTORS[7]; // six zeros then a +1 — both outcomes in one vector
    let mut num_bits = uniform(0);
    num_bits.hl1 = v.num_bits;

    let mut current = [0i16; COMPONENT_LEN];
    let mut sign = [0i16; COMPONENT_LEN];
    srl::upgrade_component(v.data, &[], &uniform(0), &num_bits, &mut current, &mut sign)
        .expect("decodes");

    assert_eq!(&sign[..v.num_values], v.freerdp);
    assert_eq!(
        sign[6], 1,
        "a coefficient SRL resolved to non-zero must stop being SRL-routed"
    );
}

/// Every vector is internally coherent: as many expected values as requested.
///
/// Cheap, but not free — it is what stops a later edit from silently shortening an expectation
/// array and turning a real comparison into a vacuous one.
#[test]
fn vectors_are_well_formed() {
    assert!(VECTORS.len() >= 8, "the vector set has shrunk");
    for v in VECTORS {
        assert_eq!(
            v.freerdp.len(),
            v.num_values,
            "{}: expectation length does not match num_values",
            v.name
        );
        assert!(v.num_bits >= 1, "{}: numBits must be at least 1", v.name);
    }
    // The set must reach past numBits == 1, where the magnitude coding is unobservable, and it
    // must reach k > 1, where the run length stops being a single bit.
    assert!(
        VECTORS.iter().any(|v| v.num_bits >= 2),
        "no vector exercises the truncated-unary magnitude loop"
    );
    assert!(
        VECTORS.iter().any(|v| v.num_values >= 7),
        "no vector runs long enough for kp to reach k > 1"
    );
}

/// **Canary** — the SRL divergence, pinned to the hand-derived FreeRDP values.
///
/// This asserts a *disagreement*, which is unusual and deliberate: while it holds, #168 cannot
/// be gated on the oracle, and the vectors above are what it is gated on instead. If an
/// `ironrdp-graphics` bump makes this go red, the measuring instrument has moved — re-read
/// ADR-0011 and #194 rather than deleting the vectors, which remain the owned basis either way.
#[test]
fn oracle_still_diverges_from_freerdp_on_srl() {
    let mut diverged = 0usize;
    for v in VECTORS {
        let got = ironrdp_graphics::srl::decode_srl(v.data, v.num_values, v.num_bits);
        eprintln!("{}: FreeRDP {:?} vs oracle {got:?}", v.name, v.freerdp);
        assert_eq!(
            got == v.freerdp,
            v.oracle_agrees,
            "{}: the oracle's agreement with FreeRDP has changed",
            v.name
        );
        if got != v.freerdp {
            diverged += 1;
        }
    }
    assert!(
        diverged >= 6,
        "fewer divergent vectors exercised than expected ({diverged})"
    );
}

/// **Canary** — the oracle reads each component's SRL and raw streams from offset 0 **once per
/// band**, where FreeRDP threads one stream, and one adaptive state, across all ten.
///
/// `ironrdp-graphics` calls `srl::decode_srl(srl_data, …)` and `RawBitReader::new(raw_data)`
/// *inside* its band loop (0.9.0 `progressive.rs:136`, `:140`), so band `n` re-reads the bytes
/// band 0 already consumed, with `kp`/`nz` reset. FreeRDP attaches both bit streams once in
/// `progressive_rfx_upgrade_component` (`progressive.c:1256-1277`) and carries
/// `RFX_PROGRESSIVE_UPGRADE_STATE` — `nz`, `kp`, `mode` — across every
/// `progressive_rfx_upgrade_block` call for that component.
///
/// The claim survives restatement without naming either implementation: *a single
/// per-component bit stream is consumed from its start once per band, so bands 1..9 decode
/// bytes that band 0 already spent.* That is a decoder defect on its own terms.
///
/// Observing it needs no pixel comparison. With `num_bits = 8` and a raw stream of exactly two
/// distinctive bytes, a threaded reader yields `0xAA, 0xBB` **once** and zeros thereafter; a
/// reader recreated per band yields them again at every band offset. The offsets this finds are
/// also the extrapolate band layout, and the last of them — **4015** — is the `LL3` offset
/// #194 cites from FreeRDP, arrived at here from the opposite direction. Our own decoder is
/// held to the other side of this in `rfx::srl`'s `one_raw_stream_is_threaded_across_every_band`.
#[test]
fn oracle_still_restarts_both_streams_at_every_band() {
    use ironrdp_pdu::codecs::rfx::progressive::ComponentCodecQuant;

    // num_bits = prev.for_band(i) - curr.for_band(i) = 8, for every band.
    let prev = ComponentCodecQuant {
        ll3: 8,
        hl3: 8,
        lh3: 8,
        hh3: 8,
        hl2: 8,
        lh2: 8,
        hh2: 8,
        hl1: 8,
        lh1: 8,
        hh1: 8,
    };
    let curr = ComponentCodecQuant::LOSSLESS;

    let raw = [0xAAu8, 0xBB];
    let srl: [u8; 0] = [];
    let mut coefficients = [0i16; 4096];
    // Every sign non-zero, so each coefficient reads from the raw stream and the SRL path is
    // not what is being measured here.
    let mut sign = [1i8; 4096];

    ironrdp_graphics::progressive::decode_upgrade_pass(
        &srl,
        &raw,
        &prev,
        &curr,
        true, // use_reduce_extrapolate — the layout every real region in the corpus declares
        &mut coefficients,
        &mut sign,
    );

    let restarts: Vec<usize> = (0..coefficients.len() - 1)
        .filter(|&i| coefficients[i] == 0xAA && coefficients[i + 1] == 0xBB)
        .collect();

    eprintln!("raw stream restarts at band offsets: {restarts:?}");
    assert!(
        restarts.len() > 1,
        "the oracle now threads one raw stream across bands (restarts: {restarts:?}). If an \
         ironrdp-graphics bump fixed this, the instrument has moved — see ADR-0011 and #194."
    );
    // Right-reason bar: one restart per band, not an incidental repeat of two byte values.
    assert_eq!(
        restarts.len(),
        10,
        "expected one restart per extrapolate band, got {restarts:?}"
    );
    assert_eq!(
        restarts,
        vec![0, 1023, 2046, 3007, 3279, 3551, 3807, 3879, 3951, 4015],
        "the restart offsets are the extrapolate band layout"
    );
}
