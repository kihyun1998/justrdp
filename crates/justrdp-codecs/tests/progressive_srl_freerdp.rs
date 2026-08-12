//! FreeRDP-derived SRL expectations — the owned basis for Progressive's upgrade-pass entropy
//! layer (issue #194, consumed as the gate for slice 2, #168).
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
//! # The algorithm, as FreeRDP implements it
//!
//! `progressive_rfx_srl_read` (`progressive.c:1075-1162`), state `{ nz, kp, mode }` persisting
//! across calls, all bit reads MSB-first:
//!
//! ```text
//! if nz > 0            { nz -= 1; return 0 }              // :1081-1085
//! k = kp / 8                                              // :1087
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
//! Two features of that machine are what these vectors pin, and neither appears in #194's
//! summary of the divergence:
//!
//! - **The magnitude is truncated unary starting at 1, with no remainder bits** and a hard cap
//!   at `(1 << numBits) - 1`. `ironrdp-graphics` (`srl.rs:86-101`) instead reads a Golomb-Rice
//!   quotient plus `numBits - 1` remainder bits. They coincide **only** at `numBits == 1`.
//! - **`mode` persists across calls.** After a `1` bit opens a `k`-bit zero run, the call that
//!   exhausts that run leaves `mode == 1`, so the *next* value skips the zero-encoding phase
//!   and goes straight to a magnitude. `ironrdp-graphics` keeps no such state and re-enters
//!   zero-run mode instead, consuming a bit FreeRDP never reads.
//!
//! **The divergence is not exotic — it is worst on the commonest input.** The corpus's
//! progressive-quant bit positions are `{0, 1, 2}`, so a real upgrade pass's
//! `numBits = prev_bitpos - curr_bitpos` is **1 or 2**, and at `numBits == 2` a magnitude of 1
//! — the smallest possible refinement, and the one a refinement pass is mostly made of — comes
//! out of FreeRDP as `+1` and out of the oracle as `0`. Vectors chosen only at larger `numBits`
//! would have made this look like a corner case; it is the main path.
//!
//! Every vector below writes out its own bit-by-bit trace, so the expectation can be checked
//! against the pseudocode by hand — which is the whole point of an owned basis. Vectors marked
//! **agree** are positive controls: at `numBits == 1` the two implementations coincide, so a
//! disagreement there would mean the harness feeds bits wrongly, not that the algorithms
//! differ.

/// A hand-derived SRL vector: input bits, and what FreeRDP's machine yields for them.
struct Vector {
    name: &'static str,
    /// The SRL byte stream, MSB-first.
    data: &'static [u8],
    num_values: usize,
    num_bits: u8,
    /// Hand-computed from `progressive.c:1075-1162`. See each vector's trace below.
    freerdp: &'static [i16],
    /// Whether `ironrdp-graphics::srl::decode_srl` is expected to agree on this vector.
    oracle_agrees: bool,
}

/// The vectors. Traces are written against the pseudocode in this file's module doc.
const VECTORS: &[Vector] = &[
    // `1` opens unary (k = 0, so no run-length bits follow), `0` is the sign.
    //   call 1: nz=0, kp=0, k=0, mode=0 → bit `1` → mode=1, k=0 → nz=0 → fall through
    //           mode=0, sign=`0` → +, kp = 0, numBits==1 → +1
    // Bits `1 0`, padded → 0b1000_0000.
    Vector {
        name: "numBits=1, single positive",
        data: &[0b1000_0000],
        num_values: 1,
        num_bits: 1,
        freerdp: &[1],
        oracle_agrees: true,
    },
    // As above with sign bit set. Bits `1 1` → 0b1100_0000.
    Vector {
        name: "numBits=1, single negative",
        data: &[0b1100_0000],
        num_values: 1,
        num_bits: 1,
        freerdp: &[-1],
        oracle_agrees: true,
    },
    //   call 1: k=0, mode=0 → bit `0` → nz = 1<<0 = 1, kp = 4, nz-- → 0, emit 0
    //   call 2: nz=0, k = 4/8 = 0, mode=0 → bit `1` → mode=1, k=0 → nz=0 → fall through
    //           mode=0, sign=`0` → +, kp = 0 (4 < 6), numBits==1 → +1
    // Bits `0 1 0` → 0b0100_0000.
    Vector {
        name: "numBits=1, zero run then a value (kp adapts 0→4→0)",
        data: &[0b0100_0000],
        num_values: 2,
        num_bits: 1,
        freerdp: &[0, 1],
        oracle_agrees: true,
    },
    // The magnitude divergence, in its mildest form.
    //   call 1: k=0, mode=0 → bit `1` → mode=1, k=0 → nz=0 → fall through
    //           mode=0, sign=`0` → +, kp=0, numBits=3 → max = 7
    //           mag=1: read `0` → mag=2; read `0` → mag=3; read `1` → break → +3
    // Bits `1 0 0 0 1` → 0b1000_1000.
    //
    // The oracle reads the same `1` and `0`, then treats the rest as Golomb-Rice: quotient
    // counts 0-bits to the terminating 1 (→ 2), extra_bits = numBits-1 = 2 remainder bits
    // (→ `00`), magnitude = (2 << 2) | 0 = 8. Not 3.
    Vector {
        name: "numBits=3, truncated-unary magnitude 3",
        data: &[0b1000_1000],
        num_values: 1,
        num_bits: 3,
        freerdp: &[3],
        oracle_agrees: false,
    },
    // The magnitude cap — the loop exits on `mag == max` without a terminating 1 bit.
    //   call 1: bit `1` → unary; sign `0` → +; numBits=3 → max = 7
    //           six `0` bits raise mag 1→7, then `mag < max` is false and the loop stops
    //           having consumed exactly six bits and no terminator → +7
    // Bits `1 0 0 0 0 0 0 0` → 0b1000_0000.
    //
    // The oracle has no cap: it counts 0-bits past the end of the stream (its reader yields
    // zeros), so the quotient runs away to its 0x8000 guard and the magnitude saturates.
    Vector {
        name: "numBits=3, magnitude truncated at (1<<numBits)-1",
        data: &[0b1000_0000],
        num_values: 1,
        num_bits: 3,
        freerdp: &[7],
        oracle_agrees: false,
    },
    // **The realistic case.** The corpus's progressive-quant bit positions are {0, 1, 2}, so a
    // real upgrade pass's numBits = prev_bitpos - curr_bitpos is 1 or 2 — never the 3 above.
    // At numBits=2 the two diverge on the *commonest* refinement there is, a magnitude of 1:
    //   call 1: bit `1` → unary; sign `0` → +; numBits=2 → max = 3
    //           mag=1: read `1` → break immediately → +1
    // Bits `1 0 1` → 0b1010_0000.
    //
    // The oracle reads the same `1` and `0`, then takes that `1` as the Golomb-Rice terminator
    // for a quotient of 0, and consumes extra_bits = numBits-1 = 1 more bit as a remainder
    // (padding, `0`) → magnitude = (0 << 1) | 0 = **0**. A refinement of +1 is silently dropped.
    Vector {
        name: "numBits=2, magnitude 1 — the commonest real refinement",
        data: &[0b1010_0000],
        num_values: 1,
        num_bits: 2,
        freerdp: &[1],
        oracle_agrees: false,
    },
    // numBits=2 at the cap, the other realistic rung.
    //   call 1: bit `1` → unary; sign `0` → +; numBits=2 → max = 3
    //           mag=1: read `0` → mag=2; read `0` → mag=3; `mag < max` false → +3
    // Bits `1 0 0 0` → 0b1000_0000.
    Vector {
        name: "numBits=2, magnitude truncated at (1<<numBits)-1",
        data: &[0b1000_0000],
        num_values: 1,
        num_bits: 2,
        freerdp: &[3],
        oracle_agrees: false,
    },
    // The `mode` state machine, isolated at numBits=1 so the magnitude coding cannot be what
    // separates the two.
    //   call 1: k=0, mode=0 → bit `0` → nz=1, kp=4, nz-- → 0, emit 0
    //   call 2: k=0, mode=0 → bit `0` → nz=1, kp=8, nz-- → 0, emit 0
    //   call 3: k = 8/8 = 1, mode=0 → bit `1` → mode=1, k=1 → nz = read(1) = `1` = 1
    //           nz > 0 → nz-- → 0, emit 0   (mode stays 1)
    //   call 4: nz=0, mode==1 → **skip the zero-encoding phase entirely**
    //           mode=0, sign=`0` → +, kp = 8-6 = 2, numBits==1 → +1
    // Bits `0 0 1 1 0` → 0b0011_0000.
    //
    // The oracle keeps no `mode`, so its fourth value re-enters zero-run mode and consumes the
    // `0` as a run-length bit, emitting a zero where FreeRDP emits +1.
    Vector {
        name: "numBits=1, mode persists across the call that drains a k-bit run",
        data: &[0b0011_0000],
        num_values: 4,
        num_bits: 1,
        freerdp: &[0, 0, 0, 1],
        oracle_agrees: false,
    },
];

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
    // The set must contain both kinds, or it cannot do its job: agreements prove the harness,
    // disagreements prove the divergence.
    assert!(
        VECTORS.iter().any(|v| v.oracle_agrees),
        "no positive control — a disagreement could then just be wrong bit packing"
    );
    assert!(
        VECTORS.iter().any(|v| !v.oracle_agrees),
        "no divergent vector — nothing pins why an owned basis is needed"
    );
}

/// **Positive control.** Where FreeRDP and the oracle genuinely coincide — `numBits == 1`, and
/// the zero-run machine up to the point `mode` matters — the oracle reproduces the hand-derived
/// values exactly.
///
/// This is what makes the divergence test below meaningful: both implementations are being fed
/// the same bits in the same order (MSB-first; `srl.rs`'s `BitReader` and FreeRDP's
/// `wBitStream` accumulator agree on that), so a mismatch elsewhere is about the algorithm.
#[test]
fn oracle_matches_freerdp_where_the_two_coincide() {
    for v in VECTORS.iter().filter(|v| v.oracle_agrees) {
        let got = ironrdp_graphics::srl::decode_srl(v.data, v.num_values, v.num_bits);
        assert_eq!(
            got, v.freerdp,
            "{}: the oracle diverged on a vector where FreeRDP's machine and its own coincide \
             — suspect the harness (bit order, padding) before the algorithms",
            v.name
        );
    }
}

/// **Canary** — the SRL divergence, pinned to the hand-derived FreeRDP values.
///
/// This asserts a *disagreement*, which is unusual and deliberate: while it holds, #168 cannot
/// be gated on the oracle, and the vectors above are what it must be gated on instead. If an
/// `ironrdp-graphics` bump makes this go red, the measuring instrument has moved — re-read
/// ADR-0011 and #194 rather than deleting the vectors, which remain the owned basis either way.
#[test]
fn oracle_still_diverges_from_freerdp_on_srl() {
    let mut diverged = 0usize;
    for v in VECTORS.iter().filter(|v| !v.oracle_agrees) {
        let got = ironrdp_graphics::srl::decode_srl(v.data, v.num_values, v.num_bits);
        eprintln!("{}: FreeRDP {:?} vs oracle {got:?}", v.name, v.freerdp);
        assert_ne!(
            got, v.freerdp,
            "{}: the oracle now agrees with FreeRDP — the divergence this basis exists for may \
             be closed",
            v.name
        );
        diverged += 1;
    }
    assert!(
        diverged >= 3,
        "fewer divergent vectors exercised than expected"
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
/// #194 cites from FreeRDP, arrived at here from the opposite direction.
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
        restarts[0], 0,
        "band 0 must start at the beginning of the stream"
    );
}
