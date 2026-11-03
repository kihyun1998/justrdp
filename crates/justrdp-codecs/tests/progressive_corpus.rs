//! Replay over the real-VM RemoteFX Progressive corpus (issue #194).
//!
//! `fixtures/progressive/replay.bin` is one session's worth of genuine `WireToSurface2` block
//! streams captured from the test VM, **in arrival order** (see the README). Order matters:
//! Progressive is stateful twice over — codec contexts live across PDUs, and an upgrade pass
//! refines coefficients a *previous* first pass wrote — so a payload decoded in isolation is a
//! different input from the same payload decoded in sequence.
//!
//! The properties asserted here are **owned**; the corpus, not the `ironrdp-graphics` oracle,
//! is Progressive's gate (ADR-0011):
//!
//! 1. The self-owned parser accepts the entire capture — no stream the real server sent is
//!    rejected.
//! 2. The corpus actually spans the axes the epic needs: both quality forms, upgrade passes
//!    with SRL bytes, and both wire flags this server sets.

use justrdp_pdu::rfx::progressive::{self, ProgressiveMessage, ProgressiveTile, QUALITY_FULL};

/// One captured `WireToSurface2` payload with the codec context and surface dimensions it was
/// decoded against.
struct Entry {
    codec_context_id: u32,
    width: u16,
    height: u16,
    data: Vec<u8>,
}

fn load_replay() -> Vec<Entry> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/progressive/replay.bin");
    let buf = std::fs::read(path).expect("the Progressive replay corpus must be present");

    let mut entries = Vec::new();
    let count = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let mut pos = 4usize;
    for _ in 0..count {
        let codec_context_id = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
        let width = u16::from_le_bytes(buf[pos + 4..pos + 6].try_into().unwrap());
        let height = u16::from_le_bytes(buf[pos + 6..pos + 8].try_into().unwrap());
        let len = u32::from_le_bytes(buf[pos + 8..pos + 12].try_into().unwrap()) as usize;
        pos += 12;
        entries.push(Entry {
            codec_context_id,
            width,
            height,
            data: buf[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    entries
}

/// What the corpus contains, counted by walking it with the self-owned parser.
#[derive(Default)]
struct Census {
    simple: usize,
    first: usize,
    upgrade: usize,
    full_quality_tiles: usize,
    indexed_quality_tiles: usize,
    srl_bytes: usize,
    raw_bytes: usize,
    subband_diffing_contexts: usize,
    reduce_extrapolate_regions: usize,
    regions_with_prog_quant_table: usize,
}

fn census(entries: &[Entry]) -> Census {
    use justrdp_pdu::rfx::progressive::{
        CONTEXT_FLAG_SUBBAND_DIFFING, REGION_FLAG_DWT_REDUCE_EXTRAPOLATE,
    };

    let mut c = Census::default();
    for e in entries {
        let messages = progressive::decode_all(&e.data).expect("corpus payload must parse");
        for message in &messages {
            match message {
                ProgressiveMessage::Context { flags, .. } => {
                    if flags & CONTEXT_FLAG_SUBBAND_DIFFING != 0 {
                        c.subband_diffing_contexts += 1;
                    }
                }
                ProgressiveMessage::Region(region) => {
                    if region.flags & REGION_FLAG_DWT_REDUCE_EXTRAPOLATE != 0 {
                        c.reduce_extrapolate_regions += 1;
                    }
                    if !region.prog_quants.is_empty() {
                        c.regions_with_prog_quant_table += 1;
                    }
                    for tile in &region.tiles {
                        match tile {
                            ProgressiveTile::Simple(_) => c.simple += 1,
                            ProgressiveTile::First(t) => {
                                c.first += 1;
                                match t.quality {
                                    Some(QUALITY_FULL) | None => c.full_quality_tiles += 1,
                                    Some(_) => c.indexed_quality_tiles += 1,
                                }
                            }
                            ProgressiveTile::Upgrade(t) => {
                                c.upgrade += 1;
                                if t.quality == QUALITY_FULL {
                                    c.full_quality_tiles += 1;
                                } else {
                                    c.indexed_quality_tiles += 1;
                                }
                                c.srl_bytes += t.y_srl.len() + t.cb_srl.len() + t.cr_srl.len();
                                c.raw_bytes += t.y_raw.len() + t.cb_raw.len() + t.cr_raw.len();
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    c
}

#[test]
fn corpus_is_present_and_non_trivial() {
    let entries = load_replay();
    assert!(
        entries.len() >= 40,
        "replay corpus is suspiciously small ({} payloads)",
        entries.len()
    );
}

/// The headline #194 result, and Progressive's primary gate until #171: the **self-owned**
/// parser accepts every stream the real server sent.
///
/// This reproduces, VM-free, what the live `capture_progressive_corpus_against_real_vm` run
/// observed. Before #193 it would have held for none of them: the four `bitmapDataLength`
/// bytes reached the codec as the head of the block stream.
#[test]
fn self_owned_parser_accepts_the_full_capture() {
    for (i, e) in load_replay().iter().enumerate() {
        let messages = progressive::decode_all(&e.data).unwrap_or_else(|err| {
            panic!(
                "payload {i} (ctx {}, {}x{}, {} bytes) was rejected: {err}",
                e.codec_context_id,
                e.width,
                e.height,
                e.data.len()
            )
        });
        assert!(
            !messages.is_empty(),
            "payload {i} parsed to nothing — a silently empty accept is not an accept"
        );
    }
}

/// A corpus proves only what it contains (ADR-0003's Amendment), so measure the
/// axes rather than inferring them from the fixture's name. Each assertion below is an axis
/// some open slice of epic #158 needs, and the counts are the ones the capture reported.
#[test]
fn corpus_spans_the_axes_the_epic_needs() {
    let c = census(&load_replay());

    // Slice 3 (#169) — both pass kinds, so cross-pass tile state is exercised, not just decode.
    assert!(c.first > 0, "no TILE_FIRST tiles");
    assert!(
        c.upgrade > 0,
        "no TILE_UPGRADE tiles — without them the corpus cannot reach SRL at all"
    );

    // Slice 2 (#168) — upgrade passes carry both refinement streams.
    assert!(c.srl_bytes > 0, "upgrade tiles carry no SRL-coded bytes");
    assert!(c.raw_bytes > 0, "upgrade tiles carry no raw-bit bytes");

    // Both quality forms. The sentinel (`quality = 0xFF`) is the full-quality form; the indexed
    // form is what exercises the progressive-quant table at all, and only appears once the
    // server has a reason to run a quality ladder.
    assert!(
        c.full_quality_tiles > 0,
        "no full-quality (0xFF sentinel) tiles"
    );
    assert!(
        c.indexed_quality_tiles > 0,
        "no table-indexed quality tiles — the quality ladder is unexercised"
    );
    assert!(
        c.regions_with_prog_quant_table > 0,
        "no region carries a progressive-quant table"
    );

    // Both wire flags this server sets. RFX_DWT_REDUCE_EXTRAPOLATE in particular makes the
    // extrapolate band layout the *live* path, not the exotic one.
    assert!(
        c.subband_diffing_contexts > 0,
        "no context sets RFX_SUBBAND_DIFFING"
    );
    assert!(
        c.reduce_extrapolate_regions > 0,
        "no region sets RFX_DWT_REDUCE_EXTRAPOLATE"
    );
}

/// **Slice 2's real-input gate (#168).** Every SRL and raw run the real server actually sent is
/// driven through the self-owned upgrade decoder, and none of them may be rejected.
///
/// What this proves and what it does not, kept explicit because the distinction is the whole
/// reason #194 built two gates instead of one:
///
/// - It **does** prove totality over real bytes: 3250 `TILE_UPGRADE` tiles × 3 components,
///   decoded with no error, no panic and no unbounded loop. That is the acceptance property,
///   and it is the one a corpus can carry.
/// - It **does not** prove values. The real per-band `num_bits` is
///   `previous_pass_bit_pos - (quant + prog_quant)`, and the previous pass's bit positions live
///   in the cross-pass `TileState` that slice 3 (#169) builds — so this drives the widths the
///   capture's quant range makes real (1 and 2, plus 0 as the skip case) rather than the exact
///   ones. Values are gated by `progressive_srl_freerdp.rs`.
///
/// Driving a width the stream was not encoded at is deliberate rather than a compromise: it is
/// strictly harder than the real configuration, because the decoder runs past the end of every
/// real run and must still terminate cleanly on the zero-fill.
#[test]
fn the_self_owned_srl_decoder_accepts_every_real_upgrade_run() {
    use justrdp_codecs::rfx::quant::COMPONENT_LEN;
    use justrdp_codecs::rfx::srl;
    use justrdp_pdu::rfx::progressive::ProgressiveQuant;

    let uniform = |v: u8| ProgressiveQuant {
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
    };

    let mut components = 0usize;
    let mut srl_bytes = 0usize;
    let mut raw_bytes = 0usize;
    let mut raw_routed = 0usize;

    for (i, e) in load_replay().iter().enumerate() {
        for message in progressive::decode_all(&e.data).expect("the corpus parses") {
            let ProgressiveMessage::Region(region) = message else {
                continue;
            };
            for tile in region.tiles {
                let ProgressiveTile::Upgrade(t) = tile else {
                    continue;
                };
                for (srl_run, raw_run) in [
                    (t.y_srl, t.y_raw),
                    (t.cb_srl, t.cb_raw),
                    (t.cr_srl, t.cr_raw),
                ] {
                    srl_bytes += srl_run.len();
                    raw_bytes += raw_run.len();
                    components += 1;
                    // The widths the capture makes real: {0, 1, 2} bit positions, so a band's
                    // num_bits is 0 (skip), 1 or 2.
                    //
                    // Each width is driven against three starting states, and the last two are
                    // what make this gate non-vacuous. `BANDS` tiles the component exactly once,
                    // so a run driven with `sign` all-zero routes **every** non-lowpass
                    // coefficient to SRL: the `sign > 0` and `sign < 0` arms never execute, the
                    // raw stream is read only by `LL3`, and every accumulate lands on a zero
                    // prior — which is precisely the state the "unreachable on real traffic"
                    // claim on `SrlError::ValueOverflow` depends on. Seeding the sign array
                    // exercises the raw routing over real bytes; seeding the coefficient store
                    // is the closest this slice can get to a pass refining what a previous pass
                    // left, which is #169's to prove properly.
                    for width in [0u8, 1, 2] {
                        for (seed, sign_seed) in [(0i16, 0i16), (0, 1), (4096, -1)] {
                            let mut current = [seed; COMPONENT_LEN];
                            let mut sign = [sign_seed; COMPONENT_LEN];
                            srl::upgrade_component(
                                srl_run,
                                raw_run,
                                &uniform(6),
                                &uniform(width),
                                &mut current,
                                &mut sign,
                            )
                            .unwrap_or_else(|err| {
                                panic!(
                                    "payload {i}: a real upgrade run was rejected at                                      num_bits={width}, seed={seed}, sign_seed={sign_seed}: {err}"
                                )
                            });
                            if sign_seed != 0 {
                                raw_routed += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // Guard against a vacuous pass: the loop above is a no-op if the corpus stops carrying
    // upgrade tiles, and a green test would then say nothing.
    assert!(
        components >= 3 * 3000,
        "too few upgrade components exercised ({components}) — the corpus may have changed"
    );
    assert!(
        srl_bytes > 0 && raw_bytes > 0,
        "the corpus carried no entropy bytes to decode (srl {srl_bytes}, raw {raw_bytes})"
    );
    assert!(
        raw_routed >= 2 * components,
        "the non-lowpass raw branches were not driven over real bytes ({raw_routed})"
    );
    eprintln!(
        "upgrade components decoded: {components} (srl {srl_bytes} B, raw {raw_bytes} B present);          {raw_routed} drives took the non-lowpass raw routing"
    );
}
