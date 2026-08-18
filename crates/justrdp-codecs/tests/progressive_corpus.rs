//! Replay + oracle canary over the real-VM RemoteFX Progressive corpus (issue #194).
//!
//! `fixtures/progressive/replay.bin` is one session's worth of genuine `WireToSurface2` block
//! streams captured from the test VM, **in arrival order** (see the README). Order matters:
//! Progressive is stateful twice over — codec contexts live across PDUs, and an upgrade pass
//! refines coefficients a *previous* first pass wrote — so a payload decoded in isolation is a
//! different input from the same payload decoded in sequence.
//!
//! **Why this file exists rather than a differential.** ADR-0011 makes the `ironrdp-graphics`
//! oracle scaffolding with a retirement condition, and #194 is the worked example: the oracle
//! cannot decode the streams this server sends. It rejects the very first frame, because
//! `quality = 0xFF` is a *full-quality sentinel* (FreeRDP `progressive.c:997`, `:1407`, table
//! initialised at `:2654`) and the oracle indexes its progressive-quant table by it
//! (`progressive.rs:1231`, `:1268` in 0.9.0). A gate defined as byte-identity with the oracle
//! would therefore have to exclude real traffic or reproduce the defect.
//!
//! So the properties asserted here are **owned**:
//!
//! 1. The self-owned parser accepts the entire capture — no stream the real server sent is
//!    rejected. This is Progressive's primary gate until the self-owned decoder lands (#171).
//! 2. The corpus actually spans the axes the epic needs: both quality forms, upgrade passes
//!    with SRL bytes, and both wire flags this server sets.
//! 3. **Canary**: the oracle still rejects the corpus with the `quality = 0xFF` signature. An
//!    oracle bump that fixes it turns this red — which is the point. The measuring instrument
//!    moving is a thing to be told about, not to discover through a silently changed baseline
//!    (`docs/map/invariant/oracle-agreement-is-not-independence.md`).

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
/// parser accepts every stream the real server sent — the property the oracle fails.
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

/// A corpus proves only what it contains (`docs/agents/theflow.md` Step 4), so measure the
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

    // Both quality forms. The sentinel is what the oracle chokes on; the indexed form is what
    // exercises the progressive-quant table at all, and only appears once the server has a
    // reason to run a quality ladder.
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

/// How the oracle fares against the corpus, bucketed by failure signature.
struct OracleOutcome {
    accepted: usize,
    sentinel_rejections: usize,
    missing_context_rejections: usize,
    other: std::collections::BTreeMap<String, usize>,
    total: usize,
}

fn run_oracle(entries: &[Entry]) -> OracleOutcome {
    let mut decoder = ironrdp_graphics::progressive::ProgressiveDecoder::new();
    let mut out = OracleOutcome {
        accepted: 0,
        sentinel_rejections: 0,
        missing_context_rejections: 0,
        other: std::collections::BTreeMap::new(),
        total: entries.len(),
    };
    for e in entries {
        match decoder.decode_bitmap(e.codec_context_id, e.width, e.height, &e.data) {
            Ok(_) => out.accepted += 1,
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("quant index 255") {
                    out.sentinel_rejections += 1;
                } else if msg.contains("missing CONTEXT block") {
                    out.missing_context_rejections += 1;
                } else {
                    *out.other.entry(msg).or_default() += 1;
                }
            }
        }
    }
    out
}

/// **Canary 1** — the oracle's `quality = 0xFF` defect, pinned.
///
/// `ironrdp-graphics` documents the sentinel on `TileState::quality` (`progressive.rs:768` on
/// master) and emits it from its own encoder, yet its region decode path indexes
/// `quant_prog_vals` by `quality` with no sentinel check (0.9.0 `progressive.rs:1231` for the
/// first pass, `:1268` for the upgrade pass). FreeRDP special-cases it at both call sites
/// (`progressive.c:997`, `:1407`, against the `quantProgValFull` entry initialised at `:2654`),
/// and the real server is on FreeRDP's side.
///
/// Mirrors `oracle_rlgr1_encoder_defect_still_present`: this test **wants** to fail on an
/// oracle bump that fixes the defect. A silently fixed oracle would change the measuring
/// instrument under a green suite — the failure mode ADR-0011 exists to prevent.
#[test]
fn oracle_still_rejects_the_full_quality_sentinel() {
    let outcome = run_oracle(&load_replay());
    assert!(
        outcome.sentinel_rejections > 0,
        "the oracle no longer rejects `quality = 0xFF`. If an ironrdp-graphics bump fixed this, \
         that is good news and this canary has done its job — re-read ADR-0011 and #194 before \
         deleting it, because the corpus, not the oracle, is still the gate."
    );
}

/// **Canary 2** — the oracle demands a `WBT_CONTEXT` block for every `codecContextId`, and this
/// server does not send one.
///
/// Measured on this corpus: the server emits **one** context block, on the first payload, and
/// then rotates `codecContextId` across **24 distinct ids in 52 payloads** — a fresh id per
/// refinement group, each grouping one first pass with its upgrade passes. The oracle keys its
/// contexts by that id and errors for every unseen one.
///
/// The direction of this divergence does not rest on the oracle at all — restated without
/// naming it: *a real Server 2022 sends these streams and a real client must paint them, so
/// refusing them is a receive-path defect.* This is the layer where `docs/agents/theflow.md`
/// gives authority to **the VM's observed behaviour, then FreeRDP's tolerance code** — the
/// tolerant-receive posture of ADR-0009 — rather than to a strict reading of the spec, so no
/// claim about what `[MS-RDPEGFX]` obliges is needed here, and none is made.
///
/// FreeRDP, the named tie-breaker, has no such requirement in any form: `progressive_wb_region`
/// (`progressive.c:2129`) gates a region on `FLAG_WBT_FRAME_BEGIN` alone, keys tile state by
/// **`surfaceId`** rather than by context id (`progressive_get_surface_data`, `:314`), and
/// merely `WLog_WARN`s when `ctxId != 0x00` (`:1999`).
///
/// This is a **separate** defect from canary 1, not a consequence of it: skipping the payload
/// that trips the sentinel does not save the payloads that follow.
#[test]
fn oracle_still_requires_a_context_block_per_codec_context_id() {
    let outcome = run_oracle(&load_replay());
    assert!(
        outcome.missing_context_rejections > 0,
        "the oracle no longer demands a CONTEXT block per codecContextId — see canary 1's note \
         on what a fixed oracle means here."
    );
}

/// The consequence the two canaries add up to, and the reason ADR-0011 §Decision 3 says a green
/// oracle diff is not an exit criterion: **the oracle cannot decode this server's traffic.**
///
/// Stated as a ceiling rather than an exact count, because the split between the two failure
/// signatures depends on where in the session the capture happened to start. What must not
/// happen quietly is the ceiling *rising* — that would mean the instrument moved.
#[test]
fn the_oracle_decodes_almost_none_of_the_corpus() {
    let outcome = run_oracle(&load_replay());
    eprintln!(
        "oracle vs corpus: {}/{} accepted, {} sentinel, {} missing-context, other {:?}",
        outcome.accepted,
        outcome.total,
        outcome.sentinel_rejections,
        outcome.missing_context_rejections,
        outcome.other
    );
    assert!(
        outcome.accepted * 10 < outcome.total,
        "the oracle decoded {}/{} payloads — it used to manage almost none. Re-read ADR-0011: \
         a more capable oracle is welcome news, but it is still not the gate.",
        outcome.accepted,
        outcome.total
    );
    // Right-reason bar: the claim is that *these two* defects are what stop it. A third
    // signature appearing is a finding, not a pass.
    assert!(
        outcome.other.is_empty(),
        "the oracle failed for a reason neither canary names: {:?}",
        outcome.other
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
                    for width in [0u8, 1, 2] {
                        let mut current = [0i16; COMPONENT_LEN];
                        let mut sign = [0i16; COMPONENT_LEN];
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
                                "payload {i}: a real upgrade run was rejected at num_bits={width}: {err}"
                            )
                        });
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
    eprintln!("upgrade components decoded: {components} (srl {srl_bytes} B, raw {raw_bytes} B)");
}
