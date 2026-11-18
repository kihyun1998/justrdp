# 0011 — Zero `ironrdp` is the terminal state: the oracle is scaffolding, not a permanent dependency

- Status: Accepted (conformance items #225) — amended 2026-08-13 (#194), 2026-08-18 (#168), 2026-08-18 (#169), 2026-08-19 (#171), 2026-08-19 (#172), 2026-08-19 (#189), 2026-08-26 (#225), 2026-10-26 (#558), 2026-11-02 (#560), 2026-11-02 (#566) and 2026-11-03 (#576); see the Amendments below
- Date: 2026-08-10
- Records a decision by the maintainer; supersedes the open-ended dev-dependency premise in [ADR-0003](0003-phased-codecs-differential-oracle.md) phase 3 and [ADR-0007](0007-stage-boundary-codec-verification.md) §Decision
- Related: #158 (Progressive), #189 (zgfx), #194 (Progressive's verification basis)

## Context

Every existing record treats the `ironrdp` dependency as *temporary in the runtime graph* and
*permanent in the test graph*, and none of them says where it ends:

- [ADR-0002](0002-dependency-boundary.md) §Notes writes the target graph as
  `justrdp → { rustls, sspi, ironrdp-graphics (temporary) }` — "temporary" with no terminal
  condition attached.
- [ADR-0003](0003-phased-codecs-differential-oracle.md) phase 3 drops the dependency **per
  codec**, gated on *"100% of oracle comparisons"* — so the oracle outlives every codec it
  gates, by construction.
- [ADR-0007](0007-stage-boundary-codec-verification.md) §Decision states it outright: *"The
  oracle crates remain **dev-dependencies only** (ADR-0003)"* — a statement about what they are,
  written where a statement about how long they last would go.

So "justrdp eventually depends on no `ironrdp` crate at all" is the project's evident intent —
`CLAUDE.md` opens with *"`ironrdp` 을 대체하되"* — and is nowhere a decision. That gap is not
academic: it makes the oracle's authority open-ended, and an instrument nobody has agreed to
retire is one nobody re-examines.

Three findings, all measured against the real WS2019 VM on 2026-08-10 while working #168,
turned that from untidy into load-bearing:

1. **The oracle rejects the first frame this server sends.** Its `TILE_FIRST` tiles carry
   `quality = 0xFF` with `numProgQuant = 0`. `0xFF` is a sentinel — *full quality, no
   progressive quantization* — special-cased by FreeRDP (`progressive.c:997`, `:1407`) and not
   by `ironrdp-graphics`, whose region decode path indexes the progressive-quant table by it and
   fails with `quant index 255 exceeds table length 0` (`progressive.rs:1064`, `:1080`) despite
   documenting the sentinel on `TileState::quality` (`:768`).
2. **The two reference implementations disagree with each other on SRL magnitude coding**
   (FreeRDP truncated-unary from 1, capped at `(1 << numBits) - 1`, `progressive.c:1145-1157`;
   IronRDP Golomb-Rice with `num_bits - 1` remainder bits, `srl.rs:86-101`), and IronRDP's SRL
   tests round-trip against its own encoder, so they are self-consistent by construction and
   cannot arbitrate.
3. **The server sets `RFX_SUBBAND_DIFFING`** (context `flags = 0x01`), which FreeRDP reads and
   then marks `WINPR_ATTR_UNUSED` at both receiving functions, and `ironrdp-graphics` never
   reads at all.

This is the fourth adjudication the oracle has lost in this repo (#122, #127, #118, now this),
and the first where it is wrong on the **live** path rather than merely same-lineage. The map's
`oracle-agreement-is-not-independence` invariant already predicts this shape — *"the oracle
rejects a stream a real Server 2019 sends"* is one of the two violations it names; what it lacks
is an end date.

## Decision

**`ironrdp` is scaffolding. The terminal state is zero `ironrdp` crates in this repo's
dependency graph — runtime *and* development.**

1. **Runtime.** Unchanged from ADR-0003: the `egfx-bootstrap` delegation drops per codec as each
   is self-owned. Progressive's dropped in #172 and zgfx's in #189, which deleted the feature
   itself — **done**: the runtime graph is `justrdp → { rustls, sspi }`.
2. **Development.** The oracle is a *bootstrapping instrument with a retirement condition*, not
   a standing gate. A codec's oracle dev-dependency drops when that codec's correctness rests on
   a basis we own — a real-server corpus plus expectations derived independently of our
   implementation, in the shape [ADR-0007](0007-stage-boundary-codec-verification.md)'s #118
   amendment already requires for the assembly layer. #194 defines that basis for Progressive
   and is the worked example.
3. **The oracle never outranks the owned basis.** Where the oracle and a real-server corpus
   disagree, the corpus wins; where the oracle and FreeRDP disagree, ~~the tie-breaker in
   [`docs/agents/thegraph.md`](../agents/thegraph.md) already names FreeRDP~~ **— the pointer
   went dangling on 2026-09-04 and the ranking now has a record of its own.** `thegraph.md`
   was cut to the five outside sources and its one-sentence tie-breaker was dropped; it names
   FreeRDP today only as an `example`-binding source, which is not a ranking. The three-level
   authority — owned basis, then the differential oracle, with FreeRDP as the tie-break — is
   stated in [ADR-0003's Amendment](0003-phased-codecs-differential-oracle.md) (2026-09-04),
   which this clause narrows rather than restates. This decision adds
   only that a green oracle diff is **not** by itself an exit criterion once an owned basis
   exists for that codec.
4. **`rustls` and `sspi` are unaffected.** They are security-critical, non-RDP-specific leaf
   dependencies (ADR-0002) and are permanent by that decision, not by this one.

### How this was decided

Presented to the maintainer on 2026-08-10 as three options after the VM probe: report the
oracle defect upstream, redefine #171's gate only, or state a terminal zero-`ironrdp` position.
They chose the third and asked that it be written down rather than left implicit in the issue
tracker — *"어차피 새 크레이트를 만들거임 ironrdp 의존 안 하고, 그게 어딘가에는 적혀있어야
한다"*. **This is a scope decision, and reversing it is theirs**; the evidence above is why it is
coherent, not why it is compelled.

## Consequences

- **ADR-0003's phase-3 exit criterion is no longer sufficient on its own.** "100% of oracle
  comparisons" remains a useful bar where the oracle is capable; it stops being *the* bar. ~~Each
  codec's issue states which basis retires its oracle.~~ **Measured false (2026-08-26 amendment,
  #225): none of them does, and #194 — the example Decision 2 names — states the opposite.** The
  rule lives here, keyed on role; the roster is derived, never written down.
- **ADR-0007 keeps its method and loses its permanence.** Stage-boundary verification against
  the oracle's primitives stays exactly as specified — that is real independent math — but its
  *"the oracle crates remain dev-dependencies only"* now reads as a scope statement, not a
  duration.
- **Progressive is the first codec to exercise this**, because it is the first where the oracle
  demonstrably cannot decode real traffic (#194).
- **The runtime half is closed and the development half is not.** `ironrdp-graphics` left the
  runtime graph entirely in #189 (2026-08-19 amendment); it remains a **dev-dependency** of
  `justrdp-codecs`, as does `ironrdp-pdu` of `justrdp-pdu` and `justrdp`, and each retires on
  that codec's or layer's own owned basis. No new tracker structure is created by this record.
- **The `ironrdp-pdu` dev-dependency in `justrdp-pdu` is in scope too.** It is the differential
  oracle for wire round-trips (`tests/differential_ironrdp.rs`), the same instrument in a
  different layer, and the same retirement condition applies: an owned basis, then drop.
- **A cost is accepted.** Removing the oracle removes a real safety net on codecs where no
  real-server corpus is obtainable — CAVIDEO RemoteFX is the standing example (ADR-0007
  §Consequences: *"synthetic-only verification is an explicit ceiling for codecs the VM never
  emits"*). For those, the oracle stays until an owned basis exists, and the honest answer may
  be "not yet".

## Rejected alternatives

- **(A) Keep the oracle as a permanent dev-dependency and treat its defects as noise.** Rejected:
  the instrument is already wrong on the live path, and a gate that cannot decode the traffic
  the product must decode is not measuring the product. Keeping it also leaves the retirement
  question permanently unasked, which is how ADR-0004's `[patch.crates-io]` bridge outlived its
  own condition by six weeks.
- **(B) Fix the oracle upstream and keep depending on it.** Rejected as the *governing* strategy,
  not as a courtesy: an upstream fix helps everyone and may still be worth sending, but making
  this project's correctness bar depend on another project's release cadence reintroduces the
  coupling ADR-0017 (then `GLOSSARY.md` §Project intent) exists to remove. It is also not one defect — findings 2
  and 3 above are a disagreement between references and an unimplemented flag, neither of which
  an upstream patch resolves.
- **(C) Drop the oracle immediately, everywhere.** Rejected: the oracle is genuinely independent
  math for the transform stages, and for codecs with no capturable real-server stream it is
  currently the only external check. Retirement is per codec, on evidence, not a flag day.
- **(D) Record this in the issue tracker only.** Rejected — and it is what prompted this record.
  #194 states the consequence for one codec; the position it follows from spans ADR-0002,
  ADR-0003 and ADR-0007, and an issue structurally cannot hold a rule that spans decisions.

## Amendment (2026-08-13, #194): the basis exists, and the oracle is less capable than this record assumed

Progressive's owned basis landed — a 52-payload real-server corpus
(`justrdp-codecs/tests/fixtures/progressive/`) plus FreeRDP-derived SRL expectations
(`tests/progressive_srl_freerdp.rs`), each defect pinned by a canary. Two corrections to the
Context above, both measured. **(a)** The oracle decodes **2 of 52** payloads, not "rejects
the first frame" — and a *fourth* defect is the larger cause: it demands a `WBT_CONTEXT`
block per `codecContextId`, while this server sends one such block ever and then rotates
through 24 ids. FreeRDP imposes no such requirement (`progressive.c:2129`, `:314`). The two
failures are independent; skipping the sentinel payload does not save the rest. **(b)** The
premise that a real-server SRL vector might be unobtainable was **false**, and the cause was
ours: the capture advertised `connectionType = LAN`, so the server sent full quality on the
first pass and never refined. Advertising `MODEM` yields 3250 upgrade tiles. Promoted to
[`capture-coverage-follows-what-we-advertise`](../map/invariant/capture-coverage-follows-what-we-advertise.md).
The Decision is unchanged; the oracle dev-dependency stays until the self-owned decoder
exists (#171) and is live (#172), and the canaries are what use it.

## Amendment (2026-08-18, #168): the oracle's reach extended into the owned basis itself

Slice 2 measured a **fifth** oracle divergence — its SRL state starts at `kp = 0` where
FreeRDP's starts at `8` (`progressive.c:1272`, unchanged since 2.11.7), so the two
desynchronise on the first symbol of every component, ahead of the three divergences #194
named. The finding that matters for *this* record is where it was found: five of the eight
hand-derived FreeRDP vectors had themselves been computed at `kp = 0` — the oracle's initial
value, though FreeRDP's own `WINPR_C_ARRAY_INIT` declaration predicts the same mistake, and
the evidence does not separate the two. So this is **not** recorded as the oracle having
shaped the basis; it is recorded as the basis having been derived from a range too narrow to
contain the state it depended on. The Decision is unchanged, and the honest strengthening is
narrower than it first looked: the owned basis was wrong on its first attempt, which is an
argument for scheduling the oracle's removal rather than for trusting either instrument.
Promoted to
[`oracle-agreement-is-not-independence`](../map/invariant/oracle-agreement-is-not-independence.md)
as a third violation shape.

## Amendment (2026-08-18, #169): two more divergences, both in the first pass, and neither one the oracle could be patched out of

Slice 3 measured a **sixth** and **seventh**:
(6) the oracle captures the DAS sign array *after* dequantization
(`progressive.rs:84`) where FreeRDP captures it off the raw entropy output
(`progressive.c:876`) — measured over the corpus, the two capture points disagree on **8369
of 8829** real components, because the LL3 delta reconstruction runs between them, and the
error is permanent rather than per-frame because the sign array routes every later
refinement of that coefficient; (7) the oracle's `dwt_extrapolate` narrows every lifting tap
with `value as i16` where FreeRDP saturates (`clampi16`), so on an overflowing tap the two
differ by a full `u16`.
Two things follow for this record. First, the count is now seven, spread across the parse,
the entropy layer, the first pass and the transform — the oracle is not defective at a point
but at every layer of this codec, which is what makes "fix it upstream" (rejected
alternative B) unavailable rather than merely unattractive. Second, and more useful: **one
oracle primitive survived and is still in use.** `dwt_extrapolate` is a self-contained
transform with no stream state, and it agrees coefficient-for-coefficient wherever the
narrowing seam is unreachable, which is what makes it a usable ADR-0007 stage-boundary
cross-check. Retirement stays *per codec and per stage*, on evidence — that is the Decision
working, not an exception to it.

## Amendment (2026-08-19, #171): the self-owned decoder exists, and the basis proved something the oracle structurally could not

Slice 5 assembled the pipeline
(`justrdp_codecs::rfx::progressive::Progressive`) and gated it on the owned basis this record
requires — the 52-payload corpus plus FreeRDP-derived expectations — with a fresh real-VM run
as the round-trip (**0 tiles skipped, 0 failures**, over 862 tiles the server sent that day).
Two things belong on this record rather than only in the issue.
**(a) The oracle is not merely unable to decode this traffic; on the assembly layer it is on
the wrong side of a picture-changing question.** `ironrdp-graphics::progressive` returns whole
64 x 64 tiles and never clips them to the region's rects; FreeRDP clips (`update_tiles`,
`progressive.c:2329-2412`). Measured over the corpus, the two policies leave **57 386 of a
1 280 x 800 surface's 1 024 000 pixels different**. So a differential against the oracle would
not merely have been *unmeetable* here — passing it would have required painting the wrong
picture, which is a stronger statement than the Context above makes and the one that
retroactively justifies rejecting alternative (B).
**(b) The owned basis found something no oracle diff could have.** The corpus carries no
expected pixels, so the decisive instrument was a *counterfactual* — replaying the same bytes
under both policies and diffing the surfaces. That is only available to a basis you own; a
differential can compare two implementations but cannot price one implementation's own
alternative. Recorded because "the owned basis is weaker than a diff, just necessary" is the
easy reading of this record, and this is a case where it was strictly stronger.
The Decision is unchanged. The dev-dependency now supports only the canaries and the
`dwt_extrapolate` stage cross-check; the **runtime** dependency for Progressive dropped in
#172 (2026-08-19 amendment), which was wiring rather than decoding.

## Amendment (2026-08-19, #172): Progressive's runtime delegation is gone, and the wiring falsified one of epic #158's own recorded premises

The self-owned decoder is the live
WireToSurface2 decoder; `ironrdp-graphics` now serves Progressive only as a dev-dependency
for the canaries and the `dwt_extrapolate` stage cross-check. The runtime graph still holds
it for **zgfx alone** (#189). Two things worth keeping off the PR body: the epic recorded
that `Surface::blit` "cannot express a source offset" and that this slice would have to widen
it — **measured false**, because the blit's slice start and its stride are independent
parameters, so a source offset is a slice rather than a signature change; and the swap
*removes* the per-tile `Vec<u8>` the bootstrap wrapper allocated, 6193 x 16 KiB over one
captured session, which is the frame path's no-owned-pixels invariant reaching one stage
further up than it had.

## Amendment (2026-08-19, #189): the runtime half of this record is done, and the reason it mattered turned out to be broader than correctness

zgfx is self-owned
(`justrdp_codecs::zgfx`), the `egfx-bootstrap` feature is deleted, and
`cargo tree -p justrdp-tokio -e normal` names **no `ironrdp` crate at all** — the Decision's
point 1 reached, and the graph is `justrdp → { rustls, sspi }` as ADR-0002 §Notes wrote it.
Three things belong on the record.
**(a) A runtime delegation exports the robustness posture too, and no oracle diff measures
that.** This record's Context is about the oracle being *wrong*; for zgfx it is not wrong —
it decodes everything its own compressor emits, and the differential in
`tests/differential_zgfx.rs` passes over sequences. What it *was* is unguarded: probed
directly, **five of seven** crafted `RDP_SEGMENTED_DATA` messages panicked inside
`ironrdp_graphics::zgfx` (`mid > len` from a `split_at` on an untrusted `u32`, `attempt to
subtract with overflow` from `8 * (len - 1) - last_byte`, and three bit-cursor index
panics), and the panic reached `justrdp::egfx::GraphicsProcessor::process` — the live path,
because this decompressor sees every EGFX byte before the PDU parser does. That gap was
**structural, not an oversight**: the fuzz roster derives from `ls fuzz/fuzz_targets/` and
the no-panic properties live in this repo's own modules, so a delegated decode path cannot
appear in either by construction. Retiring a delegation is therefore worth doing even where
the delegate is *correct*.
**(b) zgfx did not need an owned basis in Progressive's sense, and got one anyway.** The
`[MS-RDPEGFX]` sample is reproduced byte-identically by FreeRDP
(`libfreerdp/codec/test/TestFreeRDPCodecZGfx.c`, *"Sample from [MS-RDPEGFX]"*) and by
`ironrdp-graphics`, so an expectation derived independently of both implementations was
available for the asking — and its compressed segment matches at distance 31 back into an
*earlier segment*, which is the cross-message history contract in one vector. The oracle
keeps its dev-dependency role here as breadth, which is what point 3 of the Decision
intends.
**(c) The coverage ceiling, measured rather than assumed.** Instrumented against the VM for
one session: **25 messages, every one `ZGFX_SEGMENTED_SINGLE` and every one
`PACKET_COMPRESSED`** — 18 488 literal tokens, 19 024 matches, 7 unencoded runs, longest
match 5 062 bytes, **longest distance 133 937**, which is past a single segment's 65 535
ceiling and so is direct evidence of the window spanning messages on a real wire. The
multipart descriptor `0xE1` **never appeared**; its proof is the spec vector and the
oracle differential, not the VM.

## Amendment (2026-08-26, #225): the condition in Decision 2 cannot reach zero as written, and this record's own Consequences assert a distribution that never happened

#225 asked what the
development half's exit condition is now that the runtime half has closed. The measured answer is
worse than *"there is none"*: there **is** one, and it is falsified on all three of its own worked
examples.
**(a) Every surface that meets the condition still holds the dependency, and the amendments above
already say why.** Progressive meets it (#171/#194) — the 2026-08-19/#171 amendment: *"The
dev-dependency now supports only the canaries and the `dwt_extrapolate` stage cross-check."* zgfx
meets it (#189) — *"keeps its dev-dependency role here as breadth."* ClearCodec meets it (#127)
and `justrdp-codecs/tests/clearcodec_corpus.rs:107` still requires `oracle_rejections > 0`. The
structural reason is one sentence: **a canary's subject is the oracle's own defect**, so *"this
codec's correctness rests on a basis we own"* is its **precondition, not its exit** — the canary
exists precisely because the owned basis and the oracle disagree. Measured, **six** such tests
across four files: `differential_rfx.rs:328`, `progressive_corpus.rs:261` and `:294`,
`progressive_srl_freerdp.rs:389` and `:431`, `clearcodec_corpus.rs:107`. They retire by deletion,
never by satisfaction.
**(b) The Consequences above claim a distributed obligation that does not exist.** *"Each codec's
issue states which basis retires its oracle"* is false as written. #194 — the worked example
Decision 2 itself names — says the opposite: *"**Keep the oracle as a cross-check where it
agrees**, not as the exit criterion."* #127, #189, and all seven of #158's children state none.
This is the mirror of [ADR-0004](0004-sspi-contribute-and-bridge.md)'s own amendment, and
the harder direction of it: a record asserting an obligation **was** distributed reads as the
evidence that it was, so nothing prompts the check.
**(c) The corrected rule is keyed on role, not on codec, because the role decides the exit
mechanism.** Decision 2 describes one mechanism; there are five.

| Role | How it exits | Sites today |
|---|---|---|
| **R1 verifier** — the differential itself | Decision 2 as written: an owned basis, then drop. **Except** where an amendment above keeps it as *breadth* over an input space the basis cannot span (zgfx, #189) | `justrdp-pdu/tests/differential_ironrdp.rs`: `our_correlation_info_decodes_identically_in_ironrdp` (the encoder-bytes half), `connection_confirm_selected_protocol_matches_ironrdp`, `output_control::our_bytes_equal_ironrdps_encoder` · `differential_activation.rs`: `server_license_request_parses_to_the_same_rsa_key_in_both_stacks` · `justrdp-codecs/tests/differential_ironrdp_graphics.rs`: `interleaved_rle_matches_ironrdp_on_generated_streams`, `interleaved_rle_rejects_what_the_oracle_rejects`, `rdp6_aycocg_variants_match_the_oracle_decoder`, and `rdp6_planar_decodes_ironrdp_encoder_output_identically` (also R2) · `differential_zgfx.rs`: `a_compressed_stream_decodes_identically_to_the_oracle`, `every_compression_mode_decodes_identically_to_the_oracle`, `a_multipart_message_past_the_single_segment_limit_decodes_identically`, `a_long_run_decodes_identically_to_the_oracle`, `a_message_boundary_is_not_a_history_boundary` (all five also R2) · `differential_rfx.rs`: `every_inverse_stage_matches_the_oracle_primitive_at_its_boundary`, `full_payload_rgba_matches_the_composed_oracle_reference` (both also R2) · `differential_pointer_ironrdp.rs`: `random_shapes_decode_byte_identically_at_16_24_32_bpp`, `color_pointer_with_forced_special_cases_matches_the_oracle` · `clearcodec_corpus.rs`: `self_owned_matches_oracle_on_every_entry`, `text_capture_replays_and_matches_the_oracle` · `justrdp/tests/differential_input_ironrdp.rs`: `fastpath_input_pdus_match_ironrdp_byte_for_byte`, `fastpath_explicit_count_and_long_length_match_ironrdp`, `slowpath_input_body_matches_ironrdp_byte_for_byte` · `justrdp-security/tests/differential_license_crypto.rs`: `key_derivation_matches_ironrdp` · `justrdp-tokio/src/lib.rs`: `captured_bitmap_rectangles_decode_identically_in_ironrdp` |
| **R2 generator** — `ironrdp` *encodes* what we then decode | **for the codec tests (zgfx, planar, RemoteFX, ClearCodec) and the `connect.rs` helpers, we write the encoder.** No corpus retires them: a corpus supplies streams a server sent, and these tests need streams a server never sends. `differential_rfx.rs` states the trap in its module doc — *"The synthetic streams are this test's corpus"*, generated by the instrument that then grades them. **For the five `justrdp-pdu` `ironrdp_*` tests, a committed real-server capture of that frame**, as for R3: `ironrdp_font_map_decodes_as_our_session_active_gate` is met already, `ironrdp_connect_response_decodes_identically_in_justrdp` needs value assertions on `connect-response.bin` (and never for its skip-channel-join case, which this VM does not advertise), and the other three need a new capture (paragraph (d)) | `justrdp-pdu/tests/differential_ironrdp.rs`: `ironrdp_connect_response_decodes_identically_in_justrdp`, `ironrdp_attach_user_and_channel_join_confirms_decode_in_justrdp` · `differential_activation.rs`: `ironrdp_valid_client_error_alert_decodes_as_our_short_circuit`, `ironrdp_demand_active_decodes_to_the_same_capability_fields`, `ironrdp_font_map_decodes_as_our_session_active_gate` · `justrdp-codecs/src/clearcodec.rs`: `round_trips_the_oracle_encoder` · `tests/differential_ironrdp_graphics.rs`: `rdp6_planar_decodes_ironrdp_encoder_output_identically` (also R1) · `differential_zgfx.rs`: the five listed in R1 (the oracle's compressor and `wrap_uncompressed` author the streams) · `differential_rfx.rs`: `every_inverse_stage_matches_the_oracle_primitive_at_its_boundary` and `full_payload_rgba_matches_the_composed_oracle_reference` (also R1; the oracle's forward transforms in `forward_coefficients` author the coefficients, and `build_stream` encodes the TS_RFX container with `ironrdp-pdu`) · `justrdp/src/connect.rs`: the helpers `iron_connect_response`, `iron_connect_response_echoing`, `iron_attach_user_confirm`, `iron_channel_join_confirm`, `server_io_frame` and `standard_connect_response` |
| **R3 acceptance** — *their* decoder eats *our* bytes | a committed real-server capture, or the VM run. Decision 2 does not reach it at all: there is no codec, and no *"our correctness"* to rest on a basis | `differential_ironrdp.rs`: `our_connection_request_decodes_identically_in_ironrdp`, `our_correlation_info_decodes_identically_in_ironrdp` (the decode half), `our_connect_initial_decodes_identically_in_ironrdp`, `our_erect_domain_and_channel_join_requests_decode_in_ironrdp`, `our_client_info_pdu_decodes_identically_in_ironrdp`, `our_client_auto_reconnect_cookie_decodes_in_ironrdp`, `our_send_data_request_decodes_in_ironrdp_with_the_client_info_payload`, `output_control::ironrdp_decodes_our_refresh_rect`, `output_control::ironrdp_decodes_our_suppress_and_allow` · `differential_activation.rs`: `our_new_license_request_decodes_identically_in_ironrdp`, `our_platform_challenge_response_decodes_identically_in_ironrdp`, `our_confirm_active_with_default_capabilities_decodes_in_ironrdp`, `our_finalization_batch_decodes_identically_in_ironrdp` · `justrdp/src/connect.rs`: `tls_established_under_ssl_writes_connect_initial_without_nla`, `client_info_pdu_is_sent_on_the_io_channel_with_caller_fields`, `early_capability_flags_reach_the_connect_initial_verbatim`, and the helpers `sent_reconnect_cookie` and `client_user_data` · `justrdp-codecs/tests/differential_rfx.rs`: `harness_encoder_is_faithful_by_the_oracles_own_decoder` (the bytes are the test harness's encoder's, not the crate's) · `justrdp-security/tests/differential_license_crypto.rs`: `platform_challenge_response_verifies_under_ironrdp_keys` |
| **R4 canary** — the subject is the oracle's own defect | **deletion**, with the last R1 holder in that crate. Each is also a *scheduled* CI red on an upstream fix, and the instruction for that day lives only in the assertion message | `differential_rfx.rs`: `oracle_encoder_round_trips_both_modes` · `progressive_srl_freerdp.rs`: `oracle_agrees_with_freerdp_on_every_vector`, `oracle_threads_one_stream_across_every_band` (the three left after #576; the six in (a) were the 2026-08-26 count) |
| **R5 stage-boundary math** (ADR-0007) | with the last R1/R4 holder, never before — the 2026-08-18/#169 amendment keeps it explicitly (*"one oracle primitive survived and is still in use"*) | `the_reduce_extrapolate_inverse_dwt_matches_the_oracle_primitive_in_range` in `differential_progressive_stages.rs` |

**(d) "Zero `ironrdp` crates" is four crates, not two.** `Cargo.lock` names `ironrdp-core`,
`ironrdp-error`, `ironrdp-graphics` and `ironrdp-pdu`; #225's table counts the two **direct**
dev-dependencies. The Decision's wording is the lock's reading, and the two transitive crates
leave with the two direct ones — recorded so a future audit does not read a green
`cargo tree --depth 1` as the terminal state.
**(e) What this does not change.** *"No new tracker structure is created by this record"* stands.
#225's option (a) — an epic with per-surface children — was declined, and **not** on its stated
cost: that objection was measured false, since #158's seven children (#167–#172, #194) are all
closed, as is #158. It was declined because a per-surface roster keyed on *"does an owned basis
exist"* would report three surfaces ready on its first day, per (a) above. The roster is
**derived, not stored** — the manifests, plus
`grep -rln "ironrdp_[a-z]*::\|use ironrdp" --include=*.rs crates/` (15 files today). A bare
`ironrdp` grep over-counts: `progressive_assembly_corpus.rs`, `progressive_multipass_corpus.rs`
and `real_server_connect.rs` name it only in prose. Conformance items go on the Status line
above, the pattern [ADR-0012](0012-consumption-site-totality.md) already runs.
**How this was decided, and which half is reversible by whom.** (a)–(d) are **derivations** and
fall to a better derivation. The tracking shape in (e) is the maintainer's **product judgement**,
taken 2026-08-26 after being shown all four options with the measurements above — including the
one that removed (a)'s stated cost — and reversing it is theirs.

## Amendment (2026-10-26, #558): RemoteFX has a real-server corpus, and its oracle stays as breadth

The *"cost accepted"* consequence above names CAVIDEO RemoteFX as the codec with no obtainable
corpus. That is false since #554: WS2019 sends RemoteFX to an EGFX advertisement of 8 and 8.1 with
`THINCLIENT`, and `justrdp-codecs/tests/fixtures/remotefx/` holds 41 payloads, all decoding.
**(a) The corpus does not span what the differential covers.** Measured over those 41: RLGR1 only,
one quantization table, single-rectangle regions. RLGR3, every other table, the zero-exponent
refusal and empty regions (#117) reach the decoder from `differential_rfx.rs`'s synthetic streams
alone. So RemoteFX's **R1** stays as **breadth**, as zgfx's did in #189, and its **R2** stays by the
role table's own rule: only an encoder of ours ends it.
**(b) Retiring either role would not drop a dependency.** `ironrdp-graphics` is also held by
ClearCodec, zgfx, Progressive and pointer tests, and `ironrdp-pdu` by
`differential_pointer_ironrdp.rs` and `progressive_srl_freerdp.rs`; the canary at
`differential_rfx.rs:328` retires only with the crate's last R1 holder.
**(c) What the corpus is for instead.** The composed reference glues this decoder's own region and
blit logic (ADR-0007, assembly layer), so an expectation for real payloads that does not come from
that logic is the gap worth closing. It is tracked as its own issue, not as a retirement condition.
**How this was decided.** (a) and (b) are measurements and fall to better ones. Keeping the oracle
as breadth and tracking the independent expectation separately is the maintainer's call
(2026-10-26), made over three options: this, this alone without the follow-up, and the follow-up
plus a test-only TS_RFX encoder to end R2.

## Amendment (2026-11-02, #560): RemoteFX's values come from FreeRDP, and R1 stops at the ICT

#558's (c) is closed: `remotefx_freerdp_pixels.rs` checks every tile of the 41 real payloads
against FreeRDP 3.32.1's generic C decoder, through digests in `fixtures/remotefx/`.
**(a) The first comparison found a disagreement the oracle could not have.** 62 pixels in 15
records differed by one in one channel. The cause is the ICT's fixed-point coefficients: FreeRDP
rounds the spec's constants times 2^16 (`prim_colors.c`, `ycbcr_constants[16]`), and this decoder
truncated them, as `ironrdp-graphics` does through `yuv` 0.8.14 (`rdp.rs:381-384`). The oracle and
this decoder agreed because they share the choice, which is the shape
[oracle agreement is not independence](../map/invariant/oracle-agreement-is-not-independence.md)
names. With rounded constants all 3720 tiles match.
**(b) So R1 no longer covers the ICT.** `differential_rfx.rs` compares RLGR, the LL3 delta,
dequantization and the inverse DWT with the oracle's primitives, and its composed reference uses
this decoder's ICT. The ICT's expectation is FreeRDP's pixels. Progressive shares the ICT
(`color::rfx_ycbcr_to_rgba`), so its pixels moved too; its assembly test re-pinned its surface
hash, and no FreeRDP expectation covers Progressive's pixels yet.
**How this was decided.** (a) is a measurement. Rounding the constants, rather than keeping the
truncation and recording the 62 pixels as a known difference, is the maintainer's call
(2026-11-02), made on that measurement and on ADR-0003's ranking of an owned basis above the
oracle.

## Amendment (2026-11-02, #566): Progressive's pixels match FreeRDP's

#560's amendment left Progressive's pixels unmeasured against FreeRDP. `progressive_freerdp_pixels.rs`
now replays its 52 real payloads and compares the surface after each with FreeRDP 3.32.1's
generic C decoder, through digests in `fixtures/progressive/`: every one of the 13,520 tiles
matches in R, G and B. With #560's truncated coefficients 4248 would not. Alpha is not compared:
FreeRDP writes 0 and this decoder 255. This is a measurement and falls to a better one.

## Amendment (2026-11-03, #576): the oracle is at 0.11, and no R4 canary is left

`ironrdp-graphics` and `ironrdp-pdu` moved from 0.9 to 0.11 in every crate. All six R4 canaries of
the 2026-08-26 table went red on the bump, because upstream fixed the defects they pinned
(RLGR1 `kp`, the `quality = 0xFF` sentinel, the per-context CONTEXT block, SRL magnitude coding,
SRL streams restarted per band, ClearCodec's three rejections). So did two tests that rested on an
oracle defect without being listed: `the_oracle_decodes_almost_none_of_the_corpus` (0.11 decodes
52 of 52 Progressive payloads) and zgfx's single-segment test, whose 150 KB fixture the 0.11
compressor now splits into a multipart message. Eight tests in all; no test found this project's
output disagreeing with the oracle's. The changelog reading the bump is gated on is the 0.9 → 0.11
worked example in [oracle agreement is not independence](../map/invariant/oracle-agreement-is-not-independence.md#where-it-will-recur).
**(a) Where a canary already computed a comparison, it now asserts agreement.** Each was run
against 0.9 and fails there on the old defect:
- `clearcodec_corpus.rs` `self_owned_matches_oracle_on_every_entry` diffs our decoder against the
  oracle: **R1**.
- `progressive_srl_freerdp.rs` `oracle_agrees_with_freerdp_on_every_vector` checks the oracle
  against our hand-derived FreeRDP vectors, and `oracle_threads_one_stream_across_every_band` and
  `differential_rfx.rs` `oracle_encoder_round_trips_both_modes` check the oracle alone. These three
  run no code of ours; their subject is still the oracle, so they are R4 with the polarity
  reversed, and they exit as R4 does, by deletion with the crate's last R1 holder.

The three Progressive corpus canaries and the zgfx single-segment test were deleted. The zgfx
test was the only one reaching the decoder's segment cap through output already produced;
`src/zgfx.rs`'s `output_already_produced_counts_against_the_segment_cap` reaches it with
hand-built bytes, and `a_single_match_longer_than_the_segment_cap_is_an_error` covers one match
past it.
**(b) The RLGR1 canary's own instruction was not followed.** It said to drop the harness encoder
and feed the oracle's `rfx_encode_component`. That would make the oracle the stream factory, the
R2 role this record's table ends only when we own the encoder; the harness encoder is ours and
stays proven by the oracle's decoder.
**(c) ClearCodec's corpus lost a coverage proof.** `oracle_rejections > 0` and the three rejection
signatures were the evidence that the corpus exercises #56's `shortVBarCacheMiss`, `rlex` and
`vbarIndex` shapes. The 0.11 oracle rejects nothing, so nothing asserts the corpus still holds
those shapes. [ADR-0007](0007-stage-boundary-codec-verification.md) cites that guard as its
example of a coverage assertion, and [ADR-0009](0009-tolerant-negotiation-posture.md) cites the
oracle's rejections as part of the ground for ClearCodec's RLEX clip; 0.11 clips an over-filled
RLEX region and decodes the NSCodec subcodec, so that ground is now the corpus alone. Both rules
stand.
**Closed 2026-11-18 (#587), with one shape that was never there.** `clearcodec_corpus.rs`
`corpus_holds_every_shape_the_decoder_was_fixed_for` counts the shapes with a parser of its own:
684 short V-bar cache misses the swapped layout rejects, 1726 full V-bar cache hits on a column
only a stream the swap rejects stored, and 8 single-palette RLEX regions. It finds no over-filled
RLEX region. The 0.9 oracle's `rlex` rejections came from its 0-bit single-palette
parse, which over-fills by one pixel per segment, the same parse #131 removed from our decoder; with
it the test counts 8 inexact regions, the 8 single-palette ones. So the test asserts that every RLEX
region fills exactly, and the RLEX clip's corpus ground, which the sentence above assumed, is gone
(ADR-0009's #576 amendment). Asserting exact fill and recording the lost ground, while leaving the
clip itself and the keep-or-reject question open, is the maintainer's call (2026-11-18), made after
being shown the measurement and the option of leaving RLEX out of the test.
**How this was decided.** The red tests, the 0.9 reruns and the role each test now plays are
measurements. Turning the comparing canaries into agreement checks rather than deleting all of
them, as the role table's R4 row reads, is the maintainer's call (2026-11-03), made after being
shown both options: deletion drops a cross-check with an oracle that now agrees; keeping them
keeps the dependency longer. What they were shown called all four R1; that three are R4 was found
afterwards. The consequence they weighed holds either way, since R4 exits with the last R1 holder.

## Amendment (2026-11-18, follow-up of #587): the `our_*` tests are R3, and the role table cites names

Both calls below are the maintainer's, made on 2026-11-18.

**(a) The `our_*` tests in `justrdp-pdu` are R3, not R1.** The R1 row listed *"the `differential_*` tests"*,
and the `justrdp-pdu` Cargo.toml comment called that crate's oracle an *"R1 verifier"*. But R3 is defined as
*their* decoder eating *our* bytes, and the `our_*` tests in `differential_ironrdp.rs` and
`differential_activation.rs` do exactly that: they encode with our code and decode with `ironrdp_pdu::decode`.
The maintainer was shown R3's definition against the R1 listing, and chose to move them. The tests that
decode bytes built by the test itself with both stacks stay R1
(`server_license_request_parses_to_the_same_rsa_key_in_both_stacks`,
`connection_confirm_selected_protocol_matches_ironrdp`), as does a comparison of the two encoders' bytes
(`our_bytes_equal_ironrdps_encoder`). Classifying every test in the two files by the same definitions
also found five `ironrdp_*` tests where `ironrdp` encodes and we decode. They are R2 and were in no row:
`ironrdp_connect_response_decodes_identically_in_justrdp`,
`ironrdp_attach_user_and_channel_join_confirms_decode_in_justrdp`,
`ironrdp_valid_client_error_alert_decodes_as_our_short_circuit`,
`ironrdp_demand_active_decodes_to_the_same_capability_fields` and
`ironrdp_font_map_decodes_as_our_session_active_gate`. `our_correlation_info_decodes_identically_in_ironrdp`
does two things: its decode half is R3, and its comparison of `ironrdp`'s encoder bytes with ours is R1.

**What R3's exit is.** R3 exits by a real-server capture of the client-to-server leg, or a VM run. It does
not exit by an owned basis, because there is no codec of ours whose correctness a basis could rest on. So
moving these tests out of R1 means the R1 exit (an owned basis, then drop) no longer retires them.

**(b) Every cell of the role table cites test or function names with their file, not line numbers.** The
cells had drifted in under three months: R1's `justrdp-tokio/src/lib.rs:2315` and `:2330` were at about
`:10907` and `:10922`, and R2's `connect.rs:1251-1255` (the `use ironrdp_pdu` imports) at about
`:1745-1749`. The R3 row, rewritten as seven `connect.rs` line numbers in #587, is now the test names. Line
numbers cited in the amendments above are left as written, since each records what was true on its date.

**(c) The same classification over the rest of the oracle's differential tests.** Each test in
`justrdp-codecs`' `differential_ironrdp_graphics.rs`, `differential_zgfx.rs`, `differential_rfx.rs` and
`differential_pointer_ironrdp.rs`, in `justrdp`'s `differential_input_ironrdp.rs` and in
`justrdp-security`'s `differential_license_crypto.rs` was read against the definitions, and the table
cites each by name. Six calls are not what the earlier rows implied:
- The pointer tests are **R1**, not R2. The R2 row listed `differential_pointer_ironrdp.rs` for its
  `ironrdp_pdu::pointer` imports, but those are the oracle's argument types holding the test's own bytes;
  nothing of `ironrdp`'s encodes. So the `ironrdp-pdu` comment in `justrdp-codecs/Cargo.toml`, which read
  *"R2 generator only"*, now names R1 for the pointer file and R2 for `build_stream` alone.
- Where `ironrdp` encodes and both decoders then read the stream, the test holds **R1 and R2** and is named
  in both rows: `rdp6_planar_decodes_ironrdp_encoder_output_identically`, the five zgfx tests (the
  oracle's compressor and `wrap_uncompressed` author the streams), and in `differential_rfx.rs` the two
  tests whose coefficients come from the oracle's forward transforms and, for the second, whose container
  comes from `ironrdp-pdu` (`every_inverse_stage_matches_the_oracle_primitive_at_its_boundary`,
  `full_payload_rgba_matches_the_composed_oracle_reference`). The harness's RLGR encoder in that file is ours,
  as the 2026-11-03 amendment says, so only the forward transforms and the container make them R2.
- `oracle_encoder_round_trips_both_modes` is **R4**, as the 2026-11-03 amendment says. The R4 row named
  "the six in (a)", which are gone, so it now names the three left.
- `harness_encoder_is_faithful_by_the_oracles_own_decoder` is filed under **R3**: the oracle's decoder reads
  bytes that the test's own harness encoder wrote. The bytes are the harness's and not the crate's, so R3's
  exit (a real-server capture or a VM run) does not apply to it; it ends with the harness encoder.
- `platform_challenge_response_verifies_under_ironrdp_keys` is **R3**: `ironrdp` verifies a challenge built with our
  RC4 and MAC. `key_derivation_matches_ironrdp` is R1.
- `rsa_premaster_encryption_matches_independent_known_answers` holds **no role**: it compares with answers
  computed in Python and runs no `ironrdp` code, so it is an owned basis in Decision 2's sense. The same holds
  for `differential_x509_chain_ironrdp.rs`, whose expected key is a constant from IronRDP's own test and
  which runs no `ironrdp` code either.

**(d) Which of the five R2 server frames a committed capture holds, measured.** The only committed
connect-leg server bytes are `justrdp-pdu/tests/fixtures/connect/`'s three files; the `session/` fixtures
are session-leg. The R2 row's *"no corpus retires this"* was therefore false for one of the five
`justrdp-pdu` tests and partly false for another, and untested for the rest:
- `ironrdp_font_map_decodes_as_our_session_active_gate`: **held.** Frame 4 of `finalization-replies.bin`
  has the fields the test builds (`pduSource` 1002, `shareId` 0x000103EA, `streamId` 2, no compression, entries
  0/0, `mapFlags` 0x0003, `entrySize` 4; compared in the hex, not by running `ironrdp`'s encoder), and
  `a_real_servers_finalization_replies_decode_in_order` asserts all the test asserts.
- `ironrdp_connect_response_decodes_identically_in_justrdp`: **the frame type, not the values.**
  `connect-response.bin` decodes, but `a_real_servers_connect_response_decodes` asserts acceptance only. It
  matches the test on `result` 0, io channel 1003, channels [1004, 1005] and encryption 0/0, and differs on
  `node_id` (31219, test 1002), early capability flags (0x04, test `SKIP_CHANNELJOIN_SUPPORTED` 0x08) and
  `clientRequestedProtocols` (0x0b, test HYBRID_EX 0x08). This server does not advertise skip-channel-join.
- `ironrdp_attach_user_and_channel_join_confirms_decode_in_justrdp`,
  `ironrdp_valid_client_error_alert_decodes_as_our_short_circuit` and
  `ironrdp_demand_active_decodes_to_the_same_capability_fields`: **not held.** No Attach User Confirm,
  Channel Join Confirm, licensing PDU or Demand Active is in a committed file. `JUSTRDP_CONNECT_CAPTURE_FILE`
  records every connect read, so a VM run could capture them; none was run for this measurement.

So the R2 exit is split by site. The codec tests and the `connect.rs` helpers keep *"we write the encoder"*;
the five `justrdp-pdu` tests exit by a capture of their frame, which only the Font Map one has today. The
maintainer chose this split on 2026-11-18, shown the measurement and the option of leaving the text as it was.
That the Font Map test adds no assertion the capture test lacks is recorded here and not acted on; deleting
a test is outside this change.
