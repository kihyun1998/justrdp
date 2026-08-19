# Lessons — justrdp (war-story index)

What gives each `theflow` rule its teeth in this repo. Indexed by step, anchored
to the ADRs and issues. This project is young (0.1.0, plan-driven), so most
entries are **decision anchors** — the concrete reason a rule exists here — rather
than "a step was skipped and it cost us" incidents; add the latter as they occur.

Read this before starting so the bindings do not read as abstractions.

---

## Origin — why justrdp exists (the boundary has teeth)

- **A single hidden flag.** `ironrdp-connector` 0.9.0 omits
  `SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100), so EGFX cannot be enabled — one flag,
  buried, un-overridable. justrdp is the rewrite that lets the **host hold every
  RDP feature flag**. The boundary invariant (core owns all RDP-native layers,
  delegates only security-critical non-RDP crates) exists to keep that control.
  (`CONTEXT.md` §Project intent.)

## Step 1 — spec + real source, derive don't copy

- **Spec ≠ interop.** Code that matches `[MS-*]` can still not be byte-identical
  to a real server; the tolerance a server actually needs (caps it violates) is
  spec-unwritten and lives in FreeRDP/IronRDP source — #101 / ADR-0009 (tolerant
  negotiation posture) is the standing form of this.
- **Derive, don't copy (ADR-0003).** IronRDP code is re-derived from spec, and
  correctness is proven by differential test, not structural similarity — which is
  also what lets the `ironrdp-graphics` dependency be *dropped* once the oracle passes.
- **A dependency's decode path is a surface neither of this repo's rosters can
  name (#189).** zgfx was the *outermost* decoder on the EGFX path — every server byte
  crosses it before `justrdp_pdu::egfx::decode_all` — and it had neither a proptest nor a
  fuzz target, not by oversight but because it was delegated to `ironrdp-graphics`. The two
  derivations the never-panics invariant carries (`ls fuzz/fuzz_targets/` and a walk of
  `crates/*/src`) both enumerate *our* code, so they answered "fully covered" while a live
  decoder sat outside them. Probed rather than reasoned about: **5 of 7** crafted
  `RDP_SEGMENTED_DATA` messages panicked, and the panic surfaced at
  `justrdp::egfx::GraphicsProcessor::process` — the core. The generalisation is small and
  worth keeping: **a completeness claim inherits the scope of the list it was derived from**,
  so the question to ask a green roster is what it enumerates, not how long it is.
- **CVE knowledge is a reference, not a memory** — rle/planar/clearcodec/nsc OOB
  points (memory `rdp_decoder_robustness_refs`); read them at FreeRDP source.

## Step 2 — sans-IO core vs adapter (ADR-0001/0002)

- **The core never sees a `TSRequest`.** `sspi` (CredSSP/SPNEGO/NTLM/Kerberos) and
  `rustls` are security-critical, non-RDP leaf deps, so they live in the adapter
  (`justrdp-tokio`), not the core — the core stays socket-free, runtime-free, and
  policy-agnostic, which is exactly what makes it deterministically testable.
- **`ring` over `aws-lc-rs`** — the rustls provider is chosen to avoid the NASM
  build requirement on Windows; `rustls-platform-verifier` supplies the OS trust
  store (#36).

## Step 3 — the test-trust gate

- **A mutation harness can report a false green, and the tell is not in its output
  (#189).** Nine mutations were run in batches: write the mutation, `cargo test`, parse the
  FAILED lines, revert. One of them — a single wrong literal in the zgfx token table —
  came back **"no test went red"**, which reads as a coverage hole in the differential and
  would have been written up as one. Re-run alone it turns **two** tests red. The cause is
  mtime granularity: the previous mutation's revert and this one's write landed in the same
  filesystem timestamp tick, so cargo skipped the rebuild and the batch tested *unmutated*
  code. The harness never checked `returncode`, so "no failures parsed" and "nothing ran"
  were indistinguishable in its output.
  Two things this pins. **The instrument that proves a test can fail must itself be provably
  running** — the gate turned on itself, and the cheapest guard is asserting the process
  actually failed (`returncode != 0`) rather than trusting a parse of its stdout. And **a
  false green here is worse than a false red**: a false red gets investigated, while a false
  green is *evidence of a hole that does not exist*, which sends the next hour into writing
  a test for a case already covered.

## Step 4 — real round-trip, not a fake (ADR-0003/0007)

- **Codec proof is byte-identical, or it is not proof.** The same bitstream through
  our decoder and `ironrdp-graphics` must produce an identical `Vec<u8>`; 100% pass
  is the gate to drop the oracle dependency. connect/session proof is a real VM
  round-trip (`192.168.136.136`, memory `test_environment`) — a demo is not proof.

- **A measurement that can misread itself, built and thrown away (#172).** The
  bindings name that trap; this is what it looked like. Wiring the self-owned
  Progressive decoder into `justrdp::egfx` seemed to admit a decisive check: assemble
  the *same* real-VM payloads twice — once through the core (`Surface::blit`, the
  dirty list, the surface→framebuffer blit) and once directly onto a canvas — and
  since the decoder is shared, any disagreement localises in the new wiring. It
  measured **17–19% agreement**, which reads as a serious defect and is not one. The
  replay canvas is a WireToSurface2-only *accumulation* that never forgets — it still
  held the wallpaper, a Start menu closed thirty seconds earlier, and a boot-time
  overlay — while the live `Surface` receives ClearCodec and WireToSurface1 blits into
  the same buffer and holds the session's true final screen. The number was **the
  fraction of pixels where Progressive happened to be the last writer**: a property of
  the server's codec scheduling, not of this client.

  Two things it pins. **The artifacts have to be produced before the assertion, or a
  70-second run costs 70 seconds and leaves nothing to look at** — the first two runs
  panicked before the PPM dumps and the number was unreadable; moving the dumps ahead
  of the check settled it in one glance. And **a plausible number is the dangerous
  outcome**, not an implausible one: 0% would have been read as "the comparison is
  broken" immediately, where 18% invites tuning the threshold until it passes. The
  comparison was removed rather than tuned, with what would make it well-posed
  recorded where it stood (drive the replay through a `GraphicsProcessor` so both
  sides see every codec in arrival order — which needs a core-side replay seam that
  does not exist).

- **The VM proves what the VM sends, and the only way to know that is to count it
  (#189).** The zgfx swap's round-trip was the existing EGFX acceptance test, and it passed —
  198 frames, a correct Server 2022 desktop, dumped and looked at. What the pass does *not*
  say is which of the decoder's paths carried it, so a throwaway probe counted: **25 messages,
  every one `ZGFX_SEGMENTED_SINGLE` and every one `PACKET_COMPRESSED`** — 18 488 literals,
  19 024 matches, 7 unencoded runs, longest match 5 062 bytes, **longest distance 133 937**.
  Two opposite conclusions came out of the same five minutes, and neither was guessable. The
  token decoder is *heavily* exercised, and the 133 937 is direct evidence of the history
  window spanning messages on a real wire — stronger than the hand-built test that asserts the
  same thing. And the **multipart descriptor never appeared at all**, so `0xE1`'s framing is
  proved by the spec vector and the oracle differential and by nothing a server has done.
  Recorded in the territory's `## Known holes`, because "the VM renders the desktop" would
  otherwise have been written as if it covered the whole module.

## Step 5 — adversarial completeness is automated (ADR-0008)

- **proptest no-panic (#98) + cargo-fuzz (#99)** make the completeness axis
  *continuous* for untrusted parsing — the decoder enumeration you cannot trust
  yourself to have finished. (They are two automations of **one** property, not two
  lenses; the pass itself is one lens briefed on both corpora — see the bindings.)
- **Its surface is half-covered, and the map says so by derivation rather than by a
  list** — every fuzz target is codec/capability/license, while the
  connect-sequence parsers have none. (This bullet read "ten fuzz targets exist"
  until #200 — a sentence praising derivation while hand-copying the number in its
  own second half, and wrong from the day `progressive` landed.) —
  [`docs/map/invariant/untrusted-decode-never-panics.md`](../map/invariant/untrusted-decode-never-panics.md).

- **The pass found a panic in the code written to remove panics (#189).** The whole
  point of self-owning zgfx was that the delegated decompressor panicked on untrusted input;
  the replacement shipped with three no-panic proptests, two of them *directed* (prefixed with
  a valid wrapper, because a descriptor byte and a compression-type nibble gate the token
  decoder behind 1-in-2048 of random prefixes). All green at 2048 cases each. The adversarial
  pass then walked the bit cursor's invariants by hand and found that the byte-alignment step
  before an unencoded run could push the position **past** the segment's budget, after which
  `remaining()`'s subtraction underflows. Reproduced in one hand-built message, confirmed as a
  real panic, fixed by making the alignment refusable.
  Why the property could not find it: the input needs a specific first body byte, a specific
  trailing unused-bit count *and* a specific length to coincide — the same three-way
  coincidence #219 records, and the same conclusion. It also sharpens what "directed" buys: the
  prefix got the generator past the wrapper, which is necessary and nowhere near sufficient,
  because the depth that matters is *inside* the bitstream's own arithmetic.
- **The lane's first crash, and it is the sequel to the entry below (#219).** The
  #168 bullet *"`checked_shl` checks the shift amount, never the value"* records why
  `rfx::srl::accumulate` grew a round-trip guard. On 2026-08-19 the nightly fuzz lane
  panicked in that same function — `attempt to add with overflow` — because the
  round-trip has a blind spot exactly one value wide: an arithmetic right shift of
  `i64::MIN` by 63 is `-1`, so `-1 << 63` round-trips **perfectly having wrapped all
  the way**, and the widening to `i64` that the addition leaned on is one value short.
  A family, not a point: any `input == -(1 << j)` at `shift == 63 - j`.

  Four things this pins that #168's entry could only assert.

  - **Two automations of one property is not redundancy, and now there is a
    measurement.** `fuzz.yml`'s header argued the lane exists because coverage
    guidance reaches depth random sampling does not. The sibling proptest generates
    **every value involved** and has since #168 — full-`u8` quant nibbles, `i16::ANY`
    seeds. What it cannot do is make *three* of them coincide. Recorded in the
    invariant's discovery history rather than left in a PR body.
  - **A test can cover the line and miss the sign.**
    `a_shift_that_discards_the_whole_refinement_is_an_error_not_a_no_op` **already
    drove `shift == 63`** — with `sign = 1`, so it landed on the positive branch where
    `2 << 63 == 0` and the guard fires correctly. Line coverage would have called this
    surface done.
  - **The defect was in a written argument, not in a line.** The doc comment directly
    above the panicking `+` named two guards and rested the third on the accumulator's
    width. Which is the shape Step 1's *"external facts and secondhand statements are
    verification targets too"* warns about, turned inward: a rationale committed to
    the repo gets believed, including by its own author one slice later.
  - **"Unreachable through the parser" is not a severity argument on this surface.**
    The parser masks quant fields to nibbles, `quant_add` saturates at 30 and
    `upgrade_shift` subtracts one, so the live path tops out at `shift == 29`. What
    broke was `upgrade_component`'s *declared* contract — total for any `u8` — which
    the module chose deliberately because `ProgressiveQuant`'s fields are plain
    `pub u8` and the bound lives in arithmetic elsewhere. #211 is the same family at
    `rfx/quant.rs` and its evidence table cited this site as already settled.

- **The first incident, and it is about the pass declaring victory (#168).** A solo
  completeness pass on the Progressive SRL decoder found two panics, fixed them, and
  recorded convergence. A second pass — **two subagent lenses split by stance**, one
  hunting gaps and one briefed to *refute* the first's claims, both reading both
  corpora — refuted that convergence and found more than the first round had:
  - **A wrong premise, not a wrong line.** The first round asserted `num_bits` and
    `shift` were 4-bit nibbles bounded by 15 and sized two guards on it. A bit
    position is `quant + prog_quant`, the *sum* of two nibbles, so the real range is
    `0..=30`. One guard then truncated the SRL magnitude loop above 15, leaving the
    shared bit cursor short — **plausible wrong coefficients with `Ok(())`**, which
    the invariant ranks worse than a panic.
  - **`checked_shl` checks the shift amount, never the value.** `2i64 << 63` is
    `Some(0)`, so a real refinement was accepted as a no-op and the pass reported
    success having applied nothing.
  - **A mutant that passed the entire suite.** Resetting `kp`/`nz`/`mode` at every
    band boundary while leaving both bit readers threaded changed 15,786 of 19,500
    real corpus decodes and went green everywhere — because all nine value vectors
    drove a single band, and the one multi-band test set every sign non-zero so the
    SRL path was never entered. The property it broke was one the module names as
    load-bearing.
  - **Two generators built inside the guarantee they existed to test.** The first
    round caught this shape in its proptest ("seeded, not zeroed") and reproduced it
    in the very fuzz target and corpus gate it added in the same commit — both
    zeroed the coefficient and sign arrays, which made two of three routing arms
    unreachable and the divergence's own reachability claim unfalsifiable.

  Three things this pins that the rules only asserted. **The second, refuting lens
  earns its cost on an unconditional trigger** — the bindings say so and this is the
  evidence. **Splitting by stance rather than by corpus is what made the findings
  arrive adjudicated**: both lenses had read FreeRDP *and* the map, so each could say
  which way a divergence went instead of handing it back cold. And **a lens report is
  a candidate, not a finding** — reproducing each one locally is what narrowed the
  reported "family" of four shift sites to exactly one (`planar` is bounded by its
  mask, `nscodec` by parse-time validation), which is a different and more useful
  issue than the one that would have been filed on the report alone (#211).

  The refuting lens also **weakened a claim in the fix itself**: the docs had said the
  owned basis inherited the *oracle's* initial `kp`, when FreeRDP's own
  `WINPR_C_ARRAY_INIT` declaration predicts the same mistake and nothing separates the
  two hypotheses. Restated as the weaker claim that survives. A pass that only ever
  confirms the author is not adversarial.

- **#169 (Progressive slice 3) — the pass found three defects the author's own tests
  were structurally unable to see, and broke six claims the change made about itself.**
  Same two-lens stance split as #168, same unconditional trigger, and worth recording
  separately because *what* it caught was a different class.

  The three defects shared one root: **a tile's store has a history, and the history
  was not modelled.** The layout guard read the current region's extrapolate flag
  rather than the layout the store was written at — and region flags are
  per-`WBT_REGION`, so a first pass in one region followed by an upgrade in another
  slipped through exactly the silent mismatch the guard existed to refuse. A first
  pass that failed at its second component left one component from this pass and two
  from the last, which a later upgrade then refined and returned `Ok(())`. And nothing
  anywhere asserted that an upgrade pass *changes* a coefficient: deleting the
  refinement entirely left the whole corpus gate green.

  The refuting lens then broke the claim that had **justified a decision**. The store's
  key had been argued as a resource question — both keys decode the corpus, so the
  difference was said to be memory. The evidence offered was a count of "non-black"
  tiles, which cannot see a pixel change at all, because the colour step writes
  `alpha = 255` unconditionally. Hashing the tiles showed the two keyings *paint
  differently*, and the mechanism was measurable in the corpus: 1405 of 2943 first
  passes carry `RFX_TILE_DIFFERENCE`, which adds to whatever store is held for that
  grid position. It was a correctness question, and the test had asserted the opposite.

  Two rules earned here. **A test's discriminating power has to be asserted in the same
  run as the thing it asserts** — three of this slice's tests passed against wrong
  implementations because a later stage (a clamp, a constant alpha, a private helper
  standing in for its caller) destroyed the difference before the assertion saw it.
  Promoted to [`a later stage can hide an earlier
  defect`](../map/invariant/a-later-stage-can-hide-an-earlier-defect.md). And **check
  that a mutation landed before believing it survived**: a "surviving" mutant in the
  first sweep turned out to be a `replace(…, 1)` that hit a doc comment rather than the
  code, and a timed-out sweep left a live mutation in the tree that the next sweep then
  took as its baseline. A mutation harness needs the same trust gate as a test.

  Also: **twelve FreeRDP line citations were off by 1–15 lines.** #168's whole lesson
  was that a cited range can hold the algorithm and not its initial state; this slice
  re-learned the cheaper half, that a range can simply be wrong. Grepping each cited
  symbol for its line number cost minutes and is now the only way these are written.

## Step 6/7 — surfaces & gates

- **The `fuzz` crate is the `--workspace` blind spot** — out of the workspace by
  design (its own `[workspace]`), so `cargo test --workspace` does not build it. A
  public-API change needs a separate `cargo check --manifest-path fuzz/Cargo.toml`.
- **A gate that keeps its own copy of a list is a gate that will one day run on the
  wrong list — the war story for *derive, don't copy*, applied to CI (#200).**
  `fuzz.yml`'s matrix transcribed `ls fuzz/fuzz_targets/` by hand and drifted **twice
  without a signal**: `nscodec` (#143) and `progressive` (#192) each landed a
  compiling fuzz target that CI never once executed, `nscodec` for months. Nothing
  was violated — both PRs satisfied the recurrence test in
  [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md)
  exactly as it was written, because it named the artifact and not the thing that
  consumes it. Three lessons, and the second is the one that shaped the fix:
  **a rule is only as strong as its most literal reading**; **the roster had five
  copies, not two** — the directory, `fuzz/Cargo.toml`'s `[[bin]]` entries, the
  matrix, and a *count* in prose in two more places, both of which had also gone
  stale at #192, so a hand-kept number is a hand-kept list with one entry; and
  **derive from the copy whose failure is loud** — the matrix now reads the directory
  and asserts the manifest agrees, because a `.rs` with no `[[bin]]` is compiled by
  nothing, not even `cargo check --manifest-path fuzz/Cargo.toml`, and so reads as
  covered while being dead text.
- **"Temporary and tracked" decayed into "still here and untracked" — the war story
  for *external facts are verification targets too*.** The `[patch.crates-io]` bridge
  to `kihyun1998/sspi-rs` waited on Devolutions/sspi-rs#689, which **merged 2026-06-17
  and shipped in `sspi` 0.21.1 on 2026-06-26** — and it was still in the tree six weeks
  later. #61, named as the removal tracker by `Cargo.toml`, `.github/dependabot.yml`
  *and* ADR-0004, was **closed** against its own comment saying it must not be; the
  Dependabot "tripwire" could not fire because its condition was already met; and
  ADR-0004's own amendment asserted the bridge *did not exist*, so nothing greppable
  contradicted any of it. **Removed 2026-08-10** (`sspi = "=0.21.3"`, exact pin per the
  ADR), with the loopback full-CredSSP test green on the published crate — the real-VM
  gate deferred because the VM's credentials fail, which an A/B run proved is not a
  client regression. Two lessons: *"remove when X ships"* is a **status** claim that
  rots the moment it comes true, and a record asserting the **absence** of something is
  the hardest drift to notice (ADR-0004 Amendment 2026-08-10; memory
  `sspi_rs_contribution_setup`).
- **Supply-chain is a gate** — `just-shield` scans for SHA-pinned actions (ADR-0006,
  `supply-chain.yml`; memory `justrdp_ci_policy`).
- **No `Co-Authored-By` / AI-attribution** in commits (memory
  `feedback_no_ai_attribution_external`); label every new issue triage + type on
  creation (memory `feedback_label_issues_on_creation`).
