# Untrusted decode never panics

## The fact

Every byte this library parses came from a server it does not control, so **no
decode path may panic, over-read, or loop unboundedly on arbitrary input** — it must
return a typed error. "Arbitrary" is stronger than "malformed": truncated,
self-contradictory, and hostile-but-well-formed inputs are all in scope, including
lengths that claim more than the buffer holds and counts that multiply into
unreachable sizes.

A decoder is therefore judged by two separate properties: it produces the right
pixels for good input (the oracle's job), and it produces an *error* for everything
else (this invariant's job). Passing the first says nothing about the second.

## Why it is cross-cutting

The sites share an input, not a call graph. Framing, the connect-sequence parsers,
the channel layer and the codecs are separate stacks reached at different phases —
but every one of them takes its length and count fields from the wire. A guard added
in one is invisible from the others, and the fix has no natural home: it is a
property of the whole untrusted surface.

## Territories it holds in

- [Wire framing primitives](../territory/wire-framing.md) — the widest surface:
  `frame_len` / `is_fastpath` / `ReadCursor` see every byte in the process.
- [Bitmap codecs](../territory/bitmap-codecs.md) — the deepest arithmetic.
- [EGFX graphics pipeline](../territory/egfx-graphics-pipeline.md) — surface and
  cache commands.
- [Virtual channels](../territory/virtual-channels.md) — chunk reassembly lengths.
- [Session loop & PDU dispatch](../territory/session-loop-dispatch.md) — the
  dispatcher that hands bytes to all of the above.
- [Pointer & cursor](../territory/pointer-cursor.md) — mask/stride arithmetic.
- [Licensing](../territory/licensing.md) — five server parses off one cursor, every length
  server-supplied. Added by #230, which is also when four of the five acquired their first
  artifact.
- [Capability exchange & activation](../territory/capability-exchange-activation.md) — the
  Demand Active walk, the Share headers, and the three finalization replies. Added by #237,
  which is also when `finalization` acquired its first artifact; the missing edge is why it
  had none.
- [MCS / GCC channel setup](../territory/mcs-gcc-channel-setup.md) — the BER and PER length
  determinants. Edge added by #237; the code has carried both artifacts since #203.
- [X.224 negotiation](../territory/x224-negotiation.md) — the connect-sequence entry point.
  Edge added by #237; the code has carried both artifacts since #200.
- [Verification harness](../territory/verification-harness.md) — the only territory
  that *enforces* rather than obeys it: proptest in the PR gate, cargo-fuzz nightly.

## What a violation looks like

A panic is the *visible* form: the host's task dies mid-session, which reads as a
crash bug rather than a protocol bug. The invisible form is worse and more common —
a length that passes a bounds check but selects the wrong region, so decode
succeeds and returns **plausible wrong pixels**. Nothing errors, nothing crashes,
and the only signal is a picture that is subtly wrong on one server.

Rust makes the memory-safety half a panic rather than a corruption, which is why
this invariant is stated as *availability* (a denial of service against a client
that trusts its server too much) rather than as memory safety.

## Discovery history

- **#97 → ADR-0008** — the decision that hand-written vectors cannot cover this
  input space, and that the property belongs in the gate.
- **#98** — proptest "decode never panics on arbitrary bytes" + round-trip
  properties, implemented first for the RLE decoder, running on stable in the PR
  gate.
- **#99** — coverage-guided `cargo-fuzz` on a nightly CI lane, because proptest's
  random sampling does not reach depth. Two automations for one property: that
  duplication *is* the discovery history.
- **#219** — the lane's **first crash**, which turned the line above from an argument
  into a measurement. `progressive_srl` panicked in `rfx::srl::accumulate` on a
  refinement that lands on exactly `i64::MIN`, where the round-trip guard is blind
  (`i64::MIN >> 63` is `-1`, so `-1 << 63` round-trips having wrapped). The sibling
  proptest generates every one of the three values involved — it needed them to
  *coincide*, which is the depth coverage guidance buys and random sampling does not.
- **#189** — the gap the two automations above **cannot** see. zgfx was the outermost
  decoder on the EGFX path (every server byte crosses it before the PDU parser) and had
  neither a proptest nor a fuzz target, because it was *delegated*: the fuzz roster derives
  from `ls fuzz/fuzz_targets/` and the properties live in this repo's modules, so a
  dependency's decode path is outside both **by construction**. Probed directly, five of
  seven crafted `RDP_SEGMENTED_DATA` messages panicked inside `ironrdp_graphics::zgfx` and
  the panic reached `justrdp::egfx::GraphicsProcessor::process`. Self-owning it closed the
  hole; the general rule is below.
- **#189, second finding: a 2048-case property missed a panic in the replacement.** The
  self-owned decoder's own byte-alignment step could push the bit cursor past its budget,
  underflowing `remaining()`. Three no-panic proptests — one undirected, two prefixed with a
  valid wrapper — ran green over it, because the input needs a specific first byte, a
  specific trailing unused-bit count *and* a specific length to coincide. Found by the
  adversarial pass instead. Same shape as #219: random sampling generates every value and
  cannot make three of them coincide.
- **#203** — `gcc` and `mcs`, the two #200 could not add mechanically. Its "nine `gcc` entry
  points" are two trees with one root each and only one reachable from the wire, so the shape
  question was never 14 targets versus one selector.
- **#203, and the correction that matters more than the issue: undirected reach does not predict
  coverage-guided reach.** #203 was filed with `gcc` unmeasured; measuring it gave **11.98% of
  regions, 4 of 32 functions, every per-block decoder dark** against 200k random inputs, which
  read as `rfx::progressive`'s wall (8.9%) and was taken as proof that a seed corpus was
  mandatory. **The lane disagreed.** Same target, same 300s, seeded against empty:

  | | cov | ft | corp | exec/s |
  |---|---|---|---|---|
  | empty | 515 | 1207 | 255 / 21Kb | 178 573 |
  | seeded | 699 | 1987 | 391 / 94Kb | 46 166 |

  Not progressive's 62-versus-425 collapse: guidance climbs the ~12-byte magic prefix unaided.
  The mechanism is that a comparison against a byte string feeds libFuzzer's auto-dictionary
  (`__sanitizer_cov_trace_cmp`), which random sampling has no equivalent of. So the two walls are
  different in kind — **magic constants are climbable, self-consistent nested lengths are not** —
  and `progressive` needed its seed for the second reason, not the first.

  What the undirected figure *does* govern is the **proptest** half, which samples the same way:
  11.98% is why `gcc` carries nine per-entry-point properties instead of one on the root. The two
  automations ADR-0008 pairs are not interchangeable, and this is the first measurement of how
  they differ rather than an argument that they do.
- **#268 — a totality claim scoped to one step, written as a claim about the function, and the
  gap between the two scopes held a live panic.** `justrdp::egfx`'s `Surface::extract` carried a
  by-construction totality comment that said the reserve is bounded by a buffer that already
  exists, because the first two statements clip `w`/`h` before any multiply. Every word of that
  was true, and it is a claim about **the multiply**. The function does more: clipping `w` does
  not clip `x`, so at `x > self.width` the extent goes to zero, the row loop still runs, and
  `&self.rgba[off..off]` panics on a slice whose *start* is past the end — a zero-length read at
  an out-of-range offset, `left == 1920` legal and `left == 1921` fatal on a 1920x1080 surface,
  reached from the wire by `SURFACE_TO_SURFACE` and `SURFACE_TO_CACHE`. Three separate artifacts
  had already looked at this function and each cleared the step it was asking about: the comment
  (the multiply), derivation ④'s adjudication below (the *trip count* — `usize::from(<u16>)`, so
  bounded), and the EGFX territory's clipping tolerance (checked at `Surface::blit`). **None of
  the three was wrong and the union of them still did not cover the function**, which is the
  thing this entry adds: a scoped claim does not fail loudly when it is read wider than it was
  written, because there is nothing about it that is false. The narrower the step a totality
  argument is exact about, the more of the function it leaves unspoken for.

- **#203, third: a round-trip cannot reach a decoder whose encoder does not exist.** Every encoder
  in `justrdp-pdu` writes client-to-server, because justrdp is a client — so no server PDU can be
  synthesised here, and the seed had to be a real capture. That asymmetry is why this invariant
  carries the receive path alone, and why #98 could give `decode_connect_response` a no-panic
  property but no round-trip.
- **#211/#233 → [ADR-0012](../../adr/0012-consumption-site-totality.md) — the derivation
  below exempts a whole class, and the class panics.** Both commands are *byte*-scoped:
  one lists fuzz targets, the other lists what parses untrusted bytes. `rfx::quant::dequantize`
  and `nscodec::reconstruct` parse nothing — they take an *already-parsed* struct field and an
  already-validated `u8` parameter and shift by them, across a crate boundary that carries
  neither constraint. Both are `pub`, and both panicked at a shift of 16 or wider (reproduced;
  in release the shift wraps modulo the type width instead, so the same input yields silently
  wrong coefficients). The general rule is ADR-0012's, and the half that belongs here is the
  recurrence clause below.
- **#211, second: a property can be green over a live panic when its generator is bounded to
  the parser's range.** `nscodec`'s no-panic property documented itself as covering *"any
  colour-loss level"* and generated `1u8..=7` — exactly the range `parse_header` already
  enforces. Measured by mutation: with the guard removed and that generator restored, the
  property **passes** while the unit test beside it fails. A generator bounded to what the
  parser emits asserts the parser, not the function under test — which is the same
  artifact-versus-consumer gap as #143/#192 and #203, one layer out into the harness. Where a
  bound is genuinely threat-model-faithful (ADR-0008's strategy design rule — a `u16` wire
  field stays a `u16`), the test is *whether the function's own signature admits more*: a bare
  `pub fn` parameter always does.
- **#230 — the stated blocker did not exist, which is worth more than the fix.** #203 and #230
  both recorded that `&mut ReadCursor<'_>` entry points *"have no signature to point
  `fuzz_target!` at directly"*, and #230 named that as the reason these three were not
  mechanical for #200. It is false in both directions: `cursor` is a `pub mod`, and
  `fuzz_targets/license.rs` has constructed a cursor inside the target since #99. What actually
  blocked #200 was that `gcc` and `mcs` have no single top-level `decode` — a different problem
  that happened to travel with the same modules. A rationale nobody re-reads gets inherited by
  the next issue, and this one was inherited twice.
- **#230, second: an undirected no-panic property can be structurally unable to reach the
  arithmetic it is named after.** The first version of `pointer`'s properties generated
  `vec(any::<u8>(), 0..=512)` and passed over an out-of-bounds read injected into the mask
  `read_slice` — while `malformed_pointers_are_typed_errors`, the hand-written test beside it,
  went red on the same mutation. Random bytes must land `messageType` on one of two values
  (2/65536) **and** both dimensions inside the 96-pixel cap ((97/65536)²) to reach either mask
  read: about 6.7e-11 per case, against 2048 cases.

  This is the mirror image of #211's `nscodec` finding rather than a new shape. There a
  generator **bounded** to the parser's range asserted the parser instead of the function; here
  a generator too **wide** to satisfy the parser asserted the dispatch instead of the function.
  Both produce a green that means nothing, and only mutation tells them apart from a green that
  does. The fix is to **weight** the header fields into the admitted range while keeping an
  `any::<...>()` arm on every one of them, so the reject arms stay driven — which is what
  `justrdp-codecs`'s own `decode_pointer` property already did for `xor_bpp` and did not do for
  `width`/`height`.
- **#230, third: the first length field masks the second.** With both mask lengths generated as
  arbitrary `u16` (mean 32768) against a tail of at most 512 bytes, `read_slice(lengthXorMask)`
  errors before the AND read in nearly every case, so an out-of-bounds read injected into the
  **AND** mask is caught by `decode_fastpath` in **1 of 3** runs against **3 of 3** once the
  length strategy also produces satisfiable values. Two sequential reads from one hostile-length
  family need both kinds of length, or the second one is only reached by accident.
- **#230, fourth, and the one that cost the most: the mutation harness reported false greens, in
  the repo that already had a note about it.** Three separate numbers above were measured wrong
  the first time — the AND-mask row read "green" instead of "1 of 3", a `pointer` run read 0 red
  where the truth is 3, and an entire finding about `license`'s `MACData` bound (5 of 10
  property-runs red, "a coin flip") **did not survive re-measurement at all**: the unweighted
  generator catches that mutation 2 of 2, every run. The cause is #189's exactly: a harness that
  writes a mutation, tests, reverts, and immediately writes the next one lands two writes in the
  same filesystem timestamp tick, cargo skips the rebuild, and the run tests *unmutated* code.
  Knowing the note existed did not help; running the guard did.

  **A mutation harness must prove the mutated code was compiled** — assert `Compiling <crate>` in
  the output, or make each write's content unique so no fingerprint can match. The reason this
  belongs in an invariant about decoders rather than only in the lessons file: every claim this
  note makes about what a property covers is a mutation measurement, so a harness that can report
  a false green is the instrument all of them are made with. A false green here does not just
  waste an hour — it **manufactures a coverage hole that does not exist**, and the work that
  follows is machinery built to guard an unobserved case.

  A second-order consequence, and the reason this change commits **no** `proptest-regressions`
  file: a committed seed can make a mutation deterministically red whatever the strategy does, so
  the next person's discriminating-power measurement is answered by the seed rather than by the
  generator. Seeds harvested from deliberately-broken builds are worth less than the measurement
  they distort. (`gcc.txt` / `mcs.txt` / `tpkt.txt` predate this and are left alone.)
- **#230, fifth: an undirected no-panic property is the exception, not the default, and three
  more instances landed in one change.** After `pointer`, the same measurement was run on every
  entry point this issue added, and **`tpkt::frame_len` (0 of 3 runs red), `fastpath::frame_len`
  (1 of 3) and `license::RsaPublicKey::from_pkcs1_der` (0 of 3)** each shipped green over an
  injected out-of-bounds read before their generators were structured. Weighted, all four are 5
  of 5.

  Four instances make it a rule rather than a story: **if a parser has any exact-match gate in
  front of its arithmetic — a version byte, a flags mask, an ASN.1 tag, a dispatch code, a
  dimension cap — `vec(any::<u8>(), 0..=N)` does not reach past it**, and the property is
  asserting the gate. Generate the shape, keep an `any::<...>()` arm on every gate so its reject
  branch stays driven, leave the *lengths* hostile, and add a truncation arm so the shallow reads
  behind the shape stay reachable. The corollary is the cheap one: **a new no-panic property is
  not done when it passes — it is done when a mutation of the read it names has been seen to turn
  it red**, and #203's `gcc` measurement (11.98% of regions from 200k undirected inputs) was this
  same fact stated as a coverage number a year of properties earlier.
- **#237 — this note has a *third* enumeration, and it is the one that had the hole.** The two
  commands below are the derivation; the **Territories it holds in** list above is the
  human-readable index, and it is what a reader following the map actually lands on. It was
  missing three territories: **capability exchange & activation**, **MCS / GCC channel setup**
  and **X.224 negotiation**, each of which parses server bytes on the connect path. Two of the
  three were fully covered anyway (#200, #203) — the edge was simply never drawn. The third is
  where `finalization`'s parsers lived, and it is why they were invisible in a way #230's family
  was not: `pointer` and `license` were names that *lied*, while `finalization` appeared in no
  list at all.

  **The reciprocity gate cannot see this class**, which is the part worth keeping.
  `check_map.py` verifies that an edge which exists runs both ways; a territory that claims no
  invariant and an invariant that claims no territory are consistent with each other and with
  the gate. The check that does find it is one line and belongs in a completeness pass, not in
  CI: list every territory whose `## Code` names a parser module, and ask which of them do
  **not** claim this invariant.
- **#262 — the census listed the member, the pass gave it an artifact, and the artifact could
  not observe the defect.** `color::to_rgba` is derivation ③'s named member (#238); #241/#238
  worked it and shipped a no-panic property. What that property could not see is the half of
  this note's own **fact** that is not a panic: *loop unboundedly*. At `width == 0` every guard
  in `to_rgba` **passes** rather than refusing — `0 * bpp` is 0, `0 * height` is 0, and
  `src.len() < 0` is false, so the source-length check *succeeds* — and `for out_row in
  0..height` then walks a bare `usize`. The property's own generator has a `1 => any::<usize>()`
  arm, so it hung on ~43% of seeds.

  **A hang is not a red, and that is what makes this class expensive.** The property does not
  fail; it *runs*. Nothing shrinks, so nothing lands in `proptest-regressions/` — the backstop
  every other finding in this note relies on is structurally unavailable here. The mutation
  methodology this note made a rule (*"done when a mutation of the read it names has been seen
  to turn it red"*) cannot see it either: it asks whether removing a guard turns the property
  red, and the guard that was missing turns it *silent*. Measured cost before anyone read a
  cancelled log: **10 cancelled jobs, ~56.4 runner-hours** in one day — `test` 6 jobs
  (140/360/360/360/360/361 min) and `coverage` 4 jobs at the 360-minute default each, because
  `coverage.yml` runs `cargo llvm-cov --workspace --exclude justrdp-tokio`, i.e. the same
  property, on a post-merge lane nobody watches a PR check for.

  Three consequences, each of which is a different artifact:
  - **The defect fix is a guard on the loop**, `Ok(Vec::new())` at a zero extent, and it is a
    deliberate divergence from FreeRDP rather than agreement with it — the reference splits on
    *who owns the destination*, so `freerdp_glyph_convert_ex` (`color.c:265-267`), which
    allocates and returns exactly as `to_rgba` does, refuses. Argued at the site on what the one
    reachable consumer does with the error.
  - **The class fix is a job timeout**, because a guard fixes one defect and a bound fixes the
    class. Every job in all five workflows now carries `timeout-minutes`; none did before.
  - **The recurrence test is derivation ④ below**, because ①–③ are all blind to this by
    construction and so is
    [decoder dimension overflow on 32-bit](decoder-dimension-overflow-32bit.md), whose *Where it
    will recur* scopes itself to **allocation sizing** (`rg 'usize::from|as usize' … | rg '\*'`).
    A loop bound is not an allocation size, and this defect allocates nothing.
- **#263 — the census subtracted a member as covered, and the covering property could not
  reach the arm.** `justrdp_codecs::rfx::RemoteFx::decode_to_rgba` is a derivation ③ member
  (`pub fn`, `width: u16`, `height: u16`) and the subtract command
  (`rg -n 'fn [a-z_0-9]+_never_panics'`) returns
  `decode_to_rgba_never_panics_on_arbitrary_input` beside it, so the census reads it as
  **done**. It was green over a `w * h * 4` that panicked on `i686` at a maximal
  destination rectangle, because its dimension arms generated `0u16..=128`. So the
  subtract half of ③ has the same defect as the two lists further down: it answers *"is
  there a property named after this function"*, and the question is *"can that property's
  generators reach the arithmetic"*. **A covered member is a stronger hiding place than an
  uncovered one**, because the census reports it as work already done.

  Three things about it, each measured:
  - **The generator's stated rationale was false about the wire, which is a third variant
    of the #211/#230 pair rather than a repeat of either.** It read *"width/height are
    bounded because they arrive from fixed u16 destination-rect fields, never the
    stream"*. A `RDPGFX_RECT16` **is** a stream field — `[MS-RDPEGFX]` 2.2.1.2 bounds it at
    `u16` and states no maximum — so being a `u16` bounds it at 65535 and nothing bounds it
    at 128. #211's generator was narrowed to a range the parser **did** enforce; this one
    was narrowed to a range **nothing** enforces, on a sentence nobody re-read. The reject
    arm it now has to drive needs roughly 32768.
  - **Widening the generator earned nothing until the guard moved, and that is #230's
    exact-match-gate rule reaching its fifth instance.** With the guard removed: widened
    generator behind `rfx::decode_all` → **green**; the same generator with the guard
    ahead of the parse → **RED**; old `0..=128` generator, guard ahead of the parse →
    **green**. Random bytes never form a TS_RFX TILESET, so the block magic is the
    exact-match gate and the arithmetic sat behind it. The resolution here is the one
    #230 did not use — instead of generating the shape, **put the dimension refusal in
    front of the gate**, which is where it belongs anyway (a rectangle whose pixels cannot
    be addressed is not decodable at all, so there is nothing to parse first).
  - **On 64-bit the widened arms refuse nothing**, because 65535 x 65535 x 4 fits. The
    fuzz lane is x86-64, so the reject arm cannot fire there either; that half is proved
    by a target-gated unit test on `i686-pc-windows-msvc` and bounded a layer out in
    `justrdp::egfx`.

  **Deliberately not recorded here:** the arithmetic rule this issue also corrected — that
  a `checked_mul` against `usize::MAX` is not a bound, because `Vec` refuses at
  `isize::MAX` — and the widening of the *allocation-sizing* derivation that could not see
  the site. Both belong to
  [decoder dimension overflow on 32-bit](decoder-dimension-overflow-32bit.md), and this
  note records only the half about what a property can observe. **No row is added to
  derivation ④'s table either**: ④ adjudicates loop trip counts, and this defect allocates
  rather than loops.
- Prior art that made the risk concrete rather than theoretical: FreeRDP's
  rle/planar/clearcodec/nsc OOB CVEs (memory `rdp_decoder_robustness_refs`).

## Where it will recur

**If a function reads a length, count or offset from bytes it did not produce, it is
subject to this** — **and so is a function that takes such a value already parsed and does
arithmetic with it.** The second clause is not a restatement: the sentence as originally
written is byte-scoped, so both derivations below are blind to a consumer one hop past the
parser, and #211 found two such consumers panicking. The test for that class is not "does it
parse" but **"does its signature admit a value the arithmetic has no meaning for"** — which a
plain `pub` field or a bare `u8` parameter always does, whatever the parser guarantees.
[ADR-0012](../../adr/0012-consumption-site-totality.md) owns that class. **It now has an
enumeration — derivation ③ below — and producing it is what #238 turned out to be.** The issue
named one member (`justrdp_codecs::color::to_rgba`) and asked whether the unit of work was that
function or a pass over the class; the enumeration answered it by turning up **eight** uncovered
members, five of which neither #238 nor #241 had named. Four were in `justrdp::framebuffer`,
which this note listed as a *territory* the fact holds in while nobody had ever listed its
functions.

**The membership question has a second half, and it was added after the first half answered
*no* over a live defect (#262).** *"Does the signature admit a value the arithmetic has no
meaning for"* answers **no** for a zero extent — every product is 0, every guard passes, and the
arithmetic is perfectly meaningful — while the function still does not return. So ask both:

> **Does its signature admit a value that passes every arithmetic guard and leaves a loop's
> trip count unbounded?**

A guard chain that validates arithmetic does not bound a loop. The two questions fail on
disjoint inputs — `to_rgba` refuses `usize::MAX` dimensions on the first and hung on the second
— so neither subsumes the other, and derivation ③ cannot find the members of the second half
anyway: it matches on the *signature*, and both halves have the same one. That is what ④ is for.

Working the list found **four defects**, and the split between them is the useful part
(**a fifth arrived on 2026-08-31 in a member of this very table's source list** —
`color::to_rgba`'s unbounded row loop, #262, found by a CI bill rather than by the census;
see the Discovery history entry, and note that it is a **loop bound**, not an allocation):

| Site | Defect | Reachable from the wire? |
|---|---|---|
| `framebuffer::resize` | `w * h * 4` unguarded — 17_179_344_900 at the type's maximum | **yes**, `DemandActive`'s declared desktop and Display Control `OutputResized`, neither clamped |
| `nscodec::plane_sizes` | `tw * height` unguarded, and `temp_dims` rounds 65535 up to 65536 | **yes on 32-bit**, through `decode`'s own `u16` parameters |
| `framebuffer::blit` | `src_stride_px * 4` overflows on **every** target | no — callers pass `u16`-derived and `MAX_SURFACE_DIM`-bounded strides |
| `framebuffer::copy_rect_into` | out-of-range slice index on a rect outside the buffer | no — the host calls it with a `FrameUpdate` we produced |

The last two are the case ADR-0012 §1 exists for: *reachability governs priority, never the
contract*. The first two are not — they are live, and every other gate was green over both.

**One of them also shows why "total" and "does not panic" are different requirements.**
`plane_sizes` returns bounds that `decode_plane` trusts, and its empty-input branch is
`vec![0xFF; original_size]` — so making the multiply *saturating* would have converted an
arithmetic overflow into an allocation of the entire address space. It refuses instead.

**Four derivations, and the gaps between them are the finding.** There were two until
#241/#238, and each of those issues had found a different hole in them — one by **location**,
one by **kind**. #262 found a fourth hole in the *third*, by **shape**: ③ matches signatures,
and a member whose defect is a loop bound has the same signature as one whose defect is an
overflow, so ③ lists it and the adjudication clears it:

```sh
# ① what is fuzzed
ls fuzz/fuzz_targets/

# ② what parses untrusted bytes — no longer justrdp-pdu alone (#241)
rg --files crates/justrdp-pdu/src crates/justrdp/src crates/justrdp-tokio/src -g '*.rs'

# ③ what CONSUMES an already-parsed wire value as arithmetic — ADR-0012's class (#238).
#    An over-approximation on purpose: it lists candidates, and the adjudication is the
#    judgement ADR-0012 §1 states ("does the signature admit a value the arithmetic has no
#    meaning for"). Roughly 40 candidates today, of which ~20 are members. That question alone
#    is NOT sufficient — it answers "no" for a zero extent, over a live hang (#262). Ask the
#    second half above with it, and run ④ for the sites it cannot describe.
rg -U "pub fn [a-z_0-9]+ *(<[^>]*>)? *\([^)]*\b(u8|u16|u32|usize|i8|i16|i32)\b" \
   crates/justrdp-codecs/src crates/justrdp/src

# ④ what LOOPS over a wire-derived count — the half ③'s membership question answers "no" to,
#    and the half neither ①, ② nor `decoder-dimension-overflow-32bit.md` can see (#262). That
#    note's derivation is scoped to *allocation sizing* (`rg 'usize::from|as usize' | rg '\*'`),
#    and a loop bound is not an allocation size. Adjudicate each hit on two questions: is the
#    trip count a **bare `usize`** rather than `usize::from(<u16>)`, and does a zero extent
#    reach the loop rather than being refused above it?
rg -n 'for [a-z_0-9]+ in 0\.\.' crates/justrdp-codecs/src crates/justrdp/src crates/justrdp-pdu/src

# and what each already carries, to subtract:
rg -n 'fn [a-z_0-9]+_never_panics' crates/justrdp-codecs/src crates/justrdp/src crates/justrdp-pdu/src
```

**④ adjudicated in full on 2026-08-31, because an over-approximation nobody has walked is a
list rather than an answer.** ~60 hits, **two** members:

| Site | Trip count | Verdict |
|---|---|---|
| `color::to_rgba` | bare `usize` `height` | **was the defect** — guarded at `width == 0 \|\| height == 0` (#262) |
| `nscodec::reconstruct` | bare `usize` `height`, `nscodec.rs` `for y in 0..height` | **closed with #262** — the second member, guarded in the same change; its property's dimension generators were widened too, which is what would have found it |
| `rle::decompress`, `planar::decompress` | bare `usize` | closed **as policy** — both refuse a zero extent with `EmptyImage` above the loop |
| `framebuffer::blit` | `usize` mins | closed **by a guard** — `if width == 0 \|\| height == 0 { return None }` sits before the loop |
| `pointer::decode_pointer`, `egfx`'s `blit`/`fill`/`extract`, `clearcodec`'s region walks | `usize::from(<u16>)` | bounded **by construction** — ≤ 65535 rows, so the worst case is slow, not unbounded. **`extract` then panicked inside this loop (#268)**, and the verdict above is still the right answer to ④'s question: a bounded loop is not a safe loop, because ④ adjudicates the *trip count* and says nothing about the body. Read this column as "terminates", never as "cleared" |

**The `u16` row is why this defect never reached a client and the note still records it.** Every
wire path into `to_rgba` carries a `u16`-derived height (`session.rs`'s bitmap rect,
`egfx.rs`'s `Rect16`), so the worst reachable case was 65535 empty rows returning the same
value. `width == 0` *is* wire-reachable — `Rect16::width()` is `right.saturating_sub(left)` and
`[MS-RDPEGFX]` 2.2.1.2 makes the rect exclusive with no non-zero requirement — but the **hang**
is not. Reachability set the priority and not the contract, exactly as ADR-0012 §1 says, and
the cost landed on CI instead of on a host.

**Match the names exactly when subtracting ③, or the census lies in the safe-looking
direction.** Measured while writing this: a loose `rg to_rgba` reported `color::to_rgba` as
*covered*, because it matched inside `decode_to_rgba_never_panics` — a different function in a
different module. That is the same substring trap this note already records twice below, for
`pointer` across crates and `license` within one module, and the third instance was the
census command itself.

**② was widened rather than exempted, and the rule that adjudicates its new members is part of
the widening.** `crates/justrdp/src` holds exactly one live parser of server bytes that
`justrdp-pdu` does not own — `tls::extract_subject_public_key`, whose parse is
`x509_cert::Certificate::from_der`. A parse performed entirely inside a security-critical leaf
dependency (ADR-0002) is that dependency's contract, so what this note requires of such a member
is coverage of **our wrapper on the live path**, not a claim about the decoder. The audit that
produced that answer is cheap and worth repeating rather than trusting: `connect.rs:507`'s
`.get(..4)` AUTHZ read is bounded by construction, `license_crypto`'s `md5`/`sha1` take slices
and belong to ③ if anywhere, and the two `from_le_bytes` hits in `egfx.rs`/`session.rs` are in
test code.

The gap used to be the whole connect sequence. #200 closed the mechanical half of it —
`tpkt`, `x224`, `nego`, `dvc`, `svc` and `displaycontrol` now carry a target and a
property — and #203 closed `gcc` and `mcs`. **Read that sentence as the module claim it is**:
#230 re-ran the derivation by entry point and found `tpkt::frame_len` and `fastpath::frame_len`
uncovered inside two of those very modules, each a *second* parse of the same header its
`decode` re-parses rather than a helper it calls. Both are closed now, and the census that finds
the next one is spelled out below. So what remains without a target is:

- **`ber` and `per`**, which are ASN.1 *primitives* (`read_length`, `read_integer`,
  `read_octet_string`), not PDU parsers. Fuzzing them in isolation asserts little; the
  reachable surface is the one their callers above expose. Probably correct to leave
  without targets, which is a decision, not an oversight — recorded so nobody re-derives it.
  The same reasoning, checked rather than assumed, covers **`justrdp_pdu::rfx::decode_all`**:
  `justrdp_codecs::rfx::RemoteFx::decode_to_rgba` is its only caller and carries both artifacts.
- **`share`, `update`, `errinfo`**, which parse post-activation session bytes.

**Two derivations by name, and a name can be taken by different code — in another crate, or in
the same module.** Both forms have now been measured, and the second is the one that hides.

- **Across crates (#203).** `ls fuzz/fuzz_targets/` prints `pointer` and `rfx`, and both files
  exist — but they target `justrdp_codecs`, and the identically-named `justrdp-pdu` modules are
  different code. For `rfx` the codec calls the PDU parser, so the coverage is real and
  transitive; for `pointer` it does **not**: `justrdp_codecs::pointer::decode_pointer` takes
  `width`, `height`, `xor_bpp` and two mask slices *already parsed*, so the
  `TS_POINTERATTRIBUTE` header parse that produced them was reached by nothing.
- **Within one module (#230).** `license` appears in both lists, in the same crate, with no
  sibling to confuse it with — and four of its five live-path parsers had neither artifact.
  `fuzz_targets/license.rs` and the property beside it drive `ServerLicenseRequest::decode`,
  which calls none of `LicensePreamble` / `LicenseError` / `PlatformChallenge` / `NewLicense`;
  `justrdp/src/connect.rs:854-950` drives all of them off one cursor. There is no cross-crate
  tell here at all, which is why this form is worse: the `pointer` case at least *looks*
  suspicious once you notice two files share a name.

Reading the two lists side by side answers "is there a file called X", and the question is "is
this function driven" — the same gap between an artifact and the thing that consumes it that
#143 and #192 fell into, one level up. **Cross-reference by entry point, not by module name.**
The cheap mechanical form, which is what found `finalization`: list the `pub fn`s in
`justrdp-pdu` that `crates/justrdp/src` names, and check each against the properties and the
targets *by function*.

The bootstrap question was measured while closing the first bullet (#200): undirected
bytes reach **16.5%–48.8%** of the regions in the connect-sequence parsers, against
**8.9%** for `rfx::progressive`. So this family does *not* need a seed corpus the way
Progressive does — its headers are short enough that a mutator finds valid values by
chance. `displaycontrol` at 16.5% is the closest to the wall and the one to re-measure
first if a target here ever looks stuck.

**A decoder we do not own is subject to this and invisible to both derivations above.**
Neither `ls fuzz/fuzz_targets/` nor a walk of `crates/*/src` can name a decode path that
lives in a dependency, so "everything we parse is covered" was true and beside the point
while `ironrdp-graphics::zgfx` sat on the live EGFX path (#189). There is no such path
today — `cargo tree -p justrdp-tokio -e normal` names no `ironrdp` crate — which makes the
recurrence test a one-liner rather than a hole: **if that command ever prints a decoder
again, this invariant does not reach it.**

New decoder ⇒ a proptest no-panic property in the same PR (stable gate), and a fuzz
target — which is **two** artifacts, not one: `fuzz/fuzz_targets/<name>.rs` *and* its
`[[bin]]` in `fuzz/Cargo.toml`. A file without the manifest entry is never compiled by
anything, so it reads as covered and is not.

**The lane runs whatever is in the directory** (#200): `fuzz.yml` derives its matrix
from `ls fuzz/fuzz_targets/` and fails if the manifest disagrees, so a new target is
covered on the day it lands — but the lane is *nightly*, so it is not covered by the
PR gate that day. That gap is why the proptest half is not optional.

This rule used to stop at "a fuzz target in `fuzz/fuzz_targets/`", and #143 and #192
each satisfied it exactly as written while the lane's hand-kept matrix ran neither
target for months. A recurrence test that names an artifact but not the thing that
consumes it is satisfiable without the coverage it exists to buy.
