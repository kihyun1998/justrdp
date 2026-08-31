# 0012 — A parser's guarantee is not held at the point of use: consumption-site totality

- Status: Accepted (promoted while working issue #211; conformance items #211, #233, #252,
  #262, #263, #268)
  - Amendment 2026-09-01 (#268): **§5's totality comment is discharged against a *step*, and a
    reader takes it as a claim about the *function*.** The #263 Amendment below records that a
    discharged §5 argument is not a safety claim, and gives two reasons the rule cannot see —
    a threshold sized against a type, and a hazard about magnitude. This is a third and it is
    cheaper than either: the argument can be **entirely true** and still not be about the thing
    that fails. `justrdp::egfx`'s `Surface::extract` carried exactly the comment §5 asks for —
    *the first two statements clip `w`/`h` to this surface's own dimensions before any multiply,
    so the reserve is bounded by a buffer that already exists*. True, and about the multiply.
    Clipping `w` does not clip `x`, so at `x > self.width` the extent goes to zero, the row loop
    still runs, and `&self.rgba[off..off]` panics on a slice whose **start** is past the end.
    Reached from the wire through `SURFACE_TO_SURFACE` and `SURFACE_TO_CACHE` on an ordinary
    1920x1080 surface: `left == 1920` is `Ok` and `left == 1921` panics. **So §5 gains a
    qualifier rather than a clause** — where the totality argument is a comment, it names the
    step it covers, because a comment that reads as covering the function is how a §5 discharge
    stops being re-checked. **Two of §1's three grounds hold and the third does not**, which
    is worth saying because the one that fails is the one that usually carries this record:
    `extract` is **private**, so *"the functions are public"* does not apply. The other two do —
    the constraint is established in `justrdp-pdu` (`Rect16`) and consumed in `justrdp` across a
    crate boundary, and the value the indexing uses (`off`) is *derived* from `x` rather than
    being `x`. Both call sites pass `src_rect.left` / `src_rect.top` unclamped, so reachability
    is **yes** and, per §1, that sets the priority and never the contract.

    **A Consequences clause below was false when it was written, and is true now.** The #262
    bullet ends *"every other loop in the codec and framebuffer paths is either `u16`-derived or
    guarded before the loop (`framebuffer::blit`, `egfx`'s surface ops)"*. The disjunction holds
    — `extract`'s loop **is** `u16`-derived and terminates — but the parenthetical cites
    `egfx`'s surface ops as a family that was guarded before the loop, and one of the four was
    not. It is the identical failure the code comment made, one document up: a claim checked at
    some members, written about the set. Corrected by the change rather than by this record, and
    left standing with this note attached per the ADR-0002/0007 house pattern. §1–§5 are
    unaffected.

  - Amendment 2026-08-31 (#263): **§2 says which *quantity* to guard and is silent about
    which *ceiling* to guard it against, and the silence is load-bearing for every site in
    this class that allocates.** A guard written as `checked_mul` discharges §5 exactly — it
    is *"a validating step that refuses what the arithmetic cannot take"* — and it is not a
    bound: `Vec` refuses any request above **`isize::MAX`**, not above `usize::MAX`, so on a
    32-bit target there is a 2 GiB window where the guard returns `Some` and the allocation
    panics with *capacity overflow* inside `raw_vec`. Measured on `i686-pc-windows-msvc` with
    the `checked_mul` guard in place: `40000 x 20000 x 4` is 3_200_000_000, passed, and
    panicked. That is this record's own discharge condition being satisfied over a live
    panic, which is the strongest available form of the finding — the same shape §2 already
    records one order of magnitude smaller, where a guard written as `q > 15` diverges by one
    from where the arithmetic is undefined. **So §2 extends: the threshold is written on the
    quantity the arithmetic uses, *at the ceiling the operation that can fail enforces*.**
    `usize::MAX` is the type's ceiling and belongs to no operation. See §2 below and
    [decoder dimension overflow on 32-bit](../map/invariant/decoder-dimension-overflow-32bit.md),
    which owns the per-site adjudication and records that only `rfx` is corrected so far.

    **Second, and the reason this is an amendment rather than a note: totality is not the
    whole obligation, and a site can satisfy this record completely and still be the defect.**
    `justrdp_codecs::rfx::RemoteFx::decode_to_rgba` is total for its `(u16, u16)` signature
    once the refusal is written, and on **64-bit** that refusal fires on nothing at all,
    because 65535 x 65535 x 4 = 17_179_344_900 is representable. Measured: a **93-byte**
    TS_RFX tileset with `destRect = (0,0,65535,65535)` returned `Ok(Some(17_179_344_900))`
    on `x86_64-pc-windows-msvc` — 16 GiB allocated, 18.9 s, no error — and on a
    commit-constrained host `alloc_zeroed` fails, which is `handle_alloc_error` and therefore
    **`abort`**: not a `Result`, not catchable, fatal to the host process rather than to the
    RDP task. Totality is about *representability*; that failure is about *magnitude*, and no
    guard written from the parameter type can reach it. The bound has to come from a layer
    holding a defensible number — `justrdp::egfx`'s `MAX_TOTAL_SURFACE_BYTES`, which is
    derived (no admissible surface exceeds it, so no legitimate `destRect` does) rather than
    picked. **§1 is unchanged and the split is deliberate**: the codec owns totality for its
    own signature, the surface model owns magnitude, and §3's *one quantity, one answer* is
    not in play because the two are answering different questions. Recorded so a future
    reader does not take a discharged §5 argument as evidence that a consumption site is
    safe.
  - Amendment 2026-08-31 (#262): **§5's disjunction is not exhaustive, and the missing half is
    a loop rather than an expression.** As written it offers two ways to discharge the standing
    rule — refuse what the arithmetic cannot take, or *"where the arithmetic is total for the
    whole parameter type, a comment saying so and why"*. `justrdp_codecs::color::to_rgba`
    satisfies the second **exactly**: at `width == 0` every guard is not merely total but
    *passes* (`0 * bpp` is 0, `0 * height` is 0, and `src.len() < 0` is false, so the
    source-length check succeeds rather than refusing), and the function still does not return,
    because `for out_row in 0..height` walks a bare `usize` over empty rows. A property
    generating `any::<usize>()` reaches that draw in **0.2% of cases and therefore ~44% of
    runs** — `P(width == 0) = 6/9 x 1/33`, `P(height from the unbounded arm) = 1/9`, over
    proptest's default 256 cases — which is why it was invisible until it was not, and why the
    six healthy runs on either side of a killed one proved nothing. It cost ~56.4 runner-hours
    across 10 cancelled CI jobs before anyone read a killed log. **So the totality argument §5 requires
    covers the trip count of every loop a parameter bounds, not only the arithmetic performed
    inside it** — a guard chain that validates arithmetic does not bound a loop. This is an
    extension in the ADR-0002/0007 house pattern, not a rewrite: §1–§4 are about which module owns
    a guarantee and stay as written; what moves is what §5 has to *check* before it is
    discharged. **Routing note, because the wrong record was the tempting one:** this is not
    §3. That section is titled *one **undefined** input, one answer*, and a zero extent is
    defined for every function involved — `rle::decompress` and `planar::decompress` refuse it
    as **policy** (`EmptyImage`), which is a different act from bounding a loop, and a
    divergence row naming them against `to_rgba` would report a disagreement that does not
    exist. **Nor is it the clamp this record rejects.** *Saturate or clamp at the point of use*
    is declined below under ADR-0009 §3(b) (*"silent masking is forbidden"*), and a clamp is a
    wrong answer substituted for a right one; `Ok(Vec::new())` for a zero extent is the right
    answer — `[MS-RDPEGFX]` 2.2.1.2 makes `RDPGFX_RECT16` exclusive with no non-zero
    requirement, so `right == left` is spec-legal and there is no divergence being hidden.
    That the answer agrees with FreeRDP's *caller-supplied-destination* family and diverges
    from its *allocate-and-return* family (`freerdp_glyph_convert_ex`, `color.c:265-267`,
    `return nullptr`) is deliberate and argued at the site, on what the one reachable consumer
    does with the error: `justrdp::egfx`'s uncompressed WTS1 arm propagates a `ColorError` with
    `?`, which is fatal for the channel where every other codec arm there warn-and-skips.
    See the Consequences bullet below for the second known member.
  - Amendment 2026-08-25 (#252): **§3 derives a case outside codecs, which is evidence for the
    rule rather than a limit on it.** Its sentence says *"two stages of one **codec** family"*,
    and two non-codec sites now reach for it: #253 (a Share Data header field enforced in one
    module and unenforced in another) and `justrdp::session`'s reactivation arms, which checked
    a server `Control.action` the connect leg checked and the reactivation leg did not — one PDU
    family, two answers, closed by #252. Both cite §3 as **precedent**, which is the honest
    reading of the text as written. This amendment extends the reach rather than rewriting the
    sentence, per the ADR-0002/0007 house pattern: **where two consumption sites of one family —
    codec *or* PDU — consume the same quantity, they give it the same answer, or the divergence
    is a row naming both sides.** The Consequences already claim this record *derives* its
    decisions rather than listing them; a fifth derivation outside the layer it was written
    about is what that claim predicts.
  - Amendment 2026-08-24 (#233): §3's outstanding instance is settled — WireToSurface1 refuses a
    zero quantization exponent, so the two RemoteFX dequantizers now answer it alike and the
    record needs no divergence row. See §3.
  - Amendment 2026-08-24 (#241/#238): the class this record owns **has an enumeration now**, and
    it is a derivation rather than a list — ③ in
    [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md). Producing
    it is what #238 turned out to be: it named eight uncovered members where the issue had named
    one, and working them found four defects (two wire-reachable). Conformance items: #211, #233,
    #238, #241.
- Date: 2026-08-21

## Context

`justrdp-pdu` is deliberately dependency-free, and every PDU struct in it carries plain `pub`
fields. Parsing establishes value constraints — `Quant::decode` masks each band with `& 0x0F`
so a quant exponent is `0..=15`; `RfxMessage`'s tileset walk checks every `quantIdx` against the
table it indexes; `parse_header` rejects an NSCodec colour-loss level outside `1..=7`. Those
constraints are real, and they are **not carried by any type**. `justrdp-codecs` then consumes
the same values as *arithmetic*: shift amounts, table indices, buffer offsets.

Nothing re-checks the join. The constraint and the use sit in different crates, reached through
a plain field or a bare parameter, so the compiler connects them not at all and a reader
connects them only by remembering. Four times now that join has come up as a question, and each
time it was decided from scratch:

| Decision | Site | What was decided |
|---|---|---|
| #168 (PR #210) | `rfx::srl::accumulate` | total for **every** `u8` shift, unrepresentable result is a typed error |
| #169 (PR #214) | `rfx::progressive::first_pass_shift` | derive the whole ten-band table and validate it *before* any state is touched; `shift >= 16` is a typed error |
| #169 (PR #214) | `ProgressiveError::QuantIndexOutOfRange` | typed error at the index, although the parser validates every index |
| #211 | `rfx::quant::dequantize` | open — the issue this record was promoted out of |

Four combinations of the same two participants (a value the parser constrained, a consumer that
does arithmetic with it), decided four times, with the reasoning re-derived on each occasion and
recorded — where it was recorded at all — on the branch of code that happened to raise it. The
`theflow` promotion bar is two of five triggers; four fire here:

- **A pair already decided, in a different combination.** The table above.
- **An earlier issue's premise measured false.** #168's completeness pass reported this as a
  family across the codec decoders; #211's census measured that as one site, then this record's
  own sweep found it was three (below). Separately, #211's citation `quant.rs:37` went stale
  four hours after filing, when #169 moved the line to `:77`.
- **The reference cannot arbitrate.** FreeRDP contradicts itself across its own call sites:
  `prim_shift.c:38-39` refuses a shift of 16 or wider by returning `-1`, and
  `rfx_quantization.c:73-82` calls it ten times discarding every return value before `:83`
  returns `TRUE` unconditionally. The differential oracle is not a second opinion either — its
  `quantization.rs` is structurally identical to ours, down to the `factor > 0` guard, because
  it shares this code's lineage (`docs/map/invariant/oracle-agreement-is-not-independence.md`).
- **Two in-repo artifacts require opposite things.** `quant.rs:117` pins a WireToSurface1 quant
  exponent of `0` as *skip the band and continue*; `progressive.rs:2342` pins the identically
  undefined Progressive `bitPos == 0` as *fail the tile with a typed error*. Both green, neither
  citing the other. Tracked as #233.

The state space here is combinatorial — parser-side constraint × consumer-side arithmetic ×
crate boundary × reachability — so each new combination arrives looking like a fresh judgement
call, and each one silently reinterprets the last. That is what this record ends.

[ADR-0008](0008-robustness-testing-fuzz-and-property.md) governs *whether* a decode path may
panic and *how that is tested*. It does not say **which module owns a guarantee** once the
validation and the use have been separated, which is the question all four rows above are
answers to.

## Decision

A function that consumes a wire-derived value as arithmetic is **total over its parameter
types**, not over the subset its parser happens to produce.

### 1. Refusal lives at the consumption site

If the arithmetic is undefined for some value the parameter's *type* permits, the function
refuses that value with a typed error — whether or not the wire can produce it. The parser's
constraint is evidence about **reachability**, which governs priority; it is never evidence
about **totality**, which governs the contract.

Three independent grounds, each already paid for by one of the rows above:

- **The constraint and the use are in different crates**, joined by a plain `pub` field or a
  bare parameter, so nothing re-checks when either end moves. This is not hypothetical: #211's
  own line citation was stale within four hours of being written.
- **The value at the use site is frequently *derived*, not the parsed value.** `bitPos = quant +
  prog_quant` is the sum of two nibbles and reaches 30; `num_bits` is a difference of two such
  positions; `shift` is one less again. #168 sized two guards on "it is a nibble, so `<= 15`"
  and **both were wrong**, one of them silently desynchronising the shared SRL cursor rather
  than panicking. A guarantee about an input is not a guarantee about what is computed from it.
- **The functions are public.** `justrdp-codecs` exports `rfx::quant::dequantize` and
  `nscodec::reconstruct`; a host can construct their arguments. "Unreachable from the wire" and
  "unreachable" are different claims, and only the first has been established.

### 2. The threshold is written on the quantity the arithmetic uses

Not on the wire field it was derived from. `dequantize` shifts an `i16` by `factor = q - 1`, so
it is undefined at `factor >= 16` — that is `q >= 17`, and `q == 16` is well defined (it yields
`1 << 15`). A guard written as `q > 15` therefore diverges by one from `first_pass_shift`'s
`shift >= 16`, and the two stages would refuse different inputs while claiming the same reason.
Write the guard where the arithmetic is, and the two agree by construction.

**Extended 2026-08-31 (#263): the ceiling is part of "the quantity the arithmetic uses".**
Choosing the right quantity and then bounding it at the wrong number is the same defect one
order of magnitude larger, and it is what happened to every allocation-sizing guard in
`justrdp-codecs`. `checked_mul` bounds a product at `usize::MAX`, which is the *type's*
ceiling; the operation that actually fails is the allocation, and `Vec` refuses above
`isize::MAX`. On a 32-bit target that is a 2 GiB window in which the guard passes and the
allocation panics — `40000 x 20000 x 4` is 3_200_000_000, measured on
`i686-pc-windows-msvc`. So: **write the guard where the arithmetic is, at the threshold the
failing operation enforces.** For an allocation that is `isize::MAX` at worst, and better a
domain bound the caller can defend. `rfx::RemoteFx::decode_to_rgba` carries the corrected
form (`.filter(|n| *n <= isize::MAX as usize)`); the sites that do not yet are enumerated in
[decoder dimension overflow on 32-bit](../map/invariant/decoder-dimension-overflow-32bit.md),
because a record that implied the family was closed would be a false status report in the
sense §3 already names.

### 3. One undefined input, one answer, across every stage of a family

Where two stages of one codec family consume the same quantity, they give it the same answer —
or the divergence is a recorded row naming **both** sides. A row that names only one side is a
false status report.

When this record was written it did not settle its own outstanding instance, it made it
visible: `q == 0` was skipped by WireToSurface1 and refused by Progressive.

**Settled in #233 (2026-08-24): both refuse.** `quant::shifts` derives its table with
`checked_sub(1)` and returns `RfxError::ZeroQuantExponent`, the sibling of
`ProgressiveError::ZeroBitPosition` that `first_pass_shift` already returned; the two functions
now differ only in their error type. The whole defect was one token — `saturating_sub` cannot
tell `exponent == 0`, which names no shift, from `exponent == 1`, which names a shift of zero,
and the spec asks for opposite treatment of the two.

Three things about that resolution are worth keeping, because each was measured rather than
argued:

- **The escape hatch was available and did not fit.** A divergence row was the alternative, and
  every row in the project's table records justrdp choosing against *prior art*. This would have
  been the only justrdp-against-justrdp row — which is not a decision being recorded, it is an
  inconsistency wearing a decision's clothes. Nobody had chosen `saturating_sub` over
  `checked_sub`; they were written at different times.
- **The receive-path objection does not reach it, and ADR-0009 §3(a) is why — as a removal of
  the objection, not as the mandate.** §3(a) scopes tolerance to *which features may appear* and
  holds typed errors unconditionally over contents, so refusing here is not the strictness that
  posture forbids. The mandate is §1 of this record (the arithmetic is undefined) and §3 (one
  family, one answer). Sharpest form: `shift = -1` is not a value we dislike, it is the absence
  of one — the same line #189 drew for zgfx between *what did the server mean* and *what could
  any encoder have meant*.
- **This is the family's first wire-reachable refusal, and that is stated rather than glossed.**
  `ShiftOutOfRange` cannot be reached (a nibble shifts by at most 14); a `0x00` byte is two zero
  nibbles, so `ZeroQuantExponent` can. It stays outside what any conforming encoder emits —
  `[MS-RDPRFX]` constrains the encoder to 6..=15 — and the real VM cannot corroborate either way,
  because it never emits CAVIDEO. So the safety of refusing rests on FreeRDP agreeing
  (`rfx_quantization.c:66-71`, propagated through `rfx_decode.c:66-67` to `rfx.c:1082-1086`) and
  is recorded as a FreeRDP-derived position, not an observed one.

### 4. Derive-and-validate is a separate function from apply

The shape that gives a refusal somewhere to live without making a hot loop fallible, already
built once in this repo:

```
first_pass_shift(&ProgressiveQuant) -> Result<ProgressiveQuant, ProgressiveError>  // validates ten bands
dequantize_first_pass(&mut [i16], &ProgressiveQuant, bool)                          // infallible + debug_assert
```

A consumer that does both in one function has nowhere to put a `Result` without making the
per-coefficient loop fallible, which is the whole of why `dequantize` was written infallible and
then could not be fixed in place.

### 5. The standing rule

A new public function that consumes a wire-derived value as arithmetic carries its totality
argument in the same change: either a validating step that refuses what the arithmetic cannot
take, or — where the arithmetic is total for the whole parameter type — a comment saying so and
why. A no-panic property whose generator is bounded to the parser's range does **not** discharge
this; it asserts the parser, not the function.

## Consequences

- **It derives the four decisions rather than listing them, and answers a fifth nobody had
  made.** §1 gives #168's "total for every `u8`" and #169's `QuantIndexOutOfRange`; §1+§2+§4
  give #169's `first_pass_shift` and settle #211 with no new judgement. Applied to a site nobody
  had considered, it produces an answer immediately: `nscodec::reconstruct` (`nscodec.rs:251`)
  is a `pub fn` taking `color_loss_level: u8` and shifting by `color_loss_level - 1`, validated
  `1..=7` in `parse_header` — **a different function**. It panics at `color_loss_level >= 17`,
  reproduced. That is the third site in what #211's census had recorded as two, and it is the
  evidence that this record is a rule rather than a filing cabinet.

  **Re-measured 2026-08-24 (#241/#238), and "three sites" was itself an artefact of hand-counting.**
  Deriving the class instead of listing it turned up **eight** uncovered members, five of which no
  issue had named — four of those in `justrdp::framebuffer`, a module the invariant listed as a
  *territory* while nobody had listed its functions. Two of the four defects found are reachable
  from the wire (`framebuffer::resize`, `nscodec::plane_sizes`), which is a different distribution
  than this record's first four instances suggested: reachability is not rare in this class, it was
  under-sampled.
  **Re-measured again 2026-08-31 (#262), and the enumeration was not the thing that failed.**
  Derivation ③ *listed* `color::to_rgba`; #238/#241 worked it and gave it a no-panic property.
  The defect that survived that pass is the one no artifact in either lane can observe — a
  no-panic property **hangs** rather than failing on non-termination, and a hang never shrinks,
  so it never lands in `proptest-regressions/` either. So the fifth defect in this class was
  found by a CI bill, not by the census, and the census was right. What the adjudication step
  missed is stated as the Amendment above: ③'s membership question (*"does the signature admit
  a value the arithmetic has no meaning for"*) answers **no** for a zero extent, which is
  correct and beside the point. `nscodec::reconstruct` (`nscodec.rs`, `for y in 0..height` with
  `height` a bare `usize`) was the second known member and is **closed in the same change**,
  because one quantity gets one answer across a family and filing the sibling would have left
  the family split for as long as the issue sat. Two things travelled with it: `round_up`'s
  multiply now refuses instead of wrapping — `plane_sizes`' own doc-comment had named that
  multiply as *the* reachable overflow path while it stayed unchecked, so the function panicked
  before returning the `Result` it promised — and the output reservation is capped against
  `y_plane`, without which widening the property's dimension generators past `0..=32` would have
  traded a hang for an allocation abort. That widening is the §5 argument this record already
  makes for `color_loss_level`, applied to the two parameters in the same signature it had been
  left off. It is the only other member — `rle`/`planar` refuse a zero extent as policy, and every other loop in
  the codec and framebuffer paths is either `u16`-derived or guarded before the loop
  (`framebuffer::blit`, `egfx`'s surface ops). Derivation ④ in the invariant note is the
  command that finds the next one.
- **A discharged §5 argument is not a safety claim, and #263 is the instance.** The
  standing rule asks for a validating step or a totality comment; both were producible for a
  function that panicked on 32-bit *and* served a 16 GiB allocation on 64-bit. What the rule
  cannot see is a threshold sized against a type rather than against the failing operation
  (now §2), and a hazard that is about magnitude rather than representability (now the
  Amendment). Both were found by a throwaway probe on two targets, not by any gate: the
  32-bit half is now covered by `overflow-32bit.yml`, and **the 64-bit half is covered by
  nothing at all** — a decode that succeeds is green in every lane this project runs.
- **It is not a newtype mandate.** §1 is satisfied by a check at the consumption site; the
  guarantee is *not* required to move into the type. See the rejected alternative below for why
  the type-side answer was measured and declined.
- **Reachability keeps its job, and loses the other one.** "The wire cannot produce this" still
  decides priority — #211 is P2 precisely because nothing reachable panics — and no longer
  decides whether the contract holds.
- **A generator bounded to the parser's range is now a recorded defect shape.**
  `nscodec.rs:626-639`'s property is documented as covering *"any colour-loss level"* and
  generates `1u8..=7`, which is exactly the range that hides the panic above. The opposite
  convention is already written down twice, in `fuzz/fuzz_targets/progressive_srl.rs` and
  `progressive_multipass.rs`, both of which hand quant nibbles over **unmasked** on purpose and
  say why. This record makes the second convention the one the family follows.
- **Relationship to [ADR-0009](0009-tolerant-negotiation-posture.md).** §Decision 3(a) —
  *"Tolerance is about which features are allowed to appear, never about trusting their
  contents"* — is the same sentence read from the parser's side. This record is its
  point-of-use half. Nothing here narrows the tolerance posture: refusing a value the arithmetic
  has no meaning for is not strictness about *what a server may send*, and where the two could
  be confused (#233) the question was routed to a decision rather than answered by this record —
  and that decision, recorded in §3 above, went the way §1 pointed.
- **Relationship to [ADR-0008](0008-robustness-testing-fuzz-and-property.md).** 0008 governs
  whether a path may panic and how that is tested; this governs where the guarantee lives when
  validation and use are separated. Neither subsumes the other: 0008's two lanes could be fully
  green over a function this record fails, which is what `nscodec::reconstruct` demonstrates.
- **New tracker structure.** Areas this record now governs file **conformance items under it**
  rather than opening a spine. #211 and #233 are its first two.

## Rejected alternatives

- **Move the guarantee into the type — a nibble newtype in `justrdp-pdu` that only the parser
  can construct** (#211's option (b)). Rejected on cost and coverage, having measured both.
  *Coverage:* it does not reach the family. `nscodec::reconstruct`'s `color_loss_level` is a
  bare `u8` **parameter**, and `planar.rs`'s `cll` is a local computed inside `decompress` — a
  newtype on a PDU struct field reaches neither, so §1 would still be needed for two of the
  three sites. *Cost:* `ProgressiveQuant` is not only a parsed value, it is the codec crate's
  ten-band `u8` carrier for derived quantities that deliberately exceed 15 — `quant_add`,
  `quant_sub`, `upgrade_shift`, `TileState::bit_pos`, and the **public** accessor
  `bit_positions()`, whose return type would become a lie at the API boundary. Every one of
  those round-trips through `quant_from_bands([u8; 10])`, which cannot compile against a
  parser-only constructor, so a second ten-band type inside `justrdp-codecs` is forced. Both
  Progressive fuzz targets exist *specifically* to hand unmasked nibbles past the parser and say
  so in their headers; a parser-only constructor removes their stated reason to exist. And the
  escape hatch is twenty `pub` fields across two structs, so the change is twenty fields made
  private plus twenty accessors, in a crate where every other PDU struct is plain-pub.
  **The precedent argument #211 recorded against this option is withdrawn as wrong**, and it is
  worth withdrawing explicitly because it would otherwise be re-cited: the issue says a newtype
  "would be the only one in the crate", and there are five (`SecurityProtocol`,
  `NegFailureCode`, `ClientEarlyCapabilityFlags`, `ServerEarlyCapabilityFlags`,
  `ClientInfoFlags`) plus `EntropyAlgorithm` twelve lines above `Quant` in the same file, whose
  `from_bits` is private and which makes illegal values unrepresentable — the exact shape the
  option asks for. The option is declined on what it costs and what it misses, not on there
  being no precedent for it.
- **Saturate or clamp at the point of use.** Rejected by ADR-0009 §Decision 3(b): *"Silent
  masking is forbidden — a tolerance you cannot see is indistinguishable from a bug."* Note the
  reason is *not* "release already masks the shift": release wraps modulo the type width rather
  than clamping (`q = 17` yields the value unchanged, `q = 200` yields `1 << 7`), so a clamp
  agrees with release on no input at all. The argument from ADR-0009 stands without reference to
  release behaviour, and the argument from release behaviour does not stand at all.
- **Rely on the parser and document the assumption.** This is the status quo, and #168 measured
  what it costs: two guards sized on the parser's word, both wrong, one of them producing
  `Ok(())` on a desynchronised stream. A comment is not re-checked when the code on either side
  of it moves.
- **`debug_assert!` alone.** Rejected as the whole answer — the workspace sets no
  `[profile.*]`, so `overflow-checks` is off in release and the panic becomes silently wrong
  values rather than a crash. `debug_assert!` is correct in the *apply* half of §4, where the
  validating half has already refused the input, and that is where it is used
  (`dequantize_first_pass`).
- **A single shared "validated nibble" helper across the codec crate.** Deferred rather than
  rejected: the three sites take their values by different routes (struct field, bare parameter,
  local), and the shape that fits all three is not yet visible. Extract it when a fourth site
  makes the duplication real, per the same reasoning ADR-0008 applied to a shared generator
  crate.
