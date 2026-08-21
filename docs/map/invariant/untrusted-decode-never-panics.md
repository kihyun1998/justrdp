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
[ADR-0012](../../adr/0012-consumption-site-totality.md) owns that class; what belongs here is
that neither command below can see it.

Two derivations, and the gap between them is the finding:

```sh
ls fuzz/fuzz_targets/                      # what is fuzzed
rg --files crates/justrdp-pdu/src -g '*.rs'   # what parses untrusted bytes
```

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
- **`finalization::{Synchronize, Control, FontMap}::decode`**, which are the connect sequence's
  own last three server parses (`justrdp/src/connect.rs:1116`, `:1132`, `:1137`, and
  `justrdp/src/session.rs:545` on reactivation). Found by #230's completeness pass, tracked as
  **#237**, and the reason it is worth naming rather than folding into the bullet above: unlike
  `share` / `update` / `errinfo` it had never been *recorded* as uncovered at all, so nothing
  here was wrong about it — nothing here mentioned it. An unlisted gap is indistinguishable from
  a closed one; a listed gap is a decision someone can disagree with.

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
