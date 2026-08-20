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
- Prior art that made the risk concrete rather than theoretical: FreeRDP's
  rle/planar/clearcodec/nsc OOB CVEs (memory `rdp_decoder_robustness_refs`).

## Where it will recur

**If a function reads a length, count or offset from bytes it did not produce, it is
subject to this.** Two derivations, and the gap between them is the finding:

```sh
ls fuzz/fuzz_targets/                      # what is fuzzed
rg --files crates/justrdp-pdu/src -g '*.rs'   # what parses untrusted bytes
```

The gap used to be the whole connect sequence. #200 closed the mechanical half of it —
`tpkt`, `x224`, `nego`, `dvc`, `svc` and `displaycontrol` now carry a target and a
property — and #203 closed `gcc` and `mcs`. So what the second command still finds without
a target is:

- **`ber` and `per`**, which are ASN.1 *primitives* (`read_length`, `read_integer`,
  `read_octet_string`), not PDU parsers. Fuzzing them in isolation asserts little; the
  reachable surface is the one their callers above expose. Probably correct to leave
  without targets, which is a decision, not an oversight — recorded so nobody re-derives it.
  The same reasoning, checked rather than assumed, covers **`justrdp_pdu::rfx::decode_all`**:
  `justrdp_codecs::rfx::RemoteFx::decode_to_rgba` is its only caller and carries both artifacts.
- **`share`, `update`, `errinfo`**, which parse post-activation session bytes.
- **`justrdp_pdu::pointer::{decode_slowpath, decode_fastpath}`** and
  **`justrdp_pdu::client_info::decode_basic_security_header`**, which have neither artifact and
  *are* on the live path (`justrdp/src/session.rs:374`, `:554`, `justrdp/src/connect.rs:854`).
  Found by #203; see the derivation caveat below for why they had been read as covered.

**Two derivations by name, and a name can be taken by a covered sibling in another crate.**
`ls fuzz/fuzz_targets/` prints `pointer` and `rfx`, and both files exist — but they target
`justrdp_codecs`, and the identically-named `justrdp-pdu` modules are different code. For `rfx`
the codec calls the PDU parser, so the coverage is real and transitive; for `pointer` it does
**not**: `justrdp_codecs::pointer::decode_pointer` takes `width`, `height`, `xor_bpp` and two
mask slices *already parsed*, so the `TS_POINTERATTRIBUTE` header parse that produced them is
reached by nothing. Reading the two lists side by side answers "is there a file called X", and
the question is "is this function driven" — the same gap between an artifact and the thing that
consumes it that #143 and #192 fell into, one level up. **Cross-reference by entry point, not by
module name**, and note that the modules where this bites are exactly the ones split across
crates.

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
