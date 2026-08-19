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
property — so what the second command still finds without a target is:

- **`gcc` (9 block types) and `mcs` (5 PDU types)**, which have no single top-level
  `decode` to point a target at. One target per type, or one with a selector byte, is a
  shape decision rather than an omission.
- **`ber` and `per`**, which are ASN.1 *primitives* (`read_length`, `read_integer`,
  `read_octet_string`), not PDU parsers. Fuzzing them in isolation asserts little; the
  reachable surface is the one their callers above expose. Probably correct to leave
  without targets, which is a decision, not an oversight — recorded so nobody re-derives it.
- **`share`, `update`, `errinfo`**, which parse post-activation session bytes.

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
