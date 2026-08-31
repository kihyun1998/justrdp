# 0008 — Robustness testing for untrusted-input parsers: property tests + fuzzing

- Status: Accepted (issue #97; first property implemented for the RLE decoder — issue #98)
- Amended: 2026-06-19 — #98 landed the no-panic property for **all** untrusted-input decoders (not just RLE), and #99 landed the `fuzz/` CI lane; the inline notes below are updated to the as-built state.
- Amended: 2026-08-21 — the 2026-06-19 amendment's *"all decoders"* was a **module** claim reported as an entry-point one, and #230 measured the gap. See the corrected Consequences bullet below. (The first attempt at this amendment retracted the wrong sentence — the lane/property correspondence it deleted as false is true in every row; recorded because a correction that misses is worse than the claim it was aimed at.)
- Amended: 2026-08-24 (#241/#238) — **the obligation is not scoped by crate.** The Context below named `justrdp-pdu` and `justrdp-codecs`, and the census in [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md) had encoded that as `rg --files crates/justrdp-pdu/src`, so a parser in the core crate was invisible to it by construction rather than by oversight (`tls::extract_subject_public_key`, #241) — as was the whole *consumption-site* class the byte-scoped wording could not describe (ADR-0012's, #238). Both derivations are widened in that note, and `justrdp` now carries `proptest` and a fuzz target for the first time. Working the resulting list turned up four defects, two of them wire-reachable; the enumeration is in the note, not here, for the reason the 2026-08-21 amendment gives.
- Amended: 2026-08-31 (#262) — **this record's most load-bearing prediction came true, and the
  lane it named as the answer does not cover the class it came true in.** §2 says *"`proptest`
  has no per-case timeout; an infinite loop hangs the test run rather than failing it"*, and the
  Consequences call that gap *"exactly the fuzz lane's mandate"*. Measured: a `justrdp-codecs`
  no-panic property hung on ~43% of seeds and cost **~56.4 runner-hours across 10 cancelled CI
  jobs** — and `color::to_rgba` has no fuzz target, because it is an ADR-0012 consumption site
  rather than a decoder, and that whole class has none. So the sentence is right about proptest
  and over-claims about the coverage. What actually bounds the class is neither lane: every job
  in all five workflows now carries `timeout-minutes`, where none did before and GitHub's
  360-minute default applied. See the corrected Consequences bullet below.
- Amended: 2026-08-31 (#263) — **the Strategy design rule's worked example is false, and it
  propagated verbatim to ten artifacts before anything measured it.** The rule says a wire
  header field is *"bounded in the generator to its **real range**"*, which is right; the
  example then bounds `width`/`height` on the ground that *"leaving them unbounded would
  manufacture OOM/overflow 'failures' that no real server could trigger"*, and **that clause is
  the one that failed**. A server picks a `RDPGFX_RECT16` freely — `[MS-RDPEGFX]` 2.2.1.2
  bounds it at `u16` and states no maximum, 2.2.2.1 makes it the bitmap's own dimensions — so
  65535 is the real range, the resulting `65535 × 65535 × 4` is 17_179_344_900, and the failure
  it produces is a **live defect**, not a test artifact: measured, a 93-byte tileset panicked on
  `i686-pc-windows-msvc` and allocated 16 GiB on `x86_64` in 18.9 s.

  Two distinct errors travelled together, and separating them is the point of recording this.
  **(a) "Real range" was read as "a comfortable number."** Every artifact derived from this
  example bounds a `u16` field at `u8` or `0..=128`, which is not the field's range by three
  orders of magnitude. **(b) Several copies added *"never the stream"*, which is a
  contradiction** — a `TS_BITMAP_DATA` header field, an EGFX wire field and a
  `TS_*POINTERATTRIBUTE` header field *are* the stream. Nobody re-read either clause for two
  years of artifacts; #263's proptest was green over a live 32-bit overflow because of it.

  **So the rule extends rather than moves:** bound a generator to the field's **declared type**,
  and where a smaller bound is kept, keep it *as a stated budget trade* (fuzzer bytes, proptest
  runtime) with a weighted arm at the full type range so the reject branch stays driven — the
  shape #230 settled for `pointer` and #263 applied to `rfx`. That makes three recorded ways a
  generator can make a green mean nothing, and they are different bugs: **#211** bounded to what
  the parser *does* enforce (asserts the parser), **#230** too wide to satisfy the parser
  (asserts the dispatch), **#263** bounded below what *anything* enforces, justified by an
  enforcement that does not exist. The invariant note already read the rule the corrected way
  (*"a `u16` wire field stays a `u16`"*,
  [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md), #211); this
  record's own text was the outlier and is what the artifacts copied. **Widening a generator is
  not automatically the fix**: measured on `rfx`, widening alone stayed green because the
  arithmetic sat behind a parse random bytes never satisfy, and it only went red once the guard
  moved in front of that gate. And a generator is not widened where the lane cannot observe the
  arm — `fuzz.yml` runs on `ubuntu-latest`, where none of these products overflow.
- Date: 2026-06-18

## Context

[ADR-0003](0003-phased-codecs-differential-oracle.md) and [ADR-0007](0007-stage-boundary-codec-verification.md) give us a strong **correctness** story: feed identical encoded bytes to our decoder and to the `ironrdp-graphics` oracle (or its primitives), assert byte-identity. But both share a blind spot — **the inputs are ones we wrote by hand.** The differential vectors and the synthesized RemoteFX corpora are streams *we* thought to generate; they are all well-formed by construction.

We decode **untrusted server bytes**. Every wire parser in `justrdp-pdu` and every codec decoder in `justrdp-codecs` reads attacker-influenced length fields, offsets, and cache indices, then slices and allocates from them. (**Amended 2026-08-24, #241/#238:** that sentence named the two crates the work was in at the time and was read afterwards as the scope. It is not — `justrdp` parses server bytes too, and sizes buffers from server-declared dimensions. See the Amendment note in Status.) Two whole classes of defect live outside the oracle's reach:

1. **Adversarial / malformed input.** A payload we never imagined can drive an index out of bounds (panic), an arithmetic overflow (panic in debug), an unbounded allocation (DoS), or a non-terminating loop (hang). This is not hypothetical for this domain: FreeRDP's ClearCodec accrued multiple out-of-bounds CVEs in exactly this code shape. Several of our decoders *document* a no-panic contract (e.g. `RleError`: "malformed input is always a typed error, never a panic") but nothing stresses that contract across the input space.
2. **Wide valid input.** Even for well-formed streams, the handful of hand-written vectors exercises a sliver of the state space. Correctness can break on a valid-but-unusual stream we simply never generated.

The toolchain constrains *how* we can close this. The maintainer's host is **stable Windows MSVC only** — no nightly toolchain, and `cargo-fuzz`/libFuzzer (which needs nightly and is effectively unsupported on Windows MSVC) does not run there. Coverage-guided fuzzing is therefore not a local development loop for this project. Our CI, however, is **Ubuntu** — libFuzzer's native environment.

## Decision

Hand-rolled parsers of untrusted input are verified **beyond the oracle** by two complementary lanes, split by what each toolchain affords.

### 1. Property tests (`proptest`) — local, stable, mandatory

Every decoder that parses untrusted bytes carries property tests, run by plain `cargo test` (and therefore by `cargo test --workspace` in CI) on the **stable** toolchain — no new CI wiring, no nightly. `proptest` is a workspace dev-dependency.

Two properties:

- **No-panic.** A randomly generated byte stream fed to `decode()` must return `Ok`/`Err`, never panic, overflow, or read out of bounds. Reaching the end without unwinding *is* the assertion; `proptest` fails and **shrinks to a minimal counterexample** on any panic.
- **Round-trip.** Where an encoder exists for the type, `decode(encode(x)) == x` over generated `x`. (Not all decoders have an encoder — e.g. the RLE decoder ships no compressor — so this property applies only where the inverse exists. It does **not** apply to lossy codecs, per ADR-0007.)

**Strategy design rule (threat-model-faithful generation).** A field that arrives from a fixed-size wire header is bounded in the generator to its real range; only the attacker-controlled, variable-length blob is left fully arbitrary. Example (RLE): the compressed stream is generated as arbitrary bytes, but `width`/`height` are bounded because they come from fixed `u16` `TS_BITMAP_DATA` fields — leaving them unbounded would manufacture OOM/overflow "failures" that no real server could trigger, i.e. test artifacts rather than defects.

**Extended 2026-08-31 (#263) — "its real range" is the field's declared type, and the example
above got its own justification wrong.** A `u16` wire field's real range is `0..=65535`, so a
generator bounded at `u8` or `0..=128` is **not** threat-model-faithful; it is a budget trade,
and it must be written as one. The example's *"no real server could trigger"* is false for any
field the spec leaves unconstrained within its type: `[MS-RDPEGFX]` 2.2.1.2 lets a server pick
65535 for both axes of a `RDPGFX_RECT16`, and doing so is a live defect rather than a test
artifact (#263, measured on two targets). Where a smaller bound is kept for budget, keep a
weighted arm at the full type range so the reject branch stays driven; where the *lane* cannot
observe the arm (the fuzz lane is 64-bit, so a 32-bit overflow cannot fire there), say that
instead of widening. See the 2026-08-31 amendment above for the three failure modes this rule
now has to distinguish.

### 2. Coverage-guided fuzzing (`cargo-fuzz` / libFuzzer) — CI lane only

A `fuzz/` workspace member with one libFuzzer target per highest-risk untrusted-input decoder, run on **Ubuntu CI under nightly** — not on the maintainer's Windows host. This lane exists because it catches what `proptest` structurally cannot:

- **Hangs.** `proptest` has no per-case timeout; an infinite loop hangs the test run rather than failing it. libFuzzer's timeout turns a hang into a reportable crash.
- **Deeper paths.** Coverage feedback mutates toward unexplored branches, reaching states random generation rarely hits.

This ADR fixes the decision that fuzzing **belongs in CI, not local dev**, and why the two lanes are not redundant. (Amended #99, landed: the `fuzz/` workspace member now carries one libFuzzer target per highest-risk decoder, run weekly on nightly Ubuntu. Its CI actions are SHA-pinned and least-privilege per [ADR-0006](0006-supply-chain-action-pinning.md), which formalizes the supply-chain requirement this sentence originally only gestured at.)

### 3. The standing rule

Adding a decoder for untrusted bytes obligates its no-panic property (and round-trip where an encoder exists) in the same change. The highest-risk decoders additionally get a fuzz target. This mirrors IronRDP's tier rule that core crates must be fuzzed — adapted to our toolchain by making the always-on, stable half a property test and the coverage-guided half a CI lane.

## Consequences

- **The oracle's blind spot is covered without weakening it.** ADR-0003/0007 still own correctness on well-formed input; this ADR adds adversarial-robustness and wide-input coverage as a separate axis. The two are complementary, not substitutes.
- **The stable lane is free to run.** Because the properties are ordinary `#[test]`s, they ship in the existing `cargo test --workspace` CI job with zero new infrastructure — the robustness net is on from the first property, before the heavier fuzz lane exists.
- **`proptest`'s limits are explicit, and are exactly the fuzz lane's mandate.** Property tests catch panics/overflow/OOB and shrink, but not hangs and not coverage-directed depth. That gap is the *reason* fuzzing is deferred to CI rather than dropped — stated here so a future reader does not mistake "we have proptest" for "we have fuzzing."

  **Corrected 2026-08-31 (#262): "exactly the fuzz lane's mandate" is true of the mandate and false of the coverage.** A hang is not a red — the property does not fail, it *runs*, so nothing shrinks and **nothing lands in `proptest-regressions/`**, which means the repo's usual backstop for a defect a property found is structurally unavailable for this class. The fuzz lane holds the mandate only where a target exists, and it does not exist for ADR-0012's consumption sites: the roster derives from `ls fuzz/fuzz_targets/`, and a function that parses nothing has never been in it. The measured cost of the difference was ~56.4 runner-hours in one day, of which 24.0 were `coverage.yml` — a *post-merge* lane running `cargo llvm-cov --workspace --exclude justrdp-tokio`, i.e. the same property, that nobody watches a PR check for. The backstop that landed is structural and belongs to neither lane: a `timeout-minutes` on every job. Stated here rather than in the note because it is a limit of the *method* this record chose, not a fact about any one decoder.
- **No runtime dependency added.** `proptest` is a dev-dependency; the fuzz crate is a non-published workspace member. The zero-runtime-dep boundary (ADR-0002) is untouched.
- **Implemented across the decoders named below (issue #98, landed).** The RLE decoder's `decompress_never_panics_on_arbitrary_input` was the tracer bullet; the no-panic property now also covers `planar`, `clearcodec`, `rfx` and `pointer` in `justrdp-codecs`, and the server-controlled `justrdp-pdu` parsers (`egfx`, `fastpath`, `capability`, `license`, `mcs`). The `fuzz/` lane (issue #99) carries libFuzzer targets for the same entry points — verified entry point by entry point while closing #230, and true in every row. The three codec properties whose class FreeRDP has a real OOB CVE for are grounded in it (`rle` → CVE-2024-32460, `planar` → CVE-2024-32458, `clearcodec` → CVE-2020-11040).
- **Corrected 2026-08-21 (#230): the heading of that bullet used to read "across *all* decoders", and the word "all" was false.** The list is by **module**, and a module carrying a property and a target says nothing about the `pub fn`s beside them. Measured while closing #230: `license` appears above and named `ServerLicenseRequest::decode` alone, so `LicensePreamble` / `LicenseError` / `PlatformChallenge` / `NewLicense` had neither artifact; `pointer` appears above as the *codecs* decoder, whose header fields arrive already parsed, so the `justrdp-pdu` parser producing them was driven by nothing. Both are closed, `client_info::decode_basic_security_header` with them.

  **The obligation this ADR states is therefore per entry point, not per module**, and the enumeration lives in [untrusted decode never panics](../map/invariant/untrusted-decode-never-panics.md) rather than in a list here — a list here is what said "all". What that note still names uncovered is `ber`/`per` (a recorded decision) and `share`/`update`/`errinfo`; `finalization` joined them in #230's census and was closed by #237. This bullet is deliberately **not** the roster; it is the record of why a roster in an ADR is the wrong artifact.

## Alternatives considered

- **Differential oracle alone (status quo).** Rejected as sufficient — it proves correctness only on inputs we author, leaving malformed-input robustness and wide valid-input coverage untested. The classes of bug in §Context are precisely the ones it cannot see.
- **`cargo-fuzz` as the single robustness tool.** Rejected as the *primary* lane — it cannot run on the maintainer's stable Windows host, so it would mean no local robustness signal at all and a slower edit/feedback loop. It is retained as the CI lane for hangs and depth, where it is uniquely capable.
- **Property tests only, no fuzzing.** Rejected — it would leave hang-class defects (non-terminating parse loops) and coverage-directed deep paths permanently untested, and would not match the rigor of the one proven independent Rust RDP implementation (IronRDP fuzzes every core crate).
- **A shared generator crate (à la `ironrdp-pdu-generators`) up front.** Deferred, not rejected — the per-decoder `proptest` strategies are small and local today; a shared generator crate is worth extracting only once the duplication is real, to avoid speculative structure.
- **Replace the hand-written LCG synthetic streams (ADR-0007) immediately.** Deferred — those streams already serve as differential *input factories* with a coverage guard; folding them into `proptest` generators (gaining shrinking) is an improvement to make per-codec as the properties roll out, not a precondition of this ADR.
