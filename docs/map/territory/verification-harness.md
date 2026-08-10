# Verification harness

## What it is

How this project knows it is right: a differential oracle against
`ironrdp-graphics` / `ironrdp` for codecs and crypto, a corpus of real Server 2022
captures for ClearCodec, property tests that assert decoders never panic, a nightly
libFuzzer lane, a coverage discovery job, and a real Windows Server 2022 VM for the
things only a server can prove. Verification is a territory because it is something
the system does — and because a claim about correctness here is load-bearing
everywhere else.

## Governing decisions

- [ADR-0003](../../adr/0003-phased-codecs-differential-oracle.md) — the oracle
  strategy and the phase-out condition.
- [ADR-0007](../../adr/0007-stage-boundary-codec-verification.md) — stage-boundary
  verification where no assembled oracle exists; the #118 amendment adds
  assembly-layer independence.
- [ADR-0008](../../adr/0008-robustness-testing-fuzz-and-property.md) — proptest on
  stable in the PR gate, coverage-guided fuzzing on a nightly CI lane.

## Design model

- **Byte-identical output or it is not proof** (codecs). A visual check or a demo is
  a smoke test.
- **The corpus encodes tolerances that no spec states** — `clearcodec_corpus`
  fixtures are real Server 2022 streams, and the divergences from FreeRDP they force
  are requirements, not bugs (#127).
- **Robustness is a property, not a vector**: "decode never panics on arbitrary
  bytes" covers an input space hand-written vectors cannot reach.
- **The VM proves what only a server can** — the full connect sequence, licensing's
  "error means proceed", the graphics caps a real host advertises.
- **Coverage is a discovery tool with no threshold**, scoped to the sans-IO core;
  the adapter is excluded because its tests need the VM.

## Code

- `justrdp-codecs/tests/` — `differential_ironrdp_graphics.rs`,
  `differential_rfx.rs`, `differential_pointer_ironrdp.rs`, `clearcodec_corpus.rs`,
  `fixtures/`
- `justrdp-pdu/tests/` — `differential_ironrdp.rs`, `differential_activation.rs`
- `justrdp/tests/` — `differential_input_ironrdp.rs`,
  `differential_license_crypto.rs`
- `fuzz/fuzz_targets/` — `capability.rs`, `clearcodec.rs`, `egfx.rs`, `fastpath.rs`,
  `license.rs`, `nscodec.rs`, `planar.rs`, `pointer.rs`, `rfx.rs`, `rle.rs`
- `justrdp-tokio/src/lib.rs` — the `#[ignore]`d VM tests and the loopback CredSSP
  test
- Target list derivation: `ls fuzz/fuzz_targets/`

## Reference behaviour

**None.** No verified external-fact store — which is a pointed absence *here*: the
oracle compares behaviour at test time and records nothing, so a divergence
adjudicated once (say, in #127) leaves no citable artifact behind, only a fixture.

## Cross-cutting invariants

- [Oracle agreement is not independence](../invariant/oracle-agreement-is-not-independence.md)
  — the limit on what this harness can prove.
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) —
  the property this harness automates.
- [Decoder dimension overflow on 32-bit](../invariant/decoder-dimension-overflow-32bit.md)
  — the class x64 CI structurally cannot observe.

## Blast radius

- [Bitmap codecs](bitmap-codecs.md) — every correctness claim there routes through
  here.
- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — the phase-2 rewrite's exit
  criterion is an oracle pass.
- [Licensing](licensing.md) — the differential crypto test is its only proof.
- [Supply chain & gates](supply-chain-and-gates.md) — which of these run in CI, and
  which are nightly-only or VM-only.
- [Adapter drive loop](adapter-drive-loop.md) — hosts the VM and loopback tests.

## Known holes / open

- **Fuzz coverage is codec-shaped, not parser-shaped.** Ten targets exist, all
  graphics/capability/license, while roughly twice as many wire parsers have none.
  The enumeration is **owned by**
  [untrusted decode never panics](../invariant/untrusted-decode-never-panics.md),
  which carries the two commands that derive both lists — deliberately not copied
  here, because a second hand-kept list is what diverges.
- **One VM is one server.** The WS2022 box advertises a fixed cap set; paths it does
  not advertise have never been exercised against anything.
- **The VM suite does not isolate its own sessions, and the symptom masquerades as
  several unrelated failures.** Two properties, both measured 2026-08-10: it must run
  with `--test-threads=1` (in parallel, 6 of 12 fail and the same 6 pass serially —
  they race for one VM), and **no test tears down its Windows session**, so each
  connect reattaches to the previous test's disconnected session and windows
  accumulate. `keyboard_and_mouse_input_drive_the_real_vm` leaves Notepad open;
  `logoff_inside_the_session_yields_the_typed_reason` then stalls on Windows' *"close
  N apps and sign out"* confirmation — **N tracked the number of input tests that had
  run before it** — and that modal swallows the input of every later test. One
  leftover window therefore reads as three or four independent bugs. Every test passes
  on a clean session; no single run has been 12/12. The failure set moves between
  runs, which is the tell.
- **32-bit guards need an i686 run** that no CI job performs — the class closed in
  #151/#155 is provable only on a target the gate does not build.
- No captured-stream replay harness exists for the connect sequence: a VM run is the
  only end-to-end proof, and it is not reproducible offline.
