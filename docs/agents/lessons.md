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

## Step 4 — real round-trip, not a fake (ADR-0003/0007)

- **Codec proof is byte-identical, or it is not proof.** The same bitstream through
  our decoder and `ironrdp-graphics` must produce an identical `Vec<u8>`; 100% pass
  is the gate to drop the oracle dependency. connect/session proof is a real VM
  round-trip (`192.168.136.136`, memory `test_environment`) — a demo is not proof.

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
