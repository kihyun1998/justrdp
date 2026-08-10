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
  list**: ten fuzz targets exist, all codec/capability/license, while the
  connect-sequence parsers have none —
  [`docs/map/invariant/untrusted-decode-never-panics.md`](../map/invariant/untrusted-decode-never-panics.md).

## Step 6/7 — surfaces & gates

- **The `fuzz` crate is the `--workspace` blind spot** — out of the workspace by
  design (its own `[workspace]`), so `cargo test --workspace` does not build it. A
  public-API change needs a separate `cargo check --manifest-path fuzz/Cargo.toml`.
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
