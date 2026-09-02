# TLS transport security & server trust

## What it is

Upgrading the plaintext socket to TLS after the negotiation selected it, and
deciding **whether to believe the server's certificate**. The handshake itself is
`rustls`; the trust decision is a policy the host injects. This territory also owns
the extraction of the server's `subjectPublicKey`, which is not a TLS concern at all
— it exists because CredSSP binds its token exchange to that value.

## Governing decisions

- [ADR-0005](../../adr/0005-tls-trust-policy.md) — chain validation against the OS
  trust store by default (`rustls-platform-verifier`), with TOFU and accept-any as
  **explicit opt-ins**; the host chooses, the core never does.
- [ADR-0002](../../adr/0002-dependency-boundary.md) — `rustls` is a leaf,
  security-critical, non-RDP dependency used verbatim, and therefore lives in the
  adapter.

## Design model

- **The trust decision is policy, so it lives in the adapter** — the sans-IO core
  emits `Action::StartTls` and receives `Event::TlsEstablished` with the extracted
  public key. It never sees a certificate chain.
- Three policies, one of which is the default and two of which are opt-ins the host
  must name: OS-store chain validation · TOFU pinning (a pin store) · accept-any.
  A pin mismatch reports a SHA-256 fingerprint, which is why `ring` is a direct
  dependency of the adapter.
- `ring` over `aws-lc-rs` as the rustls provider — chosen to avoid the NASM build
  requirement on Windows.
- **`extract_subject_public_key` returns the inner BIT STRING contents of the
  `SubjectPublicKeyInfo`, not the whole SPKI.** The distinction is load-bearing and
  is stated at the `Action::StartNla` docs; getting it wrong produces a CredSSP
  exchange that completes locally and fails against a real server.

## Code

- `justrdp-tokio/src/trust.rs` — `TrustPolicy`, `FilePinStore`, `MemoryPinStore`,
  `pin_fingerprint`
- `justrdp/src/tls.rs` — `extract_subject_public_key`, `TlsCertError`
- `justrdp-tokio/src/lib.rs` — `Transport`, the `Action::StartTls` arm
- Stage string: `tls-handshake`

## Reference behaviour

**None.** No verified external-fact store exists. Worth noting what that costs
*here* specifically: whether other clients accept a given enterprise-CA chain is a
behavioural question no spec section answers, and it is unrecorded.

## Cross-cutting invariants

**None.**

- **`extract_subject_public_key` carries a no-panic property and a fuzz target since
  #241** — the first of either in `justrdp`. It parses a server certificate at three live call
  sites (the TLS leaf, the licensing `X509Chain` leaf, and the adapter's TOFU pin comparison),
  and the census that names what must carry them was scoped to `crates/justrdp-pdu/src`, so it
  was invisible **by construction**. No defect: the parse is `x509_cert::Certificate::from_der`,
  a leaf dependency, and 500k probes found zero panics before the artifacts existed. What the
  work fixed is that the census can see the path.
- **The property's generator mutates a real certificate rather than emitting random bytes**, and
  that distinction is asserted rather than assumed: undirected buffers bounce off the outer DER
  tag, while 355 of 512 single-byte mutants still reach a successful extraction. A separate test
  pins that number, so a future change that makes every mutant bounce goes red instead of leaving
  a green property asserting the tag.

## Blast radius

- [NLA / CredSSP authentication](nla-credssp.md) — consumes the extracted public
  key; a change to what `extract_subject_public_key` returns breaks the binding.
- [X.224 negotiation](x224-negotiation.md) — decides whether this runs at all and
  under which protocol.
- [Adapter drive loop](adapter-drive-loop.md) — owns the `Transport` switch from
  plaintext to TLS stream, so every later write goes through code this territory
  changed.
- [Supply chain & gates](supply-chain-and-gates.md) — the provider choice (`ring`)
  and `rustls-platform-verifier` are pinned dependencies with a build-time
  consequence on Windows.

## Known holes / open

- **CRL / OCSP revocation is deliberately out of scope** (ADR-0005, plan.md open
  question 7) — a certificate revoked after issuance is accepted.
- **RD Gateway certificates** are out of scope in the same record (epic #23).
- **Pin-store schema versioning** is unspecified: `FilePinStore` writes a format
  nothing versions, so a later format change has no migration path.
- This is a **sacred path** in
  [`docs/agents/thegraph.md`](../../agents/thegraph.md), so `verify`'s guard fires on
  it unconditionally — a wrong trust decision
  produces a working session and no error anywhere.
