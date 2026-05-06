# CredSSP mechanism is not abstracted behind a trait

## Status

`accepted` (2026-05-06, roadmap §5.2 / §9.6 reflecting current code state).

## Decision

`justrdp-connector::CredsspSequence` is **NTLM-locked** by design — it imports
`justrdp_pdu::ntlm::*` directly, stores raw username/password/domain, and
runs the SPNEGO+NTLM exchange inline. Kerberos lives in a *parallel*
`KerberosSequence` and is consumed through a **separate driver
implementation**, not by plugging a `dyn GssProvider` into a single
mechanism-agnostic CredSSP sequence. There is intentionally no
`GssProvider` / `GssMechanism` trait at this layer.

The seam between mechanisms is the **`CredsspDriver`** trait
(`justrdp-async`): one driver per mechanism family. `NativeCredsspDriver`
in `justrdp-tokio` is the NTLM driver; a future Kerberos driver will be
its own `impl CredsspDriver<…>` against platform GSS APIs (Windows SSPI /
libkrb5 / MIT GSS-API).

## Why

- **Spec coupling, not interface friction.** MS-CSSP §3.1.5 defines the
  CredSSP exchange in terms of SPNEGO+NTLM tokens at specific steps. The
  ~1.4 KLOC inside `CredsspSequence::step` is *the protocol* — pulling a
  `GssProvider` trait through it would not shorten or simplify the
  implementation; it would add a layer of indirection that every reader
  has to chase to verify against the spec.
- **One adapter = hypothetical seam.** Today there is a single live
  driver (`NativeCredsspDriver`, NTLM). The two-adapter rule (see
  LANGUAGE.md) is not satisfied. A trait sized for one implementation
  invariably mis-shapes the second one when it arrives.
- **Platform-native Kerberos isn't a peer of in-tree NTLM.** A real
  Kerberos driver depends on platform GSS APIs (SSPI / libkrb5) whose
  surface is utterly different from `justrdp-pdu::ntlm` (no AS/TGS
  exchange exposed to us; the OS owns the credential cache). Forcing
  both behind a shared `produce_token / consume_token` trait would
  flatten the parts that matter — credential acquisition, ticket
  caching, mech selection — into a lowest-common-denominator surface.
- **PKINIT already has the right seam.** The smartcard side *does*
  have a trait (`SmartcardProvider` in `justrdp-pkinit-card`), because
  there the seam is genuinely "swap the source of a SHA-256 signature"
  — small, well-defined, with mock + PC/SC adapters as a real two-impl
  pair. That confirms we know how to pull a trait out *when the seam is
  real*; this ADR records why the mechanism layer is not such a seam.

## Considered options

- **(A) `CredsspSequence` stays NTLM-bound; mechanisms split at the
  `CredsspDriver` layer** ⭐ accepted — this ADR. Each driver owns its
  own protocol logic, calling into platform APIs as needed.
- **(B) `GssProvider` trait inside `CredsspSequence`** — Kerberos and
  NTLM both implement `produce_initial_token / consume_token /
  produce_response`. Rejected: (i) one adapter today; (ii) Kerberos
  ticket lifecycle does not fit a token-pump shape (needs platform
  credential cache); (iii) duplicates the SPNEGO mech-selection logic
  that already lives in `credssp::spnego`.
- **(C) `KerberosSequence` becomes a `CredsspSequence` constructor
  variant** — single sequence type with a mode enum. Rejected: would
  bloat `CredsspSequence::step` to ~3 KLOC of branchy code, and
  Kerberos's AS-REQ/TGS-REQ flow has no NTLM-like challenge/response
  shape to share.

## Consequences

- `CredsspSequence` is allowed to import `justrdp_pdu::ntlm::*`
  directly. Reviewers should not flag this as a layering violation.
- `KerberosSequence` is correctly held as **infrastructure-without-driver**:
  the PDU-level state machine exists (used by §5.2 / §9.6 for
  test-vector verification and PKINIT AS-REQ construction), but is not
  wired into `connector.rs`. This is intentional — wiring it up means
  writing a Kerberos `CredsspDriver`, not changing the connector.
- A future Kerberos driver lives next to `NativeCredsspDriver` as
  `NativeKerberosCredsspDriver` (or similar) and is selected by the
  embedder, not by a runtime trait dispatch.
- `SmartcardProvider` in `justrdp-pkinit-card` is the *correct* trait
  shape because it sits at a different layer (signature source for
  PKINIT AS-REQ) and has two real adapters (Mock + PC/SC). Do not
  unify it with this ADR.
- When a PR proposes "let's pull a `GssProvider` / `GssMechanism` trait
  through `CredsspSequence`", point to this ADR.
