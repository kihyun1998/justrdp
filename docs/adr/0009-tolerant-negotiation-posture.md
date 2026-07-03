# 0009 — Negotiation posture: tolerant of server self-inconsistency in rendering, strict on security integrity

- Status: Accepted
- Date: 2026-07-03
- Closes issue #101

## Context

Real RDP servers advertise capability and drawing-order sets they then violate, and misreport their own version (RDP 5.0–8.1 all report build "4"). The two mature reference clients sit at **opposite default postures**, which is itself the evidence that this needs a deliberate decision:

- **FreeRDP defaults strict, with an opt-in escape hatch.** An unadvertised order hits `check_order_activated` (`libfreerdp/core/orders.c:271`), which returns `FALSE` — a hard parse failure that aborts the connection — logging *"SERVER BUG: … not announced! Use /relax-order-checks to ignore"*. The `/relax-order-checks` flag (`client/common/cmdline.c:4982` → `FreeRDP_AllowUnanouncedOrdersFromServer`) downgrades the error to a warning-and-accept, but it defaults **OFF**. So a spec-literal FreeRDP drops otherwise-healthy sessions against xrdp / Server 2008 R2 unless the user opts out (issue #7216).
- **IronRDP defaults tolerant by construction** — it performs *no* cross-check of server updates against advertised capabilities. Unsupported/unadvertised orders and codecs are `warn!`-ed and skipped, the session continues (`ironrdp-session active_stage.rs:411` for MS-RDPEGDI orders; `fast_path.rs:479/528` for surface codecs). There is no relax knob because nothing is ever enforced. But this tolerance is **unbounded and silent**: `fast_path.rs:168` even swallows a malformed fast-path update's `InvalidField` decode error into `UpdateKind::None`, with a code comment admitting the "fragile logic … rationale not obvious".

Both are, notably, **tolerant on version misreporting**: FreeRDP takes `MIN(server, client)` and accepts even an unknown version (logged, not aborted — `libfreerdp/core/gcc.c:210`); IronRDP does no version gating on the graphics path.

justrdp already applies a **split posture** in code, without having named the principle:

- **Strict** where a mismatch is a security/integrity threat: the connect machine rejects a server that selects a security protocol we never advertised (`connect.rs`), rejects Standard RDP Security, rejects an unsolicited Channel Join Confirm, and the DVC layer rejects a compressed chunk when compression was never advertised (`dvc.rs`).
- **Tolerant** where a mismatch is a rendering-feature divergence: the ClearCodec decoder keeps real-server leniencies the spec and the ironrdp oracle reject (over-region RLEX clip, NSCodec subcodec) because the captured WS2022 corpus requires them (ADR-0007 amendment, #120/#121/#127).
- **Not yet exercised** for drawing orders — order decode is epic #22, so the advertised-but-violated-order problem has not bitten us yet. This ADR sets the posture *before* it does.

This mirrors the project's stated identity (`CLAUDE.md`): *derivation from the normative spec, proof from the oracle/real VM* — "스펙 ≠ 상호운용". We already accept that real servers diverge from spec; the open question is only where the tolerance lives and how it is bounded. justrdp takes **IronRDP's default-tolerant stance on rendering, but with the two bounds IronRDP lacks** (still-validate-the-bytes, always-observable) — neither FreeRDP's disconnect-by-default nor IronRDP's silent, unbounded swallow.

## Decision

Be **tolerant by default of a server's self-inconsistency in rendering features, and strict on security/protocol integrity.** The dividing line is the threat model, not the spec letter:

1. **Strict — reject — where a violation is an attack vector.** Protocol downgrade (an unadvertised or weaker security protocol), injection that breaks the connect/session state machine (unsolicited or out-of-order security-relevant PDUs), and unannounced compression/encoding that could smuggle bytes. These reject today; they keep rejecting. Trust failures and negotiation violations stay typed errors on their stage.

2. **Tolerant — accept-and-log — where a violation is a rendering-feature self-inconsistency.** A drawing order absent from the server's Order Capability Set, a capability the server under- or over-advertises, a misreported version. Do not drop the session: decode what actually arrives and continue.

3. **Leniency lives at the point of use, bounded by three invariants:**
   - **(a) The bytes are still fully validated.** Tolerance is about *which features are allowed to appear*, never about trusting their contents: bounds checks, typed errors, and the ADR-0008 no-panic contract hold unconditionally. A tolerated order with a malformed body is still a typed error, never an OOB or panic.
   - **(b) Every tolerance is observable.** Each accepted divergence is logged via `tracing` (a `rdp_interop`-targeted debug/warn record naming the advertised-vs-seen mismatch). Silent masking is forbidden — a tolerance you cannot see is indistinguishable from a bug.
   - **(c) Security integrity always wins.** Rule 1 is never relaxed by rule 2; no rendering-tolerance path can accept a downgrade or an injection.

4. **Tolerant is the default with no opt-out knob (initially).** Unlike FreeRDP's opt-in `/relax-order-checks`, justrdp treats tolerance as the *correct* behavior for rendering self-inconsistency, not a workaround — so there is no strict mode to select. A future `observe`/strict mode (surfacing divergences as errors for security research or conformance testing) may be added if a use case needs it, but is out of scope here.

## Consequences

- **The two cross-cutting hard-spots #101 lists are strict-side mechanism, not posture questions — and verification (before this ADR) shows both are already handled, so nothing is split out.** FreeRDP and IronRDP converge *exactly* on both (unlike the order-posture split above), confirming they are pure mechanism, not a decision — and justrdp already implements them the same way:
  - **HYBRID_EX Early User Authorization Result PDU** — already implemented and tested. The core reads it **only when HYBRID_EX is the *selected* protocol** (`connect.rs:495` → `Stage::EarlyUserAuth` / `Action::AwaitEarlyUserAuth`), as an unframed fixed 4-byte AUTHZ code (`AUTHZ_SUCCESS = 0x0000_0000`, `connect.rs:1173`; nonzero → `ConnectError::EarlyUserAuthDenied`), with the adapter's exact-4-byte read at `justrdp-tokio lib.rs:514`. Five unit tests cover granted / denied / unrecognized-or-truncated / HYBRID_EX-gating / unexpected-substage (`connect.rs:1445–2071`), and the real-VM connect exercises the live path (it requests `SSL|HYBRID|HYBRID_EX` and reaches session-active). This matches FreeRDP (`nego.c:314`/`nla.c:2189`) and IronRDP (`credssp.rs:220`) exactly.
  - **CredSSP version + public-key binding hash (CVE-2018-0886)** — owned by the `sspi` crate behind the **ADR-0002/0004 delegation boundary**, exactly as IronRDP does it (IronRDP implements none of this either — it delegates to the same `sspi-rs`: v6 client, 32-byte nonce, `check_peer_version` lock, `<5` echo / `>=5` SHA-256 binding hash with direction-specific magic strings). Our adapter drives `CredSspClient` (`justrdp-tokio lib.rs:27`); the connector's only obligation — reaching a completed CredSSP exchange with the negotiated version — is proven by the real-VM session-active round-trip. No justrdp-side work remains.

  So #101's "related hard-spots" were **stale** — both were solved before this ADR was written. This ADR records only the negotiation *posture*; no follow-up implementation issues are filed for them.
- **Order decode (#22) is built tolerant from day one** — accept-and-log unannounced orders rather than adding strictness later and then relaxing it.
- **Generalizes the ADR-0007 codec-tolerance precedent** from the codec layer to the negotiation layer: the corpus-required leniencies were the first instance of this principle; ADR-0009 names it.
- **Risk: tolerance can mask a bug in our own decoder as "server inconsistency."** Mitigated by invariant (b) — every tolerance is logged — and by the differential/corpus tests that still assert byte-identity wherever an oracle or a captured stream exists. Tolerance widens *what we accept*, never *what we stop verifying*.
