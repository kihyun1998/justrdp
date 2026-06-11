# 0005 — TLS server trust: chain validation by default via the OS trust store, TOFU and accept-any as explicit opt-ins

- Status: Accepted
- Date: 2026-06-11
- Closes the plan.md §22 "(a) chain vs (b) TOFU" question tracked by issue #36

## Context

slice-2 (#2) shipped a deliberately permissive TLS verifier — `AcceptAnyServerCert` trusted every certificate so the connect sequence could be built before validation existed. That left a MITM hole on the production path, tracked as a ship-blocker by issue #36 lest it become a documented-but-unenforced requirement (the plan.md §0 failure mode).

plan.md §22 offered two validation options: (a) chain-of-trust, recommended for multi-server deployments, and (b) TOFU pinning, recommended for the single-server PoC target. Both have real constituencies among RDP deployments: enterprise fleets have CA-issued certificates; standalone hosts (like our test VM) present self-signed ones that no chain can validate.

## Decision

Implement **both**, expose the choice as a public `TrustPolicy` on the adapter's `ConnectOptions`, and make **chain validation the default**:

1. **`Chain` (default)** — chain + SAN/hostname validation against the host *as the caller dialed it* (the `ServerAddr` name #43 threaded to TLS SNI), via the **operating-system trust store** (`rustls-platform-verifier`), not `webpki-roots`: real RDP server certificates are overwhelmingly issued by enterprise/AD CAs that live in the OS store and would all be rejected by a Mozilla-roots-only verifier.
2. **`Tofu(Arc<dyn PinStore>)`** — per-host pinning of the certificate's inner `subjectPublicKey` (the same material CredSSP's `pubKeyAuth` binds to, extracted by the same function). First use stores; a changed key fails the handshake naming the host and both SHA-256 fingerprints and never overwrites the pin. The store is a trait (host-owned persistence); `MemoryPinStore` and a minimal `FilePinStore` ship in the adapter. Unlike accept-any, TOFU really verifies handshake signatures — a pin is only meaningful if the peer proves possession of the key.
3. **`DangerAcceptAny`** — the slice-2 behavior, danger-named, reachable only by explicit construction, never via `Default`. A CI test asserts the default policy is chain validation (the "cannot silently ship" guard #36 demanded).

Trust failures of every policy surface as the existing typed `ConnectFailure::TlsHandshake` during the `tls-handshake` stage — the connect never reaches NLA, so credentials are never offered to an unauthenticated peer.

## Consequences

- The default-constructed connect is safe but **strict**: self-signed servers (labs, fresh VMs) no longer connect out of the box; callers choose TOFU or the danger policy deliberately. Mock-server and real-VM tests opt in at the test site rather than weakening the default.
- The trust decision is the host's, the enforcement is ours: interactive allow-once/allow-always UX stays out of the library (hosts get the typed error plus `pin_fingerprint` to build it).
- Out of scope, deliberately: CRL/OCSP revocation (plan.md open question 7), RD Gateway certificates (epic #23), and pin-store schema/profile integration beyond the minimal trait.
- `rustls-platform-verifier` joins the ADR-0002 dependency set as a leaf, security-critical, non-RDP crate on the rustls side of the boundary (OS bindings: `windows-sys` / Security.framework / JNI — no aws-lc, no new crypto).
