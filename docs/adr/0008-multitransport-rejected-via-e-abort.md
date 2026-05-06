# Server multitransport offers are rejected via E_ABORT

## Status

`accepted` (2026-05-06, roadmap §10.2 / §10.3 reflecting current code state).

## Decision

`justrdp-connector::ClientConnector::step_multitransport_bootstrapping`
responds to every server `InitiateMultitransportRequest`
(MS-RDPBCGR §2.2.15.1) with
`MultitransportResponse { hr_response: HRESULT_E_ABORT }` (0x80004004),
on both UDPFECR and UDPFECL request types. The client never accepts a
UDP side-channel offer; every session stays on TCP for its entire
lifetime. This is **spec-permitted**: MS-RDPBCGR §1.3.1.1 explicitly
allows a client to refuse multitransport even when the server
advertised `SOFTSYNC_TCP_TO_UDP`, and §2.2.15.2 defines `E_ABORT` as a
valid `hrResponse`.

The decision is **not** "we have not gotten around to it." Every
sub-component of the UDP path is implemented and independently tested.
The decision is "the integration glue is intentionally deferred until
it has a concrete adopter," and this ADR records what `[ ]` entries in
the roadmap do not capture.

## Why

- **Building blocks ready, integration deferred.** The pieces below
  are all `[x]` in the roadmap and have unit / roundtrip / loopback
  coverage:
  - `justrdp-rdpeudp::v1` — MS-RDPEUDP §2.2 SYN / SYN+ACK / ACK +
    AckVector + FEC headers
  - `justrdp-rdpeudp::v2` — MS-RDPEUDP2 §2.2 packed headers,
    AckOfAcks, DataBody
  - `justrdp-rdpeudp::session` — reliable-mode reorder buffer, FEC
    encode/decode, single-loss recovery
  - `justrdp-rdpeudp::dtls_handshake` + `dtls_session` — DTLS 1.0 /
    1.2 client handshake (HelloVerifyRequest cookie, ServerHello,
    SPKI extraction, ChangeCipherSpec, Finished verify), record-layer
    encrypt / decrypt with replay rejection
  - `justrdp-rdpeudp::socket` — `std::net::UdpSocket` adapter with a
    complete SYN / SYN+ACK / ACK handshake and end-to-end loopback
    test
  - `justrdp-pdu::rdpemt` — `TunnelCreateRequest` /
    `TunnelCreateResponse` (MS-RDPEMT §2.2.2)
  - `justrdp-dvc::drdynvc` — Soft-Sync routing tables
    (`notify_tunnels_ready`, `channel_to_tunnel`, `available_tunnels`,
    `outbound_tunnels`); covered by ≥5 soft-sync tests including
    partial-availability, duplicate-channel rejection, and accumulating
    second-request semantics

  The gap is at the **connector layer**: nothing wires these
  components together when a `MultitransportRequest` arrives.

- **Integration is multi-commit, not a small step.** Flipping to
  `S_OK` is not a one-line change. It commits the connector to:
  spawning a `UdpSocket` (no async UDP exists in `justrdp-async` /
  `justrdp-tokio` today — only the blocking `RdpeudpSocket`), driving
  the RDPEUDP three-way handshake, running DTLS over it, exchanging
  `TunnelCreateRequest` / `Response`, awaiting the DRDYNVC
  `SoftSyncRequest` on the TCP main channel, and calling
  `DrdynvcClient::notify_tunnels_ready` at the right moment. Each
  step adds lifetime / retransmit / timeout decisions that ripple
  back into the connector state machine.

- **TCP-only is production-viable.** MS-RDPBCGR §1.3.1.1 ships RDP
  servers that fall back gracefully when the client refuses
  multitransport. Sessions pay a latency cost on lossy-mode media
  (RDPEA audio, H.264 video) but functionally work. The current
  embedder set — Tauri MVP, browser via `justrdp-web`, RD Gateway
  tunneling — has no UDP available anyway: gateway and WebSocket
  transports are TCP-bound by definition.

- **Locality favors a single integration PR.** Future UDP integration
  touches every layer (connector state machine, blocking + tokio
  embedders, optionally the gateway client). Adding scaffolding
  piecewise ahead of time — cookie persistence, policy hooks,
  embedder configuration knobs — risks dead infrastructure that
  doesn't fit the shape of the real adopter when it arrives. This is
  the same anti-pattern ADR-0007 records for CredSSP mechanism
  abstraction.

## Considered options

- **(A) Hardcoded `E_ABORT`, document the deferral via this ADR**
  ⭐ accepted — current code at
  `justrdp-connector/src/connector.rs::step_multitransport_bootstrapping`.
  Four tests in the same file lock in the behaviour:
  `multitransport_bootstrapping_pass_through` (no message channel
  joined → phase is a no-op),
  `multitransport_request_replied_with_e_abort`,
  `multitransport_demand_active_on_io_channel_skips_phase`,
  `multitransport_two_requests_each_get_e_abort`.
- **(B) Persist `request_id` + `security_cookie` for a future UDP
  setup** — store decoded `InitiateMultitransportRequest` instances on
  `ClientConnector` and expose them via
  `pub fn pending_multitransport_requests()`. Rejected: the cookie
  is operationally valid only until the response is sent. Once the
  client emits `E_ABORT`, the server commits to "this client does
  not honour multitransport" for the session and will not accept the
  same cookie in a later UDP `TunnelCreateRequest`. Storing it
  afterwards is pass-through state with no consumer. The natural
  place for this field is **inside** the future UDP-integration PR,
  next to the code that actually uses it — not pre-emptively.
- **(C) `MultitransportPolicy` trait or callback** — extract the
  hardcoded `E_ABORT` into
  `trait MultitransportPolicy { fn decide(&self, req: &InitiateMultitransportRequest) -> u32; }`
  so a future UDP path can inject `S_OK`. Rejected: one adopter
  today (always-reject), one adopter expected later (full UDP path).
  The two-adopter rule (see LANGUAGE.md / ADR-0007) is not satisfied.
  A trait sized for the always-reject case will mis-shape the second
  implementation when its real shape — owning a `UdpSocket`,
  consulting embedder config, checking transport availability — finally
  arrives.
- **(D) Reply `S_OK` and ignore the cookies** — non-compliant. Server
  expects a UDP `TunnelCreateRequest` echoing the cookie and will
  hang the multitransport setup waiting for it; some servers also
  gate subsequent `Demand Active` on multitransport-readiness flags
  declared during capability exchange.

## Consequences

- `step_multitransport_bootstrapping` is allowed to keep its
  hardcoded `HRESULT_E_ABORT`. Reviewers should not flag this as a
  TODO.
- The roadmap entries marked `[ ]` under §10.2 ("UDP 연결 수립
  (justrdp-blocking 통합)" / "TLS/DTLS 핸드셰이크 (UDP 위)" /
  "TLS over reliable-UDP variant") and §10.3 (Multitransport
  bootstrapping ↔ Soft-Sync wire-up) are correctly scoped — they
  are the multi-commit follow-up that this ADR intentionally defers.
- `DrdynvcClient::notify_tunnels_ready` is correctly held as a
  **public API without an in-tree caller**: the function exists for
  the future UDP integration to call. Reviewers should not flag the
  empty caller graph as dead code.
- `justrdp-rdpeudp::socket::RdpeudpSocket` (blocking) is similarly
  held as a stand-alone adapter without a connector-level
  integration point. Its loopback tests guarantee correctness in
  isolation.
- When a PR proposes "let's add a `MultitransportPolicy` trait" or
  "let's persist multitransport cookies on the connector", point to
  this ADR. The right time to add either is inside the integration
  PR, where they will have a real second adopter (the actual UDP
  path).
- This ADR is `superseded` when the integration PR lands and
  `step_multitransport_bootstrapping` returns `S_OK` for at least
  one transport type. The integration PR should update this file's
  Status to `superseded by ADR-NNNN` and link to the successor.
