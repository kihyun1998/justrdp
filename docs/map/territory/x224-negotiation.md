# X.224 negotiation & security selection

## What it is

The first protocol exchange after the TCP socket opens: the client sends an X.224
Connection Request carrying an RDP Negotiation Request (requested security
protocols), optionally followed by a correlation id (#441), and the server answers with a
Connection Confirm carrying either a Negotiation Response (the *selected* protocol
— TLS, HYBRID, HYBRID_EX) or a Negotiation Failure code. Everything downstream —
which transport wraps the socket, whether NLA runs at all, whether an Early User
Authorization Result PDU arrives — is decided here, by one byte the server picks. The
request's other optional fields, a load-balancing cookie or routing token, are not sent; they
belong to server redirection (#24).

## Governing decisions

**None.** No ADR is about this exchange.

Adjacent but not governing: [ADR-0001](../../adr/0001-sans-io-state-machine-core.md)
decides that this runs as a pure state transition rather than inline in a socket
loop — that is *where the code lives*, not what the negotiation does.
[ADR-0009](../../adr/0009-tolerant-negotiation-posture.md) governs tolerance of
server self-inconsistency in **rendering** capabilities and explicitly stays strict
on security integrity, so it constrains what this territory may *forgive* without
deciding the exchange itself.

## Design model

- The selected protocol is a **fact the server owns**; the client requests a set and
  must accept the answer or abort. Downgrade is not silently absorbed — a security
  protocol weaker than requested is a security-integrity question, which
  ADR-0009 places on the strict side of its split.
- The negotiation result **fans out into three later territories** and is the reason
  they are separate: `PROTOCOL_SSL` → TLS only; `HYBRID` → TLS + CredSSP;
  `HYBRID_EX` → TLS + CredSSP + a 4-byte Early User Authorization Result read by
  the adapter before the MCS phase.
- The machine emits `Action::StartTls { selected }` and never sees a TLS record —
  the handshake belongs to the adapter (ADR-0002; [TLS transport security](tls-transport-security.md)).
- **TLS-only security is a path of its own** (#474). When the server selects `PROTOCOL_SSL`,
  `Event::TlsEstablished` leads straight to the MCS Connect-Initial: no CredSSP, no Early User
  Authorization Result, and the certificate is not parsed, since only CredSSP binds to its key.
  Until #474 the machine asked for NLA after every TLS handshake, so the default request
  (`SSL|HYBRID|HYBRID_EX`) advertised a protocol it could not complete. That was the scope set on
  2026-06-08 (a modern Windows Server with NLA enforced; the test VM refuses a TLS-only connect
  with `HYBRID_REQUIRED_BY_SERVER`). xrdp selects `SSL` from that request and got a CredSSP
  exchange it does not speak. Building the path was the maintainer's call (2026-10-16), over
  keeping NLA mandatory and dropping `SSL` from the default request, or deferring both.
  `SSL` is honoured only when the host requested it, so a host that asks for NLA alone is never
  downgraded. Standard RDP Security (RC4) is not supported at all.
- **A correlation id is the host's, and the flag and the structure travel together** (#441).
  `ConnectConfig::correlation_id` puts a 16-byte id in an `RDP_NEG_CORRELATION_INFO` after the
  request (2.2.1.1.2), which a server or broker records for diagnostics. 2.2.1.1 makes
  `CORRELATION_INFO_PRESENT` and the structure a pair, so `NegRequest::encode` sets the flag from
  the id and clears it without one, whatever `flags` holds. The ids 2.2.1.1.2 says SHOULD NOT be
  sent (a first byte of 0x00 or 0xF4, or any 0x0D byte) are refused by `advertise::check`: the
  spec only advises against them, but FreeRDP's server fails a Connection Request carrying one.
  The same id is meant to reach RD Gateway and UDP transports (#23, #16).

## Code

- `justrdp-pdu/src/nego.rs` — `NegRequest`, `NegResponse`, `NegFailureCode`,
  `SecurityProtocol`, `CORRELATION_INFO_PRESENT` (#441)
- `justrdp/src/advertise.rs` — `ConnectConfigError::CorrelationId` (#441)
- `justrdp-pdu/src/x224.rs` — `encode_connection_request`,
  `decode_connection_confirm`, `encode_data`, `decode_data`
- `justrdp/src/connect.rs` — `ConnectStateMachine`, `Stage`, `Action::StartTls`,
  `decode_confirm`
- Stage strings: `tcp-connect`, `x224-negotiate`

## Reference behaviour

**Measured on the test VM** (#429, 2026-10-12): justrdp requests `0xb` (SSL | HYBRID | HYBRID_EX)
and the server selects `0x8` (HYBRID_EX), on 5 of 5 connects; both are recorded as `rdp_x224`
(`step="request"`, `step="selected"`) and asserted in order by
`connect_reaches_session_active_against_real_vm`. One WS2019 box.

**Correlation info: this VM accepts it, and checks none of it** (#441, 2026-10-13). A request
carrying a spec-valid `RDP_NEG_CORRELATION_INFO` reaches session-active and paints the desktop
(`a_correlation_id_in_the_connection_request_is_accepted_by_the_real_vm`). So did three malformed
ones, each tried once by mutating the encoder: a length of 0x23, the flag with no structure after
it, and an id starting with 0x0D. That test therefore proves the server tolerates the field, not
that the encoding is right; the bytes rest on 2.2.1.1.2 and agree with IronRDP's `CorrelationInfo`
(master). The pinned `ironrdp-pdu` 0.9.0 oracle cannot check them: its `ConnectionRequest`
decoder refuses any request with `CORRELATION_INFO_PRESENT` (a `TODO(#111)` in its `nego.rs`). The refusal of 0x00 / 0xF4 / 0x0D
rests on FreeRDP's server (`nego_process_correlation_info`, `libfreerdp/core/nego.c` at
`18513805`), which fails the request on each, not on anything this VM does. Whether the VM
records the id is not observed: nothing here reads its event log.

**No implementation comparison for the security selection.** This repo keeps no verified
external-fact store (see the hub's *what the map cannot answer*), so apart from the correlation
info above, no FreeRDP / IronRDP behaviour is recorded here with a pinned citation. The modules cite `[MS-RDPBCGR]` section numbers inline, which is a
*spec* pin — the implementation comparison this project's tie-breaker table relies
on has never been written down for this territory.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — `x224` and `nego` carry both artifacts since #200. The edge is drawn by #237 because it was
  missing, not because anything here is uncovered — this section read **None.** while the
  territory parsed the connect sequence's first server bytes.

## Blast radius

- [TLS transport security & trust](tls-transport-security.md) — the selected
  protocol decides whether the TLS stream is the end of the story or the carrier
  for CredSSP.
- [NLA / CredSSP authentication](nla-credssp.md) — runs only for `HYBRID` /
  `HYBRID_EX`, and `HYBRID_EX` adds the Early User Authorization read.
- [Adapter drive loop](adapter-drive-loop.md) — a new `Action` variant or a changed
  stage name is a change to the adapter's match arms and to its per-stage timeout
  map.
- [PDU constants & flag tables](pdu-constants.md) — the protocol bits are constants
  there, and a wrong bit fails the connection silently rather than loudly.

## Known holes / open

- **No governing record**, per the sentinel above: the strict/tolerant line for a
  *security* downgrade is stated in ADR-0009 only as the side it is not on.
- RD Gateway (epic #23) changes what "the socket" is before this exchange happens;
  nothing here anticipates it.
