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

[ADR-0020](../../adr/0020-standard-rdp-security-when-the-host-opts-in.md) decides that Standard RDP
Security is selectable, and only by a host that opted in. No ADR is about the rest of this exchange.

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
  Without it, a request carrying `SSL` (the default `SSL|HYBRID|HYBRID_EX`) advertises a protocol
  the client cannot complete; xrdp selects `SSL` from that request. That the path exists is the
  maintainer's call (2026-10-16), made over keeping NLA mandatory and dropping `SSL` from the
  default request, or deferring both. The test VM refuses a TLS-only connect
  (`HYBRID_REQUIRED_BY_SERVER`); xrdp and the Windows Server 2008 R2 VM accept one (#484).
- **Standard RDP Security is a path of its own, off unless the host opts in** (ADR-0020, #599).
  `ConnectConfig::standard_security` carries the client random and requires an empty `requested`,
  because `PROTOCOL_RDP` is 0 and cannot join a set. A selection of 0 from any other host stays
  refused. The selection leads straight to the Connect-Initial on the plain socket, and the security
  exchange happens after the channel join (`justrdp_security::standard`, [licensing](licensing.md)).
- **The request is checked twice against a downgrade.** The Connection Request and Confirm are
  plaintext, so an attacker can strip `HYBRID` from the request and a server that allows TLS-only
  then selects `SSL` honestly. Two checks stand against it. `SSL` is honoured only when the host
  requested it. And the Server Core Data's `clientRequestedProtocols`, which travels inside TLS,
  must equal the request sent (`[MS-RDPBCGR]` 3.2.5.3.4, a SHOULD taken as a MUST on ADR-0009's
  strict side); otherwise the connect fails with `ConnectError::RequestedProtocolsMismatch`.
  An absent echo counts as `PROTOCOL_RDP`. Every measured server echoes the request:
  xrdp 0.9.24 sent `0x0B` for justrdp's `0x0B` (a capture on 2026-10-16), and the WS2019 and
  Windows Server 2008 R2 VMs' connects reach session-active. The 2008 R2 VM selects `HYBRID`
  from `0x0B`, since it predates HYBRID_EX (#484).
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
  `decode_confirm`, `Action::ServerCertificate`, `ConnectStateMachine::take_standard_security`
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
(master). `ironrdp-pdu` 0.11 decodes the field (`CorrelationInfo::read` in its `nego.rs`), and no
differential test feeds it these bytes. The refusal of 0x00 / 0xF4 / 0x0D
rests on FreeRDP's server (`nego_process_correlation_info`, `libfreerdp/core/nego.c` at
`18513805`), which fails the request on each, not on anything this VM does. Whether the VM
records the id is not observed: nothing here reads its event log.

**Standard RDP Security on Windows Server 2019** (#599, 2026-11-06), `SecurityLayer=0`,
`UserAuthentication=0`, requested `0x0`, offering 40, 56 and 128 bits. The server selects `0x0`, then:

| `MinEncryptionLevel` | Selected | Result |
|---|---|---|
| 1 Low | method 2, level 1 | logon screen, 1131 frames |
| 2 Client Compatible | method 2, level 2 | logon screen, 1124 frames |
| 3 High | method 2, level 3 | logon screen, 1121 frames |
| 4 FIPS | none | connection reset after the Connect-Initial |

At level 2 a session is usable (#600): a password typed fast-path at the logon screen logs on, the
clipboard channel answers a Format List, and a console and pointer sweep reach 4284 PDUs sent and
6152 received, past a key update each way, with no MAC failure on either side. An earlier run reached
221,422 received. Whether Salted MAC appeared is not recorded: the default capabilities do not
advertise it.

With FIPS offered too at level 4, the server selects it and the core refuses it by value. 40 and 56
bits were never selected, so they rest on the FreeRDP vectors alone. With `SecurityLayer=2` the same
request is answered `HYBRID_REQUIRED_BY_SERVER`. One server.

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
- **Where the echo check could refuse a server that is not hostile, unmeasured.** A TLS-capable
  server that omits `clientRequestedProtocols` reads as `PROTOCOL_RDP` and fails, and so does a
  TLS-terminating proxy that negotiates with the backend on its own and forwards the backend's
  GCC. Neither has been seen; the two measured servers echo the request.
