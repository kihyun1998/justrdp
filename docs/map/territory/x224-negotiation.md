# X.224 negotiation & security selection

## What it is

The first protocol exchange after the TCP socket opens: the client sends an X.224
Connection Request carrying an RDP Negotiation Request (requested security
protocols, plus the optional cookie / routing token), and the server answers with a
Connection Confirm carrying either a Negotiation Response (the *selected* protocol
— TLS, HYBRID, HYBRID_EX) or a Negotiation Failure code. Everything downstream —
which transport wraps the socket, whether NLA runs at all, whether an Early User
Authorization Result PDU arrives — is decided here, by one byte the server picks.

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
  the handshake belongs to the adapter (plan.md §3, decision 10).

## Code

- `justrdp-pdu/src/nego.rs` — `NegRequest`, `NegResponse`, `NegFailureCode`,
  `SecurityProtocol`
- `justrdp-pdu/src/x224.rs` — `encode_connection_request`,
  `decode_connection_confirm`, `encode_data`, `decode_data`
- `justrdp/src/connect.rs` — `ConnectStateMachine`, `Stage`, `Action::StartTls`,
  `decode_confirm`
- Stage strings: `tcp-connect`, `x224-negotiate`

## Reference behaviour

**None.** This repo keeps no verified external-fact store (see the hub's *what the
map cannot answer*), so no FreeRDP / IronRDP behaviour is recorded here with a
pinned citation. The modules cite `[MS-RDPBCGR]` section numbers inline, which is a
*spec* pin — the implementation comparison this project's tie-breaker table relies
on has never been written down for this territory.

## Cross-cutting invariants

**None.**

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
