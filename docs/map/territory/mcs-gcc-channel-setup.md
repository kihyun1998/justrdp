# MCS / GCC channel setup

## What it is

The multiplexing layer underneath every later RDP message: the client packs its
GCC Conference Create Request blocks (core, security, network/channel list, and —
on the way — cluster/monitor data) into an MCS Connect-Initial, the server answers
with a Connect-Response carrying the joined channel IDs, and the client then runs
Erect Domain → Attach User → Channel Join for each channel. After this, everything
travels as MCS Send Data on a channel ID.

**This is where the flag that motivated the whole project lives.**
`ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL` (`0x0100`) — the bit
`ironrdp-connector` 0.9.0 omits, gating EGFX — is a GCC client-core-data field, set
here, long before any graphics capability is negotiated.

## Governing decisions

**None.** No ADR is about channel setup.

Adjacent but not governing: [ADR-0001](../../adr/0001-sans-io-state-machine-core.md)
places the sequence in a state machine; `CLAUDE.md`'s identity statement ("the host
holds every RDP feature flag") is the *reason* the early-capability flags are
exposed rather than curated, but it is an identity claim, not a decision record.

## Design model

- **Channel IDs are server-assigned and must be carried, not recomputed.** The
  Connect-Response's channel-ID list is the authority for the rest of the
  connection; a static channel the client asked for may be absent.
- **The GCC blocks are the client's whole self-description** — desktop size, colour
  depth, keyboard layout, client name, connection type, early capability flags. Most
  later behaviour that "cannot be turned on" traces back to one bit here rather than
  to a capability set.
- Encoding is BER (Connect-Initial/Response) over PER (the GCC blocks); both are
  hand-rolled in `justrdp-pdu` with no external ASN.1 dependency.
- The `sm-user` / `sm-test` stage strings mark the Attach-User and channel-join
  round-trips within the state machine.

## Code

- `justrdp-pdu/src/gcc.rs` — `ClientCoreData`, `ClientEarlyCapabilityFlags`
  (incl. `SUPPORT_DYN_VC_GFX_PROTOCOL`), `ClientNetworkData`, `ClientSecurityData`,
  `ChannelDef`, `ServerCoreData`, `ConferenceCreateResponse`
- `justrdp-pdu/src/mcs.rs` — `ConnectResponse`, `AttachUserConfirm`,
  `ChannelJoinConfirm`, `DomainParameters`, `SendDataIndication`,
  `encode_attach_user_request`, `decode_connect_response`
- `justrdp-pdu/src/ber.rs`, `justrdp-pdu/src/per.rs` — the two encodings
- `justrdp/src/connect.rs` — `McsConnectResult`, `StaticChannel`, `decode_mcs_frame`
- Stage strings: `sm-user`, `sm-test`, and the MCS half of `capability-exchange`

## Reference behaviour

**None.** No verified external-fact store. The tolerance questions here (a server
that omits a requested channel, an unexpected join order) are exactly the class
ADR-0009 says is spec-unwritten and lives in FreeRDP's source — and none of it is
recorded.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — `gcc` and `mcs` carry both artifacts since #203, and `ber` / `per` are the recorded
  exception (primitives; their callers are covered). The edge is drawn by #237 because it was
  missing, not because anything here is uncovered — this section read **None.** while the
  territory parsed the whole Connect-Response.

## Blast radius

- [Capability exchange & activation](capability-exchange-activation.md) — runs on
  the channel this phase joined; an early-capability flag set here changes which
  capability sets are meaningful there.
- [Virtual channels](virtual-channels.md) — static channel IDs come from here, and
  the DVC channel (`drdynvc`) is one of them.
- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — reachable **only** if
  `SUPPORT_DYN_VC_GFX_PROTOCOL` was set in this phase.
- [PDU constants & flag tables](pdu-constants.md) — the early-capability bits and
  channel-option flags live there.
- [Wire framing primitives](wire-framing.md) — BER/PER readers are the substrate.

## Known holes / open

- **No governing record** for the flag-exposure posture, although it is the
  project's founding motivation — it exists as identity prose in `CLAUDE.md` and
  `CONTEXT.md` §Project intent, and as a deliberate-divergence row in
  [`docs/agents/theflow.md`](../../agents/theflow.md).
- Multi-monitor and DPI (epic #27) add GCC monitor data that is not built.
- `SUPPORT_SKIP_CHANNELJOIN` is defined as a constant; whether the client honours
  the skip path is not recorded anywhere.
