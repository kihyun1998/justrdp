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

- [ADR-0017](../../adr/0017-rebuild-so-the-host-holds-every-policy-flag.md) — the founding
  decision: `ironrdp-connector` hardcoding away `SUPPORT_DYN_VC_GFX_PROTOCOL` in this layer's
  early-capability flags is why justrdp exists.
- [ADR-0016](../../adr/0016-policy-flags-are-the-hosts.md) — the early-capability flags are
  policy flags, so they are exposed rather than curated, and the core refuses a bit it cannot
  honour. Which bits, and why, is the table in
  [capability exchange](capability-exchange-activation.md) (#357), which also covers channel
  options and the colour-depth fields (#590).

Adjacent but not governing: [ADR-0001](../../adr/0001-sans-io-state-machine-core.md)
places the sequence in a state machine.

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
- **A Disconnect Provider Ultimatum ends the connect in every stage whose frames carry MCS**
  (#607): the Connect-Response wait, Attach User, channel join, licensing, capability exchange
  and finalization. `on_frame` tests `DisconnectProviderUltimatum::matches` on the MCS payload
  before the stage decodes the PDU it expects, the same pre-test the session loop makes, and
  fails with `ConnectError::ProviderUltimatum { reason }`. The test cannot take a well-formed
  expected PDU for an ultimatum: those open with `0x7F` (the BER `[APPLICATION 102]`
  Connect-Response) or the PER CHOICE bytes `0x2C`–`0x2F` (Attach User Confirm), `0x3C`–`0x3F`
  (Channel Join Confirm) and `0x68`–`0x6B` (Send Data Indication), and the ultimatum opens with
  `0x20`–`0x23`. An ultimatum cut short stays `ConnectError::Decode`, and X.224 negotiation does
  not test for one, since that stage reads a Connection Confirm. The host gets the raw T.125
  reason, not a `DisconnectClass`: `classify_ultimatum` reads reason 3 as a user logoff, which
  does not describe a server refusing a connect.
- **An X.224 Disconnect Request ends the connect in the same six stages** (#631). `on_frame`
  tests `x224::DisconnectRequest::matches` on the TPDU, before the ultimatum test and before the
  stage decodes its Data TPDU, and fails with `ConnectError::DisconnectRequest { reason }`
  carrying the raw X.224 `REASON`. The code octet separates it from everything the stages expect:
  a Data TPDU carries `0xF0` there. A Disconnect Request cut short stays `ConnectError::Decode`,
  as does any other TPDU code. X.224 negotiation tests for one too, in place of the Connection
  Confirm, where X.224 6.6.3 defines it ([X.224 negotiation](x224-negotiation.md)).

## Code

- `justrdp-pdu/src/gcc.rs` — `ClientCoreData`, `ClientEarlyCapabilityFlags`
  (incl. `SUPPORT_DYN_VC_GFX_PROTOCOL`), `ClientNetworkData`, `ClientSecurityData`,
  `ChannelDef`, `ServerCoreData`, `ConferenceCreateResponse`
- `justrdp-pdu/src/mcs.rs` — `ConnectResponse`, `AttachUserConfirm`,
  `ChannelJoinConfirm`, `DomainParameters`, `SendDataIndication`,
  `DisconnectProviderUltimatum`, `encode_attach_user_request`, `decode_connect_response`
- `justrdp-pdu/src/ber.rs`, `justrdp-pdu/src/per.rs` — the two encodings
- `justrdp/src/connect.rs` — `McsConnectResult`, `StaticChannel`, `decode_mcs_frame`,
  `Stage::reads_mcs` (the stages that test for the ultimatum),
  `Stage::reads_disconnect_request` (those and X.224 negotiation, for the X.224 Disconnect Request)
- Stage strings: `sm-user`, `sm-test`, and the MCS half of `capability-exchange`

## Reference behaviour

**Measured on the test VM** (#429, 2026-10-12): the server does not skip the channel join
(`skip_channel_join=false` on every connect), and its Channel Join Confirms arrive in the order
the requests went out: user channel, I/O channel (`1003`), then each static channel. Recorded as
`rdp_mcs` (`step="connect-response"`, `step="attach-user"`) and one `rdp_channel_join` per
confirm, and asserted in order by `connect_reaches_session_active_against_real_vm`. The machine
accepts confirms in any order; this server never exercised that. One WS2019 box.

**What the R3 acceptance checks still catch on `ironrdp-pdu` 0.11** (#587). `justrdp/src/connect.rs`
decodes three of the machine's frames with `ironrdp_pdu::decode` (ADR-0011's R3 role). Reading the
0.9 → 0.11 diff of each decode path found 10 inputs 0.9 refused and 0.11 accepts, and none on the
X.224 Data / MCS Send Data Request path:

| Frame (test) | What 0.11 accepts now | Verdict |
|---|---|---|
| Send Data Request (`client_user_data`, the Standard Security tests) | nothing new; 0.11 is stricter (TPKT length below 7) | still discriminates |
| Connect-Initial (`tls_established_under_ssl_writes_connect_initial_without_nla`, `early_capability_flags_reach_the_connect_initial_verbatim`) | an unknown GCC block type is skipped; `keyboardType` outside 1..7; undefined bits in `serverSelectedProtocol`, client `encryptionMethods`, channel `options`, cluster, monitor and multitransport flags | **owned check added** for the block type: the second test asserts the Network block arrives, and a mistyped one turns it red. The two asserted fields still discriminate: `serverSelectedProtocol` is compared by exact bits and `earlyCapabilityFlags` is still parsed with `from_bits`. The other fields are not asserted at these sites and carry host policy verbatim; **accepted** |
| Client Info (`client_info_pdu_is_sent_on_the_io_channel_with_caller_fields`) | a Password field that is not text reads as `password = ""` plus a cookie; undefined `ClientInfoFlags` bits are kept | **owned checks added**: no password cookie, and no flag bit outside `ClientInfoFlags::all()`. The basic security header is read with `from_bits_truncate` where 0.9 used `from_bits`, but both versions define all 16 bits of `BasicSecurityHeaderFlags`, so that accepts nothing new; INFO_PKT is still required, so a missing one still fails |

Each added assertion was watched failing with a mutated encoder: a Password field of `00 D8`, flag
bit `0x4`, and the Network block written as type `CS_NET + 0x100`. The old assertions passed all
three.

`justrdp-pdu/tests/differential_ironrdp.rs` `our_client_info_pdu_decodes_identically_in_ironrdp`
decodes the encoder's Client Info alone and carries the same two owned checks; the same Password and
flag mutations turn each red, and its old assertions passed both. The rest of that file feeds the
same encoders through paths 0.11 left alone or made stricter: the Connection Request (0.11's
`nego.rs` now checks the correlation info 0.9 refused), Erect Domain, Channel Join and Send Data
Request (`mcs.rs`, error context only), and Refresh Rect and Suppress Output. Its Connect-Initial
test meets the unknown-block skip as the `connect.rs` one did: 0.11 still requires the Core and
Security blocks (`gcc/mod.rs:167`, `:169`), and the test unwraps the Network block.

**No implementation comparison.** No verified external-fact store. The tolerance questions here (a server
that omits a requested channel, an unexpected join order) are exactly the class
ADR-0009 says is spec-unwritten and lives in FreeRDP's source — and none of it is
recorded.

## Cross-cutting invariants

- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — the early capability flags are the outermost instance: `SUPPORT_DYN_VC_GFX_PROTOCOL` is
  what makes the graphics channel exist at all, so a flag set here is a promise about a whole
  subsystem.
- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — `ServerCoreData.client_requested_protocols` is the server's echo of what we asked for
  and nothing compares it, though `connect.rs` already rejects a *selected* protocol we
  never advertised. Downgrade evidence, unread.
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

- Multi-monitor and DPI (epic #27) add GCC monitor data that is not built.
- Which connect stages a real server sends the Disconnect Provider Ultimatum in is not measured.
  It was seen once: xrdp 0.9.24 sent `0300000902f0802180` (reason 3) in `capability-exchange`
  after the channel join, under Standard RDP Security (#603, 2026-11-09). The other five stages
  are covered by feeding that frame to the sans-IO machine, not by a server. No server has been
  seen sending an X.224 Disconnect Request in any stage; the six are covered with bytes built from
  X.224 13.5.
- The skip-channel-join path is proven only against the scripted server
  (`skip_channel_join_bypasses_joins_when_both_sides_advertise_it`): the test VM never skips
  (`rdp_mcs` records `skip_channel_join=false`, #429), so no live server has exercised it.
