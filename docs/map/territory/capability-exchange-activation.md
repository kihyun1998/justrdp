# Capability exchange & activation

## What it is

The negotiation that decides what the session can actually do: the server's Demand
Active carries its capability sets and the `shareID`; the client answers with
Confirm Active carrying its own; then the finalization round-trip (Synchronize →
Control Cooperate → Control Request Control → Font List → Font Map) reaches
`session-active`. The same exchange re-runs **in-session** as
Deactivation–Reactivation, which is how a resize actually happens.

## Governing decisions

- [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md) — tolerant of server
  self-inconsistency in rendering capabilities, strict on security integrity. This
  is the record that says what to do when a server advertises something it then
  contradicts.
- [ADR-0010](../../adr/0010-frameupdate-dirty-rect-contract.md) — indirectly: the
  negotiated desktop size is what the framebuffer is allocated from.
- [ADR-0016](../../adr/0016-policy-flags-are-the-hosts.md) Decision 3 — the connect layer
  sends the host's advertisement verbatim, and the core refuses what it cannot honour. The
  table below is that decision's allow-list (#357).

## Design model

- **The negotiated desktop size is the server's, not the client's request.**
  `ActivationResult::desktop_size` comes from the server's Bitmap capability set;
  allocating the framebuffer from the GCC-requested size is the bug this field
  exists to prevent.
- **Activation hands over leftover bytes, and they must be processed before the
  next socket read.** Servers start streaming graphics immediately, so bytes after
  the Font Map routinely arrive in the same read. `ActivationResult::leftover`
  carries them; a session loop that reads the socket first loses a frame's worth of
  ordering.
- **Server capability sets are handed over verbatim**, because the session loop —
  not this phase — decides what order/codec support means.
- **Reactivation is the same exchange with session state alive.** `Phase::Reactivating`
  re-runs it; caches belong to the *connection*, not the share, so they survive.
- **The Font Map alone gates `session-active`, deliberately.** The server's Synchronize and
  Control replies are decoded and their values checked, then discarded — their *arrival* is
  recorded nowhere, so there is no completeness or ordering ladder. #252 decided this against
  a capture rather than by default; the grounds are in `## Reference behaviour`. The Font Map's
  own *body* is still strictly parsed — a separate question, settled by #237/#242.
- **Both legs answer the same question the same way.** `connect.rs`'s finalization arms and
  `session.rs`'s `Phase::Reactivating` arms call the same parsers and the same
  `Control::check_server_action`. Until #252 they did not: the reactivation leg dropped the
  `ReadCursor` unread, so a server `Control(Detach)` was fatal on connect and invisible on
  resize.
- **The default General set advertises `AUTORECONNECT_SUPPORTED`** since #306 — the
  maintainer's call, because it is the bit that makes the server issue an auto-reconnect cookie,
  and #306 implements the answer to it ([Logon & Save Session Info](logon-session-info.md)).
- **Set Keyboard Indicators (0x29) is the exception, deliberately.** The session leg surfaces
  it and this leg's catch-all skips it — the maintainer's call in #305, recorded with what it
  was decided on in [Input & platform scancode tables](input-scancodes.md).
- **The connect layer refuses what it cannot honour, before any byte** (#357).
  `ConnectStateMachine::new` returns `ConnectConfigError` naming the first refused item, and the
  adapter returns it as `ConnectFailure::Config` before dialing. The allow-lists are
  `justrdp::advertise`'s `HONOURED_*` constants plus a per-set judgement, and they grow as the
  core implements more. The rule for each row: refused if it lets the server send something the
  core skips or rejects, or obliges the client to do something the core does not do. A row that
  only describes what the client may send to the server is honoured. Every row below is a
  derivation from `[MS-RDPBCGR]` (sections cited) plus the dispatch that would receive the
  traffic.

  | Advertisement | Honoured | Refused, and why |
  |---|---|---|
  | `earlyCapabilityFlags` (2.2.1.3.2) | `ERRINFO` (Set Error Info is decoded), `WANT_32BPP` (planar decodes 32 bpp), `STRONG_ASYMMETRIC_KEYS` (Standard RDP Security only, which the connect refuses), `RELATIVE_MOUSE_INPUT` (client to server only), `VALID_CONNECTION_TYPE`, `DYNVC_GFX` (EGFX), `SKIP_CHANNELJOIN` | `STATUSINFO`, `MONITOR_LAYOUT` (PDUs the session skips); `NETCHAR_AUTODETECT`, `HEARTBEAT` (message-channel PDUs nothing handles); `DYNAMIC_TIME_ZONE` (obliges dynamic DST fields the Client Info encoder does not write); undefined `0x1000`–`0x8000` |
  | Client Info `flags` (2.2.1.11.1.1) | `MOUSE`, `DISABLECTRLALTDEL`, `AUTOLOGON`, `UNICODE`, `MAXIMIZESHELL`, `LOGONNOTIFY` and `LOGONERRORS` (Save Session Info is decoded), `ENABLEWINDOWSKEY`, `REMOTECONSOLEAUDIO`, `NOAUDIOPLAYBACK`, `VIDEO_DISABLE`, `FORCE_ENCRYPTED_CS_PDU`, `PASSWORD_IS_SC_PIN`, `USING_SAVED_CREDS`, `MOUSE_HAS_WHEEL` | `COMPRESSION` and `CompressionTypeMask` (bulk-compressed output, which `ShareDataHeader::decode` refuses); `RAIL`, `HIDEF_RAIL_SUPPORTED` (RemoteApp, #14); `AUDIOCAPTURE` (#12); every undefined or reserved bit |
  | Static channel `options` (2.2.1.3.4.1) | `INITIALIZED`, `ENCRYPT_*`, `PRI_*`, `SHOW_PROTOCOL`, `REMOTE_CONTROL_PERSISTENT` | `COMPRESS_RDP`, `COMPRESS` (compressed chunks, which the SVC layer refuses); undefined bits |
  | General | `extraFlags` `FASTPATH_OUTPUT`, `LONG_CREDENTIALS`, `AUTORECONNECT`, `ENC_SALTED_CHECKSUM`, `NO_BITMAP_COMPRESSION_HDR`; the server-only support bytes are ignored in the client's copy | any other `extraFlags` bit |
  | Bitmap | `drawingFlags` `0x02`/`0x04`/`0x08` (planar decodes CLL, subsampling and NA), `0x10` | any other `drawingFlags` bit |
  | Order | `orderSupport` all zero | any order (drawing orders are skipped, #22) |
  | Bitmap Cache rev. 1, Brush, Glyph Cache, Offscreen | every cache empty, `BRUSH_DEFAULT`, `GLYPH_SUPPORT_NONE`, level 0 | anything that invites cache, brush, glyph or offscreen orders |
  | Pointer, Input | all values (the pointer cache is sized from the set; input flags are client to server) | — |
  | Virtual Channel | `VCCAPS_COMPR_CS_8K` | `VCCAPS_COMPR_SC` (compressed channel data); undefined bits |
  | Sound | `SOUND_FLAG_BEEPS` (#354) | any other bit |
  | Multifragment Update (2.2.7.2.6) | `MaxRequestSize` up to `HONOURED_MAX_REQUEST_SIZE`, the session's fast-path reassembly cap at its floor (#150) | a larger one: the server may then send a reassembled update the session refuses |
  | Surface Commands (2.2.7.2.9) | `SETSURFACEBITS`, with `FASTPATH_OUTPUT` in the General set (#150) | `FRAMEMARKER` (the session drops Frame Markers); `STREAMSURFACEBITS` (2.2.9.2.2 makes its destination bounds meaningful where 2.2.9.2.1 says to ignore them, the session reads neither, and no capture holds one); any other bit; any command flag without `FASTPATH_OUTPUT`, which 2.2.7.2.9 makes a MUST |
  | Bitmap Codecs (2.2.7.2.10) | no codecs, or NSCodec at codec ID 1 with properties `TS_NSCODEC_CAPABILITYSET` allows (#150) | any other codec (Set Surface Bits decodes NSCodec alone); NSCodec at another ID, which 2.2.7.2.10.1.1 forbids |
  | Any other set | — | refused unread: it cannot be judged. Bitmap Cache rev. 2, Large Pointer, Frame Acknowledge, Control, Share, Font and the rest wait for a reader |

  #352 had listed `RELATIVE_MOUSE` among the refused bits. The spec gives it no
  server-to-client traffic (2.2.1.3.2 points only at client input events), so it is honoured.
  `DYNAMIC_TIME_ZONE` is refused on a different ground than #352 gave: it invites no server
  PDU, but it promises Client Info fields the encoder does not write.
- **The defaults advertise NSCodec over Set Surface Bits, with a Multifragment Update set**
  (#150). Adding them to `default_client_capabilities` was the maintainer's call, made on
  plan.md §5a's *"advertise everything we can handle"* and shown against an opt-in-only option;
  it was made **before** two measurements it could not have seen. The Multifragment set then
  went in as a derivation: without it this server sent Set Error Info `0x112F` and closed the
  session before any surface bits, so a default without it would end every 32-bpp legacy
  session. And with the defaults, a legacy session on a server at 32 bpp paints in NSCodec
  surface bits rather than bitmap updates, which the decision did not address by name.
  `SURFCMDS_FRAME_MARKER` is refused: the session decodes and drops markers rather than grouping
  a frame's tiles, and 2.2.9.2.3 gives markers that purpose.
- **Two calls after those measurements were the maintainer's** (#150, judgements). Shown that this
  VM closes a session advertising Surface Commands without a Multifragment Update set, they chose
  **not** to refuse that combination: the evidence is one server's behaviour, not a spec
  obligation, and ADR-0016 Decision 3 covers traffic the core drops, not a server's
  preconditions. Shown that the default NSCodec properties (dynamic fidelity, subsampling,
  colour-loss level 3, FreeRDP's values) make a 32-bpp legacy session lossy, they kept them; a host
  wanting lossless pixels sets the properties or leaves NSCodec out of its capability sets.
- **`DYNVC_GFX` carries an obligation the core does not meet, and it is latent.** 2.2.1.3.2:
  *"Setting this flag requires that the client support network characteristics detection"*.
  The core does not implement auto-detect, but those PDUs ride the message channel, which the
  client never requests (Client Message Channel Data is not sent). So none can arrive. The
  default keeps the bit; requesting a message channel would make the gap live.

## Code

- `justrdp-pdu/src/capability.rs` — `DemandActive`, `CapabilitySet`,
  `GeneralCapabilitySet`, `BitmapCapabilitySet`, `OrderCapabilitySet`,
  `PointerCapabilitySet`, `InputCapabilitySet`, `VirtualChannelCapabilitySet`,
  `SoundCapabilitySet` (`SOUND_FLAG_BEEPS`, #354), `BitmapCodec`, `BitmapCodecsCapabilitySet`,
  `BitmapCacheCapabilitySet`, `BrushCapabilitySet`, `GlyphCacheCapabilitySet`,
  `OffscreenCacheCapabilitySet` (#357), `MultifragmentUpdateCapabilitySet`,
  `SurfaceCommandsCapabilitySet`, `NsCodecProperties`, `CODEC_GUID_NSCODEC`, `CODEC_ID_NSCODEC`
  (#150)
- `justrdp/src/advertise.rs` — `check`, `ConnectConfigError`, `HONOURED_EARLY_CAPABILITY_FLAGS`,
  `HONOURED_CLIENT_INFO_FLAGS`, `HONOURED_CHANNEL_OPTIONS`, `HONOURED_GENERAL_EXTRA_FLAGS`,
  `HONOURED_DRAWING_FLAGS`, `HONOURED_VIRTUAL_CHANNEL_FLAGS`, `HONOURED_SOUND_FLAGS`,
  `HONOURED_SURFACE_COMMANDS`, `HONOURED_MAX_REQUEST_SIZE`, `check_bitmap_codec`
- `justrdp-tokio/src/lib.rs` — `ConnectFailure::Config`
- `justrdp-pdu/src/share.rs` — `ShareControlHeader`, `ShareDataHeader`,
  `encode_share_control`, `encode_share_data`
- `justrdp-pdu/src/finalization.rs` — `Synchronize`, `Control`, `FontMap`,
  `Control::check_server_action`, `encode_font_list`
- `justrdp/src/connect.rs` — `ActivationResult`, `Stage`
- `justrdp-pdu/src/session_info.rs` — `SaveSessionInfo`
- `justrdp/src/session.rs` — `Phase::Reactivating`, `ResizeError`
- Stage strings: `capability-exchange`, `session-active`

## Reference behaviour

**The server's Demand Active carries 17 sets, none of the four #357 typed** (2026-10-01,
`vm_advertised_bitmap_codecs_and_surface_commands`). Typed: General, Bitmap, Order, Pointer,
Input, Virtual Channel, Multifragment Update, Surface Commands, Bitmap Codecs (NSCodec, RemoteFX,
Image RemoteFX and `CODEC_GUID_IGNORE`). Unread: `0x0009` Share, `0x000A` Color Cache, `0x000E`
Font, `0x0012` Bitmap Cache Host Support, `0x0017` Rail, `0x0018` Window List, `0x001B` Large
Pointer, `0x001E` Frame Acknowledge. So the stricter decode of Bitmap Cache, Brush, Glyph Cache
and Offscreen Cache does not reach this server's receive path.

**Advertising a codec is not sending it** (#150, 2026-10-01). The same Demand Active offered
Surface Commands and NSCodec in July, which read as a proof path; the server still sent no
Surface Bits to a client advertising both, because it capped every non-EGFX session at 16 bpp.
FreeRDP 3.31 (`+nsc /bpp:32`) got 16 bpp and no Surface Bits too. With the VM's *Limit maximum
color depth* policy at 32 bpp the server answers a legacy session at 32 bpp, even one asking 24,
and paints it in NSCodec Set Surface Bits — given a Multifragment Update set, without which it
closed with Set Error Info `0x112F`. It sent Frame Markers only when `SURFCMDS_FRAME_MARKER` was
advertised, and needed no Frame Acknowledge set. The capture is
`justrdp/tests/fixtures/session/nscodec-surface-bits.bin`.

Opened by #252. It read **"None"** until then, with the note that this was the
territory where the absence cost most — and it did: #252 opened on the premise
*"the real VM sends all four finalization replies, in order"*, which nothing in
the repo could confirm or deny.

**What the real server sends** — captured 2026-08-25 via
`JUSTRDP_CONNECT_CAPTURE_FILE` (server-to-client only, hence commitable), four
activations across two tests, **identical on the connect leg and the
reactivation leg**:

```
DEMAND_ACTIVE
SYNCHRONIZE   messageType=1   targetUser=0
CONTROL       action=0x0004 (Cooperate)        grantId=0     controlId=0
CONTROL       action=0x0002 (Granted Control)  grantId=1007  controlId=0x03EA
FONT_MAP      mapFlags=0x0003  entrySize=4
```

`grantId` is the MCS user channel and `controlId` is the server channel — the two
values `[MS-RDPBCGR]` 2.2.1.21 marks MUST. Pinned as
`justrdp-pdu/tests/fixtures/connect/finalization-replies.bin`, walked by
`a_real_servers_finalization_replies_decode_in_order`. **One WS2022 box on one
advertised config**: it proves what *this* server sends, never what servers send
(see [capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)).

**What the references require of the client.** The `[MS-*]` half is thinner than
it looks: 1.3.1.1 phrases every finalization rule as a *server* obligation
("is sent in response to", "is sent after transmitting"), and the client-side
processing sections 3.2.5.3.19–.22 are one sentence each plus a MUST-ignore
field list — **no ordering obligation, no arrival precondition**, and §3.2.1's
abstract data model has no finalization-arrival variable. So the spec does not
answer the question this territory kept asking.

FreeRDP does track arrival (`finalize_sc_pdus`, `rdp_handle_sc_flags` in
`libfreerdp/core/rdp.c`), and two things about it are routinely misread:

- **It is a completeness gate, not an ordering gate.** The flag word is only
  ever OR-ed and is cleared solely at reset, so out-of-order replies still
  satisfy every rung, one PDU behind.
- **It never fails.** The else branch warns and leaves `status` untouched, so a
  missing reply parks the client on the rung rather than dropping the session.
  It **did** fail once: `ff2509bbc4e9` (2022-11-29, *"relax sc flags state
  checks"*) deleted `status = STATE_RUN_FAILED` one day after FreeRDP#8458 — an
  xrdp resolution change disconnecting on the reactivation leg.

IronRDP tracks nothing: one flat wait state, `FontMap → Finished`.

**What justrdp does with that** (#252): no completeness gate — the Font Map alone
reaches session-active, deliberately — but the field values the spec does fix are
checked, identically on both legs.

## Cross-cutting invariants

- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — this territory builds the Confirm Active capability sets, which are the general form of
  the rule: every set sent here tells the server which orders and surface commands it may now
  use, and a set advertised past what the client handles produces dropped traffic rather than
  an error.
- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — the discovery site. `Synchronize.messageType` was discarded under a spec citation the
  spec does not make, and a server `Control.action` was decoded and dropped; both closed by
  #252, both rejected by both references.
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — every PDU
  this territory parses is server-supplied: the Demand Active capability walk, the Share
  headers, and the three finalization replies. **Listed only from #237 onward, and the
  omission is the finding**: `finalization`'s three parsers had neither artifact and appeared
  in no uncovered list either, because this edge was the one place a reader would have been
  sent from. `check_map.py`'s reciprocity gate cannot catch that — it verifies that the edges
  which *exist* run both ways.
- [Capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
  — this territory builds the advertised config, so it is where a capture's coverage is
  decided, one connect sequence before anything is observed.

## Blast radius

- [Session loop & PDU dispatch](session-loop-dispatch.md) — receives `share_id`,
  the capability sets and the leftover bytes; every one of the three is a contract.
  **And a fourth since #252**: it re-runs this territory's finalization parsers on the
  reactivation leg, `Control::check_server_action` included, so a change to what a server
  reply may contain moves `session.rs` too. That edge was silent before #252, and the
  silence is what let the two legs disagree.
- [Framebuffer & frame delivery](framebuffer-frame-delivery.md) — allocated from
  the negotiated size, and reallocated on reactivation.
- [Bitmap codecs](bitmap-codecs.md) — `BitmapCodecsCapabilitySet` decides which
  decoders can be reached at all (the VM's advertised set bounds what is provable).
- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — the two graphics paths this territory
  can invite share one framebuffer. Measured on the VM, a server that negotiates EGFX sends no
  legacy graphics, surface commands included (#150), so they do not paint one session together.
- [PDU constants & flag tables](pdu-constants.md) — capability type codes and their
  flags.

## Known holes / open

- **Client-initiated resize via Deactivation–Reactivation is only half-built** —
  plan.md §23 records the inbound request handler as missing ("ironrdp-displaycontrol
  does push, not pull").
- Order capabilities are parsed but drawing orders are not implemented (epic #22),
  so `OrderCapabilitySet` advertises a surface nothing consumes yet.
- ADR-0009's tolerance is **not yet exercised for drawing orders**, stated in the
  record itself.
