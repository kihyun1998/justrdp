# Virtual channels (static & dynamic)

## What it is

The transport every non-core RDP feature rides on. **Static** virtual channels (SVC)
are negotiated at GCC, get an MCS channel ID, and carry chunked data with a length
and flags. **Dynamic** virtual channels (DVC) are a protocol *inside* one static
channel (`drdynvc`): create/open/close/data messages with their own IDs, which is
how EGFX and Display Control arrive. Today the library implements the transport and
exactly one DVC consumer beyond graphics: Display Control.

## Governing decisions

- [ADR-0014](../../adr/0014-dvc-processor-error-posture.md) — every error a `DvcProcessor`
  returns drops the connection, and the failure must name the channel; the recovery ladder
  (reset, then what) belongs to #272. Before it, no ADR was about channels.

Adjacent but not governing: `CONTEXT.md` defines **Virtual Channel** in the
glossary, which is vocabulary rather than a decision.

## Design model

- **Chunking is the SVC layer's job and the boundary is invisible above it** — a
  consumer sees a message, never a chunk. Getting the first/last flags wrong
  produces a *plausible* truncated message rather than an error.
- **DVC is a protocol in a channel, so it has its own lifecycle** — a channel the
  client did not open still sends data if the server thinks it did.
- **A Create Request for an id that is still bound replaces the binding, accepted or refused,
  and tears it down exactly as a Close does** — the processor's `close()` and any Display
  Control target recorded for that id (`Drdynvc::unbind`). `[MS-RDPEDYC]` 3.1.1 makes an id
  reusable only after a Close, but #270's probe saw this server recycle an id within 40 ms,
  twice for channels we refuse before one we accept. Until the Close path and the create path
  shared one teardown, a rebind dropped only the routing entry: resize requests kept going to
  the recycled id, and a rebound graphics channel kept the old binding's surfaces.
- **A processor's error names its channel; the transport under it does not.** `Drdynvc::dispatch`
  wraps what `DvcProcessor::process` returns as `DvcError::Processor`, which the session machine
  surfaces as `SessionError::DynamicChannel`; every drdynvc transport failure — SVC chunking, a
  malformed drdynvc PDU, the `DYNVC_DATA_FIRST.Length` cap even on an open channel — stays
  `SessionError::Decode`. Where that line sits was the maintainer's call (ADR-0014 Amendment
  2026-09-15, #285).
- **Display Control is pull-capable and gated**: `DisplayControlProcessor` only
  becomes usable once the server's caps arrive, which is the moment the session
  emits `DisplayControlReady`.
- **The drdynvc version answered is 2, and a compressed data PDU is a transport error on any
  channel** (#287). `[MS-RDPEDYC]` 1.7: version 3 adds *only* `DYNVC_DATA_FIRST_COMPRESSED` /
  `DYNVC_DATA_COMPRESSED`, which a receiver "MUST decompress" (3.1.5.2.6), and 2.2.3.3/2.2.3.4
  forbid them below version 3. So `CAPS_VERSION` states the obligation we discharge, and a Cmd 6/7
  that arrives anyway is unannounced compression (ADR-0009 §1) — refused before any channel
  lookup, unattributed like every manager failure (ADR-0014 Amendment). It had answered 3 since
  the EGFX bring-up (`b166aff`) on the recorded ground that the server resets a version-1
  transport; on 2026-09-15 this VM painted normally at 1, 2 and 3 and sent **zero** Cmd 6/7 in
  five 120 s forced-damage sessions (versions 3/2/1, `connectionType` LAN and MODEM), so that
  ground no longer holds. **Answering 2 and refusing, over implementing RDP8-lite decompression
  or only logging the drop, was the maintainer's call** — shown those three options with their
  consequences (decompression cannot be proven with no server that sends it; a log-only skip is
  violation #2 of [what we advertise](../invariant/what-we-advertise-we-must-implement.md)).
  Two parts are derivations, not that call, and fall to a better one. **2 rather than 1**:
  version 2 invites no server-sent message — its addition is a SHOULD on how the client divides
  its *own* sending bandwidth by priority class (3.2.3.1.2), which justrdp does not shape — and
  Appendix A <1> lists version 1 as supported only in Windows Vista; the maintainer was not shown
  1 as an option, though the VM painted at it. **Refusing on an unopened channel too**: below
  version 3 the command is invalid before it names any channel, so the unopened-channel ignore
  below never gets a say. **Both references answer 3**, so this is a deliberate divergence:
  FreeRDP echoes the server's version and decompresses per channel through its zgfx; IronRDP
  echoes it too, then rejects Cmd 6/7 as an unsupported `Cmd` — advertising the obligation and
  refusing it. **Not covered:** soft-sync (gated by multitransport, which justrdp never
  advertises, not by this version) and unassigned `Cmd` values, still skipped, with 3.1.5.2.4's
  "MUST terminate" left as ADR-0014's open item; any server but this WS2022 box; and a
  multitransport UDP-R tunnel. Decompression is revisited when a channel we accept has a server
  that compresses on it — that capture is its proof.
- Unknown DVCs are not fatal — an unopened channel's traffic is ignored, in the
  spirit of ADR-0009's tolerance on the rendering side.

## Code

- `justrdp-pdu/src/svc.rs` — `ChannelChunk`, `encode_chunks`
- `justrdp-pdu/src/dvc.rs` — `DvcMessage`, `encode_create_response`,
  `encode_capabilities_response`, `encode_data`, `encode_close`
- `justrdp-pdu/src/displaycontrol.rs` — `DisplayControlPdu`, `Caps`, `Monitor`,
  `encode_monitor_layout`
- `justrdp/src/dvc.rs` — `DisplayControlProcessor`, `OpenChannel`, `DvcError`
- Spec sections cited inline: `[MS-RDPEDYC]` 1.7, 2.2.2.2, 2.2.3.3, 2.2.3.4, 3.2;
  `[MS-RDPEDISP]` 1.3,
  2.2.2.2, 2.2.2.2.1

## Reference behaviour

**None.** No verified external-fact store.

## Cross-cutting invariants

- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — this territory enforces it twice: a compressed SVC chunk is a typed error because
  `VCCAPS_NO_COMPR` never advertised compression, and a compressed DVC data PDU is one because
  the drdynvc version answered never reaches 3 (#287).
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) —
  chunk reassembly is attacker-controlled length arithmetic.

## Blast radius

- [EGFX graphics pipeline](egfx-graphics-pipeline.md) — the largest DVC consumer;
  its stream arrives through this layer.
- [Session loop & PDU dispatch](session-loop-dispatch.md) — dispatches channel
  traffic and emits `DisplayControlReady`.
- [MCS / GCC channel setup](mcs-gcc-channel-setup.md) — static channel IDs and the
  `drdynvc` channel come from there.
- [Capability exchange & activation](capability-exchange-activation.md) —
  `VirtualChannelCapabilitySet` bounds chunk size and compression.

## Known holes / open

- **Every redirection feature is an unopened channel**: clipboard (#10), audio
  output (#11), audio input (#12), device/drive/printer/smartcard (#13), RemoteApp
  (#14), multitouch (#15), video (#17), camera (#19), location (#20). The transport
  exists; the consumers do not.
- Static channel 1004 traffic is ignored by the session loop with no record of what
  it contains.
- DVC compressed data (drdynvc version 3) is not implemented and not offered — see the
  design-model bullet for when that changes.
- SVC compression (`VirtualChannelCapabilitySet`'s compression flags) is not
  implemented.
