# Virtual channels (static & dynamic)

## What it is

The transport every non-core RDP feature rides on. **Static** virtual channels (SVC)
are negotiated at GCC, get an MCS channel ID, and carry chunked data with a length
and flags. **Dynamic** virtual channels (DVC) are a protocol *inside* one static
channel (`drdynvc`): create/open/close/data messages with their own IDs, which is
how EGFX and Display Control arrive. Today the library implements the transport and
exactly one DVC consumer beyond graphics: Display Control.

## Governing decisions

**None.** No ADR is about channels (measured: "virtual channel" appears in 1 of 10
records).

Adjacent but not governing: `CONTEXT.md` defines **Virtual Channel** in the
glossary, which is vocabulary rather than a decision.

## Design model

- **Chunking is the SVC layer's job and the boundary is invisible above it** — a
  consumer sees a message, never a chunk. Getting the first/last flags wrong
  produces a *plausible* truncated message rather than an error.
- **DVC is a protocol in a channel, so it has its own lifecycle** — a channel the
  client did not open still sends data if the server thinks it did.
- **Display Control is pull-capable and gated**: `DisplayControlProcessor` only
  becomes usable once the server's caps arrive, which is the moment the session
  emits `DisplayControlReady`.
- Unknown DVCs are not fatal — an unopened channel's traffic is ignored, in the
  spirit of ADR-0009's tolerance on the rendering side.

## Code

- `justrdp-pdu/src/svc.rs` — `ChannelChunk`, `encode_chunks`
- `justrdp-pdu/src/dvc.rs` — `DvcMessage`, `encode_create_response`,
  `encode_capabilities_response`, `encode_data`, `encode_close`
- `justrdp-pdu/src/displaycontrol.rs` — `DisplayControlPdu`, `Caps`, `Monitor`,
  `encode_monitor_layout`
- `justrdp/src/dvc.rs` — `DisplayControlProcessor`, `OpenChannel`
- Spec sections cited inline: `[MS-RDPEDYC]` 2.2.2.2, 3.2; `[MS-RDPEDISP]` 1.3,
  2.2.2.2, 2.2.2.2.1

## Reference behaviour

**None.** No verified external-fact store.

## Cross-cutting invariants

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
- SVC compression (`VirtualChannelCapabilitySet`'s compression flags) is not
  implemented.
