# Virtual channels (static & dynamic)

## What it is

The transport every non-core RDP feature rides on. **Static** virtual channels (SVC)
are negotiated at GCC, get an MCS channel ID, and carry chunked data with a length
and flags. **Dynamic** virtual channels (DVC) are a protocol *inside* one static
channel (`drdynvc`): create/open/close/data messages with their own IDs, which is
how EGFX and Display Control arrive. The library implements the transport, exactly one DVC
consumer beyond graphics (Display Control), and, since #307, the host's seam onto every other
static channel: messages in as `SessionOutput::ChannelData`, messages out through
`SessionStateMachine::send_channel`. Since #321 it also carries the clipboard channel's
initialization sequence as a helper the host drives over that seam (`justrdp::cliprdr`).

## Governing decisions

- [ADR-0014](../../adr/0014-dvc-processor-error-posture.md) — every error a `DvcProcessor`
  returns drops the connection, and the failure must name the channel; the recovery ladder
  (reset, then what) belongs to #272, which made the graphics processor take the 3.3.5.19
  reset for a semantic miss instead of returning an error (2026-09-17 amendment). Before it,
  no ADR was about channels.

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
- **A channel's processor names its channel; the transport under it does not.** `Drdynvc::dispatch`
  wraps what `DvcProcessor::process` returns as `DvcError::Processor`, which the session machine
  surfaces as `SessionError::DynamicChannel`; every drdynvc transport failure — SVC chunking, a
  malformed drdynvc PDU, the `DYNVC_DATA_FIRST.Length` cap even on an open channel — stays
  `SessionError::Decode`. Where that line sits was the maintainer's call (ADR-0014 Amendment
  2026-09-15, #285).

  **The line is drawn at the *origin*, not at the call, and this bullet said "a processor's error"
  until #286.** A processor can produce a `ProcessorOutput` the session machine then refuses —
  EGFX `ResetGraphics` is the one instance: the size leaves `process` as `OutputResized` and the
  framebuffer refuses it outside any processor call. That is attributed too, by `DvcEvent`
  carrying the processor's `channel_name()` into `SessionError::Framebuffer`'s `channel` field
  (ADR-0014 Amendment 2026-09-16, #286). The reassembly cap stays unattributed on the unchanged
  ground: it is the manager's bound, and no processor produced it.
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
- **Requesting a static channel is the host's declaration of interest, and every granted
  channel but `drdynvc` is delivered** (#307). There is no registration API and no
  per-channel processor: a reassembled message surfaces as `SessionOutput::ChannelData
  { channel, data }` with the MCS channel ID, and `send_channel` chunks a message onto one.
  So "granted but unconsumed" is not a state the core has; what the host does with a message
  it asked for is policy. **That model, over an IronRDP-style `SvcProcessor` the host
  registers into the core, was the maintainer's call (2026-09-22)**, shown both plus
  splitting the question into a `decide:` issue. The processor model's cost as shown: host
  code running inside the core, outside the output-enum model, with an error-attribution
  rule ADR-0014 would have to grow. **Not covered by that call:** a host that wants a
  channel granted but *not* delivered, and whether `ChannelData` should carry the name.
- **One reassembler per channel, shared by drdynvc** (`justrdp/src/svc.rs`), because
  `[MS-RDPBCGR]` 1.3.3 makes each channel an independent stream. Sharing it with drdynvc was
  the maintainer's call (2026-09-22): the old drdynvc path refused a chunk with neither
  FIRST nor LAST outside a sequence, which 3.1.5.2.2 says is a whole message. IronRDP
  follows the spec here; FreeRDP's drdynvc plugin fails the same chunk. The rest of the
  reassembler's rules are **derivations**, not that call, and fall to a better one:
  - the chunks must add up to the declared `totalLength`: short, long, a length that changes
    mid-sequence, and an unchunked message whose data differs from its length are all typed
    errors ([ADR-0009](../../adr/0009-tolerant-negotiation-posture.md) §3(a); both
    references refuse the same shapes). An overrun is refused at the chunk that causes it,
    because without that check a sequence whose LAST never comes grows past the cap.
  - `CHANNEL_FLAG_SUSPEND`/`RESUME` chunks carry no message and are skipped by the
    reassembler. FreeRDP's drdynvc does the same. **Suspending our own sending**, which
    2.2.6.1.1 asks for ("all virtual channel traffic MUST be suspended"), **was built at the
    maintainer's call (2026-09-22)**. They were shown three options: build it now, file it, or
    leave it to the map. *How* it works is a derivation. From SUSPEND to RESUME, every outbound
    virtual channel frame is held, whichever channel the flag arrived on. That covers
    `send_channel`, the machine's own drdynvc responses and a Display Control resize. The frames
    are released in order as `WriteBytes` by the call that processes the RESUME. Holding
    rather than refusing is what reaches the traffic the machine produces itself, and it spares
    the host from tracking the resume. The host's held messages are bounded by
    `CHANNEL_MESSAGE_CAP`; past it `send_channel` returns `SuspendedQueueFull`. The machine's
    own responses are not bounded, because each one answers a server message of similar size.
    **No server has been seen sending either flag**, so this is proven by unit tests only.
  - **a FIRST while a message is in flight is a typed error**, as both references treat it.
    drdynvc used to abandon the message and start over, and #307 first kept that. Refusing it
    was **the maintainer's call (2026-09-22)**, shown three options: refuse now, keep starting
    over, or file a `decide:` issue. The spec does not address the case, and this VM never
    sent it, so a conforming server is not expected to reach it.
  - `CHANNEL_FLAG_SHOW_PROTOCOL` asks that the header reach the endpoint. The core *is*
    the endpoint's reassembly, so the host gets the reassembled message and never a header.
- **Data on a channel ID that was never granted is skipped with an `rdp_svc` record**, not
  refused: nothing about it is a security integrity question (ADR-0009 §2/§3(b)), and it
  was silent before #307.
- **A multi-chunk message we send carries `CHANNEL_FLAG_SHOW_PROTOCOL` on every chunk**
  (`encode_chunks`), because 3.1.5.2.1 says chunked data MUST. IronRDP does the same;
  FreeRDP sets it only for a channel opened with `CHANNEL_OPTION_SHOW_PROTOCOL`. A
  single-chunk message carries FIRST|LAST alone, **unless the host opened the channel with
  `CHANNEL_OPTION_SHOW_PROTOCOL`**. Then every chunk carries it, which is FreeRDP's rule
  (`channels.c`). Two cases need it. RAIL: `[MS-RDPERP]` 1.5 says the RAIL server
  expects the header visible on all data over the RAIL channel, so the flag "has to be set".
  And `cliprdr`, which no spec says but the VM enforces (#321, the clipboard bullet below).
  Building it now, rather than leaving it to #14, was the maintainer's call (2026-09-22).
  `StaticChannel` carries the requested `options` so the machine can tell.
- **A host channel's message cap is 64 MiB** (`CHANNEL_MESSAGE_CAP`), against drdynvc's
  64 KiB. The value is unmeasured: 64 MiB leaves room for a 4K clipboard DIB (3840×2160×4 ≈
  33 MB), which is the largest message a channel we know of plausibly carries.
- **The clipboard is a sans-IO helper the host drives, not a session consumer** (#321). The
  host requests the channel with `cliprdr::channel_def()`, feeds each `ChannelData` message on
  it to `Clipboard::process`, and passes every `ClipboardOutput::Send` to `send_channel`; the
  session still never interprets `cliprdr` bytes, which is #307's contract left intact. **That
  placement was the maintainer's call (2026-09-23)**, chosen over the session machine owning
  CLIPRDR the way it owns drdynvc and handing the host decoded events. They were shown that the
  second conflicts with #307's contract. **Not covered by that call:** whether a later slice
  (#322-#325) may need state the session holds, such as whether the channel is suspended.
- **`cliprdr` must be requested with `CHANNEL_OPTION_SHOW_PROTOCOL`, because the server answers
  only chunks that carry `CHANNEL_FLAG_SHOW_PROTOCOL`** (#321). The spec does not say so:
  `[MS-RDPECLIP]` 2.1 names the channel and nothing else, unlike `[MS-RDPERP]` 1.5 for RAIL.
  Measured on the VM with byte-identical Capabilities and Format List: 4 of 4 answered with
  the flag on the client's chunks (16-164 ms after Monitor Ready in the three probes that timed
  it), and 0 of 4 without it in 30-90 s (plus #307's
  0 of 3). **One unflagged message is enough to lose what follows it.** #307 also saw no
  answer to a *chunked* Format List, whose chunks `encode_chunks` always flags. Its
  Capabilities went first as one chunk without the flag. Reproduced on the VM with a
  2608-byte list: unflagged Capabilities and then the flagged chunks, 0 of 1 answered; the
  same chunks with no Capabilities before them, 1 of 1. So flagging only multi-chunk messages,
  IronRDP's default, would not have been enough here. The
  GCC option does not matter by itself: with the option set but the flag forced off, 0 of 1;
  with the option clear but the flag forced on, 1 of 1. Both references agree: FreeRDP opens
  the channel with `INITIALIZED|ENCRYPT_RDP|COMPRESS_RDP|SHOW_PROTOCOL`, so every chunk
  carries the flag through the per-channel rule above; IronRDP adds `SHOW_PROTOCOL` to every
  cliprdr message ("a must", `ironrdp-cliprdr`). `CHANNEL_OPTIONS` carries
  `INITIALIZED|SHOW_PROTOCOL` only: `COMPRESS_RDP` would invite compression we never
  implement, and the VM answered without `ENCRYPT_RDP`. That is a derivation.
- **The helper advertises only what it implements** ([what we advertise, we must
  implement](../invariant/what-we-advertise-we-must-implement.md)): `ADVERTISED_FLAGS` is
  `CB_USE_LONG_FORMAT_NAMES` alone, intersected with the server's flags as FreeRDP does
  (`cliprdr_client_capabilities`). With no server Capabilities before Monitor Ready the
  server's flags are zero, which `[MS-RDPECLIP]` 2.2.2.1.1.1 makes a MUST and FreeRDP
  follows (`cliprdr_process_monitor_ready`), so short names are used.
  The file-transfer flags join the set in #324/#325. **The initial Format List is empty**, as
  FreeRDP's was against the VM: every format announced entitles the server to a Format Data Request,
  which is #322's, so announcing one here would advertise what nothing answers. A server
  Format List is answered with
  `CB_RESPONSE_OK` before it is surfaced as `RemoteFormatList`, because the answer carries no
  policy. **A server Format List that does not decode is answered with `CB_RESPONSE_FAIL`**
  and surfaced as `FormatListRejected`, because `[MS-RDPECLIP]` 3.1.5.2.2 says a failure
  response MUST be sent; any other undecodable message stays an error. Neither reference sends
  it: FreeRDP and IronRDP return the error and answer nothing. **Sending it now was the
  maintainer's call (2026-09-23)**, shown three options: build it in #321, defer it to #322,
  or record the references' behaviour and drop it. Anything else the helper does not decode is
  skipped with an `rdp_cliprdr` record.
- **How strictly a clipboard message is read** is a set of derivations, and they fall to a
  better one. `dataLen` must equal the rest of the message, where FreeRDP only needs it not to
  exceed it: one message is one PDU, and every VM message was exact. A capability set other
  than the general one is refused, as FreeRDP refuses it; only that one is defined
  (`[MS-RDPECLIP]` 2.2.2.1.1). A Format List Response must set exactly one of OK and FAIL. A
  long format name without its NUL, and a short list that is not whole 36-byte entries, are
  refused. **Two of those diverge from both references**: bytes after the last long name (FreeRDP
  reads entries while 4 bytes remain, "some clients pad the format list"; IronRDP while 6 do)
  and a general set whose `lengthCapability` is not exactly 12 (FreeRDP takes 4 or more). No
  Windows server has been seen doing either. **A 16-character short name with no NUL is
  accepted**: FreeRDP records Windows sending exactly that (`cliprdr_read_format_list`), so it
  is the server's real form rather than a malformation. An ASCII short name may fill all 32
  bytes the same way, where FreeRDP keeps 31.

## Code

- `justrdp-pdu/src/svc.rs` — `ChannelChunk`, `encode_chunks`
- `justrdp-pdu/src/dvc.rs` — `DvcMessage`, `encode_create_response`,
  `encode_capabilities_response`, `encode_data`, `encode_close`
- `justrdp-pdu/src/displaycontrol.rs` — `DisplayControlPdu`, `Caps`, `Monitor`,
  `encode_monitor_layout`
- `justrdp/src/dvc.rs` — `DisplayControlProcessor`, `OpenChannel`, `DvcError`
- `justrdp/src/svc.rs` — `Reassembler`, `CHANNEL_MESSAGE_CAP`
- `justrdp/src/session.rs` — `SessionOutput::ChannelData`, `send_channel`, `ChannelSendError`
- `justrdp-pdu/src/cliprdr.rs` — `ClipboardPdu`, `GeneralCapability`, `Format`,
  `encode_capabilities`, `encode_format_list`, `encode_format_list_response`
- `justrdp/src/cliprdr.rs` — `Clipboard`, `ClipboardOutput`, `channel_def`, `CHANNEL_OPTIONS`,
  `ADVERTISED_FLAGS`
- Spec sections cited inline: `[MS-RDPBCGR]` 1.3.3, 2.2.6.1.1, 3.1.5.2.1, 3.1.5.2.2;
  `[MS-RDPEDYC]` 1.7, 2.2.2.2, 2.2.3.3, 2.2.3.4, 3.2;
  `[MS-RDPEDISP]` 1.3,
  2.2.2.2, 2.2.2.2.1;
  `[MS-RDPECLIP]` 1.3.2.1, 2.1, 2.2.1, 2.2.2.1, 2.2.2.1.1, 2.2.2.1.1.1, 2.2.2.2, 2.2.3.1,
  2.2.3.1.2, 2.2.3.2, 3.1.5.2.2

## Reference behaviour

**Measured against the WS2022 test VM (#307, 2026-09-22):**

- Every requested channel is granted: `cliprdr`, `rdpsnd`, `rdpdr`, `rail` and `drdynvc` got
  consecutive IDs from 1004. The server's Virtual Channel capset is `flags=2`
  (`VCCAPS_COMPR_CS_8K`), `VCChunkSize=1600`.
- Unprompted, the server sends `cliprdr` Clipboard Capabilities (24 bytes) and Monitor Ready
  (8 bytes), and `rdpdr` Server Announce (`rDnI`, 12 bytes). Every one arrived as a single
  FIRST|LAST chunk, so **no multi-chunk receive has been observed live**; that path is
  proven by the unit tests alone.
- **`rdpdr` announces only when `rdpsnd` is requested too**: 0 of 2 runs without it, 4 of 4
  with it. The specs do not ask for it: `[MS-RDPEFS]` 1.4/1.5 and `[MS-RDPEA]` 1.4/1.5 each
  depend only on the channel transport. **FreeRDP always requests the two together**
  (`client/common/cmdline.c`). Enabling `rdpsnd` forces device redirection on ("rdpsnd
  requires rdpdr to be registered"). Enabling `rdpdr` without `rdpsnd` adds an `rdpsnd` with
  the silent `sys:fake` backend, in place since 2012 (`e0b37aa97e`) with no rationale
  recorded. So this reads as a Windows-server dependency rather than a protocol one. Which
  channels to request is the host's, so the pairing is the host's to know. `rdpsnd` itself
  sent nothing in 20 s, even with `rdpdr` present.
- A Client Announce Reply sent on `rdpdr` is answered with Server Core Capability Request
  (`rDPS`, 84 bytes) and Server Client ID Confirm (`rDCC`) echoing the ClientId. Without the
  reply no `rDCC` arrives. That is the live send proof.
- ~~**`cliprdr` does not answer a client Format List**~~ — it does, to chunks that carry
  `CHANNEL_FLAG_SHOW_PROTOCOL`, which #307's probe did not send (#321; the design-model bullet
  above has the counts). The clipboard-direction policy #307 suspected was not the cause:
  FreeRDP against the same VM is answered in 63 ms.

**Measured against the WS2022 test VM (#321, 2026-09-23):**

- The server's general capability set is version 2 with `generalFlags=0x3E`: long format
  names, stream fileclip, no file paths, can lock, huge files. FreeRDP 3.31 answers `0x2E`,
  dropping `CB_CAN_LOCK_CLIPDATA`, then an empty Format List (8 bytes); the server replies
  `CB_RESPONSE_OK`. A later one-format list (`CF_UNICODETEXT`, long names, 14 bytes) is
  answered OK too. Taken with `/dump` and `WLOG_FILTER=com.freerdp.channels.cliprdr.client:TRACE`.
- The server sent no Format List of its own during the handshake, with its clipboard empty, so
  **a server Format List has not been decoded live**; the unit tests alone cover it.
- A chunked client message (a 2018-byte `rdpdr` Client Name, sent without SHOW_PROTOCOL)
  did not end the session, but nothing the server sends depends on it. So **a multi-chunk
  send is not proven live either.**

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

- **Every redirection feature but the clipboard's handshake is an unopened channel**: audio
  output (#11), audio input (#12), device/drive/printer/smartcard (#13), RemoteApp
  (#14), multitouch (#15), video (#17), camera (#19), location (#20). The transport
  exists; the consumers do not. The clipboard (#10) moves no data yet: text is #322, images
  #323, files #324/#325.
- ~~Static channel 1004 traffic is ignored by the session loop with no record of what
  it contains.~~ **Closed in #307**: 1004 is `cliprdr`, and a granted channel's messages
  now reach the host. The remaining gaps are the multi-chunk live proofs above.
- DVC compressed data (drdynvc version 3) is not implemented and not offered — see the
  design-model bullet for when that changes.
- SVC compression (`VirtualChannelCapabilitySet`'s compression flags) is not
  implemented.
