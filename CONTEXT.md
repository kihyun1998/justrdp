# Context

**justrdp** is a from-scratch Rust library implementing a complete RDP client. Unlike its predecessor `ironrdp`, justrdp owns all RDP-specific protocol layers (X.224, MCS, GCC, capability exchange, session loop, virtual channels, codecs, and surface model), while delegating only to security-critical, non-RDP-specific crates (`rustls` for TLS, `sspi` for NLA authentication via CredSSP/SPNEGO/NTLM/Kerberos). The core is architected as a **sans-IO state machine** — the connection sequence and session loop are pure state transformations (bytes in → actions/bytes out) — paired with a ~30-line tokio I/O adapter, unlocking multi-runtime portability, differential-oracle codec testing, and complete host isolation.

## Project intent

justrdp replaces ironrdp's hardcoded protocol boundaries by giving the host full control over every RDP feature flag, particularly `ClientEarlyCapabilityFlags` — the field that gates EGFX (the Graphics Pipeline DVC) on modern Windows servers. The single-flag oversight in ironrdp-connector 0.9.0 that omits `SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100) motivated the entire rebuild.

**Scope:** the full multi-month plan (§2–§23 in plan.md) is the backlog; slices will walk the connect sequence, rendering, input, and virtual channels. **MVP-1** delivers Layers 0–4 (wire framing through capability/activation) + framebuffer + slow-path bitmap rendering. **MVP-2** adds EGFX + RemoteFX full codec. **Codecs are phased ("phased-c2"):** bootstrap by depending on `ironrdp-graphics` so rendering works immediately; rewrite each codec (RemoteFX / RemoteFX Progressive / ClearCodec / NSCodec / zgfx) ourselves using `ironrdp-graphics` as a **differential test oracle** (same input → byte-identical pixels) until the dependency can be dropped.

## Glossary

### Connection
A single attempt to establish an RDP session with a remote server. Begins with TCP dial and ends either in success (becoming a [[Session]]) or failure (emitting a [[Connect Error]]). Driven by the sans-IO [[Connect Stage]] state machine, with I/O supplied by the [[Host Adapter]].

### Session
A live RDP session after the [[Connect Stage]] completes activation. The Session owns the framebuffer, virtual channel processors, and the long-lived TCP stream. The session loop dispatches inbound graphics/input PDUs and emits [[Frame Update]]s, input responses, and other channel data to the host. Ends on disconnect or fatal error.

### Connect Stage
A labeled sub-step within the [[Connection]] sequence. There are six stages, shared between diagnostic logging and the host's progress UI:

1. **tcp-connect** — TCP dial to the RDP server.
2. **tls-handshake** — TLS upgrade (if SSL/HYBRID/RDSTLS negotiated).
3. **nla-credssp** — NLA authentication via CredSSP, SPNEGO, and NTLM/Kerberos.
4. **capability-exchange** — client/server advertise and negotiate feature flags and desktops size.
5. **activation** — finalize the session (synchronize, grant control, exchange fonts).
6. **session-active** — entered on successful activation; persists until disconnect.

Entered linearly; stage completion is observable by the host for both progress indication and error attribution.

### Sans-IO Core
The pure state-machine logic implementing the RDP protocol without embedding async I/O or socket operations. The `connect` and `session` machines are parameterized on `State`; callers feed them `(Action, bytes)` pairs and receive `(Output, next_state)` back. This separation unlocks multi-runtime portability (tokio, blocking, wasm), deterministic testing, and per-stage timeout/cancel at the [[Host Adapter]] boundary.

### Host Adapter
The I/O layer supplied by the consumer — typically a ~30-line tokio loop that reads from the TCP socket, feeds bytes to the [[Sans-IO Core]] state machine, writes response bytes back to the socket, and forwards [[Frame Update]]s and other events to the host's frame sink / input handler. No part of justrdp embeds the async runtime or the socket; the core is a pure function, and the adapter makes it real.

### Frame Update
The unit of communication from justrdp to the host during a [[Session]]. Conceptually a (rectangle, RGBA pixels) tuple: "replace the screen region at (x, y, w, h) with these bytes". Pixels are normalized to RGBA8888, channel order `[R, G, B, A]`, little-endian in memory. Emitted by both the [[Slow path]] (RLE bitmap decoding) and [[Graphics Pipeline]] (EGFX surface tile flushes). The host's frame sink is a synchronous callback (`Fn(FrameUpdate)`) to maximize latency predictability.

### Virtual Channel
A side-band data stream multiplexed over the [[Connection]] alongside main graphics/input traffic, identified by name and used for features beyond the desktop image: clipboard (CLIPRDR), audio (RDPSND), drive redirection (RDPDR), and dynamic resize (Display Control / RDPEDISP). Two kinds: a **Static Virtual Channel (SVC)** is negotiated at GCC (client sends ChannelDef list in Client Network Data); a **Dynamic Virtual Channel (DVC)** is created on-demand over the `drdynvc` meta-channel. justrdp reuses `ironrdp`'s `SvcProcessor` and `DvcProcessor` types; host-facing data crosses the [[Host Adapter]] boundary through plain callbacks and `mpsc` channels, keeping `ironrdp`'s RDP machinery pure.

### Surface (Graphics Pipeline context)
In EGFX ([[Graphics Pipeline]]), an off-screen pixel buffer the server creates, draws into (via decoded tiles), caches between, and maps to the visible output. justrdp does not own the surface store — `ironrdp-egfx` owns it — but bridges decoded surface regions to [[Frame Update]]s so the host sees all pixels, whether from slow-path bitmap or EGFX surface commit.

### Differential Oracle
The `ironrdp-graphics` crate, used during **phased-c2** codec development as a byte-diff test reference. For each codec (RemoteFX, RemoteFX Progressive, ClearCodec, NSCodec, zgfx), we feed identical encoded input to both justrdp's decoder and `ironrdp-graphics`, compare pixel outputs (RGBA), and ensure byte-identity. This approach lets us incrementally rewrite codecs without reimplementing decode-from-spec (the slow path); `ironrdp-graphics` answers "what should this tile look like?" Once a codec is self-owned and oracle-verified, the dev-dep is dropped.

### Slow path
The baseline graphics rendering path: the server sends desktop updates as bitmap rectangles with RLE (or other legacy) compression. justrdp decodes them into the framebuffer and emits [[Frame Update]]s for changed regions. "Slow" is relative to [[Graphics Pipeline]] — a resize forces the server to repaint the entire screen as RLE bitmaps, making the cost visible. It is the first codec path implemented and serves as the reference for all EGFX performance gains.

### Graphics Pipeline
The production graphics path on modern Windows: compressed, incrementally-refined desktop updates carried over a dedicated [[Virtual Channel]] (a DVC, the EGFX channel over `drdynvc`). Updates target off-screen [[Surface]]s rather than one framebuffer, and are advertised/negotiated by codec. Gated by advertising `ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100) in GCC early-capability flags. Supported codecs: RemoteFX (full, non-progressive), RemoteFX Progressive, ClearCodec (lossless), NSCodec (lossy, subcodec), H.264/AVC (external decoder required). EGFX is the core performance win over [[Slow path]] and the reason justrdp exists — ironrdp-connector 0.9 hardcodes away the capability flag.

---

**Cross-reference key** (terms defined above):
- [[Connection]] → [[Connect Stage]] → [[Session]]
- [[Host Adapter]] ↔ [[Sans-IO Core]]
- [[Frame Update]] ← produced by [[Slow path]] or [[Graphics Pipeline]]
- [[Graphics Pipeline]] uses [[Virtual Channel]] (EGFX DVC) + [[Surface]]
- [[Differential Oracle]] validates codec output during phased rewrites
- [[Virtual Channel]] → `ironrdp`'s SvcProcessor/DvcProcessor (pure), host-facing seams (host's responsibility)
