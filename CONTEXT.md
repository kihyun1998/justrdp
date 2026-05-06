# JustRDP

A pure-Rust RDP library — `no_std` core, zero C dependencies. This context
covers the full RDP protocol implementation, prioritised on the client side
(M-Client) and extended to the server side (M-Server) in later phases.

> **Roadmap**: `roadmap.md` is the single source of truth for plans and
> progress. `CONTEXT.md` only captures *vocabulary*; `docs/adr/*` only captures
> *decisions*.

## Language

### 1. Wire & Encoding

**PDU**:
A single message unit on the RDP wire. All PDUs are expressed via the
`Encode` / `Decode` traits.
_Spec_: MS-RDPBCGR §2.2

**X.224**:
TPKT/COTP framing — the outer envelope of the connection-establishment phase.
_Spec_: ITU-T X.224 / RFC 905

**MCS**:
Multipoint Communication Service — the channel-multiplexing layer.
Connect-Initial/Response → Erect Domain → Attach User → Channel Join, in that
order, forms the four-step handshake.
_Spec_: T.125

**GCC**:
Generic Conference Control — the payload encoding inside MCS
Connect-Initial/Response.
_Spec_: T.124

**Encode / Decode + ReadCursor / WriteCursor**:
The four-element PDU serialisation pattern. The byte count returned by
`size()` MUST equal the bytes actually written by `encode()` (CLAUDE.md
invariant). `ReadCursor` provides zero-copy reads over a borrowed slice;
`WriteCursor` provides cursor-tracked writes. The `justrdp-derive` proc-macro
generates boilerplate where the layout is straightforward. _See_: ADR-0003.
_Avoid_: serialization, marshalling

**PduHint**:
A trait that tells a streaming reader *how many more bytes are needed to
complete one PDU*. Used to detect length-prefixed PDU boundaries on top of a
byte stream (e.g. TCP) in a push fashion. Uncommon in the wider ecosystem —
this is our invention.

---

### 2. Channels

**Channel**:
*Context-dependent* — one of (a) MCS channel, (b) **SVC**, or (c) **DVC**.
Never use this term unqualified. _See_: Flagged ambiguities.

**Static Virtual Channel (SVC)**:
A fixed channel that occupies one MCS channel 1:1. Names and options are
locked in during connection negotiation (CLIPRDR, RDPSND, RDPDR, …).
_Spec_: MS-RDPBCGR §2.2.6

**Dynamic Virtual Channel (DVC)**:
A dynamic channel multiplexed over a single SVC named `DRDYNVC`. DVCs may be
opened/closed *after* the connection is established. The `justrdp-dvc` crate
provides the framework; each concrete channel lives in its own crate
(`justrdp-egfx`, `justrdp-rdpei`, …).
_Spec_: MS-RDPEDYC

**MS-RDPE\* extensions**:
The Microsoft extension protocol family layered on top of SVCs/DVCs.
Acronym → crate mapping:
- **CLIP** (CLIPRDR) — `justrdp-cliprdr`
- **FS / DR** (RDPEFS / RDPDR) — `justrdp-rdpdr`
- **SND** (RDPSND) — `justrdp-rdpsnd`
- **EAI** (RDPEAI) — `justrdp-rdpeai`
- **GFX** (RDPEGFX) — `justrdp-egfx`
- **DYC** (RDPEDYC) — `justrdp-dvc`
- **RP** (RDPERP / RAIL) — `justrdp-rail`
- **I** (RDPEI) — `justrdp-rdpei`
- **EUDP / EMT** (RDPEUDP) — `justrdp-rdpeudp`
- **DISP** (RDPEDISP) — `justrdp-displaycontrol`
- **EV / EVOR / EGT / EDC / EMC / EPNP / ECAM** — each in the corresponding crate
The full mapping lives in roadmap §3 / §8.

---

### 3a. Pre-Active Handshake

**mstshash cookie**:
The routing token in the X.224 Connection Request
(`Cookie: mstshash=<user>\r\n`) — the entry point of RDP Negotiation.
_Spec_: MS-RDPBCGR §2.2.1.1

**RDP Negotiation Request / Response**:
Negotiates the security protocol (Standard / TLS / CredSSP / RDSTLS) inside
X.224. The result determines whether the connection enters NLA / Enhanced RDP
Security.
_Spec_: MS-RDPBCGR §2.2.1.1.1, §2.2.1.2.1

**Demand Active PDU / Confirm Active PDU**:
The server→client / client→server pair that negotiates **Capability Sets**,
immediately before entering **ActiveStage**.
_Spec_: MS-RDPBCGR §2.2.1.13

**License PDU**:
The licensing handshake. JustRDP only implements the minimal NoLicense flow;
full licensing is deferred (§G.1).
_Spec_: MS-RDPELE

**Connector** (`ClientConnector`):
The state-machine object for the pre-active handshake. Driven by repeatedly
calling `next_state`, which advances through X.224 → MCS → security →
capability negotiation. _Avoid_: bare "client" (ambiguous).

**ClientConnectorState**:
The enum representing **Connector** states. Every variant is either a
**Send state** or a **Wait state**.

**Sequence** (trait):
The base abstraction for **Connector** (`justrdp-connector::Sequence`). The
M-Server acceptor defines a *separate* trait of the same name
(`justrdp-acceptor::Sequence`) that follows the same shape — a mirrored
pattern, not shared identity.

**ConnectionResult / Written**:
The result of a completed handshake. `ConnectionResult` carries the negotiated
state needed to enter the active session; `Written` reports the number of
outbound bytes produced at each step.

**Send state / Wait state**:
The dichotomy of **ClientConnectorState**. A *Send* state produces outbound
bytes and transitions to the next *Wait*; a *Wait* state blocks on an inbound
PDU before transitioning to the next *Send* (or terminating). The
`is_send_state()` invariant in CLAUDE.md enforces this split.

**Config**:
The connection-level builder — bundles user / password / domain / security
protocol selection / Auto-Reconnect cookie / etc.

---

### 3b. Active Session & Reconnect

**ActiveStage**:
The post-handshake processor. Consumes a `ConnectionResult` and drives the
active-session PDU flow (fast-path, slow-path, channel data).
_Avoid_: bare "session" (ambiguous).

**ActiveStageOutput**:
The enum returned by `ActiveStage::process_pdu` — graphics update, channel
data, send-to-server, terminate, etc.

**DeactivationReactivation**:
The sequence triggered when the server temporarily deactivates and
reactivates the session for capability renegotiation (e.g. on a resolution
change).

**Server Redirection**:
A server directive instructing the client to silently reconnect to a different
host. Roadmap §9.3 ✅.
_Spec_: MS-RDPBCGR §2.2.13

**Auto-Reconnect Cookie** (`ArcCookie`):
The token used to reauthenticate-free reconnect to a dropped session.
Roadmap §9.2.

---

### 4. Security & Auth

**NLA (Network Level Authentication)**:
Pre-RDP authentication that validates credentials *before* the TLS handshake
completes. Built on **CredSSP**.

**CredSSP**:
The protocol underlying NLA — exchanges SPNEGO + NTLM/Kerberos tokens over
TLS.
_Spec_: MS-CSSP

**RDSTLS**:
Remote Desktop Services TLS authentication scheme — an authentication variant
used in RDS Gateway environments.
_Spec_: MS-RDPBCGR §5.4.5.3

**Standard / Enhanced RDP Security**:
- **Standard** — the legacy RC4-based RDP-native encryption (pre-TLS).
  Required only by legacy servers.
- **Enhanced** — TLS / CredSSP-based transport. The default in JustRDP.
_Spec_: MS-RDPBCGR §5.3 / §5.4

**NTLM / Kerberos / SPNEGO**:
The GSS providers under **CredSSP**. JustRDP implements NTLM directly
(`justrdp-pdu::ntlm`); Kerberos is delegated to platform-native APIs
(Windows SSPI).
_Spec_: MS-NLMP / RFC 4120 / RFC 4178

---

### 5. I/O Paths & Content

**Capability Set**:
A negotiated feature block — Bitmap, Pointer, Sound, Order, etc.
_Spec_: MS-RDPBCGR §2.2.7

**Share ID**:
A session-scoped identifier — the routing key for Share Data PDUs.
_Spec_: MS-RDPBCGR §2.2.1.13.1

**Fast-Path**:
A single-byte-header optimised I/O path. Comes in two variants — *Input*
(client→server) and *Output* (server→client).
_Spec_: MS-RDPBCGR §2.2.8.1.2 / §2.2.9.1.2

**Slow-Path**:
The Share-Data-PDU-based standard path. *Used only as a foil to Fast-Path.*

**Bitmap Update**:
The most common screen-update PDU — the default graphics path before
RemoteFX.
_Spec_: MS-RDPBCGR §2.2.9.1.1.3.1.2

**Drawing Order**:
GDI primitives (OpaqueRect, LineTo, GlyphIndex, …) — more expressive than
Bitmap Update.
_Spec_: MS-RDPEGDI

**Pointer Update**:
Cursor sprite / position / shape changes. Roadmap §6.7.
_Spec_: MS-RDPBCGR §2.2.9.1.1.4

**Surface Bits Command**:
The main payload of the **RDPEGFX** graphics pipe — the *modern replacement*
for Bitmap Update.
_Spec_: MS-RDPEGFX §2.2.2

---

### 6. Compression & Codecs

**MPPC / NCRUSH / XCRUSH**:
The RDP bulk compression algorithm family — the heart of the `justrdp-bulk`
crate.
- **MPPC** — RDP 5.0 baseline
- **NCRUSH** — RDP 6.0+ improved compression
- **XCRUSH** — RDP 8.0 (egfx) compression
_Spec_: MS-RDPBCGR §3.1.8 / MS-RDPEGFX §3.1.8

**RemoteFX (RFX) / NSCodec / ClearCodec**:
The modern image-codec family (RFX is dominant). All hosted in the
`justrdp-graphics` crate, alongside H.264/AVC in its `avc` module.
_Spec_: MS-RDPRFX / MS-RDPNSC / MS-RDPCCC

---

### 7. Runtime Surfaces

**`justrdp_blocking::RdpClient`**:
The synchronous runtime. **Frozen as of §5.6.5** — bug fixes only, no new
surface. New work goes to **AsyncRdpClient v2**. _See_: ADR-0004.

**AsyncRdpClient v1 / v2**:
The async runtime in the `justrdp-tokio` crate.
- **v1** — the initial design wrapping `RdpClient` via `spawn_blocking`.
  *Deprecation pending.*
- **v2** — pure-async, no thread split. The result of §5.6 Phases 1–4. The
  default for new work. _See_: ADR-0004.

**WebClient**:
The runtime surface in the `justrdp-web` crate (WASM) — the browser-side
counterpart of **AsyncRdpClient**.

**RdpEvent**:
The unified event enum produced by the **Pump** — graphics update, pointer
position, channel data, terminate, etc.

**ReconnectPolicy**:
The auto-reconnect policy enum. Defined separately in `justrdp-blocking` and
`justrdp-async` (each binds to its own runtime context).

**Transport family**:
The transport abstraction consumed by **AsyncRdpClient v2**:
- `NativeTcpTransport` — raw TCP
- `NativeTlsTransport` — rustls-based TLS
- `NativeTlsOsTransport` — OS-native TLS (Windows SChannel, macOS
  SecureTransport)
- `NativeCredsspDriver` — the CredSSP/NLA adapter
- (custom) `WebTransport` — browser WebSocket etc.; documented in roadmap
  §13.6.

**Pump**:
The canonical name for the
`while let Some(ev) = client.next_event().await { … }` loop. An **Embedder**
MUST drive this loop on its own task.

---

### 8. Project Organization

**M-Client / M-Server**:
The two milestones the roadmap is split into. Every roadmap item carries one
of `[both]` / `[M-Client]` / `[M-Server]`. M-Client ships first; M-Server
work begins at §11. _See_: ADR-0005.

**Phase 1–8**:
The roadmap's *work-stage* split — Foundation (1) → Connection & Auth (2) →
Standalone Codecs (3) → Session Core & Channel Frameworks (4) → Channel
Implementations (5) → Advanced Features (6) → Transport Extensions (7) →
Server-Side & Ecosystem (8).

**Shipping surface**:
The public surface frozen by v2. Both the v1→v2 migration guide (§13.5) and
the custom-transport guide (§13.6) assume this surface only.

**Embedder**:
A *role*, not a concrete trait — a Tauri / native-UI / WASM host that *carries
around* the RDP library. §13.4 defines the standard pattern; `justrdp-tauri/`
is the reference implementation.

**Native surface**:
A *role*, not a single trait — the platform-facing seam inside each
`*-native` crate. Examples:
`justrdp-rdpsnd-native::NativeAudioOutput`,
`justrdp-rdpeai-native::AudioCaptureBackend`,
`justrdp-cliprdr-native::NativeClipboardSurface`,
`justrdp-rdpdr-native::FilesystemSurface`.
A Native surface speaks only platform-level vocabulary (UTF-8 strings,
DIB byte arrays, file handles, byte ranges); the surrounding `-native`
wrapper handles all RDP-protocol-specific encoding. Dual to **Embedder**:
an Embedder is the *RDP-library-consuming* role; a Native surface is
the *OS-binding* role inside a channel implementation. _See_: ADR-0006.

---

## Relationships

- An **AsyncRdpClient v2** owns one **Connector** (during the handshake) and
  produces one **Pump** stream of **RdpEvent**.
- A **Connector** transitions between **Send state** and **Wait state**; the
  `is_send_state()` invariant enforces this dichotomy.
- **CredSSP** is the protocol underlying **NLA**; **RDSTLS** is an alternative
  selected via the **RDP Negotiation Request**.
- A **DVC** rides on top of one specific **SVC** (`DRDYNVC`); other **SVC**s
  carry their own protocols (CLIPRDR, RDPSND, …).
- **Server Redirection** triggers a reconnect flow that consumes an
  **Auto-Reconnect Cookie**.
- An **Embedder** consumes **AsyncRdpClient v2** + **Pump** + **RdpEvent**;
  never **Connector** directly.
- **M-Client** depends on **Connector** + **ActiveStage** + the runtime
  surfaces; **M-Server** mirrors the **Sequence** pattern via the §11.1
  acceptor (separate trait, same shape).
- **Surface Bits Command** supersedes **Bitmap Update** when the **RDPEGFX**
  capability is negotiated; the **Drawing Order** path is independent and
  slower.
- Each `*-native` crate exposes one **Native surface** trait that its
  platform modules implement; the surrounding wrapper struct converts the
  channel's protocol vocabulary (e.g. `LongFormatName`,
  `FileContentsRequestPdu`) into and out of the Native surface's
  platform-level vocabulary.

---

## Example dialogue

**Channel ambiguity**

> **Dev:** "Which channel does the RFX output arrive on?"
> **Domain expert:** "You can't just say *channel*. RFX (= a **Surface Bits
> Command** inside **RDPEGFX**) arrives on a **DVC**. The old **Bitmap
> Update** would have arrived on the default I/O **MCS channel**, but a
> **DVC** and an **MCS channel** are 'channels' at different layers — the
> **DRDYNVC** SVC bridges the two."

**Client ambiguity**

> **Dev:** "When the client connects…"
> **Domain expert:** "*Which* client? `ClientConnector` (the state machine)
> toggles between Send state and Wait state. **AsyncRdpClient v2** is the
> *runtime surface* the **Embedder** carries around. 'RDP client' as a *role*
> is the **M-Client** milestone. Three different layers."

---

## Flagged ambiguities

- **"Channel"** — MCS channel / **SVC** / **DVC**. Always qualify.
- **"Client"** — `ClientConnector` (state machine) /
  `justrdp_blocking::RdpClient` (frozen) / **AsyncRdpClient v2** (default
  runtime) / "RDP client as a role" (= **M-Client**). Four meanings.
- **"Session"** — **ActiveStage** (post-handshake processor) / "RDP session"
  (the full lifecycle) / `SessionConfig` (a config struct). Three meanings.

---

## Deferred from glossary

The following terms are intentionally undefined for now. Add lazily as the
roadmap advances.

- **Smartcard / PKINIT** — add when roadmap §9.6 begins
- **TSGU / RD Gateway** — add when roadmap §10.1 begins
- **RDPEUDP / Multitransport** — add when roadmap §10.2–3 begins
- **Synchronize PDU / Control PDU** — sub-steps of Demand/Confirm Active.
  Absorbed into those entries; no separate term.
- **Scancode / Unicode keyboard input** — owned by the `justrdp-input` crate's
  own docs.
