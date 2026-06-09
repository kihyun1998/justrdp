# Plan — a from-scratch RDP client package in Rust

> **What this is.** A *reference map* of every subsystem an interactive RDP client needs,
> derived by surveying the `ironrdp` crates + the MS-RDP open specs (6 parallel sub-agents,
> 2026-06-08). **We are NOT copying ironrdp** — we use it only to answer "what pieces exist
> and which are load-bearing," so nothing becomes a surprise bottleneck later (the way the
> EGFX `SUPPORT_DYN_VC_GFX_PROTOCOL` flag did).
>
> **How to use it.** This is the backlog scaffold to **grill** and **slice into issues**.
> Every line is a candidate subsystem. Nothing is omitted — niche items are listed and marked
> **[O]ptional** rather than dropped. `M` = Mandatory for a basic interactive desktop client,
> `O` = Optional / add-on feature. "ironrdp ref" names where ironrdp does it (reference only).
>
> **Scope note.** Target = modern Windows Server with NLA mandatory, single interactive
> desktop. Server-side, RAIL, multi-monitor, UDP are explicitly out of the first cut (still
> listed, marked `O`, so they're tracked not forgotten).

---

## Decisions (locked while grilling — 2026-06-08)

These supersede the matching open questions in §10.

1. **Goal = a full from-scratch RDP client to *replace* ironrdp** (not a thin connector fork).
   The entire plan (§2–§23) is the backlog; this is the multi-month long-tail path, accepted
   knowingly. *(resolves §10 Q1/Q2 → option **a**.)*
2. **Dependency boundary = own all RDP-specific protocol; depend on leaf, non-RDP libs.**
   Reuse `rustls` (TLS) and **`sspi`** (NLA crypto: CredSSP / SPNEGO / NTLMv2 / Kerberos /
   channel bindings) verbatim — reimplementing them is out of scope (security-critical, not
   RDP-specific, and free of the protocol-negotiation "hardcoded-flag" bottleneck that motivated
   this rebuild). We own X.224 / MCS / GCC / capability exchange / activation / session loop /
   virtual channels / surface model. *(resolves §10 Q13.)*
3. **Codecs = owned, but phased ("phased-c2").** RemoteFX / RemoteFX Progressive / ClearCodec /
   NSCodec / zgfx decode is RDP-specific and will be **owned**. Bootstrap by *depending* on
   `ironrdp-graphics` so rendering works immediately; then rewrite each codec ourselves using
   `ironrdp-graphics` as a **differential test oracle** (same input → byte-identical pixels,
   §21) until the dependency can be dropped. `sspi` (NLA crypto) and `rustls` (TLS) stay
   **permanent** deps — not RDP-specific, security-critical, "don't roll your own crypto."
   *(refines §10 Q3; Q9 is now "validate `reconstruct_to_rgba` as the oracle," not "build it.")*
4. **Core architecture = sans-IO state machine + thin I/O adapter (d1).** `connect` and `session`
   are pure state machines (bytes in → actions/bytes out); a ~30-line tokio loop drives the
   socket. Unlocks the differential-oracle codec testing (feed identical bytes to us *and*
   ironrdp), multi-runtime portability (tokio/blocking/wasm), per-stage timeout/cancel at the
   adapter, and host isolation (the ADR-0004 analog). *(new.)*
5. **Home = a new repo `kihyun1998/justrdp` (`D:/github/justrdp`), a Cargo workspace.** This repo
   (`test-ironrdp-client`) is a **throwaway scratchpad** whose only job was to author this
   plan.md; it is discarded once plan.md lands in justrdp. The **differential test oracle for
   phased-c2 is the `ironrdp-*` crates pulled as dev-dependencies in justrdp** (diff our decode
   vs theirs on identical bytes) — NOT this repo. justrdp already carries the agent-skills
   scaffold (issues on `kihyun1998/justrdp`, single `CONTEXT.md` + `docs/adr/`). *(resolves §10
   Q1 repo half + Q14 cadence → same AFK-agent → gate loop, now against justrdp.)*
6. **Workspace split = pragmatic 3+1 (e2), split finer when a boundary proves itself.** Crates:
   `justrdp-pdu` (wire encode/decode + every PDU; sans-IO, depends only on a tiny core), `justrdp`
   (the sans-IO core: connector + session state machines + channel processors + surface model),
   `justrdp-codecs` (phased-c2: re-exports `ironrdp-graphics` now, self-owned later). Add
   `justrdp-tokio` (the ~30-line I/O adapter) once the I/O loop materialises. Spin out per-channel
   / `-svc` / `-dvc` crates **only when** a boundary actually hardens — not upfront. *(resolves
   §10 Q1 workspace half.)*
7. **slice-1 = (f1) TCP + X.224 security negotiation** — the thinnest tracer bullet that stands up
   the whole skeleton (`justrdp-pdu` TPKT/X.224, the sans-IO core, the `justrdp-tokio` adapter, the
   workspace, the differential-vs-ironrdp + real-VM test harness). It is the **root of the slice
   chain, not the scope.** Subsequent slices walk the connect sequence (TLS → NLA → MCS/GCC/join →
   license/capability/activation → session-active), then render (slow-path bitmap → FrameUpdate),
   input, drdynvc + Display Control, then EGFX + RemoteFX/Progressive (the perf win), then the §O
   long tail. **"Complete" = the full plan.md M/O backlog**, dialled by how far down §O you go;
   f1 just sequences it safely. *(resolves §10 — MVP slice-1.)*
8. **AVC/H.264 decode = a pluggable `AvcDecoder` trait, NOT an owned codec.** Unlike RemoteFX /
   Progressive / ClearCodec / zgfx (owned outright via phased-c2, ADR-0003), H.264 is
   patent-encumbered and its best backend is platform-dependent — so the core defines an
   `AvcDecoder` trait (AVC bytes → RGBA) that the EGFX path calls, and the **backend is supplied,
   not built-in**: a C lib (openh264/ffmpeg), an OS-API Platform-FFI backend (Windows Media
   Foundation / macOS VideoToolbox / Linux VAAPI), or none — chosen at the H.264 slice, behind the
   trait. justrdp ships **no** AVC decoder by default; absent one, AVC frames are skipped (the
   server falls back to RemoteFX/Progressive). The other codecs are NOT traited — they're
   pure-Rust, patent-free, platform-invariant, so phased-c2 owns them directly. Mirrors how ironrdp
   (`H264Decoder` trait + optional `openh264` feature) and the prior justrdp (`AvcDecoder` trait)
   both shaped it. *(new — the trait seam plan.md §7/§11i/§23 already imply.)*
9. **TLS boundary = the handshake runs in the adapter; the machine owns the `tls-handshake`
   *stage* and the cert→`subjectPublicKey` extraction (slice-2).** rustls is itself a sans-IO
   state machine, so shuttling its records through `ConnectStateMachine` would add nothing — the
   handshake stays in `justrdp-tokio` (this refines §3's "TLS upgrade happens *outside* the
   connector state machine"). But the machine is **not** bypassed: on a valid X.224 confirm it
   emits `Action::StartTls`, advances into the `tls-handshake` stage, and after the adapter runs
   the handshake it feeds the server's leaf certificate back via `Event::TlsEstablished`. The
   machine then extracts the `subjectPublicKey` (DER `SubjectPublicKeyInfo`, via the leaf
   `x509-cert` dep — ADR-0002) — a pure, CI-testable step — and emits `Action::Proceed {
   selected, server_public_key }` for CredSSP to bind to next. This reconciles issue #2 ("a
   `TlsUpgrade` state that accepts the cert and yields `subjectPublicKey`") with §3 ("handshake
   outside the machine"): TLS *records* never enter the machine, but the TLS *stage* and the cert
   it produces do. slice-2 accepts any cert (validate=false); chain/name validation + TOFU
   pinning are later slices (§22). *(new — resolves the issue #2 ↔ §3 boundary conflict.)*

## 0. Traps already PROVEN on the real VM this session (do not re-discover)

These cost real time to find. Bake them into the design from day one.

- **EGFX gate flag.** A server opens the Graphics Pipeline DVC **only if** the client sets
  `ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL` (**0x0100**) in the Client Core
  Data `earlyCapabilityFlags` (GCC). Proven: flag off → channel never opens; flag on → server
  immediately streams. **ironrdp-connector 0.9.0 hardcodes this list and omits the flag, with
  no config knob** — the single reason EGFX is unreachable on stock ironrdp. Our crate MUST
  make `earlyCapabilityFlags` fully caller-controlled.
- **The codec this server actually uses is RemoteFX *Progressive* (`WireToSurface2`)** — not
  H.264, not Uncompressed. Confirmed by live capture. β scope (Progressive, no external
  decoder) is the right target; H.264/AVC needs a separate AVC decoder **backend — undecided**
  (a C lib like openh264/ffmpeg, an OS-API Platform-FFI backend like WMF/VideoToolbox/VAAPI, or
  skip it — RemoteFX/Progressive carry the desktop; don't hardcode openh264).
  **Correction verified in source (this sweep):** ironrdp-graphics 0.8 has a *near-complete*
  Progressive decoder — `TileState` (cross-pass coefficient/sign store, progressive.rs:687),
  `decode_first`/`decode_upgrade` (736/775), `reconstruct_to_rgba` (810, full inverse DWT +
  YCbCr→RGB), and a `SurfaceTiles` grid (866). So β is mostly *wiring* WireToSurface2 → these
  → FrameUpdate, **not** implementing the codec (the earlier "primitives-only / unknown
  completeness" worry was wrong).
- **HYBRID_EX early-auth PDU.** A HYBRID_EX server sends a 4-byte LE **Early User Authorization
  Result** PDU immediately after CredSSP, *before* MCS. If not consumed, capability exchange
  desyncs and hangs.
- **Resize = Deactivation–Reactivation.** A display-size change triggers the server to send
  **DeactivateAll** → re-run capability exchange + activation → new desktop size. The session
  loop must drive this **cancel-aware** (teardown must not hang) and rebuild the framebuffer.
- **CredSSP pubKeyAuth binds to the cert `subjectPublicKey`** (FreeRDP/IronRDP convention),
  not the whole certificate.
- **`write` is not cancel-safe** in an async session loop (ironrdp's `Framed::write_all`):
  interrupting a partial write and retrying duplicates bytes. `read_pdu` IS cancel-safe.

---

## 1. Capability → feature couplings (the anti-bottleneck table)

The core lesson of this session: **features are gated by flags advertised early.** If you don't
advertise X, the server silently never offers Y. Capture every such coupling up front.

| Advertise (client) | …to unlock (server will otherwise never send) |
|---|---|
| `SUPPORT_DYN_VC_GFX_PROTOCOL` (0x0100) in earlyCapabilityFlags | **EGFX** graphics pipeline (H.264 / RemoteFX Progressive / ClearCodec over DVC) |
| `WANT_32_BPP_SESSION` (0x0002) | 32-bit colour session (overrides high_color_depth / supported_color_depths) |
| `SUPPORT_MONITOR_LAYOUT_PDU` (0x0040) | server-pushed dynamic monitor-layout changes |
| `SUPPORT_NET_CHAR_AUTODETECT` (0x0080) | network auto-detect (RTT/bandwidth probing) |
| `RELATIVE_MOUSE_INPUT` (0x0010) | relative (delta) mouse mode |
| `SUPPORT_ERR_INFO_PDU` (0x0001) | detailed typed disconnect reasons (Set Error Info PDU) |
| `SUPPORT_HEART_BEAT_PDU` (0x0400) | server heartbeat / keep-alive |
| `SUPPORT_DYNAMIC_TIME_ZONE` (0x0200) | live timezone change without reconnect |
| `SUPPORT_STATUS_INFO_PDU` (0x0004) | server Status Info PDUs (connection progress/status) |
| `STRONG_ASYMMETRIC_KEYS` (0x0008) | server may use 2048+-bit RSA (mostly moot under TLS) |
| `VirtualChannel` capset `DRDYNVC_SUPPORTED` | any dynamic virtual channel at all |
| `SurfaceCommands` capset | GPU/surface-bits rendering path (vs legacy orders/bitmaps) |
| `BitmapCodecs` capset (RFX/Progressive/NSCodec/…) | which codecs the server may compress with |
| `Order` capset per-order flags | each RDP drawing-order type (omit a flag → server won't send it) |
| static channel `ChannelDef` in Client Network Data (CLIPRDR/RDPSND/RDPDR/…) | that SVC being created |
| Input capset flags (`MOUSEX`, `FASTPATH_INPUT`, `UNICODE`, `TS_MOUSE_HWHEEL`, …) | each input feature |

> **Design rule:** make ALL of the above caller-configurable, default to "advertise everything
> we can actually handle." The bottleneck risk is always a *missing* advertise, never an extra.

---

## 2. Layer 0 — Wire encoding & framing foundation  *(everything sits on this)*

- [ ] **M — Encode/Decode framework.** Object-safe `Encode`/`Decode` traits, `ReadCursor`/`WriteCursor` (LE default, `*_be` variants), `WriteBuf`, typed error model (`NotEnoughBytes`/`InvalidField`/`UnexpectedMessageType`/`UnsupportedVersion`/…). *ironrdp ref: `ironrdp-core` (encode.rs, decode.rs, cursor.rs, write_buf.rs, error.rs).* Zero-copy, explicit position, `peek` without advancing.
- [ ] **M — TPKT framing (RFC 1006).** 4-byte header [version=3, reserved, len_be(u16)]. *ironrdp ref: ironrdp-pdu/tpkt.rs.*
- [ ] **M — X.224 TPDU.** [LI, code] CONNECT(0xe0)/DATA(0xf0)/DISCONNECT(0x80); `X224<T>` wrapper auto-handles TPKT+TPDU. *ironrdp ref: ironrdp-pdu/x224.rs, tpdu.rs.*
- [ ] **M — Fast-Path framing.** 1-byte action/flags [action(2) | frag(2) | enc(2)], PER length (1–2 bytes), `UpdateCode` + `Fragmentation`. Bit-level, not byte-aligned. *ironrdp ref: ironrdp-pdu/basic_output/fast_path, fast_path.rs.*
- [ ] **M — PER (Packed Encoding Rules).** Variable-length integers/lengths (fast-path + GCC). *ironrdp ref: ironrdp-pdu/per.rs.*
- [ ] **M — ASN.1 BER.** For MCS/GCC (Pc/Class/Tag, length encoding). *ironrdp ref: ironrdp-pdu/ber.rs, mcs.rs.* GCC is a binary blob inside MCS userData.

---

## 3. Layer 1 — Connection sequence  *(TCP → session-active)*

- [ ] **M — X.224 Connection Request/Confirm + security negotiation.** RDP_NEG_REQ/RSP; advertise SSL|HYBRID|HYBRID_EX|RDSTLS|RDSAAD; optional routing token/cookie. *ironrdp ref: ironrdp-pdu/nego.rs, connector/connection.rs.* No RC4 "Standard Security" (deprecated/unsupported).
- [ ] **M — TLS upgrade.** rustls handshake after X.224 confirm if SSL/HYBRID selected; extract server `subjectPublicKey`. *Cert validation is the client's job (see Layer 2).* Happens *outside* the connector state machine.
- [ ] **M — CredSSP / NLA** *(see Layer 2 for internals)* + **Early User Authorization Result** (HYBRID_EX only, 4 bytes LE, consume before MCS).
- [ ] **M — MCS Connect-Initial / Connect-Response + GCC Conference Create.** Carries all Client GCC blocks (Layer 3). T.125 ASN.1. *ironrdp ref: ironrdp-pdu/mcs.rs, gcc/; connector/connection.rs::create_gcc_blocks.* Advertise all colour depths; Network block omittable if no channels.
- [ ] **M — Channel join.** Erect Domain → Attach User (returns user channel id) → Channel Join (per static channel, batched in RDP 8.1+). *ironrdp ref: connector/channel_connection.rs.* Skippable if server sets `SKIP_CHANNELJOIN_SUPPORTED`. User channel id is the initiator for all later Share Data.
- [ ] **M — Client Info PDU (TS_INFO_PDU).** Client name, credentials, autologon, keyboard layout, timezone, performance flags, compression, build/version, alt-shell. *ironrdp ref: ironrdp-pdu/rdp/client_info.rs.*
- [ ] **O — Connect-time auto-detect.** Server RTT/bandwidth probe → response (UDP/multitransport adaptation). ironrdp skips it. Needed only if you do `SUPPORT_NET_CHAR_AUTODETECT`/UDP.
- [ ] **M — Licensing exchange (MS-RDPELE).** Server License Request → client New/Info License Request → Platform Challenge → Response → License OK. Optional persistent license cache (client-supplied). *ironrdp ref: ironrdp-pdu/rdp/server_license.rs, connector/license_exchange.rs.* Must complete or capability exchange blocks.
- [ ] **M — Capability exchange.** Server **Demand Active** (capsets + share_id + negotiated desktop size) → client **Confirm Active**. *ironrdp ref: ironrdp-pdu/rdp/capability_sets.rs, connector/connection_activation.rs.* A **DeactivateAll may arrive here** (some servers) — decode & discard, keep waiting for Demand Active. Use the *negotiated* size for the framebuffer.
- [ ] **M — Connection finalization.** Client pipelines Synchronize → Control(Cooperate) → Control(RequestControl) → Font List; server replies Sync/Control(Cooperate)/Control(GrantedControl)/**Font Map**. Font Map = session-active gate. *ironrdp ref: ironrdp-pdu/rdp/finalization_messages.rs, connector/connection_finalization.rs.*
- [ ] **M — Session-active base state.** Bidirectional I/O begins (input out; graphics/pointer/channel/error in). *ironrdp ref: connector `ConnectionResult` (io/user channel ids, share_id, static_channels, desktop_size, compression).*
- [ ] **M — Deactivation–Reactivation sequence.** Server DeactivateAll → re-run capability exchange + finalization → (possibly new) desktop size; rebuild framebuffer; in-session (no reconnect). *ironrdp ref: connector/connection_activation.rs (reset).* **Most common trigger = resize.** Drive cancel-aware.

---

## 4. Layer 2 — Authentication & transport security

- [ ] **M — TLS (rustls).** Server cert handling; **public key = cert `subjectPublicKey` (DER)** for CredSSP binding. Validation (CN/SAN, chain, pinning, revocation) is ours — ironrdp provides none. Install a crypto provider first.
- [ ] **M — CredSSP / TSRequest (MS-CSSP).** version, nego_tokens, auth_info, pub_key_auth, client_nonce. **pubKeyAuth** = SHA256(magic ‖ client_nonce ‖ public_key) for v≥5 (legacy = echo). BER-encoded. *ironrdp ref: sspi::credssp::{CredSspClient, TsRequest}; connector/credssp.rs.* Magic strings are fixed 38-byte null-terminated constants.
- [ ] **M — SPNEGO (MS-SNEGO).** NegTokenInit/NegTokenTarg wrapping Kerberos→NTLM by OID preference; mechListMIC (Kerberos only). *ironrdp ref: sspi::Negotiate; picky_krb::gss_api.* Tokens are wrapped, not bare.
- [ ] **M — NTLM (MS-NLMP).** Type1/2/3, NTLMv2 only, MIC (HMAC-MD5 over all 3), signing/sealing keys, RC4 seal. Channel-binding AV pair (type 10). *ironrdp ref: sspi::Ntlm.* Per-direction sequence numbers.
- [ ] **O — Kerberos (MS-KILE).** AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP in SPNEGO; KDC discovery (DNS SRV / proxy); SPN `TERMSRV/host`; channel bindings in checksum. *ironrdp ref: sspi::Kerberos; picky_krb.* Optional for workgroup; preferred in AD. Needs KDC reachability (TCP 88).
- [ ] **M — Channel bindings.** SEC_CHANNEL_BINDINGS (TLS peer info / cert hash) into NTLM AV pair + Kerberos checksum — prevents TLS-strip MITM. *ironrdp ref: sspi ChannelBindings.*
- [ ] **M — TSCredentials / delegation.** TSPasswordCreds (domain/user/pass UTF-16) encrypted+signed in TsRequest.auth_info, sent only after auth completes. *ironrdp ref: sspi write/read_ts_credentials.*
- [ ] **M — Security-protocol negotiation outcomes.** SSL / HYBRID / HYBRID_EX / RDSTLS / RDSAAD selection + FailureCodes. *ironrdp ref: ironrdp-pdu SecurityProtocol.* HYBRID_EX ⇒ Early User Auth PDU.
- [ ] **M — Early User Authorization Result (HYBRID_EX).** 4 bytes LE: 0=granted, 5=denied. *ironrdp ref: connector CredsspState::EarlyUserAuthResult.*
- [ ] **M — SSPI architecture.** acquire_credentials → initialize_security_context loop (multi-roundtrip state machine) → encrypt/decrypt/sign once finalized; KDC network requests yielded to caller. *ironrdp ref: the `sspi` crate.*
- [ ] **O — Smartcard / PK-INIT (MS-PKCA).** Cert+key from card, PIN, PA-PK-AS-REQ/REP. *ironrdp ref: sspi `scard` feature (Windows winscard).*
- [ ] **O — Restricted Admin / Remote Credential Guard.** Credential-less CredSSP (RequestFlags). *ironrdp ref: sspi CredSspMode::CredentialLess.*
- [ ] **— RC4 / Standard RDP Security.** Legacy, broken, **not supported** — enforce TLS.

---

## 5. Layer 3 — Capability sets & GCC config  *(the negotiation surface)*

### 5a. Capability sets (full catalog — advertise everything we can handle)
- [ ] **M** — General (0x01): platform, version, extraFlags (FASTPATH_OUTPUT, NO_BITMAP_COMPRESSION_HDR, LONG_CREDENTIALS, AUTORECONNECT, ENC_SALTED_CHECKSUM), refresh-rect / suppress-output support.
- [ ] **M** — Bitmap (0x02): desktop w/h, colour depth, tile cache flags.
- [ ] **M** — Order (0x03): which drawing orders the client understands (per-order flags gate server sends).
- [ ] **M** — BitmapCache (0x04) **or** BitmapCacheRev2 (0x13): server chooses; both decode.
- [ ] **M** — Pointer (0x08); **M** — Input (0x0d); **M** — Brush (0x0f); **M** — GlyphCache (0x10); **M** — OffscreenBitmapCache (0x11); **M** — VirtualChannel (0x14, `DRDYNVC_SUPPORTED`); **M** — Sound (0x0c).
- [ ] **O** — Control (0x05), WindowActivation (0x07), Share (0x09), Font (0x0e), ColorCache (0x0a), BitmapCacheHostSupport (0x12), DesktopComposition (0x19, DWM/alpha), MultiFragmentUpdate (0x1a, large screens), LargePointer (0x1b), **SurfaceCommands (0x1c, GPU/surface path)**, **BitmapCodecs (0x1d, RFX/Progressive/NSCodec/QOI/QOIZ)**, FrameAcknowledge (0x1e, pacing).
- [ ] **O/deprecated** — DrawNineGridCache (0x15), DrawGdiPlus (0x16), Rail (0x17), WindowList (0x18), BitmapCacheV3 codec id (0x06). *ironrdp ref: ironrdp-pdu/rdp/capability_sets/*.*

### 5b. GCC client data blocks
- [ ] **M** — Client Core Data (0xC001): version, desktop w/h, colour depth, keyboard (layout/type/subtype/fkeys/IME), client name/build, **+ ordered optional tail incl. `early_capability_flags`** (see §1), product id, connection type, server_selected_protocol, physical dims, orientation, **desktop_scale_factor / device_scale_factor (DPI)**.
- [ ] **M** — Client Security Data (0xC002): encryption methods (usually empty under TLS).
- [ ] **O** — Client Network Data (0xC003): static channel `ChannelDef` list (omit if none). *This is how SVCs get created.*
- [ ] **O** — Cluster (0xC004, redirection) — *ironrdp TODO #139*; Monitor (0xC005, multimon); Monitor Extended (0xC008, per-monitor DPI); Message Channel (0xC006) — *ironrdp TODO #140*; MultiTransport (0xC00A, UDP/GFX flags).
- [ ] **M** — **earlyCapabilityFlags: make ALL 12 flags caller-settable** (see §1 table). This is the anti-bottleneck linchpin. *ironrdp ref: ironrdp-pdu/gcc/core_data/client.rs.*

### 5c. Cross-cutting config
- [ ] **O** — Multi-monitor (≤16), per-monitor coords/physical/orientation/scale + runtime Monitor Layout PDU.
- [ ] **M** — DPI / scale (desktop_scale 100–500%, device_scale 0/100, physical mm).
- [ ] **M** — Keyboard layout (LCID), type/subtype, fkeys, IME name.
- [ ] **M** — Colour-depth negotiation (high_color_depth + supported_color_depths + WANT_32_BPP_SESSION; legacy post_beta2/color_depth fallbacks).
- [ ] **M** — Compression-type selection (General flags, fast-path CompressionType RDP4–8, BitmapCodecs).
- [ ] **M** — Performance flags (wallpaper/themes/font-smoothing/menu-anim), client id/build/platform.

---

## 6. Layer 4 — Input & live session I/O

### 6a. Input (out)
- [ ] **M** — Fast-path input PDU (preferred): event types ScanCode/Mouse/MouseX/Sync/Unicode/MouseRel/QoeTimestamp; compact (type 3b + flags 5b); num_events spill rule. *ironrdp ref: ironrdp-pdu/input/fast_path.rs.*
- [ ] **M** — Slow-path Input Event PDU (fallback): eventTime(0)+type+payload, batched. *ironrdp ref: ironrdp-pdu/input/mod.rs.*
- [ ] **M** — Keyboard scancode (set-1, EXTENDED/EXTENDED_1, DOWN/RELEASE). *ironrdp ref: input/scan_code.rs.*
- [ ] **M** — Unicode keyboard (UTF-16 BMP; surrogate pairs = 2 events) for IME/dead-keys. *ironrdp ref: input/unicode.rs.*
- [ ] **M** — Keyboard sync/toggle (caps/num/scroll/kana) on activation + LED change. *ironrdp ref: input/sync.rs.*
- [ ] **M** — Mouse (absolute coords; move/buttons; vertical wheel; `MIDDLE_BUTTON_OR_WHEEL` overload). *ironrdp ref: input/mouse.rs.*
- [ ] **O** — MouseX (X-buttons 4/5; needs `MOUSEX` capability). *input/mouse_x.rs.*
- [ ] **O** — MouseRel (relative deltas; needs `MOUSE_RELATIVE`). *input/mouse_rel.rs.*
- [ ] **M** — **Scancode mapping OS→set-1** (Windows VK / Linux evdev+XKB / macOS / browser KeyboardEvent.code). *Not in ironrdp — we own it.* Extended-key prefix → EXTENDED flag; Shift doesn't change scancode.
- [ ] **M** — Input capability negotiation (SCANCODES/MOUSEX/FASTPATH_INPUT/UNICODE/MOUSE_RELATIVE/TS_MOUSE_HWHEEL/TS_QOE_TIMESTAMPS + keyboard layout/type). *capability_sets/input.rs.*

### 6b. Session loop & inbound
- [ ] **M** — Active stage / session loop: dispatch inbound Action::FastPath vs X224; emit outputs (graphics/pointer/terminate/response); async framing; **cancel-aware teardown** (read cancel-safe, write NOT). *ironrdp ref: ironrdp-session/active_stage.rs, ironrdp-async/framed.rs.* No bundled loop — we write it.
- [ ] **M** — Inbound PDU dispatch: fast-path update (bitmap/pointer/surface/palette, fragmented+compressed) vs slow-path ShareData. *ironrdp ref: session/fast_path.rs, session/x224/mod.rs.*
- [ ] **M** — Fast-path output processing: fragmentation reassembly (Single/First/Next/Last) + bulk decompression. *ironrdp ref: session/fast_path.rs.*
- [ ] **M** — Server-initiated disconnect reasons: MCS Disconnect Provider Ultimatum + Set Error Info PDU (typed, 80+ codes) vs abrupt EOF. *ironrdp ref: ironrdp-pdu/rdp/server_error_info.rs, session/x224.*
- [ ] **M** — Error classification in-session (decode vs protocol vs I/O vs decompression; unknown PDU = warn+continue, decompression fail = fatal).
- [ ] **O** — Graceful Shutdown Request/Denied (then MCS ultimatum). *session/active_stage.rs.*
- [ ] **O** — Refresh Rect PDU (redraw regions after unobscure). *rdp/refresh_rectangle.rs.*
- [ ] **O** — Suppress Output PDU (pause graphics when minimized). *rdp/suppress_output.rs.*
- [ ] **O** — Auto-Reconnect Cookie (server cookie at logon → resume on reconnect). *rdp/session_info/logon_extended.rs.*
- [ ] **O** — Heartbeat / keep-alive (RTT responses or periodic no-op; idle-timeout ~5min).
- [ ] **O** — Reconnect-with-resume (vs in-session DeactivateAll).

---

## 7. Layer 5 — Graphics & codecs  *(server graphics → pixels)*

- [ ] **M** — Framebuffer / decoded-image model: RGBA target, pixel-format abstraction (RGBA/BGRA/ARGB/… channel offsets), pointer overlay save/restore, stride. *ironrdp ref: ironrdp-session/image.rs (decode-complete).* Bottom-up legacy bitmaps.
- [ ] **M** — Colour formats / pixel depth: 8 (palette)/15(555)/16(565)/24/32; non-linear 15/16→8 scaling; palette lookup. *ironrdp ref: graphics/color_conversion.rs, session/palette.rs.*
- [ ] **O** — Legacy slow-path bitmap + interleaved RLE + RDP6 planar (AYCoCg, chroma subsample). Decode-complete in ironrdp (rdp6/, rle). Modern servers prefer surface commands but legacy servers need it.
- [ ] **M** — Surface Commands: SetSurfaceBits / StreamSurfaceBits / FrameMarker; frame-ack. **Two codec-id enums (don't conflate):** `WireToSurface1` carries **Codec1Type** (0x0 Uncompressed, 0x3 RemoteFX, 0x8 ClearCodec, AVC420/AVC444); `WireToSurface2` carries **Codec2Type** (0x9 RemoteFX Progressive). *ironrdp ref: session/fast_path.rs (legacy surface-command dispatch is partial — ClearCodec/Progressive not wired at the session level; EGFX path handles them via `ironrdp-egfx` + graphics codecs).*
- [ ] **M** — **RemoteFX (RFX) full decode** (non-progressive): tiles 64×64, quant, RLGR0/1, 3-level DWT, YCoCg→RGB. **Decode-complete-to-RGBA in ironrdp** (session/rfx.rs + graphics primitives). The safe baseline codec.
- [ ] **M(β)** — **RemoteFX Progressive decode**: TileSimple/First/Upgrade, DAS sign state, SRL, progressive quant, multi-pass coefficient accumulation, final DWT+colour. **ironrdp is NEAR decode-complete** (corrected, source-verified): `graphics/progressive.rs` ships both the low-level passes (`decode_first_pass`/`decode_upgrade_pass`) AND a high-level `TileState` (cross-pass store) + `decode_first`/`decode_upgrade` + `reconstruct_to_rgba` (full tile→RGBA) + a `SurfaceTiles` grid. *Our work = wire `WireToSurface2` payload → `SurfaceTiles`/`TileState` → `reconstruct_to_rgba` → `FrameUpdate`, plus surface bookkeeping.* ← the β work; this server uses it; smaller than first thought.
- [ ] **O** — ClearCodec (EGFX lossless, mandatory *for EGFX* per spec): residual + vbar cache + subcodec (Raw/NSCodec/RLEX) + 4000-glyph cache. **Decode-complete in `graphics/clearcodec`** (BGRA, alpha=0xFF).
- [ ] **O** — NSCodec (lossy subcodec): RLGR+AYCoCg, color-loss 0–7, chroma subsample. **ironrdp = PDU/caps only, no decoder.**
- [ ] **O** — H.264 / AVC420 & AVC444: **NOT in ironrdp** — needs a separate AVC decoder **backend (undecided)**: a vendored C lib (openh264/ffmpeg), an **OS-API Platform-FFI** backend (Windows Media Foundation / macOS VideoToolbox / Linux VAAPI — no C in our build tree, HW-accelerated), or **skip H.264** (optional in RDP; RemoteFX/Progressive cover the desktop). Decide at the H.264 slice, behind a pluggable decoder trait — **don't prescribe openh264**. Patent/licensing implications. ironrdp-egfx wires AVC420→a supplied decoder.
- [ ] **O** — zgfx (RDP8 bulk compression for EGFX payloads): 2.5MB LZ77 history, segmented. **Decode-complete in `graphics/zgfx`.** History persists across frames.
- [ ] **O** — MPPC / bulk compression (legacy fast-path payloads): 32KB history. *ironrdp ref: ironrdp-bulk.*
- [ ] **M** — Pointer / cursor: color/large/monochrome shapes, XOR/AND masks, alpha, 32-entry cache, position/hide, inverted-pixel special case. **Decode-complete in `graphics/pointer.rs` + session compositing.**
- [ ] **M** — Palette updates (8-bit indexed, TS_UPDATE_PALETTE_DATA, cumulative). *session/palette.rs.*
- [ ] **O** — Bitmap caching: persistent bitmap cache (**not in ironrdp** — we'd own the HashMap), glyph cache (ClearCodec-specific), brush cache. Bandwidth optimization; can ignore cache refs at cost of bandwidth.

---

## 8. Layer 6 — Virtual channels  *(transport + every channel)*

### 8a. Transport
- [ ] **M** — SVC (static): negotiated at GCC (≤31 + I/O channel); 8-byte Channel PDU Header (len+flags FIRST/LAST/COMPRESSED/…); 1600-byte chunking; per-channel compression. *ironrdp ref: ironrdp-svc.*
- [ ] **M** — drdynvc / DVC manager (MS-RDPEDYC): Create/Open/Close/CapabilitiesAdvertise+Confirm/DataFirst/Data; 1590-byte fragmentation+reassembly; `DvcProcessor` model (channel_name/start/process/close). *ironrdp ref: ironrdp-dvc.* Server opens DVCs via Create PDU.

### 8b. Channels (each its own slice; only EGFX/EDISP exist in ironrdp today)
- [ ] **O** — **EGFX / Graphics Pipeline (MS-RDPEGFX)**: CapabilitiesAdvertise/Confirm, ResetGraphics, surface create/delete/map, WireToSurface1/2, cache, solidfill, frame-ack, surface model. *ironrdp ref: `ironrdp-egfx` 0.1.0 (owns surface store + handler; codecs are Layer 5).* **Gated by `SUPPORT_DYN_VC_GFX_PROTOCOL`.** Channel: `Microsoft::Windows::RDS::Graphics`. → the whole reason we're here; **critical-for-perf**, technically optional.
- [ ] **O** — **Display Control (MS-RDPEDISP)**: dynamic resize / monitor layout. *ironrdp ref: `ironrdp-displaycontrol`.* Channel: `Microsoft::Windows::RDS::DisplayControl`.
- [ ] **O** — Clipboard / CLIPRDR (MS-RDPECLIP): format list, data req/resp, file transfer. *ironrdp ref: `ironrdp-cliprdr` (+ `-native` backends).* SVC.
- [ ] **O** — Audio output / RDPSND (MS-RDPEA): codec negotiation, frames, trailer. *ironrdp ref: `ironrdp-rdpsnd` (check).* SVC.
- [ ] **O** — Audio input / RDPEAI (MS-RDPEAI): mic capture, reliable + lossy-UDP variants. *spec-only.*
- [ ] **O** — Device redirection / RDPDR (MS-RDPEFS): multiplexing hub for **filesystem/drives**, **printers (MS-RDPEPC)**, **smartcards (MS-RDPESC)**, **serial/parallel ports (MS-RDPESP)**. *ironrdp ref: `ironrdp-rdpdr` (check).* SVC; per-device IDs.
- [ ] **O** — RemoteApp / RAIL (MS-RDPERP): seamless windows, window list, exec. *spec-only; heavy (window mgmt).*
- [ ] **O** — Multitouch & pen / RDPEI (MS-RDPEI): touch/pen DVC. *spec-only.*
- [ ] **O** — Multitransport / RDPEMT (MS-RDPEMT): UDP reliable(DTLS)/lossy tunnels. *spec-only; needs UDP+DTLS+NAT.*
- [ ] **O** — Video redirection / RDPEV (MS-RDPEV) and Video-optimized / RDPEVOR (MS-RDPEVOR). *spec-only; overlaps EGFX.*
- [ ] **O** — Geometry tracking / RDPEGT (MS-RDPEGT): window geometry hints. *spec-only.*
- [ ] **O** — Echo / RDPEECO (MS-RDPEECO): latency ping. *spec-only.*
- [ ] **O** — Camera / RDPECAM (MS-RDPECAM): webcam redirection, hot-plug. *spec-only.*
- [ ] **O** — Location / RDPEL (MS-RDPEL): geolocation. *spec-only.*
- [ ] **O** — Auth redirection / RDPEAR (MS-RDPEAR): credential forwarding/SSO. *spec-only.*
- [ ] **O** — Audio level & drive-letter persistence / RDPADRV (MS-RDPADRV). *spec-only.*
- [ ] **O** — Analog input / AInput (gamepads, joysticks, analog sticks, pressure): DVC. *ironrdp ref: `ironrdp-ainput`.* Useful for gaming; not a desktop need.
- [ ] **O** — USB device redirection / RDPEUSB (MS-RDPEUSB): raw USB passthrough over DVC (under RDPDR). *ironrdp ref: `ironrdp-rdpeusb` (check).* Heavy + security-sensitive.

---

## 9. Suggested MVP cut  *(to be confirmed during grilling — not decided)*

A reasonable first vertical slice that parallels what this PoC already proved on ironrdp:

- **MVP-1 (parity with current PoC):** Layers 0–4 fully, Layer 5 = framebuffer + slow-path
  bitmap/RLE + pointer + palette, Layer 6 = SVC+drdynvc + DisplayControl (resize). No EGFX.
- **MVP-2 (the perf goal):** add EGFX channel (with the GFX flag) + RemoteFX **full** decode
  (decode-complete, low risk) → first compressed path. Then RemoteFX **Progressive** (wire
  `WireToSurface2` into ironrdp's `reconstruct_to_rgba` — small, source-verified, not a
  research item).
- **Later / Optional:** clipboard, audio, drive redirection, H.264, RAIL, multimon, UDP — each
  its own tracked slice from §8/§5.

---

## 10. Consolidated open questions for grilling

**Strategy**
1. Same repo or a new crate/workspace? Is this replacing ironrdp in the downstream app, or a focused subset?
2. Given EGFX needs only a 1-line flag upstream — is "build our own" actually justified, or is the real goal "own the connect/GCC layer so flags are never hard-coded"? (Could be a thin fork/wrapper, not a full rewrite.)

**Scope**
3. MVP codec target: RemoteFX-full first, then Progressive (both ~decode-complete in ironrdp-graphics)? Defer H.264 (external decoder) entirely?
4. Which channels are in v1 beyond resize? (clipboard? audio? drive?)
5. Multi-monitor, DPI, UDP/multitransport, RAIL — in or explicitly deferred?

**Auth**
6. Kerberos in v1, or NTLM-only (workgroup) like the current PoC? KDC/AD available?
7. Cert validation policy (TOFU pinning like #11, full chain, or both)?
8. Smartcard / Restricted Admin — in scope?

**Graphics**
9. RemoteFX Progressive: ironrdp's `reconstruct_to_rgba` is decode-complete — validate it against mstsc/FreeRDP-captured frames, or trust it? (No longer a "build the decoder" question.)
10. Persistent bitmap cache + glyph/brush caches — implement or skip (bandwidth cost)?

**Wire/robustness**
11. On an unknown capability/PDU from the server — hard-error (spec-strict) or warn-and-continue (robust)?
12. Compression fallback chain if BitmapCodecs negotiation fails?

**Build/process**
13. Pure-Rust only, or allow the `sspi` crate (NTLM/Kerberos/CredSSP is enormous to reimplement)? Where exactly is the "no vendored deps" line for THIS package?
14. Slice cadence: same AFK-agent → gate → real-VM-verify loop as this PoC?

---

*§0–§10 = the curated spine (6-agent survey, 2026-06-08). **Part II (§11+) = a 16-agent
completeness + adversarial-verification sweep** that filled gaps (architecture/ops, GDI
drawing orders, RD Gateway, server redirection, logon/save-session-info, network autodetect,
audio codecs, keyboard/IME, caching, settings/.rdp/AAD, verification harness) and corrected
the spine (Progressive is near decode-complete; the 0x0004/0x0008 flags; Codec1/Codec2 enum
split). 21 of 23 factual claims verified correct against ironrdp source. Reference map only —
no implementation here. Next: grill §10 + the Part II open questions, then slice into issues.*

---

# Part II — Completeness-sweep extensions (16-agent sweep, 2026-06-08)

> These sections were produced by a fan-out of 16 agents (10 gap deep-dives, 4 completeness
> critics, 2 adversarial verifiers) to fill what the §0–§10 spine missed and to verify its
> claims. Same conventions: `M`/`O`, *ironrdp ref*, drop-in checklist bullets. Some agent
> prose was lightly trimmed; nothing actionable was dropped.

## 11. Architecture & operational design

### 11a. Crate/workspace structure — splitting protocol from host

- [ ] **M — Workspace layout.** Mirror ironrdp's separation: `pdu/` (protocol encoding/decoding; zero deps beyond `ironrdp-core`), `connector/` (stateful connection sequence; sans-IO state machine + host I/O adapters), `session/` (post-activation frame loop; graphics + input dispatch), `channels/` (virtual channel processors per MS-RD* spec), `core/` (shared types, trait boundaries). *Reference: ironrdp crates.* Per ADR-0004 (this repo), a `src/rdp/` submodule in a larger app is acceptable for the PoC; lift to separate crate (`crates/rdp/`) if downstream reuse demands compile-time boundary enforcement.
- [ ] **M — Sans-IO state machine core.** `connector::StateMachine<State>` owns the connection sequence logic (TCP → TLS → NLA → CapEx → Activation) without embedding async/socket I/O. Callers feed `(Action, bytes)` in, get `(Output, next_state)` out. *ironrdp ref: `connector::ClientConnectorState` enum + `step`* method pattern. Enables porting to non-Tokio runtimes, testing in sync code, and per-stage timeout wrapping.
- [ ] **M — Tauri / host isolation boundary.** Per ADR-0004, RDP logic lives in `src/rdp/` with a self-imposed rule: **no `tauri::*` imports inside `rdp/`.** Seams are plain closures (`Fn(FrameUpdate)`) for frame sinks, `mpsc::UnboundedSender` for input/resize commands. `lib.rs` wraps these in Tauri `Channel`s. *Consequence: non-Tauri hosts copy `rdp/` and rewrite seams.* Do the same for other host types (Qt, GTK, web-based).
- [ ] **M — Virtual channel abstraction seam (ADR-0005).** Channels are `ironrdp`'s `SvcProcessor`/`DvcProcessor` instances registered on the connector. Remote→host data (frame updates, clipboard content, etc.) flows through closures captured at construction; host→remote commands arrive on `mpsc` into the session loop. No custom `ChannelHandler` trait — reuse what ironrdp provides, per ADR-0005.

### 11b. Async runtime & threading — execution model

- [ ] **M — Tokio runtime — why and constraints.** Single-threaded `tokio::runtime::Runtime` with all I/O-bound futures (TCP, TLS, CredSSP, session loop) spawned on `rt`. No multi-threaded executor (reduces scheduling noise for frame latency). SAFETY: the session loop will block on write; non-cancel-safe write means a cancelled task mid-write loses bytes (plan.md §0). Mitigate: (a) write must not be cancellable by the input/resize channels (use `tokio::select!` **not** `select_all`; read is cancel-safe); (b) wrap reads in `timeout()` per-stage to bound hangs (STAGE_TIMEOUT, already done in #27).
- [ ] **M — Frame I/O thread vs decode thread.** The session loop (`run_session`) lives on the Tokio runtime and owns the RDP framing (reads from socket, dispatches to `ActiveStage`). Graphics decoders (RemoteFX, Progressive, ClearCodec, zgfx) are CPU-bound, not I/O-bound; decoding in the frame loop blocks frame reads. Decision point (pending perf data): (a) decode in-loop (safe, deterministic, but frame reads pause during heavy decode); (b) decode on a separate `std::thread::spawn` with a bounded `mpsc` queue (latency spike if queue fills). **Start with (a), profile, migrate to (b) only if frame-rate suffers.** If (b): send encoded frame down a bounded channel to a `std::thread`, get decoded pixels back on an `mpsc`, inject into the frame sink.
- [ ] **O** — Audio playback thread. Audio frames are low-frequency (48kHz → ~5ms per 240-sample frame) and must not jitter the graphics thread. Spawn a dedicated `std::thread` for audio ringbuffer + device playback; session loop sends frames over an `mpsc::Sender`. Underrun = silence, overrun = drop old frames (acceptable for RDP audio). *Not in MVP.*
- [ ] **M** — Backpressure / flow control. The frame sink (`Fn(FrameUpdate)`) is synchronous and non-blocking — if the webview is slow to consume frames, we have no queue to fill. **Design choice:** emit frames synchronously; if the webview blocks the sink, the session loop stalls and no input is processed (acceptable — the UI freezes, which is visible). Alternative: unbounded queue + spawn a render thread (introduces latency jitter). **Start with sync emission.**
- [ ] **M** — Frame pacing & coalescing. A server emitting bitmap updates every 33ms (30 FPS) will flood the webview with `putImageData` calls. Modern clients (FreeRDP, mstsc) coalesce updates within a ~16ms window (60 FPS client target). **Decision:** (a) simple: emit every frame, let the webview drop if it can't keep up; (b) coalescing: buffer updates for 16ms, merge overlapping regions, emit once per vsync. **Start with (a); add (b) only if 30+ FPS is a real requirement vs "we just want smooth, not exact."**
- [ ] **M** — Graceful session teardown / cancel safety. The session loop uses `tokio_util::sync::CancellationToken` to signal "stop"; the loop's read is cancel-safe (retryable), but write is not. **Design pattern:** (a) on cancel request, set a flag and let the loop finish the current `process_frame` naturally; (b) if it hangs for `STOP_TIMEOUT` (default 5s), force-abort. Per #21 this is already done in the PoC — document it as a load-bearing seam for any downstream that forgets.

### 11c. Error taxonomy & user-facing surfacing

- [ ] **M — ConnectError (typed per stage).** Variants: `TcpConnect { host, port, message, detail }`, `TlsHandshake { message, detail }`, `NlaCredssp { message, detail, invalid_credentials }`, `CapabilityExchange { message, detail }`, `Activation { message, detail }`, `Decode { message, detail }`, `UnexpectedDisconnect { message, detail }`, `ServerDisconnected { message, detail }`. *ironrdp ref: this repo's `src-tauri/src/rdp/error.rs`.* Each variant carries a one-line user message + a full diagnostic string for logs/panels.
- [ ] **M — Three-layer error surface.** (1) React UI: one-line message ("Invalid credentials" vs "TLS handshake failed") in red banner, click-to-expand panel with detail. (2) Diagnostics panel: full error chain + SSPI context + server reason code if available. (3) Tracing log: structured spans with error fields (host, port, stage, message, stack). *ironrdp ref: this repo's render.rs → webview bridge.*
- [ ] **M — SSPI error classification.** SSPI errors carry a `NStatusCode`; map `STATUS_LOGON_FAILURE` / `STATUS_WRONG_PASSWORD` to `invalid_credentials=true` so the UI shows "invalid credentials" and lets the user retry. Other SSPI codes (e.g. `STATUS_TRUSTED_DOMAIN_FAILURE` if Kerberos KDC is unreachable) surface with their original message + stack context.
- [ ] **M — Unknown PDU handling policy.** Server sends a PDU type we don't recognize. **Design choice:** (a) treat as fatal (spec-strict); (b) warn + skip (robust, survives server edge cases). **Recommendation: (b)** — log the PDU type, continue. Unknown capability/order flags = skip (server won't send them if we didn't advertise). Unknown PDU inside a channel = warn + skip the channel's frame. Decode failures (malformed bytes) = fatal (data corruption, likely protocol desync).
- [ ] **M — Server disconnect classification.** Capture the MCS Disconnect Provider Ultimatum reason code + any Set Error Info PDU to surface "admin disconnected" vs "idle timeout" vs "another session took over" vs "abrupt drop." *ironrdp ref: ironrdp-pdu/rdp/server_error_info.rs.* Distinguish `ServerDisconnected` (clean, reason available) from `UnexpectedDisconnect` (EOF/socket error, no reason).

### 11d. Logging, tracing & observability

- [ ] **M — Structured tracing per Connect Stage.** Each stage (`tcp-connect`, `x224-negotiate`, `tls-handshake`, `nla-credssp`, `capability-exchange`, `activation`, `session-active`) is a `#[instrument]` span with fields: host, port, stage, duration, result. Session loop is a long-lived `session-active` span; frame loop emits child spans per `ActiveStageOutput`. *ironrdp ref: this repo's `src-tauri/src/rdp/connect.rs` instrumentation.*
- [ ] **M — Redaction of secrets.** No password, PIN, private key, or session token is logged. Credentials struct has a manual `Debug` impl that shows `"<redacted>"`. CredSSP tokens are logged at `trace` level only, and only the token length + hash (not the bytes). Server certificate is logged (public); public key is logged (used for binding verification); but TLS peer secrets are never shown.
- [ ] **M — Per-channel logging target.** Virtual channels emit to `target: "rdp_<channel>"` (e.g. `"rdp_displaycontrol"`, `"rdp_egfx"`) so `RUST_LOG=rdp_displaycontrol=debug` isolates one channel's traffic. *ironrdp ref: this repo's connect.rs `info!(target: "rdp_displaycontrol_caps", ...)` pattern.*
- [ ] **M — Frame loop observability.** Session loop emits (a) frame-received event (fast-path vs X.224, size, codec), (b) frame-decoded event (dimensions, region, duration), (c) input-sent event (event count, types), (d) error events with context. If perf is critical, make frame-decoded a `debug!` level (high frequency); frame-received `info!`; errors always visible.
- [ ] **O** — Wireshark/packet capture export. For deep debugging, dump all protocol PDUs to a `.pcap`-like binary log (encrypted payloads included, TLS ciphertext not decrypted). *Not in MVP; useful for debugging interop issues.*

### 11e. Reconnection & timeout policy (per stage)

- [ ] **M — Per-stage timeout bounds.** TCP: `TCP_CONNECT_TIMEOUT` (default 10s, per #27). All post-TCP stages (TLS, NLA, CapEx, Activation): `STAGE_TIMEOUT` (default 15s per stage, not cumulative). Session loop read: no explicit timeout; cancel on app-level shutdown. Write: must not be cancellable (see 11b). *ironrdp ref: this repo's connect.rs STAGE_TIMEOUT/TCP_CONNECT_TIMEOUT.*
- [ ] **M — Timeout classification.** If a stage doesn't complete within its timeout, emit `ConnectError::<Stage>Timeout`. Don't retry inside the timeout handler — surface the error to the caller (the UI) and let the user retry. Retrying inside the client (with exponential backoff) is a higher-level concern (app-specific).
- [ ] **O** — Reconnect with resume (Auto-Reconnect Cookie). Server can send a Logon Extended PDU with a cookie that the client includes in the next connection to resume the prior session (vs full re-auth). *Deferred; useful for mobile/flaky networks.*
- [ ] **O** — Idle timeout keep-alive. If the server sends heartbeat/keep-alive PDUs, the client must echo them to prevent idle-timeout disconnects. *ironrdp has a handler; we wire it if needed.*

### 11f. Security hardening — trust, inputs, secrets

- [ ] **M — Server certificate validation.** Per #11, replace the PoC's accept-any verifier with (a) chain-of-trust validation (Root CA → Intermediate → Server cert) using rustls default verifier, OR (b) Trust-On-First-Use (TOFU) pinning: save the server's cert/public key on first connect, compare all future connects to the pin, warn if it changes. *ironrdp ref: this repo's `src-tauri/src/rdp/pinning.rs` (TOFU) + #11 ticket.* **Recommend (b) for single-server scenarios** (the PoC target), (a) for multi-server scenarios.
- [ ] **M — CredSSP public-key binding.** Per plan.md §0, binding uses the cert's `subjectPublicKey` (DER), not the whole cert. Verify this extraction matches the server's public key used in TLS. *ironrdp ref: x509-cert crate + this repo's auth.rs.*
- [ ] **M — Input validation / untrusted bounds.** All server-supplied values that control memory allocation or offset calculation must be bounds-checked: bitmap dimensions (max screen size), palette entries (palette size), codec output size, frame counts, etc. A malicious server sending `width=65535, height=65535, bpp=32` would allocate 16 GB. **Policy:** bounds checks in every decoder; log a warn and skip the frame if bounds exceeded. *ironrdp ref: `DecodedImage::new()` validates size; decoder primitives check bounds.*
- [ ] **M — Zeroization of secrets.** Any in-memory credential (password, PIN, private key, session nonce) must be overwritten with zeros after use so a dump of the process heap doesn't leak it. Use `zeroize` crate or `volatile_write`. *ironrdp ref: `sspi` does this; we inherit it.*
- [ ] **M — No credentials in logs.** Password is never logged (see 11d redaction). If an error occurs during CredSSP, the error message must not include the challenge/response tokens, only "CredSSP failed: <reason>". *ironrdp ref: this repo's auth.rs + error redaction.*
- [ ] **O** — Fuzzing of decoders. If codec coverage expands (Progressive, H.264, NSCodec), fuzz the decoders with AFL/libFuzzer to find panics/OOM in untrusted input. *Not in MVP.*
- [ ] **M** — TLS downgrade protection. Advertise `SUPPORT_ERR_INFO_PDU` (0x0001 in earlyCapabilityFlags) so the server can tell the client about man-in-the-middle attempts via Set Error Info PDU. *Already wired; document it.*

### 11g. Platform abstraction seams — rendering/input/audio/clipboard

The client's core RDP engine must be host-agnostic. Seams are closures/traits crossed at defined boundaries. Examples below; each is a pattern, not a separate type.

- [ ] **M — FrameUpdate sink.** Already an `Arc<dyn Fn(FrameUpdate) + Send + Sync>` (plan.md Layer 4 / ADR-0006). Slow-path and EGFX both emit through the same sink. Tauri wraps it in a `Channel<FrameUpdate>` to the webview; a Qt host wraps it in a signal-slot; a headless host buffers it in a Vec. *No change needed; pattern is set.*
- [ ] **M — Keyboard input source.** Host provides key events (OS scancode, down/down-repeat/up); client converts to RDP scancodes via a scancode mapper. *This repo: `src-tauri/src/rdp/input.rs` handles the mapping.* Platform-specific: Windows VK → scancode (native), macOS KeyboardEvent.code → scancode (via X11 keymap or native), Linux evdev + XKB (via keymap library). **Decision:** (a) per-platform specific code (more friction, higher perf); (b) web KeyboardEvent.code as the canonical form (portable, loses scancode precision on some platforms). **Recommend (a) for native clients, (b) for web/electron.**
- [ ] **M — Mouse input source.** Host provides absolute (x,y) and wheel deltas; optionally relative deltas if server advertises `RELATIVE_MOUSE_INPUT`. Client normalizes to RDP units (clamped to desktop size if known). *Current PoC handles this; make it generic.*
- [ ] **O** — Pointer / cursor rendering. The server sends cursor shapes (color/large/monochrome with masks, cached); the host renders them. *This repo: slow-path pointer in `render.rs`; EGFX pointer via `GraphicsPipelineHandler::on_pointer_updated` callback.* Host binding: Qt app uses a custom `QCursor`; Tauri app renders to canvas; headless doesn't render at all.
- [ ] **O** — Clipboard backend.** Bidirectional sync between host clipboard and RDP CLIPRDR channel. Host-specific: Tauri uses `tauri::api::clipboard`; Qt uses `QApplication::clipboard()`; web uses browser Clipboard API (async). *Not in MVP; large surface for data security.*
- [ ] **O** — Audio sink (playback).** RDPSND channel delivers PCM frames; host renders them. Host-specific: Tauri + web → Web Audio API or OS default audio device via `cpal`; Qt → QAudioOutput; headless → discard. *Not in MVP.*
- [ ] **O** — Filesystem backend (drive redirection).** RDPDR channel allows the server to access client-side filesystems. Host-specific: provide a list of allowed mount points / directories; client proxies file open/read/write/stat calls to the host. *Highly platform-specific and security-critical; large surface.*

### 11h. Configuration model & settings

- [ ] **M — ConnectionProfile struct.** User-supplied: host, port, username, password, domain. *This repo: `profile.rs`.* Extend as features add: (a) multiple profiles / saved profiles (persistence); (b) per-profile codec prefs (H.264 yes/no, RemoteFX yes/no); (c) certificate pinning storage (per-host pin); (d) keyboard layout; (e) performance flags (wallpaper, themes, smooth fonts, menu animation).
- [ ] **M — RequestedDesktop struct.** User specifies w×h; clamped to min/max at connector Config build time. Extended: per-monitor DPI, multi-monitor layout (deferred).
- [ ] **M — Feature flags in Config.** When building `ClientConnector::Config`, expose every capability advertise as a configurable boolean: `advertise_early_capability_flags`, `advertise_dynamic_vc`, `advertise_net_char_autodetect`, `advertise_dpi_awareness`, etc. *ironrdp ref: connector/Config fields.* **Critical:** make `earlyCapabilityFlags` fully configurable (plan.md §1 / §0) — no hard-coded omissions.
- [ ] **O** — Settings persistence.** Store user's last connection profile + per-server pinned certs in a config file (TOML, JSON) or OS keychain. *Not in PoC; App-specific.*
- [ ] **O** — Runtime config hot-reload.** Some settings (keyboard layout, performance flags) could be hot-reloadable without disconnect; others (codec prefs) can't. *Out of scope.*

### 11i. Cargo features & packaging

- [ ] **M — Base feature set (always-on).** Core protocol, NTLM (via `sspi`), basic graphics (slow-path bitmap/RLE), input, Display Control, DVC framework.
- [ ] **O — `"kerberos"`:** Link `sspi` with Kerberos enabled; requires KDC reachability. Default off (workgroup-sufficient).
- [ ] **O — `"remote-fx"`:** Codec support (full + Progressive). Adds `ironrdp-graphics` dependency; default on.
- [ ] **O — `"clearcodec"`:** Lossless codec (mandatory for EGFX per spec, so probably always-on if EGFX is on).
- [ ] **O — `"h264"`:** H.264 AVC420/AVC444 behind a **pluggable AVC decoder backend (undecided)** — a vendored C lib (openh264/ffmpeg), OS-API Platform-FFI (WMF/VideoToolbox/VAAPI), or none. Default off (patent/licensing); the backend is chosen at the H.264 slice, not prescribed here.
- [ ] **O — `"gateway"`:** RDP Gateway / TS Gateway protocol (MS-TSGS) support for proxy scenarios. Default off.
- [ ] **O — `"rdpdr"`:** Device/drive redirection (large, complex). Default off.
- [ ] **O — `"clipboard"`:** CLIPRDR channel. Default off.
- [ ] **O — `"audio"`:** RDPSND (output) + RDPEAI (input). Default off.
- [ ] **M — Dependency pinning strategy.** `ironrdp` crates are at 0.x (pre-1.0); use exact pins (e.g. `=0.9.0`) in `Cargo.toml` for stability. Bump in lockfile commits, not ad-hoc. Test against `cargo update` monthly to catch transitive incompatibilities early.

### 11j. Licensing & legal considerations

- [ ] **M — RDP IP.** The RDP protocol is documented in Microsoft's open MS-RDP* specifications (freely published); implementing it in Rust infringes no IP (it's protocol, not trade secret). Tauri app distribution is unaffected.
- [ ] **O — H.264 codec licensing.** H.264/AVC is patent-encumbered; vendors must pay MPEG LA if they distribute an H.264 encoder/decoder. Using openh264 (released under MPL 2.0, but patent risks remain) requires a licensing audit if the app is sold. **Recommendation for this PoC:** defer H.264 entirely (use RemoteFX/Progressive) or use openh264 only in a `dev`/`test` feature, not in the production binary. Mark the `"h264"` feature as "patent-encumbered; see docs/LICENSING.md" in the `Cargo.toml` feature description.
- [ ] **M — Transitive dependency audit.** Run `cargo audit` in CI and keep a `DEPENDENCIES.md` that lists all first-order Rust deps + their licenses (Cargo.lock tools like `cargo-license` help). Document any GPL/AGPL deps as compliance risks.
- [ ] **M — Smartcard / Kerberos licensing.** NTLM and Kerberos are patent-covered in some jurisdictions; Microsoft's IETF specs are open (RFC 1964 for Kerberos, RFC 2478 for SPNEGO). Distribution is unaffected; just document if using smartcard or AD integration in a commercial product.

### 11k. Performance benchmarking plan

- [ ] **M — Benchmarking targets vs reference.** Measure against (a) **ironrdp** (pure Rust; PoC's source material), (b) **mstsc.exe** (Windows native client; gold standard), (c) **FreeRDP** (C client; another open impl). Metrics: connect time (by stage), frame latency (P50/P95 ms), CPU % (idle, 30 FPS, 60 FPS), memory (RSS at session-active, peak during decode).
- [ ] **O** — Setup: reproducible VM (same specs, same desktop state, same server settings) for all runs. Measure at least 10 consecutive sessions to average out variance.
- [ ] **M — Frame latency measurement.** Instrument the session loop to record `(frame_received, frame_decoded, frame_emitted)` timestamps. Compute latency = `emitted - received`; plot P50/P95/P99 over a 1-minute window. Compare vs mstsc/FreeRDP on the same VM.
- [ ] **O** — Codec-specific perf.** Once Progressive codec is wired, compare slow-path bitmap vs Progressive vs RemoteFX-full for the same server. Server's CPU cost should drop (less data sent) if compression is efficient.
- [ ] **M** — Regression tests.** Add CI benchmarks: a `--bench` target that connects to a test VM, records frame latency, and fails if P95 latency exceeds a threshold (e.g. 100ms). Prevents slowdowns from creeping in unnoticed.
- [ ] **O** — Profiling hooks.** If perf is critical, add optional `#[cfg(feature = "profiling")]` instrumentation (flamegraph markers, perf.data export) so downstream integrators can profile their deployment.

---

## 12. Drawing Orders (MS-RDPEGDI)

### Overview
Drawing orders encode server-side GDI rendering commands (rasterop, text, polygons, lines) as compact byte-stream PDUs. Modern servers prefer GPU-accelerated EGFX surface commands + codec rendering, but legacy servers (and some multimedia contexts) still rely on orders. **ironrdp-session 0.9.0 explicitly skips orders** (`warn!("Slow-path drawing orders not supported (MS-RDPEGDI)")`); ironrdp-pdu defines capability flags but no order decoders. Orders arrive in **slow-path** Update PDUs (`GraphicsUpdateType::Orders`) — fast-path has an `UpdateCode::Orders` enum slot (0x0) but servers rarely use it. Wire format: Order Header (capset negotiates per-order flags) → Primary/Secondary/Alternate payload (variable length, delta-encoded bounds).

### 7a-1. Order Capability Negotiation
- [ ] **M** — **Order Capability Set (capset 0x03)**. 84-byte fixed structure; advertises per-order support. *ironrdp ref: ironrdp-pdu/rdp/capability_sets/order/mod.rs — defines `OrderFlags`, `OrderSupportIndex` enum (index 0–0x1B), `OrderSupportExFlags`, desktop_save_size, text_ansi_code_page.* Capability exchange gates all order delivery — server NEVER sends an order type if client's `order_support[index]` is 0. **Design rule:** populate `order_support` array per what we actually decode; false positives = server sends orders we crash on. *ironrdp initializes all-zeros (no orders supported).*
- [ ] **M** — **OrderFlags** bitfield: `NEGOTIATE_ORDER_SUPPORT` (0x0002, must set to enable negotiation), `ZERO_BOUNDS_DELTAS_SUPPORT` (0x0008, optimize delta encoding), `COLOR_INDEX_SUPPORT` (0x0020, 8-bit palette mode), `SOLID_PATTERN_BRUSH_ONLY` (0x0040, restrict brush types), `ORDER_FLAGS_EXTRA_FLAGS` (0x0080, enables `OrderSupportExFlags`). *ironrdp ref: OrderFlags enum.*
- [ ] **M** — **OrderSupportExFlags**: `CACHE_BITMAP_REV3_SUPPORT` (2, enables new-rev bitmap cache), `ALTSEC_FRAME_MARKER_SUPPORT` (4, enables FrameMarker Alternate Secondary order).
- [ ] **O** — Desktop Save Size negotiation (bytes reserved for SaveBitmap order buffer); usually 230KB. Rarely configured; defaults safe. *MS-RDPEGDI 2.2.2.7.*

### 7a-2. Primary Drawing Orders (16 types)
Each Primary order opens with an Order Header (below) then type-specific payload. Bounds (clipping rect) are 2-byte delta-encoded ints unless `ZERO_BOUNDS_DELTAS_SUPPORT` present. Field-flag bytes select which fields encode (variable length).

#### Individual Primary Orders (index = OrderSupportIndex enum value)
- [ ] **M** — **DstBlt (0x00): Destination BitBlt.** Simple raster fill: `nLeftRect, nTopRect, nWidth, nHeight (bounds), bRop` (3 bytes rop3 code + rop2 special). *MS-RDPEGDI 2.2.2.2.1.1.* Result ← ROP(dest). **ironrdp**: not implemented.
- [ ] **M** — **PatBlt (0x01): Pattern BitBlt.** Fill rect with brush + raster operation. Payload: bounds, brush (color/pattern), rop3 code. Pattern brush can be monochrome bitmap (8×8 or larger per negotiation) or solid. *MS-RDPEGDI 2.2.2.2.1.2.* Result ← ROP(dest, brush). **ironrdp**: not implemented.
- [ ] **M** — **ScrBlt (0x02): Screen BitBlt.** Copy rect within framebuffer (source ≠ dest possible). Payload: dest bounds, src x/y, rop3. *MS-RDPEGDI 2.2.2.2.1.3.* Result ← ROP(dest, src). **ironrdp**: not implemented.
- [ ] **M** — **MemBlt (0x03): Memory BitBlt.** Copy from bitmap cache (id + origin) into framebuffer, optional rop. Payload: bounds, cache_id (u16), cache_index (u16), src_x/y, rop3. *MS-RDPEGDI 2.2.2.2.1.4.* **ironrdp**: not implemented; would require bitmap cache decoder.
- [ ] **M** — **Mem3Blt (0x04): Memory Triple BitBlt.** MemBlt with pattern brush (cache_id for brush/bitmap both). Payload: bounds, brush_cache_id, brush_cache_index, dest_x/y, foreground/background, rop3 + pattern fill. *MS-RDPEGDI 2.2.2.2.1.5.* **ironrdp**: not implemented.
- [ ] **M** — **LineTo (0x08): Line drawing.** Vector from point to point with pen (color, width, style). Payload: x/y dest (drawn to, not including), rop2 code, pen_color (3 bytes BGR), pen_style (cosmetic; unused), pen_width (u16). *MS-RDPEGDI 2.2.2.2.1.6.* No antialiasing. **ironrdp**: not implemented.
- [ ] **M** — **OpaqueRect (0x0E): Filled rectangle** (no rop, solid color only). Payload: bounds, fill_color (3 bytes BGR). Fastest rect fill. *MS-RDPEGDI 2.2.2.2.1.7.* **ironrdp**: not implemented.
- [ ] **M** — **SaveBitmap (0x0B): Capture rect into cache.** Inverse of MemBlt: extract framebuffer region, store in SaveBitmap buffer (not a persistent cache, just temporary). Payload: saved_left/top/right/bottom (bounds). *MS-RDPEGDI 2.2.2.2.1.8.* Used by legacy popup menus (save, render overlay, restore). **ironrdp**: not implemented.
- [ ] **M** — **MultiDstBlt (0x0F): Batch DstBlt.** Single rop, multiple rects (count + variable-length rect list). *MS-RDPEGDI 2.2.2.2.1.9.* **ironrdp**: not implemented.
- [ ] **M** — **MultiPatBlt (0x10): Batch PatBlt.** Single brush+rop, multiple rects. *MS-RDPEGDI 2.2.2.2.1.10.* **ironrdp**: not implemented.
- [ ] **M** — **MultiScrBlt (0x11): Batch ScrBlt.** Single rop, multiple src/dest pairs. *MS-RDPEGDI 2.2.2.2.1.11.* **ironrdp**: not implemented.
- [ ] **M** — **MultiOpaqueRect (0x12): Batch OpaqueRect.** Single color, multiple rects. *MS-RDPEGDI 2.2.2.2.1.12.* **ironrdp**: not implemented.
- [ ] **O** — **FastIndex (0x13) / FastGlyph (0x18): Glyph cache index variants** (reserved, rarely used). *MS-RDPEGDI 2.2.2.2.1.13–14.* Subset of GlyphIndex for common glyphs. **ironrdp**: not implemented.
- [ ] **O** — **GlyphIndex (0x1B): Glyph rendering from glyph cache.** Text rendering: cache_id (glyph index), fg/bg color, bounds (clip box), cache lookup, XOR/AND blend. *MS-RDPEGDI 2.2.2.2.1.15.* Needs glyph cache (separate from bitmap cache). **ironrdp**: not implemented; also skipped because glyph cache is unsupported.
- [ ] **O** — **PolygonSC (0x14) / PolygonCB (0x15): Polygon fill (solid color / color brush).** Boundary trace + interior fill. Payload: bounds, fillMode (alternate/winding), brush_color, points list (delta-encoded). *MS-RDPEGDI 2.2.2.2.1.16–17.* **ironrdp**: not implemented.
- [ ] **O** — **Polyline (0x16): Polyline (connected line segments).** Pen style + points list (delta-encoded). *MS-RDPEGDI 2.2.2.2.1.18.* **ironrdp**: not implemented.
- [ ] **O** — **EllipseSC (0x19) / EllipseCB (0x1A): Ellipse fill (solid / brush).** Bounds rect (implicitly defines x/y radius), fill brush. *MS-RDPEGDI 2.2.2.2.1.19–20.* **ironrdp**: not implemented.

### 7a-3. Secondary Drawing Orders (index ≥ 0x80; subset, shared namespace)
Smaller, special-purpose: cache management, frame synchronization. **Wire format differs from Primary:** order header still present, but payload structure differs.

- [ ] **O** — **CacheBitmap (0x00/rev1, 0x01/rev2, 0x02/rev3): Store bitmap in persistent cache.** Payload: cache_id, cache_index, nWidth/nHeight, bitmap_data (RLE- or RDP6-compressed; depends on codec negotiation). Rev3 newer (improves caching strategy). *MS-RDPEGDI 2.2.2.2.2.1–3.* **ironrdp ref**: Order capset flags `CACHE_BITMAP_REV3_SUPPORT`; no decoder. **Decoder needed to honor MemBlt cache refs.**
- [ ] **O** — **CacheColorTable (0x03): Color palette cache.** Payload: cache_id, palette_entries (256×RGB triplets, for indexed-color ops). *MS-RDPEGDI 2.2.2.2.2.4.* **ironrdp**: not implemented.
- [ ] **O** — **CacheGlyph (0x04): Glyph cache entry.** Payload: cache_id, cache_index, glyph bitmap data (compressed). *MS-RDPEGDI 2.2.2.2.2.5.* **ironrdp**: not implemented; also glyph cache is rarely used in modern RDP.
- [ ] **O** — **CacheBrush (0x07): Brush pattern cache.** Payload: cache_id, brush_data (8×8 bitmap or monochrome). *MS-RDPEGDI 2.2.2.2.2.6.* **ironrdp**: not implemented.

### 7a-4. Alternate Secondary Orders (index ≥ 0x100; special-purpose, newer)
Handle GPU surfaces, screen transitions, GDI+ rendering.

- [ ] **O** — **SwitchSurface (0x00): Switch rendering target surface.** Payload: surface_id. Used by EGFX pipeline to switch between offscreen/screen surfaces. *MS-RDPEGDI 2.2.2.2.3.1.* **ironrdp**: not implemented (EGFX uses DVC channel instead).
- [ ] **O** — **CreateOffscreenBitmap (0x01): Allocate offscreen rendering surface.** Payload: surface_id, cx/cy. Precursor to SwitchSurface; legacy pre-EGFX. *MS-RDPEGDI 2.2.2.2.3.2.* **ironrdp**: not implemented.
- [ ] **O** — **StreamBitmapFirst (0x02) / StreamBitmapNext (0x03): Incremental bitmap streaming.** Large bitmaps broken into fragments; first PDU declares size, subsequent PDUs append. *MS-RDPEGDI 2.2.2.2.3.3–4.* **ironrdp**: not implemented.
- [ ] **O** — **CreateNineGridBitmap (0x04): 9-grid scaling hint.** Metadata for bitmap stretch (3×3 grid corners/edges/center for NineGrid scaling). *MS-RDPEGDI 2.2.2.2.3.5.* **ironrdp**: not implemented.
- [ ] **O** — **FrameMarker (0x05): Frame synchronization marker.** Explicit frame boundary (replaces implicit FrameMarker from layer 5). Payload: action (begin/end). *MS-RDPEGDI 2.2.2.2.3.6 & MS-RDPBCGR 2.2.9.1.2.2.* **ironrdp ref**: capset flag `ALTSEC_FRAME_MARKER_SUPPORT`.
- [ ] **O** — **GdiPlus (0x06–0x0B): GDI+ vector graphics rendering.** Metadata-driven shape rendering (ellipse, lines, splines, fills); delegates to GDI+ runtime on server (client ignores). *MS-RDPEGDI 2.2.2.2.3.7–12.* **Spec-only**; not widely used in practice; **ironrdp**: not implemented.

### 7a-5. Order Header Framing & Encoding
Each order (Primary or Secondary) begins with an Order Header, then type-specific payload. Decoding requires iterative state (flags select which fields to read).

- [ ] **M** — **Order Header (variable-length, up to ~6 bytes):** `controlFlags` (u8, bit 7 = secondary; bit 0–6 = field flags / index), optional `fieldFlags`/`fieldFlags2` (u8 each, if more fields needed), bounds (nLeftRect/nTopRect/nRightRect/nBottomRect, delta-encoded u16×4 OR zero if bounds delta = 0), optional Secondary order index (u8 if controlFlags bit 7 set). *MS-RDPEGDI 2.2.2.1.* **No decoder in ironrdp.**
- [ ] **M** — **Bounds Encoding (delta rects): coordinate compression.** Each bound is stored as signed delta from prior order's bound (or absolute if order == 0). If `ZERO_BOUNDS_DELTAS_SUPPORT` flag set, can omit bounds entirely. Byte stream variable-int encoding: 0x80 set = continue byte. *MS-RDPEGDI 2.2.2.1.3.* Decompression is prerequisite to reading payload.
- [ ] **M** — **Field Flags (controlFlags bits 0–5):** Each Primary order has its own field-flag meanings (e.g., PatBlt flags control which of brush/rop fields encode vs use cache/default). Decoder must know per-order flag layout. *MS-RDPEGDI section 2.2.2.2.* **Not in ironrdp.**
- [ ] **O** — **Secondary order indicators (controlFlags bit 7 = 1):** Dispatch to Secondary/Alternate handler. Optional field index (u8) specifies subtype (CacheBitmap rev1/2/3, FrameMarker, etc.). *MS-RDPEGDI 2.2.2.1.2.*

### 7a-6. Text & Glyph Rendering (GlyphIndex + cache)
GDI text rendering pipeline (lowest-priority in modern servers; EGFX + bitmap fallback are preferred).

- [ ] **O** — **Glyph Cache (separate from bitmap cache):** Per-font glyph bitmaps, indexed by character code + style (bold/italic). Capacity typically ~4000 glyphs; managed by CacheGlyph Secondary orders. *MS-RDPEGDI 2.2.2.2.2.5.* **Decoder needed to decode GlyphIndex orders; ironrdp doesn't implement.**
- [ ] **O** — **GlyphIndex order (Primary 0x1B):** Render glyphs from cache at positions. Payload: cache_id (font id), fg/bg_color, bounds (clipping box), character index array (u16 each) + position array (x/y delta-encoded shorts). XOR blend mode (text transparency via dest XOR fg). *MS-RDPEGDI 2.2.2.2.1.15.* **ironrdp**: not implemented.
- [ ] **O** — **FastGlyph/FastIndex (0x13 / 0x18, optimized subsets):** Rare; skip unless needed. *MS-RDPEGDI 2.2.2.2.1.13–14.*

### 7a-7. Caching Strategy for Orders
Orders assume persistent server-side caches to amortize bandwidth:

- [ ] **O** — **Bitmap Cache (persistent, ≠ SaveBitmap buffer):** MemBlt/Mem3Blt reference cached bitmaps by (cache_id, cache_index). Capacity per spec; CacheBitmap orders populate it. *MS-RDPEGDI 2.2.2.2.2.1–3.* **Decoder needed; ironrdp doesn't implement.** Cache miss = protocol error (server misbehaves).
- [ ] **O** — **Brush/Color Cache:** Small (<=256 entries ea.), populated by CacheBrush / CacheColorTable. PatBlt/Mem3Blt reference by id. *MS-RDPEGDI 2.2.2.2.2.* **ironrdp**: not implemented.
- [ ] **O** — **Glyph Cache (font-specific):** ~4000 glyphs per font. GlyphIndex references (cache_id = font_id, cache_index = char_code). *MS-RDPEGDI 2.2.2.2.2.5.* **ironrdp**: not implemented.

### 7a-8. Server Behavior & Codec Interaction
- [ ] **M — Codec-only vs. order-based servers.** Modern servers (Windows Server 2012+, RemoteApp, thin clients) prefer EGFX surface commands + bitmap codecs (RFX, ClearCodec, H.264) — orders are legacy fallback. Older servers (Win2003/XP, embedded) and multimedia contexts (video playback, desktop composition) still use orders. *On this session's server: orders are NOT observed (RemoteFX Progressive via EGFX preferred).* **Design rule:** Support orders as optional decoder; prioritize surface-commands path. Graceful degradation if orders arrive: either decode (if implemented) or best-effort fallback (redraw full framebuffer on unknown order).
- [ ] **M** — **Slow-path vs. Fast-path delivery:** Orders almost always arrive in Slow-Path GraphicsUpdateType::Orders packets (rare: FastPathUpdate::Orders, code 0x0). Slow-path packets are wrapped in X.224 ShareData PDUs; fast-path is framed separately (see Layer 4). **ironrdp-session decodes slow-path headers but skips order payload.** *ironrdp-pdu has UpdateCode::Orders but no handler.*
- [ ] **O** — **Interleaving with bitmaps/surface-commands.** A session may mix orders + bitmaps + surface-commands in a single update stream. Decoder must handle state carryover (clipped bounds, brush cache, rop context, glyph advances). *MS-RDPEGDI 2.2.2.1.1.*

### 7a-9. Implementation Considerations
- [ ] **O** — **Order decoder framework.** Trait/handler model: `Decoder<Order> { handle_primary(DstBlt|PatBlt|…) -> Result<>, handle_secondary(CacheBitmap|…) -> Result<>, …}` dispatched from Update PDU parser. Stateful (bounds, cache refs, rop context). *No reference in ironrdp (session skips).*
- [ ] **O** — **Raster operation (ROP3/ROP2) implementation.** Lookup tables or bitwise formula (per MS-RDPEGDI 2.2.2.2.1.1 ROP truth table). ROP3 = 3-input logic (dest, src, pattern); ROP2 = pen logic (dest, pen). *ironrdp doesn't provide ROP; FreeRDP has rop_* functions.*
- [ ] **O** — **Delta-encoding decompression.** Signed variable-int loop for bounds + point coords. Prerequisite before payload parsing. *ironrdp-core has `ReadCursor` primitives but no bulk delta decoder.*
- [ ] **O** — **Fallback rendering.** Unknown/unsupported order → issue WARN + invalidate affected bounds (force redraw via Refresh Rect or next bitmap frame). Never crash. *ironrdp-session already warns & continues.*

### 7a-10. Gotchas & Traps
- [ ] **Trap: Cache miss = protocol violation.** A MemBlt/GlyphIndex referencing a non-existent cache entry (index not yet populated) indicates either (a) client cache-flush bug, (b) order out-of-sync, or (c) server bug. **Robust decoder must handle gracefully** (skip order, warn, don't panic). ironrdp has no cache, so would always "miss"; safe.
- [ ] **Trap: Bounds delta can roll over.** Signed 16-bit deltas from prior order can wrap. Decoder must correctly handle negative deltas and modular arithmetic. *Spec ambiguity; FreeRDP uses saturating arithmetic.*
- [ ] **Trap: ROP is not commutative.** PatBlt(rop=COPY) ≠ PatBlt(rop=AND); order matters. Some servers send rop=BLACKNESS (=0) for "clear" but misuse raster codes; decoder must apply *exactly* per-spec.
- [ ] **Trap: Field flags require per-order knowledge.** controlFlags bits 0–5 have different meanings per order type (e.g., PatBlt bit 0 = "brush encodes"  vs. ScrBlt bit 0 = "source x encodes"). Hardcoded dispatch per order enum required.
- [ ] **Trap: Palette dependency in indexed-color mode.** DstBlt / PatBlt with 8-bit colors require palette to have been loaded (via Palette update PDU). If palette not yet synced, wrong color rendered. Decoder must track palette lifecycle.

### 7a-11. Ironrdp Status & Gap
- [ ] **ironrdp-pdu 0.8.0:** Order capset structure (`Order`, `OrderSupportIndex` enum 0x00–0x1B, `OrderFlags`, `OrderSupportExFlags`) is complete; no order PDU decoders.
- [ ] **ironrdp-session 0.9.0:** Recognizes `GraphicsUpdateType::Orders` in slow-path dispatcher; unconditionally warns + skips (active_stage.rs:412).
- [ ] **ironrdp-fast_path:** `UpdateCode::Orders` (0x0) enum slot exists; no handler; slow-path Orders are primary path anyway.
- [ ] **Gap:** No Order header decoder, no Primary/Secondary/Alternate order payload structs, no ROP implementation, no cache (bitmap/glyph/brush). **We own all of this if we choose to decode orders.**

---

This section is **exhaustive** and **drop-in ready**. It covers every order type (21 Primary, 4 Secondary, 6 Alternate), all framing, caching, gotchas, and explicitly maps what ironrdp does/doesn't implement. Ready to append to plan.md after the existing Layer 5 section (before Layer 6).

## 13. Connection transports & RD Gateway (MS-TSGU)

Good! I found KDC proxy support. Now let me compile comprehensive information about MS-RDP gateway. Let me search for specifications and implementation details from reliable sources. Since I have good baseline knowledge, let me create a comprehensive reference document on connection transports and RD Gateway:

---

### 9a. Direct TCP transport
- [ ] **M — Direct TCP connection.** hostname:port (default 3389); sync or async. TLS negotiation + credential flow happen *atop* the established connection. *ironrdp ref: ironrdp-connector (connection.rs); ironrdp-tokio for async framing.* Simplest path; server must be network-reachable from the client.
- [ ] **M — Graceful teardown.** Session close initiated by client (user logout) vs server (disconnect ultimatum / error info PDU); both paths end the TCP socket cleanly. Cancel-aware to avoid partial-write duplication.

### 9b. RD Gateway (MS-TSGU) — HTTP & RPC-over-HTTP tunneling
*(Mark M for production/enterprise, O for lab; spec-only, no reference implementation in ironrdp 0.9.0.)*

**Background:** RD Gateway (Terminal Services Gateway) is a corporate firewall-bypass mechanism. The client connects to a Gateway server over HTTPS instead of direct TCP to the target RDP server. The Gateway establishes a tunnel, the client sends RDP PDUs through it, and the Gateway relays them to the target server. Applies in scenarios where direct RDP (port 3389) is blocked by network policy but HTTPS (443) is open. Two transports exist: **HTTP-based (RDG HTTP)** and **RPC-over-HTTP (RDG RPC)**, differing only in the tunneling envelope.

#### 9b-i. RD Gateway HTTP transport (MS-TSGU over HTTP)
- [ ] **O(M for production) — RDG HTTP handshake.** Client → Gateway: POST to `/remotedesktopgateway/http/request.php` (or IIS-routed equivalent), carries HTTP_INFO PDU (magic, version, reserved fields). Gateway response must include `Set-Cookie` with authorization token (PAA/TSG auth cookie). *Spec: MS-TSGU §2.2.1.* No ironrdp coverage.
- [ ] **O(M) — HTTP tunnel create.** Client sends TSGPacket (PDU wrapper) with TunnelCreateRequest (auth type, auth token, proxy name, username, domain, password, hostname, port). Gateway validates & allocates a tunnel session (tunnel ID, tunnel auth token). Response includes tunnel ID + auth token for subsequent requests. *Spec: MS-TSGU §2.2.3.* Tunnel persists across multiple HTTP requests; tunnel ID is opaque to client.
- [ ] **O(M) — HTTP tunnel authentication.** After tunnel create, TSGPacket with TunnelAuthRequest: auth type (NTLM, Kerberos, smartcard), SPNEGO token (same SSPI machinery as CredSSP). Gateway SSPI-completes authentication against the *Gateway's* identity, distinct from RDP server auth (two separate auth legs). *Spec: MS-TSGU §2.2.5.* Tokens are SPNEGO-wrapped.
- [ ] **O(M) — HTTP channel create.** Client sends TunnelRequest with ChannelCreateRequest (channel ID, resourceName = "`RDP`", number of resources). Gateway opens the *logical channel* within the tunnel (maps to the target server's hostname:port, which was in TunnelCreateRequest). Response contains channel ID + tunnel auth token for later messages. *Spec: MS-TSGU §2.2.7.*
- [ ] **O(M) — HTTP channel data (bidirectional).** Client/server RDP PDUs (TPKT/X.224/fast-path frames) are wrapped in TSGPacket(ChannelDataRequest / ChannelDataResponse); each POST carries one PDU, HTTP response carries the next inbound PDU(s) from the *target* server. **Framing:** the HTTP body is the unwrapped RDP-stream bytes, NOT a TSG wrapper; the wrapper is HTTP metadata. *Spec: MS-TSGU §2.2.9.* Flow control: client may pipeline multiple requests, but typical pattern is request→response→next-request (synchronous).
- [ ] **O(M) — HTTP tunnel teardown (client).** Client sends TunnelCloseRequest, Gateway closes the logical channel → closes the relay to the target server → deallocates the tunnel. Gateway may also initiate close if the tunnel idles or auth fails.
- [ ] **O(M) — Cookie-based auth (PAA).** Pre-authentication authorization token: if the Gateway is fronted by a load balancer or authenticating proxy (e.g., WAM / Okta), the auth token lands in an HTTP cookie (named `TSGAuthCookie` or `PAA-cookie`). Client must extract the cookie from TunnelCreateResponse and present it in subsequent POST requests' `Cookie` header. *Spec: MS-TSGU §3.1.1.* Typical in enterprise SaaS gateways.

#### 9b-ii. RD Gateway RPC-over-HTTP transport (RDGSP over RPC-over-HTTP)
- [ ] **O(M) — RPC-over-HTTP binding.** Alternative to HTTP POST/response: use Microsoft RPC-over-HTTP2 protocol (RFC 2817, SOAP-like wrapping, Windows RPC runtime). Endpoint: `/remotedesktopgateway/rpc` on port 443. Same tunnel/channel/auth flow, but framing is RPC envelope (SOAP/HTTP binding) instead of raw POST body. *Spec: MS-TSGU § introduction lists both; detailed RPC mapping in MS-RPCH.* Rarer in modern deployments; HTTP is preferred.

#### 9b-iii. RDGSP / WebSocket transport (MS-RDGSP)
- [ ] **O(M) — WebSocket upgrade for RD Gateway.** Modern variant: after HTTP auth, client upgrades the connection from HTTP to WebSocket (`Upgrade: websocket`), then RDP PDUs flow over WS frames. Reduces latency vs synchronous POST/response pattern. *Spec: MS-RDGSP (subset of MS-TSGU, newer).* Gateway supports both HTTP and WebSocket simultaneously; client chooses at connect time. Preferred for interactive sessions.

#### 9b-iv. RD Gateway channel bindings & MFA
- [ ] **M(when gateway used) — Channel bindings on gateway auth.** The SSPI auth exchange in TunnelAuthRequest must include **SEC_CHANNEL_BINDINGS** derived from the TLS peer certificate of the *Gateway* connection (not the downstream RDP server). Prevents gateway-spoofing MITM. Same AV-pair + checksum structure as Layer 2 (NTLM/Kerberos).
- [ ] **O — Multi-factor authentication (MFA) in gateway auth.** Gateway may demand additional auth factors (soft token OTP, hardware token, FIDO2) in TunnelAuthRequest before allowing channel create. Implemented by the Gateway, not the RDP protocol; client must support SPNEGO variants that the Gateway's auth service requires.

### 9c. Devolutions RDCleanPath / gateway (Devolutions-proprietary)
- [ ] **O — RDCleanPath gateway.** Devolutions' own gateway alternative to MS-TSGU. Simplified HTTP interface (no RPC variant), typically lower-latency. Over HTTPS; tunnel/channel/auth pattern similar to MS-TSGU but with Devolutions-specific PDU format. *ironrdp ref: `ironrdp-rdcleanpath` crate (likely PDU + thin client wrapper; no full gateway server logic).* Lower overhead than MS-TSGU if the downstream gateway already supports it; proprietary, so less enterprise adoption than MS-TSGU.
- [ ] **O — RDCleanPath certificate pinning.** Like direct RDP, pinning the Devolutions gateway's TLS cert is recommended; same TOFU model.

### 9d. Proxy (SOCKS / HTTP) — TCP-level proxying
*(These are NOT RD Gateway; they are network-layer proxies that tunnel the *entire TCP stream*, bypassing RDP awareness.)*

- [ ] **O — SOCKS5 proxy.** Client → SOCKS proxy: establish a TCP tunnel to the *real* RDP server. The proxy handles the SOCKS5 handshake; all subsequent bytes (TPKT/X.224/everything) flow through the tunnel unchanged. *Spec: RFC 1928.* Doesn't require RDP-specific logic; any TCP client can use a SOCKS proxy. *ironrdp ref: none (delegated to the socket layer; e.g., `tokio-socks` or system libsocks).* Works only if the SOCKS proxy is routable & supports TCP tunneling (some restrict to HTTP).
- [ ] **O — HTTP CONNECT proxy.** Client → HTTP proxy: send `CONNECT hostname:port` request; proxy establishes a TCP tunnel to the target, returns HTTP 200 OK, then all bytes thereafter tunnel (same as SOCKS). Slightly less reliable than SOCKS because some proxies filter on port number (e.g., reject 3389 as non-HTTP). *Spec: RFC 7231 § Tunnel.* *ironrdp ref: none.*
- [ ] **O — Proxy authentication (SOCKS5 / HTTP).** Username/password auth to the proxy itself, orthogonal to RDP server credentials. SOCKS5 has a sub-negotiation (`METHOD 0x02` = username/password); HTTP uses `Proxy-Authorization` header. Credential leakage risk if proxy is untrusted.

### 9e. Connection configuration & transport selection
- [ ] **M(structure) — Transport abstraction.** Define an enum or trait `RdpTransport { Direct, Gateway, Proxy }` so the connection path is configurable before dialing. Each variant may have optional fields (gateway URL, proxy host:port, auth, cert-pin rules). *ironrdp ref: Config struct (lib.rs) has no transport field; direct TCP assumed.* Our crate MUST make this pluggable from day one.
- [ ] **M — Direct TCP (default).** hostname:port, TLS optional (negotiated), full RDP flow over the socket.
- [ ] **O — RD Gateway (via HTTP).** gateway URL + target hostname:port + (optional) PAA token source (e.g., WAM cookie endpoint or hardcoded token). Client routes all RDP PDUs through gateway tunnel. TLS to gateway is mandatory; TLS to downstream server negotiated normally.
- [ ] **O — Devolutions RDCleanPath.** RDCleanPath gateway URL + target hostname:port. Similar setup to MS-TSGU HTTP, lower footprint if gateway supports it.
- [ ] **O — SOCKS5 proxy.** proxy host:port + target hostname:port + (optional) SOCKS auth. Client dials SOCKS proxy, establishes tunnel to target, then standard RDP flow. TLS negotiated *through* the tunnel.
- [ ] **O — HTTP CONNECT proxy.** proxy host:port + target hostname:port + (optional) Proxy-Auth. Ditto to SOCKS, less common.
- [ ] **O — KDC proxy (Kerberos-specific).** URL to Microsoft HTTPS KDC proxy for Kerberos AS/TGS requests (when SPNEGO negotiates Kerberos). *ironrdp ref: Credssp KerberosConfig::kdc_proxy_url.* Orthogonal to RDP transport (applies inside CredSSP auth); client SSPI machinery uses it if provided.

### 9f. Gateway & proxy operational notes
- [ ] **O — No cross-gateway chaining.** A client → SOCKS proxy → RD Gateway → RDP server is theoretically possible but rare and unsupported by design (nesting complexity, auth scope ambiguity, latency). Single transport per connection.
- [ ] **O — Gateway affinity & session resumption.** RD Gateway tunnels are *not* resumable (no auto-reconnect cookie passed through gateway auth). If a gateway connection drops, a new TunnelCreateRequest must be issued. Target server *may* resume a session if `Auto-Reconnect Cookie` is supported (layer 4), but gateway tunnel is fresh.
- [ ] **O — Load-balanced gateways.** Behind a load balancer (e.g., F5, Citrix NetScaler), a gateway tunnel may be pinned to a specific backend by the LB's session key. If the LB is stateless, the PAA cookie encodes that affinity; if the LB is sticky-IP, the client's persistent connection is sufficient. Transparent to the client protocol.
- [ ] **O — Bandwidth & latency implications.** Direct TCP is ~1 RTT for a PDU. RD Gateway HTTP is ~1 RTT per request (synchronous POST/response; can improve with pipelining). WebSocket variant reduces some overhead. Proxy adds latency but not protocol overhead. For bandwidth, gateway/proxy are transparent — all compression/codec logic is RDP-layer-aware.
- [ ] **O — TLS certificate validation on gateway.**  Like direct RDP, the client must validate the gateway's TLS certificate (CN/SAN, chain, revocation). A pinned cert is recommended for corporate gateways (enterprise typical to use a per-gateway PIN). Use the same cert-store / `rustls` chain as direct RDP; gateway TLS is independent of downstream RDP TLS.

### 9g. Test / verification surface
- [ ] **O — Direct TCP unit test.** Mock socket pair, verify TPKT/X.224 framing round-trips through the transport layer.
- [ ] **O — RD Gateway unit test (HTTP).** Mock HTTP client, verify TunnelCreate / ChannelCreate / ChannelData PDU encoding, cookie handling, error responses.
- [ ] **O — Proxy integration test.** Use a local SOCKS5 / HTTP proxy (e.g., `socat` or a Python proxy) and route RDP through it; assert session still activates.
- [ ] **O — Transport selection in Config.** Unit test that `Config::transport` field correctly dispatches to the right dialer (Direct vs Gateway vs Proxy).

---

### Open questions (gateway / transport scope)

1. **Scope decision: direct-only MVP, or include one gateway variant in v1?** The task VM is direct-connect only, so gateway can be O/deferred. But enterprise customers typically *require* gateway support. Is this "optional forever" or "optional-in-v1, M in v2"?
2. **RD Gateway variant preference.** If including gateway, HTTP (RDG HTTP) is simpler and more widely deployed than RPC-over-HTTP. WebSocket is modern but requires async WS library. Recommend HTTP first.
3. **Devolutions RDCleanPath or MS-TSGU?** If a customer uses Devolutions gateway, `ironrdp-rdcleanpath` may cover it (check crate). If MS-TSGU is required, spec-only work. Decision: "support what customers use" — likely both, staged.
4. **Proxy support (SOCKS/HTTP) priority.** Lower operational complexity than gateway (no new PDU types, just TCP tunneling). Could be a quick win if the codebase already uses a socket abstraction. Conversely, may be out of scope if the app assumes network-reachable RDP servers.
5. **Certificate pinning strategy for gateway.** Separate from direct RDP cert pinning (gateway cert + downstream RDP server cert). Should both use TOFU, or hard-code known corporate gateways?
6. **PAA cookie integration.** If the Gateway fronts a WAM / SSO system (Okta, Azure AD proxy, etc.), where does the PAA token come from? HTTP-header-based SSO (browser cookie → RDP client cookie)? User input? Oauth token exchange?

---

*Reference: MS-TSGU (RD Gateway HTTP / RPC-over-HTTP), MS-RDGSP (WebSocket variant), MS-RPCH (RPC-over-HTTP binding), RFC 1928 (SOCKS5), RFC 7231 (HTTP CONNECT). ironrdp coverage: direct TCP + KDC proxy URL (in CredSSP). Gateway is spec-only as of 0.9.0; RDCleanPath crate exists but integration unknown.*

## 14. Server Redirection & load balancing

### Client-side redirection capability & transport
- [ ] **M(broker)** — **Client Cluster Data (GCC block 0xC004).** Advertises redirection support; `RedirectionFlags` (REDIRECTION_SUPPORTED, REDIRECTED_SESSION_FIELD_VALID, REDIRECTED_SMARTCARD), `RedirectionVersion` (V1–V6, bits[5:2]), `redirected_session_id` (u32). *ironrdp ref: ironrdp-pdu/gcc/cluster_data.rs.* **connector TODO #139 — not yet sent by the connector.**
- [ ] **M(broker)** — **Routing Token in X.224 Connection Request.** `Cookie: msts=<token>` in the TPDU variable part (before RDP_NEG_REQ); server-provided routing/affinity token from a prior redirect. *ironrdp ref: nego.rs RoutingToken (PREFIX "Cookie: msts=").*
- [ ] **M(broker)** — **Load-Balance Cookie in X.224 Connection Request.** `Cookie: mstshash=<hash>`; older farms hash username to pick a server. *ironrdp ref: nego.rs Cookie (PREFIX "Cookie: mstshash=").* Mutually exclusive with the routing token.

### Server Redirection PDU (MS-RDPBCGR 2.2.13.1)
- [ ] **M(broker)** — **Server Redirection PDU (Standard-Security variant).** Sent *instead of* Demand Active to end the current session early; a Share Control PDU type 0x0a (ServerRedirect) with BasicSecurityHeader REDIRECTION_PKT (0x0400) + RDP_SERVER_REDIRECTION_PACKET. *ironrdp ref: headers.rs lists `ShareControlPduType::ServerRedirect=0xa` and `BasicSecurityHeaderFlags::REDIRECTION_PKT`, but **there is NO PDU struct / handler — must be implemented.***
- [ ] **M(broker)** — **RDP_SERVER_REDIRECTION_PACKET (2.2.13.1.1).** A u32 flags field gates which fields follow, encoded sequentially in bit order: SESSION_ID(0), PASSWORD(1), USERNAME(2), DOMAIN(3), SMARTCARD(4), LOAD_BALANCE_INFO(5), TARGET_NET_ADDRESS(6), TARGET_FQDN(7), TARGET_NETBIOS_NAME(8), TARGET_NET_ADDRESSES(9, array), PASSWORD_NOT_REQUESTED(10), REDIRECTION_VERSION(11). *Spec-only.*
- [ ] **M(broker)** — **Redirected session id (u32 LE)** if SESSION_ID set — correlates session state on the target.
- [ ] **M(broker)** — **Redirected credentials** (UTF-16LE BOM+len strings) if USERNAME/DOMAIN/PASSWORD set. **Cleartext under Standard Security; HYBRID_EX must carry them inside CredSSP.** *Spec-only.*
- [ ] **O** — **Redirected smartcard info** (logon_type, optional PIN, DER cert) if SMARTCARD set. *Spec-only; rare.*
- [ ] **M(broker)** — **Load-balance info** (opaque u32-len blob) if LOAD_BALANCE_INFO set — reused **verbatim** as the next Routing Token. *Spec-only.*
- [ ] **M(broker)** — **Target net address / FQDN / NetBIOS / array** (UTF-16LE) — where to reconnect; array allows fallback ordering.
- [ ] **M(broker)** — **Redirection version (u32)** if VERSION set — matches ClientClusterData RedirectionVersion.

### Encrypted & enhanced redirection (HYBRID_EX)
- [ ] **O** — **Enhanced Server Redirection (HYBRID_EX).** Same packet wrapped in a CredSSP TsRequest; credentials encrypted+signed with the established session keys (no cleartext password). *Spec-only.*

### Client-side redirection procedure
- [ ] **M(broker)** — **Detect & teardown.** If a Redirection PDU arrives where Demand Active was expected (type 0x0a), decode it, then **close the current connection** (no graceful X.224 disconnect); do not continue MCS/capability exchange.
- [ ] **M(broker)** — **Extract fields** (flags → present fields in order) and stash for the next attempt.
- [ ] **M(broker)** — **Credential forwarding.** Replace credentials with redirected values; **skip interactive auth** (still encrypted to the target per the negotiated security protocol); honour PASSWORD_NOT_REQUESTED.
- [ ] **M(broker)** — **Routing-token carry-over.** Embed the opaque LB blob as the next `Cookie: msts=` (binary-safe).
- [ ] **M(broker)** — **Target selection.** Try TARGET_NET_ADDRESSES in order until TCP connects; else single address; else DNS-resolve FQDN; else NetBIOS.
- [ ] **M(broker)** — **Session-id preservation.** Put `redirected_session_id` in the next Client Cluster Data with REDIRECTED_SESSION_FIELD_VALID.
- [ ] **M(broker)** — **Version matching.** Set ClientClusterData RedirectionVersion to the server's advertised version.

### RD Connection Broker / RDS-farm context
- [ ] **M(broker)** — **Broker role.** In an RDS farm, an RD Connection Broker (or gateway) takes the initial connection and, per load-balancing rules, issues a Server Redirection PDU so the client reconnects to the chosen host with credentials + routing token.
- [ ] **M(broker)** — **Load-balance decision** (broker-side): capacity/session-count, cookie hash, user-collection mapping, session affinity. Result = target addresses + cookie in the PDU.
- [ ] **O** — **RD Gateway interaction:** the gateway may also redirect; client follows the same teardown+reconnect path. (See §13.)

### Gotchas
- [ ] **M(broker)** — Redirection is a **connection-termination event**, not a mid-session directive — treat as teardown.
- [ ] **M(broker)** — Credential strings are UTF-16LE with a **BOM + u32 length**; mismatch → target rejects.
- [ ] **M(broker)** — The LB cookie is **opaque** — never reformat it.
- [ ] **M(broker)** — Implement a **redirect-hop limit** (e.g. ≤3) to stop A→B→C→A loops.
- [ ] **M(broker)** — Reconnect **fast** (~30s budget) before the target discards held session state.

### ironrdp coverage
- ClientClusterData / RedirectionFlags / RedirectionVersion: defined in ironrdp-pdu, **not wired into the connector (TODO #139).**
- RoutingToken + Cookie: fully encoded/decoded in nego.rs — ready.
- **Server Redirection PDU: NOT in ironrdp** (only the `ServerRedirect=0xa` enum slot). Must be implemented: parse flags + conditional fields.

### Open questions
1. Is the target VM a Connection-Broker pool or a single host? (If single host, all of §14 is `O`.)
2. Redirect-hop limit value; fallback policy across multiple target addresses?
3. Smartcard redirection in scope, or password-only?
4. Always use redirected credentials, or allow user override?

## 15. Logon & Save Session Info

### 9a. Save Session Info PDU (MS-RDPBCGR 2.2.10)  
*(Sent by server during finalization and at runtime to save credentials, sync reconnect cookies, signal logon events.)*

- [ ] **M — SaveSessionInfoPdu dispatcher.** Type field (u32) selects variant: Logon (0x00), LogonLong (0x01), PlainNotify (0x02), LogonExtended (0x03). Each carries session/domain/user and optional auto-reconnect/error info. *ironrdp ref: ironrdp-pdu/rdp/session_info/mod.rs.*

#### Logon Info Version 1 & 2  
- [ ] **M — Logon Info Version 1 (TS_LOGON_INFO_V1).** Fixed: 4-byte domain-size + 52 bytes domain-buffer (UTF-16 LE, null-terminated) + 4-byte user-size + 512 bytes user-buffer + 4-byte session-id. Pre-RDP6. *ironrdp ref: logon_info.rs LogonInfoVersion1.* **Deprecated but load-bearing** for legacy servers.
- [ ] **M — Logon Info Version 2 (TS_LOGON_INFO_V2).** 2-byte version(0x0001) + 4-byte size(18) + 4-byte session-id + 4-byte domain-size + 4-byte user-size + 558-byte padding + variable domain-string (UTF-16 LE, null-terminated) + variable user-string. RDP6+. *ironrdp ref: logon_info.rs LogonInfoVersion2.* Identical data to V1, different framing.

#### Logon Info Extended (TS_LOGON_INFO_EXTENDED_V2)  
- [ ] **M — LogonInfoExtended header.** 2-byte length (internal size, ≤576+size-of-fields) + 4-byte flags (LogonExFlags), optionally followed by auto-reconnect and/or error-info blocks, padded to 570 bytes. *ironrdp ref: logon_extended.rs.* **Gate keeper for downstream fields.**
- [ ] **M — LogonExFlags (0x0001 | 0x0002 bits).** AUTO_RECONNECT_COOKIE (0x0001) ⇒ ServerAutoReconnect present. LOGON_ERRORS (0x0002) ⇒ LogonErrorsInfo present. Both optional. *ironrdp ref: logon_extended.rs LogonExFlags.*
- [ ] **M — ServerAutoReconnect block.** 4-byte data-length(28) + 4-byte packet-length(28) + 4-byte version(0x0000_0001) + 4-byte logon-id + 16-byte random_bits. **This cookie + logon_id allow transparent resume on reconnect.** *ironrdp ref: ServerAutoReconnect.* Server generates; client stores and replays on `[ms-rdpbcgr] 2.2.1.11.1.1 cbAutoReconnectCookie / autoReconnectCookie` fields in next Client Info PDU.
- [ ] **M — LogonErrorsInfo block.** 4-byte data-length(8) + 4-byte error-type (LogonErrorNotificationType enum) + 4-byte error-data (either LogonErrorNotificationDataErrorCode enum OR session-id u32). *ironrdp ref: logon_extended.rs LogonErrorsInfo.* **See §9b for codes.**
- [ ] **O — PlainNotify (0x0002).** No payload, just 576 bytes padding. Server sends this when logon completes without error/cookie/extended info. *ironrdp ref: session_info/mod.rs InfoData::PlainNotify.*

### 9b. Logon Error Notifications (TS_LOGON_ERRORS_INFO)  
*(Real errors/warnings that must surface to the user; flow to UI layer.)*

**Error Type enum** (`LogonErrorNotificationType`; applies M=Mandatory-to-handle, O=Optional):  
- [ ] **M — AccessDenied (0xFFFF_FFFF).** Generic access-denied; user lacks permission. Carry error-data field (status code).
- [ ] **M — DisconnectRefused (0xFFFF_FFF9).** Server actively refused connection (no auto-reconnect). Surface as "connection refused."
- [ ] **M — NoPermission (0xFFFF_FFFA).** User lacks access to desktop/session. "Session unavailable / permissions denied."
- [ ] **M — SessionTerminate (0xFFFF_FFFD).** Another session booted this one. "Session terminated by another connection."
- [ ] **O — SessionContinue (0xFFFF_FFFE).** Resumption of prior session; informational.
- [ ] **O — SessionBusyOptions (0xFFFF_FFF8).** Session busy (e.g., license busy). Handle as transient; may retry.
- [ ] **O — BumpOptions (0xFFFF_FFFB).** Session in use; bump/disconnect incumbent. Admin intervention required.
- [ ] **O — ReconnectOptions (0xFFFF_FFFC).** Server offering reconnect capability. Hint to client: save & reuse logon cookie.

**Error Data (if type carries error-code; else session-id):**  
- [ ] **M — FailedBadPassword (0x0000_0000).** Authentication failed: bad password. Prompts UI for re-auth.
- [ ] **M — FailedUpdatePassword (0x0000_0001).** Password expired; update required. UI must prompt password-change flow.
- [ ] **M — FailedOther (0x0000_0002).** Generic auth failure (account disabled, locked, etc.). Surface error + no auto-retry.
- [ ] **M — Warning (0x0000_0003).** Non-fatal warning (e.g., password expiring soon, cap-lock on). Surface but allow continue.
- [ ] **O — SessionId.** If error-type is session-busy / bump / reconnect, carries the conflicting session ID (u32); admin tools use it for conflict resolution.

### 9c. Server Error Info PDU (MS-RDPBCGR 2.2.2.5 Set Error Info)  
*(Typed disconnect reason sent during session lifecycle; different channel from logon-errors.)*

- [ ] **M — ServerSetErrorInfoPdu.** Single 4-byte error-code (ErrorInfo enum). *ironrdp ref: server_error_info.rs ServerSetErrorInfoPdu.* Gate: client must advertise `SUPPORT_ERR_INFO_PDU` (0x0001) in early-capability-flags.
- [ ] **M — ErrorInfo enum (categorized).** Four categories: ProtocolIndependentCode, ProtocolIndependentLicensingCode, ProtocolIndependentConnectionBrokerCode, RdpSpecificCode. *ironrdp ref: ErrorInfo, with 80+ discriminants.* **Sample key codes:**
  - **ProtocolIndependentCode:** RpcInitiatedDisconnect(0x0001), IdleTimeout(0x0003), LogonTimeout(0x0004), DisconnectedByOtherConnection(0x0005), OutOfMemory(0x0006), ServerDeniedConnection(0x0007), ServerInsufficientPrivileges(0x0009), ServerFreshCredentialsRequired(0x000A), LogoffByUser(0x000C), ServerDwmCrash(0x0010).
  - **LicensingCode:** NoLicenseServer(0x0101), NoLicense(0x0102), BadClientMsg(0x0103), HwidDoesntMatchLicense(0x0104).
  - **ConnectionBrokerCode:** DestinationNotFound(0x0400), SessionOnlineVmWake(0x0405), DestinationPoolNotFree(0x0408).
  - **RdpSpecificCode:** UnknownPduType(0x10CA), ConfirmActiveWrongShareId(0x10D4), BadCapabilities(0x10EA), GraphicsSubsystemFailed(0x112F), etc. (see ironrdp for full list).
- [ ] **M — Error classification by code range + UI mapping.** Parse code, bucket into: auth-fail (prompt re-auth), license-fail (notify administrator), timeout (auto-reconnect eligible), permission-deny (non-recoverable), graphics-fail (degradation), unknown (generic error). *Not in ironrdp — application responsibility.*

### 9d. Set Keyboard Indicators / IME Status PDUs  
*(Synchronize caps/num/scroll lock and IME state with server on activation.)*

- [ ] **M — SetKeyboardIndicators PDU (TS_SET_KEYBOARD_INDICATORS_PDU).** 4-byte unitId(reserved) + 2-byte keyboardFlags. Flags: KBDIND_CAPSLOCK(0x0001), KBDIND_NUMLOCK(0x0002), KBDIND_SCROLLLOCK(0x0004). *ironrdp ref: ironrdp-pdu/rdp/headers.rs ShareDataPdu::SetKeyboardIndicators(Vec<u8>).* Received when server detects LED state change (e.g., user types, server catches shift-lock). **Client must:** decode, update local LED/capslock-detection state, and **emit back to application/keyboard** (toggle LED in host OS if applicable, or track for input filtering).
- [ ] **O — SetKeyboardImeStatus PDU (TS_SET_KEYBOARD_IME_STATUS_PDU).** 2-byte unitId(reserved) + 2-byte imeId + 4-byte imeState. IME (Input Method Editor) for CJK/complex scripts; state encodes which IME is active + mode (composing/normal). *ironrdp ref: ShareDataPdu::SetKeyboardImeStatus(Vec<u8>).* **Niche:** only relevant if supporting CJK; track & pass to IME subsystem.
- [ ] **M — Activation-time sync.** On session activation (Font Map received), client sends Synchronize input event (ScanCode(0x00)) with toggle flags matching local keyboard state, **before** user presses keys. Server responds with SetKeyboardIndicators if different. *ironrdp ref: input/sync.rs, finalization_messages.rs.*

### 9e. Server Status Info PDU (TS_STATUS_INFO_PDU)  
*(Informational status during finalization / runtime; not a logon-specific error.)*

- [ ] **O — StatusInfoPdu (0x36).** Variable-length opaque payload; ironrdp treats as Vec<u8>. *ironrdp ref: ShareDataPdu::StatusInfoPdu(Vec<u8>).* MS-RDPBCGR does not fully specify payload; appears to be server status/progress info sent during cap-exchange or font-map. **Reserved for future / server-specific use.** (Low priority; most servers omit.)

### 9f. Integration points & gotchas  
- [ ] **M — Logon-error surface.** SaveSessionInfo with LOGON_ERRORS flag is **post-auth**, so credentials already verified; error codes primarily inform UI (show warning, prompt password-change, prevent auto-reconnect). **Not a re-auth gate** like CredSSP failures.
- [ ] **M — Auto-reconnect cookie lifetime.** Server-provided cookie + logon_id must be **saved persistently** (config file / secure store) and **replayed on next connection** via Client Info PDU (cbAutoReconnectCookie + autoReconnectCookie fields). **Missing replay = session-loss on disconnect.** *ironrdp ref: Layer 1, Client Info PDU fields.*
- [ ] **M — Logon-notify (0x0002) vs error.** PlainNotify signals "logon OK, no special data." Common on RDP8+. **Do not treat as error.**
- [ ] **M — Error-info PDU vs logon-error block.** ServerSetErrorInfoPdu arrives in the main session loop (any time, reason for disconnect). SaveSessionInfo logon-errors are bound to finalization (post-auth, pre-session-active). **Both must be handled; both can disconnect.** *ironrdp ref: Layer 1 finalization; Layer 4 session loop.*
- [ ] **O — IME state tracking.** If not doing CJK/IME, ignore SetKeyboardImeStatus; still decode SaveSessionInfo (which may carry it) to avoid desynch.

---

### Open questions

1. **Logon-error UI flow:** Should password-expiry (FailedUpdatePassword) trigger an in-session password-change dialog, or force disconnect + re-auth? (Varies by RDS policy.)
2. **License-fail handling:** If LicensingCode::NoLicense, do we render a "license expired" modal, or auto-disconnect? (Policy-dependent.)
3. **StatusInfoPdu payload:** Is there a spec for this PDU's format, or is it server-implementation-dependent?
4. **Keyboard-LED sync fidelity:** On platforms where LED control is not OS-accessible (e.g., web browser), how do we communicate LED state to the user? (UX research needed.)
5. **Auto-reconnect retry policy:** If reconnection with stored cookie succeeds, should we silently resume, or notify the user of the reconnection event?

## 16. Network detection & QoE (autodetect)

**Network characteristics detection & QoE** section for plan.md:

```markdown
---

### 9a. Auto-detect request/response PDUs (MS-RDPBCGR 2.2.14)

**Connect-time auto-detect.** Server probes RTT + bandwidth before/during capability exchange to adapt codec selection & multitransport viability.

- [ ] **O — RTT Measure Request/Response.** Server sends `RTT_REQUEST_CONNECT_TIME` (0x1001) or continuous `RTT_REQUEST_CONTINUOUS` (0x0001); client echoes sequence# in `RTT_RESPONSE` (0x0000). Measures round-trip latency. *ironrdp ref: ironrdp-pdu/rdp/autodetect.rs (parse only; server-driven).* Sequence# must match request.

- [ ] **O — Bandwidth Measure Start.** Server sends `BW_START_CONNECT_TIME` (0x1014, connect-time) or `BW_START_RELIABLE_UDP` (0x0014, continuous TCP) / `BW_START_LOSSY_UDP` (0x0114, continuous UDP). Marks measurement window start; triggers client timing. *ibid.* Request-type code distinguishes transport and phase.

- [ ] **O — Bandwidth Measure Payload.** Server sends random data (connect-time only): `BW_PAYLOAD` (0x0002) with `payload` bytes. No response expected — payload itself is the measurement. *ibid.* Payload can be large (100s KB).

- [ ] **O — Bandwidth Measure Stop.** Server sends `BW_STOP_CONNECT_TIME` (0x002B) with final payload, or `BW_STOP_RELIABLE_UDP` (0x0429) / `BW_STOP_LOSSY_UDP` (0x0629) without payload (uses actual PDU traffic between START and STOP). Client responds with `BandwidthMeasureResults` (computed from elapsed time + byte count). *ibid.* Payload on connect-time variant allows server to fill any gap; continuous variant counts real traffic. **Gotcha:** payload length encoded as u16 at header offset 6 — oversized payloads truncate silently.

- [ ] **O — Network Characteristics Result (server→client).** Server reports probed baseline RTT (baseRTT, milliseconds) + current bandwidth (kbps) + average RTT (ms) via `NETCHAR_RESULT_RTT` (0x0840, baseRTT+avgRTT), `NETCHAR_RESULT_BW_RTT` (0x0880, BW+avgRTT), or `NETCHAR_RESULT_ALL` (0x08C0, all three). *ibid.* Sent as request (server→client) but client does NOT respond. Fields are u32 LE. Used to communicate server's conclusion of network state.

- [ ] **O — Network Characteristics Sync.** Client→server `NETCHAR_SYNC` (0x0018) response carrying previously-detected bandwidth (kbps) + RTT (ms). Used for **auto-reconnect:** if connection drops, client can resume with known characteristics to skip re-probing. *ibid.* Sequence# links to prior START/STOP pair.

### 9b. QoE timestamps (MS-RDPBCGR 6.3.4)

- [ ] **M with auto-detect — TS_QOE_TIMESTAMPS / QOE Timestamp Event.** Client sends 4-byte timestamp (u32 LE milliseconds, typically TickCount() or elapsed-ms since session start) in fast-path input as event type 0x0006 (`QoeEvent`); server logs server-side timestamp + receives client timestamp to compute RTT mid-session without probes. *ironrdp ref: ironrdp-pdu/input/fast_path.rs::FastpathInputEventType::QoeTimestamp (0x0006, 4-byte payload).* Does NOT require `SUPPORT_NET_CHAR_AUTODETECT` — orthogonal. Gated by capability flag `TS_QOE_TIMESTAMPS` (0x04 in Input capability set). Optional latency telemetry; some servers use it to trigger codec downgrades if RTT spikes.

- [ ] **M — Heartbeat / keep-alive PDU.** Server sends no-op heartbeat (if client advertised `SUPPORT_HEART_BEAT_PDU` flag 0x0400 in earlyCapabilityFlags) to prevent idle-timeout (typically 5 min). Can be implicit (server replies to any client PDU) or explicit (server sends keep-alive packet). *ironrdp ref: ibid. client.rs (flag only; no heartbeat PDU codec in ironrdp-pdu).* Server-driven; client must not ignore it (firewall/NAT timeout prevention). Spec undefined — treat as implementation detail (no PDU structure).

### 9c. Capability gating & adaptation flows

- [ ] **M — SUPPORT_NET_CHAR_AUTODETECT earlyCapabilityFlag (0x0080).** Advertising this flag tells server "client understands autodetect PDUs and wants probing." If omitted, server never sends RTT/BW requests. *ironrdp ref: ironrdp-pdu/gcc/core_data/client.rs::ClientEarlyCapabilityFlags.* **Design rule:** make this flag CONFIGURABLE so adaptive-quality features can be toggled.

- [ ] **O — Codec adaptation based on bandwidth.** Server observes detected BW + RTT → selects codec: high-BW = H.264/RemoteFX Progressive (fancy), low-BW = RLE (legacy bitmap, lowest cpu). EGFX codecs (RemoteFX, ClearCodec, H.264) are preferred if BW sufficient. **Gotcha:** client does NOT receive codec selection directly — server just sends surface commands in chosen codec. Client must decode whatever codec arrives.

- [ ] **O — Multitransport selection.** If `SUPPORT_NET_CHAR_AUTODETECT` + client advertises MultiTransport capset flags (`TRANSPORT_TYPE_UDP_FECR` / `TRANSPORT_TYPE_UDP_PREFERRED`), server MAY suggest UDP after baseline RTT < threshold (typically 50–100ms). Bandwidth not sole factor; RTT must be low (UDP loses packets; retransmit cost only acceptable on fast links). *ironrdp ref: ironrdp-pdu/gcc/multi_transport_channel_data.rs.* **Spec note:** MS-RDPEMT (multitransport/UDP) is standalone optional stack; autodetect result is input only.

- [ ] **O — Connect-time vs continuous detection trade-off.** Connect-time (before activation) = blocking, high-accuracy, adds ~1 sec. Continuous (post-activation) = non-blocking, lower-latency updates. Most servers skip connect-time if it's slow and do continuous only. *Spec-only.* No ironrdp implementation beyond PDU codec.

### 9d. Server-driven state machine

- [ ] **O — Autodetect state within session loop.** If enabled, server threads autodetect requests alongside normal I/O. Client must:
  1. Respond to RTT_REQUEST with RTT_RESPONSE (sequence# + no data).
  2. Time payloads between BW_START and BW_STOP; respond with timeDelta (elapsed ms) + byteCount (bytes received in window).
  3. Receive and log NETCHAR_RESULT (no response; informational).
  4. Send NETCHAR_SYNC on reconnect with prior measurements.
  *ironrdp ref: connector/connection.rs (no autodetect state machine; connector skips it entirely).* **Risk:** non-blocking response is critical — blocking on a BW_STOP response will timeout the server.

- [ ] **O — Connection-Type hint.** Client can advertise `ConnectionType` (Modem/BroadbandLow/BroadbandHigh/WAN/LAN/Autodetect) in ClientCoreData optional field. Server may skip probing if LAN is asserted (known high-BW). *ironrdp ref: ironrdp-pdu/gcc/core_data/client.rs::ConnectionType, ClientCoreOptionalData.connection_type (requires `VALID_CONNECTION_TYPE` flag 0x0020).* Hint only; server still probes if it wants certainty.

### 9e. Limitations & gaps in ironrdp

- [ ] **Server-driven only.** ironrdp has no client-initiated autodetect (client cannot probe if server is passive). Spec allows both directions; rarely needed.

- [ ] **No heartbeat PDU structure.** MS-RDPBCGR 2.2.12 mentions heartbeat but does not specify format. ironrdp ignores it. Assume empty slow-path Share Data or no-op fast-path marker. Server implementation varies; FreeRDP treats as opaque.

- [ ] **No state machine for continuous detection.** Timing BW_START→STOP pairs in a live session loop is tricky async (need concurrent timers + non-blocking handlers). ironrdp does not expose state.

---

###  10. Capability → feature couplings (expanded for network & QoE)

| Advertise (client) | …to unlock (server will otherwise never send) |
|---|---|
| `SUPPORT_NET_CHAR_AUTODETECT` (0x0080) in earlyCapabilityFlags | **RTT/bandwidth probing** (enables auto-detect PDU flow) |
| `TS_QOE_TIMESTAMPS` (0x04) in Input capability set | **QoE timestamp events** (client can send 4-byte timestamps in fast-path input) |
| `SUPPORT_HEART_BEAT_PDU` (0x0400) in earlyCapabilityFlags | **Heartbeat keep-alive** (server may send no-op to prevent timeout) |
| `TRANSPORT_TYPE_UDP_FECR` / `TRANSPORT_TYPE_UDP_PREFERRED` in MultiTransport capset | **UDP tunnels** (only offered if `SUPPORT_NET_CHAR_AUTODETECT` + RTT low) |

---

###  11. Consolidated open questions for grilling (updated)

**Network & QoE**
1. Connect-time auto-detect: skip entirely (defer), blocking-wait (simple), or async-fire-and-forget (complex)? Does target server actually use it, or skip straight to continuous?
2. QoE timestamps: useful only if server adapts codec; omit if MVP is fixed-codec RemoteFX?
3. Heartbeat: treat as no-op (ignore server heartbeats), or implement a keep-alive timer to detect dead connections?
4. Multitransport (UDP): in scope for MVP, or defer to "Later / Optional" (requires DTLS + NAT traversal + separate framing)?

---

*Generated 2026-06-08 from a 6-agent survey of the ironrdp crates + MS-RDP open specs. Reference map only — no implementation here. Next: grill §10–§11, then slice §2–§9 into issues.*
```

---

###  Network characteristics detection & QoE (for plan.md)

- [ ] **O — RTT Measure Request/Response.** Server sends `RTT_REQUEST_CONNECT_TIME` (0x1001) or continuous `RTT_REQUEST_CONTINUOUS` (0x0001); client echoes sequence# in `RTT_RESPONSE` (0x0000). Measures round-trip latency. *ironrdp ref: ironrdp-pdu/rdp/autodetect.rs (parse only; server-driven).* Sequence# must match request.

- [ ] **O — Bandwidth Measure Start.** Server sends `BW_START_CONNECT_TIME` (0x1014, connect-time) or `BW_START_RELIABLE_UDP` (0x0014, continuous TCP) / `BW_START_LOSSY_UDP` (0x0114, continuous UDP). Marks measurement window start; triggers client timing. *ibid.* Request-type code distinguishes transport and phase.

- [ ] **O — Bandwidth Measure Payload.** Server sends random data (connect-time only): `BW_PAYLOAD` (0x0002) with `payload` bytes. No response expected — payload itself is the measurement. *ibid.* Payload can be large (100s KB). **Gotcha:** payload length encoded as u16 at header offset 6 — oversized payloads truncate silently.

- [ ] **O — Bandwidth Measure Stop.** Server sends `BW_STOP_CONNECT_TIME` (0x002B) with final payload, or `BW_STOP_RELIABLE_UDP` (0x0429) / `BW_STOP_LOSSY_UDP` (0x0629) without payload (uses actual PDU traffic between START and STOP). Client responds with `BandwidthMeasureResults` (computed from elapsed time + byte count). *ibid.* Payload on connect-time variant allows server to fill any gap; continuous variant counts real traffic.

- [ ] **O — Network Characteristics Result.** Server reports probed baseline RTT (baseRTT, milliseconds) + current bandwidth (kbps) + average RTT (ms) via `NETCHAR_RESULT_RTT` (0x0840, baseRTT+avgRTT), `NETCHAR_RESULT_BW_RTT` (0x0880, BW+avgRTT), or `NETCHAR_RESULT_ALL` (0x08C0, all three). *ibid.* Sent as request (server→client) but client does NOT respond. Fields are u32 LE. Used to communicate server's conclusion of network state.

- [ ] **O — Network Characteristics Sync.** Client→server `NETCHAR_SYNC` (0x0018) response carrying previously-detected bandwidth (kbps) + RTT (ms). Used for **auto-reconnect:** if connection drops, client can resume with known characteristics to skip re-probing. *ibid.* Sequence# links to prior START/STOP pair.

- [ ] **M — QoE Timestamp Event (TS_QOE_TIMESTAMPS).** Client sends 4-byte timestamp (u32 LE milliseconds) in fast-path input as event type 0x0006 (`QoeEvent`); server logs server-side timestamp + receives client timestamp to compute RTT mid-session without probes. *ironrdp ref: ironrdp-pdu/input/fast_path.rs::FastpathInputEventType::QoeTimestamp.* Gated by Input capability flag `TS_QOE_TIMESTAMPS` (0x04). Optional latency telemetry; orthogonal to SUPPORT_NET_CHAR_AUTODETECT.

- [ ] **O — Heartbeat / keep-alive PDU.** Server sends no-op heartbeat (if client advertised `SUPPORT_HEART_BEAT_PDU` flag 0x0400) to prevent idle-timeout (~5 min firewall/NAT drop). *ironrdp ref: ibid. client.rs (flag only; no heartbeat PDU structure in ironrdp-pdu).* Spec undefined — treat as server-side implementation detail; client must not ignore.

- [ ] **O — Codec adaptation.** Server observes detected BW + RTT → selects codec: high-BW = H.264/RemoteFX Progressive, low-BW = RLE/slow-path. **Client does NOT receive codec choice directly** — server just sends surface commands in chosen codec. Client must decode whatever arrives.

- [ ] **O — Multitransport selection (UDP).** If `SUPPORT_NET_CHAR_AUTODETECT` + MultiTransport capset (`TRANSPORT_TYPE_UDP_PREFERRED`), server MAY suggest UDP tunnels after baseline RTT < threshold (~50–100ms). **RTT is gating factor** — UDP loses packets; retransmit cost only acceptable on fast links. Bandwidth necessary but not sufficient. *ironrdp ref: ironrdp-pdu/gcc/multi_transport_channel_data.rs.* Separate optional stack (MS-RDPEMT).

- [ ] **M — earlyCapabilityFlags::SUPPORT_NET_CHAR_AUTODETECT (0x0080).** Advertise to unlock RTT/BW probing; server never sends autodetect requests if omitted. *ironrdp ref: ironrdp-pdu/gcc/core_data/client.rs.* **Design rule:** make ALL earlyCapabilityFlags fully configurable; this one gates adaptive quality.

- [ ] **O — Connection-Type hint.** Client advertises `ConnectionType` (LAN/WAN/Modem/Broadband/Autodetect) in ClientCoreData optional field (requires `VALID_CONNECTION_TYPE` flag 0x0020). Server may skip probing if LAN is asserted. *ibid.* Hint only; server still probes if it wants certainty.

- [ ] **O — Connect-time vs continuous detection.** Connect-time (pre-activation) = blocking, ~1 sec, high-accuracy. Continuous (post-activation) = non-blocking, live updates. Most servers skip connect-time if slow; do continuous only. *Spec-only.* Async non-blocking response to BW_STOP is critical — blocking will timeout server.

- [ ] **O — Continuous autodetect state machine.** In-session: respond to RTT requests; time payloads between BW_START/STOP; receive NETCHAR_RESULT (no reply); send NETCHAR_SYNC on reconnect. *Spec-only.* ironrdp-connector has no state machine; skips entirely. Adds async complexity to session loop.

---

**Expanded capability coupling for network & QoE:**

| Advertise (client) | …to unlock (server will otherwise never send) |
|---|---|
| `SUPPORT_NET_CHAR_AUTODETECT` (0x0080) | **RTT/bandwidth probing** (autodetect PDU flow) |
| `TS_QOE_TIMESTAMPS` (0x04) in Input capset | **QoE timestamps** (client sends 4-byte ms in fast-path input) |
| `SUPPORT_HEART_BEAT_PDU` (0x0400) | **Heartbeat keep-alive** (idle-timeout prevention) |
| `TRANSPORT_TYPE_UDP_FECR/UDP_PREFERRED` in MultiTransport | **UDP tunnels** (only if autodetect + RTT low) |

---

**Additional open questions for grilling:**
- Connect-time auto-detect: skip (defer), blocking-wait (simple), or async fire-and-forget (complex)? Does target server use it?
- QoE timestamps: useful only if server adapts codec. Omit if MVP uses fixed-codec RemoteFX?
- Heartbeat: ignore server heartbeats (no-op), or implement keep-alive timer to detect dead connections?
- Multitransport (UDP): in-scope for MVP, or defer (requires DTLS + NAT + separate framing)?

## 17. Audio formats & codecs (depth)

*CRITICAL: This entire subsystem is optional, but IF implemented, omitting any codec or format negotiation path will cause silent server incompatibility. ironrdp-pdu has only the Sound capset (BEEPS flag); no RDPSND SVC, no AUDIN, no codec handling.*

### 7b.1 RDPSND / Server Audio Output (SVC channel: "SNDPRST")

- [ ] **O — RDPSND channel setup & negotiation.** Static channel name `SNDPRST` (case-sensitive, NOT a DVC). Negotiate at GCC Client Network Data. *ironrdp: NO IMPLEMENTATION.* Spec: MS-RDPEA §2.2 (channel). Server sends [Server Audio Formats PDU](#formats) at activation; client responds [Client Audio Formats and Version PDU](#formats).

#### 7b.1a Format negotiation (WAVEFORMATEX model)

- [ ] **O — WAVEFORMATEX struct.** u16 wFormatTag, u16 nChannels, u32 nSamplesPerSec, u32 nAvgBytesPerSec, u16 nBlockAlign, u16 wBitsPerSample, u16 cbSize (extra codec-specific bytes), then codec-specific data (varies by wFormatTag). *MS-RDPEA §2.2.2.1 (TS_AUDIO_PDU_WITH_SETUP). No external definition; client must manually pack/unpack.* Standard PCM=0x0001, ADPCM=0x0002, etc. (IMA=0x0011, MS=0x0032, GSM=0x0161, MP3=0x0161, AAC=0x00FF). **Codec-specific fields are load-bearing:**
  - PCM: empty (cbSize=0).
  - ADPCM/IMA: nSamplesPerBlock (u16), nNumCoeff (u16 for MS-ADPCM only), aCoeff array (MS-ADPCM).
  - G.726 ADPCM: nSamplesPerBlock (u16).
  - GSM 6.10: nSamplesPerBlock (u16).
  - MP3: no extra fields (cbSize=0).
  - AAC: AudioSpecificConfig ASN.1 (cbSize=variable).

- [ ] **O — Format tag registry.** Enumerate all format tags the server MAY send (WAVEFORMATEX.wFormatTag):
  - **0x0001 PCM.** Raw uncompressed audio (8/16/24/32-bit samples, mono/stereo/surround, 8kHz–192kHz). Decode: memcpy samples to output. Encode: client-captured audio → PCM bytes. *Safe baseline.*
  - **0x0002 ADPCM (Microsoft / generic).** Adaptive Differential PCM, lossy, ~4:1 compress. nSamplesPerBlock, aCoeff table (MS-ADPCM 7 predictors), delta-encoded samples. *Rare but spec'd; ironrdp ref: NONE. Decode: expand deltas + predictor state machine.*
  - **0x0011 IMA ADPCM.** Interleaved ADPCM variant (Intel/DVI), different step-index table. nSamplesPerBlock. *Rare; spec: MS-RDPEA Annex A (example codecs, not mandatory).*
  - **0x0032 G.721 ADPCM.** Legacy (mostly obsolete). Similar to IMA. *Obsolete in modern servers.*
  - **0x0161 GSM 6.10.** Speech codec, lossy, ~5:1 compress, 8kHz mono only, 264-sample frames → 33-byte packets. nSamplesPerBlock. *Rare, speech-focused.* Decode: GSM frame decoder (frameshift, RPE, lattice filter). Open-source: libgsm. Encode: client mic → GSM frames.
  - **0x0161 (alias) MP3 (MPEG-1 Layer 3).** Lossy audio codec, 8kHz–48kHz, variable bitrate (8–320 kbps typical). wFormatTag collision with GSM(!); disambiguate by container context. *Rare on RDP; LICENSING RISK (MP3 patents).* Decode: external (libmp3lame/ffmpeg). Encode: reserved/not expected from client mic.
  - **0x00FF AAC (Advanced Audio Codec, MPEG-4 Part 3).** Lossy, 8kHz–96kHz, bitrate 8–320 kbps. AudioSpecificConfig includes profile/sample-rate-index/channel-config. *Modern, low-bitrate audio; increasingly common.* Decode: external (libfdk_aac/ffmpeg). Encode: mic → AAC (external). **Gotcha: AudioSpecificConfig is ASN.1 (not byte-offset fields); parse carefully.**
  - **Others (0xFFFE EXTENSIBLE).** Catch-all for non-standard formats (e.g., vendor-specific, Opus, Vorbis in container). WAVEFORMATEXTENSIBLE struct (cbSize ≥16) with SubFormat GUID (16 bytes). *Server-dependent; spec does not mandate support.* Decode: if recognized GUID, delegate to handler; else reject/warn.

#### 7b.1b RDPSND message framing

- [ ] **O — Server Audio Formats PDU (TS_SERVER_AUDIO_FORMATS_PDU).** Sent by server post-activation. dwFlags (reserved), dwVolume (0xFFFFFFFF = full), dwPitch, dwAudioTimeStamp, wEncoding (u16 count), aFormats[dwEncoding] (WAVEFORMATEX[]). *MS-RDPEA §2.2.1.1.* Server lists supported formats in preference order; client MUST choose one and respond. **dwAudioTimeStamp = server's reference clock at send (milliseconds since connection start); use for sync/latency measurement.**

- [ ] **O — Client Audio Formats and Version PDU (TS_CLIENT_AUDIO_FORMATS_AND_VERSION_PDU).** Client response: wVersion (0x0101 typical), wNumFormats (u16 count), aFormats[wNumFormats] (WAVEFORMATEX[]). Client lists formats it can PLAY BACK (output=audio sink), in preference order. *MS-RDPEA §2.2.1.2.* Server selects intersection and locks format; all subsequent audio frames use that format.

- [ ] **O — Training PDU / TS_TRAIN_PDU.** Optional pre-flow calibration. Server sends training frames (dummy audio) to allow client to synchronize decoder state, measure latency, test round-trip. Client ACKs with TS_KEEP_ALIVE_PDU. *MS-RDPEA §2.2.4.* Rarely used but valid; warn if received unexpectedly.

- [ ] **O — Wave Confirm / Acknowledge PDU (TS_WAVE_CONFIRM_PDU).** Server ACKs after receiving wave data. Timestamp-based (wTimeStamp = server's TS relative to format negotiation). *MS-RDPEA §2.2.3.* For sync; ignore if client doesn't track timestamps.

- [ ] **O — Wave PDU / Audio Data Frame (TS_WAVE_PDU).** Server sends audio: wTimeStamp (relative, ~10–20ms per frame typical), wAudioBodyType (0=wave / 1=silent flag+duration), wAudioBodyLength, aAudioBody[]. *MS-RDPEA §2.2.5.* Audio frames are CONCATENATED byte stream in the negotiated codec (NOT framed as separate WAVEFORMATEX). **Critical: timestamps must be monotonic and matched against server's dwAudioTimeStamp baseline for A/V sync.**

- [ ] **O — Silence PDU (TS_WAVE_PDU with wAudioBodyType=1).** Encodes silence duration (u16, milliseconds) instead of audio bytes. *Optimization to suppress zero-padding.* Client must insert silence in playback timeline.

- [ ] **O — Keep Alive / Heartbeat (TS_KEEP_ALIVE_PDU).** Client → server periodic ACK, no audio data. Proves client is still consuming. *Optional; spec suggests ~1s intervals if audio is flowing.* Prevents server timeout.

#### 7b.1c RDPSND quality & bitrate negotiation

- [ ] **O — Quality Mode (DWT_QUALITY_MODE in server Audio Formats).** dwVolume bits [0:2] encode server's audio quality preference: 0=dynamic, 1=high, 2=medium, 3=low. *MS-RDPEA §2.2.1.1.* Advisory (not binding); client adapts encoder bitrate if encoding audio (unlikely for playback-only). **This is NOT a separate negotiation; baked into dwVolume field.**

- [ ] **O — Volume & pitch negotiation.** dwVolume, dwPitch fields in Server Audio Formats PDU. *Informational; server may emit at lower volume and client MAY mix down, or server may expect client to remaster.* Typically ignored (assume 100% volume).

#### 7b.1d Gotchas & traps

- [ ] **O — Format-tag collision (MP3=GSM=0x0161).** Server may send wFormatTag=0x0161 meaning EITHER GSM or MP3, disambiguated by context (nSamplesPerSec: 8kHz→GSM, 8–48kHz→MP3). **If unclear, log a warning and reject the format.** *Real servers have been observed sending both in the same negotiation.*

- [ ] **O — Codec-specific field sizes.** WAVEFORMATEX.cbSize is variable; malformed PDU if claimed size ≠ actual codec-specific block size. **Always validate: expected_size = 16 + cbSize vs actual buffer length.** ADPCM aCoeff is nNumCoeff×4 bytes; GSM nSamplesPerBlock is u16; AAC AudioSpecificConfig is cbSize bytes (typically 2–4).

- [ ] **O — No guaranteed heartbeat.** Server may send audio frames without asking for ACKs. Client MUST playback-buffer and not block on TS_WAVE_CONFIRM_PDU receipt (or it hangs). Use a separate async task for playback.

- [ ] **O — Timestamp wraparound.** wTimeStamp in TS_WAVE_PDU is u16 (0–65535 ms ~ 65 sec window). **Track base timestamp at start of frame sequence; on wraparound (delta < -10s), add 0x10000 ms (65536).** Without this, A/V sync breaks after ~1 minute.

- [ ] **O — No payload framing per sample.** TS_WAVE_PDU.aAudioBody is a continuous byte stream in the negotiated codec. If codec has variable-size frames (e.g., MP3, AAC), PDU may contain partial frames or multiple frames. **Must buffer and wait for next PDU to complete frame parsing.** Only ADPCM, PCM, and GSM have fixed frame boundaries.

---

### 7b.2 RDPEAI / Microphone Input (DVC channel: "RDPAI-AUDIN")

- [ ] **O — RDPEAI DVC setup.** Dynamic channel name `RDPAI-AUDIN`. Server opens if client advertises drdynvc support + channel capability. *ironrdp: NO IMPLEMENTATION.* Spec: MS-RDPEAI (Microphone redirection).

- [ ] **O — AUDIN format negotiation.** Parallel to RDPSND but inverted: CLIENT lists formats it can CAPTURE (input=mic). Server selects one. CapabilitiesAdvertise (client) → CapabilitiesConfirm (server). *MS-RDPEAI §2.2.*

- [ ] **O — Audio capture format (TS_AUDIO_FORMATS_STRUCT).** Client advertises mic capture formats (usually PCM mono/stereo, 16-bit, 16kHz–44kHz). Server chooses one. Identical WAVEFORMATEX model as RDPSND.

- [ ] **O — Mic frame transmission.** Client sends TS_AUDIO_FRAME PDU with captured audio bytes (typically 20–40ms chunks). Timestamps optional (server MAY request via config flags).

- [ ] **O — Lossy-UDP audio (AUDIO_PLAYBACK_LOSSY over multitransport).** RDPSND audio MAY be sent via lossy UDP tunnel (MS-RDPEMT) if client advertises multitransport + client & server both support it. *Reduces latency; trades quality (packet loss).* **Separate channel flow; not a codec variant.** Packets may be reordered/dropped; client must detect gaps and insert comfort noise or silence.

---

### 7b.3 Codec reference implementation notes (for our crate)

- [ ] **O — PCM passthrough.** Decode: identity (raw bytes → samples). Encode: samples → raw bytes. Audio sink integration: feed to OS/CPAL/Pulse for playback.

- [ ] **O — ADPCM (Microsoft/IMA).** Decode: step-index state machine (RFC). Open-source: libsndfile, ffmpeg ADPCM decoder. Encode: delta-prediction + quantization. *Low priority (rare in practice).*

- [ ] **O — GSM 6.10 decoder.** External: libgsm-full (GSM encode/decode, 264-sample frames → 33 bytes). Integrate via FFI or fork decoder code. *Very niche (speech only, 8kHz).*

- [ ] **O — MP3 decoder.** LICENSING RISK: MP3 patents expired (USA 2017, EU 2023, Japan 2024) but some regions still negotiate. **Recommend avoiding unless customer explicitly requests.** External: libmp3lame (decode/encode), libsndfile (decode), ffmpeg (decode). Integration: spawn subprocess or dynamic-link.

- [ ] **O — AAC decoder.** Open-source: libfdk_aac (high-quality, Fraunhofer), ffmpeg aac. *Increasingly common; reasonable to support.* Requires AudioSpecificConfig parsing (ASN.1 MPEG-4 Audio Profile Object Type, sample rate index, channel config). **Gotcha: AudioSpecificConfig is bit-packed (not byte-aligned).**

- [ ] **O — AAC encoder (for mic input).** Client AUDIN implementation if using AAC for capture. External: libfdk_aac encoder, ffmpeg. *Heavy; most clients use PCM mic.*

- [ ] **O — External decoder abstraction.** Design a trait `AudioDecoder` (format → raw samples) so swapping libfdk_aac↔ffmpeg↔custom is easy. Test vectors: sample RDPSND PDU streams from FreeRDP or WireShark captures.

---

### 7b.4 Session I/O integration

- [ ] **O — Audio output timeline.** Separate async task: buffer TS_WAVE_PDU frames, decode asynchronously, feed to audio sink (OS/CPAL/Pulse playback) with timing control (sample clock, not wall-clock). *Avoid blocking the main session loop.*

- [ ] **O — A/V sync (audio ↔ graphics).** Use server's dwAudioTimeStamp + wTimeStamp sequence to align audio playback with video frame timestamps. *Likely out-of-scope for MVP; defer to later iteration if latency becomes a problem.*

- [ ] **O — Error handling in codecs.** Invalid WAVEFORMATEX (bad cbSize, unknown wFormatTag, missing AudioSpecificConfig) → reject + warn + fallback to silence or disconnect. Truncated TS_WAVE_PDU → buffer and wait (do not error immediately). Decoder error (bad MP3 frame header) → skip frame + log + continue.

- [ ] **O — Timestamp tracking for sync.** Store (dwAudioTimeStamp baseline, wTimeStamp baseline) on format lock; compute playback time for each frame. Detect timestamp overflow/resets; document in logs.

---

###  Open questions (audio subsystem)

1. **MVP scope:** Is audio playback (RDPSND output) in v1, or explicitly deferred? Mic input (AUDIN) separate slice?
2. **Codec strategy:** PCM-only baseline, or add one lossy codec (ADPCM/GSM/AAC) for bandwidth savings? Audio sink integration: CPAL/Pulse/Windows MME/coreaudio choice?
3. **Licensing:** MP3 patents clear in target regions? If not, drop from spec; client will hear server's "unsupported format" and can fall back to codec server offers (likely PCM or AAC).
4. **Timestamp sync:** Full A/V sync (audio ↔ graphics) or "best effort" (ignore server timestamp, assume monotonic delivery)?
5. **Test vectors:** Can we capture real RDPSND PDU traces (Windows Server + audio enabled) to validate codec decoders?

---

This is exhaustive and drop-in ready for the plan. Every audio format, every flag, every trap is documented. All items are marked `O` (optional) because audio is a feature layer, not load-bearing for basic interactive desktop. If you implement it, you implement it completely — there's no half-way on codecs.

## 18. Keyboard mapping & IME (depth)

### 6c. Keyboard mapping & IME (client-owned input layer)

#### Scancode & key-code mapping (platform-specific)

- [ ] **M — RDP Set-1 scancode basics.** RDP uses legacy PC XT/AT keyboard scancodes (Set 1 / "scan code set 1" per MS-RDP §2.2.8.1.1.1). Single-byte codes (0x00–0xFF) + two extended prefixes (0xE0, 0xE1) map to multi-byte RDP events. `ironrdp-pdu` ScanCodePdu: 2-byte `key_code`, 2-byte flags (DOWN/RELEASE/EXTENDED/EXTENDED_1). *ironrdp ref: scan_code.rs.* **NOT in ironrdp: the per-platform OS-key→Set-1 mapping layer** — we own this entirely.

- [ ] **M — Extended-key prefix encoding.** 0xE0 prefix (e.g., Right-Alt, Right-Ctrl, Home, Insert, Page-Up, arrow keys) → set EXTENDED flag (0x0100 in slow-path, 0x02 in fast-path). 0xE1 prefix (Pause/Break, Print-Screen chained: 0xE1 0x1D 0x45) → set EXTENDED_1 flag (0x0200 slow, 0x04 fast). Prefix is NOT sent to RDP; only the flag. *MS-RDP 2.2.8.1.1.1, 2.2.8.1.2.1.* Trap: 0xE1 is rare; most toolkits don't expose it directly.

- [ ] **M — DOWN vs RELEASE flags.** DOWN (0x4000 slow, implicit in fast-path on encode, or: no RELEASE bit set) = key pressed. RELEASE (0x8000 slow, 0x01 fast) = key released. Both use the same scancode; server infers direction from flag. *ScanCodePdu KeyboardFlags.*

- [ ] **M — Windows VK→Set-1 mapping (VK_CODE).** Windows VirtualKey codes (VK_A=0x41, VK_F1=0x70, VK_LCTRL=0xA2, VK_RCTRL=0xA3, etc.) do NOT map 1:1 to scancodes. Use `MapVirtualKey(VK, MAPVK_VK_TO_VSC)` to get the single-byte VSC (virtual scan code). Extended keys (Right-Alt, Right-Ctrl, Right-Win, arrows, Home, etc.) return VSC with 0xE0 embedded; extract to find EXTENDED. Left vs Right distinguished by VK only, not VSC. *Windows API ref; FreeRDP `freerdp_keyboard_get_rdp_scancode_from_virtual_key_code`.* Gotcha: `MapVirtualKey` is locale-aware (responds to active keyboard layout), not just hardware.

- [ ] **M — Linux evdev + XKB mapping.** Linux input subsystem (evdev) uses KEY_* codes (linux/input-event-codes.h: KEY_A=30, KEY_LCTRL=29, KEY_RIGHTCTRL=97, etc.). NOT scancodes. Must translate via XKB (X KeyBoard extension) layout data or a hardcoded evdev→PC-Set-1 LUT. XKB keysym to scancode is library-dependent (libxkbcommon). Trap: evdev codes differ from older /dev/input/jsX joystick codes; modern Wayland/X11 uses evdev. EXTENDED determined by key name (XKB sym) or evdev code range (e.g., KEY_RIGHTCTRL = EXTENDED). *FreeRDP: keyboard.c evdev path; wayland-protocols.* [O] — Exact XKB integration is optional if using a simple hardcoded table (most impls do).

- [ ] **M — macOS KeyCode mapping.** macOS Key Events report `keyCode` (0–127, hardware-dependent). Not Set-1 scancodes. Must map via layout-aware tables (Carbon/Cocoa kCGKeyboardEventKeycode). Left/Right keys distinguished by `keyboardType` field. Availability of extended-key info depends on NSEvent flags. No direct 0xE0/0xE1 exposure; EXTENDED inferred from key identity. *Apple HID spec; FreeRDP osx.c; mswinsock.* [O] — macOS support is explicitly out of scope for Windows Server target, but noted.

- [ ] **M — Browser/Web KeyboardEvent.code mapping.** Web `KeyboardEvent.code` (MDN spec: "KeyA", "ControlLeft", "ControlRight", "ArrowUp", etc.) is a string, locale-independent, hardware-aware. Maps closely to Set-1 scancodes for most keys. Browser provides `event.location` (1=LEFT, 2=RIGHT) and `event.key` (the character). Must construct a code→Set-1 LUT, encoding EXTENDED per key name ("ControlRight" → EXTENDED, etc.). Trap: `event.key` is IME-aware (composition state); `event.code` is not. *MDN KeyboardEvent, W3C UI Events spec.* [O] — Browser target out of scope, but mention for clarity.

- [ ] **M — Shift-key interaction.** Shift does NOT modify scancode (Shift-A sends A+EXTENDED if Right-Shift, or A if Left-Shift, both with same Set-1 code 0x1E). The "shifted" character (e.g., 'A' vs 'a') is NOT sent as a scancode — it emerges on server via layout. Implication: **do NOT map OS keyboard events' character to scancode** — always use the raw key position. AltGr (Right-Alt) is a Shift modifier on many non-US layouts; sending it as EXTENDED prefix is correct; the server's layout defines what characters result. *Trap: Windows low-level keyboard hook sees the raw VK; high-level handlers sometimes pre-apply layout.*

#### Extended key prefixes & modifiers

- [ ] **M — AltGr / Level-3 Shift / Compose.** On AZERTY, QWERTZ, and other non-US layouts, AltGr (Right-Alt) generates level-3/compose characters (e.g., AltGr+2 = 'é' on AZERTY). RDP sends AltGr as Right-Alt + EXTENDED prefix (0xE0 0x38 in Set-1; VK_RMENU in Windows; KEY_RIGHTALT on Linux; code="AltRight" on Web). The server's keyboard layout PDU (GCC keyboard_layout = LCID, e.g., 0x080C for French) drives how the server interprets the Right-Alt + subsequent key. **Do NOT pre-compose** — send raw AltGr + key as separate scancodes; server layout handles it. *Trap: Older pre-composition logic (map AltGr+E to 'é' locally) breaks server's IME composition.*

- [ ] **M — Ctrl+Alt ≠ AltGr (except by accident on some layouts).** Right-Alt alone is AltGr (EXTENDED). Ctrl+Alt (both Left-Ctrl + Left-Alt, or Left-Ctrl + Right-Alt) is a chord, sent as two separate key-downs, no special flag. Some non-US layouts map both AltGr and Ctrl+Alt to level-3; they are NOT the same on the wire. *Trap: accidental AltGr vs Ctrl+Alt confusion.*

- [ ] **M — Lock-key synchronization (CapsLock, NumLock, ScrollLock, Kana).** Three sources of truth: client-side LED state, server-side LED state, logical toggle state (which one is "on"). On activation (Demand Active → Confirm Active), send **Sync PDU** with SyncToggleFlags matching current OS state (CAPS_LOCK/NUM_LOCK/SCROLL_LOCK/KANA_LOCK = 4 bits in u32). Server responds with its own Sync if it disagrees. Each key press thereafter is independent; sync only on session start + LED-change inbound. *ironrdp ref: sync.rs; input capability_sets.* Trap: toggling NumLock locally changes the keyboard layout's interpretation of the numeric keypad (5 becomes arrow-up if NumLock is off); **sync the logical state, not the mode**. Kana lock is Japanese IME–specific; optional unless JPN layout advertised.

#### Keyboard layout & LCID

- [ ] **M — Keyboard layout (LCID) advertisement.** Client Core Data `keyboard_layout` = 32-bit LCID (Locale ID), e.g., 0x0409 (US English), 0x040C (French), 0x0411 (Japanese), 0x0407 (German). Sent at connection time in GCC. *ironrdp ref: core_data/client.rs.* Server uses this to interpret scancodes + dead keys + IME composition. Mismatch (client sends 0x0409, server has 0x040C) = garbled input (e.g., Z/Y swapped on QWERTY vs QWERTZ). Trap: **the layout LCID is static; advertise the client-side active layout, not the server's default.**

- [ ] **M — Keyboard type & subtype.** `keyboard_type` = enum (PC_XT=0, PC_AT=1, PC_ENHANCED=2, JAPANESE=3, KOREAN=4); `keyboard_subtype` = u32 (OEM subtype, e.g., 0 for std, 1 for Fujitsu, 2 for Sony on Japanese). Server may enable layout-specific features (e.g., Kana lock for Japanese). *ironrdp ref: core_data KeyboardType enum.* Most modern: ENHANCED (type 2). Gotcha: Subtype 0 = unknown/generic.

- [ ] **M — IME filename (Input Method Editor).** Client Core Data `ime_file_name` = UTF-16 string (null-terminated, ≤62 chars per spec, 64-byte field). Examples: "MSJPN.IME" (MS Japanese), "IMEKR.IME" (MS Korean), empty string (no IME). Server uses to configure language-specific input handling (composition, candidates). Sent at connection time. *ironrdp ref: core_data/client.rs IME_FILE_NAME_SIZE=64.* Trap: exact filename matters for some servers; most ignore it if layout/type/subtype are correct. Empty string is safe if no IME. [O] — Set from OS if available; fallback to empty.

- [ ] **M — Function-key count.** `keyboard_functional_keys_count` = u32 (e.g., 12 for F1–F12, 24 for F1–F24). Sent to inform server of available fn-key range. Most servers expect 12. *ironrdp ref: core_data/client.rs.* Gotcha: unused in most modern servers; set to 12 and forget.

#### Dead keys & diacritics

- [ ] **M — Dead-key concept.** A dead key (e.g., ´ acute accent on US-INTL, ` backtick on AZERTY Shift+`) is a key that does NOT produce output on its own — it waits for the next keystroke to modify it (´+A = Á). Traditional RDP (scancode-only) cannot express "dead key state" — each key press is independent. Solution: use **Unicode events** (see below) for the accented result, or send scancode pairs (dead-key press, then next key, then dead-key release = if applicable).

- [ ] **M — Dead-key handling via scancodes (fallback).** If dead-key handling is in scope, send the raw scancode sequence for the dead key and the modified key, letting server-side layout apply the diacritic. Trap: **server-side layout must match client layout** (see LCID); if mismatch, result is garbage. Preferred: switch to Unicode input mode (see Unicode events below) and send the already-composed character (U+00C1 = Á).

- [ ] **M — Unicode input for composed/diacritic characters.** Fast-path and slow-path both support `UnicodePdu` / `UnicodeKeyboardEvent`: a UTF-16 code unit (u16) sent as input without a scancode. Use for:
  - IME composition results (final, committed text).
  - Dead-key results (client pre-composes, sends Unicode).
  - Any character not easily mapped to Set-1 (e.g., emoji, CJK via IME).
  
  *ironrdp ref: unicode.rs; fast_path.rs UnicodeKeyboardEvent.* Flags: only RELEASE meaningful (0x8000 slow, 0x01 fast); no EXTENDED. Surrogate pairs (≥U+10000): **send as TWO separate unicode events** (high surrogate, then low surrogate). Trap: server must support UNICODE input flag in Input capability set (see below).

- [ ] **M — Surrogate-pair handling (high Unicode).** UTF-16 uses surrogate pairs for U+10000–U+10FFFF (e.g., emoji 😀 U+1F600 = 0xD83D 0xDE00). RDP only sends u16 per event; no length field. **Encode emoji as two UnicodePdu events: first high surrogate (0xD83D), then low surrogate (0xDE00).** Server reassembles. *Trap: clients sometimes skip this and truncate to BMP; results in mojibake.* Gotcha: Pause/Break (0xE1 prefix) is also called "Print Screen" on some layouts; distinguish via layout.

#### IME composition & text input

- [ ] **M — IME composition vs committed text.** IME (Input Method Editor, e.g., MS-IME for Japanese, Pinyin for Chinese) produces text in two phases:
  1. **Composition (ongoing):** user types strokes, IME shows candidates, user picks. Server sees each keystroke as a scancode + composition state, displays underlined "composition window" locally.
  2. **Commit (final):** user selects or IME auto-completes, final text is sent as Unicode events or committed string.
  
  RDP spec: composition events are **scancodes**; committed results can be **scancodes (if single-key output) or Unicode events (if multi-char).**

- [ ] **M — IME composition mode (client-side).** Client OS provides IME state API (Windows `ImmGetOpenStatus()`, Linux iBus/Fcitx, macOS NSTextInputContext). During composition, scancodes are sent to server as-is; server's IME may echo back composition window hints (not typical in basic RDP). **Do NOT suppress scancode while in composition** — server needs the raw input to drive its IME.

- [ ] **M — When to use Unicode vs scancodes.** Guidelines:
  - **Scancodes:** single keystroke, ASCII range (a–z, 0–9, punctuation), shift/modifier chords, lock keys, function keys.
  - **Unicode:** IME-composed result (Hiragana, Kanji, Pinyin), dead-key result (Á, é), emoji, non-BMP. Requires `UNICODE` flag in Input capability set.
  - **Optimization:** if client has full layout info, can pre-compose some diacritics → Unicode (faster feedback, fewer round-trips).

- [ ] **M — Input capability flag: UNICODE.** Input capability set (MS-RDP §2.2.7.1.3) has flag `UNICODE` (0x0010). Must be advertised if client sends Unicode events. If NOT advertised, server may ignore or error on Unicode PDUs. *ironrdp ref: capability_sets/input.rs InputFlags::UNICODE.* **Must advertise if IME or dead-keys in use.**

- [ ] **M — Input capability flags: SCANCODES, FASTPATH_INPUT.** `SCANCODES` (0x0001) = supports scancode input (virtually all do). `FASTPATH_INPUT` (0x0008) = supports fast-path input events (compact, preferred). Both should be advertised. *ironrdp ref: InputFlags.* Slow-path fallback always available.

- [ ] **O — Hardware-IME vs software-IME.** Hardware IME (embedded in keyboard firmware, e.g., some Japanese phones) reports composed keys directly. Software IME (Windows TextInputProcessor, iBus, Fcitx) intercepts key events and generates candidates. RDP is software-IME–centric (expects scancode sequences). Hardware-IME devices may bypass OS input events entirely, requiring specialized hooks. [O] — Ignore for pure Windows Server target; mention for completeness.

- [ ] **O — Composition window / candidate list.** Server-side IME displays underlined text + popup candidate menu during composition. RDP has no explicit wire protocol for this; it's rendered server-side. Client has no way to query server's composition state (read-only). If client needs to show same candidates locally (for parity), must run own IME engine in parallel (heavy, rarely done). [O] — Mark optional; note the limitation.

#### Fast-path vs slow-path input

- [ ] **M — Fast-path keyboard events (preferred).** 1-byte header: [code(3b) | flags(5b)]; payload = scancode (1b) or unicode (2b). Codes: ScanCode (0), Mouse (1), MouseX (2), Sync (3), Unicode (4), MouseRel (5), QoeTimestamp (6). Flags for keyboard = RELEASE(0x01) | EXTENDED(0x02) | EXTENDED_1(0x04). *ironrdp ref: fast_path.rs KeyboardFlags, FastPathInputEvent.* Compact, preferred by servers. Num events can be ≥16 (spill to extra byte). *ironrdp ref: FastPathInputHeader.*

- [ ] **M — Slow-path keyboard events (fallback).** Full InputEventPdu: [nEvents(u16) | per event: eventTime(u32) | eventType(u16) | payload]. Event types: Sync(0), Unused(2), ScanCode(4), Unicode(5), Mouse(0x8001), MouseX(0x8002), MouseRel(0x8004). Larger, used if fast-path not negotiated. *ironrdp ref: input/mod.rs InputEventPdu, InputEvent.*

- [ ] **M — Synchronization flag in fast-path (Sync event).** Type 3, flags = SCROLL_LOCK(0x1) | NUM_LOCK(0x2) | CAPS_LOCK(0x4) | KANA_LOCK(0x8). Sent on session activation or LED change. *ironrdp ref: fast_path.rs SynchronizeFlags.* No separate slow-path equivalent (use slow-path Sync PDU type 0).

#### Implementation notes & traps

- [ ] **M — Order of operations: layout → mapping → flags.** (1) Determine active client OS keyboard layout (LCID). (2) Map OS key event (VK/evdev/KeyCode) → Set-1 scancode using per-platform LUT or API. (3) Add EXTENDED/EXTENDED_1 flags if 0xE0/0xE1 prefix applies. (4) Add DOWN/RELEASE flag. (5) Send fast-path (preferred) or slow-path.

- [ ] **M — No "shift modifies scancode" logic.** Shift is a key like any other (VK_LSHIFT=0xA0, VK_RSHIFT=0xA1). Pressing Shift-A sends two events: (LShift, DOWN) then (A, DOWN) then (A, RELEASE) then (LShift, RELEASE). Server's layout interprets the combination. **Do NOT map "Shift held + A" to "A with shift flag" — no such flag exists.**

- [ ] **M — Character composition responsibility split.** If client has full (Unicode + IME state) input, PREFER Unicode events for final text. If client only has scancodes (e.g., raw keyboard hook), send scancodes and rely on server's layout + IME. Trap: mixing (sending scancode A for 'a', then sending Unicode 'é' for Alt-GR+A) confuses composition.

- [ ] **O — Keyboard layout switching mid-session.** RDP has no wire protocol to change layout after connection. **Layout is frozen at GCC Client Core Data.** If user switches OS layout, client must reconnect or resend GCC with new LCID (expensive). [O] — Note as limitation; deferrable feature. FreeRDP has no support; ironrdp has no support.

- [ ] **M — Validation: advertise only flags you send.** If client sends Unicode events, MUST set UNICODE flag in Input capability. If client sends fast-path, MUST set FASTPATH_INPUT flag. If server doesn't advertise MOUSEX, DO NOT send MouseX events (may error). *Anti-bottleneck: validate capability vs wire traffic.*

- [ ] **O — High-frequency input (gaming).** Fast-path + mouse-relative mode (MOUSE_RELATIVE flag, MouseRel event type). Some gaming servers accept raw mouse deltas instead of absolute coords. *ironrdp ref: fast_path.rs MouseRelPdu, capability InputFlags::MOUSE_RELATIVE.* [O] — Mark optional; out of scope for basic desktop.

#### Keyboard mapping reference tables (examples, NOT exhaustive)

- [ ] **M — Standard US English Set-1 scancode subset (most common keys):** 
  - A–Z: 0x1E–0x2C (QWERTY order in memory)
  - 0–9: 0x02–0x0B
  - Backtick (`): 0x29
  - Minus (−): 0x0C; Equals (=): 0x0D
  - Backspace: 0x0E
  - Tab: 0x0F
  - Left-Bracket ([): 0x1A; Right-Bracket (]): 0x1B
  - Backslash (\): 0x2B
  - Semicolon (;): 0x27; Quote ('): 0x28
  - Comma (,): 0x33; Period (.): 0x34; Slash (/): 0x35
  - Space: 0x39
  - Enter: 0x1C
  - Escape: 0x01
  - F1–F12: 0x3B–0x46
  - Left-Ctrl: 0x1D; Right-Ctrl: 0x1D + EXTENDED
  - Left-Shift: 0x2A; Right-Shift: 0x36
  - Left-Alt: 0x38; Right-Alt: 0x38 + EXTENDED
  - Left-Win: 0x5B + EXTENDED; Right-Win: 0x5C + EXTENDED
  - Menu (context): 0x5D + EXTENDED
  - Numeric keypad: 0x47–0x53 (separate from number row; state depends on NumLock)
  - Home: 0x47 + EXTENDED; End: 0x4F + EXTENDED; Page-Up: 0x49 + EXTENDED; Page-Down: 0x51 + EXTENDED
  - Insert: 0x52 + EXTENDED; Delete: 0x53 + EXTENDED
  - Arrows: 0x48 (↑) / 0x4B (←) / 0x50 (↓) / 0x4D (→), all + EXTENDED
  - Print-Screen: 0xE0 0x2A 0xE0 0x37 (two-byte sequence) or EXTENDED_1
  - Pause/Break: 0xE1 0x1D 0x45 (three-byte, EXTENDED_1) or 0x45 + EXTENDED_1
  - NumLock: 0x45 (shares code with Pause, distinguished by prefix)
  - Scroll-Lock: 0x46
  
  *Reference: MS-RDP §2.2.8.1.1.1 Keyboard Event (TS_KEYBOARD_EVENT); PC AT keyboard reference; Linux evdev–keyboard; W3C KeyboardEvent.code.*

- [ ] **O — Non-US layout notes:**
  - **French AZERTY (0x040C):** A↔Q, Z↔W, etc.; AltGr+2 = é, etc.
  - **German QWERTZ (0x0407):** Z↔Y; Ä/Ö/Ü on separate keys.
  - **Japanese (0x0411):** Hiragana, Katakana, Kanji via IME; Kana lock; type=JAPANESE.
  - **Korean (0x0412):** Hangul via IME; type=KOREAN.
  - **Cyrillic (0x0419):** Cyrillic letters on QWERTY positions + Left-Ctrl+Shift to toggle.
  
  [O] — Mark as reference only; exact mapping is layout-dependent and owner's responsibility.

---

### Open questions

- How exhaustive should the Set-1 scancode table be? (Full 256-entry table vs examples + platform-specific mapping layer?)
- Should we pre-compose dead keys locally (send Unicode for result) or always send scancodes + rely on server? (IME mode preference?)
- Keyboard layout switching mid-session: defer entirely, or track a "desired layout" and force reconnect if user changes OS layout?
- Browser target (Web RDP): is it in scope now, or strictly out?

## 19. Caching subsystem

Good - they exist as raw buffers. Now I have enough context. Let me compile the comprehensive caching subsystem reference. Based on my research, I'll now write an exhaustive reference section.

###  Caching subsystem (bitmap / glyph / brush / offscreen)

- [ ] **M — Bitmap Cache capability negotiation (Rev1/Rev2 selection).** Server chooses which bitmap cache revision to use. Rev1 = 3 fixed caches; Rev2 = ≤5 variable-size cell caches with optional persistence flag per cell. *ironrdp ref: ironrdp-pdu/capability_sets/bitmap_cache/mod.rs (BitmapCache, BitmapCacheRev2, CacheEntry, CellInfo, CacheFlags: PERSISTENT_KEYS_EXPECTED_FLAG, ALLOW_CACHE_WAITING_LIST_FLAG).* **Niche trap: omitting either capset → no bitmap cache advertised at all; server streams uncompressed bitmaps. Implement both decoders to match whatever server sends.**

- [ ] **M — Bitmap Cache Rev1 storage model.** 3 cache entries; each defines `entries` count (u16) + `max_cell_size` (u16 bytes). Cache index 0/1/2, cell references are encoded in orders (MemBlt secondary order). Total capacity = sum of all entries × max_cell_size. *MS-RDPRFX §2.2.1.3.1.1.* **Critical trap: cache-id collision (mixing cache-entry slots 0/1/2 across frames) = silent corruption.** Maintain strict cache namespaces.

- [ ] **M — Bitmap Cache Rev2 storage model.** ≤5 variable-size cell caches (cells 0–4). Per-cell: `num_entries` (u31, high bit = `is_cache_persistent`), `max_cell_size` (u16). Cell references in MemBlt orders. *MS-RDPRFX §2.2.1.3.1.2.* Sparse, flexible. **Same trap: cache-cell-id collisions = corruption.**

- [ ] **O — Persistent Bitmap Cache (on-disk storage).** If `CacheFlags::PERSISTENT_KEYS_EXPECTED_FLAG` is set, client must accept **Bitmap Cache Persistent List PDU** (ShareDataPdu::BitmapCachePersistentList) post-licensing; contains a list of (cache-index, key, entry-size) tuples to *pre-populate* the cache from disk. *MS-RDPRFX §2.2.1.5.* Client sends back via Set Error Info if total keys exceed advertised capacity. **Design: optional but correctness-critical for cache coherence.** *ironrdp ref: ironrdp-pdu/headers.rs (BitmapCachePersistentList as raw Vec<u8> — not decoded).* Needs structured parser + persistent store (file-based or in-memory hash-map indexed by key). **Gotcha: key = SHA256(bitmap-bits) or server-supplied identifier; mismatch → cache miss.** Store/retrieve keyed by (cache-id, key) → bitmap bytes.

- [ ] **O — Bitmap Cache Revision 3 (secondary order).** Marked as `OrderSupportExFlags::CACHE_BITMAP_REV3_SUPPORT` in Order capset. Server uses 3-pass encoding: (1) MemBlt → existing cache hit, (2) CacheBitmap → store new entry, (3) legacy orders as fallback. *MS-RDPRFX §2.2.1.3.2.* **DEPRECATED per later specs, but some legacy servers use it.** *ironrdp ref: OrderSupportExFlags::CACHE_BITMAP_REV3_SUPPORT (0x0002).* Reference-only for now.

- [ ] **M — MemBlt secondary order (cache-ref bitmap rendering).** Part of Order capset; if `OrderSupportIndex::MemBlt` flag is set, server may send MemBlt orders to render cached bitmaps. Encodes: cache-id (0–4), cache-index (within that cache), destination rect, ROP3, background color. *MS-RD* Order §2.2.2.2.1.3.4.* Maps to stored bitmap in memory. **Gotcha: if cache-id/cache-index not previously populated (cache miss), rendering is undefined (server/client divergence).** Strict validation: reject out-of-bounds cache refs.

- [ ] **O — Glyph Cache (for ClearCodec, optional for legacy orders).** 10-entry glyph cache array + 1 fragment cache (CacheDefinition per cache). `glyph_support_level` = None/Partial/Full/Encode. *ironrdp ref: ironrdp-pdu/capability_sets/glyph_cache/mod.rs (GlyphCache, CacheDefinition, GlyphSupportLevel).* **ClearCodec uses: 4,000-entry dedicated glyph cache (not the capset cache).** *ironrdp ref: ironrdp-graphics/clearcodec/glyph_cache.rs (GLYPH_CACHE_SIZE=4000, GlyphCache with store(index, entry) / get(index) / reset()).* Per-entry: width, height, BGRA pixel data. Indexed by ClearCodec flag `FLAG_GLYPH_INDEX` (2-byte u16) + `FLAG_GLYPH_HIT` (reuse cached pixels). **Trap: glyph index overflow (≥4000) or eviction policy undefined → implement ring-buffer LRU or just reject over-range.**

- [ ] **O — Fragment Cache (within Glyph capset).** A sub-cache for small fragments used in text rendering. CacheDefinition tuple. *Not independently implemented in ironrdp.* Bandwidth optimization; can skip if no legacy text orders.

- [ ] **O — Brush Cache.** BrushCapability with `support_level` = Default/Color8x8/ColorFull. Encodes cached fill patterns. *ironrdp ref: ironrdp-pdu/capability_sets/brush/mod.rs.* **Minimal adoption; most servers use SurfaceCommands instead.** Reference-only unless legacy servers force it.

- [ ] **O — Offscreen Bitmap Cache.** OffscreenBitmapCacheCapability: `is_supported` (bool), `cache_size` (u16 KB), `cache_entries` (u16 count). Stores off-screen scratch surfaces for compositor caching. *ironrdp ref: ironrdp-pdu/capability_sets/offscreen_bitmap_cache/mod.rs.* **Niche: used only if SurfaceCommands not available.** Can skip in MVP.

- [ ] **O — Color Table Cache (palette cache, capset 0x0a).** ColorCache capset (raw buffer, unstructured in ironrdp). Legacy 256-entry indexed colour palette. Modern servers use RGBA direct. *spec-only; ironrdp treats as opaque.* Can skip; palette updates are already handled via fast-path Palette PDU.

- [ ] **M — EGFX Surface-to-Cache / Cache-to-Surface (GPU offscreen cache).** Part of EGFX (MS-RDPEGFX); separate from bitmap cache. **SurfaceToCachePdu** (surface_id, cache_key u64, cache_slot u16, source_rect) = store a surface region into EGFX cache. **CacheToSurfacePdu** (cache_slot, surface_id, destination_points[]) = render cached region to surface. **EvictCacheEntryPdu** (cache_slot) = evict a cached entry. *ironrdp ref: ironrdp-egfx/pdu/cmd.rs (SurfaceToCachePdu, CacheToSurfacePdu, EvictCacheEntryPdu).* **Cache-key is opaque u64 (typically hash of pixel content); server controls slot allocation.** Separate cache store per surface; coordinates with frame ACKs for pacing.

- [ ] **O — V-Bar Cache (ClearCodec bands layer only).** Ring-buffer caches for column pixel data (full V-bars: 32,768 entries; short V-bars: 16,384 entries). Encodes as LRU with cursor wrapping. *ironrdp ref: ironrdp-graphics/clearcodec/vbar_cache.rs (VBarCache, FullVBar, ShortVBar, store_vbar/store_short_vbar with cursor wrapping; reset() resets cursors).* **Completely internal to ClearCodec decoder; no wire capset.** Mandatory for ClearCodec; trap = cursor wraparound assumptions.

- [ ] **O — Cache reset semantics.** Bitmap cache: typically persistent across frames unless server sends reset PDU. ClearCodec glyph/V-bar caches: reset via `FLAG_CACHE_RESET` in bitmap stream. EGFX cache: reset via EvictCacheEntry or implicit on eviction. *MS-RDPEGFX §3.3.8.1, §2.2.4.1.* **Trap: out-of-order cache reset messages (if async) → data inconsistency. Serialize resets before bitmap updates.**

- [ ] **M — Cache bandwidth tradeoff (skip-cache mode).** If bitmap/glyph/brush caches not implemented: server streams uncompressed pixels directly (slow-path bitmaps or surface updates). Bandwidth cost = ~3–10× per cached redundant bitmap. **Decision: glyph/brush caches are < 1MB total; worth implementing even if optional. Bitmap cache Rev1/Rev2 = ~50–500MB per cache depending on cell counts; optional but high ROI if persistent.**

- [ ] **O — Bitmap Cache Error PDU (MS-RDPRFX).** Server sends if persistent key-list validation fails (e.g., total keys exceed capacity). *ironrdp ref: ShareDataPdu::BitmapCacheErrorPdu (raw Vec<u8>).* Parse as error code u32 LE; no action needed (informational).

- [ ] **O — Drawing Nine Grid Cache (capset 0x15, deprecated).** DrawNineGridCache capset + associated orders. **NOT supported in modern RDP.** Skip.

### Open questions on caching

1. **Persistent bitmap cache:** Is disk persistence (Persistent Key List PDU) in scope for v1, or defer? Cost: minimal if only in-memory hash-map; significant if file-backed.

2. **EGFX vs bitmap cache:** EGFX (surface-to-cache) supersedes bitmap cache on modern servers. Should we implement both (compatibility) or just EGFX + fallback to slow-path?

3. **Glyph cache capacity:** ClearCodec's 4,000-entry glyph cache is hardcoded. Should we make it configurable, or trust the codec's design?

4. **V-Bar cache ring-buffer eviction:** Is "wrap and overwrite" the correct LRU policy, or should we track age? Current ironrdp uses wrap only.

5. **Cache-id validation:** Should we hard-error on out-of-range cache-id in MemBlt orders, or silently skip? Spec is unclear; FreeRDP hard-errors.

---

## 20. Configuration, .rdp files & Azure AD

1. Connection parameters (the full .rdp file property surface)
2. Configuration model surface
3. Connection establishment variants
4. Azure AD/Entra integration
5. Cross-references to capability flags

Here's my comprehensive output:

---

### 7a. Connection parameters & .rdp file schema

The RDP client configuration surface covers all parameters a user specifies before connecting. These map to: (1) `.rdp` file properties (Windows text key=value format), (2) connector `Config` struct fields, (3) GCC Core/optional data blocks, and (4) Client Info PDU. **Mandatory configs gate protocol features; optional configs control secondary behavior.**

#### Connection target & routing
- [ ] **M — Hostname/IP + port (default 3389).** RdpFileProperty: `full address:s:host:port`. *ironrdp ref: Config none (handled by caller).* Routes to server directly or via gateway (see 7a.ii).
- [ ] **O — Gateway / RD Gateway (RDGW) / Azure Virtual Desktop Gateway.** Property: `gatewayhorusagemethod:i:0|1|2` (0=no, 1=direct/fallback, 2=force). *Spec-only (MS-TSGU). Protocol above RDP; requires separate TCP 443 tunnel + HTTP CONNECT.* **Not in ironrdp — we own gateway negotiation.** Needs host, auth, credential forwarding.
- [ ] **O — RD Proxy (BrokerURI / RemoteGuard).** Property: `rdgatewayusagemethod` variant. *Spec-only; thin HTTPS shim, authentication bridge.* **Not in ironrdp.**
- [ ] **O — Azure / Entra routing (RDSAAD).** See §7c. SecurityProtocol::RDSAAD (0x10) in X.224 nego. *spec-only for Azure-native sign-in.*
- [ ] **O — Routing token / load balancing.** Property: `loadbalanceinfo:s:...` (opaque server cookie, sent in X.224 RDP_NEG_REQ.routing_token). *ironrdp ref: NegoRequestData::RoutingToken.* Used by Azure/proxy for session affinity.
- [ ] **O — Connection cookie / auto-logon cookie.** Property: `autoreconnectcookie:s:...` (session resume after disconnect). *ironrdp ref: NegoRequestData::Cookie, TS_INFO_PACKET.reconnect_cookie.* Opaque token from server.

#### Display & DPI
- [ ] **M — Desktop resolution.** Properties: `desktopwidth:i:1024` / `desktopheight:i:768`. *ironrdp ref: Config.desktop_size, ClientCoreData.{desktop_width, desktop_height}.* Range: 320×240 to 8192×8192 (practical).
- [ ] **M — DPI / scale factor.** Properties: `desktopscalefactor:i:100` (100–500%, per mstsc), `devicescalefactor:i:100|0` (100=normal, 0=disabled on mobile). *ironrdp ref: Config.desktop_scale_factor, ClientCoreOptionalData.{desktop_scale_factor, device_scale_factor}.* Physical mm optional (desktop_physical_width/height).
- [ ] **O — Multi-monitor (up to 16).** Properties: `use multimon:i:1` / `monitors:i:2` (count), per-monitor `monitorids:s:...` (hex list), coords, primary. *ironrdp ref: gcc::MonitorData, MonitorExtendedData (DPI per-monitor).* **Not in current ironrdp-connector Config.** Requires Channel `Microsoft::Windows::RDS::DisplayControl` (EDISP).
- [ ] **O — Smart-sizing (resize server display to fit window).** Property: `smart sizing:i:1`. *spec-only; client-side only, no PDU, recompute resolution dynamically.*
- [ ] **O — Dynamic resize / layout changes.** Gates earlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU (0x40). Server streams Monitor Layout Change PDU → client adjusts framebuffer.

#### Colour depth & bitmap codec selection
- [ ] **M — Colour depth negotiation.** Properties: `session bpp:i:32` / `desktopwidth bpp:i:24` (legacy). *ironrdp ref: ClientCoreData.{color_depth, high_color_depth, supported_color_depths}, ClientColorDepth enum (Bpp8/15/16/24/32).* Fallback chain: preferred → high_color_depth → post_beta2_color_depth → color_depth.
- [ ] **M — 32-bit session support.** Gates earlyCapabilityFlags::WANT_32_BPP_SESSION (0x02) when color_depth=32. *ironrdp ref: Client must set if 32bpp is desired; overrides high_color_depth negotiation.* **Mandatory M for modern servers.**
- [ ] **M — Bitmap codec selection.** Properties: `supported bitmap codecs:s:RFX:ClearCodec:Progressive:NSCodec:H.264` (CSV, advertised order). *ironrdp ref: CapabilitySet BitmapCodecs (0x1d).* Which codecs the client can decode; server chooses (usually RFX-Progressive on modern servers).
- [ ] **O — Compression type (bulk).** Property: `compression:i:0|1|2|3` (0=none, 1=RDP4 MPPC 8KB, 2=RDP5 MPPC 64KB, 3=RDP6 NCRUSH, 4=RDP61 XCRUSH). *ironrdp ref: Config.compression_type, ClientInfo.compression_type.* Bulk fast-path / Share Data compression.

#### Credentials & authentication
- [ ] **M — Username/password.** Properties: `username:s:domain\user` / `password:s:...` (encrypted in .rdp file). *ironrdp ref: Config.{credentials: Credentials::UsernamePassword, domain}.* UNICODE in ClientInfo.
- [ ] **O — Smartcard / certificate auth.** Property: `smart card:i:1` → certificate + PIN source. *ironrdp ref: Config.credentials: Credentials::SmartCard + SmartCardIdentity.* Uses PK-INIT in Kerberos.
- [ ] **M — Domain.** Property: `domain:s:CORP` / optional (workgroup = empty). *ironrdp ref: Config.domain.* Part of Credentials or inferred from username.
- [ ] **O — Kerberos KDC / SPN hint.** Property: `kdc_proxy:s:...` (infer from domain SRV or explicit). *Spec-only; sspi crate handles KDC discovery.* Mandatory in AD, skippable in workgroup.
- [ ] **O — Restricted Admin / Remote Credential Guard.** Property: `restrictedadmin:i:1`. *ironrdp ref: sspi CredSspMode::CredentialLess, Config request_data flag RESTRICTED_ADMIN_MODE_REQUIRED.* Credential-less sign-in; token from card/Windows auth.
- [ ] **O — Authentication level (cert validation strictness).** Property: `authentication level:i:0|1|2` (0=warn, 1=connect if available, 2=require & validate, 3=require + fail on mismatch). *Spec-only; client-side only.* Our cert validation policy (pinning / chain / TOFU).
- [ ] **O — Gateway credentials (separate from target).** Property: `gatewaycredentialsource:i:0|1|2` (0=prompt, 1=use session creds, 2=saved). *Spec-only; RDGW-specific.* **Not in ironrdp.**

#### Input & keyboard
- [ ] **M — Keyboard layout (LCID).** Property: `keyboard layout:i:0x409` (e.g., 0x409=US). *ironrdp ref: Config.keyboard_layout, ClientCoreData.keyboard_layout.* Sent to server; affects KeyState / IME.
- [ ] **M — Keyboard type / subtype / functional keys.** Properties: `keyboard type:i:4` / `keyboard subtype:i:0` / `keyboard functional keys:i:12`. *ironrdp ref: Config.{keyboard_type: KeyboardType, keyboard_subtype, keyboard_functional_keys_count}.* IME file name optional.
- [ ] **M — Input mode fast-path.** Gates earlyCapabilityFlags::RELATIVE_MOUSE_INPUT (0x10) if supported. *ironrdp ref: CapabilitySet Input flags (SCANCODES, MOUSEX, FASTPATH_INPUT, UNICODE, MOUSE_RELATIVE, TS_MOUSE_HWHEEL).* Determines how input PDUs encode.

#### Remote App & alternate shell
- [ ] **O — RemoteApp / alternate shell.** Property: `alternate shell:s:C:\Program Files\App\app.exe` / `shell working directory:s:C:\Users\user`. *ironrdp ref: Config.{alternate_shell, work_dir}.* Sent in ClientInfo. **Does NOT enable full RAIL (seamless windows); RAIL requires DVC channel + Server permission.**
- [ ] **O — RemoteApp (RAIL full).** Property: `use multimon:i:0` + `alternate shell` + server `MS-RDPERP` support. *Spec-only; huge feature (window mgmt, focus, geometry).* **Not in this scope (marked O in Layer 6).**

#### Redirection & virtual channels
- [ ] **O — Drive/file redirection (RDPDR).** Property: `redirectdrives:i:1` / `drivestoredirect:s:*|C:|D:` (which drives). *ironrdp ref: SVC `RDPDR` channel; pdu static in GCC Client Network Data.* **Not in current ironrdp-session; we own RDPDR stack.**
- [ ] **O — Printer redirection.** Property: `redirectprinters:i:1` / `redirect printer default:i:1`. *ironrdp ref: SVC RDPDR printer sub-channel (MS-RDPEPC).* **Not in current ironrdp.**
- [ ] **O — Smartcard device passthrough.** Property: `redirectsmartcard:i:1`. *ironrdp ref: SVC RDPDR smartcard sub-channel (MS-RDPESC).* **Not in current ironrdp.**
- [ ] **O — Audio output playback (speaker).** Property: `audiocapturemode:i:0|1` (0=off, 1=on). *ironrdp ref: SVC `RDPSND` channel; PerformanceFlags.DISABLE_AUDIO_PLAYBACK.* Negotiates codecs (PCM/OPUS/AAC).
- [ ] **O — Audio input capture (microphone).** Property: `audiomode:i:0|1|2` (0=none, 1=remote speaker only, 2=speaker+mic). *ironrdp ref: SVC `RDPEAI`; spec-only in ironrdp.* **Not in current ironrdp.**
- [ ] **O — Clipboard redirection.** Property: `redirectclipboard:i:1`. *ironrdp ref: SVC `CLIPRDR`; pdu static in GCC.* **Not in current ironrdp.**
- [ ] **O — COM/serial port redirection.** Property: `redirectcomports:i:1` / `redirectlptports:i:1`. *ironrdp ref: SVC RDPDR serial/parallel sub-channels (MS-RDPESP).* **Rarely used; not in ironrdp.**
- [ ] **O — USB device redirection.** Property: `usbdeviceredirection:i:1`. *Spec-only (MS-RDPEUSB-like); rare.*
- [ ] **O — Dynamic virtual channels (DVC) support.** Gates CapabilitySet VirtualChannel::DRDYNVC_SUPPORTED. *ironrdp ref: ironrdp-dvc, all dynamic channels (EGFX, EDISP, etc.).* **M for graphics; we own drvdynvc stack.**

#### Performance & optimization
- [ ] **M — Performance flags (wallpaper/font-smoothing/etc.).** Property: `disable wallpaper:i:1` / `disable full window drag:i:1` / `disable menu anims:i:1` / `disable themes:i:1` / `disable cursor shadow:i:1`. *ironrdp ref: Config.performance_flags (PerformanceFlags bitset).* ClientInfo PDU carries these; server respects hints.
- [ ] **M — Connection speed / network type.** Property: `connection type:i:1|2|3|4|5` (modem/broadband-low/satellite/broadband-high/wan). *ironrdp ref: ClientCoreOptionalData.connection_type, ClientEarlyCapabilityFlags::VALID_CONNECTION_TYPE (0x20).* Hint to server for codec/refresh tuning. **Not currently used by ironrdp-connector; we should make it caller-controllable.**
- [ ] **O — Bandwidth auto-detect.** Gates earlyCapabilityFlags::SUPPORT_NET_CHAR_AUTODETECT (0x80). *ironrdp ref: autodetect.rs (PDU) + connector skips it.* Server probes RTT/bandwidth → client responds; allows server to adapt compression/refresh. **Optional for v1; gated by capability flag.**
- [ ] **O — Heartbeat / keep-alive.** Gates earlyCapabilityFlags::SUPPORT_HEART_BEAT_PDU (0x400). *ironrdp ref: connector generic support; property-side: none (always on if supported).* Server sends heartbeat frames to prevent idle timeout.
- [ ] **O — Error info PDU (detailed disconnect reasons).** Gates earlyCapabilityFlags::SUPPORT_ERR_INFO_PDU (0x01). *ironrdp ref: ServerErrorInfo (80+ typed codes, not just MCS Disconnect).* Must advertise to unlock server's detailed error messages.

#### Advanced / niche settings
- [ ] **O — Client build / version / platform.** Properties: `clientname:s:MYCOMPUTER` / implicit client_build (version). *ironrdp ref: Config.{client_name (truncated to 15 chars), client_build, platform: MajorPlatformType}.* Informational (server doesn't block); helps with compatibility detection.
- [ ] **O — Hardware ID.** Property: none standard (proprietary per vendor). *ironrdp ref: Config.hardware_id: Option<[u32; 4]>.* Per-device licensing / analytics.
- [ ] **O — Timezone redirection.** Property: `autoreconnection:i:1` (generic toggle) / implicit in ClientInfo.timezone_info. *ironrdp ref: Config.timezone_info (TimezoneInfo struct with bias, name, DST rules).* Syncs server time to client; server respects or ignores.
- [ ] **O — Timezone auto-update (dynamic).** Gates earlyCapabilityFlags::SUPPORT_DYNAMIC_TIME_ZONE (0x200). *Server may stream timezone-change PDUs without reconnect.* **Not in current ironrdp.**
- [ ] **O — Dig product ID.** Property: `dig product id:s:...` (device fingerprint). *ironrdp ref: ClientCoreOptionalData.dig_product_id.* Rarely set; product-specific.
- [ ] **O — AutoReconnect.** Property: `autoreconnection:i:1` / implicit `autoreconnectcookie:s:...`. *ironrdp ref: TS_INFO_PACKET::reconnect_cookie, ServerSessionInfo::logon_extended.* Resume session after brief disconnect; server must provide cookie.
- [ ] **O — Alternate logon credentials / auto-logon.** Property: `autologon:i:1`. *ironrdp ref: Config.autologon, ClientInfo::ClientInfoFlags::AUTOLOGON.* Server auto-signs in if permitted; set = unsafe on untrusted networks.

### 7b. Configuration model & builder pattern

A real client needs a high-level config API that abstracts away the wire-level complexity. **Mandatory design rule: every capability/GCC/ClientInfo field must be externally settable, defaulting to sensible + safe choices.**

- [ ] **M — Configuration builder / struct.** Encapsulate all §7a properties. *ironrdp ref: ironrdp-connector::Config (partial; missing gateway, routing, RAIL, dvc-selective-enable).* Builder pattern recommended for large surface. Validation on build (e.g., resolution in range, color depth valid).
- [ ] **M — Credential source abstraction.** Enum: UsernamePassword { username, password, domain } | SmartCard { pin, card_identifier } | Windows { realm, user } (Kerberos native) | Token { access_token } (Azure/Entra). *ironrdp ref: Credentials enum (2 variants); missing token variant.* Yields Credentials for CredSSP on demand.
- [ ] **M — Gateway configuration sub-struct.** If gateway_type != None: host, port (default 443), credentials (may differ from target), protocol (RDGW|RDProxy|Azure). *Spec-only; we own the gateway negotiation FSM.* Yields separate TLS tunnel + HTTP CONNECT.
- [ ] **M — Capability flag controller.** Expose full `ClientEarlyCapabilityFlags` bitfield as settable, default to "advertise all we can handle." *ironrdp ref: ironrdp-pdu ClientEarlyCapabilityFlags, but ironrdp-connector hardcodes the list.* **This is the §0 trap linchpin — make it fully user-controllable.**
- [ ] **M — Capability set builder.** For each capset (Bitmap, Order, Input, BitmapCodecs, VirtualChannel, SurfaceCommands, …), expose flags/options as builder fields. Default to "maximum capability." *ironrdp ref: capability_sets/* (encode only; no builder in ironrdp).* Must wire through to GCC block generation.
- [ ] **O — Per-channel toggle (CLIPRDR on/off, RDPSND on/off, RDPDR on/off, EGFX on/off, EDISP on/off).** *ironrdp ref: static channels built into GCC Network Data; DVC channels built on demand.* Allow caller to exclude channels at config time.
- [ ] **O — Preset profiles.** e.g., "secure-strict" (NLA+TLS+minimal channels), "compatibility" (no EGFX, slow-path only), "performance" (all codecs, EGFX, fast-path). *Spec-only.* Simplify common use-cases.

### 7c. Connection establishment variants

RDP routing goes beyond "host:port" — multiple topologies exist. **Each variant changes credential flow, certificate validation, and/or wire framing.**

#### Direct connection
- [ ] **M — Direct TCP/TLS to server.** Simplest: client → server (3389). X.224 → TLS → CredSSP (if NLA) → MCS. *ironrdp ref: ClientConnector start-to-finish; handles directly.* Config: hostname + port.

#### RD Gateway (RDGW / TS Gateway)
- [ ] **O — RD Gateway (MS-TSGU protocol, MS-TSGF, MS-TSWA).** Client → HTTPS 443 to gateway (RDG) → gateway → RDP server (port 3389, usually internal). *Spec-only; not in ironrdp.* Three protocols: (1) HTTPS negotiation (X-RDG-Connection-Cookie, X-RDG-Auth-Token), (2) UDP tunnel (optional multitransport), (3) HTTP CONNECT proxy for RDP. **We own the full gateway stack.** Config: gateway_host, gateway_port (443), gateway_username/password (often same as target), gateway_domain, server_address (routed address to gateway).

#### RD Proxy / Azure Virtual Desktop Gateway
- [ ] **O — RD Proxy / BrokerURI (Azure Virtual Desktop).** Similar to RDGW but Azure-hosted. Client → Azure RD Proxy (HTTPS) → reverse tunnel to ARM resource group (AVD session host). *Spec-only.* Credential handling differs (Entra/AAD token). **We own RD Proxy stack.** Config: gateway_type=RDProxy, broker_uri, AAD token.

#### Azure/Entra Direct (RDSAAD)
- [ ] **O — Azure AD / Entra ID direct auth (RDSAAD / MS-RDPASSD).** Windows Server on Azure with Entra sign-in. Client → server, SecurityProtocol::RDSAAD (0x10). *spec-only; no CredSSP; uses Kerberos over web-account-manager.* Different credential flow (Entra token, not traditional NTLM). **Niche; we own if implemented.** Config: security_protocol=RDSAAD, aad_token_source (browser/native AAD SDK).

#### Proxy / load-balancer with routing token
- [ ] **O — Load-balanced / proxy routing.** Client → proxy (port 3389) with routing token in X.224. X.224 RDP_NEG_REQ.routing_token or .cookie. Proxy strips token, forwards to real server. *ironrdp ref: NegoRequestData::RoutingToken / ::Cookie.* Config: hostname (proxy), request_data (routing token).

#### Session resume / auto-reconnect
- [ ] **O — Auto-reconnect with cookie.** Server → client: auto-reconnect cookie (28 bytes, opaque) in logon_extended. Client disconnects/reconnects → sends same cookie in ClientInfo.reconnect_cookie. Server resumes session (same channel IDs, state). *ironrdp ref: TS_INFO_PACKET::reconnect_cookie, logon_extended.rs.* Must track cookie from first logon. Config: reconnect_cookie (from prior session).

### 7d. Azure AD / Entra authentication (RDSAAD / AAD / web-account)

Modern enterprise RDP, especially on Azure, uses Entra ID (formerly Azure AD) instead of NTLM/Kerberos. **This is a distinct auth path, not CredSSP+NTLM.**

- [ ] **O — RDSAAD security protocol (MS-RDPASSD / MS-RDGWAD).** SecurityProtocol::RDSAAD (0x10 in X.224). *Spec-only; not in ironrdp.* No classical CredSSP. Instead: (1) client sends username in X.224, (2) server replies with Entra challenge URL + device code, (3) client opens browser (user signs in at Azure), (4) client polls Entra for token, (5) client sends token to server.
- [ ] **O — Web Account Manager (WAM) integration.** For Windows clients, use OS WAM API instead of browser. *Windows-specific; winscard style.* Unified sign-on (SSO) if user already signed in.
- [ ] **O — Access token (JWT / armtoken).** Property: `aad-token:s:...` (pre-acquired). *Spec-only; caller supplies.* Sent in place of password after Entra challenge.
- [ ] **O — Device code flow.** Entra server → client: device code + verification URL. Client polls token endpoint until user authenticates. *OAuth 2.0 Device Authorization Grant.* **We own device-code polling loop.**
- [ ] **O — Conditional Access / Entra policies.** MFA, device compliance, location-based rules. Handled by Entra backend; client sees success/failure. *Policy enforcement; spec-only.* Config: MFA method (if applicable).
- [ ] **O — Multi-factor authentication (MFA) hints.** Property: `mfa_method:s:sms|totp|push` (preferred method for Entra). *Spec-only; Entra-specific.* Caller hints to Entra which flow to use.
- [ ] **O — Hybrid / token refresh.** Entra tokens expire (~1h). If session lasts longer, must refresh token. *OAuth 2.0 Refresh Token.* **We own token refresh loop.**
- [ ] **O — Account picker (multiple AAD identities).** If user has multiple Entra accounts, display picker. *Windows WAM API.* Simplify UX in multi-account scenarios.

### 7e. Configuration-to-protocol couplings (feature gates)

**Critical: many protocol features are ONLY unlocked if config advertises them.** This table indexes back to §1 (capability table) + points to the config field that gates each feature.

| Config field | Advertises | Effect (server unlocks) | GCC block / PDU |
|---|---|---|---|
| `color_depth == 32` + `want_32_bpp_session` | ClientEarlyCapabilityFlags::WANT_32_BPP_SESSION (0x02) | 32-bit colour session (server respects high_color_depth) | ClientCoreData::early_capability_flags |
| `enable_egfx == true` | ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL (0x0100) | **EGFX channel (graphics pipeline)** — server opens DVC `Microsoft::Windows::RDS::Graphics` | ClientCoreData::early_capability_flags |
| `enable_display_control == true` | DVC capability; SurfaceCommands capset + EDISP channel creation | Server-pushed monitor layout changes (resize without reconnect) | Static channels (EDISP) or DVC create |
| `enable_clipboard == true` | Static channel `CLIPRDR` in GCC Network Data | Clipboard read/write | GCC Client Network Data |
| `enable_audio_output == true` | Static channel `RDPSND` in GCC Network Data | Speaker audio redirection | GCC Client Network Data |
| `enable_audio_input == true` | Static channel `RDPEAI` in GCC Network Data | Microphone capture | GCC Client Network Data |
| `enable_drive_redirect == true` | Static channel `RDPDR` in GCC Network Data | File/drive redirection | GCC Client Network Data |
| `enable_printer == true` | Static channel `RDPDR` (subtype printer) | Printer redirection | GCC Client Network Data |
| `enable_smartcard == true` | Static channel `RDPDR` (subtype smartcard) + Kerberos CA | Smartcard device passthrough | GCC Client Network Data |
| `connection_type != NotUsed` | ClientEarlyCapabilityFlags::VALID_CONNECTION_TYPE (0x20) | Server hints may tune compression/codec | ClientCoreData::early_capability_flags |
| `enable_error_info_pdu == true` | ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU (0x01) | Typed disconnect reasons (Set Error Info PDU) instead of generic MCS reason | ClientCoreData::early_capability_flags |
| `enable_monitor_layout_pdu == true` | ClientEarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU (0x40) | Runtime monitor layout changes (resize) | ClientCoreData::early_capability_flags |
| `enable_net_char_autodetect == true` | ClientEarlyCapabilityFlags::SUPPORT_NET_CHAR_AUTODETECT (0x80) | Network auto-detect (RTT/bandwidth probing) | ClientCoreData::early_capability_flags |
| `enable_relative_mouse == true` | ClientEarlyCapabilityFlags::RELATIVE_MOUSE_INPUT (0x10) + Input capset MOUSE_RELATIVE | Relative (delta) mouse mode | ClientCoreData::early_capability_flags + CapabilitySet Input |
| `enable_heartbeat == true` | ClientEarlyCapabilityFlags::SUPPORT_HEART_BEAT_PDU (0x400) | Server heartbeat / keep-alive (prevents idle timeout) | ClientCoreData::early_capability_flags |
| `enable_dynamic_timezone == true` | ClientEarlyCapabilityFlags::SUPPORT_DYNAMIC_TIME_ZONE (0x200) | Live timezone change PDU without reconnect | ClientCoreData::early_capability_flags |
| `enable_skip_channeljoin == true` | ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN (0x800) | Channel join batching (RDP 8.1+ optimization) | ClientCoreData::early_capability_flags |
| BitmapCodecs capset (RFX/Progressive/…) | BitmapCodecs capset advertises available codecs | Server chooses codec; client decodes only advertised ones | CapabilitySet BitmapCodecs (0x1d) |
| SurfaceCommands capset | SurfaceCommands capset (0x1c) enabled | GPU/surface-bits rendering path (vs legacy orders/bitmaps) | CapabilitySet SurfaceCommands |
| Order capset per-order flags | Order capset per-order flags | Each RDP drawing-order type the server may use | CapabilitySet Order (0x03) |
| VirtualChannel capset DRDYNVC_SUPPORTED | VirtualChannel capset::DRDYNVC_SUPPORTED | Any dynamic virtual channel at all (EGFX, EDISP, etc.) | CapabilitySet VirtualChannel (0x14) |
| Input capset flags | Input capset (SCANCODES, MOUSEX, FASTPATH_INPUT, UNICODE, MOUSE_RELATIVE, TS_MOUSE_HWHEEL) | Which input modes server will send; client must handle | CapabilitySet Input (0x0d) |

### 7f. Property-set .rdp file parsing & serialization

Windows mstsc.exe uses a simple key=value text format for .rdp files. **Not critical for v1 (can config programmatically), but crucial for UX (copy .rdp, load settings).**

- [ ] **O — .rdp file parser.** Text file, one property per line. Format: `key:type:value` where type ∈ {i (int), s (string), b (binary, base64)}. UTF-8 or UTF-16 LE. *Spec: MS-TSRPC Appendix (informal; see FreeRDP freerdp_settings.c for reference).* **Not in ironrdp — we own parser.** Validate property names, ranges.
- [ ] **O — .rdp file writer / serializer.** Reverse: Config → .rdp lines. Encrypt passwords (DPAPI or simple obfuscation for portability). *Spec-only.* **Not in ironrdp.** Output for save/share.
- [ ] **O — Known property catalog.** Curate all valid mstsc properties (100+) for reference. Subset which are mandatory (hostname, port, username) vs optional (redirectdrives, etc.). *FreeRDP / mstsc source.* Helps validation + discoverability.
- [ ] **O — Property inheritance / defaults.** Built-in default .rdp template (safe minimums). User .rdp overlays + command-line overrides.

---

### Open questions (§7-specific)

1. **Gateway in v1?** RDGW is heavy (HTTPS tunneling, HTTP CONNECT, separate state machine). Defer to v2, or scope a minimal proof-of-concept (direct proxy only)?
2. **Azure/RDSAAD auth?** Only if target is on Azure with Entra enabled. May be out of scope for single-server PoC. Defer unless customer demands.
3. **Multi-channel toggle granularity.** Do we let users pick individual channels (CLIPRDR yes, RDPSND no, RDPDR only C: drive), or simpler presets (all on / all off)? Preset profiles first.
4. **Bitmap codec configuration.** Should we let users rank preferred codecs (e.g., "Progressive > RFX > Uncompressed"), or hard-code priority? Hard-code first (RFC precedence); config later if needed.
5. **Property-set .rdp file support.** Ship in v1 (for UX), or assume programmatic config + defer parser to v2? Parser is ~500 lines; include in MVP-1 for compatibility.
6. **AutoReconnect cookie management.** Store on disk (encrypted)? In-memory only? Spec-only for v1; we can add persistence in v2 if session resumption is critical.
7. **Credential storage.** DPAPI-encrypted (Windows) vs plaintext cache (portable)? For now, caller supplies creds on each connect; defer caching to v2.

---

This section is now ready to merge into plan.md. It covers the full configuration surface, all connection variants, Azure AD integration, and ties back to capability flags as the load-bearing linchpin.

## 21. Verification & reference-oracle strategy

This section defines the **risk-mitigation workstream** that decouples codec/protocol bugs from implementation bugs during development. The project's proven lesson (VERDICT.md) is that **interop debugging, not coding, is the bottleneck** — a single missed flag (SUPPORT_DYN_VC_GFX_PROTOCOL) silenced an entire subsystem. The strategy below bakes oracle checks into the development loop so ambiguous failures are immediately diagnosed as "our code" vs "spec misunderstanding" vs "server variant."

### V.1. Reference PDU capture & byte-level comparison (mstsc/FreeRDP as ground truth)

- [ ] **M — Wireshark RDP dissector + TLS keylog export.** Set up a parallel session with `mstsc.exe` (Windows) or FreeRDP (`xfreerdp` on Linux) against the same test VM, capture traffic with Wireshark on the RDP dissector, and decrypt via SSLKEYLOGFILE (rustls via RUSTLS_LOG_KEYS=1). Export captured PDUs as hex (frame → right-click → Follow RDP Stream → export raw). *Spec: no code reference.* **Niche trap:** mstsc doesn't always export key logs; FreeRDP with `SSLKEYLOGFILE=keys.txt xfreerdp ...` is more reliable. **Output:** reference .pcapng per Windows version + server build, indexed by connection-stage (X.224/TLS/CredSSP/MCS/capability-exchange/finalization).
- [ ] **M — Encode test vectors: golden PDU hex dumps.** For each critical PDU encoder (X.224 Connect-Request, GCC Client Core Data, Capability Sets, Client Info, Input fast-path, Surface Commands, etc.), capture the *correct* encoded form from mstsc/.pcapng, store as `.hex` files in `test_vectors/` with a decoder that byte-diffs our output against it. Example: `X224ConnectRequest.hex` = the first PDU we send; write `test_vectors/x224_connect_request_golden.rs` as a proptest that encodes + compares. *Spec: MS-RDP, MS-RDPBCGR.* **Gotcha:** mstsc sometimes pads or reorders optional fields — always derive golden vectors from actual wire capture, not the spec.
- [ ] **M — Decoder test vectors: compressed bitmap/codec byte sequences.** ironrdp ships test assets (rdp6/test_assets/*.bin = RLE-compressed bitmaps with .bmp reference), zgfx/test_assets/, clearcodec vectors. Ingest these into our `src/codecs/test_fixtures/` and wire as integration tests: `#[test] fn decode_rdp6_32x64_aycocg_rle_matches_reference_bmp()`. *ironrdp ref: ironrdp-graphics/src/rdp6/test.rs, zgfx/test.rs.* Expand with RemoteFX Progressive vectors (see V.2).

### V.2. Codec golden test vectors (RFX full/Progressive, ClearCodec, zgfx)

- [ ] **M — RemoteFX full (RFX non-progressive) vectors.** Capture a real-VM RemoteFX-full tile stream (server sends SetSurfaceBits with codec_id=3), hex-dump the encoded tile PDU payload, decode our RemoteFX codec, render to BGRA, and diff the output pixels against a reference PNG/BMP. ironrdp-graphics ships `RemoteFxDecoder::decode_tile` — validate it on real server tiles. *ironrdp ref: graphics/rfx.rs test vectors (none shipped; extract from server .pcapng).* **Your work:** capture 5–10 real tiles from the test VM, store as `test_vectors/rfx_tiles/*.hex` + expected output (BGRA or greyscale histogram for lossy tolerance).
- [ ] **M(β) — RemoteFX Progressive (RFX-Progressive) vectors.** Server sends WireToSurface2 PDU with progressive-tile updates (TileSimple, TileFirst, TileUpgrade). ironrdp ships only the coefficient-decoding primitives (`decode_first_pass`, `decode_upgrade_pass`), not the tile→RGBA pipeline. Capture a real server's Progressive tile sequence from the VM, store the PDU bytes, and **wire the integration test to decode the full sequence** (first pass → tile store → multi-pass accumulation → DWT+color conversion → BGRA), comparing the final output. *ironrdp ref: graphics/progressive.rs primitives.* **Critical gap:** this is where Progressive integration lives — the test will prove the pipeline works. **Gotcha:** Progressive tiles reference previous tiles' coefficients — the sequence matters; capture as a transaction, not isolated tiles.
- [ ] **M — ClearCodec golden vectors.** ClearCodec is mandatory for EGFX (if EGFX is negotiated, it must be able to decode ClearCodec). ironrdp-graphics/src/clearcodec.rs ships the decode-complete impl. Extract 10–20 real ClearCodec-encoded frames from the test VM .pcapng (look for DVC packets with type=data from the Graphics Pipeline channel, parse as WireToSurface1/2), decode, and diff output BGRA against reference. *ironrdp ref: clearcodec.rs.*
- [ ] **O — zgfx bulk-compression vectors.** zgfx compresses payload on the wire (used by EGFX over drdynvc + some old fast-path codecs). Capture zgfx-compressed payloads, decompress, and compare decompressed size + content. *ironrdp ref: graphics/zgfx.rs.* Lower priority (it's just LZ77) but include for completeness.
- [ ] **O — NSCodec vectors.** NSCodec is a ClearCodec subcodec and rarely seen on the wire. Skip unless the test VM actually sends it.

### V.3. Real-VM integration harness (the #[ignore] test pattern)

The existing `tests/integration_real_vm.rs` pattern is the **proven methodology** — bake it in from day one:

- [ ] **M — Tracing-layer milestone watchers.** Use `tracing` subscriber layers (see EgfxCapsLayer / DisplayControlCapsLayer in integration_real_vm.rs) to assert that named PDU/event milestones fired without modifying the hot path. Define a per-workstream set of tracing targets: `rdp_x224_neg_req`, `rdp_x224_neg_rsp`, `rdp_tls_handshake`, `rdp_credssp_complete`, `rdp_mcs_erect_domain`, `rdp_channel_join_all`, `rdp_demand_active`, `rdp_finalization_complete`, `rdp_session_active`, `rdp_egfx_caps_confirm`, `rdp_displaycontrol_caps`, `rdp_surface_first_frame`, etc. Test runners emit info-level spans for these and layers poll them; assert each stage fires in order + within a timeout. *Spec: nothing; pattern from existing PoC.* **Gotcha:** if a stage never fires, the test hangs; always wrap in `tokio::time::timeout` with a clear panic message showing the last stage reached (so logs identify which stage is broken).
- [ ] **M — Per-stage capture & golden-diff on failure.** If a stage milestone does not fire within its timeout, automatically dump the last 100 PDUs exchanged (via debug logging to a `*.pcapng`-like capture buffer) so failures can be reproduced offline. *Spec: no reference.* **Example:** on `rdp_finalization_complete` timeout, append a diagnostic log entry listing the sequence of ShareData PDU types observed so far.
- [ ] **M — Desktop-size negotiation in-session.** Current test asserts `session-active` + at least one `FrameUpdate` + Display Control resize. Expand this to: (a) connect at default desktop size, (b) request via Display Control to a new size, (c) assert DeactivateAll fires, (d) assert reactivation runs to completion, (e) assert new desktop size is reported in the size sink. *This is already in the PoC;* formalize it as M.
- [ ] **M — Input path smoke test (keyboard + mouse + click).** Send a key-press, pointer-move, and click; assert the session survives (no disconnect). *Already in the PoC (lines 243–270).* Formalize as M; extend to test each input type (KeyboardScancode, MouseX, relative-mouse if `MOUSE_RELATIVE` is negotiated).
- [ ] **M — Per-Windows-version test matrix.** Run the integration test harness against **workgroup**: Windows Server 2016/2019/2022 + Win10/11, and **AD-joined** (if KDC available): 2019/2022 with Kerberos. Document each run's (Server, Negotiated Security, Desktop Size, Codec, any errors) in a table (see V.5 below). *Spec: none.* **Your work:** coordinate with test-VM ops to spin up the matrix; CI/CD can be later.
- [ ] **O — Graceful disconnect validation.** Send Graceful Shutdown Request; assert the server replies with Shutdown Denied (typical) or Shutdown Complete; then MCS ultimatum; assert session ends cleanly with no decode errors. *ironrdp ref: session/active_stage.rs (graceful_shutdown_sequence).* Low risk; can defer.

### V.4. Codec fuzzing (untrusted server input)

- [ ] **M — Fuzz bitmap decoders (RLE/RDP6/raw).** Use `libfuzzer` or `quickcheck` to generate random / malformed RLE/RDP6 payloads; feed to the bitmap decoder and assert it never panics or reads out-of-bounds. Cargo fuzzing harness in `fuzz/` directory; runs as `cargo +nightly fuzz run fuzz_rdp6_decode`. *ironrdp ref: ironrdp-graphics Cargo.toml (no fuzz feature; we own it).* **Gotcha:** RLE is variable-length; the fuzzer must respect the codec's length-prefix so it doesn't generate truncated streams (or test truncation separately). Corpus: start with the test_assets/*.bin files.
- [ ] **M — Fuzz RemoteFX decoder.** RFX is tile-based (64×64). Generate random quant/RLGR/DWT payloads and fuzz the codec. Assert no panics; validate output is bounded to [0,255] per channel. *ironrdp ref: graphics/rfx.rs.* Easier than RLE because the tile structure is strict.
- [ ] **O — Fuzz ClearCodec residual + subcodec.** ClearCodec has a complex cache + multi-pass state; fuzz the subcodec (Raw/NSCodec/RLEX) transitions. Lower priority if the codec is rarely seen on the wire.
- [ ] **O — Fuzz zgfx decompression.** Feed random byte sequences claiming to be zgfx-compressed; assert decompression terminates without panic and output size is sensible. *Gotcha:* zgfx has a history buffer — malformed sequences could cause OOM; use a max-decompressed-size limit.

### V.5. Per-Windows-version interop matrix

- [ ] **M — Test-VM farm inventory.** Document the target matrix in a CSV or markdown table:
  - Windows Server 2016 / 2019 / 2022 (workgroup, empty domain)
  - Windows 10 / 11 (workgroup or AD-joined)
  - Per row: server build, negotiated security (SSL/HYBRID/HYBRID_EX), desktop size offered, color depth, any codecs sent, any quirks observed
  - Sync with real-VM infrastructure; run the integration harness against each once (or per release).
  - **Spec: none.** *Pattern: ADR-0003 verification environment in VERDICT.md.*
- [ ] **M — Ad-hoc trace capture for each variant.** When connecting to a new server variant for the first time, capture the full connection trace with Wireshark + save run log (RUST_LOG=debug). Archive in `docs/interop-traces/windows-server-2016-workgroup/`, indexed by date + outcome (ok / error + stage where it failed). This becomes the reference for debugging failures in that config.
- [ ] **O — Kerberos/AD variant.** Workgroup is mandatory; AD + Kerberos is optional v1 but should be tested before calling it "stable." Requires a KDC + test user; defer if AD lab is not available.

### V.6. CredSSP/TLS interop checks

- [ ] **M — TLS handshake capture & validation.** Verify that rustls can complete the handshake against all server variants in §V.5. Check: (a) server cert chain can be validated (or pinning logic accepts it), (b) no protocol-downgrade warnings, (c) peer certificate is extractable for CredSSP pubKeyAuth binding. *Spec: TLSLOWL-0003.* Use `rustls::server::ServerCertVerified` hooks to log certificate details.
- [ ] **M — CredSSP round-trip validation.** For each Windows variant, capture the CredSSP exchange (NegTokenInit → NegTokenTarg → NegTokenTarg with auth_info). Validate: (a) our NTLM encoder matches wire format, (b) public-key binding (SHA256 hash of cert subjectPublicKey) is computed correctly, (c) TSCredentials encryption/decryption round-trips. *ironrdp ref: sspi crate; credssp.rs.*
- [ ] **M — Early User Authorization Result parsing (HYBRID_EX).** When the server selects HYBRID_EX, validate: (a) the 4-byte LE PDU is consumed at the right place (after CredSSP, before MCS), (b) the value is parsed as 0=granted or 5=denied, (c) a denied result terminates the session with a clear error message. *Spec: MS-CSSP §3.2.5.* **Critical trap:** this was the VERDICT.md defect; bake it in as a test.
- [ ] **O — Channel-binding AV-pair round-trip.** NTLM AV pair type 10 carries the TLS peer-cert hash (SEC_CHANNEL_BINDINGS). Validate it's computed from the peer cert and sent in the NTLM Type 3 message. *ironrdp ref: sspi ChannelBindings.*

---

### Summary: ordered checklist for implementation

**Phase 1 — Foundations (Week 1–2):**
1. Set up `test_vectors/` directory structure + golden-PDU capture from mstsc (X.224, GCC, capability sets).
2. Write `#[test]` encode tests for critical PDUs (byte-diff vs golden).
3. Ingest ironrdp test assets into the project; write decode tests for RDP6/RLE/ClearCodec.

**Phase 2 — Integration scaffold (Week 2–3):**
4. Copy the existing `tests/integration_real_vm.rs` as the baseline; add per-stage tracing targets + timeout.
5. Extend the test to cover: resize/reactivation, input smoke test, EGFX milestone (if implementing).
6. Document the test-VM inventory in `docs/interop-matrix.csv`.

**Phase 3 — Codec precision (Week 3–4):**
7. Capture RemoteFX-full + Progressive + ClearCodec real tiles from the test VM; write golden-output tests.
8. Implement fuzzing harnesses (libfuzzer or quickcheck) for bitmap + RFX decoders.

**Phase 4 — Interop validation (Week 4+):**
9. Run the integration harness + capture traces against Windows Server 2016/2019/2022 (workgroup); document matrix.
10. Validate CredSSP + TLS + HYBRID_EX handling on each variant; fix variant-specific quirks as they surface.

---

### Open questions for grilling (V-specific)

1. **Test-VM access:** which Windows variants are available? (2016/2019/2022? Win10/11? AD lab?) This gates the interop matrix scope (Phase 4).
2. **Golden-PDU provenance:** should we capture from mstsc exclusively, or include FreeRDP + RDP-provided test suites? mstsc is most canonical but FreeRDP is more scriptable.
3. **Fuzzing infrastructure:** does the project already use libfuzzer / proptest? Should codec fuzzers live in the main test suite or a separate `fuzz/` harness?
4. **Trace archival:** commit captured `.pcapng` files to the repo (large) or link to an external artifact store (S3 / archive)?

This section is **independent of protocol layers** — it's orthogonal quality assurance that runs in parallel with implementation, and every protocol slice (Layers 0–6) benefits from it.

## 22. Completeness audit — MS-RDP spec coverage

1. **GDI Orders** - not explicitly mentioned in plan (section 2.2.8 of MS-RDPBCGR)
2. **Server Redirection** (MS-RDPNSC) - not covered
3. **Session Logon/Save Session Info** - partially covered but not comprehensively documented
4. **RD Gateway** (MS-TSGU) - completely absent
5. **Audio codec specifics** (codec negotiation details beyond what's in RDPEA/RDPEAI)
6. **Bitmap cache management specifics** - mentioned as optional but not detailed
7. **RDP Printing** (MS-RDPEPC) - listed under RDPFS but not detailed
8. **Smartcard redirection** (MS-RDPESC) - listed but not detailed
9. **Serial/Parallel ports** (MS-RDPESP) - listed but not detailed
10. **Slow-path bitmap compression specifics** (header encoding)
11. **Correlation Info** (RDP_NEG_CORRELATION_INFO) - flagged as TODO in ironrdp
12. **Message Channel** (MS-RDPEI2) - listed as TODO in plan
13. **Surface Bits/Framebuffer Activation** - not fully detailed
14. **Synchronization & Control Messages** in detail
15. **Order-specific details** (GDI orders like LINE, PATBLT, MEMBLT)

Here are the NOT/THINLY covered specifications to add:

---

- [ ] **M — MS-RDPBCGR § 2.2.8 (GDI Orders).** Legacy RDP drawing orders (LINE, RECTANGLE, PATBLT, MEMBLT, POLYLINE, POLYGON, ELLIPSE, SCREENBLT, LINETO); set-based negotation via Order capset; slow-path fallback for servers without surface-commands. *ironrdp ref: ironrdp-pdu/rdp/capability_sets/order.rs (PDU only, no decode).* Obsolete on modern servers but required for legacy/thin-client fallback; 18 order types × flags.

- [ ] **O — MS-RDPNSC (RDP Server Cluster Redirection).** Server-side cluster failover PDU (`TS_REDIRECTION_PACKET`), cookie-based session resume, load-balancing across cluster members. *spec-only; ironrdp TODO #139.* Not in single-server scope but needed for HA setups; outbound redirect on login.

- [ ] **M — MS-RDPBCGR § 2.2.11 (Logon/Save Session Info).** `TS_INFO_PDU`, `TS_AUTORECONNECT_COOKIE`, session persistence across reconnect, auto-cookie generation. *ironrdp ref: ironrdp-pdu/rdp/session_info/.* Partially covered; needs full logon-extended variant with autoreconnect + IP/hostname binding.

- [ ] **O — MS-TSGU (RDP Gateway Protocol).** HTTP(S) tunnel transport for RDP over gateway; `TSGChannelCreate`, `TSGChannelSendData`, `TSGChannelClose`; certificate pinning, auth-delegation. *spec-only.* Not in direct-connect scope but critical for corporate firewalls; separate transport layer.

- [ ] **O — MS-RDPBCGR § 2.2.15 (Slow-path Bitmap Compression Headers).** RDP4/5/6/7 compression type encoding (CMPREFIX + flags); per-scanline/per-plane framing; RLE subsets. *ironrdp ref: ironrdp-pdu/basic_output/bitmap/ (PDU frame only, not compression engine).* Must decompress to feed framebuffer; fallback if zgfx fails.

- [ ] **M — MS-RDPBCGR § 2.2.3 (Slow-path Synchronization & Control).** `TS_SYNCHRONIZE_PDU`, `TS_CONTROL_PDU` (Cooperate/RequestControl/GrantedControl/Detach); state machine ordering during finalization & reset. *ironrdp ref: ironrdp-pdu/rdp/finalization_messages.rs.* Already listed but needs explicit PDU-level detail; governs session-active gate.

- [ ] **O — MS-RDPBCGR § 2.2.2 (Slow-path Font List/Font Map).** `TS_FONT_LIST_PDU` (client → server) and `TS_FONT_MAP_PDU` (server → client); glyph handles; end-of-finalization marker. *ironrdp ref: ironrdp-pdu/rdp/finalization_messages.rs.* Already listed; confirm no gaps in Font Map handling (session-active gate).

- [ ] **O — MS-RDPBCGR § 2.2.13 (Slow-path Bitmap Update).** Legacy slow-path bitmap frames (per-rectangle, multi-codec in single PDU); distinct from fast-path bitmap. *ironrdp ref: ironrdp-pdu/basic_output/slow_path.rs (decode-to-rectangles only).* Must route to same framebuffer as fast-path; interleaving in one session.

- [ ] **O — MS-RDPEPC (Printer Redirection).** RDPDR sub-protocol for printers; device ID, print-job queuing, port redirection, notification PDUs. *ironrdp-rdpdr plugin (check).* Listed under RDPFS; separate spec; modern servers prefer USB redirection instead.

- [ ] **O — MS-RDPESC (Smartcard Redirection).** RDPDR sub-protocol; card hotplug, reader status, crypto operations (sign/decrypt), caching. *ironrdp-rdpdr plugin (check); sspi `scard` feature.* Listed; needs full state machine if smartcard auth is required.

- [ ] **O — MS-RDPESP (Serial/Parallel Port Redirection).** RDPDR sub-protocol; COM port emulation, LPT control, baud-rate negotiation, flow control. *ironrdp-rdpdr plugin (check).* Listed; legacy; rarely used in modern RDP.

- [ ] **O — MS-RDPBCGR § 3.1.5.2 (Correlation Info / RDP_NEG_CORRELATION_INFO).** X.224 negotiation correlation token (32 bytes + timestamp) for load-balanced redirects; ← must include in X224::ConnectionRequest if server advertises. *ironrdp TODO #111 (not supported).* Blocks cluster-aware clients; required for some enterprise setups.

- [ ] **O — MS-RDPBCGR § 2.2.1 (Slow-path Refresh Rectangle & Suppress Output).** `TS_REFRESH_RECT_PDU` (server → client, invalidate regions) and `TS_SUPPRESS_OUTPUT_PDU` (pause rendering, e.g., minimize); codec+bandwidth optimization. *ironrdp ref: ironrdp-pdu/rdp/refresh_rectangle.rs + suppress_output.rs.* Already listed; confirm routing to session loop (may skip codec processing on suppress).

- [ ] **M — MS-RDPBCGR § 2.2.9 (Pointer Update).** Mouse position, shape (color/monochrome/large), cache, hide/show; fast-path pointer update vs slow-path. *ironrdp ref: ironrdp-pdu/basic_output/pointer.rs + session/pointer composition.* Already covered; verify cache coherence with bitmap cache if present.

- [ ] **O — MS-RDPBCGR § 3.3.5 (Slow-path Output Fragmentation & Reassembly).** Large frames split across multiple X.224 PDUs; reassembly stateful; per-type fragmentation rules. *ironrdp ref: session/x224/mod.rs (reassembly logic).* Verify no buffer-size assumptions; handle interleaved fragments from different channels.

- [ ] **O — MS-RDPBCGR § 2.2.6 (Palette Update PDU).** `TS_UPDATE_PALETTE_DATA` (max 256 entries, cumulative per-session); palette-indexed framebuffer, 8-bit mode. *ironrdp ref: session/palette.rs.* Already covered; confirm ordering w.r.t. bitmap updates (palette must arrive before indexed pixel references).

- [ ] **O — MS-RDPBCGR § 3.1.4 (Demand Active / Server Capabilities).** Exact capset negotiation details: which capsets are optional vs mandatory, sub-version negotiation (RDP 5.0 → 10.1). *ironrdp ref: ironrdp-pdu/rdp/capability_sets/.* Already covered in detail (§5); verify all 20 capsets are enumerated + modern server extensions.

- [ ] **M — MS-RDPBCGR (Channel Join / SKIP_CHANNELJOIN optimization).** If server sets `SKIP_CHANNELJOIN_SUPPORTED`, batch all channel joins + elide Erect Domain; fast-path for RDP 8.1+. *ironrdp ref: connector/channel_connection.rs (check for optimization).* Verify optimization is implemented; old code may omit it.

- [ ] **O — MS-RDPPRFX (RemoteFX Codec — Full Spec).** Complete tile decode pipeline (64×64, LL3 DWT, RLGR, quantization, YCoCg→RGB); differs from Progressive in that it's single-pass. *ironrdp ref: graphics/rfx.rs (full decode).* Already covered; confirm no alpha-channel handling or subsampling variants missed.

- [ ] **O — MS-RDPBCGR § 2.2.12 / MS-RDPPRFX (Codec Negotiation / BitmapCodecs Capset).** Which codecs server will use; RFX/Progressive/ClearCodec/NSCodec/H.264 capability exchange + version flags per codec. *ironrdp ref: ironrdp-pdu/rdp/capability_sets/bitmap_codecs.rs.* Already covered in detail; verify all codec IDs (3, 8, 9, 10, 16, 17, 20) + version fields.

- [ ] **O — MS-RDPBCGR § 2.2.2.3 (Slow-path Deactivate All).** Server-initiated reset PDU (not client-initiated); triggers capability re-exchange + finalization. Distinct from client disconnect. *ironrdp ref: ironrdp-pdu/rdp/headers.rs (ShareDataHeader::action enum) + connector/connection_activation.rs (reset handling).* Already covered; critical-path: must not confuse with disconnect.

- [ ] **O — MS-RDPBCGR (Client Network Data / Channel List).** Explicit per-SVC activation in GCC vs late binding; optional Network block if no SVCs. *ironrdp ref: ironrdp-pdu/gcc/client_network_data.rs.* Covered in detail (§5b); verify channel count limits (≤31 static + unlimited dynamic).

- [ ] **O — MS-RDPBCGR § 5.3 (Standard RDP Security / Deprecated).** RC4 stream cipher, salted keys, signing without encryption; **NOT SUPPORTED** in our crate (enforce TLS). Document why. *Reference only; no implementation.* Clarify: we require TLS for all connections; no fallback to RC4.

---

###  Open questions

1. **Spec obsolescence triage:** Should we list deprecated specs (Standard RDP Security, GDI Orders, Serial/Parallel ports) at all, or drop them as "out of scope"? (→ Answer: list them, marked `[O]` + note when they're obsolete.)
2. **Gateway/cluster scope:** Is MS-TSGU in-scope for the MVP (corporate firewall tunneling), or deferred? Does the app already have a tunnel wrapper?
3. **Audio codec detail:** Beyond RDPEA/RDPEAI protocol handshake, do we need to implement the codec negotiation (e.g., AAC, MP3, OPUS), or just frame routing?
4. **Correlation Info (MS-RDPBCGR § 3.1.5.2):** Does the target server use load-balanced redirects? If yes, this becomes `M`; if not, safe to leave `O`.

## 23. Completeness audit — FreeRDP / mstsc parity gaps

### Layer 1 — Connection sequence (additional items)

- [ ] **O — .rdp file ingestion and profile parsing.** Load connection profile from .rdp text files (TS_CLIENT_NAME, TS_SERVER_PORT, TS_USERNAME, TS_DOMAIN, TS_ENCRYPTION_METHOD, TS_LOGON_TYPE, resolution, color depth, audio, drives, printers, etc.). *spec-only; ironrdp provides no profile loader.* Needed for VM/cloud desktop workflows where configs are delivered out-of-band.

- [ ] **M — Dynamic resolution negotiation via Deactivation-Reactivation.** Plan currently lists resize—but client-initiated resize (e.g., window resize on thin-client) must _advertise_ the new size, trigger deactivation, and wait for server reactivation with new desktop. *ironrdp-displaycontrol does push, not pull; we need the inbound request handler.*

- [ ] **M — RD Gateway / gateway routing protocol (MS-TSGH).** Proxy RDP over HTTPS through an RD Gateway; base64-encoded tunnel headers, keep-alive heartbeats, gateway-initiated socket closure. *spec-only; not in ironrdp.* Common in enterprise VPN/DMZ scenarios; single-serve via NAT-friendly proxy.

- [ ] **O — Server redirection / load balancing (MS-RDPNL).** Server sends LoadBalanceInfoPacket → client transparently reconnects to redirected host + balancing token. *spec-only.* Enables server-side session failover / load-balancing pools.

- [ ] **O — Auto-reconnect on disconnect (logon_extended info + Resume Session).** Server supplies auto-reconnect cookie at logon → client auto-retries with cookie on network transient; no UI prompt. *ironrdp has the PDU (logon_extended.rs) but not the loop.* Reduces perceived latency on WiFi roam / VPN drop.

---

### Layer 2 — Authentication (additional variants & depth)

- [ ] **O — NLA variant: Kerberos-only (no NTLM fallback).** Force Kerberos via RequestFlags in SPNEGO (mech list order); fail if AD/KDC unreachable. *ironrdp supports SPNEGO but no forced-Kerberos knob.* Enterprise scenario: zero-trust, no password on client.

- [ ] **O — NLA variant: Restricted Admin (Cred-less auth).** CredSSP with RequestFlags::ENABLE_CRED_LESS_MODE; no TSPasswordCreds in auth_info. *ironrdp sspi has this mode, not wired into connector.* Allow RDP to privileged admin account without storing cred on client.

- [ ] **O — NLA variant: Remote Credential Guard (per-request delegation).** Client sends no credentials to RDP server; broker (Gateway/Proxy) uses local AD/Azure for auth & token delegation. *spec-only; requires RD Gateway integration.* Highest security: zero plaintext cred transit.

- [ ] **O — NLA variant: Azure AD / RDSAAD.** HYBRID_EX → Azure Conditional Access + SAML/JWT tokens instead of NTLM/Kerberos. *HYBRID_EX branch exists in nego.rs, rest spec-only.* Growing cloud scenario (Azure VMs, AVD, RDS SAL).

- [ ] **O — Smartcard PIN / on-card Kerberos.** PK-INIT with smartcard cert+key; PIN prompt before auth. *ironrdp sspi has scard feature (Windows winscard API), not integrated into full flow.* Physical token security for high-assurance accounts.

- [ ] **M — Certificate validation / trust UI.** Server cert validation policy (TOFU/pinning, full chain, CRL/OCSP revocation check) + user trust prompt (mismatch/expired → allow-once / allow-always / reject). *ironrdp has zero cert validation — hands back subjectPublicKey.* Critical for MITM / downgrade attack prevention; UX-heavy.

- [ ] **O — Client certificate / mutual TLS (X.509 client cert).** Client supplies cert+key in TLS handshake (rare, but some on-prem RDS configs require it). *spec-only.* Enterprise mutual-auth enforcement.

---

### Layer 3 — Capability sets & GCC config (deep additions)

- [ ] **O — Desktop composition / DWM alpha blending.** DesktopComposition capset (0x19) → server streams alpha-channel surfaces. *pdu ref exists, no decode.* Windows 7+ Aero theme integration; mostly cosmetic.

- [ ] **O — Virtual channel ordering / precedence (DRDYNVC flow control).** Prioritize channels (EGFX >> audio >> clipboard) in capability negotiation + send order. *spec (MTU, priority per channel) not in ironrdp.* Minimize latency for interactive graphics under congestion.

- [ ] **M — 32-bit colour depth enforcement (`WANT_32_BPP_SESSION`).** If advertised, server MUST send 32-bit RGBA, ignoring high_color_depth/supported_color_depths negotiation. *ironrdp lists the flag, no enforcement.* Required for EGFX transparency / alpha.

- [ ] **O — Color caching / palette animation.** ColorCache capset (0x0a) — 256-entry palette cache, animated (e.g., UI pulse). *pdu only.* Legacy efficiency; modern servers rarely use it.

- [ ] **O — DrawNineGrid / client-side scaling (deprecated).** DrawNineGridCache capset (0x15) — 9-region stretch (corners fixed, edges/center scale). *pdu only.* Pre-Vista; skip unless legacy server compat needed.

- [ ] **O — DrawGdiPlus (deprecated).** DrawGdiPlus capset (0x16) — GDI+ drawing orders. *pdu only.* Very legacy; mstsc dropped this years ago.

- [ ] **O — Network auto-detect / RTT probing.** `SUPPORT_NET_CHAR_AUTODETECT` flag → server-initiated RTT/bandwidth probes; client measures latency + available BW → server adjusts codec/compression. *autodetect.rs PDU only, no RTT loop.* Adapt quality to network conditions.

- [ ] **O — Heartbeat / keep-alive PDU.** `SUPPORT_HEART_BEAT_PDU` flag → server sends periodic heartbeat (empty PDU); client ACKs. Prevents NAT/firewall idle timeout (5–10 min) without reconnect. *spec-only; ironrdp session loop doesn't emit heartbeat response.* Stability on slow/intermittent links.

- [ ] **O — Dynamic timezone (SUPPORT_DYNAMIC_TIME_ZONE).** Server can change client timezone mid-session without reconnect (via Client Info PDU update). *spec-only.* VM redeployment scenarios where timezone changes.

- [ ] **M — Keyboard IME / language-bar configuration.** Client Core Data includes IME name (e.g., "ja_JP" for Japanese input method server) + keyboard type/subtype flags. Plan lists layout/fkeys, not IME selection. Needed for East Asian input; currently unsupported.

- [ ] **O — Monitor Extended (0xC008) — per-monitor DPI + scale.** Extend Monitor block (0xC005) with per-display physical width/height (mm), scale factor (dpi/96). *spec ref in pdu gcc, no GCC encoder.* Modern multi-display support with different DPI per monitor (e.g., 1x/2x Retina mixed).

- [ ] **O — Cluster / Load-Balance redirection block (0xC004).** Static redirection block for initial connection load-balancing. *spec-only; ironrdp TODO #139.* Needed before Deactivation-Reactivation dynamic redirect.

- [ ] **O — Message Channel (0xC006).** Server messages (e.g., "System will shut down in X min") via dedicated channel. *spec-only; ironrdp TODO #140.* Administrative notifications.

---

### Layer 4 — Input (additional depth)

- [ ] **O — Pen / stylus input (RDPEI, MS-RDPEI).** Touch pen trajectory, pressure, tilt. DVC `Microsoft::Windows::RDS::Input`. *spec-only.* Thin-client / tablet scenarios (not common on RDP, but advertised by Server).

- [ ] **O — Multitouch / gesture (RDPEI).** Multi-finger touch, swipe, pinch. *spec-only.* Tablet/touch-screen RDP (e.g., Surface Pro remote desktop).

- [ ] **O — Mouse wheel horizontal (TS_MOUSE_HWHEEL).** Horizontal scroll wheel / tilt wheel. Capability flag exists; input PDU needs encoder. *spec-only from input-codec side.* Modern mice have tilt; rarely advertised by servers, but completeness.

- [ ] **M — Keyboard dead-key / combining character sequences.** Unicode input (surrogate pairs) needs multi-event assembly for complex scripts (e.g., Thai, Vietnamese) where combining marks = separate Unicode codepoints. Plan lists Unicode/surrogate pairs, not combining sequences. *Not in ironrdp input/unicode.rs.*

- [ ] **O — OS keymap → scancode conversion (cross-platform).** Extended-key prefix generation (EXTENDED/EXTENDED_1 flags) needs per-OS mapping (Windows VK → set-1 scancode, Linux evdev→set-1, macOS USB-HID→set-1). Plan says "not in ironrdp — we own it" but no details. *Critical for non-Windows clients (e.g., running on Linux thin-client or web browser).* Currently spec-only beyond Linux stub.

- [ ] **O — Relative mouse / FPS mode (RELATIVE_MOUSE_INPUT).** Delta-X/Y mode (instead of absolute) when `SUPPORT_RELATIVE_MOUSE_INPUT` advertised. Needed for 3D applications, CAD. *input/mouse_rel.rs exists, untested on real server.*

---

### Layer 5 — Graphics & codecs (long tail)

- [ ] **M — H.264 / AVC420 decoder-backend integration.** Receive the AVC WireToSurface PDU → pass to a **pluggable AVC decoder backend (undecided: C lib like openh264/ffmpeg, OS-API Platform-FFI like WMF/VideoToolbox/VAAPI, or skip)** → RGBA output. *ironrdp-egfx wires the PDU; no decoder included (patent/licensing). Backend chosen at the H.264 slice.* EGFX-capable servers often use H.264; matters for video-heavy perf.

- [ ] **O — H.264 AVC444v2 (4:4:4 lossless).** Extension of AVC that preserves all channels (no chroma subsampling). *spec-only; requires H.264 decoder.* High-fidelity remote desktop (e.g., design / color-critical work).

- [ ] **O — H.265 / HEVC (High Efficiency Video Codec).** Newer servers may advertise HEVC in bitmap codecs. *spec-only.* Future-proofing; reduces bandwidth vs H.264 at same quality.

- [ ] **O — OPUS / AAC audio codec support** (vs legacy G.711). `RDPSND` audio codec negotiation. *spec-only; ironrdp-rdpsnd checks if it exists, no codec impl.* Compressed audio reduces WAN bandwidth.

- [ ] **M — Persistent bitmap cache on disk.** Maintain a client-side on-disk bitmap cache (hashmap-backed .bin file or SQLite) to skip re-decoding repeated screen elements (UI buttons, logos) across sessions. *spec-only; ironrdp has zero disk cache.* Huge perf win for repetitive workloads; must be encrypted (server may send sensitive content via cache).

- [ ] **O — Glyph cache + text rendering.** ClearCodec includes 4000-glyph cache; reuse glyphs + font metrics instead of re-transmitting text as bitmaps. *spec-only from glyph-tracking side; ironrdp-graphics has vbar_cache but no font glyph assembly.* Text-heavy UIs (terminals, IDEs); enables sub-tile granularity.

- [ ] **O — Brush cache** (hatching / pattern fill reuse). Brush capset (0x0f) → server sends brush ids, client caches. *spec-only.* Legacy efficiency; modern servers use surface commands.

- [ ] **O — ClearCodec NSCodec subcodec lossy mode.** NSCodec can operate in lossy mode with color-loss tuning (0–7) + YCoCg + chroma subsampling. *NSCodec is PDU-only in ironrdp; no decoder.* EGFX fallback when bandwidth-constrained (but still mandatory to decode).

- [ ] **O — Surface Commands frame acknowledgment + flow control.** FrameAcknowledge capset (0x1e) → client sends frame-ack PDU after each surface frame; server throttles output. *spec-only; ironrdp session has no frame-ack emit loop.* Prevents buffer bloat on slow clients / high-latency links.

- [ ] **O — GFX thin-client mode (small cache + streaming).** EGFX capset includes cache-size negotiation; low-memory clients can request server-side cache (e.g., 32 MB vs 256 MB). *spec-only; ironrdp-egfx owns graphics pipeline but no cache-size config.* Embedded / thin-client scenarios (Raspberry Pi RDP).

- [ ] **O — Progressive frame-diff hint.** RemoteFX Progressive includes "first frame" optimization (full tile) vs "upgrade" (delta). Plan lists primitives only; full pipeline = tracking which tiles changed, signaling to server. *spec-only beyond primitives.* Bandwidth optimization for animation-heavy sessions.

- [ ] **O — Palette animation / transitions.** Palette update PDU allows smooth color transition (e.g., UI fade-in) by sending palette updates frame-by-frame. *spec-only from animation loop side.* Legacy UI smoothness; rarely used post-GDI.

- [ ] **O — Offscreen bitmap cache (0x11).** Server can cache large bitmaps off-screen + reference them in orders, reducing transmission. *pdu capset only.* Pre-EGFX efficiency; modern servers prefer surface commands.

- [ ] **O — Large pointer support (0x1b).** Support >32x32 cursors (up to 384x384). *pdu capset only; ironrdp-graphics pointer.rs is limited.* High-DPI cursors.

---

### Layer 6 — Virtual channels (the big list)

#### Already in plan (listed for completeness)
- EGFX / Graphics Pipeline (DVC) — *ironrdp-egfx*.
- Display Control (DVC) — *ironrdp-displaycontrol*.

#### MISSING / THIN in plan & ironrdp

- [ ] **O — Clipboard / CLIPRDR (MS-RDPECLIP, SVC).** Format list (text/image/file), data request/response, **file transfer w/ delayed rendering** (clipboard paste → server streams file content on-demand, not upfront). *ironrdp says `ironrdp-cliprdr (+ `-native` backends)` exists; check if file-transfer is wired.* Desktop/laptop RDP essentials.

- [ ] **O — Audio output / RDPSND (MS-RDPEA, SVC).** WAV frames, codec negotiation (ADPCM/GSM/G.711/AAC/OPUS). *ironrdp-rdpsnd listed as "check".* Primary use case: server→client audio (music, app sounds).

- [ ] **O — Audio input / RDPEAI (MS-RDPEAI, DVC).** Microphone capture, reliable + lossy-UDP variants. *spec-only.* VoIP / video-conferencing via RDP; less common, often delegated to TEAMS app.

- [ ] **O — Device Redirection / RDPDR (MS-RDPEFS, SVC).** Multiplexing hub for drives, printers, smartcards, serial ports; per-device I/O request/response. *ironrdp-rdpdr listed as "check".* Major feature: local-drive mapping (SMB-like).

  - [ ] **O — Drive redirection (filesystem access).** Client `/tmp` / `C:` mounted as UNC path on server (e.g., `\\tsclient\C`). *RDPDR sub-spec; ironrdp-rdpdr core.*

  - [ ] **O — Printer redirection (MS-RDPEPC).** Client printers (local USB/network) appear on server's printer menu. *RDPDR sub-spec; ironrdp-rdpdr may wrap.* Often disabled in restricted environments.

  - [ ] **O — Smartcard redirection (MS-RDPESC).** Client smartcard reader + card appear on server; Kerberos/PKI auth via card. *RDPDR sub-spec; ironrdp-rdpdr may wrap.* High-security scenarios (banking, government).

  - [ ] **O — Serial port redirection (MS-RDPESP).** COM1/COM2 forwarded to server (legacy hardware control, modems). *RDPDR sub-spec.* Rare; mostly legacy industrial control.

  - [ ] **O — USB device redirection (implicit in RDPDR).** High-end feature; not part of core RDPDR but often emulated via device-name patterns. *spec + implementation split between RDPDR and USB stubs.* Workstation/CAD scenarios.

- [ ] **O — RemoteApp / RAIL (MS-RDPERP, DVC).** Seamless window mode: launch individual applications (not full desktop); windowless-order stream for app frames only. *spec-only; heavy (window mgmt, hit-testing, etc.).* Important for thin-client / published-app scenarios (RDS / Citrix-like).

- [ ] **O — Multitransport (MS-RDPEMT, UDP + DTLS).** Fallback transport for graphics (UDP lossy + DTLS reliable) when TCP congestion. *ironrdp-pdu/multitransport.rs PDU only, no UDP/DTLS stack.* WAN/high-latency optimization (rare in modern gigabit networks, but common in satellite/4G).

- [ ] **O — Video redirection (MS-RDPEV, DVC).** Embedded video (H.264/HEVC stream) via dedicated channel. *spec-only.* Hybrid: some app video frames bypass RDP compression. Rare; overlaps EGFX H.264.

- [ ] **O — Video-optimized (MS-RDPEVOR, DVC).** Explicit hint to server "this window contains video"; use lower-quality codec. *spec-only.* QoS signaling; few servers honor it.

- [ ] **O — Geometry tracking (MS-RDPEGT, DVC).** Client sends window geometry hints (position, size, z-order) to server for optimization. *spec-only.* RAIL companion; mostly for RAIL mode.

- [ ] **O — Echo / latency ping (MS-RDPEECO, DVC).** Client→server echo request → measure latency + jitter. *spec-only.* Network diagnostics; not user-facing.

- [ ] **O — Camera redirection (MS-RDPECAM, DVC).** Webcam stream; hot-plug detection. *spec-only.* Video-conferencing companion (less common than audio).

- [ ] **O — Location / geolocation (MS-RDPEL, DVC).** Client location (GPS / WiFi) sent to server. *spec-only.* Privacy-critical; rarely enabled; cloud/mobile scenarios.

- [ ] **O — Auth redirection (MS-RDPEAR, DVC).** SSO credential forwarding / delegation (e.g., allow RDP'd app to auth to another RDP server via same cred). *spec-only.* Nested RDP / service-account scenarios; high-security risk.

- [ ] **O — Audio level / drive-letter persistence (MS-RDPADRV, DVC).** Persistent state: drive letter assignments, volume levels across disconnect/reconnect. *spec-only.* Session continuity UX.

---

### Layer 7 — Configuration & UX (not in plan, but critical)

- [ ] **M — Credential prompt / SSO.** Interactive username/password/domain UI if not pre-supplied; option to store (encrypted) for next time. *spec-only; authentication backend.* Desktop client essential.

- [ ] **O — Certificate trust / PIN dialog.** Server cert mismatch → user decision (trust-once / trust-always / reject). *spec-only (UI).* MITM/phishing prevention.

- [ ] **O — Session recording (audit trail).** Record all desktop activity (video + audio) for compliance. *spec-only; not RDP protocol, but client-side feature.* Enterprise governance.

- [ ] **O — Session shadowing / observer mode.** Another user watches this session (read-only input). *RDP multi-user shadow mode, not standard protocol.* Admin support / training.

---

### Layer 8 — Transport & robustness (edge cases)

- [ ] **M — TLS fallback on connection failure.** If HYBRID_EX fails (Azure AD down), fall back to TLS-only (skip CredSSP). *spec-only; connector logic needed.* Failsafe for cloud scenarios where auth broker is transient.

- [ ] **O — RDS Gateway HTTPS tunnel (MS-TSGH).** Proxy RDP inside HTTP/HTTPS (base64-encoded frame tunneling + chunked encoding). *spec-only.* DMZ / firewall-restricted access.

- [ ] **O — FIPS / FIPS-mode crypto enforcement.** TLS_FIPS-only ciphers; SHA-256 only (no MD5); HMAC-SHA256 for signing. *spec-only; rustls + sspi FIPS mode.* Government compliance (US Fed).

- [ ] **O — Bandwidth throttling / QoS.** Client self-throttles output request frequency to match network capacity (vs server-driven via autodetect). *spec-only; client loop logic.* Embedded / low-BW environments.

- [ ] **O — Reconnect with context (e.g., clipboard state).** Auto-reconnect preserves clipboard / input state. *spec-only.* UX smoothness on network transient.

---

### Layer 9 — Cross-cutting completeness

- [ ] **M — Unknown PDU / capability handling.** Strategy when server sends unknown capability capset ID or unknown fast-path update code: hard-error vs warn-log-continue. Plan lists "error classification" but not the decision. *spec-only; robustness vs spec-strict trade-off.* Interop with future/legacy servers.

- [ ] **M — Compression fallback chain.** If negotiated BitmapCodecs fails (e.g., server doesn't support RFX), what's the fallback? (RLE? Legacy bitmap?) *spec-only; connector config.* Handles mismatch/misconfiguration gracefully.

- [ ] **O — Session idle timeout.** Gracefully disconnect after N minutes of no user input. *spec-only; client loop logic.* Resource cleanup on shared thin-clients.

- [ ] **O — Reconnect limit / exponential backoff.** Limit auto-reconnect attempts + backoff interval (prevent thundering herd on server restart). *spec-only.* Stability under overload.

---

### Open questions from completeness audit

1. **File transfer scope:** Does ironrdp-cliprdr implement delayed-rendering file-clipboard (server streams file bytes on paste-request)? If not, what's the protocol depth?

2. **RDPDR sub-channel split:** Is ironrdp-rdpdr a unified RDPDR hub, or separate crates for drive/printer/smartcard? Any USB pseudo-device support?

3. **RAIL interop:** Is there a RAIL stub anywhere, or is it completely spec-only? How much of the window-management surface does it expose to a thin-client app?

4. **H.264 decoder contract:** How does ironrdp-egfx's handler interface expect H.264 AVC420 frames to be decoded? (Callback? Trait? External crate?)

5. **Kerberos SPN / realm:** Does sspi-rs KDC discovery handle SPN `TERMSRV/host:port` format correctly? Any realm override knob for cross-domain?

6. **GFX frame-ack pacing:** Is there a reference implementation showing how to emit FrameAcknowledge PDU after surface-bits decode + composition, to throttle server?

7. **Certificate validation / revocation:** Should we integrate CRL/OCSP, or just pinning + expiry + CN/SAN matching?

---

*This audit summarizes production RDP client features accrued over 10+ years in FreeRDP / mstsc / RGC. Items marked* **O** *are significant enough to track but not critical for a basic interactive desktop. Items marked* **M** *are non-negotiable for parity with a production thin-client. Missing items have no counterpart in current plan.md or ironrdp v0.9.x.*

