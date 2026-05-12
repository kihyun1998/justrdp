# H.264 decode via openh264 in leaf binaries

## Decision

The reference Tauri binary (`justrdp-tauri`) takes a dependency on the
`openh264` Rust crate (Cisco's libopenh264 with patent-free distribution)
to implement the `AvcDecoder` trait for AVC420 / AVC444 / AVC444V2
EGFX payloads. **Core library crates remain pure Rust with zero C
dependencies** — `openh264` lives only inside leaf binaries that need
a real H.264 decoder.

Scope of this exception:

- **Allowed**: `justrdp-tauri/src-tauri/Cargo.toml`, future leaf binaries
  that need real-time H.264 decode for the reference user experience.
- **Forbidden**: every core library crate (`justrdp-core`, `justrdp-pdu`,
  `justrdp-graphics`, `justrdp-connector`, `justrdp-svc`, `justrdp-dvc`,
  `justrdp-egfx`, `justrdp-web`, etc.). These crates keep `#![forbid(unsafe_code)]`,
  `no_std + alloc` where applicable, and zero C deps per ADR-0001 / ADR-0002.

## Why

- **No viable pure-Rust H.264 decoder exists.** Rust's H.264 ecosystem
  is parser-only (`h264-reader`, `h264`) — no production decoder. The
  two practical options (`openh264`, `ffmpeg-next`) both wrap C
  libraries.
- **EGFX SVC over modern Windows servers (10/11, Server 2019/2022)
  routes a meaningful portion of visible regions through AVC420 /
  AVC444 codecs.** Without a real decoder, those regions render as
  black or stale pixels — the user-visible failure mode tracked in
  this slice (#26) and the `feedback_no_partial_protocol_enable`
  rationale. Library-only purity at the cost of "we ship an RDP client
  that can't render the screen" is not a tradeoff worth keeping.
- **Patent compliance via Cisco distribution.** The `openh264` crate
  consumes Cisco's pre-built binary. Cisco operates the H.264 patent
  license as a free passthrough when their binary is used unmodified.
  Building openh264 from source transfers the patent liability to the
  distributor; the crate's default feature flags consume the binary
  path. We follow the binary path.
- **Tauri's leaf-binary surface already has substantial C deps**:
  WebView2 (Chromium), winapi / windows-rs (Win32 Clipboard listener),
  Tauri runtime itself. Adding one well-scoped codec dependency does
  not change the leaf binary's threat surface meaningfully.

## Considered alternatives

- **WebCodecs `VideoDecoder` via WebView IPC** — viable but requires:
  (a) new TypeScript / JS code in the Tauri WebView (the project
  currently has no frontend source), (b) async impedance mismatch
  with the sync `AvcDecoder` trait, (c) browser compatibility matrix
  for WebView2 / WKWebView / WebKitGTK. This is a multi-PR effort
  (~4 sub-slices) for a path whose performance ceiling matches
  openh264 software decode. Tracked as a fallback for a future
  performance cycle, not as the first cut.
- **`ffmpeg-next`** — much larger transitive C surface (full FFmpeg
  build), more complex licensing.
- **Convert `AvcDecoder` trait to `async`** — every renderer caller
  becomes async-aware. Breaking change across `justrdp-egfx`,
  `justrdp-web`, `justrdp-graphics`. Even after the conversion we
  still need a backend; pure trait shape change doesn't render any
  AVC pixel.
- **Defer indefinitely (don't render AVC at all)** — user-facing
  failure on modern Windows servers. Not acceptable for a reference
  client.

## Consequences

- The Tauri build acquires a C build dependency. CI must have a C
  toolchain available (most CIs do by default; document explicitly
  in CONTRIBUTING / build instructions when added).
- Core library users (anyone embedding `justrdp-connector` etc. into
  their own Rust application) continue to see zero C deps. They may
  register their own `AvcDecoder` impl (WebCodecs, hardware FFI,
  whatever fits their constraints).
- Tauri binary size grows by ~1-2 MB (statically-linked decoder).
- License footnote required in any commercial distribution: "uses
  Cisco openh264 under Cisco's patent license; binary distributed via
  Cisco's binary download path".
- When a future contributor proposes "let's add a C crate to the core
  library for X", this ADR is the precedent boundary: leaf binary
  exception is narrow, codec/UI-platform specific, not a general
  loosening.

## Cross-references

- [[ADR-0001]] — pure-Rust crypto, the original "zero C deps" pillar.
- [[ADR-0002]] — `no_std` core (still holds; openh264 is in a `std`
  leaf binary).
- [[ADR-0006]] — native-surface deepening pattern (the precedent for
  "leaf binary owns the platform-specific impl, core owns the trait").
- Issue #26 — slice that introduces `OpenH264AvcDecoder`.
- Memory entry `feedback_no_partial_protocol_enable.md` — the rationale
  for why AVC handler completeness matters.
