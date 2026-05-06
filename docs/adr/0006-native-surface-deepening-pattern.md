# Native surface deepening pattern for `*-native` crates

## Status

`accepted` (2026-05-06, established by the cliprdr-native refactor at
commit `8b5fea1`).

## Decision

Every `justrdp-*-native` crate exposes a **content-typed Native surface
trait** that its platform modules implement, plus a small wrapper struct
that owns all channel-protocol encoding and dispatch on top. Platform
modules speak only platform-level vocabulary (UTF-8 strings, raw byte
arrays, OS handles); the wrapper is where the deletion-test complexity
concentrates. See the **Native surface** entry in `CONTEXT.md`.

## Why

Without this pattern the wrapper struct becomes a pass-through (its
deletion test passes vacuously), encoding logic spreads across each
platform module, and platform code drags MS-RDPECLIP / MS-RDPEA /
MS-RDPEFS protocol types into its imports. With it, each platform module
is small and testable through OS-level abstractions, and the wrapper has a
real interface that admits unit tests via mock surfaces (no real OS
clipboard / audio device required).

## Considered options

- **(A) Each platform module implements the channel's protocol trait
  directly.** This was the status quo for cliprdr-native before the
  refactor. Rejected: forces platforms to know RDP types
  (`LongFormatName`, `FormatListResponse`, `FileContentsRequestPdu`),
  duplicates the encoding code across platforms, and leaves the wrapper
  with nothing to do.
- **(B) Format-ID-typed surface** (`read(format_id) / write(format_id)`).
  Rejected: still leaks RDP format IDs (`CF_TEXT`, `CF_UNICODETEXT`,
  `CF_DIB`) into platform code; gives no advantage over content-typed
  when each channel handles a small fixed set of content kinds.
- **(C) Content-typed surface — accepted.** Platform speaks only
  OS-native shapes (text-as-`String`, image-as-DIB-bytes). Wrapper owns
  format-ID dispatch and RDP encoding.
- **(D) 3-method surface with `read_all` + wrapper-side snapshot
  caching.** Considered during the design grilling, but abandoned at the
  start of implementation: the four existing platforms read on demand per
  format with no batching opportunity, so the cache pays for nothing.

## Consequences

- The `*-native` family now has a documented standard shape.
  `rdpsnd-native` and `rdpeai-native` already follow it (with their own
  within-crate seams `NativeAudioOutput` / `AudioCaptureBackend`);
  `cliprdr-native` is now aligned via `NativeClipboardSurface`.
- `rdpdr-native` is the next candidate for the same deepening — it
  currently scatters `cfg!` directives across eight files instead of
  exposing a within-crate platform seam.
- The naming asymmetry between Native-surface traits
  (e.g. `NativeClipboardSurface`) and channel-protocol traits
  (e.g. `RdpsndBackend`, `CliprdrBackend`) is intentional: they live at
  different layers. Do not unify.
- The wrapper struct must be generic over the surface
  (`Wrapper<S: NativeSurface = PlatformDefault>`), with a default type
  parameter so existing call sites (`Wrapper::new()`) still compile
  without annotations.
- When a PR proposes "let's just have the platform implement the channel's
  protocol trait directly", point to this ADR.
