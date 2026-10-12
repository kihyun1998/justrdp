# 0019 — H.264 is decoded behind a host-supplied decoder, not owned

- Status: Accepted (decided 2026-06-08 while grilling the build plan; recorded 2026-10-12 when
  that plan was retired). The H.264 slice is epic #21.
- Date: 2026-06-08
- Kind: **judgement**. The maintainer chose it; a better derivation does not reopen it.

## Context

ADR-0003 owns every RDP graphics codec outright: RemoteFX, RemoteFX Progressive, ClearCodec,
NSCodec, planar, RLE and zgfx are pure Rust, patent-free and the same on every platform, so
owning them costs only the work.

H.264 (EGFX AVC420 / AVC444 / AVC444v2) is different on all three counts:

- **Patent-encumbered.** Shipping a decoder in a library binary carries licensing obligations
  that the host, not the library, is placed to accept.
- **Platform-dependent.** The best backend differs by host: a C library (openh264, ffmpeg), or an
  OS API with hardware acceleration (Windows Media Foundation, macOS VideoToolbox, Linux VAAPI).
- **Optional on the wire.** A client that does not advertise AVC gets RemoteFX / Progressive
  instead; the measured server's desktop codec is Progressive (`egfx-graphics-pipeline.md`).

## Decision

**The core defines an `AvcDecoder` seam (AVC bytes → RGBA) that the EGFX path calls, and the
backend is supplied by the host. justrdp ships no AVC decoder.**

- Until the seam exists (it does not yet; #21), AVC is never advertised: `AVC_DISABLED` is set
  on every 10.x capability set and 10.1 is not offered (#296), so a conforming server never
  sends AVC (ADR-0016: the core refuses an advertisement it cannot honour). Once it exists, the
  same holds for a host that supplies no decoder.
- The other codecs are **not** behind a trait. They stay owned outright (ADR-0003).
- The seam's exact shape (trait vs callback, sync vs async, frame vs NAL granularity) is
  #21's grill, not this record's.

## Consequences

- No patent-encumbered code and no C toolchain enter the default dependency graph (ADR-0002).
- A host that wants H.264 supplies a backend and takes on its licensing.
- Both prior designs had the same shape: IronRDP (`H264Decoder` trait plus an optional
  `openh264` feature) and the earlier justrdp (`AvcDecoder` trait).

## Alternatives considered

- **Own an H.264 decoder in pure Rust.** Rejected: months of work on a codec whose patents bind
  the library's users, for a stream the server falls back from.
- **Bundle openh264 behind a default feature.** Rejected: it picks one backend for every host,
  and puts a C dependency and licensing in the default build.
