//! `justrdp-codecs` — RDP graphics codecs behind a stable, sans-IO decode API.
//!
//! **Every codec here is self-owned, and `ironrdp-graphics` is a dev-dependency only.** That
//! is ADR-0003 phase 3 for the whole crate, reached in #189 when zgfx — the last phase-1
//! bootstrap wrapper — was rewritten and the `egfx-bootstrap` feature deleted with it. No
//! `ironrdp` crate is in the runtime graph any more (ADR-0011).
//!
//! How each got here differs, and the difference is the verification basis rather than the
//! code. [`rle`] (interleaved RLE, MS-RDPBCGR 3.1.9), [`planar`] (RDP6 planar,
//! MS-RDPEGDI 2.2.2.5.1) and [`rfx`] (WireToSurface1 RemoteFX, #58) skipped phase 1 outright
//! and are oracle-tested — `rfx` per ADR-0007 against the oracle's transform primitives, since
//! the bootstrap crate has no assembled RemoteFX decoder. [`clearcodec`] left phase 1 in #56,
//! correcting two oracle bit-level defects that reject genuine Server 2022 streams.
//! [`rfx::progressive::Progressive`] (#171, live since #172) is gated on a real-server corpus
//! instead of the oracle, which cannot decode this server's streams at all (ADR-0011, #194);
//! [`capture`] is that corpus's harness. [`zgfx`] (#189) is the one case where the references
//! handed over an *independent* expectation: FreeRDP and `ironrdp-graphics` reproduce the
//! `[MS-RDPEGFX]` sample byte-identically, so the oracle keeps a role here as breadth over
//! generated sequences rather than as the basis. NSCodec arrives with its own phase-2 rewrite.

/// Real-server corpus capture (ADR-0011's harness half) — ungated, see the module doc.
pub mod capture;
pub mod clearcodec;
pub mod color;
pub mod nscodec;
pub mod planar;
pub mod pointer;
pub mod rfx;
pub mod rle;
pub mod zgfx;
