//! `justrdp-codecs` — RDP graphics codecs behind a stable, sans-IO decode API.
//!
//! Phased ownership (ADR-0003): phase 1 bootstraps on `ironrdp-graphics` so rendering works
//! immediately; phase 2 rewrites each codec in-house, using `ironrdp-graphics` as a
//! **differential test oracle** (identical bytes → byte-identical pixels); phase 3 drops the
//! dependency. The slow-path codecs (slice-6) skipped phase 1 — [`rle`] (interleaved RLE,
//! MS-RDPBCGR 3.1.9) and [`planar`] (RDP6 planar, MS-RDPEGDI 2.2.2.5.1) are self-owned from
//! the start, oracle-tested against `ironrdp-graphics`. [`clearcodec`] is likewise self-owned
//! (ADR-0003 phase 2): it corrects two oracle bit-level defects that reject genuine Server 2022
//! streams. The remaining EGFX bootstrap wrapper is [`egfx`]: **zgfx alone** (slice-9), behind the
//! `egfx-bootstrap` feature. RemoteFX Progressive left it in #172 —
//! [`rfx::progressive::Progressive`] (#171) is now the only Progressive decoder in the tree,
//! self-owned and ungated, verified against a real-server corpus rather than the oracle
//! (ADR-0011); [`capture`] is that corpus's capture harness, ungated for the same reason.
//! [`rfx`] (WireToSurface1 RemoteFX, issue #58) is self-owned and ungated like ClearCodec —
//! it skipped phase 1 outright
//! (the bootstrap crate has no assembled RemoteFX decoder), verified per ADR-0007 against the
//! oracle's transform primitives; NSCodec arrives with its own phase-2 rewrite.

/// Real-server corpus capture (ADR-0011's harness half) — ungated, see the module doc.
pub mod capture;
pub mod clearcodec;
pub mod color;
#[cfg(feature = "egfx-bootstrap")]
pub mod egfx;
pub mod nscodec;
pub mod planar;
pub mod pointer;
pub mod rfx;
pub mod rle;
