//! `justrdp-codecs` — RDP graphics codecs behind a stable, sans-IO decode API.
//!
//! Phased ownership (ADR-0003): phase 1 bootstraps on `ironrdp-graphics` so rendering works
//! immediately; phase 2 rewrites each codec in-house, using `ironrdp-graphics` as a
//! **differential test oracle** (identical bytes → byte-identical pixels); phase 3 drops the
//! dependency. The slow-path codecs (slice-6) skipped phase 1 — [`rle`] (interleaved RLE,
//! MS-RDPBCGR 3.1.9) and [`planar`] (RDP6 planar, MS-RDPEGDI 2.2.2.5.1) are self-owned from
//! the start, oracle-tested against `ironrdp-graphics`. [`clearcodec`] is likewise self-owned
//! (ADR-0003 phase 2): it corrects two oracle bit-level defects that reject genuine Server 2022
//! streams. The remaining EGFX decoders ([`egfx`]: zgfx, RemoteFX Progressive — slice-9) are
//! still phase-1 bootstrap wrappers behind the `egfx-bootstrap` feature; WireToSurface1 RemoteFX
//! (CAVIDEO) and NSCodec arrive with their own phase-2 rewrites.

pub mod clearcodec;
pub mod color;
#[cfg(feature = "egfx-bootstrap")]
pub mod egfx;
pub mod planar;
pub mod pointer;
pub mod rle;
