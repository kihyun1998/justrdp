//! `justrdp-codecs` — RDP graphics codecs (RemoteFX, RemoteFX Progressive, ClearCodec, NSCodec,
//! zgfx) behind a stable, sans-IO decode API.
//!
//! Phased ownership (ADR-0003): phase 1 bootstraps on `ironrdp-graphics` so rendering works
//! immediately; phase 2 rewrites each codec in-house, using `ironrdp-graphics` as a **differential
//! test oracle** (identical bytes → byte-identical pixels); phase 3 drops the dependency.
