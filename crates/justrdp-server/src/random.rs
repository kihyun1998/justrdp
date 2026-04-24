#![forbid(unsafe_code)]

//! Caller-managed randomness seam.
//!
//! This crate deliberately does not pick a cryptographic RNG on
//! behalf of the caller. Embedding a specific crate
//! (`rand::thread_rng`, `getrandom`, …) would force a platform
//! decision on `no_std` targets and add a hard dependency for a
//! single very small surface: the 16-byte `ArcRandomBits` material
//! in `ArcScPrivatePacket` (MS-RDPBCGR §2.2.4.2).
//!
//! Callers implement [`RandomSource`] around their preferred source
//! and pass it into the API that needs it -- currently only
//! [`ServerActiveStage::emit_auto_reconnect_cookie`].
//!
//! [`ServerActiveStage::emit_auto_reconnect_cookie`]: crate::ServerActiveStage::emit_auto_reconnect_cookie

/// A source of cryptographic randomness injected by the caller.
///
/// Implementations MUST draw from a **cryptographically secure**
/// source. Auto-Reconnect cookies (`ArcScPrivatePacket.ArcRandomBits`)
/// serve as the HMAC-MD5 key in the §5.5 reconnection-verification
/// path; a predictable RNG lets an attacker forge the
/// `SecurityVerifier` in a `ClientAutoReconnectPacket` offline.
pub trait RandomSource {
    /// Fill `buf` with cryptographically secure random bytes.
    fn fill_random(&mut self, buf: &mut [u8]);
}
