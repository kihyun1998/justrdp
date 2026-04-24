#![forbid(unsafe_code)]

//! Auto-Reconnect Cookie verification helper (MS-RDPBCGR §5.5).
//!
//! Standalone helper for server applications that want to authenticate
//! a reconnecting client's [`ArcCsPrivatePacket`] against a previously
//! issued [`ArcScPrivatePacket`].
//!
//! Full reconnection wiring (Security Exchange → session-key resume
//! for Standard RDP Security) lives in the §11.2a-stdsec track. This
//! module provides only the cryptographic check, leaving
//! cookie-storage policy (same-process cache vs. shared Redis / DB
//! lookup) and the post-verification session-resume decision to the
//! caller.

use justrdp_core::crypto::hmac_md5;
use justrdp_pdu::rdp::finalization::{ArcCsPrivatePacket, ArcScPrivatePacket};

/// Canonical [`ClientRandom`] substitute used when the connection
/// negotiated Enhanced RDP Security (TLS / CredSSP / HYBRID_EX) and
/// therefore did not exchange a Security Exchange PDU.
///
/// Per MS-RDPBCGR §5.5, the HMAC-MD5 input is 32 zero bytes in that
/// path; callers SHOULD pass this constant rather than assembling
/// their own zero array to make the intent obvious at the call site.
pub const ENHANCED_SECURITY_CLIENT_RANDOM: [u8; 32] = [0u8; 32];

/// Reason a [`verify_auto_reconnect_packet`] call failed.
///
/// Exposed as a narrow enum rather than a boolean so callers can
/// distinguish policy decisions (`LogonIdMismatch` -- look up a
/// different cookie, maybe the client is echoing a stale one) from
/// cryptographic failure (`VerifierMismatch` -- credential fallback
/// per §3.3.5.3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcVerifyError {
    /// The `LogonId` in the client packet does not match the cookie
    /// the server has on file. Either the client has a stale cookie
    /// for a different session, or the caller retrieved the wrong
    /// cookie from its store.
    LogonIdMismatch,
    /// HMAC-MD5 check failed: the `SecurityVerifier` is not
    /// `HMAC_MD5(key = stored_cookie.arc_random_bits, data =
    /// client_random)`. Per §3.3.5.3.11 the correct recovery is to
    /// fall back to credential-based logon, not to disconnect.
    VerifierMismatch,
}

/// Verify a client's [`ArcCsPrivatePacket`] against a stored
/// server-side [`ArcScPrivatePacket`] per MS-RDPBCGR §5.5.
///
/// ```text
///     SecurityVerifier = HMAC_MD5(key = ArcRandomBits,
///                                 data = ClientRandom)
/// ```
///
/// * `stored_cookie` — the cookie the server issued for this session
///   via [`emit_auto_reconnect_cookie`]. Callers typically retrieve
///   this from their own session store keyed by `received.logon_id`.
/// * `received` — the [`ArcCsPrivatePacket`] carried in the client's
///   TS_EXTENDED_INFO_PACKET during reconnection.
/// * `client_random` — for Enhanced RDP Security (TLS / CredSSP /
///   HYBRID / HYBRID_EX) pass [`ENHANCED_SECURITY_CLIENT_RANDOM`]; for
///   Standard RDP Security pass the 32-byte client random that was
///   RSA-decrypted from the original Security Exchange PDU.
///
/// **Timing channel**: the HMAC digest is compared
/// byte-by-byte in constant time, so verification latency does not
/// leak prefix-match information to an attacker. `LogonIdMismatch`
/// short-circuits before the HMAC compute and is intentionally
/// non-constant-time: `logon_id` is not secret and rejecting on that
/// field is a cheap store-lookup concern, not a crypto concern.
///
/// **Replay**: this helper is stateless. It will return `Ok(())` if
/// a client replays a previously valid `(logon_id, verifier)` pair
/// against a stored cookie the server has not yet rotated. Nonce or
/// one-shot tracking is the caller's responsibility -- the usual
/// pattern is to rotate the cookie via
/// [`emit_auto_reconnect_cookie`] immediately on successful verify
/// so a replay of the old verifier matches a cookie that is no
/// longer in the store.
///
/// [`emit_auto_reconnect_cookie`]: crate::ServerActiveStage::emit_auto_reconnect_cookie
pub fn verify_auto_reconnect_packet(
    stored_cookie: &ArcScPrivatePacket,
    received: &ArcCsPrivatePacket,
    client_random: &[u8; 32],
) -> Result<(), ArcVerifyError> {
    if stored_cookie.logon_id != received.logon_id {
        return Err(ArcVerifyError::LogonIdMismatch);
    }
    let expected = hmac_md5(&stored_cookie.arc_random_bits, client_random);
    if ct_eq_16(&expected, &received.security_verifier) {
        Ok(())
    } else {
        Err(ArcVerifyError::VerifierMismatch)
    }
}

/// Constant-time equality on two 16-byte HMAC digests.
///
/// Folds every byte difference into a single accumulator so the
/// total work done is independent of where the first differing byte
/// lives. A branch on the accumulated value only at the end keeps
/// the comparison resistant to simple side-channel timing attacks on
/// the verifier check.
#[inline]
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_sc(logon_id: u32, bits: [u8; 16]) -> ArcScPrivatePacket {
        ArcScPrivatePacket {
            logon_id,
            arc_random_bits: bits,
        }
    }

    fn fake_cs(logon_id: u32, verifier: [u8; 16]) -> ArcCsPrivatePacket {
        ArcCsPrivatePacket {
            logon_id,
            security_verifier: verifier,
        }
    }

    #[test]
    fn verifier_matches_client_computed_hmac_md5() {
        // The server-side verify path MUST accept exactly the value
        // the client produces via connector.rs:1267 (which uses
        // the same hmac_md5(key=arc_random_bits, data=client_random)).
        let bits = [0x37u8; 16];
        let logon = 0x0000_0042;
        let client_random = [0xAAu8; 32];

        let verifier = hmac_md5(&bits, &client_random);
        let stored = fake_sc(logon, bits);
        let received = fake_cs(logon, verifier);

        assert_eq!(
            verify_auto_reconnect_packet(&stored, &received, &client_random),
            Ok(())
        );
    }

    #[test]
    fn enhanced_security_uses_zero_client_random() {
        // For TLS / CredSSP there is no Security Exchange PDU on
        // the wire, so ClientRandom is 32 zero bytes per §5.5.
        let bits = [0x5Au8; 16];
        let verifier = hmac_md5(&bits, &ENHANCED_SECURITY_CLIENT_RANDOM);
        let stored = fake_sc(1, bits);
        let received = fake_cs(1, verifier);

        assert_eq!(
            verify_auto_reconnect_packet(
                &stored,
                &received,
                &ENHANCED_SECURITY_CLIENT_RANDOM
            ),
            Ok(())
        );
    }

    #[test]
    fn verifier_mismatch_on_wrong_bits() {
        // An attacker without the server's arc_random_bits cannot
        // forge a valid SecurityVerifier even if they know the
        // client_random (which they do — it's on the wire in Standard
        // Security).
        let real_bits = [0x11u8; 16];
        let fake_bits = [0x22u8; 16];
        let client_random = [0xCCu8; 32];

        let stored = fake_sc(7, real_bits);
        let forged_verifier = hmac_md5(&fake_bits, &client_random);
        let received = fake_cs(7, forged_verifier);

        assert_eq!(
            verify_auto_reconnect_packet(&stored, &received, &client_random),
            Err(ArcVerifyError::VerifierMismatch)
        );
    }

    #[test]
    fn logon_id_mismatch_short_circuits_before_hmac() {
        // §5.5: the cookie table is keyed by logon_id; a client
        // echoing a different logon_id than the stored cookie is a
        // store-lookup error, not a crypto error.
        let bits = [0x01u8; 16];
        let client_random = [0xEEu8; 32];
        let stored = fake_sc(1, bits);
        let received = fake_cs(
            2, // different logon_id
            hmac_md5(&bits, &client_random),
        );

        assert_eq!(
            verify_auto_reconnect_packet(&stored, &received, &client_random),
            Err(ArcVerifyError::LogonIdMismatch)
        );
    }

    #[test]
    fn verifier_rejects_single_bit_flip() {
        // A one-bit difference in the verifier MUST fail verification.
        // Confirms the ct_eq_16 helper does a full-byte compare and
        // not some accidental prefix-only check.
        let bits = [0x2Bu8; 16];
        let client_random = [0xFEu8; 32];
        let mut verifier = hmac_md5(&bits, &client_random);
        verifier[0] ^= 0x01; // flip low bit of byte 0

        let stored = fake_sc(100, bits);
        let received = fake_cs(100, verifier);

        assert_eq!(
            verify_auto_reconnect_packet(&stored, &received, &client_random),
            Err(ArcVerifyError::VerifierMismatch)
        );
    }

    #[test]
    fn verifier_rejects_trailing_bit_flip() {
        // Catches a bug where a constant-time compare that folds into
        // a single accumulator is accidentally replaced with a prefix
        // compare that exits early -- flipping the LAST byte's high
        // bit would sneak through.
        let bits = [0x3Cu8; 16];
        let client_random = [0x99u8; 32];
        let mut verifier = hmac_md5(&bits, &client_random);
        verifier[15] ^= 0x80;

        let stored = fake_sc(50, bits);
        let received = fake_cs(50, verifier);

        assert_eq!(
            verify_auto_reconnect_packet(&stored, &received, &client_random),
            Err(ArcVerifyError::VerifierMismatch)
        );
    }

    #[test]
    fn all_zero_verifier_rejected_for_nonzero_inputs() {
        // A zeroed SecurityVerifier is the degenerate attack: an
        // adversary who cannot compute HMAC at all might try to see
        // if the helper accidentally accepts `[0; 16]`. The ct_eq
        // path MUST reject it whenever the real digest is nonzero
        // (which is statistically certain for any random key/data).
        let bits = [0x73u8; 16];
        let client_random = [0x14u8; 32];
        let stored = fake_sc(9, bits);
        let received = fake_cs(9, [0u8; 16]);

        // The real digest for these inputs is not all-zero, so the
        // compare must fail.
        let real = hmac_md5(&bits, &client_random);
        assert_ne!(real, [0u8; 16]);
        assert_eq!(
            verify_auto_reconnect_packet(&stored, &received, &client_random),
            Err(ArcVerifyError::VerifierMismatch)
        );
    }

    #[test]
    fn error_variants_are_distinguishable() {
        // Callers sometimes want to branch on the failure kind
        // (LogonIdMismatch → retry store lookup; VerifierMismatch →
        // credential fallback per §3.3.5.3.11). The Debug impl and
        // Eq discrimination MUST keep the two paths separable.
        let mismatch_logon = ArcVerifyError::LogonIdMismatch;
        let mismatch_verifier = ArcVerifyError::VerifierMismatch;
        assert_ne!(mismatch_logon, mismatch_verifier);
        assert!(alloc::format!("{mismatch_logon:?}").contains("LogonIdMismatch"));
        assert!(alloc::format!("{mismatch_verifier:?}").contains("VerifierMismatch"));
    }
}
