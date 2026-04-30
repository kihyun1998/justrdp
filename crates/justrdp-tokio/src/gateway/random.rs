#![forbid(unsafe_code)]

//! OS-RNG sourced random material for the gateway transports.
//!
//! Three call sites:
//!
//! * [`make_ntlm_random`] — fills the per-handshake [`NtlmRandom`]
//!   (8-byte client challenge + 16-byte exported session key).
//! * [`make_connection_id`] — fills the 16-byte `RDG-Connection-Id`
//!   GUID. Bits are masked so the value is a valid RFC 4122 v4 UUID
//!   even though MS-TSGU itself doesn't require it (some gateway
//!   implementations refuse to log non-conformant GUIDs).
//! * `Sec-WebSocket-Key` (G5) — generated locally inside the WS
//!   variant once it lands.

use alloc::format;

use justrdp_async::TransportError;
use justrdp_gateway::NtlmRandom;

/// Build a fresh [`NtlmRandom`] from the OS RNG.
///
/// Failures from `getrandom` surface as
/// [`TransportErrorKind::Io`](justrdp_async::TransportErrorKind::Io)
/// — we treat the OS RNG as part of the I/O substrate (a missing
/// `/dev/urandom` is an environmental, not protocol, failure).
#[allow(dead_code)]
pub(crate) fn make_ntlm_random() -> Result<NtlmRandom, TransportError> {
    let mut client_challenge = [0u8; 8];
    let mut exported_session_key = [0u8; 16];
    getrandom::getrandom(&mut client_challenge)
        .map_err(|e| TransportError::io(format!("OS random failure: {e}")))?;
    getrandom::getrandom(&mut exported_session_key)
        .map_err(|e| TransportError::io(format!("OS random failure: {e}")))?;
    Ok(NtlmRandom {
        client_challenge,
        exported_session_key,
    })
}

/// Build a fresh 16-byte `RDG-Connection-Id` GUID.
///
/// Bits 6/7 of byte 8 and bits 4-7 of byte 6 are masked to form a
/// version-4 (random) RFC 4122 UUID. MS-TSGU §3.3.5.1 doesn't require
/// the version bits, but real gateways often log the GUID in canonical
/// UUID form and reject malformed values.
#[allow(dead_code)]
pub(crate) fn make_connection_id() -> Result<[u8; 16], TransportError> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id)
        .map_err(|e| TransportError::io(format!("OS random failure: {e}")))?;
    id[6] = (id[6] & 0x0F) | 0x40;
    id[8] = (id[8] & 0x3F) | 0x80;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_ntlm_random_returns_distinct_values_across_calls() {
        // Pure smoke test on the RNG plumbing — two consecutive
        // values must not collide. (Probability of collision over
        // 24 bytes is vanishingly small; if this ever flakes, the
        // OS RNG is broken.)
        let a = make_ntlm_random().unwrap();
        let b = make_ntlm_random().unwrap();
        assert_ne!(a.client_challenge, b.client_challenge);
        assert_ne!(a.exported_session_key, b.exported_session_key);
    }

    #[test]
    fn make_connection_id_sets_uuid_v4_marker_bits() {
        let id = make_connection_id().unwrap();
        // Version-4 marker — top nibble of byte 6 is 0x4.
        assert_eq!(id[6] & 0xF0, 0x40);
        // RFC 4122 variant — top two bits of byte 8 are 0b10.
        assert_eq!(id[8] & 0xC0, 0x80);
    }
}
