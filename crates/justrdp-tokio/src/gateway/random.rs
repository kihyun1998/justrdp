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
use justrdp_rpch::pdu::uuid::RpcUuid;
use justrdp_rpch::tunnel::RpchTunnelConfig;

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

/// Generate a fresh random RFC 4122 v4 UUID (the same masking the
/// rest of this module uses for `RDG-Connection-Id`). RPC-over-HTTP
/// session setup needs four of these — virtual connection cookie,
/// IN/OUT channel cookies, association group ID — and they MUST all
/// be distinct and unpredictable per session.
fn make_random_uuid() -> Result<RpcUuid, TransportError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b)
        .map_err(|e| TransportError::io(format!("OS random failure: {e}")))?;
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    Ok(RpcUuid {
        data1: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        data2: u16::from_be_bytes([b[4], b[5]]),
        data3: u16::from_be_bytes([b[6], b[7]]),
        data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
    })
}

/// Build a fresh [`RpchTunnelConfig`] with the four random UUIDs the
/// MS-RPCH §3.2.1.5 handshake demands. Defaults match what Windows
/// RPCRT4 sends (verified via Wireshark by the blocking
/// `make_rpch_tunnel_config` author).
#[allow(dead_code)]
pub(crate) fn make_rpch_tunnel_config() -> Result<RpchTunnelConfig, TransportError> {
    Ok(RpchTunnelConfig {
        virtual_connection_cookie: make_random_uuid()?,
        out_channel_cookie: make_random_uuid()?,
        in_channel_cookie: make_random_uuid()?,
        association_group_id: make_random_uuid()?,
        receive_window_size: 65_536,
        channel_lifetime: 0x4000_0000,
        client_keepalive: 300_000,
    })
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

    #[test]
    fn make_rpch_tunnel_config_returns_distinct_uuids() {
        let cfg = make_rpch_tunnel_config().unwrap();
        // The four UUIDs must all be distinct — collisions would
        // confuse the MS-RPCH handshake.
        let uuids = [
            cfg.virtual_connection_cookie,
            cfg.out_channel_cookie,
            cfg.in_channel_cookie,
            cfg.association_group_id,
        ];
        for i in 0..uuids.len() {
            for j in (i + 1)..uuids.len() {
                assert_ne!(uuids[i], uuids[j], "uuid collision at {i}/{j}");
            }
        }
        // Sanity: defaults match Windows RPCRT4's observed values.
        assert_eq!(cfg.receive_window_size, 65_536);
        assert_eq!(cfg.channel_lifetime, 0x4000_0000);
        assert_eq!(cfg.client_keepalive, 300_000);
    }
}
