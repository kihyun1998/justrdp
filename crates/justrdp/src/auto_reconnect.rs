//! Automatic Reconnection, client side (`[MS-RDPBCGR]` 5.5): the `ARC_CS_PRIVATE_PACKET` this
//! client sends in the Client Info PDU, derived from the `ARC_SC_PRIVATE_PACKET` a previous
//! session's Save Session Info carried (issue #306).

use crate::license_crypto::md5;
use justrdp_pdu::client_info::ClientAutoReconnect;
use justrdp_pdu::session_info::ServerAutoReconnect;

/// The MD5 block size, in bytes.
const BLOCK: usize = 64;

/// `ClientRandom` under Enhanced RDP Security: 5.5 has it assumed to be 32 zero bytes.
const ZERO_CLIENT_RANDOM: [u8; 32] = [0; 32];

/// HMAC-MD5 (RFC 2104).
fn hmac_md5(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..16].copy_from_slice(&md5(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let mut outer = Vec::with_capacity(BLOCK + 16);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&md5(&inner));
    md5(&outer)
}

/// `SecurityVerifier = HMAC-MD5(ArcRandomBits, ClientRandom)`, with the zero client random
/// that Enhanced RDP Security implies.
fn security_verifier(random_bits: &[u8; 16]) -> [u8; 16] {
    hmac_md5(random_bits, &ZERO_CLIENT_RANDOM)
}

/// The `ARC_CS_PRIVATE_PACKET` answering `server`: its `Version` and `LogonId`, and the
/// verifier derived from its random.
pub(crate) fn client_cookie(server: &ServerAutoReconnect) -> ClientAutoReconnect {
    ClientAutoReconnect {
        version: server.version,
        logon_id: server.logon_id,
        security_verifier: security_verifier(&server.random_bits),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 2202 §2, HMAC-MD5 test cases 1, 2 and 6 (6 has a key longer than the block).
    #[test]
    fn hmac_md5_matches_rfc_2202() {
        assert_eq!(
            hmac_md5(&[0x0b; 16], b"Hi There").to_vec(),
            hex("9294727a3638bb1c13f48ef8158bfc9d")
        );
        assert_eq!(
            hmac_md5(b"Jefe", b"what do ya want for nothing?").to_vec(),
            hex("750c783e6ab0b503eaa86e310a5db738")
        );
        assert_eq!(
            hmac_md5(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )
            .to_vec(),
            hex("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd")
        );
    }

    /// 5.5 under Enhanced RDP Security: `HMAC-MD5(key = ArcRandomBits, msg = 32 × 0x00)`.
    /// Expected values from Python's `hmac.new(key, bytes(32), hashlib.md5)`.
    #[test]
    fn the_security_verifier_is_hmac_md5_over_a_zero_client_random() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            security_verifier(&key).to_vec(),
            hex("b639c8731638618b707972aa6e96cf90")
        );
        assert_eq!(
            security_verifier(&[0xA5; 16]).to_vec(),
            hex("949940ad86c00c6a4f4c1e5a673574bb")
        );
    }

    /// `Version` and `LogonId` are the server's, echoed; only the verifier is derived.
    #[test]
    fn the_client_cookie_echoes_version_and_logon_id() {
        let server = ServerAutoReconnect {
            version: 7,
            logon_id: 48,
            random_bits: [0xA5; 16],
        };
        let client = client_cookie(&server);
        assert_eq!(client.version, 7);
        assert_eq!(client.logon_id, 48);
        assert_eq!(
            client.security_verifier.to_vec(),
            hex("949940ad86c00c6a4f4c1e5a673574bb")
        );
    }
}
