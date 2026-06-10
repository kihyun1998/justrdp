//! RDP licensing PDUs (MS-RDPELE) — the gatekeeping exchange between the Client Info PDU and
//! capability negotiation. Pure (de)serialization: the key derivation / RC4 / RSA arithmetic the
//! full negotiation needs lives in the `justrdp` core (`license_crypto`), not here.
//!
//! Every licensing message rides in a basic security header carrying `SEC_LICENSE_PKT`
//! (`client_info::SEC_LICENSE_PKT`), then a 4-byte preamble, then the message body. In the
//! common case the exchange is a single inbound [`LicenseError`] with [`STATUS_VALID_CLIENT`];
//! the full Server License Request → New License Request → Platform Challenge → Response →
//! New/Upgrade License path is the rarer one (MS-RDPELE 1.3.3).

use crate::DecodeError;
use crate::client_info::{SEC_LICENSE_PKT, encode_basic_security_header};
use crate::cursor::ReadCursor;

/// `bMsgType`: Server License Request.
pub const MSG_LICENSE_REQUEST: u8 = 0x01;
/// `bMsgType`: Server Platform Challenge.
pub const MSG_PLATFORM_CHALLENGE: u8 = 0x02;
/// `bMsgType`: Server New License.
pub const MSG_NEW_LICENSE: u8 = 0x03;
/// `bMsgType`: Server Upgrade License.
pub const MSG_UPGRADE_LICENSE: u8 = 0x04;
/// `bMsgType`: Client New License Request.
pub const MSG_NEW_LICENSE_REQUEST: u8 = 0x13;
/// `bMsgType`: Client Platform Challenge Response.
pub const MSG_PLATFORM_CHALLENGE_RESPONSE: u8 = 0x15;
/// `bMsgType`: License Error Message (`ERROR_ALERT`).
pub const MSG_ERROR_ALERT: u8 = 0xFF;

/// `flags` low nibble: licensing protocol version 3.0 (RDP 5.0+).
const PREAMBLE_VERSION_3: u8 = 0x03;

/// `dwErrorCode`: the server accepted the client as validly licensed — the short-circuit that
/// ends licensing in one message (the path most real servers take).
pub const STATUS_VALID_CLIENT: u32 = 0x0000_0007;
/// `dwStateTransition`: total abort — the connection must be dropped.
pub const ST_TOTAL_ABORT: u32 = 0x0000_0001;
/// `dwStateTransition`: no transition — the exchange is complete.
pub const ST_NO_TRANSITION: u32 = 0x0000_0002;
/// `dwStateTransition`: reset phase to start.
pub const ST_RESET_PHASE_TO_START: u32 = 0x0000_0003;
/// `dwStateTransition`: resend last message.
pub const ST_RESEND_LAST_MESSAGE: u32 = 0x0000_0004;

/// `wBlobType`: client random / encrypted premaster secret.
const BLOB_RANDOM: u16 = 0x0002;
/// `wBlobType`: encrypted data (challenge response, HWID, license info).
const BLOB_ENCRYPTED_DATA: u16 = 0x0009;
/// `wBlobType`: client user name (ANSI, null-terminated).
const BLOB_CLIENT_USER_NAME: u16 = 0x000F;
/// `wBlobType`: client machine name (ANSI, null-terminated).
const BLOB_CLIENT_MACHINE_NAME: u16 = 0x0010;

/// `PreferredKeyExchangeAlg`: RSA (the only algorithm MS-RDPELE defines).
const KEY_EXCHANGE_ALGORITHM_RSA: u32 = 0x0000_0001;

/// A common `PlatformId` for the New License Request: client OS "NT post-5.2" + ISV
/// "Microsoft" (the value mstsc-lineage clients send; MS-RDPELE 2.2.2.2).
pub const PLATFORM_ID_NT_POST_52_MICROSOFT: u32 = 0x0401_0000;

/// `MACData` length (MS-RDPELE 2.2.1.3 et al.).
pub const MAC_SIZE: usize = 16;
/// `ServerRandom` / `ClientRandom` length.
pub const RANDOM_SIZE: usize = 32;
/// Premaster secret length (MS-RDPELE 5.1.2.1).
pub const PREMASTER_SECRET_SIZE: usize = 48;

/// The 4-byte preamble every licensing message starts with (after the security header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicensePreamble {
    /// `bMsgType` (one of the `MSG_*` constants).
    pub msg_type: u8,
    /// `flags` — low nibble is the protocol version, `0x80` advertises extended error support.
    pub flags: u8,
    /// `wMsgSize` — preamble + body length in bytes.
    pub msg_size: u16,
}

impl LicensePreamble {
    /// Decode the preamble. The caller has already consumed the basic security header and
    /// checked `SEC_LICENSE_PKT`.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let msg_type = cur.read_u8()?;
        let flags = cur.read_u8()?;
        let msg_size = cur.read_u16_le()?;
        Ok(Self {
            msg_type,
            flags,
            msg_size,
        })
    }
}

/// Append security header + preamble + `body` for a client licensing message.
fn encode_license_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 4 + body.len());
    encode_basic_security_header(&mut out, SEC_LICENSE_PKT);
    out.push(msg_type);
    out.push(PREAMBLE_VERSION_3);
    out.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Read a licensing binary blob header, returning its data slice.
fn read_blob<'a>(cur: &mut ReadCursor<'a>) -> Result<(u16, &'a [u8]), DecodeError> {
    let blob_type = cur.read_u16_le()?;
    let len = cur.read_u16_le()? as usize;
    Ok((blob_type, cur.read_slice(len)?))
}

/// Append a blob header + data.
fn write_blob(out: &mut Vec<u8>, blob_type: u16, data: &[u8]) {
    out.extend_from_slice(&blob_type.to_le_bytes());
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(data);
}

/// An RSA public key extracted from the server's licensing certificate: big-endian modulus and
/// the public exponent, ready for the premaster-secret encryption in `justrdp`'s license crypto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// The modulus, big-endian, without the proprietary format's trailing padding.
    pub modulus: Vec<u8>,
    /// The public exponent (typically 65537).
    pub exponent: u32,
}

impl RsaPublicKey {
    /// Parse a DER `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` —
    /// the inner `subjectPublicKey` of an X.509 RSA certificate. This is the only ASN.1 the
    /// licensing path needs, so it is hand-walked here rather than pulling a DER dependency
    /// into this crate (decision 6).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(der, "RSAPublicKey DER");
        read_der_tag(&mut cur, 0x30)?; // SEQUENCE (length implicitly bounds the cursor)
        read_der_tag(&mut cur, 0x02)?;
        let modulus_len = read_der_length(&mut cur)?;
        // INTEGERs are big-endian with a leading 0x00 when the high bit is set.
        let mut modulus = cur.read_slice(modulus_len)?;
        while modulus.first() == Some(&0) {
            modulus = &modulus[1..];
        }
        read_der_tag(&mut cur, 0x02)?;
        let exp_len = read_der_length(&mut cur)?;
        let mut exp_bytes = cur.read_slice(exp_len)?;
        while exp_bytes.first() == Some(&0) {
            exp_bytes = &exp_bytes[1..];
        }
        if exp_bytes.len() > 4 {
            return Err(DecodeError::InvalidField {
                field: "RSAPublicKey.publicExponent",
                reason: "public exponent wider than 32 bits",
            });
        }
        let mut exponent = 0u32;
        for &b in exp_bytes {
            exponent = exponent << 8 | b as u32;
        }
        Ok(Self {
            modulus: modulus.to_vec(),
            exponent,
        })
    }
}

/// Read one expected DER tag byte and skip its length field, leaving the cursor at the value.
fn read_der_tag(cur: &mut ReadCursor<'_>, expected: u8) -> Result<(), DecodeError> {
    if cur.read_u8()? != expected {
        return Err(DecodeError::InvalidField {
            field: "DER tag",
            reason: "unexpected ASN.1 tag in RSAPublicKey",
        });
    }
    if expected == 0x30 {
        read_der_length(cur)?; // consume the sequence length; contents follow in order
    }
    Ok(())
}

/// Read a DER length (short form, or long form up to 2 bytes — keys never need more).
fn read_der_length(cur: &mut ReadCursor<'_>) -> Result<usize, DecodeError> {
    let first = cur.read_u8()?;
    match first {
        0..=0x7F => Ok(first as usize),
        0x81 => Ok(cur.read_u8()? as usize),
        0x82 => Ok(cur.read_u16_be()? as usize),
        _ => Err(DecodeError::InvalidField {
            field: "DER length",
            reason: "unsupported long-form length",
        }),
    }
}

/// The server certificate from the License Request (MS-RDPBCGR 2.2.1.4.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerCertificate {
    /// `CERT_CHAIN_VERSION_1` — the proprietary format, already parsed down to its RSA key
    /// (the signature is not verified: licensing rides inside the already-authenticated TLS
    /// session, and the proprietary signing key is public knowledge anyway).
    Proprietary(RsaPublicKey),
    /// `CERT_CHAIN_VERSION_2` — an X.509 chain, leaf last. Parsing X.509 needs an ASN.1
    /// walker, which this dependency-free crate does not carry; the `justrdp` core extracts
    /// the key via `x509-cert` (the same leaf dependency the TLS public-key binding uses).
    X509Chain(Vec<Vec<u8>>),
}

/// `RSA1` — the magic of the proprietary `RSA_PUBLIC_KEY` structure.
const RSA_MAGIC: u32 = 0x3141_5352;
/// Trailing zero padding the proprietary modulus field carries.
const RSA_MODULUS_PADDING: usize = 8;

impl ServerCertificate {
    /// Decode from the certificate blob's data (`dwVersion` onward).
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(data, "server certificate");
        // Bit 31 is the "temporary certificate" flag; the format selector is the rest.
        let version = cur.read_u32_le()? & 0x7FFF_FFFF;
        match version {
            1 => {
                cur.read_u32_le()?; // dwSigAlgId
                cur.read_u32_le()?; // dwKeyAlgId
                cur.read_u16_le()?; // wPublicKeyBlobType (BB_RSA_KEY_BLOB)
                let key_len = cur.read_u16_le()? as usize;
                let key_data = cur.read_slice(key_len)?;
                Ok(ServerCertificate::Proprietary(decode_rsa_public_key(
                    key_data,
                )?))
                // Signature blob follows; deliberately not read (see variant docs).
            }
            2 => {
                let count = cur.read_u32_le()? as usize;
                if count == 0 || count > 16 {
                    return Err(DecodeError::InvalidField {
                        field: "NumCertBlobs",
                        reason: "X.509 certificate chain length out of range (1..=16)",
                    });
                }
                let mut chain = Vec::with_capacity(count);
                for _ in 0..count {
                    let cb = cur.read_u32_le()? as usize;
                    chain.push(cur.read_slice(cb)?.to_vec());
                }
                Ok(ServerCertificate::X509Chain(chain))
            }
            _ => Err(DecodeError::InvalidField {
                field: "dwVersion",
                reason: "unknown server certificate chain version",
            }),
        }
    }
}

/// Parse the proprietary `RSA_PUBLIC_KEY` blob into a big-endian key.
fn decode_rsa_public_key(data: &[u8]) -> Result<RsaPublicKey, DecodeError> {
    let mut cur = ReadCursor::new(data, "RSA public key");
    if cur.read_u32_le()? != RSA_MAGIC {
        return Err(DecodeError::InvalidField {
            field: "RSA_PUBLIC_KEY.magic",
            reason: "expected magic \"RSA1\"",
        });
    }
    let keylen = cur.read_u32_le()? as usize;
    let bitlen = cur.read_u32_le()? as usize;
    cur.read_u32_le()?; // datalen (max encodable bytes; implied by bitlen)
    let exponent = cur.read_u32_le()?;
    if keylen < RSA_MODULUS_PADDING
        || !bitlen.is_multiple_of(8)
        || keylen - RSA_MODULUS_PADDING != bitlen / 8
    {
        return Err(DecodeError::InvalidField {
            field: "RSA_PUBLIC_KEY.keylen",
            reason: "keylen must equal bitlen/8 plus 8 bytes of padding",
        });
    }
    let modulus_le = cur.read_slice(keylen)?;
    // Stored little-endian with 8 trailing pad bytes; expose big-endian and unpadded.
    let mut modulus: Vec<u8> = modulus_le[..keylen - RSA_MODULUS_PADDING].to_vec();
    modulus.reverse();
    Ok(RsaPublicKey { modulus, exponent })
}

/// A decoded Server License Request (MS-RDPELE 2.2.2.1) — the opening of the full negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerLicenseRequest {
    /// `ServerRandom` — feeds the session key derivation.
    pub server_random: [u8; RANDOM_SIZE],
    /// The server certificate, when present (the certificate blob may legitimately be empty
    /// when the server expects the client to already hold a license).
    pub certificate: Option<ServerCertificate>,
}

impl ServerLicenseRequest {
    /// Decode the body (after the preamble). Product info, key-exchange list, and scope list
    /// are validated structurally but not retained — nothing downstream consumes them.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let mut server_random = [0u8; RANDOM_SIZE];
        server_random.copy_from_slice(cur.read_slice(RANDOM_SIZE)?);

        // ProductInfo: dwVersion + two length-prefixed UTF-16 strings.
        cur.read_u32_le()?;
        let cb_company = cur.read_u32_le()? as usize;
        cur.read_slice(cb_company)?;
        let cb_product = cur.read_u32_le()? as usize;
        cur.read_slice(cb_product)?;

        let (_, _key_exchange_list) = read_blob(cur)?;
        let (_, cert_data) = read_blob(cur)?;
        let certificate = if cert_data.is_empty() {
            None
        } else {
            Some(ServerCertificate::decode(cert_data)?)
        };

        let scope_count = cur.read_u32_le()? as usize;
        for _ in 0..scope_count {
            read_blob(cur)?;
        }

        Ok(Self {
            server_random,
            certificate,
        })
    }
}

/// Encode a Client New License Request (MS-RDPELE 2.2.2.2), complete with security header.
/// `encrypted_premaster_secret` comes from the core's license crypto (RSA against the server
/// certificate's key); `username` / `machine_name` are sent ANSI, null-terminated.
pub fn encode_new_license_request(
    platform_id: u32,
    client_random: &[u8; RANDOM_SIZE],
    encrypted_premaster_secret: &[u8],
    username: &str,
    machine_name: &str,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&KEY_EXCHANGE_ALGORITHM_RSA.to_le_bytes());
    body.extend_from_slice(&platform_id.to_le_bytes());
    body.extend_from_slice(client_random);
    write_blob(&mut body, BLOB_RANDOM, encrypted_premaster_secret);

    let mut name = username.as_bytes().to_vec();
    name.push(0);
    write_blob(&mut body, BLOB_CLIENT_USER_NAME, &name);
    let mut machine = machine_name.as_bytes().to_vec();
    machine.push(0);
    write_blob(&mut body, BLOB_CLIENT_MACHINE_NAME, &machine);

    encode_license_message(MSG_NEW_LICENSE_REQUEST, &body)
}

/// A decoded Server Platform Challenge (MS-RDPELE 2.2.2.4). The challenge data is RC4-encrypted
/// with the licensing encryption key; decryption and the MAC check happen in the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformChallenge {
    /// `EncryptedPlatformChallenge` blob data (still encrypted).
    pub encrypted_challenge: Vec<u8>,
    /// `MACData` over the *decrypted* challenge.
    pub mac: [u8; MAC_SIZE],
}

impl PlatformChallenge {
    /// Decode the body (after the preamble).
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        cur.read_u32_le()?; // ConnectFlags (reserved)
        let (_, challenge) = read_blob(cur)?;
        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(cur.read_slice(MAC_SIZE)?);
        Ok(Self {
            encrypted_challenge: challenge.to_vec(),
            mac,
        })
    }
}

/// Encode a Client Platform Challenge Response (MS-RDPELE 2.2.2.5), complete with security
/// header. Both blobs arrive already RC4-encrypted from the core; `mac` covers the
/// concatenated *plaintext* response data + HWID.
pub fn encode_platform_challenge_response(
    encrypted_response: &[u8],
    encrypted_hwid: &[u8],
    mac: &[u8; MAC_SIZE],
) -> Vec<u8> {
    let mut body = Vec::new();
    write_blob(&mut body, BLOB_ENCRYPTED_DATA, encrypted_response);
    write_blob(&mut body, BLOB_ENCRYPTED_DATA, encrypted_hwid);
    body.extend_from_slice(mac);
    encode_license_message(MSG_PLATFORM_CHALLENGE_RESPONSE, &body)
}

/// A decoded Server New License / Upgrade License (MS-RDPELE 2.2.2.6 / 2.2.2.3) — the full
/// negotiation's happy ending. The license blob is RC4-encrypted; this slice verifies its MAC
/// (in the core) and discards it (persistent caching is plan.md backlog).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLicense {
    /// `EncryptedLicenseInfo` blob data (still encrypted).
    pub encrypted_license_info: Vec<u8>,
    /// `MACData` over the decrypted license info.
    pub mac: [u8; MAC_SIZE],
}

impl NewLicense {
    /// Decode the body (after the preamble) — same layout for New and Upgrade License.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let (_, info) = read_blob(cur)?;
        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(cur.read_slice(MAC_SIZE)?);
        Ok(Self {
            encrypted_license_info: info.to_vec(),
            mac,
        })
    }
}

/// A decoded License Error Message (MS-RDPELE 2.2.2.7). With
/// [`STATUS_VALID_CLIENT`]/[`ST_NO_TRANSITION`] this is the licensing short-circuit; any other
/// error code is a licensing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicenseError {
    /// `dwErrorCode` (e.g. [`STATUS_VALID_CLIENT`]).
    pub error_code: u32,
    /// `dwStateTransition` (one of the `ST_*` constants).
    pub state_transition: u32,
}

impl LicenseError {
    /// Decode the body (after the preamble). The trailing error-info blob is ignored.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let error_code = cur.read_u32_le()?;
        let state_transition = cur.read_u32_le()?;
        Ok(Self {
            error_code,
            state_transition,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a proprietary certificate blob around a tiny RSA key (64-bit modulus).
    fn proprietary_cert(modulus_be: &[u8], exponent: u32) -> Vec<u8> {
        let bitlen = modulus_be.len() * 8;
        let keylen = modulus_be.len() + RSA_MODULUS_PADDING;
        let mut key = Vec::new();
        key.extend_from_slice(&RSA_MAGIC.to_le_bytes());
        key.extend_from_slice(&(keylen as u32).to_le_bytes());
        key.extend_from_slice(&(bitlen as u32).to_le_bytes());
        key.extend_from_slice(&((bitlen / 8 - 1) as u32).to_le_bytes());
        key.extend_from_slice(&exponent.to_le_bytes());
        let mut le: Vec<u8> = modulus_be.to_vec();
        le.reverse();
        key.extend_from_slice(&le);
        key.extend_from_slice(&[0u8; RSA_MODULUS_PADDING]);

        let mut cert = Vec::new();
        cert.extend_from_slice(&1u32.to_le_bytes()); // CERT_CHAIN_VERSION_1
        cert.extend_from_slice(&1u32.to_le_bytes()); // dwSigAlgId
        cert.extend_from_slice(&1u32.to_le_bytes()); // dwKeyAlgId
        cert.extend_from_slice(&0x0006u16.to_le_bytes()); // BB_RSA_KEY_BLOB
        cert.extend_from_slice(&(key.len() as u16).to_le_bytes());
        cert.extend_from_slice(&key);
        cert
    }

    /// Build a full Server License Request body (no security header / preamble).
    fn license_request_body(server_random: [u8; 32], cert: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&server_random);
        body.extend_from_slice(&0x0006_0000u32.to_le_bytes()); // ProductInfo.dwVersion
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(b"M\0S\0"); // company (UTF-16)
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(b"A\0"); // product id
        write_blob(&mut body, 0x000D, &1u32.to_le_bytes()); // KeyExchangeList: RSA
        write_blob(&mut body, 0x0003, cert);
        body.extend_from_slice(&1u32.to_le_bytes()); // ScopeCount
        let mut scope = Vec::new();
        write_blob(&mut scope, 0x000E, b"scope\0");
        body.extend_from_slice(&scope);
        body
    }

    #[test]
    fn server_license_request_decodes_proprietary_certificate() {
        let modulus = [0xC3, 0x52, 0x11, 0x84, 0x39, 0x7A, 0x55, 0x01];
        let body = license_request_body([7; 32], &proprietary_cert(&modulus, 65537));
        let mut cur = ReadCursor::new(&body, "test");
        let req = ServerLicenseRequest::decode(&mut cur).unwrap();
        assert_eq!(req.server_random, [7; 32]);
        match req.certificate.unwrap() {
            ServerCertificate::Proprietary(key) => {
                assert_eq!(key.modulus, modulus);
                assert_eq!(key.exponent, 65537);
            }
            other => panic!("expected proprietary certificate, got {other:?}"),
        }
    }

    #[test]
    fn x509_chain_certificate_is_kept_raw() {
        let mut cert = Vec::new();
        cert.extend_from_slice(&(2u32 | 0x8000_0000).to_le_bytes()); // version 2 + temporary bit
        cert.extend_from_slice(&2u32.to_le_bytes()); // NumCertBlobs
        for der in [&b"fake-ca"[..], &b"fake-leaf"[..]] {
            cert.extend_from_slice(&(der.len() as u32).to_le_bytes());
            cert.extend_from_slice(der);
        }
        match ServerCertificate::decode(&cert).unwrap() {
            ServerCertificate::X509Chain(chain) => {
                assert_eq!(chain, vec![b"fake-ca".to_vec(), b"fake-leaf".to_vec()]);
            }
            other => panic!("expected X.509 chain, got {other:?}"),
        }
    }

    #[test]
    fn new_license_request_pins_wire_layout() {
        let msg = encode_new_license_request(0x0401_0000, &[9; 32], &[0xEE; 16], "user", "host");
        // Security header: SEC_LICENSE_PKT + flagsHi.
        assert_eq!(&msg[0..2], &SEC_LICENSE_PKT.to_le_bytes());
        assert_eq!(&msg[2..4], &[0, 0]);
        // Preamble: type, version, size (= everything after the security header).
        assert_eq!(msg[4], MSG_NEW_LICENSE_REQUEST);
        assert_eq!(msg[5], PREAMBLE_VERSION_3);
        assert_eq!(&msg[6..8], &((msg.len() - 4) as u16).to_le_bytes());
        // Body: key exchange alg, platform id, client random.
        assert_eq!(&msg[8..12], &1u32.to_le_bytes());
        assert_eq!(&msg[12..16], &0x0401_0000u32.to_le_bytes());
        assert_eq!(&msg[16..48], &[9; 32]);
        // Premaster blob: type RANDOM, then data.
        assert_eq!(&msg[48..50], &BLOB_RANDOM.to_le_bytes());
        assert_eq!(&msg[50..52], &16u16.to_le_bytes());
        assert_eq!(&msg[52..68], &[0xEE; 16]);
        // Username blob (null-terminated ANSI), then machine name blob.
        assert_eq!(&msg[68..70], &BLOB_CLIENT_USER_NAME.to_le_bytes());
        assert_eq!(&msg[70..72], &5u16.to_le_bytes());
        assert_eq!(&msg[72..77], b"user\0");
        assert_eq!(&msg[77..79], &BLOB_CLIENT_MACHINE_NAME.to_le_bytes());
        assert_eq!(&msg[79..81], &5u16.to_le_bytes());
        assert_eq!(&msg[81..86], b"host\0");
    }

    #[test]
    fn platform_challenge_and_response_round_trip() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        write_blob(&mut body, BLOB_ENCRYPTED_DATA, &[0x11; 10]);
        body.extend_from_slice(&[0x22; MAC_SIZE]);
        let mut cur = ReadCursor::new(&body, "test");
        let challenge = PlatformChallenge::decode(&mut cur).unwrap();
        assert_eq!(challenge.encrypted_challenge, vec![0x11; 10]);
        assert_eq!(challenge.mac, [0x22; MAC_SIZE]);

        let msg = encode_platform_challenge_response(&[1, 2], &[3, 4, 5], &[6; MAC_SIZE]);
        assert_eq!(msg[4], MSG_PLATFORM_CHALLENGE_RESPONSE);
        // Two ENCRYPTED_DATA blobs, then the MAC.
        assert_eq!(&msg[8..10], &BLOB_ENCRYPTED_DATA.to_le_bytes());
        assert_eq!(&msg[10..12], &2u16.to_le_bytes());
        assert_eq!(&msg[12..14], &[1, 2]);
        assert_eq!(&msg[14..16], &BLOB_ENCRYPTED_DATA.to_le_bytes());
        assert_eq!(&msg[16..18], &3u16.to_le_bytes());
        assert_eq!(&msg[18..21], &[3, 4, 5]);
        assert_eq!(&msg[21..], &[6; MAC_SIZE]);
    }

    #[test]
    fn license_error_short_circuit_decodes() {
        let mut body = Vec::new();
        body.extend_from_slice(&STATUS_VALID_CLIENT.to_le_bytes());
        body.extend_from_slice(&ST_NO_TRANSITION.to_le_bytes());
        // Trailing error-info blob (ignored).
        write_blob(&mut body, 0x0004, &[]);
        let mut cur = ReadCursor::new(&body, "test");
        let err = LicenseError::decode(&mut cur).unwrap();
        assert_eq!(err.error_code, STATUS_VALID_CLIENT);
        assert_eq!(err.state_transition, ST_NO_TRANSITION);
    }
}
