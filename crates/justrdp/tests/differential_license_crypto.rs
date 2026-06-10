//! Differential oracle for the hand-rolled licensing crypto (ADR-0001): the same inputs run
//! through `justrdp::license_crypto` and through ironrdp's
//! `ClientNewLicenseRequest::from_server_license_request` (which performs the identical
//! MS-RDPELE 5.1.3 derivation and 5.1.2 RSA encryption internally) must produce identical
//! session keys and identical encrypted premaster bytes.

use justrdp::license_crypto;
use justrdp_pdu::client_info;
use justrdp_pdu::license;

use ironrdp_pdu::decode as ironrdp_decode;
use ironrdp_pdu::rdp::server_license as iron_license;

const CLIENT_RANDOM: [u8; 32] = [0x11; 32];
const PREMASTER: [u8; 48] = [0x22; 48];
const SERVER_RANDOM: [u8; 32] = [0x5A; 32];

/// A synthetic Server License Request carrying a proprietary certificate with `modulus_be`.
fn server_license_request_bytes(modulus_be: &[u8], exponent: u32) -> Vec<u8> {
    let bitlen = modulus_be.len() * 8;
    let keylen = modulus_be.len() + 8;
    let mut key = Vec::new();
    key.extend_from_slice(&0x3141_5352u32.to_le_bytes());
    key.extend_from_slice(&(keylen as u32).to_le_bytes());
    key.extend_from_slice(&(bitlen as u32).to_le_bytes());
    key.extend_from_slice(&((bitlen / 8 - 1) as u32).to_le_bytes());
    key.extend_from_slice(&exponent.to_le_bytes());
    let mut le = modulus_be.to_vec();
    le.reverse();
    key.extend_from_slice(&le);
    key.extend_from_slice(&[0u8; 8]);

    let mut cert = Vec::new();
    cert.extend_from_slice(&1u32.to_le_bytes());
    cert.extend_from_slice(&1u32.to_le_bytes());
    cert.extend_from_slice(&1u32.to_le_bytes());
    cert.extend_from_slice(&0x0006u16.to_le_bytes());
    cert.extend_from_slice(&(key.len() as u16).to_le_bytes());
    cert.extend_from_slice(&key);
    // Signature blob — required by ironrdp's decoder, verified by neither stack.
    cert.extend_from_slice(&0x0008u16.to_le_bytes());
    cert.extend_from_slice(&72u16.to_le_bytes());
    cert.extend_from_slice(&[0x51; 72]);

    let mut body = Vec::new();
    body.extend_from_slice(&SERVER_RANDOM);
    body.extend_from_slice(&0x0006_0000u32.to_le_bytes());
    body.extend_from_slice(&4u32.to_le_bytes());
    body.extend_from_slice(b"M\0S\0");
    body.extend_from_slice(&2u32.to_le_bytes());
    body.extend_from_slice(b"A\0");
    body.extend_from_slice(&0x000Du16.to_le_bytes());
    body.extend_from_slice(&4u16.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&0x0003u16.to_le_bytes());
    body.extend_from_slice(&(cert.len() as u16).to_le_bytes());
    body.extend_from_slice(&cert);
    body.extend_from_slice(&0u32.to_le_bytes());

    let mut msg = Vec::new();
    client_info::encode_basic_security_header(&mut msg, client_info::SEC_LICENSE_PKT);
    msg.push(license::MSG_LICENSE_REQUEST);
    msg.push(0x03);
    msg.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
    msg.extend_from_slice(&body);
    msg
}

/// ironrdp's parsed ServerLicenseRequest for the synthetic message.
fn their_request(modulus_be: &[u8]) -> iron_license::ServerLicenseRequest {
    let bytes = server_license_request_bytes(modulus_be, 65537);
    let pdu: iron_license::LicensePdu = ironrdp_decode(&bytes).unwrap();
    match pdu {
        iron_license::LicensePdu::ServerLicenseRequest(request) => request,
        other => panic!("expected a ServerLicenseRequest, got {other:?}"),
    }
}

#[test]
fn key_derivation_matches_ironrdp() {
    let theirs_request = their_request(&[0xC3; 64]);
    let (_, their_keys) = iron_license::ClientNewLicenseRequest::from_server_license_request(
        &theirs_request,
        &CLIENT_RANDOM,
        &PREMASTER,
        "user",
        "host",
    )
    .expect("ironrdp derives the licensing keys");

    let ours = license_crypto::derive_license_keys(&PREMASTER, &CLIENT_RANDOM, &SERVER_RANDOM);
    assert_eq!(ours.mac_salt.as_slice(), their_keys.mac_salt_key.as_slice());
    assert_eq!(ours.license_key.as_slice(), their_keys.license_key.as_slice());
}

#[test]
fn rsa_premaster_encryption_matches_independent_known_answers() {
    // ironrdp 0.8 cannot oracle this one: it treats the proprietary certificate's modulus and
    // exponent — little-endian on the wire (MS-RDPBCGR 2.2.1.4.3.1.1.1) — as big-endian, so
    // its full-path licensing RSA is spec-incorrect (FreeRDP reverses; we reverse). The
    // oracle here is an independent computation instead:
    //   python: pow(int.from_bytes(premaster, 'little'), 65537, int.from_bytes(mod, 'big'))
    //   → little-endian bytes + 8 zero padding bytes.
    let cases: [(&[u8], &str); 2] = [
        (
            &[0xC3; 64],
            "ff74c1015e54c397c9710092fc4ecf06db47fe3cd634f2664d8591bb4d14861f\
             db1cb8b6c45e9448343ff753401b4f45381476f8f405a4a6a2b7644c636f4982\
             0000000000000000",
        ),
        (
            &{
                let mut m = [0xABu8; 64];
                m[0] = 0xF7;
                m[63] = 0x01;
                m
            },
            "daacf8d4f286b68ae5395f45676ac989cce0f00fc09170327434b4ba918be8b3\
             1e469825fb22450089e053cc2674d2dd553a31f925a582e6ccc24e96dd697591\
             0000000000000000",
        ),
    ];
    for (modulus_be, expected_hex) in cases {
        let ours = license_crypto::encrypt_premaster_secret(&PREMASTER, modulus_be, 65537);
        let ours_hex: String = ours.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(ours_hex, expected_hex.replace(char::is_whitespace, ""));
    }
}

#[test]
fn platform_challenge_response_verifies_under_ironrdp_keys() {
    // ironrdp's full response builder validates the challenge MAC with the keys it derived —
    // feeding it a challenge encrypted/MAC'd with OUR keys proves both stacks agree on RC4,
    // MAC, and the key schedule end to end.
    let theirs_request = their_request(&[0xC3; 64]);
    let (_, their_keys) = iron_license::ClientNewLicenseRequest::from_server_license_request(
        &theirs_request,
        &CLIENT_RANDOM,
        &PREMASTER,
        "user",
        "host",
    )
    .unwrap();

    let ours = license_crypto::derive_license_keys(&PREMASTER, &CLIENT_RANDOM, &SERVER_RANDOM);
    let challenge_plain = b"TEST\0";
    let encrypted = license_crypto::rc4(&ours.license_key, challenge_plain);
    let mac = license_crypto::mac_data(&ours.mac_salt, challenge_plain);

    let mut challenge_body = Vec::new();
    client_info::encode_basic_security_header(&mut challenge_body, client_info::SEC_LICENSE_PKT);
    challenge_body.push(license::MSG_PLATFORM_CHALLENGE);
    challenge_body.push(0x03);
    challenge_body
        .extend_from_slice(&((4 + 4 + 4 + encrypted.len() + 16) as u16).to_le_bytes());
    challenge_body.extend_from_slice(&0u32.to_le_bytes()); // ConnectFlags
    challenge_body.extend_from_slice(&0x0009u16.to_le_bytes());
    challenge_body.extend_from_slice(&(encrypted.len() as u16).to_le_bytes());
    challenge_body.extend_from_slice(&encrypted);
    challenge_body.extend_from_slice(&mac);

    let pdu: iron_license::LicensePdu = ironrdp_decode(&challenge_body).unwrap();
    let iron_license::LicensePdu::ServerPlatformChallenge(challenge) = pdu else {
        panic!("expected a ServerPlatformChallenge");
    };
    iron_license::ClientPlatformChallengeResponse::from_server_platform_challenge(
        &challenge,
        [1, 2, 3, 4],
        &their_keys,
    )
    .expect("ironrdp accepts a challenge built with our RC4 + MAC under our derived keys");
}
