//! The steps a host that uses `justrdp-security` alone follows to reach the RSA key in a server's
//! X.509 chain (ADR-0020's #603 amendment). It imports only what such a host would: `justrdp-pdu`,
//! `justrdp-security` and an X.509 parser. The expected key is the value IronRDP's own test holds
//! for this chain.

use justrdp_pdu::license::{RsaPublicKey, ServerCertificate};
use justrdp_security::standard::{ClientRandom, encrypt_client_random};
use x509_cert::Certificate;
use x509_cert::der::Decode;

const LICENSE_SERVER: &[u8] = include_bytes!("fixtures/x509_chain/license_server.der");
const SERVER: &[u8] = include_bytes!("fixtures/x509_chain/server.der");
/// The `RSAPublicKey` IronRDP's own test expects from this chain.
const SERVER_PUBLIC_KEY: &[u8] = include_bytes!("fixtures/x509_chain/server_public_key.der");

/// A Server Certificate carrying the chain, `dwVersion` onward (`[MS-RDPBCGR]` 2.2.1.4.3.1).
fn chain_certificate() -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&2u32.to_le_bytes());
    blob.extend_from_slice(&2u32.to_le_bytes());
    for certificate in [LICENSE_SERVER, SERVER] {
        blob.extend_from_slice(&(certificate.len() as u32).to_le_bytes());
        blob.extend_from_slice(certificate);
    }
    blob
}

#[test]
fn a_host_reaches_the_key_from_the_last_certificate_of_the_chain() {
    let ServerCertificate::X509Chain(chain) =
        ServerCertificate::decode(&chain_certificate()).expect("the chain decodes")
    else {
        panic!("a version 2 certificate is a chain");
    };
    assert_eq!(chain.len(), 2);

    let leaf = Certificate::from_der(chain.last().unwrap()).expect("strict DER accepts the leaf");
    let inner = leaf
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .expect("the key is byte-aligned");
    assert_eq!(inner, SERVER_PUBLIC_KEY);

    let key = RsaPublicKey::from_pkcs1_der(inner).expect("the key parses");
    let modulus_in_der = &SERVER_PUBLIC_KEY[9..265];
    assert_eq!(key.modulus, modulus_in_der);
    assert_eq!(key.exponent, 65537);

    let encrypted = encrypt_client_random(&ClientRandom::new([0x11; 32]), &key)
        .expect("the key encrypts the client random");
    assert_eq!(encrypted.len(), 256 + 8);
}

/// What a host's X.509 parser has to tolerate in the server's own certificate.
#[test]
fn the_servers_certificate_is_not_an_ordinary_rsa_certificate() {
    let describe = |der: &[u8]| {
        let certificate = Certificate::from_der(der).expect("strict DER accepts it");
        let tbs = certificate.tbs_certificate();
        let extensions = tbs.extensions().expect("it has extensions");
        (
            tbs.subject_public_key_info().algorithm.oid.to_string(),
            extensions.len(),
            extensions.iter().filter(|e| e.critical).count(),
        )
    };

    assert_eq!(describe(SERVER), ("1.3.14.3.2.15".to_string(), 5, 5));
    assert_eq!(
        describe(LICENSE_SERVER),
        ("1.2.840.113549.1.1.1".to_string(), 1, 0)
    );
}
