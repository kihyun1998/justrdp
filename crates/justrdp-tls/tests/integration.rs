#![forbid(unsafe_code)]

//! Integration tests for justrdp-tls against a real RDP server.
//!
//! These tests require a running RDP server at `RDP_TEST_HOST` (default: 192.168.136.136:3389).
//! They are `#[ignore]`d by default — run with:
//!
//! ```sh
//! cargo test -p justrdp-tls --test integration -- --ignored
//! cargo test -p justrdp-tls --test integration --features native-tls-backend -- --ignored
//! ```

use std::net::TcpStream;
use std::time::Duration;

use justrdp_tls::TlsUpgrader;

const RDP_TEST_HOST: &str = "192.168.136.136:3389";
const RDP_TEST_SERVER_NAME: &str = "192.168.136.136";
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

fn connect_tcp() -> TcpStream {
    let stream = TcpStream::connect(RDP_TEST_HOST).expect("failed to connect to RDP test server");
    stream
        .set_read_timeout(Some(TCP_TIMEOUT))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(TCP_TIMEOUT))
        .expect("set write timeout");
    stream
}

// ── rustls backend ──

#[cfg(feature = "rustls-backend")]
mod rustls_tests {
    use super::*;
    use justrdp_tls::RustlsUpgrader;

    #[test]
    #[ignore]
    fn rustls_no_verify_succeeds_with_self_signed() {
        let stream = connect_tcp();
        let upgrader = RustlsUpgrader::new();
        let result = upgrader.upgrade(stream, RDP_TEST_SERVER_NAME);

        assert!(result.is_ok(), "no-verify should accept self-signed cert");
        let upgrade = result.unwrap();
        assert!(
            !upgrade.server_public_key.is_empty(),
            "server public key should be extracted"
        );
    }

    #[test]
    #[ignore]
    fn rustls_with_verify_rejects_self_signed() {
        let stream = connect_tcp();
        let upgrader = RustlsUpgrader::with_verification();
        let result = upgrader.upgrade(stream, RDP_TEST_SERVER_NAME);

        match &result {
            Err(justrdp_tls::TlsError::Handshake(_)) => {} // expected
            Err(other) => panic!("expected TlsError::Handshake, got: {other:?}"),
            Ok(_) => panic!("with_verification should reject self-signed cert"),
        }
    }

    #[test]
    #[ignore]
    fn rustls_extracts_valid_spki() {
        let stream = connect_tcp();
        let upgrader = RustlsUpgrader::new();
        let upgrade = upgrader.upgrade(stream, RDP_TEST_SERVER_NAME).unwrap();

        let spki = &upgrade.server_public_key;

        // SPKI must start with SEQUENCE tag (0x30)
        assert_eq!(spki[0], 0x30, "SPKI should start with SEQUENCE tag");

        // Extract the SubjectPublicKey from SPKI
        let pub_key = justrdp_tls::extract_subject_public_key_from_spki(spki);
        assert!(pub_key.is_some(), "should extract SubjectPublicKey from SPKI");
        let pub_key = pub_key.unwrap();
        assert!(
            pub_key.len() > 32,
            "RSA public key should be at least 32 bytes, got {}",
            pub_key.len()
        );
    }

    #[test]
    #[ignore]
    fn rustls_two_connections_get_same_public_key() {
        let upgrader = RustlsUpgrader::new();

        let stream1 = connect_tcp();
        let key1 = upgrader
            .upgrade(stream1, RDP_TEST_SERVER_NAME)
            .unwrap()
            .server_public_key;

        let stream2 = connect_tcp();
        let key2 = upgrader
            .upgrade(stream2, RDP_TEST_SERVER_NAME)
            .unwrap()
            .server_public_key;

        assert_eq!(
            key1, key2,
            "same server should return the same public key across connections"
        );
    }
}

// ── native-tls backend ──

#[cfg(feature = "native-tls-backend")]
mod native_tls_tests {
    use super::*;
    use justrdp_tls::NativeTlsUpgrader;

    #[test]
    #[ignore]
    fn native_tls_no_verify_succeeds_with_self_signed() {
        let stream = connect_tcp();
        let upgrader = NativeTlsUpgrader::new();
        let result = upgrader.upgrade(stream, RDP_TEST_SERVER_NAME);

        assert!(result.is_ok(), "no-verify should accept self-signed cert");
        let upgrade = result.unwrap();
        assert!(
            !upgrade.server_public_key.is_empty(),
            "server public key should be extracted"
        );
    }

    #[test]
    #[ignore]
    fn native_tls_with_verify_rejects_self_signed() {
        let stream = connect_tcp();
        let upgrader = NativeTlsUpgrader::with_verification();
        let result = upgrader.upgrade(stream, RDP_TEST_SERVER_NAME);

        match &result {
            Err(justrdp_tls::TlsError::Handshake(_)) => {} // expected
            Err(other) => panic!("expected TlsError::Handshake, got: {other:?}"),
            Ok(_) => panic!("with_verification should reject self-signed cert"),
        }
    }

    #[test]
    #[ignore]
    fn native_tls_extracts_valid_spki() {
        let stream = connect_tcp();
        let upgrader = NativeTlsUpgrader::new();
        let upgrade = upgrader.upgrade(stream, RDP_TEST_SERVER_NAME).unwrap();

        let spki = &upgrade.server_public_key;
        assert_eq!(spki[0], 0x30, "SPKI should start with SEQUENCE tag");

        let pub_key = justrdp_tls::extract_subject_public_key_from_spki(spki);
        assert!(pub_key.is_some(), "should extract SubjectPublicKey from SPKI");
        let pub_key = pub_key.unwrap();
        assert!(
            pub_key.len() > 32,
            "RSA public key should be at least 32 bytes, got {}",
            pub_key.len()
        );
    }

    #[test]
    #[ignore]
    fn native_tls_and_rustls_extract_same_key() {
        // Cross-backend: both should extract identical SPKI from the same server
        let rustls_upgrader = justrdp_tls::RustlsUpgrader::new();
        let stream1 = connect_tcp();
        let rustls_key = rustls_upgrader
            .upgrade(stream1, RDP_TEST_SERVER_NAME)
            .unwrap()
            .server_public_key;

        let native_upgrader = NativeTlsUpgrader::new();
        let stream2 = connect_tcp();
        let native_key = native_upgrader
            .upgrade(stream2, RDP_TEST_SERVER_NAME)
            .unwrap()
            .server_public_key;

        assert_eq!(
            rustls_key, native_key,
            "rustls and native-tls should extract identical SPKI from the same server"
        );
    }
}
