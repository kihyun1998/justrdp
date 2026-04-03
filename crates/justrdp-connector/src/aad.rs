#![forbid(unsafe_code)]

//! Azure AD Authentication (RDSAAD) -- JWS construction and JSON helpers.
//!
//! Handles the RDP Assertion (JWS Compact Serialization) construction
//! for the PROTOCOL_RDSAAD authentication flow (MS-RDPBCGR 2.2.18).

use alloc::format;
use alloc::string::String;

use justrdp_core::base64url;
use justrdp_core::crypto::sha256;
use justrdp_core::rsa::rsa_sign_sha256;

// Note: sha256 is used for JWK thumbprint computation (not for JWS signing).

use crate::config::AadConfig;
use crate::error::{ConnectorError, ConnectorResult};

/// Build the RDP Assertion (JWS Compact Serialization) for Azure AD auth.
///
/// MS-RDPBCGR 2.2.18.2.1: `Base64URL(header).Base64URL(payload).Base64URL(signature)`
///
/// The signature uses RSASSA-PKCS1-v1_5 with SHA-256 over the ASCII bytes
/// of `header_b64 + "." + payload_b64`.
pub fn build_rdp_assertion(config: &AadConfig, server_nonce: &str) -> ConnectorResult<String> {
    let thumbprint = compute_jwk_thumbprint(&config.pop_key_n, &config.pop_key_e);
    let jwk_json = build_jwk_json(&config.pop_key_n, &config.pop_key_e);

    // JOSE Header
    let header = format!(
        r#"{{"alg":"RS256","kid":"{}"}}"#,
        thumbprint,
    );

    // client_claims is a JSON-encoded STRING value (not a nested object).
    // Inner JSON: {"aad_nonce":"<nonce>"}
    // This string must be JSON-escaped when embedded in the outer payload.
    let client_claims_inner = format!(
        r#"{{"aad_nonce":"{}"}}"#,
        json_escape(&config.aad_nonce),
    );
    let client_claims_escaped = json_escape(&client_claims_inner);

    // JWS Payload
    let payload = format!(
        r#"{{"ts":{},"at":"{}","u":"{}","nonce":"{}","cnf":{{"jwk":{}}},"client_claims":"{}"}}"#,
        config.timestamp,
        json_escape(&config.access_token),
        json_escape(&config.resource_uri),
        json_escape(server_nonce),
        jwk_json,
        client_claims_escaped,
    );

    let header_b64 = base64url::encode_string(header.as_bytes());
    let payload_b64 = base64url::encode_string(payload.as_bytes());

    // Signing input: ASCII bytes of "header_b64.payload_b64"
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // RSASSA-PKCS1-v1_5 signature with SHA-256
    // Note: rsa_sign_sha256 internally computes SHA-256, so pass plaintext (not pre-hashed)
    let signature = rsa_sign_sha256(&config.pop_key, signing_input.as_bytes())
        .map_err(|_| ConnectorError::general("RSA key too small for PKCS#1 v1.5 SHA-256 signing"))?;
    let signature_b64 = base64url::encode_string(&signature);

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

/// Compute JWK Thumbprint per RFC 7638.
///
/// For RSA keys: `SHA-256({"e":"<e_b64>","kty":"RSA","n":"<n_b64>"})` → Base64URL
/// Keys must be in lexicographic order (e, kty, n).
pub fn compute_jwk_thumbprint(n: &[u8], e: &[u8]) -> String {
    let canonical = build_canonical_jwk_json(n, e);
    let hash = sha256(canonical.as_bytes());
    base64url::encode_string(&hash)
}

/// Build the full JWK JSON object for the `cnf` field.
pub fn build_jwk_json(n: &[u8], e: &[u8]) -> String {
    let n_b64 = base64url::encode_string(n);
    let e_b64 = base64url::encode_string(e);
    format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e_b64, n_b64)
}

/// Build canonical JWK JSON for thumbprint (RFC 7638 §3: lexicographic order, minified).
fn build_canonical_jwk_json(n: &[u8], e: &[u8]) -> String {
    // Lexicographic order: e, kty, n
    build_jwk_json(n, e)
}

/// Extract a string value from a flat JSON object.
///
/// E.g., `extract_json_string_value(r#"{"ts_nonce":"abc"}"#, "ts_nonce")` → `Some("abc")`
pub fn extract_json_string_value<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let search = format!(r#""{}":""#, key);
    let start = json.find(&search)? + search.len();
    let rest = &json[start..];
    // Find closing `"` while skipping escaped `\"`
    let mut i = 0;
    let bytes = rest.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped character
            continue;
        }
        if bytes[i] == b'"' {
            return Some(&rest[..i]);
        }
        i += 1;
    }
    None
}

/// Extract an integer value from a flat JSON object.
///
/// E.g., `extract_json_integer_value(r#"{"authentication_result":0}"#, "authentication_result")` → `Some(0)`
pub fn extract_json_integer_value(json: &str, key: &str) -> Option<u32> {
    let search = format!(r#""{}":"#, key);
    let start = json.find(&search)? + search.len();
    let rest = json[start..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Build the authentication request JSON PDU.
pub fn build_auth_request_json(jws: &str) -> String {
    format!(r#"{{"rdp_assertion":"{}"}}"#, jws)
}

/// Escape a string for JSON embedding (RFC 8259 §7).
fn json_escape(s: &str) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn extract_json_string_value_basic() {
        let json = r#"{"ts_nonce":"test_nonce_123"}"#;
        assert_eq!(extract_json_string_value(json, "ts_nonce"), Some("test_nonce_123"));
    }

    #[test]
    fn extract_json_string_value_missing() {
        let json = r#"{"other":"value"}"#;
        assert_eq!(extract_json_string_value(json, "ts_nonce"), None);
    }

    #[test]
    fn extract_json_integer_value_zero() {
        let json = r#"{"authentication_result":0}"#;
        assert_eq!(extract_json_integer_value(json, "authentication_result"), Some(0));
    }

    #[test]
    fn extract_json_integer_value_nonzero() {
        let json = r#"{"authentication_result":2147942405}"#;
        assert_eq!(extract_json_integer_value(json, "authentication_result"), Some(2147942405));
    }

    #[test]
    fn build_auth_request_json_format() {
        let jws = "header.payload.signature";
        let json = build_auth_request_json(jws);
        assert_eq!(json, r#"{"rdp_assertion":"header.payload.signature"}"#);
    }

    #[test]
    fn jwk_json_structure() {
        let n = &[0x01, 0x02, 0x03];
        let e = &[0x01, 0x00, 0x01]; // 65537
        let jwk = build_jwk_json(n, e);
        // Should contain all required fields in lexicographic order (e, kty, n)
        assert!(jwk.starts_with(r#"{"e":"#));
        assert!(jwk.contains(r#""kty":"RSA""#));
        assert!(jwk.contains(r#""n":"#));
    }

    #[test]
    fn jwk_thumbprint_deterministic() {
        let n = &[0xAA; 32];
        let e = &[0x01, 0x00, 0x01];
        let t1 = compute_jwk_thumbprint(n, e);
        let t2 = compute_jwk_thumbprint(n, e);
        assert_eq!(t1, t2);
        assert!(!t1.is_empty());
    }

    #[test]
    fn rdp_assertion_has_three_segments() {
        use justrdp_core::bignum::BigUint;
        use justrdp_core::rsa::RsaPrivateKey;

        // Use the 512-bit test key from rsa.rs tests (large enough for PKCS#1 v1.5 + SHA-256)
        let n_bytes = [
            0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47,
            0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25, 0xA5, 0x8B,
            0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76,
            0x30, 0xBB, 0x58, 0xBD, 0xC3, 0x4D, 0xB1, 0xF0,
            0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36,
            0x79, 0x0D, 0xA2, 0x84, 0xB8, 0xE2, 0xE5, 0xB3,
            0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C,
            0xD7, 0xD6, 0x9A, 0x40, 0x67, 0x6A, 0xF1, 0xA7,
        ];
        let d_bytes = [
            0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC,
            0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA, 0xEF, 0xE8,
            0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E,
            0xEF, 0xAA, 0x69, 0x14, 0xF7, 0x21, 0x0E, 0x08,
            0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA,
            0x12, 0xB4, 0x76, 0xB8, 0x68, 0x84, 0x0D, 0x78,
            0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63,
            0x67, 0x9A, 0x43, 0x36, 0xDD, 0xAB, 0x3F, 0x69,
        ];
        let e_bytes = [0x01, 0x00, 0x01]; // 65537

        let config = AadConfig {
            access_token: String::from("test_token"),
            resource_uri: String::from("ms-device-service://test/user_impersonation"),
            aad_nonce: String::from("test_aad_nonce"),
            pop_key: RsaPrivateKey {
                n: BigUint::from_be_bytes(&n_bytes),
                d: BigUint::from_be_bytes(&d_bytes),
                e: BigUint::from_be_bytes(&e_bytes),
            },
            pop_key_n: n_bytes.to_vec(),
            pop_key_e: e_bytes.to_vec(),
            timestamp: 1711540800,
        };

        let assertion = build_rdp_assertion(&config, "server_nonce_123").unwrap();

        // JWS has exactly 3 dot-separated segments
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS must have 3 segments: header.payload.signature");

        // Each segment should be non-empty
        assert!(!parts[0].is_empty(), "header should not be empty");
        assert!(!parts[1].is_empty(), "payload should not be empty");
        assert!(!parts[2].is_empty(), "signature should not be empty");

        // Decode header and verify structure
        let header_bytes = base64url::decode(parts[0].as_bytes()).unwrap();
        let header_str = core::str::from_utf8(&header_bytes).unwrap();
        assert!(header_str.contains(r#""alg":"RS256""#));
        assert!(header_str.contains(r#""kid":"#));

        // Decode payload and verify fields
        let payload_bytes = base64url::decode(parts[1].as_bytes()).unwrap();
        let payload_str = core::str::from_utf8(&payload_bytes).unwrap();
        assert!(payload_str.contains(r#""ts":"#));
        assert!(payload_str.contains(r#""at":"test_token""#));
        assert!(payload_str.contains(r#""nonce":"server_nonce_123""#));
        assert!(payload_str.contains(r#""cnf":"#));
        assert!(payload_str.contains(r#""client_claims":"#));
        assert!(payload_str.contains("aad_nonce"));
    }

    #[test]
    fn rdp_assertion_signature_verifies() {
        use justrdp_core::bignum::BigUint;
        use justrdp_core::rsa::{RsaPrivateKey, RsaPublicKey, rsa_verify_sha256};

        let n_bytes = [
            0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47,
            0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25, 0xA5, 0x8B,
            0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76,
            0x30, 0xBB, 0x58, 0xBD, 0xC3, 0x4D, 0xB1, 0xF0,
            0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36,
            0x79, 0x0D, 0xA2, 0x84, 0xB8, 0xE2, 0xE5, 0xB3,
            0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C,
            0xD7, 0xD6, 0x9A, 0x40, 0x67, 0x6A, 0xF1, 0xA7,
        ];
        let d_bytes = [
            0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC,
            0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA, 0xEF, 0xE8,
            0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E,
            0xEF, 0xAA, 0x69, 0x14, 0xF7, 0x21, 0x0E, 0x08,
            0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA,
            0x12, 0xB4, 0x76, 0xB8, 0x68, 0x84, 0x0D, 0x78,
            0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63,
            0x67, 0x9A, 0x43, 0x36, 0xDD, 0xAB, 0x3F, 0x69,
        ];
        let e_bytes = [0x01, 0x00, 0x01];

        let config = AadConfig {
            access_token: String::from("token"),
            resource_uri: String::from("uri"),
            aad_nonce: String::from("nonce"),
            pop_key: RsaPrivateKey {
                n: BigUint::from_be_bytes(&n_bytes),
                d: BigUint::from_be_bytes(&d_bytes),
                e: BigUint::from_be_bytes(&e_bytes),
            },
            pop_key_n: n_bytes.to_vec(),
            pop_key_e: e_bytes.to_vec(),
            timestamp: 1000000,
        };

        let assertion = build_rdp_assertion(&config, "server_nonce").unwrap();
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Verify signature: decode signature, reconstruct signing input, verify
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = base64url::decode(parts[2].as_bytes()).unwrap();

        let pub_key = RsaPublicKey {
            n: BigUint::from_be_bytes(&n_bytes),
            e: BigUint::from_be_bytes(&e_bytes),
        };
        assert!(
            rsa_verify_sha256(&pub_key, signing_input.as_bytes(), &signature),
            "JWS signature verification failed — possible double-hash bug"
        );
    }

    #[test]
    fn client_claims_is_escaped_json_string() {
        use justrdp_core::bignum::BigUint;
        use justrdp_core::rsa::RsaPrivateKey;

        let n_bytes = [
            0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47,
            0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25, 0xA5, 0x8B,
            0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76,
            0x30, 0xBB, 0x58, 0xBD, 0xC3, 0x4D, 0xB1, 0xF0,
            0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36,
            0x79, 0x0D, 0xA2, 0x84, 0xB8, 0xE2, 0xE5, 0xB3,
            0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C,
            0xD7, 0xD6, 0x9A, 0x40, 0x67, 0x6A, 0xF1, 0xA7,
        ];
        let d_bytes = [
            0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC,
            0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA, 0xEF, 0xE8,
            0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E,
            0xEF, 0xAA, 0x69, 0x14, 0xF7, 0x21, 0x0E, 0x08,
            0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA,
            0x12, 0xB4, 0x76, 0xB8, 0x68, 0x84, 0x0D, 0x78,
            0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63,
            0x67, 0x9A, 0x43, 0x36, 0xDD, 0xAB, 0x3F, 0x69,
        ];
        let e_bytes = [0x01, 0x00, 0x01];

        let config = AadConfig {
            access_token: String::from("tok"),
            resource_uri: String::from("uri"),
            aad_nonce: String::from("test_nonce"),
            pop_key: RsaPrivateKey {
                n: BigUint::from_be_bytes(&n_bytes),
                d: BigUint::from_be_bytes(&d_bytes),
                e: BigUint::from_be_bytes(&e_bytes),
            },
            pop_key_n: n_bytes.to_vec(),
            pop_key_e: e_bytes.to_vec(),
            timestamp: 1000000,
        };

        let assertion = build_rdp_assertion(&config, "snonce").unwrap();
        let parts: Vec<&str> = assertion.split('.').collect();
        let payload_bytes = base64url::decode(parts[1].as_bytes()).unwrap();
        let payload_str = core::str::from_utf8(&payload_bytes).unwrap();

        // client_claims must be a properly escaped JSON string value
        // The payload should contain: "client_claims":"{\"aad_nonce\":\"test_nonce\"}"
        assert!(
            payload_str.contains(r#""client_claims":"{\"aad_nonce\":\"test_nonce\"}"#),
            "client_claims not properly escaped in payload: {}",
            payload_str,
        );
    }

    #[test]
    fn json_escape_special_chars() {
        assert_eq!(json_escape(r#"hello"world"#), r#"hello\"world"#);
        assert_eq!(json_escape(r"back\slash"), r"back\\slash");
        assert_eq!(json_escape("normal"), "normal");
    }
}
