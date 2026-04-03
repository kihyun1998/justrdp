#![forbid(unsafe_code)]

//! KDC Proxy message encoding/decoding (MS-KKDCP).
//!
//! Wraps Kerberos messages for transport over HTTPS via a KDC Proxy.
//! The caller is responsible for HTTP POST to the proxy URL with
//! `Content-Type: application/kdc-proxy-message`.
//!
//! ```text
//! KDC-PROXY-MESSAGE ::= SEQUENCE {
//!     kerb-message   [0] OCTET STRING,
//!     target-domain  [1] KERB-REALM OPTIONAL,
//!     dclocator-hint [2] INTEGER OPTIONAL
//! }
//! ```

use alloc::vec::Vec;

use super::asn1::*;
use justrdp_core::DecodeResult;

/// KDC Proxy message (MS-KKDCP).
#[derive(Debug, Clone)]
pub struct KdcProxyMessage {
    /// Raw Kerberos message (AS-REQ, TGS-REQ, etc.) without TCP length prefix.
    pub kerb_message: Vec<u8>,
    /// Target Kerberos realm (e.g., "EXAMPLE.COM").
    pub target_domain: Option<Vec<u8>>,
    /// DC locator hint flags (typically omitted).
    pub dclocator_hint: Option<i64>,
}

impl KdcProxyMessage {
    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            // [0] kerb-message OCTET STRING
            let t0 = build_context_tag(0, |w| w.write_octet_string(&self.kerb_message));
            w.write_raw(&t0);

            // [1] target-domain OPTIONAL (GeneralString / Realm)
            if let Some(ref domain) = self.target_domain {
                let t1 = build_context_tag(1, |w| w.write_general_string(domain));
                w.write_raw(&t1);
            }

            // [2] dclocator-hint INTEGER OPTIONAL
            if let Some(hint) = self.dclocator_hint {
                let t2 = build_context_tag(2, |w| w.write_integer(hint));
                w.write_raw(&t2);
            }
        })
    }

    /// Decode from DER.
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut seq = r.read_sequence()?;

        // [0] kerb-message
        let mut t0 = seq.read_context_tag(0)?;
        let kerb_message = t0.read_octet_string()?.to_vec();

        // [1] target-domain OPTIONAL
        let target_domain = if let Some(mut t1) = seq.read_optional_context_tag(1)? {
            Some(t1.read_general_string()?.to_vec())
        } else {
            None
        };

        // [2] dclocator-hint OPTIONAL
        let dclocator_hint = if let Some(mut t2) = seq.read_optional_context_tag(2)? {
            Some(t2.read_integer()?)
        } else {
            None
        };

        Ok(Self {
            kerb_message,
            target_domain,
            dclocator_hint,
        })
    }
}

/// Wrap a raw Kerberos message for KDC Proxy transport.
///
/// The returned bytes should be HTTP POSTed to the KDC Proxy URL with
/// `Content-Type: application/kdc-proxy-message`.
pub fn wrap_for_proxy(kerb_message: &[u8], realm: &[u8]) -> Vec<u8> {
    let msg = KdcProxyMessage {
        kerb_message: kerb_message.to_vec(),
        target_domain: Some(realm.to_vec()),
        dclocator_hint: None,
    };
    msg.encode()
}

/// Unwrap a KDC Proxy response to extract the raw Kerberos message.
pub fn unwrap_from_proxy(proxy_message: &[u8]) -> DecodeResult<Vec<u8>> {
    let msg = KdcProxyMessage::decode(proxy_message)?;
    Ok(msg.kerb_message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip_full() {
        let msg = KdcProxyMessage {
            kerb_message: vec![0x6a, 0x03, 0x01, 0x02, 0x03], // fake AS-REQ
            target_domain: Some(b"EXAMPLE.COM".to_vec()),
            dclocator_hint: Some(0),
        };
        let encoded = msg.encode();
        let decoded = KdcProxyMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.kerb_message, msg.kerb_message);
        assert_eq!(decoded.target_domain, msg.target_domain);
        assert_eq!(decoded.dclocator_hint, Some(0));
    }

    #[test]
    fn roundtrip_minimal() {
        let msg = KdcProxyMessage {
            kerb_message: vec![0x6c, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            target_domain: None,
            dclocator_hint: None,
        };
        let encoded = msg.encode();
        let decoded = KdcProxyMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.kerb_message, msg.kerb_message);
        assert_eq!(decoded.target_domain, None);
        assert_eq!(decoded.dclocator_hint, None);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kerb_msg = vec![0x6a, 0x10, 0x01, 0x02, 0x03];
        let realm = b"CORP.LOCAL";

        let wrapped = wrap_for_proxy(&kerb_msg, realm);
        let unwrapped = unwrap_from_proxy(&wrapped).unwrap();
        assert_eq!(unwrapped, kerb_msg);
    }
}
