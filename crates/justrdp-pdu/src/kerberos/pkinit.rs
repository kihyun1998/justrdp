#![forbid(unsafe_code)]

//! PKINIT (RFC 4556) ASN.1 structures for certificate-based Kerberos authentication.
//!
//! Implements the client-side structures needed for PKINIT in the RDP CredSSP flow:
//! - PA-PK-AS-REQ (client → KDC, contains signed AuthPack)
//! - PA-PK-AS-REP (KDC → client, contains KDC's DH public value)

use alloc::vec::Vec;

use super::asn1::*;
use justrdp_core::DecodeResult;

/// PA-PK-AS-REQ ::= SEQUENCE {
///     signedAuthPack [0] IMPLICIT OCTET STRING  -- CMS SignedData(AuthPack)
/// }
#[derive(Debug, Clone)]
pub struct PaPkAsReq {
    /// CMS SignedData containing the signed AuthPack.
    pub signed_auth_pack: Vec<u8>,
}

impl PaPkAsReq {
    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            // [0] IMPLICIT OCTET STRING
            let t0 = build_context_tag(0, |w| w.write_octet_string(&self.signed_auth_pack));
            w.write_raw(&t0);
        })
    }
}

/// PKAuthenticator ::= SEQUENCE {
///     cusec      [0] INTEGER,
///     ctime      [1] KerberosTime,
///     nonce      [2] INTEGER,
///     paChecksum [3] OCTET STRING OPTIONAL  -- SHA-1 of KDC-REQ-BODY
/// }
#[derive(Debug, Clone)]
pub struct PkAuthenticator {
    pub cusec: u32,
    pub ctime: Vec<u8>,
    pub nonce: u32,
    pub pa_checksum: Option<Vec<u8>>,
}

impl PkAuthenticator {
    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            // [0] cusec
            let t0 = build_context_tag(0, |w| w.write_integer(self.cusec as i64));
            w.write_raw(&t0);

            // [1] ctime (GeneralizedTime)
            let t1 = build_context_tag(1, |w| w.write_generalized_time(&self.ctime));
            w.write_raw(&t1);

            // [2] nonce
            let t2 = build_context_tag(2, |w| w.write_integer(self.nonce as i64));
            w.write_raw(&t2);

            // [3] paChecksum OPTIONAL
            if let Some(ref cksum) = self.pa_checksum {
                let t3 = build_context_tag(3, |w| w.write_octet_string(cksum));
                w.write_raw(&t3);
            }
        })
    }
}

/// AuthPack ::= SEQUENCE {
///     pkAuthenticator         [0] PKAuthenticator,
///     clientPublicValue       [1] SubjectPublicKeyInfo OPTIONAL,
///     supportedCMSTypes       [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
///     clientDHNonce           [3] DHNonce OPTIONAL
/// }
///
/// RFC 4556 §3.2.1. JustRDP does not advertise preferred CMS
/// algorithm identifiers, so `supportedCMSTypes` at `[2]` is always
/// omitted. `clientDHNonce` lives at `[3]` per the spec even when
/// `[2]` is absent — an earlier revision of this code mis-tagged it
/// as `[2]`, which would cause Windows KDCs to decode the nonce as
/// `supportedCMSTypes` and fail. Fixed by adding a `[3]` tag.
#[derive(Debug, Clone)]
pub struct AuthPack {
    pub pk_authenticator: PkAuthenticator,
    /// DER-encoded SubjectPublicKeyInfo for DH.
    pub client_public_value: Option<Vec<u8>>,
    /// Client DH nonce for key derivation (RFC 4556 §3.2.3.1).
    pub client_dh_nonce: Option<Vec<u8>>,
}

impl AuthPack {
    /// Encode as DER.
    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            // [0] pkAuthenticator
            let auth_bytes = self.pk_authenticator.encode();
            let t0 = build_context_tag(0, |w| w.write_raw(&auth_bytes));
            w.write_raw(&t0);

            // [1] clientPublicValue OPTIONAL (raw SPKI bytes)
            if let Some(ref spki) = self.client_public_value {
                let t1 = build_context_tag(1, |w| w.write_raw(spki));
                w.write_raw(&t1);
            }

            // [2] supportedCMSTypes — not used, always absent.

            // [3] clientDHNonce OPTIONAL (RFC 4556 §3.2.1)
            if let Some(ref nonce) = self.client_dh_nonce {
                let t3 = build_context_tag(3, |w| w.write_octet_string(nonce));
                w.write_raw(&t3);
            }
        })
    }
}

/// Build a SubjectPublicKeyInfo for DH (dhpublicnumber).
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm AlgorithmIdentifier { dhpublicnumber, DomainParameters },
///     subjectPublicKey BIT STRING (INTEGER)
/// }
/// ```
pub fn build_dh_spki(p: &[u8], g: &[u8], public_value: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier: SEQUENCE { OID dhpublicnumber, DomainParameters }
    // DomainParameters ::= SEQUENCE { p INTEGER, g INTEGER, q INTEGER OPTIONAL }
    let domain_params = build_sequence(|w| {
        w.write_integer_bytes(p);
        w.write_integer_bytes(g);
    });

    let algo_id = build_sequence(|w| {
        w.write_oid(OID_DH_PUBLIC_NUMBER);
        w.write_raw(&domain_params);
    });

    // SubjectPublicKey: BIT STRING wrapping INTEGER
    let pub_key_int = {
        let mut w = DerWriter::new();
        w.write_integer_bytes(public_value);
        w.into_inner()
    };

    build_sequence(|w| {
        w.write_raw(&algo_id);
        w.write_bit_string(&pub_key_int);
    })
}

/// PA-PK-AS-REP ::= CHOICE {
///     dhInfo    [0] DHRepInfo,
///     encKeyPack [1] IMPLICIT OCTET STRING  -- CMS EnvelopedData (RSA, not supported)
/// }
///
/// DHRepInfo ::= SEQUENCE {
///     dhSignedData  [0] IMPLICIT OCTET STRING,  -- CMS SignedData(KDCDHKeyInfo)
///     serverDHNonce [1] OCTET STRING OPTIONAL
/// }
#[derive(Debug, Clone)]
pub struct DhRepInfo {
    /// CMS SignedData containing KDCDHKeyInfo.
    pub dh_signed_data: Vec<u8>,
    /// Server DH nonce (optional, used in key derivation).
    pub server_dh_nonce: Option<Vec<u8>>,
}

impl DhRepInfo {
    /// Decode from DER (expects [0] context tag wrapping DHRepInfo).
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);

        // PA-PK-AS-REP is a CHOICE; [0] = dhInfo
        let mut ctx = r.read_context_tag(0)?;
        let mut seq = ctx.read_sequence()?;

        // [0] IMPLICIT OCTET STRING (dhSignedData)
        let mut t0 = seq.read_context_tag(0)?;
        let dh_signed_data = t0.read_octet_string()?.to_vec();

        // [1] serverDHNonce OPTIONAL
        let server_dh_nonce = if let Some(mut t1) = seq.read_optional_context_tag(1)? {
            Some(t1.read_octet_string()?.to_vec())
        } else {
            None
        };

        Ok(Self {
            dh_signed_data,
            server_dh_nonce,
        })
    }
}

/// KDCDHKeyInfo ::= SEQUENCE {
///     subjectPublicKey  [0] BIT STRING,   -- KDC's DH public value
///     nonce             [1] INTEGER,
///     dhKeyExpiration   [2] KerberosTime OPTIONAL
/// }
#[derive(Debug, Clone)]
pub struct KdcDhKeyInfo {
    /// KDC's DH public value (DER INTEGER inside BIT STRING).
    pub subject_public_key: Vec<u8>,
    /// Nonce (must match the one in AuthPack).
    pub nonce: i64,
}

impl KdcDhKeyInfo {
    /// Decode from DER.
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut seq = r.read_sequence()?;

        // [0] subjectPublicKey BIT STRING
        let mut t0 = seq.read_context_tag(0)?;
        let subject_public_key = t0.read_bit_string()?.to_vec();

        // [1] nonce INTEGER
        let mut t1 = seq.read_context_tag(1)?;
        let nonce = t1.read_integer()?;

        // [2] dhKeyExpiration OPTIONAL - skip if present

        Ok(Self {
            subject_public_key,
            nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn pk_authenticator_encode() {
        let auth = PkAuthenticator {
            cusec: 123456,
            ctime: b"20260326120000Z".to_vec(),
            nonce: 99999,
            pa_checksum: Some(vec![0xAA; 20]),
        };
        let encoded = auth.encode();
        assert_eq!(encoded[0], TAG_SEQUENCE);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn auth_pack_encode() {
        let pack = AuthPack {
            pk_authenticator: PkAuthenticator {
                cusec: 0,
                ctime: b"20260326120000Z".to_vec(),
                nonce: 42,
                pa_checksum: None,
            },
            client_public_value: Some(vec![0x30, 0x03, 0x01, 0x02, 0x03]),
            client_dh_nonce: None,
        };
        let encoded = pack.encode();
        assert_eq!(encoded[0], TAG_SEQUENCE);
    }

    #[test]
    fn pa_pk_as_req_encode() {
        let req = PaPkAsReq {
            signed_auth_pack: vec![0x30, 0x10, 0xAA, 0xBB],
        };
        let encoded = req.encode();
        assert_eq!(encoded[0], TAG_SEQUENCE);
    }

    #[test]
    fn dh_spki_encode() {
        let p = vec![0x00, 0xFF]; // small prime for testing
        let g = vec![0x02];
        let pub_val = vec![0x00, 0x42];
        let spki = build_dh_spki(&p, &g, &pub_val);
        assert_eq!(spki[0], TAG_SEQUENCE);
    }

    #[test]
    fn kdc_dh_key_info_roundtrip() {
        // Build a KDCDHKeyInfo manually
        let encoded = build_sequence(|w| {
            // [0] BIT STRING
            let t0 = build_context_tag(0, |w| w.write_bit_string(&[0x02, 0x01, 0x05]));
            w.write_raw(&t0);

            // [1] INTEGER
            let t1 = build_context_tag(1, |w| w.write_integer(42));
            w.write_raw(&t1);
        });

        let info = KdcDhKeyInfo::decode(&encoded).unwrap();
        assert_eq!(info.nonce, 42);
        assert_eq!(info.subject_public_key, vec![0x02, 0x01, 0x05]);
    }
}
