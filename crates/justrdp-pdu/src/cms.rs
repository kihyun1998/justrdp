#![forbid(unsafe_code)]

//! Minimal CMS (RFC 5652) SignedData for PKINIT.
//!
//! Implements just enough CMS to:
//! - Encode a SignedData wrapping an AuthPack (client → KDC)
//! - Decode a SignedData wrapping KDCDHKeyInfo (KDC → client)
//!
//! This is NOT a general-purpose CMS implementation.

use alloc::vec;
use alloc::vec::Vec;

use crate::kerberos::asn1::*;
use justrdp_core::DecodeResult;

/// Build a CMS ContentInfo { contentType: signedData, content: SignedData }.
///
/// ```text
/// ContentInfo ::= SEQUENCE {
///     contentType  ContentType (= id-signedData),
///     content      [0] EXPLICIT ANY DEFINED BY contentType
/// }
/// ```
pub fn build_content_info_signed_data(signed_data: &[u8]) -> Vec<u8> {
    build_sequence(|w| {
        w.write_oid(OID_CMS_SIGNED_DATA);
        let t0 = build_context_tag(0, |w| w.write_raw(signed_data));
        w.write_raw(&t0);
    })
}

/// Build a CMS SignedData structure.
///
/// ```text
/// SignedData ::= SEQUENCE {
///     version          INTEGER (3 for PKINIT),
///     digestAlgorithms SET OF AlgorithmIdentifier,
///     encapContentInfo EncapsulatedContentInfo,
///     certificates     [0] IMPLICIT SET OF Certificate OPTIONAL,
///     signerInfos      SET OF SignerInfo
/// }
/// ```
///
/// # Arguments
/// * `content_type` - OID for the encapsulated content (e.g., id-pkinit-authData)
/// * `content` - DER-encoded content (e.g., AuthPack)
/// * `certificates` - Client certificate(s) in DER format
/// * `signer_info` - Pre-built SignerInfo DER
pub fn build_signed_data(
    content_type: &[u8],
    content: &[u8],
    certificates: &[&[u8]],
    signer_info: &[u8],
) -> Vec<u8> {
    build_sequence(|w| {
        // version INTEGER (3 for PKINIT)
        w.write_integer(3);

        // digestAlgorithms SET OF AlgorithmIdentifier
        let digest_algos = build_set(|w| {
            let algo = build_sequence(|w| {
                w.write_oid(OID_SHA256);
                w.write_null();
            });
            w.write_raw(&algo);
        });
        w.write_raw(&digest_algos);

        // encapContentInfo EncapsulatedContentInfo
        let encap = build_sequence(|w| {
            w.write_oid(content_type);
            // [0] EXPLICIT content
            let t0 = build_context_tag(0, |w| w.write_octet_string(content));
            w.write_raw(&t0);
        });
        w.write_raw(&encap);

        // [0] IMPLICIT certificates (SET OF Certificate)
        if !certificates.is_empty() {
            let mut certs_content = Vec::new();
            for cert in certificates {
                certs_content.extend_from_slice(cert);
            }
            // [0] IMPLICIT = context tag 0, constructed
            let certs_tag = build_implicit_context_tag(0, &certs_content);
            w.write_raw(&certs_tag);
        }

        // signerInfos SET OF SignerInfo
        let signer_infos = build_set(|w| {
            w.write_raw(signer_info);
        });
        w.write_raw(&signer_infos);
    })
}

/// Build a CMS SignerInfo structure.
///
/// ```text
/// SignerInfo ::= SEQUENCE {
///     version                INTEGER (1 for issuerAndSerialNumber),
///     sid                    SignerIdentifier (IssuerAndSerialNumber),
///     digestAlgorithm        DigestAlgorithmIdentifier,
///     signedAttrs            [0] IMPLICIT SET OF Attribute OPTIONAL,
///     signatureAlgorithm     SignatureAlgorithmIdentifier,
///     signature              OCTET STRING,
///     unsignedAttrs          [1] IMPLICIT SET OF Attribute OPTIONAL
/// }
/// ```
///
/// `signed_attrs` must be the full `[0] IMPLICIT SET OF Attribute`
/// TLV bytes (tag `0xA0`) — typically produced by
/// [`build_signed_attrs_for_signer_info`]. RFC 4556 §3.2.1 requires
/// PKINIT SignerInfos to include `signedAttributes` with at minimum
/// `id-contentType` and `id-messageDigest`. Pass `None` only for
/// legacy test fixtures; real PKINIT exchanges must supply the
/// attributes.
pub fn build_signer_info(
    issuer_der: &[u8],
    serial_number_der: &[u8],
    signed_attrs: Option<&[u8]>,
    signature: &[u8],
) -> Vec<u8> {
    build_sequence(|w| {
        // version INTEGER (1)
        w.write_integer(1);

        // sid: IssuerAndSerialNumber ::= SEQUENCE { issuer, serialNumber }
        let sid = build_sequence(|w| {
            w.write_raw(issuer_der);   // issuer Name (already DER)
            w.write_raw(serial_number_der); // serialNumber INTEGER (already DER)
        });
        w.write_raw(&sid);

        // digestAlgorithm: SHA-256
        let digest_algo = build_sequence(|w| {
            w.write_oid(OID_SHA256);
            w.write_null();
        });
        w.write_raw(&digest_algo);

        // signedAttributes [0] IMPLICIT SET OF Attribute OPTIONAL
        if let Some(attrs) = signed_attrs {
            w.write_raw(attrs);
        }

        // signatureAlgorithm: SHA-256 with RSA
        let sig_algo = build_sequence(|w| {
            w.write_oid(OID_SHA256_WITH_RSA);
            w.write_null();
        });
        w.write_raw(&sig_algo);

        // signature OCTET STRING
        w.write_octet_string(signature);
    })
}

// ── Signed attributes (RFC 5652 §5.3 + RFC 4556 §3.2.1) ──

/// OID `id-contentType` (1.2.840.113549.1.9.3).
pub const OID_CONTENT_TYPE: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];

/// OID `id-messageDigest` (1.2.840.113549.1.9.4).
pub const OID_MESSAGE_DIGEST: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

/// Build the *inner* bytes of the `signedAttributes` SET — just the
/// two Attribute SEQUENCEs concatenated, without any outer SET tag.
/// Callers wrap the result twice:
///
/// * [`build_signed_attrs_for_signing`] prepends the SET tag
///   (`0x31`) so the result can be hashed and signed per RFC 5652
///   §5.4 ("separate encoding of the signedAttrs field is performed
///   for signature computation ... an EXPLICIT SET OF tag is used").
/// * [`build_signed_attrs_for_signer_info`] prepends the `[0]
///   IMPLICIT` context tag (`0xA0`) so the result can be embedded
///   in a `SignerInfo`.
///
/// The produced attributes are the two RFC 4556 §3.2.1 requires:
/// `id-contentType` carrying the eContent type OID, and
/// `id-messageDigest` carrying the SHA-256 digest of the eContent
/// octets.
///
/// DER canonical ordering of the SET OF is satisfied by the order
/// these two attributes are emitted in: the `contentType` SEQUENCE
/// starts with the same `0x30` tag as `messageDigest` but has a
/// smaller length (its value is a ~11-byte OID vs a 34-byte OCTET
/// STRING-wrapped 32-byte digest), so byte-wise comparison places
/// `contentType` first.
pub fn build_signed_attrs_inner(
    content_type_oid: &[u8],
    message_digest: &[u8],
) -> Vec<u8> {
    let attr_content_type = build_sequence(|w| {
        w.write_oid(OID_CONTENT_TYPE);
        let val_set = build_set(|w| {
            w.write_oid(content_type_oid);
        });
        w.write_raw(&val_set);
    });

    let attr_message_digest = build_sequence(|w| {
        w.write_oid(OID_MESSAGE_DIGEST);
        let val_set = build_set(|w| {
            w.write_octet_string(message_digest);
        });
        w.write_raw(&val_set);
    });

    let mut out = Vec::with_capacity(attr_content_type.len() + attr_message_digest.len());
    out.extend_from_slice(&attr_content_type);
    out.extend_from_slice(&attr_message_digest);
    out
}

/// Wrap [`build_signed_attrs_inner`] output with an explicit `SET`
/// tag (`0x31`) — the form that MUST be fed to the signing function
/// per RFC 5652 §5.4.
pub fn build_signed_attrs_for_signing(inner: &[u8]) -> Vec<u8> {
    build_set(|w| w.write_raw(inner))
}

/// Wrap [`build_signed_attrs_inner`] output with the `[0] IMPLICIT
/// SET` context tag (`0xA0`) — the form that goes inside a
/// `SignerInfo`'s `signedAttributes` field.
pub fn build_signed_attrs_for_signer_info(inner: &[u8]) -> Vec<u8> {
    build_implicit_context_tag(0, inner)
}

/// Decode a CMS ContentInfo to extract the SignedData content.
///
/// Returns the raw SignedData SEQUENCE bytes.
pub fn decode_content_info(data: &[u8]) -> DecodeResult<(Vec<u8>, Vec<u8>)> {
    let mut r = DerReader::new(data);
    let mut seq = r.read_sequence()?;

    // contentType OID
    let content_type = seq.read_oid()?.to_vec();

    // [0] EXPLICIT content — contains the full SignedData SEQUENCE
    let mut ctx = seq.read_context_tag(0)?;
    let content = ctx.read_remaining().to_vec();

    Ok((content_type, content))
}

/// Decode a CMS SignedData to extract the encapsulated content.
///
/// Returns (content_type_oid, content_bytes, certificates, signer_infos_raw).
pub fn decode_signed_data(data: &[u8]) -> DecodeResult<SignedDataParts> {
    let mut r = DerReader::new(data);
    let mut seq = r.read_sequence()?;

    // version
    let _version = seq.read_integer()?;

    // digestAlgorithms SET - skip
    let (_, _) = seq.read_tlv()?;

    // encapContentInfo SEQUENCE
    let mut encap_seq = seq.read_sequence()?;
    let content_type = encap_seq.read_oid()?.to_vec();

    // [0] EXPLICIT content OPTIONAL
    let content = if let Some(mut ctx) = encap_seq.read_optional_context_tag(0)? {
        Some(ctx.read_octet_string()?.to_vec())
    } else {
        None
    };

    // We don't parse certificates or signerInfos in detail for now.
    // The caller can verify the KDC's signature separately if needed.

    Ok(SignedDataParts {
        content_type,
        content,
    })
}

/// Parsed parts of a CMS SignedData.
#[derive(Debug, Clone)]
pub struct SignedDataParts {
    /// Content type OID (raw bytes).
    pub content_type: Vec<u8>,
    /// Encapsulated content (if present).
    pub content: Option<Vec<u8>>,
}

/// Extract issuer Name and serialNumber from a DER-encoded X.509 certificate.
///
/// Parses just enough of the TBSCertificate to extract:
/// - issuer (raw DER SEQUENCE)
/// - serialNumber (raw DER INTEGER, tag+length+value)
///
/// ```text
/// TBSCertificate ::= SEQUENCE {
///     version         [0] EXPLICIT INTEGER {v3(2)} OPTIONAL,
///     serialNumber    CertificateSerialNumber,
///     signature       AlgorithmIdentifier,
///     issuer          Name,
///     ...
/// }
/// ```
pub fn extract_cert_issuer_serial(cert_der: &[u8]) -> DecodeResult<(Vec<u8>, Vec<u8>)> {
    let mut r = DerReader::new(cert_der);
    // Outer Certificate SEQUENCE
    let mut cert_seq = r.read_sequence()?;
    // TBSCertificate SEQUENCE
    let mut tbs = cert_seq.read_sequence()?;

    // version [0] EXPLICIT INTEGER OPTIONAL
    // Skip if present (tag 0xA0)
    if let Some(_) = tbs.read_optional_context_tag(0)? {
        // version present, consumed
    }

    // serialNumber INTEGER
    let (serial_tag, serial_content) = tbs.read_tlv()?;
    let mut serial_der = vec![serial_tag];
    let len_bytes = encode_der_length(serial_content.len());
    serial_der.extend_from_slice(&len_bytes);
    serial_der.extend_from_slice(serial_content);

    // signature AlgorithmIdentifier - skip
    let (_, _) = tbs.read_tlv()?;

    // issuer Name (SEQUENCE)
    let (issuer_tag, issuer_content) = tbs.read_tlv()?;
    let mut issuer_der = vec![issuer_tag];
    let len_bytes = encode_der_length(issuer_content.len());
    issuer_der.extend_from_slice(&len_bytes);
    issuer_der.extend_from_slice(issuer_content);

    Ok((issuer_der, serial_der))
}

/// Encode a DER length field.
fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// Build a SET (tag 0x31).
fn build_set<F: FnOnce(&mut DerWriter)>(f: F) -> Vec<u8> {
    let mut w = DerWriter::new();
    f(&mut w);
    let content = w.into_inner();
    let mut result = vec![0x31]; // SET tag
    result.extend_from_slice(&encode_der_length(content.len()));
    result.extend_from_slice(&content);
    result
}

/// Build a context tag with IMPLICIT encoding (constructed, class context).
fn build_implicit_context_tag(tag_num: u8, content: &[u8]) -> Vec<u8> {
    let tag = 0xA0 | tag_num; // CONTEXT | CONSTRUCTED
    let mut result = vec![tag];
    result.extend_from_slice(&encode_der_length(content.len()));
    result.extend_from_slice(content);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn content_info_roundtrip() {
        let fake_signed_data = build_sequence(|w| {
            w.write_integer(3);
        });

        let content_info = build_content_info_signed_data(&fake_signed_data);

        let (oid, content) = decode_content_info(&content_info).unwrap();
        assert_eq!(oid, OID_CMS_SIGNED_DATA);
        assert_eq!(content, fake_signed_data);
    }

    #[test]
    fn signed_data_encode_decode() {
        let auth_pack_data = vec![0xAA, 0xBB, 0xCC];
        let fake_signature = vec![0x11; 32];
        let fake_issuer = build_sequence(|w| {
            w.write_raw(&[0x31, 0x00]); // empty SET (RDN)
        });
        let fake_serial = {
            let mut w = DerWriter::new();
            w.write_integer(12345);
            w.into_inner()
        };

        let signer_info =
            build_signer_info(&fake_issuer, &fake_serial, None, &fake_signature);

        let signed_data = build_signed_data(
            OID_PKINIT_AUTH_DATA,
            &auth_pack_data,
            &[],
            &signer_info,
        );

        let parts = decode_signed_data(&signed_data).unwrap();
        assert_eq!(parts.content_type, OID_PKINIT_AUTH_DATA);
        assert_eq!(parts.content, Some(auth_pack_data));
    }

    #[test]
    fn signer_info_builds_without_signed_attrs() {
        let issuer = vec![0x30, 0x00]; // empty SEQUENCE
        let serial = vec![0x02, 0x01, 0x01]; // INTEGER 1
        let sig = vec![0x42; 64];

        let si = build_signer_info(&issuer, &serial, None, &sig);
        assert_eq!(si[0], TAG_SEQUENCE);
    }

    #[test]
    fn signer_info_builds_with_signed_attrs() {
        let issuer = vec![0x30, 0x00];
        let serial = vec![0x02, 0x01, 0x01];
        let sig = vec![0x42; 64];

        // Build a realistic signedAttrs structure over a 32-byte
        // SHA-256 digest and an arbitrary eContent type OID.
        let inner = build_signed_attrs_inner(OID_PKINIT_AUTH_DATA, &[0x11u8; 32]);
        let attrs_in_si = build_signed_attrs_for_signer_info(&inner);

        let si = build_signer_info(&issuer, &serial, Some(&attrs_in_si), &sig);

        // The SignerInfo must now contain the 0xA0 IMPLICIT [0] SET
        // OF Attribute tag somewhere — the inner bytes start with
        // 0xA0 and we asserted earlier that this is the wrapper.
        assert_eq!(si[0], TAG_SEQUENCE);
        assert!(
            si.windows(inner.len()).any(|w| w == inner.as_slice()),
            "signedAttrs inner bytes must be embedded in the SignerInfo",
        );

        // And the for-signing form (tag 0x31) and the for-signer-info
        // form (tag 0xA0) must differ only in their leading tag byte.
        let for_signing = build_signed_attrs_for_signing(&inner);
        assert_eq!(attrs_in_si[0], 0xA0);
        assert_eq!(for_signing[0], 0x31);
        assert_eq!(&attrs_in_si[1..], &for_signing[1..]);
    }
}
