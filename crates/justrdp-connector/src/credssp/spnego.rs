#![forbid(unsafe_code)]

//! Simplified SPNEGO wrapping for NTLM tokens (MS-SPNG).
//!
//! Only handles the NTLM OID (1.3.6.1.4.1.311.2.2.10) as mechanism.

use alloc::vec;
use alloc::vec::Vec;

/// OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
const NTLMSSP_OID: &[u8] = &[0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];

/// OID for SPNEGO: 1.3.6.1.5.5.2
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];

/// Wrap an NTLM Negotiate token in SPNEGO NegTokenInit.
///
/// Structure:
/// ```text
/// APPLICATION [0] {
///   OID 1.3.6.1.5.5.2 (SPNEGO),
///   [0] NegTokenInit SEQUENCE {
///     [0] mechTypes SEQUENCE OF OID { NTLMSSP },
///     [2] mechToken OCTET STRING { ntlm_negotiate }
///   }
/// }
/// ```
pub fn wrap_negotiate(ntlm_token: &[u8]) -> Vec<u8> {
    // mechTypes: SEQUENCE { OID NTLMSSP }
    let mech_types = der_sequence(NTLMSSP_OID);
    let mech_types_tagged = der_context_tag(0, &mech_types);

    // mechToken: OCTET STRING
    let mech_token = der_octet_string(ntlm_token);
    let mech_token_tagged = der_context_tag(2, &mech_token);

    // NegTokenInit SEQUENCE
    let mut neg_token_init_body = Vec::new();
    neg_token_init_body.extend_from_slice(&mech_types_tagged);
    neg_token_init_body.extend_from_slice(&mech_token_tagged);
    let neg_token_init = der_sequence(&neg_token_init_body);

    // [0] EXPLICIT tag for NegTokenInit
    let neg_token_init_explicit = der_context_tag(0, &neg_token_init);

    // APPLICATION [0] { SPNEGO OID, NegTokenInit }
    let mut app_body = Vec::new();
    app_body.extend_from_slice(SPNEGO_OID);
    app_body.extend_from_slice(&neg_token_init_explicit);

    let mut result = vec![0x60]; // APPLICATION [0] CONSTRUCTED
    result.extend(der_length(app_body.len()));
    result.extend(app_body);
    result
}

/// Wrap an NTLM Authenticate token in SPNEGO NegTokenResp.
///
/// Structure:
/// ```text
/// [1] NegTokenResp SEQUENCE {
///   [2] responseToken OCTET STRING { ntlm_authenticate }
/// }
/// ```
pub fn wrap_authenticate(ntlm_token: &[u8]) -> Vec<u8> {
    let response_token = der_octet_string(ntlm_token);
    let response_token_tagged = der_context_tag(2, &response_token);
    let neg_token_resp = der_sequence(&response_token_tagged);
    der_context_tag(1, &neg_token_resp)
}

/// Extract the NTLM token from a SPNEGO NegTokenResp (Challenge from server).
///
/// Expected structure:
/// ```text
/// [1] NegTokenResp SEQUENCE {
///   [0] negState ENUMERATED (optional),
///   [1] supportedMech OID (optional),
///   [2] responseToken OCTET STRING { ntlm_challenge },
///   ...
/// }
/// ```
pub fn unwrap_challenge(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut pos = 0;

    // [1] context tag
    let (tag, end) = der_read_tag_len(data, &mut pos).ok_or("invalid outer tag")?;
    if tag & 0x1F != 1 {
        return Err("expected NegTokenResp [1] tag");
    }

    // SEQUENCE
    let (_, seq_end) = der_read_tag_len(data, &mut pos).ok_or("invalid SEQUENCE")?;

    while pos < seq_end && pos < end {
        let field_tag = *data.get(pos).ok_or("unexpected end")?;
        let (_, field_end) = der_read_tag_len(data, &mut pos).ok_or("invalid field")?;

        let context_id = field_tag & 0x1F;

        if context_id == 2 {
            // [2] responseToken OCTET STRING
            let (inner_tag, inner_end) = der_read_tag_len(data, &mut pos).ok_or("invalid OCTET STRING")?;
            if inner_tag != 0x04 {
                return Err("expected OCTET STRING for responseToken");
            }
            let len = inner_end - pos;
            let token = data[pos..pos + len].to_vec();
            return Ok(token);
        }

        pos = field_end;
    }

    Err("responseToken not found in NegTokenResp")
}

// ── DER helpers ──

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut r = vec![0x30];
    r.extend(der_length(content.len()));
    r.extend_from_slice(content);
    r
}

fn der_context_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut r = vec![0xA0 | tag];
    r.extend(der_length(content.len()));
    r.extend_from_slice(content);
    r
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut r = vec![0x04];
    r.extend(der_length(data.len()));
    r.extend_from_slice(data);
    r
}

fn der_read_tag_len(data: &[u8], pos: &mut usize) -> Option<(u8, usize)> {
    if *pos >= data.len() {
        return None;
    }
    let tag = data[*pos];
    *pos += 1;

    if *pos >= data.len() {
        return None;
    }
    let first = data[*pos];
    *pos += 1;

    let length = if first < 0x80 {
        first as usize
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || *pos + num_bytes > data.len() {
            return None;
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | data[*pos + i] as usize;
        }
        *pos += num_bytes;
        length
    };

    Some((tag, *pos + length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_negotiate_produces_valid_spnego() {
        let ntlm_negotiate = b"NTLMSSP\0\x01\x00\x00\x00test";
        let spnego = wrap_negotiate(ntlm_negotiate);

        // Should start with APPLICATION [0] CONSTRUCTED tag (0x60)
        assert_eq!(spnego[0], 0x60);

        // Should contain SPNEGO OID somewhere
        let contains_spnego = spnego.windows(SPNEGO_OID.len()).any(|w| w == SPNEGO_OID);
        assert!(contains_spnego, "SPNEGO OID not found");

        // Should contain NTLMSSP OID
        let contains_ntlm = spnego.windows(NTLMSSP_OID.len()).any(|w| w == NTLMSSP_OID);
        assert!(contains_ntlm, "NTLMSSP OID not found");
    }

    #[test]
    fn wrap_authenticate_produces_neg_token_resp() {
        let token = b"test_auth_token";
        let resp = wrap_authenticate(token);

        // Should start with [1] context tag
        assert_eq!(resp[0] & 0xE0, 0xA0); // Context-specific
        assert_eq!(resp[0] & 0x1F, 1);     // Tag number 1
    }

    #[test]
    fn unwrap_challenge_roundtrip() {
        // Build a NegTokenResp with [2] responseToken
        let challenge = b"test_challenge_data";
        let octet = der_octet_string(challenge);
        let tagged = der_context_tag(2, &octet);
        let seq = der_sequence(&tagged);
        let resp = der_context_tag(1, &seq);

        let extracted = unwrap_challenge(&resp).unwrap();
        assert_eq!(extracted, challenge);
    }
}
