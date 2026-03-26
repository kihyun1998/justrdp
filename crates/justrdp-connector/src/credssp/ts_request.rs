#![forbid(unsafe_code)]

//! TsRequest PDU encoding/decoding (MS-CSSP 2.2.1).
//!
//! TsRequest is encoded in ASN.1 DER format. We implement minimal DER
//! encoding/decoding specific to the CredSSP protocol.

use alloc::vec;
use alloc::vec::Vec;

/// Maximum CredSSP version supported by this client.
/// Sent in the initial TsRequest; the negotiated version is min(client, server).
pub const TS_REQUEST_MAX_VERSION: u32 = 6;

/// TsRequest PDU.
#[derive(Debug, Clone)]
pub struct TsRequest {
    pub version: u32,
    pub nego_tokens: Option<Vec<u8>>,
    pub auth_info: Option<Vec<u8>>,
    pub pub_key_auth: Option<Vec<u8>>,
    pub error_code: Option<u32>,
    pub client_nonce: Option<[u8; 32]>,
}

impl TsRequest {
    pub fn new() -> Self {
        Self {
            version: TS_REQUEST_MAX_VERSION,
            nego_tokens: None,
            auth_info: None,
            pub_key_auth: None,
            error_code: None,
            client_nonce: None,
        }
    }

    /// Encode TsRequest to DER bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = Vec::new();

        // [0] version INTEGER
        let version_inner = der_encode_integer(self.version);
        fields.extend(der_encode_context_tag(0, &version_inner));

        // [1] negoTokens SEQUENCE OF SEQUENCE { negoToken OCTET STRING }
        if let Some(ref tokens) = self.nego_tokens {
            let octet = der_encode_octet_string(tokens);
            let inner_seq_body = der_encode_context_tag(0, &octet);
            let inner_seq = der_encode_sequence(&inner_seq_body);
            let outer_seq = der_encode_sequence(&inner_seq);
            fields.extend(der_encode_context_tag(1, &outer_seq));
        }

        // [2] authInfo OCTET STRING
        if let Some(ref info) = self.auth_info {
            let octet = der_encode_octet_string(info);
            fields.extend(der_encode_context_tag(2, &octet));
        }

        // [3] pubKeyAuth OCTET STRING
        if let Some(ref auth) = self.pub_key_auth {
            let octet = der_encode_octet_string(auth);
            fields.extend(der_encode_context_tag(3, &octet));
        }

        // [4] errorCode INTEGER (v3+)
        if let Some(code) = self.error_code {
            let int = der_encode_integer(code);
            fields.extend(der_encode_context_tag(4, &int));
        }

        // [5] clientNonce OCTET STRING (v5+)
        if let Some(ref nonce) = self.client_nonce {
            let octet = der_encode_octet_string(nonce);
            fields.extend(der_encode_context_tag(5, &octet));
        }

        der_encode_sequence(&fields)
    }

    /// Decode TsRequest from DER bytes.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        let mut pos = 0;
        let (_, seq_end) = der_read_tag_length(data, &mut pos).ok_or("invalid outer SEQUENCE")?;

        let mut ts_request = TsRequest::new();

        while pos < seq_end && pos < data.len() {
            // Each field is a context-specific tag [N]
            let tag = *data.get(pos).ok_or("unexpected end")?;
            let (_, field_end) = der_read_tag_length(data, &mut pos).ok_or("invalid field TLV")?;

            let context_tag = tag & 0x1F;

            match context_tag {
                0 => {
                    // version INTEGER
                    ts_request.version = der_read_integer(data, &mut pos)?;
                }
                1 => {
                    // negoTokens: SEQUENCE OF SEQUENCE { [0] negoToken OCTET STRING }
                    // Skip outer SEQUENCE tag
                    let (_, _) = der_read_tag_length(data, &mut pos).ok_or("invalid negoTokens SEQUENCE")?;
                    // Skip inner SEQUENCE tag
                    let (_, _) = der_read_tag_length(data, &mut pos).ok_or("invalid inner SEQUENCE")?;
                    // Read [0] context tag
                    let (_, _) = der_read_tag_length(data, &mut pos).ok_or("invalid [0] tag")?;
                    // Read OCTET STRING
                    let octet = der_read_octet_string(data, &mut pos)?;
                    ts_request.nego_tokens = Some(octet);
                }
                2 => {
                    // authInfo OCTET STRING
                    let octet = der_read_octet_string(data, &mut pos)?;
                    ts_request.auth_info = Some(octet);
                }
                3 => {
                    // pubKeyAuth OCTET STRING
                    let octet = der_read_octet_string(data, &mut pos)?;
                    ts_request.pub_key_auth = Some(octet);
                }
                4 => {
                    // errorCode INTEGER
                    ts_request.error_code = Some(der_read_integer(data, &mut pos)?);
                }
                5 => {
                    // clientNonce OCTET STRING (must be exactly 32 bytes)
                    let octet = der_read_octet_string(data, &mut pos)?;
                    if octet.len() != 32 {
                        return Err("clientNonce must be exactly 32 bytes");
                    }
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&octet);
                    ts_request.client_nonce = Some(nonce);
                }
                _ => {
                    // Unknown field — skip
                    pos = field_end;
                }
            }

            // Ensure we don't go past the field end
            if pos < field_end {
                pos = field_end;
            }
        }

        Ok(ts_request)
    }
}

// ── DER encoding helpers ──

fn der_encode_length(len: usize) -> Vec<u8> {
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

fn der_encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut result = vec![0x30]; // SEQUENCE tag
    result.extend(der_encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

fn der_encode_context_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![0xA0 | tag]; // Context-specific constructed
    result.extend(der_encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

fn der_encode_integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    // Find first non-zero byte (or last byte if value is 0)
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let significant = &bytes[start..];

    let mut result = vec![0x02]; // INTEGER tag
    // Add leading zero if MSB is set (to avoid being interpreted as negative)
    if significant[0] & 0x80 != 0 {
        result.extend(der_encode_length(significant.len() + 1));
        result.push(0x00);
    } else {
        result.extend(der_encode_length(significant.len()));
    }
    result.extend_from_slice(significant);
    result
}

fn der_encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING tag
    result.extend(der_encode_length(data.len()));
    result.extend_from_slice(data);
    result
}

// ── DER decoding helpers ──

fn der_read_tag_length(data: &[u8], pos: &mut usize) -> Option<(u8, usize)> {
    if *pos >= data.len() {
        return None;
    }
    let tag = data[*pos];
    *pos += 1;

    let length = der_read_length(data, pos)?;
    let end = *pos + length;
    Some((tag, end))
}

fn der_read_length(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= data.len() {
        return None;
    }

    let first = data[*pos];
    *pos += 1;

    if first < 0x80 {
        Some(first as usize)
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
        Some(length)
    }
}

fn der_read_integer(data: &[u8], pos: &mut usize) -> Result<u32, &'static str> {
    let (tag, end) = der_read_tag_length(data, pos).ok_or("invalid INTEGER TLV")?;
    if tag != 0x02 {
        return Err("expected INTEGER tag");
    }
    let len = end - *pos;
    if len > 5 {
        return Err("INTEGER too large");
    }
    let mut value: u32 = 0;
    for i in 0..len {
        let byte = *data.get(*pos + i).ok_or("INTEGER truncated")?;
        if i == 0 && byte == 0 && len > 1 {
            // Leading zero for positive numbers — skip
            continue;
        }
        value = (value << 8) | byte as u32;
    }
    *pos = end;
    Ok(value)
}

fn der_read_octet_string(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, &'static str> {
    let (tag, end) = der_read_tag_length(data, pos).ok_or("invalid OCTET STRING TLV")?;
    if tag != 0x04 {
        return Err("expected OCTET STRING tag");
    }
    let len = end - *pos;
    if *pos + len > data.len() {
        return Err("OCTET STRING truncated");
    }
    let result = data[*pos..*pos + len].to_vec();
    *pos = end;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_request_roundtrip_minimal() {
        let req = TsRequest::new();
        let encoded = req.encode();
        let decoded = TsRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.version, TS_REQUEST_MAX_VERSION);
        assert!(decoded.nego_tokens.is_none());
        assert!(decoded.auth_info.is_none());
        assert!(decoded.pub_key_auth.is_none());
    }

    #[test]
    fn ts_request_roundtrip_with_nego_tokens() {
        let mut req = TsRequest::new();
        req.nego_tokens = Some(vec![0x01, 0x02, 0x03, 0x04]);

        let encoded = req.encode();
        let decoded = TsRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.version, TS_REQUEST_MAX_VERSION);
        assert_eq!(decoded.nego_tokens.unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn ts_request_roundtrip_with_pub_key_auth() {
        let mut req = TsRequest::new();
        req.pub_key_auth = Some(vec![0xAA; 32]);

        let encoded = req.encode();
        let decoded = TsRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.pub_key_auth.unwrap(), vec![0xAA; 32]);
    }

    #[test]
    fn ts_request_roundtrip_with_client_nonce() {
        let mut req = TsRequest::new();
        req.client_nonce = Some([0xBB; 32]);

        let encoded = req.encode();
        let decoded = TsRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.client_nonce.unwrap(), [0xBB; 32]);
    }

    #[test]
    fn ts_request_roundtrip_full() {
        let mut req = TsRequest::new();
        req.nego_tokens = Some(vec![0x01, 0x02]);
        req.auth_info = Some(vec![0x03, 0x04]);
        req.pub_key_auth = Some(vec![0x05, 0x06]);
        req.error_code = Some(0);
        req.client_nonce = Some([0x07; 32]);

        let encoded = req.encode();
        let decoded = TsRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.version, TS_REQUEST_MAX_VERSION);
        assert_eq!(decoded.nego_tokens.unwrap(), vec![0x01, 0x02]);
        assert_eq!(decoded.auth_info.unwrap(), vec![0x03, 0x04]);
        assert_eq!(decoded.pub_key_auth.unwrap(), vec![0x05, 0x06]);
        assert_eq!(decoded.error_code.unwrap(), 0);
        assert_eq!(decoded.client_nonce.unwrap(), [0x07; 32]);
    }

    #[test]
    fn der_integer_encoding() {
        assert_eq!(der_encode_integer(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(der_encode_integer(6), vec![0x02, 0x01, 0x06]);
        assert_eq!(der_encode_integer(256), vec![0x02, 0x02, 0x01, 0x00]);
    }
}
