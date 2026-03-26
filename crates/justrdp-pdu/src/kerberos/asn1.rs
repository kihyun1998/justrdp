//! Minimal ASN.1 DER encoder/decoder for Kerberos messages.
//!
//! Supports the subset of ASN.1 needed by RFC 4120:
//! - SEQUENCE, SET
//! - Context-tagged [N] EXPLICIT/IMPLICIT
//! - INTEGER, OCTET STRING, BIT STRING, BOOLEAN
//! - GeneralizedTime, GeneralString
//! - Application-tagged types
//! - ENUMERATED
//! - OBJECT IDENTIFIER

use alloc::vec;
use alloc::vec::Vec;
use justrdp_core::{DecodeError, DecodeErrorKind, DecodeResult};

fn err_not_enough(needed: usize, available: usize) -> DecodeError {
    DecodeError::new("ASN.1", DecodeErrorKind::NotEnoughBytes { needed, available })
}

fn err_unexpected(field: &'static str, got: &'static str) -> DecodeError {
    DecodeError::new("ASN.1", DecodeErrorKind::UnexpectedValue { field, got })
}

fn err_other(description: &'static str) -> DecodeError {
    DecodeError::new("ASN.1", DecodeErrorKind::Other { description })
}

// ── ASN.1 Tag Classes ──

const _CLASS_UNIVERSAL: u8 = 0x00;
const CLASS_APPLICATION: u8 = 0x40;
const CLASS_CONTEXT: u8 = 0x80;
const CONSTRUCTED: u8 = 0x20;

// ── ASN.1 Universal Tags ──

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_ENUMERATED: u8 = 0x0A;
pub const TAG_SEQUENCE: u8 = 0x30; // CONSTRUCTED | 0x10
pub const TAG_SET: u8 = 0x31; // CONSTRUCTED | 0x11
pub const TAG_GENERAL_STRING: u8 = 0x1B;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;

// ── DER Decoder ──

/// A positioned view into a DER-encoded byte slice.
#[derive(Clone)]
pub struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    /// Peek at the next tag byte without consuming.
    pub fn peek_tag(&self) -> DecodeResult<u8> {
        if self.pos >= self.data.len() {
            return Err(err_not_enough(1, 0));
        }
        Ok(self.data[self.pos])
    }

    /// Read a TLV (Tag-Length-Value) header and return (tag, content_slice).
    pub fn read_tlv(&mut self) -> DecodeResult<(u8, &'a [u8])> {
        let tag = self.read_byte()?;
        let len = self.read_length()?;
        let content = self.read_bytes(len)?;
        Ok((tag, content))
    }

    /// Read a SEQUENCE and return a sub-reader over its contents.
    pub fn read_sequence(&mut self) -> DecodeResult<DerReader<'a>> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_SEQUENCE {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        Ok(DerReader::new(content))
    }

    /// Read a context-tagged [n] EXPLICIT value and return a sub-reader.
    pub fn read_context_tag(&mut self, expected_tag: u8) -> DecodeResult<DerReader<'a>> {
        let (tag, content) = self.read_tlv()?;
        let expected = CLASS_CONTEXT | CONSTRUCTED | expected_tag;
        if tag != expected {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        Ok(DerReader::new(content))
    }

    /// Try to read a context-tagged [n] EXPLICIT value; returns None if the next
    /// tag doesn't match.
    pub fn read_optional_context_tag(
        &mut self,
        expected_tag: u8,
    ) -> DecodeResult<Option<DerReader<'a>>> {
        if self.is_empty() {
            return Ok(None);
        }
        let expected = CLASS_CONTEXT | CONSTRUCTED | expected_tag;
        if self.peek_tag()? != expected {
            return Ok(None);
        }
        self.read_context_tag(expected_tag).map(Some)
    }

    /// Read an APPLICATION-tagged type and return (tag_number, sub-reader).
    pub fn read_application_tag(&mut self, expected_tag: u8) -> DecodeResult<DerReader<'a>> {
        let (tag, content) = self.read_tlv()?;
        let expected = CLASS_APPLICATION | CONSTRUCTED | expected_tag;
        if tag != expected {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        Ok(DerReader::new(content))
    }

    /// Read an INTEGER and return as i64.
    pub fn read_integer(&mut self) -> DecodeResult<i64> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_INTEGER {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        der_integer_to_i64(content)
    }

    /// Read an ENUMERATED and return as i32.
    pub fn read_enumerated(&mut self) -> DecodeResult<i32> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_ENUMERATED {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        Ok(der_integer_to_i64(content)? as i32)
    }

    /// Read an OCTET STRING.
    pub fn read_octet_string(&mut self) -> DecodeResult<&'a [u8]> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_OCTET_STRING {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        Ok(content)
    }

    /// Read a BIT STRING and return the content bytes (excluding the unused-bits byte).
    pub fn read_bit_string(&mut self) -> DecodeResult<&'a [u8]> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_BIT_STRING {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        if content.is_empty() {
            return Err(err_not_enough(1, 0));
        }
        // content[0] = number of unused bits in last byte
        Ok(&content[1..])
    }

    /// Read a GeneralString as bytes.
    pub fn read_general_string(&mut self) -> DecodeResult<&'a [u8]> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_GENERAL_STRING {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        Ok(content)
    }

    /// Read a GeneralizedTime as bytes.
    pub fn read_generalized_time(&mut self) -> DecodeResult<&'a [u8]> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_GENERALIZED_TIME {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        Ok(content)
    }

    /// Read an OBJECT IDENTIFIER as raw bytes.
    pub fn read_oid(&mut self) -> DecodeResult<&'a [u8]> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_OID {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        Ok(content)
    }

    /// Read a BOOLEAN.
    pub fn read_boolean(&mut self) -> DecodeResult<bool> {
        let (tag, content) = self.read_tlv()?;
        if tag != TAG_BOOLEAN {
            return Err(err_unexpected("tag", "unexpected ASN.1 tag"));
        }
        if content.len() != 1 {
            return Err(err_not_enough(1, content.len()));
        }
        Ok(content[0] != 0)
    }

    /// Read remaining bytes as a raw slice.
    pub fn read_remaining(&mut self) -> &'a [u8] {
        let remaining = &self.data[self.pos..];
        self.pos = self.data.len();
        remaining
    }

    // ── Private helpers ──

    fn read_byte(&mut self) -> DecodeResult<u8> {
        if self.pos >= self.data.len() {
            return Err(err_not_enough(1, 0));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> DecodeResult<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(err_not_enough(len, self.data.len() - self.pos));
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn read_length(&mut self) -> DecodeResult<usize> {
        let first = self.read_byte()?;
        if first < 0x80 {
            Ok(first as usize)
        } else if first == 0x80 {
            Err(err_other("indefinite length not supported"))
        } else {
            let num_bytes = (first & 0x7F) as usize;
            if num_bytes > 4 {
                return Err(err_other("length too large"));
            }
            let mut len: usize = 0;
            for _ in 0..num_bytes {
                len = (len << 8) | self.read_byte()? as usize;
            }
            Ok(len)
        }
    }
}

fn der_integer_to_i64(content: &[u8]) -> DecodeResult<i64> {
    if content.is_empty() || content.len() > 8 {
        return Err(err_other("invalid integer length"));
    }
    // Sign-extend from the first byte
    let mut val: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in content {
        val = (val << 8) | b as i64;
    }
    Ok(val)
}

// ── DER Encoder ──

/// A growable DER writer.
pub struct DerWriter {
    buf: Vec<u8>,
}

impl DerWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Consume the writer and return the buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Write a complete TLV.
    pub fn write_tlv(&mut self, tag: u8, content: &[u8]) {
        self.buf.push(tag);
        self.write_length(content.len());
        self.buf.extend_from_slice(content);
    }

    /// Write a SEQUENCE wrapping the given content bytes.
    pub fn write_sequence(&mut self, content: &[u8]) {
        self.write_tlv(TAG_SEQUENCE, content);
    }

    /// Write a context-tagged [n] EXPLICIT wrapper around content.
    pub fn write_context_tag(&mut self, tag_num: u8, content: &[u8]) {
        let tag = CLASS_CONTEXT | CONSTRUCTED | tag_num;
        self.write_tlv(tag, content);
    }

    /// Write an APPLICATION-tagged wrapper around content.
    pub fn write_application_tag(&mut self, tag_num: u8, content: &[u8]) {
        let tag = CLASS_APPLICATION | CONSTRUCTED | tag_num;
        self.write_tlv(tag, content);
    }

    /// Write an INTEGER.
    pub fn write_integer(&mut self, val: i64) {
        let encoded = encode_integer(val);
        self.write_tlv(TAG_INTEGER, &encoded);
    }

    /// Write an ENUMERATED.
    pub fn write_enumerated(&mut self, val: i32) {
        let encoded = encode_integer(val as i64);
        self.write_tlv(TAG_ENUMERATED, &encoded);
    }

    /// Write an OCTET STRING.
    pub fn write_octet_string(&mut self, data: &[u8]) {
        self.write_tlv(TAG_OCTET_STRING, data);
    }

    /// Write a BIT STRING (with 0 unused bits).
    pub fn write_bit_string(&mut self, data: &[u8]) {
        self.buf.push(TAG_BIT_STRING);
        self.write_length(1 + data.len());
        self.buf.push(0); // 0 unused bits
        self.buf.extend_from_slice(data);
    }

    /// Write a GeneralString.
    pub fn write_general_string(&mut self, s: &[u8]) {
        self.write_tlv(TAG_GENERAL_STRING, s);
    }

    /// Write a GeneralizedTime.
    pub fn write_generalized_time(&mut self, t: &[u8]) {
        self.write_tlv(TAG_GENERALIZED_TIME, t);
    }

    /// Write an OBJECT IDENTIFIER.
    pub fn write_oid(&mut self, oid: &[u8]) {
        self.write_tlv(TAG_OID, oid);
    }

    /// Write a BOOLEAN.
    pub fn write_boolean(&mut self, val: bool) {
        self.write_tlv(TAG_BOOLEAN, &[if val { 0xFF } else { 0x00 }]);
    }

    /// Write a NULL value.
    pub fn write_null(&mut self) {
        self.buf.extend_from_slice(&[0x05, 0x00]);
    }

    /// Write an INTEGER from big-endian bytes (unsigned).
    ///
    /// Adds a leading 0x00 byte if the high bit is set to keep the value positive.
    pub fn write_integer_bytes(&mut self, bytes: &[u8]) {
        // Skip leading zeros
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len().saturating_sub(1));
        let significant = &bytes[start..];

        let needs_pad = !significant.is_empty() && significant[0] & 0x80 != 0;
        let len = significant.len() + if needs_pad { 1 } else { 0 };

        self.buf.push(TAG_INTEGER);
        self.write_length(len);
        if needs_pad {
            self.buf.push(0x00);
        }
        self.buf.extend_from_slice(significant);
    }

    /// Write raw bytes directly.
    pub fn write_raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn write_length(&mut self, len: usize) {
        if len < 0x80 {
            self.buf.push(len as u8);
        } else if len <= 0xFF {
            self.buf.push(0x81);
            self.buf.push(len as u8);
        } else if len <= 0xFFFF {
            self.buf.push(0x82);
            self.buf.push((len >> 8) as u8);
            self.buf.push(len as u8);
        } else if len <= 0xFF_FFFF {
            self.buf.push(0x83);
            self.buf.push((len >> 16) as u8);
            self.buf.push((len >> 8) as u8);
            self.buf.push(len as u8);
        } else {
            self.buf.push(0x84);
            self.buf.push((len >> 24) as u8);
            self.buf.push((len >> 16) as u8);
            self.buf.push((len >> 8) as u8);
            self.buf.push(len as u8);
        }
    }
}

/// Helper: build a SEQUENCE from content produced by a closure.
pub fn build_sequence(f: impl FnOnce(&mut DerWriter)) -> Vec<u8> {
    let mut inner = DerWriter::new();
    f(&mut inner);
    let content = inner.into_inner();
    let mut outer = DerWriter::new();
    outer.write_sequence(&content);
    outer.into_inner()
}

/// Helper: build a context-tagged [n] EXPLICIT from content produced by a closure.
pub fn build_context_tag(tag_num: u8, f: impl FnOnce(&mut DerWriter)) -> Vec<u8> {
    let mut inner = DerWriter::new();
    f(&mut inner);
    let content = inner.into_inner();
    let mut outer = DerWriter::new();
    outer.write_context_tag(tag_num, &content);
    outer.into_inner()
}

/// Helper: build an APPLICATION-tagged wrapper.
pub fn build_application_tag(tag_num: u8, f: impl FnOnce(&mut DerWriter)) -> Vec<u8> {
    let mut inner = DerWriter::new();
    f(&mut inner);
    let content = inner.into_inner();
    let mut outer = DerWriter::new();
    outer.write_application_tag(tag_num, &content);
    outer.into_inner()
}

fn encode_integer(val: i64) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let bytes = val.to_be_bytes();
    // Find first significant byte (skip leading 0x00 for positive, 0xFF for negative)
    let mut start = 0;
    if val > 0 {
        while start < 7 && bytes[start] == 0x00 {
            start += 1;
        }
        // If the MSB of the first significant byte is set, prepend 0x00
        if bytes[start] & 0x80 != 0 {
            let mut result = vec![0x00];
            result.extend_from_slice(&bytes[start..]);
            return result;
        }
    } else {
        while start < 7 && bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0 {
            start += 1;
        }
    }
    bytes[start..].to_vec()
}

// ── Well-known OIDs ──

/// Kerberos v5 OID: 1.2.840.113554.1.2.2
pub const OID_KRB5: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// Kerberos v5 OID (raw, without tag/length): 1.2.840.113554.1.2.2
pub const OID_KRB5_RAW: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// SPNEGO OID: 1.3.6.1.5.5.2
pub const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// MS-KRB5 OID: 1.2.840.48018.1.2.2
pub const OID_MS_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
pub const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

// ── PKINIT / CMS OIDs (raw, without tag/length) ──

/// PKINIT AuthData content type: 1.3.6.1.5.2.3.1 (id-pkinit-authData)
pub const OID_PKINIT_AUTH_DATA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01];

/// PKINIT DHKeyData content type: 1.3.6.1.5.2.3.2 (id-pkinit-DHKeyData)
pub const OID_PKINIT_DH_KEY_DATA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x02];

/// CMS SignedData: 1.2.840.113549.1.7.2
pub const OID_CMS_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

/// CMS ContentType data: 1.2.840.113549.1.7.1
pub const OID_CMS_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];

/// SHA-256: 2.16.840.1.101.3.4.2.1
pub const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// SHA-256 with RSA Encryption: 1.2.840.113549.1.1.11
pub const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

/// RSA Encryption: 1.2.840.113549.1.1.1
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// DH Public Number: 1.2.840.10046.2.1 (dhpublicnumber)
pub const OID_DH_PUBLIC_NUMBER: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_integer() {
        for val in [0i64, 1, -1, 127, 128, -128, -129, 256, 65535, -32768, 0x7FFFFFFF] {
            let mut w = DerWriter::new();
            w.write_integer(val);
            let mut r = DerReader::new(w.as_bytes());
            assert_eq!(r.read_integer().unwrap(), val, "roundtrip failed for {}", val);
        }
    }

    #[test]
    fn roundtrip_octet_string() {
        let data = b"hello world";
        let mut w = DerWriter::new();
        w.write_octet_string(data);
        let mut r = DerReader::new(w.as_bytes());
        assert_eq!(r.read_octet_string().unwrap(), data);
    }

    #[test]
    fn roundtrip_sequence() {
        let encoded = build_sequence(|w| {
            w.write_integer(42);
            w.write_octet_string(b"test");
        });
        let mut r = DerReader::new(&encoded);
        let mut seq = r.read_sequence().unwrap();
        assert_eq!(seq.read_integer().unwrap(), 42);
        assert_eq!(seq.read_octet_string().unwrap(), b"test");
    }

    #[test]
    fn roundtrip_context_tags() {
        let encoded = build_sequence(|w| {
            let tag0 = build_context_tag(0, |w| w.write_integer(5));
            w.write_raw(&tag0);
            let tag1 = build_context_tag(1, |w| w.write_octet_string(b"abc"));
            w.write_raw(&tag1);
        });
        let mut r = DerReader::new(&encoded);
        let mut seq = r.read_sequence().unwrap();
        let mut t0 = seq.read_context_tag(0).unwrap();
        assert_eq!(t0.read_integer().unwrap(), 5);
        let mut t1 = seq.read_context_tag(1).unwrap();
        assert_eq!(t1.read_octet_string().unwrap(), b"abc");
    }

    #[test]
    fn optional_context_tag() {
        let encoded = build_sequence(|w| {
            let tag2 = build_context_tag(2, |w| w.write_integer(99));
            w.write_raw(&tag2);
        });
        let mut r = DerReader::new(&encoded);
        let mut seq = r.read_sequence().unwrap();
        // Tag 0 is missing → should return None
        assert!(seq.read_optional_context_tag(0).unwrap().is_none());
        // Tag 2 is present
        let mut t2 = seq.read_optional_context_tag(2).unwrap().unwrap();
        assert_eq!(t2.read_integer().unwrap(), 99);
    }

    #[test]
    fn length_encoding() {
        // Test with data longer than 127 bytes
        let data = vec![0x42u8; 200];
        let mut w = DerWriter::new();
        w.write_octet_string(&data);
        let mut r = DerReader::new(w.as_bytes());
        assert_eq!(r.read_octet_string().unwrap(), &data[..]);
    }
}
