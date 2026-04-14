//! Common structures shared by every MS-RDPEMC PDU body.

use alloc::vec::Vec;

use justrdp_core::{
    DecodeError, DecodeResult, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use crate::constants::{MAX_UNICODE_STRING_CCH, ORDER_HDR_SIZE};

/// `ORDER_HDR` — the 4-byte common header that prefixes every MS-RDPEMC
/// PDU (MS-RDPEMC §2.2.1).
///
/// `length` is **inclusive** of the 4-byte header itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderHeader {
    /// `Type` field — message type (see [`crate::constants::odtype`]).
    pub type_: u16,
    /// `Length` field — total PDU size in bytes, including this header.
    pub length: u16,
}

const HDR_CTX: &str = "OrderHeader";

impl OrderHeader {
    pub fn new(type_: u16, length: u16) -> Self {
        Self { type_, length }
    }

    pub(crate) fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.type_, HDR_CTX)?;
        dst.write_u16_le(self.length, HDR_CTX)?;
        Ok(())
    }

    pub(crate) fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let type_ = src.read_u16_le(HDR_CTX)?;
        let length = src.read_u16_le(HDR_CTX)?;
        if (length as usize) < ORDER_HDR_SIZE {
            return Err(DecodeError::invalid_value(HDR_CTX, "length < 4"));
        }
        Ok(Self { type_, length })
    }

    /// Validate that an incoming header matches an expected `Type` and
    /// `Length`. Used by fixed-size PDU decoders.
    pub(crate) fn expect(&self, expected_type: u16, expected_length: u16) -> DecodeResult<()> {
        if self.type_ != expected_type {
            return Err(DecodeError::invalid_value(HDR_CTX, "type"));
        }
        if self.length != expected_length {
            return Err(DecodeError::invalid_value(HDR_CTX, "length"));
        }
        Ok(())
    }
}

// ── UnicodeString (§2.2.2) ────────────────────────────────────────────

/// `UNICODE_STRING` — a UTF-16LE string prefixed by a u16 character count
/// (MS-RDPEMC §2.2.2).
///
/// The character count is in UTF-16 code units, not bytes. The maximum
/// value is 1024 per spec; values above that are a protocol violation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnicodeString {
    /// Raw UTF-16LE payload — exactly `cch_string` code units
    /// (i.e. `2 * cch_string` bytes). Preserved verbatim to avoid lossy
    /// re-encoding across roundtrip.
    ///
    /// The spec terminates string content at the first UTF-16 NUL, but
    /// the wire form always carries `cch_string` code units regardless,
    /// so we mirror that.
    pub raw_utf16: Vec<u16>,
}

const USTR_CTX: &str = "UnicodeString";

impl UnicodeString {
    /// Construct an empty string.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct from pre-encoded UTF-16LE code units. Returns `None`
    /// if the length would overflow the spec cap.
    pub fn from_utf16(units: Vec<u16>) -> Option<Self> {
        if units.len() > MAX_UNICODE_STRING_CCH as usize {
            return None;
        }
        Some(Self { raw_utf16: units })
    }

    /// Number of UTF-16 code units (the `cchString` wire field).
    pub fn cch(&self) -> u16 {
        // from_utf16 enforces ≤ 1024 and empty is 0; direct callers of
        // the struct literal are expected to uphold the same invariant.
        self.raw_utf16.len() as u16
    }

    /// Encoded size in bytes (2 + 2·cch).
    pub fn size(&self) -> usize {
        2 + self.raw_utf16.len() * 2
    }

    pub(crate) fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let cch = self.raw_utf16.len();
        if cch > MAX_UNICODE_STRING_CCH as usize {
            return Err(EncodeError::invalid_value(USTR_CTX, "cchString > 1024"));
        }
        dst.write_u16_le(cch as u16, USTR_CTX)?;
        for &u in &self.raw_utf16 {
            dst.write_u16_le(u, USTR_CTX)?;
        }
        Ok(())
    }

    pub(crate) fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let cch = src.read_u16_le(USTR_CTX)?;
        if cch > MAX_UNICODE_STRING_CCH {
            return Err(DecodeError::invalid_value(USTR_CTX, "cchString > 1024"));
        }
        let mut raw = Vec::with_capacity(cch as usize);
        for _ in 0..cch {
            raw.push(src.read_u16_le(USTR_CTX)?);
        }
        Ok(Self { raw_utf16: raw })
    }
}