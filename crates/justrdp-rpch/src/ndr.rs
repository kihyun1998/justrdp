#![forbid(unsafe_code)]

//! **NDR 2.0** (Network Data Representation) transfer syntax encoder
//! and decoder.
//!
//! NDR 2.0 is specified in **C706 Chapter 14** ("Transfer Syntax
//! NDR", The Open Group) and referenced by **MS-RPCE §2.2.5**. Its
//! transfer syntax UUID is
//! `8a885d04-1ceb-11c9-9fe8-08002b104860` version 2.0.
//!
//! This module implements the **subset of NDR** that MS-TSGU /
//! MS-RPCH actually uses. Features that are known not to be needed
//! in the RDP-gateway stack are deliberately descoped; see the
//! module-level scope notes below.
//!
//! # Data representation assumption
//!
//! NDR allows the format of integers, characters, and floats to be
//! negotiated via the 4-byte `packed_drep` field in the DCE/RPC PDU
//! header (C706 §14.1). Windows and every MS-RPCE client this crate
//! targets always uses:
//!
//! - integer byte order: **little-endian**,
//! - character encoding: **ASCII** (and UTF-16LE for `wchar_t`),
//! - floating-point: **IEEE 754**.
//!
//! This module therefore hard-codes little-endian and IEEE 754. The
//! DREP label itself lives at the PDU layer (see `pdu::CommonHeader`),
//! not inside the NDR stream.
//!
//! # Alignment
//!
//! NDR alignment is *absolute to the start of the stream buffer*, not
//! relative to the current struct (C706 §14.2.2). The encoder and
//! decoder both track the current offset and insert/consume padding
//! bytes (value `0x00`) before writing/reading any primitive that
//! demands alignment.
//!
//! Alignment rules used here (C706 §14.2):
//!
//! | Type                  | Size | Alignment |
//! |-----------------------|------|-----------|
//! | `boolean`, `byte`     | 1    | 1         |
//! | `short`, `wchar_t`    | 2    | 2         |
//! | `long`, `float`       | 4    | 4         |
//! | `hyper`, `double`     | 8    | 8         |
//! | pointer word (NDR20)  | 4    | 4         |
//! | `enum16`              | 2    | 2         |
//!
//! # Scope descoped for TsProxy / MS-TSGU
//!
//! The following NDR features are **not** implemented here because
//! the interfaces we target never use them:
//!
//! - **Full (aliasing) pointers** — `TsProxy` uses only `unique` and
//!   `ref` pointers.
//! - **Multi-dimensional arrays** — one-dimensional only.
//! - **Non-encapsulated unions** — all unions are encapsulated.
//! - **Pipes** (C706 §14.3.9).
//! - **EBCDIC character encoding**, **VAX / Cray / IBM floats**.
//!
//! If a future interface requires any of these, extend this module
//! rather than reinventing NDR.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// =============================================================================
// NDR 2.0 transfer syntax identity (MS-RPCE §2.2.5.1 / C706 Appendix I)
// =============================================================================

/// UUID of the NDR 2.0 transfer syntax, in canonical mixed-endian wire
/// order (first three fields little-endian, last 8 bytes big-endian).
///
/// Source: C706 Appendix I / MS-RPCE §2.2.5.1.
pub const NDR20_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, // Data1 (u32 LE):  0x8a885d04
    0xEB, 0x1C, //             Data2 (u16 LE):  0x1ceb
    0xC9, 0x11, //             Data3 (u16 LE):  0x11c9
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, // Data4 (u64 BE bytes)
];

/// Transfer syntax version for NDR 2.0 — major = 2, minor = 0
/// (C706 Appendix I).
pub const NDR20_VERSION_MAJOR: u16 = 2;
/// Transfer syntax version for NDR 2.0 — major = 2, minor = 0
/// (C706 Appendix I).
pub const NDR20_VERSION_MINOR: u16 = 0;

/// First non-null referent ID assigned by the Windows NDR stubs.
/// Subsequent referents increment by 4. Not normative in C706 but
/// matches every Windows capture; using the same value makes our
/// traffic byte-identical where possible.
pub const INITIAL_REFERENT_ID: u32 = 0x0002_0000;

// =============================================================================
// Errors
// =============================================================================

/// Errors produced by the NDR encoder or decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdrError {
    /// The decoder was asked to read past the end of the input buffer.
    NotEnoughBytes {
        context: &'static str,
        needed: usize,
        available: usize,
    },
    /// A value read from the stream was outside the range permitted
    /// by the IDL or by this module (e.g. a non-NUL-terminated
    /// string, or `actual_count > max_count`).
    InvalidData {
        context: &'static str,
    },
    /// A reference pointer was NULL, which is forbidden by IDL
    /// (C706 §14.3.12.1).
    NullRefPointer,
}

impl fmt::Display for NdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NdrError::NotEnoughBytes { context, needed, available } => write!(
                f,
                "NDR: not enough bytes while reading {}: need {}, have {}",
                context, needed, available
            ),
            NdrError::InvalidData { context } => {
                write!(f, "NDR: invalid value while reading {}", context)
            }
            NdrError::NullRefPointer => {
                f.write_str("NDR: NULL value in a [ref] pointer slot (IDL violation)")
            }
        }
    }
}

impl core::error::Error for NdrError {}

/// Result alias used by both the encoder and decoder.
pub type NdrResult<T> = Result<T, NdrError>;

// =============================================================================
// Alignment helper
// =============================================================================

/// Returns the number of zero-padding bytes that must be inserted at
/// absolute stream offset `pos` to reach the next `align`-byte
/// boundary. `align` must be a power of two.
#[inline]
pub fn padding_needed(pos: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two(), "alignment must be a power of two");
    let mask = align - 1;
    (align - (pos & mask)) & mask
}

// =============================================================================
// Encoder
// =============================================================================

/// Buffered NDR encoder. Writes primitives with the correct alignment
/// relative to the buffer start, and hands out fresh referent IDs for
/// `[unique]` pointers.
///
/// The encoder does **not** model the deferred-referent queue itself
/// (C706 §14.3.12.2). The caller is expected to write structures in
/// the usual left-to-right, depth-first order: first the primary
/// fields of the enclosing record, then the referents of any embedded
/// pointers. For the small set of TsProxy types this is
/// straight-forward and keeps the API allocation-free.
#[derive(Debug, Default)]
pub struct NdrEncoder {
    buf: Vec<u8>,
    next_referent_id: u32,
}

impl NdrEncoder {
    /// Create a new empty encoder.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            next_referent_id: INITIAL_REFERENT_ID,
        }
    }

    /// Pre-allocate backing storage.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            next_referent_id: INITIAL_REFERENT_ID,
        }
    }

    /// Current write offset from the start of the stream.
    #[inline]
    pub fn position(&self) -> usize {
        self.buf.len()
    }

    /// Borrow the encoded bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the encoder and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Allocate the next referent ID. Windows assigns non-null
    /// referent IDs starting at [`INITIAL_REFERENT_ID`] and
    /// incrementing by 4 per referent (C706 §14.3.12.3 leaves this
    /// unspecified, but matching Windows bytes helps interop).
    pub fn allocate_referent_id(&mut self) -> u32 {
        let id = self.next_referent_id;
        self.next_referent_id = self.next_referent_id.wrapping_add(4);
        id
    }

    // ---- alignment ------------------------------------------------------

    /// Append zero bytes until `position()` is a multiple of `align`.
    /// Required before any primitive whose alignment is greater than
    /// one (C706 §14.2.2).
    pub fn align(&mut self, align: usize) {
        let pad = padding_needed(self.buf.len(), align);
        for _ in 0..pad {
            self.buf.push(0);
        }
    }

    // ---- primitives -----------------------------------------------------

    /// Write a single byte (`boolean`, `byte`, `char`). No alignment.
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write an `unsigned short` / `wchar_t` (2 bytes, 2-aligned).
    pub fn write_u16(&mut self, v: u16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write an `unsigned long` (4 bytes, 4-aligned).
    pub fn write_u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a `long` (4 bytes, 4-aligned).
    pub fn write_i32(&mut self, v: i32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a `hyper` (8 bytes, 8-aligned).
    pub fn write_u64(&mut self, v: u64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a NDR `enum16` (2 bytes, 2-aligned). NDR enums are
    /// always 16-bit on the wire regardless of IDL-language `int`
    /// width (C706 §14.2.10).
    pub fn write_enum16(&mut self, v: u16) {
        self.write_u16(v);
    }

    /// Write a byte slice verbatim. No alignment, no length prefix.
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    // ---- pointers -------------------------------------------------------

    /// Write a `[unique]` pointer word: 0 for `None`, a fresh
    /// referent ID for `Some` (C706 §14.3.12.3). The referent data is
    /// *deferred*: the caller is responsible for emitting it later in
    /// the enclosing structure, after all inline fields of the parent
    /// are written.
    ///
    /// Returns the referent ID that was written, or 0 for NULL.
    pub fn write_unique_pointer(&mut self, present: bool) -> u32 {
        let id = if present {
            self.allocate_referent_id()
        } else {
            0
        };
        self.write_u32(id);
        id
    }

    /// Write the pointer slot of a `[ref]` pointer — always a
    /// non-null referent ID placeholder. Embedded `[ref]` pointers
    /// still occupy 4 bytes on the wire (C706 §14.3.12.2). The
    /// referent data is deferred.
    pub fn write_ref_pointer(&mut self) -> u32 {
        let id = self.allocate_referent_id();
        self.write_u32(id);
        id
    }

    // ---- arrays and strings --------------------------------------------

    /// Write a one-dimensional **conformant** array prefix
    /// (`max_count`). Caller writes the elements next (C706
    /// §14.3.4.2).
    pub fn write_conformant_array_header(&mut self, max_count: u32) {
        self.write_u32(max_count);
    }

    /// Write a one-dimensional **varying** array prefix (`offset`,
    /// `actual_count`). Caller writes the elements next (C706
    /// §14.3.4.3). Windows always sends `offset = 0`.
    pub fn write_varying_array_header(&mut self, offset: u32, actual_count: u32) {
        self.write_u32(offset);
        self.write_u32(actual_count);
    }

    /// Write a one-dimensional **conformant + varying** array prefix
    /// — `max_count`, `offset`, `actual_count` — the form used by
    /// nearly every MS-RPCE string and bounded array (C706 §14.3.4.4).
    pub fn write_conformant_varying_header(
        &mut self,
        max_count: u32,
        offset: u32,
        actual_count: u32,
    ) {
        self.write_u32(max_count);
        self.write_u32(offset);
        self.write_u32(actual_count);
    }

    /// Encode a conformant-varying UTF-16LE string **including** its
    /// NUL terminator. This is the standard form for `[string]
    /// wchar_t *` in MS-RPCE (C706 §14.3.5).
    ///
    /// Wire layout: `max_count` u32 LE + `offset = 0` u32 LE +
    /// `actual_count` u32 LE + `actual_count` UTF-16LE code units,
    /// where `actual_count` includes the trailing `0x0000` terminator.
    /// `max_count` is set equal to `actual_count` (Windows convention).
    pub fn write_conformant_varying_wstring(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().chain(core::iter::once(0)).collect();
        let count = units.len() as u32;
        self.write_conformant_varying_header(count, 0, count);
        for u in &units {
            self.write_u16(*u);
        }
    }

    /// Encode a conformant-varying ASCII/OEM string **including** its
    /// NUL terminator (`char *` variant of the above).
    pub fn write_conformant_varying_cstring(&mut self, s: &[u8]) {
        let mut bytes = Vec::with_capacity(s.len() + 1);
        bytes.extend_from_slice(s);
        if bytes.last() != Some(&0) {
            bytes.push(0);
        }
        let count = bytes.len() as u32;
        self.write_conformant_varying_header(count, 0, count);
        self.buf.extend_from_slice(&bytes);
    }
}

// =============================================================================
// Decoder
// =============================================================================

/// Zero-copy NDR decoder.
#[derive(Debug)]
pub struct NdrDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> NdrDecoder<'a> {
    /// Create a decoder over the given stub data.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current absolute read offset.
    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Remaining bytes.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn ensure(&self, n: usize, context: &'static str) -> NdrResult<()> {
        if self.remaining() < n {
            Err(NdrError::NotEnoughBytes {
                context,
                needed: n,
                available: self.remaining(),
            })
        } else {
            Ok(())
        }
    }

    // ---- alignment ------------------------------------------------------

    /// Advance past up to `align - 1` padding bytes so that the next
    /// read starts on an `align`-byte boundary. Padding bytes must
    /// all be `0x00` — non-zero padding is not a hard error here (we
    /// do not verify) because some encoders get lazy, but decoding
    /// past the buffer is.
    pub fn align(&mut self, align: usize) -> NdrResult<()> {
        let pad = padding_needed(self.pos, align);
        self.ensure(pad, "NDR alignment padding")?;
        self.pos += pad;
        Ok(())
    }

    // ---- primitives -----------------------------------------------------

    pub fn read_u8(&mut self, context: &'static str) -> NdrResult<u8> {
        self.ensure(1, context)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self, context: &'static str) -> NdrResult<u16> {
        self.align(2)?;
        self.ensure(2, context)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn read_u32(&mut self, context: &'static str) -> NdrResult<u32> {
        self.align(4)?;
        self.ensure(4, context)?;
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    pub fn read_i32(&mut self, context: &'static str) -> NdrResult<i32> {
        self.align(4)?;
        self.ensure(4, context)?;
        let v = i32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    pub fn read_u64(&mut self, context: &'static str) -> NdrResult<u64> {
        self.align(8)?;
        self.ensure(8, context)?;
        let p = self.pos;
        let v = u64::from_le_bytes([
            self.buf[p],
            self.buf[p + 1],
            self.buf[p + 2],
            self.buf[p + 3],
            self.buf[p + 4],
            self.buf[p + 5],
            self.buf[p + 6],
            self.buf[p + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    pub fn read_enum16(&mut self, context: &'static str) -> NdrResult<u16> {
        self.read_u16(context)
    }

    pub fn read_bytes(&mut self, n: usize, context: &'static str) -> NdrResult<&'a [u8]> {
        self.ensure(n, context)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    // ---- pointers -------------------------------------------------------

    /// Read a `[unique]` pointer word. Returns `Some(referent_id)`
    /// for a non-zero value (deferred referent data to follow),
    /// `None` for NULL.
    pub fn read_unique_pointer(&mut self, context: &'static str) -> NdrResult<Option<u32>> {
        let id = self.read_u32(context)?;
        Ok(if id == 0 { None } else { Some(id) })
    }

    /// Read a `[ref]` pointer word. NULL is an IDL violation.
    pub fn read_ref_pointer(&mut self, context: &'static str) -> NdrResult<u32> {
        let id = self.read_u32(context)?;
        if id == 0 {
            Err(NdrError::NullRefPointer)
        } else {
            Ok(id)
        }
    }

    // ---- arrays and strings --------------------------------------------

    /// Read a one-dimensional **conformant** array prefix.
    pub fn read_conformant_array_header(&mut self) -> NdrResult<u32> {
        self.read_u32("conformant array max_count")
    }

    /// Read a one-dimensional **varying** array prefix `(offset,
    /// actual_count)`.
    pub fn read_varying_array_header(&mut self) -> NdrResult<(u32, u32)> {
        let offset = self.read_u32("varying array offset")?;
        let actual = self.read_u32("varying array actual_count")?;
        Ok((offset, actual))
    }

    /// Read a one-dimensional **conformant + varying** array prefix
    /// `(max_count, offset, actual_count)`. Enforces the invariant
    /// `offset + actual_count <= max_count`.
    pub fn read_conformant_varying_header(&mut self) -> NdrResult<(u32, u32, u32)> {
        let max = self.read_u32("conformant-varying max_count")?;
        let offset = self.read_u32("conformant-varying offset")?;
        let actual = self.read_u32("conformant-varying actual_count")?;
        if offset.saturating_add(actual) > max {
            return Err(NdrError::InvalidData {
                context: "conformant-varying: offset + actual_count > max_count",
            });
        }
        Ok((max, offset, actual))
    }

    /// Decode a conformant-varying UTF-16LE string **including** its
    /// NUL terminator, returning a heap [`String`]. Errors if the
    /// string is empty (MS-RPCE strings must contain at least the
    /// NUL), if `offset != 0`, if `actual_count` exceeds
    /// [`MAX_NDR_STRING_UNITS`], or if the data contains unpaired
    /// surrogates.
    pub fn read_conformant_varying_wstring(&mut self) -> NdrResult<String> {
        let (_max, offset, actual) = self.read_conformant_varying_header()?;
        if offset != 0 {
            return Err(NdrError::InvalidData {
                context: "wstring: non-zero offset (unsupported by MS-RPCE)",
            });
        }
        if actual == 0 {
            return Err(NdrError::InvalidData {
                context: "wstring: zero actual_count (missing NUL terminator)",
            });
        }
        if actual as usize > MAX_NDR_STRING_UNITS {
            return Err(NdrError::InvalidData {
                context: "wstring: actual_count exceeds MAX_NDR_STRING_UNITS",
            });
        }
        let mut units = Vec::with_capacity(actual as usize);
        for _ in 0..actual {
            units.push(self.read_u16("wstring element")?);
        }
        // Strip trailing NUL.
        if units.last() != Some(&0) {
            return Err(NdrError::InvalidData {
                context: "wstring: missing NUL terminator",
            });
        }
        units.pop();
        String::from_utf16(&units).map_err(|_| NdrError::InvalidData {
            context: "wstring: invalid UTF-16",
        })
    }

    /// Decode a conformant-varying ASCII/OEM string including its
    /// NUL terminator. Returns the bytes without the trailing NUL.
    pub fn read_conformant_varying_cstring(&mut self) -> NdrResult<Vec<u8>> {
        let (_max, offset, actual) = self.read_conformant_varying_header()?;
        if offset != 0 {
            return Err(NdrError::InvalidData {
                context: "cstring: non-zero offset (unsupported by MS-RPCE)",
            });
        }
        if actual == 0 {
            return Err(NdrError::InvalidData {
                context: "cstring: zero actual_count (missing NUL terminator)",
            });
        }
        if actual as usize > MAX_NDR_STRING_UNITS {
            return Err(NdrError::InvalidData {
                context: "cstring: actual_count exceeds MAX_NDR_STRING_UNITS",
            });
        }
        let bytes = self.read_bytes(actual as usize, "cstring data")?;
        if *bytes.last().unwrap() != 0 {
            return Err(NdrError::InvalidData {
                context: "cstring: missing NUL terminator",
            });
        }
        let mut out = Vec::from(&bytes[..bytes.len() - 1]);
        out.shrink_to_fit();
        Ok(out)
    }
}

/// Upper bound on a single NDR conformant-varying string's
/// `actual_count`, applied to both wstring (UTF-16 code units) and
/// cstring (ASCII bytes) decoders. Without this cap an attacker-chosen
/// `actual_count = u32::MAX` would force a 4 GiB `Vec::with_capacity`
/// and trigger OOM before the cursor-level bounds check ever runs.
///
/// 32 Ki code units is 4× larger than the longest field TsProxy
/// exchanges in practice (resource names, hostnames). The cursor still
/// enforces that the requested bytes actually fit in the input stream,
/// so this cap only bounds the pre-allocation cost.
pub const MAX_NDR_STRING_UNITS: usize = 32 * 1024;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    // ---- alignment math -------------------------------------------------

    #[test]
    fn padding_needed_boundary_cases() {
        // Already aligned: 0 pad.
        assert_eq!(padding_needed(0, 4), 0);
        assert_eq!(padding_needed(8, 4), 0);
        // Off by one to four.
        assert_eq!(padding_needed(1, 4), 3);
        assert_eq!(padding_needed(2, 4), 2);
        assert_eq!(padding_needed(3, 4), 1);
        // Larger alignments.
        assert_eq!(padding_needed(1, 8), 7);
        assert_eq!(padding_needed(5, 8), 3);
        assert_eq!(padding_needed(8, 8), 0);
    }

    #[test]
    fn alignment_inserts_pad_before_u32() {
        let mut e = NdrEncoder::new();
        e.write_u8(0x11); // pos=1
        e.write_u32(0xAABB_CCDD); // aligns to 4: 3 pad bytes, then u32
        assert_eq!(e.as_bytes(), &[0x11, 0, 0, 0, 0xDD, 0xCC, 0xBB, 0xAA]);
    }

    #[test]
    fn alignment_no_pad_when_already_aligned() {
        let mut e = NdrEncoder::new();
        e.write_u32(0x0000_0001); // pos=4
        e.write_u32(0x0000_0002); // no pad
        assert_eq!(e.as_bytes().len(), 8);
    }

    #[test]
    fn decoder_skips_padding() {
        let bytes = [0x11u8, 0, 0, 0, 0xDD, 0xCC, 0xBB, 0xAA];
        let mut d = NdrDecoder::new(&bytes);
        assert_eq!(d.read_u8("byte").unwrap(), 0x11);
        assert_eq!(d.read_u32("long").unwrap(), 0xAABB_CCDD);
        assert_eq!(d.remaining(), 0);
    }

    // ---- referent IDs ---------------------------------------------------

    #[test]
    fn referent_ids_start_at_20000_and_increment_by_four() {
        let mut e = NdrEncoder::new();
        assert_eq!(e.allocate_referent_id(), 0x0002_0000);
        assert_eq!(e.allocate_referent_id(), 0x0002_0004);
        assert_eq!(e.allocate_referent_id(), 0x0002_0008);
    }

    #[test]
    fn unique_pointer_null_encodes_zero() {
        let mut e = NdrEncoder::new();
        let id = e.write_unique_pointer(false);
        assert_eq!(id, 0);
        assert_eq!(e.as_bytes(), &[0, 0, 0, 0]);
    }

    #[test]
    fn unique_pointer_present_encodes_fresh_id() {
        let mut e = NdrEncoder::new();
        let id = e.write_unique_pointer(true);
        assert_eq!(id, 0x0002_0000);
        assert_eq!(e.as_bytes(), &[0x00, 0x00, 0x02, 0x00]);
    }

    #[test]
    fn ref_pointer_always_nonzero() {
        let mut e = NdrEncoder::new();
        let id = e.write_ref_pointer();
        assert_ne!(id, 0);
    }

    #[test]
    fn decode_unique_pointer_null() {
        let bytes = [0, 0, 0, 0];
        let mut d = NdrDecoder::new(&bytes);
        assert!(d.read_unique_pointer("p").unwrap().is_none());
    }

    #[test]
    fn decode_unique_pointer_present() {
        let bytes = [0x00, 0x00, 0x02, 0x00];
        let mut d = NdrDecoder::new(&bytes);
        assert_eq!(d.read_unique_pointer("p").unwrap(), Some(0x0002_0000));
    }

    #[test]
    fn decode_ref_pointer_zero_is_error() {
        let bytes = [0, 0, 0, 0];
        let mut d = NdrDecoder::new(&bytes);
        assert_eq!(
            d.read_ref_pointer("p").unwrap_err(),
            NdrError::NullRefPointer
        );
    }

    // ---- strings --------------------------------------------------------

    #[test]
    fn wstring_roundtrip_ascii() {
        let mut e = NdrEncoder::new();
        e.write_conformant_varying_wstring("OK");
        // max_count=3, offset=0, actual=3, chars: 'O','K','\0'
        assert_eq!(
            e.as_bytes(),
            &[
                // max_count
                0x03, 0, 0, 0,
                // offset
                0, 0, 0, 0,
                // actual_count
                0x03, 0, 0, 0,
                // 'O' (0x004F)
                0x4F, 0x00,
                // 'K' (0x004B)
                0x4B, 0x00,
                // NUL
                0x00, 0x00,
            ]
        );

        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_conformant_varying_wstring().unwrap(), "OK");
    }

    #[test]
    fn wstring_empty_string_has_count_one() {
        let mut e = NdrEncoder::new();
        e.write_conformant_varying_wstring("");
        assert_eq!(
            e.as_bytes(),
            &[
                // max_count = 1 (just the NUL)
                0x01, 0, 0, 0,
                // offset
                0, 0, 0, 0,
                // actual_count = 1
                0x01, 0, 0, 0,
                // NUL
                0x00, 0x00,
            ]
        );
        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_conformant_varying_wstring().unwrap(), "");
    }

    #[test]
    fn wstring_roundtrip_unicode() {
        let mut e = NdrEncoder::new();
        e.write_conformant_varying_wstring("가나");
        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_conformant_varying_wstring().unwrap(), "가나");
    }

    #[test]
    fn wstring_reject_missing_nul() {
        // actual_count=1 but the element is not NUL.
        let bytes = [
            0x01, 0, 0, 0, // max_count
            0, 0, 0, 0,    // offset
            0x01, 0, 0, 0, // actual_count
            0x41, 0x00,    // 'A' — no NUL
        ];
        let mut d = NdrDecoder::new(&bytes);
        assert!(matches!(
            d.read_conformant_varying_wstring().unwrap_err(),
            NdrError::InvalidData { .. }
        ));
    }

    #[test]
    fn wstring_reject_zero_actual_count() {
        let bytes = [
            0x00, 0, 0, 0, // max_count
            0, 0, 0, 0,    // offset
            0x00, 0, 0, 0, // actual_count
        ];
        let mut d = NdrDecoder::new(&bytes);
        assert!(matches!(
            d.read_conformant_varying_wstring().unwrap_err(),
            NdrError::InvalidData { .. }
        ));
    }

    #[test]
    fn wstring_reject_nonzero_offset() {
        let bytes = [
            0x02, 0, 0, 0, // max_count
            0x01, 0, 0, 0, // offset = 1 (not allowed)
            0x01, 0, 0, 0, // actual_count
            0x00, 0x00,    // NUL
        ];
        let mut d = NdrDecoder::new(&bytes);
        assert!(matches!(
            d.read_conformant_varying_wstring().unwrap_err(),
            NdrError::InvalidData { .. }
        ));
    }

    #[test]
    fn wstring_rejects_actual_count_over_string_cap() {
        // actual_count = MAX_NDR_STRING_UNITS + 1 would trigger a
        // multi-MiB Vec::with_capacity without the cap. max_count is
        // set to the same value to pass the invariant check; the
        // stream itself is short (no data bytes), which means without
        // the cap we would first allocate, then error on the cursor
        // bounds check.
        let over = (MAX_NDR_STRING_UNITS + 1) as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&over.to_le_bytes()); // max_count
        bytes.extend_from_slice(&0u32.to_le_bytes()); // offset
        bytes.extend_from_slice(&over.to_le_bytes()); // actual_count
        let mut d = NdrDecoder::new(&bytes);
        let err = d.read_conformant_varying_wstring().unwrap_err();
        match err {
            NdrError::InvalidData { context } => {
                assert!(context.contains("exceeds MAX_NDR_STRING_UNITS"));
            }
            _ => panic!("expected InvalidData, got {err:?}"),
        }
    }

    #[test]
    fn cstring_rejects_actual_count_over_string_cap() {
        let over = (MAX_NDR_STRING_UNITS + 1) as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&over.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&over.to_le_bytes());
        let mut d = NdrDecoder::new(&bytes);
        let err = d.read_conformant_varying_cstring().unwrap_err();
        match err {
            NdrError::InvalidData { context } => {
                assert!(context.contains("exceeds MAX_NDR_STRING_UNITS"));
            }
            _ => panic!("expected InvalidData, got {err:?}"),
        }
    }

    #[test]
    fn conformant_varying_header_validates_invariant() {
        // max_count=1, offset=0, actual=2 → offset+actual > max
        let bytes = [
            0x01, 0, 0, 0,
            0x00, 0, 0, 0,
            0x02, 0, 0, 0,
        ];
        let mut d = NdrDecoder::new(&bytes);
        assert!(matches!(
            d.read_conformant_varying_header().unwrap_err(),
            NdrError::InvalidData { .. }
        ));
    }

    #[test]
    fn cstring_roundtrip() {
        let mut e = NdrEncoder::new();
        e.write_conformant_varying_cstring(b"hello");
        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_conformant_varying_cstring().unwrap(), b"hello");
    }

    // ---- primitives -----------------------------------------------------

    #[test]
    fn u32_roundtrip() {
        let mut e = NdrEncoder::new();
        e.write_u32(0xDEAD_BEEF);
        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_u32("x").unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn u64_aligned_from_odd_offset() {
        let mut e = NdrEncoder::new();
        e.write_u8(1); // pos=1
        e.write_u64(0x0102_0304_0506_0708);
        // Expect: 1 byte data + 7 bytes pad + 8 bytes u64.
        assert_eq!(e.as_bytes().len(), 16);

        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_u8("b").unwrap(), 1);
        assert_eq!(d.read_u64("h").unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn enum16_roundtrip() {
        let mut e = NdrEncoder::new();
        e.write_u8(1); // odd
        e.write_enum16(0x00AB);
        // Expect: 1 + 1 pad + 2 bytes.
        assert_eq!(e.as_bytes(), &[0x01, 0x00, 0xAB, 0x00]);

        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_u8("b").unwrap(), 1);
        assert_eq!(d.read_enum16("e").unwrap(), 0x00AB);
    }

    #[test]
    fn i32_negative_roundtrip() {
        let mut e = NdrEncoder::new();
        e.write_i32(-1);
        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_i32("x").unwrap(), -1);
    }

    // ---- array headers --------------------------------------------------

    #[test]
    fn conformant_array_header_roundtrip() {
        let mut e = NdrEncoder::new();
        e.write_conformant_array_header(7);
        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_conformant_array_header().unwrap(), 7);
    }

    #[test]
    fn varying_array_header_roundtrip() {
        let mut e = NdrEncoder::new();
        e.write_varying_array_header(0, 3);
        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_varying_array_header().unwrap(), (0, 3));
    }

    #[test]
    fn conformant_varying_header_roundtrip() {
        let mut e = NdrEncoder::new();
        e.write_conformant_varying_header(5, 0, 3);
        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_conformant_varying_header().unwrap(), (5, 0, 3));
    }

    // ---- transfer syntax identity --------------------------------------

    #[test]
    fn ndr20_uuid_wire_bytes_match_c706_appendix_i() {
        // UUID {8a885d04-1ceb-11c9-9fe8-08002b104860}
        // Wire order: Data1 LE, Data2 LE, Data3 LE, Data4 BE.
        assert_eq!(
            &NDR20_UUID,
            &[
                0x04, 0x5D, 0x88, 0x8A, // Data1
                0xEB, 0x1C, //             Data2
                0xC9, 0x11, //             Data3
                0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, // Data4
            ]
        );
        assert_eq!(NDR20_VERSION_MAJOR, 2);
        assert_eq!(NDR20_VERSION_MINOR, 0);
    }

    // ---- error display --------------------------------------------------

    #[test]
    fn error_display_covers_all_variants() {
        let e1 = NdrError::NotEnoughBytes {
            context: "x",
            needed: 4,
            available: 2,
        };
        let e2 = NdrError::InvalidData { context: "y" };
        let e3 = NdrError::NullRefPointer;
        // Just ensure formatting doesn't panic and contains key info.
        let s1 = alloc::format!("{}", e1);
        let s2 = alloc::format!("{}", e2);
        let s3 = alloc::format!("{}", e3);
        assert!(s1.contains("need 4"));
        assert!(s2.contains("invalid"));
        assert!(s3.contains("NULL"));
    }

    // ---- misc smoke -----------------------------------------------------

    #[test]
    fn encoder_roundtrip_mixed_sequence() {
        // u8, u32, u16, wstring, u64 — exercises several alignment boundaries.
        let mut e = NdrEncoder::new();
        e.write_u8(0x5A);
        e.write_u32(0x1122_3344);
        e.write_u16(0xABCD);
        e.write_conformant_varying_wstring("x");
        e.write_u64(0xDEAD_BEEF_CAFE_F00D);

        let mut d = NdrDecoder::new(e.as_bytes());
        assert_eq!(d.read_u8("a").unwrap(), 0x5A);
        assert_eq!(d.read_u32("b").unwrap(), 0x1122_3344);
        assert_eq!(d.read_u16("c").unwrap(), 0xABCD);
        assert_eq!(d.read_conformant_varying_wstring().unwrap(), "x".to_string());
        assert_eq!(d.read_u64("e").unwrap(), 0xDEAD_BEEF_CAFE_F00D);
    }

    #[test]
    fn not_enough_bytes_error_on_underflow() {
        let bytes = vec![0x11u8];
        let mut d = NdrDecoder::new(&bytes);
        assert!(matches!(
            d.read_u32("x").unwrap_err(),
            NdrError::NotEnoughBytes { .. }
        ));
    }
}
