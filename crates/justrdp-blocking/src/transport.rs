#![forbid(unsafe_code)]

//! Synchronous framing helpers.
//!
//! - [`read_pdu`] reads exactly one PDU using a [`justrdp_core::PduHint`].
//! - [`read_asn1_sequence`] reads exactly one DER-encoded ASN.1 SEQUENCE
//!   (used by CredSSP, which wraps every TsRequest as a top-level SEQUENCE).
//! - [`read_exact_or_eof`] is a small `read_exact` wrapper that maps EOF to
//!   [`ConnectError::UnexpectedEof`] instead of `io::Error`.

use std::io::{self as io, Read};

use justrdp_core::PduHint;

use crate::error::ConnectError;

/// Hard cap on a single PDU to prevent runaway allocations.
/// 16 MiB matches common RDP server output limits (MS-RDPBCGR 1.3.7).
pub const MAX_PDU_SIZE: usize = 16 * 1024 * 1024;

/// Read exactly one PDU from `reader` into `scratch`, using `hint` to
/// determine the frame size.
///
/// Returns the size of the PDU now sitting at `scratch[..size]`. The
/// caller MUST call `scratch.drain(..size)` (or equivalent) after
/// consuming the PDU; `read_pdu` does NOT clear the buffer at the
/// start, because a single TCP read can return multiple pipelined PDUs
/// and the bytes following the first one would otherwise be lost.
///
/// On EOF mid-frame returns [`ConnectError::UnexpectedEof`].
pub fn read_pdu<R: Read>(
    reader: &mut R,
    hint: &dyn PduHint,
    scratch: &mut Vec<u8>,
) -> Result<usize, ConnectError> {
    let mut tmp = [0u8; 4096];

    loop {
        if let Some((_fast_path, size)) = hint.find_size(scratch) {
            if size > MAX_PDU_SIZE {
                return Err(ConnectError::FrameTooLarge(size));
            }
            while scratch.len() < size {
                let need = size - scratch.len();
                let take = need.min(tmp.len());
                let n = reader.read(&mut tmp[..take])?;
                if n == 0 {
                    return Err(ConnectError::UnexpectedEof);
                }
                scratch.extend_from_slice(&tmp[..n]);
            }
            return Ok(size);
        }

        let n = reader.read(&mut tmp)?;
        if n == 0 {
            return Err(ConnectError::UnexpectedEof);
        }
        scratch.extend_from_slice(&tmp[..n]);
    }
}

/// Convenience wrapper that maps [`io::Error`] into [`ConnectError::Tcp`].
pub fn write_all<W: std::io::Write>(writer: &mut W, bytes: &[u8]) -> Result<(), ConnectError> {
    writer.write_all(bytes).map_err(ConnectError::Tcp)?;
    writer.flush().map_err(ConnectError::Tcp)?;
    Ok(())
}

/// `read_exact` that converts EOF to [`ConnectError::UnexpectedEof`].
pub(crate) fn read_exact_or_eof<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<(), ConnectError> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(ConnectError::UnexpectedEof),
        Err(e) => Err(ConnectError::Tcp(e)),
    }
}

/// Read exactly one DER-encoded ASN.1 SEQUENCE (`0x30 <length> <content>`)
/// from `reader` into `scratch`.
///
/// CredSSP wraps every TsRequest in a top-level SEQUENCE, and TLS records
/// can split or coalesce these arbitrarily, so we cannot rely on a single
/// `read()` call returning exactly one TsRequest.
///
/// Returns the total number of bytes written to `scratch` (header + content).
pub fn read_asn1_sequence<R: Read>(
    reader: &mut R,
    scratch: &mut Vec<u8>,
) -> Result<usize, ConnectError> {
    scratch.clear();

    // Read the SEQUENCE tag and the first length byte.
    scratch.resize(2, 0);
    read_exact_or_eof(reader, &mut scratch[..2])?;

    if scratch[0] != 0x30 {
        return Err(ConnectError::Tcp(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected ASN.1 SEQUENCE tag (0x30), got 0x{:02x}",
                scratch[0]
            ),
        )));
    }

    // Decode DER length: 1 byte (< 0x80) or N+1 bytes (0x8N indicator + N).
    let first_len = scratch[1];
    let content_length = if first_len < 0x80 {
        first_len as usize
    } else {
        let num_length_bytes = (first_len & 0x7F) as usize;
        if num_length_bytes == 0 || num_length_bytes > 4 {
            return Err(ConnectError::Tcp(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid ASN.1 length byte: 0x{first_len:02x}"),
            )));
        }
        let header_pos = scratch.len();
        scratch.resize(header_pos + num_length_bytes, 0);
        read_exact_or_eof(reader, &mut scratch[header_pos..])?;
        let mut len = 0usize;
        for &b in &scratch[header_pos..header_pos + num_length_bytes] {
            len = (len << 8) | b as usize;
        }
        len
    };

    let header_size = scratch.len();
    let total = header_size
        .checked_add(content_length)
        .ok_or(ConnectError::FrameTooLarge(usize::MAX))?;
    if total > MAX_PDU_SIZE {
        return Err(ConnectError::FrameTooLarge(total));
    }

    scratch.resize(total, 0);
    read_exact_or_eof(reader, &mut scratch[header_size..])?;
    Ok(total)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Fixed-size hint: always expects `n` bytes (slow-path branch).
    struct FixedHint(usize);
    impl PduHint for FixedHint {
        fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)> {
            if bytes.len() >= 1 {
                Some((false, self.0))
            } else {
                None
            }
        }
    }

    /// Same as `FixedHint` but reports the frame as fast-path so the
    /// `(true, size)` arm of `read_pdu` gets exercised.
    struct FastPathHint(usize);
    impl PduHint for FastPathHint {
        fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)> {
            if bytes.len() >= 1 {
                Some((true, self.0))
            } else {
                None
            }
        }
    }

    #[test]
    fn read_pdu_reads_complete_frame() {
        let data = vec![0xAB; 10];
        let mut cursor = Cursor::new(data.clone());
        let mut scratch = Vec::new();
        let n = read_pdu(&mut cursor, &FixedHint(10), &mut scratch).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&scratch[..n], &data[..]);
    }

    #[test]
    fn read_pdu_rejects_oversized_frame() {
        let mut cursor = Cursor::new(vec![0u8; 1]);
        let mut scratch = Vec::new();
        let err = read_pdu(&mut cursor, &FixedHint(MAX_PDU_SIZE + 1), &mut scratch).unwrap_err();
        assert!(matches!(err, ConnectError::FrameTooLarge(_)));
    }

    #[test]
    fn read_pdu_eof_mid_frame_returns_unexpected_eof() {
        let mut cursor = Cursor::new(vec![0u8; 3]);
        let mut scratch = Vec::new();
        let err = read_pdu(&mut cursor, &FixedHint(10), &mut scratch).unwrap_err();
        assert!(matches!(err, ConnectError::UnexpectedEof));
    }

    #[test]
    fn asn1_short_form_length() {
        // SEQUENCE with 5 content bytes: 0x30 0x05 <5 bytes>
        let data = vec![0x30, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut cursor = Cursor::new(data.clone());
        let mut scratch = Vec::new();
        let n = read_asn1_sequence(&mut cursor, &mut scratch).unwrap();
        assert_eq!(n, 7);
        assert_eq!(&scratch[..n], &data[..]);
    }

    #[test]
    fn asn1_one_byte_long_form_length() {
        // 0x81 0xC8 = 200 bytes content
        let mut data = vec![0x30, 0x81, 0xC8];
        data.extend_from_slice(&vec![0x42; 200]);
        let mut cursor = Cursor::new(data.clone());
        let mut scratch = Vec::new();
        let n = read_asn1_sequence(&mut cursor, &mut scratch).unwrap();
        assert_eq!(n, 203);
        assert_eq!(&scratch[..], &data[..]);
    }

    #[test]
    fn asn1_two_byte_long_form_length() {
        // 0x82 0x04 0x00 = 1024 bytes content
        let mut data = vec![0x30, 0x82, 0x04, 0x00];
        data.extend_from_slice(&vec![0x77; 1024]);
        let mut cursor = Cursor::new(data.clone());
        let mut scratch = Vec::new();
        let n = read_asn1_sequence(&mut cursor, &mut scratch).unwrap();
        assert_eq!(n, 1028);
        assert_eq!(scratch, data);
    }

    #[test]
    fn asn1_rejects_non_sequence_tag() {
        let data = vec![0x04, 0x01, 0xAA]; // OCTET STRING, not SEQUENCE
        let mut cursor = Cursor::new(data);
        let mut scratch = Vec::new();
        let err = read_asn1_sequence(&mut cursor, &mut scratch).unwrap_err();
        match err {
            ConnectError::Tcp(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            _ => panic!("expected Tcp(InvalidData), got {err:?}"),
        }
    }

    #[test]
    fn asn1_rejects_oversized_length() {
        // Claims 0xFFFFFFFF content bytes — way over MAX_PDU_SIZE (16 MiB)
        let data = vec![0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut cursor = Cursor::new(data);
        let mut scratch = Vec::new();
        let err = read_asn1_sequence(&mut cursor, &mut scratch).unwrap_err();
        assert!(matches!(err, ConnectError::FrameTooLarge(_)));
    }

    #[test]
    fn asn1_eof_mid_content_returns_unexpected_eof() {
        // Claims 10 bytes but only 3 follow
        let data = vec![0x30, 0x0A, 0x01, 0x02, 0x03];
        let mut cursor = Cursor::new(data);
        let mut scratch = Vec::new();
        let err = read_asn1_sequence(&mut cursor, &mut scratch).unwrap_err();
        assert!(matches!(err, ConnectError::UnexpectedEof));
    }

    #[test]
    fn asn1_rejects_5_byte_length_indicator() {
        // 0x85 = 5 following length bytes (we cap at 4)
        let data = vec![0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut cursor = Cursor::new(data);
        let mut scratch = Vec::new();
        let err = read_asn1_sequence(&mut cursor, &mut scratch).unwrap_err();
        match err {
            ConnectError::Tcp(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            _ => panic!("expected Tcp(InvalidData), got {err:?}"),
        }
    }

    #[test]
    fn asn1_three_byte_long_form_length() {
        // 0x83 0x01 0x00 0x01 = 65537 content bytes
        let mut data = vec![0x30, 0x83, 0x01, 0x00, 0x01];
        data.extend(std::iter::repeat_n(0x55, 65_537));
        let mut cursor = Cursor::new(data.clone());
        let mut scratch = Vec::new();
        let n = read_asn1_sequence(&mut cursor, &mut scratch).unwrap();
        assert_eq!(n, 65_537 + 5);
        assert_eq!(scratch, data);
    }

    #[test]
    fn asn1_four_byte_long_form_length() {
        // 0x84 0x00 0x10 0x00 0x00 = 1 MiB content. Verifies the 4-byte
        // length-of-length branch and the shift accumulator order.
        let payload_len = 1024 * 1024;
        let mut data = vec![0x30, 0x84, 0x00, 0x10, 0x00, 0x00];
        data.extend(std::iter::repeat_n(0x33, payload_len));
        let mut cursor = Cursor::new(data.clone());
        let mut scratch = Vec::new();
        let n = read_asn1_sequence(&mut cursor, &mut scratch).unwrap();
        assert_eq!(n, payload_len + 6);
        assert_eq!(&scratch[..6], &[0x30, 0x84, 0x00, 0x10, 0x00, 0x00]);
        assert_eq!(scratch.len(), n);
    }

    #[test]
    fn asn1_rejects_indefinite_length_indicator() {
        // 0x80 (indefinite length) is forbidden in DER and our framer
        // must reject it because num_length_bytes == 0 indicates an
        // indefinite-length encoding.
        let data = vec![0x30, 0x80, 0x00, 0x00];
        let mut cursor = Cursor::new(data);
        let mut scratch = Vec::new();
        let err = read_asn1_sequence(&mut cursor, &mut scratch).unwrap_err();
        match err {
            ConnectError::Tcp(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            _ => panic!("expected Tcp(InvalidData), got {err:?}"),
        }
    }

    #[test]
    fn read_pdu_fast_path_branch_reads_complete_frame() {
        // Hint reports `(true, 5)` so the fast-path `(true, size)` arm
        // of read_pdu is exercised. Both branches share the read loop
        // but the public `is_fast_path` flag must propagate so future
        // refactors of read_pdu cannot silently break the fast-path
        // discriminator.
        let data = vec![0x80, 0x05, 0xAA, 0xBB, 0xCC];
        let mut cursor = Cursor::new(data.clone());
        let mut scratch = Vec::new();
        let n = read_pdu(&mut cursor, &FastPathHint(5), &mut scratch).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&scratch[..n], &data[..]);
    }
}
