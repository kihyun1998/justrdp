#![forbid(unsafe_code)]

//! Synchronous framing helper.
//!
//! Reads exactly one PDU from a [`Read`] source using a
//! [`justrdp_core::PduHint`] to determine the frame boundary.

use std::io::Read;

use justrdp_core::PduHint;

use crate::error::ConnectError;

/// Hard cap on a single PDU to prevent runaway allocations.
/// 16 MiB matches common RDP server output limits (MS-RDPBCGR 1.3.7).
pub const MAX_PDU_SIZE: usize = 16 * 1024 * 1024;

/// Read exactly one PDU from `reader` into `scratch`, using `hint` to
/// determine the frame size.
///
/// Returns the complete PDU bytes as a slice of `scratch` (`&scratch[..len]`).
/// On EOF mid-frame returns [`ConnectError::UnexpectedEof`].
pub fn read_pdu<R: Read>(
    reader: &mut R,
    hint: &dyn PduHint,
    scratch: &mut Vec<u8>,
) -> Result<usize, ConnectError> {
    scratch.clear();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Fixed-size hint: always expects `n` bytes.
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
}
