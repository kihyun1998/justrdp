#![forbid(unsafe_code)]

//! Unified bulk compression/decompression dispatcher.
//!
//! Provides [`BulkDecompressor`] which automatically dispatches to the
//! correct algorithm based on the compression type nibble in the
//! `compressedType` byte from the PDU header.
//!
//! Supported algorithms:
//! - MPPC 8K (type 0x0, RDP 4.0)
//! - MPPC 64K (type 0x1, RDP 5.0)
//! - NCRUSH (type 0x2, RDP 6.0)
//! - XCRUSH (type 0x3, RDP 6.1)
//!
//! ZGFX (type 0x4, RDP 8.0) uses a separate framing and is accessed
//! directly via [`crate::zgfx::ZgfxDecompressor`].

use alloc::vec::Vec;

use crate::mppc::{
    DecompressError, Mppc64kDecompressor, Mppc8kDecompressor, COMPRESSION_TYPE_MASK,
    PACKET_COMPR_TYPE_64K, PACKET_COMPR_TYPE_8K,
};
use crate::ncrush::{NcrushDecompressor, PACKET_COMPR_TYPE_RDP6};
use crate::xcrush::XcrushDecompressor;

/// XCRUSH compression type nibble (MS-RDPBCGR §2.2.8.1.1.1.2).
const PACKET_COMPR_TYPE_RDP61: u8 = 0x03;

/// Unified bulk decompressor for standard RDP compression algorithms.
///
/// Maintains persistent state for each algorithm (history buffers, caches)
/// across multiple PDU decompressions on the same connection.
///
/// # Usage
///
/// ```ignore
/// let mut bulk = BulkDecompressor::new();
/// let mut output = Vec::new();
/// // compressed_type comes from TS_SHAREDATAHEADER.compressedType
/// // or TS_FP_UPDATE.compressionFlags
/// bulk.decompress(compressed_type, &payload, &mut output)?;
/// ```
pub struct BulkDecompressor {
    mppc8k: Mppc8kDecompressor,
    mppc64k: Mppc64kDecompressor,
    ncrush: NcrushDecompressor,
    xcrush: XcrushDecompressor,
}

impl BulkDecompressor {
    /// Create a new bulk decompressor with all algorithms initialized.
    pub fn new() -> Self {
        Self {
            mppc8k: Mppc8kDecompressor::new(),
            mppc64k: Mppc64kDecompressor::new(),
            ncrush: NcrushDecompressor::new(),
            xcrush: XcrushDecompressor::new(),
        }
    }

    /// Decompress a PDU payload.
    ///
    /// `compressed_type` is the `compressedType` byte from the PDU header
    /// (e.g., `TS_SHAREDATAHEADER`, `TS_FP_UPDATE`, or `CHANNEL_PDU_HEADER`).
    /// The lower nibble selects the algorithm; the upper bits carry flags
    /// (`PACKET_COMPRESSED`, `PACKET_AT_FRONT`, `PACKET_FLUSHED`).
    ///
    /// `src` is the compressed payload (after the PDU header).
    /// Decompressed output is appended to `dst`.
    pub fn decompress(
        &mut self,
        compressed_type: u8,
        src: &[u8],
        dst: &mut Vec<u8>,
    ) -> Result<(), DecompressError> {
        let algo = compressed_type & COMPRESSION_TYPE_MASK;

        match algo {
            PACKET_COMPR_TYPE_8K => {
                self.mppc8k.decompress(src, compressed_type, dst)
            }
            PACKET_COMPR_TYPE_64K => {
                self.mppc64k.decompress(src, compressed_type, dst)
            }
            PACKET_COMPR_TYPE_RDP6 => {
                self.ncrush.decompress(src, compressed_type, dst)
            }
            PACKET_COMPR_TYPE_RDP61 => {
                // XCRUSH expects Level1ComprFlags + Level2ComprFlags in src.
                // The outer compressedType is only used to identify the algorithm.
                self.xcrush.decompress(src, dst)
            }
            _ => Err(DecompressError::UnknownCompressionType),
        }
    }
}

impl Default for BulkDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for BulkDecompressor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BulkDecompressor").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mppc::{PACKET_COMPRESSED, PACKET_FLUSHED};

    #[test]
    fn mppc8k_dispatch() {
        let mut bulk = BulkDecompressor::new();
        let mut out = Vec::new();
        // Uncompressed payload via MPPC 8K
        let flags = PACKET_FLUSHED | PACKET_COMPR_TYPE_8K;
        bulk.decompress(flags, b"hello", &mut out).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn mppc64k_dispatch() {
        let mut bulk = BulkDecompressor::new();
        let mut out = Vec::new();
        let flags = PACKET_FLUSHED | PACKET_COMPR_TYPE_64K;
        bulk.decompress(flags, b"world", &mut out).unwrap();
        assert_eq!(out, b"world");
    }

    #[test]
    fn ncrush_dispatch() {
        let mut bulk = BulkDecompressor::new();
        let mut out = Vec::new();
        let flags = PACKET_FLUSHED | PACKET_COMPR_TYPE_RDP6;
        bulk.decompress(flags, b"test", &mut out).unwrap();
        assert_eq!(out, b"test");
    }

    #[test]
    fn xcrush_dispatch() {
        let mut bulk = BulkDecompressor::new();
        let mut out = Vec::new();
        // XCRUSH payload with L1_NO_COMPRESSION + L1_PACKET_AT_FRONT
        let payload: &[u8] = &[
            0x06, // L1_NO_COMPRESSION | L1_PACKET_AT_FRONT
            0x00, // Level2ComprFlags (ignored)
            0x58, 0x59, // "XY"
        ];
        let flags = PACKET_COMPRESSED | PACKET_COMPR_TYPE_RDP61;
        bulk.decompress(flags, payload, &mut out).unwrap();
        assert_eq!(out, b"XY");
    }

    #[test]
    fn unsupported_type_returns_error() {
        let mut bulk = BulkDecompressor::new();
        let mut out = Vec::new();
        let flags = PACKET_COMPRESSED | 0x0F; // type nibble 0x0F = unsupported
        let result = bulk.decompress(flags, b"data", &mut out);
        assert_eq!(result, Err(DecompressError::UnknownCompressionType));
    }

    #[test]
    fn state_persists_across_calls() {
        let mut bulk = BulkDecompressor::new();

        // First call: write "abc" to MPPC 64K history
        let mut out1 = Vec::new();
        let flags1 = PACKET_FLUSHED | PACKET_COMPR_TYPE_64K;
        bulk.decompress(flags1, b"abc", &mut out1).unwrap();
        assert_eq!(out1, b"abc");

        // Second call: uncompressed "de" appended to history
        let mut out2 = Vec::new();
        let flags2 = PACKET_COMPR_TYPE_64K; // no FLUSHED, no COMPRESSED
        bulk.decompress(flags2, b"de", &mut out2).unwrap();
        assert_eq!(out2, b"de");
    }
}
