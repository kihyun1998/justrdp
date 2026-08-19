//! Phase-1 EGFX bulk decompression (ADR-0003 bootstrap): zgfx, backed by `ironrdp-graphics`
//! behind this crate's own type so the core never names an oracle type. It will be replaced by a
//! self-owned decoder verified against the same crate as a differential oracle, after which the
//! `egfx-bootstrap` feature drops the runtime dependency entirely (ADR-0003 phases 2-3).
//!
//! **zgfx is the last one here.** ClearCodec crossed the line first and moved out to
//! [`crate::clearcodec`]; RemoteFX Progressive crossed it in #171 and was wired in over this
//! wrapper in #172, so [`crate::rfx::progressive::Progressive`] is now the only Progressive
//! decoder in the tree — self-owned, ungated, and gated on a real-server corpus rather than on
//! the oracle (ADR-0011). The corpus *capture* harness this module used to carry moved with it,
//! to [`crate::capture`], which is ungated for that reason.

use ironrdp_graphics::zgfx;

/// Why an EGFX codec stage failed. Carries the bootstrap decoder's message — the typed
/// distinctions that matter (which stage) are ours; the details are diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgfxCodecError {
    /// RDP_SEGMENTED_DATA / RDP8 bulk (zgfx) decompression failed.
    Zgfx(String),
}

impl core::fmt::Display for EgfxCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EgfxCodecError::Zgfx(e) => write!(f, "zgfx decompression: {e}"),
        }
    }
}

impl core::error::Error for EgfxCodecError {}

/// Stateful zgfx (RDP8 bulk) decompressor — one per EGFX channel; the 2.5 MB history window
/// spans messages, so segments must be fed in arrival order.
pub struct Zgfx {
    inner: zgfx::Decompressor,
}

impl Zgfx {
    /// A decompressor with an empty history window.
    pub fn new() -> Self {
        Self {
            inner: zgfx::Decompressor::new(),
        }
    }

    /// Decompress one RDP_SEGMENTED_DATA message (single or multipart) into `output`, which
    /// is cleared first. Callers reuse one buffer across messages, keeping the per-message
    /// allocation off the hot path (#86).
    pub fn decompress_into(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), EgfxCodecError> {
        output.clear();
        self.inner
            .decompress(input, output)
            .map(|_| ())
            .map_err(|e| EgfxCodecError::Zgfx(e.to_string()))
    }

    /// [`Self::decompress_into`] with a freshly allocated buffer per call.
    pub fn decompress(&mut self, input: &[u8]) -> Result<Vec<u8>, EgfxCodecError> {
        let mut output = Vec::new();
        self.decompress_into(input, &mut output)?;
        Ok(output)
    }
}

impl Default for Zgfx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zgfx_unwraps_uncompressed_single_segments() {
        // Descriptor 0xE0, bulk header 0x04 (RDP8, COMPRESSED clear), raw data — the same
        // wrapping justrdp-pdu's `egfx::wrap_uncompressed` emits.
        let mut z = Zgfx::new();
        let out = z.decompress(&[0xE0, 0x04, 1, 2, 3, 4]).unwrap();
        assert_eq!(out, vec![1, 2, 3, 4]);
    }

    #[test]
    fn zgfx_round_trips_the_oracle_compressor() {
        // Compress with the oracle's compressor (full segment wrapping, COMPRESSED set),
        // decompress with our wrapper: proves the wrapper drives the stateful API correctly
        // (history window shared across calls).
        use ironrdp_graphics::zgfx::{CompressionMode, compress_and_wrap_egfx};
        let mut compressor = ironrdp_graphics::zgfx::Compressor::new();
        let mut z = Zgfx::new();
        for message in [
            &b"the quick brown fox jumps over the lazy dog"[..],
            &[7u8; 4096],
        ] {
            let wire =
                compress_and_wrap_egfx(message, &mut compressor, CompressionMode::Always).unwrap();
            assert_eq!(z.decompress(&wire).unwrap(), message);
        }
    }

    #[test]
    fn zgfx_decompress_into_clears_and_reuses_the_buffer() {
        let mut z = Zgfx::new();
        let mut buf = vec![0xAA; 7]; // stale content from a previous message
        z.decompress_into(&[0xE0, 0x04, 1, 2], &mut buf).unwrap();
        assert_eq!(buf, vec![1, 2]);
        z.decompress_into(&[0xE0, 0x04, 3], &mut buf).unwrap();
        assert_eq!(buf, vec![3]);
    }

    #[test]
    fn zgfx_garbage_is_a_typed_error() {
        let mut z = Zgfx::new();
        assert!(matches!(
            z.decompress(&[0x00, 0x01]),
            Err(EgfxCodecError::Zgfx(_))
        ));
    }
}
