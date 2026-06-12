//! Phase-1 EGFX decoders (ADR-0003 bootstrap): zgfx bulk decompression and RemoteFX
//! Progressive, backed by `ironrdp-graphics` behind this crate's own types so the core never
//! names oracle types. Each will be replaced by a self-owned decoder verified against the same
//! crate as a differential oracle, then the `egfx-bootstrap` feature gate drops the runtime
//! dependency (ADR-0003 phases 2–3). ClearCodec already crossed that line and moved out of this
//! feature-gated module entirely — it now lives, self-owned and ungated, in
//! [`crate::clearcodec`].

use ironrdp_graphics::progressive::ProgressiveDecoder;
use ironrdp_graphics::zgfx;

/// Why an EGFX codec stage failed. Carries the bootstrap decoder's message — the typed
/// distinctions that matter (which stage) are ours; the details are diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgfxCodecError {
    /// RDP_SEGMENTED_DATA / RDP8 bulk (zgfx) decompression failed.
    Zgfx(String),
    /// The RemoteFX Progressive block stream failed to decode.
    Progressive(String),
}

impl core::fmt::Display for EgfxCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EgfxCodecError::Zgfx(e) => write!(f, "zgfx decompression: {e}"),
            EgfxCodecError::Progressive(e) => write!(f, "RemoteFX Progressive decode: {e}"),
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

/// One decoded 64×64 Progressive tile: grid coordinates plus RGBA pixels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressiveTile {
    /// Tile column in the surface's 64-pixel grid.
    pub x_idx: u16,
    /// Tile row in the surface's 64-pixel grid.
    pub y_idx: u16,
    /// 64×64 RGBA pixels (16384 bytes).
    pub rgba: Vec<u8>,
}

/// Stateful RemoteFX Progressive decoder — per-context tile state survives across
/// WireToSurface2 PDUs (first pass + upgrade passes refine the same coefficients).
pub struct Progressive {
    inner: ProgressiveDecoder,
}

impl Progressive {
    /// A decoder with no codec contexts.
    pub fn new() -> Self {
        Self {
            inner: ProgressiveDecoder::new(),
        }
    }

    /// Decode one WireToSurface2 block stream, returning every tile the pass updated.
    pub fn decode(
        &mut self,
        codec_context_id: u32,
        surface_width: u16,
        surface_height: u16,
        data: &[u8],
    ) -> Result<Vec<ProgressiveTile>, EgfxCodecError> {
        let tiles = self
            .inner
            .decode_bitmap(codec_context_id, surface_width, surface_height, data)
            .map_err(|e| EgfxCodecError::Progressive(e.to_string()))?;
        Ok(tiles
            .into_iter()
            .map(|t| ProgressiveTile {
                x_idx: t.x_idx,
                y_idx: t.y_idx,
                rgba: t.pixels,
            })
            .collect())
    }

    /// Free a codec context (`RDPGFX_CMDID_DELETEENCODINGCONTEXT`).
    pub fn delete_context(&mut self, codec_context_id: u32) {
        self.inner.delete_context(codec_context_id);
    }
}

impl Default for Progressive {
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

    #[test]
    fn progressive_rejects_garbage_streams() {
        let mut p = Progressive::new();
        assert!(matches!(
            p.decode(1, 64, 64, &[0xFF; 16]),
            Err(EgfxCodecError::Progressive(_))
        ));
    }
}
