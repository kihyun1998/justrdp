//! Phase-1 EGFX decoders (ADR-0003 bootstrap): zgfx bulk decompression, RemoteFX
//! Progressive, and ClearCodec, backed by `ironrdp-graphics` behind this crate's own types so
//! the core never names oracle types. Each will be replaced by a self-owned decoder verified
//! against the same crate as a differential oracle, then the `egfx-bootstrap` feature gate
//! drops the runtime dependency (ADR-0003 phases 2–3).

use ironrdp_graphics::clearcodec::ClearCodecDecoder;
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
    /// The ClearCodec bitmap stream failed to decode.
    Clear(String),
}

impl core::fmt::Display for EgfxCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EgfxCodecError::Zgfx(e) => write!(f, "zgfx decompression: {e}"),
            EgfxCodecError::Progressive(e) => write!(f, "RemoteFX Progressive decode: {e}"),
            EgfxCodecError::Clear(e) => write!(f, "ClearCodec decode: {e}"),
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

    /// Decompress one RDP_SEGMENTED_DATA message (single or multipart) into the raw EGFX
    /// PDU blob it carries.
    pub fn decompress(&mut self, input: &[u8]) -> Result<Vec<u8>, EgfxCodecError> {
        let mut output = Vec::new();
        self.inner
            .decompress(input, &mut output)
            .map_err(|e| EgfxCodecError::Zgfx(e.to_string()))?;
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

/// Stateful ClearCodec decoder — the V-bar / glyph caches persist across PDUs.
pub struct Clear {
    inner: ClearCodecDecoder,
}

impl Clear {
    /// A decoder with empty caches.
    pub fn new() -> Self {
        Self {
            inner: ClearCodecDecoder::new(),
        }
    }

    /// Decode one ClearCodec bitmap stream into `width × height × 4` **BGRA** bytes
    /// (alpha forced to 0xFF — the wire format carries no alpha).
    ///
    /// When `JUSTRDP_CLEAR_CAPTURE_DIR` is set, the raw payload and its decode status are
    /// dumped there first (see [`capture_clear_payload`]) — the corpus harness for the #56
    /// self-owned rewrite, which needs the very streams this bootstrap oracle rejects.
    pub fn decode_to_bgra(
        &mut self,
        data: &[u8],
        width: u16,
        height: u16,
    ) -> Result<Vec<u8>, EgfxCodecError> {
        let result = self
            .inner
            .decode(data, width, height)
            .map_err(|e| EgfxCodecError::Clear(e.to_string()));
        // An *empty* value counts as unset — otherwise `Path::new("")` resolves to the
        // process CWD and litters it with `clear-*.bin`.
        if let Ok(dir) = std::env::var("JUSTRDP_CLEAR_CAPTURE_DIR")
            && !dir.is_empty()
        {
            let status = match &result {
                Ok(_) => String::from("ok"),
                Err(e) => format!("err:{e}"),
            };
            capture_clear_payload(&dir, data, width, height, &status);
        }
        result
    }
}

/// Test-only corpus capture, gated by the `JUSTRDP_CLEAR_CAPTURE_DIR` env var: append one
/// ClearCodec payload (`clear-NNNN.bin`) plus a manifest row (`idx⇥w⇥h⇥len⇥status`) to that
/// directory. It exists so a live real-VM session can harvest the fixture corpus for the #56
/// self-owned ClearCodec rewrite — crucially the streams the bootstrap oracle *rejects*, which
/// a differential test cannot arbitrate (the oracle is the thing that is wrong). Best-effort:
/// any IO error is swallowed so capture never perturbs the live decode path.
fn capture_clear_payload(dir: &str, data: &[u8], width: u16, height: u16, status: &str) {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let idx = SEQ.fetch_add(1, Ordering::Relaxed);

    let dir = std::path::Path::new(dir);
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let _ = std::fs::write(dir.join(format!("clear-{idx:04}.bin")), data);
    if let Ok(mut manifest) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("manifest.tsv"))
    {
        let _ = writeln!(
            manifest,
            "{idx:04}\t{width}\t{height}\t{}\t{status}",
            data.len()
        );
    }
}

impl Default for Clear {
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
    fn zgfx_garbage_is_a_typed_error() {
        let mut z = Zgfx::new();
        assert!(matches!(
            z.decompress(&[0x00, 0x01]),
            Err(EgfxCodecError::Zgfx(_))
        ));
    }

    #[test]
    fn clear_codec_round_trips_the_oracle_encoder() {
        let mut encoder = ironrdp_graphics::clearcodec::ClearCodecEncoder::new();
        // 4×2 solid color in BGRA.
        let bgra: Vec<u8> = (0..8).flat_map(|_| [10u8, 20, 30, 255]).collect();
        let stream = encoder.encode(&bgra, 4, 2);
        let mut clear = Clear::new();
        let decoded = clear.decode_to_bgra(&stream, 4, 2).unwrap();
        assert_eq!(decoded, bgra);
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
