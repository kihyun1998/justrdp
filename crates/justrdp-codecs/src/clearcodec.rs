//! Self-owned ClearCodec decoder (MS-RDPEGFX 2.2.4.1) — ADR-0003 phase 2.
//!
//! ClearCodec is a mandatory lossless EGFX tile codec built from three composited layers:
//! a residual BGR run-length background, a *bands* layer of cached vertical columns
//! ("V-bars") tuned for text glyphs, and a *subcodec* layer (raw BGR / NSCodec / RLEX) for
//! arbitrary rectangles. A persistent V-bar cache and a glyph cache span PDUs.
//!
//! This decoder is re-derived from the MS-RDPEGFX spec and cross-checked against FreeRDP's
//! `clear.c`; it does **not** depend on `ironrdp-graphics`. Correctness on streams the oracle
//! also accepts is proven differentially (`tests/clearcodec_*`). Two places diverge from the
//! bootstrap oracle — one an oracle defect we correct, one a deliberate tolerance choice:
//!
//! 1. **SHORT_VBAR_CACHE_MISS field layout.** The 14 payload bits are `shortVBarYOn` in bits
//!    `[7:0]` and `shortVBarYOff` in bits `[13:8]` (FreeRDP `vBarYOn = h & 0xFF`,
//!    `vBarYOff = (h >> 8) & 0x3F`). The oracle reads them swapped (`yOn = h >> 6`,
//!    `yOff = h & 0x3F`), so on real streams `yOn` routinely exceeds the 6-bit `yOff` and it
//!    rejects with `shortVBarYOff < shortVBarYOn`. Fixing the layout also repopulates the full
//!    V-bar cache correctly, which transitively removes the oracle's `vbarIndex` "cache miss on
//!    hit" rejection (bands that previously aborted mid-decode now finish and store their
//!    columns).
//!
//! 2. **RLEX region over-fill is clipped, not fatal.** A captured real Windows Server 2022
//!    stream over-fills its RLEX region (replay corpus entry 0). FreeRDP `clear.c` and the
//!    ironrdp oracle both *reject* an over-region run/suite (`:260`/`:286`/`:321`), but a client
//!    must not drop a live frame over a server's over-encode, so we clip the surplus at the
//!    region boundary (and short-fill under-runs). This is backed by the capture, **not** by
//!    FreeRDP — an earlier comment mis-attributed it as "FreeRDP parity" (#120).
//!
//! **Alpha contract:** ClearCodec carries no alpha; every output pixel's alpha byte is `0xFF`.

use std::fmt;

// --- Stream flags (MS-RDPEGFX 2.2.4.1) ---

const FLAG_GLYPH_INDEX: u8 = 0x01;
const FLAG_GLYPH_HIT: u8 = 0x02;
const FLAG_CACHE_RESET: u8 = 0x04;

// --- Cache and dimension limits ---

/// Glyph cache capacity; glyph indices are valid in `0..GLYPH_CACHE_SIZE`.
const GLYPH_CACHE_SIZE: u16 = 4_000;
/// Full V-bar storage capacity (ring buffer).
const VBAR_CACHE_SIZE: usize = 32_768;
/// Short V-bar storage capacity (ring buffer).
const SHORT_VBAR_CACHE_SIZE: usize = 16_384;
/// Maximum band height per spec.
const MAX_BAND_HEIGHT: u16 = 52;
/// Maximum palette entries for the RLEX subcodec.
const MAX_PALETTE_COUNT: u8 = 127;
/// Per-axis tile dimension cap, mirroring the bootstrap decoder's OOM guard: rejects
/// implausible tile shapes (e.g. 63961x771) regardless of total area before allocation.
const MAX_DECODE_DIM: u16 = 8_192;
/// Glyph cache stores tiles no larger than this many pixels.
const MAX_GLYPH_PIXELS: usize = 1_024;

/// Why a ClearCodec stream failed to decode. Malformed input is always a typed error, never a
/// panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearError {
    /// The stream ended inside a field of `ctx`.
    NotEnoughBytes {
        /// The structure being parsed when the buffer underflowed.
        ctx: &'static str,
    },
    /// A field held a value the spec forbids.
    InvalidField {
        /// The offending field name.
        field: &'static str,
        /// Why it is invalid.
        reason: &'static str,
    },
}

impl fmt::Display for ClearError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClearError::NotEnoughBytes { ctx } => write!(f, "not enough bytes for {ctx}"),
            ClearError::InvalidField { field, reason } => write!(f, "invalid `{field}`: {reason}"),
        }
    }
}

impl std::error::Error for ClearError {}

fn invalid(field: &'static str, reason: &'static str) -> ClearError {
    ClearError::InvalidField { field, reason }
}

// --- Minimal length-checked cursor (the crate does not depend on justrdp-pdu) ---

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn ensure(&self, size: usize, ctx: &'static str) -> Result<(), ClearError> {
        if self.remaining() < size {
            Err(ClearError::NotEnoughBytes { ctx })
        } else {
            Ok(())
        }
    }

    fn u8(&mut self) -> u8 {
        let b = self.data[self.pos];
        self.pos += 1;
        b
    }

    fn u16_le(&mut self) -> u16 {
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        v
    }

    fn u32_le(&mut self) -> u32 {
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        v
    }

    fn slice(&mut self, n: usize) -> &'a [u8] {
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        s
    }
}

/// A variable-length run length shared by the residual and RLEX layers: a single byte, or
/// `0xFF` then a u16, or `0xFF 0xFFFF` then a u32.
fn read_run_length(c: &mut Cursor<'_>, ctx: &'static str) -> Result<u32, ClearError> {
    c.ensure(1, ctx)?;
    let factor1 = c.u8();
    if factor1 < 0xFF {
        return Ok(u32::from(factor1));
    }
    c.ensure(2, ctx)?;
    let factor2 = c.u16_le();
    if factor2 < 0xFFFF {
        return Ok(u32::from(factor2));
    }
    c.ensure(4, ctx)?;
    Ok(c.u32_le())
}

// --- Persistent cache state ---

/// A cached short V-bar: only the covered pixels persist — the `yOn` offset is supplied by
/// each cache-hit header, never by the cache (MS-RDPEGFX 2.2.4.1.1.2.1.1.2).
#[derive(Clone)]
struct ShortVBar {
    /// BGR pixel data, 3 bytes per covered row.
    pixels: Vec<u8>,
}

#[derive(Clone)]
struct FullVBar {
    /// BGR pixel data, `band_height * 3` bytes.
    pixels: Vec<u8>,
}

#[derive(Clone)]
struct GlyphEntry {
    width: u16,
    height: u16,
    /// BGRA pixel data.
    pixels: Vec<u8>,
}

/// Stateful ClearCodec wrapper — the V-bar / glyph caches persist across PDUs.
///
/// This is the API the EGFX core consumes (`new` + `decode_to_bgra`). It is intentionally
/// **ungated** — ClearCodec no longer rides the `egfx-bootstrap` feature, since its decoder
/// ([`ClearDecoder`]) owns every layer and pulls in no `ironrdp-graphics`. The wrapper also
/// hosts the corpus-capture hook.
pub struct Clear {
    inner: ClearDecoder,
}

impl Default for Clear {
    fn default() -> Self {
        Self::new()
    }
}

impl Clear {
    /// A decoder with empty caches.
    pub fn new() -> Self {
        Self {
            inner: ClearDecoder::new(),
        }
    }

    /// Decode one ClearCodec bitmap stream into `width × height × 4` **BGRA** bytes
    /// (alpha forced to 0xFF — the wire format carries no alpha).
    ///
    /// When `JUSTRDP_CLEAR_CAPTURE_DIR` is set, the raw payload and its decode status are
    /// dumped there first (see [`capture_clear_payload`]) — the corpus harness for the #56
    /// rewrite, which needs the very streams the bootstrap oracle rejects.
    pub fn decode_to_bgra(
        &mut self,
        data: &[u8],
        width: u16,
        height: u16,
    ) -> Result<Vec<u8>, ClearError> {
        let result = self.inner.decode(data, width, height);
        // An *empty* value counts as unset — otherwise `Path::new("")` resolves to the process
        // CWD and litters it with `clear-*.bin`.
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
/// rewrite — crucially the streams the bootstrap oracle *rejects*, which a differential test
/// cannot arbitrate. Best-effort: any IO error is swallowed so capture never perturbs decoding.
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

/// A ClearCodec decoder holding the V-bar and glyph caches that persist across frames.
pub struct ClearDecoder {
    vbar_storage: Vec<Option<FullVBar>>,
    short_vbar_storage: Vec<Option<ShortVBar>>,
    glyph_storage: Vec<Option<GlyphEntry>>,
    vbar_cursor: u16,
    short_vbar_cursor: u16,
}

impl Default for ClearDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClearDecoder {
    /// A decoder with empty caches.
    pub fn new() -> Self {
        let mut vbar_storage = Vec::new();
        vbar_storage.resize_with(VBAR_CACHE_SIZE, || None);
        let mut short_vbar_storage = Vec::new();
        short_vbar_storage.resize_with(SHORT_VBAR_CACHE_SIZE, || None);
        let mut glyph_storage = Vec::new();
        glyph_storage.resize_with(usize::from(GLYPH_CACHE_SIZE), || None);
        Self {
            vbar_storage,
            short_vbar_storage,
            glyph_storage,
            vbar_cursor: 0,
            short_vbar_cursor: 0,
        }
    }

    /// Decode one ClearCodec bitmap stream into `width × height × 4` BGRA bytes (alpha `0xFF`).
    pub fn decode(&mut self, data: &[u8], width: u16, height: u16) -> Result<Vec<u8>, ClearError> {
        let mut c = Cursor::new(data);
        c.ensure(2, "ClearCodecBitmapStream")?;
        let flags = c.u8();
        let _seq_number = c.u8();

        let glyph_index = if flags & FLAG_GLYPH_INDEX != 0 {
            c.ensure(2, "ClearCodecBitmapStream")?;
            Some(c.u16_le())
        } else {
            None
        };

        if flags & FLAG_CACHE_RESET != 0 {
            // Only the cursors reset; existing entries are overwritten from index 0.
            self.vbar_cursor = 0;
            self.short_vbar_cursor = 0;
        }

        if let Some(idx) = glyph_index
            && idx >= GLYPH_CACHE_SIZE
        {
            return Err(invalid("glyphIndex", "glyph index out of range 0-3999"));
        }

        let pixel_count = usize::from(width)
            .checked_mul(usize::from(height))
            .ok_or_else(|| invalid("dimensions", "width * height overflow"))?;

        // Glyph hit: return the cached tile verbatim, no payload follows.
        if flags & FLAG_GLYPH_HIT != 0 {
            let idx =
                glyph_index.ok_or_else(|| invalid("flags", "GLYPH_HIT without GLYPH_INDEX"))?;
            let entry = self
                .glyph_get(idx)
                .ok_or_else(|| invalid("glyphIndex", "glyph cache miss on hit"))?;
            if entry.width != width || entry.height != height {
                return Err(invalid("glyphIndex", "cached glyph dimensions mismatch"));
            }
            return Ok(entry.pixels.clone());
        }

        if width > MAX_DECODE_DIM || height > MAX_DECODE_DIM {
            return Err(invalid(
                "dimensions",
                "width or height exceeds 8192-pixel decoder limit",
            ));
        }

        let mut output = vec![0u8; pixel_count * 4];

        // A composite payload is present unless the buffer is already spent (a cache-reset-only
        // message has no payload).
        if !c.is_empty() {
            self.decode_composite(&mut c, &mut output, width)?;
        }

        // Cache small tiles for later glyph hits.
        if flags & FLAG_GLYPH_INDEX != 0
            && let Some(idx) = glyph_index
            && pixel_count <= MAX_GLYPH_PIXELS
        {
            self.glyph_store(
                idx,
                GlyphEntry {
                    width,
                    height,
                    pixels: output.clone(),
                },
            );
        }

        Ok(output)
    }

    fn decode_composite(
        &mut self,
        c: &mut Cursor<'_>,
        output: &mut [u8],
        width: u16,
    ) -> Result<(), ClearError> {
        c.ensure(12, "CompositePayload")?;
        let residual_count = cast_usize(c.u32_le());
        let bands_count = cast_usize(c.u32_le());
        let subcodec_count = cast_usize(c.u32_le());

        let total = residual_count
            .checked_add(bands_count)
            .and_then(|s| s.checked_add(subcodec_count))
            .ok_or_else(|| invalid("byteCount", "layer byte counts overflow"))?;
        c.ensure(total, "CompositePayload")?;

        let residual = c.slice(residual_count);
        let bands = c.slice(bands_count);
        let subcodec = c.slice(subcodec_count);

        self.decode_residual_layer(residual, output)?;
        self.decode_bands_layer(bands, output, width)?;
        self.decode_subcodec_layer(subcodec, output, width)?;
        Ok(())
    }

    /// Layer 1 — residual BGR run-length background, filling the whole tile row-major. Writes
    /// are clamped to the output to defeat adversarial run lengths (FreeRDP GHSA-32q9-m5qr-9j2v).
    fn decode_residual_layer(&self, data: &[u8], output: &mut [u8]) -> Result<(), ClearError> {
        if data.is_empty() {
            return Ok(());
        }
        let mut c = Cursor::new(data);
        let max_offset = output.len();
        let mut offset = 0usize;

        while c.remaining() >= 4 {
            let blue = c.u8();
            let green = c.u8();
            let red = c.u8();
            // The run length (the variable-length factor1..factor3 sequence) follows the BGR
            // triple and is read by the shared reader.
            let run_length = read_run_length(&mut c, "RgbRunSegment")?;

            let pixels_remaining = max_offset.saturating_sub(offset) / 4;
            let effective_run = u32::try_from(pixels_remaining)
                .unwrap_or(u32::MAX)
                .min(run_length);
            for _ in 0..effective_run {
                output[offset] = blue;
                output[offset + 1] = green;
                output[offset + 2] = red;
                output[offset + 3] = 0xFF;
                offset += 4;
            }
            if offset >= max_offset {
                break;
            }
        }
        Ok(())
    }

    /// Layer 2 — bands of cached vertical columns composited over the residual.
    fn decode_bands_layer(
        &mut self,
        data: &[u8],
        output: &mut [u8],
        width: u16,
    ) -> Result<(), ClearError> {
        if data.is_empty() {
            return Ok(());
        }
        let w = usize::from(width);
        let mut c = Cursor::new(data);

        while c.remaining() >= 11 {
            let x_start = c.u16_le();
            let x_end = c.u16_le();
            let y_start = c.u16_le();
            let y_end = c.u16_le();
            let bg_blue = c.u8();
            let bg_green = c.u8();
            let bg_red = c.u8();

            let band_height = y_end
                .checked_sub(y_start)
                .and_then(|h| h.checked_add(1))
                .ok_or_else(|| invalid("yEnd", "yEnd < yStart"))?;
            if band_height > MAX_BAND_HEIGHT {
                return Err(invalid("bandHeight", "band height exceeds 52"));
            }
            if x_end < x_start {
                return Err(invalid("xEnd", "xEnd < xStart"));
            }

            let column_count = usize::from(x_end - x_start) + 1;
            for col in 0..column_count {
                let slot = self.decode_vbar(&mut c, band_height, bg_blue, bg_green, bg_red)?;
                let x = usize::from(x_start) + col;
                if x >= w {
                    continue;
                }
                // The slot was just resolved/stored, so it is always populated; compositing
                // straight from storage avoids the per-column clone (#86).
                let Some(vbar) = self.vbar_storage.get(slot).and_then(|s| s.as_ref()) else {
                    continue;
                };
                // Clamp to the current band: a full V-bar CACHE_HIT (0x8000) reuses a stored column
                // verbatim, which may have been built for a taller band. FreeRDP `clear.c` clamps at
                // composite with `if (count > nHeight) count = nHeight`, so a tall column never
                // bleeds below a shorter band (#116).
                let rows = (vbar.pixels.len() / 3).min(usize::from(band_height));
                for row in 0..rows {
                    let y = usize::from(y_start) + row;
                    let dst = (y * w + x) * 4;
                    let src = row * 3;
                    if dst + 3 < output.len() && src + 2 < vbar.pixels.len() {
                        output[dst] = vbar.pixels[src];
                        output[dst + 1] = vbar.pixels[src + 1];
                        output[dst + 2] = vbar.pixels[src + 2];
                        output[dst + 3] = 0xFF;
                    }
                }
            }
        }
        Ok(())
    }

    /// Decode one V-bar header and resolve it (through the cache) into a full column,
    /// returning its `vbar_storage` slot — callers composite straight from storage, so the
    /// hit/store paths run without per-column clones (#86).
    fn decode_vbar(
        &mut self,
        c: &mut Cursor<'_>,
        band_height: u16,
        bg_blue: u8,
        bg_green: u8,
        bg_red: u8,
    ) -> Result<usize, ClearError> {
        c.ensure(2, "VBar")?;
        let header = c.u16_le();

        // Bit 15 set: full V-bar cache hit (read-only, no cursor advance).
        if header & 0x8000 != 0 {
            let index = header & 0x7FFF;
            return self
                .vbar_get(index)
                .map(|_| usize::from(index))
                .ok_or_else(|| invalid("vbarIndex", "V-bar cache miss on hit"));
        }

        // Bit 14 set: short V-bar cache hit — reuse cached pixels with this header's yOn.
        if header & 0x4000 != 0 {
            let index = header & 0x3FFF;
            c.ensure(1, "ShortVBarCacheHit")?;
            let y_on = c.u8();
            let cached = self
                .short_vbar_get(index)
                .ok_or_else(|| invalid("shortVbarIndex", "short V-bar cache miss on hit"))?;
            let full =
                reconstruct_full_vbar(y_on, &cached.pixels, band_height, bg_blue, bg_green, bg_red);
            return Ok(self.store_vbar(full));
        }

        // Both top bits clear: short V-bar cache miss with inline pixels.
        // CORRECTED field layout (MS-RDPEGFX 2.2.4.1.1.2.1.1.3, per FreeRDP `clear.c`):
        //   shortVBarYOn  = bits [7:0]   (8 bits)
        //   shortVBarYOff = bits [13:8]  (6 bits)
        // The bootstrap oracle reads these swapped and so rejects genuine streams.
        let y_on = (header & 0x00FF) as u8;
        let y_off = ((header >> 8) & 0x3F) as u8;
        if y_off < y_on {
            return Err(invalid(
                "shortVBarCacheMiss",
                "shortVBarYOff < shortVBarYOn",
            ));
        }
        if u16::from(y_off) > band_height {
            return Err(invalid(
                "shortVBarCacheMiss",
                "shortVBarYOff exceeds band height",
            ));
        }

        let pixel_count = y_off - y_on;
        let pixel_byte_count = usize::from(pixel_count) * 3;
        c.ensure(pixel_byte_count, "ShortVBarCacheMiss")?;
        let pixels = c.slice(pixel_byte_count).to_vec();

        let full = reconstruct_full_vbar(y_on, &pixels, band_height, bg_blue, bg_green, bg_red);
        self.store_short_vbar(ShortVBar { pixels });
        Ok(self.store_vbar(full))
    }

    /// Layer 3 — subcodec rectangles composited over the result.
    fn decode_subcodec_layer(
        &self,
        data: &[u8],
        output: &mut [u8],
        surface_width: u16,
    ) -> Result<(), ClearError> {
        if data.is_empty() {
            return Ok(());
        }
        let sw = usize::from(surface_width);
        let sh = output.len() / (sw * 4).max(1);
        let mut c = Cursor::new(data);

        while c.remaining() >= 13 {
            let x_start = c.u16_le();
            let y_start = c.u16_le();
            let width = c.u16_le();
            let height = c.u16_le();
            let bitmap_byte_count = cast_usize(c.u32_le());
            let codec_id = c.u8();

            if width == 0 || height == 0 {
                return Err(invalid("dimensions", "subcodec region has zero dimension"));
            }
            c.ensure(bitmap_byte_count, "ClearCodecSubcodec")?;
            let bitmap = c.slice(bitmap_byte_count);

            let x_end = usize::from(x_start) + usize::from(width);
            let y_end = usize::from(y_start) + usize::from(height);
            if x_end > sw || y_end > sh {
                return Err(invalid("subcodec", "region exceeds surface bounds"));
            }

            match codec_id {
                0x00 => decode_raw_region(bitmap, output, x_start, y_start, width, height, sw)?,
                0x02 => decode_rlex_region(bitmap, output, x_start, y_start, width, height, sw)?,
                // NSCodec (0x01) is not produced by EGFX servers in practice; left undecoded
                // rather than rejected, matching the residual/band layers already drawn.
                0x01 => {}
                _ => return Err(invalid("subCodecId", "unknown subcodec ID")),
            }
        }
        Ok(())
    }

    // --- cache accessors ---

    fn vbar_get(&self, index: u16) -> Option<&FullVBar> {
        self.vbar_storage
            .get(usize::from(index))
            .and_then(|s| s.as_ref())
    }

    fn short_vbar_get(&self, index: u16) -> Option<&ShortVBar> {
        self.short_vbar_storage
            .get(usize::from(index))
            .and_then(|s| s.as_ref())
    }

    /// Store a full V-bar at the cursor, returning the slot it landed in.
    fn store_vbar(&mut self, vbar: FullVBar) -> usize {
        let idx = usize::from(self.vbar_cursor);
        self.vbar_storage[idx] = Some(vbar);
        self.vbar_cursor = (self.vbar_cursor + 1) % (VBAR_CACHE_SIZE as u16);
        idx
    }

    fn store_short_vbar(&mut self, short: ShortVBar) {
        let idx = usize::from(self.short_vbar_cursor);
        self.short_vbar_storage[idx] = Some(short);
        self.short_vbar_cursor = (self.short_vbar_cursor + 1) % (SHORT_VBAR_CACHE_SIZE as u16);
    }

    fn glyph_get(&self, index: u16) -> Option<&GlyphEntry> {
        self.glyph_storage
            .get(usize::from(index))
            .and_then(|s| s.as_ref())
    }

    fn glyph_store(&mut self, index: u16, entry: GlyphEntry) {
        if let Some(slot) = self.glyph_storage.get_mut(usize::from(index)) {
            *slot = Some(entry);
        }
    }
}

/// Reconstruct a full column: background above `y_on`, the short V-bar's pixels (BGR, 3 bytes
/// per covered row), then background down to `band_height`.
fn reconstruct_full_vbar(
    y_on: u8,
    short_pixels: &[u8],
    band_height: u16,
    bg_blue: u8,
    bg_green: u8,
    bg_red: u8,
) -> FullVBar {
    let height = usize::from(band_height);
    let mut pixels = Vec::with_capacity(height * 3);
    // Every fill is clamped to `band_height`: a SHORT_VBAR_CACHE_HIT can reuse a taller band's
    // short bar under a fresh `y_on`, so `y_on + short_pixels` may exceed the current band. FreeRDP
    // `clear.c` vBarUpdate clamps each of the three fills with `if ((y + count) > vBarPixelCount)
    // count = vBarPixelCount - y`; the assembled column is always exactly `band_height` rows (#116).
    let top = usize::from(y_on).min(height);
    for _ in 0..top {
        pixels.extend_from_slice(&[bg_blue, bg_green, bg_red]);
    }
    let copy_rows = (short_pixels.len() / 3).min(height - top);
    pixels.extend_from_slice(&short_pixels[..copy_rows * 3]);
    for _ in (top + copy_rows)..height {
        pixels.extend_from_slice(&[bg_blue, bg_green, bg_red]);
    }
    FullVBar { pixels }
}

fn decode_raw_region(
    bitmap: &[u8],
    output: &mut [u8],
    x_start: u16,
    y_start: u16,
    width: u16,
    height: u16,
    sw: usize,
) -> Result<(), ClearError> {
    let w = usize::from(width);
    let h = usize::from(height);
    let expected = w
        .checked_mul(h)
        .and_then(|v| v.checked_mul(3))
        .ok_or_else(|| invalid("bitmapData", "raw subcodec dimensions overflow"))?;
    if bitmap.len() < expected {
        return Err(invalid("bitmapData", "raw subcodec data too short"));
    }
    for row in 0..h {
        for col in 0..w {
            let x = usize::from(x_start) + col;
            let y = usize::from(y_start) + row;
            let src = (row * w + col) * 3;
            let dst = (y * sw + x) * 4;
            output[dst] = bitmap[src];
            output[dst + 1] = bitmap[src + 1];
            output[dst + 2] = bitmap[src + 2];
            output[dst + 3] = 0xFF;
        }
    }
    Ok(())
}

fn decode_rlex_region(
    bitmap: &[u8],
    output: &mut [u8],
    x_start: u16,
    y_start: u16,
    width: u16,
    height: u16,
    sw: usize,
) -> Result<(), ClearError> {
    let rlex = decode_rlex(bitmap)?;
    let w = usize::from(width);
    let region_pixels = usize::from(width) * usize::from(height);
    let palette_len = rlex.palette.len();

    let mut px = 0usize;
    let mut put = |px: usize, color: [u8; 3]| {
        let x = usize::from(x_start) + px % w;
        let y = usize::from(y_start) + px / w;
        let dst = (y * sw + x) * 4;
        output[dst] = color[0];
        output[dst + 1] = color[1];
        output[dst + 2] = color[2];
        output[dst + 3] = 0xFF;
    };

    // Clip surplus at the region boundary rather than reject. A captured real Windows Server
    // 2022 stream over-fills its RLEX region (replay corpus entry 0, 64x32); FreeRDP `clear.c`
    // and the ironrdp oracle both reject that (`suite exceeds region pixel count`), but a client
    // must not drop a live frame over a server's over-encode, so we stop emitting at the region
    // boundary and short-fill under-runs. (NB: this is *not* FreeRDP parity — FreeRDP rejects;
    // the basis is the real capture, verified 2026-07-02. See #120.)
    'segments: for seg in &rlex.segments {
        if usize::from(seg.start_index) >= palette_len {
            return Err(invalid("rlex", "start_index exceeds palette size"));
        }
        if usize::from(seg.stop_index) >= palette_len {
            return Err(invalid("rlex", "stop_index exceeds palette size"));
        }

        // Run: repeat the start color.
        let run_color = rlex.palette[usize::from(seg.start_index)];
        for _ in 0..seg.run_length {
            if px >= region_pixels {
                break 'segments;
            }
            put(px, run_color);
            px += 1;
        }

        // Suite: walk the palette gradient start_index..=stop_index inclusive.
        for palette_idx in seg.start_index..=seg.stop_index {
            if px >= region_pixels {
                break 'segments;
            }
            put(px, rlex.palette[usize::from(palette_idx)]);
            px += 1;
        }
    }
    Ok(())
}

// --- RLEX subcodec parsing (MS-RDPEGFX 2.2.4.1.1.3.1.3) ---

struct RlexSegment {
    start_index: u8,
    stop_index: u8,
    run_length: u32,
}

struct RlexData {
    palette: Vec<[u8; 3]>,
    segments: Vec<RlexSegment>,
}

fn decode_rlex(data: &[u8]) -> Result<RlexData, ClearError> {
    let mut c = Cursor::new(data);
    c.ensure(1, "RlexPalette")?;
    let palette_count = c.u8();
    if palette_count == 0 {
        return Err(invalid("paletteCount", "palette count is 0"));
    }
    if palette_count > MAX_PALETTE_COUNT {
        return Err(invalid("paletteCount", "palette count exceeds 127"));
    }

    let palette_bytes = usize::from(palette_count) * 3;
    c.ensure(palette_bytes, "RlexPalette")?;
    let mut palette = Vec::with_capacity(usize::from(palette_count));
    for _ in 0..palette_count {
        let b = c.u8();
        let g = c.u8();
        let r = c.u8();
        palette.push([b, g, r]);
    }

    // numBits = CLEAR_LOG2_FLOOR[paletteCount - 1] + 1 (FreeRDP `clear.c:200`): the low numBits of
    // each packed byte hold stopIndex, the upper bits hold suiteDepth, startIndex = stopIndex -
    // suiteDepth. It is >= 1 even for a single-entry palette (floor(log2(0)) is defined as 0), so a
    // packed byte is always present — one per segment, no 0-bit special case (#121).
    let stop_index_bits = if palette_count == 1 {
        1
    } else {
        bit_length(u32::from(palette_count - 1))
    };

    let mut segments = Vec::new();
    let suite_depth_bits = 8 - stop_index_bits;
    let stop_mask = (1u8 << stop_index_bits) - 1;
    let depth_mask = (1u8 << suite_depth_bits) - 1;
    while !c.is_empty() {
        let packed = c.u8();
        let stop_index = packed & stop_mask;
        let suite_depth = (packed >> stop_index_bits) & depth_mask;
        let start_index = stop_index.saturating_sub(suite_depth);
        let run_length = read_run_length(&mut c, "RlexRun")?;
        segments.push(RlexSegment {
            start_index,
            stop_index,
            run_length,
        });
    }

    Ok(RlexData { palette, segments })
}

/// `floor(log2(n)) + 1` for `n > 0`; `0` for `n == 0`.
fn bit_length(n: u32) -> u8 {
    if n == 0 {
        0
    } else {
        // `32 - leading_zeros()` is in `1..=32` for non-zero `n`, so the truncating cast is
        // lossless — no panic path, per the crate's "malformed input is never a panic" rule.
        (32 - n.leading_zeros()) as u8
    }
}

fn cast_usize(v: u32) -> usize {
    // Lossless widening: `usize` is at least 32 bits on every target this crate builds for.
    v as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // ADR-0008 / issue #97 — the no-panic robustness property. `ClearError`'s contract is the
        // same as the other codecs': malformed input is always a typed error, never a panic. The
        // ClearCodec `data` is the unbounded, attacker-controlled blob (flags + glyph/band/subcodec
        // structure, cache indices), so it is fully arbitrary; width/height are bounded because they
        // arrive from fixed u16 EGFX wire fields, never the stream. A fresh decoder per case keeps
        // each run independent of cache state. Reaching the end without unwinding IS the assertion —
        // proptest fails (and shrinks to a minimal counterexample) on any panic / arithmetic
        // overflow / OOB — the class that produced repeated ClearCodec OOB CVEs in FreeRDP
        // (CVE-2020-11040 in `clear_decompress_subcode_rlex`, and later `clear_decompress_bands_data`
        // / `residual_data` / glyphData advisories through 3.21.0).
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decode_never_panics_on_arbitrary_input(
            width in 0u16..=64,
            height in 0u16..=64,
            data in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = ClearDecoder::new().decode(&data, width, height);
        }
    }

    /// Differential round-trip: encode with the `ironrdp-graphics` oracle's ClearCodec encoder,
    /// decode with the self-owned decoder, and require the pixels back. Exercises the
    /// residual-layer path the oracle's encoder emits.
    #[test]
    fn round_trips_the_oracle_encoder() {
        let mut encoder = ironrdp_graphics::clearcodec::ClearCodecEncoder::new();
        // 4×2 solid color in BGRA.
        let bgra: Vec<u8> = (0..8).flat_map(|_| [10u8, 20, 30, 255]).collect();
        let stream = encoder.encode(&bgra, 4, 2);
        let decoded = Clear::new().decode_to_bgra(&stream, 4, 2).unwrap();
        assert_eq!(decoded, bgra);
    }

    /// The corrected SHORT_VBAR_CACHE_MISS field layout: `shortVBarYOn` is the low byte and
    /// `shortVBarYOff` is bits `[13:8]`. A header that the *oracle* would read as
    /// `yOff < yOn` (and reject) must decode here.
    #[test]
    fn short_vbar_cache_miss_uses_low_byte_for_y_on() {
        // yOn = 5 (low byte), yOff = 8 (bits[13:8]); top two bits clear → cache miss.
        // pixel_count = yOff - yOn = 3.
        let header: u16 = (8 << 8) | 5;
        // One band: x 0..=0, y 0..=51 (band_height 52), black background, then this v-bar.
        let mut bands = Vec::new();
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_start
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_end
        bands.extend_from_slice(&0u16.to_le_bytes()); // y_start
        bands.extend_from_slice(&51u16.to_le_bytes()); // y_end → height 52
        bands.extend_from_slice(&[0, 0, 0]); // bkg BGR
        bands.extend_from_slice(&header.to_le_bytes());
        bands.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF]); // 3 px

        let mut stream = vec![0x00, 0x00]; // flags, seq
        stream.extend_from_slice(&0u32.to_le_bytes()); // residualByteCount
        stream.extend_from_slice(&u32::try_from(bands.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes()); // subcodecByteCount
        stream.extend_from_slice(&bands);

        let out = ClearDecoder::new().decode(&stream, 1, 52).unwrap();
        // Row 5 (first pixel of the short v-bar) is blue 0xFF,0x00,0x00.
        assert_eq!(&out[5 * 4..5 * 4 + 3], &[0xFF, 0x00, 0x00]);
    }

    /// #116 — a V-bar cache hit can carry a *taller* band's column into a *shorter* band. The
    /// reconstruction must clamp the assembled column to the current band height (FreeRDP
    /// `clear.c` vBarUpdate clamps every fill to `vBarPixelCount`); it must never be longer.
    /// Expectation is hand-derived from the FreeRDP semantics — NOT the `ironrdp-graphics`
    /// oracle, which shares the same un-clamped `reconstruct_full_vbar` (see #118).
    #[test]
    fn reconstruct_full_vbar_clamps_to_band_height() {
        // 40 rows of short pixels, but the current band is only 10 tall, with y_on = 5.
        let short: Vec<u8> = std::iter::repeat_n([0x11u8, 0x22, 0x33], 40)
            .flatten()
            .collect();
        let full = reconstruct_full_vbar(5, &short, 10, 0, 0, 0);
        // Exactly band_height rows — not the buggy 5 + 40 = 45.
        assert_eq!(full.pixels.len(), 10 * 3);
        // Rows 0..5 background, rows 5..10 the first 5 short pixels (the surplus is dropped).
        assert_eq!(&full.pixels[0..5 * 3], &[0u8; 15]);
        assert_eq!(
            &full.pixels[5 * 3..10 * 3],
            &[0x11, 0x22, 0x33].repeat(5)[..]
        );
    }

    /// #116 — a full V-bar CACHE_HIT (0x8000) reuses a stored column verbatim; if that column was
    /// built for a taller band it must not bleed below a shorter band. FreeRDP clamps at composite
    /// (`clear.c`: `if (count > nHeight) count = nHeight`). Oracle-independent bitstream.
    #[test]
    fn full_vbar_cache_hit_does_not_bleed_below_a_shorter_band() {
        let mut bands = Vec::new();
        // Band 1: 1×20 (y 0..=19) — a SHORT_VBAR_CACHE_MISS stores a 20-row column at full slot 0.
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_start
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_end
        bands.extend_from_slice(&0u16.to_le_bytes()); // y_start
        bands.extend_from_slice(&19u16.to_le_bytes()); // y_end → height 20
        bands.extend_from_slice(&[0, 0, 0]); // bkg BGR
        let miss: u16 = 20 << 8; // yOn=0, yOff=20 → 20 short pixels
        bands.extend_from_slice(&miss.to_le_bytes());
        for _ in 0..20 {
            bands.extend_from_slice(&[0x11, 0x22, 0x33]);
        }
        // Band 2: 1×5 (y 100..=104) — a full V-bar CACHE_HIT on slot 0 (the 20-row column).
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_start
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_end
        bands.extend_from_slice(&100u16.to_le_bytes()); // y_start
        bands.extend_from_slice(&104u16.to_le_bytes()); // y_end → height 5
        bands.extend_from_slice(&[0, 0, 0]); // bkg BGR
        bands.extend_from_slice(&0x8000u16.to_le_bytes()); // full V-bar cache hit, index 0

        let out = ClearDecoder::new()
            .decode(&build_stream(&bands), 1, 120)
            .unwrap();
        // Band 2 itself (row 100) shows the column.
        assert_eq!(&out[100 * 4..100 * 4 + 3], &[0x11, 0x22, 0x33]);
        // Rows below band 2 (105..120) must stay background — the tall column must not bleed down.
        for y in 105..120 {
            assert_eq!(
                &out[y * 4..y * 4 + 3],
                &[0, 0, 0],
                "row {y} bled below the band"
            );
        }
    }

    /// #116 headline scenario, end to end — a SHORT_VBAR_CACHE_HIT (0x4000) reuses a taller band's
    /// short bar under a fresh `yOn` in a shorter band. The reconstructed column must be clamped to
    /// the shorter band. Oracle-independent bitstream.
    #[test]
    fn short_vbar_cache_hit_clamps_to_the_shorter_band() {
        let mut bands = Vec::new();
        // Band 1: 1×20 — SHORT_VBAR_CACHE_MISS stores a 10-row short bar at short slot 0.
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_start
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_end
        bands.extend_from_slice(&0u16.to_le_bytes()); // y_start
        bands.extend_from_slice(&19u16.to_le_bytes()); // y_end → height 20
        bands.extend_from_slice(&[0, 0, 0]); // bkg BGR
        let miss: u16 = 10 << 8; // yOn=0, yOff=10 → 10 short pixels
        bands.extend_from_slice(&miss.to_le_bytes());
        for _ in 0..10 {
            bands.extend_from_slice(&[0x44, 0x55, 0x66]);
        }
        // Band 2: 1×5 (y 100..=104) — SHORT_VBAR_CACHE_HIT on slot 0, fresh yOn = 2.
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_start
        bands.extend_from_slice(&0u16.to_le_bytes()); // x_end
        bands.extend_from_slice(&100u16.to_le_bytes()); // y_start
        bands.extend_from_slice(&104u16.to_le_bytes()); // y_end → height 5
        bands.extend_from_slice(&[0, 0, 0]); // bkg BGR
        bands.extend_from_slice(&0x4000u16.to_le_bytes()); // short V-bar cache hit, index 0
        bands.push(2); // yOn

        let out = ClearDecoder::new()
            .decode(&build_stream(&bands), 1, 120)
            .unwrap();
        // Within band 2: rows 100..102 background, rows 102..105 the short bar (clamped from 10→3).
        assert_eq!(&out[100 * 4..100 * 4 + 3], &[0, 0, 0]);
        assert_eq!(&out[102 * 4..102 * 4 + 3], &[0x44, 0x55, 0x66]);
        assert_eq!(&out[104 * 4..104 * 4 + 3], &[0x44, 0x55, 0x66]);
        // Below band 2 must stay background — no bleed.
        for y in 105..120 {
            assert_eq!(
                &out[y * 4..y * 4 + 3],
                &[0, 0, 0],
                "row {y} bled below the band"
            );
        }
    }

    /// Wrap a bands-layer payload in the ClearCodec bitmap-stream header (no residual/subcodec).
    fn build_stream(bands: &[u8]) -> Vec<u8> {
        let mut stream = vec![0x00, 0x00]; // flags, seq
        stream.extend_from_slice(&0u32.to_le_bytes()); // residualByteCount
        stream.extend_from_slice(&u32::try_from(bands.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes()); // subcodecByteCount
        stream.extend_from_slice(bands);
        stream
    }

    // #120 — RLEX over/under-region is tolerated, not rejected. A captured real WS2022 stream
    // over-fills its region (corpus entry 0); FreeRDP `clear.c` and the ironrdp oracle both reject
    // that, but a client must not drop a live frame, so justrdp clips the surplus and short-fills
    // under-runs. These assertions pin that intentional tolerance (independent of the oracle,
    // which rejects). palette_count=2 keeps the test off the single-palette 0-bit path (#121).

    /// A one-segment RLEX bitmap: palette of 2 BGR colors, packed byte `0x00`
    /// (stopIndex=0, suiteDepth=0, startIndex=0) → `run_length` run px + 1 suite px of palette[0].
    fn rlex_bitmap(run_length: u8) -> Vec<u8> {
        vec![2, 10, 20, 30, 40, 50, 60, 0x00, run_length]
    }

    #[test]
    fn rlex_over_region_is_clipped_not_rejected() {
        // run=5 (+1 suite = 6 px) into a 2-px region: paint the 2 region px, drop the surplus,
        // succeed — the client must not reject a real server's over-encode.
        let mut out = vec![0u8; 2 * 4];
        assert!(
            decode_rlex_region(&rlex_bitmap(5), &mut out, 0, 0, 2, 1, 2).is_ok(),
            "over-region RLEX must clip, not reject"
        );
        assert_eq!(&out[0..4], &[10, 20, 30, 0xFF]); // palette[0]
        assert_eq!(&out[4..8], &[10, 20, 30, 0xFF]);
    }

    #[test]
    fn rlex_under_fill_is_tolerated() {
        // run=0 (+1 suite = 1 px) into a 4-px region: paint what we have, leave the rest, succeed.
        let mut out = vec![0u8; 4 * 4];
        assert!(decode_rlex_region(&rlex_bitmap(0), &mut out, 0, 0, 4, 1, 4).is_ok());
        assert_eq!(&out[0..4], &[10, 20, 30, 0xFF]); // 1 suite px painted
        assert_eq!(&out[4..8], &[0, 0, 0, 0]); // remainder untouched
    }

    #[test]
    fn rlex_exact_fill_paints_the_whole_region() {
        // run=1 (+1 suite = 2 px) exactly fills a 2-px region.
        let mut out = vec![0u8; 2 * 4];
        assert!(decode_rlex_region(&rlex_bitmap(1), &mut out, 0, 0, 2, 1, 2).is_ok());
        assert_eq!(&out[0..4], &[10, 20, 30, 0xFF]);
        assert_eq!(&out[4..8], &[10, 20, 30, 0xFF]);
    }

    // #121 — single-palette RLEX. FreeRDP `numBits = CLEAR_LOG2_FLOOR[paletteCount-1] + 1` = 1 for
    // paletteCount==1 (`clear.c:200`), so a packed stop/suite byte is present per segment even for a
    // one-entry palette. The old 0-bit special case read no packed byte, misparsing genuine streams.
    // (Rendered output for a *valid* single-palette stream is identical either way — one colour — so
    // this is a spec/byte-consumption conformance fix, not an output change; the observable effect is
    // that the packed index byte is now validated.)

    #[test]
    fn single_palette_rlex_validates_the_packed_index_byte() {
        // palette_count=1, palette=[10,20,30]; packed byte 0x01 → stopIndex=1, which exceeds the
        // single-entry palette → reject (FreeRDP `clear.c` `startIndex/stopIndex >= paletteCount`).
        // Under the old 0-bit layout this byte was misread as a bare run length and accepted.
        let bitmap = vec![1, 10, 20, 30, 0x01, 0x00];
        let mut out = vec![0u8; 4 * 4];
        assert!(
            decode_rlex_region(&bitmap, &mut out, 0, 0, 4, 1, 4).is_err(),
            "single-palette RLEX must read and validate the packed index byte"
        );
    }

    #[test]
    fn single_palette_rlex_valid_stream_fills_the_region() {
        // Valid FreeRDP-format single-palette RLEX: packed 0x00 (stopIndex=0, suiteDepth=0), run=2
        // → 2 run + 1 suite = 3 px of palette[0].
        let bitmap = vec![1, 10, 20, 30, 0x00, 2];
        let mut out = vec![0u8; 3 * 4];
        assert!(decode_rlex_region(&bitmap, &mut out, 0, 0, 3, 1, 3).is_ok());
        for px in out.chunks_exact(4) {
            assert_eq!(px, &[10, 20, 30, 0xFF]);
        }
    }
}
