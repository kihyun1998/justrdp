//! Self-owned ClearCodec decoder (MS-RDPEGFX 2.2.4.1) — ADR-0003 phase 2.
//!
//! ClearCodec is a mandatory lossless EGFX tile codec built from three composited layers:
//! a residual BGR run-length background, a *bands* layer of cached vertical columns
//! ("V-bars") tuned for text glyphs, and a *subcodec* layer (raw BGR / NSCodec / RLEX) for
//! arbitrary rectangles. A persistent V-bar cache and a glyph cache span PDUs.
//!
//! This decoder is re-derived from the MS-RDPEGFX spec and cross-checked against FreeRDP's
//! `clear.c`; it does **not** depend on `ironrdp-graphics`. Correctness on streams the oracle
//! also accepts is proven differentially (`tests/clearcodec_*`). Two oracle bit-level defects
//! that reject genuine Windows Server 2022 streams are corrected here:
//!
//! 1. **SHORT_VBAR_CACHE_MISS field layout.** The 14 payload bits are `shortVBarYOn` in bits
//!    `[7:0]` and `shortVBarYOff` in bits `[13:8]` (FreeRDP `vBarYOn = h & 0xFF`,
//!    `vBarYOff = (h >> 8) & 0x3F`). The oracle reads them swapped (`yOn = h >> 6`,
//!    `yOff = h & 0x3F`), so on real streams `yOn` routinely exceeds the 6-bit `yOff` and it
//!    rejects with `shortVBarYOff < shortVBarYOn`. Fixing the layout also repopulates the full
//!    V-bar cache correctly, which transitively removes the oracle's `vbarIndex` "cache miss on
//!    hit" rejection (bands that previously aborted mid-decode now finish and store their
//!    columns).
//! 2. **RLEX region overflow is clipped, not fatal.** When a run+suite would write past the
//!    region, real servers (and FreeRDP) clip the surplus; the oracle instead rejects with
//!    `suite exceeds region pixel count`. We stop emitting at the region boundary.
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

#[derive(Clone)]
struct ShortVBar {
    y_on: u8,
    pixel_count: u8,
    /// BGR pixel data, `pixel_count * 3` bytes.
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
                let vbar = self.decode_vbar(&mut c, band_height, bg_blue, bg_green, bg_red)?;
                let x = usize::from(x_start) + col;
                if x >= w {
                    continue;
                }
                let rows = vbar.pixels.len() / 3;
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

    /// Decode one V-bar header and resolve it (through the cache) into a full column.
    fn decode_vbar(
        &mut self,
        c: &mut Cursor<'_>,
        band_height: u16,
        bg_blue: u8,
        bg_green: u8,
        bg_red: u8,
    ) -> Result<FullVBar, ClearError> {
        c.ensure(2, "VBar")?;
        let header = c.u16_le();

        // Bit 15 set: full V-bar cache hit (read-only, no cursor advance).
        if header & 0x8000 != 0 {
            let index = header & 0x7FFF;
            return self
                .vbar_get(index)
                .cloned()
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
            let short = ShortVBar {
                y_on,
                pixel_count: cached.pixel_count,
                pixels: cached.pixels.clone(),
            };
            let full = reconstruct_full_vbar(&short, band_height, bg_blue, bg_green, bg_red);
            self.store_vbar(full.clone());
            return Ok(full);
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

        let short = ShortVBar {
            y_on,
            pixel_count,
            pixels,
        };
        self.store_short_vbar(short.clone());
        let full = reconstruct_full_vbar(&short, band_height, bg_blue, bg_green, bg_red);
        self.store_vbar(full.clone());
        Ok(full)
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

    fn store_vbar(&mut self, vbar: FullVBar) {
        let idx = usize::from(self.vbar_cursor);
        self.vbar_storage[idx] = Some(vbar);
        self.vbar_cursor = (self.vbar_cursor + 1) % (VBAR_CACHE_SIZE as u16);
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

/// Reconstruct a full column: background above `y_on`, the short V-bar's pixels, then background
/// down to `band_height`.
fn reconstruct_full_vbar(
    short: &ShortVBar,
    band_height: u16,
    bg_blue: u8,
    bg_green: u8,
    bg_red: u8,
) -> FullVBar {
    let height = usize::from(band_height);
    let mut pixels = Vec::with_capacity(height * 3);
    for _ in 0..usize::from(short.y_on) {
        pixels.extend_from_slice(&[bg_blue, bg_green, bg_red]);
    }
    pixels.extend_from_slice(&short.pixels);
    let bottom_start = usize::from(short.y_on) + usize::from(short.pixel_count);
    for _ in bottom_start..height {
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
                break 'segments; // clip surplus rather than reject (FreeRDP parity)
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

    // numBits = floor(log2(paletteCount - 1)) + 1; the low numBits of each packed byte hold
    // stopIndex, the upper bits hold suiteDepth, and startIndex = stopIndex - suiteDepth.
    let stop_index_bits = if palette_count <= 1 {
        0
    } else {
        bit_length(u32::from(palette_count - 1))
    };

    let mut segments = Vec::new();
    if stop_index_bits == 0 {
        // Single palette entry: each segment is a bare run length of palette[0].
        while !c.is_empty() {
            let run_length = read_run_length(&mut c, "RlexRun")?;
            segments.push(RlexSegment {
                start_index: 0,
                stop_index: 0,
                run_length,
            });
        }
    } else {
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
}
