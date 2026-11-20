//! Self-owned ClearCodec decoder (MS-RDPEGFX 2.2.4.1) — ADR-0003 phase 2.
//!
//! ClearCodec is a mandatory lossless EGFX tile codec built from three composited layers:
//! a residual BGR run-length background, a *bands* layer of cached vertical columns
//! ("V-bars") tuned for text glyphs, and a *subcodec* layer (raw BGR / NSCodec / RLEX) for
//! arbitrary rectangles. A persistent V-bar cache and a glyph cache span PDUs.
//!
//! This decoder is re-derived from the MS-RDPEGFX spec and cross-checked against FreeRDP's
//! `clear.c`; it does **not** depend on `ironrdp-graphics`, and its output is checked against
//! that oracle differentially (`tests/clearcodec_*`). Four decisions are easy to get wrong:
//!
//! 1. **SHORT_VBAR_CACHE_MISS field layout.** The 14 payload bits are `shortVBarYOn` in bits
//!    `[7:0]` and `shortVBarYOff` in bits `[13:8]` (FreeRDP `vBarYOn = h & 0xFF`,
//!    `vBarYOff = (h >> 8) & 0x3F`). Read swapped (`yOn = h >> 6`, `yOff = h & 0x3F`), `yOn`
//!    routinely exceeds the 6-bit `yOff` on real streams and the band is rejected with
//!    `shortVBarYOff < shortVBarYOn`; every column that band would have stored then misses the
//!    full V-bar cache on a later hit (`vbarIndex`).
//!
//! 2. **A residual or RLEX layer may write fewer pixels than its region holds, never more.** A
//!    residual run, or an RLEX run or suite, that would write past the region's last pixel is a
//!    [`ClearError`] naming the layer. Fewer is conforming: `[MS-RDPEGFX]` 2.2.4.1.1.1 says the residual layer encodes
//!    "less than or equal to the number of pixels in the original image", and example 4.1.1.2
//!    decodes RLEX segments "until there is no more data left". The pixels a layer does not reach
//!    keep what the tile already held: the residual or bands pixel under an RLEX region, and the
//!    caller's seed where no layer reaches. `justrdp::egfx` seeds the tile with the surface's
//!    current pixels, so a WireToSurface1 region keeps the surface's earlier pixel there.
//!
//! 3. **The composite payload and each layer hold whole structures, and these field values the spec
//!    forbids are refused.** Bytes after a layer's last whole run segment, band or subcodec are a
//!    [`ClearError::NotEnoughBytes`] (`[MS-RDPEGFX]` 2.2.4.1.1.1, 2.2.4.1.1.2, 2.2.4.1.1.3). A
//!    residual run length whose `runLengthFactor1`, `runLengthFactor2` or `runLengthFactor3` is
//!    zero (2.2.4.1.1.1.1), a subcodec of any `subCodecId` whose `bitmapDataByteCount` exceeds
//!    `3 * width * height`, and a raw subcodec with fewer bytes than that (2.2.4.1.1.3.1) are
//!    [`ClearError::InvalidField`]. A stream without GLYPH_HIT that ends after its header (and
//!    glyph index) is a [`ClearError::NotEnoughBytes`] naming `CompositePayload`, so no all-zero
//!    tile is drawn or stored as a glyph (ADR-0009, #651). CACHE_RESET on such a stream still
//!    resets both V-bar cursors.
//!
//! 4. **Glyph flags, V-bar cache hits and bands must fit the tile they are used on.** Each of these
//!    is a [`ClearError::InvalidField`]: GLYPH_INDEX on a tile over 1,024 pixels, and a GLYPH_HIT
//!    followed by any bytes (2.2.4.1); a VBAR_CACHE_HIT whose stored V-bar is not the band's height
//!    (2.2.4.1.1.2.1.1.1); a SHORT_VBAR_CACHE_HIT whose stored short V-bar, placed at its
//!    `shortVBarYOn`, runs past the band (2.2.4.1.1.2.1.1.2); and a band whose columns or rows fall
//!    outside the tile. Nothing is clamped or skipped to make such an input fit.
//!
//! **Alpha contract:** ClearCodec carries no alpha; every pixel a layer writes has alpha `0xFF`, an
//! NSCodec subcodec's included, since `[MS-RDPEGFX]` 3.3.5.1 ignores alpha for every codec but
//! ALPHA. A pixel no layer reaches keeps the caller's seed, alpha included (decision 2).

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
/// The largest tile GLYPH_INDEX may name: `[MS-RDPEGFX]` 2.2.4.1 forbids the flag on a bitmap
/// over 1,024 square pixels, and 3.3.1.9 caps each glyph slot at that size.
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
    /// The caller's tile is not `width × height × 4` bytes.
    OutputLength {
        /// The tile width the caller asked for.
        width: u16,
        /// The tile height the caller asked for.
        height: u16,
        /// The length of the tile the caller passed.
        len: usize,
    },
}

impl fmt::Display for ClearError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClearError::NotEnoughBytes { ctx } => write!(f, "not enough bytes for {ctx}"),
            ClearError::InvalidField { field, reason } => write!(f, "invalid `{field}`: {reason}"),
            ClearError::OutputLength { width, height, len } => {
                write!(f, "a {len}-byte tile is not {width}x{height} BGRA pixels")
            }
        }
    }
}

impl std::error::Error for ClearError {}

impl From<crate::nscodec::NscError> for ClearError {
    fn from(e: crate::nscodec::NscError) -> Self {
        // The two codec error enums share a shape; map an NSCodec-subcodec failure through verbatim.
        match e {
            crate::nscodec::NscError::NotEnoughBytes { ctx } => ClearError::NotEnoughBytes { ctx },
            crate::nscodec::NscError::InvalidField { field, reason } => {
                ClearError::InvalidField { field, reason }
            }
            // The shapes stop matching here: ClearCodec has no dimensions-overflow variant of its
            // own, and inventing one would widen this enum for a case its own geometry cannot
            // reach — a ClearCodec NSCodec subcodec region is bounded by the rect it decodes into.
            // Mapped to the nearest true statement rather than to a new variant.
            crate::nscodec::NscError::DimensionsOverflow { .. } => ClearError::InvalidField {
                field: "NSCodecSubcodecGeometry",
                reason: "declared plane dimensions overflow usize on this target",
            },
        }
    }
}

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

/// The field of a variable-length run length that holds its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunLengthFactor {
    Factor1,
    Factor2,
    Factor3,
}

/// A variable-length run length shared by the residual and RLEX layers: a single byte, or
/// `0xFF` then a u16, or `0xFF 0xFFFF` then a u32. Returns the length and the field that held it.
fn read_run_length(
    c: &mut Cursor<'_>,
    ctx: &'static str,
) -> Result<(u32, RunLengthFactor), ClearError> {
    c.ensure(1, ctx)?;
    let factor1 = c.u8();
    if factor1 < 0xFF {
        return Ok((u32::from(factor1), RunLengthFactor::Factor1));
    }
    c.ensure(2, ctx)?;
    let factor2 = c.u16_le();
    if factor2 < 0xFFFF {
        return Ok((u32::from(factor2), RunLengthFactor::Factor2));
    }
    c.ensure(4, ctx)?;
    Ok((c.u32_le(), RunLengthFactor::Factor3))
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
    /// BGRA pixel data: a linear stream with no dimensions (`[MS-RDPEGFX]` 4.1.1.5).
    pixels: Vec<u8>,
}

/// Stateful ClearCodec wrapper — the V-bar / glyph caches persist across PDUs.
///
/// This is the API the EGFX core consumes (`new` + `decode_to_bgra`). It is intentionally
/// **ungated**: its decoder ([`ClearDecoder`]) owns every layer and pulls in no
/// `ironrdp-graphics`. #56 took it off the `egfx-bootstrap` feature; #189 removed that feature
/// altogether, so there is no gate left for anything here to ride. The wrapper also hosts the
/// corpus-capture hook.
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

    /// Decode one ClearCodec bitmap stream onto `tile`, `width × height × 4` **BGRA** bytes the
    /// caller has seeded, as [`ClearDecoder::decode`] does.
    ///
    /// When `JUSTRDP_CLEAR_CAPTURE_DIR` is set, the raw payload and its decode status are
    /// dumped there first (see `capture_clear_payload`) — the corpus harness for the #56
    /// rewrite, which needs streams no differential can arbitrate.
    pub fn decode_to_bgra(
        &mut self,
        data: &[u8],
        width: u16,
        height: u16,
        tile: &mut [u8],
    ) -> Result<(), ClearError> {
        let result = self.inner.decode(data, width, height, tile);
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
/// rewrite — crucially the streams a differential test cannot arbitrate. Best-effort: any IO
/// error is swallowed so capture never perturbs decoding.
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

    /// Decode one ClearCodec bitmap stream onto `tile`, `width × height × 4` BGRA bytes the
    /// caller has seeded. Every pixel a layer writes is replaced, with alpha `0xFF`; every pixel
    /// no layer reaches keeps the seed (the module's decision 2 and alpha contract). A glyph hit
    /// replaces the whole tile, and a glyph store keeps the tile as decoded onto the seed.
    ///
    /// On an error the tile may hold part of the decode, so a caller that must leave its
    /// destination untouched decodes onto a copy. A tile of the wrong length is
    /// [`ClearError::OutputLength`].
    pub fn decode(
        &mut self,
        data: &[u8],
        width: u16,
        height: u16,
        tile: &mut [u8],
    ) -> Result<(), ClearError> {
        let pixel_count = usize::from(width)
            .checked_mul(usize::from(height))
            .ok_or_else(|| invalid("dimensions", "width * height overflow"))?;
        if pixel_count.checked_mul(4) != Some(tile.len()) {
            return Err(ClearError::OutputLength {
                width,
                height,
                len: tile.len(),
            });
        }

        let mut c = Cursor::new(data);
        c.ensure(2, "ClearCodecBitmapStream")?;
        let flags = c.u8();
        // seqNumber is intentionally ignored (#127): FreeRDP validates its monotonicity and rejects
        // a mismatch, but that is a server-sanity check — a client enforcing it would drop otherwise
        // decodable frames on a benign sequence glitch. We are deliberately more lenient.
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

        if glyph_index.is_some() && pixel_count > MAX_GLYPH_PIXELS {
            return Err(invalid(
                "glyphIndex",
                "GLYPH_INDEX on a tile over 1024 pixels",
            ));
        }

        // The destination rectangle supplies the shape, so any rectangle of the cached glyph's area
        // draws it (`[MS-RDPEGFX]` 4.1.1.5).
        if flags & FLAG_GLYPH_HIT != 0 {
            let idx =
                glyph_index.ok_or_else(|| invalid("flags", "GLYPH_HIT without GLYPH_INDEX"))?;
            if !c.is_empty() {
                return Err(invalid("compositePayload", "present with GLYPH_HIT"));
            }
            let entry = self
                .glyph_get(idx)
                .ok_or_else(|| invalid("glyphIndex", "glyph cache miss on hit"))?;
            if entry.pixels.len() / 4 != pixel_count {
                return Err(invalid(
                    "glyphIndex",
                    "cached glyph area does not match destination",
                ));
            }
            tile.copy_from_slice(&entry.pixels);
            return Ok(());
        }

        if width > MAX_DECODE_DIM || height > MAX_DECODE_DIM {
            return Err(invalid(
                "dimensions",
                "width or height exceeds 8192-pixel decoder limit",
            ));
        }

        self.decode_composite(&mut c, tile, width, height)?;

        if let Some(idx) = glyph_index {
            self.glyph_store(
                idx,
                GlyphEntry {
                    pixels: tile.to_vec(),
                },
            );
        }

        Ok(())
    }

    fn decode_composite(
        &mut self,
        c: &mut Cursor<'_>,
        output: &mut [u8],
        width: u16,
        height: u16,
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
        self.decode_bands_layer(bands, output, width, height)?;
        self.decode_subcodec_layer(subcodec, output, width)?;
        Ok(())
    }

    fn decode_residual_layer(&self, data: &[u8], output: &mut [u8]) -> Result<(), ClearError> {
        if data.is_empty() {
            return Ok(());
        }
        let mut c = Cursor::new(data);
        let max_offset = output.len();
        let mut offset = 0usize;

        while !c.is_empty() {
            c.ensure(4, "RgbRunSegment")?;
            let blue = c.u8();
            let green = c.u8();
            let red = c.u8();
            // The run length (the variable-length factor1..factor3 sequence) follows the BGR
            // triple and is read by the shared reader.
            let (run_length, factor) = read_run_length(&mut c, "RgbRunSegment")?;
            if run_length == 0 {
                return Err(invalid(
                    "residual",
                    match factor {
                        RunLengthFactor::Factor1 => "runLengthFactor1 is zero",
                        RunLengthFactor::Factor2 => "runLengthFactor2 is zero",
                        RunLengthFactor::Factor3 => "runLengthFactor3 is zero",
                    },
                ));
            }

            let pixels_remaining = (max_offset - offset) / 4;
            if cast_usize(run_length) > pixels_remaining {
                return Err(invalid("residual", "run overruns the tile"));
            }
            for _ in 0..run_length {
                output[offset] = blue;
                output[offset + 1] = green;
                output[offset + 2] = red;
                output[offset + 3] = 0xFF;
                offset += 4;
            }
        }
        Ok(())
    }

    /// Layer 2 — bands of cached vertical columns composited over the residual. Bytes after the
    /// last whole band are an error (module docs, decision 3).
    fn decode_bands_layer(
        &mut self,
        data: &[u8],
        output: &mut [u8],
        width: u16,
        height: u16,
    ) -> Result<(), ClearError> {
        if data.is_empty() {
            return Ok(());
        }
        let w = usize::from(width);
        let mut c = Cursor::new(data);

        while !c.is_empty() {
            c.ensure(11, "ClearCodecBand")?;
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
            if x_end >= width {
                return Err(invalid("xEnd", "band column outside the tile"));
            }
            if y_end >= height {
                return Err(invalid("yEnd", "band row outside the tile"));
            }

            for x in usize::from(x_start)..=usize::from(x_end) {
                let slot = self.decode_vbar(&mut c, band_height, bg_blue, bg_green, bg_red)?;
                // The slot was just resolved/stored, so it is always populated; compositing
                // straight from storage avoids the per-column clone (#86).
                let Some(vbar) = self.vbar_storage.get(slot).and_then(|s| s.as_ref()) else {
                    continue;
                };
                for (row, bgr) in vbar.pixels.as_chunks::<3>().0.iter().enumerate() {
                    let dst = ((usize::from(y_start) + row) * w + x) * 4;
                    output[dst..dst + 3].copy_from_slice(bgr);
                    output[dst + 3] = 0xFF;
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

        // A cache hit on an unpopulated slot (below and in the short-V-bar path) is rejected as a
        // typed error, where FreeRDP warns and fills a dummy zeroed column (#127). We are
        // deliberately stricter: the #56 layout fix keeps the cache correctly populated for valid
        // streams, so an unpopulated hit means a malformed stream — skipping the tile (via the
        // egfx warn-and-skip) is cleaner than compositing dummy data. Corpus-verified: the real
        // capture never triggers this reject.
        //
        // Bit 15 set: full V-bar cache hit (read-only, no cursor advance).
        if header & 0x8000 != 0 {
            let index = header & 0x7FFF;
            let cached = self
                .vbar_get(index)
                .ok_or_else(|| invalid("vbarIndex", "V-bar cache miss on hit"))?;
            if cached.pixels.len() != usize::from(band_height) * 3 {
                return Err(invalid(
                    "vBarCacheHit",
                    "stored V-bar height is not the band height",
                ));
            }
            return Ok(usize::from(index));
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
                reconstruct_full_vbar(y_on, &cached.pixels, band_height, bg_blue, bg_green, bg_red)
                    .ok_or_else(|| {
                        invalid(
                            "shortVBarCacheHit",
                            "stored short V-bar exceeds band height - shortVBarYOn",
                        )
                    })?;
            return Ok(self.store_vbar(full));
        }

        // Both top bits clear: short V-bar cache miss with inline pixels.
        // CORRECTED field layout (MS-RDPEGFX 2.2.4.1.1.2.1.1.3, per FreeRDP `clear.c`):
        //   shortVBarYOn  = bits [7:0]   (8 bits)
        //   shortVBarYOff = bits [13:8]  (6 bits)
        // Read swapped, these reject genuine streams.
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

        let full = reconstruct_full_vbar(y_on, &pixels, band_height, bg_blue, bg_green, bg_red)
            .ok_or_else(|| invalid("shortVBarCacheMiss", "shortVBarYOff exceeds band height"))?;
        self.store_short_vbar(ShortVBar { pixels });
        Ok(self.store_vbar(full))
    }

    /// Layer 3 — subcodec rectangles composited over the result. Bytes after the last whole
    /// subcodec, and a subcodec above `3 * width * height` bytes, are errors (module docs,
    /// decision 3).
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

        while !c.is_empty() {
            c.ensure(13, "ClearCodecSubcodec")?;
            let x_start = c.u16_le();
            let y_start = c.u16_le();
            let width = c.u16_le();
            let height = c.u16_le();
            let bitmap_byte_count = c.u32_le();
            let codec_id = c.u8();

            if width == 0 || height == 0 {
                return Err(invalid("dimensions", "subcodec region has zero dimension"));
            }
            if u64::from(bitmap_byte_count) > u64::from(width) * u64::from(height) * 3 {
                return Err(invalid("bitmapDataByteCount", "exceeds 3 * width * height"));
            }
            let bitmap_byte_count = cast_usize(bitmap_byte_count);
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
                // NSCodec (0x01): a real WS2019 stream sends it (replay corpus entry 30, 48x78).
                // Decoded via the self-owned NSCodec codec (epic #132) and composited like the raw
                // subcodec.
                0x01 => decode_nscodec_region(bitmap, output, x_start, y_start, width, height, sw)?,
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
) -> Option<FullVBar> {
    let background = [bg_blue, bg_green, bg_red];
    let mut pixels = vec![0; usize::from(band_height) * 3];
    let (above, rest) = pixels.split_at_mut_checked(usize::from(y_on) * 3)?;
    let (bar, below) = rest.split_at_mut_checked(short_pixels.len())?;
    above.as_chunks_mut::<3>().0.fill(background);
    bar.copy_from_slice(short_pixels);
    below.as_chunks_mut::<3>().0.fill(background);
    Some(FullVBar { pixels })
}

/// Decode an NSCodec subcodec region (codecId 0x01) via the self-owned NSCodec codec and composite
/// its BGR output into the ClearCodec surface with alpha `0xFF`, like the raw subcodec
/// (`[MS-RDPEGFX]` 3.3.5.1 ignores alpha for every codec but ALPHA). Region bounds were validated
/// by the caller; NSCodec produces exactly `width*height*4` bytes on success.
fn decode_nscodec_region(
    bitmap: &[u8],
    output: &mut [u8],
    x_start: u16,
    y_start: u16,
    width: u16,
    height: u16,
    sw: usize,
) -> Result<(), ClearError> {
    let pixels = crate::nscodec::decode(bitmap, width, height)?;
    let w = usize::from(width);
    let h = usize::from(height);
    for row in 0..h {
        for col in 0..w {
            let x = usize::from(x_start) + col;
            let y = usize::from(y_start) + row;
            let src = (row * w + col) * 4;
            let dst = (y * sw + x) * 4;
            output[dst..dst + 3].copy_from_slice(&pixels[src..src + 3]);
            output[dst + 3] = 0xFF;
        }
    }
    Ok(())
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

    // A run or suite past the region's last pixel is an error; pixels after the last segment keep
    // what the earlier layers painted (module docs, decision 2).
    for seg in &rlex.segments {
        if usize::from(seg.start_index) >= palette_len {
            return Err(invalid("rlex", "start_index exceeds palette size"));
        }
        if usize::from(seg.stop_index) >= palette_len {
            return Err(invalid("rlex", "stop_index exceeds palette size"));
        }

        // Run: repeat the start color.
        let run_color = rlex.palette[usize::from(seg.start_index)];
        if cast_usize(seg.run_length) > region_pixels - px {
            return Err(invalid("rlex", "run overruns the region"));
        }
        for _ in 0..seg.run_length {
            put(px, run_color);
            px += 1;
        }

        // Suite: walk the palette gradient start_index..=stop_index inclusive.
        let suite_len = usize::from(seg.stop_index - seg.start_index) + 1;
        if suite_len > region_pixels - px {
            return Err(invalid("rlex", "suite overruns the region"));
        }
        for palette_idx in seg.start_index..=seg.stop_index {
            put(px, rlex.palette[usize::from(palette_idx)]);
            px += 1;
        }
    }
    Ok(())
}

// --- RLEX subcodec parsing (MS-RDPEGFX 2.2.4.1.1.3.1.1) ---

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

    // numBits = CLEAR_LOG2_FLOOR[paletteCount - 1] + 1 (FreeRDP `clear_decompress_subcode_rlex`):
    // the low numBits of each packed byte hold stopIndex, the upper bits hold suiteDepth,
    // startIndex = stopIndex - suiteDepth. It is >= 1 even for a single-entry palette
    // (floor(log2(0)) is defined as 0), so a packed byte is always present — one per segment, no
    // 0-bit special case (#121).
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
        // startIndex = stopIndex - suiteDepth must not underflow. FreeRDP computes it wrapping and
        // rejects when startIndex >= paletteCount; we reject the underflow directly (#127) — the
        // same outcome.
        let start_index = stop_index
            .checked_sub(suite_depth)
            .ok_or_else(|| invalid("rlex", "suiteDepth exceeds stopIndex"))?;
        let (run_length, _) = read_run_length(&mut c, "RlexRun")?;
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

    fn decode_zeroed(
        d: &mut ClearDecoder,
        data: &[u8],
        width: u16,
        height: u16,
    ) -> Result<Vec<u8>, ClearError> {
        decode_onto(d, data, width, height, [0; 4])
    }

    fn decode_onto(
        d: &mut ClearDecoder,
        data: &[u8],
        width: u16,
        height: u16,
        seed: [u8; 4],
    ) -> Result<Vec<u8>, ClearError> {
        let mut tile = seed.repeat(usize::from(width) * usize::from(height));
        d.decode(data, width, height, &mut tile).map(|()| tile)
    }

    proptest! {
        // ADR-0008 / issue #97 — the no-panic robustness property. `ClearError`'s contract is the
        // same as the other codecs': malformed input is always a typed error, never a panic. The
        // ClearCodec `data` is the unbounded, attacker-controlled blob (flags + glyph/band/subcodec
        // structure, cache indices), so it is fully arbitrary; width/height are bounded as a
        // **budget trade**. The old wording — "they arrive from fixed u16 EGFX wire fields, never
        // the stream" — is a contradiction and is retracted (#263, ADR-0008 amendment
        // 2026-08-31): these are a WireToSurface1 `destRect`, which `[MS-RDPEGFX]` 2.2.1.2 bounds
        // at `u16` with no maximum, so the real range is 0..=65535. What keeps the band closed
        // here is a length gate rather than the generator — every ClearCodec allocation is sized
        // against `bitmap.len()`. A fresh decoder per case keeps
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
            let _ = decode_zeroed(&mut ClearDecoder::new(), &data, width, height);
        }

        #[test]
        fn a_pixel_keeps_the_seed_exactly_where_no_layer_writes(
            width in 1u16..=8,
            height in 1u16..=8,
            runs in proptest::collection::vec((any::<[u8; 3]>(), 1u8..=6), 0..=12),
            sub in proptest::option::of((0u16..8, 0u16..8, 1u16..=8, 1u16..=8, any::<u8>())),
            seed in any::<[u8; 4]>(),
        ) {
            let (w, h) = (usize::from(width), usize::from(height));
            let mut colour_at = vec![None; w * h];
            let mut residual = Vec::new();
            let mut at = 0;
            for (bgr, len) in runs {
                if at + usize::from(len) > w * h {
                    break;
                }
                residual.extend_from_slice(&bgr);
                residual.push(len);
                colour_at[at..at + usize::from(len)].fill(Some(bgr));
                at += usize::from(len);
            }
            let mut subcodecs = Vec::new();
            if let Some((x, y, sw, sh, v)) = sub {
                let (x, y) = (x % width, y % height);
                let (sw, sh) = (sw.min(width - x), sh.min(height - y));
                let mut s = Vec::new();
                for f in [x, y, sw, sh] {
                    s.extend_from_slice(&f.to_le_bytes());
                }
                let bitmap = vec![v; usize::from(sw) * usize::from(sh) * 3];
                s.extend_from_slice(&u32::try_from(bitmap.len()).unwrap().to_le_bytes());
                s.push(0x00);
                s.extend_from_slice(&bitmap);
                subcodecs = s;
                for row in usize::from(y)..usize::from(y + sh) {
                    for col in usize::from(x)..usize::from(x + sw) {
                        colour_at[row * w + col] = Some([v; 3]);
                    }
                }
            }
            let mut stream = vec![0x00, 0x00];
            stream.extend_from_slice(&u32::try_from(residual.len()).unwrap().to_le_bytes());
            stream.extend_from_slice(&0u32.to_le_bytes());
            stream.extend_from_slice(&u32::try_from(subcodecs.len()).unwrap().to_le_bytes());
            stream.extend_from_slice(&residual);
            stream.extend_from_slice(&subcodecs);

            let mut tile = seed.repeat(w * h);
            prop_assert_eq!(ClearDecoder::new().decode(&stream, width, height, &mut tile), Ok(()));
            let expected: Vec<u8> = colour_at
                .iter()
                .flat_map(|c| c.map_or(seed, |[b, g, r]| [b, g, r, 0xFF]))
                .collect();
            prop_assert_eq!(tile, expected);
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
        let mut decoded = vec![0; 4 * 2 * 4];
        Clear::new()
            .decode_to_bgra(&stream, 4, 2, &mut decoded)
            .unwrap();
        assert_eq!(decoded, bgra);
    }

    /// A stream that decodes 16 distinct pixels through the residual layer and stores them in glyph
    /// slot `index`: one BGR run of length 1 per pixel, pixel `i` = `(i, 0x40 + i, 0x80 + i)`.
    fn glyph_store_stream(index: u16) -> Vec<u8> {
        let residual: Vec<u8> = (0u8..16).flat_map(|i| [i, 0x40 + i, 0x80 + i, 1]).collect();
        let mut stream = vec![FLAG_GLYPH_INDEX, 0x00];
        stream.extend_from_slice(&index.to_le_bytes());
        stream.extend_from_slice(&u32::try_from(residual.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes()); // bandsByteCount
        stream.extend_from_slice(&0u32.to_le_bytes()); // subcodecByteCount
        stream.extend_from_slice(&residual);
        stream
    }

    fn glyph_hit_stream(index: u16) -> Vec<u8> {
        let mut stream = vec![FLAG_GLYPH_INDEX | FLAG_GLYPH_HIT, 0x01];
        stream.extend_from_slice(&index.to_le_bytes());
        stream
    }

    /// `[MS-RDPEGFX]` 4.1.1.5: a glyph is stored as a linear pixel stream with no dimensions,
    /// and a hit may draw it as any rectangle of the same area — the example caches 2x8 and hits
    /// it as 4x4 and as 8x2.
    #[test]
    fn a_glyph_hit_draws_the_cached_pixels_as_any_rectangle_of_the_same_area() {
        let mut d = ClearDecoder::new();
        let stored = decode_zeroed(&mut d, &glyph_store_stream(4), 2, 8).unwrap();
        let expected: Vec<u8> = (0u8..16)
            .flat_map(|i| [i, 0x40 + i, 0x80 + i, 0xFF])
            .collect();
        assert_eq!(
            stored, expected,
            "the residual layer paints the 16 pixels in order"
        );

        for (w, h) in [(2u16, 8u16), (4, 4), (8, 2), (16, 1)] {
            assert_eq!(
                decode_zeroed(&mut d, &glyph_hit_stream(4), w, h).unwrap(),
                expected,
                "a {w}x{h} hit returns the linear stream unchanged"
            );
        }
    }

    #[test]
    fn a_glyph_hit_of_a_different_area_is_an_error() {
        let mut d = ClearDecoder::new();
        decode_zeroed(&mut d, &glyph_store_stream(4), 2, 8).unwrap();
        for (w, h) in [(3u16, 5u16), (4, 5), (1, 1)] {
            assert_eq!(
                decode_zeroed(&mut d, &glyph_hit_stream(4), w, h),
                Err(invalid(
                    "glyphIndex",
                    "cached glyph area does not match destination"
                )),
                "a {w}x{h} hit has a different area from the 2x8 glyph"
            );
        }
    }

    /// The corrected SHORT_VBAR_CACHE_MISS field layout: `shortVBarYOn` is the low byte and
    /// `shortVBarYOff` is bits `[13:8]`. A header that a swapped reading would see as
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

        let out = decode_zeroed(&mut ClearDecoder::new(), &stream, 1, 52).unwrap();
        // Row 5 (first pixel of the short v-bar) is blue 0xFF,0x00,0x00.
        assert_eq!(&out[5 * 4..5 * 4 + 3], &[0xFF, 0x00, 0x00]);
    }

    fn band(x: [u16; 2], y: [u16; 2], vbars: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [x[0], x[1], y[0], y[1]] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0, 0]);
        b.extend_from_slice(vbars);
        b
    }

    fn short_miss(rows: u8) -> Vec<u8> {
        let mut v = (u16::from(rows) << 8).to_le_bytes().to_vec();
        v.extend_from_slice(&[0x11, 0x22, 0x33].repeat(usize::from(rows)));
        v
    }

    const BAR: [u8; 4] = [0x11, 0x22, 0x33, 0xFF];
    const BKG: [u8; 4] = [0, 0, 0, 0xFF];

    /// `[MS-RDPEGFX]` 2.2.4.1.1.2.1.1.1: the stored V-bar of a VBAR_CACHE_HIT "MUST be equal to 3 *
    /// (yEnd - yStart + 1) bytes".
    #[test]
    fn a_vbar_cache_hit_whose_stored_vbar_is_not_the_band_height_is_refused() {
        let stream = |stored: u16, hit: u16| {
            let mut bands = band([0, 0], [0, stored - 1], &short_miss(stored as u8));
            bands.extend(band([1, 1], [0, hit - 1], &0x8000u16.to_le_bytes()));
            build_stream(&bands)
        };
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &stream(2, 2), 2, 2),
            Ok([BAR, BAR, BAR, BAR].concat()),
            "a stored V-bar of the band height is drawn"
        );
        for (stored, hit) in [(2, 1), (1, 2)] {
            assert_eq!(
                decode_zeroed(&mut ClearDecoder::new(), &stream(stored, hit), 2, 2),
                Err(invalid(
                    "vBarCacheHit",
                    "stored V-bar height is not the band height"
                )),
                "a {stored}-row V-bar hit in a {hit}-row band"
            );
        }
    }

    /// 2.2.4.1.1.2.1.1.2: the stored short V-bar of a SHORT_VBAR_CACHE_HIT "MUST NOT exceed 3 *
    /// (yEnd - yStart + 1 - shortVBarYOn) bytes".
    #[test]
    fn a_short_vbar_cache_hit_past_the_band_is_refused() {
        let stream = |hit: u16, y_on: u8| {
            let mut bands = band([0, 0], [0, 2], &short_miss(2));
            let mut vbar = 0x4000u16.to_le_bytes().to_vec();
            vbar.push(y_on);
            bands.extend(band([1, 1], [0, hit - 1], &vbar));
            build_stream(&bands)
        };
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &stream(3, 1), 2, 3),
            Ok([BAR, BKG, BAR, BAR, BKG, BAR].concat()),
            "a short V-bar that ends on the band's last row is drawn"
        );
        for (hit, y_on) in [(3, 2), (2, 1), (1, 0), (2, 3)] {
            assert_eq!(
                decode_zeroed(&mut ClearDecoder::new(), &stream(hit, y_on), 2, 3),
                Err(invalid(
                    "shortVBarCacheHit",
                    "stored short V-bar exceeds band height - shortVBarYOn"
                )),
                "a 2-row short V-bar at yOn {y_on} in a {hit}-row band"
            );
        }
        let empty_bar_at = |y_on: u8| {
            let mut bands = band([0, 0], [0, 2], &short_miss(0));
            bands.extend(band([1, 1], [0, 1], &[0x00, 0x40, y_on]));
            decode_zeroed(&mut ClearDecoder::new(), &build_stream(&bands), 2, 3)
        };
        assert_eq!(
            empty_bar_at(2),
            Ok([BKG, BKG, BKG, BKG, BKG, [0; 4]].concat()),
            "an empty short V-bar at the end of a 2-row band is drawn"
        );
        assert_eq!(
            empty_bar_at(3),
            Err(invalid(
                "shortVBarCacheHit",
                "stored short V-bar exceeds band height - shortVBarYOn"
            )),
            "an empty short V-bar at yOn 3 in a 2-row band"
        );
    }

    #[test]
    fn a_band_outside_the_tile_is_refused() {
        let stream = |x_end: u16, y_end: u16| {
            let vbars = [0u8, 0].repeat(usize::from(x_end) + 1);
            build_stream(&band([0, x_end], [0, y_end], &vbars))
        };
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &stream(1, 1), 2, 2),
            Ok(BKG.repeat(4))
        );
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &stream(2, 1), 2, 2),
            Err(invalid("xEnd", "band column outside the tile"))
        );
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &stream(1, 2), 2, 2),
            Err(invalid("yEnd", "band row outside the tile"))
        );
    }

    fn glyph_tile_stream(w: u16, h: u16) -> Vec<u8> {
        let mut residual = vec![1, 2, 3, 0xFF];
        residual.extend_from_slice(&(w * h).to_le_bytes());
        let mut stream = vec![FLAG_GLYPH_INDEX, 0x00, 9, 0];
        stream.extend_from_slice(&u32::try_from(residual.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&residual);
        stream
    }

    /// 2.2.4.1: GLYPH_INDEX "MUST NOT be used" on a bitmap larger than 1,024 square pixels.
    #[test]
    fn a_glyph_index_on_a_tile_over_1024_pixels_is_refused() {
        let mut d = ClearDecoder::new();
        let tile = [1u8, 2, 3, 0xFF].repeat(1024);
        assert_eq!(
            decode_zeroed(&mut d, &glyph_tile_stream(32, 32), 32, 32),
            Ok(tile.clone())
        );
        assert_eq!(
            decode_zeroed(&mut d, &glyph_hit_stream(9), 32, 32),
            Ok(tile)
        );
        for (w, h) in [(33u16, 32u16), (1025, 1)] {
            assert_eq!(
                decode_zeroed(&mut ClearDecoder::new(), &glyph_tile_stream(w, h), w, h),
                Err(invalid(
                    "glyphIndex",
                    "GLYPH_INDEX on a tile over 1024 pixels"
                )),
                "{w}x{h}"
            );
        }
    }

    /// 2.2.4.1: with GLYPH_HIT "the compositePayload field MUST NOT be present".
    #[test]
    fn a_glyph_hit_with_bytes_after_the_glyph_header_is_refused() {
        for trailing in [1usize, 11, 12, 13] {
            let mut d = ClearDecoder::new();
            decode_zeroed(&mut d, &glyph_store_stream(4), 2, 8).unwrap();
            let mut hit = glyph_hit_stream(4);
            hit.extend(std::iter::repeat_n(0, trailing));
            assert_eq!(
                decode_zeroed(&mut d, &hit, 2, 8),
                Err(invalid("compositePayload", "present with GLYPH_HIT")),
                "{trailing} trailing byte(s)"
            );
        }
    }

    #[test]
    fn a_stream_without_glyph_hit_and_with_no_composite_payload_is_refused() {
        let missing = Err(ClearError::NotEnoughBytes {
            ctx: "CompositePayload",
        });
        let mut d = ClearDecoder::new();
        assert_eq!(
            decode_zeroed(&mut d, &[FLAG_GLYPH_INDEX, 0x00, 4, 0], 2, 8),
            missing
        );
        assert_eq!(
            decode_zeroed(&mut d, &glyph_hit_stream(4), 2, 8),
            Err(invalid("glyphIndex", "glyph cache miss on hit")),
            "the refused stream stored no glyph"
        );
        for flags in [0x00, FLAG_CACHE_RESET] {
            assert_eq!(
                decode_zeroed(&mut ClearDecoder::new(), &[flags, 0x00], 2, 2),
                missing,
                "flags {flags:#04x}"
            );
        }
    }

    #[test]
    fn a_refused_cache_reset_only_stream_still_resets_the_vbar_cursors() {
        let store = |bgr: [u8; 3]| {
            let mut vbar = (2u16 << 8).to_le_bytes().to_vec();
            vbar.extend_from_slice(&bgr.repeat(2));
            build_stream(&band([0, 0], [0, 1], &vbar))
        };
        let hit_slot_0 = build_stream(&band([0, 0], [0, 1], &0x8000u16.to_le_bytes()));
        let short_hit_slot_0 = build_stream(&band([0, 0], [0, 1], &[0x00, 0x40, 0]));
        let mut d = ClearDecoder::new();
        decode_zeroed(&mut d, &store([1, 2, 3]), 1, 2).unwrap();
        assert_eq!(
            decode_zeroed(&mut d, &[FLAG_CACHE_RESET, 0x00], 1, 2),
            Err(ClearError::NotEnoughBytes {
                ctx: "CompositePayload"
            })
        );
        decode_zeroed(&mut d, &store([7, 8, 9]), 1, 2).unwrap();
        assert_eq!(
            decode_zeroed(&mut d, &hit_slot_0, 1, 2),
            Ok([7, 8, 9, 0xFF].repeat(2)),
            "the second V-bar overwrote slot 0"
        );
        assert_eq!(
            decode_zeroed(&mut d, &short_hit_slot_0, 1, 2),
            Ok([7, 8, 9, 0xFF].repeat(2)),
            "the second short V-bar overwrote slot 0"
        );
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

    // Pixel counts (module docs, decision 2): a run or suite past the region is refused, a region
    // that receives fewer pixels than it holds decodes. palette_count=2 keeps the RLEX cases off
    // the single-palette path.

    /// A one-segment RLEX bitmap: palette of 2 BGR colors, packed byte `0x00`
    /// (stopIndex=0, suiteDepth=0, startIndex=0) → `run_length` run px + 1 suite px of palette[0].
    fn rlex_bitmap(run_length: u8) -> Vec<u8> {
        vec![2, 10, 20, 30, 40, 50, 60, 0x00, run_length]
    }

    #[test]
    fn rlex_run_overrunning_the_region_is_refused() {
        // run=5 into a 2-px region.
        let mut out = vec![0u8; 2 * 4];
        assert_eq!(
            decode_rlex_region(&rlex_bitmap(5), &mut out, 0, 0, 2, 1, 2),
            Err(invalid("rlex", "run overruns the region"))
        );
    }

    #[test]
    fn rlex_suite_overrunning_the_region_is_refused() {
        // run=2 fills the 2-px region; the 1-px suite after it would be the third pixel.
        let mut out = vec![0u8; 2 * 4];
        assert_eq!(
            decode_rlex_region(&rlex_bitmap(2), &mut out, 0, 0, 2, 1, 2),
            Err(invalid("rlex", "suite overruns the region"))
        );
    }

    #[test]
    fn rlex_under_fill_leaves_the_rest_of_the_region_as_it_was() {
        // run=0 (+1 suite = 1 px) into a 4-px region that an earlier layer painted 7s.
        let mut out = vec![7u8; 4 * 4];
        assert_eq!(
            decode_rlex_region(&rlex_bitmap(0), &mut out, 0, 0, 4, 1, 4),
            Ok(())
        );
        assert_eq!(&out[0..4], &[10, 20, 30, 0xFF]); // 1 suite px painted
        assert_eq!(&out[4..], &[7u8; 12]); // remainder as the earlier layer left it
    }

    /// A residual-only ClearCodec stream: `runs` as (B, G, R, one-byte run length).
    fn residual_stream(runs: &[[u8; 4]]) -> Vec<u8> {
        let residual: Vec<u8> = runs.iter().flatten().copied().collect();
        residual_bytes_stream(&residual)
    }

    #[test]
    fn residual_run_overrunning_the_tile_is_refused() {
        // 2 + 2 px into a 3-px tile: the second run overruns by one.
        let stream = residual_stream(&[[1, 2, 3, 2], [4, 5, 6, 2]]);
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &stream, 3, 1),
            Err(invalid("residual", "run overruns the tile"))
        );
    }

    #[test]
    fn residual_under_fill_decodes_and_keeps_the_seed_over_the_rest() {
        let mut tile = [0xEE; 3 * 4];
        ClearDecoder::new()
            .decode(&residual_stream(&[[1, 2, 3, 2]]), 3, 1, &mut tile)
            .unwrap();
        assert_eq!(tile, [1, 2, 3, 0xFF, 1, 2, 3, 0xFF, 0xEE, 0xEE, 0xEE, 0xEE]);
    }

    #[test]
    fn a_pixel_no_layer_reaches_keeps_the_seed() {
        const SEED: [u8; 4] = [0xEE, 0xDD, 0xCC, 0x11];
        let onto_seed = |d: &mut ClearDecoder, stream: &[u8], w: u16, h: u16| {
            decode_onto(d, stream, w, h, SEED)
        };
        let raw_1x1 = subcodec_stream(&subcodec(1, 0x00, &[9, 8, 7]));
        assert_eq!(
            onto_seed(&mut ClearDecoder::new(), &raw_1x1, 2, 1),
            Ok([[9, 8, 7, 0xFF], SEED].concat()),
            "no residual layer, and a subcodec over half the tile"
        );
        assert_eq!(
            onto_seed(
                &mut ClearDecoder::new(),
                &build_stream(&background_band(2)),
                3,
                1
            ),
            Ok([[7, 8, 9, 0xFF], [7, 8, 9, 0xFF], SEED].concat()),
            "a band over two of three columns"
        );

        let mut d = ClearDecoder::new();
        let mut store = vec![FLAG_GLYPH_INDEX, 0x00, 3, 0];
        store.extend_from_slice(&raw_1x1[2..]);
        let stored = [[9, 8, 7, 0xFF], SEED].concat();
        assert_eq!(onto_seed(&mut d, &store, 2, 1), Ok(stored.clone()));
        let mut hit_tile = [0u8; 2 * 4];
        d.decode(&glyph_hit_stream(3), 1, 2, &mut hit_tile).unwrap();
        assert_eq!(
            hit_tile.to_vec(),
            stored,
            "the hit draws the seed it was stored over"
        );
    }

    #[test]
    fn a_tile_of_the_wrong_length_leaves_the_vbar_cursors_alone() {
        let mut d = ClearDecoder::new();
        let first = build_stream(&band([0, 0], [0, 0], &short_miss(1)));
        decode_zeroed(&mut d, &first, 1, 1).unwrap();
        let mut reset = first.clone();
        reset[0] = FLAG_CACHE_RESET;
        assert_eq!(
            d.decode(&reset, 1, 1, &mut [0; 3]),
            Err(ClearError::OutputLength {
                width: 1,
                height: 1,
                len: 3
            })
        );
        let mut other = (1u16 << 8).to_le_bytes().to_vec();
        other.extend_from_slice(&[0x44, 0x55, 0x66]);
        decode_zeroed(&mut d, &build_stream(&band([0, 0], [0, 0], &other)), 1, 1).unwrap();
        let hit_slot_0 = build_stream(&band([0, 0], [0, 0], &0x8000u16.to_le_bytes()));
        assert_eq!(decode_zeroed(&mut d, &hit_slot_0, 1, 1), Ok(BAR.to_vec()));
    }

    #[test]
    fn a_tile_of_the_wrong_length_is_an_error() {
        let stream = residual_stream(&[[1, 2, 3, 2]]);
        for len in [0, 7, 9, 12] {
            let mut tile = vec![0; len];
            assert_eq!(
                ClearDecoder::new().decode(&stream, 2, 1, &mut tile),
                Err(ClearError::OutputLength {
                    width: 2,
                    height: 1,
                    len
                }),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn residual_trailing_bytes_shorter_than_a_segment_are_refused() {
        for trailing in 1..=3 {
            let mut stream = residual_stream(&[[1, 2, 3, 3]]);
            stream.extend(std::iter::repeat_n(0xAA, trailing));
            stream[2..6].copy_from_slice(&u32::try_from(4 + trailing).unwrap().to_le_bytes());
            assert_eq!(
                decode_zeroed(&mut ClearDecoder::new(), &stream, 3, 1),
                Err(ClearError::NotEnoughBytes {
                    ctx: "RgbRunSegment"
                }),
                "{trailing} trailing byte(s)"
            );
        }
    }

    #[test]
    fn residual_run_length_factor1_of_zero_is_refused() {
        // A zero run, then a run that fills the tile.
        let stream = residual_stream(&[[1, 2, 3, 0], [4, 5, 6, 3]]);
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &stream, 3, 1),
            Err(invalid("residual", "runLengthFactor1 is zero"))
        );
    }

    /// A subcodec-only ClearCodec stream holding `subcodecs` verbatim.
    fn subcodec_stream(subcodecs: &[u8]) -> Vec<u8> {
        let mut stream = vec![0x00, 0x00]; // flags, seq
        stream.extend_from_slice(&0u32.to_le_bytes()); // residualByteCount
        stream.extend_from_slice(&0u32.to_le_bytes()); // bandsByteCount
        stream.extend_from_slice(&u32::try_from(subcodecs.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(subcodecs);
        stream
    }

    /// One CLEARCODEC_SUBCODEC at the origin: `width`x1, `codec_id`, `bitmap` verbatim.
    fn subcodec(width: u16, codec_id: u8, bitmap: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        for v in [0u16, 0, width, 1] {
            s.extend_from_slice(&v.to_le_bytes());
        }
        s.extend_from_slice(&u32::try_from(bitmap.len()).unwrap().to_le_bytes());
        s.push(codec_id);
        s.extend_from_slice(bitmap);
        s
    }

    #[test]
    fn subcodec_trailing_bytes_shorter_than_a_header_are_refused() {
        for trailing in 1..=12 {
            let mut subcodecs = subcodec(2, 0x00, &[1, 2, 3, 4, 5, 6]);
            subcodecs.extend(std::iter::repeat_n(0xAA, trailing));
            assert_eq!(
                decode_zeroed(&mut ClearDecoder::new(), &subcodec_stream(&subcodecs), 2, 1),
                Err(ClearError::NotEnoughBytes {
                    ctx: "ClearCodecSubcodec"
                }),
                "{trailing} trailing byte(s)"
            );
        }
    }

    #[test]
    fn raw_subcodec_byte_count_above_three_per_pixel_is_refused() {
        let exact = subcodec(2, 0x00, &[1, 2, 3, 4, 5, 6]);
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &subcodec_stream(&exact), 2, 1),
            Ok(vec![1, 2, 3, 0xFF, 4, 5, 6, 0xFF])
        );
        let over = subcodec(2, 0x00, &[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &subcodec_stream(&over), 2, 1),
            Err(invalid("bitmapDataByteCount", "exceeds 3 * width * height"))
        );
        let short = subcodec(2, 0x00, &[1, 2, 3, 4, 5]);
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &subcodec_stream(&short), 2, 1),
            Err(invalid("bitmapData", "raw subcodec data too short"))
        );
    }

    #[test]
    fn residual_exact_fill_paints_the_whole_tile() {
        let out = decode_zeroed(
            &mut ClearDecoder::new(),
            &residual_stream(&[[1, 2, 3, 1], [4, 5, 6, 2]]),
            3,
            1,
        )
        .unwrap();
        assert_eq!(out, [1, 2, 3, 0xFF, 4, 5, 6, 0xFF, 4, 5, 6, 0xFF]);
    }

    /// `[MS-RDPEGFX]` 4.1.1.2 (Example 2), the 144-byte stream verbatim: one 78x17 RLEX region,
    /// no residual or bands layer.
    const SPEC_EXAMPLE_2: [u8; 144] = [
        0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4e, 0x00, 0x11, 0x00, 0x75, 0x00, 0x00, 0x00, 0x02, 0x0e, 0xff, 0xff,
        0xff, 0x00, 0x00, 0x00, 0xdb, 0xff, 0xff, 0x00, 0x3a, 0x90, 0xff, 0xb6, 0x66, 0x66, 0xb6,
        0xff, 0xb6, 0x66, 0x00, 0x90, 0xdb, 0xff, 0x00, 0x00, 0x3a, 0xdb, 0x90, 0x3a, 0x3a, 0x90,
        0xdb, 0x66, 0x00, 0x00, 0xff, 0xff, 0xb6, 0x64, 0x64, 0x64, 0x11, 0x04, 0x11, 0x4c, 0x11,
        0x4c, 0x11, 0x4c, 0x11, 0x4c, 0x11, 0x4c, 0x00, 0x47, 0x13, 0x00, 0x01, 0x01, 0x04, 0x00,
        0x01, 0x00, 0x00, 0x47, 0x16, 0x00, 0x11, 0x02, 0x00, 0x47, 0x29, 0x00, 0x11, 0x01, 0x00,
        0x49, 0x0a, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x4a, 0x0a, 0x00, 0x09, 0x00,
        0x01, 0x00, 0x00, 0x47, 0x05, 0x00, 0x01, 0x01, 0x1c, 0x00, 0x01, 0x00, 0x11, 0x4c, 0x11,
        0x4c, 0x11, 0x4c, 0x00, 0x47, 0x0d, 0x4d, 0x00, 0x4d,
    ];

    #[test]
    fn spec_example_2_fills_its_region_exactly() {
        // The RLEX bitmap starts after the 14-byte stream header and the 13-byte subcodec header.
        let rlex = decode_rlex(&SPEC_EXAMPLE_2[27..]).unwrap();
        let emitted: usize = rlex
            .segments
            .iter()
            .map(|s| cast_usize(s.run_length) + usize::from(s.stop_index - s.start_index) + 1)
            .sum();
        assert_eq!(emitted, 78 * 17);
        let out = decode_zeroed(&mut ClearDecoder::new(), &SPEC_EXAMPLE_2, 78, 17).unwrap();
        assert_eq!(out.len(), 78 * 17 * 4);
        assert!(out.as_chunks::<4>().0.iter().all(|px| px[3] == 0xFF));
    }

    #[test]
    fn rlex_exact_fill_paints_the_whole_region() {
        // run=1 (+1 suite = 2 px) exactly fills a 2-px region.
        let mut out = vec![0u8; 2 * 4];
        assert!(decode_rlex_region(&rlex_bitmap(1), &mut out, 0, 0, 2, 1, 2).is_ok());
        assert_eq!(&out[0..4], &[10, 20, 30, 0xFF]);
        assert_eq!(&out[4..8], &[10, 20, 30, 0xFF]);
    }

    #[test]
    fn single_palette_rlex_validates_the_packed_index_byte() {
        // palette_count=1, palette=[10,20,30]; packed byte 0x01 → stopIndex=1, which exceeds the
        // single-entry palette → reject (FreeRDP `clear.c` `startIndex/stopIndex >= paletteCount`).
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
        for px in out.as_chunks::<4>().0 {
            assert_eq!(px, &[10, 20, 30, 0xFF]);
        }
    }

    #[test]
    fn rlex_suite_depth_exceeding_stop_index_is_rejected() {
        // #127: a packed byte whose suiteDepth > stopIndex would underflow startIndex. FreeRDP
        // rejects it (wrapping start >= paletteCount); we reject the underflow directly. packed
        // 0x02 → stopIndex=0, suiteDepth=1 (palette_count=2 → 1 stop-index bit).
        let bitmap = vec![2, 10, 20, 30, 40, 50, 60, 0x02, 0x00];
        let mut out = vec![0u8; 4];
        assert!(
            decode_rlex_region(&bitmap, &mut out, 0, 0, 1, 1, 1).is_err(),
            "suiteDepth exceeding stopIndex must be rejected"
        );
    }

    /// A 16-pixel NSCodec stream (ColorLossLevel 1, no subsampling) whose four planes are each one
    /// RLE run of `[y, co, cg, alpha]`: 48 bytes, exactly `3 * 16`.
    fn nscodec_16px(extra: &[u8]) -> Vec<u8> {
        nscodec_16px_alpha(255, extra)
    }

    fn nscodec_16px_alpha(alpha: u8, extra: &[u8]) -> Vec<u8> {
        let plane = |v: u8| [v, v, 10, v, v, v, v]; // a run of 12, then the 4-byte raw tail
        let mut nsc = Vec::new();
        for _ in 0..4 {
            nsc.extend_from_slice(&7u32.to_le_bytes()); // plane byte counts
        }
        nsc.push(1); // ColorLossLevel
        nsc.push(0); // ChromaSubsamplingLevel
        nsc.extend_from_slice(&[0, 0]); // reserved
        for v in [100, 10, 5, alpha] {
            nsc.extend_from_slice(&plane(v)); // Y, Co, Cg, A
        }
        nsc.extend_from_slice(extra);
        nsc
    }

    #[test]
    fn nscodec_subcodec_decodes_into_the_region() {
        let stream = subcodec_stream(&subcodec(16, 0x01, &nscodec_16px(&[])));
        let out = decode_zeroed(&mut ClearDecoder::new(), &stream, 16, 1).unwrap();
        // Y100 Co10 Cg5, shift 0 → R=105 G=105 B=85; BGRA.
        assert_eq!(out, [85, 105, 105, 255].repeat(16));
    }

    #[test]
    fn an_nscodec_subcodec_writes_alpha_0xff_whatever_its_alpha_plane() {
        for alpha in [0, 0x80] {
            let stream = subcodec_stream(&subcodec(16, 0x01, &nscodec_16px_alpha(alpha, &[])));
            assert_eq!(
                decode_zeroed(&mut ClearDecoder::new(), &stream, 16, 1),
                Ok([85, 105, 105, 255].repeat(16)),
                "alpha plane {alpha}"
            );
        }
    }

    #[test]
    fn subcodec_byte_count_above_three_per_pixel_is_refused_for_every_subcodec() {
        let over = Err(invalid("bitmapDataByteCount", "exceeds 3 * width * height"));
        // NSCodec: 48 bytes into 16 px decodes, 49 is refused.
        let nsc = |extra: &[u8]| subcodec_stream(&subcodec(16, 0x01, &nscodec_16px(extra)));
        assert!(decode_zeroed(&mut ClearDecoder::new(), &nsc(&[]), 16, 1).is_ok());
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &nsc(&[0]), 16, 1),
            over
        );
        // RLEX: the 9-byte two-entry-palette bitmap, `run` run pixels and one suite pixel.
        let rlex = |width: u16, run: u8| subcodec_stream(&subcodec(width, 0x02, &rlex_bitmap(run)));
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &rlex(3, 2), 3, 1),
            Ok([10, 20, 30, 0xFF].repeat(3))
        );
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &rlex(2, 1), 2, 1),
            over,
            "a run and suite that fill the 2-px region exactly, in 9 bytes"
        );
    }

    /// A residual-only ClearCodec stream holding `residual` verbatim.
    fn residual_bytes_stream(residual: &[u8]) -> Vec<u8> {
        let mut stream = vec![0x00, 0x00]; // flags, seq
        stream.extend_from_slice(&u32::try_from(residual.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes()); // bandsByteCount
        stream.extend_from_slice(&0u32.to_le_bytes()); // subcodecByteCount
        stream.extend_from_slice(residual);
        stream
    }

    #[test]
    fn residual_run_length_factor2_or_factor3_of_zero_is_refused() {
        let tile = [1, 2, 3, 0xFF].repeat(3);
        // runLengthFactor2 = 3, and runLengthFactor3 = 3, each fill the 3-px tile.
        let factor2 = |n: u8| residual_bytes_stream(&[1, 2, 3, 0xFF, n, 0, 4, 5, 6, 3]);
        let factor3 =
            |n: u8| residual_bytes_stream(&[1, 2, 3, 0xFF, 0xFF, 0xFF, n, 0, 0, 0, 4, 5, 6, 3]);
        let fill2 = residual_bytes_stream(&[1, 2, 3, 0xFF, 3, 0]);
        let fill3 = residual_bytes_stream(&[1, 2, 3, 0xFF, 0xFF, 0xFF, 3, 0, 0, 0]);
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &fill2, 3, 1),
            Ok(tile.clone())
        );
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &fill3, 3, 1),
            Ok(tile)
        );
        // A zero factor, then a run that fills the tile.
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &factor2(0), 3, 1),
            Err(invalid("residual", "runLengthFactor2 is zero"))
        );
        assert_eq!(
            decode_zeroed(&mut ClearDecoder::new(), &factor3(0), 3, 1),
            Err(invalid("residual", "runLengthFactor3 is zero"))
        );
    }

    /// One band over `width`x1 whose every column is a zero-pixel SHORT_VBAR_CACHE_MISS, so the
    /// band paints its background BGR 7, 8, 9.
    fn background_band(width: u16) -> Vec<u8> {
        let mut band = Vec::new();
        for v in [0u16, width - 1, 0, 0] {
            band.extend_from_slice(&v.to_le_bytes());
        }
        band.extend_from_slice(&[7, 8, 9]);
        for _ in 0..width {
            band.extend_from_slice(&0u16.to_le_bytes());
        }
        band
    }

    #[test]
    fn bands_trailing_bytes_shorter_than_a_band_header_are_refused() {
        assert_eq!(
            decode_zeroed(
                &mut ClearDecoder::new(),
                &build_stream(&background_band(2)),
                2,
                1
            ),
            Ok([7, 8, 9, 0xFF].repeat(2))
        );
        for trailing in 1..=10 {
            let mut bands = background_band(2);
            bands.extend(std::iter::repeat_n(0xAA, trailing));
            assert_eq!(
                decode_zeroed(&mut ClearDecoder::new(), &build_stream(&bands), 2, 1),
                Err(ClearError::NotEnoughBytes {
                    ctx: "ClearCodecBand"
                }),
                "{trailing} trailing byte(s)"
            );
        }
    }
}
