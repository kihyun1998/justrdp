//! Replay + differential anchor over the real-VM ClearCodec corpus (issue #56).
//!
//! `fixtures/clearcodec/replay.bin` is one full session's worth of genuine `CODECID_CLEARCODEC`
//! payloads captured from the test VM, **in arrival order** (see the README). Order matters:
//! ClearCodec is stateful (the V-bar and glyph caches span PDUs), so a cache-hit stream only
//! resolves when the earlier streams that populated those entries are replayed first. Decoding a
//! single captured payload in isolation would spuriously miss the cache — these tests replay the
//! whole sequence through one decoder, the way the live session does.
//!
//! `fixtures/clearcodec/replay-text.bin` is a second capture in the same format, from a session
//! with text typed into Notepad; it holds the glyph hits `replay.bin` lacks.
//!
//! What is asserted:
//!
//! 1. The self-owned decoder replays each capture without error, and the `ironrdp-graphics`
//!    oracle's output is byte-identical to it (ADR-0003 phase-2 acceptance).
//! 2. A parser in this file, independent of the decoder, counts the shapes the decoder was fixed
//!    for in `replay.bin` (ADR-0007's coverage rule), and that every RLEX region and every
//!    residual layer fills exactly.
//! 3. Every glyph hit in `replay-text.bin` is drawn from the pixels its slot's store decoded to.

use justrdp_codecs::clearcodec::ClearDecoder;

/// One captured payload with the destination-rectangle dimensions it was decoded against.
struct Entry {
    width: u16,
    height: u16,
    data: Vec<u8>,
}

fn load_replay() -> Vec<Entry> {
    load("replay.bin")
}

/// The typed-text capture: a Notepad session with text typed into it, which draws glyph hits.
fn load_text_replay() -> Vec<Entry> {
    load("replay-text.bin")
}

fn load(name: &str) -> Vec<Entry> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/clearcodec")
        .join(name);
    let buf = std::fs::read(path).expect("the ClearCodec replay corpus must be present");

    let mut entries = Vec::new();
    let count = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let mut pos = 4usize;
    for _ in 0..count {
        let width = u16::from_le_bytes(buf[pos..pos + 2].try_into().unwrap());
        let height = u16::from_le_bytes(buf[pos + 2..pos + 4].try_into().unwrap());
        let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        entries.push(Entry {
            width,
            height,
            data: buf[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    entries
}

#[test]
fn corpus_is_present_and_non_trivial() {
    let entries = load_replay();
    assert!(
        entries.len() >= 8,
        "replay corpus is suspiciously small ({} entries)",
        entries.len()
    );
}

/// The headline #56 result: the self-owned decoder replays the full captured session without a
/// single rejection — reproducing, VM-free, what the live capture observed.
///
/// This is also the **no-holes** proof. A Clear-region hole arises only when a stream fails to
/// decode and the core's warn-and-skip policy leaves the region un-painted; zero rejections
/// across the whole capture means zero skips, hence no holes. (Per-pixel blackness cannot stand
/// in for "hole" — a single-entry black palette is legitimate all-black content, e.g. entry 0.)
/// The aggregate non-black tally guards the converse: that the decoder genuinely paints content
/// rather than silently returning zeroed buffers.
#[test]
fn self_owned_replays_full_capture_without_error() {
    let mut decoder = ClearDecoder::new();
    let mut nonblack_total = 0usize;
    for (i, e) in load_replay().iter().enumerate() {
        let out = decoder
            .decode(&e.data, e.width, e.height)
            .unwrap_or_else(|err| {
                panic!(
                    "entry {i} ({}x{}) failed to decode: {err}",
                    e.width, e.height
                )
            });
        assert_eq!(
            out.len(),
            usize::from(e.width) * usize::from(e.height) * 4,
            "entry {i} decoded to the wrong BGRA size"
        );
        nonblack_total += out
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|px| px[0] != 0 || px[1] != 0 || px[2] != 0)
            .count();
    }
    assert!(
        nonblack_total > 1000,
        "the whole capture decoded to (near-)black ({nonblack_total} non-black px) — the decoder \
         is not painting real content"
    );
}

/// Differential acceptance: feed the ordered sequence to both the self-owned decoder and the
/// `ironrdp-graphics` oracle, each stateful. Both accept every entry, and the outputs are
/// byte-identical (ADR-0003 phase-2 acceptance).
#[test]
fn self_owned_matches_oracle_on_every_entry() {
    let entries = load_replay();
    assert!(!entries.is_empty(), "the replay corpus is empty");

    let mut mine = ClearDecoder::new();
    let mut oracle = ironrdp_graphics::clearcodec::ClearCodecDecoder::new();

    for (i, e) in entries.iter().enumerate() {
        let ours = mine
            .decode(&e.data, e.width, e.height)
            .unwrap_or_else(|err| panic!("entry {i}: self-owned decoder rejected it: {err}"));
        let theirs = oracle
            .decode(&e.data, e.width, e.height)
            .unwrap_or_else(|err| panic!("entry {i}: oracle rejected it: {err}"));
        assert_eq!(
            ours, theirs,
            "entry {i} ({}x{}): self-owned BGRA differs from the oracle",
            e.width, e.height
        );
    }
}

/// What a walk of the corpus's wire structure found: the shapes #56 fixed, counted by this file's
/// own parser rather than inferred from an oracle's rejections (ADR-0007).
#[derive(Default, Debug)]
struct Census {
    /// SHORT_VBAR_CACHE_MISS headers whose bits `[15:6]` exceed 63: `shortVBarYOff` >= 16. Read
    /// with the swapped layout (`yOn = h >> 6`, `yOff = h & 0x3F`), such a `yOn` exceeds every
    /// 6-bit `yOff`, so the swap rejects the band.
    short_vbar_miss_high: usize,
    /// Full V-bar cache hits (header bit 15).
    vbar_hits: usize,
    /// Full V-bar cache hits on a column last stored by a stream the swapped layout rejects as a
    /// whole, so a decoder reading the swap holds no such column when the hit arrives.
    vbar_hits_on_swap_rejected: usize,
    /// Streams with a non-empty residual layer.
    residual_layers: usize,
    /// Residual layers whose runs emit fewer pixels than `width * height`.
    residual_under: usize,
    /// Residual layers whose runs emit more pixels than `width * height`.
    residual_over: usize,
    /// RLEX subcodec regions.
    rlex_regions: usize,
    /// RLEX regions with a one-entry palette.
    rlex_single_palette: usize,
    /// RLEX regions whose segments emit a pixel count other than `width * height`.
    rlex_inexact: usize,
    /// Streams carrying GLYPH_HIT.
    glyph_hits: usize,
    /// Glyph hits whose rectangle differs from the one the slot was stored with.
    glyph_hits_reshaped: usize,
}

/// The cache bookkeeping a walk needs across streams: glyph slots' rectangles, and which stream
/// last stored each full V-bar slot.
struct Caches {
    glyphs: std::collections::HashMap<u16, (u16, u16)>,
    vbar_owner: Vec<Option<usize>>,
    vbar_cursor: usize,
    swap_rejected: Vec<bool>,
}

/// Full V-bar storage capacity (`[MS-RDPEGFX]` 3.3.1.10).
const VBAR_SLOTS: usize = 32_768;

impl Caches {
    fn new() -> Self {
        Self {
            glyphs: std::collections::HashMap::new(),
            vbar_owner: vec![None; VBAR_SLOTS],
            vbar_cursor: 0,
            swap_rejected: Vec::new(),
        }
    }
}

/// One V-bar event of a stream, in wire order.
enum VBarEvent {
    /// A column stored at the cursor (a short V-bar cache miss or hit).
    Store,
    /// A full V-bar cache hit on a slot.
    Hit(usize),
}

/// A bounds-checked reader over one layer; every read panics with `ctx` on underflow, since a
/// corpus stream that does not parse is a broken fixture, not a decoder case.
struct Walk<'a> {
    data: &'a [u8],
    pos: usize,
    ctx: String,
}

impl<'a> Walk<'a> {
    fn new(data: &'a [u8], ctx: String) -> Self {
        Self { data, pos: 0, ctx }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn bytes(&mut self, n: usize) -> &'a [u8] {
        assert!(
            self.remaining() >= n,
            "{}: truncated at byte {}",
            self.ctx,
            self.pos
        );
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        s
    }

    fn u8(&mut self) -> u8 {
        self.bytes(1)[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.bytes(2).try_into().unwrap())
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.bytes(4).try_into().unwrap())
    }

    /// The variable-length run shared by the residual and RLEX layers (`[MS-RDPEGFX]`
    /// 2.2.4.1.1.1.1, 2.2.4.1.1.3.1.1.2).
    fn run_length(&mut self) -> u64 {
        let factor1 = self.u8();
        if factor1 < 0xFF {
            return u64::from(factor1);
        }
        let factor2 = self.u16();
        if factor2 < 0xFFFF {
            return u64::from(factor2);
        }
        u64::from(self.u32())
    }

    fn assert_consumed(&self) {
        assert_eq!(self.remaining(), 0, "{}: trailing bytes", self.ctx);
    }
}

/// Walk one ClearCodec stream's structure (`[MS-RDPEGFX]` 2.2.4.1) and add what it holds to
/// `census`. Every V-bar header says how many bytes follow it, so the parse needs no pixels.
fn walk_stream(i: usize, entry: &Entry, caches: &mut Caches, census: &mut Census) {
    let mut stream = Walk::new(&entry.data, format!("entry {i}"));
    let flags = stream.u8();
    stream.u8(); // seqNumber
    let glyph_index = (flags & 0x01 != 0).then(|| stream.u16());
    if flags & 0x04 != 0 {
        caches.vbar_cursor = 0; // CACHE_RESET
    }
    let mut swap_rejected = false;
    let mut events = Vec::new();
    if flags & 0x02 != 0 {
        census.glyph_hits += 1;
        let stored = glyph_index.and_then(|index| caches.glyphs.get(&index));
        if stored != Some(&(entry.width, entry.height)) {
            census.glyph_hits_reshaped += 1;
        }
        stream.assert_consumed();
        caches.swap_rejected.push(false);
        return;
    }
    // `[MS-RDPEGFX]` 3.3.1.9: a slot holds a glyph of at most 1,024 pixels.
    if let Some(index) = glyph_index
        && u32::from(entry.width) * u32::from(entry.height) <= 1024
    {
        caches.glyphs.insert(index, (entry.width, entry.height));
    }
    if stream.remaining() > 0 {
        let residual_len = stream.u32() as usize;
        let bands_len = stream.u32() as usize;
        let subcodec_len = stream.u32() as usize;
        let residual = stream.bytes(residual_len);
        let bands = stream.bytes(bands_len);
        let subcodec = stream.bytes(subcodec_len);
        stream.assert_consumed();

        let mut layer = Walk::new(residual, format!("entry {i} residual"));
        let mut emitted = 0u64;
        while layer.remaining() > 0 {
            layer.bytes(3);
            emitted += layer.run_length();
        }
        if !residual.is_empty() {
            census.residual_layers += 1;
            let pixels = u64::from(entry.width) * u64::from(entry.height);
            census.residual_under += usize::from(emitted < pixels);
            census.residual_over += usize::from(emitted > pixels);
        }

        let mut layer = Walk::new(bands, format!("entry {i} bands"));
        while layer.remaining() > 0 {
            let x_start = layer.u16();
            let x_end = layer.u16();
            let y_start = layer.u16();
            let y_end = layer.u16();
            layer.bytes(3); // background BGR
            let band_height = y_end.wrapping_sub(y_start).wrapping_add(1);
            for _ in x_start..=x_end {
                let header = layer.u16();
                if header & 0x8000 != 0 {
                    census.vbar_hits += 1;
                    events.push(VBarEvent::Hit(usize::from(header & 0x7FFF)));
                } else if header & 0x4000 != 0 {
                    layer.u8(); // shortVBarYOn
                    events.push(VBarEvent::Store);
                } else {
                    let y_on = header & 0x00FF;
                    let y_off = (header >> 8) & 0x3F;
                    if header >> 6 > 63 {
                        census.short_vbar_miss_high += 1;
                    }
                    let (swapped_on, swapped_off) = (header >> 6, header & 0x3F);
                    if swapped_off < swapped_on || swapped_off > band_height {
                        swap_rejected = true;
                    }
                    layer.bytes(usize::from(y_off.saturating_sub(y_on)) * 3);
                    events.push(VBarEvent::Store);
                }
            }
        }

        let mut layer = Walk::new(subcodec, format!("entry {i} subcodec"));
        while layer.remaining() > 0 {
            layer.u16(); // xStart
            layer.u16(); // yStart
            let width = layer.u16();
            let height = layer.u16();
            let len = layer.u32() as usize;
            let codec_id = layer.u8();
            let bitmap = layer.bytes(len);
            if codec_id != 0x02 {
                continue;
            }
            let mut rlex = Walk::new(bitmap, format!("entry {i} rlex"));
            let palette_count = rlex.u8();
            rlex.bytes(usize::from(palette_count) * 3);
            // numBits = floor(log2(paletteCount - 1)) + 1, and 1 for a one-entry palette.
            let stop_bits = (u8::BITS - palette_count.saturating_sub(1).leading_zeros()).max(1);
            let stop_mask = ((1u16 << stop_bits) - 1) as u8;
            let mut emitted = 0u64;
            while rlex.remaining() > 0 {
                let packed = rlex.u8();
                let stop_index = packed & stop_mask;
                let suite_depth = packed.checked_shr(stop_bits).unwrap_or(0);
                emitted += rlex.run_length() + u64::from(stop_index)
                    - u64::from(stop_index.saturating_sub(suite_depth))
                    + 1;
            }
            census.rlex_regions += 1;
            if palette_count == 1 {
                census.rlex_single_palette += 1;
            }
            if emitted != u64::from(width) * u64::from(height) {
                census.rlex_inexact += 1;
            }
        }
    }

    caches.swap_rejected.push(swap_rejected);
    for event in events {
        match event {
            VBarEvent::Store => {
                caches.vbar_owner[caches.vbar_cursor] = Some(i);
                caches.vbar_cursor = (caches.vbar_cursor + 1) % VBAR_SLOTS;
            }
            VBarEvent::Hit(slot) => {
                if let Some(owner) = caches.vbar_owner[slot]
                    && owner != i
                    && caches.swap_rejected[owner]
                {
                    census.vbar_hits_on_swap_rejected += 1;
                }
            }
        }
    }
}

fn census(entries: &[Entry]) -> Census {
    let mut census = Census::default();
    let mut caches = Caches::new();
    for (i, e) in entries.iter().enumerate() {
        walk_stream(i, e, &mut caches, &mut census);
    }
    census
}

/// ADR-0007's coverage rule for this corpus: it still holds the shapes #56 fixed. A short V-bar
/// cache miss that the swapped field layout rejects; a full V-bar cache hit on a column only a
/// stream the swap rejects stored; and single-palette RLEX regions. Every RLEX region and every
/// residual layer fills its rectangle exactly.
#[test]
fn corpus_holds_every_shape_the_decoder_was_fixed_for() {
    let census = census(&load_replay());
    assert!(
        census.short_vbar_miss_high > 0,
        "no SHORT_VBAR_CACHE_MISS with header bits [15:6] > 63: {census:?}"
    );
    assert!(census.vbar_hits >= census.vbar_hits_on_swap_rejected);
    assert!(
        census.vbar_hits_on_swap_rejected > 0,
        "no full V-bar cache hit on a column a swap-rejected stream stored: {census:?}"
    );
    assert!(
        census.rlex_single_palette > 0,
        "no single-palette RLEX region: {census:?}"
    );
    assert_eq!(
        census.rlex_inexact, 0,
        "an RLEX region does not fill its rectangle exactly: {census:?}"
    );
    assert!(census.residual_layers > 0, "no residual layer: {census:?}");
    assert_eq!(
        (census.residual_under, census.residual_over),
        (0, 0),
        "a residual layer does not fill its tile exactly: {census:?}"
    );
}

/// The typed-text capture replays through one decoder without error, byte-identical to the
/// oracle.
#[test]
fn text_capture_replays_and_matches_the_oracle() {
    let entries = load_text_replay();
    let mut mine = ClearDecoder::new();
    let mut oracle = ironrdp_graphics::clearcodec::ClearCodecDecoder::new();
    for (i, e) in entries.iter().enumerate() {
        let ours = mine
            .decode(&e.data, e.width, e.height)
            .unwrap_or_else(|err| panic!("entry {i}: self-owned decoder rejected it: {err}"));
        let theirs = oracle
            .decode(&e.data, e.width, e.height)
            .unwrap_or_else(|err| panic!("entry {i}: oracle rejected it: {err}"));
        assert_eq!(ours, theirs, "entry {i} ({}x{}) differs", e.width, e.height);
    }
}

/// The typed-text capture holds glyph hits, each drawn into the rectangle its slot was stored
/// with, and each a copy of the pixels its slot's store decoded to (`[MS-RDPEGFX]` 4.1.1.5). Its
/// RLEX regions and residual layers fill their rectangles exactly too.
#[test]
fn text_capture_draws_each_glyph_hit_from_its_store() {
    let entries = load_text_replay();
    let census = census(&entries);
    assert!(census.glyph_hits > 0, "no glyph hit: {census:?}");
    assert_eq!(census.glyph_hits_reshaped, 0, "{census:?}");
    assert_eq!(census.rlex_inexact, 0, "{census:?}");
    assert!(census.residual_layers > 0, "{census:?}");
    assert_eq!(
        (census.residual_under, census.residual_over),
        (0, 0),
        "{census:?}"
    );

    let mut decoder = ClearDecoder::new();
    let mut stored: std::collections::HashMap<u16, Vec<u8>> = std::collections::HashMap::new();
    let mut hits = 0usize;
    for (i, e) in entries.iter().enumerate() {
        let out = decoder
            .decode(&e.data, e.width, e.height)
            .unwrap_or_else(|err| panic!("entry {i}: {err}"));
        assert_eq!(
            out.len(),
            usize::from(e.width) * usize::from(e.height) * 4,
            "entry {i} decoded to the wrong BGRA size"
        );
        let flags = e.data[0];
        if flags & 0x01 == 0 {
            continue;
        }
        let index = u16::from_le_bytes([e.data[2], e.data[3]]);
        if flags & 0x02 != 0 {
            hits += 1;
            assert!(
                Some(&out) == stored.get(&index),
                "entry {i}: glyph hit on slot {index} is not its store's pixels"
            );
        } else if usize::from(e.width) * usize::from(e.height) <= 1024 {
            stored.insert(index, out);
        }
    }
    assert_eq!(hits, census.glyph_hits);
}
