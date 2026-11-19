#![no_main]
//! Fuzz one ClearCodec decoder across a sequence of streams (#587). Sibling of `clearcodec`,
//! which decodes once with a fresh decoder, so its V-bar and glyph caches are always empty and
//! every cache hit it draws is a miss.
//!
//! What makes this target able to fail:
//!
//! - **One decoder for the whole sequence.** A glyph hit after a glyph store, and a V-bar cache
//!   hit after the bands that stored the column, reach the paths that read the caches: the
//!   glyph-hit area check and the refusal of a stored column whose height is not the band's.
//! - **The output length is asserted.** A wrong glyph-hit area check returns `Ok` with the
//!   cached glyph's length rather than panicking, so every `Ok` must hold `width * height * 4`
//!   bytes.
//! - **Correlated indices.** Glyph indices are drawn from a pool of eight, so a store and a
//!   later hit on the same slot are common rather than one in four thousand.
//! - **Well-formed envelopes.** A composite frame's three layer byte counts are computed from
//!   the layers, so the bytes reach the layer walks instead of the length check.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

const GLYPH_INDEX: u8 = 0x01;
const GLYPH_HIT: u8 = 0x02;
const CACHE_RESET: u8 = 0x04;

#[derive(Arbitrary, Debug)]
enum Frame {
    /// A composite payload, stored in a glyph slot when `glyph` is set.
    Composite {
        glyph: Option<u8>,
        cache_reset: bool,
        width: u8,
        height: u8,
        residual: Vec<u8>,
        bands: Vec<u8>,
        subcodec: Vec<u8>,
    },
    /// A glyph hit on a slot of the pool, drawn into any rectangle.
    GlyphHit { glyph: u8, width: u8, height: u8 },
    /// Arbitrary bytes.
    Raw {
        width: u8,
        height: u8,
        data: Vec<u8>,
    },
}

#[derive(Arbitrary, Debug)]
struct Input {
    frames: Vec<Frame>,
}

fn layer_len(layer: &[u8]) -> [u8; 4] {
    u32::try_from(layer.len()).unwrap_or(u32::MAX).to_le_bytes()
}

fuzz_target!(|input: Input| {
    let mut decoder = justrdp_codecs::clearcodec::ClearDecoder::new();
    for (seq, frame) in input.frames.iter().enumerate() {
        let seq = seq as u8;
        let (stream, width, height) = match frame {
            Frame::Composite {
                glyph,
                cache_reset,
                width,
                height,
                residual,
                bands,
                subcodec,
            } => {
                let mut flags = if *cache_reset { CACHE_RESET } else { 0 };
                if glyph.is_some() {
                    flags |= GLYPH_INDEX;
                }
                let mut stream = vec![flags, seq];
                if let Some(index) = glyph {
                    stream.extend_from_slice(&u16::from(index % 8).to_le_bytes());
                }
                stream.extend_from_slice(&layer_len(residual));
                stream.extend_from_slice(&layer_len(bands));
                stream.extend_from_slice(&layer_len(subcodec));
                stream.extend_from_slice(residual);
                stream.extend_from_slice(bands);
                stream.extend_from_slice(subcodec);
                (stream, *width, *height)
            }
            Frame::GlyphHit {
                glyph,
                width,
                height,
            } => {
                let mut stream = vec![GLYPH_INDEX | GLYPH_HIT, seq];
                stream.extend_from_slice(&u16::from(glyph % 8).to_le_bytes());
                (stream, *width, *height)
            }
            Frame::Raw {
                width,
                height,
                data,
            } => (data.clone(), *width, *height),
        };
        if let Ok(pixels) = decoder.decode(&stream, u16::from(width), u16::from(height)) {
            assert_eq!(pixels.len(), usize::from(width) * usize::from(height) * 4);
        }
    }
});
