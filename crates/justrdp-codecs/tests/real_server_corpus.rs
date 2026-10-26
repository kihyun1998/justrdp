//! Every real-server corpus carved for #554, replayed through its decoder in arrival order.
//!
//! A corpus proves **acceptance**: nothing in it is rejected. It does not prove the pixels or
//! samples are right; that is the second half of an owned basis, and none of these files holds
//! it (`docs/map/territory/verification-harness.md`). Each fixture directory's README names the
//! server, the advertised configuration, the date, and how the file was made.
//!
//! The format is one container for every codec: a `u32` count, then per record
//! `u16 a, u16 b, u16 c, u32 len, payload[len]`, little-endian, with `a`, `b` and `c` the
//! codec's own fields.

use justrdp_codecs::color::Palette;
use justrdp_codecs::mppc::{Mppc, MppcLevel};
use justrdp_codecs::ncrush::Ncrush;
use justrdp_codecs::rfx::RemoteFx;
use justrdp_codecs::xcrush::Xcrush;
use justrdp_codecs::zgfx::Zgfx;
use justrdp_codecs::{g711, nscodec, pcm, planar, pointer, rle};

/// One record of a corpus file.
struct Record {
    a: u16,
    b: u16,
    c: u16,
    payload: Vec<u8>,
}

fn load(path: &str) -> Vec<Record> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path);
    let buf = std::fs::read(&path).expect("the corpus is committed");
    let u16_at = |at: usize| u16::from_le_bytes(buf[at..at + 2].try_into().unwrap());
    let u32_at = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
    let count = u32_at(0);
    let mut at = 4;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u32_at(at + 6);
        records.push(Record {
            a: u16_at(at),
            b: u16_at(at + 2),
            c: u16_at(at + 4),
            payload: buf[at + 10..at + 10 + len].to_vec(),
        });
        at += 10 + len;
    }
    assert_eq!(
        at,
        buf.len(),
        "{}: bytes after the last record",
        path.display()
    );
    records
}

#[test]
fn nscodec_decodes_every_surface_bits_stream_ws2019_sent() {
    let records = load("nscodec/ws2019-surface-bits.bin");
    assert_eq!(records.len(), 1432);
    for (i, r) in records.iter().enumerate() {
        let bgra = nscodec::decode(&r.payload, r.a, r.b)
            .unwrap_or_else(|e| panic!("record {i} ({}x{}): {e}", r.a, r.b));
        assert_eq!(
            bgra.len(),
            usize::from(r.a) * usize::from(r.b) * 4,
            "record {i}"
        );
    }
}

#[test]
fn planar_decodes_every_32_bpp_bitmap_ws2019_sent() {
    let records = load("planar/ws2019-32bpp.bin");
    assert_eq!(records.len(), 1016);
    for (i, r) in records.iter().enumerate() {
        let (w, h) = (usize::from(r.a), usize::from(r.b));
        let bgr = planar::decompress(&r.payload, w, h)
            .unwrap_or_else(|e| panic!("record {i} ({w}x{h}): {e}"));
        assert_eq!(bgr.len(), w * h * 3, "record {i}");
    }
}

#[test]
fn rle_decodes_every_bitmap_and_cache_fill_the_servers_sent() {
    for (corpus, count, bpp) in [
        ("rle/ws2019-memblt-16bpp.bin", 188, 16),
        ("rle/ws2008r2-8bpp.bin", 97, 8),
        ("rle/ws2008r2-15bpp.bin", 556, 15),
    ] {
        let records = load(corpus);
        assert_eq!(records.len(), count, "{corpus}");
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.c, bpp, "{corpus} record {i}");
            let (w, h) = (usize::from(r.a), usize::from(r.b));
            let raw = rle::decompress(&r.payload, w, h, r.c)
                .unwrap_or_else(|e| panic!("{corpus} record {i} ({w}x{h}): {e}"));
            assert_eq!(
                raw.len(),
                w * h * usize::from(bpp.div_ceil(8)),
                "{corpus} record {i}"
            );
        }
    }
}

#[test]
fn mppc_64k_decompresses_every_section_ws2019_sent_in_order() {
    let records = load("mppc/ws2019-64k.bin");
    assert_eq!(records.len(), 38);
    let mut mppc = Mppc::new(MppcLevel::Rdp5);
    for (i, r) in records.iter().enumerate() {
        mppc.decompress(&r.payload, r.a as u8)
            .unwrap_or_else(|e| panic!("record {i} (flags {:#04x}): {e}", r.a));
    }
}

#[test]
fn ncrush_decompresses_every_section_ws2019_sent_in_order() {
    let records = load("ncrush/ws2019.bin");
    assert_eq!(records.len(), 33);
    let mut ncrush = Box::<Ncrush>::default();
    for (i, r) in records.iter().enumerate() {
        ncrush
            .decompress(&r.payload, r.a as u8)
            .unwrap_or_else(|e| panic!("record {i} (flags {:#04x}): {e}", r.a));
    }
}

#[test]
fn xcrush_decompresses_every_section_ws2019_sent_in_order() {
    let records = load("xcrush/ws2019.bin");
    assert_eq!(records.len(), 34);
    let mut xcrush = Box::<Xcrush>::default();
    for (i, r) in records.iter().enumerate() {
        xcrush
            .decompress(&r.payload, r.a as u8)
            .unwrap_or_else(|e| panic!("record {i} (flags {:#04x}): {e}", r.a));
    }
}

#[test]
fn pointer_decodes_every_shape_the_servers_sent() {
    for (corpus, count) in [("pointer/ws2019.bin", 2), ("pointer/ws2008r2.bin", 9)] {
        let records = load(corpus);
        assert_eq!(records.len(), count, "{corpus}");
        for (i, r) in records.iter().enumerate() {
            let xor_len = u32::from_le_bytes(r.payload[..4].try_into().unwrap()) as usize;
            let (xor, and) = r.payload[4..].split_at(xor_len);
            let rgba = pointer::decode_pointer(r.a, r.b, r.c, xor, and, &Palette::default())
                .unwrap_or_else(|e| {
                    panic!("{corpus} record {i} ({}x{} at {}): {e}", r.a, r.b, r.c)
                });
            assert_eq!(
                rgba.len(),
                usize::from(r.a) * usize::from(r.b) * 4,
                "{corpus} record {i}"
            );
        }
    }
}

#[test]
fn zgfx_decompresses_every_graphics_message_ws2019_sent_in_order() {
    let records = load("zgfx/ws2019.bin");
    assert_eq!(records.len(), 65);
    let mut zgfx = Zgfx::new();
    for (i, r) in records.iter().enumerate() {
        zgfx.decompress(&r.payload)
            .unwrap_or_else(|e| panic!("record {i}: {e}"));
    }
}

#[test]
fn remotefx_decodes_every_wire_to_surface_1_payload_ws2019_sent_in_order() {
    let records = load("remotefx/ws2019-thin-client.bin");
    assert_eq!(records.len(), 41);
    let mut remotefx = RemoteFx::new();
    let mut painted = 0;
    for (i, r) in records.iter().enumerate() {
        let rgba = remotefx
            .decode_to_rgba(&r.payload, r.a, r.b)
            .unwrap_or_else(|e| panic!("record {i} ({}x{}): {e}", r.a, r.b));
        if let Some(rgba) = rgba {
            assert_eq!(
                rgba.len(),
                usize::from(r.a) * usize::from(r.b) * 4,
                "record {i}"
            );
            painted += 1;
        }
    }
    assert!(painted > 0, "no record carried a tileset");
}

#[test]
fn pcm_decodes_every_wave_block_ws2019_sent() {
    let records = load("pcm/ws2019-16bit-stereo.bin");
    assert_eq!(records.len(), 3);
    for (i, r) in records.iter().enumerate() {
        let samples = pcm::decode(r.a, &r.payload).unwrap_or_else(|e| panic!("record {i}: {e}"));
        assert_eq!(samples.len(), r.payload.len() / 2, "record {i}");
    }
}

#[test]
fn alaw_decodes_every_wave_block_ws2019_sent() {
    let records = load("g711/ws2019-alaw-stereo.bin");
    assert_eq!(records.len(), 3);
    for r in &records {
        assert_eq!(g711::decode_alaw(&r.payload).len(), r.payload.len());
    }
}
