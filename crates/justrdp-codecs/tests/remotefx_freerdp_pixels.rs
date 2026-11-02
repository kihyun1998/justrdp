//! The real-server RemoteFX corpus decoded against FreeRDP's pixels (#560): the values half of
//! RemoteFX's owned basis, beside `real_server_corpus.rs`'s acceptance half.
//!
//! `fixtures/remotefx/ws2019-thin-client.freerdp-tiles.bin` holds, per corpus record, an FNV-1a
//! 64 digest of every 64×64 tile of the RGBA FreeRDP's decoder produced for it. The fixture
//! README says how it was made.

use justrdp_codecs::rfx::RemoteFx;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/remotefx")
        .join(name);
    std::fs::read(path).expect("the fixture is committed")
}

/// The corpus records, `(width, height, payload)`, in arrival order.
fn corpus() -> Vec<(u16, u16, Vec<u8>)> {
    let buf = fixture("ws2019-thin-client.bin");
    let u16_at = |at: usize| u16::from_le_bytes(buf[at..at + 2].try_into().unwrap());
    let u32_at = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
    let mut at = 4;
    let mut records = Vec::new();
    for _ in 0..u32_at(0) {
        let len = u32_at(at + 6);
        records.push((
            u16_at(at),
            u16_at(at + 2),
            buf[at + 10..at + 10 + len].to_vec(),
        ));
        at += 10 + len;
    }
    assert_eq!(at, buf.len(), "bytes after the last corpus record");
    records
}

/// The digest of each 64×64 tile of a `width × height` RGBA image, row-major over tiles, each
/// tile's rows clipped to the image.
fn tile_digests(rgba: &[u8], width: usize, height: usize) -> Vec<u64> {
    let mut digests = Vec::new();
    for ty in (0..height).step_by(64) {
        for tx in (0..width).step_by(64) {
            let mut digest = FNV_OFFSET;
            for y in ty..(ty + 64).min(height) {
                let row = (y * width + tx) * 4;
                for &byte in &rgba[row..row + ((tx + 64).min(width) - tx) * 4] {
                    digest = (digest ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
                }
            }
            digests.push(digest);
        }
    }
    digests
}

#[test]
fn every_tile_of_the_remotefx_corpus_decodes_to_freerdps_pixels() {
    let records = corpus();
    let expected = fixture("ws2019-thin-client.freerdp-tiles.bin");
    let u16_at = |at: usize| u16::from_le_bytes(expected[at..at + 2].try_into().unwrap());
    assert_eq!(
        u32::from_le_bytes(expected[..4].try_into().unwrap()) as usize,
        records.len(),
        "one digest record per corpus record"
    );

    let mut remotefx = RemoteFx::new();
    let mut at = 4;
    let mut tiles = 0;
    let mut differing = Vec::new();
    for (i, (width, height, payload)) in records.iter().enumerate() {
        assert_eq!(
            (u16_at(at), u16_at(at + 2)),
            (*width, *height),
            "record {i}: the digests were made for another rectangle"
        );
        at += 4;
        let rgba = remotefx
            .decode_to_rgba(payload, *width, *height)
            .unwrap_or_else(|e| panic!("record {i}: {e}"))
            .unwrap_or_else(|| panic!("record {i}: no tileset"));
        let (w, h) = (usize::from(*width), usize::from(*height));
        for (t, digest) in tile_digests(&rgba, w, h).into_iter().enumerate() {
            let want = u64::from_le_bytes(expected[at..at + 8].try_into().unwrap());
            if digest != want {
                differing.push((i, t % w.div_ceil(64) * 64, t / w.div_ceil(64) * 64));
            }
            at += 8;
            tiles += 1;
        }
    }
    assert_eq!(at, expected.len(), "bytes after the last digest record");
    assert_eq!(tiles, 3720);
    assert!(
        differing.is_empty(),
        "{} of {tiles} tiles differ from FreeRDP's, as (record, tile x, tile y): {differing:?}",
        differing.len()
    );
}
