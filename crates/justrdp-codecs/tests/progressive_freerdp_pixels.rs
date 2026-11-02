//! The real-server Progressive corpus decoded against FreeRDP's pixels (#566): the values half
//! of Progressive's owned basis, beside `progressive_assembly_corpus.rs`'s pinned surface.
//!
//! `fixtures/progressive/replay.freerdp-tiles.bin` holds, after each of the corpus's payloads,
//! an FNV-1a 64 digest of the R, G and B bytes of every 64×64 tile of the surface FreeRDP's
//! decoder had painted by then. Alpha is left out: FreeRDP writes 0 there and this decoder 255.
//! The fixture README says how it was made.

use justrdp_codecs::rfx::progressive::Progressive;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/progressive")
        .join(name);
    std::fs::read(path).expect("the fixture is committed")
}

/// The corpus payloads, `(width, height, payload)`, in arrival order.
fn corpus() -> Vec<(u16, u16, Vec<u8>)> {
    let buf = fixture("replay.bin");
    let u16_at = |at: usize| u16::from_le_bytes(buf[at..at + 2].try_into().unwrap());
    let u32_at = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
    let mut at = 4;
    let mut payloads = Vec::new();
    for _ in 0..u32_at(0) {
        let len = u32_at(at + 8);
        payloads.push((
            u16_at(at + 4),
            u16_at(at + 6),
            buf[at + 12..at + 12 + len].to_vec(),
        ));
        at += 12 + len;
    }
    assert_eq!(at, buf.len(), "bytes after the last corpus payload");
    payloads
}

/// The digest of the R, G and B bytes of each 64×64 tile of a `width × height` RGBA image,
/// row-major over tiles, each tile's rows clipped to the image.
fn tile_digests(rgba: &[u8], width: usize, height: usize) -> Vec<u64> {
    let mut digests = Vec::new();
    for ty in (0..height).step_by(64) {
        for tx in (0..width).step_by(64) {
            let mut digest = FNV_OFFSET;
            for y in ty..(ty + 64).min(height) {
                let row = (y * width + tx) * 4;
                for pixel in rgba[row..row + ((tx + 64).min(width) - tx) * 4]
                    .as_chunks::<4>()
                    .0
                {
                    for &byte in &pixel[..3] {
                        digest = (digest ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
                    }
                }
            }
            digests.push(digest);
        }
    }
    digests
}

#[test]
fn every_tile_of_the_progressive_surface_matches_freerdps_after_every_payload() {
    let payloads = corpus();
    let expected = fixture("replay.freerdp-tiles.bin");
    let u16_at = |at: usize| u16::from_le_bytes(expected[at..at + 2].try_into().unwrap());
    assert_eq!(
        u32::from_le_bytes(expected[..4].try_into().unwrap()) as usize,
        payloads.len(),
        "one digest record per corpus payload"
    );

    let (width, height) = (payloads[0].0, payloads[0].1);
    let (w, h) = (usize::from(width), usize::from(height));
    let mut surface = vec![0u8; w * h * 4];
    let mut decoder = Progressive::new();
    let mut at = 4;
    let mut tiles = 0;
    let mut differing = Vec::new();
    for (i, (pw, ph, payload)) in payloads.iter().enumerate() {
        assert_eq!((*pw, *ph), (width, height), "payload {i}: one surface");
        assert_eq!(
            (u16_at(at), u16_at(at + 2)),
            (width, height),
            "payload {i}: the digests were made for another surface"
        );
        at += 4;
        decoder
            .decode(0, width, height, payload, |rect| {
                let (x, y) = (usize::from(rect.x), usize::from(rect.y));
                let (sx, sy) = (usize::from(rect.src_x), usize::from(rect.src_y));
                let len = usize::from(rect.width) * 4;
                for row in 0..usize::from(rect.height) {
                    let src = ((sy + row) * 64 + sx) * 4;
                    let dst = ((y + row) * w + x) * 4;
                    surface[dst..dst + len].copy_from_slice(&rect.tile[src..src + len]);
                }
            })
            .unwrap_or_else(|e| panic!("payload {i}: {e}"));
        for (t, digest) in tile_digests(&surface, w, h).into_iter().enumerate() {
            let want = u64::from_le_bytes(expected[at..at + 8].try_into().unwrap());
            if digest != want {
                differing.push((i, t % w.div_ceil(64) * 64, t / w.div_ceil(64) * 64));
            }
            at += 8;
            tiles += 1;
        }
    }
    assert_eq!(at, expected.len(), "bytes after the last digest record");
    assert_eq!(tiles, 52 * 260);
    assert!(
        differing.is_empty(),
        "{} of {tiles} tiles differ from FreeRDP's, as (payload, tile x, tile y): first {:?}",
        differing.len(),
        &differing[..differing.len().min(40)]
    );
}
