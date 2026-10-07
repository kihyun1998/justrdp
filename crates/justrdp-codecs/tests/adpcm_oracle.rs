//! ADPCM decoded against FreeRDP's decoders (#389): every fixture in `fixtures/adpcm/` is a run of
//! encoded blocks and the samples FreeRDP decodes them to. See that directory's README for how
//! they were made and what was adjusted.

use justrdp_codecs::adpcm::{ImaAdpcm, MsAdpcm};

/// The standard MS-ADPCM `cbSize` extra: samples per block, then the seven coefficient pairs.
fn ms_extra(samples_per_block: u16) -> Vec<u8> {
    let mut extra = samples_per_block.to_le_bytes().to_vec();
    extra.extend_from_slice(&7u16.to_le_bytes());
    for (c1, c2) in [
        (256i16, 0i16),
        (512, -256),
        (0, 0),
        (192, 64),
        (240, 0),
        (460, -208),
        (392, -232),
    ] {
        extra.extend_from_slice(&c1.to_le_bytes());
        extra.extend_from_slice(&c2.to_le_bytes());
    }
    extra
}

fn fixture(name: &str) -> (Vec<u8>, Vec<i16>) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/adpcm");
    let encoded = std::fs::read(dir.join(format!("{name}.adpcm"))).expect("fixture");
    let expected = std::fs::read(dir.join(format!("{name}.s16"))).expect("fixture");
    let expected = expected
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&s| i16::from_le_bytes(s))
        .collect();
    (encoded, expected)
}

#[test]
fn ms_adpcm_matches_freerdp_on_generated_blocks() {
    for (name, channels) in [("ms_mono_generated", 1u16), ("ms_stereo_generated", 2)] {
        let block_align = 256 * channels;
        let samples_per_block = (block_align - 7 * channels) * 2 / channels + 2;
        let decoder = MsAdpcm::new(channels, block_align, &ms_extra(samples_per_block))
            .expect("a valid MS-ADPCM format");
        let (encoded, expected) = fixture(name);
        assert_eq!(decoder.decode(&encoded), Ok(expected), "{name}");
    }
}

#[test]
fn ima_adpcm_matches_freerdp_and_audioop_on_generated_blocks() {
    for (name, channels) in [("ima_mono_generated", 1u16), ("ima_stereo_generated", 2)] {
        let block_align = 256 * channels;
        let samples_per_block = (block_align - 4 * channels) * 2 / channels + 1;
        let decoder = ImaAdpcm::new(channels, block_align, &samples_per_block.to_le_bytes())
            .expect("a valid IMA-ADPCM format");
        let (encoded, expected) = fixture(name);
        assert_eq!(decoder.decode(&encoded), Ok(expected), "{name}");
    }
}

/// Real WS2022 blocks (#389): the first three loud Wave2 samples of a stock sound, four blocks
/// each, in the 44.1 kHz mono format the server chose, decoded with the `cbSize` extra it sent.
#[test]
fn real_server_adpcm_blocks_match_the_oracle() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/adpcm");
    let ms_extra = std::fs::read(dir.join("ms_mono_vm.extra")).expect("fixture");
    let ima_extra = std::fs::read(dir.join("ima_mono_vm.extra")).expect("fixture");
    let ms = MsAdpcm::new(1, 1024, &ms_extra).expect("the server's MS-ADPCM format");
    let ima = ImaAdpcm::new(1, 1024, &ima_extra).expect("the server's IMA-ADPCM format");
    for n in 0..3 {
        let (encoded, expected) = fixture(&format!("ms_mono_vm_{n}"));
        assert_eq!(ms.decode(&encoded), Ok(expected), "ms_mono_vm_{n}");
        let (encoded, expected) = fixture(&format!("ima_mono_vm_{n}"));
        assert_eq!(ima.decode(&encoded), Ok(expected), "ima_mono_vm_{n}");
    }
}
