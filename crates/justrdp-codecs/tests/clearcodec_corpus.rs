//! Regression anchor over the real-VM ClearCodec corpus (issue #56).
//!
//! The `*.bin` fixtures are genuine `CODECID_CLEARCODEC` payloads captured from the test VM
//! (see `tests/fixtures/clearcodec/README.md`). This test pins the **current bootstrap**
//! (`ironrdp-graphics`) behaviour: the `ok`-tagged streams decode, and the three `err`-tagged
//! signatures are rejected — the very streams a real server emits and mstsc renders, that the
//! oracle wrongly refuses.
//!
//! The decode outcome (ok vs err) is self-contained per payload — verified empirically that
//! replaying the full capture through one stateful decoder yields the same classification as
//! decoding each payload in isolation — so loading fixtures individually is faithful here.
//!
//! When the phase-2 self-owned decoder lands (#56), the `err` assertions below flip to `ok`:
//! that inversion is the signal the rewrite achieved its goal. Update this test then.

use justrdp_codecs::egfx::Clear;

struct Fixture {
    file: String,
    width: u16,
    height: u16,
    oracle: String,
}

fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/clearcodec")
}

fn load_manifest() -> Vec<Fixture> {
    let manifest = std::fs::read_to_string(fixtures_dir().join("manifest.tsv"))
        .expect("the ClearCodec corpus manifest must be present");
    manifest
        .lines()
        .skip(1) // header
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            Fixture {
                file: f[0].to_string(),
                width: f[1].parse().expect("width"),
                height: f[2].parse().expect("height"),
                oracle: f[4].to_string(),
            }
        })
        .collect()
}

fn payload(file: &str) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(file)).expect("fixture payload must be present")
}

#[test]
fn corpus_manifest_is_non_empty_and_covers_every_signature() {
    let fixtures = load_manifest();
    assert!(!fixtures.is_empty(), "corpus manifest is empty");
    for tag in [
        "ok",
        "rlex_suite_exceeds_region",
        "short_vbar_cache_miss",
        "vbar_cache_miss_on_hit",
    ] {
        assert!(
            fixtures.iter().any(|f| f.oracle == tag),
            "corpus is missing a `{tag}` fixture"
        );
    }
}

#[test]
fn ok_tagged_streams_decode_to_full_bgra() {
    for f in load_manifest().into_iter().filter(|f| f.oracle == "ok") {
        let mut clear = Clear::new();
        let out = clear
            .decode_to_bgra(&payload(&f.file), f.width, f.height)
            .unwrap_or_else(|e| panic!("`{}` (oracle=ok) should decode, got {e}", f.file));
        assert_eq!(
            out.len(),
            usize::from(f.width) * usize::from(f.height) * 4,
            "`{}` decoded to the wrong BGRA size",
            f.file
        );
    }
}

/// The current bootstrap oracle rejects these genuine streams — this is the #56 defect, pinned.
/// The phase-2 self-owned decoder must make them decode; when it does, move each tag into
/// [`ok_tagged_streams_decode_to_full_bgra`] and delete it here.
#[test]
fn oracle_rejected_signatures_still_fail_under_the_bootstrap() {
    for f in load_manifest().into_iter().filter(|f| f.oracle != "ok") {
        let mut clear = Clear::new();
        let result = clear.decode_to_bgra(&payload(&f.file), f.width, f.height);
        assert!(
            result.is_err(),
            "`{}` (oracle={}) unexpectedly decoded — if #56's decoder now handles it, \
             reclassify this fixture as `ok`",
            f.file,
            f.oracle
        );
    }
}
