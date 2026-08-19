//! Test-only corpus capture for the codecs that need a *real server's* bytes to be verified.
//!
//! This is the harness half of ADR-0011: Progressive is gated on a real-server corpus rather
//! than on the differential oracle, so the ability to **re-capture** that corpus is part of the
//! verification story and not a debugging convenience. It lived inside the phase-1 bootstrap
//! decoder until #172 retired that decoder from the live path; leaving it there would have taken
//! the corpus refresh down with the swap, silently, since the three tests that drive it
//! (`justrdp-tokio`'s `progressive_payloads_decode_against_real_vm`,
//! `capture_progressive_corpus_against_real_vm`, `progressive_assembles_the_desktop_against_real_vm`)
//! are all `#[ignore]`d and need the VM.
//!
//! Ungated on purpose. The bootstrap module it came from is behind `egfx-bootstrap`, which now
//! covers zgfx alone — a capture harness that disappears with an unrelated codec's feature flag
//! is the same silent-drift shape one layer up.
//!
//! **What it captures is the wire payload, not a decode.** That is why it is a free function
//! taking bytes rather than a hook inside a decoder: the self-owned
//! [`crate::rfx::progressive::Progressive`] keys its store by *surface*, so it never sees the
//! `codecContextId` the fixture format records, and burying the capture inside it would have
//! forced either a parameter the decoder does not use or a silent reinterpretation of that
//! field. `justrdp-codecs/tests/fixtures/progressive/README.md` documents the format, and
//! `progressive_multipass_corpus.rs` reads the context id for real (`:155`, `:770`, `:800`).

use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// The env var that arms [`progressive_payload`]. An **empty** value counts as unset —
/// otherwise `Path::new("")` resolves to the process CWD and litters it with `prog-*.bin`.
pub const PROGRESSIVE_CAPTURE_DIR: &str = "JUSTRDP_PROGRESSIVE_CAPTURE_DIR";

/// The capture directory, or `None` when the harness is disarmed.
///
/// Exposed so a caller can skip building the `status` string on the overwhelmingly common path
/// where nothing is being captured.
pub fn progressive_capture_dir() -> Option<String> {
    match std::env::var(PROGRESSIVE_CAPTURE_DIR) {
        Ok(dir) if !dir.is_empty() => Some(dir),
        _ => None,
    }
}

/// Append one WireToSurface2 block stream (`prog-NNNN.bin`) plus a manifest row
/// (`idx⇥ctx⇥w⇥h⇥len⇥status`) to `dir`.
///
/// Sibling of ClearCodec's `JUSTRDP_CLEAR_CAPTURE_DIR` harness, and it exists for the same
/// reason: epic #158's verification needs the streams a *real* server emits. It is also how #193
/// was found — the payloads it captured were the evidence that WireToSurface2 was handing four
/// bytes of `bitmapDataLength` to the codec.
///
/// Best-effort: every IO error is swallowed, so capture can never perturb a session.
pub fn progressive_payload(
    dir: &str,
    data: &[u8],
    codec_context_id: u32,
    width: u16,
    height: u16,
    status: &str,
) {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let idx = SEQ.fetch_add(1, Ordering::Relaxed);

    let dir = std::path::Path::new(dir);
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let _ = std::fs::write(dir.join(format!("prog-{idx:04}.bin")), data);
    if let Ok(mut manifest) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("manifest.tsv"))
    {
        let _ = writeln!(
            manifest,
            "{idx}\t{codec_context_id}\t{width}\t{height}\t{}\t{status}",
            data.len()
        );
    }
}
