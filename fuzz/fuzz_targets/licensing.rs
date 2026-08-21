#![no_main]
//! Fuzz the licensing walk as `justrdp` drives it (issue #230) — the basic security header, the
//! preamble, and the four body parsers the preamble's `bMsgType` dispatches to. Sibling of the
//! five `*_never_panics_on_arbitrary_input` proptests in `justrdp_pdu::license` and the one in
//! `justrdp_pdu::client_info`.
//!
//! ## Why this exists beside `license.rs`, which is not the same target
//!
//! `fuzz_targets/license.rs` drives `ServerLicenseRequest::decode` — the deepest parse, and the
//! reason it was the one worth a target first. It calls none of the others. So `license` appeared
//! in `ls fuzz_targets/` and the module appeared in the walk of what parses untrusted bytes, the
//! two derivations matched **by name**, and four `pub fn`s on the live path were left driven by
//! nothing: `LicensePreamble::decode`, `LicenseError::decode`, `PlatformChallenge::decode` and
//! `NewLicense::decode`. Identical shape to the `pointer` name the invariant already records, one
//! module over — see `docs/map/invariant/untrusted-decode-never-panics.md`.
//!
//! `client_info::decode_basic_security_header` joins them here rather than taking a target of its
//! own. It is four bytes — two bounds-checked `read_u16_le`s, no length, count or offset
//! arithmetic — so it is total by inspection, and its only live caller is the licensing step this
//! target reproduces (`justrdp/src/connect.rs:854`). A lane job of its own would saturate in
//! seconds and then idle through a 300s budget, which is the same reason `mcs.rs` spends one
//! target on five parsers rather than five.
//!
//! ## The two arms
//!
//! `Sequence` walks what `license_step` walks, off one cursor: security header, preamble, then the
//! body parser `bMsgType` selects (`justrdp/src/connect.rs:854-950`). That is the composition a
//! server actually drives, and it is where a length consumed by one parser can misplace the next.
//!
//! The direct arms exist for the reason #203 gave `gcc`'s per-block decoders their own: the
//! sequence has an eight-byte prefix in front of every body parser, and each of those parsers is a
//! `pub fn` reachable with no prefix at all.
//!
//! The prefix is **not** a wall on the proptest side, which samples the way an unguided mutator
//! does: `PlatformChallenge` and `NewLicense` reach their trailing `MACData` read from undirected
//! bytes reliably enough that removing the `read_slice(MAC_SIZE)` bound turns both properties red
//! on every run. That is measured, and it is the opposite of what `pointer` measured for its mask
//! reads two modules over — the difference is that a licensing blob is one `u16` length in front
//! of the read, where a pointer mask is a `messageType` dispatch and a 96-pixel dimension cap in
//! front of it. **A prefix is not a wall by being long; it is a wall by how many of its fields
//! have to coincide.** The arms are kept anyway: they cost one selector value and they make each
//! parser reachable with no prefix at all, which is what keeps the target honest if the sequence
//! ever grows a check.
//!
//! ## Byte layout
//!
//! ```text
//! [4-byte little-endian u32 selector] ++ [payload, verbatim]
//! arm = (selector as u64 * ARM_COUNT) >> 32
//! ```
//!
//! `data` is a trailing `&[u8]` rather than a `Vec<u8>` for the reason `gcc.rs` records at length:
//! measured against `arbitrary` 1.4.2, a `Vec<u8>` field consumes two bytes per element — one from
//! the front and a keep-going byte from the back — while a trailing slice takes the remainder
//! verbatim. No seeder writes for this target (the repo commits no captured licensing message), so
//! nothing outside this file depends on the layout yet.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::license;

/// Which parser `data` is handed to. `Sequence` is the only arm a server reaches as such; the
/// rest are doors into body parsers that arm otherwise guards behind an eight-byte prefix.
#[derive(Arbitrary, Debug)]
enum Entry {
    Sequence,
    Preamble,
    Error,
    Request,
    PlatformChallenge,
    NewLicense,
}

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    entry: Entry,
    data: &'a [u8],
}

/// `justrdp::connect`'s `license_step`, minus the crypto it performs on a successful decode: the
/// security header, `SEC_LICENSE_PKT`, the preamble, and the body parser `bMsgType` selects.
fn sequence(data: &[u8]) {
    let mut cur = ReadCursor::new(data, "fuzz licensing sequence");
    let Ok(flags) = justrdp_pdu::client_info::decode_basic_security_header(&mut cur) else {
        return;
    };
    // The real caller refuses anything without this bit. Driven both ways on purpose: refusing is
    // a decode outcome, and the parsers past it must be reachable however the bit lands.
    let _ = flags & justrdp_pdu::client_info::SEC_LICENSE_PKT;
    let Ok(preamble) = license::LicensePreamble::decode(&mut cur) else {
        return;
    };
    match preamble.msg_type {
        license::MSG_ERROR_ALERT => {
            let _ = license::LicenseError::decode(&mut cur);
        }
        license::MSG_LICENSE_REQUEST => {
            let _ = license::ServerLicenseRequest::decode(&mut cur);
        }
        license::MSG_PLATFORM_CHALLENGE => {
            let _ = license::PlatformChallenge::decode(&mut cur);
        }
        license::MSG_NEW_LICENSE | license::MSG_UPGRADE_LICENSE => {
            let _ = license::NewLicense::decode(&mut cur);
        }
        _ => {}
    }
}

fuzz_target!(|input: Input<'_>| {
    let d = input.data;
    let mut cur = ReadCursor::new(d, "fuzz licensing body");
    match input.entry {
        Entry::Sequence => sequence(d),
        Entry::Preamble => {
            let _ = license::LicensePreamble::decode(&mut cur);
        }
        Entry::Error => {
            let _ = license::LicenseError::decode(&mut cur);
        }
        Entry::Request => {
            let _ = license::ServerLicenseRequest::decode(&mut cur);
        }
        Entry::PlatformChallenge => {
            let _ = license::PlatformChallenge::decode(&mut cur);
        }
        Entry::NewLicense => {
            let _ = license::NewLicense::decode(&mut cur);
        }
    }
});
