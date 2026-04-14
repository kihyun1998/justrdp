//! MS-RDPECAM wire-format PDUs.
//!
//! Submodules group messages by family; each message implements
//! `Encode`/`Decode` against `justrdp-core` cursors. The [`encode_to_vec`]
//! helper packs any `Encode` impl into a fresh `Vec<u8>`, matching the
//! pattern used by sibling DVC crates (`justrdp-rdpevor`, `justrdp-rdpegt`).

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Encode, EncodeResult, WriteCursor};

pub mod header;
pub mod enumeration;
pub mod device;
pub mod stream;
pub mod capture;
pub mod property;

/// Serialises any `Encode` PDU into a heap buffer sized exactly by
/// `pdu.size()`. Used by the DVC processors to turn a constructed PDU
/// into the payload of a [`justrdp_dvc::DvcMessage`].
///
/// A mismatch between `size()` and the number of bytes actually
/// written is a programming bug that corrupts every buffer produced
/// for this PDU kind, so the check runs in release builds too
/// (`assert_eq!`). Debug-only assertion would silently return a
/// buffer with trailing zero bytes on release, which is harder to
/// catch and far more damaging at runtime than a clean panic.
pub(crate) fn encode_to_vec<E: Encode>(pdu: &E) -> EncodeResult<Vec<u8>> {
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur)?;
    assert_eq!(
        cur.pos(),
        pdu.size(),
        "encode() wrote {} bytes but size() promised {} for {}",
        cur.pos(),
        pdu.size(),
        pdu.name()
    );
    Ok(buf)
}
