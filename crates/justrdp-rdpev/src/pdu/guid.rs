//! 16-byte GUID helper for MS-RDPEV PDUs.
//!
//! The TSMF wire format embeds GUIDs as raw 16-byte blobs in MS-DTYP
//! §2.3.4.2 mixed-endian order: the first three fields are
//! little-endian (4+2+2 bytes) and the trailing 8 bytes are stored as
//! a raw byte array. Because we never need to parse or interpret the
//! individual fields at this layer -- the only thing TSMF does with a
//! `PresentationId` is use it as an opaque key into a hash map -- we
//! store the GUID as `[u8; 16]` exactly as it appears on the wire and
//! provide thin read/write helpers to keep the call sites tidy.
//!
//! Higher layers (and tests) that want a canonical string display can
//! use [`Guid::to_canonical_string`] / [`Guid::from_canonical_string`]
//! which apply the MS-DTYP byte ordering.

use justrdp_core::{DecodeResult, EncodeResult, ReadCursor, WriteCursor};

/// Wire size of a `GUID` (always 16 bytes).
pub const GUID_SIZE: usize = 16;

/// Opaque 16-byte identifier used by every TSMF PDU that carries a
/// `PresentationId`. We store the raw on-wire bytes; the dispatch
/// layer uses them as a hash map key without ever parsing the fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid(pub [u8; GUID_SIZE]);

impl Guid {
    pub const fn new(bytes: [u8; GUID_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; GUID_SIZE] {
        &self.0
    }

    /// All-zero GUID -- used by `SetChannelParams` when the server has
    /// not yet announced a presentation on this channel.
    pub const NIL: Self = Self([0u8; GUID_SIZE]);
}

/// Reads 16 raw bytes from `src` into a `Guid`.
pub fn decode_guid(src: &mut ReadCursor<'_>, ctx: &'static str) -> DecodeResult<Guid> {
    let bytes = src.read_slice(GUID_SIZE, ctx)?;
    let mut out = [0u8; GUID_SIZE];
    out.copy_from_slice(bytes);
    Ok(Guid(out))
}

/// Writes 16 raw GUID bytes to `dst`.
pub fn encode_guid(dst: &mut WriteCursor<'_>, guid: &Guid, ctx: &'static str) -> EncodeResult<()> {
    dst.write_slice(&guid.0, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn roundtrip_known_bytes() {
        // Bytes from spec §4 §11.4 ON_NEW_PRESENTATION example:
        //   {e086049f-d926-45ae-8c0f-3e056af3f7d4}
        let g = Guid([
            0x9f, 0x04, 0x86, 0xe0, 0x26, 0xd9, 0xae, 0x45, 0x8c, 0x0f, 0x3e, 0x05, 0x6a, 0xf3,
            0xf7, 0xd4,
        ]);
        let mut buf: Vec<u8> = vec![0u8; GUID_SIZE];
        let mut w = WriteCursor::new(&mut buf);
        encode_guid(&mut w, &g, "test").unwrap();
        assert_eq!(w.pos(), GUID_SIZE);
        let mut r = ReadCursor::new(&buf);
        let back = decode_guid(&mut r, "test").unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn nil_constant_is_all_zero() {
        assert_eq!(Guid::NIL.0, [0u8; GUID_SIZE]);
    }
}
