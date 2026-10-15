//! The server-to-client bulk decompression context (`[MS-RDPBCGR]` 3.1.8): one per connection,
//! shared by fast-path updates and slow-path Share Data PDUs, dispatched on the compression
//! type nibble.

use justrdp_codecs::mppc::{Mppc, MppcError, MppcLevel, PACKET_COMPRESSED, PACKET_FLUSHED};
use justrdp_codecs::xcrush::{Xcrush, XcrushError};

/// `PACKET_COMPR_TYPE_8K`: MPPC with an 8 KB history (RDP 4.0).
pub const PACKET_COMPR_TYPE_8K: u8 = 0;
/// `PACKET_COMPR_TYPE_64K`: MPPC with a 64 KB history (RDP 5.0).
pub const PACKET_COMPR_TYPE_64K: u8 = 1;
/// `PACKET_COMPR_TYPE_RDP61`: XCRUSH, `[MS-RDPEGDI]` 3.1.8.2 (RDP 6.1).
pub const PACKET_COMPR_TYPE_RDP61: u8 = 3;

/// The flag bits (`PACKET_COMPRESSED`, `PACKET_AT_FRONT`, `PACKET_FLUSHED`).
const FLAG_BITS: u8 = 0xE0;

/// Why a bulk-compressed payload could not be decompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkError {
    /// A compression type the core does not decompress.
    UnsupportedType(u8),
    /// The compression type differs from the one this connection's history was built for.
    TypeChanged {
        /// The type of the connection's first compressed payload.
        from: u8,
        /// The type now named.
        to: u8,
    },
    /// The MPPC decompressor refused the payload.
    Mppc(MppcError),
    /// The XCRUSH decompressor refused the payload.
    Xcrush(XcrushError),
}

impl core::fmt::Display for BulkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedType(t) => write!(f, "unsupported bulk compression type {t}"),
            Self::TypeChanged { from, to } => {
                write!(f, "bulk compression type changed from {from} to {to}")
            }
            Self::Mppc(e) => write!(f, "MPPC: {e}"),
            Self::Xcrush(e) => write!(f, "XCRUSH: {e}"),
        }
    }
}

impl core::error::Error for BulkError {}

/// The decompressor a connection's first compressed payload chose.
#[derive(Debug)]
enum Context {
    Mppc(Mppc),
    Xcrush(Box<Xcrush>),
}

impl Context {
    /// The context for a supported type.
    fn new(ty: u8) -> Self {
        match ty {
            PACKET_COMPR_TYPE_8K => Self::Mppc(Mppc::new(MppcLevel::Rdp4)),
            PACKET_COMPR_TYPE_64K => Self::Mppc(Mppc::new(MppcLevel::Rdp5)),
            _ => Self::Xcrush(Box::default()),
        }
    }

    fn ty(&self) -> u8 {
        match self {
            Self::Mppc(mppc) if mppc.level() == MppcLevel::Rdp4 => PACKET_COMPR_TYPE_8K,
            Self::Mppc(_) => PACKET_COMPR_TYPE_64K,
            Self::Xcrush(_) => PACKET_COMPR_TYPE_RDP61,
        }
    }
}

/// One connection's server-to-client decompression context.
#[derive(Debug, Default)]
pub(crate) struct Bulk {
    context: Option<Context>,
}

impl Bulk {
    /// Decompress one payload under its compression byte (type nibble plus flags). Without
    /// `PACKET_COMPRESSED` the payload is plain whatever the type says: it passes through, and
    /// `PACKET_FLUSHED` / `PACKET_AT_FRONT` reach the history if one exists.
    pub(crate) fn decompress<'a>(
        &'a mut self,
        src: &'a [u8],
        compression: u8,
    ) -> Result<&'a [u8], BulkError> {
        if compression & PACKET_COMPRESSED == 0 {
            if compression & FLAG_BITS != 0 {
                match self.context.as_mut() {
                    Some(Context::Mppc(mppc)) => {
                        mppc.decompress(src, compression).map_err(BulkError::Mppc)?;
                    }
                    Some(Context::Xcrush(xcrush)) if compression & PACKET_FLUSHED != 0 => {
                        xcrush.flush();
                    }
                    _ => {}
                }
            }
            return Ok(src);
        }
        let ty = compression & 0x0F;
        if !matches!(
            ty,
            PACKET_COMPR_TYPE_8K | PACKET_COMPR_TYPE_64K | PACKET_COMPR_TYPE_RDP61
        ) {
            return Err(BulkError::UnsupportedType(ty));
        }
        let context = match &mut self.context {
            Some(context) => context,
            empty => empty.insert(Context::new(ty)),
        };
        if context.ty() != ty {
            return Err(BulkError::TypeChanged {
                from: context.ty(),
                to: ty,
            });
        }
        match context {
            Context::Mppc(mppc) => mppc.decompress(src, compression).map_err(BulkError::Mppc),
            Context::Xcrush(xcrush) => xcrush
                .decompress(src, compression)
                .map_err(BulkError::Xcrush),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_codecs::mppc::{PACKET_AT_FRONT, PACKET_COMPRESSED};

    /// `"hi"` as two RDP 4/5 literals.
    const HI: [u8; 2] = *b"hi";

    #[test]
    fn a_byte_without_flags_passes_the_payload_through() {
        let mut bulk = Bulk::default();
        assert_eq!(bulk.decompress(b"plain", 0x00), Ok(&b"plain"[..]));
        assert_eq!(bulk.decompress(b"plain", 0x03), Ok(&b"plain"[..]));
        // Flags without PACKET_COMPRESSED, even under a type the core does not decompress.
        assert_eq!(bulk.decompress(b"plain", 0xCF), Ok(&b"plain"[..]));
    }

    #[test]
    fn an_uncompressed_flush_reaches_the_history() {
        use justrdp_codecs::mppc::PACKET_FLUSHED;
        let mut bulk = Bulk::default();
        bulk.decompress(&HI, PACKET_COMPR_TYPE_64K | PACKET_COMPRESSED)
            .unwrap();
        // Offset 2 back, length 3: "hi" then the byte after it, before and after a flush.
        let back_two = [0b1111_1000, 0b0100_0000];
        assert_eq!(
            bulk.decompress(&back_two, PACKET_COMPR_TYPE_64K | PACKET_COMPRESSED),
            Ok(&b"hih"[..])
        );
        assert_eq!(bulk.decompress(b"raw", PACKET_FLUSHED), Ok(&b"raw"[..]));
        // Offset 3, length 3 from 0 reads the zeroed tail; unflushed it would read "hih".
        let back_three = [0b1111_1000, 0b0110_0000];
        assert_eq!(
            bulk.decompress(&back_three, PACKET_COMPR_TYPE_64K | PACKET_COMPRESSED),
            Ok(&[0, 0, 0][..])
        );
    }

    #[test]
    fn mppc_types_decompress_and_others_are_refused() {
        for ty in [PACKET_COMPR_TYPE_8K, PACKET_COMPR_TYPE_64K] {
            let mut bulk = Bulk::default();
            assert_eq!(
                bulk.decompress(&HI, ty | PACKET_COMPRESSED | PACKET_AT_FRONT),
                Ok(&b"hi"[..])
            );
        }
        for ty in [2, 4, 15] {
            assert_eq!(
                Bulk::default().decompress(&HI, ty | PACKET_COMPRESSED),
                Err(BulkError::UnsupportedType(ty))
            );
        }
    }

    /// `[MS-RDPEGDI]` 4.7's first packet: level-1 literals "abcdefghij".
    const XCRUSH_FIRST: [u8; 12] = [
        0x16, 0x80, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    ];
    const RDP61: u8 = 3;

    #[test]
    fn xcrush_type_decompresses() {
        let mut bulk = Bulk::default();
        assert_eq!(
            bulk.decompress(&XCRUSH_FIRST, RDP61 | PACKET_COMPRESSED),
            Ok(&b"abcdefghij"[..])
        );
    }

    #[test]
    fn an_uncompressed_flush_reaches_the_xcrush_history() {
        let mut bulk = Bulk::default();
        bulk.decompress(&XCRUSH_FIRST, RDP61 | PACKET_COMPRESSED)
            .unwrap();
        assert_eq!(
            bulk.decompress(b"raw", RDP61 | justrdp_codecs::mppc::PACKET_FLUSHED),
            Ok(&b"raw"[..])
        );
        // Level-1 match of 3 bytes from history offset 5: "fgh" unless the flush zeroed it.
        let mut packet = vec![0x01, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00];
        packet.extend_from_slice(&5u32.to_le_bytes());
        assert_eq!(
            bulk.decompress(&packet, RDP61 | PACKET_COMPRESSED),
            Ok(&[0, 0, 0][..])
        );
    }

    #[test]
    fn the_type_may_not_change_between_mppc_and_xcrush() {
        let mut bulk = Bulk::default();
        bulk.decompress(&HI, PACKET_COMPR_TYPE_64K | PACKET_COMPRESSED)
            .unwrap();
        assert_eq!(
            bulk.decompress(&XCRUSH_FIRST, RDP61 | PACKET_COMPRESSED),
            Err(BulkError::TypeChanged { from: 1, to: 3 })
        );
        let mut bulk = Bulk::default();
        bulk.decompress(&XCRUSH_FIRST, RDP61 | PACKET_COMPRESSED)
            .unwrap();
        assert_eq!(
            bulk.decompress(&HI, PACKET_COMPR_TYPE_64K | PACKET_COMPRESSED),
            Err(BulkError::TypeChanged { from: 3, to: 1 })
        );
    }

    #[test]
    fn the_type_may_not_change_within_a_connection() {
        let mut bulk = Bulk::default();
        bulk.decompress(&HI, PACKET_COMPR_TYPE_64K | PACKET_COMPRESSED)
            .unwrap();
        assert_eq!(
            bulk.decompress(&HI, PACKET_COMPR_TYPE_8K | PACKET_COMPRESSED),
            Err(BulkError::TypeChanged { from: 1, to: 0 })
        );
    }
}
