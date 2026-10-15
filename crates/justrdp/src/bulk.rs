//! The server-to-client bulk decompression context (`[MS-RDPBCGR]` 3.1.8): one per connection,
//! shared by fast-path updates and slow-path Share Data PDUs, dispatched on the compression
//! type nibble.

use justrdp_codecs::mppc::{Mppc, MppcError, MppcLevel, PACKET_COMPRESSED};

/// `PACKET_COMPR_TYPE_8K`: MPPC with an 8 KB history (RDP 4.0).
pub const PACKET_COMPR_TYPE_8K: u8 = 0;
/// `PACKET_COMPR_TYPE_64K`: MPPC with a 64 KB history (RDP 5.0).
pub const PACKET_COMPR_TYPE_64K: u8 = 1;

/// The flag bits (`PACKET_COMPRESSED`, `PACKET_AT_FRONT`, `PACKET_FLUSHED`).
const FLAG_BITS: u8 = 0xE0;

/// Why a bulk-compressed payload could not be decompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkError {
    /// A compression type the core does not decompress.
    UnsupportedType(u8),
    /// The compression type differs from the one this connection's history was built for.
    TypeChanged {
        /// The type of the connection's first flagged payload.
        from: u8,
        /// The type now named.
        to: u8,
    },
    /// The MPPC decompressor refused the payload.
    Mppc(MppcError),
}

impl core::fmt::Display for BulkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedType(t) => write!(f, "unsupported bulk compression type {t}"),
            Self::TypeChanged { from, to } => {
                write!(f, "bulk compression type changed from {from} to {to}")
            }
            Self::Mppc(e) => write!(f, "MPPC: {e}"),
        }
    }
}

impl core::error::Error for BulkError {}

/// One connection's server-to-client decompression context.
#[derive(Debug, Default)]
pub(crate) struct Bulk {
    mppc: Option<Mppc>,
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
            if compression & FLAG_BITS != 0
                && let Some(mppc) = self.mppc.as_mut()
            {
                mppc.decompress(src, compression).map_err(BulkError::Mppc)?;
            }
            return Ok(src);
        }
        let ty = compression & 0x0F;
        let level = match ty {
            PACKET_COMPR_TYPE_8K => MppcLevel::Rdp4,
            PACKET_COMPR_TYPE_64K => MppcLevel::Rdp5,
            other => return Err(BulkError::UnsupportedType(other)),
        };
        let mppc = self.mppc.get_or_insert_with(|| Mppc::new(level));
        if mppc.level() != level {
            let from = match mppc.level() {
                MppcLevel::Rdp4 => PACKET_COMPR_TYPE_8K,
                MppcLevel::Rdp5 => PACKET_COMPR_TYPE_64K,
            };
            return Err(BulkError::TypeChanged { from, to: ty });
        }
        mppc.decompress(src, compression).map_err(BulkError::Mppc)
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
        for ty in [2, 3, 4] {
            assert_eq!(
                Bulk::default().decompress(&HI, ty | PACKET_COMPRESSED),
                Err(BulkError::UnsupportedType(ty))
            );
        }
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
