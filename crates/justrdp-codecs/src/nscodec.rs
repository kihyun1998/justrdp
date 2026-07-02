//! NSCodec ([MS-RDPNSC]) — codec-owned decode. Slice 1 (epic #132): the compressed
//! bitmap-stream header. Later slices decode the four RLE planes (#138), reconstruct colour
//! (colour-loss + chroma supersample + AYCoCg→ARGB, #139), and assemble the full pipeline (#140);
//! slice 5 (#141) wires it into the ClearCodec subcodec 0x01.
//!
//! `ironrdp-nscodec` ships an encoder but no decoder, so — like RemoteFX (#58) — there is no
//! high-level oracle; correctness follows ADR-0007 (stage-boundary), cross-checked against FreeRDP
//! `libfreerdp/codec/nsc.c` (`nsc_stream_initialize`).

use std::fmt;

/// Why an NSCodec stream failed to parse. Malformed input is always a typed error, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NscError {
    /// The stream ended inside a field of `ctx`.
    NotEnoughBytes {
        /// The structure being parsed when the buffer underflowed.
        ctx: &'static str,
    },
    /// A field held a value the spec forbids.
    InvalidField {
        /// The offending field name.
        field: &'static str,
        /// Why it is invalid.
        reason: &'static str,
    },
}

impl fmt::Display for NscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NscError::NotEnoughBytes { ctx } => write!(f, "not enough bytes for {ctx}"),
            NscError::InvalidField { field, reason } => write!(f, "invalid `{field}`: {reason}"),
        }
    }
}

impl std::error::Error for NscError {}

/// Plane indices into [`NscHeader::plane_byte_counts`] (MS-RDPNSC order).
pub const PLANE_LUMA: usize = 0;
/// Orange-chroma (Co) plane.
pub const PLANE_ORANGE_CHROMA: usize = 1;
/// Green-chroma (Cg) plane.
pub const PLANE_GREEN_CHROMA: usize = 2;
/// Alpha plane.
pub const PLANE_ALPHA: usize = 3;

/// Fixed header length: 4×u32 plane counts + ColorLossLevel + ChromaSubsamplingLevel + 2 reserved.
const HEADER_LEN: usize = 20;

/// The NSCodec compressed-bitmap-stream header ([MS-RDPNSC] 2.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NscHeader {
    /// RLE byte counts of the four planes, in wire order:
    /// `[Luma (Y), OrangeChroma (Co), GreenChroma (Cg), Alpha]`.
    pub plane_byte_counts: [u32; 4],
    /// Colour-loss recovery level, `1..=7`. The reconstruction shift is `color_loss_level - 1`.
    pub color_loss_level: u8,
    /// Whether the Co/Cg chroma planes are 4:2:0 subsampled (`ChromaSubsamplingLevel != 0`).
    pub chroma_subsampled: bool,
}

/// Parse the NSCodec header and return it together with the concatenated plane data — the
/// `sum(plane_byte_counts)` bytes immediately following the 20-byte header. Validates
/// `ColorLossLevel` in `1..=7` and that the declared plane data is fully present, mirroring FreeRDP
/// `nsc_stream_initialize` (`nsc.c`). The returned slice is split per plane by a later slice (#138).
pub fn parse_header(data: &[u8]) -> Result<(NscHeader, &[u8]), NscError> {
    if data.len() < HEADER_LEN {
        return Err(NscError::NotEnoughBytes {
            ctx: "NSCodecHeader",
        });
    }

    let mut plane_byte_counts = [0u32; 4];
    let mut total: u64 = 0;
    for (i, slot) in plane_byte_counts.iter_mut().enumerate() {
        let off = i * 4;
        *slot = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        total += u64::from(*slot);
    }

    let color_loss_level = data[16];
    if !(1..=7).contains(&color_loss_level) {
        return Err(NscError::InvalidField {
            field: "ColorLossLevel",
            reason: "must be in 1..=7",
        });
    }
    let chroma_subsampled = data[17] != 0;
    // data[18..20] is reserved.

    // usize::try_from guards 32-bit targets; checked_add guards the header+total sum.
    let total = usize::try_from(total)
        .ok()
        .and_then(|t| HEADER_LEN.checked_add(t));
    let end = total.ok_or(NscError::InvalidField {
        field: "PlaneByteCount",
        reason: "plane total overflows usize",
    })?;
    let planes = data.get(HEADER_LEN..end).ok_or(NscError::NotEnoughBytes {
        ctx: "NSCodecPlanes",
    })?;

    Ok((
        NscHeader {
            plane_byte_counts,
            color_loss_level,
            chroma_subsampled,
        },
        planes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Build a 20-byte header from field values (reserved zeroed).
    fn header_bytes(planes: [u32; 4], color_loss: u8, chroma: u8) -> Vec<u8> {
        let mut h = Vec::with_capacity(HEADER_LEN);
        for c in planes {
            h.extend_from_slice(&c.to_le_bytes());
        }
        h.push(color_loss);
        h.push(chroma);
        h.extend_from_slice(&[0, 0]); // reserved
        h
    }

    #[test]
    fn parses_a_valid_header_and_returns_the_plane_bytes() {
        let mut data = header_bytes([3, 2, 2, 0], 3, 1);
        data.extend_from_slice(&[0xAA; 7]); // total = 3+2+2+0

        let (hdr, planes) = parse_header(&data).unwrap();
        assert_eq!(hdr.plane_byte_counts, [3, 2, 2, 0]);
        assert_eq!(hdr.color_loss_level, 3);
        assert!(hdr.chroma_subsampled);
        assert_eq!(planes, &[0xAA; 7]);
    }

    #[test]
    fn chroma_subsampling_zero_is_not_subsampled() {
        // total = 0, so no plane bytes follow the header.
        let data = header_bytes([0, 0, 0, 0], 1, 0);
        let (hdr, planes) = parse_header(&data).unwrap();
        assert!(!hdr.chroma_subsampled);
        assert!(planes.is_empty());
    }

    #[test]
    fn color_loss_level_out_of_range_is_rejected() {
        for bad in [0u8, 8, 255] {
            let data = header_bytes([0, 0, 0, 0], bad, 0);
            assert_eq!(
                parse_header(&data),
                Err(NscError::InvalidField {
                    field: "ColorLossLevel",
                    reason: "must be in 1..=7",
                }),
                "ColorLossLevel {bad} must be rejected"
            );
        }
        // The valid boundary values pass.
        for ok in [1u8, 7] {
            assert!(parse_header(&header_bytes([0, 0, 0, 0], ok, 0)).is_ok());
        }
    }

    #[test]
    fn a_truncated_header_is_a_typed_error() {
        assert_eq!(
            parse_header(&[0u8; 19]),
            Err(NscError::NotEnoughBytes {
                ctx: "NSCodecHeader",
            })
        );
    }

    #[test]
    fn plane_data_shorter_than_declared_is_a_typed_error() {
        let mut data = header_bytes([10, 0, 0, 0], 1, 0); // declares 10 plane bytes
        data.extend_from_slice(&[0xAA; 4]); // but only 4 follow
        assert_eq!(
            parse_header(&data),
            Err(NscError::NotEnoughBytes {
                ctx: "NSCodecPlanes",
            })
        );
    }

    proptest! {
        // ADR-0008 / issue #97 — the no-panic robustness property. The whole buffer is the
        // unbounded, attacker-controlled blob; parsing must always be a typed error or Ok, never a
        // panic / overflow / OOB.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn parse_header_never_panics_on_arbitrary_input(
            data in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            let _ = parse_header(&data);
        }
    }
}
