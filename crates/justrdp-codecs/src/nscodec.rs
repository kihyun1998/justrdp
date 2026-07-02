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

/// Split the concatenated plane data (from [`parse_header`]) into the four per-plane slices in wire
/// order, by their byte counts. `parse_header` already guaranteed the total length; this is the
/// bounds-checked partition the decode slices consume.
pub fn split_planes<'a>(
    planes: &'a [u8],
    plane_byte_counts: &[u32; 4],
) -> Result<[&'a [u8]; 4], NscError> {
    let mut out: [&[u8]; 4] = [&[]; 4];
    let mut off = 0usize;
    for (i, &count) in plane_byte_counts.iter().enumerate() {
        let end = usize::try_from(count)
            .ok()
            .and_then(|c| off.checked_add(c))
            .ok_or(NscError::InvalidField {
                field: "PlaneByteCount",
                reason: "plane offset overflows usize",
            })?;
        out[i] = planes.get(off..end).ok_or(NscError::NotEnoughBytes {
            ctx: "NSCodecPlanes",
        })?;
        off = end;
    }
    Ok(out)
}

/// Decode one plane into exactly `original_size` raw bytes. Three cases mirror FreeRDP
/// `nsc_rle_decompress_data`: an empty (zero-length) plane fills `0xFF`; a plane shorter than its
/// decoded size is RLE-compressed; otherwise it is stored raw and copied verbatim. `original_size`
/// is caller-supplied geometry (width×height of the plane), not read from the untrusted stream.
pub fn decode_plane(compressed: &[u8], original_size: usize) -> Result<Vec<u8>, NscError> {
    if compressed.is_empty() {
        Ok(vec![0xFF; original_size])
    } else if compressed.len() < original_size {
        nsc_rle_decode(compressed, original_size)
    } else {
        Ok(compressed[..original_size].to_vec())
    }
}

/// The NSCodec plane RLE (FreeRDP `nsc_rle_decode`): decode `input` into exactly `original_size`
/// bytes. A run is `value value marker` (`marker < 0xFF` → `marker + 2` repeats, else `0xFF` then a
/// u32-LE count); a byte that does not repeat is a literal; the final four bytes are always stored
/// raw. Every read is bounds-checked — `input` is untrusted.
fn nsc_rle_decode(input: &[u8], original_size: usize) -> Result<Vec<u8>, NscError> {
    let short = || NscError::NotEnoughBytes {
        ctx: "NSCodecPlaneRle",
    };
    // Grow on demand; cap the pre-allocation so a large `original_size` alone can't force a huge one.
    let mut out = Vec::with_capacity(original_size.min(1 << 16));
    let mut left = original_size;
    let mut pos = 0usize;

    while left > 4 {
        let value = *input.get(pos).ok_or_else(short)?;
        pos += 1;

        if left == 5 {
            // The five-bytes-left boundary never starts a run — emit one literal, then the raw tail.
            out.push(value);
            left -= 1;
            continue;
        }

        let next = *input.get(pos).ok_or_else(short)?;
        if next != value {
            // Literal: `next` is left in place to be the following iteration's `value`.
            out.push(value);
            left -= 1;
            continue;
        }

        pos += 1; // consume the second `value`
        let marker = *input.get(pos).ok_or_else(short)?;
        let len = if marker < 0xFF {
            pos += 1;
            usize::from(marker) + 2
        } else {
            let bytes = input.get(pos + 1..pos + 5).ok_or_else(short)?;
            pos += 5; // the 0xFF marker + the 4-byte count
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
        };
        if len > left {
            return Err(NscError::InvalidField {
                field: "NSCodecPlaneRle",
                reason: "run length exceeds the plane",
            });
        }
        out.resize(out.len() + len, value);
        left -= len;
    }

    // The loop only exits at `left <= 4`, and a run may not overshoot below four — so `left` is
    // exactly 4 here, and the last four plane bytes are copied raw (FreeRDP's trailing `memcpy`).
    if left != 4 {
        return Err(NscError::InvalidField {
            field: "NSCodecPlaneRle",
            reason: "a run overshot the four-byte raw tail",
        });
    }
    let tail = input.get(pos..pos + 4).ok_or_else(short)?;
    out.extend_from_slice(tail);
    Ok(out)
}

fn round_up(v: usize, n: usize) -> usize {
    v.div_ceil(n) * n
}

/// The aligned plane dimensions FreeRDP allocates (`nsc_context_initialize`): width up to a
/// multiple of 8, height up to a multiple of 2. Only relevant when chroma is subsampled.
fn temp_dims(width: usize, height: usize) -> (usize, usize) {
    (round_up(width, 8), round_up(height, 2))
}

/// Expected decoded byte counts of the four planes `[Y, Co, Cg, Alpha]` for a `width`×`height`
/// bitmap (FreeRDP `OrgByteCount`). When subsampled the luma plane is padded to `tempWidth` and the
/// two chroma planes are quarter-area; alpha is always full resolution. Used to size the RLE decode
/// (#140) and to bound reconstruction.
pub fn plane_sizes(width: usize, height: usize, chroma_subsampled: bool) -> [usize; 4] {
    if chroma_subsampled {
        let (tw, th) = temp_dims(width, height);
        let chroma = (tw >> 1) * (th >> 1);
        [tw * height, chroma, chroma, width * height]
    } else {
        let n = width * height;
        [n, n, n, n]
    }
}

/// Reconstruct `width`×`height` **BGRA** pixels from the four decoded planes `[Y, Co, Cg, Alpha]`,
/// in one pass (FreeRDP `nsc_decode`): colour-loss recovery (`shift = ColorLossLevel - 1`), chroma
/// supersampling (4:2:0 — each Co/Cg sample covers a 2×2 block when subsampled), and AYCoCg→RGB
/// (`R = Y + Co − Cg`, `G = Y + Cg`, `B = Y − Co − Cg`, each clamped to `0..=255`). Chroma bytes are
/// shifted then sign-truncated to a signed delta (`(i8)((byte) << shift)`). Output byte order is
/// BGRA, matching the ClearCodec output buffer (#141). Plane accesses are bounds-checked: a plane
/// shorter than its geometry is a malformed stream, not a panic.
pub fn reconstruct(
    planes: &[Vec<u8>; 4],
    width: usize,
    height: usize,
    color_loss_level: u8,
    chroma_subsampled: bool,
) -> Result<Vec<u8>, NscError> {
    let total = width
        .checked_mul(height)
        .and_then(|v| v.checked_mul(4))
        .ok_or(NscError::InvalidField {
            field: "dimensions",
            reason: "width * height * 4 overflows usize",
        })?;
    let short = || NscError::NotEnoughBytes {
        ctx: "NSCodecPlanes",
    };

    let shift = color_loss_level.saturating_sub(1);
    let (temp_width, _) = temp_dims(width, height);
    let [y_plane, co_plane, cg_plane, a_plane] = planes;
    let (y_stride, co_stride) = if chroma_subsampled {
        (temp_width, temp_width >> 1)
    } else {
        (width, width)
    };

    let mut out = Vec::with_capacity(total);
    for y in 0..height {
        let y_row = y * y_stride;
        let co_row = if chroma_subsampled { y >> 1 } else { y } * co_stride;
        let a_row = y * width;
        for x in 0..width {
            let co_idx = if chroma_subsampled { x >> 1 } else { x };
            let y_val = i16::from(*y_plane.get(y_row + x).ok_or_else(short)?);
            let co_raw = *co_plane.get(co_row + co_idx).ok_or_else(short)?;
            let cg_raw = *cg_plane.get(co_row + co_idx).ok_or_else(short)?;
            let alpha = *a_plane.get(a_row + x).ok_or_else(short)?;
            // `(i8)((i16)byte << shift)`: low byte reinterpreted as a signed chroma delta.
            let co = i16::from(((i16::from(co_raw) << shift) as u8) as i8);
            let cg = i16::from(((i16::from(cg_raw) << shift) as u8) as i8);
            let r = (y_val + co - cg).clamp(0, 255) as u8;
            let g = (y_val + cg).clamp(0, 255) as u8;
            let b = (y_val - co - cg).clamp(0, 255) as u8;
            out.extend_from_slice(&[b, g, r, alpha]);
        }
    }
    Ok(out)
}

/// Decode a full NSCodec compressed-bitmap stream into `width`×`height` **BGRA** pixels — the public
/// entry point wiring the header (#137) → per-plane RLE decode (#138) → colour reconstruction
/// (#139). `width`/`height` are the region geometry supplied by the surface command / ClearCodec
/// subcodec (#141), never read from the stream. NSCodec is stateless, so this is a free function.
pub fn decode(data: &[u8], width: u16, height: u16) -> Result<Vec<u8>, NscError> {
    let (w, h) = (usize::from(width), usize::from(height));
    let (header, planes) = parse_header(data)?;
    let sizes = plane_sizes(w, h, header.chroma_subsampled);
    let slices = split_planes(planes, &header.plane_byte_counts)?;
    let decoded = [
        decode_plane(slices[0], sizes[0])?,
        decode_plane(slices[1], sizes[1])?,
        decode_plane(slices[2], sizes[2])?,
        decode_plane(slices[3], sizes[3])?,
    ];
    reconstruct(
        &decoded,
        w,
        h,
        header.color_loss_level,
        header.chroma_subsampled,
    )
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

    // --- slice 2: RLE plane decode. Vectors are hand-encoded from the FreeRDP `nsc_rle_decode`
    // scheme (`ironrdp-nscodec`'s `rle_encode` is private and only encodes whole bitmaps, so it is
    // not a usable per-plane oracle — the full-pipeline round-trip lives in slice 4 / #140).

    #[test]
    fn rle_decodes_a_run_between_literals() {
        // input: value 7 repeats (marker 3 → 3+2 = 5), then one literal (8), then the 4-byte tail.
        let input = [7, 7, 3, 8, 9, 10, 11, 12];
        let out = decode_plane(&input, 10).unwrap();
        assert_eq!(out, [7, 7, 7, 7, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn rle_all_literals_round_trips_to_itself() {
        // No repeats: the first byte is a literal, the five-left byte is a literal, then the tail.
        let input = [1, 2, 3, 4, 5, 6];
        assert_eq!(decode_plane(&input, 6).unwrap(), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn rle_long_run_uses_the_four_byte_count() {
        // marker 0xFF → the next u32-LE (266) is the run length; then the 4-byte tail.
        let mut input = vec![5, 5, 0xFF];
        input.extend_from_slice(&266u32.to_le_bytes());
        input.extend_from_slice(&[100, 101, 102, 103]); // tail
        let out = decode_plane(&input, 270).unwrap();
        let mut want = vec![5u8; 266];
        want.extend_from_slice(&[100, 101, 102, 103]);
        assert_eq!(out, want);
    }

    #[test]
    fn empty_plane_fills_0xff() {
        assert_eq!(decode_plane(&[], 5).unwrap(), [0xFF; 5]);
    }

    #[test]
    fn plane_at_least_as_long_as_its_output_is_copied_raw() {
        // compressed.len() (6) >= original_size (4): stored uncompressed, copied verbatim.
        assert_eq!(decode_plane(&[1, 2, 3, 4, 5, 6], 4).unwrap(), [1, 2, 3, 4]);
    }

    #[test]
    fn rle_run_overshooting_the_tail_is_rejected() {
        // marker 4 → len 6 consumes the whole plane, leaving 0 (< 4) — a malformed stream.
        assert_eq!(
            decode_plane(&[7, 7, 4], 6),
            Err(NscError::InvalidField {
                field: "NSCodecPlaneRle",
                reason: "a run overshot the four-byte raw tail",
            })
        );
    }

    #[test]
    fn rle_truncated_run_is_a_typed_error() {
        // A run header with no marker byte.
        assert_eq!(
            decode_plane(&[7, 7], 10),
            Err(NscError::NotEnoughBytes {
                ctx: "NSCodecPlaneRle",
            })
        );
    }

    #[test]
    fn split_planes_partitions_by_byte_counts() {
        let planes: Vec<u8> = (0..7).collect();
        let parts = split_planes(&planes, &[3, 2, 2, 0]).unwrap();
        assert_eq!(parts[PLANE_LUMA], &[0, 1, 2]);
        assert_eq!(parts[PLANE_ORANGE_CHROMA], &[3, 4]);
        assert_eq!(parts[PLANE_GREEN_CHROMA], &[5, 6]);
        assert!(parts[PLANE_ALPHA].is_empty());
    }

    // --- slice 3: colour reconstruction. Vectors are hand-computed from the AYCoCg→RGB math and
    // the FreeRDP `nsc_decode` indexing (no oracle — pure spec math, per ADR-0007 / #118).

    #[test]
    fn reconstruct_non_subsampled_applies_the_aycocg_matrix() {
        // 2×1, ColorLossLevel 1 (shift 0). px0: Y100 Co10 Cg5 → R=105 G=105 B=85. px1: Y50 → grey.
        let planes = [vec![100, 50], vec![10, 0], vec![5, 0], vec![255, 128]];
        let out = reconstruct(&planes, 2, 1, 1, false).unwrap();
        assert_eq!(out, [85, 105, 105, 255, 50, 50, 50, 128]);
    }

    #[test]
    fn reconstruct_applies_the_colour_loss_shift() {
        // 1×1, ColorLossLevel 3 (shift 2): Co 3→12, Cg 1→4. R=108 G=104 B=84.
        let planes = [vec![100], vec![3], vec![1], vec![255]];
        assert_eq!(
            reconstruct(&planes, 1, 1, 3, false).unwrap(),
            [84, 104, 108, 255]
        );
    }

    #[test]
    fn reconstruct_sign_truncates_chroma_and_clamps() {
        // 1×1, shift 2: Co 100 → (100<<2)=400 → (u8)144 → (i8)-112. R=100-112→clamp 0, B=100+112=212.
        let planes = [vec![100], vec![100], vec![0], vec![255]];
        assert_eq!(
            reconstruct(&planes, 1, 1, 3, false).unwrap(),
            [212, 100, 0, 255]
        );
    }

    #[test]
    fn reconstruct_subsampled_shares_one_chroma_sample_across_the_2x2_block() {
        // 2×2 subsampled: Y is padded to tempWidth=8 (row 1 at index 8); a single Co/Cg sample
        // (Co0=5, Cg0=2) covers all four pixels; alpha stays full-resolution.
        let planes = [
            vec![10, 20, 0, 0, 0, 0, 0, 0, 30, 40, 0, 0, 0, 0, 0, 0], // Y, stride 8
            vec![5, 0, 0, 0],                                         // Co (quarter-area)
            vec![2, 0, 0, 0],                                         // Cg
            vec![255, 254, 253, 252],                                 // Alpha, stride 2
        ];
        let out = reconstruct(&planes, 2, 2, 1, true).unwrap();
        assert_eq!(
            out,
            [
                3, 12, 13, 255, 13, 22, 23, 254, // row 0
                23, 32, 33, 253, 33, 42, 43, 252, // row 1
            ]
        );
    }

    #[test]
    fn plane_sizes_match_freerdp_orgbytecount() {
        assert_eq!(plane_sizes(3, 2, false), [6, 6, 6, 6]);
        // subsampled 3×2: tempW=8, tempH=2 → Y=16, chroma=(4)*(1)=4, alpha=6.
        assert_eq!(plane_sizes(3, 2, true), [16, 4, 4, 6]);
    }

    #[test]
    fn reconstruct_short_plane_is_a_typed_error() {
        // Y has only 1 byte for a 2×1 bitmap.
        let planes = [vec![100], vec![0, 0], vec![0, 0], vec![255, 255]];
        assert_eq!(
            reconstruct(&planes, 2, 1, 1, false),
            Err(NscError::NotEnoughBytes {
                ctx: "NSCodecPlanes",
            })
        );
    }

    // --- slice 4: full-pipeline assembly. Vectors are hand-constructed whole streams (header +
    // planes) with the expected BGRA computed from the slice-3 math. The `ironrdp-nscodec` encoder
    // is deliberately NOT used as an oracle here: it stores planes bottom-up (FreeRDP `nsc_decode`
    // reads top-down), never subsamples, and is lossy — so an encode→decode round-trip would be
    // flipped, non-subsampled-only, and inexact. The real-server proof is corpus entry 30 in slice 5
    // (#141). (ADR-0007 / #118: an unfaithful oracle is not used.)

    /// Wrap plane bytes in a full NSCodec stream (20-byte header + concatenated planes).
    fn stream(plane_counts: [u32; 4], color_loss: u8, chroma: u8, planes: &[u8]) -> Vec<u8> {
        let mut s = header_bytes(plane_counts, color_loss, chroma);
        s.extend_from_slice(planes);
        s
    }

    #[test]
    fn decode_assembles_a_non_subsampled_stream() {
        // 2×1, raw planes (planeSize == originalSize), ColorLossLevel 1 — same pixels as the
        // slice-3 non-subsampled vector, now driven end to end through the header + plane split.
        let planes = [100, 50, 10, 0, 5, 0, 255, 128]; // Y, Co, Cg, A (2 raw bytes each)
        let s = stream([2, 2, 2, 2], 1, 0, &planes);
        assert_eq!(
            decode(&s, 2, 1).unwrap(),
            [85, 105, 105, 255, 50, 50, 50, 128]
        );
    }

    #[test]
    fn decode_assembles_a_subsampled_stream_with_padded_geometry() {
        // 2×2 subsampled: plane sizes are the FreeRDP OrgByteCount [16, 4, 4, 4] (Y padded to
        // tempWidth 8, chroma quarter-area). Same pixels as the slice-3 subsampled vector.
        let mut planes = vec![10, 20, 0, 0, 0, 0, 0, 0, 30, 40, 0, 0, 0, 0, 0, 0]; // Y (16)
        planes.extend_from_slice(&[5, 0, 0, 0]); // Co (4)
        planes.extend_from_slice(&[2, 0, 0, 0]); // Cg (4)
        planes.extend_from_slice(&[255, 254, 253, 252]); // A (4)
        let s = stream([16, 4, 4, 4], 1, 1, &planes);
        assert_eq!(
            decode(&s, 2, 2).unwrap(),
            [
                3, 12, 13, 255, 13, 22, 23, 254, 23, 32, 33, 253, 33, 42, 43, 252
            ]
        );
    }

    #[test]
    fn decode_fills_an_empty_plane_with_0xff() {
        // Alpha plane count 0 → 0xFF fill: the two pixels come back fully opaque.
        let planes = [100, 50, 10, 0, 5, 0]; // Y, Co, Cg; no alpha bytes
        let s = stream([2, 2, 2, 0], 1, 0, &planes);
        assert_eq!(
            decode(&s, 2, 1).unwrap(),
            [85, 105, 105, 255, 50, 50, 50, 255]
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

        // The RLE plane decode over arbitrary bytes: `original_size` is bounded (real geometry is a
        // u16 field), so the fuzzer/proptest budget goes to the compressed `data`.
        #[test]
        fn decode_plane_never_panics_on_arbitrary_input(
            original_size in 0usize..=4096,
            data in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = decode_plane(&data, original_size);
        }

        // Reconstruction over arbitrary (possibly too-short) planes and any colour-loss level: bounded
        // dims keep the output small; a plane that underruns its geometry is a typed error, not a panic.
        #[test]
        fn reconstruct_never_panics_on_arbitrary_input(
            width in 0usize..=32,
            height in 0usize..=32,
            color_loss in 1u8..=7,
            subsampled in any::<bool>(),
            p0 in proptest::collection::vec(any::<u8>(), 0..=256),
            p1 in proptest::collection::vec(any::<u8>(), 0..=256),
            p2 in proptest::collection::vec(any::<u8>(), 0..=256),
            p3 in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            let planes = [p0, p1, p2, p3];
            let _ = reconstruct(&planes, width, height, color_loss, subsampled);
        }

        // Full-pipeline decode over an arbitrary stream: dims are bounded (real geometry is u16 from
        // the surface command), so the budget goes to the attacker-controlled stream bytes.
        #[test]
        fn decode_never_panics_on_arbitrary_input(
            width in 0u16..=48,
            height in 0u16..=48,
            data in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let _ = decode(&data, width, height);
        }
    }
}
