//! Surface commands (`[MS-RDPBCGR]` 2.2.9.2): the body of a fast-path Surface Commands Update
//! ([`crate::fastpath::FP_UPDATE_SURFCMDS`], `TS_FP_SURFCMDS` 2.2.9.1.2.1.10). The update carries
//! the commands back to back, with no count and no per-command length, so a command type this
//! decoder cannot size ends the parse. There is no slow-path form (2.2.9.2).
//!
//! Decode only: justrdp is a client and these commands are server-to-client.

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `cmdType`: Set Surface Bits (`CMDTYPE_SET_SURFACE_BITS`).
pub const CMDTYPE_SET_SURFACE_BITS: u16 = 0x0001;
/// `cmdType`: Frame Marker (`CMDTYPE_FRAME_MARKER`).
pub const CMDTYPE_FRAME_MARKER: u16 = 0x0004;
/// `cmdType`: Stream Surface Bits (`CMDTYPE_STREAM_SURFACE_BITS`).
pub const CMDTYPE_STREAM_SURFACE_BITS: u16 = 0x0006;

/// `frameAction`: the start of a frame (`SURFACECMD_FRAMEACTION_BEGIN`).
pub const FRAMEACTION_BEGIN: u16 = 0x0000;
/// `frameAction`: the end of a frame (`SURFACECMD_FRAMEACTION_END`).
pub const FRAMEACTION_END: u16 = 0x0001;

/// `TS_BITMAP_DATA_EX.flags`: a `TS_COMPRESSED_BITMAP_HEADER_EX` follows the fixed fields.
pub const EX_COMPRESSED_BITMAP_HEADER_PRESENT: u8 = 0x01;

/// The size of `TS_COMPRESSED_BITMAP_HEADER_EX` (2.2.9.2.1.1.1).
const COMPRESSED_BITMAP_HEADER_EX_LEN: usize = 24;

/// One surface command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceCommand<'a> {
    /// Set Surface Bits or Stream Surface Bits: the two share one layout (2.2.9.2.1, 2.2.9.2.2).
    SurfaceBits(SurfaceBits<'a>),
    /// Frame Marker (`TS_FRAME_MARKER`, 2.2.9.2.3).
    FrameMarker(FrameMarker),
}

/// Set Surface Bits / Stream Surface Bits (`TS_SURFCMD_SET_SURF_BITS`,
/// `TS_SURFCMD_STREAM_SURF_BITS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceBits<'a> {
    /// `cmdType`: [`CMDTYPE_SET_SURFACE_BITS`] or [`CMDTYPE_STREAM_SURFACE_BITS`].
    pub cmd_type: u16,
    /// `destLeft`.
    pub dest_left: u16,
    /// `destTop`.
    pub dest_top: u16,
    /// `destRight`, exclusive. In Set Surface Bits it SHOULD be ignored (2.2.9.2.1).
    pub dest_right: u16,
    /// `destBottom`, exclusive. In Set Surface Bits it SHOULD be ignored (2.2.9.2.1).
    pub dest_bottom: u16,
    /// `bitmapData`.
    pub bitmap: BitmapDataEx<'a>,
}

/// Extended Bitmap Data (`TS_BITMAP_DATA_EX`, 2.2.9.2.1.1), without the optional
/// `TS_COMPRESSED_BITMAP_HEADER_EX`, which is skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapDataEx<'a> {
    /// `bpp`.
    pub bpp: u8,
    /// `flags`.
    pub flags: u8,
    /// `codecID`: 0 is unencoded; anything else is an ID the client assigned in its Bitmap Codecs
    /// capability set.
    pub codec_id: u8,
    /// `width`.
    pub width: u16,
    /// `height`.
    pub height: u16,
    /// `bitmapData`, `bitmapDataLength` bytes.
    pub data: &'a [u8],
}

/// Frame Marker (`TS_FRAME_MARKER`, 2.2.9.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMarker {
    /// `frameAction`: [`FRAMEACTION_BEGIN`] or [`FRAMEACTION_END`].
    pub frame_action: u16,
    /// `frameId`.
    pub frame_id: u32,
}

/// Decode every surface command in a fast-path Surface Commands Update body.
pub fn decode_all(body: &[u8]) -> Result<Vec<SurfaceCommand<'_>>, DecodeError> {
    let mut cur = ReadCursor::new(body, "TS_FP_SURFCMDS");
    let mut commands = Vec::new();
    while cur.remaining() > 0 {
        commands.push(decode_one(&mut cur)?);
    }
    Ok(commands)
}

fn decode_one<'a>(cur: &mut ReadCursor<'a>) -> Result<SurfaceCommand<'a>, DecodeError> {
    let cmd_type = cur.read_u16_le()?;
    match cmd_type {
        CMDTYPE_SET_SURFACE_BITS | CMDTYPE_STREAM_SURFACE_BITS => {
            let dest_left = cur.read_u16_le()?;
            let dest_top = cur.read_u16_le()?;
            let dest_right = cur.read_u16_le()?;
            let dest_bottom = cur.read_u16_le()?;
            let bitmap = BitmapDataEx::decode(cur)?;
            Ok(SurfaceCommand::SurfaceBits(SurfaceBits {
                cmd_type,
                dest_left,
                dest_top,
                dest_right,
                dest_bottom,
                bitmap,
            }))
        }
        CMDTYPE_FRAME_MARKER => {
            let frame_action = cur.read_u16_le()?;
            let frame_id = cur.read_u32_le()?;
            Ok(SurfaceCommand::FrameMarker(FrameMarker {
                frame_action,
                frame_id,
            }))
        }
        _ => Err(DecodeError::InvalidField {
            field: "TS_SURFCMD.cmdType",
            reason: "unknown surface command type; the commands that follow cannot be located",
        }),
    }
}

impl<'a> BitmapDataEx<'a> {
    fn decode(cur: &mut ReadCursor<'a>) -> Result<Self, DecodeError> {
        let bpp = cur.read_u8()?;
        let flags = cur.read_u8()?;
        cur.read_u8()?; // reserved
        let codec_id = cur.read_u8()?;
        let width = cur.read_u16_le()?;
        let height = cur.read_u16_le()?;
        let data_len = cur.read_u32_le()? as usize;
        if flags & EX_COMPRESSED_BITMAP_HEADER_PRESENT != 0 {
            cur.read_slice(COMPRESSED_BITMAP_HEADER_EX_LEN)?;
        }
        let data = cur.read_slice(data_len)?;
        Ok(Self {
            bpp,
            flags,
            codec_id,
            width,
            height,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A Set Surface Bits command with the given geometry, codec and data.
    fn surface_bits(
        dest: (u16, u16, u16, u16),
        codec_id: u8,
        size: (u16, u16),
        data: &[u8],
    ) -> Vec<u8> {
        let mut out = CMDTYPE_SET_SURFACE_BITS.to_le_bytes().to_vec();
        for v in [dest.0, dest.1, dest.2, dest.3] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&[32, 0, 0, codec_id]);
        out.extend_from_slice(&size.0.to_le_bytes());
        out.extend_from_slice(&size.1.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    fn frame_marker(action: u16, id: u32) -> Vec<u8> {
        let mut out = CMDTYPE_FRAME_MARKER.to_le_bytes().to_vec();
        out.extend_from_slice(&action.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
        out
    }

    /// One command's bytes: a `cmdType` weighted towards the three this decoder sizes, then
    /// arbitrary fields. The `bitmapDataLength` lands at bytes 18..22, inside the 40-byte tail.
    fn command() -> impl Strategy<Value = Vec<u8>> {
        let cmd_type = prop_oneof![
            3 => Just(CMDTYPE_SET_SURFACE_BITS),
            3 => Just(CMDTYPE_STREAM_SURFACE_BITS),
            3 => Just(CMDTYPE_FRAME_MARKER),
            1 => any::<u16>(),
        ];
        (cmd_type, proptest::collection::vec(any::<u8>(), 0..=40)).prop_map(|(cmd_type, tail)| {
            let mut out = cmd_type.to_le_bytes().to_vec();
            out.extend(tail);
            out
        })
    }

    proptest! {
        // ADR-0008: the no-panic property for a server-controlled parser. Malformed bytes are a
        // typed `DecodeError`, never a panic; reaching the end without unwinding is the assertion.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decode_never_panics_on_arbitrary_input(
            commands in proptest::collection::vec(command(), 0..=4),
        ) {
            let _ = decode_all(&commands.concat());
        }
    }

    #[test]
    fn commands_are_decoded_back_to_back() {
        let mut body = frame_marker(FRAMEACTION_BEGIN, 7);
        body.extend(surface_bits(
            (64, 128, 128, 192),
            1,
            (64, 64),
            &[0xAA, 0xBB, 0xCC],
        ));
        body.extend(frame_marker(FRAMEACTION_END, 7));
        assert_eq!(
            decode_all(&body).expect("three commands decode"),
            vec![
                SurfaceCommand::FrameMarker(FrameMarker {
                    frame_action: FRAMEACTION_BEGIN,
                    frame_id: 7,
                }),
                SurfaceCommand::SurfaceBits(SurfaceBits {
                    cmd_type: CMDTYPE_SET_SURFACE_BITS,
                    dest_left: 64,
                    dest_top: 128,
                    dest_right: 128,
                    dest_bottom: 192,
                    bitmap: BitmapDataEx {
                        bpp: 32,
                        flags: 0,
                        codec_id: 1,
                        width: 64,
                        height: 64,
                        data: &[0xAA, 0xBB, 0xCC],
                    },
                }),
                SurfaceCommand::FrameMarker(FrameMarker {
                    frame_action: FRAMEACTION_END,
                    frame_id: 7,
                }),
            ]
        );
    }

    #[test]
    fn stream_surface_bits_shares_the_set_surface_bits_layout() {
        let mut body = surface_bits((0, 0, 1, 1), 0, (1, 1), &[1, 2, 3, 4]);
        body[..2].copy_from_slice(&CMDTYPE_STREAM_SURFACE_BITS.to_le_bytes());
        let commands = decode_all(&body).unwrap();
        let [SurfaceCommand::SurfaceBits(bits)] = commands.as_slice() else {
            panic!("one surface bits command");
        };
        assert_eq!(bits.cmd_type, CMDTYPE_STREAM_SURFACE_BITS);
        assert_eq!(bits.bitmap.data, &[1, 2, 3, 4]);
    }

    #[test]
    fn the_compressed_bitmap_header_is_skipped_and_not_counted_in_the_length() {
        // bitmapDataLength counts bitmapData only (2.2.9.2.1.1); the 24-byte header sits between.
        let mut body = surface_bits((0, 0, 1, 1), 1, (1, 1), &[]);
        body[11] = EX_COMPRESSED_BITMAP_HEADER_PRESENT;
        body[18..22].copy_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&[0xEE; COMPRESSED_BITMAP_HEADER_EX_LEN]);
        body.extend_from_slice(&[0x11, 0x22]);
        body.extend(frame_marker(FRAMEACTION_END, 1));
        let commands = decode_all(&body).expect("the header is stepped over");
        let SurfaceCommand::SurfaceBits(bits) = &commands[0] else {
            panic!("surface bits first");
        };
        assert_eq!(bits.bitmap.flags, EX_COMPRESSED_BITMAP_HEADER_PRESENT);
        assert_eq!(bits.bitmap.data, &[0x11, 0x22]);
        assert!(matches!(commands[1], SurfaceCommand::FrameMarker(_)));
    }

    #[test]
    fn an_unknown_command_type_is_a_typed_error() {
        let mut body = frame_marker(FRAMEACTION_BEGIN, 1);
        body.extend_from_slice(&0x0002u16.to_le_bytes());
        body.extend_from_slice(&[0; 8]);
        assert!(matches!(
            decode_all(&body),
            Err(DecodeError::InvalidField {
                field: "TS_SURFCMD.cmdType",
                ..
            })
        ));
    }

    #[test]
    fn bitmap_data_past_the_body_is_a_typed_error() {
        let mut body = surface_bits((0, 0, 1, 1), 1, (1, 1), &[1, 2, 3]);
        body.truncate(body.len() - 1);
        assert!(matches!(
            decode_all(&body),
            Err(DecodeError::NotEnoughBytes { .. })
        ));
    }

    #[test]
    fn a_trailing_partial_command_is_a_typed_error() {
        let mut body = frame_marker(FRAMEACTION_END, 1);
        body.push(0x04);
        assert!(matches!(
            decode_all(&body),
            Err(DecodeError::NotEnoughBytes { .. })
        ));
    }

    #[test]
    fn an_empty_body_holds_no_commands() {
        assert_eq!(decode_all(&[]), Ok(Vec::new()));
    }
}
