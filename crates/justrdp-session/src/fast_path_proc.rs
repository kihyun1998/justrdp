#![forbid(unsafe_code)]

//! Fast-path frame processing -- MS-RDPBCGR 2.2.9.1.2 / 2.2.8.1.2
//!
//! Handles server-to-client fast-path output parsing and client-to-server
//! fast-path input frame construction.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_bulk::bulk::BulkDecompressor;
use justrdp_bulk::mppc::PACKET_COMPRESSED;
use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_pdu::rdp::fast_path::{
    FastPathInputEvent, FastPathInputHeader, FastPathOutputHeader, FastPathOutputUpdate,
    FastPathUpdateType, FASTPATH_INPUT_ACTION_FASTPATH,
};

use crate::complete_data::{AssembledUpdate, CompleteData};
use crate::{ActiveStageOutput, SessionError, SessionResult};

// ── Fast-Path Output Processing (server → client) ──

/// Process a complete fast-path output frame.
///
/// The frame starts with the `fpOutputHeader` byte (action bits 0-1 == 0x00).
pub(crate) fn process_fast_path_output(
    frame: &[u8],
    decompressor: &mut BulkDecompressor,
    complete_data: &mut CompleteData,
) -> SessionResult<Vec<ActiveStageOutput>> {
    let mut src = ReadCursor::new(frame);

    // Decode the fast-path output header.
    let _header = FastPathOutputHeader::decode(&mut src)?;

    // NOTE: Encryption handling (Standard RDP Security) is not implemented here.
    // When Enhanced RDP Security (TLS/CredSSP) is active, the payload is in the clear.
    // The flags field (FASTPATH_OUTPUT_ENCRYPTED) should not be set under TLS.

    // Parse the update array from remaining bytes.
    let mut outputs = Vec::new();
    while src.remaining() > 0 {
        let update = FastPathOutputUpdate::decode(&mut src)?;

        // Decompress if needed (per-update, not per-frame).
        // MS-RDPBCGR 2.2.9.1.2.1: compressionFlags present when compression field != 0.
        let decompressed_data = if let Some(compression_flags) = update.compression_flags {
            if compression_flags & PACKET_COMPRESSED != 0 {
                let mut decompressed = Vec::new();
                decompressor
                    .decompress(compression_flags, &update.update_data, &mut decompressed)
                    .map_err(|e| SessionError::Decompress(format!("{e:?}")))?;
                Some(decompressed)
            } else {
                None
            }
        } else {
            None
        };

        // Build the update with possibly decompressed data for reassembly.
        let effective_update = if let Some(ref data) = decompressed_data {
            FastPathOutputUpdate {
                update_code: update.update_code,
                fragmentation: update.fragmentation,
                compression: 0,
                compression_flags: None,
                update_data: data.clone(),
            }
        } else {
            update
        };

        // Run through fragment reassembly.
        if let Some(assembled) = complete_data.process_update(&effective_update) {
            dispatch_update(assembled, &mut outputs);
        }
    }

    Ok(outputs)
}

/// Dispatch a reassembled update to the appropriate output variant.
fn dispatch_update(update: AssembledUpdate, outputs: &mut Vec<ActiveStageOutput>) {
    match update.update_code {
        // Graphics updates -- caller interprets the raw data.
        FastPathUpdateType::Orders
        | FastPathUpdateType::Bitmap
        | FastPathUpdateType::Palette
        | FastPathUpdateType::Synchronize
        | FastPathUpdateType::SurfaceCommands => {
            outputs.push(ActiveStageOutput::GraphicsUpdate {
                update_code: update.update_code,
                data: update.data,
            });
        }

        // Pointer updates.
        FastPathUpdateType::PointerHidden => {
            outputs.push(ActiveStageOutput::PointerHidden);
        }
        FastPathUpdateType::PointerDefault => {
            outputs.push(ActiveStageOutput::PointerDefault);
        }
        FastPathUpdateType::PointerPosition => {
            // MS-RDPBCGR 2.2.9.1.2.1.7: xPos(u16 LE) + yPos(u16 LE) = 4 bytes
            if update.data.len() >= 4 {
                let x = u16::from_le_bytes([update.data[0], update.data[1]]);
                let y = u16::from_le_bytes([update.data[2], update.data[3]]);
                outputs.push(ActiveStageOutput::PointerPosition { x, y });
            }
        }
        FastPathUpdateType::PointerColor
        | FastPathUpdateType::PointerCached
        | FastPathUpdateType::PointerNew
        | FastPathUpdateType::PointerLarge => {
            outputs.push(ActiveStageOutput::PointerBitmap {
                pointer_type: update.update_code as u8,
                data: update.data,
            });
        }
    }
}

// ── Fast-Path Input Construction (client → server) ──

/// Encode a list of fast-path input events into a complete frame.
///
/// The frame is ready to send over the wire (no additional wrapping needed).
/// Encryption is NOT applied (assumes Enhanced RDP Security / TLS).
pub(crate) fn encode_fast_path_input(events: &[FastPathInputEvent]) -> SessionResult<Vec<u8>> {
    // First, encode all events into a scratch buffer to determine total size.
    let mut events_buf = Vec::new();
    for event in events {
        let size = event.size();
        let start = events_buf.len();
        events_buf.resize(start + size, 0);
        let mut cursor = WriteCursor::new(&mut events_buf[start..]);
        event.encode(&mut cursor)?;
    }

    if events.is_empty() || events.len() > 255 {
        return Err(SessionError::Protocol(
            alloc::string::String::from("fast-path input: event count must be 1..=255"),
        ));
    }
    let num_events = events.len() as u8;

    // Build the header.
    // Under TLS: no encryption flags, no dataSignature.
    let header = FastPathInputHeader {
        action: FASTPATH_INPUT_ACTION_FASTPATH,
        num_events,
        flags: 0, // no encryption under Enhanced RDP Security
        length: 0, // placeholder, filled below
    };

    // Calculate total frame size.
    let header_size = header.size();
    let total_length = header_size + events_buf.len();

    // Re-create header with correct length.
    let header = FastPathInputHeader {
        action: FASTPATH_INPUT_ACTION_FASTPATH,
        num_events,
        flags: 0,
        length: total_length as u16,
    };

    // Encode the complete frame.
    let mut frame = vec![0u8; total_length];
    let mut cursor = WriteCursor::new(&mut frame);
    header.encode(&mut cursor)?;
    cursor.write_slice(&events_buf, "FastPathInput::events")?;

    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::rdp::fast_path::{
        FastPathInputEvent, FastPathInputHeader, FastPathScancodeEvent, FastPathMouseEvent,
        Fragmentation,
    };

    #[test]
    fn encode_single_scancode_event() {
        let events = vec![FastPathInputEvent::Scancode(FastPathScancodeEvent {
            event_flags: 0,
            key_code: 0x1E, // 'A'
        })];
        let frame = encode_fast_path_input(&events).unwrap();

        // Expected: byte0 = (0x00) | (0x01 << 2) | (0x00 << 6) = 0x04
        // length = 4 (1 header + 1 length + 2 event bytes)
        assert_eq!(frame[0], 0x04); // action=0, numEvents=1, flags=0
        assert_eq!(frame[1], 0x04); // length=4 (single byte form)
        assert_eq!(frame[2], 0x00); // eventHeader: eventFlags=0, eventCode=Scancode=0
        assert_eq!(frame[3], 0x1E); // keyCode
    }

    #[test]
    fn encode_mouse_event() {
        let events = vec![FastPathInputEvent::Mouse(FastPathMouseEvent {
            event_flags: 0,
            pointer_flags: 0x0800, // PTRFLAGS_MOVE
            x_pos: 100,
            y_pos: 200,
        })];
        let frame = encode_fast_path_input(&events).unwrap();

        assert_eq!(frame[0], 0x04); // 1 event
        // Total length: 1 header + 1 length + 7 event = 9
        assert_eq!(frame[1], 9);
    }

    #[test]
    fn encode_multiple_events() {
        let events = vec![
            FastPathInputEvent::Scancode(FastPathScancodeEvent {
                event_flags: 0,
                key_code: 0x1E,
            }),
            FastPathInputEvent::Scancode(FastPathScancodeEvent {
                event_flags: 0x01, // RELEASE
                key_code: 0x1E,
            }),
        ];
        let frame = encode_fast_path_input(&events).unwrap();

        // numEvents = 2 in header bits 2-5
        assert_eq!(frame[0] & 0x3C, 0x02 << 2);
    }

    #[test]
    fn process_single_bitmap_update() {
        // Build a minimal fast-path output frame with a single bitmap update.
        let update_data = b"bitmap_payload";
        let update = FastPathOutputUpdate {
            update_code: FastPathUpdateType::Bitmap,
            fragmentation: Fragmentation::Single,
            compression: 0,
            compression_flags: None,
            update_data: update_data.to_vec(),
        };

        let header = FastPathOutputHeader {
            action: 0,
            num_events: 1,
            flags: 0,
            length: 0, // placeholder
        };

        // Encode into a frame.
        let total_size = header.size() + update.size();
        let header = FastPathOutputHeader {
            action: 0,
            num_events: 1,
            flags: 0,
            length: total_size as u16,
        };

        let mut frame = vec![0u8; total_size];
        let mut cursor = WriteCursor::new(&mut frame);
        header.encode(&mut cursor).unwrap();
        update.encode(&mut cursor).unwrap();

        let mut decompressor = BulkDecompressor::new();
        let mut complete_data = CompleteData::new();
        let outputs = process_fast_path_output(&frame, &mut decompressor, &mut complete_data).unwrap();

        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            ActiveStageOutput::GraphicsUpdate { update_code, data } => {
                assert_eq!(*update_code, FastPathUpdateType::Bitmap);
                assert_eq!(data.as_slice(), update_data);
            }
            _ => panic!("expected GraphicsUpdate"),
        }
    }

    #[test]
    fn process_pointer_position_update() {
        let mut pos_data = vec![0u8; 4];
        pos_data[0..2].copy_from_slice(&100u16.to_le_bytes());
        pos_data[2..4].copy_from_slice(&200u16.to_le_bytes());

        let update = FastPathOutputUpdate {
            update_code: FastPathUpdateType::PointerPosition,
            fragmentation: Fragmentation::Single,
            compression: 0,
            compression_flags: None,
            update_data: pos_data,
        };

        let header = FastPathOutputHeader {
            action: 0,
            num_events: 1,
            flags: 0,
            length: 0,
        };
        let total_size = header.size() + update.size();
        let header = FastPathOutputHeader {
            action: 0,
            num_events: 1,
            flags: 0,
            length: total_size as u16,
        };

        let mut frame = vec![0u8; total_size];
        let mut cursor = WriteCursor::new(&mut frame);
        header.encode(&mut cursor).unwrap();
        update.encode(&mut cursor).unwrap();

        let mut decompressor = BulkDecompressor::new();
        let mut complete_data = CompleteData::new();
        let outputs = process_fast_path_output(&frame, &mut decompressor, &mut complete_data).unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0], ActiveStageOutput::PointerPosition { x: 100, y: 200 });
    }

    #[test]
    fn process_pointer_hidden_and_default() {
        for (update_type, expected) in [
            (FastPathUpdateType::PointerHidden, ActiveStageOutput::PointerHidden),
            (FastPathUpdateType::PointerDefault, ActiveStageOutput::PointerDefault),
        ] {
            let update = FastPathOutputUpdate {
                update_code: update_type,
                fragmentation: Fragmentation::Single,
                compression: 0,
                compression_flags: None,
                update_data: vec![],
            };

            let header = FastPathOutputHeader {
                action: 0, num_events: 1, flags: 0, length: 0,
            };
            let total_size = header.size() + update.size();
            let header = FastPathOutputHeader {
                action: 0, num_events: 1, flags: 0,
                length: total_size as u16,
            };

            let mut frame = vec![0u8; total_size];
            let mut cursor = WriteCursor::new(&mut frame);
            header.encode(&mut cursor).unwrap();
            update.encode(&mut cursor).unwrap();

            let mut decompressor = BulkDecompressor::new();
            let mut complete_data = CompleteData::new();
            let outputs = process_fast_path_output(&frame, &mut decompressor, &mut complete_data).unwrap();

            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0], expected);
        }
    }

    #[test]
    fn encode_16_events_uses_extended_byte() {
        let events: Vec<_> = (0..16)
            .map(|i| {
                FastPathInputEvent::Scancode(FastPathScancodeEvent {
                    event_flags: 0,
                    key_code: i,
                })
            })
            .collect();
        let frame = encode_fast_path_input(&events).unwrap();
        // byte0 bits 2-5 must be 0 (signals extended numEvents byte)
        assert_eq!((frame[0] >> 2) & 0x0F, 0);
        // Decode and verify numEvents == 16
        let mut cursor = ReadCursor::new(&frame);
        let hdr = FastPathInputHeader::decode(&mut cursor).unwrap();
        assert_eq!(hdr.num_events, 16);
    }

    #[test]
    fn encode_256_events_returns_protocol_error() {
        let events: Vec<_> = (0u16..256)
            .map(|i| {
                FastPathInputEvent::Scancode(FastPathScancodeEvent {
                    event_flags: 0,
                    key_code: (i & 0xFF) as u8,
                })
            })
            .collect();
        let result = encode_fast_path_input(&events);
        assert!(matches!(result, Err(SessionError::Protocol(_))));
    }

    #[test]
    fn encode_zero_events_returns_error() {
        // Sending 0 events is meaningless and the resulting frame would have
        // numEvents=0 in the 4-bit field, which the decoder interprets as
        // "extended byte follows" — producing a malformed frame.
        let result = encode_fast_path_input(&[]);
        assert!(matches!(result, Err(SessionError::Protocol(_))));
    }

    #[test]
    fn pointer_position_truncated_data_produces_no_output() {
        let update = FastPathOutputUpdate {
            update_code: FastPathUpdateType::PointerPosition,
            fragmentation: Fragmentation::Single,
            compression: 0,
            compression_flags: None,
            update_data: vec![0x00, 0x00, 0x00], // 3 bytes, needs 4
        };

        let header = FastPathOutputHeader {
            action: 0, num_events: 1, flags: 0, length: 0,
        };
        let total_size = header.size() + update.size();
        let header = FastPathOutputHeader {
            action: 0, num_events: 1, flags: 0,
            length: total_size as u16,
        };

        let mut frame = vec![0u8; total_size];
        let mut cursor = WriteCursor::new(&mut frame);
        header.encode(&mut cursor).unwrap();
        update.encode(&mut cursor).unwrap();

        let mut decompressor = BulkDecompressor::new();
        let mut complete_data = CompleteData::new();
        let outputs =
            process_fast_path_output(&frame, &mut decompressor, &mut complete_data).unwrap();
        assert!(outputs.is_empty(), "truncated PointerPosition must be silently dropped");
    }
}
