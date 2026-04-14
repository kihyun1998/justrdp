//! Unit tests and derived test vectors for MS-RDPEMC PDUs.
//!
//! The spec (§4) provides only narrative examples, no hex dumps. All
//! vectors below were derived by hand from the wire formats in §2.2
//! and appear as TV-1..TV-11 in `specs/ms-rdpemc-checklist.md` §10.

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};

use crate::constants::{flags, odtype, participant_disconnect_reason};
use crate::pdu::{
    decode_all, DecodedPdu, EncomspPdu, OdAppCreated, OdAppRemoved, OdFilterStateUpdated,
    OdGraphicsStreamPaused, OdGraphicsStreamResumed, OdParticipantCreated,
    OdParticipantCtrlChange, OdParticipantCtrlChangeResponse, OdParticipantRemoved, OdWndCreated,
    OdWndRegionUpdate, OdWndRemoved, OdWndShow, UnicodeString,
};

// ── Helpers ───────────────────────────────────────────────────────────

fn encode_one<T: Encode>(pdu: &T) -> Vec<u8> {
    let mut buf = vec![0u8; pdu.size()];
    {
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).expect("encode");
    }
    buf
}

fn decode_one<'a, T: Decode<'a>>(bytes: &'a [u8]) -> T {
    let mut cursor = ReadCursor::new(bytes);
    T::decode(&mut cursor).expect("decode")
}

// ── TV-1: OD_GRAPHICS_STREAM_PAUSED ───────────────────────────────────

#[test]
fn tv1_graphics_stream_paused_decode_matches_hex() {
    let bytes = [0x0A, 0x00, 0x04, 0x00];
    let pdu: OdGraphicsStreamPaused = decode_one(&bytes);
    assert_eq!(pdu, OdGraphicsStreamPaused);
    assert_eq!(encode_one(&pdu), bytes);
}

// ── TV-2: OD_GRAPHICS_STREAM_RESUMED ──────────────────────────────────

#[test]
fn tv2_graphics_stream_resumed_decode_matches_hex() {
    let bytes = [0x0B, 0x00, 0x04, 0x00];
    let pdu: OdGraphicsStreamResumed = decode_one(&bytes);
    assert_eq!(pdu, OdGraphicsStreamResumed);
    assert_eq!(encode_one(&pdu), bytes);
}

// ── TV-3: OD_FILTER_STATE_UPDATED (enabled) ───────────────────────────

#[test]
fn tv3_filter_state_updated_enabled() {
    let bytes = [0x01, 0x00, 0x05, 0x00, flags::FILTER_ENABLED];
    let pdu: OdFilterStateUpdated = decode_one(&bytes);
    assert_eq!(pdu.flags, flags::FILTER_ENABLED);
    assert_eq!(encode_one(&pdu), bytes);
}

// ── TV-4: OD_APP_REMOVED ──────────────────────────────────────────────

#[test]
fn tv4_app_removed_decode() {
    let bytes = [0x02, 0x00, 0x08, 0x00, 0x34, 0x12, 0x00, 0x00];
    let pdu: OdAppRemoved = decode_one(&bytes);
    assert_eq!(pdu.app_id, 0x0000_1234);
    assert_eq!(encode_one(&pdu), bytes);
}

// ── TV-5: OD_WND_REMOVED ──────────────────────────────────────────────

#[test]
fn tv5_wnd_removed_decode() {
    let bytes = [0x04, 0x00, 0x08, 0x00, 0xCD, 0xAB, 0x00, 0x00];
    let pdu: OdWndRemoved = decode_one(&bytes);
    assert_eq!(pdu.wnd_id, 0x0000_ABCD);
    assert_eq!(encode_one(&pdu), bytes);
}

// ── TV-6: OD_WND_SHOW ─────────────────────────────────────────────────

#[test]
fn tv6_wnd_show_decode() {
    let bytes = [0x06, 0x00, 0x08, 0x00, 0x78, 0x56, 0x00, 0x00];
    let pdu: OdWndShow = decode_one(&bytes);
    assert_eq!(pdu.wnd_id, 0x0000_5678);
    assert_eq!(encode_one(&pdu), bytes);
}

// ── TV-7: OD_PARTICIPANT_CTRL_CHANGE (REQUEST_INTERACT, pid=1) ───────

#[test]
fn tv7_participant_ctrl_change_decode() {
    let bytes = [
        0x09, 0x00, 0x0A, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    let pdu: OdParticipantCtrlChange = decode_one(&bytes);
    assert_eq!(pdu.flags, flags::REQUEST_INTERACT);
    assert_eq!(pdu.participant_id, 1);
    assert_eq!(encode_one(&pdu), bytes);
}

// ── TV-8: OD_APP_CREATED (AppId=42, name="app", SHARED) ──────────────

#[test]
fn tv8_app_created_with_name() {
    // "app" in UTF-16LE: 61 00 70 00 70 00
    let bytes = [
        0x03, 0x00, 0x12, 0x00, // hdr: type=APP_CREATED, length=18
        0x01, 0x00, // Flags=APPLICATION_SHARED
        0x2A, 0x00, 0x00, 0x00, // AppId=42
        0x03, 0x00, // cchString=3
        0x61, 0x00, 0x70, 0x00, 0x70, 0x00, // "app"
    ];
    let pdu: OdAppCreated = decode_one(&bytes);
    assert_eq!(pdu.flags, flags::APPLICATION_SHARED);
    assert_eq!(pdu.app_id, 42);
    assert_eq!(pdu.name.raw_utf16, vec![0x0061, 0x0070, 0x0070]);
    assert_eq!(encode_one(&pdu), bytes);
}

// ── TV-9: OD_PARTICIPANT_REMOVED (pid=1, APP, S_OK) ──────────────────

#[test]
fn tv9_participant_removed_decode() {
    let bytes = [
        0x07, 0x00, 0x10, 0x00, // hdr: type=PARTICIPANT_REMOVED, length=16
        0x01, 0x00, 0x00, 0x00, // participant_id=1
        0x00, 0x00, 0x00, 0x00, // disc_type=APP
        0x00, 0x00, 0x00, 0x00, // disc_code=S_OK
    ];
    let pdu: OdParticipantRemoved = decode_one(&bytes);
    assert_eq!(pdu.participant_id, 1);
    assert_eq!(pdu.disc_type, participant_disconnect_reason::APP);
    assert_eq!(pdu.disc_code, 0);
    assert_eq!(encode_one(&pdu), bytes);
}

// ── TV-10: Concatenated PAUSED + APP_REMOVED ─────────────────────────

#[test]
fn tv10_concatenated_decode_all() {
    let bytes = [
        0x0A, 0x00, 0x04, 0x00, // PAUSED
        0x02, 0x00, 0x08, 0x00, 0x34, 0x12, 0x00, 0x00, // APP_REMOVED 0x1234
    ];
    let mut cursor = ReadCursor::new(&bytes);
    let out = decode_all(&mut cursor).expect("decode_all");
    assert_eq!(out.len(), 2);
    match &out[0] {
        DecodedPdu::Known(EncomspPdu::GraphicsStreamPaused(_)) => {}
        other => panic!("unexpected first pdu: {other:?}"),
    }
    match &out[1] {
        DecodedPdu::Known(EncomspPdu::AppRemoved(r)) => assert_eq!(r.app_id, 0x0000_1234),
        other => panic!("unexpected second pdu: {other:?}"),
    }
    assert!(cursor.peek_remaining().is_empty());
}

// ── TV-11: Unknown Type forward-compat skip ──────────────────────────

#[test]
fn tv11_unknown_type_forward_compat_skip() {
    let bytes = [0xFF, 0x00, 0x06, 0x00, 0xAA, 0xBB];
    let mut cursor = ReadCursor::new(&bytes);
    let out = decode_all(&mut cursor).expect("decode_all");
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0],
        DecodedPdu::Skipped {
            type_: 0x00FF,
            length: 6,
        }
    );
    assert!(cursor.peek_remaining().is_empty());
}

// ── Roundtrip: OD_WND_CREATED with title ─────────────────────────────

#[test]
fn wnd_created_roundtrip_with_title() {
    let pdu = OdWndCreated {
        flags: flags::WINDOW_SHARED,
        app_id: 42,
        wnd_id: 0xDEAD_BEEF,
        name: UnicodeString::from_utf16(vec![b'H' as u16, b'i' as u16]).unwrap(),
    };
    let bytes = encode_one(&pdu);
    // fixed(14) + name(2 + 4) = 20
    assert_eq!(bytes.len(), 20);
    // header: type=0x0005, length=20
    assert_eq!(&bytes[..4], &[0x05, 0x00, 0x14, 0x00]);
    let back: OdWndCreated = decode_one(&bytes);
    assert_eq!(back, pdu);
}

// ── Roundtrip: OD_PARTICIPANT_CREATED with IS_PARTICIPANT ────────────

#[test]
fn participant_created_self_identity_roundtrip() {
    let pdu = OdParticipantCreated {
        participant_id: 7,
        group_id: 0, // Windows always 0 (Appendix A <6>)
        flags: flags::MAY_VIEW | flags::MAY_INTERACT | flags::IS_PARTICIPANT,
        friendly_name: UnicodeString::empty(),
    };
    let bytes = encode_one(&pdu);
    assert_eq!(bytes.len(), 18); // fixed 16 + cchString 2 + 0
    let back: OdParticipantCreated = decode_one(&bytes);
    assert_eq!(back, pdu);
    assert_eq!(back.flags & flags::IS_PARTICIPANT, flags::IS_PARTICIPANT);
}

// ── Roundtrip: OD_PARTICIPANT_CTRL_CHANGE_RESPONSE ───────────────────

#[test]
fn participant_ctrl_change_response_roundtrip() {
    let pdu = OdParticipantCtrlChangeResponse {
        flags: flags::REQUEST_VIEW | flags::REQUEST_INTERACT,
        participant_id: 5,
        reason_code: 0, // S_OK
    };
    let bytes = encode_one(&pdu);
    assert_eq!(bytes.len(), 14);
    assert_eq!(bytes[0], 0x0D); // type LSB = 0x000D
    let back: OdParticipantCtrlChangeResponse = decode_one(&bytes);
    assert_eq!(back, pdu);
}

// ── Roundtrip: OD_WND_REGION_UPDATE (Windows never sends this) ───────

#[test]
fn wnd_region_update_roundtrip() {
    let pdu = OdWndRegionUpdate {
        left: 10,
        top: 20,
        right: 1000,
        bottom: 2000,
    };
    let bytes = encode_one(&pdu);
    assert_eq!(bytes.len(), 20);
    assert_eq!(bytes[0], 0x0C);
    let back: OdWndRegionUpdate = decode_one(&bytes);
    assert_eq!(back, pdu);
}

// ── Edge: empty UnicodeString in APP_CREATED (Appendix A <10>) ───────

#[test]
fn app_created_with_empty_name_is_valid() {
    let pdu = OdAppCreated {
        flags: 0,
        app_id: 1,
        name: UnicodeString::empty(),
    };
    let bytes = encode_one(&pdu);
    assert_eq!(bytes.len(), 12); // fixed 10 + cchString 2 + 0
    // header.length = 12
    assert_eq!(bytes[2], 12);
    assert_eq!(bytes[3], 0);
    let back: OdAppCreated = decode_one(&bytes);
    assert_eq!(back, pdu);
}

// ── Edge: UnicodeString cchString over cap rejected ──────────────────

#[test]
fn unicode_string_cap_enforced_on_construction() {
    let too_long: Vec<u16> = vec![0; 1025];
    assert!(UnicodeString::from_utf16(too_long).is_none());
}

#[test]
fn unicode_string_cap_enforced_on_decode() {
    // Forge a UNICODE_STRING with cchString = 1025 → should fail to decode.
    let mut bytes = vec![0u8; 2 + 1025 * 2];
    bytes[0] = 0x01;
    bytes[1] = 0x04; // 0x0401 = 1025, LE
    let mut cursor = ReadCursor::new(&bytes);
    let err = UnicodeString::decode(&mut cursor);
    assert!(err.is_err());
}

// ── Edge: APP_CREATED with length shorter than fixed portion ─────────

#[test]
fn app_created_rejects_undersized_length() {
    // header.length = 9 (below 10 fixed bytes) → decode should fail.
    let bytes = [
        0x03, 0x00, 0x09, 0x00, // hdr: APP_CREATED, length=9 (invalid)
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut cursor = ReadCursor::new(&bytes);
    assert!(OdAppCreated::decode(&mut cursor).is_err());
}

// ── Edge: decode_all rejects header.length < 4 ───────────────────────

#[test]
fn decode_all_rejects_length_under_four() {
    let bytes = [0x0A, 0x00, 0x03, 0x00];
    let mut cursor = ReadCursor::new(&bytes);
    assert!(decode_all(&mut cursor).is_err());
}

// ── Edge: decode_all rejects length overflow beyond buffer ───────────

#[test]
fn decode_all_rejects_oversized_length() {
    // Claims length=100 but only 4 bytes present.
    let bytes = [0x0A, 0x00, 0x64, 0x00];
    let mut cursor = ReadCursor::new(&bytes);
    assert!(decode_all(&mut cursor).is_err());
}

// ── Edge: decode_all with truncated header ───────────────────────────

#[test]
fn decode_all_rejects_truncated_header() {
    let bytes = [0x0A, 0x00, 0x04]; // 3 bytes only
    let mut cursor = ReadCursor::new(&bytes);
    assert!(decode_all(&mut cursor).is_err());
}

// ── Edge: mixed known + unknown + known in one call ──────────────────

#[test]
fn decode_all_handles_mixed_known_unknown_known() {
    let bytes = [
        0x0A, 0x00, 0x04, 0x00, // PAUSED
        0xFF, 0x00, 0x06, 0x00, 0x11, 0x22, // unknown, skipped
        0x0B, 0x00, 0x04, 0x00, // RESUMED
    ];
    let mut cursor = ReadCursor::new(&bytes);
    let out = decode_all(&mut cursor).expect("decode_all");
    assert_eq!(out.len(), 3);
    assert!(matches!(
        out[0],
        DecodedPdu::Known(EncomspPdu::GraphicsStreamPaused(_))
    ));
    assert_eq!(
        out[1],
        DecodedPdu::Skipped {
            type_: 0x00FF,
            length: 6,
        }
    );
    assert!(matches!(
        out[2],
        DecodedPdu::Known(EncomspPdu::GraphicsStreamResumed(_))
    ));
}

// ── EncomspPdu enum dispatch roundtrip ───────────────────────────────

#[test]
fn encomsp_pdu_enum_encode_dispatch_matches_inner() {
    let inner = OdWndShow { wnd_id: 0xBABE };
    let outer = EncomspPdu::WndShow(inner);
    let mut a = vec![0u8; outer.size()];
    let mut b = vec![0u8; inner.size()];
    outer.encode(&mut WriteCursor::new(&mut a)).unwrap();
    inner.encode(&mut WriteCursor::new(&mut b)).unwrap();
    assert_eq!(a, b);
}

// ── odtype / flag constants sanity ───────────────────────────────────

#[test]
fn odtype_values_match_spec() {
    // MS-RDPEMC §2.2.1
    assert_eq!(odtype::FILTER_STATE_UPDATED, 0x0001);
    assert_eq!(odtype::APP_REMOVED, 0x0002);
    assert_eq!(odtype::APP_CREATED, 0x0003);
    assert_eq!(odtype::WND_REMOVED, 0x0004);
    assert_eq!(odtype::WND_CREATED, 0x0005);
    assert_eq!(odtype::WND_SHOW, 0x0006);
    assert_eq!(odtype::PARTICIPANT_REMOVED, 0x0007);
    assert_eq!(odtype::PARTICIPANT_CREATED, 0x0008);
    assert_eq!(odtype::PARTICIPANT_CTRL_CHANGED, 0x0009);
    assert_eq!(odtype::GRAPHICS_STREAM_PAUSED, 0x000A);
    assert_eq!(odtype::GRAPHICS_STREAM_RESUMED, 0x000B);
    assert_eq!(odtype::WND_RGN_UPDATE, 0x000C);
    assert_eq!(odtype::PARTICIPANT_CTRL_CHANGE_RESPONSE, 0x000D);
}
