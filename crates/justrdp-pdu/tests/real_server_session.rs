//! What a real server sends **after** session-active, asserted against the shipped parsers.
//!
//! The sibling `real_server_connect.rs` reads bytes from before the Font Map, which
//! `justrdp-tokio`'s `JUSTRDP_CONNECT_CAPTURE_FILE` hook records on its own. This file exists
//! because that hook stops at `Action::SessionActive`: a session-leg PDU had nowhere in the repo
//! to be recorded from, so until #304 nothing here could be captured at all.
//!
//! Same standing as its sibling. A capture proves **acceptance** — that nothing this server
//! sends is rejected — which is the half of an owned basis a corpus can supply alone
//! (`docs/map/territory/verification-harness.md`). It cannot prove the decoder rejects what it
//! should; that is the unit tests', and every guard in `session_info.rs` was mutation-tested
//! there because a conforming server never exercises one.

use justrdp_pdu::{cursor::ReadCursor, mcs, session_info, share, tpkt, x224};

const SAVE_SESSION_INFO: &[u8] = include_bytes!("fixtures/session/save-session-info.bin");

/// Walk a capture of whole TPKT frames, decoding each one's Share Data body as a Save Session
/// Info. Returns them in arrival order.
fn decode_all(mut rest: &[u8]) -> Vec<session_info::SaveSessionInfo> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        let frame_len = tpkt::frame_len(rest).expect("a complete TPKT frame");
        let (frame, tail) = rest.split_at(frame_len);
        rest = tail;

        let x224 = x224::decode_data(&frame[tpkt::HEADER_LEN..]).expect("an X.224 data TPDU");
        let indication = mcs::SendDataIndication::decode(x224).expect("an MCS data indication");
        let mut cur = ReadCursor::new(indication.user_data, "fixture");
        let control = share::ShareControlHeader::decode(&mut cur).expect("a share control header");
        assert_eq!(control.pdu_type, share::PDU_TYPE_DATA);
        let data = share::ShareDataHeader::decode(&mut cur).expect("a share data header");
        assert_eq!(
            data.pdu_type2,
            share::PDU_TYPE2_SAVE_SESSION_INFO,
            "the capture was carved on this byte; a frame without it means the wrong bytes shipped"
        );
        out.push(session_info::SaveSessionInfo::decode(&mut cur).expect("a real 0x26 body"));
        // Against real bytes, the pads are the assertion. A hand-built body's 570 and 558 zero
        // bytes are zeros the test author chose; these are the server's, and a decoder that
        // mis-sized either one leaves the cursor somewhere other than the end.
        //
        // Worth stating what this measures and does not: FreeRDP records Windows 11 appending
        // undocumented padding after a Logon Info V2's strings, so full consumption is a fact
        // about *this* server rather than an invariant of the PDU — which is why
        // `SaveSessionInfo::decode` does not enforce it and this test does.
        assert_eq!(
            cur.remaining(),
            0,
            "this server's PDU is consumed exactly; a short read here is a mis-sized pad"
        );
    }
    out
}

/// Issue #304. Two Save Session Info PDUs from one logon, captured 2026-09-21.
///
/// **The count is the load-bearing part.** `ActivationResult::save_session_info` is a `Vec` and
/// not an `Option`, and this is the evidence: an `Option` keeps one of these two and drops the
/// other, which is the defect #304 exists to end rather than relocate. It was reasoned from
/// 3.2.5.10.1 phrasing the logon notification and the cookie as separate cases; this capture is
/// the measurement that reasoning was waiting for.
///
/// **Two is this capture's count, not every logon's.** A later logon against the same VM sent
/// the `LogonLong` alone, so the arity is a range — which is a stronger argument for the `Vec`
/// than a fixed two would have been, and is why the live test beside this one asserts the
/// *shape* of what arrives rather than how much. Here the bytes are fixed, so the count is
/// asserted.
#[test]
fn a_real_servers_logon_notifications_decode_in_order() {
    let infos = decode_all(SAVE_SESSION_INFO);
    assert_eq!(infos.len(), 2, "one logon, two PDUs");

    let session_info::SaveSessionInfo::Extended(ext) = &infos[0] else {
        panic!("expected Logon Info Extended first, got {:?}", infos[0]);
    };
    assert_eq!(
        ext.fields_present,
        session_info::LOGON_EX_LOGONERRORS,
        "this server sends logon errors and no cookie"
    );
    assert!(
        ext.auto_reconnect.is_none(),
        "and so the ARC_SC branch has no server here — see the fixture README"
    );
    let err = ext.logon_error.expect("LOGON_ERRORS was set");
    assert_eq!(
        err.notification_type,
        session_info::LogonErrorNotification::SessionContinue
    );
    assert!(
        err.notification_type.data_is_session_id(),
        "every LOGON_MSG_* type carries a session ID in its data field (2.2.10.1.1.4.1.1)"
    );

    let session_info::SaveSessionInfo::LogonLong(logon) = &infos[1] else {
        panic!("expected Logon Info V2 second, got {:?}", infos[1]);
    };
    assert_eq!(
        logon.user, "rdptest",
        "the account the capture logged on with"
    );
    assert_eq!(logon.domain, "WIN-R21QJTDL2C2", "this VM's machine name");

    // `errorNotificationData` is the **session ID**, not an error code. Three logons, three
    // pairs: 2/2, 3/3 and 6/6 — it tracks the session. IronRDP maps 0..=3 to an error-code enum
    // and so reads the first two as `FailedOther` / `Warning`; justrdp carries the raw u32, and
    // this assertion is why. Asserting the *tie* rather than the literal is deliberate: the
    // value changes every logon, so a literal would pin the capture instead of the rule.
    assert_eq!(
        err.notification_data, logon.session_id,
        "the notification data tracks the session, so it is an ID and not a code"
    );
}

/// The two declared lengths this decoder deliberately does not frame from, pinned to the values
/// a real server puts in them — because in both cases the spec says something else.
///
/// `Size`: 2.2.10.1.1.2 defines it as the structure excluding `Domain` and `UserName`, which is
/// **576**. This WS2022 sends **18**, the same as the Windows Server 2019 behaviour FreeRDP
/// records. IronRDP accepts only 18 and would reject a spec-conformant server; justrdp accepts
/// both and reads neither.
///
/// `Length`: 2.2.10.1.1.4 calls it *"the total size in bytes of this structure, including the
/// variable LogonFields field"* — and this structure ends with a 570-byte pad. This server sends
/// **18**, the fields *without* the pad. A decoder that framed from `Length` under the spec's
/// own sentence would mis-parse this conforming server.
#[test]
fn the_declared_lengths_this_server_sends_are_not_the_ones_the_spec_defines() {
    // Both live at a fixed offset from the start of their PDU's body, so read them raw rather
    // than through the decoder that is being justified.
    let ext_len = tpkt::frame_len(SAVE_SESSION_INFO).expect("frame 1");
    let (frame1, frame2) = SAVE_SESSION_INFO.split_at(ext_len);

    let body = |frame: &[u8]| -> Vec<u8> {
        let x224 = x224::decode_data(&frame[tpkt::HEADER_LEN..]).expect("an X.224 data TPDU");
        let indication = mcs::SendDataIndication::decode(x224).expect("an MCS data indication");
        let mut cur = ReadCursor::new(indication.user_data, "fixture");
        share::ShareControlHeader::decode(&mut cur).expect("control header");
        share::ShareDataHeader::decode(&mut cur).expect("data header");
        indication.user_data[cur.position()..].to_vec()
    };

    let extended = body(frame1);
    assert_eq!(
        u32::from_le_bytes(extended[0..4].try_into().unwrap()),
        session_info::INFOTYPE_LOGON_EXTENDED_INFO
    );
    assert_eq!(
        u16::from_le_bytes(extended[4..6].try_into().unwrap()),
        18,
        "Length excludes the 570-byte pad here, which 2.2.10.1.1.4's wording does not"
    );

    let long = body(frame2);
    assert_eq!(
        u32::from_le_bytes(long[0..4].try_into().unwrap()),
        session_info::INFOTYPE_LOGON_LONG
    );
    assert_eq!(
        u32::from_le_bytes(long[6..10].try_into().unwrap()),
        18,
        "Size is 18, where 2.2.10.1.1.2 defines it as 576"
    );
}

/// Every truncation of the capture is a typed error, never a panic
/// (`docs/map/invariant/untrusted-decode-never-panics.md`). Real bytes rather than hand-built
/// ones, because the pads a hand-built body carries are zeros the author chose.
#[test]
fn truncating_the_capture_never_panics() {
    let frame_len = tpkt::frame_len(SAVE_SESSION_INFO).expect("frame 1");
    for frame in [
        &SAVE_SESSION_INFO[..frame_len],
        &SAVE_SESSION_INFO[frame_len..],
    ] {
        let x224 = x224::decode_data(&frame[tpkt::HEADER_LEN..]).expect("an X.224 data TPDU");
        let indication = mcs::SendDataIndication::decode(x224).expect("an MCS data indication");
        let mut cur = ReadCursor::new(indication.user_data, "fixture");
        share::ShareControlHeader::decode(&mut cur).expect("control header");
        share::ShareDataHeader::decode(&mut cur).expect("data header");
        let body = &indication.user_data[cur.position()..];
        for len in 0..body.len() {
            let mut cur = ReadCursor::new(&body[..len], "truncated");
            let _ = session_info::SaveSessionInfo::decode(&mut cur);
        }
    }
}
