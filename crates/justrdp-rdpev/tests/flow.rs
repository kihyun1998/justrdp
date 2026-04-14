//! Full MS-RDPEV (TSMF) client flow integration tests.
//!
//! Drives the [`RdpevClient`] through hand-forged "server" PDUs and
//! asserts on the bytes the processor emits in response. Because there
//! is no conformant TSMF server in the test environment, every
//! server-originated PDU is built with the crate's own encoder and
//! handed to `process()` exactly as DRDYNVC would after reassembling a
//! channel message.
//!
//! These tests live in the `tests/` directory so they exercise the
//! crate through its public API only -- they would fail to compile if
//! a public re-export went missing.

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::{DvcError, DvcProcessor};

use justrdp_rdpev::{
    capability_type, function_id, platform_cookie, AddStream, CheckFormatResult,
    CheckFormatSupportReq, CheckFormatSupportRsp, ExchangeCapabilitiesReq,
    ExchangeCapabilitiesRsp, Guid, MockTsmfMediaSink, NotifyPreroll, OnEndOfStream, OnFlush,
    OnNewPresentation, OnPlaybackPaused, OnPlaybackStarted, OnPlaybackStopped, OnSample,
    PlaybackAck, RdpevClient, RemoveStream, SetChannelParams, SetTopologyReq, SetTopologyRsp,
    ShutdownPresentationReq, ShutdownPresentationRsp, TsAmMediaType, TsMmDataSample,
    TsmmCapabilities, CHANNEL_NAME,
};

const CHAN_ID: u32 = 1;

const PRES_A: Guid = Guid([
    0x9f, 0x04, 0x86, 0xe0, 0x26, 0xd9, 0xae, 0x45, 0x8c, 0x0f, 0x3e, 0x05, 0x6a, 0xf3, 0xf7, 0xd4,
]);

const PRES_B: Guid = Guid([
    0x79, 0x40, 0x84, 0x8b, 0x0e, 0xb7, 0x0f, 0x45, 0x87, 0x93, 0x3d, 0x7f, 0xfa, 0x31, 0xd0, 0x53,
]);

// ── helpers ─────────────────────────────────────────────────────────

/// Encode a PDU into the flat byte layout DRDYNVC would hand to
/// `DvcProcessor::process`.
fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).expect("encode");
    assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
    buf
}

fn decode<'a, T: Decode<'a>>(bytes: &'a [u8]) -> T {
    let mut cur = ReadCursor::new(bytes);
    T::decode(&mut cur).expect("decode")
}

fn dummy_media_type() -> TsAmMediaType {
    TsAmMediaType {
        major_type: Guid([0x11; 16]),
        sub_type: Guid([0x22; 16]),
        b_fixed_size_samples: 0,
        b_temporal_compression: 1,
        sample_size: 0,
        format_type: Guid([0x33; 16]),
        pb_format: Vec::new(),
    }
}

fn dummy_sample(throttle: u64, p_data: Vec<u8>) -> TsMmDataSample {
    TsMmDataSample {
        sample_start_time: 0,
        sample_end_time: 100,
        throttle_duration: throttle,
        sample_flags: 0,
        sample_extensions: 0,
        p_data,
    }
}

/// Drives a single server→client PDU through the processor and
/// returns the response payloads (possibly empty for fire-and-forget).
fn run<T: Encode>(c: &mut RdpevClient, pdu: &T) -> Vec<Vec<u8>> {
    let bytes = encode(pdu);
    let out = c.process(CHAN_ID, &bytes).expect("process");
    out.into_iter().map(|m| m.data).collect()
}

fn fresh_client_with_caps(client_caps: Vec<TsmmCapabilities>) -> RdpevClient {
    let sink = Box::new(MockTsmfMediaSink::new().with_client_capabilities(client_caps));
    let mut c = RdpevClient::new(sink);
    assert!(c.start(CHAN_ID).expect("start").is_empty());
    c
}

// ── 1. Full happy path ─────────────────────────────────────────────

/// End-to-end: SET_CHANNEL_PARAMS → EXCHANGE_CAPABILITIES → ON_NEW_PRESENTATION
/// → CHECK_FORMAT_SUPPORT → ADD_STREAM → SET_TOPOLOGY → ON_SAMPLE (with
/// PlaybackAck) → control PDUs → REMOVE_STREAM → SHUTDOWN_PRESENTATION
/// → close. Verifies wire-level field echoes at every step.
#[test]
fn full_v2_happy_path() {
    let client_caps = vec![
        TsmmCapabilities::u32_payload(capability_type::VERSION, 2),
        TsmmCapabilities::u32_payload(capability_type::PLATFORM, 0x03),
    ];
    let mut c = fresh_client_with_caps(client_caps.clone());
    assert_eq!(c.channel_name(), CHANNEL_NAME);

    // 1. SET_CHANNEL_PARAMS — fire-and-forget.
    let bind = SetChannelParams {
        message_id: 0,
        presentation_id: PRES_A,
        stream_id: 0,
    };
    assert!(run(&mut c, &bind).is_empty());
    assert_eq!(c.bound_presentation(), Some(PRES_A));

    // 2. EXCHANGE_CAPABILITIES_REQ → RSP must echo MessageId.
    let server_caps = vec![TsmmCapabilities::u32_payload(capability_type::VERSION, 2)];
    let req = ExchangeCapabilitiesReq::new(0xCAFE, server_caps);
    let mut out = run(&mut c, &req);
    assert_eq!(out.len(), 1);
    let rsp: ExchangeCapabilitiesRsp = decode(&out.remove(0));
    assert_eq!(rsp.message_id, 0xCAFE);
    assert_eq!(rsp.capabilities, client_caps);

    // 3. ON_NEW_PRESENTATION — fire-and-forget; presentation count = 1.
    let new_pres = OnNewPresentation {
        message_id: 0,
        presentation_id: PRES_A,
        platform_cookie: platform_cookie::DSHOW,
    };
    assert!(run(&mut c, &new_pres).is_empty());
    assert_eq!(c.presentation_count(), 1);

    // 4. CHECK_FORMAT_SUPPORT_REQ — RSP echoes MessageId.
    let chk = CheckFormatSupportReq {
        message_id: 0xBEEF,
        platform_cookie: platform_cookie::DSHOW,
        no_rollover_flags: 0,
        media_type: dummy_media_type(),
    };
    let mut out = run(&mut c, &chk);
    assert_eq!(out.len(), 1);
    let rsp: CheckFormatSupportRsp = decode(&out.remove(0));
    assert_eq!(rsp.message_id, 0xBEEF);
    assert_eq!(rsp.format_supported, 1);

    // 5. ADD_STREAM (×2)
    for sid in [0u32, 1u32] {
        let add = AddStream {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: sid,
            media_type: dummy_media_type(),
        };
        assert!(run(&mut c, &add).is_empty());
    }

    // 6. SET_TOPOLOGY_REQ → RSP { topology_ready=1 }
    let topo = SetTopologyReq {
        message_id: 0xAAAA,
        presentation_id: PRES_A,
    };
    let mut out = run(&mut c, &topo);
    assert_eq!(out.len(), 1);
    let rsp: SetTopologyRsp = decode(&out.remove(0));
    assert_eq!(rsp.message_id, 0xAAAA);
    assert_eq!(rsp.topology_ready, 1);

    // 7. ON_SAMPLE → exactly one PlaybackAck per sample.
    for (i, throttle) in [(0u8, 100u64), (1, 200), (2, 300)].iter().copied() {
        let sample = OnSample {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: 0,
            sample: dummy_sample(throttle, vec![i, i, i, i]),
        };
        let mut out = run(&mut c, &sample);
        assert_eq!(out.len(), 1, "1:1 ack rule violated for sample {i}");
        let ack: PlaybackAck = decode(&out.remove(0));
        assert_eq!(ack.stream_id, 0);
        assert_eq!(ack.data_duration, throttle);
        assert_eq!(ack.cb_data, 4);
    }

    // 8. Playback control quartet — all fire-and-forget.
    for pdu_bytes in [
        encode(&OnPlaybackStarted {
            message_id: 0,
            presentation_id: PRES_A,
            playback_start_offset: 0,
            is_seek: 0,
        }),
        encode(&OnPlaybackPaused {
            message_id: 0,
            presentation_id: PRES_A,
        }),
        encode(&OnPlaybackStopped {
            message_id: 0,
            presentation_id: PRES_A,
        }),
        encode(&OnFlush {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: 0,
        }),
        encode(&OnEndOfStream {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: 0,
        }),
        encode(&NotifyPreroll {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: 0,
        }),
    ] {
        assert!(c.process(CHAN_ID, &pdu_bytes).expect("control").is_empty());
    }

    // 9. REMOVE_STREAM (×2) — fire-and-forget.
    for sid in [0u32, 1u32] {
        let rm = RemoveStream {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: sid,
        };
        assert!(run(&mut c, &rm).is_empty());
    }

    // 10. SHUTDOWN_PRESENTATION_REQ → RSP { S_OK }, presentation removed.
    let sd = ShutdownPresentationReq {
        message_id: 0xDEAD,
        presentation_id: PRES_A,
    };
    let mut out = run(&mut c, &sd);
    assert_eq!(out.len(), 1);
    let rsp: ShutdownPresentationRsp = decode(&out.remove(0));
    assert_eq!(rsp.message_id, 0xDEAD);
    assert_eq!(rsp.result, 0); // S_OK
    assert_eq!(c.presentation_count(), 0);

    // 11. close() clears state and rejects further process().
    c.close(CHAN_ID);
    assert!(matches!(
        c.process(CHAN_ID, &encode(&bind)),
        Err(DvcError::Protocol(_))
    ));
}

// ── 2. Multi-presentation concurrency ──────────────────────────────

/// Two concurrent presentations on the same channel must keep
/// independent stream maps and respond to per-presentation messages
/// without crosstalk.
#[test]
fn two_concurrent_presentations_isolate_their_streams() {
    let mut c = fresh_client_with_caps(vec![]);
    run(
        &mut c,
        &SetChannelParams {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: 0,
        },
    );

    // Create both presentations.
    for &g in &[PRES_A, PRES_B] {
        run(
            &mut c,
            &OnNewPresentation {
                message_id: 0,
                presentation_id: g,
                platform_cookie: platform_cookie::MF,
            },
        );
    }
    assert_eq!(c.presentation_count(), 2);

    // Add stream 0 to A and stream 5 to B.
    run(
        &mut c,
        &AddStream {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: 0,
            media_type: dummy_media_type(),
        },
    );
    run(
        &mut c,
        &AddStream {
            message_id: 0,
            presentation_id: PRES_B,
            stream_id: 5,
            media_type: dummy_media_type(),
        },
    );

    // Sample for A — ack carries stream_id 0.
    let mut out = run(
        &mut c,
        &OnSample {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: 0,
            sample: dummy_sample(11, vec![1, 2, 3]),
        },
    );
    let ack_a: PlaybackAck = decode(&out.remove(0));
    assert_eq!(ack_a.stream_id, 0);
    assert_eq!(ack_a.data_duration, 11);

    // Sample for B — ack carries stream_id 5.
    let mut out = run(
        &mut c,
        &OnSample {
            message_id: 0,
            presentation_id: PRES_B,
            stream_id: 5,
            sample: dummy_sample(22, vec![4, 5, 6, 7]),
        },
    );
    let ack_b: PlaybackAck = decode(&out.remove(0));
    assert_eq!(ack_b.stream_id, 5);
    assert_eq!(ack_b.data_duration, 22);

    // Shutdown A only — B must still be tracked.
    run(
        &mut c,
        &ShutdownPresentationReq {
            message_id: 0,
            presentation_id: PRES_A,
        },
    );
    assert_eq!(c.presentation_count(), 1);

    // Shutdown B.
    run(
        &mut c,
        &ShutdownPresentationReq {
            message_id: 0,
            presentation_id: PRES_B,
        },
    );
    assert_eq!(c.presentation_count(), 0);
}

// ── 3. Pipelined CHECK_FORMAT_SUPPORT correlation ──────────────────

/// The server may pipeline several `CHECK_FORMAT_SUPPORT_REQ` PDUs
/// with distinct MessageIds before reading the answers; each response
/// must echo the matching request's id verbatim.
#[test]
fn pipelined_check_format_support_messages_echo_each_id() {
    let mut c = fresh_client_with_caps(vec![]);
    run(
        &mut c,
        &SetChannelParams {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: 0,
        },
    );
    run(
        &mut c,
        &OnNewPresentation {
            message_id: 0,
            presentation_id: PRES_A,
            platform_cookie: platform_cookie::MF,
        },
    );

    let ids = [0x1111u32, 0x2222, 0x3333, 0xFFFF_FFFF];
    for &id in &ids {
        let mut out = run(
            &mut c,
            &CheckFormatSupportReq {
                message_id: id,
                platform_cookie: platform_cookie::MF,
                no_rollover_flags: 0,
                media_type: dummy_media_type(),
            },
        );
        assert_eq!(out.len(), 1);
        let rsp: CheckFormatSupportRsp = decode(&out.remove(0));
        assert_eq!(rsp.message_id, id, "MessageId not echoed for {id:#x}");
        assert_eq!(rsp.format_supported, 1);
    }
}

// ── 4. SET_CHANNEL_PARAMS double-bind tears the channel down ───────

/// Spec §3.3.5.1: SET_CHANNEL_PARAMS is the FIRST message on the
/// channel and must not repeat. A second one is a protocol violation
/// the processor surfaces as `DvcError::Protocol`, which the DVC
/// framework will translate into a channel close.
#[test]
fn second_set_channel_params_is_protocol_error() {
    let mut c = fresh_client_with_caps(vec![]);
    let bind = SetChannelParams {
        message_id: 0,
        presentation_id: PRES_A,
        stream_id: 0,
    };
    let bytes = encode(&bind);
    assert!(c.process(CHAN_ID, &bytes).unwrap().is_empty());
    let err = c.process(CHAN_ID, &bytes).unwrap_err();
    assert!(matches!(err, DvcError::Protocol(_)));
}

// ── 5. Unknown FunctionId is silently ignored ──────────────────────

/// Per spec §9 ("ignore unknown"), an unknown FunctionId on a known
/// interface must be dropped without tearing the channel down. This
/// is the forward-compat lever for future spec extensions.
#[test]
fn unknown_function_id_is_silently_ignored() {
    let mut c = fresh_client_with_caps(vec![]);
    // Hand-rolled 12-byte PROXY header with an unknown FunctionId.
    let bytes: [u8; 12] = [
        0x00, 0x00, 0x00, 0x40, // PROXY | ServerData
        0x00, 0x00, 0x00, 0x00, // MessageId
        0xEF, 0xBE, 0xAD, 0xDE, // FunctionId = 0xDEADBEEF
    ];
    let out = c.process(CHAN_ID, &bytes).expect("process");
    assert!(out.is_empty());
    // Channel still healthy: a normal SET_CHANNEL_PARAMS works.
    let bind = SetChannelParams {
        message_id: 0,
        presentation_id: PRES_A,
        stream_id: 0,
    };
    assert!(c.process(CHAN_ID, &encode(&bind)).unwrap().is_empty());
}

// ── 6. Unsupported format path round-trips ─────────────────────────

#[test]
fn unsupported_format_round_trips_with_format_supported_zero() {
    let sink = Box::new(
        MockTsmfMediaSink::new()
            .with_format_response(CheckFormatResult::unsupported()),
    );
    let mut c = RdpevClient::new(sink);
    c.start(CHAN_ID).unwrap();
    run(
        &mut c,
        &SetChannelParams {
            message_id: 0,
            presentation_id: PRES_A,
            stream_id: 0,
        },
    );
    let mut out = run(
        &mut c,
        &CheckFormatSupportReq {
            message_id: 7,
            platform_cookie: platform_cookie::MF,
            no_rollover_flags: 1,
            media_type: dummy_media_type(),
        },
    );
    let rsp: CheckFormatSupportRsp = decode(&out.remove(0));
    assert_eq!(rsp.message_id, 7);
    assert_eq!(rsp.format_supported, 0);
}

// ── 7. STUB-masked PDU from server is a protocol error ─────────────

#[test]
fn server_sent_response_pdu_is_protocol_error() {
    let mut c = fresh_client_with_caps(vec![]);
    // 8-byte STUB header — looks like a server-side response, which
    // the spec says only the client originates.
    let bytes: [u8; 8] = [
        0x00, 0x00, 0x00, 0x80, // STUB | ServerData
        0x00, 0x00, 0x00, 0x00, // MessageId
    ];
    let err = c.process(CHAN_ID, &bytes).unwrap_err();
    assert!(matches!(err, DvcError::Protocol(_)));
}

// ── 8. Constants sanity ────────────────────────────────────────────

#[test]
fn re_exported_function_ids_match_spec() {
    // Catch accidental rename / deletion of public re-exports.
    assert_eq!(function_id::EXCHANGE_CAPABILITIES_REQ, 0x0000_0100);
    assert_eq!(function_id::ON_SAMPLE, 0x0000_0103);
    assert_eq!(function_id::SET_SOURCE_VIDEO_RECT, 0x0000_0116);
    assert_eq!(function_id::PLAYBACK_ACK, 0x0000_0100);
}
