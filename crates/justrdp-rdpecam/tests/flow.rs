//! Full MS-RDPECAM client flow integration test.
//!
//! Runs the enumerator and per-device DVC processors side-by-side
//! against a [`MockCameraDevice`], threading hand-forged "server"
//! messages through both and asserting on the bytes each processor
//! emits. Exercises the complete v2 happy path as well as a few
//! mis-sequencing guardrails and the v1 downgrade.
//!
//! These tests stand in for the on-wire "server" half of the protocol:
//! because there is no conformant RDPECAM server available in the test
//! environment, every server-originated PDU is built with the crate's
//! own encoder and fed into `process()` as a DVC payload -- the exact
//! buffer shape DRDYNVC would hand us after reassembling the DVC data.

use justrdp_core::{Decode, ReadCursor};
use justrdp_dvc::DvcProcessor;

use justrdp_rdpecam::{
    camera_control_property_id, frame_source_types, media_type_flags, property_capabilities,
    video_proc_amp_property_id, ActivateDeviceRequest, CurrentMediaTypeRequest,
    CurrentMediaTypeResponse, DeactivateDeviceRequest, DeviceAddedNotification,
    DeviceRemovedNotification, ErrorCode, MediaFormat, MediaTypeDescription, MediaTypeListRequest,
    MediaTypeListResponse, MockCameraDevice, PropertyDescription, PropertyListRequest,
    PropertyListResponse, PropertyMode, PropertySet, PropertyValue, PropertyValueRequest,
    PropertyValueResponse, RdpecamDeviceClient, RdpecamEnumeratorClient, SampleRequest,
    SampleResponse, SelectVersionRequest, SelectVersionResponse, SetPropertyValueRequest,
    StartStreamInfo, StartStreamsRequest, StopStreamsRequest, StreamDescription,
    StreamListRequest, StreamListResponse, SuccessResponse, STREAM_CATEGORY_CAPTURE, VERSION_1,
    VERSION_2,
};

// ── Helpers ─────────────────────────────────────────────────────────

const ENUM_CHANNEL_ID: u32 = 1;
const DEVICE_CHANNEL_ID: u32 = 2;
const DEVICE_NAME: &str = "Mock Camera 1";
const VIRTUAL_CHANNEL_NAME: &[u8] = b"RDCamera_Device_0";

fn utf16(s: &str) -> Vec<u16> {
    s.chars().map(|c| c as u16).collect()
}

fn base_stream() -> StreamDescription {
    StreamDescription {
        frame_source_types: frame_source_types::COLOR,
        stream_category: STREAM_CATEGORY_CAPTURE,
        selected: 1,
        can_be_shared: 1,
    }
}

fn base_media_type() -> MediaTypeDescription {
    MediaTypeDescription {
        format: MediaFormat::H264,
        width: 1920,
        height: 1080,
        frame_rate_numerator: 30,
        frame_rate_denominator: 1,
        pixel_aspect_ratio_numerator: 1,
        pixel_aspect_ratio_denominator: 1,
        flags: media_type_flags::DECODING_REQUIRED,
    }
}

fn brightness_descriptor() -> PropertyDescription {
    PropertyDescription {
        property_set: PropertySet::VideoProcAmp,
        property_id: video_proc_amp_property_id::BRIGHTNESS,
        capabilities: property_capabilities::MANUAL,
        min_value: 0,
        max_value: 255,
        step: 1,
        default_value: 128,
    }
}

fn sample_device() -> MockCameraDevice {
    MockCameraDevice::new()
        .with_stream(base_stream(), vec![base_media_type()])
        .with_property(brightness_descriptor(), PropertyValue::manual(128))
        .with_queued_sample(0, vec![0xDE, 0xAD, 0xBE, 0xEF])
}

/// Encodes a PDU into the flat byte layout DRDYNVC would hand to
/// `DvcProcessor::process`.
fn encode<T: justrdp_core::Encode>(pdu: &T) -> Vec<u8> {
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = justrdp_core::WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).expect("encode PDU");
    assert_eq!(cur.pos(), pdu.size(), "size() mismatch for {}", pdu.name());
    buf
}

/// Drives a single server→client PDU through the device processor and
/// returns the single response payload it emits.
fn device_exchange<T: justrdp_core::Encode>(
    client: &mut RdpecamDeviceClient,
    pdu: &T,
) -> Vec<u8> {
    let mut out = client
        .process(DEVICE_CHANNEL_ID, &encode(pdu))
        .expect("device process");
    assert_eq!(
        out.len(),
        1,
        "expected exactly one response for {}",
        pdu.name()
    );
    out.remove(0).data
}

fn decode<'a, T: Decode<'a>>(bytes: &'a [u8]) -> T {
    let mut cur = ReadCursor::new(bytes);
    T::decode(&mut cur).expect("decode")
}

// ── Tests ───────────────────────────────────────────────────────────

/// Full v2 happy path: enumerator negotiation → device announce →
/// device lifecycle (activate → enumerate → stream → sample → stop →
/// deactivate) → property API get/set → clean shutdown.
#[test]
fn full_v2_happy_path() {
    // ── 1. Bring up the enumerator and negotiate v2 ──
    let mut enumerator = RdpecamEnumeratorClient::builder()
        .max_version(VERSION_2)
        .build();
    let init = enumerator
        .start(ENUM_CHANNEL_ID)
        .expect("enumerator start");
    assert_eq!(init.len(), 1);
    // start() must emit a v2 SelectVersionRequest.
    let req = decode::<SelectVersionRequest>(&init[0].data);
    assert_eq!(req.version, VERSION_2);

    // Server replies with v2.
    let server_resp = encode(&SelectVersionResponse::new(VERSION_2));
    let out = enumerator
        .process(ENUM_CHANNEL_ID, &server_resp)
        .expect("enumerator process");
    assert!(out.is_empty());
    assert_eq!(enumerator.negotiated_version(), Some(VERSION_2));
    assert!(enumerator.is_ready());

    // ── 2. Announce the camera and install the per-device processor ──
    let announcement = enumerator
        .announce_device(utf16(DEVICE_NAME), VIRTUAL_CHANNEL_NAME.to_vec())
        .expect("announce_device");
    // Verify it round-trips as a DeviceAddedNotification.
    let added = decode::<DeviceAddedNotification>(&announcement.data);
    assert_eq!(added.version, VERSION_2);
    assert_eq!(added.virtual_channel_name, VIRTUAL_CHANNEL_NAME);
    assert_eq!(added.device_name, utf16(DEVICE_NAME));
    assert_eq!(enumerator.announced_count(), 1);

    // Register the per-device processor (host-orchestrated; the
    // enumerator does not own DrdynvcClient).
    let mut device = RdpecamDeviceClient::new(
        String::from_utf8(VIRTUAL_CHANNEL_NAME.to_vec()).unwrap(),
        VERSION_2,
        Box::new(sample_device()),
    );
    device.start(DEVICE_CHANNEL_ID).expect("device start");
    assert_eq!(device.channel_name().as_bytes(), VIRTUAL_CHANNEL_NAME);

    // ── 3. Activate the device ──
    let resp = device_exchange(&mut device, &ActivateDeviceRequest::new(VERSION_2));
    let _ok = decode::<SuccessResponse>(&resp);
    assert!(device.is_activated());
    assert!(!device.is_streaming());

    // ── 4. Stream list ──
    let resp = device_exchange(&mut device, &StreamListRequest::new(VERSION_2));
    let list = decode::<StreamListResponse>(&resp);
    assert_eq!(list.streams.len(), 1);
    assert_eq!(list.streams[0].frame_source_types, frame_source_types::COLOR);

    // ── 5. Media type list for stream 0 ──
    let resp = device_exchange(
        &mut device,
        &MediaTypeListRequest::new(VERSION_2, 0),
    );
    let mtlist = decode::<MediaTypeListResponse>(&resp);
    assert_eq!(mtlist.media_types.len(), 1);
    assert_eq!(mtlist.media_types[0].format, MediaFormat::H264);
    assert_eq!(mtlist.media_types[0].width, 1920);

    // ── 6. Current media type for stream 0 ──
    let resp = device_exchange(
        &mut device,
        &CurrentMediaTypeRequest::new(VERSION_2, 0),
    );
    let cmt = decode::<CurrentMediaTypeResponse>(&resp);
    assert_eq!(cmt.media_type.width, 1920);

    // ── 7. Start streams on stream 0 ──
    let start = StartStreamsRequest {
        version: VERSION_2,
        infos: vec![StartStreamInfo {
            stream_index: 0,
            media_type: base_media_type(),
        }],
    };
    let resp = device_exchange(&mut device, &start);
    let _ok = decode::<SuccessResponse>(&resp);
    assert!(device.is_streaming());

    // ── 8. Pull the queued sample ──
    let resp = device_exchange(&mut device, &SampleRequest::new(VERSION_2, 0));
    let sample = decode::<SampleResponse>(&resp);
    assert_eq!(sample.stream_index, 0);
    assert_eq!(sample.sample, vec![0xDE, 0xAD, 0xBE, 0xEF]);

    // ── 9. Second SampleRequest must produce SampleErrorResponse
    //       (the queue is now empty -- the mock's InvalidRequest path). ──
    let resp = device_exchange(&mut device, &SampleRequest::new(VERSION_2, 0));
    // SampleErrorResponse is 7 bytes total: 2 header + 1 idx + 4 code.
    assert_eq!(resp.len(), 7);
    assert_eq!(resp[1], 0x13);
    assert_eq!(resp[2], 0);
    assert_eq!(
        u32::from_le_bytes([resp[3], resp[4], resp[5], resp[6]]),
        ErrorCode::InvalidRequest.to_u32()
    );

    // ── 10. Property API: list → get → set → get back ──
    let resp = device_exchange(&mut device, &PropertyListRequest);
    let props = decode::<PropertyListResponse>(&resp);
    assert_eq!(props.properties.len(), 1);
    assert_eq!(
        props.properties[0].property_set,
        PropertySet::VideoProcAmp
    );

    let resp = device_exchange(
        &mut device,
        &PropertyValueRequest::new(
            PropertySet::VideoProcAmp,
            video_proc_amp_property_id::BRIGHTNESS,
        ),
    );
    let value = decode::<PropertyValueResponse>(&resp);
    assert_eq!(value.value.mode, PropertyMode::Manual);
    assert_eq!(value.value.value, 128);

    let resp = device_exchange(
        &mut device,
        &SetPropertyValueRequest::new(
            PropertySet::VideoProcAmp,
            video_proc_amp_property_id::BRIGHTNESS,
            PropertyValue::manual(200),
        ),
    );
    let _ok = decode::<SuccessResponse>(&resp);

    let resp = device_exchange(
        &mut device,
        &PropertyValueRequest::new(
            PropertySet::VideoProcAmp,
            video_proc_amp_property_id::BRIGHTNESS,
        ),
    );
    let value = decode::<PropertyValueResponse>(&resp);
    assert_eq!(value.value.value, 200);

    // ── 11. Stop streams ──
    let resp = device_exchange(&mut device, &StopStreamsRequest::new(VERSION_2));
    let _ok = decode::<SuccessResponse>(&resp);
    assert!(device.is_activated());
    assert!(!device.is_streaming());

    // ── 12. Deactivate ──
    let resp = device_exchange(&mut device, &DeactivateDeviceRequest::new(VERSION_2));
    let _ok = decode::<SuccessResponse>(&resp);
    assert!(!device.is_activated());

    // ── 13. Close per-device channel ──
    device.close(DEVICE_CHANNEL_ID);
    assert!(!device.is_open());

    // ── 14. Remove the camera from the enumerator ──
    let removal = enumerator
        .remove_device(VIRTUAL_CHANNEL_NAME)
        .expect("remove_device");
    let removed = decode::<DeviceRemovedNotification>(&removal.data);
    assert_eq!(removed.virtual_channel_name, VIRTUAL_CHANNEL_NAME);
    assert_eq!(enumerator.announced_count(), 0);

    // ── 15. Close enumerator ──
    enumerator.close(ENUM_CHANNEL_ID);
}

/// Verifies that announcing and then removing a device on the
/// enumerator is a self-contained round-trip: a second `remove_device`
/// call for the same channel name must fail because the device is
/// gone. This protects against a regression where `remove_device`
/// forgets to drop its internal bookkeeping.
#[test]
fn announce_then_remove_is_idempotent_on_second_remove() {
    let mut enumerator = RdpecamEnumeratorClient::builder()
        .max_version(VERSION_2)
        .build();
    enumerator.start(ENUM_CHANNEL_ID).unwrap();
    let resp = encode(&SelectVersionResponse::new(VERSION_2));
    enumerator.process(ENUM_CHANNEL_ID, &resp).unwrap();

    enumerator
        .announce_device(utf16("X"), b"X_device".to_vec())
        .expect("first announce");
    enumerator
        .remove_device(b"X_device")
        .expect("first remove");

    assert!(enumerator.remove_device(b"X_device").is_err());
    assert_eq!(enumerator.announced_count(), 0);
}

/// Drives the enumerator through a v1 negotiation and confirms that
/// the per-device processor, instantiated with `VERSION_1`, rejects
/// v2-only PropertyList traffic as `ErrorResponse(InvalidMessage)`.
/// This is the end-to-end counterpart of the unit test that exercises
/// the same gate inside the device processor in isolation.
#[test]
fn v1_negotiation_blocks_property_api_on_device_channel() {
    // Client offers v2, server downgrades to v1.
    let mut enumerator = RdpecamEnumeratorClient::builder()
        .max_version(VERSION_2)
        .build();
    enumerator.start(ENUM_CHANNEL_ID).unwrap();
    let resp = encode(&SelectVersionResponse::new(VERSION_1));
    enumerator.process(ENUM_CHANNEL_ID, &resp).unwrap();
    assert_eq!(enumerator.negotiated_version(), Some(VERSION_1));

    // The host would pass the negotiated version to the device
    // processor at construction. Build it with v1 accordingly.
    let mut device = RdpecamDeviceClient::new(
        String::from("v1_cam"),
        VERSION_1,
        Box::new(
            MockCameraDevice::new()
                .with_stream(base_stream(), vec![base_media_type()]),
        ),
    );
    device.start(DEVICE_CHANNEL_ID).unwrap();
    // Activate normally to get past Initialised.
    let _ok = device_exchange(&mut device, &ActivateDeviceRequest::new(VERSION_1));

    // Build a synthetic v1 PropertyListRequest payload. The normal
    // encoder hardwires v2 for this PDU, so we hand-roll the bytes.
    let bogus = [VERSION_1, 0x14];
    let mut out = device.process(DEVICE_CHANNEL_ID, &bogus).unwrap();
    let resp = out.remove(0).data;
    assert_eq!(resp[0], VERSION_1);
    assert_eq!(resp[1], 0x02); // ErrorResponse
    assert_eq!(
        u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
        ErrorCode::InvalidMessage.to_u32()
    );
}

/// Cross-checks that an unknown `camera_control_property_id` against a
/// mock that has no such property propagates the host
/// `CamError::ItemNotFound` all the way through as a wire
/// `ErrorResponse(ItemNotFound)`.
#[test]
fn unknown_property_id_returns_item_not_found() {
    let mut device = RdpecamDeviceClient::new(
        String::from("lookup"),
        VERSION_2,
        Box::new(
            MockCameraDevice::new()
                .with_stream(base_stream(), vec![base_media_type()]),
        ),
    );
    device.start(DEVICE_CHANNEL_ID).unwrap();
    device_exchange(&mut device, &ActivateDeviceRequest::new(VERSION_2));

    let req = PropertyValueRequest::new(
        PropertySet::CameraControl,
        camera_control_property_id::ZOOM,
    );
    let resp = device_exchange(&mut device, &req);
    assert_eq!(resp[1], 0x02);
    assert_eq!(
        u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]),
        ErrorCode::ItemNotFound.to_u32()
    );
}

