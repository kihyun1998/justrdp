//! Integration tests for `RdpeiDvcClient` registered inside a
//! `DrdynvcClient` — the connector/session layer wiring path.
//!
//! The unit tests in `src/client.rs` exercise `DvcProcessor` directly,
//! which is enough for the RDPEI state machine in isolation. These
//! tests add one layer up: they prove that a `RdpeiDvcClient` boxed
//! into `DrdynvcClient` still receives `start()` / `process()` /
//! `close()` through the DRDYNVC multiplexer when the server drives
//! the full Caps → CreateRequest → Data sequence on the static virtual
//! channel. This is the path `justrdp-blocking::RdpClient::connect_with_processors`
//! takes in production, so these tests stand in for a real connected
//! session (which would require an RDP server).

use justrdp_core::{Encode, WriteCursor};
use justrdp_dvc::DrdynvcClient;
use justrdp_rdpei::pdu::{CsReadyPdu, ScReadyPdu, RDPINPUT_PROTOCOL_V200};
use justrdp_rdpei::RdpeiDvcClient;
use justrdp_svc::SvcProcessor;

/// The RDPEI dynamic virtual channel name, as defined in MS-RDPEI
/// §1.9 and hardcoded in `RdpeiDvcClient::channel_name()`. Repeated
/// here as a test-local constant because the crate keeps its own
/// copy private to the client module.
const RDPEI_CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Input";

// ── Helpers to forge the three server → client DRDYNVC PDUs the
//    test needs. DrdynvcClient only exposes client → server encoders,
//    so we hand-roll the server frames to keep the test self-contained.
//    Format reference: MS-RDPEDYC §2.2.2.

/// Server Capability Request (v1, minimum 4 bytes).
/// Header: `cmd=0x5 (CMD_CAPS) | sp=0 | cb_id=0` → `0x50`
/// Body: `0x00` pad + `0x0001` little-endian version.
fn caps_request_v1() -> Vec<u8> {
    vec![0x50, 0x00, 0x01, 0x00]
}

/// Server Create Request for a DVC channel named `name`.
///
/// Header: `cmd=0x1 (CMD_CREATE) | sp=0 | cb_id=0` → `0x10` (channel
/// IDs 0..=255 fit in a single byte, so `cb_id=0`). Body: 1-byte
/// `channel_id` followed by the null-terminated channel name (ASCII).
fn create_request(channel_id: u8, name: &str) -> Vec<u8> {
    assert!(name.is_ascii(), "RDP DVC channel names are ASCII");
    let mut buf = Vec::with_capacity(2 + name.len() + 1);
    buf.push(0x10); // CMD_CREATE, sp=0, cb_id=0 (1-byte channel_id)
    buf.push(channel_id);
    buf.extend_from_slice(name.as_bytes());
    buf.push(0x00); // null terminator
    buf
}

/// Server Data PDU on `channel_id`.
///
/// Header: `cmd=0x3 (CMD_DATA) | sp=0 | cb_id=0` → `0x30`.
/// Body: 1-byte channel_id + raw payload. No length field in CMD_DATA;
/// the SVC layer provides framing.
fn data_pdu(channel_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + payload.len());
    buf.push(0x30);
    buf.push(channel_id);
    buf.extend_from_slice(payload);
    buf
}

/// Extract the CMD_DATA payload from a DRDYNVC outbound frame. Panics
/// on any frame that is not a CMD_DATA on a 1-byte channel_id, which
/// is the only shape RdpeiDvcClient ever produces in these tests.
fn extract_data_payload(frame: &[u8], expected_channel_id: u8) -> &[u8] {
    assert!(!frame.is_empty(), "empty DVC frame");
    let header = frame[0];
    let cmd = header >> 4;
    let cb_id = header & 0x03;
    assert_eq!(cmd, 0x3, "expected CMD_DATA, got cmd=0x{cmd:x}");
    assert_eq!(cb_id, 0, "expected 1-byte channel_id, got cb_id={cb_id}");
    assert_eq!(frame[1], expected_channel_id);
    &frame[2..]
}

fn encode_sc_ready(version: u32) -> Vec<u8> {
    let pdu = ScReadyPdu {
        protocol_version: version,
        supported_features: None,
    };
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).unwrap();
    buf
}

fn decode_cs_ready(bytes: &[u8]) -> CsReadyPdu {
    CsReadyPdu::decode_from(bytes).unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────

#[test]
fn rdpei_registered_inside_drdynvc_receives_sc_ready() {
    // This test drives the same handshake a real server would but
    // through the `DrdynvcClient` multiplexer rather than against
    // `RdpeiDvcClient` directly, which is the thing the Phase 6 §9.4
    // "Connector/세션 레이어 등록 경로" item cared about.

    let mut drdynvc = DrdynvcClient::new();
    drdynvc.register(Box::new(RdpeiDvcClient::new()));

    // 1. Server negotiates DRDYNVC caps. The client echoes v1 back as
    //    its CapabilityResponse.
    let caps_response = drdynvc.process(&caps_request_v1()).unwrap();
    assert_eq!(caps_response.len(), 1);
    assert_eq!(&caps_response[0].data, &[0x50, 0x00, 0x01, 0x00]);

    // 2. Server opens channel_id=7 for the RDPEI channel name. The
    //    multiplexer must look up the registered processor by name
    //    and call its `start()` — RdpeiDvcClient::start returns an
    //    empty Vec because its first outbound is the CS_READY which
    //    only fires after SC_READY arrives.
    let create = create_request(7, RDPEI_CHANNEL_NAME);
    let create_responses = drdynvc.process(&create).unwrap();
    assert_eq!(
        create_responses.len(),
        1,
        "DrdynvcClient must emit exactly one CreateResponse frame"
    );
    // CreateResponse header `0x10` + 1-byte channel_id + 4-byte i32
    // status (little-endian). CREATION_STATUS_OK = 0.
    let resp = &create_responses[0].data;
    assert_eq!(resp[0], 0x10);
    assert_eq!(resp[1], 7);
    assert_eq!(&resp[2..6], &[0x00, 0x00, 0x00, 0x00]);

    // 3. Server sends SC_READY wrapped in a DVC Data PDU. The
    //    multiplexer must route it to RdpeiDvcClient, which produces
    //    a CS_READY that the multiplexer wraps in another Data PDU
    //    on the same channel.
    let sc_ready = encode_sc_ready(RDPINPUT_PROTOCOL_V200);
    let out = drdynvc.process(&data_pdu(7, &sc_ready)).unwrap();
    assert_eq!(
        out.len(),
        1,
        "RDPEI must emit CS_READY in response to SC_READY via trait dispatch"
    );
    let cs_bytes = extract_data_payload(&out[0].data, 7);
    let cs = decode_cs_ready(cs_bytes);
    assert_eq!(cs.protocol_version, RDPINPUT_PROTOCOL_V200);
}

#[test]
fn unregistered_channel_name_is_rejected_by_drdynvc() {
    // Regression guard: if a future refactor swaps the RDPEI channel
    // name constant, `Microsoft::Windows::RDS::Input` would stop
    // matching the registered processor and DrdynvcClient would
    // reject the CreateRequest with a negative creation_status. This
    // test fails loudly rather than silently dropping touch traffic.

    let mut drdynvc = DrdynvcClient::new();
    drdynvc.register(Box::new(RdpeiDvcClient::new()));
    drdynvc.process(&caps_request_v1()).unwrap();

    // "Microsoft::Windows::RDS::NotInput" — wrong channel name.
    let create = create_request(9, "Microsoft::Windows::RDS::NotInput");
    let responses = drdynvc.process(&create).unwrap();
    assert_eq!(responses.len(), 1);
    let status_bytes: [u8; 4] = responses[0].data[2..6].try_into().unwrap();
    let status = i32::from_le_bytes(status_bytes);
    assert!(
        status < 0,
        "DrdynvcClient must reject unknown channel name (got status=0x{status:08X})",
    );

    // And a subsequent Data PDU on the (rejected) channel_id must
    // not reach the processor. We verify indirectly: sending SC_READY
    // on channel 9 yields no response frames (nothing was routed).
    let sc_ready = encode_sc_ready(RDPINPUT_PROTOCOL_V200);
    let out = drdynvc.process(&data_pdu(9, &sc_ready)).unwrap();
    assert!(
        out.is_empty(),
        "rejected channel must not dispatch inbound data to any processor",
    );
}

#[test]
fn drdynvc_uses_svc_processor_vtable_not_generic_dispatch() {
    // Prove the `DrdynvcClient` itself is usable behind a
    // `dyn SvcProcessor` — this is the exact shape `RdpClient::
    // connect_with_processors` consumes, so if this compiles and
    // runs, the blocking runtime registration path is wired end to
    // end without a concrete-type leak.
    let drdynvc = DrdynvcClient::new();
    let boxed: Box<dyn SvcProcessor> = Box::new(drdynvc);
    // channel_name() goes through the vtable.
    assert_eq!(boxed.channel_name().as_str(), "drdynvc");
}
