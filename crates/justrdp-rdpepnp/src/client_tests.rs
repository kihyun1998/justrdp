//! FSM and DvcProcessor integration tests for [`crate::client::PnpInfoClient`].

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Encode, WriteCursor};
use justrdp_dvc::DvcProcessor;

use crate::client::{DeviceEntry, PnpInfoCallback, PnpInfoClient, PnpInfoState};
use crate::constants::{MAX_DEVICES, MAX_HARDWARE_ID_BYTES};
use crate::pdu::{
    AuthenticatedClientMsg, ClientDeviceAdditionMsg, ClientVersionMsg, PnpDeviceDescription,
    ServerVersionMsg,
};

// ── Recording callback ──

#[derive(Debug, Default)]
struct Recorder {
    events: Vec<Event>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Added(u32),
    Removed(u32),
    Authenticated,
}

impl PnpInfoCallback for Recorder {
    fn on_device_added(&mut self, id: u32, _entry: &DeviceEntry) {
        self.events.push(Event::Added(id));
    }
    fn on_device_removed(&mut self, id: u32) {
        self.events.push(Event::Removed(id));
    }
    fn on_authenticated(&mut self) {
        self.events.push(Event::Authenticated);
    }
}

fn encode<E: Encode>(pdu: &E) -> Vec<u8> {
    let mut buf = vec![0u8; pdu.size()];
    let mut cur = WriteCursor::new(&mut buf);
    pdu.encode(&mut cur).unwrap();
    buf
}

fn new_client() -> PnpInfoClient<Recorder> {
    PnpInfoClient::with_callback(Recorder::default())
}

fn events<'a>(c: &'a PnpInfoClient<Recorder>) -> &'a [Event] {
    &c.callback().events
}

fn sample(id: u32) -> PnpDeviceDescription {
    PnpDeviceDescription {
        client_device_id: id,
        interface_guid_array: vec![0u8; 16],
        hardware_id: b"HW".to_vec(),
        compatibility_id: vec![],
        device_description: b"D".to_vec(),
        custom_flag: crate::constants::custom_flag::REDIRECTABLE,
        container_id: None,
        device_caps: None,
    }
}

fn drive_handshake(c: &mut PnpInfoClient<Recorder>) {
    c.start(1).unwrap();
    let sv = encode(&ServerVersionMsg::new_server_windows_default());
    let reply = c.process(1, &sv).unwrap();
    // Exactly one Client Version Message replied.
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].data, encode(&ClientVersionMsg::new_client_windows_default()));
    assert_eq!(c.state(), PnpInfoState::WaitAuthenticated);

    let auth = encode(&AuthenticatedClientMsg);
    let out = c.process(1, &auth).unwrap();
    assert!(out.is_empty());
    assert_eq!(c.state(), PnpInfoState::Active);
}

// ── Handshake FSM ──

#[test]
fn start_sets_wait_server_version() {
    let mut c = new_client();
    assert!(!c.is_open());
    assert_eq!(c.start(42).unwrap().len(), 0);
    assert!(c.is_open());
    assert_eq!(c.state(), PnpInfoState::WaitServerVersion);
}

#[test]
fn full_handshake_reaches_active_and_fires_callback() {
    let mut c = new_client();
    drive_handshake(&mut c);
    assert_eq!(events(&c), &[Event::Authenticated]);
    assert!(c.server_version().is_some());
}

#[test]
fn authenticated_before_server_version_is_rejected() {
    let mut c = new_client();
    c.start(1).unwrap();
    let auth = encode(&AuthenticatedClientMsg);
    assert!(c.process(1, &auth).is_err());
}

#[test]
fn server_version_in_active_state_is_rejected() {
    let mut c = new_client();
    drive_handshake(&mut c);
    let sv = encode(&ServerVersionMsg::new_server_windows_default());
    assert!(c.process(1, &sv).is_err());
}

#[test]
fn process_before_start_is_error() {
    let mut c = new_client();
    let sv = encode(&ServerVersionMsg::new_server_windows_default());
    assert!(c.process(1, &sv).is_err());
}

#[test]
fn channel_id_mismatch_rejected() {
    let mut c = new_client();
    c.start(1).unwrap();
    let sv = encode(&ServerVersionMsg::new_server_windows_default());
    assert!(c.process(999, &sv).is_err());
}

#[test]
fn header_size_mismatch_rejected() {
    let mut c = new_client();
    c.start(1).unwrap();
    let mut sv = encode(&ServerVersionMsg::new_server_windows_default());
    sv.push(0xAB); // Extra trailing byte breaks the Size vs payload equality.
    assert!(c.process(1, &sv).is_err());
}

// ── Unknown PacketId forward-compat ──

#[test]
fn unknown_packet_id_is_silently_dropped() {
    let mut c = new_client();
    drive_handshake(&mut c);
    // Construct a fake 12-byte message with an unknown PacketId.
    let bytes = vec![
        0x0c, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
    ];
    let out = c.process(1, &bytes).unwrap();
    assert!(out.is_empty());
    // State must not advance or change.
    assert_eq!(c.state(), PnpInfoState::Active);
}

#[test]
fn server_sent_client_only_packet_id_rejected() {
    let mut c = new_client();
    drive_handshake(&mut c);
    // Client-only PacketId 0x66 echoed back from the server is a
    // protocol violation on PNPDR.
    let bytes = encode(&ClientDeviceAdditionMsg::default());
    assert!(c.process(1, &bytes).is_err());
}

// ── Add / remove ──

#[test]
fn add_device_before_active_is_rejected() {
    let mut c = new_client();
    c.start(1).unwrap();
    assert!(c.add_device(sample(1)).is_err());
}

#[test]
fn remove_device_before_active_is_rejected() {
    let mut c = new_client();
    c.start(1).unwrap();
    assert!(c.remove_device(1).is_err());
}

#[test]
fn add_device_fires_callback_and_returns_wire_bytes() {
    let mut c = new_client();
    drive_handshake(&mut c);
    let msg = c.add_device(sample(7)).unwrap();
    // Should decode back to the same addition msg with one device.
    let expected = encode(&ClientDeviceAdditionMsg::new(vec![sample(7)]));
    assert_eq!(msg.data, expected);
    assert_eq!(c.device_count(), 1);
    assert_eq!(events(&c), &[Event::Authenticated, Event::Added(7)]);
}

#[test]
fn remove_device_fires_callback() {
    let mut c = new_client();
    drive_handshake(&mut c);
    c.add_device(sample(3)).unwrap();
    c.remove_device(3).unwrap();
    assert_eq!(c.device_count(), 0);
    assert_eq!(
        events(&c),
        &[Event::Authenticated, Event::Added(3), Event::Removed(3)]
    );
}

#[test]
fn remove_unknown_device_is_protocol_error() {
    let mut c = new_client();
    drive_handshake(&mut c);
    assert!(c.remove_device(9999).is_err());
}

#[test]
fn add_device_replace_in_place_fires_added_twice() {
    // Balanced-callback exception: same ID called twice replaces in
    // place and fires on_device_added again without a removal.
    let mut c = new_client();
    drive_handshake(&mut c);
    c.add_device(sample(5)).unwrap();
    let mut replacement = sample(5);
    replacement.device_description = b"Replaced".to_vec();
    c.add_device(replacement).unwrap();
    assert_eq!(c.device_count(), 1);
    assert_eq!(
        events(&c),
        &[Event::Authenticated, Event::Added(5), Event::Added(5)]
    );
}

// ── DoS cap ──

#[test]
fn add_device_honours_max_devices_cap() {
    let mut c = new_client();
    drive_handshake(&mut c);
    for id in 0..MAX_DEVICES as u32 {
        c.add_device(sample(id)).unwrap();
    }
    assert_eq!(c.device_count(), MAX_DEVICES);
    // New ID past cap rejected.
    assert!(c.add_device(sample(MAX_DEVICES as u32)).is_err());
    // Replacing an existing ID at capacity must still succeed.
    c.add_device(sample(0)).unwrap();
    assert_eq!(c.device_count(), MAX_DEVICES);
}

#[test]
fn add_device_validation_rejects_oversize_hardware_id() {
    let mut c = new_client();
    drive_handshake(&mut c);
    let mut d = sample(1);
    d.hardware_id = vec![0u8; MAX_HARDWARE_ID_BYTES + 1];
    assert!(c.add_device(d).is_err());
    assert_eq!(c.device_count(), 0);
}

#[test]
fn add_device_validation_rejects_unaligned_interface() {
    let mut c = new_client();
    drive_handshake(&mut c);
    let mut d = sample(1);
    d.interface_guid_array = vec![0u8; 17];
    assert!(c.add_device(d).is_err());
}

// ── Close and restart ──

#[test]
fn close_flushes_devices_and_fires_removed() {
    let mut c = new_client();
    drive_handshake(&mut c);
    c.add_device(sample(1)).unwrap();
    c.add_device(sample(2)).unwrap();
    c.close(1);
    assert!(!c.is_open());
    assert_eq!(c.state(), PnpInfoState::Closed);
    // on_device_removed must fire for every entry that was present.
    let evs = events(&c);
    assert!(evs.contains(&Event::Removed(1)));
    assert!(evs.contains(&Event::Removed(2)));
}

#[test]
fn restart_flushes_stale_state() {
    let mut c = new_client();
    drive_handshake(&mut c);
    c.add_device(sample(9)).unwrap();
    // start() without an intervening close(): stale state must be gone
    // and callbacks must fire for the dropped device.
    c.start(2).unwrap();
    assert_eq!(c.device_count(), 0);
    assert_eq!(c.state(), PnpInfoState::WaitServerVersion);
    let evs = events(&c);
    assert!(evs.contains(&Event::Removed(9)));
}

#[test]
fn close_with_wrong_channel_id_is_noop() {
    let mut c = new_client();
    drive_handshake(&mut c);
    c.add_device(sample(1)).unwrap();
    c.close(999); // Wrong id.
    assert!(c.is_open(), "channel_open should not be cleared");
    assert_eq!(c.device_count(), 1);
}
