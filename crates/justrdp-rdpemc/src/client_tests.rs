//! FSM tests for [`crate::client::EncomspClient`].

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Encode, WriteCursor};
use justrdp_svc::SvcProcessor;

use crate::client::{EncomspCallback, EncomspClient, EncomspError, MAX_APPLICATIONS, MAX_WINDOWS};
use crate::constants::flags;
use crate::pdu::{
    OdAppCreated, OdAppRemoved, OdFilterStateUpdated, OdGraphicsStreamPaused,
    OdGraphicsStreamResumed, OdParticipantCreated, OdParticipantCtrlChangeResponse,
    OdParticipantRemoved, OdWndCreated, OdWndRemoved, UnicodeString,
};

// ── Recording callback ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    FilterStateChanged(bool),
    AppCreated(u32, u16),
    AppRemoved(u32),
    WindowCreated { wnd_id: u32, app_id: u32, flags: u16 },
    WindowRemoved(u32),
    ParticipantCreated(u32, u32, u16),
    ParticipantRemoved(u32, u32, u32),
    ParticipantPermissionsUpdated(u32, u16),
    SelfIdentity(u32, u16),
    SelfPermissionsUpdated(u16),
    ControlChangeResponse(u16, u32, u32),
    GraphicsPaused,
    GraphicsResumed,
}

#[derive(Debug, Default)]
struct Recorder {
    events: Vec<Event>,
}

impl Recorder {
    fn take(&mut self) -> Vec<Event> {
        core::mem::take(&mut self.events)
    }
    fn count(&self) -> usize {
        self.events.len()
    }
}

impl EncomspCallback for Recorder {
    fn on_filter_state_changed(&mut self, enabled: bool) {
        self.events.push(Event::FilterStateChanged(enabled));
    }
    fn on_app_created(&mut self, app_id: u32, flags: u16, _name: &UnicodeString) {
        self.events.push(Event::AppCreated(app_id, flags));
    }
    fn on_app_removed(&mut self, app_id: u32) {
        self.events.push(Event::AppRemoved(app_id));
    }
    fn on_window_created(&mut self, wnd_id: u32, app_id: u32, flags: u16, _name: &UnicodeString) {
        self.events.push(Event::WindowCreated {
            wnd_id,
            app_id,
            flags,
        });
    }
    fn on_window_removed(&mut self, wnd_id: u32) {
        self.events.push(Event::WindowRemoved(wnd_id));
    }
    fn on_participant_created(
        &mut self,
        participant_id: u32,
        group_id: u32,
        flags: u16,
        _friendly_name: &UnicodeString,
    ) {
        self.events
            .push(Event::ParticipantCreated(participant_id, group_id, flags));
    }
    fn on_participant_removed(&mut self, participant_id: u32, disc_type: u32, disc_code: u32) {
        self.events.push(Event::ParticipantRemoved(
            participant_id,
            disc_type,
            disc_code,
        ));
    }
    fn on_participant_permissions_updated(&mut self, participant_id: u32, new_flags: u16) {
        self.events
            .push(Event::ParticipantPermissionsUpdated(participant_id, new_flags));
    }
    fn on_self_identity(&mut self, self_id: u32, flags: u16) {
        self.events.push(Event::SelfIdentity(self_id, flags));
    }
    fn on_self_permissions_updated(&mut self, new_flags: u16) {
        self.events.push(Event::SelfPermissionsUpdated(new_flags));
    }
    fn on_control_change_response(&mut self, flags: u16, participant_id: u32, reason_code: u32) {
        self.events.push(Event::ControlChangeResponse(
            flags,
            participant_id,
            reason_code,
        ));
    }
    fn on_graphics_stream_paused(&mut self) {
        self.events.push(Event::GraphicsPaused);
    }
    fn on_graphics_stream_resumed(&mut self) {
        self.events.push(Event::GraphicsResumed);
    }
}

fn new_client() -> EncomspClient<Recorder> {
    EncomspClient::new(Recorder::default())
}

fn events(c: &EncomspClient<Recorder>) -> Vec<Event> {
    c.callback().events.clone()
}

fn drain_events(c: &mut EncomspClient<Recorder>) -> Vec<Event> {
    c.callback_mut().take()
}

// ── Encoders for test payloads ───────────────────────────────────────

fn encode<T: Encode>(pdu: &T) -> Vec<u8> {
    let mut buf = vec![0u8; pdu.size()];
    pdu.encode(&mut WriteCursor::new(&mut buf)).unwrap();
    buf
}

fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

fn app_created(app_id: u32, flags: u16) -> Vec<u8> {
    encode(&OdAppCreated {
        flags,
        app_id,
        name: UnicodeString::empty(),
    })
}

fn app_removed(app_id: u32) -> Vec<u8> {
    encode(&OdAppRemoved { app_id })
}

fn wnd_created(wnd_id: u32, app_id: u32, flags: u16) -> Vec<u8> {
    encode(&OdWndCreated {
        flags,
        app_id,
        wnd_id,
        name: UnicodeString::empty(),
    })
}

fn wnd_removed(wnd_id: u32) -> Vec<u8> {
    encode(&OdWndRemoved { wnd_id })
}

fn filter(enabled: bool) -> Vec<u8> {
    encode(&OdFilterStateUpdated {
        flags: if enabled { flags::FILTER_ENABLED } else { 0 },
    })
}

fn participant_created(pid: u32, group_id: u32, pdu_flags: u16) -> Vec<u8> {
    encode(&OdParticipantCreated {
        participant_id: pid,
        group_id,
        flags: pdu_flags,
        friendly_name: UnicodeString::empty(),
    })
}

fn participant_removed(pid: u32, disc_type: u32, disc_code: u32) -> Vec<u8> {
    encode(&OdParticipantRemoved {
        participant_id: pid,
        disc_type,
        disc_code,
    })
}

fn ctrl_response(flags: u16, pid: u32, reason: u32) -> Vec<u8> {
    encode(&OdParticipantCtrlChangeResponse {
        flags,
        participant_id: pid,
        reason_code: reason,
    })
}

// ── Tests: basic app/window lifecycle ────────────────────────────────

#[test]
fn app_created_inserts_and_fires_callback() {
    let mut c = new_client();
    c.process_payload(&app_created(42, flags::APPLICATION_SHARED))
        .unwrap();
    assert_eq!(c.app_count(), 1);
    assert_eq!(c.app(42).unwrap().flags, flags::APPLICATION_SHARED);
    assert_eq!(
        events(&c),
        vec![Event::AppCreated(42, flags::APPLICATION_SHARED)]
    );
}

#[test]
fn duplicate_app_created_replaces_without_remove_callback() {
    let mut c = new_client();
    c.process_payload(&app_created(42, 0)).unwrap();
    c.process_payload(&app_created(42, flags::APPLICATION_SHARED))
        .unwrap();
    assert_eq!(c.app(42).unwrap().flags, flags::APPLICATION_SHARED);
    assert_eq!(
        events(&c),
        vec![
            Event::AppCreated(42, 0),
            Event::AppCreated(42, flags::APPLICATION_SHARED),
        ]
    );
}

#[test]
fn app_removed_unknown_is_silent() {
    let mut c = new_client();
    c.process_payload(&app_removed(999)).unwrap();
    assert_eq!(c.callback().events.len(), 0);
    assert_eq!(c.app_count(), 0);
}

#[test]
fn wnd_created_and_removed_fires_callbacks() {
    let mut c = new_client();
    c.process_payload(&concat(&[
        app_created(1, 0),
        wnd_created(100, 1, flags::WINDOW_SHARED),
    ]))
    .unwrap();
    c.process_payload(&wnd_removed(100)).unwrap();
    assert_eq!(c.window_count(), 0);
    assert_eq!(c.app_count(), 1);
    assert_eq!(
        events(&c),
        vec![
            Event::AppCreated(1, 0),
            Event::WindowCreated {
                wnd_id: 100,
                app_id: 1,
                flags: flags::WINDOW_SHARED,
            },
            Event::WindowRemoved(100),
        ]
    );
}

// ── App removal cascade (§3.1.5.3) ──────────────────────────────────

#[test]
fn app_removed_cascades_window_removal_windows_before_app() {
    let mut c = new_client();
    c.process_payload(&concat(&[
        app_created(1, 0),
        wnd_created(100, 1, 0),
        wnd_created(101, 1, 0),
        wnd_created(200, 2, 0), // owned by a different (absent) app
    ]))
    .unwrap();
    drain_events(&mut c);
    c.process_payload(&app_removed(1)).unwrap();
    let ev = events(&c);
    assert_eq!(ev.len(), 3);
    let removed_wnds: Vec<u32> = ev
        .iter()
        .filter_map(|e| match e {
            Event::WindowRemoved(w) => Some(*w),
            _ => None,
        })
        .collect();
    assert!(removed_wnds.contains(&100));
    assert!(removed_wnds.contains(&101));
    assert!(!removed_wnds.contains(&200));
    // App removal must be last.
    assert_eq!(ev[ev.len() - 1], Event::AppRemoved(1));
    assert_eq!(c.window_count(), 1);
    assert!(c.window(200).is_some());
}

// ── Filter state flush (Appendix A <13>) ────────────────────────────

#[test]
fn filter_state_change_flushes_tables_and_fires_callbacks() {
    let mut c = new_client();
    c.process_payload(&concat(&[
        app_created(1, 0),
        app_created(2, 0),
        wnd_created(100, 1, 0),
        wnd_created(101, 2, 0),
        participant_created(50, 0, flags::MAY_VIEW),
    ]))
    .unwrap();
    drain_events(&mut c);
    c.process_payload(&filter(true)).unwrap();
    assert_eq!(c.app_count(), 0);
    assert_eq!(c.window_count(), 0);
    assert_eq!(c.participant_count(), 0);
    assert!(c.filter_enabled());
    let ev = events(&c);
    assert_eq!(ev[ev.len() - 1], Event::FilterStateChanged(true));
    let mut first_app_idx = None;
    let mut last_wnd_idx = None;
    for (i, e) in ev.iter().enumerate() {
        match e {
            Event::WindowRemoved(_) => last_wnd_idx = Some(i),
            Event::AppRemoved(_) if first_app_idx.is_none() => first_app_idx = Some(i),
            _ => {}
        }
    }
    if let (Some(w), Some(a)) = (last_wnd_idx, first_app_idx) {
        assert!(w < a, "windows must flush before apps");
    }
}

#[test]
fn filter_state_no_op_does_not_flush() {
    let mut c = new_client();
    c.process_payload(&app_created(1, 0)).unwrap();
    drain_events(&mut c);
    c.process_payload(&filter(false)).unwrap();
    assert_eq!(c.app_count(), 1);
    assert_eq!(c.callback().count(), 0);
}

// ── Participant: self identity vs remote ────────────────────────────

#[test]
fn is_participant_unicast_establishes_self_identity_without_table_insert() {
    let mut c = new_client();
    c.process_payload(&participant_created(
        7,
        0,
        flags::MAY_VIEW | flags::MAY_INTERACT | flags::IS_PARTICIPANT,
    ))
    .unwrap();
    assert_eq!(c.self_id(), Some(7));
    assert_eq!(
        c.self_flags(),
        flags::MAY_VIEW | flags::MAY_INTERACT | flags::IS_PARTICIPANT
    );
    assert_eq!(c.participant_count(), 0);
    assert_eq!(
        events(&c),
        vec![Event::SelfIdentity(
            7,
            flags::MAY_VIEW | flags::MAY_INTERACT | flags::IS_PARTICIPANT,
        )]
    );
}

#[test]
fn is_participant_rebroadcast_updates_self_permissions_only_on_change() {
    let mut c = new_client();
    let initial = flags::MAY_VIEW | flags::IS_PARTICIPANT;
    let upgraded = flags::MAY_VIEW | flags::MAY_INTERACT | flags::IS_PARTICIPANT;
    c.process_payload(&participant_created(7, 0, initial)).unwrap();
    drain_events(&mut c);
    c.process_payload(&participant_created(7, 0, initial)).unwrap();
    assert_eq!(c.callback().count(), 0);
    c.process_payload(&participant_created(7, 0, upgraded)).unwrap();
    assert_eq!(events(&c), vec![Event::SelfPermissionsUpdated(upgraded)]);
    assert_eq!(c.self_flags(), upgraded);
}

#[test]
fn remote_participant_created_inserts_into_table() {
    let mut c = new_client();
    c.process_payload(&participant_created(5, 0, flags::MAY_VIEW))
        .unwrap();
    assert_eq!(c.participant_count(), 1);
    assert_eq!(c.participant(5).unwrap().flags, flags::MAY_VIEW);
    assert_eq!(
        events(&c),
        vec![Event::ParticipantCreated(5, 0, flags::MAY_VIEW)]
    );
}

#[test]
fn is_participant_unicast_with_mismatched_self_id_is_protocol_error() {
    let mut c = new_client();
    c.process_payload(&participant_created(7, 0, flags::IS_PARTICIPANT))
        .unwrap();
    drain_events(&mut c);
    // A second IS_PARTICIPANT unicast carrying a DIFFERENT id is a
    // spec violation — the self id is stable for the lifetime of the
    // SVC session (§2.2.4.1).
    let err = c
        .process_payload(&participant_created(8, 0, flags::IS_PARTICIPANT))
        .unwrap_err();
    match err {
        EncomspError::Protocol(_) => {}
        other => panic!("expected Protocol, got {other:?}"),
    }
    assert_eq!(c.self_id(), Some(7));
}

#[test]
fn remote_participant_update_replaces_friendly_name_when_non_empty() {
    let mut c = new_client();
    let initial_name = UnicodeString::from_utf16(vec![b'A' as u16]).unwrap();
    c.process_payload(&encode(&OdParticipantCreated {
        participant_id: 5,
        group_id: 0,
        flags: flags::MAY_VIEW,
        friendly_name: initial_name,
    }))
    .unwrap();
    let updated_name = UnicodeString::from_utf16(vec![b'B' as u16, b'C' as u16]).unwrap();
    c.process_payload(&encode(&OdParticipantCreated {
        participant_id: 5,
        group_id: 0,
        flags: flags::MAY_VIEW | flags::MAY_INTERACT,
        friendly_name: updated_name.clone(),
    }))
    .unwrap();
    assert_eq!(c.participant(5).unwrap().friendly_name, updated_name);
    // Update with an empty name must preserve the stored name.
    c.process_payload(&encode(&OdParticipantCreated {
        participant_id: 5,
        group_id: 0,
        flags: flags::MAY_VIEW,
        friendly_name: UnicodeString::empty(),
    }))
    .unwrap();
    assert_eq!(c.participant(5).unwrap().friendly_name, updated_name);
}

#[test]
fn remote_participant_permission_update_fires_update_not_create() {
    let mut c = new_client();
    c.process_payload(&participant_created(5, 0, flags::MAY_VIEW))
        .unwrap();
    drain_events(&mut c);
    c.process_payload(&participant_created(
        5,
        0,
        flags::MAY_VIEW | flags::MAY_INTERACT,
    ))
    .unwrap();
    assert_eq!(
        events(&c),
        vec![Event::ParticipantPermissionsUpdated(
            5,
            flags::MAY_VIEW | flags::MAY_INTERACT,
        )]
    );
    assert_eq!(
        c.participant(5).unwrap().flags,
        flags::MAY_VIEW | flags::MAY_INTERACT
    );
}

#[test]
fn participant_removed_self_id_clears_self() {
    let mut c = new_client();
    c.process_payload(&participant_created(7, 0, flags::IS_PARTICIPANT))
        .unwrap();
    drain_events(&mut c);
    c.process_payload(&participant_removed(7, 0, 0)).unwrap();
    assert_eq!(c.self_id(), None);
    assert_eq!(c.self_flags(), 0);
    assert_eq!(events(&c), vec![Event::ParticipantRemoved(7, 0, 0)]);
}

#[test]
fn participant_removed_unknown_is_silent() {
    let mut c = new_client();
    c.process_payload(&participant_removed(999, 0, 0)).unwrap();
    assert_eq!(c.callback().count(), 0);
}

// ── Graphics stream state ───────────────────────────────────────────

#[test]
fn graphics_stream_pause_resume_transitions() {
    let mut c = new_client();
    c.process_payload(&encode(&OdGraphicsStreamPaused)).unwrap();
    assert!(c.graphics_paused());
    c.process_payload(&encode(&OdGraphicsStreamPaused)).unwrap();
    c.process_payload(&encode(&OdGraphicsStreamResumed)).unwrap();
    assert!(!c.graphics_paused());
    assert_eq!(
        events(&c),
        vec![Event::GraphicsPaused, Event::GraphicsResumed]
    );
}

// ── Control request sequence ────────────────────────────────────────

#[test]
fn control_request_builder_round_trips_through_decode() {
    let c = new_client();
    let msg = c
        .build_control_request(flags::REQUEST_INTERACT | flags::REQUEST_VIEW, 7)
        .unwrap();
    assert_eq!(msg.data.len(), 10);
    assert_eq!(msg.data[0], 0x09);
    assert_eq!(msg.data[2], 0x0A);
    assert_eq!(
        u16::from_le_bytes([msg.data[4], msg.data[5]]),
        flags::REQUEST_INTERACT | flags::REQUEST_VIEW
    );
    assert_eq!(
        u32::from_le_bytes([msg.data[6], msg.data[7], msg.data[8], msg.data[9]]),
        7
    );
}

#[test]
fn wnd_show_builder_wire_layout() {
    let c = new_client();
    let msg = c.build_wnd_show(0xDEAD_BEEF).unwrap();
    assert_eq!(msg.data.len(), 8);
    assert_eq!(msg.data[0], 0x06);
    assert_eq!(msg.data[2], 0x08);
    assert_eq!(
        u32::from_le_bytes([msg.data[4], msg.data[5], msg.data[6], msg.data[7]]),
        0xDEAD_BEEF
    );
}

#[test]
fn ctrl_change_response_fires_callback_only() {
    let mut c = new_client();
    c.process_payload(&ctrl_response(
        flags::REQUEST_INTERACT | flags::REQUEST_VIEW,
        7,
        0,
    ))
    .unwrap();
    assert_eq!(
        events(&c),
        vec![Event::ControlChangeResponse(
            flags::REQUEST_INTERACT | flags::REQUEST_VIEW,
            7,
            0,
        )]
    );
    assert_eq!(c.participant_count(), 0);
    assert!(c.self_id().is_none());
}

// ── DoS caps ────────────────────────────────────────────────────────

#[test]
fn app_table_cap_rejects_overflow() {
    let mut c = new_client();
    let mut payload = Vec::new();
    for i in 0..MAX_APPLICATIONS as u32 {
        payload.extend_from_slice(&app_created(i, 0));
    }
    c.process_payload(&payload).unwrap();
    assert_eq!(c.app_count(), MAX_APPLICATIONS);
    let err = c.process_payload(&app_created(9999, 0)).unwrap_err();
    matches_table_full(err, "applications");
    // Updating an existing id still succeeds.
    c.process_payload(&app_created(0, flags::APPLICATION_SHARED))
        .unwrap();
    assert_eq!(c.app(0).unwrap().flags, flags::APPLICATION_SHARED);
}

#[test]
fn window_table_cap_rejects_overflow() {
    let mut c = new_client();
    c.process_payload(&app_created(1, 0)).unwrap();
    let mut payload = Vec::new();
    for i in 0..MAX_WINDOWS as u32 {
        payload.extend_from_slice(&wnd_created(i, 1, 0));
    }
    c.process_payload(&payload).unwrap();
    assert_eq!(c.window_count(), MAX_WINDOWS);
    let err = c.process_payload(&wnd_created(9_999_999, 1, 0)).unwrap_err();
    matches_table_full(err, "windows");
}

fn matches_table_full(err: EncomspError, expected_which: &str) {
    match err {
        EncomspError::TableFull { which, cap: _ } => assert_eq!(which, expected_which),
        other => panic!("expected TableFull, got {}", format!("{other:?}")),
    }
}

// ── Balanced-callback invariant on filter flush ─────────────────────

#[test]
fn filter_flush_is_balanced_for_windows_and_apps() {
    let mut c = new_client();
    c.process_payload(&concat(&[
        app_created(10, 0),
        app_created(20, 0),
        wnd_created(100, 10, 0),
        wnd_created(200, 20, 0),
    ]))
    .unwrap();
    drain_events(&mut c);
    c.process_payload(&filter(true)).unwrap();
    let ev = events(&c);
    let wnd_removed: Vec<_> = ev
        .iter()
        .filter_map(|e| match e {
            Event::WindowRemoved(w) => Some(*w),
            _ => None,
        })
        .collect();
    let app_removed: Vec<_> = ev
        .iter()
        .filter_map(|e| match e {
            Event::AppRemoved(a) => Some(*a),
            _ => None,
        })
        .collect();
    assert_eq!(wnd_removed.len(), 2);
    assert_eq!(app_removed.len(), 2);
    assert!(wnd_removed.contains(&100));
    assert!(wnd_removed.contains(&200));
    assert!(app_removed.contains(&10));
    assert!(app_removed.contains(&20));
}

// ── SvcProcessor integration smoke test ─────────────────────────────

#[test]
fn svc_processor_channel_name_and_start() {
    let mut c = new_client();
    assert_eq!(c.channel_name().as_str(), "encomsp");
    let msgs = c.start().unwrap();
    assert!(msgs.is_empty());
}

#[test]
fn svc_processor_process_is_empty_response() {
    let mut c = new_client();
    let msgs = c.process(&app_created(1, 0)).unwrap();
    assert!(msgs.is_empty());
    assert_eq!(c.app_count(), 1);
}

// ── Concatenated payload round-trip ─────────────────────────────────

#[test]
fn single_call_with_concatenated_payload_processes_all_pdus() {
    let mut c = new_client();
    let payload = concat(&[
        filter(true),
        app_created(1, flags::APPLICATION_SHARED),
        wnd_created(100, 1, flags::WINDOW_SHARED),
        participant_created(7, 0, flags::IS_PARTICIPANT | flags::MAY_VIEW),
    ]);
    c.process_payload(&payload).unwrap();
    assert!(c.filter_enabled());
    assert_eq!(c.app_count(), 1);
    assert_eq!(c.window_count(), 1);
    assert_eq!(c.self_id(), Some(7));
    let ev = events(&c);
    assert!(matches!(ev[0], Event::FilterStateChanged(true)));
    assert!(matches!(ev[ev.len() - 1], Event::SelfIdentity(7, _)));
}
