//! `EncomspClient` — client-side MS-RDPEMC state machine and
//! `SvcProcessor` integration for the `"encomsp"` static virtual channel.
//!
//! The client is a *participant* (viewer) in the multi-party session.
//! It receives SM→P broadcasts and maintains three lookup tables
//! (applications, windows, participants) keyed by u32 identifiers,
//! plus scalar state for the filter, graphics stream and self identity.
//!
//! The two P→SM messages (`OD_WND_SHOW`, `OD_PARTICIPANT_CTRL_CHANGE`)
//! are sent by calling [`EncomspClient::build_wnd_show`] or
//! [`EncomspClient::build_control_request`] and forwarding the returned
//! `SvcMessage`.
//!
//! **DoS caps** — `MAX_APPLICATIONS`, `MAX_WINDOWS`, `MAX_PARTICIPANTS`
//! are hard bounds on table growth; any `_CREATED` PDU that would push
//! a table past its cap is rejected with [`EncomspError::TableFull`]
//! and the process call fails. The spec does not define these limits;
//! the values are chosen to be comfortably larger than any real-world
//! shadow session.
//!
//! **Balanced-callback invariant** — every
//! [`EncomspCallback::on_window_created`] is matched by exactly one
//! [`EncomspCallback::on_window_removed`] (whether the removal is
//! explicit, cascaded by app removal, or caused by a filter reset).
//! Similarly every [`EncomspCallback::on_app_created`] matches one
//! [`EncomspCallback::on_app_removed`], and every
//! [`EncomspCallback::on_participant_created`] matches one
//! [`EncomspCallback::on_participant_removed`] *unless* the entry was
//! only ever `IS_PARTICIPANT`-unicast (self identity — see below).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcClientProcessor, SvcError, SvcMessage, SvcProcessor,
    SvcResult, ENCOMSP,
};

use crate::constants::flags;
use crate::pdu::{
    decode_all, DecodedPdu, EncomspPdu, OdParticipantCtrlChange, OdWndShow, UnicodeString,
};

/// Maximum number of applications tracked in the application table.
pub const MAX_APPLICATIONS: usize = 512;
/// Maximum number of windows tracked in the window table.
pub const MAX_WINDOWS: usize = 1024;
/// Maximum number of remote participants tracked.
pub const MAX_PARTICIPANTS: usize = 512;

// ── Entry types ──────────────────────────────────────────────────────

/// Cached state for a shared application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEntry {
    pub flags: u16,
    pub name: UnicodeString,
}

/// Cached state for a shared window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowEntry {
    pub flags: u16,
    pub app_id: u32,
    pub name: UnicodeString,
}

/// Cached state for a remote participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantEntry {
    pub group_id: u32,
    pub flags: u16,
    pub friendly_name: UnicodeString,
}

// ── Errors ───────────────────────────────────────────────────────────

/// Errors produced by [`EncomspClient`] while processing MS-RDPEMC
/// traffic.
#[derive(Debug)]
pub enum EncomspError {
    /// A PDU failed to decode.
    Decode(justrdp_core::DecodeError),
    /// Encoding a client-originated PDU failed.
    Encode(justrdp_core::EncodeError),
    /// A table reached its DoS cap.
    TableFull { which: &'static str, cap: usize },
    /// The server violated a protocol invariant the FSM tracks (e.g.
    /// an `IS_PARTICIPANT` unicast with a different `ParticipantId`
    /// than the already-established self identity).
    Protocol(&'static str),
}

impl From<EncomspError> for SvcError {
    fn from(e: EncomspError) -> Self {
        match e {
            EncomspError::Decode(d) => SvcError::Decode(d),
            EncomspError::Encode(e) => SvcError::Encode(e),
            EncomspError::TableFull { which, cap } => {
                SvcError::Protocol(alloc::format!("encomsp table full: {which} (cap={cap})"))
            }
            EncomspError::Protocol(msg) => {
                SvcError::Protocol(alloc::format!("encomsp protocol: {msg}"))
            }
        }
    }
}

impl From<justrdp_core::DecodeError> for EncomspError {
    fn from(d: justrdp_core::DecodeError) -> Self {
        Self::Decode(d)
    }
}

impl From<justrdp_core::EncodeError> for EncomspError {
    fn from(e: justrdp_core::EncodeError) -> Self {
        Self::Encode(e)
    }
}

// ── Callback trait ───────────────────────────────────────────────────

/// Event callback for [`EncomspClient`]. All methods have default no-op
/// implementations so callers only need to override the ones they care
/// about.
///
/// Ordering notes:
///
/// * When an application is removed, `on_window_removed` is called for
///   every cascading window **before** `on_app_removed` fires.
/// * When the filter state changes the client flushes both tables
///   (MS-RDPEMC Appendix A <13>) — callbacks fire in the order
///   *windows → apps → participants* before
///   [`EncomspCallback::on_filter_state_changed`] is invoked with the
///   new value.
/// * A control-level update arriving as a second
///   `OD_PARTICIPANT_CREATED` for the same `participant_id` fires
///   [`EncomspCallback::on_participant_permissions_updated`], NOT
///   another `on_participant_created`.
/// * Applications and windows do NOT have a dedicated update callback:
///   a duplicate `OD_APP_CREATED` / `OD_WND_CREATED` (same id, new
///   payload) replaces the stored record in place and fires
///   `on_app_created` / `on_window_created` a second time. Callers
///   that materialise UI state per id MUST treat a second fire as an
///   update to the existing record, not as a new entity.
pub trait EncomspCallback {
    fn on_filter_state_changed(&mut self, _enabled: bool) {}

    fn on_app_created(&mut self, _app_id: u32, _flags: u16, _name: &UnicodeString) {}
    fn on_app_removed(&mut self, _app_id: u32) {}

    fn on_window_created(
        &mut self,
        _wnd_id: u32,
        _app_id: u32,
        _flags: u16,
        _name: &UnicodeString,
    ) {
    }
    fn on_window_removed(&mut self, _wnd_id: u32) {}

    fn on_participant_created(
        &mut self,
        _participant_id: u32,
        _group_id: u32,
        _flags: u16,
        _friendly_name: &UnicodeString,
    ) {
    }
    fn on_participant_removed(&mut self, _participant_id: u32, _disc_type: u32, _disc_code: u32) {}
    fn on_participant_permissions_updated(&mut self, _participant_id: u32, _new_flags: u16) {}

    /// Fired on the first `OD_PARTICIPANT_CREATED` whose `flags`
    /// include `IS_PARTICIPANT`, establishing the receiving
    /// participant's own identity (MS-RDPEMC §2.2.4.1).
    fn on_self_identity(&mut self, _self_id: u32, _flags: u16) {}
    /// Fired when a subsequent `IS_PARTICIPANT` unicast carries updated
    /// permission flags for the existing self identity.
    fn on_self_permissions_updated(&mut self, _new_flags: u16) {}

    fn on_control_change_response(
        &mut self,
        _flags: u16,
        _participant_id: u32,
        _reason_code: u32,
    ) {
    }

    fn on_graphics_stream_paused(&mut self) {}
    fn on_graphics_stream_resumed(&mut self) {}
}

/// A [`EncomspCallback`] implementation that drops every event.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullCallback;

impl EncomspCallback for NullCallback {}

// ── Client state ─────────────────────────────────────────────────────

/// Client-side MS-RDPEMC state machine + `SvcProcessor`.
///
/// Generic over the callback type so the processor can be instantiated
/// as `EncomspClient<NullCallback>` for passive shadow sessions or
/// wrapped around a user-defined callback that owns the UI / logging
/// side effects.
pub struct EncomspClient<C: EncomspCallback> {
    callback: C,
    apps: BTreeMap<u32, AppEntry>,
    windows: BTreeMap<u32, WindowEntry>,
    participants: BTreeMap<u32, ParticipantEntry>,
    self_id: Option<u32>,
    self_flags: u16,
    filter_enabled: bool,
    graphics_paused: bool,
}

impl<C: EncomspCallback> core::fmt::Debug for EncomspClient<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncomspClient")
            .field("apps", &self.apps.len())
            .field("windows", &self.windows.len())
            .field("participants", &self.participants.len())
            .field("self_id", &self.self_id)
            .field("self_flags", &self.self_flags)
            .field("filter_enabled", &self.filter_enabled)
            .field("graphics_paused", &self.graphics_paused)
            .finish()
    }
}

impl<C: EncomspCallback + Send + core::fmt::Debug + 'static> AsAny for EncomspClient<C> {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl<C: EncomspCallback> EncomspClient<C> {
    /// Create a new client with the supplied callback.
    pub fn new(callback: C) -> Self {
        Self {
            callback,
            apps: BTreeMap::new(),
            windows: BTreeMap::new(),
            participants: BTreeMap::new(),
            self_id: None,
            self_flags: 0,
            filter_enabled: false,
            graphics_paused: false,
        }
    }

    /// Borrow the callback.
    pub fn callback(&self) -> &C {
        &self.callback
    }

    /// Mutably borrow the callback (useful in tests to drain recorded
    /// events).
    pub fn callback_mut(&mut self) -> &mut C {
        &mut self.callback
    }
}

impl EncomspClient<NullCallback> {
    /// Convenience constructor that drops all events.
    pub fn new_null() -> Self {
        Self::new(NullCallback)
    }
}

impl<C: EncomspCallback> EncomspClient<C> {

    // ── Read-only accessors ─────────────────────────────────────────

    pub fn self_id(&self) -> Option<u32> {
        self.self_id
    }
    pub fn self_flags(&self) -> u16 {
        self.self_flags
    }
    pub fn filter_enabled(&self) -> bool {
        self.filter_enabled
    }
    pub fn graphics_paused(&self) -> bool {
        self.graphics_paused
    }
    pub fn app(&self, app_id: u32) -> Option<&AppEntry> {
        self.apps.get(&app_id)
    }
    pub fn window(&self, wnd_id: u32) -> Option<&WindowEntry> {
        self.windows.get(&wnd_id)
    }
    pub fn participant(&self, pid: u32) -> Option<&ParticipantEntry> {
        self.participants.get(&pid)
    }
    pub fn app_count(&self) -> usize {
        self.apps.len()
    }
    pub fn window_count(&self) -> usize {
        self.windows.len()
    }
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    // ── Outbound P→SM PDU builders ─────────────────────────────────

    /// Encode an `OD_WND_SHOW` (§2.2.3.6) for the caller to forward on
    /// the SVC. The sharing manager will ignore the request unless the
    /// participant has `MAY_INTERACT` (Appendix A <27>); the client does
    /// not perform that check — it is a pure request.
    pub fn build_wnd_show(&self, wnd_id: u32) -> Result<SvcMessage, EncomspError> {
        encode_to_message(&OdWndShow { wnd_id })
    }

    /// Encode an `OD_PARTICIPANT_CTRL_CHANGE` (§2.2.4.3). `flags` must
    /// be some combination of `REQUEST_VIEW` / `REQUEST_INTERACT` from
    /// [`crate::constants::flags`]; `participant_id` is the id of the
    /// participant whose permissions are being requested, which for
    /// self-initiated upgrades is [`self_id`](Self::self_id).
    pub fn build_control_request(
        &self,
        flags: u16,
        participant_id: u32,
    ) -> Result<SvcMessage, EncomspError> {
        encode_to_message(&OdParticipantCtrlChange {
            flags,
            participant_id,
        })
    }

    // ── Inbound SM→P handling ──────────────────────────────────────

    /// Process one MS-RDPEMC payload from the `"encomsp"` SVC, driving
    /// the callback and the internal state tables. Multiple PDUs may
    /// be concatenated in `payload`.
    pub fn process_payload(&mut self, payload: &[u8]) -> Result<(), EncomspError> {
        let mut cursor = ReadCursor::new(payload);
        let pdus = decode_all(&mut cursor)?;
        for slot in pdus {
            match slot {
                DecodedPdu::Known(pdu) => self.apply(pdu)?,
                DecodedPdu::Skipped { .. } => {
                    // Forward-compat: unknown types are ignored
                    // silently (MS-RDPEMC §3.1.5.1, Appendix A <7>).
                }
            }
        }
        Ok(())
    }

    fn apply(&mut self, pdu: EncomspPdu) -> Result<(), EncomspError> {
        match pdu {
            EncomspPdu::FilterStateUpdated(p) => self.apply_filter(p.flags),
            EncomspPdu::AppCreated(p) => self.apply_app_created(p.app_id, p.flags, p.name)?,
            EncomspPdu::AppRemoved(p) => self.apply_app_removed(p.app_id),
            EncomspPdu::WndCreated(p) => {
                self.apply_window_created(p.wnd_id, p.app_id, p.flags, p.name)?
            }
            EncomspPdu::WndRemoved(p) => self.apply_window_removed(p.wnd_id),
            EncomspPdu::WndShow(_) => {
                // P→SM message received from the server. The spec does
                // not describe this direction and Windows sharing
                // managers do not echo it; silently ignore.
            }
            EncomspPdu::WndRegionUpdate(_) => {
                // Windows sharing managers never send this (Appendix
                // A <5>) and the wire form has no window binding;
                // decoded for forward compatibility only.
            }
            EncomspPdu::ParticipantCreated(p) => {
                self.apply_participant_created(p.participant_id, p.group_id, p.flags, p.friendly_name)?
            }
            EncomspPdu::ParticipantRemoved(p) => {
                self.apply_participant_removed(p.participant_id, p.disc_type, p.disc_code)
            }
            EncomspPdu::ParticipantCtrlChange(_) => {
                // P→SM message received from the server; silently
                // ignore — the client only *sends* this type.
            }
            EncomspPdu::ParticipantCtrlChangeResponse(p) => {
                self.callback
                    .on_control_change_response(p.flags, p.participant_id, p.reason_code);
            }
            EncomspPdu::GraphicsStreamPaused(_) => {
                if !self.graphics_paused {
                    self.graphics_paused = true;
                    self.callback.on_graphics_stream_paused();
                }
            }
            EncomspPdu::GraphicsStreamResumed(_) => {
                if self.graphics_paused {
                    self.graphics_paused = false;
                    self.callback.on_graphics_stream_resumed();
                }
            }
        }
        Ok(())
    }

    // ── Filter ─────────────────────────────────────────────────────

    fn apply_filter(&mut self, wire_flags: u8) {
        let enabled = wire_flags & flags::FILTER_ENABLED != 0;
        if enabled == self.filter_enabled {
            // State unchanged; spec says the sharing manager re-sends
            // the whole app/window set after any filter state change
            // (Appendix A <13>), so a no-op filter PDU is a no-op here.
            return;
        }
        // Flush caches in dependency order (windows → apps →
        // participants) so callbacks see consistent state.
        self.flush_all_tables();
        self.filter_enabled = enabled;
        self.callback.on_filter_state_changed(enabled);
    }

    fn flush_all_tables(&mut self) {
        // Windows first — each removal stands on its own, independent
        // of which app it belonged to.
        let wnd_ids: Vec<u32> = self.windows.keys().copied().collect();
        for wnd_id in wnd_ids {
            self.windows.remove(&wnd_id);
            self.callback.on_window_removed(wnd_id);
        }
        // Then apps.
        let app_ids: Vec<u32> = self.apps.keys().copied().collect();
        for app_id in app_ids {
            self.apps.remove(&app_id);
            self.callback.on_app_removed(app_id);
        }
        // Then remote participants. Self identity is NOT cleared —
        // self_id / self_flags are tied to the SVC session, not to the
        // filter state.
        let pids: Vec<u32> = self.participants.keys().copied().collect();
        for pid in pids {
            self.participants.remove(&pid);
            // disc_type/disc_code are unknown here; use 0/0 by
            // convention. Windows receivers do not parse these values
            // (Appendix A <21>), and this is a client-synthesized
            // removal for a bulk flush.
            self.callback.on_participant_removed(pid, 0, 0);
        }
    }

    // ── Apps ───────────────────────────────────────────────────────

    fn apply_app_created(
        &mut self,
        app_id: u32,
        flags: u16,
        name: UnicodeString,
    ) -> Result<(), EncomspError> {
        if !self.apps.contains_key(&app_id) && self.apps.len() >= MAX_APPLICATIONS {
            return Err(EncomspError::TableFull {
                which: "applications",
                cap: MAX_APPLICATIONS,
            });
        }
        // Replace-or-insert: duplicate AppId replaces the existing
        // record (MS-RDPEMC §3.1.5.3). Windows that reference this app
        // are untouched — the spec does not require the sharing
        // manager to re-announce them on app update.
        self.apps.insert(
            app_id,
            AppEntry {
                flags,
                name: name.clone(),
            },
        );
        self.callback.on_app_created(app_id, flags, &name);
        Ok(())
    }

    fn apply_app_removed(&mut self, app_id: u32) {
        if self.apps.remove(&app_id).is_none() {
            // Unknown AppId → silently discard (§3.1.5.3).
            return;
        }
        // Cascade-remove all windows belonging to this app and fire
        // `on_window_removed` for each BEFORE firing `on_app_removed`
        // (MS-RDPEMC §3.1.5.3).
        let orphaned: Vec<u32> = self
            .windows
            .iter()
            .filter_map(|(wnd_id, entry)| (entry.app_id == app_id).then_some(*wnd_id))
            .collect();
        for wnd_id in orphaned {
            self.windows.remove(&wnd_id);
            self.callback.on_window_removed(wnd_id);
        }
        self.callback.on_app_removed(app_id);
    }

    // ── Windows ────────────────────────────────────────────────────

    fn apply_window_created(
        &mut self,
        wnd_id: u32,
        app_id: u32,
        flags: u16,
        name: UnicodeString,
    ) -> Result<(), EncomspError> {
        if !self.windows.contains_key(&wnd_id) && self.windows.len() >= MAX_WINDOWS {
            return Err(EncomspError::TableFull {
                which: "windows",
                cap: MAX_WINDOWS,
            });
        }
        // Duplicate WndId replaces the existing record (§3.1.5.3). We
        // do NOT fire on_window_removed for the old record because the
        // spec models this as an update, not a remove+create.
        self.windows.insert(
            wnd_id,
            WindowEntry {
                flags,
                app_id,
                name: name.clone(),
            },
        );
        self.callback.on_window_created(wnd_id, app_id, flags, &name);
        Ok(())
    }

    fn apply_window_removed(&mut self, wnd_id: u32) {
        if self.windows.remove(&wnd_id).is_none() {
            // Unknown WndId → silently discard (§3.1.5.3).
            return;
        }
        self.callback.on_window_removed(wnd_id);
    }

    // ── Participants ──────────────────────────────────────────────

    fn apply_participant_created(
        &mut self,
        participant_id: u32,
        group_id: u32,
        pdu_flags: u16,
        friendly_name: UnicodeString,
    ) -> Result<(), EncomspError> {
        // IS_PARTICIPANT unicast: establishes OR updates the receiving
        // participant's own identity (§2.2.4.1). Self-identity entries
        // are NOT inserted into the `participants` table because the
        // spec treats the self unicast as a private channel; that
        // table holds *remote* participants only.
        if pdu_flags & flags::IS_PARTICIPANT != 0 {
            // `friendly_name` is not stored for self identity: the
            // spec does not define a self-name field on the client
            // side, and the name is carried only for symmetry with
            // the remote-participant path.
            let _ = friendly_name;
            match self.self_id {
                None => {
                    self.self_id = Some(participant_id);
                    self.self_flags = pdu_flags;
                    self.callback.on_self_identity(participant_id, pdu_flags);
                }
                Some(existing) if existing == participant_id => {
                    // Re-unicast with the same id is a permission
                    // update after a granted CTRL_CHANGE.
                    if self.self_flags != pdu_flags {
                        self.self_flags = pdu_flags;
                        self.callback.on_self_permissions_updated(pdu_flags);
                    }
                }
                Some(_other) => {
                    // Self id is stable for the lifetime of the SVC
                    // session (§2.2.4.1) — an `IS_PARTICIPANT` unicast
                    // that carries a different ParticipantId is a
                    // protocol violation. Surface it as an error so
                    // the caller can tear down the channel.
                    return Err(EncomspError::Protocol(
                        "IS_PARTICIPANT unicast with mismatched self id",
                    ));
                }
            }
            return Ok(());
        }

        // Remote-participant branch.
        let is_new = !self.participants.contains_key(&participant_id);
        if is_new && self.participants.len() >= MAX_PARTICIPANTS {
            return Err(EncomspError::TableFull {
                which: "participants",
                cap: MAX_PARTICIPANTS,
            });
        }

        if is_new {
            self.participants.insert(
                participant_id,
                ParticipantEntry {
                    group_id,
                    flags: pdu_flags,
                    friendly_name: friendly_name.clone(),
                },
            );
            self.callback
                .on_participant_created(participant_id, group_id, pdu_flags, &friendly_name);
        } else if let Some(entry) = self.participants.get_mut(&participant_id) {
            // Existing id → permission update. Replace group_id and
            // flags; preserve the stored friendly_name unless the new
            // PDU carries a non-empty one (spec allows both).
            entry.group_id = group_id;
            let changed = entry.flags != pdu_flags;
            entry.flags = pdu_flags;
            if !friendly_name.is_empty() {
                entry.friendly_name = friendly_name;
            }
            if changed {
                self.callback
                    .on_participant_permissions_updated(participant_id, pdu_flags);
            }
        }
        Ok(())
    }

    fn apply_participant_removed(&mut self, participant_id: u32, disc_type: u32, disc_code: u32) {
        // A removal may target either the self identity or a remote
        // participant. Self-identity removal clears `self_id`; remote
        // removal drops the table row. In both cases the callback is
        // invoked with the disc_type / disc_code from the PDU (Windows
        // receivers ignore these fields per Appendix A <21>, but we
        // surface them for parity).
        if self.self_id == Some(participant_id) {
            self.self_id = None;
            self.self_flags = 0;
            self.callback
                .on_participant_removed(participant_id, disc_type, disc_code);
            return;
        }
        if self.participants.remove(&participant_id).is_some() {
            self.callback
                .on_participant_removed(participant_id, disc_type, disc_code);
        }
        // Unknown id → silently discard.
    }
}

// ── SvcProcessor glue ────────────────────────────────────────────────

impl<C> SvcProcessor for EncomspClient<C>
where
    C: EncomspCallback + Send + core::fmt::Debug + 'static,
{
    fn channel_name(&self) -> ChannelName {
        ENCOMSP
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        // Client waits for the sharing manager to populate state.
        Ok(Vec::new())
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        self.process_payload(payload)?;
        // All P→SM traffic is user-initiated via the build_* helpers;
        // processing an SM→P payload never produces automatic
        // responses.
        Ok(Vec::new())
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

impl<C> SvcClientProcessor for EncomspClient<C> where
    C: EncomspCallback + Send + core::fmt::Debug + 'static
{
}

// ── Helpers ──────────────────────────────────────────────────────────

fn encode_to_message<T: Encode>(pdu: &T) -> Result<SvcMessage, EncomspError> {
    let mut buf = alloc::vec![0u8; pdu.size()];
    {
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor)?;
    }
    Ok(SvcMessage::new(buf))
}

