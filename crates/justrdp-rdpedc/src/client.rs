//! Client-side processor for MS-RDPEDC orders.
//!
//! `RdpedcClient` consumes a stream of MS-RDPEDC Alternate Secondary
//! Orders (as they arrive multiplexed inside RDP Update PDUs), updates
//! an internal composition-mode FSM and two surface tables, and fires
//! callbacks into a user-supplied [`CompDeskCallback`] so the host
//! drawing layer can react.
//!
//! ## State
//!
//! - **Composition mode** — `Off` (initial) / `On { dwm_desk: bool }`.
//!   Mode changes on `TS_COMPDESK_TOGGLE`; when entering `Off` all
//!   surface tables are cleared (the spec says the client should
//!   release all composition state when leaving composition mode).
//! - **Logical surface table** — `BTreeMap<u64, LogicalSurface>`.
//! - **Redirection surface table** — `BTreeMap<u32, RedirSurface>`.
//!   Key is the 31-bit `cacheId`; the create/destroy discriminator
//!   (bit 31) is stripped by the PDU decoder.
//!
//! ## DoS caps
//!
//! The spec does not bound the number of surfaces. We enforce two
//! limits so a malicious server cannot drive unbounded growth:
//!
//! - [`MAX_LOGICAL_SURFACES`]  = 4096
//! - [`MAX_REDIR_SURFACES`]    = 4096
//!
//! Exceeding either cap returns [`RdpedcError::TooManySurfaces`] from
//! [`RdpedcClient::process_order`]. The caller decides whether to tear
//! down the session.

use alloc::collections::BTreeMap;

use justrdp_core::ReadCursor;

use crate::constants::ALT_SEC_HEADER_BYTE;
use crate::pdu::{
    decode_any, CompDeskPdu, CompDeskToggle, EventType, FlushComposeOnce, LSurfaceCompRefPending,
    LSurfaceCreateDestroy, LSurfaceFlags, RedirSurfAssocLSurface, SurfObjCreateDestroy,
    SwitchSurfObj, COMMON_HEADER_SIZE,
};

// ── DoS caps ─────────────────────────────────────────────────────────

/// Maximum number of live logical surfaces the client will track.
pub const MAX_LOGICAL_SURFACES: usize = 4096;
/// Maximum number of live redirection surfaces the client will track.
pub const MAX_REDIR_SURFACES: usize = 4096;

// ── Error type ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpedcError {
    /// The buffer ended before a full PDU could be read. Typically a
    /// framing issue in the outer caller (e.g. the Update PDU was
    /// fragmented) rather than a server protocol violation.
    UnexpectedEof,
    /// The first byte of the order was not [`ALT_SEC_HEADER_BYTE`]
    /// (`0x32`); the caller passed a non-MS-RDPEDC order.
    InvalidHeader,
    /// A known-op PDU body failed to decode — wrong size, invalid
    /// field, or reserved value. Contains the operation code of the
    /// offending PDU so post-mortem diagnostics can attribute the
    /// failure to a specific message type.
    DecodeBody { operation: u8 },
    /// A surface table would exceed its per-client cap.
    TooManySurfaces,
}

// ── Client-visible state types ───────────────────────────────────────

/// Composition-mode FSM value (MS-RDPEDC §3.2.5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionMode {
    /// Initial state; DWM composition not active.
    Off,
    /// Server has entered composition mode. `dwm_desk` is `true` when
    /// the server is also on a composed desktop (after
    /// `REDIRMODE_DWM_DESK_ENTER`), `false` otherwise.
    On { dwm_desk: bool },
}

/// Live logical-surface entry (MS-RDPEDC §3.2.5.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogicalSurface {
    pub flags: LSurfaceFlags,
    pub hwnd: u64,
    /// Set to `true` when the server has sent
    /// `TS_COMPDESK_LSURFACE_COMPREF_PENDING` for this surface. The
    /// host drawing layer MUST NOT release its proxy for the surface
    /// while this flag is set (MS-RDPEDC §3.2.5.2.4).
    pub compref_pending: bool,
}

/// Live redirection-surface entry (MS-RDPEDC §3.2.5.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirSurface {
    pub surface_bpp: u8,
    pub h_surf: u64,
    pub cx: u32,
    pub cy: u32,
    /// `hLSurface` the redirection surface is currently associated
    /// with, or `None` if disassociated.
    pub assoc_lsurface: Option<u64>,
}

// ── Host callback trait ──────────────────────────────────────────────

/// Host-side hook for drawing-layer side effects.
///
/// Every method has a default no-op implementation so hosts can opt
/// into only the events they care about.
///
/// ## Invocation contract
///
/// - Callbacks fire **after** the client's internal state has been
///   updated, so a callback may query the client back via its getters
///   (`mode`, `logical_surface`, `redir_surface`, ...) and see the
///   post-event state.
/// - All surface-naming callbacks only fire when the surface is known
///   to the client — either just created, or already in the table.
///   A PDU that names an unknown surface is silently dropped and does
///   not reach the callback layer. This means callback implementations
///   can assume every id they receive was valid at the moment of the
///   call.
/// - Ordering for create-over-existing: if a server sends
///   `LSURFACE create` or `SURFOBJ create` for a key that is already
///   in the table, the existing entry is first destroyed (its
///   destroy callback fires, redirection-surface `assoc_lsurface`
///   references are cleared) and then the fresh entry is inserted
///   (its create callback fires). Callback consumers therefore never
///   observe a silent replacement.
pub trait CompDeskCallback {
    fn on_mode_changed(&mut self, _mode: CompositionMode) {}
    fn on_logical_surface_created(&mut self, _h_lsurface: u64, _entry: &LogicalSurface) {}
    /// Called after a logical surface has been removed from the table.
    ///
    /// **Important**: the destroyed entry may have had
    /// `compref_pending = true` at the time of destruction. Per
    /// MS-RDPEDC §3.2.5.2.4, the host drawing layer MUST NOT release
    /// its proxy for the surface until the compositor releases its
    /// own reference. A host callback that unconditionally releases
    /// resources on destroy will violate that rule. The host MUST
    /// track `compref_pending` separately if it cares about proxy
    /// lifetime — this callback fires regardless.
    fn on_logical_surface_destroyed(&mut self, _h_lsurface: u64) {}
    fn on_redir_surface_created(&mut self, _cache_id: u32, _entry: &RedirSurface) {}
    fn on_redir_surface_destroyed(&mut self, _cache_id: u32) {}
    fn on_redir_surface_associated(&mut self, _cache_id: u32, _h_lsurface: u64) {}
    fn on_redir_surface_disassociated(&mut self, _cache_id: u32) {}
    fn on_compref_pending(&mut self, _h_lsurface: u64) {}
    /// Drawing is being retargeted at `cache_id` until the next
    /// `SWITCH_SURFOBJ` or `FLUSH_COMPOSEONCE`. Only fires when
    /// `cache_id` names a live redirection surface.
    fn on_switch_draw_target(&mut self, _cache_id: u32) {}
    /// A compose-once draw cycle for `cache_id` / `h_lsurface` is done.
    /// Only fires when `cache_id` names a live redirection surface.
    fn on_flush_compose_once(&mut self, _cache_id: u32, _h_lsurface: u64) {}
}

/// No-op callback useful for tests and host code that only cares about
/// the processor's observable state.
#[derive(Debug, Default)]
pub struct NullCallback;

impl CompDeskCallback for NullCallback {}

// ── Processor ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RdpedcClient {
    mode: CompositionMode,
    logical_surfaces: BTreeMap<u64, LogicalSurface>,
    redir_surfaces: BTreeMap<u32, RedirSurface>,
    /// `cache_id` most recently handed to a `SWITCH_SURFOBJ`, or
    /// `None` if no retargeting is active.
    current_draw_target: Option<u32>,
}

impl Default for RdpedcClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RdpedcClient {
    pub fn new() -> Self {
        Self {
            mode: CompositionMode::Off,
            logical_surfaces: BTreeMap::new(),
            redir_surfaces: BTreeMap::new(),
            current_draw_target: None,
        }
    }

    pub fn mode(&self) -> CompositionMode {
        self.mode
    }

    pub fn logical_surface(&self, h_lsurface: u64) -> Option<&LogicalSurface> {
        self.logical_surfaces.get(&h_lsurface)
    }

    pub fn redir_surface(&self, cache_id: u32) -> Option<&RedirSurface> {
        self.redir_surfaces.get(&cache_id)
    }

    pub fn current_draw_target(&self) -> Option<u32> {
        self.current_draw_target
    }

    // Test-only accounting helpers. The public surface does not
    // expose internal table sizes because call-site semantics are
    // better served by `logical_surface(id).is_some()` membership
    // checks.
    #[cfg(test)]
    pub(crate) fn logical_len(&self) -> usize {
        self.logical_surfaces.len()
    }

    #[cfg(test)]
    pub(crate) fn redir_len(&self) -> usize {
        self.redir_surfaces.len()
    }

    /// Parse and apply a single MS-RDPEDC order from `bytes`.
    ///
    /// Returns the number of bytes consumed on success so the caller
    /// can walk a batched Update PDU that mixes MS-RDPEDC orders with
    /// other alternate-secondary orders.
    ///
    /// Forward compatibility: if the order has the MS-RDPEDC header
    /// byte (`0x32`) but an unknown `operation` code, the order is
    /// skipped by consuming `4 + size` bytes rather than tearing down
    /// the stream. This matches checklist §12 — a future spec revision
    /// may introduce op codes beyond `0x07`, and a strict client would
    /// break interop against such servers.
    pub fn process_order<C: CompDeskCallback>(
        &mut self,
        bytes: &[u8],
        cb: &mut C,
    ) -> Result<usize, RdpedcError> {
        if bytes.len() < COMMON_HEADER_SIZE {
            return Err(RdpedcError::UnexpectedEof);
        }
        if bytes[0] != ALT_SEC_HEADER_BYTE {
            return Err(RdpedcError::InvalidHeader);
        }
        let operation = bytes[1];
        let body_size = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let total = COMMON_HEADER_SIZE + body_size;
        if bytes.len() < total {
            return Err(RdpedcError::UnexpectedEof);
        }
        // Skip unknown op codes per checklist §12 forward-compat rule.
        if !(0x01..=0x07).contains(&operation) {
            return Ok(total);
        }
        let mut cur = ReadCursor::new(&bytes[..total]);
        let pdu =
            decode_any(&mut cur).map_err(|_| RdpedcError::DecodeBody { operation })?;
        self.apply(pdu, cb)?;
        Ok(total)
    }

    /// Apply an already-decoded PDU. Exposed mostly for tests and for
    /// callers that do their own dispatch.
    pub fn apply<C: CompDeskCallback>(
        &mut self,
        pdu: CompDeskPdu,
        cb: &mut C,
    ) -> Result<(), RdpedcError> {
        match pdu {
            CompDeskPdu::Toggle(p) => self.apply_toggle(p, cb),
            CompDeskPdu::LSurface(p) => self.apply_lsurface(p, cb),
            CompDeskPdu::SurfObj(p) => self.apply_surfobj(p, cb),
            CompDeskPdu::RedirSurfAssoc(p) => self.apply_assoc(p, cb),
            CompDeskPdu::CompRefPending(p) => self.apply_compref(p, cb),
            CompDeskPdu::Switch(p) => self.apply_switch(p, cb),
            CompDeskPdu::Flush(p) => self.apply_flush(p, cb),
        }
    }

    fn apply_toggle<C: CompDeskCallback>(
        &mut self,
        pdu: CompDeskToggle,
        cb: &mut C,
    ) -> Result<(), RdpedcError> {
        let prev = self.mode;
        let next = match (prev, pdu.event_type) {
            // Reserved / ignored values: spec says SHOULD be ignored.
            (_, EventType::Reserved1) | (_, EventType::Reserved2) => return Ok(()),
            // Duplicate CompositionOn while already On is silently
            // ignored per spec §2.2.1 — without this narrowing, a
            // redundant CompositionOn would clobber `dwm_desk: true`.
            (CompositionMode::On { .. }, EventType::CompositionOn) => return Ok(()),
            (CompositionMode::Off, EventType::CompositionOn) => {
                CompositionMode::On { dwm_desk: false }
            }
            (_, EventType::CompositionOff) => {
                // Leaving composition mode: drop all surface state.
                self.logical_surfaces.clear();
                self.redir_surfaces.clear();
                self.current_draw_target = None;
                CompositionMode::Off
            }
            (CompositionMode::On { .. }, EventType::DwmDeskEnter) => {
                CompositionMode::On { dwm_desk: true }
            }
            (CompositionMode::On { .. }, EventType::DwmDeskLeave) => {
                CompositionMode::On { dwm_desk: false }
            }
            // DWM sub-mode events while Off: spec says toggles are
            // silently ignored in the wrong state.
            (CompositionMode::Off, EventType::DwmDeskEnter)
            | (CompositionMode::Off, EventType::DwmDeskLeave) => return Ok(()),
        };
        if next != prev {
            self.mode = next;
            cb.on_mode_changed(next);
        }
        Ok(())
    }

    /// Remove a logical surface, detach any redirection surfaces that
    /// referenced it, and fire the destroy callback. Factored out so
    /// the "create over existing" branch in [`Self::apply_lsurface`]
    /// can reuse the exact same cleanup as an explicit destroy —
    /// otherwise a server sending two creates with the same
    /// `h_lsurface` would silently drop the old entry without firing
    /// `on_logical_surface_destroyed` and without detaching dangling
    /// `assoc_lsurface` references on redirection surfaces.
    ///
    /// Callback ordering: every redirection surface whose
    /// `assoc_lsurface` is cleared by this function fires its own
    /// `on_redir_surface_disassociated` callback **before** the
    /// logical surface's `on_logical_surface_destroyed` fires. This
    /// keeps the associate/disassociate callback pairs balanced from
    /// the host's perspective: every `on_redir_surface_associated`
    /// call is eventually matched by exactly one disassociated call,
    /// regardless of whether the disassociation happened via an
    /// explicit `REDIRSURF_ASSOC` PDU or via the logical surface
    /// being destroyed out from under it.
    fn destroy_logical_surface_internal<C: CompDeskCallback>(
        &mut self,
        h_lsurface: u64,
        cb: &mut C,
    ) {
        if self.logical_surfaces.remove(&h_lsurface).is_none() {
            return;
        }
        // First pass: collect the cache_ids whose assoc_lsurface we
        // need to clear. We can't mutate the map and fire callbacks in
        // the same loop without running into the `&mut self` /
        // `&mut C` borrow conflict, and a collection avoids it.
        let mut detached: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
        for (&cache_id, entry) in self.redir_surfaces.iter_mut() {
            if entry.assoc_lsurface == Some(h_lsurface) {
                entry.assoc_lsurface = None;
                detached.push(cache_id);
            }
        }
        for cache_id in detached {
            cb.on_redir_surface_disassociated(cache_id);
        }
        cb.on_logical_surface_destroyed(h_lsurface);
    }

    /// Remove a redirection surface, clear it from `current_draw_target`
    /// if active, and fire the destroy callback. See
    /// [`Self::destroy_logical_surface_internal`] for rationale.
    fn destroy_redir_surface_internal<C: CompDeskCallback>(
        &mut self,
        cache_id: u32,
        cb: &mut C,
    ) {
        if self.redir_surfaces.remove(&cache_id).is_some() {
            if self.current_draw_target == Some(cache_id) {
                self.current_draw_target = None;
            }
            cb.on_redir_surface_destroyed(cache_id);
        }
    }

    fn apply_lsurface<C: CompDeskCallback>(
        &mut self,
        pdu: LSurfaceCreateDestroy,
        cb: &mut C,
    ) -> Result<(), RdpedcError> {
        if pdu.create {
            // Create-over-existing: run the full destroy path first so
            // the stale entry is cleanly torn down (destroy callback
            // fires, redir assoc_lsurface references are cleared)
            // before the fresh entry replaces it. Without this step a
            // malicious or buggy server could cycle the same
            // `h_lsurface` and suppress destroy notifications
            // indefinitely while accumulating stale redir associations.
            //
            // The cap check is intentionally skipped on the replace
            // path: `destroy` drops the old entry, so the table goes
            // N → N-1 → N across the two operations and the cap
            // invariant (`len <= MAX_LOGICAL_SURFACES`) still holds.
            if self.logical_surfaces.contains_key(&pdu.h_lsurface) {
                self.destroy_logical_surface_internal(pdu.h_lsurface, cb);
            } else if self.logical_surfaces.len() >= MAX_LOGICAL_SURFACES {
                return Err(RdpedcError::TooManySurfaces);
            }
            let entry = LogicalSurface {
                flags: pdu.flags,
                hwnd: pdu.hwnd,
                compref_pending: false,
            };
            self.logical_surfaces.insert(pdu.h_lsurface, entry);
            cb.on_logical_surface_created(pdu.h_lsurface, &entry);
        } else {
            self.destroy_logical_surface_internal(pdu.h_lsurface, cb);
        }
        Ok(())
    }

    fn apply_surfobj<C: CompDeskCallback>(
        &mut self,
        pdu: SurfObjCreateDestroy,
        cb: &mut C,
    ) -> Result<(), RdpedcError> {
        if pdu.create {
            // Create-over-existing: same tear-down-first semantics as
            // the logical-surface path. Cap check skipped on replace
            // for the same reason — net size delta is zero.
            if self.redir_surfaces.contains_key(&pdu.cache_id) {
                self.destroy_redir_surface_internal(pdu.cache_id, cb);
            } else if self.redir_surfaces.len() >= MAX_REDIR_SURFACES {
                return Err(RdpedcError::TooManySurfaces);
            }
            let entry = RedirSurface {
                surface_bpp: pdu.surface_bpp,
                h_surf: pdu.h_surf,
                cx: pdu.cx,
                cy: pdu.cy,
                assoc_lsurface: None,
            };
            self.redir_surfaces.insert(pdu.cache_id, entry);
            cb.on_redir_surface_created(pdu.cache_id, &entry);
        } else {
            self.destroy_redir_surface_internal(pdu.cache_id, cb);
        }
        Ok(())
    }

    fn apply_assoc<C: CompDeskCallback>(
        &mut self,
        pdu: RedirSurfAssocLSurface,
        cb: &mut C,
    ) -> Result<(), RdpedcError> {
        // The association is keyed by `hSurf`, but the redir table is
        // keyed by 31-bit `cacheId`. Walk the table to find the entry
        // whose `h_surf` matches. Unknown surfaces are silently ignored
        // per the checklist.
        let mut matched: Option<u32> = None;
        for (&cache_id, entry) in self.redir_surfaces.iter_mut() {
            if entry.h_surf == pdu.h_surf {
                if pdu.associate {
                    // Only honor the association when the target
                    // logical surface exists; otherwise ignore.
                    if self.logical_surfaces.contains_key(&pdu.h_lsurface) {
                        entry.assoc_lsurface = Some(pdu.h_lsurface);
                        matched = Some(cache_id);
                    }
                } else {
                    entry.assoc_lsurface = None;
                    matched = Some(cache_id);
                }
                break;
            }
        }
        if let Some(cache_id) = matched {
            if pdu.associate {
                cb.on_redir_surface_associated(cache_id, pdu.h_lsurface);
            } else {
                cb.on_redir_surface_disassociated(cache_id);
            }
        }
        Ok(())
    }

    fn apply_compref<C: CompDeskCallback>(
        &mut self,
        pdu: LSurfaceCompRefPending,
        cb: &mut C,
    ) -> Result<(), RdpedcError> {
        if let Some(entry) = self.logical_surfaces.get_mut(&pdu.h_lsurface) {
            entry.compref_pending = true;
            cb.on_compref_pending(pdu.h_lsurface);
        }
        Ok(())
    }

    fn apply_switch<C: CompDeskCallback>(
        &mut self,
        pdu: SwitchSurfObj,
        cb: &mut C,
    ) -> Result<(), RdpedcError> {
        // `SwitchSurfObj::decode` already rejects bit 31, so the id
        // is always a clean 31-bit value here.
        if self.redir_surfaces.contains_key(&pdu.cache_id) {
            self.current_draw_target = Some(pdu.cache_id);
            cb.on_switch_draw_target(pdu.cache_id);
        }
        // Targeting an unknown surface is silently ignored (spec-
        // permitted forward compatibility path).
        Ok(())
    }

    fn apply_flush<C: CompDeskCallback>(
        &mut self,
        pdu: FlushComposeOnce,
        cb: &mut C,
    ) -> Result<(), RdpedcError> {
        // Only act on known redirection surfaces AND known logical
        // surfaces. A server sending a FLUSH for a phantom `cache_id`
        // or a fabricated `h_lsurface` would otherwise hand attacker-
        // controlled ids to the host callback — mirror the guard in
        // `apply_switch` so the callback contract is uniform and both
        // u32/u64 arguments are guaranteed to name live table
        // entries.
        //
        // Note: the spec (§3.2.5.3.2) says FLUSH_COMPOSEONCE SHOULD
        // only arrive for logical surfaces with the
        // `TS_COMPDESK_HLSURF_COMPOSEONCE` flag set. We intentionally
        // do NOT validate that flag here — the spec only says SHOULD
        // and gives no enforcement requirement, so log-and-forward is
        // appropriate for the flag check while still validating
        // identity.
        if !self.redir_surfaces.contains_key(&pdu.cache_id)
            || !self.logical_surfaces.contains_key(&pdu.h_lsurface)
        {
            return Ok(());
        }
        // `flush` ends the currently active draw target; the next
        // drawing batch needs its own SWITCH to retarget.
        if self.current_draw_target == Some(pdu.cache_id) {
            self.current_draw_target = None;
        }
        cb.on_flush_compose_once(pdu.cache_id, pdu.h_lsurface);
        Ok(())
    }
}

// ── Order stream walker ──────────────────────────────────────────────

/// `true` if the first byte of `bytes` is [`ALT_SEC_HEADER_BYTE`].
/// Implementation detail of [`process_batch`].
pub(crate) fn peek_is_rdpedc_order(bytes: &[u8]) -> bool {
    bytes.first().copied() == Some(ALT_SEC_HEADER_BYTE)
}

/// Process every MS-RDPEDC order in `bytes`, stopping at the first
/// non-MS-RDPEDC byte or end of slice. Returns the number of bytes
/// consumed.
pub fn process_batch<C: CompDeskCallback>(
    client: &mut RdpedcClient,
    bytes: &[u8],
    cb: &mut C,
) -> Result<usize, RdpedcError> {
    let mut offset = 0;
    while offset < bytes.len() && peek_is_rdpedc_order(&bytes[offset..]) {
        if bytes.len() - offset < COMMON_HEADER_SIZE {
            return Err(RdpedcError::UnexpectedEof);
        }
        let consumed = client.process_order(&bytes[offset..], cb)?;
        offset += consumed;
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{CompDeskToggle, EventType};
    use alloc::vec;
    use alloc::vec::Vec;

    // ── Test callback: records every event in order. ─────────────────

    #[derive(Debug, Default)]
    struct RecCallback {
        events: Vec<Event>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Mode(CompositionMode),
        LCreated(u64),
        LDestroyed(u64),
        RCreated(u32),
        RDestroyed(u32),
        Assoc(u32, u64),
        Disassoc(u32),
        CompRef(u64),
        Switch(u32),
        Flush(u32, u64),
    }

    impl CompDeskCallback for RecCallback {
        fn on_mode_changed(&mut self, mode: CompositionMode) {
            self.events.push(Event::Mode(mode));
        }
        fn on_logical_surface_created(&mut self, h: u64, _e: &LogicalSurface) {
            self.events.push(Event::LCreated(h));
        }
        fn on_logical_surface_destroyed(&mut self, h: u64) {
            self.events.push(Event::LDestroyed(h));
        }
        fn on_redir_surface_created(&mut self, c: u32, _e: &RedirSurface) {
            self.events.push(Event::RCreated(c));
        }
        fn on_redir_surface_destroyed(&mut self, c: u32) {
            self.events.push(Event::RDestroyed(c));
        }
        fn on_redir_surface_associated(&mut self, c: u32, h: u64) {
            self.events.push(Event::Assoc(c, h));
        }
        fn on_redir_surface_disassociated(&mut self, c: u32) {
            self.events.push(Event::Disassoc(c));
        }
        fn on_compref_pending(&mut self, h: u64) {
            self.events.push(Event::CompRef(h));
        }
        fn on_switch_draw_target(&mut self, c: u32) {
            self.events.push(Event::Switch(c));
        }
        fn on_flush_compose_once(&mut self, c: u32, h: u64) {
            self.events.push(Event::Flush(c, h));
        }
    }

    fn apply(c: &mut RdpedcClient, pdu: CompDeskPdu, cb: &mut RecCallback) {
        c.apply(pdu, cb).unwrap();
    }

    fn toggle(ev: EventType) -> CompDeskPdu {
        CompDeskPdu::Toggle(CompDeskToggle { event_type: ev })
    }

    // ── Composition mode FSM ─────────────────────────────────────────

    #[test]
    fn initial_mode_is_off() {
        let c = RdpedcClient::new();
        assert_eq!(c.mode(), CompositionMode::Off);
    }

    #[test]
    fn composition_on_off_round_trip_fires_callbacks() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(&mut c, toggle(EventType::CompositionOn), &mut cb);
        apply(&mut c, toggle(EventType::CompositionOff), &mut cb);
        assert_eq!(
            cb.events,
            vec![
                Event::Mode(CompositionMode::On { dwm_desk: false }),
                Event::Mode(CompositionMode::Off),
            ]
        );
        assert_eq!(c.mode(), CompositionMode::Off);
    }

    #[test]
    fn dwm_desk_enter_leave_while_on() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(&mut c, toggle(EventType::CompositionOn), &mut cb);
        apply(&mut c, toggle(EventType::DwmDeskEnter), &mut cb);
        assert_eq!(c.mode(), CompositionMode::On { dwm_desk: true });
        apply(&mut c, toggle(EventType::DwmDeskLeave), &mut cb);
        assert_eq!(c.mode(), CompositionMode::On { dwm_desk: false });
    }

    #[test]
    fn dwm_desk_events_while_off_are_ignored() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(&mut c, toggle(EventType::DwmDeskEnter), &mut cb);
        apply(&mut c, toggle(EventType::DwmDeskLeave), &mut cb);
        assert_eq!(c.mode(), CompositionMode::Off);
        assert!(cb.events.is_empty());
    }

    #[test]
    fn reserved_event_types_are_silently_ignored() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(&mut c, toggle(EventType::CompositionOn), &mut cb);
        cb.events.clear();
        apply(&mut c, toggle(EventType::Reserved1), &mut cb);
        apply(&mut c, toggle(EventType::Reserved2), &mut cb);
        assert!(cb.events.is_empty());
        assert_eq!(c.mode(), CompositionMode::On { dwm_desk: false });
    }

    #[test]
    fn composition_off_clears_surface_tables() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(&mut c, toggle(EventType::CompositionOn), &mut cb);
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::COMPOSEONCE,
                h_lsurface: 1,
                hwnd: 10,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 1,
                surface_bpp: 32,
                h_surf: 100,
                cx: 64,
                cy: 64,
            }),
            &mut cb,
        );
        assert_eq!(c.logical_len(), 1);
        assert_eq!(c.redir_len(), 1);
        apply(&mut c, toggle(EventType::CompositionOff), &mut cb);
        assert_eq!(c.logical_len(), 0);
        assert_eq!(c.redir_len(), 0);
        assert_eq!(c.current_draw_target(), None);
    }

    // ── Logical surface table ────────────────────────────────────────

    #[test]
    fn logical_surface_create_and_destroy() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::REDIRECTION,
                h_lsurface: 42,
                hwnd: 99,
            }),
            &mut cb,
        );
        assert_eq!(c.logical_len(), 1);
        let entry = c.logical_surface(42).unwrap();
        assert!(entry.flags.is_redirection());
        assert_eq!(entry.hwnd, 99);

        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: false,
                flags: LSurfaceFlags::default(),
                h_lsurface: 42,
                hwnd: 0,
            }),
            &mut cb,
        );
        assert_eq!(c.logical_len(), 0);
        assert!(cb.events.contains(&Event::LDestroyed(42)));
    }

    #[test]
    fn redir_surface_destroy_unknown_is_silently_ignored() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: false,
                cache_id: 12345,
                surface_bpp: 0,
                h_surf: 0,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        assert!(cb.events.is_empty());
        assert_eq!(c.redir_len(), 0);
    }

    #[test]
    fn duplicate_composition_on_while_on_preserves_dwm_desk() {
        // Regression test for the verifier-caught spec violation: a
        // duplicate CompositionOn while in `On { dwm_desk: true }` was
        // resetting dwm_desk to false and firing a spurious callback.
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(&mut c, toggle(EventType::CompositionOn), &mut cb);
        apply(&mut c, toggle(EventType::DwmDeskEnter), &mut cb);
        cb.events.clear();
        apply(&mut c, toggle(EventType::CompositionOn), &mut cb);
        assert_eq!(c.mode(), CompositionMode::On { dwm_desk: true });
        assert!(
            cb.events.is_empty(),
            "duplicate CompositionOn must be silently ignored"
        );
    }

    #[test]
    fn process_order_skips_unknown_operation_bytes() {
        // Forward-compat: a future server op code should not tear down
        // the stream. We place an unknown op (0x42) with a plausible
        // size field between two legal orders.
        let bytes = [
            // Legal: CompositionOn toggle (5 bytes)
            0x32, 0x01, 0x01, 0x00, 0x03,
            // Unknown op 0x42 with body size = 3 (5 bytes total)
            0x32, 0x42, 0x03, 0x00, 0xAA, 0xBB, 0xCC,
            // Legal: DwmDeskEnter toggle (5 bytes)
            0x32, 0x01, 0x01, 0x00, 0x04,
        ];
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        let consumed = process_batch(&mut c, &bytes, &mut cb).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(c.mode(), CompositionMode::On { dwm_desk: true });
    }

    #[test]
    fn logical_surface_destroy_unknown_is_silently_ignored() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: false,
                flags: LSurfaceFlags::default(),
                h_lsurface: 777,
                hwnd: 0,
            }),
            &mut cb,
        );
        assert!(cb.events.is_empty());
    }

    // ── Redirection surface table ────────────────────────────────────

    #[test]
    fn redir_surface_create_and_destroy() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 9,
                surface_bpp: 32,
                h_surf: 0x0705_0184,
                cx: 64,
                cy: 64,
            }),
            &mut cb,
        );
        let entry = c.redir_surface(9).unwrap();
        assert_eq!(entry.surface_bpp, 32);
        assert_eq!(entry.cx, 64);

        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: false,
                cache_id: 9,
                surface_bpp: 0,
                h_surf: 0,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        assert_eq!(c.redir_len(), 0);
    }

    // ── assoc / disassoc ─────────────────────────────────────────────

    #[test]
    fn assoc_links_redir_to_logical_when_both_exist() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::REDIRECTION,
                h_lsurface: 100,
                hwnd: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 5,
                surface_bpp: 32,
                h_surf: 0xDEAD,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::RedirSurfAssoc(RedirSurfAssocLSurface {
                associate: true,
                h_lsurface: 100,
                h_surf: 0xDEAD,
            }),
            &mut cb,
        );
        assert_eq!(c.redir_surface(5).unwrap().assoc_lsurface, Some(100));

        apply(
            &mut c,
            CompDeskPdu::RedirSurfAssoc(RedirSurfAssocLSurface {
                associate: false,
                h_lsurface: 100,
                h_surf: 0xDEAD,
            }),
            &mut cb,
        );
        assert_eq!(c.redir_surface(5).unwrap().assoc_lsurface, None);
    }

    #[test]
    fn assoc_with_unknown_logical_is_ignored() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 5,
                surface_bpp: 32,
                h_surf: 0xBEEF,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::RedirSurfAssoc(RedirSurfAssocLSurface {
                associate: true,
                h_lsurface: 999, // not in table
                h_surf: 0xBEEF,
            }),
            &mut cb,
        );
        assert_eq!(c.redir_surface(5).unwrap().assoc_lsurface, None);
    }

    #[test]
    fn destroying_logical_detaches_redir_assoc() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::REDIRECTION,
                h_lsurface: 1,
                hwnd: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 2,
                surface_bpp: 32,
                h_surf: 0xF00D,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::RedirSurfAssoc(RedirSurfAssocLSurface {
                associate: true,
                h_lsurface: 1,
                h_surf: 0xF00D,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: false,
                flags: LSurfaceFlags::default(),
                h_lsurface: 1,
                hwnd: 0,
            }),
            &mut cb,
        );
        assert_eq!(c.redir_surface(2).unwrap().assoc_lsurface, None);
    }

    // ── compref pending ──────────────────────────────────────────────

    #[test]
    fn compref_pending_sets_flag_on_known_surface() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::COMPOSEONCE,
                h_lsurface: 1,
                hwnd: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::CompRefPending(LSurfaceCompRefPending { h_lsurface: 1 }),
            &mut cb,
        );
        assert!(c.logical_surface(1).unwrap().compref_pending);
    }

    #[test]
    fn compref_pending_on_unknown_surface_is_ignored() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::CompRefPending(LSurfaceCompRefPending { h_lsurface: 42 }),
            &mut cb,
        );
        assert!(cb.events.is_empty());
    }

    // ── switch / flush ───────────────────────────────────────────────

    #[test]
    fn switch_sets_current_draw_target_for_known_surface() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 143,
                surface_bpp: 32,
                h_surf: 0,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::Switch(SwitchSurfObj { cache_id: 143 }),
            &mut cb,
        );
        assert_eq!(c.current_draw_target(), Some(143));
    }

    #[test]
    fn switch_to_unknown_surface_is_silently_ignored() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::Switch(SwitchSurfObj { cache_id: 999 }),
            &mut cb,
        );
        assert_eq!(c.current_draw_target(), None);
        assert!(cb.events.is_empty());
    }

    #[test]
    fn flush_clears_current_draw_target_when_matching() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        // apply_flush now requires BOTH cache_id and h_lsurface to
        // name live table entries, so set up the logical surface too.
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::COMPOSEONCE,
                h_lsurface: 1,
                hwnd: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 7,
                surface_bpp: 32,
                h_surf: 0,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::Switch(SwitchSurfObj { cache_id: 7 }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::Flush(FlushComposeOnce {
                cache_id: 7,
                h_lsurface: 1,
            }),
            &mut cb,
        );
        assert_eq!(c.current_draw_target(), None);
        assert!(cb.events.contains(&Event::Flush(7, 1)));
    }

    #[test]
    fn flush_with_unknown_h_lsurface_does_not_fire_callback() {
        // Security M1 regression: even when `cache_id` is live, a
        // bogus `h_lsurface` must not reach the callback.
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 7,
                surface_bpp: 32,
                h_surf: 0,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        cb.events.clear();
        apply(
            &mut c,
            CompDeskPdu::Flush(FlushComposeOnce {
                cache_id: 7,
                h_lsurface: 0xDEAD_BEEF,
            }),
            &mut cb,
        );
        assert!(cb.events.is_empty());
    }

    #[test]
    fn destroying_current_draw_target_clears_it() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 4,
                surface_bpp: 32,
                h_surf: 0,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::Switch(SwitchSurfObj { cache_id: 4 }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: false,
                cache_id: 4,
                surface_bpp: 0,
                h_surf: 0,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        assert_eq!(c.current_draw_target(), None);
    }

    // ── DoS caps ─────────────────────────────────────────────────────

    #[test]
    fn logical_surface_cap_is_enforced() {
        let mut c = RdpedcClient::new();
        let mut cb = NullCallback;
        for i in 0..MAX_LOGICAL_SURFACES as u64 {
            c.apply(
                CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                    create: true,
                    flags: LSurfaceFlags::default(),
                    h_lsurface: i,
                    hwnd: 0,
                }),
                &mut cb,
            )
            .unwrap();
        }
        let err = c
            .apply(
                CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                    create: true,
                    flags: LSurfaceFlags::default(),
                    h_lsurface: MAX_LOGICAL_SURFACES as u64,
                    hwnd: 0,
                }),
                &mut cb,
            )
            .unwrap_err();
        assert_eq!(err, RdpedcError::TooManySurfaces);
    }

    #[test]
    fn redir_surface_cap_is_enforced() {
        let mut c = RdpedcClient::new();
        let mut cb = NullCallback;
        for i in 0..MAX_REDIR_SURFACES as u32 {
            c.apply(
                CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                    create: true,
                    cache_id: i,
                    surface_bpp: 32,
                    h_surf: i as u64,
                    cx: 0,
                    cy: 0,
                }),
                &mut cb,
            )
            .unwrap();
        }
        let err = c
            .apply(
                CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                    create: true,
                    cache_id: MAX_REDIR_SURFACES as u32,
                    surface_bpp: 32,
                    h_surf: 0,
                    cx: 0,
                    cy: 0,
                }),
                &mut cb,
            )
            .unwrap_err();
        assert_eq!(err, RdpedcError::TooManySurfaces);
    }

    // ── Byte-level entry point ───────────────────────────────────────

    #[test]
    fn process_order_from_spec_hex_bytes() {
        // Spec §4.3.2 SURFOBJ create + §4.2.1 SWITCH concatenated.
        let bytes: [u8; 26 + 8] = [
            0x32, 0x03, 0x16, 0x00, 0x09, 0x00, 0x00, 0x00, 0x20, 0x00, 0x84, 0x01, 0x05, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // SURFOBJ
            0x32, 0x06, 0x04, 0x00, 0x09, 0x00, 0x00, 0x00, // SWITCH to cache_id 9
        ];
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        let consumed = process_batch(&mut c, &bytes, &mut cb).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(c.redir_len(), 1);
        assert_eq!(c.current_draw_target(), Some(9));
    }

    #[test]
    fn process_batch_stops_at_non_rdpedc_byte() {
        let bytes = [
            0x32, 0x01, 0x01, 0x00, 0x03, // TS_COMPDESK_TOGGLE CompositionOn
            0x00, 0x00, 0x00, // non-MS-RDPEDC bytes
        ];
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        let consumed = process_batch(&mut c, &bytes, &mut cb).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(c.mode(), CompositionMode::On { dwm_desk: false });
    }

    // ── Regression tests for cross-agent review findings ─────────────

    /// Build a client with logical surface 1, redir surface 2, and
    /// an active association from 2 → 1. Used by several regression
    /// tests that need the "populated" precondition.
    fn setup_associated_pair(c: &mut RdpedcClient, cb: &mut RecCallback) {
        apply(
            c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::COMPOSEONCE,
                h_lsurface: 1,
                hwnd: 0x10,
            }),
            cb,
        );
        apply(
            c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 2,
                surface_bpp: 32,
                h_surf: 0xABCD,
                cx: 0,
                cy: 0,
            }),
            cb,
        );
        apply(
            c,
            CompDeskPdu::RedirSurfAssoc(RedirSurfAssocLSurface {
                associate: true,
                h_lsurface: 1,
                h_surf: 0xABCD,
            }),
            cb,
        );
    }

    #[test]
    fn lsurface_create_over_existing_fires_destroy_then_create() {
        // Security H1 regression: callback order is destroy-then-create
        // rather than a silent replace.
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        setup_associated_pair(&mut c, &mut cb);
        cb.events.clear();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::REDIRECTION,
                h_lsurface: 1,
                hwnd: 0x99,
            }),
            &mut cb,
        );
        assert_eq!(
            cb.events,
            vec![Event::Disassoc(2), Event::LDestroyed(1), Event::LCreated(1)]
        );
        assert_eq!(c.logical_surface(1).unwrap().hwnd, 0x99);
    }

    #[test]
    fn lsurface_create_over_existing_clears_redir_assoc() {
        // Security H1 regression (separate concern): the redir
        // surface's `assoc_lsurface` pointer is cleared.
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        setup_associated_pair(&mut c, &mut cb);
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::REDIRECTION,
                h_lsurface: 1,
                hwnd: 0x99,
            }),
            &mut cb,
        );
        assert_eq!(c.redir_surface(2).unwrap().assoc_lsurface, None);
    }

    #[test]
    fn lsurface_create_over_existing_resets_compref_pending() {
        // The fresh entry after a replace MUST have compref_pending
        // reset to false, even if the old entry had it set. This
        // assertion is only load-bearing because we set the flag on
        // the old entry via a CompRefPending PDU before replacing.
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::COMPOSEONCE,
                h_lsurface: 1,
                hwnd: 0x10,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::CompRefPending(LSurfaceCompRefPending { h_lsurface: 1 }),
            &mut cb,
        );
        assert!(c.logical_surface(1).unwrap().compref_pending);
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::REDIRECTION,
                h_lsurface: 1,
                hwnd: 0x99,
            }),
            &mut cb,
        );
        assert!(!c.logical_surface(1).unwrap().compref_pending);
    }

    #[test]
    fn explicit_lsurface_destroy_fires_disassoc_before_destroy() {
        // Security M2 regression: balanced assoc/disassoc callbacks.
        // Every `on_redir_surface_associated` must be matched by
        // exactly one `on_redir_surface_disassociated`, including when
        // the disassociation is indirect via the logical surface
        // being torn down.
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        setup_associated_pair(&mut c, &mut cb);
        cb.events.clear();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: false,
                flags: LSurfaceFlags::default(),
                h_lsurface: 1,
                hwnd: 0,
            }),
            &mut cb,
        );
        // Order: disassoc(2) first, then destroyed(1).
        assert_eq!(
            cb.events,
            vec![Event::Disassoc(2), Event::LDestroyed(1)]
        );
    }

    #[test]
    fn surfobj_create_over_existing_fires_destroy_and_clears_draw_target() {
        // Security H1 regression for the redir-surface path.
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 5,
                surface_bpp: 32,
                h_surf: 0x111,
                cx: 0,
                cy: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::Switch(SwitchSurfObj { cache_id: 5 }),
            &mut cb,
        );
        assert_eq!(c.current_draw_target(), Some(5));
        cb.events.clear();
        // Second create for cache_id 5 — must tear down first.
        apply(
            &mut c,
            CompDeskPdu::SurfObj(SurfObjCreateDestroy {
                create: true,
                cache_id: 5,
                surface_bpp: 16,
                h_surf: 0x222,
                cx: 10,
                cy: 10,
            }),
            &mut cb,
        );
        assert_eq!(
            cb.events,
            vec![Event::RDestroyed(5), Event::RCreated(5)]
        );
        assert_eq!(c.current_draw_target(), None);
        let entry = c.redir_surface(5).unwrap();
        assert_eq!(entry.surface_bpp, 16);
        assert_eq!(entry.h_surf, 0x222);
    }

    #[test]
    fn flush_on_unknown_cache_id_does_not_fire_callback() {
        // Security W1 regression: apply_flush must match apply_switch's
        // "surface must be known" contract so phantom attacker-
        // controlled ids never reach the callback layer.
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::Flush(FlushComposeOnce {
                cache_id: 0xDEAD,
                h_lsurface: 0xBEEF,
            }),
            &mut cb,
        );
        assert!(cb.events.is_empty());
    }

    #[test]
    fn destroy_logical_while_compref_pending_still_fires_destroy() {
        // Verifier MEDIUM: document-and-test that destroy fires even
        // when compref_pending is true. The trait doc warns callers to
        // check compref_pending separately; this test pins the wire
        // behaviour so it can't regress.
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: true,
                flags: LSurfaceFlags::REDIRECTION,
                h_lsurface: 77,
                hwnd: 0,
            }),
            &mut cb,
        );
        apply(
            &mut c,
            CompDeskPdu::CompRefPending(LSurfaceCompRefPending { h_lsurface: 77 }),
            &mut cb,
        );
        assert!(c.logical_surface(77).unwrap().compref_pending);
        cb.events.clear();
        apply(
            &mut c,
            CompDeskPdu::LSurface(LSurfaceCreateDestroy {
                create: false,
                flags: LSurfaceFlags::default(),
                h_lsurface: 77,
                hwnd: 0,
            }),
            &mut cb,
        );
        // Destroy fires even though compref_pending was true. It is the
        // host's responsibility to defer proxy release until the
        // compositor releases its own reference.
        assert_eq!(cb.events, vec![Event::LDestroyed(77)]);
        assert!(c.logical_surface(77).is_none());
    }

    #[test]
    fn decode_body_error_carries_operation_code() {
        // Code-reviewer W4 regression: the error variant preserves the
        // offending operation code for post-mortem diagnostics.
        // TS_COMPDESK_TOGGLE with an illegal eventType byte.
        let bytes = [0x32, 0x01, 0x01, 0x00, 0xFF];
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        let err = c.process_order(&bytes, &mut cb).unwrap_err();
        assert_eq!(err, RdpedcError::DecodeBody { operation: 0x01 });
    }

    #[test]
    fn process_order_distinguishes_eof_from_invalid_header() {
        let mut c = RdpedcClient::new();
        let mut cb = RecCallback::default();
        assert_eq!(
            c.process_order(&[0x32, 0x01], &mut cb).unwrap_err(),
            RdpedcError::UnexpectedEof
        );
        assert_eq!(
            c.process_order(&[0x00, 0x00, 0x00, 0x00], &mut cb).unwrap_err(),
            RdpedcError::InvalidHeader
        );
    }
}
