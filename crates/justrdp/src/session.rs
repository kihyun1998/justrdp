//! The sans-IO session state machine (ADR-0001): after the connect machine reaches
//! `session-active`, this machine consumes raw socket bytes and produces [`SessionOutput`]s —
//! decoded [`FrameUpdate`]s for the host's frame sink, and the occasional outbound frame
//! (Deactivation–Reactivation re-runs capability exchange in-session, plan.md §0's resize
//! trap). Implemented so far: slow-path *and* fast-path output graphics (bitmap + palette
//! updates, with fast-path fragment reassembly — slice-6) and outbound keyboard/mouse input
//! (slice-7). Orders and pointers are later slices — their PDUs are decoded-and-skipped per
//! the robustness policy (plan.md §11c: unknown-but-well-formed never kills the session,
//! malformed input does).

use crate::cursor::{CursorEvent, CursorImage};
use crate::disconnect::{DisconnectReason, ServerDisconnectCause};
use crate::dvc::{Drdynvc, DvcEvent};
use crate::framebuffer::{FrameUpdate, Framebuffer};
use justrdp_codecs::color::{self, Palette};
use justrdp_codecs::{planar, pointer as pointer_codec, rle};
use justrdp_pdu::capability::{self, CapabilitySet};
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::input::InputEvent;
use justrdp_pdu::pointer::PointerUpdate;
use justrdp_pdu::{
    displaycontrol, dvc, fastpath, finalization, input, mcs, pointer, share, svc, tpkt, update,
    x224,
};

/// Everything the session machine needs from the completed connect sequence: channel
/// addressing from [`crate::McsConnectResult`], the share state from
/// [`crate::ActivationResult`], and the same capability list the connect config carried (the
/// reactivation Confirm Active re-sends it, with the freshly negotiated size patched into the
/// Bitmap set exactly as at connect time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// The user channel ID (`initiator` for outbound MCS data).
    pub user_channel_id: u16,
    /// The I/O channel ID all share PDUs ride on.
    pub io_channel_id: u16,
    /// The share ID from activation.
    pub share_id: u32,
    /// The negotiated desktop size — the framebuffer's initial dimensions.
    pub desktop_size: (u16, u16),
    /// The Confirm Active capability sets (caller-owned, verbatim — plan.md §0).
    pub capabilities: Vec<CapabilitySet>,
    /// The server's `inputFlags` from its Demand Active Input capability set
    /// ([`crate::ActivationResult::server_capabilities`]). Selects the input transport:
    /// fast-path when the server advertised `INPUT_FLAG_FASTPATH_INPUT`/`INPUT2`, the
    /// slow-path Input Event PDU otherwise.
    pub server_input_flags: u16,
    /// The MCS channel ID the server granted for the `drdynvc` static channel
    /// ([`crate::McsConnectResult::static_channels`], entry named `"drdynvc"`), or `None` if
    /// the channel was not requested/granted — dynamic channels (Display Control resize,
    /// EGFX, …) are then unavailable.
    pub drdynvc_channel_id: Option<u16>,
}

/// One effect of feeding bytes to the machine, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOutput {
    /// Fresh pixels for the host's frame sink.
    Frame(FrameUpdate),
    /// A cursor change for the host's cursor sink (issue #41).
    Cursor(CursorEvent),
    /// Bytes the adapter must write to the socket (reactivation / drdynvc traffic).
    WriteBytes(Vec<u8>),
    /// The Display Control channel is open and the server's caps arrived:
    /// [`SessionStateMachine::request_resize`] is valid from now on.
    DisplayControlReady,
}

/// Why a [`SessionStateMachine::request_resize`] call was refused (the session itself is
/// unaffected — the host may retry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeError {
    /// The drdynvc channel was not granted, the server has not created the Display Control
    /// channel, or its caps have not arrived yet (wait for
    /// [`SessionOutput::DisplayControlReady`]).
    NotReady,
    /// The dimensions are outside MS-RDPEDISP 2.2.2.2.1's 200–8192 range, or the area
    /// exceeds what the server's caps allow.
    InvalidDimensions {
        /// Why the dimensions were rejected.
        reason: &'static str,
    },
}

impl core::fmt::Display for ResizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResizeError::NotReady => {
                write!(f, "Display Control is not ready (no channel or caps yet)")
            }
            ResizeError::InvalidDimensions { reason } => {
                write!(f, "invalid resize dimensions: {reason}")
            }
        }
    }
}

impl core::error::Error for ResizeError {}

/// Why the session failed. Malformed server data is fatal (likely protocol desync,
/// plan.md §11c); everything else never reaches this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// A malformed PDU.
    Decode(justrdp_pdu::DecodeError),
    /// Interleaved-RLE bitmap data failed to decompress.
    Rle(rle::RleError),
    /// RDP6 planar bitmap data failed to decompress.
    Planar(planar::PlanarError),
    /// Decoded pixels could not be converted (bad depth / short buffer).
    Color(color::ColorError),
    /// A pointer shape failed to decode (bad mask sizes / unsupported depth).
    Pointer(pointer_codec::PointerError),
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::Decode(e) => write!(f, "malformed session PDU: {e}"),
            SessionError::Rle(e) => write!(f, "interleaved RLE: {e}"),
            SessionError::Planar(e) => write!(f, "RDP6 planar: {e}"),
            SessionError::Color(e) => write!(f, "pixel conversion: {e}"),
            SessionError::Pointer(e) => write!(f, "pointer shape: {e}"),
        }
    }
}

impl core::error::Error for SessionError {}

/// The event a decoded shape surfaces as: zero-sized shapes are the wire form of "no shape"
/// (servers send them to blank the cursor), so they arrive as [`CursorEvent::Hidden`].
fn cursor_event_for(image: CursorImage) -> CursorEvent {
    if image.rgba.is_empty() {
        CursorEvent::Hidden
    } else {
        CursorEvent::Set(image)
    }
}

/// Where the machine stands in the (re)activation cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Live: graphics PDUs update the framebuffer.
    Active,
    /// The server sent DeactivateAll; waiting for its next Demand Active.
    Deactivated,
    /// Confirm Active + finalization batch sent; waiting for the Font Map.
    Reactivating,
}

/// The sans-IO session machine. Feed it socket bytes with
/// [`SessionStateMachine::process_bytes`]; it never touches the socket itself.
#[derive(Debug)]
pub struct SessionStateMachine {
    config: SessionConfig,
    framebuffer: Framebuffer,
    palette: Palette,
    phase: Phase,
    /// Unprocessed socket bytes (TPKT reassembly, same contract as the connect machine).
    inbox: Vec<u8>,
    /// Reassembly buffer for a fragmented fast-path update (FIRST … NEXT … LAST), keyed by
    /// the update code in flight (fragments of one update are never interleaved with
    /// another's — MS-RDPBCGR 2.2.9.1.2.1).
    fragment: Option<(u8, Vec<u8>)>,
    /// The pointer cache (issue #41), sized from the Pointer capability set the caller
    /// advertised — Color/New shapes store into it, Cached re-selects from it. It survives
    /// deactivation–reactivation (the cache belongs to the connection, not the share).
    cursor_cache: Vec<Option<CursorImage>>,
    /// The server's latest Set Error Info attribution (issue #42); `ERRINFO_NONE` clears it.
    error_info: Option<justrdp_pdu::errinfo::ErrorInfo>,
    /// The reason from a received MCS Disconnect Provider Ultimatum (issue #42).
    ultimatum_reason: Option<u8>,
    /// The drdynvc transport + Display Control state (slice-8).
    drdynvc: Drdynvc,
}

impl SessionStateMachine {
    /// Build the machine straight off the connect results. `leftover` is
    /// [`crate::ActivationResult::leftover`] — bytes already consumed from the socket that
    /// belong to this machine; they are processed by the first [`Self::process_bytes`] call.
    pub fn new(config: SessionConfig, leftover: Vec<u8>) -> Self {
        let framebuffer = Framebuffer::new(config.desktop_size.0, config.desktop_size.1);
        // The cache honors what the caller advertised in its Pointer capability set:
        // `pointerCacheSize` when present (the cache New Pointer messages address), else
        // `colorPointerCacheSize`; no Pointer set advertised means no cache (a conforming
        // server then sends no shape messages at all).
        let cache_size = config
            .capabilities
            .iter()
            .find_map(|set| match set {
                CapabilitySet::Pointer(p) => Some(if p.pointer_cache_size > 0 {
                    p.pointer_cache_size
                } else {
                    p.color_pointer_cache_size
                }),
                _ => None,
            })
            .unwrap_or(0);
        Self {
            config,
            framebuffer,
            palette: Palette::default(),
            phase: Phase::Active,
            inbox: leftover,
            fragment: None,
            cursor_cache: vec![None; usize::from(cache_size)],
            error_info: None,
            ultimatum_reason: None,
            drdynvc: Drdynvc::default(),
        }
    }

    /// Why the session ended, as far as the server said (issue #42). The adapter calls this
    /// when the transport closes: a recorded Set Error Info code is the attribution (it
    /// outranks the generic MCS ultimatum); with neither, the close is
    /// [`DisconnectReason::UnexpectedDisconnect`].
    pub fn disconnect_reason(&self) -> DisconnectReason {
        if let Some(info) = self.error_info {
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ErrorInfo(info))
        } else if let Some(reason) = self.ultimatum_reason {
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ProviderUltimatum {
                reason,
            })
        } else {
            DisconnectReason::UnexpectedDisconnect
        }
    }

    /// The framebuffer (host-side rendering can snapshot it at any time).
    pub fn framebuffer(&self) -> &Framebuffer {
        &self.framebuffer
    }

    /// Feed raw socket bytes (any chunking); returns the outputs they produced, in order.
    /// The stream interleaves TPKT frames (slow-path) and fast-path PDUs; the first byte
    /// disambiguates (TPKT's version byte is `0x03`, a fast-path header has `action == 0`).
    pub fn process_bytes(&mut self, bytes: &[u8]) -> Result<Vec<SessionOutput>, SessionError> {
        self.inbox.extend_from_slice(bytes);
        let mut outputs = Vec::new();
        while let Some(&first) = self.inbox.first() {
            let result = if fastpath::is_fastpath(first) {
                fastpath::frame_len(&self.inbox)
            } else {
                tpkt::frame_len(&self.inbox)
            };
            let frame_len = match result {
                Ok(n) => n,
                Err(justrdp_pdu::DecodeError::NotEnoughBytes { .. }) => break,
                Err(e) => return Err(SessionError::Decode(e)),
            };
            if self.inbox.len() < frame_len {
                break;
            }
            let frame: Vec<u8> = self.inbox.drain(..frame_len).collect();
            if fastpath::is_fastpath(first) {
                self.on_fastpath_pdu(&frame, &mut outputs)?;
            } else {
                self.on_frame(&frame, &mut outputs)?;
            }
        }
        Ok(outputs)
    }

    /// Handle one complete fast-path output PDU: reassemble fragmented updates, then route
    /// bitmap/palette bodies through the same handlers as their slow-path twins.
    fn on_fastpath_pdu(
        &mut self,
        frame: &[u8],
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        for section in fastpath::decode_updates(frame).map_err(SessionError::Decode)? {
            let complete: Option<(u8, Vec<u8>)> = match section.fragmentation {
                fastpath::FP_FRAGMENT_SINGLE => Some((section.code, section.data.to_vec())),
                fastpath::FP_FRAGMENT_FIRST => {
                    self.fragment = Some((section.code, section.data.to_vec()));
                    None
                }
                fastpath::FP_FRAGMENT_NEXT | fastpath::FP_FRAGMENT_LAST => {
                    match self.fragment.as_mut() {
                        Some((code, buffer)) if *code == section.code => {
                            // Cap reassembly so an endless NEXT stream cannot grow the
                            // buffer unboundedly (the TSRequest-cap precedent). A real
                            // update never exceeds one full desktop of RGBA pixels plus
                            // headers by a wide margin.
                            let cap = (usize::from(self.framebuffer.width())
                                * usize::from(self.framebuffer.height())
                                * 4)
                            .max(1 << 20)
                                + (64 << 10);
                            if buffer.len() + section.data.len() > cap {
                                return Err(SessionError::Decode(
                                    justrdp_pdu::DecodeError::InvalidField {
                                        field: "TS_FP_UPDATE.fragmentation",
                                        reason: "fragmented update exceeds the reassembly cap",
                                    },
                                ));
                            }
                            buffer.extend_from_slice(section.data);
                        }
                        // A continuation without a matching FIRST: protocol desync.
                        _ => {
                            return Err(SessionError::Decode(
                                justrdp_pdu::DecodeError::InvalidField {
                                    field: "TS_FP_UPDATE.fragmentation",
                                    reason: "fragment continuation without a first fragment",
                                },
                            ));
                        }
                    }
                    if section.fragmentation == fastpath::FP_FRAGMENT_LAST {
                        self.fragment.take()
                    } else {
                        None
                    }
                }
                _ => unreachable!("fragmentation is a 2-bit field"),
            };
            let Some((code, data)) = complete else {
                continue;
            };
            if self.phase != Phase::Active {
                continue; // graphics pause during deactivation–reactivation
            }
            let mut cur = ReadCursor::new(&data, "fast-path update body");
            match code {
                fastpath::FP_UPDATE_BITMAP => {
                    // The body is a TS_UPDATE_BITMAP_DATA, updateType field included.
                    cur.read_u16_le().map_err(SessionError::Decode)?;
                    let bitmap =
                        update::BitmapUpdate::decode(&mut cur).map_err(SessionError::Decode)?;
                    for rect in &bitmap.rectangles {
                        if let Some(frame_update) = self.apply_bitmap(rect)? {
                            outputs.push(SessionOutput::Frame(frame_update));
                        }
                    }
                }
                fastpath::FP_UPDATE_PALETTE => {
                    cur.read_u16_le().map_err(SessionError::Decode)?;
                    let palette =
                        update::PaletteUpdate::decode(&mut cur).map_err(SessionError::Decode)?;
                    self.palette = Palette {
                        entries: palette.entries,
                    };
                }
                fastpath::FP_UPDATE_PTR_NULL
                | fastpath::FP_UPDATE_PTR_DEFAULT
                | fastpath::FP_UPDATE_PTR_POSITION
                | fastpath::FP_UPDATE_COLOR_POINTER
                | fastpath::FP_UPDATE_CACHED_POINTER
                | fastpath::FP_UPDATE_NEW_POINTER => {
                    let update = PointerUpdate::decode_fastpath(code, &mut cur)
                        .map_err(SessionError::Decode)?;
                    self.on_pointer(update, outputs)?;
                }
                // Synchronize, large pointers (capability never advertised), surface
                // commands (EGFX slices), orders: skipped.
                _ => {}
            }
        }
        Ok(())
    }

    /// Handle one decoded pointer update — both transports route here (issue #41).
    fn on_pointer(
        &mut self,
        update: PointerUpdate,
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        match update {
            PointerUpdate::System { pointer_type } => {
                // SYSPTR_NULL hides; anything else (SYSPTR_DEFAULT being the only other
                // conforming value) restores the host default.
                let event = if pointer_type == pointer::SYSPTR_NULL {
                    CursorEvent::Hidden
                } else {
                    CursorEvent::Default
                };
                outputs.push(SessionOutput::Cursor(event));
            }
            PointerUpdate::Position { x, y } => {
                outputs.push(SessionOutput::Cursor(CursorEvent::Move { x, y }));
            }
            // The Color message is implicitly 24-bpp; New carries its own depth.
            PointerUpdate::Color(attr) => self.set_cursor_shape(24, attr, outputs)?,
            PointerUpdate::New { xor_bpp, color } => {
                self.set_cursor_shape(xor_bpp, color, outputs)?;
            }
            PointerUpdate::Cached { cache_index } => {
                let image = self
                    .cursor_cache
                    .get(usize::from(cache_index))
                    .and_then(Option::as_ref)
                    .ok_or(SessionError::Decode(
                        justrdp_pdu::DecodeError::InvalidField {
                            field: "TS_CACHEDPOINTERATTRIBUTE.cacheIndex",
                            reason: "cache index beyond the advertised cache or an unfilled slot",
                        },
                    ))?;
                outputs.push(SessionOutput::Cursor(cursor_event_for(image.clone())));
            }
        }
        Ok(())
    }

    /// Decode a Color/New shape, store it in its cache slot, and surface it.
    fn set_cursor_shape(
        &mut self,
        xor_bpp: u16,
        attr: pointer::ColorPointerAttribute,
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        // 8-bpp shapes resolve through the *session* palette — pointer messages carry none
        // of their own.
        let rgba = pointer_codec::decode_pointer(
            attr.width,
            attr.height,
            xor_bpp,
            &attr.xor_mask,
            &attr.and_mask,
            &self.palette,
        )
        .map_err(SessionError::Pointer)?;
        let image = CursorImage {
            width: attr.width,
            height: attr.height,
            hotspot_x: attr.hot_spot.0,
            hotspot_y: attr.hot_spot.1,
            rgba,
        };
        let slot = self
            .cursor_cache
            .get_mut(usize::from(attr.cache_index))
            .ok_or(SessionError::Decode(
                justrdp_pdu::DecodeError::InvalidField {
                    field: "TS_COLORPOINTERATTRIBUTE.cacheIndex",
                    reason: "cache index beyond the advertised pointer cache",
                },
            ))?;
        *slot = Some(image.clone());
        outputs.push(SessionOutput::Cursor(cursor_event_for(image)));
        Ok(())
    }

    /// Handle one complete TPKT frame.
    fn on_frame(
        &mut self,
        frame: &[u8],
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let tpdu = tpkt::decode(frame).map_err(SessionError::Decode)?;
        let body = x224::decode_data(tpdu).map_err(SessionError::Decode)?;
        if mcs::DisconnectProviderUltimatum::matches(body) {
            // The server's last MCS word before closing the socket (issue #42): record the
            // reason for the adapter to surface at EOF.
            let dpum =
                mcs::DisconnectProviderUltimatum::decode(body).map_err(SessionError::Decode)?;
            tracing::info!(target: "rdp_dpum", reason = dpum.reason, "MCS Disconnect Provider Ultimatum");
            self.ultimatum_reason = Some(dpum.reason);
            return Ok(());
        }
        let indication = mcs::SendDataIndication::decode(body).map_err(SessionError::Decode)?;
        if indication.channel_id != self.config.io_channel_id {
            if Some(indication.channel_id) == self.config.drdynvc_channel_id {
                return self.on_drdynvc(indication.channel_id, indication.user_data, outputs);
            }
            // Other static channel traffic (cliprdr, rdpsnd, …) — later slices' epics.
            return Ok(());
        }
        let mut cur = ReadCursor::new(indication.user_data, "session share pdu");
        let header = share::ShareControlHeader::decode(&mut cur).map_err(SessionError::Decode)?;
        match header.pdu_type {
            share::PDU_TYPE_DATA => self.on_data_pdu(&mut cur, outputs),
            share::PDU_TYPE_DEACTIVATE_ALL => {
                // The server is resetting the session (most commonly a resize). Wait for the
                // next Demand Active; graphics stop in the meantime.
                tracing::debug!(target: "rdp_deactivate_all", "DeactivateAll received");
                self.phase = Phase::Deactivated;
                Ok(())
            }
            share::PDU_TYPE_DEMAND_ACTIVE => self.on_demand_active(header, &mut cur, outputs),
            // Anything else mid-session (e.g. a Server Redirect, the broker epic) is
            // unsupported but well-formed at this layer: skipped.
            _ => Ok(()),
        }
    }

    /// Handle a Share Data PDU.
    fn on_data_pdu(
        &mut self,
        cur: &mut ReadCursor<'_>,
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let data = share::ShareDataHeader::decode(cur).map_err(SessionError::Decode)?;
        match data.pdu_type2 {
            share::PDU_TYPE2_UPDATE if self.phase == Phase::Active => {
                let update_type = cur.read_u16_le().map_err(SessionError::Decode)?;
                match update_type {
                    update::UPDATETYPE_BITMAP => {
                        let bitmap =
                            update::BitmapUpdate::decode(cur).map_err(SessionError::Decode)?;
                        for rect in &bitmap.rectangles {
                            if let Some(frame) = self.apply_bitmap(rect)? {
                                outputs.push(SessionOutput::Frame(frame));
                            }
                        }
                    }
                    update::UPDATETYPE_PALETTE => {
                        let palette =
                            update::PaletteUpdate::decode(cur).map_err(SessionError::Decode)?;
                        self.palette = Palette {
                            entries: palette.entries,
                        };
                    }
                    // Synchronize updates are no-ops; orders cannot arrive (none advertised
                    // in the Order capset) — an order update from a non-conforming server is
                    // skipped, not fatal.
                    _ => {}
                }
                Ok(())
            }
            share::PDU_TYPE2_FONT_MAP if self.phase == Phase::Reactivating => {
                finalization::FontMap::decode(cur).map_err(SessionError::Decode)?;
                tracing::debug!(target: "rdp_font_map", "Font Map received — reactivation complete");
                self.phase = Phase::Active;
                // Reactivation complete: re-emit the full screen so the host repaints
                // (content restarts black; the server repaints everything next).
                outputs.push(SessionOutput::Frame(self.framebuffer.full_frame()));
                Ok(())
            }
            share::PDU_TYPE2_POINTER if self.phase == Phase::Active => {
                let update = PointerUpdate::decode_slowpath(cur).map_err(SessionError::Decode)?;
                self.on_pointer(update, outputs)
            }
            share::PDU_TYPE2_SET_ERROR_INFO => {
                // The server's attribution for the close that usually follows (issue #42).
                // ERRINFO_NONE (0) clears rather than attributes.
                let info = justrdp_pdu::errinfo::decode_set_error_info(cur)
                    .map_err(SessionError::Decode)?;
                if info.as_u32() == 0 {
                    self.error_info = None;
                } else {
                    tracing::info!(
                        target: "rdp_error_info",
                        code = format_args!("{:#010x}", info.as_u32()),
                        description = %info.description(),
                        "server Set Error Info"
                    );
                    self.error_info = Some(info);
                }
                Ok(())
            }
            // Save Session Info, Set Error Info, server Synchronize/Control during
            // reactivation, … : decoded-and-skipped until their epics.
            _ => Ok(()),
        }
    }

    /// Decode one bitmap rectangle into the framebuffer.
    fn apply_bitmap(
        &mut self,
        rect: &update::BitmapData,
    ) -> Result<Option<FrameUpdate>, SessionError> {
        // Bound the wire-declared dimensions BEFORE the decoders allocate width × height
        // buffers: a tiny malicious PDU declaring 65535×65535 would otherwise force a
        // multi-gigabyte allocation (OOM abort, not a typed error — plan.md §11c; same
        // class as the capped TSRequest read, gate #3). Legitimate rectangles never exceed
        // the negotiated desktop plus the legacy 4-pixel alignment padding.
        let max_w = self.framebuffer.width().saturating_add(3);
        let max_h = self.framebuffer.height().saturating_add(3);
        if rect.width > max_w || rect.height > max_h {
            return Err(SessionError::Decode(
                justrdp_pdu::DecodeError::InvalidField {
                    field: "TS_BITMAP_DATA",
                    reason: "bitmap rectangle exceeds the negotiated desktop size",
                },
            ));
        }
        let width = usize::from(rect.width);
        let height = usize::from(rect.height);
        // All slow-path bitmap layouts are bottom-up; the conversion flips to top-down RGBA.
        let rgba = match (rect.compressed, rect.bits_per_pixel) {
            (false, bpp) => color::to_rgba(&rect.data, width, height, bpp, &self.palette, true)
                .map_err(SessionError::Color)?,
            // Compressed 32-bpp slow-path data is RDP6 planar (MS-RDPBCGR
            // 2.2.9.1.1.3.1.2.2); the decoder yields BGR24 in the same bottom-up layout.
            (true, 32) => {
                let bgr =
                    planar::decompress(&rect.data, width, height).map_err(SessionError::Planar)?;
                color::to_rgba(&bgr, width, height, 24, &self.palette, true)
                    .map_err(SessionError::Color)?
            }
            (true, bpp) => {
                let raw =
                    rle::decompress(&rect.data, width, height, bpp).map_err(SessionError::Rle)?;
                color::to_rgba(&raw, width, height, bpp, &self.palette, true)
                    .map_err(SessionError::Color)?
            }
        };
        // The carried bitmap may overhang the destination rectangle (legacy 4-pixel
        // alignment); the destination is inclusive, the overhang is right/bottom padding.
        let dest_w = rect.right.saturating_sub(rect.left).saturating_add(1);
        let dest_h = rect.bottom.saturating_sub(rect.top).saturating_add(1);
        Ok(self.framebuffer.blit(
            rect.left,
            rect.top,
            dest_w.min(rect.width),
            dest_h.min(rect.height),
            &rgba,
            width,
        ))
    }

    /// A Demand Active mid-session: the Deactivation–Reactivation sequence (plan.md §0 —
    /// most commonly a resize). Confirm with the caller's capabilities (new size patched into
    /// the Bitmap set), pipeline the finalization batch, rebuild the framebuffer.
    fn on_demand_active(
        &mut self,
        header: share::ShareControlHeader,
        cur: &mut ReadCursor<'_>,
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let demand = capability::DemandActive::decode(cur).map_err(SessionError::Decode)?;
        self.config.share_id = header.share_id;
        let (width, height) = demand
            .bitmap()
            .map(|b| (b.desktop_width, b.desktop_height))
            .unwrap_or(self.config.desktop_size);
        tracing::debug!(
            target: "rdp_demand_active",
            width,
            height,
            "Demand Active received (reactivation)"
        );
        if (width, height) != self.config.desktop_size {
            self.config.desktop_size = (width, height);
            self.framebuffer.resize(width, height);
        }

        let mut caps = self.config.capabilities.clone();
        for set in &mut caps {
            if let CapabilitySet::Bitmap(bitmap) = set {
                bitmap.desktop_width = width;
                bitmap.desktop_height = height;
            }
        }
        let confirm = share::encode_share_control(
            share::PDU_TYPE_CONFIRM_ACTIVE,
            self.config.user_channel_id,
            header.share_id,
            &capability::encode_confirm_active(header.pdu_source, b"justrdp\0", &caps),
        );
        outputs.push(self.send_io(&confirm));
        let batch = [
            (
                share::PDU_TYPE2_SYNCHRONIZE,
                finalization::Synchronize {
                    target_user: header.pdu_source,
                }
                .encode(),
            ),
            (
                share::PDU_TYPE2_CONTROL,
                finalization::Control::new(finalization::CTRLACTION_COOPERATE).encode(),
            ),
            (
                share::PDU_TYPE2_CONTROL,
                finalization::Control::new(finalization::CTRLACTION_REQUEST_CONTROL).encode(),
            ),
            (share::PDU_TYPE2_FONT_LIST, finalization::encode_font_list()),
        ];
        for (pdu_type2, body) in batch {
            outputs.push(self.send_io(&share::encode_share_data(
                self.config.user_channel_id,
                header.share_id,
                share::STREAM_MED,
                pdu_type2,
                &body,
            )));
        }
        self.phase = Phase::Reactivating;
        Ok(())
    }

    /// Encode host input events into complete outbound wire frames (plan.md §6a). The
    /// transport is chosen from what the server's Input capability set advertised: fast-path
    /// input PDUs when `INPUT_FLAG_FASTPATH_INPUT`/`INPUT2` was set, the slow-path Input
    /// Event PDU otherwise. Batches over a single PDU's event bound are split automatically
    /// (the fast-path spill rule), and mouse coordinates are clamped to the current desktop —
    /// a stale coordinate from a pre-resize host event must not land outside the new desktop.
    ///
    /// The adapter writes the returned frames to the socket in order. Pure function of the
    /// machine's negotiated state: no I/O, no phase change (servers accept input during
    /// reactivation; they simply ignore what no longer applies).
    pub fn encode_input(&self, events: &[InputEvent]) -> Vec<Vec<u8>> {
        if events.is_empty() {
            return Vec::new();
        }
        let (max_x, max_y) = (
            self.config.desktop_size.0.saturating_sub(1),
            self.config.desktop_size.1.saturating_sub(1),
        );
        let events: Vec<InputEvent> = events
            .iter()
            .map(|event| match *event {
                InputEvent::Mouse {
                    flags,
                    wheel_units,
                    x,
                    y,
                } => InputEvent::Mouse {
                    flags,
                    wheel_units,
                    x: x.min(max_x),
                    y: y.min(max_y),
                },
                InputEvent::MouseX { flags, x, y } => InputEvent::MouseX {
                    flags,
                    x: x.min(max_x),
                    y: y.min(max_y),
                },
                other => other,
            })
            .collect();

        let fastpath_input = self.config.server_input_flags
            & (capability::INPUT_FLAG_FASTPATH_INPUT | capability::INPUT_FLAG_FASTPATH_INPUT2)
            != 0;
        if fastpath_input {
            // 255 events is the numEvents field bound; at ≤7 wire bytes per event a full
            // chunk stays far below the 0x7FFF length-field ceiling.
            events
                .chunks(255)
                .map(input::encode_fastpath_input)
                .collect()
        } else {
            events
                .chunks(255)
                .map(|chunk| {
                    self.wrap_io(&share::encode_share_data(
                        self.config.user_channel_id,
                        self.config.share_id,
                        share::STREAM_HI,
                        share::PDU_TYPE2_INPUT,
                        &input::encode_slowpath_input_body(chunk),
                    ))
                })
                .collect()
        }
    }

    /// Consume one MCS-delivered payload on the drdynvc static channel: SVC reassembly →
    /// drdynvc dispatch (caps response, Display Control create, channel data) → outbound
    /// responses and the [`SessionOutput::DisplayControlReady`] milestone.
    fn on_drdynvc(
        &mut self,
        mcs_channel_id: u16,
        payload: &[u8],
        outputs: &mut Vec<SessionOutput>,
    ) -> Result<(), SessionError> {
        let events = self
            .drdynvc
            .on_svc_payload(payload)
            .map_err(SessionError::Decode)?;
        for event in events {
            match event {
                DvcEvent::Send(pdu) => {
                    for chunk in svc::encode_chunks(&pdu) {
                        outputs.push(SessionOutput::WriteBytes(
                            self.wrap_channel(mcs_channel_id, &chunk),
                        ));
                    }
                }
                DvcEvent::DisplayControlReady => {
                    outputs.push(SessionOutput::DisplayControlReady);
                }
                // EGFX pixels land in the same framebuffer the slow path writes — the
                // framebuffer stays the single authoritative screen state either way.
                DvcEvent::Frame(frame) => {
                    if let Some(update) = self.framebuffer.blit(
                        frame.x,
                        frame.y,
                        frame.width,
                        frame.height,
                        &frame.pixels,
                        usize::from(frame.width),
                    ) {
                        outputs.push(SessionOutput::Frame(update));
                    }
                }
                DvcEvent::OutputResized { width, height } => {
                    if (width, height) != self.config.desktop_size {
                        self.config.desktop_size = (width, height);
                        self.framebuffer.resize(width, height);
                    }
                }
            }
        }
        Ok(())
    }

    /// Encode a client-initiated resize as a Display Control Monitor Layout PDU
    /// (MS-RDPEDISP 2.2.2.2): one primary monitor at the origin with the requested size. The
    /// returned frames go to the socket verbatim; the server answers with
    /// Deactivation–Reactivation (DeactivateAll → Demand Active carrying the new size), which
    /// this machine already consumes — the framebuffer rebuilds and a full-screen
    /// [`SessionOutput::Frame`] re-emit follows the reactivation Font Map.
    ///
    /// Valid only after [`SessionOutput::DisplayControlReady`]. An odd `width` is rounded
    /// down to even (the spec forbids odd widths; mstsc does the same).
    pub fn request_resize(&self, width: u16, height: u16) -> Result<Vec<Vec<u8>>, ResizeError> {
        let drdynvc_id = self
            .config
            .drdynvc_channel_id
            .ok_or(ResizeError::NotReady)?;
        let (channel_id, caps) = self
            .drdynvc
            .display_control()
            .ok_or(ResizeError::NotReady)?;
        let width = u32::from(width) & !1; // MS-RDPEDISP 2.2.2.2.1: width must be even
        let height = u32::from(height);
        let range = displaycontrol::MIN_MONITOR_DIMENSION..=displaycontrol::MAX_MONITOR_DIMENSION;
        if !range.contains(&width) || !range.contains(&height) {
            return Err(ResizeError::InvalidDimensions {
                reason: "width/height must be within 200–8192 (MS-RDPEDISP 2.2.2.2.1)",
            });
        }
        if u64::from(width) * u64::from(height) > caps.max_area() {
            return Err(ResizeError::InvalidDimensions {
                reason: "requested area exceeds the server's Display Control caps",
            });
        }
        tracing::debug!(
            target: "rdp_displaycontrol_resize",
            width,
            height,
            "Monitor Layout resize request encoded"
        );
        let layout = displaycontrol::encode_monitor_layout(&[displaycontrol::Monitor::primary(
            width, height,
        )]);
        let mut frames = Vec::new();
        for pdu in dvc::encode_data(channel_id, &layout) {
            for chunk in svc::encode_chunks(&pdu) {
                frames.push(self.wrap_channel(drdynvc_id, &chunk));
            }
        }
        Ok(frames)
    }

    /// Wrap a channel payload into a complete outbound frame on `channel_id`.
    fn wrap_channel(&self, channel_id: u16, payload: &[u8]) -> Vec<u8> {
        tpkt::encode(&x224::encode_data(&mcs::encode_send_data_request(
            self.config.user_channel_id,
            channel_id,
            payload,
        )))
    }

    /// Wrap an I/O-channel payload into a complete outbound frame.
    fn wrap_io(&self, payload: &[u8]) -> Vec<u8> {
        self.wrap_channel(self.config.io_channel_id, payload)
    }

    /// Wrap an I/O-channel payload into an outbound [`SessionOutput`].
    fn send_io(&self, payload: &[u8]) -> SessionOutput {
        SessionOutput::WriteBytes(self.wrap_io(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IO: u16 = 1003;
    const USER: u16 = 1007;
    const DRDYNVC: u16 = 1005;
    const SHARE: u32 = 0x0001_03EA;

    fn config() -> SessionConfig {
        SessionConfig {
            user_channel_id: USER,
            io_channel_id: IO,
            share_id: SHARE,
            desktop_size: (16, 8),
            capabilities: capability::default_client_capabilities(&test_core()),
            server_input_flags: capability::INPUT_FLAG_SCANCODES
                | capability::INPUT_FLAG_FASTPATH_INPUT2,
            drdynvc_channel_id: Some(DRDYNVC),
        }
    }

    fn test_core() -> justrdp_pdu::gcc::ClientCoreData {
        justrdp_pdu::gcc::ClientCoreData {
            version: justrdp_pdu::gcc::RDP_VERSION_10_12,
            desktop_width: 16,
            desktop_height: 8,
            keyboard_layout: 0x409,
            client_build: 1,
            client_name: "session-test".to_string(),
            keyboard_type: justrdp_pdu::gcc::KEYBOARD_TYPE_IBM_ENHANCED,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            ime_file_name: String::new(),
            post_beta2_color_depth: justrdp_pdu::gcc::COLOR_DEPTH_8BPP,
            client_product_id: 1,
            serial_number: 0,
            high_color_depth: justrdp_pdu::gcc::HIGH_COLOR_DEPTH_24BPP,
            supported_color_depths: justrdp_pdu::gcc::SUPPORTED_COLOR_DEPTH_24BPP,
            early_capability_flags: justrdp_pdu::gcc::ClientEarlyCapabilityFlags::empty(),
            dig_product_id: String::new(),
            connection_type: justrdp_pdu::gcc::CONNECTION_TYPE_LAN,
            server_selected_protocol: justrdp_pdu::nego::SecurityProtocol::from_bits(0),
        }
    }

    /// Frame a server→client payload on `channel` (SendDataIndication is encoded by hand:
    /// choice 0x68, initiator 1002, the channel, then a PER length).
    fn server_channel_frame(channel: u16, user_data: &[u8]) -> Vec<u8> {
        let mut body = vec![0x68];
        body.extend_from_slice(&(1002u16 - 1001).to_be_bytes());
        body.extend_from_slice(&channel.to_be_bytes());
        body.push(0x70);
        if user_data.len() < 128 {
            body.push(user_data.len() as u8);
        } else {
            body.extend_from_slice(&(0x8000u16 | user_data.len() as u16).to_be_bytes());
        }
        body.extend_from_slice(user_data);
        tpkt::encode(&x224::encode_data(&body))
    }

    /// Frame a server→client I/O payload.
    fn server_io_frame(user_data: &[u8]) -> Vec<u8> {
        server_channel_frame(IO, user_data)
    }

    /// Frame one complete drdynvc PDU as server→client SVC chunks on the drdynvc channel.
    fn server_dvc_frames(pdu: &[u8]) -> Vec<Vec<u8>> {
        svc::encode_chunks(pdu)
            .iter()
            .map(|chunk| server_channel_frame(DRDYNVC, chunk))
            .collect()
    }

    /// Walk a fresh machine to the resize-ready state: drdynvc caps exchanged, Display
    /// Control channel 7 created, server caps (1 monitor, `area_a × area_b`) consumed.
    fn display_control_ready(sm: &mut SessionStateMachine, area_a: u32, area_b: u32) {
        display_control_ready_caps(sm, 1, area_a, area_b);
    }

    fn display_control_ready_caps(
        sm: &mut SessionStateMachine,
        max_num_monitors: u32,
        area_a: u32,
        area_b: u32,
    ) {
        let caps_request = vec![0x50, 0x00, 0x01, 0x00];
        for frame in server_dvc_frames(&caps_request) {
            sm.process_bytes(&frame).unwrap();
        }
        let mut create = vec![0x10, 0x07];
        create.extend_from_slice(displaycontrol::CHANNEL_NAME.as_bytes());
        create.push(0);
        for frame in server_dvc_frames(&create) {
            sm.process_bytes(&frame).unwrap();
        }
        let mut caps = Vec::new();
        caps.extend_from_slice(&displaycontrol::TYPE_CAPS.to_le_bytes());
        caps.extend_from_slice(&20u32.to_le_bytes());
        for v in [max_num_monitors, area_a, area_b] {
            caps.extend_from_slice(&v.to_le_bytes());
        }
        let mut ready = false;
        for pdu in dvc::encode_data(7, &caps) {
            for frame in server_dvc_frames(&pdu) {
                for output in sm.process_bytes(&frame).unwrap() {
                    ready |= output == SessionOutput::DisplayControlReady;
                }
            }
        }
        assert!(ready, "DisplayControlReady never surfaced");
    }

    fn server_data_pdu(pdu_type2: u8, body: &[u8]) -> Vec<u8> {
        server_io_frame(&share::encode_share_data(
            1002,
            SHARE,
            share::STREAM_MED,
            pdu_type2,
            body,
        ))
    }

    /// An uncompressed 24-bpp bitmap update: one rect at (x,y), w×h, all pixels `bgr`.
    fn bitmap_update_frame(x: u16, y: u16, w: u16, h: u16, bgr: [u8; 3]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [x, y, x + w - 1, y + h - 1, w, h, 24, 0] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let data: Vec<u8> = (0..w as usize * h as usize).flat_map(|_| bgr).collect();
        body.extend_from_slice(&(data.len() as u16).to_le_bytes());
        body.extend_from_slice(&data);
        server_data_pdu(share::PDU_TYPE2_UPDATE, &body)
    }

    /// A TS_FP_POINTERATTRIBUTE body: a 1×1 shape at `xor_bpp` 32 with one BGRA pixel,
    /// AND mask all zeros (opaque).
    fn new_pointer_body(cache_index: u16, bgra: [u8; 4], hot_spot: (u16, u16)) -> Vec<u8> {
        let mut body = Vec::new();
        for v in [
            32u16, // xorBpp
            cache_index,
            hot_spot.0,
            hot_spot.1,
            1, // width
            1, // height
            2, // lengthAndMask (1 bit padded to 2 bytes)
            4, // lengthXorMask
        ] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&bgra);
        body.extend_from_slice(&[0x00, 0x00]); // andMaskData
        body
    }

    fn fastpath_pointer_pdu(code: u8, body: &[u8]) -> Vec<u8> {
        fastpath::encode_pdu(&[(code, fastpath::FP_FRAGMENT_SINGLE, body)])
    }

    #[test]
    fn fastpath_new_pointer_emits_set_cursor_and_caches_the_shape() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());

        let body = new_pointer_body(3, [10, 20, 30, 200], (5, 4));
        let outputs = sm
            .process_bytes(&fastpath_pointer_pdu(
                fastpath::FP_UPDATE_NEW_POINTER,
                &body,
            ))
            .unwrap();
        let [SessionOutput::Cursor(CursorEvent::Set(image))] = outputs.as_slice() else {
            panic!("expected one SetCursor, got {outputs:?}");
        };
        assert_eq!((image.width, image.height), (1, 1));
        assert_eq!((image.hotspot_x, image.hotspot_y), (5, 4));
        // BGRA source → straight-alpha RGBA.
        assert_eq!(image.rgba, [30, 20, 10, 200]);

        // A Cached re-select of the same slot re-emits the stored shape.
        let outputs = sm
            .process_bytes(&fastpath_pointer_pdu(
                fastpath::FP_UPDATE_CACHED_POINTER,
                &3u16.to_le_bytes(),
            ))
            .unwrap();
        let [SessionOutput::Cursor(CursorEvent::Set(cached))] = outputs.as_slice() else {
            panic!("expected the cached SetCursor, got {outputs:?}");
        };
        assert_eq!(cached.rgba, [30, 20, 10, 200]);
        assert_eq!((cached.hotspot_x, cached.hotspot_y), (5, 4));
    }

    #[test]
    fn fastpath_hidden_and_default_pointers_emit_their_events() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());

        let outputs = sm
            .process_bytes(&fastpath_pointer_pdu(fastpath::FP_UPDATE_PTR_NULL, &[]))
            .unwrap();
        assert_eq!(outputs, vec![SessionOutput::Cursor(CursorEvent::Hidden)]);

        let outputs = sm
            .process_bytes(&fastpath_pointer_pdu(fastpath::FP_UPDATE_PTR_DEFAULT, &[]))
            .unwrap();
        assert_eq!(outputs, vec![SessionOutput::Cursor(CursorEvent::Default)]);
    }

    #[test]
    fn slowpath_pointer_messages_ride_the_pointer_data_pdu() {
        // The slow-path transport for the same updates: a TS_POINTER_PDU as a Share Data PDU
        // body. Position is the message servers send most.
        let mut body = justrdp_pdu::pointer::PTRMSGTYPE_POSITION
            .to_le_bytes()
            .to_vec();
        body.extend_from_slice(&0u16.to_le_bytes()); // pad2Octets
        body.extend_from_slice(&7u16.to_le_bytes());
        body.extend_from_slice(&6u16.to_le_bytes());

        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let outputs = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_POINTER, &body))
            .unwrap();
        assert_eq!(
            outputs,
            vec![SessionOutput::Cursor(CursorEvent::Move { x: 7, y: 6 })]
        );
    }

    #[test]
    fn slowpath_color_pointer_decodes_as_24bpp() {
        // TS_PTRMSGTYPE_COLOR carries an implicit 24-bpp shape. 1×1: xor stride is 4 bytes
        // (24 bits → 2-byte aligned), BGR + 1 pad byte.
        let mut attr = Vec::new();
        for v in [2u16, 0, 0, 1, 1, 2, 4] {
            attr.extend_from_slice(&v.to_le_bytes());
        }
        attr.extend_from_slice(&[1, 2, 3, 0]); // xor: B=1 G=2 R=3 + stride pad
        attr.extend_from_slice(&[0x00, 0x00]); // and
        let mut body = justrdp_pdu::pointer::PTRMSGTYPE_COLOR
            .to_le_bytes()
            .to_vec();
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&attr);

        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let outputs = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_POINTER, &body))
            .unwrap();
        let [SessionOutput::Cursor(CursorEvent::Set(image))] = outputs.as_slice() else {
            panic!("expected SetCursor, got {outputs:?}");
        };
        assert_eq!(image.rgba, [3, 2, 1, 255]);
    }

    #[test]
    fn cached_pointer_misuse_is_a_typed_error() {
        // Index beyond the advertised cache size (default capset: 20 entries): protocol
        // violation, fatal per plan.md §11c.
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        assert!(matches!(
            sm.process_bytes(&fastpath_pointer_pdu(
                fastpath::FP_UPDATE_CACHED_POINTER,
                &20u16.to_le_bytes(),
            )),
            Err(SessionError::Decode(_))
        ));

        // A never-filled slot inside the bounds is the same desync.
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        assert!(matches!(
            sm.process_bytes(&fastpath_pointer_pdu(
                fastpath::FP_UPDATE_CACHED_POINTER,
                &0u16.to_le_bytes(),
            )),
            Err(SessionError::Decode(_))
        ));
    }

    #[test]
    fn a_set_error_info_pdu_becomes_the_disconnect_attribution() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        // Before anything arrives, a close is unattributable.
        assert_eq!(
            sm.disconnect_reason(),
            DisconnectReason::UnexpectedDisconnect
        );

        // ERRINFO_LOGOFF_BY_USER (0x0000000C), then the socket closes (the close itself is
        // the adapter's observation — the machine only records the attribution).
        let outputs = sm
            .process_bytes(&server_data_pdu(
                share::PDU_TYPE2_SET_ERROR_INFO,
                &0x0000_000Cu32.to_le_bytes(),
            ))
            .unwrap();
        assert!(outputs.is_empty(), "attribution is silent, got {outputs:?}");
        assert_eq!(
            sm.disconnect_reason(),
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ErrorInfo(
                justrdp_pdu::errinfo::ErrorInfo::ProtocolIndependent(
                    justrdp_pdu::errinfo::ProtocolIndependentCode::LogoffByUser
                )
            ))
        );
    }

    #[test]
    fn errinfo_none_does_not_attribute_the_disconnect() {
        // ERRINFO_NONE (0): servers send it to clear state — not an attribution.
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        sm.process_bytes(&server_data_pdu(
            share::PDU_TYPE2_SET_ERROR_INFO,
            &0u32.to_le_bytes(),
        ))
        .unwrap();
        assert_eq!(
            sm.disconnect_reason(),
            DisconnectReason::UnexpectedDisconnect
        );
    }

    #[test]
    fn a_disconnect_provider_ultimatum_attributes_the_disconnect() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let frame = tpkt::encode(&x224::encode_data(
            &mcs::encode_disconnect_provider_ultimatum(mcs::RN_PROVIDER_INITIATED),
        ));
        let outputs = sm.process_bytes(&frame).unwrap();
        assert!(outputs.is_empty());
        assert_eq!(
            sm.disconnect_reason(),
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ProviderUltimatum {
                reason: mcs::RN_PROVIDER_INITIATED
            })
        );
    }

    #[test]
    fn an_error_info_outranks_the_generic_ultimatum() {
        // The usual server farewell is Error Info (specific) followed by a DPum (generic)
        // followed by close: the specific attribution must win regardless of order.
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        sm.process_bytes(&server_data_pdu(
            share::PDU_TYPE2_SET_ERROR_INFO,
            &0x0000_000Cu32.to_le_bytes(),
        ))
        .unwrap();
        sm.process_bytes(&tpkt::encode(&x224::encode_data(
            &mcs::encode_disconnect_provider_ultimatum(mcs::RN_PROVIDER_INITIATED),
        )))
        .unwrap();
        assert!(matches!(
            sm.disconnect_reason(),
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ErrorInfo(_))
        ));
    }

    #[test]
    fn a_truncated_error_info_body_is_a_typed_error() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        assert!(matches!(
            sm.process_bytes(&server_data_pdu(
                share::PDU_TYPE2_SET_ERROR_INFO,
                &[0x0C, 0x00]
            )),
            Err(SessionError::Decode(_))
        ));
    }

    #[test]
    fn uncompressed_bitmap_yields_a_frame_update() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let outputs = sm
            .process_bytes(&bitmap_update_frame(2, 1, 4, 2, [10, 20, 30]))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (2, 1, 4, 2));
        // BGR [10,20,30] → RGBA [30,20,10,255].
        assert_eq!(&frame.pixels[..4], &[30, 20, 10, 255]);
        // And the framebuffer holds it at (2,1): row 1 × stride 16 px + col 2, ×4 bytes.
        let off = (16 + 2) * 4;
        assert_eq!(&sm.framebuffer().pixels()[off..off + 4], &[30, 20, 10, 255]);
    }

    #[test]
    fn rle_compressed_bitmap_decodes_through_the_codec() {
        // 4×2 @ 16bpp COLOR_RUN(8) of red (0xF800), flagged compressed without CD header.
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 3, 1, 4, 2, 16] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(
            &(update::BITMAP_COMPRESSION | update::NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        let stream = [0x68, 0x00, 0xF8]; // COLOR_RUN run 8, pixel 0xF800
        body.extend_from_slice(&(stream.len() as u16).to_le_bytes());
        body.extend_from_slice(&stream);

        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let outputs = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!(&frame.pixels[..4], &[255, 0, 0, 255]);
        assert!(frame.pixels.chunks_exact(4).all(|p| p == [255, 0, 0, 255]));
    }

    #[test]
    fn palette_update_applies_to_subsequent_8bpp_bitmaps() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        // Palette: entry 5 = (1,2,3).
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_PALETTE.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&256u32.to_le_bytes());
        for i in 0..256u16 {
            if i == 5 {
                body.extend_from_slice(&[1, 2, 3]);
            } else {
                body.extend_from_slice(&[0, 0, 0]);
            }
        }
        assert!(
            sm.process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
                .unwrap()
                .is_empty()
        );

        // 8-bpp uncompressed bitmap of index 5.
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 3, 0, 4, 1, 8, 0, 4] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&[5, 5, 5, 5]);
        let outputs = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame");
        };
        assert_eq!(&frame.pixels[..4], &[1, 2, 3, 255]);
    }

    #[test]
    fn deactivate_reactivate_resizes_and_reemits_full_screen() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());

        // DeactivateAll: graphics stop, no output.
        let deactivate = server_io_frame(&share::encode_share_control(
            share::PDU_TYPE_DEACTIVATE_ALL,
            1002,
            SHARE,
            &[],
        ));
        assert!(sm.process_bytes(&deactivate).unwrap().is_empty());

        // Demand Active with a new 8×4 desktop.
        let sets = vec![CapabilitySet::Bitmap(capability::BitmapCapabilitySet {
            preferred_bits_per_pixel: 24,
            desktop_width: 8,
            desktop_height: 4,
            desktop_resize_flag: 1,
            drawing_flags: 0,
        })];
        let mut caps = Vec::new();
        for s in &sets {
            s.encode(&mut caps);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&((caps.len() + 4) as u16).to_le_bytes());
        body.extend_from_slice(b"RDP\0");
        body.extend_from_slice(&(sets.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&caps);
        body.extend_from_slice(&0u32.to_le_bytes());
        let demand = server_io_frame(&share::encode_share_control(
            share::PDU_TYPE_DEMAND_ACTIVE,
            1002,
            SHARE + 1,
            &body,
        ));
        let outputs = sm.process_bytes(&demand).unwrap();
        // Confirm Active + 4 finalization frames, all outbound writes.
        assert_eq!(outputs.len(), 5);
        assert!(
            outputs
                .iter()
                .all(|o| matches!(o, SessionOutput::WriteBytes(_)))
        );
        assert_eq!(
            (sm.framebuffer().width(), sm.framebuffer().height()),
            (8, 4)
        );

        // Bitmaps are ignored until the Font Map closes reactivation…
        assert!(
            sm.process_bytes(&bitmap_update_frame(0, 0, 4, 2, [9, 9, 9]))
                .unwrap()
                .is_empty()
        );

        // …which re-emits the full (new-size) screen.
        let font_map = server_data_pdu(share::PDU_TYPE2_FONT_MAP, &[0, 0, 0, 0, 3, 0, 4, 0]);
        let outputs = sm.process_bytes(&font_map).unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected the full-screen re-emit, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y, frame.width, frame.height), (0, 0, 8, 4));

        // And graphics flow again.
        let outputs = sm
            .process_bytes(&bitmap_update_frame(0, 0, 4, 2, [10, 20, 30]))
            .unwrap();
        assert_eq!(outputs.len(), 1);
    }

    /// The TS_UPDATE_BITMAP_DATA body (updateType included) of one uncompressed 24-bpp rect.
    fn bitmap_update_body(x: u16, y: u16, w: u16, h: u16, bgr: [u8; 3]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [x, y, x + w - 1, y + h - 1, w, h, 24, 0] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let data: Vec<u8> = (0..w as usize * h as usize).flat_map(|_| bgr).collect();
        body.extend_from_slice(&(data.len() as u16).to_le_bytes());
        body.extend_from_slice(&data);
        body
    }

    #[test]
    fn fastpath_bitmap_update_yields_a_frame() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let body = bitmap_update_body(1, 1, 4, 2, [40, 50, 60]);
        let pdu = fastpath::encode_pdu(&[(
            fastpath::FP_UPDATE_BITMAP,
            fastpath::FP_FRAGMENT_SINGLE,
            &body,
        )]);
        let outputs = sm.process_bytes(&pdu).unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected one frame, got {outputs:?}");
        };
        assert_eq!((frame.x, frame.y), (1, 1));
        assert_eq!(&frame.pixels[..4], &[60, 50, 40, 255]);
    }

    #[test]
    fn fragmented_fastpath_update_reassembles() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let body = bitmap_update_body(0, 0, 8, 4, [1, 2, 3]);
        let (a, rest) = body.split_at(10);
        let (b, c) = rest.split_at(15);
        // Three PDUs carrying FIRST / NEXT / LAST fragments, mixed with TPKT traffic between.
        let outputs = sm
            .process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_FIRST,
                a,
            )]))
            .unwrap();
        assert!(outputs.is_empty());
        let tpkt_between = server_data_pdu(share::PDU_TYPE2_SAVE_SESSION_INFO, &[0; 4]);
        assert!(sm.process_bytes(&tpkt_between).unwrap().is_empty());
        assert!(
            sm.process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_NEXT,
                b,
            )]))
            .unwrap()
            .is_empty()
        );
        let outputs = sm
            .process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_LAST,
                c,
            )]))
            .unwrap();
        let [SessionOutput::Frame(frame)] = outputs.as_slice() else {
            panic!("expected the reassembled frame, got {outputs:?}");
        };
        assert_eq!((frame.width, frame.height), (8, 4));
        assert_eq!(&frame.pixels[..4], &[3, 2, 1, 255]);
    }

    #[test]
    fn oversized_bitmap_dimensions_are_rejected_before_allocation() {
        // A ~30-byte PDU declaring a 65535×65535 compressed bitmap must yield a typed
        // error, not a multi-gigabyte allocation (gate #6 fix note 1).
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 65534, 65534, 65535, 65535, 24] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(
            &(update::BITMAP_COMPRESSION | update::NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(0x1F);
        let err = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
            .unwrap_err();
        assert!(
            matches!(
                err,
                SessionError::Decode(justrdp_pdu::DecodeError::InvalidField { .. })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn fragment_reassembly_is_capped() {
        // An endless FIRST + NEXT stream must hit the reassembly cap (typed error), not
        // grow without bound (gate #6 fix note 1). Test desktop is 16×8 → cap ≈ 1 MiB.
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let chunk = vec![0u8; 16 << 10];
        assert!(
            sm.process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_FIRST,
                &chunk,
            )]))
            .unwrap()
            .is_empty()
        );
        let mut result = Ok(Vec::new());
        for _ in 0..80 {
            result = sm.process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_NEXT,
                &chunk,
            )]));
            if result.is_err() {
                break;
            }
        }
        assert!(
            matches!(result, Err(SessionError::Decode(_))),
            "cap never tripped: {result:?}"
        );
    }

    #[test]
    fn fragment_continuation_without_first_is_a_typed_error() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let err = sm
            .process_bytes(&fastpath::encode_pdu(&[(
                fastpath::FP_UPDATE_BITMAP,
                fastpath::FP_FRAGMENT_LAST,
                &[0; 4],
            )]))
            .unwrap_err();
        assert!(matches!(err, SessionError::Decode(_)), "got {err:?}");
    }

    #[test]
    fn non_io_channels_and_unknown_pdus_are_skipped() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        // Data PDUs without a handler produce nothing (pointer PDUs graduated to handled in
        // issue #41 — save-session-info and set-error-info remain decode-and-skip).
        for (t2, body) in [
            (share::PDU_TYPE2_SAVE_SESSION_INFO, vec![0u8; 12]),
            (share::PDU_TYPE2_SET_ERROR_INFO, vec![0u8; 4]),
        ] {
            assert!(
                sm.process_bytes(&server_data_pdu(t2, &body))
                    .unwrap()
                    .is_empty()
            );
        }
        // Traffic on a static channel (1004) is ignored for now.
        let mut body = vec![0x68];
        body.extend_from_slice(&(1002u16 - 1001).to_be_bytes());
        body.extend_from_slice(&1004u16.to_be_bytes());
        body.push(0x70);
        body.push(2);
        body.extend_from_slice(&[0xAB, 0xCD]);
        let frame = tpkt::encode(&x224::encode_data(&body));
        assert!(sm.process_bytes(&frame).unwrap().is_empty());
    }

    #[test]
    fn input_uses_fastpath_when_the_server_advertised_it() {
        let sm = SessionStateMachine::new(config(), Vec::new());
        let frames = sm.encode_input(&[InputEvent::ScanCode {
            code: 0x1E,
            release: false,
            extended: false,
            extended1: false,
        }]);
        assert_eq!(frames.len(), 1);
        // A fast-path frame, not a TPKT frame.
        assert!(fastpath::is_fastpath(frames[0][0]));
        assert_eq!(
            frames[0],
            input::encode_fastpath_input(&[InputEvent::ScanCode {
                code: 0x1E,
                release: false,
                extended: false,
                extended1: false,
            }])
        );
    }

    #[test]
    fn input_falls_back_to_slowpath_without_the_server_flag() {
        let mut cfg = config();
        cfg.server_input_flags = capability::INPUT_FLAG_SCANCODES;
        let sm = SessionStateMachine::new(cfg, Vec::new());
        let event = InputEvent::Mouse {
            flags: input::PTRFLAGS_MOVE,
            wheel_units: 0,
            x: 3,
            y: 4,
        };
        let frames = sm.encode_input(&[event]);
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        // A TPKT frame wrapping MCS → Share Data PDU_TYPE2_INPUT with our event inside.
        assert_eq!(frame[0], 0x03);
        assert_eq!(justrdp_pdu::tpkt::frame_len(frame).unwrap(), frame.len());
        let body = input::encode_slowpath_input_body(&[event]);
        assert!(
            frame.windows(body.len()).any(|w| w == body),
            "slow-path frame does not embed the input body"
        );
    }

    #[test]
    fn input_mouse_coordinates_clamp_to_the_desktop() {
        let sm = SessionStateMachine::new(config(), Vec::new()); // 16×8 desktop
        let frames = sm.encode_input(&[InputEvent::Mouse {
            flags: input::PTRFLAGS_MOVE,
            wheel_units: 0,
            x: 500,
            y: 500,
        }]);
        // Fast-path: header(1) + len(1) + eventHeader(1) + flags(2) + x(2) + y(2).
        let frame = &frames[0];
        assert_eq!(u16::from_le_bytes([frame[5], frame[6]]), 15);
        assert_eq!(u16::from_le_bytes([frame[7], frame[8]]), 7);
    }

    #[test]
    fn input_batches_over_255_events_spill_into_multiple_pdus() {
        let sm = SessionStateMachine::new(config(), Vec::new());
        let events = vec![
            InputEvent::ScanCode {
                code: 0x1E,
                release: false,
                extended: false,
                extended1: false,
            };
            300
        ];
        let frames = sm.encode_input(&events);
        assert_eq!(frames.len(), 2);
        // 255 + 45 events; both frames self-describe their length correctly.
        assert_eq!(fastpath::frame_len(&frames[0]).unwrap(), frames[0].len());
        assert_eq!(fastpath::frame_len(&frames[1]).unwrap(), frames[1].len());
        assert!(sm.encode_input(&[]).is_empty());
    }

    #[test]
    fn drdynvc_caps_request_is_answered_on_the_drdynvc_channel() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let caps_request = vec![0x50, 0x00, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut outputs = Vec::new();
        for frame in server_dvc_frames(&caps_request) {
            outputs.extend(sm.process_bytes(&frame).unwrap());
        }
        let [SessionOutput::WriteBytes(frame)] = outputs.as_slice() else {
            panic!("expected one response frame, got {outputs:?}");
        };
        // The response embeds the SVC-chunked version-3 caps response and rides the
        // drdynvc channel (big-endian MCS channelId).
        let expected_chunk = &svc::encode_chunks(&dvc::encode_capabilities_response(3))[0];
        assert!(
            frame
                .windows(expected_chunk.len())
                .any(|w| w == expected_chunk.as_slice())
        );
        assert!(frame.windows(2).any(|w| w == DRDYNVC.to_be_bytes()));
    }

    #[test]
    fn display_control_ready_enables_request_resize() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        assert_eq!(sm.request_resize(1280, 1024), Err(ResizeError::NotReady));
        display_control_ready(&mut sm, 8192, 8192);

        let frames = sm.request_resize(1280, 1024).unwrap();
        assert_eq!(frames.len(), 1, "a 56-byte layout fits one SVC chunk");
        let layout =
            displaycontrol::encode_monitor_layout(&[displaycontrol::Monitor::primary(1280, 1024)]);
        let expected_chunk = &svc::encode_chunks(&dvc::encode_data(7, &layout)[0])[0];
        assert!(
            frames[0]
                .windows(expected_chunk.len())
                .any(|w| w == expected_chunk.as_slice()),
            "resize frame does not embed the Monitor Layout DVC data"
        );
        assert_eq!(tpkt::frame_len(&frames[0]).unwrap(), frames[0].len());
    }

    #[test]
    fn request_resize_rounds_odd_widths_down_and_validates_ranges() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        display_control_ready(&mut sm, 1920, 1080);

        // Odd width 1281 → 1280 on the wire (MS-RDPEDISP forbids odd widths).
        let frames = sm.request_resize(1281, 1024).unwrap();
        let layout_even =
            displaycontrol::encode_monitor_layout(&[displaycontrol::Monitor::primary(1280, 1024)]);
        assert!(
            frames[0]
                .windows(layout_even.len())
                .any(|w| w == layout_even)
        );

        // Out-of-range dimensions and caps-exceeding areas are typed errors.
        assert!(matches!(
            sm.request_resize(100, 768),
            Err(ResizeError::InvalidDimensions { .. })
        ));
        assert!(matches!(
            sm.request_resize(8192, 8192), // 64 MPx > 1920×1080 caps area
            Err(ResizeError::InvalidDimensions { .. })
        ));
    }

    #[test]
    fn hostile_caps_area_does_not_overflow_request_resize() {
        // A malicious server can advertise u32::MAX Display Control area factors;
        // their product (u32³ > u64) must not overflow caps.max_area() into a
        // debug-build panic when the client validates a resize. The product
        // saturates, so an in-range resize still proceeds. Parallel of slice-9's
        // hostile_map_origin_does_not_overflow_or_emit.
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        // All three caps factors maxed → the product is u32³ ≈ 2^96, which
        // overflows u64 (monitors must also be large; the 2-arg helper pins it to
        // 1, where MAX² still fits u64 and would not exercise the guard).
        display_control_ready_caps(&mut sm, u32::MAX, u32::MAX, u32::MAX);
        assert!(
            sm.request_resize(1280, 1024).is_ok(),
            "a saturated caps limit must not block a legitimately-bounded resize"
        );
    }

    #[test]
    fn refused_dynamic_channels_get_a_negative_creation_status() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let mut create = vec![0x10, 0x09];
        create.extend_from_slice(b"Microsoft::Windows::RDS::Geometry\0");
        let mut outputs = Vec::new();
        for frame in server_dvc_frames(&create) {
            outputs.extend(sm.process_bytes(&frame).unwrap());
        }
        let [SessionOutput::WriteBytes(frame)] = outputs.as_slice() else {
            panic!("expected one refusal frame, got {outputs:?}");
        };
        let refusal = dvc::encode_create_response(9, 0x8000_4005);
        let expected_chunk = &svc::encode_chunks(&refusal)[0];
        assert!(
            frame
                .windows(expected_chunk.len())
                .any(|w| w == expected_chunk.as_slice())
        );
        // And resize stays unavailable.
        assert_eq!(sm.request_resize(1280, 1024), Err(ResizeError::NotReady));
    }

    #[test]
    fn resize_then_deactivate_reactivate_applies_the_new_size() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        display_control_ready(&mut sm, 8192, 8192);
        sm.request_resize(8, 4).unwrap_err(); // below 200: validated
        let _ = sm.request_resize(1280, 1024).unwrap();

        // The server answers with the Deactivation–Reactivation cycle (already covered by
        // deactivate_reactivate_resizes_and_reemits_full_screen); here we assert the
        // drdynvc state survives it: Display Control stays ready afterwards.
        let deactivate = server_io_frame(&share::encode_share_control(
            share::PDU_TYPE_DEACTIVATE_ALL,
            1002,
            SHARE,
            &[],
        ));
        assert!(sm.process_bytes(&deactivate).unwrap().is_empty());
        assert!(
            sm.request_resize(1024, 768).is_ok(),
            "resize survives deactivation"
        );
    }

    #[test]
    fn without_a_drdynvc_channel_resize_is_not_ready_and_traffic_is_skipped() {
        let mut cfg = config();
        cfg.drdynvc_channel_id = None;
        let mut sm = SessionStateMachine::new(cfg, Vec::new());
        assert_eq!(sm.request_resize(1280, 1024), Err(ResizeError::NotReady));
        // What would have been drdynvc traffic is now unknown-static-channel noise: skipped.
        let caps_request = vec![0x50, 0x00, 0x01, 0x00];
        for frame in server_dvc_frames(&caps_request) {
            assert!(sm.process_bytes(&frame).unwrap().is_empty());
        }
    }

    #[test]
    fn malformed_bitmap_data_is_a_typed_error_not_a_panic() {
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        // Compressed flag with garbage RLE that overruns the image.
        let mut body = Vec::new();
        body.extend_from_slice(&update::UPDATETYPE_BITMAP.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        for v in [0u16, 0, 3, 0, 4, 1, 8] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(
            &(update::BITMAP_COMPRESSION | update::NO_BITMAP_COMPRESSION_HDR).to_le_bytes(),
        );
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(0x1F); // BG run of 31 pixels into a 4-pixel image
        let err = sm
            .process_bytes(&server_data_pdu(share::PDU_TYPE2_UPDATE, &body))
            .unwrap_err();
        assert!(matches!(err, SessionError::Rle(_)), "got {err:?}");

        // Bytes split across reads still reassemble (chunked TPKT).
        let mut sm = SessionStateMachine::new(config(), Vec::new());
        let frame = bitmap_update_frame(0, 0, 4, 2, [1, 2, 3]);
        let (a, b) = frame.split_at(7);
        assert!(sm.process_bytes(a).unwrap().is_empty());
        assert_eq!(sm.process_bytes(b).unwrap().len(), 1);
    }
}
