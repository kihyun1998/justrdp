#![forbid(unsafe_code)]

//! RDPEGFX server-side DVC processor -- mirror of [`crate::GfxClient`].
//!
//! The server holds the `Microsoft::Windows::RDS::Graphics` DVC, accepts
//! the client's `CapsAdvertise`, replies with `CapsConfirm`, and emits
//! graphics commands (CreateSurface, ResetGraphics, WireToSurface*, …)
//! into the channel.
//!
//! ## Wire framing
//!
//! Per MS-RDPEGFX §2.2.5 (Transport):
//!
//! - **Server → client** messages MUST be wrapped in `RDP_SEGMENTED_DATA`.
//!   This module emits the SINGLE form `[0xE0, 0x04, <RDPGFX_HEADER ||
//!   body bytes>]` -- ZGFX compression is left to §11.2b-4.
//! - **Client → server** messages are NOT wrapped; the server reads the
//!   `RDPGFX_HEADER` directly off the DVC payload.
//!
//! ## Commit staging (§11.2b-3)
//!
//! - **Commit 1** (this commit): skeleton, [`ServerState`] machine, caps
//!   handshake, and surface lifecycle send API
//!   (create/delete/reset/map-to-output/window/scaled-output/scaled-window).
//! - Commit 2: bitmap commands (WireToSurface1/2, SolidFill,
//!   SurfaceToSurface, DeleteEncodingContext).
//! - Commit 3: cache commands.
//! - Commit 4: frame envelope (StartFrame/EndFrame) + FrameAcknowledge
//!   tracking.
//! - Commit 5: `RdpServerDisplayHandler::get_egfx_frame()` seam +
//!   loopback integration test.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::pdu::{
    CapsAdvertisePdu, CapsConfirmPdu, CreateSurfacePdu, DeleteSurfacePdu, GfxCapSet,
    GfxMonitorDef, GfxPixelFormat, MapSurfaceToOutputPdu, MapSurfaceToScaledOutputPdu,
    MapSurfaceToScaledWindowPdu, MapSurfaceToWindowPdu, RdpgfxHeader, ResetGraphicsPdu,
    RDPGFX_CAPVERSION_10, RDPGFX_CAPVERSION_101, RDPGFX_CAPVERSION_102,
    RDPGFX_CAPVERSION_103, RDPGFX_CAPVERSION_104, RDPGFX_CAPVERSION_105,
    RDPGFX_CAPVERSION_106, RDPGFX_CAPVERSION_107, RDPGFX_CAPVERSION_8,
    RDPGFX_CAPVERSION_81, RDPGFX_CMDID_CREATESURFACE, RDPGFX_CMDID_DELETESURFACE,
    RDPGFX_CMDID_MAPSURFACETOOUTPUT, RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT,
    RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW, RDPGFX_CMDID_MAPSURFACETOWINDOW,
};

/// DVC channel name (MS-RDPEGFX §2.2.5).
const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

/// `RDP_SEGMENTED_DATA.descriptor` value for an unfragmented frame
/// (MS-RDPEGFX §2.2.5.1).
const RDP_SEGMENT_SINGLE: u8 = 0xE0;

/// Bulk-encoded-data header byte for an uncompressed RDP8 segment
/// (low nibble = `PACKET_COMPR_TYPE_RDP8 = 0x04`, `PACKET_COMPRESSED`
/// bit clear). Matches what [`crate::client::tests::wrap_uncompressed`]
/// emits and what `ZgfxDecompressor` accepts as a no-op passthrough.
const RDP8_HEADER_UNCOMPRESSED: u8 = 0x04;

/// Server's preferred capability versions, ordered highest-first.
/// `select_version` walks this list and returns the first version the
/// client also advertised. Drivers can override via
/// [`GfxServer::with_supported_versions`].
const DEFAULT_SUPPORTED_VERSIONS: &[u32] = &[
    RDPGFX_CAPVERSION_107,
    RDPGFX_CAPVERSION_106,
    RDPGFX_CAPVERSION_105,
    RDPGFX_CAPVERSION_104,
    RDPGFX_CAPVERSION_103,
    RDPGFX_CAPVERSION_102,
    RDPGFX_CAPVERSION_101,
    RDPGFX_CAPVERSION_10,
    RDPGFX_CAPVERSION_81,
    RDPGFX_CAPVERSION_8,
];

// ── ServerState ─────────────────────────────────────────────────────

/// Server-side `GfxServer` lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// DVC is open; awaiting the client's `CapsAdvertise`.
    WaitingForCapsAdvertise,
    /// Caps handshake complete; the server may emit graphics commands.
    Active,
    /// DVC has been closed.
    Closed,
}

// ── GfxServer ───────────────────────────────────────────────────────

/// RDPEGFX Graphics Pipeline DVC server.
///
/// Implements [`DvcProcessor`] for the
/// `Microsoft::Windows::RDS::Graphics` channel and exposes a send API
/// for graphics commands. State transitions are driven by the inbound
/// DVC payloads in [`DvcProcessor::process`] (Commit 1: caps only;
/// Commit 4 adds FrameAcknowledge tracking).
pub struct GfxServer {
    state: ServerState,
    supported_versions: Vec<u32>,
    negotiated: Option<GfxCapSet>,
    /// Frame IDs sent via `start_frame()` not yet acked. Populated in
    /// Commit 4; held here so the type does not change between commits.
    pending_frames: VecDeque<u32>,
    next_frame_id: u32,
    /// Set when the client returns `SUSPEND_FRAME_ACKNOWLEDGEMENT` in a
    /// `FrameAcknowledge`. Wired in Commit 4.
    ack_suspended: bool,
    total_frames_acked: u32,
}

impl Default for GfxServer {
    fn default() -> Self {
        Self::new()
    }
}

impl GfxServer {
    /// Construct a server that supports the default capability version
    /// list (10.7 down to 8, highest preferred).
    pub fn new() -> Self {
        Self::with_supported_versions(DEFAULT_SUPPORTED_VERSIONS.to_vec())
    }

    /// Construct a server with a caller-supplied list of supported
    /// capability versions, ordered highest-preferred-first. Versions
    /// the client does not advertise are skipped during selection.
    pub fn with_supported_versions(supported_versions: Vec<u32>) -> Self {
        Self {
            state: ServerState::WaitingForCapsAdvertise,
            supported_versions,
            negotiated: None,
            pending_frames: VecDeque::new(),
            next_frame_id: 0,
            ack_suspended: false,
            total_frames_acked: 0,
        }
    }

    /// Current lifecycle state.
    pub fn state(&self) -> ServerState {
        self.state
    }

    /// Negotiated capability set, available after the
    /// `CapsAdvertise → CapsConfirm` handshake completes.
    pub fn negotiated(&self) -> Option<&GfxCapSet> {
        self.negotiated.as_ref()
    }

    /// Number of frames in the in-flight set (sent `StartFrame`, no
    /// matching `FrameAcknowledge` yet). Always zero in Commit 1; wired
    /// in Commit 4.
    pub fn pending_frame_count(&self) -> usize {
        self.pending_frames.len()
    }

    /// Whether the client has asked the server to stop emitting frames
    /// via `SUSPEND_FRAME_ACKNOWLEDGEMENT`. Wired in Commit 4.
    pub fn ack_suspended(&self) -> bool {
        self.ack_suspended
    }

    /// `frame_id` that the next `start_frame()` call will assign.
    /// Wired in Commit 4; included now so the public surface is stable.
    pub fn next_frame_id(&self) -> u32 {
        self.next_frame_id
    }

    /// Choose the highest-priority version both sides advertise.
    fn select_version(&self, advertised: &[GfxCapSet]) -> Option<GfxCapSet> {
        for &v in &self.supported_versions {
            if let Some(cs) = advertised.iter().find(|cs| cs.version == v) {
                return Some(cs.clone());
            }
        }
        None
    }

    /// Build a `RDP_SEGMENTED_DATA` SINGLE wrapper around
    /// `command_bytes` and return it as a [`DvcMessage`]. Server outbound
    /// commands all flow through this helper to keep the wrapping
    /// concentrated.
    fn wrap_single(command_bytes: Vec<u8>) -> DvcMessage {
        let mut out = Vec::with_capacity(2 + command_bytes.len());
        out.push(RDP_SEGMENT_SINGLE);
        out.push(RDP8_HEADER_UNCOMPRESSED);
        out.extend_from_slice(&command_bytes);
        DvcMessage::new(out)
    }

    /// Encode an `RDPGFX_HEADER + body` pair (where `body` writes only
    /// the body bytes, like `CreateSurfacePdu` and friends) into the
    /// command bytes that `wrap_single` will then wrap.
    fn encode_command<E: Encode>(cmd_id: u16, body: &E) -> DvcResult<Vec<u8>> {
        let body_size = body.size();
        let pdu_length = (RdpgfxHeader::WIRE_SIZE + body_size) as u32;
        let mut buf = vec![0u8; RdpgfxHeader::WIRE_SIZE + body_size];
        {
            let mut c = WriteCursor::new(&mut buf);
            RdpgfxHeader {
                cmd_id,
                flags: 0,
                pdu_length,
            }
            .encode(&mut c)
            .map_err(DvcError::Encode)?;
            body.encode(&mut c).map_err(DvcError::Encode)?;
        }
        Ok(buf)
    }

    /// Encode a self-framing PDU (one whose `Encode` impl writes its own
    /// `RDPGFX_HEADER`, e.g. [`CapsConfirmPdu`]).
    fn encode_self_framed<E: Encode>(pdu: &E) -> DvcResult<Vec<u8>> {
        let mut buf = vec![0u8; pdu.size()];
        {
            let mut c = WriteCursor::new(&mut buf);
            pdu.encode(&mut c).map_err(DvcError::Encode)?;
        }
        Ok(buf)
    }

    /// Reject the call when the server is not in the `Active` state.
    fn ensure_active(&self) -> DvcResult<()> {
        match self.state {
            ServerState::Active => Ok(()),
            ServerState::WaitingForCapsAdvertise => Err(DvcError::Protocol(String::from(
                "GfxServer: send before CapsAdvertise/CapsConfirm handshake",
            ))),
            ServerState::Closed => Err(DvcError::Protocol(String::from(
                "GfxServer: channel is closed",
            ))),
        }
    }

    // ── Send API (surface lifecycle) ────────────────────────────────

    /// `RDPGFX_RESET_GRAPHICS_PDU` (MS-RDPEGFX 2.2.2.14). Resizes the
    /// virtual desktop and -- per spec -- MUST precede any surface
    /// commands targeting the new geometry.
    pub fn reset_graphics(
        &self,
        width: u32,
        height: u32,
        monitors: Vec<GfxMonitorDef>,
    ) -> DvcResult<DvcMessage> {
        self.ensure_active()?;
        let body = ResetGraphicsPdu {
            width,
            height,
            monitors,
        };
        Ok(Self::wrap_single(Self::encode_command(
            crate::pdu::RDPGFX_CMDID_RESETGRAPHICS,
            &body,
        )?))
    }

    /// `RDPGFX_CREATE_SURFACE_PDU` (MS-RDPEGFX 2.2.2.9).
    pub fn create_surface(
        &self,
        surface_id: u16,
        width: u16,
        height: u16,
        pixel_format: GfxPixelFormat,
    ) -> DvcResult<DvcMessage> {
        self.ensure_active()?;
        let body = CreateSurfacePdu {
            surface_id,
            width,
            height,
            pixel_format,
        };
        Ok(Self::wrap_single(Self::encode_command(
            RDPGFX_CMDID_CREATESURFACE,
            &body,
        )?))
    }

    /// `RDPGFX_DELETE_SURFACE_PDU` (MS-RDPEGFX 2.2.2.10).
    pub fn delete_surface(&self, surface_id: u16) -> DvcResult<DvcMessage> {
        self.ensure_active()?;
        let body = DeleteSurfacePdu { surface_id };
        Ok(Self::wrap_single(Self::encode_command(
            RDPGFX_CMDID_DELETESURFACE,
            &body,
        )?))
    }

    /// `RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU` (MS-RDPEGFX 2.2.2.15).
    pub fn map_surface_to_output(
        &self,
        surface_id: u16,
        output_origin_x: u32,
        output_origin_y: u32,
    ) -> DvcResult<DvcMessage> {
        self.ensure_active()?;
        let body = MapSurfaceToOutputPdu {
            surface_id,
            output_origin_x,
            output_origin_y,
        };
        Ok(Self::wrap_single(Self::encode_command(
            RDPGFX_CMDID_MAPSURFACETOOUTPUT,
            &body,
        )?))
    }

    /// `RDPGFX_MAP_SURFACE_TO_WINDOW_PDU` (MS-RDPEGFX 2.2.2.20). RAIL
    /// integration; available regardless of negotiated version.
    pub fn map_surface_to_window(
        &self,
        surface_id: u16,
        window_id: u64,
        mapped_width: u32,
        mapped_height: u32,
    ) -> DvcResult<DvcMessage> {
        self.ensure_active()?;
        let body = MapSurfaceToWindowPdu {
            surface_id,
            window_id,
            mapped_width,
            mapped_height,
        };
        Ok(Self::wrap_single(Self::encode_command(
            RDPGFX_CMDID_MAPSURFACETOWINDOW,
            &body,
        )?))
    }

    /// `RDPGFX_MAP_SURFACE_TO_SCALED_OUTPUT_PDU` (MS-RDPEGFX 2.2.2.22).
    /// Requires VERSION10.7 or higher; fallback callers should use
    /// [`map_surface_to_output`](Self::map_surface_to_output) instead.
    pub fn map_surface_to_scaled_output(
        &self,
        surface_id: u16,
        output_origin_x: u32,
        output_origin_y: u32,
        target_width: u32,
        target_height: u32,
    ) -> DvcResult<DvcMessage> {
        self.ensure_active()?;
        let body = MapSurfaceToScaledOutputPdu {
            surface_id,
            output_origin_x,
            output_origin_y,
            target_width,
            target_height,
        };
        Ok(Self::wrap_single(Self::encode_command(
            RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT,
            &body,
        )?))
    }

    /// `RDPGFX_MAP_SURFACE_TO_SCALED_WINDOW_PDU` (MS-RDPEGFX 2.2.2.23).
    /// Same version constraint as `map_surface_to_scaled_output`.
    pub fn map_surface_to_scaled_window(
        &self,
        surface_id: u16,
        window_id: u64,
        mapped_width: u32,
        mapped_height: u32,
        target_width: u32,
        target_height: u32,
    ) -> DvcResult<DvcMessage> {
        self.ensure_active()?;
        let body = MapSurfaceToScaledWindowPdu {
            surface_id,
            window_id,
            mapped_width,
            mapped_height,
            target_width,
            target_height,
        };
        Ok(Self::wrap_single(Self::encode_command(
            RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW,
            &body,
        )?))
    }
}

impl core::fmt::Debug for GfxServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GfxServer")
            .field("state", &self.state)
            .field("negotiated", &self.negotiated)
            .field("pending_frame_count", &self.pending_frames.len())
            .field("next_frame_id", &self.next_frame_id)
            .field("ack_suspended", &self.ack_suspended)
            .finish()
    }
}

impl AsAny for GfxServer {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for GfxServer {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // Reset session state on (re)open. Per MS-RDPEGFX 3.3.5.1 the
        // **client** speaks first with CapsAdvertise; the server emits
        // nothing at channel open time.
        self.state = ServerState::WaitingForCapsAdvertise;
        self.negotiated = None;
        self.pending_frames.clear();
        self.next_frame_id = 0;
        self.ack_suspended = false;
        self.total_frames_acked = 0;
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if matches!(self.state, ServerState::Closed) {
            return Err(DvcError::Protocol(String::from(
                "GfxServer: process on closed channel",
            )));
        }

        // Client → server payloads are NOT wrapped in RDP_SEGMENTED_DATA
        // (MS-RDPEGFX 2.2.5 Transport: "Client-to-server graphics
        // messages are not encapsulated within any external structure"),
        // so we read the RDPGFX_HEADER directly off the payload.
        let mut src = ReadCursor::new(payload);

        match self.state {
            ServerState::WaitingForCapsAdvertise => {
                let advertise = CapsAdvertisePdu::decode(&mut src).map_err(DvcError::Decode)?;
                if advertise.cap_sets.is_empty() {
                    return Err(DvcError::Protocol(String::from(
                        "GfxServer: CapsAdvertise carried zero cap sets",
                    )));
                }
                let chosen = self.select_version(&advertise.cap_sets).ok_or_else(|| {
                    DvcError::Protocol(String::from(
                        "GfxServer: no advertised cap version is supported",
                    ))
                })?;
                let confirm = CapsConfirmPdu {
                    cap_set: chosen.clone(),
                };
                let bytes = Self::encode_self_framed(&confirm)?;
                self.negotiated = Some(chosen);
                self.state = ServerState::Active;
                Ok(vec![Self::wrap_single(bytes)])
            }
            ServerState::Active => {
                // Commit 1 only: the only legal client → server traffic
                // in the Active state is FrameAcknowledge /
                // QoEFrameAcknowledge (Commit 4 wires those). For now
                // surface the unexpected payload as a protocol error so
                // tests notice if anything else slips through.
                Err(DvcError::Protocol(String::from(
                    "GfxServer: inbound dispatch in Active state lands in §11.2b-3 Commit 4",
                )))
            }
            ServerState::Closed => unreachable!("guarded above"),
        }
    }

    fn close(&mut self, _channel_id: u32) {
        self.state = ServerState::Closed;
        self.negotiated = None;
        self.pending_frames.clear();
        self.next_frame_id = 0;
        self.ack_suspended = false;
        self.total_frames_acked = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{
        PIXEL_FORMAT_XRGB_8888, RDPGFX_CMDID_CAPSCONFIRM, RDPGFX_CMDID_RESETGRAPHICS,
    };

    fn make_advertise(versions: &[u32]) -> Vec<u8> {
        let pdu = CapsAdvertisePdu {
            cap_sets: versions.iter().map(|&v| GfxCapSet { version: v, flags: 0 }).collect(),
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut c = WriteCursor::new(&mut buf);
        pdu.encode(&mut c).unwrap();
        buf
    }

    /// Strip the SINGLE wrapper from a server-emitted message and
    /// return the raw RDPGFX command bytes (header + body).
    fn unwrap_single(msg: &DvcMessage) -> &[u8] {
        assert_eq!(msg.data[0], RDP_SEGMENT_SINGLE, "missing 0xE0 descriptor");
        assert_eq!(
            msg.data[1], RDP8_HEADER_UNCOMPRESSED,
            "expected uncompressed RDP8 header byte 0x04",
        );
        &msg.data[2..]
    }

    fn parse_command_header(bytes: &[u8]) -> RdpgfxHeader {
        let mut c = ReadCursor::new(bytes);
        RdpgfxHeader::decode(&mut c).unwrap()
    }

    // ── DvcProcessor + state machine ─────────────────────────────

    #[test]
    fn channel_name_matches_client() {
        let s = GfxServer::new();
        assert_eq!(s.channel_name(), "Microsoft::Windows::RDS::Graphics");
    }

    #[test]
    fn start_emits_nothing_and_resets_state() {
        let mut s = GfxServer::new();
        let msgs = s.start(1).unwrap();
        assert!(msgs.is_empty(), "server speaks only after CapsAdvertise");
        assert_eq!(s.state(), ServerState::WaitingForCapsAdvertise);
        assert!(s.negotiated().is_none());
        assert_eq!(s.pending_frame_count(), 0);
        assert!(!s.ack_suspended());
        assert_eq!(s.next_frame_id(), 0);
    }

    #[test]
    fn caps_advertise_produces_caps_confirm_with_highest_version() {
        let mut s = GfxServer::new();
        s.start(1).unwrap();
        let advertise = make_advertise(&[
            RDPGFX_CAPVERSION_8,
            RDPGFX_CAPVERSION_10,
            RDPGFX_CAPVERSION_107,
        ]);
        let msgs = s.process(1, &advertise).unwrap();
        assert_eq!(msgs.len(), 1);

        let cmd = unwrap_single(&msgs[0]);
        let hdr = parse_command_header(cmd);
        assert_eq!(hdr.cmd_id, RDPGFX_CMDID_CAPSCONFIRM);
        assert_eq!(hdr.flags, 0);

        // Re-decode the full CapsConfirm and assert the chosen version.
        let mut c = ReadCursor::new(cmd);
        let confirm = CapsConfirmPdu::decode(&mut c).unwrap();
        assert_eq!(confirm.cap_set.version, RDPGFX_CAPVERSION_107);

        assert_eq!(s.state(), ServerState::Active);
        assert_eq!(
            s.negotiated().map(|c| c.version),
            Some(RDPGFX_CAPVERSION_107),
        );
    }

    #[test]
    fn caps_advertise_picks_highest_advertised_then_supported() {
        let mut s = GfxServer::with_supported_versions(vec![
            RDPGFX_CAPVERSION_10,
            RDPGFX_CAPVERSION_8,
        ]);
        s.start(1).unwrap();
        // Client advertises 8 and 107; server only supports 10 and 8.
        let advertise = make_advertise(&[RDPGFX_CAPVERSION_8, RDPGFX_CAPVERSION_107]);
        let msgs = s.process(1, &advertise).unwrap();
        let mut c = ReadCursor::new(unwrap_single(&msgs[0]));
        let confirm = CapsConfirmPdu::decode(&mut c).unwrap();
        // Server picked 8 (only intersection -- 107 not supported, 10 not advertised).
        assert_eq!(confirm.cap_set.version, RDPGFX_CAPVERSION_8);
    }

    #[test]
    fn caps_advertise_echoes_client_flags_for_chosen_version() {
        let mut s = GfxServer::new();
        s.start(1).unwrap();
        let pdu = CapsAdvertisePdu {
            cap_sets: vec![
                GfxCapSet { version: RDPGFX_CAPVERSION_8, flags: 0x0001 },
                GfxCapSet { version: RDPGFX_CAPVERSION_10, flags: 0x0020 },
            ],
        };
        let mut buf = vec![0u8; pdu.size()];
        pdu.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        let msgs = s.process(1, &buf).unwrap();
        let mut c = ReadCursor::new(unwrap_single(&msgs[0]));
        let confirm = CapsConfirmPdu::decode(&mut c).unwrap();
        assert_eq!(confirm.cap_set.version, RDPGFX_CAPVERSION_10);
        assert_eq!(confirm.cap_set.flags, 0x0020);
    }

    #[test]
    fn caps_advertise_rejects_when_no_match() {
        let mut s = GfxServer::with_supported_versions(vec![RDPGFX_CAPVERSION_107]);
        s.start(1).unwrap();
        let advertise = make_advertise(&[RDPGFX_CAPVERSION_8]);
        let res = s.process(1, &advertise);
        assert!(res.is_err());
        // State must NOT advance to Active when no version matches.
        assert_eq!(s.state(), ServerState::WaitingForCapsAdvertise);
        assert!(s.negotiated().is_none());
    }

    #[test]
    fn caps_advertise_rejects_empty_cap_sets() {
        let mut s = GfxServer::new();
        s.start(1).unwrap();
        let advertise = make_advertise(&[]);
        assert!(s.process(1, &advertise).is_err());
        assert_eq!(s.state(), ServerState::WaitingForCapsAdvertise);
    }

    #[test]
    fn process_in_active_state_rejects_in_commit_1() {
        // Commit 1: any inbound after Active is a protocol error
        // (Commit 4 will accept FrameAcknowledge / QoEFrameAcknowledge).
        let mut s = GfxServer::new();
        s.start(1).unwrap();
        let advertise = make_advertise(&[RDPGFX_CAPVERSION_10]);
        s.process(1, &advertise).unwrap();
        assert_eq!(s.state(), ServerState::Active);
        // Feed any non-empty payload -- expected to fail.
        assert!(s.process(1, &[0u8; 8]).is_err());
    }

    #[test]
    fn process_after_close_errors() {
        let mut s = GfxServer::new();
        s.start(1).unwrap();
        s.close(1);
        assert_eq!(s.state(), ServerState::Closed);
        let advertise = make_advertise(&[RDPGFX_CAPVERSION_10]);
        assert!(s.process(1, &advertise).is_err());
    }

    #[test]
    fn close_resets_all_state() {
        let mut s = GfxServer::new();
        s.start(1).unwrap();
        let advertise = make_advertise(&[RDPGFX_CAPVERSION_10]);
        s.process(1, &advertise).unwrap();
        assert!(s.negotiated().is_some());
        s.close(1);
        assert!(s.negotiated().is_none());
        assert_eq!(s.pending_frame_count(), 0);
    }

    // ── Send API gating ──────────────────────────────────────────

    fn activated() -> GfxServer {
        let mut s = GfxServer::new();
        s.start(1).unwrap();
        let advertise = make_advertise(&[RDPGFX_CAPVERSION_10]);
        s.process(1, &advertise).unwrap();
        assert_eq!(s.state(), ServerState::Active);
        s
    }

    #[test]
    fn send_before_active_errors() {
        let s = GfxServer::new();
        assert!(s.create_surface(1, 64, 64, GfxPixelFormat::XRGB_8888).is_err());
        assert!(s.delete_surface(1).is_err());
        assert!(s.reset_graphics(1024, 768, vec![]).is_err());
        assert!(s.map_surface_to_output(1, 0, 0).is_err());
        assert!(s.map_surface_to_window(1, 0, 0, 0).is_err());
        assert!(s.map_surface_to_scaled_output(1, 0, 0, 0, 0).is_err());
        assert!(s.map_surface_to_scaled_window(1, 0, 0, 0, 0, 0).is_err());
    }

    #[test]
    fn send_after_close_errors() {
        let mut s = activated();
        s.close(1);
        assert!(s.create_surface(1, 64, 64, GfxPixelFormat::XRGB_8888).is_err());
        assert!(s.delete_surface(1).is_err());
        assert!(s.reset_graphics(1024, 768, vec![]).is_err());
        assert!(s.map_surface_to_output(1, 0, 0).is_err());
        assert!(s.map_surface_to_window(1, 0, 0, 0).is_err());
        assert!(s.map_surface_to_scaled_output(1, 0, 0, 0, 0).is_err());
        assert!(s.map_surface_to_scaled_window(1, 0, 0, 0, 0, 0).is_err());
    }

    #[test]
    fn default_equals_new() {
        assert_eq!(GfxServer::default().state(), GfxServer::new().state());
    }

    #[test]
    fn caps_advertise_can_succeed_after_a_rejected_attempt() {
        // After an unmatched advertise the server stays in
        // WaitingForCapsAdvertise; a follow-up advertise with a
        // supported version MUST still complete the handshake.
        let mut s = GfxServer::with_supported_versions(vec![RDPGFX_CAPVERSION_10]);
        s.start(1).unwrap();
        let bad = make_advertise(&[RDPGFX_CAPVERSION_8]);
        assert!(s.process(1, &bad).is_err());
        assert_eq!(s.state(), ServerState::WaitingForCapsAdvertise);
        let good = make_advertise(&[RDPGFX_CAPVERSION_10]);
        let msgs = s.process(1, &good).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(s.state(), ServerState::Active);
    }

    // ── Send API roundtrip (each PDU) ────────────────────────────

    #[test]
    fn create_surface_roundtrip() {
        let s = activated();
        let msg = s
            .create_surface(42, 1920, 1080, GfxPixelFormat::XRGB_8888)
            .unwrap();
        let cmd = unwrap_single(&msg);
        let hdr = parse_command_header(cmd);
        assert_eq!(hdr.cmd_id, RDPGFX_CMDID_CREATESURFACE);
        assert_eq!(hdr.pdu_length as usize, cmd.len());
        let mut c = ReadCursor::new(&cmd[RdpgfxHeader::WIRE_SIZE..]);
        let body = CreateSurfacePdu::decode(&mut c).unwrap();
        assert_eq!(body.surface_id, 42);
        assert_eq!(body.width, 1920);
        assert_eq!(body.height, 1080);
        assert_eq!(body.pixel_format.0, PIXEL_FORMAT_XRGB_8888);
    }

    #[test]
    fn delete_surface_roundtrip() {
        let s = activated();
        let msg = s.delete_surface(7).unwrap();
        let cmd = unwrap_single(&msg);
        assert_eq!(parse_command_header(cmd).cmd_id, RDPGFX_CMDID_DELETESURFACE);
        let body = DeleteSurfacePdu::decode(&mut ReadCursor::new(
            &cmd[RdpgfxHeader::WIRE_SIZE..],
        ))
        .unwrap();
        assert_eq!(body.surface_id, 7);
    }

    #[test]
    fn reset_graphics_zero_monitors_roundtrip() {
        let s = activated();
        let msg = s.reset_graphics(1920, 1080, vec![]).unwrap();
        let cmd = unwrap_single(&msg);
        let hdr = parse_command_header(cmd);
        assert_eq!(hdr.cmd_id, RDPGFX_CMDID_RESETGRAPHICS);
        // MS-RDPEGFX 2.2.2.14: pduLength MUST be 340.
        assert_eq!(hdr.pdu_length, ResetGraphicsPdu::FIXED_PDU_LENGTH);
        let pdu = ResetGraphicsPdu::decode(&mut ReadCursor::new(
            &cmd[RdpgfxHeader::WIRE_SIZE..],
        ))
        .unwrap();
        assert_eq!(pdu.width, 1920);
        assert_eq!(pdu.height, 1080);
        assert!(pdu.monitors.is_empty());
    }

    #[test]
    fn reset_graphics_with_monitors_roundtrip() {
        let s = activated();
        let monitors = vec![GfxMonitorDef {
            left: 0,
            top: 0,
            right: 1919,
            bottom: 1079,
            flags: 0x0000_0001, // primary
        }];
        let msg = s
            .reset_graphics(1920, 1080, monitors.clone())
            .unwrap();
        let cmd = unwrap_single(&msg);
        let hdr = parse_command_header(cmd);
        assert_eq!(hdr.pdu_length, ResetGraphicsPdu::FIXED_PDU_LENGTH);
        let pdu = ResetGraphicsPdu::decode(&mut ReadCursor::new(
            &cmd[RdpgfxHeader::WIRE_SIZE..],
        ))
        .unwrap();
        assert_eq!(pdu.monitors, monitors);
    }

    #[test]
    fn map_surface_to_output_roundtrip() {
        let s = activated();
        let msg = s.map_surface_to_output(5, 100, 200).unwrap();
        let cmd = unwrap_single(&msg);
        assert_eq!(parse_command_header(cmd).cmd_id, RDPGFX_CMDID_MAPSURFACETOOUTPUT);
        let body = MapSurfaceToOutputPdu::decode(&mut ReadCursor::new(
            &cmd[RdpgfxHeader::WIRE_SIZE..],
        ))
        .unwrap();
        assert_eq!(body.surface_id, 5);
        assert_eq!(body.output_origin_x, 100);
        assert_eq!(body.output_origin_y, 200);
    }

    #[test]
    fn map_surface_to_window_roundtrip() {
        let s = activated();
        let msg = s
            .map_surface_to_window(9, 0xCAFE_BABE_DEAD_BEEF, 800, 600)
            .unwrap();
        let cmd = unwrap_single(&msg);
        assert_eq!(parse_command_header(cmd).cmd_id, RDPGFX_CMDID_MAPSURFACETOWINDOW);
        let body = MapSurfaceToWindowPdu::decode(&mut ReadCursor::new(
            &cmd[RdpgfxHeader::WIRE_SIZE..],
        ))
        .unwrap();
        assert_eq!(body.surface_id, 9);
        assert_eq!(body.window_id, 0xCAFE_BABE_DEAD_BEEF);
        assert_eq!(body.mapped_width, 800);
        assert_eq!(body.mapped_height, 600);
    }

    #[test]
    fn map_surface_to_scaled_output_roundtrip() {
        let s = activated();
        let msg = s
            .map_surface_to_scaled_output(2, 10, 20, 1024, 768)
            .unwrap();
        let cmd = unwrap_single(&msg);
        assert_eq!(
            parse_command_header(cmd).cmd_id,
            RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT,
        );
        let body = MapSurfaceToScaledOutputPdu::decode(&mut ReadCursor::new(
            &cmd[RdpgfxHeader::WIRE_SIZE..],
        ))
        .unwrap();
        assert_eq!(body.surface_id, 2);
        assert_eq!(body.output_origin_x, 10);
        assert_eq!(body.output_origin_y, 20);
        assert_eq!(body.target_width, 1024);
        assert_eq!(body.target_height, 768);
    }

    #[test]
    fn map_surface_to_scaled_window_roundtrip() {
        let s = activated();
        let msg = s
            .map_surface_to_scaled_window(4, 0x1234_5678_9ABC_DEF0, 800, 600, 1024, 768)
            .unwrap();
        let cmd = unwrap_single(&msg);
        assert_eq!(
            parse_command_header(cmd).cmd_id,
            RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW,
        );
        let body = MapSurfaceToScaledWindowPdu::decode(&mut ReadCursor::new(
            &cmd[RdpgfxHeader::WIRE_SIZE..],
        ))
        .unwrap();
        assert_eq!(body.surface_id, 4);
        assert_eq!(body.window_id, 0x1234_5678_9ABC_DEF0);
        assert_eq!(body.mapped_width, 800);
        assert_eq!(body.mapped_height, 600);
        assert_eq!(body.target_width, 1024);
        assert_eq!(body.target_height, 768);
    }

    // Single, separate version constants in the test scope — pull
    // unused warnings up here so the core test code stays focused.
    #[allow(unused_imports)]
    use crate::pdu::{
        RDPGFX_CAPVERSION_101, RDPGFX_CAPVERSION_102, RDPGFX_CAPVERSION_103,
        RDPGFX_CAPVERSION_104, RDPGFX_CAPVERSION_105, RDPGFX_CAPVERSION_106,
        RDPGFX_CAPVERSION_81,
    };
}
