#![forbid(unsafe_code)]

//! RDPEGFX DVC client -- MS-RDPEGFX 3.2

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_bulk::zgfx::ZgfxDecompressor;
use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::pdu::{
    CacheImportReplyPdu, CacheToSurfacePdu, CapsAdvertisePdu,
    CreateSurfacePdu, DeleteEncodingContextPdu, DeleteSurfacePdu, EndFramePdu,
    EvictCacheEntryPdu, FrameAcknowledgePdu, GfxCapSet, MapSurfaceToOutputPdu,
    MapSurfaceToScaledOutputPdu, MapSurfaceToScaledWindowPdu, MapSurfaceToWindowPdu,
    ResetGraphicsPdu, RdpgfxHeader, SolidFillPdu,
    StartFramePdu, SurfaceToCachePdu, SurfaceToSurfacePdu, WireToSurface1Pdu,
    WireToSurface2Pdu, QUEUE_DEPTH_UNAVAILABLE, RDPGFX_CAPVERSION_10,
    RDPGFX_CMDID_CACHETOSURFACE, RDPGFX_CMDID_CACHEIMPORTREPLY,
    RDPGFX_CMDID_CAPSCONFIRM, RDPGFX_CMDID_CREATESURFACE,
    RDPGFX_CMDID_DELETEENCODINGCONTEXT, RDPGFX_CMDID_DELETESURFACE,
    RDPGFX_CMDID_ENDFRAME, RDPGFX_CMDID_EVICTCACHEENTRY,
    RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT, RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW,
    RDPGFX_CMDID_MAPSURFACETOOUTPUT, RDPGFX_CMDID_MAPSURFACETOWINDOW,
    RDPGFX_CMDID_RESETGRAPHICS, RDPGFX_CMDID_SOLIDFILL,
    RDPGFX_CMDID_STARTFRAME, RDPGFX_CMDID_SURFACETOCACHE,
    RDPGFX_CMDID_SURFACETOSURFACE, RDPGFX_CMDID_WIRETOSURFACE_1,
    RDPGFX_CMDID_WIRETOSURFACE_2,
};

/// DVC channel name for RDPEGFX.
const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

/// Client state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    /// Waiting for server CapsConfirm.
    WaitingForCapsConfirm,
    /// Active: processing graphics commands.
    Active,
    /// Channel closed.
    Closed,
}

/// RDPEGFX Graphics Pipeline DVC client.
///
/// Implements `DvcProcessor` for the `Microsoft::Windows::RDS::Graphics`
/// dynamic virtual channel.
///
/// On channel start, sends a `CapsAdvertise` with the configured capability sets.
/// After receiving `CapsConfirm`, processes all graphics commands and sends
/// `FrameAcknowledge` responses.
pub struct GfxClient {
    state: ClientState,
    /// Capability sets to advertise.
    cap_sets: Vec<GfxCapSet>,
    /// Negotiated version (from server's CapsConfirm).
    negotiated_version: Option<u32>,
    /// Total frames decoded (for FrameAcknowledge).
    total_frames_decoded: u32,
    /// Whether frame ack is suspended.
    ack_suspended: bool,
    /// ZGFX decompressor for RDP_SEGMENTED_DATA.
    decompressor: ZgfxDecompressor,
}

impl GfxClient {
    /// Create a new GFX client with the given capability sets to advertise.
    ///
    /// The cap_sets should be ordered by preference (most preferred first).
    pub fn new(cap_sets: Vec<GfxCapSet>) -> Self {
        Self {
            state: ClientState::WaitingForCapsConfirm,
            cap_sets,
            negotiated_version: None,
            total_frames_decoded: 0,
            ack_suspended: false,
            decompressor: ZgfxDecompressor::new(),
        }
    }

    /// Create a GFX client with default VERSION10 capability (AVC disabled).
    pub fn default_v10() -> Self {
        Self::new(vec![GfxCapSet {
            version: RDPGFX_CAPVERSION_10,
            flags: crate::pdu::RDPGFX_CAPS_FLAG_AVC_DISABLED,
        }])
    }

    /// Returns the negotiated version, if capability exchange is complete.
    pub fn negotiated_version(&self) -> Option<u32> {
        self.negotiated_version
    }

    /// Suspend frame acknowledgement.
    pub fn suspend_ack(&mut self) {
        self.ack_suspended = true;
    }

    /// Resume frame acknowledgement.
    pub fn resume_ack(&mut self) {
        self.ack_suspended = false;
    }

    /// Process the raw DVC payload (RDP_SEGMENTED_DATA).
    ///
    /// Decompresses via ZGFX, then parses and dispatches all contained
    /// graphics commands.
    fn process_segmented_data(
        &mut self,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
        // Decompress RDP_SEGMENTED_DATA → raw graphics commands
        let mut decompressed = Vec::new();
        self.decompressor
            .decompress(payload, &mut decompressed)
            .map_err(|e| DvcError::Protocol(alloc::format!("ZGFX decompression failed: {e:?}")))?;

        self.dispatch_commands(&decompressed)
    }

    /// Parse and dispatch all graphics commands from the decompressed buffer.
    fn dispatch_commands(&mut self, data: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        let mut src = ReadCursor::new(data);
        let mut responses = Vec::new();

        while src.remaining() >= RdpgfxHeader::WIRE_SIZE {
            let header = RdpgfxHeader::decode(&mut src).map_err(DvcError::Decode)?;

            let body_len = header.pdu_length as usize - RdpgfxHeader::WIRE_SIZE;
            if src.remaining() < body_len {
                return Err(DvcError::Protocol(String::from(
                    "RDPGFX command body exceeds available data",
                )));
            }

            let body = src.read_slice(body_len, "RDPGFX::body").map_err(DvcError::Decode)?;
            let mut body_src = ReadCursor::new(body);

            // CapsConfirm must arrive first; reject other commands before handshake.
            if header.cmd_id == RDPGFX_CMDID_CAPSCONFIRM {
                if self.state != ClientState::WaitingForCapsConfirm {
                    return Err(DvcError::Protocol(String::from(
                        "duplicate CapsConfirm received",
                    )));
                }
                let cap_set = GfxCapSet::decode(&mut body_src).map_err(DvcError::Decode)?;
                self.negotiated_version = Some(cap_set.version);
                self.state = ClientState::Active;
                continue;
            }

            if self.state != ClientState::Active {
                return Err(DvcError::Protocol(String::from(
                    "graphics command received before CapsConfirm",
                )));
            }

            match header.cmd_id {
                RDPGFX_CMDID_RESETGRAPHICS => {
                    let _pdu = ResetGraphicsPdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_CREATESURFACE => {
                    let _pdu =
                        CreateSurfacePdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_DELETESURFACE => {
                    let _pdu =
                        DeleteSurfacePdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_MAPSURFACETOOUTPUT => {
                    let _pdu = MapSurfaceToOutputPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_MAPSURFACETOWINDOW => {
                    let _pdu = MapSurfaceToWindowPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT => {
                    let _pdu = MapSurfaceToScaledOutputPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW => {
                    let _pdu = MapSurfaceToScaledWindowPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_STARTFRAME => {
                    let _pdu =
                        StartFramePdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_ENDFRAME => {
                    let pdu = EndFramePdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                    self.total_frames_decoded = self.total_frames_decoded.saturating_add(1);

                    if !self.ack_suspended {
                        let ack = FrameAcknowledgePdu {
                            queue_depth: QUEUE_DEPTH_UNAVAILABLE,
                            frame_id: pdu.frame_id,
                            total_frames_decoded: self.total_frames_decoded,
                        };
                        responses.push(encode_pdu(&ack)?);
                    }
                }
                RDPGFX_CMDID_WIRETOSURFACE_1 => {
                    let _pdu = WireToSurface1Pdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_WIRETOSURFACE_2 => {
                    let _pdu = WireToSurface2Pdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_DELETEENCODINGCONTEXT => {
                    let _pdu = DeleteEncodingContextPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_SOLIDFILL => {
                    let _pdu =
                        SolidFillPdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_SURFACETOSURFACE => {
                    let _pdu = SurfaceToSurfacePdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_SURFACETOCACHE => {
                    let _pdu = SurfaceToCachePdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_CACHETOSURFACE => {
                    let _pdu = CacheToSurfacePdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_EVICTCACHEENTRY => {
                    let _pdu = EvictCacheEntryPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                RDPGFX_CMDID_CACHEIMPORTREPLY => {
                    let _pdu = CacheImportReplyPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                }
                _ => {
                    // Unknown command: skip (spec defines no error PDU)
                }
            }
        }

        Ok(responses)
    }
}

impl Default for GfxClient {
    fn default() -> Self {
        Self::default_v10()
    }
}

impl core::fmt::Debug for GfxClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GfxClient")
            .field("state", &self.state)
            .field("negotiated_version", &self.negotiated_version)
            .field("total_frames_decoded", &self.total_frames_decoded)
            .field("ack_suspended", &self.ack_suspended)
            .finish()
    }
}

impl AsAny for GfxClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for GfxClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        self.state = ClientState::WaitingForCapsConfirm;
        self.negotiated_version = None;
        self.total_frames_decoded = 0;
        self.ack_suspended = false;

        // Send CapsAdvertise
        let caps_adv = CapsAdvertisePdu {
            cap_sets: self.cap_sets.clone(),
        };
        Ok(vec![encode_pdu(&caps_adv)?])
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if payload.is_empty() {
            return Err(DvcError::Protocol(String::from("empty RDPEGFX payload")));
        }

        match self.state {
            ClientState::Closed => {
                Err(DvcError::Protocol(String::from("channel is closed")))
            }
            ClientState::WaitingForCapsConfirm | ClientState::Active => {
                self.process_segmented_data(payload)
            }
        }
    }

    fn close(&mut self, _channel_id: u32) {
        self.state = ClientState::Closed;
        self.negotiated_version = None;
        self.total_frames_decoded = 0;
        self.ack_suspended = false;
        self.decompressor = ZgfxDecompressor::new();
    }
}

/// Encode any PDU implementing Encode into a DvcMessage.
fn encode_pdu(pdu: &dyn Encode) -> DvcResult<DvcMessage> {
    let size = pdu.size();
    let mut buf = vec![0u8; size];
    let mut dst = WriteCursor::new(&mut buf);
    pdu.encode(&mut dst).map_err(DvcError::Encode)?;
    Ok(DvcMessage::new(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::*;

    /// Build a minimal SINGLE RDP_SEGMENTED_DATA wrapping uncompressed bytes.
    fn wrap_uncompressed(data: &[u8]) -> Vec<u8> {
        // descriptor=0xE0 (SINGLE) + RDP8_BULK_ENCODED_DATA header byte (no compression)
        let mut out = vec![0xE0u8]; // SEGMENTED_SINGLE
        // RDP8 header: compression type = 0x04, NOT compressed
        out.push(0x04);
        out.extend_from_slice(data);
        out
    }

    /// Build a raw GFX command with header + body.
    fn build_gfx_command(cmd_id: u16, body: &[u8]) -> Vec<u8> {
        let pdu_length = (RdpgfxHeader::WIRE_SIZE + body.len()) as u32;
        let mut buf = Vec::with_capacity(pdu_length as usize);
        buf.extend_from_slice(&cmd_id.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&pdu_length.to_le_bytes());
        buf.extend_from_slice(body);
        buf
    }

    fn build_caps_confirm(version: u32, flags: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version.to_le_bytes());
        if version == RDPGFX_CAPVERSION_101 {
            body.extend_from_slice(&16u32.to_le_bytes());
            body.extend_from_slice(&[0u8; 16]);
        } else {
            body.extend_from_slice(&4u32.to_le_bytes());
            body.extend_from_slice(&flags.to_le_bytes());
        }
        build_gfx_command(RDPGFX_CMDID_CAPSCONFIRM, &body)
    }

    fn build_start_frame(frame_id: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        body.extend_from_slice(&frame_id.to_le_bytes());
        build_gfx_command(RDPGFX_CMDID_STARTFRAME, &body)
    }

    fn build_end_frame(frame_id: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&frame_id.to_le_bytes());
        build_gfx_command(RDPGFX_CMDID_ENDFRAME, &body)
    }

    #[test]
    fn channel_name() {
        let client = GfxClient::default_v10();
        assert_eq!(client.channel_name(), "Microsoft::Windows::RDS::Graphics");
    }

    #[test]
    fn start_sends_caps_advertise() {
        let mut client = GfxClient::default_v10();
        let msgs = client.start(1).unwrap();
        assert_eq!(msgs.len(), 1);
        // Verify the message starts with CapsAdvertise cmdId
        let data = &msgs[0].data;
        assert!(data.len() >= 2);
        let cmd_id = u16::from_le_bytes([data[0], data[1]]);
        assert_eq!(cmd_id, RDPGFX_CMDID_CAPSADVERTISE);
    }

    #[test]
    fn caps_confirm_transitions_to_active() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();

        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, RDPGFX_CAPS_FLAG_AVC_DISABLED);
        let payload = wrap_uncompressed(&confirm);
        let msgs = client.process(1, &payload).unwrap();
        assert!(msgs.is_empty());
        assert_eq!(client.negotiated_version(), Some(RDPGFX_CAPVERSION_10));
        assert_eq!(client.state, ClientState::Active);
    }

    #[test]
    fn end_frame_sends_ack() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();

        // CapsConfirm
        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, RDPGFX_CAPS_FLAG_AVC_DISABLED);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();

        // StartFrame + EndFrame in one batch
        let mut commands = Vec::new();
        commands.extend_from_slice(&build_start_frame(1));
        commands.extend_from_slice(&build_end_frame(1));
        let payload = wrap_uncompressed(&commands);
        let msgs = client.process(1, &payload).unwrap();

        assert_eq!(msgs.len(), 1);
        // Verify it's a FrameAcknowledge
        let ack_data = &msgs[0].data;
        let cmd_id = u16::from_le_bytes([ack_data[0], ack_data[1]]);
        assert_eq!(cmd_id, RDPGFX_CMDID_FRAMEACKNOWLEDGE);
        // frameId at offset 12
        let frame_id = u32::from_le_bytes([ack_data[12], ack_data[13], ack_data[14], ack_data[15]]);
        assert_eq!(frame_id, 1);
        // totalFramesDecoded at offset 16
        let total = u32::from_le_bytes([ack_data[16], ack_data[17], ack_data[18], ack_data[19]]);
        assert_eq!(total, 1);
    }

    #[test]
    fn suspended_ack_no_response() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();

        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, 0);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();

        client.suspend_ack();

        let mut commands = Vec::new();
        commands.extend_from_slice(&build_start_frame(1));
        commands.extend_from_slice(&build_end_frame(1));
        let msgs = client.process(1, &wrap_uncompressed(&commands)).unwrap();
        assert!(msgs.is_empty());
        assert_eq!(client.total_frames_decoded, 1);
    }

    #[test]
    fn multiple_frames_increment_counter() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();

        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, 0);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();

        for i in 1..=3 {
            let mut commands = Vec::new();
            commands.extend_from_slice(&build_start_frame(i));
            commands.extend_from_slice(&build_end_frame(i));
            let msgs = client.process(1, &wrap_uncompressed(&commands)).unwrap();
            assert_eq!(msgs.len(), 1);
        }
        assert_eq!(client.total_frames_decoded, 3);
    }

    #[test]
    fn close_transitions_to_closed() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();
        client.close(1);
        assert_eq!(client.state, ClientState::Closed);
    }

    #[test]
    fn process_after_close_errors() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();
        client.close(1);
        let result = client.process(1, &[0xE0, 0x04]);
        assert!(result.is_err());
    }

    #[test]
    fn command_before_caps_confirm_errors() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();

        // Send a StartFrame before CapsConfirm — should error
        let cmd = build_start_frame(1);
        let result = client.process(1, &wrap_uncompressed(&cmd));
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_caps_confirm_errors() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();

        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, 0);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();

        // Second CapsConfirm should error
        let result = client.process(1, &wrap_uncompressed(&confirm));
        assert!(result.is_err());
    }

    #[test]
    fn empty_payload_errors() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();
        assert!(client.process(1, &[]).is_err());
    }

    #[test]
    fn unknown_command_skipped() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();

        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, 0);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();

        // Unknown command ID 0xFFFF with 4 bytes body
        let cmd = build_gfx_command(0xFFFF, &[0x00; 4]);
        let msgs = client.process(1, &wrap_uncompressed(&cmd)).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn create_delete_surface() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();

        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, 0);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();

        // CreateSurface: surfaceId=1, width=800, height=600, pixelFormat=XRGB
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes()); // surfaceId
        body.extend_from_slice(&800u16.to_le_bytes()); // width
        body.extend_from_slice(&600u16.to_le_bytes()); // height
        body.push(PIXEL_FORMAT_XRGB_8888); // pixelFormat
        let cmd = build_gfx_command(RDPGFX_CMDID_CREATESURFACE, &body);

        // DeleteSurface: surfaceId=1
        let del_body = 1u16.to_le_bytes();
        let del_cmd = build_gfx_command(RDPGFX_CMDID_DELETESURFACE, &del_body);

        let mut commands = Vec::new();
        commands.extend_from_slice(&cmd);
        commands.extend_from_slice(&del_cmd);
        let msgs = client.process(1, &wrap_uncompressed(&commands)).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn solid_fill_zero_rects() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();
        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, 0);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();

        // SolidFill with 0 rects
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes()); // surfaceId
        body.extend_from_slice(&[0xFF, 0x00, 0x00, 0xFF]); // fillPixel (B,G,R,XA)
        body.extend_from_slice(&0u16.to_le_bytes()); // fillRectCount = 0
        let cmd = build_gfx_command(RDPGFX_CMDID_SOLIDFILL, &body);
        let msgs = client.process(1, &wrap_uncompressed(&cmd)).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn reset_graphics_340_bytes() {
        let mut client = GfxClient::default_v10();
        client.start(1).unwrap();
        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, 0);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();

        // Build ResetGraphics: body = 332 bytes (340 - 8 header)
        let mut body = vec![0u8; 332];
        // width = 1920
        body[0..4].copy_from_slice(&1920u32.to_le_bytes());
        // height = 1080
        body[4..8].copy_from_slice(&1080u32.to_le_bytes());
        // monitorCount = 0
        body[8..12].copy_from_slice(&0u32.to_le_bytes());
        // rest is padding zeros

        let cmd = build_gfx_command(RDPGFX_CMDID_RESETGRAPHICS, &body);
        let msgs = client.process(1, &wrap_uncompressed(&cmd)).unwrap();
        assert!(msgs.is_empty());
    }
}
