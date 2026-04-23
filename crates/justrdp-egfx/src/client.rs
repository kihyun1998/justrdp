#![forbid(unsafe_code)]

//! RDPEGFX DVC client -- MS-RDPEGFX 3.2

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_bulk::zgfx::ZgfxDecompressor;
use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::pdu::{
    CacheImportReplyPdu, CacheToSurfacePdu, CapsAdvertisePdu,
    CreateSurfacePdu, DeleteEncodingContextPdu, DeleteSurfacePdu, EndFramePdu,
    EvictCacheEntryPdu, FrameAcknowledgePdu, GfxCapSet, GfxColor32, GfxMonitorDef,
    GfxPixelFormat, GfxPoint16, GfxRect16, MapSurfaceToOutputPdu,
    MapSurfaceToScaledOutputPdu, MapSurfaceToScaledWindowPdu, MapSurfaceToWindowPdu,
    ResetGraphicsPdu, RdpgfxHeader, SolidFillPdu,
    StartFramePdu, SurfaceToCachePdu, SurfaceToSurfacePdu, WireToSurface1Pdu,
    WireToSurface2Pdu, RDPGFX_CAPVERSION_10,
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

// ── GfxHandler trait ──

/// Handler for decoded RDPEGFX graphics commands.
///
/// Implement this trait to receive graphics pipeline events from the server.
/// The handler is called for each decoded command after ZGFX decompression
/// and PDU parsing.
///
/// Codec dispatch: `on_wire_to_surface_1` and `on_wire_to_surface_2` receive
/// the `codec_id` and raw `bitmap_data` — the implementor is responsible for
/// dispatching to the appropriate codec decoder (Uncompressed, ClearCodec,
/// Planar, RFX, H.264/AVC, Alpha, Progressive RFX).
pub trait GfxHandler: AsAny + Send {
    /// A new surface was created.
    fn on_create_surface(
        &mut self,
        surface_id: u16,
        width: u16,
        height: u16,
        pixel_format: GfxPixelFormat,
    );

    /// A surface was deleted.
    fn on_delete_surface(&mut self, surface_id: u16);

    /// Surface mapped to output position.
    fn on_map_surface_to_output(
        &mut self,
        surface_id: u16,
        output_origin_x: u32,
        output_origin_y: u32,
    );

    /// Surface mapped to RAIL window.
    fn on_map_surface_to_window(
        &mut self,
        surface_id: u16,
        window_id: u64,
        mapped_width: u32,
        mapped_height: u32,
    ) {
        let _ = (surface_id, window_id, mapped_width, mapped_height);
    }

    /// Surface mapped to scaled output.
    fn on_map_surface_to_scaled_output(
        &mut self,
        surface_id: u16,
        output_origin_x: u32,
        output_origin_y: u32,
        target_width: u32,
        target_height: u32,
    ) {
        let _ = (surface_id, output_origin_x, output_origin_y, target_width, target_height);
    }

    /// Surface mapped to scaled RAIL window.
    fn on_map_surface_to_scaled_window(
        &mut self,
        surface_id: u16,
        window_id: u64,
        mapped_width: u32,
        mapped_height: u32,
        target_width: u32,
        target_height: u32,
    ) {
        let _ = (surface_id, window_id, mapped_width, mapped_height, target_width, target_height);
    }

    /// Graphics state reset with new desktop dimensions.
    fn on_reset_graphics(
        &mut self,
        width: u32,
        height: u32,
        monitors: &[GfxMonitorDef],
    );

    /// Codec-based bitmap data (WireToSurface1).
    ///
    /// `codec_id` identifies the codec; `bitmap_data` is the raw codec payload.
    /// The implementor should dispatch to the appropriate decoder:
    /// - `0x0000` — Uncompressed
    /// - `0x0003` — RemoteFX (MS-RDPRFX)
    /// - `0x0008` — ClearCodec
    /// - `0x000A` — Planar
    /// - `0x000B` — AVC420
    /// - `0x000C` — Alpha
    /// - `0x000E` — AVC444
    /// - `0x000F` — AVC444v2
    fn on_wire_to_surface_1(
        &mut self,
        surface_id: u16,
        codec_id: u16,
        pixel_format: GfxPixelFormat,
        dest_rect: GfxRect16,
        bitmap_data: &[u8],
    );

    /// Context-based bitmap data (WireToSurface2, Progressive RFX only).
    ///
    /// `codec_context_id` identifies the persistent encoding context.
    fn on_wire_to_surface_2(
        &mut self,
        surface_id: u16,
        codec_id: u16,
        codec_context_id: u32,
        pixel_format: GfxPixelFormat,
        bitmap_data: &[u8],
    );

    /// An encoding context was deleted.
    fn on_delete_encoding_context(&mut self, surface_id: u16, codec_context_id: u32) {
        let _ = (surface_id, codec_context_id);
    }

    /// Solid color fill.
    fn on_solid_fill(
        &mut self,
        surface_id: u16,
        fill_color: GfxColor32,
        rects: &[GfxRect16],
    ) {
        let _ = (surface_id, fill_color, rects);
    }

    /// Surface-to-surface blit.
    fn on_surface_to_surface(
        &mut self,
        src_surface_id: u16,
        dst_surface_id: u16,
        src_rect: GfxRect16,
        dest_points: &[GfxPoint16],
    ) {
        let _ = (src_surface_id, dst_surface_id, src_rect, dest_points);
    }

    /// Cache a surface region.
    fn on_surface_to_cache(
        &mut self,
        surface_id: u16,
        cache_key: u64,
        cache_slot: u16,
        src_rect: GfxRect16,
    ) {
        let _ = (surface_id, cache_key, cache_slot, src_rect);
    }

    /// Copy cached bitmap to surface.
    fn on_cache_to_surface(
        &mut self,
        cache_slot: u16,
        surface_id: u16,
        dest_points: &[GfxPoint16],
    ) {
        let _ = (cache_slot, surface_id, dest_points);
    }

    /// Evict a cache entry.
    fn on_evict_cache_entry(&mut self, cache_slot: u16) {
        let _ = cache_slot;
    }

    /// Server accepted cache import entries.
    fn on_cache_import_reply(&mut self, cache_slots: &[u16]) {
        let _ = cache_slots;
    }

    /// Start of a frame.
    fn on_start_frame(&mut self, frame_id: u32, timestamp: u32);

    /// End of a frame. Return `Some(queue_depth)` to send a FrameAcknowledge,
    /// or `None` to suspend acknowledgement.
    fn on_end_frame(&mut self, frame_id: u32) -> Option<u32>;
}

// ── Client state machine ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    WaitingForCapsConfirm,
    Active,
    Closed,
}

/// RDPEGFX Graphics Pipeline DVC client.
///
/// Implements `DvcProcessor` for the `Microsoft::Windows::RDS::Graphics`
/// dynamic virtual channel.
///
/// Requires a [`GfxHandler`] to receive decoded graphics commands.
pub struct GfxClient {
    state: ClientState,
    cap_sets: Vec<GfxCapSet>,
    negotiated_version: Option<u32>,
    total_frames_decoded: u32,
    ack_suspended: bool,
    decompressor: ZgfxDecompressor,
    handler: Box<dyn GfxHandler>,
}

impl GfxClient {
    /// Create a new GFX client with capability sets and a handler.
    pub fn new(cap_sets: Vec<GfxCapSet>, handler: Box<dyn GfxHandler>) -> Self {
        Self {
            state: ClientState::WaitingForCapsConfirm,
            cap_sets,
            negotiated_version: None,
            total_frames_decoded: 0,
            ack_suspended: false,
            decompressor: ZgfxDecompressor::new(),
            handler,
        }
    }

    /// Create a GFX client with default VERSION10 capability (AVC disabled).
    pub fn with_handler(handler: Box<dyn GfxHandler>) -> Self {
        Self::new(
            vec![GfxCapSet {
                version: RDPGFX_CAPVERSION_10,
                flags: crate::pdu::RDPGFX_CAPS_FLAG_AVC_DISABLED,
            }],
            handler,
        )
    }

    /// Returns the negotiated version, if capability exchange is complete.
    pub fn negotiated_version(&self) -> Option<u32> {
        self.negotiated_version
    }

    /// Crate-internal accessor used by `GfxServer ↔ GfxClient` loopback
    /// tests in `crate::server` to downcast the boxed handler without
    /// adding a public API surface for application callers.
    #[cfg(test)]
    pub(crate) fn handler_ref(&self) -> &dyn GfxHandler {
        &*self.handler
    }

    /// Process the raw DVC payload (RDP_SEGMENTED_DATA).
    fn process_segmented_data(
        &mut self,
        payload: &[u8],
    ) -> DvcResult<Vec<DvcMessage>> {
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
                    let pdu = ResetGraphicsPdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                    self.handler.on_reset_graphics(pdu.width, pdu.height, &pdu.monitors);
                }
                RDPGFX_CMDID_CREATESURFACE => {
                    let pdu = CreateSurfacePdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                    self.handler.on_create_surface(
                        pdu.surface_id, pdu.width, pdu.height, pdu.pixel_format,
                    );
                }
                RDPGFX_CMDID_DELETESURFACE => {
                    let pdu = DeleteSurfacePdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                    self.handler.on_delete_surface(pdu.surface_id);
                }
                RDPGFX_CMDID_MAPSURFACETOOUTPUT => {
                    let pdu = MapSurfaceToOutputPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_map_surface_to_output(
                        pdu.surface_id, pdu.output_origin_x, pdu.output_origin_y,
                    );
                }
                RDPGFX_CMDID_MAPSURFACETOWINDOW => {
                    let pdu = MapSurfaceToWindowPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_map_surface_to_window(
                        pdu.surface_id, pdu.window_id, pdu.mapped_width, pdu.mapped_height,
                    );
                }
                RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT => {
                    let pdu = MapSurfaceToScaledOutputPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_map_surface_to_scaled_output(
                        pdu.surface_id, pdu.output_origin_x, pdu.output_origin_y,
                        pdu.target_width, pdu.target_height,
                    );
                }
                RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW => {
                    let pdu = MapSurfaceToScaledWindowPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_map_surface_to_scaled_window(
                        pdu.surface_id, pdu.window_id, pdu.mapped_width, pdu.mapped_height,
                        pdu.target_width, pdu.target_height,
                    );
                }
                RDPGFX_CMDID_STARTFRAME => {
                    let pdu = StartFramePdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                    self.handler.on_start_frame(pdu.frame_id, pdu.timestamp);
                }
                RDPGFX_CMDID_ENDFRAME => {
                    let pdu = EndFramePdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                    self.total_frames_decoded = self.total_frames_decoded.saturating_add(1);

                    match self.handler.on_end_frame(pdu.frame_id) {
                        Some(queue_depth) => {
                            self.ack_suspended = false;
                            let ack = FrameAcknowledgePdu {
                                queue_depth,
                                frame_id: pdu.frame_id,
                                total_frames_decoded: self.total_frames_decoded,
                            };
                            responses.push(encode_pdu(&ack)?);
                        }
                        None => {
                            self.ack_suspended = true;
                        }
                    }
                }
                RDPGFX_CMDID_WIRETOSURFACE_1 => {
                    let pdu = WireToSurface1Pdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_wire_to_surface_1(
                        pdu.surface_id, pdu.codec_id, pdu.pixel_format,
                        pdu.dest_rect, &pdu.bitmap_data,
                    );
                }
                RDPGFX_CMDID_WIRETOSURFACE_2 => {
                    let pdu = WireToSurface2Pdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_wire_to_surface_2(
                        pdu.surface_id, pdu.codec_id, pdu.codec_context_id,
                        pdu.pixel_format, &pdu.bitmap_data,
                    );
                }
                RDPGFX_CMDID_DELETEENCODINGCONTEXT => {
                    let pdu = DeleteEncodingContextPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_delete_encoding_context(pdu.surface_id, pdu.codec_context_id);
                }
                RDPGFX_CMDID_SOLIDFILL => {
                    let pdu = SolidFillPdu::decode(&mut body_src).map_err(DvcError::Decode)?;
                    self.handler.on_solid_fill(
                        pdu.surface_id, pdu.fill_pixel, &pdu.fill_rects,
                    );
                }
                RDPGFX_CMDID_SURFACETOSURFACE => {
                    let pdu = SurfaceToSurfacePdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_surface_to_surface(
                        pdu.surface_id_src, pdu.surface_id_dest,
                        pdu.rect_src, &pdu.dest_pts,
                    );
                }
                RDPGFX_CMDID_SURFACETOCACHE => {
                    let pdu = SurfaceToCachePdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_surface_to_cache(
                        pdu.surface_id, pdu.cache_key, pdu.cache_slot, pdu.rect_src,
                    );
                }
                RDPGFX_CMDID_CACHETOSURFACE => {
                    let pdu = CacheToSurfacePdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_cache_to_surface(
                        pdu.cache_slot, pdu.surface_id, &pdu.dest_pts,
                    );
                }
                RDPGFX_CMDID_EVICTCACHEENTRY => {
                    let pdu = EvictCacheEntryPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_evict_cache_entry(pdu.cache_slot);
                }
                RDPGFX_CMDID_CACHEIMPORTREPLY => {
                    let pdu = CacheImportReplyPdu::decode(&mut body_src)
                        .map_err(DvcError::Decode)?;
                    self.handler.on_cache_import_reply(&pdu.cache_slots);
                }
                _ => {
                    // Unknown command: skip (spec defines no error PDU)
                }
            }
        }

        Ok(responses)
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
        self.decompressor.reset();
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

    /// Minimal GfxHandler for testing.
    struct TestHandler {
        surfaces_created: Vec<u16>,
        surfaces_deleted: Vec<u16>,
        frames_started: Vec<u32>,
        frames_ended: Vec<u32>,
        bitmaps_received: u32,
        resets: u32,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                surfaces_created: Vec::new(),
                surfaces_deleted: Vec::new(),
                frames_started: Vec::new(),
                frames_ended: Vec::new(),
                bitmaps_received: 0,
                resets: 0,
            }
        }
    }

    impl AsAny for TestHandler {
        fn as_any(&self) -> &dyn core::any::Any { self }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any { self }
    }

    impl GfxHandler for TestHandler {
        fn on_create_surface(&mut self, surface_id: u16, _w: u16, _h: u16, _pf: GfxPixelFormat) {
            self.surfaces_created.push(surface_id);
        }
        fn on_delete_surface(&mut self, surface_id: u16) {
            self.surfaces_deleted.push(surface_id);
        }
        fn on_map_surface_to_output(&mut self, _sid: u16, _x: u32, _y: u32) {}
        fn on_reset_graphics(&mut self, _w: u32, _h: u32, _m: &[GfxMonitorDef]) {
            self.resets += 1;
        }
        fn on_wire_to_surface_1(&mut self, _sid: u16, _cid: u16, _pf: GfxPixelFormat, _r: GfxRect16, _d: &[u8]) {
            self.bitmaps_received += 1;
        }
        fn on_wire_to_surface_2(&mut self, _sid: u16, _cid: u16, _ctx: u32, _pf: GfxPixelFormat, _d: &[u8]) {
            self.bitmaps_received += 1;
        }
        fn on_start_frame(&mut self, frame_id: u32, _ts: u32) {
            self.frames_started.push(frame_id);
        }
        fn on_end_frame(&mut self, frame_id: u32) -> Option<u32> {
            self.frames_ended.push(frame_id);
            Some(QUEUE_DEPTH_UNAVAILABLE)
        }
    }

    fn make_client() -> GfxClient {
        GfxClient::with_handler(Box::new(TestHandler::new()))
    }

    /// Build a minimal SINGLE RDP_SEGMENTED_DATA wrapping uncompressed bytes.
    fn wrap_uncompressed(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0xE0u8];
        out.push(0x04);
        out.extend_from_slice(data);
        out
    }

    fn build_gfx_command(cmd_id: u16, body: &[u8]) -> Vec<u8> {
        let pdu_length = (RdpgfxHeader::WIRE_SIZE + body.len()) as u32;
        let mut buf = Vec::with_capacity(pdu_length as usize);
        buf.extend_from_slice(&cmd_id.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&pdu_length.to_le_bytes());
        buf.extend_from_slice(body);
        buf
    }

    fn build_caps_confirm(version: u32, flags: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version.to_le_bytes());
        if version == RDPGFX_CAPVERSION_101 {
            body.extend_from_slice(&16u32.to_le_bytes());
            body.extend_from_slice(&flags.to_le_bytes());
            body.extend_from_slice(&[0u8; 12]);
        } else {
            body.extend_from_slice(&4u32.to_le_bytes());
            body.extend_from_slice(&flags.to_le_bytes());
        }
        build_gfx_command(RDPGFX_CMDID_CAPSCONFIRM, &body)
    }

    fn build_start_frame(frame_id: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&frame_id.to_le_bytes());
        build_gfx_command(RDPGFX_CMDID_STARTFRAME, &body)
    }

    fn build_end_frame(frame_id: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&frame_id.to_le_bytes());
        build_gfx_command(RDPGFX_CMDID_ENDFRAME, &body)
    }

    fn activate_client(client: &mut GfxClient) {
        client.start(1).unwrap();
        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, RDPGFX_CAPS_FLAG_AVC_DISABLED);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();
    }

    #[test]
    fn channel_name() {
        let client = make_client();
        assert_eq!(client.channel_name(), "Microsoft::Windows::RDS::Graphics");
    }

    #[test]
    fn start_sends_caps_advertise() {
        let mut client = make_client();
        let msgs = client.start(1).unwrap();
        assert_eq!(msgs.len(), 1);
        let cmd_id = u16::from_le_bytes([msgs[0].data[0], msgs[0].data[1]]);
        assert_eq!(cmd_id, RDPGFX_CMDID_CAPSADVERTISE);
    }

    #[test]
    fn caps_confirm_transitions_to_active() {
        let mut client = make_client();
        client.start(1).unwrap();
        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, RDPGFX_CAPS_FLAG_AVC_DISABLED);
        let msgs = client.process(1, &wrap_uncompressed(&confirm)).unwrap();
        assert!(msgs.is_empty());
        assert_eq!(client.negotiated_version(), Some(RDPGFX_CAPVERSION_10));
        assert_eq!(client.state, ClientState::Active);
    }

    #[test]
    fn end_frame_sends_ack() {
        let mut client = make_client();
        activate_client(&mut client);

        let mut commands = Vec::new();
        commands.extend_from_slice(&build_start_frame(1));
        commands.extend_from_slice(&build_end_frame(1));
        let msgs = client.process(1, &wrap_uncompressed(&commands)).unwrap();

        assert_eq!(msgs.len(), 1);
        let ack_data = &msgs[0].data;
        let cmd_id = u16::from_le_bytes([ack_data[0], ack_data[1]]);
        assert_eq!(cmd_id, RDPGFX_CMDID_FRAMEACKNOWLEDGE);
        let frame_id = u32::from_le_bytes([ack_data[12], ack_data[13], ack_data[14], ack_data[15]]);
        assert_eq!(frame_id, 1);
    }

    #[test]
    fn handler_receives_create_delete_surface() {
        let mut client = make_client();
        activate_client(&mut client);

        let mut body = Vec::new();
        body.extend_from_slice(&42u16.to_le_bytes());
        body.extend_from_slice(&800u16.to_le_bytes());
        body.extend_from_slice(&600u16.to_le_bytes());
        body.push(PIXEL_FORMAT_XRGB_8888);
        let create = build_gfx_command(RDPGFX_CMDID_CREATESURFACE, &body);

        let del = build_gfx_command(RDPGFX_CMDID_DELETESURFACE, &42u16.to_le_bytes());

        let mut commands = Vec::new();
        commands.extend_from_slice(&create);
        commands.extend_from_slice(&del);
        client.process(1, &wrap_uncompressed(&commands)).unwrap();

        let handler = client.handler.as_any().downcast_ref::<TestHandler>().unwrap();
        assert_eq!(handler.surfaces_created, &[42]);
        assert_eq!(handler.surfaces_deleted, &[42]);
    }

    #[test]
    fn handler_receives_wire_to_surface_1() {
        let mut client = make_client();
        activate_client(&mut client);

        // WireToSurface1: surfaceId=1, codecId=PLANAR(0x000A), pixelFormat=XRGB,
        // destRect=(0,0,64,64), bitmapData=16 bytes
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes()); // surfaceId
        body.extend_from_slice(&0x000Au16.to_le_bytes()); // codecId (Planar)
        body.push(PIXEL_FORMAT_XRGB_8888);
        body.extend_from_slice(&0u16.to_le_bytes()); // left
        body.extend_from_slice(&0u16.to_le_bytes()); // top
        body.extend_from_slice(&64u16.to_le_bytes()); // right
        body.extend_from_slice(&64u16.to_le_bytes()); // bottom
        body.extend_from_slice(&16u32.to_le_bytes()); // bitmapDataLength
        body.extend_from_slice(&[0xAA; 16]); // bitmapData

        let cmd = build_gfx_command(RDPGFX_CMDID_WIRETOSURFACE_1, &body);
        client.process(1, &wrap_uncompressed(&cmd)).unwrap();

        let handler = client.handler.as_any().downcast_ref::<TestHandler>().unwrap();
        assert_eq!(handler.bitmaps_received, 1);
    }

    #[test]
    fn handler_receives_reset_graphics() {
        let mut client = make_client();
        activate_client(&mut client);

        let mut body = vec![0u8; 332];
        body[0..4].copy_from_slice(&1920u32.to_le_bytes());
        body[4..8].copy_from_slice(&1080u32.to_le_bytes());
        body[8..12].copy_from_slice(&0u32.to_le_bytes());

        let cmd = build_gfx_command(RDPGFX_CMDID_RESETGRAPHICS, &body);
        client.process(1, &wrap_uncompressed(&cmd)).unwrap();

        let handler = client.handler.as_any().downcast_ref::<TestHandler>().unwrap();
        assert_eq!(handler.resets, 1);
    }

    #[test]
    fn handler_receives_frames() {
        let mut client = make_client();
        activate_client(&mut client);

        for i in 1..=3 {
            let mut commands = Vec::new();
            commands.extend_from_slice(&build_start_frame(i));
            commands.extend_from_slice(&build_end_frame(i));
            client.process(1, &wrap_uncompressed(&commands)).unwrap();
        }

        let handler = client.handler.as_any().downcast_ref::<TestHandler>().unwrap();
        assert_eq!(handler.frames_started, &[1, 2, 3]);
        assert_eq!(handler.frames_ended, &[1, 2, 3]);
        assert_eq!(client.total_frames_decoded, 3);
    }

    #[test]
    fn command_before_caps_confirm_errors() {
        let mut client = make_client();
        client.start(1).unwrap();
        let cmd = build_start_frame(1);
        assert!(client.process(1, &wrap_uncompressed(&cmd)).is_err());
    }

    #[test]
    fn duplicate_caps_confirm_errors() {
        let mut client = make_client();
        activate_client(&mut client);
        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, 0);
        assert!(client.process(1, &wrap_uncompressed(&confirm)).is_err());
    }

    #[test]
    fn close_resets_state() {
        let mut client = make_client();
        activate_client(&mut client);
        client.close(1);
        assert_eq!(client.state, ClientState::Closed);
        assert!(client.negotiated_version().is_none());
    }

    #[test]
    fn process_after_close_errors() {
        let mut client = make_client();
        activate_client(&mut client);
        client.close(1);
        assert!(client.process(1, &[0xE0, 0x04]).is_err());
    }

    #[test]
    fn empty_payload_errors() {
        let mut client = make_client();
        client.start(1).unwrap();
        assert!(client.process(1, &[]).is_err());
    }

    #[test]
    fn unknown_command_skipped() {
        let mut client = make_client();
        activate_client(&mut client);
        let cmd = build_gfx_command(0xFFFF, &[0x00; 4]);
        let msgs = client.process(1, &wrap_uncompressed(&cmd)).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn solid_fill_dispatched() {
        let mut client = make_client();
        activate_client(&mut client);

        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&[0xFF, 0x00, 0x00, 0xFF]);
        body.extend_from_slice(&0u16.to_le_bytes());
        let cmd = build_gfx_command(RDPGFX_CMDID_SOLIDFILL, &body);
        client.process(1, &wrap_uncompressed(&cmd)).unwrap();
    }

    #[test]
    fn suspend_ack_via_handler() {
        struct SuspendHandler;
        impl AsAny for SuspendHandler {
            fn as_any(&self) -> &dyn core::any::Any { self }
            fn as_any_mut(&mut self) -> &mut dyn core::any::Any { self }
        }
        impl GfxHandler for SuspendHandler {
            fn on_create_surface(&mut self, _: u16, _: u16, _: u16, _: GfxPixelFormat) {}
            fn on_delete_surface(&mut self, _: u16) {}
            fn on_map_surface_to_output(&mut self, _: u16, _: u32, _: u32) {}
            fn on_reset_graphics(&mut self, _: u32, _: u32, _: &[GfxMonitorDef]) {}
            fn on_wire_to_surface_1(&mut self, _: u16, _: u16, _: GfxPixelFormat, _: GfxRect16, _: &[u8]) {}
            fn on_wire_to_surface_2(&mut self, _: u16, _: u16, _: u32, _: GfxPixelFormat, _: &[u8]) {}
            fn on_start_frame(&mut self, _: u32, _: u32) {}
            fn on_end_frame(&mut self, _: u32) -> Option<u32> { None }
        }

        let mut client = GfxClient::with_handler(Box::new(SuspendHandler));
        client.start(1).unwrap();
        let confirm = build_caps_confirm(RDPGFX_CAPVERSION_10, 0);
        client.process(1, &wrap_uncompressed(&confirm)).unwrap();

        let mut commands = Vec::new();
        commands.extend_from_slice(&build_start_frame(1));
        commands.extend_from_slice(&build_end_frame(1));
        let msgs = client.process(1, &wrap_uncompressed(&commands)).unwrap();
        assert!(msgs.is_empty()); // suspended
        assert!(client.ack_suspended);
    }
}
