#![no_std]
#![forbid(unsafe_code)]

//! Graphics Pipeline Extension Virtual Channel -- MS-RDPEGFX
//!
//! Implements the RDPEGFX protocol for hardware-accelerated graphics
//! redirection over RDP using the `Microsoft::Windows::RDS::Graphics`
//! dynamic virtual channel.
//!
//! # Usage
//!
//! ```ignore
//! use justrdp_egfx::GfxClient;
//! use justrdp_dvc::DrdynvcClient;
//!
//! let mut drdynvc = DrdynvcClient::new();
//! drdynvc.register(Box::new(GfxClient::new()));
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
mod client;

#[cfg(feature = "alloc")]
mod server;

#[cfg(feature = "alloc")]
pub use client::{GfxClient, GfxHandler};

#[cfg(feature = "alloc")]
pub use server::{GfxServer, ServerState};

#[cfg(feature = "alloc")]
pub use pdu::{
    // Command IDs
    RDPGFX_CMDID_CACHETOSURFACE, RDPGFX_CMDID_CACHEIMPORTOFFER, RDPGFX_CMDID_CACHEIMPORTREPLY,
    RDPGFX_CMDID_CAPSADVERTISE, RDPGFX_CMDID_CAPSCONFIRM, RDPGFX_CMDID_CREATESURFACE,
    RDPGFX_CMDID_DELETEENCODINGCONTEXT, RDPGFX_CMDID_DELETESURFACE, RDPGFX_CMDID_ENDFRAME,
    RDPGFX_CMDID_EVICTCACHEENTRY, RDPGFX_CMDID_FRAMEACKNOWLEDGE,
    RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT, RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW,
    RDPGFX_CMDID_MAPSURFACETOOUTPUT, RDPGFX_CMDID_MAPSURFACETOWINDOW,
    RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE, RDPGFX_CMDID_RESETGRAPHICS, RDPGFX_CMDID_SOLIDFILL,
    RDPGFX_CMDID_STARTFRAME, RDPGFX_CMDID_SURFACETOCACHE, RDPGFX_CMDID_SURFACETOSURFACE,
    RDPGFX_CMDID_WIRETOSURFACE_1, RDPGFX_CMDID_WIRETOSURFACE_2,
    // Capability versions
    RDPGFX_CAPVERSION_8, RDPGFX_CAPVERSION_81, RDPGFX_CAPVERSION_10, RDPGFX_CAPVERSION_101,
    RDPGFX_CAPVERSION_102, RDPGFX_CAPVERSION_103, RDPGFX_CAPVERSION_104, RDPGFX_CAPVERSION_105,
    RDPGFX_CAPVERSION_106, RDPGFX_CAPVERSION_107,
    // Capability flags
    RDPGFX_CAPS_FLAG_THINCLIENT, RDPGFX_CAPS_FLAG_SMALL_CACHE, RDPGFX_CAPS_FLAG_AVC420_ENABLED,
    RDPGFX_CAPS_FLAG_AVC_DISABLED, RDPGFX_CAPS_FLAG_AVC_THINCLIENT,
    RDPGFX_CAPS_FLAG_SCALEDMAP_DISABLE,
    // Codec IDs
    RDPGFX_CODECID_UNCOMPRESSED, RDPGFX_CODECID_CAVIDEO, RDPGFX_CODECID_CLEARCODEC,
    RDPGFX_CODECID_CAPROGRESSIVE, RDPGFX_CODECID_PLANAR, RDPGFX_CODECID_AVC420,
    RDPGFX_CODECID_ALPHA, RDPGFX_CODECID_AVC444, RDPGFX_CODECID_AVC444V2,
    // Pixel formats
    PIXEL_FORMAT_XRGB_8888, PIXEL_FORMAT_ARGB_8888,
    // Frame ack sentinel
    QUEUE_DEPTH_UNAVAILABLE, SUSPEND_FRAME_ACKNOWLEDGEMENT,
    // Primitive types
    GfxRect16, GfxPoint16, GfxColor32, GfxPixelFormat,
    // Header
    RdpgfxHeader,
    // PDU types
    GfxCapSet, CapsAdvertisePdu, CapsConfirmPdu,
    CreateSurfacePdu, DeleteSurfacePdu, ResetGraphicsPdu, GfxMonitorDef,
    MapSurfaceToOutputPdu, MapSurfaceToWindowPdu,
    MapSurfaceToScaledOutputPdu, MapSurfaceToScaledWindowPdu,
    WireToSurface1Pdu, WireToSurface2Pdu, DeleteEncodingContextPdu,
    SolidFillPdu, SurfaceToSurfacePdu,
    SurfaceToCachePdu, CacheToSurfacePdu, EvictCacheEntryPdu,
    CacheImportOfferPdu, CacheImportReplyPdu, CacheEntryMetadata,
    StartFramePdu, EndFramePdu, FrameAcknowledgePdu, QoeFrameAcknowledgePdu,
};
