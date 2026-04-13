#![no_std]
#![forbid(unsafe_code)]

//! Geometry Tracking Virtual Channel Extension -- MS-RDPEGT
//!
//! Implements the Geometry Tracking DVC (`"Microsoft::Windows::RDS::Geometry::v08.01"`)
//! used by the server to push video window geometry mappings to the client.
//! This channel is a dependency for MS-RDPEVOR (Video Optimized Remoting),
//! which references mappings by their `MappingId` to position decoded H.264
//! frames inside the remote desktop.
//!
//! - [`pdu`] -- wire-format structs (`MappedGeometryPacket`, `IRect`, ...)
//! - [`client`] -- `RdpegtClient` DVC processor and `GeometryLookup` trait

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
pub mod client;

#[cfg(feature = "alloc")]
pub use client::{GeometryEntry, GeometryLookup, RdpegtClient};

#[cfg(feature = "alloc")]
pub use pdu::{
    GeometryClear, GeometryUpdate, IRect, MappedGeometryPacket, CHANNEL_NAME,
    GEOMETRY_CLEAR, GEOMETRY_TYPE_REGION, GEOMETRY_UPDATE, MAPPED_GEOMETRY_VERSION,
    MAX_ACTIVE_MAPPINGS, MAX_CBGEOMETRYBUFFER, MAX_CBGEOMETRYDATA, MAX_RECTS_PER_GEOMETRY,
    RDH_RECTANGLES, RGNDATAHEADER_SIZE,
};
