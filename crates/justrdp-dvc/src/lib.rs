#![no_std]
#![forbid(unsafe_code)]

//! Dynamic Virtual Channel (DVC) framework -- MS-RDPEDYC
//!
//! Provides the [`DvcProcessor`] trait for implementing dynamic virtual channel
//! handlers, and [`DrdynvcClient`] which implements [`SvcProcessor`](justrdp_svc::SvcProcessor)
//! to manage the `drdynvc` static channel transport.
//!
//! # Usage
//!
//! ```ignore
//! // Register DVC processors with the DRDYNVC client.
//! let mut drdynvc = DrdynvcClient::new();
//! drdynvc.register(Box::new(MyGraphicsChannel::new()));
//!
//! // Register as a static virtual channel.
//! let mut channels = StaticChannelSet::new();
//! channels.insert(Box::new(drdynvc)).unwrap();
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;
#[cfg(feature = "alloc")]
mod reassembly;
#[cfg(feature = "alloc")]
mod drdynvc;

#[cfg(feature = "alloc")]
pub use drdynvc::DrdynvcClient;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use justrdp_core::AsAny;

// ── DVC error type ──

/// DVC framework error.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub enum DvcError {
    /// PDU decode error.
    Decode(justrdp_core::DecodeError),
    /// PDU encode error.
    Encode(justrdp_core::EncodeError),
    /// Protocol violation.
    Protocol(String),
}

#[cfg(feature = "alloc")]
impl From<justrdp_core::DecodeError> for DvcError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Decode(e)
    }
}

#[cfg(feature = "alloc")]
impl From<justrdp_core::EncodeError> for DvcError {
    fn from(e: justrdp_core::EncodeError) -> Self {
        Self::Encode(e)
    }
}

#[cfg(feature = "alloc")]
pub type DvcResult<T> = Result<T, DvcError>;

// ── DvcOutput ──

/// Outbound side of a DVC operation: bytes that must be sent over a
/// specific transport. Returned by route-aware DRDYNVC APIs
/// ([`DrdynvcClient::route_outbound`], [`DrdynvcClient::process_tunnel_data`])
/// so callers don't have to consult the routing table themselves.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DvcOutput {
    /// Send via the DRDYNVC SVC over the main TCP connection.
    Svc(justrdp_svc::SvcMessage),
    /// Wrap as `RDP_TUNNEL_DATA` on the named multitransport tunnel
    /// (`TUNNELTYPE_UDPFECR` / `TUNNELTYPE_UDPFECL`) and send via its
    /// UDP/DTLS transport.
    Tunnel { tunnel_type: u32, payload: Vec<u8> },
}

// ── DvcMessage ──

/// A message to be sent on a dynamic virtual channel.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DvcMessage {
    /// The payload data.
    pub data: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl DvcMessage {
    /// Create a new DVC message with the given payload.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

// ── DvcProcessor trait ──

/// A dynamic virtual channel processor.
///
/// Implement this trait to handle data on a specific DVC.
/// Register instances with [`DrdynvcClient`] before connection.
#[cfg(feature = "alloc")]
pub trait DvcProcessor: AsAny + Send {
    /// The channel name (used to match against server's CreateRequest).
    fn channel_name(&self) -> &str;

    /// Called when the server creates this channel.
    ///
    /// Returns initial messages to send to the server.
    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>>;

    /// Process a complete reassembled message from the server.
    ///
    /// Returns response messages to send back.
    fn process(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>>;

    /// Called when the channel is closed.
    fn close(&mut self, channel_id: u32);
}
