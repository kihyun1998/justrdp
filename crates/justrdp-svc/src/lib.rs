#![no_std]
#![forbid(unsafe_code)]

//! Static Virtual Channel (SVC) framework -- MS-RDPBCGR 2.2.6
//!
//! Provides the [`SvcProcessor`] trait for implementing virtual channel handlers,
//! [`StaticChannelSet`] for managing registered channels, and automatic
//! chunking/dechunking of channel data.
//!
//! # Usage
//!
//! ```ignore
//! // Register channels before connection.
//! let mut channels = StaticChannelSet::new();
//! channels.insert(Box::new(MyClipboardChannel::new()));
//!
//! // After connection, assign MCS channel IDs from ConnectionResult.
//! channels.assign_ids(&connection_result.channel_ids);
//!
//! // Process incoming channel data from ActiveStage::process().
//! if let ActiveStageOutput::ChannelData { channel_id, data } = output {
//!     let responses = channels.process_incoming(channel_id, &data)?;
//!     for msg in responses {
//!         let frames = channels.encode_message(channel_id, &msg, user_channel_id)?;
//!         for frame in frames { stream.write_all(&frame).await?; }
//!     }
//! }
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod audit;
#[cfg(feature = "alloc")]
mod channel_name;
#[cfg(feature = "alloc")]
mod channel_set;
#[cfg(feature = "alloc")]
mod dechunk;
#[cfg(feature = "alloc")]
pub mod chunk;

#[cfg(feature = "alloc")]
pub use channel_name::{ChannelName, CLIPRDR, DRDYNVC, ENCOMSP, RAIL, RDPDR, RDPSND};
#[cfg(feature = "alloc")]
pub use channel_set::StaticChannelSet;
#[cfg(feature = "alloc")]
pub use chunk::chunk_and_encode;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use core::fmt::Debug;

#[cfg(feature = "alloc")]
use justrdp_core::AsAny;

// ── SVC error type ──

/// SVC framework error.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub enum SvcError {
    /// PDU decode error.
    Decode(justrdp_core::DecodeError),
    /// PDU encode error.
    Encode(justrdp_core::EncodeError),
    /// Protocol violation.
    Protocol(String),
}

#[cfg(feature = "alloc")]
impl From<justrdp_core::DecodeError> for SvcError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Decode(e)
    }
}

#[cfg(feature = "alloc")]
impl From<justrdp_core::EncodeError> for SvcError {
    fn from(e: justrdp_core::EncodeError) -> Self {
        Self::Encode(e)
    }
}

#[cfg(feature = "alloc")]
pub type SvcResult<T> = Result<T, SvcError>;

// ── Compression condition ──

/// Controls when virtual channel data should be compressed.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionCondition {
    /// Compress only if RDP bulk compression is active.
    WhenRdpDataIsCompressed,
    /// Never compress virtual channel data.
    Never,
    /// Always compress virtual channel data.
    Always,
}

// ── SvcMessage ──

/// A message to be sent on a virtual channel.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcMessage {
    /// The payload data.
    pub data: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl SvcMessage {
    /// Create a new SVC message with the given payload.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

// ── SvcProcessor trait ──

/// A static virtual channel processor.
///
/// Implement this trait to handle data on a specific virtual channel.
/// Register instances with [`StaticChannelSet`] before connection.
#[cfg(feature = "alloc")]
pub trait SvcProcessor: AsAny + Debug + Send {
    /// The channel name (max 7 ASCII chars).
    fn channel_name(&self) -> ChannelName;

    /// Called once when the channel session starts.
    ///
    /// Returns initial messages to send to the server.
    fn start(&mut self) -> SvcResult<Vec<SvcMessage>>;

    /// Process a complete reassembled message from the server.
    ///
    /// Returns response messages to send back.
    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>>;

    /// Declare which capability bits this processor's handlers actually
    /// implement. PRD #35 Module A2: the [`audit`] harness compares the
    /// set of bits advertised on the wire against the union of every
    /// registered processor's `declared_caps`. An advertised bit with
    /// no declaration is a `feedback_no_partial_protocol_enable`
    /// violation. Default is empty — reactive processors that carry no
    /// capability semantics of their own opt out by doing nothing.
    fn declared_caps(&self) -> Vec<crate::audit::AdvertisedCap> {
        Vec::new()
    }

    /// Drain any host-side asynchronous messages this channel has queued.
    ///
    /// Called by the session loop on wake-ups that are not driven by an
    /// inbound server frame (e.g. an OS clipboard-change event reached
    /// the channel out of band). The default returns no messages, which
    /// fits any purely reactive channel.
    fn poll(&mut self) -> SvcResult<Vec<SvcMessage>> {
        Ok(Vec::new())
    }

    /// Controls when compression should be applied to outgoing data.
    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

/// Marker trait for client-side SVC processors.
#[cfg(feature = "alloc")]
pub trait SvcClientProcessor: SvcProcessor {}

/// Marker trait for server-side SVC processors.
#[cfg(feature = "alloc")]
pub trait SvcServerProcessor: SvcProcessor {}
