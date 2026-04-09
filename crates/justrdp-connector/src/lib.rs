#![no_std]
#![forbid(unsafe_code)]
#![doc = "RDP client connection state machine for JustRDP."]
#![doc = ""]
#![doc = "This crate implements a no-I/O finite state machine that drives the"]
#![doc = "full RDP client connection sequence (MS-RDPBCGR 1.3.1.1). The caller"]
#![doc = "is responsible for network I/O -- this crate only encodes/decodes PDUs"]
#![doc = "and manages the connection state."]

#[cfg(feature = "alloc")]
extern crate alloc;

mod aad;
mod config;
mod connector;
pub mod credssp;
mod encode_helpers;
mod error;
mod result;
mod sequence;
mod state;

pub use config::{
    AadConfig, AuthMode, BitmapCodecConfig, ColorDepth, CompressionConfig, Config, ConfigBuilder,
    Credentials, DesktopSize, KeyboardType, MonitorConfig, StaticChannelSet,
};
pub use connector::ClientConnector;
pub use credssp::gss_wrap::{gss_unwrap, gss_wrap};
pub use credssp::kerberos::{
    frame_kdc_message, unframe_kdc_message, KerberosRandom, KerberosSequence, KerberosState,
};
pub use credssp::{CredentialType, CredsspRandom, CredsspSequence, CredsspState};
pub use error::{ConnectorError, ConnectorErrorKind, ConnectorResult};
pub use justrdp_pdu::rdp::finalization::MonitorLayoutEntry;
pub use result::{ConnectionResult, Written};
pub use sequence::Sequence;
pub use state::ClientConnectorState;
