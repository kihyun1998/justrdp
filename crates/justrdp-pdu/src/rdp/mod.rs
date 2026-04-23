#![forbid(unsafe_code)]

//! RDP-layer PDU definitions (MS-RDPBCGR sections 2.2.7+).

pub mod bitmap;
pub mod capabilities;
pub mod client_info;
pub mod drawing_orders;
pub mod error_info;
pub mod fast_path;
pub mod finalization;
pub mod headers;
pub mod licensing;
pub mod pointer;
#[cfg(feature = "alloc")]
pub mod rdstls;
#[cfg(feature = "alloc")]
pub mod redirection;
#[cfg(feature = "alloc")]
pub mod server_certificate;
#[cfg(feature = "alloc")]
pub mod standard_security;
pub mod svc;
