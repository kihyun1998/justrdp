#![forbid(unsafe_code)]

//! RDP-layer PDU definitions (MS-RDPBCGR sections 2.2.7+).

pub mod capabilities;
pub mod client_info;
pub mod drawing_orders;
pub mod fast_path;
pub mod finalization;
pub mod headers;
pub mod licensing;
#[cfg(feature = "alloc")]
pub mod rdstls;
#[cfg(feature = "alloc")]
pub mod redirection;
#[cfg(feature = "alloc")]
pub mod server_certificate;
#[cfg(feature = "alloc")]
pub mod standard_security;
pub mod svc;
