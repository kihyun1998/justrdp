#![forbid(unsafe_code)]

//! RDP-layer PDU definitions (MS-RDPBCGR sections 2.2.7+).

pub mod capabilities;
pub mod client_info;
pub mod finalization;
pub mod headers;
pub mod licensing;
