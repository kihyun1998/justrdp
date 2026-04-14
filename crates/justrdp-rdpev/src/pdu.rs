//! MS-RDPEV wire format modules.
//!
//! Each submodule owns one message family (header, capabilities,
//! presentation, format, stream, sample, control, etc.). Step 2A only
//! ships the header; the rest land in subsequent steps.

pub mod capabilities;
pub mod control;
pub mod format;
pub mod guid;
pub mod header;
pub mod presentation;
pub mod sample;
pub mod stream;
