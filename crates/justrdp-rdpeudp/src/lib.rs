#![no_std]
#![forbid(unsafe_code)]

//! Remote Desktop Protocol: UDP Transport Extension — **MS-RDPEUDP**.
//!
//! This crate owns the on-the-wire PDU layer for the RDP-UDP
//! (datagram-oriented) transport used by Multitransport. It is
//! transport-agnostic and does not own sockets, timers, retransmit
//! buffers, congestion control, FEC, or DTLS — those live higher up
//! and will arrive in follow-up commits (see roadmap §10.2).
//!
//! Scope of this module tree:
//!
//! - **`v1`** — MS-RDPEUDP §2.2 PDU structures used during the SYN /
//!   SYN+ACK handshake and as the outer framing for Protocol Version
//!   1 and 2 data transfer.
//! - **`v2`** (follow-up) — MS-RDPEUDP2 §2.2 structures used once
//!   `RDPUDP_PROTOCOL_VERSION_3` (`0x0101`) is negotiated in a
//!   `RDPUDP_SYNDATAEX_PAYLOAD`.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod v1;

#[cfg(feature = "alloc")]
pub mod v2;

#[cfg(feature = "alloc")]
pub use v1::*;
