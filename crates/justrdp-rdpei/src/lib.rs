#![no_std]
#![forbid(unsafe_code)]

//! Touch Input Virtual Channel Extension -- MS-RDPEI
//!
//! Implements the Touch Input DVC (`Microsoft::Windows::RDS::Input`) for
//! forwarding multi-touch events from a client to a remote session.
//!
//! Step 2 delivers the wire-format PDUs (`pdu` module). The DVC processor
//! (`client` module) is added in Step 3.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
mod client;

#[cfg(feature = "alloc")]
pub use client::{RdpeiClientConfig, RdpeiDvcClient};

#[cfg(feature = "alloc")]
pub use pdu::{
    ContactFlags, ContactRect, CsReadyFlags, CsReadyPdu, DismissHoveringContactPdu,
    FieldsPresent, RdpeiHeader, ResumeInputPdu, ScReadyFlags, ScReadyPdu, SuspendInputPdu,
    TouchContact, TouchEventPdu, TouchFrame, EVENTID_CS_READY,
    EVENTID_DISMISS_HOVERING_TOUCH_CONTACT, EVENTID_RESUME_INPUT, EVENTID_SC_READY,
    EVENTID_SUSPEND_INPUT, EVENTID_TOUCH, RDPINPUT_PROTOCOL_V100, RDPINPUT_PROTOCOL_V101,
    RDPINPUT_PROTOCOL_V200, RDPINPUT_PROTOCOL_V300,
};
