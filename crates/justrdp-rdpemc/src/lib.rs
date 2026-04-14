#![no_std]
#![forbid(unsafe_code)]

//! Multiparty Virtual Channel Extension -- MS-RDPEMC.
//!
//! Server-to-client and client-to-server orders that drive multi-party
//! ("shadow session") RDP over a **static** virtual channel named
//! `"encomsp"` (MS-RDPBCGR §3.1.5.2). Despite the "virtual channel
//! extension" name, MS-RDPEMC does **not** ride on DRDYNVC.
//!
//! Every MS-RDPEMC order starts with a 4-byte common header (ORDER_HDR,
//! MS-RDPEMC §2.2.1):
//!
//! ```text
//!   2B  Type    (u16 LE, 0x0001..=0x000D)
//!   2B  Length  (u16 LE, total PDU size INCLUDING the 4-byte header)
//! ```
//!
//! Then follows one of 13 message bodies (see [`pdu`]):
//!
//! | Type   | Name                                | Dir  | Wire size       | Spec §    |
//! |-------:|-------------------------------------|------|-----------------|-----------|
//! | 0x0001 | `OD_FILTER_STATE_UPDATED`           | SM→P | 5               | §2.2.3.1  |
//! | 0x0002 | `OD_APP_REMOVED`                    | SM→P | 8               | §2.2.3.3  |
//! | 0x0003 | `OD_APP_CREATED`                    | SM→P | 12 + 2·cchStr   | §2.2.3.2  |
//! | 0x0004 | `OD_WND_REMOVED`                    | SM→P | 8               | §2.2.3.5  |
//! | 0x0005 | `OD_WND_CREATED`                    | SM→P | 16 + 2·cchStr   | §2.2.3.4  |
//! | 0x0006 | `OD_WND_SHOW`                       | P→SM | 8               | §2.2.3.6  |
//! | 0x0007 | `OD_PARTICIPANT_REMOVED`            | SM→P | 16              | §2.2.4.2  |
//! | 0x0008 | `OD_PARTICIPANT_CREATED`            | SM→P | 16 + 2·cchStr   | §2.2.4.1  |
//! | 0x0009 | `OD_PARTICIPANT_CTRL_CHANGE`        | P→SM | 10              | §2.2.4.3  |
//! | 0x000A | `OD_GRAPHICS_STREAM_PAUSED`         | SM→P | 4               | §2.2.5.1  |
//! | 0x000B | `OD_GRAPHICS_STREAM_RESUMED`        | SM→P | 4               | §2.2.5.2  |
//! | 0x000C | `OD_WND_REGION_UPDATE`              | SM→P | 20              | §2.2.3.7  |
//! | 0x000D | `OD_PARTICIPANT_CTRL_CHANGE_RESPONSE` | SM→P | 14            | §2.2.4.4  |
//!
//! SM = Sharing Manager (host/server), P = Participant (client/viewer).
//!
//! Multiple MS-RDPEMC messages may be concatenated back-to-back in a
//! single SVC payload; use [`pdu::decode_all`] to drain a buffer.
//!
//! This crate (Step 9.13a) implements the PDU layer only. The `EncomspClient`
//! `SvcProcessor` and multi-table FSM arrive in Step 9.13b.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod client;
pub mod constants;
pub mod pdu;

#[cfg(all(test, feature = "alloc"))]
mod client_tests;
#[cfg(test)]
mod tests;

#[cfg(feature = "alloc")]
pub use client::{
    AppEntry, EncomspCallback, EncomspClient, EncomspError, NullCallback, ParticipantEntry,
    WindowEntry, MAX_APPLICATIONS, MAX_PARTICIPANTS, MAX_WINDOWS,
};

pub use constants::{
    flags, odtype, participant_disconnect_reason, ENCOMSP_CHANNEL_NAME, MAX_UNICODE_STRING_CCH,
    ORDER_HDR_SIZE,
};
pub use pdu::{
    decode_all, EncomspPdu, OdAppCreated, OdAppRemoved, OdFilterStateUpdated,
    OdGraphicsStreamPaused, OdGraphicsStreamResumed, OdParticipantCreated,
    OdParticipantCtrlChange, OdParticipantCtrlChangeResponse, OdParticipantRemoved, OdWndCreated,
    OdWndRegionUpdate, OdWndRemoved, OdWndShow, OrderHeader, UnicodeString,
};
