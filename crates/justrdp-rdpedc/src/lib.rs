#![no_std]
#![forbid(unsafe_code)]

//! Desktop Composition Virtual Channel Extension -- MS-RDPEDC.
//!
//! Server-to-client orders that drive DWM desktop composition on a
//! Windows 7+ remote session. Unlike its sibling protocols (MS-RDPEV,
//! MS-RDPEVOR, ...), MS-RDPEDC does **not** open a Dynamic Virtual
//! Channel -- its 7 message types ride inside the normal RDP Update
//! PDU stream as GDI **Alternate Secondary Orders**, multiplexed with
//! regular drawing orders.
//!
//! Every MS-RDPEDC order starts with a 4-byte common prefix:
//!
//! ```text
//!   1B  header     = 0x32  (TS_ALTSEC_COMPDESK_FIRST = 0x0C, controlFlags = 0x2)
//!   1B  operation  = 0x01..=0x07
//!   2B  size  LE   = byte count of the body that follows the size field
//! ```
//!
//! Then comes one of seven bodies (see [`pdu`]):
//!
//! | Op | Name                         | Total size | Spec §     |
//! |---:|------------------------------|-----------:|------------|
//! | 01 | `TS_COMPDESK_TOGGLE`         |  5 bytes   | §2.2.1.1   |
//! | 02 | `TS_COMPDESK_LSURFACE`       | 38 bytes   | §2.2.2.1   |
//! | 03 | `TS_COMPDESK_SURFOBJ`        | 26 bytes   | §2.2.2.2   |
//! | 04 | `TS_COMPDESK_REDIRSURF_...`  | 21 bytes   | §2.2.2.3   |
//! | 05 | `TS_COMPDESK_..._COMPREF_..` | 12 bytes   | §2.2.2.4   |
//! | 06 | `TS_COMPDESK_SWITCH_SURFOBJ` |  8 bytes   | §2.2.3.1   |
//! | 07 | `TS_COMPDESK_FLUSH_COMPO...` | 16 bytes   | §2.2.3.2   |
//!
//! All PDU bodies are fixed size; there is no variable-length payload
//! in MS-RDPEDC. The client processor (added in Step 2) tracks a simple
//! composition-mode FSM plus two `BTreeMap`s for logical and
//! redirection surfaces.

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod client;
pub mod constants;
pub mod pdu;

pub use client::{
    process_batch, CompDeskCallback, CompositionMode, LogicalSurface, NullCallback, RdpedcClient,
    RdpedcError, RedirSurface, MAX_LOGICAL_SURFACES, MAX_REDIR_SURFACES,
};
pub use constants::{
    operation, ALT_SEC_HEADER_BYTE, COMPDESK_NOT_SUPPORTED, COMPDESK_SUPPORTED,
    TS_ALTSEC_COMPDESK_FIRST, TS_ALTSEC_CONTROL_FLAGS,
};
pub use pdu::{
    decode_any, CompDeskPdu, CompDeskToggle, EventType, FlushComposeOnce, LSurfaceCompRefPending,
    LSurfaceCreateDestroy, LSurfaceFlags, RedirSurfAssocLSurface, SurfObjCreateDestroy,
    SwitchSurfObj, COMMON_HEADER_SIZE,
};
