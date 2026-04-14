//! Wire constants from MS-RDPEDC v8.0.
//!
//! Values come directly from the spec; the source section is noted
//! next to each constant.

// The `process_order` forward-compat skip reads a u16 body_size and
// adds it to COMMON_HEADER_SIZE = 4. On any target where `usize` is at
// least 2 bytes wide the sum (max 65539) cannot overflow. All supported
// Rust targets have 32-bit or 64-bit `usize`, so this is a belt-and-
// braces guard for any hypothetical exotic target.
const _: () = assert!(
    core::mem::size_of::<usize>() >= 4,
    "justrdp-rdpedc requires a target with usize >= 32 bits"
);

// ── Desktop Composition Capability Set (MS-RDPBCGR §2.2.7.2.8) ───────

/// `CompDeskSupportLevel` value meaning composition services are not
/// supported. Mirrors MS-RDPBCGR §2.2.7.2.8; provided here so callers
/// of `justrdp-rdpedc` can set the capability on the main connection
/// without reaching into `justrdp-pdu`.
pub const COMPDESK_NOT_SUPPORTED: u16 = 0x0000;

/// `CompDeskSupportLevel` value meaning composition services are
/// supported (MS-RDPBCGR §2.2.7.2.8). A client MUST advertise this
/// value for the server to emit any MS-RDPEDC orders.
pub const COMPDESK_SUPPORTED: u16 = 0x0001;

// ── Alternate Secondary Order header byte (MS-RDPEGDI §2.2.2.2.1.3.1.1) ──

/// `orderType` value that tags all MS-RDPEDC orders (MS-RDPEDC §2.2).
pub const TS_ALTSEC_COMPDESK_FIRST: u8 = 0x0C;

/// `controlFlags` value for an Alternate Secondary Order
/// (`TS_STANDARD = 0`, `TS_SECONDARY = 1`, so the 2-bit field is `0b10`).
pub const TS_ALTSEC_CONTROL_FLAGS: u8 = 0x02;

/// The full first byte of every MS-RDPEDC order on the wire.
///
/// Layout of the byte: `(orderType << 2) | controlFlags`. With
/// `orderType = 0x0C` and `controlFlags = 0x02`, the constant value is
/// `(0x0C << 2) | 0x02 = 0x32`.
pub const ALT_SEC_HEADER_BYTE: u8 = (TS_ALTSEC_COMPDESK_FIRST << 2) | TS_ALTSEC_CONTROL_FLAGS;

// ── Per-PDU operation codes (MS-RDPEDC §2.2) ─────────────────────────

pub mod operation {
    //! Operation-code byte that follows [`super::ALT_SEC_HEADER_BYTE`].

    /// `TS_COMPDESK_TOGGLE` (§2.2.1.1).
    pub const COMPDESKTOGGLE: u8 = 0x01;
    /// `TS_COMPDESK_LSURFACE` (§2.2.2.1).
    pub const LSURFACE_CREATE_DESTROY: u8 = 0x02;
    /// `TS_COMPDESK_SURFOBJ` (§2.2.2.2).
    pub const SURFOBJ_CREATE_DESTROY: u8 = 0x03;
    /// `TS_COMPDESK_REDIRSURF_ASSOC_LSURFACE` (§2.2.2.3).
    pub const REDIRSURF_ASSOC_DEASSOC_LSURFACE: u8 = 0x04;
    /// `TS_COMPDESK_LSURFACE_COMPREF_PENDING` (§2.2.2.4).
    pub const LSURFACE_COMPREF_PENDING: u8 = 0x05;
    /// `TS_COMPDESK_SWITCH_SURFOBJ` (§2.2.3.1).
    pub const SURFOBJSWITCH: u8 = 0x06;
    /// `TS_COMPDESK_FLUSH_COMPOSEONCE` (§2.2.3.2).
    pub const FLUSHCOMPOSEONCE: u8 = 0x07;
}

// The eventType values from MS-RDPEDC §2.2.1.1 are encoded directly
// as variants of [`crate::pdu::EventType`]; a parallel `const` module
// would be dead code since the typed enum is the canonical API.

// ── TS_COMPDESK_LSURFACE.flags bit values (§2.2.2.1) ─────────────────

pub mod lsurface_flags {
    //! Bitfield values for `TS_COMPDESK_LSURFACE.flags`.

    /// Logical surface is a compose-once surface.
    pub const TS_COMPDESK_HLSURF_COMPOSEONCE: u8 = 0x01;
    /// Logical surface is a redirection surface.
    pub const TS_COMPDESK_HLSURF_REDIRECTION: u8 = 0x04;
    /// Mask of all defined bits; undefined bits SHOULD be zero.
    pub const DEFINED_MASK: u8 = TS_COMPDESK_HLSURF_COMPOSEONCE | TS_COMPDESK_HLSURF_REDIRECTION;
}

// ── TS_COMPDESK_SURFOBJ.cacheId bit-field (§2.2.2.2) ─────────────────

/// Bit 31 of `cacheId`: `0` = create, `1` = destroy.
pub const CACHE_ID_DESTROY_BIT: u32 = 0x8000_0000;
/// Mask for the 31 identifier bits of `cacheId`.
pub const CACHE_ID_ID_MASK: u32 = 0x7FFF_FFFF;
