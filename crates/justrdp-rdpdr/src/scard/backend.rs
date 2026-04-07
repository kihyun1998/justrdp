#![forbid(unsafe_code)]

//! Smart card redirection backend trait -- MS-RDPESC
//!
//! This module defines the [`ScardBackend`] trait that applications implement
//! to handle Smart Card API calls redirected from the RDP server. Each trait
//! method corresponds to one or more `SCARD_IOCTL_*` codes defined in
//! [MS-RDPESC] 2.2.2.
//!
//! The opaque `context` and `handle` byte slices are client-generated
//! identifiers (up to 16 bytes each) that map to smart card resource manager
//! contexts and card handles, respectively.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ── Result type ──────────────────────────────────────────────────────────────

/// Result type for SCard operations.
///
/// The error variant carries an `SCARD_E_*` or `SCARD_W_*` return code
/// as defined in [MS-RDPESC] 2.2.4 (Return Values).
pub type ScardResult<T> = Result<T, u32>;

// ── Response types ───────────────────────────────────────────────────────────

/// Response from `SCardConnect` ([MS-RDPESC] 2.2.2.14).
#[derive(Debug)]
pub struct ConnectResponse {
    /// Opaque card handle bytes (max 16).
    pub handle: Vec<u8>,
    /// Negotiated protocol (`SCARD_PROTOCOL_T0`, `SCARD_PROTOCOL_T1`, etc.)
    /// as defined in [MS-RDPESC] 2.2.5.
    pub active_protocol: u32,
}

/// Response from `SCardTransmit` ([MS-RDPESC] 2.2.2.19).
#[derive(Debug)]
pub struct TransmitResponse {
    /// Receive PCI (protocol control information), if requested.
    pub recv_pci: Option<SCardIoPci>,
    /// Response APDU data returned by the card.
    pub recv_buffer: Vec<u8>,
}

/// SCard I/O request protocol control information.
///
/// Corresponds to the `SCARD_IO_REQUEST` structure ([MS-RDPESC] 2.2.1.8).
#[derive(Debug, Clone)]
pub struct SCardIoPci {
    /// Protocol identifier (`SCARD_PROTOCOL_T0` = 1, `SCARD_PROTOCOL_T1` = 2).
    pub protocol: u32,
    /// Extra protocol-specific bytes appended after the header.
    pub extra_bytes: Vec<u8>,
}

/// Response from `SCardStatus` ([MS-RDPESC] 2.2.2.18).
#[derive(Debug)]
pub struct StatusResponse {
    /// Multi-string of reader names (null-separated, double-null terminated).
    pub reader_names: Vec<u8>,
    /// Card state flags ([MS-RDPESC] 2.2.5).
    pub state: u32,
    /// Active protocol.
    pub protocol: u32,
    /// ATR (Answer To Reset) bytes (max 32).
    pub atr: Vec<u8>,
}

/// Reader state input for `SCardGetStatusChange` ([MS-RDPESC] 2.2.2.11).
#[derive(Debug, Clone)]
pub struct ReaderState {
    /// Reader name.
    pub reader_name: String,
    /// Current state known to the caller (combination of `SCARD_STATE_*` flags).
    pub current_state: u32,
    /// Event state (filled on return).
    pub event_state: u32,
    /// ATR of the card (max 36 bytes).
    pub atr: Vec<u8>,
}

/// Reader state returned from `SCardGetStatusChange` ([MS-RDPESC] 2.2.2.11).
#[derive(Debug, Clone)]
pub struct ReaderStateReturn {
    /// Current state after the call.
    pub current_state: u32,
    /// Event state indicating what changed (`SCARD_STATE_*` flags).
    pub event_state: u32,
    /// ATR of the card (max 36 bytes).
    pub atr: Vec<u8>,
}

// ── ScardBackend trait ───────────────────────────────────────────────────────

/// Smart card backend trait for MS-RDPESC redirection.
///
/// Implement this to handle SCard API calls from the RDP server.
/// Each method corresponds to one or more `SCARD_IOCTL_*` codes
/// defined in [MS-RDPESC] 2.2.2.
///
/// The opaque `context` and `handle` byte slices are client-generated
/// opaque identifiers (max 16 bytes each).
pub trait ScardBackend: Send {
    /// `SCardEstablishContext` -- create a resource manager context.
    ///
    /// [MS-RDPESC] 2.2.2.1, IOCTL code `SCARD_IOCTL_ESTABLISHCONTEXT`.
    ///
    /// Returns the opaque context bytes on success.
    fn establish_context(&mut self, scope: u32) -> ScardResult<Vec<u8>>;

    /// `SCardReleaseContext` -- release a resource manager context.
    ///
    /// [MS-RDPESC] 2.2.2.2, IOCTL code `SCARD_IOCTL_RELEASECONTEXT`.
    fn release_context(&mut self, context: &[u8]) -> ScardResult<()>;

    /// `SCardIsValidContext` -- check if a context handle is still valid.
    ///
    /// [MS-RDPESC] 2.2.2.3, IOCTL code `SCARD_IOCTL_ISVALIDCONTEXT`.
    fn is_valid_context(&mut self, context: &[u8]) -> ScardResult<()>;

    /// `SCardListReaders` -- list available smart card readers.
    ///
    /// [MS-RDPESC] 2.2.2.4, IOCTL code `SCARD_IOCTL_LISTREADERSA` /
    /// `SCARD_IOCTL_LISTREADERSW`.
    ///
    /// Returns a multi-string (null-separated, double-null terminated).
    fn list_readers(
        &mut self,
        context: &[u8],
        groups: Option<&[u8]>,
    ) -> ScardResult<Vec<u8>>;

    /// `SCardConnect` -- connect to a card in a named reader.
    ///
    /// [MS-RDPESC] 2.2.2.14, IOCTL code `SCARD_IOCTL_CONNECTA` /
    /// `SCARD_IOCTL_CONNECTW`.
    fn connect(
        &mut self,
        context: &[u8],
        reader: &str,
        share_mode: u32,
        preferred_protocols: u32,
    ) -> ScardResult<ConnectResponse>;

    /// `SCardReconnect` -- re-establish a connection to a card.
    ///
    /// [MS-RDPESC] 2.2.2.15, IOCTL code `SCARD_IOCTL_RECONNECT`.
    ///
    /// Returns the negotiated active protocol on success.
    fn reconnect(
        &mut self,
        context: &[u8],
        handle: &[u8],
        share_mode: u32,
        preferred_protocols: u32,
        initialization: u32,
    ) -> ScardResult<u32>;

    /// `SCardDisconnect` -- disconnect from a card.
    ///
    /// [MS-RDPESC] 2.2.2.16, IOCTL code `SCARD_IOCTL_DISCONNECT`.
    fn disconnect(&mut self, context: &[u8], handle: &[u8], disposition: u32) -> ScardResult<()>;

    /// `SCardBeginTransaction` -- begin an exclusive transaction on a card.
    ///
    /// [MS-RDPESC] 2.2.2.17, IOCTL code `SCARD_IOCTL_BEGINTRANSACTION`.
    fn begin_transaction(&mut self, context: &[u8], handle: &[u8]) -> ScardResult<()>;

    /// `SCardEndTransaction` -- end an exclusive transaction.
    ///
    /// [MS-RDPESC] 2.2.2.18, IOCTL code `SCARD_IOCTL_ENDTRANSACTION`.
    fn end_transaction(
        &mut self,
        context: &[u8],
        handle: &[u8],
        disposition: u32,
    ) -> ScardResult<()>;

    /// `SCardTransmit` -- send an APDU to the card and receive a response.
    ///
    /// [MS-RDPESC] 2.2.2.19, IOCTL code `SCARD_IOCTL_TRANSMIT`.
    fn transmit(
        &mut self,
        context: &[u8],
        handle: &[u8],
        send_pci: &SCardIoPci,
        send_buffer: &[u8],
        recv_pci_requested: bool,
        max_recv_len: u32,
    ) -> ScardResult<TransmitResponse>;

    /// `SCardStatus` -- get the current status of a card/reader.
    ///
    /// [MS-RDPESC] 2.2.2.18, IOCTL code `SCARD_IOCTL_STATUSA` /
    /// `SCARD_IOCTL_STATUSW`.
    fn status(
        &mut self,
        context: &[u8],
        handle: &[u8],
        reader_names_requested: bool,
        max_reader_len: u32,
        max_atr_len: u32,
    ) -> ScardResult<StatusResponse>;

    /// `SCardGetStatusChange` -- wait for status changes on one or more readers.
    ///
    /// [MS-RDPESC] 2.2.2.11, IOCTL code `SCARD_IOCTL_GETSTATUSCHANGEA` /
    /// `SCARD_IOCTL_GETSTATUSCHANGEW`.
    fn get_status_change(
        &mut self,
        context: &[u8],
        timeout_ms: u32,
        reader_states: &[ReaderState],
    ) -> ScardResult<Vec<ReaderStateReturn>>;

    /// `SCardCancel` -- cancel a pending `GetStatusChange` call.
    ///
    /// [MS-RDPESC] 2.2.2.10, IOCTL code `SCARD_IOCTL_CANCEL`.
    fn cancel(&mut self, context: &[u8]) -> ScardResult<()>;

    /// `SCardGetAttrib` -- get a reader/card attribute value.
    ///
    /// [MS-RDPESC] 2.2.2.20, IOCTL code `SCARD_IOCTL_GETATTRIB`.
    fn get_attrib(
        &mut self,
        context: &[u8],
        handle: &[u8],
        attr_id: u32,
        max_len: u32,
    ) -> ScardResult<Vec<u8>>;

    /// `SCardSetAttrib` -- set a reader/card attribute value.
    ///
    /// [MS-RDPESC] 2.2.2.21, IOCTL code `SCARD_IOCTL_SETATTRIB`.
    fn set_attrib(
        &mut self,
        context: &[u8],
        handle: &[u8],
        attr_id: u32,
        attr_data: &[u8],
    ) -> ScardResult<()>;

    /// `SCardControl` -- send a control code directly to the reader.
    ///
    /// [MS-RDPESC] 2.2.2.22, IOCTL code `SCARD_IOCTL_CONTROL`.
    fn control(
        &mut self,
        context: &[u8],
        handle: &[u8],
        control_code: u32,
        input: &[u8],
        max_output_len: u32,
    ) -> ScardResult<Vec<u8>>;

    /// `SCardAccessStartedEvent` -- check if the smart card service is started.
    ///
    /// [MS-RDPESC] 2.2.2.13, IOCTL code `SCARD_IOCTL_ACCESSSTARTEDEVENT`.
    ///
    /// Default implementation returns success (the common case).
    fn access_started_event(&mut self) -> ScardResult<()> {
        Ok(())
    }
}
