#![forbid(unsafe_code)]

//! Clipboard channel routing on top of `justrdp-cliprdr`.
//!
//! [`ClipboardChannel`] hosts a [`CliprdrClient`] inside a
//! [`StaticChannelSet`] and exposes:
//! * `process_channel_data(channel_id, payload)` — routes raw bytes
//!   from a [`SessionEvent::Channel`] event into the CLIPRDR state
//!   machine and returns wire-ready response frames the embedder
//!   pipes back through their `WebTransport`.
//! * `set_local_format_data(format_id, bytes, name)` — pushes
//!   clipboard data to the server and returns the format-list
//!   announcement frames.
//! * `take_remote_format_data(format_id)` — drains the most recent
//!   server-pushed clipboard data for a given format id.
//!
//! Backend storage is a single `Arc<Mutex<ClipboardState>>` shared
//! between the channel and the bundled `SharedBackend` impl. UTF-16LE
//! ↔ `String` conversion for `CF_UNICODETEXT` is left to the embedder
//! (the JS / browser side does it natively via the Clipboard API).
//!
//! [`SessionEvent::Channel`]: crate::SessionEvent::Channel

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::sync::{Arc, Mutex};

use justrdp_cliprdr::pdu::LongFormatName;
use justrdp_cliprdr::{
    CliprdrBackend, CliprdrClient, ClipboardResult, FormatDataResponse, FormatListResponse,
};
use justrdp_connector::ConnectionResult;
use justrdp_svc::StaticChannelSet;

/// Embedder-visible clipboard state.
#[derive(Default)]
pub struct ClipboardState {
    /// Format data the embedder set locally — keyed by format id;
    /// served when the server requests one of these formats.
    local_format_data: BTreeMap<u32, Vec<u8>>,
    /// Format data delivered by the server. Keyed by format id; the
    /// embedder drains entries via `take_remote_format_data`.
    remote_format_data: BTreeMap<u32, Vec<u8>>,
    /// Last format list the server announced.
    last_remote_formats: Vec<LongFormatName>,
}

impl ClipboardState {
    pub fn local_format_data(&self) -> &BTreeMap<u32, Vec<u8>> {
        &self.local_format_data
    }

    pub fn remote_format_data(&self) -> &BTreeMap<u32, Vec<u8>> {
        &self.remote_format_data
    }

    pub fn last_remote_formats(&self) -> &[LongFormatName] {
        &self.last_remote_formats
    }
}

struct SharedBackend {
    state: Arc<Mutex<ClipboardState>>,
}

impl CliprdrBackend for SharedBackend {
    fn on_format_list(
        &mut self,
        formats: &[LongFormatName],
    ) -> ClipboardResult<FormatListResponse> {
        if let Ok(mut g) = self.state.lock() {
            g.last_remote_formats = formats.to_vec();
        }
        Ok(FormatListResponse::Ok)
    }

    fn on_format_data_request(&mut self, format_id: u32) -> ClipboardResult<FormatDataResponse> {
        let bytes_opt = self
            .state
            .lock()
            .ok()
            .and_then(|g| g.local_format_data.get(&format_id).cloned());
        match bytes_opt {
            Some(bytes) => Ok(FormatDataResponse::Ok(bytes)),
            None => Ok(FormatDataResponse::Fail),
        }
    }

    fn on_format_data_response(&mut self, data: &[u8], is_success: bool, format_id: Option<u32>) {
        if !is_success {
            return;
        }
        let Some(fid) = format_id else { return };
        if let Ok(mut g) = self.state.lock() {
            g.remote_format_data.insert(fid, data.to_vec());
        }
    }
}

/// Clipboard channel routing helper.
pub struct ClipboardChannel {
    channels: StaticChannelSet,
    user_channel_id: u16,
    cliprdr_channel_id: u16,
    state: Arc<Mutex<ClipboardState>>,
}

impl core::fmt::Debug for ClipboardChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClipboardChannel")
            .field("user_channel_id", &self.user_channel_id)
            .field("cliprdr_channel_id", &self.cliprdr_channel_id)
            .finish_non_exhaustive()
    }
}

/// Errors returned by [`ClipboardChannel`].
#[derive(Debug)]
pub enum ClipboardChannelError {
    /// The negotiated channel set didn't include `CLIPRDR`.
    ChannelNotNegotiated,
    /// The wrapped channel set rejected the operation.
    Svc(justrdp_svc::SvcError),
}

impl core::fmt::Display for ClipboardChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChannelNotNegotiated => f.write_str("CLIPRDR channel not negotiated by server"),
            Self::Svc(e) => write!(f, "svc: {e:?}"),
        }
    }
}

impl From<justrdp_svc::SvcError> for ClipboardChannelError {
    fn from(e: justrdp_svc::SvcError) -> Self {
        Self::Svc(e)
    }
}

impl ClipboardChannel {
    /// Construct from a [`ConnectionResult`] returned by the
    /// handshake driver. Looks up the `cliprdr` channel by name and
    /// instantiates the inner [`CliprdrClient`].
    pub fn from_connection(result: &ConnectionResult) -> Result<Self, ClipboardChannelError> {
        let state: Arc<Mutex<ClipboardState>> = Arc::new(Mutex::new(ClipboardState::default()));
        let backend: Box<dyn CliprdrBackend> = Box::new(SharedBackend {
            state: Arc::clone(&state),
        });
        Self::build(result, backend, state)
    }

    /// Construct with an embedder-owned [`CliprdrBackend`] in place of
    /// the bundled `SharedBackend`.
    ///
    /// Native embedders typically want clipboard formats routed
    /// directly to the host clipboard (e.g. `arboard`,
    /// `clipboard-win`, NSPasteboard) without going through the
    /// bundled `ClipboardState` cache. This constructor skips
    /// `SharedBackend` and hands the supplied backend straight to
    /// [`CliprdrClient`].
    ///
    /// `set_local_format_data` and `take_remote_format_data` still
    /// operate against the bundled `ClipboardState` (they're
    /// state-cache convenience APIs); embedders using a custom
    /// backend will typically not call them and instead drive
    /// clipboard sync from inside their backend.
    pub fn from_connection_with_backend<B>(
        result: &ConnectionResult,
        backend: B,
    ) -> Result<Self, ClipboardChannelError>
    where
        B: CliprdrBackend + 'static,
    {
        let state: Arc<Mutex<ClipboardState>> = Arc::new(Mutex::new(ClipboardState::default()));
        Self::build(result, Box::new(backend), state)
    }

    fn build(
        result: &ConnectionResult,
        backend: Box<dyn CliprdrBackend>,
        state: Arc<Mutex<ClipboardState>>,
    ) -> Result<Self, ClipboardChannelError> {
        let cliprdr_channel_id = result
            .channel_ids
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("cliprdr"))
            .map(|(_, id)| *id)
            .ok_or(ClipboardChannelError::ChannelNotNegotiated)?;

        let cliprdr = Box::new(CliprdrClient::new(backend));
        let mut channels = StaticChannelSet::new();
        channels.insert(cliprdr).map_err(ClipboardChannelError::Svc)?;
        channels.assign_ids(&[(String::from("cliprdr"), cliprdr_channel_id)]);

        Ok(Self {
            channels,
            user_channel_id: result.user_channel_id,
            cliprdr_channel_id,
            state,
        })
    }

    pub fn channel_id(&self) -> u16 {
        self.cliprdr_channel_id
    }

    /// Shared state — embedders read `remote_format_data` and write
    /// `local_format_data` (use `set_local_format_data` if you also
    /// want the format-list frames to send to the server).
    pub fn state(&self) -> Arc<Mutex<ClipboardState>> {
        Arc::clone(&self.state)
    }

    /// Process raw `ChannelData.data` bytes from a
    /// [`SessionEvent::Channel`] event. If `channel_id` doesn't match
    /// the negotiated CLIPRDR channel, returns an empty Vec so the
    /// embedder can blindly forward every Channel event without
    /// filtering. The returned wire frames are TPKT-framed and ready
    /// to send via `transport.send`.
    ///
    /// [`SessionEvent::Channel`]: crate::SessionEvent::Channel
    pub fn process_channel_data(
        &mut self,
        channel_id: u16,
        data: &[u8],
    ) -> Result<Vec<Vec<u8>>, ClipboardChannelError> {
        if channel_id != self.cliprdr_channel_id {
            return Ok(Vec::new());
        }
        Ok(self
            .channels
            .process_incoming(channel_id, data, self.user_channel_id)?)
    }

    /// Push clipboard bytes for `format_id` to the local cache and
    /// return the format-list announcement frames (caller `send()`s
    /// them). The server will follow up with a format-data-request
    /// when it wants the bytes; the request is processed by
    /// [`Self::process_channel_data`] which calls the bundled
    /// backend → reads from this cache → returns the response frames.
    ///
    /// Common format ids:
    /// * `1`  — `CF_TEXT` (ASCII, NUL-terminated).
    /// * `13` — `CF_UNICODETEXT` (UTF-16LE, NUL-terminated).
    /// * `2`  — `CF_BITMAP`.
    pub fn set_local_format_data(
        &mut self,
        format_id: u32,
        data: Vec<u8>,
        format_name: &str,
    ) -> Result<Vec<Vec<u8>>, ClipboardChannelError> {
        if let Ok(mut g) = self.state.lock() {
            g.local_format_data.insert(format_id, data);
        }
        let formats = alloc::vec![LongFormatName::new(format_id, format_name.to_string())];
        let processor = self
            .channels
            .get_by_channel_id_mut(self.cliprdr_channel_id)
            .ok_or(ClipboardChannelError::ChannelNotNegotiated)?;
        let cliprdr = processor
            .as_any_mut()
            .downcast_mut::<CliprdrClient>()
            .ok_or_else(|| {
                ClipboardChannelError::Svc(justrdp_svc::SvcError::Protocol(format!(
                    "expected CliprdrClient processor for channel id {}",
                    self.cliprdr_channel_id
                )))
            })?;
        let msg = cliprdr.build_format_list(&formats)?;
        // Encode as TPKT-framed wire chunks via the public helper.
        Ok(justrdp_svc::chunk_and_encode(
            self.user_channel_id,
            self.cliprdr_channel_id,
            &msg.data,
            0,
            false,
        )?)
    }

    /// Drain the most-recently-received remote clipboard data for the
    /// given format id, returning the bytes (and removing them from
    /// the cache). `None` when no entry is buffered.
    pub fn take_remote_format_data(&mut self, format_id: u32) -> Option<Vec<u8>> {
        self.state
            .lock()
            .ok()?
            .remote_format_data
            .remove(&format_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_pdu::x224::SecurityProtocol;

    fn make_result(cliprdr_id: u16) -> ConnectionResult {
        ConnectionResult {
            io_channel_id: 1003,
            user_channel_id: 1001,
            share_id: 0x0001_03ea,
            server_capabilities: Vec::new(),
            channel_ids: vec![(String::from("cliprdr"), cliprdr_id)],
            selected_protocol: SecurityProtocol::RDP,
            session_id: 0,
            server_monitor_layout: None,
            server_arc_cookie: None,
            server_redirection: None,
        }
    }

    #[test]
    fn from_connection_finds_cliprdr_channel_id() {
        let result = make_result(1004);
        let ch = ClipboardChannel::from_connection(&result).unwrap();
        assert_eq!(ch.channel_id(), 1004);
    }

    #[test]
    fn from_connection_errors_when_cliprdr_missing() {
        let mut result = make_result(0);
        result.channel_ids.clear();
        let err = ClipboardChannel::from_connection(&result).unwrap_err();
        assert!(matches!(err, ClipboardChannelError::ChannelNotNegotiated));
    }

    #[test]
    fn process_channel_data_ignores_unrelated_channel_ids() {
        let result = make_result(1004);
        let mut ch = ClipboardChannel::from_connection(&result).unwrap();
        let frames = ch.process_channel_data(2000, &[0u8; 16]).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn from_connection_with_backend_routes_through_custom_backend() {
        // Native embedders inject their own CliprdrBackend (arboard,
        // clipboard-win, NSPasteboard) instead of going through the
        // bundled `SharedBackend` cache. This verifies the
        // alternate constructor wires the channel without panicking
        // and exposes the same channel-id / state surface.
        struct StubBackend {
            calls: Arc<Mutex<u32>>,
        }
        impl CliprdrBackend for StubBackend {
            fn on_format_list(
                &mut self,
                _formats: &[LongFormatName],
            ) -> ClipboardResult<FormatListResponse> {
                *self.calls.lock().unwrap() += 1;
                Ok(FormatListResponse::Ok)
            }
            fn on_format_data_request(&mut self, _format_id: u32) -> ClipboardResult<FormatDataResponse> {
                Ok(FormatDataResponse::Fail)
            }
            fn on_format_data_response(
                &mut self,
                _data: &[u8],
                _is_success: bool,
                _format_id: Option<u32>,
            ) {
            }
        }

        let result = make_result(1004);
        let calls = Arc::new(Mutex::new(0u32));
        let backend = StubBackend {
            calls: Arc::clone(&calls),
        };
        let ch = ClipboardChannel::from_connection_with_backend(&result, backend).unwrap();
        assert_eq!(ch.channel_id(), 1004);
        // The bundled `ClipboardState` is still allocated (state cache
        // for `set_local_format_data` / `take_remote_format_data`),
        // but the embedder's backend owns the actual on_* callback
        // path. No callbacks have fired yet — `calls` stays zero
        // until a real cliprdr PDU arrives.
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[test]
    fn local_format_data_round_trips_through_state() {
        let result = make_result(1004);
        let mut ch = ClipboardChannel::from_connection(&result).unwrap();
        let frames = ch
            .set_local_format_data(13 /* CF_UNICODETEXT */, b"hello".to_vec(), "")
            .unwrap();
        // Format-list frames are non-empty (TPKT-framed wire bytes).
        assert!(!frames.is_empty());
        let state = ch.state();
        let g = state.lock().unwrap();
        assert_eq!(
            g.local_format_data.get(&13).map(|v| v.as_slice()),
            Some(b"hello".as_slice())
        );
    }
}
