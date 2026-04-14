//! [`TsmfMediaSink`] -- the host trait that a TSMF client embedder
//! implements so the [`crate::processor::RdpevClient`] can drive a
//! local media pipeline without knowing anything about the underlying
//! decoder, audio device, or window system.
//!
//! ## Lifecycle
//!
//! The trait is called synchronously from `DvcProcessor::process` on
//! the DVC thread. Implementations must not panic and SHOULD avoid
//! blocking on the hot path ([`Self::on_sample`]); the spec requires
//! the client to emit a `PLAYBACK_ACK` for every received sample, so
//! the processor will issue the ack regardless of how the sink
//! handled the frame. Errors from the sink for sample delivery are
//! deliberately swallowed -- the protocol's 1:1 ack rule wins.
//!
//! ## Mandatory vs optional methods
//!
//! Eight methods are mandatory because TSMF cannot run a presentation
//! without them:
//!
//! - [`Self::exchange_capabilities`]
//! - [`Self::on_new_presentation`]
//! - [`Self::check_format_support`]
//! - [`Self::add_stream`]
//! - [`Self::set_topology`]
//! - [`Self::on_sample`]
//! - [`Self::remove_stream`]
//! - [`Self::shutdown_presentation`]
//!
//! All other methods (playback control, volume, geometry, allocator
//! hints) have empty default implementations so a minimal client can
//! ignore them. The processor will still parse and dispatch every
//! incoming PDU; only the host action is a no-op.

use alloc::vec::Vec;

use justrdp_core::AsAny;

use crate::constants::{E_FAIL, E_NOTIMPL, E_OUT_OF_MEMORY, S_OK};
use crate::pdu::capabilities::TsmmCapabilities;
use crate::pdu::format::TsAmMediaType;
use crate::pdu::geometry::{GeometryInfo, TsRect};
use crate::pdu::guid::Guid;
use crate::pdu::sample::TsMmDataSample;

// ── Error type ──────────────────────────────────────────────────────

/// Error type returned by [`TsmfMediaSink`] implementations.
///
/// Each variant maps to an HRESULT that the processor writes into the
/// matching response PDU. Use [`Self::to_hresult`] at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsmfError {
    /// Presentation or stream identifier not recognised.
    NotFound,
    /// Resource (presentation/stream) already exists.
    AlreadyExists,
    /// Operation is intentionally unsupported by this host.
    OperationNotSupported,
    /// Allocation failed.
    OutOfMemory,
    /// Generic catch-all for host-side bugs.
    UnexpectedError,
    /// Preserved raw HRESULT for forward compat.
    Other(u32),
}

impl TsmfError {
    /// Wire HRESULT representation (little-endian u32 on the wire).
    pub fn to_hresult(self) -> u32 {
        match self {
            Self::NotFound => E_FAIL,
            Self::AlreadyExists => E_FAIL,
            Self::OperationNotSupported => E_NOTIMPL,
            Self::OutOfMemory => E_OUT_OF_MEMORY,
            Self::UnexpectedError => E_FAIL,
            Self::Other(raw) => raw,
        }
    }
}

/// Convenience: maps `Result<T, TsmfError>` to an HRESULT word that
/// can be written directly into a response PDU.
pub fn result_to_hresult<T>(res: Result<T, TsmfError>) -> u32 {
    match res {
        Ok(_) => S_OK,
        Err(e) => e.to_hresult(),
    }
}

// ── CheckFormatResult ───────────────────────────────────────────────

/// Result of a [`TsmfMediaSink::check_format_support`] query.
///
/// Per spec §2.2.5.2.3, `platform_cookie` is only meaningful when
/// `supported == true`; the wire field is undefined otherwise. We
/// still write whatever the sink returned so a strict roundtrip
/// observer can tell the two paths apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CheckFormatResult {
    pub supported: bool,
    /// Valid only when `supported == true`; ignored on the wire when
    /// the format is unsupported.
    pub platform_cookie: u32,
}

impl CheckFormatResult {
    pub fn unsupported() -> Self {
        Self {
            supported: false,
            platform_cookie: 0,
        }
    }

    pub fn supported(platform_cookie: u32) -> Self {
        Self {
            supported: true,
            platform_cookie,
        }
    }
}

// ── Trait ───────────────────────────────────────────────────────────

/// Host-supplied media pipeline for one TSMF channel.
///
/// Implementations are owned by the [`crate::processor::RdpevClient`]
/// instance and called synchronously from the DVC thread. Methods
/// MUST NOT panic; long-running work belongs to the host's own
/// queues, not this trait.
pub trait TsmfMediaSink: AsAny + Send {
    // ── Mandatory ─────────────────────────────────────────────────

    /// Returns the client's capability advertisement after seeing the
    /// server's. Called once per `EXCHANGE_CAPABILITIES_REQ`.
    fn exchange_capabilities(
        &mut self,
        server_capabilities: &[TsmmCapabilities],
    ) -> Vec<TsmmCapabilities>;

    /// Server announces a new presentation. The host should allocate
    /// any per-presentation state (decoder context, output surface).
    /// Returning `Err` causes the processor to fail subsequent
    /// per-presentation messages with the matching HRESULT.
    fn on_new_presentation(
        &mut self,
        presentation_id: Guid,
        platform_cookie: u32,
    ) -> Result<(), TsmfError>;

    /// Server asks whether a media format can be played on the
    /// specified platform cookie. The host returns a
    /// [`CheckFormatResult`] verbatim; the processor wraps it in the
    /// matching `CHECK_FORMAT_SUPPORT_RSP`.
    fn check_format_support(
        &mut self,
        presentation_id: Guid,
        media_type: &TsAmMediaType,
        preferred_platform: u32,
        no_rollover: bool,
    ) -> CheckFormatResult;

    /// Installs a stream into a presentation. The host should open
    /// its decoder for this `(presentation_id, stream_id)` pair.
    fn add_stream(
        &mut self,
        presentation_id: Guid,
        stream_id: u32,
        media_type: &TsAmMediaType,
    ) -> Result<(), TsmfError>;

    /// Server has finalised the topology and is asking the client to
    /// declare itself ready. Returning `false` causes the processor
    /// to send `SetTopologyRsp { topology_ready: 0, result: E_FAIL }`.
    fn set_topology(&mut self, presentation_id: Guid) -> bool;

    /// One media frame has arrived. The processor will emit a
    /// `PLAYBACK_ACK` regardless of what the sink does with the
    /// sample, so this method is infallible by design -- if the host
    /// fails to decode, it must absorb the error itself. The 1:1 ack
    /// rule (spec §3.3.5.3.3) cannot be violated.
    fn on_sample(&mut self, presentation_id: Guid, stream_id: u32, sample: &TsMmDataSample);

    /// Server tears down a single stream. The host should free the
    /// decoder for `(presentation_id, stream_id)`.
    fn remove_stream(&mut self, presentation_id: Guid, stream_id: u32);

    /// Server tears down a whole presentation. Returning `Err` does
    /// NOT abort the teardown -- the processor still emits a
    /// `SHUTDOWN_PRESENTATION_RSP` with the host's HRESULT.
    fn shutdown_presentation(&mut self, presentation_id: Guid) -> Result<(), TsmfError>;

    // ── Optional (default no-op) ──────────────────────────────────

    fn on_flush(&mut self, _presentation_id: Guid, _stream_id: u32) {}

    fn on_end_of_stream(&mut self, _presentation_id: Guid, _stream_id: u32) {}

    fn on_playback_started(
        &mut self,
        _presentation_id: Guid,
        _playback_start_offset: u64,
        _is_seek: bool,
    ) {
    }

    fn on_playback_paused(&mut self, _presentation_id: Guid) {}
    fn on_playback_stopped(&mut self, _presentation_id: Guid) {}
    fn on_playback_restarted(&mut self, _presentation_id: Guid) {}
    fn on_playback_rate_changed(&mut self, _presentation_id: Guid, _new_rate: f32) {}

    fn on_stream_volume(&mut self, _presentation_id: Guid, _new_volume: u32, _muted: bool) {}
    fn on_channel_volume(
        &mut self,
        _presentation_id: Guid,
        _channel_volume: u32,
        _changed_channel: u32,
    ) {
    }

    fn set_video_window(
        &mut self,
        _presentation_id: Guid,
        _video_window_id: u64,
        _hwnd_parent: u64,
    ) {
    }

    fn update_geometry(
        &mut self,
        _presentation_id: Guid,
        _geometry: &GeometryInfo,
        _visible_rects: &[TsRect],
    ) {
    }

    fn set_source_video_rect(
        &mut self,
        _presentation_id: Guid,
        _left: f32,
        _top: f32,
        _right: f32,
        _bottom: f32,
    ) {
    }

    fn set_allocator(
        &mut self,
        _presentation_id: Guid,
        _stream_id: u32,
        _c_buffers: u32,
        _cb_buffer: u32,
        _cb_align: u32,
        _cb_prefix: u32,
    ) {
    }
}

// ── MockTsmfMediaSink ───────────────────────────────────────────────

/// Deterministic in-memory `TsmfMediaSink` used by processor tests
/// and by anyone embedding the crate who wants a placeholder.
///
/// All mandatory methods succeed by default; tests can pre-load
/// failure conditions via the builder methods. Optional methods are
/// counted so tests can assert on dispatch.
#[derive(Debug, Default)]
pub struct MockTsmfMediaSink {
    /// Capabilities the mock advertises in response to
    /// `exchange_capabilities`. Defaults to an empty list.
    client_capabilities: Vec<TsmmCapabilities>,
    /// If set, [`Self::check_format_support`] returns this verbatim
    /// regardless of the format. Default = supported with cookie 1.
    format_response: Option<CheckFormatResult>,
    /// If set, [`Self::on_new_presentation`] fails with this error.
    fail_new_presentation: Option<TsmfError>,
    /// If set, [`Self::add_stream`] fails with this error.
    fail_add_stream: Option<TsmfError>,
    /// Topology readiness reply. Default = true.
    topology_ready: bool,
    /// If set, [`Self::shutdown_presentation`] fails with this error.
    fail_shutdown: Option<TsmfError>,

    // Call counters / capture for assertions:
    pub exchange_capabilities_calls: u32,
    pub last_server_capabilities: Vec<TsmmCapabilities>,
    pub on_new_presentation_calls: u32,
    pub last_new_presentation: Option<(Guid, u32)>,
    pub check_format_support_calls: u32,
    pub add_stream_calls: u32,
    pub last_added_stream: Option<(Guid, u32)>,
    pub set_topology_calls: u32,
    pub on_sample_calls: u32,
    pub last_sample: Option<(Guid, u32, Vec<u8>)>,
    pub remove_stream_calls: u32,
    pub shutdown_presentation_calls: u32,

    // Optional method counters:
    pub on_flush_calls: u32,
    pub on_end_of_stream_calls: u32,
    pub on_playback_started_calls: u32,
    pub on_playback_paused_calls: u32,
    pub on_playback_stopped_calls: u32,
    pub on_playback_restarted_calls: u32,
    pub on_playback_rate_changed_calls: u32,
    pub on_stream_volume_calls: u32,
    pub on_channel_volume_calls: u32,
    pub set_video_window_calls: u32,
    pub update_geometry_calls: u32,
    pub set_source_video_rect_calls: u32,
    pub set_allocator_calls: u32,
}

impl MockTsmfMediaSink {
    pub fn new() -> Self {
        Self {
            topology_ready: true,
            ..Default::default()
        }
    }

    pub fn with_client_capabilities(mut self, caps: Vec<TsmmCapabilities>) -> Self {
        self.client_capabilities = caps;
        self
    }

    pub fn with_format_response(mut self, resp: CheckFormatResult) -> Self {
        self.format_response = Some(resp);
        self
    }

    pub fn fail_new_presentation_with(mut self, err: TsmfError) -> Self {
        self.fail_new_presentation = Some(err);
        self
    }

    pub fn fail_add_stream_with(mut self, err: TsmfError) -> Self {
        self.fail_add_stream = Some(err);
        self
    }

    pub fn with_topology_ready(mut self, ready: bool) -> Self {
        self.topology_ready = ready;
        self
    }

    pub fn fail_shutdown_with(mut self, err: TsmfError) -> Self {
        self.fail_shutdown = Some(err);
        self
    }
}

impl AsAny for MockTsmfMediaSink {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl TsmfMediaSink for MockTsmfMediaSink {
    fn exchange_capabilities(
        &mut self,
        server_capabilities: &[TsmmCapabilities],
    ) -> Vec<TsmmCapabilities> {
        self.exchange_capabilities_calls += 1;
        self.last_server_capabilities = server_capabilities.to_vec();
        self.client_capabilities.clone()
    }

    fn on_new_presentation(
        &mut self,
        presentation_id: Guid,
        platform_cookie: u32,
    ) -> Result<(), TsmfError> {
        self.on_new_presentation_calls += 1;
        self.last_new_presentation = Some((presentation_id, platform_cookie));
        match self.fail_new_presentation {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn check_format_support(
        &mut self,
        _presentation_id: Guid,
        _media_type: &TsAmMediaType,
        _preferred_platform: u32,
        _no_rollover: bool,
    ) -> CheckFormatResult {
        self.check_format_support_calls += 1;
        self.format_response
            .unwrap_or_else(|| CheckFormatResult::supported(1))
    }

    fn add_stream(
        &mut self,
        presentation_id: Guid,
        stream_id: u32,
        _media_type: &TsAmMediaType,
    ) -> Result<(), TsmfError> {
        self.add_stream_calls += 1;
        self.last_added_stream = Some((presentation_id, stream_id));
        match self.fail_add_stream {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn set_topology(&mut self, _presentation_id: Guid) -> bool {
        self.set_topology_calls += 1;
        self.topology_ready
    }

    fn on_sample(&mut self, presentation_id: Guid, stream_id: u32, sample: &TsMmDataSample) {
        self.on_sample_calls += 1;
        self.last_sample = Some((presentation_id, stream_id, sample.p_data.clone()));
    }

    fn remove_stream(&mut self, _presentation_id: Guid, _stream_id: u32) {
        self.remove_stream_calls += 1;
    }

    fn shutdown_presentation(&mut self, _presentation_id: Guid) -> Result<(), TsmfError> {
        self.shutdown_presentation_calls += 1;
        match self.fail_shutdown {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn on_flush(&mut self, _presentation_id: Guid, _stream_id: u32) {
        self.on_flush_calls += 1;
    }
    fn on_end_of_stream(&mut self, _presentation_id: Guid, _stream_id: u32) {
        self.on_end_of_stream_calls += 1;
    }
    fn on_playback_started(
        &mut self,
        _presentation_id: Guid,
        _playback_start_offset: u64,
        _is_seek: bool,
    ) {
        self.on_playback_started_calls += 1;
    }
    fn on_playback_paused(&mut self, _presentation_id: Guid) {
        self.on_playback_paused_calls += 1;
    }
    fn on_playback_stopped(&mut self, _presentation_id: Guid) {
        self.on_playback_stopped_calls += 1;
    }
    fn on_playback_restarted(&mut self, _presentation_id: Guid) {
        self.on_playback_restarted_calls += 1;
    }
    fn on_playback_rate_changed(&mut self, _presentation_id: Guid, _new_rate: f32) {
        self.on_playback_rate_changed_calls += 1;
    }
    fn on_stream_volume(&mut self, _presentation_id: Guid, _new_volume: u32, _muted: bool) {
        self.on_stream_volume_calls += 1;
    }
    fn on_channel_volume(
        &mut self,
        _presentation_id: Guid,
        _channel_volume: u32,
        _changed_channel: u32,
    ) {
        self.on_channel_volume_calls += 1;
    }
    fn set_video_window(
        &mut self,
        _presentation_id: Guid,
        _video_window_id: u64,
        _hwnd_parent: u64,
    ) {
        self.set_video_window_calls += 1;
    }
    fn update_geometry(
        &mut self,
        _presentation_id: Guid,
        _geometry: &GeometryInfo,
        _visible_rects: &[TsRect],
    ) {
        self.update_geometry_calls += 1;
    }
    fn set_source_video_rect(
        &mut self,
        _presentation_id: Guid,
        _left: f32,
        _top: f32,
        _right: f32,
        _bottom: f32,
    ) {
        self.set_source_video_rect_calls += 1;
    }
    fn set_allocator(
        &mut self,
        _presentation_id: Guid,
        _stream_id: u32,
        _c_buffers: u32,
        _cb_buffer: u32,
        _cb_align: u32,
        _cb_prefix: u32,
    ) {
        self.set_allocator_calls += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsmf_error_to_hresult_mapping() {
        assert_eq!(TsmfError::NotFound.to_hresult(), E_FAIL);
        assert_eq!(TsmfError::AlreadyExists.to_hresult(), E_FAIL);
        assert_eq!(TsmfError::OperationNotSupported.to_hresult(), E_NOTIMPL);
        assert_eq!(TsmfError::OutOfMemory.to_hresult(), E_OUT_OF_MEMORY);
        assert_eq!(TsmfError::UnexpectedError.to_hresult(), E_FAIL);
        assert_eq!(TsmfError::Other(0xDEAD_BEEF).to_hresult(), 0xDEAD_BEEF);
    }

    #[test]
    fn result_to_hresult_ok_is_s_ok() {
        let r: Result<(), TsmfError> = Ok(());
        assert_eq!(result_to_hresult(r), S_OK);
    }

    #[test]
    fn result_to_hresult_err_maps() {
        let r: Result<(), TsmfError> = Err(TsmfError::OperationNotSupported);
        assert_eq!(result_to_hresult(r), E_NOTIMPL);
    }

    #[test]
    fn check_format_result_helpers() {
        let yes = CheckFormatResult::supported(2);
        assert!(yes.supported);
        assert_eq!(yes.platform_cookie, 2);
        let no = CheckFormatResult::unsupported();
        assert!(!no.supported);
    }

    #[test]
    fn mock_default_topology_is_ready() {
        let mut m = MockTsmfMediaSink::new();
        assert!(m.set_topology(Guid::NIL));
        assert_eq!(m.set_topology_calls, 1);
    }

    #[test]
    fn mock_can_be_configured_to_fail() {
        let mut m = MockTsmfMediaSink::new()
            .fail_new_presentation_with(TsmfError::OutOfMemory)
            .with_topology_ready(false);
        assert_eq!(
            m.on_new_presentation(Guid::NIL, 0),
            Err(TsmfError::OutOfMemory)
        );
        assert!(!m.set_topology(Guid::NIL));
    }
}
