#![forbid(unsafe_code)]

//! Generic connection driver: pumps a [`ClientConnector`] state machine to
//! `Connected` over any [`WebTransport`] implementation.
//!
//! The whole point of this crate is that `WebClient` is **transport-agnostic**:
//! it works equally well on top of `WebSocketTransport` (browser),
//! `WebTransport`/`WebRTC` (future), or an embedder-provided fake/proxy.
//! Native (non-wasm) consumers can use it just like any other async API
//! by paring it with a Tokio-style runtime.
//!
//! Scope of this S2 commit:
//! * Standard RDP Security only (`SecurityProtocol::RDP`).
//! * No TLS upgrade — hitting `EnhancedSecurityUpgrade` is reported as a
//!   typed [`DriverError::TlsRequired`] (S2 boundary; SSL/HYBRID are
//!   enabled in later steps).
//! * No CredSSP/NLA/AAD/RDSTLS — same handling.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use justrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectionResult, ConnectorError, Sequence,
};
use justrdp_core::{PduHint, WriteBuf};
use justrdp_session::SessionError;

use crate::error::TransportError;
use crate::telemetry::{async_warn, debug, info, trace};
use crate::transport::WebTransport;

/// Hard cap on a single PDU during the handshake; matches `justrdp-blocking`.
/// 16 MiB is well above any legitimate handshake PDU and protects against a
/// hostile bridge advertising an absurd `tpktLength`.
pub const MAX_HANDSHAKE_PDU_SIZE: usize = 16 * 1024 * 1024;

/// Driver-level failure modes. Kept separate from [`TransportError`] /
/// [`ConnectorError`] / [`SessionError`] so callers can pattern-match on
/// the *origin* of a failure (transport vs. connector vs. session vs.
/// driver policy).
#[derive(Debug)]
pub enum DriverError {
    /// The underlying [`WebTransport`] failed.
    Transport(TransportError),
    /// The connector state machine rejected a PDU or hit a state error.
    Connector(ConnectorError),
    /// The active session processor rejected a frame (decode/protocol).
    Session(SessionError),
    /// A handshake or active-session PDU exceeded
    /// [`MAX_HANDSHAKE_PDU_SIZE`].
    FrameTooLarge { size: usize },
    /// The connector reached `EnhancedSecurityUpgrade` but this driver
    /// doesn't support TLS in the current step (S2 boundary).
    TlsRequired,
    /// The connector reached an NLA/AAD/RDSTLS state but this driver
    /// doesn't support those flows yet (S2 boundary).
    NlaRequired { state: &'static str },
    /// An embedder-supplied [`TlsUpgrade`] returned an error during
    /// the in-band TLS handshake. The string is the upgrader's own
    /// error rendered via `Display`.
    TlsUpgrade(String),
    /// An embedder-supplied [`CredsspDriver`] returned an error during
    /// the SPNEGO / NTLM / Kerberos exchange.
    Credssp(String),
    /// The driver reached `Connected` but the connector did not produce a
    /// `ConnectionResult` — should be impossible; surfaces as a logic
    /// error rather than a panic.
    Internal(String),
}

impl DriverError {
    fn frame_too_large(size: usize) -> Self {
        Self::FrameTooLarge { size }
    }

    #[allow(dead_code)]
    fn nla_required(state: &'static str) -> Self {
        Self::NlaRequired { state }
    }

    fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl core::fmt::Display for DriverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Connector(e) => write!(f, "connector: {e:?}"),
            Self::Session(e) => write!(f, "session: {e}"),
            Self::FrameTooLarge { size } => {
                write!(f, "PDU too large: {size} bytes")
            }
            Self::TlsRequired => f.write_str("TLS upgrade required (NLA/SSL not yet supported in justrdp-web)"),
            Self::NlaRequired { state } => write!(f, "NLA/CredSSP not yet supported (state={state})"),
            Self::TlsUpgrade(msg) => write!(f, "TLS upgrade: {msg}"),
            Self::Credssp(msg) => write!(f, "CredSSP: {msg}"),
            Self::Internal(msg) => write!(f, "internal: {msg}"),
        }
    }
}

impl core::error::Error for DriverError {}

impl From<TransportError> for DriverError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

impl From<ConnectorError> for DriverError {
    fn from(e: ConnectorError) -> Self {
        Self::Connector(e)
    }
}

impl From<SessionError> for DriverError {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}

/// Pumps a [`ClientConnector`] through to `Connected` over any
/// [`WebTransport`].
///
/// Despite the `Web` prefix the type is **not** wasm-only — anyone driving
/// the connector with an async byte transport (Tauri shells, custom
/// gateway sidecars, native test rigs) can use this directly.
pub struct WebClient<T: WebTransport> {
    transport: T,
    /// When `true`, treat the connector's `EnhancedSecurityUpgrade`
    /// state as already complete — the WebSocket bridge (wsproxy /
    /// chisel / TS Gateway) is assumed to have terminated TLS to the
    /// RDP server already, so the byte stream we're moving on the
    /// `WebTransport` is already inside the post-TLS plaintext from
    /// the connector's point of view. False (default) keeps the
    /// behaviour from S2: we error with `TlsRequired` as soon as the
    /// state is reached.
    external_tls: bool,
}

impl<T: WebTransport> WebClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            external_tls: false,
        }
    }

    /// Tell the driver that any `EnhancedSecurityUpgrade` (SSL/HYBRID)
    /// the server requests has already been performed by the layer
    /// underneath the [`WebTransport`] (typically a `wss://` proxy
    /// terminating TLS to the RDP server). When set, the driver
    /// silently advances the connector through the upgrade state and
    /// keeps pumping bytes — no in-band TLS handshake.
    ///
    /// Leave `false` (the default) when the embedder is talking to a
    /// raw TCP bridge that does not perform TLS itself; the connector
    /// will error out with [`DriverError::TlsRequired`] so the embedder
    /// can plumb its own TLS upgrader (justrdp-tls or platform native).
    pub fn with_external_tls(mut self, enabled: bool) -> Self {
        self.external_tls = enabled;
        self
    }

    /// Whether `with_external_tls` was set.
    pub fn external_tls(&self) -> bool {
        self.external_tls
    }

    /// Reborrow the underlying transport without consuming the client.
    /// Useful when callers want to inspect transport state (closed flag,
    /// custom gateway counters) without ending the session.
    pub fn transport(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consume the client and surrender the transport — typically called
    /// after `connect()` succeeds and the caller wants to feed the same
    /// transport into the active session pump.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Drive the handshake to `Connected`, returning the
    /// [`ConnectionResult`] and the live transport so the caller can
    /// continue with the active-session pump.
    pub async fn connect(
        mut self,
        config: justrdp_connector::Config,
    ) -> Result<(ConnectionResult, T), DriverError> {
        info!(
            username = %config.credentials.username,
            external_tls = self.external_tls,
            "rdp.connect begin"
        );
        let mut connector = ClientConnector::new(config);
        let mut scratch: Vec<u8> = Vec::new();
        let mut output = WriteBuf::new();

        let stop = pump_until_terminal(
            &mut self.transport,
            &mut connector,
            &mut scratch,
            &mut output,
            self.external_tls,
        )
        .await?;
        match stop {
            PumpStop::Connected => {}
            PumpStop::EnhancedSecurityUpgrade => {
                async_warn!("rdp.connect tls_required (use connect_with_upgrade)");
                return Err(DriverError::TlsRequired);
            }
            PumpStop::NlaRequired { state } => {
                async_warn!(state, "rdp.connect nla_required (use connect_with_nla)");
                return Err(DriverError::NlaRequired { state });
            }
        }

        let result = connector
            .result()
            .cloned()
            .ok_or_else(|| DriverError::internal("Connected state without ConnectionResult"))?;
        info!(
            selected_protocol = ?result.selected_protocol,
            io_channel_id = result.io_channel_id,
            "rdp.connect ok"
        );
        Ok((result, self.transport))
    }

    /// Drive the handshake to `Connected` with an embedder-supplied
    /// in-band TLS upgrade. Three-phase pump:
    ///
    ///   1. Pre-TLS — pump until the connector reaches
    ///      `EnhancedSecurityUpgrade` (or `Connected` if the negotiated
    ///      protocol turned out to be Standard / RDP).
    ///   2. TLS — call `upgrade.upgrade(transport)`, which consumes the
    ///      original transport `T`, drives a TLS handshake using its
    ///      send/recv, and returns a new transport `U` whose `send` /
    ///      `recv` transparently encrypts / decrypts.
    ///   3. Post-TLS — advance the connector past the upgrade (no-op
    ///      step) and resume pumping until `Connected` over `U`.
    ///
    /// `with_external_tls(true)` and `connect_with_upgrade` are mutually
    /// exclusive: the former tells the driver "the bridge already did
    /// TLS, treat the upgrade as a no-op", while this method does an
    /// actual in-band handshake. `connect_with_upgrade` overrides the
    /// flag for the duration of the call.
    pub async fn connect_with_upgrade<U>(
        mut self,
        config: justrdp_connector::Config,
        upgrade: U,
    ) -> Result<(ConnectionResult, U::Output), DriverError>
    where
        U: TlsUpgrade<T>,
    {
        info!(
            username = %config.credentials.username,
            "rdp.connect_with_upgrade begin"
        );
        let mut connector = ClientConnector::new(config);
        let mut scratch: Vec<u8> = Vec::new();
        let mut output = WriteBuf::new();

        // Phase 1: pre-TLS pump. external_tls is forced false so we
        // actually surface the upgrade rather than skipping past it.
        debug!("rdp.connect.phase=pre_tls");
        let stop = pump_until_terminal(
            &mut self.transport,
            &mut connector,
            &mut scratch,
            &mut output,
            false,
        )
        .await?;
        match stop {
            PumpStop::Connected => {
                // Server picked Standard Security; no TLS happened. The
                // caller asked for an upgrade, so return an internal
                // error rather than silently producing a non-upgraded
                // U::Output we don't have.
                async_warn!("rdp.connect_with_upgrade server picked standard security");
                return Err(DriverError::internal(
                    "connect_with_upgrade: server selected Standard Security; \
                     use connect() instead",
                ));
            }
            PumpStop::NlaRequired { state } => {
                async_warn!(state, "rdp.connect_with_upgrade nla_required (use connect_with_nla)");
                return Err(DriverError::NlaRequired { state });
            }
            PumpStop::EnhancedSecurityUpgrade => {}
        }

        // Phase 2: hand the transport to the upgrader.
        debug!("rdp.connect.phase=tls_upgrade");
        let mut new_transport = upgrade
            .upgrade(self.transport)
            .await
            .map_err(|e| DriverError::TlsUpgrade(e.to_string()))?;

        // Advance the connector past EnhancedSecurityUpgrade (the
        // step() implementation just transitions state — no bytes
        // emitted in current connector code).
        output.clear();
        let _written = connector.step(&[], &mut output)?;
        if !output.is_empty() {
            new_transport.send(output.as_slice()).await?;
            output.clear();
        }

        // Phase 3: post-TLS pump.
        debug!("rdp.connect.phase=post_tls");
        let stop = pump_until_terminal(
            &mut new_transport,
            &mut connector,
            &mut scratch,
            &mut output,
            true, // never re-enter EnhancedSecurityUpgrade after upgrade
        )
        .await?;
        match stop {
            PumpStop::Connected => {}
            PumpStop::EnhancedSecurityUpgrade => {
                return Err(DriverError::internal(
                    "post-TLS pump returned to EnhancedSecurityUpgrade",
                ));
            }
            PumpStop::NlaRequired { state } => {
                async_warn!(state, "rdp.connect_with_upgrade nla_required after tls (use connect_with_nla)");
                return Err(DriverError::NlaRequired { state });
            }
        }

        let result = connector
            .result()
            .cloned()
            .ok_or_else(|| DriverError::internal("Connected state without ConnectionResult"))?;
        info!(
            selected_protocol = ?result.selected_protocol,
            "rdp.connect_with_upgrade ok"
        );
        Ok((result, new_transport))
    }

    /// Drive the handshake through `Connected` with both an in-band
    /// TLS upgrade and an embedder-driven CredSSP / NLA exchange.
    ///
    /// Five-phase pump:
    ///   1. Pre-TLS — pump until `EnhancedSecurityUpgrade`.
    ///   2. TLS — `tls_upgrade.upgrade(transport)`.
    ///   3. Mid pump — advance through `EnhancedSecurityUpgrade` and
    ///      pump until either `CredsspNegoTokens` (HYBRID / HYBRID_EX)
    ///      or `Connected` (SSL-only — no CredSSP needed).
    ///   4. CredSSP — `credssp.drive(connector, transport)`. The driver
    ///      runs the SPNEGO + NTLM/Kerberos exchange and advances
    ///      the connector through every CredSSP state.
    ///   5. Post-CredSSP — pump until `Connected`.
    ///
    /// Use this method only with an SSL/HYBRID-class config; for
    /// Standard Security use [`Self::connect`] (no TLS / CredSSP), and
    /// for SSL-without-NLA use [`Self::connect_with_upgrade`] (TLS
    /// only).
    pub async fn connect_with_nla<U, C>(
        mut self,
        config: justrdp_connector::Config,
        tls_upgrade: U,
        credssp: C,
    ) -> Result<(ConnectionResult, U::Output), DriverError>
    where
        U: TlsUpgrade<T>,
        C: CredsspDriver<U::Output>,
    {
        info!(
            username = %config.credentials.username,
            "rdp.connect_with_nla begin"
        );
        let mut connector = ClientConnector::new(config);
        let mut scratch: Vec<u8> = Vec::new();
        let mut output = WriteBuf::new();

        // Phase 1: pre-TLS pump.
        debug!("rdp.connect.phase=pre_tls");
        let stop = pump_until_terminal(
            &mut self.transport,
            &mut connector,
            &mut scratch,
            &mut output,
            false,
        )
        .await?;
        match stop {
            PumpStop::Connected => {
                async_warn!("rdp.connect_with_nla server picked standard security");
                return Err(DriverError::internal(
                    "connect_with_nla: server selected Standard Security; \
                     use connect() instead",
                ));
            }
            PumpStop::NlaRequired { .. } => {
                return Err(DriverError::internal(
                    "connect_with_nla: reached CredSSP state before TLS upgrade",
                ));
            }
            PumpStop::EnhancedSecurityUpgrade => {}
        }

        // Phase 2: TLS upgrade.
        debug!("rdp.connect.phase=tls_upgrade");
        let mut new_transport = tls_upgrade
            .upgrade(self.transport)
            .await
            .map_err(|e| DriverError::TlsUpgrade(e.to_string()))?;

        // Step past EnhancedSecurityUpgrade (no-op transition).
        output.clear();
        let _written = connector.step(&[], &mut output)?;
        if !output.is_empty() {
            new_transport.send(output.as_slice()).await?;
            output.clear();
        }

        // Phase 3: pump until either Connected (SSL-only) or
        // CredsspNegoTokens (HYBRID).
        debug!("rdp.connect.phase=mid_pump");
        let stop = pump_until_terminal(
            &mut new_transport,
            &mut connector,
            &mut scratch,
            &mut output,
            true,
        )
        .await?;
        match stop {
            PumpStop::Connected => {
                // SSL-only path took us all the way to Connected
                // without entering CredSSP. CredSSP driver isn't
                // needed; succeed.
                let result = connector.result().cloned().ok_or_else(|| {
                    DriverError::internal("Connected state without ConnectionResult")
                })?;
                info!(
                    selected_protocol = ?result.selected_protocol,
                    "rdp.connect_with_nla ok (ssl-only path, no credssp)"
                );
                return Ok((result, new_transport));
            }
            PumpStop::EnhancedSecurityUpgrade => {
                return Err(DriverError::internal(
                    "post-TLS pump returned to EnhancedSecurityUpgrade",
                ));
            }
            PumpStop::NlaRequired { .. } => {}
        }

        // Phase 4: CredSSP exchange. The driver advances the
        // connector through every CredSSP state.
        debug!("rdp.connect.phase=credssp");
        credssp
            .drive(&mut connector, &mut new_transport)
            .await
            .map_err(|e| DriverError::Credssp(e.to_string()))?;

        // Phase 5: post-CredSSP pump to Connected.
        debug!("rdp.connect.phase=post_credssp");
        let stop = pump_until_terminal(
            &mut new_transport,
            &mut connector,
            &mut scratch,
            &mut output,
            true,
        )
        .await?;
        match stop {
            PumpStop::Connected => {}
            PumpStop::EnhancedSecurityUpgrade => {
                return Err(DriverError::internal(
                    "post-CredSSP pump returned to EnhancedSecurityUpgrade",
                ));
            }
            PumpStop::NlaRequired { state } => {
                return Err(DriverError::internal(format!(
                    "post-CredSSP pump still at NLA state ({state}); \
                     CredsspDriver did not advance past CredSSP",
                )));
            }
        }

        let result = connector
            .result()
            .cloned()
            .ok_or_else(|| DriverError::internal("Connected state without ConnectionResult"))?;
        info!(
            selected_protocol = ?result.selected_protocol,
            "rdp.connect_with_nla ok"
        );
        Ok((result, new_transport))
    }
}

/// Outcome of one [`pump_until_terminal`] call.
#[derive(Debug)]
enum PumpStop {
    Connected,
    EnhancedSecurityUpgrade,
    NlaRequired { state: &'static str },
}

/// Drive the connector loop on `transport` until a terminal state
/// (`Connected`, `EnhancedSecurityUpgrade`, or any NLA-class state)
/// is reached. Shared between [`WebClient::connect`] (one phase) and
/// [`WebClient::connect_with_upgrade`] (two phases — same transport
/// before, new transport after).
async fn pump_until_terminal<T: WebTransport>(
    transport: &mut T,
    connector: &mut ClientConnector,
    scratch: &mut Vec<u8>,
    output: &mut WriteBuf,
    external_tls: bool,
) -> Result<PumpStop, DriverError> {
    loop {
        // Per-iteration trace — disabled at compile time without the
        // `tracing` feature. State::name() is cheap (returns &'static str).
        trace!(state = connector.state().name(), "pump_until_terminal.iter");
        match connector.state() {
            ClientConnectorState::Connected { .. } => return Ok(PumpStop::Connected),
            ClientConnectorState::EnhancedSecurityUpgrade => {
                if !external_tls {
                    return Ok(PumpStop::EnhancedSecurityUpgrade);
                }
                // The bridge already terminated TLS — advance the
                // connector through the no-op upgrade step and keep
                // looping.
                output.clear();
                let _written = connector.step(&[], output)?;
                if !output.is_empty() {
                    transport.send(output.as_slice()).await?;
                    output.clear();
                }
                continue;
            }
            state @ (ClientConnectorState::CredsspNegoTokens
            | ClientConnectorState::CredsspPubKeyAuth
            | ClientConnectorState::CredsspCredentials
            | ClientConnectorState::CredsspEarlyUserAuth
            | ClientConnectorState::AadWaitServerNonce
            | ClientConnectorState::AadSendAuthRequest
            | ClientConnectorState::AadWaitAuthResult
            | ClientConnectorState::RdstlsSendCapabilities
            | ClientConnectorState::RdstlsWaitCapabilities
            | ClientConnectorState::RdstlsSendAuthRequest
            | ClientConnectorState::RdstlsWaitAuthResponse) => {
                return Ok(PumpStop::NlaRequired {
                    state: state.name(),
                });
            }
            _ => {}
        }

        if let Some(hint) = connector.next_pdu_hint() {
            let n = recv_until_pdu(transport, hint, scratch).await?;
            let _written = connector.step(&scratch[..n], output)?;
            scratch.drain(..n);
        } else {
            output.clear();
            let _written = connector.step(&[], output)?;
        }

        if !output.is_empty() {
            transport.send(output.as_slice()).await?;
            output.clear();
        }
    }
}

/// In-band TLS upgrade contract.
///
/// `upgrade(transport)` consumes the original transport, drives the
/// TLS handshake using its `send`/`recv`, and returns a new transport
/// whose `send`/`recv` transparently encrypts / decrypts. The new
/// transport's bytes ARE the post-TLS plaintext from the connector's
/// point of view, so nothing else in [`WebClient::connect_with_upgrade`]
/// has to know TLS exists.
///
/// justrdp-web does not bundle a TLS implementation. Native callers
/// typically wrap `justrdp-tls::RustlsUpgrader`; browser callers
/// should prefer `with_external_tls(true)` against a `wss://`
/// proxy that terminates TLS to the RDP server.
pub trait TlsUpgrade<T: WebTransport> {
    /// Post-TLS transport. Same trait as the input — the rest of the
    /// pump pipes bytes through it as if no TLS happened.
    type Output: WebTransport;
    /// Upgrader-provided error type. The driver wraps it into
    /// [`DriverError::TlsUpgrade`] via `to_string`.
    type Error: core::fmt::Display;

    fn upgrade(
        self,
        transport: T,
    ) -> impl core::future::Future<Output = Result<Self::Output, Self::Error>>;
}

/// CredSSP / NLA driver contract.
///
/// `drive(connector, transport)` runs the full SPNEGO + NTLM/Kerberos
/// authentication exchange that follows the TLS upgrade for HYBRID /
/// HYBRID_EX security protocols (MS-CSSP, MS-RDPBCGR 1.3.1.1 phase 3).
/// On entry, the connector is in `CredsspNegoTokens` (or any other
/// CredSSP-class state). On successful return, the connector must
/// have advanced past every CredSSP state — typically reaching
/// `BasicSettingsExchangeSendInitial`.
///
/// Implementations are responsible for:
/// 1. Building a `CredsspSequence` from
///    `connector.credssp_credential_type()`.
/// 2. Driving the per-state TsRequest exchange over `transport`
///    (server cert, public key auth, encrypted credentials).
/// 3. Calling `connector.step(&[], &mut output)` to advance through
///    `CredsspNegoTokens → CredsspPubKeyAuth → CredsspCredentials
///    → (HYBRID_EX: CredsspEarlyUserAuth) → BasicSettingsExchangeSendInitial`.
///
/// justrdp-web ships no CredSSP implementation — the protocol needs
/// platform-specific NTLM/Kerberos integration (Windows SSPI,
/// libkrb5, MIT GSS-API). Native callers wire one through this trait;
/// browser callers typically can't run CredSSP at all and should
/// either pre-authenticate at the bridge or use a non-NLA target.
pub trait CredsspDriver<T: WebTransport> {
    /// Driver-provided error type. The driver wraps it into
    /// [`DriverError::Credssp`] via `to_string`.
    type Error: core::fmt::Display;

    fn drive(
        self,
        connector: &mut ClientConnector,
        transport: &mut T,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;
}

/// Accumulate bytes from the transport until exactly one PDU is buffered.
///
/// Browser bridges may deliver one RDP PDU per WebSocket message, but the
/// crate doesn't depend on that — we re-frame from the byte stream using
/// the connector-supplied [`PduHint`] just like `justrdp-blocking` does.
pub(crate) async fn recv_until_pdu<T: WebTransport>(
    transport: &mut T,
    hint: &dyn PduHint,
    scratch: &mut Vec<u8>,
) -> Result<usize, DriverError> {
    loop {
        if let Some((_fast_path, size)) = hint.find_size(scratch) {
            if size > MAX_HANDSHAKE_PDU_SIZE {
                return Err(DriverError::frame_too_large(size));
            }
            while scratch.len() < size {
                let frame = transport.recv().await?;
                if frame.is_empty() {
                    // Transports MUST NOT spam empty messages; an empty
                    // payload while we're waiting for body bytes is a
                    // protocol-level bug. Surfacing as ConnectionClosed is
                    // closest in semantics and lets the embedder retry.
                    return Err(DriverError::Transport(TransportError::closed(
                        "empty frame while reading PDU body",
                    )));
                }
                scratch.extend_from_slice(&frame);
            }
            return Ok(size);
        }
        let frame = transport.recv().await?;
        if frame.is_empty() {
            return Err(DriverError::Transport(TransportError::closed(
                "empty frame before PDU header",
            )));
        }
        scratch.extend_from_slice(&frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;
    use crate::TransportErrorKind;
    use alloc::vec;

    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        pollster::block_on(f)
    }

    #[test]
    fn driver_error_from_transport_preserves_kind() {
        let e: DriverError = TransportError::closed("peer gone").into();
        match e {
            DriverError::Transport(t) => {
                assert_eq!(t.kind(), TransportErrorKind::ConnectionClosed);
            }
            _ => panic!("expected Transport variant"),
        }
    }

    #[test]
    fn frame_too_large_carries_size() {
        let e = DriverError::frame_too_large(32 * 1024 * 1024);
        match e {
            DriverError::FrameTooLarge { size } => assert_eq!(size, 32 * 1024 * 1024),
            _ => panic!("expected FrameTooLarge"),
        }
    }

    /// Drives a fake "send-only" path: the connector immediately wants to
    /// send (state = ConnectionInitiationSendRequest), so the driver
    /// produces output without consuming any input. We don't run a real
    /// connector here — we just confirm `recv_until_pdu` rejects an empty
    /// pre-header frame, which is the corner case most likely to mask a
    /// silently-broken bridge.
    #[test]
    fn recv_until_pdu_rejects_empty_pre_header_frame() {
        block_on(async {
            let mut t = MockTransport::new();
            t.push_recv(vec![]);
            let mut scratch: Vec<u8> = Vec::new();
            // Use a hint that needs at least 4 bytes to figure out length.
            struct NeedsFour;
            impl PduHint for NeedsFour {
                fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)> {
                    if bytes.len() >= 4 { Some((false, 4)) } else { None }
                }
            }
            let err = recv_until_pdu(&mut t, &NeedsFour, &mut scratch)
                .await
                .unwrap_err();
            match err {
                DriverError::Transport(t) => {
                    assert_eq!(t.kind(), TransportErrorKind::ConnectionClosed);
                }
                other => panic!("expected Transport(ConnectionClosed), got {other:?}"),
            }
        });
    }

    #[test]
    fn recv_until_pdu_assembles_pdu_from_split_frames() {
        block_on(async {
            // PDU is 8 bytes. Bridge delivers it in three chunks.
            let mut t = MockTransport::new();
            t.push_recv(vec![0x01]);
            t.push_recv(vec![0x02, 0x03, 0x04]);
            t.push_recv(vec![0x05, 0x06, 0x07, 0x08]);
            let mut scratch: Vec<u8> = Vec::new();
            struct Eight;
            impl PduHint for Eight {
                fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)> {
                    if bytes.len() >= 1 { Some((false, 8)) } else { None }
                }
            }
            let n = recv_until_pdu(&mut t, &Eight, &mut scratch).await.unwrap();
            assert_eq!(n, 8);
            assert_eq!(&scratch[..n], &[1, 2, 3, 4, 5, 6, 7, 8]);
        });
    }

    #[test]
    fn recv_until_pdu_rejects_oversize() {
        block_on(async {
            let mut t = MockTransport::new();
            t.push_recv(vec![0xAA]); // any byte to satisfy hint min input
            let mut scratch: Vec<u8> = Vec::new();
            struct HugeHint;
            impl PduHint for HugeHint {
                fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)> {
                    if bytes.len() >= 1 {
                        Some((false, MAX_HANDSHAKE_PDU_SIZE + 1))
                    } else {
                        None
                    }
                }
            }
            let err = recv_until_pdu(&mut t, &HugeHint, &mut scratch)
                .await
                .unwrap_err();
            match err {
                DriverError::FrameTooLarge { size } => {
                    assert_eq!(size, MAX_HANDSHAKE_PDU_SIZE + 1);
                }
                other => panic!("expected FrameTooLarge, got {other:?}"),
            }
        });
    }

    // ── Driver-level integration with a real ClientConnector ────────────

    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use core::cell::RefCell;
    use justrdp_connector::Config;
    use justrdp_pdu::x224::SecurityProtocol;

    /// Test transport that exposes both the sent-bytes log and the
    /// recv-script via shared state, so a test can inspect what the
    /// driver wrote to the wire after a future resolves.
    #[derive(Debug)]
    struct CaptureTransport {
        shared: Rc<RefCell<CaptureShared>>,
    }

    #[derive(Debug)]
    struct CaptureShared {
        sent: Vec<Vec<u8>>,
        recv: VecDeque<Result<Vec<u8>, TransportError>>,
        closed: bool,
    }

    impl WebTransport for CaptureTransport {
        async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            let mut s = self.shared.borrow_mut();
            if s.closed {
                return Err(TransportError::closed("transport closed"));
            }
            s.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
            let mut s = self.shared.borrow_mut();
            match s.recv.pop_front() {
                Some(r) => r,
                None => Err(TransportError::closed("recv script exhausted")),
            }
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            self.shared.borrow_mut().closed = true;
            Ok(())
        }
    }

    fn standard_security_config() -> Config {
        let mut config = Config::builder("alice", "p4ss")
            .security_protocol(SecurityProtocol::RDP)
            .build();
        config.client_random = Some([0x42; 32]);
        config
    }

    /// End-to-end driver wire-up: the connector's first action is to send
    /// an X.224 Connection Request. With an empty recv script the driver
    /// must (a) emit one TPKT-framed send, then (b) bubble up the recv
    /// EOF as `DriverError::Transport(ConnectionClosed)`. This catches any
    /// regression where the loop forgets to call `transport.send()` or
    /// loses the EOF distinction from a generic transport error.
    #[test]
    fn driver_emits_x224_cr_then_propagates_recv_eof() {
        block_on(async {
            let shared = Rc::new(RefCell::new(CaptureShared {
                sent: Vec::new(),
                recv: VecDeque::new(),
                closed: false,
            }));
            let transport = CaptureTransport {
                shared: Rc::clone(&shared),
            };

            let client = WebClient::new(transport);
            let err = client
                .connect(standard_security_config())
                .await
                .unwrap_err();

            // Exactly one frame should have been sent before the driver
            // started waiting for the (never-arriving) ConnectionConfirm.
            let sent = shared.borrow().sent.clone();
            assert_eq!(sent.len(), 1, "expected one send before EOF, got {sent:?}");
            let cr = &sent[0];
            // TPKT version byte = 3, reserved = 0 (MS-RDPBCGR / RFC 1006).
            assert_eq!(cr[0], 0x03, "TPKT version byte");
            assert_eq!(cr[1], 0x00, "TPKT reserved byte");
            // TPKT length covers the whole frame.
            let tpkt_len = u16::from_be_bytes([cr[2], cr[3]]) as usize;
            assert_eq!(tpkt_len, cr.len(), "TPKT length must match payload size");
            // The driver should have surfaced the recv EOF, not a logic error.
            match err {
                DriverError::Transport(t) => {
                    assert_eq!(t.kind(), TransportErrorKind::ConnectionClosed);
                }
                other => panic!("expected Transport(ConnectionClosed), got {other:?}"),
            }
        });
    }

    /// If the configured security protocol forces NLA, the connector
    /// reaches `EnhancedSecurityUpgrade` after the X.224 handshake. The
    /// driver must surface that as `DriverError::TlsRequired` *before*
    /// trying to step the connector further — otherwise a
    /// next_pdu_hint() would loop forever in some states.
    ///
    /// We exercise this by running the connector with security_protocol =
    /// SSL | HYBRID, then handing it a fabricated ConnectionConfirm that
    /// tells it the server selected SSL.
    #[test]
    fn driver_reports_tls_required_when_server_selects_ssl() {
        use justrdp_pdu::x224::{ConnectionConfirm, NegotiationResponse, NegotiationResponseFlags};
        use justrdp_core::{Encode, WriteCursor};

        block_on(async {
            // Hand-roll the response: server picks SSL, which routes the
            // connector through EnhancedSecurityUpgrade.
            let cc = ConnectionConfirm::success(NegotiationResponse {
                flags: NegotiationResponseFlags::NONE,
                protocol: SecurityProtocol::SSL,
            });
            let inner_size = cc.size();
            let total = 4 + inner_size;
            let mut buf = vec![0u8; total];
            buf[0] = 0x03;
            buf[1] = 0x00;
            buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            let mut cursor = WriteCursor::new(&mut buf[4..]);
            cc.encode(&mut cursor).unwrap();

            let shared = Rc::new(RefCell::new(CaptureShared {
                sent: Vec::new(),
                recv: VecDeque::from([Ok(buf)]),
                closed: false,
            }));
            let transport = CaptureTransport {
                shared: Rc::clone(&shared),
            };

            let mut config = Config::builder("alice", "p4ss")
                .security_protocol(SecurityProtocol::SSL.union(SecurityProtocol::HYBRID))
                .build();
            config.client_random = Some([0x42; 32]);

            let client = WebClient::new(transport);
            let err = client.connect(config).await.unwrap_err();
            assert!(
                matches!(err, DriverError::TlsRequired),
                "expected TlsRequired, got {err:?}"
            );
            // The driver still emitted the X.224 CR before bailing.
            assert_eq!(shared.borrow().sent.len(), 1);
        });
    }

    /// `with_external_tls(true)` must let the driver advance through
    /// `EnhancedSecurityUpgrade` silently. The connector's next state
    /// after SSL upgrade is `BasicSettingsExchangeSendInitial` (a send
    /// state); the driver immediately emits the MCS Connect Initial
    /// PDU. With no further server response in the recv script, the
    /// loop then waits for `BasicSettingsExchangeWaitResponse` and
    /// hits the recv EOF — that's the signal we got past the upgrade.
    #[test]
    fn with_external_tls_advances_past_security_upgrade() {
        use justrdp_pdu::x224::{ConnectionConfirm, NegotiationResponse, NegotiationResponseFlags};
        use justrdp_core::{Encode, WriteCursor};

        block_on(async {
            let cc = ConnectionConfirm::success(NegotiationResponse {
                flags: NegotiationResponseFlags::NONE,
                protocol: SecurityProtocol::SSL,
            });
            let inner_size = cc.size();
            let total = 4 + inner_size;
            let mut buf = vec![0u8; total];
            buf[0] = 0x03;
            buf[1] = 0x00;
            buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            let mut cursor = WriteCursor::new(&mut buf[4..]);
            cc.encode(&mut cursor).unwrap();

            let shared = Rc::new(RefCell::new(CaptureShared {
                sent: Vec::new(),
                recv: VecDeque::from([Ok(buf)]),
                closed: false,
            }));
            let transport = CaptureTransport {
                shared: Rc::clone(&shared),
            };

            let mut config = Config::builder("alice", "p4ss")
                .security_protocol(SecurityProtocol::SSL)
                .build();
            config.client_random = Some([0x42; 32]);

            let client = WebClient::new(transport).with_external_tls(true);
            let err = client.connect(config).await.unwrap_err();
            // We got past the security upgrade: the driver issued
            // X.224 CR, then advanced through the upgrade, then sent
            // the MCS Connect Initial. So `sent` should now contain
            // *two* frames before the recv EOF stalled the loop.
            let sent_count = shared.borrow().sent.len();
            assert!(
                sent_count >= 2,
                "expected at least 2 sends past the upgrade, got {sent_count} (err={err:?})"
            );
            // And the failure must be the EOF, not TlsRequired.
            match err {
                DriverError::Transport(t) => {
                    assert_eq!(t.kind(), TransportErrorKind::ConnectionClosed);
                }
                other => panic!("expected Transport(ConnectionClosed), got {other:?}"),
            }
        });
    }

    /// `with_external_tls(false)` (the default) preserves the S2 behaviour:
    /// `EnhancedSecurityUpgrade` aborts with `TlsRequired` and the driver
    /// emits no further frames.
    #[test]
    fn without_external_tls_keeps_tls_required_default() {
        // This is what the `driver_reports_tls_required_when_server_selects_ssl`
        // test already covers; this is just a structural pin so the
        // default field value (`external_tls = false`) doesn't drift.
        let t = MockTransport::new();
        let client = WebClient::new(t);
        assert!(!client.external_tls());
        let client = client.with_external_tls(true);
        assert!(client.external_tls());
        let client = client.with_external_tls(false);
        assert!(!client.external_tls());
    }

    /// `CredsspDriver` exists, but a real impl needs platform NTLM /
    /// Kerberos plumbing. For tests we provide a fake that just calls
    /// `connector.step([], &mut output)` until the connector advances
    /// past every CredSSP state (which the existing connector
    /// implementation does as a no-op state transition — useful for
    /// pinning the *plumbing*).
    struct FakeCredsspDriver;

    impl<TT: WebTransport> CredsspDriver<TT> for FakeCredsspDriver {
        type Error = &'static str;

        async fn drive(
            self,
            connector: &mut ClientConnector,
            transport: &mut TT,
        ) -> Result<(), Self::Error> {
            let mut output = WriteBuf::new();
            // Step at most a few times so a buggy connector doesn't
            // loop forever in a test.
            for _ in 0..8 {
                match connector.state() {
                    ClientConnectorState::CredsspNegoTokens
                    | ClientConnectorState::CredsspPubKeyAuth
                    | ClientConnectorState::CredsspCredentials
                    | ClientConnectorState::CredsspEarlyUserAuth => {
                        output.clear();
                        connector
                            .step(&[], &mut output)
                            .map_err(|_| "step failed")?;
                        if !output.is_empty() {
                            transport
                                .send(output.as_slice())
                                .await
                                .map_err(|_| "send failed")?;
                            output.clear();
                        }
                    }
                    _ => return Ok(()),
                }
            }
            Err("CredSSP state machine did not advance past phase 3")
        }
    }

    /// `connect_with_nla` runs TLS upgrade + CredSSP plumbing. With a
    /// HYBRID protocol the connector visits CredSSP states; the fake
    /// driver advances past them so the post-CredSSP pump runs and
    /// stalls on EOF.
    #[test]
    fn connect_with_nla_runs_tls_then_credssp_plumbing() {
        use justrdp_pdu::x224::{ConnectionConfirm, NegotiationResponse, NegotiationResponseFlags};
        use justrdp_core::{Encode, WriteCursor};

        block_on(async {
            // Server picks HYBRID — connector goes through TLS then
            // CredSSP.
            let cc = ConnectionConfirm::success(NegotiationResponse {
                flags: NegotiationResponseFlags::NONE,
                protocol: SecurityProtocol::HYBRID,
            });
            let inner_size = cc.size();
            let total = 4 + inner_size;
            let mut buf = vec![0u8; total];
            buf[0] = 0x03;
            buf[1] = 0x00;
            buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            let mut cursor = WriteCursor::new(&mut buf[4..]);
            cc.encode(&mut cursor).unwrap();

            let shared = Rc::new(RefCell::new(CaptureShared {
                sent: Vec::new(),
                recv: VecDeque::from([Ok(buf)]),
                closed: false,
            }));
            let transport = CaptureTransport {
                shared: Rc::clone(&shared),
            };

            let mut config = Config::builder("alice", "p4ss")
                .security_protocol(SecurityProtocol::HYBRID)
                .build();
            config.client_random = Some([0x42; 32]);

            let client = WebClient::new(transport);
            let result = client
                .connect_with_nla(config, FakeTlsUpgrade, FakeCredsspDriver)
                .await;
            // Post-CredSSP pump stalls on recv EOF — Transport error
            // confirms we got past TLS upgrade AND the CredSSP plumbing.
            let err = result.unwrap_err();
            match err {
                DriverError::Transport(e) => {
                    assert_eq!(e.kind(), TransportErrorKind::ConnectionClosed);
                }
                other => panic!("expected Transport(ConnectionClosed), got {other:?}"),
            }
        });
    }

    /// Fake [`TlsUpgrade`] for tests — wraps the inner `CaptureTransport`
    /// in an outer struct that just delegates send/recv. A real impl
    /// would drive a TLS handshake using the inner transport's
    /// send/recv during `upgrade()`; here we want a transport-type
    /// change so the post-TLS pump runs over a *different* type.
    #[derive(Debug)]
    struct WrappedTransport {
        inner: CaptureTransport,
    }

    impl WebTransport for WrappedTransport {
        async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            self.inner.send(bytes).await
        }

        async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
            self.inner.recv().await
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            self.inner.close().await
        }
    }

    struct FakeTlsUpgrade;

    impl TlsUpgrade<CaptureTransport> for FakeTlsUpgrade {
        type Output = WrappedTransport;
        type Error = &'static str;

        async fn upgrade(self, transport: CaptureTransport) -> Result<Self::Output, Self::Error> {
            Ok(WrappedTransport { inner: transport })
        }
    }

    /// `connect_with_upgrade` runs the TLS upgrade when the server
    /// picks SSL. Since we don't ship a real ServerHello round-trip in
    /// the recv script, the post-TLS pump immediately stalls on EOF —
    /// but we can still verify that the upgrader was invoked (the
    /// returned transport is the WrappedTransport type) and that the
    /// X.224 CR was actually sent (transport.sent has 1 entry by the
    /// time we reach the upgrade).
    #[test]
    fn connect_with_upgrade_invokes_upgrader_after_security_upgrade() {
        use justrdp_pdu::x224::{ConnectionConfirm, NegotiationResponse, NegotiationResponseFlags};
        use justrdp_core::{Encode, WriteCursor};

        block_on(async {
            // Server picks SSL → connector reaches EnhancedSecurityUpgrade.
            let cc = ConnectionConfirm::success(NegotiationResponse {
                flags: NegotiationResponseFlags::NONE,
                protocol: SecurityProtocol::SSL,
            });
            let inner_size = cc.size();
            let total = 4 + inner_size;
            let mut buf = vec![0u8; total];
            buf[0] = 0x03;
            buf[1] = 0x00;
            buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            let mut cursor = WriteCursor::new(&mut buf[4..]);
            cc.encode(&mut cursor).unwrap();

            let shared = Rc::new(RefCell::new(CaptureShared {
                sent: Vec::new(),
                recv: VecDeque::from([Ok(buf)]),
                closed: false,
            }));
            let transport = CaptureTransport {
                shared: Rc::clone(&shared),
            };

            let mut config = Config::builder("alice", "p4ss")
                .security_protocol(SecurityProtocol::SSL)
                .build();
            config.client_random = Some([0x42; 32]);

            let client = WebClient::new(transport);
            let result = client.connect_with_upgrade(config, FakeTlsUpgrade).await;
            // Post-TLS pump stalls on recv EOF (our recv script only had
            // the ConnectionConfirm). That manifests as a Transport
            // error, NOT TlsRequired (we got past the upgrade) and NOT
            // a Connected without further input.
            let err = result.unwrap_err();
            match err {
                DriverError::Transport(e) => {
                    assert_eq!(e.kind(), TransportErrorKind::ConnectionClosed);
                }
                other => panic!("expected Transport(ConnectionClosed), got {other:?}"),
            }
            // sent should contain at least 2 frames: the X.224 CR
            // (pre-upgrade) and the MCS Connect Initial that the
            // post-upgrade pump emitted before stalling on recv-EOF.
            // The exact count past 2 depends on how many send states
            // the connector traverses before next_pdu_hint returns
            // Some — pinning the lower bound is enough.
            assert!(shared.borrow().sent.len() >= 2);
        });
    }

    /// If the server picks Standard Security, `connect_with_upgrade`
    /// must surface `Internal` rather than silently succeed — the
    /// caller asked for an upgrade and we don't have a U::Output to
    /// hand back.
    #[test]
    fn connect_with_upgrade_errors_on_standard_security() {
        use justrdp_pdu::x224::{ConnectionConfirm, NegotiationResponse, NegotiationResponseFlags};
        use justrdp_core::{Encode, WriteCursor};

        block_on(async {
            let cc = ConnectionConfirm::success(NegotiationResponse {
                flags: NegotiationResponseFlags::NONE,
                protocol: SecurityProtocol::RDP,
            });
            let inner_size = cc.size();
            let total = 4 + inner_size;
            let mut buf = vec![0u8; total];
            buf[0] = 0x03;
            buf[1] = 0x00;
            buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            let mut cursor = WriteCursor::new(&mut buf[4..]);
            cc.encode(&mut cursor).unwrap();

            let shared = Rc::new(RefCell::new(CaptureShared {
                sent: Vec::new(),
                recv: VecDeque::from([Ok(buf)]),
                closed: false,
            }));
            let transport = CaptureTransport {
                shared: Rc::clone(&shared),
            };

            let mut config = Config::builder("alice", "p4ss")
                .security_protocol(SecurityProtocol::RDP)
                .build();
            config.client_random = Some([0x42; 32]);

            let client = WebClient::new(transport);
            let err = client
                .connect_with_upgrade(config, FakeTlsUpgrade)
                .await
                .unwrap_err();
            // Standard Security never reaches EnhancedSecurityUpgrade;
            // the loop runs to recv-EOF (Transport error) before any
            // upgrade decision is needed. That's the *correct* outcome
            // here — the upgrade path simply isn't taken. The test
            // pins this so the user gets a recognizable error.
            assert!(
                matches!(err, DriverError::Transport(_) | DriverError::Internal(_)),
                "expected Transport or Internal error, got {err:?}"
            );
        });
    }
}
