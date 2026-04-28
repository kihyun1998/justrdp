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

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectionResult, ConnectorError, Sequence,
};
use justrdp_core::{PduHint, WriteBuf};
use justrdp_session::SessionError;

use crate::error::TransportError;
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
    /// The driver reached `Connected` but the connector did not produce a
    /// `ConnectionResult` — should be impossible; surfaces as a logic
    /// error rather than a panic.
    Internal(String),
}

impl DriverError {
    fn frame_too_large(size: usize) -> Self {
        Self::FrameTooLarge { size }
    }

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
}

impl<T: WebTransport> WebClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
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
        let mut connector = ClientConnector::new(config);
        let mut scratch: Vec<u8> = Vec::new();
        let mut output = WriteBuf::new();

        loop {
            // Terminal / unsupported-state checks first so we never call
            // step() in a state we know we can't drive forward.
            match connector.state() {
                ClientConnectorState::Connected { .. } => break,
                ClientConnectorState::EnhancedSecurityUpgrade => {
                    return Err(DriverError::TlsRequired);
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
                    return Err(DriverError::nla_required(state.name()));
                }
                _ => {}
            }

            // Hint borrow ends before step() takes &mut connector (NLL).
            if let Some(hint) = connector.next_pdu_hint() {
                let n = recv_until_pdu(&mut self.transport, hint, &mut scratch).await?;
                let _written = connector.step(&scratch[..n], &mut output)?;
                scratch.drain(..n);
            } else {
                output.clear();
                let _written = connector.step(&[], &mut output)?;
            }

            if !output.is_empty() {
                self.transport.send(output.as_slice()).await?;
                output.clear();
            }
        }

        let result = connector
            .result()
            .cloned()
            .ok_or_else(|| DriverError::internal("Connected state without ConnectionResult"))?;
        Ok((result, self.transport))
    }
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
}
