#![forbid(unsafe_code)]

use alloc::vec::Vec;

use crate::error::TransportError;

/// Lower-level byte transport for the JustRDP web stack.
///
/// Anything reachable from a browser (or a hybrid app shell) that can move
/// bytes back and forth — WebSocket, WebTransport, WebRTC DataChannel, a
/// custom gateway — implements this trait. The rest of `justrdp-web` is
/// generic over `T: WebTransport`, so the choice of transport never leaks
/// up into the connector / renderer / channel layers.
///
/// ### Framing
///
/// `send` / `recv` are message-oriented from the *transport* point of view.
/// One `recv()` returns one transport-level message (e.g. one WebSocket
/// binary frame). RDP framing — TPKT length, fast-path headers, etc. — is
/// reassembled above this trait by the connector layer; the transport must
/// not split a frame mid-PDU when sending and must not concatenate inbound
/// frames when receiving.
///
/// ### Cancellation
///
/// All futures are cancel-safe by construction: dropping a `recv()` future
/// before it resolves must not lose a queued message, and dropping `send()`
/// before it resolves must either succeed atomically or surface an error
/// on the next call. Reference implementations that buffer internally
/// (such as `WebSocketTransport`) satisfy this naturally.
///
/// ### Future Send-ness
///
/// On non-wasm targets the returned futures are bound `+ Send` so the
/// trait can be used inside multi-threaded tokio runtimes (and in
/// adapters like `justrdp-tokio::gateway::WebTransportRw` that need
/// to box the futures behind `Send`-bounded trait objects). On wasm
/// targets the bound is dropped — `js_sys` / `web-sys` futures are
/// typically `!Send` and a `+ Send` requirement would lock out every
/// browser-side impl.
#[cfg(not(target_family = "wasm"))]
pub trait WebTransport {
    /// Send one transport-level message.
    ///
    /// Implementations MUST send the entire `bytes` slice as a single
    /// frame; partial sends or splits across frames are a protocol bug.
    fn send(
        &mut self,
        bytes: &[u8],
    ) -> impl core::future::Future<Output = Result<(), TransportError>> + Send;

    /// Receive the next inbound message.
    ///
    /// Returns the complete payload of one transport-level frame. EOF
    /// (graceful peer close) is reported as
    /// [`TransportErrorKind::ConnectionClosed`].
    ///
    /// [`TransportErrorKind::ConnectionClosed`]: crate::TransportErrorKind::ConnectionClosed
    fn recv(
        &mut self,
    ) -> impl core::future::Future<Output = Result<Vec<u8>, TransportError>> + Send;

    /// Initiate orderly close.
    ///
    /// Implementations should signal end-of-stream to the peer (WebSocket
    /// Close frame, HTTP/2 RST_STREAM, etc.) and ensure subsequent
    /// `send()` calls fail with `ConnectionClosed`.
    fn close(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), TransportError>> + Send;
}

/// Wasm-side trait variant — same shape, no `Send` bound on the
/// returned futures. See the doc comment on the non-wasm trait above.
#[cfg(target_family = "wasm")]
pub trait WebTransport {
    fn send(
        &mut self,
        bytes: &[u8],
    ) -> impl core::future::Future<Output = Result<(), TransportError>>;

    fn recv(&mut self) -> impl core::future::Future<Output = Result<Vec<u8>, TransportError>>;

    fn close(&mut self) -> impl core::future::Future<Output = Result<(), TransportError>>;
}

#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use alloc::collections::VecDeque;

    /// Minimal in-memory transport for unit tests. Exposed inside the crate
    /// only — embedders are expected to write transport-specific fakes
    /// against the public trait, which keeps the test surface honest.
    #[derive(Debug)]
    pub struct MockTransport {
        pub sent: Vec<Vec<u8>>,
        pub recv_queue: VecDeque<Result<Vec<u8>, TransportError>>,
        pub closed: bool,
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self {
                sent: Vec::new(),
                recv_queue: VecDeque::new(),
                closed: false,
            }
        }

        pub fn push_recv(&mut self, frame: Vec<u8>) {
            self.recv_queue.push_back(Ok(frame));
        }

        pub fn push_recv_error(&mut self, err: TransportError) {
            self.recv_queue.push_back(Err(err));
        }
    }

    impl WebTransport for MockTransport {
        async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            if self.closed {
                return Err(TransportError::closed("transport already closed"));
            }
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
            match self.recv_queue.pop_front() {
                Some(result) => result,
                None => Err(TransportError::closed("recv queue drained")),
            }
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            self.closed = true;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockTransport;
    use super::*;
    use crate::error::TransportErrorKind;
    use alloc::vec;

    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        pollster::block_on(f)
    }

    #[test]
    fn mock_send_records_payload() {
        block_on(async {
            let mut t = MockTransport::new();
            t.send(b"hello").await.unwrap();
            t.send(b"world").await.unwrap();
            assert_eq!(t.sent, vec![b"hello".to_vec(), b"world".to_vec()]);
        });
    }

    #[test]
    fn mock_recv_returns_queued_frames_in_order() {
        block_on(async {
            let mut t = MockTransport::new();
            t.push_recv(vec![1, 2, 3]);
            t.push_recv(vec![4, 5]);
            assert_eq!(t.recv().await.unwrap(), vec![1, 2, 3]);
            assert_eq!(t.recv().await.unwrap(), vec![4, 5]);
        });
    }

    #[test]
    fn mock_send_after_close_errors_with_connection_closed() {
        block_on(async {
            let mut t = MockTransport::new();
            t.close().await.unwrap();
            let err = t.send(b"x").await.unwrap_err();
            assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        });
    }

    #[test]
    fn mock_recv_drains_then_reports_closed() {
        block_on(async {
            let mut t = MockTransport::new();
            t.push_recv(vec![0xAA]);
            assert_eq!(t.recv().await.unwrap(), vec![0xAA]);
            assert_eq!(
                t.recv().await.unwrap_err().kind(),
                TransportErrorKind::ConnectionClosed
            );
        });
    }

    #[test]
    fn mock_propagates_recv_error_kind() {
        block_on(async {
            let mut t = MockTransport::new();
            t.push_recv_error(TransportError::protocol("bad opcode"));
            assert_eq!(
                t.recv().await.unwrap_err().kind(),
                TransportErrorKind::Protocol
            );
        });
    }

    /// The trait is generic; this confirms a function written against
    /// `T: WebTransport` actually compiles for the mock impl, catching
    /// any future generic-bound regressions.
    #[test]
    fn generic_function_accepts_mock() {
        async fn drive<T: WebTransport>(t: &mut T) -> Result<(), TransportError> {
            t.send(b"ping").await?;
            t.close().await?;
            Ok(())
        }
        block_on(async {
            let mut t = MockTransport::new();
            drive(&mut t).await.unwrap();
            assert_eq!(t.sent, vec![b"ping".to_vec()]);
            assert!(t.closed);
        });
    }
}
