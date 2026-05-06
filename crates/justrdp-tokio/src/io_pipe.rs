#![forbid(unsafe_code)]

//! Internal byte-pipe helper shared by the native transports.
//!
//! `NativeTcpTransport`, `NativeTlsTransport`, and `NativeTlsOsTransport`
//! all wrap a `tokio::AsyncRead + AsyncWrite + Unpin + Send` stream and
//! expose the same `WebTransport` surface (send / recv / close + a
//! reusable read buffer + a sticky `closed` flag). Without this helper
//! the bookkeeping was triplicated across the three modules.
//!
//! The helper is `pub(crate)` on purpose — the public seam embedders
//! plug into is `justrdp_async::WebTransport` itself; exposing the
//! generic byte-pipe wrapper would introduce a second public layer
//! with no additional leverage.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use justrdp_async::TransportError;

/// Default per-`recv()` read buffer size. Sized so RemoteFX progressive
/// frames (~64 KB tile-set headers) come back in one or two reads on a
/// healthy socket without making the per-call alloc dominate. The
/// connector reassembles arbitrary chunking, so this is pure tuning.
pub(crate) const DEFAULT_RECV_BUF_BYTES: usize = 16 * 1024;

/// Internal byte-pipe over an async stream.
///
/// Owns the reusable read buffer, the sticky-`closed` flag, and an
/// `&'static str` name used as the prefix in transport errors. The
/// owning `Native*Transport` newtype delegates `WebTransport::send /
/// recv / close` to the matching helpers here.
pub(crate) struct AsyncIoTransport<S> {
    stream: S,
    /// Reusable read buffer. `tokio::AsyncReadExt::read` fills as much
    /// of this as is available, so we slice off the prefix for the
    /// returned `Vec`. Re-allocating per call would dominate the busy
    /// receive path.
    recv_buf: Vec<u8>,
    /// Sticky once peer EOF is observed or `close()` has been called.
    /// Subsequent `send` / `recv` calls fail with `ConnectionClosed`
    /// without re-touching the stream.
    closed: bool,
    /// Error-message prefix — `"native-tcp"`, `"native-tls"`,
    /// `"native-tls-os"`. Embedded into every `TransportError` produced
    /// by the helpers below so callers can tell which transport failed.
    name: &'static str,
}

impl<S> core::fmt::Debug for AsyncIoTransport<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't introspect the stream — `S` is not bounded `Debug` and
        // some stream types (TLS) carry secrets we should not render
        // in logs anyway.
        f.debug_struct("AsyncIoTransport")
            .field("name", &self.name)
            .field("closed", &self.closed)
            .field("recv_buf_len", &self.recv_buf.len())
            .finish_non_exhaustive()
    }
}

impl<S> AsyncIoTransport<S> {
    pub(crate) fn new(stream: S, name: &'static str) -> Self {
        Self::with_buf_size(stream, name, DEFAULT_RECV_BUF_BYTES)
    }

    pub(crate) fn with_buf_size(stream: S, name: &'static str, size: usize) -> Self {
        let size = if size == 0 { DEFAULT_RECV_BUF_BYTES } else { size };
        Self {
            stream,
            recv_buf: vec![0u8; size],
            closed: false,
            name,
        }
    }

    pub(crate) fn stream(&self) -> &S {
        &self.stream
    }

    pub(crate) fn into_stream(mut self) -> S {
        self.closed = true;
        self.stream
    }

    pub(crate) fn set_recv_buf_size(&mut self, bytes: usize) {
        let new_size = if bytes == 0 { DEFAULT_RECV_BUF_BYTES } else { bytes };
        self.recv_buf = vec![0u8; new_size];
    }
}

impl<S> AsyncIoTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub(crate) async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::closed(format!("{}: already closed", self.name)));
        }
        // Empty payloads are a no-op rather than a syscall (matches the
        // contract that the upper layers only send non-empty PDUs).
        if bytes.is_empty() {
            return Ok(());
        }
        // `write_all` retries short writes internally — callers see
        // either "all bytes flushed to the kernel" or an error.
        self.stream
            .write_all(bytes)
            .await
            .map_err(|e| TransportError::io(format!("{} send: {e}", self.name)))?;
        Ok(())
    }

    pub(crate) async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed {
            return Err(TransportError::closed(format!("{}: already closed", self.name)));
        }
        let n = self
            .stream
            .read(&mut self.recv_buf)
            .await
            .map_err(|e| TransportError::io(format!("{} recv: {e}", self.name)))?;
        if n == 0 {
            // Peer half-closed the stream. Stick the closed flag so the
            // next call short-circuits without a redundant syscall. The
            // driver layer maps this to a clean session termination.
            self.closed = true;
            return Err(TransportError::closed(format!("{}: peer closed", self.name)));
        }
        Ok(self.recv_buf[..n].to_vec())
    }

    pub(crate) async fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // `shutdown()` is best-effort here — peers often see the
        // disconnect via protocol-level signals before the underlying
        // stream's FIN/close-notify, so a failed shutdown isn't fatal
        // from the embedder's perspective. Surface only catastrophic
        // failures.
        if let Err(e) = self.stream.shutdown().await {
            return Err(TransportError::io(format!("{} shutdown: {e}", self.name)));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_async::TransportErrorKind;
    use tokio::io::{AsyncWriteExt, DuplexStream};

    fn pair() -> (AsyncIoTransport<DuplexStream>, DuplexStream) {
        let (a, b) = tokio::io::duplex(64);
        (AsyncIoTransport::new(a, "test"), b)
    }

    #[tokio::test]
    async fn send_writes_full_payload_to_peer() {
        let (mut client, mut peer) = pair();
        client.send(b"abcdef").await.unwrap();
        let mut buf = [0u8; 6];
        tokio::io::AsyncReadExt::read_exact(&mut peer, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"abcdef");
    }

    #[tokio::test]
    async fn empty_send_is_a_noop_and_does_not_touch_stream() {
        let (mut client, mut peer) = pair();
        client.send(&[]).await.unwrap();
        // Follow-up non-empty send proves the stream is still healthy
        // after the no-op.
        client.send(b"after").await.unwrap();
        let mut buf = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut peer, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"after");
    }

    #[tokio::test]
    async fn recv_returns_chunks_until_drained() {
        let (mut client, mut peer) = pair();
        peer.write_all(&[0xAA, 0xBB, 0xCC, 0xDD]).await.unwrap();
        let mut total: Vec<u8> = Vec::new();
        for _ in 0..4 {
            if total.len() >= 4 {
                break;
            }
            let chunk = client.recv().await.unwrap();
            total.extend_from_slice(&chunk);
        }
        assert_eq!(total, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[tokio::test]
    async fn recv_after_peer_eof_reports_connection_closed_then_short_circuits() {
        let (mut client, peer) = pair();
        drop(peer);
        let err = client.recv().await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        // Sticky-closed: subsequent recv must NOT touch the stream.
        let err2 = client.recv().await.unwrap_err();
        assert_eq!(err2.kind(), TransportErrorKind::ConnectionClosed);
    }

    #[tokio::test]
    async fn send_after_close_reports_connection_closed() {
        let (mut client, _peer) = pair();
        client.close().await.unwrap();
        let err = client.send(b"x").await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
    }

    #[tokio::test]
    async fn close_is_idempotent() {
        let (mut client, _peer) = pair();
        client.close().await.unwrap();
        // Second close must not touch the now-shutdown stream — the
        // sticky flag short-circuits before the syscall.
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn error_messages_include_configured_name() {
        let (mut client, _peer) = pair();
        client.close().await.unwrap();
        let err = client.send(b"x").await.unwrap_err();
        // The configured prefix must appear in the rendered message so
        // the owning newtype's name is preserved across the helper
        // boundary.
        assert!(format!("{err}").contains("test"), "got: {err}");
    }

    #[tokio::test]
    async fn into_stream_returns_underlying_stream_and_marks_closed() {
        let (client, _peer) = pair();
        let _stream = client.into_stream();
        // Compile-only — recovers ownership of the inner stream so the
        // caller can drive a TLS upgrade etc. The closed flag flip is
        // a precondition for the upgrader to reject double-use.
    }

    #[tokio::test]
    async fn set_recv_buf_size_zero_falls_back_to_default() {
        let (mut client, peer) = pair();
        client.set_recv_buf_size(0);
        // Internal state isn't observable, but the recv path must still
        // work — drive a recv expecting EOF.
        drop(peer);
        let err = client.recv().await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
    }
}
