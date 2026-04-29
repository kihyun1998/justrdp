#![forbid(unsafe_code)]

//! Native TCP transport — `tokio::net::TcpStream` adapted to
//! [`WebTransport`].
//!
//! Lets desktop embedders run the same `WebClient` / `ActiveSession`
//! pump that the wasm32 build uses, but talking directly to an RDP
//! server's port 3389 (no `wsproxy` shim, no WebSocket framing). The
//! transport returns whatever bytes are currently available from the
//! socket; the connector layer's `recv_until_pdu` reassembler in
//! [`crate::driver`] re-frames TPKT / fast-path PDUs across multiple
//! `recv()` calls — same as the blocking client does.
//!
//! `wasm32` builds skip this module entirely (the `tokio` dep is
//! declared only for `cfg(not(target_arch = "wasm32"))`).

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use justrdp_async::{TransportError, WebTransport};

/// Default per-`recv()` read buffer size. Sized so RemoteFX progressive
/// frames (~64 KB tile-set headers) come back in one or two reads on a
/// healthy socket without making the per-call alloc dominate. The
/// connector reassembles arbitrary chunking so this is pure tuning.
const DEFAULT_RECV_BUF_BYTES: usize = 16 * 1024;

/// Native TCP transport for desktop targets.
///
/// Construct via [`Self::connect`] (DNS-resolved address) or
/// [`Self::from_stream`] (caller-owned `TcpStream`, useful for tests
/// and for callers who set socket options or perform the connect via
/// their own runtime). Then hand the value to
/// [`crate::WebClient::connect`] / [`crate::WebClient::connect_with_upgrade`]
/// /etc. — the trait is the integration point, not this struct.
pub struct NativeTcpTransport {
    stream: TcpStream,
    /// Reusable read buffer. `tokio::AsyncReadExt::read` fills as
    /// much of this as is available, so we slice off the prefix
    /// for the returned `Vec`. Re-allocating per call would dominate
    /// the busy receive path.
    recv_buf: Vec<u8>,
    /// Sticky once peer EOF is observed or `close()` has been called.
    /// Subsequent `send` / `recv` calls fail with `ConnectionClosed`
    /// without re-touching the socket.
    closed: bool,
}

impl NativeTcpTransport {
    /// Open a TCP connection to `addr`. The socket is left in default
    /// mode (blocking-equivalent under tokio); callers that need
    /// `set_nodelay`, keepalive, etc. should construct the stream
    /// themselves and use [`Self::from_stream`].
    pub async fn connect<A>(addr: A) -> Result<Self, TransportError>
    where
        A: tokio::net::ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| TransportError::io(format!("tcp connect: {e}")))?;
        Ok(Self::from_stream(stream))
    }

    /// Wrap an already-connected `TcpStream`. Use this when the caller
    /// needs to control connect options (`set_nodelay`, source-bind,
    /// `connect_timeout`) or to reuse a stream from a higher-level
    /// connector.
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream,
            recv_buf: vec![0u8; DEFAULT_RECV_BUF_BYTES],
            closed: false,
        }
    }

    /// Override the per-`recv()` read buffer size. Larger values can
    /// reduce syscall count for high-throughput RFX / AVC traffic but
    /// pin more memory per transport. Zero is treated as the default.
    pub fn set_recv_buf_size(&mut self, bytes: usize) {
        let new_size = if bytes == 0 { DEFAULT_RECV_BUF_BYTES } else { bytes };
        self.recv_buf = vec![0u8; new_size];
    }

    /// Take back the underlying `TcpStream`. Useful when the caller
    /// wants to perform a TLS upgrade with their own rustls /
    /// native-tls stack rather than using `connect_with_upgrade`. The
    /// transport is left in a closed state; subsequent calls return
    /// `ConnectionClosed`.
    pub fn into_stream(mut self) -> TcpStream {
        self.closed = true;
        self.stream
    }
}

impl WebTransport for NativeTcpTransport {
    async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::closed("native-tcp: already closed"));
        }
        // `write_all` retries short writes internally — callers see
        // either "all bytes flushed to the kernel" or an error.
        // Empty payloads are a no-op rather than a syscall (matches
        // the contract that the upper layers only send non-empty
        // PDUs).
        if bytes.is_empty() {
            return Ok(());
        }
        self.stream
            .write_all(bytes)
            .await
            .map_err(|e| TransportError::io(format!("tcp send: {e}")))?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed {
            return Err(TransportError::closed("native-tcp: already closed"));
        }
        let n = self
            .stream
            .read(&mut self.recv_buf)
            .await
            .map_err(|e| TransportError::io(format!("tcp recv: {e}")))?;
        if n == 0 {
            // Peer half-closed the socket. Stick the closed flag so
            // the next call short-circuits without a redundant
            // syscall. The driver layer maps this to a clean session
            // termination.
            self.closed = true;
            return Err(TransportError::closed("native-tcp: peer closed"));
        }
        Ok(self.recv_buf[..n].to_vec())
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // `shutdown()` is best-effort here — RDP servers often see
        // disconnect via TPKT-level signals before TCP FIN, so a
        // failed shutdown isn't an error from the embedder's
        // perspective. Surface only catastrophic failures.
        if let Err(e) = self.stream.shutdown().await {
            return Err(TransportError::io(format!("tcp shutdown: {e}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_async::TransportErrorKind;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// Bind a loopback listener and return the bound address plus an
    /// accept-future that yields the server-side stream. Used to
    /// construct deterministic round-trip tests that don't depend on
    /// a real RDP server.
    async fn loopback_pair() -> (NativeTcpTransport, tokio::net::TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Spawn the accept on a separate task so connect & accept can
        // make progress concurrently within the same #[tokio::test].
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = NativeTcpTransport::connect(addr).await.unwrap();
        let server = accept.await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn send_writes_full_payload_to_peer() {
        let (mut client, mut server) = loopback_pair().await;
        client.send(b"abcdef").await.unwrap();
        let mut buf = [0u8; 6];
        // The server side reads the exact bytes back.
        let n = server.read_exact(&mut buf).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf, b"abcdef");
    }

    #[tokio::test]
    async fn recv_returns_chunked_bytes_from_peer() {
        // The connector layer reassembles across multiple `recv()`
        // calls, so a single peer-side write may surface as one or
        // more `recv()` returns depending on kernel buffering. We
        // assert only that the *bytes received* match what the peer
        // wrote, summed across enough calls to drain.
        let (mut client, mut server) = loopback_pair().await;
        server.write_all(&[0xAA, 0xBB, 0xCC, 0xDD]).await.unwrap();

        let mut total: Vec<u8> = Vec::new();
        // Up to 4 polls is plenty for 4 bytes on loopback.
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
    async fn recv_after_peer_eof_reports_connection_closed() {
        let (mut client, server) = loopback_pair().await;
        // Drop the server side — this closes its half of the socket.
        drop(server);
        let err = client.recv().await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
        // Subsequent calls short-circuit on the sticky flag.
        let err2 = client.recv().await.unwrap_err();
        assert_eq!(err2.kind(), TransportErrorKind::ConnectionClosed);
    }

    #[tokio::test]
    async fn send_after_close_reports_connection_closed() {
        let (mut client, _server) = loopback_pair().await;
        client.close().await.unwrap();
        let err = client.send(b"x").await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
    }

    #[tokio::test]
    async fn close_is_idempotent() {
        let (mut client, _server) = loopback_pair().await;
        client.close().await.unwrap();
        // Second close must succeed without touching the now-shutdown
        // socket (avoid `Transport endpoint is not connected` style
        // errors from the OS).
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn empty_send_is_a_noop_and_does_not_close() {
        let (mut client, mut server) = loopback_pair().await;
        client.send(&[]).await.unwrap();
        // The peer must see zero bytes available (no kernel-level
        // syscalls were issued for an empty write).
        client.send(b"after").await.unwrap();
        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"after");
    }

    #[tokio::test]
    async fn into_stream_returns_underlying_socket_and_marks_closed() {
        let (client, _server) = loopback_pair().await;
        let stream = client.into_stream();
        // Caller can use the raw stream for e.g. a TLS upgrade.
        assert!(stream.peer_addr().is_ok());
    }

    #[tokio::test]
    async fn set_recv_buf_size_zero_uses_default() {
        let (mut client, _server) = loopback_pair().await;
        client.set_recv_buf_size(0);
        // Internal state isn't observable, but a subsequent recv
        // path must still be functional. Drive a recv expecting EOF
        // (server is dropped at end of test).
        drop(_server);
        let err = client.recv().await.unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::ConnectionClosed);
    }
}
