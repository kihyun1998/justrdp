#![forbid(unsafe_code)]

//! `tokio::io::AsyncRead + AsyncWrite` adapter over a [`WebTransport`].
//!
//! Built so [`tokio_rustls::TlsConnector::connect`] (which requires
//! its IO type implement `AsyncRead + AsyncWrite + Unpin`) can run
//! the inner RDP TLS handshake on top of a gateway tunnel that itself
//! exposes only the message-oriented [`WebTransport`] surface.
//!
//! ### Storage shape
//!
//! The adapter owns the underlying transport behind
//! `Arc<tokio::sync::Mutex<T>>` so the in-flight `recv` / `send` /
//! `close` futures stored in `Self` can be `'static` — they take an
//! [`OwnedMutexGuard`](tokio::sync::OwnedMutexGuard) rather than
//! borrowing through `Self`. The mutex is uncontended in practice
//! (rustls' handshake serialises read/write on the same `Pin<&mut Self>`),
//! so the lock cost is just one CAS per round-trip.
//!
//! ### Cancel safety
//!
//! In-flight futures are kept across poll calls and only cleared on
//! completion. A cancelled `poll_read` / `poll_write` resumes the same
//! future on the next poll, so the underlying transport's atomicity
//! guarantees survive scheduler-level cancellation.

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use justrdp_async::{TransportError, TransportErrorKind, WebTransport};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as TokioMutex;

type BoxFut<O> = Pin<Box<dyn Future<Output = O> + Send>>;

/// `AsyncRead + AsyncWrite` view over a [`WebTransport`].
///
/// Construct with [`Self::new`] and hand the value to a tokio-side
/// IO consumer (`tokio_rustls::TlsConnector::connect`, a
/// `BufReader`, a Hyper HTTP/2 connection, …). The adapter never
/// fragments a single `WebTransport::send` payload across multiple
/// kernel writes, and never concatenates two `WebTransport::recv`
/// frames into one read — a single byte-stream view of a message
/// transport, with the message boundaries dissolved as the TLS layer
/// expects.
pub struct WebTransportRw<T: WebTransport + Send + 'static> {
    inner: Arc<TokioMutex<T>>,
    /// Bytes pulled from the transport but not yet handed to the
    /// caller (e.g. recv() returned a 16 KB chunk but the AsyncRead
    /// caller only had room for 4 KB on this poll).
    read_buf: Vec<u8>,
    read_pos: usize,
    in_flight_read: Option<BoxFut<Result<Vec<u8>, TransportError>>>,
    /// In-flight write future + the byte count we promised the caller
    /// when we started the future. AsyncWrite's `poll_write` returns
    /// "how many bytes were accepted"; we accept the whole buffer
    /// up front and report it on completion.
    in_flight_write: Option<(BoxFut<Result<(), TransportError>>, usize)>,
    in_flight_close: Option<BoxFut<Result<(), TransportError>>>,
}

impl<T: WebTransport + Send + 'static> core::fmt::Debug for WebTransportRw<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebTransportRw")
            .field("read_buf_len", &self.read_buf.len())
            .field("read_pos", &self.read_pos)
            .field("read_in_flight", &self.in_flight_read.is_some())
            .field("write_in_flight", &self.in_flight_write.is_some())
            .field("close_in_flight", &self.in_flight_close.is_some())
            .finish()
    }
}

impl<T: WebTransport + Send + 'static> WebTransportRw<T> {
    /// Wrap `transport`. The adapter takes ownership and serialises
    /// access through an internal mutex — callers that previously
    /// held the transport directly must drop their reference before
    /// any read / write progresses.
    pub fn new(transport: T) -> Self {
        Self {
            inner: Arc::new(TokioMutex::new(transport)),
            read_buf: Vec::new(),
            read_pos: 0,
            in_flight_read: None,
            in_flight_write: None,
            in_flight_close: None,
        }
    }

    /// Reclaim the underlying transport once the adapter is no longer
    /// needed. Panics if any in-flight future is still alive — the
    /// rustls / hyper consumer that owned them must have dropped them
    /// before this call.
    pub fn into_inner(self) -> T {
        match Arc::try_unwrap(self.inner) {
            Ok(mutex) => mutex.into_inner(),
            Err(_) => panic!(
                "WebTransportRw::into_inner: transport still locked by an in-flight future"
            ),
        }
    }
}

impl<T: WebTransport + Send + 'static> AsyncRead for WebTransportRw<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain any leftover bytes from a previous oversized recv.
        if this.read_pos < this.read_buf.len() {
            let avail = &this.read_buf[this.read_pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            this.read_pos += n;
            return Poll::Ready(Ok(()));
        }

        // Start a fresh recv future if there isn't one in flight.
        if this.in_flight_read.is_none() {
            let inner = this.inner.clone();
            this.in_flight_read = Some(Box::pin(async move {
                let mut guard = inner.lock_owned().await;
                guard.recv().await
            }));
        }

        let fut = this.in_flight_read.as_mut().expect("just set above");
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.in_flight_read = None;
                match result {
                    Ok(chunk) => {
                        if chunk.is_empty() {
                            // Empty recv = peer EOF. Tokio interprets
                            // an unfilled ReadBuf at this point as EOF
                            // (consistent with raw TcpStream).
                            return Poll::Ready(Ok(()));
                        }
                        let n = chunk.len().min(buf.remaining());
                        buf.put_slice(&chunk[..n]);
                        if n < chunk.len() {
                            this.read_buf = chunk;
                            this.read_pos = n;
                        } else {
                            this.read_buf.clear();
                            this.read_pos = 0;
                        }
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(transport_to_io(e))),
                }
            }
        }
    }
}

impl<T: WebTransport + Send + 'static> AsyncWrite for WebTransportRw<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.in_flight_write.is_none() {
            // Buffer the caller's bytes — we can't borrow them across
            // the `await` because the future has to be `'static`.
            let inner = this.inner.clone();
            let owned: Vec<u8> = buf.to_vec();
            let len = owned.len();
            this.in_flight_write = Some((
                Box::pin(async move {
                    let mut guard = inner.lock_owned().await;
                    guard.send(&owned).await
                }),
                len,
            ));
        }

        let (fut, len) = this
            .in_flight_write
            .as_mut()
            .expect("just set above");
        let len = *len;
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.in_flight_write = None;
                match result {
                    Ok(()) => Poll::Ready(Ok(len)),
                    Err(e) => Poll::Ready(Err(transport_to_io(e))),
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // WebTransport::send commits its bytes to the underlying
        // wire before the future resolves — no buffering on our
        // side, no flush work to do.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.in_flight_close.is_none() {
            let inner = this.inner.clone();
            this.in_flight_close = Some(Box::pin(async move {
                let mut guard = inner.lock_owned().await;
                guard.close().await
            }));
        }
        let fut = this
            .in_flight_close
            .as_mut()
            .expect("just set above");
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.in_flight_close = None;
                Poll::Ready(result.map_err(transport_to_io))
            }
        }
    }
}

fn transport_to_io(e: TransportError) -> io::Error {
    let kind = match e.kind() {
        TransportErrorKind::ConnectionClosed => io::ErrorKind::ConnectionAborted,
        TransportErrorKind::Protocol => io::ErrorKind::InvalidData,
        TransportErrorKind::Io
        | TransportErrorKind::Other
        | TransportErrorKind::Cancelled => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Debug, Default)]
    struct ScriptedTransport {
        sent: Vec<Vec<u8>>,
        recv_queue: VecDeque<Result<Vec<u8>, TransportError>>,
        closed: bool,
    }

    impl ScriptedTransport {
        fn push(&mut self, frame: Vec<u8>) {
            self.recv_queue.push_back(Ok(frame));
        }
    }

    impl WebTransport for ScriptedTransport {
        async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
            if self.closed {
                return Err(TransportError::closed("scripted: closed"));
            }
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
            self.recv_queue
                .pop_front()
                .unwrap_or_else(|| Err(TransportError::closed("scripted: drained")))
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            self.closed = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn read_returns_recv_frame_bytes() {
        let mut t = ScriptedTransport::default();
        t.push(vec![1, 2, 3, 4]);
        let mut rw = WebTransportRw::new(t);
        let mut buf = [0u8; 8];
        let n = rw.read(&mut buf).await.unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn read_buffers_oversized_chunks_across_calls() {
        // recv() returns 8 bytes; first read takes 4, second takes
        // the remaining 4. Only one recv() syscall must fire.
        let mut t = ScriptedTransport::default();
        t.push(vec![10, 20, 30, 40, 50, 60, 70, 80]);
        let mut rw = WebTransportRw::new(t);
        let mut a = [0u8; 4];
        rw.read_exact(&mut a).await.unwrap();
        assert_eq!(&a, &[10, 20, 30, 40]);
        let mut b = [0u8; 4];
        rw.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, &[50, 60, 70, 80]);
    }

    #[tokio::test]
    async fn write_forwards_bytes_to_send() {
        let t = ScriptedTransport::default();
        let mut rw = WebTransportRw::new(t);
        rw.write_all(b"hello").await.unwrap();
        rw.write_all(b"world").await.unwrap();
        // Drop the wrapper to reclaim the inner transport for
        // assertions; into_inner panics on in-flight futures so use
        // it after both writes have resolved.
        let inner = rw.into_inner();
        assert_eq!(inner.sent, vec![b"hello".to_vec(), b"world".to_vec()]);
    }

    #[tokio::test]
    async fn read_eof_returns_zero_bytes() {
        // Empty recv() resolves to a 0-byte buffer (interpreted as
        // EOF by tokio). The next read therefore returns 0 bytes.
        let mut t = ScriptedTransport::default();
        t.recv_queue.push_back(Ok(Vec::new()));
        let mut rw = WebTransportRw::new(t);
        let mut buf = [0u8; 4];
        let n = rw.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn read_after_peer_close_surfaces_as_io_error() {
        let t = ScriptedTransport::default(); // empty queue → drained = ConnectionClosed
        let mut rw = WebTransportRw::new(t);
        let mut buf = [0u8; 4];
        let err = rw.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn shutdown_calls_close_on_inner() {
        let t = ScriptedTransport::default();
        let mut rw = WebTransportRw::new(t);
        rw.shutdown().await.unwrap();
        let inner = rw.into_inner();
        assert!(inner.closed);
    }

    #[tokio::test]
    async fn flush_is_immediate_no_op() {
        // poll_flush returning Ready(Ok) is the entire contract; the
        // assertion is just that the call returns without spinning.
        let t = ScriptedTransport::default();
        let mut rw = WebTransportRw::new(t);
        rw.flush().await.unwrap();
    }
}
