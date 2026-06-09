//! `justrdp-tokio` — the thin Tokio I/O adapter that makes the sans-IO [`justrdp`] core real
//! (ADR-0001). It owns the socket; the state machine owns the protocol. The adapter drains the
//! machine's [`Action`]s (open the socket, write bytes), feeds it [`Event`]s (connected, bytes
//! received), and applies a per-stage timeout — surfacing the stage name on failure.
//!
//! slice-1 drives the first two connect stages (`tcp-connect` → `x224-negotiate`); later slices
//! extend the same loop through TLS, NLA, MCS, and activation.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use justrdp::{Action, ConnectError, ConnectStateMachine, Event};
use justrdp_pdu::nego::SecurityProtocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Timeout for the TCP dial.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for the X.224 security-negotiation round trip.
const X224_TIMEOUT: Duration = Duration::from_secs(15);

/// A successful slice-1 connect: the server-selected transport security protocol plus the live
/// stream, handed to the next stage (TLS upgrade) in a later slice.
#[derive(Debug)]
pub struct ConnectOutcome {
    /// The protocol the server chose in the X.224 Connection Confirm.
    pub selected: SecurityProtocol,
    /// The connected TCP stream, positioned just after the Connection Confirm.
    pub stream: TcpStream,
}

/// Why the adapter-driven connect failed.
#[derive(Debug)]
pub enum ConnectFailure {
    /// A socket-level error.
    Io(io::Error),
    /// The protocol state machine rejected the exchange.
    Protocol(ConnectError),
    /// A connect stage exceeded its timeout; carries the stage name.
    Timeout {
        /// The stage that timed out (e.g. `"tcp-connect"`, `"x224-negotiate"`).
        stage: &'static str,
    },
}

impl std::fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectFailure::Io(e) => write!(f, "i/o error: {e}"),
            ConnectFailure::Protocol(e) => write!(f, "protocol error: {e:?}"),
            ConnectFailure::Timeout { stage } => write!(f, "timed out during stage {stage}"),
        }
    }
}

impl std::error::Error for ConnectFailure {}

impl From<io::Error> for ConnectFailure {
    fn from(e: io::Error) -> Self {
        ConnectFailure::Io(e)
    }
}

/// Connect to `addr` and run the X.224 security negotiation, advertising `requested`. `on_stage`
/// is called with each connect stage label as it is entered, for progress UI / diagnostics.
///
/// Returns the negotiated protocol and the live stream on success.
#[tracing::instrument(
    skip(on_stage),
    fields(host = %addr.ip(), port = addr.port()),
    err,
)]
pub async fn connect(
    addr: SocketAddr,
    requested: SecurityProtocol,
    mut on_stage: impl FnMut(&str),
) -> Result<ConnectOutcome, ConnectFailure> {
    let mut sm = ConnectStateMachine::new(requested);
    let mut stream: Option<TcpStream> = None;
    let mut inbox: Vec<u8> = Vec::new();
    let mut readbuf = [0u8; 8192];
    let mut queue: VecDeque<Action> = sm.start().into();
    on_stage(sm.stage());
    tracing::debug!(stage = sm.stage(), "entering connect stage");

    loop {
        while let Some(action) = queue.pop_front() {
            match action {
                Action::Connect => {
                    let s = with_stage_timeout(
                        "tcp-connect",
                        TCP_CONNECT_TIMEOUT,
                        TcpStream::connect(addr),
                    )
                    .await?;
                    tracing::debug!("tcp socket connected");
                    stream = Some(s);
                    queue.extend(sm.process(Event::Connected));
                    on_stage(sm.stage());
                    tracing::debug!(stage = sm.stage(), "entering connect stage");
                }
                Action::WriteBytes(bytes) => {
                    let s = stream.as_mut().expect("socket connected before write");
                    s.write_all(&bytes).await?;
                    tracing::debug!(bytes = bytes.len(), "wrote frame to socket");
                }
                Action::Proceed { selected } => {
                    tracing::debug!(?selected, "x224 negotiation complete");
                    return Ok(ConnectOutcome {
                        selected,
                        stream: stream.expect("socket connected before proceed"),
                    });
                }
                Action::FailWith(e) => return Err(ConnectFailure::Protocol(e)),
            }
        }

        // The queue drained without a terminal action: the machine needs more bytes.
        let s = stream.as_mut().expect("socket connected before read");
        let n = with_stage_timeout(sm.stage(), X224_TIMEOUT, s.read(&mut readbuf)).await?;
        if n == 0 {
            return Err(ConnectFailure::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "server closed connection during X.224 negotiation",
            )));
        }
        tracing::debug!(bytes = n, stage = sm.stage(), "read from socket");
        inbox.extend_from_slice(&readbuf[..n]);
        queue.extend(sm.process(Event::Received(&inbox)));
    }
}

/// Await `fut` under the stage's timeout, mapping the outcome into a [`ConnectFailure`]: an I/O
/// error becomes `Io`, and an elapsed timeout becomes `Timeout { stage }`. Every connect stage
/// wraps its I/O through this single seam so the timeout/error policy lives in one place.
async fn with_stage_timeout<T>(
    stage: &'static str,
    dur: Duration,
    fut: impl Future<Output = io::Result<T>>,
) -> Result<T, ConnectFailure> {
    match tokio::time::timeout(dur, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(ConnectFailure::Io(e)),
        Err(_) => Err(ConnectFailure::Timeout { stage }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tracing_test::traced_test;

    fn requested() -> SecurityProtocol {
        SecurityProtocol::SSL | SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX
    }

    #[tokio::test]
    async fn with_stage_timeout_passes_through_ready_value() {
        let out =
            with_stage_timeout("test", Duration::from_secs(1), async { Ok::<u8, io::Error>(42) })
                .await;
        assert!(matches!(out, Ok(42)));
    }

    #[tokio::test]
    async fn with_stage_timeout_maps_io_error_to_io() {
        let out: Result<u8, ConnectFailure> =
            with_stage_timeout("test", Duration::from_secs(1), async {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
            })
            .await;
        assert!(matches!(out, Err(ConnectFailure::Io(_))));
    }

    #[tokio::test]
    async fn with_stage_timeout_maps_elapsed_to_timeout_with_stage() {
        // A future that never resolves must elapse and surface the stage name.
        let never = std::future::pending::<io::Result<u8>>();
        let out = with_stage_timeout("x224-negotiate", Duration::from_millis(10), never).await;
        assert!(matches!(
            out,
            Err(ConnectFailure::Timeout {
                stage: "x224-negotiate"
            })
        ));
    }

    /// A captured X.224 Connection Confirm carrying an 8-byte RDP negotiation structure.
    fn confirm_frame(nego: [u8; 8]) -> Vec<u8> {
        let mut cc = vec![0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00];
        cc.extend_from_slice(&nego);
        justrdp_pdu::tpkt::encode(&cc)
    }

    /// Spawn a one-shot mock RDP server on loopback that reads the client's Connection Request and
    /// replies with `reply`. Returns the address to connect to.
    async fn mock_server(reply: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 64];
            let _ = sock.read(&mut scratch).await.unwrap(); // drain the Connection Request
            sock.write_all(&reply).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_logs_stage_transitions_and_byte_counts() {
        // Server selects HYBRID (0x02).
        let addr = mock_server(confirm_frame([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00])).await;
        connect(addr, requested(), |_| {}).await.unwrap();

        // Every connect stage is named in the debug logs (criterion 14: observable transitions)...
        assert!(logs_contain("tcp-connect"), "tcp-connect stage not logged");
        assert!(logs_contain("x224-negotiate"), "x224-negotiate stage not logged");
        // ...and byte counts are logged for the bytes written and read.
        assert!(logs_contain("bytes="), "byte counts not logged");
    }

    #[tokio::test]
    async fn connect_returns_protocol_the_server_selected() {
        // Server selects HYBRID (0x02) via RDP_NEG_RSP.
        let addr = mock_server(confirm_frame([0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00])).await;

        let mut stages = Vec::new();
        let outcome = connect(addr, requested(), |s| stages.push(s.to_string()))
            .await
            .unwrap();

        assert_eq!(outcome.selected, SecurityProtocol::HYBRID);
        assert_eq!(stages, vec!["tcp-connect", "x224-negotiate"]);
    }

    #[tokio::test]
    async fn connect_surfaces_server_negotiation_failure() {
        // Server refuses with RDP_NEG_FAILURE / HYBRID_REQUIRED_BY_SERVER (0x05).
        let addr = mock_server(confirm_frame([0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00])).await;

        let err = connect(addr, requested(), |_| {}).await.unwrap_err();
        assert!(
            matches!(err, ConnectFailure::Protocol(ConnectError::NegotiationFailed(_))),
            "expected a protocol negotiation failure, got {err:?}"
        );
    }

    /// Real-VM acceptance test (ADR-0001 differential/real-VM harness). Ignored by default — run
    /// with `cargo test -p justrdp-tokio -- --ignored` against the live RDP test VM. Verifies the
    /// adapter completes X.224 negotiation and the server selects a protocol we advertised.
    #[tokio::test]
    #[ignore = "requires the live RDP test VM at 192.168.136.136:3389"]
    async fn connect_completes_x224_against_real_vm() {
        let addr: SocketAddr = "192.168.136.136:3389".parse().unwrap();
        let req = requested();

        let outcome = connect(addr, req, |stage| eprintln!("stage: {stage}"))
            .await
            .expect("X.224 negotiation should complete against the real VM");

        eprintln!("server selected protocol: {:?}", outcome.selected);
        // The server must select exactly one protocol from the set we advertised.
        assert!(outcome.selected.bits() != 0);
        assert!(req.contains(outcome.selected));
    }
}
