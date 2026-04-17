#![forbid(unsafe_code)]

//! Blocking I/O adapter that drives an [`RpchTunnelState`] over two
//! arbitrary `Read + Write` byte streams (typically two TLS-wrapped
//! `TcpStream`s — one per HTTP channel).
//!
//! The caller is responsible for performing the HTTP request phase
//! on each stream before handing it to [`RpchTunnel::connect`]: open
//! TCP, complete NTLM 401 retry loop, write the `RPC_IN_DATA` /
//! `RPC_OUT_DATA` request head, consume the HTTP 200 status line
//! and response headers. What this adapter needs is two streams
//! positioned at the **start of the HTTP body** of their respective
//! requests.
//!
//! After [`connect`][RpchTunnel::connect] returns, use
//! [`send_pdu`][RpchTunnel::send_pdu] and
//! [`recv_pdu`][RpchTunnel::recv_pdu] to exchange DCE/RPC PDUs.
//! `recv_pdu` transparently consumes CONN/A3 / C2 / FlowControlAck
//! RTS PDUs as they arrive and retries until a real data PDU lands.

extern crate std;

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use std::vec::Vec;

use justrdp_core::WriteCursor;

use crate::pdu::{
    common::{PFC_FIRST_FRAG, PFC_LAST_FRAG},
    COMMON_HEADER_SIZE,
};
use crate::tunnel::{
    peek_frag_length, HandshakeStage, OutboundAction, RpchTunnelConfig, RpchTunnelError,
    RpchTunnelState,
};

// =============================================================================
// Error type
// =============================================================================

/// Errors produced by the blocking tunnel adapter.
#[derive(Debug)]
pub enum TunnelIoError {
    Io(io::Error),
    Protocol(RpchTunnelError),
    /// The peer closed the stream while the handshake was still in
    /// progress.
    UnexpectedEof {
        stage: HandshakeStage,
    },
    /// A common-header validation failed while framing an incoming
    /// PDU from the OUT stream.
    FrameError(justrdp_core::DecodeError),
}

impl core::fmt::Display for TunnelIoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "RPCH tunnel I/O: {e}"),
            Self::Protocol(e) => write!(f, "RPCH tunnel protocol: {e}"),
            Self::UnexpectedEof { stage } => {
                write!(f, "RPCH tunnel: unexpected EOF at stage {stage:?}")
            }
            Self::FrameError(e) => write!(f, "RPCH tunnel: invalid PDU header: {e}"),
        }
    }
}

impl core::error::Error for TunnelIoError {}

impl From<io::Error> for TunnelIoError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<RpchTunnelError> for TunnelIoError {
    fn from(e: RpchTunnelError) -> Self {
        Self::Protocol(e)
    }
}

// =============================================================================
// Blocking tunnel
// =============================================================================

/// Blocking adapter that owns the two channel streams and the
/// tunnel state machine.
///
/// The IN stream is wrapped in `Arc<Mutex<_>>` so a background
/// keepalive thread (see [`spawn_keepalive_thread`]) can write
/// Ping RTS PDUs without racing against [`send_pdu`] calls on the
/// main thread. `Arc<Mutex<_>>` is intentionally required even
/// without keepalive — the contention is a single-writer bottleneck
/// in practice and the type stays the same across both call sites.
#[derive(Debug)]
pub struct RpchTunnel<I: Read + Write, O: Read + Write> {
    inbound: Arc<Mutex<I>>,
    outbound: O,
    state: RpchTunnelState,
    /// Small scratch buffer reused across `recv_pdu` calls.
    scratch: Vec<u8>,
}

impl<I: Read + Write, O: Read + Write> RpchTunnel<I, O> {
    /// Drive the CONN/A1 → A3 → C2 handshake.
    ///
    /// Writes CONN/A1 to the OUT stream's request body, CONN/B1 to
    /// the IN stream's request body, then reads RTS PDUs off the
    /// OUT stream's response body until the tunnel reaches
    /// [`HandshakeStage::Ready`]. Returns the constructed tunnel on
    /// success.
    pub fn connect(
        mut inbound: I,
        mut outbound: O,
        cfg: RpchTunnelConfig,
    ) -> Result<Self, TunnelIoError> {
        let mut state = RpchTunnelState::new(cfg);

        // Write CONN/A1 on the OUT channel body.
        let a1 = state.build_conn_a1();
        outbound.write_all(&a1)?;
        outbound.flush()?;

        // Write CONN/B1 on the IN channel body.
        let b1 = state.build_conn_b1();
        inbound.write_all(&b1)?;
        inbound.flush()?;

        let mut scratch = Vec::with_capacity(128);

        while state.stage() != HandshakeStage::Ready {
            let pdu = read_one_pdu(&mut outbound, &mut scratch)?.ok_or_else(|| {
                TunnelIoError::UnexpectedEof {
                    stage: state.stage(),
                }
            })?;
            match state.feed_out_pdu(&pdu)? {
                OutboundAction::HandshakeProgress | OutboundAction::Ping => {}
                OutboundAction::DataPdu(_) => {
                    return Err(TunnelIoError::Protocol(
                        RpchTunnelError::UnexpectedDataPdu,
                    ));
                }
                OutboundAction::FlowControlAck { .. } => {
                    // Legal per §3.2.2.1; ignored during handshake.
                }
            }
        }

        Ok(Self {
            inbound: Arc::new(Mutex::new(inbound)),
            outbound,
            state,
            scratch,
        })
    }

    /// Write one complete DCE/RPC PDU to the IN channel body.
    pub fn send_pdu(&mut self, pdu: &[u8]) -> Result<(), TunnelIoError> {
        let mut g = self.inbound.lock().expect("rpch inbound mutex poisoned");
        g.write_all(pdu)?;
        g.flush()?;
        Ok(())
    }

    /// Write a keepalive Ping RTS PDU on the IN channel. A ping is
    /// `PTYPE=0x14` with `RTS_FLAG_PING` set, `NumberOfCommands=1`
    /// with an `Empty` command — the minimal payload the gateway
    /// accepts as "client still alive" (MS-RPCH §3.2.1.5.5).
    pub fn send_ping(&mut self) -> Result<(), TunnelIoError> {
        let bytes = build_keepalive_ping_pdu();
        self.send_pdu(&bytes)
    }

    /// Clone the `Arc<Mutex<I>>` that guards the IN stream. Intended
    /// for [`spawn_keepalive_thread`] and similar out-of-band
    /// writers.
    pub fn inbound_handle(&self) -> Arc<Mutex<I>> {
        self.inbound.clone()
    }

    /// Read one complete DCE/RPC data PDU off the OUT channel body.
    ///
    /// Any server-originated RTS (flow control, ping, connection
    /// timeout refresh) is consumed transparently: this call keeps
    /// reading until a non-RTS PDU arrives or the stream closes.
    /// If the stream closes cleanly between PDUs, returns `Ok(None)`.
    pub fn recv_pdu(&mut self) -> Result<Option<Vec<u8>>, TunnelIoError> {
        loop {
            let Some(pdu) = read_one_pdu(&mut self.outbound, &mut self.scratch)? else {
                return Ok(None);
            };
            match self.state.feed_out_pdu(&pdu)? {
                OutboundAction::DataPdu(data) => {
                    // Maybe the client is now obliged to emit an ack
                    // to keep the server's send window open.
                    if let Some(ack) = self.state.flow_ack_if_due() {
                        let mut g =
                            self.inbound.lock().expect("rpch inbound mutex poisoned");
                        g.write_all(&ack)?;
                        g.flush()?;
                    }
                    return Ok(Some(data));
                }
                OutboundAction::HandshakeProgress
                | OutboundAction::FlowControlAck { .. }
                | OutboundAction::Ping => {
                    // Absorb and keep reading.
                }
            }
        }
    }

    /// Borrow the underlying state machine (for metrics / testing).
    pub fn state(&self) -> &RpchTunnelState {
        &self.state
    }
}

// =============================================================================
// Keepalive
// =============================================================================

/// Build the 24-byte serialized form of a keepalive Ping RTS PDU.
/// Used by both [`RpchTunnel::send_ping`] and
/// [`spawn_keepalive_thread`].
fn build_keepalive_ping_pdu() -> Vec<u8> {
    use crate::pdu::{RtsCommand, RtsPdu, RTS_FLAG_PING};
    let pdu = RtsPdu {
        pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
        flags: RTS_FLAG_PING,
        commands: std::vec![RtsCommand::Empty],
    };
    let mut buf = std::vec![0u8; pdu.size()];
    let mut w = WriteCursor::new(&mut buf);
    pdu.encode(&mut w).expect("ping PDU fits");
    buf
}

/// Live handle returned by [`spawn_keepalive_thread`]. Dropping it
/// signals the worker to exit and joins the thread.
#[derive(Debug)]
pub struct KeepaliveHandle {
    stop: Arc<AtomicBool>,
    joiner: Option<JoinHandle<()>>,
}

impl KeepaliveHandle {
    /// Ask the keepalive worker to stop and block until it does.
    /// Idempotent — calling more than once is a no-op.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.joiner.take() {
            let _ = j.join();
        }
    }

    /// Has the worker been asked to stop?
    pub fn is_stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

impl Drop for KeepaliveHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Spawn a background thread that writes a keepalive Ping RTS PDU
/// to `inbound` every `interval`. Returns a handle whose `Drop`
/// signals the thread to exit.
///
/// The thread never panics on transient write errors — a network
/// blip should not tear the tunnel down through this path — it
/// just swallows them and retries on the next tick. When the
/// stream really is dead, the main thread's next `send_pdu` will
/// surface the failure.
pub fn spawn_keepalive_thread<W>(inbound: Arc<Mutex<W>>, interval: Duration) -> KeepaliveHandle
where
    W: Write + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let stop_cloned = stop.clone();
    let ping_bytes = build_keepalive_ping_pdu();

    let joiner = thread::spawn(move || {
        // Use coarse-grained sleeps so shutdown is observed within
        // ~100 ms of the Drop signal, irrespective of `interval`.
        let tick = Duration::from_millis(100);
        let mut last_fire = Instant::now();
        while !stop_cloned.load(Ordering::SeqCst) {
            thread::sleep(tick.min(interval));
            if last_fire.elapsed() >= interval {
                let mut g = match inbound.lock() {
                    Ok(g) => g,
                    Err(_) => break, // poisoned — stop cleanly
                };
                if let Err(_e) = g.write_all(&ping_bytes).and_then(|_| g.flush()) {
                    // Transport is in trouble; drop the lock and
                    // let the main thread's next send_pdu report.
                    break;
                }
                drop(g);
                last_fire = Instant::now();
            }
        }
    });

    KeepaliveHandle {
        stop,
        joiner: Some(joiner),
    }
}

// =============================================================================
// PDU framing
// =============================================================================

/// Read exactly one complete CO PDU from `stream`, growing `scratch`
/// as needed. Returns `Ok(None)` if `stream` closes cleanly between
/// PDUs.
fn read_one_pdu<R: Read>(
    stream: &mut R,
    scratch: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, TunnelIoError> {
    scratch.clear();
    scratch.resize(COMMON_HEADER_SIZE, 0);

    // Read the 16-byte common header; tolerate clean EOF on the
    // very first byte.
    let mut read_so_far = 0;
    while read_so_far < COMMON_HEADER_SIZE {
        let n = stream.read(&mut scratch[read_so_far..])?;
        if n == 0 {
            return if read_so_far == 0 {
                Ok(None)
            } else {
                Err(TunnelIoError::UnexpectedEof {
                    stage: HandshakeStage::Ready,
                })
            };
        }
        read_so_far += n;
    }

    let frag = peek_frag_length(scratch).map_err(TunnelIoError::FrameError)?
        .ok_or_else(|| {
            TunnelIoError::FrameError(justrdp_core::DecodeError::invalid_value(
                "CommonHeader",
                "frag_length",
            ))
        })?;
    let frag = frag as usize;
    if frag < COMMON_HEADER_SIZE {
        return Err(TunnelIoError::FrameError(
            justrdp_core::DecodeError::invalid_value("CommonHeader", "frag_length"),
        ));
    }
    scratch.resize(frag, 0);
    stream.read_exact(&mut scratch[COMMON_HEADER_SIZE..])?;
    Ok(Some(scratch.clone()))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{
        uuid::RpcUuid, PFC_FIRST_FRAG, PFC_LAST_FRAG, RequestPdu, RtsCommand, RtsPdu,
        RTS_FLAG_NONE,
    };
    use justrdp_core::WriteCursor;
    use std::io::Cursor;
    use std::vec;

    /// A fake channel backed by two `Vec<u8>` buffers — one for
    /// bytes we will hand to `read()`, one to capture bytes the
    /// client `write()`s.
    #[derive(Debug)]
    struct FakeChannel {
        read_buf: Cursor<Vec<u8>>,
        write_buf: Vec<u8>,
    }

    impl FakeChannel {
        fn new(to_read: Vec<u8>) -> Self {
            Self {
                read_buf: Cursor::new(to_read),
                write_buf: Vec::new(),
            }
        }
    }

    impl Read for FakeChannel {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_buf.read(buf)
        }
    }

    impl Write for FakeChannel {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn encode_rts(pdu: &RtsPdu) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        buf
    }

    fn test_config() -> RpchTunnelConfig {
        RpchTunnelConfig {
            virtual_connection_cookie: RpcUuid::parse("11111111-1111-1111-1111-111111111111")
                .unwrap(),
            out_channel_cookie: RpcUuid::parse("22222222-2222-2222-2222-222222222222").unwrap(),
            in_channel_cookie: RpcUuid::parse("33333333-3333-3333-3333-333333333333").unwrap(),
            association_group_id: RpcUuid::parse("44444444-4444-4444-4444-444444444444").unwrap(),
            receive_window_size: 65536,
            channel_lifetime: 0x4000_0000,
            client_keepalive: 300_000,
        }
    }

    fn synthetic_a3() -> Vec<u8> {
        encode_rts(&RtsPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            flags: RTS_FLAG_NONE,
            commands: vec![
                RtsCommand::Version(1),
                RtsCommand::ReceiveWindowSize(65536),
            ],
        })
    }

    fn synthetic_c2() -> Vec<u8> {
        encode_rts(&RtsPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            flags: RTS_FLAG_NONE,
            commands: vec![
                RtsCommand::Version(1),
                RtsCommand::ReceiveWindowSize(65536),
                RtsCommand::ConnectionTimeout(120_000),
            ],
        })
    }

    #[test]
    fn connect_reads_a3_then_c2() {
        let mut out_stream_bytes = Vec::new();
        out_stream_bytes.extend_from_slice(&synthetic_a3());
        out_stream_bytes.extend_from_slice(&synthetic_c2());

        let inbound = FakeChannel::new(Vec::new());
        let outbound = FakeChannel::new(out_stream_bytes);

        let tunnel = RpchTunnel::connect(inbound, outbound, test_config()).unwrap();
        assert_eq!(tunnel.state().stage(), HandshakeStage::Ready);
    }

    #[test]
    fn connect_writes_a1_and_b1_on_respective_streams() {
        let mut out_stream_bytes = Vec::new();
        out_stream_bytes.extend_from_slice(&synthetic_a3());
        out_stream_bytes.extend_from_slice(&synthetic_c2());
        let inbound = FakeChannel::new(Vec::new());
        let outbound = FakeChannel::new(out_stream_bytes);

        let tunnel = RpchTunnel::connect(inbound, outbound, test_config()).unwrap();
        // First byte of IN write buffer should be an RTS PDU
        // (CONN/B1) with ptype=0x14.
        {
            let g = tunnel.inbound.lock().unwrap();
            assert_eq!(g.write_buf[2], crate::pdu::RTS_PTYPE);
        }
        // First byte of OUT write buffer should be an RTS PDU
        // (CONN/A1) with ptype=0x14.
        assert_eq!(tunnel.outbound.write_buf[2], crate::pdu::RTS_PTYPE);
    }

    #[test]
    fn connect_fails_on_premature_eof() {
        let inbound = FakeChannel::new(Vec::new());
        let outbound = FakeChannel::new(Vec::new());
        let err = RpchTunnel::connect(inbound, outbound, test_config()).unwrap_err();
        assert!(matches!(err, TunnelIoError::UnexpectedEof { .. }));
    }

    #[test]
    fn recv_pdu_returns_data_pdu_and_filters_rts() {
        // Build an OUT stream containing: A3, C2, a FlowControlAck
        // RTS, and finally a RESPONSE PDU.
        let ack = encode_rts(&RtsPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            flags: crate::pdu::RTS_FLAG_OTHER_CMD,
            commands: vec![
                RtsCommand::Destination(2),
                RtsCommand::FlowControlAck {
                    bytes_received: 4096,
                    available_window: 65536,
                    channel_cookie: RpcUuid::NIL,
                },
            ],
        });

        let resp = crate::pdu::ResponsePdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            auth: None,
        };
        let mut resp_bytes = vec![0u8; resp.size()];
        let mut w = WriteCursor::new(&mut resp_bytes);
        resp.encode(&mut w).unwrap();

        let mut out_stream_bytes = Vec::new();
        out_stream_bytes.extend_from_slice(&synthetic_a3());
        out_stream_bytes.extend_from_slice(&synthetic_c2());
        out_stream_bytes.extend_from_slice(&ack);
        out_stream_bytes.extend_from_slice(&resp_bytes);

        let inbound = FakeChannel::new(Vec::new());
        let outbound = FakeChannel::new(out_stream_bytes);

        let mut tunnel = RpchTunnel::connect(inbound, outbound, test_config()).unwrap();
        let got = tunnel.recv_pdu().unwrap().unwrap();
        assert_eq!(got, resp_bytes);
    }

    #[test]
    fn recv_pdu_returns_none_on_clean_eof() {
        let mut out = Vec::new();
        out.extend_from_slice(&synthetic_a3());
        out.extend_from_slice(&synthetic_c2());
        let inbound = FakeChannel::new(Vec::new());
        let outbound = FakeChannel::new(out);
        let mut tunnel = RpchTunnel::connect(inbound, outbound, test_config()).unwrap();
        assert!(tunnel.recv_pdu().unwrap().is_none());
    }

    #[test]
    fn send_pdu_writes_verbatim_to_in_stream() {
        let mut out = Vec::new();
        out.extend_from_slice(&synthetic_a3());
        out.extend_from_slice(&synthetic_c2());
        let inbound = FakeChannel::new(Vec::new());
        let outbound = FakeChannel::new(out);
        let mut tunnel = RpchTunnel::connect(inbound, outbound, test_config()).unwrap();

        let req = RequestPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 99,
            alloc_hint: 0,
            context_id: 0,
            opnum: 0,
            object: None,
            stub_data: vec![0xAB; 8],
            auth: None,
        };
        let mut req_bytes = vec![0u8; req.size()];
        let mut w = WriteCursor::new(&mut req_bytes);
        req.encode(&mut w).unwrap();

        tunnel.send_pdu(&req_bytes).unwrap();

        // Last bytes written to IN stream should be exactly req_bytes,
        // appended after the CONN/B1 written during connect().
        {
            let g = tunnel.inbound.lock().unwrap();
            assert!(g.write_buf.ends_with(&req_bytes));
        }
    }

    // ---- keepalive ----------------------------------------------------

    #[test]
    fn build_keepalive_ping_pdu_has_ping_flag() {
        let bytes = build_keepalive_ping_pdu();
        // Common header PTYPE is at offset 2.
        assert_eq!(bytes[2], crate::pdu::RTS_PTYPE);
        // flags lives at offset 16..18 in an RTS PDU.
        let flags = u16::from_le_bytes([bytes[16], bytes[17]]);
        assert_eq!(flags & crate::pdu::RTS_FLAG_PING, crate::pdu::RTS_FLAG_PING);
        // NumberOfCommands = 1 (one Empty command).
        let n = u16::from_le_bytes([bytes[18], bytes[19]]);
        assert_eq!(n, 1);
    }

    #[test]
    fn send_ping_appends_ping_pdu_to_inbound() {
        let mut out = Vec::new();
        out.extend_from_slice(&synthetic_a3());
        out.extend_from_slice(&synthetic_c2());
        let inbound = FakeChannel::new(Vec::new());
        let outbound = FakeChannel::new(out);
        let mut tunnel = RpchTunnel::connect(inbound, outbound, test_config()).unwrap();

        let len_before = tunnel.inbound.lock().unwrap().write_buf.len();
        tunnel.send_ping().unwrap();
        let after = tunnel.inbound.lock().unwrap().write_buf.clone();
        assert!(after.len() > len_before);
        // Last PDU emitted should be a Ping RTS.
        let ping_start = len_before;
        assert_eq!(after[ping_start + 2], crate::pdu::RTS_PTYPE);
        let flags =
            u16::from_le_bytes([after[ping_start + 16], after[ping_start + 17]]);
        assert_eq!(flags & crate::pdu::RTS_FLAG_PING, crate::pdu::RTS_FLAG_PING);
    }

    #[test]
    fn spawn_keepalive_thread_fires_pings_and_stops_on_drop() {
        use std::time::{Duration, Instant};

        let mut out = Vec::new();
        out.extend_from_slice(&synthetic_a3());
        out.extend_from_slice(&synthetic_c2());
        let inbound = FakeChannel::new(Vec::new());
        let outbound = FakeChannel::new(out);
        let tunnel = RpchTunnel::connect(inbound, outbound, test_config()).unwrap();

        let len_after_conn_b1 = tunnel.inbound.lock().unwrap().write_buf.len();
        let handle = tunnel.inbound_handle();
        // Fire every 50 ms; worker sleeps 100 ms max between ticks.
        let keepalive = spawn_keepalive_thread(handle, Duration::from_millis(50));

        // Wait for at least three pings (~ 150 ms + jitter).
        let deadline = Instant::now() + Duration::from_millis(2_000);
        loop {
            let extra = tunnel.inbound.lock().unwrap().write_buf.len() - len_after_conn_b1;
            // One Ping PDU is 24 bytes (16 header + 4 RTS head + 4 Empty cmd).
            if extra >= 24 * 3 {
                break;
            }
            if Instant::now() >= deadline {
                panic!("keepalive worker produced fewer pings than expected; extra = {extra}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        // Drop the handle — worker must exit within ~250 ms.
        let stop = Instant::now();
        drop(keepalive);
        assert!(
            stop.elapsed() < Duration::from_millis(500),
            "keepalive thread took too long to stop"
        );
    }

    #[test]
    fn recv_pdu_triggers_flow_ack_when_window_crossed() {
        // receive_window_size = 8, send a 6-byte RESPONSE PDU body.
        // Half-window threshold crossed on first recv.
        let small_cfg = RpchTunnelConfig {
            receive_window_size: 32,
            ..test_config()
        };
        let resp = crate::pdu::ResponsePdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![0xAA; 16],
            auth: None,
        };
        let mut resp_bytes = vec![0u8; resp.size()];
        let mut w = WriteCursor::new(&mut resp_bytes);
        resp.encode(&mut w).unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(&synthetic_a3());
        out.extend_from_slice(&synthetic_c2());
        out.extend_from_slice(&resp_bytes);

        let inbound = FakeChannel::new(Vec::new());
        let outbound = FakeChannel::new(out);
        let mut tunnel = RpchTunnel::connect(inbound, outbound, small_cfg).unwrap();
        let len_before = tunnel.inbound.lock().unwrap().write_buf.len();
        let _got = tunnel.recv_pdu().unwrap().unwrap();
        // After recv, IN stream must have received an additional
        // FlowControlAck RTS PDU beyond the initial CONN/B1.
        assert!(
            tunnel.inbound.lock().unwrap().write_buf.len() > len_before,
            "expected flow-control ack appended to IN stream"
        );
    }
}
