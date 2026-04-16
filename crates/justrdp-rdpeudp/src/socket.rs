#![forbid(unsafe_code)]

//! Blocking UDP socket adapter for MS-RDPEUDP.
//!
//! [`RdpeudpSocket`] wraps a `std::net::UdpSocket` and an
//! [`RdpeudpSession`] to provide a simple blocking `send` / `recv`
//! API for RDP-UDP data transfer. The handshake is driven by
//! [`RdpeudpSocket::connect`] with automatic SYN retransmission
//! (up to `max_syn_retries` attempts with exponential backoff).
//!
//! **Not in scope** (future tranches): congestion control, FEC
//! encoding/decoding, DTLS, and the full retransmission state
//! machine for data packets. This module is sufficient to prove the
//! PDU + session stack works end-to-end over real sockets.

extern crate std;
extern crate alloc;

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use alloc::vec;
use alloc::vec::Vec;

use crate::session::{RdpeudpConfig, RdpeudpError, RdpeudpSession, ReceiveAction};
use crate::v1::{
    RdpUdpFecHeader, SourcePayloadHeader, RDPUDP_FLAG_DATA,
};

use justrdp_core::{Decode, ReadCursor};

// =============================================================================
// Error
// =============================================================================

/// Errors produced by [`RdpeudpSocket`].
#[derive(Debug)]
pub enum SocketError {
    Io(io::Error),
    Session(RdpeudpError),
    /// The handshake did not complete within the allowed number of
    /// retries.
    HandshakeTimeout,
    /// Received datagram was too short to contain even an
    /// `RDPUDP_FEC_HEADER`.
    ShortDatagram,
}

impl core::fmt::Display for SocketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "rdpeudp socket io: {e}"),
            Self::Session(e) => write!(f, "rdpeudp session: {e:?}"),
            Self::HandshakeTimeout => write!(f, "rdpeudp handshake timed out"),
            Self::ShortDatagram => write!(f, "rdpeudp received short datagram"),
        }
    }
}

impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SocketError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<RdpeudpError> for SocketError {
    fn from(e: RdpeudpError) -> Self {
        Self::Session(e)
    }
}

// =============================================================================
// RdpeudpSocket
// =============================================================================

/// Blocking RDP-UDP transport over a `std::net::UdpSocket`.
pub struct RdpeudpSocket {
    socket: UdpSocket,
    session: RdpeudpSession,
    peer: SocketAddr,
}

/// Maximum UDP datagram size we read. Slightly above the spec max MTU
/// (1232) to accommodate any unexpected padding.
const MAX_DATAGRAM_SIZE: usize = 2048;

/// Default number of SYN retransmission attempts.
pub const DEFAULT_MAX_SYN_RETRIES: u32 = 5;

/// Default initial SYN timeout (doubles on each retry).
pub const DEFAULT_SYN_TIMEOUT: Duration = Duration::from_millis(500);

impl RdpeudpSocket {
    /// Perform the 3-way handshake and return a connected socket
    /// ready for data transfer.
    ///
    /// `bind_addr` is the local address the UDP socket binds to —
    /// use `"0.0.0.0:0"` for an OS-assigned ephemeral port. `peer`
    /// is the remote server's address.
    pub fn connect(
        bind_addr: SocketAddr,
        peer: SocketAddr,
        config: RdpeudpConfig,
    ) -> Result<Self, SocketError> {
        Self::connect_with_retries(
            bind_addr,
            peer,
            config,
            DEFAULT_MAX_SYN_RETRIES,
            DEFAULT_SYN_TIMEOUT,
        )
    }

    /// Like [`connect`](Self::connect) but with custom retry
    /// parameters.
    pub fn connect_with_retries(
        bind_addr: SocketAddr,
        peer: SocketAddr,
        config: RdpeudpConfig,
        max_retries: u32,
        initial_timeout: Duration,
    ) -> Result<Self, SocketError> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(peer)?;

        let mut session = RdpeudpSession::new(config);
        let mut syn_dgram = Vec::new();
        session.build_syn(&mut syn_dgram)?;

        // Handshake loop: send SYN, wait for SYN+ACK, retry on
        // timeout with exponential backoff.
        let mut timeout = initial_timeout;
        for attempt in 0..=max_retries {
            socket.send(&syn_dgram)?;
            socket.set_read_timeout(Some(timeout))?;

            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            match socket.recv(&mut buf) {
                Ok(n) => {
                    let mut ack_dgram = Vec::new();
                    match session.receive(&buf[..n], &mut ack_dgram) {
                        Ok(ReceiveAction::SendResponse) => {
                            socket.send(&ack_dgram)?;
                            // Clear the read timeout for data phase.
                            socket.set_read_timeout(None)?;
                            return Ok(Self {
                                socket,
                                session,
                                peer,
                            });
                        }
                        Ok(ReceiveAction::Nothing) => {
                            // Unexpected — SYN+ACK should produce an
                            // ACK response. Treat as a bad packet and
                            // retry.
                        }
                        Err(_) if attempt < max_retries => {
                            // Bad packet — retry.
                        }
                        Err(e) => return Err(SocketError::Session(e)),
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // Timeout — retry with doubled timeout.
                    if attempt == max_retries {
                        return Err(SocketError::HandshakeTimeout);
                    }
                    timeout = timeout.saturating_mul(2);
                }
                Err(e) => return Err(SocketError::Io(e)),
            }
        }
        Err(SocketError::HandshakeTimeout)
    }

    /// Send a data payload to the peer. Wraps `payload` in a Source
    /// Packet datagram (with piggybacked ACK vector) and sends it on
    /// the UDP socket.
    pub fn send_data(&mut self, payload: &[u8]) -> Result<u32, SocketError> {
        let mut dgram = Vec::new();
        let sn = self.session.build_data_packet(payload, &mut dgram)?;
        self.socket.send(&dgram)?;
        Ok(sn)
    }

    /// Block until a data packet arrives from the peer and copy its
    /// payload into `buf`. Returns the number of payload bytes
    /// written.
    ///
    /// Non-data datagrams (standalone ACKs, AckOfAcks) are consumed
    /// silently and the call blocks again until a data packet arrives
    /// or the socket times out / errors.
    pub fn recv_data(&mut self, buf: &mut [u8]) -> Result<usize, SocketError> {
        loop {
            let mut dgram = vec![0u8; MAX_DATAGRAM_SIZE];
            let n = self.socket.recv(&mut dgram)?;
            if n < 8 {
                return Err(SocketError::ShortDatagram);
            }

            // Feed the datagram to the session for ACK tracking.
            let mut resp = Vec::new();
            self.session.receive(&dgram[..n], &mut resp)?;
            if !resp.is_empty() {
                // The session produced a response (e.g. ACK). Send it.
                let _ = self.socket.send(&resp);
            }

            // Check if this datagram carried a Source Payload.
            let mut cur = ReadCursor::new(&dgram[..n]);
            let hdr = RdpUdpFecHeader::decode(&mut cur)
                .map_err(|e| SocketError::Session(RdpeudpError::Decode(e)))?;
            if hdr.u_flags & RDPUDP_FLAG_DATA != 0 {
                // Skip ACK vector if present.
                if hdr.u_flags & crate::v1::RDPUDP_FLAG_ACK != 0 {
                    let _ = crate::v1::AckVectorHeader::decode(&mut cur);
                }
                if hdr.u_flags & crate::v1::RDPUDP_FLAG_ACK_OF_ACKS != 0 {
                    let _ = crate::v1::AckOfAcksHeader::decode(&mut cur);
                }
                let _src = SourcePayloadHeader::decode(&mut cur)
                    .map_err(|e| SocketError::Session(RdpeudpError::Decode(e)))?;
                let remaining = cur.remaining();
                let payload = cur.read_slice(remaining, "payload")
                    .map_err(|e| SocketError::Session(RdpeudpError::Decode(e)))?;
                let copy_len = payload.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                return Ok(copy_len);
            }
            // Non-data datagram — loop and wait for the next one.
        }
    }

    /// Send a standalone ACK to the peer (e.g. when a delayed-ACK
    /// timer fires).
    pub fn send_ack(&mut self) -> Result<(), SocketError> {
        let mut dgram = Vec::new();
        self.session.build_ack(&mut dgram)?;
        self.socket.send(&dgram)?;
        Ok(())
    }

    /// Return a reference to the underlying [`RdpeudpSession`].
    pub fn session(&self) -> &RdpeudpSession {
        &self.session
    }

    /// Return the peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Return the local socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.socket.local_addr()
    }

    /// Set the read timeout on the underlying socket.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<(), io::Error> {
        self.socket.set_read_timeout(dur)
    }

    /// Return `true` if the session has completed the handshake.
    pub fn is_connected(&self) -> bool {
        self.session.is_connected()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::thread;

    fn loopback_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    fn test_config(isn: u32) -> RdpeudpConfig {
        use crate::v1::RDPUDP_PROTOCOL_VERSION_1;
        RdpeudpConfig {
            up_stream_mtu: 1200,
            down_stream_mtu: 1200,
            initial_sequence_number: isn,
            receive_window_size: 64,
            lossy: false,
            protocol_version: RDPUDP_PROTOCOL_VERSION_1,
            correlation_id: None,
            cookie_hash: None,
        }
    }

    /// Minimal mock server: binds UDP, runs the server-side handshake,
    /// then echoes one data packet back.
    fn run_echo_server(bind_addr: SocketAddr) -> SocketAddr {
        let socket = UdpSocket::bind(bind_addr).unwrap();
        let local = socket.local_addr().unwrap();

        thread::spawn(move || {
            let mut session = RdpeudpSession::new_server(test_config(0xBBBB_0001));
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

            // 1. Receive SYN → send SYN+ACK.
            let (n, client_addr) = socket.recv_from(&mut buf).unwrap();
            let mut syn_ack = Vec::new();
            session.receive(&buf[..n], &mut syn_ack).unwrap();
            socket.send_to(&syn_ack, client_addr).unwrap();

            // 2. Receive ACK → connected.
            let (n, _) = socket.recv_from(&mut buf).unwrap();
            let mut resp = Vec::new();
            session.receive(&buf[..n], &mut resp).unwrap();
            assert!(session.is_connected());

            // 3. Receive one data packet → echo it back.
            let (n, _) = socket.recv_from(&mut buf).unwrap();
            session.receive(&buf[..n], &mut resp).unwrap();

            // Extract payload from the received datagram for echo.
            let mut cur = ReadCursor::new(&buf[..n]);
            let hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
            if hdr.u_flags & RDPUDP_FLAG_DATA != 0 {
                if hdr.u_flags & crate::v1::RDPUDP_FLAG_ACK != 0 {
                    let _ = crate::v1::AckVectorHeader::decode(&mut cur);
                }
                let _src = SourcePayloadHeader::decode(&mut cur).unwrap();
                let remaining = cur.remaining();
                let payload = cur.read_slice(remaining, "payload").unwrap();

                // Echo the payload back as a server data packet.
                let mut echo_dgram = Vec::new();
                session.build_data_packet(payload, &mut echo_dgram).unwrap();
                socket.send_to(&echo_dgram, client_addr).unwrap();
            }
        });

        local
    }

    #[test]
    fn end_to_end_handshake_and_echo_over_loopback() {
        let server_addr = run_echo_server(loopback_addr());

        let mut client = RdpeudpSocket::connect_with_retries(
            loopback_addr(),
            server_addr,
            test_config(0xAAAA_0001),
            3,
            Duration::from_millis(200),
        )
        .unwrap();

        assert!(client.is_connected());

        // Send "hello" and expect the echo server to return it.
        client.send_data(b"hello").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 64];
        let n = client.recv_data(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn connect_times_out_when_no_server() {
        // Point at a port that nobody is listening on.
        let fake_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        let result = RdpeudpSocket::connect_with_retries(
            loopback_addr(),
            fake_addr,
            test_config(1),
            1,
            Duration::from_millis(50),
        );
        match result {
            Err(SocketError::HandshakeTimeout) | Err(SocketError::Io(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("expected connection to fail"),
        }
    }
}
