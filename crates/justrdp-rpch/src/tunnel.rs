#![forbid(unsafe_code)]

//! Sans-io state machine for an RPC-over-HTTP v2 **virtual
//! connection** (MS-RPCH §3.2.1).
//!
//! This module is transport-agnostic: it consumes and produces byte
//! sequences but never performs I/O. A blocking wrapper lives in
//! [`super::blocking`] for the common `std::net::TcpStream` case.
//!
//! # Handshake summary (MS-RPCH §3.2.1.5)
//!
//! 1. Client opens an OUT TCP connection, authenticates with NTLM,
//!    gets HTTP 200 on the `RPC_OUT_DATA` request.
//! 2. Client writes a **CONN/A1** RTS PDU to the OUT request body.
//! 3. Client opens an IN TCP connection, authenticates with NTLM,
//!    gets HTTP 200 on the `RPC_IN_DATA` request.
//! 4. Client writes a **CONN/B1** RTS PDU to the IN request body.
//! 5. Server sends **CONN/A3** and **CONN/C2** on the OUT response
//!    body. These land at the client; client reads them.
//! 6. (The B3 PDU referenced by older revisions of §3.2.1.5 is
//!    absorbed by the proxy on the server side; Windows-2012R2+
//!    gateways skip it.)
//! 7. Virtual connection is up. From now on:
//!     - Client writes DCE/RPC REQUEST + FlowControlAck RTS through
//!       the IN channel body.
//!     - Server writes DCE/RPC RESPONSE + CONN flow control RTS
//!       through the OUT channel body.
//!
//! # Limitations
//!
//! - **Channel recycling** (MS-RPCH §3.2.2.3.1) is not implemented:
//!   the IN channel can carry at most its advertised
//!   `Content-Length` bytes of PDU data before the client is
//!   expected to recycle. Set the IN-channel length high enough
//!   (1 GiB default) that this does not matter for one TsProxy
//!   session.
//! - **Ping** (§3.2.1.5.5) is detected and silently ignored. The
//!   client never initiates pings.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};

use crate::pdu::{conn_a1, conn_b1, CommonHeader, RtsCommand, RtsPdu, RTS_PTYPE};
use crate::pdu::uuid::RpcUuid;

// =============================================================================
// Configuration
// =============================================================================

/// Per-tunnel knobs. All defaults mirror the values Windows RPCRT4
/// sends when opening a TsProxy tunnel to a gateway (observed via
/// Wireshark captures and corroborated with MS-RPCH §2.2.3.5
/// recommended ranges).
#[derive(Debug, Clone)]
pub struct RpchTunnelConfig {
    /// Cookie that ties the IN and OUT channels of this virtual
    /// connection together. MUST be unique per tunnel.
    pub virtual_connection_cookie: RpcUuid,
    /// Identifies the OUT channel specifically. Echoed back by the
    /// server in CONN/A3.
    pub out_channel_cookie: RpcUuid,
    /// Identifies the IN channel specifically. Echoed back by the
    /// server in CONN/B3 (which is absorbed by the out-proxy on
    /// modern gateways).
    pub in_channel_cookie: RpcUuid,
    /// Client's association group ID — a GUID that spans multiple
    /// virtual connections sharing the same NT authentication.
    pub association_group_id: RpcUuid,
    /// Client's receive window advertised in CONN/A1 (bytes).
    /// 65536 is the default Windows value.
    pub receive_window_size: u32,
    /// How many bytes the IN channel may carry before the client
    /// must recycle it (CONN/B1 ChannelLifetime). 1 GiB default.
    pub channel_lifetime: u32,
    /// Client → server keepalive interval in milliseconds. Windows
    /// defaults to 5 minutes (300_000); set to 0 to disable.
    pub client_keepalive: u32,
}

impl Default for RpchTunnelConfig {
    fn default() -> Self {
        Self {
            virtual_connection_cookie: RpcUuid::NIL,
            out_channel_cookie: RpcUuid::NIL,
            in_channel_cookie: RpcUuid::NIL,
            association_group_id: RpcUuid::NIL,
            receive_window_size: 65_536,
            channel_lifetime: 0x4000_0000, // 1 GiB
            client_keepalive: 300_000,
        }
    }
}

// =============================================================================
// State machine
// =============================================================================

/// Progress of the CONN/A/B/C handshake as observed by the client.
///
/// Only three server-originated RTS PDUs land at the client during
/// handshake (MS-RPCH §3.2.1.5): **CONN/A3**, **CONN/B3** (often
/// absorbed by the proxy and never seen), and **CONN/C2**. We track
/// what has been observed so the caller knows when the virtual
/// connection is ready for DCE/RPC data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStage {
    /// OUT channel CONN/A1 pending — client has not yet written it.
    ConnA1Pending,
    /// CONN/A1 written. Waiting for CONN/A3 on OUT.
    AwaitingConnA3,
    /// Received CONN/A3. Waiting for CONN/C2 (and optionally B3).
    AwaitingConnC2,
    /// Virtual connection established; ready for DCE/RPC.
    Ready,
}

/// One action produced by [`RpchTunnelState::feed_out_pdu`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundAction {
    /// Handshake progressed; no app-visible data.
    HandshakeProgress,
    /// A server-originated DCE/RPC PDU (anything not RTS). Caller
    /// dispatches to its PDU reader.
    DataPdu(Vec<u8>),
    /// Server sent a `FlowControlAck` RTS. Value is the amount of
    /// data the server acknowledged having processed. Caller may
    /// emit additional PDUs now that its send window reopened.
    FlowControlAck {
        bytes_received: u32,
        available_window: u32,
    },
    /// Server sent a keepalive Ping; caller may optionally echo.
    Ping,
}

/// Pure state machine.
///
/// Feed each inbound PDU (read from the OUT channel response body)
/// to [`feed_out_pdu`]; react to the returned `OutboundAction` by
/// writing more bytes to the IN channel if necessary.
#[derive(Debug)]
pub struct RpchTunnelState {
    cfg: RpchTunnelConfig,
    stage: HandshakeStage,
    /// Cumulative bytes of DCE/RPC data received from the server.
    /// Used to decide when to emit a `FlowControlAck` RTS (§3.2.2.1).
    bytes_received: u64,
    /// Copy of the last `bytes_received` at which we sent an ACK.
    last_ack_bytes: u64,
}

impl RpchTunnelState {
    pub fn new(cfg: RpchTunnelConfig) -> Self {
        Self {
            cfg,
            stage: HandshakeStage::ConnA1Pending,
            bytes_received: 0,
            last_ack_bytes: 0,
        }
    }

    pub fn stage(&self) -> HandshakeStage {
        self.stage
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Build the CONN/A1 PDU bytes to send on the OUT channel.
    /// Advances the handshake from `ConnA1Pending` to
    /// `AwaitingConnA3`.
    pub fn build_conn_a1(&mut self) -> Vec<u8> {
        let pdu = conn_a1(
            self.cfg.virtual_connection_cookie,
            self.cfg.out_channel_cookie,
            self.cfg.receive_window_size,
        );
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).expect("CONN/A1 fits in its computed buffer");
        self.stage = HandshakeStage::AwaitingConnA3;
        buf
    }

    /// Build the CONN/B1 PDU bytes to send on the IN channel.
    pub fn build_conn_b1(&self) -> Vec<u8> {
        let pdu = conn_b1(
            self.cfg.virtual_connection_cookie,
            self.cfg.in_channel_cookie,
            self.cfg.channel_lifetime,
            self.cfg.client_keepalive,
            self.cfg.association_group_id,
        );
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).expect("CONN/B1 fits in its computed buffer");
        buf
    }

    /// Feed one inbound PDU (read from the OUT channel body) to the
    /// state machine.
    ///
    /// The PDU's PTYPE byte drives the dispatch:
    /// * RTS (0x14) → handshake progression / flow control / ping
    /// * anything else → data PDU returned verbatim to the caller
    pub fn feed_out_pdu(&mut self, pdu: &[u8]) -> Result<OutboundAction, RpchTunnelError> {
        if pdu.len() < 16 {
            return Err(RpchTunnelError::PduTooShort {
                got: pdu.len(),
                needed: 16,
            });
        }
        let ptype = pdu[2];
        if ptype != RTS_PTYPE {
            self.bytes_received = self.bytes_received.saturating_add(pdu.len() as u64);
            return Ok(OutboundAction::DataPdu(pdu.to_vec()));
        }

        let mut cursor = ReadCursor::new(pdu);
        let rts = RtsPdu::decode(&mut cursor).map_err(RpchTunnelError::DecodeRts)?;

        // First look for ping: RTS_FLAG_PING marks a keepalive.
        use crate::pdu::{RTS_FLAG_OTHER_CMD, RTS_FLAG_PING};
        if rts.flags & RTS_FLAG_PING != 0 {
            return Ok(OutboundAction::Ping);
        }

        // FlowControlAck RTS — let the caller know the window
        // re-opened. The command is not supposed to arrive during
        // handshake, but it is legal after CONN/C2.
        for cmd in &rts.commands {
            if let RtsCommand::FlowControlAck {
                bytes_received,
                available_window,
                ..
            } = cmd
            {
                return Ok(OutboundAction::FlowControlAck {
                    bytes_received: *bytes_received,
                    available_window: *available_window,
                });
            }
        }

        // Handshake progression based on the stage we're in.
        match self.stage {
            HandshakeStage::AwaitingConnA3 => {
                // CONN/A3 carries ConnectionTimeout + Version. It
                // arrives with RTS_FLAG_NONE.
                self.stage = HandshakeStage::AwaitingConnC2;
            }
            HandshakeStage::AwaitingConnC2 => {
                // CONN/C2 carries ReceiveWindowSize + Version +
                // ConnectionTimeout. Windows 2008 R2 may also send
                // CONN/B3 here; either way we consider the tunnel
                // ready once we see any further RTS without
                // RECYCLE_CHANNEL/OTHER_CMD flags.
                if rts.flags & RTS_FLAG_OTHER_CMD == 0 {
                    self.stage = HandshakeStage::Ready;
                }
            }
            HandshakeStage::ConnA1Pending => {
                // We haven't even sent A1 yet — anything from the
                // server is a protocol violation.
                return Err(RpchTunnelError::UnexpectedRts(
                    "RTS received before CONN/A1 sent",
                ));
            }
            HandshakeStage::Ready => {
                // Post-handshake RTS (other than FlowControlAck /
                // Ping, already handled above). Silently ignore
                // unknown control traffic — the gateway occasionally
                // sends ConnectionTimeout refreshes.
            }
        }
        Ok(OutboundAction::HandshakeProgress)
    }

    /// Return `Some(flow_ack_pdu)` if the cumulative unacknowledged
    /// data has crossed half of the receive window — the standard
    /// trigger defined by MS-RPCH §3.2.2.1. The byte count is
    /// tracked internally by [`feed_out_pdu`]; callers invoke this
    /// after handling a `DataPdu` to check whether it is time to
    /// send a flow-control ack.
    pub fn flow_ack_if_due(&mut self) -> Option<Vec<u8>> {
        let window = self.cfg.receive_window_size as u64;
        if window == 0 {
            return None;
        }
        let threshold = window / 2;
        if self.bytes_received.saturating_sub(self.last_ack_bytes) < threshold {
            return None;
        }
        self.last_ack_bytes = self.bytes_received;
        let ack = RtsPdu {
            pfc_flags: crate::pdu::common::PFC_FIRST_FRAG | crate::pdu::common::PFC_LAST_FRAG,
            flags: crate::pdu::RTS_FLAG_OTHER_CMD,
            commands: alloc::vec![
                RtsCommand::Destination(2), // FDServer
                RtsCommand::FlowControlAck {
                    bytes_received: self.bytes_received as u32,
                    available_window: self.cfg.receive_window_size,
                    channel_cookie: self.cfg.out_channel_cookie,
                },
            ],
        };
        let mut buf = alloc::vec![0u8; ack.size()];
        let mut w = WriteCursor::new(&mut buf);
        ack.encode(&mut w).expect("FlowControlAck fits");
        Some(buf)
    }

    /// Accessor used by the blocking adapter to peek at the
    /// configured window.
    pub fn receive_window_size(&self) -> u32 {
        self.cfg.receive_window_size
    }
}

// =============================================================================
// Error type
// =============================================================================

/// Errors raised by the tunnel state machine.
#[derive(Debug, Clone)]
pub enum RpchTunnelError {
    PduTooShort { got: usize, needed: usize },
    DecodeRts(justrdp_core::DecodeError),
    UnexpectedRts(&'static str),
    /// A non-RTS DCE/RPC PDU arrived before the handshake reached
    /// `Ready`. The server is violating the CONN flow from MS-RPCH
    /// §3.2.1.5.
    UnexpectedDataPdu,
}

impl core::fmt::Display for RpchTunnelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PduTooShort { got, needed } => {
                write!(f, "RPCH tunnel: PDU shorter than {needed} bytes ({got})")
            }
            Self::DecodeRts(e) => write!(f, "RPCH tunnel: failed to decode RTS PDU: {e}"),
            Self::UnexpectedRts(msg) => write!(f, "RPCH tunnel: {msg}"),
            Self::UnexpectedDataPdu => f.write_str(
                "RPCH tunnel: data PDU received before handshake completed",
            ),
        }
    }
}

impl core::error::Error for RpchTunnelError {}

// =============================================================================
// PDU framing helper (shared between sans-io and blocking paths)
// =============================================================================

/// Peek at the 16-byte common header of a buffer and return the
/// declared `frag_length`. Used by the blocking adapter to know how
/// many bytes to read to complete a single PDU.
///
/// Returns `Ok(None)` if the buffer is shorter than 16 bytes,
/// `Ok(Some(len))` otherwise, or `Err` if the header is clearly not
/// an MS-RPCE PDU (wrong rpc_vers or DREP).
pub fn peek_frag_length(buf: &[u8]) -> Result<Option<u16>, justrdp_core::DecodeError> {
    if buf.len() < 16 {
        return Ok(None);
    }
    let mut c = ReadCursor::new(buf);
    let (_hdr, frag, _auth) = CommonHeader::decode(&mut c)?;
    Ok(Some(frag))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{RESPONSE_PTYPE, ResponsePdu};
    use alloc::vec;

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

    #[test]
    fn initial_stage_is_conn_a1_pending() {
        let s = RpchTunnelState::new(test_config());
        assert_eq!(s.stage(), HandshakeStage::ConnA1Pending);
    }

    #[test]
    fn build_conn_a1_advances_stage() {
        let mut s = RpchTunnelState::new(test_config());
        let bytes = s.build_conn_a1();
        assert_eq!(bytes[2], RTS_PTYPE, "first RTS byte is PTYPE 0x14");
        assert_eq!(s.stage(), HandshakeStage::AwaitingConnA3);
    }

    #[test]
    fn build_conn_b1_does_not_change_stage() {
        let mut s = RpchTunnelState::new(test_config());
        let _ = s.build_conn_a1();
        assert_eq!(s.stage(), HandshakeStage::AwaitingConnA3);
        let _ = s.build_conn_b1();
        assert_eq!(s.stage(), HandshakeStage::AwaitingConnA3);
    }

    /// Build a synthetic CONN/A3 response (server-originated): an
    /// RTS PDU with Version + ReceiveWindowSize, no special flags.
    fn conn_a3_bytes() -> Vec<u8> {
        let pdu = RtsPdu {
            pfc_flags: crate::pdu::PFC_FIRST_FRAG | crate::pdu::PFC_LAST_FRAG,
            flags: crate::pdu::RTS_FLAG_NONE,
            commands: vec![
                RtsCommand::Version(1),
                RtsCommand::ReceiveWindowSize(65536),
            ],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        buf
    }

    /// Build a synthetic CONN/C2 response.
    fn conn_c2_bytes() -> Vec<u8> {
        let pdu = RtsPdu {
            pfc_flags: crate::pdu::PFC_FIRST_FRAG | crate::pdu::PFC_LAST_FRAG,
            flags: crate::pdu::RTS_FLAG_NONE,
            commands: vec![
                RtsCommand::Version(1),
                RtsCommand::ReceiveWindowSize(65536),
                RtsCommand::ConnectionTimeout(120_000),
            ],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        buf
    }

    #[test]
    fn handshake_completes_on_a3_then_c2() {
        let mut s = RpchTunnelState::new(test_config());
        let _ = s.build_conn_a1();
        let _ = s.build_conn_b1();

        let act = s.feed_out_pdu(&conn_a3_bytes()).unwrap();
        assert_eq!(act, OutboundAction::HandshakeProgress);
        assert_eq!(s.stage(), HandshakeStage::AwaitingConnC2);

        let act = s.feed_out_pdu(&conn_c2_bytes()).unwrap();
        assert_eq!(act, OutboundAction::HandshakeProgress);
        assert_eq!(s.stage(), HandshakeStage::Ready);
    }

    #[test]
    fn rts_before_a1_is_error() {
        let mut s = RpchTunnelState::new(test_config());
        let act = s.feed_out_pdu(&conn_a3_bytes());
        assert!(act.is_err());
    }

    #[test]
    fn data_pdu_routed_through() {
        let mut s = RpchTunnelState::new(test_config());
        // Fast-forward past handshake.
        let _ = s.build_conn_a1();
        let _ = s.feed_out_pdu(&conn_a3_bytes()).unwrap();
        let _ = s.feed_out_pdu(&conn_c2_bytes()).unwrap();
        assert_eq!(s.stage(), HandshakeStage::Ready);

        // Build a trivial RESPONSE PDU (PTYPE=0x02).
        let resp = ResponsePdu {
            pfc_flags: crate::pdu::PFC_FIRST_FRAG | crate::pdu::PFC_LAST_FRAG,
            call_id: 1,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![0xDE, 0xAD],
            auth: None,
        };
        let mut buf = vec![0u8; resp.size()];
        let mut w = WriteCursor::new(&mut buf);
        resp.encode(&mut w).unwrap();
        assert_eq!(buf[2], RESPONSE_PTYPE);

        let act = s.feed_out_pdu(&buf).unwrap();
        match act {
            OutboundAction::DataPdu(bytes) => assert_eq!(bytes, buf),
            other => panic!("expected DataPdu, got {other:?}"),
        }
        assert_eq!(s.bytes_received(), buf.len() as u64);
    }

    #[test]
    fn flow_control_ack_detected() {
        let mut s = RpchTunnelState::new(test_config());
        let _ = s.build_conn_a1();
        let _ = s.feed_out_pdu(&conn_a3_bytes()).unwrap();
        let _ = s.feed_out_pdu(&conn_c2_bytes()).unwrap();

        let fca = RtsPdu {
            pfc_flags: crate::pdu::PFC_FIRST_FRAG | crate::pdu::PFC_LAST_FRAG,
            flags: crate::pdu::RTS_FLAG_OTHER_CMD,
            commands: vec![
                RtsCommand::Destination(2),
                RtsCommand::FlowControlAck {
                    bytes_received: 4096,
                    available_window: 65536,
                    channel_cookie: s.cfg.out_channel_cookie,
                },
            ],
        };
        let mut buf = vec![0u8; fca.size()];
        let mut w = WriteCursor::new(&mut buf);
        fca.encode(&mut w).unwrap();

        let act = s.feed_out_pdu(&buf).unwrap();
        assert_eq!(
            act,
            OutboundAction::FlowControlAck {
                bytes_received: 4096,
                available_window: 65536,
            }
        );
    }

    #[test]
    fn ping_detected() {
        let mut s = RpchTunnelState::new(test_config());
        let _ = s.build_conn_a1();
        let _ = s.feed_out_pdu(&conn_a3_bytes()).unwrap();
        let _ = s.feed_out_pdu(&conn_c2_bytes()).unwrap();

        let ping = RtsPdu {
            pfc_flags: crate::pdu::PFC_FIRST_FRAG | crate::pdu::PFC_LAST_FRAG,
            flags: crate::pdu::RTS_FLAG_PING,
            commands: vec![RtsCommand::Empty],
        };
        let mut buf = vec![0u8; ping.size()];
        let mut w = WriteCursor::new(&mut buf);
        ping.encode(&mut w).unwrap();

        let act = s.feed_out_pdu(&buf).unwrap();
        assert_eq!(act, OutboundAction::Ping);
    }

    #[test]
    fn pdu_too_short_errors() {
        let mut s = RpchTunnelState::new(test_config());
        let act = s.feed_out_pdu(&[0, 0, 0]);
        assert!(matches!(act, Err(RpchTunnelError::PduTooShort { .. })));
    }

    #[test]
    fn flow_ack_if_due_emits_ack_at_half_window() {
        let mut s = RpchTunnelState::new(RpchTunnelConfig {
            receive_window_size: 8,
            ..test_config()
        });
        // Simulate having received 4 bytes of data.
        s.bytes_received = 4;
        let ack = s.flow_ack_if_due();
        assert!(ack.is_some(), "half window crossed → must emit ack");
        // Second call with nothing new — no ack.
        let ack2 = s.flow_ack_if_due();
        assert!(ack2.is_none());
    }

    #[test]
    fn flow_ack_if_due_no_ack_below_half_window() {
        let mut s = RpchTunnelState::new(RpchTunnelConfig {
            receive_window_size: 1000,
            ..test_config()
        });
        s.bytes_received = 100;
        assert!(s.flow_ack_if_due().is_none());
    }

    #[test]
    fn peek_frag_length_returns_none_for_short_buf() {
        assert_eq!(peek_frag_length(&[0; 10]).unwrap(), None);
    }

    #[test]
    fn peek_frag_length_parses_common_header() {
        // Build a small REQUEST PDU and peek its frag_length.
        let req = crate::pdu::RequestPdu {
            pfc_flags: crate::pdu::PFC_FIRST_FRAG | crate::pdu::PFC_LAST_FRAG,
            call_id: 1,
            alloc_hint: 0,
            context_id: 0,
            opnum: 0,
            object: None,
            stub_data: vec![0; 8],
            auth: None,
        };
        let mut buf = vec![0u8; req.size()];
        let mut w = WriteCursor::new(&mut buf);
        req.encode(&mut w).unwrap();

        assert_eq!(peek_frag_length(&buf).unwrap(), Some(req.size() as u16));
    }

    #[test]
    fn config_defaults_are_spec_reasonable() {
        let d = RpchTunnelConfig::default();
        assert_eq!(d.receive_window_size, 65_536);
        assert_eq!(d.channel_lifetime, 0x4000_0000);
        assert_eq!(d.client_keepalive, 300_000);
    }
}
