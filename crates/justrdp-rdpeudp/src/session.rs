#![forbid(unsafe_code)]

//! Sans-io RDP-UDP session state machine.
//!
//! Drives the 3-way handshake (SYN → SYN+ACK → ACK) and tracks the
//! negotiated parameters (MTU, protocol version, initial sequence
//! numbers). This module does **not** own sockets, timers, or
//! retransmit buffers — the caller is responsible for sending the
//! datagrams produced by [`RdpeudpSession`] and for implementing
//! retransmission logic (e.g. re-calling [`RdpeudpSession::build_syn`]
//! when a SYN+ACK is not received within the RTO window).
//!
//! ## Client-side flow
//!
//! 1. [`RdpeudpSession::new`] — creates a session in `Idle`.
//! 2. [`RdpeudpSession::build_syn`] — produces the SYN datagram,
//!    transitions to `SynSent`.
//! 3. [`RdpeudpSession::receive`] — parses the SYN+ACK, produces the
//!    final ACK datagram, transitions to `Connected`.
//!
//! ## Server-side flow (for testing / future `justrdp-acceptor`)
//!
//! 1. [`RdpeudpSession::new_server`] — creates a server session in
//!    `Listening`.
//! 2. [`RdpeudpSession::receive`] — parses the client SYN, produces
//!    SYN+ACK, transitions to `SynReceived`.
//! 3. [`RdpeudpSession::receive`] — parses the client ACK, transitions
//!    to `Connected`.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{
    Decode, Encode, ReadCursor, WriteCursor,
};

use crate::v1::{
    AckVectorElement, AckVectorHeader, CorrelationIdPayload, RdpUdpFecHeader,
    SourcePayloadHeader, SynDataExPayload, SynDataPayload, VectorElementState,
    RDPUDP_FLAG_ACK, RDPUDP_FLAG_ACK_OF_ACKS, RDPUDP_FLAG_CORRELATION_ID,
    RDPUDP_FLAG_DATA, RDPUDP_FLAG_SYN, RDPUDP_FLAG_SYNEX, RDPUDP_FLAG_SYNLOSSY,
    RDPUDP_INITIAL_SOURCE_ACK, RDPUDP_MAX_ACK_VECTOR_SIZE, RDPUDP_PROTOCOL_VERSION_1,
    RDPUDP_VERSION_INFO_VALID, AckOfAcksHeader,
};

// =============================================================================
// Configuration
// =============================================================================

/// Connection parameters for an [`RdpeudpSession`].
#[derive(Debug, Clone)]
pub struct RdpeudpConfig {
    /// Maximum datagram size this endpoint will send.
    pub up_stream_mtu: u16,
    /// Maximum datagram size this endpoint can accept.
    pub down_stream_mtu: u16,
    /// Starting sequence number. MUST be CSPRNG-generated in
    /// production; tests may use a fixed value.
    pub initial_sequence_number: u32,
    /// Receive window size advertised in every datagram header.
    pub receive_window_size: u16,
    /// Request best-effort (lossy) mode — sets `RDPUDP_FLAG_SYNLOSSY`
    /// on SYN/SYN+ACK.
    pub lossy: bool,
    /// Protocol version to advertise in [`SynDataExPayload`].
    /// Set to `0` to omit the SYNEX payload entirely (implies v1).
    pub protocol_version: u16,
    /// Optional 16-byte correlation identifier (client SYN only).
    pub correlation_id: Option<[u8; 16]>,
    /// Optional SHA-256 cookie hash (v3 client SYN only).
    pub cookie_hash: Option<[u8; 32]>,
}

impl RdpeudpConfig {
    pub fn new(initial_sequence_number: u32) -> Self {
        Self {
            up_stream_mtu: 1200,
            down_stream_mtu: 1200,
            initial_sequence_number,
            receive_window_size: 64,
            lossy: false,
            protocol_version: RDPUDP_PROTOCOL_VERSION_1,
            correlation_id: None,
            cookie_hash: None,
        }
    }
}

// =============================================================================
// State
// =============================================================================

/// Connection state of an [`RdpeudpSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpeudpState {
    /// Initial state. Call [`RdpeudpSession::build_syn`] (client) or
    /// wait for a SYN via [`RdpeudpSession::receive`] (server).
    Idle,
    /// Server-side: waiting for a client SYN.
    Listening,
    /// Client has sent SYN, waiting for SYN+ACK.
    SynSent,
    /// Server has received SYN and sent SYN+ACK, waiting for ACK.
    SynReceived,
    /// Handshake complete. Data transfer may begin.
    Connected,
    /// Session terminated.
    Closed,
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug)]
pub enum RdpeudpError {
    /// Method called in a state that does not accept it.
    InvalidState(&'static str),
    /// Received datagram could not be decoded.
    Decode(justrdp_core::DecodeError),
    /// Encoding a response datagram failed (buffer too small, etc.).
    Encode(justrdp_core::EncodeError),
    /// The peer's SYN/SYN+ACK contained structurally valid but
    /// semantically unacceptable parameters (e.g. mismatched flags).
    Protocol(&'static str),
}

impl From<justrdp_core::DecodeError> for RdpeudpError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<justrdp_core::EncodeError> for RdpeudpError {
    fn from(e: justrdp_core::EncodeError) -> Self {
        Self::Encode(e)
    }
}

// =============================================================================
// Result of a receive() call
// =============================================================================

/// What the caller should do after [`RdpeudpSession::receive`]
/// returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveAction {
    /// A response datagram was written to the output buffer. The
    /// caller MUST send it on the wire.
    SendResponse,
    /// No output was produced. The state machine absorbed the
    /// datagram silently (e.g. duplicate ACK, ignored flag).
    Nothing,
}

// =============================================================================
// RdpeudpSession
// =============================================================================

/// Sans-io RDP-UDP handshake + data-path state machine.
pub struct RdpeudpSession {
    config: RdpeudpConfig,
    state: RdpeudpState,
    /// True for the party that called `new_server`.
    #[allow(dead_code)]
    is_server: bool,
    /// Remote peer's initial sequence number, captured from SYN or
    /// SYN+ACK. `None` until a SYN-bearing datagram is received.
    remote_initial_sn: Option<u32>,
    /// Negotiated MTU: `min(our_up, their_down, our_down, their_up)`.
    negotiated_mtu: Option<u16>,
    /// Negotiated protocol version (from SYNEX exchange). `None` if
    /// neither side advertised a version.
    negotiated_version: Option<u16>,
    /// True if the connection is lossy (best-effort) mode.
    negotiated_lossy: bool,

    // ── Sequence number tracking (active after Connected) ──

    /// Next Coded Packet sequence number to assign when sending a
    /// Source Packet. Initialized to `initial_sequence_number + 1`
    /// after handshake.
    next_send_coded_sn: u32,
    /// Next Source Packet sequence number. Equals `next_send_coded_sn`
    /// when no FEC is used.
    next_send_source_sn: u32,
    /// Highest Source Packet sequence number received from the peer.
    /// Used as `snSourceAck` in outgoing packets.
    highest_received_sn: u32,

    // ── ACK vector state ──

    /// Ring buffer tracking the reception state of recent incoming
    /// sequence numbers. `recv_bitmap[sn - recv_base]` is `true` if
    /// the packet was received.
    recv_bitmap: Vec<bool>,
    /// The sequence number corresponding to `recv_bitmap[0]`.
    recv_base: u32,
    /// Base sequence number the peer has acknowledged via an
    /// AckOfAcks — we only need to report ACK vector entries for
    /// sequence numbers > this value.
    ack_of_acks_base: u32,
}

impl RdpeudpSession {
    /// Create a **client-side** session in `Idle`.
    pub fn new(config: RdpeudpConfig) -> Self {
        let isn = config.initial_sequence_number;
        Self {
            config,
            state: RdpeudpState::Idle,
            is_server: false,
            remote_initial_sn: None,
            negotiated_mtu: None,
            negotiated_version: None,
            negotiated_lossy: false,
            next_send_coded_sn: isn.wrapping_add(1),
            next_send_source_sn: isn.wrapping_add(1),
            highest_received_sn: 0,
            recv_bitmap: Vec::new(),
            recv_base: 0,
            ack_of_acks_base: 0,
        }
    }

    /// Create a **server-side** session in `Listening`.
    pub fn new_server(config: RdpeudpConfig) -> Self {
        let isn = config.initial_sequence_number;
        Self {
            config,
            state: RdpeudpState::Listening,
            is_server: true,
            remote_initial_sn: None,
            negotiated_mtu: None,
            negotiated_version: None,
            negotiated_lossy: false,
            next_send_coded_sn: isn.wrapping_add(1),
            next_send_source_sn: isn.wrapping_add(1),
            highest_received_sn: 0,
            recv_bitmap: Vec::new(),
            recv_base: 0,
            ack_of_acks_base: 0,
        }
    }

    pub fn state(&self) -> RdpeudpState {
        self.state
    }

    pub fn is_connected(&self) -> bool {
        self.state == RdpeudpState::Connected
    }

    pub fn remote_initial_sn(&self) -> Option<u32> {
        self.remote_initial_sn
    }

    pub fn negotiated_mtu(&self) -> Option<u16> {
        self.negotiated_mtu
    }

    pub fn negotiated_version(&self) -> Option<u16> {
        self.negotiated_version
    }

    pub fn negotiated_lossy(&self) -> bool {
        self.negotiated_lossy
    }

    // ─────────────── Client: build SYN ───────────────

    /// Produce the initial SYN datagram for the client and transition
    /// to [`RdpeudpState::SynSent`].
    ///
    /// `output` is cleared and filled with the complete datagram
    /// bytes ready to send on a UDP socket. The datagram is
    /// zero-padded to `min(up_mtu, down_mtu)` per §3.1.5.1.1 step 6.
    pub fn build_syn(&mut self, output: &mut Vec<u8>) -> Result<(), RdpeudpError> {
        if self.state != RdpeudpState::Idle {
            return Err(RdpeudpError::InvalidState(
                "build_syn: session is not Idle",
            ));
        }

        let mut flags: u16 = RDPUDP_FLAG_SYN;
        if self.config.lossy {
            flags |= RDPUDP_FLAG_SYNLOSSY;
        }
        if self.config.correlation_id.is_some() {
            flags |= RDPUDP_FLAG_CORRELATION_ID;
        }
        if self.config.protocol_version != 0 {
            flags |= RDPUDP_FLAG_SYNEX;
        }

        let header = RdpUdpFecHeader {
            sn_source_ack: RDPUDP_INITIAL_SOURCE_ACK,
            u_receive_window_size: self.config.receive_window_size,
            u_flags: flags,
        };
        let syn = SynDataPayload {
            sn_initial_sequence_number: self.config.initial_sequence_number,
            u_up_stream_mtu: self.config.up_stream_mtu,
            u_down_stream_mtu: self.config.down_stream_mtu,
        };

        let mut size = header.size() + syn.size();
        let corr = self.config.correlation_id.map(|id| CorrelationIdPayload {
            u_correlation_id: id,
        });
        if let Some(ref c) = corr {
            size += c.size();
        }
        let synex = if self.config.protocol_version != 0 {
            let payload = SynDataExPayload {
                u_syn_ex_flags: RDPUDP_VERSION_INFO_VALID,
                u_udp_ver: self.config.protocol_version,
                cookie_hash: self.config.cookie_hash,
            };
            size += payload.size();
            Some(payload)
        } else {
            None
        };

        // Zero-pad to min MTU.
        let target = core::cmp::min(self.config.up_stream_mtu, self.config.down_stream_mtu) as usize;
        let padded_size = core::cmp::max(size, target);

        output.clear();
        output.resize(padded_size, 0);
        let mut cur = WriteCursor::new(output);
        header.encode(&mut cur)?;
        syn.encode(&mut cur)?;
        if let Some(ref c) = corr {
            c.encode(&mut cur)?;
        }
        if let Some(ref s) = synex {
            s.encode(&mut cur)?;
        }
        // Remaining bytes are already zero-filled by resize.

        self.state = RdpeudpState::SynSent;
        Ok(())
    }

    // ─────────────── Receive datagram ───────────────

    /// Process a received datagram and optionally produce a response
    /// in `output`. Returns an action telling the caller whether to
    /// send the contents of `output`.
    pub fn receive(
        &mut self,
        datagram: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<ReceiveAction, RdpeudpError> {
        output.clear();
        let mut cur = ReadCursor::new(datagram);
        let header = RdpUdpFecHeader::decode(&mut cur)?;
        let flags = header.u_flags;

        match self.state {
            RdpeudpState::SynSent => {
                // Expecting SYN+ACK from the server.
                if flags & RDPUDP_FLAG_SYN == 0 || flags & RDPUDP_FLAG_ACK == 0 {
                    return Err(RdpeudpError::Protocol(
                        "expected SYN+ACK in SynSent state",
                    ));
                }
                self.process_syn_ack(&header, &mut cur, flags, output)
            }
            RdpeudpState::Listening => {
                // Server: expecting client SYN.
                if flags & RDPUDP_FLAG_SYN == 0 {
                    return Err(RdpeudpError::Protocol(
                        "expected SYN in Listening state",
                    ));
                }
                self.process_client_syn(&header, &mut cur, flags, output)
            }
            RdpeudpState::SynReceived => {
                // Server: expecting client ACK.
                if flags & RDPUDP_FLAG_ACK == 0 {
                    return Err(RdpeudpError::Protocol(
                        "expected ACK in SynReceived state",
                    ));
                }
                self.process_handshake_ack(&header, &mut cur)?;
                // Initialize data-path tracking from the client's ISN.
                if let Some(remote_isn) = self.remote_initial_sn {
                    self.highest_received_sn = remote_isn;
                    self.recv_base = remote_isn.wrapping_add(1);
                }
                self.state = RdpeudpState::Connected;
                Ok(ReceiveAction::Nothing)
            }
            RdpeudpState::Connected => {
                self.process_connected_datagram(&header, &mut cur, flags, output)
            }
            _ => Err(RdpeudpError::InvalidState(
                "receive called in Idle/Closed state",
            )),
        }
    }

    // ─────────────── Client: process SYN+ACK ───────────────

    fn process_syn_ack(
        &mut self,
        header: &RdpUdpFecHeader,
        cur: &mut ReadCursor<'_>,
        flags: u16,
        output: &mut Vec<u8>,
    ) -> Result<ReceiveAction, RdpeudpError> {
        // § SynDataPayload
        let syn_data = SynDataPayload::decode(cur)?;
        self.remote_initial_sn = Some(syn_data.sn_initial_sequence_number);

        // § AckVectorHeader (RDPUDP_FLAG_ACK is set)
        let _ack_vec = AckVectorHeader::decode(cur)?;

        // §3.1.5.1.1: CorrelationId comes before SynDataEx on SYN,
        // but §3.1.5.1.2 says the SYN+ACK does NOT carry a
        // CorrelationId — skip even if flag is set on the SYN+ACK.

        // § SynDataExPayload (optional)
        if flags & RDPUDP_FLAG_SYNEX != 0 {
            let synex = SynDataExPayload::decode_with_cookie(cur, false)?;
            if synex.u_syn_ex_flags & RDPUDP_VERSION_INFO_VALID != 0 {
                self.negotiated_version = Some(synex.u_udp_ver);
            }
        }

        // Negotiate MTU: min of all four values.
        self.negotiated_mtu = Some(
            self.config
                .up_stream_mtu
                .min(self.config.down_stream_mtu)
                .min(syn_data.u_up_stream_mtu)
                .min(syn_data.u_down_stream_mtu),
        );

        self.negotiated_lossy =
            self.config.lossy && (flags & RDPUDP_FLAG_SYNLOSSY != 0);

        // §3.1.5.1.2: The snSourceAck in SYN+ACK MUST equal our
        // initial sequence number.
        if header.sn_source_ack != self.config.initial_sequence_number {
            return Err(RdpeudpError::Protocol(
                "SYN+ACK snSourceAck does not match our initial sequence number",
            ));
        }

        // Initialize data-path tracking from the peer's ISN.
        let remote_isn = syn_data.sn_initial_sequence_number;
        self.highest_received_sn = remote_isn;
        self.recv_base = remote_isn.wrapping_add(1);

        // Build the handshake ACK datagram.
        self.build_handshake_ack(remote_isn, output)?;
        self.state = RdpeudpState::Connected;
        Ok(ReceiveAction::SendResponse)
    }

    // ─────────────── Server: process client SYN ───────────────

    fn process_client_syn(
        &mut self,
        _header: &RdpUdpFecHeader,
        cur: &mut ReadCursor<'_>,
        flags: u16,
        output: &mut Vec<u8>,
    ) -> Result<ReceiveAction, RdpeudpError> {
        let syn_data = SynDataPayload::decode(cur)?;
        self.remote_initial_sn = Some(syn_data.sn_initial_sequence_number);

        // Skip CorrelationId if present (we don't validate it here).
        if flags & RDPUDP_FLAG_CORRELATION_ID != 0 {
            let _corr = CorrelationIdPayload::decode(cur)?;
        }

        // Parse optional SYNEX.
        let mut client_version: Option<u16> = None;
        if flags & RDPUDP_FLAG_SYNEX != 0 {
            let synex = SynDataExPayload::decode_with_cookie(cur, false)?;
            if synex.u_syn_ex_flags & RDPUDP_VERSION_INFO_VALID != 0 {
                client_version = Some(synex.u_udp_ver);
            }
        }

        // Negotiate version: minimum of client and server.
        if let Some(cv) = client_version {
            if self.config.protocol_version != 0 {
                self.negotiated_version =
                    Some(core::cmp::min(cv, self.config.protocol_version));
            } else {
                self.negotiated_version = Some(cv);
            }
        }

        // Negotiate MTU.
        self.negotiated_mtu = Some(
            self.config
                .up_stream_mtu
                .min(self.config.down_stream_mtu)
                .min(syn_data.u_up_stream_mtu)
                .min(syn_data.u_down_stream_mtu),
        );

        self.negotiated_lossy =
            self.config.lossy && (flags & RDPUDP_FLAG_SYNLOSSY != 0);

        // Build SYN+ACK.
        self.build_syn_ack(syn_data.sn_initial_sequence_number, output)?;
        self.state = RdpeudpState::SynReceived;
        Ok(ReceiveAction::SendResponse)
    }

    // ─────────────── Server: process handshake ACK ───────────────

    fn process_handshake_ack(
        &mut self,
        header: &RdpUdpFecHeader,
        cur: &mut ReadCursor<'_>,
    ) -> Result<(), RdpeudpError> {
        // Verify snSourceAck matches our ISN.
        if header.sn_source_ack != self.config.initial_sequence_number {
            return Err(RdpeudpError::Protocol(
                "handshake ACK snSourceAck does not match server ISN",
            ));
        }
        // Consume the AckVectorHeader.
        let _ack = AckVectorHeader::decode(cur)?;
        Ok(())
    }

    // ─────────────── Datagram builders ───────────────

    fn build_handshake_ack(
        &self,
        remote_isn: u32,
        output: &mut Vec<u8>,
    ) -> Result<(), RdpeudpError> {
        let header = RdpUdpFecHeader {
            sn_source_ack: remote_isn,
            u_receive_window_size: self.config.receive_window_size,
            u_flags: RDPUDP_FLAG_ACK,
        };
        // Empty ACK vector: we haven't received any data packets yet.
        let ack_vec = AckVectorHeader::new(alloc::vec![
            AckVectorElement::new(VectorElementState::DatagramReceived, 1)
        ]);

        let size = header.size() + ack_vec.size();
        output.resize(size, 0);
        let mut cur = WriteCursor::new(output);
        header.encode(&mut cur)?;
        ack_vec.encode(&mut cur)?;
        Ok(())
    }

    fn build_syn_ack(
        &self,
        client_isn: u32,
        output: &mut Vec<u8>,
    ) -> Result<(), RdpeudpError> {
        let mut flags: u16 = RDPUDP_FLAG_SYN | RDPUDP_FLAG_ACK;
        if self.negotiated_lossy {
            flags |= RDPUDP_FLAG_SYNLOSSY;
        }
        if self.negotiated_version.is_some() {
            flags |= RDPUDP_FLAG_SYNEX;
        }

        let header = RdpUdpFecHeader {
            sn_source_ack: client_isn,
            u_receive_window_size: self.config.receive_window_size,
            u_flags: flags,
        };
        let syn = SynDataPayload {
            sn_initial_sequence_number: self.config.initial_sequence_number,
            u_up_stream_mtu: self.config.up_stream_mtu,
            u_down_stream_mtu: self.config.down_stream_mtu,
        };
        // SYN+ACK carries an (empty-ish) ACK vector per the flag.
        let ack_vec = AckVectorHeader::new(alloc::vec![
            AckVectorElement::new(VectorElementState::DatagramReceived, 1)
        ]);

        let synex = self.negotiated_version.map(|ver| SynDataExPayload {
            u_syn_ex_flags: RDPUDP_VERSION_INFO_VALID,
            u_udp_ver: ver,
            cookie_hash: None,
        });

        let mut size = header.size() + syn.size() + ack_vec.size();
        if let Some(ref s) = synex {
            size += s.size();
        }

        let target = core::cmp::min(self.config.up_stream_mtu, self.config.down_stream_mtu) as usize;
        let padded_size = core::cmp::max(size, target);
        output.resize(padded_size, 0);
        let mut cur = WriteCursor::new(output);
        header.encode(&mut cur)?;
        syn.encode(&mut cur)?;
        ack_vec.encode(&mut cur)?;
        if let Some(ref s) = synex {
            s.encode(&mut cur)?;
        }
        Ok(())
    }

    // ─────────────── Connected: data path ───────────────

    fn process_connected_datagram(
        &mut self,
        _header: &RdpUdpFecHeader,
        cur: &mut ReadCursor<'_>,
        flags: u16,
        _output: &mut Vec<u8>,
    ) -> Result<ReceiveAction, RdpeudpError> {
        // Process ACK vector if present — the peer is acknowledging
        // packets we sent. For now we just consume it; a future
        // tranche will feed it into the retransmit state.
        if flags & RDPUDP_FLAG_ACK != 0 {
            let _ack_vec = AckVectorHeader::decode(cur)?;
        }
        // Process AckOfAcks if present.
        if flags & RDPUDP_FLAG_ACK_OF_ACKS != 0 {
            let aoa = AckOfAcksHeader::decode(cur)?;
            self.advance_ack_of_acks(aoa.sn_reset_seq_num);
        }
        // Process data payload if present.
        if flags & RDPUDP_FLAG_DATA != 0 {
            let src_hdr = SourcePayloadHeader::decode(cur)?;
            let payload = cur.remaining();
            let data = cur.read_slice(payload, "SourcePayload")?;
            self.record_received(src_hdr.sn_source_start);
            // Update highest_received_sn.
            if sn_after(src_hdr.sn_source_start, self.highest_received_sn) {
                self.highest_received_sn = src_hdr.sn_source_start;
            }
            // TODO: deliver `data` to caller via a buffer or callback.
            let _ = data;
        }
        Ok(ReceiveAction::Nothing)
    }

    /// Record that we received a packet with the given source SN.
    fn record_received(&mut self, sn: u32) {
        if self.recv_bitmap.is_empty() {
            // First data packet: initialize the bitmap.
            self.recv_base = sn;
            self.recv_bitmap.push(true);
            return;
        }
        if sn == self.recv_base.wrapping_sub(1) || sn_before(sn, self.recv_base) {
            // Old packet — already acked. Ignore.
            return;
        }
        let offset = sn.wrapping_sub(self.recv_base) as usize;
        if offset >= self.recv_bitmap.len() {
            // Extend the bitmap up to this SN.
            self.recv_bitmap.resize(offset + 1, false);
        }
        self.recv_bitmap[offset] = true;
    }

    /// Advance the ack-of-acks base. The peer tells us it has
    /// received our ACK vector up to `sn`, so we can discard entries
    /// from `recv_bitmap` that are ≤ sn.
    fn advance_ack_of_acks(&mut self, sn: u32) {
        if self.recv_bitmap.is_empty() {
            self.ack_of_acks_base = sn;
            return;
        }
        if !sn_after(sn, self.recv_base) {
            return;
        }
        let discard = sn.wrapping_sub(self.recv_base) as usize;
        let discard = discard.min(self.recv_bitmap.len());
        self.recv_bitmap.drain(..discard);
        self.recv_base = self.recv_base.wrapping_add(discard as u32);
        self.ack_of_acks_base = sn;
    }

    // ─────────────── Public data-path API ───────────────

    /// Build a Source Packet datagram wrapping `payload`. The caller
    /// MUST send it on the wire. Returns the assigned source sequence
    /// number.
    pub fn build_data_packet(
        &mut self,
        payload: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<u32, RdpeudpError> {
        if self.state != RdpeudpState::Connected {
            return Err(RdpeudpError::InvalidState(
                "build_data_packet: not connected",
            ));
        }
        let sn_coded = self.next_send_coded_sn;
        let sn_source = self.next_send_source_sn;
        self.next_send_coded_sn = sn_coded.wrapping_add(1);
        self.next_send_source_sn = sn_source.wrapping_add(1);

        let header = RdpUdpFecHeader {
            sn_source_ack: self.highest_received_sn,
            u_receive_window_size: self.config.receive_window_size,
            u_flags: RDPUDP_FLAG_DATA | RDPUDP_FLAG_ACK,
        };
        let src_hdr = SourcePayloadHeader {
            sn_coded,
            sn_source_start: sn_source,
        };
        // Include a minimal ACK vector so the peer knows we're alive.
        let ack_vec = self.build_ack_vector();

        let size =
            header.size() + ack_vec.size() + src_hdr.size() + payload.len();
        output.clear();
        output.resize(size, 0);
        let mut cur = WriteCursor::new(output);
        header.encode(&mut cur)?;
        ack_vec.encode(&mut cur)?;
        src_hdr.encode(&mut cur)?;
        cur.write_slice(payload, "SourcePayload")?;
        Ok(sn_source)
    }

    /// Build a standalone ACK datagram (no data). The caller SHOULD
    /// send it periodically or when the delayed-ACK timer fires.
    pub fn build_ack(&self, output: &mut Vec<u8>) -> Result<(), RdpeudpError> {
        if self.state != RdpeudpState::Connected {
            return Err(RdpeudpError::InvalidState("build_ack: not connected"));
        }
        let header = RdpUdpFecHeader {
            sn_source_ack: self.highest_received_sn,
            u_receive_window_size: self.config.receive_window_size,
            u_flags: RDPUDP_FLAG_ACK,
        };
        let ack_vec = self.build_ack_vector();

        let size = header.size() + ack_vec.size();
        output.clear();
        output.resize(size, 0);
        let mut cur = WriteCursor::new(output);
        header.encode(&mut cur)?;
        ack_vec.encode(&mut cur)?;
        Ok(())
    }

    /// Build the ACK vector reflecting the current receive bitmap.
    fn build_ack_vector(&self) -> AckVectorHeader {
        if self.recv_bitmap.is_empty() {
            return AckVectorHeader::new(alloc::vec![]);
        }
        // RLE-compress the bitmap into AckVectorElements, capped at
        // RDPUDP_MAX_ACK_VECTOR_SIZE bytes.
        let mut elements = Vec::new();
        let mut i = 0;
        while i < self.recv_bitmap.len() && elements.len() < RDPUDP_MAX_ACK_VECTOR_SIZE {
            let received = self.recv_bitmap[i];
            let state = if received {
                VectorElementState::DatagramReceived
            } else {
                VectorElementState::DatagramNotYetReceived
            };
            let mut run: u8 = 1;
            while i + (run as usize) < self.recv_bitmap.len()
                && self.recv_bitmap[i + (run as usize)] == received
                && run < 64
            {
                run += 1;
            }
            elements.push(AckVectorElement::new(state, run));
            i += run as usize;
        }
        AckVectorHeader::new(elements)
    }

    /// Return the next send source sequence number (for diagnostics).
    pub fn next_send_sn(&self) -> u32 {
        self.next_send_source_sn
    }

    /// Return the highest received source SN (snSourceAck value).
    pub fn highest_received_sn(&self) -> u32 {
        self.highest_received_sn
    }
}

// =============================================================================
// Sequence-number comparison (modular arithmetic, RFC 793 §3.3)
// =============================================================================

/// Return `true` if `a` is "after" `b` in the circular 32-bit
/// sequence space.
fn sn_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Return `true` if `a` is strictly "before" `b`.
fn sn_before(a: u32, b: u32) -> bool {
    sn_after(b, a)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::*;

    fn client_config() -> RdpeudpConfig {
        RdpeudpConfig {
            up_stream_mtu: 1200,
            down_stream_mtu: 1200,
            initial_sequence_number: 0xAAAA_0001,
            receive_window_size: 64,
            lossy: false,
            protocol_version: RDPUDP_PROTOCOL_VERSION_2,
            correlation_id: None,
            cookie_hash: None,
        }
    }

    fn server_config() -> RdpeudpConfig {
        RdpeudpConfig {
            up_stream_mtu: 1200,
            down_stream_mtu: 1200,
            initial_sequence_number: 0xBBBB_0002,
            receive_window_size: 32,
            lossy: false,
            protocol_version: RDPUDP_PROTOCOL_VERSION_2,
            correlation_id: None,
            cookie_hash: None,
        }
    }

    // ── build_syn ──

    #[test]
    fn build_syn_produces_padded_datagram_and_transitions_to_syn_sent() {
        let mut session = RdpeudpSession::new(client_config());
        let mut out = Vec::new();
        session.build_syn(&mut out).unwrap();
        assert_eq!(session.state(), RdpeudpState::SynSent);
        // Datagram should be padded to min(up, down) = 1200.
        assert_eq!(out.len(), 1200);

        // Verify header.
        let mut cur = ReadCursor::new(&out);
        let hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
        assert_eq!(hdr.sn_source_ack, RDPUDP_INITIAL_SOURCE_ACK);
        assert_ne!(hdr.u_flags & RDPUDP_FLAG_SYN, 0);
        assert_ne!(hdr.u_flags & RDPUDP_FLAG_SYNEX, 0);
        assert_eq!(hdr.u_flags & RDPUDP_FLAG_ACK, 0);

        // Verify SynDataPayload.
        let syn = SynDataPayload::decode(&mut cur).unwrap();
        assert_eq!(syn.sn_initial_sequence_number, 0xAAAA_0001);
        assert_eq!(syn.u_up_stream_mtu, 1200);
    }

    #[test]
    fn build_syn_rejects_non_idle_state() {
        let mut session = RdpeudpSession::new(client_config());
        let mut out = Vec::new();
        session.build_syn(&mut out).unwrap();
        // Second call should fail (already SynSent).
        assert!(session.build_syn(&mut out).is_err());
    }

    #[test]
    fn build_syn_with_correlation_id() {
        let mut cfg = client_config();
        cfg.correlation_id = Some([0x11u8; 16]);
        let mut session = RdpeudpSession::new(cfg);
        let mut out = Vec::new();
        session.build_syn(&mut out).unwrap();

        let mut cur = ReadCursor::new(&out);
        let hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
        assert_ne!(hdr.u_flags & RDPUDP_FLAG_CORRELATION_ID, 0);
        let _syn = SynDataPayload::decode(&mut cur).unwrap();
        let corr = CorrelationIdPayload::decode(&mut cur).unwrap();
        assert_eq!(corr.u_correlation_id, [0x11u8; 16]);
    }

    #[test]
    fn build_syn_lossy_sets_flag() {
        let mut cfg = client_config();
        cfg.lossy = true;
        let mut session = RdpeudpSession::new(cfg);
        let mut out = Vec::new();
        session.build_syn(&mut out).unwrap();

        let mut cur = ReadCursor::new(&out);
        let hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
        assert_ne!(hdr.u_flags & RDPUDP_FLAG_SYNLOSSY, 0);
    }

    // ── Full 3-way handshake ──

    #[test]
    fn full_three_way_handshake_client_server() {
        let mut client = RdpeudpSession::new(client_config());
        let mut server = RdpeudpSession::new_server(server_config());

        // 1. Client → Server: SYN.
        let mut syn_dgram = Vec::new();
        client.build_syn(&mut syn_dgram).unwrap();
        assert_eq!(client.state(), RdpeudpState::SynSent);

        // 2. Server processes SYN → produces SYN+ACK.
        let mut syn_ack_dgram = Vec::new();
        let action = server.receive(&syn_dgram, &mut syn_ack_dgram).unwrap();
        assert_eq!(action, ReceiveAction::SendResponse);
        assert_eq!(server.state(), RdpeudpState::SynReceived);
        assert_eq!(server.remote_initial_sn(), Some(0xAAAA_0001));

        // 3. Client processes SYN+ACK → produces ACK → Connected.
        let mut ack_dgram = Vec::new();
        let action = client.receive(&syn_ack_dgram, &mut ack_dgram).unwrap();
        assert_eq!(action, ReceiveAction::SendResponse);
        assert!(client.is_connected());
        assert_eq!(client.remote_initial_sn(), Some(0xBBBB_0002));

        // 4. Server processes ACK → Connected.
        let mut no_output = Vec::new();
        let action = server.receive(&ack_dgram, &mut no_output).unwrap();
        assert_eq!(action, ReceiveAction::Nothing);
        assert!(server.is_connected());

        // Verify negotiated parameters.
        assert_eq!(client.negotiated_mtu(), Some(1200));
        assert_eq!(server.negotiated_mtu(), Some(1200));
        assert_eq!(
            client.negotiated_version(),
            Some(RDPUDP_PROTOCOL_VERSION_2)
        );
        assert_eq!(
            server.negotiated_version(),
            Some(RDPUDP_PROTOCOL_VERSION_2)
        );
        assert!(!client.negotiated_lossy());
        assert!(!server.negotiated_lossy());
    }

    #[test]
    fn handshake_negotiates_minimum_mtu() {
        let mut ccfg = client_config();
        ccfg.up_stream_mtu = 1200;
        ccfg.down_stream_mtu = 1180;
        let mut scfg = server_config();
        scfg.up_stream_mtu = 1190;
        scfg.down_stream_mtu = 1132;

        let mut client = RdpeudpSession::new(ccfg);
        let mut server = RdpeudpSession::new_server(scfg);

        let mut syn = Vec::new();
        client.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        server.receive(&syn, &mut syn_ack).unwrap();
        let mut ack = Vec::new();
        client.receive(&syn_ack, &mut ack).unwrap();

        assert_eq!(client.negotiated_mtu(), Some(1132));
        assert_eq!(server.negotiated_mtu(), Some(1132));
    }

    #[test]
    fn handshake_negotiates_version_min() {
        let mut ccfg = client_config();
        ccfg.protocol_version = RDPUDP_PROTOCOL_VERSION_2;
        let mut scfg = server_config();
        scfg.protocol_version = RDPUDP_PROTOCOL_VERSION_1;

        let mut client = RdpeudpSession::new(ccfg);
        let mut server = RdpeudpSession::new_server(scfg);

        let mut syn = Vec::new();
        client.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        server.receive(&syn, &mut syn_ack).unwrap();
        let mut ack = Vec::new();
        client.receive(&syn_ack, &mut ack).unwrap();

        // Server picks min(client=2, server=1) = 1; client accepts
        // whatever the server advertises.
        assert_eq!(
            server.negotiated_version(),
            Some(RDPUDP_PROTOCOL_VERSION_1)
        );
        assert_eq!(
            client.negotiated_version(),
            Some(RDPUDP_PROTOCOL_VERSION_1)
        );
    }

    #[test]
    fn handshake_lossy_requires_both_sides() {
        // Client lossy, server not.
        let mut ccfg = client_config();
        ccfg.lossy = true;
        let mut scfg = server_config();
        scfg.lossy = false;

        let mut client = RdpeudpSession::new(ccfg);
        let mut server = RdpeudpSession::new_server(scfg);
        let mut syn = Vec::new();
        client.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        server.receive(&syn, &mut syn_ack).unwrap();
        let mut ack = Vec::new();
        client.receive(&syn_ack, &mut ack).unwrap();

        assert!(!client.negotiated_lossy());
        assert!(!server.negotiated_lossy());
    }

    #[test]
    fn handshake_lossy_succeeds_when_both_set() {
        let mut ccfg = client_config();
        ccfg.lossy = true;
        let mut scfg = server_config();
        scfg.lossy = true;

        let mut client = RdpeudpSession::new(ccfg);
        let mut server = RdpeudpSession::new_server(scfg);
        let mut syn = Vec::new();
        client.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        server.receive(&syn, &mut syn_ack).unwrap();
        let mut ack = Vec::new();
        client.receive(&syn_ack, &mut ack).unwrap();

        assert!(client.negotiated_lossy());
        assert!(server.negotiated_lossy());
    }

    // ── Error paths ──

    #[test]
    fn client_rejects_plain_ack_instead_of_syn_ack() {
        let mut client = RdpeudpSession::new(client_config());
        let mut out = Vec::new();
        client.build_syn(&mut out).unwrap();

        // Forge a datagram with only ACK flag (no SYN).
        let hdr = RdpUdpFecHeader {
            sn_source_ack: 0xAAAA_0001,
            u_receive_window_size: 32,
            u_flags: RDPUDP_FLAG_ACK,
        };
        let ack_vec = AckVectorHeader::new(alloc::vec![
            AckVectorElement::new(VectorElementState::DatagramReceived, 1)
        ]);
        let size = hdr.size() + ack_vec.size();
        let mut fake = alloc::vec![0u8; size];
        let mut cur = WriteCursor::new(&mut fake);
        hdr.encode(&mut cur).unwrap();
        ack_vec.encode(&mut cur).unwrap();

        let mut resp = Vec::new();
        let err = client.receive(&fake, &mut resp).unwrap_err();
        assert!(matches!(err, RdpeudpError::Protocol(_)));
    }

    #[test]
    fn client_rejects_syn_ack_with_wrong_source_ack() {
        let mut client = RdpeudpSession::new(client_config());
        let mut server = RdpeudpSession::new_server(server_config());

        let mut syn = Vec::new();
        client.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        server.receive(&syn, &mut syn_ack).unwrap();

        // Corrupt the snSourceAck field (bytes 0..4) in the SYN+ACK.
        syn_ack[0] = 0x00;
        syn_ack[1] = 0x00;
        syn_ack[2] = 0x00;
        syn_ack[3] = 0x00;

        let mut ack = Vec::new();
        let err = client.receive(&syn_ack, &mut ack).unwrap_err();
        assert!(matches!(err, RdpeudpError::Protocol(_)));
    }

    #[test]
    fn server_rejects_non_syn_in_listening() {
        let mut server = RdpeudpSession::new_server(server_config());
        let hdr = RdpUdpFecHeader {
            sn_source_ack: RDPUDP_INITIAL_SOURCE_ACK,
            u_receive_window_size: 64,
            u_flags: RDPUDP_FLAG_ACK, // missing SYN
        };
        let ack_vec = AckVectorHeader::new(alloc::vec![
            AckVectorElement::new(VectorElementState::DatagramReceived, 1)
        ]);
        let size = hdr.size() + ack_vec.size();
        let mut fake = alloc::vec![0u8; size];
        let mut cur = WriteCursor::new(&mut fake);
        hdr.encode(&mut cur).unwrap();
        ack_vec.encode(&mut cur).unwrap();

        let mut resp = Vec::new();
        let err = server.receive(&fake, &mut resp).unwrap_err();
        assert!(matches!(err, RdpeudpError::Protocol(_)));
    }

    // ── Data path ──

    fn drive_to_connected() -> (RdpeudpSession, RdpeudpSession) {
        let mut client = RdpeudpSession::new(client_config());
        let mut server = RdpeudpSession::new_server(server_config());
        let mut syn = Vec::new();
        client.build_syn(&mut syn).unwrap();
        let mut syn_ack = Vec::new();
        server.receive(&syn, &mut syn_ack).unwrap();
        let mut ack = Vec::new();
        client.receive(&syn_ack, &mut ack).unwrap();
        let mut no_out = Vec::new();
        server.receive(&ack, &mut no_out).unwrap();
        assert!(client.is_connected());
        assert!(server.is_connected());
        (client, server)
    }

    #[test]
    fn build_data_packet_assigns_incrementing_sn() {
        let (mut client, _server) = drive_to_connected();
        let mut out = Vec::new();
        let sn1 = client.build_data_packet(b"hello", &mut out).unwrap();
        let sn2 = client.build_data_packet(b"world", &mut out).unwrap();
        assert_eq!(sn2, sn1.wrapping_add(1));
    }

    #[test]
    fn build_data_packet_includes_source_payload_header_and_payload() {
        let (mut client, _server) = drive_to_connected();
        let mut out = Vec::new();
        let sn = client.build_data_packet(b"test", &mut out).unwrap();

        let mut cur = ReadCursor::new(&out);
        let hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
        assert_ne!(hdr.u_flags & RDPUDP_FLAG_DATA, 0);
        assert_ne!(hdr.u_flags & RDPUDP_FLAG_ACK, 0);

        let _ack = AckVectorHeader::decode(&mut cur).unwrap();
        let src = SourcePayloadHeader::decode(&mut cur).unwrap();
        assert_eq!(src.sn_source_start, sn);

        let remaining = cur.remaining();
        let payload = cur.read_slice(remaining, "payload").unwrap();
        assert_eq!(payload, b"test");
    }

    #[test]
    fn data_roundtrip_client_to_server() {
        let (mut client, mut server) = drive_to_connected();
        let mut dgram = Vec::new();
        client.build_data_packet(b"RDP-DATA", &mut dgram).unwrap();

        let mut resp = Vec::new();
        let action = server.receive(&dgram, &mut resp).unwrap();
        assert_eq!(action, ReceiveAction::Nothing);

        // Server should have updated its tracking.
        let expected_sn = client_config().initial_sequence_number.wrapping_add(1);
        assert_eq!(server.highest_received_sn(), expected_sn);
    }

    #[test]
    fn data_roundtrip_bidirectional() {
        let (mut client, mut server) = drive_to_connected();

        // Client → Server.
        let mut dgram = Vec::new();
        client.build_data_packet(b"C2S", &mut dgram).unwrap();
        server.receive(&dgram, &mut Vec::new()).unwrap();

        // Server → Client.
        server.build_data_packet(b"S2C", &mut dgram).unwrap();
        client.receive(&dgram, &mut Vec::new()).unwrap();

        let expected_server_sn = server_config().initial_sequence_number.wrapping_add(1);
        assert_eq!(client.highest_received_sn(), expected_server_sn);
    }

    #[test]
    fn build_ack_standalone() {
        let (mut client, mut server) = drive_to_connected();
        let mut dgram = Vec::new();
        client.build_data_packet(b"ping", &mut dgram).unwrap();
        server.receive(&dgram, &mut Vec::new()).unwrap();

        let mut ack = Vec::new();
        server.build_ack(&mut ack).unwrap();

        let mut cur = ReadCursor::new(&ack);
        let hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
        assert_eq!(hdr.u_flags, RDPUDP_FLAG_ACK);
        let expected_sn = client_config().initial_sequence_number.wrapping_add(1);
        assert_eq!(hdr.sn_source_ack, expected_sn);
    }

    #[test]
    fn ack_vector_records_gap() {
        let (mut client, mut server) = drive_to_connected();
        // Send packets SN+1 and SN+3 (skip SN+2) to create a gap.
        let mut out = Vec::new();
        let _sn1 = client.build_data_packet(b"1", &mut out).unwrap();
        server.receive(&out, &mut Vec::new()).unwrap();
        // Skip SN+2 — build it but don't deliver to server.
        client.build_data_packet(b"2", &mut out).unwrap();
        // SN+3:
        client.build_data_packet(b"3", &mut out).unwrap();
        server.receive(&out, &mut Vec::new()).unwrap();

        // Now server's ACK vector should show: SN+1 received, SN+2
        // not received, SN+3 received.
        let mut ack = Vec::new();
        server.build_ack(&mut ack).unwrap();
        let mut cur = ReadCursor::new(&ack);
        let _hdr = RdpUdpFecHeader::decode(&mut cur).unwrap();
        let ack_vec = AckVectorHeader::decode(&mut cur).unwrap();

        // Expect 3 elements: R(1), N(1), R(1).
        assert_eq!(ack_vec.ack_vector.len(), 3);
        assert_eq!(
            ack_vec.ack_vector[0].state,
            VectorElementState::DatagramReceived
        );
        assert_eq!(ack_vec.ack_vector[0].run_length, 1);
        assert_eq!(
            ack_vec.ack_vector[1].state,
            VectorElementState::DatagramNotYetReceived
        );
        assert_eq!(ack_vec.ack_vector[1].run_length, 1);
        assert_eq!(
            ack_vec.ack_vector[2].state,
            VectorElementState::DatagramReceived
        );
        assert_eq!(ack_vec.ack_vector[2].run_length, 1);
    }

    #[test]
    fn build_data_packet_before_connected_fails() {
        let mut session = RdpeudpSession::new(client_config());
        let mut out = Vec::new();
        assert!(session.build_data_packet(b"x", &mut out).is_err());
    }

    #[test]
    fn sn_after_wrapping_arithmetic() {
        assert!(sn_after(1, 0));
        assert!(!sn_after(0, 1));
        // Wrap: 0x0000_0001 is "after" 0xFFFF_FFFF.
        assert!(sn_after(0x0000_0001, 0xFFFF_FFFF));
        assert!(sn_before(0xFFFF_FFFF, 0x0000_0001));
        // Equal is neither before nor after.
        assert!(!sn_after(42, 42));
        assert!(!sn_before(42, 42));
    }
}
