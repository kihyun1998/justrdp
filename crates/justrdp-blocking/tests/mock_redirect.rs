//! Integration tests for Session Redirection (§9.3) using a mock RDP server.
//!
//! Two `TcpListener`s are used:
//! - **broker**: performs a minimal RDP handshake, then sends a `ServerRedirectionPdu`
//!   pointing to the target.
//! - **target**: performs the same minimal handshake through finalization and reaches
//!   `Connected` state.
//!
//! TLS is skipped via `NoopTlsUpgrader` which wraps raw TCP without encryption.
//! CredSSP is skipped by negotiating `SSL` only (no `HYBRID`).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use justrdp_blocking::{RdpClient, RdpEvent};
use justrdp_connector::Config;
use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_pdu::mcs::{
    AttachUserConfirm, ChannelJoinConfirm, ChannelJoinRequest, ConnectResponse,
    ConnectResponseResult, DomainParameters, SendDataIndication,
};
use justrdp_pdu::rdp::capabilities::{CapabilitySet, GeneralCapability, DemandActivePdu};
use justrdp_pdu::rdp::finalization::{ControlAction, ControlPdu, FontListPdu, SynchronizePdu};
use justrdp_pdu::rdp::headers::{ShareControlPduType, ShareDataPduType};
use justrdp_pdu::rdp::licensing::LicenseErrorMessage;
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{
    ConnectionConfirm, ConnectionConfirmNegotiation, DataTransfer, NegotiationResponse,
    NegotiationResponseFlags, SecurityProtocol, DATA_TRANSFER_HEADER_SIZE,
};
use justrdp_pdu::gcc::ConferenceCreateResponse;
use justrdp_pdu::gcc::server::{ServerCoreData, ServerNetworkData, ServerSecurityData};
use justrdp_tls::{TlsError, TlsUpgradeResult, TlsUpgrader};

// ── NoopUpgrader ──

/// Wrapper that forwards Read+Write to the inner stream.
struct PassthroughStream<S: Read + Write>(S);

impl<S: Read + Write> Read for PassthroughStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
impl<S: Read + Write> Write for PassthroughStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

struct NoopUpgrader;

impl TlsUpgrader for NoopUpgrader {
    type Stream = PassthroughStream<Box<dyn justrdp_tls::ReadWrite>>;

    fn upgrade<S: Read + Write + 'static>(
        &self,
        stream: S,
        _server_name: &str,
    ) -> Result<TlsUpgradeResult<Self::Stream>, TlsError> {
        let boxed: Box<dyn justrdp_tls::ReadWrite> = Box::new(stream);
        Ok(TlsUpgradeResult {
            stream: PassthroughStream(boxed),
            server_public_key: vec![0u8; 32], // dummy
        })
    }
}

// ── Frame building helpers ──

const IO_CHANNEL_ID: u16 = 1003;
const USER_CHANNEL_ID: u16 = 1007;
const SHARE_ID: u32 = 0x0004_0006;

/// Encode a PDU to bytes.
fn encode_pdu(pdu: &dyn Encode) -> Vec<u8> {
    let size = pdu.size();
    let mut buf = vec![0u8; size];
    let mut cursor = WriteCursor::new(&mut buf);
    pdu.encode(&mut cursor).unwrap();
    buf
}

/// Wrap bytes in TPKT + X.224 DataTransfer header.
fn wrap_tpkt_dt(payload: &[u8]) -> Vec<u8> {
    let mcs_size = DATA_TRANSFER_HEADER_SIZE + payload.len();
    let mut frame = vec![0u8; TPKT_HEADER_SIZE + mcs_size];
    let mut cursor = WriteCursor::new(&mut frame);
    TpktHeader::for_payload(mcs_size).encode(&mut cursor).unwrap();
    DataTransfer.encode(&mut cursor).unwrap();
    frame[TPKT_HEADER_SIZE + DATA_TRANSFER_HEADER_SIZE..].copy_from_slice(payload);
    frame
}

/// Build a ShareControl + ShareData frame wrapped in MCS SDI + TPKT.
fn build_server_data_frame(pdu_type2: ShareDataPduType, body: &[u8]) -> Vec<u8> {
    // ShareDataHeader: shareId(4) + pad(1) + streamId(1) + uncompressedLen(2) + pduType2(1) + compType(1) + compLen(2)
    let share_data_header_size = 12;
    let mut sd = vec![0u8; share_data_header_size + body.len()];
    sd[0..4].copy_from_slice(&SHARE_ID.to_le_bytes());
    sd[4] = 0; // pad
    sd[5] = 1; // streamId = STREAM_LOW
    sd[6..8].copy_from_slice(&(body.len() as u16).to_le_bytes()); // uncompressedLength
    sd[8] = pdu_type2 as u8;
    sd[9] = 0; // compType
    sd[10..12].copy_from_slice(&0u16.to_le_bytes()); // compressedLength
    sd[12..].copy_from_slice(body);

    // ShareControlHeader: totalLength(2) + pduType(2) + pduSource(2)
    let sc_header_size = 6;
    let total_len = (sc_header_size + sd.len()) as u16;
    let mut sc = vec![0u8; sc_header_size + sd.len()];
    sc[0..2].copy_from_slice(&total_len.to_le_bytes());
    sc[2..4].copy_from_slice(&(ShareControlPduType::Data as u16).to_le_bytes());
    sc[4..6].copy_from_slice(&0x03EA_u16.to_le_bytes()); // pduSource
    sc[6..].copy_from_slice(&sd);

    // MCS SendDataIndication
    let sdi = SendDataIndication {
        initiator: 0x03EA,
        channel_id: IO_CHANNEL_ID,
        user_data: &sc,
    };
    let sdi_bytes = encode_pdu(&sdi);
    wrap_tpkt_dt(&sdi_bytes)
}

/// Build a DemandActive frame (ShareControl pduType=DemandActive, no ShareData).
fn build_demand_active_frame() -> Vec<u8> {
    let pdu = DemandActivePdu {
        share_id: SHARE_ID,
        source_descriptor: b"MockRDP\0".to_vec(),
        capability_sets: vec![
            // Minimal: just General capability
            CapabilitySet::General(GeneralCapability {
                os_major_type: 1,
                os_minor_type: 3,
                protocol_version: 0x0200,
                pad2: 0,
                general_compression_types: 0,
                extra_flags: 0,
                update_capability_flag: 0,
                remote_unshare_flag: 0,
                general_compression_level: 0,
                refresh_rect_support: 0,
                suppress_output_support: 0,
            }),
        ],
        session_id: 0,
    };
    let pdu_bytes = encode_pdu(&pdu);

    // ShareControlHeader wrapping DemandActive (no ShareData)
    let sc_header_size = 6;
    let total_len = (sc_header_size + pdu_bytes.len()) as u16;
    let mut sc = vec![0u8; sc_header_size + pdu_bytes.len()];
    sc[0..2].copy_from_slice(&total_len.to_le_bytes());
    sc[2..4].copy_from_slice(&(ShareControlPduType::DemandActivePdu as u16).to_le_bytes());
    sc[4..6].copy_from_slice(&0x03EA_u16.to_le_bytes());
    sc[6..].copy_from_slice(&pdu_bytes);

    let sdi = SendDataIndication {
        initiator: 0x03EA,
        channel_id: IO_CHANNEL_ID,
        user_data: &sc,
    };
    let sdi_bytes = encode_pdu(&sdi);
    wrap_tpkt_dt(&sdi_bytes)
}

/// Build a licensing STATUS_VALID_CLIENT frame.
fn build_license_valid_frame() -> Vec<u8> {
    let lic = LicenseErrorMessage::valid_client();
    let lic_bytes = encode_pdu(&lic);

    // Security header: flags(2) + flagsHi(2)
    let mut sec = vec![0u8; 4 + lic_bytes.len()];
    sec[0..2].copy_from_slice(&0x0080_u16.to_le_bytes()); // SEC_LICENSE_PKT
    sec[2..4].copy_from_slice(&0u16.to_le_bytes()); // flagsHi
    sec[4..].copy_from_slice(&lic_bytes);

    let sdi = SendDataIndication {
        initiator: 0x03EA,
        channel_id: IO_CHANNEL_ID,
        user_data: &sec,
    };
    let sdi_bytes = encode_pdu(&sdi);
    wrap_tpkt_dt(&sdi_bytes)
}

/// Build MCS ConnectResponse with minimal GCC server data.
fn build_mcs_connect_response() -> Vec<u8> {
    // Build GCC server data blocks
    let core = ServerCoreData {
        version: 0x00080004, // RDP 5.0+
        client_requested_protocols: Some(SecurityProtocol::SSL.bits()),
        early_capability_flags: None,
    };
    let security = ServerSecurityData {
        encryption_method: 0, // None (TLS handles it)
        encryption_level: 0,
        server_random: None,
        server_certificate: None,
    };
    let network = ServerNetworkData {
        mcs_channel_id: IO_CHANNEL_ID,
        channel_ids: vec![], // no extra channels
    };

    // Each ServerXxxData::Encode includes its own block header, so just
    // concatenate the encoded bytes directly.
    let mut gcc_data = Vec::new();
    gcc_data.extend_from_slice(&encode_pdu(&core));
    gcc_data.extend_from_slice(&encode_pdu(&security));
    gcc_data.extend_from_slice(&encode_pdu(&network));

    let gcc_response = ConferenceCreateResponse::new(gcc_data);
    let gcc_bytes = encode_pdu(&gcc_response);

    let response = ConnectResponse {
        result: ConnectResponseResult::RtSuccessful,
        called_connect_id: 0,
        domain_parameters: DomainParameters {
            max_channel_ids: 34,
            max_user_ids: 3,
            max_token_ids: 0,
            num_priorities: 1,
            min_throughput: 0,
            max_height: 1,
            max_mcs_pdu_size: 65535,
            protocol_version: 2,
        },
        user_data: gcc_bytes,
    };

    let resp_bytes = encode_pdu(&response);
    wrap_tpkt_dt(&resp_bytes)
}

/// Build a ServerRedirectionPdu frame (Enhanced Security variant).
///
/// If `target_addr` is empty, `LB_TARGET_NET_ADDRESS` is not set in the flags.
fn build_redirect_frame(target_addr: &str, lb_info: &[u8]) -> Vec<u8> {
    use justrdp_pdu::rdp::redirection::{LB_LOAD_BALANCE_INFO, LB_TARGET_NET_ADDRESS};

    let has_target = !target_addr.is_empty();
    let mut flags: u32 = LB_LOAD_BALANCE_INFO;
    if has_target {
        flags |= LB_TARGET_NET_ADDRESS;
    }

    let mut body = Vec::new();
    let sec_redirection_pkt: u16 = 0x0400;
    body.extend_from_slice(&sec_redirection_pkt.to_le_bytes());
    let length_offset = body.len();
    body.extend_from_slice(&0u16.to_le_bytes()); // length placeholder
    body.extend_from_slice(&0u32.to_le_bytes()); // session_id
    body.extend_from_slice(&flags.to_le_bytes()); // redir_flags

    // LB_TARGET_NET_ADDRESS (if present): length(u32) + UTF-16LE null-terminated
    if has_target {
        let mut target_utf16 = Vec::new();
        for ch in target_addr.encode_utf16() {
            target_utf16.extend_from_slice(&ch.to_le_bytes());
        }
        target_utf16.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&(target_utf16.len() as u32).to_le_bytes());
        body.extend_from_slice(&target_utf16);
    }

    // LB_LOAD_BALANCE_INFO: length(u32) + data
    body.extend_from_slice(&(lb_info.len() as u32).to_le_bytes());
    body.extend_from_slice(lb_info);

    // length = total bytes from flags(2) onward (inclusive of flags+length themselves)
    let total = body.len() as u16;
    body[length_offset..length_offset + 2].copy_from_slice(&total.to_le_bytes());

    // Pad to 8-byte alignment (decoder silently consumes trailing pad)
    while body.len() % 8 != 0 {
        body.push(0);
    }

    // Wrap in ShareControl with ServerRedirect type (Enhanced Security path)
    // ShareControlHeader: totalLength(2) + pduType(2) + pduSource(2) + pad(2) + body
    let sc_header_size = 8; // 6 + 2 pad bytes for Enhanced Security redirect
    let total_len = (sc_header_size + body.len()) as u16;
    let mut sc = vec![0u8; sc_header_size + body.len()];
    sc[0..2].copy_from_slice(&total_len.to_le_bytes());
    sc[2..4].copy_from_slice(&(ShareControlPduType::ServerRedirect as u16).to_le_bytes());
    sc[4..6].copy_from_slice(&0x03EA_u16.to_le_bytes());
    sc[6..8].copy_from_slice(&[0x00, 0x00]); // 2-byte pad
    sc[8..].copy_from_slice(&body);

    let sdi = SendDataIndication {
        initiator: 0x03EA,
        channel_id: IO_CHANNEL_ID,
        user_data: &sc,
    };
    let sdi_bytes = encode_pdu(&sdi);
    wrap_tpkt_dt(&sdi_bytes)
}

// ── MockRdpServer ──

/// What to do at finalization time.
enum MockMode {
    /// Send a ServerRedirectionPdu and disconnect.
    Broker {
        target_addr: String,
        lb_info: Vec<u8>,
    },
    /// Complete finalization normally (Sync, Cooperate, Granted, FontMap).
    Target,
}

/// Read a complete TPKT-framed PDU from the stream.
fn read_pdu(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    if length < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "TPKT too short"));
    }
    let mut buf = vec![0u8; length];
    buf[..4].copy_from_slice(&header);
    stream.read_exact(&mut buf[4..])?;
    Ok(buf)
}

/// Run the mock server handshake on an accepted stream.
fn run_mock_handshake(mut stream: TcpStream, mode: MockMode) -> io::Result<()> {
    // 1. Read X.224 Connection Request
    let _cr = read_pdu(&mut stream)?;

    // 2. Write X.224 Connection Confirm (SSL only, no CredSSP)
    //    CC uses TPKT + X.224 CC header (NOT DataTransfer).
    let cc = ConnectionConfirm {
        negotiation: Some(ConnectionConfirmNegotiation::Response(NegotiationResponse {
            flags: NegotiationResponseFlags::NONE,
            protocol: SecurityProtocol::SSL,
        })),
    };
    let cc_bytes = encode_pdu(&cc);
    let mut cc_frame = vec![0u8; TPKT_HEADER_SIZE + cc_bytes.len()];
    {
        let mut cursor = WriteCursor::new(&mut cc_frame);
        TpktHeader::for_payload(cc_bytes.len()).encode(&mut cursor).unwrap();
    }
    cc_frame[TPKT_HEADER_SIZE..].copy_from_slice(&cc_bytes);
    stream.write_all(&cc_frame)?;

    // 3. [Client does TLS upgrade — NoopUpgrader passes through]
    //    The client will write MCS Connect Initial next.

    // 4. Read MCS Connect Initial
    let _ci = read_pdu(&mut stream)?;

    // 5. Write MCS Connect Response
    let cr_frame = build_mcs_connect_response();
    stream.write_all(&cr_frame)?;

    // 6. Read Erect Domain Request
    let _edr = read_pdu(&mut stream)?;

    // 7. Read Attach User Request → Write Attach User Confirm
    let _aur = read_pdu(&mut stream)?;
    let auc = AttachUserConfirm {
        result: 0, // rt-successful
        initiator: Some(USER_CHANNEL_ID),
    };
    let auc_bytes = encode_pdu(&auc);
    stream.write_all(&wrap_tpkt_dt(&auc_bytes))?;

    // 8. Read Channel Join Request(s) → Write Channel Join Confirm(s)
    //    Client joins: user_channel_id, io_channel_id (at minimum)
    for _ in 0..2 {
        let cjr_pdu = read_pdu(&mut stream)?;
        // Parse channel ID from the request
        let mut cursor = ReadCursor::new(&cjr_pdu);
        let _tpkt = TpktHeader::decode(&mut cursor).unwrap();
        let _dt = DataTransfer::decode(&mut cursor).unwrap();
        let cjr = ChannelJoinRequest::decode(&mut cursor).unwrap();
        let cjc = ChannelJoinConfirm {
            result: 0,
            initiator: USER_CHANNEL_ID,
            requested: cjr.channel_id,
            channel_id: Some(cjr.channel_id),
        };
        let cjc_bytes = encode_pdu(&cjc);
        stream.write_all(&wrap_tpkt_dt(&cjc_bytes))?;
    }

    // 9. Read Client Info PDU (Security Exchange / Secure Settings)
    let _info = read_pdu(&mut stream)?;

    // 10. Write License Valid
    stream.write_all(&build_license_valid_frame())?;

    // 11. Write Demand Active
    stream.write_all(&build_demand_active_frame())?;

    // 12. Read Confirm Active
    let _ca = read_pdu(&mut stream)?;

    // 13. Read client finalization: Synchronize, Cooperate, RequestControl, FontList
    for _ in 0..4 {
        let _fin = read_pdu(&mut stream)?;
    }

    // 14. Mode-dependent response
    match mode {
        MockMode::Broker { target_addr, lb_info } => {
            // Send ServerRedirectionPdu
            let frame = build_redirect_frame(&target_addr, &lb_info);
            stream.write_all(&frame)?;
            // Client will disconnect after processing the redirect
        }
        MockMode::Target => {
            // Complete finalization: Synchronize + Cooperate + Granted + FontMap
            let sync = SynchronizePdu { message_type: 1, target_user: USER_CHANNEL_ID };
            let sync_bytes = encode_pdu(&sync);
            stream.write_all(&build_server_data_frame(
                ShareDataPduType::Synchronize,
                &sync_bytes,
            ))?;

            let cooperate = ControlPdu {
                action: ControlAction::Cooperate,
                grant_id: 0,
                control_id: 0,
            };
            let coop_bytes = encode_pdu(&cooperate);
            stream.write_all(&build_server_data_frame(
                ShareDataPduType::Control,
                &coop_bytes,
            ))?;

            let granted = ControlPdu {
                action: ControlAction::GrantedControl,
                grant_id: USER_CHANNEL_ID,
                control_id: SHARE_ID,
            };
            let granted_bytes = encode_pdu(&granted);
            stream.write_all(&build_server_data_frame(
                ShareDataPduType::Control,
                &granted_bytes,
            ))?;

            let fontmap = FontListPdu {
                number_fonts: 0,
                total_num_fonts: 0,
                list_flags: 0x002C,
                entry_size: 0x0032,
            };
            let fm_bytes = encode_pdu(&fontmap);
            stream.write_all(&build_server_data_frame(
                ShareDataPduType::FontMap,
                &fm_bytes,
            ))?;
        }
    }

    stream.flush()?;
    Ok(())
}

/// Start a mock server on a random port.
fn start_mock_server(mode: MockMode) -> (SocketAddr, thread::JoinHandle<io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept()?;
        run_mock_handshake(stream, mode)
    });
    (addr, handle)
}

// ── Tests ──

#[test]
fn test_direct_connect_to_target() {
    // Sanity: connect to a target mock (no redirect) and verify Connected.
    let (addr, server) = start_mock_server(MockMode::Target);

    let config = Config::builder("user", "pass")
        .security_protocol(SecurityProtocol::SSL)
        .build();

    let result = RdpClient::connect_with_upgrader(addr, "localhost", config, NoopUpgrader, vec![]);
    match result {
        Ok(_client) => { /* success */ }
        Err(e) => panic!("direct connect failed: {e}"),
    }

    server.join().unwrap().unwrap();
}

#[test]
fn test_redirect_broker_to_target() {
    // Start the target first so we know its address.
    let (target_addr, target_server) = start_mock_server(MockMode::Target);
    let target_ip = target_addr.ip().to_string();
    let target_port = target_addr.port();
    let target_str = format!("{target_ip}:{target_port}");

    // Start the broker pointing to the target.
    let lb_info = b"test-lb-cookie".to_vec();
    let (broker_addr, broker_server) = start_mock_server(MockMode::Broker {
        target_addr: target_str,
        lb_info,
    });

    let config = Config::builder("user", "pass")
        .security_protocol(SecurityProtocol::SSL)
        .build();

    let mut client = RdpClient::connect_with_upgrader(
        broker_addr,
        "localhost",
        config,
        NoopUpgrader,
        vec![],
    )
    .expect("redirect connect should succeed");

    // The first event should be Redirected.
    let event = client.next_event().expect("next_event should not error");
    match event {
        Some(RdpEvent::Redirected { target }) => {
            assert!(
                target.contains(&target_ip),
                "redirect target should contain the target IP, got: {target}",
            );
        }
        other => panic!("expected Redirected event, got: {other:?}"),
    }

    broker_server.join().unwrap().unwrap();
    target_server.join().unwrap().unwrap();
}

#[test]
fn test_max_redirect_depth_exceeded() {
    // Create a chain of 7 brokers (exceeds MAX_REDIRECTS=5).
    // Each broker redirects to the next. The 7th is never reached.
    let mut addrs = Vec::new();
    let mut handles = Vec::new();

    // Pre-bind all listeners so we know addresses before starting threads.
    let listeners: Vec<TcpListener> = (0..7)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    for l in &listeners {
        addrs.push(l.local_addr().unwrap());
    }

    // Each broker (0..6) redirects to the next address.
    for (i, listener) in listeners.into_iter().enumerate() {
        let next_addr = if i < 6 {
            format!("{}:{}", addrs[i + 1].ip(), addrs[i + 1].port())
        } else {
            // The 7th broker should never be reached, but if it is,
            // redirect to itself (will time out).
            format!("{}:{}", addrs[i].ip(), addrs[i].port())
        };
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept()?;
            run_mock_handshake(
                stream,
                MockMode::Broker {
                    target_addr: next_addr,
                    lb_info: format!("chain-{i}").into_bytes(),
                },
            )
        });
        handles.push(handle);
    }

    let config = Config::builder("user", "pass")
        .security_protocol(SecurityProtocol::SSL)
        .build();

    let result = RdpClient::connect_with_upgrader(
        addrs[0],
        "localhost",
        config,
        NoopUpgrader,
        vec![],
    );

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("should fail with too many redirects"),
    };
    let err_msg = format!("{err}");
    assert!(
        err_msg.contains("too many redirects"),
        "error should mention 'too many redirects', got: {err_msg}",
    );

    // Join the threads that were actually used (first 6).
    // The 7th may never accept a connection — give it a moment to be sure
    // it doesn't block forever.
    for handle in handles.into_iter().take(6) {
        let _ = handle.join();
    }
}

#[test]
fn test_redirect_no_target_address() {
    // Broker sends redirect with LB info but NO target address.
    // Client should fall back to the original (broker) address, which
    // means it reconnects to the broker again. Second time the broker
    // is gone, so connection fails — but the important thing is it
    // doesn't panic and attempts the fallback.

    let (broker_addr, broker_server) = start_mock_server(MockMode::Broker {
        // Empty target_addr → no LB_TARGET_NET_ADDRESS in the PDU
        target_addr: String::new(),
        lb_info: b"fallback-test".to_vec(),
    });

    let config = Config::builder("user", "pass")
        .security_protocol(SecurityProtocol::SSL)
        .build();

    // The redirect will try to connect back to broker_addr (fallback),
    // but the mock only accepts one connection. The second attempt
    // should fail with a TCP error, not a panic.
    let result = RdpClient::connect_with_upgrader(
        broker_addr,
        "localhost",
        config,
        NoopUpgrader,
        vec![],
    );

    // We expect some form of connection error (the broker is gone).
    match result {
        Err(_) => { /* expected */ }
        Ok(_) => panic!("should fail when broker is gone after redirect"),
    }

    let _ = broker_server.join();
}
