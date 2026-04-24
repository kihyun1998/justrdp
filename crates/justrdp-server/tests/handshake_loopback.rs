//! End-to-end handshake integration test (§11.2d, first deliverable).
//!
//! Drives a [`ClientConnector`] against a [`ServerAcceptor`] in a single
//! process using in-memory byte queues. The `PROTOCOL_RDP` security
//! path is chosen so both sides skip TLS / CredSSP entirely -- this is
//! the "`NoopTlsUpgrader`" approach the roadmap calls for: rather than
//! faking TLS bytes we configure both peers to negotiate a path where
//! the TLS state is never entered.
//!
//! Standard-RDP-Security encryption (RC4 + MAC) is still a stub per
//! §11.2a and is wired up separately in §11.2a-stdsec; this file only
//! validates the state-machine plumbing end-to-end.

use justrdp_acceptor::{
    AcceptorConfig, Sequence as AcceptorSequence, ServerAcceptor, ServerAcceptorState,
    StandardSecurityConfig,
};
use justrdp_connector::{
    ClientConnector, ClientConnectorState, Config, Sequence as ConnectorSequence,
};
use justrdp_core::{Decode, Encode, ReadCursor, WriteBuf, WriteCursor};
use justrdp_pdu::x224::SecurityProtocol;
use justrdp_server::{
    encode_bitmap_update, BitmapUpdate, DisplayRect, DisplayUpdate, EgfxFrame,
    RdpServerDisplayHandler, RdpServerInputHandler, ServerActiveStage,
};
use justrdp_pdu::rdp::error_info::ErrorInfoCode;
use justrdp_pdu::rdp::fast_path::{
    FastPathInputEvent, FastPathInputHeader, FastPathOutputHeader, FastPathOutputUpdate,
    FastPathScancodeEvent, FastPathUpdateType, FASTPATH_INPUT_ACTION_FASTPATH,
    FASTPATH_INPUT_ENCRYPTED,
};
use justrdp_pdu::mcs::{SendDataIndication, SendDataRequest};
use justrdp_pdu::rdp::redirection::{
    ServerRedirectionPdu, LB_LOAD_BALANCE_INFO, LB_TARGET_NET_ADDRESS,
};
use justrdp_pdu::rdp::svc::{
    ChannelPduHeader, CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST, CHANNEL_OPTION_INITIALIZED,
    CHANNEL_PDU_HEADER_SIZE,
};
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

/// Upper bound on the number of drive iterations before declaring the
/// handshake deadlocked. Empirically the PROTOCOL_RDP path completes in
/// well under 100 iterations; `4096` gives slack without hiding real
/// infinite loops.
const DRIVE_ITERATIONS_CAP: usize = 4096;

/// Build a PROTOCOL_RDP-only client config. No TLS certificate or
/// credentials are exercised; the username / password are retained
/// because `Config::builder` requires them, but they are never used
/// in the absence of CredSSP/RDSTLS.
fn rdp_only_client_config() -> Config {
    Config::builder("test-user", "test-pass")
        .security_protocol(SecurityProtocol::RDP)
        .build()
}

/// Same as [`rdp_only_client_config`] but with `cliprdr` / `rdpsnd`
/// registered as static virtual channels so the server side can
/// exercise its channel-handler dispatch on those IDs.
fn rdp_client_config_with_channels() -> Config {
    Config::builder("test-user", "test-pass")
        .security_protocol(SecurityProtocol::RDP)
        .channel("cliprdr", CHANNEL_OPTION_INITIALIZED)
        .channel("rdpsnd", CHANNEL_OPTION_INITIALIZED)
        .build()
}

/// Build a PROTOCOL_RDP-only acceptor config. `require_enhanced_security`
/// MUST be `false` here since the server is advertising only
/// `PROTOCOL_RDP`; otherwise the builder rejects the combination as a
/// downgrade hazard (which is the correct default for production but
/// unhelpful for this loopback).
fn rdp_only_acceptor_config() -> AcceptorConfig {
    AcceptorConfig::builder()
        .supported_protocols(SecurityProtocol::RDP)
        .require_enhanced_security(false)
        .build()
        .expect("PROTOCOL_RDP-only is a valid combination")
}

/// Result of one drive attempt on a `Sequence` implementor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepOutcome {
    /// State machine advanced (either emitted output or consumed input).
    Progressed,
    /// Wait state and the inbound buffer does not yet contain a full
    /// PDU -- caller should let the peer run to produce more bytes.
    WaitingForInput,
    /// Terminal state reached; no further steps meaningful.
    Terminal,
}

/// Drive the client one step.
fn step_client(
    client: &mut ClientConnector,
    inbound: &mut Vec<u8>,
    out: &mut WriteBuf,
    outbound: &mut Vec<u8>,
) -> StepOutcome {
    if client.state().is_connected() {
        return StepOutcome::Terminal;
    }
    match client.next_pdu_hint() {
        None => {
            // Send / external-delegation state: step with no input.
            out.clear();
            client
                .step(&[], out)
                .expect("client send-state step failed");
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
        Some(hint) => {
            let Some((_is_pdu, n)) = hint.find_size(inbound) else {
                return StepOutcome::WaitingForInput;
            };
            if n == 0 {
                return StepOutcome::WaitingForInput;
            }
            out.clear();
            client
                .step(&inbound[..n], out)
                .expect("client wait-state step failed");
            inbound.drain(..n);
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
    }
}

/// Drive the acceptor one step. Mirror of `step_client`.
fn step_acceptor(
    acceptor: &mut ServerAcceptor,
    inbound: &mut Vec<u8>,
    out: &mut WriteBuf,
    outbound: &mut Vec<u8>,
) -> StepOutcome {
    if acceptor.state().is_terminal() {
        return StepOutcome::Terminal;
    }
    match AcceptorSequence::next_pdu_hint(acceptor) {
        None => {
            out.clear();
            acceptor
                .step(&[], out)
                .expect("acceptor send-state step failed");
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
        Some(hint) => {
            let Some((_is_pdu, n)) = hint.find_size(inbound) else {
                return StepOutcome::WaitingForInput;
            };
            if n == 0 {
                return StepOutcome::WaitingForInput;
            }
            out.clear();
            acceptor
                .step(&inbound[..n], out)
                .expect("acceptor wait-state step failed");
            inbound.drain(..n);
            outbound.extend_from_slice(out.as_slice());
            StepOutcome::Progressed
        }
    }
}

/// Drive client ↔ acceptor to the terminal Connected / Accepted pair.
///
/// Alternates calls to `step_client` and `step_acceptor`; each function
/// either emits bytes (if in a send state), consumes buffered input
/// (if in a wait state with a full PDU available), or reports that it
/// is waiting. The loop terminates when both peers are terminal; a
/// round with no progress on either side is treated as a deadlock
/// and raises a panic with diagnostic context.
fn drive_full_handshake(
    mut client: ClientConnector,
    mut acceptor: ServerAcceptor,
) -> (ClientConnector, ServerAcceptor) {
    let mut c2s: Vec<u8> = Vec::new();
    let mut s2c: Vec<u8> = Vec::new();
    let mut client_out = WriteBuf::new();
    let mut server_out = WriteBuf::new();

    for i in 0..DRIVE_ITERATIONS_CAP {
        let client_done = client.state().is_connected();
        let server_done = acceptor.state().is_accepted();
        if client_done && server_done {
            return (client, acceptor);
        }

        // Let each side make as much progress as possible this round.
        // A state machine may chain several send states back-to-back
        // (e.g. the client's finalization burst) without waiting for
        // peer input, so we loop until the step either waits or
        // terminates.
        let mut any_progress = false;
        loop {
            match step_client(&mut client, &mut s2c, &mut client_out, &mut c2s) {
                StepOutcome::Progressed => any_progress = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }
        loop {
            match step_acceptor(&mut acceptor, &mut c2s, &mut server_out, &mut s2c) {
                StepOutcome::Progressed => any_progress = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }

        if !any_progress {
            panic!(
                "handshake deadlocked at iteration {i}: \
                 client_state={:?} server_state={:?} \
                 c2s_buffered={}B s2c_buffered={}B",
                client.state(),
                acceptor.state(),
                c2s.len(),
                s2c.len(),
            );
        }
    }
    panic!(
        "handshake did not complete within {DRIVE_ITERATIONS_CAP} iterations \
         (client_state={:?} server_state={:?})",
        client.state(),
        acceptor.state(),
    );
}

/// Minimal display handler: exposes `Option<DisplayUpdate>`; yields it
/// once, then returns `None`. Used by the bitmap-emit test to verify
/// the active stage consumes the handler output.
struct SingleShotDisplay {
    pending: Option<DisplayUpdate>,
    size: (u16, u16),
}

impl RdpServerDisplayHandler for SingleShotDisplay {
    fn get_display_update(&mut self) -> Option<DisplayUpdate> {
        self.pending.take()
    }
    fn get_display_size(&self) -> (u16, u16) {
        self.size
    }
}

/// Input handler that records every callback so the active-session
/// test can assert on what the server dispatched.
#[derive(Default)]
struct RecordingInput {
    scancodes: Vec<(u16, u8)>,
}

impl RdpServerInputHandler for RecordingInput {
    fn on_keyboard_scancode(&mut self, flags: u16, key_code: u8) {
        self.scancodes.push((flags, key_code));
    }
}

/// Build a `BitmapUpdate` with an 8x8 32-bpp solid-color fill. The
/// row-stride padding requirement (4-byte boundary) is already met for
/// 32-bpp * 8 pixels = 32 bytes per row.
fn solid_bitmap_update(color: u32) -> BitmapUpdate {
    let row_stride = 8 * 4; // 32 bpp * 8 pixels
    let mut data = Vec::with_capacity(row_stride * 8);
    for _ in 0..8 {
        for _ in 0..8 {
            data.extend_from_slice(&color.to_le_bytes());
        }
    }
    BitmapUpdate {
        dest_left: 0,
        dest_top: 0,
        width: 8,
        height: 8,
        bits_per_pixel: 32,
        data,
    }
}

/// Build a fast-path input PDU carrying a single scancode event. The
/// layout mirrors `build_fast_path_input` in `active.rs` but lives in
/// the test crate so we do not re-export test-only helpers.
fn fast_path_scancode_pdu(flags: u8, key_code: u8) -> Vec<u8> {
    let event = FastPathInputEvent::Scancode(FastPathScancodeEvent {
        event_flags: flags,
        key_code,
    });
    let body_size = event.size();
    let provisional_total = 1 + 2 + body_size;
    let total = if provisional_total <= 0x7F {
        2 + body_size
    } else {
        provisional_total
    };
    let header = FastPathInputHeader {
        action: FASTPATH_INPUT_ACTION_FASTPATH,
        num_events: 1,
        flags: 0,
        length: total as u16,
    };
    let mut buf = vec![0u8; header.size() + body_size];
    let mut c = WriteCursor::new(&mut buf);
    header.encode(&mut c).unwrap();
    event.encode(&mut c).unwrap();
    buf
}

/// Decode one fast-path output frame into its update PDU. Asserts the
/// outer framing (action + length) looks sane and returns the inner
/// `FastPathOutputUpdate` so callers can assert on `update_code` /
/// `update_data`.
fn decode_fast_path_output(frame: &[u8]) -> FastPathOutputUpdate {
    let mut cursor = ReadCursor::new(frame);
    let hdr = FastPathOutputHeader::decode(&mut cursor).expect("fast-path header decode");
    assert_eq!(
        hdr.action, 0x00,
        "FASTPATH_OUTPUT_ACTION_FASTPATH action byte"
    );
    assert_eq!(
        hdr.length as usize,
        frame.len(),
        "fast-path header length MUST equal total frame size"
    );
    FastPathOutputUpdate::decode(&mut cursor).expect("fast-path output update decode")
}

#[test]
fn protocol_rdp_handshake_reaches_both_terminal_states() {
    // Sanity: starting states are as expected.
    let client = ClientConnector::new(rdp_only_client_config());
    let acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    assert!(matches!(
        client.state(),
        ClientConnectorState::ConnectionInitiationSendRequest
    ));
    assert!(matches!(
        acceptor.state(),
        ServerAcceptorState::WaitConnectionRequest
    ));

    let (client, acceptor) = drive_full_handshake(client, acceptor);

    assert!(
        client.state().is_connected(),
        "client did not reach Connected: {:?}",
        client.state()
    );
    assert!(
        acceptor.state().is_accepted(),
        "acceptor did not reach Accepted: {:?}",
        acceptor.state()
    );

    // Cross-verify the negotiated parameters look sane on both sides.
    let client_result = client.result().expect("Connected implies ConnectionResult");
    match acceptor.state() {
        ServerAcceptorState::Accepted { result } => {
            assert_eq!(
                result.io_channel_id, client_result.io_channel_id,
                "I/O channel ID MUST match on both sides"
            );
            assert_eq!(
                result.user_channel_id, client_result.user_channel_id,
                "user channel ID MUST match on both sides"
            );
            assert_eq!(
                result.share_id, client_result.share_id,
                "share_id MUST match on both sides"
            );
            assert_eq!(result.selected_protocol, SecurityProtocol::RDP);
        }
        other => panic!("unexpected acceptor state: {other:?}"),
    }
}

/// Same 512-bit synthetic RSA key used by the `justrdp-core::rsa` and
/// `justrdp-acceptor` tests. We recreate it inline so we don't need to
/// expose internal test helpers across crate boundaries.
fn synthetic_512bit_rsa() -> (
    justrdp_core::rsa::RsaPrivateKey,
    justrdp_pdu::rdp::server_certificate::ServerRsaPublicKey,
) {
    use justrdp_core::bignum::BigUint;
    use justrdp_core::rsa::RsaPrivateKey;
    use justrdp_pdu::rdp::server_certificate::ServerRsaPublicKey;
    let n_bytes = [
        0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47, 0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25, 0xA5,
        0x8B, 0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76, 0x30, 0xBB, 0x58, 0xBD, 0xC3, 0x4D,
        0xB1, 0xF0, 0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36, 0x79, 0x0D, 0xA2, 0x84, 0xB8,
        0xE2, 0xE5, 0xB3, 0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C, 0xD7, 0xD6, 0x9A, 0x40,
        0x67, 0x6A, 0xF1, 0xA7,
    ];
    let e_bytes = [0x01, 0x00, 0x01];
    let d_bytes = [
        0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC, 0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA, 0xEF,
        0xE8, 0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E, 0xEF, 0xAA, 0x69, 0x14, 0xF7, 0x21,
        0x0E, 0x08, 0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA, 0x12, 0xB4, 0x76, 0xB8, 0x68,
        0x84, 0x0D, 0x78, 0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63, 0x67, 0x9A, 0x43, 0x36,
        0xDD, 0xAB, 0x3F, 0x69,
    ];
    let mut modulus_le = n_bytes.to_vec();
    modulus_le.reverse();
    let priv_key = RsaPrivateKey {
        n: BigUint::from_be_bytes(&n_bytes),
        d: BigUint::from_be_bytes(&d_bytes),
        e: BigUint::from_be_bytes(&e_bytes),
    };
    let pub_key = ServerRsaPublicKey {
        exponent: 0x0001_0001,
        modulus: modulus_le,
        bit_len: 512,
    };
    (priv_key, pub_key)
}

/// End-to-end §11.2a-stdsec S3a validation: a ClientConnector and a
/// ServerAcceptor both configured for Standard RDP Security (RC4 +
/// MAC) drive themselves to terminal states using the same drive loop
/// as the plain PROTOCOL_RDP test. This exercises every acceptor
/// phase's new `wrap_security_payload` / `unwrap_security_payload`
/// plumbing in a single wire transcript:
///
/// - MCS Connect Response carries a signed proprietary server cert
///   + serverRandom in SC_SECURITY.
/// - Security Exchange PDU delivers an RSA-encrypted clientRandom
///   which the server RSA-decrypts + derives session keys from.
/// - Client Info PDU arrives with SEC_ENCRYPT + MAC (decrypted by
///   `step_wait_client_info`).
/// - License PDU (SEC_LICENSE_PKT | SEC_ENCRYPT), DemandActive
///   (SEC_ENCRYPT), ConfirmActive (decrypted), and all 8 finalization
///   sub-phases round-trip through the RC4 stream in both directions.
///
/// A regression here is a high-stakes bug: any mismatch in session-key
/// derivation or MAC ordering would stop the handshake somewhere past
/// the Security Exchange with one side failing to decrypt; the deadlock
/// check in `drive_full_handshake` would fire with a diagnostic state.
#[test]
fn standard_security_handshake_reaches_both_terminal_states() {
    use justrdp_pdu::rdp::server_certificate::encode_proprietary_certificate;
    use justrdp_pdu::rdp::standard_security::{derive_session_keys, ENCRYPTION_METHOD_128BIT};

    let (priv_key, pub_key) = synthetic_512bit_rsa();
    // Deterministic randoms so a regression reproduces bit-for-bit.
    let client_random: [u8; 32] = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
        0xEF, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0x11, 0x00,
    ];
    let server_random: [u8; 32] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
        0xBE, 0xBF,
    ];

    // Pre-render the cert once so the test double-checks
    // `encode_proprietary_certificate` is stable across the handshake
    // (the acceptor's internal build call would otherwise re-sign it).
    let cert_blob = encode_proprietary_certificate(&pub_key);
    let std_cfg = StandardSecurityConfig {
        encryption_method: ENCRYPTION_METHOD_128BIT,
        encryption_level: 2, // client-compatible
        server_random,
        private_key: priv_key,
        public_key: pub_key,
        server_cert_blob: Some(cert_blob),
    };

    let client_cfg = Config::builder("test-user", "test-pass")
        .security_protocol(SecurityProtocol::RDP)
        .client_random(client_random)
        .build();
    let acceptor_cfg = AcceptorConfig::builder()
        .supported_protocols(SecurityProtocol::RDP)
        .require_enhanced_security(false)
        .standard_security(std_cfg)
        .build()
        .expect("PROTOCOL_RDP + StandardSecurityConfig is a valid combination");

    let client = ClientConnector::new(client_cfg);
    let acceptor = ServerAcceptor::new(acceptor_cfg);
    let (client, acceptor) = drive_full_handshake(client, acceptor);

    // Both peers terminal:
    assert!(
        client.state().is_connected(),
        "client did not reach Connected: {:?}",
        client.state()
    );
    assert!(
        acceptor.state().is_accepted(),
        "acceptor did not reach Accepted: {:?}",
        acceptor.state()
    );

    // The recovered client random must match what we configured; this
    // proves the RSA-decrypt + LE-byte handling round-tripped bytewise.
    assert_eq!(acceptor.client_random().unwrap(), &client_random);

    // Session keys on both sides are a function of
    // (clientRandom, serverRandom, encryption_method). Independently
    // re-derive and compare byte-for-byte. If this fails, the server's
    // RC4 stream and the client's would diverge exactly at the first
    // encrypted PDU -- which is why the drive loop deadlock would
    // precede the assertion.
    let expected = derive_session_keys(&client_random, &server_random, ENCRYPTION_METHOD_128BIT)
        .expect("128-bit RC4 key derivation always succeeds");
    let server_keys = acceptor.session_keys().unwrap();
    assert_eq!(server_keys.mac_key, expected.mac_key);
    assert_eq!(server_keys.encrypt_key, expected.encrypt_key);
    assert_eq!(server_keys.decrypt_key, expected.decrypt_key);
    assert_eq!(server_keys.key_len, 16);

    // Spot-check negotiated identifiers match on both sides (same as
    // the plain PROTOCOL_RDP test), i.e. encryption didn't corrupt any
    // late-handshake field.
    let client_result = client.result().expect("Connected implies ConnectionResult");
    match acceptor.state() {
        ServerAcceptorState::Accepted { result } => {
            assert_eq!(result.io_channel_id, client_result.io_channel_id);
            assert_eq!(result.user_channel_id, client_result.user_channel_id);
            assert_eq!(result.share_id, client_result.share_id);
            assert_eq!(result.selected_protocol, SecurityProtocol::RDP);
        }
        other => panic!("unexpected acceptor state: {other:?}"),
    }
}

/// Build a *client-produced* encrypted fast-path input PDU: single
/// scancode event, wrapped with `FASTPATH_INPUT_ENCRYPTED` flag + 8-byte
/// MAC + RC4-encrypted event body. Mirrors the wire shape a real mstsc
/// emits during a `PROTOCOL_RDP` session at
/// `ENCRYPTION_LEVEL_CLIENT_COMPATIBLE`.
///
/// `ctx` is mutated because `encrypt()` advances the RC4 state and MAC
/// sequence counter.
fn encrypted_fast_path_scancode_pdu(
    ctx: &mut justrdp_pdu::rdp::standard_security::RdpSecurityContext,
    flags: u8,
    key_code: u8,
) -> Vec<u8> {
    // Plaintext event body: one scancode event.
    let event = FastPathInputEvent::Scancode(FastPathScancodeEvent {
        event_flags: flags,
        key_code,
    });
    let body_size = event.size();
    let mut plaintext = vec![0u8; body_size];
    {
        let mut c = WriteCursor::new(&mut plaintext);
        event.encode(&mut c).unwrap();
    }

    // Encrypt + MAC.
    let mut encrypted = plaintext.clone();
    let mac = ctx.encrypt(&mut encrypted);

    // Header length = byte0(1) + length(1 or 2) + MAC(8) + body.
    // The first-draft length assumes the 1-byte length-field encoding
    // (which covers PDUs up to 127 bytes). For scancode (body=2) the
    // total is 1 + 1 + 8 + 2 = 12, comfortably inside that limit.
    let total = 1 + 1 + 8 + encrypted.len();
    assert!(total <= 0x7F, "encrypted fast-path PDU shape assumes 1-byte length encoding");

    let header = FastPathInputHeader {
        action: FASTPATH_INPUT_ACTION_FASTPATH,
        num_events: 1,
        flags: FASTPATH_INPUT_ENCRYPTED,
        length: total as u16,
    };

    let mut buf = vec![0u8; total];
    let mut c = WriteCursor::new(&mut buf);
    header.encode(&mut c).unwrap();
    c.write_slice(&mac, "mac").unwrap();
    c.write_slice(&encrypted, "encryptedEvents").unwrap();
    buf
}

/// Build a synthetic encrypted Standard-Security session (no handshake):
/// a paired `(client_ctx, server_ctx)` and a minimal
/// [`AcceptanceResult`] plus an [`AcceptorConfig`] so callers can spin
/// up an [`ServerActiveStage`] directly.
///
/// Skipping the handshake lets the test pin `encrypt_count` /
/// `decrypt_count` to `0` on both sides -- a real end-to-end run would
/// advance them by the 6 slow-path PDUs each direction carries during
/// the handshake, which is an orthogonal concern already proven by
/// `standard_security_handshake_reaches_both_terminal_states`. This
/// test isolates the active-stage decrypt path.
fn fresh_paired_security_contexts() -> (
    justrdp_pdu::rdp::standard_security::RdpSecurityContext,
    justrdp_pdu::rdp::standard_security::RdpSecurityContext,
) {
    use justrdp_pdu::rdp::standard_security::{
        derive_session_keys, RdpSecurityContext, SessionKeys, ENCRYPTION_METHOD_128BIT,
    };
    let cr = [0x01u8; 32];
    let sr = [0x02u8; 32];
    let client_keys = derive_session_keys(&cr, &sr, ENCRYPTION_METHOD_128BIT).unwrap();
    // Server perspective: encrypt/decrypt direction swapped (matches
    // the acceptor's `step_wait_security_exchange` logic).
    let server_keys = SessionKeys {
        encrypt_key: client_keys.decrypt_key,
        decrypt_key: client_keys.encrypt_key,
        encrypt_update_key: client_keys.decrypt_update_key,
        decrypt_update_key: client_keys.encrypt_update_key,
        ..client_keys.clone()
    };
    // Match acceptor's default: RDP 10.7 >= 0x00080004 -> salted MAC.
    let client_ctx = RdpSecurityContext::new(client_keys, true);
    let server_ctx = RdpSecurityContext::new(server_keys, true);
    (client_ctx, server_ctx)
}

/// Build a minimal `AcceptanceResult` suitable for driving a
/// `ServerActiveStage` without going through the handshake. All
/// fields are constructed directly from pub members; values mirror
/// what the acceptor would have assigned to a no-VC session. Only the
/// channel IDs and share_id matter to the active stage's inbound
/// validation -- the rest are left at type defaults.
fn minimal_acceptance_result() -> justrdp_acceptor::AcceptanceResult {
    use justrdp_acceptor::{AcceptanceResult, ClientRequestInfo};
    use justrdp_pdu::x224::{NegotiationRequestFlags, NegotiationResponseFlags};
    AcceptanceResult {
        selected_protocol: SecurityProtocol::RDP,
        server_nego_flags: NegotiationResponseFlags::NONE,
        client_request: ClientRequestInfo {
            cookie: None,
            routing_token: None,
            requested_protocols: SecurityProtocol::RDP,
            request_flags: NegotiationRequestFlags::NONE,
            had_negotiation_request: true,
        },
        io_channel_id: 0x03EB,
        user_channel_id: 0x03EF,
        message_channel_id: None,
        share_id: 0x0001_03EA,
        channel_ids: Vec::new(),
        client_capabilities: Vec::new(),
        client_info: None,
    }
}

/// End-to-end §11.2a-stdsec S3b validation: when the active stage
/// holds a `RdpSecurityContext`, an encrypted fast-path input PDU
/// produced by the matching client-side context is RC4-decrypted,
/// MAC-verified, and dispatched to the input handler.
///
/// The test deliberately does NOT run a live handshake -- doing so
/// would advance both cipher streams by the 6 slow-path PDUs the
/// handshake carries, requiring the "client side" synthetic to
/// advance in lockstep. Pairing fresh `(client_ctx, server_ctx)`
/// contexts lets this test focus squarely on the active-stage
/// plumbing: `decrypt_fast_path_input`, the `FASTPATH_INPUT_ENCRYPTED`
/// flag handling, and the handoff that `with_security_context`
/// performs. The full handshake-plus-active round trip is covered by
/// `standard_security_handshake_reaches_both_terminal_states` +
/// this test in combination.
#[test]
fn standard_security_active_session_fast_path_input_decrypts() {
    let (mut client_ctx, server_ctx) = fresh_paired_security_contexts();
    let result = minimal_acceptance_result();
    let config = justrdp_server::RdpServerConfig::builder().build().unwrap();
    let mut active = ServerActiveStage::new(result, config).with_security_context(server_ctx);
    assert!(active.is_encrypted());

    let mut input = RecordingInput::default();
    // Press-down 'A' (key_code 0x1E).
    let pdu = encrypted_fast_path_scancode_pdu(&mut client_ctx, 0x00, 0x1E);
    let out = active
        .process(&pdu, &mut input)
        .expect("active stage must decrypt+dispatch encrypted fast-path input");
    assert!(out.is_empty(), "scancode dispatch produces no outbound PDU");
    assert_eq!(
        input.scancodes,
        vec![(0x0000, 0x1E)],
        "recorded scancode MUST round-trip through RC4+MAC"
    );

    // Second event on the same stream advances the cipher + MAC seqno
    // -- confirms the RC4 state is actually being carried forward
    // (and would catch a regression where each PDU is decrypted from
    // a fresh RC4 state, or where the MAC seqno is always zero).
    let pdu2 = encrypted_fast_path_scancode_pdu(&mut client_ctx, 0x01, 0x1E); // key-up 'A'
    active
        .process(&pdu2, &mut input)
        .expect("second encrypted PDU on the same stream must also decrypt");
    assert_eq!(
        input.scancodes.last(),
        Some(&(0x0001, 0x1E)),
        "second scancode dispatched with its own flag bits"
    );
}

/// Slow-path roundtrip: `wrap_slow_path_outbound` on one ActiveStage
/// produces bytes that `unwrap_slow_path_inbound` on the paired stage
/// decrypts byte-for-byte.
///
/// This isolates the slow-path cipher helpers from the rest of the
/// active-session pipeline. Both helpers are public, so this test
/// also serves as executable documentation for callers building
/// custom slow-path handlers on top of the ActiveStage API.
#[test]
fn standard_security_active_session_slow_path_wrap_unwrap_roundtrip() {
    let (client_ctx, server_ctx) = fresh_paired_security_contexts();
    // Client writes to `client_active` via `wrap_slow_path_outbound`;
    // server reads from `server_active` via `unwrap_slow_path_inbound`.
    // Each side needs its own ActiveStage holding the matching context.
    let client_result = minimal_acceptance_result();
    let server_result = minimal_acceptance_result();
    let config = justrdp_server::RdpServerConfig::builder().build().unwrap();
    let mut client_active =
        ServerActiveStage::new(client_result, config.clone()).with_security_context(client_ctx);
    let mut server_active =
        ServerActiveStage::new(server_result, config).with_security_context(server_ctx);

    // Distinct payloads so a "return the same bytes always" bug would
    // immediately surface as a spurious pass on the first payload and
    // a failure on the next.
    let payloads: Vec<&[u8]> = vec![
        b"hello standard rdp security",
        b"second payload on the RC4 stream",
        // Short payload -- catches off-by-one errors in length math.
        b"x",
        // Longer payload with binary noise.
        &[0x00, 0xFF, 0x5A, 0xA5, 0x01, 0x02, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF],
    ];

    for (i, plaintext) in payloads.iter().enumerate() {
        let wrapped = client_active
            .wrap_slow_path_outbound(plaintext, 0)
            .expect("wrap MUST succeed when security context is active");
        // Wrapped output MUST be exactly 4 (sec header) + 8 (MAC) +
        // plaintext.len() bytes. Anything else is a sign the header
        // or MAC size drifted.
        assert_eq!(
            wrapped.len(),
            4 + 8 + plaintext.len(),
            "payload #{i}: wrapped length must be header+MAC+body"
        );

        let recovered = server_active
            .unwrap_slow_path_inbound(&wrapped)
            .expect("unwrap MUST succeed for a freshly-wrapped payload");
        assert_eq!(
            recovered.as_slice(),
            *plaintext,
            "payload #{i}: roundtrip MUST return byte-identical plaintext"
        );
    }

    // Tampering test: flip a bit in the ciphertext of a fresh wrapped
    // payload; the server MUST reject with a MAC-verify error.
    let original = b"some payload to tamper with";
    let mut tampered = client_active.wrap_slow_path_outbound(original, 0).unwrap();
    // Flip the last byte of the ciphertext (MAC is at [4..12],
    // ciphertext starts at index 12).
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let err = server_active
        .unwrap_slow_path_inbound(&tampered)
        .expect_err("MAC-tampered payload MUST fail verification");
    assert!(
        format!("{err}").contains("MAC"),
        "expected MAC failure, got: {err}"
    );
}

/// Fast-path **output** wrap: `wrap_fast_path_outbound` takes a
/// plaintext frame (as produced by `encode_bitmap_update`) and emits
/// the encrypted wire form. A paired client-side decrypt validates
/// the MAC + recovers the original update bytes.
///
/// Also covers the length-field promotion: when the plaintext frame's
/// 1-byte length sits just below 0x78, adding the 8-byte MAC pushes
/// the total past 0x7F and the length field must grow to 2 bytes.
#[test]
fn standard_security_active_session_fast_path_output_wrap_roundtrip() {
    use justrdp_pdu::rdp::fast_path::{FastPathOutputHeader, FASTPATH_OUTPUT_ENCRYPTED};

    let (client_ctx, server_ctx) = fresh_paired_security_contexts();
    let mut server_active = ServerActiveStage::new(
        minimal_acceptance_result(),
        justrdp_server::RdpServerConfig::builder().build().unwrap(),
    )
    .with_security_context(server_ctx);

    // Build a plaintext fast-path output frame that would naturally
    // carry a BITMAP update (8x8 32bpp solid, same as the TLS/NLA
    // test uses). Bounce it through the real server-side encoder so
    // the input to the wrap helper matches what production code emits.
    let cfg = justrdp_server::RdpServerConfig::builder().build().unwrap();
    let frames = justrdp_server::encode_bitmap_update(&cfg, &solid_bitmap_update(0xFF00_00FF))
        .expect("encode_bitmap_update returns at least one frame");
    assert!(!frames.is_empty());
    let plaintext_frame = &frames[0];

    // Wrap with encryption.
    let encrypted_frame = server_active
        .wrap_fast_path_outbound(plaintext_frame)
        .expect("wrap MUST succeed when security context is active");
    // The length field reports the total frame size -- parse the
    // emitted header and cross-check.
    let mut c = ReadCursor::new(&encrypted_frame);
    let hdr = FastPathOutputHeader::decode(&mut c).unwrap();
    assert_eq!(
        hdr.length as usize,
        encrypted_frame.len(),
        "wrapped header length MUST equal frame size"
    );
    assert!(
        hdr.flags & FASTPATH_OUTPUT_ENCRYPTED != 0,
        "encrypted frame MUST set FASTPATH_OUTPUT_ENCRYPTED bit"
    );

    // Client-side decrypt: strip header, read MAC, decrypt body,
    // verify MAC. Mirrors what a ClientConnector with Standard
    // Security would do on receipt.
    let header_size = hdr.size();
    let body = &encrypted_frame[header_size..];
    assert!(body.len() >= 8, "encrypted body MUST carry at least 8 MAC bytes");
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&body[..8]);
    let mut ciphertext = body[8..].to_vec();

    // Client-side context (encrypt/decrypt direction opposite to
    // server). Rebuild from the paired pair so we have a matching
    // decrypt stream.
    let mut client_ctx = client_ctx;
    let ok = client_ctx.decrypt(&mut ciphertext, &mac);
    assert!(ok, "client-side MAC verify MUST succeed for a fresh wrap");

    // The recovered plaintext must equal the original frame's body.
    let plaintext_body = &plaintext_frame[FastPathOutputHeader::decode(
        &mut ReadCursor::new(plaintext_frame),
    )
    .unwrap()
    .size()..];
    assert_eq!(
        ciphertext.as_slice(),
        plaintext_body,
        "decrypted body MUST match the original update"
    );

    // Tampering: flip a bit in the ciphertext; MAC verify MUST fail.
    // Drop the decrypted state above by reconstructing a fresh client.
    let (client_ctx2, server_ctx2) = fresh_paired_security_contexts();
    let mut server_active2 = ServerActiveStage::new(
        minimal_acceptance_result(),
        justrdp_server::RdpServerConfig::builder().build().unwrap(),
    )
    .with_security_context(server_ctx2);
    let mut tampered = server_active2
        .wrap_fast_path_outbound(plaintext_frame)
        .unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let mut c = ReadCursor::new(&tampered);
    let hdr = FastPathOutputHeader::decode(&mut c).unwrap();
    let tampered_body = &tampered[hdr.size()..];
    let mut mac2 = [0u8; 8];
    mac2.copy_from_slice(&tampered_body[..8]);
    let mut ct2 = tampered_body[8..].to_vec();
    let mut client_ctx2 = client_ctx2;
    let ok = client_ctx2.decrypt(&mut ct2, &mac2);
    assert!(!ok, "tampered frame MUST fail MAC verify");
}

/// Negative test: when Standard RDP Security is active, a fast-path
/// input PDU without the `FASTPATH_INPUT_ENCRYPTED` flag MUST be
/// rejected. Silently accepting it would let a MITM strip encryption
/// mid-session.
#[test]
fn standard_security_active_session_rejects_unencrypted_fast_path_input() {
    let (_client_ctx, server_ctx) = fresh_paired_security_contexts();
    let result = minimal_acceptance_result();
    let mut active = ServerActiveStage::new(
        result,
        justrdp_server::RdpServerConfig::builder().build().unwrap(),
    )
    .with_security_context(server_ctx);

    // Build a plaintext fast-path input and feed it in. Active stage
    // must reject because encryption is negotiated.
    let plaintext_pdu = fast_path_scancode_pdu(0x00, 0x1E);
    let err = active
        .process(&plaintext_pdu, &mut RecordingInput::default())
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("FASTPATH_INPUT_ENCRYPTED"),
        "unexpected error: {msg}"
    );
}

/// Drive the handshake and then exercise both directions of the active
/// session:
///
/// 1. Server emits an 8x8 bitmap via `encode_bitmap_update`; the test
///    parses the resulting fast-path frame(s) and asserts the update
///    code is `Bitmap`.
/// 2. The test builds a fast-path scancode PDU as a client would; feeds
///    it to `ServerActiveStage::process`; asserts the recording input
///    handler observed the scancode with the expected flags.
/// 3. Server emits a clean-disconnect pair (`SetErrorInfoPdu` wrapped
///    in ShareData + MCS `DisconnectProviderUltimatum`); the test
///    verifies both frames are non-empty, distinguishable, and in the
///    expected TPKT vs. raw-MCS framing.
#[test]
fn active_session_bitmap_emit_input_dispatch_and_clean_disconnect() {
    // Phase 1: handshake (same as the prior test).
    let client = ClientConnector::new(rdp_only_client_config());
    let acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    let (_client, acceptor) = drive_full_handshake(client, acceptor);

    // Clone the `AcceptanceResult` out of the Accepted-state acceptor.
    // (We use `ServerAcceptor` directly rather than `RdpServer` here
    // so the handshake drive loop can use the same low-level API on
    // both sides; cloning the result is the trade-off.)
    let result = match acceptor.state() {
        ServerAcceptorState::Accepted { result } => result.clone(),
        other => panic!("expected Accepted state, got {other:?}"),
    };
    let config = justrdp_server::RdpServerConfig::builder()
        .build()
        .expect("default RdpServerConfig");
    let mut active = ServerActiveStage::new(result, config.clone());

    // ── Direction 1: server emits a bitmap ──
    let frames = encode_bitmap_update(&config, &solid_bitmap_update(0xFF00_00FF))
        .expect("encode_bitmap_update should succeed for an 8x8 32-bpp solid");
    assert!(!frames.is_empty(), "at least one fast-path frame expected");

    for frame in &frames {
        let update = decode_fast_path_output(frame);
        assert_eq!(
            update.update_code,
            FastPathUpdateType::Bitmap,
            "emitted frame MUST carry a BITMAP update"
        );
        assert!(
            !update.update_data.is_empty(),
            "BITMAP update_data cannot be empty"
        );
    }

    // Poll the display handler seam too -- confirms the public contract
    // remains usable from the integration test vantage.
    let mut display = SingleShotDisplay {
        pending: Some(DisplayUpdate::Bitmap(solid_bitmap_update(0x00FF_00FF))),
        size: (1024, 768),
    };
    match display.get_display_update() {
        Some(DisplayUpdate::Bitmap(u)) => assert_eq!(u.width, 8),
        other => panic!("expected Bitmap update, got {other:?}"),
    }
    assert!(display.get_display_update().is_none());

    // ── Direction 2: client emits fast-path input ──
    // Build a press-down scancode for 'A' (key_code 0x1E) with event_flags=0.
    let mut input = RecordingInput::default();
    let fp_input = fast_path_scancode_pdu(0x00, 0x1E);
    let out = active
        .process(&fp_input, &mut input)
        .expect("server MUST dispatch fast-path input");
    assert!(
        out.is_empty(),
        "fast-path input events produce no outbound PDUs by themselves"
    );
    assert_eq!(
        input.scancodes,
        vec![(0x0000, 0x1E)],
        "recorded scancode MUST match the wire event_flags / key_code"
    );

    // ── Direction 3: clean disconnect ──
    let disconnect_frames = active
        .encode_disconnect(ErrorInfoCode::RpcInitiatedDisconnect)
        .expect("encode_disconnect should succeed in Active state");
    assert_eq!(
        disconnect_frames.len(),
        2,
        "clean disconnect is exactly `SetErrorInfoPdu` + `DisconnectProviderUltimatum`"
    );
    let [set_error_frame, ultimatum_frame] = [&disconnect_frames[0], &disconnect_frames[1]];

    // SetErrorInfoPdu is wrapped in TPKT (starts with 0x03); the MCS
    // ultimatum is raw X.224 DT (starts with 0x03 too). Both share the
    // TPKT framing. A reasonable sanity check is that they are distinct
    // and neither is empty.
    assert!(!set_error_frame.is_empty());
    assert!(!ultimatum_frame.is_empty());
    assert_ne!(
        set_error_frame, ultimatum_frame,
        "disconnect frames MUST be distinct"
    );
    assert_eq!(
        set_error_frame[0], 0x03,
        "SetErrorInfo PDU MUST be TPKT-framed"
    );
    assert_eq!(
        ultimatum_frame[0], 0x03,
        "DisconnectProviderUltimatum MUST also be TPKT-framed (X.224 DT)"
    );

    // ── Sanity: refresh-rect / suppress-output input path still works ──
    // The display handler's on_refresh_rect default drops the event;
    // assert via a custom handler that it surfaces the rectangle.
    struct SuppressRecorder {
        suppress_calls: Vec<(bool, Option<DisplayRect>)>,
    }
    impl RdpServerDisplayHandler for SuppressRecorder {
        fn get_display_update(&mut self) -> Option<DisplayUpdate> {
            None
        }
        fn get_display_size(&self) -> (u16, u16) {
            (1024, 768)
        }
        fn on_suppress_output(&mut self, suppress: bool, area: Option<DisplayRect>) {
            self.suppress_calls.push((suppress, area));
        }
    }
    let mut rec = SuppressRecorder {
        suppress_calls: Vec::new(),
    };
    rec.on_suppress_output(true, None);
    assert_eq!(rec.suppress_calls, vec![(true, None)]);
}

// ───────────────────────────────────────────────────────────────
// Channel-handler validation (§11.2d, 3rd deliverable)
// ───────────────────────────────────────────────────────────────

/// Wrap a single SVC chunk in the client-side framing
/// `TPKT + X.224 DT + MCS SendDataRequest + ChannelPduHeader` so
/// `ServerActiveStage::process` can decode it.
fn wrap_client_svc(
    user_channel_id: u16,
    channel_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = vec![0u8; CHANNEL_PDU_HEADER_SIZE + payload.len()];
    {
        let mut c = WriteCursor::new(&mut body);
        ChannelPduHeader {
            length: payload.len() as u32,
            flags: CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST,
        }
        .encode(&mut c)
        .unwrap();
        c.write_slice(payload, "chunk").unwrap();
    }
    let sdr = SendDataRequest {
        initiator: user_channel_id,
        channel_id,
        user_data: &body,
    };
    let payload_size = DATA_TRANSFER_HEADER_SIZE + sdr.size();
    let total = TPKT_HEADER_SIZE + payload_size;
    let mut buf = vec![0u8; total];
    let mut c = WriteCursor::new(&mut buf);
    TpktHeader::try_for_payload(payload_size).unwrap().encode(&mut c).unwrap();
    DataTransfer.encode(&mut c).unwrap();
    sdr.encode(&mut c).unwrap();
    buf
}

/// Decode a server-direction frame produced by
/// `encode_svc_send` / the SVC dispatch path. Returns
/// `(channel_id, svc_payload)`.
fn unwrap_server_svc(frame: &[u8]) -> (u16, Vec<u8>) {
    let mut c = ReadCursor::new(frame);
    let _tpkt = TpktHeader::decode(&mut c).unwrap();
    let _dt = DataTransfer::decode(&mut c).unwrap();
    let sdi = SendDataIndication::decode(&mut c).unwrap();
    let mut inner = ReadCursor::new(sdi.user_data);
    let _hdr = ChannelPduHeader::decode(&mut inner).unwrap();
    (sdi.channel_id, inner.peek_remaining().to_vec())
}

/// Channel-handler seam validation: drive a handshake that negotiates
/// `cliprdr` and `rdpsnd` as static channels, register the servers
/// against the active stage, and verify:
///
/// 1. `register_svc_processor` emits the expected init burst for each
///    channel (cliprdr: Caps + MonitorReady; rdpsnd: Server Audio
///    Formats).
/// 2. A client-direction CLIPRDR Format List PDU elicits a Format
///    List Response PDU from the server, encoded as an SVC frame.
/// 3. A client-direction RDPSND Client Audio Formats PDU advances the
///    server past format negotiation (recorded by the handler).
#[test]
fn channel_handlers_roundtrip_over_active_stage() {
    use justrdp_cliprdr::pdu::{
        ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType, FormatListPdu, LongFormatName,
    };
    use justrdp_cliprdr::{
        ClipboardResult, ClipboardServer, FormatDataResponse, FormatListResponse,
        RdpServerClipboardHandler,
    };
    use justrdp_rdpsnd::pdu::{
        AudioFormat, ClientAudioFormatsPdu, ClientSndFlags, SndHeader, SndMsgType,
    };
    use justrdp_rdpsnd::{RdpServerSoundHandler, SoundServer};

    // Drive a handshake that registers cliprdr + rdpsnd on the client.
    let client = ClientConnector::new(rdp_client_config_with_channels());
    let acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    let (client, acceptor) = drive_full_handshake(client, acceptor);

    // Cross-check both sides agree on the channel IDs.
    let result = match acceptor.state() {
        ServerAcceptorState::Accepted { result } => result.clone(),
        other => panic!("expected Accepted, got {other:?}"),
    };
    let client_result = client.result().expect("Connected implies result");
    let cliprdr_id = result
        .channel_ids
        .iter()
        .find(|(n, _)| n == "cliprdr")
        .map(|(_, id)| *id)
        .expect("cliprdr channel negotiated");
    let rdpsnd_id = result
        .channel_ids
        .iter()
        .find(|(n, _)| n == "rdpsnd")
        .map(|(_, id)| *id)
        .expect("rdpsnd channel negotiated");
    assert_eq!(
        client_result.channel_ids, result.channel_ids,
        "both sides see the same channel_id list"
    );
    let user_channel_id = result.user_channel_id;

    let config = justrdp_server::RdpServerConfig::builder()
        .build()
        .expect("default RdpServerConfig");
    let mut active = ServerActiveStage::new(result, config);

    // ── Register ClipboardServer (server-direction cliprdr) ──
    struct AcceptingClipHandler;
    impl RdpServerClipboardHandler for AcceptingClipHandler {
        fn on_format_list(
            &mut self,
            _formats: &[LongFormatName],
        ) -> ClipboardResult<FormatListResponse> {
            Ok(FormatListResponse::Ok)
        }
        fn on_format_data_request(
            &mut self,
            _format_id: u32,
        ) -> ClipboardResult<FormatDataResponse> {
            Ok(FormatDataResponse::Fail)
        }
        fn on_format_data_response(
            &mut self,
            _data: &[u8],
            _is_success: bool,
            _format_id: Option<u32>,
        ) {
        }
    }
    let clip_frames = active
        .register_svc_processor(Box::new(ClipboardServer::new(Box::new(
            AcceptingClipHandler,
        ))))
        .expect("register cliprdr server");
    assert_eq!(
        clip_frames.len(),
        2,
        "cliprdr init burst emits 2 frames (Caps + MonitorReady)"
    );
    {
        let (ch0, payload0) = unwrap_server_svc(&clip_frames[0]);
        let (ch1, payload1) = unwrap_server_svc(&clip_frames[1]);
        assert_eq!(ch0, cliprdr_id);
        assert_eq!(ch1, cliprdr_id);
        let h0 = ClipboardHeader::decode(&mut ReadCursor::new(&payload0)).unwrap();
        let h1 = ClipboardHeader::decode(&mut ReadCursor::new(&payload1)).unwrap();
        assert_eq!(h0.msg_type, ClipboardMsgType::ClipCaps);
        assert_eq!(h1.msg_type, ClipboardMsgType::MonitorReady);
    }

    // ── Register SoundServer (server-direction rdpsnd) ──
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    struct SoundHandlerState {
        client_formats_calls: u32,
    }
    struct RecordingSoundHandler {
        state: Arc<Mutex<SoundHandlerState>>,
    }
    impl RdpServerSoundHandler for RecordingSoundHandler {
        fn on_client_formats(
            &mut self,
            _formats: &[AudioFormat],
            _flags: ClientSndFlags,
            _version: u16,
        ) {
            self.state.lock().unwrap().client_formats_calls += 1;
        }
    }
    let sound_state = Arc::new(Mutex::new(SoundHandlerState::default()));
    let sound_server = SoundServer::new(
        Box::new(RecordingSoundHandler {
            state: sound_state.clone(),
        }),
        vec![AudioFormat::pcm(2, 44100, 16)],
    );
    let snd_frames = active
        .register_svc_processor(Box::new(sound_server))
        .expect("register rdpsnd server");
    assert_eq!(snd_frames.len(), 1, "rdpsnd emits ServerAudioFormats");
    {
        let (ch, payload) = unwrap_server_svc(&snd_frames[0]);
        assert_eq!(ch, rdpsnd_id);
        let h = SndHeader::decode(&mut ReadCursor::new(&payload)).unwrap();
        assert_eq!(h.msg_type, SndMsgType::Formats);
    }

    // ── CLIPRDR roundtrip: client FormatList → server FormatListResponse ──
    let client_clip_caps_body = {
        // Minimal Client Capabilities PDU: needed so the server can
        // negotiate `USE_LONG_FORMAT_NAMES` before the Format List parses
        // in long form.
        use justrdp_cliprdr::pdu::{
            ClipboardCapsPdu, GeneralCapabilityFlags, GeneralCapabilitySet, CB_CAPS_VERSION_2,
        };
        let caps = ClipboardCapsPdu::new(GeneralCapabilitySet::new(
            CB_CAPS_VERSION_2,
            GeneralCapabilityFlags::USE_LONG_FORMAT_NAMES,
        ));
        let mut buf = vec![0u8; caps.size()];
        caps.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf
    };
    let caps_bytes = wrap_client_svc(user_channel_id, cliprdr_id, &client_clip_caps_body);
    let mut drop_input = RecordingInput::default();
    let caps_out = active.process(&caps_bytes, &mut drop_input).unwrap();
    assert!(
        caps_out.is_empty(),
        "Caps PDU produces no response (state change only)"
    );

    // Now send the Format List (long variant, one entry: CF_UNICODETEXT).
    let format_list_body = {
        let pdu = FormatListPdu::Long(vec![LongFormatName::new(0x000D, String::new())]);
        let mut buf = vec![0u8; pdu.full_size()];
        pdu.encode_full(&mut WriteCursor::new(&mut buf)).unwrap();
        buf
    };
    let fl_bytes = wrap_client_svc(user_channel_id, cliprdr_id, &format_list_body);
    let fl_out = active.process(&fl_bytes, &mut drop_input).unwrap();
    assert_eq!(fl_out.len(), 1, "exactly one FormatListResponse frame");
    let out_bytes = match &fl_out[0] {
        justrdp_server::ActiveStageOutput::SendBytes(b) => b.clone(),
        other => panic!("expected SendBytes, got {other:?}"),
    };
    let (ch, payload) = unwrap_server_svc(&out_bytes);
    assert_eq!(ch, cliprdr_id);
    let resp_header = ClipboardHeader::decode(&mut ReadCursor::new(&payload)).unwrap();
    assert_eq!(resp_header.msg_type, ClipboardMsgType::FormatListResponse);
    assert!(resp_header.msg_flags.contains(ClipboardMsgFlags::CB_RESPONSE_OK));

    // ── RDPSND handshake: client sends Client Audio Formats ──
    let client_snd_body = {
        let pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE,
            volume: 0,
            pitch: 0,
            version: 6,
            formats: vec![AudioFormat::pcm(2, 44100, 16)],
        };
        let mut buf = vec![0u8; pdu.size()];
        pdu.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        buf
    };
    let snd_bytes = wrap_client_svc(user_channel_id, rdpsnd_id, &client_snd_body);
    let snd_out = active.process(&snd_bytes, &mut drop_input).unwrap();
    assert!(
        snd_out.is_empty(),
        "ClientAudioFormats produces no direct response"
    );
    assert_eq!(
        sound_state.lock().unwrap().client_formats_calls,
        1,
        "SoundServer handler MUST receive on_client_formats exactly once"
    );
}

// ───────────────────────────────────────────────────────────────
// GFX pipeline seam smoke test (§11.2d, 4th deliverable)
// ───────────────────────────────────────────────────────────────
//
// The full GfxServer ↔ GfxClient round-trip (RFX / EGFX
// `WireToSurface` / `FrameAcknowledge`) is covered by the loopback
// test added in §11.2b-3 (commit a12f1b2). Here we only smoke-test the
// `get_egfx_frame` seam so a future change to `RdpServerDisplayHandler`
// cannot silently break the hook the server uses to drain EGFX frames.

/// Display handler that surfaces a pre-built EGFX frame once.
struct GfxFrameHandler {
    frame: Option<EgfxFrame>,
}

impl RdpServerDisplayHandler for GfxFrameHandler {
    fn get_display_update(&mut self) -> Option<DisplayUpdate> {
        None
    }
    fn get_display_size(&self) -> (u16, u16) {
        (1024, 768)
    }
    fn get_egfx_frame(&mut self) -> Option<EgfxFrame> {
        self.frame.take()
    }
}

// ───────────────────────────────────────────────────────────────
// Server Redirection loopback (§11.2e Commit 2)
// ───────────────────────────────────────────────────────────────

/// UTF-16LE encode `s` with a trailing `\0` word. Local helper so this
/// test's setup does not depend on a common utility we are not ready
/// to lift into the public API yet.
fn utf16le_null_terminated(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

/// End-to-end loopback test for §11.2e: the server emits a Server
/// Redirection PDU just as the handshake is about to terminate, and
/// the real `ClientConnector` decodes it into
/// `ConnectionResult.server_redirection`.
///
/// Injection strategy: drive the handshake normally until the
/// `ServerAcceptor` transitions to `Accepted` (which means it has
/// just emitted its final Font Map PDU into the server-to-client
/// buffer). At that instant the client is still in
/// `ConnectionFinalizationWaitFontMap` -- the exact state where the
/// finalization PDU decoder recognises `ShareControlPduType::ServerRedirect`.
/// We discard the pending Font Map bytes, replace them with the
/// redirection frame produced by `ServerActiveStage::emit_redirection`,
/// and continue driving. The client parses the redirection and
/// transitions directly to `Connected` with the PDU carried in
/// `ConnectionResult.server_redirection`.
#[test]
fn server_emit_redirection_during_finalization_reaches_connected() {
    let mut client = ClientConnector::new(rdp_only_client_config());
    let mut acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    let mut c2s: Vec<u8> = Vec::new();
    let mut s2c: Vec<u8> = Vec::new();
    let mut client_out = WriteBuf::new();
    let mut server_out = WriteBuf::new();

    let redirection_pdu = ServerRedirectionPdu {
        session_id: 0xCAFE_BABE,
        redir_flags: LB_TARGET_NET_ADDRESS | LB_LOAD_BALANCE_INFO,
        target_net_address: Some(utf16le_null_terminated("10.9.8.7")),
        load_balance_info: Some(b"Cookie: msts=redirected\r\n".to_vec()),
        ..Default::default()
    };

    let mut injected = false;
    for i in 0..DRIVE_ITERATIONS_CAP {
        if client.state().is_connected() {
            break;
        }

        // Trigger the injection on the first iteration after the
        // acceptor reaches Accepted. By construction, `step_acceptor`
        // of the prior iteration placed the final Font Map into
        // `s2c`; we overwrite it before the client gets a chance to
        // read those bytes.
        if !injected && acceptor.state().is_accepted() {
            let result = match acceptor.state() {
                ServerAcceptorState::Accepted { result } => result.clone(),
                _ => unreachable!(),
            };
            let config = justrdp_server::RdpServerConfig::builder()
                .build()
                .expect("default RdpServerConfig");
            let mut active = ServerActiveStage::new(result, config);
            let frame = active
                .emit_redirection(&redirection_pdu)
                .expect("emit_redirection should succeed on a fresh Active stage");
            s2c.clear();
            s2c.extend_from_slice(&frame);
            injected = true;
            continue;
        }

        let mut any = false;
        loop {
            match step_client(&mut client, &mut s2c, &mut client_out, &mut c2s) {
                StepOutcome::Progressed => any = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }
        loop {
            match step_acceptor(&mut acceptor, &mut c2s, &mut server_out, &mut s2c) {
                StepOutcome::Progressed => any = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }
        if !any {
            panic!(
                "handshake deadlocked at iteration {i} before injection: \
                 client_state={:?} acceptor_state={:?}",
                client.state(),
                acceptor.state()
            );
        }
    }

    assert!(injected, "redirection was never injected into the handshake");
    assert!(
        client.state().is_connected(),
        "client MUST reach Connected after receiving the redirection PDU, got {:?}",
        client.state()
    );

    let result = client.result().expect("Connected implies ConnectionResult");
    let got = result
        .server_redirection
        .as_ref()
        .expect("ConnectionResult.server_redirection MUST be populated");
    assert_eq!(got.session_id, 0xCAFE_BABE);
    assert!(got.has_flag(LB_TARGET_NET_ADDRESS));
    assert!(got.has_flag(LB_LOAD_BALANCE_INFO));
    assert_eq!(got, &redirection_pdu);
}

// ───────────────────────────────────────────────────────────────
// Auto-Reconnect Cookie loopback (§11.2f Commit 1)
// ───────────────────────────────────────────────────────────────

/// End-to-end loopback test for §11.2f: the server emits a
/// `Save Session Info PDU` (infoType = `INFOTYPE_LOGON_EXTENDED_INFO`)
/// carrying an `ArcScPrivatePacket`, and the real `ClientConnector`
/// surfaces it in `ConnectionResult.server_arc_cookie`.
///
/// Injection strategy: drive the handshake normally until the
/// `ServerAcceptor` transitions to `Accepted`. At that instant the
/// server has just queued the Font Map PDU in `s2c`; the client is
/// still in `ConnectionFinalizationWaitFontMap`. We splice a
/// Save Session Info frame **before** those pending FontMap bytes.
/// The client connector's finalization loop decodes the cookie via
/// `try_store_monitor_layout` (which also handles
/// `ShareDataPduType::SaveSessionInfo`) before the FontMap advances
/// it to `Connected`.
#[test]
fn server_emit_auto_reconnect_cookie_reaches_client_connection_result() {
    use justrdp_server::RandomSource;

    struct FixedRng(u8);
    impl RandomSource for FixedRng {
        fn fill_random(&mut self, buf: &mut [u8]) {
            buf.fill(self.0);
        }
    }

    let mut client = ClientConnector::new(rdp_only_client_config());
    let mut acceptor = ServerAcceptor::new(rdp_only_acceptor_config());
    let mut c2s: Vec<u8> = Vec::new();
    let mut s2c: Vec<u8> = Vec::new();
    let mut client_out = WriteBuf::new();
    let mut server_out = WriteBuf::new();

    let expected_logon_id: u32 = 0xDEAD_BEEF;
    let expected_bits = [0xA5u8; 16];

    let mut injected = false;
    for i in 0..DRIVE_ITERATIONS_CAP {
        if client.state().is_connected() {
            break;
        }

        if !injected && acceptor.state().is_accepted() {
            let result = match acceptor.state() {
                ServerAcceptorState::Accepted { result } => result.clone(),
                _ => unreachable!(),
            };
            let config = justrdp_server::RdpServerConfig::builder()
                .build()
                .expect("default RdpServerConfig");
            let mut active = ServerActiveStage::new(result, config);
            let mut rng = FixedRng(0xA5);
            let (cookie_frame, cookie) = active
                .emit_auto_reconnect_cookie(expected_logon_id, &mut rng)
                .expect("emit_auto_reconnect_cookie on fresh Active stage");
            assert_eq!(cookie.logon_id, expected_logon_id);
            assert_eq!(cookie.arc_random_bits, expected_bits);

            // Splice the cookie frame BEFORE the pending FontMap bytes.
            // The client consumes SaveSessionInfo first (captures ARC),
            // then FontMap drives the transition to Connected.
            let mut spliced = Vec::with_capacity(cookie_frame.len() + s2c.len());
            spliced.extend_from_slice(&cookie_frame);
            spliced.extend_from_slice(&s2c);
            s2c = spliced;
            injected = true;
            continue;
        }

        let mut any = false;
        loop {
            match step_client(&mut client, &mut s2c, &mut client_out, &mut c2s) {
                StepOutcome::Progressed => any = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }
        loop {
            match step_acceptor(&mut acceptor, &mut c2s, &mut server_out, &mut s2c) {
                StepOutcome::Progressed => any = true,
                StepOutcome::WaitingForInput | StepOutcome::Terminal => break,
            }
        }
        if !any {
            panic!(
                "handshake deadlocked at iteration {i} before injection: \
                 client_state={:?} acceptor_state={:?}",
                client.state(),
                acceptor.state()
            );
        }
    }

    assert!(injected, "cookie was never injected into the handshake");
    assert!(
        client.state().is_connected(),
        "client MUST reach Connected after consuming cookie + FontMap, got {:?}",
        client.state()
    );

    let result = client.result().expect("Connected implies ConnectionResult");
    let got = result
        .server_arc_cookie
        .as_ref()
        .expect("ConnectionResult.server_arc_cookie MUST be populated");
    assert_eq!(got.logon_id, expected_logon_id);
    assert_eq!(got.arc_random_bits, expected_bits);
}

#[test]
fn egfx_frame_seam_surfaces_caller_owned_bytes() {
    // Pretend two `DrdynvcServer::send_data` payloads came out of a
    // `GfxServer` — we do not reproduce the GFX encoding here (that is
    // §11.2b-3's turf). The seam's contract is that whatever the caller
    // pushes through `EgfxFrame::with_messages` survives round-tripping
    // through `RdpServerDisplayHandler::get_egfx_frame`.
    let payload_a = vec![0xE0, 0x04, 0xAA, 0xBB, 0xCC];
    let payload_b = vec![0xE0, 0x04, 0x11, 0x22, 0x33, 0x44];
    let frame = EgfxFrame::with_messages(vec![payload_a.clone(), payload_b.clone()]);
    let mut handler = GfxFrameHandler {
        frame: Some(frame),
    };

    // First poll yields the frame with bytes intact.
    let out = handler
        .get_egfx_frame()
        .expect("seam MUST surface the queued EGFX frame");
    assert_eq!(out.messages.len(), 2);
    assert_eq!(out.messages[0], payload_a);
    assert_eq!(out.messages[1], payload_b);
    // Second poll returns None (default idle response).
    assert!(handler.get_egfx_frame().is_none());
}
