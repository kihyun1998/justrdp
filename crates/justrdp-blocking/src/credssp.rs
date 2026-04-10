#![forbid(unsafe_code)]

//! CredSSP / NLA driver for the blocking runtime.
//!
//! Drives a [`CredsspSequence`] to completion over an arbitrary
//! [`Read`] + [`Write`] transport (typically the post-TLS-upgrade stream).
//! The connector itself treats `Credssp*` states as "send states" that just
//! advance internal state — the *actual* token exchange is performed here.
//!
//! Token framing: every CredSSP message except the HYBRID_EX
//! `EarlyUserAuthResult` is a top-level ASN.1 SEQUENCE (TsRequest) and is
//! framed by [`crate::transport::read_asn1_sequence`]. The
//! `EarlyUserAuthResult` is either a fixed 4-byte little-endian status
//! code (MS-RDPBCGR 5.4.2.2) or a fallback TsRequest, so the wait branch
//! peeks the first byte before deciding.

use std::io::{Read, Write};

use justrdp_connector::{ClientConnector, CredsspRandom, CredsspSequence, CredsspState};
use justrdp_pdu::x224::SecurityProtocol;

use crate::error::ConnectError;
use crate::transport::{read_asn1_sequence, read_exact_or_eof, write_all};

/// Drive a full CredSSP exchange over `transport`.
///
/// Reads credentials and randomness from the connector's [`Config`] and
/// uses [`getrandom`] to fill the `CredsspRandom` fields. The function
/// returns once the underlying [`CredsspSequence`] reaches
/// [`CredsspState::Done`]. The connector is *not* stepped here — the caller
/// is expected to advance the connector's `Credssp*` no-op states
/// afterwards (those just transition the connector's internal state).
pub fn run_credssp_sequence<S: Read + Write>(
    connector: &ClientConnector,
    transport: &mut S,
    server_public_key: Vec<u8>,
) -> Result<(), ConnectError> {
    let config = connector.config();
    let username = config.credentials.username.as_str();
    let password = config.credentials.password.as_str();
    let domain = config.domain.as_deref().unwrap_or("");
    let use_hybrid_ex = connector
        .selected_protocol()
        .contains(SecurityProtocol::HYBRID_EX);

    let random = generate_credssp_random()?;
    let credential_type = connector.credssp_credential_type();

    let mut credssp = CredsspSequence::with_credential_type(
        username,
        password,
        domain,
        server_public_key,
        random,
        use_hybrid_ex,
        credential_type,
    );

    let mut scratch: Vec<u8> = Vec::new();

    loop {
        match credssp.state() {
            CredsspState::Done => return Ok(()),

            CredsspState::SendNegoToken | CredsspState::SendCredentials => {
                let bytes = credssp.step(&[])?;
                if !bytes.is_empty() {
                    write_all(transport, &bytes)?;
                }
            }

            CredsspState::WaitChallenge | CredsspState::WaitPubKeyAuth => {
                let n = read_asn1_sequence(transport, &mut scratch)?;
                let response = credssp.step(&scratch[..n])?;
                if !response.is_empty() {
                    write_all(transport, &response)?;
                }
            }

            CredsspState::WaitEarlyUserAuth => {
                // EarlyUserAuthResult is a 4-byte LE UINT32, but some servers
                // wrap it in a fallback TsRequest (ASN.1 SEQUENCE). Peek the
                // first byte to decide which framing to use.
                let mut peek = [0u8; 1];
                if transport.read(&mut peek).map_err(ConnectError::Tcp)? == 0 {
                    return Err(ConnectError::UnexpectedEof);
                }
                if peek[0] == 0x30 {
                    // SEQUENCE: read the rest of the TsRequest using the same
                    // framing as the other CredSSP states. We need to push the
                    // already-consumed peek byte back into the framer; the
                    // simplest way is to inline the length decode here.
                    scratch.clear();
                    scratch.push(0x30);
                    let mut len_byte = [0u8; 1];
                    read_exact_or_eof(transport, &mut len_byte)?;
                    scratch.push(len_byte[0]);
                    let content_length = if len_byte[0] < 0x80 {
                        len_byte[0] as usize
                    } else {
                        let n = (len_byte[0] & 0x7F) as usize;
                        if n == 0 || n > 4 {
                            return Err(ConnectError::Tcp(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid ASN.1 length in EarlyUserAuthResult fallback",
                            )));
                        }
                        let mut len_buf = [0u8; 4];
                        read_exact_or_eof(transport, &mut len_buf[..n])?;
                        scratch.extend_from_slice(&len_buf[..n]);
                        let mut acc = 0usize;
                        for &b in &len_buf[..n] {
                            acc = (acc << 8) | b as usize;
                        }
                        acc
                    };
                    let header_size = scratch.len();
                    scratch.resize(header_size + content_length, 0);
                    read_exact_or_eof(transport, &mut scratch[header_size..])?;
                    credssp.step(&scratch)?;
                } else {
                    // Raw 4-byte status: peek byte is the LSB.
                    let mut tail = [0u8; 3];
                    read_exact_or_eof(transport, &mut tail)?;
                    let four = [peek[0], tail[0], tail[1], tail[2]];
                    credssp.step(&four)?;
                }
            }
        }
    }
}

/// Fill a [`CredsspRandom`] with cryptographically random bytes from the OS.
fn generate_credssp_random() -> Result<CredsspRandom, ConnectError> {
    let mut client_nonce = [0u8; 32];
    let mut client_challenge = [0u8; 8];
    let mut exported_session_key = [0u8; 16];
    fill_random(&mut client_nonce)?;
    fill_random(&mut client_challenge)?;
    fill_random(&mut exported_session_key)?;
    Ok(CredsspRandom {
        client_nonce,
        client_challenge,
        exported_session_key,
    })
}

fn fill_random(buf: &mut [u8]) -> Result<(), ConnectError> {
    getrandom::getrandom(buf).map_err(|e| {
        ConnectError::Tcp(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("OS random failure: {e}"),
        ))
    })
}

