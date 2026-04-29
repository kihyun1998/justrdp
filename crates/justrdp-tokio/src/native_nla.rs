#![forbid(unsafe_code)]

//! Native CredSSP / NLA driver.
//!
//! Adapts `justrdp-blocking`'s synchronous `run_credssp_sequence` to
//! the async [`justrdp_async::CredsspDriver`] contract used by
//! [`justrdp_async::WebClient::connect_with_nla`]. The state machine is
//! identical to the blocking version — only the I/O is async.
//!
//! ## Wire-up
//!
//! ```ignore
//! use justrdp_async::WebClient;
//! use justrdp_tokio::{NativeTcpTransport, NativeTlsUpgrade, NativeCredsspDriver};
//!
//! let transport = NativeTcpTransport::connect(("rdp.example.com", 3389)).await?;
//! let tls = NativeTlsUpgrade::dangerous_no_verify("rdp.example.com")?;
//! let credssp = NativeCredsspDriver::new();
//! let (result, post_tls) = WebClient::new(transport)
//!     .connect_with_nla(config, tls, credssp)
//!     .await?;
//! ```
//!
//! `NativeCredsspDriver` is `CredsspDriver<NativeTlsTransport>` only —
//! it pulls the server SPKI directly from the post-TLS stream via
//! [`NativeTlsTransport::server_public_key`], so it's not generic
//! over arbitrary `WebTransport`s. Embedders using a custom transport
//! can implement [`CredsspDriver`] themselves.
//!
//! ## What this driver does NOT do
//!
//! Username/password (NTLMv2) credentials work out of the box because
//! `justrdp-connector::CredsspSequence` ships the NTLM stack. Kerberos
//! against a real KDC requires platform integration (Windows SSPI /
//! libkrb5 / MIT GSS-API) which is intentionally out of scope here —
//! that lives in a separate driver implementation.

use alloc::format;
use alloc::vec::Vec;

use justrdp_connector::{ClientConnector, CredsspRandom, CredsspSequence, CredsspState, Sequence};
use justrdp_pdu::x224::SecurityProtocol;

use justrdp_async::{CredsspDriver, TransportError, WebTransport};
use crate::native_tls::NativeTlsTransport;

/// Async CredSSP / NLA driver bound to [`NativeTlsTransport`].
///
/// The driver is intentionally minimal — it pulls credentials and the
/// HYBRID/HYBRID_EX selection from the connector's `Config`, fills
/// the per-session randomness via OS RNG, and shuttles bytes between
/// `CredsspSequence` and the post-TLS transport.
#[derive(Debug, Default)]
pub struct NativeCredsspDriver;

impl NativeCredsspDriver {
    pub fn new() -> Self {
        Self
    }
}

impl CredsspDriver<NativeTlsTransport> for NativeCredsspDriver {
    type Error = TransportError;

    async fn drive(
        self,
        connector: &mut ClientConnector,
        transport: &mut NativeTlsTransport,
    ) -> Result<(), TransportError> {
        // 1. Extract the server's leaf SPKI from the rustls handshake
        //    we just completed. CredSSP's `pubKeyAuth` step binds the
        //    NTLM session key against this — without it the server
        //    will reject the credentials with `STATUS_LOGON_FAILURE`
        //    even if the password is right.
        let server_public_key = transport
            .server_public_key()
            .ok_or_else(|| TransportError::other("native-nla: TLS peer cert missing or unparseable"))?;

        // 2. Build a CredsspSequence from the connector's config.
        //    Username / password / domain / HYBRID_EX / credential
        //    type all flow from the connector — the driver itself
        //    is stateless.
        let config = connector.config();
        let username = config.credentials.username.clone();
        let password = config.credentials.password.clone();
        let domain = config.domain.clone().unwrap_or_default();
        let use_hybrid_ex = connector
            .selected_protocol()
            .contains(SecurityProtocol::HYBRID_EX);
        let credential_type = connector.credssp_credential_type();
        let random = generate_credssp_random()?;

        let mut credssp = CredsspSequence::with_credential_type(
            &username,
            &password,
            &domain,
            server_public_key,
            random,
            use_hybrid_ex,
            credential_type,
        );

        // 3. Drive the CredsspSequence state machine over the
        //    transport. The shape mirrors `justrdp-blocking`'s
        //    `run_credssp_sequence` — same states, async I/O.
        let mut scratch: Vec<u8> = Vec::new();
        loop {
            let state = credssp.state().clone();
            match state {
                CredsspState::Done => break,

                CredsspState::SendNegoToken | CredsspState::SendCredentials => {
                    let bytes = credssp
                        .step(&[])
                        .map_err(|e| TransportError::other(format!("credssp step: {e:?}")))?;
                    if !bytes.is_empty() {
                        transport.send(&bytes).await?;
                    }
                }

                CredsspState::WaitChallenge | CredsspState::WaitPubKeyAuth => {
                    let n = read_asn1_sequence(transport, &mut scratch).await?;
                    let response = credssp
                        .step(&scratch[..n])
                        .map_err(|e| TransportError::other(format!("credssp step: {e:?}")))?;
                    if !response.is_empty() {
                        transport.send(&response).await?;
                    }
                }

                CredsspState::WaitEarlyUserAuth => {
                    handle_early_user_auth(transport, &mut credssp, &mut scratch).await?;
                }
            }
        }

        // 4. Step the connector through its CredSSP no-op states
        //    (CredsspNegoTokens → CredsspPubKeyAuth → CredsspCredentials
        //    → optional CredsspEarlyUserAuth → BasicSettingsExchangeSendInitial).
        //    The post-CredSSP pump in `connect_with_nla` then takes over.
        use justrdp_connector::ClientConnectorState as S;
        let mut output = justrdp_core::WriteBuf::new();
        loop {
            output.clear();
            let advance = matches!(
                connector.state(),
                S::CredsspNegoTokens
                    | S::CredsspPubKeyAuth
                    | S::CredsspCredentials
                    | S::CredsspEarlyUserAuth
            );
            if !advance {
                break;
            }
            connector
                .step(&[], &mut output)
                .map_err(|e| TransportError::other(format!("connector credssp step: {e:?}")))?;
        }
        Ok(())
    }
}

/// Pull bytes off the transport into `scratch` until at least one
/// complete top-level ASN.1 SEQUENCE is buffered, then return its
/// total byte count.
///
/// The CredSSP wire format wraps every TsRequest in a SEQUENCE
/// (DER tag `0x30`); this is the same framing the blocking client
/// uses (see `justrdp-blocking::transport::read_asn1_sequence`).
/// We re-frame here because the transport may deliver bytes in
/// arbitrary chunks (TCP) or one-frame-per-message (WebSocket); the
/// helper handles both.
async fn read_asn1_sequence(
    transport: &mut NativeTlsTransport,
    scratch: &mut Vec<u8>,
) -> Result<usize, TransportError> {
    scratch.clear();

    // 1. Tag byte (must be 0x30 for SEQUENCE).
    fill_until(transport, scratch, 1).await?;
    if scratch[0] != 0x30 {
        return Err(TransportError::protocol(format!(
            "credssp expected SEQUENCE (0x30) tag, got 0x{:02X}",
            scratch[0]
        )));
    }

    // 2. Length prefix — short form (single byte < 0x80) or long
    //    form (byte 0x80|n followed by n length bytes, big-endian).
    fill_until(transport, scratch, 2).await?;
    let len_byte = scratch[1];
    let (header_len, content_len) = if len_byte < 0x80 {
        (2, len_byte as usize)
    } else {
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(TransportError::protocol(format!(
                "credssp invalid ASN.1 length prefix: {len_byte:02X}"
            )));
        }
        fill_until(transport, scratch, 2 + n).await?;
        let mut acc: usize = 0;
        for &b in &scratch[2..2 + n] {
            acc = (acc << 8) | b as usize;
        }
        (2 + n, acc)
    };

    // 3. Body.
    let total = header_len + content_len;
    fill_until(transport, scratch, total).await?;
    Ok(total)
}

/// HYBRID_EX servers respond after `SendCredentials` with either:
/// * a 4-byte little-endian status (`EarlyUserAuthResult`,
///   MS-RDPBCGR 5.4.2.2), or
/// * a fallback TsRequest SEQUENCE.
///
/// We peek the first byte to decide which framing applies. `0x30`
/// (SEQUENCE tag) → fallback path; anything else → raw 4-byte status.
async fn handle_early_user_auth(
    transport: &mut NativeTlsTransport,
    credssp: &mut CredsspSequence,
    scratch: &mut Vec<u8>,
) -> Result<(), TransportError> {
    scratch.clear();
    fill_until(transport, scratch, 1).await?;
    if scratch[0] == 0x30 {
        // Fallback TsRequest. The first byte is already buffered;
        // continue framing the SEQUENCE in place.
        fill_until(transport, scratch, 2).await?;
        let len_byte = scratch[1];
        let (header_len, content_len) = if len_byte < 0x80 {
            (2, len_byte as usize)
        } else {
            let n = (len_byte & 0x7F) as usize;
            if n == 0 || n > 4 {
                return Err(TransportError::protocol(format!(
                    "early-user-auth fallback bad length: {len_byte:02X}"
                )));
            }
            fill_until(transport, scratch, 2 + n).await?;
            let mut acc: usize = 0;
            for &b in &scratch[2..2 + n] {
                acc = (acc << 8) | b as usize;
            }
            (2 + n, acc)
        };
        let total = header_len + content_len;
        fill_until(transport, scratch, total).await?;
        credssp
            .step(&scratch[..total])
            .map_err(|e| TransportError::other(format!("credssp early-user-auth: {e:?}")))?;
    } else {
        // Raw 4-byte status. The peek byte is already byte 0.
        fill_until(transport, scratch, 4).await?;
        credssp
            .step(&scratch[..4])
            .map_err(|e| TransportError::other(format!("credssp early-user-auth: {e:?}")))?;
    }
    Ok(())
}

/// Drain `transport` into `scratch` until it holds at least
/// `target` bytes. Each `recv()` returns whatever is currently
/// available; we accumulate until the caller's framing is satisfied.
async fn fill_until(
    transport: &mut NativeTlsTransport,
    scratch: &mut Vec<u8>,
    target: usize,
) -> Result<(), TransportError> {
    while scratch.len() < target {
        let chunk = transport.recv().await?;
        if chunk.is_empty() {
            return Err(TransportError::closed(
                "native-nla: transport returned empty frame mid-CredSSP",
            ));
        }
        scratch.extend_from_slice(&chunk);
    }
    Ok(())
}

/// Fill a fresh [`CredsspRandom`] with cryptographic randomness from
/// the OS RNG. Mirrors `justrdp-blocking`'s `generate_credssp_random`.
fn generate_credssp_random() -> Result<CredsspRandom, TransportError> {
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

fn fill_random(buf: &mut [u8]) -> Result<(), TransportError> {
    getrandom::getrandom(buf).map_err(|e| TransportError::other(format!("OS RNG: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_constructs_default() {
        // Smoke test: the struct is empty, but the impl block must
        // compile. Real wire-level coverage lives in the integration
        // example (S7-5) since CredSSP needs a peer to converse with.
        let _driver = NativeCredsspDriver::new();
        let _driver2 = NativeCredsspDriver::default();
    }

    #[test]
    fn fill_random_fills_buffer() {
        let mut buf = [0u8; 16];
        fill_random(&mut buf).expect("OS RNG should be available in tests");
        // Cryptographic randomness almost never produces an all-zero
        // 16-byte buffer; failing that asserts the function actually
        // wrote.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn generate_credssp_random_yields_unique_fields() {
        let r = generate_credssp_random().unwrap();
        assert_eq!(r.client_nonce.len(), 32);
        assert_eq!(r.client_challenge.len(), 8);
        assert_eq!(r.exported_session_key.len(), 16);
        assert!(r.client_nonce.iter().any(|&b| b != 0));
    }
}
