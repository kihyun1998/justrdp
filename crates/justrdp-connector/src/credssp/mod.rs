#![forbid(unsafe_code)]

//! CredSSP / NLA (Network Level Authentication) state machine (MS-CSSP).
//!
//! Implements the CredSSP handshake per MS-CSSP 3.1.5:
//! 1. Client sends NTLM Negotiate in SPNEGO/TsRequest
//! 2. Server responds with NTLM Challenge in SPNEGO/TsRequest
//! 3. Client sends NTLM Authenticate + pubKeyAuth in TsRequest
//! 4. Server responds with pubKeyAuth verification
//! 5. Client sends encrypted credentials in TsRequest

pub mod gss_wrap;
pub mod kerberos;
pub mod spnego;
pub mod ts_request;

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::crypto::{hmac_md5, Rc4, Sha256};

use justrdp_pdu::ntlm::compute::{
    compute_mic, compute_response, key_exchange_encrypt, modify_target_info, ntowfv2,
};
use justrdp_pdu::ntlm::messages::{
    AuthenticateMessage, AvId, AvPair, ChallengeMessage, NegotiateFlags, NegotiateMessage,
    NtlmVersion, to_utf16le,
};
use justrdp_pdu::ntlm::signing;

use self::ts_request::TsRequest;
use crate::error::{ConnectorError, ConnectorErrorKind, ConnectorResult};

/// CredSSP Client-To-Server hash magic string (MS-CSSP 3.1.5, v5+).
const CLIENT_SERVER_HASH_MAGIC: &[u8] = b"CredSSP Client-To-Server Binding Hash\0";
/// CredSSP Server-To-Client hash magic string (MS-CSSP 3.1.5, v5+).
const SERVER_CLIENT_HASH_MAGIC: &[u8] = b"CredSSP Server-To-Client Binding Hash\0";

/// CredSSP sequence state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredsspState {
    /// Send NTLM Negotiate wrapped in SPNEGO/TsRequest.
    SendNegoToken,
    /// Wait for server Challenge.
    WaitChallenge,
    /// Wait for server pubKeyAuth response.
    WaitPubKeyAuth,
    /// Send encrypted credentials.
    SendCredentials,
    /// Wait for EarlyUserAuthResult (HYBRID_EX only).
    WaitEarlyUserAuth,
    /// Done.
    Done,
}

// ── Credential types (MS-CSSP 2.2.1.2) ──

/// A supplemental credential package (e.g., device Kerberos token for Compound Identity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplementalCred {
    /// Package name in UTF-16LE (e.g., `to_utf16le("Kerberos")`).
    pub package_name: Vec<u8>,
    /// Credential buffer (e.g., device AP-REQ token).
    pub cred_buffer: Vec<u8>,
}

/// Credential type for TSCredentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialType {
    /// TSPasswordCreds (credType = 1): send domain/username/password.
    Password,
    /// TSRemoteGuardCreds (credType = 6): Remote Credential Guard.
    /// Contains Kerberos AP-REQ token for SSO without password delegation.
    /// Optionally includes supplemental credentials for Compound Identity
    /// (device claims via device Kerberos token).
    RemoteGuard {
        /// Kerberos AP-REQ token bytes (user logon credential).
        kerberos_token: Vec<u8>,
        /// Supplemental credentials for Compound Identity.
        /// Typically contains a device Kerberos AP-REQ token so the server
        /// can evaluate device-based conditional access policies.
        supplemental_creds: Vec<SupplementalCred>,
    },
    /// Restricted Admin (credType = 1 with empty credentials).
    /// No credentials are sent to the server.
    RestrictedAdmin,
}

/// Random bytes needed by CredSSP (caller must generate cryptographically).
pub struct CredsspRandom {
    /// 32-byte client nonce (for CredSSP v5+).
    pub client_nonce: [u8; 32],
    /// 8-byte client challenge (for NTLMv2).
    pub client_challenge: [u8; 8],
    /// 16-byte exported session key (for NTLM key exchange).
    pub exported_session_key: [u8; 16],
}

/// CredSSP handshake sequence.
pub struct CredsspSequence {
    state: CredsspState,
    username: Vec<u8>,
    password: Vec<u8>,
    domain: Vec<u8>,
    server_public_key: Vec<u8>,

    // Random values (from caller)
    random: CredsspRandom,

    /// Credential type to send (password, Remote Guard, or Restricted Admin).
    credential_type: CredentialType,

    // CredSSP version negotiation
    /// Negotiated CredSSP version: min(client_max, server_version).
    negotiated_version: u32,
    /// Whether the server selected HYBRID_EX protocol.
    use_hybrid_ex: bool,

    // NTLM state accumulated during handshake
    negotiate_bytes: Vec<u8>,
    challenge_bytes: Vec<u8>,
    pub exported_session_key: [u8; 16],
    // Persistent NTLM sealing state (RC4 + seq num)
    pub send_signing_key: [u8; 16],
    send_sealing_rc4: Option<Rc4>,
    send_seq_num: u32,
    // Receive signing/sealing state (for server pubKeyAuth verification)
    recv_signing_key: [u8; 16],
    recv_sealing_rc4: Option<Rc4>,
    recv_seq_num: u32,
}

impl CredsspSequence {
    /// Create a new CredSSP sequence with password credentials.
    ///
    /// `server_public_key` is the DER-encoded SubjectPublicKeyInfo from the TLS certificate.
    /// `random` contains cryptographically random bytes (caller must generate).
    /// `use_hybrid_ex` should be true if the server selected HYBRID_EX protocol.
    pub fn new(
        username: &str,
        password: &str,
        domain: &str,
        server_public_key: Vec<u8>,
        random: CredsspRandom,
        use_hybrid_ex: bool,
    ) -> Self {
        Self::with_credential_type(
            username, password, domain, server_public_key, random,
            use_hybrid_ex, CredentialType::Password,
        )
    }

    /// Create a new CredSSP sequence with a specific credential type.
    pub fn with_credential_type(
        username: &str,
        password: &str,
        domain: &str,
        server_public_key: Vec<u8>,
        random: CredsspRandom,
        use_hybrid_ex: bool,
        credential_type: CredentialType,
    ) -> Self {
        Self {
            state: CredsspState::SendNegoToken,
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
            domain: domain.as_bytes().to_vec(),
            server_public_key,
            random,
            credential_type,
            negotiated_version: ts_request::TS_REQUEST_MAX_VERSION,
            use_hybrid_ex,
            negotiate_bytes: Vec::new(),
            challenge_bytes: Vec::new(),
            exported_session_key: [0u8; 16],
            send_signing_key: [0u8; 16],
            send_sealing_rc4: None,
            send_seq_num: 0,
            recv_signing_key: [0u8; 16],
            recv_sealing_rc4: None,
            recv_seq_num: 0,
        }
    }

    pub fn state(&self) -> &CredsspState {
        &self.state
    }

    /// Debug accessor: current send sequence number.
    pub fn send_seq_num(&self) -> u32 {
        self.send_seq_num
    }

    /// Debug accessor: negotiated CredSSP version.
    pub fn negotiated_version(&self) -> u32 {
        self.negotiated_version
    }

    /// Step the CredSSP sequence.
    pub fn step(&mut self, input: &[u8]) -> ConnectorResult<Vec<u8>> {
        match self.state {
            CredsspState::SendNegoToken => self.step_send_negotiate(),
            CredsspState::WaitChallenge => self.step_process_challenge(input),
            CredsspState::WaitPubKeyAuth => self.step_process_pub_key_auth(input),
            CredsspState::SendCredentials => self.step_send_credentials(),
            CredsspState::WaitEarlyUserAuth => self.step_wait_early_user_auth(input),
            CredsspState::Done => Err(ConnectorError {
                kind: ConnectorErrorKind::InvalidState,
            }),
        }
    }

    fn step_send_negotiate(&mut self) -> ConnectorResult<Vec<u8>> {
        let negotiate = NegotiateMessage::new();
        let negotiate_bytes = justrdp_core::encode_vec(&negotiate)?;
        self.negotiate_bytes = negotiate_bytes.clone();

        let spnego_token = spnego::wrap_negotiate(&negotiate_bytes);

        let mut ts_request = TsRequest::new();
        ts_request.nego_tokens = Some(spnego_token);
        // Per MS-CSSP 3.1.5: clientNonce is sent with the Authenticate TsRequest, not here.

        self.state = CredsspState::WaitChallenge;
        Ok(ts_request.encode())
    }

    fn step_process_challenge(&mut self, input: &[u8]) -> ConnectorResult<Vec<u8>> {
        let server_ts = TsRequest::decode(input)
            .map_err(|_| ConnectorError::general("failed to decode server TsRequest"))?;

        // Negotiate version: use min(client_max, server_version)
        self.negotiated_version = core::cmp::min(
            ts_request::TS_REQUEST_MAX_VERSION,
            server_ts.version,
        );

        let spnego_token = server_ts
            .nego_tokens
            .ok_or_else(|| ConnectorError::general("server TsRequest missing negoTokens"))?;

        let ntlm_challenge_bytes = spnego::unwrap_challenge(&spnego_token)
            .map_err(|_| ConnectorError::general("failed to unwrap SPNEGO challenge"))?;

        self.challenge_bytes = ntlm_challenge_bytes.clone();

        let challenge = ChallengeMessage::decode_from_bytes(&ntlm_challenge_bytes)
            .map_err(|_| ConnectorError::general("failed to decode NTLM Challenge"))?;

        let username = core::str::from_utf8(&self.username)
            .map_err(|_| ConnectorError::general("invalid UTF-8 username"))?;
        let password = core::str::from_utf8(&self.password)
            .map_err(|_| ConnectorError::general("invalid UTF-8 password"))?;
        let domain_str = core::str::from_utf8(&self.domain)
            .map_err(|_| ConnectorError::general("invalid UTF-8 domain"))?;

        // Parse server target_info
        let av_pairs = AvPair::parse_list(&challenge.target_info)
            .map_err(|_| ConnectorError::general("failed to parse AV_PAIRS"))?;

        // MS-NLMP 3.1.5.1.2: If user didn't supply a domain, use the server's
        // NbDomainName from target_info.  Windows SAM stores NTOWFv2 hashes with
        // the machine's NETBIOS name as domain for local accounts.
        let effective_domain: alloc::string::String = if domain_str.is_empty() {
            if let Some(nb) = AvPair::find(&av_pairs, AvId::MsvAvNbDomainName) {
                // Decode UTF-16LE
                nb.value
                    .chunks_exact(2)
                    .filter_map(|c| {
                        let ch = u16::from_le_bytes([c[0], c[1]]);
                        char::from_u32(ch as u32)
                    })
                    .collect()
            } else {
                alloc::string::String::new()
            }
        } else {
            alloc::string::String::from(domain_str)
        };

        let response_key = ntowfv2(password, username, &effective_domain);

        let has_timestamp = av_pairs.iter().any(|p| p.id == AvId::MsvAvTimestamp as u16);

        let time = if let Some(ts_pair) = AvPair::find(&av_pairs, AvId::MsvAvTimestamp) {
            if ts_pair.value.len() == 8 {
                u64::from_le_bytes(ts_pair.value[..8].try_into().unwrap())
            } else {
                0
            }
        } else {
            0
        };

        // MS-NLMP 3.1.5.1.2: Modify target_info before ComputeResponse
        let modified_target_info = modify_target_info(&challenge.target_info);

        let (nt_response, lm_response, session_base_key) = compute_response(
            &response_key,
            &challenge.server_challenge,
            &self.random.client_challenge,
            time,
            &modified_target_info,
            has_timestamp,
        );

        // Key exchange: for NTLMv2, KeyExchangeKey = SessionBaseKey
        self.exported_session_key = self.random.exported_session_key;
        let encrypted_random_session_key =
            key_exchange_encrypt(&session_base_key, &self.exported_session_key);

        // Negotiate flags: AND client defaults with server flags
        let negotiated_flags = NegotiateFlags::client_default()
            .bits() & challenge.flags.bits();
        let negotiated_flags = NegotiateFlags::from_bits(negotiated_flags);

        // Build Authenticate message (with MIC zeroed for initial encoding)
        let mut authenticate = AuthenticateMessage {
            flags: negotiated_flags,
            lm_response,
            nt_response,
            domain_name: to_utf16le(&effective_domain),
            user_name: to_utf16le(username),
            workstation: Vec::new(),
            encrypted_random_session_key,
            version: NtlmVersion::windows_10(),
            mic: [0u8; 16], // Zeroed for MIC computation
        };

        // Compute MIC: HMAC_MD5(ExportedSessionKey, Negotiate + Challenge + Authenticate_zeroed_MIC)
        let auth_bytes_zeroed_mic = authenticate.to_bytes();
        let mic = compute_mic(
            &self.exported_session_key,
            &self.negotiate_bytes,
            &self.challenge_bytes,
            &auth_bytes_zeroed_mic,
        );
        authenticate.mic = mic;
        let authenticate_bytes = authenticate.to_bytes();

        self.send_signing_key = signing::signing_key(&self.exported_session_key, true);
        let seal_key = signing::sealing_key(&self.exported_session_key, true);
        self.send_sealing_rc4 = Some(Rc4::new(&seal_key));
        self.recv_signing_key = signing::signing_key(&self.exported_session_key, false);
        let recv_seal_key = signing::sealing_key(&self.exported_session_key, false);
        self.recv_sealing_rc4 = Some(Rc4::new(&recv_seal_key));

        // mechListMIC uses a TEMPORARY RC4 (seq=0), then RC4 state is restored.
        // pubKeyAuth uses the main RC4 at initial state (seq=1, since seq continues).
        let mech_list_mic = {
            let mut temp_rc4 = Rc4::new(&seal_key);
            let mech_types = spnego::mech_types_bytes();
            let mut hmac_input = vec![0u8; 4 + mech_types.len()];
            hmac_input[4..].copy_from_slice(&mech_types);
            let digest = hmac_md5(&self.send_signing_key, &hmac_input);
            let mut checksum = [0u8; 8];
            checksum.copy_from_slice(&digest[..8]);
            temp_rc4.process(&mut checksum);
            let mut mac = [0u8; 16];
            mac[..4].copy_from_slice(&1u32.to_le_bytes());
            mac[4..12].copy_from_slice(&checksum);
            mac
        };
        // seq_num continues past mechListMIC
        self.send_seq_num = 1;

        let pub_key_auth = self.compute_pub_key_auth()?;
        let spnego_token = spnego::wrap_authenticate(&authenticate_bytes, Some(&mech_list_mic));

        // Build TsRequest with negoTokens AND pubKeyAuth (MS-CSSP 3.1.5: sent together)
        let mut ts_request = TsRequest::new();
        ts_request.version = self.negotiated_version;
        ts_request.nego_tokens = Some(spnego_token);
        ts_request.pub_key_auth = Some(pub_key_auth);
        if self.negotiated_version >= 5 {
            ts_request.client_nonce = Some(self.random.client_nonce);
        }

        self.state = CredsspState::WaitPubKeyAuth;
        Ok(ts_request.encode())
    }

    fn step_process_pub_key_auth(&mut self, input: &[u8]) -> ConnectorResult<Vec<u8>> {
        let server_ts = TsRequest::decode(input)
            .map_err(|_| ConnectorError::general("failed to decode server TsRequest"))?;

        // Check for error code (v3+)
        if let Some(code) = server_ts.error_code {
            if code != 0 {
                return Err(ConnectorError::general("server CredSSP error (NTSTATUS in errorCode)"));
            }
        }

        // Process server's SPNEGO NegTokenResp (may contain mechListMIC).
        // If the server sent mechListMIC, we must verify it and advance recv_seq_num
        // before verifying pubKeyAuth (which the server sent at seq=1).
        // Process server's SPNEGO mechListMIC.
        // Per MS-SPNG: after mechListMIC, RC4 state is restored to initial.
        // seq_num continues (mechListMIC=0, pubKeyAuth=1).
        if let Some(ref nego_tokens) = server_ts.nego_tokens {
            if let Ok(resp) = justrdp_pdu::kerberos::spnego::NegTokenResp::decode(nego_tokens) {
                if let Some(ref mic_bytes) = resp.mech_list_mic {
                    self.ntlm_verify_mic(mic_bytes, &spnego::mech_types_bytes())?;
                    // Restore recv RC4 to initial state (per MS-SPNG save/restore)
                    let recv_seal_key = signing::sealing_key(&self.exported_session_key, false);
                    self.recv_sealing_rc4 = Some(Rc4::new(&recv_seal_key));
                }
            }
        }

        let server_pub_key_auth = server_ts.pub_key_auth
            .ok_or_else(|| ConnectorError::general("server TsRequest missing pubKeyAuth"))?;

        // Decrypt server's pubKeyAuth (seq follows after mechListMIC verification)
        let decrypted = self.ntlm_decrypt(&server_pub_key_auth)?;

        // Verify server's hash — use same key bytes as compute_pub_key_auth
        let subject_public_key = extract_subject_public_key(&self.server_public_key)
            .ok_or_else(|| ConnectorError::general(
                "failed to extract SubjectPublicKey from SPKI for verification",
            ))?;

        if self.negotiated_version >= 5 {
            // v5+: server sends SHA256("CredSSP Server-To-Client Binding Hash\0" + Nonce + SubjectPublicKey)
            let mut hasher = Sha256::new();
            hasher.update(SERVER_CLIENT_HASH_MAGIC);
            hasher.update(&self.random.client_nonce);
            hasher.update(&subject_public_key);
            let expected = hasher.finalize();

            if decrypted != expected.as_slice() {
                return Err(ConnectorError::general(
                    "server pubKeyAuth verification failed (v5+ hash mismatch)",
                ));
            }
        } else {
            // v2-v4: server sends SubjectPublicKey + 1 (first byte incremented)
            let mut expected = subject_public_key;
            if !expected.is_empty() {
                expected[0] = expected[0].wrapping_add(1);
            }
            if decrypted != expected {
                return Err(ConnectorError::general(
                    "server pubKeyAuth verification failed (v2-v4 key mismatch)",
                ));
            }
        }

        self.state = CredsspState::SendCredentials;
        self.step_send_credentials()
    }

    fn step_send_credentials(&mut self) -> ConnectorResult<Vec<u8>> {
        let mut ts_request = TsRequest::new();
        ts_request.version = self.negotiated_version;

        // MS-CSSP 3.1.5: Restricted Admin omits authInfo entirely;
        // all other modes encrypt and send TSCredentials.
        if !matches!(self.credential_type, CredentialType::RestrictedAdmin) {
            let ts_credentials = self.build_ts_credentials();
            let encrypted = self.ntlm_encrypt(&ts_credentials);
            ts_request.auth_info = Some(encrypted);
        }

        if self.use_hybrid_ex {
            self.state = CredsspState::WaitEarlyUserAuth;
        } else {
            self.state = CredsspState::Done;
        }
        Ok(ts_request.encode())
    }

    /// Process EarlyUserAuthResult (HYBRID_EX only, MS-RDPBCGR 5.4.2.2).
    ///
    /// The server sends a 4-byte LE UINT32:
    /// - `AUTHZ_SUCCESS` (0x00000000) = success (proceed with RDP connection)
    /// - `LOGON_FAILED_OTHER` (0x00000001) = auth failed
    /// - other non-zero = error
    fn step_wait_early_user_auth(&mut self, input: &[u8]) -> ConnectorResult<Vec<u8>> {
        // EarlyUserAuthResult is a raw 4-byte LE UINT32 (MS-RDPBCGR 5.4.2.2).
        // Some server implementations may wrap it in a TsRequest (starts with 0x30 SEQUENCE).
        // Note: a raw status value starting with byte 0x30 (e.g., status=0x00000030)
        // would be misclassified as a TsRequest; this is benign since such status
        // codes are not defined by the spec and the TsRequest fallback treats missing
        // errorCode as success.
        if input.first() == Some(&0x30) {
            // Looks like a TsRequest — try to decode
            if let Ok(ts_req) = TsRequest::decode(input) {
                if let Some(code) = ts_req.error_code {
                    if code != 0 {
                        return Err(ConnectorError::general("EarlyUserAuthResult: authentication failed"));
                    }
                }
            }
        } else if input.len() >= 4 {
            // Raw 4-byte LE UINT32
            let status = u32::from_le_bytes(input[..4].try_into().unwrap());
            if status != 0 {
                return Err(ConnectorError::general("EarlyUserAuthResult: authentication failed"));
            }
        } else {
            return Err(ConnectorError::general("EarlyUserAuthResult too short"));
        }

        self.state = CredsspState::Done;
        Ok(Vec::new())
    }

    /// Compute pubKeyAuth based on CredSSP version.
    ///
    /// MS-CSSP specifies using the "SubjectPublicKey sub-field" of SubjectPublicKeyInfo,
    /// i.e., the BIT STRING value (not the full SPKI).
    ///
    /// v2-v4: encrypt SubjectPublicKey
    /// v5+: encrypt SHA256("CredSSP Client-To-Server Binding Hash\0" + Nonce + SubjectPublicKey)
    fn compute_pub_key_auth(&mut self) -> ConnectorResult<Vec<u8>> {
        // For v2-v4: encrypt SubjectPublicKey (BIT STRING value, without unused-bits byte)
        // For v5+: SHA256(magic + nonce + SubjectPublicKey)
        let subject_public_key = extract_subject_public_key(&self.server_public_key)
            .ok_or_else(|| ConnectorError::general(
                "failed to extract SubjectPublicKey from SPKI",
            ))?;

        if self.negotiated_version >= 5 {
            let mut hasher = Sha256::new();
            hasher.update(CLIENT_SERVER_HASH_MAGIC);
            hasher.update(&self.random.client_nonce);
            hasher.update(&subject_public_key);
            let hash = hasher.finalize();
            Ok(self.ntlm_encrypt(&hash))
        } else {
            // v2-v4: encrypt SubjectPublicKey directly
            Ok(self.ntlm_encrypt(&subject_public_key))
        }
    }

    /// NTLM sign (MAC only, no encryption) per MS-NLMP 3.4.4.2.
    ///
    /// Used for SPNEGO mechListMIC (GSS_GetMIC).
    /// Returns 16-byte MAC: Version(4) + Checksum(8) + SeqNum(4).
    fn ntlm_sign(&mut self, message: &[u8]) -> [u8; 16] {
        let rc4 = self.send_sealing_rc4.as_mut().expect("sealing key not initialized");
        let seq_num = self.send_seq_num;
        self.send_seq_num += 1;

        // HMAC_MD5(SigningKey, SeqNum + Message)
        let mut hmac_input = vec![0u8; 4 + message.len()];
        hmac_input[..4].copy_from_slice(&seq_num.to_le_bytes());
        hmac_input[4..].copy_from_slice(message);
        let digest = hmac_md5(&self.send_signing_key, &hmac_input);

        // RC4-encrypt first 8 bytes of HMAC
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&digest[..8]);
        rc4.process(&mut checksum);

        // Build MAC: Version(0x00000001) + Checksum(8) + SeqNum(4)
        let mut mac = [0u8; 16];
        mac[..4].copy_from_slice(&1u32.to_le_bytes());
        mac[4..12].copy_from_slice(&checksum);
        mac[12..16].copy_from_slice(&seq_num.to_le_bytes());

        mac
    }

    /// Verify a received NTLM MAC (mechListMIC from server) using the recv context.
    fn ntlm_verify_mic(&mut self, received_mac: &[u8], message: &[u8]) -> ConnectorResult<()> {
        if received_mac.len() != 16 {
            return Err(ConnectorError::general("mechListMIC must be 16 bytes"));
        }
        let rc4 = self.recv_sealing_rc4.as_mut()
            .ok_or_else(|| ConnectorError::general("recv sealing key not initialized"))?;
        let seq_num = self.recv_seq_num;
        self.recv_seq_num += 1;

        // Recompute: HMAC_MD5(RecvSigningKey, SeqNum + message)
        let mut hmac_input = vec![0u8; 4 + message.len()];
        hmac_input[..4].copy_from_slice(&seq_num.to_le_bytes());
        hmac_input[4..].copy_from_slice(message);
        let digest = hmac_md5(&self.recv_signing_key, &hmac_input);

        // RC4-encrypt first 8 bytes
        let mut expected_checksum = [0u8; 8];
        expected_checksum.copy_from_slice(&digest[..8]);
        rc4.process(&mut expected_checksum);

        if &received_mac[4..12] != &expected_checksum {
            return Err(ConnectorError::general("server mechListMIC verification failed"));
        }
        Ok(())
    }

    /// NTLM encrypt (seal) a message: produces signature(16) + encrypted_data.
    ///
    /// Per MS-NLMP 3.4.4.2.1 with NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
    /// 1. Compute digest = HMAC_MD5(SigningKey, SeqNum + plaintext)
    /// 2. Encrypt message data with persistent RC4 stream
    /// 3. Encrypt first 8 bytes of digest with same RC4 stream (continued)
    /// 4. Build: Version(4) + Checksum(8) + SeqNum(4) + EncryptedData
    /// NTLM seal (encrypt + sign) per MS-NLMP 3.4.4.2.1.
    ///
    /// With NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
    /// 1. RC4-encrypt message data (advances RC4 stream)
    /// 2. Compute HMAC-MD5(SigningKey, SeqNum + **original plaintext**)
    /// 3. RC4-encrypt first 8 bytes of HMAC (continues RC4 stream)
    /// 4. Build: Version(4) + Checksum(8) + SeqNum(4) + EncryptedData
    fn ntlm_encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let rc4 = self.send_sealing_rc4.as_mut().expect("sealing key not initialized");
        let seq_num = self.send_seq_num;
        self.send_seq_num += 1;

        // Step 1: RC4-encrypt message data first
        let mut encrypted = plaintext.to_vec();
        rc4.process(&mut encrypted);

        // Step 2: Compute HMAC over SeqNum + original plaintext
        let mut hmac_input = vec![0u8; 4 + plaintext.len()];
        hmac_input[..4].copy_from_slice(&seq_num.to_le_bytes());
        hmac_input[4..].copy_from_slice(plaintext);
        let digest = hmac_md5(&self.send_signing_key, &hmac_input);

        // Step 3: RC4-encrypt first 8 bytes of HMAC (continues RC4 stream)
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&digest[..8]);
        rc4.process(&mut checksum);

        // Step 4: Build signature(16) + encrypted_data
        let mut result = vec![0u8; 16 + encrypted.len()];
        result[..4].copy_from_slice(&1u32.to_le_bytes()); // Version = 1
        result[4..12].copy_from_slice(&checksum);
        result[12..16].copy_from_slice(&seq_num.to_le_bytes());
        result[16..].copy_from_slice(&encrypted);

        result
    }

    /// NTLM unseal (decrypt + verify) per MS-NLMP 3.4.4.2.1.
    ///
    /// Input: signature(16) + encrypted_data
    /// Returns decrypted plaintext, or error if MAC verification fails.
    fn ntlm_decrypt(&mut self, sealed: &[u8]) -> ConnectorResult<Vec<u8>> {
        if sealed.len() < 16 {
            return Err(ConnectorError::general("NTLM sealed message too short"));
        }

        let rc4 = self.recv_sealing_rc4.as_mut()
            .ok_or_else(|| ConnectorError::general("receive sealing key not initialized"))?;
        let seq_num = self.recv_seq_num;
        self.recv_seq_num += 1;

        let checksum_encrypted = &sealed[4..12];
        let _seq_from_msg = &sealed[12..16];
        let encrypted_data = &sealed[16..];

        // Step 1: RC4-decrypt message data
        let mut plaintext = encrypted_data.to_vec();
        rc4.process(&mut plaintext);

        // Step 2: Compute HMAC over SeqNum + decrypted plaintext
        let mut hmac_input = vec![0u8; 4 + plaintext.len()];
        hmac_input[..4].copy_from_slice(&seq_num.to_le_bytes());
        hmac_input[4..].copy_from_slice(&plaintext);
        let digest = hmac_md5(&self.recv_signing_key, &hmac_input);

        // Step 3: RC4-encrypt first 8 bytes of HMAC to get expected checksum
        let mut expected_checksum = [0u8; 8];
        expected_checksum.copy_from_slice(&digest[..8]);
        rc4.process(&mut expected_checksum);

        // Step 4: Verify checksum
        if expected_checksum != checksum_encrypted {
            return Err(ConnectorError::general("NTLM MAC verification failed"));
        }

        Ok(plaintext)
    }

    /// Build TSCredentials ASN.1 DER structure (MS-CSSP 2.2.1.2).
    ///
    /// Supports:
    /// - credType 1: TSPasswordCreds (password auth)
    /// - credType 6: TSRemoteGuardCreds (Remote Credential Guard)
    ///
    /// Note: RestrictedAdmin omits authInfo entirely (handled in step_send_credentials).
    fn build_ts_credentials(&self) -> Vec<u8> {
        match &self.credential_type {
            CredentialType::Password => self.build_ts_password_creds(),
            CredentialType::RemoteGuard { kerberos_token, supplemental_creds } => {
                build_ts_remote_guard_creds(kerberos_token, supplemental_creds)
            }
            CredentialType::RestrictedAdmin => {
                // Must never be called — RestrictedAdmin omits authInfo entirely
                // in step_send_credentials. Return empty bytes as a safety fallback
                // to avoid leaking real credentials if this path is ever reached.
                Vec::new()
            }
        }
    }

    /// Build TSCredentials with TSPasswordCreds (credType = 1).
    fn build_ts_password_creds(&self) -> Vec<u8> {
        let username = core::str::from_utf8(&self.username).unwrap_or("");
        let password = core::str::from_utf8(&self.password).unwrap_or("");
        let domain = core::str::from_utf8(&self.domain).unwrap_or("");

        let domain_utf16 = to_utf16le(domain);
        let user_utf16 = to_utf16le(username);
        let pass_utf16 = to_utf16le(password);

        // TSPasswordCreds ::= SEQUENCE {
        //   domainName [0] OCTET STRING,
        //   userName [1] OCTET STRING,
        //   password [2] OCTET STRING
        // }
        let mut pass_creds_body = Vec::new();
        pass_creds_body.extend(der_context_tag(0, &der_octet_string(&domain_utf16)));
        pass_creds_body.extend(der_context_tag(1, &der_octet_string(&user_utf16)));
        pass_creds_body.extend(der_context_tag(2, &der_octet_string(&pass_utf16)));
        let pass_creds = der_sequence(&pass_creds_body);

        // TSCredentials ::= SEQUENCE {
        //   credType [0] INTEGER (1 = password),
        //   credentials [1] OCTET STRING (TSPasswordCreds)
        // }
        let mut creds_body = Vec::new();
        creds_body.extend(der_context_tag(0, &der_integer(1)));
        creds_body.extend(der_context_tag(1, &der_octet_string(&pass_creds)));
        der_sequence(&creds_body)
    }

}

// ── Remote Credential Guard (MS-CSSP 2.2.1.2.3) ──

/// Build TSCredentials with TSRemoteGuardCreds (credType = 6).
///
/// ```text
/// TSRemoteGuardPackageCred ::= SEQUENCE {
///   packageName [0] OCTET STRING (UTF-16LE),
///   credBuffer  [1] OCTET STRING (AP-REQ token)
/// }
///
/// TSRemoteGuardCreds ::= SEQUENCE {
///   logonCred          [0] TSRemoteGuardPackageCred,
///   supplementalCreds  [1] SEQUENCE OF TSRemoteGuardPackageCred OPTIONAL
/// }
///
/// TSCredentials ::= SEQUENCE {
///   credType    [0] INTEGER (6),
///   credentials [1] OCTET STRING (TSRemoteGuardCreds)
/// }
/// ```
fn build_ts_remote_guard_creds(
    kerberos_token: &[u8],
    supplemental_creds: &[SupplementalCred],
) -> Vec<u8> {
    // TSRemoteGuardPackageCred for Kerberos (logon credential)
    // packageName is UTF-16LE per MS-CSSP 2.2.1.2.3 (UNICODE-STRING)
    let kerberos_utf16 = to_utf16le("Kerberos");
    let logon_cred = build_package_cred(&kerberos_utf16, kerberos_token);

    // TSRemoteGuardCreds
    let mut guard_creds_body = Vec::new();
    guard_creds_body.extend(der_context_tag(0, &logon_cred));

    // supplementalCreds [1] SEQUENCE OF TSRemoteGuardPackageCred OPTIONAL
    // Used for Compound Identity (device claims via device Kerberos token)
    if !supplemental_creds.is_empty() {
        let mut seq_body = Vec::new();
        for cred in supplemental_creds {
            // packageName should be UTF-16LE; caller provides raw bytes
            seq_body.extend(build_package_cred(&cred.package_name, &cred.cred_buffer));
        }
        guard_creds_body.extend(der_context_tag(1, &der_sequence(&seq_body)));
    }

    let guard_creds = der_sequence(&guard_creds_body);

    // TSCredentials
    let mut creds_body = Vec::new();
    creds_body.extend(der_context_tag(0, &der_integer(6))); // credType = 6
    creds_body.extend(der_context_tag(1, &der_octet_string(&guard_creds)));
    der_sequence(&creds_body)
}

/// Build a single TSRemoteGuardPackageCred.
fn build_package_cred(package_name: &[u8], cred_buffer: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(der_context_tag(0, &der_octet_string(package_name)));
    body.extend(der_context_tag(1, &der_octet_string(cred_buffer)));
    der_sequence(&body)
}

// ── ASN.1 DER helpers ──

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut r = vec![0x30];
    r.extend(der_length(content.len()));
    r.extend_from_slice(content);
    r
}

fn der_context_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut r = vec![0xA0 | tag];
    r.extend(der_length(content.len()));
    r.extend_from_slice(content);
    r
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut r = vec![0x04];
    r.extend(der_length(data.len()));
    r.extend_from_slice(data);
    r
}

fn der_integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let significant = &bytes[start..];

    let mut result = vec![0x02];
    if significant[0] & 0x80 != 0 {
        result.extend(der_length(significant.len() + 1));
        result.push(0x00);
    } else {
        result.extend(der_length(significant.len()));
    }
    result.extend_from_slice(significant);
    result
}

/// Extract SubjectPublicKey (BIT STRING value) from DER-encoded SubjectPublicKeyInfo.
///
/// SPKI structure:
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm            AlgorithmIdentifier,
///     subjectPublicKey     BIT STRING
/// }
/// ```
///
/// Returns the BIT STRING contents (including the leading unused-bits byte).
///
/// MS-CSSP 3.1.5.2.1: the SubjectPublicKey includes "the initial octet
/// that encodes the number of unused bits".
fn extract_subject_public_key(spki: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;

    // Outer SEQUENCE
    if pos >= spki.len() || spki[pos] != 0x30 {
        return None;
    }
    pos += 1;
    der_skip_length(spki, &mut pos)?;

    // AlgorithmIdentifier - skip entire TLV
    der_skip_content_tlv(spki, &mut pos)?;

    // subjectPublicKey BIT STRING
    if pos >= spki.len() || spki[pos] != 0x03 {
        return None;
    }
    pos += 1;
    let len = der_read_content_length(spki, &mut pos)?;
    if pos + len > spki.len() || len == 0 {
        return None;
    }

    // Skip the BIT STRING "unused bits" byte (always 0x00 for keys).
    // MS-CSSP uses the SubjectPublicKey VALUE (the actual key bits),
    // not the DER encoding. Windows CRYPT_BIT_BLOB.pbData excludes this byte.
    Some(spki[pos + 1..pos + len].to_vec())
}

/// Skip a DER length field, returning the length value.
fn der_skip_length(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= data.len() {
        return None;
    }
    let first = data[*pos];
    *pos += 1;
    if first < 0x80 {
        Some(first as usize)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || *pos + n > data.len() {
            return None;
        }
        let mut length = 0usize;
        for i in 0..n {
            length = (length << 8) | data[*pos + i] as usize;
        }
        *pos += n;
        Some(length)
    }
}

/// Read a DER length field (same as der_skip_length but named for clarity).
fn der_read_content_length(data: &[u8], pos: &mut usize) -> Option<usize> {
    der_skip_length(data, pos)
}

/// Skip an entire DER TLV (tag + length + value).
fn der_skip_content_tlv(data: &[u8], pos: &mut usize) -> Option<()> {
    if *pos >= data.len() {
        return None;
    }
    *pos += 1; // skip tag
    let len = der_skip_length(data, pos)?;
    if *pos + len > data.len() {
        return None;
    }
    *pos += len;
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_random() -> CredsspRandom {
        CredsspRandom {
            client_nonce: [0x11u8; 32],
            client_challenge: [0x22u8; 8],
            exported_session_key: [0x33u8; 16],
        }
    }

    #[test]
    fn credssp_initial_state() {
        let seq = CredsspSequence::new("user", "pass", "DOMAIN", vec![0xAA; 32], test_random(), false);
        assert_eq!(*seq.state(), CredsspState::SendNegoToken);
    }

    #[test]
    fn credssp_send_negotiate_produces_ts_request() {
        let mut seq = CredsspSequence::new("user", "pass", "DOMAIN", vec![0xAA; 32], test_random(), false);
        let output = seq.step(&[]).unwrap();

        let ts_req = TsRequest::decode(&output).unwrap();
        assert!(ts_req.nego_tokens.is_some());
        // clientNonce is sent with Authenticate TsRequest, not here (MS-CSSP 3.1.5)
        assert!(ts_req.client_nonce.is_none());
        assert_eq!(*seq.state(), CredsspState::WaitChallenge);
    }

    #[test]
    fn build_ts_credentials() {
        let seq = CredsspSequence::new("admin", "password123", "CORP", vec![], test_random(), false);
        let creds = seq.build_ts_credentials();

        assert_eq!(creds[0], 0x30); // SEQUENCE tag
        assert!(creds.len() > 10);
    }

    #[test]
    fn ntlm_encrypt_produces_mac_and_data() {
        let mut seq = CredsspSequence::new("user", "pass", "", vec![], test_random(), false);
        seq.exported_session_key = [0x55u8; 16];
        seq.send_signing_key = signing::signing_key(&seq.exported_session_key, true);
        let seal_key = signing::sealing_key(&seq.exported_session_key, true);
        seq.send_sealing_rc4 = Some(Rc4::new(&seal_key));

        let result = seq.ntlm_encrypt(b"hello");

        // Signature(16) + EncryptedData(5)
        assert_eq!(result.len(), 16 + 5);
        // Version should be 1
        assert_eq!(u32::from_le_bytes(result[..4].try_into().unwrap()), 1);
        // SeqNum should be 0
        assert_eq!(u32::from_le_bytes(result[12..16].try_into().unwrap()), 0);
    }

    #[test]
    fn ntlm_encrypt_increments_seq_num() {
        let mut seq = CredsspSequence::new("user", "pass", "", vec![], test_random(), false);
        seq.exported_session_key = [0x55u8; 16];
        seq.send_signing_key = signing::signing_key(&seq.exported_session_key, true);
        let seal_key = signing::sealing_key(&seq.exported_session_key, true);
        seq.send_sealing_rc4 = Some(Rc4::new(&seal_key));

        let r1 = seq.ntlm_encrypt(b"msg1");
        let r2 = seq.ntlm_encrypt(b"msg2");

        let seq1 = u32::from_le_bytes(r1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(r2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    #[test]
    fn extract_subject_public_key_from_rsa_spki() {
        // Minimal RSA SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        // AlgorithmIdentifier = SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }
        let spki = vec![
            0x30, 0x1F, // SEQUENCE (31 bytes)
                0x30, 0x0D, // AlgorithmIdentifier SEQUENCE (13 bytes)
                    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // OID
                    0x05, 0x00, // NULL
                0x03, 0x0E, // BIT STRING (14 bytes)
                    0x00, // unused bits = 0
                    0x30, 0x0B, 0x02, 0x03, 0x01, 0x00, 0x01, // mock RSA key data
                    0x02, 0x04, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = extract_subject_public_key(&spki).unwrap();
        // Should get BIT STRING value WITHOUT unused-bits byte (13 bytes)
        assert_eq!(result.len(), 13);
        assert_eq!(result[0], 0x30); // RSA key SEQUENCE tag (not 0x00 unused bits)
    }

    #[test]
    fn build_ts_remote_guard_credentials() {
        let token = vec![0x60, 0x82, 0x01, 0x00]; // mock AP-REQ
        let creds = super::build_ts_remote_guard_creds(&token, &[]);

        assert_eq!(creds[0], 0x30); // outer SEQUENCE
        assert!(creds.len() > 10);
        // Should contain "Kerberos" as UTF-16LE
        let kerberos_utf16 = to_utf16le("Kerberos");
        assert!(creds.windows(kerberos_utf16.len()).any(|w| w == kerberos_utf16.as_slice()));
    }

    #[test]
    fn build_ts_credentials_remote_guard() {
        let seq = CredsspSequence::with_credential_type(
            "admin", "", "CORP", vec![], test_random(), false,
            CredentialType::RemoteGuard { kerberos_token: vec![0xAA; 16], supplemental_creds: vec![] },
        );
        let creds = seq.build_ts_credentials();
        assert_eq!(creds[0], 0x30); // SEQUENCE
        let kerberos_utf16 = to_utf16le("Kerberos");
        assert!(creds.windows(kerberos_utf16.len()).any(|w| w == kerberos_utf16.as_slice()));
    }

    #[test]
    fn restricted_admin_omits_auth_info() {
        // Restricted Admin: step_send_credentials should produce TsRequest with no authInfo
        let mut seq = CredsspSequence::with_credential_type(
            "", "", "", vec![], test_random(), false,
            CredentialType::RestrictedAdmin,
        );
        // Initialize sealing keys (needed by ntlm_encrypt if called, but shouldn't be for RestrictedAdmin)
        seq.exported_session_key = [0x55u8; 16];
        seq.send_signing_key = signing::signing_key(&seq.exported_session_key, true);
        let seal_key = signing::sealing_key(&seq.exported_session_key, true);
        seq.send_sealing_rc4 = Some(Rc4::new(&seal_key));
        seq.state = CredsspState::SendCredentials;
        seq.negotiated_version = 6;

        let output = seq.step(&[]).unwrap();
        let ts_req = TsRequest::decode(&output).unwrap();
        // authInfo must be absent for Restricted Admin
        assert!(ts_req.auth_info.is_none(), "Restricted Admin must omit authInfo");
        assert_eq!(*seq.state(), CredsspState::Done);
    }

    // ── Test #6: ntlm_encrypt / ntlm_decrypt roundtrip (covers crypto path used by pubKeyAuth) ──

    #[test]
    fn ntlm_encrypt_decrypt_roundtrip() {
        let key = [0x55u8; 16];

        let mut seq = CredsspSequence::new("user", "pass", "", vec![], test_random(), false);
        seq.exported_session_key = key;
        seq.send_signing_key = signing::signing_key(&key, true);
        let send_seal_key = signing::sealing_key(&key, true);
        seq.send_sealing_rc4 = Some(Rc4::new(&send_seal_key));
        // Setup receive with same direction as send (for roundtrip test)
        seq.recv_signing_key = signing::signing_key(&key, true);
        let recv_seal_key = signing::sealing_key(&key, true);
        seq.recv_sealing_rc4 = Some(Rc4::new(&recv_seal_key));

        let plaintext = b"SubjectPublicKey data for pubKeyAuth test";
        let sealed = seq.ntlm_encrypt(plaintext);
        let decrypted = seq.ntlm_decrypt(&sealed).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ── Test #7: compute_pub_key_auth for v5+ and v2-v4 ──

    #[test]
    fn compute_pub_key_auth_v5_uses_sha256() {
        // Minimal RSA SPKI
        let spki = vec![
            0x30, 0x1F,
                0x30, 0x0D,
                    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
                    0x05, 0x00,
                0x03, 0x0E,
                    0x00,
                    0x30, 0x0B, 0x02, 0x03, 0x01, 0x00, 0x01,
                    0x02, 0x04, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut seq = CredsspSequence::new("user", "pass", "", spki.clone(), test_random(), false);
        seq.exported_session_key = [0x55u8; 16];
        seq.send_signing_key = signing::signing_key(&seq.exported_session_key, true);
        let seal_key = signing::sealing_key(&seq.exported_session_key, true);
        seq.send_sealing_rc4 = Some(Rc4::new(&seal_key));

        // v5+: should produce encrypted SHA256 hash
        seq.negotiated_version = 6;
        let auth_v5 = seq.compute_pub_key_auth().unwrap();
        // signature(16) + encrypted_data(32 = SHA256 output)
        assert_eq!(auth_v5.len(), 16 + 32);
    }

    #[test]
    fn compute_pub_key_auth_v4_uses_raw_key() {
        let spki = vec![
            0x30, 0x1F,
                0x30, 0x0D,
                    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
                    0x05, 0x00,
                0x03, 0x0E,
                    0x00,
                    0x30, 0x0B, 0x02, 0x03, 0x01, 0x00, 0x01,
                    0x02, 0x04, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut seq = CredsspSequence::new("user", "pass", "", spki.clone(), test_random(), false);
        seq.exported_session_key = [0x55u8; 16];
        seq.send_signing_key = signing::signing_key(&seq.exported_session_key, true);
        let seal_key = signing::sealing_key(&seq.exported_session_key, true);
        seq.send_sealing_rc4 = Some(Rc4::new(&seal_key));

        // v4: should produce encrypted raw SubjectPublicKey (14 bytes = BIT STRING content)
        seq.negotiated_version = 4;
        let auth_v4 = seq.compute_pub_key_auth().unwrap();
        // signature(16) + encrypted_data(14 = BIT STRING content length)
        // signature(16) + encrypted_data(13 = BIT STRING content without unused bits byte)
        assert_eq!(auth_v4.len(), 16 + 13);
    }

    // ── Test #8: EarlyUserAuthResult success and error paths ──

    #[test]
    fn early_user_auth_result_success() {
        let mut seq = CredsspSequence::new("user", "pass", "", vec![], test_random(), true);
        seq.state = CredsspState::WaitEarlyUserAuth;

        // Success: 4-byte LE 0x00000000
        let input = 0u32.to_le_bytes();
        let result = seq.step(&input).unwrap();
        assert!(result.is_empty());
        assert_eq!(*seq.state(), CredsspState::Done);
    }

    #[test]
    fn early_user_auth_result_failure() {
        let mut seq = CredsspSequence::new("user", "pass", "", vec![], test_random(), true);
        seq.state = CredsspState::WaitEarlyUserAuth;

        // Failure: LOGON_FAILED_OTHER (0x00000001)
        let input = 1u32.to_le_bytes();
        let result = seq.step(&input);
        assert!(result.is_err());
    }

    // ── Test #10: v2-v4 omits clientNonce from authenticate TsRequest ──

    #[test]
    fn v4_negotiate_omits_client_nonce_in_authenticate() {
        // Verify that when negotiated_version < 5, clientNonce is not sent
        // in the authenticate TsRequest (step_process_challenge path).
        // We can't easily drive step_process_challenge without a real NTLM
        // Challenge, but we can verify the TsRequest building logic:
        let mut ts_request = TsRequest::new();
        ts_request.version = 4;
        ts_request.nego_tokens = Some(vec![0x01]);
        ts_request.pub_key_auth = Some(vec![0x02]);
        // Do NOT set client_nonce for v4
        let encoded = ts_request.encode();
        let decoded = TsRequest::decode(&encoded).unwrap();
        assert!(decoded.client_nonce.is_none(), "v4 TsRequest should not have clientNonce");
    }

    #[test]
    fn v5_includes_client_nonce() {
        let mut ts_request = TsRequest::new();
        ts_request.version = 5;
        ts_request.nego_tokens = Some(vec![0x01]);
        ts_request.client_nonce = Some([0xCC; 32]);
        let encoded = ts_request.encode();
        let decoded = TsRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.client_nonce, Some([0xCC; 32]));
    }

    #[test]
    fn build_ts_credentials_compound_identity() {
        let device_token = vec![0xDD; 32]; // mock device AP-REQ
        let kerberos_utf16 = to_utf16le("Kerberos");
        let seq = CredsspSequence::with_credential_type(
            "admin", "", "CORP", vec![], test_random(), false,
            CredentialType::RemoteGuard {
                kerberos_token: vec![0xAA; 16],
                supplemental_creds: vec![
                    SupplementalCred {
                        package_name: kerberos_utf16.clone(),
                        cred_buffer: device_token.clone(),
                    },
                ],
            },
        );
        let creds = seq.build_ts_credentials();
        assert_eq!(creds[0], 0x30); // SEQUENCE
        // Should contain "Kerberos" (UTF-16LE) twice (logon + supplemental)
        let kerberos_count = creds.windows(kerberos_utf16.len())
            .filter(|w| *w == kerberos_utf16.as_slice())
            .count();
        assert_eq!(kerberos_count, 2);
        // Should contain the device token
        assert!(creds.windows(32).any(|w| w == device_token.as_slice()));
    }

    // ── Test: mechListMIC + pubKeyAuth roundtrip (client↔server simulation) ──

    /// Simulate the server-side verification of mechListMIC and pubKeyAuth.
    ///
    /// This verifies that the seq_num ordering (mechListMIC=0, pubKeyAuth=1) is
    /// consistent between the client's sign/seal and the server's verify/unseal.
    #[test]
    fn mech_list_mic_and_pub_key_auth_roundtrip() {
        let key = [0x55u8; 16];
        let mech_types = spnego::mech_types_bytes();
        let pub_key_data = b"fake SubjectPublicKey for testing";

        // ── Client side: mechListMIC (seq=0) then pubKeyAuth (seq=1) ──
        let mut client = CredsspSequence::new("user", "pass", "", vec![], test_random(), false);
        client.exported_session_key = key;
        client.send_signing_key = signing::signing_key(&key, true);
        let send_seal_key = signing::sealing_key(&key, true);
        client.send_sealing_rc4 = Some(Rc4::new(&send_seal_key));

        let client_mic = client.ntlm_sign(&mech_types);   // seq_num=0
        let client_sealed = client.ntlm_encrypt(pub_key_data); // seq_num=1

        assert_eq!(client.send_seq_num, 2);
        assert_eq!(u32::from_le_bytes(client_mic[12..16].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(client_sealed[12..16].try_into().unwrap()), 1);

        // ── Server side: verify mechListMIC (seq=0) then unseal pubKeyAuth (seq=1) ──
        // Server uses client-to-server keys for verification (same direction).
        let server_sign_key = signing::signing_key(&key, true);
        let server_seal_key = signing::sealing_key(&key, true);
        let mut server_rc4 = Rc4::new(&server_seal_key);
        let mut server_seq_num: u32 = 0;

        // Verify mechListMIC (sign-only, no decryption)
        {
            let seq_num = server_seq_num;
            server_seq_num += 1;

            // Recompute HMAC_MD5(SigningKey, SeqNum + mechTypes)
            let mut hmac_input = vec![0u8; 4 + mech_types.len()];
            hmac_input[..4].copy_from_slice(&seq_num.to_le_bytes());
            hmac_input[4..].copy_from_slice(&mech_types);
            let digest = hmac_md5(&server_sign_key, &hmac_input);

            // RC4-encrypt first 8 bytes (advances server RC4 stream)
            let mut expected_checksum = [0u8; 8];
            expected_checksum.copy_from_slice(&digest[..8]);
            server_rc4.process(&mut expected_checksum);

            // Compare with client's mechListMIC
            assert_eq!(&client_mic[..4], &1u32.to_le_bytes(), "version mismatch");
            assert_eq!(&client_mic[4..12], &expected_checksum, "mechListMIC checksum mismatch");
            assert_eq!(&client_mic[12..16], &seq_num.to_le_bytes(), "mechListMIC seq_num mismatch");
        }

        // Unseal pubKeyAuth (decrypt + verify)
        {
            let seq_num = server_seq_num;
            // server_seq_num += 1;

            let encrypted_data = &client_sealed[16..];
            let client_checksum = &client_sealed[4..12];

            // Step 1: RC4-decrypt message data
            let mut plaintext = encrypted_data.to_vec();
            server_rc4.process(&mut plaintext);

            assert_eq!(plaintext, pub_key_data, "pubKeyAuth decryption mismatch");

            // Step 2: HMAC over SeqNum + decrypted plaintext
            let mut hmac_input = vec![0u8; 4 + plaintext.len()];
            hmac_input[..4].copy_from_slice(&seq_num.to_le_bytes());
            hmac_input[4..].copy_from_slice(&plaintext);
            let digest = hmac_md5(&server_sign_key, &hmac_input);

            // Step 3: RC4-encrypt checksum
            let mut expected_checksum = [0u8; 8];
            expected_checksum.copy_from_slice(&digest[..8]);
            server_rc4.process(&mut expected_checksum);

            assert_eq!(client_checksum, &expected_checksum, "pubKeyAuth MAC mismatch");
        }
    }

    /// Same test but with reversed order (pubKeyAuth=0, mechListMIC=1).
    /// Both orders should produce internally-consistent results — but only
    /// one matches what the server expects. This test verifies the crypto
    /// is self-consistent for both orderings.
    #[test]
    fn pub_key_auth_then_mech_list_mic_roundtrip() {
        let key = [0x55u8; 16];
        let mech_types = spnego::mech_types_bytes();
        let pub_key_data = b"fake SubjectPublicKey for testing";

        // ── Client side: pubKeyAuth (seq=0) then mechListMIC (seq=1) ──
        let mut client = CredsspSequence::new("user", "pass", "", vec![], test_random(), false);
        client.exported_session_key = key;
        client.send_signing_key = signing::signing_key(&key, true);
        let send_seal_key = signing::sealing_key(&key, true);
        client.send_sealing_rc4 = Some(Rc4::new(&send_seal_key));

        let client_sealed = client.ntlm_encrypt(pub_key_data); // seq_num=0
        let client_mic = client.ntlm_sign(&mech_types);        // seq_num=1

        // ── Server side: unseal pubKeyAuth (seq=0) then verify mechListMIC (seq=1) ──
        let server_sign_key = signing::signing_key(&key, true);
        let server_seal_key = signing::sealing_key(&key, true);
        let mut server_rc4 = Rc4::new(&server_seal_key);
        let mut server_seq_num: u32 = 0;

        // Unseal pubKeyAuth first
        {
            let seq_num = server_seq_num;
            server_seq_num += 1;

            let mut plaintext = client_sealed[16..].to_vec();
            server_rc4.process(&mut plaintext);
            assert_eq!(plaintext, pub_key_data);

            let mut hmac_input = vec![0u8; 4 + plaintext.len()];
            hmac_input[..4].copy_from_slice(&seq_num.to_le_bytes());
            hmac_input[4..].copy_from_slice(&plaintext);
            let digest = hmac_md5(&server_sign_key, &hmac_input);

            let mut expected_checksum = [0u8; 8];
            expected_checksum.copy_from_slice(&digest[..8]);
            server_rc4.process(&mut expected_checksum);
            assert_eq!(&client_sealed[4..12], &expected_checksum, "pubKeyAuth MAC mismatch (order B)");
        }

        // Verify mechListMIC second
        {
            let seq_num = server_seq_num;

            let mut hmac_input = vec![0u8; 4 + mech_types.len()];
            hmac_input[..4].copy_from_slice(&seq_num.to_le_bytes());
            hmac_input[4..].copy_from_slice(&mech_types);
            let digest = hmac_md5(&server_sign_key, &hmac_input);

            let mut expected_checksum = [0u8; 8];
            expected_checksum.copy_from_slice(&digest[..8]);
            server_rc4.process(&mut expected_checksum);
            assert_eq!(&client_mic[4..12], &expected_checksum, "mechListMIC checksum mismatch (order B)");
        }
    }
}
