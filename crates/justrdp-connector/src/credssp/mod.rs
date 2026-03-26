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
    /// Package name (e.g., "Kerberos").
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
        // Always include clientNonce; server version determines if it's used for pubKeyAuth.
        ts_request.client_nonce = Some(self.random.client_nonce);

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

        // Use user-supplied domain for NTOWFv2 (can be empty for workgroup servers)
        let response_key = ntowfv2(password, username, domain_str);

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
            &modified_target_info,  // Use MODIFIED target_info (with MsvAvFlags, etc.)
            has_timestamp,          // When true, LM response = Z(24)
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
            domain_name: to_utf16le(domain_str),
            user_name: to_utf16le(username),
            workstation: Vec::new(),
            encrypted_random_session_key,
            version: Some(NtlmVersion::windows_10()),
            mic: [0u8; 16], // Zeroed for MIC computation
        };

        // Compute MIC: HMAC_MD5(ExportedSessionKey, Negotiate + Challenge + Authenticate_with_zeroed_MIC)
        let auth_bytes_zeroed_mic = authenticate.to_bytes();
        let mic = compute_mic(
            &self.exported_session_key,
            &self.negotiate_bytes,
            &self.challenge_bytes,
            &auth_bytes_zeroed_mic,
        );
        authenticate.mic = mic;
        let authenticate_bytes = authenticate.to_bytes();

        // Initialize persistent signing/sealing keys from ExportedSessionKey
        // Client-to-server (send)
        self.send_signing_key = signing::signing_key(&self.exported_session_key, true);
        let seal_key = signing::sealing_key(&self.exported_session_key, true);
        self.send_sealing_rc4 = Some(Rc4::new(&seal_key));
        // Server-to-client (receive) — for pubKeyAuth verification
        self.recv_signing_key = signing::signing_key(&self.exported_session_key, false);
        let recv_seal_key = signing::sealing_key(&self.exported_session_key, false);
        self.recv_sealing_rc4 = Some(Rc4::new(&recv_seal_key));

        // Compute pubKeyAuth
        let pub_key_auth = self.compute_pub_key_auth()?;

        // Wrap Authenticate in SPNEGO NegTokenResp
        let spnego_token = spnego::wrap_authenticate(&authenticate_bytes);

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

        let server_pub_key_auth = server_ts.pub_key_auth
            .ok_or_else(|| ConnectorError::general("server TsRequest missing pubKeyAuth"))?;

        // Decrypt server's pubKeyAuth
        let decrypted = self.ntlm_decrypt(&server_pub_key_auth)?;

        // Verify server's hash
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
        let ts_credentials = self.build_ts_credentials();
        let encrypted = self.ntlm_encrypt(&ts_credentials);

        let mut ts_request = TsRequest::new();
        ts_request.version = self.negotiated_version;
        ts_request.auth_info = Some(encrypted);

        if self.use_hybrid_ex {
            self.state = CredsspState::WaitEarlyUserAuth;
        } else {
            self.state = CredsspState::Done;
        }
        Ok(ts_request.encode())
    }

    /// Process EarlyUserAuthResult (HYBRID_EX only, MS-CSSP 2.2.1.1).
    ///
    /// The server sends a 4-byte NTSTATUS code:
    /// - `STATUS_LOGON_FAILURE` (0xC000006D) = auth failed
    /// - other non-zero = error
    /// - 0 = success (proceed with RDP connection)
    fn step_wait_early_user_auth(&mut self, input: &[u8]) -> ConnectorResult<Vec<u8>> {
        // EarlyUserAuthResult is a raw 4-byte NTSTATUS, not a TsRequest.
        if input.len() < 4 {
            return Err(ConnectorError::general("EarlyUserAuthResult too short"));
        }

        let status = u32::from_le_bytes(input[..4].try_into().unwrap());
        if status != 0 {
            return Err(ConnectorError::general("EarlyUserAuthResult: authentication failed"));
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
        let subject_public_key = extract_subject_public_key(&self.server_public_key)
            .ok_or_else(|| ConnectorError::general(
                "failed to extract SubjectPublicKey from SPKI",
            ))?;

        if self.negotiated_version >= 5 {
            // v5+: SHA256 hash
            let mut hasher = Sha256::new();
            hasher.update(CLIENT_SERVER_HASH_MAGIC);
            hasher.update(&self.random.client_nonce);
            hasher.update(&subject_public_key);
            let hash = hasher.finalize();
            Ok(self.ntlm_encrypt(&hash))
        } else {
            // v2-v4: encrypt SubjectPublicKey
            Ok(self.ntlm_encrypt(&subject_public_key))
        }
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
    fn build_ts_credentials(&self) -> Vec<u8> {
        match &self.credential_type {
            CredentialType::Password => self.build_ts_password_creds(),
            CredentialType::RemoteGuard { kerberos_token, supplemental_creds } => {
                build_ts_remote_guard_creds(kerberos_token, supplemental_creds)
            }
            CredentialType::RestrictedAdmin => self.build_ts_restricted_admin_creds(),
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

    /// Build TSCredentials for Restricted Admin (credType = 1, empty password).
    fn build_ts_restricted_admin_creds(&self) -> Vec<u8> {
        // Restricted Admin: send empty credentials
        let mut pass_creds_body = Vec::new();
        pass_creds_body.extend(der_context_tag(0, &der_octet_string(&[]))); // empty domain
        pass_creds_body.extend(der_context_tag(1, &der_octet_string(&[]))); // empty user
        pass_creds_body.extend(der_context_tag(2, &der_octet_string(&[]))); // empty password
        let pass_creds = der_sequence(&pass_creds_body);

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
///   packageName [0] OCTET STRING (UTF-8 "Kerberos"),
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
    let logon_cred = build_package_cred(b"Kerberos", kerberos_token);

    // TSRemoteGuardCreds
    let mut guard_creds_body = Vec::new();
    guard_creds_body.extend(der_context_tag(0, &logon_cred));

    // supplementalCreds [1] SEQUENCE OF TSRemoteGuardPackageCred OPTIONAL
    // Used for Compound Identity (device claims via device Kerberos token)
    if !supplemental_creds.is_empty() {
        let mut seq_body = Vec::new();
        for cred in supplemental_creds {
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
    if pos + len > spki.len() {
        return None;
    }

    Some(spki[pos..pos + len].to_vec())
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
        assert!(ts_req.client_nonce.is_some());
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
        // Should get BIT STRING contents (14 bytes including unused-bits byte)
        assert_eq!(result.len(), 14);
        assert_eq!(result[0], 0x00); // unused bits byte
    }

    #[test]
    fn build_ts_remote_guard_credentials() {
        let token = vec![0x60, 0x82, 0x01, 0x00]; // mock AP-REQ
        let creds = super::build_ts_remote_guard_creds(&token, &[]);

        assert_eq!(creds[0], 0x30); // outer SEQUENCE
        // Verify credType = 6 is encoded
        // Find the INTEGER value inside context [0]
        assert!(creds.len() > 10);
        // Should contain "Kerberos" package name
        assert!(creds.windows(8).any(|w| w == b"Kerberos"));
    }

    #[test]
    fn build_ts_credentials_remote_guard() {
        let seq = CredsspSequence::with_credential_type(
            "admin", "", "CORP", vec![], test_random(), false,
            CredentialType::RemoteGuard { kerberos_token: vec![0xAA; 16], supplemental_creds: vec![] },
        );
        let creds = seq.build_ts_credentials();
        assert_eq!(creds[0], 0x30); // SEQUENCE
        assert!(creds.windows(8).any(|w| w == b"Kerberos"));
    }

    #[test]
    fn build_ts_credentials_restricted_admin() {
        let seq = CredsspSequence::with_credential_type(
            "", "", "", vec![], test_random(), false,
            CredentialType::RestrictedAdmin,
        );
        let creds = seq.build_ts_credentials();
        assert_eq!(creds[0], 0x30); // SEQUENCE
        // Should be relatively short (empty credentials)
        assert!(creds.len() < 30);
    }

    #[test]
    fn build_ts_credentials_compound_identity() {
        let device_token = vec![0xDD; 32]; // mock device AP-REQ
        let seq = CredsspSequence::with_credential_type(
            "admin", "", "CORP", vec![], test_random(), false,
            CredentialType::RemoteGuard {
                kerberos_token: vec![0xAA; 16],
                supplemental_creds: vec![
                    SupplementalCred {
                        package_name: b"Kerberos".to_vec(),
                        cred_buffer: device_token.clone(),
                    },
                ],
            },
        );
        let creds = seq.build_ts_credentials();
        assert_eq!(creds[0], 0x30); // SEQUENCE
        // Should contain "Kerberos" twice (logon + supplemental)
        let kerberos_count = creds.windows(8)
            .filter(|w| *w == b"Kerberos")
            .count();
        assert_eq!(kerberos_count, 2);
        // Should contain the device token
        assert!(creds.windows(32).any(|w| w == device_token.as_slice()));
    }
}
