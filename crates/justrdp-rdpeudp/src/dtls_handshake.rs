#![forbid(unsafe_code)]

//! DTLS 1.0/1.2 client handshake state machine.
//!
//! Drives the minimal DTLS handshake needed by MS-RDPEUDP:
//!
//! ```text
//! Client                          Server
//!   ClientHello          →
//!                        ← HelloVerifyRequest (optional)
//!   ClientHello+cookie   →
//!                        ← ServerHello
//!                        ← Certificate
//!                        ← ServerHelloDone
//!   ClientKeyExchange    →
//!   ChangeCipherSpec     →
//!   Finished             →
//!                        ← ChangeCipherSpec
//!                        ← Finished
//!   <application data>   ↔ <application data>
//! ```
//!
//! The state machine produces and consumes [`DtlsRecord`]s. It is
//! sans-io: the caller is responsible for sending the records over
//! the `RdpeudpSession` transport and feeding received records back.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::crypto::sha256;
use justrdp_core::rsa::RsaPublicKey;
use justrdp_core::bignum::BigUint;

use crate::dtls::*;

// =============================================================================
// State
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsState {
    /// Ready to send the first ClientHello.
    Initial,
    /// ClientHello sent, waiting for ServerHello or HelloVerifyRequest.
    WaitServerHello,
    /// Received HelloVerifyRequest — will resend ClientHello with cookie.
    GotHelloVerifyRequest,
    /// ServerHello received, waiting for Certificate.
    WaitCertificate,
    /// Certificate received, waiting for ServerHelloDone.
    WaitServerHelloDone,
    /// ServerHelloDone received — ready to send CKE + CCS + Finished.
    SendClientFinish,
    /// Client flight sent, waiting for server CCS + Finished.
    WaitServerFinished,
    /// Handshake complete. Data may flow.
    Connected,
    /// Fatal error — session is dead.
    Failed,
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug)]
pub enum DtlsError {
    /// Method called in wrong state.
    InvalidState(&'static str),
    /// Server sent unexpected handshake type.
    UnexpectedMessage(u8),
    /// Cipher suite mismatch.
    CipherMismatch,
    /// Certificate parsing failed.
    BadCertificate,
    /// Server Finished verify_data mismatch.
    VerifyDataMismatch,
    /// Encode/decode failure.
    Protocol(&'static str),
}

// =============================================================================
// Random source trait
// =============================================================================

/// Trait for injecting randomness. The DTLS handshake needs random
/// bytes for `client_random`, `pre_master_secret`, and record IVs.
pub trait DtlsRandom {
    fn fill(&mut self, buf: &mut [u8]);
}

// =============================================================================
// DtlsClientHandshake
// =============================================================================

/// Sans-io DTLS client handshake state machine.
pub struct DtlsClientHandshake {
    state: DtlsState,
    /// Client-side handshake message sequence counter.
    client_msg_seq: u16,
    /// DTLS record epoch (0 = plaintext, 1 = encrypted).
    epoch: u16,
    /// Per-epoch record sequence counter.
    record_seq: u64,
    /// Negotiated version (filled after ServerHello).
    version: [u8; 2],

    // ── Handshake transcript ──
    /// Raw bytes of all handshake messages seen so far (header +
    /// body). Needed because `Sha256` doesn't impl `Clone` — we
    /// re-hash from scratch when we need a snapshot.
    transcript_bytes: Vec<u8>,

    // ── Key material ──
    client_random: [u8; 32],
    server_random: [u8; 32],
    pre_master_secret: [u8; PRE_MASTER_SECRET_SIZE],
    master_secret: [u8; MASTER_SECRET_SIZE],
    keys: Option<KeyBlock>,
    server_public_key: Option<RsaPublicKey>,

    // ── Cookie from HelloVerifyRequest ──
    cookie: Vec<u8>,
}

impl DtlsClientHandshake {
    pub fn new<R: DtlsRandom>(rng: &mut R) -> Self {
        let mut client_random = [0u8; 32];
        rng.fill(&mut client_random);
        let mut pre_master_secret = [0u8; PRE_MASTER_SECRET_SIZE];
        // Bytes 0..2 = client version (DTLS 1.0 wire).
        pre_master_secret[0] = DTLS_1_0[0];
        pre_master_secret[1] = DTLS_1_0[1];
        rng.fill(&mut pre_master_secret[2..]);

        Self {
            state: DtlsState::Initial,
            client_msg_seq: 0,
            epoch: 0,
            record_seq: 0,
            version: DTLS_1_0,
            transcript_bytes: Vec::new(),
            client_random,
            server_random: [0; 32],
            pre_master_secret,
            master_secret: [0; MASTER_SECRET_SIZE],
            keys: None,
            server_public_key: None,
            cookie: Vec::new(),
        }
    }

    pub fn state(&self) -> DtlsState {
        self.state
    }

    pub fn is_connected(&self) -> bool {
        self.state == DtlsState::Connected
    }

    /// Return the active key block (available after handshake
    /// completes).
    pub fn keys(&self) -> Option<&KeyBlock> {
        self.keys.as_ref()
    }

    /// Return the negotiated DTLS version bytes.
    pub fn negotiated_version(&self) -> [u8; 2] {
        self.version
    }

    /// Current epoch (0 = plaintext, 1 = encrypted).
    pub fn epoch(&self) -> u16 {
        self.epoch
    }

    /// Compute SHA-256 of the transcript bytes accumulated so far.
    fn snapshot_transcript(&self) -> [u8; 32] {
        sha256(&self.transcript_bytes)
    }

    // ─────────────── Build ClientHello ───────────────

    /// Produce the ClientHello record(s). Call in `Initial` or
    /// `GotHelloVerifyRequest` state.
    pub fn build_client_hello(&mut self) -> Result<Vec<DtlsRecord>, DtlsError> {
        if self.state != DtlsState::Initial
            && self.state != DtlsState::GotHelloVerifyRequest
        {
            return Err(DtlsError::InvalidState("build_client_hello"));
        }

        let body = self.encode_client_hello_body();
        let msg_seq = if self.state == DtlsState::GotHelloVerifyRequest {
            // RFC 6347 §4.2.1: message_seq resets to 0 after HVR.
            self.client_msg_seq = 0;
            0
        } else {
            let s = self.client_msg_seq;
            self.client_msg_seq += 1;
            s
        };

        let mut hs_data = Vec::new();
        let hdr = HandshakeHeader::unfragmented(
            HT_CLIENT_HELLO,
            body.len() as u32,
            msg_seq,
        );
        hdr.encode(&mut hs_data);
        hs_data.extend_from_slice(&body);

        // Add to transcript.
        self.transcript_bytes.extend_from_slice(&hs_data);

        let record = self.make_record(CONTENT_TYPE_HANDSHAKE, hs_data);
        self.state = DtlsState::WaitServerHello;
        Ok(vec![record])
    }

    fn encode_client_hello_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(128);
        // client_version
        body.extend_from_slice(&DTLS_1_0);
        // random
        body.extend_from_slice(&self.client_random);
        // session_id (empty)
        body.push(0);
        // cookie
        body.push(self.cookie.len() as u8);
        body.extend_from_slice(&self.cookie);
        // cipher_suites: 2 suites × 2 bytes = 4 bytes
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&TLS_RSA_WITH_AES_128_CBC_SHA256);
        body.extend_from_slice(&TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        // compression_methods: 1 method, null
        body.push(1);
        body.push(0);
        // no extensions
        body
    }

    // ─────────────── Process server records ───────────────

    /// Feed a received DTLS record and optionally produce response
    /// records.
    pub fn receive(&mut self, record: &DtlsRecord) -> Result<Vec<DtlsRecord>, DtlsError> {
        match record.content_type {
            CONTENT_TYPE_HANDSHAKE => self.process_handshake(record),
            CONTENT_TYPE_CHANGE_CIPHER_SPEC => self.process_ccs(record),
            _ => Err(DtlsError::UnexpectedMessage(record.content_type)),
        }
    }

    fn process_handshake(
        &mut self,
        record: &DtlsRecord,
    ) -> Result<Vec<DtlsRecord>, DtlsError> {
        let hdr = HandshakeHeader::decode(&record.fragment)
            .ok_or(DtlsError::Protocol("short handshake header"))?;
        let body_start = DTLS_HANDSHAKE_HEADER_SIZE;
        let body_end = body_start + hdr.fragment_length as usize;
        if record.fragment.len() < body_end {
            return Err(DtlsError::Protocol("handshake body truncated"));
        }
        let body = &record.fragment[body_start..body_end];

        // Add the full handshake message to the transcript
        // (header + body, for unfragmented messages).
        self.transcript_bytes
            .extend_from_slice(&record.fragment[..body_end]);

        match hdr.msg_type {
            HT_HELLO_VERIFY_REQUEST => self.handle_hello_verify_request(body),
            HT_SERVER_HELLO => self.handle_server_hello(body),
            HT_CERTIFICATE => self.handle_certificate(body),
            HT_SERVER_HELLO_DONE => self.handle_server_hello_done(),
            HT_FINISHED => self.handle_server_finished(body),
            other => Err(DtlsError::UnexpectedMessage(other)),
        }
    }

    fn handle_hello_verify_request(
        &mut self,
        body: &[u8],
    ) -> Result<Vec<DtlsRecord>, DtlsError> {
        if self.state != DtlsState::WaitServerHello {
            return Err(DtlsError::InvalidState("HVR in wrong state"));
        }
        // body: version(2) + cookie_len(1) + cookie
        if body.len() < 3 {
            return Err(DtlsError::Protocol("HVR too short"));
        }
        let cookie_len = body[2] as usize;
        if body.len() < 3 + cookie_len {
            return Err(DtlsError::Protocol("HVR cookie truncated"));
        }
        self.cookie = body[3..3 + cookie_len].to_vec();

        // Reset transcript — the initial ClientHello is NOT part of
        // the transcript after HVR (RFC 6347 §4.2.1).
        self.transcript_bytes.clear();
        self.state = DtlsState::GotHelloVerifyRequest;

        // Immediately rebuild and return the new ClientHello.
        self.build_client_hello()
    }

    fn handle_server_hello(
        &mut self,
        body: &[u8],
    ) -> Result<Vec<DtlsRecord>, DtlsError> {
        if self.state != DtlsState::WaitServerHello {
            return Err(DtlsError::InvalidState("ServerHello in wrong state"));
        }
        if body.len() < 38 {
            return Err(DtlsError::Protocol("ServerHello too short"));
        }
        self.version = [body[0], body[1]];
        self.server_random.copy_from_slice(&body[2..34]);
        let session_id_len = body[34] as usize;
        let after_sid = 35 + session_id_len;
        if body.len() < after_sid + 3 {
            return Err(DtlsError::Protocol("ServerHello truncated after session_id"));
        }
        let cipher_suite = [body[after_sid], body[after_sid + 1]];
        if cipher_suite != TLS_RSA_WITH_AES_128_CBC_SHA256 {
            return Err(DtlsError::CipherMismatch);
        }
        // compression must be null
        if body[after_sid + 2] != 0 {
            return Err(DtlsError::Protocol("non-null compression"));
        }
        self.state = DtlsState::WaitCertificate;
        Ok(vec![])
    }

    fn handle_certificate(
        &mut self,
        body: &[u8],
    ) -> Result<Vec<DtlsRecord>, DtlsError> {
        if self.state != DtlsState::WaitCertificate {
            return Err(DtlsError::InvalidState("Certificate in wrong state"));
        }
        // body: cert_list_len(3) + [cert_len(3) + cert_der]*
        if body.len() < 3 {
            return Err(DtlsError::Protocol("Certificate body too short"));
        }
        let total_len =
            u32::from_be_bytes([0, body[0], body[1], body[2]]) as usize;
        if body.len() < 3 + total_len || total_len < 3 {
            return Err(DtlsError::Protocol("Certificate list truncated"));
        }
        // Parse the first (leaf) certificate.
        let cert_start = 3;
        let cert_len = u32::from_be_bytes([
            0,
            body[cert_start],
            body[cert_start + 1],
            body[cert_start + 2],
        ]) as usize;
        let cert_der = &body[cert_start + 3..cert_start + 3 + cert_len];

        // Extract RSA public key from the DER certificate.
        let spki = justrdp_tls_free::extract_spki(cert_der)
            .ok_or(DtlsError::BadCertificate)?;
        let pubkey = parse_rsa_spki(&spki).ok_or(DtlsError::BadCertificate)?;
        self.server_public_key = Some(pubkey);

        self.state = DtlsState::WaitServerHelloDone;
        Ok(vec![])
    }

    fn handle_server_hello_done(&mut self) -> Result<Vec<DtlsRecord>, DtlsError> {
        if self.state != DtlsState::WaitServerHelloDone {
            return Err(DtlsError::InvalidState("ServerHelloDone in wrong state"));
        }
        self.state = DtlsState::SendClientFinish;
        // The caller should now call build_client_finish_flight().
        Ok(vec![])
    }

    // ─────────────── Build client finish flight ───────────────

    /// Produce the ClientKeyExchange + ChangeCipherSpec + Finished
    /// records. Call after receiving ServerHelloDone.
    pub fn build_client_finish_flight<R: DtlsRandom>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<DtlsRecord>, DtlsError> {
        if self.state != DtlsState::SendClientFinish {
            return Err(DtlsError::InvalidState("build_client_finish_flight"));
        }
        let server_key = self
            .server_public_key
            .as_ref()
            .ok_or(DtlsError::BadCertificate)?;

        let mut records = Vec::new();

        // 1. ClientKeyExchange
        let encrypted_pms = rsa_pkcs1_v15_encrypt(
            server_key,
            &self.pre_master_secret,
            rng,
        );
        let mut cke_body = Vec::new();
        cke_body.extend_from_slice(&(encrypted_pms.len() as u16).to_be_bytes());
        cke_body.extend_from_slice(&encrypted_pms);

        let cke_seq = self.client_msg_seq;
        self.client_msg_seq += 1;
        let mut cke_data = Vec::new();
        let cke_hdr = HandshakeHeader::unfragmented(
            HT_CLIENT_KEY_EXCHANGE,
            cke_body.len() as u32,
            cke_seq,
        );
        cke_hdr.encode(&mut cke_data);
        cke_data.extend_from_slice(&cke_body);
        self.transcript_bytes.extend_from_slice(&cke_data);
        records.push(self.make_record(CONTENT_TYPE_HANDSHAKE, cke_data));

        // 2. ChangeCipherSpec
        records.push(self.make_record(
            CONTENT_TYPE_CHANGE_CIPHER_SPEC,
            vec![0x01],
        ));

        // Derive keys.
        self.master_secret = derive_master_secret(
            &self.pre_master_secret,
            &self.client_random,
            &self.server_random,
        );
        self.keys = Some(derive_key_block(
            &self.master_secret,
            &self.client_random,
            &self.server_random,
        ));

        // Epoch transition.
        self.epoch = 1;
        self.record_seq = 0;

        // 3. Finished (encrypted under epoch 1).
        let transcript_hash = self.snapshot_transcript();
        let verify_data = compute_verify_data(
            &self.master_secret,
            b"client finished",
            &transcript_hash,
        );
        let fin_seq = self.client_msg_seq;
        self.client_msg_seq += 1;
        let mut fin_data = Vec::new();
        let fin_hdr = HandshakeHeader::unfragmented(
            HT_FINISHED,
            FINISHED_VERIFY_DATA_SIZE as u32,
            fin_seq,
        );
        fin_hdr.encode(&mut fin_data);
        fin_data.extend_from_slice(&verify_data);
        // Finished is added to transcript AFTER computing verify_data
        // but BEFORE we send — needed for server's Finished.
        self.transcript_bytes.extend_from_slice(&fin_data);

        // Encrypt the Finished message.
        let keys = self.keys.as_ref().unwrap();
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let encrypted = encrypt_record(
            &keys.client_write_mac_key,
            &keys.client_write_key,
            &iv,
            CONTENT_TYPE_HANDSHAKE,
            &self.version,
            self.epoch,
            self.record_seq,
            &fin_data,
        );
        let rec = DtlsRecord {
            content_type: CONTENT_TYPE_HANDSHAKE,
            version: self.version,
            epoch: self.epoch,
            sequence_number: self.record_seq,
            fragment: encrypted,
        };
        self.record_seq += 1;
        records.push(rec);

        self.state = DtlsState::WaitServerFinished;
        Ok(records)
    }

    // ─────────────── Server CCS + Finished ───────────────

    fn process_ccs(
        &mut self,
        _record: &DtlsRecord,
    ) -> Result<Vec<DtlsRecord>, DtlsError> {
        // Just note that the server's epoch incremented; next record
        // will be encrypted. No output needed.
        Ok(vec![])
    }

    fn handle_server_finished(
        &mut self,
        body: &[u8],
    ) -> Result<Vec<DtlsRecord>, DtlsError> {
        if self.state != DtlsState::WaitServerFinished {
            return Err(DtlsError::InvalidState("Finished in wrong state"));
        }
        if body.len() < FINISHED_VERIFY_DATA_SIZE {
            return Err(DtlsError::Protocol("Finished too short"));
        }
        let transcript_hash = self.snapshot_transcript();
        let expected = compute_verify_data(
            &self.master_secret,
            b"server finished",
            &transcript_hash,
        );
        if body[..FINISHED_VERIFY_DATA_SIZE] != expected[..] {
            self.state = DtlsState::Failed;
            return Err(DtlsError::VerifyDataMismatch);
        }
        self.state = DtlsState::Connected;
        Ok(vec![])
    }

    // ─────────────── Record helpers ───────────────

    fn make_record(&mut self, content_type: u8, fragment: Vec<u8>) -> DtlsRecord {
        let rec = DtlsRecord {
            content_type,
            version: self.version,
            epoch: self.epoch,
            sequence_number: self.record_seq,
            fragment,
        };
        self.record_seq += 1;
        rec
    }
}

// =============================================================================
// PKCS#1 v1.5 Type 2 encryption (RFC 8017 §7.2.1)
// =============================================================================

/// RSA PKCS#1 v1.5 Type 2 (encryption) padding and public-key
/// encryption. Returns the ciphertext as big-endian bytes.
fn rsa_pkcs1_v15_encrypt<R: DtlsRandom>(
    key: &RsaPublicKey,
    message: &[u8],
    rng: &mut R,
) -> Vec<u8> {
    let k = key.n.bit_len().div_ceil(8);
    debug_assert!(message.len() + 11 <= k);

    // EM = 0x00 || 0x02 || PS || 0x00 || message
    let ps_len = k - message.len() - 3;
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    // PS: ps_len non-zero random bytes.
    let mut ps = vec![0u8; ps_len];
    rng.fill(&mut ps);
    // Replace any zeros (PKCS#1 requires non-zero PS).
    for b in &mut ps {
        while *b == 0 {
            let mut one = [0u8; 1];
            rng.fill(&mut one);
            *b = one[0];
        }
    }
    em.extend_from_slice(&ps);
    em.push(0x00);
    em.extend_from_slice(message);

    // RSA: c = em^e mod n (big-endian).
    let m = BigUint::from_be_bytes(&em);
    let c = m.mod_exp(&key.e, &key.n);
    c.to_be_bytes_padded(k)
}

// =============================================================================
// Minimal X.509 / SPKI helpers
// =============================================================================

/// Minimal SPKI extraction from a DER-encoded X.509 certificate.
/// Duplicates the logic from `justrdp-tls` but avoids a crate dep.
mod justrdp_tls_free {
    use alloc::vec::Vec;

    /// Minimal X.509 SPKI extraction — inlined to avoid a dep on
    /// `justrdp-tls`. Walks the DER structure of a Certificate to
    /// reach the SubjectPublicKeyInfo SEQUENCE and returns it raw.
    pub fn extract_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
        let mut pos = 0;
        // Certificate SEQUENCE
        let (_, _cert_end) = super::der_read_seq(cert_der, &mut pos)?;
        // TBSCertificate SEQUENCE
        let (_, tbs_end) = super::der_read_seq(cert_der, &mut pos)?;
        // version [0] EXPLICIT (optional)
        if pos < tbs_end && cert_der[pos] == 0xA0 {
            super::der_skip_tlv(cert_der, &mut pos)?;
            super::der_skip_tlv(cert_der, &mut pos)?; // inner INTEGER
        }
        // serialNumber
        super::der_skip_tlv(cert_der, &mut pos)?;
        // signature AlgorithmIdentifier
        super::der_skip_tlv(cert_der, &mut pos)?;
        // issuer
        super::der_skip_tlv(cert_der, &mut pos)?;
        // validity
        super::der_skip_tlv(cert_der, &mut pos)?;
        // subject
        super::der_skip_tlv(cert_der, &mut pos)?;
        // subjectPublicKeyInfo — this is what we want.
        let spki_start = pos;
        super::der_skip_tlv(cert_der, &mut pos)?;
        Some(cert_der[spki_start..pos].to_vec())
    }
}

/// Parse an RSA SubjectPublicKeyInfo DER blob into `RsaPublicKey`.
fn parse_rsa_spki(spki: &[u8]) -> Option<RsaPublicKey> {
    // SPKI = SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    // We skip the algorithm OID and parse the BIT STRING which contains
    // the RSA public key: SEQUENCE { modulus INTEGER, exponent INTEGER }.
    let mut pos = 0;
    // Outer SEQUENCE
    let (_, seq_end) = der_read_seq(spki, &mut pos)?;
    // AlgorithmIdentifier SEQUENCE — skip
    der_skip_tlv(spki, &mut pos)?;
    // BIT STRING
    if pos >= seq_end || spki[pos] != 0x03 {
        return None;
    }
    let (_, bs_end) = der_read_tl(spki, &mut pos)?;
    if pos >= bs_end {
        return None;
    }
    // Skip the "unused bits" byte (should be 0).
    pos += 1;
    // Now we're at the inner SEQUENCE { modulus, exponent }.
    let (_, rsa_end) = der_read_seq(spki, &mut pos)?;
    let n = der_read_integer_bytes(spki, &mut pos)?;
    let e = der_read_integer_bytes(spki, &mut pos)?;
    let _ = rsa_end;
    Some(RsaPublicKey {
        n: BigUint::from_be_bytes(n),
        e: BigUint::from_be_bytes(e),
    })
}

fn der_read_tl(data: &[u8], pos: &mut usize) -> Option<(u8, usize)> {
    if *pos >= data.len() {
        return None;
    }
    let tag = data[*pos];
    *pos += 1;
    let len = der_read_length(data, pos)?;
    let end = *pos + len;
    if end > data.len() {
        return None;
    }
    Some((tag, end))
}

fn der_read_seq(data: &[u8], pos: &mut usize) -> Option<(u8, usize)> {
    let (tag, end) = der_read_tl(data, pos)?;
    if tag != 0x30 {
        return None;
    }
    Some((tag, end))
}

fn der_skip_tlv(data: &[u8], pos: &mut usize) -> Option<()> {
    let (_, end) = der_read_tl(data, pos)?;
    *pos = end;
    Some(())
}

fn der_read_length(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= data.len() {
        return None;
    }
    let b = data[*pos];
    *pos += 1;
    if b < 0x80 {
        Some(b as usize)
    } else {
        let n = (b & 0x7F) as usize;
        if n == 0 || n > 4 || *pos + n > data.len() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | data[*pos] as usize;
            *pos += 1;
        }
        Some(len)
    }
}

fn der_read_integer_bytes<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    if *pos >= data.len() || data[*pos] != 0x02 {
        return None;
    }
    let (_, end) = der_read_tl(data, pos)?;
    let start = *pos;
    *pos = end;
    let mut bytes = &data[start..end];
    // Strip leading zero (sign byte for positive integers).
    if !bytes.is_empty() && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    Some(bytes)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic RNG for tests: cycles through a fixed pattern.
    struct FixedRng(u8);
    impl DtlsRandom for FixedRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
        }
    }

    #[test]
    fn client_hello_initial_produces_record() {
        let mut rng = FixedRng(0x41);
        let mut hs = DtlsClientHandshake::new(&mut rng);
        assert_eq!(hs.state(), DtlsState::Initial);

        let records = hs.build_client_hello().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(records[0].epoch, 0);
        assert_eq!(hs.state(), DtlsState::WaitServerHello);

        // The fragment should start with a HandshakeHeader for ClientHello.
        let hdr = HandshakeHeader::decode(&records[0].fragment).unwrap();
        assert_eq!(hdr.msg_type, HT_CLIENT_HELLO);
        assert_eq!(hdr.message_seq, 0);
    }

    #[test]
    fn client_hello_contains_cipher_suite() {
        let mut rng = FixedRng(0);
        let mut hs = DtlsClientHandshake::new(&mut rng);
        let records = hs.build_client_hello().unwrap();
        let frag = &records[0].fragment;
        // Search for the cipher suite bytes in the fragment.
        assert!(
            frag.windows(2)
                .any(|w| w == TLS_RSA_WITH_AES_128_CBC_SHA256),
            "cipher suite not found in ClientHello"
        );
    }

    #[test]
    fn hello_verify_request_triggers_cookie_retry() {
        let mut rng = FixedRng(0);
        let mut hs = DtlsClientHandshake::new(&mut rng);
        hs.build_client_hello().unwrap();

        // Build a fake HelloVerifyRequest.
        let cookie = b"test-cookie";
        let mut hvr_body = Vec::new();
        hvr_body.extend_from_slice(&DTLS_1_0);
        hvr_body.push(cookie.len() as u8);
        hvr_body.extend_from_slice(cookie);

        let mut frag = Vec::new();
        let hdr = HandshakeHeader::unfragmented(
            HT_HELLO_VERIFY_REQUEST,
            hvr_body.len() as u32,
            0,
        );
        hdr.encode(&mut frag);
        frag.extend_from_slice(&hvr_body);

        let hvr_record = DtlsRecord {
            content_type: CONTENT_TYPE_HANDSHAKE,
            version: DTLS_1_0,
            epoch: 0,
            sequence_number: 0,
            fragment: frag,
        };

        let retries = hs.receive(&hvr_record).unwrap();
        assert_eq!(retries.len(), 1, "should produce a new ClientHello");
        assert_eq!(hs.state(), DtlsState::WaitServerHello);

        // The retried ClientHello should contain the cookie.
        let frag = &retries[0].fragment;
        assert!(
            frag.windows(cookie.len())
                .any(|w| w == cookie),
            "cookie not found in retried ClientHello"
        );
    }

    #[test]
    fn rsa_pkcs1_v15_encrypt_produces_correct_length() {
        // Use a small "key" for testing (not cryptographically secure).
        let key = RsaPublicKey {
            n: BigUint::from_be_bytes(&[0xFF; 128]), // 1024-bit
            e: BigUint::from_be_bytes(&[0x01, 0x00, 0x01]), // 65537
        };
        let mut rng = FixedRng(0x42);
        let pms = [0xAA; PRE_MASTER_SECRET_SIZE];
        let ct = rsa_pkcs1_v15_encrypt(&key, &pms, &mut rng);
        assert_eq!(ct.len(), 128, "ciphertext must equal modulus size");
    }

    #[test]
    fn state_transitions_reject_wrong_order() {
        let mut rng = FixedRng(0);
        let mut hs = DtlsClientHandshake::new(&mut rng);
        // Can't build finish flight before handshake.
        assert!(hs.build_client_finish_flight(&mut rng).is_err());
    }
}
