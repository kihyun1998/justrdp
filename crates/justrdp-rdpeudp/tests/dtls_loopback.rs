//! End-to-end DTLS 1.0/1.2 handshake loopback.
//!
//! Drives a real `DtlsSession` (client) against a hand-rolled minimal
//! DTLS server implemented inline in this file using the same
//! primitives the production client uses (record codec, PRF, key
//! derivation, AES-CBC-SHA256 record protection). The server holds a
//! 512-bit RSA test key and a self-signed cert so it can decrypt the
//! ClientKeyExchange.
//!
//! Coverage:
//!   - Full handshake flow including HelloVerifyRequest cookie retry.
//!   - SPKI capture from the leaf certificate (MS-RDPEMT §5.1 pinning).
//!   - Bidirectional encrypted application-data round-trip after
//!     reaching the Connected state.
//!
//! The mock server is *not* production-grade; it skips alert handling,
//! retransmission, fragmentation, certificate validation, and signed
//! key exchange (we use TLS_RSA_WITH_AES_128_CBC_SHA256 — RSA key
//! transport, no signature). Sufficient for driving the client.

#![forbid(unsafe_code)]

use justrdp_core::bignum::BigUint;
use justrdp_core::crypto::sha256;
use justrdp_core::rsa::RsaPrivateKey;

use justrdp_rdpeudp::dtls::{
    compute_verify_data, ct_eq, decrypt_record, derive_key_block, derive_master_secret,
    encrypt_record, DtlsRecord, HandshakeHeader, KeyBlock, AES_BLOCK_SIZE,
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    DTLS_1_2, DTLS_HANDSHAKE_HEADER_SIZE, FINISHED_VERIFY_DATA_SIZE, HT_CERTIFICATE,
    HT_CLIENT_HELLO, HT_CLIENT_KEY_EXCHANGE, HT_FINISHED, HT_HELLO_VERIFY_REQUEST,
    HT_SERVER_HELLO, HT_SERVER_HELLO_DONE, MASTER_SECRET_SIZE, PRE_MASTER_SECRET_SIZE,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
};
use justrdp_rdpeudp::dtls_handshake::DtlsRandom;
use justrdp_rdpeudp::dtls_session::DtlsSession;

// ─────────────────────────────────────────────────────────────────────
// Test RSA key — same precomputed 512-bit pair as
// `justrdp_core::rsa::tests::test_512bit_key`. Generated with seed=42,
// NOT secure; reproduced inline so the integration test doesn't depend
// on cfg(test) symbols from another crate.
// ─────────────────────────────────────────────────────────────────────

const RSA_512_N: [u8; 64] = [
    0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47, 0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25, 0xA5,
    0x8B, 0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76, 0x30, 0xBB, 0x58, 0xBD, 0xC3, 0x4D,
    0xB1, 0xF0, 0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36, 0x79, 0x0D, 0xA2, 0x84, 0xB8,
    0xE2, 0xE5, 0xB3, 0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C, 0xD7, 0xD6, 0x9A, 0x40,
    0x67, 0x6A, 0xF1, 0xA7,
];
const RSA_512_D: [u8; 64] = [
    0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC, 0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA, 0xEF,
    0xE8, 0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E, 0xEF, 0xAA, 0x69, 0x14, 0xF7, 0x21,
    0x0E, 0x08, 0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA, 0x12, 0xB4, 0x76, 0xB8, 0x68,
    0x84, 0x0D, 0x78, 0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63, 0x67, 0x9A, 0x43, 0x36,
    0xDD, 0xAB, 0x3F, 0x69,
];
const RSA_512_E: [u8; 3] = [0x01, 0x00, 0x01]; // 65537

fn build_test_keys() -> RsaPrivateKey {
    RsaPrivateKey {
        n: BigUint::from_be_bytes(&RSA_512_N),
        d: BigUint::from_be_bytes(&RSA_512_D),
        e: BigUint::from_be_bytes(&RSA_512_E),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Minimal DER helpers — just enough to wrap the RSA key in an SPKI and
// the SPKI in a self-signed v3 X.509 certificate so DtlsClientHandshake
// can parse it.
// ─────────────────────────────────────────────────────────────────────

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else if n < 0x10000 {
        vec![0x82, (n >> 8) as u8, n as u8]
    } else {
        panic!("test cert too big")
    }
}

fn der_seq(content: &[u8]) -> Vec<u8> {
    let mut r = vec![0x30];
    r.extend(der_len(content.len()));
    r.extend_from_slice(content);
    r
}

fn der_int(value: &[u8]) -> Vec<u8> {
    // PKCS-style INTEGER: prepend 0x00 if MSB is set so it's positive.
    let mut body = Vec::new();
    if !value.is_empty() && value[0] & 0x80 != 0 {
        body.push(0x00);
    }
    body.extend_from_slice(value);
    let mut r = vec![0x02];
    r.extend(der_len(body.len()));
    r.extend_from_slice(&body);
    r
}

fn der_bitstr(content: &[u8]) -> Vec<u8> {
    let mut body = vec![0x00]; // unused bits
    body.extend_from_slice(content);
    let mut r = vec![0x03];
    r.extend(der_len(body.len()));
    r.extend_from_slice(&body);
    r
}

fn der_ctx0(content: &[u8]) -> Vec<u8> {
    let mut r = vec![0xA0];
    r.extend(der_len(content.len()));
    r.extend_from_slice(content);
    r
}

/// Build SubjectPublicKeyInfo for the test RSA key.
fn build_rsa_spki() -> Vec<u8> {
    // RSAPublicKey SEQUENCE { modulus, publicExponent }
    let mut rsa_pubkey = Vec::new();
    rsa_pubkey.extend_from_slice(&der_int(&RSA_512_N));
    rsa_pubkey.extend_from_slice(&der_int(&RSA_512_E));
    let rsa_pubkey_seq = der_seq(&rsa_pubkey);

    // AlgorithmIdentifier SEQUENCE { OID rsaEncryption, NULL }
    let algo = vec![
        0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];

    // SubjectPublicKeyInfo SEQUENCE { algo, BIT STRING containing rsa_pubkey_seq }
    let mut spki_body = Vec::new();
    spki_body.extend_from_slice(&algo);
    spki_body.extend_from_slice(&der_bitstr(&rsa_pubkey_seq));
    der_seq(&spki_body)
}

/// Build a minimal v3 X.509 cert wrapping the test SPKI.
fn build_test_cert(spki: &[u8]) -> Vec<u8> {
    let dummy_oid = vec![0x06, 0x03, 0x55, 0x04, 0x03];
    let sig_algo = der_seq(&dummy_oid);

    let version = der_ctx0(&der_int(&[0x02])); // v3
    let serial = der_int(&[0x01]);
    let issuer = der_seq(&[]);
    let validity = der_seq(&[]);
    let subject = der_seq(&[]);

    let mut tbs_body = Vec::new();
    tbs_body.extend_from_slice(&version);
    tbs_body.extend_from_slice(&serial);
    tbs_body.extend_from_slice(&sig_algo);
    tbs_body.extend_from_slice(&issuer);
    tbs_body.extend_from_slice(&validity);
    tbs_body.extend_from_slice(&subject);
    tbs_body.extend_from_slice(spki);
    let tbs = der_seq(&tbs_body);

    let outer_sig_algo = der_seq(&dummy_oid);
    let sig_value = der_bitstr(&[0xAA, 0xBB]);

    let mut cert_body = Vec::new();
    cert_body.extend_from_slice(&tbs);
    cert_body.extend_from_slice(&outer_sig_algo);
    cert_body.extend_from_slice(&sig_value);
    der_seq(&cert_body)
}

// ─────────────────────────────────────────────────────────────────────
// PKCS#1 v1.5 Type 2 RSA decryption (RFC 8017 §7.2.2). Server-only —
// undoes what the client's `rsa_pkcs1_v15_encrypt` produces. Returns
// `None` on any padding violation.
// ─────────────────────────────────────────────────────────────────────

fn rsa_pkcs1_v15_decrypt(key: &RsaPrivateKey, ciphertext: &[u8]) -> Option<Vec<u8>> {
    let k = (key.n.bit_len() + 7) / 8;
    if ciphertext.len() != k {
        return None;
    }
    let c = BigUint::from_be_bytes(ciphertext);
    let m = c.mod_exp(&key.d, &key.n);
    let em = m.to_be_bytes_padded(k);

    // EM = 0x00 || 0x02 || PS (≥8 nonzero) || 0x00 || M
    if em.len() != k || em[0] != 0x00 || em[1] != 0x02 {
        return None;
    }
    let mut sep = None;
    for (i, &b) in em.iter().enumerate().skip(2) {
        if b == 0x00 {
            sep = Some(i);
            break;
        }
    }
    let sep = sep?;
    // PS occupies em[2..sep], so PS length = sep - 2. RFC 8017 §7.2.2
    // requires PS length >= 8, i.e. sep >= 10.
    if sep < 10 {
        return None;
    }
    Some(em[sep + 1..].to_vec())
}

// ─────────────────────────────────────────────────────────────────────
// Test RNG — counter-based, deterministic, NOT secure.
// ─────────────────────────────────────────────────────────────────────

struct CounterRng(u8);
impl DtlsRandom for CounterRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Mock DTLS server.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerState {
    WaitInitialClientHello,
    WaitRetriedClientHello,
    WaitClientKeyExchange,
    WaitClientCcs,
    WaitClientFinished,
    Connected,
}

struct MockServer {
    state: ServerState,
    private_key: RsaPrivateKey,
    cert_der: Vec<u8>,
    cookie: Vec<u8>,
    server_random: [u8; 32],
    server_msg_seq: u16,
    server_record_seq_e0: u64, // epoch 0
    server_record_seq_e1: u64, // epoch 1
    transcript_bytes: Vec<u8>,
    client_random: [u8; 32],
    pre_master_secret: [u8; PRE_MASTER_SECRET_SIZE],
    master_secret: [u8; MASTER_SECRET_SIZE],
    keys: Option<KeyBlock>,
    rng: CounterRng,
}

impl MockServer {
    fn new() -> Self {
        let private_key = build_test_keys();
        let spki = build_rsa_spki();
        let cert_der = build_test_cert(&spki);

        // Deterministic server random / cookie for stable test output.
        let mut rng = CounterRng(0x70);
        let mut server_random = [0u8; 32];
        rng.fill(&mut server_random);
        let mut cookie = vec![0u8; 16];
        rng.fill(&mut cookie);

        Self {
            state: ServerState::WaitInitialClientHello,
            private_key,
            cert_der,
            cookie,
            server_random,
            server_msg_seq: 0,
            server_record_seq_e0: 0,
            server_record_seq_e1: 0,
            transcript_bytes: Vec::new(),
            client_random: [0; 32],
            pre_master_secret: [0; PRE_MASTER_SECRET_SIZE],
            master_secret: [0; MASTER_SECRET_SIZE],
            keys: None,
            rng,
        }
    }

    fn make_record_e0(&mut self, content_type: u8, fragment: Vec<u8>) -> DtlsRecord {
        let rec = DtlsRecord {
            content_type,
            version: DTLS_1_2,
            epoch: 0,
            sequence_number: self.server_record_seq_e0,
            fragment,
        };
        self.server_record_seq_e0 += 1;
        rec
    }

    fn add_handshake_to_transcript(&mut self, msg_type: u8, body: &[u8], msg_seq: u16) -> Vec<u8> {
        let hdr = HandshakeHeader::unfragmented(msg_type, body.len() as u32, msg_seq);
        let mut hs_data = Vec::new();
        hdr.encode(&mut hs_data);
        hs_data.extend_from_slice(body);
        self.transcript_bytes.extend_from_slice(&hs_data);
        hs_data
    }

    fn handle(&mut self, record: &DtlsRecord) -> Vec<DtlsRecord> {
        match record.content_type {
            CONTENT_TYPE_HANDSHAKE => self.handle_handshake_record(record),
            CONTENT_TYPE_CHANGE_CIPHER_SPEC => self.handle_ccs(record),
            _ => panic!("server: unexpected content_type {}", record.content_type),
        }
    }

    fn handle_handshake_record(&mut self, record: &DtlsRecord) -> Vec<DtlsRecord> {
        // Pull the handshake header out of the record's fragment.
        let plaintext = if record.epoch == 0 {
            record.fragment.clone()
        } else {
            // Encrypted client Finished — decrypt with client_write keys.
            let keys = self.keys.as_ref().expect("keys before encrypted handshake");
            decrypt_record(
                &keys.client_write_mac_key,
                &keys.client_write_key,
                CONTENT_TYPE_HANDSHAKE,
                &record.version,
                record.epoch,
                record.sequence_number,
                &record.fragment,
            )
            .expect("server: client Finished decrypt")
        };
        let hdr = HandshakeHeader::decode(&plaintext).expect("hs header");
        let body_start = DTLS_HANDSHAKE_HEADER_SIZE;
        let body_end = body_start + hdr.fragment_length as usize;
        let body = &plaintext[body_start..body_end];

        match hdr.msg_type {
            HT_CLIENT_HELLO => self.handle_client_hello(body, &plaintext[..body_end]),
            HT_CLIENT_KEY_EXCHANGE => self.handle_cke(body, &plaintext[..body_end]),
            HT_FINISHED => self.handle_client_finished(body, &plaintext[..body_end]),
            other => panic!("server: unexpected handshake type {other:#04x}"),
        }
    }

    fn handle_client_hello(&mut self, body: &[u8], full_msg: &[u8]) -> Vec<DtlsRecord> {
        // Parse: client_version(2) + random(32) + session_id_len(1) + sid +
        // cookie_len(1) + cookie + cipher_suites_len(2) + cs + comp_len(1) + comp + extensions
        let client_random: [u8; 32] = body[2..34].try_into().expect("client_random");
        self.client_random = client_random;
        let sid_len = body[34] as usize;
        let cookie_len_pos = 35 + sid_len;
        let cookie_len = body[cookie_len_pos] as usize;
        let cookie_bytes = &body[cookie_len_pos + 1..cookie_len_pos + 1 + cookie_len];

        match self.state {
            ServerState::WaitInitialClientHello => {
                if !cookie_bytes.is_empty() {
                    panic!("server: initial CH carried unexpected cookie");
                }
                // Send HelloVerifyRequest. Per RFC 6347 §4.2.1, the
                // initial ClientHello and HVR are NOT in the transcript;
                // the transcript starts with the retried ClientHello.
                let mut hvr_body = Vec::new();
                hvr_body.extend_from_slice(&DTLS_1_2);
                hvr_body.push(self.cookie.len() as u8);
                hvr_body.extend_from_slice(&self.cookie);
                let msg_seq = self.server_msg_seq;
                self.server_msg_seq += 1;
                let hdr = HandshakeHeader::unfragmented(
                    HT_HELLO_VERIFY_REQUEST,
                    hvr_body.len() as u32,
                    msg_seq,
                );
                let mut hs_data = Vec::new();
                hdr.encode(&mut hs_data);
                hs_data.extend_from_slice(&hvr_body);
                let rec = self.make_record_e0(CONTENT_TYPE_HANDSHAKE, hs_data);
                self.state = ServerState::WaitRetriedClientHello;
                vec![rec]
            }
            ServerState::WaitRetriedClientHello => {
                if cookie_bytes != self.cookie {
                    panic!(
                        "server: retried CH cookie mismatch (got {:?}, want {:?})",
                        cookie_bytes, self.cookie
                    );
                }
                // Retried ClientHello IS in the transcript.
                self.transcript_bytes.extend_from_slice(full_msg);

                // Build server flight: ServerHello, Certificate, ServerHelloDone.
                let mut out = Vec::new();
                out.push(self.build_and_send_server_hello());
                out.push(self.build_and_send_certificate());
                out.push(self.build_and_send_server_hello_done());
                self.state = ServerState::WaitClientKeyExchange;
                out
            }
            other => panic!("server: ClientHello in state {other:?}"),
        }
    }

    fn build_and_send_server_hello(&mut self) -> DtlsRecord {
        let mut body = Vec::new();
        body.extend_from_slice(&DTLS_1_2);
        body.extend_from_slice(&self.server_random);
        body.push(0); // session_id length
        body.extend_from_slice(&TLS_RSA_WITH_AES_128_CBC_SHA256);
        body.push(0); // compression: null
        // No extensions.

        let msg_seq = self.server_msg_seq;
        self.server_msg_seq += 1;
        let hs_data = self.add_handshake_to_transcript(HT_SERVER_HELLO, &body, msg_seq);
        self.make_record_e0(CONTENT_TYPE_HANDSHAKE, hs_data)
    }

    fn build_and_send_certificate(&mut self) -> DtlsRecord {
        // Body: cert_list_len(3) + [ cert_len(3) + cert_der ]+
        let cert_len = self.cert_der.len();
        let mut body = Vec::new();
        let total_len = 3 + cert_len;
        body.extend_from_slice(&[(total_len >> 16) as u8, (total_len >> 8) as u8, total_len as u8]);
        body.extend_from_slice(&[(cert_len >> 16) as u8, (cert_len >> 8) as u8, cert_len as u8]);
        body.extend_from_slice(&self.cert_der);

        let msg_seq = self.server_msg_seq;
        self.server_msg_seq += 1;
        let hs_data = self.add_handshake_to_transcript(HT_CERTIFICATE, &body, msg_seq);
        self.make_record_e0(CONTENT_TYPE_HANDSHAKE, hs_data)
    }

    fn build_and_send_server_hello_done(&mut self) -> DtlsRecord {
        let body: Vec<u8> = Vec::new(); // ServerHelloDone has empty body
        let msg_seq = self.server_msg_seq;
        self.server_msg_seq += 1;
        let hs_data = self.add_handshake_to_transcript(HT_SERVER_HELLO_DONE, &body, msg_seq);
        self.make_record_e0(CONTENT_TYPE_HANDSHAKE, hs_data)
    }

    fn handle_cke(&mut self, body: &[u8], full_msg: &[u8]) -> Vec<DtlsRecord> {
        if self.state != ServerState::WaitClientKeyExchange {
            panic!("server: CKE in state {:?}", self.state);
        }
        // body: encrypted_pms_len(2) + encrypted_pms
        let pms_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        let ciphertext = &body[2..2 + pms_len];
        let pms = rsa_pkcs1_v15_decrypt(&self.private_key, ciphertext)
            .expect("server: PMS decrypt");
        assert_eq!(pms.len(), PRE_MASTER_SECRET_SIZE, "PMS length mismatch");
        self.pre_master_secret.copy_from_slice(&pms);

        // Add CKE to transcript before deriving keys.
        self.transcript_bytes.extend_from_slice(full_msg);

        // Derive master secret + key block — must mirror the client.
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

        self.state = ServerState::WaitClientCcs;
        Vec::new()
    }

    fn handle_ccs(&mut self, _record: &DtlsRecord) -> Vec<DtlsRecord> {
        if self.state != ServerState::WaitClientCcs {
            panic!("server: CCS in state {:?}", self.state);
        }
        self.state = ServerState::WaitClientFinished;
        Vec::new()
    }

    fn handle_client_finished(&mut self, body: &[u8], full_msg: &[u8]) -> Vec<DtlsRecord> {
        if self.state != ServerState::WaitClientFinished {
            panic!("server: Finished in state {:?}", self.state);
        }
        // Verify client's verify_data BEFORE adding to transcript.
        let transcript_hash = sha256(&self.transcript_bytes);
        let expected = compute_verify_data(
            &self.master_secret,
            b"client finished",
            &transcript_hash,
        );
        let received = &body[..FINISHED_VERIFY_DATA_SIZE];
        assert!(
            ct_eq(received, &expected[..]),
            "server: client Finished verify_data mismatch",
        );
        // Append client Finished to transcript so server's verify_data
        // covers it (RFC 5246 §7.4.9).
        self.transcript_bytes.extend_from_slice(full_msg);

        // Send server flight: CCS (epoch 0) + encrypted Finished (epoch 1).
        let ccs = self.make_record_e0(CONTENT_TYPE_CHANGE_CIPHER_SPEC, vec![0x01]);

        let server_transcript_hash = sha256(&self.transcript_bytes);
        let server_verify = compute_verify_data(
            &self.master_secret,
            b"server finished",
            &server_transcript_hash,
        );
        let mut fin_data = Vec::new();
        let fin_msg_seq = self.server_msg_seq;
        self.server_msg_seq += 1;
        let fin_hdr = HandshakeHeader::unfragmented(
            HT_FINISHED,
            FINISHED_VERIFY_DATA_SIZE as u32,
            fin_msg_seq,
        );
        fin_hdr.encode(&mut fin_data);
        fin_data.extend_from_slice(&server_verify);

        let keys = self.keys.as_ref().unwrap();
        let mut iv = [0u8; AES_BLOCK_SIZE];
        self.rng.fill(&mut iv);
        let encrypted = encrypt_record(
            &keys.server_write_mac_key,
            &keys.server_write_key,
            &iv,
            CONTENT_TYPE_HANDSHAKE,
            &DTLS_1_2,
            1,
            self.server_record_seq_e1,
            &fin_data,
        );
        let fin_rec = DtlsRecord {
            content_type: CONTENT_TYPE_HANDSHAKE,
            version: DTLS_1_2,
            epoch: 1,
            sequence_number: self.server_record_seq_e1,
            fragment: encrypted,
        };
        self.server_record_seq_e1 += 1;

        self.state = ServerState::Connected;
        vec![ccs, fin_rec]
    }

    /// Encrypt application data (server → client) using the server
    /// write keys; produces an APPLICATION_DATA record with epoch 1.
    fn encrypt_app_data(&mut self, plaintext: &[u8]) -> DtlsRecord {
        assert_eq!(self.state, ServerState::Connected);
        let keys = self.keys.as_ref().unwrap();
        let mut iv = [0u8; AES_BLOCK_SIZE];
        self.rng.fill(&mut iv);
        let fragment = encrypt_record(
            &keys.server_write_mac_key,
            &keys.server_write_key,
            &iv,
            CONTENT_TYPE_APPLICATION_DATA,
            &DTLS_1_2,
            1,
            self.server_record_seq_e1,
            plaintext,
        );
        let rec = DtlsRecord {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            version: DTLS_1_2,
            epoch: 1,
            sequence_number: self.server_record_seq_e1,
            fragment,
        };
        self.server_record_seq_e1 += 1;
        rec
    }

    /// Decrypt an APPLICATION_DATA record sent by the client (epoch 1).
    fn decrypt_app_data(&mut self, record: &DtlsRecord) -> Vec<u8> {
        assert_eq!(self.state, ServerState::Connected);
        assert_eq!(record.epoch, 1);
        let keys = self.keys.as_ref().unwrap();
        decrypt_record(
            &keys.client_write_mac_key,
            &keys.client_write_key,
            CONTENT_TYPE_APPLICATION_DATA,
            &record.version,
            record.epoch,
            record.sequence_number,
            &record.fragment,
        )
        .expect("server: app data decrypt")
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[test]
fn full_dtls_handshake_with_hello_verify_request() {
    let mut rng = CounterRng(0xA0);
    let mut client = DtlsSession::new(&mut rng).unwrap();
    let mut server = MockServer::new();

    // Drive the exchange. Each round: client emits records → server
    // responds → client consumes responses. Loop until Connected.
    let mut rounds = 0;
    while !client.is_connected() {
        let outgoing = client.drain_outgoing();
        assert!(
            !outgoing.is_empty() || rounds == 0,
            "no progress: client emitted nothing in round {rounds}",
        );
        let mut server_responses = Vec::new();
        for rec in &outgoing {
            server_responses.extend(server.handle(rec));
        }
        for rec in &server_responses {
            client.feed_record(&mut rng, rec).unwrap();
        }
        rounds += 1;
        assert!(rounds < 8, "DTLS handshake did not converge in 8 rounds");
    }

    assert!(client.is_connected());
    // SPKI must have been captured from the server's Certificate.
    let expected_spki = build_rsa_spki();
    assert_eq!(client.server_spki(), Some(expected_spki.as_slice()));
    assert!(client.verify_server_spki(&expected_spki));
    assert!(!client.verify_server_spki(b"wrong spki"));

    // Bidirectional encrypted application data.
    let client_msg = b"client says hello";
    let app_record = client.encrypt_app_data(&mut rng, client_msg).unwrap();
    let server_received = server.decrypt_app_data(&app_record);
    assert_eq!(server_received, client_msg);

    let server_msg = b"server replies pong";
    let server_record = server.encrypt_app_data(server_msg);
    // Regression guard against the "Item 6" false positive raised in an
    // earlier review pass: server `Finished` consumed epoch-1 seqnum 0,
    // so the server's first app data MUST start at seqnum 1, and the
    // client's `last_recv_seq=Some(0)` MUST still accept it. If a future
    // refactor split the seqnum counter or reset the server's
    // `server_record_seq_e1` after Finished, this assertion fires before
    // the decrypt would be silently rejected as replay.
    assert_eq!(
        server_record.sequence_number, 1,
        "server first app-data must be epoch-1 seq=1 (Finished was seq=0)",
    );
    let client_received = client.decrypt_app_data(&server_record).unwrap();
    assert_eq!(client_received, server_msg);

    // A second round-trip exercises sequence-number advancement.
    let client_msg2 = b"second message";
    let rec2 = client.encrypt_app_data(&mut rng, client_msg2).unwrap();
    assert_eq!(rec2.sequence_number, 1);
    let server_received2 = server.decrypt_app_data(&rec2);
    assert_eq!(server_received2, client_msg2);
}
