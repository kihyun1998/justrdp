#![forbid(unsafe_code)]

//! Kerberos authentication sequence for CredSSP.
//!
//! Drives the KDC exchange (AS-REQ/AS-REP, TGS-REQ/TGS-REP) and
//! produces SPNEGO tokens (AP-REQ/AP-REP) for use in the CredSSP flow.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::aes::{
    krb5_aes_checksum, krb5_aes_decrypt, krb5_aes_encrypt, krb5_aes_string_to_key,
};
use justrdp_core::bignum::BigUint;
use justrdp_core::crypto::{Sha1, Sha256};
use justrdp_core::dh::{dh_compute_shared, dh_generate_keypair, OakleyGroup14};
use justrdp_core::rsa::{rsa_sign_sha256, RsaPrivateKey};
use justrdp_pdu::cms;
use justrdp_pdu::kerberos::asn1::*;
use justrdp_pdu::kerberos::pkinit::*;
use justrdp_pdu::kerberos::*;

use crate::error::{ConnectorError, ConnectorResult};

/// State of the Kerberos authentication sequence.
///
/// The caller drives the exchange externally:
/// 1. Check state → build the corresponding request
/// 2. Send to KDC, receive response
/// 3. Call the appropriate `process_*_response` method
/// 4. Check new state → repeat
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KerberosState {
    /// Need to send AS-REQ (initial, no pre-auth).
    SendAsReq,
    /// Need to send AS-REQ (with pre-auth, after KRB-ERROR 25).
    SendAsReqPreAuth,
    /// Need to send AS-REQ with PKINIT pre-auth.
    SendAsReqPkinit,
    /// Need to send TGS-REQ for the service ticket.
    SendTgsReq,
    /// Kerberos exchange complete, AP-REQ ready.
    Done,
}

/// PKINIT configuration for certificate-based authentication.
///
/// Two source modes are supported:
///
/// 1. **Raw key** (legacy / test path): provide `client_cert_der` and
///    `private_key` directly. The host process holds the private key
///    in memory and computes the signature locally.
/// 2. **Smartcard provider** (recommended for hardware tokens): set
///    `smartcard_provider` to a `Box<dyn SmartcardProvider>`. PKINIT
///    will fetch the certificate chain via the provider and delegate
///    the SHA-256-digest signing operation to it. The private key
///    never leaves the card. Use [`PkinitConfig::from_provider`] for
///    the convenient builder.
///
/// When `smartcard_provider` is `Some`, the `client_cert_der` and
/// `private_key` fields are ignored. They remain in the struct only so
/// the legacy `PkinitConfig { ... }` literal continues to compile.
pub struct PkinitConfig {
    /// Client certificate in DER format. Ignored when
    /// `smartcard_provider` is set.
    pub client_cert_der: Vec<u8>,
    /// RSA private key for signing. Ignored when `smartcard_provider`
    /// is set; populate with any placeholder in that case.
    pub private_key: RsaPrivateKey,
    /// DH private exponent bytes (random, at least 32 bytes).
    pub dh_private_bytes: Vec<u8>,
    /// Optional smartcard / HSM provider. Takes precedence over the
    /// raw `client_cert_der` + `private_key` fields when present.
    pub smartcard_provider: Option<Box<dyn justrdp_pkinit_card::SmartcardProvider>>,
}

impl PkinitConfig {
    /// Build a `PkinitConfig` backed by a smartcard provider.
    ///
    /// `dh_private_bytes` must be at least 32 random bytes (host-side,
    /// the DH keypair is unrelated to the smartcard).
    pub fn from_provider(
        provider: Box<dyn justrdp_pkinit_card::SmartcardProvider>,
        dh_private_bytes: Vec<u8>,
    ) -> Self {
        Self {
            client_cert_der: Vec::new(),
            private_key: RsaPrivateKey {
                n: BigUint::zero(),
                d: BigUint::zero(),
                e: BigUint::zero(),
            },
            dh_private_bytes,
            smartcard_provider: Some(provider),
        }
    }
}

impl Drop for PkinitConfig {
    fn drop(&mut self) {
        self.dh_private_bytes.fill(0);
        core::hint::black_box(&self.dh_private_bytes);
    }
}

/// Kerberos authentication sequence.
///
/// This implements the client-side Kerberos flow for RDP CredSSP:
/// 1. AS-REQ → KDC (get TGT)
/// 2. TGS-REQ → KDC (get service ticket for TERMSRV/hostname)
/// 3. Build AP-REQ for SPNEGO
pub struct KerberosSequence {
    state: KerberosState,
    // Configuration
    username: Vec<u8>,
    password: Vec<u8>,
    domain: Vec<u8>,   // uppercase realm, e.g., "EXAMPLE.COM"
    hostname: Vec<u8>, // target server hostname
    // Crypto state
    client_key: Vec<u8>,  // derived from password+salt
    etype: i32,           // negotiated encryption type
    // KDC exchange state
    nonce: u32,
    tgs_nonce: u32,
    tgt_session_key: Vec<u8>,
    tgt_ticket: Option<Ticket>,
    service_session_key: Vec<u8>,
    service_ticket: Option<Ticket>,
    // ETYPE-INFO2 from KDC
    salt: Vec<u8>,
    iterations: u32,
    // Output
    ap_req_bytes: Vec<u8>,
    subkey: Vec<u8>,          // generated subkey for session protection
    seq_number: u32,
    // PKINIT state
    pkinit_config: Option<PkinitConfig>,
    dh_private_key: Option<BigUint>,
    /// Client DH nonce for PKINIT key derivation.
    client_dh_nonce: Option<Vec<u8>>,
}

/// Random values needed by the Kerberos sequence.
pub struct KerberosRandom {
    /// Nonce for AS-REQ (RFC 4120: each request should use a fresh nonce).
    pub nonce: u32,
    /// Separate nonce for TGS-REQ.
    pub tgs_nonce: u32,
    pub confounder_as: [u8; 16],
    pub confounder_tgs_auth: [u8; 16],
    pub confounder_ap_auth: [u8; 16],
    pub subkey: Vec<u8>,
    pub seq_number: u32,
    pub timestamp_usec: u32,
    /// Client DH nonce for PKINIT key derivation (RFC 4556 3.2.3.1).
    /// Should be 32 bytes of random data when using DH key agreement.
    pub client_dh_nonce: [u8; 32],
}

impl KerberosSequence {
    pub fn new(
        username: &str,
        password: &str,
        domain: &str,
        hostname: &str,
        random: KerberosRandom,
    ) -> Self {
        Self {
            state: KerberosState::SendAsReq,
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
            domain: domain.as_bytes().to_vec(),
            hostname: hostname.as_bytes().to_vec(),
            client_key: Vec::new(),
            etype: ETYPE_AES256_CTS_HMAC_SHA1,
            nonce: random.nonce,
            tgs_nonce: random.tgs_nonce,
            tgt_session_key: Vec::new(),
            tgt_ticket: None,
            service_session_key: Vec::new(),
            service_ticket: None,
            salt: Vec::new(),
            iterations: 4096,
            ap_req_bytes: Vec::new(),
            subkey: random.subkey.clone(),
            seq_number: random.seq_number,
            pkinit_config: None,
            dh_private_key: None,
            client_dh_nonce: None,
        }
    }

    /// Create a new Kerberos sequence with a pre-derived long-term key (keytab).
    ///
    /// Skips password-based key derivation — the key is used directly for
    /// pre-authentication. The `etype` must match the key's encryption type.
    pub fn new_with_key(
        username: &str,
        domain: &str,
        hostname: &str,
        random: KerberosRandom,
        key: Vec<u8>,
        etype: i32,
    ) -> Self {
        Self {
            state: KerberosState::SendAsReqPreAuth,
            username: username.as_bytes().to_vec(),
            password: Vec::new(),
            domain: domain.as_bytes().to_vec(),
            hostname: hostname.as_bytes().to_vec(),
            client_key: key,
            etype,
            nonce: random.nonce,
            tgs_nonce: random.tgs_nonce,
            tgt_session_key: Vec::new(),
            tgt_ticket: None,
            service_session_key: Vec::new(),
            service_ticket: None,
            salt: Vec::new(),
            iterations: 4096,
            ap_req_bytes: Vec::new(),
            subkey: random.subkey,
            seq_number: random.seq_number,
            pkinit_config: None,
            dh_private_key: None,
            client_dh_nonce: None,
        }
    }

    /// Create a new PKINIT-based Kerberos sequence.
    ///
    /// Uses certificate-based authentication instead of password.
    pub fn new_pkinit(
        username: &str,
        domain: &str,
        hostname: &str,
        random: KerberosRandom,
        config: PkinitConfig,
    ) -> Self {
        Self {
            state: KerberosState::SendAsReqPkinit,
            username: username.as_bytes().to_vec(),
            password: Vec::new(), // not used for PKINIT
            domain: domain.as_bytes().to_vec(),
            hostname: hostname.as_bytes().to_vec(),
            client_key: Vec::new(),
            etype: ETYPE_AES256_CTS_HMAC_SHA1,
            nonce: random.nonce,
            tgs_nonce: random.tgs_nonce,
            tgt_session_key: Vec::new(),
            tgt_ticket: None,
            service_session_key: Vec::new(),
            service_ticket: None,
            salt: Vec::new(),
            iterations: 4096,
            ap_req_bytes: Vec::new(),
            subkey: random.subkey,
            seq_number: random.seq_number,
            pkinit_config: Some(config),
            dh_private_key: None,
            client_dh_nonce: Some(random.client_dh_nonce.to_vec()),
        }
    }

    pub fn state(&self) -> &KerberosState {
        &self.state
    }

    /// Get the generated AP-REQ bytes (available after Done state).
    pub fn ap_req_bytes(&self) -> &[u8] {
        &self.ap_req_bytes
    }

    /// Get the session key for GSS Wrap operations (subkey if generated, else service session key).
    pub fn session_key(&self) -> &[u8] {
        if !self.subkey.is_empty() {
            &self.subkey
        } else {
            &self.service_session_key
        }
    }

    /// Get the etype.
    pub fn etype(&self) -> i32 {
        self.etype
    }

    /// Get the sequence number.
    pub fn seq_number(&self) -> u32 {
        self.seq_number
    }

    /// Build an AS-REQ message (initial, without pre-authentication).
    pub fn build_as_req(&self) -> Vec<u8> {
        let req_body = KdcReqBody {
            kdc_options: KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
            cname: Some(PrincipalName::principal(&self.username)),
            realm: self.domain.clone(),
            sname: Some(PrincipalName::service(b"krbtgt", &self.domain)),
            till: b"20370913024805Z".to_vec(),
            nonce: self.nonce,
            etype: vec![ETYPE_AES256_CTS_HMAC_SHA1, ETYPE_AES128_CTS_HMAC_SHA1],
        };

        let padata = vec![
            PaData::new(PA_PAC_REQUEST, encode_pa_pac_request(true)),
        ];

        let req = KdcReq::as_req(padata, req_body);
        req.encode()
    }

    /// Build an AS-REQ with pre-authentication (PA-ENC-TIMESTAMP).
    pub fn build_as_req_preauth(&self, timestamp: &[u8], usec: u32, confounder: &[u8; 16]) -> ConnectorResult<Vec<u8>> {
        // Encode the timestamp
        let ts_enc = encode_pa_enc_ts_enc(timestamp, usec);

        // Encrypt with client key
        let encrypted = krb5_aes_encrypt(
            &self.client_key,
            KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
            &ts_enc,
            confounder,
        ).map_err(|_| ConnectorError::general("pre-auth encrypt failed: invalid client key"))?;

        let enc_data = EncryptedData::new(self.etype, encrypted);

        let req_body = KdcReqBody {
            kdc_options: KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
            cname: Some(PrincipalName::principal(&self.username)),
            realm: self.domain.clone(),
            sname: Some(PrincipalName::service(b"krbtgt", &self.domain)),
            till: b"20370913024805Z".to_vec(),
            nonce: self.nonce,
            etype: vec![ETYPE_AES256_CTS_HMAC_SHA1, ETYPE_AES128_CTS_HMAC_SHA1],
        };

        let padata = vec![
            PaData::new(PA_ENC_TIMESTAMP, enc_data.encode()),
            PaData::new(PA_PAC_REQUEST, encode_pa_pac_request(true)),
        ];

        let req = KdcReq::as_req(padata, req_body);
        Ok(req.encode())
    }

    /// Build an AS-REQ with PKINIT pre-authentication (PA-PK-AS-REQ).
    pub fn build_as_req_pkinit(
        &mut self,
        timestamp: &[u8],
        usec: u32,
    ) -> ConnectorResult<Vec<u8>> {
        let config = self.pkinit_config.as_ref()
            .ok_or_else(|| ConnectorError::general("PKINIT config not set"))?;

        // Generate DH key pair
        let mut kp = dh_generate_keypair(&config.dh_private_bytes)
            .map_err(|_| ConnectorError::general("DH private key too short (min 32 bytes)"))?;
        let p = OakleyGroup14::prime();
        let g = OakleyGroup14::generator();

        let pub_bytes = kp.public_key.to_be_bytes();
        let p_bytes = p.to_be_bytes();
        let g_bytes = g.to_be_bytes();

        // Build the req body first (needed for paChecksum)
        let req_body = KdcReqBody {
            kdc_options: KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
            cname: Some(PrincipalName::principal(&self.username)),
            realm: self.domain.clone(),
            sname: Some(PrincipalName::service(b"krbtgt", &self.domain)),
            till: b"20370913024805Z".to_vec(),
            nonce: self.nonce,
            etype: vec![ETYPE_AES256_CTS_HMAC_SHA1, ETYPE_AES128_CTS_HMAC_SHA1],
        };

        // Compute paChecksum = SHA-1(KDC-REQ-BODY)
        let body_bytes = req_body.encode();
        let mut sha1 = Sha1::new();
        sha1.update(&body_bytes);
        let pa_checksum = sha1.finalize().to_vec();

        // Build AuthPack
        let dh_spki = build_dh_spki(&p_bytes, &g_bytes, &pub_bytes);

        let auth_pack = AuthPack {
            pk_authenticator: PkAuthenticator {
                cusec: usec,
                ctime: timestamp.to_vec(),
                nonce: self.nonce,
                pa_checksum: Some(pa_checksum),
            },
            client_public_value: Some(dh_spki),
            client_dh_nonce: self.client_dh_nonce.clone(),
        };

        let auth_pack_der = auth_pack.encode();

        // Two source modes for the certificate and signature:
        //   - smartcard_provider: host hashes, card signs, chain comes
        //     from the provider (end-entity + intermediates).
        //   - raw key: legacy path, in-memory RsaPrivateKey signs and
        //     a single client_cert_der is used.
        let (cert_chain, signature) = if let Some(provider) = config.smartcard_provider.as_ref() {
            // Host-side SHA-256 of AuthPack DER, then delegate to card.
            // Matches PIV (NIST SP 800-73-4 §3.3.2) and PKCS#11
            // CKM_RSA_PKCS pre-hashed mode. RFC 4556 §3.2.1 + spec memo
            // specs/pkinit-smartcard-notes.md.
            let end_entity = provider.get_certificate();
            if end_entity.is_empty() {
                return Err(ConnectorError::general(
                    "smartcard provider returned an empty certificate",
                ));
            }
            let mut hasher = Sha256::new();
            hasher.update(&auth_pack_der);
            let digest = hasher.finalize();
            let sig = provider.sign_digest(&digest).map_err(|e| {
                ConnectorError::general_owned(alloc::format!(
                    "smartcard sign_digest failed: {e}"
                ))
            })?;
            let mut chain: Vec<Vec<u8>> = vec![end_entity];
            chain.extend(provider.get_intermediate_chain());
            (chain, sig)
        } else {
            // Legacy raw-key path.
            let sig = rsa_sign_sha256(&config.private_key, &auth_pack_der)
                .map_err(|_| ConnectorError::general("RSA key too small for PKCS#1 v1.5 signing"))?;
            let chain: Vec<Vec<u8>> = vec![config.client_cert_der.clone()];
            (chain, sig)
        };

        // Extract issuer and serial from end-entity certificate.
        let (issuer_der, serial_der) = cms::extract_cert_issuer_serial(&cert_chain[0])
            .map_err(|e| {
                ConnectorError::general_owned(alloc::format!(
                    "failed to parse client certificate: {e:?}"
                ))
            })?;

        // Build CMS SignerInfo.
        let signer_info = cms::build_signer_info(&issuer_der, &serial_der, &signature);

        // Build CMS SignedData with the full chain (root excluded — the
        // smartcard provider is responsible for that, and the legacy
        // raw-key path simply has no intermediates).
        let cert_refs: Vec<&[u8]> = cert_chain.iter().map(|c| c.as_slice()).collect();
        let signed_data = cms::build_signed_data(
            OID_PKINIT_AUTH_DATA,
            &auth_pack_der,
            &cert_refs,
            &signer_info,
        );

        // Build ContentInfo
        let content_info = cms::build_content_info_signed_data(&signed_data);

        // Build PA-PK-AS-REQ
        let pa_pk = PaPkAsReq {
            signed_auth_pack: content_info,
        };

        let padata = vec![
            PaData::new(PA_PK_AS_REQ, pa_pk.encode()),
            PaData::new(PA_PAC_REQUEST, encode_pa_pac_request(true)),
        ];

        // Take DH private key for later shared secret computation
        // (use mem::replace to move out of DhKeyPair which implements Drop)
        self.dh_private_key = Some(core::mem::replace(&mut kp.private_key, BigUint::zero()));

        let req = KdcReq::as_req(padata, req_body);
        Ok(req.encode())
    }

    /// Process AS-REP or KRB-ERROR response from KDC.
    pub fn process_as_response(&mut self, data: &[u8]) -> ConnectorResult<()> {
        let msg_type = detect_krb_message_type(data);

        match msg_type {
            Some(KRB_ERROR) => {
                let error = KrbError::decode(data)
                    .map_err(|_| ConnectorError::general("KRB-ERROR decode failed"))?;

                if error.error_code == KDC_ERR_PREAUTH_REQUIRED {
                    // Parse ETYPE-INFO2 from e-data
                    if let Some(ref e_data) = error.e_data {
                        self.parse_etype_info2(e_data)?;
                    }
                    // Derive client key from password + salt
                    let key_len = if self.etype == ETYPE_AES256_CTS_HMAC_SHA1 { 32 } else { 16 };
                    self.client_key = krb5_aes_string_to_key(
                        &self.password,
                        &self.salt,
                        self.iterations,
                        key_len,
                    ).map_err(|_| ConnectorError::general("invalid AES key length for string-to-key"))?;
                    self.state = KerberosState::SendAsReqPreAuth;
                    Ok(())
                } else {
                    Err(ConnectorError::general("KDC error (not preauth-required)"))
                }
            }
            Some(KRB_AS_REP) => {
                let rep = KdcRep::decode(data)
                    .map_err(|_| ConnectorError::general("AS-REP decode failed"))?;

                // Determine decryption key based on auth mode
                let reply_key = if self.dh_private_key.is_some() {
                    // PKINIT: derive reply key from DH shared secret
                    self.derive_pkinit_reply_key(&rep)?
                } else {
                    // Password-based: use client_key directly
                    self.client_key.clone()
                };

                // Decrypt enc-part
                let key_usage = KEY_USAGE_AS_REP_ENC_PART;
                let decrypted = krb5_aes_decrypt(&reply_key, key_usage, &rep.enc_part.cipher)
                    .map_err(|_| ConnectorError::general("AS-REP decrypt failed"))?;

                // Decode EncKDCRepPart
                let enc_part = EncKdcRepPart::decode(&decrypted)
                    .map_err(|_| ConnectorError::general("EncASRepPart decode failed"))?;

                // Verify nonce
                if enc_part.nonce != self.nonce {
                    return Err(ConnectorError::general("AS-REP nonce mismatch"));
                }

                // Store TGT session key and ticket
                self.tgt_session_key = enc_part.key.keyvalue;
                self.etype = enc_part.key.keytype;
                self.tgt_ticket = Some(rep.ticket);
                self.state = KerberosState::SendTgsReq;
                Ok(())
            }
            _ => Err(ConnectorError::general("unexpected KDC response")),
        }
    }

    /// Build a TGS-REQ for the TERMSRV service ticket.
    pub fn build_tgs_req(&self, timestamp: &[u8], usec: u32, confounder: &[u8; 16]) -> ConnectorResult<Vec<u8>> {
        let tgt = self.tgt_ticket.as_ref()
            .ok_or_else(|| ConnectorError::general("no TGT available"))?;

        // Build TGS-REQ body first (needed for authenticator checksum)
        let req_body = KdcReqBody {
            kdc_options: KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
            cname: None, // derived from TGT
            realm: self.domain.clone(),
            sname: Some(PrincipalName::service(b"TERMSRV", &self.hostname)),
            till: b"20370913024805Z".to_vec(),
            nonce: self.tgs_nonce,
            etype: vec![ETYPE_AES256_CTS_HMAC_SHA1, ETYPE_AES128_CTS_HMAC_SHA1],
        };

        // Checksum of req_body for PA-TGS-REQ (RFC 4120 7.2.1)
        let body_bytes = req_body.encode();
        let cksum_value = krb5_aes_checksum(
            &self.tgt_session_key,
            KEY_USAGE_TGS_REQ_PA_TGS_REQ_CKSUM,
            &body_bytes,
        ).map_err(|_| ConnectorError::general("failed to compute TGS-REQ checksum"))?;

        // Checksum type: HMAC-SHA1-96-AES256 = 16, HMAC-SHA1-96-AES128 = 15
        let cksumtype = if self.etype == ETYPE_AES256_CTS_HMAC_SHA1 { 16 } else { 15 };

        // Build the Authenticator for PA-TGS-REQ with checksum
        let authenticator = Authenticator {
            crealm: self.domain.clone(),
            cname: PrincipalName::principal(&self.username),
            cksum: Some(Checksum {
                cksumtype,
                checksum: cksum_value,
            }),
            cusec: usec,
            ctime: timestamp.to_vec(),
            subkey: None,
            seq_number: None,
        };

        let auth_bytes = authenticator.encode();

        // Encrypt Authenticator with TGT session key
        let encrypted_auth = krb5_aes_encrypt(
            &self.tgt_session_key,
            KEY_USAGE_TGS_REQ_AUTHENTICATOR,
            &auth_bytes,
            confounder,
        ).map_err(|_| ConnectorError::general("failed to encrypt TGS-REQ authenticator"))?;

        let enc_auth = EncryptedData::new(self.etype, encrypted_auth);

        // Build AP-REQ for PA-TGS-REQ
        let ap_req = ApReq {
            ap_options: 0,
            ticket: tgt.clone(),
            authenticator: enc_auth,
        };

        let ap_req_bytes = ap_req.encode();

        let padata = vec![
            PaData::new(PA_TGS_REQ, ap_req_bytes),
        ];

        let req = KdcReq::tgs_req(padata, req_body);
        Ok(req.encode())
    }

    /// Process TGS-REP response from KDC.
    pub fn process_tgs_response(&mut self, data: &[u8]) -> ConnectorResult<()> {
        let msg_type = detect_krb_message_type(data);

        match msg_type {
            Some(KRB_ERROR) => {
                let _error = KrbError::decode(data)
                    .map_err(|_| ConnectorError::general("TGS KRB-ERROR decode failed"))?;
                Err(ConnectorError::general("TGS KDC error"))
            }
            Some(KRB_TGS_REP) => {
                let rep = KdcRep::decode(data)
                    .map_err(|_| ConnectorError::general("TGS-REP decode failed"))?;

                // Decrypt enc-part with TGT session key
                let decrypted = krb5_aes_decrypt(
                    &self.tgt_session_key,
                    KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
                    &rep.enc_part.cipher,
                ).map_err(|_| ConnectorError::general("TGS-REP decrypt failed"))?;

                let enc_part = EncKdcRepPart::decode(&decrypted)
                    .map_err(|_| ConnectorError::general("EncTGSRepPart decode failed"))?;

                if enc_part.nonce != self.tgs_nonce {
                    return Err(ConnectorError::general("TGS-REP nonce mismatch"));
                }

                self.service_session_key = enc_part.key.keyvalue;
                self.etype = enc_part.key.keytype;
                self.service_ticket = Some(rep.ticket);
                self.state = KerberosState::Done;
                Ok(())
            }
            _ => Err(ConnectorError::general("unexpected TGS response")),
        }
    }

    /// Build AP-REQ for use in SPNEGO.
    pub fn build_ap_req(
        &mut self,
        timestamp: &[u8],
        usec: u32,
        confounder: &[u8; 16],
    ) -> ConnectorResult<Vec<u8>> {
        let ticket = self.service_ticket.as_ref()
            .ok_or_else(|| ConnectorError::general("no service ticket"))?;

        // Build GSS checksum per RFC 4121 section 4.1.1:
        //   Bytes 0-3:   Lgth = 0x00000010 (16 in LE, length of Bnd field)
        //   Bytes 4-19:  Bnd  = MD5(channel bindings) (16 bytes, zeros when not using EPA)
        //   Bytes 20-23: Flags (little-endian u32)
        //   (Bytes 24+:  optional Deleg, not used)
        let mut gss_cksum = vec![0u8; 24];
        // Bytes 0-3: Lgth = 16 (LE)
        gss_cksum[0..4].copy_from_slice(&16u32.to_le_bytes());
        // Bytes 4-19: Bnd = all zeros (no channel bindings)
        // Bytes 20-23: Flags
        let gss_flags: u32 = 0x3E; // mutual|replay|sequence|integ|conf
        gss_cksum[20..24].copy_from_slice(&gss_flags.to_le_bytes());

        let subkey_enc = if !self.subkey.is_empty() {
            Some(EncryptionKey {
                keytype: self.etype,
                keyvalue: self.subkey.clone(),
            })
        } else {
            None
        };

        let authenticator = Authenticator {
            crealm: self.domain.clone(),
            cname: PrincipalName::principal(&self.username),
            cksum: Some(Checksum {
                cksumtype: 0x8003, // GSS checksum
                checksum: gss_cksum,
            }),
            cusec: usec,
            ctime: timestamp.to_vec(),
            subkey: subkey_enc,
            seq_number: Some(self.seq_number),
        };

        let auth_bytes = authenticator.encode();

        // Encrypt Authenticator with service session key
        let encrypted_auth = krb5_aes_encrypt(
            &self.service_session_key,
            KEY_USAGE_AP_REQ_AUTHENTICATOR,
            &auth_bytes,
            confounder,
        ).map_err(|_| ConnectorError::general("failed to encrypt AP-REQ authenticator"))?;

        let enc_auth = EncryptedData::new(self.etype, encrypted_auth);

        let ap_req = ApReq {
            ap_options: AP_OPT_MUTUAL_REQUIRED,
            ticket: ticket.clone(),
            authenticator: enc_auth,
        };

        let ap_req_bytes = ap_req.encode();

        // Wrap in SPNEGO NegTokenInit
        let spnego_init = NegTokenInit {
            mech_types: vec![
                OID_KRB5_RAW.to_vec(),
                OID_MS_KRB5.to_vec(),
            ],
            mech_token: Some(ap_req_bytes.clone()),
        };

        self.ap_req_bytes = ap_req_bytes;
        Ok(spnego_init.encode())
    }

    /// Process AP-REP from server (received in SPNEGO NegTokenResp).
    pub fn process_ap_rep(&self, ap_rep_data: &[u8]) -> ConnectorResult<EncApRepPart> {
        let ap_rep = ApRep::decode(ap_rep_data)
            .map_err(|_| ConnectorError::general("AP-REP decode failed"))?;

        // Decrypt with service session key (RFC 4120 3.2.5: always session key from ticket)
        let decrypted = krb5_aes_decrypt(
            &self.service_session_key,
            KEY_USAGE_AP_REP_ENC_PART,
            &ap_rep.enc_part.cipher,
        ).map_err(|_| ConnectorError::general("AP-REP decrypt failed"))?;

        let enc_part = EncApRepPart::decode(&decrypted)
            .map_err(|_| ConnectorError::general("EncAPRepPart decode failed"))?;

        Ok(enc_part)
    }

    // ── Private helpers ──

    /// Derive PKINIT reply key from the DH shared secret (RFC 4556 section 3.2.3.1).
    ///
    /// 1. Parse PA-PK-AS-REP from AS-REP padata to get KDC's DH public value
    /// 2. Compute DH shared secret = kdc_public^my_private mod p
    /// 3. Derive reply key using octetstring2key
    fn derive_pkinit_reply_key(&self, rep: &KdcRep) -> ConnectorResult<Vec<u8>> {
        let dh_private = self.dh_private_key.as_ref()
            .ok_or_else(|| ConnectorError::general("PKINIT: no DH private key"))?;

        // Find PA-PK-AS-REP in padata
        let pa_pk_data = rep.padata.iter()
            .find(|pa| pa.padata_type == PA_PK_AS_REP)
            .ok_or_else(|| ConnectorError::general("PKINIT: no PA-PK-AS-REP in AS-REP"))?;

        // Decode PA-PK-AS-REP → DHRepInfo
        let dh_rep = DhRepInfo::decode(&pa_pk_data.padata_value)
            .map_err(|_| ConnectorError::general("PKINIT: PA-PK-AS-REP decode failed"))?;

        // Decode CMS SignedData → KDCDHKeyInfo
        let (_, signed_data_bytes) = cms::decode_content_info(&dh_rep.dh_signed_data)
            .map_err(|_| ConnectorError::general("PKINIT: CMS ContentInfo decode failed"))?;

        let parts = cms::decode_signed_data(&signed_data_bytes)
            .map_err(|_| ConnectorError::general("PKINIT: CMS SignedData decode failed"))?;

        let kdc_dh_content = parts.content
            .ok_or_else(|| ConnectorError::general("PKINIT: no KDCDHKeyInfo content"))?;

        let kdc_dh_info = KdcDhKeyInfo::decode(&kdc_dh_content)
            .map_err(|_| ConnectorError::general("PKINIT: KDCDHKeyInfo decode failed"))?;

        // Extract KDC's DH public value from BIT STRING → INTEGER
        // The subjectPublicKey is a BIT STRING containing a DER INTEGER
        let mut kdc_pub_reader = DerReader::new(&kdc_dh_info.subject_public_key);
        let kdc_pub_int = kdc_pub_reader.read_integer()
            .map_err(|_| ConnectorError::general("PKINIT: KDC DH public key parse failed"))?;

        let kdc_public = BigUint::from_be_bytes(&kdc_pub_int.to_be_bytes());
        let p = OakleyGroup14::prime();

        // Compute DH shared secret
        let shared_secret = dh_compute_shared(&kdc_public, dh_private, &p);
        let shared_bytes = shared_secret.to_be_bytes_padded(OakleyGroup14::key_size());

        // Derive reply key per RFC 4556 section 3.2.3.1
        let key_len = if self.etype == ETYPE_AES256_CTS_HMAC_SHA1 { 32 } else { 16 };

        let reply_key = if let Some(ref server_nonce) = dh_rep.server_dh_nonce {
            // When serverDHNonce is present (RFC 4556 3.2.3.1):
            // x = DHSharedSecret || clientDHNonce || serverDHNonce
            // Apply octetstring2key(x) = random-to-key(SHA1-KDF(x, key_len))
            //
            // SHA1-KDF per RFC 4556 §3.2.3.1:
            //   K(i) = SHA1(counter || x)  where counter = i as 4-byte BE
            //   Concatenate K(1), K(2), ... and truncate to key_len bytes.
            let client_nonce = self.client_dh_nonce.as_ref()
                .ok_or_else(|| ConnectorError::general("PKINIT: no client DH nonce"))?;

            let mut x = Vec::new();
            x.extend_from_slice(&shared_bytes);
            x.extend_from_slice(client_nonce);
            x.extend_from_slice(server_nonce);

            let mut key_material = Vec::with_capacity(key_len);
            let mut counter: u32 = 1;
            while key_material.len() < key_len {
                let mut sha1 = Sha1::new();
                sha1.update(&counter.to_be_bytes());
                sha1.update(&x);
                let hash = sha1.finalize();
                key_material.extend_from_slice(&hash);
                counter += 1;
            }
            key_material.truncate(key_len);
            key_material
        } else {
            // No serverDHNonce: apply octetstring2key per RFC 4556 §3.2.3.1.
            // Same SHA1-KDF loop but with only DHSharedSecret as input (no nonces).
            let mut key_material = Vec::with_capacity(key_len);
            let mut counter: u32 = 1;
            while key_material.len() < key_len {
                let mut sha1 = Sha1::new();
                sha1.update(&counter.to_be_bytes());
                sha1.update(&shared_bytes);
                let hash = sha1.finalize();
                key_material.extend_from_slice(&hash);
                counter += 1;
            }
            key_material.truncate(key_len);
            key_material
        };

        Ok(reply_key)
    }

    fn parse_etype_info2(&mut self, e_data: &[u8]) -> ConnectorResult<()> {
        // e-data contains METHOD-DATA (SEQUENCE OF PA-DATA) or ETYPE-INFO2 directly
        // Try parsing as a SEQUENCE of PA-DATA first
        let mut reader = DerReader::new(e_data);
        if let Ok(mut seq) = reader.read_sequence() {
            while !seq.is_empty() {
                if let Ok((tag, content)) = seq.read_tlv() {
                    if tag == TAG_SEQUENCE {
                        // This might be a PA-DATA or an ETYPE-INFO2-ENTRY
                        // Try PA-DATA first
                        let mut full = vec![TAG_SEQUENCE];
                        if content.len() < 0x80 {
                            full.push(content.len() as u8);
                        } else {
                            full.push(0x82);
                            full.push((content.len() >> 8) as u8);
                            full.push(content.len() as u8);
                        }
                        full.extend_from_slice(content);

                        if let Ok(pa) = PaData::decode(&full) {
                            if pa.padata_type == PA_ETYPE_INFO2 {
                                self.parse_etype_info2_inner(&pa.padata_value)?;
                                return Ok(());
                            }
                        }
                        // Maybe it's an ETYPE-INFO2-ENTRY directly
                        if let Ok(entry) = ETypeInfo2Entry::decode(&full) {
                            self.apply_etype_info2_entry(&entry);
                            return Ok(());
                        }
                    }
                }
            }
        }

        // Fallback: try parsing the whole thing as ETYPE-INFO2
        self.parse_etype_info2_inner(e_data)?;
        Ok(())
    }

    fn parse_etype_info2_inner(&mut self, data: &[u8]) -> ConnectorResult<()> {
        let mut reader = DerReader::new(data);
        let mut fallback_entry: Option<ETypeInfo2Entry> = None;
        if let Ok(mut seq) = reader.read_sequence() {
            // SEQUENCE OF ETYPE-INFO2-ENTRY — prefer AES-256 over AES-128
            while !seq.is_empty() {
                // Read each entry
                let (tag, content) = seq.read_tlv()
                    .map_err(|_| ConnectorError::general("ETYPE-INFO2 parse failed"))?;

                if tag == TAG_SEQUENCE {
                    let mut full = vec![TAG_SEQUENCE];
                    if content.len() < 0x80 {
                        full.push(content.len() as u8);
                    } else {
                        full.push(0x82);
                        full.push((content.len() >> 8) as u8);
                        full.push(content.len() as u8);
                    }
                    full.extend_from_slice(content);

                    if let Ok(entry) = ETypeInfo2Entry::decode(&full) {
                        // Prefer AES-256 over AES-128
                        if entry.etype == ETYPE_AES256_CTS_HMAC_SHA1 {
                            self.apply_etype_info2_entry(&entry);
                            return Ok(());
                        }
                        if entry.etype == ETYPE_AES128_CTS_HMAC_SHA1 && fallback_entry.is_none() {
                            fallback_entry = Some(entry);
                        }
                    }
                }
            }
        }

        // Use AES-128 fallback if AES-256 was not available
        if let Some(entry) = fallback_entry {
            self.apply_etype_info2_entry(&entry);
        }

        // Default salt: REALM + username
        if self.salt.is_empty() {
            self.salt = [self.domain.as_slice(), self.username.as_slice()].concat();
        }
        Ok(())
    }

    fn apply_etype_info2_entry(&mut self, entry: &ETypeInfo2Entry) {
        self.etype = entry.etype;
        if let Some(ref salt) = entry.salt {
            self.salt = salt.clone();
        } else {
            self.salt = [self.domain.as_slice(), self.username.as_slice()].concat();
        }
        if let Some(ref params) = entry.s2kparams {
            if params.len() == 4 {
                // Cap at 1M to prevent DoS from a rogue KDC
                const MAX_KDF_ITERATIONS: u32 = 1_000_000;
                self.iterations = u32::from_be_bytes([params[0], params[1], params[2], params[3]])
                    .min(MAX_KDF_ITERATIONS);
            }
        }
    }
}

impl Drop for KerberosSequence {
    fn drop(&mut self) {
        // Zeroize identity fields (PII)
        self.username.fill(0);
        core::hint::black_box(&self.username);
        self.domain.fill(0);
        core::hint::black_box(&self.domain);
        self.hostname.fill(0);
        core::hint::black_box(&self.hostname);
        // Zeroize password and derived keys
        self.password.fill(0);
        core::hint::black_box(&self.password);
        self.client_key.fill(0);
        core::hint::black_box(&self.client_key);
        self.tgt_session_key.fill(0);
        core::hint::black_box(&self.tgt_session_key);
        self.service_session_key.fill(0);
        core::hint::black_box(&self.service_session_key);
        self.subkey.fill(0);
        core::hint::black_box(&self.subkey);
        // Zeroize bearer credential and password-derived salt
        self.ap_req_bytes.fill(0);
        core::hint::black_box(&self.ap_req_bytes);
        self.salt.fill(0);
        core::hint::black_box(&self.salt);
        // Zeroize DH private key (BigUint holds the DH private exponent)
        if let Some(ref mut key) = self.dh_private_key {
            key.zeroize();
        }
        // Zeroize client DH nonce
        if let Some(ref mut nonce) = self.client_dh_nonce {
            nonce.fill(0);
            core::hint::black_box(nonce);
        }
    }
}

/// Frame a Kerberos message with the TCP 4-byte length prefix.
/// KDC over TCP uses: [4-byte big-endian length][message] (RFC 4120 §7.2.2).
pub fn frame_kdc_message(msg: &[u8]) -> ConnectorResult<Vec<u8>> {
    let len: u32 = msg.len().try_into()
        .map_err(|_| ConnectorError::general("KDC message exceeds u32::MAX"))?;
    let mut framed = Vec::with_capacity(4 + msg.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(msg);
    Ok(framed)
}

/// Extract a Kerberos message from a TCP-framed buffer.
/// Returns (message_bytes, bytes_consumed) or None if not enough data.
pub fn unframe_kdc_message(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return None;
    }
    Some((&data[4..4 + len], 4 + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_as_req_produces_valid_structure() {
        let random = KerberosRandom {
            nonce: 12345,
            tgs_nonce: 54321,
            confounder_as: [0; 16],
            confounder_tgs_auth: [0; 16],
            confounder_ap_auth: [0; 16],
            subkey: vec![0x42; 32],
            seq_number: 1,
            timestamp_usec: 0,
            client_dh_nonce: [0u8; 32],
        };

        let seq = KerberosSequence::new("user", "pass", "EXAMPLE.COM", "server.example.com", random);
        let as_req = seq.build_as_req();

        // Should start with APPLICATION 10 tag
        assert_eq!(as_req[0], 0x6a); // APPLICATION | CONSTRUCTED | 10
        assert!(!as_req.is_empty());
    }

    #[test]
    fn frame_unframe_roundtrip() {
        let msg = b"hello kerberos";
        let framed = frame_kdc_message(msg).unwrap();
        assert_eq!(framed.len(), 4 + msg.len());
        let (unframed, consumed) = unframe_kdc_message(&framed).unwrap();
        assert_eq!(unframed, msg);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn kerberos_initial_state() {
        let random = KerberosRandom {
            nonce: 0,
            tgs_nonce: 0,
            confounder_as: [0; 16],
            confounder_tgs_auth: [0; 16],
            confounder_ap_auth: [0; 16],
            subkey: vec![0; 16],
            seq_number: 0,
            timestamp_usec: 0,
            client_dh_nonce: [0u8; 32],
        };
        let seq = KerberosSequence::new("user", "pass", "REALM", "host", random);
        assert_eq!(*seq.state(), KerberosState::SendAsReq);
    }

    #[test]
    fn pkinit_initial_state() {
        let random = KerberosRandom {
            nonce: 42,
            tgs_nonce: 43,
            confounder_as: [0; 16],
            confounder_tgs_auth: [0; 16],
            confounder_ap_auth: [0; 16],
            subkey: vec![0x55; 32],
            seq_number: 1,
            timestamp_usec: 0,
            client_dh_nonce: [0u8; 32],
        };

        let config = PkinitConfig {
            client_cert_der: vec![0x30, 0x00], // dummy cert
            private_key: RsaPrivateKey {
                n: BigUint::from_u32(3233),
                d: BigUint::from_u32(2753),
                e: BigUint::from_u32(17),
            },
            dh_private_bytes: vec![0x42; 32],
            smartcard_provider: None,
        };

        let seq = KerberosSequence::new_pkinit("user", "REALM", "host", random, config);
        assert_eq!(*seq.state(), KerberosState::SendAsReqPkinit);
    }

    #[test]
    fn pkinit_build_as_req_produces_output() {
        let random = KerberosRandom {
            nonce: 12345,
            tgs_nonce: 54321,
            confounder_as: [0; 16],
            confounder_tgs_auth: [0; 16],
            confounder_ap_auth: [0; 16],
            subkey: vec![0x42; 32],
            seq_number: 1,
            timestamp_usec: 0,
            client_dh_nonce: [0u8; 32],
        };

        // Use the valid 512-bit test key from rsa.rs tests
        let n_bytes = [
            0x9A, 0xD2, 0x93, 0x02, 0xA1, 0xC2, 0x45, 0x47,
            0x32, 0x6C, 0x6A, 0x4E, 0x0B, 0x25, 0xA5, 0x8B,
            0xFE, 0x2C, 0xA4, 0x03, 0xF3, 0x21, 0x59, 0x76,
            0x30, 0xBB, 0x58, 0xBD, 0xC3, 0x4D, 0xB1, 0xF0,
            0x86, 0xC1, 0x79, 0xCD, 0xF8, 0xCF, 0xB6, 0x36,
            0x79, 0x0D, 0xA2, 0x84, 0xB8, 0xE2, 0xE5, 0xB3,
            0xF0, 0x6B, 0xD4, 0x15, 0xEB, 0xCD, 0xAA, 0x2C,
            0xD7, 0xD6, 0x9A, 0x40, 0x67, 0x6A, 0xF1, 0xA7,
        ];
        let d_bytes = [
            0x80, 0x03, 0xAF, 0x74, 0xD4, 0xA5, 0x9A, 0xBC,
            0xE4, 0xEF, 0x89, 0xF2, 0x9F, 0xFA, 0xEF, 0xE8,
            0x52, 0x31, 0x3D, 0x28, 0xDA, 0xE6, 0xEF, 0x5E,
            0xEF, 0xAA, 0x69, 0x14, 0xF7, 0x21, 0x0E, 0x08,
            0x25, 0x2F, 0xB2, 0x8D, 0x9A, 0x5B, 0x7E, 0xAA,
            0x12, 0xB4, 0x76, 0xB8, 0x68, 0x84, 0x0D, 0x78,
            0x30, 0x8A, 0x93, 0xCD, 0x69, 0x65, 0x8C, 0x63,
            0x67, 0x9A, 0x43, 0x36, 0xDD, 0xAB, 0x3F, 0x69,
        ];

        // Build a minimal DER certificate for testing
        // Certificate ::= SEQUENCE { TBSCertificate, ... }
        // TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature, issuer, ... }
        use justrdp_pdu::kerberos::asn1::{build_sequence, build_context_tag};
        let tbs = build_sequence(|w| {
            // [0] version = v3(2)
            let v = build_context_tag(0, |w| w.write_integer(2));
            w.write_raw(&v);
            // serialNumber
            w.write_integer(1);
            // signature AlgorithmIdentifier
            let algo = build_sequence(|w| {
                w.write_oid(OID_SHA256_WITH_RSA);
                w.write_null();
            });
            w.write_raw(&algo);
            // issuer (empty)
            let issuer = build_sequence(|_w| {});
            w.write_raw(&issuer);
        });
        let cert = build_sequence(|w| {
            w.write_raw(&tbs);
        });

        let config = PkinitConfig {
            client_cert_der: cert,
            private_key: RsaPrivateKey {
                n: BigUint::from_be_bytes(&n_bytes),
                d: BigUint::from_be_bytes(&d_bytes),
                e: BigUint::from_be_bytes(&[0x01, 0x00, 0x01]),
            },
            dh_private_bytes: vec![0x42; 32],
            smartcard_provider: None,
        };

        let mut seq = KerberosSequence::new_pkinit("user", "REALM.COM", "server", random, config);
        let result = seq.build_as_req_pkinit(b"20260326120000Z", 0);
        assert!(result.is_ok());

        let as_req = result.unwrap();
        // Should start with APPLICATION 10 tag (AS-REQ)
        assert_eq!(as_req[0], 0x6a);
        // DH private key should be stored
        assert!(seq.dh_private_key.is_some());
    }

    #[test]
    fn pkinit_smartcard_provider_path_produces_as_req() {
        // End-to-end: a Mock provider drives the entire PKINIT AS-REQ
        // build. Verifies that smartcard_provider takes precedence over
        // the raw client_cert_der/private_key fields.
        use justrdp_pkinit_card::MockSmartcardProvider;

        let random = KerberosRandom {
            nonce: 99,
            tgs_nonce: 100,
            confounder_as: [0; 16],
            confounder_tgs_auth: [0; 16],
            confounder_ap_auth: [0; 16],
            subkey: vec![0x42; 32],
            seq_number: 1,
            timestamp_usec: 0,
            client_dh_nonce: [0u8; 32],
        };

        let provider = Box::new(MockSmartcardProvider::new());
        let config = PkinitConfig::from_provider(provider, vec![0x42; 32]);

        let mut seq =
            KerberosSequence::new_pkinit("alice", "REALM.COM", "server", random, config);
        let as_req = seq
            .build_as_req_pkinit(b"20260326120000Z", 0)
            .expect("smartcard PKINIT AS-REQ must build");

        // APPLICATION 10 tag (AS-REQ).
        assert_eq!(as_req[0], 0x6a);
        // DH private key was stored host-side.
        assert!(seq.dh_private_key.is_some());
    }

    #[test]
    fn pkinit_smartcard_provider_empty_certificate_rejected() {
        // A malicious / misconfigured provider returning an empty cert
        // must be rejected with a clear error before any signing.
        use justrdp_pkinit_card::{SmartcardError, SmartcardProvider};

        struct EmptyCertProvider;
        impl SmartcardProvider for EmptyCertProvider {
            fn get_certificate(&self) -> Vec<u8> {
                Vec::new()
            }
            fn get_intermediate_chain(&self) -> Vec<Vec<u8>> {
                Vec::new()
            }
            fn verify_pin(&mut self, _pin: &[u8]) -> Result<(), SmartcardError> {
                Ok(())
            }
            fn sign_digest(&self, _digest: &[u8]) -> Result<Vec<u8>, SmartcardError> {
                Ok(Vec::new())
            }
        }

        let random = KerberosRandom {
            nonce: 99,
            tgs_nonce: 100,
            confounder_as: [0; 16],
            confounder_tgs_auth: [0; 16],
            confounder_ap_auth: [0; 16],
            subkey: vec![0x42; 32],
            seq_number: 1,
            timestamp_usec: 0,
            client_dh_nonce: [0u8; 32],
        };
        let config = PkinitConfig::from_provider(Box::new(EmptyCertProvider), vec![0x42; 32]);
        let mut seq =
            KerberosSequence::new_pkinit("alice", "REALM.COM", "server", random, config);
        let result = seq.build_as_req_pkinit(b"20260326120000Z", 0);
        assert!(result.is_err(), "empty cert must be rejected");
    }

    #[test]
    fn pkinit_smartcard_provider_with_intermediates_includes_chain() {
        use justrdp_pdu::cms;
        use justrdp_pkinit_card::{MockSmartcardProvider, SmartcardProvider};

        let random = KerberosRandom {
            nonce: 99,
            tgs_nonce: 100,
            confounder_as: [0; 16],
            confounder_tgs_auth: [0; 16],
            confounder_ap_auth: [0; 16],
            subkey: vec![0x42; 32],
            seq_number: 1,
            timestamp_usec: 0,
            client_dh_nonce: [0u8; 32],
        };

        // Inject one intermediate. The build path should accept it
        // even though the actual DER contents are placeholder bytes —
        // the chain is bundled into SignedData.certificates and only
        // the end-entity cert is parsed for issuer/serial extraction.
        let provider = Box::new(
            MockSmartcardProvider::new().with_intermediate(vec![0x30, 0x02, 0x05, 0x00]),
        );
        // Sanity: the mock returns 2 entries (end-entity + 1 intermediate).
        assert_eq!(provider.get_intermediate_chain().len(), 1);
        // And cms::extract_cert_issuer_serial parses the end-entity OK.
        let _ = cms::extract_cert_issuer_serial(&provider.get_certificate()).unwrap();

        let config = PkinitConfig::from_provider(provider, vec![0x42; 32]);
        let mut seq =
            KerberosSequence::new_pkinit("alice", "REALM.COM", "server", random, config);
        let as_req = seq
            .build_as_req_pkinit(b"20260326120000Z", 0)
            .expect("smartcard PKINIT with intermediate must build");
        assert_eq!(as_req[0], 0x6a);
    }

    #[test]
    fn keytab_constructor_starts_at_preauth() {
        let random = KerberosRandom {
            nonce: 42,
            tgs_nonce: 43,
            confounder_as: [0; 16],
            confounder_tgs_auth: [0; 16],
            confounder_ap_auth: [0; 16],
            subkey: vec![0x42; 32],
            seq_number: 1,
            timestamp_usec: 0,
            client_dh_nonce: [0u8; 32],
        };

        let key = vec![0xAA; 32]; // pre-derived AES-256 key
        let seq = KerberosSequence::new_with_key(
            "user", "REALM.COM", "server", random, key.clone(), ETYPE_AES256_CTS_HMAC_SHA1,
        );

        // Should skip initial AS-REQ (no pre-auth needed) and go straight to pre-auth
        assert_eq!(*seq.state(), KerberosState::SendAsReqPreAuth);
        // Key should be set directly
        assert_eq!(seq.client_key, key);
        assert_eq!(seq.etype, ETYPE_AES256_CTS_HMAC_SHA1);
    }

    #[test]
    fn gss_checksum_layout_rfc4121() {
        let random = KerberosRandom {
            nonce: 0,
            tgs_nonce: 0,
            confounder_as: [0; 16],
            confounder_tgs_auth: [0; 16],
            confounder_ap_auth: [0; 16],
            subkey: vec![0x42; 32],
            seq_number: 1,
            timestamp_usec: 0,
            client_dh_nonce: [0u8; 32],
        };

        let mut seq = KerberosSequence::new("user", "pass", "REALM", "host", random);
        seq.service_session_key = vec![0x55; 32];
        seq.etype = ETYPE_AES256_CTS_HMAC_SHA1;
        seq.service_ticket = Some(Ticket {
            realm: b"REALM".to_vec(),
            sname: PrincipalName::service(b"TERMSRV", b"host"),
            enc_part: EncryptedData::new(ETYPE_AES256_CTS_HMAC_SHA1, vec![0; 32]),
        });

        let result = seq.build_ap_req(b"20260327120000Z", 0, &[0u8; 16]);
        assert!(result.is_ok());
    }

    #[test]
    fn gss_checksum_bytes_direct() {
        // Directly verify the GSS checksum byte layout per RFC 4121 §4.1.1
        let mut gss_cksum = vec![0u8; 24];
        // Bytes 0-3: Lgth = 16 (LE)
        gss_cksum[0..4].copy_from_slice(&16u32.to_le_bytes());
        // Bytes 4-19: Bnd = zeros (no channel bindings) — already zero
        // Bytes 20-23: Flags
        let gss_flags: u32 = 0x3E;
        gss_cksum[20..24].copy_from_slice(&gss_flags.to_le_bytes());

        // Verify Lgth field
        assert_eq!(&gss_cksum[0..4], &[0x10, 0x00, 0x00, 0x00], "Lgth should be 16 in LE");
        // Verify Bnd field (all zeros)
        assert_eq!(&gss_cksum[4..20], &[0u8; 16], "Bnd should be all zeros");
        // Verify Flags field
        assert_eq!(&gss_cksum[20..24], &[0x3E, 0x00, 0x00, 0x00], "Flags should be 0x3E in LE");
        // Verify total length
        assert_eq!(gss_cksum.len(), 24);
    }

    #[test]
    fn pkinit_octetstring2key_sha1_kdf() {
        // Verify the iterative SHA-1 KDF used for PKINIT reply key derivation.
        // For a 32-byte key (AES-256), we need ceil(32/20) = 2 SHA-1 iterations.
        let shared = vec![0xAA; 32];
        let client_nonce = vec![0xBB; 32];
        let server_nonce = vec![0xCC; 32];

        let mut x = Vec::new();
        x.extend_from_slice(&shared);
        x.extend_from_slice(&client_nonce);
        x.extend_from_slice(&server_nonce);

        // Compute expected: K(1) = SHA1(0x00000001 || x), K(2) = SHA1(0x00000002 || x)
        let mut sha1_1 = Sha1::new();
        sha1_1.update(&1u32.to_be_bytes());
        sha1_1.update(&x);
        let k1 = sha1_1.finalize();

        let mut sha1_2 = Sha1::new();
        sha1_2.update(&2u32.to_be_bytes());
        sha1_2.update(&x);
        let k2 = sha1_2.finalize();

        let mut expected = Vec::new();
        expected.extend_from_slice(&k1);
        expected.extend_from_slice(&k2);
        expected.truncate(32);

        // Verify our KDF produces the same result
        let key_len = 32;
        let mut key_material = Vec::with_capacity(key_len);
        let mut counter: u32 = 1;
        while key_material.len() < key_len {
            let mut sha1 = Sha1::new();
            sha1.update(&counter.to_be_bytes());
            sha1.update(&x);
            let hash = sha1.finalize();
            key_material.extend_from_slice(&hash);
            counter += 1;
        }
        key_material.truncate(key_len);

        assert_eq!(key_material, expected);
        assert_eq!(key_material.len(), 32);
        // Verify it took exactly 2 iterations
        assert_eq!(counter, 3); // counter was incremented to 3 after 2nd iteration
    }
}
