#![forbid(unsafe_code)]

//! Standard RDP Security -- MS-RDPBCGR 5.3/5.4
//!
//! Implements:
//! - RSA key exchange (encrypt client random with server public key)
//! - Session key derivation (client random + server random → RC4 keys)
//! - RC4 encryption/decryption with MAC signing
//! - Key update every 4096 packets
//! - FIPS 140-1 mode (3DES-CBC + SHA-1 HMAC)
//!
//! ## Key Derivation Overview (MS-RDPBCGR 5.3.5)
//!
//! ```text
//! PreMasterSecret = first 48 bytes of (ClientRandom + ServerRandom)
//! MasterSecret = SaltedHash(PreMasterSecret, "A", CR, SR)
//!             || SaltedHash(PreMasterSecret, "BB", CR, SR)
//!             || SaltedHash(PreMasterSecret, "CCC", CR, SR)
//! SessionKeyBlob = SaltedHash(MasterSecret, "X", CR, SR)
//!               || SaltedHash(MasterSecret, "YY", CR, SR)
//!               || SaltedHash(MasterSecret, "ZZZ", CR, SR)
//! ```

use alloc::vec::Vec;

use justrdp_core::bignum::BigUint;
use justrdp_core::crypto::{self, Md5, Rc4, Sha1};
use justrdp_core::rsa::{RsaPublicKey, rsa_public_encrypt_rdp};

use super::server_certificate::ServerRsaPublicKey;

// ── Encryption method flags (MS-RDPBCGR 2.2.1.4.3) ──

/// 40-bit RC4.
pub const ENCRYPTION_METHOD_40BIT: u32 = 0x0000_0001;
/// 128-bit RC4.
pub const ENCRYPTION_METHOD_128BIT: u32 = 0x0000_0002;
/// 56-bit RC4.
pub const ENCRYPTION_METHOD_56BIT: u32 = 0x0000_0008;
/// FIPS 140-1 compliant (3DES + SHA-1).
pub const ENCRYPTION_METHOD_FIPS: u32 = 0x0000_0010;

/// Encryption level values.
pub const ENCRYPTION_LEVEL_NONE: u32 = 0;
pub const ENCRYPTION_LEVEL_LOW: u32 = 1;
pub const ENCRYPTION_LEVEL_CLIENT_COMPATIBLE: u32 = 2;
pub const ENCRYPTION_LEVEL_HIGH: u32 = 3;
pub const ENCRYPTION_LEVEL_FIPS: u32 = 4;

// ── Security header flags ──

/// Data is encrypted.
pub const SEC_ENCRYPT: u16 = 0x0008;
/// Marks a Security Exchange PDU (client random).
pub const SEC_EXCHANGE_PKT: u16 = 0x0001;
/// Client Info PDU marker.
pub const SEC_INFO_PKT: u16 = 0x0040;
/// License PDU marker.
pub const SEC_LICENSE_PKT: u16 = 0x0080;
/// Salted MAC signature.
pub const SEC_SECURE_CHECKSUM: u16 = 0x0800;
/// Reset seqno (key update marker in server-to-client).
pub const SEC_RESET_SEQNO: u16 = 0x0002;

// ── RSA Key Exchange ──

/// Encrypt the 32-byte client random using the server's RSA public key.
///
/// MS-RDPBCGR 5.3.4.1: The client random is encrypted with the server's
/// public key using RSA. The data is in little-endian byte order.
///
/// Returns the encrypted client random (modulus-sized, little-endian).
pub fn encrypt_client_random(
    server_key: &ServerRsaPublicKey,
    client_random: &[u8; 32],
) -> Vec<u8> {
    let rsa_key = RsaPublicKey {
        n: BigUint::from_le_bytes(&server_key.modulus),
        e: BigUint::from_u32(server_key.exponent),
    };

    rsa_public_encrypt_rdp(&rsa_key, client_random)
}

// ── Session Key Derivation (MS-RDPBCGR 5.3.5) ──

/// Compute SaltedHash: MD5(Salt + SHA1(S + Salt + ClientRandom + ServerRandom))
fn salted_hash(
    secret: &[u8],
    salt: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> [u8; 16] {
    let mut sha1 = Sha1::new();
    sha1.update(salt);
    sha1.update(secret);
    sha1.update(client_random);
    sha1.update(server_random);
    let sha1_hash = sha1.finalize();

    let mut md5 = Md5::new();
    md5.update(secret);
    md5.update(&sha1_hash);
    md5.finalize()
}

/// Derive the initial session keys from client and server randoms.
///
/// Returns `(mac_key, initial_encrypt_key, initial_decrypt_key)`.
/// All keys are 16 bytes; they may be truncated based on encryption method.
pub fn derive_session_keys(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    encryption_method: u32,
) -> SessionKeys {
    // PreMasterSecret: first 24 bytes of ClientRandom + first 24 bytes of ServerRandom
    let mut pre_master_secret = [0u8; 48];
    pre_master_secret[..24].copy_from_slice(&client_random[..24]);
    pre_master_secret[24..].copy_from_slice(&server_random[..24]);

    // MasterSecret = SaltedHash("A") || SaltedHash("BB") || SaltedHash("CCC")
    let mut master_secret = [0u8; 48];
    master_secret[..16].copy_from_slice(&salted_hash(
        &pre_master_secret, b"A", client_random, server_random,
    ));
    master_secret[16..32].copy_from_slice(&salted_hash(
        &pre_master_secret, b"BB", client_random, server_random,
    ));
    master_secret[32..].copy_from_slice(&salted_hash(
        &pre_master_secret, b"CCC", client_random, server_random,
    ));

    // SessionKeyBlob = SaltedHash("X") || SaltedHash("YY") || SaltedHash("ZZZ")
    let mut session_key_blob = [0u8; 48];
    session_key_blob[..16].copy_from_slice(&salted_hash(
        &master_secret, b"X", client_random, server_random,
    ));
    session_key_blob[16..32].copy_from_slice(&salted_hash(
        &master_secret, b"YY", client_random, server_random,
    ));
    session_key_blob[32..].copy_from_slice(&salted_hash(
        &master_secret, b"ZZZ", client_random, server_random,
    ));

    // MAC key = first 16 bytes of session key blob
    let mac_key: [u8; 16] = session_key_blob[..16].try_into().unwrap();

    // Encryption/decryption keys depend on method
    match encryption_method {
        ENCRYPTION_METHOD_40BIT => {
            // MACKey5 = first 5 bytes of mac_key + 0xD1269E
            let mac_key_5 = finalize_key_40bit(&mac_key);
            // Encryption key = MD5(session_key_blob[32..48] + client_random + server_random)
            let initial_encrypt = derive_final_key(&session_key_blob[32..48], client_random, server_random);
            let initial_decrypt = derive_final_key(&session_key_blob[16..32], client_random, server_random);

            SessionKeys {
                mac_key: mac_key_5,
                encrypt_key: finalize_key_40bit(&initial_encrypt),
                decrypt_key: finalize_key_40bit(&initial_decrypt),
                encrypt_update_key: finalize_key_40bit(&initial_encrypt),
                decrypt_update_key: finalize_key_40bit(&initial_decrypt),
                key_len: 8, // RC4 with 8-byte effective key (5 known + 3 salt)
                encryption_method,
            }
        }
        ENCRYPTION_METHOD_56BIT => {
            let mac_key_7 = finalize_key_56bit(&mac_key);
            let initial_encrypt = derive_final_key(&session_key_blob[32..48], client_random, server_random);
            let initial_decrypt = derive_final_key(&session_key_blob[16..32], client_random, server_random);

            SessionKeys {
                mac_key: mac_key_7,
                encrypt_key: finalize_key_56bit(&initial_encrypt),
                decrypt_key: finalize_key_56bit(&initial_decrypt),
                encrypt_update_key: finalize_key_56bit(&initial_encrypt),
                decrypt_update_key: finalize_key_56bit(&initial_decrypt),
                key_len: 8,
                encryption_method,
            }
        }
        ENCRYPTION_METHOD_128BIT => {
            let initial_encrypt = derive_final_key(&session_key_blob[32..48], client_random, server_random);
            let initial_decrypt = derive_final_key(&session_key_blob[16..32], client_random, server_random);

            SessionKeys {
                mac_key,
                encrypt_key: initial_encrypt,
                decrypt_key: initial_decrypt,
                encrypt_update_key: initial_encrypt,
                decrypt_update_key: initial_decrypt,
                key_len: 16,
                encryption_method,
            }
        }
        _ => {
            // Unsupported method, return 128-bit as default
            let initial_encrypt = derive_final_key(&session_key_blob[32..48], client_random, server_random);
            let initial_decrypt = derive_final_key(&session_key_blob[16..32], client_random, server_random);

            SessionKeys {
                mac_key,
                encrypt_key: initial_encrypt,
                decrypt_key: initial_decrypt,
                encrypt_update_key: initial_encrypt,
                decrypt_update_key: initial_decrypt,
                key_len: 16,
                encryption_method,
            }
        }
    }
}

/// Final key derivation: MD5(session_key_blob_portion + ClientRandom + ServerRandom)
fn derive_final_key(key_material: &[u8], client_random: &[u8], server_random: &[u8]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(key_material);
    md5.update(client_random);
    md5.update(server_random);
    md5.finalize()
}

/// Reduce to 40-bit effective key (MS-RDPBCGR 5.3.5.1).
///
/// 8-byte RC4 key: First5Bytes(key) || 0xD1 || 0x26 || 0x9E
fn finalize_key_40bit(key: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..5].copy_from_slice(&key[..5]);
    out[5] = 0xD1;
    out[6] = 0x26;
    out[7] = 0x9E;
    // bytes 8..16 are zero (not used, RC4 key_len = 8)
    out
}

/// Reduce to 56-bit effective key (MS-RDPBCGR 5.3.5.1).
///
/// 8-byte RC4 key: First7Bytes(key) || 0xD1
fn finalize_key_56bit(key: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..7].copy_from_slice(&key[..7]);
    out[7] = 0xD1;
    out
}

/// Derived session keys.
#[derive(Clone)]
pub struct SessionKeys {
    pub mac_key: [u8; 16],
    pub encrypt_key: [u8; 16],
    pub decrypt_key: [u8; 16],
    /// Original key for update derivation (encrypt direction).
    pub encrypt_update_key: [u8; 16],
    /// Original key for update derivation (decrypt direction).
    pub decrypt_update_key: [u8; 16],
    /// Effective key length for RC4 (8 for 40/56-bit, 16 for 128-bit).
    pub key_len: usize,
    pub encryption_method: u32,
}

// ── MAC Signature (MS-RDPBCGR 5.3.6.1) ──

/// Compute the Standard RDP MAC signature over data.
///
/// ```text
/// MAC = MD5(MACKey + pad1 + DataLength(LE32) + Data)
/// where pad1 = 0x36 repeated 40 times
/// then  MAC = MD5(MACKey + pad2 + SHA1_result)
/// where pad2 = 0x5C repeated 48 times
/// ```
///
/// Wait — per MS-RDPBCGR 5.3.6.1.1 the actual MAC is:
/// ```text
/// SHAComponent = SHA1(MACKeyN + Pad1 + DataLenLE + Data)
/// MACSignature = MD5(MACKeyN + Pad2 + SHAComponent)[0..8]
/// ```
pub fn compute_mac(mac_key: &[u8; 16], data: &[u8]) -> [u8; 8] {
    let pad1 = [0x36u8; 40];
    let pad2 = [0x5Cu8; 48];

    let data_len = (data.len() as u32).to_le_bytes();

    let mut sha1 = Sha1::new();
    sha1.update(mac_key);
    sha1.update(&pad1);
    sha1.update(&data_len);
    sha1.update(data);
    let sha_result = sha1.finalize();

    let mut md5 = Md5::new();
    md5.update(mac_key);
    md5.update(&pad2);
    md5.update(&sha_result);
    let md5_result = md5.finalize();

    let mut mac = [0u8; 8];
    mac.copy_from_slice(&md5_result[..8]);
    mac
}

/// Compute salted MAC (SEC_SECURE_CHECKSUM) -- MS-RDPBCGR 5.3.6.1.2.
///
/// ```text
/// SHAComponent = SHA1(MACKeyN + Pad1 + EncryptionCount(LE32) + Data)
/// MACSignature = First64Bits(MD5(MACKeyN + Pad2 + SHAComponent))
/// ```
///
/// The key difference from the standard MAC is that EncryptionCount
/// replaces DataLength in the SHA1 input.
pub fn compute_salted_mac(
    mac_key: &[u8; 16],
    data: &[u8],
    seq_number: u32,
) -> [u8; 8] {
    let pad1 = [0x36u8; 40];
    let pad2 = [0x5Cu8; 48];

    let seq_bytes = seq_number.to_le_bytes();

    let mut sha1 = Sha1::new();
    sha1.update(mac_key);
    sha1.update(&pad1);
    sha1.update(&seq_bytes); // EncryptionCount replaces DataLength
    sha1.update(data);
    let sha_result = sha1.finalize();

    let mut md5 = Md5::new();
    md5.update(mac_key);
    md5.update(&pad2);
    md5.update(&sha_result);
    let md5_result = md5.finalize();

    let mut mac = [0u8; 8];
    mac.copy_from_slice(&md5_result[..8]);
    mac
}

// ── Key Update (MS-RDPBCGR 5.3.5.3) ──

/// Update a session key after 4096 packets.
///
/// ```text
/// SHA1Component = SHA1(OriginalKey + Pad1 + CurrentKey)
/// TempKey = MD5(OriginalKey + Pad2 + SHA1Component)
/// NewKey = RC4(TempKey, TempKey[0..key_len])
/// ```
fn update_key(original_key: &[u8; 16], current_key: &[u8; 16], key_len: usize) -> [u8; 16] {
    let pad1 = [0x36u8; 40];
    let pad2 = [0x5Cu8; 48];

    let mut sha1 = Sha1::new();
    sha1.update(original_key);
    sha1.update(&pad1);
    sha1.update(current_key);
    let sha_result = sha1.finalize();

    let mut md5 = Md5::new();
    md5.update(original_key);
    md5.update(&pad2);
    md5.update(&sha_result);
    let temp_key = md5.finalize();

    // RC4-encrypt the temp key with itself (only key_len bytes)
    let mut rc4 = Rc4::new(&temp_key[..key_len]);
    let mut new_key = temp_key;
    rc4.process(&mut new_key[..key_len]);

    new_key
}

// ── Security Context ──

/// Standard RDP Security context for encryption/decryption.
///
/// Manages RC4 state, MAC computation, sequence numbers, and automatic
/// key updates every 4096 packets.
pub struct RdpSecurityContext {
    keys: SessionKeys,

    encrypt_rc4: Rc4,
    decrypt_rc4: Rc4,

    encrypt_count: u32,
    decrypt_count: u32,

    /// Whether to use salted MAC (SEC_SECURE_CHECKSUM).
    use_salted_mac: bool,
}

impl RdpSecurityContext {
    /// Create a new security context from derived session keys.
    pub fn new(keys: SessionKeys, use_salted_mac: bool) -> Self {
        let encrypt_rc4 = Rc4::new(&keys.encrypt_key[..keys.key_len]);
        let decrypt_rc4 = Rc4::new(&keys.decrypt_key[..keys.key_len]);

        Self {
            keys,
            encrypt_rc4,
            decrypt_rc4,
            encrypt_count: 0,
            decrypt_count: 0,
            use_salted_mac,
        }
    }

    /// Encrypt data in-place and return the MAC signature.
    ///
    /// The caller should prepend the security header with the returned MAC.
    pub fn encrypt(&mut self, data: &mut [u8]) -> [u8; 8] {
        // Compute MAC over plaintext
        let mac = if self.use_salted_mac {
            compute_salted_mac(&self.keys.mac_key, data, self.encrypt_count)
        } else {
            compute_mac(&self.keys.mac_key, data)
        };

        // Encrypt
        self.encrypt_rc4.process(data);
        self.encrypt_count += 1;

        // Key update every 4096 packets
        if self.encrypt_count % 4096 == 0 {
            self.keys.encrypt_key = update_key(
                &self.keys.encrypt_update_key,
                &self.keys.encrypt_key,
                self.keys.key_len,
            );
            self.encrypt_rc4 = Rc4::new(&self.keys.encrypt_key[..self.keys.key_len]);
        }

        mac
    }

    /// Decrypt data in-place and verify the MAC signature.
    ///
    /// Returns `true` if the MAC matches.
    pub fn decrypt(&mut self, data: &mut [u8], expected_mac: &[u8; 8]) -> bool {
        // Decrypt
        self.decrypt_rc4.process(data);

        // Verify MAC over decrypted plaintext
        let computed_mac = if self.use_salted_mac {
            compute_salted_mac(&self.keys.mac_key, data, self.decrypt_count)
        } else {
            compute_mac(&self.keys.mac_key, data)
        };

        self.decrypt_count += 1;

        // Key update every 4096 packets
        if self.decrypt_count % 4096 == 0 {
            self.keys.decrypt_key = update_key(
                &self.keys.decrypt_update_key,
                &self.keys.decrypt_key,
                self.keys.key_len,
            );
            self.decrypt_rc4 = Rc4::new(&self.keys.decrypt_key[..self.keys.key_len]);
        }

        computed_mac == *expected_mac
    }

    /// Get the current encryption method.
    pub fn encryption_method(&self) -> u32 {
        self.keys.encryption_method
    }

    /// Get current encrypt sequence number.
    pub fn encrypt_count(&self) -> u32 {
        self.encrypt_count
    }

    /// Get current decrypt sequence number.
    pub fn decrypt_count(&self) -> u32 {
        self.decrypt_count
    }
}

// ── FIPS Session Key Derivation (MS-RDPBCGR 5.3.5.2) ──

/// Derive FIPS session keys.
///
/// FIPS mode uses SHA-1 exclusively for key derivation:
/// ```text
/// S = SHA1(ClientRandom + ServerRandom)
/// MACKey = S[0..16] (first 16 bytes of SHA-1 hash, but we take first 20)
/// EncryptKey = SHA1(S + "encrypt" + ...)  — actually simpler
/// ```
///
/// Per MS-RDPBCGR 5.3.5.2:
/// ```text
/// MACKey = SHA1(ClientRandom + ServerRandom)[0..16] with odd parity
/// EncryptKey = SHA1(ServerRandom + ClientRandom)[0..24] split for 3DES
/// ```
///
/// Derive FIPS session keys per MS-RDPBCGR 5.3.5.2.
///
/// Steps:
/// 1. SHA-1 of split halves → 160-bit temp keys
/// 2. Expand 160→168 bits by appending first byte
/// 3. Expand 168→192 bits with DES parity insertion
/// 4. MACKey = SHA1(DecryptKeyT + EncryptKeyT)
pub fn derive_fips_session_keys(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> FipsSessionKeys {
    // Step 1: Generate 160-bit temp keys
    // Client encrypt key (= server decrypt key): SHA1(Last128Bits(CR) + Last128Bits(SR))
    let encrypt_key_t = crypto::sha1(&[&client_random[16..], &server_random[16..]].concat());
    // Client decrypt key (= server encrypt key): SHA1(First128Bits(CR) + First128Bits(SR))
    let decrypt_key_t = crypto::sha1(&[&client_random[..16], &server_random[..16]].concat());

    // Step 2: Expand 160→168 bits (append first byte)
    let mut encrypt_168 = [0u8; 21];
    encrypt_168[..20].copy_from_slice(&encrypt_key_t);
    encrypt_168[20] = encrypt_key_t[0];

    let mut decrypt_168 = [0u8; 21];
    decrypt_168[..20].copy_from_slice(&decrypt_key_t);
    decrypt_168[20] = decrypt_key_t[0];

    // Step 3: Expand 168→192 bits with DES odd-parity (3 × 8-byte DES keys)
    let encrypt_key = des_parity_expand_168(&encrypt_168);
    let decrypt_key = des_parity_expand_168(&decrypt_168);

    // Step 4: MAC key = SHA1(DecryptKeyT + EncryptKeyT), first 16 bytes
    let mac_hash = crypto::sha1(&[decrypt_key_t.as_slice(), encrypt_key_t.as_slice()].concat());
    let mut mac_key = [0u8; 16];
    mac_key.copy_from_slice(&mac_hash[..16]);

    FipsSessionKeys {
        mac_key,
        encrypt_key,
        decrypt_key,
    }
}

/// Expand a 168-bit (21-byte) key to 192 bits (24 bytes) with DES odd-parity.
///
/// MS-RDPBCGR 5.3.5.2: Insert a zero-bit after every 7 bits, then apply
/// DES odd-parity to each byte's LSB.
fn des_parity_expand_168(key_168: &[u8; 21]) -> [u8; 24] {
    let mut out = [0u8; 24];
    // Process 168 bits → 24 bytes (each 7-bit group → 1 byte with parity)
    // Extract 7 bits at a time from the bit stream and set odd parity
    for i in 0..24 {
        let bit_offset = i * 7;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;

        // Extract 7 bits spanning byte boundary
        let val = if bit_idx <= 1 {
            // Fits in one byte
            (key_168[byte_idx] >> (1 - bit_idx)) & 0x7F
        } else {
            // Spans two bytes
            let hi = (key_168[byte_idx] as u16) << 8;
            let lo = if byte_idx + 1 < key_168.len() {
                key_168[byte_idx + 1] as u16
            } else {
                0
            };
            let combined = hi | lo;
            ((combined >> (9 - bit_idx)) & 0x7F) as u8
        };

        // Place 7 bits in high bits, set LSB for odd parity
        let byte_val = val << 1;
        let ones = byte_val.count_ones();
        out[i] = if ones % 2 == 0 { byte_val | 1 } else { byte_val };
    }
    out
}

/// FIPS session keys (3DES + SHA-1 HMAC).
#[derive(Clone)]
pub struct FipsSessionKeys {
    pub mac_key: [u8; 16],
    /// 3DES key (24 bytes = 3 × 8-byte DES keys).
    pub encrypt_key: [u8; 24],
    pub decrypt_key: [u8; 24],
}

/// Compute FIPS MAC (SHA-1 HMAC) -- MS-RDPBCGR 5.3.6.2.
pub fn compute_fips_mac(mac_key: &[u8; 16], data: &[u8]) -> [u8; 8] {
    let hmac = crypto::hmac_sha1(mac_key, data);
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&hmac[..8]);
    mac
}

// ── FIPS Security Context ──

/// FIPS 140-1 Standard RDP Security context (3DES-CBC + SHA-1 HMAC).
///
/// MS-RDPBCGR 5.4.1 FIPS mode uses:
/// - 3DES-CBC for encryption/decryption
/// - SHA-1 HMAC for MAC signatures
/// - PKCS#5 padding (pad to 8-byte boundary)
pub struct FipsSecurityContext {
    keys: FipsSessionKeys,
    encrypt_cipher: justrdp_core::des::TripleDes,
    decrypt_cipher: justrdp_core::des::TripleDes,
    encrypt_iv: [u8; 8],
    decrypt_iv: [u8; 8],
    encrypt_count: u32,
    decrypt_count: u32,
}

impl FipsSecurityContext {
    /// Create a new FIPS security context.
    pub fn new(keys: FipsSessionKeys) -> Self {
        let encrypt_cipher = justrdp_core::des::TripleDes::new(&keys.encrypt_key);
        let decrypt_cipher = justrdp_core::des::TripleDes::new(&keys.decrypt_key);

        Self {
            keys,
            encrypt_cipher,
            decrypt_cipher,
            encrypt_iv: [0u8; 8],
            decrypt_iv: [0u8; 8],
            encrypt_count: 0,
            decrypt_count: 0,
        }
    }

    /// Encrypt data with 3DES-CBC and return (ciphertext, mac, pad_len).
    ///
    /// FIPS encryption adds PKCS#5 padding so the result may be larger.
    /// The caller must include `padlen` in the FIPS security header.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> (Vec<u8>, [u8; 8], u8) {
        // Compute HMAC over plaintext
        let mac = compute_fips_mac(&self.keys.mac_key, plaintext);

        // PKCS#5 padding: always add 1-8 bytes (no outer % 8)
        let pad_len = 8 - (plaintext.len() % 8);
        let total_len = plaintext.len() + pad_len;
        let mut padded = Vec::with_capacity(total_len);
        padded.extend_from_slice(plaintext);
        padded.resize(total_len, pad_len as u8);

        // 3DES-CBC encrypt (data is always padded to block size above)
        let ciphertext = self.encrypt_cipher.encrypt_cbc(&padded, &self.encrypt_iv)
            .expect("FIPS encrypt: data is pre-padded to 8-byte block size");

        // Update IV: last 8 bytes of ciphertext
        if ciphertext.len() >= 8 {
            self.encrypt_iv.copy_from_slice(&ciphertext[ciphertext.len() - 8..]);
        }

        self.encrypt_count += 1;

        (ciphertext, mac, pad_len as u8)
    }

    /// Decrypt data with 3DES-CBC and verify MAC.
    ///
    /// `pad_len` is from the FIPS security header.
    /// Returns the plaintext (without padding) and whether MAC is valid.
    pub fn decrypt(&mut self, ciphertext: &[u8], expected_mac: &[u8; 8], pad_len: u8) -> (Vec<u8>, bool) {
        // Save current IV, update for next block
        let iv = self.decrypt_iv;
        if ciphertext.len() >= 8 {
            self.decrypt_iv.copy_from_slice(&ciphertext[ciphertext.len() - 8..]);
        }

        // 3DES-CBC decrypt (ciphertext is always block-aligned from the protocol)
        let decrypted = self.decrypt_cipher.decrypt_cbc(ciphertext, &iv)
            .expect("FIPS decrypt: ciphertext is block-aligned");

        // Remove padding
        let data_len = decrypted.len().saturating_sub(pad_len as usize);
        let plaintext = decrypted[..data_len].to_vec();

        // Verify HMAC
        let computed_mac = compute_fips_mac(&self.keys.mac_key, &plaintext);
        let valid = computed_mac == *expected_mac;

        self.decrypt_count += 1;

        (plaintext, valid)
    }

    /// Get the current encryption method (always FIPS).
    pub fn encryption_method(&self) -> u32 {
        ENCRYPTION_METHOD_FIPS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn salted_hash_deterministic() {
        let secret = [0xAAu8; 48];
        let cr = [0x01u8; 32];
        let sr = [0x02u8; 32];

        let h1 = salted_hash(&secret, b"A", &cr, &sr);
        let h2 = salted_hash(&secret, b"A", &cr, &sr);
        assert_eq!(h1, h2);

        // Different salt → different hash
        let h3 = salted_hash(&secret, b"BB", &cr, &sr);
        assert_ne!(h1, h3);
    }

    #[test]
    fn derive_session_keys_128bit() {
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];

        let keys = derive_session_keys(&cr, &sr, ENCRYPTION_METHOD_128BIT);
        assert_eq!(keys.key_len, 16);
        // Keys should be deterministic
        let keys2 = derive_session_keys(&cr, &sr, ENCRYPTION_METHOD_128BIT);
        assert_eq!(keys.mac_key, keys2.mac_key);
        assert_eq!(keys.encrypt_key, keys2.encrypt_key);
        assert_eq!(keys.decrypt_key, keys2.decrypt_key);
        // MAC key ≠ encrypt key ≠ decrypt key
        assert_ne!(keys.mac_key, keys.encrypt_key);
        assert_ne!(keys.encrypt_key, keys.decrypt_key);
    }

    #[test]
    fn derive_session_keys_40bit() {
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];

        let keys = derive_session_keys(&cr, &sr, ENCRYPTION_METHOD_40BIT);
        assert_eq!(keys.key_len, 8);
        // 40-bit keys: 5 key bytes + salt 0xD1269E at bytes 5-7
        assert_eq!(keys.encrypt_key[5], 0xD1);
        assert_eq!(keys.encrypt_key[6], 0x26);
        assert_eq!(keys.encrypt_key[7], 0x9E);
    }

    #[test]
    fn mac_signature() {
        let mac_key = [0x42u8; 16];
        let data = b"Hello RDP Security";
        let mac = compute_mac(&mac_key, data);
        assert_eq!(mac.len(), 8);

        // Deterministic
        let mac2 = compute_mac(&mac_key, data);
        assert_eq!(mac, mac2);

        // Different data → different MAC
        let mac3 = compute_mac(&mac_key, b"Other data");
        assert_ne!(mac, mac3);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let cr = [0xAAu8; 32];
        let sr = [0xBBu8; 32];

        let keys = derive_session_keys(&cr, &sr, ENCRYPTION_METHOD_128BIT);
        let mut enc_ctx = RdpSecurityContext::new(keys.clone(), false);

        // For decryption, swap encrypt/decrypt keys (server uses opposite direction)
        let dec_keys = SessionKeys {
            encrypt_key: keys.decrypt_key,
            decrypt_key: keys.encrypt_key,
            encrypt_update_key: keys.decrypt_update_key,
            decrypt_update_key: keys.encrypt_update_key,
            ..keys
        };
        let mut dec_ctx = RdpSecurityContext::new(dec_keys, false);

        let original = b"Test data for Standard RDP Security encryption";
        let mut data = original.to_vec();

        let mac = enc_ctx.encrypt(&mut data);
        assert_ne!(data.as_slice(), original.as_slice()); // encrypted

        let valid = dec_ctx.decrypt(&mut data, &mac);
        assert!(valid);
        assert_eq!(data.as_slice(), original.as_slice()); // decrypted back
    }

    #[test]
    fn key_update_at_4096() {
        let cr = [0xCCu8; 32];
        let sr = [0xDDu8; 32];
        let keys = derive_session_keys(&cr, &sr, ENCRYPTION_METHOD_128BIT);
        let original_encrypt_key = keys.encrypt_key;

        let mut ctx = RdpSecurityContext::new(keys, false);

        // Encrypt 4096 packets
        for _ in 0..4096 {
            let mut data = vec![0x42u8; 16];
            ctx.encrypt(&mut data);
        }

        // After 4096 packets, the key should have been updated
        assert_ne!(ctx.keys.encrypt_key, original_encrypt_key);
        assert_eq!(ctx.encrypt_count, 4096);
    }

    #[test]
    fn salted_mac_differs_by_seqno() {
        let mac_key = [0x55u8; 16];
        let data = b"test";

        let mac0 = compute_salted_mac(&mac_key, data, 0);
        let mac1 = compute_salted_mac(&mac_key, data, 1);
        assert_ne!(mac0, mac1);
    }

    #[test]
    fn fips_key_derivation() {
        // Use randoms with distinct first/last halves so encrypt ≠ decrypt
        let mut cr = [0u8; 32];
        for i in 0..32 { cr[i] = i as u8; }
        let mut sr = [0u8; 32];
        for i in 0..32 { sr[i] = (0x80 + i) as u8; }

        let fips = derive_fips_session_keys(&cr, &sr);
        assert_eq!(fips.mac_key.len(), 16);
        assert_eq!(fips.encrypt_key.len(), 24);
        assert_eq!(fips.decrypt_key.len(), 24);

        // Deterministic
        let fips2 = derive_fips_session_keys(&cr, &sr);
        assert_eq!(fips.mac_key, fips2.mac_key);
        assert_eq!(fips.encrypt_key, fips2.encrypt_key);
        assert_eq!(fips.decrypt_key, fips2.decrypt_key);

        // Encrypt and decrypt keys should differ (different halves of randoms)
        assert_ne!(fips.encrypt_key, fips.decrypt_key);

        // All DES key bytes should have odd parity
        for &byte in fips.encrypt_key.iter().chain(fips.decrypt_key.iter()) {
            assert_eq!(byte.count_ones() % 2, 1,
                "DES key byte 0x{:02X} does not have odd parity", byte);
        }
    }

    #[test]
    fn des_parity_expand_produces_odd_parity() {
        // Every byte in a DES parity-expanded key must have odd parity
        let key_168 = [0xD1, 0x5E, 0xC4, 0x7E, 0xDA, 0x12, 0x34,
                       0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11,
                       0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let expanded = des_parity_expand_168(&key_168);
        assert_eq!(expanded.len(), 24);

        // Every byte must have odd parity (odd number of 1-bits)
        for (i, &byte) in expanded.iter().enumerate() {
            assert_eq!(byte.count_ones() % 2, 1,
                "byte {} (0x{:02X}) does not have odd parity", i, byte);
        }
    }

    #[test]
    fn fips_encrypt_block_aligned_input() {
        // Test PKCS#5 padding when input is exactly block-aligned (8 bytes)
        // Should add a full 8-byte padding block
        let cr = [0xAAu8; 32];
        let sr = [0xBBu8; 32];
        let keys = derive_fips_session_keys(&cr, &sr);

        let enc_keys = keys.clone();
        let dec_keys = FipsSessionKeys {
            mac_key: keys.mac_key,
            encrypt_key: keys.decrypt_key,
            decrypt_key: keys.encrypt_key,
        };

        let mut enc_ctx = FipsSecurityContext::new(enc_keys);
        let mut dec_ctx = FipsSecurityContext::new(dec_keys);

        // 8 bytes = block-aligned → PKCS#5 adds 8 bytes of padding (value 0x08)
        let original = b"12345678";
        let (ciphertext, mac, pad_len) = enc_ctx.encrypt(original);
        assert_eq!(pad_len, 8, "block-aligned input should get 8 bytes of PKCS#5 padding");
        assert_eq!(ciphertext.len(), 16, "8 bytes + 8 padding = 16 bytes ciphertext");

        let (plaintext, valid) = dec_ctx.decrypt(&ciphertext, &mac, pad_len);
        assert!(valid);
        assert_eq!(&plaintext[..], &original[..]);
    }

    #[test]
    fn salted_mac_uses_seq_not_datalen() {
        // Verify salted MAC changes with seq number, not just data length
        let mac_key = [0x42u8; 16];
        let data = b"test data";

        let mac_seq0 = compute_salted_mac(&mac_key, data, 0);
        let mac_seq1 = compute_salted_mac(&mac_key, data, 1);
        let mac_std = compute_mac(&mac_key, data);

        // Salted MACs should differ by seq
        assert_ne!(mac_seq0, mac_seq1);
        // Salted MAC should differ from standard MAC (different SHA1 input)
        assert_ne!(mac_seq0, mac_std);
    }

    #[test]
    fn fips_encrypt_decrypt_roundtrip() {
        let cr = [0xAAu8; 32];
        let sr = [0xBBu8; 32];

        let keys = derive_fips_session_keys(&cr, &sr);

        // For roundtrip: encrypt context uses encrypt key, decrypt uses decrypt key
        let enc_keys = keys.clone();
        let dec_keys = FipsSessionKeys {
            mac_key: keys.mac_key,
            encrypt_key: keys.decrypt_key, // swap for other direction
            decrypt_key: keys.encrypt_key,
        };

        let mut enc_ctx = FipsSecurityContext::new(enc_keys);
        let mut dec_ctx = FipsSecurityContext::new(dec_keys);

        let original = b"FIPS 140-1 Standard RDP Security test data!!";
        let (ciphertext, mac, pad_len) = enc_ctx.encrypt(original);

        assert_ne!(&ciphertext[..], &original[..]);
        assert!(ciphertext.len() % 8 == 0); // 3DES block-aligned

        let (plaintext, valid) = dec_ctx.decrypt(&ciphertext, &mac, pad_len);
        assert!(valid);
        assert_eq!(&plaintext[..], &original[..]);
    }
}
