#![forbid(unsafe_code)]

//! NTLM signing and sealing (MS-NLMP 3.4.4).

use alloc::vec;

use justrdp_core::crypto::{hmac_md5, md5, Rc4};

/// Derive signing key from session key.
///
/// SignKey = MD5(SessionKey + "session key to client-to-server signing key magic constant\0")
pub fn signing_key(session_key: &[u8; 16], client_to_server: bool) -> [u8; 16] {
    let magic = if client_to_server {
        b"session key to client-to-server signing key magic constant\0"
    } else {
        b"session key to server-to-client signing key magic constant\0"
    };

    let mut input = vec![0u8; 16 + magic.len()];
    input[..16].copy_from_slice(session_key);
    input[16..].copy_from_slice(magic);
    md5(&input)
}

/// Derive sealing key from session key.
///
/// For 128-bit: SealKey = MD5(SessionKey + "session key to client-to-server sealing key magic constant\0")
pub fn sealing_key(session_key: &[u8; 16], client_to_server: bool) -> [u8; 16] {
    let magic = if client_to_server {
        b"session key to client-to-server sealing key magic constant\0"
    } else {
        b"session key to server-to-client sealing key magic constant\0"
    };

    let mut input = vec![0u8; 16 + magic.len()];
    input[..16].copy_from_slice(session_key);
    input[16..].copy_from_slice(magic);
    md5(&input)
}

/// NTLM sealing key state (RC4 cipher state).
pub struct NtlmSealingKey {
    rc4: Rc4,
}

impl NtlmSealingKey {
    /// Create a new sealing key from the derived key bytes.
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            rc4: Rc4::new(key),
        }
    }
}

/// NTLM signing/sealing context.
pub struct NtlmSigningContext {
    pub signing_key: [u8; 16],
    pub sealing_key: NtlmSealingKey,
    pub seq_num: u32,
}

impl NtlmSigningContext {
    /// Create a new signing context.
    pub fn new(session_key: &[u8; 16], client_to_server: bool) -> Self {
        let sign_key = signing_key(session_key, client_to_server);
        let seal_key = sealing_key(session_key, client_to_server);

        Self {
            signing_key: sign_key,
            sealing_key: NtlmSealingKey::new(&seal_key),
            seq_num: 0,
        }
    }

    /// Compute NTLM MAC (signature) for a message.
    ///
    /// Returns the 16-byte MAC. Format (MS-NLMP 3.4.4.2):
    /// Version(4) + Checksum(8) + SeqNum(4)
    pub fn sign(&mut self, message: &[u8]) -> [u8; 16] {
        // HMAC_MD5(SigningKey, SeqNum + Message)
        let mut hmac_input = vec![0u8; 4 + message.len()];
        hmac_input[..4].copy_from_slice(&self.seq_num.to_le_bytes());
        hmac_input[4..].copy_from_slice(message);
        let hmac_result = hmac_md5(&self.signing_key, &hmac_input);

        // Encrypt first 8 bytes of HMAC with RC4
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&hmac_result[..8]);
        self.sealing_key.rc4.process(&mut checksum);

        // Build MAC: Version(0x00000001) + Checksum(8) + SeqNum(4)
        let mut mac = [0u8; 16];
        mac[..4].copy_from_slice(&1u32.to_le_bytes()); // Version
        mac[4..12].copy_from_slice(&checksum);
        mac[12..16].copy_from_slice(&self.seq_num.to_le_bytes());

        self.seq_num += 1;
        mac
    }

    /// Seal (encrypt) a message and compute its MAC.
    ///
    /// Per MS-NLMP 3.4.4.2.1 with ESS:
    /// 1. Encrypt message in-place with RC4 (advancing RC4 state)
    /// 2. Compute HMAC-MD5(SigningKey, SeqNum + original_plaintext)
    /// 3. Encrypt first 8 bytes of HMAC with same RC4 stream
    ///
    /// Returns the 16-byte MAC. Message is encrypted in-place.
    pub fn seal(&mut self, message: &mut [u8]) -> [u8; 16] {
        let seq_num = self.seq_num;

        // Step 1: Save plaintext for HMAC computation, then encrypt
        let plaintext_copy = message.to_vec();
        self.sealing_key.rc4.process(message);

        // Step 2: HMAC-MD5(SigningKey, SeqNum + original_plaintext)
        let mut hmac_input = alloc::vec![0u8; 4 + plaintext_copy.len()];
        hmac_input[..4].copy_from_slice(&seq_num.to_le_bytes());
        hmac_input[4..].copy_from_slice(&plaintext_copy);
        let hmac_result = hmac_md5(&self.signing_key, &hmac_input);

        // Step 3: Encrypt first 8 bytes of HMAC with same RC4 stream
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&hmac_result[..8]);
        self.sealing_key.rc4.process(&mut checksum);

        // Build MAC: Version(0x00000001) + Checksum(8) + SeqNum(4)
        let mut mac = [0u8; 16];
        mac[..4].copy_from_slice(&1u32.to_le_bytes());
        mac[4..12].copy_from_slice(&checksum);
        mac[12..16].copy_from_slice(&seq_num.to_le_bytes());

        self.seq_num += 1;
        mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_derivation() {
        let session_key = [0x55u8; 16];
        let key = signing_key(&session_key, true);
        // Should produce a valid 16-byte key
        assert_eq!(key.len(), 16);
        // Client and server keys should differ
        let server_key = signing_key(&session_key, false);
        assert_ne!(key, server_key);
    }

    #[test]
    fn sealing_key_derivation() {
        let session_key = [0x55u8; 16];
        let key = sealing_key(&session_key, true);
        assert_eq!(key.len(), 16);
        let server_key = sealing_key(&session_key, false);
        assert_ne!(key, server_key);
    }

    #[test]
    fn sign_produces_valid_mac() {
        let session_key = [0x55u8; 16];
        let mut ctx = NtlmSigningContext::new(&session_key, true);

        let mac = ctx.sign(b"Hello, World!");
        // Version should be 1
        assert_eq!(u32::from_le_bytes(mac[..4].try_into().unwrap()), 1);
        // SeqNum should be 0 (was 0 before sign, incremented after)
        assert_eq!(u32::from_le_bytes(mac[12..16].try_into().unwrap()), 0);
    }

    #[test]
    fn sign_increments_seq_num() {
        let session_key = [0x55u8; 16];
        let mut ctx = NtlmSigningContext::new(&session_key, true);

        let mac1 = ctx.sign(b"msg1");
        let mac2 = ctx.sign(b"msg2");

        let seq1 = u32::from_le_bytes(mac1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(mac2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }
}
