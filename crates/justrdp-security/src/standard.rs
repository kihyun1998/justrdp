//! Standard RDP Security (`[MS-RDPBCGR]` 5.3), the client's side of it: the encrypted client
//! random, the session keys, and the protection of each PDU in each direction.
//!
//! [`StandardSecurity`] is a value with no socket: bytes in, bytes out. The cipher state advances
//! on every call, so PDUs must reach the wire in the order they were protected.

use crate::license_crypto::{Rc4, md5, rsa_public_le, salted_hash, sha1};
use justrdp_pdu::client_info::{
    MAC_SIGNATURE_SIZE, SEC_AUTODETECT_REQ, SEC_ENCRYPT, SEC_HEARTBEAT, SEC_LICENSE_PKT,
    SEC_REDIRECTION_PKT, SEC_SECURE_CHECKSUM, SEC_TRANSPORT_REQ, encode_basic_security_header,
};
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::error::DecodeError;
use justrdp_pdu::license::RsaPublicKey;

/// The size of the client and server randoms (5.3.4).
pub const RANDOM_SIZE: usize = 32;
/// Packets one key encrypts before it is updated (5.3.7.1).
const PACKETS_PER_KEY: u32 = 4096;
/// The longest modulus accepted, in bytes.
const MAX_MODULUS_SIZE: usize = 512;
/// `FASTPATH_*_SECURE_CHECKSUM`, as a fast-path header's two flag bits hold it.
pub const FASTPATH_SECURE_CHECKSUM: u8 = 0x1;
/// `FASTPATH_*_ENCRYPTED`, as a fast-path header's two flag bits hold it.
pub const FASTPATH_ENCRYPTED: u8 = 0x2;

/// The server PDUs whose own sections allow them unencrypted at any level.
const MAY_STAY_IN_THE_CLEAR: u16 =
    SEC_LICENSE_PKT | SEC_AUTODETECT_REQ | SEC_TRANSPORT_REQ | SEC_HEARTBEAT;

const PAD1: [u8; 40] = [0x36; 40];
const PAD2: [u8; 48] = [0x5C; 48];

/// The client random. Its [`Debug`](core::fmt::Debug) output holds none of it.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientRandom([u8; RANDOM_SIZE]);

impl ClientRandom {
    /// Wrap 32 bytes from a cryptographically safe source (5.3.4).
    pub fn new(bytes: [u8; RANDOM_SIZE]) -> Self {
        Self(bytes)
    }

    /// The random itself.
    pub fn as_bytes(&self) -> &[u8; RANDOM_SIZE] {
        &self.0
    }
}

impl core::fmt::Debug for ClientRandom {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClientRandom(..)")
    }
}

/// The session key strength the server selected (`encryptionMethod`, 2.2.1.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    /// `ENCRYPTION_METHOD_40BIT`.
    Rc4Bit40,
    /// `ENCRYPTION_METHOD_56BIT`.
    Rc4Bit56,
    /// `ENCRYPTION_METHOD_128BIT`.
    Rc4Bit128,
}

impl EncryptionMethod {
    /// From the wire value. `ENCRYPTION_METHOD_FIPS` is Triple DES, which this layer does not hold.
    pub fn from_wire(value: u32) -> Result<Self, StandardSecurityError> {
        match value {
            0x01 => Ok(Self::Rc4Bit40),
            0x08 => Ok(Self::Rc4Bit56),
            0x02 => Ok(Self::Rc4Bit128),
            other => Err(StandardSecurityError::UnsupportedMethod(other)),
        }
    }

    /// The RC4 key length (5.3.5.1, Table 1).
    fn key_len(self) -> usize {
        match self {
            Self::Rc4Bit40 | Self::Rc4Bit56 => 8,
            Self::Rc4Bit128 => 16,
        }
    }

    /// Overwrite the bytes that reduce the key's entropy (5.3.5.1, Table 1).
    fn salt(self, key: &mut [u8; 16]) {
        match self {
            Self::Rc4Bit40 => key[..3].copy_from_slice(&[0xD1, 0x26, 0x9E]),
            Self::Rc4Bit56 => key[0] = 0xD1,
            Self::Rc4Bit128 => {}
        }
    }
}

/// What the server encrypts (`encryptionLevel`, 5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionLevel {
    /// `ENCRYPTION_LEVEL_LOW`: client-to-server traffic only.
    Low,
    /// `ENCRYPTION_LEVEL_CLIENT_COMPATIBLE`: both directions.
    ClientCompatible,
    /// `ENCRYPTION_LEVEL_HIGH`: both directions.
    High,
}

impl EncryptionLevel {
    /// From the wire value. `ENCRYPTION_LEVEL_FIPS` is Triple DES, which this layer does not hold.
    pub fn from_wire(value: u32) -> Result<Self, StandardSecurityError> {
        match value {
            1 => Ok(Self::Low),
            2 => Ok(Self::ClientCompatible),
            3 => Ok(Self::High),
            other => Err(StandardSecurityError::UnsupportedLevel(other)),
        }
    }

    fn encrypts_server_traffic(self) -> bool {
        self != Self::Low
    }
}

/// Why the layer refused. Holds no key material and no plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardSecurityError {
    /// An `encryptionMethod` this layer does not implement.
    UnsupportedMethod(u32),
    /// An `encryptionLevel` this layer does not implement.
    UnsupportedLevel(u32),
    /// A `serverRandom` that is not 32 bytes, with the length it had.
    ServerRandomLength(usize),
    /// A public key with a zero modulus, or one past the longest accepted.
    InvalidPublicKey,
    /// A MAC that does not match its data.
    MacMismatch,
    /// A PDU that was not encrypted, at a level where it must be.
    NotEncrypted,
    /// A PDU too short for its security header.
    Malformed(DecodeError),
}

impl core::fmt::Display for StandardSecurityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedMethod(value) => write!(f, "unsupported encryption method {value:#x}"),
            Self::UnsupportedLevel(value) => write!(f, "unsupported encryption level {value}"),
            Self::ServerRandomLength(len) => write!(f, "server random of {len} bytes, not 32"),
            Self::InvalidPublicKey => f.write_str("unusable server public key"),
            Self::MacMismatch => f.write_str("MAC mismatch"),
            Self::NotEncrypted => f.write_str("unencrypted PDU at an encrypting level"),
            Self::Malformed(error) => write!(f, "malformed security header: {error}"),
        }
    }
}

impl std::error::Error for StandardSecurityError {}

impl From<DecodeError> for StandardSecurityError {
    fn from(error: DecodeError) -> Self {
        Self::Malformed(error)
    }
}

/// Encrypt the client random for the Security Exchange PDU (5.3.4.1): `(bitlen / 8) + 8` bytes,
/// little-endian, whatever the value's magnitude. For a server that sends an X.509 chain, `key` is
/// the leaf's `subjectPublicKey` through [`RsaPublicKey::from_pkcs1_der`].
pub fn encrypt_client_random(
    client_random: &ClientRandom,
    key: &RsaPublicKey,
) -> Result<Vec<u8>, StandardSecurityError> {
    if key.modulus.len() > MAX_MODULUS_SIZE || key.modulus.iter().all(|&b| b == 0) {
        return Err(StandardSecurityError::InvalidPublicKey);
    }
    let mut out = rsa_public_le(client_random.as_bytes(), &key.modulus, key.exponent);
    out.resize(out.len() + 8, 0);
    Ok(out)
}

/// One direction's cipher: the key it started from, the current one and the keystream.
struct Cipher {
    method: EncryptionMethod,
    initial: [u8; 16],
    current: [u8; 16],
    rc4: Rc4,
    since_update: u32,
    total: u32,
}

impl Cipher {
    fn new(method: EncryptionMethod, key: [u8; 16]) -> Self {
        Self {
            method,
            initial: key,
            current: key,
            rc4: Rc4::new(&key[..method.key_len()]),
            since_update: 0,
            total: 0,
        }
    }

    /// Update the key (5.3.7.1) when this packet is the first past the limit, then apply the
    /// keystream.
    fn apply(&mut self, data: &mut [u8]) {
        if self.since_update >= PACKETS_PER_KEY {
            self.update_key();
        }
        self.rc4.apply(data);
        self.since_update += 1;
        self.total = self.total.wrapping_add(1);
    }

    fn update_key(&mut self) {
        let len = self.method.key_len();
        let sha = sha1(&[&self.initial[..len], &PAD1, &self.current[..len]].concat());
        let temp = md5(&[&self.initial[..len], &PAD2, &sha].concat());
        let mut next = [0u8; 16];
        next[..len].copy_from_slice(&temp[..len]);
        Rc4::new(&temp[..len]).apply(&mut next[..len]);
        self.method.salt(&mut next);
        self.current = next;
        self.rc4 = Rc4::new(&next[..len]);
        self.since_update = 0;
    }
}

/// The session keys and cipher state of one connection, client side. Its
/// [`Debug`](core::fmt::Debug) output holds none of them.
pub struct StandardSecurity {
    method: EncryptionMethod,
    level: EncryptionLevel,
    mac_key: [u8; 16],
    salted_mac: bool,
    outbound: Cipher,
    inbound: Cipher,
}

impl core::fmt::Debug for StandardSecurity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StandardSecurity")
            .field("method", &self.method)
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

/// A PDU after [`StandardSecurity::unprotect_slow_path`]. Its [`Debug`](core::fmt::Debug) output
/// holds the payload's length, not the payload.
#[derive(Clone, PartialEq, Eq)]
pub struct SlowPathPdu {
    /// The security header's `flags`.
    pub flags: u16,
    /// The data after the security header, decrypted.
    pub payload: Vec<u8>,
}

impl core::fmt::Debug for SlowPathPdu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlowPathPdu")
            .field("flags", &self.flags)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// A fast-path PDU's protected parts, from [`StandardSecurity::protect_fast_path`].
pub struct FastPathBody {
    /// The two flag bits for the PDU's header.
    pub header_flags: u8,
    /// `dataSignature` and the encrypted data: what follows the PDU's length fields.
    pub body: Vec<u8>,
}

impl StandardSecurity {
    /// Derive the session keys (5.3.5.1).
    pub fn new(
        method: EncryptionMethod,
        level: EncryptionLevel,
        client_random: &ClientRandom,
        server_random: &[u8],
    ) -> Result<Self, StandardSecurityError> {
        let server_random: &[u8; RANDOM_SIZE] = server_random
            .try_into()
            .map_err(|_| StandardSecurityError::ServerRandomLength(server_random.len()))?;
        let client_random = client_random.as_bytes();

        let blob = |secret: &[u8], inputs: [&[u8]; 3]| -> [u8; 48] {
            let mut out = [0u8; 48];
            for (chunk, input) in out.as_chunks_mut::<16>().0.iter_mut().zip(inputs) {
                chunk.copy_from_slice(&salted_hash(secret, client_random, server_random, input));
            }
            out
        };
        let pre_master = [&client_random[..24], &server_random[..24]].concat();
        let master = blob(&pre_master, [b"A", b"BB", b"CCC"]);
        let session = blob(&master, [b"X", b"YY", b"ZZZ"]);

        let final_hash =
            |k: &[u8]| -> [u8; 16] { md5(&[k, client_random, server_random].concat()) };
        let mut mac_key = [0u8; 16];
        mac_key.copy_from_slice(&session[..16]);
        let mut decrypt = final_hash(&session[16..32]);
        let mut encrypt = final_hash(&session[32..48]);
        method.salt(&mut mac_key);
        method.salt(&mut decrypt);
        method.salt(&mut encrypt);

        Ok(Self {
            method,
            level,
            mac_key,
            salted_mac: false,
            outbound: Cipher::new(method, encrypt),
            inbound: Cipher::new(method, decrypt),
        })
    }

    /// Whether [`protect_slow_path`](Self::protect_slow_path) and
    /// [`protect_fast_path`](Self::protect_fast_path) salt their MAC. Set once both sides have
    /// advertised `ENC_SALTED_CHECKSUM` in the General Capability Set (5.3.6.1.1). Inbound, each
    /// PDU's own flags decide.
    pub fn set_salted_mac(&mut self, salted: bool) {
        self.salted_mac = salted;
    }

    /// This connection's other end, for a test that scripts a server.
    #[cfg(any(test, feature = "test-peer"))]
    pub fn into_server_peer(mut self) -> Self {
        core::mem::swap(&mut self.outbound, &mut self.inbound);
        self
    }

    /// The MAC of `plain` (5.3.6.1), salted with `count` when given (5.3.6.1.1).
    fn signature(&self, plain: &[u8], count: Option<u32>) -> [u8; MAC_SIGNATURE_SIZE] {
        let key = &self.mac_key[..self.method.key_len()];
        let len = (plain.len() as u32).to_le_bytes();
        let salt = count.map(u32::to_le_bytes);
        let sha = sha1(&[key, &PAD1, &len, plain, salt.as_ref().map_or(&[], |s| s)].concat());
        let digest = md5(&[key, &PAD2, &sha].concat());
        let mut out = [0u8; MAC_SIGNATURE_SIZE];
        out.copy_from_slice(&digest[..MAC_SIGNATURE_SIZE]);
        out
    }

    /// Sign and encrypt one PDU's data, returning the signature and the ciphertext.
    pub fn protect(&mut self, plain: &[u8], salted: bool) -> ([u8; MAC_SIGNATURE_SIZE], Vec<u8>) {
        let count = salted.then_some(self.outbound.total);
        let signature = self.signature(plain, count);
        let mut data = plain.to_vec();
        self.outbound.apply(&mut data);
        (signature, data)
    }

    /// Decrypt one PDU's data and check its signature. A mismatch is an error: the connection is
    /// to be dropped (5.3.6.1).
    pub fn unprotect(
        &mut self,
        signature: &[u8; MAC_SIGNATURE_SIZE],
        ciphertext: &[u8],
        salted: bool,
    ) -> Result<Vec<u8>, StandardSecurityError> {
        let count = salted.then_some(self.inbound.total);
        let mut data = ciphertext.to_vec();
        self.inbound.apply(&mut data);
        if &self.signature(&data, count) != signature {
            return Err(StandardSecurityError::MacMismatch);
        }
        Ok(data)
    }

    /// A slow-path PDU's data: a non-FIPS security header carrying `flags` and [`SEC_ENCRYPT`],
    /// then the encrypted `plain`.
    pub fn protect_slow_path(&mut self, flags: u16, plain: &[u8]) -> Vec<u8> {
        let salted = self.salted_mac;
        let (signature, ciphertext) = self.protect(plain, salted);
        let checksum = if salted { SEC_SECURE_CHECKSUM } else { 0 };
        let mut out = Vec::with_capacity(4 + MAC_SIGNATURE_SIZE + ciphertext.len());
        encode_basic_security_header(&mut out, flags | SEC_ENCRYPT | checksum);
        out.extend_from_slice(&signature);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Read a slow-path PDU's security header and decrypt what follows. An unencrypted PDU is
    /// accepted only at a level that leaves server traffic in the clear, or when its flags name a
    /// PDU the spec allows in the clear at any level: licensing (2.2.1.12), Auto-Detect Request
    /// (2.2.14.3), Initiate Multitransport Request (2.2.15.1) and Heartbeat (2.2.16.1). The flags
    /// are what is read, whatever the connection's phase.
    pub fn unprotect_slow_path(
        &mut self,
        bytes: &[u8],
    ) -> Result<SlowPathPdu, StandardSecurityError> {
        let mut cur = ReadCursor::new(bytes, "security header");
        let flags = cur.read_u16_le()?;
        cur.read_u16_le()?; // flagsHi
        if flags & (SEC_ENCRYPT | SEC_REDIRECTION_PKT) == 0 {
            if self.level.encrypts_server_traffic() && flags & MAY_STAY_IN_THE_CLEAR == 0 {
                return Err(StandardSecurityError::NotEncrypted);
            }
            let payload = cur.read_slice(cur.remaining())?.to_vec();
            return Ok(SlowPathPdu { flags, payload });
        }
        let signature = read_signature(&mut cur)?;
        let ciphertext = cur.read_slice(cur.remaining())?;
        let payload = self.unprotect(&signature, ciphertext, flags & SEC_SECURE_CHECKSUM != 0)?;
        Ok(SlowPathPdu { flags, payload })
    }

    /// Sign and encrypt a fast-path PDU's data, input or output alike (2.2.8.1.2, 2.2.9.1.2).
    pub fn protect_fast_path(&mut self, plain: &[u8]) -> FastPathBody {
        let salted = self.salted_mac;
        let (signature, ciphertext) = self.protect(plain, salted);
        let mut body = signature.to_vec();
        body.extend_from_slice(&ciphertext);
        let checksum = if salted { FASTPATH_SECURE_CHECKSUM } else { 0 };
        FastPathBody {
            header_flags: FASTPATH_ENCRYPTED | checksum,
            body,
        }
    }

    /// Decrypt a fast-path PDU's body: the bytes after its length fields, given the two flag bits
    /// of its header (2.2.9.1.2). Unencrypted bytes follow the same rule as
    /// [`unprotect_slow_path`](Self::unprotect_slow_path).
    pub fn unprotect_fast_path(
        &mut self,
        header_flags: u8,
        body: &[u8],
    ) -> Result<Vec<u8>, StandardSecurityError> {
        if header_flags & FASTPATH_ENCRYPTED == 0 {
            if self.level.encrypts_server_traffic() {
                return Err(StandardSecurityError::NotEncrypted);
            }
            return Ok(body.to_vec());
        }
        let mut cur = ReadCursor::new(body, "fast-path dataSignature");
        let signature = read_signature(&mut cur)?;
        let ciphertext = cur.read_slice(cur.remaining())?;
        self.unprotect(
            &signature,
            ciphertext,
            header_flags & FASTPATH_SECURE_CHECKSUM != 0,
        )
    }
}

fn read_signature(
    cur: &mut ReadCursor<'_>,
) -> Result<[u8; MAC_SIGNATURE_SIZE], StandardSecurityError> {
    let mut signature = [0u8; MAC_SIGNATURE_SIZE];
    signature.copy_from_slice(cur.read_slice(MAC_SIGNATURE_SIZE)?);
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::client_info::{SEC_INFO_PKT, encode_security_exchange};
    use proptest::prelude::*;

    /// Printed by FreeRDP's own `security.c`; see `tests/fixtures/freerdp_vectors/README.md`.
    const VECTORS: &str = include_str!("../tests/fixtures/freerdp_vectors/vectors.txt");

    const METHODS: [(u32, EncryptionMethod); 3] = [
        (1, EncryptionMethod::Rc4Bit40),
        (8, EncryptionMethod::Rc4Bit56),
        (2, EncryptionMethod::Rc4Bit128),
    ];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The randoms the fixture was generated from.
    fn randoms() -> (ClientRandom, [u8; 32]) {
        (
            ClientRandom::new(core::array::from_fn(|i| 0x10 + i as u8)),
            core::array::from_fn(|i| 0xE0 ^ (i * 7) as u8),
        )
    }

    fn client(method: EncryptionMethod) -> StandardSecurity {
        let (client, server) = randoms();
        StandardSecurity::new(method, EncryptionLevel::High, &client, &server).unwrap()
    }

    /// The server's side of `client`, built by swapping its ciphers.
    fn server_of(method: EncryptionMethod) -> StandardSecurity {
        client(method).into_server_peer()
    }

    /// Packet `i` of the fixture's traffic.
    fn packet(i: u32) -> (Vec<u8>, bool) {
        let len = 1 + i % 31;
        (
            (0..len).map(|j| (i + j) as u8).collect(),
            i.is_multiple_of(3),
        )
    }

    /// The fixture's lines for one method and direction: `i -> (sig, ct)`, and the MD5 over all.
    fn expected(
        method: u32,
        dir: &str,
    ) -> (std::collections::HashMap<u32, (String, String)>, Vec<u8>) {
        let mut lines = VECTORS
            .lines()
            .skip_while(|l| !l.starts_with(&format!("method={method} ")));
        lines.next();
        let mut packets = std::collections::HashMap::new();
        let mut total = None;
        for line in lines.take_while(|l| !l.starts_with("method=")) {
            let mut fields = line.split_whitespace();
            if fields.next() != Some(dir) {
                continue;
            }
            let values: Vec<&str> = fields.map(|f| f.split_once('=').unwrap().1).collect();
            if values.len() == 1 {
                total = Some(unhex(values[0]));
            } else {
                packets.insert(
                    values[0].parse().unwrap(),
                    (values[1].to_string(), values[2].to_string()),
                );
            }
        }
        (packets, total.unwrap())
    }

    /// Everything `sender` produces is what FreeRDP produced in that direction, past two key
    /// updates, and `receiver` recovers every packet from it.
    fn assert_traffic(
        method: u32,
        dir: &str,
        sender: &mut StandardSecurity,
        receiver: &mut StandardSecurity,
    ) {
        let (packets, total) = expected(method, dir);
        assert_eq!(packets.len(), 8);
        let mut all = Vec::new();
        for i in 0..8200 {
            let (plain, salted) = packet(i);
            let (sig, ct) = sender.protect(&plain, salted);
            if let Some((want_sig, want_ct)) = packets.get(&i) {
                assert_eq!(&hex(&sig), want_sig, "method {method} {dir} signature {i}");
                assert_eq!(&hex(&ct), want_ct, "method {method} {dir} ciphertext {i}");
            }
            all.extend_from_slice(&sig);
            all.extend_from_slice(&ct);
            assert_eq!(receiver.unprotect(&sig, &ct, salted).unwrap(), plain);
        }
        assert_eq!(
            md5(&all).to_vec(),
            total,
            "method {method} {dir} all packets"
        );
    }

    #[test]
    fn client_to_server_traffic_matches_freerdp_at_every_strength() {
        for (wire, method) in METHODS {
            assert_traffic(wire, "c2s", &mut client(method), &mut server_of(method));
        }
    }

    #[test]
    fn server_to_client_traffic_matches_freerdp_at_every_strength() {
        for (wire, method) in METHODS {
            assert_traffic(wire, "s2c", &mut server_of(method), &mut client(method));
        }
    }

    /// `[MS-RDPBCGR]` 4.8's sample key.
    const SPEC_MODULUS_LE: &str = "37a870fe9ab9a854cb9879447ab9eb3806ea26a147ea19705df352887021b59e\
                                   50b4e1f51ad82d514d1aad797c8946b0cc667402d8285d9dd7cafc600f38f9b3";

    fn spec_key() -> RsaPublicKey {
        let mut modulus = unhex(SPEC_MODULUS_LE);
        modulus.reverse();
        RsaPublicKey {
            modulus,
            exponent: 0x10001,
        }
    }

    #[test]
    fn the_client_random_encrypts_to_the_spec_keys_value() {
        let mut random = [0u8; 32];
        random[0] = 0xff;
        random[1] = 0xee;
        random[31] = 0xff;
        let encrypted = encrypt_client_random(&ClientRandom::new(random), &spec_key()).unwrap();
        assert_eq!(
            hex(&encrypted),
            "c0129666be28607bb0b403feda386ab9399d10a276b88b4ce4259a229ee00134\
             d4c13738b7ef500955c5b335179ebd9e45933cd85de67ca9c3702e18f2237109\
             0000000000000000"
        );
    }

    /// 1^e mod n is 1, whose little-endian form ends in zeros a trimming encoder would drop.
    #[test]
    fn a_small_encrypted_random_still_fills_the_buffer() {
        let mut random = [0u8; 32];
        random[0] = 1;
        let encrypted = encrypt_client_random(&ClientRandom::new(random), &spec_key()).unwrap();
        assert_eq!(encrypted.len(), 72);
        assert_eq!(encrypted[0], 1);
        assert!(encrypted[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn an_unusable_public_key_is_refused() {
        let random = ClientRandom::new([1; 32]);
        for modulus in [vec![], vec![0; 64], vec![0xFF; MAX_MODULUS_SIZE + 1]] {
            let key = RsaPublicKey {
                modulus,
                exponent: u32::MAX,
            };
            assert_eq!(
                encrypt_client_random(&random, &key),
                Err(StandardSecurityError::InvalidPublicKey)
            );
        }
    }

    /// `[MS-RDPBCGR]` 4.1.9's annotated PDU, from the basic security header on.
    #[test]
    fn the_security_exchange_pdu_has_the_spec_dumps_layout() {
        let encrypted = unhex(
            "91ac0c8f648c39f4e7ff0a3b79115c13512acb728f9db7422ef7084c8eae5599\
             62d28181e466c805ead473063fc85faf2afdfcf164b33f0a151ddb2c109d3011\
             0000000000000000",
        );
        assert_eq!(
            hex(&encode_security_exchange(&encrypted)),
            format!("0102000048000000{}", hex(&encrypted))
        );
    }

    #[test]
    fn a_fips_or_unknown_method_or_level_is_a_typed_refusal() {
        assert_eq!(
            EncryptionMethod::from_wire(0x10),
            Err(StandardSecurityError::UnsupportedMethod(0x10))
        );
        assert_eq!(
            EncryptionLevel::from_wire(4),
            Err(StandardSecurityError::UnsupportedLevel(4))
        );
        assert_eq!(
            EncryptionLevel::from_wire(0),
            Err(StandardSecurityError::UnsupportedLevel(0))
        );
    }

    #[test]
    fn a_server_random_of_the_wrong_length_is_refused() {
        let (client, _) = randoms();
        let error = StandardSecurity::new(
            EncryptionMethod::Rc4Bit128,
            EncryptionLevel::High,
            &client,
            &[0; 31],
        )
        .unwrap_err();
        assert_eq!(error, StandardSecurityError::ServerRandomLength(31));
    }

    #[test]
    fn a_wrong_mac_is_a_failure_in_every_form() {
        let method = EncryptionMethod::Rc4Bit128;
        let (sig, ct) = server_of(method).protect(b"hello", false);

        let mut bad_sig = sig;
        bad_sig[7] ^= 1;
        assert_eq!(
            client(method).unprotect(&bad_sig, &ct, false),
            Err(StandardSecurityError::MacMismatch)
        );

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert_eq!(
            client(method).unprotect(&sig, &bad_ct, false),
            Err(StandardSecurityError::MacMismatch)
        );

        // A MAC made salted does not pass as unsalted, or the other way round.
        assert_eq!(
            client(method).unprotect(&sig, &ct, true),
            Err(StandardSecurityError::MacMismatch)
        );

        let mut slow = server_of(method).protect_slow_path(0, b"hello");
        slow[4] ^= 1;
        assert_eq!(
            client(method).unprotect_slow_path(&slow),
            Err(StandardSecurityError::MacMismatch)
        );

        let mut fast = sig.to_vec();
        fast.extend_from_slice(&bad_ct);
        assert_eq!(
            client(method).unprotect_fast_path(FASTPATH_ENCRYPTED, &fast),
            Err(StandardSecurityError::MacMismatch)
        );
        assert_eq!(
            client(method).unprotect(&sig, &ct, false).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn a_slow_path_pdu_round_trips_with_its_flags() {
        let method = EncryptionMethod::Rc4Bit128;
        let (mut sender, mut receiver) = (server_of(method), client(method));
        for (salted, checksum) in [(false, 0), (true, SEC_SECURE_CHECKSUM)] {
            sender.set_salted_mac(salted);
            let bytes = sender.protect_slow_path(SEC_INFO_PKT, b"payload");
            assert_eq!(
                u16::from_le_bytes([bytes[0], bytes[1]]),
                SEC_INFO_PKT | SEC_ENCRYPT | checksum
            );
            assert_eq!(&bytes[2..4], [0, 0]);
            assert_eq!(bytes.len(), 12 + 7);
            let pdu = receiver.unprotect_slow_path(&bytes).unwrap();
            assert_eq!(pdu.flags, SEC_INFO_PKT | SEC_ENCRYPT | checksum);
            assert_eq!(pdu.payload, b"payload");
        }
    }

    #[test]
    fn a_fast_path_body_round_trips_with_its_flags() {
        let method = EncryptionMethod::Rc4Bit128;
        let (mut sender, mut receiver) = (server_of(method), client(method));
        for (salted, flags) in [
            (false, FASTPATH_ENCRYPTED),
            (true, FASTPATH_ENCRYPTED | FASTPATH_SECURE_CHECKSUM),
        ] {
            sender.set_salted_mac(salted);
            let protected = sender.protect_fast_path(b"update");
            assert_eq!(protected.header_flags, flags);
            assert_eq!(protected.body.len(), 8 + 6);
            assert_eq!(
                receiver
                    .unprotect_fast_path(protected.header_flags, &protected.body)
                    .unwrap(),
                b"update"
            );
        }
    }

    fn at_level(level: EncryptionLevel) -> StandardSecurity {
        let (client, server) = randoms();
        StandardSecurity::new(EncryptionMethod::Rc4Bit128, level, &client, &server).unwrap()
    }

    #[test]
    fn stripping_the_encryption_is_refused_where_the_server_must_encrypt() {
        let clear = [SEC_INFO_PKT.to_le_bytes().as_slice(), &[0, 0], b"x"].concat();
        for level in [EncryptionLevel::ClientCompatible, EncryptionLevel::High] {
            assert_eq!(
                at_level(level).unprotect_slow_path(&clear),
                Err(StandardSecurityError::NotEncrypted)
            );
            assert_eq!(
                at_level(level).unprotect_fast_path(0, b"x"),
                Err(StandardSecurityError::NotEncrypted)
            );
        }
        let mut low = at_level(EncryptionLevel::Low);
        assert_eq!(low.unprotect_slow_path(&clear).unwrap().payload, b"x");
        assert_eq!(low.unprotect_fast_path(0, b"x").unwrap(), b"x");
    }

    #[test]
    fn the_pdus_the_spec_allows_in_the_clear_stay_readable_at_any_level() {
        for flag in [
            SEC_LICENSE_PKT,
            SEC_AUTODETECT_REQ,
            SEC_TRANSPORT_REQ,
            SEC_HEARTBEAT,
        ] {
            let clear = [flag.to_le_bytes().as_slice(), &[0, 0], b"pdu"].concat();
            let pdu = at_level(EncryptionLevel::High)
                .unprotect_slow_path(&clear)
                .unwrap();
            assert_eq!(pdu.flags, flag);
            assert_eq!(pdu.payload, b"pdu");
        }
    }

    #[test]
    fn a_redirection_pdu_is_decrypted_with_or_without_sec_encrypt() {
        let method = EncryptionMethod::Rc4Bit128;
        let mut sender = server_of(method);
        let mut bytes = sender.protect_slow_path(SEC_REDIRECTION_PKT, b"route");
        bytes[..2].copy_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        let pdu = client(method).unprotect_slow_path(&bytes).unwrap();
        assert_eq!(pdu.flags, SEC_REDIRECTION_PKT);
        assert_eq!(pdu.payload, b"route");
    }

    #[test]
    fn a_decrypted_payload_does_not_reach_debug() {
        let pdu = SlowPathPdu {
            flags: 0,
            payload: vec![0xAB; 4],
        };
        let text = format!("{pdu:?}");
        assert!(text.contains("payload_len: 4"), "{text}");
        assert!(!text.contains("171"), "{text}");
    }

    #[test]
    fn no_secret_reaches_debug_or_an_error() {
        let (random, server) = randoms();
        let mut security = client(EncryptionMethod::Rc4Bit128);
        let keys = [
            hex(&security.mac_key),
            hex(&security.outbound.current),
            hex(&security.inbound.current),
            hex(random.as_bytes()),
        ];
        let (sig, ct) = security.protect(b"secret", false);
        let error = security.unprotect(&sig, &ct, false).unwrap_err();
        let texts = [
            format!("{security:?}"),
            format!("{random:?}"),
            format!("{:?}", security.outbound.rc4),
            format!("{error:?}"),
            error.to_string(),
        ];
        let _ = server;
        for text in texts {
            let lower = text.to_lowercase();
            assert!(keys.iter().all(|key| !lower.contains(key)), "{text}");
            let digits = lower.chars().filter(char::is_ascii_hexdigit).count();
            assert!(digits < 32, "{text}");
        }
    }

    proptest! {
        #[test]
        fn unprotect_slow_path_never_panics_on_arbitrary_input(
            bytes in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let _ = client(EncryptionMethod::Rc4Bit128).unprotect_slow_path(&bytes);
        }

        #[test]
        fn unprotect_slow_path_reaches_the_mac_when_the_flag_is_set(
            body in proptest::collection::vec(any::<u8>(), 8..=64),
        ) {
            let bytes = [SEC_ENCRYPT.to_le_bytes().as_slice(), &[0, 0], &body].concat();
            prop_assert_eq!(
                client(EncryptionMethod::Rc4Bit128).unprotect_slow_path(&bytes),
                Err(StandardSecurityError::MacMismatch)
            );
        }

        #[test]
        fn unprotect_fast_path_never_panics_on_arbitrary_input(
            flags in any::<u8>(),
            body in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let _ = client(EncryptionMethod::Rc4Bit128).unprotect_fast_path(flags, &body);
        }
    }
}
