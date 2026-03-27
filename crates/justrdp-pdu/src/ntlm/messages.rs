#![forbid(unsafe_code)]

//! NTLM message types (MS-NLMP 2.2).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor};

use super::{NTLMSSP_SIGNATURE, NTLM_AUTHENTICATE, NTLM_CHALLENGE, NTLM_NEGOTIATE};

// ── Negotiate Flags (MS-NLMP 2.2.2.5) ──

/// NTLM negotiate flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiateFlags(u32);

impl NegotiateFlags {
    pub const NEGOTIATE_UNICODE: Self = Self(0x00000001);
    pub const NEGOTIATE_OEM: Self = Self(0x00000002);
    pub const REQUEST_TARGET: Self = Self(0x00000004);
    pub const NEGOTIATE_SIGN: Self = Self(0x00000010);
    pub const NEGOTIATE_SEAL: Self = Self(0x00000020);
    pub const NEGOTIATE_DATAGRAM: Self = Self(0x00000040);
    pub const NEGOTIATE_LM_KEY: Self = Self(0x00000080);
    pub const NEGOTIATE_NTLM: Self = Self(0x00000200);
    pub const NEGOTIATE_ANONYMOUS: Self = Self(0x00000800);
    pub const NEGOTIATE_OEM_DOMAIN_SUPPLIED: Self = Self(0x00001000);
    pub const NEGOTIATE_OEM_WORKSTATION_SUPPLIED: Self = Self(0x00002000);
    pub const NEGOTIATE_ALWAYS_SIGN: Self = Self(0x00008000);
    pub const TARGET_TYPE_DOMAIN: Self = Self(0x00010000);
    pub const TARGET_TYPE_SERVER: Self = Self(0x00020000);
    pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: Self = Self(0x00080000);
    pub const NEGOTIATE_IDENTIFY: Self = Self(0x00100000);
    pub const REQUEST_NON_NT_SESSION_KEY: Self = Self(0x00400000);
    pub const NEGOTIATE_TARGET_INFO: Self = Self(0x00800000);
    pub const NEGOTIATE_VERSION: Self = Self(0x02000000);
    pub const NEGOTIATE_128: Self = Self(0x20000000);
    pub const NEGOTIATE_KEY_EXCH: Self = Self(0x40000000);
    pub const NEGOTIATE_56: Self = Self(0x80000000);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Standard flags for NTLMv2 client negotiate message.
    pub fn client_default() -> Self {
        Self::NEGOTIATE_UNICODE
            .union(Self::REQUEST_TARGET)
            .union(Self::NEGOTIATE_NTLM)
            .union(Self::NEGOTIATE_ALWAYS_SIGN)
            .union(Self::NEGOTIATE_EXTENDED_SESSIONSECURITY)
            .union(Self::NEGOTIATE_TARGET_INFO)
            .union(Self::NEGOTIATE_VERSION)
            .union(Self::NEGOTIATE_128)
            .union(Self::NEGOTIATE_KEY_EXCH)
            .union(Self::NEGOTIATE_56)
            .union(Self::NEGOTIATE_SEAL)
            .union(Self::NEGOTIATE_SIGN)
    }
}

// ── AV_PAIR (MS-NLMP 2.2.2.1) ──

/// AV_PAIR identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AvId {
    MsvAvEOL = 0x0000,
    MsvAvNbComputerName = 0x0001,
    MsvAvNbDomainName = 0x0002,
    MsvAvDnsComputerName = 0x0003,
    MsvAvDnsDomainName = 0x0004,
    MsvAvDnsTreeName = 0x0005,
    MsvAvFlags = 0x0006,
    MsvAvTimestamp = 0x0007,
    MsvAvSingleHost = 0x0008,
    MsvAvTargetName = 0x0009,
    MsvAvChannelBindings = 0x000A,
}

impl AvId {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::MsvAvEOL),
            1 => Some(Self::MsvAvNbComputerName),
            2 => Some(Self::MsvAvNbDomainName),
            3 => Some(Self::MsvAvDnsComputerName),
            4 => Some(Self::MsvAvDnsDomainName),
            5 => Some(Self::MsvAvDnsTreeName),
            6 => Some(Self::MsvAvFlags),
            7 => Some(Self::MsvAvTimestamp),
            8 => Some(Self::MsvAvSingleHost),
            9 => Some(Self::MsvAvTargetName),
            10 => Some(Self::MsvAvChannelBindings),
            _ => None,
        }
    }
}

/// An AV_PAIR entry from target info.
#[derive(Debug, Clone)]
pub struct AvPair {
    pub id: u16,
    pub value: Vec<u8>,
}

impl AvPair {
    pub fn new(id: AvId, value: Vec<u8>) -> Self {
        Self {
            id: id as u16,
            value,
        }
    }

    /// Parse AV_PAIR list from raw bytes.
    pub fn parse_list(data: &[u8]) -> DecodeResult<Vec<Self>> {
        let mut cursor = ReadCursor::new(data);
        let mut pairs = Vec::new();

        loop {
            if cursor.len() < 4 {
                break;
            }
            let id = cursor.read_u16_le("AvPair::id")?;
            let len = cursor.read_u16_le("AvPair::len")? as usize;

            if id == AvId::MsvAvEOL as u16 {
                break;
            }

            let value = cursor.read_slice(len, "AvPair::value")?.to_vec();
            pairs.push(AvPair { id, value });
        }

        Ok(pairs)
    }

    /// Encode AV_PAIR list to bytes (including MsvAvEOL terminator).
    pub fn encode_list(pairs: &[AvPair]) -> Vec<u8> {
        let mut size = 4; // EOL terminator
        for p in pairs {
            size += 4 + p.value.len();
        }

        let mut buf = vec![0u8; size];
        let mut offset = 0;

        for p in pairs {
            buf[offset..offset + 2].copy_from_slice(&p.id.to_le_bytes());
            buf[offset + 2..offset + 4].copy_from_slice(&(p.value.len() as u16).to_le_bytes());
            buf[offset + 4..offset + 4 + p.value.len()].copy_from_slice(&p.value);
            offset += 4 + p.value.len();
        }

        // EOL
        buf[offset..offset + 4].copy_from_slice(&[0, 0, 0, 0]);

        buf
    }

    /// Find a specific AV_PAIR by ID.
    pub fn find(pairs: &[AvPair], id: AvId) -> Option<&AvPair> {
        pairs.iter().find(|p| p.id == id as u16)
    }
}

// ── NTLM Version (MS-NLMP 2.2.2.10) ──

/// NTLM Version structure (8 bytes).
#[derive(Debug, Clone, Copy)]
pub struct NtlmVersion {
    pub major: u8,
    pub minor: u8,
    pub build: u16,
    pub revision: u8,
}

impl NtlmVersion {
    /// Windows 10/11 version for client identification.
    pub fn windows_10() -> Self {
        Self {
            major: 10,
            minor: 0,
            build: 22621, // Windows 11 22H2
            revision: 15,
        }
    }

    pub fn encode(&self, cursor: &mut WriteCursor<'_>) -> EncodeResult<()> {
        cursor.write_u8(self.major, "Version::major")?;
        cursor.write_u8(self.minor, "Version::minor")?;
        cursor.write_u16_le(self.build, "Version::build")?;
        cursor.write_u8(0, "Version::reserved1")?;
        cursor.write_u8(0, "Version::reserved2")?;
        cursor.write_u8(0, "Version::reserved3")?;
        cursor.write_u8(self.revision, "Version::revision")?;
        Ok(())
    }

    pub fn decode(cursor: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let major = cursor.read_u8("Version::major")?;
        let minor = cursor.read_u8("Version::minor")?;
        let build = cursor.read_u16_le("Version::build")?;
        let _ = cursor.read_u8("Version::reserved1")?;
        let _ = cursor.read_u8("Version::reserved2")?;
        let _ = cursor.read_u8("Version::reserved3")?;
        let revision = cursor.read_u8("Version::revision")?;
        Ok(Self {
            major,
            minor,
            build,
            revision,
        })
    }
}

// ── NEGOTIATE_MESSAGE (MS-NLMP 2.2.1.1) ──

/// NTLM Negotiate message (Type 1).
#[derive(Debug, Clone)]
pub struct NegotiateMessage {
    pub flags: NegotiateFlags,
    pub domain_name: String,
    pub workstation: String,
    pub version: Option<NtlmVersion>,
}

impl NegotiateMessage {
    /// Create a standard NTLMv2 negotiate message.
    pub fn new() -> Self {
        Self {
            flags: NegotiateFlags::client_default(),
            domain_name: String::new(),
            workstation: String::new(),
            version: Some(NtlmVersion::windows_10()),
        }
    }
}

impl Encode for NegotiateMessage {
    fn name(&self) -> &'static str {
        "NTLM_NEGOTIATE"
    }

    fn size(&self) -> usize {
        // Signature(8) + MessageType(4) + NegotiateFlags(4) +
        // DomainNameFields(8) + WorkstationFields(8) = 32
        // + Version(8) only if NEGOTIATE_VERSION flag is set
        // + domain payload + workstation payload
        let header_size = if self.version.is_some() { 40 } else { 32 };
        let domain_bytes = self.domain_name.as_bytes();
        let workstation_bytes = self.workstation.as_bytes();
        header_size + domain_bytes.len() + workstation_bytes.len()
    }

    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_slice(NTLMSSP_SIGNATURE, "NTLMSSP_SIGNATURE")?;
        dst.write_u32_le(NTLM_NEGOTIATE, "MessageType")?;
        dst.write_u32_le(self.flags.bits(), "NegotiateFlags")?;

        let payload_offset: u32 = if self.version.is_some() { 40 } else { 32 };
        let domain_bytes = self.domain_name.as_bytes();
        let workstation_bytes = self.workstation.as_bytes();

        // DomainNameFields: Len(2) + MaxLen(2) + Offset(4)
        let domain_offset = payload_offset;
        dst.write_u16_le(domain_bytes.len() as u16, "DomainName::Len")?;
        dst.write_u16_le(domain_bytes.len() as u16, "DomainName::MaxLen")?;
        dst.write_u32_le(domain_offset, "DomainName::Offset")?;

        // WorkstationFields
        let workstation_offset = domain_offset + domain_bytes.len() as u32;
        dst.write_u16_le(workstation_bytes.len() as u16, "Workstation::Len")?;
        dst.write_u16_le(workstation_bytes.len() as u16, "Workstation::MaxLen")?;
        dst.write_u32_le(workstation_offset, "Workstation::Offset")?;

        // Version (only if NEGOTIATE_VERSION flag is set)
        if let Some(ref ver) = self.version {
            ver.encode(dst)?;
        }

        // Payload
        if !domain_bytes.is_empty() {
            dst.write_slice(domain_bytes, "DomainName::payload")?;
        }
        if !workstation_bytes.is_empty() {
            dst.write_slice(workstation_bytes, "Workstation::payload")?;
        }

        Ok(())
    }
}

// ── CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2) ──

/// NTLM Challenge message (Type 2).
#[derive(Debug, Clone)]
pub struct ChallengeMessage {
    pub flags: NegotiateFlags,
    pub server_challenge: [u8; 8],
    pub target_name: Vec<u8>,
    pub target_info: Vec<u8>,
    pub version: Option<NtlmVersion>,
}

impl ChallengeMessage {
    /// Decode a Challenge message from raw bytes (after NTLMSSP signature + type).
    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut cursor = ReadCursor::new(data);

        // Verify signature
        let sig = cursor.read_slice(8, "Signature")?;
        if sig != NTLMSSP_SIGNATURE {
            return Err(justrdp_core::DecodeError::new(
                "NTLM_CHALLENGE",
                justrdp_core::DecodeErrorKind::InvalidValue {
                    field: "Signature",
                },
            ));
        }

        let msg_type = cursor.read_u32_le("MessageType")?;
        if msg_type != NTLM_CHALLENGE {
            return Err(justrdp_core::DecodeError::new(
                "NTLM_CHALLENGE",
                justrdp_core::DecodeErrorKind::UnexpectedValue {
                    field: "MessageType",
                    got: "not NTLM_CHALLENGE",
                },
            ));
        }

        // TargetNameFields
        let target_name_len = cursor.read_u16_le("TargetName::Len")? as usize;
        let _target_name_max_len = cursor.read_u16_le("TargetName::MaxLen")?;
        let target_name_offset = cursor.read_u32_le("TargetName::Offset")? as usize;

        let flags = NegotiateFlags::from_bits(cursor.read_u32_le("NegotiateFlags")?);

        let mut server_challenge = [0u8; 8];
        let sc = cursor.read_slice(8, "ServerChallenge")?;
        server_challenge.copy_from_slice(sc);

        // Reserved (8 bytes)
        let _ = cursor.read_slice(8, "Reserved")?;

        // TargetInfoFields
        let target_info_len = cursor.read_u16_le("TargetInfo::Len")? as usize;
        let _target_info_max_len = cursor.read_u16_le("TargetInfo::MaxLen")?;
        let target_info_offset = cursor.read_u32_le("TargetInfo::Offset")? as usize;

        // Version (if NEGOTIATE_VERSION flag set)
        let version = if flags.contains(NegotiateFlags::NEGOTIATE_VERSION) {
            Some(NtlmVersion::decode(&mut cursor)?)
        } else {
            None
        };

        // Read payloads from offsets
        let target_name = if target_name_len > 0 && target_name_offset + target_name_len <= data.len() {
            data[target_name_offset..target_name_offset + target_name_len].to_vec()
        } else {
            Vec::new()
        };

        let target_info = if target_info_len > 0 && target_info_offset + target_info_len <= data.len() {
            data[target_info_offset..target_info_offset + target_info_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            flags,
            server_challenge,
            target_name,
            target_info,
            version,
        })
    }
}

// ── AUTHENTICATE_MESSAGE (MS-NLMP 2.2.1.3) ──

/// NTLM Authenticate message (Type 3).
///
/// The `version` field is always present in the wire format because
/// the MIC field (at offset 72) requires Version (at offset 64) to be
/// present to maintain correct offsets. Per MS-NLMP 2.2.1.3, Version
/// is present when NTLMSSP_NEGOTIATE_VERSION is set, and MIC requires it.
#[derive(Debug, Clone)]
pub struct AuthenticateMessage {
    pub flags: NegotiateFlags,
    pub lm_response: Vec<u8>,
    pub nt_response: Vec<u8>,
    pub domain_name: Vec<u8>,
    pub user_name: Vec<u8>,
    pub workstation: Vec<u8>,
    pub encrypted_random_session_key: Vec<u8>,
    /// NTLM version info (always encoded; required for correct MIC offset).
    pub version: NtlmVersion,
    /// 16-byte MIC (set after initial encode, then re-encoded).
    pub mic: [u8; 16],
}

impl AuthenticateMessage {
    /// Encode to bytes. The MIC field position is at offset 72..88.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_size = 88; // Up to and including MIC
        let payload_size = self.lm_response.len()
            + self.nt_response.len()
            + self.domain_name.len()
            + self.user_name.len()
            + self.workstation.len()
            + self.encrypted_random_session_key.len();
        let total = header_size + payload_size;
        let mut buf = vec![0u8; total];

        let mut offset = 0;

        // Signature
        buf[offset..offset + 8].copy_from_slice(NTLMSSP_SIGNATURE);
        offset += 8;

        // MessageType
        buf[offset..offset + 4].copy_from_slice(&NTLM_AUTHENTICATE.to_le_bytes());
        offset += 4;

        // Payload starts after the fixed header (88 bytes)
        let mut payload_offset = header_size as u32;

        // LmChallengeResponseFields
        let lm_len = self.lm_response.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&lm_len.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&lm_len.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&payload_offset.to_le_bytes());
        offset += 8;
        let lm_offset = payload_offset as usize;
        payload_offset += lm_len as u32;

        // NtChallengeResponseFields
        let nt_len = self.nt_response.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&nt_len.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&nt_len.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&payload_offset.to_le_bytes());
        offset += 8;
        let nt_offset = payload_offset as usize;
        payload_offset += nt_len as u32;

        // DomainNameFields
        let domain_len = self.domain_name.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&domain_len.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&domain_len.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&payload_offset.to_le_bytes());
        offset += 8;
        let domain_offset = payload_offset as usize;
        payload_offset += domain_len as u32;

        // UserNameFields
        let user_len = self.user_name.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&user_len.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&user_len.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&payload_offset.to_le_bytes());
        offset += 8;
        let user_offset = payload_offset as usize;
        payload_offset += user_len as u32;

        // WorkstationFields
        let ws_len = self.workstation.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&ws_len.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&ws_len.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&payload_offset.to_le_bytes());
        offset += 8;
        let ws_offset = payload_offset as usize;
        payload_offset += ws_len as u32;

        // EncryptedRandomSessionKeyFields
        let key_len = self.encrypted_random_session_key.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&key_len.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&key_len.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&payload_offset.to_le_bytes());
        offset += 8;
        let key_offset = payload_offset as usize;

        // NegotiateFlags
        buf[offset..offset + 4].copy_from_slice(&self.flags.bits().to_le_bytes());
        offset += 4;

        // Version (8 bytes, always present)
        {
            let mut ver_buf = [0u8; 8];
            let mut cursor = WriteCursor::new(&mut ver_buf);
            let _ = self.version.encode(&mut cursor);
            buf[offset..offset + 8].copy_from_slice(&ver_buf);
        }
        offset += 8;

        // MIC (16 bytes at offset 72)
        buf[offset..offset + 16].copy_from_slice(&self.mic);
        // offset += 16; // = 88 = header_size

        // Write payloads
        buf[lm_offset..lm_offset + self.lm_response.len()].copy_from_slice(&self.lm_response);
        buf[nt_offset..nt_offset + self.nt_response.len()].copy_from_slice(&self.nt_response);
        buf[domain_offset..domain_offset + self.domain_name.len()]
            .copy_from_slice(&self.domain_name);
        buf[user_offset..user_offset + self.user_name.len()].copy_from_slice(&self.user_name);
        buf[ws_offset..ws_offset + self.workstation.len()].copy_from_slice(&self.workstation);
        buf[key_offset..key_offset + self.encrypted_random_session_key.len()]
            .copy_from_slice(&self.encrypted_random_session_key);

        buf
    }

    /// The byte offset of the MIC field in the encoded message.
    pub const MIC_OFFSET: usize = 72;
}

/// Encode a string as UTF-16LE bytes.
pub fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_flags_operations() {
        let a = NegotiateFlags::NEGOTIATE_UNICODE;
        let b = NegotiateFlags::NEGOTIATE_NTLM;
        let c = a.union(b);
        assert!(c.contains(a));
        assert!(c.contains(b));
        assert!(!a.contains(b));
    }

    #[test]
    fn negotiate_message_encode() {
        let msg = NegotiateMessage::new();
        let size = msg.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        msg.encode(&mut cursor).unwrap();

        // Verify signature
        assert_eq!(&buf[0..8], NTLMSSP_SIGNATURE);
        // Verify message type
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), NTLM_NEGOTIATE);
    }

    #[test]
    fn av_pair_roundtrip() {
        let pairs = vec![
            AvPair::new(AvId::MsvAvNbDomainName, to_utf16le("DOMAIN")),
            AvPair::new(AvId::MsvAvNbComputerName, to_utf16le("SERVER")),
        ];

        let encoded = AvPair::encode_list(&pairs);
        let decoded = AvPair::parse_list(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].id, AvId::MsvAvNbDomainName as u16);
        assert_eq!(decoded[1].id, AvId::MsvAvNbComputerName as u16);
    }

    #[test]
    fn utf16le_encoding() {
        let result = to_utf16le("A");
        assert_eq!(result, &[0x41, 0x00]);
    }

    #[test]
    fn authenticate_message_mic_offset() {
        let msg = AuthenticateMessage {
            flags: NegotiateFlags::client_default(),
            lm_response: vec![0; 24],
            nt_response: vec![0; 24],
            domain_name: to_utf16le("DOMAIN"),
            user_name: to_utf16le("User"),
            workstation: to_utf16le("WORKSTATION"),
            encrypted_random_session_key: vec![0; 16],
            version: NtlmVersion::windows_10(),
            mic: [0xAA; 16],
        };

        let bytes = msg.to_bytes();
        // MIC at offset 72..88 should be our 0xAA bytes
        assert_eq!(&bytes[72..88], &[0xAA; 16]);
    }
}
