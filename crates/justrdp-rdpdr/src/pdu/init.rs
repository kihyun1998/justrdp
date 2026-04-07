#![forbid(unsafe_code)]

//! Initialization Exchange PDUs -- MS-RDPEFS 2.2.2
//!
//! PDU bodies for the initialization sequence (header is decoded separately):
//! - Server Announce Request (2.2.2.2)
//! - Client Announce Reply (2.2.2.3)
//! - Client Name Request (2.2.2.4)
//! - Server Client ID Confirm (2.2.2.6)
//! - User Logged On (2.2.2.5)

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult};

// ── Version PDU (shared wire format) ────────────────────────────────────────

/// Version and client ID PDU body -- MS-RDPEFS 2.2.2.2 / 2.2.2.3 / 2.2.2.6
///
/// Shared 8-byte wire format used by Server Announce Request, Client Announce
/// Reply, and Server Client ID Confirm.
///
/// ```text
/// ┌───────────────┬───────────────┬───────────────┐
/// │ VersionMajor  │ VersionMinor  │ ClientId      │
/// │ (2 bytes)     │ (2 bytes)     │ (4 bytes)     │
/// └───────────────┴───────────────┴───────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPdu {
    /// Major version number. MUST be 0x0001.
    pub version_major: u16,
    /// Minor version number.
    pub version_minor: u16,
    /// Client identifier.
    pub client_id: u32,
}

/// Size of the VersionPdu on the wire.
const VERSION_PDU_SIZE: usize = 2 + 2 + 4; // 8 bytes

/// DR_CORE_SERVER_ANNOUNCE_REQ -- MS-RDPEFS 2.2.2.2
pub type ServerAnnounceRequest = VersionPdu;

/// DR_CORE_CLIENT_ANNOUNCE_RSP -- MS-RDPEFS 2.2.2.3
pub type ClientAnnounceReply = VersionPdu;

/// DR_CORE_SERVER_CLIENTID_CONFIRM -- MS-RDPEFS 2.2.2.6
pub type ServerClientIdConfirm = VersionPdu;

impl Encode for VersionPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.version_major, "VersionPdu::VersionMajor")?;
        dst.write_u16_le(self.version_minor, "VersionPdu::VersionMinor")?;
        dst.write_u32_le(self.client_id, "VersionPdu::ClientId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "VersionPdu"
    }

    fn size(&self) -> usize {
        VERSION_PDU_SIZE
    }
}

impl<'de> Decode<'de> for VersionPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let version_major = src.read_u16_le("VersionPdu::VersionMajor")?;
        let version_minor = src.read_u16_le("VersionPdu::VersionMinor")?;
        let client_id = src.read_u32_le("VersionPdu::ClientId")?;

        Ok(Self {
            version_major,
            version_minor,
            client_id,
        })
    }
}

// ── Client Name Request ─────────────────────────────────────────────────────

/// Unicode flag value -- MS-RDPEFS 2.2.2.4
const UNICODE_FLAG: u32 = 0x0000_0001;

/// DR_CORE_CLIENT_NAME_REQ -- MS-RDPEFS 2.2.2.4
///
/// ```text
/// ┌──────────────┬──────────────┬─────────────────┬──────────────┐
/// │ UnicodeFlag  │ CodePage     │ ComputerNameLen │ ComputerName │
/// │ (4 bytes)    │ (4 bytes)    │ (4 bytes)       │ (variable)   │
/// └──────────────┴──────────────┴─────────────────┴──────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNameRequest {
    /// If true, ComputerName is encoded as UTF-16LE; otherwise ASCII.
    pub unicode: bool,
    /// Client computer name (without null terminator).
    pub computer_name: String,
}

impl ClientNameRequest {
    /// Fixed-size portion: UnicodeFlag (4) + CodePage (4) + ComputerNameLen (4).
    const FIXED_SIZE: usize = 4 + 4 + 4;

    /// Compute the byte length of the computer name including null terminator.
    fn computer_name_wire_len(&self) -> usize {
        if self.unicode {
            // UTF-16LE code units + 2-byte null terminator
            let code_units: usize = self.computer_name.encode_utf16().count();
            (code_units + 1) * 2
        } else {
            // ASCII bytes + 1-byte null terminator
            self.computer_name.len() + 1
        }
    }
}

impl Encode for ClientNameRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let unicode_flag: u32 = if self.unicode { UNICODE_FLAG } else { 0 };
        dst.write_u32_le(unicode_flag, "ClientNameRequest::UnicodeFlag")?;
        dst.write_u32_le(0, "ClientNameRequest::CodePage")?; // MUST be 0

        let name_bytes = if self.unicode {
            encode_utf16le(&self.computer_name)
        } else {
            encode_ascii(&self.computer_name)
        };

        dst.write_u32_le(name_bytes.len() as u32, "ClientNameRequest::ComputerNameLen")?;
        dst.write_slice(&name_bytes, "ClientNameRequest::ComputerName")?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ClientNameRequest"
    }

    fn size(&self) -> usize {
        Self::FIXED_SIZE + self.computer_name_wire_len()
    }
}

impl<'de> Decode<'de> for ClientNameRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let unicode_flag = src.read_u32_le("ClientNameRequest::UnicodeFlag")?;
        let unicode = match unicode_flag {
            UNICODE_FLAG => true,
            0 => false,
            _ => return Err(DecodeError::invalid_value("ClientNameRequest", "UnicodeFlag")),
        };

        let _code_page = src.read_u32_le("ClientNameRequest::CodePage")?;

        let computer_name_len_raw = src.read_u32_le("ClientNameRequest::ComputerNameLen")?;
        // Max 520 bytes: 260 UTF-16LE chars (MAX_COMPUTERNAME_LENGTH + 1) × 2
        if computer_name_len_raw > 520 {
            return Err(DecodeError::invalid_value(
                "ClientNameRequest",
                "ComputerNameLen",
            ));
        }
        let computer_name_len = computer_name_len_raw as usize;
        let name_data = src.read_slice(computer_name_len, "ClientNameRequest::ComputerName")?;

        let computer_name = if unicode {
            decode_utf16le(name_data)
        } else {
            decode_ascii(name_data)
        };

        Ok(Self {
            unicode,
            computer_name,
        })
    }
}

// ── User Logged On ──────────────────────────────────────────────────────────

/// DR_CORE_USER_LOGGEDON -- MS-RDPEFS 2.2.2.5
///
/// Empty PDU body (only the shared header is sent on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserLoggedOnPdu;

impl Encode for UserLoggedOnPdu {
    fn encode(&self, _dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "UserLoggedOnPdu"
    }

    fn size(&self) -> usize {
        0
    }
}

impl<'de> Decode<'de> for UserLoggedOnPdu {
    fn decode(_src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        Ok(Self)
    }
}

// ── UTF-16LE / ASCII helpers ────────────────────────────────────────────────

use super::util::decode_utf16le;

/// Encode a string as UTF-16LE with a 2-byte null terminator.
fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for code_unit in s.encode_utf16() {
        buf.extend_from_slice(&code_unit.to_le_bytes());
    }
    // Null terminator (U+0000 as UTF-16LE)
    buf.extend_from_slice(&[0x00, 0x00]);
    buf
}

/// Encode a string as ASCII bytes with a 1-byte null terminator.
///
/// Non-ASCII characters are replaced with `?`.
fn encode_ascii(s: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = s.bytes().map(|b| if b > 0x7F { b'?' } else { b }).collect();
    buf.push(0x00); // null terminator
    buf
}

/// Decode ASCII bytes (possibly null-terminated) into a String.
///
/// Non-ASCII bytes (> 0x7F) are replaced with `?` to match `encode_ascii`.
fn decode_ascii(data: &[u8]) -> String {
    let s: String = data
        .iter()
        .map(|&b| if b > 0x7F { '?' } else { b as char })
        .collect();
    s.trim_end_matches('\0').into()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── VersionPdu ──────────────────────────────────────────────────────

    #[test]
    fn version_pdu_roundtrip() {
        let pdu = VersionPdu {
            version_major: 0x0001,
            version_minor: 0x000C,
            client_id: 0xDEAD_BEEF,
        };
        assert_eq!(pdu.size(), VERSION_PDU_SIZE);

        let mut buf = [0u8; VERSION_PDU_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = VersionPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn version_pdu_known_bytes() {
        // VersionMajor=0x0001, VersionMinor=0x000D, ClientId=0x00000001
        #[rustfmt::skip]
        let bytes: [u8; 8] = [
            0x01, 0x00, // VersionMajor (LE)
            0x0D, 0x00, // VersionMinor (LE)
            0x01, 0x00, 0x00, 0x00, // ClientId (LE)
        ];
        let mut cursor = ReadCursor::new(&bytes);
        let pdu = VersionPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu.version_major, 0x0001);
        assert_eq!(pdu.version_minor, 0x000D);
        assert_eq!(pdu.client_id, 1);
    }

    // ── ClientNameRequest (Unicode) ─────────────────────────────────────

    #[test]
    fn client_name_request_unicode_roundtrip() {
        let pdu = ClientNameRequest {
            unicode: true,
            computer_name: String::from("DESKTOP-RDP"),
        };

        let size = pdu.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientNameRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn client_name_request_ascii_roundtrip() {
        let pdu = ClientNameRequest {
            unicode: false,
            computer_name: String::from("TESTPC"),
        };

        let size = pdu.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientNameRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn client_name_request_unicode_known_bytes() {
        // "AB" in UTF-16LE + null = [0x41, 0x00, 0x42, 0x00, 0x00, 0x00] (6 bytes)
        #[rustfmt::skip]
        let bytes: [u8; 18] = [
            0x01, 0x00, 0x00, 0x00, // UnicodeFlag = 1
            0x00, 0x00, 0x00, 0x00, // CodePage = 0
            0x06, 0x00, 0x00, 0x00, // ComputerNameLen = 6
            0x41, 0x00,             // 'A'
            0x42, 0x00,             // 'B'
            0x00, 0x00,             // null terminator
        ];
        let mut cursor = ReadCursor::new(&bytes);
        let pdu = ClientNameRequest::decode(&mut cursor).unwrap();
        assert!(pdu.unicode);
        assert_eq!(pdu.computer_name, "AB");
    }

    #[test]
    fn client_name_request_ascii_known_bytes() {
        // "AB" in ASCII + null = [0x41, 0x42, 0x00] (3 bytes)
        #[rustfmt::skip]
        let bytes: [u8; 15] = [
            0x00, 0x00, 0x00, 0x00, // UnicodeFlag = 0
            0x00, 0x00, 0x00, 0x00, // CodePage = 0
            0x03, 0x00, 0x00, 0x00, // ComputerNameLen = 3
            0x41, 0x42, 0x00,       // "AB\0"
        ];
        let mut cursor = ReadCursor::new(&bytes);
        let pdu = ClientNameRequest::decode(&mut cursor).unwrap();
        assert!(!pdu.unicode);
        assert_eq!(pdu.computer_name, "AB");
    }

    #[test]
    fn client_name_request_empty_name_unicode() {
        let pdu = ClientNameRequest {
            unicode: true,
            computer_name: String::new(),
        };
        // size = 12 (fixed) + 2 (null terminator only)
        assert_eq!(pdu.size(), 14);

        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientNameRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.computer_name, "");
    }

    #[test]
    fn client_name_request_empty_name_ascii() {
        let pdu = ClientNameRequest {
            unicode: false,
            computer_name: String::new(),
        };
        // size = 12 (fixed) + 1 (null terminator only)
        assert_eq!(pdu.size(), 13);

        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientNameRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.computer_name, "");
    }

    // ── UserLoggedOnPdu ─────────────────────────────────────────────────

    #[test]
    fn user_logged_on_roundtrip() {
        let pdu = UserLoggedOnPdu;
        assert_eq!(pdu.size(), 0);

        let mut buf = [0u8; 0];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&[]);
        let decoded = UserLoggedOnPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded, pdu);
    }
}
