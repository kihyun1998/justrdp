#![forbid(unsafe_code)]

//! RDP Licensing PDUs -- MS-RDPELE
//!
//! Licensing PDUs are exchanged after the secure settings exchange.
//! In NLA/TLS connections, the server typically sends a single
//! LicenseErrorMessage with STATUS_VALID_CLIENT to skip licensing.

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

/// License preamble message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LicenseMsgType {
    LicenseRequest = 0x01,
    PlatformChallenge = 0x02,
    NewLicense = 0x03,
    UpgradeLicense = 0x04,
    LicenseInfo = 0x12,
    NewLicenseRequest = 0x13,
    PlatformChallengeResponse = 0x15,
    ErrorAlert = 0xFF,
}

impl LicenseMsgType {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            0x01 => Ok(Self::LicenseRequest),
            0x02 => Ok(Self::PlatformChallenge),
            0x03 => Ok(Self::NewLicense),
            0x04 => Ok(Self::UpgradeLicense),
            0x12 => Ok(Self::LicenseInfo),
            0x13 => Ok(Self::NewLicenseRequest),
            0x15 => Ok(Self::PlatformChallengeResponse),
            0xFF => Ok(Self::ErrorAlert),
            _ => Err(DecodeError::unexpected_value("LicenseMsgType", "type", "unknown license msg type")),
        }
    }
}

/// License preamble flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicenseFlags(u8);

impl LicenseFlags {
    pub const EXTENDED_ERROR_MSG_SUPPORTED: Self = Self(0x80);

    pub fn from_bits(bits: u8) -> Self { Self(bits) }
    pub fn bits(&self) -> u8 { self.0 }
}

/// License preamble header (4 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicensePreamble {
    pub msg_type: LicenseMsgType,
    pub flags: LicenseFlags,
    pub msg_size: u16,
}

pub const LICENSE_PREAMBLE_SIZE: usize = 4;

impl Encode for LicensePreamble {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(self.msg_type as u8, "LicensePreamble::msgType")?;
        dst.write_u8(self.flags.bits(), "LicensePreamble::flags")?;
        dst.write_u16_le(self.msg_size, "LicensePreamble::msgSize")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "LicensePreamble" }
    fn size(&self) -> usize { LICENSE_PREAMBLE_SIZE }
}

impl<'de> Decode<'de> for LicensePreamble {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let msg_type = LicenseMsgType::from_u8(src.read_u8("LicensePreamble::msgType")?)?;
        let flags = LicenseFlags::from_bits(src.read_u8("LicensePreamble::flags")?);
        let msg_size = src.read_u16_le("LicensePreamble::msgSize")?;
        Ok(Self { msg_type, flags, msg_size })
    }
}

/// License error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LicenseErrorCode {
    InvalidServerCertificate = 0x0001,
    NoLicense = 0x0002,
    InvalidScope = 0x0004,
    NoLicenseServer = 0x0006,
    StatusValidClient = 0x0007,
    InvalidClient = 0x0008,
    InvalidProductId = 0x000B,
    InvalidMessageLen = 0x000C,
}

impl LicenseErrorCode {
    pub fn from_u32(val: u32) -> DecodeResult<Self> {
        match val {
            0x0001 => Ok(Self::InvalidServerCertificate),
            0x0002 => Ok(Self::NoLicense),
            0x0004 => Ok(Self::InvalidScope),
            0x0006 => Ok(Self::NoLicenseServer),
            0x0007 => Ok(Self::StatusValidClient),
            0x0008 => Ok(Self::InvalidClient),
            0x000B => Ok(Self::InvalidProductId),
            0x000C => Ok(Self::InvalidMessageLen),
            _ => Err(DecodeError::unexpected_value("LicenseErrorCode", "code", "unknown error code")),
        }
    }
}

/// License state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LicenseStateTransition {
    TotalAbort = 0x0001,
    NoTransition = 0x0002,
    ResetPhaseToStart = 0x0003,
    ResendLastMessage = 0x0004,
}

impl LicenseStateTransition {
    pub fn from_u32(val: u32) -> DecodeResult<Self> {
        match val {
            0x0001 => Ok(Self::TotalAbort),
            0x0002 => Ok(Self::NoTransition),
            0x0003 => Ok(Self::ResetPhaseToStart),
            0x0004 => Ok(Self::ResendLastMessage),
            _ => Err(DecodeError::unexpected_value("LicenseStateTransition", "state", "unknown state")),
        }
    }
}

/// License Error Message (most common licensing PDU in NLA).
///
/// When the server sends STATUS_VALID_CLIENT, the licensing phase is complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseErrorMessage {
    pub preamble: LicensePreamble,
    pub error_code: LicenseErrorCode,
    pub state_transition: LicenseStateTransition,
    pub error_info: Vec<u8>,
}

impl LicenseErrorMessage {
    /// Create a STATUS_VALID_CLIENT message (licensing complete).
    pub fn valid_client() -> Self {
        Self {
            preamble: LicensePreamble {
                msg_type: LicenseMsgType::ErrorAlert,
                flags: LicenseFlags::EXTENDED_ERROR_MSG_SUPPORTED,
                msg_size: 16, // 4 preamble + 4 error + 4 state + 4 blob header
            },
            error_code: LicenseErrorCode::StatusValidClient,
            state_transition: LicenseStateTransition::NoTransition,
            error_info: Vec::new(),
        }
    }
}

/// License binary blob header.
const LICENSE_BLOB_HEADER_SIZE: usize = 4; // wBlobType(2) + wBlobLen(2)

impl Encode for LicenseErrorMessage {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.preamble.encode(dst)?;
        dst.write_u32_le(self.error_code as u32, "LicenseError::errorCode")?;
        dst.write_u32_le(self.state_transition as u32, "LicenseError::stateTransition")?;
        // Error info blob: wBlobType(2) + wBlobLen(2) + data
        dst.write_u16_le(0x0004, "LicenseError::blobType")?; // BB_ERROR_BLOB
        if self.error_info.len() > u16::MAX as usize {
            return Err(justrdp_core::EncodeError::other("LicenseError", "blobLen exceeds u16"));
        }
        dst.write_u16_le(self.error_info.len() as u16, "LicenseError::blobLen")?;
        if !self.error_info.is_empty() {
            dst.write_slice(&self.error_info, "LicenseError::blobData")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "LicenseErrorMessage" }

    fn size(&self) -> usize {
        LICENSE_PREAMBLE_SIZE + 4 + 4 + LICENSE_BLOB_HEADER_SIZE + self.error_info.len()
    }
}

impl<'de> Decode<'de> for LicenseErrorMessage {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let preamble = LicensePreamble::decode(src)?;
        let error_code = LicenseErrorCode::from_u32(src.read_u32_le("LicenseError::errorCode")?)?;
        let state_transition = LicenseStateTransition::from_u32(src.read_u32_le("LicenseError::stateTransition")?)?;
        let _blob_type = src.read_u16_le("LicenseError::blobType")?;
        let blob_len = src.read_u16_le("LicenseError::blobLen")? as usize;
        let error_info = if blob_len > 0 {
            src.read_slice(blob_len, "LicenseError::blobData")?.into()
        } else {
            Vec::new()
        };
        Ok(Self { preamble, error_code, state_transition, error_info })
    }
}

/// Generic license PDU (for types we don't fully parse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseGenericPdu {
    pub preamble: LicensePreamble,
    pub data: Vec<u8>,
}

impl Encode for LicenseGenericPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.preamble.encode(dst)?;
        dst.write_slice(&self.data, "LicenseGeneric::data")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "LicenseGenericPdu" }
    fn size(&self) -> usize { LICENSE_PREAMBLE_SIZE + self.data.len() }
}

impl<'de> Decode<'de> for LicenseGenericPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let preamble = LicensePreamble::decode(src)?;
        let data_len = (preamble.msg_size as usize).saturating_sub(LICENSE_PREAMBLE_SIZE);
        let data = src.read_slice(data_len, "LicenseGeneric::data")?.into();
        Ok(Self { preamble, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn license_error_valid_client_roundtrip() {
        let msg = LicenseErrorMessage::valid_client();
        let size = msg.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        msg.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = LicenseErrorMessage::decode(&mut cursor).unwrap();
        assert_eq!(decoded.error_code, LicenseErrorCode::StatusValidClient);
        assert_eq!(decoded.state_transition, LicenseStateTransition::NoTransition);
        assert!(decoded.error_info.is_empty());
    }

    #[test]
    fn license_preamble_roundtrip() {
        let pre = LicensePreamble {
            msg_type: LicenseMsgType::LicenseRequest,
            flags: LicenseFlags::EXTENDED_ERROR_MSG_SUPPORTED,
            msg_size: 100,
        };
        let mut buf = [0u8; LICENSE_PREAMBLE_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        pre.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = LicensePreamble::decode(&mut cursor).unwrap();
        assert_eq!(decoded.msg_type, LicenseMsgType::LicenseRequest);
        assert_eq!(decoded.msg_size, 100);
    }

    #[test]
    fn license_generic_pdu_roundtrip() {
        let pdu = LicenseGenericPdu {
            preamble: LicensePreamble {
                msg_type: LicenseMsgType::PlatformChallenge,
                flags: LicenseFlags::from_bits(0),
                msg_size: 12,
            },
            data: alloc::vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22],
        };
        let size = pdu.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = LicenseGenericPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded.preamble.msg_type, LicenseMsgType::PlatformChallenge);
        assert_eq!(decoded.data.len(), 8);
    }

    #[test]
    fn license_error_unknown_code() {
        assert!(LicenseErrorCode::from_u32(0xFFFF).is_err());
    }

    #[test]
    fn license_error_valid_client_wire_format() {
        let msg = LicenseErrorMessage::valid_client();
        let mut buf = alloc::vec![0u8; msg.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        msg.encode(&mut cursor).unwrap();

        assert_eq!(buf[0], 0xFF);  // ErrorAlert
        assert_eq!(buf[1], 0x80);  // EXTENDED_ERROR_MSG_SUPPORTED
        assert_eq!(&buf[2..4], &[0x10, 0x00]); // msg_size = 16 LE
        assert_eq!(&buf[4..8], &[0x07, 0x00, 0x00, 0x00]); // STATUS_VALID_CLIENT
        assert_eq!(&buf[8..12], &[0x02, 0x00, 0x00, 0x00]); // ST_NO_TRANSITION
        assert_eq!(&buf[12..16], &[0x04, 0x00, 0x00, 0x00]); // BB_ERROR_BLOB, len=0
    }
}
