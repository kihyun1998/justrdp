#![forbid(unsafe_code)]

//! RDSTLS (RDS Transport Layer Security) protocol -- MS-RDPBCGR 5.4.5
//!
//! RDSTLS is an alternative to CredSSP for Remote Credential Guard and
//! Azure AD authentication. It runs over TLS and consists of:
//!
//! 1. **Capabilities handshake**: Client and server exchange supported versions
//! 2. **Authentication**: Client sends auth data (Kerberos token or AAD token)
//! 3. **Result**: Server responds with NTSTATUS result
//!
//! ## Message Format
//!
//! All RDSTLS messages share a common header:
//! ```text
//! Version (2 bytes LE)  -- must be 0x0001
//! DataType (2 bytes LE) -- message type
//! PduLength (2 bytes LE) -- total length including header
//! ```

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

// ── Constants ──

/// RDSTLS protocol version.
pub const RDSTLS_VERSION_1: u16 = 0x0001;

/// RDSTLS message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RdstlsDataType {
    /// Capabilities exchange.
    Capabilities = 0x0001,
    /// Authentication request/response.
    AuthenticationRequest = 0x0002,
    /// Authentication result from server.
    AuthenticationResponse = 0x0004,
}

impl RdstlsDataType {
    pub fn from_u16(v: u16) -> DecodeResult<Self> {
        match v {
            0x0001 => Ok(Self::Capabilities),
            0x0002 => Ok(Self::AuthenticationRequest),
            0x0004 => Ok(Self::AuthenticationResponse),
            _ => Err(DecodeError::unexpected_value("RdstlsDataType", "dataType", "unknown")),
        }
    }
}

/// RDSTLS authentication request type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RdstlsAuthDataType {
    /// Password-based authentication.
    Password = 0x0001,
    /// Auto-reconnect cookie.
    AutoReconnectCookie = 0x0002,
    /// Redirected authentication (Remote Credential Guard).
    ///
    /// MS-RDPBCGR 2.2.23.2: When REDIRECTED_AUTHENTICATION_MODE is active,
    /// the auth data contains the Kerberos AP-REQ token directly.
    RedirectedAuthentication = 0x0003,
}

// ── Header ──

/// Common RDSTLS PDU header (6 bytes).
const RDSTLS_HEADER_SIZE: usize = 6;

// ── Capabilities ──

/// RDSTLS Capabilities PDU -- MS-RDPBCGR 2.2.23.1
///
/// Exchanged between client and server to establish supported RDSTLS versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdstlsCapabilities {
    /// Supported RDSTLS versions (bitfield).
    pub supported_versions: u16,
}

impl RdstlsCapabilities {
    pub fn new() -> Self {
        Self {
            supported_versions: RDSTLS_VERSION_1,
        }
    }
}

impl Encode for RdstlsCapabilities {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let total_len = self.size() as u16;
        // Header
        dst.write_u16_le(RDSTLS_VERSION_1, "RdstlsCap::version")?;
        dst.write_u16_le(RdstlsDataType::Capabilities as u16, "RdstlsCap::dataType")?;
        dst.write_u16_le(total_len, "RdstlsCap::pduLength")?;
        // Body
        dst.write_u16_le(self.supported_versions, "RdstlsCap::supportedVersions")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "RdstlsCapabilities" }

    fn size(&self) -> usize {
        RDSTLS_HEADER_SIZE + 2 // header + supportedVersions
    }
}

impl<'de> Decode<'de> for RdstlsCapabilities {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let version = src.read_u16_le("RdstlsCap::version")?;
        if version != RDSTLS_VERSION_1 {
            return Err(DecodeError::unexpected_value(
                "RdstlsCapabilities", "version", "expected RDSTLS version 1",
            ));
        }
        let data_type = src.read_u16_le("RdstlsCap::dataType")?;
        if data_type != RdstlsDataType::Capabilities as u16 {
            return Err(DecodeError::unexpected_value(
                "RdstlsCapabilities", "dataType", "expected Capabilities (1)",
            ));
        }
        let _pdu_length = src.read_u16_le("RdstlsCap::pduLength")?;
        let supported_versions = src.read_u16_le("RdstlsCap::supportedVersions")?;
        Ok(Self { supported_versions })
    }
}

// ── Authentication Request ──

/// RDSTLS Authentication Request PDU -- MS-RDPBCGR 2.2.23.2
///
/// Sent by the client after capabilities exchange.
/// Contains the authentication data (Kerberos ticket, redirect info, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdstlsAuthenticationRequest {
    /// Authentication data type.
    pub data_type: u16,
    /// Redirect flags (for auto-reconnect).
    pub redirect_flags: Option<u32>,
    /// Opaque redirect GUID (16 bytes, for auto-reconnect).
    pub redirect_guid: Option<[u8; 16]>,
    /// Authentication data (Kerberos AP-REQ token or password).
    pub auth_data: Vec<u8>,
}

impl RdstlsAuthenticationRequest {
    /// Create a new password-based auth request.
    ///
    /// Returns `Err` if any field exceeds u16::MAX bytes.
    pub fn password(
        domain: &[u8],
        username: &[u8],
        password: &[u8],
    ) -> EncodeResult<Self> {
        // Password auth data format:
        // Domain (UTF-16LE, null-terminated, len u16 LE)
        // Username (UTF-16LE, null-terminated, len u16 LE)
        // Password (UTF-16LE, null-terminated, len u16 LE)
        let mut auth_data = Vec::new();

        macro_rules! append_field {
            ($data:expr, $name:expr) => {{
                let with_null = append_null_utf16($data);
                let len = u16::try_from(with_null.len())
                    .map_err(|_| justrdp_core::EncodeError::other($name, "field too long for u16"))?;
                auth_data.extend_from_slice(&len.to_le_bytes());
                auth_data.extend_from_slice(&with_null);
            }};
        }

        append_field!(domain, "RDSTLS::domain");
        append_field!(username, "RDSTLS::username");
        append_field!(password, "RDSTLS::password");

        Ok(Self {
            data_type: RdstlsAuthDataType::Password as u16,
            redirect_flags: None,
            redirect_guid: None,
            auth_data,
        })
    }

    /// Create a password-based auth request for a redirected connection.
    ///
    /// Unlike [`password()`](Self::password), the fields come directly from a
    /// `ServerRedirectionPdu` and the password blob is opaque (PK-encrypted by
    /// the Connection Broker). All byte slices are sent verbatim — no
    /// UTF-16LE re-encoding or null-termination is applied.
    ///
    /// MS-RDPBCGR §2.2.17.2: RDSTLS Authentication Request with Password Credentials.
    pub fn password_cookie(
        redirection_guid: &[u8],
        username: &[u8],
        domain: &[u8],
        password_blob: &[u8],
    ) -> EncodeResult<Self> {
        // Wire layout inside auth_data:
        //   RedirectionGuidLength (u16) + RedirectionGuid
        //   UserNameLength (u16) + UserName
        //   DomainLength (u16) + Domain
        //   PasswordLength (u16) + Password
        let mut auth_data = Vec::new();

        macro_rules! append_raw {
            ($data:expr, $name:expr) => {{
                let len = u16::try_from($data.len())
                    .map_err(|_| justrdp_core::EncodeError::other($name, "field too long for u16"))?;
                auth_data.extend_from_slice(&len.to_le_bytes());
                auth_data.extend_from_slice($data);
            }};
        }

        append_raw!(redirection_guid, "RDSTLS::redirectionGuid");
        append_raw!(username, "RDSTLS::userName");
        append_raw!(domain, "RDSTLS::domain");
        append_raw!(password_blob, "RDSTLS::password");

        Ok(Self {
            data_type: RdstlsAuthDataType::Password as u16,
            redirect_flags: None,
            redirect_guid: None,
            auth_data,
        })
    }

    /// Create an auth request with a Kerberos token for Remote Credential Guard.
    ///
    /// Uses `RedirectedAuthentication` (0x0003) data type.
    /// The auth data contains the raw Kerberos AP-REQ token.
    pub fn kerberos(kerberos_token: Vec<u8>) -> Self {
        Self {
            data_type: RdstlsAuthDataType::RedirectedAuthentication as u16,
            redirect_flags: None,
            redirect_guid: None,
            auth_data: kerberos_token,
        }
    }

    /// Create an auto-reconnect auth request.
    pub fn auto_reconnect(
        redirect_flags: u32,
        redirect_guid: [u8; 16],
        cookie: Vec<u8>,
    ) -> Self {
        Self {
            data_type: RdstlsAuthDataType::AutoReconnectCookie as u16,
            redirect_flags: Some(redirect_flags),
            redirect_guid: Some(redirect_guid),
            auth_data: cookie,
        }
    }
}

impl Encode for RdstlsAuthenticationRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let size = self.size();
        if size > u16::MAX as usize {
            return Err(justrdp_core::EncodeError::other("RdstlsAuth", "pduLength exceeds u16"));
        }
        let total_len = size as u16;
        // Header
        dst.write_u16_le(RDSTLS_VERSION_1, "RdstlsAuth::version")?;
        dst.write_u16_le(RdstlsDataType::AuthenticationRequest as u16, "RdstlsAuth::dataType")?;
        dst.write_u16_le(total_len, "RdstlsAuth::pduLength")?;
        // Body
        dst.write_u16_le(self.data_type, "RdstlsAuth::authDataType")?;

        if let (Some(flags), Some(guid)) = (self.redirect_flags, &self.redirect_guid) {
            dst.write_u32_le(flags, "RdstlsAuth::redirectFlags")?;
            dst.write_slice(guid, "RdstlsAuth::redirectGuid")?;
        }

        // Auth data length + data
        if self.auth_data.len() > u16::MAX as usize {
            return Err(justrdp_core::EncodeError::other("RdstlsAuth", "authData exceeds u16"));
        }
        dst.write_u16_le(self.auth_data.len() as u16, "RdstlsAuth::authDataLen")?;
        dst.write_slice(&self.auth_data, "RdstlsAuth::authData")?;

        Ok(())
    }

    fn name(&self) -> &'static str { "RdstlsAuthenticationRequest" }

    fn size(&self) -> usize {
        let mut size = RDSTLS_HEADER_SIZE + 2; // header + authDataType
        if self.redirect_flags.is_some() {
            size += 4 + 16; // redirectFlags + redirectGuid
        }
        size += 2 + self.auth_data.len(); // authDataLen + authData
        size
    }
}

impl<'de> Decode<'de> for RdstlsAuthenticationRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let version = src.read_u16_le("RdstlsAuth::version")?;
        if version != RDSTLS_VERSION_1 {
            return Err(DecodeError::unexpected_value(
                "RdstlsAuthReq", "version", "expected RDSTLS version 1",
            ));
        }
        let msg_type = src.read_u16_le("RdstlsAuth::dataType")?;
        if msg_type != RdstlsDataType::AuthenticationRequest as u16 {
            return Err(DecodeError::unexpected_value(
                "RdstlsAuthReq", "dataType", "expected AuthenticationRequest (2)",
            ));
        }
        let _pdu_length = src.read_u16_le("RdstlsAuth::pduLength")?;
        let data_type = src.read_u16_le("RdstlsAuth::authDataType")?;

        let (redirect_flags, redirect_guid) = if data_type == RdstlsAuthDataType::AutoReconnectCookie as u16 {
            let flags = src.read_u32_le("RdstlsAuth::redirectFlags")?;
            let guid_bytes = src.read_slice(16, "RdstlsAuth::redirectGuid")?;
            let mut guid = [0u8; 16];
            guid.copy_from_slice(guid_bytes);
            (Some(flags), Some(guid))
        } else {
            (None, None)
        };

        let auth_data_len = src.read_u16_le("RdstlsAuth::authDataLen")? as usize;
        let auth_data = src.read_slice(auth_data_len, "RdstlsAuth::authData")?.to_vec();

        Ok(Self {
            data_type,
            redirect_flags,
            redirect_guid,
            auth_data,
        })
    }
}

// ── Authentication Response ──

/// RDSTLS Authentication Response PDU -- MS-RDPBCGR 2.2.23.3
///
/// Sent by the server with the authentication result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdstlsAuthenticationResponse {
    /// NTSTATUS result code.
    /// 0 = success, non-zero = error.
    pub result_code: u32,
}

impl Encode for RdstlsAuthenticationResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let total_len = self.size() as u16;
        dst.write_u16_le(RDSTLS_VERSION_1, "RdstlsResp::version")?;
        dst.write_u16_le(RdstlsDataType::AuthenticationResponse as u16, "RdstlsResp::dataType")?;
        dst.write_u16_le(total_len, "RdstlsResp::pduLength")?;
        dst.write_u32_le(self.result_code, "RdstlsResp::resultCode")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "RdstlsAuthenticationResponse" }

    fn size(&self) -> usize {
        RDSTLS_HEADER_SIZE + 4 // header + resultCode
    }
}

impl<'de> Decode<'de> for RdstlsAuthenticationResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let version = src.read_u16_le("RdstlsResp::version")?;
        if version != RDSTLS_VERSION_1 {
            return Err(DecodeError::unexpected_value(
                "RdstlsAuthResp", "version", "expected RDSTLS version 1",
            ));
        }
        let msg_type = src.read_u16_le("RdstlsResp::dataType")?;
        if msg_type != RdstlsDataType::AuthenticationResponse as u16 {
            return Err(DecodeError::unexpected_value(
                "RdstlsAuthResp", "dataType", "expected AuthenticationResponse (4)",
            ));
        }
        let _pdu_length = src.read_u16_le("RdstlsResp::pduLength")?;
        let result_code = src.read_u32_le("RdstlsResp::resultCode")?;
        Ok(Self { result_code })
    }
}

// ── Helpers ──

/// Append UTF-16LE null terminator if not already present.
fn append_null_utf16(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    // Check if already null-terminated (last 2 bytes are 0x00 0x00)
    if result.len() < 2 || result[result.len() - 2..] != [0x00, 0x00] {
        result.extend_from_slice(&[0x00, 0x00]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn capabilities_roundtrip() {
        let caps = RdstlsCapabilities::new();
        let size = caps.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        caps.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = RdstlsCapabilities::decode(&mut cursor).unwrap();
        assert_eq!(decoded.supported_versions, RDSTLS_VERSION_1);
    }

    #[test]
    fn auth_response_roundtrip() {
        let resp = RdstlsAuthenticationResponse { result_code: 0 };
        let size = resp.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        resp.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = RdstlsAuthenticationResponse::decode(&mut cursor).unwrap();
        assert_eq!(decoded.result_code, 0);
    }

    #[test]
    fn auth_response_failure() {
        let resp = RdstlsAuthenticationResponse { result_code: 0xC000006D }; // STATUS_LOGON_FAILURE
        let size = resp.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        resp.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = RdstlsAuthenticationResponse::decode(&mut cursor).unwrap();
        assert_eq!(decoded.result_code, 0xC000006D);
    }

    #[test]
    fn auth_request_password_roundtrip() {
        let domain = b"C\x00O\x00R\x00P\x00"; // "CORP" in UTF-16LE
        let user = b"a\x00d\x00m\x00i\x00n\x00"; // "admin"
        let pass = b"p\x00a\x00s\x00s\x00"; // "pass"
        let req = RdstlsAuthenticationRequest::password(domain, user, pass).unwrap();

        let size = req.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        req.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = RdstlsAuthenticationRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.data_type, RdstlsAuthDataType::Password as u16);
        assert_eq!(decoded.auth_data, req.auth_data);
    }

    #[test]
    fn auth_request_kerberos() {
        let token = vec![0x60, 0x82, 0x01, 0x00, 0xAA, 0xBB];
        let req = RdstlsAuthenticationRequest::kerberos(token.clone());

        let size = req.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        req.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = RdstlsAuthenticationRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.data_type, RdstlsAuthDataType::RedirectedAuthentication as u16);
        assert_eq!(decoded.auth_data, token);
    }

    #[test]
    fn auto_reconnect_roundtrip() {
        let guid = [0x42u8; 16];
        let cookie = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let req = RdstlsAuthenticationRequest::auto_reconnect(0x01, guid, cookie.clone());

        let size = req.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        req.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = RdstlsAuthenticationRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.data_type, RdstlsAuthDataType::AutoReconnectCookie as u16);
        assert_eq!(decoded.redirect_flags, Some(0x01));
        assert_eq!(decoded.redirect_guid, Some(guid));
        assert_eq!(decoded.auth_data, cookie);
    }

    #[test]
    fn auth_request_password_cookie_roundtrip() {
        let guid = vec![0x42u8; 48]; // simulated Base64-GUID in UTF-16LE
        let user = b"a\x00d\x00m\x00i\x00n\x00\x00\x00"; // "admin" UTF-16LE null-terminated
        let domain = b"C\x00O\x00R\x00P\x00\x00\x00"; // "CORP"
        let blob = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]; // opaque PK-encrypted blob

        let req = RdstlsAuthenticationRequest::password_cookie(
            &guid, user, domain, &blob,
        ).unwrap();

        assert_eq!(req.data_type, RdstlsAuthDataType::Password as u16);

        let size = req.size();
        let mut buf = vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        req.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = RdstlsAuthenticationRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.data_type, RdstlsAuthDataType::Password as u16);
        assert_eq!(decoded.auth_data, req.auth_data, "auth_data must round-trip");
    }

    #[test]
    fn password_cookie_preserves_opaque_blob_verbatim() {
        // Verify the password blob is NOT re-encoded or null-terminated.
        let guid = b"";
        let user = b"";
        let domain = b"";
        let blob = vec![0x01, 0x02, 0x03];

        let req = RdstlsAuthenticationRequest::password_cookie(
            guid, user, domain, &blob,
        ).unwrap();

        // auth_data layout: 4 × (u16 len + data)
        // guid: 0x0000
        // user: 0x0000
        // domain: 0x0000
        // password: 0x0300 + [01, 02, 03]
        let expected: Vec<u8> = vec![
            0x00, 0x00, // guid len = 0
            0x00, 0x00, // user len = 0
            0x00, 0x00, // domain len = 0
            0x03, 0x00, // password len = 3
            0x01, 0x02, 0x03, // password blob verbatim
        ];
        assert_eq!(req.auth_data, expected);
    }

    #[test]
    fn password_cookie_rejects_oversized_field() {
        let huge = vec![0u8; 65537]; // > u16::MAX
        let result = RdstlsAuthenticationRequest::password_cookie(
            &huge, b"", b"", b"",
        );
        assert!(result.is_err(), "must reject field > u16::MAX");
    }
}
