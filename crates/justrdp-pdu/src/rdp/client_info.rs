#![forbid(unsafe_code)]

//! Client Info PDU -- MS-RDPBCGR 2.2.1.11

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeResult, EncodeResult};

/// Client Info flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfoFlags(u32);

impl InfoFlags {
    pub const MOUSE: Self = Self(0x0001);
    pub const DISABLE_CTRL_ALT_DEL: Self = Self(0x0002);
    pub const AUTOLOGON: Self = Self(0x0008);
    pub const UNICODE: Self = Self(0x0010);
    pub const MAXIMIZE_SHELL: Self = Self(0x0020);
    pub const LOGON_NOTIFY: Self = Self(0x0040);
    pub const COMPRESSION: Self = Self(0x0080);
    pub const ENABLE_WINDOWS_KEY: Self = Self(0x0100);
    pub const REMOTE_CONSOLE_AUDIO: Self = Self(0x2000);
    pub const FORCE_ENCRYPTED_CS_PDU: Self = Self(0x4000);
    pub const RAIL: Self = Self(0x8000);
    pub const LOGON_ERRORS: Self = Self(0x0001_0000);
    pub const MOUSE_HAS_WHEEL: Self = Self(0x0002_0000);
    pub const NO_AUDIO_PLAYBACK: Self = Self(0x0008_0000);
    pub const USING_SAVED_CREDS: Self = Self(0x0010_0000);
    pub const AUDIO_CAPTURE: Self = Self(0x0020_0000);
    pub const VIDEO_DISABLE: Self = Self(0x0040_0000);
    pub const HIDEF_RAIL_SUPPORTED: Self = Self(0x0200_0000);

    pub fn from_bits(bits: u32) -> Self { Self(bits) }
    pub fn bits(&self) -> u32 { self.0 }
    pub fn contains(&self, other: Self) -> bool { (self.0 & other.0) == other.0 }
    pub fn union(self, other: Self) -> Self { Self(self.0 | other.0) }
}

/// Compression type (bits 9-12 of flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CompressionType {
    Type8K = 0x0000,
    Type64K = 0x0200,
    TypeRdp6 = 0x0400,
    TypeRdp61 = 0x0600,
}

/// Performance flags for connection experience.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerformanceFlags(u32);

impl PerformanceFlags {
    pub const DISABLE_WALLPAPER: Self = Self(0x0001);
    pub const DISABLE_FULLWINDOWDRAG: Self = Self(0x0002);
    pub const DISABLE_MENUANIMATIONS: Self = Self(0x0004);
    pub const DISABLE_THEMING: Self = Self(0x0008);
    pub const DISABLE_CURSOR_SHADOW: Self = Self(0x0020);
    pub const DISABLE_CURSORSETTINGS: Self = Self(0x0040);
    pub const ENABLE_FONT_SMOOTHING: Self = Self(0x0080);
    pub const ENABLE_DESKTOP_COMPOSITION: Self = Self(0x0100);

    pub fn from_bits(bits: u32) -> Self { Self(bits) }
    pub fn bits(&self) -> u32 { self.0 }
}

/// Client Info PDU.
///
/// Sent during the secure settings exchange phase.
/// Contains user credentials and session preferences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfoPdu {
    pub code_page: u32,
    pub flags: InfoFlags,
    pub domain: String,
    pub user_name: String,
    pub password: String,
    pub alternate_shell: String,
    pub working_dir: String,
    /// Extended client info (present when INFO_UNICODE is set).
    pub extra: Option<ExtendedClientInfo>,
}

/// Extended Client Info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedClientInfo {
    pub client_address_family: u16,
    pub client_address: String,
    pub client_dir: String,
    pub performance_flags: PerformanceFlags,
    pub auto_reconnect_cookie: Option<Vec<u8>>,
}

impl ClientInfoPdu {
    /// Create a basic Unicode client info.
    pub fn new(domain: &str, user_name: &str, password: &str) -> Self {
        Self {
            code_page: 0,
            flags: InfoFlags::MOUSE
                .union(InfoFlags::UNICODE)
                .union(InfoFlags::LOGON_NOTIFY)
                .union(InfoFlags::LOGON_ERRORS)
                .union(InfoFlags::DISABLE_CTRL_ALT_DEL)
                .union(InfoFlags::ENABLE_WINDOWS_KEY),
            domain: domain.into(),
            user_name: user_name.into(),
            password: password.into(),
            alternate_shell: String::new(),
            working_dir: String::new(),
            extra: Some(ExtendedClientInfo {
                client_address_family: 0x0002, // AF_INET
                client_address: String::new(),
                client_dir: String::new(),
                performance_flags: PerformanceFlags::from_bits(0),
                auto_reconnect_cookie: None,
            }),
        }
    }

    /// Set performance flags.
    pub fn with_performance_flags(mut self, flags: PerformanceFlags) -> Self {
        if let Some(ref mut extra) = self.extra {
            extra.performance_flags = flags;
        }
        self
    }
}

/// Encode a string as UTF-16LE bytes (without null terminator size, but WITH null on wire).
fn utf16le_bytes(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for ch in s.encode_utf16() {
        bytes.extend_from_slice(&ch.to_le_bytes());
    }
    bytes
}

/// Size of a UTF-16LE string on wire (excluding null terminator).
fn utf16le_size(s: &str) -> usize {
    s.encode_utf16().count() * 2
}

impl Encode for ClientInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.code_page, "ClientInfo::codePage")?;
        dst.write_u32_le(self.flags.bits(), "ClientInfo::flags")?;

        let domain = utf16le_bytes(&self.domain);
        let user = utf16le_bytes(&self.user_name);
        let pass = utf16le_bytes(&self.password);
        let shell = utf16le_bytes(&self.alternate_shell);
        let workdir = utf16le_bytes(&self.working_dir);

        // Length fields (cbDomain, cbUserName, etc.) exclude null terminator
        macro_rules! check_u16 {
            ($val:expr, $ctx:expr) => {
                u16::try_from($val).map_err(|_| justrdp_core::EncodeError::other($ctx, "too long for u16"))?
            };
        }
        dst.write_u16_le(check_u16!(domain.len(), "ClientInfo::cbDomain"), "ClientInfo::cbDomain")?;
        dst.write_u16_le(check_u16!(user.len(), "ClientInfo::cbUserName"), "ClientInfo::cbUserName")?;
        dst.write_u16_le(check_u16!(pass.len(), "ClientInfo::cbPassword"), "ClientInfo::cbPassword")?;
        dst.write_u16_le(check_u16!(shell.len(), "ClientInfo::cbAlternateShell"), "ClientInfo::cbAlternateShell")?;
        dst.write_u16_le(check_u16!(workdir.len(), "ClientInfo::cbWorkingDir"), "ClientInfo::cbWorkingDir")?;

        // String data: each followed by null terminator (2 bytes for Unicode)
        dst.write_slice(&domain, "ClientInfo::domain")?;
        dst.write_u16_le(0, "ClientInfo::domain_null")?;
        dst.write_slice(&user, "ClientInfo::userName")?;
        dst.write_u16_le(0, "ClientInfo::userName_null")?;
        dst.write_slice(&pass, "ClientInfo::password")?;
        dst.write_u16_le(0, "ClientInfo::password_null")?;
        dst.write_slice(&shell, "ClientInfo::alternateShell")?;
        dst.write_u16_le(0, "ClientInfo::shell_null")?;
        dst.write_slice(&workdir, "ClientInfo::workingDir")?;
        dst.write_u16_le(0, "ClientInfo::workdir_null")?;

        // Extended info
        if let Some(ref extra) = self.extra {
            dst.write_u16_le(extra.client_address_family, "ExtInfo::addressFamily")?;

            let addr = utf16le_bytes(&extra.client_address);
            let cb_addr = u16::try_from(addr.len() + 2).map_err(|_| {
                justrdp_core::EncodeError::other("ExtInfo::cbClientAddress", "address too long for u16")
            })?;
            dst.write_u16_le(cb_addr, "ExtInfo::cbClientAddress")?;
            dst.write_slice(&addr, "ExtInfo::clientAddress")?;
            dst.write_u16_le(0, "ExtInfo::clientAddress_null")?;

            let dir = utf16le_bytes(&extra.client_dir);
            let cb_dir = u16::try_from(dir.len() + 2).map_err(|_| {
                justrdp_core::EncodeError::other("ExtInfo::cbClientDir", "dir too long for u16")
            })?;
            dst.write_u16_le(cb_dir, "ExtInfo::cbClientDir")?;
            dst.write_slice(&dir, "ExtInfo::clientDir")?;
            dst.write_u16_le(0, "ExtInfo::clientDir_null")?;

            // Timezone (172 bytes of zeros for simplicity)
            dst.write_zeros(172, "ExtInfo::timeZone")?;

            // Client session ID
            dst.write_u32_le(0, "ExtInfo::clientSessionId")?;

            // Performance flags
            dst.write_u32_le(extra.performance_flags.bits(), "ExtInfo::performanceFlags")?;

            // Auto-reconnect cookie
            if let Some(ref cookie) = extra.auto_reconnect_cookie {
                let cb_cookie = u16::try_from(cookie.len()).map_err(|_| {
                    justrdp_core::EncodeError::other("ExtInfo::cbAutoReconnectCookie", "cookie too long for u16")
                })?;
                dst.write_u16_le(cb_cookie, "ExtInfo::cbAutoReconnectCookie")?;
                dst.write_slice(cookie, "ExtInfo::autoReconnectCookie")?;
            } else {
                dst.write_u16_le(0, "ExtInfo::cbAutoReconnectCookie")?;
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str { "ClientInfoPdu" }

    fn size(&self) -> usize {
        let mut size = 4 + 4 + 10; // codePage + flags + 5 x cbLength
        // Strings + null terminators (2 bytes each for Unicode)
        size += utf16le_size(&self.domain) + 2;
        size += utf16le_size(&self.user_name) + 2;
        size += utf16le_size(&self.password) + 2;
        size += utf16le_size(&self.alternate_shell) + 2;
        size += utf16le_size(&self.working_dir) + 2;

        if let Some(ref extra) = self.extra {
            size += 2; // addressFamily
            size += 2 + utf16le_size(&extra.client_address) + 2; // cbAddr + addr + null
            size += 2 + utf16le_size(&extra.client_dir) + 2; // cbDir + dir + null
            size += 172; // timezone
            size += 4; // clientSessionId
            size += 4; // performanceFlags
            size += 2; // cbAutoReconnectCookie
            if let Some(ref cookie) = extra.auto_reconnect_cookie {
                size += cookie.len();
            }
        }
        size
    }
}

impl<'de> Decode<'de> for ClientInfoPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let code_page = src.read_u32_le("ClientInfo::codePage")?;
        let flags = InfoFlags::from_bits(src.read_u32_le("ClientInfo::flags")?);
        let is_unicode = flags.contains(InfoFlags::UNICODE);

        let cb_domain = src.read_u16_le("ClientInfo::cbDomain")? as usize;
        let cb_user = src.read_u16_le("ClientInfo::cbUserName")? as usize;
        let cb_pass = src.read_u16_le("ClientInfo::cbPassword")? as usize;
        let cb_shell = src.read_u16_le("ClientInfo::cbAlternateShell")? as usize;
        let cb_workdir = src.read_u16_le("ClientInfo::cbWorkingDir")? as usize;

        let domain = read_string(src, cb_domain, is_unicode, "ClientInfo::domain")?;
        let user_name = read_string(src, cb_user, is_unicode, "ClientInfo::userName")?;
        let password = read_string(src, cb_pass, is_unicode, "ClientInfo::password")?;
        let alternate_shell = read_string(src, cb_shell, is_unicode, "ClientInfo::alternateShell")?;
        let working_dir = read_string(src, cb_workdir, is_unicode, "ClientInfo::workingDir")?;

        // Extended info if remaining bytes
        let extra = if src.remaining() >= 4 {
            let client_address_family = src.read_u16_le("ExtInfo::addressFamily")?;

            let cb_addr = src.read_u16_le("ExtInfo::cbClientAddress")? as usize;
            let client_address = if cb_addr > 0 {
                read_string_with_null(src, cb_addr, "ExtInfo::clientAddress")?
            } else {
                String::new()
            };

            let cb_dir = src.read_u16_le("ExtInfo::cbClientDir")? as usize;
            let client_dir = if cb_dir > 0 {
                read_string_with_null(src, cb_dir, "ExtInfo::clientDir")?
            } else {
                String::new()
            };

            // Timezone (172 bytes)
            if src.remaining() >= 172 {
                src.skip(172, "ExtInfo::timeZone")?;
            }

            // Client session ID
            let _session_id = if src.remaining() >= 4 {
                Some(src.read_u32_le("ExtInfo::clientSessionId")?)
            } else { None };

            let performance_flags = if src.remaining() >= 4 {
                PerformanceFlags::from_bits(src.read_u32_le("ExtInfo::performanceFlags")?)
            } else {
                PerformanceFlags::from_bits(0)
            };

            let auto_reconnect_cookie = if src.remaining() >= 2 {
                let cb = src.read_u16_le("ExtInfo::cbAutoReconnectCookie")? as usize;
                if cb > 0 && src.remaining() >= cb {
                    Some(src.read_slice(cb, "ExtInfo::autoReconnectCookie")?.into())
                } else {
                    None
                }
            } else { None };

            Some(ExtendedClientInfo {
                client_address_family,
                client_address,
                client_dir,
                performance_flags,
                auto_reconnect_cookie,
            })
        } else {
            None
        };

        Ok(Self {
            code_page, flags, domain, user_name, password,
            alternate_shell, working_dir, extra,
        })
    }
}

/// Read a UTF-16LE string of `byte_len` bytes, then skip the null terminator.
fn read_string(
    src: &mut ReadCursor<'_>,
    byte_len: usize,
    is_unicode: bool,
    ctx: &'static str,
) -> DecodeResult<String> {
    let data = src.read_slice(byte_len, ctx)?;
    // Skip null terminator
    let null_size = if is_unicode { 2 } else { 1 };
    src.skip(null_size, ctx)?;

    if is_unicode {
        let u16s: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&u16s))
    } else {
        Ok(String::from_utf8_lossy(data).into_owned())
    }
}

/// Read a UTF-16LE string where the length includes the null terminator.
fn read_string_with_null(
    src: &mut ReadCursor<'_>,
    total_len: usize,
    ctx: &'static str,
) -> DecodeResult<String> {
    let data = src.read_slice(total_len, ctx)?;
    // Strip null terminator
    let str_len = if total_len >= 2 { total_len - 2 } else { 0 };
    let u16s: Vec<u16> = data[..str_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&u16s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_info_roundtrip() {
        let info = ClientInfoPdu::new("DOMAIN", "user", "pass123");

        let size = info.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        info.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientInfoPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded.domain, "DOMAIN");
        assert_eq!(decoded.user_name, "user");
        assert_eq!(decoded.password, "pass123");
        assert!(decoded.flags.contains(InfoFlags::UNICODE));
        assert!(decoded.extra.is_some());
    }

    #[test]
    fn client_info_empty_strings() {
        let info = ClientInfoPdu::new("", "", "");

        let size = info.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        info.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ClientInfoPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded.domain, "");
        assert_eq!(decoded.user_name, "");
    }

    #[test]
    fn info_flags() {
        let flags = InfoFlags::UNICODE.union(InfoFlags::MOUSE);
        assert!(flags.contains(InfoFlags::UNICODE));
        assert!(flags.contains(InfoFlags::MOUSE));
        assert!(!flags.contains(InfoFlags::AUTOLOGON));
    }
}
