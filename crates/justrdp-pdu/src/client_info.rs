//! The Client Info PDU (MS-RDPBCGR 2.2.1.11) — the Secure Settings Exchange payload the client
//! MUST send on the I/O channel right after MCS channel join; the server does not begin
//! licensing until it arrives (plan.md §3 Layer 1).
//!
//! Layout: a [`basic security header`](encode_basic_security_header) with [`SEC_INFO_PKT`],
//! then `TS_INFO_PACKET` (code page, INFO_* flags, five length-prefixed strings) followed by
//! `TS_EXTENDED_INFO_PACKET` (client address, directory, time zone, session id, performance
//! flags, and the auto-reconnect cookie length — zero until epic #25 populates it).
//!
//! Length-field semantics differ between the two packets and are the classic trap here: the
//! `TS_INFO_PACKET` `cb*` fields **exclude** each string's mandatory null terminator, while the
//! extended packet's `cbClientAddress`/`cbClientDir` **include** it.
//!
//! Wire-format reference: ironrdp-pdu `rdp/client_info.rs` (the differential oracle).

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// `TS_SECURITY_HEADER` flag: the payload is a Client Info PDU (`SEC_INFO_PKT`).
pub const SEC_INFO_PKT: u16 = 0x0040;
/// `TS_SECURITY_HEADER` flag: the payload is a licensing PDU (`SEC_LICENSE_PKT`) — the first
/// thing the server sends back after the Client Info PDU.
pub const SEC_LICENSE_PKT: u16 = 0x0080;

/// Write a basic security header (`TS_SECURITY_HEADER`): `flags` + `flagsHi` (always 0; the
/// `FLAGSHI_VALID` bit is never set by this client).
pub fn encode_basic_security_header(out: &mut Vec<u8>, flags: u16) {
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
}

/// Read a basic security header, returning its flags.
pub fn decode_basic_security_header(cur: &mut ReadCursor<'_>) -> Result<u16, DecodeError> {
    let flags = cur.read_u16_le()?;
    cur.read_u16_le()?; // flagsHi — unused without FLAGSHI_VALID
    Ok(flags)
}

/// `flags` in the `TS_INFO_PACKET` (MS-RDPBCGR 2.2.1.11.1.1). A dependency-free bitflag newtype
/// (decision 6); all bits are caller-set — justrdp adds only [`ClientInfoFlags::UNICODE`], the
/// encoding-mechanics bit that must match the UTF-16 strings the encoder actually writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientInfoFlags(u32);

impl ClientInfoFlags {
    /// `INFO_MOUSE` — the client uses mouse coordinates in input PDUs.
    pub const MOUSE: Self = Self(0x0000_0001);
    /// `INFO_DISABLECTRLALTDEL` — the server does not require Ctrl+Alt+Del before logon.
    pub const DISABLE_CTRL_ALT_DEL: Self = Self(0x0000_0002);
    /// `INFO_AUTOLOGON` — log the user on automatically with the supplied (or, under NLA, the
    /// CredSSP-delegated) credentials.
    pub const AUTOLOGON: Self = Self(0x0000_0008);
    /// `INFO_UNICODE` — the string fields are UTF-16. The encoder always sets this bit because
    /// it only ever writes UTF-16 strings (wire consistency, not caller policy).
    pub const UNICODE: Self = Self(0x0000_0010);
    /// `INFO_MAXIMIZESHELL` — maximize the alternate shell.
    pub const MAXIMIZE_SHELL: Self = Self(0x0000_0020);
    /// `INFO_LOGONNOTIFY` — the client wants Save Session Info logon notifications.
    pub const LOGON_NOTIFY: Self = Self(0x0000_0040);
    /// `INFO_COMPRESSION` — bulk compression is requested (the type rides bits 9–12).
    pub const COMPRESSION: Self = Self(0x0000_0080);
    /// `INFO_ENABLEWINDOWSKEY` — the client keyboard has a Windows key.
    pub const ENABLE_WINDOWS_KEY: Self = Self(0x0000_0100);
    /// `INFO_LOGONERRORS` — the client wants typed logon error notifications.
    pub const LOGON_ERRORS: Self = Self(0x0001_0000);
    /// `INFO_MOUSE_HAS_WHEEL` — the mouse has a wheel.
    pub const MOUSE_HAS_WHEEL: Self = Self(0x0002_0000);
    /// `INFO_NOAUDIOPLAYBACK` — do not play audio on the client.
    pub const NO_AUDIO_PLAYBACK: Self = Self(0x0008_0000);
    /// `INFO_VIDEO_DISABLE` — disable video redirection.
    pub const VIDEO_DISABLE: Self = Self(0x0040_0000);

    /// No flags set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// The raw bitmask.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Build from a raw bitmask (unknown bits preserved).
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// True if every bit in `other` is set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for ClientInfoFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// `clientAddressFamily` — IPv4.
pub const ADDRESS_FAMILY_INET: u16 = 0x0002;
/// `clientAddressFamily` — IPv6.
pub const ADDRESS_FAMILY_INET6: u16 = 0x0017;

/// `TS_TIME_ZONE_INFORMATION` (MS-RDPBCGR 2.2.1.11.1.1.1.1), 172 bytes on the wire. This slice
/// models fixed-offset zones: bias values and zone names are caller-set, while the DST
/// transition dates (`StandardDate`/`DaylightDate` SYSTEMTIMEs) are encoded as all-zero
/// ("no transition"), which every decoder — including the oracle — reads back as absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimezoneInfo {
    /// Minutes west of UTC (`UTC = local time + bias`); e.g. -540 for KST (UTC+9).
    pub bias: i32,
    /// Standard-time zone name (at most 31 UTF-16 units).
    pub standard_name: String,
    /// Additional bias while standard time is active (usually 0).
    pub standard_bias: i32,
    /// Daylight-time zone name.
    pub daylight_name: String,
    /// Additional bias while daylight time is active (conventionally -60).
    pub daylight_bias: i32,
}

impl TimezoneInfo {
    /// The fixed on-wire size.
    pub const ENCODED_LEN: usize = 172;

    /// A UTC zone: zero bias, empty names.
    pub fn utc() -> Self {
        Self {
            bias: 0,
            standard_name: String::new(),
            standard_bias: 0,
            daylight_name: String::new(),
            daylight_bias: 0,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bias.to_le_bytes());
        put_utf16_padded(out, &self.standard_name, 64);
        out.extend(std::iter::repeat_n(0u8, 16)); // StandardDate: no transition
        out.extend_from_slice(&self.standard_bias.to_le_bytes());
        put_utf16_padded(out, &self.daylight_name, 64);
        out.extend(std::iter::repeat_n(0u8, 16)); // DaylightDate: no transition
        out.extend_from_slice(&self.daylight_bias.to_le_bytes());
    }

    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let bias = cur.read_u32_le()? as i32;
        let standard_name = read_utf16_padded(cur, 64)?;
        cur.read_slice(16)?; // StandardDate
        let standard_bias = cur.read_u32_le()? as i32;
        let daylight_name = read_utf16_padded(cur, 64)?;
        cur.read_slice(16)?; // DaylightDate
        let daylight_bias = cur.read_u32_le()? as i32;
        Ok(Self {
            bias,
            standard_name,
            standard_bias,
            daylight_name,
            daylight_bias,
        })
    }
}

/// `TS_EXTENDED_INFO_PACKET` (MS-RDPBCGR 2.2.1.11.1.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedClientInfo {
    /// `clientAddressFamily` ([`ADDRESS_FAMILY_INET`] / [`ADDRESS_FAMILY_INET6`]).
    pub address_family: u16,
    /// The client's own address as text (informational; servers log it).
    pub address: String,
    /// `clientDir` — the client software's working directory (informational).
    pub dir: String,
    /// The client time zone.
    pub timezone: TimezoneInfo,
    /// `clientSessionId` (0 unless reconnecting to a known session).
    pub session_id: u32,
    /// `performanceFlags` (`PERF_*` bits, raw — caller policy).
    pub performance_flags: u32,
    /// The 28-byte auto-reconnect cookie, replayed from a previous session's Save Session Info
    /// (epic #25). `None` encodes `cbAutoReconnectCookie = 0` — the field is always present.
    pub reconnect_cookie: Option<[u8; 28]>,
}

/// The Client Info PDU body (security header excluded — see [`ClientInfo::encode`] for the
/// framed form). String fields are always encoded UTF-16; the password field exists because the
/// wire demands one, and stays empty under NLA where CredSSP already delegated the real
/// credentials (plan.md decision 10 keeps secrets out of the sans-IO machine entirely).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    /// `CodePage` (0 with UTF-16 strings; carries the ANSI code page only for ANSI clients).
    pub code_page: u32,
    /// `INFO_*` flags — caller policy, plus [`ClientInfoFlags::UNICODE`] which the encoder
    /// enforces to match its UTF-16 strings.
    pub flags: ClientInfoFlags,
    /// Logon domain (may be empty).
    pub domain: String,
    /// Logon user name (may be empty under NLA).
    pub username: String,
    /// Logon password — empty under NLA (CredSSP delegates the real credentials).
    pub password: String,
    /// `AlternateShell` — program to run instead of explorer.
    pub alternate_shell: String,
    /// `WorkingDir` for the alternate shell.
    pub work_dir: String,
    /// The extended info packet.
    pub extra: ExtendedClientInfo,
}

/// Write `s` as UTF-16LE plus a null terminator, returning the string's byte length
/// **excluding** the terminator.
fn put_utf16_nul(out: &mut Vec<u8>, s: &str) -> usize {
    let start = out.len();
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    let len = out.len() - start;
    out.extend_from_slice(&[0, 0]);
    len
}

/// Write `s` as UTF-16LE into exactly `total` bytes, zero-padded (no separate terminator
/// convention — the padding is the terminator).
fn put_utf16_padded(out: &mut Vec<u8>, s: &str, total: usize) {
    let max_units = total / 2 - 1;
    let start = out.len();
    for unit in s.encode_utf16().take(max_units) {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend(std::iter::repeat_n(0u8, total - (out.len() - start)));
}

/// Read a fixed UTF-16LE field of `total` bytes, trimming trailing nulls.
fn read_utf16_padded(cur: &mut ReadCursor<'_>, total: usize) -> Result<String, DecodeError> {
    let bytes = cur.read_slice(total)?;
    Ok(utf16_string(bytes))
}

/// Decode UTF-16LE bytes up to the first null unit.
fn utf16_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

impl ClientInfo {
    /// Encode the full Client Info PDU: basic security header ([`SEC_INFO_PKT`]) + `TS_INFO` +
    /// `TS_EXTENDED_INFO`. This is the byte blob carried by the MCS Send Data Request.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::header_estimate(self));
        encode_basic_security_header(&mut out, SEC_INFO_PKT);
        self.encode_body_into(&mut out);
        out
    }

    fn header_estimate(&self) -> usize {
        64 + TimezoneInfo::ENCODED_LEN
            + (self.domain.len()
                + self.username.len()
                + self.password.len()
                + self.alternate_shell.len()
                + self.work_dir.len()
                + self.extra.address.len()
                + self.extra.dir.len())
                * 2
    }

    /// Encode only the `TS_INFO_PACKET` + `TS_EXTENDED_INFO_PACKET` body (no security header).
    pub fn encode_body_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.code_page.to_le_bytes());
        // The encoder writes UTF-16 strings unconditionally, so INFO_UNICODE must be set on the
        // wire regardless of the caller's bits — encoding mechanics, not policy.
        let flags = self.flags | ClientInfoFlags::UNICODE;
        out.extend_from_slice(&flags.bits().to_le_bytes());

        // The five cb* fields exclude each string's null terminator. Reserve, write strings,
        // backfill the lengths.
        let cb_at = out.len();
        out.extend_from_slice(&[0u8; 10]);
        let mut cbs = [0u16; 5];
        let strings = [
            &self.domain,
            &self.username,
            &self.password,
            &self.alternate_shell,
            &self.work_dir,
        ];
        for (i, s) in strings.into_iter().enumerate() {
            cbs[i] = put_utf16_nul(out, s) as u16;
        }
        for (i, cb) in cbs.iter().enumerate() {
            out[cb_at + i * 2..cb_at + i * 2 + 2].copy_from_slice(&cb.to_le_bytes());
        }

        // TS_EXTENDED_INFO_PACKET. Unlike the cb* fields above, these two lengths INCLUDE the
        // null terminator.
        out.extend_from_slice(&self.extra.address_family.to_le_bytes());
        let len_at = out.len();
        out.extend_from_slice(&[0u8; 2]);
        let n = put_utf16_nul(out, &self.extra.address) + 2;
        out[len_at..len_at + 2].copy_from_slice(&(n as u16).to_le_bytes());
        let len_at = out.len();
        out.extend_from_slice(&[0u8; 2]);
        let n = put_utf16_nul(out, &self.extra.dir) + 2;
        out[len_at..len_at + 2].copy_from_slice(&(n as u16).to_le_bytes());

        self.extra.timezone.encode_into(out);
        out.extend_from_slice(&self.extra.session_id.to_le_bytes());
        out.extend_from_slice(&self.extra.performance_flags.to_le_bytes());
        match self.extra.reconnect_cookie {
            // cbAutoReconnectCookie is always emitted; zero means "no cookie yet" (epic #25
            // populates it from Save Session Info).
            None => out.extend_from_slice(&0u16.to_le_bytes()),
            Some(cookie) => {
                out.extend_from_slice(&(cookie.len() as u16).to_le_bytes());
                out.extend_from_slice(&cookie);
            }
        }
    }

    /// Decode a full Client Info PDU (security header + body). Round-trip aid; the client never
    /// receives this PDU in production.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(bytes, "client info pdu");
        let flags = decode_basic_security_header(&mut cur)?;
        if flags & SEC_INFO_PKT == 0 {
            return Err(DecodeError::InvalidField {
                field: "securityHeader.flags",
                reason: "SEC_INFO_PKT not set",
            });
        }
        Self::decode_body(&mut cur)
    }

    fn decode_body(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let code_page = cur.read_u32_le()?;
        let flags = ClientInfoFlags::from_bits(cur.read_u32_le()?);
        if !flags.contains(ClientInfoFlags::UNICODE) {
            return Err(DecodeError::InvalidField {
                field: "TS_INFO_PACKET.flags",
                reason: "only INFO_UNICODE encodings are supported",
            });
        }
        let mut cbs = [0usize; 5];
        for cb in &mut cbs {
            *cb = cur.read_u16_le()? as usize;
        }
        let mut strings: [String; 5] = Default::default();
        for (i, s) in strings.iter_mut().enumerate() {
            // cb excludes the null terminator; the field includes it.
            *s = utf16_string(cur.read_slice(cbs[i] + 2)?);
        }
        let [domain, username, password, alternate_shell, work_dir] = strings;

        let address_family = cur.read_u16_le()?;
        let n = cur.read_u16_le()? as usize; // includes the null terminator
        let address = utf16_string(cur.read_slice(n)?);
        let n = cur.read_u16_le()? as usize;
        let dir = utf16_string(cur.read_slice(n)?);
        let timezone = TimezoneInfo::decode(cur)?;
        let session_id = cur.read_u32_le()?;
        let performance_flags = cur.read_u32_le()?;
        let cookie_len = cur.read_u16_le()? as usize;
        let reconnect_cookie = match cookie_len {
            0 => None,
            28 => {
                let mut cookie = [0u8; 28];
                cookie.copy_from_slice(cur.read_slice(28)?);
                Some(cookie)
            }
            _ => {
                return Err(DecodeError::InvalidField {
                    field: "cbAutoReconnectCookie",
                    reason: "cookie length is neither 0 nor 28",
                });
            }
        };

        Ok(Self {
            code_page,
            flags,
            domain,
            username,
            password,
            alternate_shell,
            work_dir,
            extra: ExtendedClientInfo {
                address_family,
                address,
                dir,
                timezone,
                session_id,
                performance_flags,
                reconnect_cookie,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_info() -> ClientInfo {
        ClientInfo {
            code_page: 0,
            flags: ClientInfoFlags::MOUSE
                | ClientInfoFlags::AUTOLOGON
                | ClientInfoFlags::LOGON_NOTIFY
                | ClientInfoFlags::LOGON_ERRORS
                | ClientInfoFlags::MOUSE_HAS_WHEEL,
            domain: "WORKGROUP".to_string(),
            username: "rdptest".to_string(),
            password: String::new(),
            alternate_shell: String::new(),
            work_dir: String::new(),
            extra: ExtendedClientInfo {
                address_family: ADDRESS_FAMILY_INET,
                address: "192.168.0.10".to_string(),
                dir: "C:\\justrdp".to_string(),
                timezone: TimezoneInfo {
                    bias: -540, // KST, UTC+9
                    standard_name: "Korea Standard Time".to_string(),
                    standard_bias: 0,
                    daylight_name: "Korea Daylight Time".to_string(),
                    daylight_bias: -60,
                },
                session_id: 0,
                performance_flags: 0x0000_0007,
                reconnect_cookie: None,
            },
        }
    }

    #[test]
    fn client_info_round_trips_through_the_security_header() {
        let info = client_info();
        let bytes = info.encode();
        // The security header leads with SEC_INFO_PKT, flagsHi 0.
        assert_eq!(&bytes[..4], &[0x40, 0x00, 0x00, 0x00]);
        let mut decoded = ClientInfo::decode(&bytes).unwrap();
        // The encoder forces INFO_UNICODE; normalize before comparing.
        let expected_flags = info.flags | ClientInfoFlags::UNICODE;
        assert_eq!(decoded.flags, expected_flags);
        decoded.flags = info.flags;
        assert_eq!(decoded, info);
    }

    #[test]
    fn cb_fields_exclude_the_null_terminator_in_ts_info() {
        // A single-character username: cbUserName must be 2 (one UTF-16 unit), while the field
        // itself occupies 4 bytes (unit + null terminator).
        let mut info = client_info();
        info.domain = String::new();
        info.username = "a".to_string();
        let bytes = info.encode();
        // Offsets: header 4 + codePage 4 + flags 4 = 12; cbDomain at 12, cbUserName at 14.
        assert_eq!(&bytes[12..14], &[0x00, 0x00]); // cbDomain = 0
        assert_eq!(&bytes[14..16], &[0x02, 0x00]); // cbUserName = 2, null excluded
    }

    #[test]
    fn extended_lengths_include_the_null_terminator() {
        let mut info = client_info();
        info.domain = String::new();
        info.username = String::new();
        info.password = String::new();
        info.alternate_shell = String::new();
        info.work_dir = String::new();
        info.extra.address = "ab".to_string();
        let bytes = info.encode();
        // Header 4 + fixed TS_INFO 18 + five empty strings (2 bytes null each) = 32; then
        // addressFamily (2) at 32, cbClientAddress at 34: "ab" = 4 bytes + 2 null = 6.
        assert_eq!(&bytes[34..36], &[0x06, 0x00]);
    }

    #[test]
    fn timezone_block_is_exactly_172_bytes() {
        let mut out = Vec::new();
        client_info().extra.timezone.encode_into(&mut out);
        assert_eq!(out.len(), TimezoneInfo::ENCODED_LEN);
    }

    #[test]
    fn empty_cookie_encodes_a_zero_length_field() {
        let bytes = client_info().encode();
        // The very last two bytes are cbAutoReconnectCookie = 0 (the criterion: the field is
        // present and empty until epic #25 populates it).
        assert_eq!(&bytes[bytes.len() - 2..], &[0x00, 0x00]);
    }

    #[test]
    fn reconnect_cookie_round_trips_when_present() {
        let mut info = client_info();
        info.extra.reconnect_cookie = Some([0xAB; 28]);
        let bytes = info.encode();
        let decoded = ClientInfo::decode(&bytes).unwrap();
        assert_eq!(decoded.extra.reconnect_cookie, Some([0xAB; 28]));
    }

    #[test]
    fn truncated_input_is_a_typed_error_not_a_panic() {
        let bytes = client_info().encode();
        for cut in [0, 3, 11, 30, bytes.len() - 1] {
            let err = ClientInfo::decode(&bytes[..cut]).unwrap_err();
            assert!(
                matches!(err, DecodeError::NotEnoughBytes { .. }),
                "cut at {cut}: {err:?}"
            );
        }
    }
}
