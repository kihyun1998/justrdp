//! Save Session Info PDU (`[MS-RDPBCGR]` 2.2.10.1): the server's notification of who logged
//! on, into which session, whether the logon carried an error, and the cookie that would let
//! this client resume that session. Four `infoType` variants share one Share **Data** PDU body
//! (`PDUTYPE2_SAVE_SESSION_INFO`) — frame them with [`crate::share::encode_share_data`].
//!
//! Decode only: justrdp is a client and this PDU is server-to-client. There is no encoder here,
//! which is why the tests replay captured bytes and hand-built bodies rather than round-tripping.

use crate::DecodeError;
use crate::cursor::{ReadCursor, utf16_string};

/// `infoType`: the `infoData` that follows is a Logon Info Version 1 (2.2.10.1.1.1).
pub const INFOTYPE_LOGON: u32 = 0x0000_0000;
/// `infoType`: the `infoData` that follows is a Logon Info Version 2 (2.2.10.1.1.2).
pub const INFOTYPE_LOGON_LONG: u32 = 0x0000_0001;
/// `infoType`: the `infoData` that follows is 576 bytes of padding (2.2.10.1.1.3).
pub const INFOTYPE_LOGON_PLAINNOTIFY: u32 = 0x0000_0002;
/// `infoType`: the `infoData` that follows is a Logon Info Extended (2.2.10.1.1.4).
pub const INFOTYPE_LOGON_EXTENDED_INFO: u32 = 0x0000_0003;

/// `FieldsPresent`: `LogonFields` holds a Server Auto-Reconnect Packet (2.2.4.2).
pub const LOGON_EX_AUTORECONNECTCOOKIE: u32 = 0x0000_0001;
/// `FieldsPresent`: `LogonFields` holds a Logon Errors Info (2.2.10.1.1.4.1.1).
pub const LOGON_EX_LOGONERRORS: u32 = 0x0000_0002;

/// `errorNotificationData` (2.2.10.1.1.4.1.1): the credentials supplied were invalid. The data
/// field carries one of these four when the type is an NTSTATUS
/// ([`LogonErrorNotification::Other`]); for the seven `LOGON_MSG_*` types it is a session ID.
pub const LOGON_FAILED_BAD_PASSWORD: u32 = 0x0000_0000;
/// `errorNotificationData`: the password must be changed.
pub const LOGON_FAILED_UPDATE_PASSWORD: u32 = 0x0000_0001;
/// `errorNotificationData`: the logon failed for another reason.
pub const LOGON_FAILED_OTHER: u32 = 0x0000_0002;
/// `errorNotificationData`: a warning, not a failure.
pub const LOGON_WARNING: u32 = 0x0000_0003;

/// `errorNotificationType` (2.2.10.1.1.4.1.1) — what the server is telling the client about
/// the logon.
///
/// Typed with a raw-preserving [`Self::Other`] arm, the shape
/// [`crate::errinfo::ErrorInfo`] already uses for this repo's other catalogued server status
/// code: decoding **never fails on the value**, because a future server speaks first and the
/// notification must survive it. IronRDP enumerates the same eight and rejects anything else;
/// FreeRDP types none of them and passes the `u32` through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonErrorNotification {
    /// 0xFFFFFFF8 — the session is busy; the data field holds the options.
    SessionBusyOptions,
    /// 0xFFFFFFF9 — the disconnection was refused.
    DisconnectRefused,
    /// 0xFFFFFFFA — the user has no permission to log on.
    NoPermission,
    /// 0xFFFFFFFB — another session may be disconnected to free this one.
    BumpOptions,
    /// 0xFFFFFFFC — a reconnect is offered.
    ReconnectOptions,
    /// 0xFFFFFFFD — the session is terminating.
    SessionTerminate,
    /// 0xFFFFFFFE — the session continues. This is what the real VM sends on every logon.
    SessionContinue,
    /// 0xFFFFFFFF — access was denied.
    AccessDenied,
    /// Any other value — which 2.2.10.1.1.4.1.1 defines as an **NTSTATUS** (`[MS-ERREF]` 2.3.1),
    /// not as an unknown. Its `errorNotificationData` is one of the `LOGON_FAILED_*` codes.
    Other(u32),
}

impl LogonErrorNotification {
    /// Classify a wire value. Total by construction.
    fn from_u32(value: u32) -> Self {
        match value {
            0xFFFF_FFF8 => Self::SessionBusyOptions,
            0xFFFF_FFF9 => Self::DisconnectRefused,
            0xFFFF_FFFA => Self::NoPermission,
            0xFFFF_FFFB => Self::BumpOptions,
            0xFFFF_FFFC => Self::ReconnectOptions,
            0xFFFF_FFFD => Self::SessionTerminate,
            0xFFFF_FFFE => Self::SessionContinue,
            0xFFFF_FFFF => Self::AccessDenied,
            other => Self::Other(other),
        }
    }

    /// The value as it appeared on the wire.
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::SessionBusyOptions => 0xFFFF_FFF8,
            Self::DisconnectRefused => 0xFFFF_FFF9,
            Self::NoPermission => 0xFFFF_FFFA,
            Self::BumpOptions => 0xFFFF_FFFB,
            Self::ReconnectOptions => 0xFFFF_FFFC,
            Self::SessionTerminate => 0xFFFF_FFFD,
            Self::SessionContinue => 0xFFFF_FFFE,
            Self::AccessDenied => 0xFFFF_FFFF,
            Self::Other(raw) => *raw,
        }
    }

    /// Whether [`LogonErrorsInfo::notification_data`] is a **session ID** rather than one of
    /// the `LOGON_FAILED_*` codes.
    ///
    /// `[MS-RDPBCGR]` 2.2.10.1.1.4.1.1 decides it by the type, and says so for each value: all
    /// seven `LOGON_MSG_*` types read *"The session identifier is specified by the
    /// ErrorNotificationData field"*; for [`Self::AccessDenied`] the data *"SHOULD be ignored"*;
    /// and any other type is an NTSTATUS, whose data is a `LOGON_FAILED_*` code.
    ///
    /// Deciding it by the data's own value is the mistake to avoid. IronRDP maps `0..=3` to an
    /// error-code enum whatever the type says, and the real VM sends [`Self::SessionContinue`]
    /// with the logon's `SessionId` in it — small numbers that land inside that range.
    pub fn data_is_session_id(&self) -> bool {
        !matches!(self, Self::AccessDenied | Self::Other(_))
    }
}

/// The fixed `Domain` field of a Logon Info Version 1 — 26 UTF-16 units.
const DOMAIN_FIELD_LEN: usize = 52;
/// The fixed `UserName` field of a Logon Info Version 1 — 256 UTF-16 units.
const USER_FIELD_LEN: usize = 512;
/// `TS_PLAIN_NOTIFY` is padding and nothing else.
const PLAIN_NOTIFY_PAD_LEN: usize = 576;
/// The `Pad` between a Logon Info Version 2's lengths and its strings.
const LOGON_INFO_V2_PAD_LEN: usize = 558;
/// The `Pad` that ends a Logon Info Extended.
const LOGON_EX_PAD_LEN: usize = 570;
/// The only legal `Version` of a Logon Info Version 2.
const SAVE_SESSION_PDU_VERSION_ONE: u16 = 0x0001;
/// `cbLen` of an `ARC_SC_PRIVATE_PACKET`, which counts itself.
const ARC_SC_PACKET_LEN: u32 = 28;
/// `ArcRandomBits` of an `ARC_SC_PRIVATE_PACKET`.
const ARC_RANDOM_BITS_LEN: usize = 16;

/// One Save Session Info PDU body, discriminated by its `infoType`.
///
/// [`Self::Unknown`] is the tolerant arm and is not a wire value: an `infoType` outside the four
/// 2.2.10.1.1 defines is carried rather than rejected, because a future RDP version's fifth type
/// is not an attack (ADR-0009) and failing the session over one would be worse than any client
/// in the field. The references split here — FreeRDP warns and succeeds, IronRDP errors — and
/// neither can tell the host it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveSessionInfo {
    /// `INFOTYPE_LOGON` — a Logon Info Version 1.
    Logon(LogonInfo),
    /// `INFOTYPE_LOGON_LONG` — a Logon Info Version 2.
    LogonLong(LogonInfo),
    /// `INFOTYPE_LOGON_PLAINNOTIFY` — "the user logged on", with no detail.
    PlainNotify,
    /// `INFOTYPE_LOGON_EXTENDED_INFO` — a Logon Info Extended.
    Extended(LogonInfoExtended),
    /// An `infoType` this revision of `[MS-RDPBCGR]` does not define. The body is not decoded.
    Unknown {
        /// The value read off the wire.
        info_type: u32,
    },
}

impl SaveSessionInfo {
    /// Decode the Share Data body of a `PDUTYPE2_SAVE_SESSION_INFO` PDU.
    ///
    /// The cursor is left where the variant's decoder finished. A Logon Info Version 2 may leave
    /// bytes unread: FreeRDP records undocumented trailing padding from Windows 11 and seeks past
    /// it, so full consumption is not an invariant of this PDU and is not asserted.
    pub fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let info_type = cur.read_u32_le()?;
        match info_type {
            INFOTYPE_LOGON => Ok(Self::Logon(LogonInfo::decode_v1(cur)?)),
            INFOTYPE_LOGON_LONG => Ok(Self::LogonLong(LogonInfo::decode_v2(cur)?)),
            INFOTYPE_LOGON_PLAINNOTIFY => {
                cur.read_slice(PLAIN_NOTIFY_PAD_LEN)?;
                Ok(Self::PlainNotify)
            }
            INFOTYPE_LOGON_EXTENDED_INFO => Ok(Self::Extended(LogonInfoExtended::decode(cur)?)),
            _ => Ok(Self::Unknown { info_type }),
        }
    }
}

/// Who logged on, and into which session. Both `infoType` variants that carry logon detail
/// decode into this — version 1's fields are fixed-length and version 2's are variable, and
/// nothing past the decoder cares which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonInfo {
    /// `Domain` — the domain the user logged on to, up to the first null unit.
    pub domain: String,
    /// `UserName` — the account the logon used, up to the first null unit.
    pub user: String,
    /// `SessionId` — the session's ID on the server, according to the server.
    pub session_id: u32,
}

impl LogonInfo {
    /// Decode a `TS_LOGON_INFO` (2.2.10.1.1.1): fixed 52-byte and 512-byte string fields.
    ///
    /// `cbDomain` and `cbUserName` bound the character data *inside* those fixed fields, so they
    /// frame nothing — but a value past the field is nonsense and both references reject it.
    fn decode_v1(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let cb_domain = cur.read_u32_le()?;
        if cb_domain as usize > DOMAIN_FIELD_LEN {
            return Err(DecodeError::InvalidField {
                field: "LogonInfoV1.cbDomain",
                reason: "longer than the fixed 52-byte Domain field",
            });
        }
        let domain = utf16_string(cur.read_slice(DOMAIN_FIELD_LEN)?);
        let cb_user = cur.read_u32_le()?;
        if cb_user as usize > USER_FIELD_LEN {
            return Err(DecodeError::InvalidField {
                field: "LogonInfoV1.cbUserName",
                reason: "longer than the fixed 512-byte UserName field",
            });
        }
        let user = utf16_string(cur.read_slice(USER_FIELD_LEN)?);
        let session_id = cur.read_u32_le()?;
        Ok(Self {
            domain,
            user,
            session_id,
        })
    }

    /// Decode a `TS_LOGON_INFO_VERSION_2` (2.2.10.1.1.2): lengths, a 558-byte pad, then the
    /// strings those lengths size.
    ///
    /// `Size` is read and discarded. 2.2.10.1.1.2 defines it as the structure excluding `Domain`
    /// and `UserName`, which is 576 — and FreeRDP records that Windows Server 2019 sends 18, the
    /// fixed fields without the pad. IronRDP accepts **only** 18 and so rejects a server that
    /// obeys the spec. Neither implementation frames from it, and there is nothing it could
    /// decide here: the pad is 558 bytes whatever `Size` says.
    fn decode_v2(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let version = cur.read_u16_le()?;
        if version != SAVE_SESSION_PDU_VERSION_ONE {
            return Err(DecodeError::InvalidField {
                field: "LogonInfoV2.Version",
                reason: "not SAVE_SESSION_PDU_VERSION_ONE",
            });
        }
        let _size = cur.read_u32_le()?;
        let session_id = cur.read_u32_le()?;
        let cb_domain = cur.read_u32_le()? as usize;
        let cb_user = cur.read_u32_le()? as usize;
        // Here the lengths do frame: the strings that follow the pad are sized by them. Both
        // references cap them at version 1's fixed field sizes, which 2.2.10.1.1.2 does not
        // state — FreeRDP says so in as many words.
        if cb_domain > DOMAIN_FIELD_LEN {
            return Err(DecodeError::InvalidField {
                field: "LogonInfoV2.cbDomain",
                reason: "longer than version 1's 52-byte Domain field",
            });
        }
        if cb_user > USER_FIELD_LEN {
            return Err(DecodeError::InvalidField {
                field: "LogonInfoV2.cbUserName",
                reason: "longer than version 1's 512-byte UserName field",
            });
        }
        cur.read_slice(LOGON_INFO_V2_PAD_LEN)?;
        let domain = utf16_string(cur.read_slice(cb_domain)?);
        let user = utf16_string(cur.read_slice(cb_user)?);
        Ok(Self {
            domain,
            user,
            session_id,
        })
    }
}

/// A `TS_LOGON_INFO_EXTENDED` (2.2.10.1.1.4): the auto-reconnect cookie, the logon error, or
/// neither — all four combinations of the two `FieldsPresent` flags are legal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonInfoExtended {
    /// `FieldsPresent` verbatim, including bits beyond the two this revision defines.
    pub fields_present: u32,
    /// The Server Auto-Reconnect Packet, present iff [`LOGON_EX_AUTORECONNECTCOOKIE`] is set.
    pub auto_reconnect: Option<ServerAutoReconnect>,
    /// The logon error or warning, present iff [`LOGON_EX_LOGONERRORS`] is set.
    pub logon_error: Option<LogonErrorsInfo>,
}

impl LogonInfoExtended {
    /// Decode the body.
    ///
    /// `Length` is read and discarded, and the 570-byte `Pad` is consumed from the cursor rather
    /// than skipped by arithmetic over it. 2.2.10.1.1.4 calls `Length` *"the total size in bytes
    /// of this structure, including the variable LogonFields field"* — which reads as including
    /// the pad, while IronRDP's encoder writes the total *without* it. Neither reference frames
    /// from the field, and a decoder that did would disagree with one of them whichever reading
    /// it took.
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        let _length = cur.read_u16_le()?;
        let fields_present = cur.read_u32_le()?;
        let auto_reconnect = if fields_present & LOGON_EX_AUTORECONNECTCOOKIE != 0 {
            Some(ServerAutoReconnect::decode(cur)?)
        } else {
            None
        };
        let logon_error = if fields_present & LOGON_EX_LOGONERRORS != 0 {
            Some(LogonErrorsInfo::decode(cur)?)
        } else {
            None
        };
        cur.read_slice(LOGON_EX_PAD_LEN)?;
        Ok(Self {
            fields_present,
            auto_reconnect,
            logon_error,
        })
    }
}

/// The `ARC_SC_PRIVATE_PACKET` (2.2.4.2) the server issues so this client can resume the
/// session. The host stores it and hands it back on the next connect (issue #306); the
/// verifier that actually goes out is derived from [`Self::random_bits`], never these bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerAutoReconnect {
    /// `Version` — carried rather than checked. IronRDP rejects anything but 1 and drops the
    /// field; FreeRDP echoes the server's value back on reconnect, and so does this client
    /// (#306), which makes the `ARC_CS_PRIVATE_PACKET` derivation its reader.
    pub version: u32,
    /// `LogonId` — the session this cookie resumes.
    pub logon_id: u32,
    /// `ArcRandomBits` — the HMAC key that proves, on reconnect, that this client was the one
    /// last attached to the session.
    pub random_bits: [u8; ARC_RANDOM_BITS_LEN],
}

/// `random_bits` is a live credential: `[MS-RDPBCGR]` 5.5 has the client hold the cookie
/// *"in memory, never allowing programmatic access to it"*, and this type reaches the host
/// inside a `SessionOutput` that derives `Debug`. Redacted for the same reason
/// `justrdp_tokio::Credentials` redacts its password.
impl core::fmt::Debug for ServerAutoReconnect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerAutoReconnect")
            .field("version", &self.version)
            .field("logon_id", &self.logon_id)
            .field("random_bits", &"<redacted>")
            .finish()
    }
}

impl ServerAutoReconnect {
    /// Decode one `TS_LOGON_INFO_FIELD` holding an `ARC_SC_PRIVATE_PACKET`.
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        read_field_length(cur, "LogonInfoField.cbFieldData")?;
        let cb_len = cur.read_u32_le()?;
        if cb_len != ARC_SC_PACKET_LEN {
            return Err(DecodeError::InvalidField {
                field: "ArcScPrivatePacket.cbLen",
                reason: "not 28",
            });
        }
        let version = cur.read_u32_le()?;
        let logon_id = cur.read_u32_le()?;
        let mut random_bits = [0u8; ARC_RANDOM_BITS_LEN];
        random_bits.copy_from_slice(cur.read_slice(ARC_RANDOM_BITS_LEN)?);
        Ok(Self {
            version,
            logon_id,
            random_bits,
        })
    }
}

/// A `TS_LOGON_ERRORS_INFO` (2.2.10.1.1.4.1.1). Both fields are carried raw: the notification
/// type's eight values are the ones this revision names, and a server may send others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonErrorsInfo {
    /// `errorNotificationType`.
    pub notification_type: LogonErrorNotification,
    /// `errorNotificationData`, verbatim. Whether it is a `LOGON_FAILED_*` code or a session
    /// ID is decided by [`Self::notification_type`] — see
    /// [`LogonErrorNotification::data_is_session_id`].
    pub notification_data: u32,
}

impl LogonErrorsInfo {
    /// Decode one `TS_LOGON_INFO_FIELD` holding a `TS_LOGON_ERRORS_INFO`.
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        read_field_length(cur, "LogonInfoField.cbFieldData")?;
        let notification_type = LogonErrorNotification::from_u32(cur.read_u32_le()?);
        let notification_data = cur.read_u32_le()?;
        Ok(Self {
            notification_type,
            notification_data,
        })
    }

    /// A human-readable account of the notification, for logs and host UIs — the counterpart
    /// of [`crate::errinfo::ErrorInfo::description`].
    ///
    /// The data field is only spelled out where it is a code; where it is a session ID the
    /// number is the host's to use and saying "session 6" adds nothing a match could not.
    pub fn description(&self) -> String {
        use LogonErrorNotification as N;
        match self.notification_type {
            N::SessionBusyOptions => "the session is busy".into(),
            N::DisconnectRefused => "the disconnection was refused".into(),
            N::NoPermission => "no permission to log on".into(),
            N::BumpOptions => "another session may be disconnected".into(),
            N::ReconnectOptions => "a reconnect is offered".into(),
            N::SessionTerminate => "the session is terminating".into(),
            N::SessionContinue => "the session continues".into(),
            N::AccessDenied => "access denied".into(),
            N::Other(raw) => match self.notification_data {
                LOGON_FAILED_BAD_PASSWORD => "logon failed: bad password".into(),
                LOGON_FAILED_UPDATE_PASSWORD => "logon failed: the password must be changed".into(),
                LOGON_FAILED_OTHER => "logon failed".into(),
                LOGON_WARNING => "logon warning".into(),
                _ => format!("logon failed with NTSTATUS {raw:#010x}"),
            },
        }
    }
}

/// Read a `TS_LOGON_INFO_FIELD`'s `cbFieldData` and bound it against what is left.
///
/// The value frames nothing — each field this revision defines has a fixed size, and both
/// references decode that size rather than `cbFieldData` bytes. What it is good for is the
/// check FreeRDP makes: a length declaring more than the buffer holds is a malformed PDU, and
/// catching it here turns it into a typed error instead of a short read further down.
fn read_field_length(cur: &mut ReadCursor<'_>, field: &'static str) -> Result<u32, DecodeError> {
    let cb_field_data = cur.read_u32_le()?;
    if cb_field_data as usize > cur.remaining() {
        return Err(DecodeError::InvalidField {
            field,
            reason: "declares more bytes than the PDU holds",
        });
    }
    Ok(cb_field_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Size` as 2.2.10.1.1.2 defines it: everything but `Domain` and `UserName`.
    const LOGON_INFO_V2_SIZE_SPEC: u32 = 576;
    /// `Size` as Windows Server 2019 sends it, per FreeRDP: the fixed fields without the `Pad`.
    const LOGON_INFO_V2_SIZE_OBSERVED: u32 = 18;

    /// UTF-16LE with the mandatory null terminator, as `cbDomain` / `cbUserName` count it.
    fn utf16z(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend_from_slice(&[0, 0]);
        out
    }

    fn v1_body(domain: &str, user: &str, session_id: u32) -> Vec<u8> {
        let (d, u) = (utf16z(domain), utf16z(user));
        let mut out = INFOTYPE_LOGON.to_le_bytes().to_vec();
        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
        let mut field = d.clone();
        field.resize(DOMAIN_FIELD_LEN, 0);
        out.extend_from_slice(&field);
        out.extend_from_slice(&(u.len() as u32).to_le_bytes());
        let mut field = u.clone();
        field.resize(USER_FIELD_LEN, 0);
        out.extend_from_slice(&field);
        out.extend_from_slice(&session_id.to_le_bytes());
        out
    }

    fn v2_body(domain: &str, user: &str, session_id: u32, size: u32) -> Vec<u8> {
        let (d, u) = (utf16z(domain), utf16z(user));
        let mut out = INFOTYPE_LOGON_LONG.to_le_bytes().to_vec();
        out.extend_from_slice(&SAVE_SESSION_PDU_VERSION_ONE.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&session_id.to_le_bytes());
        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
        out.extend_from_slice(&(u.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0u8; LOGON_INFO_V2_PAD_LEN]);
        out.extend_from_slice(&d);
        out.extend_from_slice(&u);
        out
    }

    fn plain_notify_body() -> Vec<u8> {
        let mut out = INFOTYPE_LOGON_PLAINNOTIFY.to_le_bytes().to_vec();
        out.extend_from_slice(&[0u8; PLAIN_NOTIFY_PAD_LEN]);
        out
    }

    /// `cookie` and `error` select which `LogonFields` are present; the flags follow from them,
    /// so a body can never claim a field it does not carry by accident.
    fn extended_body(cookie: Option<(u32, u32, [u8; 16])>, error: Option<(u32, u32)>) -> Vec<u8> {
        let mut fields: Vec<u8> = Vec::new();
        let mut flags = 0u32;
        if let Some((version, logon_id, random_bits)) = cookie {
            flags |= LOGON_EX_AUTORECONNECTCOOKIE;
            fields.extend_from_slice(&ARC_SC_PACKET_LEN.to_le_bytes()); // cbFieldData
            fields.extend_from_slice(&ARC_SC_PACKET_LEN.to_le_bytes()); // cbLen
            fields.extend_from_slice(&version.to_le_bytes());
            fields.extend_from_slice(&logon_id.to_le_bytes());
            fields.extend_from_slice(&random_bits);
        }
        if let Some((notification_type, notification_data)) = error {
            flags |= LOGON_EX_LOGONERRORS;
            fields.extend_from_slice(&8u32.to_le_bytes()); // cbFieldData
            fields.extend_from_slice(&notification_type.to_le_bytes());
            fields.extend_from_slice(&notification_data.to_le_bytes());
        }
        let mut out = INFOTYPE_LOGON_EXTENDED_INFO.to_le_bytes().to_vec();
        out.extend_from_slice(&((6 + fields.len()) as u16).to_le_bytes()); // Length
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&fields);
        out.extend_from_slice(&[0u8; LOGON_EX_PAD_LEN]);
        out
    }

    /// Decode a whole body and assert the cursor is empty afterwards.
    ///
    /// The consumption half is the point, and it replaces what #304 asked for — *"assert the
    /// next PDU in the same batch still decodes"*. That assertion cannot fail: `session.rs`
    /// frames by TPKT and hands each Share Data PDU a cursor over one MCS indication, which is
    /// dropped when the arm returns, so nothing this decoder leaves unread can reach the next
    /// PDU. A short read is invisible from the batch and visible from here.
    fn decode_fully(body: &[u8]) -> SaveSessionInfo {
        let mut cur = ReadCursor::new(body, "test");
        let info = SaveSessionInfo::decode(&mut cur).expect("a well-formed body decodes");
        assert_eq!(cur.remaining(), 0, "the whole body must be consumed");
        info
    }

    #[test]
    fn logon_info_v1_carries_the_identity_and_the_session() {
        let info = decode_fully(&v1_body("CONTOSO", "rdptest", 0x0000_0002));
        assert_eq!(
            info,
            SaveSessionInfo::Logon(LogonInfo {
                domain: "CONTOSO".to_string(),
                user: "rdptest".to_string(),
                session_id: 2,
            })
        );
    }

    /// `Size` is declared two different ways in the wild and decides nothing here.
    ///
    /// 2.2.10.1.1.2 defines it as the structure excluding the two variable strings — 576 — and
    /// FreeRDP records that Windows Server 2019 sends 18, the fixed fields without the pad.
    /// IronRDP accepts **only** 18, so it rejects the value the spec asks for. Both decode here,
    /// and so does a third value no implementation expects: nothing downstream reads it.
    #[test]
    fn logon_info_v2_accepts_every_size_the_references_disagree_about() {
        let expected = SaveSessionInfo::LogonLong(LogonInfo {
            domain: "CONTOSO".to_string(),
            user: "rdptest".to_string(),
            session_id: 7,
        });
        for size in [LOGON_INFO_V2_SIZE_SPEC, LOGON_INFO_V2_SIZE_OBSERVED, 0] {
            assert_eq!(
                decode_fully(&v2_body("CONTOSO", "rdptest", 7, size)),
                expected,
                "Size = {size} must not change the decode"
            );
        }
    }

    #[test]
    fn plain_notify_consumes_its_576_byte_pad() {
        assert_eq!(
            decode_fully(&plain_notify_body()),
            SaveSessionInfo::PlainNotify
        );
    }

    /// All four combinations of the two `FieldsPresent` flags are legal, and the 570-byte pad
    /// follows whichever of them arrived.
    #[test]
    fn extended_decodes_every_combination_of_its_two_fields() {
        let bits = [0xAAu8; 16];
        let cookie = Some((1, 0x0000_03EA, bits));
        let error = Some((LogonErrorNotification::SessionContinue.as_u32(), 0));

        let both = decode_fully(&extended_body(cookie, error));
        let SaveSessionInfo::Extended(ext) = both else {
            panic!("expected Extended, got {both:?}");
        };
        assert_eq!(
            ext.fields_present,
            LOGON_EX_AUTORECONNECTCOOKIE | LOGON_EX_LOGONERRORS
        );
        assert_eq!(
            ext.auto_reconnect,
            Some(ServerAutoReconnect {
                version: 1,
                logon_id: 0x0000_03EA,
                random_bits: bits,
            })
        );
        assert_eq!(
            ext.logon_error,
            Some(LogonErrorsInfo {
                notification_type: LogonErrorNotification::SessionContinue,
                notification_data: 0,
            })
        );

        for (c, e, want_cookie, want_error) in [
            (cookie, None, true, false),
            (None, error, false, true),
            (None, None, false, false),
        ] {
            let info = decode_fully(&extended_body(c, e));
            let SaveSessionInfo::Extended(ext) = info else {
                panic!("expected Extended");
            };
            assert_eq!(ext.auto_reconnect.is_some(), want_cookie);
            assert_eq!(ext.logon_error.is_some(), want_error);
        }
    }

    /// An `infoType` outside the four defined ones is carried, not rejected — and is still
    /// something the host can observe, which is the whole point of #304.
    #[test]
    fn an_undefined_info_type_is_carried_rather_than_fatal() {
        let mut body = 0x0000_0009u32.to_le_bytes().to_vec();
        body.extend_from_slice(&[0xFF; 8]);
        let mut cur = ReadCursor::new(&body, "test");
        assert_eq!(
            SaveSessionInfo::decode(&mut cur).expect("an unknown infoType is not fatal"),
            SaveSessionInfo::Unknown { info_type: 9 }
        );
    }

    #[test]
    fn a_version_other_than_one_is_rejected() {
        let mut body = v2_body("CONTOSO", "rdptest", 7, LOGON_INFO_V2_SIZE_SPEC);
        body[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            SaveSessionInfo::decode(&mut ReadCursor::new(&body, "test")).unwrap_err(),
            DecodeError::InvalidField {
                field: "LogonInfoV2.Version",
                reason: "not SAVE_SESSION_PDU_VERSION_ONE",
            }
        );
    }

    /// A string length past its field is nonsense in either version, and both references say so.
    #[test]
    fn a_string_length_past_its_field_is_rejected_in_both_versions() {
        let mut v1 = v1_body("CONTOSO", "rdptest", 2);
        v1[4..8].copy_from_slice(&(DOMAIN_FIELD_LEN as u32 + 2).to_le_bytes());
        assert_eq!(
            SaveSessionInfo::decode(&mut ReadCursor::new(&v1, "test")).unwrap_err(),
            DecodeError::InvalidField {
                field: "LogonInfoV1.cbDomain",
                reason: "longer than the fixed 52-byte Domain field",
            }
        );

        let mut v2 = v2_body("CONTOSO", "rdptest", 7, LOGON_INFO_V2_SIZE_SPEC);
        v2[14..18].copy_from_slice(&(DOMAIN_FIELD_LEN as u32 + 2).to_le_bytes());
        assert_eq!(
            SaveSessionInfo::decode(&mut ReadCursor::new(&v2, "test")).unwrap_err(),
            DecodeError::InvalidField {
                field: "LogonInfoV2.cbDomain",
                reason: "longer than version 1's 52-byte Domain field",
            }
        );
    }

    #[test]
    fn an_auto_reconnect_cookie_that_is_not_28_bytes_is_rejected() {
        let mut body = extended_body(Some((1, 1, [0; 16])), None);
        // cbLen sits right after infoType(4) + Length(2) + FieldsPresent(4) + cbFieldData(4).
        body[14..18].copy_from_slice(&27u32.to_le_bytes());
        assert_eq!(
            SaveSessionInfo::decode(&mut ReadCursor::new(&body, "test")).unwrap_err(),
            DecodeError::InvalidField {
                field: "ArcScPrivatePacket.cbLen",
                reason: "not 28",
            }
        );
    }

    /// `cbFieldData` is bounded against what is left, and against nothing else.
    ///
    /// The rejection alone does not pin that: `u32::MAX` is past every candidate bound, so a
    /// decoder comparing it to the cursor's *position* would reject it too and look correct. The
    /// second half is where the two differ — a `cbFieldData` larger than the field it introduces
    /// but still inside the PDU is legal, because the value frames nothing here and each field
    /// this revision defines has a fixed size. Only a bound against the remainder accepts it.
    #[test]
    fn a_field_length_is_bounded_against_what_is_left_of_the_pdu() {
        let mut body = extended_body(Some((1, 1, [0; 16])), None);
        body[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            SaveSessionInfo::decode(&mut ReadCursor::new(&body, "test")).unwrap_err(),
            DecodeError::InvalidField {
                field: "LogonInfoField.cbFieldData",
                reason: "declares more bytes than the PDU holds",
            }
        );

        let mut body = extended_body(Some((1, 1, [0; 16])), None);
        body[10..14].copy_from_slice(&100u32.to_le_bytes());
        let info = decode_fully(&body);
        let SaveSessionInfo::Extended(ext) = info else {
            panic!("expected Extended");
        };
        assert_eq!(
            ext.auto_reconnect.map(|c| c.logon_id),
            Some(1),
            "a cbFieldData inside the PDU is legal and the fixed packet is read regardless"
        );
    }

    /// Every prefix of every variant is a typed error and never a panic
    /// (`docs/map/invariant/untrusted-decode-never-panics.md`). The pads are what make this
    /// worth running: they are the longest reads in the PDU and the easiest to truncate into.
    #[test]
    fn every_truncation_of_every_variant_is_a_typed_error() {
        let bodies = [
            v1_body("CONTOSO", "rdptest", 2),
            v2_body("CONTOSO", "rdptest", 7, LOGON_INFO_V2_SIZE_SPEC),
            plain_notify_body(),
            extended_body(
                Some((1, 1, [0; 16])),
                Some((LogonErrorNotification::AccessDenied.as_u32(), 2)),
            ),
        ];
        for body in &bodies {
            for len in 0..body.len() {
                let mut cur = ReadCursor::new(&body[..len], "truncated");
                let _ = SaveSessionInfo::decode(&mut cur);
            }
        }
    }

    /// An `errorNotificationType` outside the eight named ones is carried, not rejected.
    ///
    /// 2.2.10.1.1.4.1.1 defines any such value as an NTSTATUS, so it is expected rather than
    /// exotic. The `Other(u32)` arm is what made typing this field safe at all — `errinfo::ErrorInfo`
    /// took the same exit for the same reason. IronRDP enumerates the same eight values with no
    /// fallback and errors on a ninth, which turns a notification the client could have ignored
    /// into a dead session.
    #[test]
    fn an_unrecognised_notification_type_is_carried_verbatim() {
        let body = extended_body(None, Some((0xDEAD_BEEF, 7)));
        let info = decode_fully(&body);
        let SaveSessionInfo::Extended(ext) = info else {
            panic!("expected Extended");
        };
        let err = ext.logon_error.expect("LOGON_ERRORS was set");
        assert_eq!(
            err.notification_type,
            LogonErrorNotification::Other(0xDEAD_BEEF)
        );
        assert_eq!(err.notification_type.as_u32(), 0xDEAD_BEEF, "round-trips");
        assert_eq!(err.notification_data, 7, "and the data is untouched");
        assert!(
            err.description().contains("0xdeadbeef"),
            "an unrecognised type names its value: {}",
            err.description()
        );
    }

    /// Which `errorNotificationType` values make `errorNotificationData` a session ID.
    ///
    /// **The expected values come from `[MS-RDPBCGR]` 2.2.10.1.1.4.1.1, not from the code.** This
    /// test used to assert a classification derived from plan.md and IronRDP — four
    /// "offer-shaped" types — and the code shared the same model, so the two confirmed each other
    /// and mutations that broke the code reddened it. The spec says otherwise: every one of the
    /// seven `LOGON_MSG_*` values reads *"The session identifier is specified by the
    /// ErrorNotificationData field"*, `ERROR_CODE_ACCESS_DENIED`'s data *"SHOULD be ignored"*, and
    /// any other type is an NTSTATUS, whose data is one of the `LOGON_FAILED_*` codes.
    ///
    /// The real VM agrees where it reaches: `SessionContinue` carried the logon's `SessionId`
    /// on seven of seven logons.
    #[test]
    fn the_data_field_is_a_session_id_for_every_logon_msg_type_per_the_spec() {
        // "The session identifier is specified by the ErrorNotificationData field."
        for t in [
            LogonErrorNotification::SessionBusyOptions,
            LogonErrorNotification::DisconnectRefused,
            LogonErrorNotification::NoPermission,
            LogonErrorNotification::BumpOptions,
            LogonErrorNotification::ReconnectOptions,
            LogonErrorNotification::SessionTerminate,
            LogonErrorNotification::SessionContinue,
        ] {
            assert!(
                t.data_is_session_id(),
                "{t:?}: the spec says the data is a session ID"
            );
        }
        // ERROR_CODE_ACCESS_DENIED: "SHOULD be ignored". An NTSTATUS: a LOGON_FAILED_* code.
        for t in [
            LogonErrorNotification::AccessDenied,
            LogonErrorNotification::Other(0xC000_006D), // STATUS_LOGON_FAILURE
        ] {
            assert!(
                !t.data_is_session_id(),
                "{t:?}: the data is not a session ID"
            );
        }
    }

    /// Every named value round-trips through the wire representation, and no two share one.
    #[test]
    fn the_eight_named_notification_types_are_distinct_and_round_trip() {
        let named = [
            LogonErrorNotification::SessionBusyOptions,
            LogonErrorNotification::DisconnectRefused,
            LogonErrorNotification::NoPermission,
            LogonErrorNotification::BumpOptions,
            LogonErrorNotification::ReconnectOptions,
            LogonErrorNotification::SessionTerminate,
            LogonErrorNotification::SessionContinue,
            LogonErrorNotification::AccessDenied,
        ];
        let mut seen: Vec<u32> = Vec::new();
        for t in named {
            let raw = t.as_u32();
            assert_eq!(LogonErrorNotification::from_u32(raw), t, "{t:?}");
            assert!(!seen.contains(&raw), "{t:?} reuses {raw:#010x}");
            seen.push(raw);
        }
        assert_eq!(seen.len(), 8);
    }

    /// The cookie is the key to an HMAC that resumes the session, and it reaches the host inside
    /// a `SessionOutput` that derives `Debug`. `[MS-RDPBCGR]` 5.5 has the client hold it
    /// *"never allowing programmatic access"*; the least this crate can do is keep it out of
    /// whatever logs the output.
    #[test]
    fn the_reconnect_cookie_is_not_printed_by_debug() {
        let cookie = ServerAutoReconnect {
            version: 1,
            logon_id: 0x0000_03EA,
            random_bits: [0xAB; 16],
        };
        let printed = format!("{cookie:?}");
        assert!(!printed.contains("171"), "random_bits leaked: {printed}");
        assert!(!printed.contains("ab"), "random_bits leaked: {printed}");
        assert!(printed.contains("<redacted>"), "got {printed}");
        assert!(
            printed.contains("1002"),
            "logon_id must stay visible: {printed}"
        );
    }
}
