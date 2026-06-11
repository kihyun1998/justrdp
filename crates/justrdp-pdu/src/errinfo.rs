//! The Set Error Info PDU's error code (MS-RDPBCGR 2.2.5.1.1 `ServerSetErrorInfoPdu`) — the
//! server's attribution for why the session is about to end, sent moments before the socket
//! closes (gated on the client advertising `SUPPORT_ERR_INFO_PDU` in its
//! `earlyCapabilityFlags`). Decode only; the classification of codes into host-reaction
//! buckets lives in the `justrdp` core.

use crate::DecodeError;
use crate::cursor::ReadCursor;

/// `errorInfo` from a Set Error Info PDU, typed by its MS-RDPBCGR 2.2.5.1.1 category. Decoding
/// **never fails on the code value**: an unlisted code lands in [`ErrorInfo::Other`] with the
/// raw u32 preserved — a future server speaks first, and the attribution must survive it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorInfo {
    /// A protocol-independent code (0x0000_0000–0x0000_00FF band).
    ProtocolIndependent(ProtocolIndependentCode),
    /// A protocol-independent licensing code (0x0000_0100 band).
    Licensing(LicensingCode),
    /// A protocol-independent connection-broker code (0x0000_0400 band).
    ConnectionBroker(ConnectionBrokerCode),
    /// An RDP-specific protocol-consistency code (0x0000_10C9–0x0000_1463): the server is
    /// reporting that *this client* sent something malformed. The raw code is preserved —
    /// the 50+ individually-named codes all classify identically (a client bug, fatal).
    RdpSpecific(u32),
    /// Any code outside the catalogued bands, preserved verbatim.
    Other(u32),
}

/// The protocol-independent `errorInfo` codes (MS-RDPBCGR 2.2.5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolIndependentCode {
    /// 0x0001 — an administrative tool on the server, from another session, disconnected us.
    RpcInitiatedDisconnect,
    /// 0x0002 — an administrative tool on the server forced a logoff.
    RpcInitiatedLogoff,
    /// 0x0003 — the idle session limit elapsed.
    IdleTimeout,
    /// 0x0004 — the active session limit elapsed.
    LogonTimeout,
    /// 0x0005 — another connection (same user elsewhere) displaced this one.
    DisconnectedByOtherConnection,
    /// 0x0006 — the server ran out of memory.
    OutOfMemory,
    /// 0x0007 — the server denied the connection.
    ServerDeniedConnection,
    /// 0x0009 — insufficient access privileges.
    ServerInsufficientPrivileges,
    /// 0x000A — saved credentials are not accepted; fresh credentials required.
    ServerFreshCredentialsRequired,
    /// 0x000B — an administrative tool in the user's own session disconnected us (`tsdiscon`).
    RpcInitiatedDisconnectByUser,
    /// 0x000C — the user logged the session off.
    LogoffByUser,
    /// 0x000F — the remote display driver did not start in time.
    CloseStackOnDriverNotReady,
    /// 0x0010 — the remote session's DWM crashed.
    ServerDwmCrash,
    /// 0x0011 — the remote display driver failed to start.
    CloseStackOnDriverFailure,
    /// 0x0012 — the remote display driver started but was unusable.
    CloseStackOnDriverIfaceFailure,
    /// 0x0017 — the remote session's Winlogon crashed.
    ServerWinlogonCrash,
    /// 0x0018 — the remote session's CSRSS crashed.
    ServerCsrssCrash,
}

/// The licensing `errorInfo` codes (0x0000_0100 band).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicensingCode {
    /// 0x0100 — internal licensing error.
    Internal,
    /// 0x0101 — no license server available.
    NoLicenseServer,
    /// 0x0102 — no Client Access Licenses available.
    NoLicense,
    /// 0x0103 — the server received an invalid licensing message from us.
    BadClientMsg,
    /// 0x0104 — the stored CAL's hardware ID does not match.
    HwidDoesntMatchLicense,
    /// 0x0105 — the stored CAL is malformed.
    BadClientLicense,
    /// 0x0106 — network problems ended the licensing protocol.
    CantFinishProtocol,
    /// 0x0107 — the client ended the licensing protocol prematurely.
    ClientEndedProtocol,
    /// 0x0108 — a licensing message was incorrectly encrypted.
    BadClientEncryption,
    /// 0x0109 — the stored CAL could not be upgraded or renewed.
    CantUpgradeLicense,
    /// 0x010A — the server is not licensed to accept remote connections.
    NoRemoteConnections,
}

/// The connection-broker `errorInfo` codes (0x0000_0400 band).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionBrokerCode {
    /// 0x0400 — the target endpoint could not be found.
    DestinationNotFound,
    /// 0x0402 — the target endpoint is disconnecting from the broker.
    LoadingDestination,
    /// 0x0404 — redirection to the target endpoint failed.
    RedirectingToDestination,
    /// 0x0405 — waking the target VM failed.
    SessionOnlineVmWake,
    /// 0x0406 — booting the target VM failed.
    SessionOnlineVmBoot,
    /// 0x0407 — the target VM's IP address could not be determined.
    SessionOnlineVmNoDns,
    /// 0x0408 — no free endpoint in the broker's pool.
    DestinationPoolNotFree,
    /// 0x0409 — the connection was cancelled.
    ConnectionCancelled,
    /// 0x0410 — the routingToken settings could not be validated.
    ConnectionErrorInvalidSettings,
    /// 0x0411 — booting the target VM timed out.
    SessionOnlineVmBootTimeout,
    /// 0x0412 — session monitoring failed while the target VM started.
    SessionOnlineVmSessmonFailed,
}

impl ErrorInfo {
    /// Type a raw `errorInfo` code. Total — never fails (see the enum docs).
    pub fn from_u32(code: u32) -> Self {
        use ConnectionBrokerCode as Cb;
        use LicensingCode as Lic;
        use ProtocolIndependentCode as Pi;
        match code {
            0x0000_0001 => Self::ProtocolIndependent(Pi::RpcInitiatedDisconnect),
            0x0000_0002 => Self::ProtocolIndependent(Pi::RpcInitiatedLogoff),
            0x0000_0003 => Self::ProtocolIndependent(Pi::IdleTimeout),
            0x0000_0004 => Self::ProtocolIndependent(Pi::LogonTimeout),
            0x0000_0005 => Self::ProtocolIndependent(Pi::DisconnectedByOtherConnection),
            0x0000_0006 => Self::ProtocolIndependent(Pi::OutOfMemory),
            0x0000_0007 => Self::ProtocolIndependent(Pi::ServerDeniedConnection),
            0x0000_0009 => Self::ProtocolIndependent(Pi::ServerInsufficientPrivileges),
            0x0000_000A => Self::ProtocolIndependent(Pi::ServerFreshCredentialsRequired),
            0x0000_000B => Self::ProtocolIndependent(Pi::RpcInitiatedDisconnectByUser),
            0x0000_000C => Self::ProtocolIndependent(Pi::LogoffByUser),
            0x0000_000F => Self::ProtocolIndependent(Pi::CloseStackOnDriverNotReady),
            0x0000_0010 => Self::ProtocolIndependent(Pi::ServerDwmCrash),
            0x0000_0011 => Self::ProtocolIndependent(Pi::CloseStackOnDriverFailure),
            0x0000_0012 => Self::ProtocolIndependent(Pi::CloseStackOnDriverIfaceFailure),
            0x0000_0017 => Self::ProtocolIndependent(Pi::ServerWinlogonCrash),
            0x0000_0018 => Self::ProtocolIndependent(Pi::ServerCsrssCrash),
            0x0000_0100 => Self::Licensing(Lic::Internal),
            0x0000_0101 => Self::Licensing(Lic::NoLicenseServer),
            0x0000_0102 => Self::Licensing(Lic::NoLicense),
            0x0000_0103 => Self::Licensing(Lic::BadClientMsg),
            0x0000_0104 => Self::Licensing(Lic::HwidDoesntMatchLicense),
            0x0000_0105 => Self::Licensing(Lic::BadClientLicense),
            0x0000_0106 => Self::Licensing(Lic::CantFinishProtocol),
            0x0000_0107 => Self::Licensing(Lic::ClientEndedProtocol),
            0x0000_0108 => Self::Licensing(Lic::BadClientEncryption),
            0x0000_0109 => Self::Licensing(Lic::CantUpgradeLicense),
            0x0000_010A => Self::Licensing(Lic::NoRemoteConnections),
            0x0000_0400 => Self::ConnectionBroker(Cb::DestinationNotFound),
            0x0000_0402 => Self::ConnectionBroker(Cb::LoadingDestination),
            0x0000_0404 => Self::ConnectionBroker(Cb::RedirectingToDestination),
            0x0000_0405 => Self::ConnectionBroker(Cb::SessionOnlineVmWake),
            0x0000_0406 => Self::ConnectionBroker(Cb::SessionOnlineVmBoot),
            0x0000_0407 => Self::ConnectionBroker(Cb::SessionOnlineVmNoDns),
            0x0000_0408 => Self::ConnectionBroker(Cb::DestinationPoolNotFree),
            0x0000_0409 => Self::ConnectionBroker(Cb::ConnectionCancelled),
            0x0000_0410 => Self::ConnectionBroker(Cb::ConnectionErrorInvalidSettings),
            0x0000_0411 => Self::ConnectionBroker(Cb::SessionOnlineVmBootTimeout),
            0x0000_0412 => Self::ConnectionBroker(Cb::SessionOnlineVmSessmonFailed),
            0x0000_10C9..=0x0000_1463 => Self::RdpSpecific(code),
            other => Self::Other(other),
        }
    }

    /// The raw `errorInfo` code this variant came from.
    pub fn as_u32(&self) -> u32 {
        use ConnectionBrokerCode as Cb;
        use LicensingCode as Lic;
        use ProtocolIndependentCode as Pi;
        match self {
            Self::ProtocolIndependent(c) => match c {
                Pi::RpcInitiatedDisconnect => 0x0000_0001,
                Pi::RpcInitiatedLogoff => 0x0000_0002,
                Pi::IdleTimeout => 0x0000_0003,
                Pi::LogonTimeout => 0x0000_0004,
                Pi::DisconnectedByOtherConnection => 0x0000_0005,
                Pi::OutOfMemory => 0x0000_0006,
                Pi::ServerDeniedConnection => 0x0000_0007,
                Pi::ServerInsufficientPrivileges => 0x0000_0009,
                Pi::ServerFreshCredentialsRequired => 0x0000_000A,
                Pi::RpcInitiatedDisconnectByUser => 0x0000_000B,
                Pi::LogoffByUser => 0x0000_000C,
                Pi::CloseStackOnDriverNotReady => 0x0000_000F,
                Pi::ServerDwmCrash => 0x0000_0010,
                Pi::CloseStackOnDriverFailure => 0x0000_0011,
                Pi::CloseStackOnDriverIfaceFailure => 0x0000_0012,
                Pi::ServerWinlogonCrash => 0x0000_0017,
                Pi::ServerCsrssCrash => 0x0000_0018,
            },
            Self::Licensing(c) => match c {
                Lic::Internal => 0x0000_0100,
                Lic::NoLicenseServer => 0x0000_0101,
                Lic::NoLicense => 0x0000_0102,
                Lic::BadClientMsg => 0x0000_0103,
                Lic::HwidDoesntMatchLicense => 0x0000_0104,
                Lic::BadClientLicense => 0x0000_0105,
                Lic::CantFinishProtocol => 0x0000_0106,
                Lic::ClientEndedProtocol => 0x0000_0107,
                Lic::BadClientEncryption => 0x0000_0108,
                Lic::CantUpgradeLicense => 0x0000_0109,
                Lic::NoRemoteConnections => 0x0000_010A,
            },
            Self::ConnectionBroker(c) => match c {
                Cb::DestinationNotFound => 0x0000_0400,
                Cb::LoadingDestination => 0x0000_0402,
                Cb::RedirectingToDestination => 0x0000_0404,
                Cb::SessionOnlineVmWake => 0x0000_0405,
                Cb::SessionOnlineVmBoot => 0x0000_0406,
                Cb::SessionOnlineVmNoDns => 0x0000_0407,
                Cb::DestinationPoolNotFree => 0x0000_0408,
                Cb::ConnectionCancelled => 0x0000_0409,
                Cb::ConnectionErrorInvalidSettings => 0x0000_0410,
                Cb::SessionOnlineVmBootTimeout => 0x0000_0411,
                Cb::SessionOnlineVmSessmonFailed => 0x0000_0412,
            },
            Self::RdpSpecific(code) | Self::Other(code) => *code,
        }
    }

    /// A human-readable account of the code, for logs and host UIs.
    pub fn description(&self) -> String {
        use ProtocolIndependentCode as Pi;
        match self {
            Self::ProtocolIndependent(c) => match c {
                Pi::RpcInitiatedDisconnect => {
                    "an administrative tool on the server disconnected the session".into()
                }
                Pi::RpcInitiatedLogoff => {
                    "an administrative tool on the server forced a logoff".into()
                }
                Pi::IdleTimeout => "the idle session limit elapsed".into(),
                Pi::LogonTimeout => "the active session limit elapsed".into(),
                Pi::DisconnectedByOtherConnection => {
                    "another connection displaced this session".into()
                }
                Pi::OutOfMemory => "the server ran out of memory".into(),
                Pi::ServerDeniedConnection => "the server denied the connection".into(),
                Pi::ServerInsufficientPrivileges => {
                    "insufficient access privileges for this connection".into()
                }
                Pi::ServerFreshCredentialsRequired => {
                    "the server requires freshly entered credentials".into()
                }
                Pi::RpcInitiatedDisconnectByUser => {
                    "an administrative tool in the user's session disconnected it".into()
                }
                Pi::LogoffByUser => "the user logging off ended the session".into(),
                Pi::CloseStackOnDriverNotReady => {
                    "the remote display driver did not start in time".into()
                }
                Pi::ServerDwmCrash => "the remote session's DWM crashed".into(),
                Pi::CloseStackOnDriverFailure => "the remote display driver failed to start".into(),
                Pi::CloseStackOnDriverIfaceFailure => {
                    "the remote display driver started but was unusable".into()
                }
                Pi::ServerWinlogonCrash => "the remote session's Winlogon crashed".into(),
                Pi::ServerCsrssCrash => "the remote session's CSRSS crashed".into(),
            },
            Self::Licensing(c) => format!("licensing failure: {c:?}"),
            Self::ConnectionBroker(c) => format!("connection broker failure: {c:?}"),
            Self::RdpSpecific(code) => format!(
                "the server reported a protocol-consistency error ({code:#010x}) — a client bug"
            ),
            Self::Other(code) => format!("unrecognized server error code {code:#010x}"),
        }
    }
}

/// Decode the body of a Set Error Info PDU (the Share Data payload: one u32 LE `errorInfo`).
pub fn decode_set_error_info(cur: &mut ReadCursor<'_>) -> Result<ErrorInfo, DecodeError> {
    Ok(ErrorInfo::from_u32(cur.read_u32_le()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecodeError;
    use crate::cursor::ReadCursor;

    #[test]
    fn each_category_decodes_to_its_typed_variant() {
        // One representative per category (MS-RDPBCGR 2.2.5.1.1).
        assert_eq!(
            ErrorInfo::from_u32(0x0000_000C),
            ErrorInfo::ProtocolIndependent(ProtocolIndependentCode::LogoffByUser)
        );
        assert_eq!(
            ErrorInfo::from_u32(0x0000_0003),
            ErrorInfo::ProtocolIndependent(ProtocolIndependentCode::IdleTimeout)
        );
        assert_eq!(
            ErrorInfo::from_u32(0x0000_0102),
            ErrorInfo::Licensing(LicensingCode::NoLicense)
        );
        assert_eq!(
            ErrorInfo::from_u32(0x0000_0400),
            ErrorInfo::ConnectionBroker(ConnectionBrokerCode::DestinationNotFound)
        );
        // The RDP-specific protocol-consistency band (0x10C9..) is typed as a category with
        // the raw code preserved — 50+ individually-named variants would all classify the
        // same way.
        assert_eq!(
            ErrorInfo::from_u32(0x0000_10E7),
            ErrorInfo::RdpSpecific(0x0000_10E7)
        );
    }

    #[test]
    fn unknown_codes_are_preserved_not_rejected() {
        // An unlisted code must never fail the decode (a future server speaks first): the
        // raw u32 is kept in a catch-all.
        assert_eq!(
            ErrorInfo::from_u32(0x0000_0042),
            ErrorInfo::Other(0x0000_0042)
        );
        assert_eq!(
            ErrorInfo::from_u32(0xDEAD_BEEF),
            ErrorInfo::Other(0xDEAD_BEEF)
        );
        // And the raw code round-trips from every variant.
        assert_eq!(ErrorInfo::from_u32(0x0000_010A).as_u32(), 0x0000_010A);
        assert_eq!(ErrorInfo::from_u32(0xDEAD_BEEF).as_u32(), 0xDEAD_BEEF);
    }

    #[test]
    fn the_pdu_body_decodes_the_little_endian_code() {
        // The Share Data body of a Set Error Info PDU is exactly one u32 LE.
        let body = 0x0000_000Cu32.to_le_bytes();
        let mut cur = ReadCursor::new(&body, "test");
        assert_eq!(
            decode_set_error_info(&mut cur).unwrap(),
            ErrorInfo::ProtocolIndependent(ProtocolIndependentCode::LogoffByUser)
        );
    }

    #[test]
    fn a_truncated_body_is_a_typed_error_not_a_panic() {
        let mut cur = ReadCursor::new(&[0x0C, 0x00], "test");
        assert!(matches!(
            decode_set_error_info(&mut cur),
            Err(DecodeError::NotEnoughBytes { .. })
        ));
    }

    #[test]
    fn descriptions_are_human_readable() {
        let info = ErrorInfo::from_u32(0x0000_000C);
        assert!(info.description().contains("logging off"));
        let info = ErrorInfo::from_u32(0xDEAD_BEEF);
        assert!(info.description().contains("deadbeef"));
    }
}
