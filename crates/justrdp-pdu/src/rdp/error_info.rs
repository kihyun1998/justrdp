//! Symbolic representation of `SetErrorInfoPdu.error_info` codes
//! (MS-RDPBCGR 2.2.5.1.1).
//!
//! The wire value is a 32-bit unsigned integer; the spec defines ~100
//! discrete values across four categories plus a large block of
//! internal RDP protocol errors. Applications typically only need to
//! branch on the "top-level" 42 codes (protocol-independent / license /
//! Connection Broker); the remaining ~80 RDP-internal codes
//! (`0x10C9..=0x1195`) are diagnostic-only and are folded into a single
//! [`ErrorInfoCode::RdpProtocol`] variant carrying the raw value.
//!
//! Use [`ErrorInfoCode::from_u32`] to classify a wire value, then
//! [`ErrorInfoCode::description`], [`ErrorInfoCode::category`],
//! [`ErrorInfoCode::severity`], and [`ErrorInfoCode::is_retryable`] to
//! drive user-facing messages and reconnect policy.

#![allow(clippy::enum_variant_names)]

/// Classified [`SetErrorInfoPdu`](super::finalization::SetErrorInfoPdu)
/// value.
///
/// Construct via [`ErrorInfoCode::from_u32`]. Two raw values always
/// escape into catch-all variants:
///
/// * `0x10C9..=0x1195` → [`Self::RdpProtocol`] (internal protocol
///   violations — interesting for logging, rarely for UI).
/// * everything else → [`Self::Unknown`] (future codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorInfoCode {
    // ── Protocol-independent (0x00000000 .. 0x0000001A) ──
    /// `ERRINFO_NONE (0x00000000)` — not a real disconnect reason.
    None,
    /// `ERRINFO_RPC_INITIATED_DISCONNECT (0x00000001)` — admin tool in
    /// another session dropped us.
    RpcInitiatedDisconnect,
    /// `ERRINFO_RPC_INITIATED_LOGOFF (0x00000002)` — admin forced logoff.
    RpcInitiatedLogoff,
    /// `ERRINFO_IDLE_TIMEOUT (0x00000003)` — idle session timer expired.
    IdleTimeout,
    /// `ERRINFO_LOGON_TIMEOUT (0x00000004)` — active session timer expired.
    LogonTimeout,
    /// `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION (0x00000005)` —
    /// displaced by another user on the same console.
    DisconnectedByOtherConnection,
    /// `ERRINFO_OUT_OF_MEMORY (0x00000006)` — server allocator failure.
    OutOfMemory,
    /// `ERRINFO_SERVER_DENIED_CONNECTION (0x00000007)` — server refused.
    ServerDeniedConnection,
    /// `ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES (0x00000009)` — ACL denial.
    ServerInsufficientPrivileges,
    /// `ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED (0x0000000A)` —
    /// server does not accept saved credentials for this user.
    ServerFreshCredentialsRequired,
    /// `ERRINFO_RPC_INITIATED_DISCONNECT_BYUSER (0x0000000B)` — admin
    /// tool in *this* user's session initiated the disconnect.
    RpcInitiatedDisconnectByUser,
    /// `ERRINFO_LOGOFF_BY_USER (0x0000000C)` — user clicked log off.
    LogoffByUser,
    /// `ERRINFO_CLOSE_STACK_ON_DRIVER_NOT_READY (0x0000000F)` — display
    /// driver in the remote session did not start in time.
    CloseStackOnDriverNotReady,
    /// `ERRINFO_SERVER_DWM_CRASH (0x00000010)` — DWM in the remote
    /// session crashed.
    ServerDwmCrash,
    /// `ERRINFO_CLOSE_STACK_ON_DRIVER_FAILURE (0x00000011)` — display
    /// driver failed to start.
    CloseStackOnDriverFailure,
    /// `ERRINFO_CLOSE_STACK_ON_DRIVER_IFACE_FAILURE (0x00000012)` —
    /// driver started but is not usable by the remoting stack.
    CloseStackOnDriverIfaceFailure,
    /// `ERRINFO_SERVER_WINLOGON_CRASH (0x00000017)` — Winlogon in the
    /// remote session crashed.
    ServerWinlogonCrash,
    /// `ERRINFO_SERVER_CSRSS_CRASH (0x00000018)` — CSRSS in the remote
    /// session crashed.
    ServerCsrssCrash,
    /// `ERRINFO_SERVER_SHUTDOWN (0x00000019)` — remote server is
    /// shutting down.
    ServerShutdown,
    /// `ERRINFO_SERVER_REBOOT (0x0000001A)` — remote server is rebooting.
    ServerReboot,

    // ── Licensing (0x00000100 .. 0x0000010A) ──
    /// `ERRINFO_LICENSE_INTERNAL (0x00000100)`.
    LicenseInternal,
    /// `ERRINFO_LICENSE_NO_LICENSE_SERVER (0x00000101)`.
    LicenseNoLicenseServer,
    /// `ERRINFO_LICENSE_NO_LICENSE (0x00000102)` — no CALs available.
    LicenseNoLicense,
    /// `ERRINFO_LICENSE_BAD_CLIENT_MSG (0x00000103)`.
    LicenseBadClientMsg,
    /// `ERRINFO_LICENSE_HWID_DOESNT_MATCH_LICENSE (0x00000104)`.
    LicenseHwidDoesntMatchLicense,
    /// `ERRINFO_LICENSE_BAD_CLIENT_LICENSE (0x00000105)`.
    LicenseBadClientLicense,
    /// `ERRINFO_LICENSE_CANT_FINISH_PROTOCOL (0x00000106)`.
    LicenseCantFinishProtocol,
    /// `ERRINFO_LICENSE_CLIENT_ENDED_PROTOCOL (0x00000107)`.
    LicenseClientEndedProtocol,
    /// `ERRINFO_LICENSE_BAD_CLIENT_ENCRYPTION (0x00000108)`.
    LicenseBadClientEncryption,
    /// `ERRINFO_LICENSE_CANT_UPGRADE_LICENSE (0x00000109)`.
    LicenseCantUpgradeLicense,
    /// `ERRINFO_LICENSE_NO_REMOTE_CONNECTIONS (0x0000010A)` — remote
    /// computer is not licensed to accept remote connections.
    LicenseNoRemoteConnections,

    // ── Connection Broker (0x00000400 .. 0x00000412, sparse) ──
    /// `ERRINFO_CB_DESTINATION_NOT_FOUND (0x00000400)`.
    CbDestinationNotFound,
    /// `ERRINFO_CB_LOADING_DESTINATION (0x00000402)`.
    CbLoadingDestination,
    /// `ERRINFO_CB_REDIRECTING_TO_DESTINATION (0x00000404)`.
    CbRedirectingToDestination,
    /// `ERRINFO_CB_SESSION_ONLINE_VM_WAKE (0x00000405)`.
    CbSessionOnlineVmWake,
    /// `ERRINFO_CB_SESSION_ONLINE_VM_BOOT (0x00000406)`.
    CbSessionOnlineVmBoot,
    /// `ERRINFO_CB_SESSION_ONLINE_VM_NO_DNS (0x00000407)`.
    CbSessionOnlineVmNoDns,
    /// `ERRINFO_CB_DESTINATION_POOL_NOT_FREE (0x00000408)`.
    CbDestinationPoolNotFree,
    /// `ERRINFO_CB_CONNECTION_CANCELLED (0x00000409)`.
    CbConnectionCancelled,
    /// `ERRINFO_CB_CONNECTION_ERROR_INVALID_SETTINGS (0x00000410)`.
    CbConnectionErrorInvalidSettings,
    /// `ERRINFO_CB_SESSION_ONLINE_VM_BOOT_TIMEOUT (0x00000411)`.
    CbSessionOnlineVmBootTimeout,
    /// `ERRINFO_CB_SESSION_ONLINE_VM_SESSMON_FAILED (0x00000412)`.
    CbSessionOnlineVmSessmonFailed,

    // ── RDP internal protocol errors (0x10C9..=0x1195) ──
    /// Any `ERRINFO_*` in the internal RDP-specific range
    /// `0x000010C9..=0x00001195` — there are ~80 of these and they all
    /// share the same semantics (server detected a malformed PDU,
    /// unexpected sequence, or security failure). Wrapped rather than
    /// enumerated so the enum stays tractable.
    RdpProtocol(u32),

    /// Anything the spec does not currently define. Treated as a
    /// transient condition by [`Self::is_retryable`] so future spec
    /// additions do not brick existing clients.
    Unknown(u32),
}

/// High-level category used for log filtering and user-facing grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorInfoCategory {
    /// `ERRINFO_NONE` — no error signalled.
    None,
    /// Protocol-independent disconnect reasons (`0x0001..=0x001A`).
    ProtocolIndependent,
    /// Licensing failures (`0x0100..=0x010A`).
    Licensing,
    /// Connection Broker / redirection (`0x0400..=0x0412`).
    ConnectionBroker,
    /// Internal RDP protocol violations (`0x10C9..=0x1195`).
    RdpProtocol,
    /// Future / unknown codes.
    Unknown,
}

/// Log severity hint. Ordered from least to most severe so consumers
/// can compare with `<`/`>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorInfoSeverity {
    /// No-op or deliberate user action — nothing to show.
    Info,
    /// Expected transient condition (idle timeout, VM boot).
    Warning,
    /// Unexpected failure, automatic retry is reasonable.
    Error,
    /// Terminal condition — do not retry without operator intervention
    /// (license failure, insufficient privileges, explicit denial).
    Fatal,
}

impl ErrorInfoCode {
    /// Classify a raw wire value.
    pub const fn from_u32(code: u32) -> Self {
        match code {
            0x0000_0000 => Self::None,
            0x0000_0001 => Self::RpcInitiatedDisconnect,
            0x0000_0002 => Self::RpcInitiatedLogoff,
            0x0000_0003 => Self::IdleTimeout,
            0x0000_0004 => Self::LogonTimeout,
            0x0000_0005 => Self::DisconnectedByOtherConnection,
            0x0000_0006 => Self::OutOfMemory,
            0x0000_0007 => Self::ServerDeniedConnection,
            0x0000_0009 => Self::ServerInsufficientPrivileges,
            0x0000_000A => Self::ServerFreshCredentialsRequired,
            0x0000_000B => Self::RpcInitiatedDisconnectByUser,
            0x0000_000C => Self::LogoffByUser,
            0x0000_000F => Self::CloseStackOnDriverNotReady,
            0x0000_0010 => Self::ServerDwmCrash,
            0x0000_0011 => Self::CloseStackOnDriverFailure,
            0x0000_0012 => Self::CloseStackOnDriverIfaceFailure,
            0x0000_0017 => Self::ServerWinlogonCrash,
            0x0000_0018 => Self::ServerCsrssCrash,
            0x0000_0019 => Self::ServerShutdown,
            0x0000_001A => Self::ServerReboot,

            0x0000_0100 => Self::LicenseInternal,
            0x0000_0101 => Self::LicenseNoLicenseServer,
            0x0000_0102 => Self::LicenseNoLicense,
            0x0000_0103 => Self::LicenseBadClientMsg,
            0x0000_0104 => Self::LicenseHwidDoesntMatchLicense,
            0x0000_0105 => Self::LicenseBadClientLicense,
            0x0000_0106 => Self::LicenseCantFinishProtocol,
            0x0000_0107 => Self::LicenseClientEndedProtocol,
            0x0000_0108 => Self::LicenseBadClientEncryption,
            0x0000_0109 => Self::LicenseCantUpgradeLicense,
            0x0000_010A => Self::LicenseNoRemoteConnections,

            0x0000_0400 => Self::CbDestinationNotFound,
            0x0000_0402 => Self::CbLoadingDestination,
            0x0000_0404 => Self::CbRedirectingToDestination,
            0x0000_0405 => Self::CbSessionOnlineVmWake,
            0x0000_0406 => Self::CbSessionOnlineVmBoot,
            0x0000_0407 => Self::CbSessionOnlineVmNoDns,
            0x0000_0408 => Self::CbDestinationPoolNotFree,
            0x0000_0409 => Self::CbConnectionCancelled,
            0x0000_0410 => Self::CbConnectionErrorInvalidSettings,
            0x0000_0411 => Self::CbSessionOnlineVmBootTimeout,
            0x0000_0412 => Self::CbSessionOnlineVmSessmonFailed,

            // RDP-specific protocol errors span 0x10C9..=0x1195. Use a
            // range match so any value in that block is preserved
            // rather than being collapsed into Unknown — the raw code
            // still has diagnostic value in logs even when the enum
            // doesn't name it.
            0x0000_10C9..=0x0000_1195 => Self::RdpProtocol(code),

            _ => Self::Unknown(code),
        }
    }

    /// Raw wire value this variant encodes.
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::None => 0x0000_0000,
            Self::RpcInitiatedDisconnect => 0x0000_0001,
            Self::RpcInitiatedLogoff => 0x0000_0002,
            Self::IdleTimeout => 0x0000_0003,
            Self::LogonTimeout => 0x0000_0004,
            Self::DisconnectedByOtherConnection => 0x0000_0005,
            Self::OutOfMemory => 0x0000_0006,
            Self::ServerDeniedConnection => 0x0000_0007,
            Self::ServerInsufficientPrivileges => 0x0000_0009,
            Self::ServerFreshCredentialsRequired => 0x0000_000A,
            Self::RpcInitiatedDisconnectByUser => 0x0000_000B,
            Self::LogoffByUser => 0x0000_000C,
            Self::CloseStackOnDriverNotReady => 0x0000_000F,
            Self::ServerDwmCrash => 0x0000_0010,
            Self::CloseStackOnDriverFailure => 0x0000_0011,
            Self::CloseStackOnDriverIfaceFailure => 0x0000_0012,
            Self::ServerWinlogonCrash => 0x0000_0017,
            Self::ServerCsrssCrash => 0x0000_0018,
            Self::ServerShutdown => 0x0000_0019,
            Self::ServerReboot => 0x0000_001A,

            Self::LicenseInternal => 0x0000_0100,
            Self::LicenseNoLicenseServer => 0x0000_0101,
            Self::LicenseNoLicense => 0x0000_0102,
            Self::LicenseBadClientMsg => 0x0000_0103,
            Self::LicenseHwidDoesntMatchLicense => 0x0000_0104,
            Self::LicenseBadClientLicense => 0x0000_0105,
            Self::LicenseCantFinishProtocol => 0x0000_0106,
            Self::LicenseClientEndedProtocol => 0x0000_0107,
            Self::LicenseBadClientEncryption => 0x0000_0108,
            Self::LicenseCantUpgradeLicense => 0x0000_0109,
            Self::LicenseNoRemoteConnections => 0x0000_010A,

            Self::CbDestinationNotFound => 0x0000_0400,
            Self::CbLoadingDestination => 0x0000_0402,
            Self::CbRedirectingToDestination => 0x0000_0404,
            Self::CbSessionOnlineVmWake => 0x0000_0405,
            Self::CbSessionOnlineVmBoot => 0x0000_0406,
            Self::CbSessionOnlineVmNoDns => 0x0000_0407,
            Self::CbDestinationPoolNotFree => 0x0000_0408,
            Self::CbConnectionCancelled => 0x0000_0409,
            Self::CbConnectionErrorInvalidSettings => 0x0000_0410,
            Self::CbSessionOnlineVmBootTimeout => 0x0000_0411,
            Self::CbSessionOnlineVmSessmonFailed => 0x0000_0412,

            Self::RdpProtocol(code) | Self::Unknown(code) => code,
        }
    }

    /// Top-level category (Protocol-Independent / Licensing / CB / …).
    pub const fn category(self) -> ErrorInfoCategory {
        match self {
            Self::None => ErrorInfoCategory::None,
            Self::RpcInitiatedDisconnect
            | Self::RpcInitiatedLogoff
            | Self::IdleTimeout
            | Self::LogonTimeout
            | Self::DisconnectedByOtherConnection
            | Self::OutOfMemory
            | Self::ServerDeniedConnection
            | Self::ServerInsufficientPrivileges
            | Self::ServerFreshCredentialsRequired
            | Self::RpcInitiatedDisconnectByUser
            | Self::LogoffByUser
            | Self::CloseStackOnDriverNotReady
            | Self::ServerDwmCrash
            | Self::CloseStackOnDriverFailure
            | Self::CloseStackOnDriverIfaceFailure
            | Self::ServerWinlogonCrash
            | Self::ServerCsrssCrash
            | Self::ServerShutdown
            | Self::ServerReboot => ErrorInfoCategory::ProtocolIndependent,

            Self::LicenseInternal
            | Self::LicenseNoLicenseServer
            | Self::LicenseNoLicense
            | Self::LicenseBadClientMsg
            | Self::LicenseHwidDoesntMatchLicense
            | Self::LicenseBadClientLicense
            | Self::LicenseCantFinishProtocol
            | Self::LicenseClientEndedProtocol
            | Self::LicenseBadClientEncryption
            | Self::LicenseCantUpgradeLicense
            | Self::LicenseNoRemoteConnections => ErrorInfoCategory::Licensing,

            Self::CbDestinationNotFound
            | Self::CbLoadingDestination
            | Self::CbRedirectingToDestination
            | Self::CbSessionOnlineVmWake
            | Self::CbSessionOnlineVmBoot
            | Self::CbSessionOnlineVmNoDns
            | Self::CbDestinationPoolNotFree
            | Self::CbConnectionCancelled
            | Self::CbConnectionErrorInvalidSettings
            | Self::CbSessionOnlineVmBootTimeout
            | Self::CbSessionOnlineVmSessmonFailed => ErrorInfoCategory::ConnectionBroker,

            Self::RdpProtocol(_) => ErrorInfoCategory::RdpProtocol,
            Self::Unknown(_) => ErrorInfoCategory::Unknown,
        }
    }

    /// Severity hint for log routing and UI badges.
    pub const fn severity(self) -> ErrorInfoSeverity {
        use ErrorInfoSeverity::*;
        match self {
            Self::None => Info,

            // User / admin intent — not a failure from the client's PoV.
            Self::RpcInitiatedDisconnect
            | Self::RpcInitiatedLogoff
            | Self::RpcInitiatedDisconnectByUser
            | Self::LogoffByUser
            | Self::DisconnectedByOtherConnection => Info,

            // Expected transient states.
            Self::IdleTimeout
            | Self::LogonTimeout
            | Self::ServerShutdown
            | Self::ServerReboot
            | Self::CbLoadingDestination
            | Self::CbRedirectingToDestination
            | Self::CbSessionOnlineVmWake
            | Self::CbSessionOnlineVmBoot => Warning,

            // Terminal — operator action required.
            Self::ServerDeniedConnection
            | Self::ServerInsufficientPrivileges
            | Self::ServerFreshCredentialsRequired
            | Self::LicenseInternal
            | Self::LicenseNoLicenseServer
            | Self::LicenseNoLicense
            | Self::LicenseBadClientMsg
            | Self::LicenseHwidDoesntMatchLicense
            | Self::LicenseBadClientLicense
            | Self::LicenseCantFinishProtocol
            | Self::LicenseClientEndedProtocol
            | Self::LicenseBadClientEncryption
            | Self::LicenseCantUpgradeLicense
            | Self::LicenseNoRemoteConnections
            | Self::CbDestinationNotFound
            | Self::CbConnectionErrorInvalidSettings
            | Self::CbDestinationPoolNotFree
            | Self::CbConnectionCancelled
            | Self::CbSessionOnlineVmBootTimeout
            | Self::CbSessionOnlineVmSessmonFailed
            | Self::CbSessionOnlineVmNoDns => Fatal,

            // Server-side crashes and protocol violations — the
            // connection is broken but a retry may succeed.
            Self::OutOfMemory
            | Self::CloseStackOnDriverNotReady
            | Self::CloseStackOnDriverFailure
            | Self::CloseStackOnDriverIfaceFailure
            | Self::ServerDwmCrash
            | Self::ServerWinlogonCrash
            | Self::ServerCsrssCrash
            | Self::RdpProtocol(_) => Error,

            Self::Unknown(_) => Error,
        }
    }

    /// Whether an automatic reconnect has a reasonable chance of
    /// succeeding. The blocking runtime consumes this to gate the
    /// auto-reconnect path.
    ///
    /// Non-retryable = deliberate user/admin action OR policy denial
    /// OR licensing failure OR broker redirect. Everything else
    /// (including unknown codes) is optimistically retryable.
    pub const fn is_retryable(self) -> bool {
        match self {
            // NONE is not really a disconnect, but blocking's
            // next_event treats it as "no fatal error seen yet" so
            // we must not block a subsequent reconnect on it.
            Self::None => true,

            // User / admin intent.
            Self::RpcInitiatedDisconnect
            | Self::RpcInitiatedLogoff
            | Self::RpcInitiatedDisconnectByUser
            | Self::LogoffByUser
            | Self::DisconnectedByOtherConnection
            | Self::ServerDeniedConnection
            | Self::ServerInsufficientPrivileges
            | Self::ServerFreshCredentialsRequired => false,

            // Transient.
            Self::IdleTimeout | Self::LogonTimeout | Self::OutOfMemory => true,

            // Server-side crashes & stack failures — reconnect often
            // succeeds once the remote side finishes restarting.
            Self::CloseStackOnDriverNotReady
            | Self::CloseStackOnDriverFailure
            | Self::CloseStackOnDriverIfaceFailure
            | Self::ServerDwmCrash
            | Self::ServerWinlogonCrash
            | Self::ServerCsrssCrash
            | Self::ServerShutdown
            | Self::ServerReboot => true,

            // Licensing — operator intervention required.
            Self::LicenseInternal
            | Self::LicenseNoLicenseServer
            | Self::LicenseNoLicense
            | Self::LicenseBadClientMsg
            | Self::LicenseHwidDoesntMatchLicense
            | Self::LicenseBadClientLicense
            | Self::LicenseCantFinishProtocol
            | Self::LicenseClientEndedProtocol
            | Self::LicenseBadClientEncryption
            | Self::LicenseCantUpgradeLicense
            | Self::LicenseNoRemoteConnections => false,

            // Connection broker: the client should be responding to a
            // Redirection PDU, not retrying the original target.
            Self::CbDestinationNotFound
            | Self::CbLoadingDestination
            | Self::CbRedirectingToDestination
            | Self::CbSessionOnlineVmWake
            | Self::CbSessionOnlineVmBoot
            | Self::CbSessionOnlineVmNoDns
            | Self::CbDestinationPoolNotFree
            | Self::CbConnectionCancelled
            | Self::CbConnectionErrorInvalidSettings
            | Self::CbSessionOnlineVmBootTimeout
            | Self::CbSessionOnlineVmSessmonFailed => false,

            // Internal protocol errors — usually transient server-side
            // bugs or MITM artifacts; let the runtime try once.
            Self::RdpProtocol(_) => true,

            // Future codes — optimistic default so new spec values do
            // not silently brick the auto-reconnect path.
            Self::Unknown(_) => true,
        }
    }

    /// Short English description suitable for log lines. The blocking
    /// layer can wrap this in its own localized string lookup if
    /// needed; keeping it plain `&'static str` avoids pulling a
    /// formatter into the `no_std` PDU layer.
    pub const fn description(self) -> &'static str {
        match self {
            Self::None => "no error",
            Self::RpcInitiatedDisconnect => "disconnected by admin (other session)",
            Self::RpcInitiatedLogoff => "forced logoff by admin",
            Self::IdleTimeout => "idle session timeout",
            Self::LogonTimeout => "logon session timeout",
            Self::DisconnectedByOtherConnection => "displaced by another connection",
            Self::OutOfMemory => "server out of memory",
            Self::ServerDeniedConnection => "server denied connection",
            Self::ServerInsufficientPrivileges => "insufficient access privileges",
            Self::ServerFreshCredentialsRequired => "server requires fresh credentials",
            Self::RpcInitiatedDisconnectByUser => "disconnected by admin (this session)",
            Self::LogoffByUser => "user logged off",
            Self::CloseStackOnDriverNotReady => "display driver not ready",
            Self::ServerDwmCrash => "server DWM crashed",
            Self::CloseStackOnDriverFailure => "display driver failed to start",
            Self::CloseStackOnDriverIfaceFailure => "display driver interface failure",
            Self::ServerWinlogonCrash => "server Winlogon crashed",
            Self::ServerCsrssCrash => "server CSRSS crashed",
            Self::ServerShutdown => "server is shutting down",
            Self::ServerReboot => "server is rebooting",

            Self::LicenseInternal => "licensing internal error",
            Self::LicenseNoLicenseServer => "no license server available",
            Self::LicenseNoLicense => "no Client Access Licenses available",
            Self::LicenseBadClientMsg => "server received invalid licensing message",
            Self::LicenseHwidDoesntMatchLicense => "stored CAL was modified (HWID mismatch)",
            Self::LicenseBadClientLicense => "stored CAL has invalid format",
            Self::LicenseCantFinishProtocol => "licensing protocol aborted",
            Self::LicenseClientEndedProtocol => "client ended licensing protocol early",
            Self::LicenseBadClientEncryption => "licensing message incorrectly encrypted",
            Self::LicenseCantUpgradeLicense => "stored CAL could not be upgraded",
            Self::LicenseNoRemoteConnections => "server not licensed for remote connections",

            Self::CbDestinationNotFound => "broker: destination endpoint not found",
            Self::CbLoadingDestination => "broker: destination is disconnecting",
            Self::CbRedirectingToDestination => "broker: redirect to destination failed",
            Self::CbSessionOnlineVmWake => "broker: VM wake failure",
            Self::CbSessionOnlineVmBoot => "broker: VM boot failure",
            Self::CbSessionOnlineVmNoDns => "broker: VM has no DNS",
            Self::CbDestinationPoolNotFree => "broker: no free endpoints in pool",
            Self::CbConnectionCancelled => "broker: connection canceled",
            Self::CbConnectionErrorInvalidSettings => "broker: invalid routing token",
            Self::CbSessionOnlineVmBootTimeout => "broker: VM boot timeout",
            Self::CbSessionOnlineVmSessmonFailed => "broker: session monitoring failure",

            Self::RdpProtocol(_) => "RDP internal protocol error",
            Self::Unknown(_) => "unknown disconnect reason",
        }
    }
}

impl From<u32> for ErrorInfoCode {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<ErrorInfoCode> for u32 {
    fn from(value: ErrorInfoCode) -> Self {
        value.as_u32()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_named_codes() {
        // Every known code must survive from_u32 → as_u32.
        for code in [
            0x0000_0000_u32,
            0x0000_0001,
            0x0000_0002,
            0x0000_0003,
            0x0000_0004,
            0x0000_0005,
            0x0000_0006,
            0x0000_0007,
            0x0000_0009,
            0x0000_000A,
            0x0000_000B,
            0x0000_000C,
            0x0000_000F,
            0x0000_0010,
            0x0000_0011,
            0x0000_0012,
            0x0000_0017,
            0x0000_0018,
            0x0000_0019,
            0x0000_001A,
            0x0000_0100,
            0x0000_0101,
            0x0000_0102,
            0x0000_0103,
            0x0000_0104,
            0x0000_0105,
            0x0000_0106,
            0x0000_0107,
            0x0000_0108,
            0x0000_0109,
            0x0000_010A,
            0x0000_0400,
            0x0000_0402,
            0x0000_0404,
            0x0000_0405,
            0x0000_0406,
            0x0000_0407,
            0x0000_0408,
            0x0000_0409,
            0x0000_0410,
            0x0000_0411,
            0x0000_0412,
        ] {
            let e = ErrorInfoCode::from_u32(code);
            assert_eq!(e.as_u32(), code, "round-trip failed for 0x{code:08X}");
        }
    }

    #[test]
    fn rdp_protocol_range() {
        // Boundaries of the internal protocol error block round-trip
        // as RdpProtocol with the raw value preserved.
        for code in [0x10C9_u32, 0x10F0, 0x1192, 0x1195] {
            let e = ErrorInfoCode::from_u32(code);
            assert!(matches!(e, ErrorInfoCode::RdpProtocol(_)));
            assert_eq!(e.as_u32(), code);
            assert_eq!(e.category(), ErrorInfoCategory::RdpProtocol);
        }
        // Just outside the block falls into Unknown.
        let before = ErrorInfoCode::from_u32(0x10C8);
        assert!(matches!(before, ErrorInfoCode::Unknown(0x10C8)));
        let after = ErrorInfoCode::from_u32(0x1196);
        assert!(matches!(after, ErrorInfoCode::Unknown(0x1196)));
    }

    #[test]
    fn licensing_not_retryable() {
        // Regression guard for a previous latent bug where the
        // retryable classifier used wrong numeric ranges and returned
        // true for real license errors.
        for raw in [
            0x0000_0100,
            0x0000_0101,
            0x0000_0102,
            0x0000_0103,
            0x0000_0104,
            0x0000_0105,
            0x0000_0106,
            0x0000_0107,
            0x0000_0108,
            0x0000_0109,
            0x0000_010A,
        ] {
            let e = ErrorInfoCode::from_u32(raw);
            assert!(!e.is_retryable(), "0x{raw:08X} must be non-retryable");
            assert_eq!(e.category(), ErrorInfoCategory::Licensing);
            assert_eq!(e.severity(), ErrorInfoSeverity::Fatal);
        }
    }

    #[test]
    fn connection_broker_not_retryable() {
        for raw in [
            0x0000_0400,
            0x0000_0402,
            0x0000_0404,
            0x0000_0405,
            0x0000_0406,
            0x0000_0407,
            0x0000_0408,
            0x0000_0409,
            0x0000_0410,
            0x0000_0411,
            0x0000_0412,
        ] {
            let e = ErrorInfoCode::from_u32(raw);
            assert!(!e.is_retryable(), "0x{raw:08X} must be non-retryable");
            assert_eq!(e.category(), ErrorInfoCategory::ConnectionBroker);
        }
    }

    #[test]
    fn user_intent_not_retryable() {
        for raw in [
            0x0000_0001, // admin disconnect
            0x0000_0002, // admin logoff
            0x0000_000B, // admin disconnect by user
            0x0000_000C, // user logoff
            0x0000_0005, // displaced
            0x0000_0007, // denied
            0x0000_0009, // insufficient privs
            0x0000_000A, // fresh credentials
        ] {
            assert!(!ErrorInfoCode::from_u32(raw).is_retryable(), "0x{raw:08X}");
        }
    }

    #[test]
    fn transient_is_retryable() {
        for raw in [
            0x0000_0000, // NONE
            0x0000_0003, // idle
            0x0000_0004, // logon timeout
            0x0000_0006, // OOM
            0x0000_0019, // shutdown
            0x0000_001A, // reboot
            0x0000_0010, // DWM crash
            0x0000_0017, // Winlogon crash
            0x10C9,      // RdpProtocol
        ] {
            assert!(ErrorInfoCode::from_u32(raw).is_retryable(), "0x{raw:08X}");
        }
    }

    #[test]
    fn unknown_code_is_retryable_by_default() {
        let e = ErrorInfoCode::from_u32(0xDEAD_BEEF);
        assert!(matches!(e, ErrorInfoCode::Unknown(0xDEAD_BEEF)));
        assert!(e.is_retryable());
        assert_eq!(e.category(), ErrorInfoCategory::Unknown);
    }

    #[test]
    fn severity_ordering_is_useful() {
        assert!(ErrorInfoSeverity::Info < ErrorInfoSeverity::Warning);
        assert!(ErrorInfoSeverity::Warning < ErrorInfoSeverity::Error);
        assert!(ErrorInfoSeverity::Error < ErrorInfoSeverity::Fatal);
    }

    #[test]
    fn description_is_non_empty_for_every_variant() {
        // Named variants + representative RdpProtocol + Unknown.
        let samples = [
            ErrorInfoCode::None,
            ErrorInfoCode::IdleTimeout,
            ErrorInfoCode::LicenseNoLicenseServer,
            ErrorInfoCode::CbDestinationNotFound,
            ErrorInfoCode::RdpProtocol(0x10C9),
            ErrorInfoCode::Unknown(0xFFFF_FFFF),
        ];
        for s in samples {
            assert!(!s.description().is_empty());
        }
    }
}
