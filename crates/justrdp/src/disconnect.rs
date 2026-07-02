//! Typed disconnect classification (issue #42, plan.md §6/§9c/§10) — make every session end
//! attributable. The session machine records the server's last word ([`ServerDisconnectCause`])
//! as it arrives; when the transport closes, the adapter surfaces a single
//! [`DisconnectReason`] as the session's terminal value, and [`DisconnectClass`] tells the
//! host how to react (re-auth, notify, auto-reconnect, give up).

use justrdp_pdu::errinfo::{ErrorInfo, ProtocolIndependentCode};

/// What the server said before the session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerDisconnectCause {
    /// A Set Error Info PDU (MS-RDPBCGR 2.2.5.1.1) — the specific attribution.
    ErrorInfo(ErrorInfo),
    /// An MCS Disconnect Provider Ultimatum (T.125) — the generic farewell, used when no
    /// Error Info arrived (the specific code outranks it when both are present).
    ProviderUltimatum {
        /// The T.125 reason (`justrdp_pdu::mcs::RN_*`).
        reason: u8,
    },
}

/// Why the session ended — the session's terminal value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The server attributed the end before closing: clean and explainable.
    ServerDisconnected(ServerDisconnectCause),
    /// The transport ended (EOF or a broken connection) with no server-supplied reason.
    UnexpectedDisconnect,
    /// The host ended the session locally (cancellation) — not a disconnect at all.
    LocalClosed,
}

/// The host-reaction bucket for a disconnect (plan.md §9c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectClass {
    /// Credentials must be re-entered (re-auth flow).
    AuthFail,
    /// A licensing problem — notify an administrator.
    LicenseFail,
    /// A session limit elapsed — auto-reconnect eligible.
    Timeout,
    /// Access denied — non-recoverable without administrative change.
    PermissionDeny,
    /// The remote graphics stack failed — degradation / retry may help.
    GraphicsFail,
    /// The user ended or disconnected their own session — expected, nothing to repair.
    UserLogoff,
    /// No finer classification available.
    Unknown,
}

impl DisconnectReason {
    /// The host-reaction bucket for this reason — a pure mapping; the detailed cause stays
    /// available for finer-grained handling.
    pub fn class(&self) -> DisconnectClass {
        match self {
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ErrorInfo(info)) => {
                classify(*info)
            }
            DisconnectReason::ServerDisconnected(ServerDisconnectCause::ProviderUltimatum {
                ..
            }) => DisconnectClass::Unknown,
            DisconnectReason::UnexpectedDisconnect | DisconnectReason::LocalClosed => {
                DisconnectClass::Unknown
            }
        }
    }
}

/// Classify one Error Info code into its host-reaction bucket (pure).
pub fn classify(info: ErrorInfo) -> DisconnectClass {
    use ProtocolIndependentCode as Pi;
    match info {
        ErrorInfo::ProtocolIndependent(code) => match code {
            // Ends originating in the *user's own session* (MS-RDPBCGR 2.2.5.1.1): a user logoff
            // (LogoffByUser) or a disconnect from a tool in their session (RpcInitiatedDisconnectByUser,
            // e.g. `tsdiscon`). Their own choice — expected, nothing to repair. The "another session"
            // pair — RpcInitiatedDisconnect (0x01) and RpcInitiatedLogoff (0x02), both admin-initiated
            // *from another session* — is a different case and stays Unknown below (#119).
            Pi::LogoffByUser | Pi::RpcInitiatedDisconnectByUser => DisconnectClass::UserLogoff,
            Pi::IdleTimeout | Pi::LogonTimeout => DisconnectClass::Timeout,
            Pi::ServerFreshCredentialsRequired => DisconnectClass::AuthFail,
            Pi::ServerDeniedConnection | Pi::ServerInsufficientPrivileges => {
                DisconnectClass::PermissionDeny
            }
            Pi::CloseStackOnDriverNotReady
            | Pi::CloseStackOnDriverFailure
            | Pi::CloseStackOnDriverIfaceFailure
            | Pi::ServerDwmCrash => DisconnectClass::GraphicsFail,
            // Administrative disconnects, displacement by another connection, server-side
            // crashes/OOM: real causes, but none of the seven buckets fits a *reaction* —
            // hosts read the typed cause itself for these.
            _ => DisconnectClass::Unknown,
        },
        ErrorInfo::Licensing(_) => DisconnectClass::LicenseFail,
        ErrorInfo::ConnectionBroker(_) | ErrorInfo::RdpSpecific(_) | ErrorInfo::Other(_) => {
            DisconnectClass::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::errinfo::{ConnectionBrokerCode, LicensingCode};

    #[test]
    fn representative_codes_classify_into_their_buckets() {
        // One representative per bucket, per the issue's acceptance list.
        for (code, class) in [
            (0x0000_000Cu32, DisconnectClass::UserLogoff), // LogoffByUser
            (0x0000_000B, DisconnectClass::UserLogoff), // RpcInitiatedDisconnectByUser (tsdiscon)
            (0x0000_0001, DisconnectClass::Unknown), // RpcInitiatedDisconnect (admin, another session)
            (0x0000_0002, DisconnectClass::Unknown), // RpcInitiatedLogoff (admin, another session) — spec-sibling of 0x01
            (0x0000_0003, DisconnectClass::Timeout), // IdleTimeout
            (0x0000_0004, DisconnectClass::Timeout), // LogonTimeout
            (0x0000_000A, DisconnectClass::AuthFail), // FreshCredentialsRequired
            (0x0000_0007, DisconnectClass::PermissionDeny), // ServerDeniedConnection
            (0x0000_0010, DisconnectClass::GraphicsFail), // ServerDwmCrash
            (0x0000_0102, DisconnectClass::LicenseFail), // NoLicense
            (0x0000_10E7, DisconnectClass::Unknown), // CapabilitySetTooSmall (RDP band)
            (0xDEAD_BEEF, DisconnectClass::Unknown), // uncatalogued
        ] {
            assert_eq!(
                classify(ErrorInfo::from_u32(code)),
                class,
                "code {code:#010x}"
            );
        }
        // Category-level checks: every licensing code is LicenseFail; broker codes carry no
        // reaction of their own.
        assert_eq!(
            classify(ErrorInfo::Licensing(LicensingCode::NoRemoteConnections)),
            DisconnectClass::LicenseFail
        );
        assert_eq!(
            classify(ErrorInfo::ConnectionBroker(
                ConnectionBrokerCode::DestinationNotFound
            )),
            DisconnectClass::Unknown
        );
    }

    #[test]
    fn reasons_expose_their_bucket() {
        let reason = DisconnectReason::ServerDisconnected(ServerDisconnectCause::ErrorInfo(
            ErrorInfo::from_u32(0x0000_000C),
        ));
        assert_eq!(reason.class(), DisconnectClass::UserLogoff);
        assert_eq!(
            DisconnectReason::UnexpectedDisconnect.class(),
            DisconnectClass::Unknown
        );
    }
}
