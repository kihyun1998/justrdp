#![forbid(unsafe_code)]

//! HRESULT / DWORD return codes used by the TsProxy RPC interface
//! (MS-TSGU §2.2.6 / §3.7.4).
//!
//! Two namespaces coexist:
//!
//! - **Full HRESULTs (`E_PROXY_*`)** returned through the normal
//!   NDR-marshaled return value of an RPC method — `CreateTunnel`,
//!   `AuthorizeTunnel`, etc.
//! - **`HRESULT_CODE` variants (low 16 bits only)** returned through
//!   the DWORD path — `SetupReceivePipe` and `SendToServer` bypass
//!   NDR and return the DWORD value directly.

// =============================================================================
// Win32 / NT status
// =============================================================================

pub const ERROR_SUCCESS: u32 = 0x0000_0000;
pub const ERROR_ACCESS_DENIED: u32 = 0x0000_0005;
/// The expected "success" return code streamed as the final DWORD of
/// `TsProxySetupReceivePipe` when the client calls CloseChannel to
/// gracefully end the session.
pub const ERROR_GRACEFUL_DISCONNECT: u32 = 0x0000_04CA;
pub const ERROR_ONLY_IF_CONNECTED: u32 = 0x0000_04E3;
pub const ERROR_OPERATION_ABORTED: u32 = 0x0000_03E3;
pub const ERROR_INVALID_PARAMETER: u32 = 0x0000_0057;
pub const ERROR_BAD_ARGUMENTS: u32 = 0x0000_00A0;

// =============================================================================
// Full E_PROXY_* HRESULTs (MS-TSGU §2.2.6)
// =============================================================================

pub const E_PROXY_INTERNALERROR: u32 = 0x8007_59D8;
pub const E_PROXY_RAP_ACCESSDENIED: u32 = 0x8007_59DA;
pub const E_PROXY_NAP_ACCESSDENIED: u32 = 0x8007_59DB;
pub const E_PROXY_ALREADYDISCONNECTED: u32 = 0x8007_59DF;
pub const E_PROXY_CAPABILITYMISMATCH: u32 = 0x8007_59E9;
pub const E_PROXY_QUARANTINE_ACCESSDENIED: u32 = 0x8007_59ED;
pub const E_PROXY_NOCERTAVAILABLE: u32 = 0x8007_59EE;
pub const E_PROXY_COOKIE_BADPACKET: u32 = 0x8007_59F7;
pub const E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED: u32 = 0x8007_59F8;
pub const E_PROXY_UNSUPPORTED_AUTHENTICATION_METHOD: u32 = 0x8007_59F9;

// =============================================================================
// HRESULT_CODE variants (low word) returned via the DWORD path
// =============================================================================

pub const HRESULT_CODE_E_PROXY_INTERNALERROR: u32 = 0x0000_59D8;
pub const HRESULT_CODE_E_PROXY_TS_CONNECTFAILED: u32 = 0x0000_59DD;
pub const HRESULT_CODE_E_PROXY_MAXCONNECTIONSREACHED: u32 = 0x0000_59E6;
pub const HRESULT_CODE_E_PROXY_NOTSUPPORTED: u32 = 0x0000_59E8;
pub const HRESULT_CODE_E_PROXY_SESSIONTIMEOUT: u32 = 0x0000_59F6;
pub const HRESULT_CODE_E_PROXY_CONNECTIONABORTED: u32 = 0x0000_04D4;

/// Return a human-readable label for a TsProxy HRESULT / DWORD
/// value. Returns `"unknown"` for values we do not recognize —
/// callers should still log the raw hex.
pub fn name_of(status: u32) -> &'static str {
    match status {
        ERROR_SUCCESS => "ERROR_SUCCESS",
        ERROR_ACCESS_DENIED => "ERROR_ACCESS_DENIED",
        ERROR_GRACEFUL_DISCONNECT => "ERROR_GRACEFUL_DISCONNECT",
        ERROR_ONLY_IF_CONNECTED => "ERROR_ONLY_IF_CONNECTED",
        ERROR_OPERATION_ABORTED => "ERROR_OPERATION_ABORTED",
        ERROR_INVALID_PARAMETER => "ERROR_INVALID_PARAMETER",
        ERROR_BAD_ARGUMENTS => "ERROR_BAD_ARGUMENTS",

        E_PROXY_INTERNALERROR => "E_PROXY_INTERNALERROR",
        E_PROXY_RAP_ACCESSDENIED => "E_PROXY_RAP_ACCESSDENIED",
        E_PROXY_NAP_ACCESSDENIED => "E_PROXY_NAP_ACCESSDENIED",
        E_PROXY_ALREADYDISCONNECTED => "E_PROXY_ALREADYDISCONNECTED",
        E_PROXY_CAPABILITYMISMATCH => "E_PROXY_CAPABILITYMISMATCH",
        E_PROXY_QUARANTINE_ACCESSDENIED => "E_PROXY_QUARANTINE_ACCESSDENIED",
        E_PROXY_NOCERTAVAILABLE => "E_PROXY_NOCERTAVAILABLE",
        E_PROXY_COOKIE_BADPACKET => "E_PROXY_COOKIE_BADPACKET",
        E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED => "E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED",
        E_PROXY_UNSUPPORTED_AUTHENTICATION_METHOD => "E_PROXY_UNSUPPORTED_AUTHENTICATION_METHOD",

        HRESULT_CODE_E_PROXY_INTERNALERROR => "HRESULT_CODE(E_PROXY_INTERNALERROR)",
        HRESULT_CODE_E_PROXY_TS_CONNECTFAILED => "HRESULT_CODE(E_PROXY_TS_CONNECTFAILED)",
        HRESULT_CODE_E_PROXY_MAXCONNECTIONSREACHED => "HRESULT_CODE(E_PROXY_MAXCONNECTIONSREACHED)",
        HRESULT_CODE_E_PROXY_NOTSUPPORTED => "HRESULT_CODE(E_PROXY_NOTSUPPORTED)",
        HRESULT_CODE_E_PROXY_SESSIONTIMEOUT => "HRESULT_CODE(E_PROXY_SESSIONTIMEOUT)",
        HRESULT_CODE_E_PROXY_CONNECTIONABORTED => "HRESULT_CODE(E_PROXY_CONNECTIONABORTED)",

        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_error_values() {
        // Sanity against known published values.
        assert_eq!(E_PROXY_INTERNALERROR, 0x8007_59D8);
        assert_eq!(E_PROXY_NAP_ACCESSDENIED, 0x8007_59DB);
        assert_eq!(E_PROXY_RAP_ACCESSDENIED, 0x8007_59DA);
        assert_eq!(E_PROXY_QUARANTINE_ACCESSDENIED, 0x8007_59ED);
        assert_eq!(E_PROXY_NOCERTAVAILABLE, 0x8007_59EE);
        assert_eq!(E_PROXY_COOKIE_BADPACKET, 0x8007_59F7);
        assert_eq!(E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED, 0x8007_59F8);
        assert_eq!(ERROR_GRACEFUL_DISCONNECT, 0x0000_04CA);
    }

    #[test]
    fn name_of_recognizes_canonical_codes() {
        assert_eq!(name_of(ERROR_SUCCESS), "ERROR_SUCCESS");
        assert_eq!(name_of(E_PROXY_INTERNALERROR), "E_PROXY_INTERNALERROR");
        assert_eq!(name_of(0xDEAD_BEEF), "unknown");
    }
}
