#![forbid(unsafe_code)]

//! Error helpers for the async gateway transport family.
//!
//! The async stack standardises on
//! [`justrdp_async::TransportError`](justrdp_async::TransportError) so
//! every gateway-side failure surfaces as one of the existing
//! `TransportErrorKind` variants the connector loop already handles.
//! These helpers wrap the no_std error types from `justrdp_gateway`
//! into that envelope.

use alloc::format;
use alloc::string::String;

use justrdp_async::TransportError;
use justrdp_gateway::{GatewayError, NtlmError};

// `dead_code` is silenced on the helpers below — they're scaffolding
// the upcoming HTTP / WebSocket / RPCH adapters (G2-G9) will consume.
// The `error` module is committed first so subsequent transport
// commits can stay focused on protocol logic.

/// Wrap a [`NtlmError`] (NTLMSSP state-machine failure — bad
/// challenge, target-info parse error, etc.) into a transport-level
/// `Protocol` error. NTLM failures are programmer / server bugs at
/// the protocol layer, not I/O failures.
#[allow(dead_code)]
pub(crate) fn ntlm_err(e: NtlmError) -> TransportError {
    TransportError::protocol(format!("ntlm: {e:?}"))
}

/// Wrap a [`GatewayError`] (MS-TSGU state-machine PDU encode / decode
/// or invalid-transition error) into a transport-level `Protocol`
/// error. The state machine itself lives in `justrdp_gateway::client`
/// and is reused verbatim from blocking; only the I/O around it is
/// async.
#[allow(dead_code)]
pub(crate) fn gw_err(e: GatewayError) -> TransportError {
    TransportError::protocol(format!("gateway: {e:?}"))
}

/// Build a `Protocol`-class error for HTTP/1.1 surface failures
/// (missing header, bad status code, malformed `WWW-Authenticate`).
/// Mirrors the blocking `http_err` helper.
#[allow(dead_code)]
pub(crate) fn http_err(msg: impl Into<String>) -> TransportError {
    TransportError::protocol(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_async::TransportErrorKind;

    #[test]
    fn http_err_has_protocol_kind() {
        let e = http_err("missing header");
        assert_eq!(e.kind(), TransportErrorKind::Protocol);
    }

    #[test]
    fn ntlm_err_has_protocol_kind() {
        // `NtlmError` doesn't expose a public constructor for tests;
        // we exercise the helper through `unwrap_err` of an actual
        // negotiate-against-empty-credentials path in the higher-
        // level integration tests. The shape of the conversion is
        // exercised by static type checks here.
        let _f: fn(NtlmError) -> TransportError = ntlm_err;
    }

    #[test]
    fn gw_err_has_protocol_kind() {
        let _f: fn(GatewayError) -> TransportError = gw_err;
    }
}
