#![forbid(unsafe_code)]

//! Helpers for establishing a DCE/RPC association to the TsProxy
//! interface over an [`RpchTunnel`][justrdp_rpch::RpchTunnel] that
//! has already completed its CONN/A/B/C handshake.
//!
//! RPC-over-HTTP terminology recap: the virtual connection is
//! already up once [`RpchTunnel::connect`][justrdp_rpch::RpchTunnel]
//! returns, but the caller has not yet *bound* any interface onto
//! it. Binding is a DCE/RPC-level handshake (C706 §12.6.4.3): the
//! client sends a **BIND** PDU advertising one or more presentation
//! contexts, each naming an abstract syntax (TsProxy here) and a
//! candidate transfer syntax (NDR 2.0); the server replies with a
//! **BIND_ACK** indicating which context was accepted and on which
//! `p_cont_id` subsequent REQUEST PDUs must quote.
//!
//! This module provides:
//!
//! - [`build_tsproxy_bind_pdu`] — constructs a BIND PDU with a
//!   single context offering TsProxy v1.3 + NDR 2.0, no auth.
//! - [`validate_tsproxy_bind_ack`] — parses a BIND_ACK and confirms
//!   that the TsProxy context was accepted (and not provider- or
//!   user-rejected).
//!
//! The returned / accepted `p_cont_id` is what a [`TsProxyClient`]
//! must be constructed with via
//! [`TsProxyClient::with_context_id`][crate::rpch::TsProxyClient::with_context_id].
//!
//! # Auth level
//!
//! We send BIND with no `auth_verifier` (auth_level=NONE). RPC-
//! level authentication is optional — the real tunnel
//! authentication happens later inside
//! `TsProxyAuthorizeTunnel` via the PAA cookie. For deployments
//! that require RPC-level auth, extend this module to emit an
//! `auth_verifier` carrying an NTLM NEGOTIATE or SPNEGO blob, and
//! drive the BIND_ACK → AUTH3 follow-up.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{DecodeError, DecodeErrorKind, ReadCursor, WriteCursor};
use justrdp_rpch::pdu::{
    BindAckPdu, BindPdu, ContextElement, SyntaxId, BIND_PTYPE, PFC_FIRST_FRAG, PFC_LAST_FRAG,
    RESULT_ACCEPTANCE,
};
use justrdp_rpch::pdu::uuid::RpcUuid;

use super::types::TSPROXY_INTERFACE_UUID;

/// Suggested maximum fragment size for the BIND negotiation — what
/// Windows RPCRT4 sends by default (MS-RPCE §3.3.1.5.2).
pub const DEFAULT_MAX_XMIT_FRAG: u16 = 5840;
/// Suggested maximum receive fragment.
pub const DEFAULT_MAX_RECV_FRAG: u16 = 5840;

/// Presentation-context ID assigned to the TsProxy interface in the
/// BIND we produce. Callers should pass this value into
/// [`TsProxyClient::with_context_id`][crate::rpch::TsProxyClient::with_context_id]
/// (it is purely a client-side identifier; the server honours
/// whatever the client chose as long as it is unique within the
/// association).
pub const TSPROXY_CONTEXT_ID: u16 = 0;

/// Build a BIND PDU that offers a single presentation context:
/// TsProxy v1.3 abstract syntax + NDR 2.0 transfer syntax, no auth
/// verifier.
pub fn build_tsproxy_bind_pdu(call_id: u32) -> Vec<u8> {
    let tsproxy_abstract = SyntaxId {
        uuid: RpcUuid::from_str_unchecked(TSPROXY_INTERFACE_UUID),
        version_major: 1,
        version_minor: 3,
    };
    let ndr20_transfer = SyntaxId {
        uuid: RpcUuid::from_str_unchecked("8a885d04-1ceb-11c9-9fe8-08002b104860"),
        version_major: 2,
        version_minor: 0,
    };

    let pdu = BindPdu {
        ptype: BIND_PTYPE,
        pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
        call_id,
        max_xmit_frag: DEFAULT_MAX_XMIT_FRAG,
        max_recv_frag: DEFAULT_MAX_RECV_FRAG,
        // 0 = "allocate a new association group" (C706 §12.6.4.3).
        assoc_group_id: 0,
        contexts: alloc::vec![ContextElement {
            context_id: TSPROXY_CONTEXT_ID,
            abstract_syntax: tsproxy_abstract,
            transfer_syntaxes: alloc::vec![ndr20_transfer],
        }],
        auth: None,
    };

    let mut buf = alloc::vec![0u8; pdu.size()];
    let mut w = WriteCursor::new(&mut buf);
    pdu.encode(&mut w).expect("BIND fits in its computed buffer");
    buf
}

/// Reason a BIND_ACK was rejected or malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAckError {
    /// The PDU bytes failed to decode as a BIND_ACK. The first field
    /// is a short descriptor (`"PDU shorter than common header"` for
    /// our own guards, or the `context` field of the underlying
    /// [`DecodeError`] for failures surfaced through `From`). The
    /// second field carries the [`DecodeErrorKind`] when a
    /// `DecodeError` was converted — otherwise `None`.
    Decode(&'static str, Option<DecodeErrorKind>),
    /// Decoded fine but not a BIND_ACK (unexpected `ptype`).
    NotBindAck { got_ptype: u8 },
    /// BIND_ACK contained no result entries — the server did not
    /// tell us whether TsProxy was accepted.
    NoResults,
    /// The TsProxy context we offered was rejected.
    Rejected { result: u16, reason: u16 },
}

impl core::fmt::Display for BindAckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(ctx, Some(kind)) => {
                write!(f, "BIND_ACK decode failed in {ctx}: {kind:?}")
            }
            Self::Decode(ctx, None) => write!(f, "BIND_ACK decode failed: {ctx}"),
            Self::NotBindAck { got_ptype } => {
                write!(f, "not a BIND_ACK (ptype={got_ptype:#04x})")
            }
            Self::NoResults => f.write_str("BIND_ACK has zero result entries"),
            Self::Rejected { result, reason } => write!(
                f,
                "BIND_ACK rejected TsProxy context (result={result}, reason={reason})"
            ),
        }
    }
}

impl core::error::Error for BindAckError {}

impl From<DecodeError> for BindAckError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e.context, Some(e.kind))
    }
}

/// Parse a BIND_ACK PDU and verify that the TsProxy interface was
/// accepted. Returns the server-granted `assoc_group_id` on
/// success.
pub fn validate_tsproxy_bind_ack(pdu_bytes: &[u8]) -> Result<u32, BindAckError> {
    if pdu_bytes.len() < 16 {
        return Err(BindAckError::Decode("PDU shorter than common header", None));
    }
    let mut c = ReadCursor::new(pdu_bytes);
    let pdu = BindAckPdu::decode(&mut c)?;
    if pdu.ptype != justrdp_rpch::pdu::BIND_ACK_PTYPE {
        return Err(BindAckError::NotBindAck {
            got_ptype: pdu.ptype,
        });
    }
    let first = pdu.results.first().ok_or(BindAckError::NoResults)?;
    if first.result != RESULT_ACCEPTANCE {
        return Err(BindAckError::Rejected {
            result: first.result,
            reason: first.reason,
        });
    }
    Ok(pdu.assoc_group_id)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_rpch::pdu::{
        BindAckPdu, ContextResult, BIND_ACK_PTYPE, PROVIDER_REJECT_LOCAL_LIMIT_EXCEEDED,
        RESULT_PROVIDER_REJECTION,
    };

    fn ndr20() -> SyntaxId {
        SyntaxId {
            uuid: RpcUuid::from_str_unchecked("8a885d04-1ceb-11c9-9fe8-08002b104860"),
            version_major: 2,
            version_minor: 0,
        }
    }

    #[test]
    fn bind_pdu_is_self_consistent() {
        let bytes = build_tsproxy_bind_pdu(7);
        let mut c = ReadCursor::new(&bytes);
        let pdu = BindPdu::decode(&mut c).unwrap();
        assert_eq!(pdu.ptype, BIND_PTYPE);
        assert_eq!(pdu.call_id, 7);
        assert_eq!(pdu.contexts.len(), 1);

        let ctx = &pdu.contexts[0];
        assert_eq!(ctx.context_id, TSPROXY_CONTEXT_ID);
        assert_eq!(
            ctx.abstract_syntax.uuid,
            RpcUuid::from_str_unchecked(TSPROXY_INTERFACE_UUID)
        );
        assert_eq!(ctx.abstract_syntax.version_major, 1);
        assert_eq!(ctx.abstract_syntax.version_minor, 3);
        assert_eq!(ctx.transfer_syntaxes.len(), 1);
        assert_eq!(ctx.transfer_syntaxes[0], ndr20());
        assert!(pdu.auth.is_none());
    }

    #[test]
    fn bind_pdu_offers_default_frag_sizes() {
        let bytes = build_tsproxy_bind_pdu(1);
        let mut c = ReadCursor::new(&bytes);
        let pdu = BindPdu::decode(&mut c).unwrap();
        assert_eq!(pdu.max_xmit_frag, DEFAULT_MAX_XMIT_FRAG);
        assert_eq!(pdu.max_recv_frag, DEFAULT_MAX_RECV_FRAG);
        assert_eq!(pdu.assoc_group_id, 0);
    }

    fn encode_bind_ack(pdu: &BindAckPdu) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        buf
    }

    #[test]
    fn validate_accepts_single_acceptance() {
        let ack = BindAckPdu {
            ptype: BIND_ACK_PTYPE,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            max_xmit_frag: DEFAULT_MAX_XMIT_FRAG,
            max_recv_frag: DEFAULT_MAX_RECV_FRAG,
            assoc_group_id: 0x0ABC_DEF0,
            sec_addr: alloc::vec![],
            results: alloc::vec![ContextResult {
                result: RESULT_ACCEPTANCE,
                reason: 0,
                transfer_syntax: ndr20(),
            }],
            auth: None,
        };
        let got = validate_tsproxy_bind_ack(&encode_bind_ack(&ack)).unwrap();
        assert_eq!(got, 0x0ABC_DEF0);
    }

    #[test]
    fn validate_reports_provider_rejection() {
        let ack = BindAckPdu {
            ptype: BIND_ACK_PTYPE,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            max_xmit_frag: DEFAULT_MAX_XMIT_FRAG,
            max_recv_frag: DEFAULT_MAX_RECV_FRAG,
            assoc_group_id: 0,
            sec_addr: alloc::vec![],
            results: alloc::vec![ContextResult {
                result: RESULT_PROVIDER_REJECTION,
                reason: PROVIDER_REJECT_LOCAL_LIMIT_EXCEEDED,
                transfer_syntax: ndr20(),
            }],
            auth: None,
        };
        let err = validate_tsproxy_bind_ack(&encode_bind_ack(&ack)).unwrap_err();
        assert_eq!(
            err,
            BindAckError::Rejected {
                result: RESULT_PROVIDER_REJECTION,
                reason: PROVIDER_REJECT_LOCAL_LIMIT_EXCEEDED,
            }
        );
    }

    #[test]
    fn validate_rejects_malformed_pdu_bytes() {
        // A BIND PDU's body layout differs from BIND_ACK, so
        // decoding as BindAckPdu fails and we surface `Decode`.
        let bytes = build_tsproxy_bind_pdu(1);
        let err = validate_tsproxy_bind_ack(&bytes).unwrap_err();
        assert!(matches!(err, BindAckError::Decode(..)));
    }

    #[test]
    fn validate_rejects_alter_context_response_as_not_bind_ack() {
        // Build a PDU that decodes cleanly through `BindAckPdu::decode`
        // (which accepts both BIND_ACK and ALTER_CONTEXT_RESPONSE
        // ptypes) but carries ALTER_CONTEXT_RESPONSE_PTYPE — our
        // validator should reject it with `NotBindAck`.
        use justrdp_rpch::pdu::ALTER_CONTEXT_RESPONSE_PTYPE;
        let ack = BindAckPdu {
            ptype: ALTER_CONTEXT_RESPONSE_PTYPE,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            max_xmit_frag: DEFAULT_MAX_XMIT_FRAG,
            max_recv_frag: DEFAULT_MAX_RECV_FRAG,
            assoc_group_id: 1,
            sec_addr: alloc::vec![],
            results: alloc::vec![ContextResult {
                result: RESULT_ACCEPTANCE,
                reason: 0,
                transfer_syntax: ndr20(),
            }],
            auth: None,
        };
        let err = validate_tsproxy_bind_ack(&encode_bind_ack(&ack)).unwrap_err();
        assert_eq!(
            err,
            BindAckError::NotBindAck {
                got_ptype: ALTER_CONTEXT_RESPONSE_PTYPE,
            }
        );
    }

    #[test]
    fn validate_rejects_empty_results() {
        let ack = BindAckPdu {
            ptype: BIND_ACK_PTYPE,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            max_xmit_frag: DEFAULT_MAX_XMIT_FRAG,
            max_recv_frag: DEFAULT_MAX_RECV_FRAG,
            assoc_group_id: 0,
            sec_addr: alloc::vec![],
            results: alloc::vec![],
            auth: None,
        };
        let err = validate_tsproxy_bind_ack(&encode_bind_ack(&ack)).unwrap_err();
        assert_eq!(err, BindAckError::NoResults);
    }
}
