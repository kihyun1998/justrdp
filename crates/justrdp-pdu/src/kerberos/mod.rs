//! Kerberos v5 authentication types (RFC 4120).
//!
//! Implements the ASN.1 structures needed for Kerberos authentication
//! in the RDP CredSSP flow:
//! - AS-REQ/AS-REP (initial authentication with KDC)
//! - TGS-REQ/TGS-REP (service ticket request)
//! - AP-REQ/AP-REP (application-level authentication, used in SPNEGO)

pub mod asn1;
pub mod kdcproxy;
pub mod messages;
pub mod pkinit;
pub mod spnego;

pub use kdcproxy::{KdcProxyMessage, unwrap_from_proxy, wrap_for_proxy};
pub use messages::*;
pub use spnego::{NegState, NegTokenInit, NegTokenResp};

// ── Kerberos Constants ──

/// Kerberos protocol version.
pub const KRB5_PVNO: i64 = 5;

/// Message types (RFC 4120 section 7.5.7).
pub const KRB_AS_REQ: i64 = 10;
pub const KRB_AS_REP: i64 = 11;
pub const KRB_TGS_REQ: i64 = 12;
pub const KRB_TGS_REP: i64 = 13;
pub const KRB_AP_REQ: i64 = 14;
pub const KRB_AP_REP: i64 = 15;
pub const KRB_ERROR: i64 = 30;

/// Name types (RFC 4120 section 6.2).
pub const NT_PRINCIPAL: i32 = 1;
pub const NT_SRV_INST: i32 = 2;
pub const NT_ENTERPRISE: i32 = 10;

/// Encryption types (RFC 3962, RFC 3961).
pub const ETYPE_AES256_CTS_HMAC_SHA1: i32 = 18;
pub const ETYPE_AES128_CTS_HMAC_SHA1: i32 = 17;
pub const ETYPE_RC4_HMAC: i32 = 23;

/// Pre-authentication data types.
pub const PA_TGS_REQ: i32 = 1;
pub const PA_ENC_TIMESTAMP: i32 = 2;
pub const PA_PK_AS_REQ: i32 = 16;
pub const PA_PK_AS_REP: i32 = 17;
pub const PA_ETYPE_INFO2: i32 = 19;
pub const PA_PAC_REQUEST: i32 = 128;

/// KDC options flags (RFC 4120 section 5.4.1).
pub const KDC_OPT_FORWARDABLE: u32 = 0x40000000;
pub const KDC_OPT_RENEWABLE: u32 = 0x00800000;
pub const KDC_OPT_CANONICALIZE: u32 = 0x00010000;
pub const KDC_OPT_RENEWABLE_OK: u32 = 0x00000010;

/// AP options flags (RFC 4120 section 5.5.1).
pub const AP_OPT_MUTUAL_REQUIRED: u32 = 0x20000000;

/// Key usage numbers (RFC 3961 section 7.5.1).
pub const KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP: i32 = 1;
pub const KEY_USAGE_AS_REP_ENC_PART: i32 = 3;
pub const KEY_USAGE_TGS_REQ_AUTHENTICATOR: i32 = 7;
pub const KEY_USAGE_AP_REQ_AUTHENTICATOR: i32 = 11;
pub const KEY_USAGE_AP_REP_ENC_PART: i32 = 12;
pub const KEY_USAGE_TGS_REQ_PA_TGS_REQ_CKSUM: i32 = 6;
pub const KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY: i32 = 8;
pub const KEY_USAGE_ACCEPTOR_SEAL: i32 = 22;
pub const KEY_USAGE_ACCEPTOR_SIGN: i32 = 23;
pub const KEY_USAGE_INITIATOR_SEAL: i32 = 24;
pub const KEY_USAGE_INITIATOR_SIGN: i32 = 25;

/// Error codes (RFC 4120 section 7.5.9).
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
