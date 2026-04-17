#![forbid(unsafe_code)]

//! DCE/RPC connection-oriented PDU encodings (C706 Chapter 12,
//! MS-RPCE §2.2.2) and the RTS PDU that MS-RPCH uses for
//! RPC-over-HTTP flow control (MS-RPCH §2.2.3.5).
//!
//! This module is a **framing layer only**: it encodes and decodes
//! PDUs byte-for-byte. It does not maintain call state, fragment
//! reassembly queues, or security contexts — those belong to the
//! higher layers in `http.rs` and to callers.
//!
//! # Submodules
//!
//! - [`common`] — 16-byte common header shared by every CO PDU, plus
//!   every PTYPE / PFC_* / DREP constant.
//! - [`uuid`] — the DCE "mixed-endian" UUID wire format used for
//!   interface / transfer-syntax identifiers and for REQUEST's
//!   optional object UUID.
//! - [`auth`] — `SecurityTrailer` (auth_verifier), shared by any PDU
//!   that carries an auth_value.
//! - [`bind`] — BIND / BIND_ACK / BIND_NAK / ALTER_CONTEXT /
//!   ALTER_CONTEXT_RESPONSE, plus the presentation-context
//!   negotiation types used inside them.
//! - [`body`] — REQUEST / RESPONSE / FAULT / AUTH3 / SHUTDOWN /
//!   CO_CANCEL / ORPHANED.
//! - [`rts`] — the RTS PDU type plus all 15 RTS command variants
//!   from MS-RPCH §2.2.3.5, and the high-level `ConnA1` / `ConnB1`
//!   / etc. builders used during tunnel setup.

pub mod auth;
pub mod bind;
pub mod body;
pub mod common;
pub mod reassembly;
pub mod rts;
pub mod uuid;

pub use auth::{SecurityTrailer, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_GSS_KERBEROS,
    RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_INTEGRITY,
    RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT, RPC_C_AUTHN_LEVEL_PRIVACY,
    RPC_C_AUTHN_NONE, RPC_C_AUTHN_WINNT};
pub use bind::{BindAckPdu, BindNakPdu, BindPdu, ContextElement, ContextResult, SyntaxId,
    ALTER_CONTEXT_PTYPE, ALTER_CONTEXT_RESPONSE_PTYPE, BIND_ACK_PTYPE, BIND_NAK_PTYPE, BIND_PTYPE,
    PROVIDER_REJECT_LOCAL_LIMIT_EXCEEDED, PROVIDER_REJECT_PROTOCOL_VERSION_NOT_SUPPORTED,
    PROVIDER_REJECT_REASON_NOT_SPECIFIED, RESULT_ACCEPTANCE, RESULT_PROVIDER_REJECTION,
    RESULT_USER_REJECTION};
pub use body::{
    AuthThreePdu, FaultPdu, RequestPdu, ResponsePdu, AUTH3_PTYPE, CO_CANCEL_PTYPE,
    FAULT_PTYPE, NCA_S_FAULT_ACCESS_DENIED, NCA_S_FAULT_ACCESS_DENIED_DCE,
    NCA_S_FAULT_CANT_PERFORM, NCA_S_FAULT_CONTEXT_MISMATCH, NCA_S_FAULT_INVALID_BOUND,
    NCA_S_FAULT_NO_MEMORY, ORPHANED_PTYPE, REQUEST_PTYPE, RESPONSE_PTYPE, SHUTDOWN_PTYPE,
};
pub use common::{
    CommonHeader, COMMON_HEADER_SIZE, DREP_DEFAULT, PFC_CONC_MPX, PFC_DID_NOT_EXECUTE,
    PFC_FIRST_FRAG, PFC_LAST_FRAG, PFC_MAYBE, PFC_OBJECT_UUID, PFC_PENDING_CANCEL,
    RPC_VERS, RPC_VERS_MINOR,
};
pub use reassembly::{
    ReassembledPdu, ReassemblyBuffer, ReassemblyError, DEFAULT_REASSEMBLY_CAP,
};
pub use rts::{
    conn_a1, conn_b1, RtsCommand, RtsPdu, RTS_FLAG_ECHO, RTS_FLAG_EOF, RTS_FLAG_IN_CHANNEL,
    RTS_FLAG_NONE, RTS_FLAG_OTHER_CMD, RTS_FLAG_OUT_CHANNEL, RTS_FLAG_PING,
    RTS_FLAG_RECYCLE_CHANNEL, RTS_PTYPE,
};
pub use uuid::RpcUuid;
