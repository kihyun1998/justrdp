#![forbid(unsafe_code)]

//! NTLM authentication (MS-NLMP).
//!
//! Implements NTLMv2 authentication protocol including:
//! - Negotiate, Challenge, and Authenticate messages
//! - NTOWFv2 hash computation
//! - NTProofStr and session key derivation
//! - MIC (Message Integrity Code)
//! - NTLM signing and sealing

pub mod compute;
pub mod messages;
pub mod signing;

pub use compute::{compute_mic, compute_response, modify_target_info, ntowfv2};
pub use messages::{
    AuthenticateMessage, AvId, AvPair, ChallengeMessage, NegotiateFlags, NegotiateMessage,
};
pub use signing::{NtlmSealingKey, NtlmSigningContext};

/// NTLMSSP signature: "NTLMSSP\0"
pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// Message type constants.
pub const NTLM_NEGOTIATE: u32 = 1;
pub const NTLM_CHALLENGE: u32 = 2;
pub const NTLM_AUTHENTICATE: u32 = 3;
