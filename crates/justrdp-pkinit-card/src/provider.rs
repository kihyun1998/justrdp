#![forbid(unsafe_code)]

//! `SmartcardProvider` trait and `SmartcardError` enum.
//!
//! The trait is the contract the PKINIT layer calls. Reader enumeration
//! and card selection are *not* part of the trait — they belong to the
//! concrete provider's constructor (Mock = struct literal, PCSC =
//! `PcscSmartcardProvider::open`).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Errors a smartcard provider may return.
///
/// PIN-related variants are best-effort: hardware tokens may not always
/// expose remaining-tries counts, and some cards block silently after a
/// PIN failure threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmartcardError {
    /// PIN was rejected. `remaining_tries` is `None` when the card does
    /// not expose a counter.
    PinIncorrect { remaining_tries: Option<u8> },
    /// PIN counter reached zero; the card refuses further PIN attempts
    /// until administratively unblocked.
    PinBlocked,
    /// No card present in the selected reader (or the reader was
    /// disconnected between selection and operation).
    CardNotPresent,
    /// Card was removed mid-operation.
    CardRemoved,
    /// Underlying crypto failed (e.g., key too small for the digest size,
    /// modulus mismatch). The string is for human diagnosis only — do not
    /// pattern-match on its content.
    CryptoFailure(String),
    /// Catch-all for backend-specific failures that don't fit the
    /// categories above. The string is for human diagnosis only.
    Other(String),
}

impl core::fmt::Display for SmartcardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PinIncorrect { remaining_tries: Some(n) } => {
                write!(f, "PIN incorrect ({n} tries remaining)")
            }
            Self::PinIncorrect { remaining_tries: None } => write!(f, "PIN incorrect"),
            Self::PinBlocked => write!(f, "PIN blocked"),
            Self::CardNotPresent => write!(f, "no card present"),
            Self::CardRemoved => write!(f, "card removed"),
            Self::CryptoFailure(msg) => write!(f, "crypto failure: {msg}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl core::error::Error for SmartcardError {}

/// Source of a client certificate and signing capability for PKINIT.
///
/// Implementations may be backed by a smartcard, an HSM, a PKCS#11
/// token, or a software-only test fixture. The trait is intentionally
/// minimal: reader/slot discovery and PIN cache lifetime are the
/// concrete provider's responsibility.
///
/// # Required call order
///
/// 1. Application instantiates a concrete provider (e.g.
///    `MockSmartcardProvider::new()` or `PcscSmartcardProvider::open(...)`).
/// 2. Application calls `verify_pin(...)` once, if the provider needs
///    a PIN. Mock providers may return `Ok(())` unconditionally.
/// 3. Application hands the provider to `PkinitConfig::from_provider(...)`
///    (in `justrdp-connector`). PKINIT will then call `get_certificate`,
///    `get_intermediate_chain`, and `sign_digest` as needed during the
///    AS-REQ build.
///
/// PKINIT will never call `verify_pin` itself — it assumes the card
/// session is already authenticated. This split mirrors PIV
/// (NIST SP 800-73-4 §2.4): VERIFY happens once per session, then the
/// card cache satisfies subsequent crypto operations.
pub trait SmartcardProvider: Send + Sync {
    /// End-entity X.509 certificate, DER-encoded.
    fn get_certificate(&self) -> Vec<u8>;

    /// Intermediate CA certificates needed to build a chain to a
    /// KDC-trusted anchor. **Root CA MUST NOT be included** (RFC 4556
    /// §3.2.1). Empty `Vec` if the end-entity is directly trusted.
    fn get_intermediate_chain(&self) -> Vec<Vec<u8>>;

    /// Verify the user PIN (PIV SP 800-73-4 §2.4 VERIFY command).
    ///
    /// Implementations SHOULD zeroize the `pin` slice after copying it
    /// into the underlying APDU buffer. Mock providers may return
    /// `Ok(())` immediately.
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), SmartcardError>;

    /// Sign a 32-byte SHA-256 digest with PKCS#1 v1.5 padding + RSA.
    ///
    /// Returns the signature bytes (modulus length). Used by PKINIT to
    /// produce the `signedAuthPack.signerInfos[0].signature` field over
    /// `AuthPack` DER bytes (CMS `eContent`).
    ///
    /// `digest` must be exactly 32 bytes; the implementation MAY return
    /// `SmartcardError::CryptoFailure` if it is not.
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, SmartcardError>;
}
