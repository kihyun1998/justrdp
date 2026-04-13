#![no_std]
#![forbid(unsafe_code)]

//! Smartcard / HSM source abstraction for client-side PKINIT.
//!
//! Existing PKINIT support in `justrdp-connector` accepts a raw
//! certificate DER plus an in-memory `RsaPrivateKey`. This crate adds an
//! optional indirection — `SmartcardProvider` — so the certificate and
//! signing operation can be sourced from a hardware token (PC/SC,
//! PKCS#11) or from a test fixture, without exposing the private key
//! material to the host process.
//!
//! # Layers
//!
//! - [`SmartcardProvider`] — minimal trait the PKINIT layer calls.
//!   Returns the end-entity certificate, the intermediate chain, and a
//!   PKCS#1 v1.5 signature over a pre-computed SHA-256 digest. PIN
//!   verification is a separate one-shot call and is the application's
//!   responsibility before handing the provider to the connector.
//! - [`MockSmartcardProvider`] (`mock` feature, default) — in-memory
//!   provider with a hard-coded test certificate and key, useful for
//!   unit/integration tests with no hardware.
//! - `PcscSmartcardProvider` (`pcsc` feature, opt-in) — cross-platform
//!   PC/SC adapter built on the `pcsc` crate (WinSCard / pcsc-lite /
//!   CryptoTokenKit). **Compile-tested only — real-hardware validation
//!   is a TODO.**
//!
//! # Spec reference
//!
//! Trait shape derived from RFC 4556 §3.2.1 + NIST SP 800-73-4 §3.3.2
//! (PIV GENERAL AUTHENTICATE). See `specs/pkinit-smartcard-notes.md`
//! for the full analysis.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod provider;

#[cfg(feature = "mock")]
pub mod mock;

#[cfg(feature = "pcsc")]
pub mod pcsc_backend;

#[cfg(feature = "alloc")]
pub use provider::{SmartcardError, SmartcardProvider};

#[cfg(feature = "mock")]
pub use mock::MockSmartcardProvider;

#[cfg(feature = "pcsc")]
pub use pcsc_backend::PcscSmartcardProvider;
