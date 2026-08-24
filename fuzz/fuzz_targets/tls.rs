#![no_main]
//! Fuzz the sans-IO core's X.509 key extraction (#241). The **first** fuzz target outside
//! `justrdp-pdu` / `justrdp-codecs`: the census that names what must be fuzzed was scoped to
//! `crates/justrdp-pdu/src`, so it could not see a parser living in the core crate at all, and
//! `fuzz/Cargo.toml` could not even reach that crate until this change.
//!
//! `extract_subject_public_key` parses a **server-supplied** certificate at three live call
//! sites: the TLS leaf on `TlsEstablished` (`connect.rs`), the licensing `X509Chain` leaf
//! (`connect.rs`), and the TOFU pin comparison in the adapter (`justrdp-tokio/src/trust.rs`).
//! The parse itself is `x509_cert::Certificate::from_der`, a leaf dependency — which is exactly
//! why the census could not see it and why nothing here asserts it is *ours* to get right; what
//! this target asserts is that the wrapper on the live path is total over what a server sends.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp::tls::extract_subject_public_key(data);
});
