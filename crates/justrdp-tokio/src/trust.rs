//! Server-certificate trust policies for the TLS upgrade (issue #36, plan.md §22).
//!
//! slice-2 shipped a deliberately permissive verifier (accept-any) so the connect sequence could
//! be built before validation existed. This module replaces it with a caller-chosen
//! [`TrustPolicy`]: real chain/SAN validation by default, and accept-any only behind an
//! explicitly danger-named opt-in. The policy decides the rustls `ServerCertVerifier`; the
//! handshake itself still runs in the adapter loop.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;

/// How the connect decides whether to trust the server's TLS certificate.
///
/// The default is [`TrustPolicy::Chain`] — never accept-any. An untrusted, name-mismatched, or
/// (for TOFU) changed certificate fails the `tls-handshake` stage with
/// [`ConnectFailure::TlsHandshake`](crate::ConnectFailure::TlsHandshake); the connect never
/// reaches NLA, so credentials are never exposed to an unauthenticated peer.
#[derive(Debug, Clone, Default)]
pub enum TrustPolicy {
    /// Chain-of-trust + SAN/hostname validation against the host **as the caller dialed it**,
    /// using the **operating-system trust store** (`rustls-platform-verifier`). Real RDP server
    /// certificates are overwhelmingly issued by enterprise CAs that live in the OS store; a
    /// Mozilla-roots-only verifier would reject most legitimate deployments.
    #[default]
    Chain,
    /// Trust-On-First-Use: pin the server's `subjectPublicKey` per host in the given
    /// [`PinStore`]. The first connect to a host stores its key; every later connect compares —
    /// an unchanged key connects, a changed one fails the handshake with an error naming the
    /// host and both SHA-256 fingerprints (and the old pin is **not** overwritten). plan.md §22
    /// recommends this for single-server scenarios, where no CA chain exists to validate.
    Tofu(Arc<dyn PinStore>),
    /// Accept **any** certificate, with no validation of any kind — the connection is open to
    /// man-in-the-middle interception. Lab and test use only; never reachable via `Default`.
    DangerAcceptAny,
}

/// Where TOFU pins live, keyed by the host **as the caller dialed it** (the same string that
/// reaches TLS SNI and the CredSSP SPN). The pin is the certificate's inner `subjectPublicKey`
/// — the same material CredSSP's `pubKeyAuth` binds to, extracted by
/// [`justrdp::tls::extract_subject_public_key`]. The library itself does no file I/O beyond the
/// bundled stores; hosts with their own persistence (a connection profile, a keychain)
/// implement this trait.
pub trait PinStore: Send + Sync + std::fmt::Debug {
    /// The pin stored for `host`, or `None` if this is the first use.
    fn lookup(&self, host: &str) -> io::Result<Option<Vec<u8>>>;
    /// Persist `pin` as the trusted key for `host`.
    fn store(&self, host: &str, pin: &[u8]) -> io::Result<()>;
}

/// An in-memory [`PinStore`]: pins live for the lifetime of the process. Useful for tests and
/// for hosts that load/save pins themselves around it.
#[derive(Debug, Default)]
pub struct MemoryPinStore {
    pins: Mutex<HashMap<String, Vec<u8>>>,
}

impl PinStore for MemoryPinStore {
    fn lookup(&self, host: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(self
            .pins
            .lock()
            .expect("pin store poisoned")
            .get(host)
            .cloned())
    }

    fn store(&self, host: &str, pin: &[u8]) -> io::Result<()> {
        self.pins
            .lock()
            .expect("pin store poisoned")
            .insert(host.to_string(), pin.to_vec());
        Ok(())
    }
}

/// The SHA-256 fingerprint of a pin, lowercase hex — the form TOFU mismatch errors use, exposed
/// so host applications can render their own "server key changed" warnings consistently.
pub fn pin_fingerprint(pin: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, pin);
    digest
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The rustls client config for the connect's TLS upgrade, with the verifier chosen by `trust`.
/// `host` is the server host as the caller dialed it — the TOFU pin-store key. The `ring`
/// crypto provider is selected explicitly so no process-default provider needs installing.
/// Default protocol versions (TLS 1.2 and 1.3) are kept — CredSSP/NLA over TLS 1.3 was verified
/// against the real VM (slice-3).
pub(crate) fn client_config(
    trust: &TrustPolicy,
    host: &str,
) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS protocol versions");
    let config = match trust {
        TrustPolicy::Chain => builder.with_platform_verifier()?.with_no_client_auth(),
        TrustPolicy::Tofu(store) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TofuVerifier {
                provider,
                store: store.clone(),
                host: host.to_string(),
            }))
            .with_no_client_auth(),
        TrustPolicy::DangerAcceptAny => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
            .with_no_client_auth(),
    };
    Ok(config)
}

/// The TOFU `ServerCertVerifier`: compares the presented certificate's `subjectPublicKey`
/// against the per-host pin, storing it on first use. Unlike [`AcceptAnyServerCert`], handshake
/// signatures are **really** verified — the pin is only meaningful if the peer proves possession
/// of the pinned key.
#[derive(Debug)]
struct TofuVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    store: Arc<dyn PinStore>,
    /// The host as dialed — the pin-store key (kept verbatim rather than re-derived from the
    /// rustls `ServerName`, so the store key always matches what the caller wrote).
    host: String,
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented =
            justrdp::tls::extract_subject_public_key(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let pinned = self.store.lookup(&self.host).map_err(|e| {
            rustls::Error::General(format!("TOFU pin lookup for {} failed: {e}", self.host))
        })?;
        match pinned {
            None => {
                self.store.store(&self.host, &presented).map_err(|e| {
                    rustls::Error::General(format!(
                        "TOFU first-use pin store for {} failed: {e}",
                        self.host
                    ))
                })?;
                Ok(ServerCertVerified::assertion())
            }
            Some(pinned) if pinned == presented => Ok(ServerCertVerified::assertion()),
            Some(pinned) => Err(rustls::Error::General(format!(
                "TOFU pin mismatch for {}: pinned key SHA-256 {} but the server presented \
                 SHA-256 {} — the server key changed (possible interception); remove the \
                 stored pin only if the change is expected",
                self.host,
                pin_fingerprint(&pinned),
                pin_fingerprint(&presented),
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A `ServerCertVerifier` that accepts every certificate and signature — the implementation
/// detail of [`TrustPolicy::DangerAcceptAny`], constructible only through that variant.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
