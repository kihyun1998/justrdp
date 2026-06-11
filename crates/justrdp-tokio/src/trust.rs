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

/// A minimal file-backed [`PinStore`] for tests and PoC hosts: one `host<TAB>hex-pin` line per
/// host. Every lookup re-reads the file (external edits are seen immediately); every store
/// rewrites it through a temp-file rename, so a crash never leaves a half-written pin file. A
/// corrupt file is an **error**, not first-use — failing open would let an attacker re-pin by
/// corrupting the store. Production hosts should implement [`PinStore`] over their own profile
/// storage instead: this store does synchronous file I/O inside the TLS handshake and does no
/// cross-process locking.
#[derive(Debug)]
pub struct FilePinStore {
    path: std::path::PathBuf,
    /// Serializes in-process read-modify-write cycles.
    write_lock: Mutex<()>,
}

impl FilePinStore {
    /// A pin store backed by the file at `path` (created on first store).
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            write_lock: Mutex::new(()),
        }
    }

    fn read_all(&self) -> io::Result<HashMap<String, Vec<u8>>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(e),
        };
        let mut pins = HashMap::new();
        for (idx, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let parsed = line
                .split_once('\t')
                .and_then(|(host, hex)| Some((host, hex_to_bytes(hex)?)));
            let Some((host, pin)) = parsed else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("malformed pin file {:?} at line {}", self.path, idx + 1),
                ));
            };
            pins.insert(host.to_string(), pin);
        }
        Ok(pins)
    }
}

impl PinStore for FilePinStore {
    fn lookup(&self, host: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(self.read_all()?.remove(host))
    }

    fn store(&self, host: &str, pin: &[u8]) -> io::Result<()> {
        let _guard = self.write_lock.lock().expect("pin store poisoned");
        let mut pins = self.read_all()?;
        pins.insert(host.to_string(), pin.to_vec());

        let mut text = String::new();
        for (host, pin) in &pins {
            use std::fmt::Write as _;
            let _ = writeln!(text, "{host}\t{}", bytes_to_hex(pin));
        }
        // Write-then-rename: the file is replaced atomically, never observed half-written.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp path per test, pre-cleaned so reruns start fresh.
    fn temp_pin_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("justrdp-pins-{}-{tag}.tsv", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn file_pin_store_round_trips_a_pin_across_instances() {
        let path = temp_pin_path("roundtrip");
        let store = FilePinStore::new(&path);
        store.store("vm.example.test", &[0x01, 0x02, 0xFF]).unwrap();

        // A brand-new instance reading the same file sees the pin — that is the persistence
        // a process restart depends on.
        let reopened = FilePinStore::new(&path);
        assert_eq!(
            reopened.lookup("vm.example.test").unwrap(),
            Some(vec![0x01, 0x02, 0xFF])
        );
        assert_eq!(reopened.lookup("other.host").unwrap(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_pin_store_keeps_hosts_independent() {
        let path = temp_pin_path("independent");
        let store = FilePinStore::new(&path);
        store.store("a.example.test", b"key-a").unwrap();
        store.store("b.example.test", b"key-b").unwrap();
        // Storing for one host must not clobber another (the store rewrites the whole file).
        store.store("a.example.test", b"key-a2").unwrap();

        assert_eq!(
            store.lookup("a.example.test").unwrap(),
            Some(b"key-a2".to_vec())
        );
        assert_eq!(
            store.lookup("b.example.test").unwrap(),
            Some(b"key-b".to_vec())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_pin_store_treats_a_missing_file_as_first_use() {
        let path = temp_pin_path("missing");
        let store = FilePinStore::new(&path);
        assert_eq!(store.lookup("any.host").unwrap(), None);
    }

    #[test]
    fn file_pin_store_surfaces_a_corrupt_file_as_an_error() {
        // A corrupt pin file must fail closed (an error the verifier turns into a handshake
        // failure), never silently behave like first-use — that would re-pin an attacker's key.
        let path = temp_pin_path("corrupt");
        std::fs::write(&path, "vm.example.test\tnot-hex!!\n").unwrap();
        let store = FilePinStore::new(&path);
        assert!(store.lookup("vm.example.test").is_err());
        let _ = std::fs::remove_file(&path);
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
