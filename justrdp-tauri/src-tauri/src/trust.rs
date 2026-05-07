//! TOFU certificate trust store (Slice E).
//!
//! [`TrustStore`] persists `host → SPKI SHA-256` mappings to a
//! config-dir-scoped JSON file. The store is the deep module of
//! Slice E — it owns all filesystem boundary handling and SPKI
//! comparison; the verifier wrapper and Tauri commands are thin
//! adapters on top.
//!
//! ## On-disk format
//!
//! ```json
//! {
//!   "version": 1,
//!   "trusted": {
//!     "192.168.136.136": "abcdef0123...32 bytes hex"
//!   }
//! }
//! ```
//!
//! - `version` is reserved for future migrations (currently always 1).
//! - `trusted` keys by raw host (no port) — RDP almost always lives
//!   on 3389 and per-port pinning would surprise users who change
//!   ports between sessions.
//! - SPKI hash is hex-encoded SHA-256 of the DER SubjectPublicKeyInfo
//!   (matching `justrdp_tls::PinnedSpki::from_cert_der` output).

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use justrdp_core::crypto::sha256;
use justrdp_tls::{extract_spki_from_cert_der, CertDecision, ServerCertVerifier};
use serde::{Deserialize, Serialize};

const STORE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u32,
    trusted: BTreeMap<String, String>,
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Result of looking up a host's presented SPKI in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStatus {
    /// Host is in the store and the presented SPKI matches.
    Trusted,
    /// Host is in the store but the presented SPKI differs from the
    /// stored one. Both fingerprints are surfaced so the embedder
    /// can show them side-by-side in a warning dialog.
    Mismatch {
        stored_sha256: [u8; 32],
        presented_sha256: [u8; 32],
    },
    /// Host is not in the store — embedder should run the first-use
    /// prompt flow.
    Unknown,
}

/// File-backed `host → SPKI SHA-256` store.
pub struct TrustStore {
    path: PathBuf,
    entries: BTreeMap<String, [u8; 32]>,
}

impl TrustStore {
    /// Open the store at `path`. A missing file yields an empty
    /// in-memory store; corrupted JSON also yields empty (the
    /// embedder gets a fresh slate rather than a panic).
    pub fn open(path: PathBuf) -> Self {
        let entries = match fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Persisted>(&text) {
                Ok(p) => p
                    .trusted
                    .into_iter()
                    .filter_map(|(host, hex)| hex_decode(&hex).map(|b| (host, b)))
                    .collect(),
                // Corrupted JSON / wrong shape — fall back to empty
                // rather than panic. Cycle 6 pins this behavior.
                Err(_) => BTreeMap::new(),
            },
            Err(_) => BTreeMap::new(),
        };
        Self { path, entries }
    }

    /// Look up `host` and decide whether `presented_sha256` matches.
    pub fn lookup(&self, host: &str, presented_sha256: &[u8; 32]) -> TrustStatus {
        match self.entries.get(host) {
            None => TrustStatus::Unknown,
            Some(stored) if stored == presented_sha256 => TrustStatus::Trusted,
            Some(stored) => TrustStatus::Mismatch {
                stored_sha256: *stored,
                presented_sha256: *presented_sha256,
            },
        }
    }

    /// Insert (or overwrite) the trusted SPKI for `host` and
    /// flush the whole store to disk.
    pub fn add(&mut self, host: &str, spki_sha256: [u8; 32]) -> io::Result<()> {
        self.entries.insert(host.to_string(), spki_sha256);
        let persisted = Persisted {
            version: STORE_VERSION,
            trusted: self
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), hex_encode(v)))
                .collect(),
        };
        let text = serde_json::to_string_pretty(&persisted).map_err(io::Error::other)?;
        if let Some(parent) = self.path.parent() {
            // Ignore "already exists"; surface every other error.
            if let Err(e) = fs::create_dir_all(parent) {
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(e);
                }
            }
        }
        fs::write(&self.path, text)
    }
}

/// Compute the SHA-256 of the SubjectPublicKeyInfo extracted from a
/// DER-encoded X.509 certificate, or `None` if the cert cannot be
/// parsed. This is the fingerprint shape the trust store keys on.
pub fn spki_sha256_of_cert(cert_der: &[u8]) -> Option<[u8; 32]> {
    let spki = extract_spki_from_cert_der(cert_der)?;
    Some(sha256(&spki))
}

/// `ServerCertVerifier` impl backed by a [`TrustStore`]. The
/// verifier itself never prompts — `Unknown` and `Mismatch` both
/// surface as `Reject`. The first-use prompt flow lives outside
/// (the embedder calls `rdp_fetch_cert_spki` + `rdp_trust_spki`
/// before re-trying `rdp_connect`).
pub struct TrustStoreVerifier {
    store: Arc<RwLock<TrustStore>>,
}

impl TrustStoreVerifier {
    pub fn new(store: Arc<RwLock<TrustStore>>) -> Self {
        Self { store }
    }
}

impl ServerCertVerifier for TrustStoreVerifier {
    fn verify(&self, cert_der: &[u8], server_name: &str) -> CertDecision {
        let Some(presented) = spki_sha256_of_cert(cert_der) else {
            // Unparseable cert — never trust it.
            return CertDecision::Reject;
        };
        let store = self.store.read().expect("trust store lock poisoned");
        match store.lookup(server_name, &presented) {
            TrustStatus::Trusted => CertDecision::Accept,
            TrustStatus::Mismatch { .. } | TrustStatus::Unknown => CertDecision::Reject,
        }
    }
}

/// Verifier that captures the leaf SPKI fingerprint and then
/// rejects — used by `rdp_fetch_cert_spki` to learn what fingerprint
/// to prompt the user about without committing trust. The Reject
/// causes the handshake to fail fast so the connection isn't kept
/// open longer than needed.
pub struct CaptureSpki {
    captured: Mutex<Option<[u8; 32]>>,
}

impl CaptureSpki {
    pub fn new() -> Self {
        Self {
            captured: Mutex::new(None),
        }
    }

    /// Read the captured fingerprint (if `verify` has been called
    /// with a parseable cert).
    pub fn captured(&self) -> Option<[u8; 32]> {
        *self.captured.lock().expect("capture lock poisoned")
    }
}

impl Default for CaptureSpki {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerCertVerifier for CaptureSpki {
    fn verify(&self, cert_der: &[u8], _server_name: &str) -> CertDecision {
        if let Some(s) = spki_sha256_of_cert(cert_der) {
            *self.captured.lock().expect("capture lock poisoned") = Some(s);
        }
        CertDecision::Reject
    }
}

/// Format a 32-byte fingerprint as 64 hex chars (lowercase). Public
/// so commands can ship the fingerprint to the frontend dialog.
pub fn hex_encode_fingerprint(bytes: &[u8; 32]) -> String {
    hex_encode(bytes)
}

/// Parse a 64-char hex string back into a fingerprint, or None if
/// length / digit shape is wrong.
pub fn hex_decode_fingerprint(s: &str) -> Option<[u8; 32]> {
    hex_decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store_path(dir: &TempDir) -> PathBuf {
        dir.path().join("trusted-spki.json")
    }

    #[test]
    fn empty_store_returns_unknown_for_any_host() {
        let dir = TempDir::new().expect("tempdir");
        let store = TrustStore::open(store_path(&dir));
        assert_eq!(
            store.lookup("192.168.136.136", &[0u8; 32]),
            TrustStatus::Unknown
        );
    }

    #[test]
    fn add_then_lookup_with_matching_sha_returns_trusted() {
        let dir = TempDir::new().unwrap();
        let mut store = TrustStore::open(store_path(&dir));
        let spki = [0xAB; 32];
        store.add("192.168.136.136", spki).expect("add ok");
        assert_eq!(
            store.lookup("192.168.136.136", &spki),
            TrustStatus::Trusted
        );
    }

    #[test]
    fn lookup_with_different_sha_for_known_host_returns_mismatch() {
        let dir = TempDir::new().unwrap();
        let mut store = TrustStore::open(store_path(&dir));
        let stored = [0xAB; 32];
        let presented = [0xCD; 32];
        store.add("192.168.136.136", stored).unwrap();
        assert_eq!(
            store.lookup("192.168.136.136", &presented),
            TrustStatus::Mismatch {
                stored_sha256: stored,
                presented_sha256: presented,
            }
        );
    }

    #[test]
    fn other_hosts_are_unaffected_by_add() {
        let dir = TempDir::new().unwrap();
        let mut store = TrustStore::open(store_path(&dir));
        store.add("foo.example", [0xAA; 32]).unwrap();
        // bar.example was never added — still Unknown even though
        // foo.example is now Trusted.
        assert_eq!(
            store.lookup("bar.example", &[0xAA; 32]),
            TrustStatus::Unknown
        );
    }

    #[test]
    fn add_persists_across_drop_and_reopen() {
        let dir = TempDir::new().unwrap();
        let path = store_path(&dir);
        let spki = [0xAB; 32];
        {
            let mut store = TrustStore::open(path.clone());
            store.add("192.168.136.136", spki).expect("add ok");
        }
        // First store dropped — reopening should re-read the JSON
        // file and surface the previously trusted SPKI.
        let store = TrustStore::open(path);
        assert_eq!(
            store.lookup("192.168.136.136", &spki),
            TrustStatus::Trusted
        );
    }

    #[test]
    fn corrupted_store_falls_back_to_empty_without_panic() {
        let dir = TempDir::new().unwrap();
        let path = store_path(&dir);
        // Write garbage that is neither valid JSON nor matches the
        // Persisted shape. open() must NOT panic — fresh users
        // should never lose access to the app because some other
        // process scribbled on the trust file.
        fs::write(&path, "this is not json{{ ;;").unwrap();
        let store = TrustStore::open(path);
        assert_eq!(
            store.lookup("any.host", &[0u8; 32]),
            TrustStatus::Unknown
        );
    }

    #[test]
    fn verifier_rejects_unparseable_cert() {
        let dir = TempDir::new().unwrap();
        let store = TrustStore::open(store_path(&dir));
        let verifier = TrustStoreVerifier::new(Arc::new(RwLock::new(store)));
        // Random bytes are not a valid X.509 cert — extract_spki
        // returns None and the verifier must Reject. Without this
        // guard a malformed handshake could silently bypass trust.
        assert_eq!(
            verifier.verify(b"not a cert", "any.host"),
            CertDecision::Reject
        );
    }

    #[test]
    fn verifier_rejects_unknown_host_with_valid_cert() {
        let dir = TempDir::new().unwrap();
        let store = TrustStore::open(store_path(&dir));
        let verifier = TrustStoreVerifier::new(Arc::new(RwLock::new(store)));
        let cert = build_minimal_cert();
        // Cert parses fine but the host has never been added —
        // verifier must Reject (Unknown maps to Reject; the
        // first-use prompt lives outside the verifier).
        assert_eq!(
            verifier.verify(&cert, "unknown.host"),
            CertDecision::Reject
        );
    }

    #[test]
    fn verifier_accepts_when_store_has_matching_spki() {
        let cert = build_minimal_cert();
        let presented = spki_sha256_of_cert(&cert).expect("valid cert");
        let dir = TempDir::new().unwrap();
        let mut store = TrustStore::open(store_path(&dir));
        store.add("server.example", presented).unwrap();
        let verifier = TrustStoreVerifier::new(Arc::new(RwLock::new(store)));
        assert_eq!(
            verifier.verify(&cert, "server.example"),
            CertDecision::Accept
        );
    }

    /// Minimal valid X.509 cert DER with a parseable SPKI. Carbon
    /// copy of the helper in `justrdp-tls/verifier.rs` tests — that
    /// helper isn't pub-exported, so we duplicate the byte layout
    /// here.
    fn build_minimal_cert() -> Vec<u8> {
        fn der_len(len: usize) -> Vec<u8> {
            if len < 0x80 {
                vec![len as u8]
            } else if len < 0x100 {
                vec![0x81, len as u8]
            } else {
                vec![0x82, (len >> 8) as u8, len as u8]
            }
        }
        fn seq(content: &[u8]) -> Vec<u8> {
            let mut r = vec![0x30];
            r.extend(der_len(content.len()));
            r.extend_from_slice(content);
            r
        }
        let algo = vec![
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        let bitstr = vec![0x03, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut spki_body = Vec::new();
        spki_body.extend_from_slice(&algo);
        spki_body.extend_from_slice(&bitstr);
        let spki = seq(&spki_body);
        let version = vec![0xA0, 0x03, 0x02, 0x01, 0x02];
        let serial = vec![0x02, 0x01, 0x01];
        let sig_algo = vec![0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
        let issuer = vec![0x30, 0x00];
        let validity = vec![0x30, 0x00];
        let subject = vec![0x30, 0x00];
        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&version);
        tbs_body.extend_from_slice(&serial);
        tbs_body.extend_from_slice(&sig_algo);
        tbs_body.extend_from_slice(&issuer);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(&subject);
        tbs_body.extend_from_slice(&spki);
        let tbs = seq(&tbs_body);
        let outer_sig_algo = vec![0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
        let sig_value = vec![0x03, 0x03, 0x00, 0xAA, 0xBB];
        let mut cert_body = Vec::new();
        cert_body.extend_from_slice(&tbs);
        cert_body.extend_from_slice(&outer_sig_algo);
        cert_body.extend_from_slice(&sig_value);
        seq(&cert_body)
    }

    #[test]
    fn concurrent_handles_last_writer_wins() {
        // Two long-lived handles to the same store file. Each `add`
        // re-serialises the handle's full in-memory state, so the
        // second write overwrites the first. Acceptable for a TOFU
        // store (additions are rare; the user explicitly accepts
        // each one) — the assertion pins that semantic so a future
        // change to file-locking / merge semantics is a deliberate
        // breakage of this contract.
        let dir = TempDir::new().unwrap();
        let path = store_path(&dir);
        let mut s1 = TrustStore::open(path.clone());
        let mut s2 = TrustStore::open(path.clone());

        s1.add("a.example", [0xAA; 32]).unwrap();
        s2.add("b.example", [0xBB; 32]).unwrap();

        let s3 = TrustStore::open(path);
        // Last writer (s2) wins for its own entry.
        assert_eq!(
            s3.lookup("b.example", &[0xBB; 32]),
            TrustStatus::Trusted
        );
        // s1's add was lost when s2 overwrote — pin this so the
        // contract is explicit. If we ever add file locking or a
        // merge step, this assertion flips and is a deliberate
        // semver moment.
        assert_eq!(
            s3.lookup("a.example", &[0xAA; 32]),
            TrustStatus::Unknown
        );
    }
}
