#![forbid(unsafe_code)]

//! High-level DTLS 1.0/1.2 session wrapper.
//!
//! [`DtlsSession`] owns a [`DtlsClientHandshake`], routes incoming
//! [`DtlsRecord`]s through it (decrypting epoch=1 records first when
//! the server transitions cipher), drives the client finish flight, and
//! after handshake completion exposes a stateful application-data
//! encrypt/decrypt API with per-direction sequence numbers.
//!
//! Sans-io: the caller is responsible for reading/writing UDP datagrams
//! and serializing [`DtlsRecord`]s on the wire.
//!
//! ```text
//! Caller                     DtlsSession                  RdpeudpSession (UDP)
//!   new(rng)        ─────►   build ClientHello   ─────►   send datagram(s)
//!   recv datagram   ─────►   feed_record(rec)
//!                            ├─► HVR     → re-ClientHello
//!                            ├─► ServerHello/Cert/SHD
//!                            └─► CCS+Finished (after CKE flight)
//!   is_connected()  ─────►   true
//!   encrypt_app_data       ─────►   APPLICATION_DATA record  ─────►   send datagram
//!   feed_record(app)       ─────►   decrypt_app_data → plaintext
//! ```

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::dtls::{
    ct_eq, decrypt_record, encrypt_record, DtlsRecord, KeyBlock, AES_BLOCK_SIZE,
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
};
use crate::dtls_handshake::{
    DtlsClientHandshake, DtlsError, DtlsRandom, DtlsState,
};

/// High-level DTLS client session — drives the handshake and then
/// transports application data with per-direction record sequencing.
pub struct DtlsSession {
    handshake: DtlsClientHandshake,
    pending_outgoing: VecDeque<DtlsRecord>,

    /// Frozen at handshake completion so app-data encrypt/decrypt
    /// doesn't borrow back into the handshake.
    keys: Option<KeyBlock>,
    version: [u8; 2],

    /// Outgoing application-data record sequence (epoch 1, distinct
    /// from the handshake's record_seq once Connected).
    app_send_seq: u64,
    /// Highest server epoch=1 sequence number we've accepted; we
    /// require strictly increasing seqnums (anti-replay).
    last_recv_seq: Option<u64>,
}

impl DtlsSession {
    /// Build a new client session and queue the initial ClientHello.
    pub fn new<R: DtlsRandom>(rng: &mut R) -> Result<Self, DtlsError> {
        let mut handshake = DtlsClientHandshake::new(rng);
        let initial = handshake.build_client_hello()?;
        let mut pending = VecDeque::new();
        for rec in initial {
            pending.push_back(rec);
        }
        Ok(Self {
            handshake,
            pending_outgoing: pending,
            keys: None,
            version: crate::dtls::DTLS_1_0,
            app_send_seq: 0,
            last_recv_seq: None,
        })
    }

    /// Take all queued outgoing records (handshake or post-handshake).
    pub fn drain_outgoing(&mut self) -> Vec<DtlsRecord> {
        self.pending_outgoing.drain(..).collect()
    }

    /// True once both server `Finished` has verified.
    pub fn is_connected(&self) -> bool {
        self.handshake.is_connected()
    }

    /// Negotiated wire version (DTLS 1.0 or 1.2).
    pub fn negotiated_version(&self) -> [u8; 2] {
        self.handshake.negotiated_version()
    }

    /// Server's leaf-cert SubjectPublicKeyInfo (after `Certificate` is
    /// processed). Use this with [`Self::verify_server_spki`] to pin
    /// against the main RDP TLS channel per MS-RDPEMT §5.1.
    pub fn server_spki(&self) -> Option<&[u8]> {
        self.handshake.server_spki()
    }

    /// Constant-time check that the DTLS server's SPKI exactly matches
    /// `expected` (typically the SPKI captured from the main RDP TLS
    /// connection). MS-RDPEMT §5.1 mandates this; mismatch indicates an
    /// active MITM on the UDP path.
    pub fn verify_server_spki(&self, expected: &[u8]) -> bool {
        match self.handshake.server_spki() {
            Some(actual) => ct_eq(actual, expected),
            None => false,
        }
    }

    /// Feed a received DTLS record into the session. Plaintext records
    /// (epoch 0) go straight to the handshake; encrypted records
    /// (epoch ≥ 1) are decrypted first and dispatched by their inner
    /// content type.
    ///
    /// May internally produce response records (e.g. a retried
    /// ClientHello after a HelloVerifyRequest, or the CKE+CCS+Finished
    /// flight after ServerHelloDone) — those are queued and become
    /// visible via [`Self::drain_outgoing`].
    pub fn feed_record<R: DtlsRandom>(
        &mut self,
        rng: &mut R,
        record: &DtlsRecord,
    ) -> Result<(), DtlsError> {
        // Encrypted records arrive once the server enters epoch 1
        // (server CCS or Finished, then any application data). Decrypt
        // before letting the handshake or the app layer see them.
        let plaintext_record;
        let dispatched: &DtlsRecord = if record.epoch == 0 {
            record
        } else {
            // Need server keys to decrypt. They land at the same time
            // we send our CKE (we derive both directions from the same
            // key block in build_client_finish_flight).
            let keys = self.handshake.keys().ok_or(DtlsError::InvalidState(
                "encrypted record before keys derived",
            ))?;
            // Anti-replay: enforce strictly increasing seqnum within
            // epoch 1.
            if let Some(prev) = self.last_recv_seq {
                if record.sequence_number <= prev {
                    return Err(DtlsError::Protocol("DTLS replay/out-of-order"));
                }
            }
            let plaintext = decrypt_record(
                &keys.server_write_mac_key,
                &keys.server_write_key,
                record.content_type,
                &record.version,
                record.epoch,
                record.sequence_number,
                &record.fragment,
            )
            .ok_or(DtlsError::Protocol("DTLS record decrypt failed"))?;
            self.last_recv_seq = Some(record.sequence_number);
            plaintext_record = DtlsRecord {
                content_type: record.content_type,
                version: record.version,
                epoch: record.epoch,
                sequence_number: record.sequence_number,
                fragment: plaintext,
            };
            &plaintext_record
        };

        // Application data after handshake completes is returned to
        // the caller via decrypt_app_data — it doesn't go through the
        // handshake's receive() path.
        if dispatched.content_type == CONTENT_TYPE_APPLICATION_DATA {
            return Err(DtlsError::InvalidState(
                "application data must be consumed via decrypt_app_data",
            ));
        }

        let responses = self.handshake.receive(dispatched)?;
        for r in responses {
            self.pending_outgoing.push_back(r);
        }

        // After ServerHelloDone we transition to SendClientFinish; the
        // wrapper drives the client flight automatically so callers
        // don't have to remember the magic state.
        if self.handshake.state() == DtlsState::SendClientFinish {
            let flight = self.handshake.build_client_finish_flight(rng)?;
            for r in flight {
                self.pending_outgoing.push_back(r);
            }
        }

        // Snapshot final keys/version once Connected so app data can
        // run without re-borrowing the handshake.
        if self.handshake.is_connected() && self.keys.is_none() {
            self.keys = self.handshake.keys().cloned();
            self.version = self.handshake.negotiated_version();
        }
        Ok(())
    }

    /// Encrypt application data. Returns a sealed [`DtlsRecord`] with
    /// `content_type = APPLICATION_DATA` and `epoch = 1`.
    pub fn encrypt_app_data<R: DtlsRandom>(
        &mut self,
        rng: &mut R,
        plaintext: &[u8],
    ) -> Result<DtlsRecord, DtlsError> {
        let keys = self
            .keys
            .as_ref()
            .ok_or(DtlsError::InvalidState("encrypt_app_data before Connected"))?;
        let mut iv = [0u8; AES_BLOCK_SIZE];
        rng.fill(&mut iv);
        let fragment = encrypt_record(
            &keys.client_write_mac_key,
            &keys.client_write_key,
            &iv,
            CONTENT_TYPE_APPLICATION_DATA,
            &self.version,
            1, // epoch 1 for all post-handshake records
            self.app_send_seq,
            plaintext,
        );
        let rec = DtlsRecord {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            version: self.version,
            epoch: 1,
            sequence_number: self.app_send_seq,
            fragment,
        };
        self.app_send_seq = self.app_send_seq.checked_add(1).ok_or(
            DtlsError::InvalidState("DTLS send sequence number wrap"),
        )?;
        Ok(rec)
    }

    /// Decrypt an application-data record received from the server.
    /// Enforces strictly increasing server sequence numbers; out-of-
    /// order or replayed records are rejected.
    pub fn decrypt_app_data(&mut self, record: &DtlsRecord) -> Result<Vec<u8>, DtlsError> {
        if record.content_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(DtlsError::InvalidState(
                "decrypt_app_data on non-app record",
            ));
        }
        if record.epoch != 1 {
            return Err(DtlsError::InvalidState("app data must be epoch 1"));
        }
        let keys = self
            .keys
            .as_ref()
            .ok_or(DtlsError::InvalidState("decrypt_app_data before Connected"))?;
        if let Some(prev) = self.last_recv_seq {
            if record.sequence_number <= prev {
                return Err(DtlsError::Protocol("DTLS app-data replay/out-of-order"));
            }
        }
        let plaintext = decrypt_record(
            &keys.server_write_mac_key,
            &keys.server_write_key,
            CONTENT_TYPE_APPLICATION_DATA,
            &record.version,
            record.epoch,
            record.sequence_number,
            &record.fragment,
        )
        .ok_or(DtlsError::Protocol("DTLS app-data decrypt failed"))?;
        self.last_recv_seq = Some(record.sequence_number);
        Ok(plaintext)
    }
}

// `CONTENT_TYPE_HANDSHAKE` and `CONTENT_TYPE_CHANGE_CIPHER_SPEC` are
// re-exported so loopback tests in other crates don't have to dig into
// the dtls module just to drive the wrapper.
pub use crate::dtls::{
    CONTENT_TYPE_APPLICATION_DATA as APPLICATION_DATA_CONTENT_TYPE,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC as CHANGE_CIPHER_SPEC_CONTENT_TYPE,
    CONTENT_TYPE_HANDSHAKE as HANDSHAKE_CONTENT_TYPE,
};

// Keep the imports above honest for clippy / dead-code checks.
#[allow(dead_code)]
const _ASSERT: (u8, u8, u8) = (
    CONTENT_TYPE_HANDSHAKE,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_APPLICATION_DATA,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtls::{KeyBlock, DTLS_1_2};
    use alloc::vec;

    /// A counter-based RNG for deterministic test vectors. NOT
    /// cryptographically secure — tests only.
    struct CounterRng(u8);
    impl DtlsRandom for CounterRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    /// Build a fresh client session and harvest its initial flight.
    #[test]
    fn new_session_emits_client_hello() {
        let mut rng = CounterRng(0);
        let mut session = DtlsSession::new(&mut rng).unwrap();
        let outgoing = session.drain_outgoing();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].content_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(outgoing[0].epoch, 0);
        assert!(!session.is_connected());
        assert!(session.server_spki().is_none());
    }

    /// drain_outgoing is idempotent — calling twice returns no records
    /// the second time until new ones are queued.
    #[test]
    fn drain_outgoing_is_idempotent() {
        let mut rng = CounterRng(0);
        let mut session = DtlsSession::new(&mut rng).unwrap();
        let first = session.drain_outgoing();
        let second = session.drain_outgoing();
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
    }

    #[test]
    fn encrypt_app_data_before_connected_errors() {
        let mut rng = CounterRng(0);
        let mut session = DtlsSession::new(&mut rng).unwrap();
        let err = session.encrypt_app_data(&mut rng, b"hi").unwrap_err();
        assert!(matches!(err, DtlsError::InvalidState(_)));
    }

    #[test]
    fn decrypt_app_data_before_connected_errors() {
        let mut rng = CounterRng(0);
        let mut session = DtlsSession::new(&mut rng).unwrap();
        let fake = DtlsRecord {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            version: DTLS_1_2,
            epoch: 1,
            sequence_number: 0,
            fragment: vec![0u8; 64],
        };
        assert!(session.decrypt_app_data(&fake).is_err());
    }

    /// Synthetic test: pretend the handshake finished, splice key
    /// material in, then verify encrypt/decrypt round-trips when the
    /// "server" mirror runs the same primitives with swapped roles.
    /// This exercises the post-handshake send/recv state independently
    /// of the handshake state machine — a full handshake loopback
    /// lives in tests/dtls_loopback.rs (Commit C.2).
    #[test]
    fn app_data_roundtrip_against_mirror_keys() {
        // Construct a key block where client_write and server_write
        // are different so MAC failures would be detected.
        let keys = KeyBlock {
            client_write_mac_key: [0xC1; 32],
            server_write_mac_key: [0x53; 32],
            client_write_key: [0xC2; 16],
            server_write_key: [0x54; 16],
        };
        let version = DTLS_1_2;

        // Build a session in "Connected"-equivalent state by driving
        // the wrapper into a configuration where keys + version are
        // populated. We can't reach Connected without a server, so
        // construct a fresh session and patch the post-Connected
        // fields directly via a small helper.
        let mut session = make_synthetic_connected_session(keys.clone(), version);
        let mut rng = CounterRng(0xA0);

        // Client encrypts → server decrypts using server-side keys.
        let plaintext = b"jcr loopback";
        let record = session.encrypt_app_data(&mut rng, plaintext).unwrap();
        assert_eq!(record.content_type, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(record.epoch, 1);
        assert_eq!(record.sequence_number, 0);

        // "Server" decrypts using its own (client_write) keys.
        let decrypted = decrypt_record(
            &keys.client_write_mac_key,
            &keys.client_write_key,
            CONTENT_TYPE_APPLICATION_DATA,
            &record.version,
            record.epoch,
            record.sequence_number,
            &record.fragment,
        )
        .expect("server-side decrypt of client record");
        assert_eq!(decrypted, plaintext);

        // Server encrypts → client decrypts via session.decrypt_app_data.
        let server_seq = 0u64;
        let server_iv = [0xEE; 16];
        let server_fragment = encrypt_record(
            &keys.server_write_mac_key,
            &keys.server_write_key,
            &server_iv,
            CONTENT_TYPE_APPLICATION_DATA,
            &version,
            1,
            server_seq,
            b"server reply",
        );
        let server_record = DtlsRecord {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            version,
            epoch: 1,
            sequence_number: server_seq,
            fragment: server_fragment,
        };
        let plaintext = session.decrypt_app_data(&server_record).unwrap();
        assert_eq!(plaintext, b"server reply");
    }

    #[test]
    fn app_data_replay_rejected() {
        let keys = KeyBlock {
            client_write_mac_key: [0x11; 32],
            server_write_mac_key: [0x22; 32],
            client_write_key: [0x33; 16],
            server_write_key: [0x44; 16],
        };
        let version = DTLS_1_2;
        let mut session = make_synthetic_connected_session(keys.clone(), version);

        let iv = [0x77; 16];
        let frag = encrypt_record(
            &keys.server_write_mac_key,
            &keys.server_write_key,
            &iv,
            CONTENT_TYPE_APPLICATION_DATA,
            &version,
            1,
            5, // arbitrary seq
            b"once",
        );
        let rec = DtlsRecord {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            version,
            epoch: 1,
            sequence_number: 5,
            fragment: frag.clone(),
        };
        let _ = session.decrypt_app_data(&rec).unwrap();
        // Same seqnum again → rejected.
        let dup = DtlsRecord { fragment: frag.clone(), ..rec.clone() };
        assert!(session.decrypt_app_data(&dup).is_err());
        // Lower seqnum → rejected.
        let lower = DtlsRecord { sequence_number: 3, fragment: frag, ..rec };
        assert!(session.decrypt_app_data(&lower).is_err());
    }

    #[test]
    fn verify_server_spki_no_handshake_returns_false() {
        let mut rng = CounterRng(0);
        let session = DtlsSession::new(&mut rng).unwrap();
        // Before Certificate is processed, no SPKI captured.
        assert!(!session.verify_server_spki(b"anything"));
        assert!(session.server_spki().is_none());
    }

    #[test]
    fn encrypt_seq_advances_on_success() {
        let keys = KeyBlock {
            client_write_mac_key: [0xAA; 32],
            server_write_mac_key: [0xBB; 32],
            client_write_key: [0xCC; 16],
            server_write_key: [0xDD; 16],
        };
        let mut session = make_synthetic_connected_session(keys, DTLS_1_2);
        let mut rng = CounterRng(0);
        let r0 = session.encrypt_app_data(&mut rng, b"a").unwrap();
        let r1 = session.encrypt_app_data(&mut rng, b"b").unwrap();
        assert_eq!(r0.sequence_number, 0);
        assert_eq!(r1.sequence_number, 1);
    }

    /// Drive a session into a state mathematically equivalent to
    /// "Connected" so post-handshake APIs can be tested without
    /// running the actual handshake. Used by tests in this module
    /// only — production code reaches Connected via `feed_record`.
    fn make_synthetic_connected_session(keys: KeyBlock, version: [u8; 2]) -> DtlsSession {
        let mut rng = CounterRng(0);
        let mut session = DtlsSession::new(&mut rng).unwrap();
        session.keys = Some(keys);
        session.version = version;
        // We don't pretend the handshake field reports Connected — the
        // post-handshake APIs only touch session.keys / .version /
        // .app_send_seq / .last_recv_seq, all of which are owned by
        // the wrapper itself. is_connected() will still return false
        // (it delegates to the handshake), which is correct: this
        // helper exposes only what unit tests need.
        session
    }
}
