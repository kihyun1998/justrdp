//! [`RdpecamEnumeratorClient`] -- DVC processor for the fixed
//! `RDCamera_Device_Enumerator` channel (MS-RDPECAM §2.1).
//!
//! # State machine
//!
//! ```text
//!   start()  ──► Uninitialised
//!       │           │  (queue SelectVersionRequest → return from start())
//!       ▼           ▼
//!   ╔════════════════════╗   process(SelectVersionResponse)   ╔═══════════╗
//!   ║  AwaitingVersion    ║ ───────────────────────────────► ║  Ready    ║
//!   ╚════════════════════╝                                   ╚═══════════╝
//!                                                                   │
//!                                                                   ▼
//!                                                         announce_device() /
//!                                                           remove_device()
//!                                                        produce notifications
//! ```
//!
//! In the `Ready` state the host is free to announce cameras as they
//! become visible on the local machine. Each call to
//! [`RdpecamEnumeratorClient::announce_device`] returns a pre-encoded
//! [`DvcMessage`] containing a `DeviceAddedNotification` for the host to
//! dispatch, AND records the device in a private map so that the host
//! can later look up the per-device DVC name it committed to. The
//! orchestration of `DrdynvcClient::register` for the per-device
//! processor is explicitly the host's responsibility (see the crate
//! root docs) -- this type does not own the DVC router.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, ReadCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::constants::{VERSION_1, VERSION_2};
use crate::pdu::encode_to_vec;
use crate::pdu::enumeration::{
    DeviceAddedNotification, DeviceRemovedNotification, SelectVersionRequest,
    SelectVersionResponse, MAX_DEVICE_NAME_UTF16, MAX_VIRTUAL_CHANNEL_NAME,
};
use crate::ENUMERATOR_CHANNEL_NAME;

/// Internal lifecycle of the enumerator processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnumeratorState {
    /// `start()` has not been called yet; no DVC is open.
    Uninitialised,
    /// `start()` has been called, `SelectVersionRequest` has been queued
    /// for dispatch, and we are waiting for the server's
    /// `SelectVersionResponse`.
    AwaitingVersion { client_max: u8 },
    /// Version negotiation is complete. Any further traffic is the host
    /// announcing or removing devices.
    Ready { negotiated: u8 },
    /// The DVC was closed.
    Closed,
}

/// Announced device record kept inside the enumerator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncedDevice {
    /// Display name (raw UTF-16 code units, no terminator).
    pub device_name: Vec<u16>,
    /// Per-device channel name (raw ANSI bytes, no terminator). The host
    /// must install a per-device `DvcProcessor` under exactly this name
    /// before the server issues a `CreateRequest` for it.
    pub virtual_channel_name: Vec<u8>,
}

/// DVC processor for the fixed enumeration channel.
///
/// Construct via [`RdpecamEnumeratorClient::builder`], register with
/// `DrdynvcClient`, and then drive device hot-plug through
/// [`Self::announce_device`] / [`Self::remove_device`].
pub struct RdpecamEnumeratorClient {
    client_max_version: u8,
    state: EnumeratorState,
    channel_id: u32,
    devices: BTreeMap<Vec<u8>, AnnouncedDevice>,
}

impl core::fmt::Debug for RdpecamEnumeratorClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpecamEnumeratorClient")
            .field("client_max_version", &self.client_max_version)
            .field("state", &self.state)
            .field("channel_id", &self.channel_id)
            .field("device_count", &self.devices.len())
            .finish()
    }
}

// ── Builder ──

/// Fluent builder for [`RdpecamEnumeratorClient`].
#[derive(Debug, Clone)]
pub struct RdpecamEnumeratorBuilder {
    client_max_version: u8,
}

impl Default for RdpecamEnumeratorBuilder {
    fn default() -> Self {
        // Default to v2 so the property API is advertised; the server
        // will downgrade to v1 automatically if it does not understand
        // v2. Hosts that want to pin v1 explicitly can call
        // `max_version(VERSION_1)`.
        Self { client_max_version: VERSION_2 }
    }
}

impl RdpecamEnumeratorBuilder {
    /// Overrides the maximum protocol version offered to the server.
    /// Must be one of [`VERSION_1`] or [`VERSION_2`]; any other value is
    /// clamped to `VERSION_2`.
    pub fn max_version(mut self, version: u8) -> Self {
        self.client_max_version = match version {
            VERSION_1 | VERSION_2 => version,
            _ => VERSION_2,
        };
        self
    }

    pub fn build(self) -> RdpecamEnumeratorClient {
        RdpecamEnumeratorClient {
            client_max_version: self.client_max_version,
            state: EnumeratorState::Uninitialised,
            channel_id: 0,
            devices: BTreeMap::new(),
        }
    }
}

impl RdpecamEnumeratorClient {
    /// Returns a default builder. Default max protocol version is 2.
    pub fn builder() -> RdpecamEnumeratorBuilder {
        RdpecamEnumeratorBuilder::default()
    }

    /// Convenience constructor equivalent to `builder().build()`.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Returns the negotiated protocol version once the handshake has
    /// completed. `None` before the server responds.
    pub fn negotiated_version(&self) -> Option<u8> {
        match self.state {
            EnumeratorState::Ready { negotiated } => Some(negotiated),
            _ => None,
        }
    }

    /// True when the enumerator is past version negotiation and it is
    /// safe to announce devices.
    pub fn is_ready(&self) -> bool {
        matches!(self.state, EnumeratorState::Ready { .. })
    }

    /// Number of devices currently announced to the server but not yet removed.
    pub fn announced_count(&self) -> usize {
        self.devices.len()
    }

    /// True iff a device with this per-device channel name has been
    /// announced and not yet removed.
    pub fn has_device(&self, virtual_channel_name: &[u8]) -> bool {
        self.devices.contains_key(virtual_channel_name)
    }

    /// Announces a new camera to the server.
    ///
    /// Returns a single [`DvcMessage`] carrying the encoded
    /// `DeviceAddedNotification`. The host MUST dispatch the returned
    /// bytes on the enumerator DVC, AND ensure a per-device
    /// `DvcProcessor` is registered on `DrdynvcClient` under exactly
    /// `virtual_channel_name` BEFORE it forwards the notification to
    /// the server -- otherwise the subsequent server-side `CreateRequest`
    /// for the per-device channel will fail to match.
    ///
    /// Errors:
    ///
    /// - [`DvcError::Protocol`] if the enumerator is not yet in the
    ///   `Ready` state (no version negotiation completed).
    /// - [`DvcError::Protocol`] if a device with the same
    ///   `virtual_channel_name` is already announced.
    /// - [`DvcError::Encode`] / [`DvcError::Protocol`] if the supplied
    ///   names violate the MS-RDPECAM length caps.
    pub fn announce_device(
        &mut self,
        device_name: Vec<u16>,
        virtual_channel_name: Vec<u8>,
    ) -> DvcResult<DvcMessage> {
        let negotiated = match self.state {
            EnumeratorState::Ready { negotiated } => negotiated,
            _ => {
                return Err(DvcError::Protocol(String::from(
                    "RDPECAM enumerator: announce_device before version negotiation",
                )));
            }
        };
        if device_name.len() > MAX_DEVICE_NAME_UTF16 {
            return Err(DvcError::Protocol(String::from(
                "RDPECAM enumerator: device_name exceeds MAX_DEVICE_NAME_UTF16",
            )));
        }
        if virtual_channel_name.len() + 1 > MAX_VIRTUAL_CHANNEL_NAME {
            return Err(DvcError::Protocol(String::from(
                "RDPECAM enumerator: virtual_channel_name exceeds cap",
            )));
        }
        if virtual_channel_name.is_empty() {
            return Err(DvcError::Protocol(String::from(
                "RDPECAM enumerator: virtual_channel_name must be non-empty",
            )));
        }
        if self.devices.contains_key(&virtual_channel_name) {
            return Err(DvcError::Protocol(String::from(
                "RDPECAM enumerator: duplicate virtual_channel_name",
            )));
        }
        let pdu = DeviceAddedNotification {
            version: negotiated,
            device_name: device_name.clone(),
            virtual_channel_name: virtual_channel_name.clone(),
        };
        let bytes = encode_to_vec(&pdu)?;
        self.devices.insert(
            virtual_channel_name.clone(),
            AnnouncedDevice {
                device_name,
                virtual_channel_name,
            },
        );
        Ok(DvcMessage::new(bytes))
    }

    /// Removes a previously announced device. Returns the
    /// `DeviceRemovedNotification` to be dispatched on the enumerator
    /// DVC. The host is responsible for closing the per-device DVC
    /// entry on its own (the spec says this MUST happen AFTER the
    /// notification has been sent, so the ordering is enforced by the
    /// host, not by this type).
    pub fn remove_device(&mut self, virtual_channel_name: &[u8]) -> DvcResult<DvcMessage> {
        let negotiated = match self.state {
            EnumeratorState::Ready { negotiated } => negotiated,
            _ => {
                return Err(DvcError::Protocol(String::from(
                    "RDPECAM enumerator: remove_device before version negotiation",
                )));
            }
        };
        if self.devices.remove(virtual_channel_name).is_none() {
            return Err(DvcError::Protocol(String::from(
                "RDPECAM enumerator: remove_device for unknown virtual_channel_name",
            )));
        }
        let pdu = DeviceRemovedNotification {
            version: negotiated,
            virtual_channel_name: virtual_channel_name.to_vec(),
        };
        let bytes = encode_to_vec(&pdu)?;
        Ok(DvcMessage::new(bytes))
    }
}

impl Default for RdpecamEnumeratorClient {
    fn default() -> Self {
        Self::new()
    }
}

impl AsAny for RdpecamEnumeratorClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for RdpecamEnumeratorClient {
    fn channel_name(&self) -> &str {
        ENUMERATOR_CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // Reset every bit of state carried across DVC lifetimes so that
        // a server-initiated re-create does not leak a stale device map
        // or a stale negotiated version into the new session.
        self.channel_id = channel_id;
        self.devices.clear();
        self.state = EnumeratorState::AwaitingVersion {
            client_max: self.client_max_version,
        };
        // Per MS-RDPECAM §2.2.2.1 the SelectVersionRequest MUST be the
        // first message on the enumeration channel; the cleanest place
        // to emit it is right here in the channel-open callback.
        let request = SelectVersionRequest::new(self.client_max_version);
        let bytes = encode_to_vec(&request)?;
        Ok(alloc::vec![DvcMessage::new(bytes)])
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if channel_id != self.channel_id {
            return Err(DvcError::Protocol(String::from(
                "RDPECAM enumerator: channel_id mismatch",
            )));
        }
        match self.state {
            EnumeratorState::AwaitingVersion { client_max } => {
                let mut cur = ReadCursor::new(payload);
                let resp = SelectVersionResponse::decode(&mut cur).map_err(DvcError::Decode)?;
                if cur.remaining() != 0 {
                    return Err(DvcError::Protocol(String::from(
                        "RDPECAM enumerator: trailing bytes after SelectVersionResponse",
                    )));
                }
                // The server MUST NOT pick a version greater than what
                // the client offered; guarding against a buggy server
                // here stops a malformed negotiation from poisoning the
                // property API gating.
                if resp.version > client_max {
                    return Err(DvcError::Protocol(String::from(
                        "RDPECAM enumerator: server version exceeds client max",
                    )));
                }
                self.state = EnumeratorState::Ready {
                    negotiated: resp.version,
                };
                Ok(Vec::new())
            }
            EnumeratorState::Ready { .. } => {
                // After negotiation the client is the one that sends
                // device notifications; the server should not be
                // transmitting anything. Treat any payload as protocol
                // error rather than silently dropping it.
                Err(DvcError::Protocol(String::from(
                    "RDPECAM enumerator: unexpected server payload in Ready state",
                )))
            }
            EnumeratorState::Uninitialised | EnumeratorState::Closed => {
                Err(DvcError::Protocol(String::from(
                    "RDPECAM enumerator: process() called outside open lifetime",
                )))
            }
        }
    }

    fn close(&mut self, channel_id: u32) {
        if channel_id != self.channel_id {
            return;
        }
        self.state = EnumeratorState::Closed;
        self.devices.clear();
        self.channel_id = 0;
    }
}

impl RdpecamEnumeratorClient {
    /// Test-only helper used by integration tests to drive the server
    /// side without going through an actual `SelectVersionResponse` wire
    /// message. Not exposed to library users.
    #[cfg(test)]
    pub(crate) fn force_ready(&mut self, negotiated: u8) {
        self.state = EnumeratorState::Ready { negotiated };
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u16> {
        s.chars().map(|c| c as u16).collect()
    }

    fn spin_up(client: &mut RdpecamEnumeratorClient) -> Vec<DvcMessage> {
        client.start(42).unwrap()
    }

    fn drive_through_negotiation(client_max: u8, server_version: u8) -> RdpecamEnumeratorClient {
        let mut c = RdpecamEnumeratorClient::builder()
            .max_version(client_max)
            .build();
        let init = spin_up(&mut c);
        // start() MUST emit exactly one SelectVersionRequest.
        assert_eq!(init.len(), 1);
        assert_eq!(init[0].data, alloc::vec![client_max, 0x03]);
        // Drive the response.
        let resp_bytes = alloc::vec![server_version, 0x04];
        let emitted = c.process(42, &resp_bytes).unwrap();
        assert!(emitted.is_empty());
        c
    }

    // ── State machine ──

    #[test]
    fn builder_default_is_v2() {
        let c = RdpecamEnumeratorClient::builder().build();
        assert_eq!(c.client_max_version, VERSION_2);
    }

    #[test]
    fn builder_allows_v1_override() {
        let c = RdpecamEnumeratorClient::builder()
            .max_version(VERSION_1)
            .build();
        assert_eq!(c.client_max_version, VERSION_1);
    }

    #[test]
    fn builder_clamps_bogus_version_to_v2() {
        let c = RdpecamEnumeratorClient::builder().max_version(99).build();
        assert_eq!(c.client_max_version, VERSION_2);
    }

    #[test]
    fn start_emits_select_version_request_and_enters_await() {
        let mut c = RdpecamEnumeratorClient::new();
        let out = c.start(7).unwrap();
        assert_eq!(out.len(), 1);
        // bytes should decode as SelectVersionRequest(v2).
        assert_eq!(out[0].data, alloc::vec![0x02, 0x03]);
        assert_eq!(c.channel_id, 7);
        assert!(matches!(c.state, EnumeratorState::AwaitingVersion { client_max: VERSION_2 }));
        assert!(!c.is_ready());
        assert_eq!(c.negotiated_version(), None);
    }

    #[test]
    fn full_negotiation_enters_ready() {
        let c = drive_through_negotiation(VERSION_2, VERSION_2);
        assert!(c.is_ready());
        assert_eq!(c.negotiated_version(), Some(VERSION_2));
    }

    #[test]
    fn negotiation_downgrades_to_v1_when_server_only_supports_v1() {
        let c = drive_through_negotiation(VERSION_2, VERSION_1);
        assert_eq!(c.negotiated_version(), Some(VERSION_1));
    }

    #[test]
    fn negotiation_rejects_server_version_exceeding_client_max() {
        let mut c = RdpecamEnumeratorClient::builder()
            .max_version(VERSION_1)
            .build();
        c.start(1).unwrap();
        // Server claims v2 even though we advertised v1.
        let err = c.process(1, &[VERSION_2, 0x04]).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn process_rejects_payload_before_start() {
        let mut c = RdpecamEnumeratorClient::new();
        let err = c.process(1, &[VERSION_2, 0x04]).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn process_rejects_wrong_channel_id() {
        let mut c = RdpecamEnumeratorClient::new();
        c.start(10).unwrap();
        let err = c.process(11, &[VERSION_2, 0x04]).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn process_rejects_payload_in_ready_state() {
        // After negotiation, the client owns the channel; server pushes
        // should be a protocol error.
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        let err = c.process(42, &[VERSION_2, 0x05]).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn process_rejects_trailing_bytes_after_response() {
        let mut c = RdpecamEnumeratorClient::new();
        c.start(1).unwrap();
        let err = c.process(1, &[VERSION_2, 0x04, 0xFF]).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn close_resets_state() {
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        c.close(42);
        assert!(matches!(c.state, EnumeratorState::Closed));
        assert_eq!(c.announced_count(), 0);
    }

    #[test]
    fn close_ignores_wrong_channel_id() {
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        c.close(99);
        // Still ready.
        assert!(c.is_ready());
    }

    // ── announce_device / remove_device ──

    #[test]
    fn announce_rejects_before_ready() {
        let mut c = RdpecamEnumeratorClient::new();
        let err = c
            .announce_device(utf16("Mock"), b"RDCamera_Device_0".to_vec())
            .unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn announce_happy_path_produces_correct_pdu() {
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        let msg = c
            .announce_device(utf16("Mock Camera 1"), b"RDCamera_Device_0".to_vec())
            .unwrap();
        // First two bytes: Version=2, MessageId=0x05.
        assert_eq!(&msg.data[..2], &[VERSION_2, 0x05]);
        // Device count tracks.
        assert_eq!(c.announced_count(), 1);
        assert!(c.has_device(b"RDCamera_Device_0"));
    }

    #[test]
    fn announce_rejects_duplicate_virtual_channel_name() {
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        c.announce_device(utf16("A"), b"RDCamera_Device_0".to_vec())
            .unwrap();
        let err = c
            .announce_device(utf16("B"), b"RDCamera_Device_0".to_vec())
            .unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn announce_rejects_empty_channel_name() {
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        let err = c.announce_device(utf16("x"), Vec::new()).unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn announce_rejects_channel_name_over_cap() {
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        let err = c
            .announce_device(
                utf16("x"),
                alloc::vec![b'A'; MAX_VIRTUAL_CHANNEL_NAME],
            )
            .unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn announce_rejects_device_name_over_cap() {
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        let err = c
            .announce_device(
                alloc::vec![0x41u16; MAX_DEVICE_NAME_UTF16 + 1],
                b"x".to_vec(),
            )
            .unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn remove_happy_path_produces_correct_pdu_and_drops_record() {
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        c.announce_device(utf16("Mock"), b"RDCamera_Device_0".to_vec())
            .unwrap();
        let msg = c.remove_device(b"RDCamera_Device_0").unwrap();
        assert_eq!(&msg.data[..2], &[VERSION_2, 0x06]);
        assert_eq!(c.announced_count(), 0);
        assert!(!c.has_device(b"RDCamera_Device_0"));
    }

    #[test]
    fn remove_rejects_unknown_virtual_channel_name() {
        let mut c = drive_through_negotiation(VERSION_2, VERSION_2);
        let err = c.remove_device(b"missing").unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    #[test]
    fn remove_rejects_before_ready() {
        let mut c = RdpecamEnumeratorClient::new();
        let err = c.remove_device(b"x").unwrap_err();
        assert!(matches!(err, DvcError::Protocol(_)));
    }

    // ── force_ready test helper sanity ──

    #[test]
    fn force_ready_helper_unblocks_announce() {
        let mut c = RdpecamEnumeratorClient::new();
        c.start(1).unwrap();
        c.force_ready(VERSION_2);
        assert!(c.is_ready());
        c.announce_device(utf16("x"), b"y".to_vec()).unwrap();
    }
}
