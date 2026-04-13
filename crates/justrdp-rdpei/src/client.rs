#![forbid(unsafe_code)]

//! Touch and Pen Input DVC client -- MS-RDPEI 3.2
//!
//! `RdpeiDvcClient` implements [`DvcProcessor`] for the
//! `Microsoft::Windows::RDS::Input` dynamic virtual channel. It negotiates
//! the protocol version with the server, tracks the suspend/resume state,
//! and provides an API for forwarding multi-touch events.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Encode, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::pdu::{
    CsReadyFlags, CsReadyPdu, DismissHoveringContactPdu, EVENTID_CS_READY,
    EVENTID_DISMISS_HOVERING_TOUCH_CONTACT, EVENTID_PEN, EVENTID_RESUME_INPUT, EVENTID_SC_READY,
    EVENTID_SUSPEND_INPUT, EVENTID_TOUCH, MAX_PEN_CONTACTS_PER_FRAME, PenEventPdu, PenFrame,
    RDPINPUT_PROTOCOL_V100, RDPINPUT_PROTOCOL_V200, RDPINPUT_PROTOCOL_V300, RdpeiHeader,
    ResumeInputPdu, ScReadyFlags, ScReadyPdu, SuspendInputPdu, TouchEventPdu, TouchFrame,
};

/// DVC channel name for Touch Input.
/// MS-RDPEI 2.1
const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Input";

// =============================================================================
// Config
// =============================================================================

/// Client-side configuration for `RdpeiDvcClient`.
#[derive(Debug, Clone)]
pub struct RdpeiClientConfig {
    /// Maximum protocol version the client supports. Default: V200.
    ///
    /// During negotiation the client picks `min(server_version, client_max)`.
    pub client_max_version: u32,
    /// Flags advertised in the CS_READY PDU (`CsReadyFlags::*`). Default: 0.
    pub cs_ready_flags: u32,
    /// Maximum simultaneous touch contacts the client reports. Default: 10.
    pub max_touch_contacts: u16,
    /// Upper bound on the internal outbound queue. When the queue is full,
    /// `send_touch_event` and `dismiss_hovering_contact` return an error
    /// instead of pushing, preventing unbounded growth if the application
    /// forgets to call `take_pending_messages`. Default: 1024.
    pub max_pending_messages: usize,
}

impl Default for RdpeiClientConfig {
    fn default() -> Self {
        Self {
            client_max_version: RDPINPUT_PROTOCOL_V200,
            cs_ready_flags: 0,
            max_touch_contacts: 10,
            max_pending_messages: 1024,
        }
    }
}

// =============================================================================
// State machine
// =============================================================================

/// Internal state of the DVC processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for the server's SC_READY PDU.
    WaitScReady,
    /// CS_READY has been queued; touch events may be sent (unless suspended).
    Ready,
}

// =============================================================================
// Client
// =============================================================================

/// Touch Input DVC client.
///
/// Implements [`DvcProcessor`] for `Microsoft::Windows::RDS::Input`.
///
/// ```ignore
/// use justrdp_rdpei::RdpeiDvcClient;
/// use justrdp_dvc::DrdynvcClient;
///
/// let mut drdynvc = DrdynvcClient::new();
/// drdynvc.register(Box::new(RdpeiDvcClient::new()));
/// ```
pub struct RdpeiDvcClient {
    config: RdpeiClientConfig,
    state: State,
    /// Negotiated protocol version = `min(server_version, client_max_version)`.
    /// `None` until SC_READY is received.
    negotiated_version: Option<u32>,
    /// `supportedFeatures` from the server (V300 only).
    server_features: Option<u32>,
    /// Server-controlled ADM: MS-RDPEI 3.3.1.1.
    input_suspended: bool,
    /// Pen Input Allowed ADM (MS-RDPEI 3.3.1.2): `true` when the negotiated
    /// protocol version supports pen (V200+).
    pen_input_allowed: bool,
    /// Multipen injection active: negotiated V300 + server advertised
    /// `SC_READY_MULTIPEN_INJECTION_SUPPORTED` + client requested
    /// `CS_READY_FLAGS_ENABLE_MULTIPEN_INJECTION`.
    multipen_active: bool,
    /// Client-initiated outbound messages queued between `process()` calls.
    outbound: Vec<DvcMessage>,
}

impl RdpeiDvcClient {
    /// Create a new client with default config.
    pub fn new() -> Self {
        Self::with_config(RdpeiClientConfig::default())
    }

    /// Create a new client with custom config.
    pub fn with_config(config: RdpeiClientConfig) -> Self {
        Self {
            config,
            state: State::WaitScReady,
            negotiated_version: None,
            server_features: None,
            input_suspended: false,
            pen_input_allowed: false,
            multipen_active: false,
            outbound: Vec::new(),
        }
    }

    /// Returns `true` once CS_READY has been sent.
    pub fn is_ready(&self) -> bool {
        matches!(self.state, State::Ready)
    }

    /// Returns `true` while the server has issued SUSPEND_INPUT without a
    /// matching RESUME_INPUT. MS-RDPEI 3.3.5.4
    pub fn is_input_suspended(&self) -> bool {
        self.input_suspended
    }

    /// Negotiated protocol version (`None` until SC_READY is received).
    pub fn negotiated_version(&self) -> Option<u32> {
        self.negotiated_version
    }

    /// Server-advertised `supportedFeatures` (V300 only).
    pub fn server_features(&self) -> Option<u32> {
        self.server_features
    }

    /// Whether pen input is allowed on the negotiated channel. Set to
    /// `true` after SC_READY when negotiated version >= V200. MS-RDPEI 3.3.1.2
    pub fn pen_input_allowed(&self) -> bool {
        self.pen_input_allowed
    }

    /// Whether multipen injection is active. Requires all three:
    /// negotiated V300, server `SC_READY_MULTIPEN_INJECTION_SUPPORTED`,
    /// and client `CS_READY_FLAGS_ENABLE_MULTIPEN_INJECTION`.
    pub fn multipen_active(&self) -> bool {
        self.multipen_active
    }

    /// Queue a TOUCH_EVENT_PDU to send to the server.
    ///
    /// Returns an error when the channel is not yet ready or when input
    /// transmission has been suspended (MS-RDPEI 3.3.5.4: client MUST NOT
    /// send touch events while suspended).
    pub fn send_touch_event(
        &mut self,
        encode_time: u32,
        frames: Vec<TouchFrame>,
    ) -> Result<(), String> {
        if !self.is_ready() {
            return Err(String::from("RDPEI channel is not ready"));
        }
        if self.input_suspended {
            return Err(String::from("input transmission is suspended"));
        }
        let pdu = TouchEventPdu {
            encode_time,
            frames,
        };
        self.enqueue_pdu(&pdu)
            .map_err(|e| format!("failed to encode TouchEventPdu: {e:?}"))?;
        Ok(())
    }

    /// Queue an RDPINPUT_PEN_EVENT_PDU to send to the server.
    ///
    /// Requires the negotiated version to be V200 or higher (checked via
    /// `pen_input_allowed`). Rejected while input transmission is
    /// suspended. Validates `deviceId` against the multipen state: if
    /// multipen is not active, all contacts MUST have `device_id = 0`;
    /// if multipen is active, `device_id` must be ≤ 3 and each frame
    /// must not exceed `MAX_PEN_CONTACTS_PER_FRAME`.
    pub fn send_pen_event(
        &mut self,
        encode_time: u32,
        frames: Vec<PenFrame>,
    ) -> Result<(), String> {
        if !self.is_ready() {
            return Err(String::from("RDPEI channel is not ready"));
        }
        if !self.pen_input_allowed {
            return Err(String::from(
                "pen input not allowed (negotiated version < V200)",
            ));
        }
        if self.input_suspended {
            return Err(String::from("input transmission is suspended"));
        }
        if frames.is_empty() {
            return Err(String::from("pen event must contain at least one frame"));
        }
        for frame in &frames {
            if frame.contacts.len() > MAX_PEN_CONTACTS_PER_FRAME as usize {
                return Err(format!(
                    "pen frame has {} contacts, max is {}",
                    frame.contacts.len(),
                    MAX_PEN_CONTACTS_PER_FRAME
                ));
            }
            if !self.multipen_active {
                // Single-pen mode: only device_id = 0 permitted.
                if let Some(bad) = frame.contacts.iter().find(|c| c.device_id != 0) {
                    return Err(format!(
                        "device_id {} must be 0 when multipen is not active",
                        bad.device_id
                    ));
                }
                if frame.contacts.len() > 1 {
                    return Err(format!(
                        "single-pen mode permits 1 contact per frame, got {}",
                        frame.contacts.len()
                    ));
                }
            } else if let Some(bad) = frame.contacts.iter().find(|c| c.device_id > 3) {
                return Err(format!(
                    "device_id {} must be <= 3 when multipen is active",
                    bad.device_id
                ));
            }
        }
        let pdu = PenEventPdu {
            encode_time,
            frames,
        };
        self.enqueue_pdu(&pdu)
            .map_err(|e| format!("failed to encode PenEventPdu: {e:?}"))?;
        Ok(())
    }

    /// Queue a DISMISS_HOVERING_TOUCH_CONTACT_PDU for the given contact.
    ///
    /// MS-RDPEI 2.2.3.6: used to transition a hovering contact back to
    /// out-of-range. Valid after CS_READY even while input is suspended
    /// (SUSPEND_INPUT gates touch frames, not hover dismissal).
    pub fn dismiss_hovering_contact(&mut self, contact_id: u8) -> Result<(), String> {
        if !self.is_ready() {
            return Err(String::from("RDPEI channel is not ready"));
        }
        let pdu = DismissHoveringContactPdu { contact_id };
        self.enqueue_pdu(&pdu)
            .map_err(|e| format!("failed to encode DismissHoveringContactPdu: {e:?}"))?;
        Ok(())
    }

    /// Drain all queued outbound messages.
    ///
    /// Call this after invoking `send_touch_event` /
    /// `dismiss_hovering_contact` to retrieve the encoded PDUs for
    /// transmission on the DVC channel.
    pub fn take_pending_messages(&mut self) -> Vec<DvcMessage> {
        core::mem::take(&mut self.outbound)
    }

    // ── Internals ──

    fn enqueue_pdu<E: Encode>(&mut self, pdu: &E) -> DvcResult<()> {
        if self.outbound.len() >= self.config.max_pending_messages {
            return Err(DvcError::Protocol(String::from(
                "RDPEI outbound queue is full (max_pending_messages)",
            )));
        }
        let msg = encode_pdu(pdu)?;
        self.outbound.push(msg);
        Ok(())
    }

    /// Handle SC_READY: store negotiated version, queue CS_READY response.
    fn handle_sc_ready(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        // Preemptive reset: if decode fails midway (malformed SC_READY),
        // previous-session pen state must not leak through and let the
        // caller keep sending pen events under stale negotiation.
        self.pen_input_allowed = false;
        self.multipen_active = false;
        let sc_ready = ScReadyPdu::decode_from(payload).map_err(DvcError::Decode)?;
        let negotiated = core::cmp::min(sc_ready.protocol_version, self.config.client_max_version);
        self.negotiated_version = Some(negotiated);
        self.server_features = sc_ready.supported_features;

        // Pen Input Allowed ADM: set when negotiated >= V200 (MS-RDPEI 3.3.1.2).
        self.pen_input_allowed = negotiated >= RDPINPUT_PROTOCOL_V200;

        // Strip DISABLE_TIMESTAMP_INJECTION when negotiating V100 (MS-RDPEI
        // 2.2.3.2 SHOULD NOT be sent to V100 servers).
        let mut flags = self.config.cs_ready_flags;
        if negotiated == RDPINPUT_PROTOCOL_V100 {
            flags &= !CsReadyFlags::DISABLE_TIMESTAMP_INJECTION;
        }

        // Multipen injection requires all three: negotiated V300, server
        // advertises SC_READY_MULTIPEN_INJECTION_SUPPORTED, and client
        // requests CS_READY_FLAGS_ENABLE_MULTIPEN_INJECTION. Strip the
        // client request flag if the preconditions are not met
        // (SHOULD NOT send without server advertisement).
        let client_wants_multipen = flags & CsReadyFlags::ENABLE_MULTIPEN_INJECTION != 0;
        let server_advertises = sc_ready
            .supported_features
            .is_some_and(|f| f & ScReadyFlags::MULTIPEN_INJECTION_SUPPORTED != 0);
        let multipen_ok =
            negotiated >= RDPINPUT_PROTOCOL_V300 && server_advertises && client_wants_multipen;
        if !multipen_ok {
            flags &= !CsReadyFlags::ENABLE_MULTIPEN_INJECTION;
        }
        self.multipen_active = multipen_ok;

        let cs_ready = CsReadyPdu {
            flags,
            protocol_version: negotiated,
            max_touch_contacts: self.config.max_touch_contacts,
        };
        let msg = encode_pdu(&cs_ready)?;
        self.state = State::Ready;
        // Re-entry into WaitScReady (e.g., server re-sends SC_READY) must also
        // clear the suspended flag: a fresh handshake starts from unsuspended.
        self.input_suspended = false;
        Ok(alloc::vec![msg])
    }
}

impl Default for RdpeiDvcClient {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for RdpeiDvcClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpeiDvcClient")
            .field("state", &self.state)
            .field("negotiated_version", &self.negotiated_version)
            .field("server_features", &self.server_features)
            .field("input_suspended", &self.input_suspended)
            .field("pending_outbound", &self.outbound.len())
            .finish()
    }
}

impl AsAny for RdpeiDvcClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for RdpeiDvcClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // Server speaks first (SC_READY).
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        // Peek at the event ID to dispatch.
        let mut src = justrdp_core::ReadCursor::new(payload);
        let header = RdpeiHeader::decode(&mut src).map_err(DvcError::Decode)?;
        match header.event_id {
            EVENTID_SC_READY => self.handle_sc_ready(payload),
            EVENTID_SUSPEND_INPUT => {
                // Full PDU validation (length, etc.).
                SuspendInputPdu::decode_from(payload).map_err(DvcError::Decode)?;
                self.input_suspended = true;
                Ok(Vec::new())
            }
            EVENTID_RESUME_INPUT => {
                ResumeInputPdu::decode_from(payload).map_err(DvcError::Decode)?;
                self.input_suspended = false;
                Ok(Vec::new())
            }
            EVENTID_CS_READY
            | EVENTID_TOUCH
            | EVENTID_DISMISS_HOVERING_TOUCH_CONTACT
            | EVENTID_PEN => {
                // Client-sourced event IDs never arrive from the server.
                // MS-RDPEI 3.1.5.1: ignore unexpected PDUs.
                Ok(Vec::new())
            }
            _ => {
                // Unknown event ID (e.g., future extensions). Ignore.
                Ok(Vec::new())
            }
        }
    }

    fn close(&mut self, _channel_id: u32) {
        self.state = State::WaitScReady;
        self.negotiated_version = None;
        self.server_features = None;
        self.input_suspended = false;
        self.pen_input_allowed = false;
        self.multipen_active = false;
        self.outbound.clear();
    }
}

/// Encode any RDPEI PDU into a `DvcMessage`.
fn encode_pdu<E: Encode>(pdu: &E) -> DvcResult<DvcMessage> {
    let size = pdu.size();
    let mut buf = alloc::vec![0u8; size];
    let mut dst = WriteCursor::new(&mut buf);
    pdu.encode(&mut dst).map_err(DvcError::Encode)?;
    Ok(DvcMessage::new(buf))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{
        ContactFlags, CsReadyFlags, PenContact, PenFlags, RDPINPUT_PROTOCOL_V101,
        RDPINPUT_PROTOCOL_V300, ScReadyFlags, TouchContact, TouchFrame,
    };

    fn encode<E: Encode>(pdu: &E) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        buf
    }

    fn sc_ready(version: u32, features: Option<u32>) -> Vec<u8> {
        encode(&ScReadyPdu {
            protocol_version: version,
            supported_features: features,
        })
    }

    fn suspend() -> Vec<u8> {
        encode(&SuspendInputPdu)
    }

    fn resume() -> Vec<u8> {
        encode(&ResumeInputPdu)
    }

    fn sample_contact(id: u8) -> TouchContact {
        TouchContact {
            contact_id: id,
            x: 100,
            y: 200,
            contact_flags: ContactFlags::DOWN | ContactFlags::INRANGE | ContactFlags::INCONTACT,
            contact_rect: None,
            orientation: None,
            pressure: None,
        }
    }

    // ── Basic trait plumbing ──

    #[test]
    fn channel_name_matches_spec() {
        let c = RdpeiDvcClient::new();
        assert_eq!(c.channel_name(), "Microsoft::Windows::RDS::Input");
    }

    #[test]
    fn start_returns_empty() {
        let mut c = RdpeiDvcClient::new();
        assert!(c.start(1).unwrap().is_empty());
        assert!(!c.is_ready());
    }

    // ── SC_READY handshake & negotiation ──

    #[test]
    fn sc_ready_triggers_cs_ready_response() {
        let mut c = RdpeiDvcClient::new();
        let msgs = c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V101, None)).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(c.is_ready());
        // Response is a valid CS_READY.
        let cs = CsReadyPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(cs.protocol_version, RDPINPUT_PROTOCOL_V101);
        assert_eq!(cs.max_touch_contacts, 10);
    }

    #[test]
    fn version_negotiation_picks_min() {
        // Server V300, client default max V200 → negotiate V200.
        let mut c = RdpeiDvcClient::new();
        let msgs = c
            .process(
                1,
                &sc_ready(RDPINPUT_PROTOCOL_V300, Some(ScReadyFlags::MULTIPEN_INJECTION_SUPPORTED)),
            )
            .unwrap();
        let cs = CsReadyPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(cs.protocol_version, RDPINPUT_PROTOCOL_V200);
        assert_eq!(c.negotiated_version(), Some(RDPINPUT_PROTOCOL_V200));
        assert_eq!(
            c.server_features(),
            Some(ScReadyFlags::MULTIPEN_INJECTION_SUPPORTED)
        );
    }

    #[test]
    fn version_negotiation_server_lower_than_client_max() {
        // Server V100, client max V300 → negotiate V100.
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            client_max_version: RDPINPUT_PROTOCOL_V300,
            ..Default::default()
        });
        let msgs = c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V100, None)).unwrap();
        let cs = CsReadyPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(cs.protocol_version, RDPINPUT_PROTOCOL_V100);
    }

    #[test]
    fn v100_strips_disable_timestamp_injection_flag() {
        // Config requests DISABLE_TIMESTAMP_INJECTION + SHOW_TOUCH_VISUALS,
        // but server only speaks V100 → only SHOW_TOUCH_VISUALS survives.
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            client_max_version: RDPINPUT_PROTOCOL_V300,
            cs_ready_flags: CsReadyFlags::SHOW_TOUCH_VISUALS
                | CsReadyFlags::DISABLE_TIMESTAMP_INJECTION,
            ..Default::default()
        });
        let msgs = c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V100, None)).unwrap();
        let cs = CsReadyPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(cs.flags, CsReadyFlags::SHOW_TOUCH_VISUALS);
    }

    #[test]
    fn flags_preserved_for_v200_and_above() {
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            client_max_version: RDPINPUT_PROTOCOL_V300,
            cs_ready_flags: CsReadyFlags::SHOW_TOUCH_VISUALS
                | CsReadyFlags::DISABLE_TIMESTAMP_INJECTION,
            ..Default::default()
        });
        let msgs = c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        let cs = CsReadyPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(
            cs.flags,
            CsReadyFlags::SHOW_TOUCH_VISUALS | CsReadyFlags::DISABLE_TIMESTAMP_INJECTION
        );
    }

    // ── Suspend / Resume ──

    #[test]
    fn suspend_blocks_send_touch_event() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.take_pending_messages(); // drop CS_READY (it's in process() return, not outbound)

        let msgs = c.process(1, &suspend()).unwrap();
        assert!(msgs.is_empty());
        assert!(c.is_input_suspended());

        let err = c.send_touch_event(
            0,
            alloc::vec![TouchFrame {
                frame_offset: 0,
                contacts: alloc::vec![sample_contact(1)],
            }],
        );
        assert!(err.is_err());
    }

    #[test]
    fn resume_reenables_send() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.process(1, &suspend()).unwrap();
        c.process(1, &resume()).unwrap();
        assert!(!c.is_input_suspended());

        let result = c.send_touch_event(
            10,
            alloc::vec![TouchFrame {
                frame_offset: 0,
                contacts: alloc::vec![sample_contact(1)],
            }],
        );
        assert!(result.is_ok());
        assert_eq!(c.take_pending_messages().len(), 1);
    }

    #[test]
    fn duplicate_suspend_is_idempotent() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.process(1, &suspend()).unwrap();
        c.process(1, &suspend()).unwrap();
        assert!(c.is_input_suspended());
    }

    // ── send_touch_event / dismiss_hovering_contact ──

    #[test]
    fn send_touch_event_before_ready_fails() {
        let mut c = RdpeiDvcClient::new();
        let result = c.send_touch_event(
            0,
            alloc::vec![TouchFrame {
                frame_offset: 0,
                contacts: alloc::vec![sample_contact(1)],
            }],
        );
        assert!(result.is_err());
    }

    #[test]
    fn send_touch_event_queues_encoded_pdu() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();

        c.send_touch_event(
            12345,
            alloc::vec![TouchFrame {
                frame_offset: 0,
                contacts: alloc::vec![sample_contact(1), sample_contact(2)],
            }],
        )
        .unwrap();

        let msgs = c.take_pending_messages();
        assert_eq!(msgs.len(), 1);
        // Roundtrip the encoded PDU.
        let decoded = TouchEventPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(decoded.encode_time, 12345);
        assert_eq!(decoded.frames.len(), 1);
        assert_eq!(decoded.frames[0].contacts.len(), 2);
    }

    #[test]
    fn dismiss_hovering_contact_queues_pdu() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();

        c.dismiss_hovering_contact(7).unwrap();
        let msgs = c.take_pending_messages();
        assert_eq!(msgs.len(), 1);
        let decoded = DismissHoveringContactPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(decoded.contact_id, 7);
    }

    #[test]
    fn dismiss_hovering_contact_works_while_suspended() {
        // SUSPEND gates touch frames only, not hover dismissal.
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.process(1, &suspend()).unwrap();
        assert!(c.dismiss_hovering_contact(3).is_ok());
    }

    #[test]
    fn dismiss_hovering_contact_before_ready_fails() {
        let mut c = RdpeiDvcClient::new();
        assert!(c.dismiss_hovering_contact(1).is_err());
    }

    // ── Ignored / unexpected PDUs ──

    #[test]
    fn unknown_event_id_ignored() {
        let mut c = RdpeiDvcClient::new();
        // Hand-craft a header with event_id = 0x00FF (undefined).
        let buf = [0xFFu8, 0x00, 0x06, 0x00, 0x00, 0x00];
        let msgs = c.process(1, &buf).unwrap();
        assert!(msgs.is_empty());
        assert!(!c.is_ready());
    }

    #[test]
    fn client_sourced_event_id_ignored_on_inbound() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        // A "CS_READY" arriving FROM the server must be ignored.
        let buf = [0x02u8, 0x00, 0x10, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x01, 0x00,
                   0x00, 0x00];
        assert!(c.process(1, &buf).unwrap().is_empty());
    }

    #[test]
    fn short_payload_returns_error() {
        let mut c = RdpeiDvcClient::new();
        let short = [0x01u8, 0x00, 0x05]; // truncated header
        assert!(c.process(1, &short).is_err());
    }

    // ── Reconnect / close ──

    #[test]
    fn second_sc_ready_resends_cs_ready_and_clears_suspend() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.process(1, &suspend()).unwrap();
        assert!(c.is_input_suspended());

        // Second SC_READY (e.g., after reconnect).
        let msgs = c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(!c.is_input_suspended(), "second SC_READY must reset suspend flag");
    }

    // ── Trait-object dispatch (DvcProcessor) ──

    // ── Pen extension (§9.5) ──

    fn single_pen_frame(device_id: u8) -> PenFrame {
        PenFrame {
            frame_offset: 0,
            contacts: alloc::vec![PenContact {
                device_id,
                x: 100,
                y: 200,
                contact_flags: ContactFlags::DOWN
                    | ContactFlags::INRANGE
                    | ContactFlags::INCONTACT,
                pen_flags: Some(PenFlags::BARREL_PRESSED),
                pressure: Some(512),
                rotation: Some(90),
                tilt_x: Some(10),
                tilt_y: Some(-5),
            }],
        }
    }

    #[test]
    fn pen_input_allowed_gated_on_v200() {
        // V100 → pen not allowed.
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(crate::pdu::RDPINPUT_PROTOCOL_V100, None))
            .unwrap();
        assert!(!c.pen_input_allowed());
        assert!(c.send_pen_event(0, alloc::vec![single_pen_frame(0)]).is_err());

        // V101 → still touch-only (< V200).
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V101, None)).unwrap();
        assert!(!c.pen_input_allowed());

        // V200 → allowed.
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        assert!(c.pen_input_allowed());
        assert!(!c.multipen_active());
    }

    #[test]
    fn multipen_requires_all_three_conditions() {
        // 1. V300 + server advertises + client requests → active.
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            client_max_version: RDPINPUT_PROTOCOL_V300,
            cs_ready_flags: CsReadyFlags::ENABLE_MULTIPEN_INJECTION,
            ..Default::default()
        });
        c.process(
            1,
            &sc_ready(
                RDPINPUT_PROTOCOL_V300,
                Some(ScReadyFlags::MULTIPEN_INJECTION_SUPPORTED),
            ),
        )
        .unwrap();
        assert!(c.multipen_active());
        c.take_pending_messages();

        // 2. Server didn't advertise → inactive; flag stripped from CS_READY.
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            client_max_version: RDPINPUT_PROTOCOL_V300,
            cs_ready_flags: CsReadyFlags::ENABLE_MULTIPEN_INJECTION,
            ..Default::default()
        });
        let msgs = c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V300, None)).unwrap();
        assert!(!c.multipen_active());
        let cs = CsReadyPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(cs.flags & CsReadyFlags::ENABLE_MULTIPEN_INJECTION, 0);

        // 3. Client didn't request → inactive.
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            client_max_version: RDPINPUT_PROTOCOL_V300,
            cs_ready_flags: 0,
            ..Default::default()
        });
        c.process(
            1,
            &sc_ready(
                RDPINPUT_PROTOCOL_V300,
                Some(ScReadyFlags::MULTIPEN_INJECTION_SUPPORTED),
            ),
        )
        .unwrap();
        assert!(!c.multipen_active());

        // 4. Negotiated < V300 (server V200) → inactive even with client request.
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            client_max_version: RDPINPUT_PROTOCOL_V300,
            cs_ready_flags: CsReadyFlags::ENABLE_MULTIPEN_INJECTION,
            ..Default::default()
        });
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        assert!(!c.multipen_active());
    }

    #[test]
    fn send_pen_event_requires_ready() {
        let mut c = RdpeiDvcClient::new();
        assert!(c.send_pen_event(0, alloc::vec![single_pen_frame(0)]).is_err());
    }

    #[test]
    fn send_pen_event_blocked_while_suspended() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.process(1, &suspend()).unwrap();
        assert!(c.send_pen_event(0, alloc::vec![single_pen_frame(0)]).is_err());
    }

    #[test]
    fn send_pen_event_single_pen_rejects_nonzero_device_id() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        // device_id = 1 invalid in single-pen mode.
        assert!(c.send_pen_event(0, alloc::vec![single_pen_frame(1)]).is_err());
    }

    #[test]
    fn send_pen_event_single_pen_rejects_multi_contact() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        let frame = PenFrame {
            frame_offset: 0,
            contacts: alloc::vec![single_pen_frame(0).contacts[0].clone(); 2],
        };
        assert!(c.send_pen_event(0, alloc::vec![frame]).is_err());
    }

    #[test]
    fn send_pen_event_multipen_accepts_device_ids_0_to_3() {
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            client_max_version: RDPINPUT_PROTOCOL_V300,
            cs_ready_flags: CsReadyFlags::ENABLE_MULTIPEN_INJECTION,
            ..Default::default()
        });
        c.process(
            1,
            &sc_ready(
                RDPINPUT_PROTOCOL_V300,
                Some(ScReadyFlags::MULTIPEN_INJECTION_SUPPORTED),
            ),
        )
        .unwrap();
        assert!(c.multipen_active());
        let frame = PenFrame {
            frame_offset: 0,
            contacts: (0..4).map(|i| single_pen_frame(i).contacts[0].clone()).collect(),
        };
        assert!(c.send_pen_event(0, alloc::vec![frame]).is_ok());
    }

    #[test]
    fn send_pen_event_multipen_rejects_device_id_gt_3() {
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            client_max_version: RDPINPUT_PROTOCOL_V300,
            cs_ready_flags: CsReadyFlags::ENABLE_MULTIPEN_INJECTION,
            ..Default::default()
        });
        c.process(
            1,
            &sc_ready(
                RDPINPUT_PROTOCOL_V300,
                Some(ScReadyFlags::MULTIPEN_INJECTION_SUPPORTED),
            ),
        )
        .unwrap();
        assert!(c.send_pen_event(0, alloc::vec![single_pen_frame(4)]).is_err());
    }

    #[test]
    fn send_pen_event_queues_encoded_pdu() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.send_pen_event(999, alloc::vec![single_pen_frame(0)])
            .unwrap();
        let msgs = c.take_pending_messages();
        assert_eq!(msgs.len(), 1);
        let decoded = crate::pdu::PenEventPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(decoded.encode_time, 999);
        assert_eq!(decoded.frames.len(), 1);
        assert_eq!(decoded.frames[0].contacts.len(), 1);
    }

    #[test]
    fn second_sc_ready_updates_pen_state() {
        // First handshake V200 → pen allowed.
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        assert!(c.pen_input_allowed());
        // Second SC_READY claims V100 → pen must be disallowed after re-negotiation.
        c.process(1, &sc_ready(crate::pdu::RDPINPUT_PROTOCOL_V100, None))
            .unwrap();
        assert!(!c.pen_input_allowed());
        assert!(!c.multipen_active());
    }

    #[test]
    fn send_pen_event_rejects_empty_frames() {
        // Prevents callers from burning the outbound cap on no-op PDUs.
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        assert!(c.send_pen_event(0, alloc::vec![]).is_err());
    }

    #[test]
    fn malformed_second_sc_ready_resets_pen_state() {
        // After a valid V200 handshake, a malformed SC_READY body (valid
        // header but unrecognized pdu_length) must not leave the client
        // in pen_input_allowed=true with stale negotiation. The
        // preemptive reset in handle_sc_ready guarantees this.
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        assert!(c.pen_input_allowed());
        // 11-byte SC_READY: valid header with pdu_length=11 (neither 10
        // nor 14), so ScReadyPdu::decode_from rejects after reading
        // protocolVersion. By then, preemptive reset has fired.
        let bad_body = [
            0x01, 0x00, // eventId = SC_READY
            0x0B, 0x00, 0x00, 0x00, // pduLength = 11 (invalid)
            0x00, 0x00, 0x02, 0x00, // protocolVersion = V200
            0x00, // bogus trailing byte
        ];
        assert!(c.process(1, &bad_body).is_err());
        assert!(
            !c.pen_input_allowed(),
            "pen_input_allowed must reset when SC_READY decode fails"
        );
        assert!(!c.multipen_active());
    }

    #[test]
    fn send_pen_event_queue_cap_enforced() {
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            max_pending_messages: 1,
            ..Default::default()
        });
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.send_pen_event(0, alloc::vec![single_pen_frame(0)]).unwrap();
        // Second push exceeds cap (queue holds 1).
        assert!(c.send_pen_event(0, alloc::vec![single_pen_frame(0)]).is_err());
        // Drain and retry.
        assert_eq!(c.take_pending_messages().len(), 1);
        assert!(c.send_pen_event(0, alloc::vec![single_pen_frame(0)]).is_ok());
    }

    #[test]
    fn inbound_pen_event_ignored() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        // Hand-craft a minimal PEN_EVENT_PDU as if the server sent it.
        let inbound_pen = encode(&crate::pdu::PenEventPdu {
            encode_time: 0,
            frames: alloc::vec![],
        });
        assert!(c.process(1, &inbound_pen).unwrap().is_empty());
    }

    #[test]
    fn dvc_processor_trait_object_full_flow() {
        // Drive the full handshake through `&mut dyn DvcProcessor` to verify
        // vtable dispatch (channel_name / start / process / close).
        let mut owner = RdpeiDvcClient::new();
        let dyn_proc: &mut dyn DvcProcessor = &mut owner;

        assert_eq!(dyn_proc.channel_name(), "Microsoft::Windows::RDS::Input");
        assert!(dyn_proc.start(1).unwrap().is_empty());

        let sc_bytes = sc_ready(RDPINPUT_PROTOCOL_V200, None);
        let msgs = dyn_proc.process(1, &sc_bytes).unwrap();
        assert_eq!(msgs.len(), 1);
        // Decoded CS_READY negotiated to V200.
        let cs = CsReadyPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(cs.protocol_version, RDPINPUT_PROTOCOL_V200);

        // SUSPEND via trait object.
        let suspended = dyn_proc.process(1, &suspend()).unwrap();
        assert!(suspended.is_empty());

        dyn_proc.close(1);
        // Post-close: not ready.
        assert!(!owner.is_ready());
    }

    #[test]
    fn outbound_queue_cap_enforced() {
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            max_pending_messages: 2,
            ..Default::default()
        });
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.dismiss_hovering_contact(1).unwrap();
        c.dismiss_hovering_contact(2).unwrap();
        // Third push exceeds the cap.
        assert!(c.dismiss_hovering_contact(3).is_err());
        // Drain and retry — should succeed again.
        let drained = c.take_pending_messages();
        assert_eq!(drained.len(), 2);
        assert!(c.dismiss_hovering_contact(3).is_ok());
    }

    #[test]
    fn take_pending_messages_idempotent() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.dismiss_hovering_contact(1).unwrap();
        assert_eq!(c.take_pending_messages().len(), 1);
        // Second call after drain returns empty.
        assert!(c.take_pending_messages().is_empty());
    }

    #[test]
    fn custom_max_touch_contacts_reflected_in_cs_ready() {
        let mut c = RdpeiDvcClient::with_config(RdpeiClientConfig {
            max_touch_contacts: 256,
            ..Default::default()
        });
        let msgs = c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        let cs = CsReadyPdu::decode_from(&msgs[0].data).unwrap();
        assert_eq!(cs.max_touch_contacts, 256);
    }

    #[test]
    fn close_resets_state() {
        let mut c = RdpeiDvcClient::new();
        c.process(1, &sc_ready(RDPINPUT_PROTOCOL_V200, None)).unwrap();
        c.dismiss_hovering_contact(1).unwrap();
        assert!(c.is_ready());

        c.close(1);
        assert!(!c.is_ready());
        assert!(
            c.take_pending_messages().is_empty(),
            "close() must clear outbound queue"
        );
        assert_eq!(c.negotiated_version(), None);
        assert_eq!(c.server_features(), None);
        assert!(!c.is_input_suspended());
        assert!(!c.pen_input_allowed(), "close() must reset pen_input_allowed");
        assert!(!c.multipen_active(), "close() must reset multipen_active");
        assert_eq!(c.negotiated_version(), None);
        assert_eq!(c.server_features(), None);
        assert!(!c.is_input_suspended());
    }
}
