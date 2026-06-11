//! The drdynvc manager (MS-RDPEDYC 3.2) — the sans-IO state for the dynamic-virtual-channel
//! transport riding the `drdynvc` static channel. The manager owns the **transport**: it
//! answers the server's Capabilities Request (version 1), matches Create Requests against the
//! registered processors (refusing unknown channel names), and reassembles fragmented channel
//! data (DataFirst + Data). Each channel is a [`DvcProcessor`] — the
//! `channel_name`/`start`/`process`/`close` model (issue #8, conceptually after `ironrdp-dvc`,
//! implemented here per ADR-0002) — which only ever sees complete messages. The session
//! machine feeds the manager SVC payloads and wraps whatever it wants sent; this module never
//! sees MCS framing.

use crate::egfx::GraphicsProcessor;
use crate::framebuffer::FrameUpdate;
use justrdp_pdu::DecodeError;
use justrdp_pdu::displaycontrol::{self, DisplayControlPdu};
use justrdp_pdu::dvc::{self, DvcMessage};
use justrdp_pdu::svc;

/// Refuse a Create Request with this `CreationStatus` (`E_FAIL` — any negative HRESULT
/// refuses, MS-RDPEDYC 2.2.2.2).
const CREATION_STATUS_REFUSED: u32 = 0x8000_4005;

/// Accept a Create Request.
const CREATION_STATUS_OK: u32 = 0x0000_0000;

/// One SVC message (a drdynvc PDU) may span several 1600-byte chunks but is itself small;
/// anything beyond this declared length is treated as malformed (allocation-bound, the
/// fast-path reassembly-cap precedent).
const SVC_MESSAGE_CAP: usize = 64 << 10;

/// Reassembled dynamic-channel messages are capped too. Display Control messages are tens of
/// bytes; the cap leaves room for future channels without allowing unbounded allocation.
const DVC_MESSAGE_CAP: usize = 4 << 20;

/// A dynamic-channel endpoint: one implementation per channel the client supports
/// (Display Control today; EGFX and friends in their slices). The manager handles transport —
/// processors receive only complete, reassembled messages.
pub(crate) trait DvcProcessor {
    /// The channel name the server's Create Request must match.
    fn channel_name(&self) -> &'static str;
    /// Called when the server created the channel (after the accepting Create Response is
    /// queued). Returned outputs are processed like [`Self::process`]'s.
    fn start(&mut self, channel_id: u32) -> Vec<ProcessorOutput>;
    /// One complete (reassembled) channel message.
    fn process(&mut self, message: &[u8]) -> Result<Vec<ProcessorOutput>, DecodeError>;
    /// The channel closed (server Close PDU); drop per-channel state.
    fn close(&mut self);
}

/// What a [`DvcProcessor`] wants done, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessorOutput {
    /// A complete channel message to send (the manager fragments it into DVC data PDUs).
    Send(Vec<u8>),
    /// Display Control: the server's caps arrived — resize requests are valid now.
    DisplayControlCaps(displaycontrol::Caps),
    /// EGFX: fresh pixels in output coordinates for the session framebuffer.
    Frame(FrameUpdate),
    /// EGFX: the server reset the output size (ResetGraphics).
    OutputResized {
        /// New output width in pixels.
        width: u16,
        /// New output height in pixels.
        height: u16,
    },
}

/// What the manager wants done after consuming one SVC payload, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DvcEvent {
    /// A drdynvc PDU to send (the session machine adds SVC chunking + MCS framing).
    Send(Vec<u8>),
    /// The Display Control channel is open and the server's caps arrived: resize requests
    /// are valid from now on.
    DisplayControlReady,
    /// EGFX pixels in output coordinates (the session machine blits its framebuffer).
    Frame(FrameUpdate),
    /// EGFX output resize (the session machine rebuilds its framebuffer).
    OutputResized {
        /// New output width in pixels.
        width: u16,
        /// New output height in pixels.
        height: u16,
    },
}

/// The Display Control channel processor (MS-RDPEDISP): consumes the server's Caps PDU —
/// the channel's only server→client message — and surfaces it; everything else on the
/// channel is skipped as well-formed-but-unknown.
#[derive(Debug, Default)]
struct DisplayControlProcessor {
    caps_seen: bool,
}

impl DvcProcessor for DisplayControlProcessor {
    fn channel_name(&self) -> &'static str {
        displaycontrol::CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> Vec<ProcessorOutput> {
        Vec::new() // the server speaks first (its Caps PDU)
    }

    fn process(&mut self, message: &[u8]) -> Result<Vec<ProcessorOutput>, DecodeError> {
        match DisplayControlPdu::decode(message)? {
            DisplayControlPdu::Caps(caps) => {
                tracing::debug!(
                    target: "rdp_displaycontrol_caps",
                    max_monitors = caps.max_num_monitors,
                    area_a = caps.max_monitor_area_factor_a,
                    area_b = caps.max_monitor_area_factor_b,
                    "DISPLAYCONTROL_CAPS received"
                );
                let first = !self.caps_seen;
                self.caps_seen = true;
                Ok(if first {
                    vec![ProcessorOutput::DisplayControlCaps(caps)]
                } else {
                    Vec::new()
                })
            }
            DisplayControlPdu::Unknown { pdu_type } => {
                tracing::debug!(
                    target: "rdp_displaycontrol_caps",
                    pdu_type,
                    "unknown Display Control PDU skipped"
                );
                Ok(Vec::new())
            }
        }
    }

    fn close(&mut self) {
        self.caps_seen = false;
    }
}

/// One open dynamic channel: its server-assigned ID, the owning processor, and any
/// fragmented message in flight (DataFirst total + accumulated bytes).
#[derive(Debug)]
struct OpenChannel {
    channel_id: u32,
    processor: usize,
    reassembly: Option<(usize, Vec<u8>)>,
}

/// The drdynvc transport state plus the registered channel processors.
pub(crate) struct Drdynvc {
    processors: Vec<Box<dyn DvcProcessor + Send>>,
    open: Vec<OpenChannel>,
    /// SVC chunk reassembly for the drdynvc channel itself.
    svc_buffer: Vec<u8>,
    svc_in_flight: bool,
    /// The Display Control channel ID + server caps, recorded off the processor's output.
    display_control: Option<(u32, displaycontrol::Caps)>,
}

impl core::fmt::Debug for Drdynvc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Drdynvc")
            .field("open", &self.open)
            .field("display_control", &self.display_control)
            .finish_non_exhaustive()
    }
}

impl Default for Drdynvc {
    fn default() -> Self {
        Self {
            processors: vec![
                Box::new(DisplayControlProcessor::default()),
                Box::new(GraphicsProcessor::default()),
            ],
            open: Vec::new(),
            svc_buffer: Vec::new(),
            svc_in_flight: false,
            display_control: None,
        }
    }
}

impl Drdynvc {
    /// The Display Control channel ID and server caps, once both are known — the
    /// preconditions for a resize request (MS-RDPEDISP 1.3: the client must consume the Caps
    /// PDU before sending a Monitor Layout).
    pub(crate) fn display_control(&self) -> Option<(u32, displaycontrol::Caps)> {
        self.display_control
    }

    /// Consume one MCS-delivered SVC payload on the drdynvc channel.
    pub(crate) fn on_svc_payload(&mut self, payload: &[u8]) -> Result<Vec<DvcEvent>, DecodeError> {
        let chunk = svc::ChannelChunk::decode(payload)?;
        if chunk.flags & svc::CHANNEL_FLAG_PACKET_COMPRESSED != 0 {
            // justrdp advertises VCCAPS_NO_COMPR; compressed chunks are a violation.
            return Err(DecodeError::InvalidField {
                field: "CHANNEL_PDU_HEADER.flags",
                reason: "compressed SVC chunk but compression was never advertised",
            });
        }
        if chunk.total_length as usize > SVC_MESSAGE_CAP {
            return Err(DecodeError::InvalidField {
                field: "CHANNEL_PDU_HEADER.length",
                reason: "drdynvc SVC message exceeds the reassembly cap",
            });
        }
        if chunk.flags & svc::CHANNEL_FLAG_FIRST != 0 {
            self.svc_buffer.clear();
            self.svc_in_flight = true;
        } else if !self.svc_in_flight {
            return Err(DecodeError::InvalidField {
                field: "CHANNEL_PDU_HEADER.flags",
                reason: "SVC continuation chunk without a first chunk",
            });
        }
        if self.svc_buffer.len() + chunk.data.len() > SVC_MESSAGE_CAP {
            return Err(DecodeError::InvalidField {
                field: "CHANNEL_PDU_HEADER.length",
                reason: "drdynvc SVC message grew past its declared length cap",
            });
        }
        self.svc_buffer.extend_from_slice(chunk.data);
        if chunk.flags & svc::CHANNEL_FLAG_LAST == 0 {
            return Ok(Vec::new());
        }
        self.svc_in_flight = false;
        let message = core::mem::take(&mut self.svc_buffer);
        self.on_dvc_pdu(&message)
    }

    /// Handle one complete drdynvc PDU.
    fn on_dvc_pdu(&mut self, pdu: &[u8]) -> Result<Vec<DvcEvent>, DecodeError> {
        match DvcMessage::decode(pdu)? {
            DvcMessage::CapabilitiesRequest { version } => {
                let answered = version.min(dvc::CAPS_VERSION);
                tracing::debug!(
                    target: "rdp_drdynvc",
                    server_version = version,
                    answered,
                    "DYNVC capabilities request"
                );
                Ok(vec![DvcEvent::Send(dvc::encode_capabilities_response(
                    answered,
                ))])
            }
            DvcMessage::CreateRequest { channel_id, name } => {
                let Some(processor) = self
                    .processors
                    .iter()
                    .position(|p| p.channel_name() == name)
                else {
                    tracing::debug!(target: "rdp_drdynvc", channel_id, name, "DYNVC create refused");
                    // Channels with no registered processor are refused, which tells the
                    // server not to send data on them (EGFX and friends arrive as their own
                    // slices, each registering a processor).
                    return Ok(vec![DvcEvent::Send(dvc::encode_create_response(
                        channel_id,
                        CREATION_STATUS_REFUSED,
                    ))]);
                };
                tracing::debug!(target: "rdp_drdynvc", channel_id, name, "DYNVC create accepted");
                self.open.retain(|c| c.channel_id != channel_id);
                self.open.push(OpenChannel {
                    channel_id,
                    processor,
                    reassembly: None,
                });
                let mut events = vec![DvcEvent::Send(dvc::encode_create_response(
                    channel_id,
                    CREATION_STATUS_OK,
                ))];
                let outputs = self.processors[processor].start(channel_id);
                events.extend(self.apply_outputs(channel_id, outputs));
                Ok(events)
            }
            DvcMessage::DataFirst {
                channel_id,
                total_length,
                data,
            } => {
                let Some(open) = self.open.iter_mut().find(|c| c.channel_id == channel_id) else {
                    return Ok(Vec::new()); // data on a refused channel: skipped
                };
                if total_length as usize > DVC_MESSAGE_CAP {
                    return Err(DecodeError::InvalidField {
                        field: "DYNVC_DATA_FIRST.Length",
                        reason: "dynamic channel message exceeds the reassembly cap",
                    });
                }
                if data.len() >= total_length as usize {
                    // Degenerate single-fragment DataFirst: complete immediately.
                    open.reassembly = None;
                    let message = data[..total_length as usize].to_vec();
                    return self.dispatch(channel_id, &message);
                }
                open.reassembly = Some((total_length as usize, data.to_vec()));
                Ok(Vec::new())
            }
            DvcMessage::Data { channel_id, data } => {
                let Some(open) = self.open.iter_mut().find(|c| c.channel_id == channel_id) else {
                    return Ok(Vec::new());
                };
                match open.reassembly.as_mut() {
                    Some((total, buffer)) => {
                        buffer.extend_from_slice(data);
                        if buffer.len() >= *total {
                            let total = *total;
                            let buffer = open.reassembly.take().map(|(_, b)| b).unwrap_or_default();
                            return self.dispatch(channel_id, &buffer[..total]);
                        }
                        Ok(Vec::new())
                    }
                    // No DataFirst in flight: the message fits one PDU.
                    None => {
                        let message = data.to_vec();
                        self.dispatch(channel_id, &message)
                    }
                }
            }
            DvcMessage::Close { channel_id } => {
                tracing::debug!(target: "rdp_drdynvc", channel_id, "DYNVC close");
                if let Some(at) = self.open.iter().position(|c| c.channel_id == channel_id) {
                    let open = self.open.remove(at);
                    self.processors[open.processor].close();
                }
                if self.display_control.map(|(id, _)| id) == Some(channel_id) {
                    self.display_control = None;
                }
                Ok(Vec::new())
            }
            // Compressed / soft-sync / unknown commands: never negotiated, skipped
            // (well-formed-but-unknown never kills the session, plan.md §11c).
            DvcMessage::Unsupported { cmd } => {
                tracing::debug!(target: "rdp_drdynvc", cmd, "unsupported DYNVC command skipped");
                Ok(Vec::new())
            }
        }
    }

    /// Route one complete message to its channel's processor and apply the outputs.
    fn dispatch(&mut self, channel_id: u32, message: &[u8]) -> Result<Vec<DvcEvent>, DecodeError> {
        let Some(open) = self.open.iter().find(|c| c.channel_id == channel_id) else {
            return Ok(Vec::new());
        };
        let outputs = self.processors[open.processor].process(message)?;
        Ok(self.apply_outputs(channel_id, outputs))
    }

    /// Turn processor outputs into manager events (fragmenting sends, recording the
    /// Display Control milestone).
    fn apply_outputs(&mut self, channel_id: u32, outputs: Vec<ProcessorOutput>) -> Vec<DvcEvent> {
        let mut events = Vec::new();
        for output in outputs {
            match output {
                ProcessorOutput::Send(message) => {
                    for pdu in dvc::encode_data(channel_id, &message) {
                        events.push(DvcEvent::Send(pdu));
                    }
                }
                ProcessorOutput::DisplayControlCaps(caps) => {
                    self.display_control = Some((channel_id, caps));
                    events.push(DvcEvent::DisplayControlReady);
                }
                ProcessorOutput::Frame(frame) => events.push(DvcEvent::Frame(frame)),
                ProcessorOutput::OutputResized { width, height } => {
                    events.push(DvcEvent::OutputResized { width, height });
                }
            }
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc_payloads(message: &[u8]) -> Vec<Vec<u8>> {
        svc::encode_chunks(message)
    }

    fn caps_request() -> Vec<u8> {
        vec![0x50, 0x00, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0] // version 3 + priority charges
    }

    fn create_request(id: u8, name: &str) -> Vec<u8> {
        let mut pdu = vec![0x10, id];
        pdu.extend_from_slice(name.as_bytes());
        pdu.push(0);
        pdu
    }

    fn display_caps_pdu(monitors: u32, a: u32, b: u32) -> Vec<u8> {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&displaycontrol::TYPE_CAPS.to_le_bytes());
        pdu.extend_from_slice(&20u32.to_le_bytes());
        for v in [monitors, a, b] {
            pdu.extend_from_slice(&v.to_le_bytes());
        }
        pdu
    }

    fn feed(manager: &mut Drdynvc, dvc_pdu: &[u8]) -> Vec<DvcEvent> {
        let mut events = Vec::new();
        for payload in svc_payloads(dvc_pdu) {
            events.extend(manager.on_svc_payload(&payload).unwrap());
        }
        events
    }

    #[test]
    fn capabilities_request_is_answered_with_min_of_server_and_ours() {
        let mut manager = Drdynvc::default();
        // Server offers 3, we support 3 → answer 3.
        let events = feed(&mut manager, &caps_request());
        assert_eq!(
            events,
            vec![DvcEvent::Send(dvc::encode_capabilities_response(3))]
        );
        // Server offers 2 → answer is capped at the server's offer.
        let mut manager = Drdynvc::default();
        let events = feed(
            &mut manager,
            &[0x50, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            events,
            vec![DvcEvent::Send(dvc::encode_capabilities_response(2))]
        );
    }

    #[test]
    fn display_control_create_is_accepted_and_caps_make_it_ready() {
        let mut manager = Drdynvc::default();
        let events = feed(
            &mut manager,
            &create_request(7, displaycontrol::CHANNEL_NAME),
        );
        assert_eq!(
            events,
            vec![DvcEvent::Send(dvc::encode_create_response(7, 0))]
        );
        assert!(manager.display_control().is_none(), "caps not yet received");

        let layout = display_caps_pdu(1, 3840, 2160);
        let mut events = Vec::new();
        for pdu in dvc::encode_data(7, &layout) {
            events.extend(feed(&mut manager, &pdu));
        }
        assert_eq!(events, vec![DvcEvent::DisplayControlReady]);
        let (id, caps) = manager.display_control().unwrap();
        assert_eq!(id, 7);
        assert_eq!(caps.max_area(), 3840 * 2160);
    }

    #[test]
    fn unknown_channels_are_refused() {
        let mut manager = Drdynvc::default();
        let events = feed(
            &mut manager,
            &create_request(9, "Microsoft::Windows::RDS::Geometry"),
        );
        let [DvcEvent::Send(response)] = events.as_slice() else {
            panic!("expected one response, got {events:?}");
        };
        assert_eq!(
            response,
            &dvc::encode_create_response(9, CREATION_STATUS_REFUSED)
        );
        // Data on the refused channel is skipped without error.
        assert!(feed(&mut manager, &dvc::encode_data(9, &[1, 2, 3])[0]).is_empty());
    }

    #[test]
    fn fragmented_display_caps_reassemble_across_data_first_and_data() {
        let mut manager = Drdynvc::default();
        feed(
            &mut manager,
            &create_request(7, displaycontrol::CHANNEL_NAME),
        );
        let caps = display_caps_pdu(2, 1920, 1080);
        // Hand-fragment into DataFirst(8 bytes) + Data(rest) to exercise reassembly even
        // though a real caps PDU fits one fragment.
        let mut first = Vec::new();
        first.push((dvc::CMD_DATA_FIRST << 4) | 0); // cbId=0, Sp=0 (1-byte length)
        first.push(7);
        first.push(caps.len() as u8);
        first.extend_from_slice(&caps[..8]);
        let mut rest = vec![(dvc::CMD_DATA << 4) | 0, 7];
        rest.extend_from_slice(&caps[8..]);

        assert!(feed(&mut manager, &first).is_empty());
        let events = feed(&mut manager, &rest);
        assert_eq!(events, vec![DvcEvent::DisplayControlReady]);
        assert_eq!(manager.display_control().unwrap().1.max_num_monitors, 2);
    }

    #[test]
    fn svc_chunked_dvc_pdu_reassembles() {
        // One DVC PDU split across two SVC chunks (FIRST then LAST).
        let mut manager = Drdynvc::default();
        let pdu = caps_request();
        let (a, b) = pdu.split_at(3);
        let mut chunk1 = Vec::new();
        chunk1.extend_from_slice(&(pdu.len() as u32).to_le_bytes());
        chunk1.extend_from_slice(&svc::CHANNEL_FLAG_FIRST.to_le_bytes());
        chunk1.extend_from_slice(a);
        let mut chunk2 = Vec::new();
        chunk2.extend_from_slice(&(pdu.len() as u32).to_le_bytes());
        chunk2.extend_from_slice(&svc::CHANNEL_FLAG_LAST.to_le_bytes());
        chunk2.extend_from_slice(b);
        assert!(manager.on_svc_payload(&chunk1).unwrap().is_empty());
        let events = manager.on_svc_payload(&chunk2).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn close_tears_down_display_control() {
        let mut manager = Drdynvc::default();
        feed(
            &mut manager,
            &create_request(7, displaycontrol::CHANNEL_NAME),
        );
        for pdu in dvc::encode_data(7, &display_caps_pdu(1, 1024, 768)) {
            feed(&mut manager, &pdu);
        }
        assert!(manager.display_control().is_some());
        feed(&mut manager, &dvc::encode_close(7));
        assert!(manager.display_control().is_none());

        // A re-created channel starts fresh: caps must arrive again before ready.
        let events = feed(
            &mut manager,
            &create_request(8, displaycontrol::CHANNEL_NAME),
        );
        assert_eq!(
            events,
            vec![DvcEvent::Send(dvc::encode_create_response(8, 0))]
        );
        assert!(manager.display_control().is_none());
        for pdu in dvc::encode_data(8, &display_caps_pdu(1, 800, 600)) {
            feed(&mut manager, &pdu);
        }
        assert_eq!(manager.display_control().unwrap().0, 8);
    }

    /// A stub processor that speaks first: `start` returns a message larger than one DVC
    /// data PDU, exercising the manager's Send path (fragmentation included).
    struct ChattyProcessor;

    impl DvcProcessor for ChattyProcessor {
        fn channel_name(&self) -> &'static str {
            "justrdp::test::Chatty"
        }
        fn start(&mut self, _channel_id: u32) -> Vec<ProcessorOutput> {
            vec![ProcessorOutput::Send(vec![0xAB; dvc::MAX_DATA_CHUNK + 1])]
        }
        fn process(&mut self, _message: &[u8]) -> Result<Vec<ProcessorOutput>, DecodeError> {
            Ok(Vec::new())
        }
        fn close(&mut self) {}
    }

    #[test]
    fn processor_start_messages_are_sent_and_fragmented() {
        let mut manager = Drdynvc {
            processors: vec![Box::new(ChattyProcessor)],
            ..Drdynvc::default()
        };
        let events = feed(&mut manager, &create_request(5, "justrdp::test::Chatty"));
        // Create Response + DataFirst + Data (the start message spans two fragments).
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], DvcEvent::Send(dvc::encode_create_response(5, 0)));
        let DvcEvent::Send(first) = &events[1] else {
            panic!("expected a DataFirst send");
        };
        assert!(matches!(
            DvcMessage::decode(first).unwrap(),
            DvcMessage::DataFirst { channel_id: 5, .. }
        ));
        let DvcEvent::Send(rest) = &events[2] else {
            panic!("expected a Data send");
        };
        assert!(matches!(
            DvcMessage::decode(rest).unwrap(),
            DvcMessage::Data { channel_id: 5, .. }
        ));
    }

    #[test]
    fn compressed_svc_chunk_is_a_typed_error() {
        let mut manager = Drdynvc::default();
        let mut payload = Vec::new();
        payload.extend_from_slice(&4u32.to_le_bytes());
        payload.extend_from_slice(
            &(svc::CHANNEL_FLAG_FIRST
                | svc::CHANNEL_FLAG_LAST
                | svc::CHANNEL_FLAG_PACKET_COMPRESSED)
                .to_le_bytes(),
        );
        payload.extend_from_slice(&[0; 4]);
        assert!(manager.on_svc_payload(&payload).is_err());
    }

    #[test]
    fn oversized_declared_lengths_are_rejected() {
        let mut manager = Drdynvc::default();
        // SVC message declaring 1 MiB.
        let mut payload = Vec::new();
        payload.extend_from_slice(&(1u32 << 20).to_le_bytes());
        payload.extend_from_slice(&svc::CHANNEL_FLAG_FIRST.to_le_bytes());
        payload.extend_from_slice(&[0; 8]);
        assert!(manager.on_svc_payload(&payload).is_err());

        // DataFirst declaring more than the DVC cap on the accepted channel.
        let mut manager = Drdynvc::default();
        feed(
            &mut manager,
            &create_request(7, displaycontrol::CHANNEL_NAME),
        );
        let mut pdu = Vec::new();
        pdu.push((dvc::CMD_DATA_FIRST << 4) | (2 << 2)); // cbId=0, Sp=2 (4-byte length)
        pdu.push(7);
        pdu.extend_from_slice(&(64u32 << 20).to_le_bytes());
        pdu.extend_from_slice(&[0; 4]);
        let mut failed = false;
        for payload in svc_payloads(&pdu) {
            if manager.on_svc_payload(&payload).is_err() {
                failed = true;
            }
        }
        assert!(failed, "oversized DataFirst length was accepted");
    }
}
