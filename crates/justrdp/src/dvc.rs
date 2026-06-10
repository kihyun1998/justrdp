//! The drdynvc manager (MS-RDPEDYC 3.2) — the sans-IO state for the dynamic-virtual-channel
//! transport riding the `drdynvc` static channel. It answers the server's Capabilities
//! Request (version 1), accepts the Display Control channel ([MS-RDPEDISP]) and refuses every
//! other Create Request, and reassembles fragmented channel data (DataFirst + Data). The
//! session machine feeds it SVC payloads and wraps whatever it wants sent; this module never
//! sees MCS framing.

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

/// What the manager wants done after consuming one SVC payload, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DvcEvent {
    /// A drdynvc PDU to send (the session machine adds SVC chunking + MCS framing).
    Send(Vec<u8>),
    /// The Display Control channel is open and the server's caps arrived: resize requests
    /// are valid from now on.
    DisplayControlReady,
}

/// In-flight reassembly of one fragmented dynamic-channel message.
#[derive(Debug)]
struct Reassembly {
    channel_id: u32,
    total: usize,
    buffer: Vec<u8>,
}

/// The drdynvc transport + Display Control state.
#[derive(Debug, Default)]
pub(crate) struct Drdynvc {
    /// SVC chunk reassembly for the drdynvc channel itself.
    svc_buffer: Vec<u8>,
    svc_in_flight: bool,
    /// The Display Control dynamic channel ID, once the server created it.
    display_control: Option<u32>,
    /// The server's Display Control caps, once received.
    display_caps: Option<displaycontrol::Caps>,
    /// One fragmented message in flight (only the accepted channel ever carries data).
    reassembly: Option<Reassembly>,
}

impl Drdynvc {
    /// The Display Control channel ID and server caps, once both are known — the
    /// preconditions for a resize request (MS-RDPEDISP 1.3: the client must consume the Caps
    /// PDU before sending a Monitor Layout).
    pub(crate) fn display_control(&self) -> Option<(u32, displaycontrol::Caps)> {
        Some((self.display_control?, self.display_caps?))
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
            DvcMessage::CapabilitiesRequest { .. } => {
                // The server's version is always ≥ ours; answer with what we implement.
                Ok(vec![DvcEvent::Send(dvc::encode_capabilities_response(
                    dvc::CAPS_VERSION,
                ))])
            }
            DvcMessage::CreateRequest { channel_id, name } => {
                if name == displaycontrol::CHANNEL_NAME {
                    self.display_control = Some(channel_id);
                    self.display_caps = None; // fresh channel, fresh caps
                    Ok(vec![DvcEvent::Send(dvc::encode_create_response(
                        channel_id,
                        CREATION_STATUS_OK,
                    ))])
                } else {
                    // Channels justrdp does not implement yet are refused, which tells the
                    // server not to send data on them (EGFX and friends arrive as their own
                    // slices and extend this dispatch).
                    Ok(vec![DvcEvent::Send(dvc::encode_create_response(
                        channel_id,
                        CREATION_STATUS_REFUSED,
                    ))])
                }
            }
            DvcMessage::DataFirst {
                channel_id,
                total_length,
                data,
            } => {
                if Some(channel_id) != self.display_control {
                    return Ok(Vec::new()); // data on a refused channel: skipped
                }
                if total_length as usize > DVC_MESSAGE_CAP {
                    return Err(DecodeError::InvalidField {
                        field: "DYNVC_DATA_FIRST.Length",
                        reason: "dynamic channel message exceeds the reassembly cap",
                    });
                }
                if data.len() >= total_length as usize {
                    // Degenerate single-fragment DataFirst: complete immediately.
                    self.reassembly = None;
                    return self.on_channel_message(channel_id, &data[..total_length as usize]);
                }
                self.reassembly = Some(Reassembly {
                    channel_id,
                    total: total_length as usize,
                    buffer: data.to_vec(),
                });
                Ok(Vec::new())
            }
            DvcMessage::Data { channel_id, data } => {
                if Some(channel_id) != self.display_control {
                    return Ok(Vec::new());
                }
                match self.reassembly.as_mut() {
                    Some(r) if r.channel_id == channel_id => {
                        r.buffer.extend_from_slice(data);
                        if r.buffer.len() >= r.total {
                            let r = self.reassembly.take().expect("checked above");
                            return self.on_channel_message(channel_id, &r.buffer[..r.total]);
                        }
                        Ok(Vec::new())
                    }
                    // No DataFirst in flight: the message fits one PDU.
                    _ => self.on_channel_message(channel_id, data),
                }
            }
            DvcMessage::Close { channel_id } => {
                if Some(channel_id) == self.display_control {
                    self.display_control = None;
                    self.display_caps = None;
                    self.reassembly = None;
                }
                Ok(Vec::new())
            }
            // Compressed / soft-sync / unknown commands: never negotiated, skipped
            // (well-formed-but-unknown never kills the session, plan.md §11c).
            DvcMessage::Unsupported { .. } => Ok(Vec::new()),
        }
    }

    /// Handle one complete message on an accepted dynamic channel (Display Control only).
    fn on_channel_message(
        &mut self,
        _channel_id: u32,
        message: &[u8],
    ) -> Result<Vec<DvcEvent>, DecodeError> {
        match DisplayControlPdu::decode(message)? {
            DisplayControlPdu::Caps(caps) => {
                let first = self.display_caps.is_none();
                self.display_caps = Some(caps);
                Ok(if first {
                    vec![DvcEvent::DisplayControlReady]
                } else {
                    Vec::new()
                })
            }
            // The server never legitimately sends anything else on this channel
            // (MS-RDPEDISP has no other server→client message); skip unknowns.
            DisplayControlPdu::Unknown { .. } => Ok(Vec::new()),
        }
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
    fn capabilities_request_is_answered_with_version_1() {
        let mut manager = Drdynvc::default();
        let events = feed(&mut manager, &caps_request());
        assert_eq!(
            events,
            vec![DvcEvent::Send(dvc::encode_capabilities_response(1))]
        );
    }

    #[test]
    fn display_control_create_is_accepted_and_caps_make_it_ready() {
        let mut manager = Drdynvc::default();
        let events = feed(&mut manager, &create_request(7, displaycontrol::CHANNEL_NAME));
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
        let events = feed(&mut manager, &create_request(9, "Microsoft::Windows::RDS::Graphics"));
        let [DvcEvent::Send(response)] = events.as_slice() else {
            panic!("expected one response, got {events:?}");
        };
        assert_eq!(response, &dvc::encode_create_response(9, CREATION_STATUS_REFUSED));
        // Data on the refused channel is skipped without error.
        assert!(feed(&mut manager, &dvc::encode_data(9, &[1, 2, 3])[0]).is_empty());
    }

    #[test]
    fn fragmented_display_caps_reassemble_across_data_first_and_data() {
        let mut manager = Drdynvc::default();
        feed(&mut manager, &create_request(7, displaycontrol::CHANNEL_NAME));
        let caps = display_caps_pdu(2, 1920, 1080);
        // Hand-fragment into DataFirst(8 bytes) + Data(rest) to exercise reassembly even
        // though a real caps PDU fits one fragment.
        let mut first = vec![0x24, 7, caps.len() as u8]; // Cmd=2, Sp=1? — build manually:
        first.clear();
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
        feed(&mut manager, &create_request(7, displaycontrol::CHANNEL_NAME));
        for pdu in dvc::encode_data(7, &display_caps_pdu(1, 1024, 768)) {
            feed(&mut manager, &pdu);
        }
        assert!(manager.display_control().is_some());
        feed(&mut manager, &dvc::encode_close(7));
        assert!(manager.display_control().is_none());
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
        feed(&mut manager, &create_request(7, displaycontrol::CHANNEL_NAME));
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
