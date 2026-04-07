#![forbid(unsafe_code)]

//! Audio Input DVC client -- MS-RDPEAI 3.2

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};
use justrdp_rdpsnd::pdu::{AudioFormat, WaveFormatTag};

use crate::pdu::{
    DataPdu, FormatChangePdu, IncomingDataPdu, OpenPdu, OpenReplyPdu, SoundFormatsPdu, VersionPdu,
    MSG_SNDIN_FORMATCHANGE, MSG_SNDIN_FORMATS, MSG_SNDIN_OPEN, MSG_SNDIN_VERSION,
    MAX_NUM_FORMATS, SNDIN_VERSION_2,
};

/// DVC channel name for Audio Input.
/// MS-RDPEAI 1.0
const CHANNEL_NAME: &str = "AUDIO_INPUT";

/// Client state machine states.
/// MS-RDPEAI 3.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    /// Waiting for server's Version PDU.
    WaitingForVersion,
    /// Waiting for server's Sound Formats PDU.
    WaitingForFormats,
    /// Waiting for server's Open PDU.
    WaitingForOpen,
    /// Recording: audio capture is active.
    Recording,
    /// Terminal state (negotiation failed or device open failed).
    Closed,
}

/// Audio Input DVC client.
///
/// Implements `DvcProcessor` for the `AUDIO_INPUT` dynamic virtual channel.
/// Handles version/format negotiation and provides an API for sending
/// captured audio data.
pub struct AudioInputClient {
    state: ClientState,
    /// Client-supported version. Defaults to version 2.
    client_version: u32,
    /// Negotiated version = min(server, client).
    negotiated_version: u32,
    /// Negotiated audio format list (intersection of server and client formats).
    negotiated_formats: Vec<AudioFormat>,
    /// Current active format index (into negotiated_formats).
    current_format_index: u32,
    /// Frames per packet (set by server's Open PDU).
    frames_per_packet: u32,
    /// Client-supported format list. Must include PCM.
    supported_formats: Vec<AudioFormat>,
}

impl AudioInputClient {
    /// Create a new Audio Input client with default PCM format support.
    pub fn new() -> Self {
        Self::init(alloc::vec![
            AudioFormat::pcm(2, 44100, 16),
            AudioFormat::pcm(1, 44100, 16),
            AudioFormat::pcm(2, 22050, 16),
            AudioFormat::pcm(1, 22050, 16),
        ])
    }

    /// Create a client with custom supported formats.
    ///
    /// The format list MUST include at least one PCM format (MS-RDPEAI requirement)
    /// and must not exceed `MAX_NUM_FORMATS` (256) entries.
    pub fn with_formats(formats: Vec<AudioFormat>) -> Result<Self, String> {
        if !formats.iter().any(|f| f.format_tag == WaveFormatTag::PCM) {
            return Err(String::from("supported formats must include at least one PCM format"));
        }
        if formats.len() > MAX_NUM_FORMATS as usize {
            return Err(String::from("supported formats exceeds maximum (256)"));
        }
        Ok(Self::init(formats))
    }

    fn init(supported_formats: Vec<AudioFormat>) -> Self {
        Self {
            state: ClientState::Closed,
            client_version: SNDIN_VERSION_2,
            negotiated_version: 0,
            negotiated_formats: Vec::new(),
            current_format_index: 0,
            frames_per_packet: 0,
            supported_formats,
        }
    }

    /// Returns `true` if the client is in the Recording state and ready to send audio data.
    pub fn is_recording(&self) -> bool {
        self.state == ClientState::Recording
    }

    /// Returns the negotiated format list.
    pub fn negotiated_formats(&self) -> &[AudioFormat] {
        &self.negotiated_formats
    }

    /// Returns the current active audio format, if recording.
    pub fn current_format(&self) -> Option<&AudioFormat> {
        if self.state == ClientState::Recording {
            self.negotiated_formats.get(self.current_format_index as usize)
        } else {
            None
        }
    }

    /// Returns the frames per packet requested by the server.
    pub fn frames_per_packet(&self) -> u32 {
        self.frames_per_packet
    }

    /// Returns the negotiated protocol version (min of server and client versions).
    pub fn negotiated_version(&self) -> u32 {
        self.negotiated_version
    }

    /// Build messages to send captured audio data.
    ///
    /// Returns (IncomingDataPdu, DataPdu) pair as DVC messages.
    /// Must only be called in the Recording state.
    pub fn build_audio_messages(&self, audio_data: Vec<u8>) -> DvcResult<Vec<DvcMessage>> {
        if self.state != ClientState::Recording {
            return Err(DvcError::Protocol(String::from("not in recording state")));
        }

        let incoming = encode_dvc_message(&IncomingDataPdu)?;
        let data = encode_dvc_message(&DataPdu { data: audio_data })?;
        Ok(alloc::vec![incoming, data])
    }

    /// Handle incoming server Version PDU.
    fn handle_version(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if self.state != ClientState::WaitingForVersion {
            return Err(DvcError::Protocol(String::from(
                "received Version PDU in unexpected state",
            )));
        }

        let mut src = ReadCursor::new(payload);
        let server_pdu = VersionPdu::decode(&mut src).map_err(DvcError::Decode)?;
        self.negotiated_version = core::cmp::min(server_pdu.version, self.client_version);

        // Reply with client version
        let reply = VersionPdu {
            version: self.client_version,
        };
        self.state = ClientState::WaitingForFormats;
        Ok(alloc::vec![encode_dvc_message(&reply)?])
    }

    /// Handle incoming server Sound Formats PDU.
    fn handle_formats(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if self.state != ClientState::WaitingForFormats {
            return Err(DvcError::Protocol(String::from(
                "received Formats PDU in unexpected state",
            )));
        }

        let server_pdu = SoundFormatsPdu::decode_from(payload).map_err(DvcError::Decode)?;

        // Compute intersection: client formats that also appear in server's list
        let mut negotiated = Vec::new();
        for client_fmt in &self.supported_formats {
            for server_fmt in &server_pdu.formats {
                if client_fmt.format_tag == server_fmt.format_tag
                    && client_fmt.n_channels == server_fmt.n_channels
                    && client_fmt.n_samples_per_sec == server_fmt.n_samples_per_sec
                    && client_fmt.bits_per_sample == server_fmt.bits_per_sample
                {
                    negotiated.push(client_fmt.clone());
                    break;
                }
            }
        }

        // Build client response
        let mut reply = SoundFormatsPdu {
            formats: negotiated.clone(),
            cb_size_formats_packet: 0,
        };
        reply.cb_size_formats_packet = reply.compute_cb_size();

        self.negotiated_formats = negotiated;

        if self.negotiated_formats.is_empty() {
            self.state = ClientState::Closed;
        } else {
            self.state = ClientState::WaitingForOpen;
        }

        Ok(alloc::vec![encode_dvc_message(&reply)?])
    }

    /// Handle incoming server Open PDU.
    fn handle_open(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if self.state != ClientState::WaitingForOpen {
            return Err(DvcError::Protocol(String::from(
                "received Open PDU in unexpected state",
            )));
        }

        let open_pdu = OpenPdu::decode_from(payload).map_err(DvcError::Decode)?;

        // Validate initialFormat index
        if open_pdu.initial_format as usize >= self.negotiated_formats.len() {
            // Protocol error — send failure reply
            let reply = OpenReplyPdu { result: OpenReplyPdu::E_FAIL };
            self.state = ClientState::Closed;
            return Ok(alloc::vec![encode_dvc_message(&reply)?]);
        }

        self.current_format_index = open_pdu.initial_format;
        self.frames_per_packet = open_pdu.frames_per_packet;

        // Send success reply
        let reply = OpenReplyPdu {
            result: OpenReplyPdu::S_OK,
        };
        self.state = ClientState::Recording;
        Ok(alloc::vec![encode_dvc_message(&reply)?])
    }

    /// Handle incoming server Format Change PDU.
    fn handle_format_change(&mut self, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if self.state != ClientState::Recording {
            return Err(DvcError::Protocol(String::from(
                "received FormatChange PDU in unexpected state",
            )));
        }

        let mut src = ReadCursor::new(payload);
        let fc_pdu = FormatChangePdu::decode(&mut src).map_err(DvcError::Decode)?;

        if fc_pdu.new_format as usize >= self.negotiated_formats.len() {
            return Err(DvcError::Protocol(String::from(
                "FormatChange index out of range",
            )));
        }

        self.current_format_index = fc_pdu.new_format;

        // Echo back confirmation
        Ok(alloc::vec![encode_dvc_message(&fc_pdu)?])
    }
}

impl Default for AudioInputClient {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for AudioInputClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AudioInputClient")
            .field("state", &self.state)
            .field("negotiated_version", &self.negotiated_version)
            .field("negotiated_formats", &self.negotiated_formats.len())
            .field("current_format_index", &self.current_format_index)
            .field("frames_per_packet", &self.frames_per_packet)
            .finish()
    }
}

impl AsAny for AudioInputClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl DvcProcessor for AudioInputClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // Transition to WaitingForVersion. Client waits for server's Version PDU.
        self.state = ClientState::WaitingForVersion;
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        if self.state == ClientState::Closed {
            return Ok(Vec::new());
        }

        if payload.is_empty() {
            return Err(DvcError::Protocol(String::from("empty payload")));
        }

        let message_id = payload[0];

        match message_id {
            MSG_SNDIN_VERSION => self.handle_version(payload),
            MSG_SNDIN_FORMATS => self.handle_formats(payload),
            MSG_SNDIN_OPEN => self.handle_open(payload),
            MSG_SNDIN_FORMATCHANGE => self.handle_format_change(payload),
            _ => Err(DvcError::Protocol(String::from("unknown MessageId"))),
        }
    }

    fn close(&mut self, _channel_id: u32) {
        self.state = ClientState::Closed;
        self.negotiated_version = 0;
        self.negotiated_formats.clear();
        self.current_format_index = 0;
        self.frames_per_packet = 0;
    }
}

/// Encode an Encode-able PDU into a DvcMessage.
fn encode_dvc_message(pdu: &dyn Encode) -> DvcResult<DvcMessage> {
    let size = pdu.size();
    let mut buf = alloc::vec![0u8; size];
    let mut dst = WriteCursor::new(&mut buf);
    pdu.encode(&mut dst).map_err(DvcError::Encode)?;
    Ok(DvcMessage::new(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{MSG_SNDIN_OPEN_REPLY, SNDIN_VERSION_1};

    fn make_version_payload(version: u32) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; 5];
        buf[0] = MSG_SNDIN_VERSION;
        buf[1..5].copy_from_slice(&version.to_le_bytes());
        buf
    }

    fn make_formats_payload(formats: &[AudioFormat]) -> Vec<u8> {
        let pdu = SoundFormatsPdu {
            formats: formats.to_vec(),
            cb_size_formats_packet: 0x8000_0000, // server sends arbitrary value
        };
        let size = pdu.size();
        let mut buf = alloc::vec![0u8; size];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        buf
    }

    fn make_open_payload(frames_per_packet: u32, initial_format: u32) -> Vec<u8> {
        let fmt = AudioFormat::pcm(2, 44100, 16);
        let mut buf = alloc::vec![0u8; 27];
        buf[0] = MSG_SNDIN_OPEN;
        buf[1..5].copy_from_slice(&frames_per_packet.to_le_bytes());
        buf[5..9].copy_from_slice(&initial_format.to_le_bytes());
        // Inline PCM AudioFormat (18 bytes)
        let mut dst = WriteCursor::new(&mut buf[9..]);
        fmt.encode(&mut dst).unwrap();
        buf
    }

    fn make_format_change_payload(new_format: u32) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; 5];
        buf[0] = MSG_SNDIN_FORMATCHANGE;
        buf[1..5].copy_from_slice(&new_format.to_le_bytes());
        buf
    }

    /// Drive client through full negotiation to Recording state.
    fn drive_to_recording(client: &mut AudioInputClient) {
        client.start(1).unwrap();

        // Version exchange
        let version_payload = make_version_payload(SNDIN_VERSION_2);
        let msgs = client.process(1, &version_payload).unwrap();
        assert_eq!(msgs.len(), 1);

        // Format negotiation (server offers PCM 2ch 44100 16-bit)
        let server_formats = alloc::vec![AudioFormat::pcm(2, 44100, 16)];
        let formats_payload = make_formats_payload(&server_formats);
        let msgs = client.process(1, &formats_payload).unwrap();
        assert_eq!(msgs.len(), 1);

        // Open
        let open_payload = make_open_payload(1024, 0);
        let msgs = client.process(1, &open_payload).unwrap();
        assert_eq!(msgs.len(), 1);
        // Verify Open Reply is S_OK
        assert_eq!(msgs[0].data[0], MSG_SNDIN_OPEN_REPLY);
        assert_eq!(&msgs[0].data[1..5], &[0x00, 0x00, 0x00, 0x00]);

        assert!(client.is_recording());
    }

    #[test]
    fn channel_name_matches_spec() {
        let client = AudioInputClient::new();
        assert_eq!(client.channel_name(), "AUDIO_INPUT");
    }

    #[test]
    fn start_returns_empty() {
        let mut client = AudioInputClient::new();
        let msgs = client.start(1).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn version_negotiation_v2() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();

        let payload = make_version_payload(SNDIN_VERSION_2);
        let msgs = client.process(1, &payload).unwrap();
        assert_eq!(msgs.len(), 1);

        // Client should reply with its own version
        let reply = &msgs[0].data;
        assert_eq!(reply[0], MSG_SNDIN_VERSION);
        let version = u32::from_le_bytes([reply[1], reply[2], reply[3], reply[4]]);
        assert_eq!(version, SNDIN_VERSION_2);
    }

    #[test]
    fn version_negotiation_server_v1() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();

        let payload = make_version_payload(SNDIN_VERSION_1);
        let msgs = client.process(1, &payload).unwrap();
        assert_eq!(msgs.len(), 1);

        // Negotiated should be min(1, 2) = 1
        assert_eq!(client.negotiated_version, SNDIN_VERSION_1);
    }

    #[test]
    fn version_invalid_rejected() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();

        let payload = make_version_payload(3);
        assert!(client.process(1, &payload).is_err());
    }

    #[test]
    fn format_negotiation_intersection() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();
        client.process(1, &make_version_payload(SNDIN_VERSION_2)).unwrap();

        // Server offers PCM 2ch 44100 and PCM 1ch 8000
        let server_formats = alloc::vec![
            AudioFormat::pcm(2, 44100, 16),
            AudioFormat::pcm(1, 8000, 16),
        ];
        let payload = make_formats_payload(&server_formats);
        let msgs = client.process(1, &payload).unwrap();
        assert_eq!(msgs.len(), 1);

        // Client defaults include PCM 2ch 44100 — that should be in negotiated list
        assert!(!client.negotiated_formats.is_empty());
        assert!(client.negotiated_formats.iter().any(|f| {
            f.format_tag == WaveFormatTag::PCM
                && f.n_channels == 2
                && f.n_samples_per_sec == 44100
        }));
    }

    #[test]
    fn format_negotiation_no_common_formats() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();
        client.process(1, &make_version_payload(SNDIN_VERSION_2)).unwrap();

        // Server offers only a format the client doesn't support
        let server_formats = alloc::vec![AudioFormat::pcm(6, 96000, 24)];
        let payload = make_formats_payload(&server_formats);
        let msgs = client.process(1, &payload).unwrap();
        assert_eq!(msgs.len(), 1);

        assert!(client.negotiated_formats.is_empty());
        assert_eq!(client.state, ClientState::Closed);
    }

    #[test]
    fn full_negotiation_to_recording() {
        let mut client = AudioInputClient::new();
        drive_to_recording(&mut client);
        assert!(client.is_recording());
        assert_eq!(client.frames_per_packet(), 1024);
        assert!(client.current_format().is_some());
    }

    #[test]
    fn open_invalid_format_index() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();
        client.process(1, &make_version_payload(SNDIN_VERSION_2)).unwrap();

        let server_formats = alloc::vec![AudioFormat::pcm(2, 44100, 16)];
        client.process(1, &make_formats_payload(&server_formats)).unwrap();

        // initialFormat = 99 (out of range)
        let open_payload = make_open_payload(1024, 99);
        let msgs = client.process(1, &open_payload).unwrap();
        // Should send failure reply
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].data[0], MSG_SNDIN_OPEN_REPLY);
        // Non-zero result
        let result = u32::from_le_bytes([
            msgs[0].data[1], msgs[0].data[2], msgs[0].data[3], msgs[0].data[4],
        ]);
        assert_ne!(result, 0);
        assert_eq!(client.state, ClientState::Closed);
    }

    #[test]
    fn format_change_during_recording() {
        let mut client = AudioInputClient::new();
        // Setup: negotiate with 2 formats
        client.start(1).unwrap();
        client.process(1, &make_version_payload(SNDIN_VERSION_2)).unwrap();

        let server_formats = alloc::vec![
            AudioFormat::pcm(2, 44100, 16),
            AudioFormat::pcm(1, 44100, 16),
        ];
        client.process(1, &make_formats_payload(&server_formats)).unwrap();

        let open_payload = make_open_payload(1024, 0);
        client.process(1, &open_payload).unwrap();
        assert!(client.is_recording());
        assert_eq!(client.current_format_index, 0);

        // Server sends format change to index 1
        let fc_payload = make_format_change_payload(1);
        let msgs = client.process(1, &fc_payload).unwrap();
        assert_eq!(msgs.len(), 1);
        // Client echoes back confirmation
        assert_eq!(msgs[0].data[0], MSG_SNDIN_FORMATCHANGE);
        assert_eq!(client.current_format_index, 1);
    }

    #[test]
    fn format_change_out_of_range() {
        let mut client = AudioInputClient::new();
        drive_to_recording(&mut client);

        let fc_payload = make_format_change_payload(99);
        assert!(client.process(1, &fc_payload).is_err());
    }

    #[test]
    fn format_change_before_recording_rejected() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();
        client.process(1, &make_version_payload(SNDIN_VERSION_2)).unwrap();

        let fc_payload = make_format_change_payload(0);
        assert!(client.process(1, &fc_payload).is_err());
    }

    #[test]
    fn build_audio_messages_in_recording() {
        let mut client = AudioInputClient::new();
        drive_to_recording(&mut client);

        let msgs = client.build_audio_messages(alloc::vec![0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(msgs.len(), 2);
        // First: IncomingDataPdu (0x05)
        assert_eq!(msgs[0].data, [0x05]);
        // Second: DataPdu (0x06 + data)
        assert_eq!(msgs[1].data, [0x06, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn build_audio_messages_not_recording() {
        let client = AudioInputClient::new();
        assert!(client.build_audio_messages(alloc::vec![0x01]).is_err());
    }

    #[test]
    fn close_resets_state() {
        let mut client = AudioInputClient::new();
        drive_to_recording(&mut client);
        assert!(client.is_recording());

        client.close(1);
        assert!(!client.is_recording());
        assert!(client.negotiated_formats().is_empty());
        assert_eq!(client.frames_per_packet(), 0);
    }

    #[test]
    fn empty_payload_rejected() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();
        assert!(client.process(1, &[]).is_err());
    }

    #[test]
    fn unknown_message_id_rejected() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();
        assert!(client.process(1, &[0xFF]).is_err());
    }

    #[test]
    fn version_in_wrong_state_rejected() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();
        client.process(1, &make_version_payload(SNDIN_VERSION_2)).unwrap();

        // Send version again in WaitingForFormats state
        assert!(client.process(1, &make_version_payload(SNDIN_VERSION_2)).is_err());
    }

    #[test]
    fn formats_in_wrong_state_rejected() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();

        // Send formats before version
        let server_formats = alloc::vec![AudioFormat::pcm(2, 44100, 16)];
        let payload = make_formats_payload(&server_formats);
        assert!(client.process(1, &payload).is_err());
    }

    #[test]
    fn open_in_wrong_state_rejected() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();

        // Send open before negotiation
        let open_payload = make_open_payload(1024, 0);
        assert!(client.process(1, &open_payload).is_err());
    }

    #[test]
    fn closed_state_ignores_messages() {
        let mut client = AudioInputClient::new();
        // Client starts in Closed state (not started)
        let msgs = client.process(1, &make_version_payload(SNDIN_VERSION_2)).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn with_formats_requires_pcm() {
        let formats = alloc::vec![AudioFormat {
            format_tag: WaveFormatTag::ADPCM,
            n_channels: 2,
            n_samples_per_sec: 44100,
            n_avg_bytes_per_sec: 22050,
            n_block_align: 1024,
            bits_per_sample: 4,
            extra_data: alloc::vec![],
        }];
        assert!(AudioInputClient::with_formats(formats).is_err());
    }

    #[test]
    fn with_formats_accepts_pcm() {
        let formats = alloc::vec![AudioFormat::pcm(1, 16000, 16)];
        assert!(AudioInputClient::with_formats(formats).is_ok());
    }

    #[test]
    fn with_formats_rejects_too_many() {
        let mut formats: Vec<AudioFormat> = (0..257)
            .map(|i| AudioFormat::pcm(1, 8000 + i as u32, 16))
            .collect();
        // Ensure PCM is present so the PCM check passes
        formats[0] = AudioFormat::pcm(1, 8000, 16);
        assert!(AudioInputClient::with_formats(formats).is_err());
    }

    #[test]
    fn current_format_none_when_not_recording() {
        let client = AudioInputClient::new();
        assert!(client.current_format().is_none());
    }

    #[test]
    fn negotiated_version_v1_when_server_v1() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();
        client.process(1, &make_version_payload(SNDIN_VERSION_1)).unwrap();
        assert_eq!(client.negotiated_version(), SNDIN_VERSION_1);
    }

    #[test]
    fn negotiated_version_v2_when_both_v2() {
        let mut client = AudioInputClient::new();
        client.start(1).unwrap();
        client.process(1, &make_version_payload(SNDIN_VERSION_2)).unwrap();
        assert_eq!(client.negotiated_version(), SNDIN_VERSION_2);
    }
}
