#![forbid(unsafe_code)]

//! RDPSND channel processor -- SVC integration.

use alloc::boxed::Box;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcClientProcessor, SvcMessage, SvcProcessor, SvcResult,
    RDPSND,
};

use crate::backend::RdpsndBackend;
use crate::pdu::{
    AudioFormat, ClientAudioFormatsPdu, ClientSndFlags, QualityMode, QualityModePdu,
    ServerAudioFormatsPdu, SndHeader, SndMsgType, TrainingConfirmPdu, TrainingPdu,
    VolumePdu, Wave2Pdu, WaveConfirmPdu, WaveInfoPdu, decode_wave_data,
};

/// RDPSND protocol version we advertise.
const CLIENT_VERSION: u16 = 0x0006;

/// Client-side RDPSND state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RdpsndState {
    /// Waiting for server's Audio Formats PDU.
    WaitServerFormats,
    /// Sent client formats, waiting for Training PDU.
    WaitTraining,
    /// Received WaveInfo, waiting for the following Wave PDU data.
    WaitWaveData,
    /// Active: audio data may flow.
    Active,
}

/// Client-side RDPSND processor.
pub struct RdpsndClient {
    state: RdpsndState,
    backend: Box<dyn RdpsndBackend>,
    /// Server's protocol version.
    server_version: u16,
    /// Negotiated audio formats (intersection).
    negotiated_formats: Vec<AudioFormat>,
    /// Pending WaveInfo (when waiting for Wave PDU).
    pending_wave_info: Option<WaveInfoPdu>,
}

impl AsAny for RdpsndClient {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl core::fmt::Debug for RdpsndClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpsndClient")
            .field("state", &self.state)
            .field("server_version", &self.server_version)
            .field("negotiated_formats_count", &self.negotiated_formats.len())
            .finish()
    }
}

impl RdpsndClient {
    /// Create a new RDPSND client processor.
    pub fn new(backend: Box<dyn RdpsndBackend>) -> Self {
        Self {
            state: RdpsndState::WaitServerFormats,
            backend,
            server_version: 0,
            negotiated_formats: Vec::new(),
            pending_wave_info: None,
        }
    }

    /// Encode a PDU into an SvcMessage.
    fn encode_pdu<T: Encode>(pdu: &T) -> SvcResult<SvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }

    /// Handle incoming PDU based on current state.
    fn handle_pdu(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        let mut cursor = ReadCursor::new(payload);

        // Special case: if we're waiting for Wave data (no header).
        if self.state == RdpsndState::WaitWaveData {
            return self.handle_wave_data(&mut cursor);
        }

        let header = SndHeader::decode(&mut cursor)?;

        match header.msg_type {
            SndMsgType::Formats if self.state == RdpsndState::WaitServerFormats => {
                self.handle_server_formats(&mut cursor)
            }

            SndMsgType::Training => self.handle_training(&mut cursor, header.body_size),

            SndMsgType::Wave if self.state == RdpsndState::Active => {
                self.handle_wave_info(&mut cursor, header.body_size)
            }

            SndMsgType::Wave2 if self.state == RdpsndState::Active => {
                self.handle_wave2(&mut cursor, header.body_size)
            }

            SndMsgType::WaveConfirm => {
                // Server shouldn't send this to client; ignore.
                Ok(Vec::new())
            }

            SndMsgType::SetVolume => {
                let vol = VolumePdu::decode_body(&mut cursor)?;
                self.backend.on_volume(&vol);
                Ok(Vec::new())
            }

            SndMsgType::SetPitch => {
                // Client MUST ignore pitch per spec.
                Ok(Vec::new())
            }

            SndMsgType::Close => {
                self.backend.on_close();
                Ok(Vec::new())
            }

            SndMsgType::QualityMode => {
                // Server shouldn't send this; ignore.
                Ok(Vec::new())
            }

            // UDP-only or unknown: skip.
            _ => Ok(Vec::new()),
        }
    }

    fn handle_server_formats(
        &mut self,
        cursor: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        let server_pdu = ServerAudioFormatsPdu::decode_body(cursor)?;
        self.server_version = server_pdu.version;

        // Ask backend which formats to support.
        let supported_indices = self.backend.on_server_formats(&server_pdu.formats);

        // Build negotiated format list (intersection).
        self.negotiated_formats = supported_indices
            .iter()
            .filter_map(|&i| server_pdu.formats.get(i).cloned())
            .collect();

        // Build client response.
        let client_pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE.union(ClientSndFlags::VOLUME),
            volume: 0xFFFF_FFFF, // Full volume both channels.
            pitch: 0x0001_0000,  // 1.0x pitch.
            version: CLIENT_VERSION,
            formats: self.negotiated_formats.clone(),
        };
        let mut messages = alloc::vec![Self::encode_pdu(&client_pdu)?];

        // If both versions >= 6, send Quality Mode PDU.
        if self.server_version >= 6 && CLIENT_VERSION >= 6 {
            let quality = QualityModePdu::new(QualityMode::Dynamic);
            messages.push(Self::encode_pdu(&quality)?);
        }

        self.state = RdpsndState::WaitTraining;
        Ok(messages)
    }

    fn handle_training(
        &mut self,
        cursor: &mut ReadCursor<'_>,
        body_size: u16,
    ) -> SvcResult<Vec<SvcMessage>> {
        let training = TrainingPdu::decode_body(cursor, body_size)?;
        let confirm = TrainingConfirmPdu::from_training(&training);

        self.state = RdpsndState::Active;
        Ok(alloc::vec![Self::encode_pdu(&confirm)?])
    }

    fn handle_wave_info(
        &mut self,
        cursor: &mut ReadCursor<'_>,
        body_size: u16,
    ) -> SvcResult<Vec<SvcMessage>> {
        let wave_info = WaveInfoPdu::decode_body(cursor, body_size)?;
        self.pending_wave_info = Some(wave_info);
        self.state = RdpsndState::WaitWaveData;
        Ok(Vec::new())
    }

    fn handle_wave_data(
        &mut self,
        cursor: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        let wave_info = self.pending_wave_info.take().ok_or_else(|| {
            justrdp_svc::SvcError::Protocol(alloc::string::String::from(
                "Wave PDU without preceding WaveInfo",
            ))
        })?;

        let audio = decode_wave_data(cursor, &wave_info)?;
        self.backend
            .on_wave_data(wave_info.format_no, &audio, None);

        self.state = RdpsndState::Active;

        // Send Wave Confirm.
        let confirm = WaveConfirmPdu::new(wave_info.timestamp, wave_info.block_no);
        Ok(alloc::vec![Self::encode_pdu(&confirm)?])
    }

    fn handle_wave2(
        &mut self,
        cursor: &mut ReadCursor<'_>,
        body_size: u16,
    ) -> SvcResult<Vec<SvcMessage>> {
        let wave2 = Wave2Pdu::decode_body(cursor, body_size)?;
        self.backend
            .on_wave_data(wave2.format_no, &wave2.data, Some(wave2.audio_timestamp));

        // Send Wave Confirm.
        let confirm = WaveConfirmPdu::new(wave2.timestamp, wave2.block_no);
        Ok(alloc::vec![Self::encode_pdu(&confirm)?])
    }
}

impl SvcProcessor for RdpsndClient {
    fn channel_name(&self) -> ChannelName {
        RDPSND
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        // Client waits for server to send formats first.
        Ok(Vec::new())
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        self.handle_pdu(payload)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

impl SvcClientProcessor for RdpsndClient {}
