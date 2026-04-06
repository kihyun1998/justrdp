#![forbid(unsafe_code)]

//! Transport-agnostic RDPSND core logic.
//!
//! Shared between SVC (`RdpsndClient`) and DVC (`RdpsndDvcClient`) processors.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};

use crate::backend::RdpsndBackend;
use crate::pdu::{
    AudioFormat, ClientAudioFormatsPdu, ClientSndFlags, QualityMode, QualityModePdu,
    ServerAudioFormatsPdu, SndHeader, SndMsgType, TrainingConfirmPdu, TrainingPdu, VolumePdu,
    Wave2Pdu, WaveConfirmPdu, WaveInfoPdu, decode_wave_data,
};

/// RDPSND protocol version for SVC mode.
const CLIENT_VERSION_SVC: u16 = 0x0006;

/// RDPSND protocol version for DVC mode (Windows 8+).
/// MS-RDPEA Product Behavior <3>, <6>: version >= 8 enables Wave2 and DVC.
const CLIENT_VERSION_DVC: u16 = 0x0008;

/// MS-RDPEA 2.2.2.3: Quality Mode PDU requires both sides at version >= 6.
const QUALITY_MODE_MIN_VERSION: u16 = 6;

/// RDPSND protocol state machine -- MS-RDPEA 3.2.5
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RdpsndState {
    /// Waiting for server's Audio Formats PDU.
    WaitServerFormats,
    /// Sent client formats, waiting for Training PDU.
    WaitTraining,
    /// Received WaveInfo, waiting for the following Wave PDU data.
    WaitWaveData,
    /// Active: audio data may flow.
    Active,
}

/// Error from RDPSND core logic.
#[derive(Debug)]
pub(crate) enum RdpsndError {
    Decode(justrdp_core::DecodeError),
    Encode(justrdp_core::EncodeError),
    Protocol(String),
}

impl From<justrdp_core::DecodeError> for RdpsndError {
    fn from(e: justrdp_core::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<justrdp_core::EncodeError> for RdpsndError {
    fn from(e: justrdp_core::EncodeError) -> Self {
        Self::Encode(e)
    }
}

pub(crate) type RdpsndResult<T> = Result<T, RdpsndError>;

/// Transport-agnostic RDPSND core.
///
/// Handles all PDU parsing, state transitions, and response generation.
/// Returns raw encoded bytes; the transport wrapper converts to `SvcMessage`
/// or `DvcMessage`.
pub(crate) struct RdpsndCore {
    state: RdpsndState,
    backend: Box<dyn RdpsndBackend>,
    /// Server's protocol version.
    server_version: u16,
    /// Client protocol version to advertise.
    client_version: u16,
    /// Negotiated audio formats (intersection).
    negotiated_formats: Vec<AudioFormat>,
    /// Pending WaveInfo (when waiting for Wave PDU).
    pending_wave_info: Option<WaveInfoPdu>,
}

impl core::fmt::Debug for RdpsndCore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdpsndCore")
            .field("state", &self.state)
            .field("server_version", &self.server_version)
            .field("client_version", &self.client_version)
            .field("negotiated_formats_count", &self.negotiated_formats.len())
            .finish()
    }
}

impl RdpsndCore {
    /// Create a new RDPSND core with the given backend and client version.
    pub(crate) fn new_svc(backend: Box<dyn RdpsndBackend>) -> Self {
        Self::new(backend, CLIENT_VERSION_SVC)
    }

    /// Create a new RDPSND core for DVC mode (advertises version 8).
    pub(crate) fn new_dvc(backend: Box<dyn RdpsndBackend>) -> Self {
        Self::new(backend, CLIENT_VERSION_DVC)
    }

    fn new(backend: Box<dyn RdpsndBackend>, client_version: u16) -> Self {
        Self {
            state: RdpsndState::WaitServerFormats,
            backend,
            client_version,
            server_version: 0,
            negotiated_formats: Vec::new(),
            pending_wave_info: None,
        }
    }

    /// Encode a PDU into raw bytes.
    pub(crate) fn encode_pdu<T: Encode>(pdu: &T) -> RdpsndResult<Vec<u8>> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor)?;
        Ok(buf)
    }

    /// Reset state to initial (used on Close or DVC channel re-open).
    pub(crate) fn reset(&mut self) {
        self.state = RdpsndState::WaitServerFormats;
        self.server_version = 0;
        self.negotiated_formats.clear();
        self.pending_wave_info = None;
    }

    /// Handle incoming PDU payload. Returns zero or more encoded response PDUs.
    pub(crate) fn handle_pdu(&mut self, payload: &[u8]) -> RdpsndResult<Vec<Vec<u8>>> {
        let mut cursor = ReadCursor::new(payload);

        // Special case: if we're waiting for Wave data (no SNDPROLOG header).
        // The Wave PDU is raw audio prefixed by 4 pad bytes.
        // However, if the payload starts with a valid SndMsgType byte, it is
        // a new PDU (e.g., Training, Close) rather than raw wave data.
        // In that case, discard the orphaned wave info and fall through to
        // normal header-based dispatch.
        if self.state == RdpsndState::WaitWaveData {
            let is_new_pdu = payload.len() >= 4 && SndMsgType::is_valid(payload[0]);
            if !is_new_pdu {
                return self.handle_wave_data(&mut cursor);
            }
            // Orphaned WaveInfo: the expected Wave data never arrived.
            self.pending_wave_info = None;
            self.state = RdpsndState::Active;
        }

        let header = SndHeader::decode(&mut cursor)?;

        match header.msg_type {
            SndMsgType::Formats if self.state == RdpsndState::WaitServerFormats => {
                self.handle_server_formats(&mut cursor)
            }

            // MS-RDPEA 3.2.5: server may send Training in WaitTraining or Active.
            SndMsgType::Training
                if matches!(
                    self.state,
                    RdpsndState::WaitTraining | RdpsndState::Active
                ) =>
            {
                self.handle_training(&mut cursor, header.body_size)
            }

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
                self.reset();
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

    /// Handle incoming PDU on lossy DVC transport.
    ///
    /// Delegates to `handle_pdu`, which already recovers from orphaned
    /// `WaitWaveData` state by detecting valid SNDPROLOG headers in the
    /// incoming payload. On lossy (UDP) transport this recovery is expected
    /// due to packet loss; on reliable (TCP) transport it acts as a safety net.
    pub(crate) fn handle_pdu_lossy(&mut self, payload: &[u8]) -> RdpsndResult<Vec<Vec<u8>>> {
        self.handle_pdu(payload)
    }

    fn handle_server_formats(
        &mut self,
        cursor: &mut ReadCursor<'_>,
    ) -> RdpsndResult<Vec<Vec<u8>>> {
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
            volume: 0xFFFF_FFFF, // MS-RDPEA 2.2.2.2: full volume both channels
            pitch: 0x0001_0000,  // MS-RDPEA 2.2.2.2: 1.0x pitch (fixed-point)
            version: self.client_version,
            formats: self.negotiated_formats.clone(),
        };
        let mut messages = alloc::vec![Self::encode_pdu(&client_pdu)?];

        // MS-RDPEA 2.2.2.3: client MUST send Quality Mode PDU when both versions >= 6.
        if self.server_version >= QUALITY_MODE_MIN_VERSION
            && self.client_version >= QUALITY_MODE_MIN_VERSION
        {
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
    ) -> RdpsndResult<Vec<Vec<u8>>> {
        let training = TrainingPdu::decode_body(cursor, body_size)?;
        let confirm = TrainingConfirmPdu::from_training(&training);

        self.state = RdpsndState::Active;
        Ok(alloc::vec![Self::encode_pdu(&confirm)?])
    }

    fn handle_wave_info(
        &mut self,
        cursor: &mut ReadCursor<'_>,
        body_size: u16,
    ) -> RdpsndResult<Vec<Vec<u8>>> {
        let wave_info = WaveInfoPdu::decode_body(cursor, body_size)?;
        self.pending_wave_info = Some(wave_info);
        self.state = RdpsndState::WaitWaveData;
        Ok(Vec::new())
    }

    fn handle_wave_data(&mut self, cursor: &mut ReadCursor<'_>) -> RdpsndResult<Vec<Vec<u8>>> {
        let wave_info = self.pending_wave_info.take().ok_or_else(|| {
            RdpsndError::Protocol(format!("Wave PDU without preceding WaveInfo"))
        })?;

        if wave_info.format_no as usize >= self.negotiated_formats.len() {
            return Err(RdpsndError::Protocol(format!(
                "Wave format_no {} out of range (negotiated: {})",
                wave_info.format_no,
                self.negotiated_formats.len(),
            )));
        }

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
    ) -> RdpsndResult<Vec<Vec<u8>>> {
        let wave2 = Wave2Pdu::decode_body(cursor, body_size)?;

        if wave2.format_no as usize >= self.negotiated_formats.len() {
            return Err(RdpsndError::Protocol(format!(
                "Wave2 format_no {} out of range (negotiated: {})",
                wave2.format_no,
                self.negotiated_formats.len(),
            )));
        }

        self.backend
            .on_wave_data(wave2.format_no, &wave2.data, Some(wave2.audio_timestamp));

        // Send Wave Confirm.
        let confirm = WaveConfirmPdu::new(wave2.timestamp, wave2.block_no);
        Ok(alloc::vec![Self::encode_pdu(&confirm)?])
    }
}
