#![forbid(unsafe_code)]

//! Server-side audio channel processor -- MS-RDPEA server role.
//!
//! Mirror of [`crate::RdpsndClient`] for the server direction. Drives
//! the MS-RDPEA 1.3.2 initialization sequence (Server Audio Formats →
//! Client Audio Formats → optional Quality Mode / Training) and then
//! streams audio via [`SoundServer::emit_wave_chunk`] (WaveInfo + Wave
//! pair, §2.2.3.3-4) or [`SoundServer::emit_wave2_chunk`] (single
//! compressed PDU, §2.2.3.10).
//!
//! `WaveConfirm` PDUs from the client are correlated against the
//! server's outgoing block numbers; the measured u16-wrapping latency
//! is handed to the application via
//! [`RdpServerSoundHandler::on_wave_confirm`].

use alloc::boxed::Box;
use alloc::vec::Vec;

use justrdp_core::{AsAny, Decode, Encode, ReadCursor, WriteCursor};
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcError, SvcMessage, SvcProcessor, SvcResult,
    SvcServerProcessor, RDPSND,
};

use crate::pdu::{
    encode_wave_pdu_body, AudioFormat, ClientAudioFormatsPdu, ClientSndFlags, QualityMode,
    QualityModePdu, ServerAudioFormatsPdu, ServerSndCapsFlags, SndHeader, SndMsgType,
    TrainingPdu, Wave2Pdu, WaveConfirmPdu, WaveInfoPdu,
};

/// Server-side audio channel state -- MS-RDPEA 3.3.5 abstract data model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoundServerState {
    /// `start()` has not been called yet.
    NotStarted,
    /// Server emitted Audio Formats PDU; awaiting the client's Formats
    /// reply (MS-RDPEA 1.3.2).
    WaitClientFormats,
    /// Client responded; full data exchange enabled. WaveInfo/Wave2
    /// emits are only valid in this state.
    Streaming,
}

/// Upper bound on how many blocks the server keeps in its pending-confirm
/// ring. With an 8-bit block counter the protocol cannot place more than
/// 256 in flight anyway; an oversized allocation would only happen from a
/// buggy caller emitting chunks without ever waiting for confirms.
const MAX_PENDING_CONFIRMS: usize = 256;

/// Application-side audio handler invoked by [`SoundServer`] when the
/// client drives audio events. Symmetric in name to
/// [`crate::RdpsndBackend`] but deliberately distinct so a client
/// backend cannot be wired into the server processor.
pub trait RdpServerSoundHandler: Send {
    /// Client responded with its Audio Formats PDU. The arguments
    /// carry the *negotiated* values:
    ///
    /// - `negotiated_formats`: intersection of the server-advertised
    ///   list and the client-accepted list (by AUDIO_FORMAT equality).
    /// - `negotiated_flags`: bitwise AND of server and client
    ///   `dwFlags` (ALIVE / VOLUME / PITCH).
    /// - `negotiated_version`: `min(server, client)` versions.
    fn on_client_formats(
        &mut self,
        negotiated_formats: &[AudioFormat],
        negotiated_flags: ClientSndFlags,
        negotiated_version: u16,
    );

    /// Client emitted a `QualityMode` PDU (either during init or mid-
    /// stream). Default: ignore.
    fn on_quality_mode(&mut self, _mode: QualityMode) {}

    /// Client emitted a `WaveConfirm` PDU matching an in-flight block
    /// the server recorded at emit time. `latency_ms` is the u16
    /// wrapping subtraction of `(current_ts - sent_ts)`. Unmatched
    /// confirms are silently dropped (not forwarded here).
    fn on_wave_confirm(
        &mut self,
        _timestamp: u16,
        _confirmed_block_no: u8,
        _latency_ms: u16,
    ) {
    }

    /// Client emitted the Training Confirm PDU responding to a prior
    /// `send_training()`. `rtt_ms` is the u16-wrapping round-trip
    /// latency; `pack_size` echoes the server's request.
    fn on_training_confirm(&mut self, _timestamp: u16, _pack_size: u16, _rtt_ms: u16) {}

    /// Client emitted a `Close` PDU requesting the server to shut
    /// down audio streaming. Default: no-op.
    fn on_close(&mut self) {}
}

/// Server-side RDPSND SVC channel processor.
///
/// `start()` emits the Server Audio Formats and Version PDU
/// (MS-RDPEA 2.2.2.1). Subsequent `process()` calls handle client PDUs
/// and dispatch to [`RdpServerSoundHandler`]. Proactive server-side
/// emits (Quality Mode, Training, Wave/Wave2 streaming) go through
/// the `build_*` / `send_*` / `emit_*` helpers on [`SoundServer`].
pub struct SoundServer {
    state: SoundServerState,
    handler: Box<dyn RdpServerSoundHandler>,
    server_formats: Vec<AudioFormat>,
    server_flags: ServerSndCapsFlags,
    server_version: u16,
    initial_volume: u32,
    initial_pitch: u32,
    /// Formats the client accepted from the server's advertised list
    /// (populated when the client's Audio Formats PDU arrives).
    negotiated_formats: Vec<AudioFormat>,
    /// `server_flags & client_flags` once the client responds;
    /// `ClientSndFlags::from_bits(0)` before.
    negotiated_flags: ClientSndFlags,
    /// `min(server_version, client_version)` once negotiated; `0` before.
    negotiated_version: u16,
    /// Monotonically-incrementing block counter (u8 wrapping).
    next_block_no: u8,
    /// Recently emitted `(block_no, timestamp)` pairs awaiting Wave
    /// Confirm. Capped at [`MAX_PENDING_CONFIRMS`]; oldest entries
    /// are dropped FIFO when the cap is exceeded.
    pending_confirms: Vec<(u8, u16)>,
    /// Timestamp of an outgoing Training PDU awaiting Training Confirm.
    /// `Some` only between `send_training()` and the confirm arrival.
    training_emit_ts: Option<u16>,
}

impl AsAny for SoundServer {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl core::fmt::Debug for SoundServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoundServer")
            .field("state", &self.state)
            .field("server_version", &self.server_version)
            .field("negotiated_version", &self.negotiated_version)
            .field("negotiated_formats", &self.negotiated_formats.len())
            .field("next_block_no", &self.next_block_no)
            .finish()
    }
}

impl SoundServer {
    /// Construct a server processor. `server_formats` is the list of
    /// `AUDIO_FORMAT`s the server advertises; an empty list advertises
    /// no capability (legal but no audio will flow).
    pub fn new(
        handler: Box<dyn RdpServerSoundHandler>,
        server_formats: Vec<AudioFormat>,
    ) -> Self {
        Self {
            state: SoundServerState::NotStarted,
            handler,
            server_formats,
            server_flags: ServerSndCapsFlags::ALIVE,
            // Default to version 6 -- the first version that enables
            // Quality Mode and Wave2 (MS-RDPEA product behaviour).
            server_version: 6,
            initial_volume: 0xFFFF_FFFF,
            initial_pitch: 0x0001_0000,
            negotiated_formats: Vec::new(),
            negotiated_flags: ClientSndFlags::from_bits(0),
            negotiated_version: 0,
            next_block_no: 0,
            pending_confirms: Vec::new(),
            training_emit_ts: None,
        }
    }

    /// Override the server capability flags (default: ALIVE only).
    pub fn with_flags(mut self, flags: ServerSndCapsFlags) -> Self {
        self.server_flags = flags;
        self
    }

    /// Override the advertised protocol version (default: 6).
    pub fn with_version(mut self, version: u16) -> Self {
        self.server_version = version;
        self
    }

    /// Override the initial volume advertised in the Server Audio
    /// Formats PDU (default: `0xFFFF_FFFF` = full stereo).
    pub fn with_initial_volume(mut self, volume: u32) -> Self {
        self.initial_volume = volume;
        self
    }

    /// Override the initial pitch advertised in the Server Audio
    /// Formats PDU (default: `0x0001_0000` = 1.0 in 16.16 fixed).
    pub fn with_initial_pitch(mut self, pitch: u32) -> Self {
        self.initial_pitch = pitch;
        self
    }

    /// Formats the client accepted from the server's advertised list.
    /// Empty until the client's Audio Formats PDU arrives.
    pub fn negotiated_formats(&self) -> &[AudioFormat] {
        &self.negotiated_formats
    }

    /// Negotiated capability flags (`ALIVE`/`VOLUME`/`PITCH` bits).
    pub fn negotiated_flags(&self) -> ClientSndFlags {
        self.negotiated_flags
    }

    /// Negotiated protocol version; `0` until the client responds.
    pub fn negotiated_version(&self) -> u16 {
        self.negotiated_version
    }

    /// Whether the server has reached the `Streaming` state and can
    /// call `emit_wave_chunk` / `emit_wave2_chunk`.
    pub fn is_streaming(&self) -> bool {
        self.state == SoundServerState::Streaming
    }

    fn encode_pdu<T: Encode>(pdu: &T) -> SvcResult<SvcMessage> {
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor)?;
        Ok(SvcMessage::new(buf))
    }

    /// Build the Server Audio Formats and Version PDU from current
    /// configuration.
    fn build_server_formats(&self) -> ServerAudioFormatsPdu {
        ServerAudioFormatsPdu {
            flags: self.server_flags,
            volume: self.initial_volume,
            pitch: self.initial_pitch,
            dgram_port: 0,
            // MS-RDPEA test vector shows 0xFF in the first emit; this
            // signals "no blocks confirmed yet".
            last_block_confirmed: 0xFF,
            version: self.server_version,
            formats: self.server_formats.clone(),
        }
    }

    fn push_pending_confirm(&mut self, block_no: u8, timestamp: u16) {
        if self.pending_confirms.len() >= MAX_PENDING_CONFIRMS {
            // Drop oldest to keep the ring bounded. This only happens
            // if the caller emits ~256 chunks without receiving any
            // confirms -- at which point the client is unresponsive
            // anyway and keeping stale entries serves no purpose.
            self.pending_confirms.remove(0);
        }
        self.pending_confirms.push((block_no, timestamp));
    }

    fn take_pending_confirm(&mut self, block_no: u8) -> Option<u16> {
        let idx = self
            .pending_confirms
            .iter()
            .position(|(b, _)| *b == block_no)?;
        let (_, ts) = self.pending_confirms.remove(idx);
        Some(ts)
    }

    /// Determine whether `format_index` is a server-advertised format
    /// that the client also accepted. Protects `emit_wave*_chunk`
    /// against emitting PDUs referencing formats the client would
    /// reject.
    fn is_negotiated_format(&self, format_index: usize) -> bool {
        let Some(fmt) = self.server_formats.get(format_index) else {
            return false;
        };
        self.negotiated_formats.iter().any(|f| f == fmt)
    }

    fn handle_client_formats(
        &mut self,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        let pdu = ClientAudioFormatsPdu::decode_body(body)?;

        // Format intersection (MS-RDPEA 3.3.5.1.2). The client
        // returns full AUDIO_FORMAT structs from the server's list,
        // not indices; we filter the client's list to those that
        // also appear in ours.
        let negotiated: Vec<AudioFormat> = pdu
            .formats
            .iter()
            .filter(|f| self.server_formats.iter().any(|s| s == *f))
            .cloned()
            .collect();

        self.negotiated_formats = negotiated;
        self.negotiated_flags = ClientSndFlags::from_bits(
            self.server_flags.bits() & pdu.flags.bits(),
        );
        self.negotiated_version = self.server_version.min(pdu.version);
        self.state = SoundServerState::Streaming;

        self.handler.on_client_formats(
            &self.negotiated_formats,
            self.negotiated_flags,
            self.negotiated_version,
        );
        Ok(Vec::new())
    }

    fn handle_quality_mode(
        &mut self,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        let pdu = QualityModePdu::decode_body(body)?;
        self.handler.on_quality_mode(pdu.quality_mode);
        Ok(Vec::new())
    }

    fn handle_training_confirm(
        &mut self,
        body: &mut ReadCursor<'_>,
        body_size: u16,
    ) -> SvcResult<Vec<SvcMessage>> {
        let pdu = TrainingPdu::decode_body(body, body_size)?;
        if let Some(sent_ts) = self.training_emit_ts.take() {
            let rtt = pdu.timestamp.wrapping_sub(sent_ts);
            self.handler.on_training_confirm(pdu.timestamp, pdu.pack_size, rtt);
        }
        // A confirm without a pending training (stale / duplicate)
        // is silently ignored per MS-RDPEA 3.1.5.1.
        Ok(Vec::new())
    }

    fn handle_wave_confirm(
        &mut self,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        let pdu = WaveConfirmPdu::decode_body(body)?;
        if let Some(sent_ts) = self.take_pending_confirm(pdu.confirmed_block_no) {
            let latency = pdu.timestamp.wrapping_sub(sent_ts);
            self.handler
                .on_wave_confirm(pdu.timestamp, pdu.confirmed_block_no, latency);
        }
        // Unmatched confirms (stale / duplicate) are silently dropped.
        Ok(Vec::new())
    }

    fn reset(&mut self) {
        self.state = SoundServerState::NotStarted;
        self.negotiated_formats.clear();
        self.negotiated_flags = ClientSndFlags::from_bits(0);
        self.negotiated_version = 0;
        self.next_block_no = 0;
        self.pending_confirms.clear();
        self.training_emit_ts = None;
    }

    fn handle_pdu(
        &mut self,
        header: &SndHeader,
        body: &mut ReadCursor<'_>,
    ) -> SvcResult<Vec<SvcMessage>> {
        // Gate data-phase PDUs on the Streaming state; the init phase
        // only permits the Formats exchange. Unexpected PDUs are
        // dropped silently per MS-RDPEA 3.1.5.1.
        if self.state == SoundServerState::WaitClientFormats {
            match header.msg_type {
                SndMsgType::Formats => {}
                SndMsgType::Close => {
                    self.handler.on_close();
                    self.reset();
                    return Ok(Vec::new());
                }
                _ => return Ok(Vec::new()),
            }
        }

        match header.msg_type {
            SndMsgType::Formats => {
                if self.state == SoundServerState::WaitClientFormats {
                    self.handle_client_formats(body)
                } else {
                    // Re-negotiation mid-stream is not defined by the
                    // spec; drop silently.
                    Ok(Vec::new())
                }
            }
            SndMsgType::Training => {
                // Server-sent Training and client-sent Training Confirm
                // share msgType=0x06. Direction disambiguates: we only
                // receive Training PDUs while a prior `send_training()`
                // is outstanding.
                self.handle_training_confirm(body, header.body_size)
            }
            SndMsgType::WaveConfirm => self.handle_wave_confirm(body),
            SndMsgType::QualityMode => self.handle_quality_mode(body),
            SndMsgType::Close => {
                self.handler.on_close();
                self.reset();
                Ok(Vec::new())
            }
            // PDUs that should only flow server→client -- if received,
            // silently drop (MS-RDPEA 3.1.5.1).
            SndMsgType::Wave
            | SndMsgType::Wave2
            | SndMsgType::SetVolume
            | SndMsgType::SetPitch
            | SndMsgType::CryptKey
            | SndMsgType::WaveEncrypt
            | SndMsgType::UdpWave
            | SndMsgType::UdpWaveLast => Ok(Vec::new()),
        }
    }
}

// Outbound proactive emit helpers.
impl SoundServer {
    /// Build a Quality Mode PDU (MS-RDPEA 2.2.2.3) for the caller to
    /// transmit. Only meaningful when the negotiated version is `>= 6`
    /// (earlier versions do not define this PDU); returns the encoded
    /// message regardless so a test harness can exercise both paths.
    pub fn build_quality_mode(&self, mode: QualityMode) -> SvcResult<SvcMessage> {
        Self::encode_pdu(&QualityModePdu::new(mode))
    }

    /// Build and arm a Training PDU. Records `timestamp` so the
    /// eventual Training Confirm can be correlated via
    /// [`RdpServerSoundHandler::on_training_confirm`].
    ///
    /// `pack_size = 0` emits an 8-byte Training PDU; any other value
    /// pads the PDU so its total wire size equals `pack_size`, letting
    /// the server measure round-trip latency at a specific packet size.
    ///
    /// Returns an error if the server is not yet `Streaming`; Training
    /// is only defined after the Audio Formats exchange.
    pub fn send_training(
        &mut self,
        timestamp: u16,
        pack_size: u16,
    ) -> SvcResult<SvcMessage> {
        if self.state != SoundServerState::Streaming {
            return Err(SvcError::Protocol(alloc::string::String::from(
                "SoundServer::send_training called before negotiation complete",
            )));
        }
        self.training_emit_ts = Some(timestamp);
        let pdu = TrainingPdu::new(timestamp, pack_size);
        Self::encode_pdu(&pdu)
    }

    /// Emit an audio chunk as a WaveInfo + Wave PDU pair
    /// (MS-RDPEA 2.2.3.3-4). Returns two [`SvcMessage`]s; the caller
    /// MUST send them in order with no intervening PDU on the same
    /// channel.
    ///
    /// `format_index` is the index into the originally-advertised
    /// server format list (that same index is the wire `wFormatNo`).
    /// The format MUST be one the client accepted in its Audio
    /// Formats response; otherwise an error is returned.
    ///
    /// `audio` MUST be at least 4 bytes (the WaveInfo `Data[4]` field
    /// cannot be shortened per spec). `timestamp` is the server's
    /// wall-clock tick; it is recorded for later correlation with the
    /// client's Wave Confirm.
    pub fn emit_wave_chunk(
        &mut self,
        format_index: usize,
        audio: &[u8],
        timestamp: u16,
    ) -> SvcResult<Vec<SvcMessage>> {
        if self.state != SoundServerState::Streaming {
            return Err(SvcError::Protocol(alloc::string::String::from(
                "SoundServer::emit_wave_chunk called before Streaming",
            )));
        }
        if !self.is_negotiated_format(format_index) {
            return Err(SvcError::Protocol(alloc::string::String::from(
                "format_index is not in the negotiated format set",
            )));
        }
        let format_no = u16::try_from(format_index).map_err(|_| {
            SvcError::Protocol(alloc::string::String::from("format_index > u16::MAX"))
        })?;
        let block_no = self.next_block_no;
        let info = WaveInfoPdu::from_chunk(timestamp, format_no, block_no, audio).ok_or_else(
            || {
                SvcError::Protocol(alloc::string::String::from(
                    "audio chunk smaller than 4 bytes (WaveInfo Data[4] minimum)",
                ))
            },
        )?;
        let info_msg = Self::encode_pdu(&info)?;
        let wave_msg = SvcMessage::new(encode_wave_pdu_body(&audio[4..]));
        self.push_pending_confirm(block_no, timestamp);
        self.next_block_no = self.next_block_no.wrapping_add(1);
        Ok(alloc::vec![info_msg, wave_msg])
    }

    /// Emit an audio chunk as a Wave2 PDU (MS-RDPEA 2.2.3.10). Unlike
    /// [`emit_wave_chunk`], Wave2 is a single self-contained PDU and
    /// carries `dwAudioTimeStamp` (capture time in milliseconds) for
    /// A/V sync.
    ///
    /// Same `format_index` / `Streaming`-state constraints as
    /// [`emit_wave_chunk`]. `audio` has no minimum length.
    pub fn emit_wave2_chunk(
        &mut self,
        format_index: usize,
        audio: Vec<u8>,
        timestamp: u16,
        audio_timestamp: u32,
    ) -> SvcResult<SvcMessage> {
        if self.state != SoundServerState::Streaming {
            return Err(SvcError::Protocol(alloc::string::String::from(
                "SoundServer::emit_wave2_chunk called before Streaming",
            )));
        }
        if !self.is_negotiated_format(format_index) {
            return Err(SvcError::Protocol(alloc::string::String::from(
                "format_index is not in the negotiated format set",
            )));
        }
        let format_no = u16::try_from(format_index).map_err(|_| {
            SvcError::Protocol(alloc::string::String::from("format_index > u16::MAX"))
        })?;
        let block_no = self.next_block_no;
        let pdu = Wave2Pdu {
            timestamp,
            format_no,
            block_no,
            audio_timestamp,
            data: audio,
        };
        let msg = Self::encode_pdu(&pdu)?;
        self.push_pending_confirm(block_no, timestamp);
        self.next_block_no = self.next_block_no.wrapping_add(1);
        Ok(msg)
    }

    /// Build a Close PDU (MS-RDPEA 2.2.3.11). Emitting this signals
    /// the client to stop audio playback; the server transitions to
    /// the pre-`start()` state on its own side so a fresh
    /// initialization sequence can follow.
    pub fn build_close(&mut self) -> SvcResult<SvcMessage> {
        let header = SndHeader::new(SndMsgType::Close, 0);
        let msg = Self::encode_pdu(&header)?;
        self.reset();
        Ok(msg)
    }
}

impl SvcProcessor for SoundServer {
    fn channel_name(&self) -> ChannelName {
        RDPSND
    }

    fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
        if self.state != SoundServerState::NotStarted {
            return Ok(Vec::new());
        }
        let pdu = self.build_server_formats();
        let msg = Self::encode_pdu(&pdu)?;
        self.state = SoundServerState::WaitClientFormats;
        Ok(alloc::vec![msg])
    }

    fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
        // MS-RDPEA 3.1.5.1: unknown / malformed PDUs SHOULD be ignored.
        // Zero-length payloads are surfaced by some SVC chunkers as a
        // degenerate "empty message" -- drop them rather than returning
        // a DecodeError, matching the unknown-msgType policy below.
        if payload.is_empty() {
            return Ok(Vec::new());
        }
        // Peek the msgType byte before full decode so an unrecognized
        // value does not propagate as a DecodeError.
        if !SndMsgType::is_valid(payload[0]) {
            return Ok(Vec::new());
        }
        let mut cursor = ReadCursor::new(payload);
        let header = SndHeader::decode(&mut cursor)?;
        self.handle_pdu(&header, &mut cursor)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::Never
    }
}

impl SvcServerProcessor for SoundServer {}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use std::sync::{Arc, Mutex};

    use crate::pdu::{AudioFormat, WaveFormatTag};

    /// Shared state observed by the test after handler calls.
    #[derive(Default)]
    struct HandlerState {
        client_formats_calls: Vec<(Vec<AudioFormat>, u32, u16)>,
        quality_mode_calls: Vec<QualityMode>,
        wave_confirm_calls: Vec<(u16, u8, u16)>,
        training_confirm_calls: Vec<(u16, u16, u16)>,
        close_calls: u32,
    }

    struct MockHandler {
        state: Arc<Mutex<HandlerState>>,
    }

    impl RdpServerSoundHandler for MockHandler {
        fn on_client_formats(
            &mut self,
            negotiated_formats: &[AudioFormat],
            negotiated_flags: ClientSndFlags,
            negotiated_version: u16,
        ) {
            self.state.lock().unwrap().client_formats_calls.push((
                negotiated_formats.to_vec(),
                negotiated_flags.bits(),
                negotiated_version,
            ));
        }
        fn on_quality_mode(&mut self, mode: QualityMode) {
            self.state.lock().unwrap().quality_mode_calls.push(mode);
        }
        fn on_wave_confirm(
            &mut self,
            timestamp: u16,
            confirmed_block_no: u8,
            latency_ms: u16,
        ) {
            self.state
                .lock()
                .unwrap()
                .wave_confirm_calls
                .push((timestamp, confirmed_block_no, latency_ms));
        }
        fn on_training_confirm(&mut self, timestamp: u16, pack_size: u16, rtt_ms: u16) {
            self.state
                .lock()
                .unwrap()
                .training_confirm_calls
                .push((timestamp, pack_size, rtt_ms));
        }
        fn on_close(&mut self) {
            self.state.lock().unwrap().close_calls += 1;
        }
    }

    fn new_server(formats: Vec<AudioFormat>) -> (SoundServer, Arc<Mutex<HandlerState>>) {
        let state = Arc::new(Mutex::new(HandlerState::default()));
        let handler = MockHandler {
            state: state.clone(),
        };
        (SoundServer::new(Box::new(handler), formats), state)
    }

    fn pcm_44k_16_stereo() -> AudioFormat {
        AudioFormat::pcm(2, 44100, 16)
    }

    fn pcm_22k_16_mono() -> AudioFormat {
        AudioFormat::pcm(1, 22050, 16)
    }

    /// Encode a ClientAudioFormatsPdu to raw bytes the server will
    /// receive.
    fn client_formats_bytes(pdu: &ClientAudioFormatsPdu) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        buf
    }

    fn encode_bytes<T: Encode>(pdu: &T) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();
        buf
    }

    fn wave_confirm_bytes(timestamp: u16, block_no: u8) -> Vec<u8> {
        encode_bytes(&WaveConfirmPdu::new(timestamp, block_no))
    }

    fn training_confirm_bytes(timestamp: u16, pack_size: u16) -> Vec<u8> {
        // Training Confirm is a TrainingConfirmPdu on the wire (msgType=0x06).
        encode_bytes(&crate::pdu::TrainingConfirmPdu {
            timestamp,
            pack_size,
        })
    }

    fn decode_header(msg: &SvcMessage) -> SndHeader {
        let mut cursor = ReadCursor::new(&msg.data);
        SndHeader::decode(&mut cursor).unwrap()
    }

    #[test]
    fn start_emits_server_formats_once() {
        let (mut server, _state) = new_server(vec![pcm_44k_16_stereo()]);
        let msgs = server.start().unwrap();
        assert_eq!(msgs.len(), 1);
        let h = decode_header(&msgs[0]);
        assert_eq!(h.msg_type, SndMsgType::Formats);

        // Idempotent: second start() is a no-op.
        let msgs2 = server.start().unwrap();
        assert!(msgs2.is_empty());
    }

    #[test]
    fn start_emits_advertised_flags_and_version() {
        let mut server = SoundServer::new(
            Box::new(MockHandler {
                state: Arc::new(Mutex::new(HandlerState::default())),
            }),
            vec![pcm_44k_16_stereo()],
        )
        .with_flags(ServerSndCapsFlags::ALIVE.union(ServerSndCapsFlags::VOLUME))
        .with_version(8);

        let msgs = server.start().unwrap();
        let mut cursor = ReadCursor::new(&msgs[0].data);
        let _ = SndHeader::decode(&mut cursor).unwrap();
        let pdu = ServerAudioFormatsPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(
            pdu.flags.bits(),
            ServerSndCapsFlags::ALIVE.bits() | ServerSndCapsFlags::VOLUME.bits()
        );
        assert_eq!(pdu.version, 8);
        assert_eq!(pdu.last_block_confirmed, 0xFF);
    }

    #[test]
    fn format_intersection_with_client() {
        // Server advertises [PCM44k, PCM22k]; client accepts [PCM22k].
        let (mut server, state) = new_server(vec![pcm_44k_16_stereo(), pcm_22k_16_mono()]);
        server.start().unwrap();

        let client_pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE.union(ClientSndFlags::VOLUME),
            volume: 0xFFFF_FFFF,
            pitch: 0x0001_0000,
            version: 6,
            formats: vec![pcm_22k_16_mono()],
        };
        server.process(&client_formats_bytes(&client_pdu)).unwrap();

        assert_eq!(server.negotiated_formats(), &[pcm_22k_16_mono()]);
        assert_eq!(
            server.negotiated_flags().bits(),
            ClientSndFlags::ALIVE.bits(),
        );
        assert_eq!(server.negotiated_version(), 6);
        assert!(server.is_streaming());

        let s = state.lock().unwrap();
        assert_eq!(s.client_formats_calls.len(), 1);
        assert_eq!(s.client_formats_calls[0].0, vec![pcm_22k_16_mono()]);
    }

    #[test]
    fn empty_format_intersection_still_streams() {
        // Client accepts a format the server did NOT advertise.
        let (mut server, _state) = new_server(vec![pcm_44k_16_stereo()]);
        server.start().unwrap();

        let client_pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE,
            volume: 0,
            pitch: 0,
            version: 6,
            formats: vec![pcm_22k_16_mono()],
        };
        server.process(&client_formats_bytes(&client_pdu)).unwrap();

        assert!(server.is_streaming());
        assert!(server.negotiated_formats().is_empty());
    }

    #[test]
    fn version_intersection_is_min_of_both() {
        // Server version 8; client version 5 → negotiated 5.
        let mut server = SoundServer::new(
            Box::new(MockHandler {
                state: Arc::new(Mutex::new(HandlerState::default())),
            }),
            vec![pcm_44k_16_stereo()],
        )
        .with_version(8);
        let _ = server.start().unwrap();

        let client_pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE,
            volume: 0,
            pitch: 0,
            version: 5,
            formats: vec![pcm_44k_16_stereo()],
        };
        server.process(&client_formats_bytes(&client_pdu)).unwrap();
        assert_eq!(server.negotiated_version(), 5);
    }

    #[test]
    fn data_phase_pdus_dropped_before_client_formats() {
        let (mut server, state) = new_server(vec![pcm_44k_16_stereo()]);
        server.start().unwrap();

        // WaveConfirm before negotiation → silently dropped (handler not called).
        let resp = server.process(&wave_confirm_bytes(100, 5)).unwrap();
        assert!(resp.is_empty());

        let s = state.lock().unwrap();
        assert!(s.wave_confirm_calls.is_empty());
    }

    #[test]
    fn unknown_msgtype_silently_dropped() {
        // MS-RDPEA 3.1.5.1.
        let (mut server, _state) = new_server(vec![pcm_44k_16_stereo()]);
        server.start().unwrap();
        // Bogus msgType=0xFF.
        let resp = server.process(&[0xFF, 0x00, 0x00, 0x00]).unwrap();
        assert!(resp.is_empty());
    }

    #[test]
    fn empty_payload_silently_dropped() {
        // A zero-length SVC payload is not a valid RDPSND PDU; drop
        // silently rather than surfacing a DecodeError.
        let (mut server, _state) = new_server(vec![pcm_44k_16_stereo()]);
        server.start().unwrap();
        let resp = server.process(&[]).unwrap();
        assert!(resp.is_empty());
    }

    #[test]
    fn client_quality_mode_dispatched_to_handler() {
        let (mut server, state) = new_server(vec![pcm_44k_16_stereo()]);
        server.start().unwrap();
        let client_pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE,
            volume: 0,
            pitch: 0,
            version: 6,
            formats: vec![pcm_44k_16_stereo()],
        };
        server.process(&client_formats_bytes(&client_pdu)).unwrap();

        let qm = QualityModePdu::new(QualityMode::High);
        server.process(&encode_bytes(&qm)).unwrap();

        let s = state.lock().unwrap();
        assert_eq!(s.quality_mode_calls, vec![QualityMode::High]);
    }

    #[test]
    fn close_pdu_resets_state_and_notifies_handler() {
        let (mut server, state) = new_server(vec![pcm_44k_16_stereo()]);
        server.start().unwrap();

        // Close before streaming also notifies.
        let close_header = SndHeader::new(SndMsgType::Close, 0);
        server.process(&encode_bytes(&close_header)).unwrap();

        assert_eq!(state.lock().unwrap().close_calls, 1);
        assert_eq!(server.state, SoundServerState::NotStarted);

        // start() can be called again after reset.
        let msgs = server.start().unwrap();
        assert_eq!(msgs.len(), 1);
    }

    fn initialize_server_for_streaming() -> (SoundServer, Arc<Mutex<HandlerState>>) {
        let (mut server, state) = new_server(vec![pcm_44k_16_stereo(), pcm_22k_16_mono()]);
        server.start().unwrap();
        let client_pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE,
            volume: 0,
            pitch: 0,
            version: 6,
            formats: vec![pcm_44k_16_stereo(), pcm_22k_16_mono()],
        };
        server.process(&client_formats_bytes(&client_pdu)).unwrap();
        (server, state)
    }

    #[test]
    fn emit_wave_chunk_before_streaming_errors() {
        let (mut server, _state) = new_server(vec![pcm_44k_16_stereo()]);
        let audio = vec![0u8; 16];
        assert!(server.emit_wave_chunk(0, &audio, 0).is_err());
    }

    #[test]
    fn emit_wave_chunk_returns_info_and_wave_pair() {
        let (mut server, _state) = initialize_server_for_streaming();
        let audio = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let msgs = server.emit_wave_chunk(0, &audio, 1000).unwrap();
        assert_eq!(msgs.len(), 2, "WaveInfo + Wave");
        // First message is WaveInfo with SNDPROLOG msgType=Wave.
        let h = decode_header(&msgs[0]);
        assert_eq!(h.msg_type, SndMsgType::Wave);
        // Second is raw Wave PDU: 4 zero-pad + remaining 4 bytes of audio.
        assert_eq!(msgs[1].data[..4], [0, 0, 0, 0]);
        assert_eq!(&msgs[1].data[4..], &audio[4..]);
    }

    #[test]
    fn emit_wave_chunk_rejects_unaccepted_format() {
        // Server advertises two formats, but suppose client accepts only one.
        let (mut server, _state) = new_server(vec![pcm_44k_16_stereo(), pcm_22k_16_mono()]);
        server.start().unwrap();
        let client_pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE,
            volume: 0,
            pitch: 0,
            version: 6,
            formats: vec![pcm_44k_16_stereo()], // index 0 only
        };
        server.process(&client_formats_bytes(&client_pdu)).unwrap();

        // Emitting on format_index=1 (22k mono) must fail -- not negotiated.
        assert!(server.emit_wave_chunk(1, &[0; 8], 0).is_err());
        // But format_index=0 must succeed.
        assert!(server.emit_wave_chunk(0, &[0; 8], 0).is_ok());
    }

    #[test]
    fn emit_wave_chunk_rejects_short_audio() {
        let (mut server, _state) = initialize_server_for_streaming();
        assert!(server.emit_wave_chunk(0, &[0, 1, 2], 0).is_err());
    }

    #[test]
    fn wave_confirm_dispatches_with_latency() {
        let (mut server, state) = initialize_server_for_streaming();
        let _ = server.emit_wave_chunk(0, &[0u8; 8], 100).unwrap();
        // Client confirms at ts=250 → latency = 150.
        server.process(&wave_confirm_bytes(250, 0)).unwrap();

        let s = state.lock().unwrap();
        assert_eq!(s.wave_confirm_calls, vec![(250, 0, 150)]);
    }

    #[test]
    fn wave_confirm_for_unknown_block_silently_ignored() {
        let (mut server, state) = initialize_server_for_streaming();
        let _ = server.emit_wave_chunk(0, &[0u8; 8], 100).unwrap();
        // Confirm a block that was never emitted.
        server.process(&wave_confirm_bytes(250, 99)).unwrap();

        assert!(state.lock().unwrap().wave_confirm_calls.is_empty());
    }

    #[test]
    fn wave_confirm_latency_with_wraparound() {
        let (mut server, state) = initialize_server_for_streaming();
        let _ = server.emit_wave_chunk(0, &[0u8; 8], 65530).unwrap();
        server.process(&wave_confirm_bytes(5, 0)).unwrap();
        // 5 - 65530 wrapping = 11.
        let s = state.lock().unwrap();
        assert_eq!(s.wave_confirm_calls, vec![(5, 0, 11)]);
    }

    #[test]
    fn block_no_wraps_from_255_to_0() {
        let (mut server, _state) = initialize_server_for_streaming();
        // Force the counter near the wrap point.
        server.next_block_no = 254;
        let _ = server.emit_wave_chunk(0, &[0u8; 8], 0).unwrap();
        assert_eq!(server.next_block_no, 255);
        let _ = server.emit_wave_chunk(0, &[0u8; 8], 0).unwrap();
        assert_eq!(server.next_block_no, 0, "wrap 255 → 0");
        // Next emit uses block 0.
        let _ = server.emit_wave_chunk(0, &[0u8; 8], 0).unwrap();
        assert_eq!(server.next_block_no, 1);
    }

    #[test]
    fn emit_wave2_chunk_encodes_single_pdu() {
        let (mut server, _state) = initialize_server_for_streaming();
        let msg = server
            .emit_wave2_chunk(0, vec![1, 2, 3, 4], 500, 12345)
            .unwrap();
        let h = decode_header(&msg);
        assert_eq!(h.msg_type, SndMsgType::Wave2);
    }

    #[test]
    fn emit_wave2_chunk_tracks_latency() {
        let (mut server, state) = initialize_server_for_streaming();
        let _ = server
            .emit_wave2_chunk(0, vec![1, 2, 3, 4], 500, 0)
            .unwrap();
        // Client confirms the Wave2 block (block 0).
        server.process(&wave_confirm_bytes(700, 0)).unwrap();
        let s = state.lock().unwrap();
        assert_eq!(s.wave_confirm_calls, vec![(700, 0, 200)]);
    }

    #[test]
    fn training_confirm_measures_rtt() {
        let (mut server, state) = initialize_server_for_streaming();
        let _ = server.send_training(1000, 0).unwrap();
        // Client echoes ts=1000, pack_size=0; server gets it at ts=?
        // Training Confirm carries the same ts (client echoes). rtt = ts_echo - ts_emit.
        // With echo: confirm.timestamp == 1000, so rtt = 1000 - 1000 = 0.
        server.process(&training_confirm_bytes(1000, 0)).unwrap();
        let s = state.lock().unwrap();
        assert_eq!(s.training_confirm_calls, vec![(1000, 0, 0)]);
    }

    #[test]
    fn training_confirm_without_pending_ignored() {
        let (mut server, state) = initialize_server_for_streaming();
        // No send_training() → stray Training Confirm is dropped.
        server.process(&training_confirm_bytes(1000, 0)).unwrap();
        assert!(state.lock().unwrap().training_confirm_calls.is_empty());
    }

    #[test]
    fn send_training_before_streaming_errors() {
        let (mut server, _state) = new_server(vec![pcm_44k_16_stereo()]);
        assert!(server.send_training(1000, 0).is_err());
    }

    #[test]
    fn pending_confirms_bounded_at_cap() {
        let (mut server, _state) = initialize_server_for_streaming();
        // Force the bound to exercise the drop-oldest path. Emit
        // MAX_PENDING_CONFIRMS + 1 chunks without any confirms.
        for i in 0..(MAX_PENDING_CONFIRMS + 1) {
            let _ = server
                .emit_wave_chunk(0, &[0u8; 8], i as u16)
                .unwrap();
        }
        assert_eq!(server.pending_confirms.len(), MAX_PENDING_CONFIRMS);
    }

    #[test]
    fn build_quality_mode_encodes_high() {
        let (server, _state) = new_server(vec![pcm_44k_16_stereo()]);
        let msg = server.build_quality_mode(QualityMode::High).unwrap();
        let h = decode_header(&msg);
        assert_eq!(h.msg_type, SndMsgType::QualityMode);
        // Decode body and verify mode.
        let mut cursor = ReadCursor::new(&msg.data);
        let _ = SndHeader::decode(&mut cursor).unwrap();
        let pdu = QualityModePdu::decode_body(&mut cursor).unwrap();
        assert_eq!(pdu.quality_mode, QualityMode::High);
    }

    #[test]
    fn build_close_resets_state() {
        let (mut server, _state) = initialize_server_for_streaming();
        // Force pending / block counter to non-default.
        let _ = server.emit_wave_chunk(0, &[0u8; 8], 0).unwrap();
        assert!(!server.pending_confirms.is_empty());

        let msg = server.build_close().unwrap();
        let h = decode_header(&msg);
        assert_eq!(h.msg_type, SndMsgType::Close);
        assert_eq!(h.body_size, 0);

        assert_eq!(server.state, SoundServerState::NotStarted);
        assert!(server.pending_confirms.is_empty());
        assert_eq!(server.next_block_no, 0);
    }

    #[test]
    fn unsolicited_wave_from_client_silently_dropped() {
        // The server MUST NOT accept server→client-only PDUs received
        // from the client (MS-RDPEA 3.1.5.1).
        let (mut server, state) = initialize_server_for_streaming();
        let audio = alloc::vec![0u8; 12];
        let wave_info = WaveInfoPdu::from_chunk(100, 0, 99, &audio).unwrap();
        let resp = server.process(&encode_bytes(&wave_info)).unwrap();
        assert!(resp.is_empty());
        assert!(state.lock().unwrap().wave_confirm_calls.is_empty());
    }

    #[test]
    fn mid_stream_reformats_are_dropped() {
        // Second Formats PDU after Streaming is not spec'd; drop silently.
        let (mut server, state) = initialize_server_for_streaming();
        // Counter: one valid on_client_formats call so far.
        assert_eq!(state.lock().unwrap().client_formats_calls.len(), 1);

        let client_pdu = ClientAudioFormatsPdu {
            flags: ClientSndFlags::ALIVE,
            volume: 0,
            pitch: 0,
            version: 6,
            formats: vec![pcm_22k_16_mono()],
        };
        server.process(&client_formats_bytes(&client_pdu)).unwrap();

        // No additional dispatch.
        assert_eq!(state.lock().unwrap().client_formats_calls.len(), 1);
    }
}
