#![forbid(unsafe_code)]

//! RDPSND channel processor -- DVC integration.
//!
//! `RdpsndDvcClient` handles `AUDIO_PLAYBACK_DVC` (reliable DVC).
//! `RdpsndLossyDvcClient` handles `AUDIO_PLAYBACK_LOSSY_DVC` (lossy DVC over UDP multitransport).

use alloc::boxed::Box;
use alloc::vec::Vec;

use justrdp_core::AsAny;
use justrdp_dvc::{DvcError, DvcMessage, DvcProcessor, DvcResult};

use crate::backend::RdpsndBackend;
use crate::engine::{RdpsndCore, RdpsndError};

/// DVC channel name for reliable audio playback -- MS-RDPEA 2.1
const AUDIO_PLAYBACK_DVC_NAME: &str = "AUDIO_PLAYBACK_DVC";

/// DVC channel name for lossy audio playback -- MS-RDPEA 2.1
const AUDIO_PLAYBACK_LOSSY_DVC_NAME: &str = "AUDIO_PLAYBACK_LOSSY_DVC";

/// Convert `RdpsndError` to `DvcError`.
fn to_dvc_error(e: RdpsndError) -> DvcError {
    match e {
        RdpsndError::Decode(d) => DvcError::Decode(d),
        RdpsndError::Encode(e) => DvcError::Encode(e),
        RdpsndError::Protocol(s) => DvcError::Protocol(s),
    }
}

/// Wrap raw byte buffers into `DvcMessage`s.
fn to_dvc_messages(bufs: Vec<Vec<u8>>) -> Vec<DvcMessage> {
    bufs.into_iter().map(DvcMessage::new).collect()
}

// ── RdpsndDvcClient (reliable) ──

/// Client-side RDPSND processor for reliable DVC transport (`AUDIO_PLAYBACK_DVC`).
///
/// Windows 8+ servers prefer DVC over SVC for audio. If this processor is
/// registered with `DrdynvcClient`, the server will use DVC; otherwise it
/// falls back to the SVC `"rdpsnd"` channel.
pub struct RdpsndDvcClient {
    core: RdpsndCore,
}

impl AsAny for RdpsndDvcClient {
    fn as_any(&self) -> &dyn ::core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn ::core::any::Any {
        self
    }
}

impl ::core::fmt::Debug for RdpsndDvcClient {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.debug_struct("RdpsndDvcClient")
            .field("core", &self.core)
            .finish()
    }
}

impl RdpsndDvcClient {
    /// Create a new RDPSND DVC client (reliable, version 8).
    pub fn new(backend: Box<dyn RdpsndBackend>) -> Self {
        Self {
            core: RdpsndCore::new_dvc(backend),
        }
    }
}

impl DvcProcessor for RdpsndDvcClient {
    fn channel_name(&self) -> &str {
        AUDIO_PLAYBACK_DVC_NAME
    }

    fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // Server speaks first (sends Audio Formats PDU).
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        self.core
            .handle_pdu(payload)
            .map(to_dvc_messages)
            .map_err(to_dvc_error)
    }

    fn close(&mut self, _channel_id: u32) {
        self.core.reset();
    }
}

// ── RdpsndLossyDvcClient (lossy/UDP) ──

/// Client-side RDPSND processor for lossy DVC transport (`AUDIO_PLAYBACK_LOSSY_DVC`).
///
/// Used when UDP multitransport (MS-RDPEMT) is available and both sides
/// support version >= 8. Tolerates packet loss by recovering from orphaned
/// `WaitWaveData` state.
pub struct RdpsndLossyDvcClient {
    core: RdpsndCore,
}

impl AsAny for RdpsndLossyDvcClient {
    fn as_any(&self) -> &dyn ::core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn ::core::any::Any {
        self
    }
}

impl ::core::fmt::Debug for RdpsndLossyDvcClient {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.debug_struct("RdpsndLossyDvcClient")
            .field("core", &self.core)
            .finish()
    }
}

impl RdpsndLossyDvcClient {
    /// Create a new RDPSND lossy DVC client (UDP multitransport, version 8).
    pub fn new(backend: Box<dyn RdpsndBackend>) -> Self {
        Self {
            core: RdpsndCore::new_dvc(backend),
        }
    }
}

impl DvcProcessor for RdpsndLossyDvcClient {
    fn channel_name(&self) -> &str {
        AUDIO_PLAYBACK_LOSSY_DVC_NAME
    }

    fn start(&mut self, _channel_id: u32) -> DvcResult<Vec<DvcMessage>> {
        // Server speaks first.
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> DvcResult<Vec<DvcMessage>> {
        // Use lossy-aware handler that recovers from dropped Wave PDUs.
        self.core
            .handle_pdu_lossy(payload)
            .map(to_dvc_messages)
            .map_err(to_dvc_error)
    }

    fn close(&mut self, _channel_id: u32) {
        self.core.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};

    use crate::pdu::{AudioFormat, SndHeader, SndMsgType, Wave2Pdu, WaveConfirmPdu};

    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    /// Mock backend that accepts all server formats and counts wave data calls.
    struct MockBackend {
        wave_count: Arc<AtomicU32>,
        closed: bool,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                wave_count: Arc::new(AtomicU32::new(0)),
                closed: false,
            }
        }

        fn wave_count_handle(&self) -> Arc<AtomicU32> {
            Arc::clone(&self.wave_count)
        }
    }

    impl RdpsndBackend for MockBackend {
        fn on_server_formats(&mut self, server_formats: &[AudioFormat]) -> Vec<usize> {
            (0..server_formats.len()).collect()
        }

        fn on_wave_data(&mut self, _format_no: u16, _data: &[u8], _audio_ts: Option<u32>) {
            self.wave_count.fetch_add(1, Ordering::Relaxed);
        }

        fn on_volume(&mut self, _volume: &crate::pdu::VolumePdu) {}

        fn on_close(&mut self) {
            self.closed = true;
        }
    }

    /// Build a minimal ServerAudioFormatsPdu wire bytes with one PCM format.
    fn build_server_formats(ver: u16) -> Vec<u8> {
        let pcm = AudioFormat::pcm(2, 44100, 16);
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // dwFlags
        body.extend_from_slice(&0u32.to_le_bytes()); // dwVolume
        body.extend_from_slice(&0u32.to_le_bytes()); // dwPitch
        body.extend_from_slice(&0u16.to_le_bytes()); // wDGramPort
        body.extend_from_slice(&1u16.to_le_bytes()); // wNumberOfFormats = 1
        body.push(0xFF);                             // cLastBlockConfirmed
        body.extend_from_slice(&ver.to_le_bytes());  // wVersion
        body.push(0x00);                             // bPad
        let mut fmt_buf = vec![0u8; pcm.size()];
        let mut cursor = WriteCursor::new(&mut fmt_buf);
        pcm.encode(&mut cursor).unwrap();
        body.extend_from_slice(&fmt_buf);

        let body_size = body.len() as u16;
        let mut pdu = Vec::new();
        pdu.push(SndMsgType::Formats as u8);
        pdu.push(0x00);
        pdu.extend_from_slice(&body_size.to_le_bytes());
        pdu.extend_from_slice(&body);
        pdu
    }

    fn build_training(timestamp: u16) -> Vec<u8> {
        let mut pdu = Vec::new();
        pdu.push(SndMsgType::Training as u8);
        pdu.push(0x00);
        pdu.extend_from_slice(&4u16.to_le_bytes());
        pdu.extend_from_slice(&timestamp.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu
    }

    fn build_wave2(timestamp: u16, format_no: u16, block_no: u8, audio_data: &[u8]) -> Vec<u8> {
        let wave2 = Wave2Pdu {
            timestamp,
            format_no,
            block_no,
            audio_timestamp: 12345,
            data: audio_data.to_vec(),
        };
        let mut buf = vec![0u8; wave2.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        wave2.encode(&mut cursor).unwrap();
        buf
    }

    fn build_close() -> Vec<u8> {
        vec![SndMsgType::Close as u8, 0x00, 0x00, 0x00]
    }

    fn build_wave_info(timestamp: u16, format_no: u16, block_no: u8) -> Vec<u8> {
        let mut pdu = Vec::new();
        pdu.push(SndMsgType::Wave as u8);
        pdu.push(0x00);
        pdu.extend_from_slice(&12u16.to_le_bytes()); // body_size
        pdu.extend_from_slice(&timestamp.to_le_bytes());
        pdu.extend_from_slice(&format_no.to_le_bytes());
        pdu.push(block_no);
        pdu.extend_from_slice(&[0x00, 0x00, 0x00]);
        pdu.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        pdu
    }

    fn build_wave_data() -> Vec<u8> {
        vec![0x00, 0x00, 0x00, 0x00, 0xEE, 0xFF, 0x11, 0x22]
    }

    // ── Channel name tests ──

    #[test]
    fn dvc_client_channel_name() {
        let client = RdpsndDvcClient::new(Box::new(MockBackend::new()));
        assert_eq!(client.channel_name(), "AUDIO_PLAYBACK_DVC");
    }

    #[test]
    fn lossy_dvc_client_channel_name() {
        let client = RdpsndLossyDvcClient::new(Box::new(MockBackend::new()));
        assert_eq!(client.channel_name(), "AUDIO_PLAYBACK_LOSSY_DVC");
    }

    // ── Start tests ──

    #[test]
    fn dvc_client_start_returns_empty() {
        let mut client = RdpsndDvcClient::new(Box::new(MockBackend::new()));
        let msgs = client.start(42).unwrap();
        assert!(msgs.is_empty(), "server speaks first");
    }

    #[test]
    fn lossy_dvc_client_start_returns_empty() {
        let mut client = RdpsndLossyDvcClient::new(Box::new(MockBackend::new()));
        let msgs = client.start(99).unwrap();
        assert!(msgs.is_empty());
    }

    // ── Full init sequence (reliable DVC) ──

    #[test]
    fn dvc_client_full_init_sequence() {
        let mut client = RdpsndDvcClient::new(Box::new(MockBackend::new()));
        client.start(1).unwrap();

        // 1. Server sends Formats (version 8).
        let server_formats = build_server_formats(8);
        let responses = client.process(1, &server_formats).unwrap();
        assert_eq!(responses.len(), 2, "expected ClientFormats + QualityMode");

        // Verify client advertises version 8.
        let client_fmt_bytes = &responses[0].data;
        let body_start = &client_fmt_bytes[4..];
        let version_offset = 4 + 4 + 4 + 2 + 2 + 1; // 17
        let version =
            u16::from_le_bytes([body_start[version_offset], body_start[version_offset + 1]]);
        assert_eq!(version, 0x0008, "DVC client should advertise version 8");

        // Verify QualityMode PDU.
        let quality_bytes = &responses[1].data;
        let mut cursor = ReadCursor::new(quality_bytes);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::QualityMode);

        // 2. Server sends Training.
        let training = build_training(100);
        let responses = client.process(1, &training).unwrap();
        assert_eq!(responses.len(), 1);
        let mut cursor = ReadCursor::new(&responses[0].data);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::Training);

        // 3. Server sends Wave2.
        let wave2 = build_wave2(200, 0, 1, &[0x10, 0x20, 0x30]);
        let responses = client.process(1, &wave2).unwrap();
        assert_eq!(responses.len(), 1);
        let mut cursor = ReadCursor::new(&responses[0].data);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::WaveConfirm);
        let wc = WaveConfirmPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(wc.timestamp, 200);
        assert_eq!(wc.confirmed_block_no, 1);
    }

    // ── Close resets state ──

    #[test]
    fn dvc_client_close_resets_state() {
        let mut client = RdpsndDvcClient::new(Box::new(MockBackend::new()));
        client.start(1).unwrap();

        let formats = build_server_formats(8);
        client.process(1, &formats).unwrap();
        let training = build_training(0);
        client.process(1, &training).unwrap();

        client.close(1);

        // Re-init after close.
        client.start(1).unwrap();
        let formats2 = build_server_formats(8);
        let responses = client.process(1, &formats2).unwrap();
        assert_eq!(responses.len(), 2, "re-init after close should work");
    }

    // ── SndMsgType::Close PDU also resets ──

    #[test]
    fn dvc_close_pdu_resets_state() {
        let mut client = RdpsndDvcClient::new(Box::new(MockBackend::new()));
        client.start(1).unwrap();

        let formats = build_server_formats(8);
        client.process(1, &formats).unwrap();
        let training = build_training(0);
        client.process(1, &training).unwrap();

        let close = build_close();
        let responses = client.process(1, &close).unwrap();
        assert!(responses.is_empty());

        // Re-init should work.
        let formats2 = build_server_formats(8);
        let responses = client.process(1, &formats2).unwrap();
        assert_eq!(responses.len(), 2);
    }

    // ── Lossy: orphaned WaveInfo recovery ──

    #[test]
    fn lossy_dvc_orphaned_wave_info_recovery() {
        let backend = MockBackend::new();
        let wave_count = backend.wave_count_handle();
        let mut client = RdpsndLossyDvcClient::new(Box::new(backend));
        client.start(1).unwrap();

        let formats = build_server_formats(8);
        client.process(1, &formats).unwrap();
        let training = build_training(0);
        client.process(1, &training).unwrap();

        // WaveInfo -> enters WaitWaveData.
        let wave_info = build_wave_info(100, 0, 1);
        let responses = client.process(1, &wave_info).unwrap();
        assert!(responses.is_empty());
        assert_eq!(wave_count.load(Ordering::Relaxed), 0, "orphaned wave should not deliver audio");

        // Packet loss: Wave never arrives. New Wave2 arrives instead.
        let wave2 = build_wave2(200, 0, 2, &[0xAA, 0xBB]);
        let responses = client.process(1, &wave2).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(wave_count.load(Ordering::Relaxed), 1, "only Wave2 audio should be delivered");
        let mut cursor = ReadCursor::new(&responses[0].data);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::WaveConfirm);
        let wc = WaveConfirmPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(wc.confirmed_block_no, 2);
    }

    // ── Reliable DVC: WaveInfo + Wave pair ──

    #[test]
    fn reliable_dvc_wave_info_then_wave() {
        let mut client = RdpsndDvcClient::new(Box::new(MockBackend::new()));
        client.start(1).unwrap();

        let formats = build_server_formats(8);
        client.process(1, &formats).unwrap();
        let training = build_training(0);
        client.process(1, &training).unwrap();

        let wave_info = build_wave_info(300, 0, 5);
        let responses = client.process(1, &wave_info).unwrap();
        assert!(responses.is_empty());

        let wave_data = build_wave_data();
        let responses = client.process(1, &wave_data).unwrap();
        assert_eq!(responses.len(), 1);
        let mut cursor = ReadCursor::new(&responses[0].data);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::WaveConfirm);
        let wc = WaveConfirmPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(wc.timestamp, 300);
        assert_eq!(wc.confirmed_block_no, 5);
    }

    // ── Reliable DVC: Training in WaitWaveData recovers ──

    #[test]
    fn reliable_dvc_training_in_wait_wave_data_recovers() {
        let backend = MockBackend::new();
        let wave_count = backend.wave_count_handle();
        let mut client = RdpsndDvcClient::new(Box::new(backend));
        client.start(1).unwrap();

        let formats = build_server_formats(8);
        client.process(1, &formats).unwrap();
        let training = build_training(0);
        client.process(1, &training).unwrap();

        // Enter WaitWaveData.
        let wave_info = build_wave_info(100, 0, 1);
        let responses = client.process(1, &wave_info).unwrap();
        assert!(responses.is_empty());

        // Server sends Training instead of Wave data (protocol re-sync).
        let training2 = build_training(200);
        let responses = client.process(1, &training2).unwrap();
        // Should recover: discard orphaned wave info, handle Training normally.
        assert_eq!(responses.len(), 1);
        let mut cursor = ReadCursor::new(&responses[0].data);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::Training);
        assert_eq!(wave_count.load(Ordering::Relaxed), 0, "orphaned wave should not deliver audio");

        // Subsequent Wave2 should work (state is Active).
        let wave2 = build_wave2(300, 0, 2, &[0xAA]);
        let responses = client.process(1, &wave2).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(wave_count.load(Ordering::Relaxed), 1);
    }

    // ── Training ignored in WaitServerFormats ──

    #[test]
    fn training_ignored_in_wait_server_formats() {
        let mut client = RdpsndDvcClient::new(Box::new(MockBackend::new()));
        client.start(1).unwrap();

        // Send Training before any Formats PDU.
        let training = build_training(42);
        let responses = client.process(1, &training).unwrap();
        assert!(responses.is_empty(), "Training in WaitServerFormats should be ignored");

        // Formats should still work (state unchanged).
        let formats = build_server_formats(8);
        let responses = client.process(1, &formats).unwrap();
        assert_eq!(responses.len(), 2, "full init should still work after ignored Training");
    }

    // ── SVC and DVC produce identical QualityMode bytes ──

    #[test]
    fn svc_and_dvc_identical_quality_mode_bytes() {
        use crate::processor::RdpsndClient;
        use justrdp_svc::SvcProcessor;

        let mut svc = RdpsndClient::new(Box::new(MockBackend::new()));
        svc.start().unwrap();
        let svc_responses = svc.process(&build_server_formats(6)).unwrap();

        let mut dvc = RdpsndDvcClient::new(Box::new(MockBackend::new()));
        dvc.start(1).unwrap();
        let dvc_responses = dvc.process(1, &build_server_formats(8)).unwrap();

        assert_eq!(svc_responses.len(), 2);
        assert_eq!(dvc_responses.len(), 2);

        // QualityMode PDU bytes should be identical.
        assert_eq!(svc_responses[1].data, dvc_responses[1].data);

        // ClientFormats headers should match (same type and body size).
        let mut svc_cursor = ReadCursor::new(&svc_responses[0].data);
        let svc_header = SndHeader::decode(&mut svc_cursor).unwrap();
        let mut dvc_cursor = ReadCursor::new(&dvc_responses[0].data);
        let dvc_header = SndHeader::decode(&mut dvc_cursor).unwrap();
        assert_eq!(svc_header.msg_type, dvc_header.msg_type);
        assert_eq!(svc_header.body_size, dvc_header.body_size);
    }
}
