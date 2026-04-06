#![forbid(unsafe_code)]

//! RDPSND channel processor -- SVC integration.

use alloc::boxed::Box;
use alloc::vec::Vec;

use justrdp_core::AsAny;
use justrdp_svc::{
    ChannelName, CompressionCondition, SvcClientProcessor, SvcMessage, SvcProcessor, SvcResult,
    RDPSND,
};

use crate::backend::RdpsndBackend;
use crate::engine::{RdpsndCore, RdpsndError};

/// Client-side RDPSND processor (SVC transport).
pub struct RdpsndClient {
    core: RdpsndCore,
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
            .field("core", &self.core)
            .finish()
    }
}

impl RdpsndClient {
    /// Create a new RDPSND client processor (SVC mode, version 6).
    pub fn new(backend: Box<dyn RdpsndBackend>) -> Self {
        Self {
            core: RdpsndCore::new_svc(backend),
        }
    }
}

/// Convert `RdpsndError` to `SvcError`.
fn to_svc_error(e: RdpsndError) -> justrdp_svc::SvcError {
    match e {
        RdpsndError::Decode(d) => justrdp_svc::SvcError::Decode(d),
        RdpsndError::Encode(e) => justrdp_svc::SvcError::Encode(e),
        RdpsndError::Protocol(s) => justrdp_svc::SvcError::Protocol(s),
    }
}

/// Wrap raw byte buffers into `SvcMessage`s.
fn to_svc_messages(bufs: Vec<Vec<u8>>) -> Vec<SvcMessage> {
    bufs.into_iter().map(SvcMessage::new).collect()
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
        self.core
            .handle_pdu(payload)
            .map(to_svc_messages)
            .map_err(to_svc_error)
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }
}

impl SvcClientProcessor for RdpsndClient {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};

    use crate::pdu::{AudioFormat, SndHeader, SndMsgType, Wave2Pdu, WaveConfirmPdu};

    struct MockBackend;

    impl crate::backend::RdpsndBackend for MockBackend {
        fn on_server_formats(&mut self, server_formats: &[AudioFormat]) -> Vec<usize> {
            (0..server_formats.len()).collect()
        }
        fn on_wave_data(&mut self, _: u16, _: &[u8], _: Option<u32>) {}
        fn on_volume(&mut self, _: &crate::pdu::VolumePdu) {}
        fn on_close(&mut self) {}
    }

    fn build_server_formats(ver: u16) -> Vec<u8> {
        let pcm = AudioFormat::pcm(2, 44100, 16);
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(0xFF);
        body.extend_from_slice(&ver.to_le_bytes());
        body.push(0x00);
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

    #[test]
    fn svc_client_full_init_sequence() {
        let mut client = RdpsndClient::new(Box::new(MockBackend));
        client.start().unwrap();

        // Server sends Formats (version 6).
        let responses = client.process(&build_server_formats(6)).unwrap();
        assert_eq!(responses.len(), 2, "expected ClientFormats + QualityMode");

        // Verify client advertises version 6 (SVC mode).
        let body_start = &responses[0].data[4..];
        let version_offset = 4 + 4 + 4 + 2 + 2 + 1; // 17
        let version =
            u16::from_le_bytes([body_start[version_offset], body_start[version_offset + 1]]);
        assert_eq!(version, 0x0006, "SVC client should advertise version 6");

        // Server sends Training.
        let responses = client.process(&build_training(42)).unwrap();
        assert_eq!(responses.len(), 1);
        let mut cursor = ReadCursor::new(&responses[0].data);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::Training);

        // Server sends Wave2.
        let wave2 = Wave2Pdu {
            timestamp: 100,
            format_no: 0,
            block_no: 7,
            audio_timestamp: 5000,
            data: vec![0x01, 0x02],
        };
        let mut buf = vec![0u8; wave2.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        wave2.encode(&mut cursor).unwrap();
        let responses = client.process(&buf).unwrap();
        assert_eq!(responses.len(), 1);
        let mut cursor = ReadCursor::new(&responses[0].data);
        let header = SndHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.msg_type, SndMsgType::WaveConfirm);
        let wc = WaveConfirmPdu::decode_body(&mut cursor).unwrap();
        assert_eq!(wc.timestamp, 100);
        assert_eq!(wc.confirmed_block_no, 7);
    }

    #[test]
    fn svc_no_quality_mode_when_server_version_below_6() {
        let mut client = RdpsndClient::new(Box::new(MockBackend));
        client.start().unwrap();

        // Server sends Formats with version 5 (< 6).
        let responses = client.process(&build_server_formats(5)).unwrap();
        // Should only get ClientFormats, no QualityMode.
        assert_eq!(responses.len(), 1, "no QualityMode when server version < 6");
    }
}
