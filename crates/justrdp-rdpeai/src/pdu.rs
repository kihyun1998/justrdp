#![forbid(unsafe_code)]

//! Audio Input PDU types -- MS-RDPEAI 2.2

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor};
use justrdp_rdpsnd::pdu::AudioFormat;

// =============================================================================
// Constants -- MS-RDPEAI 2.2.1
// =============================================================================

/// MessageId for Version PDU.
/// MS-RDPEAI 2.2.2.1
pub const MSG_SNDIN_VERSION: u8 = 0x01;

/// MessageId for Sound Formats PDU.
/// MS-RDPEAI 2.2.2.2
pub const MSG_SNDIN_FORMATS: u8 = 0x02;

/// MessageId for Open PDU.
/// MS-RDPEAI 2.2.2.3
pub const MSG_SNDIN_OPEN: u8 = 0x03;

/// MessageId for Open Reply PDU.
/// MS-RDPEAI 2.2.2.4
pub const MSG_SNDIN_OPEN_REPLY: u8 = 0x04;

/// MessageId for Incoming Data PDU.
/// MS-RDPEAI 2.2.3.1
pub const MSG_SNDIN_DATA_INCOMING: u8 = 0x05;

/// MessageId for Data PDU.
/// MS-RDPEAI 2.2.3.2
pub const MSG_SNDIN_DATA: u8 = 0x06;

/// MessageId for Format Change PDU.
/// MS-RDPEAI 2.2.4.1
pub const MSG_SNDIN_FORMATCHANGE: u8 = 0x07;

/// Protocol version 1.
/// MS-RDPEAI 2.2.2.1
pub const SNDIN_VERSION_1: u32 = 0x0000_0001;

/// Protocol version 2 (unlocks AAC format change).
/// MS-RDPEAI 2.2.2.1
pub const SNDIN_VERSION_2: u32 = 0x0000_0002;

/// Maximum number of audio formats we accept (DoS guard).
pub const MAX_NUM_FORMATS: u32 = 256;

// =============================================================================
// VersionPdu -- MS-RDPEAI 2.2.2.1
// =============================================================================

/// Version PDU (bidirectional).
///
/// MS-RDPEAI 2.2.2.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPdu {
    pub version: u32,
}

impl VersionPdu {
    /// Wire size: 1 (header) + 4 (version) = 5 bytes.
    pub const WIRE_SIZE: usize = 5;
}

impl Encode for VersionPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(MSG_SNDIN_VERSION, "VersionPdu::Header")?;
        dst.write_u32_le(self.version, "VersionPdu::Version")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "VersionPdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for VersionPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("VersionPdu::Header")?;
        if header != MSG_SNDIN_VERSION {
            return Err(DecodeError::unexpected_value(
                "VersionPdu",
                "Header",
                "expected MSG_SNDIN_VERSION (0x01)",
            ));
        }
        let version = src.read_u32_le("VersionPdu::Version")?;
        if !matches!(version, SNDIN_VERSION_1 | SNDIN_VERSION_2) {
            return Err(DecodeError::unexpected_value(
                "VersionPdu",
                "Version",
                "expected 0x00000001 or 0x00000002",
            ));
        }
        Ok(Self { version })
    }
}

// =============================================================================
// SoundFormatsPdu -- MS-RDPEAI 2.2.2.2
// =============================================================================

/// Sound Formats PDU (bidirectional).
///
/// MS-RDPEAI 2.2.2.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoundFormatsPdu {
    /// Number of audio formats.
    pub formats: Vec<AudioFormat>,
    /// `cbSizeFormatsPacket` — arbitrary from server, computed by client.
    pub cb_size_formats_packet: u32,
}

impl SoundFormatsPdu {
    /// Compute the correct `cbSizeFormatsPacket` value for a client response.
    /// = 1 (header) + 4 (NumFormats) + 4 (cbSizeFormatsPacket) + sum of format wire sizes.
    ///
    /// With MAX_NUM_FORMATS=256 and `AudioFormat`'s internal extra-data cap of 256 bytes,
    /// the maximum value is 9 + 256*(18+256) = 70_153, well within u32.
    pub fn compute_cb_size(&self) -> u32 {
        let formats_total: usize = self.formats.iter().map(|f| f.size()).sum();
        // Safe: bounded by MAX_NUM_FORMATS * (AudioFormat fixed 18 + extra_data cap 256) < u32::MAX
        u32::try_from(9usize + formats_total).expect("cbSizeFormatsPacket overflows u32")
    }

    /// Decode from raw DVC payload.
    ///
    /// The `cbSizeFormatsPacket` field is stored as-is; when received from the
    /// server it carries an arbitrary value and MUST be ignored (MS-RDPEAI 2.2.2.2).
    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);

        let header = src.read_u8("SoundFormatsPdu::Header")?;
        if header != MSG_SNDIN_FORMATS {
            return Err(DecodeError::unexpected_value(
                "SoundFormatsPdu",
                "Header",
                "expected MSG_SNDIN_FORMATS (0x02)",
            ));
        }

        let num_formats = src.read_u32_le("SoundFormatsPdu::NumFormats")?;
        if num_formats > MAX_NUM_FORMATS {
            return Err(DecodeError::unexpected_value(
                "SoundFormatsPdu",
                "NumFormats",
                "exceeds maximum (256)",
            ));
        }

        let cb_size_formats_packet = src.read_u32_le("SoundFormatsPdu::cbSizeFormatsPacket")?;

        let mut formats = Vec::with_capacity(num_formats as usize);
        for _ in 0..num_formats {
            formats.push(AudioFormat::decode(&mut src)?);
        }

        Ok(Self {
            formats,
            cb_size_formats_packet,
        })
    }
}

impl Encode for SoundFormatsPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let num_formats = u32::try_from(self.formats.len())
            .map_err(|_| EncodeError::invalid_value("SoundFormatsPdu", "NumFormats exceeds u32"))?;

        dst.write_u8(MSG_SNDIN_FORMATS, "SoundFormatsPdu::Header")?;
        dst.write_u32_le(num_formats, "SoundFormatsPdu::NumFormats")?;
        dst.write_u32_le(self.cb_size_formats_packet, "SoundFormatsPdu::cbSizeFormatsPacket")?;

        for fmt in &self.formats {
            fmt.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "SoundFormatsPdu"
    }

    fn size(&self) -> usize {
        self.compute_cb_size() as usize
    }
}

// =============================================================================
// OpenPdu -- MS-RDPEAI 2.2.2.3 (server → client, decode only)
// =============================================================================

/// Open PDU sent by the server to start audio capture.
///
/// MS-RDPEAI 2.2.2.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPdu {
    /// Number of frames the client MUST send per Data PDU.
    pub frames_per_packet: u32,
    /// Zero-based index into the negotiated format list.
    pub initial_format: u32,
    /// Capture device audio format.
    pub capture_format: AudioFormat,
}

impl OpenPdu {
    /// Minimum wire size: 1 (header) + 4 + 4 + 18 (AudioFormat fixed) = 27 bytes.
    pub const MIN_WIRE_SIZE: usize = 27;

    /// Decode from raw DVC payload.
    pub fn decode_from(payload: &[u8]) -> DecodeResult<Self> {
        let mut src = ReadCursor::new(payload);

        let header = src.read_u8("OpenPdu::Header")?;
        if header != MSG_SNDIN_OPEN {
            return Err(DecodeError::unexpected_value(
                "OpenPdu",
                "Header",
                "expected MSG_SNDIN_OPEN (0x03)",
            ));
        }

        let frames_per_packet = src.read_u32_le("OpenPdu::FramesPerPacket")?;
        if frames_per_packet == 0 {
            return Err(DecodeError::unexpected_value(
                "OpenPdu",
                "FramesPerPacket",
                "must be non-zero",
            ));
        }

        let initial_format = src.read_u32_le("OpenPdu::initialFormat")?;
        let capture_format = AudioFormat::decode(&mut src)?;

        Ok(Self {
            frames_per_packet,
            initial_format,
            capture_format,
        })
    }
}

// =============================================================================
// OpenReplyPdu -- MS-RDPEAI 2.2.2.4 (client → server)
// =============================================================================

/// Open Reply PDU sent by the client.
///
/// MS-RDPEAI 2.2.2.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReplyPdu {
    /// HRESULT: 0x00000000 = success, non-zero = failure.
    pub result: u32,
}

impl OpenReplyPdu {
    /// Wire size: 1 (header) + 4 (Result) = 5 bytes.
    pub const WIRE_SIZE: usize = 5;

    /// HRESULT S_OK — success.
    pub const S_OK: u32 = 0x0000_0000;

    /// HRESULT E_FAIL — generic failure (MS-ERREF 2.1).
    pub const E_FAIL: u32 = 0x8000_4005;
}

impl Encode for OpenReplyPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(MSG_SNDIN_OPEN_REPLY, "OpenReplyPdu::Header")?;
        dst.write_u32_le(self.result, "OpenReplyPdu::Result")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "OpenReplyPdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for OpenReplyPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("OpenReplyPdu::Header")?;
        if header != MSG_SNDIN_OPEN_REPLY {
            return Err(DecodeError::unexpected_value(
                "OpenReplyPdu",
                "Header",
                "expected MSG_SNDIN_OPEN_REPLY (0x04)",
            ));
        }
        let result = src.read_u32_le("OpenReplyPdu::Result")?;
        Ok(Self { result })
    }
}

// =============================================================================
// IncomingDataPdu -- MS-RDPEAI 2.2.3.1 (client → server)
// =============================================================================

/// Incoming Data PDU — sent immediately before each Data PDU.
///
/// MS-RDPEAI 2.2.3.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingDataPdu;

impl IncomingDataPdu {
    /// Wire size: 1 byte (header only).
    pub const WIRE_SIZE: usize = 1;
}

impl Encode for IncomingDataPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(MSG_SNDIN_DATA_INCOMING, "IncomingDataPdu::Header")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "IncomingDataPdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for IncomingDataPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("IncomingDataPdu::Header")?;
        if header != MSG_SNDIN_DATA_INCOMING {
            return Err(DecodeError::unexpected_value(
                "IncomingDataPdu",
                "Header",
                "expected MSG_SNDIN_DATA_INCOMING (0x05)",
            ));
        }
        Ok(Self)
    }
}

// =============================================================================
// DataPdu -- MS-RDPEAI 2.2.3.2 (client → server)
// =============================================================================

/// Data PDU carrying captured audio samples.
///
/// MS-RDPEAI 2.2.3.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPdu {
    /// Audio data encoded in the current format.
    pub data: Vec<u8>,
}

impl Encode for DataPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(MSG_SNDIN_DATA, "DataPdu::Header")?;
        dst.write_slice(&self.data, "DataPdu::Data")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DataPdu"
    }

    fn size(&self) -> usize {
        1 + self.data.len()
    }
}

impl<'de> Decode<'de> for DataPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("DataPdu::Header")?;
        if header != MSG_SNDIN_DATA {
            return Err(DecodeError::unexpected_value(
                "DataPdu",
                "Header",
                "expected MSG_SNDIN_DATA (0x06)",
            ));
        }
        let remaining = src.remaining();
        let data = src.read_slice(remaining, "DataPdu::Data")?.to_vec();
        Ok(Self { data })
    }
}

// =============================================================================
// FormatChangePdu -- MS-RDPEAI 2.2.4.1 (bidirectional)
// =============================================================================

/// Format Change PDU.
///
/// MS-RDPEAI 2.2.4.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatChangePdu {
    /// Zero-based index into the negotiated format list.
    pub new_format: u32,
}

impl FormatChangePdu {
    /// Wire size: 1 (header) + 4 (NewFormat) = 5 bytes.
    pub const WIRE_SIZE: usize = 5;
}

impl Encode for FormatChangePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8(MSG_SNDIN_FORMATCHANGE, "FormatChangePdu::Header")?;
        dst.write_u32_le(self.new_format, "FormatChangePdu::NewFormat")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FormatChangePdu"
    }

    fn size(&self) -> usize {
        Self::WIRE_SIZE
    }
}

impl<'de> Decode<'de> for FormatChangePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let header = src.read_u8("FormatChangePdu::Header")?;
        if header != MSG_SNDIN_FORMATCHANGE {
            return Err(DecodeError::unexpected_value(
                "FormatChangePdu",
                "Header",
                "expected MSG_SNDIN_FORMATCHANGE (0x07)",
            ));
        }
        let new_format = src.read_u32_le("FormatChangePdu::NewFormat")?;
        Ok(Self { new_format })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_rdpsnd::pdu::WaveFormatTag;

    // ── VersionPdu ──

    #[test]
    fn version_v1_roundtrip() {
        let pdu = VersionPdu { version: SNDIN_VERSION_1 };
        let mut buf = [0u8; 5];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(buf, [0x01, 0x01, 0x00, 0x00, 0x00]);

        let mut src = ReadCursor::new(&buf);
        let decoded = VersionPdu::decode(&mut src).unwrap();
        assert_eq!(decoded.version, SNDIN_VERSION_1);
    }

    #[test]
    fn version_v2_roundtrip() {
        let pdu = VersionPdu { version: SNDIN_VERSION_2 };
        let mut buf = [0u8; 5];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(buf, [0x01, 0x02, 0x00, 0x00, 0x00]);

        let mut src = ReadCursor::new(&buf);
        let decoded = VersionPdu::decode(&mut src).unwrap();
        assert_eq!(decoded.version, SNDIN_VERSION_2);
    }

    #[test]
    fn version_invalid_rejected() {
        let buf = [0x01, 0x03, 0x00, 0x00, 0x00]; // version 3
        let mut src = ReadCursor::new(&buf);
        assert!(VersionPdu::decode(&mut src).is_err());
    }

    #[test]
    fn version_wrong_header() {
        let buf = [0x02, 0x01, 0x00, 0x00, 0x00]; // header 0x02 instead of 0x01
        let mut src = ReadCursor::new(&buf);
        assert!(VersionPdu::decode(&mut src).is_err());
    }

    #[test]
    fn version_size_matches_encode() {
        let pdu = VersionPdu { version: SNDIN_VERSION_1 };
        assert_eq!(pdu.size(), VersionPdu::WIRE_SIZE);
        let mut buf = [0u8; 5];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(dst.remaining(), 0);
    }

    // ── SoundFormatsPdu ──

    #[test]
    fn sound_formats_pcm_roundtrip() {
        let fmt = AudioFormat::pcm(2, 44100, 16);
        let pdu = SoundFormatsPdu {
            formats: alloc::vec![fmt.clone()],
            cb_size_formats_packet: 0, // will be set below
        };
        let mut pdu = pdu;
        pdu.cb_size_formats_packet = pdu.compute_cb_size();

        let size = pdu.size();
        let mut buf = alloc::vec![0u8; size];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();

        let decoded = SoundFormatsPdu::decode_from(&buf).unwrap();
        assert_eq!(decoded.formats.len(), 1);
        assert_eq!(decoded.formats[0].format_tag, WaveFormatTag::PCM);
        assert_eq!(decoded.formats[0].n_channels, 2);
        assert_eq!(decoded.formats[0].n_samples_per_sec, 44100);
    }

    #[test]
    fn sound_formats_empty_roundtrip() {
        let pdu = SoundFormatsPdu {
            formats: alloc::vec![],
            cb_size_formats_packet: 9, // 1 + 4 + 4
        };
        let size = pdu.size();
        let mut buf = alloc::vec![0u8; size];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();

        let decoded = SoundFormatsPdu::decode_from(&buf).unwrap();
        assert_eq!(decoded.formats.len(), 0);
    }

    #[test]
    fn sound_formats_server_arbitrary_cb_size() {
        // Server can send arbitrary cbSizeFormatsPacket (e.g., 0x80000000)
        #[rustfmt::skip]
        let buf: [u8; 27] = [
            0x02,                   // Header
            0x01, 0x00, 0x00, 0x00, // NumFormats = 1
            0x00, 0x00, 0x00, 0x80, // cbSizeFormatsPacket = 0x80000000 (arbitrary)
            // PCM format: 18 bytes
            0x01, 0x00, // wFormatTag = PCM
            0x02, 0x00, // nChannels = 2
            0x44, 0xAC, 0x00, 0x00, // nSamplesPerSec = 44100
            0x10, 0xB1, 0x02, 0x00, // nAvgBytesPerSec = 176400
            0x04, 0x00, // nBlockAlign = 4
            0x10, 0x00, // wBitsPerSample = 16
            0x00, 0x00, // cbSize = 0
        ];
        let decoded = SoundFormatsPdu::decode_from(&buf).unwrap();
        assert_eq!(decoded.formats.len(), 1);
        assert_eq!(decoded.cb_size_formats_packet, 0x8000_0000);
    }

    #[test]
    fn sound_formats_wrong_header() {
        let buf = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(SoundFormatsPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn sound_formats_too_many_rejected() {
        // NumFormats = 257 (exceeds MAX_NUM_FORMATS=256)
        #[rustfmt::skip]
        let buf: [u8; 9] = [
            0x02,                   // Header
            0x01, 0x01, 0x00, 0x00, // NumFormats = 257
            0x00, 0x00, 0x00, 0x00, // cbSizeFormatsPacket
        ];
        assert!(SoundFormatsPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn sound_formats_size_matches_encode() {
        let pdu = SoundFormatsPdu {
            formats: alloc::vec![AudioFormat::pcm(1, 8000, 16)],
            cb_size_formats_packet: 27,
        };
        let size = pdu.size();
        let mut buf = alloc::vec![0u8; size];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(dst.remaining(), 0);
    }

    #[test]
    fn sound_formats_compute_cb_size() {
        let pdu = SoundFormatsPdu {
            formats: alloc::vec![AudioFormat::pcm(2, 44100, 16)],
            cb_size_formats_packet: 0,
        };
        // 1 (header) + 4 (NumFormats) + 4 (cbSize) + 18 (PCM format) = 27
        assert_eq!(pdu.compute_cb_size(), 27);
    }

    // ── OpenPdu ──

    #[test]
    fn open_pdu_spec_test_vector() {
        // MS-RDPEAI section 4.2 annotated dump
        #[rustfmt::skip]
        let buf: [u8; 49] = [
            0x03,                   // Header: MSG_SNDIN_OPEN
            0x9d, 0x08, 0x00, 0x00, // FramesPerPacket = 2205
            0x0b, 0x00, 0x00, 0x00, // initialFormat = 11
            0xfe, 0xff,             // wFormatTag = WAVE_FORMAT_EXTENSIBLE
            0x02, 0x00,             // nChannels = 2
            0x44, 0xac, 0x00, 0x00, // nSamplesPerSec = 44100
            0x10, 0xb1, 0x02, 0x00, // nAvgBytesPerSec = 176400
            0x04, 0x00,             // nBlockAlign = 4
            0x10, 0x00,             // wBitsPerSample = 16
            0x16, 0x00,             // cbSize = 22
            // WAVEFORMAT_EXTENSIBLE (22 bytes)
            0x10, 0x00,             // wValidBitsPerSample = 16
            0x03, 0x00, 0x00, 0x00, // dwChannelMask = FRONT_LEFT | FRONT_RIGHT
            // SubFormat GUID (KSDATAFORMAT_SUBTYPE_PCM)
            0x01, 0x00, 0x00, 0x00, // Data1 (LE)
            0x00, 0x00,             // Data2 (LE)
            0x10, 0x00,             // Data3 (LE)
            0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71, // Data4
        ];

        let pdu = OpenPdu::decode_from(&buf).unwrap();
        assert_eq!(pdu.frames_per_packet, 2205);
        assert_eq!(pdu.initial_format, 11);
        assert_eq!(pdu.capture_format.format_tag, WaveFormatTag(0xFFFE));
        assert_eq!(pdu.capture_format.n_channels, 2);
        assert_eq!(pdu.capture_format.n_samples_per_sec, 44100);
        assert_eq!(pdu.capture_format.n_avg_bytes_per_sec, 176400);
        assert_eq!(pdu.capture_format.n_block_align, 4);
        assert_eq!(pdu.capture_format.bits_per_sample, 16);
        assert_eq!(pdu.capture_format.extra_data.len(), 22);
    }

    #[test]
    fn open_pdu_pcm_no_extra() {
        #[rustfmt::skip]
        let buf: [u8; 27] = [
            0x03,                   // Header
            0x00, 0x04, 0x00, 0x00, // FramesPerPacket = 1024
            0x00, 0x00, 0x00, 0x00, // initialFormat = 0
            0x01, 0x00,             // wFormatTag = PCM
            0x01, 0x00,             // nChannels = 1
            0x40, 0x1F, 0x00, 0x00, // nSamplesPerSec = 8000
            0x80, 0x3E, 0x00, 0x00, // nAvgBytesPerSec = 16000
            0x02, 0x00,             // nBlockAlign = 2
            0x10, 0x00,             // wBitsPerSample = 16
            0x00, 0x00,             // cbSize = 0
        ];

        let pdu = OpenPdu::decode_from(&buf).unwrap();
        assert_eq!(pdu.frames_per_packet, 1024);
        assert_eq!(pdu.initial_format, 0);
        assert_eq!(pdu.capture_format.format_tag, WaveFormatTag::PCM);
        assert!(pdu.capture_format.extra_data.is_empty());
    }

    #[test]
    fn open_pdu_zero_frames_rejected() {
        #[rustfmt::skip]
        let buf: [u8; 27] = [
            0x03,
            0x00, 0x00, 0x00, 0x00, // FramesPerPacket = 0
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00,
            0x40, 0x1F, 0x00, 0x00,
            0x80, 0x3E, 0x00, 0x00,
            0x02, 0x00, 0x10, 0x00,
            0x00, 0x00,
        ];
        assert!(OpenPdu::decode_from(&buf).is_err());
    }

    #[test]
    fn open_pdu_wrong_header() {
        let buf = [0x01; 27]; // wrong header
        assert!(OpenPdu::decode_from(&buf).is_err());
    }

    // ── OpenReplyPdu ──

    #[test]
    fn open_reply_success_roundtrip() {
        let pdu = OpenReplyPdu { result: OpenReplyPdu::S_OK };
        let mut buf = [0u8; 5];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(buf, [0x04, 0x00, 0x00, 0x00, 0x00]);

        let mut src = ReadCursor::new(&buf);
        let decoded = OpenReplyPdu::decode(&mut src).unwrap();
        assert_eq!(decoded.result, OpenReplyPdu::S_OK);
    }

    #[test]
    fn open_reply_failure_roundtrip() {
        let pdu = OpenReplyPdu { result: OpenReplyPdu::E_FAIL };
        let mut buf = [0u8; 5];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(buf, [0x04, 0x05, 0x40, 0x00, 0x80]);

        let mut src = ReadCursor::new(&buf);
        let decoded = OpenReplyPdu::decode(&mut src).unwrap();
        assert_eq!(decoded.result, OpenReplyPdu::E_FAIL);
    }

    #[test]
    fn open_reply_size_matches_encode() {
        let pdu = OpenReplyPdu { result: 0 };
        assert_eq!(pdu.size(), OpenReplyPdu::WIRE_SIZE);
        let mut buf = [0u8; 5];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(dst.remaining(), 0);
    }

    // ── IncomingDataPdu ──

    #[test]
    fn incoming_data_roundtrip() {
        let pdu = IncomingDataPdu;
        let mut buf = [0u8; 1];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(buf, [0x05]);

        let mut src = ReadCursor::new(&buf);
        let decoded = IncomingDataPdu::decode(&mut src).unwrap();
        assert_eq!(decoded, IncomingDataPdu);
    }

    #[test]
    fn incoming_data_wrong_header() {
        let buf = [0x06];
        let mut src = ReadCursor::new(&buf);
        assert!(IncomingDataPdu::decode(&mut src).is_err());
    }

    // ── DataPdu ──

    #[test]
    fn data_pdu_roundtrip() {
        let pdu = DataPdu {
            data: alloc::vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let size = pdu.size();
        assert_eq!(size, 5);
        let mut buf = alloc::vec![0u8; size];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(buf, [0x06, 0xAA, 0xBB, 0xCC, 0xDD]);

        let mut src = ReadCursor::new(&buf);
        let decoded = DataPdu::decode(&mut src).unwrap();
        assert_eq!(decoded.data, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn data_pdu_empty_payload() {
        let pdu = DataPdu {
            data: alloc::vec![],
        };
        let mut buf = alloc::vec![0u8; 1];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(buf, [0x06]);

        let mut src = ReadCursor::new(&buf);
        let decoded = DataPdu::decode(&mut src).unwrap();
        assert!(decoded.data.is_empty());
    }

    // ── FormatChangePdu ──

    #[test]
    fn format_change_roundtrip() {
        let pdu = FormatChangePdu { new_format: 3 };
        let mut buf = [0u8; 5];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(buf, [0x07, 0x03, 0x00, 0x00, 0x00]);

        let mut src = ReadCursor::new(&buf);
        let decoded = FormatChangePdu::decode(&mut src).unwrap();
        assert_eq!(decoded.new_format, 3);
    }

    #[test]
    fn format_change_size_matches_encode() {
        let pdu = FormatChangePdu { new_format: 0 };
        assert_eq!(pdu.size(), FormatChangePdu::WIRE_SIZE);
        let mut buf = [0u8; 5];
        let mut dst = WriteCursor::new(&mut buf);
        pdu.encode(&mut dst).unwrap();
        assert_eq!(dst.remaining(), 0);
    }

    #[test]
    fn format_change_wrong_header() {
        let buf = [0x01, 0x00, 0x00, 0x00, 0x00];
        let mut src = ReadCursor::new(&buf);
        assert!(FormatChangePdu::decode(&mut src).is_err());
    }
}
