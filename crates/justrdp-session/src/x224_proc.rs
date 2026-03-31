#![forbid(unsafe_code)]

//! Slow-path (X.224/TPKT) frame processing -- MS-RDPBCGR 2.2.8.1 / 2.2.9.1.1
//!
//! Processes server-to-client slow-path PDUs: TPKT → X.224 DT → MCS → ShareControl → ShareData.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_bulk::bulk::BulkDecompressor;
use justrdp_bulk::mppc::PACKET_COMPRESSED;
use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_pdu::mcs::{
    DisconnectProviderUltimatum, DomainMcsPduType, SendDataIndication,
    SendDataRequest,
};
use justrdp_pdu::rdp::fast_path::FastPathUpdateType;
use justrdp_pdu::rdp::finalization::{
    DeactivateAllPdu, SaveSessionInfoPdu, SetErrorInfoPdu, ERRINFO_NONE,
};
use justrdp_pdu::rdp::headers::{
    ShareControlHeader, ShareControlPduType, ShareDataHeader, ShareDataPduType,
    SHARE_CONTROL_HEADER_SIZE, SHARE_DATA_HEADER_SIZE,
};
use justrdp_pdu::tpkt::{TpktHeader, TPKT_HEADER_SIZE};
use justrdp_pdu::x224::{DataTransfer, DATA_TRANSFER_HEADER_SIZE};

use crate::{
    ActiveStageOutput, DeactivationReactivation, GracefulDisconnectReason, SessionConfig,
    SessionError, SessionResult,
};

/// Process a complete slow-path frame (starts with TPKT version byte 0x03).
pub(crate) fn process_slow_path(
    frame: &[u8],
    config: &SessionConfig,
    decompressor: &mut BulkDecompressor,
    last_error_info: &mut u32,
) -> SessionResult<Vec<ActiveStageOutput>> {
    let mut src = ReadCursor::new(frame);

    // Layer 1: TPKT header (4 bytes)
    let _tpkt = TpktHeader::decode(&mut src)?;

    // Layer 2: X.224 Data Transfer (3 bytes)
    let _dt = DataTransfer::decode(&mut src)?;

    // Layer 3: MCS domain PDU -- peek at choice byte to determine type.
    if src.remaining() == 0 {
        return Ok(vec![]);
    }

    let choice_byte = src.peek_remaining()[0];
    let choice = choice_byte >> 2;
    let mcs_type = DomainMcsPduType::from_u8(choice);

    match mcs_type {
        Ok(DomainMcsPduType::SendDataIndication) => {
            let sdi = SendDataIndication::decode(&mut src)?;
            process_mcs_data(sdi.channel_id, sdi.user_data, config, decompressor, last_error_info)
        }
        Ok(DomainMcsPduType::DisconnectProviderUltimatum) => {
            let dpu = DisconnectProviderUltimatum::decode(&mut src)?;
            let reason = if *last_error_info != ERRINFO_NONE {
                GracefulDisconnectReason::ServerError(*last_error_info)
            } else {
                GracefulDisconnectReason::ServerDisconnect(dpu.reason as u8)
            };
            Ok(vec![ActiveStageOutput::Terminate(reason)])
        }
        _ => {
            // Unknown or unexpected MCS PDU during active session -- skip.
            Ok(vec![])
        }
    }
}

/// Process MCS user data (after SendDataIndication decode).
fn process_mcs_data(
    channel_id: u16,
    user_data: &[u8],
    config: &SessionConfig,
    decompressor: &mut BulkDecompressor,
    last_error_info: &mut u32,
) -> SessionResult<Vec<ActiveStageOutput>> {
    if channel_id == config.io_channel_id {
        // I/O channel: RDP data PDU.
        process_rdp_data(user_data, decompressor, last_error_info)
    } else {
        // Virtual channel data -- pass through to caller.
        Ok(vec![ActiveStageOutput::ChannelData {
            channel_id,
            data: user_data.to_vec(),
        }])
    }
}

/// Process RDP data on the I/O channel (ShareControlHeader layer).
fn process_rdp_data(
    data: &[u8],
    decompressor: &mut BulkDecompressor,
    last_error_info: &mut u32,
) -> SessionResult<Vec<ActiveStageOutput>> {
    let mut src = ReadCursor::new(data);
    let share_hdr = ShareControlHeader::decode(&mut src)?;

    match share_hdr.pdu_type {
        ShareControlPduType::Data => {
            process_share_data(&mut src, decompressor, last_error_info)
        }
        ShareControlPduType::DeactivateAllPdu => {
            let deactivate = DeactivateAllPdu::decode(&mut src)?;
            // Skip source_descriptor bytes if present.
            let desc_len = deactivate.length_source_descriptor as usize;
            if desc_len > 0 && src.remaining() >= desc_len {
                src.skip(desc_len, "DeactivateAllPdu::sourceDescriptor")?;
            }
            Ok(vec![ActiveStageOutput::DeactivateAll(
                DeactivationReactivation {
                    share_id: deactivate.share_id,
                },
            )])
        }
        ShareControlPduType::DemandActivePdu => {
            // Server re-sent Demand Active (reactivation).
            // For now, signal as deactivation -- caller must drive the response.
            // The raw data is in `src.peek_remaining()`.
            Ok(vec![ActiveStageOutput::DeactivateAll(
                DeactivationReactivation {
                    share_id: 0, // will be re-read from DemandActivePdu by caller
                },
            )])
        }
        ShareControlPduType::ServerRedirect => {
            // Server redirection during active session (rare).
            Ok(vec![ActiveStageOutput::Terminate(
                GracefulDisconnectReason::ServerDisconnect(0),
            )])
        }
        _ => Ok(vec![]),
    }
}

/// Process a Share Data PDU (pduType == Data).
fn process_share_data(
    src: &mut ReadCursor<'_>,
    decompressor: &mut BulkDecompressor,
    last_error_info: &mut u32,
) -> SessionResult<Vec<ActiveStageOutput>> {
    let data_hdr = ShareDataHeader::decode(src)?;

    // Decompress the inner payload if needed.
    // MS-RDPBCGR 2.2.8.1.1.1.2: compressedType flags determine compression.
    let inner_data = if data_hdr.compressed_type & PACKET_COMPRESSED != 0 {
        let compressed_len = if data_hdr.compressed_length > 0 {
            data_hdr.compressed_length as usize
        } else {
            src.remaining()
        };
        let compressed = src.read_slice(compressed_len, "ShareData::compressedPayload")?;
        let mut decompressed = Vec::new();
        decompressor
            .decompress(data_hdr.compressed_type, compressed, &mut decompressed)
            .map_err(|e| SessionError::Decompress(format!("{e:?}")))?;
        decompressed
    } else {
        let remaining = src.remaining();
        src.read_slice(remaining, "ShareData::payload")?.to_vec()
    };

    dispatch_pdu_type2(data_hdr.pdu_type2, &inner_data, last_error_info)
}

/// Dispatch based on pduType2 value.
fn dispatch_pdu_type2(
    pdu_type2: ShareDataPduType,
    data: &[u8],
    last_error_info: &mut u32,
) -> SessionResult<Vec<ActiveStageOutput>> {
    match pdu_type2 {
        ShareDataPduType::Update => {
            // Slow-path graphics update: updateType(u16) + data
            if data.len() < 2 {
                return Ok(vec![]);
            }
            let update_type = u16::from_le_bytes([data[0], data[1]]);
            // Map slow-path update type to FastPathUpdateType for unified output.
            // MS-RDPBCGR 2.2.9.1.1.3: UPDATETYPE_ORDERS=0, BITMAP=1, PALETTE=2, SYNCHRONIZE=3
            let update_code = match update_type {
                0x0000 => FastPathUpdateType::Orders,
                0x0001 => FastPathUpdateType::Bitmap,
                0x0002 => FastPathUpdateType::Palette,
                0x0003 => FastPathUpdateType::Synchronize,
                _ => return Ok(vec![]),
            };
            Ok(vec![ActiveStageOutput::GraphicsUpdate {
                update_code,
                data: data[2..].to_vec(),
            }])
        }

        ShareDataPduType::Pointer => {
            // Slow-path pointer update: messageType(u16) + pad2(u16) + data
            if data.len() < 4 {
                return Ok(vec![]);
            }
            let msg_type = u16::from_le_bytes([data[0], data[1]]);
            // Map to fast-path pointer types for unified output.
            match msg_type {
                0x0001 => {
                    // TS_PTRMSGTYPE_SYSTEM: pointerType u32
                    if data.len() >= 8 {
                        let ptr_type = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                        if ptr_type == 0 {
                            Ok(vec![ActiveStageOutput::PointerHidden])
                        } else {
                            Ok(vec![ActiveStageOutput::PointerDefault])
                        }
                    } else {
                        Ok(vec![])
                    }
                }
                0x0003 => {
                    // TS_PTRMSGTYPE_POSITION: xPos(u16) + yPos(u16)
                    if data.len() >= 8 {
                        let x = u16::from_le_bytes([data[4], data[5]]);
                        let y = u16::from_le_bytes([data[6], data[7]]);
                        Ok(vec![ActiveStageOutput::PointerPosition { x, y }])
                    } else {
                        Ok(vec![])
                    }
                }
                // Color(6), Cached(7), New(8), Large(9) -- pass raw data.
                _ => Ok(vec![ActiveStageOutput::PointerBitmap {
                    pointer_type: msg_type as u8,
                    data: data[4..].to_vec(),
                }]),
            }
        }

        ShareDataPduType::SetErrorInfo => {
            // MS-RDPBCGR 3.2.5.5: SetErrorInfo is informational -- the session is still
            // alive. Store the error code; the actual Terminate is emitted when
            // DisconnectProviderUltimatum arrives (or TCP drops).
            let mut inner_src = ReadCursor::new(data);
            let pdu = SetErrorInfoPdu::decode(&mut inner_src)?;
            if pdu.error_info != ERRINFO_NONE {
                *last_error_info = pdu.error_info;
            }
            Ok(vec![])
        }

        ShareDataPduType::SaveSessionInfo => {
            let mut inner_src = ReadCursor::new(data);
            let pdu = SaveSessionInfoPdu::decode(&mut inner_src)?;
            Ok(vec![ActiveStageOutput::SaveSessionInfo {
                info_type: pdu.info_type,
                data: pdu.info_data,
            }])
        }

        ShareDataPduType::ShutdownDenied => {
            Ok(vec![ActiveStageOutput::Terminate(
                GracefulDisconnectReason::ShutdownDenied,
            )])
        }

        // Finalization PDUs that may arrive during reactivation -- skip.
        ShareDataPduType::Synchronize
        | ShareDataPduType::Control
        | ShareDataPduType::FontMap
        | ShareDataPduType::FontList => Ok(vec![]),

        // Monitor layout -- could be used for resize notification.
        ShareDataPduType::MonitorLayoutPdu => {
            // For now, pass through as-is. Caller can decode if needed.
            Ok(vec![])
        }

        // All other pduType2 values -- skip gracefully.
        _ => Ok(vec![]),
    }
}

// ── Encoding helpers ──

/// Encode a graceful shutdown request PDU.
pub(crate) fn encode_shutdown_request(
    user_channel_id: u16,
    io_channel_id: u16,
    share_id: u32,
) -> SessionResult<Vec<u8>> {
    // Inner: ShutdownRequestPdu (0 bytes body)
    let inner = &[];

    // Wrap in ShareDataHeader
    let share_data = wrap_share_data(share_id, ShareDataPduType::ShutdownRequest, inner);

    // Wrap in ShareControlHeader
    let share_control = wrap_share_control(
        ShareControlPduType::Data,
        user_channel_id,
        &share_data,
    );

    // Wrap in MCS SendDataRequest + X.224 DT + TPKT
    encode_mcs_send_data(user_channel_id, io_channel_id, &share_control)
}

/// Build a ShareControlHeader + inner payload as bytes.
fn wrap_share_control(
    pdu_type: ShareControlPduType,
    pdu_source: u16,
    inner: &[u8],
) -> Vec<u8> {
    let total_length = SHARE_CONTROL_HEADER_SIZE + inner.len();
    let hdr = ShareControlHeader {
        total_length: total_length as u16,
        pdu_type,
        pdu_source,
    };

    let mut buf = vec![0u8; total_length];
    let mut cursor = WriteCursor::new(&mut buf);
    hdr.encode(&mut cursor).expect("share control header encode");
    cursor.write_slice(inner, "share_control_inner").expect("share control inner");
    buf
}

/// Build a ShareDataHeader + inner payload as bytes.
fn wrap_share_data(
    share_id: u32,
    pdu_type2: ShareDataPduType,
    inner: &[u8],
) -> Vec<u8> {
    let total_length = SHARE_DATA_HEADER_SIZE + inner.len();
    let hdr = ShareDataHeader {
        share_id,
        stream_id: 1, // STREAM_LOW -- MS-RDPBCGR 2.2.8.1.1.1.2
        uncompressed_length: inner.len() as u16,
        pdu_type2,
        compressed_type: 0,
        compressed_length: 0,
    };

    let mut buf = vec![0u8; total_length];
    let mut cursor = WriteCursor::new(&mut buf);
    hdr.encode(&mut cursor).expect("share data header encode");
    cursor.write_slice(inner, "share_data_inner").expect("share data inner");
    buf
}

/// Encode a PDU wrapped in TPKT + X.224 DT + MCS SendDataRequest.
fn encode_mcs_send_data(
    initiator: u16,
    channel_id: u16,
    inner: &[u8],
) -> SessionResult<Vec<u8>> {
    let sdr = SendDataRequest {
        initiator,
        channel_id,
        user_data: inner,
    };

    let mcs_size = DATA_TRANSFER_HEADER_SIZE + sdr.size();
    let total_size = TPKT_HEADER_SIZE + mcs_size;

    let mut buf = vec![0u8; total_size];
    let mut cursor = WriteCursor::new(&mut buf);

    TpktHeader::for_payload(mcs_size).encode(&mut cursor)?;
    DataTransfer.encode(&mut cursor)?;
    sdr.encode(&mut cursor)?;

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::mcs::DisconnectReason;
    use justrdp_pdu::rdp::fast_path::FastPathUpdateType;

    /// Build a minimal slow-path frame with the given ShareData content.
    fn build_slow_path_frame(
        io_channel_id: u16,
        share_id: u32,
        pdu_type2: ShareDataPduType,
        inner_body: &[u8],
    ) -> Vec<u8> {
        // Build ShareDataHeader + inner body
        let share_data = wrap_share_data(share_id, pdu_type2, inner_body);

        // Build ShareControlHeader + share_data
        let share_control = wrap_share_control(
            ShareControlPduType::Data,
            0x03EA, // server pdu_source
            &share_data,
        );

        // Build SendDataIndication
        let sdi = SendDataIndication {
            initiator: 0x03EA,
            channel_id: io_channel_id,
            user_data: &share_control,
        };

        // Build TPKT + X.224 DT + MCS
        let mcs_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let total_size = TPKT_HEADER_SIZE + mcs_size;
        let mut frame = vec![0u8; total_size];
        let mut cursor = WriteCursor::new(&mut frame);
        TpktHeader::for_payload(mcs_size).encode(&mut cursor).unwrap();
        DataTransfer.encode(&mut cursor).unwrap();
        sdi.encode(&mut cursor).unwrap();
        frame
    }

    fn test_config() -> SessionConfig {
        SessionConfig {
            io_channel_id: 1003,
            user_channel_id: 1007,
            share_id: 0x00040006,
            channel_ids: vec![],
        }
    }

    #[test]
    fn process_set_error_info_none_is_silent() {
        let config = test_config();
        let body = 0u32.to_le_bytes();
        let frame = build_slow_path_frame(config.io_channel_id, config.share_id, ShareDataPduType::SetErrorInfo, &body);

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert!(outputs.is_empty());
    }

    #[test]
    fn process_set_error_info_nonzero_stores_but_no_terminate() {
        // MS-RDPBCGR 3.2.5.5: SetErrorInfo is informational; session is still alive.
        // Terminate is only emitted when DisconnectProviderUltimatum arrives.
        let config = test_config();
        let body = 3u32.to_le_bytes(); // ERRINFO_IDLE_TIMEOUT
        let frame = build_slow_path_frame(config.io_channel_id, config.share_id, ShareDataPduType::SetErrorInfo, &body);

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        // No Terminate yet -- only stored.
        assert!(outputs.is_empty());
        assert_eq!(last_error_info, 3);
    }

    #[test]
    fn set_error_info_then_disconnect_uses_error_code() {
        let config = test_config();

        // First: SetErrorInfo with ERRINFO_IDLE_TIMEOUT
        let body = 3u32.to_le_bytes();
        let frame = build_slow_path_frame(config.io_channel_id, config.share_id, ShareDataPduType::SetErrorInfo, &body);
        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let _ = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(last_error_info, 3);

        // Then: DisconnectProviderUltimatum
        let dpu = DisconnectProviderUltimatum {
            reason: DisconnectReason::UserRequested,
        };
        let mcs_size = DATA_TRANSFER_HEADER_SIZE + dpu.size();
        let total_size = TPKT_HEADER_SIZE + mcs_size;
        let mut frame = vec![0u8; total_size];
        let mut cursor = WriteCursor::new(&mut frame);
        TpktHeader::for_payload(mcs_size).encode(&mut cursor).unwrap();
        DataTransfer.encode(&mut cursor).unwrap();
        dpu.encode(&mut cursor).unwrap();

        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        // Should use the stored error info, not the generic disconnect reason.
        match &outputs[0] {
            ActiveStageOutput::Terminate(GracefulDisconnectReason::ServerError(code)) => {
                assert_eq!(*code, 3);
            }
            _ => panic!("expected Terminate(ServerError(3))"),
        }
    }

    #[test]
    fn process_save_session_info() {
        let config = test_config();
        // info_type=0 (LOGON), followed by dummy data
        let mut body = vec![];
        body.extend_from_slice(&0u32.to_le_bytes()); // info_type = INFO_TYPE_LOGON
        body.extend_from_slice(b"logon_data");
        let frame = build_slow_path_frame(config.io_channel_id, config.share_id, ShareDataPduType::SaveSessionInfo, &body);

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            ActiveStageOutput::SaveSessionInfo { info_type, data } => {
                assert_eq!(*info_type, 0);
                assert_eq!(data, b"logon_data");
            }
            _ => panic!("expected SaveSessionInfo"),
        }
    }

    #[test]
    fn process_slow_path_bitmap_update() {
        let config = test_config();
        // Slow-path update: updateType=BITMAP(0x0001), then raw data
        let mut body = vec![];
        body.extend_from_slice(&1u16.to_le_bytes()); // UPDATETYPE_BITMAP
        body.extend_from_slice(b"bitmap_data");
        let frame = build_slow_path_frame(config.io_channel_id, config.share_id, ShareDataPduType::Update, &body);

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            ActiveStageOutput::GraphicsUpdate { update_code, data } => {
                assert_eq!(*update_code, FastPathUpdateType::Bitmap);
                assert_eq!(data.as_slice(), b"bitmap_data");
            }
            _ => panic!("expected GraphicsUpdate"),
        }
    }

    #[test]
    fn process_virtual_channel_data() {
        let config = test_config();
        let vc_channel_id = 1004u16; // not the I/O channel

        // Build a frame on a virtual channel.
        let vc_data = b"channel_payload";
        let sdi = SendDataIndication {
            initiator: 0x03EA,
            channel_id: vc_channel_id,
            user_data: vc_data,
        };
        let mcs_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let total_size = TPKT_HEADER_SIZE + mcs_size;
        let mut frame = vec![0u8; total_size];
        let mut cursor = WriteCursor::new(&mut frame);
        TpktHeader::for_payload(mcs_size).encode(&mut cursor).unwrap();
        DataTransfer.encode(&mut cursor).unwrap();
        sdi.encode(&mut cursor).unwrap();

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            ActiveStageOutput::ChannelData { channel_id, data } => {
                assert_eq!(*channel_id, vc_channel_id);
                assert_eq!(data.as_slice(), vc_data);
            }
            _ => panic!("expected ChannelData"),
        }
    }

    #[test]
    fn process_disconnect_provider_ultimatum() {
        let dpu = DisconnectProviderUltimatum {
            reason: DisconnectReason::UserRequested,
        };
        let mcs_size = DATA_TRANSFER_HEADER_SIZE + dpu.size();
        let total_size = TPKT_HEADER_SIZE + mcs_size;
        let mut frame = vec![0u8; total_size];
        let mut cursor = WriteCursor::new(&mut frame);
        TpktHeader::for_payload(mcs_size).encode(&mut cursor).unwrap();
        DataTransfer.encode(&mut cursor).unwrap();
        dpu.encode(&mut cursor).unwrap();

        let config = test_config();
        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            ActiveStageOutput::Terminate(GracefulDisconnectReason::ServerDisconnect(reason)) => {
                assert_eq!(*reason, DisconnectReason::UserRequested as u8);
            }
            _ => panic!("expected Terminate(ServerDisconnect)"),
        }
    }

    #[test]
    fn encode_shutdown_request_roundtrip() {
        let frame = encode_shutdown_request(1007, 1003, 0x00040006).unwrap();
        // Verify it starts with TPKT
        assert_eq!(frame[0], 0x03);
        // Verify it's parseable back
        let mut src = ReadCursor::new(&frame);
        let _tpkt = TpktHeader::decode(&mut src).unwrap();
        let _dt = DataTransfer::decode(&mut src).unwrap();
        // Should be a SendDataRequest
        let choice = src.peek_remaining()[0] >> 2;
        assert_eq!(choice, DomainMcsPduType::SendDataRequest as u8);
    }

    #[test]
    fn process_slow_path_pointer_position() {
        let config = test_config();
        // Pointer update: messageType=POSITION(0x0003), pad2=0, xPos=50, yPos=75
        let mut body = vec![];
        body.extend_from_slice(&0x0003u16.to_le_bytes()); // messageType
        body.extend_from_slice(&0x0000u16.to_le_bytes()); // pad2
        body.extend_from_slice(&50u16.to_le_bytes());     // xPos
        body.extend_from_slice(&75u16.to_le_bytes());     // yPos
        let frame = build_slow_path_frame(config.io_channel_id, config.share_id, ShareDataPduType::Pointer, &body);

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0], ActiveStageOutput::PointerPosition { x: 50, y: 75 });
    }

    #[test]
    fn process_slow_path_system_pointer_hidden() {
        let config = test_config();
        // System pointer: messageType=SYSTEM(0x0001), pad2=0, pointerType=0 (hidden)
        let mut body = vec![];
        body.extend_from_slice(&0x0001u16.to_le_bytes()); // messageType
        body.extend_from_slice(&0x0000u16.to_le_bytes()); // pad2
        body.extend_from_slice(&0u32.to_le_bytes());       // pointerType = hidden
        let frame = build_slow_path_frame(config.io_channel_id, config.share_id, ShareDataPduType::Pointer, &body);

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0], ActiveStageOutput::PointerHidden);
    }

    #[test]
    fn process_deactivate_all_extracts_share_id() {
        let config = test_config();
        // Build DeactivateAllPdu: share_id=0xDEADBEEF, length_source_descriptor=4, source_descriptor=[0,0,0,0]
        let mut deactivate_body = vec![];
        deactivate_body.extend_from_slice(&0xDEADBEEFu32.to_le_bytes()); // shareId
        deactivate_body.extend_from_slice(&4u16.to_le_bytes()); // lengthSourceDescriptor
        deactivate_body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // sourceDescriptor

        // Wrap in ShareControlHeader with DeactivateAllPdu type.
        let share_control = wrap_share_control(
            ShareControlPduType::DeactivateAllPdu,
            0x03EA,
            &deactivate_body,
        );

        // Wrap in SendDataIndication + X.224 + TPKT.
        let sdi = SendDataIndication {
            initiator: 0x03EA,
            channel_id: config.io_channel_id,
            user_data: &share_control,
        };
        let mcs_size = DATA_TRANSFER_HEADER_SIZE + sdi.size();
        let total_size = TPKT_HEADER_SIZE + mcs_size;
        let mut frame = vec![0u8; total_size];
        let mut cursor = WriteCursor::new(&mut frame);
        TpktHeader::for_payload(mcs_size).encode(&mut cursor).unwrap();
        DataTransfer.encode(&mut cursor).unwrap();
        sdi.encode(&mut cursor).unwrap();

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            ActiveStageOutput::DeactivateAll(info) => {
                assert_eq!(info.share_id, 0xDEADBEEF);
            }
            _ => panic!("expected DeactivateAll"),
        }
    }

    #[test]
    fn process_shutdown_denied() {
        let config = test_config();
        let frame = build_slow_path_frame(
            config.io_channel_id,
            config.share_id,
            ShareDataPduType::ShutdownDenied,
            &[],
        );

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(
            outputs[0],
            ActiveStageOutput::Terminate(GracefulDisconnectReason::ShutdownDenied)
        );
    }

    #[test]
    fn process_empty_frame_returns_empty() {
        let config = test_config();
        let mut stage = crate::ActiveStage::new(config);
        let outputs = stage.process(&[]).unwrap();
        assert!(outputs.is_empty());
    }

    #[test]
    fn process_slow_path_orders_update() {
        let config = test_config();
        let mut body = vec![];
        body.extend_from_slice(&0x0000u16.to_le_bytes()); // UPDATETYPE_ORDERS
        body.extend_from_slice(b"order_data");
        let frame = build_slow_path_frame(
            config.io_channel_id,
            config.share_id,
            ShareDataPduType::Update,
            &body,
        );

        let mut decompressor = BulkDecompressor::new();
        let mut last_error_info = 0u32;
        let outputs = process_slow_path(&frame, &config, &mut decompressor, &mut last_error_info).unwrap();
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            ActiveStageOutput::GraphicsUpdate { update_code, data } => {
                assert_eq!(*update_code, FastPathUpdateType::Orders);
                assert_eq!(data.as_slice(), b"order_data");
            }
            _ => panic!("expected GraphicsUpdate with Orders"),
        }
    }
}
