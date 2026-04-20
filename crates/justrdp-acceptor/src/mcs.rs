#![forbid(unsafe_code)]

//! MCS Connect Initial / Connect Response handling for the server side.
//!
//! Mirrors the client-side `BasicSettingsExchange` phase from
//! `justrdp-connector` -- parses the client GCC data blocks out of an MCS
//! Connect Initial PDU, allocates channel IDs, and builds the matching
//! GCC ConferenceCreateResponse to ship inside an MCS Connect Response.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};

use justrdp_pdu::gcc::client::{
    ChannelDef, ClientClusterData, ClientCoreData, ClientMessageChannelData,
    ClientMonitorData, ClientMonitorExtendedData, ClientMultitransportChannelData,
    ClientNetworkData, ClientSecurityData,
};
use justrdp_pdu::gcc::server::{
    ServerCoreData, ServerMessageChannelData, ServerMultitransportChannelData,
    ServerNetworkData, ServerSecurityData,
};
use justrdp_pdu::gcc::{
    read_block_header, ClientDataBlockType, ConferenceCreateRequest, ConferenceCreateResponse,
    DATA_BLOCK_HEADER_SIZE,
};

use crate::error::AcceptorError;
use crate::error::AcceptorResult;

/// Standard I/O channel ID assigned by the server (MS-RDPBCGR convention).
///
/// Windows servers always allocate `0x03EB` (1003) for the I/O channel.
/// Static virtual channels are assigned sequentially starting at
/// `IO_CHANNEL_ID + 1`.
pub const IO_CHANNEL_ID: u16 = 0x03EB;

/// Maximum static virtual channels per MS-RDPBCGR §2.2.1.3.4 (also §2.2.1.4.4).
const MAX_STATIC_CHANNELS: usize = 31;

/// Decoded client data captured from the MCS Connect Initial GCC payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGccData {
    pub core: ClientCoreData,
    /// Optional CS_SECURITY (always present in practice).
    pub security: Option<ClientSecurityData>,
    pub cluster: Option<ClientClusterData>,
    pub network: Option<ClientNetworkData>,
    pub monitor: Option<ClientMonitorData>,
    pub monitor_ex: Option<ClientMonitorExtendedData>,
    pub message_channel: Option<ClientMessageChannelData>,
    pub multitransport: Option<ClientMultitransportChannelData>,
}

/// Parse the client GCC user_data section into structured blocks.
///
/// Tolerates blocks in any order and skips unknown block types (the spec
/// allows new block types to be added without breaking older receivers).
/// Rejects: malformed headers, blocks whose declared length undershoots
/// the header, blocks that overflow the available buffer.
pub fn parse_client_data_blocks(data: &[u8]) -> AcceptorResult<ClientGccData> {
    let mut core = None;
    let mut security = None;
    let mut cluster = None;
    let mut network = None;
    let mut monitor = None;
    let mut monitor_ex = None;
    let mut message_channel = None;
    let mut multitransport = None;

    // Walk the buffer with an absolute byte offset rather than threading
    // ReadCursor positions through reassignments. The outer loop:
    //   1. peeks the 4-byte header at `offset`
    //   2. constructs a per-block ReadCursor over `data[offset..offset+blen]`
    //   3. dispatches the appropriate decoder
    //   4. advances `offset += blen` regardless of how much the inner
    //      decoder consumed (keeps outer alignment glued to spec block
    //      boundaries; future-proofs against decoders that ignore
    //      trailing optional fields).
    let mut offset = 0usize;
    while data.len().saturating_sub(offset) >= DATA_BLOCK_HEADER_SIZE {
        // Peek header without committing.
        let mut hdr_cursor = ReadCursor::new(&data[offset..]);
        let (block_type, block_length) =
            read_block_header(&mut hdr_cursor, "ClientDataBlock::header")?;

        let block_length = block_length as usize;
        if block_length < DATA_BLOCK_HEADER_SIZE {
            return Err(AcceptorError::general(
                "client data block length smaller than 4-byte header",
            ));
        }
        let end = offset.checked_add(block_length).ok_or_else(|| {
            AcceptorError::general("client data block length overflows usize")
        })?;
        if end > data.len() {
            return Err(AcceptorError::general(
                "client data block length overflows GCC user_data",
            ));
        }

        let block_bytes = &data[offset..end];
        let mut block_cursor = ReadCursor::new(block_bytes);

        match block_type {
            t if t == ClientDataBlockType::CoreData as u16 => {
                core = Some(ClientCoreData::decode(&mut block_cursor)?);
            }
            t if t == ClientDataBlockType::SecurityData as u16 => {
                security = Some(ClientSecurityData::decode(&mut block_cursor)?);
            }
            t if t == ClientDataBlockType::ClusterData as u16 => {
                cluster = Some(ClientClusterData::decode(&mut block_cursor)?);
            }
            t if t == ClientDataBlockType::NetworkData as u16 => {
                network = Some(ClientNetworkData::decode(&mut block_cursor)?);
            }
            t if t == ClientDataBlockType::MonitorData as u16 => {
                monitor = Some(ClientMonitorData::decode(&mut block_cursor)?);
            }
            t if t == ClientDataBlockType::MonitorExtendedData as u16 => {
                monitor_ex = Some(ClientMonitorExtendedData::decode(&mut block_cursor)?);
            }
            t if t == ClientDataBlockType::MessageChannelData as u16 => {
                message_channel = Some(ClientMessageChannelData::decode(&mut block_cursor)?);
            }
            t if t == ClientDataBlockType::MultitransportChannelData as u16 => {
                multitransport = Some(ClientMultitransportChannelData::decode(&mut block_cursor)?);
            }
            _ => {
                // Unknown block type -- ignore but do not abort parsing.
            }
        }

        offset = end;
    }

    let core = core.ok_or_else(|| {
        AcceptorError::general("MCS Connect Initial GCC payload is missing CS_CORE")
    })?;
    Ok(ClientGccData {
        core,
        security,
        cluster,
        network,
        monitor,
        monitor_ex,
        message_channel,
        multitransport,
    })
}

/// Channel allocation result from `allocate_channel_ids`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAllocation {
    /// MCS I/O channel ID -- always `IO_CHANNEL_ID`.
    pub io_channel_id: u16,
    /// Static virtual channels: `(name, channel_id)` pairs, in the same
    /// order as the client requested them.
    pub static_channels: Vec<(String, u16)>,
    /// MCS message channel ID, if the client requested one and the
    /// server config allows it.
    pub message_channel_id: Option<u16>,
}

/// Allocate channel IDs for the I/O channel, the requested static
/// virtual channels, and the optional message channel.
///
/// Spec note (MS-RDPBCGR §2.2.1.4.4): the channel IDs in
/// `ServerNetworkData.channelIdArray` MUST appear in the same order as
/// the channels declared in `ClientNetworkData.channelDefArray` (the
/// client matches them by index). Allocation is sequential starting at
/// `IO_CHANNEL_ID + 1`. The message channel, if present, takes the
/// next free ID *after* the static channels.
pub fn allocate_channel_ids(
    client_channels: &[ChannelDef],
    enable_message_channel: bool,
) -> AcceptorResult<ChannelAllocation> {
    if client_channels.len() > MAX_STATIC_CHANNELS {
        return Err(AcceptorError::general(
            "client requested more than 31 static virtual channels",
        ));
    }

    let io_channel_id = IO_CHANNEL_ID;
    let mut next_id = io_channel_id + 1;

    let mut static_channels = Vec::with_capacity(client_channels.len());
    for ch in client_channels {
        let name = ch.name_str().into();
        static_channels.push((name, next_id));
        next_id = next_id.checked_add(1).ok_or_else(|| {
            AcceptorError::general("channel ID overflow while allocating static channels")
        })?;
    }

    let message_channel_id = if enable_message_channel {
        Some(next_id)
    } else {
        None
    };

    Ok(ChannelAllocation {
        io_channel_id,
        static_channels,
        message_channel_id,
    })
}

/// Inputs needed to build the server GCC data blocks.
pub struct ServerGccInputs<'a> {
    /// Server RDP version reported in `SC_CORE.version` (e.g. RDP 10.12 =
    /// `0x000A_0007` per MS-RDPBCGR §2.2.1.4.2).
    pub server_version: u32,
    /// Echo of the client's `requestedProtocols` from the X.224 CR. The
    /// spec recommends including this so the client can detect a MITM
    /// downgrade attempt.
    pub client_requested_protocols: u32,
    /// Optional `earlyCapabilityFlags` to advertise (RDP 10.x).
    pub early_capability_flags: Option<u32>,
    /// `(encryption_method, encryption_level)` pair for the SC_SECURITY
    /// block. For TLS/NLA both should be 0 (`ENCRYPTION_METHOD_NONE` /
    /// `ENCRYPTION_LEVEL_NONE`).
    pub encryption_method: u32,
    pub encryption_level: u32,
    /// Server random bytes (always 32) -- only present for Standard RDP
    /// Security. Pass `None` for TLS/NLA.
    pub server_random: Option<&'a [u8]>,
    /// Server certificate bytes -- only present for Standard RDP
    /// Security. Pass `None` for TLS/NLA.
    pub server_certificate: Option<&'a [u8]>,
    /// Allocation produced by `allocate_channel_ids`.
    pub channels: &'a ChannelAllocation,
    /// `SC_MULTITRANSPORT.flags` to advertise. `None` to omit the block.
    pub multitransport_flags: Option<u32>,
}

/// Build the concatenated server GCC data blocks (the `userData` field of
/// `ConferenceCreateResponse`).
///
/// MS-RDPBCGR §2.2.1.4 mandates the order Core -> Security -> Network ->
/// MessageChannel -> MultitransportChannel.
pub fn build_server_data_blocks(inputs: &ServerGccInputs<'_>) -> AcceptorResult<Vec<u8>> {
    let mut core = ServerCoreData::new(inputs.server_version);
    core.client_requested_protocols = Some(inputs.client_requested_protocols);
    if let Some(flags) = inputs.early_capability_flags {
        core.early_capability_flags = Some(flags);
    }

    let security = ServerSecurityData {
        encryption_method: inputs.encryption_method,
        encryption_level: inputs.encryption_level,
        server_random: inputs.server_random.map(|s| s.to_vec()),
        server_certificate: inputs.server_certificate.map(|s| s.to_vec()),
    };

    let static_ids: Vec<u16> = inputs
        .channels
        .static_channels
        .iter()
        .map(|(_, id)| *id)
        .collect();
    let network = ServerNetworkData {
        mcs_channel_id: inputs.channels.io_channel_id,
        channel_ids: static_ids,
    };

    let msg_block = inputs
        .channels
        .message_channel_id
        .map(|id| ServerMessageChannelData {
            mcs_message_channel_id: id,
        });
    let mt_block = inputs
        .multitransport_flags
        .map(|flags| ServerMultitransportChannelData { flags });

    // Compute total size.
    let mut total = core.size() + security.size() + network.size();
    if let Some(ref m) = msg_block {
        total += m.size();
    }
    if let Some(ref t) = mt_block {
        total += t.size();
    }

    let mut buf = vec![0u8; total];
    {
        let mut cursor = WriteCursor::new(&mut buf);
        core.encode(&mut cursor)?;
        security.encode(&mut cursor)?;
        network.encode(&mut cursor)?;
        if let Some(ref m) = msg_block {
            m.encode(&mut cursor)?;
        }
        if let Some(ref t) = mt_block {
            t.encode(&mut cursor)?;
        }
    }
    Ok(buf)
}

/// Wrap the server data blocks in a GCC ConferenceCreateResponse.
pub fn wrap_server_gcc(server_data: Vec<u8>) -> AcceptorResult<Vec<u8>> {
    let ccr = ConferenceCreateResponse::new(server_data);
    Ok(justrdp_core::encode_vec(&ccr)?)
}

/// Decode an MCS Connect Initial -> GCC -> client data blocks in one go.
pub fn decode_connect_initial_gcc(user_data: &[u8]) -> AcceptorResult<ClientGccData> {
    let mut cursor = ReadCursor::new(user_data);
    let gcc = ConferenceCreateRequest::decode(&mut cursor)?;
    parse_client_data_blocks(&gcc.user_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::gcc::client::{ChannelDef, ClientNetworkData};

    #[test]
    fn allocate_channel_ids_sequential() {
        let chans = vec![
            ChannelDef::new("rdpdr", 0),
            ChannelDef::new("rdpsnd", 0),
            ChannelDef::new("cliprdr", 0),
        ];
        let alloc = allocate_channel_ids(&chans, false).unwrap();
        assert_eq!(alloc.io_channel_id, IO_CHANNEL_ID);
        assert_eq!(alloc.static_channels.len(), 3);
        assert_eq!(alloc.static_channels[0].1, IO_CHANNEL_ID + 1);
        assert_eq!(alloc.static_channels[1].1, IO_CHANNEL_ID + 2);
        assert_eq!(alloc.static_channels[2].1, IO_CHANNEL_ID + 3);
        assert_eq!(alloc.static_channels[0].0, "rdpdr");
        assert_eq!(alloc.message_channel_id, None);
    }

    #[test]
    fn allocate_channel_ids_with_message_channel() {
        let chans = vec![ChannelDef::new("rdpdr", 0)];
        let alloc = allocate_channel_ids(&chans, true).unwrap();
        assert_eq!(alloc.io_channel_id, IO_CHANNEL_ID);
        assert_eq!(alloc.static_channels[0].1, IO_CHANNEL_ID + 1);
        assert_eq!(alloc.message_channel_id, Some(IO_CHANNEL_ID + 2));
    }

    #[test]
    fn allocate_channel_ids_no_static_with_message_channel() {
        let alloc = allocate_channel_ids(&[], true).unwrap();
        assert!(alloc.static_channels.is_empty());
        assert_eq!(alloc.message_channel_id, Some(IO_CHANNEL_ID + 1));
    }

    #[test]
    fn allocate_channel_ids_rejects_too_many() {
        let chans: Vec<ChannelDef> = (0..32)
            .map(|i| ChannelDef::new(&alloc::format!("c{i}"), 0))
            .collect();
        let err = allocate_channel_ids(&chans, false).unwrap_err();
        assert!(alloc::format!("{err}").contains("31"));
    }

    #[test]
    fn parse_client_data_blocks_minimum_core_only() {
        // Encode just CS_CORE
        let core = ClientCoreData::new(1024, 768);
        let mut buf = vec![0u8; core.size()];
        core.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        let parsed = parse_client_data_blocks(&buf).unwrap();
        assert_eq!(parsed.core.desktop_width, 1024);
        assert!(parsed.security.is_none());
        assert!(parsed.network.is_none());
    }

    #[test]
    fn parse_client_data_blocks_full_set() {
        let core = ClientCoreData::new(1920, 1080);
        let security = ClientSecurityData::new();
        let cluster = ClientClusterData {
            flags: 0x11,
            redirected_session_id: 0,
        };
        let network = ClientNetworkData {
            channels: vec![ChannelDef::new("rdpdr", 0xC000_0000)],
        };

        let total = core.size() + security.size() + cluster.size() + network.size();
        let mut buf = vec![0u8; total];
        {
            let mut c = WriteCursor::new(&mut buf);
            core.encode(&mut c).unwrap();
            security.encode(&mut c).unwrap();
            cluster.encode(&mut c).unwrap();
            network.encode(&mut c).unwrap();
        }
        let parsed = parse_client_data_blocks(&buf).unwrap();
        assert_eq!(parsed.core.desktop_width, 1920);
        assert!(parsed.security.is_some());
        assert!(parsed.cluster.is_some());
        assert_eq!(
            parsed.network.unwrap().channels[0].name_str(),
            "rdpdr"
        );
    }

    #[test]
    fn parse_client_data_blocks_rejects_missing_core() {
        // Just CS_SECURITY, no CS_CORE.
        let security = ClientSecurityData::new();
        let mut buf = vec![0u8; security.size()];
        security.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        let err = parse_client_data_blocks(&buf).unwrap_err();
        assert!(alloc::format!("{err}").contains("CS_CORE"));
    }

    #[test]
    fn parse_client_data_blocks_skips_unknown_type() {
        // Build CS_CORE then a bogus 0xFFFF block.
        let core = ClientCoreData::new(800, 600);
        let mut buf = vec![0u8; core.size()];
        core.encode(&mut WriteCursor::new(&mut buf)).unwrap();
        // Append an unknown 8-byte block (header + 4 bytes payload).
        let mut bogus = vec![0u8; 8];
        let mut cursor = WriteCursor::new(&mut bogus);
        cursor.write_u16_le(0xFFFF, "test::type").unwrap();
        cursor.write_u16_le(8, "test::length").unwrap();
        cursor.write_u32_le(0xDEAD_BEEF, "test::payload").unwrap();
        buf.extend_from_slice(&bogus);
        // Then a known CS_SECURITY after the unknown block.
        let security = ClientSecurityData::new();
        let mut sec_buf = vec![0u8; security.size()];
        security
            .encode(&mut WriteCursor::new(&mut sec_buf))
            .unwrap();
        buf.extend_from_slice(&sec_buf);

        let parsed = parse_client_data_blocks(&buf).unwrap();
        assert_eq!(parsed.core.desktop_width, 800);
        // The unknown block did not derail decoding the trailing
        // CS_SECURITY.
        assert!(parsed.security.is_some());
    }

    #[test]
    fn parse_client_data_blocks_rejects_overflow_length() {
        // CS_CORE header claiming length > available bytes.
        let mut buf = vec![0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor
            .write_u16_le(ClientDataBlockType::CoreData as u16, "type")
            .unwrap();
        // Length = 1024 but only 8 bytes available.
        cursor.write_u16_le(1024, "length").unwrap();
        cursor.write_u32_le(0, "payload").unwrap();
        let err = parse_client_data_blocks(&buf).unwrap_err();
        assert!(alloc::format!("{err}").contains("overflow"));
    }

    #[test]
    fn parse_client_data_blocks_rejects_undersized_length() {
        // length < header size (4).
        let mut buf = vec![0u8; 8];
        let mut cursor = WriteCursor::new(&mut buf);
        cursor
            .write_u16_le(ClientDataBlockType::CoreData as u16, "type")
            .unwrap();
        cursor.write_u16_le(2, "length").unwrap();
        cursor.write_u32_le(0, "payload").unwrap();
        let err = parse_client_data_blocks(&buf).unwrap_err();
        assert!(alloc::format!("{err}").contains("smaller than 4-byte header"));
    }

    #[test]
    fn build_server_data_blocks_tls_path() {
        let chans = vec![ChannelDef::new("rdpdr", 0), ChannelDef::new("snd", 0)];
        let alloc = allocate_channel_ids(&chans, true).unwrap();
        let inputs = ServerGccInputs {
            server_version: 0x0008_0004,
            client_requested_protocols: 0x0000_0003, // SSL|HYBRID
            early_capability_flags: Some(0x01),
            encryption_method: 0,
            encryption_level: 0,
            server_random: None,
            server_certificate: None,
            channels: &alloc,
            multitransport_flags: Some(0x101), // SOFTSYNC | TUNNEL_UDP_FECR
        };
        let bytes = build_server_data_blocks(&inputs).unwrap();
        // Decode round-trip: re-parse the buffer with the server-side
        // decoders to confirm wire correctness.
        let mut cursor = ReadCursor::new(&bytes);
        let core = ServerCoreData::decode(&mut cursor).unwrap();
        assert_eq!(core.version, 0x0008_0004);
        assert_eq!(core.client_requested_protocols, Some(3));
        assert_eq!(core.early_capability_flags, Some(0x01));
        let sec = ServerSecurityData::decode(&mut cursor).unwrap();
        assert_eq!(sec.encryption_method, 0);
        let net = ServerNetworkData::decode(&mut cursor).unwrap();
        assert_eq!(net.mcs_channel_id, IO_CHANNEL_ID);
        assert_eq!(net.channel_ids, vec![IO_CHANNEL_ID + 1, IO_CHANNEL_ID + 2]);
        let msg = ServerMessageChannelData::decode(&mut cursor).unwrap();
        assert_eq!(msg.mcs_message_channel_id, IO_CHANNEL_ID + 3);
        let mt = ServerMultitransportChannelData::decode(&mut cursor).unwrap();
        assert_eq!(mt.flags, 0x101);
    }
}
