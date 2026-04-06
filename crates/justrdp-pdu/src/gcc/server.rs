#![forbid(unsafe_code)]

//! GCC Server Data Blocks -- MS-RDPBCGR 2.2.1.4

use alloc::vec::Vec;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

use super::{write_block_header, read_block_header, ServerDataBlockType, DATA_BLOCK_HEADER_SIZE};

// ── ServerCoreData (SC_CORE 0x0C01) ──

/// Server Core Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCoreData {
    pub version: u32,
    pub client_requested_protocols: Option<u32>,
    pub early_capability_flags: Option<u32>,
}

impl ServerCoreData {
    pub fn new(version: u32) -> Self {
        Self {
            version,
            client_requested_protocols: None,
            early_capability_flags: None,
        }
    }
}

impl Encode for ServerCoreData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let size = self.size();
        if size > u16::MAX as usize {
            return Err(justrdp_core::EncodeError::other("ServerCoreData", "size exceeds u16"));
        }
        write_block_header(dst, ServerDataBlockType::CoreData as u16, size as u16, "ServerCoreData::header")?;
        dst.write_u32_le(self.version, "ServerCoreData::version")?;
        if let Some(v) = self.client_requested_protocols {
            dst.write_u32_le(v, "ServerCoreData::clientRequestedProtocols")?;
        } else {
            return Ok(());
        }
        if let Some(v) = self.early_capability_flags {
            dst.write_u32_le(v, "ServerCoreData::earlyCapabilityFlags")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "ServerCoreData" }

    fn size(&self) -> usize {
        let mut size = DATA_BLOCK_HEADER_SIZE + 4;
        if self.client_requested_protocols.is_some() { size += 4; } else { return size; }
        if self.early_capability_flags.is_some() { size += 4; }
        size
    }
}

impl<'de> Decode<'de> for ServerCoreData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, blen) = read_block_header(src, "ServerCoreData::header")?;
        if btype != ServerDataBlockType::CoreData as u16 {
            return Err(DecodeError::unexpected_value("ServerCoreData", "type", "expected 0x0C01"));
        }
        let data_len = (blen as usize).saturating_sub(DATA_BLOCK_HEADER_SIZE);
        let start = src.pos();

        let version = src.read_u32_le("ServerCoreData::version")?;
        let end_pos = start + data_len;

        macro_rules! rem {
            () => { end_pos.saturating_sub(src.pos()) };
        }

        let client_requested_protocols = if rem!() >= 4 {
            Some(src.read_u32_le("ServerCoreData::clientRequestedProtocols")?)
        } else { None };
        let early_capability_flags = if rem!() >= 4 {
            Some(src.read_u32_le("ServerCoreData::earlyCapabilityFlags")?)
        } else { None };

        let leftover = rem!();
        if leftover > 0 { src.skip(leftover, "ServerCoreData::unknown")?; }

        Ok(Self { version, client_requested_protocols, early_capability_flags })
    }
}

// ── ServerSecurityData (SC_SECURITY 0x0C02) ──

/// Server Security Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSecurityData {
    pub encryption_method: u32,
    pub encryption_level: u32,
    /// Optional: server random (32 bytes) + server certificate.
    /// Only present when encryption_method != 0 and encryption_level != 0.
    pub server_random: Option<Vec<u8>>,
    pub server_certificate: Option<Vec<u8>>,
}

impl ServerSecurityData {
    /// Create with no encryption (TLS/NLA mode).
    pub fn none() -> Self {
        Self {
            encryption_method: 0,
            encryption_level: 0,
            server_random: None,
            server_certificate: None,
        }
    }
}

impl Encode for ServerSecurityData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let size = self.size();
        if size > u16::MAX as usize {
            return Err(justrdp_core::EncodeError::other("ServerSecurityData", "size exceeds u16"));
        }
        write_block_header(dst, ServerDataBlockType::SecurityData as u16, size as u16, "ServerSecurityData::header")?;
        dst.write_u32_le(self.encryption_method, "ServerSecurityData::encryptionMethod")?;
        dst.write_u32_le(self.encryption_level, "ServerSecurityData::encryptionLevel")?;

        if let (Some(random), Some(cert)) = (&self.server_random, &self.server_certificate) {
            dst.write_u32_le(random.len() as u32, "ServerSecurityData::serverRandomLen")?;
            dst.write_u32_le(cert.len() as u32, "ServerSecurityData::serverCertificateLen")?;
            dst.write_slice(random, "ServerSecurityData::serverRandom")?;
            dst.write_slice(cert, "ServerSecurityData::serverCertificate")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "ServerSecurityData" }

    fn size(&self) -> usize {
        let mut size = DATA_BLOCK_HEADER_SIZE + 8; // header + method + level
        if let (Some(random), Some(cert)) = (&self.server_random, &self.server_certificate) {
            size += 4 + 4 + random.len() + cert.len(); // randomLen + certLen + data
        }
        size
    }
}

impl<'de> Decode<'de> for ServerSecurityData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, blen) = read_block_header(src, "ServerSecurityData::header")?;
        if btype != ServerDataBlockType::SecurityData as u16 {
            return Err(DecodeError::unexpected_value("ServerSecurityData", "type", "expected 0x0C02"));
        }
        let data_len = (blen as usize).saturating_sub(DATA_BLOCK_HEADER_SIZE);
        let start = src.pos();

        let encryption_method = src.read_u32_le("ServerSecurityData::encryptionMethod")?;
        let encryption_level = src.read_u32_le("ServerSecurityData::encryptionLevel")?;

        let remaining = data_len.saturating_sub(src.pos() - start);
        let (server_random, server_certificate) = if remaining >= 8 {
            let random_len = src.read_u32_le("ServerSecurityData::serverRandomLen")? as usize;
            let cert_len = src.read_u32_le("ServerSecurityData::serverCertificateLen")? as usize;
            // MS-RDPBCGR 2.2.1.4.3: server random is 32 bytes; certificate has a practical limit
            if random_len > 64 {
                return Err(DecodeError::unexpected_value("ServerSecurityData", "serverRandomLen", "exceeds maximum 64"));
            }
            if cert_len > 16384 {
                return Err(DecodeError::unexpected_value("ServerSecurityData", "serverCertificateLen", "exceeds maximum 16384"));
            }
            let random = src.read_slice(random_len, "ServerSecurityData::serverRandom")?.into();
            let cert = src.read_slice(cert_len, "ServerSecurityData::serverCertificate")?.into();
            (Some(random), Some(cert))
        } else {
            (None, None)
        };

        Ok(Self {
            encryption_method,
            encryption_level,
            server_random,
            server_certificate,
        })
    }
}

// ── ServerNetworkData (SC_NET 0x0C03) ──

/// Server Network Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerNetworkData {
    pub mcs_channel_id: u16,
    pub channel_ids: Vec<u16>,
}

impl Encode for ServerNetworkData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let size = self.size();
        if size > u16::MAX as usize {
            return Err(justrdp_core::EncodeError::other("ServerNetworkData", "size exceeds u16"));
        }
        write_block_header(dst, ServerDataBlockType::NetworkData as u16, size as u16, "ServerNetworkData::header")?;
        dst.write_u16_le(self.mcs_channel_id, "ServerNetworkData::mcsChannelId")?;
        dst.write_u16_le(self.channel_ids.len() as u16, "ServerNetworkData::channelCount")?;
        for &id in &self.channel_ids {
            dst.write_u16_le(id, "ServerNetworkData::channelId")?;
        }
        // Pad to 4-byte boundary if odd number of channels
        if self.channel_ids.len() % 2 != 0 {
            dst.write_u16_le(0, "ServerNetworkData::pad")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str { "ServerNetworkData" }

    fn size(&self) -> usize {
        let mut size = DATA_BLOCK_HEADER_SIZE + 2 + 2 + self.channel_ids.len() * 2;
        if self.channel_ids.len() % 2 != 0 {
            size += 2; // padding
        }
        size
    }
}

impl<'de> Decode<'de> for ServerNetworkData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, blen) = read_block_header(src, "ServerNetworkData::header")?;
        if btype != ServerDataBlockType::NetworkData as u16 {
            return Err(DecodeError::unexpected_value("ServerNetworkData", "type", "expected 0x0C03"));
        }
        let mcs_channel_id = src.read_u16_le("ServerNetworkData::mcsChannelId")?;
        let count = src.read_u16_le("ServerNetworkData::channelCount")? as usize;
        // MS-RDPBCGR 2.2.1.4.4: channelCount MUST be ≤ 31
        if count > 31 {
            return Err(DecodeError::unexpected_value("ServerNetworkData", "channelCount", "exceeds maximum 31"));
        }
        let mut channel_ids = Vec::with_capacity(count);
        for _ in 0..count {
            channel_ids.push(src.read_u16_le("ServerNetworkData::channelId")?);
        }
        // Skip padding
        let consumed = DATA_BLOCK_HEADER_SIZE + 2 + 2 + count * 2;
        let total = blen as usize;
        if total > consumed {
            src.skip(total - consumed, "ServerNetworkData::pad")?;
        }
        Ok(Self { mcs_channel_id, channel_ids })
    }
}

// ── ServerMessageChannelData (SC_MCS_MSGCHANNEL 0x0C04) ──

/// Server Message Channel Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerMessageChannelData {
    pub mcs_message_channel_id: u16,
}

const SERVER_MSG_CHANNEL_SIZE: usize = DATA_BLOCK_HEADER_SIZE + 2;

impl Encode for ServerMessageChannelData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_block_header(dst, ServerDataBlockType::MessageChannelData as u16, SERVER_MSG_CHANNEL_SIZE as u16, "ServerMsgChannel::header")?;
        dst.write_u16_le(self.mcs_message_channel_id, "ServerMsgChannel::channelId")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "ServerMessageChannelData" }
    fn size(&self) -> usize { SERVER_MSG_CHANNEL_SIZE }
}

impl<'de> Decode<'de> for ServerMessageChannelData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, _blen) = read_block_header(src, "ServerMsgChannel::header")?;
        if btype != ServerDataBlockType::MessageChannelData as u16 {
            return Err(DecodeError::unexpected_value("ServerMessageChannelData", "type", "expected 0x0C04"));
        }
        Ok(Self { mcs_message_channel_id: src.read_u16_le("ServerMsgChannel::channelId")? })
    }
}

// ── ServerMultitransportChannelData (SC_MULTITRANSPORT 0x0C08) ──

/// Server Multitransport Channel Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerMultitransportChannelData {
    pub flags: u32,
}

const SERVER_MULTITRANSPORT_SIZE: usize = DATA_BLOCK_HEADER_SIZE + 4;

impl Encode for ServerMultitransportChannelData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        write_block_header(dst, ServerDataBlockType::MultitransportChannelData as u16, SERVER_MULTITRANSPORT_SIZE as u16, "ServerMultitransport::header")?;
        dst.write_u32_le(self.flags, "ServerMultitransport::flags")?;
        Ok(())
    }

    fn name(&self) -> &'static str { "ServerMultitransportChannelData" }
    fn size(&self) -> usize { SERVER_MULTITRANSPORT_SIZE }
}

impl<'de> Decode<'de> for ServerMultitransportChannelData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let (btype, _blen) = read_block_header(src, "ServerMultitransport::header")?;
        if btype != ServerDataBlockType::MultitransportChannelData as u16 {
            return Err(DecodeError::unexpected_value("ServerMultitransportChannelData", "type", "expected 0x0C08"));
        }
        Ok(Self { flags: src.read_u32_le("ServerMultitransport::flags")? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_core_data_roundtrip() {
        let mut sc = ServerCoreData::new(0x00080004);
        sc.client_requested_protocols = Some(0x03);
        sc.early_capability_flags = Some(0x01);

        let size = sc.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        sc.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerCoreData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.version, 0x00080004);
        assert_eq!(decoded.client_requested_protocols, Some(0x03));
        assert_eq!(decoded.early_capability_flags, Some(0x01));
    }

    #[test]
    fn server_core_data_minimal() {
        let sc = ServerCoreData::new(0x00080004);
        let size = sc.size();
        assert_eq!(size, DATA_BLOCK_HEADER_SIZE + 4);

        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        sc.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerCoreData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.client_requested_protocols, None);
        assert_eq!(decoded.early_capability_flags, None);
    }

    #[test]
    fn server_security_data_none_roundtrip() {
        let ss = ServerSecurityData::none();
        let size = ss.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ss.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerSecurityData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.encryption_method, 0);
        assert_eq!(decoded.server_random, None);
    }

    #[test]
    fn server_security_data_with_crypto_roundtrip() {
        let ss = ServerSecurityData {
            encryption_method: 0x01,
            encryption_level: 0x02,
            server_random: Some(alloc::vec![0xAA; 32]),
            server_certificate: Some(alloc::vec![0xBB; 16]),
        };
        let size = ss.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ss.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerSecurityData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.encryption_method, 0x01);
        assert_eq!(decoded.server_random.as_ref().unwrap().len(), 32);
        assert_eq!(decoded.server_certificate.as_ref().unwrap().len(), 16);
    }

    #[test]
    fn server_network_data_roundtrip() {
        let sn = ServerNetworkData {
            mcs_channel_id: 0x03EC,
            channel_ids: alloc::vec![0x03ED, 0x03EE, 0x03EF],
        };
        let size = sn.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        sn.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerNetworkData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.mcs_channel_id, 0x03EC);
        assert_eq!(decoded.channel_ids, alloc::vec![0x03ED, 0x03EE, 0x03EF]);
    }

    #[test]
    fn server_network_data_even_channels() {
        let sn = ServerNetworkData {
            mcs_channel_id: 0x03EC,
            channel_ids: alloc::vec![0x03ED, 0x03EE],
        };
        let size = sn.size();
        // Even count: no padding
        assert_eq!(size, DATA_BLOCK_HEADER_SIZE + 2 + 2 + 4);
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        sn.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerNetworkData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.channel_ids.len(), 2);
    }

    #[test]
    fn server_message_channel_roundtrip() {
        let sm = ServerMessageChannelData { mcs_message_channel_id: 0x03F0 };
        let mut buf = [0u8; SERVER_MSG_CHANNEL_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        sm.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerMessageChannelData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.mcs_message_channel_id, 0x03F0);
    }

    #[test]
    fn server_multitransport_roundtrip() {
        let sm = ServerMultitransportChannelData { flags: 0x05 };
        let mut buf = [0u8; SERVER_MULTITRANSPORT_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        sm.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerMultitransportChannelData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.flags, 0x05);
    }

    #[test]
    fn server_core_data_one_optional_field() {
        let mut sc = ServerCoreData::new(0x00080004);
        sc.client_requested_protocols = Some(0x03);
        sc.early_capability_flags = None;

        let size = sc.size();
        assert_eq!(size, DATA_BLOCK_HEADER_SIZE + 4 + 4);
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        sc.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerCoreData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.client_requested_protocols, Some(0x03));
        assert_eq!(decoded.early_capability_flags, None);
    }

    #[test]
    fn server_network_data_zero_channels() {
        let sn = ServerNetworkData {
            mcs_channel_id: 0x03EC,
            channel_ids: alloc::vec![],
        };
        let size = sn.size();
        assert_eq!(size, DATA_BLOCK_HEADER_SIZE + 2 + 2); // header + mcsChId + count
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        sn.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ServerNetworkData::decode(&mut cursor).unwrap();
        assert_eq!(decoded.mcs_channel_id, 0x03EC);
        assert!(decoded.channel_ids.is_empty());
    }
}
