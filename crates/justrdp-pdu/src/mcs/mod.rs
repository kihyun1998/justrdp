#![forbid(unsafe_code)]

//! MCS (Multipoint Communication Service) layer -- T.125
//!
//! MCS sits between the X.224 transport and the GCC/RDP upper layers.
//! It provides multipoint channel multiplexing.
//!
//! ## Encoding
//! - **Connect Initial / Response**: BER-encoded
//! - **All other Domain PDUs**: PER-encoded (aligned)

pub mod ber;
pub mod per;

use justrdp_core::{Decode, Encode, ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeResult};

// ── Domain Parameters ──

/// MCS Domain Parameters (used in Connect Initial / Response).
///
/// Encoded using BER as a SEQUENCE of INTEGERs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainParameters {
    pub max_channel_ids: u32,
    pub max_user_ids: u32,
    pub max_token_ids: u32,
    pub num_priorities: u32,
    pub min_throughput: u32,
    pub max_height: u32,
    pub max_mcs_pdu_size: u32,
    pub protocol_version: u32,
}

impl DomainParameters {
    /// Reasonable client defaults.
    pub fn client_default() -> Self {
        Self {
            max_channel_ids: 34,
            max_user_ids: 2,
            max_token_ids: 0,
            num_priorities: 1,
            min_throughput: 0,
            max_height: 1,
            max_mcs_pdu_size: 65535,
            protocol_version: 2,
        }
    }

    /// Minimum parameters.
    pub fn min_default() -> Self {
        Self {
            max_channel_ids: 1,
            max_user_ids: 1,
            max_token_ids: 1,
            num_priorities: 1,
            min_throughput: 0,
            max_height: 1,
            max_mcs_pdu_size: 1056,
            protocol_version: 2,
        }
    }

    /// Maximum parameters.
    pub fn max_default() -> Self {
        Self {
            max_channel_ids: 65535,
            max_user_ids: 64535,
            max_token_ids: 65535,
            num_priorities: 1,
            min_throughput: 0,
            max_height: 1,
            max_mcs_pdu_size: 65535,
            protocol_version: 2,
        }
    }

    fn content_size(&self) -> usize {
        ber::sizeof_integer(self.max_channel_ids as i64)
            + ber::sizeof_integer(self.max_user_ids as i64)
            + ber::sizeof_integer(self.max_token_ids as i64)
            + ber::sizeof_integer(self.num_priorities as i64)
            + ber::sizeof_integer(self.min_throughput as i64)
            + ber::sizeof_integer(self.max_height as i64)
            + ber::sizeof_integer(self.max_mcs_pdu_size as i64)
            + ber::sizeof_integer(self.protocol_version as i64)
    }
}

impl Encode for DomainParameters {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let content_size = self.content_size();
        ber::write_sequence_tag(dst, content_size, "DomainParameters")?;
        ber::write_integer(dst, self.max_channel_ids as i64, "DomainParameters::maxChannelIds")?;
        ber::write_integer(dst, self.max_user_ids as i64, "DomainParameters::maxUserIds")?;
        ber::write_integer(dst, self.max_token_ids as i64, "DomainParameters::maxTokenIds")?;
        ber::write_integer(dst, self.num_priorities as i64, "DomainParameters::numPriorities")?;
        ber::write_integer(dst, self.min_throughput as i64, "DomainParameters::minThroughput")?;
        ber::write_integer(dst, self.max_height as i64, "DomainParameters::maxHeight")?;
        ber::write_integer(dst, self.max_mcs_pdu_size as i64, "DomainParameters::maxMcsPduSize")?;
        ber::write_integer(dst, self.protocol_version as i64, "DomainParameters::protocolVersion")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DomainParameters"
    }

    fn size(&self) -> usize {
        ber::sizeof_sequence(self.content_size())
    }
}

impl<'de> Decode<'de> for DomainParameters {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let _content_len = ber::read_sequence_tag(src, "DomainParameters")?;
        Ok(Self {
            max_channel_ids: ber::read_integer_u32(src, "DomainParameters::maxChannelIds")?,
            max_user_ids: ber::read_integer_u32(src, "DomainParameters::maxUserIds")?,
            max_token_ids: ber::read_integer_u32(src, "DomainParameters::maxTokenIds")?,
            num_priorities: ber::read_integer_u32(src, "DomainParameters::numPriorities")?,
            min_throughput: ber::read_integer_u32(src, "DomainParameters::minThroughput")?,
            max_height: ber::read_integer_u32(src, "DomainParameters::maxHeight")?,
            max_mcs_pdu_size: ber::read_integer_u32(src, "DomainParameters::maxMcsPduSize")?,
            protocol_version: ber::read_integer_u32(src, "DomainParameters::protocolVersion")?,
        })
    }
}

// ── Connect Initial (BER) ──

/// MCS Connect Initial PDU (BER-encoded).
///
/// Carries domain parameters and GCC conference create request as user data.
/// Application tag = 101 (0x65 = 0x60 | 5, but per T.125 spec uses [APPLICATION 101]).
///
/// Wire: APPLICATION 101 IMPLICIT SEQUENCE { ... }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectInitial {
    /// Calling domain selector.
    pub calling_domain_selector: alloc::vec::Vec<u8>,
    /// Called domain selector.
    pub called_domain_selector: alloc::vec::Vec<u8>,
    /// Whether upward flag is set.
    pub upward_flag: bool,
    /// Target domain parameters.
    pub target_parameters: DomainParameters,
    /// Minimum domain parameters.
    pub minimum_parameters: DomainParameters,
    /// Maximum domain parameters.
    pub maximum_parameters: DomainParameters,
    /// User data (GCC ConferenceCreateRequest).
    pub user_data: alloc::vec::Vec<u8>,
}

/// BER application tag number for Connect Initial.
/// T.125 defines Connect-Initial as [APPLICATION 101].
/// In BER: class=application(01), constructed(1), tag=101 → 0x7F65
const CONNECT_INITIAL_TAG: u8 = 101;

/// BER application tag number for Connect Response.
const CONNECT_RESPONSE_TAG: u8 = 102;

impl ConnectInitial {
    fn content_size(&self) -> usize {
        ber::sizeof_octet_string(self.calling_domain_selector.len())
            + ber::sizeof_octet_string(self.called_domain_selector.len())
            + ber::sizeof_boolean()
            + self.target_parameters.size()
            + self.minimum_parameters.size()
            + self.maximum_parameters.size()
            + ber::sizeof_octet_string(self.user_data.len())
    }
}

impl Encode for ConnectInitial {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let content_size = self.content_size();
        // Write tag: APPLICATION 101 CONSTRUCTED
        // For tags > 30 in BER: first byte = class|constructed|0x1F, then tag number bytes
        write_high_tag(dst, 0x60, CONNECT_INITIAL_TAG, "ConnectInitial::tag")?;
        ber::write_length(dst, content_size, "ConnectInitial::length")?;

        ber::write_octet_string(dst, &self.calling_domain_selector, "ConnectInitial::callingDomainSelector")?;
        ber::write_octet_string(dst, &self.called_domain_selector, "ConnectInitial::calledDomainSelector")?;
        ber::write_boolean(dst, self.upward_flag, "ConnectInitial::upwardFlag")?;
        self.target_parameters.encode(dst)?;
        self.minimum_parameters.encode(dst)?;
        self.maximum_parameters.encode(dst)?;
        ber::write_octet_string(dst, &self.user_data, "ConnectInitial::userData")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "McsConnectInitial"
    }

    fn size(&self) -> usize {
        let content_size = self.content_size();
        high_tag_size(CONNECT_INITIAL_TAG) + ber::ber_length_size(content_size) + content_size
    }
}

#[cfg(feature = "alloc")]
impl<'de> Decode<'de> for ConnectInitial {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        read_high_tag(src, 0x60, CONNECT_INITIAL_TAG, "ConnectInitial::tag")?;
        let _content_len = ber::read_length(src, "ConnectInitial::length")?;

        let calling = ber::read_octet_string(src, "ConnectInitial::callingDomainSelector")?;
        let called = ber::read_octet_string(src, "ConnectInitial::calledDomainSelector")?;
        let upward_flag = ber::read_boolean(src, "ConnectInitial::upwardFlag")?;
        let target = DomainParameters::decode(src)?;
        let minimum = DomainParameters::decode(src)?;
        let maximum = DomainParameters::decode(src)?;
        let user_data = ber::read_octet_string(src, "ConnectInitial::userData")?;

        Ok(Self {
            calling_domain_selector: calling.into(),
            called_domain_selector: called.into(),
            upward_flag,
            target_parameters: target,
            minimum_parameters: minimum,
            maximum_parameters: maximum,
            user_data: user_data.into(),
        })
    }
}

// ── Connect Response (BER) ──

/// MCS Connect Response result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectResponseResult {
    RtSuccessful = 0,
    RtDomainMerging = 1,
    RtDomainNotHierarchical = 2,
    RtNoSuchChannel = 3,
    RtNoSuchDomain = 4,
    RtNoSuchUser = 5,
    RtNotAdmitted = 6,
    RtOtherUserId = 7,
    RtParametersUnacceptable = 8,
    RtTokenNotAvailable = 9,
    RtTokenNotPossessed = 10,
    RtTooManyChannels = 11,
    RtTooManyTokens = 12,
    RtTooManyUsers = 13,
    RtUnspecifiedFailure = 14,
    RtUserRejected = 15,
}

impl ConnectResponseResult {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            0 => Ok(Self::RtSuccessful),
            1 => Ok(Self::RtDomainMerging),
            2 => Ok(Self::RtDomainNotHierarchical),
            3 => Ok(Self::RtNoSuchChannel),
            4 => Ok(Self::RtNoSuchDomain),
            5 => Ok(Self::RtNoSuchUser),
            6 => Ok(Self::RtNotAdmitted),
            7 => Ok(Self::RtOtherUserId),
            8 => Ok(Self::RtParametersUnacceptable),
            9 => Ok(Self::RtTokenNotAvailable),
            10 => Ok(Self::RtTokenNotPossessed),
            11 => Ok(Self::RtTooManyChannels),
            12 => Ok(Self::RtTooManyTokens),
            13 => Ok(Self::RtTooManyUsers),
            14 => Ok(Self::RtUnspecifiedFailure),
            15 => Ok(Self::RtUserRejected),
            _ => Err(DecodeError::unexpected_value(
                "ConnectResponseResult",
                "result",
                "unknown result code",
            )),
        }
    }
}

/// MCS Connect Response PDU (BER-encoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResponse {
    /// Result of the connection attempt.
    pub result: ConnectResponseResult,
    /// Called connect ID.
    pub called_connect_id: u32,
    /// Domain parameters selected by the server.
    pub domain_parameters: DomainParameters,
    /// User data (GCC ConferenceCreateResponse).
    pub user_data: alloc::vec::Vec<u8>,
}

impl ConnectResponse {
    fn content_size(&self) -> usize {
        ber::sizeof_enumerated()
            + ber::sizeof_integer(self.called_connect_id as i64)
            + self.domain_parameters.size()
            + ber::sizeof_octet_string(self.user_data.len())
    }
}

impl Encode for ConnectResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let content_size = self.content_size();
        write_high_tag(dst, 0x60, CONNECT_RESPONSE_TAG, "ConnectResponse::tag")?;
        ber::write_length(dst, content_size, "ConnectResponse::length")?;

        ber::write_enumerated(dst, self.result as u8, "ConnectResponse::result")?;
        ber::write_integer(dst, self.called_connect_id as i64, "ConnectResponse::calledConnectId")?;
        self.domain_parameters.encode(dst)?;
        ber::write_octet_string(dst, &self.user_data, "ConnectResponse::userData")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "McsConnectResponse"
    }

    fn size(&self) -> usize {
        let content_size = self.content_size();
        high_tag_size(CONNECT_RESPONSE_TAG) + ber::ber_length_size(content_size) + content_size
    }
}

#[cfg(feature = "alloc")]
impl<'de> Decode<'de> for ConnectResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        read_high_tag(src, 0x60, CONNECT_RESPONSE_TAG, "ConnectResponse::tag")?;
        let _content_len = ber::read_length(src, "ConnectResponse::length")?;

        let result_val = ber::read_enumerated(src, "ConnectResponse::result")?;
        let result = ConnectResponseResult::from_u8(result_val)?;
        let called_connect_id = ber::read_integer_u32(src, "ConnectResponse::calledConnectId")?;
        let domain_parameters = DomainParameters::decode(src)?;
        let user_data = ber::read_octet_string(src, "ConnectResponse::userData")?;

        Ok(Self {
            result,
            called_connect_id,
            domain_parameters,
            user_data: user_data.into(),
        })
    }
}

// ── PER-encoded Domain PDUs ──

/// MCS Domain PDU type (PER CHOICE index).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DomainMcsPduType {
    ErectDomainRequest = 1,
    DisconnectProviderUltimatum = 8,
    AttachUserRequest = 10,
    AttachUserConfirm = 11,
    ChannelJoinRequest = 14,
    ChannelJoinConfirm = 15,
    SendDataRequest = 25,
    SendDataIndication = 26,
}

impl DomainMcsPduType {
    pub fn from_u8(val: u8) -> DecodeResult<Self> {
        match val {
            1 => Ok(Self::ErectDomainRequest),
            8 => Ok(Self::DisconnectProviderUltimatum),
            10 => Ok(Self::AttachUserRequest),
            11 => Ok(Self::AttachUserConfirm),
            14 => Ok(Self::ChannelJoinRequest),
            15 => Ok(Self::ChannelJoinConfirm),
            25 => Ok(Self::SendDataRequest),
            26 => Ok(Self::SendDataIndication),
            _ => Err(DecodeError::unexpected_value(
                "DomainMcsPduType",
                "choice",
                "unknown MCS PDU type",
            )),
        }
    }
}

/// Erect Domain Request (PER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErectDomainRequest {
    pub sub_height: u32,
    pub sub_interval: u32,
}

/// Fixed size: choice(1) + 2x PER integer(2) = 5.
pub const ERECT_DOMAIN_REQUEST_SIZE: usize = 5;

impl Encode for ErectDomainRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // DomainMCSPDU CHOICE index shifted left by 2 bits
        dst.write_u8((DomainMcsPduType::ErectDomainRequest as u8) << 2, "ErectDomainRequest::choice")?;
        per::write_integer_u16(dst, self.sub_height as u16, "ErectDomainRequest::subHeight")?;
        per::write_integer_u16(dst, self.sub_interval as u16, "ErectDomainRequest::subInterval")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ErectDomainRequest"
    }

    fn size(&self) -> usize {
        ERECT_DOMAIN_REQUEST_SIZE
    }
}

impl<'de> Decode<'de> for ErectDomainRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let choice = src.read_u8("ErectDomainRequest::choice")? >> 2;
        if choice != DomainMcsPduType::ErectDomainRequest as u8 {
            return Err(DecodeError::unexpected_value(
                "ErectDomainRequest",
                "choice",
                "expected ErectDomainRequest",
            ));
        }
        let sub_height = per::read_integer_u16(src, "ErectDomainRequest::subHeight")? as u32;
        let sub_interval = per::read_integer_u16(src, "ErectDomainRequest::subInterval")? as u32;
        Ok(Self {
            sub_height,
            sub_interval,
        })
    }
}

/// Attach User Request (PER).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachUserRequest;

impl Encode for AttachUserRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8((DomainMcsPduType::AttachUserRequest as u8) << 2, "AttachUserRequest::choice")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "AttachUserRequest"
    }

    fn size(&self) -> usize {
        1
    }
}

impl<'de> Decode<'de> for AttachUserRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let choice = src.read_u8("AttachUserRequest::choice")? >> 2;
        if choice != DomainMcsPduType::AttachUserRequest as u8 {
            return Err(DecodeError::unexpected_value(
                "AttachUserRequest",
                "choice",
                "expected AttachUserRequest",
            ));
        }
        Ok(Self)
    }
}

/// Attach User Confirm (PER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachUserConfirm {
    pub result: u8,
    pub initiator: Option<u16>,
}

impl Encode for AttachUserConfirm {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let has_initiator = self.initiator.is_some();
        let choice_byte = ((DomainMcsPduType::AttachUserConfirm as u8) << 2)
            | if has_initiator { 0x02 } else { 0x00 };
        dst.write_u8(choice_byte, "AttachUserConfirm::choice")?;
        per::write_enumerated(dst, self.result, "AttachUserConfirm::result")?;
        if let Some(initiator) = self.initiator {
            // User ID is channel_id - 1001
            per::write_integer_u16(dst, initiator.saturating_sub(1001), "AttachUserConfirm::initiator")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "AttachUserConfirm"
    }

    fn size(&self) -> usize {
        1 + 1 + if self.initiator.is_some() { 2 } else { 0 }
    }
}

impl<'de> Decode<'de> for AttachUserConfirm {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let byte = src.read_u8("AttachUserConfirm::choice")?;
        let choice = byte >> 2;
        if choice != DomainMcsPduType::AttachUserConfirm as u8 {
            return Err(DecodeError::unexpected_value(
                "AttachUserConfirm",
                "choice",
                "expected AttachUserConfirm",
            ));
        }
        let has_initiator = byte & 0x02 != 0;
        let result = per::read_enumerated(src, "AttachUserConfirm::result")?;
        let initiator = if has_initiator {
            Some(per::read_integer_u16(src, "AttachUserConfirm::initiator")? + 1001)
        } else {
            None
        };
        Ok(Self { result, initiator })
    }
}

/// Channel Join Request (PER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelJoinRequest {
    pub initiator: u16,
    pub channel_id: u16,
}

impl Encode for ChannelJoinRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8((DomainMcsPduType::ChannelJoinRequest as u8) << 2, "ChannelJoinRequest::choice")?;
        per::write_integer_u16(dst, self.initiator.saturating_sub(1001), "ChannelJoinRequest::initiator")?;
        per::write_integer_u16(dst, self.channel_id, "ChannelJoinRequest::channelId")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ChannelJoinRequest"
    }

    fn size(&self) -> usize {
        1 + per::sizeof_integer_u16(self.initiator.saturating_sub(1001) as u16)
          + per::sizeof_integer_u16(self.channel_id)
    }
}

impl<'de> Decode<'de> for ChannelJoinRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let choice = src.read_u8("ChannelJoinRequest::choice")? >> 2;
        if choice != DomainMcsPduType::ChannelJoinRequest as u8 {
            return Err(DecodeError::unexpected_value(
                "ChannelJoinRequest",
                "choice",
                "expected ChannelJoinRequest",
            ));
        }
        let initiator = per::read_integer_u16(src, "ChannelJoinRequest::initiator")? + 1001;
        let channel_id = per::read_integer_u16(src, "ChannelJoinRequest::channelId")?;
        Ok(Self {
            initiator,
            channel_id,
        })
    }
}

/// Channel Join Confirm (PER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelJoinConfirm {
    pub result: u8,
    pub initiator: u16,
    pub requested: u16,
    pub channel_id: Option<u16>,
}

impl Encode for ChannelJoinConfirm {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let has_channel = self.channel_id.is_some();
        let choice_byte = ((DomainMcsPduType::ChannelJoinConfirm as u8) << 2)
            | if has_channel { 0x02 } else { 0x00 };
        dst.write_u8(choice_byte, "ChannelJoinConfirm::choice")?;
        per::write_enumerated(dst, self.result, "ChannelJoinConfirm::result")?;
        per::write_integer_u16(dst, self.initiator.saturating_sub(1001), "ChannelJoinConfirm::initiator")?;
        per::write_integer_u16(dst, self.requested, "ChannelJoinConfirm::requested")?;
        if let Some(channel_id) = self.channel_id {
            per::write_integer_u16(dst, channel_id, "ChannelJoinConfirm::channelId")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ChannelJoinConfirm"
    }

    fn size(&self) -> usize {
        1 + 1 // choice + result
          + per::sizeof_integer_u16(self.initiator.saturating_sub(1001) as u16)
          + per::sizeof_integer_u16(self.requested)
          + if let Some(ch) = self.channel_id { per::sizeof_integer_u16(ch) } else { 0 }
    }
}

impl<'de> Decode<'de> for ChannelJoinConfirm {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let byte = src.read_u8("ChannelJoinConfirm::choice")?;
        let choice = byte >> 2;
        if choice != DomainMcsPduType::ChannelJoinConfirm as u8 {
            return Err(DecodeError::unexpected_value(
                "ChannelJoinConfirm",
                "choice",
                "expected ChannelJoinConfirm",
            ));
        }
        let has_channel = byte & 0x02 != 0;
        let result = per::read_enumerated(src, "ChannelJoinConfirm::result")?;
        let initiator = per::read_integer_u16(src, "ChannelJoinConfirm::initiator")? + 1001;
        let requested = per::read_integer_u16(src, "ChannelJoinConfirm::requested")?;
        let channel_id = if has_channel {
            Some(per::read_integer_u16(src, "ChannelJoinConfirm::channelId")?)
        } else {
            None
        };
        Ok(Self {
            result,
            initiator,
            requested,
            channel_id,
        })
    }
}

/// Send Data Request (PER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendDataRequest<'a> {
    pub initiator: u16,
    pub channel_id: u16,
    pub user_data: &'a [u8],
}

impl Encode for SendDataRequest<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8((DomainMcsPduType::SendDataRequest as u8) << 2, "SendDataRequest::choice")?;
        per::write_integer_u16(dst, self.initiator.saturating_sub(1001), "SendDataRequest::initiator")?;
        per::write_integer_u16(dst, self.channel_id, "SendDataRequest::channelId")?;
        // T.125 §11.33: dataPriority(high) + segmentation(begin|end) = 0b01_11_00_00 = 0x70
        dst.write_u8(0x70, "SendDataRequest::dataPriority")?;
        per::write_octet_string(dst, self.user_data, "SendDataRequest::userData")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SendDataRequest"
    }

    fn size(&self) -> usize {
        1 + per::sizeof_integer_u16(self.initiator.saturating_sub(1001) as u16)
          + per::sizeof_integer_u16(self.channel_id)
          + 1 // data priority
          + per::sizeof_octet_string(self.user_data.len())
    }
}

impl<'de> Decode<'de> for SendDataRequest<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let choice = src.read_u8("SendDataRequest::choice")? >> 2;
        if choice != DomainMcsPduType::SendDataRequest as u8 {
            return Err(DecodeError::unexpected_value(
                "SendDataRequest",
                "choice",
                "expected SendDataRequest",
            ));
        }
        let initiator = per::read_integer_u16(src, "SendDataRequest::initiator")? + 1001;
        let channel_id = per::read_integer_u16(src, "SendDataRequest::channelId")?;
        let _priority = src.read_u8("SendDataRequest::dataPriority")?;
        let user_data = per::read_octet_string(src, "SendDataRequest::userData")?;
        Ok(Self {
            initiator,
            channel_id,
            user_data,
        })
    }
}

/// Send Data Indication (PER) -- server to client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendDataIndication<'a> {
    pub initiator: u16,
    pub channel_id: u16,
    pub user_data: &'a [u8],
}

impl Encode for SendDataIndication<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u8((DomainMcsPduType::SendDataIndication as u8) << 2, "SendDataIndication::choice")?;
        per::write_integer_u16(dst, self.initiator.saturating_sub(1001), "SendDataIndication::initiator")?;
        per::write_integer_u16(dst, self.channel_id, "SendDataIndication::channelId")?;
        // T.125 §11.33: dataPriority(high) + segmentation(begin|end) = 0x70
        dst.write_u8(0x70, "SendDataIndication::dataPriority")?;
        per::write_octet_string(dst, self.user_data, "SendDataIndication::userData")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SendDataIndication"
    }

    fn size(&self) -> usize {
        1 + per::sizeof_integer_u16(self.initiator.saturating_sub(1001) as u16)
          + per::sizeof_integer_u16(self.channel_id)
          + 1 // data priority
          + per::sizeof_octet_string(self.user_data.len())
    }
}

impl<'de> Decode<'de> for SendDataIndication<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let choice = src.read_u8("SendDataIndication::choice")? >> 2;
        if choice != DomainMcsPduType::SendDataIndication as u8 {
            return Err(DecodeError::unexpected_value(
                "SendDataIndication",
                "choice",
                "expected SendDataIndication",
            ));
        }
        let initiator = per::read_integer_u16(src, "SendDataIndication::initiator")? + 1001;
        let channel_id = per::read_integer_u16(src, "SendDataIndication::channelId")?;
        let _priority = src.read_u8("SendDataIndication::dataPriority")?;
        let user_data = per::read_octet_string(src, "SendDataIndication::userData")?;
        Ok(Self {
            initiator,
            channel_id,
            user_data,
        })
    }
}

/// Disconnect Provider Ultimatum (PER).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectProviderUltimatum {
    pub reason: DisconnectReason,
}

/// MCS disconnect reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason {
    DomainDisconnected = 0,
    ProviderInitiated = 1,
    TokenPurged = 2,
    UserRequested = 3,
    ChannelPurged = 4,
}

impl DisconnectReason {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::DomainDisconnected,
            1 => Self::ProviderInitiated,
            2 => Self::TokenPurged,
            3 => Self::UserRequested,
            4 => Self::ChannelPurged,
            _ => Self::ProviderInitiated,
        }
    }
}

impl Encode for DisconnectProviderUltimatum {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // Choice index + reason packed into 1 byte:
        // bits 7-2 = choice (8), bits 1-0 = reason high bits
        // Then 1 more byte for reason low bits
        let choice = DomainMcsPduType::DisconnectProviderUltimatum as u8;
        let reason = self.reason as u8;
        // Pack: choice<<2 | (reason>>1)
        dst.write_u8((choice << 2) | (reason >> 1), "DisconnectProviderUltimatum::byte0")?;
        // Remaining bit of reason in high bit of next byte
        dst.write_u8((reason & 0x01) << 7, "DisconnectProviderUltimatum::byte1")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DisconnectProviderUltimatum"
    }

    fn size(&self) -> usize {
        2
    }
}

impl<'de> Decode<'de> for DisconnectProviderUltimatum {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let byte0 = src.read_u8("DisconnectProviderUltimatum::byte0")?;
        let byte1 = src.read_u8("DisconnectProviderUltimatum::byte1")?;
        let choice = byte0 >> 2;
        if choice != DomainMcsPduType::DisconnectProviderUltimatum as u8 {
            return Err(DecodeError::unexpected_value(
                "DisconnectProviderUltimatum",
                "choice",
                "expected DisconnectProviderUltimatum",
            ));
        }
        let reason = ((byte0 & 0x03) << 1) | (byte1 >> 7);
        Ok(Self {
            reason: DisconnectReason::from_u8(reason),
        })
    }
}

// ── High-tag BER helpers (for tags > 30) ──

/// Size of a high-tag BER tag encoding.
fn high_tag_size(tag_number: u8) -> usize {
    if tag_number < 128 {
        2 // class byte + 1 tag byte
    } else {
        3 // class byte + 2 tag bytes (not needed for MCS, but safe)
    }
}

/// Write a BER high-tag (tag number > 30).
fn write_high_tag(
    dst: &mut WriteCursor<'_>,
    class_bits: u8,
    tag_number: u8,
    ctx: &'static str,
) -> EncodeResult<()> {
    // First byte: class + constructed + 0x1F (means "long form tag")
    dst.write_u8(class_bits | 0x1F, ctx)?;
    // Tag number (for values < 128, single byte)
    dst.write_u8(tag_number & 0x7F, ctx)?;
    Ok(())
}

/// Read a BER high-tag.
fn read_high_tag(
    src: &mut ReadCursor<'_>,
    expected_class: u8,
    expected_number: u8,
    ctx: &'static str,
) -> DecodeResult<()> {
    let first = src.read_u8(ctx)?;
    if first != (expected_class | 0x1F) {
        return Err(DecodeError::unexpected_value(ctx, "tag class", "unexpected BER tag class"));
    }
    let tag_number = src.read_u8(ctx)?;
    if tag_number != (expected_number & 0x7F) {
        return Err(DecodeError::unexpected_value(ctx, "tag number", "unexpected BER tag number"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn domain_parameters_roundtrip() {
        let params = DomainParameters::client_default();
        let size = params.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        params.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = DomainParameters::decode(&mut cursor).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn connect_initial_roundtrip() {
        let ci = ConnectInitial {
            calling_domain_selector: alloc::vec![1],
            called_domain_selector: alloc::vec![1],
            upward_flag: true,
            target_parameters: DomainParameters::client_default(),
            minimum_parameters: DomainParameters::min_default(),
            maximum_parameters: DomainParameters::max_default(),
            user_data: alloc::vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let size = ci.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        ci.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConnectInitial::decode(&mut cursor).unwrap();
        assert_eq!(decoded, ci);
    }

    #[test]
    fn connect_response_roundtrip() {
        let cr = ConnectResponse {
            result: ConnectResponseResult::RtSuccessful,
            called_connect_id: 0,
            domain_parameters: DomainParameters::client_default(),
            user_data: alloc::vec![0xCA, 0xFE],
        };

        let size = cr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ConnectResponse::decode(&mut cursor).unwrap();
        assert_eq!(decoded, cr);
    }

    #[test]
    fn erect_domain_request_roundtrip() {
        let edr = ErectDomainRequest {
            sub_height: 0,
            sub_interval: 0,
        };
        let mut buf = [0u8; ERECT_DOMAIN_REQUEST_SIZE];
        let mut cursor = WriteCursor::new(&mut buf);
        edr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ErectDomainRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded, edr);
    }

    #[test]
    fn attach_user_request_roundtrip() {
        let aur = AttachUserRequest;
        let mut buf = [0u8; 1];
        let mut cursor = WriteCursor::new(&mut buf);
        aur.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = AttachUserRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded, aur);
    }

    #[test]
    fn attach_user_confirm_roundtrip() {
        let auc = AttachUserConfirm {
            result: 0,
            initiator: Some(1007),
        };
        let size = auc.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        auc.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = AttachUserConfirm::decode(&mut cursor).unwrap();
        assert_eq!(decoded, auc);
    }

    #[test]
    fn attach_user_confirm_no_initiator() {
        let auc = AttachUserConfirm {
            result: 14, // unspecified failure
            initiator: None,
        };
        let size = auc.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        auc.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = AttachUserConfirm::decode(&mut cursor).unwrap();
        assert_eq!(decoded, auc);
    }

    #[test]
    fn channel_join_request_roundtrip() {
        let cjr = ChannelJoinRequest {
            initiator: 1007,
            channel_id: 1003,
        };
        let size = cjr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cjr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ChannelJoinRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded, cjr);
    }

    #[test]
    fn channel_join_confirm_roundtrip() {
        let cjc = ChannelJoinConfirm {
            result: 0,
            initiator: 1007,
            requested: 1003,
            channel_id: Some(1003),
        };
        let size = cjc.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cjc.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = ChannelJoinConfirm::decode(&mut cursor).unwrap();
        assert_eq!(decoded, cjc);
    }

    #[test]
    fn send_data_request_roundtrip() {
        let payload = [0x01, 0x02, 0x03, 0x04];
        let sdr = SendDataRequest {
            initiator: 1007,
            channel_id: 1003,
            user_data: &payload,
        };
        let size = sdr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        sdr.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = SendDataRequest::decode(&mut cursor).unwrap();
        assert_eq!(decoded.initiator, 1007);
        assert_eq!(decoded.channel_id, 1003);
        assert_eq!(decoded.user_data, &payload);
    }

    #[test]
    fn send_data_indication_roundtrip() {
        let payload = [0xAA, 0xBB];
        let sdi = SendDataIndication {
            initiator: 1002,
            channel_id: 1003,
            user_data: &payload,
        };
        let size = sdi.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        sdi.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = SendDataIndication::decode(&mut cursor).unwrap();
        assert_eq!(decoded.initiator, 1002);
        assert_eq!(decoded.channel_id, 1003);
        assert_eq!(decoded.user_data, &payload);
    }

    #[test]
    fn disconnect_provider_ultimatum_roundtrip() {
        for reason in [
            DisconnectReason::DomainDisconnected,
            DisconnectReason::ProviderInitiated,
            DisconnectReason::UserRequested,
            DisconnectReason::ChannelPurged,
        ] {
            let dpu = DisconnectProviderUltimatum { reason };
            let mut buf = [0u8; 2];
            let mut cursor = WriteCursor::new(&mut buf);
            dpu.encode(&mut cursor).unwrap();

            let mut cursor = ReadCursor::new(&buf);
            let decoded = DisconnectProviderUltimatum::decode(&mut cursor).unwrap();
            assert_eq!(decoded.reason, reason);
        }
    }

    // ── Error path tests ──

    #[test]
    fn erect_domain_wrong_choice() {
        let buf = [0x00, 0x00, 0x00, 0x00, 0x00]; // choice=0 (wrong)
        let mut cursor = ReadCursor::new(&buf);
        assert!(ErectDomainRequest::decode(&mut cursor).is_err());
    }

    #[test]
    fn attach_user_confirm_wrong_choice() {
        let buf = [0x00, 0x00];
        let mut cursor = ReadCursor::new(&buf);
        assert!(AttachUserConfirm::decode(&mut cursor).is_err());
    }

    #[test]
    fn connect_response_bad_result() {
        // Build a ConnectResponse with bad result value
        let cr = ConnectResponse {
            result: ConnectResponseResult::RtSuccessful,
            called_connect_id: 0,
            domain_parameters: DomainParameters::client_default(),
            user_data: alloc::vec![],
        };
        let size = cr.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cr.encode(&mut cursor).unwrap();

        // Tamper: change the enumerated value to 99
        // Find the enumerated tag (0x0A) after the application tag+length
        for i in 0..buf.len() - 2 {
            if buf[i] == 0x0A && buf[i + 1] == 0x01 {
                buf[i + 2] = 99;
                break;
            }
        }

        let mut cursor = ReadCursor::new(&buf);
        assert!(ConnectResponse::decode(&mut cursor).is_err());
    }

    #[test]
    fn connect_initial_outer_tag_wire_bytes() {
        let ci = ConnectInitial {
            calling_domain_selector: vec![1],
            called_domain_selector: vec![1],
            upward_flag: true,
            target_parameters: DomainParameters::client_default(),
            minimum_parameters: DomainParameters::min_default(),
            maximum_parameters: DomainParameters::max_default(),
            user_data: vec![0x42],
        };
        let mut buf = alloc::vec![0u8; ci.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        ci.encode(&mut cursor).unwrap();
        // T.125 APPLICATION 101 CONSTRUCTED = 0x7F, 0x65
        assert_eq!(buf[0], 0x7F);
        assert_eq!(buf[1], 0x65);
    }

    #[test]
    fn channel_join_confirm_no_channel_id() {
        let cjc = ChannelJoinConfirm {
            result: 8, // failure
            initiator: 1007,
            requested: 1003,
            channel_id: None,
        };
        let size = cjc.size();
        let mut buf = alloc::vec![0u8; size];
        let mut cursor = WriteCursor::new(&mut buf);
        cjc.encode(&mut cursor).unwrap();
        // optional bit must be clear
        assert_eq!(buf[0] & 0x02, 0);
        let mut cursor = ReadCursor::new(&buf);
        let decoded = ChannelJoinConfirm::decode(&mut cursor).unwrap();
        assert_eq!(decoded.channel_id, None);
    }

    #[test]
    fn disconnect_provider_all_reasons_including_token_purged() {
        for reason in [
            DisconnectReason::DomainDisconnected,
            DisconnectReason::ProviderInitiated,
            DisconnectReason::TokenPurged,
            DisconnectReason::UserRequested,
            DisconnectReason::ChannelPurged,
        ] {
            let dpu = DisconnectProviderUltimatum { reason };
            let mut buf = [0u8; 2];
            let mut cursor = WriteCursor::new(&mut buf);
            dpu.encode(&mut cursor).unwrap();
            let mut cursor = ReadCursor::new(&buf);
            let decoded = DisconnectProviderUltimatum::decode(&mut cursor).unwrap();
            assert_eq!(decoded.reason, reason, "reason {:?} roundtrip failed", reason);
        }
    }
}
