//! T.125 MCS PDUs (plan.md §3 Layer 1): the BER-encoded Connect-Initial / Connect-Response pair
//! carrying the GCC conference payloads ([`crate::gcc`]), and the ALIGNED-PER domain PDUs that
//! follow them — Erect Domain, Attach User, and Channel Join.
//!
//! All of these ride inside an X.224 Data TPDU ([`crate::x224::encode_data`]) inside a TPKT
//! frame. This module produces and consumes the MCS payload only.
//!
//! Wire-format reference: ironrdp-pdu `mcs.rs` (the differential oracle).

use crate::cursor::ReadCursor;
use crate::error::DecodeError;
use crate::gcc::{ClientGccBlocks, ConferenceCreateResponse, encode_conference_create_request};
use crate::{ber, per};

/// `[APPLICATION 101]` — Connect-Initial.
const TAG_CONNECT_INITIAL: u8 = 101;
/// `[APPLICATION 102]` — Connect-Response.
const TAG_CONNECT_RESPONSE: u8 = 102;

/// The base every T.125 UserId is offset from in PER (`UserId ::= INTEGER (1001..65535)`).
pub const USER_CHANNEL_BASE: u16 = 1001;
/// The MCS I/O (global) channel servers conventionally assign.
pub const IO_CHANNEL_ID: u16 = 1003;
/// The `Result ::= ENUMERATED` cardinality (rt-successful = 0 … rt-user-rejected = 15).
const RESULT_ENUM_COUNT: u8 = 16;

/// DomainMCSPDU CHOICE indices (the application tag in the top 6 bits of the first byte).
const CHOICE_ERECT_DOMAIN: u8 = 1;
const CHOICE_ATTACH_USER_REQUEST: u8 = 10;
const CHOICE_ATTACH_USER_CONFIRM: u8 = 11;
const CHOICE_CHANNEL_JOIN_REQUEST: u8 = 14;
const CHOICE_CHANNEL_JOIN_CONFIRM: u8 = 15;

/// T.125 DomainParameters. The three parameter sets in the Connect-Initial are fixed
/// protocol-shaped values (every RDP client sends the same shapes); they carry no caller policy.
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
    /// The `targetParameters` every RDP client requests.
    pub fn target() -> Self {
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

    /// The `minimumParameters` floor.
    pub fn min() -> Self {
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

    /// The `maximumParameters` ceiling.
    pub fn max() -> Self {
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

    /// Append the BER SEQUENCE to `out`.
    fn encode_into(&self, out: &mut Vec<u8>) {
        let mut body = Vec::with_capacity(32);
        ber::write_integer(&mut body, self.max_channel_ids);
        ber::write_integer(&mut body, self.max_user_ids);
        ber::write_integer(&mut body, self.max_token_ids);
        ber::write_integer(&mut body, self.num_priorities);
        ber::write_integer(&mut body, self.min_throughput);
        ber::write_integer(&mut body, self.max_height);
        ber::write_integer(&mut body, self.max_mcs_pdu_size);
        ber::write_integer(&mut body, self.protocol_version);
        ber::write_sequence_tag(out, body.len() as u16);
        out.extend_from_slice(&body);
    }

    /// Decode the BER SEQUENCE.
    fn decode(cur: &mut ReadCursor<'_>) -> Result<Self, DecodeError> {
        ber::read_sequence_tag(cur)?;
        Ok(Self {
            max_channel_ids: ber::read_integer(cur)?,
            max_user_ids: ber::read_integer(cur)?,
            max_token_ids: ber::read_integer(cur)?,
            num_priorities: ber::read_integer(cur)?,
            min_throughput: ber::read_integer(cur)?,
            max_height: ber::read_integer(cur)?,
            max_mcs_pdu_size: ber::read_integer(cur)?,
            protocol_version: ber::read_integer(cur)?,
        })
    }
}

/// Encode an MCS Connect-Initial carrying `blocks` as its GCC Conference Create Request
/// payload. Returns the BER body; the caller wraps it in an X.224 Data TPDU + TPKT.
///
/// The domain selectors, upward flag, and parameter sets are the fixed values every RDP client
/// sends (protocol shape, not policy — the caller-controlled surface is entirely in `blocks`).
pub fn encode_connect_initial(blocks: &ClientGccBlocks) -> Vec<u8> {
    let user_data = encode_conference_create_request(blocks);

    let mut fields = Vec::with_capacity(user_data.len() + 64);
    ber::write_octet_string(&mut fields, &[0x01]); // callingDomainSelector
    ber::write_octet_string(&mut fields, &[0x01]); // calledDomainSelector
    ber::write_bool(&mut fields, true); // upwardFlag
    DomainParameters::target().encode_into(&mut fields);
    DomainParameters::min().encode_into(&mut fields);
    DomainParameters::max().encode_into(&mut fields);
    ber::write_octet_string(&mut fields, &user_data);

    let mut out = Vec::with_capacity(fields.len() + 5);
    ber::write_application_tag(&mut out, TAG_CONNECT_INITIAL, fields.len() as u16);
    out.extend_from_slice(&fields);
    out
}

/// A decoded MCS Connect-Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResponse {
    /// `result` (0 = rt-successful).
    pub result: u8,
    /// `calledConnectId`.
    pub called_connect_id: u32,
    /// The domain parameters the server settled on.
    pub domain_parameters: DomainParameters,
    /// The GCC Conference Create Response with the server's settings blocks.
    pub conference: ConferenceCreateResponse,
}

/// Decode an MCS Connect-Response from its BER body (the X.224 Data TPDU payload).
pub fn decode_connect_response(body: &[u8]) -> Result<ConnectResponse, DecodeError> {
    let mut cur = ReadCursor::new(body, "mcs connect response");
    ber::read_application_tag(&mut cur, TAG_CONNECT_RESPONSE)?;
    let result = ber::read_enumerated(&mut cur, RESULT_ENUM_COUNT)?;
    let called_connect_id = ber::read_integer(&mut cur)?;
    let domain_parameters = DomainParameters::decode(&mut cur)?;
    let user_data_len = ber::read_octet_string_tag(&mut cur)? as usize;
    let user_data = cur.read_slice(user_data_len.min(cur.remaining()))?;
    let conference = ConferenceCreateResponse::decode(user_data)?;
    Ok(ConnectResponse {
        result,
        called_connect_id,
        domain_parameters,
        conference,
    })
}

/// Encode an Erect Domain Request (`subHeight` = 0, `subInterval` = 0 — the values every RDP
/// client sends).
pub fn encode_erect_domain_request() -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    per::write_choice(&mut out, CHOICE_ERECT_DOMAIN << 2);
    per::write_u32(&mut out, 0); // subHeight
    per::write_u32(&mut out, 0); // subInterval
    out
}

/// Encode an Attach User Request (a bare CHOICE byte).
pub fn encode_attach_user_request() -> Vec<u8> {
    vec![CHOICE_ATTACH_USER_REQUEST << 2]
}

/// A decoded Attach User Confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachUserConfirm {
    /// `result` (0 = rt-successful).
    pub result: u8,
    /// The user channel ID the server assigned (the `initiator` for all later requests).
    pub initiator_id: u16,
}

/// Read and verify a DomainMCSPDU choice byte, returning it (low option bits included).
fn read_domain_choice(
    cur: &mut ReadCursor<'_>,
    expected: u8,
    name: &'static str,
) -> Result<(), DecodeError> {
    let choice = per::read_choice(cur)?;
    if choice >> 2 != expected {
        return Err(DecodeError::InvalidField {
            field: name,
            reason: "unexpected DomainMCSPDU choice",
        });
    }
    Ok(())
}

impl AttachUserConfirm {
    /// Decode from the MCS payload of an X.224 Data TPDU.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(body, "attach user confirm");
        read_domain_choice(&mut cur, CHOICE_ATTACH_USER_CONFIRM, "AttachUserConfirm")?;
        let result = per::read_enum(&mut cur, RESULT_ENUM_COUNT)?;
        let initiator_id = per::read_u16(&mut cur, USER_CHANNEL_BASE)?;
        Ok(Self {
            result,
            initiator_id,
        })
    }
}

/// Encode a Channel Join Request for `channel_id` on behalf of `initiator_id`.
pub fn encode_channel_join_request(initiator_id: u16, channel_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    per::write_choice(&mut out, CHOICE_CHANNEL_JOIN_REQUEST << 2);
    per::write_u16(&mut out, initiator_id, USER_CHANNEL_BASE)
        .expect("initiator is a server-assigned UserId >= 1001");
    per::write_u16(&mut out, channel_id, 0).expect("base 0 cannot underflow");
    out
}

/// A decoded Channel Join Confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelJoinConfirm {
    /// `result` (0 = rt-successful).
    pub result: u8,
    /// The requesting user channel ID, echoed back.
    pub initiator_id: u16,
    /// The channel ID the client asked to join.
    pub requested_channel_id: u16,
    /// The channel ID actually joined.
    pub channel_id: u16,
}

impl ChannelJoinConfirm {
    /// Decode from the MCS payload of an X.224 Data TPDU.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(body, "channel join confirm");
        read_domain_choice(&mut cur, CHOICE_CHANNEL_JOIN_CONFIRM, "ChannelJoinConfirm")?;
        let result = per::read_enum(&mut cur, RESULT_ENUM_COUNT)?;
        let initiator_id = per::read_u16(&mut cur, USER_CHANNEL_BASE)?;
        let requested_channel_id = per::read_u16(&mut cur, 0)?;
        let channel_id = per::read_u16(&mut cur, 0)?;
        Ok(Self {
            result,
            initiator_id,
            requested_channel_id,
            channel_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erect_domain_request_matches_the_canonical_bytes() {
        // CHOICE 1<<2, then PER INTEGER 0 twice (length 1, value 0).
        assert_eq!(
            encode_erect_domain_request(),
            vec![0x04, 0x01, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn attach_user_request_is_a_bare_choice_byte() {
        assert_eq!(encode_attach_user_request(), vec![0x28]);
    }

    #[test]
    fn channel_join_request_offsets_the_initiator_from_1001() {
        // initiator 1007 → 6; channel 1003 raw.
        assert_eq!(
            encode_channel_join_request(1007, 1003),
            vec![0x38, 0x00, 0x06, 0x03, 0xEB]
        );
    }

    #[test]
    fn attach_user_confirm_decodes_result_and_initiator() {
        // 0x2E = (11 << 2) | 2 (initiator present), result 0, initiator offset 6 → 1007.
        let confirm = AttachUserConfirm::decode(&[0x2E, 0x00, 0x00, 0x06]).unwrap();
        assert_eq!(
            confirm,
            AttachUserConfirm {
                result: 0,
                initiator_id: 1007,
            }
        );
    }

    #[test]
    fn channel_join_confirm_decodes_all_four_fields() {
        // 0x3E = (15 << 2) | 2, result 0, initiator 1007, requested 1003, joined 1003.
        let confirm =
            ChannelJoinConfirm::decode(&[0x3E, 0x00, 0x00, 0x06, 0x03, 0xEB, 0x03, 0xEB]).unwrap();
        assert_eq!(
            confirm,
            ChannelJoinConfirm {
                result: 0,
                initiator_id: 1007,
                requested_channel_id: 1003,
                channel_id: 1003,
            }
        );
    }

    #[test]
    fn wrong_domain_choice_is_rejected() {
        // An AttachUserConfirm fed to the ChannelJoinConfirm decoder must fail on the choice.
        let err = ChannelJoinConfirm::decode(&[0x2E, 0x00, 0x00, 0x06]).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidField { .. }));
    }

    #[test]
    fn domain_parameters_round_trip_through_ber() {
        for params in [
            DomainParameters::target(),
            DomainParameters::min(),
            DomainParameters::max(),
        ] {
            let mut out = Vec::new();
            params.encode_into(&mut out);
            let mut cur = ReadCursor::new(&out, "t");
            assert_eq!(DomainParameters::decode(&mut cur).unwrap(), params);
            assert_eq!(cur.remaining(), 0);
        }
    }
}
