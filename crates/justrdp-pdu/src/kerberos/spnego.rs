#![forbid(unsafe_code)]

//! SPNEGO (RFC 4178) token encoding/decoding.
//!
//! SPNEGO wraps Kerberos AP-REQ/AP-REP tokens for use in CredSSP/NLA.

use alloc::vec::Vec;

use super::asn1::*;
use justrdp_core::DecodeResult;

/// SPNEGO NegTokenInit ::= SEQUENCE {
///     mechTypes    [0] MechTypeList,
///     reqFlags     [1] ContextFlags OPTIONAL,
///     mechToken    [2] OCTET STRING OPTIONAL,
///     mechListMIC  [3] OCTET STRING OPTIONAL
/// }
///
/// Wrapped in: [APPLICATION 0] {
///     thisOID OBJECT IDENTIFIER (SPNEGO),
///     innerToken [0] NegTokenInit
/// }
#[derive(Debug, Clone)]
pub struct NegTokenInit {
    pub mech_types: Vec<Vec<u8>>,    // list of OID raw bytes
    pub mech_token: Option<Vec<u8>>, // e.g., AP-REQ bytes
}

impl NegTokenInit {
    /// Encode as a SPNEGO InitialContextToken (RFC 2743 + RFC 4178).
    ///
    /// Structure: APPLICATION 0 { SPNEGO OID, [0] NegTokenInit }
    pub fn encode(&self) -> Vec<u8> {
        // Build inner NegTokenInit SEQUENCE
        let neg_token = build_sequence(|w| {
            // [0] mechTypes: SEQUENCE OF OID
            let mech_list = build_sequence(|w| {
                for oid in &self.mech_types {
                    w.write_oid(oid);
                }
            });
            let t0 = build_context_tag(0, |w| w.write_raw(&mech_list));
            w.write_raw(&t0);

            // [2] mechToken OPTIONAL
            if let Some(ref token) = self.mech_token {
                let t2 = build_context_tag(2, |w| w.write_octet_string(token));
                w.write_raw(&t2);
            }
        });

        // Wrap in APPLICATION 0 { OID, [0] NegTokenInit }
        build_application_tag(0, |w| {
            w.write_oid(OID_SPNEGO);
            let inner = build_context_tag(0, |w| w.write_raw(&neg_token));
            w.write_raw(&inner);
        })
    }
}

/// NegTokenResp / NegTokenTarg ::= SEQUENCE {
///     negState      [0] ENUMERATED OPTIONAL,
///     supportedMech [1] MechType OPTIONAL,
///     responseToken [2] OCTET STRING OPTIONAL,
///     mechListMIC   [3] OCTET STRING OPTIONAL
/// }
#[derive(Debug, Clone)]
pub struct NegTokenResp {
    pub neg_state: Option<NegState>,
    pub supported_mech: Option<Vec<u8>>, // OID raw bytes
    pub response_token: Option<Vec<u8>>,
    pub mech_list_mic: Option<Vec<u8>>,
}

/// SPNEGO negotiation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegState {
    AcceptCompleted = 0,
    AcceptIncomplete = 1,
    Reject = 2,
    RequestMic = 3,
}

impl NegTokenResp {
    /// Decode a NegTokenResp.
    ///
    /// The input may be wrapped in a context tag [1] (as sent by the server in CredSSP).
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);

        // May be wrapped in context [1]
        let tag = r.peek_tag()?;
        let mut seq = if tag == 0xa1 {
            let mut ctx = r.read_context_tag(1)?;
            ctx.read_sequence()?
        } else {
            r.read_sequence()?
        };

        // [0] negState OPTIONAL
        let neg_state = if let Some(mut t0) = seq.read_optional_context_tag(0)? {
            let val = t0.read_enumerated()?;
            Some(match val {
                0 => NegState::AcceptCompleted,
                1 => NegState::AcceptIncomplete,
                2 => NegState::Reject,
                3 => NegState::RequestMic,
                _ => NegState::Reject,
            })
        } else {
            None
        };

        // [1] supportedMech OPTIONAL
        let supported_mech = if let Some(mut t1) = seq.read_optional_context_tag(1)? {
            Some(t1.read_oid()?.to_vec())
        } else {
            None
        };

        // [2] responseToken OPTIONAL
        let response_token = if let Some(mut t2) = seq.read_optional_context_tag(2)? {
            Some(t2.read_octet_string()?.to_vec())
        } else {
            None
        };

        // [3] mechListMIC OPTIONAL
        let mech_list_mic = if let Some(mut t3) = seq.read_optional_context_tag(3)? {
            Some(t3.read_octet_string()?.to_vec())
        } else {
            None
        };

        Ok(Self {
            neg_state,
            supported_mech,
            response_token,
            mech_list_mic,
        })
    }

    /// Encode a NegTokenResp wrapped in context tag [1].
    pub fn encode(&self) -> Vec<u8> {
        let inner = build_sequence(|w| {
            // [0] negState
            if let Some(state) = self.neg_state {
                let t0 = build_context_tag(0, |w| w.write_enumerated(state as i32));
                w.write_raw(&t0);
            }
            // [1] supportedMech
            if let Some(ref mech) = self.supported_mech {
                let t1 = build_context_tag(1, |w| w.write_oid(mech));
                w.write_raw(&t1);
            }
            // [2] responseToken
            if let Some(ref token) = self.response_token {
                let t2 = build_context_tag(2, |w| w.write_octet_string(token));
                w.write_raw(&t2);
            }
            // [3] mechListMIC
            if let Some(ref mic) = self.mech_list_mic {
                let t3 = build_context_tag(3, |w| w.write_octet_string(mic));
                w.write_raw(&t3);
            }
        });
        // Wrap in context tag [1]
        build_context_tag(1, |w| w.write_raw(&inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn neg_token_init_roundtrip() {
        let init = NegTokenInit {
            mech_types: vec![OID_KRB5_RAW.to_vec(), OID_MS_KRB5.to_vec()],
            mech_token: Some(vec![0x01, 0x02, 0x03]),
        };
        let encoded = init.encode();
        // Verify it starts with APPLICATION 0
        assert_eq!(encoded[0], 0x60); // APPLICATION | CONSTRUCTED | 0
    }

    #[test]
    fn neg_token_resp_roundtrip() {
        let resp = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(OID_KRB5_RAW.to_vec()),
            response_token: Some(vec![0xAA, 0xBB]),
            mech_list_mic: None,
        };
        let encoded = resp.encode();
        let decoded = NegTokenResp::decode(&encoded).unwrap();
        assert_eq!(decoded.neg_state, Some(NegState::AcceptIncomplete));
        assert_eq!(decoded.supported_mech, Some(OID_KRB5_RAW.to_vec()));
        assert_eq!(decoded.response_token, Some(vec![0xAA, 0xBB]));
        assert_eq!(decoded.mech_list_mic, None);
    }
}
