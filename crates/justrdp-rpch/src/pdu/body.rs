#![forbid(unsafe_code)]

//! Data-phase PDUs: REQUEST / RESPONSE / FAULT / AUTH3 and the
//! three body-less control PDUs SHUTDOWN, CO_CANCEL, ORPHANED.
//!
//! Specified in C706 §12.6.4.9 (REQUEST), §12.6.4.10 (RESPONSE),
//! §12.6.4.7 (FAULT), §12.6.4.14 (SHUTDOWN), §12.6.4.6 (CO_CANCEL),
//! §12.6.4.11 (ORPHANED), and MS-RPCE §2.2.2.9 (AUTH3 — Microsoft
//! extension that piggybacks the NTLM AUTHENTICATE message).

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

use super::auth::SecurityTrailer;
use super::common::{CommonHeader, COMMON_HEADER_SIZE, PFC_OBJECT_UUID};
use super::uuid::RpcUuid;

// =============================================================================
// PTYPE values
// =============================================================================

pub const REQUEST_PTYPE: u8 = 0x00;
pub const RESPONSE_PTYPE: u8 = 0x02;
pub const FAULT_PTYPE: u8 = 0x03;
pub const AUTH3_PTYPE: u8 = 0x10;
pub const SHUTDOWN_PTYPE: u8 = 0x11;
pub const CO_CANCEL_PTYPE: u8 = 0x12;
pub const ORPHANED_PTYPE: u8 = 0x13;

// =============================================================================
// Fault status codes (C706 Appendix E / MS-RPCE §2.2.2.6)
// =============================================================================

/// Access-denied fault as returned by **Microsoft RPC runtime**:
/// the Win32 `ERROR_ACCESS_DENIED` value rather than the DCE-style
/// `0x1C00_0009`. This is what RPCRT4.DLL places in FAULT PDUs seen
/// from Windows servers, so this is the value code compares against
/// when deciding "the server rejected this call".
pub const NCA_S_FAULT_ACCESS_DENIED: u32 = 0x0000_0005;
/// Canonical DCE value for access-denied fault (C706 Appendix E);
/// exists for completeness — Windows rarely emits this.
pub const NCA_S_FAULT_ACCESS_DENIED_DCE: u32 = 0x1C00_0009;

pub const NCA_S_FAULT_INVALID_BOUND: u32 = 0x1C00_0001;
pub const NCA_S_FAULT_CONTEXT_MISMATCH: u32 = 0x1C00_0004;
pub const NCA_S_FAULT_CANT_PERFORM: u32 = 0x1C01_0006;
pub const NCA_S_FAULT_NO_MEMORY: u32 = 0x1C00_0017;

// =============================================================================
// REQUEST
// =============================================================================

/// REQUEST PDU (`ptype == 0x00`, C706 §12.6.4.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPdu {
    pub pfc_flags: u8,
    pub call_id: u32,
    /// Hint for the server's buffer allocator; may be 0.
    pub alloc_hint: u32,
    /// Presentation-context ID previously accepted in BIND_ACK.
    pub context_id: u16,
    /// Operation number within the bound abstract interface.
    pub opnum: u16,
    /// Optional object UUID (for object-based RPC) — present on the
    /// wire iff [`PFC_OBJECT_UUID`] is set in `pfc_flags`.
    pub object: Option<RpcUuid>,
    /// NDR-marshaled argument data.
    pub stub_data: Vec<u8>,
    pub auth: Option<SecurityTrailer>,
}

impl RequestPdu {
    fn body_end_offset(&self) -> usize {
        let mut n = COMMON_HEADER_SIZE;
        n += 4 + 2 + 2; // alloc_hint + p_cont_id + opnum
        if self.object.is_some() {
            n += RpcUuid::SIZE;
        }
        n += self.stub_data.len();
        n
    }

    pub fn size(&self) -> usize {
        let body_end = self.body_end_offset();
        match &self.auth {
            None => body_end,
            Some(a) => {
                let pad = SecurityTrailer::pad_length_for(body_end);
                body_end + pad as usize + a.size()
            }
        }
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let mut flags = self.pfc_flags;
        if self.object.is_some() {
            flags |= PFC_OBJECT_UUID;
        } else {
            flags &= !PFC_OBJECT_UUID;
        }
        let hdr = CommonHeader {
            ptype: REQUEST_PTYPE,
            pfc_flags: flags,
            call_id: self.call_id,
        };
        let auth_length = self.auth.as_ref().map(|a| a.auth_length()).unwrap_or(0);
        hdr.encode(dst, self.size() as u16, auth_length)?;

        dst.write_u32_le(self.alloc_hint, "alloc_hint")?;
        dst.write_u16_le(self.context_id, "p_cont_id")?;
        dst.write_u16_le(self.opnum, "opnum")?;
        if let Some(u) = &self.object {
            u.encode(dst)?;
        }
        dst.write_slice(&self.stub_data, "stub_data")?;

        if let Some(a) = &self.auth {
            let body_end = dst.pos();
            let apad = SecurityTrailer::pad_length_for(body_end);
            if apad > 0 {
                dst.write_zeros(apad as usize, "auth_pad")?;
            }
            let mut trailer = a.clone();
            trailer.auth_pad_length = apad;
            trailer.encode(dst)?;
        }
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let (hdr, frag_length, auth_length) = CommonHeader::decode(src)?;
        if hdr.ptype != REQUEST_PTYPE {
            return Err(DecodeError::invalid_value("RequestPdu", "ptype"));
        }

        let alloc_hint = src.read_u32_le("alloc_hint")?;
        let context_id = src.read_u16_le("p_cont_id")?;
        let opnum = src.read_u16_le("opnum")?;
        let object = if hdr.pfc_flags & PFC_OBJECT_UUID != 0 {
            Some(RpcUuid::decode(src)?)
        } else {
            None
        };

        let stub_end = (frag_length as usize)
            .checked_sub(auth_length as usize)
            .and_then(|n| {
                if auth_length > 0 {
                    n.checked_sub(8)
                } else {
                    Some(n)
                }
            })
            .ok_or_else(|| DecodeError::invalid_value("RequestPdu", "frag_length"))?;

        // stub_end accounts for auth_pad_length implicitly: stub_data
        // is everything from current pos up to `stub_end` minus the
        // auth_pad bytes. We do not know auth_pad until we decode
        // the trailer header, so stash it and chop the pad afterwards.
        let stub_area_start = src.pos();
        if stub_end < stub_area_start {
            return Err(DecodeError::invalid_value(
                "RequestPdu",
                "stub_end < current position",
            ));
        }
        let stub_area = src.read_slice(stub_end - stub_area_start, "stub+pad")?;

        let (stub_data, auth) = if auth_length > 0 {
            let trailer = SecurityTrailer::decode(src, auth_length)?;
            let pad = trailer.auth_pad_length as usize;
            if pad > stub_area.len() {
                return Err(DecodeError::invalid_value(
                    "RequestPdu",
                    "auth_pad_length exceeds stub_data length",
                ));
            }
            let stub = stub_area[..stub_area.len() - pad].to_vec();
            (stub, Some(trailer))
        } else {
            (stub_area.to_vec(), None)
        };

        Ok(Self {
            pfc_flags: hdr.pfc_flags & !PFC_OBJECT_UUID,
            call_id: hdr.call_id,
            alloc_hint,
            context_id,
            opnum,
            object,
            stub_data,
            auth,
        })
    }
}

// =============================================================================
// RESPONSE
// =============================================================================

/// RESPONSE PDU (`ptype == 0x02`, C706 §12.6.4.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsePdu {
    pub pfc_flags: u8,
    pub call_id: u32,
    pub alloc_hint: u32,
    pub context_id: u16,
    /// Number of pending cancels the server saw before responding.
    pub cancel_count: u8,
    pub stub_data: Vec<u8>,
    pub auth: Option<SecurityTrailer>,
}

impl ResponsePdu {
    fn body_end_offset(&self) -> usize {
        COMMON_HEADER_SIZE + 4 + 2 + 1 + 1 + self.stub_data.len()
    }

    pub fn size(&self) -> usize {
        let body_end = self.body_end_offset();
        match &self.auth {
            None => body_end,
            Some(a) => body_end + SecurityTrailer::pad_length_for(body_end) as usize + a.size(),
        }
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let hdr = CommonHeader {
            ptype: RESPONSE_PTYPE,
            pfc_flags: self.pfc_flags,
            call_id: self.call_id,
        };
        let auth_length = self.auth.as_ref().map(|a| a.auth_length()).unwrap_or(0);
        hdr.encode(dst, self.size() as u16, auth_length)?;

        dst.write_u32_le(self.alloc_hint, "alloc_hint")?;
        dst.write_u16_le(self.context_id, "p_cont_id")?;
        dst.write_u8(self.cancel_count, "cancel_count")?;
        dst.write_u8(0, "reserved")?;
        dst.write_slice(&self.stub_data, "stub_data")?;

        if let Some(a) = &self.auth {
            let body_end = dst.pos();
            let apad = SecurityTrailer::pad_length_for(body_end);
            if apad > 0 {
                dst.write_zeros(apad as usize, "auth_pad")?;
            }
            let mut trailer = a.clone();
            trailer.auth_pad_length = apad;
            trailer.encode(dst)?;
        }
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let (hdr, frag_length, auth_length) = CommonHeader::decode(src)?;
        if hdr.ptype != RESPONSE_PTYPE {
            return Err(DecodeError::invalid_value("ResponsePdu", "ptype"));
        }
        let alloc_hint = src.read_u32_le("alloc_hint")?;
        let context_id = src.read_u16_le("p_cont_id")?;
        let cancel_count = src.read_u8("cancel_count")?;
        let _reserved = src.read_u8("reserved")?;

        let stub_area_start = src.pos();
        let stub_end = (frag_length as usize)
            .checked_sub(auth_length as usize)
            .and_then(|n| {
                if auth_length > 0 {
                    n.checked_sub(8)
                } else {
                    Some(n)
                }
            })
            .ok_or_else(|| DecodeError::invalid_value("ResponsePdu", "frag_length"))?;
        if stub_end < stub_area_start {
            return Err(DecodeError::invalid_value("ResponsePdu", "stub_end"));
        }
        let stub_area = src.read_slice(stub_end - stub_area_start, "stub+pad")?;

        let (stub_data, auth) = if auth_length > 0 {
            let trailer = SecurityTrailer::decode(src, auth_length)?;
            let pad = trailer.auth_pad_length as usize;
            if pad > stub_area.len() {
                return Err(DecodeError::invalid_value(
                    "ResponsePdu",
                    "auth_pad_length",
                ));
            }
            let stub = stub_area[..stub_area.len() - pad].to_vec();
            (stub, Some(trailer))
        } else {
            (stub_area.to_vec(), None)
        };

        Ok(Self {
            pfc_flags: hdr.pfc_flags,
            call_id: hdr.call_id,
            alloc_hint,
            context_id,
            cancel_count,
            stub_data,
            auth,
        })
    }
}

// =============================================================================
// FAULT
// =============================================================================

/// FAULT PDU (`ptype == 0x03`, C706 §12.6.4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPdu {
    pub pfc_flags: u8,
    pub call_id: u32,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    /// One of the `NCA_S_FAULT_*` constants above (or any other
    /// DCE/RPC fault code).
    pub status: u32,
    /// Optional NDR-marshaled fault detail.
    pub stub_data: Vec<u8>,
}

impl FaultPdu {
    pub fn size(&self) -> usize {
        COMMON_HEADER_SIZE + 4 + 2 + 1 + 1 + 4 + 4 + self.stub_data.len()
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let hdr = CommonHeader {
            ptype: FAULT_PTYPE,
            pfc_flags: self.pfc_flags,
            call_id: self.call_id,
        };
        hdr.encode(dst, self.size() as u16, 0)?;
        dst.write_u32_le(self.alloc_hint, "alloc_hint")?;
        dst.write_u16_le(self.context_id, "p_cont_id")?;
        dst.write_u8(self.cancel_count, "cancel_count")?;
        dst.write_u8(0, "reserved")?;
        dst.write_u32_le(self.status, "status")?;
        dst.write_u32_le(0, "reserved2")?;
        dst.write_slice(&self.stub_data, "stub_data")?;
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let (hdr, frag_length, auth_length) = CommonHeader::decode(src)?;
        if hdr.ptype != FAULT_PTYPE {
            return Err(DecodeError::invalid_value("FaultPdu", "ptype"));
        }
        let alloc_hint = src.read_u32_le("alloc_hint")?;
        let context_id = src.read_u16_le("p_cont_id")?;
        let cancel_count = src.read_u8("cancel_count")?;
        let _reserved = src.read_u8("reserved")?;
        let status = src.read_u32_le("status")?;
        let _reserved2 = src.read_u32_le("reserved2")?;

        // FAULT may carry stub_data plus an optional auth trailer.
        let stub_end = (frag_length as usize)
            .checked_sub(auth_length as usize)
            .and_then(|n| {
                if auth_length > 0 {
                    n.checked_sub(8)
                } else {
                    Some(n)
                }
            })
            .ok_or_else(|| DecodeError::invalid_value("FaultPdu", "frag_length"))?;
        let pos = src.pos();
        if stub_end < pos {
            return Err(DecodeError::invalid_value("FaultPdu", "stub_end"));
        }
        let stub_data = src.read_slice(stub_end - pos, "stub_data")?.to_vec();

        Ok(Self {
            pfc_flags: hdr.pfc_flags,
            call_id: hdr.call_id,
            alloc_hint,
            context_id,
            cancel_count,
            status,
            stub_data,
        })
    }
}

// =============================================================================
// AUTH3 (MS-RPCE §2.2.2.9)
// =============================================================================

/// AUTH3 PDU (`ptype == 0x10`).
///
/// Microsoft's extension that carries the third NTLM leg
/// (AUTHENTICATE) without requiring a REQUEST/RESPONSE round trip.
/// The body is just a 4-byte structural pad followed by a security
/// trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthThreePdu {
    pub pfc_flags: u8,
    pub call_id: u32,
    pub auth: SecurityTrailer,
}

impl AuthThreePdu {
    pub fn size(&self) -> usize {
        COMMON_HEADER_SIZE + 4 + self.auth.size()
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let hdr = CommonHeader {
            ptype: AUTH3_PTYPE,
            pfc_flags: self.pfc_flags,
            call_id: self.call_id,
        };
        hdr.encode(dst, self.size() as u16, self.auth.auth_length())?;
        dst.write_u32_le(0, "auth3_pad")?;
        self.auth.encode(dst)?;
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let (hdr, _frag, auth_length) = CommonHeader::decode(src)?;
        if hdr.ptype != AUTH3_PTYPE {
            return Err(DecodeError::invalid_value("AuthThreePdu", "ptype"));
        }
        let _pad = src.read_u32_le("auth3_pad")?;
        let auth = SecurityTrailer::decode(src, auth_length)?;
        Ok(Self {
            pfc_flags: hdr.pfc_flags,
            call_id: hdr.call_id,
            auth,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::auth::{RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_WINNT};
    use alloc::vec;

    #[test]
    fn request_roundtrip_no_auth_no_object() {
        let pdu = RequestPdu {
            pfc_flags: 0x03,
            call_id: 2,
            alloc_hint: 0x100,
            context_id: 0,
            opnum: 1,
            object: None,
            stub_data: vec![0x11, 0x22, 0x33, 0x44],
            auth: None,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size());

        let mut r = ReadCursor::new(&buf);
        let got = RequestPdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn request_roundtrip_with_object_uuid() {
        let pdu = RequestPdu {
            pfc_flags: 0x03,
            call_id: 2,
            alloc_hint: 0,
            context_id: 0,
            opnum: 5,
            object: Some(RpcUuid::parse("deadbeef-1234-5678-9abc-def012345678").unwrap()),
            stub_data: vec![0xAB; 16],
            auth: None,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();

        // Verify PFC_OBJECT_UUID got set in the encoded header.
        assert_eq!(buf[3] & PFC_OBJECT_UUID, PFC_OBJECT_UUID);

        let mut r = ReadCursor::new(&buf);
        let got = RequestPdu::decode(&mut r).unwrap();
        assert_eq!(got.object, pdu.object);
        assert_eq!(got.stub_data, pdu.stub_data);
    }

    #[test]
    fn request_roundtrip_with_auth_and_pad() {
        // 6-byte stub_data → trailer pad must be 2 to reach 4-byte
        // alignment.
        let stub = vec![1, 2, 3, 4, 5, 6];
        let pdu = RequestPdu {
            pfc_flags: 0x03,
            call_id: 2,
            alloc_hint: 0,
            context_id: 0,
            opnum: 1,
            object: None,
            stub_data: stub.clone(),
            auth: Some(SecurityTrailer {
                auth_type: RPC_C_AUTHN_WINNT,
                auth_level: RPC_C_AUTHN_LEVEL_CONNECT,
                auth_pad_length: 0, // will be recomputed on encode
                auth_context_id: 0,
                auth_value: vec![0xBE; 16],
            }),
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        let mut r = ReadCursor::new(&buf);
        let got = RequestPdu::decode(&mut r).unwrap();
        assert_eq!(got.stub_data, stub, "stub_data must be intact after pad");
        assert_eq!(got.auth.as_ref().unwrap().auth_value, vec![0xBE; 16]);
        // Verify auth_pad_length is set to reach alignment. body_end
        // before pad = 16 + 4 + 2 + 2 + 6 = 30 → pad = 2.
        assert_eq!(got.auth.unwrap().auth_pad_length, 2);
    }

    #[test]
    fn response_roundtrip() {
        let pdu = ResponsePdu {
            pfc_flags: 0x03,
            call_id: 2,
            alloc_hint: 0x1000,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![0xAA; 32],
            auth: None,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        let mut r = ReadCursor::new(&buf);
        let got = ResponsePdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn fault_roundtrip() {
        let pdu = FaultPdu {
            pfc_flags: 0x03,
            call_id: 2,
            alloc_hint: 0x20,
            context_id: 0,
            cancel_count: 0,
            status: NCA_S_FAULT_ACCESS_DENIED,
            stub_data: vec![],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        let mut r = ReadCursor::new(&buf);
        let got = FaultPdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn fault_status_codes_are_canonical() {
        // Windows RPC runtime uses the Win32 error code for access
        // denied; see the comment next to the constant definition.
        assert_eq!(NCA_S_FAULT_ACCESS_DENIED, 0x0000_0005);
        assert_eq!(NCA_S_FAULT_ACCESS_DENIED_DCE, 0x1C00_0009);
        // The rest match C706 Appendix E / MS-RPCE §2.2.2.6 exactly.
        assert_eq!(NCA_S_FAULT_INVALID_BOUND, 0x1C00_0001);
        assert_eq!(NCA_S_FAULT_CONTEXT_MISMATCH, 0x1C00_0004);
        assert_eq!(NCA_S_FAULT_CANT_PERFORM, 0x1C01_0006);
        assert_eq!(NCA_S_FAULT_NO_MEMORY, 0x1C00_0017);
    }

    #[test]
    fn auth3_roundtrip() {
        let pdu = AuthThreePdu {
            pfc_flags: 0x03,
            call_id: 3,
            auth: SecurityTrailer {
                auth_type: RPC_C_AUTHN_WINNT,
                auth_level: RPC_C_AUTHN_LEVEL_CONNECT,
                auth_pad_length: 0,
                auth_context_id: 0,
                auth_value: vec![0xAB; 24],
            },
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();

        // Verify the 4-byte structural pad at offset 16..20.
        assert_eq!(&buf[16..20], &[0, 0, 0, 0]);

        let mut r = ReadCursor::new(&buf);
        let got = AuthThreePdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn size_matches_encode_for_all_body_pdus() {
        // Helper closure to avoid copying the pattern 4x.
        let check = |pdu_size: usize, encoded: usize| assert_eq!(pdu_size, encoded);

        let req = RequestPdu {
            pfc_flags: 0x03,
            call_id: 1,
            alloc_hint: 0,
            context_id: 0,
            opnum: 0,
            object: None,
            stub_data: vec![0xDE, 0xAD],
            auth: None,
        };
        let mut buf = vec![0u8; req.size()];
        let mut w = WriteCursor::new(&mut buf);
        req.encode(&mut w).unwrap();
        check(req.size(), w.pos());

        let resp = ResponsePdu {
            pfc_flags: 0x03,
            call_id: 1,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![0xBE, 0xEF, 0xCA, 0xFE, 0xBA],
            auth: None,
        };
        let mut buf = vec![0u8; resp.size()];
        let mut w = WriteCursor::new(&mut buf);
        resp.encode(&mut w).unwrap();
        check(resp.size(), w.pos());

        let flt = FaultPdu {
            pfc_flags: 0x03,
            call_id: 1,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            status: NCA_S_FAULT_ACCESS_DENIED,
            stub_data: vec![],
        };
        let mut buf = vec![0u8; flt.size()];
        let mut w = WriteCursor::new(&mut buf);
        flt.encode(&mut w).unwrap();
        check(flt.size(), w.pos());

        let a3 = AuthThreePdu {
            pfc_flags: 0x03,
            call_id: 1,
            auth: SecurityTrailer {
                auth_type: 0,
                auth_level: 0,
                auth_pad_length: 0,
                auth_context_id: 0,
                auth_value: vec![],
            },
        };
        let mut buf = vec![0u8; a3.size()];
        let mut w = WriteCursor::new(&mut buf);
        a3.encode(&mut w).unwrap();
        check(a3.size(), w.pos());
    }

    #[test]
    fn request_reject_non_request_ptype() {
        // Encode a RESPONSE then try to decode as REQUEST.
        let resp = ResponsePdu {
            pfc_flags: 0x03,
            call_id: 1,
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            stub_data: vec![],
            auth: None,
        };
        let mut buf = vec![0u8; resp.size()];
        let mut w = WriteCursor::new(&mut buf);
        resp.encode(&mut w).unwrap();
        let mut r = ReadCursor::new(&buf);
        assert!(RequestPdu::decode(&mut r).is_err());
    }
}
