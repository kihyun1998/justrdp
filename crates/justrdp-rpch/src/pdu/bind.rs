#![forbid(unsafe_code)]

//! Association setup PDUs: BIND / BIND_ACK / BIND_NAK plus their
//! ALTER_CONTEXT / ALTER_CONTEXT_RESPONSE siblings.
//!
//! Specified in C706 §12.6.4.3 (BIND), §12.6.4.4 (BIND_ACK),
//! §12.6.4.5 (BIND_NAK) and MS-RPCE §2.2.2.5–§2.2.2.6 (ALTER_CONTEXT
//! family). ALTER_CONTEXT has a body identical to BIND, and
//! ALTER_CONTEXT_RESPONSE to BIND_ACK, so the same Rust type is
//! reused with a different `ptype`.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

use super::auth::SecurityTrailer;
use super::common::{CommonHeader, COMMON_HEADER_SIZE};
use super::uuid::RpcUuid;

// =============================================================================
// PTYPE values
// =============================================================================

pub const BIND_PTYPE: u8 = 0x0B;
pub const BIND_ACK_PTYPE: u8 = 0x0C;
pub const BIND_NAK_PTYPE: u8 = 0x0D;
pub const ALTER_CONTEXT_PTYPE: u8 = 0x0E;
pub const ALTER_CONTEXT_RESPONSE_PTYPE: u8 = 0x0F;

// =============================================================================
// Result codes (C706 §12.6.4.4)
// =============================================================================

pub const RESULT_ACCEPTANCE: u16 = 0x0000;
pub const RESULT_USER_REJECTION: u16 = 0x0001;
pub const RESULT_PROVIDER_REJECTION: u16 = 0x0002;

// =============================================================================
// Provider-reject reasons (C706 §12.6.4.5)
// =============================================================================

pub const PROVIDER_REJECT_REASON_NOT_SPECIFIED: u16 = 0x0000;
pub const PROVIDER_REJECT_LOCAL_LIMIT_EXCEEDED: u16 = 0x0002;
pub const PROVIDER_REJECT_PROTOCOL_VERSION_NOT_SUPPORTED: u16 = 0x0004;

// =============================================================================
// Presentation-context primitives
// =============================================================================

/// 20-byte `p_syntax_id_t` — the combination of a 16-byte UUID and a
/// 4-byte interface version (major u16, minor u16) — used for both
/// the abstract syntax (the IDL interface) and each offered transfer
/// syntax (usually NDR 2.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntaxId {
    pub uuid: RpcUuid,
    pub version_major: u16,
    pub version_minor: u16,
}

impl SyntaxId {
    pub const SIZE: usize = 20;

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        self.uuid.encode(dst)?;
        dst.write_u16_le(self.version_major, "syntax.version_major")?;
        dst.write_u16_le(self.version_minor, "syntax.version_minor")?;
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let uuid = RpcUuid::decode(src)?;
        let version_major = src.read_u16_le("syntax.version_major")?;
        let version_minor = src.read_u16_le("syntax.version_minor")?;
        Ok(Self {
            uuid,
            version_major,
            version_minor,
        })
    }
}

/// `p_cont_elem_t` — a presentation-context element offered by the
/// client in BIND / ALTER_CONTEXT. It advertises one abstract
/// syntax (the IDL interface) and one or more candidate transfer
/// syntaxes the client can speak for that interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextElement {
    /// Caller-assigned presentation-context identifier. Must be
    /// unique within the association.
    pub context_id: u16,
    /// The RPC interface (e.g. TsProxy: `44e265dd-…` v1.3).
    pub abstract_syntax: SyntaxId,
    /// Ordered list of transfer syntaxes the caller can support
    /// (usually a single entry: NDR 2.0 `8a885d04-…` v2.0).
    pub transfer_syntaxes: Vec<SyntaxId>,
}

impl ContextElement {
    /// Wire size of this element.
    pub fn size(&self) -> usize {
        4 // p_cont_id(2) + n_transfer_syn(1) + reserved(1)
            + SyntaxId::SIZE
            + self.transfer_syntaxes.len() * SyntaxId::SIZE
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.context_id, "p_cont_id")?;
        let n = self.transfer_syntaxes.len();
        if n > u8::MAX as usize {
            return Err(
                justrdp_core::EncodeError::other("ContextElement", "too many transfer syntaxes"),
            );
        }
        // C706 §12.6.4.3 declares `p_cont_elem_t.n_transfer_syn` as
        // `unsigned short` (u16) plus 2 reserved bytes of padding,
        // yielding the same 4-byte slot we emit here. Windows
        // `RPCRT4` and every observed client implementation write
        // the count into the low byte only and leave the other three
        // bytes at zero, so `u8 + u8 + u16 reserved` is bytewise
        // indistinguishable on the wire. We keep the u8 form for
        // symmetry with existing Windows packet captures; the
        // `n > u8::MAX` guard above preserves the MS-RPCE practical
        // upper bound of 255 contexts.
        dst.write_u8(n as u8, "n_transfer_syn")?;
        dst.write_u8(0, "reserved")?;
        self.abstract_syntax.encode(dst)?;
        for ts in &self.transfer_syntaxes {
            ts.encode(dst)?;
        }
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let context_id = src.read_u16_le("p_cont_id")?;
        // See the matching comment on `encode` — we interpret
        // C706's `unsigned short n_transfer_syn` as u8 + 0 pad byte
        // to match Windows' wire layout.
        let n = src.read_u8("n_transfer_syn")? as usize;
        let _reserved = src.read_u8("reserved")?;
        let abstract_syntax = SyntaxId::decode(src)?;
        let mut transfer_syntaxes = Vec::with_capacity(n);
        for _ in 0..n {
            transfer_syntaxes.push(SyntaxId::decode(src)?);
        }
        Ok(Self {
            context_id,
            abstract_syntax,
            transfer_syntaxes,
        })
    }
}

/// A single entry of the server's `p_result_list_t` in BIND_ACK /
/// ALTER_CONTEXT_RESPONSE — one per context offered by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextResult {
    /// One of the `RESULT_*` constants.
    pub result: u16,
    /// Provider-reject reason (only meaningful if `result ==
    /// RESULT_PROVIDER_REJECTION`).
    pub reason: u16,
    /// Transfer syntax the server picked (zero UUID on rejection).
    pub transfer_syntax: SyntaxId,
}

impl ContextResult {
    pub const SIZE: usize = 4 + SyntaxId::SIZE;

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u16_le(self.result, "result")?;
        dst.write_u16_le(self.reason, "reason")?;
        self.transfer_syntax.encode(dst)?;
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let result = src.read_u16_le("result")?;
        let reason = src.read_u16_le("reason")?;
        let transfer_syntax = SyntaxId::decode(src)?;
        Ok(Self {
            result,
            reason,
            transfer_syntax,
        })
    }
}

// =============================================================================
// BIND / ALTER_CONTEXT
// =============================================================================

/// BIND PDU (`ptype == 0x0B`) or ALTER_CONTEXT PDU (`ptype == 0x0E`),
/// with identical wire body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindPdu {
    /// One of [`BIND_PTYPE`] or [`ALTER_CONTEXT_PTYPE`].
    pub ptype: u8,
    pub pfc_flags: u8,
    pub call_id: u32,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub contexts: Vec<ContextElement>,
    pub auth: Option<SecurityTrailer>,
}

impl BindPdu {
    /// Wire size including the common header, all contexts, any
    /// alignment padding to the auth trailer, and the auth trailer.
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

    fn body_end_offset(&self) -> usize {
        let mut n = COMMON_HEADER_SIZE;
        n += 2 + 2 + 4 + 1 + 3; // max_xmit + max_recv + assoc + n_ctx + 3 reserved
        for c in &self.contexts {
            n += c.size();
        }
        n
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let hdr = CommonHeader {
            ptype: self.ptype,
            pfc_flags: self.pfc_flags,
            call_id: self.call_id,
        };
        let frag_length = self.size();
        let auth_length = self.auth.as_ref().map(|a| a.auth_length()).unwrap_or(0);
        let body_end = self.body_end_offset();
        let pad = self
            .auth
            .as_ref()
            .map(|_| SecurityTrailer::pad_length_for(body_end))
            .unwrap_or(0);

        hdr.encode(dst, frag_length as u16, auth_length)?;

        dst.write_u16_le(self.max_xmit_frag, "max_xmit_frag")?;
        dst.write_u16_le(self.max_recv_frag, "max_recv_frag")?;
        dst.write_u32_le(self.assoc_group_id, "assoc_group_id")?;
        if self.contexts.len() > u8::MAX as usize {
            return Err(
                justrdp_core::EncodeError::other("BindPdu", "too many context elements"),
            );
        }
        dst.write_u8(self.contexts.len() as u8, "n_context_elem")?;
        dst.write_u8(0, "reserved1")?;
        dst.write_u8(0, "reserved2")?;
        dst.write_u8(0, "reserved3")?;
        for c in &self.contexts {
            c.encode(dst)?;
        }

        if let Some(a) = &self.auth {
            if pad > 0 {
                dst.write_zeros(pad as usize, "auth_pad")?;
            }
            // auth_pad_length is independent of the encoded trailer —
            // callers may override, but we compute it here.
            let mut trailer = a.clone();
            trailer.auth_pad_length = pad;
            trailer.encode(dst)?;
        }

        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let (hdr, frag_length, auth_length) = CommonHeader::decode(src)?;
        if hdr.ptype != BIND_PTYPE && hdr.ptype != ALTER_CONTEXT_PTYPE {
            return Err(DecodeError::invalid_value("BindPdu", "ptype"));
        }

        let max_xmit_frag = src.read_u16_le("max_xmit_frag")?;
        let max_recv_frag = src.read_u16_le("max_recv_frag")?;
        let assoc_group_id = src.read_u32_le("assoc_group_id")?;
        let n = src.read_u8("n_context_elem")? as usize;
        src.skip(3, "reserved")?;

        let mut contexts = Vec::with_capacity(n);
        for _ in 0..n {
            contexts.push(ContextElement::decode(src)?);
        }

        let auth = if auth_length > 0 {
            // Skip auth_pad bytes between stub/body and the trailer.
            // The pad count is in the trailer header, which we
            // haven't read yet. Inspect the pad byte directly.
            let body_end = src.pos();
            let declared_trailer_start = (frag_length as usize) - (auth_length as usize) - 8;
            if declared_trailer_start < body_end {
                return Err(DecodeError::invalid_value("BindPdu", "auth_pad_length"));
            }
            let pad = declared_trailer_start - body_end;
            src.skip(pad, "auth_pad")?;
            Some(SecurityTrailer::decode(src, auth_length)?)
        } else {
            None
        };

        Ok(Self {
            ptype: hdr.ptype,
            pfc_flags: hdr.pfc_flags,
            call_id: hdr.call_id,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            contexts,
            auth,
        })
    }
}

// =============================================================================
// BIND_ACK / ALTER_CONTEXT_RESPONSE
// =============================================================================

/// BIND_ACK (`ptype == 0x0C`) or ALTER_CONTEXT_RESPONSE
/// (`ptype == 0x0F`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindAckPdu {
    pub ptype: u8,
    pub pfc_flags: u8,
    pub call_id: u32,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    /// ASCII secondary address, NUL-terminated. Windows gateways
    /// typically return an empty string here (`b""`).
    pub sec_addr: Vec<u8>,
    pub results: Vec<ContextResult>,
    pub auth: Option<SecurityTrailer>,
}

impl BindAckPdu {
    fn sec_addr_field_size(&self) -> usize {
        // 2-byte length prefix + sec_addr bytes + NUL if not empty.
        if self.sec_addr.is_empty() {
            2
        } else if self.sec_addr.last() == Some(&0) {
            2 + self.sec_addr.len()
        } else {
            2 + self.sec_addr.len() + 1
        }
    }

    fn body_end_offset(&self) -> usize {
        let mut n = COMMON_HEADER_SIZE;
        n += 2 + 2 + 4; // max_xmit, max_recv, assoc_group
        n += self.sec_addr_field_size();
        // Pad to 4-byte boundary after sec_addr.
        let pad_sec = (4 - (n & 3)) & 3;
        n += pad_sec;
        n += 1 + 3; // n_results + 3 reserved
        n += self.results.len() * ContextResult::SIZE;
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
        let hdr = CommonHeader {
            ptype: self.ptype,
            pfc_flags: self.pfc_flags,
            call_id: self.call_id,
        };
        let frag_length = self.size();
        let auth_length = self.auth.as_ref().map(|a| a.auth_length()).unwrap_or(0);
        hdr.encode(dst, frag_length as u16, auth_length)?;

        dst.write_u16_le(self.max_xmit_frag, "max_xmit_frag")?;
        dst.write_u16_le(self.max_recv_frag, "max_recv_frag")?;
        dst.write_u32_le(self.assoc_group_id, "assoc_group_id")?;

        // sec_addr field: a 2-byte length (including NUL) and the
        // bytes. Pad to 4-byte alignment afterwards.
        let sec = if self.sec_addr.is_empty() {
            Vec::new()
        } else if self.sec_addr.last() == Some(&0) {
            self.sec_addr.clone()
        } else {
            let mut v = self.sec_addr.clone();
            v.push(0);
            v
        };
        dst.write_u16_le(sec.len() as u16, "sec_addr_length")?;
        if !sec.is_empty() {
            dst.write_slice(&sec, "sec_addr")?;
        }
        let after_sec = dst.pos();
        let pad = (4 - (after_sec & 3)) & 3;
        if pad > 0 {
            dst.write_zeros(pad, "sec_addr_pad")?;
        }

        if self.results.len() > u8::MAX as usize {
            return Err(
                justrdp_core::EncodeError::other("BindAckPdu", "too many results"),
            );
        }
        dst.write_u8(self.results.len() as u8, "n_results")?;
        dst.write_u8(0, "reserved1")?;
        dst.write_u8(0, "reserved2")?;
        dst.write_u8(0, "reserved3")?;
        for r in &self.results {
            r.encode(dst)?;
        }

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
        if hdr.ptype != BIND_ACK_PTYPE && hdr.ptype != ALTER_CONTEXT_RESPONSE_PTYPE {
            return Err(DecodeError::invalid_value("BindAckPdu", "ptype"));
        }

        let max_xmit_frag = src.read_u16_le("max_xmit_frag")?;
        let max_recv_frag = src.read_u16_le("max_recv_frag")?;
        let assoc_group_id = src.read_u32_le("assoc_group_id")?;
        let sec_len = src.read_u16_le("sec_addr_length")? as usize;
        let sec_bytes = if sec_len == 0 {
            Vec::new()
        } else {
            src.read_slice(sec_len, "sec_addr")?.to_vec()
        };
        // Strip trailing NUL to match the struct convention.
        let sec_addr = if sec_bytes.last() == Some(&0) {
            sec_bytes[..sec_bytes.len() - 1].to_vec()
        } else {
            sec_bytes
        };
        let after_sec = src.pos();
        let pad = (4 - (after_sec & 3)) & 3;
        src.skip(pad, "sec_addr_pad")?;

        let n = src.read_u8("n_results")? as usize;
        src.skip(3, "reserved")?;
        let mut results = Vec::with_capacity(n);
        for _ in 0..n {
            results.push(ContextResult::decode(src)?);
        }

        let auth = if auth_length > 0 {
            let body_end = src.pos();
            let declared_trailer_start = (frag_length as usize) - (auth_length as usize) - 8;
            if declared_trailer_start < body_end {
                return Err(DecodeError::invalid_value(
                    "BindAckPdu",
                    "auth_pad_length",
                ));
            }
            let apad = declared_trailer_start - body_end;
            src.skip(apad, "auth_pad")?;
            Some(SecurityTrailer::decode(src, auth_length)?)
        } else {
            None
        };

        Ok(Self {
            ptype: hdr.ptype,
            pfc_flags: hdr.pfc_flags,
            call_id: hdr.call_id,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            sec_addr,
            results,
            auth,
        })
    }
}

// =============================================================================
// BIND_NAK
// =============================================================================

/// BIND_NAK (`ptype == 0x0D`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindNakPdu {
    pub pfc_flags: u8,
    pub call_id: u32,
    /// One of the `PROVIDER_REJECT_*` constants above.
    pub provider_reject_reason: u16,
    /// List of protocol versions the server supports, as `(major,
    /// minor)` pairs.
    pub versions: Vec<(u8, u8)>,
}

impl BindNakPdu {
    pub fn size(&self) -> usize {
        COMMON_HEADER_SIZE + 2 + 1 + 3 + self.versions.len() * 2
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let hdr = CommonHeader {
            ptype: BIND_NAK_PTYPE,
            pfc_flags: self.pfc_flags,
            call_id: self.call_id,
        };
        hdr.encode(dst, self.size() as u16, 0)?;
        dst.write_u16_le(self.provider_reject_reason, "provider_reject_reason")?;
        if self.versions.len() > u8::MAX as usize {
            return Err(
                justrdp_core::EncodeError::other("BindNakPdu", "too many versions"),
            );
        }
        dst.write_u8(self.versions.len() as u8, "n_protocols")?;
        dst.write_u8(0, "reserved1")?;
        dst.write_u8(0, "reserved2")?;
        dst.write_u8(0, "reserved3")?;
        for (major, minor) in &self.versions {
            dst.write_u8(*major, "protocol.major")?;
            dst.write_u8(*minor, "protocol.minor")?;
        }
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let (hdr, _frag, _auth) = CommonHeader::decode(src)?;
        if hdr.ptype != BIND_NAK_PTYPE {
            return Err(DecodeError::invalid_value("BindNakPdu", "ptype"));
        }
        let provider_reject_reason = src.read_u16_le("provider_reject_reason")?;
        let n = src.read_u8("n_protocols")? as usize;
        src.skip(3, "reserved")?;
        let mut versions = Vec::with_capacity(n);
        for _ in 0..n {
            let major = src.read_u8("protocol.major")?;
            let minor = src.read_u8("protocol.minor")?;
            versions.push((major, minor));
        }
        Ok(Self {
            pfc_flags: hdr.pfc_flags,
            call_id: hdr.call_id,
            provider_reject_reason,
            versions,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::common::{PFC_FIRST_FRAG, PFC_LAST_FRAG};
    use alloc::vec;

    fn ndr20() -> SyntaxId {
        SyntaxId {
            uuid: RpcUuid::parse("8a885d04-1ceb-11c9-9fe8-08002b104860").unwrap(),
            version_major: 2,
            version_minor: 0,
        }
    }

    fn tsproxy_abstract() -> SyntaxId {
        SyntaxId {
            uuid: RpcUuid::parse("44e265dd-7daf-42cd-8560-3cdb6e7a2729").unwrap(),
            version_major: 1,
            version_minor: 3,
        }
    }

    #[test]
    fn syntax_id_roundtrip() {
        let s = ndr20();
        let mut buf = vec![0u8; SyntaxId::SIZE];
        let mut w = WriteCursor::new(&mut buf);
        s.encode(&mut w).unwrap();
        assert_eq!(w.pos(), SyntaxId::SIZE);

        let mut r = ReadCursor::new(&buf);
        let got = SyntaxId::decode(&mut r).unwrap();
        assert_eq!(got, s);
    }

    #[test]
    fn context_element_roundtrip() {
        let c = ContextElement {
            context_id: 0,
            abstract_syntax: tsproxy_abstract(),
            transfer_syntaxes: vec![ndr20()],
        };
        let mut buf = vec![0u8; c.size()];
        let mut w = WriteCursor::new(&mut buf);
        c.encode(&mut w).unwrap();

        let mut r = ReadCursor::new(&buf);
        let got = ContextElement::decode(&mut r).unwrap();
        assert_eq!(got, c);
    }

    #[test]
    fn context_element_size_matches_encode() {
        let c = ContextElement {
            context_id: 0,
            abstract_syntax: tsproxy_abstract(),
            transfer_syntaxes: vec![ndr20(), ndr20()],
        };
        let mut buf = vec![0u8; c.size() + 10];
        let mut w = WriteCursor::new(&mut buf);
        c.encode(&mut w).unwrap();
        assert_eq!(w.pos(), c.size());
    }

    #[test]
    fn bind_roundtrip_no_auth() {
        let pdu = BindPdu {
            ptype: BIND_PTYPE,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            contexts: vec![ContextElement {
                context_id: 0,
                abstract_syntax: tsproxy_abstract(),
                transfer_syntaxes: vec![ndr20()],
            }],
            auth: None,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size());

        let mut r = ReadCursor::new(&buf);
        let got = BindPdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn bind_roundtrip_with_ntlm_auth() {
        let pdu = BindPdu {
            ptype: BIND_PTYPE,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            contexts: vec![ContextElement {
                context_id: 0,
                abstract_syntax: tsproxy_abstract(),
                transfer_syntaxes: vec![ndr20()],
            }],
            auth: Some(SecurityTrailer {
                auth_type: super::super::auth::RPC_C_AUTHN_WINNT,
                auth_level: super::super::auth::RPC_C_AUTHN_LEVEL_CONNECT,
                auth_pad_length: 0,
                auth_context_id: 0,
                // Realistic NTLM NEGOTIATE message length.
                auth_value: vec![0xDE; 40],
            }),
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();

        let mut r = ReadCursor::new(&buf);
        let got = BindPdu::decode(&mut r).unwrap();
        assert_eq!(got.contexts, pdu.contexts);
        assert_eq!(got.auth.as_ref().unwrap().auth_value, vec![0xDE; 40]);
    }

    #[test]
    fn bind_ack_roundtrip() {
        let pdu = BindAckPdu {
            ptype: BIND_ACK_PTYPE,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0x1000,
            sec_addr: b"49922".to_vec(),
            results: vec![ContextResult {
                result: RESULT_ACCEPTANCE,
                reason: 0,
                transfer_syntax: ndr20(),
            }],
            auth: None,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size());

        let mut r = ReadCursor::new(&buf);
        let got = BindAckPdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn bind_ack_empty_sec_addr() {
        let pdu = BindAckPdu {
            ptype: BIND_ACK_PTYPE,
            pfc_flags: 0x03,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 1,
            sec_addr: vec![],
            results: vec![ContextResult {
                result: RESULT_ACCEPTANCE,
                reason: 0,
                transfer_syntax: ndr20(),
            }],
            auth: None,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        let mut r = ReadCursor::new(&buf);
        let got = BindAckPdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn bind_nak_roundtrip() {
        let pdu = BindNakPdu {
            pfc_flags: 0x03,
            call_id: 1,
            provider_reject_reason: PROVIDER_REJECT_PROTOCOL_VERSION_NOT_SUPPORTED,
            versions: vec![(5, 0)],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();

        let mut r = ReadCursor::new(&buf);
        let got = BindNakPdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn alter_context_shares_bind_body() {
        let pdu = BindPdu {
            ptype: ALTER_CONTEXT_PTYPE,
            pfc_flags: 0x03,
            call_id: 2,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0x1000,
            contexts: vec![ContextElement {
                context_id: 1,
                abstract_syntax: tsproxy_abstract(),
                transfer_syntaxes: vec![ndr20()],
            }],
            auth: None,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        let mut r = ReadCursor::new(&buf);
        let got = BindPdu::decode(&mut r).unwrap();
        assert_eq!(got.ptype, ALTER_CONTEXT_PTYPE);
        assert_eq!(got, pdu);
    }

    #[test]
    fn decode_rejects_wrong_ptype() {
        // Build a REQUEST PDU header and try to decode as BIND.
        let hdr = CommonHeader {
            ptype: 0x00, // REQUEST
            pfc_flags: 0x03,
            call_id: 1,
        };
        let mut buf = [0u8; COMMON_HEADER_SIZE + 100];
        let mut w = WriteCursor::new(&mut buf);
        hdr.encode(&mut w, 16, 0).unwrap();
        let mut r = ReadCursor::new(&buf);
        assert!(BindPdu::decode(&mut r).is_err());
    }

    #[test]
    fn bind_size_matches_encode_exactly() {
        let pdu = BindPdu {
            ptype: BIND_PTYPE,
            pfc_flags: 0x03,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            contexts: vec![
                ContextElement {
                    context_id: 0,
                    abstract_syntax: tsproxy_abstract(),
                    transfer_syntaxes: vec![ndr20()],
                },
                ContextElement {
                    context_id: 1,
                    abstract_syntax: tsproxy_abstract(),
                    transfer_syntaxes: vec![ndr20()],
                },
            ],
            auth: None,
        };
        let mut buf = vec![0u8; pdu.size() + 5];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size());
    }

    #[test]
    fn frag_length_in_encoded_bind_matches_size() {
        let pdu = BindPdu {
            ptype: BIND_PTYPE,
            pfc_flags: 0x03,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            contexts: vec![ContextElement {
                context_id: 0,
                abstract_syntax: tsproxy_abstract(),
                transfer_syntaxes: vec![ndr20()],
            }],
            auth: None,
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        // frag_length lives at offset 8..10.
        let frag = u16::from_le_bytes([buf[8], buf[9]]);
        assert_eq!(frag as usize, pdu.size());
    }
}
