#![forbid(unsafe_code)]

//! Server Redirection PDU (MS-RDPBCGR 2.2.13.1).
//!
//! Sent by a Connection Broker (or any RDP server) to instruct the client
//! to disconnect from the current server and reconnect to a different
//! target. Used by load-balanced deployments and Connection Broker
//! environments.
//!
//! Two transport variants exist (MS-RDPBCGR 2.2.13.2.1 and 2.2.13.3.1):
//!
//! - **Standard Security**: the body is RC4-encrypted under a security
//!   header with `SEC_REDIRECTION_PKT (0x0400)` set. Decrypt before
//!   calling `ServerRedirectionPdu::decode`.
//! - **Enhanced Security** (TLS / CredSSP): the body is wrapped in a
//!   `ShareControlHeader` with `pduType == ServerRedirect (0x000A)`,
//!   followed by a 2-byte pad, then the redirection packet. The TLS
//!   record encrypts the whole thing.
//!
//! This module decodes only the inner [`ServerRedirectionPdu`] body —
//! the per-transport framing must be peeled off by the caller.

use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, ReadCursor};

// ── Header constants ──

/// Magic value for the `Flags` field of a Server Redirection Packet.
/// Same value as `SEC_REDIRECTION_PKT` in the security header.
pub const SEC_REDIRECTION_PKT: u16 = 0x0400;

/// Total size of the fixed header (Flags + Length + SessionID + RedirFlags).
pub const REDIRECTION_HEADER_SIZE: usize = 12;

// ── RedirFlags bit definitions (MS-RDPBCGR 2.2.13.1) ──

/// `LB_TARGET_NET_ADDRESS`: TargetNetAddress field is present.
pub const LB_TARGET_NET_ADDRESS: u32 = 0x0000_0001;
/// `LB_LOAD_BALANCE_INFO`: LoadBalanceInfo field is present.
pub const LB_LOAD_BALANCE_INFO: u32 = 0x0000_0002;
/// `LB_USERNAME`: UserName field is present.
pub const LB_USERNAME: u32 = 0x0000_0004;
/// `LB_DOMAIN`: Domain field is present.
pub const LB_DOMAIN: u32 = 0x0000_0008;
/// `LB_PASSWORD`: Password field is present.
pub const LB_PASSWORD: u32 = 0x0000_0010;
/// `LB_DONTSTOREUSERNAME`: client must forward UserName as-is.
pub const LB_DONTSTOREUSERNAME: u32 = 0x0000_0020;
/// `LB_SMARTCARD_LOGON`: smartcard authentication is in use.
pub const LB_SMARTCARD_LOGON: u32 = 0x0000_0040;
/// `LB_NOREDIRECT`: PDU is informational; no actual reconnection required.
pub const LB_NOREDIRECT: u32 = 0x0000_0080;
/// `LB_TARGET_FQDN`: TargetFQDN field is present.
pub const LB_TARGET_FQDN: u32 = 0x0000_0100;
/// `LB_TARGET_NETBIOS_NAME`: TargetNetBiosName field is present.
pub const LB_TARGET_NETBIOS_NAME: u32 = 0x0000_0200;
/// `LB_TARGET_NET_ADDRESSES`: TargetNetAddresses field is present.
pub const LB_TARGET_NET_ADDRESSES: u32 = 0x0000_0800;
/// `LB_CLIENT_TSV_URL`: TsvUrl field is present.
pub const LB_CLIENT_TSV_URL: u32 = 0x0000_1000;
/// `LB_SERVER_TSV_CAPABLE`: server supports TsvUrl-based redirection.
pub const LB_SERVER_TSV_CAPABLE: u32 = 0x0000_2000;
/// `LB_PASSWORD_IS_PK_ENCRYPTED`: password is an opaque RDSTLS blob.
pub const LB_PASSWORD_IS_PK_ENCRYPTED: u32 = 0x0000_4000;
/// `LB_REDIRECTION_GUID`: RedirectionGuid field is present.
pub const LB_REDIRECTION_GUID: u32 = 0x0000_8000;
/// `LB_TARGET_CERTIFICATE`: TargetCertificate field is present.
pub const LB_TARGET_CERTIFICATE: u32 = 0x0001_0000;

/// Hard cap on a single optional field length to prevent runaway
/// allocations from a malformed or hostile server. 64 KiB is far above
/// any legitimate field (the largest reasonable case is a multi-address
/// `TargetNetAddresses` block).
const MAX_FIELD_LEN: u32 = 65_536;

/// One target network address (MS-RDPBCGR 2.2.13.1.1.1).
///
/// `address` is the raw bytes; the spec says they are UTF-16LE
/// null-terminated, but the decoder leaves the bytes as-is so the
/// caller can decide whether to interpret as text or treat as opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetNetAddress {
    pub address: Vec<u8>,
}

impl<'de> Decode<'de> for TargetNetAddress {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let len = src.read_u32_le("TargetNetAddress::addressLength")? as usize;
        if len > MAX_FIELD_LEN as usize {
            return Err(DecodeError::unexpected_value(
                "TargetNetAddress",
                "addressLength",
                "exceeds 64 KiB sanity cap",
            ));
        }
        let address = src
            .read_slice(len, "TargetNetAddress::address")?
            .to_vec();
        Ok(Self { address })
    }
}

/// Collection of target network addresses (MS-RDPBCGR 2.2.13.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TargetNetAddresses {
    pub addresses: Vec<TargetNetAddress>,
}

impl<'de> Decode<'de> for TargetNetAddresses {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let count = src.read_u32_le("TargetNetAddresses::addressCount")?;
        if count > 256 {
            return Err(DecodeError::unexpected_value(
                "TargetNetAddresses",
                "addressCount",
                "exceeds 256 addresses",
            ));
        }
        let mut addresses = Vec::with_capacity(count as usize);
        for _ in 0..count {
            addresses.push(TargetNetAddress::decode(src)?);
        }
        Ok(Self { addresses })
    }
}

/// Server Redirection Packet (MS-RDPBCGR 2.2.13.1).
///
/// Decoder accepts the packet body — the caller is responsible for
/// peeling off the security header (Standard Security) or the
/// `ShareControlHeader` + 2-byte pad (Enhanced Security) before passing
/// the body bytes here.
///
/// All optional fields are `Option<Vec<u8>>` carrying the raw bytes
/// (UTF-16LE for string fields, opaque for `LoadBalanceInfo` /
/// `Password`). Decoding stops at the `Length` field; any trailing
/// padding bytes are silently consumed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerRedirectionPdu {
    /// Session ID the client should reconnect into. Goes into
    /// `ClientClusterData.RedirectedSessionID` on the next connection.
    pub session_id: u32,
    /// Redirection flag bitfield. See the `LB_*` constants.
    pub redir_flags: u32,
    /// Target network address (UTF-16LE, null-terminated). Use this as
    /// the new TCP connection target if `LB_TARGET_NET_ADDRESS` is set.
    pub target_net_address: Option<Vec<u8>>,
    /// Load balance info — opaque cookie that goes verbatim into the
    /// X.224 Connection Request `routingToken` on the next connection,
    /// when `LB_TARGET_NET_ADDRESS` is NOT set.
    pub load_balance_info: Option<Vec<u8>>,
    /// User name (UTF-16LE, null-terminated).
    pub username: Option<Vec<u8>>,
    /// Domain (UTF-16LE, null-terminated).
    pub domain: Option<Vec<u8>>,
    /// Password (UTF-16LE if cleartext, opaque if `LB_PASSWORD_IS_PK_ENCRYPTED`).
    pub password: Option<Vec<u8>>,
    /// Target FQDN (UTF-16LE, null-terminated). Use for TLS SNI / cert
    /// validation on the new connection.
    pub target_fqdn: Option<Vec<u8>>,
    /// Target NetBIOS name (UTF-16LE, null-terminated).
    pub target_netbios_name: Option<Vec<u8>>,
    /// Multiple target addresses (used by IPv4/IPv6 dual-stack
    /// deployments). Each entry is itself a UTF-16LE null-terminated
    /// address string.
    pub target_net_addresses: Option<TargetNetAddresses>,
    /// `TsvUrl` cookie — must round-trip back unchanged on reconnect
    /// when `LB_CLIENT_TSV_URL` is set.
    pub tsv_url: Option<Vec<u8>>,
    /// Redirection GUID (Base64-encoded GUID in UTF-16LE).
    pub redirection_guid: Option<Vec<u8>>,
    /// Target certificate (Base64-encoded `TARGET_CERTIFICATE_CONTAINER`
    /// in UTF-16LE).
    pub target_certificate: Option<Vec<u8>>,
}

impl ServerRedirectionPdu {
    /// Returns `true` if `flag` is set in `redir_flags`.
    pub fn has_flag(&self, flag: u32) -> bool {
        self.redir_flags & flag != 0
    }

    /// Convenience: returns `true` if the server is asking for
    /// informational-only redirection (no reconnect required).
    pub fn is_no_redirect(&self) -> bool {
        self.has_flag(LB_NOREDIRECT)
    }
}

impl<'de> Decode<'de> for ServerRedirectionPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let body_start = src.pos();

        // Fixed 12-byte header.
        let flags = src.read_u16_le("ServerRedirectionPdu::flags")?;
        if flags != SEC_REDIRECTION_PKT {
            return Err(DecodeError::unexpected_value(
                "ServerRedirectionPdu",
                "flags",
                "expected SEC_REDIRECTION_PKT (0x0400)",
            ));
        }
        let length = src.read_u16_le("ServerRedirectionPdu::length")? as usize;
        if length < REDIRECTION_HEADER_SIZE {
            return Err(DecodeError::unexpected_value(
                "ServerRedirectionPdu",
                "length",
                "less than fixed header size",
            ));
        }
        let session_id = src.read_u32_le("ServerRedirectionPdu::sessionId")?;
        let redir_flags = src.read_u32_le("ServerRedirectionPdu::redirFlags")?;

        // Compute the byte limit for optional fields and per-flag pad.
        // After the variable section the spec allows up to 8 bytes of
        // alignment padding before the next PDU; we enforce only that
        // we do not read past `length` bytes total.
        let body_end = body_start + length;
        let read_until = |s: &ReadCursor<'_>| s.pos() <= body_end;

        let mut pdu = ServerRedirectionPdu {
            session_id,
            redir_flags,
            ..Default::default()
        };

        // Helper closure: read a length-prefixed optional field if the
        // gating flag is set. Bounds-checked against `body_end`.
        macro_rules! read_optional {
            ($flag:expr, $field:ident, $name:literal) => {
                if redir_flags & $flag != 0 {
                    if !read_until(src) {
                        return Err(DecodeError::not_enough_bytes(
                            concat!("ServerRedirectionPdu::", $name),
                            0,
                            0,
                        ));
                    }
                    let len = src.read_u32_le(concat!(
                        "ServerRedirectionPdu::",
                        $name,
                        "Length"
                    ))?;
                    if len > MAX_FIELD_LEN {
                        return Err(DecodeError::unexpected_value(
                            "ServerRedirectionPdu",
                            $name,
                            "field length exceeds 64 KiB sanity cap",
                        ));
                    }
                    let len = len as usize;
                    if src.pos() + len > body_end {
                        return Err(DecodeError::unexpected_value(
                            "ServerRedirectionPdu",
                            $name,
                            "field overruns declared body length",
                        ));
                    }
                    pdu.$field = Some(src.read_slice(len, $name)?.to_vec());
                }
            };
        }

        // Optional fields appear in fixed order per the spec, regardless
        // of which flags are set. The decoder must read them only when
        // the corresponding flag is set, in this exact order.
        read_optional!(LB_TARGET_NET_ADDRESS, target_net_address, "targetNetAddress");
        read_optional!(LB_LOAD_BALANCE_INFO, load_balance_info, "loadBalanceInfo");
        read_optional!(LB_USERNAME, username, "userName");
        read_optional!(LB_DOMAIN, domain, "domain");
        read_optional!(LB_PASSWORD, password, "password");
        read_optional!(LB_TARGET_FQDN, target_fqdn, "targetFQDN");
        read_optional!(LB_TARGET_NETBIOS_NAME, target_netbios_name, "targetNetBiosName");

        // TargetNetAddresses is a structured field, not a length-prefixed
        // blob, so it must be decoded with its own parser instead of the
        // macro. Per MS-RDPBCGR 2.2.13.1 it appears AFTER TargetNetBiosName
        // and BEFORE TsvUrl.
        if redir_flags & LB_TARGET_NET_ADDRESSES != 0 {
            // Read the outer length prefix (4 bytes), then the
            // structured TARGET_NET_ADDRESSES body of that length.
            let len = src.read_u32_le("ServerRedirectionPdu::targetNetAddressesLength")? as usize;
            if len > MAX_FIELD_LEN as usize {
                return Err(DecodeError::unexpected_value(
                    "ServerRedirectionPdu",
                    "targetNetAddressesLength",
                    "exceeds 64 KiB sanity cap",
                ));
            }
            if src.pos() + len > body_end {
                return Err(DecodeError::unexpected_value(
                    "ServerRedirectionPdu",
                    "targetNetAddresses",
                    "structure overruns declared body length",
                ));
            }
            let inner_bytes = src.read_slice(len, "ServerRedirectionPdu::targetNetAddresses")?;
            let mut inner = ReadCursor::new(inner_bytes);
            pdu.target_net_addresses = Some(TargetNetAddresses::decode(&mut inner)?);
        }

        read_optional!(LB_CLIENT_TSV_URL, tsv_url, "tsvUrl");
        read_optional!(LB_REDIRECTION_GUID, redirection_guid, "redirectionGuid");
        read_optional!(LB_TARGET_CERTIFICATE, target_certificate, "targetCertificate");

        // Skip any trailing padding bytes up to `length`. The spec
        // allows up to 8 bytes of alignment pad here.
        let consumed = src.pos() - body_start;
        if consumed < length {
            let pad = length - consumed;
            src.read_slice(pad, "ServerRedirectionPdu::pad")?;
        }

        Ok(pdu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build a minimal redirection packet body with just the fixed
    /// header — no optional fields.
    fn build_header_only(session_id: u32, redir_flags: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        buf.extend_from_slice(&12u16.to_le_bytes()); // length = header only
        buf.extend_from_slice(&session_id.to_le_bytes());
        buf.extend_from_slice(&redir_flags.to_le_bytes());
        buf
    }

    #[test]
    fn header_only_roundtrip() {
        let bytes = build_header_only(0x1234, LB_NOREDIRECT);
        let mut cursor = ReadCursor::new(&bytes);
        let pdu = ServerRedirectionPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu.session_id, 0x1234);
        assert_eq!(pdu.redir_flags, LB_NOREDIRECT);
        assert!(pdu.is_no_redirect());
        assert_eq!(pdu.target_net_address, None);
        assert_eq!(pdu.load_balance_info, None);
    }

    #[test]
    fn rejects_wrong_flags_magic() {
        let mut bytes = build_header_only(1, 0);
        bytes[0] = 0xFF; // corrupt the magic
        let mut cursor = ReadCursor::new(&bytes);
        assert!(ServerRedirectionPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn rejects_truncated_header() {
        let bytes = vec![0x00, 0x04]; // only 2 bytes, need 12
        let mut cursor = ReadCursor::new(&bytes);
        assert!(ServerRedirectionPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn rejects_length_smaller_than_header() {
        // length = 8, less than 12-byte header
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let mut cursor = ReadCursor::new(&bytes);
        assert!(ServerRedirectionPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn target_net_address_only() {
        // Build a packet with just LB_TARGET_NET_ADDRESS set, carrying
        // the UTF-16LE string "10.0.0.5\0" (9 chars * 2 bytes = 18).
        let addr_utf16: Vec<u8> = "10.0.0.5\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let addr_len = addr_utf16.len() as u32;

        let mut body = Vec::new();
        body.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        let total_length = 12u16 + 4 + addr_len as u16;
        body.extend_from_slice(&total_length.to_le_bytes());
        body.extend_from_slice(&7u32.to_le_bytes()); // session id
        body.extend_from_slice(&LB_TARGET_NET_ADDRESS.to_le_bytes());
        body.extend_from_slice(&addr_len.to_le_bytes());
        body.extend_from_slice(&addr_utf16);

        let mut cursor = ReadCursor::new(&body);
        let pdu = ServerRedirectionPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu.session_id, 7);
        assert!(pdu.has_flag(LB_TARGET_NET_ADDRESS));
        assert_eq!(pdu.target_net_address.as_ref().unwrap(), &addr_utf16);
        assert_eq!(pdu.load_balance_info, None);
    }

    #[test]
    fn load_balance_info_only() {
        let cookie = b"Cookie: msts=12345\r\n";
        let mut body = Vec::new();
        body.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        let total_length = (12 + 4 + cookie.len()) as u16;
        body.extend_from_slice(&total_length.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&LB_LOAD_BALANCE_INFO.to_le_bytes());
        body.extend_from_slice(&(cookie.len() as u32).to_le_bytes());
        body.extend_from_slice(cookie);

        let mut cursor = ReadCursor::new(&body);
        let pdu = ServerRedirectionPdu::decode(&mut cursor).unwrap();
        assert!(pdu.has_flag(LB_LOAD_BALANCE_INFO));
        assert_eq!(pdu.load_balance_info.as_deref(), Some(cookie.as_slice()));
        assert_eq!(pdu.target_net_address, None);
    }

    #[test]
    fn multiple_optional_fields_in_order() {
        // address ("X\0") + lb info ("ab") + username ("U\0")
        let addr_utf16 = vec![0x58, 0x00, 0x00, 0x00];
        let lb = vec![0x61, 0x62];
        let user_utf16 = vec![0x55, 0x00, 0x00, 0x00];

        let mut body = Vec::new();
        body.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        let payload_len = 4 + addr_utf16.len() + 4 + lb.len() + 4 + user_utf16.len();
        let total_length = (12 + payload_len) as u16;
        body.extend_from_slice(&total_length.to_le_bytes());
        body.extend_from_slice(&42u32.to_le_bytes());
        let flags = LB_TARGET_NET_ADDRESS | LB_LOAD_BALANCE_INFO | LB_USERNAME;
        body.extend_from_slice(&flags.to_le_bytes());

        body.extend_from_slice(&(addr_utf16.len() as u32).to_le_bytes());
        body.extend_from_slice(&addr_utf16);
        body.extend_from_slice(&(lb.len() as u32).to_le_bytes());
        body.extend_from_slice(&lb);
        body.extend_from_slice(&(user_utf16.len() as u32).to_le_bytes());
        body.extend_from_slice(&user_utf16);

        let mut cursor = ReadCursor::new(&body);
        let pdu = ServerRedirectionPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu.session_id, 42);
        assert_eq!(pdu.target_net_address.unwrap(), addr_utf16);
        assert_eq!(pdu.load_balance_info.unwrap(), lb);
        assert_eq!(pdu.username.unwrap(), user_utf16);
    }

    #[test]
    fn target_net_addresses_structure() {
        // Two addresses: "1.1.1.1\0" and "2.2.2.2\0" both UTF-16LE.
        let a1: Vec<u8> = "1.1.1.1\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let a2: Vec<u8> = "2.2.2.2\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        // TARGET_NET_ADDRESSES body: count(4) + addr1.len(4) + addr1 + addr2.len(4) + addr2
        let mut tna_body = Vec::new();
        tna_body.extend_from_slice(&2u32.to_le_bytes()); // addressCount
        tna_body.extend_from_slice(&(a1.len() as u32).to_le_bytes());
        tna_body.extend_from_slice(&a1);
        tna_body.extend_from_slice(&(a2.len() as u32).to_le_bytes());
        tna_body.extend_from_slice(&a2);

        let mut body = Vec::new();
        body.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        let total_length = (12 + 4 + tna_body.len()) as u16;
        body.extend_from_slice(&total_length.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&LB_TARGET_NET_ADDRESSES.to_le_bytes());
        body.extend_from_slice(&(tna_body.len() as u32).to_le_bytes());
        body.extend_from_slice(&tna_body);

        let mut cursor = ReadCursor::new(&body);
        let pdu = ServerRedirectionPdu::decode(&mut cursor).unwrap();
        let addrs = pdu.target_net_addresses.unwrap();
        assert_eq!(addrs.addresses.len(), 2);
        assert_eq!(addrs.addresses[0].address, a1);
        assert_eq!(addrs.addresses[1].address, a2);
    }

    #[test]
    fn rejects_field_length_overrun() {
        // Header says length = 16 (header + 4 byte length field), but
        // the length field claims 100 bytes follow — overruns the body.
        let mut body = Vec::new();
        body.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        body.extend_from_slice(&16u16.to_le_bytes()); // length
        body.extend_from_slice(&0u32.to_le_bytes()); // session id
        body.extend_from_slice(&LB_TARGET_NET_ADDRESS.to_le_bytes());
        body.extend_from_slice(&100u32.to_le_bytes()); // bogus inner length
        // No payload bytes; the cursor end-of-data triggers before the
        // overrun check, but either way decode must fail.
        let mut cursor = ReadCursor::new(&body);
        assert!(ServerRedirectionPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn rejects_oversized_field() {
        let mut body = Vec::new();
        body.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        body.extend_from_slice(&u16::MAX.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&LB_TARGET_NET_ADDRESS.to_le_bytes());
        body.extend_from_slice(&(MAX_FIELD_LEN + 1).to_le_bytes());
        body.resize(body.len() + 100, 0);
        let mut cursor = ReadCursor::new(&body);
        assert!(ServerRedirectionPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn trailing_padding_consumed() {
        // Header-only packet but length includes 4 bytes of padding.
        let mut body = Vec::new();
        body.extend_from_slice(&SEC_REDIRECTION_PKT.to_le_bytes());
        body.extend_from_slice(&16u16.to_le_bytes()); // length includes 4 pad
        body.extend_from_slice(&5u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // no flags
        body.extend_from_slice(&[0xC0, 0xC0, 0xC0, 0xC0]); // pad
        let mut cursor = ReadCursor::new(&body);
        let pdu = ServerRedirectionPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu.session_id, 5);
        // Cursor should be exactly at end of body.
        assert_eq!(cursor.pos(), body.len());
    }
}
