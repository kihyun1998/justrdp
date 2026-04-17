#![forbid(unsafe_code)]

//! TSG-prefixed IDL types from MS-TSGU §2.2.9 and §2.2.3 with NDR
//! 2.0 marshaling.
//!
//! This module is the on-the-wire schema for every TsProxy RPC
//! parameter that flows through the stub-data section of a DCE/RPC
//! REQUEST or RESPONSE PDU. It does **not** model RPC framing — the
//! 16-byte common header + 4-byte PDU-private fields (alloc_hint,
//! context_id, opnum …) belong to `justrdp-rpch::pdu`.
//!
//! # Conventions
//!
//! Each public struct exposes two associated functions:
//!
//! ```ignore
//! fn encode_ndr(&self, e: &mut NdrEncoder);
//! fn decode_ndr(d: &mut NdrDecoder) -> NdrResult<Self>;
//! ```
//!
//! `encode_ndr` writes the struct's **inline** fields first (any
//! pointer in the struct is encoded as its 4-byte referent ID),
//! then writes the corresponding **deferred** referent bodies in
//! the order they appeared — matching the C706 §14.3.12.2 depth-
//! first deferral order. `decode_ndr` mirrors it.
//!
//! For the small set of TsProxy types there is no referent aliasing
//! (`[ptr]` / `[full]`), so we do not maintain a `referent →
//! payload` map; each pointer slot gets a freshly allocated
//! referent ID on encode.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_rpch::ndr::{NdrDecoder, NdrEncoder, NdrError, NdrResult};
use justrdp_rpch::pdu::uuid::RpcUuid;

// =============================================================================
// Interface identity
// =============================================================================

/// TsProxy interface UUID (MS-TSGU §1.9).
pub const TSPROXY_INTERFACE_UUID: &str = "44e265dd-7daf-42cd-8560-3cdb6e7a2729";

// =============================================================================
// TSG_PACKET_TYPE_* discriminants (MS-TSGU §2.2.9)
// =============================================================================

pub const TSG_PACKET_TYPE_HEADER: u32 = 0x0000_4844; // "HD"
pub const TSG_PACKET_TYPE_VERSIONCAPS: u32 = 0x0000_5643; // "VC"
pub const TSG_PACKET_TYPE_QUARCONFIGREQUEST: u32 = 0x0000_5143; // "QC"
pub const TSG_PACKET_TYPE_QUARREQUEST: u32 = 0x0000_5152; // "QR"
pub const TSG_PACKET_TYPE_RESPONSE: u32 = 0x0000_5052; // "RP"
pub const TSG_PACKET_TYPE_QUARENC_RESPONSE: u32 = 0x0000_4552; // "QE"
pub const TSG_PACKET_TYPE_CAPS_RESPONSE: u32 = 0x0000_4350; // "CP"
pub const TSG_PACKET_TYPE_MSGREQUEST_PACKET: u32 = 0x0000_4752; // "GR"
pub const TSG_PACKET_TYPE_MESSAGE_PACKET: u32 = 0x0000_4750; // "GP"
pub const TSG_PACKET_TYPE_AUTH: u32 = 0x0000_4054; // "@T"
pub const TSG_PACKET_TYPE_REAUTH: u32 = 0x0000_5250; // "RP"

/// ComponentId baked into every `TSG_PACKET_HEADER` (MS-TSGU
/// §2.2.9.2): ASCII "TR" — Terminal Server Gateway Transport.
pub const TSG_COMPONENT_ID_TR: u16 = 0x5452;

// =============================================================================
// TSG_CAPABILITY_* (MS-TSGU §2.2.9.2.1)
// =============================================================================

pub const TSG_CAPABILITY_TYPE_NAP: u32 = 0x0000_0001;

pub const TSG_NAP_CAPABILITY_QUAR_SOH: u32 = 0x0000_0001;
pub const TSG_NAP_CAPABILITY_IDLE_TIMEOUT: u32 = 0x0000_0002;
pub const TSG_MESSAGING_CAP_CONSENT_SIGN: u32 = 0x0000_0004;
pub const TSG_MESSAGING_CAP_SERVICE_MSG: u32 = 0x0000_0008;
pub const TSG_MESSAGING_CAP_REAUTH: u32 = 0x0000_0010;

// =============================================================================
// Context handle (C706 Appendix N, MS-TSGU §2.2.9.4)
// =============================================================================

/// A DCE/RPC `[context_handle]` — 4-byte attributes + 16-byte UUID
/// in mixed-endian form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextHandle {
    pub attributes: u32,
    pub uuid: RpcUuid,
}

impl Default for ContextHandle {
    fn default() -> Self {
        Self::NIL
    }
}

impl ContextHandle {
    /// Fixed NDR wire size.
    pub const SIZE: usize = 20;

    /// A NULL handle — attributes zero, UUID all zeros. Sent as the
    /// input half of a `[in, out]` parameter when we want the
    /// server to close it.
    pub const NIL: Self = Self {
        attributes: 0,
        uuid: RpcUuid::NIL,
    };

    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        e.write_u32(self.attributes);
        // Inline the 16-byte UUID in DCE mixed-endian.
        e.write_u32(self.uuid.data1);
        e.write_u16(self.uuid.data2);
        e.write_u16(self.uuid.data3);
        e.write_bytes(&self.uuid.data4);
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let attributes = d.read_u32("ContextHandle.attributes")?;
        let data1 = d.read_u32("ContextHandle.uuid.data1")?;
        let data2 = d.read_u16("ContextHandle.uuid.data2")?;
        let data3 = d.read_u16("ContextHandle.uuid.data3")?;
        let data4_slice = d.read_bytes(8, "ContextHandle.uuid.data4")?;
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(data4_slice);
        Ok(Self {
            attributes,
            uuid: RpcUuid {
                data1,
                data2,
                data3,
                data4,
            },
        })
    }
}

// =============================================================================
// TSG_PACKET_HEADER (§2.2.9.2)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsgPacketHeader {
    /// Always [`TSG_COMPONENT_ID_TR`].
    pub component_id: u16,
    pub packet_id: u16,
}

impl TsgPacketHeader {
    pub const SIZE: usize = 4;

    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        e.write_u16(self.component_id);
        e.write_u16(self.packet_id);
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let component_id = d.read_u16("TsgPacketHeader.component_id")?;
        let packet_id = d.read_u16("TsgPacketHeader.packet_id")?;
        Ok(Self {
            component_id,
            packet_id,
        })
    }
}

// =============================================================================
// TSG_NAP_CAPABILITY / TSG_PACKET_CAPABILITIES (§2.2.9.2.1)
// =============================================================================

/// Single NAP capability word as an u32 bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsgNapCapability {
    pub capabilities: u32,
}

/// `TSG_PACKET_CAPABILITIES` — a capability-type-discriminated
/// envelope. The only arm Microsoft ever defines is `NAP`, so we
/// flatten the union.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsgPacketCapabilities {
    pub capability_type: u32,
    pub nap: TsgNapCapability,
}

impl TsgPacketCapabilities {
    /// Single flat capability element — convenient constructor for
    /// CreateTunnel requests.
    pub fn nap(bits: u32) -> Self {
        Self {
            capability_type: TSG_CAPABILITY_TYPE_NAP,
            nap: TsgNapCapability { capabilities: bits },
        }
    }

    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        e.write_u32(self.capability_type);
        e.write_u32(self.nap.capabilities);
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let capability_type = d.read_u32("TsgPacketCapabilities.capability_type")?;
        let capabilities = d.read_u32("TsgPacketCapabilities.capabilities")?;
        Ok(Self {
            capability_type,
            nap: TsgNapCapability { capabilities },
        })
    }
}

// =============================================================================
// TSG_PACKET_VERSIONCAPS (§2.2.9.2.2)
// =============================================================================

/// Carries the client/server's protocol version plus the set of
/// capabilities it supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsgPacketVersionCaps {
    pub header: TsgPacketHeader,
    pub tsg_caps: Vec<TsgPacketCapabilities>,
    pub major_version: u16,
    pub minor_version: u16,
    pub quarantine_capabilities: u16,
}

impl TsgPacketVersionCaps {
    /// Convenience constructor mirroring what Windows clients send:
    /// "TR" component id, VersionCaps packet id, the supplied
    /// capability set flattened into a single NAP element,
    /// version 1.1, quarantine disabled.
    pub fn client_default(capability_bits: u32) -> Self {
        Self {
            header: TsgPacketHeader {
                component_id: TSG_COMPONENT_ID_TR,
                packet_id: TSG_PACKET_TYPE_VERSIONCAPS as u16,
            },
            tsg_caps: alloc::vec![TsgPacketCapabilities::nap(capability_bits)],
            major_version: 1,
            minor_version: 1,
            quarantine_capabilities: 0,
        }
    }

    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        // Inline portion.
        self.header.encode_ndr(e);
        // `TSGCaps` — unique pointer to a conformant array. Emit
        // its referent ID; the array body is written in the
        // deferred section below.
        let present = !self.tsg_caps.is_empty();
        let _id = e.write_unique_pointer(present);
        e.write_u32(self.tsg_caps.len() as u32); // numCapabilities
        e.write_u16(self.major_version);
        e.write_u16(self.minor_version);
        e.write_u16(self.quarantine_capabilities);

        // Deferred: the conformant array body.
        if present {
            // Conformant array inline of struct elements — max_count
            // prefix followed by elements.
            e.write_u32(self.tsg_caps.len() as u32);
            for c in &self.tsg_caps {
                c.encode_ndr(e);
            }
        }
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let header = TsgPacketHeader::decode_ndr(d)?;
        let tsg_caps_ptr = d.read_unique_pointer("TsgPacketVersionCaps.tsg_caps")?;
        let num_caps = d.read_u32("TsgPacketVersionCaps.num_capabilities")?;
        let major_version = d.read_u16("TsgPacketVersionCaps.major_version")?;
        let minor_version = d.read_u16("TsgPacketVersionCaps.minor_version")?;
        let quarantine_capabilities =
            d.read_u16("TsgPacketVersionCaps.quarantine_capabilities")?;

        let tsg_caps = if tsg_caps_ptr.is_some() {
            let max_count = d.read_u32("TsgPacketVersionCaps.tsg_caps.max_count")?;
            if max_count != num_caps {
                return Err(NdrError::InvalidData {
                    context: "TsgPacketVersionCaps: max_count != numCapabilities",
                });
            }
            let mut caps = Vec::with_capacity(num_caps as usize);
            for _ in 0..num_caps {
                caps.push(TsgPacketCapabilities::decode_ndr(d)?);
            }
            caps
        } else {
            Vec::new()
        };

        Ok(Self {
            header,
            tsg_caps,
            major_version,
            minor_version,
            quarantine_capabilities,
        })
    }
}

// =============================================================================
// TSG_PACKET_QUARREQUEST (§2.2.9.2 — input of AuthorizeTunnel)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsgPacketQuarRequest {
    pub flags: u32,
    pub machine_name: Option<String>,
    /// Encoded SoH blob; `None` means "no quarantine data available".
    pub data: Option<Vec<u8>>,
}

impl TsgPacketQuarRequest {
    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        e.write_u32(self.flags);
        let mn_present = self.machine_name.is_some();
        let _ = e.write_unique_pointer(mn_present);
        // nameLength: wchar count including NUL.
        let name_length = match &self.machine_name {
            Some(s) => (s.encode_utf16().count() + 1) as u32,
            None => 0,
        };
        e.write_u32(name_length);
        let data_present = self.data.is_some();
        let _ = e.write_unique_pointer(data_present);
        let data_len = self.data.as_ref().map(|d| d.len() as u32).unwrap_or(0);
        e.write_u32(data_len);

        // Deferred:
        if let Some(s) = &self.machine_name {
            e.write_conformant_varying_wstring(s);
        }
        if let Some(d) = &self.data {
            e.write_u32(d.len() as u32);
            e.write_bytes(d);
        }
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let flags = d.read_u32("TsgPacketQuarRequest.flags")?;
        let mn_ptr = d.read_unique_pointer("TsgPacketQuarRequest.machine_name")?;
        let _name_length = d.read_u32("TsgPacketQuarRequest.name_length")?;
        let data_ptr = d.read_unique_pointer("TsgPacketQuarRequest.data")?;
        let data_len = d.read_u32("TsgPacketQuarRequest.data_len")?;

        let machine_name = if mn_ptr.is_some() {
            Some(d.read_conformant_varying_wstring()?)
        } else {
            None
        };
        let data = if data_ptr.is_some() {
            let max_count = d.read_u32("TsgPacketQuarRequest.data.max_count")?;
            if max_count != data_len {
                return Err(NdrError::InvalidData {
                    context: "TsgPacketQuarRequest: data max_count mismatch",
                });
            }
            let bytes = d.read_bytes(data_len as usize, "TsgPacketQuarRequest.data")?;
            Some(bytes.to_vec())
        } else {
            None
        };
        Ok(Self {
            flags,
            machine_name,
            data,
        })
    }
}

// =============================================================================
// TSG_REDIRECTION_FLAGS (§2.2.9.2.3.1) — 32 bytes (8 × BOOL)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TsgRedirectionFlags {
    pub enable_all_redirections: bool,
    pub disable_all_redirections: bool,
    pub drive_redirection_disabled: bool,
    pub printer_redirection_disabled: bool,
    pub port_redirection_disabled: bool,
    /// Reserved — written as 0 on encode, ignored on decode.
    pub reserved: bool,
    pub clipboard_redirection_disabled: bool,
    pub pnp_redirection_disabled: bool,
}

impl TsgRedirectionFlags {
    fn encode_bool(e: &mut NdrEncoder, v: bool) {
        e.write_u32(if v { 1 } else { 0 });
    }

    fn decode_bool(d: &mut NdrDecoder<'_>, ctx: &'static str) -> NdrResult<bool> {
        Ok(d.read_u32(ctx)? != 0)
    }

    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        Self::encode_bool(e, self.enable_all_redirections);
        Self::encode_bool(e, self.disable_all_redirections);
        Self::encode_bool(e, self.drive_redirection_disabled);
        Self::encode_bool(e, self.printer_redirection_disabled);
        Self::encode_bool(e, self.port_redirection_disabled);
        Self::encode_bool(e, self.reserved);
        Self::encode_bool(e, self.clipboard_redirection_disabled);
        Self::encode_bool(e, self.pnp_redirection_disabled);
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        Ok(Self {
            enable_all_redirections: Self::decode_bool(d, "enable_all")?,
            disable_all_redirections: Self::decode_bool(d, "disable_all")?,
            drive_redirection_disabled: Self::decode_bool(d, "drive")?,
            printer_redirection_disabled: Self::decode_bool(d, "printer")?,
            port_redirection_disabled: Self::decode_bool(d, "port")?,
            reserved: Self::decode_bool(d, "reserved")?,
            clipboard_redirection_disabled: Self::decode_bool(d, "clipboard")?,
            pnp_redirection_disabled: Self::decode_bool(d, "pnp")?,
        })
    }
}

// =============================================================================
// TSG_PACKET_RESPONSE (§2.2.9.2.3 — output of AuthorizeTunnel)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsgPacketResponse {
    pub flags: u32,
    /// SoH response blob. Empty when quarantine was not active.
    pub response_data: Vec<u8>,
    pub redirection_flags: TsgRedirectionFlags,
}

impl TsgPacketResponse {
    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        e.write_u32(self.flags);
        e.write_u32(0); // reserved
        let present = !self.response_data.is_empty();
        let _ = e.write_unique_pointer(present);
        e.write_u32(self.response_data.len() as u32);
        self.redirection_flags.encode_ndr(e);
        if present {
            e.write_u32(self.response_data.len() as u32);
            e.write_bytes(&self.response_data);
        }
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let flags = d.read_u32("TsgPacketResponse.flags")?;
        let _reserved = d.read_u32("TsgPacketResponse.reserved")?;
        let data_ptr = d.read_unique_pointer("TsgPacketResponse.response_data")?;
        let response_data_len = d.read_u32("TsgPacketResponse.response_data_len")?;
        let redirection_flags = TsgRedirectionFlags::decode_ndr(d)?;

        let response_data = if data_ptr.is_some() {
            let max_count = d.read_u32("TsgPacketResponse.response_data.max_count")?;
            if max_count != response_data_len {
                return Err(NdrError::InvalidData {
                    context: "TsgPacketResponse: response_data max_count mismatch",
                });
            }
            d.read_bytes(response_data_len as usize, "TsgPacketResponse.response_data")?
                .to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            flags,
            response_data,
            redirection_flags,
        })
    }
}

// =============================================================================
// TSG_PACKET_QUARENC_RESPONSE (§2.2.9.2.4)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsgPacketQuarEncResponse {
    pub flags: u32,
    /// PEM/DER cert chain transmitted as a wide string.
    pub cert_chain: Option<String>,
    pub nonce: RpcUuid,
    /// Server's advertised VersionCaps.
    pub version_caps: Option<TsgPacketVersionCaps>,
}

impl TsgPacketQuarEncResponse {
    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        e.write_u32(self.flags);
        // certChainLen includes NUL if cert_chain present.
        let cert_chain_len = match &self.cert_chain {
            Some(s) => (s.encode_utf16().count() + 1) as u32,
            None => 0,
        };
        e.write_u32(cert_chain_len);
        let cc_present = self.cert_chain.is_some();
        let _ = e.write_unique_pointer(cc_present);
        // nonce (16 bytes, mixed-endian — reuse RpcUuid encoding).
        e.write_u32(self.nonce.data1);
        e.write_u16(self.nonce.data2);
        e.write_u16(self.nonce.data3);
        e.write_bytes(&self.nonce.data4);
        let vc_present = self.version_caps.is_some();
        let _ = e.write_unique_pointer(vc_present);

        // Deferred:
        if let Some(s) = &self.cert_chain {
            e.write_conformant_varying_wstring(s);
        }
        if let Some(vc) = &self.version_caps {
            vc.encode_ndr(e);
        }
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let flags = d.read_u32("TsgPacketQuarEncResponse.flags")?;
        let _cert_chain_len = d.read_u32("TsgPacketQuarEncResponse.cert_chain_len")?;
        let cc_ptr = d.read_unique_pointer("TsgPacketQuarEncResponse.cert_chain")?;
        let data1 = d.read_u32("TsgPacketQuarEncResponse.nonce.data1")?;
        let data2 = d.read_u16("TsgPacketQuarEncResponse.nonce.data2")?;
        let data3 = d.read_u16("TsgPacketQuarEncResponse.nonce.data3")?;
        let data4 = d.read_bytes(8, "TsgPacketQuarEncResponse.nonce.data4")?;
        let mut data4_arr = [0u8; 8];
        data4_arr.copy_from_slice(data4);
        let nonce = RpcUuid {
            data1,
            data2,
            data3,
            data4: data4_arr,
        };
        let vc_ptr = d.read_unique_pointer("TsgPacketQuarEncResponse.version_caps")?;

        let cert_chain = if cc_ptr.is_some() {
            Some(d.read_conformant_varying_wstring()?)
        } else {
            None
        };
        let version_caps = if vc_ptr.is_some() {
            Some(TsgPacketVersionCaps::decode_ndr(d)?)
        } else {
            None
        };

        Ok(Self {
            flags,
            cert_chain,
            nonce,
            version_caps,
        })
    }
}

// =============================================================================
// TSG_PACKET_CAPS_RESPONSE (§2.2.9.2.3)
// =============================================================================

/// Returned from `TsProxyCreateTunnel` when the server negotiated
/// `TSG_MESSAGING_CAP_CONSENT_SIGN`. It simply concatenates a
/// `QuarEncResponse` and a `MsgResponse` (left as raw bytes here —
/// we do not need to model it for the minimum-viable tunnel).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsgPacketCapsResponse {
    pub pkt_quar_enc_response: TsgPacketQuarEncResponse,
    /// Opaque message-packet bytes; NDR-encoded per §2.2.9.2.7 but
    /// we don't need to introspect it for the tunnel-up path.
    pub pkt_consent_message_raw: Vec<u8>,
}

impl TsgPacketCapsResponse {
    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        self.pkt_quar_enc_response.encode_ndr(e);
        e.write_bytes(&self.pkt_consent_message_raw);
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let pkt_quar_enc_response = TsgPacketQuarEncResponse::decode_ndr(d)?;
        let pkt_consent_message_raw = d.read_bytes(
            d.remaining(),
            "TsgPacketCapsResponse.pkt_consent_message",
        )?
        .to_vec();
        Ok(Self {
            pkt_quar_enc_response,
            pkt_consent_message_raw,
        })
    }
}

// =============================================================================
// TSG_PACKET_AUTH (§2.2.9.2.5)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsgPacketAuth {
    /// Must be a valid client VersionCaps (§2.2.9.2.2).
    pub version_caps: TsgPacketVersionCaps,
    /// PAA cookie bytes (§2.2.10.1).
    pub cookie: Vec<u8>,
}

impl TsgPacketAuth {
    /// Encode per the MS-TSGU Appendix A IDL field order for
    /// `TSG_PACKET_AUTH`: embedded `TSGVersionCaps` first, then
    /// `cookieLen` DWORD, then the `[size_is(cookieLen)] byte*
    /// cookie` pointer slot. `cookieLen` precedes the pointer — this
    /// is the reverse of the `[unique, size_is] wchar_t*` + length
    /// pairs seen in `TSG_PACKET_QUARREQUEST` where the pointer comes
    /// first — so the ordering below is intentional.
    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        self.version_caps.encode_ndr(e);
        e.write_u32(self.cookie.len() as u32);
        let present = !self.cookie.is_empty();
        let _ = e.write_unique_pointer(present);
        if present {
            e.write_u32(self.cookie.len() as u32);
            e.write_bytes(&self.cookie);
        }
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let version_caps = TsgPacketVersionCaps::decode_ndr(d)?;
        let cookie_len = d.read_u32("TsgPacketAuth.cookie_len")?;
        let ptr = d.read_unique_pointer("TsgPacketAuth.cookie")?;
        let cookie = if ptr.is_some() {
            let max_count = d.read_u32("TsgPacketAuth.cookie.max_count")?;
            if max_count != cookie_len {
                return Err(NdrError::InvalidData {
                    context: "TsgPacketAuth: cookie max_count mismatch",
                });
            }
            d.read_bytes(cookie_len as usize, "TsgPacketAuth.cookie")?
                .to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            version_caps,
            cookie,
        })
    }
}

// =============================================================================
// TSG_PACKET outer envelope (§2.2.9)
// =============================================================================

/// The `TSG_PACKET` union — discriminated by `packetId`. We only
/// model the arms used by the minimum-viable tunnel flow. The rest
/// of the message/reauth arms are represented as opaque raw bytes
/// (future work).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsgPacket {
    VersionCaps(TsgPacketVersionCaps),
    QuarRequest(TsgPacketQuarRequest),
    Response(TsgPacketResponse),
    QuarEncResponse(TsgPacketQuarEncResponse),
    CapsResponse(TsgPacketCapsResponse),
    Auth(TsgPacketAuth),
}

impl TsgPacket {
    pub fn packet_id(&self) -> u32 {
        match self {
            Self::VersionCaps(_) => TSG_PACKET_TYPE_VERSIONCAPS,
            Self::QuarRequest(_) => TSG_PACKET_TYPE_QUARREQUEST,
            Self::Response(_) => TSG_PACKET_TYPE_RESPONSE,
            Self::QuarEncResponse(_) => TSG_PACKET_TYPE_QUARENC_RESPONSE,
            Self::CapsResponse(_) => TSG_PACKET_TYPE_CAPS_RESPONSE,
            Self::Auth(_) => TSG_PACKET_TYPE_AUTH,
        }
    }

    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        // Outer envelope: packetId discriminant + encapsulated union
        // arm. Each arm is a `[unique]` pointer to the concrete
        // struct; emit its referent ID then the body in the deferred
        // slot.
        e.write_u32(self.packet_id());
        let _id = e.write_unique_pointer(true);
        match self {
            Self::VersionCaps(x) => x.encode_ndr(e),
            Self::QuarRequest(x) => x.encode_ndr(e),
            Self::Response(x) => x.encode_ndr(e),
            Self::QuarEncResponse(x) => x.encode_ndr(e),
            Self::CapsResponse(x) => x.encode_ndr(e),
            Self::Auth(x) => x.encode_ndr(e),
        }
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let packet_id = d.read_u32("TsgPacket.packet_id")?;
        let _ptr = d.read_unique_pointer("TsgPacket.arm")?;
        match packet_id {
            TSG_PACKET_TYPE_VERSIONCAPS => Ok(Self::VersionCaps(TsgPacketVersionCaps::decode_ndr(d)?)),
            TSG_PACKET_TYPE_QUARREQUEST => Ok(Self::QuarRequest(TsgPacketQuarRequest::decode_ndr(d)?)),
            TSG_PACKET_TYPE_RESPONSE => Ok(Self::Response(TsgPacketResponse::decode_ndr(d)?)),
            TSG_PACKET_TYPE_QUARENC_RESPONSE => {
                Ok(Self::QuarEncResponse(TsgPacketQuarEncResponse::decode_ndr(d)?))
            }
            TSG_PACKET_TYPE_CAPS_RESPONSE => Ok(Self::CapsResponse(TsgPacketCapsResponse::decode_ndr(d)?)),
            TSG_PACKET_TYPE_AUTH => Ok(Self::Auth(TsgPacketAuth::decode_ndr(d)?)),
            _ => Err(NdrError::InvalidData {
                context: "TsgPacket: unsupported packet_id",
            }),
        }
    }
}

// =============================================================================
// TSENDPOINTINFO (§2.2.9.3)
// =============================================================================

/// Target description passed to `TsProxyCreateChannel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsEndpointInfo {
    /// Primary resource names (up to 50 per IDL `[range(0,50)]`).
    pub resource_names: Vec<String>,
    /// Optional alternate resource names (up to 3).
    pub alternate_resource_names: Vec<String>,
    /// Port field encoding (§2.2.3.3): high 16 bits = transport
    /// protocol (3 = RDP/TCP), low 16 bits = port number (typically
    /// 3389). The encoder/decoder treats this as a single u32.
    pub port: u32,
}

impl TsEndpointInfo {
    pub const TRANSPORT_PROTOCOL_TCP: u16 = 3;

    /// Build the canonical port value: `(TCP << 16) | port`.
    pub fn rdp_port(port: u16) -> u32 {
        ((Self::TRANSPORT_PROTOCOL_TCP as u32) << 16) | port as u32
    }

    pub fn encode_ndr(&self, e: &mut NdrEncoder) {
        // Inline: pointer slot for resourceName conformant array +
        // numResourceNames + alternate conformant-array pointer +
        // numAlternate + Port.
        let _ = e.write_unique_pointer(!self.resource_names.is_empty());
        e.write_u32(self.resource_names.len() as u32);
        let _ = e.write_unique_pointer(!self.alternate_resource_names.is_empty());
        e.write_u16(self.alternate_resource_names.len() as u16);
        e.write_u32(self.port);

        // Deferred:
        if !self.resource_names.is_empty() {
            // Conformant array of `[string] wchar_t*` pointers. On
            // the wire: max_count + (referent_id per element) + per-
            // element deferred wstrings.
            e.write_u32(self.resource_names.len() as u32);
            for _ in &self.resource_names {
                let _ = e.write_unique_pointer(true);
            }
            for s in &self.resource_names {
                e.write_conformant_varying_wstring(s);
            }
        }
        if !self.alternate_resource_names.is_empty() {
            e.write_u32(self.alternate_resource_names.len() as u32);
            for _ in &self.alternate_resource_names {
                let _ = e.write_unique_pointer(true);
            }
            for s in &self.alternate_resource_names {
                e.write_conformant_varying_wstring(s);
            }
        }
    }

    pub fn decode_ndr(d: &mut NdrDecoder<'_>) -> NdrResult<Self> {
        let rn_ptr = d.read_unique_pointer("TsEndpointInfo.resource_names")?;
        let num_rn = d.read_u32("TsEndpointInfo.num_resource_names")?;
        let arn_ptr = d.read_unique_pointer("TsEndpointInfo.alternate_resource_names")?;
        let num_arn = d.read_u16("TsEndpointInfo.num_alternate_resource_names")?;
        let port = d.read_u32("TsEndpointInfo.port")?;

        let resource_names = if rn_ptr.is_some() {
            let max_count = d.read_u32("resource_names.max_count")?;
            if max_count != num_rn {
                return Err(NdrError::InvalidData {
                    context: "TsEndpointInfo: resource_names max_count mismatch",
                });
            }
            let mut ptrs = Vec::with_capacity(max_count as usize);
            for _ in 0..max_count {
                ptrs.push(d.read_unique_pointer("resource_names[i]")?);
            }
            let mut out = Vec::with_capacity(max_count as usize);
            for ptr in &ptrs {
                if ptr.is_some() {
                    out.push(d.read_conformant_varying_wstring()?);
                } else {
                    return Err(NdrError::InvalidData {
                        context: "TsEndpointInfo: NULL resource name",
                    });
                }
            }
            out
        } else {
            Vec::new()
        };

        let alternate_resource_names = if arn_ptr.is_some() {
            let max_count = d.read_u32("alternate_resource_names.max_count")?;
            if max_count != num_arn as u32 {
                return Err(NdrError::InvalidData {
                    context: "TsEndpointInfo: alternate_resource_names max_count mismatch",
                });
            }
            let mut ptrs = Vec::with_capacity(max_count as usize);
            for _ in 0..max_count {
                ptrs.push(d.read_unique_pointer("alt_resource_names[i]")?);
            }
            let mut out = Vec::with_capacity(max_count as usize);
            for ptr in &ptrs {
                if ptr.is_some() {
                    out.push(d.read_conformant_varying_wstring()?);
                }
            }
            out
        } else {
            Vec::new()
        };

        Ok(Self {
            resource_names,
            alternate_resource_names,
            port,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip<T, F, G>(value: &T, encode: F, decode: G) -> T
    where
        F: Fn(&T, &mut NdrEncoder),
        G: Fn(&mut NdrDecoder<'_>) -> NdrResult<T>,
    {
        let mut e = NdrEncoder::new();
        encode(value, &mut e);
        let bytes = e.into_bytes();
        let mut d = NdrDecoder::new(&bytes);
        decode(&mut d).unwrap()
    }

    #[test]
    fn context_handle_is_20_bytes() {
        let h = ContextHandle {
            attributes: 0,
            uuid: RpcUuid::parse("aabbccdd-1122-3344-5566-77889900aabb").unwrap(),
        };
        let mut e = NdrEncoder::new();
        h.encode_ndr(&mut e);
        assert_eq!(e.as_bytes().len(), ContextHandle::SIZE);
    }

    #[test]
    fn context_handle_roundtrip() {
        let h = ContextHandle {
            attributes: 1,
            uuid: RpcUuid::parse("aabbccdd-1122-3344-5566-77889900aabb").unwrap(),
        };
        let got = roundtrip(&h, ContextHandle::encode_ndr, ContextHandle::decode_ndr);
        assert_eq!(got, h);
    }

    #[test]
    fn tsg_packet_header_roundtrip() {
        let h = TsgPacketHeader {
            component_id: TSG_COMPONENT_ID_TR,
            packet_id: TSG_PACKET_TYPE_VERSIONCAPS as u16,
        };
        let got = roundtrip(&h, TsgPacketHeader::encode_ndr, TsgPacketHeader::decode_ndr);
        assert_eq!(got, h);
    }

    #[test]
    fn version_caps_roundtrip_with_nap() {
        let vc = TsgPacketVersionCaps::client_default(
            TSG_NAP_CAPABILITY_QUAR_SOH | TSG_NAP_CAPABILITY_IDLE_TIMEOUT,
        );
        let got = roundtrip(
            &vc,
            TsgPacketVersionCaps::encode_ndr,
            TsgPacketVersionCaps::decode_ndr,
        );
        assert_eq!(got, vc);
        assert_eq!(got.tsg_caps.len(), 1);
        assert_eq!(got.tsg_caps[0].capability_type, TSG_CAPABILITY_TYPE_NAP);
        assert_eq!(
            got.tsg_caps[0].nap.capabilities,
            TSG_NAP_CAPABILITY_QUAR_SOH | TSG_NAP_CAPABILITY_IDLE_TIMEOUT
        );
    }

    #[test]
    fn version_caps_roundtrip_empty_caps() {
        let vc = TsgPacketVersionCaps {
            header: TsgPacketHeader {
                component_id: TSG_COMPONENT_ID_TR,
                packet_id: TSG_PACKET_TYPE_VERSIONCAPS as u16,
            },
            tsg_caps: vec![],
            major_version: 1,
            minor_version: 1,
            quarantine_capabilities: 0,
        };
        let got = roundtrip(
            &vc,
            TsgPacketVersionCaps::encode_ndr,
            TsgPacketVersionCaps::decode_ndr,
        );
        assert_eq!(got, vc);
    }

    #[test]
    fn quar_request_roundtrip_no_data() {
        let q = TsgPacketQuarRequest {
            flags: 0,
            machine_name: None,
            data: None,
        };
        let got = roundtrip(
            &q,
            TsgPacketQuarRequest::encode_ndr,
            TsgPacketQuarRequest::decode_ndr,
        );
        assert_eq!(got, q);
    }

    #[test]
    fn quar_request_roundtrip_with_machine_name() {
        let q = TsgPacketQuarRequest {
            flags: 0,
            machine_name: Some(String::from("CLIENT01")),
            data: Some(alloc::vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let got = roundtrip(
            &q,
            TsgPacketQuarRequest::encode_ndr,
            TsgPacketQuarRequest::decode_ndr,
        );
        assert_eq!(got, q);
    }

    #[test]
    fn response_roundtrip() {
        let r = TsgPacketResponse {
            flags: 0,
            response_data: alloc::vec![],
            redirection_flags: TsgRedirectionFlags {
                disable_all_redirections: true,
                ..Default::default()
            },
        };
        let got = roundtrip(
            &r,
            TsgPacketResponse::encode_ndr,
            TsgPacketResponse::decode_ndr,
        );
        assert_eq!(got, r);
        assert!(got.redirection_flags.disable_all_redirections);
    }

    #[test]
    fn quar_enc_response_roundtrip_full() {
        let q = TsgPacketQuarEncResponse {
            flags: 0,
            cert_chain: Some(String::from("-----BEGIN CERT-----\n...")),
            nonce: RpcUuid::parse("12345678-1234-1234-1234-123456789012").unwrap(),
            version_caps: Some(TsgPacketVersionCaps::client_default(
                TSG_NAP_CAPABILITY_QUAR_SOH,
            )),
        };
        let got = roundtrip(
            &q,
            TsgPacketQuarEncResponse::encode_ndr,
            TsgPacketQuarEncResponse::decode_ndr,
        );
        assert_eq!(got, q);
    }

    #[test]
    fn quar_enc_response_roundtrip_no_cert_no_vc() {
        let q = TsgPacketQuarEncResponse {
            flags: 0,
            cert_chain: None,
            nonce: RpcUuid::NIL,
            version_caps: None,
        };
        let got = roundtrip(
            &q,
            TsgPacketQuarEncResponse::encode_ndr,
            TsgPacketQuarEncResponse::decode_ndr,
        );
        assert_eq!(got, q);
    }

    #[test]
    fn auth_roundtrip() {
        let a = TsgPacketAuth {
            version_caps: TsgPacketVersionCaps::client_default(TSG_NAP_CAPABILITY_QUAR_SOH),
            cookie: alloc::vec![0xAA; 128],
        };
        let got = roundtrip(&a, TsgPacketAuth::encode_ndr, TsgPacketAuth::decode_ndr);
        assert_eq!(got, a);
    }

    #[test]
    fn tsg_packet_version_caps_variant_roundtrip() {
        let p = TsgPacket::VersionCaps(TsgPacketVersionCaps::client_default(
            TSG_MESSAGING_CAP_REAUTH,
        ));
        let got = roundtrip(&p, TsgPacket::encode_ndr, TsgPacket::decode_ndr);
        assert_eq!(got, p);
        assert_eq!(got.packet_id(), TSG_PACKET_TYPE_VERSIONCAPS);
    }

    #[test]
    fn tsg_packet_response_variant_roundtrip() {
        let p = TsgPacket::Response(TsgPacketResponse {
            flags: 0,
            response_data: vec![],
            redirection_flags: TsgRedirectionFlags::default(),
        });
        let got = roundtrip(&p, TsgPacket::encode_ndr, TsgPacket::decode_ndr);
        assert_eq!(got, p);
    }

    #[test]
    fn endpoint_info_rdp_port_encoding() {
        assert_eq!(TsEndpointInfo::rdp_port(3389), 0x0003_0D3D);
    }

    #[test]
    fn endpoint_info_roundtrip_single_resource() {
        let ep = TsEndpointInfo {
            resource_names: vec![String::from("server1.contoso.com")],
            alternate_resource_names: vec![],
            port: TsEndpointInfo::rdp_port(3389),
        };
        let got = roundtrip(&ep, TsEndpointInfo::encode_ndr, TsEndpointInfo::decode_ndr);
        assert_eq!(got, ep);
    }

    #[test]
    fn endpoint_info_roundtrip_with_alternates() {
        let ep = TsEndpointInfo {
            resource_names: vec![String::from("primary.contoso.com")],
            alternate_resource_names: vec![
                String::from("alt1.contoso.com"),
                String::from("alt2.contoso.com"),
            ],
            port: TsEndpointInfo::rdp_port(3389),
        };
        let got = roundtrip(&ep, TsEndpointInfo::encode_ndr, TsEndpointInfo::decode_ndr);
        assert_eq!(got, ep);
    }

    #[test]
    fn component_id_is_ascii_tr() {
        assert_eq!(TSG_COMPONENT_ID_TR, 0x5452);
        // 0x5452 LE bytes = "RT" → reading back as "TR" because of
        // little-endian; both "TR" and "RT" appear in docs. We keep
        // the Microsoft-documented value.
        assert_eq!(TSG_COMPONENT_ID_TR.to_le_bytes(), [0x52, 0x54]);
    }

    #[test]
    fn discriminant_constants_match_spec() {
        assert_eq!(TSG_PACKET_TYPE_HEADER, 0x4844);
        assert_eq!(TSG_PACKET_TYPE_VERSIONCAPS, 0x5643);
        assert_eq!(TSG_PACKET_TYPE_QUARREQUEST, 0x5152);
        assert_eq!(TSG_PACKET_TYPE_RESPONSE, 0x5052);
        assert_eq!(TSG_PACKET_TYPE_QUARENC_RESPONSE, 0x4552);
        assert_eq!(TSG_PACKET_TYPE_CAPS_RESPONSE, 0x4350);
        assert_eq!(TSG_PACKET_TYPE_AUTH, 0x4054);
    }
}
