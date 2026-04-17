#![forbid(unsafe_code)]

//! RTS (Request-to-Send) PDU and its 15 command variants from
//! **MS-RPCH §2.2.3.5**.
//!
//! RTS is the RPC-over-HTTP control channel: it carries all the
//! out-of-band information needed to set up, keep alive, and tear
//! down a virtual connection that tunnels a normal DCE/RPC
//! association over two HTTP channels (IN and OUT).
//!
//! MS-RPCH §2.2.3.1 forbids RTS PDUs from carrying an auth_verifier
//! (`auth_length` MUST be 0), from carrying any stub data outside
//! the command list, and from using a non-zero `call_id`. This
//! module enforces all three on decode.

extern crate alloc;

use alloc::vec::Vec;

use justrdp_core::{DecodeError, DecodeResult, EncodeResult, ReadCursor, WriteCursor};

use super::common::{CommonHeader, COMMON_HEADER_SIZE, PFC_FIRST_FRAG, PFC_LAST_FRAG};
use super::uuid::RpcUuid;

// =============================================================================
// PTYPE
// =============================================================================

pub const RTS_PTYPE: u8 = 0x14;

// =============================================================================
// RTS header flags (MS-RPCH §2.2.3.1)
// =============================================================================

pub const RTS_FLAG_NONE: u16 = 0x0000;
pub const RTS_FLAG_PING: u16 = 0x0001;
pub const RTS_FLAG_OTHER_CMD: u16 = 0x0002;
pub const RTS_FLAG_RECYCLE_CHANNEL: u16 = 0x0004;
pub const RTS_FLAG_IN_CHANNEL: u16 = 0x0008;
pub const RTS_FLAG_OUT_CHANNEL: u16 = 0x0010;
pub const RTS_FLAG_EOF: u16 = 0x0020;
pub const RTS_FLAG_ECHO: u16 = 0x0040;

// =============================================================================
// Command types (MS-RPCH §2.2.3.5.1 – §2.2.3.5.15)
// =============================================================================

const CMD_RECEIVE_WINDOW_SIZE: u32 = 0x0000_0000;
const CMD_FLOW_CONTROL_ACK: u32 = 0x0000_0001;
const CMD_CONNECTION_TIMEOUT: u32 = 0x0000_0002;
const CMD_COOKIE: u32 = 0x0000_0003;
const CMD_CHANNEL_LIFETIME: u32 = 0x0000_0004;
const CMD_CLIENT_KEEPALIVE: u32 = 0x0000_0005;
const CMD_VERSION: u32 = 0x0000_0006;
const CMD_EMPTY: u32 = 0x0000_0007;
const CMD_PADDING: u32 = 0x0000_0008;
const CMD_NEGATIVE_ANCE: u32 = 0x0000_0009;
const CMD_ANCE: u32 = 0x0000_000A;
const CMD_CLIENT_ADDRESS: u32 = 0x0000_000B;
const CMD_ASSOCIATION_GROUP_ID: u32 = 0x0000_000C;
const CMD_DESTINATION: u32 = 0x0000_000D;
const CMD_PING_TRAFFIC_SENT_NOTIFY: u32 = 0x0000_000E;

// =============================================================================
// RTS command
// =============================================================================

/// Individual RTS command inside an RTS PDU (MS-RPCH §2.2.3.5.1 ff).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtsCommand {
    /// §2.2.3.5.1 — 4-byte body.
    ReceiveWindowSize(u32),
    /// §2.2.3.5.2 — 24-byte body.
    FlowControlAck {
        bytes_received: u32,
        available_window: u32,
        channel_cookie: RpcUuid,
    },
    /// §2.2.3.5.3 — 4-byte body (milliseconds).
    ConnectionTimeout(u32),
    /// §2.2.3.5.4 — 16-byte GUID. Used for VirtualConnection,
    /// INChannel, and OUTChannel cookies.
    Cookie(RpcUuid),
    /// §2.2.3.5.5 — 4-byte body (bytes).
    ChannelLifetime(u32),
    /// §2.2.3.5.6 — 4-byte body (milliseconds). 0 disables keepalive.
    ClientKeepalive(u32),
    /// §2.2.3.5.7 — 4-byte body. MUST be 1.
    Version(u32),
    /// §2.2.3.5.8 — no body.
    Empty,
    /// §2.2.3.5.9 — variable-length conformance count + zero bytes.
    Padding(Vec<u8>),
    /// §2.2.3.5.10 — no body.
    NegativeAnce,
    /// §2.2.3.5.11 — no body.
    Ance,
    /// §2.2.3.5.12 — IPv4 (20 bytes total body) or IPv6 (32 bytes).
    ClientAddressV4 {
        address: [u8; 4],
        /// 12 reserved zero bytes on the wire; carried for fidelity.
        reserved: [u8; 12],
    },
    ClientAddressV6 {
        address: [u8; 16],
        reserved: [u8; 12],
    },
    /// §2.2.3.5.13 — 16-byte GUID.
    AssociationGroupId(RpcUuid),
    /// §2.2.3.5.14 — 4-byte enum. 0=FDClient, 1=FDInProxy,
    /// 2=FDServer, 3=FDOutProxy.
    Destination(u32),
    /// §2.2.3.5.15 — 4-byte body.
    PingTrafficSentNotify(u32),
}

impl RtsCommand {
    /// Wire size of this command (4-byte type + body).
    pub fn size(&self) -> usize {
        4 + match self {
            Self::ReceiveWindowSize(_) => 4,
            Self::FlowControlAck { .. } => 24,
            Self::ConnectionTimeout(_) => 4,
            Self::Cookie(_) => 16,
            Self::ChannelLifetime(_) => 4,
            Self::ClientKeepalive(_) => 4,
            Self::Version(_) => 4,
            Self::Empty => 0,
            Self::Padding(p) => 4 + p.len(),
            Self::NegativeAnce => 0,
            Self::Ance => 0,
            Self::ClientAddressV4 { .. } => 20,
            Self::ClientAddressV6 { .. } => 32,
            Self::AssociationGroupId(_) => 16,
            Self::Destination(_) => 4,
            Self::PingTrafficSentNotify(_) => 4,
        }
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        match self {
            Self::ReceiveWindowSize(v) => {
                dst.write_u32_le(CMD_RECEIVE_WINDOW_SIZE, "cmd_type")?;
                dst.write_u32_le(*v, "ReceiveWindowSize")?;
            }
            Self::FlowControlAck {
                bytes_received,
                available_window,
                channel_cookie,
            } => {
                dst.write_u32_le(CMD_FLOW_CONTROL_ACK, "cmd_type")?;
                dst.write_u32_le(*bytes_received, "FlowControlAck.bytes_received")?;
                dst.write_u32_le(*available_window, "FlowControlAck.available_window")?;
                channel_cookie.encode(dst)?;
            }
            Self::ConnectionTimeout(v) => {
                dst.write_u32_le(CMD_CONNECTION_TIMEOUT, "cmd_type")?;
                dst.write_u32_le(*v, "ConnectionTimeout")?;
            }
            Self::Cookie(u) => {
                dst.write_u32_le(CMD_COOKIE, "cmd_type")?;
                u.encode(dst)?;
            }
            Self::ChannelLifetime(v) => {
                dst.write_u32_le(CMD_CHANNEL_LIFETIME, "cmd_type")?;
                dst.write_u32_le(*v, "ChannelLifetime")?;
            }
            Self::ClientKeepalive(v) => {
                dst.write_u32_le(CMD_CLIENT_KEEPALIVE, "cmd_type")?;
                dst.write_u32_le(*v, "ClientKeepalive")?;
            }
            Self::Version(v) => {
                dst.write_u32_le(CMD_VERSION, "cmd_type")?;
                dst.write_u32_le(*v, "Version")?;
            }
            Self::Empty => {
                dst.write_u32_le(CMD_EMPTY, "cmd_type")?;
            }
            Self::Padding(pad) => {
                dst.write_u32_le(CMD_PADDING, "cmd_type")?;
                dst.write_u32_le(pad.len() as u32, "Padding.conformance")?;
                dst.write_slice(pad, "Padding.bytes")?;
            }
            Self::NegativeAnce => {
                dst.write_u32_le(CMD_NEGATIVE_ANCE, "cmd_type")?;
            }
            Self::Ance => {
                dst.write_u32_le(CMD_ANCE, "cmd_type")?;
            }
            Self::ClientAddressV4 { address, reserved } => {
                dst.write_u32_le(CMD_CLIENT_ADDRESS, "cmd_type")?;
                dst.write_u32_le(0, "ClientAddress.AddressType")?; // IPv4
                dst.write_slice(address, "ClientAddress.ipv4")?;
                dst.write_slice(reserved, "ClientAddress.reserved")?;
            }
            Self::ClientAddressV6 { address, reserved } => {
                dst.write_u32_le(CMD_CLIENT_ADDRESS, "cmd_type")?;
                dst.write_u32_le(1, "ClientAddress.AddressType")?; // IPv6
                dst.write_slice(address, "ClientAddress.ipv6")?;
                dst.write_slice(reserved, "ClientAddress.reserved")?;
            }
            Self::AssociationGroupId(u) => {
                dst.write_u32_le(CMD_ASSOCIATION_GROUP_ID, "cmd_type")?;
                u.encode(dst)?;
            }
            Self::Destination(v) => {
                dst.write_u32_le(CMD_DESTINATION, "cmd_type")?;
                dst.write_u32_le(*v, "Destination")?;
            }
            Self::PingTrafficSentNotify(v) => {
                dst.write_u32_le(CMD_PING_TRAFFIC_SENT_NOTIFY, "cmd_type")?;
                dst.write_u32_le(*v, "PingTrafficSent")?;
            }
        }
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let cmd_type = src.read_u32_le("rts.cmd_type")?;
        match cmd_type {
            CMD_RECEIVE_WINDOW_SIZE => Ok(Self::ReceiveWindowSize(
                src.read_u32_le("ReceiveWindowSize")?,
            )),
            CMD_FLOW_CONTROL_ACK => Ok(Self::FlowControlAck {
                bytes_received: src.read_u32_le("FlowControlAck.bytes_received")?,
                available_window: src.read_u32_le("FlowControlAck.available_window")?,
                channel_cookie: RpcUuid::decode(src)?,
            }),
            CMD_CONNECTION_TIMEOUT => {
                Ok(Self::ConnectionTimeout(src.read_u32_le("ConnectionTimeout")?))
            }
            CMD_COOKIE => Ok(Self::Cookie(RpcUuid::decode(src)?)),
            CMD_CHANNEL_LIFETIME => {
                Ok(Self::ChannelLifetime(src.read_u32_le("ChannelLifetime")?))
            }
            CMD_CLIENT_KEEPALIVE => {
                Ok(Self::ClientKeepalive(src.read_u32_le("ClientKeepalive")?))
            }
            CMD_VERSION => Ok(Self::Version(src.read_u32_le("Version")?)),
            CMD_EMPTY => Ok(Self::Empty),
            CMD_PADDING => {
                let len = src.read_u32_le("Padding.conformance")? as usize;
                let pad = src.read_slice(len, "Padding.bytes")?.to_vec();
                Ok(Self::Padding(pad))
            }
            CMD_NEGATIVE_ANCE => Ok(Self::NegativeAnce),
            CMD_ANCE => Ok(Self::Ance),
            CMD_CLIENT_ADDRESS => {
                let addr_type = src.read_u32_le("ClientAddress.AddressType")?;
                match addr_type {
                    0 => {
                        let a = src.read_slice(4, "ClientAddress.ipv4")?;
                        let mut address = [0u8; 4];
                        address.copy_from_slice(a);
                        let r = src.read_slice(12, "ClientAddress.reserved")?;
                        let mut reserved = [0u8; 12];
                        reserved.copy_from_slice(r);
                        Ok(Self::ClientAddressV4 { address, reserved })
                    }
                    1 => {
                        let a = src.read_slice(16, "ClientAddress.ipv6")?;
                        let mut address = [0u8; 16];
                        address.copy_from_slice(a);
                        let r = src.read_slice(12, "ClientAddress.reserved")?;
                        let mut reserved = [0u8; 12];
                        reserved.copy_from_slice(r);
                        Ok(Self::ClientAddressV6 { address, reserved })
                    }
                    _ => Err(DecodeError::invalid_value(
                        "RtsCommand",
                        "ClientAddress.AddressType",
                    )),
                }
            }
            CMD_ASSOCIATION_GROUP_ID => Ok(Self::AssociationGroupId(RpcUuid::decode(src)?)),
            CMD_DESTINATION => Ok(Self::Destination(src.read_u32_le("Destination")?)),
            CMD_PING_TRAFFIC_SENT_NOTIFY => Ok(Self::PingTrafficSentNotify(
                src.read_u32_le("PingTrafficSent")?,
            )),
            _ => Err(DecodeError::invalid_value("RtsCommand", "CommandType")),
        }
    }
}

// =============================================================================
// RTS PDU
// =============================================================================

/// RTS PDU (`ptype == 0x14`, MS-RPCH §2.2.3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtsPdu {
    /// `pfc_flags`. Typical CONN/A1 etc. set `PFC_FIRST_FRAG |
    /// PFC_LAST_FRAG`.
    pub pfc_flags: u8,
    /// RTS-specific flags (`RTS_FLAG_*`).
    pub flags: u16,
    /// Ordered list of commands.
    pub commands: Vec<RtsCommand>,
}

impl RtsPdu {
    /// Total wire size.
    pub fn size(&self) -> usize {
        let mut n = COMMON_HEADER_SIZE + 2 + 2; // common + flags + NumberOfCommands
        for c in &self.commands {
            n += c.size();
        }
        n
    }

    pub fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        // Per MS-RPCH §2.2.3.1, RTS PDUs MUST have call_id == 0 and
        // no auth_verifier. Force both.
        let hdr = CommonHeader {
            ptype: RTS_PTYPE,
            pfc_flags: self.pfc_flags,
            call_id: 0,
        };
        hdr.encode(dst, self.size() as u16, 0)?;
        dst.write_u16_le(self.flags, "rts.flags")?;
        if self.commands.len() > u16::MAX as usize {
            return Err(justrdp_core::EncodeError::other(
                "RtsPdu",
                "too many commands",
            ));
        }
        dst.write_u16_le(self.commands.len() as u16, "rts.NumberOfCommands")?;
        for c in &self.commands {
            c.encode(dst)?;
        }
        Ok(())
    }

    pub fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        let (hdr, frag_length, auth_length) = CommonHeader::decode(src)?;
        if hdr.ptype != RTS_PTYPE {
            return Err(DecodeError::invalid_value("RtsPdu", "ptype"));
        }
        if hdr.call_id != 0 {
            return Err(DecodeError::invalid_value("RtsPdu", "call_id"));
        }
        if auth_length != 0 {
            return Err(DecodeError::invalid_value("RtsPdu", "auth_length"));
        }
        let flags = src.read_u16_le("rts.flags")?;
        let n = src.read_u16_le("rts.NumberOfCommands")? as usize;
        let mut commands = Vec::with_capacity(n);
        for _ in 0..n {
            commands.push(RtsCommand::decode(src)?);
        }
        if src.pos() != frag_length as usize {
            return Err(DecodeError::invalid_value(
                "RtsPdu",
                "trailing bytes after command list",
            ));
        }
        Ok(Self {
            pfc_flags: hdr.pfc_flags,
            flags,
            commands,
        })
    }
}

// =============================================================================
// High-level connection-setup builders (MS-RPCH §2.2.4)
// =============================================================================

/// Build a CONN/A1 PDU — client to outbound proxy on the OUT channel
/// (MS-RPCH §2.2.4.2). Carries Version, VirtualConnection cookie,
/// OUTChannel cookie, and ReceiveWindowSize.
pub fn conn_a1(
    virtual_connection_cookie: RpcUuid,
    out_channel_cookie: RpcUuid,
    receive_window_size: u32,
) -> RtsPdu {
    RtsPdu {
        pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
        flags: RTS_FLAG_NONE,
        commands: Vec::from([
            RtsCommand::Version(1),
            RtsCommand::Cookie(virtual_connection_cookie),
            RtsCommand::Cookie(out_channel_cookie),
            RtsCommand::ReceiveWindowSize(receive_window_size),
        ]),
    }
}

/// Build a CONN/B1 PDU — client to inbound proxy on the IN channel
/// (MS-RPCH §2.2.4.4). Sets the `RTS_FLAG_IN_CHANNEL` bit and
/// carries Version, VC cookie, INChannel cookie, ChannelLifetime,
/// ClientKeepalive, and AssociationGroupId.
pub fn conn_b1(
    virtual_connection_cookie: RpcUuid,
    in_channel_cookie: RpcUuid,
    channel_lifetime: u32,
    client_keepalive: u32,
    association_group_id: RpcUuid,
) -> RtsPdu {
    RtsPdu {
        pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
        flags: RTS_FLAG_IN_CHANNEL,
        commands: Vec::from([
            RtsCommand::Version(1),
            RtsCommand::Cookie(virtual_connection_cookie),
            RtsCommand::Cookie(in_channel_cookie),
            RtsCommand::ChannelLifetime(channel_lifetime),
            RtsCommand::ClientKeepalive(client_keepalive),
            RtsCommand::AssociationGroupId(association_group_id),
        ]),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn cookie() -> RpcUuid {
        RpcUuid::parse("44443333-2222-1111-0000-aaaabbbbcccc").unwrap()
    }

    #[test]
    fn command_roundtrip_all_variants() {
        let cases: Vec<RtsCommand> = vec![
            RtsCommand::ReceiveWindowSize(65536),
            RtsCommand::FlowControlAck {
                bytes_received: 1024,
                available_window: 65536,
                channel_cookie: cookie(),
            },
            RtsCommand::ConnectionTimeout(120_000),
            RtsCommand::Cookie(cookie()),
            RtsCommand::ChannelLifetime(1_073_741_824),
            RtsCommand::ClientKeepalive(300_000),
            RtsCommand::Version(1),
            RtsCommand::Empty,
            RtsCommand::Padding(vec![0u8; 5]),
            RtsCommand::NegativeAnce,
            RtsCommand::Ance,
            RtsCommand::ClientAddressV4 {
                address: [192, 168, 1, 2],
                reserved: [0; 12],
            },
            RtsCommand::ClientAddressV6 {
                address: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                reserved: [0; 12],
            },
            RtsCommand::AssociationGroupId(cookie()),
            RtsCommand::Destination(2),
            RtsCommand::PingTrafficSentNotify(1024),
        ];
        for c in cases {
            let mut buf = vec![0u8; c.size()];
            let mut w = WriteCursor::new(&mut buf);
            c.encode(&mut w).unwrap();
            assert_eq!(w.pos(), c.size(), "size mismatch for {c:?}");
            let mut r = ReadCursor::new(&buf);
            let got = RtsCommand::decode(&mut r).unwrap();
            assert_eq!(got, c);
        }
    }

    #[test]
    fn conn_a1_has_expected_structure() {
        let vc = cookie();
        let out = RpcUuid::parse("deadbeef-0000-0000-0000-000000000001").unwrap();
        let pdu = conn_a1(vc, out, 65536);
        assert_eq!(pdu.flags, RTS_FLAG_NONE);
        assert_eq!(pdu.commands.len(), 4);
        match &pdu.commands[0] {
            RtsCommand::Version(1) => {}
            _ => panic!("first cmd must be Version(1)"),
        }
        match &pdu.commands[3] {
            RtsCommand::ReceiveWindowSize(65536) => {}
            _ => panic!("last cmd must be ReceiveWindowSize(65536)"),
        }
    }

    #[test]
    fn conn_b1_sets_in_channel_flag() {
        let pdu = conn_b1(cookie(), cookie(), 1_073_741_824, 300_000, cookie());
        assert_eq!(pdu.flags & RTS_FLAG_IN_CHANNEL, RTS_FLAG_IN_CHANNEL);
        assert_eq!(pdu.commands.len(), 6);
    }

    #[test]
    fn rts_pdu_roundtrip_conn_a1() {
        let pdu = conn_a1(cookie(), cookie(), 65536);
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        assert_eq!(w.pos(), pdu.size());

        let mut r = ReadCursor::new(&buf);
        let got = RtsPdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn rts_pdu_zero_call_id_enforced_on_decode() {
        // Hand-craft an RTS PDU with call_id != 0.
        let mut buf = vec![0u8; 20];
        let hdr = CommonHeader {
            ptype: RTS_PTYPE,
            pfc_flags: 0x03,
            call_id: 42, // forbidden
        };
        let mut w = WriteCursor::new(&mut buf);
        hdr.encode(&mut w, 20, 0).unwrap();
        w.write_u16_le(0, "flags").unwrap();
        w.write_u16_le(0, "n_cmds").unwrap();

        let mut r = ReadCursor::new(&buf);
        assert!(RtsPdu::decode(&mut r).is_err());
    }

    #[test]
    fn rts_pdu_nonzero_auth_length_rejected() {
        let mut buf = vec![0u8; 28];
        let hdr = CommonHeader {
            ptype: RTS_PTYPE,
            pfc_flags: 0x03,
            call_id: 0,
        };
        let mut w = WriteCursor::new(&mut buf);
        hdr.encode(&mut w, 28, 8).unwrap(); // fake auth_length=8
        w.write_u16_le(0, "flags").unwrap();
        w.write_u16_le(0, "n_cmds").unwrap();

        let mut r = ReadCursor::new(&buf);
        assert!(RtsPdu::decode(&mut r).is_err());
    }

    #[test]
    fn rts_pdu_trailing_bytes_rejected() {
        // Encode a valid RTS PDU then decode from a buffer that
        // declares an overly long frag_length.
        let pdu = conn_a1(cookie(), cookie(), 65536);
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        // Rewrite frag_length to declare 10 extra bytes.
        let bogus_frag = (pdu.size() + 10) as u16;
        buf[8..10].copy_from_slice(&bogus_frag.to_le_bytes());
        buf.extend(vec![0; 10]);
        let mut r = ReadCursor::new(&buf);
        assert!(RtsPdu::decode(&mut r).is_err());
    }

    #[test]
    fn unknown_command_type_rejected() {
        let mut buf = [0u8; 4];
        buf[0] = 0xFF;
        buf[1] = 0xFF;
        buf[2] = 0x00;
        buf[3] = 0x00;
        let mut r = ReadCursor::new(&buf);
        assert!(RtsCommand::decode(&mut r).is_err());
    }

    #[test]
    fn ping_pdu_shape() {
        // A ping PDU has PING flag + an Empty command.
        let pdu = RtsPdu {
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            flags: RTS_FLAG_PING,
            commands: vec![RtsCommand::Empty],
        };
        let mut buf = vec![0u8; pdu.size()];
        let mut w = WriteCursor::new(&mut buf);
        pdu.encode(&mut w).unwrap();
        let mut r = ReadCursor::new(&buf);
        let got = RtsPdu::decode(&mut r).unwrap();
        assert_eq!(got, pdu);
    }

    #[test]
    fn flow_control_ack_exact_bytes() {
        let cmd = RtsCommand::FlowControlAck {
            bytes_received: 0x1122_3344,
            available_window: 0x55667788,
            channel_cookie: RpcUuid {
                data1: 0xAABB_CCDD,
                data2: 0xEEFF,
                data3: 0x0011,
                data4: [0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99],
            },
        };
        let mut buf = vec![0u8; cmd.size()];
        let mut w = WriteCursor::new(&mut buf);
        cmd.encode(&mut w).unwrap();
        assert_eq!(
            buf,
            vec![
                // CommandType = 0x00000001
                0x01, 0x00, 0x00, 0x00,
                // bytes_received LE
                0x44, 0x33, 0x22, 0x11,
                // available_window LE
                0x88, 0x77, 0x66, 0x55,
                // UUID (mixed endian)
                0xDD, 0xCC, 0xBB, 0xAA,
                0xFF, 0xEE,
                0x11, 0x00,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            ]
        );
    }
}
