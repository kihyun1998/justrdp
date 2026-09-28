//! Device redirection virtual channel PDUs (MS-RDPEFS), carried over the static channel
//! [`CHANNEL_NAME`]. Every PDU is one whole channel message starting with an `RDPDR_HEADER`
//! (2.2.1.1). The initialization sequence (1.3.1) is Server Announce, then Client Announce
//! Reply and Client Name, answered by Server Core Capability Request and Server Client ID
//! Confirm, then Client Core Capability Response and, after User Logged On, Client Device List
//! Announce.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// The static channel name (2.1).
pub const CHANNEL_NAME: &str = "rdpdr";

/// `RDPDR_CTYP_CORE`: the component of every PDU but the printer ones (2.2.1.1).
pub const RDPDR_CTYP_CORE: u16 = 0x4472;

/// `PAKID_CORE_SERVER_ANNOUNCE` (2.2.2.2).
pub const PAKID_CORE_SERVER_ANNOUNCE: u16 = 0x496E;
/// `PAKID_CORE_CLIENTID_CONFIRM`: Client Announce Reply (2.2.2.3) and Server Client ID
/// Confirm (2.2.2.6).
pub const PAKID_CORE_CLIENTID_CONFIRM: u16 = 0x4343;
/// `PAKID_CORE_CLIENT_NAME` (2.2.2.4).
pub const PAKID_CORE_CLIENT_NAME: u16 = 0x434E;
/// `PAKID_CORE_DEVICELIST_ANNOUNCE` (2.2.2.9).
pub const PAKID_CORE_DEVICELIST_ANNOUNCE: u16 = 0x4441;
/// `PAKID_CORE_DEVICE_REPLY`: Server Device Announce Response (2.2.2.1).
pub const PAKID_CORE_DEVICE_REPLY: u16 = 0x6472;
/// `PAKID_CORE_DEVICE_IOREQUEST` (2.2.1.4).
pub const PAKID_CORE_DEVICE_IOREQUEST: u16 = 0x4952;
/// `PAKID_CORE_DEVICE_IOCOMPLETION` (2.2.1.5).
pub const PAKID_CORE_DEVICE_IOCOMPLETION: u16 = 0x4943;
/// `PAKID_CORE_SERVER_CAPABILITY` (2.2.2.7).
pub const PAKID_CORE_SERVER_CAPABILITY: u16 = 0x5350;
/// `PAKID_CORE_CLIENT_CAPABILITY` (2.2.2.8).
pub const PAKID_CORE_CLIENT_CAPABILITY: u16 = 0x4350;
/// `PAKID_CORE_USER_LOGGEDON` (2.2.2.5).
pub const PAKID_CORE_USER_LOGGEDON: u16 = 0x554C;

/// `CAP_GENERAL_TYPE` (2.2.1.2).
pub const CAP_GENERAL_TYPE: u16 = 0x0001;
/// `CAP_DRIVE_TYPE` (2.2.1.2).
pub const CAP_DRIVE_TYPE: u16 = 0x0004;
/// `GENERAL_CAPABILITY_VERSION_02`: the General set carries `SpecialTypeDeviceCap` (2.2.1.2).
pub const GENERAL_CAPABILITY_VERSION_02: u32 = 0x0000_0002;
/// `DRIVE_CAPABILITY_VERSION_02`: a drive's full name may travel in `DeviceData` (2.2.1.2).
pub const DRIVE_CAPABILITY_VERSION_02: u32 = 0x0000_0002;

/// `ioCode1` bits 0x1 through 0x2000, which 2.2.2.7.1 marks "Unused, always set".
pub const IO_CODE1_ALWAYS_SET: u32 = 0x0000_3FFF;
/// `extendedPDU`: `RDPDR_CLIENT_DISPLAY_NAME_PDU`, "Unused, always set" (2.2.2.7.1).
pub const RDPDR_CLIENT_DISPLAY_NAME_PDU: u32 = 0x0000_0002;
/// `extendedPDU`: the server may send User Logged On (2.2.2.7.1).
pub const RDPDR_USER_LOGGEDON_PDU: u32 = 0x0000_0004;

/// `RDPDR_DTYP_FILESYSTEM` (2.2.1.3).
pub const RDPDR_DTYP_FILESYSTEM: u32 = 0x0000_0008;

/// `IRP_MJ_CREATE` (2.2.1.4).
pub const IRP_MJ_CREATE: u32 = 0x0000_0000;
/// `IRP_MJ_CLOSE` (2.2.1.4).
pub const IRP_MJ_CLOSE: u32 = 0x0000_0002;
/// `IRP_MJ_READ` (2.2.1.4).
pub const IRP_MJ_READ: u32 = 0x0000_0003;
/// `IRP_MJ_WRITE` (2.2.1.4).
pub const IRP_MJ_WRITE: u32 = 0x0000_0004;
/// `IRP_MJ_QUERY_INFORMATION` (2.2.1.4).
pub const IRP_MJ_QUERY_INFORMATION: u32 = 0x0000_0005;
/// `IRP_MJ_SET_INFORMATION` (2.2.1.4).
pub const IRP_MJ_SET_INFORMATION: u32 = 0x0000_0006;
/// `IRP_MJ_QUERY_VOLUME_INFORMATION` (2.2.1.4).
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: u32 = 0x0000_000A;
/// `IRP_MJ_SET_VOLUME_INFORMATION` (2.2.1.4).
pub const IRP_MJ_SET_VOLUME_INFORMATION: u32 = 0x0000_000B;
/// `IRP_MJ_DIRECTORY_CONTROL` (2.2.1.4).
pub const IRP_MJ_DIRECTORY_CONTROL: u32 = 0x0000_000C;
/// `IRP_MJ_DEVICE_CONTROL` (2.2.1.4).
pub const IRP_MJ_DEVICE_CONTROL: u32 = 0x0000_000E;
/// `IRP_MJ_LOCK_CONTROL` (2.2.1.4).
pub const IRP_MJ_LOCK_CONTROL: u32 = 0x0000_0011;

/// `STATUS_SUCCESS`.
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_UNSUCCESSFUL`.
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
/// `STATUS_NOT_SUPPORTED`.
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// The `PreferredDosName` field's size, NUL included (2.2.1.3).
pub const DOS_NAME_SIZE: usize = 8;

/// The General capability set (2.2.2.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralCapability {
    /// The capability set's version: 1, or [`GENERAL_CAPABILITY_VERSION_02`], which adds
    /// `special_type_device_cap`.
    pub version: u32,
    /// `osType`, which the receiver ignores.
    pub os_type: u32,
    /// `osVersion`, which the receiver ignores.
    pub os_version: u32,
    /// `protocolMinorVersion`.
    pub protocol_minor: u16,
    /// `ioCode1`: the I/O requests allowed.
    pub io_code1: u32,
    /// `extendedPDU`.
    pub extended_pdu: u32,
    /// `extraFlags1`.
    pub extra_flags1: u32,
    /// `SpecialTypeDeviceCap`: devices announced before logon (version 2 only).
    pub special_type_device_cap: u32,
}

/// One capability set of a Core Capability Request or Response (2.2.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilitySet {
    /// The General capability set.
    General(GeneralCapability),
    /// A set carrying only its header: printer, port, drive or smartcard (2.2.2.7.2-5).
    Other {
        /// `CapabilityType`.
        kind: u16,
        /// The set's version.
        version: u32,
    },
}

/// A Device I/O Request's header (2.2.1.4). The body after it depends on `major`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoRequest {
    /// The device the request is for.
    pub device_id: u32,
    /// The file the request is for, after a Create.
    pub file_id: u32,
    /// The ID its completion must carry.
    pub completion_id: u32,
    /// `MajorFunction`.
    pub major: u32,
    /// `MinorFunction`.
    pub minor: u32,
}

/// A device in a Client Device List Announce (2.2.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAnnounce {
    /// `DeviceType`.
    pub device_type: u32,
    /// `DeviceId`, unique among the devices announced.
    pub device_id: u32,
    /// `PreferredDosName`: ASCII, NUL-terminated.
    pub preferred_dos_name: [u8; DOS_NAME_SIZE],
    /// `DeviceData`.
    pub device_data: Vec<u8>,
}

/// A device redirection message the server sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdpdrPdu {
    /// Server Announce Request (2.2.2.2).
    ServerAnnounce {
        /// The server's `VersionMinor`.
        version_minor: u16,
        /// The `ClientId` the server offers.
        client_id: u32,
    },
    /// Server Client ID Confirm (2.2.2.6).
    ClientIdConfirm {
        /// The server's `VersionMinor`.
        version_minor: u16,
        /// The `ClientId` of the Client Announce Reply.
        client_id: u32,
    },
    /// Server Core Capability Request (2.2.2.7).
    ServerCapabilities(Vec<CapabilitySet>),
    /// Server User Logged On (2.2.2.5).
    UserLoggedOn,
    /// Server Device Announce Response (2.2.2.1).
    DeviceAnnounceResponse {
        /// The device announced.
        device_id: u32,
        /// `ResultCode`, an NTSTATUS.
        result_code: u32,
    },
    /// Device I/O Request (2.2.1.4).
    IoRequest(IoRequest),
    /// A message this decoder does not handle.
    Unknown {
        /// `Component`.
        component: u16,
        /// `PacketId`.
        packet_id: u16,
    },
}

impl RdpdrPdu {
    /// Decode one complete device redirection message the server sent.
    pub fn decode(message: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(message, "RDPDR_HEADER");
        let component = cur.read_u16_le()?;
        let packet_id = cur.read_u16_le()?;
        if component != RDPDR_CTYP_CORE {
            return Ok(RdpdrPdu::Unknown {
                component,
                packet_id,
            });
        }
        match packet_id {
            PAKID_CORE_SERVER_ANNOUNCE | PAKID_CORE_CLIENTID_CONFIRM => {
                let mut cur = ReadCursor::new(&message[4..], "DR_CORE_SERVER_ANNOUNCE_REQ");
                let _version_major = cur.read_u16_le()?;
                let version_minor = cur.read_u16_le()?;
                let client_id = cur.read_u32_le()?;
                Ok(if packet_id == PAKID_CORE_SERVER_ANNOUNCE {
                    RdpdrPdu::ServerAnnounce {
                        version_minor,
                        client_id,
                    }
                } else {
                    RdpdrPdu::ClientIdConfirm {
                        version_minor,
                        client_id,
                    }
                })
            }
            PAKID_CORE_SERVER_CAPABILITY => decode_capabilities(&message[4..]),
            PAKID_CORE_USER_LOGGEDON => Ok(RdpdrPdu::UserLoggedOn),
            PAKID_CORE_DEVICE_REPLY => {
                let mut cur = ReadCursor::new(&message[4..], "DR_CORE_DEVICE_ANNOUNCE_RSP");
                Ok(RdpdrPdu::DeviceAnnounceResponse {
                    device_id: cur.read_u32_le()?,
                    result_code: cur.read_u32_le()?,
                })
            }
            PAKID_CORE_DEVICE_IOREQUEST => {
                let mut cur = ReadCursor::new(&message[4..], "DR_DEVICE_IOREQUEST");
                Ok(RdpdrPdu::IoRequest(IoRequest {
                    device_id: cur.read_u32_le()?,
                    file_id: cur.read_u32_le()?,
                    completion_id: cur.read_u32_le()?,
                    major: cur.read_u32_le()?,
                    minor: cur.read_u32_le()?,
                }))
            }
            packet_id => Ok(RdpdrPdu::Unknown {
                component,
                packet_id,
            }),
        }
    }
}

/// The capability sets after a Core Capability header (2.2.2.7). Each set is read to its
/// declared `CapabilityLength`, so fields a later version appends are skipped.
fn decode_capabilities(body: &[u8]) -> Result<RdpdrPdu, DecodeError> {
    let mut cur = ReadCursor::new(body, "DR_CORE_CAPABILITY_REQ");
    let count = cur.read_u16_le()?;
    let _padding = cur.read_u16_le()?;
    let mut sets = Vec::new();
    for _ in 0..count {
        let kind = cur.read_u16_le()?;
        let length = cur.read_u16_le()? as usize;
        let version = cur.read_u32_le()?;
        let Some(rest) = length.checked_sub(8) else {
            return Err(DecodeError::InvalidField {
                field: "CAPABILITY_HEADER.CapabilityLength",
                reason: "shorter than the header it includes",
            });
        };
        let data = cur.read_slice(rest)?;
        sets.push(if kind == CAP_GENERAL_TYPE {
            CapabilitySet::General(decode_general(version, data)?)
        } else {
            CapabilitySet::Other { kind, version }
        });
    }
    Ok(RdpdrPdu::ServerCapabilities(sets))
}

fn decode_general(version: u32, data: &[u8]) -> Result<GeneralCapability, DecodeError> {
    let mut cur = ReadCursor::new(data, "GENERAL_CAPS_SET");
    let os_type = cur.read_u32_le()?;
    let os_version = cur.read_u32_le()?;
    let _protocol_major = cur.read_u16_le()?;
    let protocol_minor = cur.read_u16_le()?;
    let io_code1 = cur.read_u32_le()?;
    let _io_code2 = cur.read_u32_le()?;
    let extended_pdu = cur.read_u32_le()?;
    let extra_flags1 = cur.read_u32_le()?;
    let _extra_flags2 = cur.read_u32_le()?;
    let special_type_device_cap = if version >= GENERAL_CAPABILITY_VERSION_02 {
        cur.read_u32_le()?
    } else {
        0
    };
    Ok(GeneralCapability {
        version,
        os_type,
        os_version,
        protocol_minor,
        io_code1,
        extended_pdu,
        extra_flags1,
        special_type_device_cap,
    })
}

fn with_header(packet_id: u16, body_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body_len);
    out.extend_from_slice(&RDPDR_CTYP_CORE.to_le_bytes());
    out.extend_from_slice(&packet_id.to_le_bytes());
    out
}

/// A Client Announce Reply (2.2.2.3).
pub fn encode_client_announce_reply(version_minor: u16, client_id: u32) -> Vec<u8> {
    let mut out = with_header(PAKID_CORE_CLIENTID_CONFIRM, 8);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&version_minor.to_le_bytes());
    out.extend_from_slice(&client_id.to_le_bytes());
    out
}

/// A Client Name Request carrying `name` as NUL-terminated UTF-16 (2.2.2.4).
pub fn encode_client_name(name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut out = with_header(PAKID_CORE_CLIENT_NAME, 12 + units.len() * 2);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&((units.len() * 2) as u32).to_le_bytes());
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// A Client Core Capability Response (2.2.2.8).
pub fn encode_client_capabilities(sets: &[CapabilitySet]) -> Vec<u8> {
    let mut out = with_header(PAKID_CORE_CLIENT_CAPABILITY, 4 + sets.len() * 44);
    out.extend_from_slice(&(sets.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    for set in sets {
        match set {
            CapabilitySet::General(general) => {
                let v2 = general.version >= GENERAL_CAPABILITY_VERSION_02;
                let length: u16 = if v2 { 44 } else { 40 };
                out.extend_from_slice(&CAP_GENERAL_TYPE.to_le_bytes());
                out.extend_from_slice(&length.to_le_bytes());
                out.extend_from_slice(&general.version.to_le_bytes());
                out.extend_from_slice(&general.os_type.to_le_bytes());
                out.extend_from_slice(&general.os_version.to_le_bytes());
                out.extend_from_slice(&1u16.to_le_bytes());
                out.extend_from_slice(&general.protocol_minor.to_le_bytes());
                out.extend_from_slice(&general.io_code1.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&general.extended_pdu.to_le_bytes());
                out.extend_from_slice(&general.extra_flags1.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                if v2 {
                    out.extend_from_slice(&general.special_type_device_cap.to_le_bytes());
                }
            }
            CapabilitySet::Other { kind, version } => {
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(&8u16.to_le_bytes());
                out.extend_from_slice(&version.to_le_bytes());
            }
        }
    }
    out
}

/// A Client Device List Announce Request (2.2.2.9). The devices follow each other with no
/// padding.
pub fn encode_device_list_announce(devices: &[DeviceAnnounce]) -> Vec<u8> {
    let data: usize = devices.iter().map(|d| 20 + d.device_data.len()).sum();
    let mut out = with_header(PAKID_CORE_DEVICELIST_ANNOUNCE, 4 + data);
    out.extend_from_slice(&(devices.len() as u32).to_le_bytes());
    for device in devices {
        out.extend_from_slice(&device.device_type.to_le_bytes());
        out.extend_from_slice(&device.device_id.to_le_bytes());
        out.extend_from_slice(&device.preferred_dos_name);
        out.extend_from_slice(&(device.device_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&device.device_data);
    }
    out
}

/// A Device I/O Response (2.2.1.5): the completion header, then `body`, the fields the
/// request's major function answers with.
pub fn encode_io_completion(
    device_id: u32,
    completion_id: u32,
    io_status: u32,
    body: &[u8],
) -> Vec<u8> {
    let mut out = with_header(PAKID_CORE_DEVICE_IOCOMPLETION, 12 + body.len());
    out.extend_from_slice(&device_id.to_le_bytes());
    out.extend_from_slice(&completion_id.to_le_bytes());
    out.extend_from_slice(&io_status.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// The zero-filled fields a failed response to `major` carries after its completion header
/// (2.2.1.5.1-5, 2.2.3.4): a Create's `FileId` and `Information`, a Close's or Lock's
/// padding, a Write's `Length` and padding, and every other known response's `Length`. An
/// unknown major function answers with the header alone.
pub fn failure_body(major: u32) -> &'static [u8] {
    match major {
        IRP_MJ_CREATE | IRP_MJ_WRITE | IRP_MJ_LOCK_CONTROL => &[0; 5],
        IRP_MJ_CLOSE
        | IRP_MJ_READ
        | IRP_MJ_QUERY_INFORMATION
        | IRP_MJ_SET_INFORMATION
        | IRP_MJ_QUERY_VOLUME_INFORMATION
        | IRP_MJ_SET_VOLUME_INFORMATION
        | IRP_MJ_DIRECTORY_CONTROL
        | IRP_MJ_DEVICE_CONTROL => &[0; 4],
        _ => &[],
    }
}

/// Whether `major` is a major function 2.2.1.4 defines.
pub fn is_known_major(major: u32) -> bool {
    !failure_body(major).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[MS-RDPEFS]` 4.3.
    const SERVER_ANNOUNCE: [u8; 12] = [
        0x72, 0x44, 0x6e, 0x49, 0x01, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn the_spec_server_announce_decodes() {
        assert_eq!(
            RdpdrPdu::decode(&SERVER_ANNOUNCE),
            Ok(RdpdrPdu::ServerAnnounce {
                version_minor: 0x0c,
                client_id: 1
            })
        );
    }

    #[test]
    fn the_spec_client_announce_reply_encodes() {
        assert_eq!(
            encode_client_announce_reply(0x0c, 1),
            [
                0x72, 0x44, 0x43, 0x43, 0x01, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn the_spec_client_name_encodes() {
        let expected: Vec<u8> = [
            0x72, 0x44, 0x4e, 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00,
            0x00, 0x00, 0x54, 0x00, 0x53, 0x00, 0x44, 0x00, 0x45, 0x00, 0x56, 0x00, 0x2d, 0x00,
            0x53, 0x00, 0x45, 0x00, 0x4c, 0x00, 0x46, 0x00, 0x48, 0x00, 0x4f, 0x00, 0x53, 0x00,
            0x54, 0x00, 0x00, 0x00,
        ]
        .to_vec();
        assert_eq!(encode_client_name("TSDEV-SELFHOST"), expected);
    }

    /// `[MS-RDPEFS]` 4.9. Its hex holds `osVersion` 0x00060000, where the annotation says zero.
    const SPEC_CAPABILITIES_BODY: [u8; 80] = [
        0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x0c, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x08, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x08,
        0x00, 0x01, 0x00, 0x00, 0x00,
    ];

    fn spec_capability_sets() -> Vec<CapabilitySet> {
        vec![
            CapabilitySet::General(GeneralCapability {
                version: GENERAL_CAPABILITY_VERSION_02,
                os_type: 2,
                os_version: 0x0006_0000,
                protocol_minor: 0x0c,
                io_code1: 0xffff,
                extended_pdu: 7,
                extra_flags1: 0,
                special_type_device_cap: 2,
            }),
            CapabilitySet::Other {
                kind: 2,
                version: 1,
            },
            CapabilitySet::Other {
                kind: 3,
                version: 1,
            },
            CapabilitySet::Other {
                kind: CAP_DRIVE_TYPE,
                version: DRIVE_CAPABILITY_VERSION_02,
            },
            CapabilitySet::Other {
                kind: 5,
                version: 1,
            },
        ]
    }

    #[test]
    fn the_spec_client_capabilities_encode() {
        let mut expected = vec![0x72, 0x44, 0x50, 0x43];
        expected.extend_from_slice(&SPEC_CAPABILITIES_BODY);
        assert_eq!(
            encode_client_capabilities(&spec_capability_sets()),
            expected
        );
    }

    /// The same sets under the server's packet ID decode to what they were built from.
    #[test]
    fn server_capabilities_decode() {
        let mut message = vec![0x72, 0x44, 0x50, 0x53];
        message.extend_from_slice(&SPEC_CAPABILITIES_BODY);
        assert_eq!(
            RdpdrPdu::decode(&message),
            Ok(RdpdrPdu::ServerCapabilities(spec_capability_sets()))
        );
    }

    /// A General set from a later version, longer than this decoder reads, is read to its
    /// declared length and the sets after it still decode.
    #[test]
    fn a_longer_capability_set_is_skipped_to_its_length() {
        let mut message = vec![0x72, 0x44, 0x50, 0x53, 0x02, 0x00, 0x00, 0x00];
        message.extend_from_slice(&[0x01, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 0x00]);
        message.extend_from_slice(&[0; 40]);
        message.extend_from_slice(&[0x04, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]);
        let Ok(RdpdrPdu::ServerCapabilities(sets)) = RdpdrPdu::decode(&message) else {
            panic!("the capabilities decode");
        };
        assert_eq!(
            sets[1],
            CapabilitySet::Other {
                kind: CAP_DRIVE_TYPE,
                version: 2
            }
        );
    }

    #[test]
    fn a_capability_length_below_its_header_is_an_error() {
        let message = [
            0x72, 0x44, 0x50, 0x53, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x07, 0x00, 0x02, 0x00,
            0x00, 0x00,
        ];
        assert!(RdpdrPdu::decode(&message).is_err());
    }

    #[test]
    fn the_spec_device_list_announce_encodes() {
        let drive = |id: u32, letter: u8| DeviceAnnounce {
            device_type: RDPDR_DTYP_FILESYSTEM,
            device_id: id,
            preferred_dos_name: [letter, b':', 0, 0, 0, 0, 0, 0],
            device_data: Vec::new(),
        };
        let expected: Vec<u8> = [
            0x72, 0x44, 0x41, 0x44, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x00, 0x45, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x44, 0x3a, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x43, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
        .to_vec();
        assert_eq!(
            encode_device_list_announce(&[drive(3, b'E'), drive(2, b'D'), drive(1, b'C')]),
            expected
        );
    }

    #[test]
    fn user_logged_on_and_device_reply_decode() {
        assert_eq!(
            RdpdrPdu::decode(&[0x72, 0x44, 0x4c, 0x55]),
            Ok(RdpdrPdu::UserLoggedOn)
        );
        assert_eq!(
            RdpdrPdu::decode(&[
                0x72, 0x44, 0x72, 0x64, 0x07, 0x00, 0x00, 0x00, 0xbb, 0x00, 0x00, 0xc0
            ]),
            Ok(RdpdrPdu::DeviceAnnounceResponse {
                device_id: 7,
                result_code: STATUS_NOT_SUPPORTED
            })
        );
    }

    #[test]
    fn an_io_request_header_decodes_and_its_completion_encodes() {
        let request = [
            0x72, 0x44, 0x52, 0x49, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa,
        ];
        assert_eq!(
            RdpdrPdu::decode(&request),
            Ok(RdpdrPdu::IoRequest(IoRequest {
                device_id: 1,
                file_id: 2,
                completion_id: 3,
                major: IRP_MJ_CREATE,
                minor: 0,
            }))
        );
        assert_eq!(
            encode_io_completion(1, 3, STATUS_NOT_SUPPORTED, failure_body(IRP_MJ_CREATE)),
            [
                0x72, 0x44, 0x43, 0x49, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xbb, 0x00,
                0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn failure_bodies_follow_each_response_layout() {
        let lengths: Vec<_> = [
            IRP_MJ_CREATE,
            IRP_MJ_CLOSE,
            IRP_MJ_READ,
            IRP_MJ_WRITE,
            IRP_MJ_LOCK_CONTROL,
            IRP_MJ_DIRECTORY_CONTROL,
            0x0000_0001,
        ]
        .iter()
        .map(|&major| failure_body(major).len())
        .collect();
        assert_eq!(lengths, [5, 4, 4, 5, 5, 4, 0]);
        assert!(!is_known_major(0x0000_0001));
    }

    #[test]
    fn a_printer_component_is_unknown_and_a_short_message_is_an_error() {
        assert_eq!(
            RdpdrPdu::decode(&[0x52, 0x50, 0x43, 0x50]),
            Ok(RdpdrPdu::Unknown {
                component: 0x5052,
                packet_id: 0x5043
            })
        );
        assert!(RdpdrPdu::decode(&[0x72, 0x44, 0x6e]).is_err());
        assert!(RdpdrPdu::decode(&SERVER_ANNOUNCE[..11]).is_err());
    }

    proptest::proptest! {
        #[test]
        fn decode_never_panics_on_arbitrary_input(bytes in proptest::collection::vec(0u8.., 0..256)) {
            let _ = RdpdrPdu::decode(&bytes);
        }
    }
}
