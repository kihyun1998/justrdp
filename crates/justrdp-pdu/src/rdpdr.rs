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
/// `IRP_MN_QUERY_DIRECTORY`, a Directory Control's minor function (2.2.1.4).
pub const IRP_MN_QUERY_DIRECTORY: u32 = 0x0000_0001;
/// `IRP_MN_NOTIFY_CHANGE_DIRECTORY`, a Directory Control's minor function (2.2.1.4).
pub const IRP_MN_NOTIFY_CHANGE_DIRECTORY: u32 = 0x0000_0002;

/// `CreateOptions`: the file opened must be a directory.
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
/// `CreateOptions`: the file opened must not be a directory.
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

/// `CreateDisposition` `FILE_SUPERSEDE`.
pub const FILE_SUPERSEDE: u32 = 0x0000_0000;
/// `CreateDisposition` `FILE_OPEN`.
pub const FILE_OPEN: u32 = 0x0000_0001;
/// `CreateDisposition` `FILE_CREATE`.
pub const FILE_CREATE: u32 = 0x0000_0002;
/// `CreateDisposition` `FILE_OPEN_IF`.
pub const FILE_OPEN_IF: u32 = 0x0000_0003;
/// `CreateDisposition` `FILE_OVERWRITE`.
pub const FILE_OVERWRITE: u32 = 0x0000_0004;
/// `CreateDisposition` `FILE_OVERWRITE_IF`.
pub const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

/// A Create response's `Information` `FILE_SUPERSEDED` (2.2.1.5.1).
pub const FILE_SUPERSEDED: u8 = 0x00;
/// A Create response's `Information` `FILE_OPENED` (2.2.1.5.1).
pub const FILE_OPENED: u8 = 0x01;
/// A Create response's `Information` `FILE_OVERWRITTEN` (2.2.1.5.1).
pub const FILE_OVERWRITTEN: u8 = 0x03;

/// `FileAttributes`: a directory (`[MS-FSCC]` 2.6).
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// `FileFullDirectoryInformation` (`[MS-FSCC]` 2.4.17).
pub const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
/// `FileBothDirectoryInformation` (`[MS-FSCC]` 2.4.8).
pub const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
/// `FileBasicInformation` (`[MS-FSCC]` 2.4.7).
pub const FILE_BASIC_INFORMATION: u32 = 4;
/// `FileStandardInformation` (`[MS-FSCC]` 2.4.47).
pub const FILE_STANDARD_INFORMATION: u32 = 5;
/// `FileFsVolumeInformation` (`[MS-FSCC]` 2.5.9).
pub const FILE_FS_VOLUME_INFORMATION: u32 = 1;
/// `FileFsAttributeInformation` (`[MS-FSCC]` 2.5.1).
pub const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
/// `FileFsFullSizeInformation` (`[MS-FSCC]` 2.5.4).
pub const FILE_FS_FULL_SIZE_INFORMATION: u32 = 7;

/// `STATUS_SUCCESS`.
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_UNSUCCESSFUL`.
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
/// `STATUS_NOT_SUPPORTED`.
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// `STATUS_NO_MORE_FILES`: a later Query Directory found nothing more (2.2.3.3.10).
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
/// `STATUS_NO_SUCH_FILE`: a first Query Directory found nothing (2.2.3.3.10).
pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
/// `STATUS_INVALID_PARAMETER`.
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// `STATUS_ACCESS_DENIED`.
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// `STATUS_OBJECT_NAME_INVALID`.
pub const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
/// `STATUS_INSUFFICIENT_RESOURCES`.
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// `STATUS_NOT_A_DIRECTORY`.
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
/// `STATUS_TOO_MANY_OPENED_FILES`.
pub const STATUS_TOO_MANY_OPENED_FILES: u32 = 0xC000_011F;
/// `STATUS_CANCELLED`.
pub const STATUS_CANCELLED: u32 = 0xC000_0120;

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

/// A Device I/O Request (2.2.1.4): its header, and the body its `major` and `minor` define.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The request's body, or why it does not decode.
    pub body: Result<IoBody, DecodeError>,
}

/// The body of a Device I/O Request a drive answers (2.2.1.4, 2.2.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoBody {
    /// Device Create Request (2.2.1.4.1).
    Create(CreateRequest),
    /// Query Volume Information Request (2.2.3.3.6).
    QueryVolumeInformation {
        /// `FsInformationClass`.
        class: u32,
    },
    /// Query Information Request (2.2.3.3.8).
    QueryInformation {
        /// `FsInformationClass`.
        class: u32,
    },
    /// Query Directory Request (2.2.3.3.10).
    QueryDirectory {
        /// `FsInformationClass`.
        class: u32,
        /// `InitialQuery`: whether `path` starts a new search.
        initial: bool,
        /// The search path, its terminating NUL removed; empty when not `initial`, since
        /// 2.2.3.3.10 says to ignore it then.
        path: Vec<u16>,
    },
    /// Any other request, whose body this decoder does not read.
    Other,
}

/// A Device Create Request's fields (2.2.1.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    /// `DesiredAccess`.
    pub desired_access: u32,
    /// `FileAttributes`.
    pub file_attributes: u32,
    /// `SharedAccess`.
    pub shared_access: u32,
    /// `CreateDisposition`.
    pub create_disposition: u32,
    /// `CreateOptions`.
    pub create_options: u32,
    /// `Path`, UTF-16 with its terminating NUL removed.
    pub path: Vec<u16>,
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
                let device_id = cur.read_u32_le()?;
                let file_id = cur.read_u32_le()?;
                let completion_id = cur.read_u32_le()?;
                let major = cur.read_u32_le()?;
                let minor = cur.read_u32_le()?;
                Ok(RdpdrPdu::IoRequest(IoRequest {
                    device_id,
                    file_id,
                    completion_id,
                    major,
                    minor,
                    body: decode_io_body(major, minor, &message[24..]),
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

fn decode_io_body(major: u32, minor: u32, body: &[u8]) -> Result<IoBody, DecodeError> {
    match (major, minor) {
        (IRP_MJ_CREATE, _) => {
            let mut cur = ReadCursor::new(body, "DR_CREATE_REQ");
            let desired_access = cur.read_u32_le()?;
            let _allocation_size = cur.read_slice(8)?;
            let file_attributes = cur.read_u32_le()?;
            let shared_access = cur.read_u32_le()?;
            let create_disposition = cur.read_u32_le()?;
            let create_options = cur.read_u32_le()?;
            let path_length = cur.read_u32_le()? as usize;
            let path = utf16_path(cur.read_slice(path_length)?, "DR_CREATE_REQ.Path")?;
            Ok(IoBody::Create(CreateRequest {
                desired_access,
                file_attributes,
                shared_access,
                create_disposition,
                create_options,
                path,
            }))
        }
        (IRP_MJ_QUERY_VOLUME_INFORMATION, _) => Ok(IoBody::QueryVolumeInformation {
            class: ReadCursor::new(body, "DR_DRIVE_QUERY_VOLUME_INFORMATION_REQ").read_u32_le()?,
        }),
        (IRP_MJ_QUERY_INFORMATION, _) => Ok(IoBody::QueryInformation {
            class: ReadCursor::new(body, "DR_DRIVE_QUERY_INFORMATION_REQ").read_u32_le()?,
        }),
        (IRP_MJ_DIRECTORY_CONTROL, IRP_MN_QUERY_DIRECTORY) => {
            let mut cur = ReadCursor::new(body, "DR_DRIVE_QUERY_DIRECTORY_REQ");
            let class = cur.read_u32_le()?;
            let initial = cur.read_u8()? != 0;
            let path_length = cur.read_u32_le()? as usize;
            let _padding = cur.read_slice(23)?;
            let path = if initial {
                utf16_path(
                    cur.read_slice(path_length)?,
                    "DR_DRIVE_QUERY_DIRECTORY_REQ.Path",
                )?
            } else {
                Vec::new()
            };
            Ok(IoBody::QueryDirectory {
                class,
                initial,
                path,
            })
        }
        _ => Ok(IoBody::Other),
    }
}

/// A NUL-terminated UTF-16 path, its trailing NULs removed.
fn utf16_path(bytes: &[u8], field: &'static str) -> Result<Vec<u16>, DecodeError> {
    let (pairs, []) = bytes.as_chunks::<2>() else {
        return Err(DecodeError::InvalidField {
            field,
            reason: "an odd number of bytes is not UTF-16",
        });
    };
    let mut units: Vec<u16> = pairs.iter().map(|&pair| u16::from_le_bytes(pair)).collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    Ok(units)
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
/// padding, a Write's or Directory Control's `Length` and padding, and every other known
/// response's `Length`. An unknown major function answers with the header alone.
pub fn failure_body(major: u32) -> &'static [u8] {
    match major {
        IRP_MJ_CREATE | IRP_MJ_WRITE | IRP_MJ_LOCK_CONTROL | IRP_MJ_DIRECTORY_CONTROL => &[0; 5],
        IRP_MJ_CLOSE
        | IRP_MJ_READ
        | IRP_MJ_QUERY_INFORMATION
        | IRP_MJ_SET_INFORMATION
        | IRP_MJ_QUERY_VOLUME_INFORMATION
        | IRP_MJ_SET_VOLUME_INFORMATION
        | IRP_MJ_DEVICE_CONTROL => &[0; 4],
        _ => &[],
    }
}

/// Whether `major` is a major function 2.2.1.4 defines.
pub fn is_known_major(major: u32) -> bool {
    !failure_body(major).is_empty()
}

/// A file's times, size and attributes as `[MS-FSCC]` structures carry them. Times are
/// `FILETIME`s: 100-nanosecond intervals since 1601-01-01 UTC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileInformation {
    /// `CreationTime`.
    pub creation_time: u64,
    /// `LastAccessTime`.
    pub last_access_time: u64,
    /// `LastWriteTime`.
    pub last_write_time: u64,
    /// `ChangeTime`.
    pub change_time: u64,
    /// `EndOfFile`: the size in bytes.
    pub end_of_file: u64,
    /// `AllocationSize`.
    pub allocation_size: u64,
    /// `FileAttributes` (`[MS-FSCC]` 2.6).
    pub attributes: u32,
}

impl FileInformation {
    /// Whether the attributes name a directory.
    pub fn is_directory(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }
}

/// A volume's label, sizes and file system as `[MS-FSCC]` 2.5 structures carry them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeInformation {
    /// `VolumeLabel`.
    pub label: String,
    /// `VolumeSerialNumber`.
    pub serial_number: u32,
    /// `VolumeCreationTime`, a `FILETIME`.
    pub creation_time: u64,
    /// `TotalAllocationUnits`.
    pub total_units: u64,
    /// `AvailableAllocationUnits`.
    pub available_units: u64,
    /// `SectorsPerAllocationUnit`.
    pub sectors_per_unit: u32,
    /// `BytesPerSector`.
    pub bytes_per_sector: u32,
    /// `FileSystemName`, such as `NTFS`.
    pub file_system: String,
    /// `FileSystemAttributes`.
    pub file_system_attributes: u32,
    /// `MaximumComponentNameLength`: at least 1 and at most 255 (`[MS-FSCC]` 2.5.1).
    pub max_component_length: u32,
}

fn utf16_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A Query Information buffer of `class` for `file` (2.2.3.3.8): `FileBasicInformation` or
/// `FileStandardInformation`, the two WS2022 asks for, and `None` for any other. `FileBasicInformation` and `FileStandardInformation` omit the
/// trailing `Reserved` field, as 2.2.3.3.8 requires.
pub fn encode_file_information(class: u32, file: &FileInformation) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match class {
        FILE_BASIC_INFORMATION => {
            for time in [
                file.creation_time,
                file.last_access_time,
                file.last_write_time,
                file.change_time,
            ] {
                out.extend_from_slice(&time.to_le_bytes());
            }
            out.extend_from_slice(&file.attributes.to_le_bytes());
        }
        FILE_STANDARD_INFORMATION => {
            out.extend_from_slice(&file.allocation_size.to_le_bytes());
            out.extend_from_slice(&file.end_of_file.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.push(0);
            out.push(u8::from(file.is_directory()));
        }
        _ => return None,
    }
    Some(out)
}

/// A Query Volume Information buffer of `class` (2.2.3.3.6): `FileFsVolumeInformation`,
/// `FileFsAttributeInformation` or `FileFsFullSizeInformation`, the three WS2022 asks for, and
/// `None` for any other. `FileFsVolumeInformation` omits its `Reserved` byte, as
/// 2.2.3.3.6 requires, and its label length counts the terminating NUL.
pub fn encode_volume_information(class: u32, volume: &VolumeInformation) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match class {
        FILE_FS_VOLUME_INFORMATION => {
            let mut label = utf16_bytes(&volume.label);
            label.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&volume.creation_time.to_le_bytes());
            out.extend_from_slice(&volume.serial_number.to_le_bytes());
            out.extend_from_slice(&(label.len() as u32).to_le_bytes());
            out.push(0);
            out.extend_from_slice(&label);
        }
        FILE_FS_FULL_SIZE_INFORMATION => {
            out.extend_from_slice(&volume.total_units.to_le_bytes());
            out.extend_from_slice(&volume.available_units.to_le_bytes());
            out.extend_from_slice(&volume.available_units.to_le_bytes());
            out.extend_from_slice(&volume.sectors_per_unit.to_le_bytes());
            out.extend_from_slice(&volume.bytes_per_sector.to_le_bytes());
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            let name = utf16_bytes(&volume.file_system);
            out.extend_from_slice(&volume.file_system_attributes.to_le_bytes());
            out.extend_from_slice(&volume.max_component_length.to_le_bytes());
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(&name);
        }
        _ => return None,
    }
    Some(out)
}

/// One Query Directory entry of `class` for the file `name` (2.2.3.3.10), alone in its
/// buffer so `NextEntryOffset` is zero: `FileFullDirectoryInformation` or
/// `FileBothDirectoryInformation`, the two WS2022 asks for, and `None` for any other. `FileBothDirectoryInformation` omits its `Reserved` byte, as 2.2.3.3.10
/// requires, and its short name is empty.
pub fn encode_directory_entry(class: u32, name: &str, file: &FileInformation) -> Option<Vec<u8>> {
    if !matches!(
        class,
        FILE_FULL_DIRECTORY_INFORMATION | FILE_BOTH_DIRECTORY_INFORMATION
    ) {
        return None;
    }
    let name = utf16_bytes(name);
    let mut out = Vec::new();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for time in [
        file.creation_time,
        file.last_access_time,
        file.last_write_time,
        file.change_time,
    ] {
        out.extend_from_slice(&time.to_le_bytes());
    }
    out.extend_from_slice(&file.end_of_file.to_le_bytes());
    out.extend_from_slice(&file.allocation_size.to_le_bytes());
    out.extend_from_slice(&file.attributes.to_le_bytes());
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    if class == FILE_BOTH_DIRECTORY_INFORMATION {
        out.push(0);
        out.extend_from_slice(&[0; 24]);
    }
    out.extend_from_slice(&name);
    Some(out)
}

/// A query response's body: `Length`, the buffer, and for a Query Volume Information or
/// Query Directory response with an empty buffer the optional padding byte FreeRDP sends.
pub fn length_prefixed(buffer: &[u8], pad_when_empty: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + buffer.len());
    out.extend_from_slice(&(buffer.len() as u32).to_le_bytes());
    out.extend_from_slice(buffer);
    if pad_when_empty && buffer.is_empty() {
        out.push(0);
    }
    out
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
                body: Err(DecodeError::NotEnoughBytes {
                    context: "DR_CREATE_REQ",
                    needed: 4,
                    got: 1,
                }),
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
        assert_eq!(lengths, [5, 4, 4, 5, 5, 5, 0]);
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

    fn utf16z(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn io_header(major: u32, minor: u32) -> Vec<u8> {
        let mut m = vec![0x72, 0x44, 0x52, 0x49];
        for field in [1u32, 2, 3, major, minor] {
            m.extend_from_slice(&field.to_le_bytes());
        }
        m
    }

    #[test]
    fn a_create_request_body_decodes() {
        let mut m = io_header(IRP_MJ_CREATE, 0);
        let path = utf16z("\\dir\\a.txt");
        for field in [
            0x0012_0089u32,
            0,
            0,
            0x80,
            7,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE,
        ] {
            m.extend_from_slice(&field.to_le_bytes());
        }
        m.extend_from_slice(&(path.len() as u32).to_le_bytes());
        m.extend_from_slice(&path);
        let Ok(RdpdrPdu::IoRequest(request)) = RdpdrPdu::decode(&m) else {
            panic!("the request decodes");
        };
        assert_eq!(
            request.body,
            Ok(IoBody::Create(CreateRequest {
                desired_access: 0x0012_0089,
                file_attributes: 0x80,
                shared_access: 7,
                create_disposition: FILE_OPEN_IF,
                create_options: FILE_NON_DIRECTORY_FILE,
                path: "\\dir\\a.txt".encode_utf16().collect(),
            }))
        );
    }

    /// 2.2.3.3.10: `PathLength` sits unaligned after the one-byte `InitialQuery`, and the path
    /// of a later query is ignored.
    #[test]
    fn a_query_directory_body_decodes() {
        let query = |initial: u8| {
            let mut m = io_header(IRP_MJ_DIRECTORY_CONTROL, IRP_MN_QUERY_DIRECTORY);
            let path = utf16z("\\*");
            m.extend_from_slice(&FILE_BOTH_DIRECTORY_INFORMATION.to_le_bytes());
            m.push(initial);
            m.extend_from_slice(&(path.len() as u32).to_le_bytes());
            m.extend_from_slice(&[0; 23]);
            m.extend_from_slice(&path);
            match RdpdrPdu::decode(&m) {
                Ok(RdpdrPdu::IoRequest(request)) => request.body,
                other => panic!("expected a request, got {other:?}"),
            }
        };
        assert_eq!(
            query(1),
            Ok(IoBody::QueryDirectory {
                class: FILE_BOTH_DIRECTORY_INFORMATION,
                initial: true,
                path: "\\*".encode_utf16().collect(),
            })
        );
        assert_eq!(
            query(0),
            Ok(IoBody::QueryDirectory {
                class: FILE_BOTH_DIRECTORY_INFORMATION,
                initial: false,
                path: Vec::new(),
            })
        );
    }

    #[test]
    fn an_odd_length_path_is_malformed() {
        let mut m = io_header(IRP_MJ_CREATE, 0);
        for field in [0u32, 0, 0, 0, 0, FILE_OPEN, 0, 3] {
            m.extend_from_slice(&field.to_le_bytes());
        }
        m.extend_from_slice(&[b'a', 0, 0]);
        let Ok(RdpdrPdu::IoRequest(request)) = RdpdrPdu::decode(&m) else {
            panic!("the header decodes");
        };
        assert!(request.body.is_err());
    }

    fn sample_file() -> FileInformation {
        FileInformation {
            creation_time: 1,
            last_access_time: 2,
            last_write_time: 3,
            change_time: 4,
            end_of_file: 5,
            allocation_size: 8,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
        }
    }

    /// The sizes 2.2.3.3.8 gives once the `Reserved` fields are dropped: Basic 36, Standard
    /// 22.
    #[test]
    fn file_information_has_the_rdpdr_layouts() {
        let file = sample_file();
        let basic = encode_file_information(FILE_BASIC_INFORMATION, &file).unwrap();
        assert_eq!(basic.len(), 36);
        assert_eq!(&basic[24..32], &4u64.to_le_bytes());
        assert_eq!(&basic[32..36], &FILE_ATTRIBUTE_DIRECTORY.to_le_bytes());
        let standard = encode_file_information(FILE_STANDARD_INFORMATION, &file).unwrap();
        assert_eq!(standard.len(), 22);
        assert_eq!(&standard[0..8], &8u64.to_le_bytes());
        assert_eq!(&standard[8..16], &5u64.to_le_bytes());
        assert_eq!(standard[21], 1, "Directory");
        assert_eq!(encode_file_information(0x23, &file), None);
    }

    /// `FileFsVolumeInformation` has 17 bytes before its label, which counts its NUL.
    #[test]
    fn volume_information_has_the_rdpdr_layouts() {
        let volume = VolumeInformation {
            label: "ab".to_string(),
            serial_number: 0x1234,
            file_system: "NTFS".to_string(),
            max_component_length: 255,
            ..VolumeInformation::default()
        };
        let v = encode_volume_information(FILE_FS_VOLUME_INFORMATION, &volume).unwrap();
        assert_eq!(v.len(), 17 + 6);
        assert_eq!(&v[12..16], &6u32.to_le_bytes());
        assert_eq!(&v[17..], &[b'a', 0, b'b', 0, 0, 0]);
        let a = encode_volume_information(FILE_FS_ATTRIBUTE_INFORMATION, &volume).unwrap();
        assert_eq!(&a[4..8], &255u32.to_le_bytes());
        assert_eq!(&a[8..12], &8u32.to_le_bytes());
        assert_eq!(a.len(), 12 + 8);
        assert_eq!(
            encode_volume_information(FILE_FS_FULL_SIZE_INFORMATION, &volume)
                .unwrap()
                .len(),
            32
        );
        for unmeasured in [3, 4] {
            assert_eq!(encode_volume_information(unmeasured, &volume), None);
        }
    }

    /// Each directory class puts the name where its layout does: 68, and 93 with the
    /// `Reserved` byte dropped as 2.2.3.3.10 requires; no NUL, and `NextEntryOffset` zero.
    #[test]
    fn directory_entries_have_the_rdpdr_layouts() {
        let file = sample_file();
        for (class, at) in [
            (FILE_FULL_DIRECTORY_INFORMATION, 68),
            (FILE_BOTH_DIRECTORY_INFORMATION, 93),
        ] {
            let entry = encode_directory_entry(class, "ab", &file).unwrap();
            assert_eq!(entry.len(), at + 4, "class {class}");
            assert_eq!(&entry[at..], &[b'a', 0, b'b', 0], "class {class}");
            assert_eq!(&entry[0..4], &[0; 4]);
            assert_eq!(&entry[60..64], &4u32.to_le_bytes(), "class {class}");
        }
        let both = encode_directory_entry(FILE_BOTH_DIRECTORY_INFORMATION, "ab", &file).unwrap();
        assert_eq!(&both[40..48], &5u64.to_le_bytes(), "EndOfFile");
        assert_eq!(&both[56..60], &FILE_ATTRIBUTE_DIRECTORY.to_le_bytes());
        for unmeasured in [1, 12] {
            assert_eq!(encode_directory_entry(unmeasured, "ab", &file), None);
        }
    }

    #[test]
    fn an_empty_query_buffer_is_padded() {
        assert_eq!(length_prefixed(&[], true), [0, 0, 0, 0, 0]);
        assert_eq!(length_prefixed(&[], false), [0, 0, 0, 0]);
        assert_eq!(length_prefixed(&[9], true), [1, 0, 0, 0, 9]);
    }

    proptest::proptest! {
        #[test]
        fn decode_never_panics_on_arbitrary_input(bytes in proptest::collection::vec(0u8.., 0..256)) {
            let _ = RdpdrPdu::decode(&bytes);
        }
    }
}
