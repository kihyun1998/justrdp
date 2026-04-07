#![forbid(unsafe_code)]

//! IRP (I/O Request Packet) PDUs -- MS-RDPEFS 2.2.1.4, 2.2.1.5, 2.2.3.3, 2.2.3.4

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{Decode, DecodeError, DecodeResult, Encode, EncodeResult};
use justrdp_core::{ReadCursor, WriteCursor};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum buffer size on decode to prevent unbounded allocation (16 MB).
const MAX_IO_BUFFER: u32 = 16 * 1024 * 1024;

/// Maximum number of locks per request.
const MAX_LOCK_COUNT: u32 = 4096;

// NTSTATUS codes -- MS-ERREF 2.3.1
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

// CreateDisposition -- MS-SMB2 2.2.13
pub const FILE_SUPERSEDE: u32 = 0x0000_0000;
pub const FILE_OPEN: u32 = 0x0000_0001;
pub const FILE_CREATE: u32 = 0x0000_0002;
pub const FILE_OPEN_IF: u32 = 0x0000_0003;
pub const FILE_OVERWRITE: u32 = 0x0000_0004;
pub const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

// FileAttributes -- MS-SMB2 2.2.13
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

// FsInformationClass -- file info (MS-FSCC 2.4)
pub const FILE_BASIC_INFORMATION: u32 = 0x0000_0004;
pub const FILE_STANDARD_INFORMATION: u32 = 0x0000_0005;
pub const FILE_RENAME_INFORMATION: u32 = 0x0000_000A;
pub const FILE_DISPOSITION_INFORMATION: u32 = 0x0000_000D;
pub const FILE_ALLOCATION_INFORMATION: u32 = 0x0000_0013;
pub const FILE_END_OF_FILE_INFORMATION: u32 = 0x0000_0014;
pub const FILE_ATTRIBUTE_TAG_INFORMATION: u32 = 0x0000_0023;

// FsInformationClass -- volume info (MS-FSCC 2.5)
pub const FILE_FS_VOLUME_INFORMATION: u32 = 0x0000_0001;
pub const FILE_FS_SIZE_INFORMATION: u32 = 0x0000_0003;
pub const FILE_FS_DEVICE_INFORMATION: u32 = 0x0000_0004;
pub const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 0x0000_0005;
pub const FILE_FS_FULL_SIZE_INFORMATION: u32 = 0x0000_0007;

// FsInformationClass -- directory info (MS-FSCC 2.4)
pub const FILE_DIRECTORY_INFORMATION: u32 = 0x0000_0001;
pub const FILE_FULL_DIRECTORY_INFORMATION: u32 = 0x0000_0002;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 0x0000_0003;
pub const FILE_NAMES_INFORMATION: u32 = 0x0000_000C;

// ── MajorFunction -- MS-RDPEFS 2.2.1.4 ──────────────────────────────────────

/// IRP major function codes -- MS-RDPEFS 2.2.1.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MajorFunction {
    /// IRP_MJ_CREATE
    Create = 0x0000_0000,
    /// IRP_MJ_CLOSE
    Close = 0x0000_0002,
    /// IRP_MJ_READ
    Read = 0x0000_0003,
    /// IRP_MJ_WRITE
    Write = 0x0000_0004,
    /// IRP_MJ_QUERY_INFORMATION
    QueryInformation = 0x0000_0005,
    /// IRP_MJ_SET_INFORMATION
    SetInformation = 0x0000_0006,
    /// IRP_MJ_QUERY_VOLUME_INFORMATION
    QueryVolumeInformation = 0x0000_000A,
    /// IRP_MJ_SET_VOLUME_INFORMATION
    SetVolumeInformation = 0x0000_000B,
    /// IRP_MJ_DIRECTORY_CONTROL
    DirectoryControl = 0x0000_000C,
    /// IRP_MJ_DEVICE_CONTROL
    DeviceControl = 0x0000_000E,
    /// IRP_MJ_LOCK_CONTROL
    LockControl = 0x0000_0011,
}

impl MajorFunction {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x0000_0000 => Some(Self::Create),
            0x0000_0002 => Some(Self::Close),
            0x0000_0003 => Some(Self::Read),
            0x0000_0004 => Some(Self::Write),
            0x0000_0005 => Some(Self::QueryInformation),
            0x0000_0006 => Some(Self::SetInformation),
            0x0000_000A => Some(Self::QueryVolumeInformation),
            0x0000_000B => Some(Self::SetVolumeInformation),
            0x0000_000C => Some(Self::DirectoryControl),
            0x0000_000E => Some(Self::DeviceControl),
            0x0000_0011 => Some(Self::LockControl),
            _ => None,
        }
    }
}

// ── MinorFunction -- MS-RDPEFS 2.2.1.4 ──────────────────────────────────────

/// IRP minor function codes -- MS-RDPEFS 2.2.1.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MinorFunction {
    /// No minor function.
    None = 0x0000_0000,
    /// IRP_MN_QUERY_DIRECTORY
    QueryDirectory = 0x0000_0001,
    /// IRP_MN_NOTIFY_CHANGE_DIRECTORY
    NotifyChangeDirectory = 0x0000_0002,
}

impl MinorFunction {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x0000_0000 => Some(Self::None),
            0x0000_0001 => Some(Self::QueryDirectory),
            0x0000_0002 => Some(Self::NotifyChangeDirectory),
            _ => None,
        }
    }
}

// ── DeviceIoRequest -- MS-RDPEFS 2.2.1.4 ────────────────────────────────────

/// DR_DEVICE_IOREQUEST body (after RDPDR_HEADER) -- MS-RDPEFS 2.2.1.4
///
/// ```text
/// offset  size  field
/// 0       4     DeviceId        (u32 LE)
/// 4       4     FileId          (u32 LE)
/// 8       4     CompletionId    (u32 LE)
/// 12      4     MajorFunction   (u32 LE)
/// 16      4     MinorFunction   (u32 LE)
/// total   20 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIoRequest {
    pub device_id: u32,
    pub file_id: u32,
    pub completion_id: u32,
    pub major_function: MajorFunction,
    pub minor_function: MinorFunction,
}

const DEVICE_IO_REQUEST_SIZE: usize = 20;

impl Encode for DeviceIoRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.device_id, "DeviceIoRequest::DeviceId")?;
        dst.write_u32_le(self.file_id, "DeviceIoRequest::FileId")?;
        dst.write_u32_le(self.completion_id, "DeviceIoRequest::CompletionId")?;
        dst.write_u32_le(self.major_function as u32, "DeviceIoRequest::MajorFunction")?;
        dst.write_u32_le(self.minor_function as u32, "DeviceIoRequest::MinorFunction")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DeviceIoRequest"
    }

    fn size(&self) -> usize {
        DEVICE_IO_REQUEST_SIZE
    }
}

impl<'de> Decode<'de> for DeviceIoRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let device_id = src.read_u32_le("DeviceIoRequest::DeviceId")?;
        let file_id = src.read_u32_le("DeviceIoRequest::FileId")?;
        let completion_id = src.read_u32_le("DeviceIoRequest::CompletionId")?;
        let major_raw = src.read_u32_le("DeviceIoRequest::MajorFunction")?;
        let major_function = MajorFunction::from_u32(major_raw)
            .ok_or_else(|| DecodeError::invalid_value("DeviceIoRequest", "MajorFunction"))?;
        let minor_raw = src.read_u32_le("DeviceIoRequest::MinorFunction")?;
        let minor_function = MinorFunction::from_u32(minor_raw)
            .ok_or_else(|| DecodeError::invalid_value("DeviceIoRequest", "MinorFunction"))?;

        Ok(Self {
            device_id,
            file_id,
            completion_id,
            major_function,
            minor_function,
        })
    }
}

// ── DeviceIoResponse -- MS-RDPEFS 2.2.1.5 ───────────────────────────────────

/// DR_DEVICE_IOCOMPLETION body (after RDPDR_HEADER) -- MS-RDPEFS 2.2.1.5
///
/// ```text
/// offset  size  field
/// 0       4     DeviceId      (u32 LE)
/// 4       4     CompletionId  (u32 LE)
/// 8       4     IoStatus      (u32 LE) - NTSTATUS
/// total   12 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIoResponse {
    pub device_id: u32,
    pub completion_id: u32,
    pub io_status: u32,
}

const DEVICE_IO_RESPONSE_SIZE: usize = 12;

impl Encode for DeviceIoResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.device_id, "DeviceIoResponse::DeviceId")?;
        dst.write_u32_le(self.completion_id, "DeviceIoResponse::CompletionId")?;
        dst.write_u32_le(self.io_status, "DeviceIoResponse::IoStatus")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "DeviceIoResponse"
    }

    fn size(&self) -> usize {
        DEVICE_IO_RESPONSE_SIZE
    }
}

impl<'de> Decode<'de> for DeviceIoResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let device_id = src.read_u32_le("DeviceIoResponse::DeviceId")?;
        let completion_id = src.read_u32_le("DeviceIoResponse::CompletionId")?;
        let io_status = src.read_u32_le("DeviceIoResponse::IoStatus")?;
        Ok(Self {
            device_id,
            completion_id,
            io_status,
        })
    }
}

// ── IRP Request Bodies ───────────────────────────────────────────────────────

/// Device Create Request body -- MS-RDPEFS 2.2.1.4.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCreateRequest {
    pub desired_access: u32,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub shared_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub path: String,
}

/// Device Read Request body -- MS-RDPEFS 2.2.1.4.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceReadRequest {
    pub length: u32,
    pub offset: u64,
}

/// Device Write Request body -- MS-RDPEFS 2.2.1.4.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceWriteRequest {
    pub offset: u64,
    pub write_data: Vec<u8>,
}

/// Device Control Request body -- MS-RDPEFS 2.2.1.4.5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceControlRequest {
    pub output_buffer_length: u32,
    pub io_control_code: u32,
    pub input_buffer: Vec<u8>,
}

/// Query Information Request body -- MS-RDPEFS 2.2.3.3.8
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceQueryInformationRequest {
    pub fs_information_class: u32,
    pub query_buffer: Vec<u8>,
}

/// Set Information Request body -- MS-RDPEFS 2.2.3.3.9
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSetInformationRequest {
    pub fs_information_class: u32,
    pub set_buffer: Vec<u8>,
}

/// Query Volume Information Request body -- MS-RDPEFS 2.2.3.3.6
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceQueryVolumeInformationRequest {
    pub fs_information_class: u32,
    pub query_volume_buffer: Vec<u8>,
}

/// Query Directory Request body -- MS-RDPEFS 2.2.3.3.10
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceQueryDirectoryRequest {
    pub fs_information_class: u32,
    pub initial_query: u8,
    pub path: String,
}

/// Notify Change Directory Request body -- MS-RDPEFS 2.2.3.3.11
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNotifyChangeDirectoryRequest {
    pub watch_tree: u32,
    pub completion_filter: u32,
}

/// Lock Info entry -- MS-RDPEFS 2.2.3.3.12
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockInfo {
    pub length: u64,
    pub offset: u64,
}

/// Lock Control Request body -- MS-RDPEFS 2.2.3.3.12
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLockControlRequest {
    pub operation: u32,
    pub locks: Vec<LockInfo>,
}

// ── IrpRequest enum ──────────────────────────────────────────────────────────

/// Unified IRP request enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrpRequest {
    Create(DeviceCreateRequest),
    Close,
    Read(DeviceReadRequest),
    Write(DeviceWriteRequest),
    DeviceControl(DeviceControlRequest),
    QueryInformation(DeviceQueryInformationRequest),
    SetInformation(DeviceSetInformationRequest),
    QueryVolumeInformation(DeviceQueryVolumeInformationRequest),
    QueryDirectory(DeviceQueryDirectoryRequest),
    NotifyChangeDirectory(DeviceNotifyChangeDirectoryRequest),
    LockControl(DeviceLockControlRequest),
}

impl IrpRequest {
    /// Decode the IRP-specific body based on MajorFunction/MinorFunction.
    pub fn decode_body(
        major: MajorFunction,
        minor: MinorFunction,
        src: &mut ReadCursor<'_>,
    ) -> DecodeResult<Self> {
        match major {
            MajorFunction::Create => {
                let desired_access = src.read_u32_le("Create::DesiredAccess")?;
                let allocation_size = src.read_u64_le("Create::AllocationSize")?;
                let file_attributes = src.read_u32_le("Create::FileAttributes")?;
                let shared_access = src.read_u32_le("Create::SharedAccess")?;
                let create_disposition = src.read_u32_le("Create::CreateDisposition")?;
                let create_options = src.read_u32_le("Create::CreateOptions")?;
                let path_length_raw = src.read_u32_le("Create::PathLength")?;
                if path_length_raw > MAX_IO_BUFFER {
                    return Err(DecodeError::invalid_value("Create", "PathLength"));
                }
                let path_length = path_length_raw as usize;
                let path_bytes = src.read_slice(path_length, "Create::Path")?;
                let path = decode_utf16le(path_bytes);
                Ok(IrpRequest::Create(DeviceCreateRequest {
                    desired_access,
                    allocation_size,
                    file_attributes,
                    shared_access,
                    create_disposition,
                    create_options,
                    path,
                }))
            }

            MajorFunction::Close => {
                // 32 bytes padding -- MS-RDPEFS 2.2.1.4.2
                src.skip(32, "Close::Padding")?;
                Ok(IrpRequest::Close)
            }

            MajorFunction::Read => {
                let length = src.read_u32_le("Read::Length")?;
                if length > MAX_IO_BUFFER {
                    return Err(DecodeError::invalid_value("Read", "Length"));
                }
                let offset = src.read_u64_le("Read::Offset")?;
                src.skip(20, "Read::Padding")?;
                Ok(IrpRequest::Read(DeviceReadRequest { length, offset }))
            }

            MajorFunction::Write => {
                let length = src.read_u32_le("Write::Length")?;
                if length > MAX_IO_BUFFER {
                    return Err(DecodeError::invalid_value("Write", "Length"));
                }
                let offset = src.read_u64_le("Write::Offset")?;
                src.skip(20, "Write::Padding")?;
                let write_data =
                    src.read_slice(length as usize, "Write::WriteData")?.to_vec();
                Ok(IrpRequest::Write(DeviceWriteRequest { offset, write_data }))
            }

            MajorFunction::DeviceControl => {
                let output_buffer_length = src.read_u32_le("Control::OutputBufferLength")?;
                let input_buffer_length = src.read_u32_le("Control::InputBufferLength")?;
                if input_buffer_length > MAX_IO_BUFFER {
                    return Err(DecodeError::invalid_value("Control", "InputBufferLength"));
                }
                let io_control_code = src.read_u32_le("Control::IoControlCode")?;
                src.skip(20, "Control::Padding")?;
                let input_buffer = src
                    .read_slice(input_buffer_length as usize, "Control::InputBuffer")?
                    .to_vec();
                Ok(IrpRequest::DeviceControl(DeviceControlRequest {
                    output_buffer_length,
                    io_control_code,
                    input_buffer,
                }))
            }

            MajorFunction::QueryInformation => {
                let fs_information_class =
                    src.read_u32_le("QueryInformation::FsInformationClass")?;
                let length = src.read_u32_le("QueryInformation::Length")?;
                if length > MAX_IO_BUFFER {
                    return Err(DecodeError::invalid_value("QueryInformation", "Length"));
                }
                src.skip(24, "QueryInformation::Padding")?;
                let query_buffer = if length > 0 {
                    src.read_slice(length as usize, "QueryInformation::QueryBuffer")?
                        .to_vec()
                } else {
                    Vec::new()
                };
                Ok(IrpRequest::QueryInformation(
                    DeviceQueryInformationRequest {
                        fs_information_class,
                        query_buffer,
                    },
                ))
            }

            MajorFunction::SetInformation => {
                let fs_information_class =
                    src.read_u32_le("SetInformation::FsInformationClass")?;
                let length = src.read_u32_le("SetInformation::Length")?;
                if length > MAX_IO_BUFFER {
                    return Err(DecodeError::invalid_value("SetInformation", "Length"));
                }
                src.skip(24, "SetInformation::Padding")?;
                let set_buffer = src
                    .read_slice(length as usize, "SetInformation::SetBuffer")?
                    .to_vec();
                Ok(IrpRequest::SetInformation(DeviceSetInformationRequest {
                    fs_information_class,
                    set_buffer,
                }))
            }

            MajorFunction::QueryVolumeInformation => {
                let fs_information_class =
                    src.read_u32_le("QueryVolumeInformation::FsInformationClass")?;
                let length = src.read_u32_le("QueryVolumeInformation::Length")?;
                if length > MAX_IO_BUFFER {
                    return Err(DecodeError::invalid_value(
                        "QueryVolumeInformation",
                        "Length",
                    ));
                }
                src.skip(24, "QueryVolumeInformation::Padding")?;
                let query_volume_buffer = if length > 0 {
                    src.read_slice(length as usize, "QueryVolumeInformation::QueryVolumeBuffer")?
                        .to_vec()
                } else {
                    Vec::new()
                };
                Ok(IrpRequest::QueryVolumeInformation(
                    DeviceQueryVolumeInformationRequest {
                        fs_information_class,
                        query_volume_buffer,
                    },
                ))
            }

            MajorFunction::SetVolumeInformation => {
                Err(DecodeError::invalid_value(
                    "IrpRequest",
                    "SetVolumeInformation not supported",
                ))
            }

            MajorFunction::DirectoryControl => match minor {
                MinorFunction::QueryDirectory => {
                    let fs_information_class =
                        src.read_u32_le("QueryDirectory::FsInformationClass")?;
                    let initial_query = src.read_u8("QueryDirectory::InitialQuery")?;
                    let path_length_raw =
                        src.read_u32_le("QueryDirectory::PathLength")?;
                    if path_length_raw > MAX_IO_BUFFER {
                        return Err(DecodeError::invalid_value(
                            "QueryDirectory",
                            "PathLength",
                        ));
                    }
                    let path_length = path_length_raw as usize;
                    src.skip(23, "QueryDirectory::Padding")?;
                    let path = if path_length > 0 {
                        let path_bytes =
                            src.read_slice(path_length, "QueryDirectory::Path")?;
                        decode_utf16le(path_bytes)
                    } else {
                        String::new()
                    };
                    Ok(IrpRequest::QueryDirectory(DeviceQueryDirectoryRequest {
                        fs_information_class,
                        initial_query,
                        path,
                    }))
                }
                MinorFunction::NotifyChangeDirectory => {
                    let watch_tree = src.read_u32_le("NotifyChangeDirectory::WatchTree")?;
                    let completion_filter =
                        src.read_u32_le("NotifyChangeDirectory::CompletionFilter")?;
                    src.skip(28, "NotifyChangeDirectory::Padding")?;
                    Ok(IrpRequest::NotifyChangeDirectory(
                        DeviceNotifyChangeDirectoryRequest {
                            watch_tree,
                            completion_filter,
                        },
                    ))
                }
                MinorFunction::None => Err(DecodeError::invalid_value(
                    "IrpRequest",
                    "DirectoryControl requires non-zero MinorFunction",
                )),
            },

            MajorFunction::LockControl => {
                let operation = src.read_u32_le("LockControl::Operation")?;
                let _padding = src.read_u32_le("LockControl::Padding")?;
                let num_locks = src.read_u32_le("LockControl::NumLocks")?;
                if num_locks > MAX_LOCK_COUNT {
                    return Err(DecodeError::invalid_value("LockControl", "NumLocks"));
                }
                let _padding2 = src.read_u32_le("LockControl::Padding2")?;
                let mut locks = Vec::with_capacity(num_locks as usize);
                for _ in 0..num_locks {
                    // RDP_LOCK_INFO: Length(8) + Offset(8) = 16 bytes per entry
                    // MS-RDPEFS 2.2.3.3.12
                    let length = src.read_u64_le("LockInfo::Length")?;
                    let offset = src.read_u64_le("LockInfo::Offset")?;
                    locks.push(LockInfo { length, offset });
                }
                Ok(IrpRequest::LockControl(DeviceLockControlRequest {
                    operation,
                    locks,
                }))
            }
        }
    }
}

// ── UTF-16LE helpers ─────────────────────────────────────────────────────────

use super::util::decode_utf16le;

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn device_io_request_roundtrip() {
        let req = DeviceIoRequest {
            device_id: 1,
            file_id: 0x223,
            completion_id: 6,
            major_function: MajorFunction::Write,
            minor_function: MinorFunction::None,
        };

        let mut buf = [0u8; DEVICE_IO_REQUEST_SIZE];
        let mut wc = WriteCursor::new(&mut buf);
        req.encode(&mut wc).unwrap();

        let mut rc = ReadCursor::new(&buf);
        let decoded = DeviceIoRequest::decode(&mut rc).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn device_io_response_roundtrip() {
        let resp = DeviceIoResponse {
            device_id: 1,
            completion_id: 6,
            io_status: STATUS_SUCCESS,
        };

        let mut buf = [0u8; DEVICE_IO_RESPONSE_SIZE];
        let mut wc = WriteCursor::new(&mut buf);
        resp.encode(&mut wc).unwrap();

        let mut rc = ReadCursor::new(&buf);
        let decoded = DeviceIoResponse::decode(&mut rc).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn irp_create_decode() {
        #[rustfmt::skip]
        let body: Vec<u8> = vec![
            // DesiredAccess
            0x01, 0x00, 0x00, 0x80,
            // AllocationSize
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // FileAttributes
            0x00, 0x00, 0x00, 0x00,
            // SharedAccess
            0x07, 0x00, 0x00, 0x00,
            // CreateDisposition
            0x01, 0x00, 0x00, 0x00,
            // CreateOptions
            0x21, 0x00, 0x00, 0x00,
            // PathLength
            0x04, 0x00, 0x00, 0x00,
            // Path: "\" + null
            0x5C, 0x00, 0x00, 0x00,
        ];

        let mut rc = ReadCursor::new(&body);
        let irp =
            IrpRequest::decode_body(MajorFunction::Create, MinorFunction::None, &mut rc).unwrap();

        match irp {
            IrpRequest::Create(req) => {
                assert_eq!(req.desired_access, 0x8000_0001);
                assert_eq!(req.create_disposition, FILE_OPEN);
                assert_eq!(req.path, "\\");
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn irp_close_decode() {
        let body = [0u8; 32];
        let mut rc = ReadCursor::new(&body);
        let irp =
            IrpRequest::decode_body(MajorFunction::Close, MinorFunction::None, &mut rc).unwrap();
        assert_eq!(irp, IrpRequest::Close);
    }

    #[test]
    fn irp_read_decode() {
        #[rustfmt::skip]
        let mut body = vec![
            // Length
            0x00, 0x10, 0x00, 0x00,
            // Offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        body.extend_from_slice(&[0u8; 20]);

        let mut rc = ReadCursor::new(&body);
        let irp =
            IrpRequest::decode_body(MajorFunction::Read, MinorFunction::None, &mut rc).unwrap();

        match irp {
            IrpRequest::Read(req) => {
                assert_eq!(req.length, 4096);
                assert_eq!(req.offset, 0);
            }
            _ => panic!("expected Read"),
        }
    }

    #[test]
    fn irp_write_decode() {
        #[rustfmt::skip]
        let mut body = vec![
            0x09, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        body.extend_from_slice(&[0u8; 20]);
        body.extend_from_slice(b"sfddsafsa");

        let mut rc = ReadCursor::new(&body);
        let irp =
            IrpRequest::decode_body(MajorFunction::Write, MinorFunction::None, &mut rc).unwrap();

        match irp {
            IrpRequest::Write(req) => {
                assert_eq!(req.write_data, b"sfddsafsa");
                assert_eq!(req.offset, 0);
            }
            _ => panic!("expected Write"),
        }
    }

    #[test]
    fn irp_query_directory_decode() {
        #[rustfmt::skip]
        let mut body = vec![
            0x03, 0x00, 0x00, 0x00, // FsInformationClass
            0x01,                     // InitialQuery
            0x06, 0x00, 0x00, 0x00, // PathLength
        ];
        body.extend_from_slice(&[0u8; 23]);
        body.extend_from_slice(&[0x5C, 0x00, 0x2A, 0x00, 0x00, 0x00]);

        let mut rc = ReadCursor::new(&body);
        let irp = IrpRequest::decode_body(
            MajorFunction::DirectoryControl,
            MinorFunction::QueryDirectory,
            &mut rc,
        )
        .unwrap();

        match irp {
            IrpRequest::QueryDirectory(req) => {
                assert_eq!(req.fs_information_class, FILE_BOTH_DIRECTORY_INFORMATION);
                assert_eq!(req.initial_query, 1);
                assert_eq!(req.path, "\\*");
            }
            _ => panic!("expected QueryDirectory"),
        }
    }

    #[test]
    fn irp_lock_control_decode() {
        // RDP_LOCK_INFO is 16 bytes: Length(8) + Offset(8), no padding
        // MS-RDPEFS 2.2.3.3.12
        #[rustfmt::skip]
        let body = vec![
            0x24, 0x00, 0x00, 0x00, // Operation
            0x00, 0x00, 0x00, 0x00, // Padding
            0x01, 0x00, 0x00, 0x00, // NumLocks
            0x00, 0x00, 0x00, 0x00, // Padding2
            // LockInfo[0]: Length(8) + Offset(8) = 16 bytes
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Length=256
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Offset=0
        ];

        let mut rc = ReadCursor::new(&body);
        let irp = IrpRequest::decode_body(
            MajorFunction::LockControl,
            MinorFunction::None,
            &mut rc,
        )
        .unwrap();

        match irp {
            IrpRequest::LockControl(req) => {
                assert_eq!(req.operation, 0x24);
                assert_eq!(req.locks.len(), 1);
                assert_eq!(req.locks[0].length, 256);
                assert_eq!(req.locks[0].offset, 0);
            }
            _ => panic!("expected LockControl"),
        }
    }
}
