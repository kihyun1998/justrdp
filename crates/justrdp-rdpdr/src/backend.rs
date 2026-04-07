#![forbid(unsafe_code)]

//! Application-level device redirection backend trait -- MS-RDPEFS
//!
//! This module defines the [`RdpdrBackend`] trait that applications implement
//! to handle device I/O requests from the RDP server. The trait methods
//! correspond to IRP major function codes defined in MS-RDPEFS 2.2.1.4.

extern crate alloc;

use alloc::vec::Vec;

use crate::pdu::irp::{
    STATUS_ACCESS_DENIED, STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_NOT_SUPPORTED,
    STATUS_UNSUCCESSFUL,
};
use crate::pdu::DeviceAnnounce;

// ── DeviceIoError ──────────────────────────────────────────────────────────────

/// Device I/O error carrying an NTSTATUS code to return to the server.
///
/// NTSTATUS codes are defined in [MS-ERREF] 2.3.1.
#[derive(Debug, Clone, Copy)]
pub struct DeviceIoError {
    /// NTSTATUS code to return to the server.
    pub ntstatus: u32,
}

impl DeviceIoError {
    /// Create an error with the given NTSTATUS code.
    pub fn new(ntstatus: u32) -> Self {
        Self { ntstatus }
    }

    /// STATUS_ACCESS_DENIED (0xC0000022)
    pub fn access_denied() -> Self {
        Self { ntstatus: STATUS_ACCESS_DENIED }
    }

    /// STATUS_NOT_SUPPORTED (0xC00000BB)
    pub fn not_supported() -> Self {
        Self { ntstatus: STATUS_NOT_SUPPORTED }
    }

    /// STATUS_UNSUCCESSFUL (0xC0000001)
    pub fn unsuccessful() -> Self {
        Self { ntstatus: STATUS_UNSUCCESSFUL }
    }

    /// STATUS_NO_SUCH_FILE (0xC000000F)
    pub fn no_such_file() -> Self {
        Self { ntstatus: STATUS_NO_SUCH_FILE }
    }

    /// STATUS_NO_MORE_FILES (0x80000006)
    pub fn no_more_files() -> Self {
        Self { ntstatus: STATUS_NO_MORE_FILES }
    }
}

impl core::fmt::Display for DeviceIoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "device I/O error (NTSTATUS: 0x{:08X})", self.ntstatus)
    }
}

// ── DeviceIoResult ─────────────────────────────────────────────────────────────

/// Result type for device I/O operations.
pub type DeviceIoResult<T> = Result<T, DeviceIoError>;

// ── FileHandle ─────────────────────────────────────────────────────────────────

/// Opaque file handle returned by create operations.
///
/// Wraps the client-assigned file ID that appears in DR_DEVICE_IOREQUEST
/// (MS-RDPEFS 2.2.1.4, FileId field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileHandle(pub u32);

// ── CreateResponse ─────────────────────────────────────────────────────────────

/// Result of a create (IRP_MJ_CREATE) operation.
///
/// Returned by [`RdpdrBackend::create`] and mapped into
/// DR_CREATE_RSP (MS-RDPEFS 2.2.1.5.1).
#[derive(Debug)]
pub struct CreateResponse {
    /// Client-assigned file handle.
    pub file_id: FileHandle,
    /// Information field indicating the action taken:
    /// - `FILE_SUPERSEDED` = 0x00000000
    /// - `FILE_OPENED` = 0x00000001
    /// - `FILE_OVERWRITTEN` = 0x00000003
    ///
    /// See [MS-RDPEFS] 2.2.1.5.1 and [MS-SMB2] 2.2.14 for values.
    pub information: u8,
}

// ── RdpdrBackend trait ─────────────────────────────────────────────────────────

/// Application-level device redirection backend.
///
/// Implement this trait to handle device I/O requests from the RDP server.
/// Each method corresponds to an IRP major function code from
/// DR_DEVICE_IOREQUEST (MS-RDPEFS 2.2.1.4).
pub trait RdpdrBackend: Send {
    /// Return the list of devices to announce to the server.
    ///
    /// Called during initialization to build the DR_DEVICELIST_ANNOUNCE
    /// (MS-RDPEFS 2.2.3.1) PDU.
    fn device_list(&self) -> Vec<DeviceAnnounce>;

    /// Called when the server replies to a device announce.
    ///
    /// `result_code` is the NTSTATUS from DR_CORE_DEVICE_ANNOUNCE_RSP
    /// (MS-RDPEFS 2.2.2.1). A value of 0 (STATUS_SUCCESS) means the
    /// device was accepted.
    fn on_device_reply(&mut self, device_id: u32, result_code: u32);

    /// Handle IRP_MJ_CREATE -- open a file or device.
    ///
    /// Corresponds to DR_CREATE_REQ (MS-RDPEFS 2.2.1.4.1).
    fn create(
        &mut self,
        device_id: u32,
        path: &str,
        desired_access: u32,
        create_disposition: u32,
        create_options: u32,
        file_attributes: u32,
    ) -> DeviceIoResult<CreateResponse>;

    /// Handle IRP_MJ_CLOSE -- close a file handle.
    ///
    /// Corresponds to DR_CLOSE_REQ (MS-RDPEFS 2.2.1.4.2).
    fn close(&mut self, device_id: u32, file_id: FileHandle) -> DeviceIoResult<()>;

    /// Handle IRP_MJ_READ -- read data from a file.
    ///
    /// Corresponds to DR_READ_REQ (MS-RDPEFS 2.2.1.4.3).
    /// Returns the bytes read (up to `length` bytes starting at `offset`).
    fn read(
        &mut self,
        device_id: u32,
        file_id: FileHandle,
        length: u32,
        offset: u64,
    ) -> DeviceIoResult<Vec<u8>>;

    /// Handle IRP_MJ_WRITE -- write data to a file.
    ///
    /// Corresponds to DR_WRITE_REQ (MS-RDPEFS 2.2.1.4.4).
    /// Returns the number of bytes written.
    fn write(
        &mut self,
        device_id: u32,
        file_id: FileHandle,
        offset: u64,
        data: &[u8],
    ) -> DeviceIoResult<u32>;

    /// Handle IRP_MJ_DEVICE_CONTROL -- IOCTL request.
    ///
    /// Corresponds to DR_CONTROL_REQ (MS-RDPEFS 2.2.1.4.5).
    /// Returns the output buffer data.
    fn device_control(
        &mut self,
        device_id: u32,
        file_id: FileHandle,
        io_control_code: u32,
        input: &[u8],
        output_buffer_length: u32,
    ) -> DeviceIoResult<Vec<u8>>;

    /// Handle IRP_MJ_QUERY_INFORMATION -- query file information.
    ///
    /// Corresponds to DR_QUERY_INFORMATION_REQ (MS-RDPEFS 2.2.3.3.8).
    /// `fs_information_class` identifies which FILE_INFORMATION_CLASS
    /// is being queried. Returns the raw info buffer.
    fn query_information(
        &mut self,
        device_id: u32,
        file_id: FileHandle,
        fs_information_class: u32,
    ) -> DeviceIoResult<Vec<u8>>;

    /// Handle IRP_MJ_SET_INFORMATION -- set file information.
    ///
    /// Corresponds to DR_SET_INFORMATION_REQ (MS-RDPEFS 2.2.3.3.9).
    fn set_information(
        &mut self,
        device_id: u32,
        file_id: FileHandle,
        fs_information_class: u32,
        data: &[u8],
    ) -> DeviceIoResult<()>;

    /// Handle IRP_MJ_QUERY_VOLUME_INFORMATION -- query volume info.
    ///
    /// Corresponds to DR_QUERY_VOLUME_INFORMATION_REQ (MS-RDPEFS 2.2.3.3.6).
    /// Returns the raw volume info buffer.
    fn query_volume_information(
        &mut self,
        device_id: u32,
        fs_information_class: u32,
    ) -> DeviceIoResult<Vec<u8>>;

    /// Handle IRP_MJ_DIRECTORY_CONTROL / IRP_MN_QUERY_DIRECTORY.
    ///
    /// Corresponds to DR_QUERY_DIRECTORY_REQ (MS-RDPEFS 2.2.3.3.10).
    /// `initial_query` is true for the first query (InitialQuery != 0).
    /// `path` is the search pattern (may be `None` on subsequent queries).
    fn query_directory(
        &mut self,
        device_id: u32,
        file_id: FileHandle,
        fs_information_class: u32,
        initial_query: bool,
        path: Option<&str>,
    ) -> DeviceIoResult<Vec<u8>>;

    /// Handle IRP_MJ_DIRECTORY_CONTROL / IRP_MN_NOTIFY_CHANGE_DIRECTORY.
    ///
    /// Corresponds to DR_NOTIFY_CHANGE_DIRECTORY_REQ (MS-RDPEFS 2.2.3.3.11).
    /// `watch_tree` indicates whether to watch subdirectories.
    /// `completion_filter` specifies which changes to watch for.
    fn notify_change_directory(
        &mut self,
        device_id: u32,
        file_id: FileHandle,
        watch_tree: bool,
        completion_filter: u32,
    ) -> DeviceIoResult<Vec<u8>>;

    /// Handle IRP_MJ_LOCK_CONTROL -- file byte-range locking.
    ///
    /// Corresponds to DR_LOCK_REQ (MS-RDPEFS 2.2.3.3.12).
    /// `operation` contains the lock flags.
    /// `locks` contains (offset, length) pairs for each lock region.
    fn lock_control(
        &mut self,
        device_id: u32,
        file_id: FileHandle,
        operation: u32,
        locks: &[(u64, u64)],
    ) -> DeviceIoResult<()>;

    /// Called when the server sends DR_PRN_USING_XPS -- MS-RDPEPC 2.2.2.2.
    ///
    /// The server indicates that a printer should use XPS format.
    /// Default implementation does nothing.
    fn on_printer_using_xps(&mut self, _printer_id: u32, _flags: u32) {}

    /// Called when the server sends DR_PRN_CACHE_DATA -- MS-RDPEPC 2.2.2.3-2.2.2.6.
    ///
    /// The server notifies the client of a printer cache event
    /// (add=1, update=2, delete=3, rename=4).
    /// Default implementation does nothing.
    fn on_printer_cache_data(&mut self, _event_id: u32, _event_data: &[u8]) {}
}
