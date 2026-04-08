//! Native filesystem backend for Device Redirection (MS-RDPEFS).
//!
//! Provides [`NativeFilesystemBackend`] which implements [`RdpdrBackend`]
//! using `std::fs` operations to serve a local directory as a redirected drive.

mod create;
mod dir_info;
mod fs_info;
mod handle_map;
mod path;
mod volume_info;

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use justrdp_rdpdr::pdu::device::DeviceAnnounce;
use justrdp_rdpdr::pdu::irp::{
    FILE_ATTRIBUTE_TAG_INFORMATION, FILE_BASIC_INFORMATION, FILE_DISPOSITION_INFORMATION,
    FILE_END_OF_FILE_INFORMATION, FILE_FS_ATTRIBUTE_INFORMATION, FILE_FS_DEVICE_INFORMATION,
    FILE_FS_FULL_SIZE_INFORMATION, FILE_FS_SIZE_INFORMATION, FILE_FS_VOLUME_INFORMATION,
    FILE_RENAME_INFORMATION, FILE_STANDARD_INFORMATION, STATUS_ACCESS_DENIED, STATUS_NO_MORE_FILES,
};
use justrdp_rdpdr::{CreateResponse, DeviceIoError, DeviceIoResult, FileHandle, RdpdrBackend};

use crate::create::open_file;
use crate::dir_info::encode_dir_entry;
use crate::fs_info::{
    encode_attribute_tag_info, encode_basic_info, encode_standard_info, parse_basic_info_set,
    parse_disposition, parse_end_of_file, parse_rename,
};
use crate::handle_map::{DirEntry, DirState, HandleMap};
use crate::path::rdp_to_local;
use crate::volume_info::{
    encode_attribute_info, encode_device_info, encode_full_size_info, encode_size_info,
    encode_volume_info, DiskSpace,
};

// ── NTSTATUS codes not already in justrdp-rdpdr ────────────────────────────

const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_DISK_FULL: u32 = 0xC000_007F;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Maximum bytes for a single read request (4 MiB).
const MAX_READ_BYTES: u32 = 4 * 1024 * 1024;

// ── NativeFilesystemBackend ────────────────────────────────────────────────

/// A native filesystem backend that shares a local directory as an RDP
/// redirected drive.
///
/// # Example
///
/// ```ignore
/// use justrdp_rdpdr::RdpdrClient;
/// use justrdp_rdpdr_native::NativeFilesystemBackend;
///
/// let backend = NativeFilesystemBackend::new("/shared/folder", 1, "C:");
/// let rdpdr = RdpdrClient::new(Box::new(backend));
/// ```
pub struct NativeFilesystemBackend {
    root_path: PathBuf,
    device_id: u32,
    dos_name: String,
    display_name: Option<String>,
    handles: HandleMap,
    volume_label: String,
    fs_name: String,
}

impl NativeFilesystemBackend {
    /// Create a new native filesystem backend.
    ///
    /// - `root_path`: Local directory to share.
    /// - `device_id`: Client-assigned unique device ID.
    /// - `dos_name`: DOS drive name (e.g., `"C:"`), max 7 chars.
    pub fn new(root_path: impl Into<PathBuf>, device_id: u32, dos_name: &str) -> Self {
        Self {
            root_path: root_path.into(),
            device_id,
            dos_name: dos_name.to_string(),
            display_name: None,
            handles: HandleMap::new(),
            volume_label: String::from("LOCAL"),
            fs_name: String::from("NTFS"),
        }
    }

    /// Set the display name shown to the server (optional).
    pub fn with_display_name(mut self, name: &str) -> Self {
        self.display_name = Some(name.to_string());
        self
    }

    /// Set the volume label (default: `"LOCAL"`).
    pub fn with_volume_label(mut self, label: &str) -> Self {
        self.volume_label = label.to_string();
        self
    }

    /// Set the filesystem name (default: `"NTFS"`).
    pub fn with_fs_name(mut self, name: &str) -> Self {
        self.fs_name = name.to_string();
        self
    }

    /// Resolve an RDP path to a local path, returning a DeviceIoError on failure.
    fn resolve_path(&self, rdp_path: &str) -> DeviceIoResult<PathBuf> {
        rdp_to_local(&self.root_path, rdp_path)
            .ok_or(DeviceIoError::new(STATUS_ACCESS_DENIED))
    }

    /// Map an `std::io::Error` to a `DeviceIoError`.
    fn map_io_error(err: &std::io::Error) -> DeviceIoError {
        match err.kind() {
            std::io::ErrorKind::NotFound => DeviceIoError::no_such_file(),
            std::io::ErrorKind::PermissionDenied => DeviceIoError::access_denied(),
            std::io::ErrorKind::AlreadyExists => DeviceIoError::new(STATUS_OBJECT_NAME_COLLISION),
            _ => DeviceIoError::unsuccessful(),
        }
    }

    /// Simple glob pattern matching for directory queries.
    ///
    /// Supports `*` (match any), `?` (match one), and `*.*` (match all with extension).
    fn pattern_matches(pattern: &str, name: &str) -> bool {
        let pattern = pattern.trim_start_matches('\\').trim_start_matches('/');

        // "*" and "*.*" match everything
        if pattern == "*" || pattern == "*.*" {
            return true;
        }

        // Simple character-by-character matching with `*` and `?`
        Self::glob_match(pattern.as_bytes(), name.as_bytes())
    }

    fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
        let mut pi = 0;
        let mut ti = 0;
        let mut star_pi = usize::MAX;
        let mut star_ti = 0;

        while ti < text.len() {
            if pi < pattern.len()
                && (pattern[pi].eq_ignore_ascii_case(&text[ti]) || pattern[pi] == b'?')
            {
                pi += 1;
                ti += 1;
            } else if pi < pattern.len() && pattern[pi] == b'*' {
                star_pi = pi;
                star_ti = ti;
                pi += 1;
            } else if star_pi != usize::MAX {
                pi = star_pi + 1;
                star_ti += 1;
                ti = star_ti;
            } else {
                return false;
            }
        }

        while pi < pattern.len() && pattern[pi] == b'*' {
            pi += 1;
        }

        pi == pattern.len()
    }
}

impl std::fmt::Debug for NativeFilesystemBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeFilesystemBackend")
            .field("root_path", &self.root_path)
            .field("device_id", &self.device_id)
            .field("dos_name", &self.dos_name)
            .finish()
    }
}

// ── RdpdrBackend implementation ────────────────────────────────────────────

impl RdpdrBackend for NativeFilesystemBackend {
    fn device_list(&self) -> Vec<DeviceAnnounce> {
        vec![DeviceAnnounce::filesystem(
            self.device_id,
            &self.dos_name,
            self.display_name.as_deref(),
        )]
    }

    fn on_device_reply(&mut self, _device_id: u32, _result_code: u32) {
        // Nothing to do — the processor handles this.
    }

    fn create(
        &mut self,
        _device_id: u32,
        path: &str,
        desired_access: u32,
        create_disposition: u32,
        create_options: u32,
        file_attributes: u32,
    ) -> DeviceIoResult<CreateResponse> {
        let local_path = self.resolve_path(path)?;

        let result = open_file(
            &local_path,
            desired_access,
            create_disposition,
            create_options,
            file_attributes,
        )
        .map_err(|e| Self::map_io_error(&e))?;

        let file_id = self
            .handles
            .insert(result.file, local_path, result.is_dir, result.delete_on_close)
            .ok_or(DeviceIoError::new(STATUS_INSUFFICIENT_RESOURCES))?;

        Ok(CreateResponse {
            file_id,
            information: result.information,
        })
    }

    fn close(&mut self, _device_id: u32, file_id: FileHandle) -> DeviceIoResult<()> {
        let entry = self
            .handles
            .remove(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        // Handle delete-on-close
        if entry.delete_on_close {
            if entry.is_dir {
                let _ = fs::remove_dir(&entry.path);
            } else {
                let _ = fs::remove_file(&entry.path);
            }
        }

        Ok(())
    }

    fn read(
        &mut self,
        _device_id: u32,
        file_id: FileHandle,
        length: u32,
        offset: u64,
    ) -> DeviceIoResult<Vec<u8>> {
        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        entry
            .file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| Self::map_io_error(&e))?;

        let capped_length = length.min(MAX_READ_BYTES) as usize;
        let mut buf = vec![0u8; capped_length];
        let n = entry
            .file
            .read(&mut buf)
            .map_err(|e| Self::map_io_error(&e))?;
        buf.truncate(n);

        Ok(buf)
    }

    fn write(
        &mut self,
        _device_id: u32,
        file_id: FileHandle,
        offset: u64,
        data: &[u8],
    ) -> DeviceIoResult<u32> {
        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        entry
            .file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| Self::map_io_error(&e))?;

        entry
            .file
            .write_all(data)
            .map_err(|e| Self::map_io_error(&e))?;

        Ok(data.len() as u32)
    }

    fn device_control(
        &mut self,
        _device_id: u32,
        _file_id: FileHandle,
        _io_control_code: u32,
        _input: &[u8],
        _output_buffer_length: u32,
    ) -> DeviceIoResult<Vec<u8>> {
        Err(DeviceIoError::not_supported())
    }

    fn query_information(
        &mut self,
        _device_id: u32,
        file_id: FileHandle,
        fs_information_class: u32,
    ) -> DeviceIoResult<Vec<u8>> {
        let entry = self
            .handles
            .get(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        let metadata = entry
            .file
            .metadata()
            .map_err(|e| Self::map_io_error(&e))?;

        match fs_information_class {
            FILE_BASIC_INFORMATION => Ok(encode_basic_info(&metadata)),
            FILE_STANDARD_INFORMATION => Ok(encode_standard_info(&metadata)),
            FILE_ATTRIBUTE_TAG_INFORMATION => Ok(encode_attribute_tag_info(&metadata)),
            _ => Err(DeviceIoError::not_supported()),
        }
    }

    fn set_information(
        &mut self,
        _device_id: u32,
        file_id: FileHandle,
        fs_information_class: u32,
        data: &[u8],
    ) -> DeviceIoResult<()> {
        match fs_information_class {
            FILE_END_OF_FILE_INFORMATION => {
                let new_size = parse_end_of_file(data)
                    .ok_or(DeviceIoError::new(STATUS_INVALID_PARAMETER))?;

                let entry = self
                    .handles
                    .get(&file_id)
                    .ok_or(DeviceIoError::no_such_file())?;

                if entry.is_dir {
                    return Err(DeviceIoError::new(STATUS_INVALID_PARAMETER));
                }

                entry
                    .file
                    .set_len(new_size)
                    .map_err(|e| {
                        if e.kind() == std::io::ErrorKind::Other {
                            DeviceIoError::new(STATUS_DISK_FULL)
                        } else {
                            Self::map_io_error(&e)
                        }
                    })?;

                Ok(())
            }

            FILE_DISPOSITION_INFORMATION => {
                let delete = parse_disposition(data)
                    .ok_or(DeviceIoError::new(STATUS_INVALID_PARAMETER))?;

                let entry = self
                    .handles
                    .get_mut(&file_id)
                    .ok_or(DeviceIoError::no_such_file())?;

                entry.delete_on_close = delete;
                Ok(())
            }

            FILE_RENAME_INFORMATION => {
                let (replace_if_exists, new_name) = parse_rename(data)
                    .ok_or(DeviceIoError::new(STATUS_INVALID_PARAMETER))?;

                let entry = self
                    .handles
                    .get(&file_id)
                    .ok_or(DeviceIoError::no_such_file())?;

                let new_path = rdp_to_local(&self.root_path, &new_name)
                    .ok_or(DeviceIoError::access_denied())?;

                if new_path.exists() && !replace_if_exists {
                    return Err(DeviceIoError::new(STATUS_OBJECT_NAME_COLLISION));
                }

                // Create parent directories if needed
                if let Some(parent) = new_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }

                fs::rename(&entry.path, &new_path)
                    .map_err(|e| Self::map_io_error(&e))?;

                // Update the stored path
                let entry = self
                    .handles
                    .get_mut(&file_id)
                    .ok_or(DeviceIoError::no_such_file())?;
                entry.path = new_path;

                Ok(())
            }

            FILE_BASIC_INFORMATION => {
                // Validate the PDU format
                let _info = parse_basic_info_set(data)
                    .ok_or(DeviceIoError::new(STATUS_INVALID_PARAMETER))?;

                // Accept without modifying timestamps. Returning STATUS_SUCCESS
                // (not STATUS_NOT_SUPPORTED) because Windows clients set timestamps
                // during file copy; returning an error would break file operations.
                // Platform-specific timestamp APIs can be added in the future.
                Ok(())
            }

            _ => Err(DeviceIoError::not_supported()),
        }
    }

    fn query_volume_information(
        &mut self,
        _device_id: u32,
        fs_information_class: u32,
    ) -> DeviceIoResult<Vec<u8>> {
        match fs_information_class {
            FILE_FS_VOLUME_INFORMATION => Ok(encode_volume_info(&self.volume_label)),

            FILE_FS_SIZE_INFORMATION => {
                let disk = DiskSpace::query(&self.root_path)
                    .ok_or(DeviceIoError::unsuccessful())?;
                Ok(encode_size_info(&disk))
            }

            FILE_FS_DEVICE_INFORMATION => Ok(encode_device_info()),

            FILE_FS_ATTRIBUTE_INFORMATION => Ok(encode_attribute_info(&self.fs_name)),

            FILE_FS_FULL_SIZE_INFORMATION => {
                let disk = DiskSpace::query(&self.root_path)
                    .ok_or(DeviceIoError::unsuccessful())?;
                Ok(encode_full_size_info(&disk))
            }

            _ => Err(DeviceIoError::not_supported()),
        }
    }

    fn query_directory(
        &mut self,
        _device_id: u32,
        file_id: FileHandle,
        fs_information_class: u32,
        initial_query: bool,
        path: Option<&str>,
    ) -> DeviceIoResult<Vec<u8>> {
        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        if !entry.is_dir {
            return Err(DeviceIoError::new(STATUS_NOT_A_DIRECTORY));
        }

        if initial_query {
            // Read the directory and build the enumeration state
            let pattern = path
                .map(|p| p.trim_start_matches('\\').trim_start_matches('/'))
                .unwrap_or("*");

            let mut entries = Vec::new();

            // Add "." and ".." entries first
            if Self::pattern_matches(pattern, ".") {
                if let Ok(meta) = fs::metadata(&entry.path) {
                    entries.push(DirEntry {
                        name: ".".to_string(),
                        metadata: meta,
                    });
                }
            }
            if Self::pattern_matches(pattern, "..") {
                let parent_meta = entry
                    .path
                    .parent()
                    .and_then(|p| fs::metadata(p).ok())
                    .or_else(|| fs::metadata(&entry.path).ok());
                if let Some(meta) = parent_meta {
                    entries.push(DirEntry {
                        name: "..".to_string(),
                        metadata: meta,
                    });
                }
            }

            // Read directory contents
            if let Ok(read_dir) = fs::read_dir(&entry.path) {
                for dir_entry in read_dir.flatten() {
                    let name = dir_entry.file_name().to_string_lossy().to_string();
                    if Self::pattern_matches(pattern, &name) {
                        if let Ok(meta) = dir_entry.metadata() {
                            entries.push(DirEntry {
                                name,
                                metadata: meta,
                            });
                        }
                    }
                }
            }

            entry.dir_state = Some(DirState {
                entries,
                cursor: 0,
            });
        }

        // Return the next entry from the enumeration
        let dir_state = entry
            .dir_state
            .as_mut()
            .ok_or(DeviceIoError::new(STATUS_NO_MORE_FILES))?;

        if dir_state.cursor >= dir_state.entries.len() {
            return Err(DeviceIoError::new(STATUS_NO_MORE_FILES));
        }

        let dir_entry = &dir_state.entries[dir_state.cursor];
        dir_state.cursor += 1;

        // Encode a single entry
        let buf = encode_dir_entry(fs_information_class, &dir_entry.name, &dir_entry.metadata)
            .ok_or(DeviceIoError::not_supported())?;

        Ok(buf)
    }

    fn notify_change_directory(
        &mut self,
        _device_id: u32,
        _file_id: FileHandle,
        _watch_tree: bool,
        _completion_filter: u32,
    ) -> DeviceIoResult<Vec<u8>> {
        // Not implemented — deferred to future work.
        Err(DeviceIoError::not_supported())
    }

    fn lock_control(
        &mut self,
        _device_id: u32,
        _file_id: FileHandle,
        _operation: u32,
        _locks: &[(u64, u64)],
    ) -> DeviceIoResult<()> {
        // Not implemented — deferred to future work.
        Err(DeviceIoError::not_supported())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backend(dir: &tempfile::TempDir) -> NativeFilesystemBackend {
        NativeFilesystemBackend::new(dir.path(), 1, "C:")
    }

    // ── Device list ────────────────────────────────────────────────────

    #[test]
    fn device_list_returns_filesystem_announce() {
        let dir = tempfile::tempdir().unwrap();
        let backend = make_backend(&dir);
        let devices = backend.device_list();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, 1);
        assert_eq!(devices[0].dos_name_str(), "C:");
    }

    // ── Create + Close lifecycle ───────────────────────────────────────

    #[test]
    fn create_and_close_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("test.txt"), b"hello").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\test.txt", 0x8000_0001, 1, 0, 0)
            .unwrap();
        assert_eq!(resp.information, create::FILE_OPENED);

        backend.close(1, resp.file_id).unwrap();
    }

    #[test]
    fn create_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = make_backend(&dir);

        let resp = backend
            .create(1, "\\new.txt", 0x4000_0000, 2, 0, 0) // GENERIC_WRITE, FILE_CREATE
            .unwrap();
        assert_eq!(resp.information, create::FILE_CREATED);
        assert!(dir.path().join("new.txt").exists());

        backend.close(1, resp.file_id).unwrap();
    }

    // ── Read + Write ───────────────────────────────────────────────────

    #[test]
    fn write_then_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = make_backend(&dir);

        // Create and write
        let resp = backend
            .create(1, "\\data.bin", 0x4000_0000, 2, 0, 0)
            .unwrap();
        backend
            .write(1, resp.file_id, 0, b"Hello, RDP!")
            .unwrap();
        backend.close(1, resp.file_id).unwrap();

        // Re-open and read
        let resp = backend
            .create(1, "\\data.bin", 0x8000_0000, 1, 0, 0) // GENERIC_READ, FILE_OPEN
            .unwrap();
        let data = backend.read(1, resp.file_id, 1024, 0).unwrap();
        assert_eq!(data, b"Hello, RDP!");

        backend.close(1, resp.file_id).unwrap();
    }

    // ── Query Information ──────────────────────────────────────────────

    #[test]
    fn query_basic_info() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("info.txt"), b"data").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\info.txt", 0x8000_0000, 1, 0, 0)
            .unwrap();

        let buf = backend
            .query_information(1, resp.file_id, FILE_BASIC_INFORMATION)
            .unwrap();
        assert_eq!(buf.len(), 40);

        backend.close(1, resp.file_id).unwrap();
    }

    #[test]
    fn query_standard_info() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("std.txt"), b"content").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\std.txt", 0x8000_0000, 1, 0, 0)
            .unwrap();

        let buf = backend
            .query_information(1, resp.file_id, FILE_STANDARD_INFORMATION)
            .unwrap();
        assert_eq!(buf.len(), 24);

        backend.close(1, resp.file_id).unwrap();
    }

    // ── Set Information ────────────────────────────────────────────────

    #[test]
    fn set_end_of_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("trunc.txt"), b"hello world").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\trunc.txt", 0x4000_0000, 1, 0, 0)
            .unwrap();

        // Truncate to 5 bytes
        let mut data = [0u8; 8];
        data[..8].copy_from_slice(&5i64.to_le_bytes());
        backend
            .set_information(1, resp.file_id, FILE_END_OF_FILE_INFORMATION, &data)
            .unwrap();

        backend.close(1, resp.file_id).unwrap();

        let content = fs::read(dir.path().join("trunc.txt")).unwrap();
        assert_eq!(content.len(), 5);
    }

    #[test]
    fn set_disposition_delete_on_close() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("deleteme.txt");
        fs::write(&p, b"bye").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\deleteme.txt", 0x4000_0000, 1, 0, 0)
            .unwrap();

        backend
            .set_information(1, resp.file_id, FILE_DISPOSITION_INFORMATION, &[0x01])
            .unwrap();

        // File should be deleted on close
        backend.close(1, resp.file_id).unwrap();
        assert!(!p.exists());
    }

    // ── Query Volume Information ───────────────────────────────────────

    #[test]
    fn query_volume_device_info() {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = make_backend(&dir);

        let buf = backend
            .query_volume_information(1, FILE_FS_DEVICE_INFORMATION)
            .unwrap();
        assert_eq!(buf.len(), 8);
        // FILE_DEVICE_DISK = 0x07
        assert_eq!(buf[0], 0x07);
    }

    #[test]
    fn query_volume_attribute_info() {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = make_backend(&dir);

        let buf = backend
            .query_volume_information(1, FILE_FS_ATTRIBUTE_INFORMATION)
            .unwrap();
        // 12 bytes header + "NTFS" in UTF-16LE (8 bytes) = 20
        assert_eq!(buf.len(), 20);
    }

    // ── Query Directory ────────────────────────────────────────────────

    #[test]
    fn query_directory_lists_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
        fs::write(dir.path().join("b.txt"), b"bbb").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\", 0x8000_0001, 1, create::FILE_DIRECTORY_FILE, 0)
            .unwrap();

        // Initial query with "*" pattern
        let buf = backend
            .query_directory(
                1,
                resp.file_id,
                justrdp_rdpdr::pdu::irp::FILE_BOTH_DIRECTORY_INFORMATION,
                true,
                Some("\\*"),
            )
            .unwrap();
        assert!(!buf.is_empty()); // First entry: "."

        // Continue reading until STATUS_NO_MORE_FILES
        let mut count = 1;
        while backend
            .query_directory(
                1,
                resp.file_id,
                justrdp_rdpdr::pdu::irp::FILE_BOTH_DIRECTORY_INFORMATION,
                false,
                None,
            )
            .is_ok()
        {
            count += 1;
            if count > 20 {
                break; // safety
            }
        }

        // Should have: ".", "..", "a.txt", "b.txt" = 4 entries
        assert_eq!(count, 4);

        backend.close(1, resp.file_id).unwrap();
    }

    // ── Path traversal protection ──────────────────────────────────────

    #[test]
    fn traversal_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = make_backend(&dir);

        let err = backend
            .create(1, "\\..\\secret.txt", 0x8000_0000, 1, 0, 0)
            .unwrap_err();
        assert_eq!(err.ntstatus, STATUS_ACCESS_DENIED);
    }

    // ── Glob pattern matching ──────────────────────────────────────────

    #[test]
    fn glob_star_matches_all() {
        assert!(NativeFilesystemBackend::pattern_matches("*", "anything"));
        assert!(NativeFilesystemBackend::pattern_matches("*.*", "file.txt"));
        assert!(NativeFilesystemBackend::pattern_matches("*.*", "noext"));
    }

    #[test]
    fn glob_specific_pattern() {
        assert!(NativeFilesystemBackend::pattern_matches("*.txt", "hello.txt"));
        assert!(!NativeFilesystemBackend::pattern_matches("*.txt", "hello.doc"));
        assert!(NativeFilesystemBackend::pattern_matches("test?", "test1"));
        assert!(!NativeFilesystemBackend::pattern_matches("test?", "test12"));
    }

    // ── Unsupported operations ─────────────────────────────────────────

    #[test]
    fn device_control_not_supported() {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = make_backend(&dir);

        let err = backend
            .device_control(1, FileHandle(1), 0, &[], 0)
            .unwrap_err();
        assert_eq!(err.ntstatus, justrdp_rdpdr::pdu::irp::STATUS_NOT_SUPPORTED);
    }
}
