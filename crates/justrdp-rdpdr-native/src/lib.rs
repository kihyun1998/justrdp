// Platform-specific modules use unsafe for libc/windows-sys FFI.
#![deny(unsafe_code)]
#![allow(unsafe_code)] // FFI functions in this file require unsafe.

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

// ── Lock operation flags (MS-SMB2 2.2.26) ─────────────────────────────────

/// Shared (read) lock. If not set, exclusive (write) lock.
const LOCK_SHARED: u32 = 0x0000_0001;
/// Return immediately if lock cannot be acquired.
const LOCK_FAIL_IMMEDIATELY: u32 = 0x0000_0002;
/// Release the lock. If not set, acquire it.
const LOCK_UNLOCK: u32 = 0x0000_0004;

/// Maximum bytes for a single read request (4 MiB).
const MAX_READ_BYTES: u32 = 4 * 1024 * 1024;

// FILE_ACTION constants (MS-FSCC 2.4.42)
const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;

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

                // Only create the immediate parent if missing — do not create
                // deep directory trees from untrusted server input.
                if let Some(parent) = new_path.parent() {
                    if !parent.exists() {
                        fs::create_dir(parent).map_err(|e| Self::map_io_error(&e))?;
                    }
                }

                if replace_if_exists {
                    fs::rename(&entry.path, &new_path)
                        .map_err(|e| Self::map_io_error(&e))?;
                } else {
                    // Atomic rename without replacement using platform-specific APIs
                    // to avoid TOCTOU race between exists() check and rename().
                    rename_exclusive(&entry.path, &new_path)
                        .map_err(|e| Self::map_io_error(&e))?;
                }

                // Update the stored path
                let entry = self
                    .handles
                    .get_mut(&file_id)
                    .ok_or(DeviceIoError::no_such_file())?;
                entry.path = new_path;

                Ok(())
            }

            FILE_BASIC_INFORMATION => {
                let info = parse_basic_info_set(data)
                    .ok_or(DeviceIoError::new(STATUS_INVALID_PARAMETER))?;

                let entry = self
                    .handles
                    .get(&file_id)
                    .ok_or(DeviceIoError::no_such_file())?;

                // Apply timestamps using platform-specific APIs.
                // Value 0 means "don't change", value -1 means "don't update
                // on subsequent ops" — both are treated as no-op here.
                // Best-effort: timestamp setting failures are not fatal.
                // Windows clients set timestamps during file copy and some
                // platforms silently reject certain timestamp values.
                let _ = set_file_times(&entry.path, &info);

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
        file_id: FileHandle,
        _watch_tree: bool,
        _completion_filter: u32,
    ) -> DeviceIoResult<Vec<u8>> {
        let entry = self
            .handles
            .get(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        if !entry.is_dir {
            return Err(DeviceIoError::new(STATUS_NOT_A_DIRECTORY));
        }

        // Block until a filesystem change is detected in the directory.
        let changed_name = wait_for_directory_change(&entry.path)
            .map_err(|_| DeviceIoError::unsuccessful())?;

        // Encode a single FILE_NOTIFY_INFORMATION entry.
        // FILE_ACTION_MODIFIED (0x03) is a safe default for all change types.
        Ok(encode_notify_info(&changed_name, FILE_ACTION_MODIFIED))
    }

    fn lock_control(
        &mut self,
        _device_id: u32,
        file_id: FileHandle,
        operation: u32,
        locks: &[(u64, u64)],
    ) -> DeviceIoResult<()> {
        let entry = self
            .handles
            .get(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        let is_unlock = operation & LOCK_UNLOCK != 0;
        let is_shared = operation & LOCK_SHARED != 0;
        let fail_immediately = operation & LOCK_FAIL_IMMEDIATELY != 0;

        for &(offset, length) in locks {
            if is_unlock {
                unlock_file(&entry.file, offset, length)
                    .map_err(|e| Self::map_io_error(&e))?;
            } else {
                lock_file(&entry.file, offset, length, is_shared, fail_immediately)
                    .map_err(|e| Self::map_io_error(&e))?;
            }
        }

        Ok(())
    }
}

// ── Platform-specific helpers ─────────────────────────────────────────────

// ── FILE_NOTIFY_INFORMATION encoding ──────────────────────────────────────

/// Encode a single FILE_NOTIFY_INFORMATION entry (MS-FSCC 2.4.42).
///
/// Layout:
/// - NextEntryOffset: u32 LE (0 = last entry)
/// - Action: u32 LE
/// - FileNameLength: u32 LE (bytes)
/// - FileName: UTF-16LE
fn encode_notify_info(filename: &str, action: u32) -> Vec<u8> {
    let name_utf16 = path::encode_utf16le(filename);
    let name_len = name_utf16.len() as u32;

    let mut buf = Vec::with_capacity(12 + name_utf16.len());
    buf.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset = 0 (single entry)
    buf.extend_from_slice(&action.to_le_bytes()); // Action
    buf.extend_from_slice(&name_len.to_le_bytes()); // FileNameLength
    buf.extend_from_slice(&name_utf16); // FileName (UTF-16LE)

    buf
}

// ── Directory change notification ─────────────────────────────────────────

/// Block until a change is detected in the given directory.
/// Returns the name of the first changed file/entry, or "." if unknown.
#[cfg(target_os = "macos")]
fn wait_for_directory_change(dir: &std::path::Path) -> std::io::Result<String> {
    use std::os::unix::io::AsRawFd;

    let dir_file = fs::File::open(dir)?;
    let fd = dir_file.as_raw_fd();

    // SAFETY: Creating a kqueue file descriptor. Returns -1 on failure.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Watch for NOTE_WRITE (files added/removed/renamed) on the directory fd.
    let changelist = libc::kevent {
        ident: fd as usize,
        filter: libc::EVFILT_VNODE,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
        fflags: libc::NOTE_WRITE | libc::NOTE_ATTRIB | libc::NOTE_RENAME,
        data: 0,
        udata: std::ptr::null_mut(),
    };

    let mut eventlist: libc::kevent = unsafe { std::mem::zeroed() };

    // Set a timeout of 30 seconds to prevent indefinite blocking.
    let timeout = libc::timespec {
        tv_sec: 30,
        tv_nsec: 0,
    };

    // SAFETY: kq is a valid kqueue fd, changelist and eventlist are valid pointers.
    let nev = unsafe {
        libc::kevent(
            kq,
            &changelist,
            1,
            &mut eventlist,
            1,
            &timeout,
        )
    };

    // SAFETY: Closing the kqueue fd.
    unsafe {
        libc::close(kq);
    }

    if nev < 0 {
        return Err(std::io::Error::last_os_error());
    }

    if nev == 0 {
        // Timeout — return a generic change to unblock the caller.
        return Ok(".".to_string());
    }

    // kqueue doesn't tell us WHICH file changed, just that the directory was modified.
    // Return "." as a generic indicator.
    Ok(".".to_string())
}

#[cfg(target_os = "linux")]
fn wait_for_directory_change(dir: &std::path::Path) -> std::io::Result<String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;

    // SAFETY: Creating an inotify instance.
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if inotify_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mask = libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_MODIFY
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_ATTRIB;

    // SAFETY: Adding a watch on a valid inotify fd with a valid C path.
    let wd = unsafe { libc::inotify_add_watch(inotify_fd, c_path.as_ptr(), mask as u32) };
    if wd < 0 {
        unsafe { libc::close(inotify_fd); }
        return Err(std::io::Error::last_os_error());
    }

    // Set a read timeout using poll.
    let mut pollfd = libc::pollfd {
        fd: inotify_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    // SAFETY: Polling a valid fd with a 30-second timeout.
    let ret = unsafe { libc::poll(&mut pollfd, 1, 30_000) };

    if ret <= 0 {
        unsafe {
            libc::inotify_rm_watch(inotify_fd, wd);
            libc::close(inotify_fd);
        }
        if ret == 0 {
            return Ok(".".to_string()); // Timeout
        }
        return Err(std::io::Error::last_os_error());
    }

    // Read the event to get the filename.
    let mut buf = [0u8; 4096];
    // SAFETY: Reading from a valid inotify fd into a valid buffer.
    let n = unsafe {
        libc::read(inotify_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };

    unsafe {
        libc::inotify_rm_watch(inotify_fd, wd);
        libc::close(inotify_fd);
    }

    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Parse the first inotify_event to extract the filename.
    // Use read_unaligned because buf is a [u8] array with 1-byte alignment,
    // but inotify_event has 4-byte aligned fields.
    if n as usize >= std::mem::size_of::<libc::inotify_event>() {
        let event = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const libc::inotify_event) };
        if event.len > 0 {
            let name_start = std::mem::size_of::<libc::inotify_event>();
            let name_end = name_start + event.len as usize;
            if name_end <= n as usize {
                let name_bytes = &buf[name_start..name_end];
                // Trim trailing nulls
                let name = std::str::from_utf8(
                    &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len())]
                )
                .unwrap_or(".");
                return Ok(name.to_string());
            }
        }
    }

    Ok(".".to_string())
}

#[cfg(windows)]
fn wait_for_directory_change(dir: &std::path::Path) -> std::io::Result<String> {
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    // SAFETY: Calling FindFirstChangeNotificationW with a valid wide string path.
    let handle = unsafe {
        windows_sys::Win32::Storage::FileSystem::FindFirstChangeNotificationW(
            wide.as_ptr(),
            0, // don't watch subtree
            windows_sys::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE_FILE_NAME
                | windows_sys::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE_DIR_NAME
                | windows_sys::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE_SIZE
                | windows_sys::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE_LAST_WRITE,
        )
    };

    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    // Wait for the notification (30-second timeout).
    // SAFETY: handle is valid.
    let wait_result = unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 30_000)
    };

    // SAFETY: Closing the notification handle.
    unsafe {
        windows_sys::Win32::Storage::FileSystem::FindCloseChangeNotification(handle);
    }

    match wait_result {
        0 => Ok(".".to_string()), // WAIT_OBJECT_0 — change detected
        0x102 => Ok(".".to_string()), // WAIT_TIMEOUT
        _ => Err(std::io::Error::last_os_error()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn wait_for_directory_change(_dir: &std::path::Path) -> std::io::Result<String> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "directory change notification not supported on this platform",
    ))
}

// ── Atomic rename (no-replace) ────────────────────────────────────────────

/// Rename a file/directory atomically, failing if the destination exists.
///
/// Uses platform-specific APIs to avoid TOCTOU race between an existence
/// check and the rename operation.
#[cfg(target_os = "linux")]
fn rename_exclusive(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let from_c = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
    let to_c = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;

    // SAFETY: Calling libc renameat2 with valid C strings and AT_FDCWD.
    // RENAME_NOREPLACE (1) fails atomically if destination exists.
    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from_c.as_ptr(),
            libc::AT_FDCWD,
            to_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_exclusive(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let from_c = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
    let to_c = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;

    // SAFETY: Calling libc renameatx_np with valid C strings and AT_FDCWD.
    // RENAME_EXCL (0x0004) fails atomically if destination exists.
    let ret = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            from_c.as_ptr(),
            libc::AT_FDCWD,
            to_c.as_ptr(),
            libc::RENAME_EXCL,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn rename_exclusive(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let from_wide: Vec<u16> = from.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let to_wide: Vec<u16> = to.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    // SAFETY: Calling MoveFileExW with valid null-terminated wide strings.
    // Flags = 0 means no MOVEFILE_REPLACE_EXISTING — fails if destination exists.
    let ret = unsafe {
        windows_sys::Win32::Storage::FileSystem::MoveFileExW(
            from_wide.as_ptr(),
            to_wide.as_ptr(),
            0, // no replace
        )
    };

    if ret != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn rename_exclusive(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    // Fallback: best-effort check + rename. Small TOCTOU window remains.
    if to.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    fs::rename(from, to)
}

// ── File timestamp setting ────────────────────────────────────────────────

/// Set file timestamps from a FILE_BASIC_INFORMATION structure.
///
/// Timestamps with value 0 or -1 are skipped (meaning "don't change").
#[cfg(unix)]
fn set_file_times(path: &std::path::Path, info: &fs_info::BasicInfoSet) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => return,
    };

    let access_time = filetime_to_timespec(info.last_access_time);
    let mod_time = filetime_to_timespec(info.last_write_time);

    let times = [access_time, mod_time];

    // SAFETY: Calling utimensat with a valid C string path and valid timespec array.
    // AT_FDCWD resolves relative paths from the current directory.
    unsafe {
        libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0);
    }
}

#[cfg(unix)]
fn filetime_to_timespec(filetime: i64) -> libc::timespec {
    // 0 = don't change, -1 = don't update on subsequent ops
    if filetime <= 0 {
        return libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        };
    }

    // FILETIME: 100-nanosecond intervals since 1601-01-01
    // Unix epoch offset: 116_444_736_000_000_000
    const FILETIME_UNIX_OFFSET: i64 = 116_444_736_000_000_000;

    let relative = filetime - FILETIME_UNIX_OFFSET;

    if relative < 0 {
        // Before Unix epoch — set to epoch (best effort).
        // We check `relative` instead of just `secs` to avoid negative tv_nsec
        // from the modulo operation (POSIX requires tv_nsec >= 0).
        return libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
    }

    let secs = relative / 10_000_000;
    let nsecs = (relative % 10_000_000) * 100;

    {
        libc::timespec {
            tv_sec: secs as libc::time_t,
            tv_nsec: nsecs as libc::c_long,
        }
    }
}

#[cfg(windows)]
fn set_file_times(path: &std::path::Path, info: &fs_info::BasicInfoSet) {
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    // Open with FILE_WRITE_ATTRIBUTES to set timestamps.
    // SAFETY: Calling Windows API with valid null-terminated wide string.
    let handle = unsafe {
        windows_sys::Win32::Storage::FileSystem::CreateFileW(
            wide.as_ptr(),
            0x0100, // FILE_WRITE_ATTRIBUTES
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            std::ptr::null(),
            windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING,
            windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };

    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return;
    }

    let creation = filetime_or_null(info.creation_time);
    let access = filetime_or_null(info.last_access_time);
    let write = filetime_or_null(info.last_write_time);

    // SAFETY: handle is valid and FILETIME pointers are valid or null.
    unsafe {
        windows_sys::Win32::Storage::FileSystem::SetFileTime(
            handle,
            creation.as_ref().map_or(std::ptr::null(), |ft| ft),
            access.as_ref().map_or(std::ptr::null(), |ft| ft),
            write.as_ref().map_or(std::ptr::null(), |ft| ft),
        );
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }
}

#[cfg(windows)]
fn filetime_or_null(ft: i64) -> Option<windows_sys::Win32::Foundation::FILETIME> {
    if ft <= 0 {
        None
    } else {
        Some(windows_sys::Win32::Foundation::FILETIME {
            dwLowDateTime: ft as u32,
            dwHighDateTime: (ft >> 32) as u32,
        })
    }
}

#[cfg(not(any(unix, windows)))]
fn set_file_times(_path: &std::path::Path, _info: &fs_info::BasicInfoSet) {
    // No platform API available — accept silently.
}

// ── File locking ──────────────────────────────────────────────────────────

#[cfg(unix)]
fn lock_file(
    file: &std::fs::File,
    offset: u64,
    length: u64,
    shared: bool,
    fail_immediately: bool,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let lock_type = if shared { libc::F_RDLCK } else { libc::F_WRLCK };
    let cmd = if fail_immediately {
        libc::F_SETLK
    } else {
        libc::F_SETLKW
    };

    let flock = libc::flock {
        l_type: lock_type as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: offset as libc::off_t,
        l_len: length as libc::off_t,
        l_pid: 0,
    };

    // SAFETY: file descriptor is valid, flock struct is properly initialized.
    let ret = unsafe { libc::fcntl(file.as_raw_fd(), cmd, &flock) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_file(file: &std::fs::File, offset: u64, length: u64) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let flock = libc::flock {
        l_type: libc::F_UNLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: offset as libc::off_t,
        l_len: length as libc::off_t,
        l_pid: 0,
    };

    // SAFETY: file descriptor is valid, flock struct is properly initialized.
    let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &flock) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_file(
    file: &std::fs::File,
    offset: u64,
    length: u64,
    shared: bool,
    fail_immediately: bool,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let mut flags = 0u32;
    if !shared {
        flags |= windows_sys::Win32::Storage::FileSystem::LOCKFILE_EXCLUSIVE_LOCK;
    }
    if fail_immediately {
        flags |= windows_sys::Win32::Storage::FileSystem::LOCKFILE_FAIL_IMMEDIATELY;
    }

    let mut overlapped: windows_sys::Win32::System::IO::OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.Anonymous.Anonymous.Offset = offset as u32;
    overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;

    // SAFETY: file handle is valid, OVERLAPPED is properly initialized.
    let ret = unsafe {
        windows_sys::Win32::Storage::FileSystem::LockFileEx(
            file.as_raw_handle() as _,
            flags,
            0,
            length as u32,
            (length >> 32) as u32,
            &mut overlapped,
        )
    };

    if ret != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn unlock_file(file: &std::fs::File, offset: u64, length: u64) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let mut overlapped: windows_sys::Win32::System::IO::OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.Anonymous.Anonymous.Offset = offset as u32;
    overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;

    // SAFETY: file handle is valid, OVERLAPPED is properly initialized.
    let ret = unsafe {
        windows_sys::Win32::Storage::FileSystem::UnlockFileEx(
            file.as_raw_handle() as _,
            0,
            length as u32,
            (length >> 32) as u32,
            &mut overlapped,
        )
    };

    if ret != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(unix, windows)))]
fn lock_file(
    _file: &std::fs::File,
    _offset: u64,
    _length: u64,
    _shared: bool,
    _fail_immediately: bool,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "file locking not supported on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
fn unlock_file(_file: &std::fs::File, _offset: u64, _length: u64) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "file locking not supported on this platform",
    ))
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

    // ── Rename ─────────────────────────────────────────────────────────

    #[test]
    fn rename_exclusive_fails_if_destination_exists() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("src.txt"), b"data").unwrap();
        fs::write(dir.path().join("dst.txt"), b"existing").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\src.txt", 0x4000_0000, 1, 0, 0)
            .unwrap();

        // Build FILE_RENAME_INFORMATION with replace_if_exists = false
        let name = "\\dst.txt";
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut data = Vec::new();
        data.push(0x00); // ReplaceIfExists = false
        data.extend_from_slice(&[0, 0, 0]); // Reserved
        data.extend_from_slice(&0u32.to_le_bytes()); // RootDirectory
        data.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        data.extend_from_slice(&name_utf16);

        let err = backend
            .set_information(1, resp.file_id, FILE_RENAME_INFORMATION, &data)
            .unwrap_err();
        assert_eq!(err.ntstatus, STATUS_OBJECT_NAME_COLLISION);

        backend.close(1, resp.file_id).unwrap();
    }

    #[test]
    fn rename_with_replace_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("src.txt"), b"new data").unwrap();
        fs::write(dir.path().join("dst.txt"), b"old data").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\src.txt", 0x4000_0000, 1, 0, 0)
            .unwrap();

        // Build FILE_RENAME_INFORMATION with replace_if_exists = true
        let name = "\\dst.txt";
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut data = Vec::new();
        data.push(0x01); // ReplaceIfExists = true
        data.extend_from_slice(&[0, 0, 0]);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        data.extend_from_slice(&name_utf16);

        backend
            .set_information(1, resp.file_id, FILE_RENAME_INFORMATION, &data)
            .unwrap();

        backend.close(1, resp.file_id).unwrap();

        // dst.txt should now contain the new data
        assert!(!dir.path().join("src.txt").exists());
        assert_eq!(fs::read(dir.path().join("dst.txt")).unwrap(), b"new data");
    }

    // ── Lock control ──────────────────────────────────────────────────

    #[test]
    fn lock_and_unlock_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lock.txt"), b"lockable").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\lock.txt", 0x4000_0000, 1, 0, 0)
            .unwrap();

        // Exclusive lock, fail immediately
        let locks = vec![(0u64, 100u64)];
        backend
            .lock_control(1, resp.file_id, LOCK_FAIL_IMMEDIATELY, &locks)
            .unwrap();

        // Unlock
        backend
            .lock_control(1, resp.file_id, LOCK_UNLOCK, &locks)
            .unwrap();

        backend.close(1, resp.file_id).unwrap();
    }

    #[test]
    fn shared_lock_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("shared.txt"), b"data").unwrap();

        let mut backend = make_backend(&dir);
        let resp = backend
            .create(1, "\\shared.txt", 0x8000_0000, 1, 0, 0)
            .unwrap();

        // Shared lock, fail immediately
        let locks = vec![(0u64, 50u64)];
        backend
            .lock_control(
                1,
                resp.file_id,
                LOCK_SHARED | LOCK_FAIL_IMMEDIATELY,
                &locks,
            )
            .unwrap();

        // Unlock
        backend
            .lock_control(1, resp.file_id, LOCK_UNLOCK, &locks)
            .unwrap();

        backend.close(1, resp.file_id).unwrap();
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
