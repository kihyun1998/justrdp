//! Native filesystem backend for Device Redirection (MS-RDPEFS).
//!
//! [`NativeFilesystemBackend`] implements [`RdpdrBackend`] by translating
//! the RDPEFS / FSCC wire protocol into operations against a pluggable
//! [`FilesystemSurface`] adapter.  The default adapter is [`StdFilesystem`],
//! which serves a local directory as a redirected drive via `std::fs`.
//! Test code can substitute a mock surface (no real disk required) — see
//! ADR-0006 for the deepening rationale.

mod create;
mod dir_info;
mod fs_info;
mod handle_map;
mod path;
mod std_fs;
pub mod surface;
mod volume_info;

pub use std_fs::StdFilesystem;
pub use surface::{
    DiskSpace, FileTimes, FilesystemSurface, LockMode, LockRange, NativeDirEntry,
    NativeFilesystemError, NativeFilesystemResult, NativeMetadata, OpenAccess, OpenDisposition,
    OpenKind, OpenOptions, OpenOutcome, Opened,
};

use std::path::PathBuf;

use justrdp_rdpdr::pdu::device::DeviceAnnounce;
use justrdp_rdpdr::pdu::irp::{
    FILE_ATTRIBUTE_TAG_INFORMATION, FILE_BASIC_INFORMATION, FILE_DISPOSITION_INFORMATION,
    FILE_END_OF_FILE_INFORMATION, FILE_FS_ATTRIBUTE_INFORMATION, FILE_FS_DEVICE_INFORMATION,
    FILE_FS_FULL_SIZE_INFORMATION, FILE_FS_SIZE_INFORMATION, FILE_FS_VOLUME_INFORMATION,
    FILE_RENAME_INFORMATION, FILE_STANDARD_INFORMATION, STATUS_ACCESS_DENIED, STATUS_NO_MORE_FILES,
};
use justrdp_rdpdr::{CreateResponse, DeviceIoError, DeviceIoResult, FileHandle, RdpdrBackend};

use crate::create::{
    FILE_CREATED, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPENED,
    FILE_OVERWRITTEN, FILE_SUPERSEDED,
};
use crate::dir_info::encode_dir_entry;
use crate::fs_info::{
    encode_attribute_tag_info, encode_basic_info, encode_standard_info, parse_basic_info_set,
    parse_disposition, parse_end_of_file, parse_rename, BasicInfoSet, FILETIME_UNIX_EPOCH_OFFSET,
};
use crate::handle_map::{DirEntry, DirState, HandleMap};
use crate::path::rdp_to_local;
use crate::volume_info::{
    encode_attribute_info, encode_device_info, encode_full_size_info, encode_size_info,
    encode_volume_info,
};

// ── NTSTATUS codes not already in justrdp-rdpdr ────────────────────────────

const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_DISK_FULL: u32 = 0xC000_007F;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_FILE_LOCK_CONFLICT: u32 = 0xC000_0054;

// ── Lock operation flags (MS-RDPEFS, aligned with Windows SL_ constants) ──

/// Exclusive lock. If not set, shared (read) lock.
const SL_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
/// Return immediately if lock cannot be acquired.
const SL_FAIL_IMMEDIATELY: u32 = 0x0000_0004;
/// Release the lock. If not set, acquire it.
const SL_LOCK_RELEASE: u32 = 0x0000_0020;

/// Maximum bytes for a single read request (4 MiB).
const MAX_READ_BYTES: u32 = 4 * 1024 * 1024;

/// Maximum bytes for a single write request (4 MiB).
const MAX_WRITE_BYTES: usize = 4 * 1024 * 1024;

// FILE_ACTION constants (MS-FSCC 2.4.42)
const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;

// DesiredAccess flags (MS-SMB2 2.2.13.1.1) — used by raw_to_opts
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

// ── NativeFilesystemBackend ────────────────────────────────────────────────

/// A native filesystem backend that shares a local directory as an RDP
/// redirected drive.
///
/// Generic over a [`FilesystemSurface`] adapter `F`.  The default
/// (`F = StdFilesystem`) is the production adapter; tests can construct
/// the backend with a mock surface via [`NativeFilesystemBackend::with_surface`].
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
pub struct NativeFilesystemBackend<F: FilesystemSurface = StdFilesystem> {
    surface: F,
    root_path: PathBuf,
    device_id: u32,
    dos_name: String,
    display_name: Option<String>,
    handles: HandleMap<F::Handle>,
    volume_label: String,
    fs_name: String,
}

impl NativeFilesystemBackend<StdFilesystem> {
    /// Create a new native filesystem backend backed by [`StdFilesystem`].
    ///
    /// - `root_path`: Local directory to share. Must exist and be a directory.
    /// - `device_id`: Client-assigned unique device ID.
    /// - `dos_name`: DOS drive name (e.g., `"C:"`), max 7 chars.
    ///
    /// # Panics
    ///
    /// Panics if `dos_name` exceeds 7 characters or if `root_path` is not an
    /// existing directory.
    pub fn new(root_path: impl Into<PathBuf>, device_id: u32, dos_name: &str) -> Self {
        Self::with_surface(StdFilesystem::new(), root_path, device_id, dos_name)
    }
}

impl<F: FilesystemSurface> NativeFilesystemBackend<F> {
    /// Create a backend with a custom [`FilesystemSurface`] adapter.  Used by
    /// the tests in this crate to substitute a mock surface for the real
    /// `std::fs`.
    pub fn with_surface(
        surface: F,
        root_path: impl Into<PathBuf>,
        device_id: u32,
        dos_name: &str,
    ) -> Self {
        assert!(
            dos_name.len() <= 7,
            "dos_name must be at most 7 characters, got {}",
            dos_name.len()
        );
        let root_path = root_path.into();
        assert!(
            root_path.is_dir(),
            "root_path must be an existing directory: {:?}",
            root_path
        );
        Self {
            surface,
            root_path,
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

    /// Borrow the underlying surface — used by tests to inspect mock state.
    pub fn surface(&self) -> &F {
        &self.surface
    }

    /// Mutably borrow the underlying surface — used by tests to mutate mock
    /// state between operations.
    pub fn surface_mut(&mut self) -> &mut F {
        &mut self.surface
    }

    /// Resolve an RDP path to a local path, returning a DeviceIoError on failure.
    fn resolve_path(&self, rdp_path: &str) -> DeviceIoResult<PathBuf> {
        rdp_to_local(&self.root_path, rdp_path)
            .ok_or(DeviceIoError::new(STATUS_ACCESS_DENIED))
    }

    /// Maximum directory entries to buffer (prevents memory exhaustion from
    /// adversarial directories, e.g., millions of files).
    const MAX_DIR_ENTRIES: usize = 100_000;

    /// Read a directory via the surface and build enumeration state.
    ///
    /// "." and ".." are synthesized at this layer with minimal directory
    /// metadata (`is_dir: true`, zero size, no timestamps).  The
    /// [`FilesystemSurface`] does not expose a path-based stat method —
    /// real adapters' `read_dir` already excludes "." / ".." so the
    /// wrapper is responsible for filling them in.  Synthetic metadata
    /// is acceptable because the encoded `FILE_*_DIRECTORY_INFORMATION`
    /// entry needs only the directory bit set; consumers do not validate
    /// timestamps for these synthetic entries.
    fn populate_dir_state(
        surface: &F,
        dir_path: &std::path::Path,
        path: Option<&str>,
    ) -> DirState {
        let pattern = path
            .map(|p| p.trim_start_matches('\\').trim_start_matches('/'))
            .unwrap_or("*");

        let mut entries = Vec::new();

        let dot_metadata = NativeMetadata {
            is_dir: true,
            is_readonly: false,
            size: 0,
            created: None,
            accessed: None,
            modified: None,
        };

        if pattern_matches(pattern, ".") {
            entries.push(DirEntry {
                name: ".".to_string(),
                metadata: dot_metadata.clone(),
            });
        }
        if pattern_matches(pattern, "..") {
            entries.push(DirEntry {
                name: "..".to_string(),
                metadata: dot_metadata,
            });
        }

        if let Ok(read_dir) = surface.read_dir(dir_path) {
            for native_entry in read_dir {
                if entries.len() >= Self::MAX_DIR_ENTRIES {
                    break;
                }
                if pattern_matches(pattern, &native_entry.name) {
                    entries.push(DirEntry {
                        name: native_entry.name,
                        metadata: native_entry.metadata,
                    });
                }
            }
        }

        DirState {
            entries,
            cursor: 0,
        }
    }

    // Glob-pattern helpers exposed at the impl level so the existing tests
    // can address them without specifying a concrete `F`.  These delegate to
    // the free-function implementations.
    #[cfg(test)]
    fn pattern_matches(pattern: &str, name: &str) -> bool {
        pattern_matches(pattern, name)
    }
}

impl<F: FilesystemSurface> std::fmt::Debug for NativeFilesystemBackend<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeFilesystemBackend")
            .field("root_path", &self.root_path)
            .field("device_id", &self.device_id)
            .field("dos_name", &self.dos_name)
            .finish()
    }
}

// ── Glob pattern matching (free functions) ──────────────────────────────────

/// Simple glob pattern matching for directory queries.
///
/// Supports `*` (match any), `?` (match one), and `*.*` (match all with extension).
fn pattern_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.trim_start_matches('\\').trim_start_matches('/');

    // "*" and "*.*" match everything
    if pattern == "*" || pattern == "*.*" {
        return true;
    }

    glob_match(pattern.as_bytes(), name.as_bytes())
}

fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len()
            && (pattern[pi].eq_ignore_ascii_case(&text[ti]) || pattern[pi] == b'?')
        {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
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

// ── Raw → typed translations ────────────────────────────────────────────────

/// Translate the raw `IRP_MJ_CREATE` parameters into typed [`OpenOptions`]
/// plus a separately-returned `delete_on_close` flag (which the wrapper
/// owns; the surface does not see it).
fn raw_to_opts(
    desired_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> DeviceIoResult<(OpenOptions, bool)> {
    use justrdp_rdpdr::pdu::irp::{
        FILE_CREATE, FILE_OPEN, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE,
    };

    let need_write = desired_access
        & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL)
        != 0;
    let need_read = desired_access
        & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL | MAXIMUM_ALLOWED)
        != 0
        || !need_write; // default to read if no specific flags

    let access = match (need_read, need_write) {
        (true, true) => OpenAccess::ReadWrite,
        (false, true) => OpenAccess::Write,
        _ => OpenAccess::Read,
    };

    let disposition = match create_disposition {
        FILE_OPEN => OpenDisposition::Open,
        FILE_CREATE => OpenDisposition::Create,
        FILE_OPEN_IF => OpenDisposition::OpenIf,
        FILE_OVERWRITE => OpenDisposition::Overwrite,
        FILE_OVERWRITE_IF => OpenDisposition::OverwriteIf,
        FILE_SUPERSEDE => OpenDisposition::Supersede,
        _ => return Err(DeviceIoError::new(STATUS_INVALID_PARAMETER)),
    };

    let kind = if create_options & FILE_DIRECTORY_FILE != 0 {
        OpenKind::Directory
    } else if create_options & FILE_NON_DIRECTORY_FILE != 0 {
        OpenKind::FileStrict
    } else {
        OpenKind::File
    };

    let append = desired_access & FILE_APPEND_DATA != 0;
    let delete_on_close = create_options & FILE_DELETE_ON_CLOSE != 0;

    Ok((
        OpenOptions {
            access,
            disposition,
            kind,
            append,
        },
        delete_on_close,
    ))
}

fn outcome_to_information(outcome: OpenOutcome) -> u8 {
    match outcome {
        OpenOutcome::Created => FILE_CREATED,
        OpenOutcome::Opened => FILE_OPENED,
        OpenOutcome::Overwritten => FILE_OVERWRITTEN,
        OpenOutcome::Superseded => FILE_SUPERSEDED,
    }
}

/// Map a [`NativeFilesystemError`] to the RDPEFS [`DeviceIoError`] the
/// caller expects.  Variant-by-variant translation keeps the wrapper
/// independent of `std::io::ErrorKind`.
fn map_native_fs_error(e: NativeFilesystemError) -> DeviceIoError {
    match e {
        NativeFilesystemError::NotFound => DeviceIoError::no_such_file(),
        NativeFilesystemError::AccessDenied => DeviceIoError::access_denied(),
        NativeFilesystemError::AlreadyExists => DeviceIoError::new(STATUS_OBJECT_NAME_COLLISION),
        NativeFilesystemError::DiskFull => DeviceIoError::new(STATUS_DISK_FULL),
        NativeFilesystemError::NotADirectory => DeviceIoError::new(STATUS_NOT_A_DIRECTORY),
        NativeFilesystemError::Locked => DeviceIoError::new(STATUS_FILE_LOCK_CONFLICT),
        NativeFilesystemError::Unsupported => DeviceIoError::not_supported(),
        NativeFilesystemError::InvalidInput => DeviceIoError::new(STATUS_INVALID_PARAMETER),
        NativeFilesystemError::OsApi(_) => DeviceIoError::unsuccessful(),
    }
}

/// Convert a parsed `FILE_BASIC_INFORMATION` request into a typed
/// [`FileTimes`] for the surface.  Slots with sentinel values `0`
/// ("don't change") and `-1` ("don't update on subsequent ops") become
/// `None`; positive values are converted to `SystemTime`.
fn basic_info_to_file_times(info: &BasicInfoSet) -> FileTimes {
    FileTimes {
        creation: filetime_to_system_time(info.creation_time),
        access: filetime_to_system_time(info.last_access_time),
        write: filetime_to_system_time(info.last_write_time),
    }
}

fn filetime_to_system_time(ft: i64) -> Option<std::time::SystemTime> {
    if ft <= 0 {
        return None; // 0 = "don't change", -1 = "don't update"; both → no-op
    }
    let relative = ft - FILETIME_UNIX_EPOCH_OFFSET;
    if relative < 0 {
        Some(std::time::UNIX_EPOCH) // Pre-1970 — clamp to epoch (best effort)
    } else {
        let secs = (relative / 10_000_000) as u64;
        let nanos = ((relative % 10_000_000) * 100) as u32;
        Some(
            std::time::UNIX_EPOCH
                + std::time::Duration::new(secs, nanos),
        )
    }
}

// ── RdpdrBackend implementation ────────────────────────────────────────────

impl<F: FilesystemSurface> RdpdrBackend for NativeFilesystemBackend<F> {
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
        _file_attributes: u32,
    ) -> DeviceIoResult<CreateResponse> {
        let local_path = self.resolve_path(path)?;
        let (opts, delete_on_close) =
            raw_to_opts(desired_access, create_disposition, create_options)?;

        let opened = self
            .surface
            .open(&local_path, opts)
            .map_err(map_native_fs_error)?;

        let information = outcome_to_information(opened.outcome);

        let file_id = self
            .handles
            .insert(opened.handle, local_path, opened.is_dir, delete_on_close)
            .ok_or(DeviceIoError::new(STATUS_INSUFFICIENT_RESOURCES))?;

        Ok(CreateResponse {
            file_id,
            information,
        })
    }

    fn close(&mut self, _device_id: u32, file_id: FileHandle) -> DeviceIoResult<()> {
        let entry = self
            .handles
            .remove(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        // Close the surface handle first so any platform locks are
        // released before we attempt the deletion below.
        self.surface
            .close(entry.handle)
            .map_err(map_native_fs_error)?;

        if entry.delete_on_close {
            let result = if entry.is_dir {
                self.surface.remove_dir(&entry.path)
            } else {
                self.surface.remove_file(&entry.path)
            };
            result.map_err(map_native_fs_error)?;
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
        let capped_length = length.min(MAX_READ_BYTES) as usize;
        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        self.surface
            .read(&mut entry.handle, offset, capped_length)
            .map_err(map_native_fs_error)
    }

    fn write(
        &mut self,
        _device_id: u32,
        file_id: FileHandle,
        offset: u64,
        data: &[u8],
    ) -> DeviceIoResult<u32> {
        let data = if data.len() > MAX_WRITE_BYTES {
            &data[..MAX_WRITE_BYTES]
        } else {
            data
        };
        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        self.surface
            .write(&mut entry.handle, offset, data)
            .map_err(map_native_fs_error)
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

        let metadata = self
            .surface
            .metadata(&entry.handle)
            .map_err(map_native_fs_error)?;

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
            FILE_END_OF_FILE_INFORMATION => self.apply_end_of_file(file_id, data),
            FILE_DISPOSITION_INFORMATION => self.apply_disposition(file_id, data),
            FILE_RENAME_INFORMATION => self.apply_rename(file_id, data),
            FILE_BASIC_INFORMATION => self.apply_basic_info(file_id, data),
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
                let disk = self
                    .surface
                    .disk_space(&self.root_path)
                    .map_err(map_native_fs_error)?;
                Ok(encode_size_info(&disk))
            }

            FILE_FS_DEVICE_INFORMATION => Ok(encode_device_info()),

            FILE_FS_ATTRIBUTE_INFORMATION => Ok(encode_attribute_info(&self.fs_name)),

            FILE_FS_FULL_SIZE_INFORMATION => {
                let disk = self
                    .surface
                    .disk_space(&self.root_path)
                    .map_err(map_native_fs_error)?;
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
        // `initial_query` populates the cursor — done with `&self.surface`
        // before we take a `&mut` on the entry, to avoid reborrow issues.
        if initial_query {
            let entry = self
                .handles
                .get(&file_id)
                .ok_or(DeviceIoError::no_such_file())?;

            if !entry.is_dir {
                return Err(DeviceIoError::new(STATUS_NOT_A_DIRECTORY));
            }

            let dir_path = entry.path.clone();
            let new_state = Self::populate_dir_state(&self.surface, &dir_path, path);

            let entry = self
                .handles
                .get_mut(&file_id)
                .ok_or(DeviceIoError::no_such_file())?;
            entry.dir_state = Some(new_state);
        }

        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        if !entry.is_dir {
            return Err(DeviceIoError::new(STATUS_NOT_A_DIRECTORY));
        }

        let dir_state = entry
            .dir_state
            .as_mut()
            .ok_or(DeviceIoError::new(STATUS_NO_MORE_FILES))?;

        if dir_state.cursor >= dir_state.entries.len() {
            return Err(DeviceIoError::new(STATUS_NO_MORE_FILES));
        }

        let dir_entry = &dir_state.entries[dir_state.cursor];
        dir_state.cursor += 1;

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

        // NOTE: `surface.watch` blocks the current thread for up to its own
        // configured timeout (30 s for [`StdFilesystem`]).  Callers must
        // invoke this method from a dedicated blocking thread — not from an
        // async executor or the main RDP processing loop.
        let changed_name = self
            .surface
            .watch(&entry.path)
            .map_err(map_native_fs_error)?;

        Ok(encode_notify_info(&changed_name, FILE_ACTION_MODIFIED))
    }

    fn lock_control(
        &mut self,
        _device_id: u32,
        file_id: FileHandle,
        operation: u32,
        locks: &[(u64, u64)],
    ) -> DeviceIoResult<()> {
        let is_unlock = operation & SL_LOCK_RELEASE != 0;
        let mode = LockMode {
            exclusive: operation & SL_EXCLUSIVE_LOCK != 0,
            fail_immediately: operation & SL_FAIL_IMMEDIATELY != 0,
        };

        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        for &(offset, length) in locks {
            let range = LockRange { offset, length };
            let result = if is_unlock {
                self.surface.unlock(&mut entry.handle, range)
            } else {
                self.surface.lock(&mut entry.handle, range, mode)
            };
            result.map_err(map_native_fs_error)?;
        }

        Ok(())
    }
}

// ── set_information helpers ───────────────────────────────────────────────

impl<F: FilesystemSurface> NativeFilesystemBackend<F> {
    fn apply_end_of_file(&mut self, file_id: FileHandle, data: &[u8]) -> DeviceIoResult<()> {
        let new_size =
            parse_end_of_file(data).ok_or(DeviceIoError::new(STATUS_INVALID_PARAMETER))?;

        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        if entry.is_dir {
            return Err(DeviceIoError::new(STATUS_INVALID_PARAMETER));
        }

        self.surface
            .set_len(&mut entry.handle, new_size)
            .map_err(map_native_fs_error)
    }

    fn apply_disposition(&mut self, file_id: FileHandle, data: &[u8]) -> DeviceIoResult<()> {
        let delete =
            parse_disposition(data).ok_or(DeviceIoError::new(STATUS_INVALID_PARAMETER))?;

        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        entry.delete_on_close = delete;
        Ok(())
    }

    fn apply_rename(&mut self, file_id: FileHandle, data: &[u8]) -> DeviceIoResult<()> {
        let (replace_if_exists, new_name) =
            parse_rename(data).ok_or(DeviceIoError::new(STATUS_INVALID_PARAMETER))?;

        let entry = self
            .handles
            .get(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        let new_path =
            rdp_to_local(&self.root_path, &new_name).ok_or(DeviceIoError::access_denied())?;
        let old_path = entry.path.clone();

        self.surface
            .rename(&old_path, &new_path, replace_if_exists)
            .map_err(map_native_fs_error)?;

        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;
        entry.path = new_path;

        Ok(())
    }

    fn apply_basic_info(&mut self, file_id: FileHandle, data: &[u8]) -> DeviceIoResult<()> {
        let info =
            parse_basic_info_set(data).ok_or(DeviceIoError::new(STATUS_INVALID_PARAMETER))?;
        let times = basic_info_to_file_times(&info);

        let entry = self
            .handles
            .get_mut(&file_id)
            .ok_or(DeviceIoError::no_such_file())?;

        // Best-effort: timestamp setting failures are swallowed by the
        // adapter (mirrors prior behavior — the trait method returns
        // Result<()> for symmetry but [`StdFilesystem::set_times`] always
        // returns `Ok`).
        let _ = self.surface.set_times(&mut entry.handle, times);

        Ok(())
    }
}

// ── FILE_NOTIFY_INFORMATION encoding ──────────────────────────────────────

/// FILE_NOTIFY_INFORMATION fixed header size (before FileName).
const NOTIFY_INFO_HEADER: usize = 12;

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

    let mut buf = Vec::with_capacity(NOTIFY_INFO_HEADER + name_utf16.len());
    buf.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset = 0 (single entry)
    buf.extend_from_slice(&action.to_le_bytes()); // Action
    buf.extend_from_slice(&name_len.to_le_bytes()); // FileNameLength
    buf.extend_from_slice(&name_utf16); // FileName (UTF-16LE)

    buf
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        backend.write(1, resp.file_id, 0, b"Hello, RDP!").unwrap();
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
        assert!(NativeFilesystemBackend::<StdFilesystem>::pattern_matches("*", "anything"));
        assert!(NativeFilesystemBackend::<StdFilesystem>::pattern_matches("*.*", "file.txt"));
        assert!(NativeFilesystemBackend::<StdFilesystem>::pattern_matches("*.*", "noext"));
    }

    #[test]
    fn glob_specific_pattern() {
        assert!(NativeFilesystemBackend::<StdFilesystem>::pattern_matches("*.txt", "hello.txt"));
        assert!(!NativeFilesystemBackend::<StdFilesystem>::pattern_matches("*.txt", "hello.doc"));
        assert!(NativeFilesystemBackend::<StdFilesystem>::pattern_matches("test?", "test1"));
        assert!(!NativeFilesystemBackend::<StdFilesystem>::pattern_matches("test?", "test12"));
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
            .lock_control(1, resp.file_id, SL_EXCLUSIVE_LOCK | SL_FAIL_IMMEDIATELY, &locks)
            .unwrap();

        // Unlock
        backend
            .lock_control(1, resp.file_id, SL_LOCK_RELEASE, &locks)
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

        // Shared lock (no SL_EXCLUSIVE_LOCK), fail immediately
        let locks = vec![(0u64, 50u64)];
        backend
            .lock_control(
                1,
                resp.file_id,
                SL_FAIL_IMMEDIATELY, // no SL_EXCLUSIVE_LOCK = shared
                &locks,
            )
            .unwrap();

        // Unlock
        backend
            .lock_control(1, resp.file_id, SL_LOCK_RELEASE, &locks)
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
