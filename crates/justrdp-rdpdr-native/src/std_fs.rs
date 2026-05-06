//! Production [`FilesystemSurface`] adapter — `std::fs` plus four small
//! platform-FFI helpers (`lock_file` / `unlock_file`, `set_file_times`,
//! `rename_exclusive`, `wait_for_directory_change`).
//!
//! This adapter is wired up as the default backing of
//! [`crate::NativeFilesystemBackend`] (see step 3 of the deepening); test
//! adapters such as `MockFilesystem` (step 4) implement the same trait
//! to drive protocol logic without touching the real filesystem.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

use crate::create::{open_file, FILE_CREATED, FILE_OPENED, FILE_OVERWRITTEN, FILE_SUPERSEDED};
use crate::fs_info::{system_time_to_filetime, BasicInfoSet};
use crate::surface::{
    DiskSpace, FileTimes, FilesystemSurface, LockMode, LockRange, NativeDirEntry,
    NativeFilesystemError, NativeFilesystemResult, NativeMetadata, OpenAccess, OpenDisposition,
    OpenKind, OpenOptions, OpenOutcome, Opened,
};

/// Production [`FilesystemSurface`] over `std::fs`.
///
/// Stateless — every operation is a direct syscall.  Construct with
/// [`StdFilesystem::new`] (or via `Default`).
#[derive(Debug, Default)]
pub struct StdFilesystem;

impl StdFilesystem {
    /// Create a new `StdFilesystem` adapter.
    pub fn new() -> Self {
        Self
    }
}

impl FilesystemSurface for StdFilesystem {
    type Handle = fs::File;

    fn open(
        &mut self,
        path: &Path,
        opts: OpenOptions,
    ) -> NativeFilesystemResult<Opened<Self::Handle>> {
        let (desired_access, create_disposition, create_options) = opts_to_raw(opts);
        let result = open_file(path, desired_access, create_disposition, create_options, 0)
            .map_err(|e| map_io_error(&e))?;
        Ok(Opened {
            handle: result.file,
            outcome: information_to_outcome(result.information),
            is_dir: result.is_dir,
        })
    }

    fn rename(
        &mut self,
        from: &Path,
        to: &Path,
        replace: bool,
    ) -> NativeFilesystemResult<()> {
        let res = if replace {
            fs::rename(from, to)
        } else {
            crate::rename_exclusive(from, to)
        };
        res.map_err(|e| map_io_error(&e))
    }

    fn remove_file(&mut self, path: &Path) -> NativeFilesystemResult<()> {
        fs::remove_file(path).map_err(|e| map_io_error(&e))
    }

    fn remove_dir(&mut self, path: &Path) -> NativeFilesystemResult<()> {
        fs::remove_dir(path).map_err(|e| map_io_error(&e))
    }

    fn read_dir(&self, path: &Path) -> NativeFilesystemResult<Vec<NativeDirEntry>> {
        let read_dir = fs::read_dir(path).map_err(|e| map_io_error(&e))?;
        let mut entries = Vec::new();
        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue, // skip entries we can't stat (e.g., disappeared mid-iter)
            };
            entries.push(NativeDirEntry {
                name,
                metadata: metadata_from_std(&metadata),
            });
        }
        Ok(entries)
    }

    fn disk_space(&self, path: &Path) -> NativeFilesystemResult<DiskSpace> {
        DiskSpace::query(path).ok_or_else(|| {
            NativeFilesystemError::OsApi("disk_space query failed".to_string())
        })
    }

    fn close(&mut self, _handle: Self::Handle) -> NativeFilesystemResult<()> {
        // `Drop` closes the underlying file descriptor / handle.  We swallow
        // any close-time errors because Rust's `File::drop` does the same —
        // there is no portable way to surface them through `Drop`.
        Ok(())
    }

    fn read(
        &mut self,
        handle: &mut Self::Handle,
        offset: u64,
        len: usize,
    ) -> NativeFilesystemResult<Vec<u8>> {
        handle
            .seek(SeekFrom::Start(offset))
            .map_err(|e| map_io_error(&e))?;
        let mut buf = vec![0u8; len];
        let n = handle.read(&mut buf).map_err(|e| map_io_error(&e))?;
        buf.truncate(n);
        Ok(buf)
    }

    fn write(
        &mut self,
        handle: &mut Self::Handle,
        offset: u64,
        data: &[u8],
    ) -> NativeFilesystemResult<u32> {
        handle
            .seek(SeekFrom::Start(offset))
            .map_err(|e| map_io_error(&e))?;
        handle.write_all(data).map_err(|e| map_io_error(&e))?;
        Ok(data.len() as u32)
    }

    fn set_len(
        &mut self,
        handle: &mut Self::Handle,
        len: u64,
    ) -> NativeFilesystemResult<()> {
        handle.set_len(len).map_err(|e| map_set_len_error(&e))
    }

    fn metadata(&self, handle: &Self::Handle) -> NativeFilesystemResult<NativeMetadata> {
        handle
            .metadata()
            .map(|m| metadata_from_std(&m))
            .map_err(|e| map_io_error(&e))
    }

    fn set_times(
        &mut self,
        handle: &mut Self::Handle,
        times: FileTimes,
    ) -> NativeFilesystemResult<()> {
        let info = file_times_to_basic_info(times);
        crate::set_file_times(handle, &info);
        Ok(())
    }

    fn lock(
        &mut self,
        handle: &mut Self::Handle,
        range: LockRange,
        mode: LockMode,
    ) -> NativeFilesystemResult<()> {
        crate::lock_file(
            handle,
            range.offset,
            range.length,
            !mode.exclusive,
            mode.fail_immediately,
        )
        .map_err(|e| match e.kind() {
            io::ErrorKind::WouldBlock => NativeFilesystemError::Locked,
            _ => map_io_error(&e),
        })
    }

    fn unlock(
        &mut self,
        handle: &mut Self::Handle,
        range: LockRange,
    ) -> NativeFilesystemResult<()> {
        crate::unlock_file(handle, range.offset, range.length).map_err(|e| map_io_error(&e))
    }

    fn watch(&self, path: &Path) -> NativeFilesystemResult<String> {
        crate::wait_for_directory_change(path).map_err(|e| map_io_error(&e))
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Map an `std::io::Error` to a [`NativeFilesystemError`].  Variants that
/// don't have an `io::ErrorKind` counterpart fall through to [`OsApi`].
fn map_io_error(e: &io::Error) -> NativeFilesystemError {
    match e.kind() {
        io::ErrorKind::NotFound => NativeFilesystemError::NotFound,
        io::ErrorKind::PermissionDenied => NativeFilesystemError::AccessDenied,
        io::ErrorKind::AlreadyExists => NativeFilesystemError::AlreadyExists,
        io::ErrorKind::InvalidInput => NativeFilesystemError::InvalidInput,
        io::ErrorKind::Unsupported => NativeFilesystemError::Unsupported,
        _ => NativeFilesystemError::OsApi(e.to_string()),
    }
}

/// `set_len`-specific error mapping with disk-full detection.  ENOSPC (Unix)
/// and ERROR_DISK_FULL (Windows) become [`NativeFilesystemError::DiskFull`];
/// everything else routes through [`map_io_error`].
fn map_set_len_error(e: &io::Error) -> NativeFilesystemError {
    #[cfg(unix)]
    let is_disk_full = e.raw_os_error() == Some(libc::ENOSPC);
    #[cfg(windows)]
    let is_disk_full = e.raw_os_error() == Some(112); // ERROR_DISK_FULL
    #[cfg(not(any(unix, windows)))]
    let is_disk_full = false;

    if is_disk_full {
        NativeFilesystemError::DiskFull
    } else {
        map_io_error(e)
    }
}

fn metadata_from_std(m: &fs::Metadata) -> NativeMetadata {
    NativeMetadata {
        is_dir: m.is_dir(),
        is_readonly: is_readonly_std(m),
        size: m.len(),
        created: m.created().ok(),
        accessed: m.accessed().ok(),
        modified: m.modified().ok(),
    }
}

#[cfg(windows)]
fn is_readonly_std(m: &fs::Metadata) -> bool {
    m.permissions().readonly()
}

#[cfg(unix)]
fn is_readonly_std(m: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // Owner-write bit clear → readonly.  Mirrors `fs_info::is_readonly`.
    m.permissions().mode() & 0o200 == 0
}

#[cfg(not(any(unix, windows)))]
fn is_readonly_std(m: &fs::Metadata) -> bool {
    m.permissions().readonly()
}

/// Translate [`OpenOptions`] back to the raw u32 triple consumed by
/// [`crate::create::open_file`].  This shim exists only because step 3 hasn't
/// yet reshaped `open_file` to accept the typed options directly — once it
/// does, this function disappears.
fn opts_to_raw(opts: OpenOptions) -> (u32, u32, u32) {
    use crate::create::{FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE};
    use justrdp_rdpdr::pdu::irp::{
        FILE_CREATE, FILE_OPEN, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE,
    };

    // DesiredAccess flags (MS-SMB2 2.2.13.1.1)
    const FILE_APPEND_DATA: u32 = 0x0000_0004;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;

    let mut desired_access = match opts.access {
        OpenAccess::Read => GENERIC_READ,
        OpenAccess::Write => GENERIC_WRITE,
        OpenAccess::ReadWrite => GENERIC_READ | GENERIC_WRITE,
    };
    if opts.append {
        desired_access |= FILE_APPEND_DATA;
    }

    let create_disposition = match opts.disposition {
        OpenDisposition::Open => FILE_OPEN,
        OpenDisposition::Create => FILE_CREATE,
        OpenDisposition::OpenIf => FILE_OPEN_IF,
        OpenDisposition::Overwrite => FILE_OVERWRITE,
        OpenDisposition::OverwriteIf => FILE_OVERWRITE_IF,
        OpenDisposition::Supersede => FILE_SUPERSEDE,
    };

    let create_options = match opts.kind {
        OpenKind::File => FILE_NON_DIRECTORY_FILE,
        OpenKind::Directory => FILE_DIRECTORY_FILE,
    };

    (desired_access, create_disposition, create_options)
}

fn information_to_outcome(info: u8) -> OpenOutcome {
    match info {
        FILE_OPENED => OpenOutcome::Opened,
        FILE_CREATED => OpenOutcome::Created,
        FILE_OVERWRITTEN => OpenOutcome::Overwritten,
        FILE_SUPERSEDED => OpenOutcome::Superseded,
        // `open_file` only emits the four values above; this arm is
        // unreachable, but pattern exhaustiveness on `u8` requires a
        // catch-all.
        _ => OpenOutcome::Opened,
    }
}

fn file_times_to_basic_info(times: FileTimes) -> BasicInfoSet {
    BasicInfoSet {
        creation_time: time_to_filetime_or_zero(times.creation),
        last_access_time: time_to_filetime_or_zero(times.access),
        last_write_time: time_to_filetime_or_zero(times.write),
        // FILE_BASIC_INFORMATION carries a ChangeTime field, but neither
        // `futimens` (Unix) nor `SetFileTime` (Windows) accepts a separate
        // change time, so it's always 0 here ("don't change").
        change_time: 0,
        file_attributes: 0,
    }
}

fn time_to_filetime_or_zero(t: Option<SystemTime>) -> i64 {
    match t {
        Some(time) => system_time_to_filetime(time),
        None => 0, // 0 = "don't change" in FILETIME convention used by `set_file_times`
    }
}
