//! Production [`FilesystemSurface`] adapter — `std::fs` plus four small
//! platform-FFI helpers (`lock_file` / `unlock_file`, `set_file_times`,
//! `rename_exclusive`, `wait_for_directory_change`) inlined in this module.
//!
//! All platform-specific (`#[cfg(...)]`) code in this crate lives here —
//! the wrapper [`crate::NativeFilesystemBackend`] is platform-neutral.
//! When a future port adds support for a new OS, only this file needs
//! per-target arms; nothing in lib.rs / fs_info.rs / dir_info.rs
//! changes.

#![allow(unsafe_code)]

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
            rename_exclusive(from, to)
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
                metadata: NativeMetadata::from_std(&metadata),
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
            .map(|m| NativeMetadata::from_std(&m))
            .map_err(|e| map_io_error(&e))
    }

    fn set_times(
        &mut self,
        handle: &mut Self::Handle,
        times: FileTimes,
    ) -> NativeFilesystemResult<()> {
        let info = file_times_to_basic_info(times);
        set_file_times(handle, &info);
        Ok(())
    }

    fn lock(
        &mut self,
        handle: &mut Self::Handle,
        range: LockRange,
        mode: LockMode,
    ) -> NativeFilesystemResult<()> {
        lock_file(
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
        unlock_file(handle, range.offset, range.length).map_err(|e| map_io_error(&e))
    }

    fn watch(&self, path: &Path) -> NativeFilesystemResult<String> {
        wait_for_directory_change(path).map_err(|e| map_io_error(&e))
    }
}

// ── Error mapping ─────────────────────────────────────────────────────────

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

// ── Open-options translation ──────────────────────────────────────────────

/// Translate [`OpenOptions`] back to the raw u32 triple consumed by
/// [`crate::create::open_file`].  This shim straddles the typed surface API
/// and the legacy `create::open_file` that still parses raw flag values
/// internally — folding the two would mean rewriting the disposition
/// dispatch, deferred to a future cleanup.
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
        // Lenient — neither bit set, matches "no kind preference" callers.
        OpenKind::File => 0,
        OpenKind::FileStrict => FILE_NON_DIRECTORY_FILE,
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

// ── Directory change notification ─────────────────────────────────────────

/// Block until a change is detected in the given directory.
/// Returns the name of the first changed file/entry, or "." if unknown.
#[cfg(target_os = "macos")]
fn wait_for_directory_change(dir: &Path) -> io::Result<String> {
    use std::os::unix::io::AsRawFd;

    let dir_file = fs::File::open(dir)?;
    let fd = dir_file.as_raw_fd();

    // SAFETY: Creating a kqueue file descriptor. Returns -1 on failure.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(io::Error::last_os_error());
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
        libc::kevent(kq, &changelist, 1, &mut eventlist, 1, &timeout)
    };

    // SAFETY: Closing the kqueue fd.
    unsafe {
        libc::close(kq);
    }

    if nev < 0 {
        return Err(io::Error::last_os_error());
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
fn wait_for_directory_change(dir: &Path) -> io::Result<String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?;

    // SAFETY: Creating an inotify instance.
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if inotify_fd < 0 {
        return Err(io::Error::last_os_error());
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
        unsafe {
            libc::close(inotify_fd);
        }
        return Err(io::Error::last_os_error());
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
        return Err(io::Error::last_os_error());
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
        return Err(io::Error::last_os_error());
    }

    // Parse the first inotify_event to extract the filename.
    // NOTE: Only the first event is parsed. If the kernel batches multiple events
    // into a single read() call (standard inotify behavior), subsequent events are
    // ignored. This is acceptable because we only need one change name as a hint.
    // Use read_unaligned because buf is a [u8] array with 1-byte alignment,
    // but inotify_event has 4-byte aligned fields.
    if n as usize >= std::mem::size_of::<libc::inotify_event>() {
        let event = unsafe {
            std::ptr::read_unaligned(buf.as_ptr() as *const libc::inotify_event)
        };
        if event.len > 0 {
            let name_start = std::mem::size_of::<libc::inotify_event>();
            let name_end = match name_start.checked_add(event.len as usize) {
                Some(end) => end,
                None => return Ok(".".to_string()),
            };
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
fn wait_for_directory_change(dir: &Path) -> io::Result<String> {
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
        return Err(io::Error::last_os_error());
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
        0 => Ok(".".to_string()),     // WAIT_OBJECT_0 — change detected
        0x102 => Ok(".".to_string()), // WAIT_TIMEOUT
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn wait_for_directory_change(_dir: &Path) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory change notification not supported on this platform",
    ))
}

// ── Atomic rename (no-replace) ────────────────────────────────────────────

/// Convert a `Path` to a `CString` for FFI calls on Unix.
#[cfg(unix)]
fn path_to_cstring(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))
}

/// Rename a file/directory atomically, failing if the destination exists.
///
/// Uses platform-specific APIs to avoid TOCTOU race between an existence
/// check and the rename operation.
#[cfg(target_os = "linux")]
fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let from_c = path_to_cstring(from)?;
    let to_c = path_to_cstring(to)?;

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
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let from_c = path_to_cstring(from)?;
    let to_c = path_to_cstring(to)?;

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
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
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
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn rename_exclusive(_from: &Path, _to: &Path) -> io::Result<()> {
    // No atomic rename-exclusive available on this platform.
    // Return Unsupported rather than silently degrading to a racy check+rename.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic rename-exclusive not supported on this platform",
    ))
}

// ── File timestamp setting ────────────────────────────────────────────────

/// Set file timestamps from a FILE_BASIC_INFORMATION structure.
///
/// Timestamps with value 0 or -1 are skipped (meaning "don't change").
/// Uses `futimens` on the open fd to avoid rename-race issues with path-based APIs.
#[cfg(unix)]
fn set_file_times(file: &fs::File, info: &BasicInfoSet) {
    use std::os::unix::io::AsRawFd;

    let access_time = filetime_to_timespec(info.last_access_time);
    let mod_time = filetime_to_timespec(info.last_write_time);

    let times = [access_time, mod_time];

    // SAFETY: fd is a valid open file descriptor, times is a valid [timespec; 2].
    unsafe {
        libc::futimens(file.as_raw_fd(), times.as_ptr());
    }
}

#[cfg(unix)]
fn filetime_to_timespec(filetime: i64) -> libc::timespec {
    use crate::fs_info::FILETIME_UNIX_EPOCH_OFFSET;

    // 0 = don't change, -1 = don't update on subsequent ops
    if filetime <= 0 {
        return libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        };
    }

    let relative = filetime - FILETIME_UNIX_EPOCH_OFFSET;

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

    libc::timespec {
        tv_sec: secs as libc::time_t,
        tv_nsec: nsecs as libc::c_long,
    }
}

#[cfg(windows)]
fn set_file_times(file: &fs::File, info: &BasicInfoSet) {
    use std::os::windows::io::AsRawHandle;

    let creation = filetime_or_null(info.creation_time);
    let access = filetime_or_null(info.last_access_time);
    let write = filetime_or_null(info.last_write_time);

    // SAFETY: file handle is valid, FILETIME pointers are valid or null.
    // Using the open file handle directly avoids rename-race issues.
    unsafe {
        windows_sys::Win32::Storage::FileSystem::SetFileTime(
            file.as_raw_handle() as _,
            creation.as_ref().map_or(std::ptr::null(), |ft| ft),
            access.as_ref().map_or(std::ptr::null(), |ft| ft),
            write.as_ref().map_or(std::ptr::null(), |ft| ft),
        );
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
fn set_file_times(_file: &fs::File, _info: &BasicInfoSet) {
    // No platform API available — accept silently.
}

// ── File locking ──────────────────────────────────────────────────────────

#[cfg(unix)]
fn lock_file(
    file: &fs::File,
    offset: u64,
    length: u64,
    shared: bool,
    fail_immediately: bool,
) -> io::Result<()> {
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
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_file(file: &fs::File, offset: u64, length: u64) -> io::Result<()> {
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
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_file(
    file: &fs::File,
    offset: u64,
    length: u64,
    shared: bool,
    fail_immediately: bool,
) -> io::Result<()> {
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
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn unlock_file(file: &fs::File, offset: u64, length: u64) -> io::Result<()> {
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
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(unix, windows)))]
fn lock_file(
    _file: &fs::File,
    _offset: u64,
    _length: u64,
    _shared: bool,
    _fail_immediately: bool,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file locking not supported on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
fn unlock_file(_file: &fs::File, _offset: u64, _length: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file locking not supported on this platform",
    ))
}
