//! Native filesystem surface — the platform-binding seam.
//!
//! Defines [`FilesystemSurface`], the trait that platform-specific filesystem
//! adapters implement.  The trait is **content-typed** (not RDP-format-typed):
//! adapters speak only filesystem-level vocabulary — file handles, byte offsets,
//! [`SystemTime`], path strings — and never see MS-RDPEFS / MS-FSCC wire types
//! such as `FILE_BASIC_INFORMATION`, NTSTATUS codes, or FILETIME (i64) values.
//!
//! This mirrors the [`NativeClipboardSurface`] pattern in `justrdp-cliprdr-native`
//! (see ADR-0006).  The wrapper [`crate::NativeFilesystemBackend`] owns all
//! protocol-level state — IRP dispatch, NTSTATUS mapping, glob pattern matching,
//! directory cursor — and forwards filesystem-level work to the surface.
//!
//! Two adapters exist:
//! - [`crate::StdFilesystem`] — production adapter over `std::fs` plus four
//!   small platform-FFI helpers (`lock_file`, `set_file_times`,
//!   `rename_exclusive`, `wait_for_directory_change`).
//! - `MockFilesystem` (test-only) — used by the wrapper unit tests to exercise
//!   protocol logic without touching the real filesystem.
//!
//! [`NativeClipboardSurface`]: https://docs.rs/justrdp-cliprdr-native

use std::path::Path;
use std::time::SystemTime;

pub use crate::volume_info::DiskSpace;

// ── Errors ─────────────────────────────────────────────────────────────────

/// Errors emitted by a [`FilesystemSurface`].
///
/// Variants correspond to filesystem-level error categories the wrapper needs
/// to distinguish for NTSTATUS mapping.  Adapters should classify OS errors
/// into one of these variants where possible, falling back to
/// [`NativeFilesystemError::OsApi`] for unclassified errors.
#[derive(Debug, Clone)]
pub enum NativeFilesystemError {
    /// Path or handle does not refer to an existing entry.
    NotFound,
    /// Target already exists (e.g., `FILE_CREATE` against an existing file,
    /// `rename` with `replace=false` to an existing destination).
    AlreadyExists,
    /// Permission denied at the OS level.
    AccessDenied,
    /// No space left on device (e.g., `set_len` past quota, `write` to full disk).
    DiskFull,
    /// Operation requires a directory but the target is a regular file (or
    /// vice versa).
    NotADirectory,
    /// Lock could not be acquired (only emitted by `lock` when
    /// `fail_immediately` is set).
    Locked,
    /// Operation is not implemented on the current platform (e.g., directory
    /// change notification on platforms without inotify/kqueue/FindFirstChange).
    Unsupported,
    /// Caller supplied an invalid argument (e.g., negative file length).
    InvalidInput,
    /// Unclassified OS error.  The string carries an adapter-specific
    /// description for diagnostics; the wrapper maps this to
    /// `STATUS_UNSUCCESSFUL`.
    OsApi(String),
}

impl core::fmt::Display for NativeFilesystemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::AlreadyExists => f.write_str("already exists"),
            Self::AccessDenied => f.write_str("access denied"),
            Self::DiskFull => f.write_str("disk full"),
            Self::NotADirectory => f.write_str("not a directory"),
            Self::Locked => f.write_str("locked"),
            Self::Unsupported => f.write_str("unsupported on this platform"),
            Self::InvalidInput => f.write_str("invalid input"),
            Self::OsApi(msg) => write!(f, "OS error: {msg}"),
        }
    }
}

impl std::error::Error for NativeFilesystemError {}

/// Result alias for filesystem-surface operations.
pub type NativeFilesystemResult<T> = Result<T, NativeFilesystemError>;

// ── Open ───────────────────────────────────────────────────────────────────

/// Outcome of a successful [`FilesystemSurface::open`] call.
///
/// Maps 1:1 to MS-RDPEFS `Information` field values (see
/// `create.rs::FILE_OPENED` etc.) — but adapters return this Rust enum, and
/// the wrapper translates to wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenOutcome {
    /// File or directory was created (the path did not exist before).
    Created,
    /// Existing file or directory was opened unmodified.
    Opened,
    /// Existing file was opened and truncated (`FILE_OVERWRITE` /
    /// `FILE_OVERWRITE_IF` semantics).
    Overwritten,
    /// Existing file was replaced (`FILE_SUPERSEDE` semantics).
    Superseded,
}

/// Read/write access flavor requested for an open operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAccess {
    /// Read-only handle.
    Read,
    /// Write-only handle.
    Write,
    /// Read+write handle.
    ReadWrite,
}

/// What the open path is expected to refer to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
}

/// What to do when the target path does or does not already exist.
///
/// Maps 1:1 to MS-SMB2 CreateDisposition values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDisposition {
    /// Open existing only; fail if missing.
    Open,
    /// Create new only; fail if exists.
    Create,
    /// Open if exists, create if missing.
    OpenIf,
    /// Open existing and truncate; fail if missing.
    Overwrite,
    /// Open existing and truncate, or create if missing.
    OverwriteIf,
    /// Replace existing (delete + create), or create if missing.
    Supersede,
}

/// Parameters for [`FilesystemSurface::open`].
#[derive(Debug, Clone, Copy)]
pub struct OpenOptions {
    pub access: OpenAccess,
    pub disposition: OpenDisposition,
    pub kind: OpenKind,
    /// Append mode (writes go to end of file regardless of seek position).
    pub append: bool,
}

/// Successful result of [`FilesystemSurface::open`].
#[derive(Debug)]
pub struct Opened<H> {
    pub handle: H,
    pub outcome: OpenOutcome,
    /// `true` if the opened entry is a directory.  May differ from the
    /// requested [`OpenKind`] when the target turns out to be the opposite
    /// kind — adapters either honor `kind` strictly or report the actual kind.
    pub is_dir: bool,
}

// ── Metadata ───────────────────────────────────────────────────────────────

/// Filesystem-level metadata for a file or directory.
///
/// Adapter-neutral; populated by the surface from `std::fs::Metadata` (real)
/// or from in-memory state (mock).  The wrapper translates this into
/// MS-FSCC wire structures (`FILE_BASIC_INFORMATION`, `FILE_STANDARD_INFORMATION`,
/// directory info classes).
#[derive(Debug, Clone)]
pub struct NativeMetadata {
    pub is_dir: bool,
    pub is_readonly: bool,
    pub size: u64,
    pub created: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub modified: Option<SystemTime>,
}

/// One entry returned by [`FilesystemSurface::read_dir`].
///
/// `name` is the platform filename as a UTF-8 string (lossy-converted from
/// `OsString` if necessary; adapters using non-UTF-8 filesystems should
/// substitute `\u{FFFD}` for invalid bytes).
#[derive(Debug, Clone)]
pub struct NativeDirEntry {
    pub name: String,
    pub metadata: NativeMetadata,
}

// ── File times ─────────────────────────────────────────────────────────────

/// Timestamps to apply via [`FilesystemSurface::set_times`].
///
/// `None` means *don't change*.  The "don't update on subsequent ops"
/// semantic of FILETIME `-1` is folded into `None` here — the surface does
/// not need to distinguish, since both translate to `UTIME_OMIT` /
/// no-op `SetFileTime` slot.
#[derive(Debug, Clone, Copy)]
pub struct FileTimes {
    pub creation: Option<SystemTime>,
    pub access: Option<SystemTime>,
    pub write: Option<SystemTime>,
}

// ── Lock ranges ────────────────────────────────────────────────────────────

/// Byte range to lock or unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockRange {
    pub offset: u64,
    pub length: u64,
}

/// Mode for [`FilesystemSurface::lock`].
#[derive(Debug, Clone, Copy)]
pub struct LockMode {
    /// `true` for exclusive (write) lock; `false` for shared (read) lock.
    pub exclusive: bool,
    /// `true` to fail with [`NativeFilesystemError::Locked`] if the lock
    /// can't be acquired immediately; `false` to block until acquired.
    pub fail_immediately: bool,
}

// ── Trait ──────────────────────────────────────────────────────────────────

/// Platform-binding seam for the rdpdr filesystem backend.
///
/// Implementors expose filesystem operations as content-typed methods.  See
/// the module-level documentation for the rationale.
///
/// All path arguments are already root-resolved and traversal-validated by
/// the wrapper — adapters should treat them as trusted local filesystem
/// paths and just execute.
pub trait FilesystemSurface {
    /// Opaque per-handle resource the adapter associates with each open
    /// file or directory.  For the production adapter this is
    /// `std::fs::File`; for the mock adapter it is an in-memory token.
    type Handle;

    // ── Path-based operations ──────────────────────────────────────────

    /// Open or create a file/directory.  See [`OpenOptions`] and
    /// [`OpenOutcome`].
    fn open(
        &mut self,
        path: &Path,
        opts: OpenOptions,
    ) -> NativeFilesystemResult<Opened<Self::Handle>>;

    /// Atomically rename `from` to `to`.  When `replace` is `false`, fail
    /// with [`NativeFilesystemError::AlreadyExists`] if `to` exists (without
    /// a TOCTOU window).
    fn rename(
        &mut self,
        from: &Path,
        to: &Path,
        replace: bool,
    ) -> NativeFilesystemResult<()>;

    /// Remove a regular file at `path`.
    fn remove_file(&mut self, path: &Path) -> NativeFilesystemResult<()>;

    /// Remove an empty directory at `path`.
    fn remove_dir(&mut self, path: &Path) -> NativeFilesystemResult<()>;

    /// Read the entries of a directory at `path`.
    ///
    /// The returned vector is unordered; the wrapper applies its own glob
    /// filter and ordering.  `.` and `..` are **not** included — the wrapper
    /// synthesizes those entries.
    fn read_dir(&self, path: &Path) -> NativeFilesystemResult<Vec<NativeDirEntry>>;

    /// Query disk usage for the volume containing `path`.
    fn disk_space(&self, path: &Path) -> NativeFilesystemResult<DiskSpace>;

    // ── Handle-based operations ────────────────────────────────────────

    /// Close a handle.  When the wrapper has set the delete-on-close flag
    /// for this handle, it will follow the close with a `remove_file` /
    /// `remove_dir` call against the path it tracked separately — adapters
    /// do **not** observe delete-on-close state.
    fn close(&mut self, handle: Self::Handle) -> NativeFilesystemResult<()>;

    /// Read up to `len` bytes from `handle` starting at `offset`.  Returns
    /// the actual bytes read (may be shorter than `len` at EOF).
    fn read(
        &mut self,
        handle: &mut Self::Handle,
        offset: u64,
        len: usize,
    ) -> NativeFilesystemResult<Vec<u8>>;

    /// Write `data` to `handle` starting at `offset`.  Returns the number
    /// of bytes actually written.
    fn write(
        &mut self,
        handle: &mut Self::Handle,
        offset: u64,
        data: &[u8],
    ) -> NativeFilesystemResult<u32>;

    /// Truncate or extend `handle` to exactly `len` bytes.
    fn set_len(
        &mut self,
        handle: &mut Self::Handle,
        len: u64,
    ) -> NativeFilesystemResult<()>;

    /// Query metadata for `handle`.
    fn metadata(&self, handle: &Self::Handle) -> NativeFilesystemResult<NativeMetadata>;

    /// Set file timestamps via the open handle.  Slots where the
    /// corresponding [`FileTimes`] field is `None` are left unchanged.
    fn set_times(
        &mut self,
        handle: &mut Self::Handle,
        times: FileTimes,
    ) -> NativeFilesystemResult<()>;

    /// Acquire a byte-range lock on `handle`.
    fn lock(
        &mut self,
        handle: &mut Self::Handle,
        range: LockRange,
        mode: LockMode,
    ) -> NativeFilesystemResult<()>;

    /// Release a previously-acquired byte-range lock on `handle`.
    fn unlock(
        &mut self,
        handle: &mut Self::Handle,
        range: LockRange,
    ) -> NativeFilesystemResult<()>;

    /// Block until a change is detected in the directory referenced by
    /// `handle`, returning the changed entry name (or `"."` when the
    /// platform reports a directory-level event without naming the entry).
    /// Implementations should apply a finite timeout and return `"."` when
    /// the timeout elapses without a change.
    fn watch(&self, handle: &Self::Handle) -> NativeFilesystemResult<String>;
}
