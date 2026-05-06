//! Platform-facing clipboard surface — the seam between `NativeClipboard`
//! (which speaks MS-RDPECLIP) and the platform-specific adapters
//! (which speak the host OS clipboard API).
//!
//! See `CONTEXT.md` for the **Native surface** role.

use std::fmt;

/// Errors a clipboard Native surface can report.
#[derive(Debug)]
pub enum NativeClipboardError {
    /// OS clipboard is currently locked by another process.
    Locked,
    /// The requested format ID is not currently held by the OS clipboard.
    FormatNotAvailable(u32),
    /// An OS-level API call failed; the message is platform-specific.
    OsApi(String),
    /// Bytes from the OS could not be re-encoded into RDP-canonical form.
    Encoding(String),
}

impl fmt::Display for NativeClipboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("OS clipboard is locked"),
            Self::FormatNotAvailable(id) => write!(f, "format id {id:#x} not available"),
            Self::OsApi(msg) => write!(f, "OS clipboard API: {msg}"),
            Self::Encoding(msg) => write!(f, "encoding: {msg}"),
        }
    }
}

impl std::error::Error for NativeClipboardError {}

pub type NativeClipboardResult<T> = Result<T, NativeClipboardError>;

/// The platform-facing clipboard surface.
///
/// Implementors are platform-specific adapters (Windows / X11 / Wayland /
/// macOS). They speak only platform-level vocabulary: format IDs and
/// RDP-canonical byte payloads. The surrounding `NativeClipboard` wrapper
/// is the sole consumer; it converts between MS-RDPECLIP protocol types
/// (`LongFormatName`, `FormatListResponse`, `FileContentsRequestPdu`) and
/// this surface.
///
/// # Byte encoding
///
/// `read_all` returns bytes already in **RDP-canonical encoding** for the
/// given `format_id`:
///
/// - `CF_TEXT`: null-terminated ANSI / Latin-1
/// - `CF_UNICODETEXT`: null-terminated UTF-16LE
/// - `CF_DIB`: a BITMAPINFOHEADER + optional color table + pixel data,
///   *without* the 14-byte BITMAPFILEHEADER
/// - other formats: bytes exactly as the protocol expects them
///
/// `write_formats` accepts bytes in the same shape.
///
/// # Snapshot semantics
///
/// `NativeClipboard` calls `read_all` at most once per RDP format-list
/// cycle and caches the result. Implementors may treat `read_all` as an
/// expensive operation (e.g. a single `OpenClipboard` / `CloseClipboard`
/// pair on Windows).
pub trait NativeClipboardSurface: Send {
    /// Return the format IDs currently available on the OS clipboard.
    fn list_formats(&mut self) -> NativeClipboardResult<Vec<u32>>;

    /// Read every available format from the OS clipboard.
    ///
    /// The returned pairs are in no particular order. The caller treats
    /// the result as a snapshot for the current format-list cycle.
    fn read_all(&mut self) -> NativeClipboardResult<Vec<(u32, Vec<u8>)>>;

    /// Write all the given formats to the OS clipboard, replacing any
    /// existing content.
    fn write_formats(
        &mut self,
        entries: &[(u32, Vec<u8>)],
    ) -> NativeClipboardResult<()>;
}

/// File metadata as the **Native surface** sees it.
///
/// `NativeClipboard` converts this into MS-FSCC `FILE_DESCRIPTORW` for
/// transmission inside a `FileContentsResponsePdu`.
#[derive(Debug, Clone)]
pub struct NativeFileMeta {
    /// File name relative to the clipboard's drag root. UTF-8.
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// Last-modified Unix timestamp, if known.
    pub modified_unix: Option<i64>,
    /// RDP file-attribute bitfield (MS-FSCC §2.6 `FILE_ATTRIBUTE_*`).
    pub rdp_attributes: u32,
}

/// Optional supertrait for clipboard surfaces that can transfer files.
///
/// Implement this when the host OS clipboard exposes a file-list payload
/// (Windows `CFSTR_FILECONTENTS`, macOS file URL pasteboard items). X11
/// and Wayland generally cannot expose byte-range streaming and should not
/// implement this trait — `NativeClipboard` will then reject file-contents
/// requests by default.
pub trait NativeClipboardFiles: NativeClipboardSurface {
    /// Number of files available for byte-range streaming.
    fn file_count(&mut self) -> NativeClipboardResult<u32>;

    /// Metadata for the file at `index` (zero-based).
    fn file_metadata(&mut self, index: u32) -> NativeClipboardResult<NativeFileMeta>;

    /// Read up to `len` bytes starting at `offset` from the file at `index`.
    /// Implementors may return fewer than `len` bytes only at end-of-file.
    fn file_chunk(
        &mut self,
        index: u32,
        offset: u64,
        len: u32,
    ) -> NativeClipboardResult<Vec<u8>>;
}
