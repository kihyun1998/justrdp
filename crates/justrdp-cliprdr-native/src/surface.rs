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
    /// An OS-level API call failed; the message is platform-specific.
    OsApi(String),
    /// Bytes from the OS could not be re-encoded into RDP-canonical form.
    Encoding(String),
}

impl fmt::Display for NativeClipboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("OS clipboard is locked"),
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
/// macOS). They speak only platform-level vocabulary — UTF-8 text,
/// device-independent-bitmap byte arrays — and never see MS-RDPECLIP types
/// (`LongFormatName`, `FormatListResponse`, `FileContentsRequestPdu`). The
/// surrounding `NativeClipboard` wrapper is the sole consumer; it owns all
/// RDP-protocol encoding and format-ID dispatch.
///
/// # Available formats
///
/// Implementors expose two content kinds:
///
/// - **Text** as UTF-8 `String`s. The wrapper maps these to RDP `CF_TEXT`
///   or `CF_UNICODETEXT` as the protocol negotiation requires.
/// - **Image** as DIB bytes (BITMAPINFOHEADER + optional color table +
///   pixel data, *without* the 14-byte BITMAPFILEHEADER). The wrapper maps
///   these to RDP `CF_DIB`.
///
/// `read_*` returns `Ok(None)` when the OS clipboard does not currently
/// carry that content kind. Reserve `Err(_)` for genuine OS-level failures.
pub trait NativeClipboardSurface: Send {
    /// Read text from the OS clipboard, if available.
    fn read_text(&mut self) -> NativeClipboardResult<Option<String>>;

    /// Write text to the OS clipboard, replacing any existing content.
    fn write_text(&mut self, text: &str) -> NativeClipboardResult<()>;

    /// Read an image from the OS clipboard as DIB bytes, if available.
    fn read_image(&mut self) -> NativeClipboardResult<Option<Vec<u8>>>;

    /// Write an image (as DIB bytes) to the OS clipboard, replacing any
    /// existing content.
    fn write_image(&mut self, dib: &[u8]) -> NativeClipboardResult<()>;
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
/// (Windows `CFSTR_FILECONTENTS`, macOS file URL pasteboard items). X11 and
/// Wayland generally cannot expose byte-range streaming and should not
/// implement this trait.
///
/// **No wrapper currently delegates to this trait** — `NativeClipboard`
/// rejects file-contents requests by default. A future
/// `NativeClipboardWithFiles` wrapper variant will land alongside the first
/// concrete file-capable implementation.
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
