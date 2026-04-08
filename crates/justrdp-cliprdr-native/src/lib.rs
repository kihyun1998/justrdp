#![deny(unsafe_code)]

//! Native OS clipboard backend for Clipboard Redirection (MS-RDPECLIP).
//!
//! Provides [`NativeClipboard`] which implements [`CliprdrBackend`] using
//! the host OS's native clipboard API.
//!
//! # Platform Support
//!
//! - **Windows**: Win32 Clipboard API via `clipboard-win`
//! - **Linux** (feature `x11`): X11 Selection via `x11-clipboard`
//! - **Linux** (feature `wayland`): Wayland data-device via `wl-clipboard-rs`
//! - **macOS**: NSPasteboard via `objc2`
//!
//! # Example
//!
//! ```ignore
//! use justrdp_cliprdr::CliprdrClient;
//! use justrdp_cliprdr_native::NativeClipboard;
//!
//! let clipboard = NativeClipboard::new().expect("clipboard init");
//! let cliprdr = CliprdrClient::new(Box::new(clipboard));
//! ```

mod common;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(all(target_os = "linux", feature = "x11"))]
mod x11;

#[cfg(all(target_os = "linux", feature = "wayland"))]
mod wayland;

// macOS backend uses unsafe for NSData::getBytes_length and
// NSBitmapImageRep::representationUsingType_properties FFI calls.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;

use justrdp_cliprdr::pdu::{FileContentsRequestPdu, FileContentsResponsePdu, LongFormatName};
use justrdp_cliprdr::{CliprdrBackend, ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse};

// ── Platform inner type selection ─────────���────────────────────────────────

#[cfg(target_os = "windows")]
type PlatformClipboard = windows::WindowsClipboard;

#[cfg(all(target_os = "linux", feature = "wayland"))]
type PlatformClipboard = wayland::WaylandClipboard;

#[cfg(all(target_os = "linux", feature = "x11", not(feature = "wayland")))]
type PlatformClipboard = x11::X11Clipboard;

#[cfg(target_os = "macos")]
type PlatformClipboard = macos::MacosClipboard;

// Fallback: unsupported platform
#[cfg(not(any(
    target_os = "windows",
    all(target_os = "linux", any(feature = "x11", feature = "wayland")),
    target_os = "macos",
)))]
compile_error!(
    "justrdp-cliprdr-native requires one of: Windows, Linux (with feature 'x11' or 'wayland'), or macOS"
);

// ── NativeClipboard ──────────────────��─────────────────────────────────────

/// Native OS clipboard backend.
///
/// Wraps the platform-specific clipboard implementation and delegates
/// all [`CliprdrBackend`] calls to it.
pub struct NativeClipboard {
    inner: PlatformClipboard,
}

impl NativeClipboard {
    /// Create a new native clipboard backend.
    ///
    /// On Linux, the Wayland backend is preferred when the `wayland` feature
    /// is enabled; otherwise the X11 backend is used.
    pub fn new() -> Result<Self, ClipboardError> {
        let inner = PlatformClipboard::new()?;
        Ok(Self { inner })
    }
}

impl std::fmt::Debug for NativeClipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeClipboard").finish()
    }
}

impl CliprdrBackend for NativeClipboard {
    fn on_format_list(&mut self, formats: &[LongFormatName]) -> ClipboardResult<FormatListResponse> {
        self.inner.on_format_list(formats)
    }

    fn on_format_data_request(&mut self, format_id: u32) -> ClipboardResult<FormatDataResponse> {
        self.inner.on_format_data_request(format_id)
    }

    fn on_format_data_response(&mut self, data: &[u8], is_success: bool) {
        self.inner.on_format_data_response(data, is_success);
    }

    fn on_file_contents_request(
        &mut self,
        request: &FileContentsRequestPdu,
    ) -> ClipboardResult<FileContentsResponsePdu> {
        self.inner.on_file_contents_request(request)
    }

    fn on_file_contents_response(&mut self, response: &FileContentsResponsePdu) {
        self.inner.on_file_contents_response(response);
    }

    fn on_lock(&mut self, lock_id: u32) {
        self.inner.on_lock(lock_id);
    }

    fn on_unlock(&mut self, lock_id: u32) {
        self.inner.on_unlock(lock_id);
    }
}

#[cfg(test)]
mod tests {
    use super::common::*;

    #[test]
    fn common_roundtrip_unicode() {
        let original = "Hello, clipboard!";
        let rdp = utf8_to_rdp(original, CF_UNICODETEXT).unwrap();
        let back = rdp_to_utf8(&rdp, CF_UNICODETEXT).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn common_roundtrip_text() {
        let original = "ASCII only";
        let rdp = utf8_to_rdp(original, CF_TEXT).unwrap();
        let back = rdp_to_utf8(&rdp, CF_TEXT).unwrap();
        assert_eq!(back, original);
    }
}
