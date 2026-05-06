#![deny(unsafe_code)]

//! Native OS clipboard backend for Clipboard Redirection (MS-RDPECLIP).
//!
//! Provides [`NativeClipboard`] — a `CliprdrBackend` that delegates platform
//! clipboard work to a pluggable [`NativeClipboardSurface`]. The default
//! constructor selects the platform's bundled surface; tests and embedders
//! may pass a custom surface via [`NativeClipboard::with_surface`].
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
pub mod surface;

pub use surface::{
    NativeClipboardError, NativeClipboardFiles, NativeClipboardResult,
    NativeClipboardSurface, NativeFileMeta,
};

#[cfg(target_os = "windows")]
mod windows;

#[cfg(all(target_os = "linux", feature = "x11"))]
mod x11;

#[cfg(all(target_os = "linux", feature = "wayland"))]
mod wayland;

// macOS backend uses unsafe for GCD dispatch and NSBitmapImageRep FFI calls.
#[cfg(target_os = "macos")]
mod macos;

use justrdp_cliprdr::pdu::LongFormatName;
use justrdp_cliprdr::{
    CliprdrBackend, ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse,
};

use crate::common::{
    accept_supported_format_list, is_image_format, is_text_format, looks_like_dib,
    rdp_bytes_to_utf8, utf8_to_rdp, CF_DIB,
};

// ── Default platform surface ───────────────────────────────────────────────

/// The platform-specific clipboard surface bundled with this build.
///
/// `NativeClipboard::new()` returns `NativeClipboard<PlatformClipboard>`
/// without further annotation.
#[cfg(target_os = "windows")]
pub type PlatformClipboard = windows::WindowsClipboard;

#[cfg(all(target_os = "linux", feature = "wayland"))]
pub type PlatformClipboard = wayland::WaylandClipboard;

#[cfg(all(target_os = "linux", feature = "x11", not(feature = "wayland")))]
pub type PlatformClipboard = x11::X11Clipboard;

#[cfg(target_os = "macos")]
pub type PlatformClipboard = macos::MacosClipboard;

#[cfg(not(any(
    target_os = "windows",
    all(target_os = "linux", any(feature = "x11", feature = "wayland")),
    target_os = "macos",
)))]
compile_error!(
    "justrdp-cliprdr-native requires one of: Windows, Linux (with feature 'x11' or 'wayland'), or macOS"
);

// ── NativeClipboard wrapper ────────────────────────────────────────────────

/// `CliprdrBackend` adapter that delegates platform clipboard work to a
/// pluggable [`NativeClipboardSurface`].
///
/// The wrapper owns all MS-RDPECLIP encoding (UTF-16LE / DIB framing),
/// format-ID dispatch, and the on-format-data-response heuristic that picks
/// image-vs-text when the server omits the negotiated format ID. The
/// surface only ever sees UTF-8 strings and DIB byte arrays.
///
/// The default type parameter binds `S` to the platform's bundled
/// [`PlatformClipboard`] so existing callers (`NativeClipboard::new()`)
/// require no annotations.
pub struct NativeClipboard<S: NativeClipboardSurface = PlatformClipboard> {
    surface: S,
}

impl NativeClipboard<PlatformClipboard> {
    /// Create with the platform's default clipboard surface.
    pub fn new() -> Result<Self, ClipboardError> {
        let surface = PlatformClipboard::new()?;
        Ok(Self { surface })
    }
}

impl<S: NativeClipboardSurface> NativeClipboard<S> {
    /// Create with a custom clipboard surface — primarily for tests and
    /// embedders that provide their own platform binding.
    pub fn with_surface(surface: S) -> Self {
        Self { surface }
    }

    /// Borrow the underlying surface immutably.
    pub fn surface(&self) -> &S {
        &self.surface
    }

    /// Borrow the underlying surface mutably.
    pub fn surface_mut(&mut self) -> &mut S {
        &mut self.surface
    }
}

impl<S: NativeClipboardSurface> std::fmt::Debug for NativeClipboard<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeClipboard").finish()
    }
}

fn map_surface_err(e: NativeClipboardError) -> ClipboardError {
    match e {
        NativeClipboardError::Locked => ClipboardError::Failed,
        NativeClipboardError::OsApi(msg) | NativeClipboardError::Encoding(msg) => {
            ClipboardError::Other(msg)
        }
    }
}

impl<S: NativeClipboardSurface> CliprdrBackend for NativeClipboard<S> {
    fn on_format_list(
        &mut self,
        formats: &[LongFormatName],
    ) -> ClipboardResult<FormatListResponse> {
        accept_supported_format_list(formats)
    }

    fn on_format_data_request(
        &mut self,
        format_id: u32,
    ) -> ClipboardResult<FormatDataResponse> {
        if is_text_format(format_id) {
            return match self.surface.read_text() {
                Ok(Some(text)) => match utf8_to_rdp(&text, format_id) {
                    Some(bytes) => Ok(FormatDataResponse::Ok(bytes)),
                    None => Ok(FormatDataResponse::Fail),
                },
                Ok(None) => Ok(FormatDataResponse::Fail),
                Err(e) => Err(map_surface_err(e)),
            };
        }

        if is_image_format(format_id) {
            return match self.surface.read_image() {
                Ok(Some(dib)) => Ok(FormatDataResponse::Ok(dib)),
                Ok(None) => Ok(FormatDataResponse::Fail),
                Err(e) => Err(map_surface_err(e)),
            };
        }

        Ok(FormatDataResponse::Fail)
    }

    fn on_format_data_response(
        &mut self,
        data: &[u8],
        is_success: bool,
        format_id: Option<u32>,
    ) {
        if !is_success {
            return;
        }

        // Image path: explicit CF_DIB OR no negotiated format and DIB-shaped bytes.
        if format_id == Some(CF_DIB) || (format_id.is_none() && looks_like_dib(data)) {
            let _ = self.surface.write_image(data);
            return;
        }

        // Text path: decode RDP-canonical bytes (auto-detect even-/odd-length).
        if let Some(text) = rdp_bytes_to_utf8(data) {
            let _ = self.surface.write_text(&text);
        }
    }

    // on_file_contents_request / response, on_lock / unlock use trait defaults
    // (reject / no-op). A future `NativeClipboardWithFiles` wrapper variant
    // will override these for surfaces that implement `NativeClipboardFiles`.
}

#[cfg(test)]
mod wrapper_tests {
    use super::*;
    use crate::common::{CF_DIB, CF_TEXT, CF_UNICODETEXT};
    use justrdp_cliprdr::pdu::LongFormatName;
    use std::cell::RefCell;

    /// In-memory mock surface for wrapper unit tests.
    #[derive(Default)]
    struct MockSurface {
        text: Option<String>,
        image: Option<Vec<u8>>,
        text_writes: RefCell<Vec<String>>,
        image_writes: RefCell<Vec<Vec<u8>>>,
        next_read_err: RefCell<Option<NativeClipboardError>>,
    }

    impl MockSurface {
        fn with_text(text: &str) -> Self {
            let mut m = Self::default();
            m.text = Some(text.to_string());
            m
        }

        fn with_image(dib: Vec<u8>) -> Self {
            let mut m = Self::default();
            m.image = Some(dib);
            m
        }
    }

    impl NativeClipboardSurface for MockSurface {
        fn read_text(&mut self) -> NativeClipboardResult<Option<String>> {
            if let Some(e) = self.next_read_err.borrow_mut().take() {
                return Err(e);
            }
            Ok(self.text.clone())
        }

        fn write_text(&mut self, text: &str) -> NativeClipboardResult<()> {
            self.text_writes.borrow_mut().push(text.to_string());
            Ok(())
        }

        fn read_image(&mut self) -> NativeClipboardResult<Option<Vec<u8>>> {
            if let Some(e) = self.next_read_err.borrow_mut().take() {
                return Err(e);
            }
            Ok(self.image.clone())
        }

        fn write_image(&mut self, dib: &[u8]) -> NativeClipboardResult<()> {
            self.image_writes.borrow_mut().push(dib.to_vec());
            Ok(())
        }
    }

    fn long_name(format_id: u32) -> LongFormatName {
        LongFormatName {
            format_id,
            format_name: String::new(),
        }
    }

    #[test]
    fn format_list_with_supported_format_accepted() {
        let mut nc = NativeClipboard::with_surface(MockSurface::default());
        let resp = nc.on_format_list(&[long_name(CF_UNICODETEXT)]).unwrap();
        assert_eq!(resp, FormatListResponse::Ok);
    }

    #[test]
    fn format_list_unsupported_only_rejected() {
        let mut nc = NativeClipboard::with_surface(MockSurface::default());
        let resp = nc.on_format_list(&[long_name(0x9999)]).unwrap();
        assert_eq!(resp, FormatListResponse::Fail);
    }

    #[test]
    fn data_request_unicode_text_encodes_to_utf16le() {
        let mut nc = NativeClipboard::with_surface(MockSurface::with_text("Hi"));
        let resp = nc.on_format_data_request(CF_UNICODETEXT).unwrap();
        match resp {
            FormatDataResponse::Ok(bytes) => {
                // "Hi" UTF-16LE + null
                assert_eq!(bytes, vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00]);
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn data_request_text_when_clipboard_empty_fails() {
        let mut nc = NativeClipboard::with_surface(MockSurface::default());
        let resp = nc.on_format_data_request(CF_UNICODETEXT).unwrap();
        assert!(matches!(resp, FormatDataResponse::Fail));
    }

    #[test]
    fn data_request_image_passes_through_dib() {
        let dib = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut nc = NativeClipboard::with_surface(MockSurface::with_image(dib.clone()));
        let resp = nc.on_format_data_request(CF_DIB).unwrap();
        match resp {
            FormatDataResponse::Ok(bytes) => assert_eq!(bytes, dib),
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn data_request_unknown_format_fails() {
        let mut nc = NativeClipboard::with_surface(MockSurface::default());
        let resp = nc.on_format_data_request(0x9999).unwrap();
        assert!(matches!(resp, FormatDataResponse::Fail));
    }

    #[test]
    fn data_request_os_error_propagates_as_other() {
        let surface = MockSurface::default();
        *surface.next_read_err.borrow_mut() =
            Some(NativeClipboardError::OsApi("io-fail".to_string()));
        let mut nc = NativeClipboard::with_surface(surface);
        let result = nc.on_format_data_request(CF_UNICODETEXT);
        assert!(matches!(result, Err(ClipboardError::Other(_))));
    }

    #[test]
    fn data_response_unicode_text_writes_decoded_to_surface() {
        let mut nc = NativeClipboard::with_surface(MockSurface::default());
        // "Hi" in UTF-16LE + null
        let data = [0x48u8, 0x00, 0x69, 0x00, 0x00, 0x00];
        nc.on_format_data_response(&data, true, Some(CF_UNICODETEXT));
        let writes = nc.surface().text_writes.borrow();
        assert_eq!(*writes, vec!["Hi".to_string()]);
    }

    #[test]
    fn data_response_explicit_dib_writes_image() {
        let mut nc = NativeClipboard::with_surface(MockSurface::default());
        // Minimal valid DIB header (40 bytes BITMAPINFOHEADER + 4 pixel)
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&24u16.to_le_bytes());
        dib.extend_from_slice(&[0u8; 20]);
        dib.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);

        nc.on_format_data_response(&dib, true, Some(CF_DIB));
        let writes = nc.surface().image_writes.borrow();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0], dib);
    }

    #[test]
    fn data_response_no_format_id_dib_shape_writes_image() {
        let mut nc = NativeClipboard::with_surface(MockSurface::default());
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&24u16.to_le_bytes());
        dib.extend_from_slice(&[0u8; 20]);
        dib.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);

        nc.on_format_data_response(&dib, true, None);
        let writes = nc.surface().image_writes.borrow();
        assert_eq!(writes.len(), 1);
    }

    #[test]
    fn data_response_no_format_id_text_shape_writes_text() {
        let mut nc = NativeClipboard::with_surface(MockSurface::default());
        // "Hi" UTF-16LE — even-length, decodes via rdp_bytes_to_utf8
        let data = [0x48u8, 0x00, 0x69, 0x00];
        nc.on_format_data_response(&data, true, None);
        let writes = nc.surface().text_writes.borrow();
        assert_eq!(*writes, vec!["Hi".to_string()]);
    }

    #[test]
    fn data_response_failure_writes_nothing() {
        let mut nc = NativeClipboard::with_surface(MockSurface::default());
        let data = [0x48u8, 0x00, 0x69, 0x00];
        nc.on_format_data_response(&data, false, Some(CF_UNICODETEXT));
        assert!(nc.surface().text_writes.borrow().is_empty());
        assert!(nc.surface().image_writes.borrow().is_empty());
    }

    #[test]
    fn data_request_text_skips_unsupported_text_id() {
        // CF_TEXT (1) is supported and goes through text path.
        let mut nc = NativeClipboard::with_surface(MockSurface::with_text("Hi"));
        let resp = nc.on_format_data_request(CF_TEXT).unwrap();
        match resp {
            FormatDataResponse::Ok(bytes) => {
                // CF_TEXT = ASCII + null
                assert_eq!(bytes, vec![b'H', b'i', 0]);
            }
            _ => panic!("expected Ok"),
        }
    }
}
