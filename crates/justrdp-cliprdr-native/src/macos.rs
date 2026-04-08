//! macOS native clipboard backend using `objc2` + `objc2-app-kit`.
//!
//! Provides text clipboard integration (CF_TEXT, CF_UNICODETEXT) via NSPasteboard.

use objc2_app_kit::NSPasteboard;
use objc2_foundation::NSString;

use justrdp_cliprdr::pdu::{FileContentsRequestPdu, FileContentsResponsePdu, LongFormatName};
use justrdp_cliprdr::{ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse};

use crate::common::{self, is_text_format, rdp_bytes_to_utf8, utf8_to_rdp};

/// UTI for plain text on macOS.
const UTI_PLAIN_TEXT: &str = "public.utf8-plain-text";

/// macOS clipboard backend.
///
/// Uses `NSPasteboard` via the `objc2` crate to read from and write to the
/// local macOS clipboard. Currently supports text formats only.
///
/// **Thread safety**: `NSPasteboard` must be accessed from the main thread.
/// The caller must ensure `NativeClipboard` methods are invoked on the main thread.
pub struct MacosClipboard;

impl MacosClipboard {
    /// Create a new macOS clipboard backend.
    pub fn new() -> Result<Self, ClipboardError> {
        Ok(Self)
    }

    /// Accept the format list if it contains any text format.
    pub fn on_format_list(
        &mut self,
        formats: &[LongFormatName],
    ) -> ClipboardResult<FormatListResponse> {
        common::accept_text_format_list(formats)
    }

    /// Read from the macOS clipboard and encode for the requested format.
    pub fn on_format_data_request(
        &mut self,
        format_id: u32,
    ) -> ClipboardResult<FormatDataResponse> {
        if !is_text_format(format_id) {
            return Ok(FormatDataResponse::Fail);
        }

        let text = read_pasteboard_text().ok_or(ClipboardError::Failed)?;
        let data = utf8_to_rdp(&text, format_id).ok_or(ClipboardError::Failed)?;
        Ok(FormatDataResponse::Ok(data))
    }

    /// Decode server data and write to the macOS clipboard.
    pub fn on_format_data_response(&mut self, data: &[u8], is_success: bool) {
        if !is_success {
            return;
        }
        if let Some(text) = rdp_bytes_to_utf8(data) {
            let _ = write_pasteboard_text(&text);
        }
    }

    pub fn on_file_contents_request(
        &mut self,
        _request: &FileContentsRequestPdu,
    ) -> ClipboardResult<FileContentsResponsePdu> {
        Err(ClipboardError::Other("file transfer not supported".into()))
    }

    pub fn on_file_contents_response(&mut self, _response: &FileContentsResponsePdu) {}

    pub fn on_lock(&mut self, _lock_id: u32) {}

    pub fn on_unlock(&mut self, _lock_id: u32) {}
}

/// Read plain text from the macOS general pasteboard.
///
/// **Thread safety**: `NSPasteboard` must be accessed from the main thread.
/// The caller is responsible for ensuring this function is invoked on the
/// main thread.
fn read_pasteboard_text() -> Option<String> {
    let pasteboard = NSPasteboard::generalPasteboard();
    let ns_string_type = NSString::from_str(UTI_PLAIN_TEXT);
    let result = pasteboard.stringForType(&ns_string_type)?;
    Some(result.to_string())
}

/// Write plain text to the macOS general pasteboard.
///
/// **Thread safety**: Same main-thread requirement as [`read_pasteboard_text`].
fn write_pasteboard_text(text: &str) -> bool {
    let pasteboard = NSPasteboard::generalPasteboard();
    pasteboard.clearContents();
    let ns_string = NSString::from_str(text);
    let ns_string_type = NSString::from_str(UTI_PLAIN_TEXT);
    pasteboard.setString_forType(&ns_string, &ns_string_type)
}
