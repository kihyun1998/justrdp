//! Windows native clipboard backend using `clipboard-win` crate.
//!
//! Provides text clipboard integration (CF_TEXT, CF_UNICODETEXT) via Win32 API.

use clipboard_win::formats::Unicode;
use clipboard_win::{get_clipboard, set_clipboard};

use justrdp_cliprdr::pdu::{FileContentsRequestPdu, FileContentsResponsePdu, LongFormatName};
use justrdp_cliprdr::{ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse};

use crate::common::{self, is_text_format, rdp_bytes_to_utf8, utf8_to_rdp};

/// Windows clipboard backend.
///
/// Uses the `clipboard-win` crate to read from and write to the local
/// Windows clipboard. Currently supports text formats only.
pub struct WindowsClipboard;

impl WindowsClipboard {
    /// Create a new Windows clipboard backend.
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

    /// Read from the local clipboard and encode for the requested format.
    pub fn on_format_data_request(
        &mut self,
        format_id: u32,
    ) -> ClipboardResult<FormatDataResponse> {
        if !is_text_format(format_id) {
            return Ok(FormatDataResponse::Fail);
        }

        let text: String = get_clipboard(Unicode).map_err(|_| ClipboardError::Failed)?;
        let data = utf8_to_rdp(&text, format_id).ok_or(ClipboardError::Failed)?;
        Ok(FormatDataResponse::Ok(data))
    }

    /// Decode server data and write to the local clipboard.
    pub fn on_format_data_response(&mut self, data: &[u8], is_success: bool) {
        if !is_success {
            return;
        }
        if let Some(text) = rdp_bytes_to_utf8(data) {
            let _ = set_clipboard(Unicode, &text);
        }
    }

    pub fn on_file_contents_request(
        &mut self,
        _request: &FileContentsRequestPdu,
    ) -> ClipboardResult<FileContentsResponsePdu> {
        Err(ClipboardError::Other("file transfer not supported"))
    }

    pub fn on_file_contents_response(&mut self, _response: &FileContentsResponsePdu) {}

    pub fn on_lock(&mut self, _lock_id: u32) {}

    pub fn on_unlock(&mut self, _lock_id: u32) {}
}
