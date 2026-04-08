//! X11 clipboard backend for RDP clipboard redirection.
//!
//! Uses the `x11-clipboard` crate to interact with the X11 CLIPBOARD selection.

use justrdp_cliprdr::pdu::{FileContentsRequestPdu, FileContentsResponsePdu, LongFormatName};
use justrdp_cliprdr::{ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse};
use x11_clipboard::Clipboard as X11Clip;

use crate::common::{self, rdp_bytes_to_utf8, utf8_to_rdp};

/// X11 clipboard timeout for selection reads.
const X11_CLIPBOARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// X11 clipboard backend.
///
/// Wraps the X11 CLIPBOARD selection for reading and writing text data
/// during RDP clipboard redirection.
pub struct X11Clipboard {
    clip: X11Clip,
}

impl X11Clipboard {
    /// Create a new X11 clipboard backend.
    ///
    /// Opens a connection to the X11 display. Fails if no X11 display is available.
    pub fn new() -> Result<Self, ClipboardError> {
        let clip = X11Clip::new().map_err(|_| ClipboardError::Failed)?;
        Ok(Self { clip })
    }

    /// Accept the format list if it contains any text format.
    pub fn on_format_list(
        &mut self,
        formats: &[LongFormatName],
    ) -> ClipboardResult<FormatListResponse> {
        common::accept_text_format_list(formats)
    }

    /// Read from the X11 CLIPBOARD selection and encode for the requested format.
    pub fn on_format_data_request(
        &mut self,
        format_id: u32,
    ) -> ClipboardResult<FormatDataResponse> {
        if !common::is_text_format(format_id) {
            return Ok(FormatDataResponse::Fail);
        }

        let atoms = &self.clip.getter.atoms;
        let text_bytes = self
            .clip
            .load(
                atoms.clipboard,
                atoms.utf8_string,
                atoms.property,
                X11_CLIPBOARD_TIMEOUT,
            )
            .map_err(|_| ClipboardError::Failed)?;

        let text = String::from_utf8(text_bytes).map_err(|_| ClipboardError::Failed)?;
        let data = utf8_to_rdp(&text, format_id).ok_or(ClipboardError::Failed)?;
        Ok(FormatDataResponse::Ok(data))
    }

    /// Decode server data and write to the X11 CLIPBOARD selection.
    pub fn on_format_data_response(&mut self, data: &[u8], is_success: bool) {
        if !is_success {
            return;
        }
        if let Some(text) = rdp_bytes_to_utf8(data) {
            let atoms = &self.clip.setter.atoms;
            let _ = self.clip.store(atoms.clipboard, atoms.utf8_string, text.as_bytes());
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
