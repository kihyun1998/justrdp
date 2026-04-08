//! Wayland clipboard backend for RDP clipboard redirection.
//!
//! Uses the `wl-clipboard-rs` crate to interact with the Wayland clipboard.
//! Supports text (CF_TEXT, CF_UNICODETEXT) and image (CF_DIB via BMP) formats.

use std::io::Read;

use justrdp_cliprdr::pdu::{FileContentsRequestPdu, FileContentsResponsePdu, LongFormatName};
use justrdp_cliprdr::{ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse};

use crate::common::{self, bmp_to_dib, dib_to_bmp, rdp_bytes_to_utf8, utf8_to_rdp};

/// Maximum clipboard data to read from the compositor pipe (4 MiB).
const MAX_CLIPBOARD_READ_BYTES: u64 = 4 * 1024 * 1024;

/// Wayland clipboard backend.
///
/// Unlike X11, Wayland clipboard access is per-invocation — there is no
/// persistent clipboard handle. Each read/write spawns a short-lived
/// interaction with the compositor.
pub struct WaylandClipboard;

impl WaylandClipboard {
    /// Create a new Wayland clipboard backend.
    pub fn new() -> Result<Self, ClipboardError> {
        Ok(Self)
    }

    /// Accept the format list if it contains any supported format.
    pub fn on_format_list(
        &mut self,
        formats: &[LongFormatName],
    ) -> ClipboardResult<FormatListResponse> {
        common::accept_supported_format_list(formats)
    }

    /// Read from the Wayland clipboard and encode for the requested format.
    pub fn on_format_data_request(
        &mut self,
        format_id: u32,
    ) -> ClipboardResult<FormatDataResponse> {
        if common::is_text_format(format_id) {
            use wl_clipboard_rs::paste::{get_contents, ClipboardType, MimeType, Seat};

            let (pipe, _mime) =
                get_contents(ClipboardType::Regular, Seat::Unspecified, MimeType::Text)
                    .map_err(|_| ClipboardError::Failed)?;

            let mut text = String::new();
            pipe.take(MAX_CLIPBOARD_READ_BYTES)
                .read_to_string(&mut text)
                .map_err(|_| ClipboardError::Failed)?;

            let data = utf8_to_rdp(&text, format_id).ok_or(ClipboardError::Failed)?;
            return Ok(FormatDataResponse::Ok(data));
        }

        if common::is_image_format(format_id) {
            use wl_clipboard_rs::paste::{get_contents, ClipboardType, MimeType, Seat};

            let (mut pipe, _mime) = get_contents(
                ClipboardType::Regular,
                Seat::Unspecified,
                MimeType::Specific("image/bmp"),
            )
            .map_err(|_| ClipboardError::Failed)?;

            let mut bmp_bytes = Vec::new();
            pipe.take(MAX_CLIPBOARD_READ_BYTES)
                .read_to_end(&mut bmp_bytes)
                .map_err(|_| ClipboardError::Failed)?;

            let dib = bmp_to_dib(&bmp_bytes).ok_or(ClipboardError::Failed)?;
            return Ok(FormatDataResponse::Ok(dib));
        }

        Ok(FormatDataResponse::Fail)
    }

    /// Decode server data and copy to the Wayland clipboard.
    pub fn on_format_data_response(&mut self, data: &[u8], is_success: bool) {
        if !is_success {
            return;
        }

        use wl_clipboard_rs::copy::{MimeType, Options, Source};

        // Try image first
        if data.len() >= 40 {
            let bi_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if bi_size >= 40 {
                if let Some(bmp) = dib_to_bmp(data) {
                    let opts = Options::new();
                    let _ = opts.copy(
                        Source::Bytes(bmp.into()),
                        MimeType::Specific("image/bmp"),
                    );
                    return;
                }
            }
        }

        // Fall back to text
        if let Some(text) = rdp_bytes_to_utf8(data) {
            let opts = Options::new();
            let _ = opts.copy(Source::Bytes(text.into_bytes().into()), MimeType::Text);
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
