#![forbid(unsafe_code)]

//! Clipboard backend trait -- application-level clipboard integration.

use alloc::vec::Vec;

use crate::pdu::{FileContentsRequestPdu, FileContentsResponsePdu, LongFormatName};

/// Result type for clipboard operations.
pub type ClipboardResult<T> = Result<T, ClipboardError>;

/// Clipboard operation error.
#[derive(Debug)]
pub enum ClipboardError {
    /// The requested operation failed.
    Failed,
    /// A custom error message with context.
    Other(alloc::string::String),
}

impl core::fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Failed => f.write_str("clipboard operation failed"),
            Self::Other(msg) => f.write_str(msg),
        }
    }
}

/// Response to a format list notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatListResponse {
    /// Accept the format list.
    Ok,
    /// Reject the format list.
    Fail,
}

/// Response to a format data request.
#[derive(Debug)]
pub enum FormatDataResponse {
    /// Successful response with clipboard data.
    Ok(Vec<u8>),
    /// The requested format data is not available.
    Fail,
}

/// Application-level clipboard backend.
///
/// Implement this trait to integrate clipboard functionality with your
/// platform's native clipboard or application logic.
pub trait CliprdrBackend: Send {
    /// Called when the remote side advertises new clipboard formats.
    ///
    /// Return `Ok` to accept or `Fail` to reject the format list.
    fn on_format_list(&mut self, formats: &[LongFormatName]) -> ClipboardResult<FormatListResponse>;

    /// Called when the remote side requests clipboard data in a specific format.
    fn on_format_data_request(&mut self, format_id: u32) -> ClipboardResult<FormatDataResponse>;

    /// Called when the remote side responds with clipboard data.
    fn on_format_data_response(&mut self, data: &[u8], is_success: bool);

    /// Called when the remote side requests file contents.
    fn on_file_contents_request(
        &mut self,
        request: &FileContentsRequestPdu,
    ) -> ClipboardResult<FileContentsResponsePdu>;

    /// Called when the remote side responds with file contents.
    fn on_file_contents_response(&mut self, response: &FileContentsResponsePdu);

    /// Called when the remote side locks clipboard data.
    fn on_lock(&mut self, lock_id: u32);

    /// Called when the remote side unlocks clipboard data.
    fn on_unlock(&mut self, lock_id: u32);
}
