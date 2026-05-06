//! Windows clipboard adapter using the `clipboard-win` crate.
//!
//! Provides [`WindowsClipboard`] — a [`NativeClipboardSurface`] over the
//! Win32 Clipboard API.

use clipboard_win::formats::{Bitmap, Unicode};
use clipboard_win::{get_clipboard, set_clipboard};
use justrdp_cliprdr::ClipboardError;

use crate::surface::{NativeClipboardError, NativeClipboardResult, NativeClipboardSurface};

/// Windows clipboard surface.
pub struct WindowsClipboard;

impl WindowsClipboard {
    /// Create a new Windows clipboard surface.
    pub fn new() -> Result<Self, ClipboardError> {
        Ok(Self)
    }
}

impl NativeClipboardSurface for WindowsClipboard {
    fn read_text(&mut self) -> NativeClipboardResult<Option<String>> {
        // `clipboard-win`'s `Unicode` formatter performs the UTF-16LE → UTF-8
        // conversion internally; any error (including "format not present")
        // collapses to `Ok(None)`.
        Ok(get_clipboard::<String, _>(Unicode).ok())
    }

    fn write_text(&mut self, text: &str) -> NativeClipboardResult<()> {
        set_clipboard(Unicode, text)
            .map_err(|e| NativeClipboardError::OsApi(format!("set_clipboard(Unicode): {e}")))
    }

    fn read_image(&mut self) -> NativeClipboardResult<Option<Vec<u8>>> {
        // `clipboard-win`'s `Bitmap` formatter returns DIB bytes directly.
        Ok(get_clipboard::<Vec<u8>, _>(Bitmap).ok())
    }

    fn write_image(&mut self, dib: &[u8]) -> NativeClipboardResult<()> {
        set_clipboard(Bitmap, dib)
            .map_err(|e| NativeClipboardError::OsApi(format!("set_clipboard(Bitmap): {e}")))
    }
}
