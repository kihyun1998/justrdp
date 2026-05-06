//! Wayland clipboard adapter using `wl-clipboard-rs`.
//!
//! Provides [`WaylandClipboard`] — a [`NativeClipboardSurface`] over the
//! Wayland clipboard. Each read/write spawns a short-lived interaction with
//! the compositor (Wayland has no persistent clipboard handle).

use std::io::Read;

use justrdp_cliprdr::ClipboardError;

use crate::common::{bmp_to_dib, dib_to_bmp, MAX_CLIPBOARD_BYTES};
use crate::surface::{NativeClipboardError, NativeClipboardResult, NativeClipboardSurface};

/// Wayland clipboard surface.
pub struct WaylandClipboard;

impl WaylandClipboard {
    pub fn new() -> Result<Self, ClipboardError> {
        Ok(Self)
    }
}

impl NativeClipboardSurface for WaylandClipboard {
    fn read_text(&mut self) -> NativeClipboardResult<Option<String>> {
        use wl_clipboard_rs::paste::{get_contents, ClipboardType, MimeType, Seat};

        let (pipe, _mime) =
            match get_contents(ClipboardType::Regular, Seat::Unspecified, MimeType::Text) {
                Ok(t) => t,
                Err(_) => return Ok(None),
            };

        let mut text = String::with_capacity(4096);
        pipe.take(MAX_CLIPBOARD_BYTES as u64)
            .read_to_string(&mut text)
            .map_err(|e| NativeClipboardError::Encoding(format!("Wayland text read: {e}")))?;
        Ok(Some(text))
    }

    fn write_text(&mut self, text: &str) -> NativeClipboardResult<()> {
        use wl_clipboard_rs::copy::{MimeType, Options, Source};

        let opts = Options::new();
        opts.copy(Source::Bytes(text.as_bytes().to_vec().into()), MimeType::Text)
            .map_err(|e| NativeClipboardError::OsApi(format!("Wayland copy text: {e}")))
    }

    fn read_image(&mut self) -> NativeClipboardResult<Option<Vec<u8>>> {
        use wl_clipboard_rs::paste::{get_contents, ClipboardType, MimeType, Seat};

        let (mut pipe, _mime) = match get_contents(
            ClipboardType::Regular,
            Seat::Unspecified,
            MimeType::Specific("image/bmp"),
        ) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };

        let mut bmp_bytes = Vec::with_capacity(4096);
        pipe.take(MAX_CLIPBOARD_BYTES as u64)
            .read_to_end(&mut bmp_bytes)
            .map_err(|e| NativeClipboardError::OsApi(format!("Wayland image read: {e}")))?;

        Ok(bmp_to_dib(&bmp_bytes))
    }

    fn write_image(&mut self, dib: &[u8]) -> NativeClipboardResult<()> {
        use wl_clipboard_rs::copy::{MimeType, Options, Source};

        let bmp = dib_to_bmp(dib).ok_or_else(|| {
            NativeClipboardError::Encoding("dib_to_bmp conversion failed".to_string())
        })?;
        let opts = Options::new();
        opts.copy(Source::Bytes(bmp.into()), MimeType::Specific("image/bmp"))
            .map_err(|e| NativeClipboardError::OsApi(format!("Wayland copy image: {e}")))
    }
}
