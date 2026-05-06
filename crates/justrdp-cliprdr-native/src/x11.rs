//! X11 clipboard adapter using the `x11-clipboard` crate.
//!
//! Provides [`X11Clipboard`] — a [`NativeClipboardSurface`] over the X11
//! CLIPBOARD selection. Image transfers go through the `image/bmp` MIME atom
//! and are DIB↔BMP-converted at this layer.

use justrdp_cliprdr::ClipboardError;
use x11_clipboard::Clipboard as X11Clip;

use crate::common::{bmp_to_dib, dib_to_bmp};
use crate::surface::{NativeClipboardError, NativeClipboardResult, NativeClipboardSurface};

/// X11 clipboard timeout for selection reads.
const X11_CLIPBOARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// X11 clipboard surface.
pub struct X11Clipboard {
    clip: X11Clip,
}

impl X11Clipboard {
    /// Create a new X11 clipboard surface. Fails if no X11 display is
    /// available.
    pub fn new() -> Result<Self, ClipboardError> {
        let clip = X11Clip::new().map_err(|_| ClipboardError::Failed)?;
        Ok(Self { clip })
    }
}

impl NativeClipboardSurface for X11Clipboard {
    fn read_text(&mut self) -> NativeClipboardResult<Option<String>> {
        let atoms = &self.clip.getter.atoms;
        let bytes = match self.clip.load(
            atoms.clipboard,
            atoms.utf8_string,
            atoms.property,
            X11_CLIPBOARD_TIMEOUT,
        ) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        match String::from_utf8(bytes) {
            Ok(s) => Ok(Some(s)),
            Err(e) => Err(NativeClipboardError::Encoding(format!("X11 utf8: {e}"))),
        }
    }

    fn write_text(&mut self, text: &str) -> NativeClipboardResult<()> {
        let atoms = &self.clip.setter.atoms;
        self.clip
            .store(atoms.clipboard, atoms.utf8_string, text.as_bytes())
            .map_err(|e| NativeClipboardError::OsApi(format!("X11 store: {e}")))
    }

    fn read_image(&mut self) -> NativeClipboardResult<Option<Vec<u8>>> {
        let bmp_atom = match intern_bmp_atom(&self.clip.getter.connection) {
            Some(a) => a,
            None => return Ok(None),
        };

        let atoms = &self.clip.getter.atoms;
        let bmp_bytes = match self
            .clip
            .load(atoms.clipboard, bmp_atom, atoms.property, X11_CLIPBOARD_TIMEOUT)
        {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };

        Ok(bmp_to_dib(&bmp_bytes))
    }

    fn write_image(&mut self, dib: &[u8]) -> NativeClipboardResult<()> {
        let bmp = dib_to_bmp(dib).ok_or_else(|| {
            NativeClipboardError::Encoding("dib_to_bmp conversion failed".to_string())
        })?;
        let atom = intern_bmp_atom(&self.clip.setter.connection)
            .ok_or_else(|| NativeClipboardError::OsApi("intern image/bmp atom failed".to_string()))?;
        let atoms = &self.clip.setter.atoms;
        self.clip
            .store(atoms.clipboard, atom, bmp)
            .map_err(|e| NativeClipboardError::OsApi(format!("X11 store image: {e}")))
    }
}

fn intern_bmp_atom(conn: &x11_clipboard::xcb::Connection) -> Option<x11_clipboard::xcb::x::Atom> {
    use x11_clipboard::xcb::Xid;
    let cookie = conn.send_request(&x11_clipboard::xcb::x::InternAtom {
        only_if_exists: false,
        name: b"image/bmp",
    });
    let reply = conn.wait_for_reply(cookie).ok()?;
    let atom = reply.atom();
    if atom.is_none() {
        return None;
    }
    Some(atom)
}
