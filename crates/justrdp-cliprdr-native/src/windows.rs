// Win32 message-only window + AddClipboardFormatListener requires unsafe
// FFI; the rest of the crate is `#![deny(unsafe_code)]`. The unsafe code
// is confined to this module and bracketed with SAFETY comments.
#![allow(unsafe_code)]

//! Windows clipboard adapter using the `clipboard-win` crate.
//!
//! Provides [`WindowsClipboard`] — a [`NativeClipboardSurface`] over the
//! Win32 Clipboard API. The listener-enabled constructor spawns a
//! dedicated thread with a message-only window registered for
//! `WM_CLIPBOARDUPDATE` (issue #34 host→server outbound seam).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use clipboard_win::formats::{Bitmap, Unicode};
use clipboard_win::{get_clipboard, set_clipboard};
use justrdp_cliprdr::ClipboardError;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::DataExchange::{
    AddClipboardFormatListener, RemoveClipboardFormatListener,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostMessageW,
    RegisterClassW, TranslateMessage, HWND_MESSAGE, MSG, WM_CLIPBOARDUPDATE, WM_USER, WNDCLASSW,
};

use crate::surface::{NativeClipboardError, NativeClipboardResult, NativeClipboardSurface};

/// User-defined message posted from `Drop` to break the listener thread's
/// `GetMessageW` loop. Values >= `WM_USER` are reserved for application use.
const WM_USER_STOP: u32 = WM_USER + 1;

/// Windows clipboard surface.
///
/// The optional `listener` field is populated by
/// [`Self::new_with_listener`]; when present it owns a dedicated message
/// pump thread that signals the parent each time the OS clipboard
/// changes.
pub struct WindowsClipboard {
    listener: Option<Listener>,
}

struct Listener {
    /// `true` if a `WM_CLIPBOARDUPDATE` has been observed since the last
    /// `poll_change()` call. Drained atomically.
    changed: Arc<AtomicBool>,
    /// Raw HWND of the message-only window, stored as `usize` for `Send`.
    /// PostMessageW is thread-safe so the parent may post to it on drop.
    hwnd_raw: usize,
    /// Listener-thread join handle. Joined on drop.
    thread: Option<JoinHandle<()>>,
}

impl WindowsClipboard {
    /// Create a listener-less surface — host→server outbound stays silent.
    pub fn new() -> Result<Self, ClipboardError> {
        Ok(Self { listener: None })
    }

    /// Create a surface with a dedicated thread that owns a message-only
    /// window registered for `WM_CLIPBOARDUPDATE`.
    ///
    /// Each update sets the `changed` atomic and sends `()` on `wake_tx`
    /// so the session loop wakes and drains via `poll_change()`.
    pub fn new_with_listener(wake_tx: Sender<()>) -> Result<Self, ClipboardError> {
        let listener = spawn_listener(wake_tx)
            .map_err(|msg| ClipboardError::Other(format!("clipboard listener init: {msg}")))?;
        log::info!(
            "[DIAG-clip] WindowsClipboard listener thread up (hwnd=0x{:x})",
            listener.hwnd_raw
        );
        Ok(Self {
            listener: Some(listener),
        })
    }
}

impl Drop for WindowsClipboard {
    fn drop(&mut self) {
        if let Some(mut l) = self.listener.take() {
            // SAFETY: `hwnd_raw` was returned by `CreateWindowExW` in the
            // listener thread's setup; it remains valid until the thread
            // calls `DestroyWindow` (which it does only after observing
            // `WM_USER_STOP`). `PostMessageW` is thread-safe.
            unsafe {
                PostMessageW(l.hwnd_raw as HWND, WM_USER_STOP, 0, 0);
            }
            if let Some(t) = l.thread.take() {
                let _ = t.join();
            }
            log::info!("[DIAG-clip] WindowsClipboard listener thread joined");
        }
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

    fn poll_change(&mut self) -> bool {
        match &self.listener {
            Some(l) => l.changed.swap(false, Ordering::AcqRel),
            None => false,
        }
    }
}

/// Spawn the listener thread, block until it returns the created HWND
/// (or signals failure), then return the `Listener` handle.
fn spawn_listener(wake_tx: Sender<()>) -> Result<Listener, String> {
    let (hwnd_tx, hwnd_rx) = channel::<isize>();
    let changed = Arc::new(AtomicBool::new(false));
    let changed_thread = Arc::clone(&changed);

    let thread = thread::Builder::new()
        .name("justrdp-clip-listener".into())
        .spawn(move || listener_main(hwnd_tx, changed_thread, wake_tx))
        .map_err(|e| format!("spawn: {e}"))?;

    let hwnd_raw = hwnd_rx
        .recv()
        .map_err(|_| "listener thread exited before sending HWND".to_string())?;
    if hwnd_raw == 0 {
        let _ = thread.join();
        return Err("listener thread failed to create message-only window".into());
    }

    Ok(Listener {
        changed,
        hwnd_raw: hwnd_raw as usize,
        thread: Some(thread),
    })
}

/// Listener thread entry point. Owns the HWND for its entire lifetime;
/// no FFI handle escapes except the raw `HWND` value sent back to the
/// parent for the `WM_USER_STOP` PostMessage.
fn listener_main(
    hwnd_tx: Sender<isize>,
    changed: Arc<AtomicBool>,
    wake_tx: Sender<()>,
) {
    // UTF-16LE class/window name with trailing NUL.
    let class_name: Vec<u16> = "JustRdpClipListener\0".encode_utf16().collect();

    // SAFETY block: every FFI call below documents its invariants.
    unsafe {
        // SAFETY: GetModuleHandleW(NULL) returns the EXE handle; never fails.
        let hinst = GetModuleHandleW(std::ptr::null());

        // SAFETY: WNDCLASSW is plain old data; zero-init is valid.
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(DefWindowProcW);
        wc.hInstance = hinst;
        wc.lpszClassName = class_name.as_ptr();

        // SAFETY: `wc` is a properly initialised WNDCLASSW; failing
        // because the class is already registered (`ERROR_CLASS_ALREADY_EXISTS`)
        // is acceptable — re-registration is a no-op for CreateWindowExW.
        let _ = RegisterClassW(&wc);

        // SAFETY: HWND_MESSAGE creates a message-only window — no rendering,
        // no parent painting, just a queue for thread-targeted messages.
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            let _ = hwnd_tx.send(0);
            return;
        }

        // SAFETY: hwnd is non-null and was just created; AddClipboardFormatListener
        // takes ownership of the listener registration tied to hwnd's lifetime.
        if AddClipboardFormatListener(hwnd) == 0 {
            DestroyWindow(hwnd);
            let _ = hwnd_tx.send(0);
            return;
        }

        // Notify parent that init is complete.
        if hwnd_tx.send(hwnd as isize).is_err() {
            // Parent went away before init finished — clean up and exit.
            RemoveClipboardFormatListener(hwnd);
            DestroyWindow(hwnd);
            return;
        }

        // Message pump. We do NOT use a custom WindowProc; instead we
        // observe the messages directly from the queue. DefWindowProcW
        // handles dispatch fallthrough for anything we don't filter.
        // SAFETY: `msg` is initialised by GetMessageW on every successful call.
        let mut msg: MSG = std::mem::zeroed();
        loop {
            let r = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
            if r <= 0 {
                // 0 = WM_QUIT received via PostQuitMessage (we do not post
                // one, but DefWindowProc may); -1 = error. Either way: exit.
                break;
            }
            if msg.message == WM_CLIPBOARDUPDATE {
                changed.store(true, Ordering::Release);
                // wake_tx.send() failing means the session loop has dropped
                // its receiver — the parent will shortly drop us too.
                let _ = wake_tx.send(());
                log::info!("[DIAG-clip] WM_CLIPBOARDUPDATE — host clipboard changed");
            } else if msg.message == WM_USER_STOP {
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // SAFETY: hwnd is still valid (we never destroyed it). Both calls
        // are idempotent-ish — removing an already-removed listener
        // returns BOOL=0 which we ignore.
        RemoveClipboardFormatListener(hwnd);
        DestroyWindow(hwnd);
    }
}
