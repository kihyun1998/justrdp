//! macOS native clipboard backend using `objc2` + `objc2-app-kit`.
//!
//! Provides text (CF_TEXT, CF_UNICODETEXT) and image (CF_DIB) clipboard
//! integration via NSPasteboard.
//!
//! All NSPasteboard operations are dispatched to the main thread via
//! `dispatch_sync(dispatch_get_main_queue(), ...)` to satisfy AppKit's
//! main-thread requirement, allowing this backend to be safely called
//! from any thread (e.g., an RDP session worker thread).

// Required: brings AnyThread trait into scope so NSBitmapImageRep::alloc() resolves.
use objc2::AnyThread;
use objc2_app_kit::NSPasteboard;
use objc2_foundation::NSString;

use justrdp_cliprdr::pdu::{FileContentsRequestPdu, FileContentsResponsePdu, LongFormatName};
use justrdp_cliprdr::{ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse};

use crate::common::{
    self, bmp_to_dib, dib_to_bmp, is_image_format, is_text_format, looks_like_dib,
    rdp_bytes_to_utf8, utf8_to_rdp, MAX_CLIPBOARD_BYTES,
};

/// UTI for plain text on macOS.
const UTI_PLAIN_TEXT: &str = "public.utf8-plain-text";
/// UTI for BMP images on macOS.
const UTI_BMP: &str = "com.microsoft.bmp";
/// UTI for TIFF images on macOS (read-only, for native macOS apps).
const UTI_TIFF: &str = "public.tiff";

// ── GCD (Grand Central Dispatch) FFI ──────────────────────────────────────

// These are part of libdispatch, which is always available on macOS.
// The libc crate doesn't expose them, so we declare them directly.
type DispatchQueue = *mut std::ffi::c_void;
type DispatchFunction = extern "C" fn(*mut std::ffi::c_void);

unsafe extern "C" {
    fn dispatch_get_main_queue() -> DispatchQueue;
    fn dispatch_sync_f(queue: DispatchQueue, context: *mut std::ffi::c_void, work: DispatchFunction);
}

// ── Main-thread dispatch ──────────────────────────────────────────────────

/// Execute a closure on the main thread, blocking until completion.
///
/// If already on the main thread, the closure is called directly to
/// avoid deadlocking `dispatch_sync`. Otherwise, dispatches via GCD's
/// main queue.
///
/// # Panics
///
/// Panics if the closure panics (the panic is caught and re-raised on
/// the calling thread to avoid undefined behavior across the FFI boundary).
/// Also panics if `dispatch_sync_f` returns without invoking the trampoline.
///
/// # Preconditions
///
/// - `F` and `R` must be `Send` (enforced by trait bounds).
/// - Must not be called recursively from within a `dispatch_sync` callback
///   on the main queue (deadlock).
#[allow(unsafe_code)]
fn on_main_thread<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    // SAFETY: pthread_main_np() returns non-zero if this is the main thread.
    // Available on macOS since 10.0 via libpthread.
    unsafe extern "C" {
        fn pthread_main_np() -> std::ffi::c_int;
    }
    if unsafe { pthread_main_np() } != 0 {
        return f();
    }

    // Dispatch to the main queue synchronously.
    let mut result: Option<Result<R, Box<dyn std::any::Any + Send>>> = None;
    let result_ptr: *mut Option<Result<R, Box<dyn std::any::Any + Send>>> = &mut result;

    // Pack the closure and result pointer into a context struct.
    // Both are valid for the lifetime of this function because
    // dispatch_sync blocks until the work completes.
    struct Context<F, R> {
        f: Option<F>,
        result_ptr: *mut Option<Result<R, Box<dyn std::any::Any + Send>>>,
    }

    // SAFETY: Context is only accessed by the trampoline on the main thread,
    // and dispatch_sync guarantees the trampoline completes before returning.
    // The raw pointers are valid for the duration of the dispatch_sync call.
    unsafe impl<F: Send, R: Send> Send for Context<F, R> {}

    let mut ctx = Context {
        f: Some(f),
        result_ptr,
    };

    extern "C" fn trampoline<F, R>(context: *mut std::ffi::c_void)
    where
        F: FnOnce() -> R,
    {
        // SAFETY: context points to a valid Context<F, R> on the caller's stack.
        // dispatch_sync guarantees this function completes before the caller returns.
        let ctx = unsafe { &mut *(context as *mut Context<F, R>) };
        let f = ctx.f.take().unwrap();
        // Catch panics to avoid undefined behavior when a panic crosses the
        // C FFI boundary (dispatch_sync_f → trampoline).
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        unsafe {
            *ctx.result_ptr = Some(outcome);
        }
    }

    // SAFETY: dispatch_get_main_queue returns a valid serial queue.
    // dispatch_sync_f blocks until the trampoline completes, so ctx
    // remains valid for the entire call. We are NOT on the main thread
    // (checked above), so dispatch_sync will not deadlock.
    unsafe {
        dispatch_sync_f(
            dispatch_get_main_queue(),
            &mut ctx as *mut Context<F, R> as *mut std::ffi::c_void,
            trampoline::<F, R>,
        );
    }

    match result.expect("dispatch_sync_f did not invoke the trampoline") {
        Ok(value) => value,
        Err(panic_payload) => std::panic::resume_unwind(panic_payload),
    }
}

// ── MacosClipboard ────────────────────────────────────────────────────────

/// macOS clipboard backend.
///
/// Uses `NSPasteboard` via the `objc2` crate to read from and write to the
/// local macOS clipboard. Supports text (CF_TEXT, CF_UNICODETEXT) and
/// image (CF_DIB) formats.
///
/// **Thread safety**: All NSPasteboard operations are automatically dispatched
/// to the main thread via GCD. This struct is `Send` and can be safely used
/// from any thread.
pub struct MacosClipboard;

impl MacosClipboard {
    pub fn new() -> Result<Self, ClipboardError> {
        Ok(Self)
    }

    pub fn on_format_list(
        &mut self,
        formats: &[LongFormatName],
    ) -> ClipboardResult<FormatListResponse> {
        common::accept_supported_format_list(formats)
    }

    pub fn on_format_data_request(
        &mut self,
        format_id: u32,
    ) -> ClipboardResult<FormatDataResponse> {
        if is_text_format(format_id) {
            let text = on_main_thread(read_pasteboard_text).ok_or(ClipboardError::Failed)?;
            let data = utf8_to_rdp(&text, format_id).ok_or(ClipboardError::Failed)?;
            return Ok(FormatDataResponse::Ok(data));
        }

        if is_image_format(format_id) {
            let dib = on_main_thread(read_pasteboard_image).ok_or(ClipboardError::Failed)?;
            return Ok(FormatDataResponse::Ok(dib));
        }

        Ok(FormatDataResponse::Fail)
    }

    pub fn on_format_data_response(&mut self, data: &[u8], is_success: bool, format_id: Option<u32>) {
        if !is_success {
            return;
        }

        // Use the negotiated format_id when available; fall back to content heuristic.
        if format_id == Some(common::CF_DIB) || (format_id.is_none() && looks_like_dib(data)) {
            let data_owned = data.to_vec();
            let written = on_main_thread(move || write_pasteboard_image(&data_owned));
            if written {
                return;
            }
        }

        if let Some(text) = rdp_bytes_to_utf8(data) {
            on_main_thread(move || {
                let _ = write_pasteboard_text(&text);
            });
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

// ── NSPasteboard operations (must run on main thread) ─────────────────────

fn read_pasteboard_text() -> Option<String> {
    let pasteboard = NSPasteboard::generalPasteboard();
    let ns_string_type = NSString::from_str(UTI_PLAIN_TEXT);
    let result = pasteboard.stringForType(&ns_string_type)?;
    Some(result.to_string())
}

fn write_pasteboard_text(text: &str) -> bool {
    let pasteboard = NSPasteboard::generalPasteboard();
    pasteboard.clearContents();
    let ns_string = NSString::from_str(text);
    let ns_string_type = NSString::from_str(UTI_PLAIN_TEXT);
    pasteboard.setString_forType(&ns_string, &ns_string_type)
}

/// Copy `NSData` bytes into a `Vec<u8>`. Returns `None` if data exceeds
/// the size limit to prevent unbounded allocation.
fn nsdata_to_vec(data: &objc2_foundation::NSData) -> Option<Vec<u8>> {
    nsdata_to_vec_with_limit(data, MAX_CLIPBOARD_BYTES)
}

fn nsdata_to_vec_with_limit(data: &objc2_foundation::NSData, max_bytes: usize) -> Option<Vec<u8>> {
    // Use `as_bytes()` to get a single-snapshot slice, avoiding TOCTOU between
    // `length()` and `getBytes_length()` if NSData is mutated concurrently.
    let bytes = data.as_bytes();
    if bytes.len() > max_bytes {
        return None;
    }
    Some(bytes.to_vec())
}

fn read_pasteboard_image() -> Option<Vec<u8>> {
    let pasteboard = NSPasteboard::generalPasteboard();

    // Try BMP format — direct conversion to DIB by stripping the file header.
    let bmp_type = NSString::from_str(UTI_BMP);
    if let Some(bmp_data) = pasteboard.dataForType(&bmp_type) {
        let bytes = nsdata_to_vec(&bmp_data)?;
        return bmp_to_dib(&bytes);
    }

    // Try TIFF format — use NSBitmapImageRep to convert to BMP.
    let tiff_type = NSString::from_str(UTI_TIFF);
    if let Some(tiff_data) = pasteboard.dataForType(&tiff_type) {
        return tiff_data_to_dib(&tiff_data);
    }

    None
}

/// Maximum TIFF data size to process (32 MiB).
const MAX_TIFF_BYTES: usize = 32 * 1024 * 1024;

#[allow(unsafe_code)]
fn tiff_data_to_dib(tiff_data: &objc2_foundation::NSData) -> Option<Vec<u8>> {
    use objc2_app_kit::{NSBitmapImageFileType, NSBitmapImageRep};
    use objc2_foundation::NSDictionary;

    if tiff_data.length() > MAX_TIFF_BYTES {
        return None;
    }

    let rep = NSBitmapImageRep::initWithData(NSBitmapImageRep::alloc(), tiff_data)?;

    let properties = NSDictionary::new();
    // SAFETY: rep is a valid NSBitmapImageRep. BMP is a well-supported output format.
    let bmp_data = unsafe {
        rep.representationUsingType_properties(NSBitmapImageFileType::BMP, &properties)
    }?;

    // Use the TIFF limit for the BMP output since image data expands during conversion.
    let bytes = nsdata_to_vec_with_limit(&bmp_data, MAX_TIFF_BYTES)?;
    bmp_to_dib(&bytes)
}

fn write_pasteboard_image(dib: &[u8]) -> bool {
    let bmp = match dib_to_bmp(dib) {
        Some(b) => b,
        None => return false,
    };

    let pasteboard = NSPasteboard::generalPasteboard();
    pasteboard.clearContents();

    let bmp_type = NSString::from_str(UTI_BMP);
    let ns_data = objc2_foundation::NSData::with_bytes(&bmp);
    pasteboard.setData_forType(Some(&*ns_data), &bmp_type)
}
