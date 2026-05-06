//! macOS clipboard adapter using `objc2` + `objc2-app-kit`.
//!
//! Provides [`MacosClipboard`] — a [`NativeClipboardSurface`] over
//! NSPasteboard. All NSPasteboard operations are dispatched to the main
//! thread via GCD `dispatch_sync`, allowing this surface to be used safely
//! from any thread (e.g. an RDP session worker).

// Required: brings AnyThread trait into scope so NSBitmapImageRep::alloc() resolves.
use objc2::AnyThread;
use objc2_app_kit::NSPasteboard;
use objc2_foundation::NSString;

use justrdp_cliprdr::ClipboardError;

use crate::common::{bmp_to_dib, dib_to_bmp, MAX_CLIPBOARD_BYTES};
use crate::surface::{NativeClipboardError, NativeClipboardResult, NativeClipboardSurface};

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
/// If already on the main thread, the closure is called directly to avoid
/// deadlocking `dispatch_sync`. Otherwise dispatches via GCD's main queue.
#[allow(unsafe_code)]
fn on_main_thread<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    unsafe extern "C" {
        fn pthread_main_np() -> std::ffi::c_int;
    }
    if unsafe { pthread_main_np() } != 0 {
        return f();
    }

    let mut result: Option<Result<R, Box<dyn std::any::Any + Send>>> = None;
    let result_ptr: *mut Option<Result<R, Box<dyn std::any::Any + Send>>> = &mut result;

    struct Context<F, R> {
        f: Option<F>,
        result_ptr: *mut Option<Result<R, Box<dyn std::any::Any + Send>>>,
    }

    unsafe impl<F: Send, R: Send> Send for Context<F, R> {}

    let mut ctx = Context {
        f: Some(f),
        result_ptr,
    };

    extern "C" fn trampoline<F, R>(context: *mut std::ffi::c_void)
    where
        F: FnOnce() -> R,
    {
        let ctx = unsafe { &mut *(context as *mut Context<F, R>) };
        let f = ctx.f.take().unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        unsafe {
            *ctx.result_ptr = Some(outcome);
        }
    }

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

/// macOS clipboard surface.
pub struct MacosClipboard;

impl MacosClipboard {
    pub fn new() -> Result<Self, ClipboardError> {
        Ok(Self)
    }
}

impl NativeClipboardSurface for MacosClipboard {
    fn read_text(&mut self) -> NativeClipboardResult<Option<String>> {
        Ok(on_main_thread(read_pasteboard_text))
    }

    fn write_text(&mut self, text: &str) -> NativeClipboardResult<()> {
        let text_owned = text.to_string();
        let ok = on_main_thread(move || write_pasteboard_text(&text_owned));
        if ok {
            Ok(())
        } else {
            Err(NativeClipboardError::OsApi(
                "NSPasteboard.setString_forType returned false".to_string(),
            ))
        }
    }

    fn read_image(&mut self) -> NativeClipboardResult<Option<Vec<u8>>> {
        Ok(on_main_thread(read_pasteboard_image))
    }

    fn write_image(&mut self, dib: &[u8]) -> NativeClipboardResult<()> {
        let dib_owned = dib.to_vec();
        let ok = on_main_thread(move || write_pasteboard_image(&dib_owned));
        if ok {
            Ok(())
        } else {
            Err(NativeClipboardError::OsApi(
                "NSPasteboard.setData_forType returned false (or BMP conversion failed)".to_string(),
            ))
        }
    }
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

fn nsdata_to_vec(data: &objc2_foundation::NSData) -> Option<Vec<u8>> {
    nsdata_to_vec_with_limit(data, MAX_CLIPBOARD_BYTES)
}

fn nsdata_to_vec_with_limit(data: &objc2_foundation::NSData, max_bytes: usize) -> Option<Vec<u8>> {
    let bytes = data.as_bytes();
    if bytes.len() > max_bytes {
        return None;
    }
    Some(bytes.to_vec())
}

fn read_pasteboard_image() -> Option<Vec<u8>> {
    let pasteboard = NSPasteboard::generalPasteboard();

    let bmp_type = NSString::from_str(UTI_BMP);
    if let Some(bmp_data) = pasteboard.dataForType(&bmp_type) {
        let bytes = nsdata_to_vec(&bmp_data)?;
        return bmp_to_dib(&bytes);
    }

    let tiff_type = NSString::from_str(UTI_TIFF);
    if let Some(tiff_data) = pasteboard.dataForType(&tiff_type) {
        return tiff_data_to_dib(&tiff_data);
    }

    None
}

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
    let bmp_data = unsafe {
        rep.representationUsingType_properties(NSBitmapImageFileType::BMP, &properties)
    }?;

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
