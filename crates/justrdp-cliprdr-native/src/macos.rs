//! macOS native clipboard backend using `objc2` + `objc2-app-kit`.
//!
//! Provides text (CF_TEXT, CF_UNICODETEXT) and image (CF_DIB) clipboard
//! integration via NSPasteboard.

use objc2::AnyThread;
use objc2_app_kit::NSPasteboard;
use objc2_foundation::NSString;

use justrdp_cliprdr::pdu::{FileContentsRequestPdu, FileContentsResponsePdu, LongFormatName};
use justrdp_cliprdr::{ClipboardError, ClipboardResult, FormatDataResponse, FormatListResponse};

use crate::common::{
    self, bmp_to_dib, dib_to_bmp, is_image_format, is_text_format, rdp_bytes_to_utf8, utf8_to_rdp,
};

/// UTI for plain text on macOS.
const UTI_PLAIN_TEXT: &str = "public.utf8-plain-text";
/// UTI for BMP images on macOS.
const UTI_BMP: &str = "com.microsoft.bmp";
/// UTI for TIFF images on macOS (read-only, for native macOS apps).
const UTI_TIFF: &str = "public.tiff";

/// macOS clipboard backend.
///
/// Uses `NSPasteboard` via the `objc2` crate to read from and write to the
/// local macOS clipboard. Supports text (CF_TEXT, CF_UNICODETEXT) and
/// image (CF_DIB) formats.
///
/// **Thread safety**: `NSPasteboard` must be accessed from the main thread.
/// The caller must ensure `NativeClipboard` methods are invoked on the main thread.
pub struct MacosClipboard;

impl MacosClipboard {
    /// Create a new macOS clipboard backend.
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

    /// Read from the macOS clipboard and encode for the requested format.
    pub fn on_format_data_request(
        &mut self,
        format_id: u32,
    ) -> ClipboardResult<FormatDataResponse> {
        if is_text_format(format_id) {
            let text = read_pasteboard_text().ok_or(ClipboardError::Failed)?;
            let data = utf8_to_rdp(&text, format_id).ok_or(ClipboardError::Failed)?;
            return Ok(FormatDataResponse::Ok(data));
        }

        if is_image_format(format_id) {
            let dib = read_pasteboard_image().ok_or(ClipboardError::Failed)?;
            return Ok(FormatDataResponse::Ok(dib));
        }

        Ok(FormatDataResponse::Fail)
    }

    /// Decode server data and write to the macOS clipboard.
    pub fn on_format_data_response(&mut self, data: &[u8], is_success: bool) {
        if !is_success {
            return;
        }

        // Try image first (DIB data has a BITMAPINFOHEADER starting with biSize >= 40)
        if data.len() >= 40 {
            let bi_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if bi_size >= 40 && write_pasteboard_image(data) {
                return;
            }
        }

        // Fall back to text
        if let Some(text) = rdp_bytes_to_utf8(data) {
            let _ = write_pasteboard_text(&text);
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

/// Read plain text from the macOS general pasteboard.
fn read_pasteboard_text() -> Option<String> {
    let pasteboard = NSPasteboard::generalPasteboard();
    let ns_string_type = NSString::from_str(UTI_PLAIN_TEXT);
    let result = pasteboard.stringForType(&ns_string_type)?;
    Some(result.to_string())
}

/// Write plain text to the macOS general pasteboard.
fn write_pasteboard_text(text: &str) -> bool {
    let pasteboard = NSPasteboard::generalPasteboard();
    pasteboard.clearContents();
    let ns_string = NSString::from_str(text);
    let ns_string_type = NSString::from_str(UTI_PLAIN_TEXT);
    pasteboard.setString_forType(&ns_string, &ns_string_type)
}

/// Read image data from the macOS pasteboard as CF_DIB.
///
/// Tries BMP format first (direct DIB extraction from pasteboard), then
/// TIFF (native macOS format used by most apps). TIFF data is converted
/// to BMP using NSBitmapImageRep when available.
fn read_pasteboard_image() -> Option<Vec<u8>> {
    let pasteboard = NSPasteboard::generalPasteboard();

    // Try BMP format — direct conversion to DIB by stripping the file header.
    let bmp_type = NSString::from_str(UTI_BMP);
    if let Some(bmp_data) = pasteboard.dataForType(&bmp_type) {
        let len = bmp_data.length();
        let mut bytes = vec![0u8; len];
        // SAFETY: bytes buffer has exactly `len` bytes capacity, and bmp_data is valid.
        unsafe {
            bmp_data.getBytes_length(
                std::ptr::NonNull::new(bytes.as_mut_ptr().cast()).unwrap(),
                len,
            );
        }
        return bmp_to_dib(&bytes);
    }

    // Try TIFF format — use NSBitmapImageRep to convert to BMP.
    let tiff_type = NSString::from_str(UTI_TIFF);
    if let Some(tiff_data) = pasteboard.dataForType(&tiff_type) {
        return tiff_data_to_dib(&tiff_data);
    }

    None
}

/// Convert TIFF pasteboard data to CF_DIB using NSBitmapImageRep.
fn tiff_data_to_dib(tiff_data: &objc2_foundation::NSData) -> Option<Vec<u8>> {
    use objc2_app_kit::{NSBitmapImageFileType, NSBitmapImageRep};
    use objc2_foundation::NSDictionary;

    let rep = NSBitmapImageRep::initWithData(NSBitmapImageRep::alloc(), tiff_data)?;

    let properties = NSDictionary::new();
    // SAFETY: rep is a valid NSBitmapImageRep. BMP is a well-supported output format.
    let bmp_data = unsafe {
        rep.representationUsingType_properties(NSBitmapImageFileType::BMP, &properties)
    }?;

    let len = bmp_data.length();
    let mut bytes = vec![0u8; len];
    // SAFETY: bytes buffer has exactly `len` bytes capacity.
    unsafe {
        bmp_data.getBytes_length(
            std::ptr::NonNull::new(bytes.as_mut_ptr().cast()).unwrap(),
            len,
        );
    }

    bmp_to_dib(&bytes)
}

/// Write CF_DIB image data to the macOS pasteboard as BMP.
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
