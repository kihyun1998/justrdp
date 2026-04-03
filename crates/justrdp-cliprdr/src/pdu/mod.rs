#![forbid(unsafe_code)]

//! Clipboard PDU types -- MS-RDPECLIP 2.2

mod header;
mod caps;
mod format_data;
mod format_list;
mod file_contents;
mod file_list;
mod lock;
mod temp_dir;
mod util;

pub use header::{ClipboardHeader, ClipboardMsgFlags, ClipboardMsgType};
pub use caps::{
    ClipboardCapsPdu, GeneralCapabilitySet, GeneralCapabilityFlags,
    CB_CAPS_VERSION_1, CB_CAPS_VERSION_2,
};
pub use format_data::{FormatDataRequestPdu, FormatDataResponsePdu};
pub use format_list::{
    FormatListPdu, LongFormatName, ShortFormatName, FormatListResponsePdu,
};
pub use file_contents::{
    FileContentsRequestPdu, FileContentsResponsePdu, FileContentsFlags,
};
pub use file_list::{
    FileListPdu, FileDescriptor, FileDescriptorFlags, FileAttributes,
};
pub use lock::{LockClipDataPdu, UnlockClipDataPdu};
pub use temp_dir::TempDirectoryPdu;

/// Standard Windows clipboard format IDs.
/// MS-RDPECLIP 1.3.1.2
pub mod format_id {
    /// ANSI text, null-terminated.
    pub const CF_TEXT: u32 = 0x0001;
    /// Device-dependent bitmap.
    pub const CF_BITMAP: u32 = 0x0002;
    /// Metafile picture.
    pub const CF_METAFILEPICT: u32 = 0x0003;
    /// Symbolic link.
    pub const CF_SYLK: u32 = 0x0004;
    /// Data interchange format.
    pub const CF_DIF: u32 = 0x0005;
    /// Tagged-image file format.
    pub const CF_TIFF: u32 = 0x0006;
    /// OEM text.
    pub const CF_OEMTEXT: u32 = 0x0007;
    /// Device-independent bitmap (BITMAPINFO + pixel data).
    pub const CF_DIB: u32 = 0x0008;
    /// Palette.
    pub const CF_PALETTE: u32 = 0x0009;
    /// Pen data.
    pub const CF_PENDATA: u32 = 0x000A;
    /// RIFF audio.
    pub const CF_RIFF: u32 = 0x000B;
    /// Wave audio.
    pub const CF_WAVE: u32 = 0x000C;
    /// UTF-16LE text, null-terminated.
    pub const CF_UNICODETEXT: u32 = 0x000D;
    /// Enhanced metafile.
    pub const CF_ENHMETAFILE: u32 = 0x000E;
    /// File drop list (maps to CLIPRDR_FILELIST payload).
    pub const CF_HDROP: u32 = 0x000F;
    /// Locale identifier.
    pub const CF_LOCALE: u32 = 0x0010;
    /// Device-independent bitmap v5.
    pub const CF_DIBV5: u32 = 0x0011;
}
