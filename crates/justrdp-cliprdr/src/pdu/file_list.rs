#![forbid(unsafe_code)]

//! CLIPRDR_FILELIST and CLIPRDR_FILEDESCRIPTOR -- MS-RDPECLIP 2.2.5.2.3

use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{ReadCursor, WriteCursor};
use justrdp_core::{DecodeError, DecodeResult, EncodeError, EncodeResult};
use justrdp_core::{Decode, Encode};

use super::util;

/// Size of a single CLIPRDR_FILEDESCRIPTOR -- MS-RDPECLIP 2.2.5.2.3.1
const FILE_DESCRIPTOR_SIZE: usize = 592;

/// File name buffer size (260 UTF-16LE code units = 520 bytes).
const FILE_NAME_BUFFER_SIZE: usize = 520;

/// File descriptor flags -- MS-RDPECLIP 2.2.5.2.3.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDescriptorFlags(u32);

impl FileDescriptorFlags {
    /// No flags.
    pub const NONE: Self = Self(0x0000_0000);
    /// `fileAttributes` field is valid.
    pub const FD_ATTRIBUTES: Self = Self(0x0000_0004);
    /// `lastWriteTime` field is valid.
    pub const FD_WRITESTIME: Self = Self(0x0000_0020);
    /// `fileSizeHigh`/`fileSizeLow` fields are valid.
    pub const FD_FILESIZE: Self = Self(0x0000_0040);
    /// Progress indicator SHOULD be shown during copy.
    pub const FD_SHOWPROGRESSUI: Self = Self(0x0000_4000);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// File attribute flags -- MS-RDPECLIP 2.2.5.2.3.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAttributes(u32);

impl FileAttributes {
    /// Read-only file.
    pub const READONLY: Self = Self(0x0000_0001);
    /// Hidden file.
    pub const HIDDEN: Self = Self(0x0000_0002);
    /// System file.
    pub const SYSTEM: Self = Self(0x0000_0004);
    /// Directory.
    pub const DIRECTORY: Self = Self(0x0000_0010);
    /// Archive file.
    pub const ARCHIVE: Self = Self(0x0000_0020);
    /// Normal file (no other attributes set).
    pub const NORMAL: Self = Self(0x0000_0080);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if an attribute is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// A file descriptor entry -- MS-RDPECLIP 2.2.5.2.3.1
///
/// 592 bytes fixed size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptor {
    /// Bitmask indicating which fields are valid.
    pub flags: FileDescriptorFlags,
    /// Win32 file attributes (valid if FD_ATTRIBUTES is set).
    pub file_attributes: FileAttributes,
    /// Last write time as Windows FILETIME (valid if FD_WRITESTIME is set).
    pub last_write_time: u64,
    /// File size in bytes (valid if FD_FILESIZE is set).
    pub file_size: u64,
    /// File name (no path when CB_FILECLIP_NO_FILE_PATHS is set).
    pub file_name: String,
}

impl FileDescriptor {
    /// Create a new file descriptor.
    pub fn new(file_name: String) -> Self {
        Self {
            flags: FileDescriptorFlags::NONE,
            file_attributes: FileAttributes::from_bits(0),
            last_write_time: 0,
            file_size: 0,
            file_name,
        }
    }

    /// Set the file size and mark the size flag as valid.
    pub fn with_size(mut self, size: u64) -> Self {
        self.file_size = size;
        self.flags = self.flags.union(FileDescriptorFlags::FD_FILESIZE);
        self
    }

    /// Set file attributes and mark the attributes flag as valid.
    pub fn with_attributes(mut self, attrs: FileAttributes) -> Self {
        self.file_attributes = attrs;
        self.flags = self.flags.union(FileDescriptorFlags::FD_ATTRIBUTES);
        self
    }

    /// Set last write time and mark the time flag as valid.
    pub fn with_last_write_time(mut self, time: u64) -> Self {
        self.last_write_time = time;
        self.flags = self.flags.union(FileDescriptorFlags::FD_WRITESTIME);
        self
    }

    /// Encode file name as UTF-16LE into a 520-byte buffer.
    fn encode_file_name(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let mut buf = [0u8; FILE_NAME_BUFFER_SIZE];
        util::encode_utf16le_fixed(&self.file_name, &mut buf);
        dst.write_slice(&buf, "FileDescriptor::fileName")?;
        Ok(())
    }

    /// Decode file name from a 520-byte UTF-16LE buffer.
    fn decode_file_name(name_bytes: &[u8]) -> DecodeResult<String> {
        util::decode_utf16le_null_terminated(name_bytes, "FileDescriptor", "fileName")
    }
}

impl Encode for FileDescriptor {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        dst.write_u32_le(self.flags.bits(), "FileDescriptor::flags")?;
        // reserved1: 32 bytes of zeros
        dst.write_slice(&[0u8; 32], "FileDescriptor::reserved1")?;
        dst.write_u32_le(self.file_attributes.bits(), "FileDescriptor::fileAttributes")?;
        // reserved2: 16 bytes of zeros
        dst.write_slice(&[0u8; 16], "FileDescriptor::reserved2")?;
        dst.write_u64_le(self.last_write_time, "FileDescriptor::lastWriteTime")?;
        dst.write_u32_le(
            (self.file_size >> 32) as u32,
            "FileDescriptor::fileSizeHigh",
        )?;
        dst.write_u32_le(self.file_size as u32, "FileDescriptor::fileSizeLow")?;
        self.encode_file_name(dst)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FileDescriptor"
    }

    fn size(&self) -> usize {
        FILE_DESCRIPTOR_SIZE
    }
}

impl<'de> Decode<'de> for FileDescriptor {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let flags = FileDescriptorFlags::from_bits(src.read_u32_le("FileDescriptor::flags")?);
        src.skip(32, "FileDescriptor::reserved1")?;
        let file_attributes =
            FileAttributes::from_bits(src.read_u32_le("FileDescriptor::fileAttributes")?);
        src.skip(16, "FileDescriptor::reserved2")?;
        let last_write_time = src.read_u64_le("FileDescriptor::lastWriteTime")?;
        let file_size_high = src.read_u32_le("FileDescriptor::fileSizeHigh")?;
        let file_size_low = src.read_u32_le("FileDescriptor::fileSizeLow")?;
        let file_size = ((file_size_high as u64) << 32) | (file_size_low as u64);
        let name_bytes = src.read_slice(FILE_NAME_BUFFER_SIZE, "FileDescriptor::fileName")?;
        let file_name = Self::decode_file_name(name_bytes)?;

        Ok(Self {
            flags,
            file_attributes,
            last_write_time,
            file_size,
            file_name,
        })
    }
}

/// CLIPRDR_FILELIST -- MS-RDPECLIP 2.2.5.2.3
///
/// Contains a count and array of file descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListPdu {
    /// File descriptor entries.
    pub files: Vec<FileDescriptor>,
}

impl FileListPdu {
    /// Create a new file list.
    pub fn new(files: Vec<FileDescriptor>) -> Self {
        Self { files }
    }
}

impl Encode for FileListPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let count = u32::try_from(self.files.len())
            .map_err(|_| EncodeError::invalid_value("FileListPdu", "cItems too large"))?;
        dst.write_u32_le(count, "FileListPdu::cItems")?;
        for file in &self.files {
            file.encode(dst)?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "FileListPdu"
    }

    fn size(&self) -> usize {
        4 + self.files.len() * FILE_DESCRIPTOR_SIZE
    }
}

/// Maximum number of files in a single CLIPRDR_FILELIST.
/// Caps pre-allocation to prevent amplified allocation from untrusted `cItems`.
/// 16 384 × 592 bytes ≈ 9.7 MiB.
const MAX_FILE_LIST_ENTRIES: usize = 16_384;

impl<'de> Decode<'de> for FileListPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let raw_count = src.read_u32_le("FileListPdu::cItems")?;
        if raw_count as usize > MAX_FILE_LIST_ENTRIES {
            return Err(DecodeError::invalid_value("FileListPdu", "cItems exceeds maximum"));
        }
        let count = raw_count as usize;
        let mut files = Vec::with_capacity(count);
        for _ in 0..count {
            files.push(FileDescriptor::decode(src)?);
        }
        Ok(Self { files })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_descriptor_roundtrip() {
        let fd = FileDescriptor::new(String::from("test.txt"))
            .with_size(1024)
            .with_attributes(FileAttributes::NORMAL);

        let mut buf = alloc::vec![0u8; fd.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        fd.encode(&mut cursor).unwrap();
        assert_eq!(buf.len(), FILE_DESCRIPTOR_SIZE);

        let mut cursor = ReadCursor::new(&buf);
        let decoded = FileDescriptor::decode(&mut cursor).unwrap();
        assert_eq!(fd, decoded);
    }

    #[test]
    fn file_list_roundtrip() {
        let fl = FileListPdu::new(alloc::vec![
            FileDescriptor::new(String::from("hello.txt")).with_size(100),
            FileDescriptor::new(String::from("world.txt")).with_size(200),
        ]);

        let mut buf = alloc::vec![0u8; fl.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        fl.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = FileListPdu::decode(&mut cursor).unwrap();
        assert_eq!(fl, decoded);
    }

    #[test]
    fn file_descriptor_size_is_592() {
        assert_eq!(FILE_DESCRIPTOR_SIZE, 592);
        // 4 (flags) + 32 (reserved1) + 4 (attrs) + 16 (reserved2) + 8 (time)
        // + 4 (sizeHigh) + 4 (sizeLow) + 520 (name) = 592
        assert_eq!(4 + 32 + 4 + 16 + 8 + 4 + 4 + 520, 592);
    }

    /// Helper: create a string of exactly `n` BMP characters (all 'A').
    fn make_string(n: usize) -> String {
        core::iter::repeat('A').take(n).collect()
    }

    #[test]
    fn file_name_truncation_259_code_units() {
        // 259 code units fits: 259 data + 1 null = 260 code units = 520 bytes.
        let name = make_string(259);
        let fd = FileDescriptor::new(name.clone());
        let mut buf = alloc::vec![0u8; fd.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        fd.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = FileDescriptor::decode(&mut cursor).unwrap();
        assert_eq!(decoded.file_name, name);
    }

    #[test]
    fn file_name_truncation_260_code_units() {
        // 260 code units would need 260 data + 1 null = 261 × 2 = 522 bytes > 520.
        // The encoder truncates to 259 data code units.
        let name = make_string(260);
        let fd = FileDescriptor::new(name.clone());
        let mut buf = alloc::vec![0u8; fd.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        fd.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = FileDescriptor::decode(&mut cursor).unwrap();
        // Truncated to 259 characters.
        assert_eq!(decoded.file_name.len(), 259);
        assert_eq!(decoded.file_name, make_string(259));
    }

    #[test]
    fn file_name_truncation_261_code_units() {
        // 261 also truncates to 259.
        let name = make_string(261);
        let fd = FileDescriptor::new(name);
        let mut buf = alloc::vec![0u8; fd.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        fd.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let decoded = FileDescriptor::decode(&mut cursor).unwrap();
        assert_eq!(decoded.file_name.len(), 259);
    }
}
