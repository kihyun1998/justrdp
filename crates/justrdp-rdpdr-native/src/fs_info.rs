//! File information class encoders and decoders for MS-FSCC structures.
//!
//! Encodes metadata into raw little-endian byte buffers for `IRP_MJ_QUERY_INFORMATION`
//! responses and decodes `IRP_MJ_SET_INFORMATION` request buffers.

use std::fs::Metadata;
#[cfg(test)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use justrdp_rdpdr::pdu::irp::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_READONLY,
};

// ── FILETIME ────────────────────────────────────────────────────────────────

/// 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
pub(crate) const FILETIME_UNIX_EPOCH_OFFSET: i64 = 116_444_736_000_000_000;

/// Convert a `SystemTime` to Windows FILETIME (i64).
///
/// Windows FILETIME represents 100-nanosecond intervals since 1601-01-01 UTC.
pub fn system_time_to_filetime(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(dur) => {
            let nanos_100 = dur.as_nanos() / 100;
            // Saturate to i64::MAX for dates far in the future (past ~year 2554)
            let nanos_100_capped = nanos_100.min(i64::MAX as u128);
            (nanos_100_capped as i64).saturating_add(FILETIME_UNIX_EPOCH_OFFSET).max(0)
        }
        Err(err) => {
            // Time is before Unix epoch — compute how far back
            let before = err.duration();
            let nanos_100 = before.as_nanos() / 100;
            let nanos_100_capped = nanos_100.min(i64::MAX as u128);
            let ft = FILETIME_UNIX_EPOCH_OFFSET.saturating_sub(nanos_100_capped as i64);
            ft.max(0)
        }
    }
}

/// Convert Windows FILETIME to `SystemTime`.
///
/// Returns `None` if the FILETIME value is negative or represents a time
/// before the Unix epoch that cannot be represented.
#[cfg(test)]
pub fn filetime_to_system_time(filetime: i64) -> Option<SystemTime> {
    if filetime < 0 {
        return None;
    }

    let relative_to_unix = filetime - FILETIME_UNIX_EPOCH_OFFSET;

    if relative_to_unix >= 0 {
        let nanos = (relative_to_unix as u128) * 100;
        let dur = Duration::from_nanos(nanos.min(u64::MAX as u128) as u64);
        Some(UNIX_EPOCH + dur)
    } else {
        // Before Unix epoch
        let nanos = ((-relative_to_unix) as u128) * 100;
        let dur = Duration::from_nanos(nanos as u64);
        UNIX_EPOCH.checked_sub(dur)
    }
}

// ── File Attributes ─────────────────────────────────────────────────────────

/// Map `std::fs::Metadata` to NT file attributes (MS-FSCC 2.6).
pub fn metadata_to_attributes(metadata: &Metadata) -> u32 {
    metadata_to_attributes_inner(metadata, false)
}

/// Map metadata to attributes, considering the filename for hidden detection.
///
/// On Unix, files starting with `.` are treated as hidden.
pub fn metadata_to_attributes_with_name(metadata: &Metadata, name: &str) -> u32 {
    let is_hidden = name.starts_with('.');
    metadata_to_attributes_inner(metadata, is_hidden)
}

fn metadata_to_attributes_inner(metadata: &Metadata, hidden: bool) -> u32 {
    let mut attrs = 0u32;

    if metadata.is_dir() {
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    }

    if is_readonly(metadata) {
        attrs |= FILE_ATTRIBUTE_READONLY;
    }

    if hidden {
        attrs |= FILE_ATTRIBUTE_HIDDEN;
    }

    if metadata.is_dir() {
        // Directories: just the directory flag + any other flags (readonly, hidden)
        attrs
    } else if attrs == 0 {
        // Regular file with no special attributes — use ARCHIVE (MS-FSCC 2.6)
        FILE_ATTRIBUTE_ARCHIVE
    } else {
        // Regular file with some attributes — add ARCHIVE
        attrs | FILE_ATTRIBUTE_ARCHIVE
    }
}

#[cfg(windows)]
fn is_readonly(metadata: &Metadata) -> bool {
    metadata.permissions().readonly()
}

#[cfg(unix)]
fn is_readonly(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    // Check if owner write bit is not set
    mode & 0o200 == 0
}

#[cfg(not(any(unix, windows)))]
fn is_readonly(metadata: &Metadata) -> bool {
    metadata.permissions().readonly()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Default allocation unit size in bytes (standard 4 KiB block).
pub const ALLOCATION_UNIT_BYTES: u64 = 4096;

/// Round `size` up to the nearest `block_size` multiple.
pub fn align_allocation(size: u64, block_size: u64) -> i64 {
    if block_size == 0 || size == 0 {
        return 0;
    }
    let aligned = size.div_ceil(block_size) * block_size;
    i64::try_from(aligned).unwrap_or(i64::MAX)
}

fn time_to_filetime_or_zero(time: std::io::Result<SystemTime>) -> i64 {
    match time {
        Ok(t) => system_time_to_filetime(t),
        Err(_) => 0,
    }
}

// ── File Information Class Encoders ─────────────────────────────────────────

/// Encode FILE_BASIC_INFORMATION (class 4) — 40 bytes.
///
/// MS-FSCC 2.4.7
pub fn encode_basic_info(metadata: &Metadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40);

    let creation_time = time_to_filetime_or_zero(metadata.created());
    let last_access_time = time_to_filetime_or_zero(metadata.accessed());
    let last_write_time = time_to_filetime_or_zero(metadata.modified());
    let change_time = last_write_time;
    let file_attributes = metadata_to_attributes(metadata);

    buf.extend_from_slice(&creation_time.to_le_bytes());
    buf.extend_from_slice(&last_access_time.to_le_bytes());
    buf.extend_from_slice(&last_write_time.to_le_bytes());
    buf.extend_from_slice(&change_time.to_le_bytes());
    buf.extend_from_slice(&file_attributes.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved

    buf
}

/// Encode FILE_STANDARD_INFORMATION (class 5) — 24 bytes.
///
/// MS-FSCC 2.4.41
pub fn encode_standard_info(metadata: &Metadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);

    let is_dir = metadata.is_dir();
    let file_size = if is_dir { 0 } else { metadata.len() };
    let allocation_size = align_allocation(file_size, ALLOCATION_UNIT_BYTES);

    buf.extend_from_slice(&allocation_size.to_le_bytes()); // AllocationSize
    buf.extend_from_slice(&(file_size as i64).to_le_bytes()); // EndOfFile
    buf.extend_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
    buf.push(0u8); // DeletePending
    buf.push(if is_dir { 1u8 } else { 0u8 }); // Directory
    buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved

    buf
}

/// Encode FILE_ATTRIBUTE_TAG_INFORMATION (class 35) — 8 bytes.
///
/// MS-FSCC 2.4.6
pub fn encode_attribute_tag_info(metadata: &Metadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);

    let file_attributes = metadata_to_attributes(metadata);

    buf.extend_from_slice(&file_attributes.to_le_bytes()); // FileAttributes
    buf.extend_from_slice(&0u32.to_le_bytes()); // ReparseTag

    buf
}

// ── Set Information Decoders ────────────────────────────────────────────────

/// Parse FILE_END_OF_FILE_INFORMATION (class 20).
///
/// Returns the new file size. The value must be non-negative.
pub fn parse_end_of_file(data: &[u8]) -> Option<u64> {
    if data.len() < 8 {
        return None;
    }
    let value = i64::from_le_bytes(data[..8].try_into().unwrap());
    if value < 0 {
        None
    } else {
        Some(value as u64)
    }
}

/// Parse FILE_DISPOSITION_INFORMATION (class 13).
///
/// Returns the delete-on-close flag.
pub fn parse_disposition(data: &[u8]) -> Option<bool> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0x00 => Some(false),
        0x01 => Some(true),
        _ => None,
    }
}

/// Parse FILE_RENAME_INFORMATION (class 10, TYPE_1).
///
/// Returns `(replace_if_exists, new_name)`.
///
/// Layout:
/// - ReplaceIfExists (1 byte)
/// - Reserved (3 bytes)
/// - RootDirectory (4 bytes) — must be 0
/// - FileNameLength (4 bytes, u32 LE)
/// - FileName (FileNameLength bytes, UTF-16LE, no null terminator)
pub fn parse_rename(data: &[u8]) -> Option<(bool, String)> {
    // Minimum size: 1 + 3 + 4 + 4 = 12 bytes header
    if data.len() < 12 {
        return None;
    }

    let replace_if_exists = data[0] != 0;
    // data[1..4] reserved

    let root_directory = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if root_directory != 0 {
        return None;
    }

    let file_name_length = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;

    // Cap at 32KB to prevent unbounded allocation from malicious server input.
    const MAX_RENAME_NAME_BYTES: usize = 32 * 1024;
    if file_name_length > MAX_RENAME_NAME_BYTES {
        return None;
    }

    if data.len() < 12 + file_name_length {
        return None;
    }

    // file_name_length must be even (UTF-16LE)
    if file_name_length % 2 != 0 {
        return None;
    }

    let name_bytes = &data[12..12 + file_name_length];
    let code_units: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    let name = String::from_utf16(&code_units).ok()?;
    Some((replace_if_exists, name))
}

/// Parsed timestamps and attributes from a FILE_BASIC_INFORMATION set request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicInfoSet {
    /// Creation time. 0 = don't change, -1 = don't update on subsequent ops.
    pub creation_time: i64,
    /// Last access time. 0 = don't change, -1 = don't update on subsequent ops.
    pub last_access_time: i64,
    /// Last write time. 0 = don't change, -1 = don't update on subsequent ops.
    pub last_write_time: i64,
    /// Change time. 0 = don't change, -1 = don't update on subsequent ops.
    pub change_time: i64,
    /// File attributes. 0 = don't change.
    pub file_attributes: u32,
}

/// Parse FILE_BASIC_INFORMATION for set (class 4) — 40 bytes.
///
/// Timestamp value 0 means "don't change". Value -1 means "don't change on subsequent ops".
pub fn parse_basic_info_set(data: &[u8]) -> Option<BasicInfoSet> {
    if data.len() < 40 {
        return None;
    }

    let creation_time = i64::from_le_bytes(data[0..8].try_into().unwrap());
    let last_access_time = i64::from_le_bytes(data[8..16].try_into().unwrap());
    let last_write_time = i64::from_le_bytes(data[16..24].try_into().unwrap());
    let change_time = i64::from_le_bytes(data[24..32].try_into().unwrap());
    let file_attributes = u32::from_le_bytes(data[32..36].try_into().unwrap());

    Some(BasicInfoSet {
        creation_time,
        last_access_time,
        last_write_time,
        change_time,
        file_attributes,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};


    #[test]
    fn filetime_unix_epoch() {
        let ft = system_time_to_filetime(UNIX_EPOCH);
        assert_eq!(ft, 116_444_736_000_000_000);
        assert_eq!(ft, 0x019D_B1DE_D53E_8000);
    }

    #[test]
    fn filetime_year_2000() {
        // 2000-01-01 00:00:00 UTC
        let t = UNIX_EPOCH + Duration::from_secs(946_684_800);
        let ft = system_time_to_filetime(t);
        // Expected: 125_911_584_000_000_000
        assert_eq!(ft, 125_911_584_000_000_000);
    }

    #[test]
    fn filetime_roundtrip() {
        let original = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let ft = system_time_to_filetime(original);
        let recovered = filetime_to_system_time(ft).unwrap();
        // Allow 100ns precision loss
        let diff = if recovered > original {
            recovered.duration_since(original).unwrap()
        } else {
            original.duration_since(recovered).unwrap()
        };
        assert!(diff < Duration::from_micros(1));
    }

    #[test]
    fn filetime_negative_returns_none() {
        assert!(filetime_to_system_time(-1).is_none());
    }

    #[test]
    fn filetime_zero() {
        // FILETIME 0 is 1601-01-01, which is before Unix epoch
        let t = filetime_to_system_time(0);
        assert!(t.is_some());
    }

    #[test]
    fn encode_basic_info_size() {
        let tmp = tempfile();
        let metadata = fs::metadata(tmp.path()).unwrap();
        let buf = encode_basic_info(&metadata);
        assert_eq!(buf.len(), 40);
    }

    #[test]
    fn encode_standard_info_size() {
        let tmp = tempfile();
        let metadata = fs::metadata(tmp.path()).unwrap();
        let buf = encode_standard_info(&metadata);
        assert_eq!(buf.len(), 24);
    }

    #[test]
    fn encode_standard_info_allocation_aligned() {
        let tmp = tempfile();
        // Write some data so len > 0
        std::fs::write(tmp.path(), &[0u8; 5000]).unwrap();
        let metadata = fs::metadata(tmp.path()).unwrap();
        let buf = encode_standard_info(&metadata);
        assert_eq!(buf.len(), 24);

        // AllocationSize (first 8 bytes) should be rounded up to 4096 multiple
        let alloc_size = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(alloc_size, 8192); // 5000 rounds up to 8192

        // EndOfFile (next 8 bytes) should be actual size
        let eof = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(eof, 5000);
    }

    #[test]
    fn encode_standard_info_directory() {
        let dir = tempdir();
        let metadata = fs::metadata(dir.path()).unwrap();
        let buf = encode_standard_info(&metadata);
        assert_eq!(buf.len(), 24);

        // Directory flag at offset 21
        assert_eq!(buf[21], 1);
    }

    #[test]
    fn encode_attribute_tag_info_size() {
        let tmp = tempfile();
        let metadata = fs::metadata(tmp.path()).unwrap();
        let buf = encode_attribute_tag_info(&metadata);
        assert_eq!(buf.len(), 8);

        // ReparseTag (last 4 bytes) should be 0
        let reparse_tag = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(reparse_tag, 0);
    }

    #[test]
    fn attributes_directory() {
        let dir = tempdir();
        let metadata = fs::metadata(dir.path()).unwrap();
        let attrs = metadata_to_attributes(&metadata);
        assert!(attrs & FILE_ATTRIBUTE_DIRECTORY != 0);
    }

    #[test]
    fn attributes_regular_file() {
        let tmp = tempfile();
        let metadata = fs::metadata(tmp.path()).unwrap();
        let attrs = metadata_to_attributes(&metadata);
        // A regular writable file should have ARCHIVE (MS-FSCC 2.6)
        assert!(
            attrs & FILE_ATTRIBUTE_ARCHIVE != 0,
            "Expected ARCHIVE, got 0x{:08X}",
            attrs,
        );
    }

    #[test]
    fn attributes_hidden_dotfile() {
        let tmp = tempfile();
        let metadata = fs::metadata(tmp.path()).unwrap();
        let attrs = metadata_to_attributes_with_name(&metadata, ".hidden_file");
        assert!(attrs & FILE_ATTRIBUTE_HIDDEN != 0);
    }

    #[test]
    fn parse_end_of_file_valid() {
        let data = 4096i64.to_le_bytes();
        assert_eq!(parse_end_of_file(&data), Some(4096));
    }

    #[test]
    fn parse_end_of_file_zero() {
        let data = 0i64.to_le_bytes();
        assert_eq!(parse_end_of_file(&data), Some(0));
    }

    #[test]
    fn parse_end_of_file_negative() {
        let data = (-1i64).to_le_bytes();
        assert_eq!(parse_end_of_file(&data), None);
    }

    #[test]
    fn parse_end_of_file_too_short() {
        let data = [0u8; 4];
        assert_eq!(parse_end_of_file(&data), None);
    }

    #[test]
    fn parse_disposition_true() {
        assert_eq!(parse_disposition(&[0x01]), Some(true));
    }

    #[test]
    fn parse_disposition_false() {
        assert_eq!(parse_disposition(&[0x00]), Some(false));
    }

    #[test]
    fn parse_disposition_invalid() {
        assert_eq!(parse_disposition(&[0x02]), None);
    }

    #[test]
    fn parse_disposition_empty() {
        assert_eq!(parse_disposition(&[]), None);
    }

    #[test]
    fn parse_rename_valid() {
        // "test.txt" in UTF-16LE
        let name = "test.txt";
        let name_utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();

        let mut data = Vec::new();
        data.push(0x01); // ReplaceIfExists = true
        data.extend_from_slice(&[0, 0, 0]); // Reserved
        data.extend_from_slice(&0u32.to_le_bytes()); // RootDirectory
        data.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes()); // FileNameLength
        data.extend_from_slice(&name_utf16); // FileName

        let (replace, parsed_name) = parse_rename(&data).unwrap();
        assert!(replace);
        assert_eq!(parsed_name, "test.txt");
    }

    #[test]
    fn parse_rename_no_replace() {
        let name = "new.txt";
        let name_utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();

        let mut data = Vec::new();
        data.push(0x00); // ReplaceIfExists = false
        data.extend_from_slice(&[0, 0, 0]);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        data.extend_from_slice(&name_utf16);

        let (replace, parsed_name) = parse_rename(&data).unwrap();
        assert!(!replace);
        assert_eq!(parsed_name, "new.txt");
    }

    #[test]
    fn parse_rename_too_short() {
        assert!(parse_rename(&[0; 8]).is_none());
    }

    #[test]
    fn parse_rename_non_zero_root() {
        let mut data = vec![0u8; 12];
        // Set RootDirectory to non-zero
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_rename(&data).is_none());
    }

    #[test]
    fn parse_basic_info_set_valid() {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&100i64.to_le_bytes()); // creation
        data.extend_from_slice(&200i64.to_le_bytes()); // access
        data.extend_from_slice(&300i64.to_le_bytes()); // write
        data.extend_from_slice(&400i64.to_le_bytes()); // change
        data.extend_from_slice(&0x20u32.to_le_bytes()); // attributes
        data.extend_from_slice(&0u32.to_le_bytes()); // reserved

        let info = parse_basic_info_set(&data).unwrap();
        assert_eq!(info.creation_time, 100);
        assert_eq!(info.last_access_time, 200);
        assert_eq!(info.last_write_time, 300);
        assert_eq!(info.change_time, 400);
        assert_eq!(info.file_attributes, 0x20);
    }

    #[test]
    fn parse_basic_info_set_dont_change() {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&0i64.to_le_bytes()); // don't change
        data.extend_from_slice(&(-1i64).to_le_bytes()); // don't update
        data.extend_from_slice(&0i64.to_le_bytes());
        data.extend_from_slice(&0i64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
        data.extend_from_slice(&0u32.to_le_bytes()); // Reserved

        let info = parse_basic_info_set(&data).unwrap();
        assert_eq!(info.creation_time, 0);
        assert_eq!(info.last_access_time, -1);
    }

    #[test]
    fn parse_basic_info_set_too_short() {
        let data = [0u8; 39];
        assert!(parse_basic_info_set(&data).is_none());
    }

    #[test]
    fn align_allocation_cases() {
        assert_eq!(align_allocation(0, 4096), 0);
        assert_eq!(align_allocation(1, 4096), 4096);
        assert_eq!(align_allocation(4096, 4096), 4096);
        assert_eq!(align_allocation(4097, 4096), 8192);
        assert_eq!(align_allocation(5000, 4096), 8192);
    }

    // ── Test helpers ────────────────────────────────────────────────────────

    struct TempFile {
        path: std::path::PathBuf,
    }

    impl TempFile {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn unique_id() -> u64 {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn tempfile() -> TempFile {
        let path = std::env::temp_dir().join(format!(
            "justrdp_fsinfo_test_{}_{}", std::process::id(), unique_id()
        ));
        fs::File::create(&path).unwrap();
        TempFile { path }
    }

    fn tempdir() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "justrdp_fsinfo_test_dir_{}_{}", std::process::id(), unique_id()
        ));
        fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }
}
