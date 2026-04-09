//! Encodes MS-FSCC directory information structures as raw bytes for query_directory responses.
//!
//! Supports the following information classes:
//! - `FILE_DIRECTORY_INFORMATION` (0x01)
//! - `FILE_FULL_DIRECTORY_INFORMATION` (0x02)
//! - `FILE_BOTH_DIRECTORY_INFORMATION` (0x03)
//! - `FILE_NAMES_INFORMATION` (0x0C)
//!
//! See MS-FSCC 2.4 for wire format details.

use std::fs::Metadata;

use justrdp_rdpdr::pdu::irp::{
    FILE_BOTH_DIRECTORY_INFORMATION, FILE_DIRECTORY_INFORMATION, FILE_FULL_DIRECTORY_INFORMATION,
    FILE_NAMES_INFORMATION,
};

use crate::fs_info::{
    align_allocation, metadata_to_attributes_with_name, system_time_to_filetime,
    ALLOCATION_UNIT_BYTES,
};
use crate::path::encode_utf16le;

// ── Alignment ──────────────────────────────────────────────────────────────

/// Round `n` up to the next 8-byte boundary (used by `encode_dir_entries` in tests).
#[cfg(test)]
fn align8(n: usize) -> usize {
    (n + 7) & !7
}

// ── Fixed header sizes ─────────────────────────────────────────────────────

/// FILE_DIRECTORY_INFORMATION fixed header size (before FileName).
const DIR_INFO_HEADER: usize = 64;

/// FILE_FULL_DIRECTORY_INFORMATION fixed header size (before FileName).
const FULL_DIR_INFO_HEADER: usize = 68;

/// FILE_BOTH_DIRECTORY_INFORMATION fixed header size (before FileName).
const BOTH_DIR_INFO_HEADER: usize = 94;

/// FILE_NAMES_INFORMATION fixed header size (before FileName).
const NAMES_INFO_HEADER: usize = 12;

// ── Public API ─────────────────────────────────────────────────────────────

/// Encode a single directory entry in the specified information class.
///
/// Returns the raw bytes for this entry (without alignment padding -- caller handles that).
/// `NextEntryOffset` is set to 0. Returns `None` for unsupported information classes.
pub fn encode_dir_entry(
    fs_information_class: u32,
    name: &str,
    metadata: &Metadata,
) -> Option<Vec<u8>> {
    match fs_information_class {
        FILE_DIRECTORY_INFORMATION => Some(encode_file_directory_info(name, metadata)),
        FILE_FULL_DIRECTORY_INFORMATION => Some(encode_file_full_directory_info(name, metadata)),
        FILE_BOTH_DIRECTORY_INFORMATION => Some(encode_file_both_directory_info(name, metadata)),
        FILE_NAMES_INFORMATION => Some(encode_file_names_info(name)),
        _ => None,
    }
}

/// Encode multiple directory entries into a single buffer with 8-byte alignment.
///
/// Each entry's `NextEntryOffset` is set correctly. Last entry has `NextEntryOffset = 0`.
/// Returns `None` for unsupported information classes or if `entries` is empty.
#[cfg(test)]
pub fn encode_dir_entries(
    fs_information_class: u32,
    entries: &[(String, Metadata)],
) -> Option<Vec<u8>> {
    if entries.is_empty() {
        return None;
    }

    // Encode each entry individually.
    let encoded: Vec<Vec<u8>> = entries
        .iter()
        .map(|(name, meta)| encode_dir_entry(fs_information_class, name, meta))
        .collect::<Option<Vec<_>>>()?;

    let count = encoded.len();
    let mut buf = Vec::new();

    for (i, entry) in encoded.into_iter().enumerate() {
        let is_last = i == count - 1;

        if is_last {
            // Last entry: NextEntryOffset = 0 (already 0 from encode_dir_entry), no padding.
            buf.extend_from_slice(&entry);
        } else {
            let aligned_size = align8(entry.len());
            let padding = aligned_size - entry.len();

            // Write entry with NextEntryOffset set to aligned_size.
            let mut padded_entry = entry;
            // Overwrite NextEntryOffset at offset 0 (u32 LE).
            let next_offset = aligned_size as u32;
            padded_entry[0..4].copy_from_slice(&next_offset.to_le_bytes());
            buf.extend_from_slice(&padded_entry);
            // Add zero padding for alignment.
            buf.extend(std::iter::repeat_n(0u8, padding));
        }
    }

    Some(buf)
}

// ── Entry encoders ─────────────────────────────────────────────────────────

/// Write the 60-byte common header shared by classes 1, 2, and 3.
///
/// Layout:
/// ```text
/// NextEntryOffset  (u32)  offset  0
/// FileIndex        (u32)  offset  4
/// CreationTime     (i64)  offset  8
/// LastAccessTime   (i64)  offset 16
/// LastWriteTime    (i64)  offset 24
/// ChangeTime       (i64)  offset 32
/// EndOfFile        (i64)  offset 40
/// AllocationSize   (i64)  offset 48
/// FileAttributes   (u32)  offset 56
/// ```
fn write_common_dir_header(
    buf: &mut Vec<u8>,
    name: &str,
    metadata: &Metadata,
    file_name_length: u32,
) {
    let (creation, last_access, last_write, change) = extract_times(metadata);
    let end_of_file = file_size(metadata);
    let allocation_size = compute_allocation_size(metadata);
    let attrs = metadata_to_attributes_with_name(metadata, name);

    // NextEntryOffset (0 for single entry)
    buf.extend_from_slice(&0u32.to_le_bytes());
    // FileIndex
    buf.extend_from_slice(&0u32.to_le_bytes());
    // CreationTime
    buf.extend_from_slice(&creation.to_le_bytes());
    // LastAccessTime
    buf.extend_from_slice(&last_access.to_le_bytes());
    // LastWriteTime
    buf.extend_from_slice(&last_write.to_le_bytes());
    // ChangeTime
    buf.extend_from_slice(&change.to_le_bytes());
    // EndOfFile
    buf.extend_from_slice(&end_of_file.to_le_bytes());
    // AllocationSize
    buf.extend_from_slice(&allocation_size.to_le_bytes());
    // FileAttributes
    buf.extend_from_slice(&attrs.to_le_bytes());
    // FileNameLength
    buf.extend_from_slice(&file_name_length.to_le_bytes());
}

/// Encode FILE_DIRECTORY_INFORMATION (class 1).
///
/// Header: 64 bytes (common 60 + FileNameLength 4) + FileName.
fn encode_file_directory_info(name: &str, metadata: &Metadata) -> Vec<u8> {
    let file_name_bytes = encode_utf16le(name);
    let mut buf = Vec::with_capacity(DIR_INFO_HEADER + file_name_bytes.len());
    write_common_dir_header(&mut buf, name, metadata, file_name_bytes.len() as u32);
    buf.extend_from_slice(&file_name_bytes);
    buf
}

/// Encode FILE_FULL_DIRECTORY_INFORMATION (class 2).
///
/// Same as class 1 with an additional EaSize (u32) field.
/// Header: 68 bytes + FileName.
fn encode_file_full_directory_info(name: &str, metadata: &Metadata) -> Vec<u8> {
    let file_name_bytes = encode_utf16le(name);
    let mut buf = Vec::with_capacity(FULL_DIR_INFO_HEADER + file_name_bytes.len());
    write_common_dir_header(&mut buf, name, metadata, file_name_bytes.len() as u32);
    // EaSize
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&file_name_bytes);
    buf
}

/// Encode FILE_BOTH_DIRECTORY_INFORMATION (class 3).
///
/// Same as class 2 with additional ShortNameLength (u8), Reserved (u8),
/// and ShortName (24 bytes) after EaSize.
/// Header: 94 bytes + FileName.
fn encode_file_both_directory_info(name: &str, metadata: &Metadata) -> Vec<u8> {
    let file_name_bytes = encode_utf16le(name);
    let mut buf = Vec::with_capacity(BOTH_DIR_INFO_HEADER + file_name_bytes.len());
    write_common_dir_header(&mut buf, name, metadata, file_name_bytes.len() as u32);
    // EaSize
    buf.extend_from_slice(&0u32.to_le_bytes());
    // ShortNameLength
    buf.push(0u8);
    // Reserved
    buf.push(0u8);
    // ShortName (24 bytes, zero-filled)
    buf.extend_from_slice(&[0u8; 24]);
    buf.extend_from_slice(&file_name_bytes);
    buf
}

/// Encode FILE_NAMES_INFORMATION (class 12).
///
/// Layout (12 bytes header + FileName):
/// ```text
/// NextEntryOffset  (u32)  offset 0
/// FileIndex        (u32)  offset 4
/// FileNameLength   (u32)  offset 8
/// FileName         (var)  offset 12
/// ```
fn encode_file_names_info(name: &str) -> Vec<u8> {
    let file_name_bytes = encode_utf16le(name);
    let file_name_length = file_name_bytes.len() as u32;

    let mut buf = Vec::with_capacity(NAMES_INFO_HEADER + file_name_bytes.len());

    // NextEntryOffset
    buf.extend_from_slice(&0u32.to_le_bytes());
    // FileIndex
    buf.extend_from_slice(&0u32.to_le_bytes());
    // FileNameLength
    buf.extend_from_slice(&file_name_length.to_le_bytes());
    // FileName
    buf.extend_from_slice(&file_name_bytes);

    buf
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Extract all four time fields from metadata, converting to Windows FILETIME (i64).
///
/// Falls back to 0 if a time field is not available (e.g., on some platforms).
fn extract_times(metadata: &Metadata) -> (i64, i64, i64, i64) {
    let creation = metadata
        .created()
        .map(system_time_to_filetime)
        .unwrap_or(0);
    let last_access = metadata
        .accessed()
        .map(system_time_to_filetime)
        .unwrap_or(0);
    let last_write = metadata
        .modified()
        .map(system_time_to_filetime)
        .unwrap_or(0);
    // ChangeTime = LastWriteTime (no separate change time in std::fs::Metadata)
    let change = last_write;

    (creation, last_access, last_write, change)
}

/// Get the file size. Directories report 0.
fn file_size(metadata: &Metadata) -> i64 {
    if metadata.is_dir() {
        0
    } else {
        metadata.len() as i64
    }
}

/// Compute the allocation size (rounded up to [`ALLOCATION_UNIT_BYTES`] blocks).
/// Directories report 0.
fn compute_allocation_size(metadata: &Metadata) -> i64 {
    if metadata.is_dir() {
        0
    } else {
        align_allocation(metadata.len(), ALLOCATION_UNIT_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // ── align8 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_align8() {
        assert_eq!(align8(0), 0);
        assert_eq!(align8(1), 8);
        assert_eq!(align8(7), 8);
        assert_eq!(align8(8), 8);
        assert_eq!(align8(9), 16);
        assert_eq!(align8(14), 16);
        assert_eq!(align8(16), 16);
        assert_eq!(align8(17), 24);
    }

    // ── FILE_DIRECTORY_INFORMATION (class 1) ───────────────────────────────

    #[test]
    fn file_directory_info_header_size() {
        let dir = temp_dir();
        let p = dir.path().join("test.txt");
        fs::write(&p, b"hello").unwrap();
        let meta = fs::metadata(&p).unwrap();

        let entry = encode_dir_entry(FILE_DIRECTORY_INFORMATION, "test.txt", &meta).unwrap();
        let name_bytes = encode_utf16le("test.txt");
        assert_eq!(entry.len(), DIR_INFO_HEADER + name_bytes.len());
    }

    #[test]
    fn file_directory_info_next_entry_offset_zero() {
        let dir = temp_dir();
        let p = dir.path().join("a.txt");
        fs::write(&p, b"").unwrap();
        let meta = fs::metadata(&p).unwrap();

        let entry = encode_dir_entry(FILE_DIRECTORY_INFORMATION, "a.txt", &meta).unwrap();
        let next_offset = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        assert_eq!(next_offset, 0);
    }

    // ── FILE_FULL_DIRECTORY_INFORMATION (class 2) ──────────────────────────

    #[test]
    fn file_full_directory_info_header_size() {
        let dir = temp_dir();
        let p = dir.path().join("test.txt");
        fs::write(&p, b"hello").unwrap();
        let meta = fs::metadata(&p).unwrap();

        let entry =
            encode_dir_entry(FILE_FULL_DIRECTORY_INFORMATION, "test.txt", &meta).unwrap();
        let name_bytes = encode_utf16le("test.txt");
        assert_eq!(entry.len(), FULL_DIR_INFO_HEADER + name_bytes.len());
    }

    // ── FILE_BOTH_DIRECTORY_INFORMATION (class 3) ──────────────────────────

    #[test]
    fn file_both_directory_info_header_size() {
        let dir = temp_dir();
        let p = dir.path().join("test.txt");
        fs::write(&p, b"hello").unwrap();
        let meta = fs::metadata(&p).unwrap();

        let entry =
            encode_dir_entry(FILE_BOTH_DIRECTORY_INFORMATION, "test.txt", &meta).unwrap();
        let name_bytes = encode_utf16le("test.txt");
        assert_eq!(entry.len(), BOTH_DIR_INFO_HEADER + name_bytes.len());
    }

    #[test]
    fn file_both_directory_info_short_name_zeroed() {
        let dir = temp_dir();
        let p = dir.path().join("test.txt");
        fs::write(&p, b"hello").unwrap();
        let meta = fs::metadata(&p).unwrap();

        let entry =
            encode_dir_entry(FILE_BOTH_DIRECTORY_INFORMATION, "test.txt", &meta).unwrap();
        // ShortNameLength at offset 68
        assert_eq!(entry[68], 0);
        // Reserved at offset 69
        assert_eq!(entry[69], 0);
        // ShortName (24 bytes) at offset 70..94
        assert_eq!(&entry[70..94], &[0u8; 24]);
    }

    // ── FILE_NAMES_INFORMATION (class 12) ──────────────────────────────────

    #[test]
    fn file_names_info_minimal() {
        let dir = temp_dir();
        let p = dir.path().join("x");
        fs::write(&p, b"").unwrap();
        let meta = fs::metadata(&p).unwrap();

        let entry = encode_dir_entry(FILE_NAMES_INFORMATION, "x", &meta).unwrap();
        let name_bytes = encode_utf16le("x");
        assert_eq!(entry.len(), NAMES_INFO_HEADER + name_bytes.len());
        // 12 bytes header + 2 bytes filename ("x" in UTF-16LE)
        assert_eq!(entry.len(), 14);
    }

    #[test]
    fn file_names_info_filename_length_field() {
        let dir = temp_dir();
        let p = dir.path().join("abc.txt");
        fs::write(&p, b"").unwrap();
        let meta = fs::metadata(&p).unwrap();

        let entry = encode_dir_entry(FILE_NAMES_INFORMATION, "abc.txt", &meta).unwrap();
        // FileNameLength at offset 8
        let name_len = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
        assert_eq!(name_len as usize, encode_utf16le("abc.txt").len());
    }

    // ── Unsupported class ──────────────────────────────────────────────────

    #[test]
    fn unsupported_class_returns_none() {
        let dir = temp_dir();
        let p = dir.path().join("x");
        fs::write(&p, b"").unwrap();
        let meta = fs::metadata(&p).unwrap();

        assert!(encode_dir_entry(0xFF, "x", &meta).is_none());
    }

    // ── encode_dir_entries ─────────────────────────────────────────────────

    #[test]
    fn empty_entries_returns_none() {
        assert!(encode_dir_entries(FILE_DIRECTORY_INFORMATION, &[]).is_none());
    }

    #[test]
    fn single_entry_no_padding() {
        let dir = temp_dir();
        let p = dir.path().join("file.txt");
        fs::write(&p, b"data").unwrap();
        let meta = fs::metadata(&p).unwrap();

        let entries = vec![("file.txt".to_string(), meta.clone())];
        let buf = encode_dir_entries(FILE_DIRECTORY_INFORMATION, &entries).unwrap();

        // Single entry: same as encode_dir_entry, no padding.
        let single = encode_dir_entry(FILE_DIRECTORY_INFORMATION, "file.txt", &meta).unwrap();
        assert_eq!(buf.len(), single.len());

        // NextEntryOffset should be 0 (last/only entry).
        let next_offset = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(next_offset, 0);
    }

    #[test]
    fn multiple_entries_alignment() {
        let dir = temp_dir();

        // Create two files with different name lengths.
        let p1 = dir.path().join("a.txt");
        fs::write(&p1, b"hello").unwrap();
        let m1 = fs::metadata(&p1).unwrap();

        let p2 = dir.path().join("bb.txt");
        fs::write(&p2, b"world!").unwrap();
        let m2 = fs::metadata(&p2).unwrap();

        let entries = vec![
            ("a.txt".to_string(), m1.clone()),
            ("bb.txt".to_string(), m2.clone()),
        ];

        let buf = encode_dir_entries(FILE_DIRECTORY_INFORMATION, &entries).unwrap();

        // First entry raw size.
        let e1 = encode_dir_entry(FILE_DIRECTORY_INFORMATION, "a.txt", &m1).unwrap();
        let e1_aligned = align8(e1.len());

        // NextEntryOffset of first entry should be aligned size.
        let next_offset = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(next_offset as usize, e1_aligned);

        // Second entry starts at e1_aligned, its NextEntryOffset should be 0.
        let next_offset2 = u32::from_le_bytes([
            buf[e1_aligned],
            buf[e1_aligned + 1],
            buf[e1_aligned + 2],
            buf[e1_aligned + 3],
        ]);
        assert_eq!(next_offset2, 0);

        // Total buffer length: aligned first entry + raw second entry.
        let e2 = encode_dir_entry(FILE_DIRECTORY_INFORMATION, "bb.txt", &m2).unwrap();
        assert_eq!(buf.len(), e1_aligned + e2.len());
    }

    #[test]
    fn three_entries_last_has_zero_offset() {
        let dir = temp_dir();

        let p1 = dir.path().join("x");
        fs::write(&p1, b"").unwrap();
        let m1 = fs::metadata(&p1).unwrap();

        let p2 = dir.path().join("yy");
        fs::write(&p2, b"ab").unwrap();
        let m2 = fs::metadata(&p2).unwrap();

        let p3 = dir.path().join("zzz");
        fs::write(&p3, b"abc").unwrap();
        let m3 = fs::metadata(&p3).unwrap();

        let entries = vec![
            ("x".to_string(), m1.clone()),
            ("yy".to_string(), m2.clone()),
            ("zzz".to_string(), m3.clone()),
        ];

        let buf = encode_dir_entries(FILE_NAMES_INFORMATION, &entries).unwrap();

        // Walk entries and verify NextEntryOffset chain.
        let mut offset = 0usize;
        for i in 0..3 {
            let next = u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]);
            if i < 2 {
                assert_ne!(next, 0, "entry {i} should have non-zero NextEntryOffset");
                assert_eq!(next as usize % 8, 0, "entry {i} NextEntryOffset must be 8-byte aligned");
                offset += next as usize;
            } else {
                assert_eq!(next, 0, "last entry should have NextEntryOffset = 0");
            }
        }
    }

    #[test]
    fn padding_bytes_are_zero() {
        let dir = temp_dir();

        // Create a file whose entry length is NOT 8-byte aligned.
        // FILE_NAMES_INFORMATION: 12 + name_len_bytes
        // "x" -> 12 + 2 = 14 bytes (needs 2 bytes padding to reach 16)
        let p = dir.path().join("x");
        fs::write(&p, b"").unwrap();
        let mx = fs::metadata(&p).unwrap();

        let p2 = dir.path().join("y");
        fs::write(&p2, b"").unwrap();
        let my = fs::metadata(&p2).unwrap();

        let entries = vec![("x".to_string(), mx), ("y".to_string(), my)];
        let buf = encode_dir_entries(FILE_NAMES_INFORMATION, &entries).unwrap();

        // First entry is 14 bytes, aligned to 16. Bytes at index 14, 15 should be 0.
        assert_eq!(buf[14], 0);
        assert_eq!(buf[15], 0);
    }
}
