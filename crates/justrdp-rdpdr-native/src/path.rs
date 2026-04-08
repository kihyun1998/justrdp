use std::path::{Component, Path, PathBuf};

/// Convert an RDP path to a local filesystem path relative to `root`.
///
/// RDP paths use backslash separators (e.g., `\dir\file.txt`).
/// This function strips leading separators and trailing null characters,
/// replaces backslashes with the OS path separator, and validates that
/// no `..` components are present (to prevent directory traversal).
///
/// Returns `None` if the path attempts directory traversal.
pub fn rdp_to_local(root: &Path, rdp_path: &str) -> Option<PathBuf> {
    // Strip trailing null characters (RDP paths from UTF-16LE may have them)
    let trimmed = rdp_path.trim_end_matches('\0');

    // Strip leading separators
    let trimmed = trimmed.trim_start_matches(['\\', '/']);

    // Empty or root path maps to the root directory itself
    if trimmed.is_empty() {
        return Some(root.to_path_buf());
    }

    // Replace backslashes with forward slashes for uniform handling
    let normalized = trimmed.replace('\\', "/");

    let relative = Path::new(&normalized);

    // Reject any component that could escape the root:
    // - ParentDir (..) allows traversal
    // - Prefix (C:, \\server\share) produces absolute paths that override root on join
    // - RootDir (leading /) also creates absolute paths
    for component in relative.components() {
        match component {
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => return None,
            _ => {}
        }
    }

    Some(root.join(relative))
}

/// Convert a local filename to UTF-16LE bytes (no null terminator).
///
/// Used for directory info FileName fields in RDP responses.
pub fn encode_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|code_unit| code_unit.to_le_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn normal_path() {
        let root = Path::new("/mnt/share");
        let result = rdp_to_local(root, r"\dir\file.txt").unwrap();
        assert_eq!(result, root.join("dir/file.txt"));
    }

    #[test]
    fn root_path() {
        let root = Path::new("/mnt/share");
        let result = rdp_to_local(root, r"\").unwrap();
        assert_eq!(result, root.to_path_buf());
    }

    #[test]
    fn empty_path() {
        let root = Path::new("/mnt/share");
        let result = rdp_to_local(root, "").unwrap();
        assert_eq!(result, root.to_path_buf());
    }

    #[test]
    fn traversal_rejected() {
        let root = Path::new("/mnt/share");
        assert!(rdp_to_local(root, r"\..\secret").is_none());
        assert!(rdp_to_local(root, r"\dir\..\..\etc\passwd").is_none());
    }

    #[test]
    fn bare_traversal_rejected() {
        let root = Path::new("/mnt/share");
        assert!(rdp_to_local(root, r"..\secret").is_none());
    }

    #[test]
    fn path_with_trailing_null() {
        let root = Path::new("/mnt/share");
        let result = rdp_to_local(root, "\\dir\\file.txt\0").unwrap();
        assert_eq!(result, root.join("dir/file.txt"));
    }

    #[test]
    fn path_with_multiple_trailing_nulls() {
        let root = Path::new("/mnt/share");
        let result = rdp_to_local(root, "\\dir\\file.txt\0\0\0").unwrap();
        assert_eq!(result, root.join("dir/file.txt"));
    }

    #[test]
    fn nested_path() {
        let root = Path::new("/mnt/share");
        let result = rdp_to_local(root, r"\a\b\c\d.txt").unwrap();
        assert_eq!(result, root.join("a/b/c/d.txt"));
    }

    #[test]
    fn path_with_forward_slash() {
        let root = Path::new("/mnt/share");
        let result = rdp_to_local(root, "/dir/file.txt").unwrap();
        assert_eq!(result, root.join("dir/file.txt"));
    }

    #[test]
    fn encode_utf16le_hello() {
        let bytes = encode_utf16le("hello");
        // 'h'=0x0068, 'e'=0x0065, 'l'=0x006C, 'l'=0x006C, 'o'=0x006F
        let expected: Vec<u8> = vec![
            0x68, 0x00, // h
            0x65, 0x00, // e
            0x6C, 0x00, // l
            0x6C, 0x00, // l
            0x6F, 0x00, // o
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn encode_utf16le_dot() {
        let bytes = encode_utf16le(".");
        assert_eq!(bytes, vec![0x2E, 0x00]); // '.'=0x002E
    }

    #[test]
    fn encode_utf16le_dotdot() {
        let bytes = encode_utf16le("..");
        assert_eq!(bytes, vec![0x2E, 0x00, 0x2E, 0x00]);
    }

    #[test]
    fn encode_utf16le_empty() {
        let bytes = encode_utf16le("");
        assert!(bytes.is_empty());
    }

    #[test]
    fn encode_utf16le_non_ascii() {
        // Korean character '한' = U+D55C → UTF-16LE: 0x5C 0xD5
        let bytes = encode_utf16le("한");
        assert_eq!(bytes, vec![0x5C, 0xD5]);
    }
}
