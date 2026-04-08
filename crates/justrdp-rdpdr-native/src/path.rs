use std::path::{Component, Path, PathBuf};

/// Convert an RDP path to a local filesystem path relative to `root`.
///
/// RDP paths use backslash separators (e.g., `\dir\file.txt`).
/// This function strips leading separators and trailing null characters,
/// replaces backslashes with the OS path separator, and validates that
/// no `..` components are present (to prevent directory traversal).
///
/// On Unix, symlink validation is performed atomically using `open()` + fd-based
/// path resolution to prevent TOCTOU races between existence checks and
/// canonicalization. On other platforms, a best-effort canonicalize + starts_with
/// check is used.
///
/// Returns `None` if the path attempts directory traversal or escapes root.
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

    let joined = root.join(relative);

    // Validate the resolved path remains within root.
    validate_within_root(&joined, root)
}

/// Validate that `path` resolves within `root`, returning `Some(path)` if valid.
///
/// Uses fd-based path resolution on Unix to avoid TOCTOU races between
/// existence checks and symlink resolution.
#[cfg(unix)]
fn validate_within_root(path: &Path, root: &Path) -> Option<PathBuf> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // If root itself cannot be canonicalized (e.g., doesn't exist), fall back
    // to component-level validation only.
    let root_canonical = match root.canonicalize() {
        Ok(c) => c,
        Err(_) => return Some(path.to_path_buf()),
    };

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;

    // Open the path atomically — open() follows all symlinks in a single
    // syscall, eliminating the TOCTOU window between exists() and canonicalize().
    // O_RDONLY is used because O_PATH is Linux-specific.
    // O_NOFOLLOW is NOT set so symlinks ARE followed (we want the resolved target).
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };

    if fd >= 0 {
        // Path exists — get its real path from the fd.
        let real_path = fd_to_path(fd);
        unsafe {
            libc::close(fd);
        }

        let real = real_path?;
        if !real.starts_with(&root_canonical) {
            return None;
        }
        return Some(path.to_path_buf());
    }

    // open() failed — path likely doesn't exist.
    // Validate the parent directory atomically instead.
    if let Some(parent) = path.parent() {
        let c_parent = CString::new(parent.as_os_str().as_bytes()).ok()?;
        let parent_fd = unsafe {
            libc::open(
                c_parent.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };

        if parent_fd >= 0 {
            let parent_real = fd_to_path(parent_fd);
            unsafe {
                libc::close(parent_fd);
            }

            let real = parent_real?;
            if !real.starts_with(&root_canonical) {
                return None;
            }
        }
        // If parent also doesn't exist, we rely on the component validation
        // above (no .., no absolute paths) as a best-effort guard.
    }

    Some(path.to_path_buf())
}

/// Get the canonical filesystem path for an open file descriptor.
#[cfg(target_os = "macos")]
fn fd_to_path(fd: std::os::unix::io::RawFd) -> Option<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: fd is a valid open file descriptor, buf has PATH_MAX capacity.
    // F_GETPATH writes the null-terminated canonical path into the buffer.
    let ret = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) };
    if ret < 0 {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(PathBuf::from(OsStr::from_bytes(&buf[..len])))
}

/// Get the canonical filesystem path for an open file descriptor.
#[cfg(target_os = "linux")]
fn fd_to_path(fd: std::os::unix::io::RawFd) -> Option<PathBuf> {
    let proc_path = format!("/proc/self/fd/{fd}");
    std::fs::read_link(proc_path).ok()
}

/// Get the canonical filesystem path for an open file descriptor.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn fd_to_path(_fd: std::os::unix::io::RawFd) -> Option<PathBuf> {
    // No portable way to get a path from an fd on other Unix systems.
    // Fall back to None, which causes the parent to skip validation
    // (relying only on component-level checks).
    None
}

/// Best-effort validation on non-Unix platforms (Windows uses different APIs).
#[cfg(not(unix))]
fn validate_within_root(path: &Path, root: &Path) -> Option<PathBuf> {
    if path.exists() {
        let canonical = path.canonicalize().ok()?;
        let root_canonical = root.canonicalize().ok()?;
        if !canonical.starts_with(&root_canonical) {
            return None;
        }
    } else if let Some(parent) = path.parent() {
        if parent.exists() {
            let parent_canonical = parent.canonicalize().ok()?;
            let root_canonical = root.canonicalize().ok()?;
            if !parent_canonical.starts_with(&root_canonical) {
                return None;
            }
        }
    }

    Some(path.to_path_buf())
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
    fn symlink_escape_rejected() {
        // Create a temp dir structure with a symlink pointing outside root.
        let root_dir = std::env::temp_dir().join(format!(
            "justrdp_symlink_test_root_{}",
            std::process::id()
        ));
        let outside_dir = std::env::temp_dir().join(format!(
            "justrdp_symlink_test_outside_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&root_dir);
        let _ = std::fs::create_dir_all(&outside_dir);
        let _ = std::fs::write(outside_dir.join("secret.txt"), b"secret");

        // Create a symlink inside root pointing to outside_dir
        let link_path = root_dir.join("escape");
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&outside_dir, &link_path);
        }
        #[cfg(windows)]
        {
            let _ = std::os::windows::fs::symlink_dir(&outside_dir, &link_path);
        }

        // The symlink itself exists inside root, but resolves outside
        if link_path.exists() {
            let result = rdp_to_local(&root_dir, r"\escape\secret.txt");
            assert!(result.is_none(), "symlink escape should be rejected");
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&root_dir);
        let _ = std::fs::remove_dir_all(&outside_dir);
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
