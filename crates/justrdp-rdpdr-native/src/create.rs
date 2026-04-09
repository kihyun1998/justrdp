//! Maps RDP CreateDisposition and DesiredAccess values to `std::fs::OpenOptions`.
//!
//! See MS-SMB2 2.2.13 and MS-RDPEFS 2.2.1.4.1 for wire format details.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

use justrdp_rdpdr::pdu::irp::{
    FILE_CREATE, FILE_OPEN, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE,
};

// ── DesiredAccess constants (MS-SMB2 2.2.13.1.1) ───────────────────────────

const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
// ── CreateOptions constants (MS-SMB2 2.2.13) ───────────────────────────────

pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

// ── CreateResponse information values (MS-RDPEFS 2.2.1.5.1) ────────────────

pub const FILE_SUPERSEDED: u8 = 0x00;
pub const FILE_OPENED: u8 = 0x01;
pub const FILE_CREATED: u8 = 0x02;
pub const FILE_OVERWRITTEN: u8 = 0x03;

// ── Public API ──────────────────────────────────────────────────────────────

/// Result of opening a file/directory.
#[derive(Debug)]
pub struct OpenResult {
    pub file: File,
    pub is_dir: bool,
    pub information: u8,
    pub delete_on_close: bool,
}

/// Open or create a file/directory based on RDP create parameters.
///
/// `path` is the resolved local filesystem path.
pub fn open_file(
    path: &Path,
    desired_access: u32,
    create_disposition: u32,
    create_options: u32,
    _file_attributes: u32,
) -> io::Result<OpenResult> {
    let delete_on_close = create_options & FILE_DELETE_ON_CLOSE != 0;
    let is_directory_request = create_options & FILE_DIRECTORY_FILE != 0;
    let is_non_directory_request = create_options & FILE_NON_DIRECTORY_FILE != 0;

    // If FILE_NON_DIRECTORY_FILE is set but the target is an existing directory, fail.
    if is_non_directory_request && path.is_dir() {
        return Err(io::Error::other(
            "FILE_NON_DIRECTORY_FILE set but target is a directory",
        ));
    }

    if is_directory_request {
        return open_directory(path, create_disposition, delete_on_close);
    }

    open_regular_file(path, desired_access, create_disposition, delete_on_close)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Open a directory as a `File` handle.
///
/// On Windows, directories require `FILE_FLAG_BACKUP_SEMANTICS` (0x0200_0000).
fn open_dir_handle(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        OpenOptions::new()
            .read(true)
            .custom_flags(0x0200_0000) // FILE_FLAG_BACKUP_SEMANTICS
            .open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

// ── Directory handling ──────────────────────────────────────────────────────

fn open_directory(
    path: &Path,
    create_disposition: u32,
    delete_on_close: bool,
) -> io::Result<OpenResult> {
    match create_disposition {
        FILE_CREATE => {
            // Atomic: create_dir fails with AlreadyExists if the directory exists.
            match fs::create_dir(path) {
                Ok(()) => {
                    let file = open_dir_handle(path)?;
                    Ok(OpenResult {
                        file,
                        is_dir: true,
                        information: FILE_CREATED,
                        delete_on_close,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(e),
                Err(e) => {
                    // Parent may not exist — try create_dir_all then re-check atomically.
                    fs::create_dir_all(path).map_err(|_| e)?;
                    let file = open_dir_handle(path)?;
                    Ok(OpenResult {
                        file,
                        is_dir: true,
                        information: FILE_CREATED,
                        delete_on_close,
                    })
                }
            }
        }
        FILE_OPEN => {
            // Atomic: open_dir_handle fails with NotFound if it doesn't exist.
            let file = open_dir_handle(path)?;
            Ok(OpenResult {
                file,
                is_dir: true,
                information: FILE_OPENED,
                delete_on_close,
            })
        }
        FILE_OPEN_IF => {
            // Try to open first; if not found, create and report.
            match open_dir_handle(path) {
                Ok(file) => Ok(OpenResult {
                    file,
                    is_dir: true,
                    information: FILE_OPENED,
                    delete_on_close,
                }),
                Err(_) => {
                    fs::create_dir_all(path)?;
                    let file = open_dir_handle(path)?;
                    Ok(OpenResult {
                        file,
                        is_dir: true,
                        information: FILE_CREATED,
                        delete_on_close,
                    })
                }
            }
        }
        FILE_OVERWRITE => {
            // Directory must exist — open atomically (same as FILE_OPEN for dirs).
            let file = open_dir_handle(path)?;
            Ok(OpenResult {
                file,
                is_dir: true,
                information: FILE_OVERWRITTEN,
                delete_on_close,
            })
        }
        FILE_SUPERSEDE | FILE_OVERWRITE_IF => {
            // Open if exists, create if not. Infer information from which path succeeded.
            match open_dir_handle(path) {
                Ok(file) => {
                    let information = match create_disposition {
                        FILE_SUPERSEDE => FILE_SUPERSEDED,
                        _ => FILE_OVERWRITTEN,
                    };
                    Ok(OpenResult {
                        file,
                        is_dir: true,
                        information,
                        delete_on_close,
                    })
                }
                Err(_) => {
                    fs::create_dir_all(path)?;
                    let file = open_dir_handle(path)?;
                    Ok(OpenResult {
                        file,
                        is_dir: true,
                        information: FILE_CREATED,
                        delete_on_close,
                    })
                }
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid create disposition",
        )),
    }
}

// ── Regular file handling ───────────────────────────────────────────────────

fn open_regular_file(
    path: &Path,
    desired_access: u32,
    create_disposition: u32,
    delete_on_close: bool,
) -> io::Result<OpenResult> {
    let need_write = desired_access
        & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL)
        != 0;
    let need_read = desired_access
        & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL | MAXIMUM_ALLOWED)
        != 0
        || !need_write; // default to read if no specific flags

    let mut opts = OpenOptions::new();
    opts.read(need_read).write(need_write);

    if desired_access & FILE_APPEND_DATA != 0 {
        opts.append(true);
    }

    match create_disposition {
        FILE_SUPERSEDE => {
            // Try create_new first to distinguish created vs superseded atomically.
            opts.write(true).create_new(true);
            match opts.open(path) {
                Ok(file) => Ok(OpenResult {
                    file,
                    is_dir: false,
                    information: FILE_CREATED,
                    delete_on_close,
                }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // File existed — reopen with truncate.
                    let mut opts2 = OpenOptions::new();
                    opts2.read(need_read).write(true).truncate(true);
                    let file = opts2.open(path)?;
                    Ok(OpenResult {
                        file,
                        is_dir: false,
                        information: FILE_SUPERSEDED,
                        delete_on_close,
                    })
                }
                Err(e) => Err(e),
            }
        }
        FILE_OPEN => {
            // Open existing only — open() fails with NotFound atomically.
            let file = opts.open(path)?;
            Ok(OpenResult {
                file,
                is_dir: false,
                information: FILE_OPENED,
                delete_on_close,
            })
        }
        FILE_CREATE => {
            // Create new, fail if exists — create_new is atomic.
            opts.create_new(true);
            if !need_write {
                opts.write(true);
            }
            let file = opts.open(path)?;
            Ok(OpenResult {
                file,
                is_dir: false,
                information: FILE_CREATED,
                delete_on_close,
            })
        }
        FILE_OPEN_IF => {
            // Try create_new to detect creation atomically.
            if !need_write {
                opts.write(true);
            }
            opts.create_new(true);
            match opts.open(path) {
                Ok(file) => Ok(OpenResult {
                    file,
                    is_dir: false,
                    information: FILE_CREATED,
                    delete_on_close,
                }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // File existed — open normally.
                    let mut opts2 = OpenOptions::new();
                    opts2.read(need_read).write(need_write);
                    let file = opts2.open(path)?;
                    Ok(OpenResult {
                        file,
                        is_dir: false,
                        information: FILE_OPENED,
                        delete_on_close,
                    })
                }
                Err(e) => Err(e),
            }
        }
        FILE_OVERWRITE => {
            // Open existing + truncate — open() fails with NotFound atomically.
            opts.truncate(true);
            if !need_write {
                opts.write(true);
            }
            let file = opts.open(path)?;
            Ok(OpenResult {
                file,
                is_dir: false,
                information: FILE_OVERWRITTEN,
                delete_on_close,
            })
        }
        FILE_OVERWRITE_IF => {
            // Try create_new to detect creation atomically.
            if !need_write {
                opts.write(true);
            }
            opts.create_new(true);
            match opts.open(path) {
                Ok(file) => Ok(OpenResult {
                    file,
                    is_dir: false,
                    information: FILE_CREATED,
                    delete_on_close,
                }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // File existed — reopen with truncate.
                    let mut opts2 = OpenOptions::new();
                    opts2.read(need_read).write(true).truncate(true);
                    let file = opts2.open(path)?;
                    Ok(OpenResult {
                        file,
                        is_dir: false,
                        information: FILE_OVERWRITTEN,
                        delete_on_close,
                    })
                }
                Err(e) => Err(e),
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid create disposition",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // ── FILE_OPEN ───────────────────────────────────────────────────────

    #[test]
    fn file_open_existing() {
        let dir = temp_dir();
        let p = dir.path().join("existing.txt");
        fs::write(&p, b"hello").unwrap();

        let res = open_file(&p, FILE_READ_DATA, FILE_OPEN, 0, 0).unwrap();
        assert!(!res.is_dir);
        assert_eq!(res.information, FILE_OPENED);
        assert!(!res.delete_on_close);
    }

    #[test]
    fn file_open_missing_fails() {
        let dir = temp_dir();
        let p = dir.path().join("missing.txt");

        let err = open_file(&p, FILE_READ_DATA, FILE_OPEN, 0, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // ── FILE_CREATE ─────────────────────────────────────────────────────

    #[test]
    fn file_create_new() {
        let dir = temp_dir();
        let p = dir.path().join("new.txt");

        let res = open_file(&p, FILE_WRITE_DATA, FILE_CREATE, 0, 0).unwrap();
        assert!(!res.is_dir);
        assert_eq!(res.information, FILE_CREATED);
        assert!(p.exists());
    }

    #[test]
    fn file_create_already_exists_fails() {
        let dir = temp_dir();
        let p = dir.path().join("exists.txt");
        fs::write(&p, b"data").unwrap();

        let err = open_file(&p, FILE_WRITE_DATA, FILE_CREATE, 0, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    // ── FILE_OPEN_IF ────────────────────────────────────────────────────

    #[test]
    fn file_open_if_existing() {
        let dir = temp_dir();
        let p = dir.path().join("existing.txt");
        fs::write(&p, b"data").unwrap();

        let res = open_file(&p, FILE_READ_DATA, FILE_OPEN_IF, 0, 0).unwrap();
        assert_eq!(res.information, FILE_OPENED);
    }

    #[test]
    fn file_open_if_creates_new() {
        let dir = temp_dir();
        let p = dir.path().join("new.txt");

        let res = open_file(&p, FILE_WRITE_DATA, FILE_OPEN_IF, 0, 0).unwrap();
        assert_eq!(res.information, FILE_CREATED);
        assert!(p.exists());
    }

    // ── FILE_SUPERSEDE ──────────────────────────────────────────────────

    #[test]
    fn file_supersede_existing_truncates() {
        let dir = temp_dir();
        let p = dir.path().join("target.txt");
        fs::write(&p, b"old data").unwrap();

        let res = open_file(&p, FILE_WRITE_DATA, FILE_SUPERSEDE, 0, 0).unwrap();
        assert_eq!(res.information, FILE_SUPERSEDED);
        drop(res);
        assert_eq!(fs::read(&p).unwrap().len(), 0);
    }

    #[test]
    fn file_supersede_creates_new() {
        let dir = temp_dir();
        let p = dir.path().join("new.txt");

        let res = open_file(&p, FILE_WRITE_DATA, FILE_SUPERSEDE, 0, 0).unwrap();
        assert_eq!(res.information, FILE_CREATED);
        assert!(p.exists());
    }

    // ── FILE_OVERWRITE ──────────────────────────────────────────────────

    #[test]
    fn file_overwrite_existing() {
        let dir = temp_dir();
        let p = dir.path().join("target.txt");
        fs::write(&p, b"old data").unwrap();

        let res = open_file(&p, FILE_WRITE_DATA, FILE_OVERWRITE, 0, 0).unwrap();
        assert_eq!(res.information, FILE_OVERWRITTEN);
        drop(res);
        assert_eq!(fs::read(&p).unwrap().len(), 0);
    }

    #[test]
    fn file_overwrite_missing_fails() {
        let dir = temp_dir();
        let p = dir.path().join("missing.txt");

        let err = open_file(&p, FILE_WRITE_DATA, FILE_OVERWRITE, 0, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // ── FILE_OVERWRITE_IF ───────────────────────────────────────────────

    #[test]
    fn file_overwrite_if_existing() {
        let dir = temp_dir();
        let p = dir.path().join("target.txt");
        fs::write(&p, b"old data").unwrap();

        let res = open_file(&p, FILE_WRITE_DATA, FILE_OVERWRITE_IF, 0, 0).unwrap();
        assert_eq!(res.information, FILE_OVERWRITTEN);
        drop(res);
        assert_eq!(fs::read(&p).unwrap().len(), 0);
    }

    #[test]
    fn file_overwrite_if_creates_new() {
        let dir = temp_dir();
        let p = dir.path().join("new.txt");

        let res = open_file(&p, FILE_WRITE_DATA, FILE_OVERWRITE_IF, 0, 0).unwrap();
        assert_eq!(res.information, FILE_CREATED);
        assert!(p.exists());
    }

    // ── Directory operations ────────────────────────────────────────────

    #[test]
    fn dir_open_existing() {
        let dir = temp_dir();
        let p = dir.path().join("subdir");
        fs::create_dir(&p).unwrap();

        let res = open_file(&p, FILE_READ_DATA, FILE_OPEN, FILE_DIRECTORY_FILE, 0).unwrap();
        assert!(res.is_dir);
        assert_eq!(res.information, FILE_OPENED);
    }

    #[test]
    fn dir_open_missing_fails() {
        let dir = temp_dir();
        let p = dir.path().join("nope");

        let err = open_file(&p, FILE_READ_DATA, FILE_OPEN, FILE_DIRECTORY_FILE, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn dir_create_new() {
        let dir = temp_dir();
        let p = dir.path().join("newdir");

        let res = open_file(&p, FILE_READ_DATA, FILE_CREATE, FILE_DIRECTORY_FILE, 0).unwrap();
        assert!(res.is_dir);
        assert_eq!(res.information, FILE_CREATED);
        assert!(p.is_dir());
    }

    #[test]
    fn dir_create_already_exists_fails() {
        let dir = temp_dir();
        let p = dir.path().join("existing");
        fs::create_dir(&p).unwrap();

        let err =
            open_file(&p, FILE_READ_DATA, FILE_CREATE, FILE_DIRECTORY_FILE, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn dir_open_if_creates() {
        let dir = temp_dir();
        let p = dir.path().join("maybe");

        let res = open_file(&p, FILE_READ_DATA, FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0).unwrap();
        assert!(res.is_dir);
        assert_eq!(res.information, FILE_CREATED);
        assert!(p.is_dir());
    }

    #[test]
    fn dir_open_if_opens_existing() {
        let dir = temp_dir();
        let p = dir.path().join("existing");
        fs::create_dir(&p).unwrap();

        let res = open_file(&p, FILE_READ_DATA, FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0).unwrap();
        assert!(res.is_dir);
        assert_eq!(res.information, FILE_OPENED);
    }

    // ── FILE_OVERWRITE directory ──────────────────────────────────────

    #[test]
    fn dir_overwrite_missing_fails() {
        let dir = temp_dir();
        let p = dir.path().join("nope");

        let err =
            open_file(&p, FILE_READ_DATA, FILE_OVERWRITE, FILE_DIRECTORY_FILE, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn dir_overwrite_existing() {
        let dir = temp_dir();
        let p = dir.path().join("existing");
        fs::create_dir(&p).unwrap();

        let res =
            open_file(&p, FILE_READ_DATA, FILE_OVERWRITE, FILE_DIRECTORY_FILE, 0).unwrap();
        assert!(res.is_dir);
        assert_eq!(res.information, FILE_OVERWRITTEN);
    }

    // ── Delete on close ─────────────────────────────────────────────────

    #[test]
    fn delete_on_close_flag() {
        let dir = temp_dir();
        let p = dir.path().join("del.txt");
        fs::write(&p, b"data").unwrap();

        let res = open_file(&p, FILE_READ_DATA, FILE_OPEN, FILE_DELETE_ON_CLOSE, 0).unwrap();
        assert!(res.delete_on_close);
    }

    // ── FILE_NON_DIRECTORY_FILE guard ───────────────────────────────────

    #[test]
    fn non_directory_file_rejects_directory() {
        let dir = temp_dir();
        let p = dir.path().join("subdir");
        fs::create_dir(&p).unwrap();

        let err =
            open_file(&p, FILE_READ_DATA, FILE_OPEN, FILE_NON_DIRECTORY_FILE, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    // ── Access flags ────────────────────────────────────────────────────

    #[test]
    fn write_access_with_generic_write() {
        let dir = temp_dir();
        let p = dir.path().join("writable.txt");

        let res = open_file(&p, GENERIC_WRITE, FILE_OPEN_IF, 0, 0).unwrap();
        // Should be writable -- write some data to verify.
        let mut f = res.file;
        f.write_all(b"test").unwrap();
    }

    #[test]
    fn write_access_with_generic_all() {
        let dir = temp_dir();
        let p = dir.path().join("all.txt");

        let res = open_file(&p, GENERIC_ALL, FILE_OPEN_IF, 0, 0).unwrap();
        let mut f = res.file;
        f.write_all(b"test").unwrap();
    }

    #[test]
    fn read_access_default_when_no_flags() {
        let dir = temp_dir();
        let p = dir.path().join("default.txt");
        fs::write(&p, b"hello").unwrap();

        // No specific access flags -- should default to read.
        let res = open_file(&p, 0, FILE_OPEN, 0, 0).unwrap();
        assert_eq!(res.information, FILE_OPENED);
    }

    // ── Invalid disposition ─────────────────────────────────────────────

    #[test]
    fn invalid_disposition_fails() {
        let dir = temp_dir();
        let p = dir.path().join("x.txt");
        fs::write(&p, b"data").unwrap();

        let err = open_file(&p, FILE_READ_DATA, 0xFF, 0, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
