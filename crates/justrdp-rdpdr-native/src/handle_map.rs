use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;

use justrdp_rdpdr::FileHandle;

/// Metadata for a single directory entry, captured during enumeration.
#[derive(Debug)]
pub struct DirEntry {
    pub name: String,
    pub metadata: std::fs::Metadata,
}

/// Tracks directory enumeration state for a single open directory handle.
#[derive(Debug)]
pub struct DirState {
    pub entries: Vec<DirEntry>,
    pub cursor: usize,
}

/// A file or directory that is currently open via the native backend.
#[derive(Debug)]
pub struct OpenEntry {
    pub file: File,
    pub path: PathBuf,
    pub is_dir: bool,
    pub delete_on_close: bool,
    pub dir_state: Option<DirState>,
}

/// Maps RDP file handles (`FileHandle(u32)`) to native OS open entries.
///
/// Handle 0 is reserved and never assigned (it is used as "no handle" in
/// error responses). The first assigned handle is 1.
#[derive(Debug)]
pub struct HandleMap {
    map: HashMap<u32, OpenEntry>,
    next_id: u32,
}

impl HandleMap {
    /// Creates a new, empty handle map. The first handle assigned will be 1.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            next_id: 1,
        }
    }

    /// Maximum number of concurrently open handles.
    const MAX_OPEN_HANDLES: usize = 4096;

    /// Inserts a new open file/directory and returns the assigned `FileHandle`.
    ///
    /// Returns `None` if the maximum number of open handles has been reached.
    pub fn insert(
        &mut self,
        file: File,
        path: PathBuf,
        is_dir: bool,
        delete_on_close: bool,
    ) -> Option<FileHandle> {
        if self.map.len() >= Self::MAX_OPEN_HANDLES {
            return None;
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        // Skip 0 — it is reserved.
        if self.next_id == 0 {
            self.next_id = 1;
        }

        let entry = OpenEntry {
            file,
            path,
            is_dir,
            delete_on_close,
            dir_state: None,
        };

        self.map.insert(id, entry);

        Some(FileHandle(id))
    }

    /// Returns a reference to the entry for the given handle, if it exists.
    pub fn get(&self, handle: &FileHandle) -> Option<&OpenEntry> {
        self.map.get(&handle.0)
    }

    /// Returns a mutable reference to the entry for the given handle, if it exists.
    pub fn get_mut(&mut self, handle: &FileHandle) -> Option<&mut OpenEntry> {
        self.map.get_mut(&handle.0)
    }

    /// Removes and returns the entry for the given handle, if it exists.
    pub fn remove(&mut self, handle: &FileHandle) -> Option<OpenEntry> {
        self.map.remove(&handle.0)
    }
}

impl Default for HandleMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    fn temp_file() -> (File, PathBuf) {
        let path = std::env::temp_dir().join(format!("justrdp_test_{}", std::process::id()));
        let file = File::create(&path).expect("failed to create temp file");
        (file, path)
    }

    #[test]
    fn insert_returns_nonzero_handle() {
        let mut map = HandleMap::new();
        let (file, path) = temp_file();
        let handle = map.insert(file, path.clone(), false, false).unwrap();
        assert_ne!(handle.0, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn get_returns_inserted_entry() {
        let mut map = HandleMap::new();
        let (file, path) = temp_file();
        let handle = map.insert(file, path.clone(), true, false).unwrap();

        let entry = map.get(&handle).expect("entry should exist");
        assert_eq!(entry.path, path);
        assert!(entry.is_dir);
        assert!(!entry.delete_on_close);
        assert!(entry.dir_state.is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn get_mut_allows_modification() {
        let mut map = HandleMap::new();
        let (file, path) = temp_file();
        let handle = map.insert(file, path.clone(), false, false).unwrap();

        let entry = map.get_mut(&handle).expect("entry should exist");
        entry.delete_on_close = true;

        let entry = map.get(&handle).expect("entry should exist");
        assert!(entry.delete_on_close);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_returns_entry_and_clears() {
        let mut map = HandleMap::new();
        let (file, path) = temp_file();
        let handle = map.insert(file, path.clone(), false, false).unwrap();

        let entry = map.remove(&handle).expect("entry should exist");
        assert_eq!(entry.path, path);

        assert!(map.get(&handle).is_none());
        assert!(map.remove(&handle).is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn get_unknown_handle_returns_none() {
        let map = HandleMap::new();
        assert!(map.get(&FileHandle(42)).is_none());
    }

    #[test]
    fn handles_increment() {
        let mut map = HandleMap::new();

        let (f1, p1) = temp_file();
        let h1 = map.insert(f1, p1.clone(), false, false).unwrap();

        let (f2, p2) = temp_file();
        let h2 = map.insert(f2, p2.clone(), false, false).unwrap();

        assert_eq!(h1.0 + 1, h2.0);

        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn insert_with_delete_on_close() {
        let mut map = HandleMap::new();
        let (file, path) = temp_file();
        let handle = map.insert(file, path.clone(), false, true).unwrap();

        let entry = map.get(&handle).unwrap();
        assert!(entry.delete_on_close);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn insert_rejects_when_full() {
        let mut map = HandleMap::new();
        // Fill to capacity
        for _ in 0..HandleMap::MAX_OPEN_HANDLES {
            let (file, path) = temp_file();
            assert!(map.insert(file, path, false, false).is_some());
        }
        // Next insert should fail
        let (file, path) = temp_file();
        assert!(map.insert(file, path.clone(), false, false).is_none());
        let _ = std::fs::remove_file(&path);
    }
}
