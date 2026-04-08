//! MS-FSCC volume information encoders for query_volume_information responses.

use std::path::Path;

use crate::path::encode_utf16le;

// DeviceType -- MS-FSCC 2.5.1
const FILE_DEVICE_DISK: u32 = 0x0000_0007;

// Characteristics -- MS-FSCC 2.5.1
const FILE_DEVICE_IS_MOUNTED: u32 = 0x0000_0020;

// FileSystemAttributes -- MS-FSCC 2.5.2
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;

/// Platform-specific disk space information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskSpace {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
}

impl DiskSpace {
    /// Query disk space for the given path.
    pub fn query(path: &Path) -> Option<DiskSpace> {
        Self::query_impl(path)
    }

    fn cluster_size(&self) -> u64 {
        u64::from(self.sectors_per_cluster) * u64::from(self.bytes_per_sector)
    }

    #[cfg(windows)]
    fn query_impl(path: &Path) -> Option<DiskSpace> {
        use std::os::windows::ffi::OsStrExt;

        // Encode path as null-terminated UTF-16LE for Windows API
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

        let mut free_bytes_available_to_caller: u64 = 0;
        let mut total_number_of_bytes: u64 = 0;
        let mut total_number_of_free_bytes: u64 = 0;

        // SAFETY: Calling Windows API with valid null-terminated wide string and valid pointers.
        let ret = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free_bytes_available_to_caller,
                &mut total_number_of_bytes,
                &mut total_number_of_free_bytes,
            )
        };

        if ret == 0 {
            return None;
        }

        // Query actual bytes_per_sector and sectors_per_cluster from the filesystem.
        let mut sectors_per_cluster: u32 = 0;
        let mut bytes_per_sector: u32 = 0;
        let mut _number_of_free_clusters: u32 = 0;
        let mut _total_number_of_clusters: u32 = 0;

        // SAFETY: Calling Windows API with valid null-terminated wide string and valid pointers.
        let ret2 = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceW(
                wide.as_ptr(),
                &mut sectors_per_cluster,
                &mut bytes_per_sector,
                &mut _number_of_free_clusters,
                &mut _total_number_of_clusters,
            )
        };

        // If GetDiskFreeSpaceW fails, fall back to reasonable defaults.
        if ret2 == 0 {
            sectors_per_cluster = 8;
            bytes_per_sector = 512;
        }

        Some(DiskSpace {
            total_bytes: total_number_of_bytes,
            free_bytes: total_number_of_free_bytes,
            available_bytes: free_bytes_available_to_caller,
            bytes_per_sector,
            sectors_per_cluster,
        })
    }

    #[cfg(unix)]
    fn query_impl(path: &Path) -> Option<DiskSpace> {
        let c_path = std::ffi::CString::new(path.to_str()?).ok()?;

        // SAFETY: `statvfs` is called with a valid null-terminated C string and a valid pointer.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
            return None;
        }

        let frsize = stat.f_frsize as u64;

        Some(DiskSpace {
            total_bytes: stat.f_blocks as u64 * frsize,
            free_bytes: stat.f_bfree as u64 * frsize,
            available_bytes: stat.f_bavail as u64 * frsize,
            bytes_per_sector: 512,
            sectors_per_cluster: (stat.f_frsize as u32) / 512,
        })
    }

    #[cfg(not(any(windows, unix)))]
    fn query_impl(_path: &Path) -> Option<DiskSpace> {
        None
    }
}

/// Encode FileFsVolumeInformation (class 1).
///
/// Layout (MS-FSCC 2.5.9):
/// - VolumeCreationTime: i64 LE (8 bytes)
/// - VolumeSerialNumber: u32 LE (4 bytes)
/// - VolumeLabelLength: u32 LE (4 bytes)
/// - SupportsObjects: u8 (1 byte)
/// - Reserved: u8 (1 byte)
/// - VolumeLabel: variable UTF-16LE
pub fn encode_volume_info(volume_label: &str) -> Vec<u8> {
    let label_bytes = encode_utf16le(volume_label);
    let label_len = label_bytes.len() as u32;

    let mut buf = Vec::with_capacity(18 + label_bytes.len());

    // VolumeCreationTime (8 bytes) — 0 (unknown)
    buf.extend_from_slice(&0i64.to_le_bytes());
    // VolumeSerialNumber (4 bytes)
    buf.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    // VolumeLabelLength (4 bytes)
    buf.extend_from_slice(&label_len.to_le_bytes());
    // SupportsObjects (1 byte)
    buf.push(0);
    // Reserved (1 byte)
    buf.push(0);
    // VolumeLabel (variable)
    buf.extend_from_slice(&label_bytes);

    buf
}

/// Encode FileFsSizeInformation (class 3).
///
/// Layout (MS-FSCC 2.5.8):
/// - TotalAllocationUnits: i64 LE (8 bytes)
/// - AvailableAllocationUnits: i64 LE (8 bytes)
/// - SectorsPerAllocationUnit: u32 LE (4 bytes)
/// - BytesPerSector: u32 LE (4 bytes)
pub fn encode_size_info(disk: &DiskSpace) -> Vec<u8> {
    let cluster_size = disk.cluster_size();
    let total_units = if cluster_size > 0 {
        disk.total_bytes / cluster_size
    } else {
        0
    };
    let available_units = if cluster_size > 0 {
        disk.available_bytes / cluster_size
    } else {
        0
    };

    let mut buf = Vec::with_capacity(24);

    // TotalAllocationUnits (8 bytes)
    buf.extend_from_slice(&(total_units as i64).to_le_bytes());
    // AvailableAllocationUnits (8 bytes)
    buf.extend_from_slice(&(available_units as i64).to_le_bytes());
    // SectorsPerAllocationUnit (4 bytes)
    buf.extend_from_slice(&disk.sectors_per_cluster.to_le_bytes());
    // BytesPerSector (4 bytes)
    buf.extend_from_slice(&disk.bytes_per_sector.to_le_bytes());

    buf
}

/// Encode FileFsDeviceInformation (class 4).
///
/// Layout (MS-FSCC 2.5.10):
/// - DeviceType: u32 LE (4 bytes) — FILE_DEVICE_DISK
/// - Characteristics: u32 LE (4 bytes) — FILE_DEVICE_IS_MOUNTED
pub fn encode_device_info() -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);

    // DeviceType (4 bytes)
    buf.extend_from_slice(&FILE_DEVICE_DISK.to_le_bytes());
    // Characteristics (4 bytes)
    buf.extend_from_slice(&FILE_DEVICE_IS_MOUNTED.to_le_bytes());

    buf
}

/// Encode FileFsAttributeInformation (class 5).
///
/// Layout (MS-FSCC 2.5.1):
/// - FileSystemAttributes: u32 LE (4 bytes)
/// - MaximumComponentNameLength: i32 LE (4 bytes)
/// - FileSystemNameLength: u32 LE (4 bytes)
/// - FileSystemName: variable UTF-16LE (NOT null-terminated)
pub fn encode_attribute_info(fs_name: &str) -> Vec<u8> {
    let name_bytes = encode_utf16le(fs_name);
    let name_len = name_bytes.len() as u32;

    let attributes = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK;

    let mut buf = Vec::with_capacity(12 + name_bytes.len());

    // FileSystemAttributes (4 bytes)
    buf.extend_from_slice(&attributes.to_le_bytes());
    // MaximumComponentNameLength (4 bytes)
    buf.extend_from_slice(&255i32.to_le_bytes());
    // FileSystemNameLength (4 bytes)
    buf.extend_from_slice(&name_len.to_le_bytes());
    // FileSystemName (variable)
    buf.extend_from_slice(&name_bytes);

    buf
}

/// Encode FileFsFullSizeInformation (class 7).
///
/// Layout (MS-FSCC 2.5.4):
/// - TotalAllocationUnits: i64 LE (8 bytes)
/// - CallerAvailableAllocationUnits: i64 LE (8 bytes)
/// - ActualAvailableAllocationUnits: i64 LE (8 bytes)
/// - SectorsPerAllocationUnit: u32 LE (4 bytes)
/// - BytesPerSector: u32 LE (4 bytes)
pub fn encode_full_size_info(disk: &DiskSpace) -> Vec<u8> {
    let cluster_size = disk.cluster_size();
    let total_units = if cluster_size > 0 {
        disk.total_bytes / cluster_size
    } else {
        0
    };
    let caller_available = if cluster_size > 0 {
        disk.available_bytes / cluster_size
    } else {
        0
    };
    let actual_available = if cluster_size > 0 {
        disk.free_bytes / cluster_size
    } else {
        0
    };

    let mut buf = Vec::with_capacity(32);

    // TotalAllocationUnits (8 bytes)
    buf.extend_from_slice(&(total_units as i64).to_le_bytes());
    // CallerAvailableAllocationUnits (8 bytes)
    buf.extend_from_slice(&(caller_available as i64).to_le_bytes());
    // ActualAvailableAllocationUnits (8 bytes)
    buf.extend_from_slice(&(actual_available as i64).to_le_bytes());
    // SectorsPerAllocationUnit (4 bytes)
    buf.extend_from_slice(&disk.sectors_per_cluster.to_le_bytes());
    // BytesPerSector (4 bytes)
    buf.extend_from_slice(&disk.bytes_per_sector.to_le_bytes());

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_device_info_exact_bytes() {
        let buf = encode_device_info();
        assert_eq!(buf.len(), 8);
        assert_eq!(buf, [0x07, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn encode_volume_info_length() {
        let label = "TestVol";
        let buf = encode_volume_info(label);
        let label_utf16le_len = label.encode_utf16().count() * 2;
        assert_eq!(buf.len(), 18 + label_utf16le_len);

        // Verify VolumeLabelLength field (offset 12..16)
        let label_len = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        assert_eq!(label_len as usize, label_utf16le_len);
    }

    #[test]
    fn encode_size_info_24_bytes() {
        let disk = DiskSpace {
            total_bytes: 1_000_000_000,
            free_bytes: 500_000_000,
            available_bytes: 400_000_000,
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
        };
        let buf = encode_size_info(&disk);
        assert_eq!(buf.len(), 24);

        let cluster_size: u64 = 512 * 8;
        let total = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let available = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        let spc = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let bps = u32::from_le_bytes(buf[20..24].try_into().unwrap());

        assert_eq!(total, (1_000_000_000u64 / cluster_size) as i64);
        assert_eq!(available, (400_000_000u64 / cluster_size) as i64);
        assert_eq!(spc, 8);
        assert_eq!(bps, 512);
    }

    #[test]
    fn encode_full_size_info_32_bytes() {
        let disk = DiskSpace {
            total_bytes: 2_000_000_000,
            free_bytes: 1_000_000_000,
            available_bytes: 800_000_000,
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
        };
        let buf = encode_full_size_info(&disk);
        assert_eq!(buf.len(), 32);

        let cluster_size: u64 = 512 * 8;
        let total = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let caller_avail = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        let actual_avail = i64::from_le_bytes(buf[16..24].try_into().unwrap());
        let spc = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let bps = u32::from_le_bytes(buf[28..32].try_into().unwrap());

        assert_eq!(total, (2_000_000_000u64 / cluster_size) as i64);
        assert_eq!(caller_avail, (800_000_000u64 / cluster_size) as i64);
        assert_eq!(actual_avail, (1_000_000_000u64 / cluster_size) as i64);
        assert_eq!(spc, 8);
        assert_eq!(bps, 512);
    }

    #[test]
    fn encode_attribute_info_ntfs() {
        let buf = encode_attribute_info("NTFS");
        // "NTFS" = 4 UTF-16LE code units = 8 bytes
        assert_eq!(buf.len(), 12 + 8);
        assert_eq!(buf.len(), 20);

        let attrs = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(
            attrs,
            FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK
        );
        assert_eq!(attrs, 0x07);

        let max_component = i32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(max_component, 255);

        let name_len = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(name_len, 8);
    }
}
