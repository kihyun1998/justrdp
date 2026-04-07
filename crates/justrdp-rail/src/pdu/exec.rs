#![forbid(unsafe_code)]

//! Exec Request/Result PDUs -- MS-RDPERP 2.2.2.3.1, 2.2.2.3.2

use alloc::vec::Vec;

use justrdp_core::{
    Decode, DecodeError, DecodeResult, Encode, EncodeError, EncodeResult, ReadCursor, WriteCursor,
};

use super::header::{RailHeader, RailOrderType, RAIL_HEADER_SIZE};

// ── Exec flags -- MS-RDPERP 2.2.2.3.1 ──

/// Expand environment variables in working directory.
pub const TS_RAIL_EXEC_FLAG_EXPAND_WORKINGDIRECTORY: u16 = 0x0001;
/// Translate file path for drive redirection.
pub const TS_RAIL_EXEC_FLAG_TRANSLATE_FILES: u16 = 0x0002;
/// ExeOrFile is a file path, not a program name.
pub const TS_RAIL_EXEC_FLAG_FILE: u16 = 0x0004;
/// Expand environment variables in arguments.
pub const TS_RAIL_EXEC_FLAG_EXPAND_ARGUMENTS: u16 = 0x0008;
/// ExeOrFile is an AppUserModelID.
pub const TS_RAIL_EXEC_FLAG_APP_USER_MODEL_ID: u16 = 0x0010;

/// Maximum byte length for ExeOrFile / WorkingDir fields.
const MAX_EXE_OR_FILE_LENGTH: u16 = 520;
/// Maximum byte length for Arguments field.
const MAX_ARGUMENTS_LENGTH: u16 = 16000;

// ── Exec result codes -- MS-RDPERP 2.2.2.3.2 ──

/// Execution succeeded.
pub const RAIL_EXEC_S_OK: u16 = 0x0000;
/// RAIL shell hook not loaded.
pub const RAIL_EXEC_E_HOOK_NOT_LOADED: u16 = 0x0001;
/// PDU decode failed on server.
pub const RAIL_EXEC_E_DECODE_FAILED: u16 = 0x0002;
/// Program not in allow list.
pub const RAIL_EXEC_E_NOT_IN_ALLOWLIST: u16 = 0x0003;
/// Runtime DLL not found.
pub const RAIL_EXEC_E_RUNTIME_DLL_NOT_FOUND: u16 = 0x0004;
/// File not found.
pub const RAIL_EXEC_E_FILE_NOT_FOUND: u16 = 0x0005;
/// General failure.
pub const RAIL_EXEC_E_FAIL: u16 = 0x0006;
/// Session is locked.
pub const RAIL_EXEC_E_SESSION_LOCKED: u16 = 0x0007;

/// Client Execute PDU -- MS-RDPERP 2.2.2.3.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPdu {
    /// Execution flags.
    pub flags: u16,
    /// Program name or file path (UTF-16LE, not null-terminated).
    pub exe_or_file: Vec<u8>,
    /// Working directory (UTF-16LE, not null-terminated). Empty if absent.
    pub working_dir: Vec<u8>,
    /// Command-line arguments (UTF-16LE, not null-terminated). Empty if absent.
    pub arguments: Vec<u8>,
}

impl ExecPdu {
    pub fn new(flags: u16, exe_or_file: Vec<u8>, working_dir: Vec<u8>, arguments: Vec<u8>) -> Self {
        Self {
            flags,
            exe_or_file,
            working_dir,
            arguments,
        }
    }
}

impl Encode for ExecPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(
            RailOrderType::Exec,
            u16::try_from(self.size()).map_err(|_| EncodeError::other("ExecPdu", "size"))?,
        );
        header.encode(dst)?;
        dst.write_u16_le(self.flags, "Exec::Flags")?;
        let exe_len = u16::try_from(self.exe_or_file.len())
            .map_err(|_| EncodeError::other("ExecPdu", "ExeOrFileLength"))?;
        let wd_len = u16::try_from(self.working_dir.len())
            .map_err(|_| EncodeError::other("ExecPdu", "WorkingDirLength"))?;
        let args_len = u16::try_from(self.arguments.len())
            .map_err(|_| EncodeError::other("ExecPdu", "ArgumentsLen"))?;
        dst.write_u16_le(exe_len, "Exec::ExeOrFileLength")?;
        dst.write_u16_le(wd_len, "Exec::WorkingDirLength")?;
        dst.write_u16_le(args_len, "Exec::ArgumentsLen")?;
        dst.write_slice(&self.exe_or_file, "Exec::ExeOrFile")?;
        if !self.working_dir.is_empty() {
            dst.write_slice(&self.working_dir, "Exec::WorkingDir")?;
        }
        if !self.arguments.is_empty() {
            dst.write_slice(&self.arguments, "Exec::Arguments")?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ExecPdu"
    }

    fn size(&self) -> usize {
        RAIL_HEADER_SIZE + 2 + 2 + 2 + 2 + self.exe_or_file.len() + self.working_dir.len()
            + self.arguments.len()
    }
}

impl<'de> Decode<'de> for ExecPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let flags = src.read_u16_le("Exec::Flags")?;
        let exe_len = src.read_u16_le("Exec::ExeOrFileLength")?;
        let wd_len = src.read_u16_le("Exec::WorkingDirLength")?;
        let args_len = src.read_u16_le("Exec::ArgumentsLen")?;

        if exe_len == 0 || exe_len % 2 != 0 {
            return Err(DecodeError::invalid_value("ExecPdu", "ExeOrFileLength"));
        }
        if exe_len > MAX_EXE_OR_FILE_LENGTH {
            return Err(DecodeError::invalid_value("ExecPdu", "ExeOrFileLength"));
        }
        if wd_len > MAX_EXE_OR_FILE_LENGTH || wd_len % 2 != 0 {
            return Err(DecodeError::invalid_value("ExecPdu", "WorkingDirLength"));
        }
        if args_len > MAX_ARGUMENTS_LENGTH || args_len % 2 != 0 {
            return Err(DecodeError::invalid_value("ExecPdu", "ArgumentsLen"));
        }

        let exe_or_file = src.read_slice(exe_len as usize, "Exec::ExeOrFile")?.to_vec();
        let working_dir = if wd_len > 0 {
            src.read_slice(wd_len as usize, "Exec::WorkingDir")?.to_vec()
        } else {
            Vec::new()
        };
        let arguments = if args_len > 0 {
            src.read_slice(args_len as usize, "Exec::Arguments")?.to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            flags,
            exe_or_file,
            working_dir,
            arguments,
        })
    }
}

/// Server Execute Result PDU -- MS-RDPERP 2.2.2.3.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResultPdu {
    /// Echo of the flags from the Client Execute PDU.
    pub flags: u16,
    /// Execution result code.
    pub exec_result: u16,
    /// OS-specific return code.
    pub raw_result: u32,
    /// Program name or file path (UTF-16LE, not null-terminated).
    pub exe_or_file: Vec<u8>,
}

impl ExecResultPdu {
    pub fn new(flags: u16, exec_result: u16, raw_result: u32, exe_or_file: Vec<u8>) -> Self {
        Self {
            flags,
            exec_result,
            raw_result,
            exe_or_file,
        }
    }
}

impl Encode for ExecResultPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let header = RailHeader::new(
            RailOrderType::ExecResult,
            u16::try_from(self.size()).map_err(|_| EncodeError::other("ExecResultPdu", "size"))?,
        );
        header.encode(dst)?;
        dst.write_u16_le(self.flags, "ExecResult::Flags")?;
        dst.write_u16_le(self.exec_result, "ExecResult::ExecResult")?;
        dst.write_u32_le(self.raw_result, "ExecResult::RawResult")?;
        // Padding (2 bytes, reserved)
        dst.write_u16_le(0, "ExecResult::Padding")?;
        let exe_len = u16::try_from(self.exe_or_file.len())
            .map_err(|_| EncodeError::other("ExecResultPdu", "ExeOrFileLength"))?;
        dst.write_u16_le(exe_len, "ExecResult::ExeOrFileLength")?;
        dst.write_slice(&self.exe_or_file, "ExecResult::ExeOrFile")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ExecResultPdu"
    }

    fn size(&self) -> usize {
        // header(4) + flags(2) + result(2) + rawResult(4) + padding(2) + exeLen(2) + exeOrFile
        RAIL_HEADER_SIZE + 2 + 2 + 4 + 2 + 2 + self.exe_or_file.len()
    }
}

impl<'de> Decode<'de> for ExecResultPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let flags = src.read_u16_le("ExecResult::Flags")?;
        let exec_result = src.read_u16_le("ExecResult::ExecResult")?;
        let raw_result = src.read_u32_le("ExecResult::RawResult")?;
        let _padding = src.read_u16_le("ExecResult::Padding")?;
        let exe_len = src.read_u16_le("ExecResult::ExeOrFileLength")?;

        if exe_len == 0 || exe_len % 2 != 0 {
            return Err(DecodeError::invalid_value("ExecResultPdu", "ExeOrFileLength"));
        }
        if exe_len > MAX_EXE_OR_FILE_LENGTH {
            return Err(DecodeError::invalid_value("ExecResultPdu", "ExeOrFileLength"));
        }

        let exe_or_file = src.read_slice(exe_len as usize, "ExecResult::ExeOrFile")?.to_vec();

        Ok(Self {
            flags,
            exec_result,
            raw_result,
            exe_or_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_roundtrip() {
        // "notepad" in UTF-16LE
        let exe = b"n\x00o\x00t\x00e\x00p\x00a\x00d\x00".to_vec();
        let pdu = ExecPdu::new(0, exe.clone(), Vec::new(), Vec::new());
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.order_type, RailOrderType::Exec);
        let decoded = ExecPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn exec_with_args_roundtrip() {
        let exe = b"c\x00m\x00d\x00".to_vec();
        let args = b"/\x00c\x00".to_vec();
        let wd = b"C\x00:\x00\\\x00".to_vec();
        let pdu = ExecPdu::new(
            TS_RAIL_EXEC_FLAG_EXPAND_WORKINGDIRECTORY | TS_RAIL_EXEC_FLAG_EXPAND_ARGUMENTS,
            exe,
            wd,
            args,
        );
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = ExecPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn exec_zero_length_rejected() {
        // flags=0, ExeOrFileLength=0, WorkingDirLength=0, ArgumentsLen=0
        let bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        assert!(ExecPdu::decode(&mut cursor).is_err());
    }

    #[test]
    fn exec_result_roundtrip() {
        let exe = b"n\x00o\x00t\x00e\x00p\x00a\x00d\x00".to_vec();
        let pdu = ExecResultPdu::new(0, RAIL_EXEC_S_OK, 0, exe);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let header = RailHeader::decode(&mut cursor).unwrap();
        assert_eq!(header.order_type, RailOrderType::ExecResult);
        let decoded = ExecResultPdu::decode(&mut cursor).unwrap();
        assert_eq!(pdu, decoded);
    }

    #[test]
    fn exec_result_failure() {
        let exe = b"b\x00a\x00d\x00".to_vec();
        let pdu = ExecResultPdu::new(0, RAIL_EXEC_E_FILE_NOT_FOUND, 0x80070002, exe);
        let mut buf = alloc::vec![0u8; pdu.size()];
        let mut cursor = WriteCursor::new(&mut buf);
        pdu.encode(&mut cursor).unwrap();

        let mut cursor = ReadCursor::new(&buf);
        let _header = RailHeader::decode(&mut cursor).unwrap();
        let decoded = ExecResultPdu::decode(&mut cursor).unwrap();
        assert_eq!(decoded.exec_result, RAIL_EXEC_E_FILE_NOT_FOUND);
        assert_eq!(decoded.raw_result, 0x80070002);
    }
}
