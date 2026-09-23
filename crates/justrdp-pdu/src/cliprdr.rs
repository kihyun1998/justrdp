//! Clipboard virtual channel PDUs (MS-RDPECLIP), carried over the static channel
//! [`CHANNEL_NAME`]. Every PDU is one whole channel message: a `CLIPRDR_HEADER` (2.2.1),
//! `dataLen` bytes of body, and possibly padding ([`padding`]). The initialization sequence (1.3.2.1) is server Capabilities and
//! Monitor Ready, then client Capabilities and a Format List, answered by a Format List
//! Response.

use crate::cursor::ReadCursor;
use crate::error::DecodeError;

/// The static channel name (2.1).
pub const CHANNEL_NAME: &str = "cliprdr";

/// `CB_MONITOR_READY` (2.2.2.2).
pub const CB_MONITOR_READY: u16 = 0x0001;
/// `CB_FORMAT_LIST` (2.2.3.1).
pub const CB_FORMAT_LIST: u16 = 0x0002;
/// `CB_FORMAT_LIST_RESPONSE` (2.2.3.2).
pub const CB_FORMAT_LIST_RESPONSE: u16 = 0x0003;
/// `CB_FORMAT_DATA_REQUEST` (2.2.5.1).
pub const CB_FORMAT_DATA_REQUEST: u16 = 0x0004;
/// `CB_FORMAT_DATA_RESPONSE` (2.2.5.2).
pub const CB_FORMAT_DATA_RESPONSE: u16 = 0x0005;
/// `CB_CLIP_CAPS` (2.2.2.1).
pub const CB_CLIP_CAPS: u16 = 0x0007;
/// `CB_FILECONTENTS_REQUEST` (2.2.5.3).
pub const CB_FILECONTENTS_REQUEST: u16 = 0x0008;
/// `CB_FILECONTENTS_RESPONSE` (2.2.5.4).
pub const CB_FILECONTENTS_RESPONSE: u16 = 0x0009;
/// `CB_LOCK_CLIPDATA` (2.2.4.1).
pub const CB_LOCK_CLIPDATA: u16 = 0x000A;
/// `CB_UNLOCK_CLIPDATA` (2.2.4.2).
pub const CB_UNLOCK_CLIPDATA: u16 = 0x000B;

/// `msgFlags`: the request succeeded.
pub const CB_RESPONSE_OK: u16 = 0x0001;
/// `msgFlags`: the request failed.
pub const CB_RESPONSE_FAIL: u16 = 0x0002;
/// `msgFlags` on a short-name Format List: the names are ASCII, not UTF-16.
pub const CB_ASCII_NAMES: u16 = 0x0004;

/// `CB_CAPSTYPE_GENERAL` (2.2.2.1.1).
pub const CB_CAPSTYPE_GENERAL: u16 = 0x0001;
/// `CB_CAPS_VERSION_2` (2.2.2.1.1.1).
pub const CB_CAPS_VERSION_2: u32 = 0x0000_0002;

/// `generalFlags`: Format Lists carry long, variable-length names (2.2.3.1.2).
pub const CB_USE_LONG_FORMAT_NAMES: u32 = 0x0000_0002;
/// `generalFlags`: file contents can be streamed.
pub const CB_STREAM_FILECLIP_ENABLED: u32 = 0x0000_0004;
/// `generalFlags`: file paths are not sent in file lists.
pub const CB_FILECLIP_NO_FILE_PATHS: u32 = 0x0000_0008;
/// `generalFlags`: Lock/Unlock Clipboard Data is supported.
pub const CB_CAN_LOCK_CLIPDATA: u32 = 0x0000_0010;
/// `generalFlags`: files of 4 GiB and more are supported.
pub const CB_HUGE_FILE_SUPPORT_ENABLED: u32 = 0x0000_0020;

/// `CF_DIB`, the standard clipboard format for a device-independent bitmap: a
/// `BITMAPINFO` header followed by the pixels.
pub const CF_DIB: u32 = 8;
/// `CF_UNICODETEXT`, the standard clipboard format for UTF-16 text.
pub const CF_UNICODETEXT: u32 = 13;
/// `CF_DIBV5`, a device-independent bitmap with a `BITMAPV5HEADER`.
pub const CF_DIBV5: u32 = 17;

/// The registered format name whose data is a [`FileDescriptor`] list (`CLIPRDR_FILELIST`,
/// 2.2.5.2.3).
pub const FILE_GROUP_DESCRIPTOR_W: &str = "FileGroupDescriptorW";

/// `FILECONTENTS_SIZE`: a File Contents Request for a file's size.
pub const FILECONTENTS_SIZE: u32 = 0x0000_0001;
/// `FILECONTENTS_RANGE`: a File Contents Request for a range of a file's bytes.
pub const FILECONTENTS_RANGE: u32 = 0x0000_0002;

/// `FD_ATTRIBUTES`: a descriptor's `fileAttributes` is valid.
pub const FD_ATTRIBUTES: u32 = 0x0000_0004;
/// `FD_WRITESTIME`: a descriptor's `lastWriteTime` is valid.
pub const FD_WRITESTIME: u32 = 0x0000_0020;
/// `FD_FILESIZE`: a descriptor's file size is valid.
pub const FD_FILESIZE: u32 = 0x0000_0040;
/// `FILE_ATTRIBUTE_DIRECTORY`.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// The size of a `CLIPRDR_FILEDESCRIPTOR`.
const FILE_DESCRIPTOR_SIZE: usize = 592;
/// The size of a descriptor's `fileName` field.
const FILE_NAME_BYTES: usize = 520;

/// One file in a `CLIPRDR_FILELIST` (2.2.5.2.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptor {
    /// `flags` (`FD_ATTRIBUTES`, `FD_WRITESTIME`, `FD_FILESIZE`, ...).
    pub flags: u32,
    /// `fileAttributes`, meaningful with [`FD_ATTRIBUTES`].
    pub attributes: u32,
    /// `lastWriteTime`, meaningful with [`FD_WRITESTIME`].
    pub last_write_time: u64,
    /// The file size, `Some` with [`FD_FILESIZE`].
    pub size: Option<u64>,
    /// `fileName`: a relative path whose components are separated by `\`.
    pub name: String,
}

/// What a File Contents Request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileContentsOp {
    /// The file's size (`FILECONTENTS_SIZE`).
    Size,
    /// Up to `len` bytes from `position` (`FILECONTENTS_RANGE`).
    Range {
        /// The offset into the file.
        position: u64,
        /// The most bytes to return (`cbRequested`).
        len: u32,
    },
}

/// A File Contents Request (2.2.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileContentsRequest {
    /// `streamId`, echoed by the response.
    pub stream_id: u32,
    /// `lindex`: the file's index in the file list.
    pub index: u32,
    /// What is asked for.
    pub op: FileContentsOp,
    /// `clipDataId`, when the file list was locked.
    pub clip_data_id: Option<u32>,
}

/// The size of a `CLIPRDR_HEADER`.
const HEADER_SIZE: usize = 8;
/// The size of a `CLIPRDR_GENERAL_CAPABILITY` set, header included.
const GENERAL_CAPABILITY_SIZE: u16 = 12;
/// The size of a `CLIPRDR_SHORT_FORMAT_NAME` entry: a format ID and a 32-byte name.
const SHORT_FORMAT_NAME_SIZE: usize = 36;
/// The size of a short format name's name field.
const SHORT_NAME_BYTES: usize = 32;

/// A `CLIPRDR_GENERAL_CAPABILITY` set (2.2.2.1.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralCapability {
    /// `version` ([`CB_CAPS_VERSION_2`]).
    pub version: u32,
    /// `generalFlags` (`CB_USE_LONG_FORMAT_NAMES` and the file-transfer flags).
    pub general_flags: u32,
}

/// One clipboard format in a Format List: its ID and, for a registered format, its name.
/// A standard format such as [`CF_UNICODETEXT`] has an empty name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Format {
    /// `formatId`.
    pub id: u32,
    /// `formatName`, without its terminator.
    pub name: String,
}

/// One clipboard message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardPdu {
    /// Clipboard Capabilities (2.2.2.1). `general` is `None` when no general set is present.
    Capabilities {
        /// The general capability set.
        general: Option<GeneralCapability>,
    },
    /// Monitor Ready (2.2.2.2).
    MonitorReady,
    /// Format List (2.2.3.1).
    FormatList(Vec<Format>),
    /// Format List Response (2.2.3.2).
    FormatListResponse {
        /// `CB_RESPONSE_OK` rather than `CB_RESPONSE_FAIL`.
        ok: bool,
    },
    /// Format Data Request (2.2.5.1).
    FormatDataRequest {
        /// `requestedFormatId`.
        format_id: u32,
    },
    /// Format Data Response (2.2.5.2). `None` is `CB_RESPONSE_FAIL`.
    FormatDataResponse {
        /// `requestedFormatData`.
        data: Option<Vec<u8>>,
    },
    /// File Contents Request (2.2.5.3).
    FileContentsRequest(FileContentsRequest),
    /// File Contents Response (2.2.5.4). `data` is `None` for `CB_RESPONSE_FAIL`.
    FileContentsResponse {
        /// `streamId`.
        stream_id: u32,
        /// `requestedFileContentsData`.
        data: Option<Vec<u8>>,
    },
    /// Lock Clipboard Data (2.2.4.1).
    LockClipData {
        /// `clipDataId`.
        clip_data_id: u32,
    },
    /// Unlock Clipboard Data (2.2.4.2).
    UnlockClipData {
        /// `clipDataId`.
        clip_data_id: u32,
    },
    /// A message type this module does not decode.
    Unknown {
        /// `msgType`.
        msg_type: u16,
        /// `msgFlags`.
        msg_flags: u16,
    },
}

impl ClipboardPdu {
    /// Decode one complete clipboard message. `long_format_names` is whether both sides
    /// advertised [`CB_USE_LONG_FORMAT_NAMES`], which decides a Format List's layout. Bytes after
    /// `dataLen` are padding and are not read ([`padding`]).
    pub fn decode(message: &[u8], long_format_names: bool) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(message, "CLIPRDR_HEADER");
        let msg_type = cur.read_u16_le()?;
        let msg_flags = cur.read_u16_le()?;
        let data_len = cur.read_u32_le()? as usize;
        if data_len > cur.remaining() {
            return Err(DecodeError::InvalidField {
                field: "CLIPRDR_HEADER.dataLen",
                reason: "runs past the message",
            });
        }
        let body = cur.read_slice(data_len)?;
        match msg_type {
            CB_CLIP_CAPS => decode_capabilities(body),
            CB_MONITOR_READY => Ok(ClipboardPdu::MonitorReady),
            CB_FORMAT_LIST if long_format_names => decode_long_format_list(body),
            CB_FORMAT_LIST => decode_short_format_list(body, msg_flags & CB_ASCII_NAMES != 0),
            CB_FORMAT_LIST_RESPONSE => match msg_flags & (CB_RESPONSE_OK | CB_RESPONSE_FAIL) {
                CB_RESPONSE_OK => Ok(ClipboardPdu::FormatListResponse { ok: true }),
                CB_RESPONSE_FAIL => Ok(ClipboardPdu::FormatListResponse { ok: false }),
                _ => Err(DecodeError::InvalidField {
                    field: "CLIPRDR_HEADER.msgFlags",
                    reason: "a response must be exactly one of CB_RESPONSE_OK and CB_RESPONSE_FAIL",
                }),
            },
            CB_FORMAT_DATA_REQUEST => {
                let bytes: [u8; 4] = body.try_into().map_err(|_| DecodeError::InvalidField {
                    field: "CLIPRDR_FORMAT_DATA_REQUEST",
                    reason: "the body is one 4-byte format ID",
                })?;
                Ok(ClipboardPdu::FormatDataRequest {
                    format_id: u32::from_le_bytes(bytes),
                })
            }
            CB_FORMAT_DATA_RESPONSE => match msg_flags & (CB_RESPONSE_OK | CB_RESPONSE_FAIL) {
                CB_RESPONSE_OK => Ok(ClipboardPdu::FormatDataResponse {
                    data: Some(body.to_vec()),
                }),
                CB_RESPONSE_FAIL if body.is_empty() => {
                    Ok(ClipboardPdu::FormatDataResponse { data: None })
                }
                CB_RESPONSE_FAIL => Err(DecodeError::InvalidField {
                    field: "CLIPRDR_FORMAT_DATA_RESPONSE.requestedFormatData",
                    reason: "a failed response carries no data",
                }),
                _ => Err(DecodeError::InvalidField {
                    field: "CLIPRDR_HEADER.msgFlags",
                    reason: "a response must be exactly one of CB_RESPONSE_OK and CB_RESPONSE_FAIL",
                }),
            },
            CB_FILECONTENTS_REQUEST => decode_file_contents_request(body),
            CB_FILECONTENTS_RESPONSE => {
                let mut cur = ReadCursor::new(body, "CLIPRDR_FILECONTENTS_RESPONSE");
                let stream_id = cur.read_u32_le()?;
                let data = cur.read_slice(cur.remaining())?;
                match msg_flags & (CB_RESPONSE_OK | CB_RESPONSE_FAIL) {
                    CB_RESPONSE_OK => Ok(ClipboardPdu::FileContentsResponse {
                        stream_id,
                        data: Some(data.to_vec()),
                    }),
                    CB_RESPONSE_FAIL => Ok(ClipboardPdu::FileContentsResponse {
                        stream_id,
                        data: None,
                    }),
                    _ => Err(DecodeError::InvalidField {
                        field: "CLIPRDR_HEADER.msgFlags",
                        reason: "a response must be exactly one of CB_RESPONSE_OK and CB_RESPONSE_FAIL",
                    }),
                }
            }
            CB_LOCK_CLIPDATA => Ok(ClipboardPdu::LockClipData {
                clip_data_id: one_u32(body, "CLIPRDR_LOCK_CLIPDATA")?,
            }),
            CB_UNLOCK_CLIPDATA => Ok(ClipboardPdu::UnlockClipData {
                clip_data_id: one_u32(body, "CLIPRDR_UNLOCK_CLIPDATA")?,
            }),
            msg_type => Ok(ClipboardPdu::Unknown {
                msg_type,
                msg_flags,
            }),
        }
    }
}

fn one_u32(body: &[u8], field: &'static str) -> Result<u32, DecodeError> {
    let bytes: [u8; 4] = body.try_into().map_err(|_| DecodeError::InvalidField {
        field,
        reason: "the body is one 4-byte value",
    })?;
    Ok(u32::from_le_bytes(bytes))
}

fn decode_file_contents_request(body: &[u8]) -> Result<ClipboardPdu, DecodeError> {
    let mut cur = ReadCursor::new(body, "CLIPRDR_FILECONTENTS_REQUEST");
    let stream_id = cur.read_u32_le()?;
    let index = cur.read_u32_le()?;
    let flags = cur.read_u32_le()?;
    let low = cur.read_u32_le()?;
    let high = cur.read_u32_le()?;
    let len = cur.read_u32_le()?;
    let clip_data_id = match cur.remaining() {
        0 => None,
        4 => Some(cur.read_u32_le()?),
        _ => {
            return Err(DecodeError::InvalidField {
                field: "CLIPRDR_FILECONTENTS_REQUEST.clipDataId",
                reason: "the optional clipDataId is 4 bytes",
            });
        }
    };
    let op = match flags & (FILECONTENTS_SIZE | FILECONTENTS_RANGE) {
        FILECONTENTS_SIZE if low == 0 && high == 0 && len == 8 => FileContentsOp::Size,
        FILECONTENTS_SIZE => {
            return Err(DecodeError::InvalidField {
                field: "CLIPRDR_FILECONTENTS_REQUEST.cbRequested",
                reason: "a size request asks for 8 bytes at position 0",
            });
        }
        FILECONTENTS_RANGE => FileContentsOp::Range {
            position: u64::from(high) << 32 | u64::from(low),
            len,
        },
        _ => {
            return Err(DecodeError::InvalidField {
                field: "CLIPRDR_FILECONTENTS_REQUEST.dwFlags",
                reason: "exactly one of FILECONTENTS_SIZE and FILECONTENTS_RANGE",
            });
        }
    };
    Ok(ClipboardPdu::FileContentsRequest(FileContentsRequest {
        stream_id,
        index,
        op,
        clip_data_id,
    }))
}

fn decode_capabilities(body: &[u8]) -> Result<ClipboardPdu, DecodeError> {
    let mut cur = ReadCursor::new(body, "CLIPRDR_CAPS");
    let count = cur.read_u16_le()?;
    let _pad = cur.read_u16_le()?;
    let mut general = None;
    for _ in 0..count {
        let set_type = cur.read_u16_le()?;
        let set_length = cur.read_u16_le()?;
        if set_type != CB_CAPSTYPE_GENERAL {
            return Err(DecodeError::InvalidField {
                field: "CLIPRDR_CAPS_SET.capabilitySetType",
                reason: "only the general capability set is defined",
            });
        }
        if set_length != GENERAL_CAPABILITY_SIZE {
            return Err(DecodeError::InvalidField {
                field: "CLIPRDR_GENERAL_CAPABILITY.lengthCapability",
                reason: "the general capability set is 12 bytes",
            });
        }
        general = Some(GeneralCapability {
            version: cur.read_u32_le()?,
            general_flags: cur.read_u32_le()?,
        });
    }
    if cur.remaining() != 0 {
        return Err(DecodeError::InvalidField {
            field: "CLIPRDR_CAPS.cCapabilitiesSets",
            reason: "the capability sets do not fill the message",
        });
    }
    Ok(ClipboardPdu::Capabilities { general })
}

fn decode_short_format_list(body: &[u8], ascii: bool) -> Result<ClipboardPdu, DecodeError> {
    let (entries, partial) = body.as_chunks::<SHORT_FORMAT_NAME_SIZE>();
    if !partial.is_empty() {
        return Err(DecodeError::InvalidField {
            field: "CLIPRDR_SHORT_FORMAT_NAMES",
            reason: "not a whole number of 36-byte entries",
        });
    }
    let formats = entries
        .iter()
        .map(|entry| {
            let id = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let field = &entry[4..];
            let name = if ascii {
                let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
                String::from_utf8_lossy(&field[..end]).into_owned()
            } else {
                utf16_to_string(
                    field
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|&u| u16::from_le_bytes(u))
                        .take_while(|&u| u != 0),
                )
            };
            Format { id, name }
        })
        .collect();
    Ok(ClipboardPdu::FormatList(formats))
}

fn decode_long_format_list(body: &[u8]) -> Result<ClipboardPdu, DecodeError> {
    let mut cur = ReadCursor::new(body, "CLIPRDR_LONG_FORMAT_NAME");
    let mut count = 0usize;
    while cur.remaining() != 0 {
        next_long_format_name(&mut cur, body)?;
        count += 1;
    }
    let mut formats = Vec::with_capacity(count);
    let mut cur = ReadCursor::new(body, "CLIPRDR_LONG_FORMAT_NAME");
    while cur.remaining() != 0 {
        let (id, name) = next_long_format_name(&mut cur, body)?;
        formats.push(Format {
            id,
            name: utf16_to_string(
                name.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&u| u16::from_le_bytes(u)),
            ),
        });
    }
    Ok(ClipboardPdu::FormatList(formats))
}

/// One `CLIPRDR_LONG_FORMAT_NAME`: its format ID and its name's UTF-16LE bytes, without the NUL.
fn next_long_format_name<'a>(
    cur: &mut ReadCursor<'a>,
    body: &'a [u8],
) -> Result<(u32, &'a [u8]), DecodeError> {
    let id = cur.read_u32_le()?;
    let start = cur.position();
    loop {
        if cur.remaining() < 2 {
            return Err(DecodeError::InvalidField {
                field: "CLIPRDR_LONG_FORMAT_NAME.wszFormatName",
                reason: "the name has no terminator",
            });
        }
        if cur.read_u16_le()? == 0 {
            return Ok((id, &body[start..cur.position() - 2]));
        }
    }
}

fn utf16_to_string(units: impl IntoIterator<Item = u16>) -> String {
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn with_header(msg_type: u16, msg_flags: u16, body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + body.len());
    out.extend_from_slice(&msg_type.to_le_bytes());
    out.extend_from_slice(&msg_flags.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// The bytes of `message` after its header's `dataLen`, which [`ClipboardPdu::decode`] skips.
pub fn padding(message: &[u8]) -> usize {
    match message.get(4..8) {
        Some(len) => {
            let data_len = u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize;
            message
                .len()
                .saturating_sub(HEADER_SIZE)
                .saturating_sub(data_len)
        }
        None => 0,
    }
}

/// Encode a client Clipboard Capabilities PDU carrying one general set.
pub fn encode_capabilities(general: GeneralCapability) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + GENERAL_CAPABILITY_SIZE as usize);
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&CB_CAPSTYPE_GENERAL.to_le_bytes());
    body.extend_from_slice(&GENERAL_CAPABILITY_SIZE.to_le_bytes());
    body.extend_from_slice(&general.version.to_le_bytes());
    body.extend_from_slice(&general.general_flags.to_le_bytes());
    with_header(CB_CLIP_CAPS, 0, body)
}

/// Encode a Format List PDU. With `long_format_names` each name is NUL-terminated UTF-16;
/// otherwise each is a 32-byte UTF-16 field, truncated to 15 code units.
pub fn encode_format_list(formats: &[Format], long_format_names: bool) -> Vec<u8> {
    let mut body = Vec::new();
    for format in formats {
        body.extend_from_slice(&format.id.to_le_bytes());
        let units = format.name.encode_utf16();
        if long_format_names {
            body.extend(units.chain([0]).flat_map(u16::to_le_bytes));
        } else {
            let mut field = [0u8; SHORT_NAME_BYTES];
            let kept = units.take(SHORT_NAME_BYTES / 2 - 1);
            for (slot, unit) in field.as_chunks_mut::<2>().0.iter_mut().zip(kept) {
                *slot = unit.to_le_bytes();
            }
            body.extend_from_slice(&field);
        }
    }
    with_header(CB_FORMAT_LIST, 0, body)
}

/// Encode a Format Data Request PDU.
pub fn encode_format_data_request(format_id: u32) -> Vec<u8> {
    with_header(CB_FORMAT_DATA_REQUEST, 0, format_id.to_le_bytes().to_vec())
}

/// Encode a Format Data Response PDU: `Some` is `CB_RESPONSE_OK` with the data, `None` is
/// `CB_RESPONSE_FAIL` with none.
pub fn encode_format_data_response(data: Option<&[u8]>) -> Vec<u8> {
    match data {
        Some(data) => with_header(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, data.to_vec()),
        None => with_header(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, Vec::new()),
    }
}

/// `CF_UNICODETEXT` data for `text`: UTF-16LE with a NUL terminator.
pub fn encode_unicode_text(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// The text in `CF_UNICODETEXT` data, up to its NUL terminator or the end of the data.
pub fn decode_unicode_text(data: &[u8]) -> String {
    utf16_to_string(
        data.as_chunks::<2>()
            .0
            .iter()
            .map(|&u| u16::from_le_bytes(u))
            .take_while(|&u| u != 0),
    )
}

/// The files in `CLIPRDR_FILELIST` data (2.2.5.2.3). A name that is empty, starts with a
/// separator, holds a `:` or a `.` or `..` component is refused, and so is the whole list.
pub fn decode_file_list(data: &[u8]) -> Result<Vec<FileDescriptor>, DecodeError> {
    let mut cur = ReadCursor::new(data, "CLIPRDR_FILELIST");
    let count = cur.read_u32_le()? as usize;
    let (descriptors, rest) = data[4..].as_chunks::<FILE_DESCRIPTOR_SIZE>();
    if descriptors.len() != count || !rest.is_empty() {
        return Err(DecodeError::InvalidField {
            field: "CLIPRDR_FILELIST.cItems",
            reason: "the list does not hold exactly cItems descriptors",
        });
    }
    descriptors.iter().map(decode_file_descriptor).collect()
}

fn decode_file_descriptor(d: &[u8; FILE_DESCRIPTOR_SIZE]) -> Result<FileDescriptor, DecodeError> {
    let u32_at = |at: usize| u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]);
    let flags = u32_at(0);
    let high = u32_at(64);
    let low = u32_at(68);
    let units = d[72..72 + FILE_NAME_BYTES]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&u| u16::from_le_bytes(u));
    let len = units
        .clone()
        .position(|u| u == 0)
        .ok_or(DecodeError::InvalidField {
            field: "CLIPRDR_FILEDESCRIPTOR.fileName",
            reason: "the name has no terminator",
        })?;
    let name = utf16_to_string(units.take(len));
    let escapes = name.contains(':')
        || name
            .split(['\\', '/'])
            .any(|part| part.is_empty() || part == "." || part == "..");
    if escapes {
        return Err(DecodeError::InvalidField {
            field: "CLIPRDR_FILEDESCRIPTOR.fileName",
            reason: "the name is not a relative path inside the paste target",
        });
    }
    Ok(FileDescriptor {
        flags,
        attributes: u32_at(36),
        last_write_time: u64::from(u32_at(60)) << 32 | u64::from(u32_at(56)),
        size: (flags & FD_FILESIZE != 0).then_some(u64::from(high) << 32 | u64::from(low)),
        name,
    })
}

/// `CLIPRDR_FILELIST` data for `files`. A name longer than 259 UTF-16 code units is cut.
pub fn encode_file_list(files: &[FileDescriptor]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + files.len() * FILE_DESCRIPTOR_SIZE);
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for file in files {
        let mut d = [0u8; FILE_DESCRIPTOR_SIZE];
        d[0..4].copy_from_slice(&file.flags.to_le_bytes());
        d[36..40].copy_from_slice(&file.attributes.to_le_bytes());
        d[56..64].copy_from_slice(&file.last_write_time.to_le_bytes());
        let size = file.size.unwrap_or(0);
        d[64..68].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
        d[68..72].copy_from_slice(&(size as u32).to_le_bytes());
        let name = file.name.encode_utf16().take(FILE_NAME_BYTES / 2 - 1);
        for (slot, unit) in d[72..72 + FILE_NAME_BYTES]
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .zip(name)
        {
            *slot = unit.to_le_bytes();
        }
        out.extend_from_slice(&d);
    }
    out
}

/// Encode a File Contents Request PDU.
pub fn encode_file_contents_request(request: &FileContentsRequest) -> Vec<u8> {
    let (flags, position, len) = match request.op {
        FileContentsOp::Size => (FILECONTENTS_SIZE, 0, 8),
        FileContentsOp::Range { position, len } => (FILECONTENTS_RANGE, position, len),
    };
    let mut body = Vec::with_capacity(28);
    for value in [
        request.stream_id,
        request.index,
        flags,
        position as u32,
        (position >> 32) as u32,
        len,
    ] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    if let Some(id) = request.clip_data_id {
        body.extend_from_slice(&id.to_le_bytes());
    }
    with_header(CB_FILECONTENTS_REQUEST, 0, body)
}

/// Encode a File Contents Response PDU: `Some` is `CB_RESPONSE_OK` with the data, `None`
/// `CB_RESPONSE_FAIL` with none.
pub fn encode_file_contents_response(stream_id: u32, data: Option<&[u8]>) -> Vec<u8> {
    let mut body = stream_id.to_le_bytes().to_vec();
    let flags = match data {
        Some(data) => {
            body.extend_from_slice(data);
            CB_RESPONSE_OK
        }
        None => CB_RESPONSE_FAIL,
    };
    with_header(CB_FILECONTENTS_RESPONSE, flags, body)
}

/// Encode a Lock Clipboard Data PDU.
pub fn encode_lock_clip_data(clip_data_id: u32) -> Vec<u8> {
    with_header(CB_LOCK_CLIPDATA, 0, clip_data_id.to_le_bytes().to_vec())
}

/// Encode an Unlock Clipboard Data PDU.
pub fn encode_unlock_clip_data(clip_data_id: u32) -> Vec<u8> {
    with_header(CB_UNLOCK_CLIPDATA, 0, clip_data_id.to_le_bytes().to_vec())
}

/// Encode a Format List Response PDU.
pub fn encode_format_list_response(ok: bool) -> Vec<u8> {
    let flags = if ok { CB_RESPONSE_OK } else { CB_RESPONSE_FAIL };
    with_header(CB_FORMAT_LIST_RESPONSE, flags, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The server Clipboard Capabilities the WS2022 test VM sends (#307, #321).
    const VM_SERVER_CAPS: [u8; 24] = [
        0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00,
    ];
    /// The VM's Monitor Ready.
    const VM_MONITOR_READY: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    /// The VM's answer to a Format List (#321).
    const VM_FORMAT_LIST_RESPONSE_OK: [u8; 8] = [0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];

    fn unicode_text() -> Format {
        Format {
            id: CF_UNICODETEXT,
            name: String::new(),
        }
    }

    fn named(id: u32, name: &str) -> Format {
        Format {
            id,
            name: name.to_string(),
        }
    }

    fn header(msg_type: u16, msg_flags: u16, body: &[u8]) -> Vec<u8> {
        let mut out = msg_type.to_le_bytes().to_vec();
        out.extend_from_slice(&msg_flags.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(|u| u.to_le_bytes())
            .collect()
    }

    #[test]
    fn the_vms_capabilities_decode() {
        assert_eq!(
            ClipboardPdu::decode(&VM_SERVER_CAPS, false).unwrap(),
            ClipboardPdu::Capabilities {
                general: Some(GeneralCapability {
                    version: CB_CAPS_VERSION_2,
                    general_flags: 0x3e,
                })
            }
        );
    }

    #[test]
    fn the_vms_monitor_ready_and_response_decode() {
        assert_eq!(
            ClipboardPdu::decode(&VM_MONITOR_READY, true).unwrap(),
            ClipboardPdu::MonitorReady
        );
        assert_eq!(
            ClipboardPdu::decode(&VM_FORMAT_LIST_RESPONSE_OK, true).unwrap(),
            ClipboardPdu::FormatListResponse { ok: true }
        );
    }

    /// FreeRDP's client Capabilities, byte for byte from its `/dump` against the VM (#321).
    #[test]
    fn capabilities_encode_as_freerdp_sends_them() {
        let encoded = encode_capabilities(GeneralCapability {
            version: CB_CAPS_VERSION_2,
            general_flags: 0x2e,
        });
        assert_eq!(
            encoded,
            [
                0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn capabilities_round_trip() {
        let general = GeneralCapability {
            version: CB_CAPS_VERSION_2,
            general_flags: CB_USE_LONG_FORMAT_NAMES,
        };
        assert_eq!(
            ClipboardPdu::decode(&encode_capabilities(general), false).unwrap(),
            ClipboardPdu::Capabilities {
                general: Some(general)
            }
        );
    }

    /// FreeRDP's empty initial Format List and its one-format list, both from its dump (#321).
    #[test]
    fn format_lists_encode_as_freerdp_sends_them() {
        assert_eq!(
            encode_format_list(&[], true),
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode_format_list(&[unicode_text()], true),
            [
                0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn long_format_lists_round_trip() {
        let formats = vec![unicode_text(), named(0xC0A1, "HTML Format"), named(7, "")];
        let encoded = encode_format_list(&formats, true);
        assert_eq!(
            ClipboardPdu::decode(&encoded, true).unwrap(),
            ClipboardPdu::FormatList(formats)
        );
    }

    #[test]
    fn short_format_lists_round_trip() {
        let formats = vec![unicode_text(), named(0xC0A1, "Rich Text")];
        let encoded = encode_format_list(&formats, false);
        assert_eq!(encoded.len(), HEADER_SIZE + 2 * SHORT_FORMAT_NAME_SIZE);
        assert_eq!(
            ClipboardPdu::decode(&encoded, false).unwrap(),
            ClipboardPdu::FormatList(formats)
        );
    }

    /// A short name keeps 15 code units and its terminator.
    #[test]
    fn a_long_name_is_truncated_in_a_short_list() {
        let encoded = encode_format_list(&[named(0xC0A2, "Rich Text Format Extra")], false);
        assert_eq!(
            ClipboardPdu::decode(&encoded, false).unwrap(),
            ClipboardPdu::FormatList(vec![named(0xC0A2, "Rich Text Forma")])
        );
    }

    /// Windows sends a 16-character short name with no terminator (FreeRDP
    /// `cliprdr_read_format_list`), so the full field is the name.
    #[test]
    fn a_short_name_filling_its_field_needs_no_terminator() {
        let mut body = 0xC0A3u32.to_le_bytes().to_vec();
        body.extend(
            "Rich Text Format"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes()),
        );
        assert_eq!(body.len(), SHORT_FORMAT_NAME_SIZE);
        assert_eq!(
            ClipboardPdu::decode(&header(CB_FORMAT_LIST, 0, &body), false).unwrap(),
            ClipboardPdu::FormatList(vec![named(0xC0A3, "Rich Text Format")])
        );
    }

    #[test]
    fn ascii_short_names_decode() {
        let mut body = 0xC0A4u32.to_le_bytes().to_vec();
        let mut name = [0u8; SHORT_NAME_BYTES];
        name[..4].copy_from_slice(b"Link");
        body.extend_from_slice(&name);
        assert_eq!(
            ClipboardPdu::decode(&header(CB_FORMAT_LIST, CB_ASCII_NAMES, &body), false).unwrap(),
            ClipboardPdu::FormatList(vec![named(0xC0A4, "Link")])
        );
    }

    #[test]
    fn a_short_list_with_a_partial_entry_is_refused() {
        let body = [0u8; SHORT_FORMAT_NAME_SIZE + 4];
        assert!(ClipboardPdu::decode(&header(CB_FORMAT_LIST, 0, &body), false).is_err());
    }

    #[test]
    fn a_long_name_without_its_terminator_is_refused() {
        let mut body = 0xC0A5u32.to_le_bytes().to_vec();
        body.extend("HTML".encode_utf16().flat_map(|u| u.to_le_bytes()));
        assert!(ClipboardPdu::decode(&header(CB_FORMAT_LIST, 0, &body), true).is_err());
    }

    #[test]
    fn a_long_list_with_a_dangling_format_id_is_refused() {
        let mut body = 0xC0A6u32.to_le_bytes().to_vec();
        body.extend(utf16z("HTML"));
        body.extend_from_slice(&[0x0d, 0x00]);
        assert!(ClipboardPdu::decode(&header(CB_FORMAT_LIST, 0, &body), true).is_err());
    }

    /// The list is counted before it is allocated, as FreeRDP's `cliprdr_read_format_list`
    /// does, so a long list costs its formats and no growth headroom.
    #[test]
    fn a_long_list_is_allocated_exactly() {
        let formats: Vec<Format> = (0..5).map(|i| named(0xC100 + i, "F")).collect();
        let ClipboardPdu::FormatList(decoded) =
            ClipboardPdu::decode(&encode_format_list(&formats, true), true).unwrap()
        else {
            panic!("a Format List");
        };
        assert_eq!(decoded, formats);
        assert_eq!(decoded.capacity(), decoded.len());
    }

    #[test]
    fn a_long_list_holds_many_formats() {
        let mut body = Vec::new();
        for (id, name) in [(13u32, ""), (0xC0A7, "A"), (0xC0A8, "BB")] {
            body.extend_from_slice(&id.to_le_bytes());
            body.extend(utf16z(name));
        }
        assert_eq!(
            ClipboardPdu::decode(&header(CB_FORMAT_LIST, 0, &body), true).unwrap(),
            ClipboardPdu::FormatList(vec![
                unicode_text(),
                named(0xC0A7, "A"),
                named(0xC0A8, "BB")
            ])
        );
    }

    #[test]
    fn format_list_responses_encode_and_decode() {
        assert_eq!(
            encode_format_list_response(true),
            VM_FORMAT_LIST_RESPONSE_OK
        );
        assert_eq!(
            ClipboardPdu::decode(&encode_format_list_response(false), true).unwrap(),
            ClipboardPdu::FormatListResponse { ok: false }
        );
    }

    #[test]
    fn a_response_that_is_neither_ok_nor_fail_is_refused() {
        assert!(ClipboardPdu::decode(&header(CB_FORMAT_LIST_RESPONSE, 0, &[]), true).is_err());
        let both = CB_RESPONSE_OK | CB_RESPONSE_FAIL;
        assert!(ClipboardPdu::decode(&header(CB_FORMAT_LIST_RESPONSE, both, &[]), true).is_err());
    }

    #[test]
    fn a_data_length_past_the_message_is_refused() {
        let mut short = VM_SERVER_CAPS.to_vec();
        short.pop();
        assert!(ClipboardPdu::decode(&short, true).is_err());
        assert!(ClipboardPdu::decode(&VM_MONITOR_READY[..7], true).is_err());
    }

    /// The VM's File Contents Response for `small.txt` (#324): `dataLen` is 16, and four zero
    /// bytes follow the body. What follows `dataLen` is padding, not part of the PDU.
    #[test]
    fn bytes_after_the_data_length_are_padding() {
        let vm_response: [u8; 28] = [
            0x09, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x68, 0x65,
            0x6c, 0x6c, 0x6f, 0x20, 0xed, 0x8c, 0x8c, 0xec, 0x9d, 0xbc, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            ClipboardPdu::decode(&vm_response, true).unwrap(),
            ClipboardPdu::FileContentsResponse {
                stream_id: 1,
                data: Some("hello 파일".as_bytes().to_vec())
            }
        );
        let mut padded = VM_MONITOR_READY.to_vec();
        padded.extend_from_slice(&[0; 4]);
        assert_eq!(
            ClipboardPdu::decode(&padded, true).unwrap(),
            ClipboardPdu::MonitorReady
        );
        assert_eq!(padding(&padded), 4);
        assert_eq!(padding(&vm_response), 4);
        assert_eq!(padding(&VM_MONITOR_READY), 0);
        assert_eq!(padding(&VM_MONITOR_READY[..6]), 0);
    }

    #[test]
    fn capabilities_without_a_general_set_decode() {
        let body = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            ClipboardPdu::decode(&header(CB_CLIP_CAPS, 0, &body), true).unwrap(),
            ClipboardPdu::Capabilities { general: None }
        );
    }

    /// Only the general set is defined (2.2.2.1.1); FreeRDP refuses any other type.
    #[test]
    fn an_unknown_capability_set_is_refused() {
        let mut body = vec![0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0x00];
        body.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
        assert!(ClipboardPdu::decode(&header(CB_CLIP_CAPS, 0, &body), true).is_err());
    }

    #[test]
    fn a_capability_set_shorter_than_its_header_is_refused() {
        let body = [0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00];
        assert!(ClipboardPdu::decode(&header(CB_CLIP_CAPS, 0, &body), true).is_err());
    }

    #[test]
    fn a_general_set_with_the_wrong_length_is_refused() {
        let mut body = vec![0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00];
        body.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
        assert!(ClipboardPdu::decode(&header(CB_CLIP_CAPS, 0, &body), true).is_err());
    }

    #[test]
    fn capability_sets_must_fill_the_message() {
        let mut caps = VM_SERVER_CAPS.to_vec();
        caps.extend_from_slice(&[0, 0]);
        caps[4] += 2;
        assert!(ClipboardPdu::decode(&caps, true).is_err());
    }

    #[test]
    fn unknown_message_types_decode_as_unknown() {
        assert_eq!(
            ClipboardPdu::decode(&header(0x0006, 0, &[0x0d, 0, 0, 0]), true).unwrap(),
            ClipboardPdu::Unknown {
                msg_type: 0x0006,
                msg_flags: 0
            }
        );
    }

    #[test]
    fn format_data_requests_encode_and_decode() {
        let encoded = encode_format_data_request(CF_UNICODETEXT);
        assert_eq!(
            encoded,
            [
                0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(
            ClipboardPdu::decode(&encoded, true).unwrap(),
            ClipboardPdu::FormatDataRequest {
                format_id: CF_UNICODETEXT
            }
        );
    }

    #[test]
    fn a_format_data_request_is_one_format_id() {
        assert!(
            ClipboardPdu::decode(&header(CB_FORMAT_DATA_REQUEST, 0, &[0x0d, 0, 0]), true).is_err()
        );
        assert!(
            ClipboardPdu::decode(
                &header(CB_FORMAT_DATA_REQUEST, 0, &[0x0d, 0, 0, 0, 0]),
                true
            )
            .is_err()
        );
    }

    #[test]
    fn format_data_responses_encode_and_decode() {
        let ok = encode_format_data_response(Some(b"hi"));
        assert_eq!(
            ok,
            [0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, b'h', b'i']
        );
        assert_eq!(
            ClipboardPdu::decode(&ok, true).unwrap(),
            ClipboardPdu::FormatDataResponse {
                data: Some(b"hi".to_vec())
            }
        );
        let fail = encode_format_data_response(None);
        assert_eq!(fail, [0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            ClipboardPdu::decode(&fail, true).unwrap(),
            ClipboardPdu::FormatDataResponse { data: None }
        );
    }

    /// 2.2.5.2: exactly one of OK and FAIL, and a failure carries no data.
    #[test]
    fn malformed_format_data_responses_are_refused() {
        assert!(ClipboardPdu::decode(&header(CB_FORMAT_DATA_RESPONSE, 0, b"x"), true).is_err());
        let both = CB_RESPONSE_OK | CB_RESPONSE_FAIL;
        assert!(ClipboardPdu::decode(&header(CB_FORMAT_DATA_RESPONSE, both, b"x"), true).is_err());
        assert!(
            ClipboardPdu::decode(
                &header(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, b"x"),
                true
            )
            .is_err()
        );
    }

    /// An empty successful response is data of length zero, not a failure.
    #[test]
    fn an_empty_successful_response_is_empty_data() {
        assert_eq!(
            ClipboardPdu::decode(&encode_format_data_response(Some(&[])), true).unwrap(),
            ClipboardPdu::FormatDataResponse {
                data: Some(Vec::new())
            }
        );
    }

    #[test]
    fn unicode_text_is_nul_terminated_utf16() {
        assert_eq!(encode_unicode_text("hé"), [b'h', 0, 0xe9, 0, 0, 0]);
        let text = "Hé 한글 😀";
        assert_eq!(decode_unicode_text(&encode_unicode_text(text)), text);
    }

    /// The text ends at the first NUL; what follows it is not text.
    #[test]
    fn unicode_text_stops_at_its_terminator() {
        assert_eq!(decode_unicode_text(&[b'a', 0, 0, 0, b'b', 0]), "a");
        assert_eq!(decode_unicode_text(&[b'a', 0, b'b', 0]), "ab");
        assert_eq!(decode_unicode_text(&[b'a', 0, b'b']), "a");
        assert_eq!(decode_unicode_text(&[]), "");
    }

    fn file(name: &str, size: Option<u64>) -> FileDescriptor {
        FileDescriptor {
            flags: FD_ATTRIBUTES | FD_WRITESTIME | if size.is_some() { FD_FILESIZE } else { 0 },
            attributes: 0x20,
            last_write_time: 0x01DA_0000_1234_5678,
            size,
            name: name.to_string(),
        }
    }

    #[test]
    fn file_lists_round_trip() {
        let files = vec![
            file("big.bin", Some(300_000)),
            file("dir\\small.txt", Some(12)),
            file("파일.txt", None),
        ];
        let data = encode_file_list(&files);
        assert_eq!(data.len(), 4 + 3 * FILE_DESCRIPTOR_SIZE);
        assert_eq!(decode_file_list(&data).unwrap(), files);
    }

    /// The field layout of 2.2.5.2.3.1, checked byte by byte on one descriptor.
    #[test]
    fn a_file_descriptor_is_laid_out_as_the_spec_says() {
        let data = encode_file_list(&[file("a", Some(0x1_0000_0002))]);
        assert_eq!(&data[..4], &1u32.to_le_bytes());
        let d = &data[4..];
        assert_eq!(
            &d[0..4],
            &(FD_ATTRIBUTES | FD_WRITESTIME | FD_FILESIZE).to_le_bytes()
        );
        assert!(d[4..36].iter().all(|&b| b == 0));
        assert_eq!(&d[36..40], &0x20u32.to_le_bytes());
        assert!(d[40..56].iter().all(|&b| b == 0));
        assert_eq!(&d[56..64], &0x01DA_0000_1234_5678u64.to_le_bytes());
        assert_eq!(&d[64..68], &1u32.to_le_bytes());
        assert_eq!(&d[68..72], &2u32.to_le_bytes());
        assert_eq!(&d[72..76], &[b'a', 0, 0, 0]);
    }

    #[test]
    fn a_file_list_must_hold_exactly_its_items() {
        let mut data = encode_file_list(&[file("a", None)]);
        data.push(0);
        assert!(decode_file_list(&data).is_err());
        data.truncate(data.len() - 2);
        assert!(decode_file_list(&data).is_err());
        assert!(decode_file_list(&[1, 0, 0]).is_err());
        let mut two = encode_file_list(&[file("a", None)]);
        two[0] = 2;
        assert!(decode_file_list(&two).is_err());
        assert_eq!(decode_file_list(&0u32.to_le_bytes()).unwrap(), Vec::new());
    }

    #[test]
    fn a_file_name_without_its_terminator_is_refused() {
        let mut data = encode_file_list(&[file("a", None)]);
        let name = 4 + 72;
        for b in &mut data[name..name + FILE_NAME_BYTES] {
            *b = b'a';
        }
        assert!(decode_file_list(&data).is_err());
    }

    /// The maintainer's call (#324): a name that could leave the directory the host chose, or
    /// name another stream or drive, refuses the whole list.
    #[test]
    fn a_file_name_that_could_escape_is_refused() {
        for name in [
            "", "..", "..\\x", "a\\..\\b", "a/../b", ".", "a\\.\\b", "\\x", "/x", "C:x",
            "a:stream", "a\\",
        ] {
            let data = encode_file_list(&[file("ok", None), file(name, None)]);
            assert!(
                decode_file_list(&data).is_err(),
                "{name:?} should be refused"
            );
        }
        let data = encode_file_list(&[file("dir\\sub\\f.txt", None), file("..x", None)]);
        assert!(decode_file_list(&data).is_ok());
    }

    #[test]
    fn file_contents_requests_round_trip() {
        let size = FileContentsRequest {
            stream_id: 7,
            index: 1,
            op: FileContentsOp::Size,
            clip_data_id: Some(3),
        };
        let encoded = encode_file_contents_request(&size);
        assert_eq!(
            encoded,
            [
                0x08, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 7, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 3, 0, 0, 0
            ]
        );
        assert_eq!(
            ClipboardPdu::decode(&encoded, true).unwrap(),
            ClipboardPdu::FileContentsRequest(size)
        );
        let range = FileContentsRequest {
            stream_id: 8,
            index: 0,
            op: FileContentsOp::Range {
                position: 0x1_0000_0010,
                len: 65536,
            },
            clip_data_id: None,
        };
        let encoded = encode_file_contents_request(&range);
        assert_eq!(encoded.len(), 8 + 24);
        assert_eq!(&encoded[20..28], &[0x10, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(
            ClipboardPdu::decode(&encoded, true).unwrap(),
            ClipboardPdu::FileContentsRequest(range)
        );
    }

    /// 2.2.5.3: SIZE and RANGE are exclusive, and a SIZE request asks for 8 bytes at 0.
    #[test]
    fn malformed_file_contents_requests_are_refused() {
        let body = |flags: u32, low: u32, cb: u32| {
            let mut b = Vec::new();
            for v in [1u32, 0, flags, low, 0, cb] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            header(CB_FILECONTENTS_REQUEST, 0, &b)
        };
        assert!(ClipboardPdu::decode(&body(3, 0, 8), true).is_err());
        assert!(ClipboardPdu::decode(&body(0, 0, 8), true).is_err());
        assert!(ClipboardPdu::decode(&body(1, 0, 4), true).is_err());
        assert!(ClipboardPdu::decode(&body(1, 5, 8), true).is_err());
        let mut long = body(2, 0, 8);
        long.extend_from_slice(&[0; 5]);
        long[4] += 5;
        assert!(ClipboardPdu::decode(&long, true).is_err());
    }

    #[test]
    fn file_contents_responses_round_trip() {
        let ok = encode_file_contents_response(9, Some(b"abc"));
        assert_eq!(
            ok,
            [0x09, 0, 0x01, 0, 7, 0, 0, 0, 9, 0, 0, 0, b'a', b'b', b'c']
        );
        assert_eq!(
            ClipboardPdu::decode(&ok, true).unwrap(),
            ClipboardPdu::FileContentsResponse {
                stream_id: 9,
                data: Some(b"abc".to_vec())
            }
        );
        let fail = encode_file_contents_response(9, None);
        assert_eq!(
            ClipboardPdu::decode(&fail, true).unwrap(),
            ClipboardPdu::FileContentsResponse {
                stream_id: 9,
                data: None
            }
        );
        assert!(
            ClipboardPdu::decode(&header(CB_FILECONTENTS_RESPONSE, 1, &[9, 0, 0]), true).is_err()
        );
        let both = CB_RESPONSE_OK | CB_RESPONSE_FAIL;
        assert!(
            ClipboardPdu::decode(&header(CB_FILECONTENTS_RESPONSE, both, &[9, 0, 0, 0]), true)
                .is_err()
        );
    }

    #[test]
    fn lock_and_unlock_round_trip() {
        let lock = encode_lock_clip_data(5);
        assert_eq!(lock, [0x0a, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(
            ClipboardPdu::decode(&lock, true).unwrap(),
            ClipboardPdu::LockClipData { clip_data_id: 5 }
        );
        let unlock = encode_unlock_clip_data(5);
        assert_eq!(unlock, [0x0b, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(
            ClipboardPdu::decode(&unlock, true).unwrap(),
            ClipboardPdu::UnlockClipData { clip_data_id: 5 }
        );
        assert!(ClipboardPdu::decode(&header(CB_LOCK_CLIPDATA, 0, &[5, 0, 0]), true).is_err());
    }

    proptest! {
        // ADR-0008: a server-controlled clipboard message surfaces as a typed `DecodeError`,
        // never a panic. Reaching the end without unwinding is the assertion.
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn decode_never_panics_on_arbitrary_input(
            message in proptest::collection::vec(any::<u8>(), 0..=512),
            long_format_names in any::<bool>(),
        ) {
            let _ = ClipboardPdu::decode(&message, long_format_names);
            let _ = decode_unicode_text(&message);
            let _ = decode_file_list(&message);
        }
    }
}
