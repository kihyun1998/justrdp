//! Clipboard virtual channel PDUs (MS-RDPECLIP), carried over the static channel
//! [`CHANNEL_NAME`]. Every PDU is one whole channel message: a `CLIPRDR_HEADER` (2.2.1) and
//! `dataLen` bytes of body. The initialization sequence (1.3.2.1) is server Capabilities and
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
/// `CB_CLIP_CAPS` (2.2.2.1).
pub const CB_CLIP_CAPS: u16 = 0x0007;

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

/// `CF_UNICODETEXT`, the standard clipboard format for UTF-16 text.
pub const CF_UNICODETEXT: u32 = 13;

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
    /// advertised [`CB_USE_LONG_FORMAT_NAMES`], which decides a Format List's layout.
    pub fn decode(message: &[u8], long_format_names: bool) -> Result<Self, DecodeError> {
        let mut cur = ReadCursor::new(message, "CLIPRDR_HEADER");
        let msg_type = cur.read_u16_le()?;
        let msg_flags = cur.read_u16_le()?;
        let data_len = cur.read_u32_le()? as usize;
        if data_len != cur.remaining() {
            return Err(DecodeError::InvalidField {
                field: "CLIPRDR_HEADER.dataLen",
                reason: "does not match the message length",
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
            msg_type => Ok(ClipboardPdu::Unknown {
                msg_type,
                msg_flags,
            }),
        }
    }
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
    let mut formats = Vec::new();
    while cur.remaining() != 0 {
        let id = cur.read_u32_le()?;
        let mut units = Vec::new();
        loop {
            if cur.remaining() < 2 {
                return Err(DecodeError::InvalidField {
                    field: "CLIPRDR_LONG_FORMAT_NAME.wszFormatName",
                    reason: "the name has no terminator",
                });
            }
            match cur.read_u16_le()? {
                0 => break,
                unit => units.push(unit),
            }
        }
        formats.push(Format {
            id,
            name: utf16_to_string(units),
        });
    }
    Ok(ClipboardPdu::FormatList(formats))
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
    fn a_data_length_that_disagrees_with_the_message_is_refused() {
        let mut long = VM_MONITOR_READY.to_vec();
        long.push(0);
        assert!(ClipboardPdu::decode(&long, true).is_err());
        let mut short = VM_SERVER_CAPS.to_vec();
        short.pop();
        assert!(ClipboardPdu::decode(&short, true).is_err());
        assert!(ClipboardPdu::decode(&VM_MONITOR_READY[..7], true).is_err());
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
            ClipboardPdu::decode(&header(0x0004, 0, &[0x0d, 0, 0, 0]), true).unwrap(),
            ClipboardPdu::Unknown {
                msg_type: 0x0004,
                msg_flags: 0
            }
        );
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
        }
    }
}
