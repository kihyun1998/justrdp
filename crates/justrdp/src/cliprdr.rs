//! The clipboard channel's initialization sequence (MS-RDPECLIP 1.3.2.1), as a sans-IO helper
//! the host drives. The session never interprets `cliprdr` bytes: the host requests the channel
//! with [`channel_def`], feeds each `SessionOutput::ChannelData` message on it to
//! [`Clipboard::process`], and passes every [`ClipboardOutput::Send`] to
//! `SessionStateMachine::send_channel`.

use justrdp_pdu::DecodeError;
use justrdp_pdu::cliprdr::{
    self as pdu, CB_CAPS_VERSION_2, CB_USE_LONG_FORMAT_NAMES, ClipboardPdu, Format,
    GeneralCapability,
};
use justrdp_pdu::gcc::{CHANNEL_OPTION_INITIALIZED, CHANNEL_OPTION_SHOW_PROTOCOL, ChannelDef};

/// The options the clipboard channel is requested with. `CHANNEL_OPTION_SHOW_PROTOCOL` makes
/// every chunk sent on it carry `CHANNEL_FLAG_SHOW_PROTOCOL`.
pub const CHANNEL_OPTIONS: u32 = CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_SHOW_PROTOCOL;

/// The `generalFlags` this helper implements and so advertises.
pub const ADVERTISED_FLAGS: u32 = CB_USE_LONG_FORMAT_NAMES;

/// The Client Network Data entry for the clipboard channel.
pub fn channel_def() -> ChannelDef {
    ChannelDef::new(pdu::CHANNEL_NAME, CHANNEL_OPTIONS)
        .expect("\"cliprdr\" is a valid channel name")
}

/// What processing one clipboard message produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardOutput {
    /// A message to send on the clipboard channel.
    Send(Vec<u8>),
    /// The server answered a Format List this side sent.
    FormatListResponse {
        /// Whether the server accepted it.
        ok: bool,
    },
    /// The server announced the formats on its clipboard. It has already been answered.
    RemoteFormatList(Vec<Format>),
    /// A server Format List could not be decoded. It has already been answered with a failure.
    FormatListRejected(DecodeError),
}

/// The client side of one clipboard channel. Its initial Format List is empty.
#[derive(Debug, Clone, Default)]
pub struct Clipboard {
    server_flags: u32,
    general_flags: u32,
}

impl Clipboard {
    /// A clipboard waiting for the server's Monitor Ready.
    pub fn new() -> Self {
        Self::default()
    }

    /// The `generalFlags` both sides advertised, zero until the server's Monitor Ready.
    pub fn general_flags(&self) -> u32 {
        self.general_flags
    }

    /// Process one whole message received on the clipboard channel.
    pub fn process(&mut self, message: &[u8]) -> Result<Vec<ClipboardOutput>, DecodeError> {
        let long_format_names = self.general_flags & CB_USE_LONG_FORMAT_NAMES != 0;
        let pdu = match ClipboardPdu::decode(message, long_format_names) {
            Ok(pdu) => pdu,
            Err(error) if message.starts_with(&pdu::CB_FORMAT_LIST.to_le_bytes()) => {
                tracing::warn!(target: "rdp_cliprdr", %error, "server Format List refused");
                return Ok(vec![
                    ClipboardOutput::Send(pdu::encode_format_list_response(false)),
                    ClipboardOutput::FormatListRejected(error),
                ]);
            }
            Err(error) => return Err(error),
        };
        match pdu {
            ClipboardPdu::Capabilities { general } => {
                self.server_flags = general.map_or(0, |g| g.general_flags);
                Ok(Vec::new())
            }
            ClipboardPdu::MonitorReady => {
                self.general_flags = ADVERTISED_FLAGS & self.server_flags;
                let caps = pdu::encode_capabilities(GeneralCapability {
                    version: CB_CAPS_VERSION_2,
                    general_flags: self.general_flags,
                });
                let list = pdu::encode_format_list(
                    &[],
                    self.general_flags & CB_USE_LONG_FORMAT_NAMES != 0,
                );
                Ok(vec![
                    ClipboardOutput::Send(caps),
                    ClipboardOutput::Send(list),
                ])
            }
            ClipboardPdu::FormatList(formats) => Ok(vec![
                ClipboardOutput::Send(pdu::encode_format_list_response(true)),
                ClipboardOutput::RemoteFormatList(formats),
            ]),
            ClipboardPdu::FormatListResponse { ok } => {
                Ok(vec![ClipboardOutput::FormatListResponse { ok }])
            }
            ClipboardPdu::Unknown {
                msg_type,
                msg_flags,
            } => {
                tracing::debug!(
                    target: "rdp_cliprdr",
                    msg_type,
                    msg_flags,
                    "clipboard message not handled"
                );
                Ok(Vec::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::cliprdr::{CF_UNICODETEXT, encode_format_list};

    /// The server Clipboard Capabilities the WS2022 test VM sends (#307, #321).
    const VM_SERVER_CAPS: [u8; 24] = [
        0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00,
    ];
    const VM_MONITOR_READY: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    fn unicode_text() -> Format {
        Format {
            id: CF_UNICODETEXT,
            name: String::new(),
        }
    }

    fn sent(outputs: &[ClipboardOutput]) -> Vec<&[u8]> {
        outputs
            .iter()
            .filter_map(|o| match o {
                ClipboardOutput::Send(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
            .collect()
    }

    fn caps_with(flags: u32) -> Vec<u8> {
        pdu::encode_capabilities(GeneralCapability {
            version: CB_CAPS_VERSION_2,
            general_flags: flags,
        })
    }

    #[test]
    fn the_channel_is_requested_showing_the_protocol() {
        let def = channel_def();
        assert_eq!(def.name_str(), "cliprdr");
        assert_eq!(
            def.options,
            CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_SHOW_PROTOCOL
        );
    }

    /// Against the VM's own messages, the answer is FreeRDP's (#321): Capabilities carrying
    /// the one flag both sides have, then the initial Format List with long names.
    #[test]
    fn monitor_ready_is_answered_with_capabilities_and_a_format_list() {
        let mut clipboard = Clipboard::new();
        assert!(clipboard.process(&VM_SERVER_CAPS).unwrap().is_empty());
        let outputs = clipboard.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(
            outputs,
            vec![
                ClipboardOutput::Send(caps_with(CB_USE_LONG_FORMAT_NAMES)),
                ClipboardOutput::Send(vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ]
        );
        assert_eq!(clipboard.general_flags(), CB_USE_LONG_FORMAT_NAMES);
    }

    /// A server without long format names is not offered the flag.
    #[test]
    fn a_server_without_long_names_is_not_offered_them() {
        let mut clipboard = Clipboard::new();
        clipboard.process(&caps_with(0)).unwrap();
        let outputs = clipboard.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(
            sent(&outputs),
            vec![
                caps_with(0).as_slice(),
                encode_format_list(&[], false).as_slice()
            ]
        );
        assert_eq!(clipboard.general_flags(), 0);
    }

    /// With no server Capabilities before Monitor Ready, the server's flags are zero
    /// (MS-RDPECLIP 2.2.2.1.1.1; FreeRDP `cliprdr_process_monitor_ready`).
    #[test]
    fn monitor_ready_without_server_capabilities_negotiates_nothing() {
        let mut clipboard = Clipboard::new();
        let outputs = clipboard.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(sent(&outputs)[0], caps_with(0));
        assert_eq!(clipboard.general_flags(), 0);
    }

    /// The server offers more than this helper implements; only the implemented flag is sent.
    #[test]
    fn only_implemented_flags_are_advertised() {
        let mut clipboard = Clipboard::new();
        clipboard.process(&caps_with(0xFFFF_FFFF)).unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(clipboard.general_flags(), CB_USE_LONG_FORMAT_NAMES);
    }

    #[test]
    fn a_server_format_list_is_answered_and_surfaced() {
        let mut clipboard = Clipboard::new();
        clipboard.process(&VM_SERVER_CAPS).unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        let html = Format {
            id: 0xC0A1,
            name: "HTML Format".to_string(),
        };
        let formats = vec![unicode_text(), html];
        let outputs = clipboard
            .process(&encode_format_list(&formats, true))
            .unwrap();
        assert_eq!(
            outputs,
            vec![
                ClipboardOutput::Send(vec![0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
                ClipboardOutput::RemoteFormatList(formats),
            ]
        );
    }

    /// A server Format List is read in the layout the two sides negotiated.
    #[test]
    fn a_server_format_list_is_read_with_the_negotiated_names() {
        let mut clipboard = Clipboard::new();
        clipboard.process(&caps_with(0)).unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        let outputs = clipboard
            .process(&encode_format_list(&[unicode_text()], false))
            .unwrap();
        assert_eq!(
            outputs[1],
            ClipboardOutput::RemoteFormatList(vec![unicode_text()])
        );
    }

    #[test]
    fn a_format_list_response_is_surfaced() {
        let mut clipboard = Clipboard::new();
        let ok = [0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let fail = [0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            clipboard.process(&ok).unwrap(),
            vec![ClipboardOutput::FormatListResponse { ok: true }]
        );
        assert_eq!(
            clipboard.process(&fail).unwrap(),
            vec![ClipboardOutput::FormatListResponse { ok: false }]
        );
    }

    #[test]
    fn an_unhandled_message_produces_nothing() {
        let mut clipboard = Clipboard::new();
        let data_request = [
            0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
        ];
        assert!(clipboard.process(&data_request).unwrap().is_empty());
    }

    /// MS-RDPECLIP 3.1.5.2.2: a Format List that cannot be processed is answered with a
    /// failure, and the host is told why.
    #[test]
    fn an_undecodable_server_format_list_is_answered_with_a_failure() {
        let mut clipboard = Clipboard::new();
        clipboard.process(&VM_SERVER_CAPS).unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        // A long name with no terminator.
        let unterminated = [
            0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x41, 0x00,
        ];
        let outputs = clipboard.process(&unterminated).unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(
            outputs[0],
            ClipboardOutput::Send(vec![0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
        );
        assert!(matches!(outputs[1], ClipboardOutput::FormatListRejected(_)));
    }

    /// A Format List whose header disagrees with the message is refused the same way.
    #[test]
    fn a_format_list_with_a_bad_length_is_answered_with_a_failure() {
        let mut clipboard = Clipboard::new();
        let outputs = clipboard
            .process(&[0x02, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00])
            .unwrap();
        assert_eq!(
            outputs[0],
            ClipboardOutput::Send(vec![0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
        );
    }

    /// Any other undecodable message, or one too short to name its type, is an error.
    #[test]
    fn a_malformed_message_is_an_error() {
        assert!(Clipboard::new().process(&[0x02]).is_err());
        let bad_response = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(Clipboard::new().process(&bad_response).is_err());
        let mut clipboard = Clipboard::new();
        assert!(clipboard.process(&VM_MONITOR_READY[..6]).is_err());
    }
}
