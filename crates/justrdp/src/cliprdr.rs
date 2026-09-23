//! The clipboard channel (MS-RDPECLIP) as a sans-IO helper the host drives: the
//! initialization sequence (1.3.2.1), Format Lists both ways, and Format Data Requests and
//! Responses both ways. The session never interprets `cliprdr` bytes: the host requests the channel
//! with [`channel_def`], feeds each `SessionOutput::ChannelData` message on it to
//! [`Clipboard::process`], and passes every [`ClipboardOutput::Send`] to
//! `SessionStateMachine::send_channel`.

use std::collections::VecDeque;

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
    /// The server asked for the data of a format this side announced. The host answers with
    /// [`Clipboard::respond`].
    DataRequested {
        /// The requested format.
        format_id: u32,
    },
    /// The server answered a [`Clipboard::request`]. `None` is a failure.
    FormatData {
        /// The format that was requested.
        format_id: u32,
        /// The format's data.
        data: Option<Vec<u8>>,
    },
}

/// Why [`Clipboard::request`] sent nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// The server's current Format List does not hold this format.
    NotAnnounced {
        /// The format asked for.
        format_id: u32,
    },
    /// A request is already waiting for its response.
    Pending {
        /// The format that request asked for.
        format_id: u32,
    },
}

/// A Format Data Response this side owes the server, in the order the requests came.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owed {
    /// The host answers it.
    Host,
    /// A failure, sent once every answer before it has gone out.
    Refusal,
}

/// The client side of one clipboard channel.
#[derive(Debug, Clone, Default)]
pub struct Clipboard {
    server_flags: u32,
    general_flags: u32,
    ready: bool,
    local_formats: Vec<Format>,
    local_list_refused: bool,
    remote_format_ids: Vec<u32>,
    requested: Option<u32>,
    owed: VecDeque<Owed>,
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

    /// Announce the formats now on the host's clipboard. Before the server's Monitor Ready they
    /// are kept for the initial Format List and nothing is returned; after it, the Format List
    /// to send is.
    pub fn announce(&mut self, formats: Vec<Format>) -> Option<Vec<u8>> {
        self.local_formats = formats;
        self.local_list_refused = false;
        self.ready.then(|| self.local_format_list())
    }

    /// The Format Data Request for `format_id` from the server's clipboard. The answer arrives
    /// as [`ClipboardOutput::FormatData`].
    pub fn request(&mut self, format_id: u32) -> Result<Vec<u8>, RequestError> {
        if let Some(format_id) = self.requested {
            return Err(RequestError::Pending { format_id });
        }
        if !self.remote_format_ids.contains(&format_id) {
            return Err(RequestError::NotAnnounced { format_id });
        }
        self.requested = Some(format_id);
        Ok(pdu::encode_format_data_request(format_id))
    }

    /// The Format Data Responses owed now that the host answers the oldest
    /// [`ClipboardOutput::DataRequested`]: `Some` sends the data, `None` a failure. Refusals
    /// queued behind that request follow it. Empty when no request is waiting.
    pub fn respond(&mut self, data: Option<&[u8]>) -> Vec<Vec<u8>> {
        if self.owed.pop_front() != Some(Owed::Host) {
            return Vec::new();
        }
        let mut out = vec![pdu::encode_format_data_response(data)];
        while self.owed.front() == Some(&Owed::Refusal) {
            self.owed.pop_front();
            out.push(pdu::encode_format_data_response(None));
        }
        out
    }

    /// Stop waiting for the answer to [`Clipboard::request`], returning the format it asked
    /// for. A response that arrives later is skipped.
    pub fn cancel_request(&mut self) -> Option<u32> {
        self.requested.take()
    }

    /// Answer a server request with a failure, after every answer still owed before it.
    fn refuse_request(&mut self) -> Vec<ClipboardOutput> {
        if self.owed.is_empty() {
            vec![ClipboardOutput::Send(pdu::encode_format_data_response(
                None,
            ))]
        } else {
            self.owed.push_back(Owed::Refusal);
            Vec::new()
        }
    }

    /// Handle a message that does not decode, by the type its header names.
    fn undecodable(
        &mut self,
        message: &[u8],
        error: DecodeError,
    ) -> Result<Vec<ClipboardOutput>, DecodeError> {
        let msg_type = message.get(..2).map(|t| u16::from_le_bytes([t[0], t[1]]));
        tracing::warn!(target: "rdp_cliprdr", ?msg_type, %error, "clipboard message refused");
        match msg_type {
            Some(pdu::CB_FORMAT_LIST) => {
                self.remote_format_ids.clear();
                Ok(vec![
                    ClipboardOutput::Send(pdu::encode_format_list_response(false)),
                    ClipboardOutput::FormatListRejected(error),
                ])
            }
            Some(pdu::CB_FORMAT_DATA_REQUEST) => Ok(self.refuse_request()),
            Some(pdu::CB_FORMAT_DATA_RESPONSE) => {
                self.requested = None;
                Err(error)
            }
            _ => Err(error),
        }
    }

    fn local_format_list(&self) -> Vec<u8> {
        pdu::encode_format_list(
            &self.local_formats,
            self.general_flags & CB_USE_LONG_FORMAT_NAMES != 0,
        )
    }

    /// Process one whole message received on the clipboard channel.
    pub fn process(&mut self, message: &[u8]) -> Result<Vec<ClipboardOutput>, DecodeError> {
        let long_format_names = self.general_flags & CB_USE_LONG_FORMAT_NAMES != 0;
        let pdu = match ClipboardPdu::decode(message, long_format_names) {
            Ok(pdu) => pdu,
            Err(error) => return self.undecodable(message, error),
        };
        match pdu {
            ClipboardPdu::Capabilities { general } => {
                self.server_flags = general.map_or(0, |g| g.general_flags);
                Ok(Vec::new())
            }
            ClipboardPdu::MonitorReady => {
                self.general_flags = ADVERTISED_FLAGS & self.server_flags;
                self.ready = true;
                let caps = pdu::encode_capabilities(GeneralCapability {
                    version: CB_CAPS_VERSION_2,
                    general_flags: self.general_flags,
                });
                Ok(vec![
                    ClipboardOutput::Send(caps),
                    ClipboardOutput::Send(self.local_format_list()),
                ])
            }
            ClipboardPdu::FormatList(formats) => {
                self.remote_format_ids = formats.iter().map(|f| f.id).collect();
                Ok(vec![
                    ClipboardOutput::Send(pdu::encode_format_list_response(true)),
                    ClipboardOutput::RemoteFormatList(formats),
                ])
            }
            ClipboardPdu::FormatListResponse { ok } => {
                self.local_list_refused = !ok;
                Ok(vec![ClipboardOutput::FormatListResponse { ok }])
            }
            ClipboardPdu::FormatDataRequest { format_id } => {
                let announced = self.local_formats.iter().any(|f| f.id == format_id);
                if !announced || self.local_list_refused {
                    tracing::warn!(
                        target: "rdp_cliprdr",
                        format_id,
                        announced,
                        "Format Data Request refused"
                    );
                    return Ok(self.refuse_request());
                }
                self.owed.push_back(Owed::Host);
                Ok(vec![ClipboardOutput::DataRequested { format_id }])
            }
            ClipboardPdu::FormatDataResponse { data } => match self.requested.take() {
                Some(format_id) => Ok(vec![ClipboardOutput::FormatData { format_id, data }]),
                None => {
                    tracing::warn!(target: "rdp_cliprdr", "Format Data Response nothing asked for");
                    Ok(Vec::new())
                }
            },
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
        let temp_directory = [0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(clipboard.process(&temp_directory).unwrap().is_empty());
    }

    fn ready() -> Clipboard {
        let mut clipboard = Clipboard::new();
        clipboard.process(&VM_SERVER_CAPS).unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        clipboard
    }

    fn server_copied(clipboard: &mut Clipboard, formats: &[Format]) {
        clipboard
            .process(&encode_format_list(formats, true))
            .unwrap();
    }

    fn data_request(format_id: u32) -> Vec<u8> {
        pdu::encode_format_data_request(format_id)
    }

    /// Formats announced before Monitor Ready become the initial Format List.
    #[test]
    fn formats_announced_early_are_the_initial_list() {
        let mut clipboard = Clipboard::new();
        assert_eq!(clipboard.announce(vec![unicode_text()]), None);
        clipboard.process(&VM_SERVER_CAPS).unwrap();
        let outputs = clipboard.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(
            sent(&outputs)[1],
            encode_format_list(&[unicode_text()], true)
        );
    }

    #[test]
    fn formats_announced_later_are_sent_at_once() {
        let mut clipboard = ready();
        assert_eq!(
            clipboard.announce(vec![unicode_text()]),
            Some(encode_format_list(&[unicode_text()], true))
        );
    }

    /// Server to host: request a format the server listed, and the response carries it.
    #[test]
    fn a_requested_format_arrives_as_its_data() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[unicode_text()]);
        assert_eq!(
            clipboard.request(CF_UNICODETEXT),
            Ok(data_request(CF_UNICODETEXT))
        );
        let text = pdu::encode_unicode_text("한글");
        let outputs = clipboard
            .process(&pdu::encode_format_data_response(Some(&text)))
            .unwrap();
        assert_eq!(
            outputs,
            vec![ClipboardOutput::FormatData {
                format_id: CF_UNICODETEXT,
                data: Some(text)
            }]
        );
    }

    #[test]
    fn a_failed_response_arrives_as_no_data() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[unicode_text()]);
        clipboard.request(CF_UNICODETEXT).unwrap();
        let outputs = clipboard
            .process(&pdu::encode_format_data_response(None))
            .unwrap();
        assert_eq!(
            outputs,
            vec![ClipboardOutput::FormatData {
                format_id: CF_UNICODETEXT,
                data: None
            }]
        );
    }

    /// 2.2.5.1: the requested format MUST be one the server listed.
    #[test]
    fn a_format_the_server_did_not_list_is_not_requested() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[unicode_text()]);
        assert_eq!(
            clipboard.request(1),
            Err(RequestError::NotAnnounced { format_id: 1 })
        );
        assert_eq!(
            Clipboard::new().request(CF_UNICODETEXT),
            Err(RequestError::NotAnnounced {
                format_id: CF_UNICODETEXT
            })
        );
    }

    /// A response names no format, so one request waits at a time.
    #[test]
    fn one_request_waits_at_a_time() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[unicode_text()]);
        clipboard.request(CF_UNICODETEXT).unwrap();
        assert_eq!(
            clipboard.request(CF_UNICODETEXT),
            Err(RequestError::Pending {
                format_id: CF_UNICODETEXT
            })
        );
        clipboard
            .process(&pdu::encode_format_data_response(None))
            .unwrap();
        assert!(clipboard.request(CF_UNICODETEXT).is_ok());
    }

    #[test]
    fn a_response_nothing_asked_for_is_skipped() {
        let mut clipboard = ready();
        let outputs = clipboard
            .process(&pdu::encode_format_data_response(Some(b"x")))
            .unwrap();
        assert!(outputs.is_empty());
    }

    /// Host to server: the server asks for an announced format and the host answers it.
    #[test]
    fn a_server_request_is_surfaced_and_answered() {
        let mut clipboard = ready();
        clipboard.announce(vec![unicode_text()]);
        let outputs = clipboard.process(&data_request(CF_UNICODETEXT)).unwrap();
        assert_eq!(
            outputs,
            vec![ClipboardOutput::DataRequested {
                format_id: CF_UNICODETEXT
            }]
        );
        let text = pdu::encode_unicode_text("hi");
        assert_eq!(
            clipboard.respond(Some(&text)),
            vec![pdu::encode_format_data_response(Some(&text))]
        );
        assert!(clipboard.respond(Some(&text)).is_empty());
    }

    #[test]
    fn the_host_can_answer_with_a_failure() {
        let mut clipboard = ready();
        clipboard.announce(vec![unicode_text()]);
        clipboard.process(&data_request(CF_UNICODETEXT)).unwrap();
        assert_eq!(
            clipboard.respond(None),
            vec![pdu::encode_format_data_response(None)]
        );
    }

    #[test]
    fn nothing_is_answered_when_nothing_was_asked() {
        assert!(ready().respond(Some(b"x")).is_empty());
    }

    /// A request for a format this side never announced is answered with a failure and does
    /// not reach the host (ADR-0009: observable, the server's inconsistency).
    #[test]
    fn a_request_for_an_unannounced_format_is_refused() {
        let mut clipboard = ready();
        clipboard.announce(vec![unicode_text()]);
        let outputs = clipboard.process(&data_request(1)).unwrap();
        assert_eq!(
            outputs,
            vec![ClipboardOutput::Send(pdu::encode_format_data_response(
                None
            ))]
        );
        assert!(clipboard.respond(Some(b"x")).is_empty());
    }

    /// Responses name no format, so they go out in the order the requests came.
    #[test]
    fn two_server_requests_are_answered_in_order() {
        let mut clipboard = ready();
        clipboard.announce(vec![unicode_text()]);
        for _ in 0..2 {
            assert_eq!(
                clipboard.process(&data_request(CF_UNICODETEXT)).unwrap(),
                vec![ClipboardOutput::DataRequested {
                    format_id: CF_UNICODETEXT
                }]
            );
        }
        assert_eq!(
            clipboard.respond(Some(b"1")),
            vec![pdu::encode_format_data_response(Some(b"1"))]
        );
        assert_eq!(
            clipboard.respond(Some(b"2")),
            vec![pdu::encode_format_data_response(Some(b"2"))]
        );
        assert!(clipboard.respond(Some(b"3")).is_empty());
    }

    /// A refusal owed behind an unanswered request waits for it, so the two stay in order.
    #[test]
    fn a_refusal_waits_behind_an_owed_answer() {
        let mut clipboard = ready();
        clipboard.announce(vec![unicode_text()]);
        clipboard.process(&data_request(CF_UNICODETEXT)).unwrap();
        assert!(clipboard.process(&data_request(1)).unwrap().is_empty());
        assert_eq!(
            clipboard.respond(Some(b"text")),
            vec![
                pdu::encode_format_data_response(Some(b"text")),
                pdu::encode_format_data_response(None)
            ]
        );
    }

    /// A request whose body does not decode is still answered, with a failure.
    #[test]
    fn an_undecodable_server_request_is_answered_with_a_failure() {
        let mut clipboard = ready();
        let short = [0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0d, 0x00];
        assert_eq!(
            clipboard.process(&short).unwrap(),
            vec![ClipboardOutput::Send(pdu::encode_format_data_response(
                None
            ))]
        );
    }

    /// A response that does not decode ends the wait, so the host can ask again.
    #[test]
    fn an_undecodable_response_ends_the_wait() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[unicode_text()]);
        clipboard.request(CF_UNICODETEXT).unwrap();
        let fail_with_data = [0x05, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78];
        assert!(clipboard.process(&fail_with_data).is_err());
        assert!(clipboard.request(CF_UNICODETEXT).is_ok());
    }

    #[test]
    fn a_request_can_be_cancelled() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[unicode_text()]);
        assert_eq!(clipboard.cancel_request(), None);
        clipboard.request(CF_UNICODETEXT).unwrap();
        assert_eq!(clipboard.cancel_request(), Some(CF_UNICODETEXT));
        assert!(
            clipboard
                .process(&pdu::encode_format_data_response(Some(b"late")))
                .unwrap()
                .is_empty()
        );
        assert!(clipboard.request(CF_UNICODETEXT).is_ok());
    }

    /// A server Format List that does not decode replaced what the server had.
    #[test]
    fn an_undecodable_server_list_clears_the_old_one() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[unicode_text()]);
        let unterminated = [
            0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x41, 0x00,
        ];
        clipboard.process(&unterminated).unwrap();
        assert_eq!(
            clipboard.request(CF_UNICODETEXT),
            Err(RequestError::NotAnnounced {
                format_id: CF_UNICODETEXT
            })
        );
    }

    /// 3.1.5.4.3: after the server refused this side's Format List, requests fail.
    #[test]
    fn after_a_refused_format_list_requests_fail() {
        let mut clipboard = ready();
        clipboard.announce(vec![unicode_text()]);
        let refused = [0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        clipboard.process(&refused).unwrap();
        let outputs = clipboard.process(&data_request(CF_UNICODETEXT)).unwrap();
        assert_eq!(
            outputs,
            vec![ClipboardOutput::Send(pdu::encode_format_data_response(
                None
            ))]
        );
        clipboard.announce(vec![unicode_text()]);
        let outputs = clipboard.process(&data_request(CF_UNICODETEXT)).unwrap();
        assert!(matches!(outputs[0], ClipboardOutput::DataRequested { .. }));
    }

    /// A new server Format List replaces the old one.
    #[test]
    fn the_latest_server_list_decides_what_can_be_requested() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[unicode_text()]);
        server_copied(&mut clipboard, &[]);
        assert_eq!(
            clipboard.request(CF_UNICODETEXT),
            Err(RequestError::NotAnnounced {
                format_id: CF_UNICODETEXT
            })
        );
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
