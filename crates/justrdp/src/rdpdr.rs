//! The device redirection channel (MS-RDPEFS) as a sans-IO helper the host drives: the
//! initialization sequence (1.3.1) and the announcement of the host's drives. The session never
//! interprets `rdpdr` bytes: the host requests the channel with [`channel_def`], feeds each
//! `SessionOutput::ChannelData` message on it to [`DeviceRedirection::process`], and passes
//! every [`DeviceRedirectionOutput::Send`] to `SessionStateMachine::send_channel`.
//!
//! This server starts the channel only when `rdpsnd` is requested too (`[MS-RDPEFS]` 2.1,
//! footnote 1), so a host that wants drives requests both. Nothing has to answer `rdpsnd`.

use justrdp_pdu::DecodeError;
use justrdp_pdu::gcc::{CHANNEL_OPTION_INITIALIZED, ChannelDef};
use justrdp_pdu::rdpdr::{
    self as pdu, CAP_DRIVE_TYPE, CapabilitySet, DOS_NAME_SIZE, DRIVE_CAPABILITY_VERSION_02,
    DeviceAnnounce, GENERAL_CAPABILITY_VERSION_02, GeneralCapability, IO_CODE1_ALWAYS_SET,
    IoRequest, RDPDR_CLIENT_DISPLAY_NAME_PDU, RDPDR_DTYP_FILESYSTEM, RDPDR_USER_LOGGEDON_PDU,
    RdpdrPdu, STATUS_NOT_SUPPORTED, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};

/// The `VersionMinor` values a client may send, highest first (2.2.2.3).
const CLIENT_VERSIONS: [u16; 5] = [0x000D, 0x000C, 0x000A, 0x0005, 0x0002];

/// The server version from which the client echoes the server's `ClientId` (3.2.5.1.3).
const ECHO_CLIENT_ID_FROM: u16 = 0x000C;

/// The Client Network Data entry for the device redirection channel.
pub fn channel_def() -> ChannelDef {
    ChannelDef::new(pdu::CHANNEL_NAME, CHANNEL_OPTION_INITIALIZED)
        .expect("\"rdpdr\" is a valid channel name")
}

/// A drive the host redirects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drive {
    /// The ID the server's requests for this drive name, unique among the host's drives.
    pub device_id: u32,
    /// The drive's name on the server, as in `\\tsclient\<name>`.
    pub name: String,
}

/// Why [`DeviceRedirection::new`] refused the host's drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveError {
    /// A name is empty, not ASCII, holds a NUL or one of `< > " / \ |`, or has a `:` before
    /// its end (2.2.1.3).
    InvalidName(String),
    /// Two drives share a `device_id`.
    DuplicateId(u32),
}

/// What processing one device redirection message produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRedirectionOutput {
    /// A message to send on the device redirection channel.
    Send(Vec<u8>),
    /// The server accepted a drive: its requests may now arrive.
    DriveAccepted {
        /// The drive's `device_id`.
        device_id: u32,
    },
    /// The server refused a drive.
    DriveRefused {
        /// The drive's `device_id`.
        device_id: u32,
        /// The server's `ResultCode`, an NTSTATUS.
        status: u32,
    },
    /// The server sent a message this side cannot read, so the channel is ended (3.1.5.2): every
    /// later message on it is ignored. The rest of the session goes on.
    Terminated(DecodeError),
}

/// The client side of one device redirection channel.
#[derive(Debug, Clone)]
pub struct DeviceRedirection {
    computer_name: String,
    drives: Vec<DeviceAnnounce>,
    /// The `ClientId` used when the server's version is below 12, from the host's randomness.
    random_client_id: u32,
    /// The `VersionMinor` and `ClientId` sent in the Client Announce Reply.
    announced_as: Option<(u16, u32)>,
    devices_announced: bool,
    terminated: bool,
}

impl DeviceRedirection {
    /// A helper redirecting `drives` under `computer_name`, waiting for the server's Server
    /// Announce. `random_client_id` is a fresh random value the host draws: it is the
    /// `ClientId` sent to a server older than version 12, which 3.2.5.1.3 requires to be random.
    pub fn new(
        computer_name: impl Into<String>,
        drives: Vec<Drive>,
        random_client_id: u32,
    ) -> Result<Self, DriveError> {
        let mut announced: Vec<DeviceAnnounce> = Vec::with_capacity(drives.len());
        for drive in drives {
            if announced.iter().any(|d| d.device_id == drive.device_id) {
                return Err(DriveError::DuplicateId(drive.device_id));
            }
            announced.push(drive_announce(drive)?);
        }
        Ok(Self {
            computer_name: computer_name.into(),
            drives: announced,
            random_client_id,
            announced_as: None,
            devices_announced: false,
            terminated: false,
        })
    }

    /// Process one whole message received on the device redirection channel.
    pub fn process(&mut self, message: &[u8]) -> Vec<DeviceRedirectionOutput> {
        if self.terminated {
            return Vec::new();
        }
        match RdpdrPdu::decode(message) {
            Ok(pdu) => self.handle(pdu),
            Err(error) => self.terminate(error),
        }
    }

    fn handle(&mut self, pdu: RdpdrPdu) -> Vec<DeviceRedirectionOutput> {
        use DeviceRedirectionOutput::Send;
        match pdu {
            // A later Server Announce starts the sequence over (3.2.5.1.2).
            RdpdrPdu::ServerAnnounce {
                version_minor,
                client_id,
            } => {
                let version = client_version(version_minor);
                let client_id = if version_minor >= ECHO_CLIENT_ID_FROM {
                    client_id
                } else {
                    self.random_client_id
                };
                self.announced_as = Some((version, client_id));
                self.devices_announced = false;
                vec![
                    Send(pdu::encode_client_announce_reply(version, client_id)),
                    Send(pdu::encode_client_name(&self.computer_name)),
                ]
            }
            RdpdrPdu::ServerCapabilities(_) => {
                let Some((version, _)) = self.announced_as else {
                    return out_of_sequence("Server Core Capability Request");
                };
                vec![Send(pdu::encode_client_capabilities(&client_capabilities(
                    version,
                )))]
            }
            RdpdrPdu::ClientIdConfirm { client_id, .. } => match self.announced_as {
                None => out_of_sequence("Server Client ID Confirm"),
                Some((_, sent)) if sent == client_id => Vec::new(),
                Some(_) => self.terminate(DecodeError::InvalidField {
                    field: "DR_CORE_CLIENT_ANNOUNCE_RSP.ClientId",
                    reason: "is not the ClientId of the Client Announce Reply",
                }),
            },
            RdpdrPdu::UserLoggedOn => {
                if self.announced_as.is_none() {
                    return out_of_sequence("Server User Logged On");
                }
                if self.devices_announced || self.drives.is_empty() {
                    return Vec::new();
                }
                self.devices_announced = true;
                vec![Send(pdu::encode_device_list_announce(&self.drives))]
            }
            RdpdrPdu::DeviceAnnounceResponse {
                device_id,
                result_code,
            } => {
                if !self.is_announced(device_id) {
                    tracing::warn!(target: "rdp_rdpdr", device_id, "Device Announce Response for no device");
                    return Vec::new();
                }
                vec![if result_code == STATUS_SUCCESS {
                    DeviceRedirectionOutput::DriveAccepted { device_id }
                } else {
                    DeviceRedirectionOutput::DriveRefused {
                        device_id,
                        status: result_code,
                    }
                }]
            }
            RdpdrPdu::IoRequest(request) => self.refuse_io(request),
            RdpdrPdu::Unknown {
                component,
                packet_id,
            } => {
                tracing::warn!(target: "rdp_rdpdr", component, packet_id, "unknown rdpdr message");
                self.terminate(DecodeError::InvalidField {
                    field: "RDPDR_HEADER",
                    reason: "names a Component and PacketId this client does not handle",
                })
            }
        }
    }

    fn is_announced(&self, device_id: u32) -> bool {
        self.devices_announced && self.drives.iter().any(|d| d.device_id == device_id)
    }

    /// Answer a Device I/O Request with a failure: `STATUS_NOT_SUPPORTED` for a major function
    /// 2.2.1.4 defines, `STATUS_UNSUCCESSFUL` for any other (3.1.5.2). One for a device never
    /// announced is ignored (3.1.5.2).
    fn refuse_io(&mut self, request: IoRequest) -> Vec<DeviceRedirectionOutput> {
        if !self.is_announced(request.device_id) {
            tracing::warn!(
                target: "rdp_rdpdr",
                device_id = request.device_id,
                "Device I/O Request for no device ignored"
            );
            return Vec::new();
        }
        let status = if pdu::is_known_major(request.major) {
            STATUS_NOT_SUPPORTED
        } else {
            STATUS_UNSUCCESSFUL
        };
        tracing::debug!(
            target: "rdp_rdpdr",
            major = request.major,
            minor = request.minor,
            status,
            "Device I/O Request refused"
        );
        vec![DeviceRedirectionOutput::Send(pdu::encode_io_completion(
            request.device_id,
            request.completion_id,
            status,
            pdu::failure_body(request.major),
        ))]
    }

    fn terminate(&mut self, error: DecodeError) -> Vec<DeviceRedirectionOutput> {
        tracing::warn!(target: "rdp_rdpdr", %error, "device redirection channel ended");
        self.terminated = true;
        vec![DeviceRedirectionOutput::Terminated(error)]
    }
}

/// A message that arrived before the Server Announce it depends on, skipped (3.1.5.2 allows
/// ending the channel instead).
fn out_of_sequence(what: &'static str) -> Vec<DeviceRedirectionOutput> {
    tracing::warn!(target: "rdp_rdpdr", what, "rdpdr message before Server Announce skipped");
    Vec::new()
}

/// The highest client version not above the server's.
fn client_version(server: u16) -> u16 {
    CLIENT_VERSIONS
        .into_iter()
        .find(|&v| v <= server)
        .unwrap_or(CLIENT_VERSIONS[CLIENT_VERSIONS.len() - 1])
}

/// The General and Drive capability sets this client supports (2.2.2.8).
fn client_capabilities(version: u16) -> [CapabilitySet; 2] {
    [
        CapabilitySet::General(GeneralCapability {
            version: GENERAL_CAPABILITY_VERSION_02,
            os_type: 0,
            os_version: 0,
            protocol_minor: version,
            io_code1: IO_CODE1_ALWAYS_SET,
            extended_pdu: RDPDR_CLIENT_DISPLAY_NAME_PDU | RDPDR_USER_LOGGEDON_PDU,
            extra_flags1: 0,
            special_type_device_cap: 0,
        }),
        CapabilitySet::Other {
            kind: CAP_DRIVE_TYPE,
            version: DRIVE_CAPABILITY_VERSION_02,
        },
    ]
}

/// A drive's announcement: its name cut to fit `PreferredDosName`, and in full as
/// NUL-terminated UTF-16 in `DeviceData` (2.2.3.1).
fn drive_announce(drive: Drive) -> Result<DeviceAnnounce, DriveError> {
    let name = &drive.name;
    let last = name.len().saturating_sub(1);
    let valid = !name.is_empty()
        && name.bytes().enumerate().all(|(at, b)| {
            b.is_ascii() && b != 0 && !b"<>\"/\\|".contains(&b) && (b != b':' || at == last)
        });
    if !valid {
        return Err(DriveError::InvalidName(drive.name));
    }
    let mut preferred_dos_name = [0; DOS_NAME_SIZE];
    let fits = name.len().min(DOS_NAME_SIZE - 1);
    preferred_dos_name[..fits].copy_from_slice(&name.as_bytes()[..fits]);
    let device_data = name
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    Ok(DeviceAnnounce {
        device_type: RDPDR_DTYP_FILESYSTEM,
        device_id: drive.device_id,
        preferred_dos_name,
        device_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use justrdp_pdu::rdpdr::{IRP_MJ_CREATE, IRP_MJ_READ};

    fn server_announce(version_minor: u16, client_id: u32) -> Vec<u8> {
        let mut m = vec![0x72, 0x44, 0x6e, 0x49, 0x01, 0x00];
        m.extend_from_slice(&version_minor.to_le_bytes());
        m.extend_from_slice(&client_id.to_le_bytes());
        m
    }

    fn client_id_confirm(client_id: u32) -> Vec<u8> {
        let mut m = vec![0x72, 0x44, 0x43, 0x43, 0x01, 0x00, 0x0d, 0x00];
        m.extend_from_slice(&client_id.to_le_bytes());
        m
    }

    const SERVER_CAPABILITIES: [u8; 16] = [
        0x72, 0x44, 0x50, 0x53, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
        0x00,
    ];
    const USER_LOGGED_ON: [u8; 4] = [0x72, 0x44, 0x4c, 0x55];

    fn device_reply(device_id: u32, status: u32) -> Vec<u8> {
        let mut m = vec![0x72, 0x44, 0x72, 0x64];
        m.extend_from_slice(&device_id.to_le_bytes());
        m.extend_from_slice(&status.to_le_bytes());
        m
    }

    fn io_request(device_id: u32, completion_id: u32, major: u32) -> Vec<u8> {
        let mut m = vec![0x72, 0x44, 0x52, 0x49];
        for field in [device_id, 0, completion_id, major, 0] {
            m.extend_from_slice(&field.to_le_bytes());
        }
        m
    }

    fn sent(outputs: &[DeviceRedirectionOutput]) -> Vec<&[u8]> {
        outputs
            .iter()
            .filter_map(|o| match o {
                DeviceRedirectionOutput::Send(m) => Some(m.as_slice()),
                _ => None,
            })
            .collect()
    }

    fn drive(device_id: u32, name: &str) -> Drive {
        Drive {
            device_id,
            name: name.to_string(),
        }
    }

    fn helper() -> DeviceRedirection {
        DeviceRedirection::new("host", vec![drive(1, "justrdp")], 0xABCD).unwrap()
    }

    /// Through User Logged On, the sequence the VM runs.
    fn ready() -> DeviceRedirection {
        let mut h = helper();
        h.process(&server_announce(0x0d, 7));
        h.process(&SERVER_CAPABILITIES);
        h.process(&client_id_confirm(7));
        h.process(&USER_LOGGED_ON);
        h
    }

    #[test]
    fn the_channel_is_requested_initialized() {
        let def = channel_def();
        assert_eq!(def.name_str(), "rdpdr");
        assert_eq!(def.options, CHANNEL_OPTION_INITIALIZED);
    }

    /// Server Announce is answered with the Client Announce Reply and the Client Name, the reply
    /// echoing a version-12-or-later server's ClientId.
    #[test]
    fn server_announce_is_answered_with_reply_and_name() {
        let outputs = helper().process(&server_announce(0x0d, 7));
        assert_eq!(
            sent(&outputs),
            vec![
                pdu::encode_client_announce_reply(0x0d, 7).as_slice(),
                pdu::encode_client_name("host").as_slice(),
            ]
        );
    }

    /// Below version 12 the ClientId is the host's random value, and the version never exceeds
    /// the server's.
    #[test]
    fn an_older_server_gets_the_random_client_id_and_its_own_version() {
        let outputs = helper().process(&server_announce(0x0a, 7));
        assert_eq!(
            sent(&outputs)[0],
            pdu::encode_client_announce_reply(0x0a, 0xABCD)
        );
        assert_eq!(client_version(0x0e), 0x0d);
        assert_eq!(client_version(0x0b), 0x0a);
        assert_eq!(client_version(0x01), 0x02);
    }

    /// The capability response carries General (always-set ioCode1, no security bits, no async
    /// I/O, User Logged On) and Drive version 2, and nothing else.
    #[test]
    fn capabilities_are_answered_with_general_and_drive() {
        let mut h = helper();
        h.process(&server_announce(0x0c, 7));
        let outputs = h.process(&SERVER_CAPABILITIES);
        assert_eq!(
            sent(&outputs),
            vec![pdu::encode_client_capabilities(&client_capabilities(0x0c)).as_slice()]
        );
        let [CapabilitySet::General(general), drive] = client_capabilities(0x0c) else {
            unreachable!()
        };
        assert_eq!(general.io_code1, 0x3FFF);
        assert_eq!(general.extra_flags1, 0);
        assert_eq!(
            general.extended_pdu & RDPDR_USER_LOGGEDON_PDU,
            RDPDR_USER_LOGGEDON_PDU
        );
        assert_eq!(general.protocol_minor, 0x0c);
        assert_eq!(
            drive,
            CapabilitySet::Other {
                kind: CAP_DRIVE_TYPE,
                version: 2
            }
        );
    }

    /// Drives are announced once, on User Logged On, and the server's answer to each is
    /// surfaced.
    #[test]
    fn drives_are_announced_after_logon_and_their_answers_surfaced() {
        let mut h = helper();
        h.process(&server_announce(0x0d, 7));
        h.process(&SERVER_CAPABILITIES);
        assert!(h.process(&client_id_confirm(7)).is_empty());
        let announce = h.process(&USER_LOGGED_ON);
        assert_eq!(
            sent(&announce),
            vec![pdu::encode_device_list_announce(&h.drives).as_slice()]
        );
        assert!(h.process(&USER_LOGGED_ON).is_empty());
        assert_eq!(
            h.process(&device_reply(1, STATUS_SUCCESS)),
            vec![DeviceRedirectionOutput::DriveAccepted { device_id: 1 }]
        );
        assert_eq!(
            h.process(&device_reply(1, STATUS_UNSUCCESSFUL)),
            vec![DeviceRedirectionOutput::DriveRefused {
                device_id: 1,
                status: STATUS_UNSUCCESSFUL
            }]
        );
        assert!(h.process(&device_reply(9, STATUS_SUCCESS)).is_empty());
    }

    /// A drive's name is cut to seven ASCII characters for `PreferredDosName` and sent in full
    /// in `DeviceData`.
    #[test]
    fn a_drive_name_fills_both_fields() {
        let announce = drive_announce(drive(3, "projects")).unwrap();
        assert_eq!(&announce.preferred_dos_name, b"project\0");
        let full: Vec<u8> = "projects\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(announce.device_data, full);
        assert_eq!(announce.device_type, RDPDR_DTYP_FILESYSTEM);
    }

    #[test]
    fn invalid_drives_are_refused() {
        for name in ["", "a/b", "a|b", "a:b", "caf\u{e9}", "a\0"] {
            assert_eq!(
                DeviceRedirection::new("host", vec![drive(1, name)], 0).err(),
                Some(DriveError::InvalidName(name.to_string())),
                "{name:?}"
            );
        }
        assert!(DeviceRedirection::new("host", vec![drive(1, "c:")], 0).is_ok());
        assert_eq!(
            DeviceRedirection::new("host", vec![drive(1, "a"), drive(1, "b")], 0).err(),
            Some(DriveError::DuplicateId(1))
        );
    }

    /// Every I/O request is refused with its body's fields zeroed: not supported for a known
    /// major function, unsuccessful for an unknown one; one for no announced device is ignored.
    #[test]
    fn io_requests_are_refused_until_implemented() {
        let mut h = ready();
        assert_eq!(
            sent(&h.process(&io_request(1, 5, IRP_MJ_CREATE))),
            vec![pdu::encode_io_completion(1, 5, STATUS_NOT_SUPPORTED, &[0; 5]).as_slice()]
        );
        assert_eq!(
            sent(&h.process(&io_request(1, 6, IRP_MJ_READ))),
            vec![pdu::encode_io_completion(1, 6, STATUS_NOT_SUPPORTED, &[0; 4]).as_slice()]
        );
        assert_eq!(
            sent(&h.process(&io_request(1, 7, 0x0000_0001))),
            vec![pdu::encode_io_completion(1, 7, STATUS_UNSUCCESSFUL, &[]).as_slice()]
        );
        assert!(h.process(&io_request(2, 8, IRP_MJ_CREATE)).is_empty());
    }

    /// Before the drives are announced no device exists, so a request is ignored.
    #[test]
    fn io_requests_before_the_announce_are_ignored() {
        let mut h = helper();
        h.process(&server_announce(0x0d, 7));
        assert!(h.process(&io_request(1, 5, IRP_MJ_CREATE)).is_empty());
    }

    /// A message that does not decode, or an unknown one, ends the channel; later messages,
    /// even a new Server Announce, are ignored.
    #[test]
    fn an_unreadable_message_ends_the_channel() {
        let mut h = ready();
        let outputs = h.process(&[0x72, 0x44, 0x52]);
        assert!(matches!(
            outputs.as_slice(),
            [DeviceRedirectionOutput::Terminated(_)]
        ));
        assert!(h.process(&io_request(1, 5, IRP_MJ_CREATE)).is_empty());
        assert!(h.process(&server_announce(0x0d, 7)).is_empty());

        let mut h = ready();
        assert!(matches!(
            h.process(&[0x72, 0x44, 0x99, 0x99]).as_slice(),
            [DeviceRedirectionOutput::Terminated(_)]
        ));
    }

    /// A confirm for another ClientId ends the channel (3.2.5.1.6).
    #[test]
    fn a_confirm_for_another_client_id_ends_the_channel() {
        let mut h = helper();
        h.process(&server_announce(0x0d, 7));
        assert!(matches!(
            h.process(&client_id_confirm(8)).as_slice(),
            [DeviceRedirectionOutput::Terminated(_)]
        ));
    }

    /// Messages that depend on Server Announce are skipped before it.
    #[test]
    fn messages_before_server_announce_are_skipped() {
        let mut h = helper();
        assert!(h.process(&SERVER_CAPABILITIES).is_empty());
        assert!(h.process(&client_id_confirm(7)).is_empty());
        assert!(h.process(&USER_LOGGED_ON).is_empty());
        assert_eq!(sent(&h.process(&server_announce(0x0d, 7))).len(), 2);
    }

    /// A second Server Announce starts over: the drives are announced again after the next
    /// logon (3.2.5.1.2).
    #[test]
    fn a_second_server_announce_starts_over() {
        let mut h = ready();
        h.process(&server_announce(0x0d, 9));
        assert!(h.process(&io_request(1, 5, IRP_MJ_CREATE)).is_empty());
        h.process(&SERVER_CAPABILITIES);
        h.process(&client_id_confirm(9));
        assert_eq!(sent(&h.process(&USER_LOGGED_ON)).len(), 1);
    }

    #[test]
    fn no_drives_announce_nothing() {
        let mut h = DeviceRedirection::new("host", Vec::new(), 0).unwrap();
        h.process(&server_announce(0x0d, 7));
        assert!(h.process(&USER_LOGGED_ON).is_empty());
    }
}
