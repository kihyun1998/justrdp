//! The device redirection channel (MS-RDPEFS) as a sans-IO helper the host drives: the
//! initialization sequence (1.3.1), the announcement of the host's drives, and the drive
//! requests the server sends, which reach the host as [`DeviceRedirectionOutput::DriveRequest`]
//! and are answered by `CompletionId`. The session never
//! interprets `rdpdr` bytes: the host requests the channel with [`channel_def`], feeds each
//! `SessionOutput::ChannelData` message on it to [`DeviceRedirection::process`], and passes
//! every [`DeviceRedirectionOutput::Send`] to `SessionStateMachine::send_channel`.
//!
//! This server starts the channel only when `rdpsnd` is requested too (`[MS-RDPEFS]` 2.1,
//! footnote 1), so a host that wants drives requests both. Nothing has to answer `rdpsnd`.

use justrdp_pdu::DecodeError;
use justrdp_pdu::gcc::{CHANNEL_OPTION_INITIALIZED, ChannelDef};
use std::collections::VecDeque;

use justrdp_pdu::rdpdr::{
    self as pdu, CAP_DRIVE_TYPE, CapabilitySet, CreateRequest, DOS_NAME_SIZE,
    DRIVE_CAPABILITY_VERSION_02, DeviceAnnounce, GENERAL_CAPABILITY_VERSION_02, GeneralCapability,
    IO_CODE1_ALWAYS_SET, IoBody, IoRequest, RDPDR_CLIENT_DISPLAY_NAME_PDU, RDPDR_DTYP_FILESYSTEM,
    RDPDR_USER_LOGGEDON_PDU, RdpdrPdu, STATUS_ACCESS_DENIED, STATUS_CANCELLED,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER,
    STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_NOT_A_DIRECTORY, STATUS_NOT_SUPPORTED,
    STATUS_OBJECT_NAME_INVALID, STATUS_SUCCESS, STATUS_TOO_MANY_OPENED_FILES, STATUS_UNSUCCESSFUL,
    SetInformation,
};
pub use justrdp_pdu::rdpdr::{BasicInformation, FileInformation, VolumeInformation};

/// The `VersionMinor` values a client may send, highest first (2.2.2.3).
const CLIENT_VERSIONS: [u16; 5] = [0x000D, 0x000C, 0x000A, 0x0005, 0x0002];

/// The server version from which the client echoes the server's `ClientId` (3.2.5.1.3).
const ECHO_CLIENT_ID_FROM: u16 = 0x000C;

/// The client version from which a Write `Offset` of all ones appends (2.2.1.4.4).
const APPEND_FROM: u16 = 0x000D;

/// `MAXLONGLONG`, the furthest a file's data reaches (`[MS-FSA]` 2.1.5.3, 2.1.5.4).
const MAX_FILE_END: u64 = i64::MAX as u64;

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

/// The most Device I/O Requests kept waiting for the host; one past it is answered with
/// `STATUS_INSUFFICIENT_RESOURCES`.
pub const MAX_PENDING_REQUESTS: usize = 100;

/// The most files kept open at once; a Create past it is answered with
/// `STATUS_TOO_MANY_OPENED_FILES`.
pub const MAX_OPEN_FILES: usize = 1024;

/// The names 3.2.5.2.3 requires a Create to refuse with `STATUS_ACCESS_DENIED`.
const RESERVED_NAMES: [&str; 23] = [
    "CON", "PRN", "AUX", "NUL", "CLOCK$", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
    "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

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
    /// The server asks the host about a drive. The host answers with the `respond_*` method
    /// the request names, by `completion_id`, in any order.
    DriveRequest {
        /// The ID the answer is paired by.
        completion_id: u32,
        /// The drive's `device_id`.
        device_id: u32,
        /// What the server asks.
        request: DriveRequest,
    },
    /// A file the host opened is closed: the server closed it, or the channel started over or
    /// ended. Requests about it that the host still owes are no longer awaited.
    FileClosed {
        /// The drive's `device_id`.
        device_id: u32,
        /// The file's ID, from its [`DriveRequest::Open`].
        file_id: u32,
        /// Whether the host deletes the file now: its Open asked for `delete_on_close`, or the
        /// host last accepted a [`DriveRequest::Delete`] with `delete` set.
        delete: bool,
    },
    /// The server sent a message this side cannot read, so the channel is ended (3.1.5.2): every
    /// later message on it is ignored. The rest of the session goes on.
    Terminated(DecodeError),
}

/// What a Create asks the opened file to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenKind {
    /// A file or a directory.
    Any,
    /// A directory (`FILE_DIRECTORY_FILE`); a file is answered `STATUS_NOT_A_DIRECTORY`.
    Directory,
    /// Not a directory (`FILE_NON_DIRECTORY_FILE`).
    File,
}

/// A Create's `CreateDisposition` (2.2.1.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Replace the file if it exists, create it if not.
    Supersede,
    /// Open the file; fail if it does not exist.
    Open,
    /// Create the file; fail if it exists.
    Create,
    /// Open the file, creating it if it does not exist.
    OpenIf,
    /// Overwrite the file; fail if it does not exist.
    Overwrite,
    /// Overwrite the file, creating it if it does not exist.
    OverwriteIf,
}

impl Disposition {
    fn from_wire(value: u32) -> Option<Self> {
        Some(match value {
            pdu::FILE_SUPERSEDE => Self::Supersede,
            pdu::FILE_OPEN => Self::Open,
            pdu::FILE_CREATE => Self::Create,
            pdu::FILE_OPEN_IF => Self::OpenIf,
            pdu::FILE_OVERWRITE => Self::Overwrite,
            pdu::FILE_OVERWRITE_IF => Self::OverwriteIf,
            _ => return None,
        })
    }

    /// A successful Create's `Information`, which 2.2.1.5.1 derives from the disposition.
    fn information(self) -> u8 {
        match self {
            Self::OpenIf => pdu::FILE_OPENED,
            Self::OverwriteIf => pdu::FILE_OVERWRITTEN,
            _ => pdu::FILE_SUPERSEDED,
        }
    }
}

/// What the server asks the host about a drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveRequest {
    /// Open `path` as `file_id`. Answer with [`DeviceRedirection::respond_open`].
    Open {
        /// The ID later requests name the file by, chosen by the helper.
        file_id: u32,
        /// The path's components below the drive's root; empty for the root. None is empty,
        /// `.` or `..`, or holds a NUL, `/`, `\` or `:`.
        path: Vec<String>,
        /// Whether the file must be a directory, or must not.
        kind: OpenKind,
        /// What to do when the file exists or does not.
        disposition: Disposition,
        /// `DesiredAccess`, the access the server asks for.
        desired_access: u32,
        /// Whether the file is deleted when it closes (`FILE_DELETE_ON_CLOSE`).
        delete_on_close: bool,
    },
    /// Read at most `length` bytes of the open file `file_id` from `offset`. Answer with
    /// [`DeviceRedirection::respond_read`].
    Read {
        /// The file.
        file_id: u32,
        /// Where in the file to read from.
        offset: u64,
        /// The most bytes to read, as the server sized it: never zero, and `offset + length`
        /// never exceeds `i64::MAX`.
        length: u32,
    },
    /// Write `data` to the open file `file_id`. Answer with [`DeviceRedirection::respond_write`].
    Write {
        /// The file.
        file_id: u32,
        /// Where to write.
        offset: WriteOffset,
        /// The bytes to write, possibly none.
        data: Vec<u8>,
    },
    /// Set the size of the open file `file_id`. Answer with [`DeviceRedirection::respond_set`].
    SetEndOfFile {
        /// The file, never a directory.
        file_id: u32,
        /// The new size in bytes, at most `i64::MAX`.
        size: u64,
    },
    /// Set the allocation size of the open file `file_id`. Answer with
    /// [`DeviceRedirection::respond_set`].
    SetAllocationSize {
        /// The file, never a directory.
        file_id: u32,
        /// The new allocation size in bytes, at most `i64::MAX`.
        size: u64,
    },
    /// Set the times and attributes of the open file `file_id`, by `[MS-FSCC]` 2.4.7's
    /// meanings. Answer with [`DeviceRedirection::respond_set`].
    SetBasic {
        /// The file.
        file_id: u32,
        /// What to set.
        info: BasicInformation,
    },
    /// Move the open file `file_id` to `path`. Answer with [`DeviceRedirection::respond_set`].
    Rename {
        /// The file.
        file_id: u32,
        /// The new path's components below the drive's root, never empty, by the rules of
        /// [`DriveRequest::Open`]'s `path`.
        path: Vec<String>,
        /// Whether a file already at `path` is replaced.
        replace_if_exists: bool,
    },
    /// Mark the open file `file_id` to be deleted when it closes, or unmark it. Answer with
    /// [`DeviceRedirection::respond_set`]; the helper reports the outcome in
    /// [`DeviceRedirectionOutput::FileClosed`], and the host deletes then.
    Delete {
        /// The file.
        file_id: u32,
        /// Whether to delete it.
        delete: bool,
    },
    /// Describe the drive's volume. Answer with [`DeviceRedirection::respond_volume`].
    QueryVolume,
    /// Describe the open file `file_id`. Answer with [`DeviceRedirection::respond_information`].
    QueryInformation {
        /// The file.
        file_id: u32,
    },
    /// List the directory `path`, opened as `file_id`: every entry, which the helper matches
    /// against the server's pattern and hands out one at a time. Answer with
    /// [`DeviceRedirection::respond_listing`].
    ListDirectory {
        /// The directory, as opened.
        file_id: u32,
        /// The directory's components below the drive's root, by the rules of
        /// [`DriveRequest::Open`]'s `path`.
        path: Vec<String>,
    },
}

/// Where a [`DriveRequest::Write`] writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOffset {
    /// At this offset; `offset + data.len()` never exceeds `i64::MAX`.
    At(u64),
    /// At the file's end.
    Append,
}

/// What an opened file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    /// A file.
    File,
    /// A directory.
    Directory,
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// The entry's name.
    pub name: String,
    /// The entry's times, size and attributes.
    pub info: FileInformation,
}

/// Why a `respond_*` method refused the host's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespondError {
    /// No request waits under that `completion_id`.
    NotRequested,
    /// The request under that `completion_id` asks for a different answer.
    WrongKind,
    /// The answer holds more bytes than the read asked for, or counts more than the write
    /// carried.
    TooLong,
}

/// A request waiting for the host, and what its answer needs.
#[derive(Debug, Clone)]
struct Pending {
    completion_id: u32,
    device_id: u32,
    file_id: u32,
    kind: PendingKind,
}

#[derive(Debug, Clone)]
enum PendingKind {
    Open {
        disposition: Disposition,
        delete_on_close: bool,
    },
    Read {
        length: u32,
    },
    Write {
        length: u32,
    },
    /// A Set Information request: its `Length`, and the delete mark an accepted answer sets.
    Set {
        length: u32,
        delete: Option<bool>,
    },
    Volume {
        class: u32,
    },
    Information {
        class: u32,
    },
    Listing {
        class: u32,
        pattern: Vec<char>,
    },
}

impl PendingKind {
    /// The body of a failed response to the request this stands for: its response layout's
    /// fields zeroed, a Set Information's `Length` repeated (2.2.3.4.9).
    fn failed_body(&self) -> Vec<u8> {
        let major = match self {
            Self::Open { .. } => pdu::IRP_MJ_CREATE,
            Self::Read { .. } => pdu::IRP_MJ_READ,
            Self::Write { .. } => pdu::IRP_MJ_WRITE,
            Self::Set { length, .. } => return length.to_le_bytes().to_vec(),
            Self::Volume { .. } => pdu::IRP_MJ_QUERY_VOLUME_INFORMATION,
            Self::Information { .. } => pdu::IRP_MJ_QUERY_INFORMATION,
            Self::Listing { .. } => pdu::IRP_MJ_DIRECTORY_CONTROL,
        };
        pdu::failure_body(major).to_vec()
    }
}

/// A file the host opened.
#[derive(Debug, Clone)]
struct OpenFile {
    device_id: u32,
    file_id: u32,
    directory: bool,
    /// Whether the host deletes the file when it closes.
    delete: bool,
    /// The entries of the directory's current search not yet handed out.
    listing: VecDeque<DirectoryEntry>,
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
    /// Requests waiting for the host.
    pending: Vec<Pending>,
    /// Files the host opened and the server has not closed.
    files: Vec<OpenFile>,
    last_file_id: u32,
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
            pending: Vec::new(),
            files: Vec::new(),
            last_file_id: 0,
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

    /// The answer to [`DriveRequest::Open`]: what the host opened, or the NTSTATUS it failed
    /// with.
    pub fn respond_open(
        &mut self,
        completion_id: u32,
        answer: Result<Opened, u32>,
    ) -> Result<Vec<u8>, RespondError> {
        let pending =
            self.take_pending(completion_id, |k| matches!(k, PendingKind::Open { .. }))?;
        let PendingKind::Open {
            disposition,
            delete_on_close,
        } = pending.kind
        else {
            unreachable!("take_pending matched an Open")
        };
        Ok(match answer {
            Ok(opened) => {
                self.files.push(OpenFile {
                    device_id: pending.device_id,
                    file_id: pending.file_id,
                    directory: opened == Opened::Directory,
                    delete: delete_on_close,
                    listing: VecDeque::new(),
                });
                let mut body = pending.file_id.to_le_bytes().to_vec();
                body.push(disposition.information());
                complete(&pending, STATUS_SUCCESS, &body)
            }
            Err(status) => complete(&pending, status, pdu::failure_body(pdu::IRP_MJ_CREATE)),
        })
    }

    /// The answer to [`DriveRequest::Read`]: the bytes read, at most the `length` asked for
    /// and fewer at the file's end, or the NTSTATUS the host failed with.
    pub fn respond_read(
        &mut self,
        completion_id: u32,
        answer: Result<&[u8], u32>,
    ) -> Result<Vec<u8>, RespondError> {
        let at = self
            .pending
            .iter()
            .position(|p| p.completion_id == completion_id)
            .ok_or(RespondError::NotRequested)?;
        let PendingKind::Read { length } = self.pending[at].kind else {
            return Err(RespondError::WrongKind);
        };
        if let Ok(data) = answer
            && data.len() > length as usize
        {
            return Err(RespondError::TooLong);
        }
        let pending = self.pending.remove(at);
        Ok(match answer {
            Ok(data) => {
                let mut body = (data.len() as u32).to_le_bytes().to_vec();
                body.extend_from_slice(data);
                complete(&pending, STATUS_SUCCESS, &body)
            }
            Err(status) => complete(&pending, status, pdu::failure_body(pdu::IRP_MJ_READ)),
        })
    }

    /// The answer to [`DriveRequest::Write`]: how many bytes were written, at most the data's
    /// length, or the NTSTATUS the host failed with.
    pub fn respond_write(
        &mut self,
        completion_id: u32,
        answer: Result<u32, u32>,
    ) -> Result<Vec<u8>, RespondError> {
        let at = self
            .pending
            .iter()
            .position(|p| p.completion_id == completion_id)
            .ok_or(RespondError::NotRequested)?;
        let PendingKind::Write { length } = self.pending[at].kind else {
            return Err(RespondError::WrongKind);
        };
        if answer.is_ok_and(|written| written > length) {
            return Err(RespondError::TooLong);
        }
        let pending = self.pending.remove(at);
        Ok(match answer {
            Ok(written) => {
                let mut body = written.to_le_bytes().to_vec();
                body.push(0);
                complete(&pending, STATUS_SUCCESS, &body)
            }
            Err(status) => complete(&pending, status, pdu::failure_body(pdu::IRP_MJ_WRITE)),
        })
    }

    /// The answer to [`DriveRequest::SetEndOfFile`], [`DriveRequest::SetAllocationSize`],
    /// [`DriveRequest::SetBasic`], [`DriveRequest::Rename`] and [`DriveRequest::Delete`]:
    /// done, or the NTSTATUS the host failed with.
    pub fn respond_set(
        &mut self,
        completion_id: u32,
        answer: Result<(), u32>,
    ) -> Result<Vec<u8>, RespondError> {
        let pending = self.take_pending(completion_id, |k| matches!(k, PendingKind::Set { .. }))?;
        let PendingKind::Set { length, delete } = pending.kind else {
            unreachable!("take_pending matched a Set")
        };
        let status = match answer {
            Ok(()) => {
                if let Some(delete) = delete
                    && let Some(file) = self.file_mut(pending.device_id, pending.file_id)
                {
                    file.delete = delete;
                }
                STATUS_SUCCESS
            }
            Err(status) => status,
        };
        Ok(complete(&pending, status, &length.to_le_bytes()))
    }

    /// The answer to [`DriveRequest::QueryVolume`]: the volume, or the NTSTATUS the host
    /// failed with.
    pub fn respond_volume(
        &mut self,
        completion_id: u32,
        answer: Result<&VolumeInformation, u32>,
    ) -> Result<Vec<u8>, RespondError> {
        let pending =
            self.take_pending(completion_id, |k| matches!(k, PendingKind::Volume { .. }))?;
        let PendingKind::Volume { class } = pending.kind else {
            unreachable!("take_pending matched a Volume")
        };
        Ok(match answer {
            Ok(volume) => {
                let buffer = pdu::encode_volume_information(class, volume)
                    .expect("only an implemented class is asked for");
                complete(
                    &pending,
                    STATUS_SUCCESS,
                    &pdu::length_prefixed(&buffer, true),
                )
            }
            Err(status) => complete(
                &pending,
                status,
                pdu::failure_body(pdu::IRP_MJ_QUERY_VOLUME_INFORMATION),
            ),
        })
    }

    /// The answer to [`DriveRequest::QueryInformation`]: the file's information, or the
    /// NTSTATUS the host failed with.
    pub fn respond_information(
        &mut self,
        completion_id: u32,
        answer: Result<&FileInformation, u32>,
    ) -> Result<Vec<u8>, RespondError> {
        let pending = self.take_pending(completion_id, |k| {
            matches!(k, PendingKind::Information { .. })
        })?;
        let PendingKind::Information { class } = pending.kind else {
            unreachable!("take_pending matched an Information")
        };
        Ok(match answer {
            Ok(file) => {
                let buffer = pdu::encode_file_information(class, file)
                    .expect("only an implemented class is asked for");
                complete(
                    &pending,
                    STATUS_SUCCESS,
                    &pdu::length_prefixed(&buffer, false),
                )
            }
            Err(status) => complete(
                &pending,
                status,
                pdu::failure_body(pdu::IRP_MJ_QUERY_INFORMATION),
            ),
        })
    }

    /// The answer to [`DriveRequest::ListDirectory`]: every entry of the directory, or the
    /// NTSTATUS the host failed with. The helper keeps the entries the server's pattern matches
    /// and answers with the first; the server's later queries take the rest.
    pub fn respond_listing(
        &mut self,
        completion_id: u32,
        answer: Result<Vec<DirectoryEntry>, u32>,
    ) -> Result<Vec<u8>, RespondError> {
        let pending =
            self.take_pending(completion_id, |k| matches!(k, PendingKind::Listing { .. }))?;
        let PendingKind::Listing { class, ref pattern } = pending.kind else {
            unreachable!("take_pending matched a Listing")
        };
        let entries = match answer {
            Ok(entries) => entries,
            Err(status) => {
                return Ok(complete(
                    &pending,
                    status,
                    pdu::failure_body(pdu::IRP_MJ_DIRECTORY_CONTROL),
                ));
            }
        };
        let matched: VecDeque<_> = entries
            .into_iter()
            .filter(|entry| matches_pattern(pattern, &entry.name))
            .collect();
        let Some(file) = self.file_mut(pending.device_id, pending.file_id) else {
            return Ok(complete(
                &pending,
                STATUS_CANCELLED,
                pdu::failure_body(pdu::IRP_MJ_DIRECTORY_CONTROL),
            ));
        };
        file.listing = matched;
        Ok(next_entry(&pending, class, file, STATUS_NO_SUCH_FILE))
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
                let mut outputs = self.close_all();
                self.announced_as = Some((version, client_id));
                self.devices_announced = false;
                outputs.push(Send(pdu::encode_client_announce_reply(version, client_id)));
                outputs.push(Send(pdu::encode_client_name(&self.computer_name)));
                outputs
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
            RdpdrPdu::IoRequest(request) => self.io_request(request),
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

    /// Handle a Device I/O Request. One for a device never announced is ignored (3.1.5.2).
    fn io_request(&mut self, request: IoRequest) -> Vec<DeviceRedirectionOutput> {
        if !self.is_announced(request.device_id) {
            tracing::warn!(
                target: "rdp_rdpdr",
                device_id = request.device_id,
                "Device I/O Request for no device ignored"
            );
            return Vec::new();
        }
        let reject = |status| refuse(&request, status);
        let body = match &request.body {
            Ok(body) => body.clone(),
            Err(error) => {
                tracing::warn!(target: "rdp_rdpdr", %error, major = request.major, "Device I/O Request refused");
                return reject(STATUS_UNSUCCESSFUL);
            }
        };
        match (request.major, body) {
            (pdu::IRP_MJ_CREATE, IoBody::Create(create)) => self.create(&request, create),
            (pdu::IRP_MJ_CLOSE, _) => self.close(&request),
            (pdu::IRP_MJ_READ, IoBody::Read { length, offset }) => {
                self.read(&request, length, offset)
            }
            (pdu::IRP_MJ_WRITE, IoBody::Write { offset, data }) => {
                self.write(&request, offset, data)
            }
            (pdu::IRP_MJ_SET_INFORMATION, IoBody::SetInformation { length, info }) => {
                self.set_information(&request, length, info)
            }
            (pdu::IRP_MJ_QUERY_VOLUME_INFORMATION, IoBody::QueryVolumeInformation { class }) => {
                if pdu::encode_volume_information(class, &VolumeInformation::default()).is_none() {
                    return reject(STATUS_NOT_SUPPORTED);
                }
                self.ask(
                    &request,
                    PendingKind::Volume { class },
                    DriveRequest::QueryVolume,
                )
            }
            (pdu::IRP_MJ_QUERY_INFORMATION, IoBody::QueryInformation { class }) => {
                if self.file_mut(request.device_id, request.file_id).is_none() {
                    return reject(STATUS_UNSUCCESSFUL);
                }
                if pdu::encode_file_information(class, &FileInformation::default()).is_none() {
                    return reject(STATUS_NOT_SUPPORTED);
                }
                let file_id = request.file_id;
                self.ask(
                    &request,
                    PendingKind::Information { class },
                    DriveRequest::QueryInformation { file_id },
                )
            }
            (
                pdu::IRP_MJ_DIRECTORY_CONTROL,
                IoBody::QueryDirectory {
                    class,
                    initial,
                    path,
                },
            ) => self.query_directory(&request, class, initial, &path),
            (major, _) if pdu::is_known_major(major) => reject(STATUS_NOT_SUPPORTED),
            _ => reject(STATUS_UNSUCCESSFUL),
        }
    }

    /// A Create: the path checked against the drive's wire rules, then handed to the host under
    /// a new `file_id`.
    fn create(
        &mut self,
        request: &IoRequest,
        create: CreateRequest,
    ) -> Vec<DeviceRedirectionOutput> {
        let path = match drive_path(&create.path, true) {
            Ok(path) => path,
            Err(status) => return refuse(request, status),
        };
        let Some(disposition) = Disposition::from_wire(create.create_disposition) else {
            return refuse(request, STATUS_INVALID_PARAMETER);
        };
        let opening = self
            .pending
            .iter()
            .filter(|p| matches!(p.kind, PendingKind::Open { .. }))
            .count();
        if self.files.len() + opening >= MAX_OPEN_FILES {
            tracing::warn!(target: "rdp_rdpdr", "Create refused: too many files open");
            return refuse(request, STATUS_TOO_MANY_OPENED_FILES);
        }
        let kind = if create.create_options & pdu::FILE_DIRECTORY_FILE != 0 {
            OpenKind::Directory
        } else if create.create_options & pdu::FILE_NON_DIRECTORY_FILE != 0 {
            OpenKind::File
        } else {
            OpenKind::Any
        };
        let (files, pending) = (&self.files, &self.pending);
        let file_id = next_id(&mut self.last_file_id, |id| {
            files.iter().any(|f| f.file_id == id) || pending.iter().any(|p| p.file_id == id)
        });
        let delete_on_close = create.create_options & pdu::FILE_DELETE_ON_CLOSE != 0;
        let open = DriveRequest::Open {
            file_id,
            path,
            kind,
            disposition,
            desired_access: create.desired_access,
            delete_on_close,
        };
        let mut request = request.clone();
        request.file_id = file_id;
        self.ask(
            &request,
            PendingKind::Open {
                disposition,
                delete_on_close,
            },
            open,
        )
    }

    /// A Close: the file is forgotten, requests the host still owes about it are answered
    /// `STATUS_CANCELLED` (3.2.5.2.5), and the host is told.
    fn close(&mut self, request: &IoRequest) -> Vec<DeviceRedirectionOutput> {
        let Some(at) = self
            .files
            .iter()
            .position(|f| f.device_id == request.device_id && f.file_id == request.file_id)
        else {
            return refuse(request, STATUS_UNSUCCESSFUL);
        };
        let file = self.files.remove(at);
        let mut outputs =
            self.cancel_pending(|p| p.device_id == file.device_id && p.file_id == file.file_id);
        outputs.push(DeviceRedirectionOutput::FileClosed {
            device_id: file.device_id,
            file_id: file.file_id,
            delete: file.delete,
        });
        outputs.push(DeviceRedirectionOutput::Send(pdu::encode_io_completion(
            request.device_id,
            request.completion_id,
            STATUS_SUCCESS,
            pdu::failure_body(pdu::IRP_MJ_CLOSE),
        )));
        outputs
    }

    /// A Read: handed to the host, except what `[MS-FSA]` 2.1.5.3 answers before the file's data
    /// is reached, and a read of a directory or of a file not open.
    fn read(
        &mut self,
        request: &IoRequest,
        length: u32,
        offset: u64,
    ) -> Vec<DeviceRedirectionOutput> {
        let Some(file) = self.file_mut(request.device_id, request.file_id) else {
            return refuse(request, STATUS_UNSUCCESSFUL);
        };
        if file.directory {
            return refuse(request, STATUS_INVALID_DEVICE_REQUEST);
        }
        if offset
            .checked_add(u64::from(length))
            .is_none_or(|end| end > MAX_FILE_END)
        {
            return refuse(request, STATUS_INVALID_PARAMETER);
        }
        if length == 0 {
            return vec![DeviceRedirectionOutput::Send(pdu::encode_io_completion(
                request.device_id,
                request.completion_id,
                STATUS_SUCCESS,
                &0u32.to_le_bytes(),
            ))];
        }
        let file_id = request.file_id;
        self.ask(
            request,
            PendingKind::Read { length },
            DriveRequest::Read {
                file_id,
                offset,
                length,
            },
        )
    }

    /// A Write: handed to the host, except a write to a directory or a file not open, and a
    /// range past `MAXLONGLONG` (`[MS-FSA]` 2.1.5.4). A zero-length write still reaches the host,
    /// which refuses it first on a read-only drive.
    fn write(
        &mut self,
        request: &IoRequest,
        offset: u64,
        data: Vec<u8>,
    ) -> Vec<DeviceRedirectionOutput> {
        let appends = self
            .announced_as
            .is_some_and(|(version, _)| version >= APPEND_FROM);
        let Some(file) = self.file_mut(request.device_id, request.file_id) else {
            return refuse(request, STATUS_UNSUCCESSFUL);
        };
        if file.directory {
            return refuse(request, STATUS_INVALID_DEVICE_REQUEST);
        }
        let offset = if appends && offset == u64::MAX {
            WriteOffset::Append
        } else {
            if offset
                .checked_add(data.len() as u64)
                .is_none_or(|end| end > MAX_FILE_END)
            {
                return refuse(request, STATUS_INVALID_PARAMETER);
            }
            WriteOffset::At(offset)
        };
        let file_id = request.file_id;
        self.ask(
            request,
            PendingKind::Write {
                length: data.len() as u32,
            },
            DriveRequest::Write {
                file_id,
                offset,
                data,
            },
        )
    }

    /// A Set Information: each class 2.2.3.3.9 names reaches the host as its own request, a
    /// rename target checked against the wire first. Every response repeats the request's
    /// `Length` (2.2.3.4.9).
    fn set_information(
        &mut self,
        request: &IoRequest,
        length: u32,
        info: SetInformation,
    ) -> Vec<DeviceRedirectionOutput> {
        let reject = |status: u32| {
            vec![DeviceRedirectionOutput::Send(pdu::encode_io_completion(
                request.device_id,
                request.completion_id,
                status,
                &length.to_le_bytes(),
            ))]
        };
        let Some(file) = self.file_mut(request.device_id, request.file_id) else {
            return reject(STATUS_UNSUCCESSFUL);
        };
        let (directory, file_id) = (file.directory, request.file_id);
        let mut delete = None;
        let drive_request = match info {
            SetInformation::EndOfFile(size) | SetInformation::Allocation(size)
                if directory || size > MAX_FILE_END =>
            {
                return reject(STATUS_INVALID_PARAMETER);
            }
            SetInformation::EndOfFile(size) => DriveRequest::SetEndOfFile { file_id, size },
            SetInformation::Allocation(size) => DriveRequest::SetAllocationSize { file_id, size },
            SetInformation::Basic(info) => DriveRequest::SetBasic { file_id, info },
            SetInformation::Disposition { delete_pending } => {
                delete = Some(delete_pending);
                DriveRequest::Delete {
                    file_id,
                    delete: delete_pending,
                }
            }
            SetInformation::Rename {
                replace_if_exists,
                root_directory,
                path,
            } => {
                if root_directory != 0 {
                    return reject(STATUS_INVALID_PARAMETER);
                }
                let path = match drive_path(&path, false) {
                    Ok(path) if !path.is_empty() => path,
                    Ok(_) => return reject(STATUS_OBJECT_NAME_INVALID),
                    Err(status) => return reject(status),
                };
                DriveRequest::Rename {
                    file_id,
                    path,
                    replace_if_exists,
                }
            }
            SetInformation::Other { .. } => return reject(STATUS_NOT_SUPPORTED),
        };
        self.ask(request, PendingKind::Set { length, delete }, drive_request)
    }

    /// A Query Directory: a first query asks the host for the directory's entries, and a later
    /// one takes the next entry that matched (2.2.3.3.10).
    fn query_directory(
        &mut self,
        request: &IoRequest,
        class: u32,
        initial: bool,
        path: &[u16],
    ) -> Vec<DeviceRedirectionOutput> {
        let Some(file) = self.file_mut(request.device_id, request.file_id) else {
            return refuse(request, STATUS_UNSUCCESSFUL);
        };
        if !file.directory {
            return refuse(request, STATUS_NOT_A_DIRECTORY);
        }
        if pdu::encode_directory_entry(class, "", &FileInformation::default()).is_none() {
            return refuse(request, STATUS_NOT_SUPPORTED);
        }
        if !initial {
            let pending = Pending {
                completion_id: request.completion_id,
                device_id: request.device_id,
                file_id: request.file_id,
                kind: PendingKind::Listing {
                    class,
                    pattern: Vec::new(),
                },
            };
            return vec![DeviceRedirectionOutput::Send(next_entry(
                &pending,
                class,
                file,
                STATUS_NO_MORE_FILES,
            ))];
        }
        file.listing.clear();
        let mut path = match drive_path(path, false) {
            Ok(path) => path,
            Err(status) => return refuse(request, status),
        };
        let pattern = path.pop().unwrap_or_else(|| "*".to_string());
        let file_id = request.file_id;
        self.ask(
            request,
            PendingKind::Listing {
                class,
                pattern: pattern.chars().collect(),
            },
            DriveRequest::ListDirectory { file_id, path },
        )
    }

    /// Hand `drive_request` to the host, or refuse it when [`MAX_PENDING_REQUESTS`] already
    /// wait or its `CompletionId` is already waiting.
    fn ask(
        &mut self,
        request: &IoRequest,
        kind: PendingKind,
        drive_request: DriveRequest,
    ) -> Vec<DeviceRedirectionOutput> {
        let status = if self.pending.len() >= MAX_PENDING_REQUESTS {
            tracing::warn!(target: "rdp_rdpdr", "Device I/O Request refused: too many waiting");
            STATUS_INSUFFICIENT_RESOURCES
        } else if self
            .pending
            .iter()
            .any(|p| p.completion_id == request.completion_id)
        {
            STATUS_UNSUCCESSFUL
        } else {
            STATUS_SUCCESS
        };
        if status != STATUS_SUCCESS {
            return vec![DeviceRedirectionOutput::Send(pdu::encode_io_completion(
                request.device_id,
                request.completion_id,
                status,
                &kind.failed_body(),
            ))];
        }
        self.pending.push(Pending {
            completion_id: request.completion_id,
            device_id: request.device_id,
            file_id: request.file_id,
            kind,
        });
        vec![DeviceRedirectionOutput::DriveRequest {
            completion_id: request.completion_id,
            device_id: request.device_id,
            request: drive_request,
        }]
    }

    fn take_pending(
        &mut self,
        completion_id: u32,
        fits: impl FnOnce(&PendingKind) -> bool,
    ) -> Result<Pending, RespondError> {
        let at = self
            .pending
            .iter()
            .position(|p| p.completion_id == completion_id)
            .ok_or(RespondError::NotRequested)?;
        if !fits(&self.pending[at].kind) {
            return Err(RespondError::WrongKind);
        }
        Ok(self.pending.remove(at))
    }

    /// Answer every waiting request `which` selects with `STATUS_CANCELLED`.
    fn cancel_pending(&mut self, which: impl Fn(&Pending) -> bool) -> Vec<DeviceRedirectionOutput> {
        let (cancelled, kept) = core::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| which(p));
        self.pending = kept;
        cancelled
            .iter()
            .map(|p: &Pending| {
                DeviceRedirectionOutput::Send(complete(p, STATUS_CANCELLED, &p.kind.failed_body()))
            })
            .collect()
    }

    /// Forget every file and waiting request, telling the host of each file.
    fn close_all(&mut self) -> Vec<DeviceRedirectionOutput> {
        self.pending.clear();
        self.files
            .drain(..)
            .map(|f| DeviceRedirectionOutput::FileClosed {
                device_id: f.device_id,
                file_id: f.file_id,
                delete: f.delete,
            })
            .collect()
    }

    fn file_mut(&mut self, device_id: u32, file_id: u32) -> Option<&mut OpenFile> {
        self.files
            .iter_mut()
            .find(|f| f.device_id == device_id && f.file_id == file_id)
    }

    fn terminate(&mut self, error: DecodeError) -> Vec<DeviceRedirectionOutput> {
        tracing::warn!(target: "rdp_rdpdr", %error, "device redirection channel ended");
        self.terminated = true;
        let mut outputs = self.close_all();
        outputs.push(DeviceRedirectionOutput::Terminated(error));
        outputs
    }
}

/// A Device I/O Response to the request `pending` stands for.
fn complete(pending: &Pending, status: u32, body: &[u8]) -> Vec<u8> {
    pdu::encode_io_completion(pending.device_id, pending.completion_id, status, body)
}

/// A failed response to `request`, its fields zeroed.
fn refuse(request: &IoRequest, status: u32) -> Vec<DeviceRedirectionOutput> {
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

/// The Query Directory response carrying `file`'s next matched entry, or `none_left` when
/// there is none.
fn next_entry(pending: &Pending, class: u32, file: &mut OpenFile, none_left: u32) -> Vec<u8> {
    match file.listing.pop_front() {
        Some(entry) => {
            let buffer = pdu::encode_directory_entry(class, &entry.name, &entry.info)
                .expect("only an implemented class is asked for");
            complete(
                pending,
                STATUS_SUCCESS,
                &pdu::length_prefixed(&buffer, true),
            )
        }
        None => complete(pending, none_left, &pdu::length_prefixed(&[], true)),
    }
}

/// The next nonzero id after `last` that `in_use` does not claim.
fn next_id(last: &mut u32, in_use: impl Fn(u32) -> bool) -> u32 {
    loop {
        *last = last.wrapping_add(1);
        if *last != 0 && !in_use(*last) {
            return *last;
        }
    }
}

/// A server path's components below the drive's root, or the NTSTATUS refusing it. A path
/// that is not UTF-16, holds a NUL, or has a component that is `.` or `..` or holds `/` or `:`
/// cannot stay inside the drive and is `STATUS_OBJECT_NAME_INVALID`. For a Create
/// (`reserved`), a path naming a device 3.2.5.2.3 lists is `STATUS_ACCESS_DENIED`.
fn drive_path(units: &[u16], reserved: bool) -> Result<Vec<String>, u32> {
    let path = String::from_utf16(units).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
    let components: Vec<String> = path
        .split('\\')
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect();
    let escapes = |c: &String| c == "." || c == ".." || c.contains(['\0', '/', ':']);
    if components.iter().any(escapes) {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    if reserved
        && let [name] = components.as_slice()
        && RESERVED_NAMES.iter().any(|r| r.eq_ignore_ascii_case(name))
    {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(components)
}

/// Whether `name` matches `pattern` as a Windows file system does (`[MS-FSA]` 2.1.4.4),
/// ignoring case: `*` any run of characters, `?` any one, and the DOS wildcards `<` (any run
/// up to the name's last `.`), `>` (any one, or none at a `.` or the end) and `"` (a `.`, or
/// none at the end).
fn matches_pattern(pattern: &[char], name: &str) -> bool {
    let name: Vec<char> = name.chars().flat_map(char::to_lowercase).collect();
    let pattern: Vec<char> = pattern.iter().flat_map(|c| c.to_lowercase()).collect();
    let last_dot = name.iter().rposition(|&c| c == '.');
    // reachable[j]: the pattern so far can end having consumed `name[..j]`.
    let mut reachable = vec![false; name.len() + 1];
    reachable[0] = true;
    for &p in &pattern {
        let Some(first) = reachable.iter().position(|&r| r) else {
            return false;
        };
        let mut next = vec![false; name.len() + 1];
        // `*` and `<` reach every position from the first reachable one on, so each is one
        // pass over the name rather than one per reachable position.
        if p == '*' {
            next[first..].fill(true);
            reachable = next;
            continue;
        }
        if p == '<' {
            let stop = last_dot.unwrap_or(name.len());
            if first <= stop {
                next[first..=stop].fill(true);
            }
            for j in stop + 1..=name.len() {
                next[j] |= reachable[j];
            }
            reachable = next;
            continue;
        }
        for j in first..=name.len() {
            if !reachable[j] {
                continue;
            }
            match p {
                '?' => {
                    if j < name.len() {
                        next[j + 1] = true;
                    }
                }
                '>' => {
                    if j < name.len() && name[j] != '.' {
                        next[j + 1] = true;
                    } else {
                        next[j] = true;
                    }
                }
                '"' => {
                    if j < name.len() && name[j] == '.' {
                        next[j + 1] = true;
                    } else if j == name.len() {
                        next[j] = true;
                    }
                }
                c => {
                    if j < name.len() && name[j] == c {
                        next[j + 1] = true;
                    }
                }
            }
        }
        reachable = next;
    }
    reachable[name.len()]
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
/// NUL-terminated ASCII in `DeviceData`, which the server reads as 8-bit characters.
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
    let device_data = name.bytes().chain([0]).collect();
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
    use justrdp_pdu::rdpdr::{IRP_MJ_CREATE, IRP_MJ_READ, STATUS_INVALID_DEVICE_REQUEST};

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
        assert_eq!(announce.device_data, b"projects\0");
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
    /// A known major function not implemented yet is `STATUS_NOT_SUPPORTED`, an unknown one
    /// `STATUS_UNSUCCESSFUL`, each with its body's fields zeroed; a request for no announced
    /// device is ignored.
    #[test]
    fn unimplemented_requests_are_refused() {
        let mut h = ready();
        assert_eq!(
            sent(&h.process(&io_request(1, 6, pdu::IRP_MJ_LOCK_CONTROL))),
            vec![pdu::encode_io_completion(1, 6, STATUS_NOT_SUPPORTED, &[0; 5]).as_slice()]
        );
        assert_eq!(
            sent(&h.process(&io_request(1, 7, 0x0000_0001))),
            vec![pdu::encode_io_completion(1, 7, STATUS_UNSUCCESSFUL, &[]).as_slice()]
        );
        assert!(h.process(&io_request(2, 8, IRP_MJ_CREATE)).is_empty());
    }

    /// A request whose header reads but whose body does not is refused, and the channel goes
    /// on.
    #[test]
    fn a_request_with_a_malformed_body_is_refused() {
        let mut h = ready();
        assert_eq!(
            sent(&h.process(&io_request(1, 5, IRP_MJ_CREATE))),
            vec![pdu::encode_io_completion(1, 5, STATUS_UNSUCCESSFUL, &[0; 5]).as_slice()]
        );
        assert!(!h.terminated);
    }

    fn utf16(path: &str) -> Vec<u8> {
        path.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn header(file_id: u32, completion_id: u32, major: u32, minor: u32) -> Vec<u8> {
        let mut m = vec![0x72, 0x44, 0x52, 0x49];
        for field in [1, file_id, completion_id, major, minor] {
            m.extend_from_slice(&field.to_le_bytes());
        }
        m
    }

    fn create(completion_id: u32, disposition: u32, options: u32, path: &str) -> Vec<u8> {
        let mut m = header(0, completion_id, IRP_MJ_CREATE, 0);
        let path = utf16(path);
        for field in [0x0012_0089u32, 0, 0, 0x80, 7, disposition, options] {
            m.extend_from_slice(&field.to_le_bytes());
        }
        m.extend_from_slice(&(path.len() as u32).to_le_bytes());
        m.extend_from_slice(&path);
        m
    }

    fn close(completion_id: u32, file_id: u32) -> Vec<u8> {
        let mut m = header(file_id, completion_id, pdu::IRP_MJ_CLOSE, 0);
        m.extend_from_slice(&[0; 32]);
        m
    }

    fn query(completion_id: u32, file_id: u32, major: u32, class: u32) -> Vec<u8> {
        let mut m = header(file_id, completion_id, major, 0);
        m.extend_from_slice(&class.to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes());
        m.extend_from_slice(&[0; 24]);
        m
    }

    fn query_directory(
        completion_id: u32,
        file_id: u32,
        class: u32,
        path: Option<&str>,
    ) -> Vec<u8> {
        let mut m = header(
            file_id,
            completion_id,
            pdu::IRP_MJ_DIRECTORY_CONTROL,
            pdu::IRP_MN_QUERY_DIRECTORY,
        );
        let path = path.map(utf16);
        m.extend_from_slice(&class.to_le_bytes());
        m.push(u8::from(path.is_some()));
        let path = path.unwrap_or_default();
        m.extend_from_slice(&(path.len() as u32).to_le_bytes());
        m.extend_from_slice(&[0; 23]);
        m.extend_from_slice(&path);
        m
    }

    fn asked(outputs: &[DeviceRedirectionOutput]) -> &DriveRequest {
        match outputs {
            [DeviceRedirectionOutput::DriveRequest { request, .. }] => request,
            other => panic!("expected one drive request, got {other:?}"),
        }
    }

    /// Open `path` as a directory and answer that it is one, returning its `file_id`.
    fn open_directory(h: &mut DeviceRedirection, completion_id: u32, path: &str) -> u32 {
        let outputs = h.process(&create(completion_id, pdu::FILE_OPEN, 1, path));
        let DriveRequest::Open { file_id, .. } = *asked(&outputs) else {
            panic!("expected an Open");
        };
        h.respond_open(completion_id, Ok(Opened::Directory))
            .unwrap();
        file_id
    }

    fn file(name: &str, size: u64, directory: bool) -> DirectoryEntry {
        DirectoryEntry {
            name: name.to_string(),
            info: FileInformation {
                end_of_file: size,
                attributes: if directory {
                    pdu::FILE_ATTRIBUTE_DIRECTORY
                } else {
                    0x20
                },
                ..FileInformation::default()
            },
        }
    }

    fn read(completion_id: u32, file_id: u32, offset: u64, length: u32) -> Vec<u8> {
        let mut m = header(file_id, completion_id, IRP_MJ_READ, 0);
        m.extend_from_slice(&length.to_le_bytes());
        m.extend_from_slice(&offset.to_le_bytes());
        m.extend_from_slice(&[0; 20]);
        m
    }

    /// Open `path` as a file and answer that it is one, returning its `file_id`.
    fn open_file(h: &mut DeviceRedirection, completion_id: u32, path: &str) -> u32 {
        let outputs = h.process(&create(completion_id, pdu::FILE_OPEN, 0x40, path));
        let DriveRequest::Open { file_id, .. } = *asked(&outputs) else {
            panic!("expected an Open");
        };
        h.respond_open(completion_id, Ok(Opened::File)).unwrap();
        file_id
    }

    /// A Read reaches the host with its offset and length; the answer goes back as `Length`
    /// and the bytes, a short one included, and a failure with `Length` zero.
    #[test]
    fn a_read_is_answered_by_the_host() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        let outputs = h.process(&read(2, file, 0x1_0000_0000, 8));
        assert_eq!(
            asked(&outputs),
            &DriveRequest::Read {
                file_id: file,
                offset: 0x1_0000_0000,
                length: 8
            }
        );
        let mut body = 3u32.to_le_bytes().to_vec();
        body.extend_from_slice(b"abc");
        assert_eq!(
            h.respond_read(2, Ok(b"abc")),
            Ok(pdu::encode_io_completion(1, 2, STATUS_SUCCESS, &body))
        );
        h.process(&read(3, file, 0, 8));
        assert_eq!(
            h.respond_read(3, Err(STATUS_ACCESS_DENIED)),
            Ok(pdu::encode_io_completion(
                1,
                3,
                STATUS_ACCESS_DENIED,
                &[0; 4]
            ))
        );
        assert_eq!(
            h.respond_information(3, Ok(&FileInformation::default())),
            Err(RespondError::NotRequested)
        );
    }

    /// An answer longer than the read asked for is refused and the read keeps waiting.
    #[test]
    fn an_answer_longer_than_the_read_is_refused() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        h.process(&read(2, file, 0, 4));
        assert_eq!(h.respond_read(2, Ok(b"abcde")), Err(RespondError::TooLong));
        let mut body = 4u32.to_le_bytes().to_vec();
        body.extend_from_slice(b"abcd");
        assert_eq!(
            h.respond_read(2, Ok(b"abcd")),
            Ok(pdu::encode_io_completion(1, 2, STATUS_SUCCESS, &body))
        );
    }

    /// Reads the host cannot answer differently are answered without it (`[MS-FSA]` 2.1.5.3):
    /// nothing asked, a range past `MAXLONGLONG`, a directory, a file never opened.
    #[test]
    fn a_read_the_helper_can_answer_skips_the_host() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        let dir = open_directory(&mut h, 2, "\\d");
        let answered = |h: &mut DeviceRedirection, m: &[u8], status: u32| {
            let outputs = h.process(m);
            assert_eq!(outputs.len(), 1, "{outputs:?}");
            assert_eq!(
                sent(&outputs),
                vec![pdu::encode_io_completion(1, 9, status, &[0; 4]).as_slice()]
            );
        };
        answered(&mut h, &read(9, file, 5, 0), STATUS_SUCCESS);
        answered(
            &mut h,
            &read(9, file, i64::MAX as u64, 1),
            STATUS_INVALID_PARAMETER,
        );
        answered(
            &mut h,
            &read(9, file, u64::MAX, 0),
            STATUS_INVALID_PARAMETER,
        );
        answered(
            &mut h,
            &read(9, file, u64::MAX, 1),
            STATUS_INVALID_PARAMETER,
        );
        answered(&mut h, &read(9, dir, 0, 1), STATUS_INVALID_DEVICE_REQUEST);
        answered(&mut h, &read(9, 999, 0, 1), STATUS_UNSUCCESSFUL);
        let outputs = h.process(&read(9, file, i64::MAX as u64 - 1, 1));
        assert!(matches!(asked(&outputs), DriveRequest::Read { .. }));
    }

    /// A Close cancels a read the host still owes.
    #[test]
    fn a_close_cancels_a_waiting_read() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        h.process(&read(2, file, 0, 4));
        assert_eq!(
            sent(&h.process(&close(3, file)))[0],
            pdu::encode_io_completion(1, 2, STATUS_CANCELLED, &[0; 4])
        );
        assert_eq!(
            h.respond_read(2, Ok(b"ab")),
            Err(RespondError::NotRequested)
        );
    }

    fn write(completion_id: u32, file_id: u32, offset: u64, data: &[u8]) -> Vec<u8> {
        let mut m = header(file_id, completion_id, pdu::IRP_MJ_WRITE, 0);
        m.extend_from_slice(&(data.len() as u32).to_le_bytes());
        m.extend_from_slice(&offset.to_le_bytes());
        m.extend_from_slice(&[0; 20]);
        m.extend_from_slice(data);
        m
    }

    fn set_info(completion_id: u32, file_id: u32, class: u32, buffer: &[u8]) -> Vec<u8> {
        let mut m = header(file_id, completion_id, pdu::IRP_MJ_SET_INFORMATION, 0);
        m.extend_from_slice(&class.to_le_bytes());
        m.extend_from_slice(&(buffer.len() as u32).to_le_bytes());
        m.extend_from_slice(&[0; 24]);
        m.extend_from_slice(buffer);
        m
    }

    fn rename_buffer(root_directory: u8, path: &str) -> Vec<u8> {
        let name: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut b = vec![1, root_directory];
        b.extend_from_slice(&(name.len() as u32).to_le_bytes());
        b.extend_from_slice(&name);
        b
    }

    /// A Write reaches the host with its offset and data; the answer is the count written and a
    /// padding byte, and a count above what was sent is refused.
    #[test]
    fn a_write_is_answered_by_the_host() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        let outputs = h.process(&write(2, file, 5, b"abc"));
        assert_eq!(
            asked(&outputs),
            &DriveRequest::Write {
                file_id: file,
                offset: WriteOffset::At(5),
                data: b"abc".to_vec()
            }
        );
        assert_eq!(h.respond_write(2, Ok(4)), Err(RespondError::TooLong));
        assert_eq!(
            h.respond_write(2, Ok(3)),
            Ok(pdu::encode_io_completion(
                1,
                2,
                STATUS_SUCCESS,
                &[3, 0, 0, 0, 0]
            ))
        );
        h.process(&write(3, file, 0, b"x"));
        assert_eq!(
            h.respond_write(3, Err(pdu::STATUS_MEDIA_WRITE_PROTECTED)),
            Ok(pdu::encode_io_completion(
                1,
                3,
                pdu::STATUS_MEDIA_WRITE_PROTECTED,
                &[0; 5]
            ))
        );
        // A zero-length write still reaches the host: a read-only drive refuses it first
        // (`[MS-FSA]` 2.1.5.4).
        let outputs = h.process(&write(4, file, 0, b""));
        assert!(matches!(asked(&outputs), DriveRequest::Write { data, .. } if data.is_empty()));
    }

    /// An `Offset` of all ones appends when this client announced version 13 or later
    /// (2.2.1.4.4), and is an offset past `MAXLONGLONG` below it.
    #[test]
    fn all_ones_appends_from_version_13() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        let outputs = h.process(&write(2, file, u64::MAX, b"z"));
        assert!(matches!(
            asked(&outputs),
            DriveRequest::Write {
                offset: WriteOffset::Append,
                ..
            }
        ));

        let mut h = helper();
        h.process(&server_announce(0x0c, 7));
        h.process(&SERVER_CAPABILITIES);
        h.process(&client_id_confirm(7));
        h.process(&USER_LOGGED_ON);
        let file = open_file(&mut h, 1, "\\a.txt");
        assert_eq!(
            sent(&h.process(&write(2, file, u64::MAX, b"z"))),
            vec![pdu::encode_io_completion(1, 2, STATUS_INVALID_PARAMETER, &[0; 5]).as_slice()]
        );
    }

    /// Writes answered without the host: a directory, a file not open, and a range past
    /// `MAXLONGLONG` (`[MS-FSA]` 2.1.5.4).
    #[test]
    fn a_write_the_helper_can_answer_skips_the_host() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        let dir = open_directory(&mut h, 2, "\\d");
        for (m, status) in [
            (write(9, dir, 0, b"x"), STATUS_INVALID_DEVICE_REQUEST),
            (write(9, 999, 0, b"x"), STATUS_UNSUCCESSFUL),
            (
                write(9, file, i64::MAX as u64, b"x"),
                STATUS_INVALID_PARAMETER,
            ),
        ] {
            assert_eq!(
                sent(&h.process(&m)),
                vec![pdu::encode_io_completion(1, 9, status, &[0; 5]).as_slice()]
            );
        }
        let outputs = h.process(&write(9, file, i64::MAX as u64 - 1, b"x"));
        assert!(matches!(asked(&outputs), DriveRequest::Write { .. }));
    }

    /// Each class 2.2.3.3.9 names reaches the host as its own request, answered with
    /// `respond_set`; the response repeats the request's `Length`, a failed one included.
    #[test]
    fn set_information_reaches_the_host() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        let cases: Vec<(Vec<u8>, DriveRequest)> = vec![
            (
                set_info(
                    2,
                    file,
                    pdu::FILE_END_OF_FILE_INFORMATION,
                    &7u64.to_le_bytes(),
                ),
                DriveRequest::SetEndOfFile {
                    file_id: file,
                    size: 7,
                },
            ),
            (
                set_info(
                    2,
                    file,
                    pdu::FILE_ALLOCATION_INFORMATION,
                    &9u64.to_le_bytes(),
                ),
                DriveRequest::SetAllocationSize {
                    file_id: file,
                    size: 9,
                },
            ),
            (
                set_info(2, file, pdu::FILE_DISPOSITION_INFORMATION, &[]),
                DriveRequest::Delete {
                    file_id: file,
                    delete: true,
                },
            ),
            (
                set_info(
                    2,
                    file,
                    pdu::FILE_RENAME_INFORMATION,
                    &rename_buffer(0, "\\sub\\b.txt"),
                ),
                DriveRequest::Rename {
                    file_id: file,
                    path: vec!["sub".to_string(), "b.txt".to_string()],
                    replace_if_exists: true,
                },
            ),
        ];
        for (m, expected) in cases {
            let length = u32::from_le_bytes(m[28..32].try_into().unwrap());
            assert_eq!(asked(&h.process(&m)), &expected);
            assert_eq!(
                h.respond_set(2, Ok(())),
                Ok(pdu::encode_io_completion(
                    1,
                    2,
                    STATUS_SUCCESS,
                    &length.to_le_bytes()
                ))
            );
        }
        let mut basic = Vec::new();
        for time in [0i64, -1, 3, 0] {
            basic.extend_from_slice(&time.to_le_bytes());
        }
        basic.extend_from_slice(&0x21u32.to_le_bytes());
        let outputs = h.process(&set_info(3, file, pdu::FILE_BASIC_INFORMATION, &basic));
        assert_eq!(
            asked(&outputs),
            &DriveRequest::SetBasic {
                file_id: file,
                info: pdu::BasicInformation {
                    creation_time: 0,
                    last_access_time: -1,
                    last_write_time: 3,
                    change_time: 0,
                    attributes: 0x21,
                }
            }
        );
        assert_eq!(h.respond_write(3, Ok(0)), Err(RespondError::WrongKind));
        assert_eq!(
            h.respond_set(3, Err(pdu::STATUS_MEDIA_WRITE_PROTECTED)),
            Ok(pdu::encode_io_completion(
                1,
                3,
                pdu::STATUS_MEDIA_WRITE_PROTECTED,
                &36u32.to_le_bytes()
            ))
        );
    }

    /// A rename target that escapes the drive, names its root, or gives a `RootDirectory` is
    /// refused without reaching the host, the response repeating `Length`.
    #[test]
    fn a_rename_escaping_the_drive_is_refused() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        for (root, path, status) in [
            (0, "\\..\\b.txt", STATUS_OBJECT_NAME_INVALID),
            (0, "\\sub\\..\\..\\b.txt", STATUS_OBJECT_NAME_INVALID),
            (0, "C:\\b.txt", STATUS_OBJECT_NAME_INVALID),
            (0, "\\b\0.txt", STATUS_OBJECT_NAME_INVALID),
            (0, "\\sub/..\\b.txt", STATUS_OBJECT_NAME_INVALID),
            (0, "\\", STATUS_OBJECT_NAME_INVALID),
            (1, "\\b.txt", STATUS_INVALID_PARAMETER),
        ] {
            let buffer = rename_buffer(root, path);
            assert_eq!(
                h.process(&set_info(4, file, pdu::FILE_RENAME_INFORMATION, &buffer)),
                vec![DeviceRedirectionOutput::Send(pdu::encode_io_completion(
                    1,
                    4,
                    status,
                    &(buffer.len() as u32).to_le_bytes()
                ))],
                "{path:?}"
            );
        }
    }

    /// Set Information the helper answers itself still repeats `Length`: an unknown class, a
    /// file not open, a size past `MAXLONGLONG`, and a size on a directory.
    #[test]
    fn set_information_the_helper_refuses_repeats_the_length() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        let dir = open_directory(&mut h, 2, "\\d");
        let eof = |size: u64| size.to_le_bytes();
        for (m, status, length) in [
            (
                set_info(5, file, 0x22, &[1, 2, 3]),
                STATUS_NOT_SUPPORTED,
                3u32,
            ),
            (
                set_info(5, 999, pdu::FILE_DISPOSITION_INFORMATION, &[1]),
                STATUS_UNSUCCESSFUL,
                1,
            ),
            (
                set_info(5, file, pdu::FILE_END_OF_FILE_INFORMATION, &eof(1 << 63)),
                STATUS_INVALID_PARAMETER,
                8,
            ),
            (
                set_info(5, file, pdu::FILE_ALLOCATION_INFORMATION, &eof(1 << 63)),
                STATUS_INVALID_PARAMETER,
                8,
            ),
            (
                set_info(5, dir, pdu::FILE_END_OF_FILE_INFORMATION, &eof(1)),
                STATUS_INVALID_PARAMETER,
                8,
            ),
        ] {
            assert_eq!(
                sent(&h.process(&m)),
                vec![pdu::encode_io_completion(1, 5, status, &length.to_le_bytes()).as_slice()]
            );
        }
    }

    /// A Set Information the host still owes is cancelled by a Close, repeating its `Length`.
    #[test]
    fn a_close_cancels_a_waiting_set_information_with_its_length() {
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        h.process(&set_info(
            2,
            file,
            pdu::FILE_END_OF_FILE_INFORMATION,
            &7u64.to_le_bytes(),
        ));
        assert_eq!(
            sent(&h.process(&close(3, file)))[0],
            pdu::encode_io_completion(1, 2, STATUS_CANCELLED, &8u32.to_le_bytes())
        );
    }

    /// A delete the host accepted, or a Create asking for one, happens when the file closes:
    /// `FileClosed` says so. One cancelled or refused does not.
    #[test]
    fn a_delete_happens_when_the_file_closes() {
        let closed = |outputs: Vec<DeviceRedirectionOutput>| {
            outputs.into_iter().find_map(|o| match o {
                DeviceRedirectionOutput::FileClosed { delete, .. } => Some(delete),
                _ => None,
            })
        };
        let disposition = |pending: u8| [pending];
        let mut h = ready();
        let file = open_file(&mut h, 1, "\\a.txt");
        h.process(&set_info(
            2,
            file,
            pdu::FILE_DISPOSITION_INFORMATION,
            &disposition(1),
        ));
        h.respond_set(2, Ok(())).unwrap();
        assert_eq!(closed(h.process(&close(3, file))), Some(true));

        let file = open_file(&mut h, 4, "\\a.txt");
        h.process(&set_info(
            5,
            file,
            pdu::FILE_DISPOSITION_INFORMATION,
            &disposition(1),
        ));
        h.respond_set(5, Ok(())).unwrap();
        h.process(&set_info(
            6,
            file,
            pdu::FILE_DISPOSITION_INFORMATION,
            &disposition(0),
        ));
        h.respond_set(6, Ok(())).unwrap();
        assert_eq!(closed(h.process(&close(7, file))), Some(false));

        let file = open_file(&mut h, 8, "\\a.txt");
        h.process(&set_info(
            9,
            file,
            pdu::FILE_DISPOSITION_INFORMATION,
            &disposition(1),
        ));
        h.respond_set(9, Err(pdu::STATUS_CANNOT_DELETE)).unwrap();
        assert_eq!(closed(h.process(&close(10, file))), Some(false));

        // FILE_DELETE_ON_CLOSE on the Create.
        let outputs = h.process(&create(11, pdu::FILE_OPEN, 0x1040, "\\a.txt"));
        let DriveRequest::Open {
            delete_on_close, ..
        } = *asked(&outputs)
        else {
            panic!("expected an Open");
        };
        assert!(delete_on_close);
        h.respond_open(11, Ok(Opened::File)).unwrap();
        assert_eq!(closed(h.process(&server_announce(0x0d, 9))), Some(true));
    }

    /// A Create reaches the host as an Open under a new file ID, with the path split below the
    /// drive's root; the answer carries that ID and the `Information` its disposition implies.
    #[test]
    fn a_create_is_opened_by_the_host() {
        let mut h = ready();
        let outputs = h.process(&create(5, pdu::FILE_OPEN_IF, 0x40, "\\docs\\a.txt"));
        let DriveRequest::Open {
            file_id,
            path,
            kind,
            disposition,
            desired_access,
            delete_on_close,
        } = asked(&outputs).clone()
        else {
            panic!("expected an Open");
        };
        assert_eq!(path, ["docs", "a.txt"]);
        assert!(!delete_on_close);
        assert_eq!(kind, OpenKind::File);
        assert_eq!(disposition, Disposition::OpenIf);
        assert_eq!(desired_access, 0x0012_0089);
        let mut body = file_id.to_le_bytes().to_vec();
        body.push(pdu::FILE_OPENED);
        assert_eq!(
            h.respond_open(5, Ok(Opened::File)),
            Ok(pdu::encode_io_completion(1, 5, STATUS_SUCCESS, &body))
        );
        assert_eq!(
            h.respond_open(5, Ok(Opened::File)),
            Err(RespondError::NotRequested)
        );
        let outputs = h.process(&create(6, pdu::FILE_OPEN, 1, ""));
        assert!(matches!(
            asked(&outputs),
            DriveRequest::Open { path, kind: OpenKind::Directory, file_id: next, .. }
                if path.is_empty() && *next != file_id
        ));
        assert_eq!(
            h.respond_open(6, Err(pdu::STATUS_NO_SUCH_FILE)),
            Ok(pdu::encode_io_completion(
                1,
                6,
                pdu::STATUS_NO_SUCH_FILE,
                &[0; 5]
            ))
        );
    }

    /// A path that would leave the drive never reaches the host.
    #[test]
    fn a_path_escaping_the_drive_is_refused() {
        let mut h = ready();
        for (at, path) in [
            "\\..\\secret",
            "\\a\\..\\..\\b",
            "\\.\\a",
            "C:\\Windows",
            "\\a/..\\b",
            "\\a\0b",
        ]
        .into_iter()
        .enumerate()
        {
            let id = 10 + at as u32;
            assert_eq!(
                sent(&h.process(&create(id, pdu::FILE_OPEN, 0, path))),
                vec![
                    pdu::encode_io_completion(1, id, STATUS_OBJECT_NAME_INVALID, &[0; 5])
                        .as_slice()
                ],
                "{path:?}"
            );
        }
        let mut lone_surrogate = header(0, 20, IRP_MJ_CREATE, 0);
        for field in [0u32, 0, 0, 0, 0, pdu::FILE_OPEN, 0, 4] {
            lone_surrogate.extend_from_slice(&field.to_le_bytes());
        }
        lone_surrogate.extend_from_slice(&[0x00, 0xD8, 0, 0]);
        assert_eq!(
            sent(&h.process(&lone_surrogate)),
            vec![pdu::encode_io_completion(1, 20, STATUS_OBJECT_NAME_INVALID, &[0; 5]).as_slice()]
        );
        assert!(h.pending.is_empty());
    }

    /// 3.2.5.2.3: a Create naming a reserved device is `STATUS_ACCESS_DENIED`; the same name
    /// deeper in a path is the host's to judge.
    #[test]
    fn a_reserved_device_name_is_denied() {
        let mut h = ready();
        for (id, path) in [(1, "CON"), (2, "\\lpt9"), (3, "\\Clock$")] {
            assert_eq!(
                sent(&h.process(&create(id, pdu::FILE_OPEN, 0, path))),
                vec![pdu::encode_io_completion(1, id, STATUS_ACCESS_DENIED, &[0; 5]).as_slice()],
                "{path:?}"
            );
        }
        assert!(matches!(
            asked(&h.process(&create(4, pdu::FILE_OPEN, 0, "\\dir\\con"))),
            DriveRequest::Open { .. }
        ));
    }

    #[test]
    fn an_unknown_disposition_is_invalid() {
        let mut h = ready();
        assert_eq!(
            sent(&h.process(&create(5, 9, 0, "\\a"))),
            vec![pdu::encode_io_completion(1, 5, STATUS_INVALID_PARAMETER, &[0; 5]).as_slice()]
        );
    }

    /// Volume and file information reach the host; an unimplemented class is refused without
    /// it, and so is a query for a file never opened.
    #[test]
    fn information_is_asked_of_the_host() {
        let mut h = ready();
        let root = open_directory(&mut h, 1, "");
        let class = pdu::FILE_FS_VOLUME_INFORMATION;
        let outputs = h.process(&query(2, root, pdu::IRP_MJ_QUERY_VOLUME_INFORMATION, class));
        assert_eq!(asked(&outputs), &DriveRequest::QueryVolume);
        let volume = VolumeInformation {
            label: "justrdp".to_string(),
            ..VolumeInformation::default()
        };
        let buffer = pdu::encode_volume_information(class, &volume).unwrap();
        assert_eq!(
            h.respond_volume(2, Ok(&volume)),
            Ok(pdu::encode_io_completion(
                1,
                2,
                STATUS_SUCCESS,
                &pdu::length_prefixed(&buffer, true)
            ))
        );
        assert_eq!(
            sent(&h.process(&query(3, root, pdu::IRP_MJ_QUERY_VOLUME_INFORMATION, 2))),
            vec![pdu::encode_io_completion(1, 3, STATUS_NOT_SUPPORTED, &[0; 4]).as_slice()]
        );

        let class = pdu::FILE_BASIC_INFORMATION;
        let outputs = h.process(&query(4, root, pdu::IRP_MJ_QUERY_INFORMATION, class));
        assert_eq!(
            asked(&outputs),
            &DriveRequest::QueryInformation { file_id: root }
        );
        let info = file("x", 0, true).info;
        let buffer = pdu::encode_file_information(class, &info).unwrap();
        assert_eq!(
            h.respond_information(4, Ok(&info)),
            Ok(pdu::encode_io_completion(
                1,
                4,
                STATUS_SUCCESS,
                &pdu::length_prefixed(&buffer, false)
            ))
        );
        assert_eq!(
            sent(&h.process(&query(5, root, pdu::IRP_MJ_QUERY_INFORMATION, 99))),
            vec![pdu::encode_io_completion(1, 5, STATUS_NOT_SUPPORTED, &[0; 4]).as_slice()]
        );
        assert_eq!(
            sent(&h.process(&query(6, 999, pdu::IRP_MJ_QUERY_INFORMATION, class))),
            vec![pdu::encode_io_completion(1, 6, STATUS_UNSUCCESSFUL, &[0; 4]).as_slice()]
        );
    }

    /// A first Query Directory asks the host for the directory's entries; those the pattern
    /// matches come out one per query, then `STATUS_NO_MORE_FILES`.
    #[test]
    fn a_directory_is_listed_one_entry_at_a_time() {
        let mut h = ready();
        let dir = open_directory(&mut h, 1, "\\sub");
        let class = pdu::FILE_BOTH_DIRECTORY_INFORMATION;
        let outputs = h.process(&query_directory(2, dir, class, Some("\\sub\\*.txt")));
        assert_eq!(
            asked(&outputs),
            &DriveRequest::ListDirectory {
                file_id: dir,
                path: vec!["sub".to_string()]
            }
        );
        let entries = vec![
            file("a.txt", 3, false),
            file("b.bin", 4, false),
            file("C.TXT", 5, false),
        ];
        let entry = |e: &DirectoryEntry| {
            pdu::encode_io_completion(
                1,
                0,
                STATUS_SUCCESS,
                &pdu::length_prefixed(
                    &pdu::encode_directory_entry(class, &e.name, &e.info).unwrap(),
                    true,
                ),
            )
        };
        let with_id = |mut m: Vec<u8>, id: u32| {
            m[8..12].copy_from_slice(&id.to_le_bytes());
            m
        };
        assert_eq!(
            h.respond_listing(2, Ok(entries.clone())),
            Ok(with_id(entry(&entries[0]), 2))
        );
        assert_eq!(
            sent(&h.process(&query_directory(3, dir, class, None))),
            vec![with_id(entry(&entries[2]), 3).as_slice()]
        );
        assert_eq!(
            sent(&h.process(&query_directory(4, dir, class, None))),
            vec![pdu::encode_io_completion(1, 4, STATUS_NO_MORE_FILES, &[0; 5]).as_slice()]
        );
        h.process(&query_directory(5, dir, class, Some("\\sub\\nothing")));
        assert_eq!(
            h.respond_listing(5, Ok(entries)),
            Ok(pdu::encode_io_completion(
                1,
                5,
                pdu::STATUS_NO_SUCH_FILE,
                &[0; 5]
            ))
        );
    }

    /// A Query Directory on a file, with an unimplemented class, or a change notification is
    /// refused without the host.
    #[test]
    fn a_directory_query_the_host_cannot_answer_is_refused() {
        let mut h = ready();
        h.process(&create(1, pdu::FILE_OPEN, 0, "\\a.txt"));
        h.respond_open(1, Ok(Opened::File)).unwrap();
        let DriveRequest::Open { file_id, .. } =
            *asked(&h.process(&create(2, pdu::FILE_OPEN, 0, "\\b")))
        else {
            panic!("expected an Open");
        };
        h.respond_open(2, Ok(Opened::Directory)).unwrap();
        let file_id_a = h.files[0].file_id;
        assert_eq!(
            sent(&h.process(&query_directory(3, file_id_a, 1, Some("\\a.txt\\*")))),
            vec![pdu::encode_io_completion(1, 3, STATUS_NOT_A_DIRECTORY, &[0; 5]).as_slice()]
        );
        assert_eq!(
            sent(&h.process(&query_directory(4, file_id, 0x3F, Some("\\b\\*")))),
            vec![pdu::encode_io_completion(1, 4, STATUS_NOT_SUPPORTED, &[0; 5]).as_slice()]
        );
        let mut notify = header(
            file_id,
            5,
            pdu::IRP_MJ_DIRECTORY_CONTROL,
            pdu::IRP_MN_NOTIFY_CHANGE_DIRECTORY,
        );
        notify.extend_from_slice(&[0; 32]);
        assert_eq!(
            sent(&h.process(&notify)),
            vec![pdu::encode_io_completion(1, 5, STATUS_NOT_SUPPORTED, &[0; 5]).as_slice()]
        );
    }

    /// Answers pair by `CompletionId` in any order; one of the wrong kind is refused and the
    /// request keeps waiting.
    #[test]
    fn answers_pair_by_completion_id_in_any_order() {
        let mut h = ready();
        h.process(&create(1, pdu::FILE_OPEN, 0, "\\a"));
        h.process(&create(2, pdu::FILE_OPEN, 0, "\\b"));
        assert_eq!(
            h.respond_volume(2, Err(STATUS_UNSUCCESSFUL)),
            Err(RespondError::WrongKind)
        );
        assert!(h.respond_open(2, Ok(Opened::File)).is_ok());
        assert!(h.respond_open(1, Ok(Opened::File)).is_ok());
        assert_eq!(h.files.len(), 2);
    }

    /// Requests past the bound are refused and the session goes on; so is a `CompletionId`
    /// already waiting.
    #[test]
    fn waiting_requests_are_bounded() {
        let mut h = ready();
        for id in 0..MAX_PENDING_REQUESTS as u32 {
            assert!(matches!(
                asked(&h.process(&create(id, pdu::FILE_OPEN, 0, "\\a"))),
                DriveRequest::Open { .. }
            ));
        }
        let over = MAX_PENDING_REQUESTS as u32;
        assert_eq!(
            sent(&h.process(&create(over, pdu::FILE_OPEN, 0, "\\a"))),
            vec![
                pdu::encode_io_completion(1, over, STATUS_INSUFFICIENT_RESOURCES, &[0; 5])
                    .as_slice()
            ]
        );
        h.respond_open(0, Ok(Opened::File)).unwrap();
        assert_eq!(
            sent(&h.process(&create(1, pdu::FILE_OPEN, 0, "\\a"))),
            vec![pdu::encode_io_completion(1, 1, STATUS_UNSUCCESSFUL, &[0; 5]).as_slice()]
        );
        assert!(matches!(
            asked(&h.process(&create(over, pdu::FILE_OPEN, 0, "\\a"))),
            DriveRequest::Open { .. }
        ));
    }

    /// Open files are bounded too: a Create past the bound is refused without the host.
    #[test]
    fn open_files_are_bounded() {
        let mut h = ready();
        for id in 0..MAX_OPEN_FILES as u32 {
            h.process(&create(id, pdu::FILE_OPEN, 0, "\\a"));
            h.respond_open(id, Ok(Opened::File)).unwrap();
        }
        assert_eq!(
            sent(&h.process(&create(9999, pdu::FILE_OPEN, 0, "\\a"))),
            vec![
                pdu::encode_io_completion(1, 9999, STATUS_TOO_MANY_OPENED_FILES, &[0; 5])
                    .as_slice()
            ]
        );
    }

    /// A Close forgets the file, cancels what the host still owes about it, and tells the host.
    #[test]
    fn a_close_cancels_what_is_owed_and_tells_the_host() {
        let mut h = ready();
        let dir = open_directory(&mut h, 1, "\\d");
        h.process(&query(
            2,
            dir,
            pdu::IRP_MJ_QUERY_INFORMATION,
            pdu::FILE_BASIC_INFORMATION,
        ));
        let outputs = h.process(&close(3, dir));
        assert_eq!(
            outputs,
            vec![
                DeviceRedirectionOutput::Send(pdu::encode_io_completion(
                    1,
                    2,
                    STATUS_CANCELLED,
                    &[0; 4]
                )),
                DeviceRedirectionOutput::FileClosed {
                    device_id: 1,
                    file_id: dir,
                    delete: false
                },
                DeviceRedirectionOutput::Send(pdu::encode_io_completion(
                    1,
                    3,
                    STATUS_SUCCESS,
                    &[0; 4]
                )),
            ]
        );
        assert_eq!(
            h.respond_information(2, Ok(&FileInformation::default())),
            Err(RespondError::NotRequested)
        );
        assert_eq!(
            sent(&h.process(&close(4, dir))),
            vec![pdu::encode_io_completion(1, 4, STATUS_UNSUCCESSFUL, &[0; 4]).as_slice()]
        );
    }

    /// A new Server Announce, like the channel ending, closes every file for the host.
    #[test]
    fn starting_over_closes_every_file() {
        let mut h = ready();
        let dir = open_directory(&mut h, 1, "\\d");
        let outputs = h.process(&server_announce(0x0d, 9));
        assert_eq!(
            outputs[0],
            DeviceRedirectionOutput::FileClosed {
                device_id: 1,
                file_id: dir,
                delete: false
            }
        );
        assert!(h.files.is_empty());

        let mut h = ready();
        let dir = open_directory(&mut h, 1, "\\d");
        let outputs = h.process(&[0x72, 0x44, 0x99, 0x99]);
        assert_eq!(
            outputs[0],
            DeviceRedirectionOutput::FileClosed {
                device_id: 1,
                file_id: dir,
                delete: false
            }
        );
    }

    #[test]
    fn patterns_match_as_windows_does() {
        let m =
            |pattern: &str, name: &str| matches_pattern(&pattern.chars().collect::<Vec<_>>(), name);
        assert!(m("*", "anything.txt"));
        assert!(m("*", ""));
        assert!(m("*.txt", "Notes.TXT"));
        assert!(!m("*.txt", "notes.txt.bak"));
        assert!(m("a?c", "abc"));
        assert!(!m("a?c", "ac"));
        assert!(m("exact", "EXACT"));
        assert!(!m("exact", "exactly"));
        // DOS_STAR stops at the name's last dot; DOS_QM and DOS_DOT may match nothing there.
        assert!(m("<.txt", "a.b.txt"));
        assert!(!m("<.txt", "a.b.txt.bak"));
        assert!(m("<", "no-dot"));
        assert!(m("ab>>", "ab"));
        assert!(m("a>\"txt", "a.txt"));
        assert!(m("a\"", "a"));
    }

    /// A server-sized pattern costs one pass per character, not one per reachable position.
    #[test]
    fn a_long_pattern_is_matched_in_linear_passes() {
        let pattern: Vec<char> = "*<".repeat(200_000).chars().collect();
        let name = "x".repeat(255);
        let start = std::time::Instant::now();
        assert!(matches_pattern(&pattern, &name));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
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
