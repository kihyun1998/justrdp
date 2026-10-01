//! The clipboard channel (MS-RDPECLIP) as a sans-IO helper the host drives: the
//! initialization sequence (1.3.2.1), Format Lists both ways, and Format Data Requests and
//! Responses both ways, files the server copied, fetched with File Contents Requests under a
//! clipboard lock, and files the host copied, served to the server's File Contents Requests from
//! the list each server lock pins. The session never interprets `cliprdr` bytes: the host
//! requests the channel with [`channel_def`], feeds each `SessionOutput::ChannelData` message on
//! it to [`Clipboard::process`], and passes every [`ClipboardOutput::Send`] to
//! `SessionStateMachine::send_channel`.

use std::collections::VecDeque;
use std::sync::Arc;

use justrdp_pdu::DecodeError;
use justrdp_pdu::cliprdr::{
    self as pdu, CB_CAN_LOCK_CLIPDATA, CB_CAPS_VERSION_2, CB_FILECLIP_NO_FILE_PATHS,
    CB_HUGE_FILE_SUPPORT_ENABLED, CB_STREAM_FILECLIP_ENABLED, CB_USE_LONG_FORMAT_NAMES,
    ClipboardPdu, FileContentsOp, FileContentsRequest, FileDescriptor, Format, GeneralCapability,
};
use justrdp_pdu::gcc::{CHANNEL_OPTION_INITIALIZED, CHANNEL_OPTION_SHOW_PROTOCOL, ChannelDef};

/// The options the clipboard channel is requested with. `CHANNEL_OPTION_SHOW_PROTOCOL` makes
/// every chunk sent on it carry `CHANNEL_FLAG_SHOW_PROTOCOL`.
pub const CHANNEL_OPTIONS: u32 = CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_SHOW_PROTOCOL;

/// The `generalFlags` this helper implements and so advertises.
pub const ADVERTISED_FLAGS: u32 = CB_USE_LONG_FORMAT_NAMES
    | CB_STREAM_FILECLIP_ENABLED
    | CB_FILECLIP_NO_FILE_PATHS
    | CB_CAN_LOCK_CLIPDATA
    | CB_HUGE_FILE_SUPPORT_ENABLED;

/// The `generalFlags` of file transfer: [`ADVERTISED_FLAGS`] less these is what
/// [`Clipboard::without_file_transfer`] advertises.
pub const FILE_TRANSFER_FLAGS: u32 = CB_STREAM_FILECLIP_ENABLED
    | CB_FILECLIP_NO_FILE_PATHS
    | CB_CAN_LOCK_CLIPDATA
    | CB_HUGE_FILE_SUPPORT_ENABLED;

/// The most server locks kept at once; a Lock Clipboard Data past it is not kept.
pub const MAX_SERVER_LOCKS: usize = 100;

/// The most Format Data Requests and File Contents Requests each kept waiting for the host; a
/// request past it is answered with a failure.
pub const MAX_PENDING_SERVER_REQUESTS: usize = 100;

/// The ID this side gives `FileGroupDescriptorW`, or the next one the host's formats leave free.
const LOCAL_FILE_LIST_FORMAT: u32 = 0xC0FE;

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
    /// The server answered [`Clipboard::request_file_list`] with the files it copied. Their
    /// contents are fetched with [`Clipboard::request_file_contents`] under `clip_data_id`, and
    /// the lock is released with [`Clipboard::release`].
    FileList {
        /// The lock that keeps these files available, if both sides can lock.
        clip_data_id: Option<u32>,
        /// The files.
        files: Vec<FileDescriptor>,
    },
    /// The server's file list failed, and its lock has been released. `error` is `None` when the
    /// server answered with a failure, and says why otherwise: the list did not decode, or it
    /// named a path outside the paste target.
    FileListFailed {
        /// Why the list was refused, when this side refused it.
        error: Option<DecodeError>,
    },
    /// The server answered a size request. `None` is a failure.
    FileSize {
        /// The request's `streamId`.
        stream_id: u32,
        /// The file's size.
        size: Option<u64>,
    },
    /// The server answered a range request. `None` is a failure.
    FileRange {
        /// The request's `streamId`.
        stream_id: u32,
        /// The bytes, at most the length asked for.
        data: Option<Vec<u8>>,
    },
    /// The server asked for the size or a range of file `index` of the host's list `list_id`.
    /// The host answers with [`Clipboard::respond_file_size`] or
    /// [`Clipboard::respond_file_range`].
    FileContentsRequested {
        /// The request's `streamId`, which the answer names.
        stream_id: u32,
        /// The [`Announcement::list_id`] the file belongs to.
        list_id: u32,
        /// The file's position in that list.
        index: u32,
        /// What is asked for.
        op: FileContentsOp,
    },
    /// The host's file list `list_id` is neither on its clipboard nor held by a server lock,
    /// so no request for it will be handed to the host again. A request already handed over
    /// still owes its answer, a failure if the host has let go of the file.
    FilesReleased {
        /// The [`Announcement::list_id`] released.
        list_id: u32,
    },
}

/// Why [`Clipboard::request_file_contents`] sent nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRequestError {
    /// The two sides did not both advertise `CB_STREAM_FILECLIP_ENABLED`.
    NotNegotiated,
    /// `clip_data_id` names no lock this side holds.
    UnknownLock {
        /// The id asked for.
        clip_data_id: u32,
    },
    /// The range starts at 2 GiB or later, which needs `CB_HUGE_FILE_SUPPORT_ENABLED` on both
    /// sides.
    TooFar,
}

/// Why [`Clipboard::respond_file_size`] or [`Clipboard::respond_file_range`] sent nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRespondError {
    /// No server request with this `streamId` is waiting for the host.
    NotRequested,
    /// The request asked for the other of size and range.
    WrongKind,
    /// The range is longer than the request asked for.
    TooLong,
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
    /// The server's current Format List names no `FileGroupDescriptorW`.
    NoFileList,
}

/// What [`Clipboard::request_file_list`] sends, and the lock it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListRequest {
    /// The lock taken for the files, if both sides can lock. The host releases it with
    /// [`Clipboard::release`]; a failed list releases it by itself.
    pub clip_data_id: Option<u32>,
    /// The messages to send, in order: the Lock Clipboard Data, if any, then the Format Data
    /// Request.
    pub messages: Vec<Vec<u8>>,
}

/// What [`Clipboard::announce`] or [`Clipboard::announce_files`] announced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    /// The Format List to send, `None` before the server's Monitor Ready.
    pub message: Option<Vec<u8>>,
    /// The id the server's File Contents Requests for the announced files arrive under; `None`
    /// when no files were announced.
    pub list_id: Option<u32>,
    /// A file list this announcement replaced and no server lock holds, which the host no
    /// longer serves.
    pub released: Option<u32>,
}

/// Why [`Clipboard::announce_files`] announced nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAnnounceError {
    /// The server's Monitor Ready has not arrived, or the two sides did not both advertise
    /// `CB_STREAM_FILECLIP_ENABLED`.
    NotNegotiated,
    /// File `index` has a name that is not a relative path inside the paste target, holds a
    /// NUL, or is longer than the 259 UTF-16 code units a descriptor holds.
    BadName {
        /// The file's position in the list.
        index: usize,
    },
    /// File `index` is larger than 4,294,967,295 bytes, which needs
    /// `CB_HUGE_FILE_SUPPORT_ENABLED` on both sides.
    TooLarge {
        /// The file's position in the list.
        index: usize,
    },
}

/// A Format Data Response this side owes the server, in the order the requests came.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Owed {
    /// The host answers it.
    Host,
    /// Data the helper answered with, sent once every answer before it has gone out.
    Ready(Arc<[u8]>),
    /// This many failures in a row, sent once every answer before them has gone out.
    Refused(usize),
}

/// Files the host announced.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AnnouncedList {
    id: u32,
    /// How many files the list holds.
    count: usize,
    /// The list as `CLIPRDR_FILELIST` data.
    encoded: Arc<[u8]>,
}

/// The client side of one clipboard channel.
#[derive(Debug, Clone, Default)]
pub struct Clipboard {
    /// The host chose not to offer file transfer.
    without_file_transfer: bool,
    server_flags: u32,
    general_flags: u32,
    ready: bool,
    local_formats: Vec<Format>,
    local_list_refused: bool,
    remote_format_ids: Vec<u32>,
    requested: Option<u32>,
    /// `Some(lock)` while `requested` is a [`Clipboard::request_file_list`].
    requested_file_list: Option<Option<u32>>,
    owed: VecDeque<Owed>,
    /// The ID of `FileGroupDescriptorW` in the server's latest Format List.
    file_list_format: Option<u32>,
    /// Every lock taken and not yet released.
    held_locks: Vec<u32>,
    last_clip_data_id: u32,
    /// File Contents Requests waiting for their response.
    file_requests: Vec<(u32, FileContentsOp)>,
    last_stream_id: u32,
    /// Every file list the host announced that is still served.
    announced: Vec<AnnouncedList>,
    /// The id of the file list on the host's clipboard now.
    current_files: Option<u32>,
    /// The ID of `FileGroupDescriptorW` in this side's latest Format List.
    local_file_list_format: Option<u32>,
    last_list_id: u32,
    /// Server File Contents Requests the host has not answered.
    serving: Vec<(u32, FileContentsOp)>,
    /// Each server lock's `clipDataId` and the host file list it holds.
    server_locks: Vec<(u32, u32)>,
}

impl Clipboard {
    /// A clipboard waiting for the server's Monitor Ready, offering file transfer.
    pub fn new() -> Self {
        Self::default()
    }

    /// A clipboard waiting for the server's Monitor Ready that does not offer file transfer:
    /// none of [`FILE_TRANSFER_FLAGS`] is advertised, so the file operations report
    /// `NotNegotiated` as they do against a server without streaming.
    pub fn without_file_transfer() -> Self {
        Self {
            without_file_transfer: true,
            ..Self::default()
        }
    }

    /// The `generalFlags` both sides advertised, zero until the server's Monitor Ready.
    pub fn general_flags(&self) -> u32 {
        self.general_flags
    }

    /// Announce the formats now on the host's clipboard. Before the server's Monitor Ready they
    /// are kept for the initial Format List and no message is returned; after it, the Format
    /// List to send is.
    pub fn announce(&mut self, formats: Vec<Format>) -> Announcement {
        let released = self.replace_current_files(None);
        self.local_file_list_format = None;
        self.local_formats = formats;
        self.local_list_refused = false;
        Announcement {
            message: self.ready.then(|| self.local_format_list()),
            list_id: None,
            released,
        }
    }

    /// Announce files on the host's clipboard, with `formats` beside them. The helper adds
    /// `FileGroupDescriptorW` to the Format List and answers the server's request for it; the
    /// host serves the files' contents through [`ClipboardOutput::FileContentsRequested`].
    pub fn announce_files(
        &mut self,
        files: Vec<FileDescriptor>,
        mut formats: Vec<Format>,
    ) -> Result<Announcement, FileAnnounceError> {
        if !self.ready || self.general_flags & CB_STREAM_FILECLIP_ENABLED == 0 {
            return Err(FileAnnounceError::NotNegotiated);
        }
        if let Some(index) = files.iter().position(|f| {
            !pdu::is_contained_file_name(&f.name)
                || f.name.contains('\0')
                || f.name.encode_utf16().count() > pdu::FILE_NAME_MAX_UNITS
        }) {
            return Err(FileAnnounceError::BadName { index });
        }
        if self.general_flags & CB_HUGE_FILE_SUPPORT_ENABLED == 0
            && let Some(index) = files
                .iter()
                .position(|f| f.size.is_some_and(|size| size > u64::from(u32::MAX)))
        {
            return Err(FileAnnounceError::TooLarge { index });
        }
        let mut format_id = LOCAL_FILE_LIST_FORMAT;
        while formats.iter().any(|f| f.id == format_id) {
            format_id += 1;
        }
        formats.push(Format {
            id: format_id,
            name: pdu::FILE_GROUP_DESCRIPTOR_W.to_string(),
        });
        let announced = &self.announced;
        let list_id = next_id(&mut self.last_list_id, |id| {
            announced.iter().any(|list| list.id == id)
        });
        self.announced.push(AnnouncedList {
            id: list_id,
            count: files.len(),
            encoded: pdu::encode_file_list(&files).into(),
        });
        let released = self.replace_current_files(Some(list_id));
        self.local_file_list_format = Some(format_id);
        self.local_formats = formats;
        self.local_list_refused = false;
        Ok(Announcement {
            message: Some(self.local_format_list()),
            list_id: Some(list_id),
            released,
        })
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
        self.requested_file_list = None;
        Ok(pdu::encode_format_data_request(format_id))
    }

    /// Lock the files on the server's clipboard, when both sides can lock, and request their
    /// list. The answer arrives as [`ClipboardOutput::FileList`] or
    /// [`ClipboardOutput::FileListFailed`].
    pub fn request_file_list(&mut self) -> Result<FileListRequest, RequestError> {
        if let Some(format_id) = self.requested {
            return Err(RequestError::Pending { format_id });
        }
        let format_id = self.file_list_format.ok_or(RequestError::NoFileList)?;
        let mut messages = Vec::with_capacity(2);
        let clip_data_id = self.lock().map(|(id, lock)| {
            messages.push(lock);
            id
        });
        messages.push(pdu::encode_format_data_request(format_id));
        self.requested = Some(format_id);
        self.requested_file_list = Some(clip_data_id);
        Ok(FileListRequest {
            clip_data_id,
            messages,
        })
    }

    /// The File Contents Request for file `index` of a [`ClipboardOutput::FileList`], under
    /// the list's `clip_data_id`. Returns the request's `streamId` and the message to send; the
    /// answer arrives as [`ClipboardOutput::FileSize`] or [`ClipboardOutput::FileRange`].
    pub fn request_file_contents(
        &mut self,
        index: u32,
        op: FileContentsOp,
        clip_data_id: Option<u32>,
    ) -> Result<(u32, Vec<u8>), FileRequestError> {
        if self.general_flags & CB_STREAM_FILECLIP_ENABLED == 0 {
            return Err(FileRequestError::NotNegotiated);
        }
        if let Some(clip_data_id) = clip_data_id
            && !self.held_locks.contains(&clip_data_id)
        {
            return Err(FileRequestError::UnknownLock { clip_data_id });
        }
        if let FileContentsOp::Range { position, .. } = op
            && self.general_flags & CB_HUGE_FILE_SUPPORT_ENABLED == 0
            && position >= 1 << 31
        {
            return Err(FileRequestError::TooFar);
        }
        let stream_id = next_id(&mut self.last_stream_id, |id| {
            self.file_requests.iter().any(|(pending, _)| *pending == id)
        });
        self.file_requests.push((stream_id, op));
        let request = FileContentsRequest {
            stream_id,
            index,
            op,
            clip_data_id,
        };
        Ok((stream_id, pdu::encode_file_contents_request(&request)))
    }

    /// Stop waiting for the answer to the File Contents Request `stream_id`, returning whether
    /// one was waiting. A response that arrives later is skipped.
    pub fn cancel_file_request(&mut self, stream_id: u32) -> bool {
        let before = self.file_requests.len();
        self.file_requests.retain(|(id, _)| *id != stream_id);
        self.file_requests.len() != before
    }

    /// The Unlock Clipboard Data for `clip_data_id`, once the host is done with its files.
    /// `None` when this side holds no such lock.
    pub fn release(&mut self, clip_data_id: u32) -> Option<Vec<u8>> {
        let at = self.held_locks.iter().position(|&id| id == clip_data_id)?;
        self.held_locks.remove(at);
        Some(pdu::encode_unlock_clip_data(clip_data_id))
    }

    /// The Format Data Responses owed now that the host answers the oldest
    /// [`ClipboardOutput::DataRequested`]: `Some` sends the data, `None` a failure. Refusals
    /// queued behind that request follow it. Empty when no request is waiting.
    pub fn respond(&mut self, data: Option<&[u8]>) -> Vec<Vec<u8>> {
        if self.owed.pop_front() != Some(Owed::Host) {
            return Vec::new();
        }
        let mut out = vec![pdu::encode_format_data_response(data)];
        while self.owed.front().is_some_and(|owed| *owed != Owed::Host) {
            match self.owed.pop_front() {
                Some(Owed::Ready(answer)) => {
                    out.push(pdu::encode_format_data_response(Some(&answer)))
                }
                Some(Owed::Refused(count)) => out.extend(
                    core::iter::repeat_with(|| pdu::encode_format_data_response(None)).take(count),
                ),
                _ => {}
            }
        }
        out
    }

    /// The File Contents Response carrying the size of the file a server size request named,
    /// or a failure for `None`.
    pub fn respond_file_size(
        &mut self,
        stream_id: u32,
        size: Option<u64>,
    ) -> Result<Vec<u8>, FileRespondError> {
        self.take_serving(stream_id, |op| match op {
            FileContentsOp::Size => Ok(()),
            FileContentsOp::Range { .. } => Err(FileRespondError::WrongKind),
        })?;
        let size = size.map(u64::to_le_bytes);
        Ok(pdu::encode_file_contents_response(
            stream_id,
            size.as_ref().map(|s| s.as_slice()),
        ))
    }

    /// The File Contents Response carrying the bytes a server range request asked for, fewer
    /// at the end of the file, or a failure for `None`.
    pub fn respond_file_range(
        &mut self,
        stream_id: u32,
        data: Option<&[u8]>,
    ) -> Result<Vec<u8>, FileRespondError> {
        self.take_serving(stream_id, |op| match op {
            FileContentsOp::Range { len, .. } if data.is_some_and(|d| d.len() > len as usize) => {
                Err(FileRespondError::TooLong)
            }
            FileContentsOp::Range { .. } => Ok(()),
            FileContentsOp::Size => Err(FileRespondError::WrongKind),
        })?;
        Ok(pdu::encode_file_contents_response(stream_id, data))
    }

    /// Stop waiting for the answer to [`Clipboard::request`] or
    /// [`Clipboard::request_file_list`], returning the format it asked for. A response that
    /// arrives later is skipped; a file list's lock stays held until the host releases it.
    pub fn cancel_request(&mut self) -> Option<u32> {
        self.requested_file_list = None;
        self.requested.take()
    }

    /// Make `list_id` the host's current file list, returning the one it replaced when no
    /// server lock holds it.
    fn replace_current_files(&mut self, list_id: Option<u32>) -> Option<u32> {
        let old = core::mem::replace(&mut self.current_files, list_id)?;
        self.release_if_unheld(old)
    }

    /// Forget file list `list_id` when it is neither current nor held by a server lock,
    /// returning it.
    fn release_if_unheld(&mut self, list_id: u32) -> Option<u32> {
        let held = self.current_files == Some(list_id)
            || self.server_locks.iter().any(|&(_, list)| list == list_id);
        if held {
            return None;
        }
        self.announced.retain(|list| list.id != list_id);
        Some(list_id)
    }

    /// A server Lock Clipboard Data: `clip_data_id` holds the host's current file list, if
    /// there is one (3.1.5.3.2).
    fn server_lock(&mut self, clip_data_id: u32) -> Vec<ClipboardOutput> {
        let Some(current) = self.current_files else {
            tracing::debug!(target: "rdp_cliprdr", clip_data_id, "server lock with no host files");
            return Vec::new();
        };
        let outputs = self.server_unlock(clip_data_id);
        if self.server_locks.len() >= MAX_SERVER_LOCKS {
            tracing::warn!(target: "rdp_cliprdr", clip_data_id, "server lock not kept: too many held");
            return outputs;
        }
        self.server_locks.push((clip_data_id, current));
        outputs
    }

    /// A server Unlock Clipboard Data: `clip_data_id` holds nothing any more (3.1.5.3.4).
    fn server_unlock(&mut self, clip_data_id: u32) -> Vec<ClipboardOutput> {
        let Some(at) = self
            .server_locks
            .iter()
            .position(|&(id, _)| id == clip_data_id)
        else {
            return Vec::new();
        };
        let (_, list_id) = self.server_locks.remove(at);
        self.release_if_unheld(list_id)
            .map(|list_id| ClipboardOutput::FilesReleased { list_id })
            .into_iter()
            .collect()
    }

    /// Remove the server request `stream_id` once `fits` accepts the answer for its op.
    fn take_serving(
        &mut self,
        stream_id: u32,
        fits: impl FnOnce(FileContentsOp) -> Result<(), FileRespondError>,
    ) -> Result<(), FileRespondError> {
        let at = self
            .serving
            .iter()
            .position(|(id, _)| *id == stream_id)
            .ok_or(FileRespondError::NotRequested)?;
        fits(self.serving[at].1)?;
        self.serving.remove(at);
        Ok(())
    }

    /// A server File Contents Request for a file the host announced, handed to the host, or
    /// answered with a failure when it names no such file.
    fn serve_file_contents(&mut self, request: FileContentsRequest) -> Vec<ClipboardOutput> {
        if self.local_list_refused {
            return refuse_file_contents(request.stream_id, "Format List refused");
        }
        if self.serving.len() >= MAX_PENDING_SERVER_REQUESTS {
            return refuse_file_contents(request.stream_id, "too many waiting");
        }
        if self.serving.iter().any(|(id, _)| *id == request.stream_id) {
            return refuse_file_contents(request.stream_id, "streamId already waiting");
        }
        let list_id = match request.clip_data_id {
            Some(clip_data_id) => self
                .server_locks
                .iter()
                .find(|&&(id, _)| id == clip_data_id)
                .map(|&(_, list)| list),
            None => self.current_files,
        };
        let list = list_id.and_then(|id| self.announced.iter().find(|list| list.id == id));
        let Some(list) = list.filter(|list| (request.index as usize) < list.count) else {
            return refuse_file_contents(request.stream_id, "no such file");
        };
        self.serving.push((request.stream_id, request.op));
        vec![ClipboardOutput::FileContentsRequested {
            stream_id: request.stream_id,
            list_id: list.id,
            index: request.index,
            op: request.op,
        }]
    }

    /// Take a lock on the server's current clipboard, when both sides can lock.
    fn lock(&mut self) -> Option<(u32, Vec<u8>)> {
        if self.general_flags & CB_CAN_LOCK_CLIPDATA == 0 {
            return None;
        }
        let held = &self.held_locks;
        let id = next_id(&mut self.last_clip_data_id, |id| held.contains(&id));
        self.held_locks.push(id);
        Some((id, pdu::encode_lock_clip_data(id)))
    }

    /// The answer to a Format Data Response: a file list when the request was
    /// [`Clipboard::request_file_list`], the data otherwise.
    fn format_data(&mut self, format_id: u32, data: Option<Vec<u8>>) -> Vec<ClipboardOutput> {
        let Some(clip_data_id) = self.requested_file_list.take() else {
            return vec![ClipboardOutput::FormatData { format_id, data }];
        };
        match data.as_deref().map(pdu::decode_file_list) {
            Some(Ok(files)) => vec![ClipboardOutput::FileList {
                clip_data_id,
                files,
            }],
            Some(Err(error)) => self.file_list_failed(clip_data_id, Some(error)),
            None => self.file_list_failed(clip_data_id, None),
        }
    }

    /// A failed file list, with its lock released.
    fn file_list_failed(
        &mut self,
        clip_data_id: Option<u32>,
        error: Option<DecodeError>,
    ) -> Vec<ClipboardOutput> {
        tracing::warn!(target: "rdp_cliprdr", ?error, "server file list failed");
        let mut outputs = Vec::with_capacity(2);
        if let Some(unlock) = clip_data_id.and_then(|id| self.release(id)) {
            outputs.push(ClipboardOutput::Send(unlock));
        }
        outputs.push(ClipboardOutput::FileListFailed { error });
        outputs
    }

    /// Answer a server request with a failure, after every answer still owed before it.
    fn refuse_request(&mut self) -> Vec<ClipboardOutput> {
        match self.owed.back_mut() {
            None => vec![ClipboardOutput::Send(pdu::encode_format_data_response(
                None,
            ))],
            Some(Owed::Refused(count)) => {
                *count = count.saturating_add(1);
                Vec::new()
            }
            Some(_) => {
                self.owed.push_back(Owed::Refused(1));
                Vec::new()
            }
        }
    }

    /// Answer a server request with `answer`, after every answer still owed before it, or with
    /// a failure when `MAX_PENDING_SERVER_REQUESTS` are owed.
    fn answer_request(&mut self, answer: Option<Arc<[u8]>>) -> Vec<ClipboardOutput> {
        let Some(answer) = answer else {
            return self.refuse_request();
        };
        if self.owed.is_empty() {
            vec![ClipboardOutput::Send(pdu::encode_format_data_response(
                Some(&answer),
            ))]
        } else if self.owed_full() {
            self.refuse_request()
        } else {
            self.owed.push_back(Owed::Ready(answer));
            Vec::new()
        }
    }

    /// Whether `MAX_PENDING_SERVER_REQUESTS` answers are owed, so the request in hand is refused.
    fn owed_full(&self) -> bool {
        if self.owed.len() >= MAX_PENDING_SERVER_REQUESTS {
            tracing::warn!(target: "rdp_cliprdr", "Format Data Request refused: too many waiting");
            return true;
        }
        false
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
                match self.requested_file_list.take() {
                    Some(clip_data_id) => Ok(self.file_list_failed(clip_data_id, Some(error))),
                    None => Err(error),
                }
            }
            // A request whose streamId can be read is answered, as a well-formed one would be.
            Some(pdu::CB_FILECONTENTS_REQUEST) => match stream_id(message) {
                Some(stream_id) => Ok(vec![ClipboardOutput::Send(
                    pdu::encode_file_contents_response(stream_id, None),
                )]),
                None => Err(error),
            },
            Some(pdu::CB_FILECONTENTS_RESPONSE) => {
                if let Some(stream_id) = stream_id(message) {
                    self.cancel_file_request(stream_id);
                }
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
        let padding = pdu::padding(message);
        if padding != 0 {
            if message[message.len() - padding..].iter().all(|&b| b == 0) {
                tracing::debug!(target: "rdp_cliprdr", padding, "clipboard PDU padding skipped");
            } else {
                tracing::warn!(target: "rdp_cliprdr", padding, "nonzero bytes after a clipboard PDU skipped");
            }
        }
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
                // A new initialization sequence: nothing the old one asked for, locked or
                // announced as files stands.
                let mut outputs: Vec<_> = self
                    .announced
                    .iter()
                    .map(|list| ClipboardOutput::FilesReleased { list_id: list.id })
                    .collect();
                let mut local_formats = core::mem::take(&mut self.local_formats);
                local_formats.retain(|f| Some(f.id) != self.local_file_list_format);
                *self = Self {
                    without_file_transfer: self.without_file_transfer,
                    server_flags: self.server_flags,
                    local_formats,
                    last_clip_data_id: self.last_clip_data_id,
                    last_stream_id: self.last_stream_id,
                    last_list_id: self.last_list_id,
                    ..Self::default()
                };
                let advertised = if self.without_file_transfer {
                    ADVERTISED_FLAGS & !FILE_TRANSFER_FLAGS
                } else {
                    ADVERTISED_FLAGS
                };
                self.general_flags = advertised & self.server_flags;
                self.ready = true;
                let caps = pdu::encode_capabilities(GeneralCapability {
                    version: CB_CAPS_VERSION_2,
                    general_flags: self.general_flags,
                });
                outputs.push(ClipboardOutput::Send(caps));
                outputs.push(ClipboardOutput::Send(self.local_format_list()));
                Ok(outputs)
            }
            ClipboardPdu::FormatList(formats) => {
                self.remote_format_ids = formats.iter().map(|f| f.id).collect();
                self.file_list_format = formats
                    .iter()
                    .find(|f| f.name == pdu::FILE_GROUP_DESCRIPTOR_W)
                    .map(|f| f.id);
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
                if Some(format_id) == self.local_file_list_format {
                    let list = self
                        .current_files
                        .and_then(|id| self.announced.iter().find(|list| list.id == id))
                        .map(|list| list.encoded.clone());
                    return Ok(self.answer_request(list));
                }
                if self.owed_full() {
                    return Ok(self.refuse_request());
                }
                self.owed.push_back(Owed::Host);
                Ok(vec![ClipboardOutput::DataRequested { format_id }])
            }
            ClipboardPdu::FormatDataResponse { data } => match self.requested.take() {
                Some(format_id) => Ok(self.format_data(format_id, data)),
                None => {
                    tracing::warn!(target: "rdp_cliprdr", "Format Data Response nothing asked for");
                    Ok(Vec::new())
                }
            },
            ClipboardPdu::FileContentsResponse { stream_id, data } => {
                let Some(at) = self
                    .file_requests
                    .iter()
                    .position(|(id, _)| *id == stream_id)
                else {
                    tracing::warn!(target: "rdp_cliprdr", stream_id, "File Contents Response nothing asked for");
                    return Ok(Vec::new());
                };
                let (_, op) = self.file_requests.remove(at);
                Ok(vec![file_contents(stream_id, op, data)])
            }
            ClipboardPdu::FileContentsRequest(request) => Ok(self.serve_file_contents(request)),
            ClipboardPdu::LockClipData { clip_data_id } => Ok(self.server_lock(clip_data_id)),
            ClipboardPdu::UnlockClipData { clip_data_id } => Ok(self.server_unlock(clip_data_id)),
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

/// A failed File Contents Response for a server request the helper cannot serve.
fn refuse_file_contents(stream_id: u32, why: &'static str) -> Vec<ClipboardOutput> {
    tracing::warn!(target: "rdp_cliprdr", stream_id, why, "File Contents Request refused");
    vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
        stream_id, None,
    ))]
}

/// The `streamId` of a File Contents Request or Response, when the message holds one.
fn stream_id(message: &[u8]) -> Option<u32> {
    message
        .get(8..12)
        .map(|id| u32::from_le_bytes([id[0], id[1], id[2], id[3]]))
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

/// A File Contents Response as the output its request asked for. A size that is not 8 bytes,
/// or a range longer than was asked for, is a failure.
fn file_contents(stream_id: u32, op: FileContentsOp, data: Option<Vec<u8>>) -> ClipboardOutput {
    let malformed = |bytes: usize| {
        tracing::warn!(target: "rdp_cliprdr", stream_id, bytes, "File Contents Response refused");
    };
    match op {
        FileContentsOp::Size => {
            let size = data.and_then(|d| match <[u8; 8]>::try_from(d.as_slice()) {
                Ok(size) => Some(u64::from_le_bytes(size)),
                Err(_) => {
                    malformed(d.len());
                    None
                }
            });
            ClipboardOutput::FileSize { stream_id, size }
        }
        FileContentsOp::Range { len, .. } => ClipboardOutput::FileRange {
            stream_id,
            data: data.filter(|d| {
                let fits = d.len() <= len as usize;
                if !fits {
                    malformed(d.len());
                }
                fits
            }),
        },
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
                ClipboardOutput::Send(caps_with(0x3e)),
                ClipboardOutput::Send(vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ]
        );
        assert_eq!(clipboard.general_flags(), 0x3e);
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
        assert_eq!(clipboard.general_flags(), ADVERTISED_FLAGS);
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
        assert_eq!(clipboard.announce(vec![unicode_text()]).message, None);
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
            clipboard.announce(vec![unicode_text()]).message,
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

    /// A server asking faster than the host answers is refused past the bound, and the owed
    /// queue stays bounded however long it keeps asking; the refusals go out in order.
    #[test]
    fn server_requests_past_the_bound_are_refused_in_order() {
        let mut clipboard = ready();
        clipboard.announce(vec![unicode_text()]);
        for _ in 0..MAX_PENDING_SERVER_REQUESTS {
            assert_eq!(
                clipboard.process(&data_request(CF_UNICODETEXT)).unwrap(),
                vec![ClipboardOutput::DataRequested {
                    format_id: CF_UNICODETEXT
                }]
            );
        }
        let flood = 3 * MAX_PENDING_SERVER_REQUESTS;
        for _ in 0..flood {
            assert!(
                clipboard
                    .process(&data_request(CF_UNICODETEXT))
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(clipboard.owed.len() <= MAX_PENDING_SERVER_REQUESTS + 1);
        for _ in 1..MAX_PENDING_SERVER_REQUESTS {
            assert_eq!(clipboard.respond(Some(b"t")).len(), 1);
        }
        let last = clipboard.respond(Some(b"t"));
        assert_eq!(last.len(), 1 + flood);
        assert_eq!(last[0], pdu::encode_format_data_response(Some(b"t")));
        assert!(
            last[1..]
                .iter()
                .all(|r| *r == pdu::encode_format_data_response(None))
        );
        assert!(clipboard.owed.is_empty());
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

    const FILE_LIST_ID: u32 = 0xC0FE;

    fn file_list_format() -> Format {
        Format {
            id: FILE_LIST_ID,
            name: pdu::FILE_GROUP_DESCRIPTOR_W.to_string(),
        }
    }

    fn a_file(name: &str, size: u64) -> FileDescriptor {
        FileDescriptor {
            flags: pdu::FD_FILESIZE,
            attributes: 0,
            last_write_time: 0,
            size: Some(size),
            name: name.to_string(),
        }
    }

    fn range(position: u64, len: u32) -> FileContentsOp {
        FileContentsOp::Range { position, len }
    }

    /// A server Format List naming files locks nothing: a host that never asks for them holds
    /// no lock.
    #[test]
    fn a_server_list_with_files_takes_no_lock() {
        let mut clipboard = ready();
        let outputs = clipboard
            .process(&encode_format_list(&[file_list_format()], true))
            .unwrap();
        assert_eq!(
            sent(&outputs),
            vec![pdu::encode_format_list_response(true).as_slice()]
        );
        assert!(clipboard.held_locks.is_empty());
    }

    /// Asking for the file list locks the server's clipboard first, and says which lock.
    #[test]
    fn a_file_list_request_locks_then_asks() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[file_list_format()]);
        assert_eq!(
            clipboard.request_file_list(),
            Ok(FileListRequest {
                clip_data_id: Some(1),
                messages: vec![pdu::encode_lock_clip_data(1), data_request(FILE_LIST_ID)],
            })
        );
        assert_eq!(
            clipboard.request_file_list(),
            Err(RequestError::Pending {
                format_id: FILE_LIST_ID
            })
        );
    }

    #[test]
    fn a_file_list_needs_one_announced_and_takes_no_lock_without_support() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[unicode_text()]);
        assert_eq!(clipboard.request_file_list(), Err(RequestError::NoFileList));

        let mut clipboard = Clipboard::new();
        clipboard.process(&caps_with(0x2e)).unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        server_copied(&mut clipboard, &[file_list_format()]);
        assert_eq!(
            clipboard.request_file_list(),
            Ok(FileListRequest {
                clip_data_id: None,
                messages: vec![data_request(FILE_LIST_ID)],
            })
        );
    }

    #[test]
    fn a_requested_file_list_arrives_with_its_lock() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[file_list_format()]);
        clipboard.request_file_list().unwrap();
        let files = vec![a_file("a.txt", 3), a_file("dir\\b.bin", 70_000)];
        let list = pdu::encode_file_list(&files);
        assert_eq!(
            clipboard
                .process(&pdu::encode_format_data_response(Some(&list)))
                .unwrap(),
            vec![ClipboardOutput::FileList {
                clip_data_id: Some(1),
                files
            }]
        );
    }

    /// The same format ID asked for with `request` is plain data, whatever the list says.
    #[test]
    fn a_plain_request_of_the_file_list_format_is_plain_data() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[file_list_format()]);
        clipboard.request(FILE_LIST_ID).unwrap();
        let list = pdu::encode_file_list(&[a_file("..", 1)]);
        assert_eq!(
            clipboard
                .process(&pdu::encode_format_data_response(Some(&list)))
                .unwrap(),
            vec![ClipboardOutput::FormatData {
                format_id: FILE_LIST_ID,
                data: Some(list)
            }]
        );
    }

    /// A list that names an escape, a failed one, and one that does not decode all release
    /// their lock.
    #[test]
    fn a_failed_file_list_releases_its_lock() {
        let answers = [
            pdu::encode_format_data_response(Some(&pdu::encode_file_list(&[a_file("..\\x", 1)]))),
            pdu::encode_format_data_response(None),
            vec![0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];
        for (n, answer) in answers.iter().enumerate() {
            let mut clipboard = ready();
            server_copied(&mut clipboard, &[file_list_format()]);
            clipboard.request_file_list().unwrap();
            let outputs = clipboard.process(answer).unwrap();
            assert_eq!(
                outputs[0],
                ClipboardOutput::Send(pdu::encode_unlock_clip_data(1)),
                "answer {n}"
            );
            assert!(
                matches!(outputs[1], ClipboardOutput::FileListFailed { .. }),
                "answer {n}"
            );
            assert!(clipboard.held_locks.is_empty(), "answer {n}");
            assert!(clipboard.request_file_list().is_ok(), "answer {n}");
        }
    }

    /// Requests carry the list's lock and are answered by their stream id, in any order.
    #[test]
    fn file_contents_are_fetched_by_stream_id() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[file_list_format()]);
        clipboard.request_file_list().unwrap();
        let (size_id, size_request) = clipboard
            .request_file_contents(1, FileContentsOp::Size, Some(1))
            .unwrap();
        assert_eq!(
            size_request,
            pdu::encode_file_contents_request(&FileContentsRequest {
                stream_id: size_id,
                index: 1,
                op: FileContentsOp::Size,
                clip_data_id: Some(1),
            })
        );
        let (range_id, _) = clipboard
            .request_file_contents(1, range(65536, 4), Some(1))
            .unwrap();
        assert_ne!(size_id, range_id);
        assert_eq!(
            clipboard
                .process(&pdu::encode_file_contents_response(range_id, Some(b"wxyz")))
                .unwrap(),
            vec![ClipboardOutput::FileRange {
                stream_id: range_id,
                data: Some(b"wxyz".to_vec())
            }]
        );
        assert_eq!(
            clipboard
                .process(&pdu::encode_file_contents_response(
                    size_id,
                    Some(&70_000u64.to_le_bytes())
                ))
                .unwrap(),
            vec![ClipboardOutput::FileSize {
                stream_id: size_id,
                size: Some(70_000)
            }]
        );
        assert!(
            clipboard
                .process(&pdu::encode_file_contents_response(size_id, Some(b"late")))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn malformed_file_contents_are_failures() {
        let mut clipboard = ready();
        let (size_id, _) = clipboard
            .request_file_contents(0, FileContentsOp::Size, None)
            .unwrap();
        let (range_id, _) = clipboard
            .request_file_contents(0, range(0, 2), None)
            .unwrap();
        assert_eq!(
            clipboard
                .process(&pdu::encode_file_contents_response(size_id, Some(b"four")))
                .unwrap(),
            vec![ClipboardOutput::FileSize {
                stream_id: size_id,
                size: None
            }]
        );
        assert_eq!(
            clipboard
                .process(&pdu::encode_file_contents_response(range_id, Some(b"abc")))
                .unwrap(),
            vec![ClipboardOutput::FileRange {
                stream_id: range_id,
                data: None
            }]
        );
    }

    /// A response that does not decode ends its request's wait.
    #[test]
    fn an_undecodable_file_contents_response_ends_its_wait() {
        let mut clipboard = ready();
        let (stream_id, _) = clipboard
            .request_file_contents(0, range(0, 8), None)
            .unwrap();
        let mut neither = pdu::encode_file_contents_response(stream_id, Some(b"x"));
        neither[2] = 0;
        assert!(clipboard.process(&neither).is_err());
        assert!(!clipboard.cancel_file_request(stream_id));
    }

    /// `[MS-RDPECLIP]` 2.2.5.3 bounds the offset, not the end, without huge-file support.
    #[test]
    fn file_contents_need_the_negotiated_features() {
        let mut clipboard = Clipboard::new();
        clipboard
            .process(&caps_with(CB_USE_LONG_FORMAT_NAMES))
            .unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(
            clipboard.request_file_contents(0, FileContentsOp::Size, None),
            Err(FileRequestError::NotNegotiated)
        );

        let mut clipboard = Clipboard::new();
        clipboard
            .process(&caps_with(
                CB_USE_LONG_FORMAT_NAMES | CB_STREAM_FILECLIP_ENABLED,
            ))
            .unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(
            clipboard.request_file_contents(0, range(1 << 31, 8), None),
            Err(FileRequestError::TooFar)
        );
        assert!(
            clipboard
                .request_file_contents(0, range((1 << 31) - 1, 8), None)
                .is_ok()
        );
        assert!(
            ready()
                .request_file_contents(0, range(u64::MAX, 8), None)
                .is_ok()
        );
    }

    #[test]
    fn only_a_held_lock_can_be_used_and_released() {
        let mut clipboard = ready();
        assert_eq!(
            clipboard.request_file_contents(0, FileContentsOp::Size, Some(1)),
            Err(FileRequestError::UnknownLock { clip_data_id: 1 })
        );
        server_copied(&mut clipboard, &[file_list_format()]);
        clipboard.request_file_list().unwrap();
        assert_eq!(clipboard.release(1), Some(pdu::encode_unlock_clip_data(1)));
        assert_eq!(clipboard.release(1), None);
        assert_eq!(
            clipboard.request_file_contents(0, FileContentsOp::Size, Some(1)),
            Err(FileRequestError::UnknownLock { clip_data_id: 1 })
        );
    }

    /// A later server copy releases nothing, so a transfer under the earlier lock goes on.
    #[test]
    fn a_later_copy_keeps_the_earlier_lock() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[file_list_format()]);
        clipboard.request_file_list().unwrap();
        server_copied(&mut clipboard, &[unicode_text()]);
        assert!(
            clipboard
                .request_file_contents(0, range(0, 8), Some(1))
                .is_ok()
        );
    }

    /// With no files announced, a server File Contents Request gets a failure, even one that does
    /// not decode as long as its streamId can be read.
    #[test]
    fn a_server_file_contents_request_is_refused() {
        let mut clipboard = ready();
        let request = pdu::encode_file_contents_request(&FileContentsRequest {
            stream_id: 4,
            index: 0,
            op: FileContentsOp::Size,
            clip_data_id: None,
        });
        let refusal = vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
            4, None,
        ))];
        assert_eq!(clipboard.process(&request).unwrap(), refusal);
        let mut both = request.clone();
        both[16] = 3;
        assert_eq!(clipboard.process(&both).unwrap(), refusal);
        assert!(clipboard.process(&request[..10]).is_err());
    }

    fn host_files() -> Vec<FileDescriptor> {
        vec![a_file("small.txt", 12), a_file("big.bin", 300_000)]
    }

    /// The host's files are announced as `FileGroupDescriptorW`, and the server's request for
    /// that format is answered with the list by the helper.
    #[test]
    fn announced_files_answer_the_file_list_request() {
        let mut clipboard = ready();
        let offer = clipboard
            .announce_files(host_files(), vec![unicode_text()])
            .unwrap();
        let listed = pdu::ClipboardPdu::decode(offer.message.as_ref().unwrap(), true).unwrap();
        let ClipboardPdu::FormatList(formats) = listed else {
            panic!("expected a Format List, got {listed:?}");
        };
        assert_eq!(formats[0], unicode_text());
        assert_eq!(formats[1].name, pdu::FILE_GROUP_DESCRIPTOR_W);
        assert_eq!(offer.released, None);
        let answer = clipboard.process(&data_request(formats[1].id)).unwrap();
        assert_eq!(
            answer,
            vec![ClipboardOutput::Send(pdu::encode_format_data_response(
                Some(&pdu::encode_file_list(&host_files()))
            ))]
        );
    }

    /// Responses name no format, so the helper's file list waits behind an answer the host
    /// still owes.
    #[test]
    fn the_file_list_answer_waits_behind_an_owed_one() {
        let mut clipboard = ready();
        let offer = clipboard
            .announce_files(host_files(), vec![unicode_text()])
            .unwrap();
        let file_list_format = file_list_format_in(&offer);
        clipboard.process(&data_request(CF_UNICODETEXT)).unwrap();
        assert!(
            clipboard
                .process(&data_request(file_list_format))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            clipboard.respond(Some(b"t")),
            vec![
                pdu::encode_format_data_response(Some(b"t")),
                pdu::encode_format_data_response(Some(&pdu::encode_file_list(&host_files()))),
            ]
        );
    }

    /// The helper's own file list answer counts toward the bound too: past it, a request for
    /// the list is refused instead of queued.
    #[test]
    fn the_file_list_answer_past_the_bound_is_refused() {
        let mut clipboard = ready();
        let offer = clipboard
            .announce_files(host_files(), vec![unicode_text()])
            .unwrap();
        let file_list_format = file_list_format_in(&offer);
        for _ in 0..MAX_PENDING_SERVER_REQUESTS {
            clipboard.process(&data_request(CF_UNICODETEXT)).unwrap();
        }
        for _ in 0..2 {
            clipboard.process(&data_request(file_list_format)).unwrap();
        }
        assert_eq!(clipboard.owed.len(), MAX_PENDING_SERVER_REQUESTS + 1);
        for _ in 1..MAX_PENDING_SERVER_REQUESTS {
            clipboard.respond(Some(b"t"));
        }
        assert_eq!(
            clipboard.respond(Some(b"t")),
            vec![
                pdu::encode_format_data_response(Some(b"t")),
                pdu::encode_format_data_response(None),
                pdu::encode_format_data_response(None),
            ]
        );
    }

    fn server_asks(stream_id: u32, index: u32, op: FileContentsOp, lock: Option<u32>) -> Vec<u8> {
        pdu::encode_file_contents_request(&FileContentsRequest {
            stream_id,
            index,
            op,
            clip_data_id: lock,
        })
    }

    /// A server File Contents Request for an announced file reaches the host, which answers
    /// it by `streamId`, in any order.
    #[test]
    fn the_host_serves_the_files_it_announced() {
        let mut clipboard = ready();
        let list_id = clipboard
            .announce_files(host_files(), Vec::new())
            .unwrap()
            .list_id
            .unwrap();
        assert_eq!(
            clipboard
                .process(&server_asks(7, 1, FileContentsOp::Size, None))
                .unwrap(),
            vec![ClipboardOutput::FileContentsRequested {
                stream_id: 7,
                list_id,
                index: 1,
                op: FileContentsOp::Size,
            }]
        );
        assert_eq!(
            clipboard
                .process(&server_asks(8, 1, range(4, 3), None))
                .unwrap(),
            vec![ClipboardOutput::FileContentsRequested {
                stream_id: 8,
                list_id,
                index: 1,
                op: range(4, 3),
            }]
        );
        assert_eq!(
            clipboard.respond_file_range(8, Some(b"abc")),
            Ok(pdu::encode_file_contents_response(8, Some(b"abc")))
        );
        assert_eq!(
            clipboard.respond_file_size(7, Some(300_000)),
            Ok(pdu::encode_file_contents_response(
                7,
                Some(&300_000u64.to_le_bytes())
            ))
        );
        assert_eq!(
            clipboard.respond_file_size(7, Some(1)),
            Err(FileRespondError::NotRequested)
        );
    }

    /// The host answers each request with what it asked for, and at most the length asked.
    #[test]
    fn a_host_answer_must_fit_its_request() {
        let mut clipboard = ready();
        clipboard.announce_files(host_files(), Vec::new()).unwrap();
        clipboard
            .process(&server_asks(1, 0, range(0, 2), None))
            .unwrap();
        clipboard
            .process(&server_asks(2, 0, FileContentsOp::Size, None))
            .unwrap();
        assert_eq!(
            clipboard.respond_file_range(1, Some(b"abc")),
            Err(FileRespondError::TooLong)
        );
        assert_eq!(
            clipboard.respond_file_size(1, Some(3)),
            Err(FileRespondError::WrongKind)
        );
        assert_eq!(
            clipboard.respond_file_range(2, Some(b"")),
            Err(FileRespondError::WrongKind)
        );
        assert_eq!(
            clipboard.respond_file_range(1, None),
            Ok(pdu::encode_file_contents_response(1, None))
        );
        assert_eq!(
            clipboard.respond_file_size(2, None),
            Ok(pdu::encode_file_contents_response(2, None))
        );
    }

    /// A request this side cannot serve gets a failed response, never reaches the host, and
    /// the session goes on (#325).
    #[test]
    fn a_request_for_no_such_file_is_refused() {
        let refused = |stream_id| {
            vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
                stream_id, None,
            ))]
        };
        let mut clipboard = ready();
        clipboard.announce_files(host_files(), Vec::new()).unwrap();
        assert_eq!(
            clipboard
                .process(&server_asks(1, 2, FileContentsOp::Size, None))
                .unwrap(),
            refused(1)
        );
        assert_eq!(
            clipboard
                .process(&server_asks(2, u32::MAX, range(0, 8), None))
                .unwrap(),
            refused(2)
        );
        assert_eq!(
            clipboard.respond_file_size(1, Some(1)),
            Err(FileRespondError::NotRequested)
        );
    }

    /// 2.2.5.3 asks the server not to send an offset at 2 GiB or later without huge-file support,
    /// as a SHOULD, so one that arrives is still served.
    #[test]
    fn a_far_offset_is_served_without_huge_file_support() {
        let mut clipboard = Clipboard::new();
        clipboard
            .process(&caps_with(
                CB_USE_LONG_FORMAT_NAMES | CB_STREAM_FILECLIP_ENABLED,
            ))
            .unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        clipboard
            .announce_files(vec![a_file("big", 3 << 30)], Vec::new())
            .unwrap();
        assert!(matches!(
            clipboard
                .process(&server_asks(3, 0, range(1 << 31, 8), None))
                .unwrap()[..],
            [ClipboardOutput::FileContentsRequested { stream_id: 3, .. }]
        ));
    }

    /// 2.2.2.1.1.1: without huge-file support only files up to 4,294,967,295 bytes are exchanged.
    #[test]
    fn a_file_over_4_gib_needs_huge_file_support() {
        let mut clipboard = Clipboard::new();
        clipboard
            .process(&caps_with(
                CB_USE_LONG_FORMAT_NAMES | CB_STREAM_FILECLIP_ENABLED,
            ))
            .unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        let limit = u64::from(u32::MAX);
        assert!(
            clipboard
                .announce_files(vec![a_file("at", limit)], Vec::new())
                .is_ok()
        );
        assert_eq!(
            clipboard.announce_files(vec![a_file("a", 1), a_file("over", limit + 1)], Vec::new()),
            Err(FileAnnounceError::TooLarge { index: 1 })
        );
        assert!(
            ready()
                .announce_files(vec![a_file("over", limit + 1)], Vec::new())
                .is_ok()
        );
    }

    /// 3.1.5.4.7: after the server refused this side's Format List, every File Contents Request
    /// fails, until the host announces again.
    #[test]
    fn after_a_refused_format_list_files_are_not_served() {
        let mut clipboard = ready();
        clipboard.announce_files(host_files(), Vec::new()).unwrap();
        clipboard.process(&lock(9)).unwrap();
        let refused = [0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        clipboard.process(&refused).unwrap();
        for (stream_id, lock) in [(1, None), (2, Some(9))] {
            assert_eq!(
                clipboard
                    .process(&server_asks(stream_id, 0, FileContentsOp::Size, lock))
                    .unwrap(),
                vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
                    stream_id, None
                ))]
            );
        }
        clipboard.announce_files(host_files(), Vec::new()).unwrap();
        let asked = clipboard
            .process(&server_asks(3, 0, FileContentsOp::Size, None))
            .unwrap();
        assert!(asked_list(&asked).is_some());
    }

    /// A second request under a `streamId` the host still owes would make the answers
    /// ambiguous, so it is refused.
    #[test]
    fn a_stream_id_already_waiting_is_refused() {
        let mut clipboard = ready();
        clipboard.announce_files(host_files(), Vec::new()).unwrap();
        clipboard
            .process(&server_asks(5, 0, FileContentsOp::Size, None))
            .unwrap();
        assert_eq!(
            clipboard
                .process(&server_asks(5, 1, range(0, 8), None))
                .unwrap(),
            vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
                5, None
            ))]
        );
        assert!(clipboard.respond_file_size(5, Some(12)).is_ok());
    }

    /// File Contents Requests the host has not answered are bounded; one past the bound is
    /// refused at once, and answering one makes room again.
    #[test]
    fn file_requests_past_the_bound_are_refused() {
        let mut clipboard = ready();
        clipboard.announce_files(host_files(), Vec::new()).unwrap();
        let bound = MAX_PENDING_SERVER_REQUESTS as u32;
        for stream_id in 1..=bound {
            let outputs = clipboard
                .process(&server_asks(stream_id, 0, FileContentsOp::Size, None))
                .unwrap();
            assert!(asked_list(&outputs).is_some());
        }
        assert_eq!(
            clipboard
                .process(&server_asks(bound + 1, 0, FileContentsOp::Size, None))
                .unwrap(),
            vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
                bound + 1,
                None
            ))]
        );
        assert!(clipboard.respond_file_size(1, Some(12)).is_ok());
        let outputs = clipboard
            .process(&server_asks(bound + 2, 0, FileContentsOp::Size, None))
            .unwrap();
        assert!(asked_list(&outputs).is_some());
    }

    #[test]
    fn files_need_streaming_and_contained_names() {
        let mut clipboard = Clipboard::new();
        assert_eq!(
            clipboard.announce_files(host_files(), Vec::new()),
            Err(FileAnnounceError::NotNegotiated)
        );
        clipboard
            .process(&caps_with(CB_USE_LONG_FORMAT_NAMES))
            .unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(
            clipboard.announce_files(host_files(), Vec::new()),
            Err(FileAnnounceError::NotNegotiated)
        );

        let long = "x".repeat(pdu::FILE_NAME_MAX_UNITS);
        assert!(
            ready()
                .announce_files(vec![a_file(&long, 1)], Vec::new())
                .is_ok()
        );
        for name in ["..\\x", "c:x", "", "a\0b", &format!("{long}y")] {
            assert_eq!(
                ready().announce_files(vec![a_file("ok", 1), a_file(name, 1)], Vec::new()),
                Err(FileAnnounceError::BadName { index: 1 }),
                "{name:?}"
            );
        }
    }

    fn lock(clip_data_id: u32) -> Vec<u8> {
        pdu::encode_lock_clip_data(clip_data_id)
    }

    fn unlock(clip_data_id: u32) -> Vec<u8> {
        pdu::encode_unlock_clip_data(clip_data_id)
    }

    fn asked_list(outputs: &[ClipboardOutput]) -> Option<u32> {
        match outputs {
            [ClipboardOutput::FileContentsRequested { list_id, .. }] => Some(*list_id),
            _ => None,
        }
    }

    /// 3.1.5.3.2: a server lock keeps the files on the host's clipboard then servable under
    /// its `clipDataId` after the host copies something else, until the Unlock.
    #[test]
    fn a_server_lock_keeps_the_host_files_it_found() {
        let mut clipboard = ready();
        let first = clipboard.announce_files(host_files(), Vec::new()).unwrap();
        assert!(clipboard.process(&lock(9)).unwrap().is_empty());
        let second = clipboard
            .announce_files(vec![a_file("other.txt", 1)], Vec::new())
            .unwrap();
        assert_eq!(second.released, None);
        let (first, second) = (first.list_id.unwrap(), second.list_id.unwrap());
        assert_ne!(first, second);
        let locked = clipboard
            .process(&server_asks(1, 1, FileContentsOp::Size, Some(9)))
            .unwrap();
        assert_eq!(asked_list(&locked), Some(first));
        let current = clipboard
            .process(&server_asks(2, 0, FileContentsOp::Size, None))
            .unwrap();
        assert_eq!(asked_list(&current), Some(second));
        // The second list holds one file, so index 1 exists only under the lock.
        let beyond = clipboard
            .process(&server_asks(3, 1, FileContentsOp::Size, None))
            .unwrap();
        assert_eq!(asked_list(&beyond), None);

        assert_eq!(
            clipboard.process(&unlock(9)).unwrap(),
            vec![ClipboardOutput::FilesReleased { list_id: first }]
        );
        assert_eq!(
            clipboard
                .process(&server_asks(4, 1, FileContentsOp::Size, Some(9)))
                .unwrap(),
            vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
                4, None
            ))]
        );
    }

    /// Unlocking the list still on the host's clipboard releases nothing.
    #[test]
    fn unlocking_the_current_list_keeps_it() {
        let mut clipboard = ready();
        clipboard.announce_files(host_files(), Vec::new()).unwrap();
        clipboard.process(&lock(9)).unwrap();
        assert!(clipboard.process(&unlock(9)).unwrap().is_empty());
        let asked = clipboard
            .process(&server_asks(1, 0, FileContentsOp::Size, None))
            .unwrap();
        assert!(asked_list(&asked).is_some());
    }

    /// A list the host replaces while nothing locks it is released at once.
    #[test]
    fn an_unlocked_list_is_released_by_the_next_announcement() {
        let mut clipboard = ready();
        let files = clipboard.announce_files(host_files(), Vec::new()).unwrap();
        let text = clipboard.announce(vec![unicode_text()]);
        assert_eq!(text.released, files.list_id);
        assert_eq!(text.list_id, None);
        assert_eq!(
            clipboard
                .process(&server_asks(1, 0, FileContentsOp::Size, None))
                .unwrap(),
            vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
                1, None
            ))]
        );
    }

    /// 3.1.5.3.2 and 3.1.5.3.4: a lock with no files stores nothing, and an unlock for an id
    /// that stores nothing is ignored.
    #[test]
    fn locks_without_files_are_ignored() {
        let mut clipboard = ready();
        assert!(clipboard.process(&lock(1)).unwrap().is_empty());
        clipboard.announce_files(host_files(), Vec::new()).unwrap();
        assert_eq!(
            clipboard
                .process(&server_asks(1, 0, FileContentsOp::Size, Some(1)))
                .unwrap(),
            vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
                1, None
            ))]
        );
        assert!(clipboard.process(&unlock(2)).unwrap().is_empty());
    }

    /// A lock id taken again moves to the files on the clipboard now, and a list it was the
    /// last lock on is released.
    #[test]
    fn a_lock_id_taken_again_moves() {
        let mut clipboard = ready();
        let first = clipboard.announce_files(host_files(), Vec::new()).unwrap();
        clipboard.process(&lock(9)).unwrap();
        let second = clipboard
            .announce_files(vec![a_file("other.txt", 1)], Vec::new())
            .unwrap();
        assert_eq!(
            clipboard.process(&lock(9)).unwrap(),
            vec![ClipboardOutput::FilesReleased {
                list_id: first.list_id.unwrap()
            }]
        );
        let asked = clipboard
            .process(&server_asks(1, 0, FileContentsOp::Size, Some(9)))
            .unwrap();
        assert_eq!(asked_list(&asked), second.list_id);
    }

    /// The server's locks are bounded; one past the bound is not kept.
    #[test]
    fn server_locks_are_bounded() {
        let mut clipboard = ready();
        clipboard.announce_files(host_files(), Vec::new()).unwrap();
        for id in 1..=MAX_SERVER_LOCKS as u32 + 1 {
            clipboard.process(&lock(id)).unwrap();
        }
        let kept = clipboard
            .process(&server_asks(
                1,
                0,
                FileContentsOp::Size,
                Some(MAX_SERVER_LOCKS as u32),
            ))
            .unwrap();
        assert!(asked_list(&kept).is_some());
        let over = clipboard
            .process(&server_asks(
                2,
                0,
                FileContentsOp::Size,
                Some(MAX_SERVER_LOCKS as u32 + 1),
            ))
            .unwrap();
        assert_eq!(asked_list(&over), None);
    }

    /// A new Monitor Ready releases every list the host announced, and its initial Format List
    /// names no files.
    #[test]
    fn a_new_monitor_ready_releases_the_host_files() {
        let mut clipboard = ready();
        let first = clipboard
            .announce_files(host_files(), vec![unicode_text()])
            .unwrap();
        clipboard.process(&lock(9)).unwrap();
        let second = clipboard.announce_files(host_files(), Vec::new()).unwrap();
        clipboard
            .process(&server_asks(1, 0, FileContentsOp::Size, None))
            .unwrap();
        let outputs = clipboard.process(&VM_MONITOR_READY).unwrap();
        let released: Vec<_> = outputs
            .iter()
            .filter_map(|o| match o {
                ClipboardOutput::FilesReleased { list_id } => Some(*list_id),
                _ => None,
            })
            .collect();
        assert_eq!(
            released,
            vec![first.list_id.unwrap(), second.list_id.unwrap()]
        );
        assert_eq!(sent(&outputs)[1], encode_format_list(&[], true));
        assert_eq!(
            clipboard.respond_file_size(1, Some(1)),
            Err(FileRespondError::NotRequested)
        );
    }

    fn file_list_format_in(offer: &Announcement) -> u32 {
        match pdu::ClipboardPdu::decode(offer.message.as_ref().unwrap(), true).unwrap() {
            ClipboardPdu::FormatList(formats) => {
                formats
                    .iter()
                    .find(|f| f.name == pdu::FILE_GROUP_DESCRIPTOR_W)
                    .unwrap()
                    .id
            }
            other => panic!("expected a Format List, got {other:?}"),
        }
    }

    /// A new Monitor Ready starts over: waits and locks from before it are gone.
    #[test]
    fn a_new_monitor_ready_forgets_the_old_sequence() {
        let mut clipboard = ready();
        clipboard.announce(vec![unicode_text()]);
        server_copied(&mut clipboard, &[file_list_format()]);
        clipboard.request_file_list().unwrap();
        let (stream_id, _) = clipboard
            .request_file_contents(0, range(0, 8), Some(1))
            .unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        assert!(clipboard.held_locks.is_empty());
        assert!(!clipboard.cancel_file_request(stream_id));
        assert_eq!(clipboard.request_file_list(), Err(RequestError::NoFileList));
        assert_eq!(clipboard.local_formats, vec![unicode_text()]);
    }

    #[test]
    fn ids_skip_zero_and_those_in_use() {
        let mut last = u32::MAX;
        assert_eq!(next_id(&mut last, |_| false), 1);
        assert_eq!(next_id(&mut last, |id| id == 2), 3);
    }

    /// The VM does not answer a request for files it no longer holds (#324), so the host can
    /// stop waiting.
    #[test]
    fn a_file_request_can_be_cancelled() {
        let mut clipboard = ready();
        let (stream_id, _) = clipboard
            .request_file_contents(0, range(0, 8), None)
            .unwrap();
        assert!(clipboard.cancel_file_request(stream_id));
        assert!(!clipboard.cancel_file_request(stream_id));
        assert!(
            clipboard
                .process(&pdu::encode_file_contents_response(
                    stream_id,
                    Some(b"late")
                ))
                .unwrap()
                .is_empty()
        );
    }

    /// A cancelled file list keeps its lock for the host to release, even when a response that
    /// does not decode arrives late.
    #[test]
    fn a_cancelled_file_list_keeps_its_lock() {
        let mut clipboard = ready();
        server_copied(&mut clipboard, &[file_list_format()]);
        clipboard.request_file_list().unwrap();
        assert_eq!(clipboard.cancel_request(), Some(FILE_LIST_ID));
        let neither = [0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(clipboard.process(&neither).is_err());
        assert_eq!(clipboard.held_locks, vec![1]);
    }

    /// Issue #355: with file transfer off, the Capabilities carry none of the file flags, only
    /// long names; with it on, the bytes are those `new` always sent.
    #[test]
    fn file_transfer_off_advertises_no_file_flags() {
        let mut off = Clipboard::without_file_transfer();
        off.process(&VM_SERVER_CAPS).unwrap();
        let outputs = off.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(sent(&outputs)[0], caps_with(CB_USE_LONG_FORMAT_NAMES));
        assert_eq!(off.general_flags(), CB_USE_LONG_FORMAT_NAMES);
        assert_eq!(FILE_TRANSFER_FLAGS & CB_USE_LONG_FORMAT_NAMES, 0);
        assert_eq!(
            ADVERTISED_FLAGS & !FILE_TRANSFER_FLAGS,
            CB_USE_LONG_FORMAT_NAMES
        );

        let mut on = Clipboard::new();
        on.process(&VM_SERVER_CAPS).unwrap();
        assert_eq!(
            sent(&on.process(&VM_MONITOR_READY).unwrap())[0],
            caps_with(0x3e)
        );
    }

    /// With file transfer off, every file operation behaves as against a server that did not
    /// advertise streaming.
    #[test]
    fn file_transfer_off_behaves_as_a_server_without_streaming() {
        let mut off = Clipboard::without_file_transfer();
        off.process(&caps_with(0xFFFF_FFFF)).unwrap();
        off.process(&VM_MONITOR_READY).unwrap();
        let mut unoffered = Clipboard::new();
        unoffered
            .process(&caps_with(CB_USE_LONG_FORMAT_NAMES))
            .unwrap();
        unoffered.process(&VM_MONITOR_READY).unwrap();

        for clipboard in [&mut off, &mut unoffered] {
            assert_eq!(
                clipboard.announce_files(host_files(), Vec::new()),
                Err(FileAnnounceError::NotNegotiated)
            );
            assert_eq!(
                clipboard.request_file_contents(0, FileContentsOp::Size, None),
                Err(FileRequestError::NotNegotiated)
            );
            assert_eq!(
                clipboard
                    .process(&server_asks(7, 0, FileContentsOp::Size, None))
                    .unwrap(),
                vec![ClipboardOutput::Send(pdu::encode_file_contents_response(
                    7, None
                ))]
            );
        }
        assert_eq!(off.general_flags(), unoffered.general_flags());
    }

    /// A new initialization sequence keeps the host's choice.
    #[test]
    fn file_transfer_off_survives_a_second_monitor_ready() {
        let mut clipboard = Clipboard::without_file_transfer();
        clipboard.process(&VM_SERVER_CAPS).unwrap();
        clipboard.process(&VM_MONITOR_READY).unwrap();
        let outputs = clipboard.process(&VM_MONITOR_READY).unwrap();
        assert_eq!(sent(&outputs)[0], caps_with(CB_USE_LONG_FORMAT_NAMES));
        assert_eq!(clipboard.general_flags(), CB_USE_LONG_FORMAT_NAMES);
    }
}
