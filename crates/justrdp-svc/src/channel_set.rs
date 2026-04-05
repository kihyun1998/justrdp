#![forbid(unsafe_code)]

//! Static channel set -- manages registered SVC processors.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{Decode, ReadCursor};
use justrdp_pdu::rdp::svc::{
    ChannelPduHeader, CHANNEL_CHUNK_LENGTH, CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST,
    CHANNEL_FLAG_SUSPEND, CHANNEL_FLAG_RESUME, CHANNEL_PDU_HEADER_SIZE,
};

use crate::chunk;
use crate::dechunk::Dechunker;
use crate::{ChannelName, SvcError, SvcMessage, SvcProcessor, SvcResult};

/// Maximum number of static virtual channels (MS-RDPBCGR 2.2.1.3.4).
const MAX_CHANNELS: usize = 31;

/// Maximum chunk size (MS-RDPBCGR 2.2.7.1.10: VCCHUNKSIZE max = 16,776,960).
const MAX_CHUNK_SIZE: usize = 16_776_960;

/// A registered channel with its processor and dechunking state.
struct ChannelEntry {
    processor: Box<dyn SvcProcessor>,
    dechunker: Dechunker,
    /// Assigned MCS channel ID (`None` if not yet assigned).
    mcs_channel_id: Option<u16>,
    /// Whether CHANNEL_OPTION_SHOW_PROTOCOL is set for this channel.
    show_protocol: bool,
}

/// Collection of static virtual channel processors.
///
/// Register processors before connection, then assign MCS channel IDs
/// from the server's response after the connection sequence completes.
pub struct StaticChannelSet {
    entries: Vec<ChannelEntry>,
    /// Maximum chunk size for outgoing data.
    chunk_size: usize,
    /// Whether all channels are suspended.
    suspended: bool,
}

impl StaticChannelSet {
    /// Create a new empty channel set.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            chunk_size: CHANNEL_CHUNK_LENGTH,
            suspended: false,
        }
    }

    /// Set the maximum chunk size for outgoing data.
    ///
    /// Use the `VCChunkSize` from the server's VirtualChannelCapability.
    /// If not called, defaults to [`CHANNEL_CHUNK_LENGTH`] (1600).
    /// Zero is treated as the default; values above [`MAX_CHUNK_SIZE`] are clamped.
    pub fn set_chunk_size(&mut self, size: usize) {
        self.chunk_size = match size {
            0 => CHANNEL_CHUNK_LENGTH,
            s if s > MAX_CHUNK_SIZE => MAX_CHUNK_SIZE,
            s => s,
        };
    }

    /// Register a channel processor.
    ///
    /// Returns an error if the maximum number of channels is exceeded
    /// or a channel with the same name already exists.
    pub fn insert(&mut self, processor: Box<dyn SvcProcessor>) -> SvcResult<()> {
        if self.entries.len() >= MAX_CHANNELS {
            return Err(SvcError::Protocol(alloc::format!(
                "maximum {MAX_CHANNELS} static virtual channels",
            )));
        }
        let name = processor.channel_name();
        if self.entries.iter().any(|e| e.processor.channel_name() == name) {
            return Err(SvcError::Protocol(alloc::format!(
                "duplicate channel name: {name}"
            )));
        }
        self.entries.push(ChannelEntry {
            processor,
            dechunker: Dechunker::new(),
            mcs_channel_id: None,
            show_protocol: false,
        });
        Ok(())
    }

    /// Assign MCS channel IDs from the connection result.
    ///
    /// `channel_ids` is the `ConnectionResult::channel_ids` mapping
    /// (channel_name, mcs_channel_id). Channels not present in the
    /// mapping will not be assigned an ID and will be ignored.
    ///
    /// Note: channel options (e.g., `CHANNEL_OPTION_SHOW_PROTOCOL`) must be
    /// configured separately via [`set_show_protocol`](Self::set_show_protocol).
    pub fn assign_ids(&mut self, channel_ids: &[(String, u16)]) {
        for entry in &mut self.entries {
            let name = entry.processor.channel_name();
            if let Some((_, id)) = channel_ids.iter().find(|(n, _)| n.as_str() == name.as_str()) {
                entry.mcs_channel_id = Some(*id);
            }
        }
    }

    /// Set `CHANNEL_OPTION_SHOW_PROTOCOL` for a channel by name.
    pub fn set_show_protocol(&mut self, name: ChannelName, show: bool) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.processor.channel_name() == name) {
            entry.show_protocol = show;
        }
    }

    /// Get the list of channel names for building `ClientNetworkData`.
    pub fn channel_names(&self) -> Vec<ChannelName> {
        self.entries.iter().map(|e| e.processor.channel_name()).collect()
    }

    /// Call `start()` on all processors and collect initial messages.
    ///
    /// Returns `(channel_id, frames)` pairs ready to send.
    pub fn start_all(&mut self, user_channel_id: u16) -> SvcResult<Vec<(u16, Vec<Vec<u8>>)>> {
        let mut results = Vec::new();
        for entry in &mut self.entries {
            let Some(channel_id) = entry.mcs_channel_id else {
                continue; // not assigned
            };
            let messages = entry.processor.start()?;
            if !messages.is_empty() {
                let frames = encode_messages(
                    user_channel_id,
                    channel_id,
                    &messages,
                    self.chunk_size,
                    entry.show_protocol,
                )?;
                results.push((channel_id, frames));
            }
        }
        Ok(results)
    }

    /// Process incoming channel data from the session layer.
    ///
    /// `raw_data` is the MCS userData bytes (starting with ChannelPduHeader).
    /// Returns response frames ready to send (already MCS-wrapped).
    pub fn process_incoming(
        &mut self,
        channel_id: u16,
        raw_data: &[u8],
        user_channel_id: u16,
    ) -> SvcResult<Vec<Vec<u8>>> {
        // Decode ChannelPduHeader.
        if raw_data.len() < CHANNEL_PDU_HEADER_SIZE {
            return Err(SvcError::Protocol(String::from(
                "channel data too short for ChannelPduHeader",
            )));
        }
        let mut src = ReadCursor::new(raw_data);
        let hdr = ChannelPduHeader::decode(&mut src)?;
        let chunk_data = src.peek_remaining();

        // Find the channel entry index — only process data from known channels.
        let entry_idx = match self.entries.iter().position(|e| e.mcs_channel_id == Some(channel_id)) {
            Some(idx) => idx,
            None => return Ok(Vec::new()), // unknown channel, ignore
        };

        // Handle SUSPEND/RESUME (affects all channels, MS-RDPBCGR 2.2.6.1).
        // SUSPEND/RESUME PDUs carry no data and must not set FIRST or LAST.
        if hdr.flags & CHANNEL_FLAG_SUSPEND != 0 {
            if hdr.flags & (CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST) != 0 {
                return Err(SvcError::Protocol(String::from(
                    "SUSPEND combined with FIRST/LAST is invalid",
                )));
            }
            self.suspended = true;
            return Ok(Vec::new());
        }
        if hdr.flags & CHANNEL_FLAG_RESUME != 0 {
            if hdr.flags & (CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST) != 0 {
                return Err(SvcError::Protocol(String::from(
                    "RESUME combined with FIRST/LAST is invalid",
                )));
            }
            self.suspended = false;
            return Ok(Vec::new());
        }

        if self.suspended {
            return Ok(Vec::new());
        }

        let entry = &mut self.entries[entry_idx];

        // Feed chunk to dechunker.
        let complete = entry.dechunker.process_chunk(hdr.length, hdr.flags, chunk_data)?;

        if let Some(payload) = complete {
            // Complete message -- dispatch to processor.
            let responses = entry.processor.process(&payload)?;
            if responses.is_empty() {
                return Ok(Vec::new());
            }
            let show_protocol = entry.show_protocol;
            encode_messages(user_channel_id, channel_id, &responses, self.chunk_size, show_protocol)
        } else {
            Ok(Vec::new())
        }
    }

    /// Encode a message for a specific channel (for direct sending).
    pub fn encode_message(
        &self,
        user_channel_id: u16,
        channel_id: u16,
        message: &SvcMessage,
    ) -> SvcResult<Vec<Vec<u8>>> {
        let show_protocol = self
            .entries
            .iter()
            .find(|e| e.mcs_channel_id == Some(channel_id))
            .map_or(false, |e| e.show_protocol);
        chunk::chunk_and_encode(user_channel_id, channel_id, &message.data, self.chunk_size, show_protocol)
    }

    /// Get a reference to a processor by MCS channel ID.
    pub fn get_by_channel_id(&self, channel_id: u16) -> Option<&dyn SvcProcessor> {
        self.entries
            .iter()
            .find(|e| e.mcs_channel_id == Some(channel_id))
            .map(|e| &*e.processor)
    }

    /// Get a mutable reference to a processor by MCS channel ID.
    pub fn get_by_channel_id_mut(&mut self, channel_id: u16) -> Option<&mut dyn SvcProcessor> {
        self.entries
            .iter_mut()
            .find(|e| e.mcs_channel_id == Some(channel_id))
            .map(|e| &mut *e.processor)
    }

    /// Get a processor by channel name.
    pub fn get_by_name(&self, name: ChannelName) -> Option<&dyn SvcProcessor> {
        self.entries
            .iter()
            .find(|e| e.processor.channel_name() == name)
            .map(|e| &*e.processor)
    }

    /// Get the MCS channel ID for a channel name.
    pub fn channel_id_for_name(&self, name: ChannelName) -> Option<u16> {
        self.entries
            .iter()
            .find(|e| e.processor.channel_name() == name)
            .and_then(|e| e.mcs_channel_id)
    }

    /// Number of registered channels.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no channels are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Reset all dechunkers (e.g., on deactivation-reactivation).
    pub fn reset_dechunkers(&mut self) {
        for entry in &mut self.entries {
            entry.dechunker.reset();
        }
    }
}

impl Default for StaticChannelSet {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for StaticChannelSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticChannelSet")
            .field("channels", &self.entries.len())
            .field("chunk_size", &self.chunk_size)
            .field("suspended", &self.suspended)
            .finish()
    }
}

/// Encode multiple SVC messages into wire frames.
fn encode_messages(
    user_channel_id: u16,
    channel_id: u16,
    messages: &[SvcMessage],
    chunk_size: usize,
    show_protocol: bool,
) -> SvcResult<Vec<Vec<u8>>> {
    let mut all_frames = Vec::new();
    for msg in messages {
        let frames = chunk::chunk_and_encode(user_channel_id, channel_id, &msg.data, chunk_size, show_protocol)?;
        all_frames.extend(frames);
    }
    Ok(all_frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;

    /// A simple test SVC processor.
    #[derive(Debug)]
    struct EchoProcessor {
        name: ChannelName,
    }

    impl justrdp_core::AsAny for EchoProcessor {
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
            self
        }
    }

    impl SvcProcessor for EchoProcessor {
        fn channel_name(&self) -> ChannelName {
            self.name
        }

        fn start(&mut self) -> SvcResult<Vec<SvcMessage>> {
            Ok(vec![SvcMessage::new(b"init".to_vec())])
        }

        fn process(&mut self, payload: &[u8]) -> SvcResult<Vec<SvcMessage>> {
            // Echo back what we received.
            Ok(vec![SvcMessage::new(payload.to_vec())])
        }
    }

    fn make_channel_data(total_length: u32, flags: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CHANNEL_PDU_HEADER_SIZE + data.len());
        buf.extend_from_slice(&total_length.to_le_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    #[test]
    fn insert_and_assign_ids() {
        let mut set = StaticChannelSet::new();
        set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"testch"),
        }))
        .unwrap();

        assert_eq!(set.len(), 1);
        assert_eq!(set.channel_names()[0].as_str(), "testch");

        set.assign_ids(&[(String::from("testch"), 1004)]);
        assert_eq!(set.channel_id_for_name(ChannelName::new(b"testch")), Some(1004));
    }

    #[test]
    fn duplicate_name_rejected() {
        let mut set = StaticChannelSet::new();
        set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"cliprdr"),
        }))
        .unwrap();
        let result = set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"cliprdr"),
        }));
        assert!(result.is_err());
    }

    #[test]
    fn max_channels_enforced() {
        let mut set = StaticChannelSet::new();
        for i in 0..MAX_CHANNELS {
            let name = alloc::format!("ch{i:05}");
            let mut bytes = [0u8; 7];
            bytes[..name.len().min(7)].copy_from_slice(&name.as_bytes()[..name.len().min(7)]);
            set.insert(Box::new(EchoProcessor {
                name: ChannelName::new(&bytes[..name.len().min(7)]),
            }))
            .unwrap();
        }
        assert_eq!(set.len(), MAX_CHANNELS);
        let result = set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"extra"),
        }));
        assert!(result.is_err());
    }

    #[test]
    fn process_single_chunk_echoes_back() {
        let mut set = StaticChannelSet::new();
        set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"echo"),
        }))
        .unwrap();
        set.assign_ids(&[(String::from("echo"), 1004)]);

        use justrdp_pdu::rdp::svc::{CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST};

        let raw = make_channel_data(
            5,
            CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST,
            b"hello",
        );

        let frames = set.process_incoming(1004, &raw, 1007).unwrap();
        // Echo processor produces a response with "hello".
        assert!(!frames.is_empty());
    }

    #[test]
    fn unknown_channel_ignored() {
        let mut set = StaticChannelSet::new();
        let raw = make_channel_data(3, 0x03, b"abc");
        let frames = set.process_incoming(9999, &raw, 1007).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn suspend_resume() {
        let mut set = StaticChannelSet::new();
        set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"test"),
        }))
        .unwrap();
        set.assign_ids(&[(String::from("test"), 1004)]);

        // SUSPEND
        let raw = make_channel_data(0, CHANNEL_FLAG_SUSPEND, &[]);
        set.process_incoming(1004, &raw, 1007).unwrap();

        // Data while suspended -- should be ignored.
        let raw = make_channel_data(5, 0x03, b"hello");
        let frames = set.process_incoming(1004, &raw, 1007).unwrap();
        assert!(frames.is_empty());

        // RESUME
        let raw = make_channel_data(0, CHANNEL_FLAG_RESUME, &[]);
        set.process_incoming(1004, &raw, 1007).unwrap();

        // Now data should work.
        let raw = make_channel_data(5, 0x03, b"hello");
        let frames = set.process_incoming(1004, &raw, 1007).unwrap();
        assert!(!frames.is_empty());
    }

    #[test]
    fn multi_chunk_dechunk_integration() {
        let mut set = StaticChannelSet::new();
        set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"echo"),
        }))
        .unwrap();
        set.assign_ids(&[(String::from("echo"), 1004)]);

        use justrdp_pdu::rdp::svc::{CHANNEL_FLAG_FIRST, CHANNEL_FLAG_LAST, CHANNEL_FLAG_SHOW_PROTOCOL};

        // First chunk
        let raw1 = make_channel_data(
            6,
            CHANNEL_FLAG_FIRST | CHANNEL_FLAG_SHOW_PROTOCOL,
            b"AAA",
        );
        let frames = set.process_incoming(1004, &raw1, 1007).unwrap();
        assert!(frames.is_empty()); // not complete yet

        // Last chunk
        let raw2 = make_channel_data(
            6,
            CHANNEL_FLAG_LAST | CHANNEL_FLAG_SHOW_PROTOCOL,
            b"BBB",
        );
        let frames = set.process_incoming(1004, &raw2, 1007).unwrap();
        // Should echo back "AAABBB"
        assert!(!frames.is_empty());
    }

    #[test]
    fn start_all_collects_initial_messages() {
        let mut set = StaticChannelSet::new();
        set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"echo"),
        }))
        .unwrap();
        set.assign_ids(&[(String::from("echo"), 1004)]);

        let results = set.start_all(1007).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 1004);
        assert!(!results[0].1.is_empty()); // should have frames for "init" message
    }

    #[test]
    fn start_all_skips_unassigned() {
        let mut set = StaticChannelSet::new();
        set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"noid"),
        }))
        .unwrap();
        // Don't assign any IDs.
        let results = set.start_all(1007).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn set_chunk_size_zero_defaults() {
        let mut set = StaticChannelSet::new();
        set.set_chunk_size(0);
        assert_eq!(set.chunk_size, CHANNEL_CHUNK_LENGTH);
    }

    #[test]
    fn set_chunk_size_clamped_to_max() {
        let mut set = StaticChannelSet::new();
        set.set_chunk_size(usize::MAX);
        assert_eq!(set.chunk_size, MAX_CHUNK_SIZE);
    }

    #[test]
    fn show_protocol_propagated_to_encode() {
        use justrdp_core::{Decode, ReadCursor};
        use justrdp_pdu::mcs::SendDataRequest;
        use justrdp_pdu::rdp::svc::CHANNEL_FLAG_SHOW_PROTOCOL;
        use justrdp_pdu::tpkt::TpktHeader;
        use justrdp_pdu::x224::DataTransfer;

        let mut set = StaticChannelSet::new();
        set.insert(Box::new(EchoProcessor {
            name: ChannelName::new(b"show"),
        }))
        .unwrap();
        set.assign_ids(&[(String::from("show"), 1004)]);
        set.set_show_protocol(ChannelName::new(b"show"), true);

        // Single-chunk encode_message should set SHOW_PROTOCOL.
        let msg = crate::SvcMessage::new(b"test".to_vec());
        let frames = set.encode_message(1007, 1004, &msg).unwrap();
        assert_eq!(frames.len(), 1);

        let frame = &frames[0];
        let mut src = ReadCursor::new(frame);
        TpktHeader::decode(&mut src).unwrap();
        DataTransfer::decode(&mut src).unwrap();
        let sdr = SendDataRequest::decode(&mut src).unwrap();
        let mut ud_src = ReadCursor::new(sdr.user_data);
        let ch_hdr = ChannelPduHeader::decode(&mut ud_src).unwrap();
        assert!(ch_hdr.flags & CHANNEL_FLAG_SHOW_PROTOCOL != 0);
    }
}
