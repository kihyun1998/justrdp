#![forbid(unsafe_code)]

//! Static channel set -- manages registered SVC processors.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use justrdp_core::{Decode, ReadCursor};
use justrdp_pdu::rdp::svc::{
    ChannelPduHeader, CHANNEL_CHUNK_LENGTH, CHANNEL_FLAG_SUSPEND, CHANNEL_FLAG_RESUME,
};

use crate::chunk;
use crate::dechunk::Dechunker;
use crate::{ChannelName, SvcError, SvcMessage, SvcProcessor, SvcResult};

/// Maximum number of static virtual channels (MS-RDPBCGR 2.2.1.3.4).
const MAX_CHANNELS: usize = 31;

/// A registered channel with its processor and dechunking state.
struct ChannelEntry {
    processor: Box<dyn SvcProcessor>,
    dechunker: Dechunker,
    /// Assigned MCS channel ID (0 if not yet assigned).
    mcs_channel_id: u16,
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
    pub fn set_chunk_size(&mut self, size: usize) {
        self.chunk_size = size;
    }

    /// Register a channel processor.
    ///
    /// Returns an error if the maximum number of channels (31) is exceeded
    /// or a channel with the same name already exists.
    pub fn insert(&mut self, processor: Box<dyn SvcProcessor>) -> SvcResult<()> {
        if self.entries.len() >= MAX_CHANNELS {
            return Err(SvcError::Protocol(String::from(
                "maximum 31 static virtual channels",
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
            mcs_channel_id: 0,
        });
        Ok(())
    }

    /// Assign MCS channel IDs from the connection result.
    ///
    /// `channel_ids` is the `ConnectionResult::channel_ids` mapping
    /// (channel_name, mcs_channel_id). Channels not present in the
    /// mapping will not be assigned an ID and will be ignored.
    pub fn assign_ids(&mut self, channel_ids: &[(String, u16)]) {
        for entry in &mut self.entries {
            let name = entry.processor.channel_name();
            if let Some((_, id)) = channel_ids.iter().find(|(n, _)| n.as_str() == name.as_str()) {
                entry.mcs_channel_id = *id;
            }
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
            if entry.mcs_channel_id == 0 {
                continue; // not assigned
            }
            let messages = entry.processor.start()?;
            if !messages.is_empty() {
                let channel_id = entry.mcs_channel_id;
                let frames = encode_messages(
                    user_channel_id,
                    channel_id,
                    &messages,
                    self.chunk_size,
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
        if raw_data.len() < 8 {
            return Err(SvcError::Protocol(String::from(
                "channel data too short for ChannelPduHeader",
            )));
        }
        let mut src = ReadCursor::new(raw_data);
        let hdr = ChannelPduHeader::decode(&mut src)?;
        let chunk_data = src.peek_remaining();

        // Handle SUSPEND/RESUME (affects all channels).
        if hdr.flags & CHANNEL_FLAG_SUSPEND != 0 {
            self.suspended = true;
            return Ok(Vec::new());
        }
        if hdr.flags & CHANNEL_FLAG_RESUME != 0 {
            self.suspended = false;
            return Ok(Vec::new());
        }

        if self.suspended {
            return Ok(Vec::new());
        }

        // Find the channel entry.
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.mcs_channel_id == channel_id);
        let entry = match entry {
            Some(e) => e,
            None => return Ok(Vec::new()), // unknown channel, ignore
        };

        // Feed chunk to dechunker.
        let complete = entry.dechunker.process_chunk(hdr.length, hdr.flags, chunk_data)?;

        if let Some(payload) = complete {
            // Complete message -- dispatch to processor.
            let responses = entry.processor.process(&payload)?;
            if responses.is_empty() {
                return Ok(Vec::new());
            }
            encode_messages(user_channel_id, channel_id, &responses, self.chunk_size)
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
        chunk::chunk_and_encode(user_channel_id, channel_id, &message.data, self.chunk_size, false)
    }

    /// Get a reference to a processor by MCS channel ID.
    pub fn get_by_channel_id(&self, channel_id: u16) -> Option<&dyn SvcProcessor> {
        self.entries
            .iter()
            .find(|e| e.mcs_channel_id == channel_id)
            .map(|e| &*e.processor)
    }

    /// Get a mutable reference to a processor by MCS channel ID.
    pub fn get_by_channel_id_mut(&mut self, channel_id: u16) -> Option<&mut dyn SvcProcessor> {
        self.entries
            .iter_mut()
            .find(|e| e.mcs_channel_id == channel_id)
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
            .find(|e| e.processor.channel_name() == name && e.mcs_channel_id != 0)
            .map(|e| e.mcs_channel_id)
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
) -> SvcResult<Vec<Vec<u8>>> {
    let mut all_frames = Vec::new();
    for msg in messages {
        let frames = chunk::chunk_and_encode(user_channel_id, channel_id, &msg.data, chunk_size, false)?;
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
        let mut buf = Vec::with_capacity(8 + data.len());
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
}
