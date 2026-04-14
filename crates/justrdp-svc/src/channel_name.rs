#![forbid(unsafe_code)]

//! Channel name type for static virtual channels.

use core::fmt;

/// A static virtual channel name (max 7 ASCII characters).
///
/// On the wire, channel names are 8-byte null-padded ASCII strings
/// (MS-RDPBCGR 2.2.1.3.4.1 CHANNEL_DEF::name).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelName {
    /// The 8-byte wire representation (null-padded).
    bytes: [u8; 8],
}

impl ChannelName {
    /// Create a channel name from a string.
    ///
    /// # Panics
    ///
    /// Panics if `name` is longer than 7 bytes or contains non-ASCII characters.
    pub const fn new(name: &[u8]) -> Self {
        assert!(name.len() <= 7, "channel name must be at most 7 bytes");
        let mut bytes = [0u8; 8];
        let mut i = 0;
        while i < name.len() {
            assert!(name[i].is_ascii(), "channel name must be ASCII");
            bytes[i] = name[i];
            i += 1;
        }
        Self { bytes }
    }

    /// Create from an 8-byte wire representation.
    ///
    /// Returns `None` if the name contains non-ASCII bytes or has
    /// non-zero bytes after the null terminator
    /// (MS-RDPBCGR 2.2.1.3.4.1: CHANNEL_DEF::name is a null-terminated ANSI string).
    pub fn from_wire(bytes: [u8; 8]) -> Option<Self> {
        let mut past_null = false;
        for &b in &bytes {
            if past_null {
                if b != 0 {
                    return None;
                }
            } else if b == 0 {
                past_null = true;
            } else if !b.is_ascii() {
                return None;
            }
        }
        // Must contain at least one null terminator (max 7 significant chars).
        if !past_null {
            return None;
        }
        Some(Self { bytes })
    }

    /// Get the wire representation.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.bytes
    }

    /// Get the name as a string slice (without null padding).
    ///
    /// ASCII-only content is guaranteed by both `new()` and `from_wire()`.
    pub fn as_str(&self) -> &str {
        let len = self.bytes.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.bytes[..len])
            .expect("ChannelName invariant: content is always valid ASCII")
    }
}

impl fmt::Debug for ChannelName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelName({:?})", self.as_str())
    }
}

impl fmt::Display for ChannelName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Well-known channel names ──

/// Clipboard redirection channel.
pub const CLIPRDR: ChannelName = ChannelName::new(b"cliprdr");
/// Audio output (sound) channel.
pub const RDPSND: ChannelName = ChannelName::new(b"rdpsnd");
/// Device redirection channel.
pub const RDPDR: ChannelName = ChannelName::new(b"rdpdr");
/// Dynamic Virtual Channel transport.
pub const DRDYNVC: ChannelName = ChannelName::new(b"drdynvc");
/// Remote Programs (RAIL) channel.
pub const RAIL: ChannelName = ChannelName::new(b"rail");
/// Multiparty Virtual Channel Extension channel (MS-RDPEMC §2.1).
pub const ENCOMSP: ChannelName = ChannelName::new(b"encomsp");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_name_as_str() {
        let name = ChannelName::new(b"cliprdr");
        assert_eq!(name.as_str(), "cliprdr");
    }

    #[test]
    fn channel_name_wire_format() {
        let name = ChannelName::new(b"rdpsnd");
        assert_eq!(name.as_bytes(), b"rdpsnd\0\0");
    }

    #[test]
    fn channel_name_equality() {
        assert_eq!(ChannelName::new(b"cliprdr"), CLIPRDR);
        assert_ne!(CLIPRDR, RDPSND);
    }

    #[test]
    fn channel_name_from_wire() {
        let name = ChannelName::from_wire(*b"rdpdr\0\0\0").unwrap();
        assert_eq!(name, RDPDR);
    }

    #[test]
    fn channel_name_from_wire_non_ascii_rejected() {
        assert!(ChannelName::from_wire([0xFF, 0x80, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn channel_name_from_wire_garbage_after_null_rejected() {
        // Bytes after null terminator must also be null.
        assert!(ChannelName::from_wire([b'a', 0, 0xFF, 0, 0, 0, 0, 0]).is_none());
        assert!(ChannelName::from_wire([b'a', b'b', 0, 0, 0, 1, 0, 0]).is_none());
    }

    #[test]
    fn channel_name_from_wire_no_null_terminator_rejected() {
        // All 8 bytes non-null — no room for null terminator.
        assert!(ChannelName::from_wire(*b"abcdefgh").is_none());
    }

    #[test]
    fn channel_name_display() {
        let name = ChannelName::new(b"drdynvc");
        assert_eq!(alloc::format!("{name}"), "drdynvc");
    }

    #[test]
    #[should_panic(expected = "at most 7 bytes")]
    fn channel_name_too_long() {
        let _ = ChannelName::new(b"toolongx");
    }

    #[test]
    #[should_panic(expected = "must be ASCII")]
    fn channel_name_non_ascii() {
        let _ = ChannelName::new(&[0xFF, 0x80]);
    }
}
