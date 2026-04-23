#![forbid(unsafe_code)]

//! `RdpServer` runtime configuration.

use justrdp_acceptor::AcceptorConfig;

use crate::error::ServerConfigError;

/// Default SVC chunk length emitted by the server. Matches
/// `CHANNEL_CHUNK_LENGTH = 1600` from MS-RDPBCGR §2.2.7.1.10.
pub const DEFAULT_CHANNEL_CHUNK_LENGTH: usize = 1600;

/// Hard cap on `channel_chunk_length` -- the spec's `CHANNEL_CHUNK_LENGTH`.
/// Real Windows clients have been observed to silently truncate chunks
/// larger than this, so the builder rejects oversized values up-front.
pub const MAX_CHANNEL_CHUNK_LENGTH: usize = 1600;

/// Conservative default for `max_bitmap_fragment_size`. Leaves room for
/// the fast-path output header (3 bytes), the per-update updateHeader +
/// size (1 + 2 = 3 bytes), and the `TS_UPDATE_BITMAP_DATA` numberRectangles
/// (2 bytes) within a fast-path PDU bounded by the 15-bit length field.
pub const DEFAULT_MAX_BITMAP_FRAGMENT_SIZE: usize = 16_364;

/// Hard cap on `max_bitmap_fragment_size` derived from the fast-path
/// 15-bit length field (`0x7FFF = 32_767`) minus a safety margin for the
/// outer headers.
pub const MAX_BITMAP_FRAGMENT_SIZE_LIMIT: usize = 32_767 - 16;

/// Configuration for [`RdpServer`].
///
/// Wraps the [`AcceptorConfig`] used during the connection-acceptance phase
/// and adds the runtime parameters that govern the active-session loop
/// (chunk sizing, bitmap fragmentation thresholds).
///
/// [`RdpServer`]: crate::RdpServer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpServerConfig {
    /// Configuration for the wrapped `ServerAcceptor` driving the
    /// X.224 / MCS / Capability Exchange / Finalization handshake.
    pub acceptor_config: AcceptorConfig,
    /// Maximum byte count of a single fast-path bitmap fragment payload.
    /// Larger updates MUST be split via the
    /// `Fragmentation::First`/`Next`/`Last` markers on
    /// `FastPathOutputUpdate`.
    pub max_bitmap_fragment_size: usize,
    /// Per-chunk length used when forwarding SVC data outbound. Bounded
    /// above by [`MAX_CHANNEL_CHUNK_LENGTH`] (MS-RDPBCGR §2.2.7.1.10).
    pub channel_chunk_length: usize,
}

impl Default for RdpServerConfig {
    fn default() -> Self {
        Self {
            acceptor_config: AcceptorConfig::default(),
            max_bitmap_fragment_size: DEFAULT_MAX_BITMAP_FRAGMENT_SIZE,
            channel_chunk_length: DEFAULT_CHANNEL_CHUNK_LENGTH,
        }
    }
}

impl RdpServerConfig {
    /// Start a new builder pre-populated with default values.
    pub fn builder() -> RdpServerConfigBuilder {
        RdpServerConfigBuilder::new()
    }
}

/// Builder for [`RdpServerConfig`].
#[derive(Debug, Clone)]
pub struct RdpServerConfigBuilder {
    inner: RdpServerConfig,
}

impl RdpServerConfigBuilder {
    pub fn new() -> Self {
        Self {
            inner: RdpServerConfig::default(),
        }
    }

    pub fn acceptor_config(mut self, cfg: AcceptorConfig) -> Self {
        self.inner.acceptor_config = cfg;
        self
    }

    pub fn max_bitmap_fragment_size(mut self, size: usize) -> Self {
        self.inner.max_bitmap_fragment_size = size;
        self
    }

    pub fn channel_chunk_length(mut self, size: usize) -> Self {
        self.inner.channel_chunk_length = size;
        self
    }

    /// Validate and build the config.
    pub fn build(self) -> Result<RdpServerConfig, ServerConfigError> {
        let cfg = self.inner;
        if cfg.channel_chunk_length < 8 || cfg.channel_chunk_length > MAX_CHANNEL_CHUNK_LENGTH {
            return Err(ServerConfigError::InvalidChannelChunkLength {
                value: cfg.channel_chunk_length,
            });
        }
        if cfg.max_bitmap_fragment_size == 0
            || cfg.max_bitmap_fragment_size > MAX_BITMAP_FRAGMENT_SIZE_LIMIT
        {
            return Err(ServerConfigError::InvalidBitmapFragmentSize {
                value: cfg.max_bitmap_fragment_size,
                limit: MAX_BITMAP_FRAGMENT_SIZE_LIMIT,
            });
        }
        Ok(cfg)
    }
}

impl Default for RdpServerConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    #[test]
    fn defaults_pass_validation() {
        let cfg = RdpServerConfig::builder().build().unwrap();
        assert_eq!(cfg.channel_chunk_length, DEFAULT_CHANNEL_CHUNK_LENGTH);
        assert_eq!(cfg.max_bitmap_fragment_size, DEFAULT_MAX_BITMAP_FRAGMENT_SIZE);
    }

    #[test]
    fn rejects_zero_chunk_length() {
        let err = RdpServerConfig::builder()
            .channel_chunk_length(0)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ServerConfigError::InvalidChannelChunkLength { .. }
        ));
    }

    #[test]
    fn rejects_too_small_chunk_length() {
        // < 8 leaves no room for ChannelPduHeader (8 bytes).
        let err = RdpServerConfig::builder()
            .channel_chunk_length(7)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ServerConfigError::InvalidChannelChunkLength { value: 7 }
        ));
    }

    #[test]
    fn accepts_min_chunk_length() {
        let cfg = RdpServerConfig::builder()
            .channel_chunk_length(8)
            .build()
            .unwrap();
        assert_eq!(cfg.channel_chunk_length, 8);
    }

    #[test]
    fn accepts_max_chunk_length() {
        let cfg = RdpServerConfig::builder()
            .channel_chunk_length(MAX_CHANNEL_CHUNK_LENGTH)
            .build()
            .unwrap();
        assert_eq!(cfg.channel_chunk_length, MAX_CHANNEL_CHUNK_LENGTH);
    }

    #[test]
    fn rejects_oversized_chunk_length() {
        let err = RdpServerConfig::builder()
            .channel_chunk_length(MAX_CHANNEL_CHUNK_LENGTH + 1)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ServerConfigError::InvalidChannelChunkLength { .. }
        ));
    }

    #[test]
    fn rejects_zero_bitmap_fragment_size() {
        let err = RdpServerConfig::builder()
            .max_bitmap_fragment_size(0)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ServerConfigError::InvalidBitmapFragmentSize { value: 0, .. }
        ));
    }

    #[test]
    fn rejects_oversized_bitmap_fragment_size() {
        let err = RdpServerConfig::builder()
            .max_bitmap_fragment_size(MAX_BITMAP_FRAGMENT_SIZE_LIMIT + 1)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ServerConfigError::InvalidBitmapFragmentSize { .. }
        ));
    }

    #[test]
    fn accepts_max_bitmap_fragment_size() {
        let cfg = RdpServerConfig::builder()
            .max_bitmap_fragment_size(MAX_BITMAP_FRAGMENT_SIZE_LIMIT)
            .build()
            .unwrap();
        assert_eq!(cfg.max_bitmap_fragment_size, MAX_BITMAP_FRAGMENT_SIZE_LIMIT);
    }

    #[test]
    fn config_error_display_mentions_spec_section() {
        let err = ServerConfigError::InvalidChannelChunkLength { value: 0 };
        let s = alloc::format!("{err}");
        assert!(s.contains("CHANNEL_CHUNK_LENGTH"), "got: {s}");
        assert!(s.contains("2.2.7.1.10"), "got: {s}");
    }
}
