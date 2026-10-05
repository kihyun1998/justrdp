//! What the connect layer may advertise: the allow-lists [`check`] holds a [`ConnectConfig`]
//! against before the connection starts (ADR-0016 Decision 3). The config still reaches the
//! wire verbatim; an advertisement the core cannot honour is refused instead of sent.
//!
//! Every list here names what the core handles, so it grows as the core implements more.

use crate::connect::ConnectConfig;
use justrdp_pdu::capability::{self, CapabilitySet};
use justrdp_pdu::client_info::ClientInfoFlags;
use justrdp_pdu::gcc::{self, ClientEarlyCapabilityFlags};

/// The `earlyCapabilityFlags` the core honours.
pub const HONOURED_EARLY_CAPABILITY_FLAGS: ClientEarlyCapabilityFlags =
    ClientEarlyCapabilityFlags::from_bits(
        ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU.bits()
            | ClientEarlyCapabilityFlags::WANT_32_BPP_SESSION.bits()
            | ClientEarlyCapabilityFlags::STRONG_ASYMMETRIC_KEYS.bits()
            | ClientEarlyCapabilityFlags::RELATIVE_MOUSE_INPUT.bits()
            | ClientEarlyCapabilityFlags::VALID_CONNECTION_TYPE.bits()
            | ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL.bits()
            | ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN.bits(),
    );

/// The Client Info `flags` the core honours.
pub const HONOURED_CLIENT_INFO_FLAGS: ClientInfoFlags = ClientInfoFlags::from_bits(
    ClientInfoFlags::MOUSE.bits()
        | ClientInfoFlags::DISABLE_CTRL_ALT_DEL.bits()
        | ClientInfoFlags::AUTOLOGON.bits()
        | ClientInfoFlags::UNICODE.bits()
        | ClientInfoFlags::MAXIMIZE_SHELL.bits()
        | ClientInfoFlags::LOGON_NOTIFY.bits()
        | ClientInfoFlags::ENABLE_WINDOWS_KEY.bits()
        | ClientInfoFlags::REMOTE_CONSOLE_AUDIO.bits()
        | ClientInfoFlags::FORCE_ENCRYPTED_CS_PDU.bits()
        | ClientInfoFlags::LOGON_ERRORS.bits()
        | ClientInfoFlags::MOUSE_HAS_WHEEL.bits()
        | ClientInfoFlags::PASSWORD_IS_SC_PIN.bits()
        | ClientInfoFlags::NO_AUDIO_PLAYBACK.bits()
        | ClientInfoFlags::USING_SAVED_CREDS.bits()
        | ClientInfoFlags::VIDEO_DISABLE.bits(),
);

/// The static channel `options` the core honours.
pub const HONOURED_CHANNEL_OPTIONS: u32 = gcc::CHANNEL_OPTION_INITIALIZED
    | gcc::CHANNEL_OPTION_ENCRYPT_RDP
    | gcc::CHANNEL_OPTION_ENCRYPT_SC
    | gcc::CHANNEL_OPTION_ENCRYPT_CS
    | gcc::CHANNEL_OPTION_PRI_HIGH
    | gcc::CHANNEL_OPTION_PRI_MED
    | gcc::CHANNEL_OPTION_PRI_LOW
    | gcc::CHANNEL_OPTION_SHOW_PROTOCOL
    | gcc::CHANNEL_OPTION_REMOTE_CONTROL_PERSISTENT;

/// The General set's `extraFlags` the core honours.
pub const HONOURED_GENERAL_EXTRA_FLAGS: u16 = capability::GENERAL_FASTPATH_OUTPUT_SUPPORTED
    | capability::GENERAL_LONG_CREDENTIALS_SUPPORTED
    | capability::GENERAL_AUTORECONNECT_SUPPORTED
    | capability::GENERAL_ENC_SALTED_CHECKSUM
    | capability::GENERAL_NO_BITMAP_COMPRESSION_HDR;

/// The Bitmap set's `drawingFlags` the core honours.
pub const HONOURED_DRAWING_FLAGS: u8 = capability::DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY
    | capability::DRAW_ALLOW_COLOR_SUBSAMPLING
    | capability::DRAW_ALLOW_SKIP_ALPHA
    | capability::DRAW_UNUSED_FLAG;

/// The Virtual Channel set's `flags` the core honours.
pub const HONOURED_VIRTUAL_CHANNEL_FLAGS: u32 = capability::VCCAPS_COMPR_CS_8K;

/// The Sound set's `soundFlags` the core honours.
pub const HONOURED_SOUND_FLAGS: u16 = capability::SOUND_FLAG_BEEPS;

/// The Surface Commands set's `cmdFlags` the core honours.
pub const HONOURED_SURFACE_COMMANDS: u32 = capability::SURFCMDS_SET_SURFACE_BITS;

/// The largest Multifragment Update `MaxRequestSize` the core honours: the session's fast-path
/// reassembly cap at its floor, which no desktop size lowers.
pub const HONOURED_MAX_REQUEST_SIZE: u32 = (1 << 20) + (64 << 10);

/// Why a [`ConnectConfig`] cannot be advertised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectConfigError {
    /// `earlyCapabilityFlags` outside [`HONOURED_EARLY_CAPABILITY_FLAGS`]: the refused bits.
    EarlyCapabilityFlags(ClientEarlyCapabilityFlags),
    /// Client Info `flags` outside [`HONOURED_CLIENT_INFO_FLAGS`]: the refused bits.
    ClientInfoFlags(ClientInfoFlags),
    /// A static channel's `options` outside [`HONOURED_CHANNEL_OPTIONS`].
    ChannelOptions {
        /// The channel name.
        channel: String,
        /// The refused option bits.
        options: u32,
    },
    /// A capability set whose contents invite traffic the core does not handle.
    CapabilitySet {
        /// `capabilitySetType`.
        set_type: u16,
        /// What in it is refused.
        reason: &'static str,
    },
    /// A capability set the core cannot read, and so cannot judge.
    UnreadableCapabilitySet {
        /// `capabilitySetType`.
        set_type: u16,
    },
}

impl core::fmt::Display for ConnectConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EarlyCapabilityFlags(bits) => write!(
                f,
                "earlyCapabilityFlags {:#06x} cannot be honoured",
                bits.bits()
            ),
            Self::ClientInfoFlags(bits) => {
                write!(
                    f,
                    "Client Info flags {:#010x} cannot be honoured",
                    bits.bits()
                )
            }
            Self::ChannelOptions { channel, options } => write!(
                f,
                "channel {channel:?} options {options:#010x} cannot be honoured"
            ),
            Self::CapabilitySet { set_type, reason } => {
                write!(
                    f,
                    "capability set {set_type:#06x} cannot be honoured: {reason}"
                )
            }
            Self::UnreadableCapabilitySet { set_type } => {
                write!(
                    f,
                    "capability set {set_type:#06x} cannot be read, so it cannot be judged"
                )
            }
        }
    }
}

impl core::error::Error for ConnectConfigError {}

/// Refuse the first advertisement in `config` the core cannot honour.
pub fn check(config: &ConnectConfig) -> Result<(), ConnectConfigError> {
    let early = config.core.early_capability_flags.bits() & !HONOURED_EARLY_CAPABILITY_FLAGS.bits();
    if early != 0 {
        return Err(ConnectConfigError::EarlyCapabilityFlags(
            ClientEarlyCapabilityFlags::from_bits(early),
        ));
    }
    let info = config.client_info.flags.bits() & !HONOURED_CLIENT_INFO_FLAGS.bits();
    if info != 0 {
        return Err(ConnectConfigError::ClientInfoFlags(
            ClientInfoFlags::from_bits(info),
        ));
    }
    for channel in &config.channels {
        let options = channel.options & !HONOURED_CHANNEL_OPTIONS;
        if options != 0 {
            return Err(ConnectConfigError::ChannelOptions {
                channel: channel.name_str().to_string(),
                options,
            });
        }
    }
    config
        .capabilities
        .iter()
        .try_for_each(check_capability_set)?;
    let surface_commands = config
        .capabilities
        .iter()
        .any(|set| matches!(set, CapabilitySet::SurfaceCommands(s) if s.cmd_flags != 0));
    let fastpath_output = config.capabilities.iter().any(|set| {
        matches!(set, CapabilitySet::General(g)
            if g.extra_flags & capability::GENERAL_FASTPATH_OUTPUT_SUPPORTED != 0)
    });
    if surface_commands && !fastpath_output {
        return refuse(
            capability::CAPSET_SURFACE_COMMANDS,
            "surface commands require FASTPATH_OUTPUT_SUPPORTED in the General set (2.2.7.2.9)",
        );
    }
    Ok(())
}

fn refuse(set_type: u16, reason: &'static str) -> Result<(), ConnectConfigError> {
    Err(ConnectConfigError::CapabilitySet { set_type, reason })
}

/// Refuse a capability set whose contents invite traffic the core does not handle.
fn check_capability_set(set: &CapabilitySet) -> Result<(), ConnectConfigError> {
    match set {
        CapabilitySet::General(g) if g.extra_flags & !HONOURED_GENERAL_EXTRA_FLAGS != 0 => refuse(
            capability::CAPSET_GENERAL,
            "extraFlags outside the honoured set",
        ),
        CapabilitySet::Bitmap(b) if b.drawing_flags & !HONOURED_DRAWING_FLAGS != 0 => refuse(
            capability::CAPSET_BITMAP,
            "drawingFlags outside the honoured set",
        ),
        CapabilitySet::Order(o) if o.order_support.iter().any(|&order| order != 0) => refuse(
            capability::CAPSET_ORDER,
            "orderSupport enables drawing orders, which the session skips",
        ),
        CapabilitySet::BitmapCache(c) if c.caches.iter().any(|&(entries, _)| entries != 0) => {
            refuse(
                capability::CAPSET_BITMAP_CACHE,
                "a bitmap cache invites Cache Bitmap orders, which the session skips",
            )
        }
        CapabilitySet::Brush(b) if b.brush_support_level != 0 => refuse(
            capability::CAPSET_BRUSH,
            "a brush level above BRUSH_DEFAULT invites Cache Brush orders",
        ),
        CapabilitySet::GlyphCache(g) if g.glyph_support_level != 0 => refuse(
            capability::CAPSET_GLYPH_CACHE,
            "a glyph level above GLYPH_SUPPORT_NONE invites glyph orders",
        ),
        CapabilitySet::OffscreenCache(o) if o.offscreen_support_level != 0 => refuse(
            capability::CAPSET_OFFSCREEN_CACHE,
            "an offscreen cache invites offscreen bitmap orders",
        ),
        CapabilitySet::VirtualChannel(v) if v.flags & !HONOURED_VIRTUAL_CHANNEL_FLAGS != 0 => {
            refuse(
                capability::CAPSET_VIRTUAL_CHANNEL,
                "VCCAPS_COMPR_SC invites compressed channel data, which is refused",
            )
        }
        CapabilitySet::Sound(s) if s.sound_flags & !HONOURED_SOUND_FLAGS != 0 => refuse(
            capability::CAPSET_SOUND,
            "soundFlags outside SOUND_FLAG_BEEPS",
        ),
        CapabilitySet::SurfaceCommands(c) if c.cmd_flags & !HONOURED_SURFACE_COMMANDS != 0 => {
            refuse(
                capability::CAPSET_SURFACE_COMMANDS,
                "cmdFlags outside the honoured set",
            )
        }
        CapabilitySet::MultifragmentUpdate(m) if m.max_request_size > HONOURED_MAX_REQUEST_SIZE => {
            refuse(
                capability::CAPSET_MULTIFRAGMENT_UPDATE,
                "MaxRequestSize above the session's fast-path reassembly cap",
            )
        }
        CapabilitySet::BitmapCodecs(c) => c.codecs.iter().try_for_each(check_bitmap_codec),
        CapabilitySet::Unknown { set_type, .. } => {
            Err(ConnectConfigError::UnreadableCapabilitySet {
                set_type: *set_type,
            })
        }
        _ => Ok(()),
    }
}

/// Refuse a Bitmap Codecs entry the session cannot decode: only NSCodec, at the codec ID
/// 2.2.7.2.10.1.1 fixes for it, with properties the decoder handles.
fn check_bitmap_codec(codec: &capability::BitmapCodec) -> Result<(), ConnectConfigError> {
    let reason = if codec.guid != capability::CODEC_GUID_NSCODEC {
        "the session decodes NSCodec alone"
    } else if codec.id != capability::CODEC_ID_NSCODEC {
        "NSCodec's codecID must be 1"
    } else if capability::NsCodecProperties::decode(&codec.properties).is_err() {
        "NSCodec properties outside TS_NSCODEC_CAPABILITYSET"
    } else {
        return Ok(());
    };
    refuse(capability::CAPSET_BITMAP_CODECS, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::tests::config;
    use justrdp_pdu::capability::{
        BitmapCacheCapabilitySet, BitmapCodec, BitmapCodecsCapabilitySet, BrushCapabilitySet,
        GlyphCacheCapabilitySet, OffscreenCacheCapabilitySet, OrderCapabilitySet,
        SoundCapabilitySet, VirtualChannelCapabilitySet,
    };

    /// Issue #357: the shipped defaults — `ClientCoreData::default`, the default capability
    /// sets, and the Client Info flags the adapter's tests send — advertise nothing refused.
    #[test]
    fn the_defaults_pass() {
        let mut config = config();
        assert_eq!(check(&config), Ok(()));
        config.core = gcc::ClientCoreData::default();
        config.capabilities = capability::default_client_capabilities(&config.core);
        config.client_info.flags = ClientInfoFlags::MOUSE
            | ClientInfoFlags::AUTOLOGON
            | ClientInfoFlags::LOGON_NOTIFY
            | ClientInfoFlags::LOGON_ERRORS
            | ClientInfoFlags::MOUSE_HAS_WHEEL;
        assert_eq!(check(&config), Ok(()));
    }

    /// The machine itself refuses: no machine, so no action and no byte.
    #[test]
    fn the_machine_refuses_an_unhonourable_config() {
        let mut config = config();
        config.client_info.flags = ClientInfoFlags::MOUSE | ClientInfoFlags::COMPRESSION;
        assert_eq!(
            crate::ConnectStateMachine::new(config).err(),
            Some(ConnectConfigError::ClientInfoFlags(
                ClientInfoFlags::COMPRESSION
            ))
        );
    }

    #[test]
    fn every_honoured_early_flag_passes_and_every_other_bit_is_refused() {
        let mut config = config();
        config.core.early_capability_flags = HONOURED_EARLY_CAPABILITY_FLAGS;
        assert_eq!(check(&config), Ok(()));
        for bit in (0..16).map(|n| 1u16 << n) {
            config.core.early_capability_flags = ClientEarlyCapabilityFlags::from_bits(bit);
            let honoured = HONOURED_EARLY_CAPABILITY_FLAGS.bits() & bit != 0;
            assert_eq!(
                check(&config).is_ok(),
                honoured,
                "earlyCapabilityFlags {bit:#06x}"
            );
        }
        config.core.early_capability_flags = ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU
            | ClientEarlyCapabilityFlags::SUPPORT_HEART_BEAT_PDU;
        assert_eq!(
            check(&config),
            Err(ConnectConfigError::EarlyCapabilityFlags(
                ClientEarlyCapabilityFlags::SUPPORT_HEART_BEAT_PDU
            )),
            "the error names the refused bits alone"
        );
    }

    /// The honoured early flags and Client Info flags, named rather than read back from the
    /// constants, so a flag dropped from an allow-list is seen.
    #[test]
    fn the_honourable_flags_pass_one_by_one() {
        for flag in [
            ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU,
            ClientEarlyCapabilityFlags::WANT_32_BPP_SESSION,
            ClientEarlyCapabilityFlags::STRONG_ASYMMETRIC_KEYS,
            ClientEarlyCapabilityFlags::RELATIVE_MOUSE_INPUT,
            ClientEarlyCapabilityFlags::VALID_CONNECTION_TYPE,
            ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL,
            ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN,
        ] {
            let mut config = config();
            config.core.early_capability_flags = flag;
            assert_eq!(check(&config), Ok(()), "{flag:?}");
        }
        for flag in [
            ClientInfoFlags::MOUSE,
            ClientInfoFlags::DISABLE_CTRL_ALT_DEL,
            ClientInfoFlags::AUTOLOGON,
            ClientInfoFlags::UNICODE,
            ClientInfoFlags::MAXIMIZE_SHELL,
            ClientInfoFlags::LOGON_NOTIFY,
            ClientInfoFlags::ENABLE_WINDOWS_KEY,
            ClientInfoFlags::REMOTE_CONSOLE_AUDIO,
            ClientInfoFlags::FORCE_ENCRYPTED_CS_PDU,
            ClientInfoFlags::LOGON_ERRORS,
            ClientInfoFlags::MOUSE_HAS_WHEEL,
            ClientInfoFlags::PASSWORD_IS_SC_PIN,
            ClientInfoFlags::NO_AUDIO_PLAYBACK,
            ClientInfoFlags::USING_SAVED_CREDS,
            ClientInfoFlags::VIDEO_DISABLE,
        ] {
            let mut config = config();
            config.client_info.flags = flag;
            assert_eq!(check(&config), Ok(()), "{flag:?}");
        }
        for option in [
            gcc::CHANNEL_OPTION_INITIALIZED,
            gcc::CHANNEL_OPTION_ENCRYPT_RDP,
            gcc::CHANNEL_OPTION_ENCRYPT_SC,
            gcc::CHANNEL_OPTION_ENCRYPT_CS,
            gcc::CHANNEL_OPTION_PRI_HIGH,
            gcc::CHANNEL_OPTION_PRI_MED,
            gcc::CHANNEL_OPTION_PRI_LOW,
            gcc::CHANNEL_OPTION_SHOW_PROTOCOL,
            gcc::CHANNEL_OPTION_REMOTE_CONTROL_PERSISTENT,
        ] {
            let mut config = config();
            config.channels = vec![gcc::ChannelDef::new("rdpsnd", option).unwrap()];
            assert_eq!(check(&config), Ok(()), "{option:#010x}");
        }
    }

    /// The refused early flags, each for the reason the map's table gives.
    #[test]
    fn the_unhonourable_early_flags_are_refused() {
        for flag in [
            ClientEarlyCapabilityFlags::SUPPORT_STATUS_INFO_PDU,
            ClientEarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU,
            ClientEarlyCapabilityFlags::SUPPORT_NET_CHAR_AUTODETECT,
            ClientEarlyCapabilityFlags::SUPPORT_DYNAMIC_TIME_ZONE,
            ClientEarlyCapabilityFlags::SUPPORT_HEART_BEAT_PDU,
        ] {
            let mut config = config();
            config.core.early_capability_flags = flag;
            assert_eq!(
                check(&config),
                Err(ConnectConfigError::EarlyCapabilityFlags(flag))
            );
        }
    }

    #[test]
    fn every_honoured_info_flag_passes_and_every_other_bit_is_refused() {
        let mut config = config();
        config.client_info.flags = HONOURED_CLIENT_INFO_FLAGS;
        assert_eq!(check(&config), Ok(()));
        for bit in (0..32).map(|n| 1u32 << n) {
            config.client_info.flags = ClientInfoFlags::from_bits(bit);
            let honoured = HONOURED_CLIENT_INFO_FLAGS.bits() & bit != 0;
            assert_eq!(
                check(&config).is_ok(),
                honoured,
                "Client Info flag {bit:#010x}"
            );
        }
        for flag in [
            ClientInfoFlags::COMPRESSION,
            ClientInfoFlags::COMPRESSION_TYPE_MASK,
            ClientInfoFlags::RAIL,
            ClientInfoFlags::AUDIO_CAPTURE,
            ClientInfoFlags::HIDEF_RAIL_SUPPORTED,
        ] {
            config.client_info.flags = ClientInfoFlags::MOUSE | flag;
            assert_eq!(
                check(&config),
                Err(ConnectConfigError::ClientInfoFlags(flag))
            );
        }
    }

    #[test]
    fn a_compressing_channel_option_is_refused() {
        for option in [
            gcc::CHANNEL_OPTION_COMPRESS_RDP,
            gcc::CHANNEL_OPTION_COMPRESS,
        ] {
            let mut config = config();
            config.channels.push(
                gcc::ChannelDef::new("rdpsnd", gcc::CHANNEL_OPTION_INITIALIZED | option).unwrap(),
            );
            assert_eq!(
                check(&config),
                Err(ConnectConfigError::ChannelOptions {
                    channel: "rdpsnd".to_string(),
                    options: option,
                })
            );
        }
        let mut config = config();
        config
            .channels
            .push(gcc::ChannelDef::new("rdpsnd", HONOURED_CHANNEL_OPTIONS).unwrap());
        assert_eq!(check(&config), Ok(()));
    }

    fn with_set(set: CapabilitySet) -> Result<(), ConnectConfigError> {
        let mut config = config();
        config.capabilities.push(set);
        check(&config)
    }

    fn refused_type(result: Result<(), ConnectConfigError>) -> Option<u16> {
        match result {
            Err(ConnectConfigError::CapabilitySet { set_type, .. }) => Some(set_type),
            _ => None,
        }
    }

    /// Each set whose contents invite skipped or refused traffic is refused, by its own type.
    #[test]
    fn capability_sets_that_invite_unhandled_traffic_are_refused() {
        let mut orders = OrderCapabilitySet::default();
        orders.order_support[0] = 1; // TS_NEG_DSTBLT_INDEX
        let mut general = crate::connect::tests::config()
            .capabilities
            .into_iter()
            .find_map(|s| match s {
                CapabilitySet::General(g) => Some(g),
                _ => None,
            })
            .unwrap();
        general.extra_flags |= 0x0002;
        let mut bitmap = capability::BitmapCapabilitySet {
            drawing_flags: 0x01,
            ..Default::default()
        };
        bitmap.desktop_width = 1280;
        for (set, set_type) in [
            (CapabilitySet::General(general), capability::CAPSET_GENERAL),
            (CapabilitySet::Bitmap(bitmap), capability::CAPSET_BITMAP),
            (CapabilitySet::Order(orders), capability::CAPSET_ORDER),
            (
                CapabilitySet::BitmapCache(BitmapCacheCapabilitySet {
                    caches: [(0, 0), (120, 1024), (0, 0)],
                }),
                capability::CAPSET_BITMAP_CACHE,
            ),
            (
                CapabilitySet::Brush(BrushCapabilitySet {
                    brush_support_level: 1,
                }),
                capability::CAPSET_BRUSH,
            ),
            (
                CapabilitySet::GlyphCache(GlyphCacheCapabilitySet {
                    glyph_support_level: 2,
                    ..Default::default()
                }),
                capability::CAPSET_GLYPH_CACHE,
            ),
            (
                CapabilitySet::OffscreenCache(OffscreenCacheCapabilitySet {
                    offscreen_support_level: 1,
                    ..Default::default()
                }),
                capability::CAPSET_OFFSCREEN_CACHE,
            ),
            (
                CapabilitySet::VirtualChannel(VirtualChannelCapabilitySet {
                    flags: capability::VCCAPS_COMPR_SC,
                    chunk_size: 1600,
                }),
                capability::CAPSET_VIRTUAL_CHANNEL,
            ),
            (
                CapabilitySet::Sound(SoundCapabilitySet {
                    sound_flags: 0x0002,
                }),
                capability::CAPSET_SOUND,
            ),
            (
                CapabilitySet::BitmapCodecs(BitmapCodecsCapabilitySet {
                    codecs: vec![BitmapCodec {
                        guid: [0xAA; 16],
                        id: 1,
                        properties: Vec::new(),
                    }],
                }),
                capability::CAPSET_BITMAP_CODECS,
            ),
        ] {
            assert_eq!(
                refused_type(with_set(set.clone())),
                Some(set_type),
                "{set:?}"
            );
        }
    }

    /// The honoured edges of the same sets pass: every honoured flag, empty codecs.
    #[test]
    fn capability_sets_within_the_honoured_edges_pass() {
        for set in [
            CapabilitySet::VirtualChannel(VirtualChannelCapabilitySet {
                flags: capability::VCCAPS_COMPR_CS_8K,
                chunk_size: 1600,
            }),
            CapabilitySet::Bitmap(capability::BitmapCapabilitySet {
                drawing_flags: capability::DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY
                    | capability::DRAW_ALLOW_COLOR_SUBSAMPLING
                    | capability::DRAW_ALLOW_SKIP_ALPHA
                    | capability::DRAW_UNUSED_FLAG,
                ..Default::default()
            }),
            CapabilitySet::BitmapCodecs(BitmapCodecsCapabilitySet::default()),
            CapabilitySet::BitmapCache(BitmapCacheCapabilitySet {
                caches: [(0, 1024), (0, 2048), (0, 4096)],
            }),
        ] {
            assert_eq!(with_set(set.clone()), Ok(()), "{set:?}");
        }
    }

    /// A set the core cannot read cannot be judged, so it is refused.
    #[test]
    fn an_unreadable_capability_set_is_refused() {
        for set_type in [0x0005, 0x001B, 0x0013, 0x001E] {
            assert_eq!(
                with_set(CapabilitySet::Unknown {
                    set_type,
                    data: vec![0; 4],
                }),
                Err(ConnectConfigError::UnreadableCapabilitySet { set_type })
            );
        }
    }

    fn nscodec(id: u8, properties: Vec<u8>) -> CapabilitySet {
        CapabilitySet::BitmapCodecs(BitmapCodecsCapabilitySet {
            codecs: vec![BitmapCodec {
                guid: capability::CODEC_GUID_NSCODEC,
                id,
                properties,
            }],
        })
    }

    /// Issue #150: Set Surface Bits carrying NSCodec is honoured at its edges: every honoured
    /// command flag, the reassembly floor as `MaxRequestSize`, NSCodec at codec ID 1 with any
    /// properties the spec allows.
    #[test]
    fn surface_bits_with_nscodec_pass_at_their_edges() {
        for set in [
            CapabilitySet::SurfaceCommands(capability::SurfaceCommandsCapabilitySet {
                cmd_flags: capability::SURFCMDS_SET_SURFACE_BITS,
            }),
            CapabilitySet::MultifragmentUpdate(capability::MultifragmentUpdateCapabilitySet {
                max_request_size: HONOURED_MAX_REQUEST_SIZE,
            }),
            nscodec(capability::CODEC_ID_NSCODEC, vec![0, 0, 1]),
            nscodec(capability::CODEC_ID_NSCODEC, vec![1, 1, 7]),
        ] {
            assert_eq!(with_set(set.clone()), Ok(()), "{set:?}");
        }
    }

    /// Issue #150: past those edges each set is refused by its own type.
    #[test]
    fn surface_bits_with_nscodec_are_refused_past_their_edges() {
        for (set, set_type) in [
            (
                CapabilitySet::SurfaceCommands(capability::SurfaceCommandsCapabilitySet {
                    cmd_flags: capability::SURFCMDS_SET_SURFACE_BITS | 0x0000_0001,
                }),
                capability::CAPSET_SURFACE_COMMANDS,
            ),
            // The session drops Frame Markers, so it does not invite them.
            (
                CapabilitySet::SurfaceCommands(capability::SurfaceCommandsCapabilitySet {
                    cmd_flags: capability::SURFCMDS_SET_SURFACE_BITS
                        | capability::SURFCMDS_FRAME_MARKER,
                }),
                capability::CAPSET_SURFACE_COMMANDS,
            ),
            // 2.2.9.2.2 gives Stream Surface Bits' destination bounds a meaning the session
            // does not read.
            (
                CapabilitySet::SurfaceCommands(capability::SurfaceCommandsCapabilitySet {
                    cmd_flags: capability::SURFCMDS_STREAM_SURFACE_BITS,
                }),
                capability::CAPSET_SURFACE_COMMANDS,
            ),
            (
                CapabilitySet::MultifragmentUpdate(capability::MultifragmentUpdateCapabilitySet {
                    max_request_size: HONOURED_MAX_REQUEST_SIZE + 1,
                }),
                capability::CAPSET_MULTIFRAGMENT_UPDATE,
            ),
            (nscodec(2, vec![1, 1, 3]), capability::CAPSET_BITMAP_CODECS),
            (
                nscodec(capability::CODEC_ID_NSCODEC, vec![1, 1, 8]),
                capability::CAPSET_BITMAP_CODECS,
            ),
            (
                nscodec(capability::CODEC_ID_NSCODEC, Vec::new()),
                capability::CAPSET_BITMAP_CODECS,
            ),
        ] {
            assert_eq!(
                refused_type(with_set(set.clone())),
                Some(set_type),
                "{set:?}"
            );
        }
    }

    /// 2.2.7.2.9: a client advertising surface commands MUST set `FASTPATH_OUTPUT_SUPPORTED`.
    #[test]
    fn surface_commands_without_fastpath_output_are_refused() {
        let mut config = config();
        for set in &mut config.capabilities {
            if let CapabilitySet::General(g) = set {
                g.extra_flags &= !capability::GENERAL_FASTPATH_OUTPUT_SUPPORTED;
            }
        }
        config
            .capabilities
            .retain(|set| !matches!(set, CapabilitySet::SurfaceCommands(_)));
        assert_eq!(check(&config), Ok(()), "no surface commands, no obligation");
        config.capabilities.push(CapabilitySet::SurfaceCommands(
            capability::SurfaceCommandsCapabilitySet { cmd_flags: 0 },
        ));
        assert_eq!(check(&config), Ok(()), "no command flags, no obligation");
        config.capabilities.push(CapabilitySet::SurfaceCommands(
            capability::SurfaceCommandsCapabilitySet {
                cmd_flags: capability::SURFCMDS_SET_SURFACE_BITS,
            },
        ));
        assert_eq!(
            refused_type(check(&config)),
            Some(capability::CAPSET_SURFACE_COMMANDS)
        );
    }
}
