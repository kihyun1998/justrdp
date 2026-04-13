#![no_std]
#![forbid(unsafe_code)]

//! Video Optimized Remoting Virtual Channel Extension -- MS-RDPEVOR
//!
//! Implements the two DVCs used by the server to stream H.264 video
//! samples to the client:
//!
//! - `Microsoft::Windows::RDS::Video::Control::v08.01`
//! - `Microsoft::Windows::RDS::Video::Data::v08.01`
//!
//! The crate only provides wire-format PDUs, DVC processors and a
//! `VideoDecoder` abstraction -- there is no in-tree H.264 decoder.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod pdu;

#[cfg(feature = "alloc")]
pub mod decoder;

#[cfg(feature = "alloc")]
pub mod control;

#[cfg(feature = "alloc")]
pub mod data;

#[cfg(feature = "alloc")]
pub use decoder::{MockVideoDecoder, VideoDecodeError, VideoDecoder};

#[cfg(feature = "alloc")]
pub use control::RdpevorControlClient;

#[cfg(feature = "alloc")]
pub use data::{RdpevorDataClient, VideoSink};

#[cfg(feature = "alloc")]
pub use pdu::{
    ClientNotification, FrameRateOverride, NotificationData, PresentationRequest,
    PresentationResponse, TsmmHeader, VideoData, CONTROL_CHANNEL_NAME, DATA_CHANNEL_NAME,
    MAX_CBEXTRA, MAX_CBSAMPLE, MAX_CONCURRENT_PRESENTATIONS, MAX_DESIRED_FRAMERATE,
    MAX_PACKETS_IN_SAMPLE, MAX_PENDING_REASSEMBLY_SAMPLES, MAX_SCALED_HEIGHT, MAX_SCALED_WIDTH,
    MF_VIDEO_FORMAT_H264_BYTES, TSMM_CLIENT_NOTIFICATION_TYPE_FRAMERATE_OVERRIDE,
    TSMM_CLIENT_NOTIFICATION_TYPE_NETWORK_ERROR, TSMM_FRAMERATE_FLAG_OVERRIDE,
    TSMM_FRAMERATE_FLAG_UNRESTRICTED, TSMM_PACKET_TYPE_CLIENT_NOTIFICATION,
    TSMM_PACKET_TYPE_PRESENTATION_REQUEST, TSMM_PACKET_TYPE_PRESENTATION_RESPONSE,
    TSMM_PACKET_TYPE_VIDEO_DATA, TSMM_PROTOCOL_VERSION_RDP8,
    TSMM_VIDEO_DATA_FLAG_HAS_TIMESTAMPS, TSMM_VIDEO_DATA_FLAG_KEYFRAME,
    TSMM_VIDEO_DATA_FLAG_NEW_FRAMERATE, TSMM_VIDEO_PLAYBACK_COMMAND_START,
    TSMM_VIDEO_PLAYBACK_COMMAND_STOP,
};
