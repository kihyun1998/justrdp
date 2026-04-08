//! Error types for native audio output.

use std::fmt;

/// Error from the native audio output backend.
#[derive(Debug)]
pub enum NativeAudioError {
    /// Audio output device not available or failed to open.
    DeviceError(String),
    /// Audio format not supported by the platform backend.
    FormatNotSupported,
    /// Write to audio device failed.
    WriteError(String),
    /// Codec decode error.
    DecodeError(String),
}

impl fmt::Display for NativeAudioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceError(msg) => write!(f, "audio device error: {msg}"),
            Self::FormatNotSupported => f.write_str("audio format not supported"),
            Self::WriteError(msg) => write!(f, "audio write error: {msg}"),
            Self::DecodeError(msg) => write!(f, "audio decode error: {msg}"),
        }
    }
}

impl std::error::Error for NativeAudioError {}

pub type NativeAudioResult<T> = Result<T, NativeAudioError>;
