#![forbid(unsafe_code)]

//! Audio output backend trait -- platform-level audio integration.

use alloc::vec::Vec;

use crate::pdu::{AudioFormat, VolumePdu};

/// Application-level audio output backend.
///
/// Implement this trait to integrate audio playback with your
/// platform's native audio system.
pub trait RdpsndBackend: Send {
    /// Called when the server sends its supported audio formats.
    ///
    /// Return the indices (into `server_formats`) of formats the client supports.
    /// The client will advertise only these formats back to the server.
    fn on_server_formats(&mut self, server_formats: &[AudioFormat]) -> Vec<usize>;

    /// Called when audio data is received (from WaveInfo+Wave or Wave2).
    ///
    /// `format_no` is the index into the negotiated format list.
    /// `data` is the complete audio payload.
    fn on_wave_data(&mut self, format_no: u16, data: &[u8], audio_timestamp: Option<u32>);

    /// Called when the server sets the volume.
    fn on_volume(&mut self, volume: &VolumePdu);

    /// Called when the server closes the audio channel.
    fn on_close(&mut self);
}
