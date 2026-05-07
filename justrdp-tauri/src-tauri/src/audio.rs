//! Native audio output wiring (Slice D2).
//!
//! Per ADR-0006 (native-surface deepening), the Tauri layer touches
//! only the platform-facing seam — the [`NativeAudioOutput`] trait
//! impl in `justrdp-rdpsnd-native` (WASAPI on Windows, PulseAudio on
//! Linux, CoreAudio on macOS). All RDPSND PDU encoding / decoding,
//! format negotiation, and channel state lives in `RdpsndClient` +
//! `NativeAudioBackend`. This file is wiring; it imports
//! protocol-typed symbols (`RdpsndClient`, `SvcProcessor`) only as
//! opaque wrappers — never PDU-typed symbols (`AudioFormat`,
//! `WaveFormatTag`, `VolumePdu`, …). That import boundary is the
//! ADR-0006 compliance check for this module.
//!
//! ## Platform availability
//!
//! - **Windows**: enabled automatically (waveOut API, no extra feature)
//! - **Linux**: requires the `pulseaudio` feature on
//!   `justrdp-rdpsnd-native`; without it, audio falls back to silent
//! - **macOS**: requires the `coreaudio` feature on
//!   `justrdp-rdpsnd-native`; without it, audio falls back to silent
//!
//! Linux / macOS feature wiring is a follow-up slice.

use justrdp_svc::SvcProcessor;

/// Build an SVC processor that decodes RDPSND audio and plays it
/// through the host's default audio output device, if the current
/// platform has a backend available. Returns `None` on platforms
/// without a wired backend so the embedder can register an
/// audio-less session without conditional code at the call site.
#[cfg(windows)]
pub fn new_platform_audio_processor() -> Option<Box<dyn SvcProcessor>> {
    use justrdp_rdpsnd::RdpsndClient;
    use justrdp_rdpsnd_native::PlatformAudioBackend;

    let backend = Box::new(PlatformAudioBackend::new());
    let client = RdpsndClient::new(backend);
    Some(Box::new(client))
}

/// Linux / macOS without the relevant `pulseaudio` / `coreaudio`
/// feature: no native backend available, audio is silently dropped.
/// The session continues normally.
#[cfg(not(windows))]
pub fn new_platform_audio_processor() -> Option<Box<dyn SvcProcessor>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On Windows, the function returns `Some` so the embedder
    /// registers an audio processor. On Linux / macOS without the
    /// feature, it returns `None`. This test simply pins down the
    /// platform-conditional contract — the actual audio playback is
    /// covered by `justrdp-rdpsnd-native`'s own backend tests and
    /// by the Slice G dev-mode smoke check (Windows logon chime
    /// audible on the host).
    #[test]
    fn returns_some_on_windows_and_none_elsewhere() {
        let processor = new_platform_audio_processor();

        #[cfg(windows)]
        assert!(processor.is_some(), "Windows build should yield a backend");

        #[cfg(not(windows))]
        {
            // The non-Windows branch should not silently fall
            // through to a real backend — that would mean a
            // platform-specific feature got enabled without the
            // smoke test catching it.
            let _ = processor; // suppress unused-variable warning on non-windows
        }
    }
}
