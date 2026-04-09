//! PulseAudio audio output backend for Linux.

#![deny(unsafe_op_in_unsafe_fn)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libpulse_binding::callbacks::ListResult;
use libpulse_binding::context::{Context, FlagSet as ContextFlagSet, State as ContextState};
use libpulse_binding::mainloop::standard::Mainloop;
use libpulse_binding::operation::State as OpState;
use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_binding::volume::{ChannelVolumes, Volume};
use libpulse_simple_binding::Simple;

use crate::error::{NativeAudioError, NativeAudioResult};
use crate::output::NativeAudioOutput;

/// Application name used for PulseAudio stream identification.
const APP_NAME: &str = "justrdp";

/// Maximum PulseAudio channels supported (PA limit is 32).
const MAX_CHANNELS: u16 = 32;

/// Wall-clock timeout for PulseAudio mainloop operations.
const MAINLOOP_TIMEOUT: Duration = Duration::from_secs(5);

/// PulseAudio output using the Simple (blocking) API with per-stream volume
/// control via the introspect API.
pub struct PulseAudioOutput {
    simple: Simple,
    channels: u16,
}

impl NativeAudioOutput for PulseAudioOutput {
    fn open(sample_rate: u32, channels: u16, bits_per_sample: u16) -> NativeAudioResult<Self> {
        if bits_per_sample != 16 || channels == 0 || channels > MAX_CHANNELS || sample_rate == 0 {
            return Err(NativeAudioError::FormatNotSupported);
        }

        let spec = Spec {
            format: Format::S16le,
            channels: channels as u8,
            rate: sample_rate,
        };

        if !spec.is_valid() {
            return Err(NativeAudioError::FormatNotSupported);
        }

        let simple = Simple::new(
            None,                  // default server
            APP_NAME,              // application name
            Direction::Playback,
            None,                  // default device
            "RDP Audio Output",    // stream description
            &spec,
            None,                  // default channel map
            None,                  // default buffering
        )
        .map_err(|e| NativeAudioError::DeviceError(e.to_string().unwrap_or_default()))?;

        Ok(Self { simple, channels })
    }

    fn write_samples(&mut self, samples: &[i16]) -> NativeAudioResult<()> {
        // Convert to S16LE bytes explicitly for endian-safety.
        let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();

        self.simple
            .write(&bytes)
            .map_err(|e| NativeAudioError::WriteError(e.to_string().unwrap_or_default()))?;

        Ok(())
    }

    fn set_volume(&mut self, left: u16, right: u16) {
        // Build the target volume for our channel count.
        debug_assert!(self.channels > 0, "channels validated in open()");
        let ch_count = self.channels as u8;
        let mut volumes = ChannelVolumes::default();
        volumes.set_len(ch_count);

        // Map 0..=0xFFFF to PulseAudio Volume range (0 = mute, NORMAL = 100%).
        let left_vol = Volume(((left as u32) * Volume::NORMAL.0) / 0xFFFF);
        let right_vol = Volume(((right as u32) * Volume::NORMAL.0) / 0xFFFF);

        if self.channels >= 2 {
            volumes.set(0, left_vol);
            volumes.set(1, right_vol);
            // Fill remaining channels (if any) with the average volume.
            let avg = Volume(left_vol.0.saturating_add(right_vol.0) / 2);
            for i in 2..ch_count {
                volumes.set(i, avg);
            }
        } else {
            volumes.set(0, Volume(left_vol.0.saturating_add(right_vol.0) / 2));
        }

        // Find our sink input and set its volume via the introspect API.
        if let Err(e) = set_sink_input_volume_by_name(APP_NAME, &volumes) {
            eprintln!("[rdpsnd-native] PulseAudio set_volume failed: {e}");
        }
    }

    fn close(&mut self) {
        let _ = self.simple.drain();
    }
}

impl Drop for PulseAudioOutput {
    fn drop(&mut self) {
        self.close();
    }
}

/// Find a sink input by application name and set its volume.
///
/// Creates a temporary PulseAudio mainloop + context for the introspect call.
/// NOTE: This creates a temporary PA context per call; caching would be more
/// efficient but the Simple API does not expose the underlying context.
fn set_sink_input_volume_by_name(
    app_name: &str,
    volumes: &ChannelVolumes,
) -> NativeAudioResult<()> {
    let mut mainloop =
        Mainloop::new().ok_or_else(|| NativeAudioError::DeviceError("PA mainloop creation failed".into()))?;
    let mut context = Context::new(&mainloop, "justrdp-vol")
        .ok_or_else(|| NativeAudioError::DeviceError("PA context creation failed".into()))?;

    context
        .connect(None, ContextFlagSet::NOFLAGS, None)
        .map_err(|_| NativeAudioError::DeviceError("PA context connect failed".into()))?;

    let deadline = Instant::now() + MAINLOOP_TIMEOUT;

    // Wait for context ready with wall-clock timeout.
    // Use iterate(false) (non-blocking) so the deadline is enforced even if
    // the PA daemon is completely unresponsive.
    loop {
        mainloop.iterate(false);
        match context.get_state() {
            ContextState::Ready => break,
            ContextState::Failed | ContextState::Terminated => {
                return Err(NativeAudioError::DeviceError("PA context failed".into()));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(NativeAudioError::DeviceError("PA context ready timeout".into()));
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // Phase 1: Find our sink input index by application name.
    let found_idx: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let idx_clone = found_idx.clone();
    let target_name = app_name.to_string();

    let op = context.introspect().get_sink_input_info_list(move |result| {
        if let ListResult::Item(info) = result {
            let matches = info
                .proplist
                .get_str("application.name")
                .map(|n| n == target_name)
                .unwrap_or(false);
            if matches {
                if let Ok(mut idx) = idx_clone.lock() {
                    *idx = Some(info.index);
                }
            }
        }
    });

    loop {
        mainloop.iterate(false);
        match op.get_state() {
            OpState::Done => break,
            OpState::Cancelled => {
                return Err(NativeAudioError::DeviceError("PA introspect cancelled".into()));
            }
            OpState::Running => {}
        }
        if Instant::now() >= deadline {
            return Err(NativeAudioError::DeviceError("PA introspect timeout".into()));
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // Phase 2: Set volume on the found sink input.
    if let Some(idx) = *found_idx
        .lock()
        .map_err(|_| NativeAudioError::DeviceError("PA mutex poisoned".into()))?
    {
        let op2 = context
            .introspect()
            .set_sink_input_volume(idx, volumes, None);
        loop {
            mainloop.iterate(false);
            match op2.get_state() {
                OpState::Done => break,
                OpState::Cancelled => {
                    return Err(NativeAudioError::DeviceError("PA set_volume cancelled".into()));
                }
                OpState::Running => {}
            }
            if Instant::now() >= deadline {
                return Err(NativeAudioError::DeviceError("PA set_volume timeout".into()));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    context.disconnect();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify volume mapping from 0..=0xFFFF to PulseAudio 0..=NORMAL.
    #[test]
    fn volume_mapping_boundaries() {
        // Mute: 0x0000 → Volume(0)
        let vol = Volume(((0u32) * Volume::NORMAL.0) / 0xFFFF);
        assert_eq!(vol.0, 0);

        // Max: 0xFFFF → Volume(NORMAL)
        let vol = Volume(((0xFFFFu32) * Volume::NORMAL.0) / 0xFFFF);
        assert_eq!(vol.0, Volume::NORMAL.0);

        // Mid: 0x7FFF → ~half of NORMAL
        let vol = Volume(((0x7FFFu32) * Volume::NORMAL.0) / 0xFFFF);
        let expected_half = Volume::NORMAL.0 / 2;
        // Allow ±1 for rounding
        assert!(vol.0.abs_diff(expected_half) <= 1);
    }

    /// Verify mono volume averaging.
    #[test]
    fn mono_volume_averaging() {
        let left_vol = Volume(((0x8000u32) * Volume::NORMAL.0) / 0xFFFF);
        let right_vol = Volume(((0x4000u32) * Volume::NORMAL.0) / 0xFFFF);
        let avg = Volume((left_vol.0 + right_vol.0) / 2);

        // Average of ~50% and ~25% should be ~37.5%
        let expected = Volume(((0x6000u32) * Volume::NORMAL.0) / 0xFFFF);
        assert!(avg.0.abs_diff(expected.0) <= 1);
    }

    /// Verify open() rejects invalid formats.
    #[test]
    fn open_rejects_invalid_formats() {
        // Non-16-bit
        assert!(PulseAudioOutput::open(44100, 2, 8).is_err());
        // Zero channels
        assert!(PulseAudioOutput::open(44100, 0, 16).is_err());
        // Too many channels
        assert!(PulseAudioOutput::open(44100, 33, 16).is_err());
        // Zero sample rate
        assert!(PulseAudioOutput::open(0, 2, 16).is_err());
    }
}
