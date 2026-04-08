//! PulseAudio audio output backend for Linux.

use std::sync::{Arc, Mutex};

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

/// PulseAudio output using the Simple (blocking) API with per-stream volume
/// control via the introspect API.
pub struct PulseAudioOutput {
    simple: Simple,
    channels: u16,
}

impl NativeAudioOutput for PulseAudioOutput {
    fn open(sample_rate: u32, channels: u16, bits_per_sample: u16) -> NativeAudioResult<Self> {
        if bits_per_sample != 16 {
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
        // SAFETY: Reinterprets `&[i16]` as `&[u8]` with exactly `samples.len() * 2` bytes.
        // The pointer is valid for the entire slice, and `i16` has no invalid bit patterns.
        // PulseAudio expects raw PCM bytes in the format specified at open time (S16LE).
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(samples.as_ptr() as *const u8, samples.len() * 2)
        };

        self.simple
            .write(bytes)
            .map_err(|e| NativeAudioError::WriteError(e.to_string().unwrap_or_default()))?;

        Ok(())
    }

    fn set_volume(&mut self, left: u16, right: u16) {
        // Build the target volume for our channel count.
        let mut volumes = ChannelVolumes::default();
        volumes.set_len(self.channels.max(1) as u8);

        // Map 0..=0xFFFF to PulseAudio Volume range (0 = mute, NORMAL = 100%).
        let left_vol = Volume(((left as u32) * Volume::NORMAL.0) / 0xFFFF);
        let right_vol = Volume(((right as u32) * Volume::NORMAL.0) / 0xFFFF);

        if self.channels >= 2 {
            volumes.set(0, left_vol);
            volumes.set(1, right_vol);
        } else {
            volumes.set(0, Volume((left_vol.0 + right_vol.0) / 2));
        }

        // Find our sink input and set its volume via the introspect API.
        let _ = set_sink_input_volume_by_name(APP_NAME, &volumes);
    }

    fn close(&mut self) {
        let _ = self.simple.drain();
    }
}

/// Find a sink input by application name and set its volume.
///
/// Creates a temporary PulseAudio mainloop + context for the introspect call.
fn set_sink_input_volume_by_name(app_name: &str, volumes: &ChannelVolumes) -> Result<(), ()> {
    let mut mainloop = Mainloop::new().ok_or(())?;
    let mut context = Context::new(&mainloop, "justrdp-vol").ok_or(())?;

    context
        .connect(None, ContextFlagSet::NOFLAGS, None)
        .map_err(|_| ())?;

    // Wait for context ready.
    loop {
        mainloop.iterate(true);
        match context.get_state() {
            ContextState::Ready => break,
            ContextState::Failed | ContextState::Terminated => return Err(()),
            _ => {}
        }
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
        mainloop.iterate(true);
        match op.get_state() {
            OpState::Done => break,
            OpState::Cancelled => return Err(()),
            OpState::Running => {}
        }
    }

    // Phase 2: Set volume on the found sink input.
    if let Some(idx) = *found_idx.lock().map_err(|_| ())? {
        let op2 = context
            .introspect()
            .set_sink_input_volume(idx, volumes, None);
        loop {
            mainloop.iterate(true);
            match op2.get_state() {
                OpState::Done => break,
                OpState::Cancelled => return Err(()),
                OpState::Running => {}
            }
        }
    }

    context.disconnect();
    Ok(())
}
