# ADPCM fixtures (#389)

Each case is a pair: `<case>.adpcm`, a run of whole ADPCM blocks, and `<case>.s16`, the signed
16-bit little-endian samples they decode to. `tests/adpcm_oracle.rs` decodes the first and
compares with the second.

## Where the bytes come from

| Case | Blocks |
|---|---|
| `ms_{mono,stereo}_generated` | three generated MS-ADPCM blocks, `nBlockAlign` 256 per channel: random headers and nibbles, except that a nibble that would grow a channel's step past 20,000 is replaced by a small one (FreeRDP's `INT32` arithmetic overflows past that, and real encoders stay far below it) |
| `ima_{mono,stereo}_generated` | three generated IMA-ADPCM blocks, `nBlockAlign` 256 per channel, random headers and nibbles |
| `ms_mono_vm_{0,1,2}`, `ima_mono_vm_{0,1,2}` | the first three non-silent Wave2 samples (four blocks each) WS2022 sent on 2026-10-07 for a stock `%windir%\Media\Alarm01.wav`, to a host listing only that codec, captured with `JUSTRDP_AUDIO_CAPTURE_DIR` by `a_sound_reaches_the_host_in_*_adpcm_when_the_host_takes_only_it_on_the_real_vm` |
| `ms_mono_vm.extra`, `ima_mono_vm.extra` | the `cbSize` extra the server sent with that format: 2036 samples per block and the seven standard coefficient pairs; 2041 samples per block |

## Where the expected samples come from

FreeRDP's decoders, `freerdp_dsp_decode_ms_adpcm` and `freerdp_dsp_decode_ima_adpcm` from
`libfreerdp/codec/dsp.c` at commit `6e09e9ab57fd4130de9923588ae6e2a93b4ab29e`. They were taken
verbatim, compiled with MSVC behind a minimal type and stream shim, and run on each case. The
harness is not in the repository; it is FreeRDP's code, and these files are its output.

**One adjustment, to IMA only.** FreeRDP does not emit an IMA block's header sample, so it
yields 2 × (`nBlockAlign` − 4 × channels) samples per block where the format's
`wSamplesPerBlock` declares one more per channel; WS2022's IMA formats declare 1017 at
`nBlockAlign` 1024 stereo and 2041 at 1024 mono. The header sample of each channel was inserted
before FreeRDP's output for that block. Every IMA case was then decoded independently with
CPython 3.12's `audioop.adpcm2lin` (nibbles swapped to its high-first order, the header as its
starting state, the header sample prepended), and it matches every sample.

MS-ADPCM has no second oracle here. FreeRDP ignores the format's coefficient table and uses the
seven standard pairs; WS2022 sends exactly those, so the two agree on these cases.
