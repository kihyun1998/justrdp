# ADPCM fixtures (#389)

Each case is a pair: `<case>.adpcm`, a run of whole ADPCM blocks, and `<case>.s16`, the signed
16-bit little-endian samples they decode to. `tests/adpcm_oracle.rs` decodes the first and
compares with the second.

## Where the bytes come from

| Case | Blocks |
|---|---|
| `ms_{mono,stereo}_generated` | three generated MS-ADPCM blocks, `nBlockAlign` 256 per channel: random headers and nibbles, except that a nibble that would grow a channel's step past 20,000 is replaced by a small one (FreeRDP's `INT32` arithmetic overflows past that, and real encoders stay far below it) |
| `ima_{mono,stereo}_generated` | three generated IMA-ADPCM blocks, `nBlockAlign` 256 per channel, random headers and nibbles |
| `ms_mono_vm_{0,1,2}`, `ima_mono_vm_{0,1,2}` | the first three non-silent Wave2 samples (four blocks each) WS2019 sent on 2026-10-07 for a stock `%windir%\Media\Alarm01.wav`, to a host listing only that codec, captured with `JUSTRDP_AUDIO_CAPTURE_DIR` by `a_sound_reaches_the_host_in_*_adpcm_when_the_host_takes_only_it_on_the_real_vm` |
| `ms_mono_vm.extra`, `ima_mono_vm.extra` | the `cbSize` extra the server sent with that format: 2036 samples per block and the seven standard coefficient pairs; 2041 samples per block |

## Where the expected samples come from

FreeRDP's decoders, `freerdp_dsp_decode_ms_adpcm` and `freerdp_dsp_decode_ima_adpcm` from
`libfreerdp/codec/dsp.c` at commit `6e09e9ab57fd4130de9923588ae6e2a93b4ab29e`. They were taken
verbatim, compiled with MSVC behind a minimal type and stream shim, and run on each case. The
harness is not in the repository; it is FreeRDP's code, and these files are its output.

**One adjustment, to IMA only.** FreeRDP does not emit an IMA block's header sample, so it
yields 2 × (`nBlockAlign` − 4 × channels) samples per block where the format's
`wSamplesPerBlock` declares one more per channel; WS2019's IMA formats declare 1017 at
`nBlockAlign` 1024 stereo and 2041 at 1024 mono. The header sample of each channel was inserted
before FreeRDP's output for that block. Every IMA case was then decoded independently with
CPython 3.12's `audioop.adpcm2lin` (nibbles swapped to its high-first order, the header as its
starting state, the header sample prepended), and it matches every sample.

MS-ADPCM has no second oracle here. FreeRDP ignores the format's coefficient table and uses the
seven standard pairs; WS2019 sends exactly those, so the two agree on these cases.

## Encoder oracles (#403)

`src/adpcm.rs`'s tests read three more files, each made outside the repository:

| File | What it holds | Made by |
|---|---|---|
| `ima_quantizer_freerdp.bin` | 20,000 records of 9 bytes: an IMA state (last sample `i16`, step index `u8`), a sample `i16`, then the nibble `u8` and the state after it | FreeRDP's `dsp_encode_ima_adpcm_sample` |
| `ms_quantizer_freerdp_ffmpeg.bin` | 20,000 records of 23 bytes: an MS-ADPCM state (standard pair index `u8`, `sample1` `i16`, `sample2` `i16`, step `u16`), a sample `i16`, then for FreeRDP and then for ffmpeg the nibble `u8`, `sample1` `i16` and step `i32` after it | FreeRDP's `freerdp_dsp_encode_ms_adpcm_sample` and ffmpeg's `adpcm_ms_compress_sample` |
| `ima_blocks_audioop.bin` | 24 records of 2,543 bytes: a starting step index `u8`, 1,017 mono samples `i16`, and the 508-byte block body | CPython 3.12's `audioop.lin2adpcm` on samples 1 to 1,016 from the state (sample 0, step index), nibbles swapped to the WAV block's low-first order |

The two C functions were copied verbatim from FreeRDP `libfreerdp/codec/dsp.c` at commit
`87baff6c80e16087c146937bca81d2bdb788e236` and ffmpeg `libavcodec/adpcmenc.c` and
`adpcm_data.c` at commit `f4012774b92996fe22effafaf65625247ce7f4ad`, with their tables, behind
a shim of types and macros, compiled with clang 21, and run on cases from a fixed splitmix64
seed: half of the samples anywhere in range, half within a few steps of the prediction. The
harness is not in the repository; these files are its output.

ffmpeg's IMA encoder is not an oracle: outside trellis mode its `adpcm_ima_compress_sample`
quantises with `4 × |error| ÷ step` and reconstructs with a Yamaha difference table, not with
the decoder's shifted step sums, so its state can part from a decoder's.
