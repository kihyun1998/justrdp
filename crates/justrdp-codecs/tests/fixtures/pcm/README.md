# PCM corpus (#554)

`ws2019-16bit-stereo.bin`: the first three Wave2 samples that were not silence, 32 768 bytes each,
that the WS2019 VM (192.168.136.136) sent on 2026-10-26 to a host listing only PCM at 44 100 Hz,
2 channels, 16 bits. Captured by `a_sound_played_in_the_session_reaches_the_host_as_pcm_on_the_real_vm`
over the dynamic audio channel, with `test_config`'s defaults (`connectionType` 0x06, LAN).

## Format

The container every #554 corpus shares, little-endian: a `u32` record count, then per record
`u16 a, u16 b, u16 c, u32 len, payload[len]`. `a` is the bits per sample, `b` the channel count, `c` 0.
`tests/real_server_corpus.rs` replays it.

## How to regenerate it

Run the test with `JUSTRDP_AUDIO_CAPTURE_DIR` set; it writes the first three Wave2 samples that are
not silence as `<wFormatTag>_<nChannels>ch_<nBlockAlign>_<n>.bin`. Each file is one record here,
in the order of `n`. The ADPCM fixtures (`../adpcm/`) came from the same hook.
