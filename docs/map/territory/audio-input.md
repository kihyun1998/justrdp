# Audio input

## What it is

The audio input channel (`[MS-RDPEAI]`): the server opens the dynamic channel `AUDIO_INPUT`,
the two sides exchange versions and agree a list of formats, the server asks the client to
record, and the client sends what it captures as Data PDUs. `justrdp-pdu::audin` holds the
PDUs, `justrdp-codecs::pcm::encode` turns signed 16-bit samples into linear PCM, and
`justrdp::audin::AudioInput` is a sans-IO helper the host drives over the host dynamic channel
seam (ADR-0018), as it drives the audio output helper. Epic #12; #401 builds PCM and proves it
against the spec, and #404 proves it against a real server, the Windows 11 VM
(`192.168.136.163`), by recording a tone the host pushes.

## Governing decisions

- [ADR-0018](../../adr/0018-host-terminated-dynamic-channels.md) — `AUDIO_INPUT` is a
  Host-terminated Dynamic Virtual Channel: the host registers it and runs the helper.
- [ADR-0016](../../adr/0016-policy-flags-are-the-hosts.md) — `INFO_AUDIOCAPTURE`, the format
  tags and their order, and the Open Reply's `HRESULT` are the host's; the version and refusing
  a format the core cannot encode are the core's.
- [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md) — the receive posture, which
  3.1.5 makes stricter than tolerance: malformed, unknown and out-of-sequence PDUs MUST be
  ignored.

## Design model

- **The host pushes samples; the helper cuts packets.** After the Open, the host hands
  interleaved i16 samples of any length to `AudioInput::push`, at the current format's rate
  and channel count, and the helper returns an Incoming Data PDU and a Data PDU for every
  `FramesPerPacket` frames it holds (3.2.5.2). Resampling and the device are the host's. That
  split was the maintainer's call in #12's grilling (2026-10-07), shown the alternatives of the
  host handing exact packets or already-encoded bytes. FreeRDP's channel code sends whatever
  its device delivers and leaves the frame count to the device.
- **The host names format tags, not formats**, as on audio output: the helper answers the
  server's list with every server format of the host's tags that the core encodes, in the
  host's order of tags and the server's within a tag, copied as sent. For PCM that is 8 or 16
  bits, at least one channel, and a block of exactly one frame. The `initialFormat` and
  `NewFormat` indices count in that client list (3.1.1).
- **The order of the client's messages is fixed by the spec.** An Incoming Data PDU goes
  before the Sound Formats PDU (3.2.5.1.4) and before every Data PDU (3.2.5.2.1); a Format
  Change PDU naming `initialFormat` goes before the Open Reply (3.2.5.1.7), so the helper sends
  it when the Open arrives and the host's answer follows.
- **The Open Reply is the host's.** The helper reports the Open with the format to push in,
  the capture format the server suggests and `FramesPerPacket`; the host opens its device and
  calls `AudioInput::open_reply` with the `HRESULT`. A success code starts recording; an error
  code does not, and another Open is then answered (3.3.5.1.8). Windows ends the protocol 5 s
  after an unanswered Open (product note 4), and the helper keeps no clock.
- **The stages are 3.1.5's Figure 4**, which the section's text does not repeat: once recording
  (Opened), only a Format Change or closing the channel moves the protocol, so **an Open while
  recording is ignored**, and so is a Format Change while an Open waits for the host's answer.
  FreeRDP 3.31 takes an Open in any state; the figure is normative and FreeRDP is an example
  (`docs/agents/thegraph.md`).
- **The capture format passes through.** The Open PDU's suggested capture format, a
  `WAVEFORMAT_EXTENSIBLE` in the spec's example, reaches the host as the server sent it; the
  helper neither decodes the extensible part nor checks its `cbSize` of 22 (2.2.2.3), since it
  is a suggestion the samples are not encoded in.
- **A Format Change drops the partial packet.** It cannot go short, since every Data PDU holds
  `FramesPerPacket` frames, and everything after the confirmation is in the new format
  (3.2.5.3.2). The host learns the new format from `AudioInputEvent::FormatChanged`.
- **Everything the spec says to ignore is ignored** (3.1.5), unlike the audio output helper,
  whose malformed PDUs are `DecodeError`s: a malformed or unknown PDU, a second Version PDU,
  formats before the version, an Open anywhere but after the formats or a failed Open, a Format
  Change anywhere but while recording, and an index past the client's list. A `FramesPerPacket` of zero would ask for empty packets, so its Open is
  ignored too. **Derivation**, from 3.1.5.
- **A packet holds at most one second of its format.** The helper holds pushed samples until
  a packet fills, so a `FramesPerPacket` the server sets near `u32::MAX` would hold them without
  bound: at 44.1 kHz stereo 16-bit, 176 KB a second, about 15 GB a day, and an allocation
  failure after about 3.4 hours on a 32-bit host (#401's review). An Open or a Format Change
  whose `FramesPerPacket` exceeds the format's `nSamplesPerSec` is ignored. The spec's example
  asks for 2205 frames at 44.1 kHz, 50 ms. **Derivation**: a one-second packet is already far
  from real-time capture, and FreeRDP refuses only `INT32_MAX` and above.
- **The version is 2**, as FreeRDP 3.31 advertises; version 2 only adds that the server may
  send Format Change PDUs for AAC (3.3.5.3.1), and the helper takes every Format Change. The
  server's version is answered whatever it is, as 3.2.5.1.2 requires; FreeRDP answers nothing
  when the server's is higher. **Derivation.**
- **8-bit PCM packets hold one byte a sample.** The Open PDU's `nChannels × 2 ×
  FramesPerPacket` (2.2.2.3) describes 16-bit samples; the frame count is what binds.

## Code

- `crates/justrdp-pdu/src/audin.rs` — `ServerPdu`, `Open`, `CHANNEL_NAME`, `encode_version`,
  `encode_formats`, `encode_open_reply`, `encode_incoming_data`, `encode_data`,
  `encode_format_change`
- `crates/justrdp-codecs/src/pcm.rs` — `encode`
- `crates/justrdp/src/audin.rs` — `AudioInput`, `AudioInputConfig`, `AudioInputConfigError`,
  `AudioInputEvent`, `CLIENT_VERSION`, `ENCODABLE_FORMAT_TAGS`
- `crates/justrdp/src/advertise.rs` — `HONOURED_CLIENT_INFO_FLAGS`, which holds
  `AUDIO_CAPTURE` since #401
- `crates/justrdp-tokio/src/lib.rs` — `a_tone_pushed_as_audio_input_is_what_the_session_records_on_the_real_vm`,
  `without_the_capture_flag_the_session_has_no_microphone_on_the_real_vm`,
  `record_a_tone_pushed_as_audio_input`
- `fuzz/fuzz_targets/audin.rs` — the PDU parser and the helper over split input, the host's
  side played, seeded by `.github/scripts/seed_fuzz_corpus.py` with a session that reaches
  recording
- Spec sections cited inline: `[MS-RDPEAI]` 2.1, 2.2.1–2.2.4.1, 3.1.1, 3.1.5,
  3.2.5.1.2–3.2.5.3.2, 3.3.5.1.8, 3.3.5.3.1, section 4 (the annotated examples the PDU tests
  decode and encode byte for byte), product note 4

## Reference behaviour

**Measured against the Windows 11 Enterprise evaluation VM (#404, 2026-10-08)**, which opens
`AUDIO_INPUT` with no RD Session Host role and no policy; the Server 2019 VM never does (#400):

- **The channel opens when the session starts recording**, not at logon: the server sends its
  Create Request for `AUDIO_INPUT` as winmm MCI `record` runs, then Version 2, a Sound Formats
  PDU of **30 formats** (AAC `0xA106` ×8 first, PCM 44.1 kHz stereo 16-bit ×1, MS-ADPCM ×9
  and IMA-ADPCM ×9 at 44.1, 22.05, 11.025 and 8 kHz, A-law 22.05 kHz stereo ×1, GSM 6.10 ×4;
  no µ-law), and, to a client answering with PCM alone, an Open PDU with `FramesPerPacket`
  441 (10 ms), `initialFormat` 0 and a `WAVEFORMAT_EXTENSIBLE` capture format at 44.1 kHz
  stereo 16-bit (`cbSize` 22). FreeRDP 3.31 saw the same (#400).
- **A pushed tone is what the session records**: with the host pushing a 440 Hz sine ten
  milliseconds at a time, each packet a 1,765-byte Data PDU sent as a Data First and a Data
  PDU, the WAV MCI saves (11,025 Hz 8-bit mono) read back over `rdpdr` holds 440 Hz at about
  10^5 times the power of any of five other frequencies
  (`a_tone_pushed_as_audio_input_is_what_the_session_records_on_the_real_vm`). Pushing 620 Hz
  instead turns it red.
- **Without `INFO_AUDIOCAPTURE` the server opens no `AUDIO_INPUT` and the session has no
  capture device**: MCI `record` returns 328, `MCIERR_WAVE_INPUTSUNSUITABLE`
  (`without_the_capture_flag_the_session_has_no_microphone_on_the_real_vm`). So the flag is
  what gives a session a microphone, and a host that sets it and registers no `AUDIO_INPUT`
  offers one the server cannot open.
- **These Data PDUs found a static channel defect**: each DVC fragment has to ride one SVC
  chunk, and until #404 an SVC chunk carried 1,592 data bytes where `[MS-RDPBCGR]` 2.2.6.1
  allows 1,600, so a 1,594-byte fragment straddled two chunks and Windows 11 ended the session
  with `ERRINFO_VCDECODINGERROR` (`0x1133`) ([Virtual channels](virtual-channels.md)).

- **`[MS-RDPEAI]` section 4** is the spec's wire evidence: the PDU tests decode its server
  Sound Formats PDU (21 formats, PCM, MS-ADPCM, IMA-ADPCM and GSM 6.10 at several rates) and
  its Open PDU, and encode its Version, client Sound Formats, Open Reply, Incoming Data, Data
  and Format Change PDUs byte for byte. Its client list carries the server's 21 formats and 37
  bytes of `ExtraData` that `cbSizeFormatsPacket` (667) leaves out.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — every
  audio input message is server-supplied; `ServerPdu::decode` has a proptest, a `NumFormats`
  far past the message is a short read rather than an allocation, and a fuzz target drives the
  helper (#401).
- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — the client format list names only formats the core encodes, and version 2 promises only
  that Format Change PDUs are taken.

## Blast radius

- [Virtual channels](virtual-channels.md) — the host dynamic channel seam this rides on; the
  first DVC messages the host sends in a stream.
- [Audio output](audio-output.md) — shares `AUDIO_FORMAT` and its encoding with this channel,
  and the PCM codec module.
- [Capability exchange & activation](capability-exchange-activation.md) — `INFO_AUDIOCAPTURE`
  is honoured in the Client Info PDU.
- [Verification harness](verification-harness.md) — the live proof runs against a second VM,
  the Windows 11 one, through `Target::AudioInput`.

## Known holes / open

- **`AudioFormat` lives in `justrdp-pdu::rdpsnd`** and `audin` re-exports it, its codec
  `pub(crate)`: the type is `[MS-RDPEA]`'s, now shared by two channels. Moving it to a neutral
  module waits for a third user; that was the maintainer's call (2026-10-08), shown the
  alternative of a `wave` module in this change.
- **PCM only.** A-law (#402) and MS-ADPCM and IMA-ADPCM (#403) are all in the Windows 11
  server's list; AAC waits on #21's decoder-backend question; GSM 6.10 is not encoded.
- **One server.** Only a Windows 11 client SKU has been measured; a Server SKU with the RD
  Session Host role did not open the channel for FreeRDP or mstsc (#400).
