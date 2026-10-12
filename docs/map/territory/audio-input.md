# Audio input

## What it is

The audio input channel (`[MS-RDPEAI]`): the server opens the dynamic channel `AUDIO_INPUT`,
the two sides exchange versions and agree a list of formats, the server asks the client to
record, and the client sends what it captures as Data PDUs. `justrdp-pdu::audin` holds the
PDUs, `justrdp-codecs::pcm::encode` turns signed 16-bit samples into linear PCM and
`justrdp-codecs::g711::encode_alaw` into A-law (#402), and
`justrdp::audin::AudioInput` is a sans-IO helper the host drives over the host dynamic channel
seam (ADR-0018), as it drives the audio output helper. Epic #12; #401 builds PCM and proves it
against the spec, and #404 proves it against a real server, the Windows 11 VM
(`192.168.136.163`), by recording a signal the host pushes.

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
  packet it holds (3.2.5.2), a packet lasting `FramesPerPacket` frames of the capture format
  (below). Resampling and the device are the host's. That
  split was the maintainer's call in #12's grilling (2026-10-07), shown the alternatives of the
  host handing exact packets or already-encoded bytes. FreeRDP's channel code sends whatever
  its device delivers and leaves the frame count to the device.
- **The host names format tags, not formats**, as on audio output: the helper answers the
  server's list with every server format of the host's tags that the core encodes, in the
  host's order of tags and the server's within a tag, copied as sent. For PCM that is 8 or 16
  bits, for A-law 8 (#402); for both, at least one channel and a block of exactly one frame. The `initialFormat` and
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
- **A Format Change drops the partial packet.** It cannot go short, since every Data PDU holds a
  whole packet, and everything after the confirmation is in the new format
  (3.2.5.3.2). The host learns the new format from `AudioInputEvent::FormatChanged`.
- **Everything the spec says to ignore is ignored** (3.1.5), unlike the audio output helper,
  whose malformed PDUs are `DecodeError`s: a malformed or unknown PDU, a second Version PDU,
  formats before the version, an Open anywhere but after the formats or a failed Open, a Format
  Change anywhere but while recording, and an index past the client's list. A `FramesPerPacket` of zero would ask for empty packets, so its Open is
  ignored too. **Derivation**, from 3.1.5.
- **A packet lasts `FramesPerPacket` frames of the Open's capture format** (#402): it holds
  `FramesPerPacket` × the format's `nSamplesPerSec` ÷ the capture format's `nSamplesPerSec`
  frames, rounded down and at least one, or `FramesPerPacket` frames when the capture format
  has no rate. A Format Change keeps that length in time. For PCM at the capture format's rate,
  as Windows 11 picks it, that is `FramesPerPacket` frames; for its A-law at 22.05 kHz against
  a 44.1 kHz capture format, 220 frames, 10 ms. **That rule was the maintainer's call
  (2026-10-08)**, shown the measurements below and the alternatives of a fixed 10 ms packet and
  of leaving A-law out of the helper. It departs from the letter of 2.2.2.3, whose two MUSTs, a
  Data PDU of `FramesPerPacket` frames and one of `nChannels × 2 × FramesPerPacket` bytes, both
  fail for A-law on Windows 11 (Reference behaviour); for 16-bit PCM at the capture rate the
  three agree. It replaces #401's derivation that the frame count binds.
- **A packet holds at most one second of its format.** The helper holds pushed samples until
  a packet fills, so a `FramesPerPacket` the server sets near `u32::MAX` would hold them without
  bound: at 44.1 kHz stereo 16-bit, 176 KB a second, about 15 GB a day, and an allocation
  failure after about 3.4 hours on a 32-bit host (#401's review). An Open whose packet would
  hold more frames than the format's `nSamplesPerSec` is ignored; a Format Change keeps the
  packet's length in time, so it cannot lengthen one. The spec's example
  asks for 2205 frames at 44.1 kHz, 50 ms. **Derivation**: a one-second packet is already far
  from real-time capture, and FreeRDP refuses only `INT32_MAX` and above.
- **The version is 2**, as FreeRDP 3.31 advertises; version 2 only adds that the server may
  send Format Change PDUs for AAC (3.3.5.3.1), and the helper takes every Format Change. The
  server's version is answered whatever it is, as 3.2.5.1.2 requires; FreeRDP answers nothing
  when the server's is higher. **Derivation.**
- **The ADPCM encoders follow ffmpeg where FreeRDP and ffmpeg part** (#403). An encoder
  carries each channel's step from one block into the next, as both do. An IMA block's header
  holds the block's first frame, as ffmpeg's does and as the decoder reads it (#389); FreeRDP
  writes the previous block's last sample there and encodes one frame fewer, so each of its
  blocks repeats a sample. MS-ADPCM uses the format's first coefficient pair in every block,
  as both do, and rounds an error to the nearest step with halves away from zero, as ffmpeg
  does; FreeRDP never rounds a negative error away from zero, a bias, and differs in 2,532 of
  the 20,000 oracle cases, all of them those. A header's step is capped at `i16::MAX`, which
  only a first pair that predicts past the samples' range can reach. **Derivation**, from the
  two encoders and the decoders.
- **8-bit PCM and A-law packets hold one byte a sample.**
- **A-law is checked against an independent encoder** (#402): every one of the 65,536 16-bit
  samples is compared with CPython 3.12's `audioop.lin2alaw`, kept in the test as the 256 runs
  of samples it maps to one code, and each sample decodes through the owned decoder to within
  half its step. `audioop` is the oracle the A-law decoder already uses (#388, [Audio
  output](audio-output.md)); FreeRDP encodes no A-law for audio input.

## Code

- `crates/justrdp-pdu/src/audin.rs` — `ServerPdu`, `Open`, `CHANNEL_NAME`, `encode_version`,
  `encode_formats`, `encode_open_reply`, `encode_incoming_data`, `encode_data`,
  `encode_format_change`
- `crates/justrdp-codecs/src/pcm.rs` — `encode`
- `crates/justrdp-codecs/src/g711.rs` — `i16_to_alaw`, `encode_alaw`
- `crates/justrdp-codecs/src/adpcm.rs` — `MsAdpcmEncoder`, `ImaAdpcmEncoder`,
  `MsAdpcm::encoder`, `ImaAdpcm::encoder`, `samples_per_block`, and the quantiser oracle tests
  (#403); the helper does not use them
- `crates/justrdp-codecs/tests/fixtures/adpcm/` — the encoder oracles' cases and their README
- `crates/justrdp/src/audin.rs` — `AudioInput`, `AudioInputConfig`, `AudioInputConfigError`,
  `AudioInputEvent`, `CLIENT_VERSION`, `ENCODABLE_FORMAT_TAGS`
- `crates/justrdp/src/advertise.rs` — `HONOURED_CLIENT_INFO_FLAGS`, which holds
  `AUDIO_CAPTURE` since #401
- `crates/justrdp-tokio/src/lib.rs` — `a_signal_pushed_as_audio_input_is_what_the_session_records_on_the_real_vm`,
  `a_signal_pushed_in_alaw_is_what_the_session_records_on_the_real_vm`,
  `the_signal_check_finds_the_pushed_signal_whole_and_nothing_else`, `holds_pushed_signal`,
  `pushed_sample`,
  `without_the_capture_flag_the_session_has_no_microphone_on_the_real_vm`,
  `record_a_signal_pushed_as_audio_input`
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
  PDU of **30 formats** (AAC `0xA106` ×8 first, PCM 44.1 kHz stereo 16-bit ×1, MS-ADPCM ×8
  and IMA-ADPCM ×8, A-law 22.05 kHz stereo ×1, GSM 6.10 ×4; no µ-law; counted in #403, where
  #404 had read nine ADPCM formats of each), and, to a client answering with PCM alone, an Open PDU with `FramesPerPacket`
  441 (10 ms), `initialFormat` 0 and a `WAVEFORMAT_EXTENSIBLE` capture format at 44.1 kHz
  stereo 16-bit (`cbSize` 22). FreeRDP 3.31 saw the same (#400).
- **A pushed signal is what the session records**: with the host pushing ten milliseconds at
  a time, each packet a 1,765-byte Data PDU sent as a Data First and a Data PDU, the WAV MCI
  saves (11,025 Hz 8-bit mono) read back over `rdpdr` holds what was pushed
  (`a_signal_pushed_as_audio_input_is_what_the_session_records_on_the_real_vm`). Until #411
  the signal was a 440 Hz tone, which held at about 10^5 times the power of five other
  frequencies; it is now deterministic noise, mapped window by window (below).
- **Without `INFO_AUDIOCAPTURE` the server opens no `AUDIO_INPUT` and the session has no
  capture device**: MCI `record` returns 328, `MCIERR_WAVE_INPUTSUNSUITABLE`
  (`without_the_capture_flag_the_session_has_no_microphone_on_the_real_vm`). So the flag is
  what gives a session a microphone, and a host that sets it and registers no `AUDIO_INPUT`
  offers one the server cannot open.
- **A host listing only A-law gets the server's one A-law format**, 22,050 Hz stereo 8-bit,
  `nBlockAlign` 2, `nAvgBytesPerSec` 44,100, and the same Open: `FramesPerPacket` 441 and a
  44.1 kHz capture format. Pushed in packets of 220 frames, the signal is what the session
  records, whole (`a_signal_pushed_in_alaw_is_what_the_session_records_on_the_real_vm`).
- **Windows 11 records audio input only from short packets, whatever the codec** (#402). Traced
  by pushing deterministic noise and correlating each 10 ms of the recording with it, which
  maps every output stretch to the input it came from to within 0.09 ms:

  | Data PDU | PCM 44.1 kHz | A-law 22.05 kHz |
  |---|---|---|
  | 5 ms | lossless | a few lost packets |
  | 10 ms | lossless (441 frames, the helper's) | lossless (220 frames, the helper's) |
  | 15 ms | — | lossless |
  | 20 ms | a few lost 10 ms stretches | 441 frames: all discarded; 440: a few lost stretches; 442: lossless |
  | 21–25 ms | — | lossless |
  | 30 ms | a few lost packets | a few lost packets |
  | 35 ms | — | a few lost 5 ms stretches |
  | 38–60 ms | 40 ms: 30 ms kept, 10 ms dropped, from every packet | 30 ms kept from every packet |

  PCM's 40 ms packets and A-law's lose the same stretches at the same input times, so the limit
  is the server's and not the codec's. Pushing 3% slower or faster moves nothing, so it is not
  a buffer filling. The spec's byte rule gives A-law 40 ms packets and loses a quarter of them.
- **Windows 11 discards every A-law Data PDU of exactly `FramesPerPacket` × `nBlockAlign`
  bytes**, 882, which is the spec's frame rule: the recording is empty. Packets of 440 and 442
  frames record; alternating 441 and 442 loses each 441 alone. Why is not visible from the
  wire. PCM at the capture format's rate is unaffected. Whether the size or the rate decides
  it is open: ADPCM cannot show it, since a block format has no packet of `FramesPerPacket` ×
  `nBlockAlign` bytes, and no other 8-bit format is offered.
- **Windows 11 loses part of every ADPCM packet** (#403, 2026-10-12). It offers MS-ADPCM and
  IMA-ADPCM each at 44.1 kHz stereo (`nBlockAlign` 2048), 22.05 kHz stereo (1024), 44.1 kHz
  mono (1024), 11.025 kHz stereo (512), 22.05 kHz mono (512), 8 kHz stereo (512), 11.025 kHz
  mono (256) and 8 kHz mono (256), MS-ADPCM with the seven standard coefficient pairs, and every
  block lasts 45 to 63 ms. To a client answering with all eight it opens the 22.05 kHz mono one
  with `FramesPerPacket` 441 and the same 44.1 kHz capture format. A Data PDU of one block,
  45.9 ms, keeps 30 ms and loses about 16, a third of the audio, for both codecs; the
  recording is otherwise the pushed signal (correlation 0.9). A block split over two or four
  Data PDUs records nothing, and more blocks to a PDU only lengthen it, so no packet the client
  can send records whole.
- **A tone cannot measure a loss.** A dropped stretch shows in a tone's phase only modulo one
  period, 2.27 ms at 440 Hz: the 10 ms drops above first read as 0.78 ms ones and a 452 Hz
  pitch. The noise correlation has no period to hide one in.
- **So the live tests map the recording to what was pushed** (#411, `holds_pushed_signal`;
  **the maintainer's call, 2026-10-12**, shown the alternative of pushing the tone and the
  noise together and keeping both checks). The host pushes a hash of each frame's index,
  averaged over four frames, on every channel; the check averages it down to the recording's
  rate, finds where the recording's first hundredth of a second came from, and then requires
  every later hundredth to match the signal at that same offset with a correlation of at least
  0.5 (clean runs measure 0.70 for PCM and 0.83 for A-law), over at least 4.5 of MCI's 5
  seconds. It sees any stretch dropped or repeated after the recording starts, to one sample
  of the recording (0.09 ms); a failure says where the stretch came from instead. It does not
  see what is lost before MCI starts recording, a change of level, or a loss smaller than one
  recorded sample. Dropping five whole 440 Hz periods a second, which a tone's power cannot
  see, and the 2.2.2.3 byte rule for A-law both turn it red.
- **Windows 11 drops audio input that arrives in bursts, and some PCM it receives on time**
  (#411). With the harness's first pusher, a tokio interval that on Windows ticks to a 15.6 ms
  quantum and now and then missed two or three ticks, packets arrived in bursts of three or four
  and half the PCM and A-law runs lost 10 to 40 ms; paced by its own thread to each 10 ms
  deadline, A-law recorded whole in 6 runs of 6. PCM still loses whole packets in about two runs
  of five (13 of 34), though every packet is written to the socket the moment it is pushed, no
  read took more than 2 ms to process, and TCP retransmitted no more than the idle host does.
  Pushing 0.5 % slower or faster, single-fragment 5 ms packets (5 of 6 lost), and four vCPUs
  for the VM (8 of 16) did not remove it; neither did MCI recording in the pushed format,
  44.1 kHz 16-bit stereo (2 of 7).
- **The PCM loss is the guest's audio engine falling behind** (#416). Traced inside the VM with
  ETW (`Microsoft-Windows-Audio`, `TerminalServices-RdpSoundDriver`, `RdpCoreTS`, logged by an
  elevated `logman` around the recording): in the one run of five that lost audio, the engine's
  pump logged **"Pump: Processing pass skipped"** 94 times (1 to 55 in the clean runs) and then
  **"Engine Glitch: CP Server Output Endpoint - Read Pointer Overwrite"** (`Audio` event 35) 12
  times, each of 1,764 bytes, one 10 ms packet; the recording lost 10 + 30 + 30 + 50 ms,
  120 ms, twelve packets. The clean runs logged no event 35. So the RDP endpoint writes each
  packet on time into the buffer it shares with the audio engine, and when the engine's pump
  misses its passes the writer overruns what the reader has not taken, packet by packet; the
  per-period "CrossProcess packet added" events arrived 20 to 47 ms apart in that stretch,
  against at most 21 ms in clean runs. The client cannot prevent it: its packets arrive whole
  and on time. A host should still deliver captured audio steadily, since bursts overrun the
  same buffer: the helper keeps no clock and sends what it is given when it is given it.
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
- **PCM and A-law only.** `justrdp-codecs` encodes MS-ADPCM and IMA-ADPCM (#403), checked
  against FreeRDP's, ffmpeg's and CPython's encoders, but the helper does not offer them,
  because Windows 11 loses a third of every packet (Reference behaviour). **That was the
  maintainer's call (2026-10-12)**, shown that measurement and the alternatives of offering
  them with the loss documented and of dropping the encoders as well. A server that records
  ADPCM whole would bring them back: their tags into `ENCODABLE_FORMAT_TAGS`, packets of whole
  blocks, and a live proof. AAC waits on #21's decoder-backend question; GSM 6.10 is not
  encoded.
- **PCM audio input loses packets on this Windows 11 VM** in about two runs of five, by the
  guest's audio engine overrunning its endpoint buffer when it skips processing passes (#416,
  Reference behaviour). Not measured on Windows on hardware; the PCM live test says it fails
  that often, and why.
- **8-bit PCM is unmeasured.** Windows 11 offers none, and at the capture rate its packet is
  `FramesPerPacket` × `nBlockAlign` bytes, the size it discards for A-law.
- **One server.** Only a Windows 11 client SKU has been measured; a Server SKU with the RD
  Session Host role did not open the channel for FreeRDP or mstsc (#400).
