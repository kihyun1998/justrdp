# Audio output

## What it is

The audio output channel (`[MS-RDPEA]`): the server sends audio samples and the client
confirms each one once it has played it. `justrdp-pdu::rdpsnd` holds the PDUs,
`justrdp-codecs::pcm` turns linear PCM into signed 16-bit samples, and
`justrdp::rdpsnd::AudioOutput` is a sans-IO helper the host drives, as the clipboard and device
redirection helpers are. The helper does not care which transport carries the messages: the
same bytes ride the static channel `rdpsnd` or the dynamic channel `AUDIO_PLAYBACK_DVC`
(ADR-0018). Epic #11; #386 decodes PCM over the dynamic channel, and #387 proves the static
channel and the server's fallback to it. A-law is #388's, MS-ADPCM and IMA-ADPCM #389's.

## Governing decisions

- [ADR-0018](../../adr/0018-host-terminated-dynamic-channels.md) — the dynamic channel is
  Host-terminated, and one transport-indifferent helper serves both transports.
- [ADR-0016](../../adr/0016-policy-flags-are-the-hosts.md) — the format list and its order,
  the Quality Mode, and whether volume control is advertised are the host's; the version, the
  `TSSNDCAPS_ALIVE` bit and never advertising pitch are the core's, and a format the core cannot
  decode is refused.
- [ADR-0003](../../adr/0003-phased-codecs-differential-oracle.md) and the
  [ADR-0001 Amendment](../../adr/0001-sans-io-state-machine-core.md) — every audio codec is
  owned in `justrdp-codecs` (epic #11's grilling, 2026-10-06).

## Design model

- **The host names format tags, not formats.** `AudioOutputConfig::format_tags` lists the
  `wFormatTag`s the host takes, most preferred first, each once. The helper answers the
  server's list with every server format of those tags **that the core decodes**, in the
  host's tag order and the server's order within a tag, copied as the server sent it. For PCM
  that is 8 or 16 bits, at least one channel, and an `nBlockAlign` of exactly one frame, so a
  block always holds whole frames of `channels` samples (#386's review: the tag alone let
  24-bit PCM and a half-frame `nBlockAlign` through). So the client list is a subset of the server's,
  as 2.2.2.2 requires, `cbSize` data included. This shape was confirmed by the maintainer
  (2026-10-07, #386), who was shown the alternative of exact formats from the host, which
  would need the host to know the server's list. A Wave's `wFormatNo` indexes the **client's**
  list (3.1.1.2). With no server format of the host's tags the answer is an empty list, and
  the host learns it from `AudioOutputEvent::Negotiated`.
- **A refused sample is still confirmed.** A sample whose header was read but which the
  helper refuses (a `wFormatNo` outside the client's list, data that is not whole frames, a
  Wave PDU that does not match its WaveInfo) comes out as `AudioOutputEvent::Dropped` with its
  `WaveConfirm` token and a `warn` record, and the host confirms it like a block it dropped.
  A malformed PDU whose header cannot be read is still a `DecodeError`. **Derivation**, not a
  call: the host-confirms decision says a block is confirmed once played *or dropped*, the
  clipboard helper answers a request whose id it can read, and IronRDP confirms refused waves
  (`client.rs`, "still confirm so servers can advance latency accounting").
- **The core has no clock, so the host confirms.** Each `AudioBlock` carries a `WaveConfirm`
  token holding its `wTimeStamp` and `cBlockNo`. The host returns it with the milliseconds
  since arrival once it has played or dropped the sample, and `AudioOutput::confirm` encodes
  the Wave Confirm. The spec asks for it "immediately after" the sample is emitted to
  completion, with the timestamp plus that delay (3.2.5.2.1.6). The token makes the helper
  keep no per-block state. That placement was the maintainer's call in epic #11's grilling
  (2026-10-06), over a core-sent immediate confirm and over FreeRDP's two confirms per sample.
  The timestamp wraps at 16 bits, where FreeRDP wraps at 65,535.
- **A WaveInfo PDU makes the next message a Wave PDU.** The Wave PDU has no header; its first
  four bytes are padding that the four bytes the WaveInfo carried replace. A WaveInfo's
  `BodySize` counts the Wave PDU's data too, so `WaveInfo::sample_len` is `BodySize` − 8 and
  the Wave PDU must be exactly that long. The pending WaveInfo is the one piece of state
  between messages. A WaveInfo announcing four bytes or fewer, which 2.2.3.3 forbids, still
  takes the next message as its Wave, which is then dropped, so the framing holds.
- **The helper answers what needs no decision**: Training with Training Confirm, echoing
  both fields, and the Quality Mode after its format list whenever the server's version is at
  least 6 (2.2.2.3). Pitch PDUs are ignored, as 2.2.4.2 requires, and a Volume PDU reaches the
  host only when it advertised volume control. An unknown `msgType` is skipped (ADR-0009). A
  malformed PDU, a `wFormatNo` outside the client's list and a sample that is not whole
  `nBlockAlign` frames are `DecodeError`s, which the host gets back from `process`.
- **The version is 8**, which brings Wave2. `wDGramPort` is always 0, which keeps audio on the
  virtual channel; UDP and the lossy channel are #16's.
- **8-bit PCM is unsigned around `0x80`, 16-bit PCM is signed little-endian.** Microsoft's
  documentation states the signedness, not the byte order. The byte order is measured below.
- **Which transport carries audio is the server's, and the host's only lever is registering
  `AUDIO_PLAYBACK_DVC`.** With it registered the server uses the dynamic channel; without it the
  server's Create Request is refused and audio comes on `rdpsnd`. `rdpsnd` needs no channel
  option beyond `INITIALIZED`, unlike `cliprdr` (#321). Either way the host feeds the same
  `AudioOutput`.
- **A host that does not want audio** requests `rdpsnd` (which the server needs for `rdpdr`),
  registers no audio channel, and leaves `rdpsnd` unanswered.

## Code

- `justrdp-pdu/src/rdpsnd.rs` — `ServerPdu`, `WaveInfo`, `AudioFormat`, `ClientFormats`,
  `decode_wave`, `encode_client_formats`, `encode_quality_mode`, `encode_training_confirm`,
  `encode_wave_confirm`, `CHANNEL_NAME`, `DVC_CHANNEL_NAME`
- `justrdp-codecs/src/pcm.rs` — `decode`, `PcmError`
- `justrdp/src/rdpsnd.rs` — `AudioOutput`, `AudioOutputConfig`, `AudioOutputConfigError`,
  `AudioOutputEvent`, `AudioBlock`, `WaveConfirm`, `QualityMode`, `CLIENT_VERSION`,
  `DECODABLE_FORMAT_TAGS`
- `fuzz/fuzz_targets/rdpsnd.rs` — the PDU parser and the helper over split input
- Spec sections cited inline: `[MS-RDPEA]` 2.1, 2.2.1, 2.2.2.1, 2.2.2.1.1, 2.2.2.2, 2.2.2.3,
  2.2.3.1–2.2.3.4, 2.2.3.8–2.2.3.10, 2.2.4.1, 2.2.4.2, 3.1.1.2, 3.2.5.1.1.2, 3.2.5.2.1.6,
  section 4 (the annotated examples the PDU tests decode byte for byte)

## Reference behaviour

**Measured against the WS2022 test VM (#387, 2026-10-07):**

- **The server falls back to `rdpsnd` when `AUDIO_PLAYBACK_DVC` is refused.** With `rdpsnd`,
  `rdpdr` and `drdynvc` requested and no audio channel registered, the server asked for
  `AUDIO_PLAYBACK_DVC` twice in the run whose log was read, was refused both times, and then sent the same stream on `rdpsnd`:
  the format list, four Training PDUs, 30 Wave2 PDUs of PCM 44.1 kHz stereo 16-bit, 491,520
  samples, little-endian as on the dynamic channel
  (`a_sound_falls_back_to_the_static_channel_when_the_dynamic_one_is_refused_on_the_real_vm`,
  which asserts the refusal record). `[MS-RDPEA]` product note 11 says this of Windows 8 /
  Server 2012; WS2022 does it too.
- **Without `drdynvc` at all, audio comes on `rdpsnd` the same way**, the same 30 blocks
  (`a_sound_reaches_the_host_over_the_static_channel_without_drdynvc_on_the_real_vm`).
- **`rdpsnd` requested with `INITIALIZED` alone is answered**, so `CHANNEL_OPTION_SHOW_PROTOCOL`,
  which `cliprdr` needs, was not tried.
- This also settles #307's silent `rdpsnd`: that probe refused the dynamic channel too, but
  played no sound, and the server sends nothing on either channel until a sound plays.

**Measured against the WS2022 test VM (#386, 2026-10-07):**

- **Each audio VM test also asserts the transport**: every block arrives on the channel its
  mode names, and none on the other.
- **The VM had no audio until its Windows Audio service ran.** `Audiosrv` and
  `AudioEndpointBuilder` were `Stopped`, the default on Windows Server, and the session's
  speaker icon was crossed out. `SoundPlayer.PlaySync()` returned at once and nothing arrived
  on the channel. The maintainer set both services to Automatic and started them on the VM
  console (2026-10-07). A VM rebuilt without that loses this territory's live proof
  (`a_sound_played_in_the_session_reaches_the_host_as_pcm_on_the_real_vm`).
- **The format list comes only when a sound plays.** It arrived 2.2–2.3 s (two runs) after the test
  started typing the PowerShell line that plays the sound, and typing that line takes about
  1.5 s. #385 saw nothing on the channel in 90 s of a session that played nothing.
- **The server's list holds 26 formats, version 8**, in this order: AAC (`0xA106`, 44.1 kHz
  stereo 16-bit) four times, PCM 44.1 kHz stereo 16-bit once, then MS-ADPCM (`0x0002`) and
  IMA-ADPCM (`0x0011`) at 44.1, 22.05, 11.025 and 8 kHz in stereo and mono, A-law (`0x0006`)
  22.05 kHz stereo 8-bit once, and GSM 6.10 (`0x0031`) at four rates. **There is no µ-law
  (`0x0007`)**, and IMA-ADPCM is offered, though `[MS-RDPEA]` product note 4 lists neither
  that way.
- **Every sample came as Wave2**: 30 Wave2 PDUs and no WaveInfo, for a stock
  `%windir%\Media\Alarm01.wav`, in PCM 44.1 kHz stereo 16-bit, 491,520 samples (16,384 per
  block, about 186 ms). The server also sent four Training PDUs.
- **16-bit samples are little-endian**: the mean step between consecutive samples of a
  channel is 158.8 read as sent and 17,612.7 byte-swapped. The test asserts that comparison,
  and decoding big-endian turns it red.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — every
  audio message is server-supplied, and a WaveInfo's `BodySize` announces the length of the
  next message; `ServerPdu::decode` has a proptest and a fuzz target that also drives the
  helper and the PCM conversion.
- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — the client list names only formats the core decodes, version 8 promises Wave2, and
  volume control is advertised only when the host takes Volume PDUs.

## Blast radius

- [Virtual channels](virtual-channels.md) — the dynamic channel seam this rides on, and the
  static channel seam #387 will add.
- [Device redirection](device-redirection.md) — the server starts audio only with `rdpdr`
  advertised, and `rdpdr` only with `rdpsnd` requested.
- [Bitmap codecs](bitmap-codecs.md) — `justrdp-codecs` now holds audio codecs too, and its
  crate-level rules (no external dependency, the oracle discipline) bind them.
- [Verification harness](verification-harness.md) — the live proof depends on the VM's audio
  service, a VM state outside the repository.

## Known holes / open

- **WaveInfo + Wave is proven against the spec's example only**: this server sent Wave2 in
  every block.
- **Two strictnesses are unmeasured, because this server sent only Wave2.** A Wave PDU longer
  than its WaveInfo announced is dropped, where FreeRDP and IronRDP take the announced length;
  and a WaveInfo followed by anything but its Wave loses that message, which the spec rules out
  (the PDU after a WaveInfo MUST be a Wave). ADR-0009 §3(a) allows both.
- **Only PCM decodes.** A-law is #388, and MS-ADPCM and IMA-ADPCM are #389. Measuring this
  server's list re-planned both (the maintainer's calls, 2026-10-07): IMA-ADPCM, which epic #11
  had dropped on product note 4, joined #389, and µ-law, which this server does not offer, left
  #388.
- **AAC is offered first and not taken** (#21's decoder-backend question).
