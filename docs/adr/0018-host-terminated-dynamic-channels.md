# 0018 — A Dynamic Virtual Channel can be Host-terminated

- Status: Accepted (epic #11)
- Date: 2026-10-06
- Kind: **judgement**. The maintainer chose between the options below, each with its
  consequences listed. A better derivation does not reopen it; the maintainer does.

## Context

Every Dynamic Virtual Channel was Core-terminated: the drdynvc manager accepts a Create Request
only for a name a core `DvcProcessor` registered (Display Control, the Graphics Pipeline) and
refuses every other name. Static channels already had a host seam (#307): messages in as
`SessionOutput::ChannelData`, out through `send_channel`, with the clipboard and device
redirection protocols run by helpers the host drives over it.

Audio output (`[MS-RDPEA]`) arrives on either transport with identical PDUs: the static channel
`RDPSND` or the dynamic channel `AUDIO_PLAYBACK_DVC`. Windows 8 / Server 2012 and later try the
dynamic channel first and fall back to the static one when it is refused (`[MS-RDPEA]` 3.1.3,
product note 11). Audio input, multitouch and camera redirection (#12, #15, #19) are
dynamic-only.

## Decision

**A host registers dynamic channel names in the session configuration, and the drdynvc manager
hands their messages to the host, which answers and closes them, the way the static channel seam
does.**

- The manager keeps the transport: Create/Close, fragmentation, reassembly and its caps. The
  host sees only complete messages.
- A name a core processor registered cannot also be registered by the host; the configuration
  is refused when the session is built, since the server opens dynamic channels only once the
  session is active.
- An unregistered name is refused, as today.
- A protocol the host terminates is run by a sans-IO helper that is indifferent to transport, so
  one audio output helper serves `RDPSND` and `AUDIO_PLAYBACK_DVC`.

### Options shown to the maintainer

- **Static channel only for this epic, and build the seam with audio input.** Rejected: it
  relies on the server's fallback, and #12 would build the seam anyway.
- **A core `DvcProcessor` for audio output.** Rejected: the same protocol would be run two ways,
  host-driven over the static channel and core-driven over the dynamic one.

### What this decision did not cover

- How a Host-terminated Dynamic Virtual Channel's protocol errors are handled. ADR-0014 governs
  core processors; a host helper's error is the host's, as on a static channel.
- The lossy `AUDIO_PLAYBACK_LOSSY_DVC`, which needs UDP transport (#16).

## Amendment (2026-10-06, #385): where the names are registered

The Decision first said the host registers its names "before connecting" and that a core name
is refused then. #385 built the registration into the session configuration instead, refused by
`SessionStateMachine::new`, because the server opens dynamic channels only once the session is
active. **Keeping that and rewording the Decision was the maintainer's call (2026-10-06)**,
shown the alternative of a second list in the connect configuration, refused before connecting.
