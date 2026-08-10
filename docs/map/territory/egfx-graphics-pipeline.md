# EGFX graphics pipeline

## What it is

The modern graphics path (`[MS-RDPEGFX]`), carried over the
`Microsoft::Windows::RDS::Graphics` dynamic virtual channel: the server creates
off-screen **surfaces**, fills them with codec-compressed wire-to-surface commands,
maps them to output positions, keeps a bitmap **cache**, and expects the client to
acknowledge frames. It is server→client only, and it is reachable only if
`SUPPORT_DYN_VC_GFX_PROTOCOL` was set back at GCC.

## Governing decisions

- [ADR-0003](../../adr/0003-phased-codecs-differential-oracle.md) — the EGFX
  decoders (zgfx, RemoteFX Progressive) are the ones still on the phase-1
  `egfx-bootstrap` wrapper, so this territory is where the phased-ownership plan is
  visibly unfinished (epic #158).
- [ADR-0010](../../adr/0010-frameupdate-dirty-rect-contract.md) — surfaces blit
  straight into the framebuffer with no intermediate extract copy (#163).

## Design model

- **A surface is an addressable off-screen buffer with its own dirty list**, and it
  becomes visible only when `MapSurfaceToOutput` gives it an output-space origin.
  Until then, decoded pixels are real but unreachable — a decode bug and a mapping
  bug look identical from the framebuffer.
- **Frame acknowledgement is flow control, not bookkeeping.** A server that
  advertises frame-ack expects it; not sending it stalls the stream rather than
  producing an error.
- **The cache belongs to the connection, not the share** — it survives
  Deactivation–Reactivation, which is stated in the session code and matters here.
- **The EGFX channel is a DVC**, so its framing is the dynamic-channel layer's
  problem, not this territory's.

## Code

- `justrdp/src/egfx.rs` — `Surface`, `CachedBitmap` (`mapped`, `dirty`)
- `justrdp-pdu/src/egfx.rs` — `EgfxPdu`, `Rect16`, `Point16`, `decode_all`,
  `encode_caps_advertise`, `encode_frame_acknowledge`, `wrap_uncompressed`
- `justrdp-codecs/src/egfx.rs` — `Zgfx`, `Progressive`, `ProgressiveTile`
  (behind the `egfx-bootstrap` feature — the remaining phase-1 wrappers)
- Spec sections cited inline: `[MS-RDPEGFX]` 2.2.2.14, 3.3.8.2

## Reference behaviour

**None.** No verified external-fact store. Note that this is the territory whose
phase-2 rewrite (epic #158) *depends* on a reference comparison — the oracle is
`ironrdp-graphics`, and its shared lineage is itself an invariant below.

## Cross-cutting invariants

- [Oracle agreement is not independence](../invariant/oracle-agreement-is-not-independence.md)
  — the phase-2 rewrite is verified against a codebase sharing this project's
  lineage.
- [The frame path carries no owned pixels](../invariant/frame-path-carries-no-owned-pixels.md)
  — the surface→framebuffer blit is where the last extract copy was removed (#163).
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md)
- [Decoder dimension overflow on 32-bit](../invariant/decoder-dimension-overflow-32bit.md)
  — surface allocation is `width × height × 4`.

## Blast radius

- [Bitmap codecs](bitmap-codecs.md) — wire-to-surface payloads are codec streams;
  the Progressive rewrite moves work across this boundary.
- [Framebuffer & frame delivery](framebuffer-frame-delivery.md) — the blit target.
- [Virtual channels](virtual-channels.md) — the EGFX channel's framing, chunking and
  lifecycle.
- [MCS / GCC channel setup](mcs-gcc-channel-setup.md) — the `0x0100` early flag is
  the on/off switch for this whole territory.
- [Capability exchange & activation](capability-exchange-activation.md) — surface
  commands and frame-ack are capability-gated.

## Known holes / open

- **zgfx and RemoteFX Progressive are still `ironrdp-graphics` wrappers** behind
  `egfx-bootstrap`; epic #158 (slices #167–#172) is the rewrite, and #91 the
  bit-reader performance work alongside it.
- H.264 / AVC420 / AVC444 (epic #21) is absent — no oracle exists for it either
  (ADR-0002's amendment says so explicitly).
- Surface-to-surface and surface-to-cache commands are implemented against one
  server's behaviour; the VM's advertised cap set bounds what has ever been
  exercised.
