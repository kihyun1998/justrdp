# justrdp

A pure-Rust RDP client library that owns every RDP-native protocol layer, so the host holds every
policy flag ([ADR-0017](docs/adr/0017-rebuild-so-the-host-holds-every-policy-flag.md)).

## Language

### Connecting

**Connection**:
One attempt to establish an RDP session with a server, from the TCP dial until it becomes a
Session or fails.

**Connect Stage**:
A labelled step of the Connection, shared by diagnostic logging and the host's progress UI. There
are seven, entered in order:

1. **tcp-connect**: the TCP dial to the server.
2. **x224-negotiate**: the X.224 Connection Request/Confirm that selects the security protocol
   (SSL / HYBRID / HYBRID_EX).
3. **tls-handshake**: the TLS upgrade.
4. **nla-credssp**: Network Level Authentication over CredSSP.
5. **capability-exchange**: client/server advertise and negotiate feature flags and desktop size.
6. **activation**: synchronize, control and font exchange that finalize the session.
7. **session-active**: entered on successful activation; lasts until disconnect.

**Session**:
A live RDP session after activation, lasting until disconnect or a fatal error.

### Shape of the library

**Sans-IO Core**:
The protocol logic as pure state machines: bytes and events in, actions and outputs out, with no
socket, runtime or async in it.

**Host Adapter**:
The layer that makes the Sans-IO Core real: it owns the socket and runtime, runs the TLS handshake
and CredSSP loop, and forwards outputs to the host.

**Policy flag**:
A value the client sends that a host may legitimately want different for its own reasons, such as
`earlyCapabilityFlags` or the EGFX versions. The host owns it.
_Avoid_: feature flag, policy-bearing field

**Implementation flag**:
A value that only tells the server what the core handles, such as rdpdr's `ioCode1`. The core owns
it.
_Avoid_: capability flag (both kinds travel in capability sets)

### Graphics

**Frame Update**:
A rectangle of the desktop and its new pixels in RGBA8888, the unit justrdp hands the host during
a Session.

**Legacy graphics**:
The graphics path of a session without the Graphics Pipeline: bitmap updates and surface commands
decoded straight into the framebuffer.
_Avoid_: slow path (MS-RDPBCGR's name for the non-fast-path PDU framing)

**Graphics Pipeline**:
The production graphics path on modern Windows (MS-RDPEGFX, "EGFX"): codec-compressed updates to
Surfaces, carried over a Dynamic Virtual Channel and enabled by `SUPPORT_DYN_VC_GFX_PROTOCOL`.

**Surface**:
An off-screen pixel buffer in the Graphics Pipeline that the server creates, draws into, caches
from and maps onto the visible desktop.

**Differential Oracle**:
A reference decoder (`ironrdp-graphics`) fed the same encoded input as a justrdp codec so their
outputs can be compared; scaffolding with a retirement condition, never the definition of a
correct picture.

### Channels

**Virtual Channel**:
A named side-band stream multiplexed over the Connection for features beyond the desktop image,
such as clipboard, audio and drive redirection.

**Static Virtual Channel**:
A Virtual Channel negotiated at GCC from the client's channel list.

**Dynamic Virtual Channel**:
A Virtual Channel the server opens on demand over the `drdynvc` channel.

**Host-terminated Channel**:
A Virtual Channel whose protocol the host runs to its end, such as clipboard, device redirection
and audio output; the core carries its messages without interpreting them.
_Avoid_: host channel, channel helper

**Core-terminated Channel**:
A Virtual Channel whose protocol the core runs to its end, such as the Graphics Pipeline and
Display Control.
_Avoid_: internal channel, DVC processor
