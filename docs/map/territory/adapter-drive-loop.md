# Adapter drive loop (tokio)

## What it is

The only place in the repo that owns a socket. It drains the core's `Action`s (open,
write, start TLS, start NLA), feeds it `Event`s, applies a per-stage timeout, runs
the TLS and CredSSP sub-protocols that deliberately live outside the core, and then
drives the session: reading bytes, delivering frames and cursor events to
host-supplied sinks, accepting input and resize commands, and cancelling cleanly.

**Its size is a finding, not a detail.** The adapter file is 4875 lines, of which
**1032 are code** and the rest tests. `CLAUDE.md` and `justrdp/src/lib.rs` used to
call it *"~30 lines"* — true of the *drive loop* (a match over `Action`), false of
the crate, and it shipped verbatim to docs.rs. Both were corrected when this map was
written; the number above is what to keep it honest against.

The two numbers have since moved apart, which is the point of keeping both: the total
grew by ~1250 lines across #197 and #198 and the **code count did not move at all**,
because every line of both was harness. A single "lines in this file" figure would have
read as the adapter growing a third of its size.

## Governing decisions

- [ADR-0001](../../adr/0001-sans-io-state-machine-core.md) — the adapter/core split
  is this territory's reason to exist.
- [ADR-0002](../../adr/0002-dependency-boundary.md) — `tokio`, `sspi` and
  `tokio-rustls` are confined here.
- [ADR-0005](../../adr/0005-tls-trust-policy.md) — the trust policy the adapter
  injects.

## Design model

- **Policy is injected, never decided here either** — the host supplies credentials,
  the trust policy, the frame sink and the cursor sink; the adapter wires them.
- **One timeout seam.** Every stage's I/O goes through `with_stage_timeout`, so the
  timeout/error policy exists once and a failure is reported *with its stage name*.
- **Three entry points, increasing in capability**: `connect`,
  `connect_with_timeouts`, `connect_with_options`; and three session runners:
  `run_session`, `run_session_with_input`, `run_session_with_commands`.
- **Cancellation is a token, not a drop** — `tokio-util`'s `CancellationToken` lets
  a resize or teardown race the select loop safely. The loop sees it between machine calls
  only, so a call's length bounds how late it lands.
- **A paused machine resumes through the select loop** (#496). When the machine reports
  `has_pending_input()`, the runners arm a `yield_now()` branch that resumes it with no bytes.
  The yield first returns to the scheduler, so a cancellation, input or the open-frame timer
  already due wins over the resume. The socket is not read while the machine is paused, so a
  server sending faster than the client paints is held back by TCP rather than growing the
  inbox. A reader that does nothing between calls drains instead (the test harness's
  `feed_drained`, the `real_server_*` tests, the session fuzz targets).
- **Each connect stage is a tracing span** — a no-op without a subscriber, so observability
  does not compromise portability. Core records use `rdp_<area>` targets
  (`rdp_finalization`, `rdp_drdynvc`, …), so `RUST_LOG=rdp_drdynvc=debug` isolates one area.
- **Only the read is raced; every write runs to completion.** The session runners'
  `tokio::select!` races `stream.read` against the input/command receivers, and the writes
  happen inside the winning arm's body, never as a raced future. A read is cancel-safe: a
  cancelled read has consumed nothing. A write is not: cancelling a partial `write_all` and
  retrying duplicates the bytes already sent, which desynchronises the stream (the same trap
  IronRDP's `Framed::write_all` documents). A new arm that awaits a write *as the raced
  future* reintroduces it.
- **A frame left open is released after 1 s** (#470). `run_session_with_input` and
  `run_session_with_commands` (which `run_session` reaches through the first) look at the
  machine once per batch of outputs, which is once per socket read. `OpenFrameRelease` arms a
  deadline `OPEN_FRAME_RELEASE` after the first batch that leaves a frame open, and a `select!`
  arm then calls `release_open_frames` and feeds what it returns through the same output loop as
  the socket's. A batch that leaves no frame open disarms it; one still open after a release
  re-arms it, and so does a frame open across a Deactivation, whose releases return nothing.
  **`has_open_frame` alone cannot say a frame ended**: a read that ends one frame and
  opens the next leaves it true on both sides, and the first frame's deadline would release the
  second one milliseconds in. So the runner also compares `SessionStateMachine::frames_ended`,
  which only grows (a frame a reactivation or a channel close drops counts too), and restarts the
  interval when it moved.
  That the host releases, and the core only provides the means, was the maintainer's call
  (2026-10-16); **the 1 s is a derivation, not their call**: it only has to sit far above any
  frame a server ends. Measured on the WS2019 VM (2026-10-16, throwaway instrumentation of
  `feed_session`, never committed), over one order Frame Marker session and two Graphics Pipeline
  sessions: 3 frames were still open when a socket read had been fed, open for 0.4, 3.5 and
  7.6 ms; every other frame started and ended inside one read. The arm is a sleep, so it is
  cancel-safe like the read, and it adds no read site: the capture funnel stays the only path from
  the socket. The interval is not host-configurable. The VM tests drive the machine themselves,
  not through a runner, so they never release. The proof is
  `run_session_with_input_releases_an_unended_frame` and its `run_session_with_commands` twin, on
  tokio's paused clock over a loopback TLS server, and
  `the_release_deadline_follows_the_frame_open_now` for the restart.
- **Tokio's paused clock does not wait for a loopback socket.** It jumps to the next timer
  whenever the runtime has nothing ready, and a byte written on loopback is not always readable
  by then (presumably because readiness reaches the runtime through IOCP on this Windows host; not
  measured). A test whose server sleeps between
  writes therefore lets virtual time pass the client's deadline before the client has read: #470's
  first restart test saw a frame end at 1.536 s that was sent at 0.6 s. A paused-clock test over a
  socket is sound only while the client's own timer is the only one, as in the two release tests;
  timing across several writes is tested on the machine directly.
- **The VM-dependent tests live here and are `#[ignore]`d**, which is why the
  coverage job excludes this crate.
- **Every write goes out through `write_frame`, which flushes** (#325). The connect driver, the
  CredSSP loop and all three session runners use it. The trap: `tokio-rustls`'s
  `poll_write` returns `Ok(n)` once rustls has taken the plaintext, even when the socket
  would block on the ciphertext (0.26.5, `common/mod.rs`). Unflushed, that ciphertext stays
  in the TLS session until the next write, and before #325 nothing flushed. Small messages
  never filled the socket, and later traffic always pushed the rest out, so the bug stayed
  hidden until a 262,156-byte clipboard response was the last thing written. Measured on the
  VM (#325): with nothing written after it, the server never got the rest, 3 of 3 runs; with
  the flush, 3 of 3 arrived. A Format List written after it by chance rescued 4 of 6 runs.
  Flushing every write, rather than once per batch, is a derivation; the flush on an empty
  session costs one socket poll. `a_large_channel_message_is_written_whole` is the
  regression test: a mock server stops reading so the client's socket fills mid-message.
  **Fixing it in #325 rather than in its own issue was the maintainer's call (2026-09-28)**,
  after being shown two alternatives: file it and fix it first, or fix only the channel path.

## Code

- `justrdp-tokio/src/lib.rs` — `connect`, `connect_with_timeouts`,
  `connect_with_options`, `connect_inner`, `with_stage_timeout`, `announce_stage`,
  `configure_session_socket`, `Transport`, `ConnectOutcome`, `ConnectOptions`,
  `ConnectTimeouts`, `ConnectFailure`, `Credentials`, `ServerAddr`, `run_session`,
  `run_session_with_input`, `run_session_with_commands`, `SessionCommand`,
  `SessionEvent`, `SessionFailure`, `generate_license_entropy`, `write_frame`,
  `OPEN_FRAME_RELEASE`, `OpenFrameRelease`
- `justrdp-tokio/src/trust.rs` — the injected policy (see
  [TLS transport security](tls-transport-security.md))

## Reference behaviour

**None.** No verified external-fact store.

## Cross-cutting invariants

- [The frame path carries no owned pixels](../invariant/frame-path-carries-no-owned-pixels.md)
  — the sink is invoked **synchronously** from this loop, and that is what makes the
  borrow sound; an async or deferred sink would force a copy back into the library.

## Blast radius

- [X.224 negotiation](x224-negotiation.md), [TLS transport security](tls-transport-security.md),
  [NLA / CredSSP authentication](nla-credssp.md) — each `Action` variant is a match
  arm here; a new one is a change in this file.
- [Session loop & PDU dispatch](session-loop-dispatch.md) — the read/write/select
  loop and the ordering between input and output.
- [Framebuffer & frame delivery](framebuffer-frame-delivery.md) — the frame sink is
  invoked here, synchronously, which is what bounds ADR-0010's borrow.
- [Input & platform scancode tables](input-scancodes.md) — `SessionCommand` and the
  platform toggle-flag read.
- [Verification harness](verification-harness.md) — the loopback CredSSP test and
  every VM test live here.

## Known holes / open

- **Reconnect is not implemented** — no auto-reconnect loop, so a transient network drop
  ends the session. The cookie half shipped in #306; when and how often to reconnect is the
  host's reconnect strategy (CLAUDE.md, "the host owns").
- Multi-transport / UDP (epic #16) would add a second transport under this loop;
  nothing here anticipates it.
