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
  a resize or teardown race the select loop safely.
- **Each connect stage is a tracing span** (plan.md §11d) — a no-op without a
  subscriber, so observability does not compromise portability.
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
  `SessionEvent`, `SessionFailure`, `generate_license_entropy`, `write_frame`
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

- **Reconnect is not implemented** — no auto-reconnect loop (plan.md §23), so a
  transient network drop ends the session.
- Multi-transport / UDP (epic #16) would add a second transport under this loop;
  nothing here anticipates it.
