# 0001 — sans-IO state machine core

- Status: Accepted — the workspace sketch in Decision superseded by the Amendment below (2026-09-04), which states the tree rule as concrete paths
- Date: 2026-06-08

## Context

A from-scratch RDP client must be tested without network access, portable across async runtimes (tokio, blocking, WASM), and isolated from host concerns (frame sinks, I/O loops). Additionally, the phased-codec strategy (decision 3) requires feeding identical bytes to both justrdp and ironrdp simultaneously to verify bit-for-bit output equivalence — the differential test oracle.

Traditional async-coupled designs embed socket I/O directly in connection logic (e.g., `async fn connect() { socket.write(...).await; socket.read(...).await }`), which makes all three goals impossible:

- **Offline testing.** Logic awaiting the socket cannot be tested without a live network or mock async executor.
- **Runtime portability.** Tokio-coupled code cannot run on a blocking executor or WASM runtime.
- **Differential oracle.** To feed identical bytes to justrdp and ironrdp in the same test, both must receive the same sequence of inputs; but if justrdp's connect logic owns the socket and drives reads/writes, it cannot receive pre-recorded bytes from a test harness.
- **Host isolation.** The Frame Update sink and input command queue must cross a boundary without exposing the runtime's internal types to the host adaptor.

## Decision

The `connect` and `session` logic are **sans-IO state machines**: pure functions (modulo a nominal `RngCore` for nonces) that accept bytes in and yield actions (connect-to-host, write-bytes-to-socket, emit-FrameUpdate) and a next state, with no embedded async or socket I/O.

**Structure:**

```
Core state machines (justrdp crate, sans-IO):
  - ConnectStateMachine: TCP → TLS → NLA → MCS/GCC → Activation
  - SessionStateMachine: post-activation frame loop

Workspace:
  - justrdp-pdu: wire encode/decode + every PDU
  - justrdp: the state machines + channel processors + surface model
  - justrdp-codecs: phased-c2 codec re-exports (transitional)
  - justrdp-tokio (later): ~30-line I/O adapter (per runtime)

I/O adapter (justrdp-tokio, ~30 lines):
  - Single-threaded Tokio runtime
  - Socket read loop feeds bytes to ConnectStateMachine
  - ConnectStateMachine actions (write, timeout, proceed) drive the socket
  - Session-active state transitions to SessionStateMachine
  - SessionStateMachine outputs (FrameUpdate, disconnect reason) routed to host sinks
  - Per-stage timeout/cancel via tokio::timeout / CancellationToken

Host integration (application-specific):
  - Frame sink: fn(FrameUpdate) — synchronous, non-blocking
  - Input queue: mpsc::UnboundedReceiver<InputEvent>
  - Resize queue: mpsc::UnboundedReceiver<(u32, u32)> for Display Control
  - Connect-stage progress callback: fn(&str) for diagnostic UI
```

## Consequences

**Positive:**

- **Offline codec testing.** Capture a byte sequence from a real RDP server (via pcap or a test VM), feed the identical bytes to both justrdp's SessionStateMachine and ironrdp's session loop in the same test, decode the frame outputs, and byte-diff the pixels. This unlocks confidence in phased-c2 (codec rewrites).
- **Runtime portability.** The state machines are pure — they run on any runtime (tokio/blocking/WASM) via a thin adapter. Swapping runtimes requires only a new adapter crate, not rewriting the machines.
- **Per-stage timeout/cancel.** The adapter can apply `tokio::timeout` to each stage independently (e.g., TCP connect gets 10s, TLS gets 15s, NLA gets 30s). If a stage hangs, the adapter cancels and surfaces the stage name to the UI.
- **Host isolation.** The state machines emit plain `enum Action { WriteBytes, Timeout, Proceed, EmitFrameUpdate }` and take plain bytes in. The adapter and host glue (`lib.rs` or equivalent) can layer async, Tauri channels, and other host concerns without the machines knowing about them.
- **Testability.** The connect/session logic can be tested in sync code (`#[test]` with `Vec<u8>` I/O buffers) without a runtime, socket, or VM. State assertions are direct struct inspection.

**Negative:**

- **More boilerplate.** The adapter loop is straightforward (~30 lines per runtime) but non-trivial. A naive async-coupled design would be 10 lines shorter. This cost is acceptable for the testing + portability + isolation wins.
- **Explicit state threading.** Each state machine transition must be explicit: `(new_state, actions) = state.process(bytes)`. The machine does not maintain internal position across a buffer (e.g., "read 5 bytes, pause, wait for more"). The adapter must buffer partial frames and retry `process` on each new byte batch. This is a one-time design cost per machine, not a per-call cost; it is well-understood (see ironrdp's `ClientConnectorState::step` or FreeRDP's state machine).
- **Cannot await within the machines.** Any I/O (socket, timer, KDC lookup) must happen in the adapter layer, not the machines. For CredSSP/NLA (which yields KDC network requests to the caller — SSPI's design), this is a natural fit; for custom channel processors, it means a processor cannot directly spawn a blocking syscall. This constraint is intentional and aligns with ADR-0005 (channels use plain seams).

## Alternatives considered

**Async-coupled design (rejected):**

```
async fn connect(socket: &mut TcpStream) {
  socket.write_all(&X224_REQ).await?;
  let resp = socket.read_exact(...).await?;
  ...  // NLA, MCS, etc., all await socket
}
```

Pros: shorter code, no explicit state threading.

Cons: 
- Testing requires a mock async executor or real network.
- Runtime-locked to whichever executor the logic used (`tokio`, `async-std`, etc.).
- Cannot feed captured bytes to both justrdp and ironrdp in the same test harness.
- Host adaptor cannot isolate host concerns; the async machinery is baked in.

**Trait-based abstraction over I/O (rejected):**

```
trait RdpSocket: Send {
  async fn write(&mut self, bytes: &[u8]);
  async fn read(&mut self, buf: &mut [u8]) -> usize;
}
```

This defers the problem: the machines are now trait-generic, but the trait is still async, still runtime-coupled, and still makes differential testing harder (the trait impl must be mocked differently for justrdp vs ironrdp). The sans-IO design achieves the same decoupling without the trait indirection.

---

## Amendment (2026-09-04): the tree rule, as concrete paths

**Gap this closes.** Decision's `Structure:` block sketches the workspace at crate
granularity and says nothing about which directory owns which *file*. A directory
boundary is where the seam is physically expressed, so a file written to the wrong one
breaks the seam while producing **no error, no failing test and no warning** — the one
class of mistake this repo's gates structurally cannot catch. The rule below was compiled
by `plat` against four maintainer-confirmed peers (`quinn-proto`/`quinn`/`quinn-udp`,
`ironrdp-pdu`/`-graphics`/`-tokio`, `rustls`, `h2`) and lived only in a generated build
document until that document was retired; **no other file in the repo restates it.**

**Two lines of Decision's block are now false, and are corrected here** rather than left
to be read as current:

- `justrdp-codecs: phased-c2 codec re-exports (transitional)` — codecs are **fully
  self-owned** since #189; `ironrdp-graphics` is a **dev-dependency oracle only** and is
  absent from the runtime graph.
- `justrdp-tokio (later): ~30-line I/O adapter` — the *drive loop* is a few dozen lines
  of `match` on `Action`, but the crate is **~1,000 lines**: the TLS handshake, the
  CredSSP token loop, per-stage timeouts and the session runner live there too. The
  "~30 lines" figure describes one function and was read as describing the crate.

**A declared rule outranks what the tree merely looks like** — and here the two never
conflicted. Measured: the declared dependency boundary has **zero violators**, and the
measurement is *stricter* than the declaration (`justrdp-codecs` has no external
dependency at all; the four crates depend only downward).

| Path | Owns | Grounds |
|---|---|---|
| `crates/justrdp-pdu/src/*.rs` | one file per `[MS-*]` protocol area — bytes↔types only. **Zero external dependencies** | this record + ADR-0002, measured 0 violators |
| `crates/justrdp-pdu/src/<area>/` | a protocol area that outgrew one file. Module root is **`<area>.rs` beside it**, never `mod.rs` | spelling rule |
| `crates/justrdp-codecs/src/*.rs` | one codec per file — **pixel math only**. Depends on `justrdp-pdu` and nothing else | ADR-0003 / ADR-0007, measured |
| `crates/justrdp-codecs/src/<codec>/` | a codec that outgrew one file | spelling rule |
| `crates/justrdp/src/*.rs` | the sans-IO state machines and the host-facing output types. **No `tokio`, no `rustls`, no `sspi`** | this record; measured: `x509-cert` + `tracing` only |
| `crates/justrdp-tokio/src/*.rs` | **the only place `tokio`, `rustls`, `sspi` or `ring` may appear.** Policy injection | ADR-0002, measured 0 violators |
| `crates/*/tests/*.rs` | **differential-oracle and real-corpus tests only** | see the test-layout rule below |
| `crates/*/tests/fixtures/<name>/` | captured real-server bytes plus a `README.md`. Appears **only** in a crate whose tests replay them | which is why `crates/justrdp/tests/` has none — both its tests are differential |
| `crates/*/proptest-regressions/` | generated. Never authored | — |
| `fuzz/fuzz_targets/*.rs` | fuzz targets, **out of the workspace** | matches 3/3 peers that run a fuzz lane |
| `.github/workflows/*.yml` · `.github/scripts/*.py` | things that **are** CI gates | — |
| `docs/adr/NNNN-<kebab>.md` · `docs/agents/*.md` · `docs/map/territory/<area>.md` · `docs/map/invariant/<claim>.md` | decision records · agent contracts · the wiring map | — |

**`fuzz/` is out of the workspace, and that is a gate blind spot, not an oversight.**
`cargo <cmd> --workspace` does not build it, so a rename or a public-path change can leave
it broken while every gate stays green. It needs its own
`cargo check --manifest-path fuzz/Cargo.toml`.

### Two layout rules that were previously declared nowhere

Both were carried as *deliberate divergences from prior art* in the retired build document
and, unlike every other row there, **neither named a decision record** — so both are
recorded here rather than dropped.

- **`justrdp-pdu/src/` is flat** — one file per `[MS-*]` protocol area, 25 of them, where
  **IronRDP** nests by area (`basic_output/`, `gcc/`, `input/`, `rdp/`, `connection/`).
  The grounds are not taste: `docs/map/territory/` depends on a **1:1 area↔file
  correspondence**, so nesting would break the map's addressing scheme, which is how a
  change's blast radius is looked up before it is designed.
- **Unit tests are inline `#[cfg(test)]`; `crates/*/tests/` holds differential and corpus
  tests only** — where **h2** and **quinn** put ordinary integration tests in `tests/`.
  Measured 15/15 conforming at the time of writing. Keeping `tests/` reserved is what
  makes "does an owned basis exist for this codec?" answerable by listing a directory.
