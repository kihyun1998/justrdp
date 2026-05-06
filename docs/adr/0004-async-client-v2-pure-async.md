# `AsyncRdpClient v2` is pure-async; the blocking runtime is frozen

## Status

`accepted` (commit `6361544`, 2026-04-30, roadmap §5.6.5)

## Decision

`justrdp-tokio::AsyncRdpClient v2` is implemented as *pure-async* — it never
calls `tokio::task::spawn_blocking` and never spawns a sync I/O thread of its
own. The previous v1 (an adapter that wrapped `justrdp_blocking::RdpClient`
via `spawn_blocking`) and `justrdp_blocking::RdpClient` itself are **frozen**:
bug fixes only, no new surface. All new work goes to v2.

## Why

- **Clean cancellation** — sync I/O parked inside `spawn_blocking` does not
  react promptly when the parent future is dropped. For long-lived RDP
  sessions that's a leak risk.
- **Embedder-friendly** — Tauri / WASM hosts run on cooperative scheduling.
  Not forcing a thread pool keeps us consistent with the §13.4 pattern.
- **Single source of truth for I/O state** — v1 had state spread across the
  sync `RdpClient` and the async shim, opening up race conditions.

## Considered options

- **(a) v2 pure-async, freeze v1 + blocking** ⭐ accepted — this ADR.
- **(b) Keep v1, evolve v2 in parallel** — maintaining the same surface in
  two vintages is expensive, and embedders would have to choose every time.
- **(c) Keep blocking, async as a thin wrapper** — leaves the cancellation
  problem unsolved for embedders and WASM.

## Consequences

- The v1→v2 migration guide is roadmap §13.5.
- Do not add new methods to `RdpClient` or to v1 `AsyncRdpClient` — land them
  on v2 and update the §13.5 migration notes.
- When a PR proposes "I/O is heavy here, let's wrap it in `spawn_blocking`",
  point to this ADR.
