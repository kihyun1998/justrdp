# M-Client first, M-Server deferred to Phase 8

## Decision

The roadmap is split into two milestones — **M-Client** and **M-Server** —
and the order is enforced. M-Client ships first; M-Server work begins at
Phase 8 (`§11`). Every roadmap item carries one of the tags `[both]`,
`[M-Client]`, or `[M-Server]`.

## Why

- **Validate `§5.1 Connector` on the client side first**, then have the
  M-Server acceptor (§11.1) reuse the pattern — i.e. a separate, mirrored
  `Sequence` trait. Carrying an unproven abstraction on both sides at once
  multiplies the cost of any change.
- **Smaller test matrix** — guaranteeing both client and server behaviour
  from the start would explode regression-test costs in the early phases.
  Client-only lets us treat real RDP servers (Windows / FreeRDP) as a fixed
  point and validate against them.
- **Commercial priority** — JustRDP's primary market hypothesis is the
  *embedder* (Tauri / WASM client). The server is secondary.

## Considered options

- **(a) M-Client → M-Server, sequenced** ⭐ accepted — this ADR.
- **(b) Both in parallel** — share the wire format in Phases 1–2, then run
  client/server in parallel from §5. Rejected: large throwaway risk if the
  abstraction turns out wrong.
- **(c) Server first** — the choice some libraries make (e.g. parts of
  IronRDP). Rejected: doesn't match our market hypothesis, and we'd have no
  client fixed point to validate against.

## Consequences

- §5.1 `Connector` and the §11.1 acceptor define *separate* traits with the
  same shape (see the **Sequence** entry in `CONTEXT.md`).
- When an M-Server request arrives before §11 begins, point to this ADR.
- Only items tagged `[both]` (§4 wire format, §6 codecs, etc.) advance any
  server-side work *indirectly* during the M-Client phase.
