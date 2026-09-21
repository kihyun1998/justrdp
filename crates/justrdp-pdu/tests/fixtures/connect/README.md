# `connect/` — server bytes captured before session-active

Server-to-client only, so no credential crosses into these files: the Client Info PDU carrying
the password travels the other way and never reaches a capture. Captured from the real VM
(`docs/agents/thegraph.md`'s third source; memory `test_environment`), one WS2022 box on one
advertised configuration — **they prove what this server sends, never what servers send.**

They are the repo's only server-to-client connect-sequence bytes that no encoder of ours
produced. Every encoder in `justrdp-pdu` writes client-to-server, because justrdp is a client,
so a round-trip test cannot reach these decoders at all. That is why they exist.

The sibling `session/` holds bytes from after the Font Map. Keep the two apart: the replays walk
each file assuming it holds its own leg only.

## The three files are not produced the same way

| File | Bytes | From | Regenerate |
|---|---|---|---|
| `connect-response.bin` | 101 | #203, 2026-08-20 — the MCS Connect-Response | `JUSTRDP_WRITE_CONNECT_FIXTURES=1` on `capture_connect_response_against_real_vm` |
| `conference-create-response.bin` | 62 | #203, 2026-08-20 — its GCC user data (offset 39 of the above) | same run |
| `finalization-replies.bin` | 156 | #252, 2026-08-25 — Synchronize, Control ×2, Font Map | **no generator.** Captured once through `JUSTRDP_CONNECT_CAPTURE_FILE` and carved by hand |

**Regenerating is deliberate, and running the VM suite is not it.** Since #311 the capture test
only compares against the first two files by default and fails if the server's bytes differ, so
`cargo test -p justrdp-tokio -- --ignored` never edits this directory. When it fails that way the
fixture is stale for the server, not broken: regenerate with the env var above and read the diff
before committing it.

## Who reads them

- `crates/justrdp-pdu/tests/real_server_connect.rs` — all three, in the stable gate: acceptance
  of what a real server sends, a truncation sweep over the first two, a single-bit-flip sweep
  over `conference-create-response.bin`, and a check that the GCC file is the tail of the MCS one
  (`the_two_fixtures_cannot_drift`) — so regenerating one without the other fails.
- `.github/scripts/seed_fuzz_corpus.py` — the first two, as the seed corpus of the `mcs` and
  `gcc` fuzz targets (nightly).
- `finalization-replies.bin` is also what
  `docs/map/territory/capability-exchange-activation.md`'s `## Reference behaviour` rests on.

## What they cannot prove

- **Acceptance, not rejection.** A conforming server never exercises a guard, so these files
  cannot redden on a guard that was deleted. #252 measured this for the finalization guards:
  removing either left the replay green, while making one too strict reddened it at once. The
  defect side lives in the unit tests in `justrdp-pdu/src/finalization.rs` and
  `justrdp/src/connect.rs`.
- **One server's configuration.** `finalization-replies.bin` shows this server sending all four
  replies in order, identical across four activations on both the connect and reactivation legs.
  That is a fact about this box, not an ordering guarantee — #252 decided against gating on it
  for exactly that reason.
- **Nothing the connect leg does not carry.** Save Session Info arrives on the session leg on
  this server (#304), so it is in `session/`, not here.
