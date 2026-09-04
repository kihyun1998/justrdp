# thegraph build (justrdp)

## What this project is

A pure-Rust RDP client library that owns every RDP-native protocol layer itself as a
sans-IO state machine, delegating only security-critical non-RDP work (`rustls`, `sspi`)
to the adapter. See `CLAUDE.md`.

## References

| Source | Informs | Reached by | Binding |
|---|---|---|---|
| `[MS-*]` normative specs — `[MS-RDPBCGR]`, `[MS-RDPRFX]`, `[MS-RDPEGDI]`, `[MS-RDPEGFX]` | how it works — what we **emit** | `curl -sL <learn.microsoft.com/…> > "$SCRATCH/spec.html"`, then `grep -n` — **raw** | **spec** — cite the section |
| FreeRDP (C) + IronRDP (Rust) real source | how it works — hidden state, server tolerance, CVE points | `gh api repos/<o>/<r>/contents/<path> --jq .content \| base64 -d`, then `grep -n` — **raw**. `WebFetch` banned: it drops handler bodies, so a branch that *is* there reads as absent | example |
| The real VM — `192.168.136.136` (memory `test_environment`) | how it works — what we **accept** | a throwaway probe, or `JUSTRDP_CONNECT_CAPTURE_FILE` into a committable fixture — **raw observation**. One WS2022 box: it proves the paths it advertises and nothing about the ones it does not | **spec** for the receive path |
| Published external state — crates.io, an upstream repo's own state | how it works | a registry query / `gh api`, never a sentence about them — **raw** | **spec** — it is the state, not an example |
| Layout peers — `quinn-proto`/`quinn`/`quinn-udp`, `ironrdp-pdu`/`-graphics`/`-tokio`, `rustls`, `h2` | **where files go**, and nothing else | `gh api …/contents/<path>` against the **real tree** — **raw**. A layout read off a docs site or a starter template is summarized and confirms nothing | example |

**Not a source class**: a *performance* claim resolves to our own `--release` measurement,
never to prior art. **Concept ≠ mechanism** is a reading rule over the first two, not a
sixth source — a codec we newly own may be absent from IronRDP while its components exist
in FreeRDP and in the spec. Read both; "new" never justifies skipping the mechanism.
