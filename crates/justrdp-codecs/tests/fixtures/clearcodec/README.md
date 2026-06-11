# ClearCodec corpus (issue #56)

Real ClearCodec (`RDPGFX_CODECID_CLEARCODEC`) bitmap streams harvested from the live test
VM (192.168.136.136, Windows Server 2022) by the `capture_clearcodec_corpus_against_real_vm`
`#[ignore]` test in `justrdp-tokio`. Each `*.bin` is one post-zgfx `CODECID_CLEARCODEC`
payload exactly as it reached `Clear::decode_to_bgra` on the wire.

This corpus exists because ClearCodec is the ADR-0003 case where the **bootstrap oracle
(`ironrdp-graphics`) is itself wrong**: it rejects genuine streams a real server emits and
mstsc renders. A differential test cannot arbitrate streams the oracle refuses to decode, so
the phase-2 self-owned decoder (#56) is validated against these captures instead.

## `manifest.tsv`

Tab-separated, one row per fixture:

| column   | meaning                                                              |
| -------- | ------------------------------------------------------------------- |
| `file`   | the `*.bin` payload                                                  |
| `width`  | destination rectangle width  (decode argument)                      |
| `height` | destination rectangle height (decode argument)                      |
| `len`    | payload byte length                                                 |
| `oracle` | how `ironrdp-graphics` 0.8 classifies it (see tags below)           |
| `detail` | the oracle's rejection message, for the `err` tags                  |

## Oracle tags

- `ok` — the bootstrap oracle decodes it. The self-owned decoder must produce **byte-identical
  RGBA** to the oracle for these (the normal differential path still applies where the oracle
  is right).
- `rlex_suite_exceeds_region` — oracle raises ``invalid `rlex`: suite exceeds region pixel
  count`` (over-strict subcodec RLEX validation).
- `short_vbar_cache_miss` — oracle raises ``invalid `shortVBarCacheMiss`: shortVBarYOff <
  shortVBarYOn`` (wrong V-bar band validation).
- `vbar_cache_miss_on_hit` — oracle raises ``invalid `vbarIndex`: V-bar cache miss on hit``
  (a third limitation surfaced during capture, not noted in the original #56 write-up).

The three `err` tags are exactly the streams #56 must decode successfully. Ground truth for
their *pixels* is the full-desktop render in the slice-9 EGFX acceptance test (no Clear-region
holes), since the oracle cannot supply a per-stream reference for streams it rejects.

## Provenance

Captured 2026-06-11 from a normal interactive desktop session (taskbar/tray + open windows).
Which regions a server Clear-codes is non-deterministic; re-running the capture harness yields
a different mix. This curated subset (4 per `err` signature where available, 4 `ok`) is a
representative slice of one capture run — the full run produced 71 payloads (19 ok, 52
rejected).
