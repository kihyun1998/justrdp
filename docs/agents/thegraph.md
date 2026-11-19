# thegraph build (justrdp)

## What this project is

A pure-Rust RDP client library that owns every RDP-native protocol layer itself as a
sans-IO state machine, delegating only security-critical non-RDP work (`rustls`, `sspi`)
to the adapter. See `CLAUDE.md`.

## References

| Source | Informs | Reached by | Binding |
|---|---|---|---|
| `[MS-*]` normative specs — `[MS-RDPBCGR]`, `[MS-RDPRFX]`, `[MS-RDPEGDI]`, `[MS-RDPEGFX]`, `[MS-TSGU]`; RFC 6455 for the WebSocket under an RD Gateway (`curl -sL https://www.rfc-editor.org/rfc/rfc6455.txt`) | how it works — what we **emit** | `curl -sL <learn.microsoft.com/…> > "$SCRATCH/spec.html"`, then `grep -n` — **raw**. With no section URL in hand, the whole spec: the PDF link on the spec's learn.microsoft.com landing page (`winprotocoldocs-…azurefd.net/MS-XXX/[MS-XXX].pdf`; the old `winprotocoldoc.blob.core.windows.net` host refuses), then `pdftotext -layout` (`poppler-utils` in WSL) and `grep -n` | **spec** — cite the section |
| FreeRDP (C) + IronRDP (Rust) real source | how it works — hidden state, server tolerance, CVE points | `gh api repos/<o>/<r>/contents/<path> --jq .content \| base64 -d`, then `grep -n` — **raw**. `WebFetch` banned: it drops handler bodies, so a branch that *is* there reads as absent | example |
| The real VM — `192.168.136.136` (memory `test_environment`) | how it works — what we **accept** | a throwaway probe, or a capture into a committable fixture — `JUSTRDP_CONNECT_CAPTURE_FILE` up to session-active, `JUSTRDP_SESSION_CAPTURE_FILE` after it, `JUSTRDP_GATEWAY_CAPTURE_FILE` for what an RD Gateway sends (#308, #613; all server-to-client only, and both are per **process**, so a harness that reconnects appends every session) — **raw observation**. One WS2019 box: it proves the paths it advertises and nothing about the ones it does not | **spec** for the receive path |
| FreeRDP **as a client** against the same VM (`xfreerdp3` in WSL; procedure in `docs/map/territory/verification-harness.md` §Reference behaviour) | how it works — what the server sends **a client that advertises differently** | a manual session with `WLOG_FILTER=com.freerdp.core.rdp:DEBUG`, which logs every received Data PDU by type — **raw observation**. Run it **before** recording that the VM never sends something: it separates *"the server does not send X"* from *"the server does not send X to us"* | **spec** for the receive path, as the VM is; one run is one session |
| Published external state — crates.io, an upstream repo's own state | how it works | a registry query / `gh api`, never a sentence about them — **raw** | **spec** — it is the state, not an example |
| Layout peers — `quinn-proto`/`quinn`/`quinn-udp`, `ironrdp-pdu`/`-graphics`/`-tokio`, `rustls`, `h2` | **where files go**, and nothing else | `gh api …/contents/<path>` against the **real tree** — **raw**. A layout read off a docs site or a starter template is summarized and confirms nothing | example |

**Not a source class**: a *performance* claim resolves to our own `--release` measurement,
never to prior art. **Concept ≠ mechanism** is a reading rule over the first two, not a
sixth source — a codec we newly own may be absent from IronRDP while its components exist
in FreeRDP and in the spec. Read both; "new" never justifies skipping the mechanism.

## Proof of a performance claim

A change that touches `crates/justrdp-codecs/` runs the codec benchmarks against master during
`check-it`'s `silt` step and puts the comparison in the PR (#555). It is not a CI gate: CI has no
stable runner.

The benchmarks replay the real-server corpora in `tests/fixtures/`, one captured session per
iteration, so they time the workload a server actually sends. Run them in one sitting, pinned to
one performance core (on Windows, `start /wait /b /high /affinity 4 <bench exe> --bench …`, the
exe being what `cargo bench -p justrdp-codecs --no-run` prints):

1. master, `--save-baseline master`;
2. master again, `--baseline master` — **this run's change is the noise floor**;
3. the branch, `--baseline master`.

A codec counts as changed only where step 3's interval lies outside step 2's. #555 measured the
floor on the maintainer's host at −7 % to +74 % across codecs, with other work running; a
difference inside the floor is no difference. Three rules from #250 bound the rest:

- **State the noise floor with the number.** #91 read a 0.5 % effect off an instrument that spread
  9.6 %.
- **Isolate before you time.** A component's share of its codec's time comes first: at 4.6 % of the
  work, a 2× win is capped at 2.3 %.
- **Measure the workload's shape, not only its duration.** #91's verdict came from the run-length
  distribution of real streams, not from a stopwatch.

**On a host shared with other work, the three steps can fail to resolve anything.** #649 ran them
while other sessions used the machine: master against itself moved −43 % to +19 % across codecs,
and codecs the change never touched read as regressed. What resolved it was narrowing to the
suspect codec and alternating: `<exe> --bench <codec> --measurement-time 8 --noplot
--discard-baseline`, master and branch in turn, five pairs, each pinned as above. Judge by the
spread within each side and by the minimum, since interference only adds time: clearcodec read
1.77–1.81 ms on master against 2.62–2.72 ms on the branch, each side within 4 %, which no single
three-step run had shown.
