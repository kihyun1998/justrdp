# NLA / CredSSP authentication

## What it is

Network Level Authentication: after TLS is up, a CredSSP token exchange
(SPNEGO/NTLM, Kerberos later) authenticates the user *before* the RDP session is
established, and delegates the credential to the server. `sspi` owns the protocol;
this territory owns driving its loop, framing the `TSRequest`s over the TLS stream,
and binding the exchange to the server's public key.

## Governing decisions

- [ADR-0002](../../adr/0002-dependency-boundary.md) — `sspi` is security-critical
  and non-RDP, so it is delegated verbatim and lives in the adapter. **The core
  never sees a `TSRequest`.**
- [ADR-0004](../../adr/0004-sspi-contribute-and-bridge.md) — contribute upstream and
  bridge with `[patch.crates-io]` in the meantime, with an exact version pin and the
  real-VM suite as the version-bump gate. The bridge was carried (#61) and **exited on
  2026-08-10** (Amendment). The long-term direction (*not yet scheduled*, per the
  record itself) moves the ADR-0002 boundary one layer down and owns the RDP-adjacent
  auth layers.

## Design model

- **The core delegates by construction, not by convenience.** The connect machine
  emits `Action::StartNla { selected, server_public_key }` and waits for
  `Event::NlaComplete`; the token round-trips never enter it. Same shape as the TLS
  handshake, and for the same reason: `sspi` is itself a state machine, so shuttling
  its records through ours would add a layer and no information.
- **The public-key binding is the security content of the exchange.** `pubKeyAuth`
  binds to the server's `subjectPublicKey` — the inner BIT STRING, not the whole
  SPKI (see [TLS transport security](tls-transport-security.md)). A wrong binding
  still *completes* a loopback handshake, which is precisely why the loopback test
  is not sufficient proof here.
- **Tokens are SPNEGO-wrapped, never bare NTLM.** `run_credssp` builds
  `ClientMode::Negotiate` with the package list pinned to `"ntlm,!kerberos,!pku2u"`, so SPNEGO
  wraps NTLM and `sspi` never yields a KDC request. Measured on the VM (slice-3):
  `ClientMode::Ntlm` sends raw NTLM messages and the Windows server aborts the TLS session
  with a fatal `internal_error` alert. CredSSP over TLS 1.3 works against the same VM; no
  TLS-version pin is needed. Widening the package list is #45's work.
- **HYBRID_EX adds a fourth message**: after CredSSP finishes, the server sends a
  4-byte Early User Authorization Result PDU that the adapter reads before MCS. Left
  unread, capability exchange desyncs and hangs.
- **No secret enters the sans-IO machine.** Credentials are a `connect()` input the adapter
  holds; the machine's `Action::StartNla` carries only the selected protocol and the
  server key it extracted itself. This is why `justrdp-pdu` has no `TSRequest` codec and the
  core hand-rolls none of the CredSSP crypto (ADR-0002).
- Credentials are host-supplied and `Debug` is implemented by hand so a password
  never reaches a log.

## Code

- `justrdp-tokio/src/lib.rs` — `run_credssp`, `write_ts_request`, `read_ts_request`,
  `Credentials`, the `Action::StartNla` arm
- `justrdp/src/connect.rs` — `Action::StartNla`, `Event::NlaComplete`,
  `ConnectStateMachine`
- `Cargo.toml` — `sspi = "=0.23.1"`, the exact pin ADR-0004 requires (the
  `[patch.crates-io]` bridge that used to sit here was removed 2026-08-10)
- Stage string: `nla-credssp`

## Reference behaviour

**None.** No verified external-fact store. The upstream facts this territory rests
on are recorded as *issue* text instead: Devolutions/sspi-rs#687 (the loopback
defect), #689 (the maintainer's rework that fixed it).

## Cross-cutting invariants

**None.**

## Blast radius

- [TLS transport security & trust](tls-transport-security.md) — supplies the bound
  public key; a change to its extraction silently breaks the binding.
- [X.224 negotiation](x224-negotiation.md) — decides whether NLA runs, and whether
  the HYBRID_EX extra read is expected.
- [MCS / GCC channel setup](mcs-gcc-channel-setup.md) — the stage that follows; an
  NLA failure surfaces as a stage-named connect failure, not an MCS error.
- [Supply chain & gates](supply-chain-and-gates.md) — the fork bridge is a
  dependency-graph fact with a removal obligation attached.
- [Verification harness](verification-harness.md) — the loopback full-CredSSP test
  exists only because the fork made it possible; it is CI's only positive NLA path.

## Known holes / open

- **The version-bump gate ADR-0004 requires is satisfied for the current pin** (`sspi
  = "=0.23.1"`, 2026-11-09, Dependabot #582). 0.23.1 leaves `src/ntlm` as it was and changes
  `src/negotiate`, `src/credssp` and username parsing. The client now exchanges `mechListMIC`
  whenever the server sent one; an NTLM logon other than Guest already did, so only a Guest
  account changes. `Username::new` and `Username::parse` now drop a `.\` in front of an
  already-qualified name, which both arms of `Credentials::to_sspi` reach. The main suite ran on a clone of the WS2019
  VM at `.131`, because the maintainer needed the original: 66 of 67 passed. The two
  Standard RDP Security tests need their own server and did not run. The row probe passed on
  WS2008 R2 and Win11, and the five GDI orders tests passed on WS2008 R2. Three results were
  not clean:
  - `capture_progressive_corpus_against_real_vm` fails on the clone (it never reaches its
    2,000 lit pixels) with 0.23.1 and with 0.23.0, and passed with 0.23.1 on the original.
  - The two audio input tests ran five times with each version, on Win11: PCM passed 3 of 5
    with 0.23.1 and 5 of 5 with 0.23.0; A-law passed 1 of 5 and 2 of 5. A-law fails on both
    versions. PCM failed only on 0.23.1 here, at the rate [Audio input](audio-input.md) measured
    before this bump (13 of 34). Five runs cannot tell the rates apart, and `sspi` is called
    only during CredSSP, before the session starts.
- **`picky-krb` 0.13.1 understates two of its minimums.** It declares `picky-asn1-der ^0.5` and
  `picky-asn1-x509 ^0.15` but does not compile below 0.5.7 and 0.15.5, so a lockfile that keeps
  older ones fails to build once `sspi` 0.23.1 brings it in. `Cargo.lock` holds those two
  versions; no `[patch.crates-io]` is involved.
- **The pin before it** (`=0.23.0`, 2026-10-12, Dependabot #413) passed
  `connect_reaches_session_active_against_real_vm` — the whole X.224 → TLS → CredSSP →
  MCS/GCC → activation sequence against the live test VM —
  `first_frames_render_the_desktop_against_real_vm` and the loopback full-CredSSP test
  (`connect_completes_credssp_against_a_loopback_server`). That bump took in 0.22.1, which
  stopped NTLM MIC generation resetting the RC4 sealing state CredSSP's `pubKeyAuth` is
  wrapped with, so it touched this path; 0.23.0 itself changed only Kerberos and `winscard`,
  neither of which this client builds. The pin before it (`=0.22.0`,
  2026-10-06) passed the same gate. The first exact pin after the fork bridge (`=0.21.3`,
  2026-08-10) passed the same gate; see ADR-0004's *Result* section for that run and
  for the suite's session-isolation caveat.
- **A bump also runs the row probe on every other interop-matrix row** (ADR-0004 Amendment
  2026-10-22, #428): `JUSTRDP_TEST_SERVER=ws2008r2` and `=win11`, then
  `interop_matrix_row_probe_against_real_vm`. The rows negotiate NLA differently: WS2008 R2
  selects HYBRID, while WS2019 and Win11 select HYBRID_EX.
- **0.22 made `TsRequest::buffer_len()` fallible** (`Result<u16>`): a request whose
  encoded length overflows `u16` is now an error rather than a truncated size.
  `write_ts_request` surfaces it as `ConnectFailure::Nla`, the same as an encode
  failure. The same bump moved `md4` 0.10 → 0.11, the hash under the NTLM password
  — one more reason the real-VM run, not the loopback test, is the gate.
- **Why it took six weeks, recorded because the mechanism is reusable.** #61 — named
  as the removal tracker by `Cargo.toml`, `.github/dependabot.yml` *and* ADR-0004 —
  was closed against its own comment; Dependabot's "new release is the signal"
  tripwire cannot fire for a condition already met; and ADR-0004's earlier amendment
  asserted the bridge *did not exist*. Nothing greppable disagreed with anything.
- **Kerberos NLA is not built** — epic #45 (sspi `NetworkRequest` driving + KDC
  discovery). Today's path is SPNEGO/NTLM only.
- ADR-0004's end state ("own the RDP-adjacent auth layers") is explicitly *not
  scheduled*; nothing tracks it as work.
