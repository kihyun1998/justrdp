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
- **HYBRID_EX adds a fourth message**: after CredSSP finishes, the server sends a
  4-byte Early User Authorization Result PDU that the adapter reads before MCS.
- Credentials are host-supplied and `Debug` is implemented by hand so a password
  never reaches a log.

## Code

- `justrdp-tokio/src/lib.rs` — `run_credssp`, `write_ts_request`, `read_ts_request`,
  `Credentials`, the `Action::StartNla` arm
- `justrdp/src/connect.rs` — `Action::StartNla`, `Event::NlaComplete`,
  `ConnectStateMachine`
- `Cargo.toml` — `sspi = "=0.21.3"`, the exact pin ADR-0004 requires (the
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

- **The version-bump gate ADR-0004 requires has not run for the current pin.** The
  fork bridge was removed and `sspi` pinned at `=0.21.3` on 2026-08-10 with
  `cargo test --workspace` green — *including*
  `connect_completes_credssp_against_a_loopback_server`, the test that existed only
  because of the fork, which is the direct evidence that the published crate carries
  Devolutions/sspi-rs#689. But the **real-VM acceptance suite could not run**: all 12
  VM tests fail `STATUS_LOGON_FAILURE [0xc000006d]`, and an A/B run with the fork
  restored fails **identically**, so the blocker is the VM's account state, not the
  bump. Re-run `cargo test -p justrdp-tokio -- --ignored` once credentials are
  restored and record it in ADR-0004.
- **Why it took six weeks, recorded because the mechanism is reusable.** #61 — named
  as the removal tracker by `Cargo.toml`, `.github/dependabot.yml` *and* ADR-0004 —
  was closed against its own comment; Dependabot's "new release is the signal"
  tripwire cannot fire for a condition already met; and ADR-0004's earlier amendment
  asserted the bridge *did not exist*. Nothing greppable disagreed with anything.
- **Kerberos NLA is not built** — epic #45 (sspi `NetworkRequest` driving + KDC
  discovery). Today's path is SPNEGO/NTLM only.
- ADR-0004's end state ("own the RDP-adjacent auth layers") is explicitly *not
  scheduled*; nothing tracks it as work.
