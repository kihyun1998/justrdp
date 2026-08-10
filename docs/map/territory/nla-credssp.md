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
  bridge with `[patch.crates-io]` in the meantime; the long-term direction (*not yet
  scheduled*, per the record itself) moves the ADR-0002 boundary one layer down and
  owns the RDP-adjacent auth layers.

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
- `Cargo.toml` — the `[patch.crates-io]` `sspi` fork pin (ADR-0004 bridge)
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

- **The fork bridge is obsolete and still in the tree, and its tracker is closed.**
  Devolutions/sspi-rs#689 merged upstream **2026-06-17** and first shipped on
  crates.io in **sspi 0.21.1 (2026-06-26)**, so ADR-0004's exit condition has been
  met for weeks — but `[patch.crates-io]` is still pinned to `kihyun1998/sspi-rs`,
  and the three artifacts that name **#61** as the tracker (`Cargo.toml`,
  `.github/dependabot.yml`, ADR-0004) all point at a **closed** issue whose own
  comment says it must not close before the patch is deleted.
- **The removal is verified except for the one gate ADR-0004 names.** Measured
  2026-08-10: with the patch removed and `sspi = "0.21.3"`, `cargo test --workspace`
  is green *including* `connect_completes_credssp_against_a_loopback_server` — the
  test that existed only because of the fork. The **real-VM suite cannot certify it**:
  all 12 VM tests fail `STATUS_LOGON_FAILURE [0xc000006d]`, and an A/B run with the
  fork restored fails **identically**, so the blocker is the VM's credentials, not the
  bump. The removal is held until that is resolved.
- **Kerberos NLA is not built** — epic #45 (sspi `NetworkRequest` driving + KDC
  discovery). Today's path is SPNEGO/NTLM only.
- ADR-0004's end state ("own the RDP-adjacent auth layers") is explicitly *not
  scheduled*; nothing tracks it as work.
