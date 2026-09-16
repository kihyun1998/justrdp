# justrdp

A **pure-Rust RDP client library**, written from scratch to replace `ironrdp`. It owns every
RDP-native layer (X.224, MCS, GCC, capabilities, session loop, virtual channels, codecs,
surfaces) and delegates only security-critical non-RDP work (`rustls` for TLS, `sspi` for NLA).
The core is a **sans-IO state machine**: connect sequence and session loop are pure transitions
(bytes in → actions/bytes out). `justrdp-tokio` makes them real, and it also holds what the core
deliberately leaves out: the TLS handshake, the CredSSP token loop, per-stage timeouts, the
session runner.

Before implementing, read `CONTEXT.md` (ubiquitous language, boundary, §Project intent),
`docs/adr/` (why each decision was made) and `docs/plan.md` (build plan §2–§23).

## Workflow — `thegraph`

- Build substantive changes with **`/thegraph`**. The skill owns its node catalog; this repo
  supplies only the outside sources it is built against, in
  [`docs/agents/thegraph.md`](docs/agents/thegraph.md). When a run asks something that file
  cannot answer, append the answer there.
- A settled argument is owned by the record that settled it. Read the original:

  | Question | Owner |
  |---|---|
  | which directory owns a file | ADR-0001 Amendment |
  | may this dependency enter, and where | ADR-0002 |
  | which codec oracle wins (owned basis → oracle → FreeRDP tie-break) | ADR-0003 Amendment, narrowed by ADR-0011 §3 |
  | how tolerant the receive path is | ADR-0009 |

- Before starting, read [`docs/agents/lessons.md`](docs/agents/lessons.md): the ADR and issue
  anchors that give each rule its teeth. Keep its Step numbers stable — shipped rustdoc, ADRs and
  `docs/map/` cite them.

## Before settling a design — `docs/map/`

Open [`docs/map/README.md`](docs/map/README.md) before a design is fixed. Each territory's
`## Blast radius` says what moves when you touch it; `invariant/` holds facts that cross
territories. ADRs are indexed by the day a decision was argued and `plan.md` by build order, so
neither answers "what moves with this".

## Boundary invariant (the identity)

justrdp **does**: parse the wire → drive the connect state machine → dispatch graphics/input PDUs
in the session loop → expose *FrameUpdate* (rect + RGBA8888 pixels), input responses and channel
data to the host.

The core stays **I/O-free, runtime-free and policy-agnostic** — keep sockets, tokio/async, TLS
trust (ADR-0005), credential sourcing and frame-sink behaviour out of it, including as
dependencies. That is what makes it testable deterministically with no socket (oracle round-trip +
real VM).

- **Mechanism in the core, policy in the adapter** (ADR-0001). Wire parsing, state transitions and
  codecs live in the core; `sspi` and `rustls` live in `justrdp-tokio`, and the core never sees a
  TSRequest.
- **The host owns, by definition**: socket and runtime, TLS trust, credentials, frame sink and
  presentation, input-device semantics, clipboard and redirection policy, reconnect strategy, and
  **every RDP feature flag**. The only consumer seam is in-repo (`justrdp-tokio`); there is no
  published consumer.
- **When a report says "the core should solve this for me", first ask whose invariant broke.**
  Policy-agnosticism and the dirty-rect `FrameUpdate` (ADR-0010) are contracts; treating a report
  against them as a defect deletes the contract.
- **Fix upstream defects upstream.** Report and fix them there; bridge with `[patch.crates-io]`
  only until the fix ships, then remove the bridge (ADR-0004 is the worked example). The moment you
  want to compensate in a shallower layer to make a test pass is a `stop` edge: stop, explain,
  ask — never work around it alone or file an issue silently and move on.

## Crate structure (ADR-0001)

Virtual workspace, edition 2024; members in `Cargo.toml`, plus `fuzz/` outside the workspace
(nightly).

- `justrdp-pdu` — PDUs, no dependencies.
- `justrdp` — the sans-IO core.
- `justrdp-codecs` — every codec, owned. `ironrdp-graphics` is a **dev-dependency oracle only**;
  the runtime graph holds no `ironrdp` (ADR-0011).
- `justrdp-tokio` — the I/O adapter, and the only crate that may depend on tokio, `sspi` or
  `rustls`.

The concrete tree rule is the [ADR-0001 Amendment](docs/adr/0001-sans-io-state-machine-core.md).
`--workspace` never builds `fuzz/`: after a rename or a public-path change, also run
`cargo check --manifest-path fuzz/Cargo.toml`.

Delegated dependencies are leaf, security-critical and non-RDP only (ADR-0002). `sspi` is pinned
exactly (`=x.y.z`); a bump passes the real-VM suite before it lands (ADR-0004,
[`docs/map/territory/nla-credssp.md`](docs/map/territory/nla-credssp.md)).

## Core rules

- **Language**: code comments, `CLAUDE.md`, `CONTEXT.md`, `docs/adr/` and `docs/agents/` in
  English (LLM token efficiency); other human-facing docs in Korean.
- **Comments** say what the code is. Why it is this way, what it deliberately leaves out, the trap
  and the measured value go to the matching note under `docs/map/territory/`; history goes to the
  commit message.
- **Commit messages**: `feat(<scope>): … (#issue)`, with no `Co-Authored-By` or other AI
  attribution (memory `feedback_no_ai_attribution_external`).
- **Issues**: always apply a triage label and a type label (memory
  `feedback_label_issues_on_creation`).
- **Agreed multi-step plans**: continue across phase boundaries without asking whether to stop
  (memory `feedback_no_stop_prompts`).

## Agent skills

### Issue tracker
Issues and PRDs are tracked as GitHub issues on `kihyun1998/justrdp`, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels
Five canonical triage roles mapped 1:1 to default label strings (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs
Single-context: one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### CI gates
The gates are `.github/workflows/*.yml`; each file's header says what it guards and whether it
gates (`coverage.yml` does not). Gate policy: memory `justrdp_ci_policy`.

- **Run every gate bare** (`bare` skill): a pipeline's exit status is its last command's, so a
  check filtered through another command cannot fail.
- `rust-toolchain.toml` pins the compiler exactly (ADR-0013), so local gates mirror CI; Dependabot
  bumps it. `+nightly` overrides the pin, so the fuzz lane is unaffected.
