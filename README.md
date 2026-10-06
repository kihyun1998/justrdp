<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="logo/readme/justrdp-readme-dark.png">
    <img alt="justrdp" src="logo/readme/justrdp-readme-light.png" width="600">
  </picture>
</p>

<p align="center">
  <b>A pure-Rust RDP client library, built as a sans-IO state machine.</b>
</p>

<p align="center">
  <a href="https://github.com/kihyun1998/justrdp/actions/workflows/test.yml"><img alt="test" src="https://github.com/kihyun1998/justrdp/actions/workflows/test.yml/badge.svg"></a>
  <a href="https://github.com/kihyun1998/justrdp/actions/workflows/fuzz.yml"><img alt="fuzz" src="https://github.com/kihyun1998/justrdp/actions/workflows/fuzz.yml/badge.svg"></a>
  <img alt="rust 1.98.1" src="https://img.shields.io/badge/rust-1.98.1-orange">
  <img alt="license" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue">
</p>

---

justrdp is an RDP client written from scratch in Rust. It owns every RDP-native layer — X.224,
MCS, GCC, capability exchange, the session loop, virtual channels, codecs and surfaces — and
delegates only security-critical work that is not RDP: TLS to [`rustls`](https://github.com/rustls/rustls)
and NLA to [`sspi`](https://github.com/Devolutions/sspi-rs).

## Why

- **The host decides every policy flag.** Nothing in justrdp hardcodes a choice that is the
  host's to make, and nothing advertises what the core cannot handle (ADR-0016). In particular,
  all `earlyCapabilityFlags` reach the wire as the host sets them, including
  `SUPPORT_DYN_VC_GFX_PROTOCOL`, the flag that turns on the Graphics Pipeline (EGFX) on modern
  Windows servers.
- **The core does no I/O.** The connect sequence and the session loop are pure transitions:
  bytes in, actions and bytes out. There are no sockets, no async runtime and no TLS policy in the
  core, so it can be tested deterministically without a network and driven from any runtime.
- **Every codec is our own.** RemoteFX, RemoteFX Progressive, ClearCodec, NSCodec, Planar,
  interleaved RLE and zgfx are all implemented in this repository. No `ironrdp` crate is in the
  runtime dependency graph.

## Crates

| Crate | Role | Depends on |
|---|---|---|
| [`justrdp-pdu`](crates/justrdp-pdu) | RDP wire-format PDUs: encode and decode | nothing |
| [`justrdp-codecs`](crates/justrdp-codecs) | Bitmap and surface codecs, decoding to RGBA8888 | `justrdp-pdu` |
| [`justrdp`](crates/justrdp) | The sans-IO core: connect and session state machines, virtual channels, framebuffer | `justrdp-pdu`, `justrdp-codecs` |
| [`justrdp-tokio`](crates/justrdp-tokio) | The Tokio adapter: socket, TLS handshake and trust, CredSSP, per-stage timeouts, session runner | `justrdp`, `tokio`, `rustls`, `sspi` |

`tokio`, `rustls` and `sspi` may appear only in `justrdp-tokio`.

## What it does

**Connection**
- X.224 negotiation of TLS, HYBRID (NLA) and HYBRID_EX
- NLA through CredSSP with NTLM
- Server certificate checking against the OS trust store, with trust-on-first-use pinning
- Licensing, client info and capability exchange through to an active session
- A timeout for each stage; a failure names the stage it happened in (`tcp-connect`,
  `x224-negotiate`, `tls-handshake`, `nla-credssp`, …)
- Typed disconnect reasons and auto-reconnect cookies

**Graphics**
- Slow-path and fast-path bitmap updates (interleaved RLE, Planar)
- The Graphics Pipeline (EGFX) over a dynamic virtual channel: surfaces, cache and blits, with
  RemoteFX, RemoteFX Progressive, ClearCodec and NSCodec, compressed with zgfx
- Pointer shapes and the pointer cache
- Output as a `FrameUpdate`: a dirty rectangle plus RGBA8888 pixels

**Input and channels**
- Keyboard (scancodes), mouse and lock-key sync, sent fast-path when the server supports it
- Static and dynamic virtual channels. Any static channel the core does not handle is passed to
  the host as raw messages
- Display Control (resize)
- Sans-IO helpers for clipboard (`justrdp::cliprdr`) and drive redirection (`justrdp::rdpdr`).
  The host drives them, so the session itself interprets neither protocol

## Usage

justrdp is not on crates.io yet. Depend on it by git:

```toml
[dependencies]
justrdp = { git = "https://github.com/kihyun1998/justrdp" }
justrdp-tokio = { git = "https://github.com/kihyun1998/justrdp" }
```

The Tokio adapter drives the whole sequence. The host builds the `ConnectConfig` (GCC data,
capability sets, licensing entropy): every flag is the host's choice.

```rust
use justrdp::{ConnectConfig, SessionConfig, SessionStateMachine};
use justrdp_tokio::{connect, run_session, Credentials, ServerAddr};

let config: ConnectConfig = /* your GCC, capability and license settings */;
let credentials = Credentials {
    username: "user".into(),
    password: "secret".into(),
    domain: None,
};

let mut outcome = connect(
    ServerAddr::new("rdp.example.com", 3389),
    config,
    credentials,
    |stage| println!("stage: {stage}"),
)
.await?;

let session_config: SessionConfig = /* channel IDs and desktop size from `outcome` */;
let mut machine = SessionStateMachine::new(session_config, outcome.activation.leftover)?;

let reason = run_session(
    &mut outcome.stream,
    &mut machine,
    |frame, framebuffer| { /* copy `frame.rect` from `framebuffer` to your surface */ },
    |cursor| { /* update the pointer */ },
)
.await?;
```

`run_session_with_input` adds an input channel, and `run_session_with_commands` adds resize,
virtual channel writes and cancellation.

## Design

The core never touches a socket. It returns `Action`s (open a socket, write these bytes, start
TLS), and the adapter carries them out and feeds the results back as `Event`s. Because the TLS
handshake and the CredSSP token loop are state machines of their own, they run in the adapter,
and the core never sees a TSRequest.

What stays with the host: the socket and runtime, TLS trust, credentials, the frame sink and how
it is presented, input device semantics, clipboard and redirection policy, reconnect strategy and
every policy flag.

More detail:

- [`GLOSSARY.md`](GLOSSARY.md): vocabulary and the core/adapter boundary
- [`docs/adr/`](docs/adr/): architecture decision records
- [`docs/plan.md`](docs/plan.md): the build plan
- [`docs/map/`](docs/map/README.md): what moves when each area changes

## Testing

- **Differential and corpus tests.** Codecs are checked against byte streams captured from a real
  Windows Server and against expected output derived independently of the decoder.
- **Property tests and fuzzing.** Every decoder of untrusted input has `proptest` properties
  ("never panics") and a `cargo-fuzz` target run in a nightly CI lane (`fuzz/`, outside the
  workspace).
- **A 32-bit overflow lane.** Dimension overflow guards are proven on a 32-bit target.
- **Real VM runs.** Connect and session behaviour is verified against a real Windows Server 2022
  VM.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml   # fuzz/ is not a workspace member
```

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

## License

Licensed under either of MIT or Apache-2.0, at your option.
