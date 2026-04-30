# justrdp-tokio

Tokio runtime adapter for JustRDP — pure-async client (`AsyncRdpClient`
v2) plus native transports + RD Gateway.

## Why this crate exists

The JustRDP stack splits across:

- **sans-io / `no_std` cores** (`justrdp-async`, `justrdp-connector`,
  `justrdp-session`, …) — protocol logic with no I/O,
- **runtime adapters** (this crate, `justrdp-web`, `justrdp-blocking`)
  — concrete I/O bindings.

`justrdp-tokio` is the runtime adapter for tokio embedders (Tauri,
axum sidecars, native UI shells, server-side fan-out workloads). It
wraps the async core in a friendly `connect → next_event → send_*`
API and ships the native TCP / TLS / CredSSP / gateway transports
needed to talk to a real RDP server.

## Usage

```rust,ignore
use justrdp_tokio::{AsyncRdpClient, Config, MouseButton};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder("user", "pass").build();
    let mut client = AsyncRdpClient::connect(
        "192.0.2.10:3389",
        "rdp.example".to_string(),
        config,
    )
    .await?;

    while let Some(event) = client.next_event().await {
        match event? {
            ev @ justrdp_tokio::RdpEvent::GraphicsUpdate { .. } => {
                // forward to renderer
                drop(ev);
            }
            justrdp_tokio::RdpEvent::Disconnected(_) => break,
            _ => {}
        }
        // input is fire-and-forget from any tokio task
        client.send_mouse_move(100, 100).await?;
    }

    client.disconnect().await?;
    Ok(())
}
```

The example is marked `ignore` because `AsyncRdpClient` lives behind
the `native-nla` feature (which cascades the full TLS + CredSSP
stack); doc-tests run with default features only. Real builds turn
the feature on:

```toml
[dependencies]
justrdp-tokio = { version = "0.1", features = ["native-nla"] }
```

## Architecture

`AsyncRdpClient` v2 spawns one **tokio task** per session (NOT a
blocking-pool thread) over the async pump in
[`justrdp_async::ActiveSession`](../justrdp-async). The pump uses
`tokio::select!` to multiplex command receives with event polls, so
a `Disconnect` request arriving mid-await of `next_events` is
processed within a scheduling tick — no waiting for the next server
frame or TCP keepalive.

Input commands flow in via an mpsc channel; events flow out via
another. All `send_*` methods take `&self` so multiple tokio tasks
can dispatch input concurrently without external locking.

## Available features

| Feature       | Brings in                                           |
|---------------|-----------------------------------------------------|
| `native-tcp`  | `NativeTcpTransport` (`tokio::net::TcpStream`)      |
| `native-tls`  | `NativeTlsUpgrade` / `NativeTlsTransport` (rustls)  |
| `native-tls-os` | OS-native TLS (SChannel / Secure Transport / OpenSSL) |
| `native-nla`  | Full `AsyncRdpClient` + `NativeCredsspDriver`       |
| `gateway`     | MS-TSGU HTTP / WebSocket / RPC-over-HTTP variants   |
| `tracing`     | Structured tracing events on connect / pump        |
