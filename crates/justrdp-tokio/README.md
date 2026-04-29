# justrdp-tokio

Tokio runtime adapter for [`justrdp-blocking`](../justrdp-blocking)::`RdpClient`.

## Why this crate exists

`justrdp-blocking::RdpClient` is the only I/O-performing crate in the
JustRDP stack — every other crate is `no_std`/sans-IO. `RdpClient`
itself is synchronous (`std::net::TcpStream` + `std::sync::Mutex`),
which is a poor fit for embedders running on tokio: each one ends up
hand-rolling a `spawn_blocking` wrapper plus mpsc plumbing.

`justrdp-tokio` does that wrapping exactly once, in the place where it
can be tested and maintained.

## Usage

```rust,no_run
use justrdp_tokio::{AsyncRdpClient, Config, MouseButton};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
# Ok(())
# }
```

## Architecture

One [`tokio::task::spawn_blocking`] worker per session owns the
`RdpClient`. Input commands arrive through an mpsc channel; events
leave through another. See `lib.rs` for the cancel-safety contract.
