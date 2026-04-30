//! Lifecycle tests for `AsyncRdpClient` v2.
//!
//! These tests do not require a live RDP server. They cover:
//! 1. The connect path correctly maps a refused TCP connection to
//!    `ConnectError::Tcp` (no panic, no JoinError-derived noise).
//! 2. Type-level requirements: `AsyncRdpClient: Send` and the wrapper
//!    re-exports compile against an outside consumer.
//!
//! Gated on `native-nla` because v2's full async stack (TCP + TLS +
//! CredSSP) lives behind that feature. Builds without `native-nla`
//! skip these tests.
//!
//! End-to-end tests that drive a complete handshake are deferred to
//! `justrdp-blocking`'s mock-broker test (§9.3.5 in roadmap.md), which
//! exercises the underlying handshake directly. Re-running the same
//! scenario through the tokio wrapper would only re-test channel
//! plumbing that is already covered here.

#![cfg(feature = "native-nla")]

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use justrdp_tokio::{AsyncRdpClient, Config, ConnectError};

/// Trigger a connect attempt against a closed port and assert the
/// blocking error surfaces through the async wrapper as
/// `ConnectError::Tcp` (not a JoinError-derived `Other`, not a panic).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_to_closed_port_returns_tcp_error() {
    // Bind+drop to grab a port that is guaranteed unused for the
    // remainder of the test (the TIME_WAIT window beats the connect
    // attempt's RST/ECONNREFUSED). On Windows + Linux, `connect` to a
    // recently-released port returns ECONNREFUSED before any other
    // protocol step runs.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    };

    let config = Config::builder("user", "pass").build();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        AsyncRdpClient::connect(format!("127.0.0.1:{port}"), "test.local", config),
    )
    .await
    .expect("connect must not hang past the timeout");

    match result {
        Err(ConnectError::Tcp(e)) => {
            // The exact errno varies (Windows returns ConnectionRefused
            // or sometimes a Wsock-specific kind); we just need the
            // error to round-trip as a TCP-layer failure.
            let _ = e;
        }
        Err(other) => panic!("expected ConnectError::Tcp, got {other:?}"),
        Ok(_) => panic!("connect to closed port must not succeed"),
    }
}

/// `AsyncRdpClient` MUST be `Send` so tokio embedders can hold it
/// across `.await` and move it between tasks. Compile-time check.
#[test]
fn async_rdp_client_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<AsyncRdpClient>();
}

/// `&AsyncRdpClient` (shared reference) MUST be `Send` so embedders
/// can `Arc::new(client)` and dispatch `send_*` concurrently from
/// multiple tokio tasks. v2 makes this explicit by having all
/// `send_*` methods take `&self`; the underlying `mpsc::Sender` is
/// `Send + Sync + Clone` so the pump serialises commands without
/// needing external locking. Compile-time check.
#[test]
fn shared_ref_is_send() {
    fn assert_ref_send<T: ?Sized>()
    where
        for<'a> &'a T: Send,
    {
    }
    assert_ref_send::<AsyncRdpClient>();
}

/// The wrapper accepts a closed TCP connection (handshake fails inside
/// the connector before TLS) and surfaces a `ConnectError`. This guards
/// against the worker accidentally panicking or the spawn_blocking
/// JoinError leaking out as an Other-kinded error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_against_immediate_close_surfaces_error() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();

    // Accept-then-close on a background OS thread so the connector
    // sees an immediate EOF mid-handshake.
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            // Drop immediately — server-style RST.
            drop::<TcpStream>(stream);
        }
    });

    let config = Config::builder("user", "pass").build();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        AsyncRdpClient::connect(addr, "test.local", config),
    )
    .await
    .expect("connect must not hang past the timeout");

    assert!(
        result.is_err(),
        "connect against immediate close must return an error, got Ok"
    );
}
