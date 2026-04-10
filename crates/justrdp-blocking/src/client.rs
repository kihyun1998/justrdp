#![forbid(unsafe_code)]

//! [`RdpClient`] — high-level synchronous RDP client.
//!
//! The scaffold compiles end-to-end. As of M1, `connect()` drives the
//! connector through the TLS upgrade point, performs the handshake via
//! a user-supplied [`TlsUpgrader`], and then hands back an
//! [`ConnectError::Unimplemented`] for the post-TLS pump (M2 onwards).

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

use justrdp_connector::{ClientConnector, ClientConnectorState, Config, Sequence};
use justrdp_core::WriteBuf;
use justrdp_input::Scancode;
use justrdp_session::ActiveStage;
use justrdp_tls::{AcceptAll, ReadWrite, RustlsUpgrader, ServerCertVerifier, TlsUpgrader};

use crate::error::{ConnectError, RuntimeError};
use crate::event::RdpEvent;
use crate::reconnect::ReconnectPolicy;
use crate::transport::{read_pdu, write_all};

/// Transport abstraction shared across the pre-TLS and post-TLS phases.
///
/// Before TLS upgrade the transport holds a raw [`TcpStream`]; after upgrade
/// it holds the boxed rustls stream. [`Read`] / [`Write`] dispatch to
/// whichever variant is active, so the pump code can read and write without
/// caring which phase it is in.
pub(crate) enum Transport {
    /// Raw TCP (pre-handshake or Standard RDP Security).
    Tcp(TcpStream),
    /// Post-TLS-upgrade stream (any backend that implements [`ReadWrite`]).
    ///
    /// Intentionally not `Send`: rustls's `StreamOwned` is not `Send` when
    /// boxed through `justrdp_tls::ReadWrite`, and blocking clients are
    /// single-threaded. Cross-thread ownership is an M7+ concern.
    Tls(Box<dyn ReadWrite>),
    /// Placeholder used while the transport is swapped during upgrade.
    Swapping,
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
            Self::Swapping => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "transport is being swapped",
            )),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
            Self::Swapping => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "transport is being swapped",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Tls(s) => s.flush(),
            Self::Swapping => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "transport is being swapped",
            )),
        }
    }
}

/// High-level synchronous RDP client.
pub struct RdpClient {
    transport: Option<Transport>,
    session: Option<ActiveStage>,
    reconnect_policy: ReconnectPolicy,
    scratch: Vec<u8>,
    /// Server public key captured at TLS upgrade (for CredSSP pubKeyAuth in M2).
    #[allow(dead_code)]
    server_public_key: Option<Vec<u8>>,
}

impl RdpClient {
    /// Perform the full connection sequence using the default
    /// [`RustlsUpgrader`] with [`AcceptAll`] (mstsc.exe-like behavior).
    pub fn connect<A: ToSocketAddrs>(
        server: A,
        server_name: &str,
        config: Config,
    ) -> Result<Self, ConnectError> {
        Self::connect_with_verifier(server, server_name, config, Arc::new(AcceptAll))
    }

    /// Perform the connection sequence using a custom [`ServerCertVerifier`].
    ///
    /// Prefer this over [`connect`](Self::connect) for production deployments
    /// — pass [`PinnedSpki`](justrdp_tls::PinnedSpki) or a GUI-backed verifier
    /// so self-signed certificates are not accepted blindly.
    pub fn connect_with_verifier<A: ToSocketAddrs>(
        server: A,
        server_name: &str,
        config: Config,
        verifier: Arc<dyn ServerCertVerifier>,
    ) -> Result<Self, ConnectError> {
        let upgrader = RustlsUpgrader::with_verifier(verifier);
        Self::connect_with_upgrader(server, server_name, config, upgrader)
    }

    /// Perform the connection sequence using an arbitrary [`TlsUpgrader`].
    ///
    /// Used by tests and by callers who want full control over the TLS stack
    /// (e.g. `native-tls` backend).
    pub fn connect_with_upgrader<A, U>(
        server: A,
        server_name: &str,
        config: Config,
        upgrader: U,
    ) -> Result<Self, ConnectError>
    where
        A: ToSocketAddrs,
        U: TlsUpgrader,
        U::Stream: 'static,
    {
        let tcp = TcpStream::connect(server)?;
        let mut connector = ClientConnector::new(config);
        let mut transport = Transport::Tcp(tcp);

        // Phase 1: drive the connector until it hits the TLS upgrade point.
        drive_until_state_change(&mut connector, &mut transport, |s| {
            matches!(
                s,
                ClientConnectorState::EnhancedSecurityUpgrade
                    | ClientConnectorState::Connected { .. }
            )
        })?;

        // Phase 2: perform TLS upgrade if the connector asked for it.
        let server_public_key = if matches!(
            connector.state(),
            ClientConnectorState::EnhancedSecurityUpgrade
        ) {
            let tcp = match std::mem::replace(&mut transport, Transport::Swapping) {
                Transport::Tcp(s) => s,
                _ => {
                    return Err(ConnectError::Unimplemented(
                        "unexpected transport variant before TLS upgrade",
                    ));
                }
            };
            let upgraded = upgrader.upgrade(tcp, server_name)?;
            transport = Transport::Tls(Box::new(upgraded.stream));
            Some(upgraded.server_public_key)
        } else {
            None
        };

        // Phase 3 (M2+): post-TLS CredSSP + connection finalization pump.
        // Explicitly drop the upgraded transport here so rustc doesn't warn
        // about an unread assignment — M2 will replace this with the pump
        // loop that actually consumes `transport` and `server_public_key`.
        drop(transport);
        let _ = server_public_key;
        Err(ConnectError::Unimplemented(
            "post-TLS CredSSP + connection finalization (M2+)",
        ))
    }

    /// Set the [`ReconnectPolicy`] to consult when the session drops.
    pub fn set_reconnect_policy(&mut self, policy: ReconnectPolicy) {
        self.reconnect_policy = policy;
    }

    /// Read the next session event.
    ///
    /// *Scaffold: always returns [`RuntimeError::Unimplemented`].*
    pub fn next_event(&mut self) -> Result<Option<RdpEvent>, RuntimeError> {
        let _ = (
            &mut self.transport,
            &mut self.session,
            &mut self.scratch,
            &self.server_public_key,
        );
        Err(RuntimeError::Unimplemented("active session pump"))
    }

    /// Send a single key press/release.
    ///
    /// *Scaffold: always returns [`RuntimeError::Unimplemented`].*
    pub fn send_keyboard(&mut self, _scancode: Scancode, _pressed: bool) -> Result<(), RuntimeError> {
        Err(RuntimeError::Unimplemented("send_keyboard"))
    }

    /// Send a mouse movement or button event.
    ///
    /// *Scaffold: always returns [`RuntimeError::Unimplemented`].*
    pub fn send_mouse(&mut self, _x: u16, _y: u16) -> Result<(), RuntimeError> {
        Err(RuntimeError::Unimplemented("send_mouse"))
    }

    /// Gracefully disconnect the session and consume the client.
    ///
    /// *Scaffold: just drops the transport.*
    pub fn disconnect(mut self) -> Result<(), RuntimeError> {
        self.transport.take();
        self.session.take();
        Ok(())
    }
}

/// Drive the connector step loop, forwarding bytes to/from `transport`,
/// until `stop_when(connector.state())` returns `true`.
fn drive_until_state_change<F>(
    connector: &mut ClientConnector,
    transport: &mut Transport,
    stop_when: F,
) -> Result<(), ConnectError>
where
    F: Fn(&ClientConnectorState) -> bool,
{
    let mut output = WriteBuf::new();
    let mut scratch: Vec<u8> = Vec::new();

    loop {
        if stop_when(connector.state()) {
            return Ok(());
        }

        let hint = connector.next_pdu_hint();
        if let Some(hint) = hint {
            let n = read_pdu(transport, hint, &mut scratch)?;
            let _written = connector.step(&scratch[..n], &mut output)?;
        } else {
            output.clear();
            let _written = connector.step(&[], &mut output)?;
        }

        if !output.is_empty() {
            write_all(transport, output.as_slice())?;
            output.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Transport::Swapping` must return an error on any I/O attempt so
    /// that a partially-swapped client never silently drops bytes.
    #[test]
    fn swapping_transport_errors_on_read_and_write() {
        let mut t = Transport::Swapping;
        let mut buf = [0u8; 4];
        assert!(t.read(&mut buf).is_err());
        assert!(t.write(b"hi").is_err());
        assert!(t.flush().is_err());
    }
}
