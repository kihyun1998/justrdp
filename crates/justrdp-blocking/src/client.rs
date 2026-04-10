#![forbid(unsafe_code)]

//! [`RdpClient`] — high-level synchronous RDP client.
//!
//! This is the public API surface users will interact with. The scaffold
//! compiles and has the full shape but most methods currently return
//! [`RuntimeError::Unimplemented`]; subsequent commits will fill in:
//!
//! - TLS upgrade wiring at `EnhancedSecurityUpgrade` (5.4 `ServerCertVerifier`)
//! - CredSSP token pump-through
//! - `ActiveStage` frame loop
//! - Input helpers (keyboard, mouse, unicode)
//! - Auto-Reconnect runtime (roadmap §9.2)
//! - Session Redirection runtime (roadmap §9.3)
//! - License persistence (roadmap §9.15)

use std::net::{TcpStream, ToSocketAddrs};

use justrdp_connector::{ClientConnector, ClientConnectorState, Config, Sequence};
use justrdp_core::WriteBuf;
use justrdp_input::Scancode;
use justrdp_session::ActiveStage;

use crate::error::{ConnectError, RuntimeError};
use crate::event::RdpEvent;
use crate::reconnect::ReconnectPolicy;
use crate::transport::{read_pdu, write_all};

/// High-level synchronous RDP client.
pub struct RdpClient {
    /// Transport after the connection sequence completes. `None` means the
    /// client is in a disconnected state.
    transport: Option<TcpStream>,
    /// Active session processor. `None` until the handshake completes.
    session: Option<ActiveStage>,
    /// Reconnect policy consulted by the runtime on socket drop.
    reconnect_policy: ReconnectPolicy,
    /// Scratch buffer reused across frame reads to avoid reallocation.
    scratch: Vec<u8>,
}

impl RdpClient {
    /// Perform the full connection sequence to `server:port` and return
    /// a client ready to drive the active session.
    ///
    /// *Scaffold: runs the connector pump up to the TLS upgrade point and
    /// then returns [`ConnectError::Unimplemented`] until TLS wiring lands
    /// in a follow-up commit.*
    pub fn connect<A: ToSocketAddrs>(server: A, config: Config) -> Result<Self, ConnectError> {
        let tcp = TcpStream::connect(server)?;
        let mut connector = ClientConnector::new(config);

        drive_until_tls_upgrade(&mut connector, &tcp)?;

        // TODO: perform TLS upgrade via justrdp-tls, then resume pumping
        // CredSSP / BasicSettingsExchange / Finalization until Connected.
        Err(ConnectError::Unimplemented(
            "TLS upgrade + post-TLS pump (follow-up commit)",
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
        let _ = (&mut self.transport, &mut self.session, &mut self.scratch);
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

/// Run the connector state machine from `ConnectionInitiationSendRequest`
/// through `ConnectionInitiationWaitConfirm` up to — and including — the
/// transition into `EnhancedSecurityUpgrade`, at which point the caller
/// must perform TLS upgrade externally.
///
/// *Scaffold: currently a no-op that returns once the send-state loop is
/// exhausted. Full pump comes with the TLS follow-up.*
fn drive_until_tls_upgrade(
    connector: &mut ClientConnector,
    tcp: &TcpStream,
) -> Result<(), ConnectError> {
    let mut output = WriteBuf::new();
    let mut scratch: Vec<u8> = Vec::new();

    loop {
        match connector.state() {
            ClientConnectorState::EnhancedSecurityUpgrade => return Ok(()),
            ClientConnectorState::Connected { .. } => return Ok(()),
            _ => {}
        }

        let hint = connector.next_pdu_hint();
        if let Some(hint) = hint {
            // Receive state: read one PDU from the socket.
            let mut tcp_ref = tcp;
            let n = read_pdu(&mut tcp_ref, hint, &mut scratch)?;
            let _written = connector.step(&scratch[..n], &mut output)?;
        } else {
            // Send state: step with empty input, then flush any bytes.
            output.clear();
            let _written = connector.step(&[], &mut output)?;
        }

        if !output.is_empty() {
            let mut tcp_ref = tcp;
            write_all(&mut tcp_ref, output.as_slice())?;
            output.clear();
        }
    }
}
