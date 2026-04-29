//! End-to-end native connect demo for `justrdp-web`.
//!
//! Proves the §11.3 transport-agnostic core compiles and links on a
//! desktop target — no wsproxy, no browser. The example:
//!
//! 1. Opens a TCP socket to an RDP server (`NativeTcpTransport`).
//! 2. Drives the X.224 / TLS / NLA handshake
//!    (`NativeTlsUpgrade` + `NativeCredsspDriver`).
//! 3. Pumps a handful of session events (`ActiveSession::next_events`)
//!    so the embedder sees the post-MCS data flow start.
//! 4. Closes the transport.
//!
//! Run with the `native-nla` feature so the transport, TLS, and NLA
//! adapters are all available:
//!
//! ```bash
//! cargo run --release \
//!     --example native_connect_demo \
//!     --features native-nla \
//!     -- 192.168.136.136:3389 testuser password
//! ```
//!
//! The example does no rendering — it's a smoke test that the connect
//! path completes against a real Windows RDP server. Visual validation
//! (winit + softbuffer + PNG dump) is a follow-up — see roadmap §11.3
//! S7-5b.

use std::env;
use std::time::Duration;

use justrdp_connector::Config;
use justrdp_web::{
    ActiveSession, NativeCredsspDriver, NativeTcpTransport, NativeTlsUpgrade, WebClient,
    WebTransport,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} <host:port> <username> <password> [domain]",
            args.first().map(String::as_str).unwrap_or("native_connect_demo")
        );
        std::process::exit(2);
    }
    let addr = args[1].as_str();
    let username = args[2].as_str();
    let password = args[3].as_str();
    let domain = args.get(4).map(String::as_str);

    // Server name for SNI: strip the port if the address has one.
    let server_name = addr.rsplit_once(':').map(|(host, _)| host).unwrap_or(addr);

    eprintln!("connecting to {addr} (SNI: {server_name})");

    // 1. TCP.
    let transport = NativeTcpTransport::connect(addr).await?;

    // 2. TLS upgrade (no-verify — RDP self-signed default; CredSSP's
    //    pubKeyAuth checks the server identity separately).
    let tls = NativeTlsUpgrade::dangerous_no_verify(server_name)?;

    // 3. NLA driver. Wires `CredsspSequence` against the post-TLS
    //    transport — NTLMv2 against username/password is the common
    //    case for Windows desktops in a workgroup.
    let credssp = NativeCredsspDriver::new();

    // 4. Connector config. SSL + HYBRID is the default; HYBRID is
    //    what triggers the NLA driver. The desktop size is just a
    //    request — the server clamps to its supported sizes.
    let mut builder = Config::builder(username, password);
    if let Some(dom) = domain {
        builder = builder.domain(dom);
    }
    let config = builder.build();

    let client = WebClient::new(transport);
    let (result, post_tls) = client.connect_with_nla(config, tls, credssp).await?;

    eprintln!(
        "connected: share_id=0x{:08x}, io_channel={}, user_channel={}",
        result.share_id, result.io_channel_id, result.user_channel_id,
    );

    // 5. Pump a few events so the post-MCS data path actually moves.
    //    A real client would loop here forever and feed events to a
    //    renderer + input pump; we just want the smoke-test signal.
    let mut session = ActiveSession::new(post_tls, &result);
    for i in 0..5 {
        match tokio::time::timeout(Duration::from_secs(5), session.next_events()).await {
            Ok(Ok(events)) => eprintln!("frame {i}: {} events", events.len()),
            Ok(Err(e)) => {
                eprintln!("frame {i}: terminated: {e}");
                break;
            }
            Err(_elapsed) => {
                eprintln!("frame {i}: idle (5s timeout)");
                break;
            }
        }
    }

    // 6. Disconnect cleanly.
    let mut transport = session.into_transport();
    transport.close().await?;
    eprintln!("disconnected");
    Ok(())
}
