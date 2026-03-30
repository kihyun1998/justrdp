//! Integration test: connect to a real RDP server.
//!
//! Usage: rdp-connect-test <host> <port> <username> <password> [domain]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use justrdp_connector::{
    ClientConnector, ClientConnectorState, Config, CredsspRandom, CredsspSequence, CredsspState,
    Sequence,
};
use justrdp_core::WriteBuf;
use justrdp_tls::RustlsUpgrader;
use justrdp_tls::TlsUpgrader;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: {} <host> <port> <username> <password> [domain]", args[0]);
        std::process::exit(1);
    }

    let host = &args[1];
    let port: u16 = args[2].parse().expect("invalid port");
    let username = &args[3];
    // Strip any backslash escaping that bash might add
    let password_raw = args[4].replace("\\!", "!");
    let password: &str = &password_raw;
    let domain = if args.len() > 5 { &args[5] } else { "" };

    println!("[*] Username: '{}', Password: '{}', Domain: '{}'", username, password, domain);

    println!("[*] Connecting to {}:{}", host, port);

    let stream = TcpStream::connect_timeout(
        &format!("{}:{}", host, port).parse().unwrap(),
        Duration::from_secs(5),
    )
    .expect("TCP connect failed");

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    println!("[+] TCP connected");

    let config = Config::builder(username, password)
        .domain(domain)
        .desktop_size(1024, 768)
        .build();

    let mut connector = ClientConnector::new(config);
    let mut output = WriteBuf::new();

    // Wrap stream in a mutable reference we can reborrow
    let mut raw_stream = stream;

    // Phase 1: Connection Initiation (X.224 CR/CC)
    drive_connector_until(
        &mut connector,
        &mut raw_stream,
        &mut output,
        &ClientConnectorState::EnhancedSecurityUpgrade,
        "Connection Initiation",
    );

    println!("[+] Security upgrade required (protocol: {:?})", connector.selected_protocol());

    // Phase 2: TLS Upgrade
    // Signal the connector that we're about to do TLS
    output.clear();
    connector.step(&[], &mut output).unwrap(); // SecurityUpgrade → CredSsp or BasicSettings

    let next_state = connector.state().clone();
    println!("[*] After SecurityUpgrade: {:?}", next_state);

    // Actually perform TLS
    println!("[*] Performing TLS handshake...");
    let tls_upgrader = RustlsUpgrader::new(); // accepts self-signed certs
    let tls_result = tls_upgrader
        .upgrade(raw_stream, host)
        .expect("TLS handshake failed");

    println!(
        "[+] TLS handshake complete, server public key: {} bytes",
        tls_result.server_public_key.len()
    );

    let mut tls_stream = tls_result.stream;
    let server_public_key = tls_result.server_public_key;

    // Phase 3: CredSSP/NLA (if needed)
    if next_state == ClientConnectorState::CredsspNegoTokens {
        println!("[*] Starting CredSSP/NLA...");

        // Generate random values for CredSSP
        let random = CredsspRandom {
            client_nonce: generate_random_bytes_32(),
            client_challenge: generate_random_bytes_8(),
            exported_session_key: generate_random_bytes_16(),
        };

        let use_hybrid_ex = connector.selected_protocol().contains(
            justrdp_pdu::x224::SecurityProtocol::HYBRID_EX,
        );
        let mut credssp = CredsspSequence::new(
            username, password, domain, server_public_key, random, use_hybrid_ex,
        );

        // CredSSP loop
        loop {
            match credssp.state() {
                CredsspState::SendNegoToken | CredsspState::SendCredentials => {
                    let ts_request_bytes = credssp.step(&[]).expect("CredSSP step failed");
                    println!(
                        "[*] CredSSP send: {} bytes (state: {:?})",
                        ts_request_bytes.len(),
                        credssp.state()
                    );
                    tls_stream
                        .write_all(&ts_request_bytes)
                        .expect("TLS write failed");
                    tls_stream.flush().expect("TLS flush failed");
                }
                CredsspState::WaitChallenge => {
                    let mut buf = vec![0u8; 8192];
                    let n = tls_stream.read(&mut buf).expect("TLS read failed");
                    println!(
                        "[*] CredSSP recv: {} bytes (state: {:?})",
                        n,
                        credssp.state()
                    );
                    if n == 0 {
                        panic!("server closed connection during CredSSP");
                    }
                    let response = match credssp.step(&buf[..n]) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("[-] CredSSP challenge step failed: {}", e);
                            std::process::exit(1);
                        }
                    };
                    if !response.is_empty() {
                        println!("[*] CredSSP send authenticate+pubKeyAuth: {} bytes", response.len());
                        tls_stream.write_all(&response).expect("TLS write failed");
                        tls_stream.flush().expect("TLS flush failed");
                    }
                }
                CredsspState::WaitPubKeyAuth => {
                    let mut buf = vec![0u8; 8192];
                    let n = tls_stream.read(&mut buf).expect("TLS read failed");
                    println!(
                        "[*] CredSSP recv: {} bytes (state: {:?})",
                        n,
                        credssp.state()
                    );
                    if n == 0 {
                        panic!("server closed connection during CredSSP");
                    }
                    // Hex dump for debugging
                    print!("    hex: ");
                    for b in &buf[..n.min(64)] {
                        print!("{:02x} ", b);
                    }
                    if n > 64 { print!("..."); }
                    println!();

                    let response = match credssp.step(&buf[..n]) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("[-] CredSSP step failed: {}", e);
                            // Try to decode the TsRequest for more details
                            if let Ok(ts) = justrdp_connector::credssp::ts_request::TsRequest::decode(&buf[..n]) {
                                eprintln!("    TsRequest version: {}", ts.version);
                                eprintln!("    TsRequest errorCode: {:?}", ts.error_code);
                                eprintln!("    TsRequest negoTokens: {} bytes", ts.nego_tokens.as_ref().map_or(0, |t| t.len()));
                                eprintln!("    TsRequest pubKeyAuth: {} bytes", ts.pub_key_auth.as_ref().map_or(0, |t| t.len()));
                            }
                            std::process::exit(1);
                        }
                    };
                    if !response.is_empty() {
                        println!("[*] CredSSP send response: {} bytes", response.len());
                        tls_stream.write_all(&response).expect("TLS write failed");
                        tls_stream.flush().expect("TLS flush failed");
                    }
                }
                CredsspState::WaitEarlyUserAuth => {
                    let mut buf = vec![0u8; 8192];
                    let n = tls_stream.read(&mut buf).expect("TLS read failed");
                    println!(
                        "[*] CredSSP recv EarlyUserAuthResult: {} bytes",
                        n,
                    );
                    if n == 0 {
                        panic!("server closed connection during CredSSP");
                    }
                    let response = match credssp.step(&buf[..n]) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("[-] EarlyUserAuthResult failed: {}", e);
                            std::process::exit(1);
                        }
                    };
                    if !response.is_empty() {
                        tls_stream.write_all(&response).expect("TLS write failed");
                        tls_stream.flush().expect("TLS flush failed");
                    }
                }
                CredsspState::Done => {
                    println!("[+] CredSSP/NLA complete");
                    break;
                }
            }
        }

        // Advance through remaining CredSSP states, sending any output to server
        loop {
            output.clear();
            connector.step(&[], &mut output).unwrap();
            let state = connector.state().clone();
            println!("[*] Connector state: {:?}", state);
            // Send any output produced (e.g., CredSSP Credentials TsRequest)
            let out_slice = output.as_mut_slice();
            if !out_slice.is_empty() {
                println!("[*] Sending {} bytes for state transition", out_slice.len());
                tls_stream.write_all(out_slice).expect("TLS write failed");
                tls_stream.flush().expect("TLS flush failed");
            }
            if state == ClientConnectorState::BasicSettingsExchangeSendInitial {
                break;
            }
        }
    }

    // Phase 4+: Drive remaining connection sequence over TLS
    drive_connector_tls(
        &mut connector,
        &mut tls_stream,
        &mut output,
        "RDP Connection",
    );

    if connector.state().is_connected() {
        println!("[+] RDP connection established successfully!");
        if let Some(result) = connector.result() {
            println!("    IO Channel: {}", result.io_channel_id);
            println!("    User Channel: {}", result.user_channel_id);
            println!("    Share ID: 0x{:08X}", result.share_id);
            println!("    Server Capabilities: {}", result.server_capabilities.len());
            println!("    Channels: {:?}", result.channel_ids);
        }
    } else {
        println!("[-] Connection failed. Final state: {:?}", connector.state());
    }
}

/// Drive the connector FSM over a raw TCP stream until target state.
fn drive_connector_until(
    connector: &mut ClientConnector,
    stream: &mut TcpStream,
    output: &mut WriteBuf,
    target: &ClientConnectorState,
    phase_name: &str,
) {
    loop {
        if connector.state() == target {
            break;
        }

        let hint = connector.next_pdu_hint();

        if hint.is_none() {
            // Send state: call step with empty input
            output.clear();
            let written = connector
                .step(&[], output)
                .unwrap_or_else(|e| panic!("[{}] step failed: {}", phase_name, e));

            if written.size > 0 {
                stream
                    .write_all(&output.as_mut_slice()[..written.size])
                    .unwrap_or_else(|e| panic!("[{}] write failed: {}", phase_name, e));
                stream.flush().unwrap();
                println!(
                    "[*] {} sent {} bytes (state: {:?})",
                    phase_name,
                    written.size,
                    connector.state()
                );
            }
        } else {
            // Wait state: read from network
            let mut buf = vec![0u8; 16384];
            let mut total = 0;

            // Read until we have a complete PDU
            loop {
                let n = stream
                    .read(&mut buf[total..])
                    .unwrap_or_else(|e| panic!("[{}] read failed: {}", phase_name, e));
                if n == 0 {
                    panic!("[{}] server closed connection", phase_name);
                }
                total += n;

                // Check if we have enough
                if let Some(hint) = connector.next_pdu_hint() {
                    if let Some((_is_fast_path, size)) = hint.find_size(&buf[..total]) {
                        if total >= size {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }

            println!(
                "[*] {} recv {} bytes (state: {:?})",
                phase_name,
                total,
                connector.state()
            );
            for chunk in buf[..total].chunks(32) {
                print!("    ");
                for b in chunk { print!("{:02x} ", b); }
                println!();
            }

            output.clear();
            let written = connector
                .step(&buf[..total], output)
                .unwrap_or_else(|e| panic!("[{}] step failed on input: {}", phase_name, e));

            if written.size > 0 {
                stream
                    .write_all(&output.as_mut_slice()[..written.size])
                    .unwrap();
                stream.flush().unwrap();
                println!(
                    "[*] {} sent {} bytes (state: {:?})",
                    phase_name,
                    written.size,
                    connector.state()
                );
            }
        }
    }
}

// ── Simple random byte generation using system time ──

fn simple_random_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn fill_random(buf: &mut [u8]) {
    let mut state = simple_random_seed();
    for byte in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
}

fn generate_random_bytes_8() -> [u8; 8] {
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    buf
}

fn generate_random_bytes_16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    fill_random(&mut buf);
    buf
}

fn generate_random_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    fill_random(&mut buf);
    buf
}

/// Drive the connector FSM over a TLS stream until Connected.
fn drive_connector_tls<S: Read + Write>(
    connector: &mut ClientConnector,
    stream: &mut S,
    output: &mut WriteBuf,
    phase_name: &str,
) {
    loop {
        if connector.state().is_connected() {
            break;
        }

        let hint = connector.next_pdu_hint();

        if hint.is_none() {
            // Send state
            output.clear();
            let pre_state = format!("{:?}", connector.state());
            let written = connector
                .step(&[], output)
                .unwrap_or_else(|e| {
                    panic!("[{}] step failed (send, was {}): {}", phase_name, pre_state, e);
                });

            if written.size > 0 {
                let data = &output.as_mut_slice()[..written.size];
                println!(
                    "[*] {} sent {} bytes (was: {} now: {:?})",
                    phase_name, written.size, pre_state, connector.state()
                );
                stream
                    .write_all(data)
                    .unwrap_or_else(|e| panic!("[{}] write failed: {}", phase_name, e));
                stream.flush().unwrap();
            }
        } else {
            // Wait state: read from network
            let mut buf = vec![0u8; 65536];
            let mut total = 0;

            loop {
                let n = stream
                    .read(&mut buf[total..])
                    .unwrap_or_else(|e| panic!("[{}] read failed: {}", phase_name, e));
                if n == 0 {
                    panic!("[{}] server closed connection", phase_name);
                }
                total += n;

                if let Some(hint) = connector.next_pdu_hint() {
                    if let Some((_is_fast_path, size)) = hint.find_size(&buf[..total]) {
                        if total >= size {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }

            println!(
                "[*] {} recv {} bytes (state: {:?})",
                phase_name,
                total,
                connector.state()
            );
            for chunk in buf[..total].chunks(32) {
                print!("    ");
                for b in chunk { print!("{:02x} ", b); }
                println!();
            }

            output.clear();
            let written = connector
                .step(&buf[..total], output)
                .unwrap_or_else(|e| panic!("[{}] step failed on input: {}", phase_name, e));

            if written.size > 0 {
                stream
                    .write_all(&output.as_mut_slice()[..written.size])
                    .unwrap();
                stream.flush().unwrap();
                println!(
                    "[*] {} sent {} bytes (state: {:?})",
                    phase_name,
                    written.size,
                    connector.state()
                );
            }
        }
    }
}
