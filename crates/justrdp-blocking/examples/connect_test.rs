//! Real-server smoke test for `justrdp-blocking`.
//!
//! Connects to an RDP server, prints every event surfaced by `next_event`,
//! and (optionally) sends a few keyboard / mouse inputs after the session
//! becomes active. Used to verify M1–M7 against a Windows RDS host.
//!
//! Usage:
//!
//!     cargo run -p justrdp-blocking --example connect_test -- \
//!         --host 192.168.136.136 \
//!         --port 3389 \
//!         --user rdptest \
//!         --password qweQWEqwe! \
//!         --domain '' \
//!         [--max-events 50] \
//!         [--reconnect] \
//!         [--send-input]
//!
//! Exit codes:
//!   0 — clean disconnect (server-initiated or max-events reached)
//!   1 — connect failed
//!   2 — runtime error
//!   3 — argument parsing failed
//!
//! # Validation status (manual run, target 192.168.136.136)
//!
//! Pumps through the full sequence: TCP → X.224 → TLS → CredSSP/NLA →
//! BasicSettingsExchange → ChannelConnection → CapabilitiesExchange →
//! ConnectionFinalization (single unified `ConnectionFinalizationWaitFontMap`
//! state — Synchronize/Cooperate/GrantedControl are silently consumed in
//! arrival order; only FontMap completes the phase per MS-RDPBCGR
//! §2.2.1.22). Successful completion: live frame stream from the server
//! after `Connected`.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use justrdp_blocking::{RdpClient, RdpEvent, ReconnectPolicy};
use justrdp_connector::{ArcCookie, Config};
use justrdp_input::{MouseButton, Scancode};

#[derive(Debug, Default)]
struct Args {
    host: String,
    port: u16,
    user: String,
    password: String,
    domain: String,
    width: u16,
    height: u16,
    max_events: u32,
    reconnect: bool,
    send_input: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        port: 3389,
        width: 1024,
        height: 768,
        max_events: 100,
        ..Args::default()
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--host" => args.host = iter.next().ok_or("--host needs value")?,
            "--port" => {
                args.port = iter
                    .next()
                    .ok_or("--port needs value")?
                    .parse()
                    .map_err(|e| format!("invalid port: {e}"))?
            }
            "--user" => args.user = iter.next().ok_or("--user needs value")?,
            "--password" => args.password = iter.next().ok_or("--password needs value")?,
            "--domain" => args.domain = iter.next().ok_or("--domain needs value")?,
            "--width" => {
                args.width = iter
                    .next()
                    .ok_or("--width needs value")?
                    .parse()
                    .map_err(|e| format!("invalid width: {e}"))?
            }
            "--height" => {
                args.height = iter
                    .next()
                    .ok_or("--height needs value")?
                    .parse()
                    .map_err(|e| format!("invalid height: {e}"))?
            }
            "--max-events" => {
                args.max_events = iter
                    .next()
                    .ok_or("--max-events needs value")?
                    .parse()
                    .map_err(|e| format!("invalid max-events: {e}"))?
            }
            "--reconnect" => args.reconnect = true,
            "--send-input" => args.send_input = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    if args.host.is_empty() {
        return Err("--host is required".into());
    }
    if args.user.is_empty() {
        return Err("--user is required".into());
    }
    Ok(args)
}

fn print_usage() {
    eprintln!(
        "usage: connect_test --host <H> [--port 3389] --user <U> --password <P> \\\n\
         \t\t [--domain ''] [--width 1024] [--height 768] [--max-events 100] \\\n\
         \t\t [--reconnect] [--send-input]"
    );
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[-] arg error: {e}");
            print_usage();
            return ExitCode::from(3);
        }
    };

    println!(
        "[*] connect_test starting: {}:{} as {}@{}",
        args.host,
        args.port,
        args.user,
        if args.domain.is_empty() {
            "<no domain>"
        } else {
            args.domain.as_str()
        }
    );

    let server = format!("{}:{}", args.host, args.port);
    let config = Config::builder(&args.user, &args.password)
        .domain(&args.domain)
        .desktop_size(args.width, args.height)
        .build();

    let connect_started = Instant::now();
    let mut client = match RdpClient::connect(server.as_str(), &args.host, config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] connect failed after {:?}: {e}", connect_started.elapsed());
            return ExitCode::from(1);
        }
    };
    println!(
        "[+] connected in {:?} — entering event loop",
        connect_started.elapsed()
    );

    if args.reconnect {
        client.set_reconnect_policy(ReconnectPolicy::aggressive());
        println!("[*] reconnect policy: aggressive (5 attempts, 1s/2s/4s/8s/10s backoff)");
        // Many RDS deployments do not advertise an Auto-Reconnect Cookie
        // unless the relevant Group Policy is on, so seed a synthetic one
        // to exercise the can_reconnect predicate. The actual reconnect
        // will likely fail at the server side because this cookie is
        // bogus, but we still observe the Reconnecting → Reconnected /
        // Disconnected control flow that M7 wires up.
        client.test_set_arc_cookie(ArcCookie::new(0xDEAD_BEEF, [0x42u8; 16]));
        println!("[*] injected synthetic ARC cookie for reconnect-loop validation");
    }

    let mut event_count: u32 = 0;
    let mut graphics_bytes: u64 = 0;
    let mut input_sent = false;
    let mut transport_dropped = false;
    let mut session_started = Instant::now();

    loop {
        let event = match client.next_event() {
            Ok(Some(e)) => e,
            Ok(None) => {
                println!(
                    "[+] session ended cleanly after {} events / {:?}",
                    event_count,
                    session_started.elapsed()
                );
                return ExitCode::from(0);
            }
            Err(e) => {
                eprintln!(
                    "[-] runtime error after {} events: {e}",
                    event_count
                );
                return ExitCode::from(2);
            }
        };
        event_count += 1;

        match &event {
            RdpEvent::GraphicsUpdate { update_code, data } => {
                graphics_bytes += data.len() as u64;
                if event_count <= 5 || event_count.is_multiple_of(20) {
                    println!(
                        "[#{event_count}] GraphicsUpdate {:?} ({} bytes, total {} KiB)",
                        update_code,
                        data.len(),
                        graphics_bytes / 1024
                    );
                }
            }
            RdpEvent::PointerPosition { x, y } => {
                println!("[#{event_count}] PointerPosition ({x}, {y})");
            }
            RdpEvent::PointerDefault => println!("[#{event_count}] PointerDefault"),
            RdpEvent::PointerHidden => println!("[#{event_count}] PointerHidden"),
            RdpEvent::PointerBitmap { pointer_type, data } => {
                println!(
                    "[#{event_count}] PointerBitmap type=0x{pointer_type:04x} ({} bytes)",
                    data.len()
                );
            }
            RdpEvent::KeyboardIndicators { scroll, num, caps, kana } => {
                println!(
                    "[#{event_count}] KeyboardIndicators caps={caps} num={num} scroll={scroll} kana={kana}"
                );
            }
            RdpEvent::ImeStatus { state, convert } => {
                println!("[#{event_count}] ImeStatus state={state} convert=0x{convert:08x}");
            }
            RdpEvent::PlaySound { frequency, duration_ms } => {
                println!("[#{event_count}] PlaySound {frequency} Hz / {duration_ms} ms");
            }
            RdpEvent::SuppressOutput { allow } => {
                println!("[#{event_count}] SuppressOutput allow={allow}");
            }
            RdpEvent::SaveSessionInfo(data) => {
                let arc = data.arc_random().is_some();
                println!(
                    "[#{event_count}] SaveSessionInfo (arc_cookie_present={arc}) {data:?}"
                );
            }
            RdpEvent::ServerMonitorLayout { monitors } => {
                println!(
                    "[#{event_count}] ServerMonitorLayout ({} monitors)",
                    monitors.len()
                );
            }
            RdpEvent::ChannelData { channel_id, data } => {
                println!(
                    "[#{event_count}] ChannelData ch={channel_id} ({} bytes) — no processor registered",
                    data.len()
                );
            }
            RdpEvent::Reconnecting { attempt } => {
                println!("[#{event_count}] Reconnecting (attempt {attempt})");
                session_started = Instant::now();
            }
            RdpEvent::Reconnected => {
                println!(
                    "[#{event_count}] Reconnected — recovered in {:?}",
                    session_started.elapsed()
                );
                input_sent = false; // re-arm input on reconnect
            }
            RdpEvent::Redirected { target } => {
                println!("[#{event_count}] Redirected to {target}");
            }
            RdpEvent::Disconnected(reason) => {
                println!("[#{event_count}] Disconnected: {reason:?}");
                return ExitCode::from(0);
            }
        }

        // After enough graphics frames, fire a few input events to verify
        // M5. We do this exactly once per session so we don't spam the
        // server with synthetic typing.
        if args.send_input && !input_sent && graphics_bytes > 50_000 {
            input_sent = true;
            if let Err(e) = exercise_input(&mut client) {
                eprintln!("[-] input send failed: {e}");
            } else {
                println!("[*] input batch sent (mouse move + 'a' press/release)");
            }
        }

        // M7 validation: after a few events, simulate a transport drop
        // and watch for the Reconnecting/Reconnected/Disconnected sequence.
        // We only do this once per session and only when --reconnect is set.
        if args.reconnect && !transport_dropped && event_count >= 10 {
            transport_dropped = true;
            println!("[*] simulating transport drop to exercise M7 reconnect");
            client.test_drop_transport();
        }

        if event_count >= args.max_events {
            println!(
                "[+] max-events ({}) reached after {:?}, exiting",
                args.max_events,
                session_started.elapsed()
            );
            return ExitCode::from(0);
        }
    }
}

/// Send a small batch of inputs to verify the M5 helpers against a real
/// server. Errors are returned to the caller for logging.
fn exercise_input(client: &mut RdpClient) -> Result<(), Box<dyn std::error::Error>> {
    // Move the cursor to the middle of a 1024x768 desktop
    client.send_mouse_move(512, 384)?;
    std::thread::sleep(Duration::from_millis(50));
    // Left-click at the same position
    client.send_mouse_button(MouseButton::Left, true, 512, 384)?;
    client.send_mouse_button(MouseButton::Left, false, 512, 384)?;
    std::thread::sleep(Duration::from_millis(50));
    // Press and release 'A' (PC scancode 0x1E, no extended bit)
    let a = Scancode::new(0x1E, false);
    client.send_keyboard(a, true)?;
    std::thread::sleep(Duration::from_millis(50));
    client.send_keyboard(a, false)?;
    Ok(())
}
