//! CLI smoke for CLIPRDR — headless companion to the Tauri test app.
//!
//! Connects to a real RDP server with the CLIPRDR processor registered
//! (with the platform's native clipboard listener), runs `next_event`
//! for a bounded duration, and forwards every `[DIAG-clip]` log line
//! to stderr through the global `log` facade.
//!
//! The point of this binary is to compare **server-side response
//! patterns** for two different capability advertisements:
//!
//!   1. The current code: `0x3e` (long names + every file/lock cap we
//!      don't actually implement). The Tauri-side log shows the server
//!      goes silent after MonitorReady — no FormatListResponse, no
//!      FormatDataRequest, no server-initiated FormatList.
//!
//!   2. A narrowed advertisement: `0x02` (long names only). The
//!      `feedback_no_partial_protocol_enable` memory predicts Microsoft
//!      RDP silently degrades when a client over-advertises caps without
//!      handlers; if that's right, switching to `0x02` should unblock
//!      bidirectional traffic.
//!
//! Run:
//!
//! ```text
//! cargo run -p justrdp-blocking --example cliprdr_cli --features tracing -- \
//!     --host 192.168.136.136 --user rdptest --password 'qweQWEqwe!' --cap 0x02
//! ```
//!
//! `--cap` accepts hex (`0x02`) or decimal (`2`). Defaults to the full
//! `0x3e` advertisement that the Tauri build currently emits, so the
//! out-of-the-box run reproduces the bug without code edits.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use justrdp_blocking::{RdpClient, RdpEvent};
use justrdp_cliprdr::pdu::GeneralCapabilityFlags;
use justrdp_cliprdr::CliprdrClient;
use justrdp_cliprdr_native::NativeClipboard;
use justrdp_connector::Config;
use justrdp_svc::SvcProcessor;

// CHANNEL_OPTION_INITIALIZED (0x80000000) | CHANNEL_OPTION_COMPRESS_RDP (0x00800000)
// Same flags the Tauri build uses for cliprdr / rdpsnd / drdynvc.
const SVC_FLAGS_DEFAULT: u32 = 0x8080_0000;
// + CHANNEL_OPTION_SHOW_PROTOCOL (0x00200000) — what FreeRDP advertises
// for cliprdr. Tells the server we want the channel header echoed on
// reassembled chunks, which some Microsoft servers use as a "we speak
// the full protocol" signal.
const SVC_FLAGS_SHOW_PROTO: u32 = 0x80A0_0000;

#[derive(Debug, Default)]
struct Args {
    host: String,
    port: u16,
    user: String,
    password: String,
    domain: String,
    width: u16,
    height: u16,
    cap_flags: u32,
    /// Seconds before forcing a clean exit. The bug shows up well within
    /// 30s after MonitorReady, so the default is short.
    seconds: u64,
    /// Disable the Win32 clipboard listener thread — useful to confirm
    /// "did the server send anything spontaneously?" without our own
    /// outbound traffic muddying the picture.
    no_listener: bool,
    /// Set CHANNEL_OPTION_SHOW_PROTOCOL on the cliprdr channel
    /// advertisement. FreeRDP / mstsc both set this; the current Tauri
    /// build does not. Toggling this probes whether the missing flag is
    /// why the server silently degrades after MonitorReady.
    show_protocol: bool,
    /// Send a Temporary Directory PDU between caps and the format list.
    /// Spec marks this optional but Microsoft RDP servers may treat its
    /// absence as a conformance signal when file caps are advertised.
    temp_dir: Option<String>,
}

fn parse_cap(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("invalid hex cap '{raw}': {e}"))
    } else {
        trimmed
            .parse::<u32>()
            .map_err(|e| format!("invalid decimal cap '{raw}': {e}"))
    }
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        port: 3389,
        width: 1024,
        height: 768,
        // Match CliprdrClient::new default — reproduces the bug as-is.
        cap_flags: 0x3e,
        seconds: 30,
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
            "--cap" => args.cap_flags = parse_cap(&iter.next().ok_or("--cap needs value")?)?,
            "--seconds" => {
                args.seconds = iter
                    .next()
                    .ok_or("--seconds needs value")?
                    .parse()
                    .map_err(|e| format!("invalid seconds: {e}"))?
            }
            "--no-listener" => args.no_listener = true,
            "--show-protocol" => args.show_protocol = true,
            "--temp-dir" => args.temp_dir = Some(iter.next().ok_or("--temp-dir needs value")?),
            "--help" | "-h" => {
                eprintln!(
                    "usage: cliprdr_cli --host <H> --user <U> --password <P> \\\n\
                     \t[--port 3389] [--domain ''] [--cap 0x3e|0x02|...] [--seconds 30] [--no-listener]"
                );
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

fn main() -> ExitCode {
    // Send `info`+ from every crate to stderr through the `log` facade.
    // `[DIAG-clip]` lines come from justrdp-cliprdr / cliprdr-native /
    // justrdp-async / justrdp-tauri-* — all of which use `log::info!`.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[CLI] arg error: {e}");
            return ExitCode::from(3);
        }
    };

    let svc_flags = if args.show_protocol {
        SVC_FLAGS_SHOW_PROTO
    } else {
        SVC_FLAGS_DEFAULT
    };
    eprintln!(
        "[CLI] target={}:{} user={} cap=0x{:08x} svc_flags=0x{:08x} temp_dir={:?} seconds={} listener={}",
        args.host,
        args.port,
        args.user,
        args.cap_flags,
        svc_flags,
        args.temp_dir,
        args.seconds,
        if args.no_listener { "off" } else { "on" }
    );

    let server = format!("{}:{}", args.host, args.port);
    let mut builder = Config::builder(&args.user, &args.password)
        .desktop_size(args.width, args.height)
        .channel("cliprdr", svc_flags);
    // Match Tauri's behaviour: only call .domain() when one was supplied.
    // Setting an empty string makes CredSSP put `""` on the wire instead
    // of omitting the field, which some Windows servers reject.
    if !args.domain.is_empty() {
        builder = builder.domain(&args.domain);
    }
    // mstsc / FreeRDP always populate the NetBIOS-style clientName; some
    // Microsoft servers silently disable channel redirection (cliprdr,
    // rdpsnd) when the field is empty, treating the connection as a
    // "non-standard client". Default to the local hostname to mirror
    // mstsc's behaviour.
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "justrdp-cli".into());
    builder = builder.client_name(&hostname);
    let config = builder.build();
    eprintln!("[CLI] client_name='{hostname}'");

    // Cap-flag knob: the `CliprdrClient::with_flags` builder lets us
    // narrow the advertisement without touching production code, so the
    // 0x3e ↔ 0x02 A/B is a pure runtime parameter.
    let local_flags = GeneralCapabilityFlags::from_bits(args.cap_flags);

    let cliprdr_proc: Box<dyn SvcProcessor> = if args.no_listener {
        let clip = match NativeClipboard::new() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[CLI] NativeClipboard::new failed: {e}");
                return ExitCode::from(2);
            }
        };
        {
            let mut c = CliprdrClient::new(Box::new(clip)).with_flags(local_flags);
            if let Some(ref t) = args.temp_dir {
                c = c.with_temp_dir(t.clone());
            }
            Box::new(c)
        }
    } else {
        // `new_with_listener` takes a Sender<()>; we don't drive
        // poll_outbound from this binary (it would need a separate
        // thread + sharable client handle), but the listener still
        // exists so WM_CLIPBOARDUPDATE feeds the backend's internal
        // outbound queue. Drained PDUs sit there until something polls.
        let (wake_tx, _wake_rx) = std::sync::mpsc::channel::<()>();
        let clip = match NativeClipboard::new_with_listener(wake_tx) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[CLI] NativeClipboard::new_with_listener failed: {e}");
                return ExitCode::from(2);
            }
        };
        {
            let mut c = CliprdrClient::new(Box::new(clip)).with_flags(local_flags);
            if let Some(ref t) = args.temp_dir {
                c = c.with_temp_dir(t.clone());
            }
            Box::new(c)
        }
    };

    let connect_started = Instant::now();
    let mut client =
        match RdpClient::connect_with_processors(server.as_str(), &args.host, config, vec![cliprdr_proc]) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[CLI] connect failed after {:?}: {e}", connect_started.elapsed());
                return ExitCode::from(1);
            }
        };
    eprintln!("[CLI] connected in {:?}", connect_started.elapsed());
    let _ = &client; // suppress unused-mut warning until first next_event

    let deadline = Instant::now() + Duration::from_secs(args.seconds);
    let mut event_count: u32 = 0;
    let mut graphics_bytes: u64 = 0;
    let mut channel_events: u32 = 0;

    loop {
        if Instant::now() >= deadline {
            eprintln!(
                "[CLI] deadline reached ({}s) — events={} graphics={}KiB channel_events={}",
                args.seconds,
                event_count,
                graphics_bytes / 1024,
                channel_events
            );
            return ExitCode::from(0);
        }

        let event = match client.next_event() {
            Ok(Some(e)) => e,
            Ok(None) => {
                eprintln!("[CLI] session ended cleanly after {event_count} events");
                return ExitCode::from(0);
            }
            Err(e) => {
                eprintln!("[CLI] runtime error after {event_count} events: {e}");
                return ExitCode::from(2);
            }
        };
        event_count += 1;

        match &event {
            // Graphics frames are noisy; collapse to a periodic counter.
            RdpEvent::GraphicsUpdate { data, .. } => {
                graphics_bytes += data.len() as u64;
            }
            // Anything CLIPRDR / unknown-channel-passthrough lands here.
            RdpEvent::ChannelData { channel_id, data } => {
                channel_events += 1;
                eprintln!(
                    "[CLI] #{event_count} ChannelData ch={channel_id} bytes={}",
                    data.len()
                );
            }
            // Everything else: 1-line summary so the operator can spot
            // unexpected server activity.
            other => {
                eprintln!("[CLI] #{event_count} {other:?}");
            }
        }
    }
}
