//! Native render-to-PNG demo for `justrdp-web`.
//!
//! Extends [`native_connect_demo`](native_connect_demo) with the
//! rendering half of the §11.3 transport-agnostic core: every
//! `SessionEvent::Graphics` event is fed through `render_event` into
//! a custom `FrameSink` that writes pixels into an in-memory RGBA
//! framebuffer. After the configured pump-frame budget, the
//! framebuffer is saved as `frame.png` for visual inspection.
//!
//! Run with:
//!
//! ```bash
//! cargo run --release \
//!     --example native_render_demo \
//!     --features native-nla \
//!     -- 192.168.136.136:3389 testuser password
//! ```
//!
//! The PNG ends up at the cwd. winit + softbuffer integration (live
//! window) is intentionally deferred — it adds ~500 lines of
//! event-loop boilerplate without changing what's being proven
//! (BitmapRenderer composing with WebClient on a desktop target).
//! See roadmap §11.3 S7-5c for the live-window follow-up.

use std::env;
use std::fs::File;
use std::io::BufWriter;
use std::time::Duration;

use justrdp_connector::Config;
use justrdp_web::{
    render_event, ActiveSession, FrameSink, NativeCredsspDriver, NativeTcpTransport,
    NativeTlsUpgrade, SessionEvent, WebClient, WebTransport,
};

const DEFAULT_WIDTH: u16 = 1024;
const DEFAULT_HEIGHT: u16 = 768;
const FRAME_BUDGET: u32 = 30;
const POLL_TIMEOUT_SECS: u64 = 5;

/// In-memory RGBA framebuffer that backs the render pump. The
/// framebuffer is stored row-major top-down (the same layout
/// `render_event` blits into, and the layout the `png` crate
/// expects for `ColorType::Rgba`).
struct PngFrameSink {
    width: u16,
    height: u16,
    pixels: Vec<u8>,
}

impl PngFrameSink {
    fn new(width: u16, height: u16) -> Self {
        // Initialise to opaque black. RDP servers typically push a
        // full-screen update on the first frame, but if that doesn't
        // happen (e.g. early disconnect) we still want a valid PNG.
        let mut pixels = vec![0u8; width as usize * height as usize * 4];
        for px in pixels.chunks_exact_mut(4) {
            px[3] = 0xFF;
        }
        Self {
            width,
            height,
            pixels,
        }
    }

    /// Save the framebuffer to `path` as RGBA PNG (8-bit).
    fn save_png(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        let mut encoder = png::Encoder::new(writer, self.width as u32, self.height as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&self.pixels)?;
        Ok(())
    }
}

impl FrameSink for PngFrameSink {
    fn resize(&mut self, width: u16, height: u16) {
        if width == self.width && height == self.height {
            return;
        }
        // Server announced a new desktop size mid-session
        // (deactivation/reactivation). Re-allocate at the new size and
        // reset to opaque black.
        self.width = width;
        self.height = height;
        self.pixels = vec![0u8; width as usize * height as usize * 4];
        for px in self.pixels.chunks_exact_mut(4) {
            px[3] = 0xFF;
        }
    }

    fn blit_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        pixels_rgba: &[u8],
    ) {
        // Clip to surface — RDP servers occasionally send rectangles
        // that extend past the negotiated desktop size; ignoring the
        // overflow is safer than panicking.
        let dx = dest_left as usize;
        let dy = dest_top as usize;
        let w = width as usize;
        let h = height as usize;
        let surface_w = self.width as usize;
        let surface_h = self.height as usize;
        let copy_w = w.min(surface_w.saturating_sub(dx));
        let copy_h = h.min(surface_h.saturating_sub(dy));
        if copy_w == 0 || copy_h == 0 {
            return;
        }
        for row in 0..copy_h {
            let src_off = row * w * 4;
            let dst_off = ((dy + row) * surface_w + dx) * 4;
            self.pixels[dst_off..dst_off + copy_w * 4]
                .copy_from_slice(&pixels_rgba[src_off..src_off + copy_w * 4]);
        }
    }

    fn peek_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        out: &mut Vec<u8>,
    ) -> bool {
        // Implementing peek_rgba unlocks DSTINVERT / non-SRCCOPY
        // MemBlt and other read-modify-write ROPs. For a one-shot
        // PNG dump it's fine to return false; the renderer will
        // silent-drop those orders without corrupting the surface.
        // Wire it up here to demonstrate the full FrameSink contract
        // — implementing it costs four lines.
        let dx = dest_left as usize;
        let dy = dest_top as usize;
        let w = width as usize;
        let h = height as usize;
        let surface_w = self.width as usize;
        let surface_h = self.height as usize;
        if dx + w > surface_w || dy + h > surface_h {
            return false;
        }
        out.clear();
        out.reserve(w * h * 4);
        for row in 0..h {
            let off = ((dy + row) * surface_w + dx) * 4;
            out.extend_from_slice(&self.pixels[off..off + w * 4]);
        }
        true
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} <host:port> <username> <password> [domain]",
            args.first().map(String::as_str).unwrap_or("native_render_demo")
        );
        std::process::exit(2);
    }
    let addr = args[1].as_str();
    let username = args[2].as_str();
    let password = args[3].as_str();
    let domain = args.get(4).map(String::as_str);
    let server_name = addr.rsplit_once(':').map(|(host, _)| host).unwrap_or(addr);

    eprintln!("connecting to {addr}");
    let transport = NativeTcpTransport::connect(addr).await?;
    let tls = NativeTlsUpgrade::dangerous_no_verify(server_name)?;
    let credssp = NativeCredsspDriver::new();

    let mut builder = Config::builder(username, password)
        .desktop_size(DEFAULT_WIDTH, DEFAULT_HEIGHT);
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

    let mut sink = PngFrameSink::new(DEFAULT_WIDTH, DEFAULT_HEIGHT);
    let mut session = ActiveSession::new(post_tls, &result);

    let mut frames_with_pixels: u32 = 0;
    let mut total_events: u32 = 0;

    for i in 0..FRAME_BUDGET {
        match tokio::time::timeout(Duration::from_secs(POLL_TIMEOUT_SECS), session.next_events())
            .await
        {
            Ok(Ok(events)) => {
                total_events += events.len() as u32;
                for ev in &events {
                    if matches!(ev, SessionEvent::Graphics { .. }) {
                        if render_event(ev, &mut sink).unwrap_or(false) {
                            frames_with_pixels += 1;
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("frame {i}: terminated: {e}");
                break;
            }
            Err(_) => {
                eprintln!("frame {i}: idle ({POLL_TIMEOUT_SECS}s timeout)");
                break;
            }
        }
    }

    eprintln!(
        "rendered {frames_with_pixels} bitmap-update batches across {total_events} events",
    );

    let png_path = "frame.png";
    sink.save_png(png_path)?;
    eprintln!("wrote {png_path} ({}x{})", sink.width, sink.height);

    let mut transport = session.into_transport();
    transport.close().await?;
    eprintln!("disconnected");
    Ok(())
}
