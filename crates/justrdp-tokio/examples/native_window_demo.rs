//! Native window demo for `justrdp-web` — winit + softbuffer.
//!
//! The render-to-PNG demo (`native_render_demo`) proves the
//! `BitmapRenderer` composes with `WebClient` and produces drawable
//! pixels; this demo extends that with a real OS window so the user
//! actually sees the remote desktop. Architecture:
//!
//! ```text
//! [tokio thread]              [winit main thread]
//!   NativeTcpTransport          EventLoop
//!   NativeTlsUpgrade            ApplicationHandler
//!   NativeCredsspDriver           ↑
//!   ActiveSession.next_events     │ EventLoopProxy::send_event(Redraw)
//!         │                       │
//!         ↓ render_event           │
//!   WinitFrameSink ──────────────────┐
//!         │ writes pixels             ↓
//!         ↓                       softbuffer Surface
//!   Arc<Mutex<Framebuffer>> ──────────┘ (ARGB upload on redraw)
//! ```
//!
//! Run with:
//!
//! ```bash
//! cargo run --release \
//!     --example native_window_demo \
//!     --features native-nla \
//!     -- 192.168.136.136:3389 testuser password
//! ```
//!
//! Close the window to disconnect. Keyboard / mouse forwarding is
//! intentionally out of scope (matches the roadmap S7-5 spec —
//! "1 frame 디코드"); the goal is visual proof, not interactive use.

use std::env;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::thread;

use justrdp_connector::Config;
use justrdp_async::{ActiveSession, SessionEvent, WebClient};
use justrdp_tokio::{NativeCredsspDriver, NativeTcpTransport, NativeTlsUpgrade};
use justrdp_web::{render_event, FrameSink};
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::window::{Window, WindowId};

const DEFAULT_WIDTH: u16 = 1024;
const DEFAULT_HEIGHT: u16 = 768;

/// Shared RDP-side framebuffer. The RDP pump thread writes pixels into
/// `pixels` (ARGB packed for direct softbuffer consumption); the winit
/// thread copies them into the surface buffer on each redraw.
struct Framebuffer {
    width: u16,
    height: u16,
    pixels: Vec<u32>,
}

impl Framebuffer {
    fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            pixels: vec![0u32; width as usize * height as usize],
        }
    }
}

/// Custom user event delivered to the winit event loop from the
/// tokio thread. `Redraw` is fired after each frame batch with
/// pixels; `Disconnected` exits the loop.
#[derive(Debug)]
enum AppEvent {
    Redraw,
    Disconnected,
}

/// Winit application state. Window + softbuffer surface are
/// constructed lazily in `resumed` per winit 0.30+ conventions.
struct App {
    window: Option<Arc<Window>>,
    surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
    framebuffer: Arc<Mutex<Framebuffer>>,
}

impl App {
    fn new(framebuffer: Arc<Mutex<Framebuffer>>) -> Self {
        Self {
            window: None,
            surface: None,
            framebuffer,
        }
    }
}

impl ApplicationHandler<AppEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        let attrs = Window::default_attributes()
            .with_title("JustRDP — native window demo")
            .with_inner_size(LogicalSize::new(
                DEFAULT_WIDTH as u32,
                DEFAULT_HEIGHT as u32,
            ));
        let window = Arc::new(
            event_loop
                .create_window(attrs)
                .expect("create_window should succeed on a desktop platform"),
        );
        let context = softbuffer::Context::new(window.clone())
            .expect("softbuffer Context creation");
        let surface = softbuffer::Surface::new(&context, window.clone())
            .expect("softbuffer Surface creation");
        self.window = Some(window);
        self.surface = Some(surface);
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::RedrawRequested => self.redraw(),
            _ => {}
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: AppEvent) {
        match event {
            AppEvent::Redraw => {
                if let Some(window) = &self.window {
                    window.request_redraw();
                }
            }
            AppEvent::Disconnected => {
                eprintln!("RDP session terminated; exiting window");
                event_loop.exit();
            }
        }
    }
}

impl App {
    fn redraw(&mut self) {
        let (Some(window), Some(surface)) = (&self.window, &mut self.surface) else {
            return;
        };
        let size = window.inner_size();
        let Some(width) = NonZeroU32::new(size.width) else {
            return;
        };
        let Some(height) = NonZeroU32::new(size.height) else {
            return;
        };
        if let Err(e) = surface.resize(width, height) {
            eprintln!("softbuffer resize: {e:?}");
            return;
        }
        let mut buffer = match surface.buffer_mut() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("softbuffer buffer_mut: {e:?}");
                return;
            }
        };

        // Copy from the RDP framebuffer into the surface buffer with
        // simple top-left clipping (no scaling). When the window is
        // larger than the framebuffer we leave the right / bottom
        // strip black; when it's smaller we clip. A real client would
        // do nearest-neighbor or bilinear upscale here.
        let win_w = size.width as usize;
        let win_h = size.height as usize;
        let fb = self.framebuffer.lock().expect("framebuffer mutex");
        let fb_w = fb.width as usize;
        let fb_h = fb.height as usize;
        let copy_w = win_w.min(fb_w);
        let copy_h = win_h.min(fb_h);

        // Clear unused strips to black so the previous frame doesn't
        // ghost when the window is resized larger than the
        // framebuffer.
        for px in buffer.iter_mut() {
            *px = 0xFF000000;
        }
        for row in 0..copy_h {
            let dst_off = row * win_w;
            let src_off = row * fb_w;
            buffer[dst_off..dst_off + copy_w]
                .copy_from_slice(&fb.pixels[src_off..src_off + copy_w]);
        }
        drop(fb);

        if let Err(e) = buffer.present() {
            eprintln!("softbuffer present: {e:?}");
        }
    }
}

/// `FrameSink` that writes incoming RGBA bytes into the shared
/// framebuffer (as 0x00RRGGBB) and pokes the winit thread to redraw.
struct WinitFrameSink {
    framebuffer: Arc<Mutex<Framebuffer>>,
    proxy: EventLoopProxy<AppEvent>,
    /// Set on the first `flush()` so we don't spam the winit proxy
    /// queue with duplicate Redraw events between batches that
    /// produced no pixels.
    pending_redraw: bool,
}

impl FrameSink for WinitFrameSink {
    fn resize(&mut self, width: u16, height: u16) {
        let mut fb = self.framebuffer.lock().expect("framebuffer mutex");
        if fb.width == width && fb.height == height {
            return;
        }
        *fb = Framebuffer::new(width, height);
    }

    fn blit_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        pixels_rgba: &[u8],
    ) {
        let mut fb = self.framebuffer.lock().expect("framebuffer mutex");
        let fb_w = fb.width as usize;
        let fb_h = fb.height as usize;
        let dx = dest_left as usize;
        let dy = dest_top as usize;
        let copy_w = (width as usize).min(fb_w.saturating_sub(dx));
        let copy_h = (height as usize).min(fb_h.saturating_sub(dy));
        if copy_w == 0 || copy_h == 0 {
            return;
        }
        let src_stride = width as usize;
        for row in 0..copy_h {
            for col in 0..copy_w {
                let s = (row * src_stride + col) * 4;
                let r = pixels_rgba[s] as u32;
                let g = pixels_rgba[s + 1] as u32;
                let b = pixels_rgba[s + 2] as u32;
                // softbuffer expects 0x00RRGGBB; alpha byte is
                // ignored on most platforms but Linux/X11 does
                // honour it as ARGB, so leave it 0xFF.
                let argb = 0xFF000000 | (r << 16) | (g << 8) | b;
                let dst_idx = (dy + row) * fb_w + (dx + col);
                fb.pixels[dst_idx] = argb;
            }
        }
        self.pending_redraw = true;
    }

    fn peek_rgba(
        &mut self,
        dest_left: u16,
        dest_top: u16,
        width: u16,
        height: u16,
        out: &mut Vec<u8>,
    ) -> bool {
        let fb = self.framebuffer.lock().expect("framebuffer mutex");
        let fb_w = fb.width as usize;
        let fb_h = fb.height as usize;
        let dx = dest_left as usize;
        let dy = dest_top as usize;
        let w = width as usize;
        let h = height as usize;
        if dx + w > fb_w || dy + h > fb_h {
            return false;
        }
        out.clear();
        out.reserve(w * h * 4);
        for row in 0..h {
            for col in 0..w {
                let argb = fb.pixels[(dy + row) * fb_w + (dx + col)];
                out.push(((argb >> 16) & 0xFF) as u8); // R
                out.push(((argb >> 8) & 0xFF) as u8); // G
                out.push((argb & 0xFF) as u8); // B
                out.push(0xFF);
            }
        }
        true
    }

    fn flush(&mut self) {
        if self.pending_redraw {
            self.pending_redraw = false;
            // Best-effort — if the winit loop has exited the proxy
            // returns an error which we silently ignore.
            let _ = self.proxy.send_event(AppEvent::Redraw);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} <host:port> <username> <password> [domain]",
            args.first().map(String::as_str).unwrap_or("native_window_demo")
        );
        std::process::exit(2);
    }
    let host = args[1].clone();
    let username = args[2].clone();
    let password = args[3].clone();
    let domain = args.get(4).cloned();

    let event_loop: EventLoop<AppEvent> =
        EventLoop::with_user_event().build()?;
    event_loop.set_control_flow(ControlFlow::Wait);

    let framebuffer = Arc::new(Mutex::new(Framebuffer::new(DEFAULT_WIDTH, DEFAULT_HEIGHT)));
    let proxy = event_loop.create_proxy();

    // Spawn the RDP pump on a dedicated tokio thread so the main
    // thread stays available for the winit event loop (winit owns
    // the main thread on macOS).
    {
        let fb = Arc::clone(&framebuffer);
        let proxy = proxy.clone();
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime.block_on(async move {
                if let Err(e) =
                    run_rdp_pump(host, username, password, domain, fb, proxy.clone()).await
                {
                    eprintln!("RDP error: {e}");
                }
                let _ = proxy.send_event(AppEvent::Disconnected);
            });
        });
    }

    let mut app = App::new(framebuffer);
    event_loop.run_app(&mut app)?;
    Ok(())
}

/// Run the full connect + pump loop on the tokio side. Errors are
/// boxed as `Send + Sync` so they can cross the tokio task boundary
/// before being printed by the spawning closure.
async fn run_rdp_pump(
    host: String,
    username: String,
    password: String,
    domain: Option<String>,
    framebuffer: Arc<Mutex<Framebuffer>>,
    proxy: EventLoopProxy<AppEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_name = host
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&host)
        .to_string();
    eprintln!("connecting to {host}");
    let transport = NativeTcpTransport::connect(host.as_str()).await?;
    let tls = NativeTlsUpgrade::dangerous_no_verify(server_name)?;
    let credssp = NativeCredsspDriver::new();

    let mut builder =
        Config::builder(&username, &password).desktop_size(DEFAULT_WIDTH, DEFAULT_HEIGHT);
    if let Some(d) = &domain {
        builder = builder.domain(d);
    }
    let config = builder.build();

    let client = WebClient::new(transport);
    let (result, post_tls) = client.connect_with_nla(config, tls, credssp).await?;
    eprintln!(
        "connected: share_id=0x{:08x}, io_channel={}, user_channel={}",
        result.share_id, result.io_channel_id, result.user_channel_id,
    );

    let mut sink = WinitFrameSink {
        framebuffer,
        proxy,
        pending_redraw: false,
    };
    let mut session = ActiveSession::new(post_tls, &result);

    loop {
        let events = session.next_events().await?;
        for ev in &events {
            if matches!(ev, SessionEvent::Graphics { .. }) {
                let _ = render_event(ev, &mut sink);
            }
            if matches!(ev, SessionEvent::Terminated(_)) {
                eprintln!("server terminated session");
                return Ok(());
            }
        }
    }
}
