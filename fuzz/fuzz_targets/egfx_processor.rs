#![no_main]
//! Fuzz the EGFX **graphics processor** — `justrdp::egfx::GraphicsProcessor` (issue #267).
//! Sibling of that module's `graphics_processor_is_total_over_arbitrary_sessions` proptest.
//!
//! ## Why this is not `egfx.rs`, which targets different code
//!
//! `fuzz_targets/egfx.rs` drives `justrdp_pdu::egfx::decode_all` — the *PDU crate's* parser. The
//! two modules share a name, so the untrusted-decode invariant's two derivations (`ls
//! fuzz_targets/` and a walk of what parses server bytes) matched by name and reported this
//! surface as covered while nothing drove it. Fourth instance of that trap: `pointer` across
//! crates (#203), `license` within one module (#230), `tls` in the core crate (#241), and now
//! the graphics processor one crate further out again. See
//! `docs/map/invariant/untrusted-decode-never-panics.md`.
//!
//! The split of labour between the two is real and worth keeping. `egfx.rs` feeds raw bytes to
//! the parser, which is where malformed *framing* belongs. This target's input is a sequence of
//! **structurally valid** commands, because the processor's defects do not live in the header
//! walk — they live in what the arms do with state a previous message established.
//!
//! ## Why a sequence, and why a bootstrap
//!
//! Every other target in this directory drives a stateless parse. This subject is not one: the
//! processor carries the zgfx LZ77 history, the Progressive tile store, the ClearCodec caches,
//! the surface list and the bitmap cache across messages, and #268's defect was funded by
//! exactly that — a 262 KB PDU whose cost came from a bitmap an earlier message had cached.
//!
//! Measured on the proptest side while writing it: deleting `Surface::blit`'s zero-extent early
//! return left the property **green** until a correlated opening message was prepended, because
//! that panic needs a destination past the surface *and* a live cached bitmap to paste — a
//! three-command sequence independently drawn commands almost never assemble. `Bootstrap`
//! carries that here. `ironrdp-fuzzing`'s `egfx_multi_frame` does the same thing one step
//! earlier, calling `DvcProcessor::start` before its loop.
//!
//! ## Why the bodies are assembled by hand
//!
//! `ironrdp-fuzzing` generates typed PDUs and re-encodes them with `encode_vec`. That is not
//! available here: **every encoder in `justrdp-pdu` writes client-to-server** (ADR-0008's
//! 2026-09-04 amendment), so there is no server-side encoder to borrow and `Body` below is the
//! generator's own.
//!
//! ## Why the crate needs a feature to be reachable
//!
//! `justrdp`'s `egfx` and `dvc` are private modules and `GraphicsProcessor` is core mechanism
//! rather than host API (ADR-0001) — what a host may reach into is the open question in #273.
//! The `fuzzing` feature re-exports just this pair through `justrdp::fuzzing` without widening
//! the published surface. Maintainer's call, 2026-09-07.
//!
//! ## Byte layout
//!
//! `Arbitrary` derives it. `Vec<u8>` fields cost two bytes per element against `arbitrary`
//! 1.4.2 — one from the front and a keep-going byte from the back, the measurement `gcc.rs`
//! records — which is why the payloads here are `Vec<u8>` and not larger structures: the
//! interesting inputs are short. No seeder writes for this target.

use justrdp::Framebuffer;
use justrdp::fuzzing::{DvcProcessor as _, GraphicsProcessor};
use justrdp_pdu::egfx;
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// Little-endian body writer — the same shape the in-crate property uses, for the same reason.
#[derive(Default)]
struct Body(Vec<u8>);

impl Body {
    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn rect(self, r: (u16, u16, u16, u16)) -> Self {
        self.u16(r.0).u16(r.1).u16(r.2).u16(r.3)
    }
    fn bytes(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
    /// Prepend the `RDPGFX_HEADER` (`cmdId`, `flags`, `pduLength`) the processor walks.
    fn header(self, cmd_id: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.0.len());
        out.extend_from_slice(&cmd_id.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&((8 + self.0.len()) as u32).to_le_bytes());
        out.extend_from_slice(&self.0);
        out
    }
}

/// One server command. The `Raw` arm keeps the header's own refusals and the `Unknown` skip
/// driven; every other arm is a command a real server sends.
#[derive(Arbitrary, Debug)]
enum Cmd {
    CapsConfirm(u32, u32),
    ResetGraphics(u32, u32),
    CreateSurface(u16, u16, u16, u8),
    DeleteSurface(u16),
    MapSurfaceToOutput(u16, u32, u32),
    StartFrame(u32),
    EndFrame(u32),
    WireToSurface1(u16, u16, u8, (u16, u16, u16, u16), Vec<u8>),
    WireToSurface2(u16, u16, u32, u8, Vec<u8>),
    DeleteEncodingContext(u16, u32),
    SolidFill(u16, [u8; 4], u16, Vec<(u16, u16, u16, u16)>),
    SurfaceToSurface(u16, u16, (u16, u16, u16, u16), u16, Vec<(u16, u16)>),
    SurfaceToCache(u16, u32, u32, u16, (u16, u16, u16, u16)),
    CacheToSurface(u16, u16, u16, Vec<(u16, u16)>),
    EvictCacheEntry(u16),
    Raw(u16, Vec<u8>),
}

impl Cmd {
    fn encode(&self) -> Vec<u8> {
        match self {
            Cmd::CapsConfirm(v, f) => Body::default()
                .u32(*v)
                .u32(4)
                .u32(*f)
                .header(egfx::CMDID_CAPS_CONFIRM),
            Cmd::ResetGraphics(w, h) => Body::default()
                .u32(*w)
                .u32(*h)
                .header(egfx::CMDID_RESET_GRAPHICS),
            Cmd::CreateSurface(s, w, h, pf) => Body::default()
                .u16(*s)
                .u16(*w)
                .u16(*h)
                .u8(*pf)
                .header(egfx::CMDID_CREATE_SURFACE),
            Cmd::DeleteSurface(s) => Body::default().u16(*s).header(egfx::CMDID_DELETE_SURFACE),
            Cmd::MapSurfaceToOutput(s, x, y) => Body::default()
                .u16(*s)
                .u16(0)
                .u32(*x)
                .u32(*y)
                .header(egfx::CMDID_MAP_SURFACE_TO_OUTPUT),
            Cmd::StartFrame(f) => Body::default()
                .u32(0)
                .u32(*f)
                .header(egfx::CMDID_START_FRAME),
            Cmd::EndFrame(f) => Body::default().u32(*f).header(egfx::CMDID_END_FRAME),
            Cmd::WireToSurface1(s, c, pf, r, d) => Body::default()
                .u16(*s)
                .u16(*c)
                .u8(*pf)
                .rect(*r)
                .u32(d.len() as u32)
                .bytes(d)
                .header(egfx::CMDID_WIRE_TO_SURFACE_1),
            Cmd::WireToSurface2(s, c, ctx, pf, d) => Body::default()
                .u16(*s)
                .u16(*c)
                .u32(*ctx)
                .u8(*pf)
                .u32(d.len() as u32)
                .bytes(d)
                .header(egfx::CMDID_WIRE_TO_SURFACE_2),
            Cmd::DeleteEncodingContext(s, c) => Body::default()
                .u16(*s)
                .u32(*c)
                .header(egfx::CMDID_DELETE_ENCODING_CONTEXT),
            // The declared count and the entries written are independent on purpose: a count
            // larger than the bytes present is the reject branch, and one the bytes cover is
            // #268's shape, where four bytes buy a blit of a bitmap chosen in another PDU.
            Cmd::SolidFill(s, col, declared, rects) => {
                let mut b = Body::default().u16(*s).bytes(col).u16(*declared);
                for r in rects {
                    b = b.rect(*r);
                }
                b.header(egfx::CMDID_SOLID_FILL)
            }
            Cmd::SurfaceToSurface(src, dst, r, declared, points) => {
                let mut b = Body::default().u16(*src).u16(*dst).rect(*r).u16(*declared);
                for (x, y) in points {
                    b = b.u16(*x).u16(*y);
                }
                b.header(egfx::CMDID_SURFACE_TO_SURFACE)
            }
            Cmd::SurfaceToCache(s, lo, hi, slot, r) => Body::default()
                .u16(*s)
                .u32(*lo)
                .u32(*hi)
                .u16(*slot)
                .rect(*r)
                .header(egfx::CMDID_SURFACE_TO_CACHE),
            Cmd::CacheToSurface(slot, s, declared, points) => {
                let mut b = Body::default().u16(*slot).u16(*s).u16(*declared);
                for (x, y) in points {
                    b = b.u16(*x).u16(*y);
                }
                b.header(egfx::CMDID_CACHE_TO_SURFACE)
            }
            Cmd::EvictCacheEntry(slot) => Body::default()
                .u16(*slot)
                .header(egfx::CMDID_EVICT_CACHE_ENTRY),
            Cmd::Raw(id, body) => Body::default().bytes(body).header(*id),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// Prepend a valid surface + mapping + filled cache slot. See the module docs: without it
    /// the stateful arms are reachable only by coincidence, and a measured mutation stayed
    /// green because of it.
    bootstrap: bool,
    /// One `Vec<Cmd>` per `process` call — the manager's message boundary, and where state an
    /// earlier message established gets spent.
    messages: Vec<Vec<Cmd>>,
}

fn bootstrap() -> Vec<u8> {
    let mut blob = Vec::new();
    for c in [
        Cmd::CreateSurface(1, 64, 64, egfx::PIXEL_FORMAT_XRGB_8888),
        Cmd::MapSurfaceToOutput(1, 0, 0),
        Cmd::SurfaceToCache(1, 0, 0, 2, (0, 0, 32, 32)),
    ] {
        blob.extend_from_slice(&c.encode());
    }
    blob
}

fuzz_target!(|input: Input| {
    let mut p = GraphicsProcessor::default();
    // The framebuffer the session machine owns; `flush_frames` blits straight into it (#163).
    let Ok(mut fb) = Framebuffer::new(1280, 800) else {
        return;
    };

    if input.bootstrap {
        let _ = p.process(&egfx::wrap_uncompressed(&bootstrap()));
    }

    for message in &input.messages {
        let mut blob = Vec::new();
        for c in message {
            blob.extend_from_slice(&c.encode());
        }
        // `flush_frames` **only** on an `Ok`: `Drdynvc::on_svc_payload` propagates a processor
        // error with `?` and `session.rs`'s flush sits after it, so flushing a payload whose
        // `process` failed is a sequence the live path cannot produce. Two server-controlled
        // `u32`s — a `MapSurfaceToOutput` origin, narrowed to `u16` in `blit_dirty` — are
        // reachable only through the second call.
        if p.process(&egfx::wrap_uncompressed(&blob)).is_ok() {
            let _ = p.flush_frames(&mut fb);
        }
    }
});
