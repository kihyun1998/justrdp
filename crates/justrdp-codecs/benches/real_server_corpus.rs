//! Each owned codec timed over the real-server corpus in `tests/fixtures/` (#555), one criterion
//! group per codec and one captured session per iteration, replayed in arrival order through a
//! fresh decoder. Throughput is the corpus's input bytes. How to compare a change against master is
//! `docs/agents/thegraph.md` § *Proof of a performance claim*.

use std::hint::black_box;
use std::path::PathBuf;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use justrdp_codecs::adpcm::{ImaAdpcm, MsAdpcm};
use justrdp_codecs::clearcodec::ClearDecoder;
use justrdp_codecs::color::Palette;
use justrdp_codecs::mppc::{Mppc, MppcLevel};
use justrdp_codecs::ncrush::Ncrush;
use justrdp_codecs::rfx::RemoteFx;
use justrdp_codecs::rfx::progressive::Progressive;
use justrdp_codecs::xcrush::Xcrush;
use justrdp_codecs::zgfx::Zgfx;
use justrdp_codecs::{g711, nscodec, pcm, planar, pointer, rle};

fn fixture(path: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// One record of the #554 container: three codec-defined fields and the payload.
struct Record {
    a: u16,
    b: u16,
    c: u16,
    payload: Vec<u8>,
}

fn records(path: &str) -> Vec<Record> {
    let buf = fixture(path);
    let u16_at = |at: usize| u16::from_le_bytes(buf[at..at + 2].try_into().unwrap());
    let u32_at = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
    let mut at = 4;
    (0..u32_at(0))
        .map(|_| {
            let len = u32_at(at + 6);
            let record = Record {
                a: u16_at(at),
                b: u16_at(at + 2),
                c: u16_at(at + 4),
                payload: buf[at + 10..at + 10 + len].to_vec(),
            };
            at += 10 + len;
            record
        })
        .collect()
}

fn input_bytes(records: &[Record]) -> u64 {
    records.iter().map(|r| r.payload.len() as u64).sum()
}

/// Time `replay` over `records` as one group named `name`, with a fresh `state` per iteration.
fn session<S>(
    c: &mut Criterion,
    name: &str,
    records: &[Record],
    state: impl Fn() -> S,
    replay: impl Fn(&mut S, &Record),
) {
    let mut group = c.benchmark_group(name);
    group.throughput(Throughput::Bytes(input_bytes(records)));
    group.bench_function("session", |b| {
        b.iter_batched_ref(
            &state,
            |s| {
                for r in records {
                    replay(s, black_box(r));
                }
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn graphics(c: &mut Criterion) {
    session(
        c,
        "nscodec",
        &records("nscodec/ws2019-surface-bits.bin"),
        || (),
        |_, r| {
            black_box(nscodec::decode(&r.payload, r.a, r.b).unwrap());
        },
    );
    session(
        c,
        "planar",
        &records("planar/ws2019-32bpp.bin"),
        || (),
        |_, r| {
            black_box(planar::decompress(&r.payload, r.a.into(), r.b.into()).unwrap());
        },
    );
    for corpus in ["ws2019-memblt-16bpp", "ws2008r2-15bpp", "ws2008r2-8bpp"] {
        let name = format!("rle/{corpus}");
        session(
            c,
            &name,
            &records(&format!("rle/{corpus}.bin")),
            || (),
            |_, r| {
                black_box(rle::decompress(&r.payload, r.a.into(), r.b.into(), r.c).unwrap());
            },
        );
    }
    let shapes: Vec<Record> = ["pointer/ws2019.bin", "pointer/ws2008r2.bin"]
        .into_iter()
        .flat_map(records)
        .collect();
    session(
        c,
        "pointer",
        &shapes,
        || (),
        |_, r| {
            let xor_len = u32::from_le_bytes(r.payload[..4].try_into().unwrap()) as usize;
            let (xor, and) = r.payload[4..].split_at(xor_len);
            black_box(
                pointer::decode_pointer(r.a, r.b, r.c, xor, and, &Palette::default()).unwrap(),
            );
        },
    );
    session(
        c,
        "remotefx",
        &records("remotefx/ws2019-thin-client.bin"),
        RemoteFx::new,
        |d, r| {
            black_box(d.decode_to_rgba(&r.payload, r.a, r.b).unwrap());
        },
    );
    session(
        c,
        "clearcodec",
        &clearcodec_records(),
        ClearDecoder::new,
        |d, r| {
            black_box(d.decode(&r.payload, r.a, r.b).unwrap());
        },
    );
    session(
        c,
        "progressive",
        &progressive_records(),
        Progressive::new,
        |d, r| {
            d.decode(0, r.a, r.b, &r.payload, |rect| {
                black_box(rect);
            })
            .unwrap();
        },
    );
}

fn bulk(c: &mut Criterion) {
    session(c, "zgfx", &records("zgfx/ws2019.bin"), Zgfx::new, |d, r| {
        black_box(d.decompress(&r.payload).unwrap());
    });
    let level = || Mppc::new(MppcLevel::Rdp5);
    session(c, "mppc", &records("mppc/ws2019-64k.bin"), level, |d, r| {
        black_box(d.decompress(&r.payload, r.a as u8).unwrap());
    });
    session(
        c,
        "ncrush",
        &records("ncrush/ws2019.bin"),
        Box::<Ncrush>::default,
        |d, r| {
            black_box(d.decompress(&r.payload, r.a as u8).unwrap());
        },
    );
    session(
        c,
        "xcrush",
        &records("xcrush/ws2019.bin"),
        Box::<Xcrush>::default,
        |d, r| {
            black_box(d.decompress(&r.payload, r.a as u8).unwrap());
        },
    );
}

fn audio(c: &mut Criterion) {
    session(
        c,
        "pcm",
        &records("pcm/ws2019-16bit-stereo.bin"),
        || (),
        |_, r| {
            black_box(pcm::decode(r.a, &r.payload).unwrap());
        },
    );
    session(
        c,
        "g711_alaw",
        &records("g711/ws2019-alaw-stereo.bin"),
        || (),
        |_, r| {
            black_box(g711::decode_alaw(&r.payload));
        },
    );
    let blocks = |prefix: &str| -> Vec<Record> {
        (0..3)
            .map(|n| Record {
                a: 0,
                b: 0,
                c: 0,
                payload: fixture(&format!("adpcm/{prefix}_mono_vm_{n}.adpcm")),
            })
            .collect()
    };
    let ms_extra = fixture("adpcm/ms_mono_vm.extra");
    let ms = MsAdpcm::new(1, 1024, &ms_extra).unwrap();
    session(
        c,
        "adpcm_ms",
        &blocks("ms"),
        || (),
        |_, r| {
            black_box(ms.decode(&r.payload).unwrap());
        },
    );
    let ima_extra = fixture("adpcm/ima_mono_vm.extra");
    let ima = ImaAdpcm::new(1, 1024, &ima_extra).unwrap();
    session(
        c,
        "adpcm_ima",
        &blocks("ima"),
        || (),
        |_, r| {
            black_box(ima.decode(&r.payload).unwrap());
        },
    );
}

/// `clearcodec/replay.bin`: `u32 count`, then per stream `u16 width, u16 height, u32 len, payload`.
fn clearcodec_records() -> Vec<Record> {
    let buf = fixture("clearcodec/replay.bin");
    let mut at = 4;
    (0..u32::from_le_bytes(buf[..4].try_into().unwrap()))
        .map(|_| {
            let field = |o: usize| u16::from_le_bytes(buf[at + o..at + o + 2].try_into().unwrap());
            let len = u32::from_le_bytes(buf[at + 4..at + 8].try_into().unwrap()) as usize;
            let record = Record {
                a: field(0),
                b: field(2),
                c: 0,
                payload: buf[at + 8..at + 8 + len].to_vec(),
            };
            at += 8 + len;
            record
        })
        .collect()
}

/// `progressive/replay.bin`: `u32 count`, then per payload `u32 codec_context_id, u16 width,
/// u16 height, u32 len, payload`. The context id is dropped: the decoder keys tiles by surface.
fn progressive_records() -> Vec<Record> {
    let buf = fixture("progressive/replay.bin");
    let mut at = 4;
    (0..u32::from_le_bytes(buf[..4].try_into().unwrap()))
        .map(|_| {
            let field = |o: usize| u16::from_le_bytes(buf[at + o..at + o + 2].try_into().unwrap());
            let len = u32::from_le_bytes(buf[at + 8..at + 12].try_into().unwrap()) as usize;
            let record = Record {
                a: field(4),
                b: field(6),
                c: 0,
                payload: buf[at + 12..at + 12 + len].to_vec(),
            };
            at += 12 + len;
            record
        })
        .collect()
}

criterion_group!(codecs, graphics, bulk, audio);
criterion_main!(codecs);
