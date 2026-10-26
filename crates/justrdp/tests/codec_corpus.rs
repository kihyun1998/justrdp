//! The codec-level corpora in `justrdp-codecs/tests/fixtures/` (#554), carved from server-to-client
//! session captures by walking them with `justrdp-pdu`'s parsers.
//!
//! A carved file holds what one codec was handed during one captured session, in arrival order,
//! so the codecs crate can replay it without the session machine above it. Each record is
//! `u16 a, u16 b, u16 c, u32 len, payload[len]`, little-endian after a `u32` count; what `a`,
//! `b` and `c` mean is the codec's, and each corpus README states it.
//!
//! The corpora carved from this crate's own `tests/fixtures/session/` captures are checked here
//! against a fresh carve. `JUSTRDP_BLESS_CODEC_CORPUS=1` writes them instead. A capture that is not
//! committed is carved once by [`carve_a_session_capture`].

use std::collections::HashMap;

use justrdp_codecs::mppc::{self, Mppc, MppcLevel};
use justrdp_codecs::ncrush::Ncrush;
use justrdp_codecs::xcrush::Xcrush;
use justrdp_codecs::zgfx::Zgfx;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::dvc::DvcMessage;
use justrdp_pdu::pointer::PointerUpdate;
use justrdp_pdu::{
    capability, egfx, fastpath, mcs, orders, surface_commands, svc, tpkt, update, x224,
};

/// One carved codec input: three codec-defined fields and the bytes the codec was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    a: u16,
    b: u16,
    c: u16,
    payload: Vec<u8>,
}

/// Every codec input one capture holds, per codec, in arrival order.
#[derive(Debug, Default)]
struct Carved {
    /// NSCodec Set Surface Bits: `(width, height, 0)`.
    nscodec: Vec<Record>,
    /// RDP6 planar bitmap rectangles: `(width, height, 32)`.
    planar: Vec<Record>,
    /// Interleaved RLE bitmap rectangles and cache fills: `(width, height, bpp)`.
    rle: Vec<Record>,
    /// Bulk-compressed fast-path update sections: `(compressionFlags, 0, 0)`.
    bulk: Vec<Record>,
    /// Pointer shapes: `(width, height, xorBpp)`, payload `u32 xor_len, xor, and`.
    pointer: Vec<Record>,
    /// Graphics channel messages as the zgfx decompressor receives them: `(0, 0, 0)`.
    zgfx: Vec<Record>,
    /// WireToSurface1 RemoteFX payloads: `(width, height, 0)`.
    remotefx: Vec<Record>,
}

/// The server-to-client bulk decompression context, keyed on the type nibble the way
/// `justrdp::bulk` keys it.
#[derive(Default)]
struct Bulk {
    mppc: Option<Mppc>,
    ncrush: Option<Box<Ncrush>>,
    xcrush: Option<Box<Xcrush>>,
}

impl Bulk {
    fn decompress(&mut self, src: &[u8], flags: u8) -> Vec<u8> {
        if flags & mppc::PACKET_COMPRESSED == 0 {
            assert_eq!(
                flags & 0xE0,
                0,
                "a flag-only section: the carve does not model one"
            );
            return src.to_vec();
        }
        match flags & 0x0F {
            ty @ (0 | 1) => {
                let level = if ty == 0 {
                    MppcLevel::Rdp4
                } else {
                    MppcLevel::Rdp5
                };
                let mppc = self.mppc.get_or_insert_with(|| Mppc::new(level));
                mppc.decompress(src, flags).expect("MPPC").to_vec()
            }
            2 => self
                .ncrush
                .get_or_insert_default()
                .decompress(src, flags)
                .expect("NCRUSH")
                .to_vec(),
            _ => self
                .xcrush
                .get_or_insert_default()
                .decompress(src, flags)
                .expect("XCRUSH")
                .to_vec(),
        }
    }
}

/// Walk a session capture: fast-path PDUs and the TPKT frames carrying the dynamic channels.
fn carve(mut wire: &[u8]) -> Carved {
    let mut carved = Carved::default();
    let mut bulk = Bulk::default();
    let mut fragment: Option<(u8, Vec<u8>)> = None;
    let mut history = orders::OrderHistory::default();
    let mut chunks = HashMap::<u16, Vec<u8>>::new();
    let mut graphics = None::<u32>;
    let mut dvc = HashMap::<u32, (usize, Vec<u8>)>::new();
    let mut zgfx = Zgfx::new();
    while !wire.is_empty() {
        if !fastpath::is_fastpath(wire[0]) {
            let len = tpkt::frame_len(wire).expect("a whole TPKT frame");
            let (frame, rest) = wire.split_at(len);
            wire = rest;
            let tpdu = x224::decode_data(&frame[tpkt::HEADER_LEN..]).expect("an X.224 data TPDU");
            let Ok(sdi) = mcs::SendDataIndication::decode(tpdu) else {
                continue;
            };
            if sdi.channel_id == mcs::IO_CHANNEL_ID {
                continue;
            }
            let chunk = svc::ChannelChunk::decode(sdi.user_data).expect("a channel chunk");
            let message = chunks.entry(sdi.channel_id).or_default();
            if chunk.flags & svc::CHANNEL_FLAG_FIRST != 0 {
                message.clear();
            }
            message.extend_from_slice(chunk.data);
            if chunk.flags & svc::CHANNEL_FLAG_LAST == 0 {
                continue;
            }
            let message = std::mem::take(message);
            let complete = match DvcMessage::decode(&message) {
                Ok(DvcMessage::CreateRequest {
                    channel_id,
                    name: "Microsoft::Windows::RDS::Graphics",
                }) => {
                    graphics = Some(channel_id);
                    None
                }
                Ok(DvcMessage::DataFirst {
                    channel_id,
                    total_length,
                    data,
                }) if Some(channel_id) == graphics => {
                    let (want, buffer) = dvc.entry(channel_id).or_default();
                    *want = total_length as usize;
                    buffer.clear();
                    buffer.extend_from_slice(data);
                    (buffer.len() == *want).then(|| std::mem::take(buffer))
                }
                Ok(DvcMessage::Data { channel_id, data }) if Some(channel_id) == graphics => {
                    let (want, buffer) = dvc.entry(channel_id).or_default();
                    if buffer.is_empty() {
                        Some(data.to_vec())
                    } else {
                        buffer.extend_from_slice(data);
                        (buffer.len() == *want).then(|| std::mem::take(buffer))
                    }
                }
                _ => None,
            };
            if let Some(message) = complete {
                let blob = zgfx.decompress(&message).expect("zgfx");
                carved.zgfx.push(Record {
                    a: 0,
                    b: 0,
                    c: 0,
                    payload: message,
                });
                for pdu in egfx::decode_all(&blob).expect("EGFX PDUs") {
                    if let egfx::EgfxPdu::WireToSurface1 {
                        codec_id,
                        dest_rect,
                        data,
                        ..
                    } = pdu
                    {
                        let record = Record {
                            a: dest_rect.width(),
                            b: dest_rect.height(),
                            c: 0,
                            payload: data.to_vec(),
                        };
                        match codec_id {
                            egfx::CODECID_CAVIDEO => carved.remotefx.push(record),
                            egfx::CODECID_PLANAR => carved.planar.push(Record { c: 32, ..record }),
                            _ => {}
                        }
                    }
                }
            }
            continue;
        }

        let len = fastpath::frame_len(wire).expect("a whole fast-path PDU");
        let (pdu, rest) = wire.split_at(len);
        wire = rest;
        for section in fastpath::decode_updates(pdu).expect("fast-path update sections") {
            if section.compression_flags != 0 {
                carved.bulk.push(Record {
                    a: u16::from(section.compression_flags),
                    b: 0,
                    c: 0,
                    payload: section.data.to_vec(),
                });
            }
            let data = bulk.decompress(section.data, section.compression_flags);
            let complete = match section.fragmentation {
                fastpath::FP_FRAGMENT_SINGLE => Some((section.code, data)),
                fastpath::FP_FRAGMENT_FIRST => {
                    fragment = Some((section.code, data));
                    None
                }
                fragmentation => {
                    let (_, buffer) = fragment.as_mut().expect("a first fragment");
                    buffer.extend_from_slice(&data);
                    if fragmentation == fastpath::FP_FRAGMENT_LAST {
                        fragment.take()
                    } else {
                        None
                    }
                }
            };
            let Some((code, data)) = complete else {
                continue;
            };
            let mut cur = ReadCursor::new(&data, "fast-path update body");
            match code {
                fastpath::FP_UPDATE_BITMAP => {
                    cur.read_u16_le().expect("updateType");
                    let bitmap = update::BitmapUpdate::decode(&mut cur).expect("a bitmap update");
                    for rect in bitmap.rectangles.into_iter().filter(|r| r.compressed) {
                        let record = Record {
                            a: rect.width,
                            b: rect.height,
                            c: rect.bits_per_pixel,
                            payload: rect.data,
                        };
                        if rect.bits_per_pixel == 32 {
                            carved.planar.push(record);
                        } else {
                            carved.rle.push(record);
                        }
                    }
                }
                fastpath::FP_UPDATE_SURFCMDS => {
                    for command in surface_commands::decode_all(&data).expect("surface commands") {
                        if let surface_commands::SurfaceCommand::SurfaceBits(bits) = command
                            && bits.bitmap.codec_id == capability::CODEC_ID_NSCODEC
                        {
                            carved.nscodec.push(Record {
                                a: bits.bitmap.width,
                                b: bits.bitmap.height,
                                c: 0,
                                payload: bits.bitmap.data.to_vec(),
                            });
                        }
                    }
                }
                fastpath::FP_UPDATE_COLOR_POINTER | fastpath::FP_UPDATE_NEW_POINTER => {
                    let (xor_bpp, shape) =
                        match PointerUpdate::decode_fastpath(code, &mut cur).expect("a pointer") {
                            PointerUpdate::Color(shape) => (24, shape),
                            PointerUpdate::New { xor_bpp, color } => (xor_bpp, color),
                            _ => continue,
                        };
                    let mut payload = (shape.xor_mask.len() as u32).to_le_bytes().to_vec();
                    payload.extend_from_slice(&shape.xor_mask);
                    payload.extend_from_slice(&shape.and_mask);
                    carved.pointer.push(Record {
                        a: shape.width,
                        b: shape.height,
                        c: xor_bpp,
                        payload,
                    });
                }
                fastpath::FP_UPDATE_ORDERS => {
                    let update = orders::OrdersUpdate::decode_fast_path(&mut cur).expect("orders");
                    let mut orders_cur = ReadCursor::new(update.order_data, "orders");
                    for _ in 0..update.number_orders {
                        let order = orders::decode_order(&mut orders_cur, &mut history)
                            .expect("a drawing order");
                        if let orders::DrawingOrder::CacheBitmapRev2(fill) = order
                            && fill.compressed
                        {
                            carved.rle.push(Record {
                                a: fill.width,
                                b: fill.height,
                                c: fill.bits_per_pixel,
                                payload: fill.data.to_vec(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }
    carved
}

/// The corpus file format the codecs crate's `real_server_corpus.rs` reads.
fn encode(records: &[Record]) -> Vec<u8> {
    let mut out = (records.len() as u32).to_le_bytes().to_vec();
    for record in records {
        for field in [record.a, record.b, record.c] {
            out.extend_from_slice(&field.to_le_bytes());
        }
        out.extend_from_slice(&(record.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&record.payload);
    }
    out
}

fn codecs_fixture(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../justrdp-codecs/tests/fixtures")
        .join(path)
}

/// The committed corpus at `path` is `records`, or becomes it under `JUSTRDP_BLESS_CODEC_CORPUS`.
fn matches_or_bless(path: &str, records: &[Record]) {
    assert!(!records.is_empty(), "{path}: the capture carved to nothing");
    let carved = encode(records);
    let path = codecs_fixture(path);
    if std::env::var_os("JUSTRDP_BLESS_CODEC_CORPUS").is_some() {
        std::fs::write(&path, &carved).expect("write the corpus");
        return;
    }
    let committed = std::fs::read(&path).expect("the committed corpus");
    assert!(
        committed == carved,
        "{} differs from a fresh carve of its capture; regenerate it with \
         JUSTRDP_BLESS_CODEC_CORPUS=1",
        path.display()
    );
}

fn session_fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/session")
        .join(name);
    std::fs::read(path).expect("the session capture")
}

#[test]
fn the_nscodec_corpus_is_carved_from_the_surface_bits_capture() {
    let carved = carve(&session_fixture("nscodec-surface-bits.bin"));
    assert_eq!(carved.nscodec.len(), 1432);
    matches_or_bless("nscodec/ws2019-surface-bits.bin", &carved.nscodec);
}

#[test]
fn the_bulk_corpora_are_carved_from_the_compressed_captures() {
    for (capture, corpus, sections) in [
        ("mppc-64k.bin", "mppc/ws2019-64k.bin", 38),
        ("ncrush.bin", "ncrush/ws2019.bin", 33),
        ("xcrush.bin", "xcrush/ws2019.bin", 34),
    ] {
        let carved = carve(&session_fixture(capture));
        assert_eq!(carved.bulk.len(), sections, "{capture}");
        matches_or_bless(corpus, &carved.bulk);
    }
}

#[test]
fn the_rle_cache_fill_corpus_is_carved_from_the_memblt_capture() {
    let carved = carve(&session_fixture("memblt.bin"));
    assert_eq!(carved.rle.len(), 188);
    matches_or_bless("rle/ws2019-memblt-16bpp.bin", &carved.rle);
}

/// The longest run of `records` from the first whose encoding fits `max_bytes`.
fn prefix(records: &[Record], max_bytes: usize) -> &[Record] {
    let mut size = 4;
    let fits = records
        .iter()
        .take_while(|record| {
            size += 10 + record.payload.len();
            size <= max_bytes
        })
        .count();
    &records[..fits]
}

/// Carve an uncommitted capture into `JUSTRDP_CARVE_OUT`: the first `JUSTRDP_CARVE_LEN` bytes of
/// `JUSTRDP_CARVE_CAPTURE`, the length a `corpus_session` run printed before its sign-out
/// session appended to the same file. Each corpus keeps the records from the first that fit
/// `JUSTRDP_CARVE_MAX_BYTES`.
#[test]
#[ignore = "carves a capture named by JUSTRDP_CARVE_CAPTURE, JUSTRDP_CARVE_LEN, JUSTRDP_CARVE_MAX_BYTES and JUSTRDP_CARVE_OUT"]
fn carve_a_session_capture() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is set"));
    let wire = std::fs::read(var("JUSTRDP_CARVE_CAPTURE")).expect("the capture");
    let len: usize = var("JUSTRDP_CARVE_LEN").parse().expect("a byte count");
    let max_bytes: usize = var("JUSTRDP_CARVE_MAX_BYTES")
        .parse()
        .expect("a byte count");
    let out = std::path::PathBuf::from(var("JUSTRDP_CARVE_OUT"));
    let carved = carve(&wire[..len]);
    for (name, records) in [
        ("nscodec", &carved.nscodec),
        ("planar", &carved.planar),
        ("rle", &carved.rle),
        ("bulk", &carved.bulk),
        ("pointer", &carved.pointer),
        ("zgfx", &carved.zgfx),
        ("remotefx", &carved.remotefx),
    ] {
        let kept = prefix(records, max_bytes);
        let bytes = encode(kept);
        eprintln!(
            "{name}: {} of {} records, {} bytes",
            kept.len(),
            records.len(),
            bytes.len()
        );
        if !kept.is_empty() {
            std::fs::write(out.join(format!("{name}.bin")), bytes).expect("write the carve");
        }
    }
}
