//! What a real server sends in drawing orders over a Revision 2 bitmap cache, replayed through the
//! session machine.
//!
//! A capture proves **acceptance**: every Cache Bitmap (Revision 2) and MemBlt this server sent
//! decodes and paints, and the desktop is the one the live session drew. It cannot prove the
//! decoder refuses what it should, nor anything about orders this server never sent; the unit
//! tests in `justrdp-pdu`'s `orders.rs` and `justrdp`'s `orders.rs` hold those.

use justrdp::{SessionConfig, SessionOutput, SessionStateMachine};
use justrdp_pdu::capability::{self, CapabilitySet};
use justrdp_pdu::{fastpath, gcc};

const MEMBLT: &[u8] = include_bytes!("fixtures/session/memblt.bin");

/// The session the capture was taken in: a 1280×800 desktop at 16 bpp, the default capability
/// sets without Surface Commands or Bitmap Codecs, MemBlt and Mem3Blt over a Revision 2 cache
/// of 120, 120 and 2553 entries.
fn machine() -> SessionStateMachine {
    let core = gcc::ClientCoreData {
        desktop_width: 1280,
        desktop_height: 800,
        ..Default::default()
    };
    let mut capabilities = capability::default_client_capabilities(&core);
    capabilities.retain(|set| {
        !matches!(
            set,
            CapabilitySet::SurfaceCommands(_)
                | CapabilitySet::BitmapCodecs(_)
                | CapabilitySet::BitmapCache(_)
        )
    });
    for set in &mut capabilities {
        match set {
            CapabilitySet::Order(o) => {
                o.order_support[capability::ORDER_NEG_MEMBLT_INDEX] = 1;
                o.order_support[capability::ORDER_NEG_MEM3BLT_INDEX] = 1;
            }
            CapabilitySet::Bitmap(b) => b.preferred_bits_per_pixel = 16,
            _ => {}
        }
    }
    capabilities.push(CapabilitySet::BitmapCacheRev2(
        capability::BitmapCacheRev2CapabilitySet {
            cache_flags: 0,
            cells: [120, 120, 2553]
                .map(|entries| capability::BitmapCacheCellInfo {
                    entries,
                    persistent: false,
                })
                .to_vec(),
        },
    ));
    SessionStateMachine::new(
        SessionConfig {
            user_channel_id: 1007,
            io_channel_id: 1003,
            share_id: 0x0001_03EA,
            desktop_size: (1280, 800),
            capabilities,
            server: justrdp::ServerAnnouncement {
                input_flags: capability::INPUT_FLAG_SCANCODES,
                bits_per_pixel: 16,
                ..Default::default()
            },
            drdynvc_channel_id: None,
            static_channels: Vec::new(),
            dynamic_channels: Vec::new(),
            egfx: Default::default(),
        },
        Vec::new(),
    )
    .expect("1280x800 is within MAX_DESKTOP_DIM")
}

/// FNV-1a over the framebuffer's RGB bytes, the form of the live session's PPM dump.
fn fnv1a_rgb(rgba: &[u8]) -> u64 {
    rgba.as_chunks::<4>()
        .0
        .iter()
        .flat_map(|px| &px[..3])
        .fold(0xcbf2_9ce4_8422_2325, |hash, &b| {
            (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

/// Issue #460. One logon's desktop, captured 2026-10-15 from the WS2019 VM.
#[test]
fn a_real_desktop_painted_in_memblt_orders_replays() {
    let mut sm = machine();
    let mut rest = MEMBLT;
    let mut updates = std::collections::BTreeMap::<u8, usize>::new();
    let mut frames = 0usize;
    while !rest.is_empty() {
        let len = fastpath::frame_len(rest).expect("a complete fast-path PDU");
        let (pdu, tail) = rest.split_at(len);
        rest = tail;
        for update in fastpath::decode_updates(pdu).expect("a fast-path PDU") {
            *updates.entry(update.code).or_default() += 1;
        }
        frames += sm
            .process_bytes(pdu)
            .expect("every order this server sent decodes")
            .iter()
            .filter(|output| matches!(output, SessionOutput::Frame(_)))
            .count();
    }
    // Orders, the default pointer, and one new pointer.
    assert_eq!(
        updates.into_iter().collect::<Vec<_>>(),
        [
            (fastpath::FP_UPDATE_ORDERS, 39),
            (fastpath::FP_UPDATE_PTR_DEFAULT, 132),
            (fastpath::FP_UPDATE_NEW_POINTER, 1),
        ]
    );
    assert_eq!(
        frames, 1495,
        "one frame per MemBlt the live session painted"
    );
    assert_eq!(
        fnv1a_rgb(sm.framebuffer().pixels()),
        0x8458_7863_67b7_eacf,
        "the live session's framebuffer, as dumped and looked at when the fixture was taken"
    );
}
