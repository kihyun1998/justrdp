//! What a real server sends under MPPC 64K bulk compression, replayed through the session machine.
//!
//! A capture proves **acceptance**: every compressed update this server sent decompresses against
//! the shared history and the desktop it paints is the one the live session drew. It cannot prove
//! the decompressor rejects what it should; the unit tests in `mppc.rs`, `bulk.rs` and
//! `session.rs` hold that half.

use justrdp::{SessionConfig, SessionOutput, SessionStateMachine};
use justrdp_pdu::{capability, fastpath, gcc};

const MPPC_64K: &[u8] = include_bytes!("fixtures/session/mppc-64k.bin");

/// The session the capture was taken in: a 1280×800 desktop, the default capability sets.
fn machine() -> SessionStateMachine {
    let core = gcc::ClientCoreData {
        desktop_width: 1280,
        desktop_height: 800,
        ..Default::default()
    };
    SessionStateMachine::new(
        SessionConfig {
            user_channel_id: 1007,
            io_channel_id: 1003,
            share_id: 0x0001_03EA,
            desktop_size: (1280, 800),
            capabilities: capability::default_client_capabilities(&core),
            server: justrdp::ServerAnnouncement {
                input_flags: capability::INPUT_FLAG_SCANCODES,
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

/// Issue #454. One logon's desktop, captured 2026-10-15 from the WS2019 VM advertising MPPC 64K.
#[test]
fn a_real_desktop_sent_mppc_compressed_replays() {
    let mut sm = machine();
    let mut rest = MPPC_64K;
    let mut flags = std::collections::BTreeMap::<u8, usize>::new();
    let mut covered = 0u64;
    while !rest.is_empty() {
        let len = fastpath::frame_len(rest).expect("a complete fast-path PDU");
        let (pdu, tail) = rest.split_at(len);
        rest = tail;
        for update in fastpath::decode_updates(pdu).expect("a fast-path PDU") {
            *flags.entry(update.compression_flags).or_default() += 1;
        }
        for output in {
            let mut outputs = sm
                .process_bytes(pdu)
                .expect("every update this server sent decompresses and decodes");
            while sm.has_pending_input() {
                outputs.extend(
                    sm.process_bytes(&[])
                        .expect("every update this server sent decompresses and decodes"),
                );
            }
            outputs
        } {
            if let SessionOutput::Frame(frame) = output {
                covered += u64::from(frame.width) * u64::from(frame.height);
            }
        }
    }
    // Uncompressed, PACKET_COMPRESSED | 64K, and PACKET_AT_FRONT on top.
    assert_eq!(
        flags.into_iter().collect::<Vec<_>>(),
        [(0x00, 139), (0x21, 33), (0x61, 5)]
    );
    assert!(
        covered >= 1280 * 800,
        "the whole desktop is painted: {covered}"
    );
    assert_eq!(
        fnv1a_rgb(sm.framebuffer().pixels()),
        0x1669_5233_9ba8_f838,
        "the live session's framebuffer, as dumped and looked at when the fixture was taken"
    );
}
