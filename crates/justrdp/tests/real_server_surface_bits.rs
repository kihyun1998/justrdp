//! What a real server paints with NSCodec Set Surface Bits, replayed through the session machine.
//!
//! A capture proves **acceptance**: every Surface Commands update this server sent decodes, and
//! the desktop it paints is the one the server drew. It cannot prove the decoder rejects what it
//! should; the unit tests in `session.rs`, `surface_commands.rs` and `nscodec.rs` hold that half.

use justrdp::{SessionConfig, SessionOutput, SessionStateMachine};
use justrdp_pdu::{capability, fastpath, gcc};

const NSCODEC_SURFACE_BITS: &[u8] = include_bytes!("fixtures/session/nscodec-surface-bits.bin");

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
            server_input_flags: capability::INPUT_FLAG_SCANCODES,
            drdynvc_channel_id: None,
            static_channels: Vec::new(),
            egfx: Default::default(),
        },
        Vec::new(),
    )
    .expect("1280x800 is within MAX_DESKTOP_DIM")
}

/// FNV-1a over the framebuffer.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Issue #150. One logon's desktop, captured 2026-10-01 from the WS2022 VM with its colour depth
/// policy at 32 bpp.
#[test]
fn a_real_desktop_painted_in_nscodec_surface_bits_replays() {
    let mut sm = machine();
    let (mut rest, mut pdus, mut surface_updates, mut frames) = (NSCODEC_SURFACE_BITS, 0, 0, 0u64);
    let mut covered = 0u64;
    while !rest.is_empty() {
        let len = fastpath::frame_len(rest).expect("a complete fast-path PDU");
        let (pdu, tail) = rest.split_at(len);
        rest = tail;
        pdus += 1;
        surface_updates += fastpath::decode_updates(pdu)
            .expect("a fast-path PDU")
            .iter()
            .filter(|update| update.code == fastpath::FP_UPDATE_SURFCMDS)
            .count();
        for output in sm
            .process_bytes(pdu)
            .expect("every update this server sent decodes")
        {
            if let SessionOutput::Frame(frame) = output {
                frames += 1;
                covered += u64::from(frame.width) * u64::from(frame.height);
            }
        }
    }
    assert_eq!((pdus, surface_updates), (162, 26));
    assert_eq!(frames, 1432, "one FrameUpdate per Set Surface Bits command");
    assert!(
        covered >= 1280 * 800,
        "the whole desktop is painted: {covered}"
    );
    assert_eq!(
        fnv1a(sm.framebuffer().pixels()),
        0x15ce_6ef3_22bc_070d,
        "the desktop as it was rendered and looked at when the fixture was taken"
    );
}
