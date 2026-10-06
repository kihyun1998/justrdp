#![no_main]
//! Fuzz the session's Surface Bits path (#369): one fast-path Surface Commands update through
//! `SessionStateMachine::process_bytes`, so the NSCodec and raw decodes and the blit are reached.
//! Sibling of `session`'s `surface_bits_through_the_session_never_panic` proptest.
//!
//! The input is read as commands of an 8-byte head `[x, y, w, h, codec, cll, subsampled, fill]`
//! followed, for NSCodec, by a plane-count selector byte: even means the planes' decoded sizes
//! (copied raw), odd means four counts taken from the next 16 bytes. A 64x48 desktop keeps every
//! case cheap.

use justrdp::{SessionConfig, SessionStateMachine};
use justrdp_codecs::nscodec;
use justrdp_pdu::{capability, fastpath, gcc};
use libfuzzer_sys::fuzz_target;

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = data.split_at_checked(n)?;
    *data = rest;
    Some(head)
}

fuzz_target!(|input: &[u8]| {
    let mut data = input;
    let mut commands = Vec::new();
    while let Some(head) = take(&mut data, 8) {
        let (x, y) = (u16::from(head[0] % 80), u16::from(head[1] % 60));
        let (w, h) = (u16::from(head[2] % 72) + 1, u16::from(head[3] % 56) + 1);
        let codec_id = match head[4] % 9 {
            0..=5 => capability::CODEC_ID_NSCODEC,
            6 | 7 => 0,
            _ => head[4],
        };
        let (cll, subsampled, fill) = (head[5] % 7 + 1, head[6] & 1 == 1, head[7]);
        let bitmap = if codec_id == capability::CODEC_ID_NSCODEC {
            let Ok(sizes) = nscodec::plane_sizes(w.into(), h.into(), subsampled) else {
                continue;
            };
            let mut counts = sizes.map(|n| n as u32);
            if take(&mut data, 1).is_some_and(|s| s[0] & 1 == 1) {
                if let Some(raw) = take(&mut data, 16) {
                    for (i, c) in counts.iter_mut().enumerate() {
                        *c = u32::from_le_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap()) % 8193;
                    }
                }
            }
            let mut nsc = Vec::new();
            for c in counts {
                nsc.extend_from_slice(&c.to_le_bytes());
            }
            nsc.extend_from_slice(&[cll, u8::from(subsampled), 0, 0]);
            let planes: u32 = counts.iter().sum();
            nsc.extend(std::iter::repeat_n(fill, planes.min(65_536) as usize));
            nsc
        } else {
            vec![fill; usize::from(w) * usize::from(h) * 4]
        };
        let mut body = 1u16.to_le_bytes().to_vec(); // CMDTYPE_SET_SURFACE_BITS
        for v in [x, y, x + w, y + h] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&[32, 0, 0, codec_id]);
        body.extend_from_slice(&w.to_le_bytes());
        body.extend_from_slice(&h.to_le_bytes());
        body.extend_from_slice(&(bitmap.len() as u32).to_le_bytes());
        body.extend_from_slice(&bitmap);
        commands.push(body);
    }
    let core = gcc::ClientCoreData {
        desktop_width: 64,
        desktop_height: 48,
        ..Default::default()
    };
    let Ok(mut sm) = SessionStateMachine::new(
        SessionConfig {
            user_channel_id: 1007,
            io_channel_id: 1003,
            share_id: 1,
            desktop_size: (64, 48),
            capabilities: capability::default_client_capabilities(&core),
            server_input_flags: capability::INPUT_FLAG_SCANCODES,
            drdynvc_channel_id: None,
            static_channels: Vec::new(),
            dynamic_channels: Vec::new(),
            egfx: Default::default(),
        },
        Vec::new(),
    ) else {
        return;
    };
    // One update per command, each within a single fast-path PDU.
    for body in commands.iter().filter(|b| b.len() <= 32_000) {
        let _ = sm.process_bytes(&fastpath::encode_pdu(&[(
            fastpath::FP_UPDATE_SURFCMDS,
            fastpath::FP_FRAGMENT_SINGLE,
            body,
        )]));
    }
});
