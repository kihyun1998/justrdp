#![no_main]
//! Fuzz the session's drawing-order path (#460, #461, #462, #475): fast-path Orders Updates
//! through `SessionStateMachine::process_bytes` with DstBlt, PatBlt (and so OpaqueRect), ScrBlt,
//! MemBlt and Mem3Blt advertised over Revision 2 caches, so the cache fills, the ROPs, the fills,
//! the blits, the copies within the framebuffer and the frames Frame Markers hold are reached. Sibling of `orders`'s `orders_never_panic` proptest.
//!
//! The input is split on its first byte: that many updates of equal share, each prefixed by a
//! cache fill of a 4x4 bitmap into cache 0 entry 0 so a MemBlt has something to hit. A 64x48
//! desktop keeps every case cheap.

use justrdp::{SessionConfig, SessionStateMachine};
use justrdp_pdu::capability::{self, CapabilitySet};
use justrdp_pdu::{fastpath, gcc};
use libfuzzer_sys::fuzz_target;

/// A Cache Bitmap (Revision 2) of a 4x4 16-bpp bitmap into cache 0, entry 0.
fn cache_fill() -> Vec<u8> {
    let data = [0x5Au8; 4 * 4 * 2];
    let mut body = vec![4, 4, data.len() as u8, 0];
    body.extend_from_slice(&data);
    let mut order = vec![0x03];
    order.extend_from_slice(&((body.len() as i16) - 7).to_le_bytes());
    order.extend_from_slice(&(0x4u16 << 3).to_le_bytes());
    order.push(0x04);
    order.extend_from_slice(&body);
    order
}

fuzz_target!(|input: &[u8]| {
    let Some((&count, data)) = input.split_first() else {
        return;
    };
    let core = gcc::ClientCoreData {
        desktop_width: 64,
        desktop_height: 48,
        ..Default::default()
    };
    let mut capabilities = capability::default_client_capabilities(&core);
    capabilities.retain(|set| !matches!(set, CapabilitySet::BitmapCache(_)));
    for set in &mut capabilities {
        if let CapabilitySet::Order(o) = set {
            o.order_support[capability::ORDER_NEG_DSTBLT_INDEX] = 1;
            o.order_support[capability::ORDER_NEG_PATBLT_INDEX] = 1;
            o.order_support[capability::ORDER_NEG_SCRBLT_INDEX] = 1;
            o.order_support[capability::ORDER_NEG_MEMBLT_INDEX] = 1;
            o.order_support[capability::ORDER_NEG_MEM3BLT_INDEX] = 1;
            o.order_flags |= capability::ORDER_FLAGS_EXTRA_FLAGS;
            o.order_support_ex_flags = capability::ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT;
        }
    }
    capabilities.push(CapabilitySet::BitmapCacheRev2(
        capability::BitmapCacheRev2CapabilitySet {
            cache_flags: capability::ALLOW_CACHE_WAITING_LIST_FLAG,
            cells: vec![
                capability::BitmapCacheCellInfo {
                    entries: 4,
                    persistent: false,
                };
                3
            ],
        },
    ));
    let Ok(mut sm) = SessionStateMachine::new(
        SessionConfig {
            user_channel_id: 1007,
            io_channel_id: 1003,
            share_id: 1,
            desktop_size: (64, 48),
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
    ) else {
        return;
    };
    let updates = usize::from(count % 8) + 1;
    let share = data.len().div_ceil(updates).max(1);
    for chunk in data.chunks(share) {
        let mut body = 64u16.to_le_bytes().to_vec(); // numberOrders
        body.extend(cache_fill());
        body.extend_from_slice(chunk);
        if body.len() > 32_000 {
            continue;
        }
        let _ = sm.process_bytes(&fastpath::encode_pdu(&[(
            fastpath::FP_UPDATE_ORDERS,
            fastpath::FP_FRAGMENT_SINGLE,
            &body,
        )]));
    }
});
