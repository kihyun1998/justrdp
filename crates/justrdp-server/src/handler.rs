#![forbid(unsafe_code)]

//! Display and input handler traits.
//!
//! These traits are the seam between the protocol-level
//! `ServerActiveStage` (Commit 5+) and the application that owns the
//! pixel data, the cursor, and the input device handlers. The traits are
//! intentionally narrow: they accept only the values the spec defines on
//! the wire (no opaque event objects, no hidden lifetimes), so any
//! caller -- a headless test harness, a real GUI, or a frame-grabber
//! proxy -- can implement them without pulling in extra dependencies.

use alloc::vec::Vec;

use justrdp_pdu::rdp::pointer::TsPoint16;

// ── Display update enum ──────────────────────────────────────────────

/// One unit of work the application wants the active session to push to
/// the client. The variants map 1:1 to the fast-path output update types
/// emitted by Commits 6 and 7:
///
/// | Variant            | Fast-path code                          | Payload                                             |
/// |--------------------|------------------------------------------|----------------------------------------------------|
/// | `Bitmap`           | `FASTPATH_UPDATETYPE_BITMAP (0x1)`       | `TS_UPDATE_BITMAP_DATA` (one rectangle per call)   |
/// | `Palette`          | `FASTPATH_UPDATETYPE_PALETTE (0x2)`      | 256-entry RGB palette (`Vec<u8>` of 768 bytes)     |
/// | `PointerPosition`  | `FASTPATH_UPDATETYPE_PTR_POSITION (0x8)` | `TS_POINT16`                                        |
/// | `PointerHidden`    | `FASTPATH_UPDATETYPE_PTR_NULL (0x5)`     | empty                                              |
/// | `PointerDefault`   | `FASTPATH_UPDATETYPE_PTR_DEFAULT (0x6)`  | empty                                              |
/// | `PointerColor`     | `FASTPATH_UPDATETYPE_PTR_COLOR (0x9)`    | `TS_COLORPOINTERATTRIBUTE`                          |
/// | `PointerNew`       | `FASTPATH_UPDATETYPE_PTR_NEW (0xB)`      | `TS_POINTERATTRIBUTE`                               |
/// | `PointerCached`    | `FASTPATH_UPDATETYPE_PTR_CACHED (0xA)`   | `TS_CACHEDPOINTERATTRIBUTE.cacheIndex`              |
/// | `Reset`            | (Deactivation-Reactivation, §11.2b)      | new `(width, height)` -- triggers DAS in 11.2b     |
///
/// The variants are kept lean so the application doesn't have to allocate
/// or learn the wire format. The active stage is responsible for
/// (1) wrapping the payload in the appropriate `FastPathOutputUpdate`,
/// (2) honouring `suppress_output` (drop updates while the client has
/// suppressed display), and (3) fragmenting bitmaps that exceed
/// `RdpServerConfig::max_bitmap_fragment_size`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayUpdate {
    /// Uncompressed bitmap region. The application owns the bottom-up,
    /// row-padded pixel buffer; see `bitmap::uncompressed_row_stride`
    /// (MS-RDPBCGR §2.2.9.1.1.3.1.2.1 Remarks).
    Bitmap(BitmapUpdate),
    /// Pointer position update -- moves the cursor without changing its
    /// shape. Coordinates are in screen pixels.
    PointerPosition(TsPoint16),
    /// Hide the pointer (`SYSPTR_NULL` semantics).
    PointerHidden,
    /// Show the system default pointer (`SYSPTR_DEFAULT` semantics).
    PointerDefault,
    /// Cache a 24-bpp color cursor (≤ 32×32 per spec).
    PointerColor(PointerColorUpdate),
    /// Cache a new-style cursor with explicit XOR bit depth (1/4/8/16/24/32).
    PointerNew(PointerNewUpdate),
    /// Re-activate a previously cached cursor by index.
    PointerCached { cache_index: u16 },
    /// 256-entry palette update for 8-bpp sessions
    /// (`FASTPATH_UPDATETYPE_PALETTE`, §2.2.9.1.2.1.1). The buffer is the
    /// 256 RGB triplets (3 bytes each, 768 bytes total). 8-bpp sessions
    /// are the only ones that emit this; 16/24/32-bpp sessions can leave
    /// the variant unused.
    Palette(Vec<u8>),
    /// Display dimensions changed and the session needs a
    /// Deactivation-Reactivation Sequence. The active stage may emit
    /// `Deactivate All` and re-drive Demand Active in §11.2b; for the
    /// 11.2a skeleton it is a no-op signal that the application has
    /// resized.
    Reset { width: u16, height: u16 },
}

// ── Inner payloads ───────────────────────────────────────────────────

/// Uncompressed bitmap update payload.
///
/// The wire form (single `TS_BITMAP_DATA` rectangle) is built by the
/// active-stage encoder in Commit 6 from these fields. `dest_left`/`top`
/// are the on-screen position of the upper-left pixel; `width`/`height`
/// describe the rectangle dimensions; `bits_per_pixel` is one of
/// `{ 8, 15, 16, 24, 32 }`; `data` carries `height` rows of pixels in
/// **bottom-up** order with each row padded to a 4-byte boundary
/// (use `justrdp_pdu::rdp::bitmap::uncompressed_row_stride` to size the
/// buffer correctly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapUpdate {
    pub dest_left: u16,
    pub dest_top: u16,
    pub width: u16,
    pub height: u16,
    pub bits_per_pixel: u16,
    pub data: Vec<u8>,
}

/// Color cursor cache entry (`TS_COLORPOINTERATTRIBUTE`,
/// MS-RDPBCGR §2.2.9.1.1.4.4). `width`/`height` MUST be ≤ 32; the active
/// stage validates this against
/// `pointer::validate_color_pointer_dimensions` before emitting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerColorUpdate {
    pub cache_index: u16,
    pub hot_spot: TsPoint16,
    pub width: u16,
    pub height: u16,
    /// 24-bpp XOR mask data, bottom-up, scan-line padded to 2-byte
    /// boundary (use `pointer::xor_mask_row_stride(width, 24)`).
    pub xor_mask_data: Vec<u8>,
    /// 1-bpp AND mask data, bottom-up, scan-line padded to 2-byte
    /// boundary (use `pointer::and_mask_row_stride(width)`).
    pub and_mask_data: Vec<u8>,
}

/// New-style pointer cache entry (`TS_POINTERATTRIBUTE`,
/// MS-RDPBCGR §2.2.9.1.1.4.5). `xor_bpp` may be 1, 4, 8, 16, 24, or 32;
/// `width`/`height` are bounded by the negotiated `pointerCacheSize`
/// (`PointerCapability`, §2.2.7.1.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerNewUpdate {
    pub xor_bpp: u16,
    pub cache_index: u16,
    pub hot_spot: TsPoint16,
    pub width: u16,
    pub height: u16,
    /// XOR mask in `xor_bpp`-bit pixels, bottom-up, scan-line padded to
    /// 2-byte boundary (use `pointer::xor_mask_row_stride(width, xor_bpp)`).
    pub xor_mask_data: Vec<u8>,
    /// 1-bpp AND mask, bottom-up, scan-line padded to 2-byte boundary
    /// (use `pointer::and_mask_row_stride(width)`).
    pub and_mask_data: Vec<u8>,
}

// ── Display handler trait ────────────────────────────────────────────

/// Application-side hook the active stage polls each tick for a new
/// display update and notifies of incoming display-control PDUs.
pub trait RdpServerDisplayHandler {
    /// Pull the next display update from the application. Returning
    /// `None` is the steady-state idle response and is fine to return
    /// every tick -- the active stage backs off transparently.
    fn get_display_update(&mut self) -> Option<DisplayUpdate>;

    /// Current desktop size as (`width`, `height`) in pixels. Used by
    /// the active stage during `Reset` and Deactivation-Reactivation
    /// (§11.2b). The dimensions MUST match the value sent in
    /// `BitmapCapability` of the most recent Demand Active PDU.
    fn get_display_size(&self) -> (u16, u16);

    /// Client called Suppress Output (MS-RDPBCGR §2.2.11.3).
    ///
    /// `suppress_output` is `true` when the client asked the server to
    /// stop sending updates (e.g. window minimised); `false` when the
    /// client asks to resume. When resuming, `area` carries the visible
    /// rectangle the client is willing to render (inclusive coordinates,
    /// `dest_right` = `left + width - 1`).
    ///
    /// The default implementation drops the notification. Implement it
    /// to throttle / pause your render loop while the client is hidden.
    fn on_suppress_output(&mut self, suppress: bool, area: Option<DisplayRect>) {
        let _ = (suppress, area);
    }

    /// Client called Refresh Rect (MS-RDPBCGR §2.2.11.2). The application
    /// SHOULD re-emit the listed areas at the next tick. The default
    /// implementation drops the notification.
    fn on_refresh_rect(&mut self, areas: &[DisplayRect]) {
        let _ = areas;
    }
}

/// Inclusive rectangle expressed exactly as it arrives on the wire
/// (MS-RDPBCGR uses `left`, `top`, `right`, `bottom` as inclusive
/// boundaries, so a `1x1` rectangle has `left == right` and
/// `top == bottom`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayRect {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

// ── Input handler trait ──────────────────────────────────────────────

/// Application-side hook the active stage calls when the client emits
/// an input event (fast-path or slow-path). All callbacks pass the raw
/// wire-level fields so the application can decide how to translate them
/// into device events.
///
/// Default implementations drop the event. Implement only the methods
/// you need.
pub trait RdpServerInputHandler {
    /// Scancode keyboard event (MS-RDPBCGR §2.2.8.1.2.2.1 / §2.2.8.1.1.3.1.1.1).
    ///
    /// `flags` is the keyboard-flags bitfield in its **fast-path** layout
    /// (low byte): `FASTPATH_INPUT_KBDFLAGS_RELEASE = 0x01`,
    /// `_EXTENDED = 0x02`, `_EXTENDED1 = 0x04`. Slow-path events are
    /// translated by the active stage so handlers see a consistent
    /// representation regardless of input path.
    fn on_keyboard_scancode(&mut self, flags: u16, key_code: u8) {
        let _ = (flags, key_code);
    }

    /// Unicode keyboard event (MS-RDPBCGR §2.2.8.1.2.2.2 /
    /// §2.2.8.1.1.3.1.1.2). `flags` carries the same press / release bits
    /// as `on_keyboard_scancode`.
    fn on_keyboard_unicode(&mut self, flags: u16, unicode_code: u16) {
        let _ = (flags, unicode_code);
    }

    /// Mouse event (MS-RDPBCGR §2.2.8.1.2.2.3 / §2.2.8.1.1.3.1.1.3).
    ///
    /// `pointer_flags` is the `PTRFLAGS_*` bitmask
    /// (`PTRFLAGS_MOVE = 0x0800`, `_BUTTON1 = 0x1000`, `_BUTTON2 = 0x2000`,
    /// `_BUTTON3 = 0x4000`, `_WHEEL = 0x0200`, `_DOWN = 0x8000`). `x`/`y`
    /// are screen coordinates.
    fn on_mouse(&mut self, pointer_flags: u16, x: u16, y: u16) {
        let _ = (pointer_flags, x, y);
    }

    /// Extended mouse event (MS-RDPBCGR §2.2.8.1.2.2.4 /
    /// §2.2.8.1.1.3.1.1.4) -- carries the X1/X2 buttons.
    /// `pointer_flags`: `PTRXFLAGS_BUTTON1 = 0x0001`, `_BUTTON2 = 0x0002`,
    /// `_DOWN = 0x8000`.
    fn on_mouse_extended(&mut self, pointer_flags: u16, x: u16, y: u16) {
        let _ = (pointer_flags, x, y);
    }

    /// Relative mouse event (MS-RDPBCGR §2.2.8.1.2.2.5). Carries signed
    /// deltas; only sent when the client negotiated Relative Mouse
    /// Input (`HasRelativeMouseInputCapability`, §2.2.7.2.6).
    fn on_mouse_relative(&mut self, pointer_flags: u16, x_delta: i16, y_delta: i16) {
        let _ = (pointer_flags, x_delta, y_delta);
    }

    /// Synchronize event (MS-RDPBCGR §2.2.8.1.2.2.6 /
    /// §2.2.8.1.1.3.1.1.5). The `flags` byte carries the toggle-key
    /// states: `SYNC_SCROLL_LOCK = 0x01`, `SYNC_NUM_LOCK = 0x02`,
    /// `SYNC_CAPS_LOCK = 0x04`, `SYNC_KANA_LOCK = 0x08`.
    fn on_sync(&mut self, flags: u8) {
        let _ = flags;
    }

    /// QoE timestamp event (MS-RDPBCGR §2.2.8.1.2.2.7) -- only sent when
    /// the client and server have negotiated QoE input feedback.
    fn on_qoe_timestamp(&mut self, timestamp: u32) {
        let _ = timestamp;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn display_update_variants_are_constructible() {
        // Smoke-test for variant construction. The encoders in Commits 6
        // and 7 will exercise field semantics; here we just confirm the
        // public shape compiles.
        let _ = DisplayUpdate::Bitmap(BitmapUpdate {
            dest_left: 0,
            dest_top: 0,
            width: 8,
            height: 8,
            bits_per_pixel: 32,
            data: vec![0u8; 8 * 8 * 4],
        });
        let _ = DisplayUpdate::PointerPosition(TsPoint16 { x_pos: 0, y_pos: 0 });
        let _ = DisplayUpdate::PointerHidden;
        let _ = DisplayUpdate::PointerDefault;
        let _ = DisplayUpdate::PointerCached { cache_index: 0 };
        let _ = DisplayUpdate::Reset { width: 1024, height: 768 };
        let _ = DisplayUpdate::Palette(vec![0u8; 768]);
    }

    /// A handler that records callback invocations so tests in later
    /// commits can assert on the dispatcher path.
    #[derive(Default)]
    struct RecordingHandler {
        scancodes: Vec<(u16, u8)>,
        sync_flags: Vec<u8>,
    }

    impl RdpServerInputHandler for RecordingHandler {
        fn on_keyboard_scancode(&mut self, flags: u16, key_code: u8) {
            self.scancodes.push((flags, key_code));
        }
        fn on_sync(&mut self, flags: u8) {
            self.sync_flags.push(flags);
        }
    }

    #[test]
    fn input_handler_default_methods_drop_events() {
        // A handler that overrides nothing must still compile and
        // accept every callback without panicking.
        struct Empty;
        impl RdpServerInputHandler for Empty {}
        let mut h = Empty;
        h.on_keyboard_scancode(0x01, 0x1E);
        h.on_keyboard_unicode(0x00, 0x0041);
        h.on_mouse(0x8000, 100, 100);
        h.on_mouse_extended(0x0001, 0, 0);
        h.on_mouse_relative(0, -5, 5);
        h.on_sync(0x07);
        h.on_qoe_timestamp(0xDEAD_BEEF);
    }

    #[test]
    fn input_handler_overrides_record_events() {
        let mut h = RecordingHandler::default();
        h.on_keyboard_scancode(0x01, 0x1E);
        h.on_keyboard_scancode(0x00, 0x1E);
        h.on_sync(0x04);
        assert_eq!(h.scancodes, vec![(0x01, 0x1E), (0x00, 0x1E)]);
        assert_eq!(h.sync_flags, vec![0x04]);
    }

    /// A display handler that returns a single bitmap update once,
    /// then `None` forever -- shape the dispatcher (Commit 5) will use.
    struct OneShotDisplay {
        update: Option<DisplayUpdate>,
        size: (u16, u16),
    }

    impl RdpServerDisplayHandler for OneShotDisplay {
        fn get_display_update(&mut self) -> Option<DisplayUpdate> {
            self.update.take()
        }
        fn get_display_size(&self) -> (u16, u16) {
            self.size
        }
    }

    #[test]
    fn display_handler_yields_single_update_then_idles() {
        let mut h = OneShotDisplay {
            update: Some(DisplayUpdate::PointerHidden),
            size: (1920, 1080),
        };
        assert!(matches!(
            h.get_display_update(),
            Some(DisplayUpdate::PointerHidden)
        ));
        assert!(h.get_display_update().is_none());
        assert_eq!(h.get_display_size(), (1920, 1080));
    }

    #[test]
    fn display_handler_default_notifications_are_no_ops() {
        let mut h = OneShotDisplay { update: None, size: (800, 600) };
        h.on_suppress_output(true, None);
        h.on_suppress_output(
            false,
            Some(DisplayRect { left: 0, top: 0, right: 799, bottom: 599 }),
        );
        h.on_refresh_rect(&[DisplayRect { left: 0, top: 0, right: 0, bottom: 0 }]);
    }
}
