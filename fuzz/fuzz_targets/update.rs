#![no_main]
//! Fuzz the slow-path Bitmap and Palette Update bodies (issue #354). Sibling of update's two
//! `*_never_panics_on_arbitrary_input` proptests. `BitmapUpdate::decode` walks a server-declared
//! rectangle count and per-rectangle lengths.

use libfuzzer_sys::fuzz_target;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::update::{BitmapUpdate, PaletteUpdate};

fuzz_target!(|data: &[u8]| {
    let mut cur = ReadCursor::new(data, "fuzz bitmap update");
    let _ = BitmapUpdate::decode(&mut cur);

    let mut cur = ReadCursor::new(data, "fuzz palette update");
    let _ = PaletteUpdate::decode(&mut cur);
});
