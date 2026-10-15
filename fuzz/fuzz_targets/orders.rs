#![no_main]
//! Fuzz the drawing-order decoder (#460): orders one after another against one history, as an
//! Orders Update carries them. Sibling of `orders`'s `orders_never_panic` proptest.

use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::orders::{decode_order, OrderHistory};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut history = OrderHistory::default();
    let mut cur = ReadCursor::new(data, "fuzz orders");
    while cur.remaining() > 0 {
        if decode_order(&mut cur, &mut history).is_err() {
            break;
        }
    }
});
