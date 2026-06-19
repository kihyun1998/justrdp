#![no_main]
//! Fuzz the TS_DEMAND_ACTIVE capability parser (issue #99). Sibling of capability's
//! `demand_active_decode_never_panics` proptest. `DemandActive::decode` walks an arbitrary list
//! of capability sets, so this one target covers the per-set `CapabilitySet::decode` paths too.

use libfuzzer_sys::fuzz_target;
use justrdp_pdu::capability::DemandActive;
use justrdp_pdu::cursor::ReadCursor;

fuzz_target!(|data: &[u8]| {
    let mut cur = ReadCursor::new(data, "fuzz demand-active");
    let _ = DemandActive::decode(&mut cur);
});
