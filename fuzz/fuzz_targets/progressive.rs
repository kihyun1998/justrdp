#![no_main]
//! Fuzz the RemoteFX Progressive block-stream parser (issue #99). Sibling of progressive's
//! `decode_all_never_panics_on_arbitrary_input` proptest. `decode_all` walks an arbitrary
//! number of RFX_PROGRESSIVE_* blocks out of one WireToSurface2 payload, with lengths nested
//! three deep — block, the region's tile window, then each tile's per-component runs — so the
//! whole input is the attacker-controlled surface, and the nesting is what coverage guidance
//! reaches that random bytes do not.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::rfx::progressive::decode_all(data);
});
