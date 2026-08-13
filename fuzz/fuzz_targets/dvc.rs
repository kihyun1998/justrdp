#![no_main]
//! Fuzz the dynamic virtual channel PDU parser (issue #200). Sibling of dvc's
//! `decode_never_panics_on_arbitrary_input` proptest.
//!
//! `DvcMessage::decode` splits a DRDYNVC PDU whose command nibble selects the layout and whose
//! `cbId`/`Len` fields size the fields that follow — a variable-width header where the widths
//! themselves come off the wire. It is the layer EGFX rides, so everything the graphics pipeline
//! sees is framed by this.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = justrdp_pdu::dvc::DvcMessage::decode(data);
});
