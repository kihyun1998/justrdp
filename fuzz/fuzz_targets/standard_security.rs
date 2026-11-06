#![no_main]
//! Fuzz the Standard RDP Security unprotect paths (#598), siblings of `standard`'s
//! `*_never_panics_on_arbitrary_input` properties. Every byte is what a server sends before a MAC
//! has been checked. The first byte picks the fast-path flag bits and the level.

use justrdp_security::standard::{
    ClientRandom, EncryptionLevel, EncryptionMethod, StandardSecurity,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let level = match selector >> 6 {
        0 => EncryptionLevel::Low,
        1 => EncryptionLevel::ClientCompatible,
        _ => EncryptionLevel::High,
    };
    let random = ClientRandom::new([0x11; 32]);
    let mut security =
        StandardSecurity::new(EncryptionMethod::Rc4Bit128, level, &random, &[0x22; 32]).unwrap();
    if selector & 0x20 == 0 {
        let _ = security.unprotect_slow_path(body);
    } else {
        let _ = security.unprotect_fast_path(selector & 0x3, body);
    }
});
