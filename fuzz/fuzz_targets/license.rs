#![no_main]
//! Fuzz the server license-request parser (issue #99). Sibling of license's
//! `server_license_request_decode_never_panics` proptest. `ServerLicenseRequest::decode` is the
//! deepest license parse — it walks the embedded `ServerCertificate` and proprietary RSA modulus
//! (a length-driven, OOB-prone path), so this target covers those nested parsers too.

use libfuzzer_sys::fuzz_target;
use justrdp_pdu::cursor::ReadCursor;
use justrdp_pdu::license::ServerLicenseRequest;

fuzz_target!(|data: &[u8]| {
    let mut cur = ReadCursor::new(data, "fuzz license-request");
    let _ = ServerLicenseRequest::decode(&mut cur);
});
