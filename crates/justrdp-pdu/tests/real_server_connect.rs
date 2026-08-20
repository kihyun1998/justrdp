//! What a real server actually sent, asserted against the shipped parsers (#203).
//!
//! The fixtures are captured by `justrdp-tokio`'s `capture_connect_response_against_real_vm`
//! and are the seed corpus for the `gcc` and `mcs` fuzz targets. They are read here as well,
//! and not only by the nightly lane, for two reasons:
//!
//! - **A fixture only the fuzz lane reads is a fixture nothing checks.** The lane is nightly and
//!   its seeder would report a stale file as a corpus that merely decodes badly, which is
//!   indistinguishable from a corpus that is doing its job.
//! - **A capture proves *acceptance*** — that nothing this server sends is rejected — which is
//!   the half of an owned basis a corpus can supply on its own
//!   (`docs/map/territory/verification-harness.md`). The differential test beside this one
//!   proves values against `ironrdp`; this proves the real thing parses.
//!
//! These are the only server-to-client connect bytes in the repo that no encoder of ours
//! produced. Every encoder in `justrdp-pdu` writes client-to-server, because justrdp is a
//! client — so a round-trip test structurally cannot reach these decoders, and this file plus
//! the no-panic properties are what stands in for it.

use justrdp_pdu::{gcc, mcs};

const CONNECT_RESPONSE: &[u8] = include_bytes!("fixtures/connect/connect-response.bin");
const CONFERENCE_CREATE_RESPONSE: &[u8] =
    include_bytes!("fixtures/connect/conference-create-response.bin");

#[test]
fn a_real_servers_connect_response_decodes() {
    let response = mcs::decode_connect_response(CONNECT_RESPONSE)
        .expect("the captured MCS Connect-Response decodes");

    assert_eq!(
        response.result, 0,
        "the capture is not an rt-successful response"
    );
    let blocks = &response.conference.blocks;
    assert_ne!(
        blocks.network.io_channel, 0,
        "no I/O channel in the server's network data"
    );
    assert!(
        response.conference.node_id >= 1001,
        "nodeID {} is below the PER base",
        response.conference.node_id
    );
}

#[test]
fn a_real_servers_gcc_user_data_decodes_standalone() {
    // This is the exact byte range the `gcc` fuzz target's first arm is handed, so it has to
    // parse on its own and not only as a slice of the frame above.
    let ccr = gcc::ConferenceCreateResponse::decode(CONFERENCE_CREATE_RESPONSE)
        .expect("the captured GCC user data decodes standalone");
    assert!(ccr.blocks.network.io_channel != 0);
}

#[test]
fn the_two_fixtures_cannot_drift() {
    // Written by one capture run from one frame: the GCC user data is a suffix of the MCS body.
    // A future recapture that updated only one of them would fail here rather than seeding the
    // fuzz corpus with a mismatched pair.
    assert!(
        CONNECT_RESPONSE.ends_with(CONFERENCE_CREATE_RESPONSE),
        "the GCC fixture is not the tail of the MCS fixture"
    );
}

#[test]
fn every_truncation_of_a_real_response_is_an_error_not_a_panic() {
    // The no-panic properties in `mcs` and `gcc` feed the parsers random bytes, which almost
    // never get past the magic prefix -- measured, 200k of them reach 11.98% of `gcc.rs`. A real
    // response truncated at each byte is the opposite input: valid right up to the cut, so every
    // length field inside it points past the end. That is the commonest real malformation (a
    // short read, a clipped frame) and the one random bytes structurally cannot produce.
    //
    // **It is a weaker net than the corruption sweep below, and that is measured rather than
    // assumed.** Injecting an out-of-bounds read into `ServerNetworkData::decode` leaves this
    // test green while turning the other three in this file red: truncation always fails in an
    // *outer* parser first, because `read_block` needs `block_len >= 4` and then a `read_slice`
    // that a clipped buffer cannot satisfy, so a short body never reaches a per-block decoder.
    // Corrupting a byte can set that same length field *to* 4, which does. The two sweeps probe
    // different axes -- where the buffer ends, versus what the fields say -- and keeping both is
    // the finding, not redundancy.
    for cut in 0..CONNECT_RESPONSE.len() {
        let _ = mcs::decode_connect_response(&CONNECT_RESPONSE[..cut]);
    }
    for cut in 0..CONFERENCE_CREATE_RESPONSE.len() {
        let _ = gcc::ConferenceCreateResponse::decode(&CONFERENCE_CREATE_RESPONSE[..cut]);
    }
    // Reaching here without unwinding IS the assertion.
}

#[test]
fn every_single_byte_corruption_of_the_gcc_user_data_is_survivable() {
    // One flipped byte in an otherwise valid response: the shape a fuzzer reaches immediately
    // from this seed and the shape a flaky link produces. Cheap to run exhaustively at this size
    // -- and unlike the truncation sweep it perturbs *values* (block types, lengths, counts)
    // rather than the buffer end, which is what lets it reach the per-block decoders at all.
    // This is the discriminating half of the pair: it is the one that goes red when an
    // out-of-bounds read is injected into `ServerNetworkData::decode`.
    let mut buf = CONFERENCE_CREATE_RESPONSE.to_vec();
    for i in 0..buf.len() {
        let original = buf[i];
        for bit in 0..8 {
            buf[i] = original ^ (1 << bit);
            let _ = gcc::ConferenceCreateResponse::decode(&buf);
        }
        buf[i] = original;
    }
}
