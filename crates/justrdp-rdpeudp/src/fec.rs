#![forbid(unsafe_code)]

//! XOR-based Forward Error Correction for MS-RDPEUDP.
//!
//! MS-RDPEUDP uses a simple XOR FEC scheme: the FEC payload is the
//! byte-wise XOR of a group of source payloads (each prefixed with a
//! 2-byte `RDPUDP_PAYLOAD_PREFIX` length). The receiver can recover
//! any single missing source packet from the remaining source packets
//! + the FEC packet via `payload = fec_xor ⊕ xor_of_received`.
//!
//! This module provides the encode (group → FEC payload) and decode
//! (recover one missing packet from the group + FEC payload) helpers.
//! It does **not** decide when to send FEC packets or which source
//! packets to group — that is the state machine's job.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

// =============================================================================
// FEC encode / decode
// =============================================================================

/// Compute the XOR FEC payload for a group of source payloads.
///
/// Each source payload is implicitly prefixed with a 2-byte
/// little-endian `RDPUDP_PAYLOAD_PREFIX` (its length) before XOR-ing.
/// The result has the same length as the longest prefixed payload,
/// zero-padded as needed.
pub fn fec_encode(sources: &[&[u8]]) -> Vec<u8> {
    if sources.is_empty() {
        return Vec::new();
    }
    // Max length of a prefixed payload.
    let max_len = sources.iter().map(|s| s.len() + 2).max().unwrap_or(0);
    let mut fec = vec![0u8; max_len];
    for src in sources {
        let prefixed = prefix_payload(src);
        for (i, b) in prefixed.iter().enumerate() {
            fec[i] ^= b;
        }
    }
    fec
}

/// Recover a single missing source payload from the FEC payload and
/// the remaining (received) source payloads.
///
/// Returns the recovered payload **without** the 2-byte prefix — the
/// caller receives the raw application data.
pub fn fec_recover(fec_payload: &[u8], received: &[&[u8]]) -> Option<Vec<u8>> {
    // XOR the received payloads into the FEC to isolate the missing
    // one's prefixed form.
    let mut recovered = fec_payload.to_vec();
    for src in received {
        let prefixed = prefix_payload(src);
        for (i, b) in prefixed.iter().enumerate() {
            if i < recovered.len() {
                recovered[i] ^= b;
            }
        }
    }
    // Parse the 2-byte prefix to determine the actual payload length.
    if recovered.len() < 2 {
        return None;
    }
    let len = u16::from_le_bytes([recovered[0], recovered[1]]) as usize;
    if 2 + len > recovered.len() {
        return None;
    }
    Some(recovered[2..2 + len].to_vec())
}

/// Prepend a 2-byte LE length prefix to `payload`, matching the
/// `RDPUDP_PAYLOAD_PREFIX` structure (§2.2.2.3).
fn prefix_payload(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fec_encode_single_source_equals_prefixed_payload() {
        let src = b"hello";
        let fec = fec_encode(&[src]);
        // Prefixed: [0x05, 0x00, h, e, l, l, o]
        assert_eq!(&fec[..2], &[0x05, 0x00]);
        assert_eq!(&fec[2..], b"hello");
    }

    #[test]
    fn fec_encode_two_sources_xor() {
        let a = b"AB";
        let b_src = b"CD";
        let fec = fec_encode(&[a, b_src]);
        // a_prefixed: [0x02, 0x00, 0x41, 0x42]
        // b_prefixed: [0x02, 0x00, 0x43, 0x44]
        // XOR:        [0x00, 0x00, 0x02, 0x06]
        assert_eq!(fec, vec![0x00, 0x00, 0x02, 0x06]);
    }

    #[test]
    fn fec_recover_single_loss() {
        let a = b"hello";
        let b_src = b"world";
        let c = b"test!";
        let fec = fec_encode(&[a, b_src, c]);
        // Lose b_src — recover from a, c, and the FEC payload.
        let recovered = fec_recover(&fec, &[a, c]).unwrap();
        assert_eq!(recovered, b"world");
    }

    #[test]
    fn fec_recover_first_packet_lost() {
        let a = b"AAAA";
        let b_src = b"BBBB";
        let fec = fec_encode(&[a, b_src]);
        let recovered = fec_recover(&fec, &[b_src]).unwrap();
        assert_eq!(recovered, a);
    }

    #[test]
    fn fec_recover_last_packet_lost() {
        let a = b"AAAA";
        let b_src = b"BBBB";
        let fec = fec_encode(&[a, b_src]);
        let recovered = fec_recover(&fec, &[a]).unwrap();
        assert_eq!(recovered, b_src);
    }

    #[test]
    fn fec_recover_different_lengths() {
        // Source payloads of different sizes — shorter ones are
        // zero-padded during XOR.
        let short = b"hi";
        let long = b"hello world!";
        let fec = fec_encode(&[short, long]);
        // Lose `short`, recover from `long` + FEC.
        let recovered = fec_recover(&fec, &[long]).unwrap();
        assert_eq!(recovered, short);
        // Lose `long`, recover from `short` + FEC.
        let recovered = fec_recover(&fec, &[short]).unwrap();
        assert_eq!(recovered, long);
    }

    #[test]
    fn fec_encode_empty_sources() {
        assert!(fec_encode(&[]).is_empty());
    }

    #[test]
    fn fec_recover_returns_none_on_corrupt_prefix() {
        // Manually build a FEC payload whose recovered prefix claims
        // a length larger than available bytes.
        let fec = vec![0xFF, 0xFF, 0x01]; // prefix says 65535 bytes, only 1 available
        assert!(fec_recover(&fec, &[]).is_none());
    }

    #[test]
    fn fec_roundtrip_three_sources_each_loss_position() {
        let sources: &[&[u8]] = &[b"one", b"two", b"three"];
        let fec = fec_encode(sources);
        for i in 0..sources.len() {
            let received: Vec<&[u8]> = sources
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, s)| *s)
                .collect();
            let recovered = fec_recover(&fec, &received).unwrap();
            assert_eq!(recovered, sources[i], "failed to recover index {i}");
        }
    }
}
