#![forbid(unsafe_code)]

//! Cross-platform PC/SC smartcard backend (Phase 2).
//!
//! **STATUS: COMPILE-TESTED ONLY.** This module builds against the
//! `pcsc` crate (resolved version 2.9 at workspace lock time, which
//! transparently dispatches to WinSCard on Windows, pcsc-lite on
//! Linux/BSD, and CryptoTokenKit on macOS) and
//! its pure-Rust APDU helpers are unit-tested, but the live PC/SC
//! call paths (`Context::establish`, `Card::transmit`) have **not**
//! been validated against real hardware. Treat as a starting skeleton.
//!
//! # Card profile
//!
//! Targets **PIV (NIST SP 800-73-4)** cards exclusively. The PIV
//! application is selected via its standard AID
//! `A0 00 00 03 08 00 00 10 00 01 00`, the Authentication key (slot
//! `9A`) is used for signing, and the Authentication certificate
//! object (`5F C1 05`) supplies the X.509 cert.
//!
//! # PIN handling
//!
//! `verify_pin` issues a single PIV `VERIFY` (CLA 00, INS 20, P1 00,
//! P2 80) APDU. PIV pads the PIN to 8 bytes with `0xFF`. After a
//! successful VERIFY the card retains the unlocked state for the
//! duration of the connection.
//!
//! # Signing
//!
//! PIV cards perform raw RSA exponentiation only — the host must do
//! PKCS#1 v1.5 padding. `sign_digest` builds the padded message with
//! [`justrdp_core::rsa::pkcs1_v15_pad_sha256_digest`] sized to the
//! card's RSA modulus (currently hard-coded to 256 bytes / RSA-2048;
//! a future revision should read the actual modulus length from the
//! cached certificate's `SubjectPublicKeyInfo`).

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::CStr;

use justrdp_core::rsa::pkcs1_v15_pad_sha256_digest;

use crate::provider::{SmartcardError, SmartcardProvider};

// ── PIV constants (NIST SP 800-73-4) ──

/// PIV application AID.
pub const PIV_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// PIV Authentication key reference (slot 9A).
pub const PIV_KEY_AUTH: u8 = 0x9A;

/// PIV cryptographic algorithm reference for RSA 2048.
pub const PIV_ALG_RSA_2048: u8 = 0x07;

/// PIV Authentication certificate object tag (5F C1 05).
pub const PIV_OBJECT_AUTH_CERT: &[u8] = &[0x5F, 0xC1, 0x05];

/// Hard-coded modulus size (bytes) for PIV RSA-2048. A future revision
/// should parse this from the cached certificate's SPKI.
pub const PIV_RSA_2048_MODULUS_BYTES: usize = 256;

/// Maximum APDU response length we accept in a single transmit (Le=0).
pub const MAX_APDU_RESPONSE: usize = 4096;

/// Response buffer size for SELECT (FCI is small).
const SELECT_RSP_BUF: usize = 256;

/// Response buffer size for VERIFY (only SW1/SW2).
const VERIFY_RSP_BUF: usize = 16;

// ── Pure APDU helpers (unit-testable, no PC/SC dependency) ──

/// Build a CLA=00 case-4 APDU: SELECT (INS=A4) by AID with the PIV AID.
pub fn build_select_piv_apdu() -> Vec<u8> {
    let mut apdu = Vec::with_capacity(5 + PIV_AID.len());
    apdu.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00, PIV_AID.len() as u8]);
    apdu.extend_from_slice(PIV_AID);
    apdu
}

/// Build a PIV VERIFY APDU (CLA=00, INS=20, P1=00, P2=80) with the PIN
/// padded to 8 bytes with 0xFF as required by SP 800-73-4.
///
/// Returns `None` if the PIN is empty or longer than 8 bytes.
pub fn build_verify_pin_apdu(pin: &[u8]) -> Option<Vec<u8>> {
    if pin.is_empty() || pin.len() > 8 {
        return None;
    }
    let mut apdu = Vec::with_capacity(5 + 8);
    apdu.extend_from_slice(&[0x00, 0x20, 0x00, 0x80, 0x08]);
    apdu.extend_from_slice(pin);
    apdu.resize(5 + 8, 0xFF);
    Some(apdu)
}

/// Build a PIV GENERAL AUTHENTICATE APDU for RSA signature.
///
/// `padded_message` is the host-padded PKCS#1 v1.5 EM (256 bytes for
/// RSA-2048). The resulting APDU uses extended-length Lc/Le.
///
/// Wire shape: `00 87 ALG KEY 00 LcHi LcLo 7C L1 [82 00 81 L2 <padded>] 00 00`
pub fn build_general_authenticate_apdu(
    algorithm: u8,
    key_ref: u8,
    padded_message: &[u8],
) -> Vec<u8> {
    let mut inner = Vec::with_capacity(2 + padded_message.len() + 4);
    inner.extend_from_slice(&[0x82, 0x00]); // empty response template
    inner.push(0x81);
    push_ber_length(&mut inner, padded_message.len());
    inner.extend_from_slice(padded_message);

    let mut wrapped = Vec::with_capacity(inner.len() + 4);
    wrapped.push(0x7C);
    push_ber_length(&mut wrapped, inner.len());
    wrapped.extend_from_slice(&inner);

    let mut apdu = Vec::with_capacity(7 + wrapped.len() + 2);
    apdu.extend_from_slice(&[0x00, 0x87, algorithm, key_ref]);
    // Extended Lc.
    apdu.push(0x00);
    apdu.push((wrapped.len() >> 8) as u8);
    apdu.push((wrapped.len() & 0xFF) as u8);
    apdu.extend_from_slice(&wrapped);
    // Extended Le = 00 00 (max).
    apdu.push(0x00);
    apdu.push(0x00);
    apdu
}

/// Build the GET DATA APDU for a PIV object identified by a 3-byte
/// object tag (e.g. `5F C1 05` for the PIV Authentication cert).
pub fn build_get_data_apdu(object_tag: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(2 + object_tag.len());
    data.push(0x5C);
    data.push(object_tag.len() as u8);
    data.extend_from_slice(object_tag);

    let mut apdu = Vec::with_capacity(5 + data.len() + 1);
    apdu.extend_from_slice(&[0x00, 0xCB, 0x3F, 0xFF, data.len() as u8]);
    apdu.extend_from_slice(&data);
    apdu.push(0x00); // Le=0 → max
    apdu
}

/// Push a BER-TLV length octet sequence (short or long form) onto `out`.
pub fn push_ber_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

/// Parse a BER-TLV length starting at offset 0 of `bytes`.
/// Returns `(length, header_size)` or `None` on malformed input.
pub fn parse_ber_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || bytes.len() < 1 + n {
            return None;
        }
        let mut len = 0usize;
        for &b in &bytes[1..1 + n] {
            len = (len << 8) | b as usize;
        }
        Some((len, 1 + n))
    }
}

/// Strip the PIV GENERAL AUTHENTICATE response wrapper:
/// `7C L1 [82 L2 <signature>]` → `<signature>`.
pub fn parse_general_authenticate_response(rsp: &[u8]) -> Result<Vec<u8>, SmartcardError> {
    if rsp.first().copied() != Some(0x7C) {
        return Err(SmartcardError::CryptoFailure(
            "GENERAL AUTHENTICATE response missing 7C tag".to_string(),
        ));
    }
    let (outer_len, outer_hdr) = parse_ber_length(&rsp[1..]).ok_or_else(|| {
        SmartcardError::CryptoFailure("GENERAL AUTHENTICATE: bad outer length".to_string())
    })?;
    let outer_start = 1 + outer_hdr;
    let outer_end = outer_start
        .checked_add(outer_len)
        .ok_or_else(|| SmartcardError::CryptoFailure("length overflow".to_string()))?;
    if rsp.len() < outer_end {
        return Err(SmartcardError::CryptoFailure(
            "GENERAL AUTHENTICATE: outer length exceeds payload".to_string(),
        ));
    }
    let inner = &rsp[outer_start..outer_end];
    if inner.first().copied() != Some(0x82) {
        return Err(SmartcardError::CryptoFailure(
            "GENERAL AUTHENTICATE: missing 82 response tag".to_string(),
        ));
    }
    let (sig_len, sig_hdr) = parse_ber_length(&inner[1..]).ok_or_else(|| {
        SmartcardError::CryptoFailure("GENERAL AUTHENTICATE: bad signature length".to_string())
    })?;
    let sig_start = 1 + sig_hdr;
    let sig_end = sig_start
        .checked_add(sig_len)
        .ok_or_else(|| SmartcardError::CryptoFailure("length overflow".to_string()))?;
    if inner.len() < sig_end {
        return Err(SmartcardError::CryptoFailure(
            "GENERAL AUTHENTICATE: signature length exceeds payload".to_string(),
        ));
    }
    Ok(inner[sig_start..sig_end].to_vec())
}

/// Map a PIV VERIFY status word pair to a `SmartcardError`. PIV
/// returns `63 CX` where X is the remaining tries on a wrong-PIN, and
/// `69 83` for a blocked card. `63 C0` (zero remaining tries) is
/// promoted to `PinBlocked` so callers don't have to special-case it.
pub fn classify_verify_sw(sw1: u8, sw2: u8) -> Option<SmartcardError> {
    match (sw1, sw2) {
        (0x90, 0x00) => None,
        (0x63, 0xC0) => Some(SmartcardError::PinBlocked),
        (0x63, c) if (0xC1..=0xCF).contains(&c) => Some(SmartcardError::PinIncorrect {
            remaining_tries: Some(c & 0x0F),
        }),
        (0x69, 0x83) => Some(SmartcardError::PinBlocked),
        _ => Some(SmartcardError::Other(format!(
            "VERIFY failed: SW={sw1:02X}{sw2:02X}"
        ))),
    }
}

/// Strip the PIV `53 L1 [70 L2 <DER> 71 ...]` envelope returned by
/// GET DATA for the PIV Authentication certificate object, returning
/// the X.509 DER bytes alone.
pub fn parse_piv_certificate_envelope(body: &[u8]) -> Result<Vec<u8>, SmartcardError> {
    if body.first().copied() != Some(0x53) {
        return Err(SmartcardError::Other(
            "GET DATA: missing 53 wrapper".to_string(),
        ));
    }
    let (outer_len, outer_hdr) = parse_ber_length(&body[1..])
        .ok_or_else(|| SmartcardError::Other("GET DATA: bad outer length".to_string()))?;
    let outer_start = 1 + outer_hdr;
    let outer_end = outer_start
        .checked_add(outer_len)
        .ok_or_else(|| SmartcardError::Other("length overflow".to_string()))?;
    if body.len() < outer_end {
        return Err(SmartcardError::Other(
            "GET DATA: outer length exceeds payload".to_string(),
        ));
    }
    let inner = &body[outer_start..outer_end];
    let mut i = 0;
    while i < inner.len() {
        let tag = inner[i];
        let rest = inner
            .get(i + 1..)
            .ok_or_else(|| SmartcardError::Other("inner TLV truncated".to_string()))?;
        let (len, hdr) = parse_ber_length(rest)
            .ok_or_else(|| SmartcardError::Other("inner TLV bad length".to_string()))?;
        let val_start = i + 1 + hdr;
        let val_end = val_start
            .checked_add(len)
            .ok_or_else(|| SmartcardError::Other("length overflow".to_string()))?;
        if inner.len() < val_end {
            return Err(SmartcardError::Other(
                "inner TLV length exceeds payload".to_string(),
            ));
        }
        if tag == 0x70 {
            return Ok(inner[val_start..val_end].to_vec());
        }
        i = val_end;
    }
    Err(SmartcardError::Other(
        "GET DATA: no 70 certificate tag in PIV envelope".to_string(),
    ))
}

// ── Live PC/SC provider (untested without hardware) ──

/// PC/SC smartcard provider targeting PIV cards.
///
/// **Untested without real hardware.** Constructed via
/// [`PcscSmartcardProvider::open`], which establishes a PC/SC context,
/// connects to a reader, selects the PIV application, and caches the
/// authentication certificate.
pub struct PcscSmartcardProvider {
    /// PC/SC card handle, kept open for the provider's lifetime.
    card: pcsc::Card,
    /// Cached end-entity certificate (DER), fetched at `open` time.
    certificate: Vec<u8>,
}

impl PcscSmartcardProvider {
    /// Open a PIV card on a reader matching `reader_substring` (case
    /// sensitive). Pass `None` to pick the first available reader.
    ///
    /// **Untested without real hardware.**
    pub fn open(reader_substring: Option<&str>) -> Result<Self, SmartcardError> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)
            .map_err(|e| SmartcardError::Other(format!("pcsc establish: {e:?}")))?;

        let mut readers_buf = [0u8; 2048];
        let readers = ctx
            .list_readers(&mut readers_buf)
            .map_err(|e| SmartcardError::Other(format!("pcsc list_readers: {e:?}")))?;

        let mut chosen: Option<&CStr> = None;
        for reader in readers {
            match (reader_substring, reader.to_str()) {
                (Some(needle), Ok(name)) if name.contains(needle) => {
                    chosen = Some(reader);
                    break;
                }
                (None, _) => {
                    chosen = Some(reader);
                    break;
                }
                _ => continue,
            }
        }
        let reader = chosen.ok_or(SmartcardError::CardNotPresent)?;

        let card = ctx
            .connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .map_err(|e| match e {
                pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard => {
                    SmartcardError::CardNotPresent
                }
                other => SmartcardError::Other(format!("pcsc connect: {other:?}")),
            })?;

        // Select PIV application.
        let select = build_select_piv_apdu();
        let mut rsp_buf = [0u8; SELECT_RSP_BUF];
        let rsp = card
            .transmit(&select, &mut rsp_buf)
            .map_err(|e| SmartcardError::Other(format!("SELECT PIV transmit: {e:?}")))?;
        let _ = check_status(rsp)?;

        // Fetch PIV Authentication certificate.
        let cert = read_piv_certificate(&card)?;

        Ok(Self {
            card,
            certificate: cert,
        })
    }
}

impl SmartcardProvider for PcscSmartcardProvider {
    fn get_certificate(&self) -> Vec<u8> {
        self.certificate.clone()
    }

    fn get_intermediate_chain(&self) -> Vec<Vec<u8>> {
        // PIV does not store a chain on-card by default. The
        // application is responsible for supplying intermediates if
        // the KDC requires them.
        Vec::new()
    }

    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), SmartcardError> {
        let mut apdu = build_verify_pin_apdu(pin)
            .ok_or_else(|| SmartcardError::Other("PIN must be 1..=8 bytes".to_string()))?;
        let mut rsp_buf = [0u8; VERIFY_RSP_BUF];
        let result = self
            .card
            .transmit(&apdu, &mut rsp_buf)
            .map(|rsp| (rsp.len(), rsp.first().copied().unwrap_or(0), rsp));
        // Zero the APDU buffer immediately — it contains the PIN bytes
        // padded with 0xFF. SHOULD per `SmartcardProvider::verify_pin`
        // contract. We do this regardless of transmit success.
        apdu.fill(0);
        let rsp = result
            .map(|(_, _, rsp)| rsp)
            .map_err(|e| SmartcardError::Other(format!("VERIFY transmit: {e:?}")))?;
        if rsp.len() < 2 {
            return Err(SmartcardError::Other("VERIFY: short response".to_string()));
        }
        let sw1 = rsp[rsp.len() - 2];
        let sw2 = rsp[rsp.len() - 1];
        match classify_verify_sw(sw1, sw2) {
            None => Ok(()),
            Some(err) => Err(err),
        }
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, SmartcardError> {
        if digest.len() != 32 {
            return Err(SmartcardError::CryptoFailure(
                "digest must be 32 bytes (SHA-256)".to_string(),
            ));
        }
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(digest);

        let padded = pkcs1_v15_pad_sha256_digest(PIV_RSA_2048_MODULUS_BYTES, &digest_arr)
            .ok_or_else(|| {
                SmartcardError::CryptoFailure("PKCS#1 v1.5 padding failed".to_string())
            })?;

        let apdu = build_general_authenticate_apdu(PIV_ALG_RSA_2048, PIV_KEY_AUTH, &padded);
        let mut rsp_buf = [0u8; MAX_APDU_RESPONSE];
        let rsp = self
            .card
            .transmit(&apdu, &mut rsp_buf)
            .map_err(|e| match e {
                pcsc::Error::RemovedCard => SmartcardError::CardRemoved,
                other => SmartcardError::CryptoFailure(format!("GENERAL AUTH transmit: {other:?}")),
            })?;
        let body = check_status(rsp)?;
        parse_general_authenticate_response(body)
    }
}

/// Validate the trailing SW1 SW2 status word and return the response
/// body (without SW). 90 00 → success.
fn check_status(rsp: &[u8]) -> Result<&[u8], SmartcardError> {
    if rsp.len() < 2 {
        return Err(SmartcardError::Other("APDU response too short".to_string()));
    }
    let sw1 = rsp[rsp.len() - 2];
    let sw2 = rsp[rsp.len() - 1];
    if (sw1, sw2) == (0x90, 0x00) {
        Ok(&rsp[..rsp.len() - 2])
    } else {
        Err(SmartcardError::Other(format!(
            "APDU error SW={sw1:02X}{sw2:02X}"
        )))
    }
}

/// Read the PIV Authentication certificate object and return its
/// X.509 DER bytes after stripping the PIV envelope.
fn read_piv_certificate(card: &pcsc::Card) -> Result<Vec<u8>, SmartcardError> {
    let apdu = build_get_data_apdu(PIV_OBJECT_AUTH_CERT);
    let mut rsp_buf = [0u8; MAX_APDU_RESPONSE];
    let rsp = card
        .transmit(&apdu, &mut rsp_buf)
        .map_err(|e| SmartcardError::Other(format!("GET DATA transmit: {e:?}")))?;
    let body = check_status(rsp)?;
    parse_piv_certificate_envelope(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // ── Pure helpers (unit-testable, no hardware) ──

    #[test]
    fn select_apdu_targets_piv_aid() {
        let apdu = build_select_piv_apdu();
        assert_eq!(
            apdu,
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10,
                0x00, 0x01, 0x00,
            ]
        );
    }

    #[test]
    fn verify_apdu_pads_pin_to_8_bytes() {
        let apdu = build_verify_pin_apdu(b"1234").unwrap();
        assert_eq!(
            apdu,
            vec![0x00, 0x20, 0x00, 0x80, 0x08, b'1', b'2', b'3', b'4', 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn verify_apdu_rejects_empty_or_oversized() {
        assert!(build_verify_pin_apdu(b"").is_none());
        assert!(build_verify_pin_apdu(b"123456789").is_none());
    }

    #[test]
    fn verify_apdu_accepts_full_8_bytes() {
        let apdu = build_verify_pin_apdu(b"12345678").unwrap();
        assert_eq!(&apdu[5..], b"12345678");
    }

    #[test]
    fn ber_length_short_form() {
        let mut buf = Vec::new();
        push_ber_length(&mut buf, 0x7F);
        assert_eq!(buf, vec![0x7F]);
        assert_eq!(parse_ber_length(&buf), Some((0x7F, 1)));
    }

    #[test]
    fn ber_length_one_byte_long_form() {
        let mut buf = Vec::new();
        push_ber_length(&mut buf, 0xFF);
        assert_eq!(buf, vec![0x81, 0xFF]);
        assert_eq!(parse_ber_length(&buf), Some((0xFF, 2)));
    }

    #[test]
    fn ber_length_two_byte_long_form() {
        let mut buf = Vec::new();
        push_ber_length(&mut buf, 0x1234);
        assert_eq!(buf, vec![0x82, 0x12, 0x34]);
        assert_eq!(parse_ber_length(&buf), Some((0x1234, 3)));
    }

    #[test]
    fn ber_length_three_byte_long_form() {
        let mut buf = Vec::new();
        push_ber_length(&mut buf, 0x010000);
        assert_eq!(buf, vec![0x83, 0x01, 0x00, 0x00]);
        assert_eq!(parse_ber_length(&buf), Some((0x010000, 4)));
    }

    #[test]
    fn ber_length_round_trip_boundaries() {
        for len in [0usize, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000] {
            let mut buf = Vec::new();
            push_ber_length(&mut buf, len);
            let (parsed, _hdr) = parse_ber_length(&buf).unwrap();
            assert_eq!(parsed, len, "round-trip failed for {len}");
        }
    }

    #[test]
    fn general_authenticate_apdu_layout() {
        let padded = vec![0x42u8; 256];
        let apdu = build_general_authenticate_apdu(PIV_ALG_RSA_2048, PIV_KEY_AUTH, &padded);
        // Header: CLA INS ALG KEY
        assert_eq!(&apdu[0..4], &[0x00, 0x87, 0x07, 0x9A]);
        // Inner template: 82 00 (2) + 81 82 01 00 (4) + 256 padded = 262
        // Outer wrapper = 7C 82 01 06 (4-byte hdr) + 262 inner = 266 total
        // Extended Lc = 00 01 0A (266)
        assert_eq!(&apdu[4..7], &[0x00, 0x01, 0x0A]);
        // Wrapper tag 7C immediately after Lc
        assert_eq!(apdu[7], 0x7C);
        // 7C length header is 3 bytes (long form for 262): 82 01 06
        assert_eq!(&apdu[8..11], &[0x82, 0x01, 0x06]);
        // Inner template starts with 82 00 81 ...
        assert_eq!(&apdu[11..15], &[0x82, 0x00, 0x81, 0x82]);
        // Extended Le tail = 00 00
        assert_eq!(&apdu[apdu.len() - 2..], &[0x00, 0x00]);
        // Total APDU = 4 (header) + 3 (ext Lc) + 266 (wrapper) + 2 (ext Le) = 275
        assert_eq!(apdu.len(), 275);
    }

    #[test]
    fn general_authenticate_response_parsing_round_trip() {
        let signature = vec![0xAAu8; 256];
        let mut inner = Vec::new();
        inner.push(0x82);
        push_ber_length(&mut inner, signature.len());
        inner.extend_from_slice(&signature);
        let mut rsp = Vec::new();
        rsp.push(0x7C);
        push_ber_length(&mut rsp, inner.len());
        rsp.extend_from_slice(&inner);
        let parsed = parse_general_authenticate_response(&rsp).unwrap();
        assert_eq!(parsed, signature);
    }

    #[test]
    fn general_authenticate_response_rejects_missing_outer_tag() {
        let bad = vec![0x99, 0x82, 0x01, 0x00];
        assert!(parse_general_authenticate_response(&bad).is_err());
    }

    #[test]
    fn general_authenticate_response_rejects_missing_inner_tag() {
        // 7C L1 [99 02 AA BB]  — wrong inner tag
        let mut rsp = vec![0x7C, 0x04, 0x99, 0x02, 0xAA, 0xBB];
        assert!(parse_general_authenticate_response(&rsp).is_err());
        rsp[2] = 0x82;
        assert_eq!(
            parse_general_authenticate_response(&rsp).unwrap(),
            vec![0xAA, 0xBB]
        );
    }

    #[test]
    fn get_data_apdu_targets_auth_cert_object() {
        let apdu = build_get_data_apdu(PIV_OBJECT_AUTH_CERT);
        assert_eq!(
            apdu,
            vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00]
        );
    }

    #[test]
    fn classify_verify_sw_success() {
        assert!(classify_verify_sw(0x90, 0x00).is_none());
    }

    #[test]
    fn classify_verify_sw_pin_incorrect_with_tries() {
        let err = classify_verify_sw(0x63, 0xC2).unwrap();
        assert_eq!(
            err,
            SmartcardError::PinIncorrect {
                remaining_tries: Some(2)
            }
        );
    }

    #[test]
    fn classify_verify_sw_pin_blocked() {
        let err = classify_verify_sw(0x69, 0x83).unwrap();
        assert_eq!(err, SmartcardError::PinBlocked);
    }

    #[test]
    fn classify_verify_sw_63c0_promoted_to_blocked() {
        // `63 C0` means zero remaining tries → effectively blocked.
        let err = classify_verify_sw(0x63, 0xC0).unwrap();
        assert_eq!(err, SmartcardError::PinBlocked);
    }

    #[test]
    fn classify_verify_sw_unknown_falls_back_to_other() {
        let err = classify_verify_sw(0x6A, 0x82).unwrap();
        assert!(matches!(err, SmartcardError::Other(_)));
    }

    #[test]
    fn parse_piv_envelope_extracts_cert() {
        // 53 L1 [70 L2 <der> 71 01 00]
        let der = vec![0x30, 0x82, 0x01, 0x23, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut inner = Vec::new();
        inner.push(0x70);
        push_ber_length(&mut inner, der.len());
        inner.extend_from_slice(&der);
        // Trailing TLVs (compression marker, error code) should be ignored.
        inner.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
        let mut env = Vec::new();
        env.push(0x53);
        push_ber_length(&mut env, inner.len());
        env.extend_from_slice(&inner);
        let extracted = parse_piv_certificate_envelope(&env).unwrap();
        assert_eq!(extracted, der);
    }

    #[test]
    fn parse_piv_envelope_rejects_missing_53() {
        let bad = vec![0x99, 0x02, 0x70, 0x00];
        assert!(parse_piv_certificate_envelope(&bad).is_err());
    }

    #[test]
    fn parse_piv_envelope_rejects_missing_70() {
        let mut inner = vec![0x71, 0x01, 0x00];
        let mut env = Vec::new();
        env.push(0x53);
        push_ber_length(&mut env, inner.len());
        env.append(&mut inner);
        assert!(parse_piv_certificate_envelope(&env).is_err());
    }
}
