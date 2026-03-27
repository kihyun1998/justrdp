#![forbid(unsafe_code)]

//! NTLMv2 cryptographic computations (MS-NLMP 3.3.2).

use alloc::vec;
use alloc::vec::Vec;

use justrdp_core::crypto::{hmac_md5, md4, Rc4};

use super::messages::{to_utf16le, AvId, AvPair};

/// Compute NTOWFv2: HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user) + domain))
///
/// MS-NLMP 3.3.2
///
/// Note: MS-NLMP specifies OEM uppercase (ASCII uppercase only).
/// Unicode case folding (e.g., German sharp-s ß → SS) is NOT applied.
pub fn ntowfv2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let password_utf16 = to_utf16le(password);
    let nt_hash = md4(&password_utf16);

    // OEM uppercase: only convert ASCII a-z to A-Z
    let upper_user: alloc::string::String =
        user.chars().map(|c| if c.is_ascii_lowercase() { c.to_ascii_uppercase() } else { c }).collect();
    let concat = alloc::format!("{}{}", upper_user, domain);
    let user_domain_utf16 = to_utf16le(&concat);

    hmac_md5(&nt_hash, &user_domain_utf16)
}

/// Modify the server's target_info for NTLMv2 response computation.
///
/// Per MS-NLMP 3.1.5.1.2:
/// 1. If MsvAvTimestamp present, set MsvAvFlags bit 0x02 (MIC provided)
/// 2. Add MsvAvChannelBindings = Z(16) (no channel bindings)
/// 3. Add MsvAvTargetName = "" (empty, as UTF-16LE)
///
/// Returns the modified target_info as encoded AV_PAIR bytes.
pub fn modify_target_info(server_target_info: &[u8]) -> Vec<u8> {
    let mut pairs = AvPair::parse_list(server_target_info).unwrap_or_default();

    let has_timestamp = pairs.iter().any(|p| p.id == AvId::MsvAvTimestamp as u16);

    if has_timestamp {
        // Set MsvAvFlags bit 0x02 (MIC_PROVIDED)
        let flags_idx = pairs.iter().position(|p| p.id == AvId::MsvAvFlags as u16);
        if let Some(idx) = flags_idx {
            // Modify existing flags
            if pairs[idx].value.len() >= 4 {
                let mut flags = u32::from_le_bytes(pairs[idx].value[..4].try_into().unwrap());
                flags |= 0x02; // MIC_PROVIDED
                pairs[idx].value = flags.to_le_bytes().to_vec();
            }
        } else {
            // Add new MsvAvFlags with MIC_PROVIDED
            pairs.push(AvPair {
                id: AvId::MsvAvFlags as u16,
                value: 0x0002u32.to_le_bytes().to_vec(),
            });
        }
    }

    // Add MsvAvChannelBindings = Z(16) if not present
    if !pairs.iter().any(|p| p.id == AvId::MsvAvChannelBindings as u16) {
        pairs.push(AvPair {
            id: AvId::MsvAvChannelBindings as u16,
            value: vec![0u8; 16],
        });
    }

    // Add MsvAvTargetName = "" if not present
    if !pairs.iter().any(|p| p.id == AvId::MsvAvTargetName as u16) {
        pairs.push(AvPair {
            id: AvId::MsvAvTargetName as u16,
            value: Vec::new(),
        });
    }

    AvPair::encode_list(&pairs)
}

/// Compute NTLMv2 response and session base key.
///
/// `target_info` should be the MODIFIED target info (after `modify_target_info`).
///
/// Returns (nt_response, lm_response, session_base_key).
///
/// MS-NLMP 3.3.2: ComputeResponse
pub fn compute_response(
    response_key_nt: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    time: u64,
    target_info: &[u8],
    has_timestamp: bool,
) -> (Vec<u8>, Vec<u8>, [u8; 16]) {
    // ── NTLMv2 Response ──
    // temp = Responserversion(1) + HiResponserversion(1) + Z(6) + Time(8) +
    //        ClientChallenge(8) + Z(4) + ServerName(=modified_target_info) + Z(4)
    // NTLMv2_CLIENT_CHALLENGE structure:
    // RespType(1) + HiRespType(1) + Reserved1(2) + Reserved2(4) + TimeStamp(8) +
    // ChallengeFromClient(8) + Reserved3(4) + AvPairs(variable, including MsvAvEOL)
    let mut temp = Vec::with_capacity(28 + target_info.len());
    temp.push(0x01); // RespType
    temp.push(0x01); // HiRespType
    temp.extend_from_slice(&[0u8; 2]); // Reserved1
    temp.extend_from_slice(&[0u8; 4]); // Reserved2
    temp.extend_from_slice(&time.to_le_bytes()); // TimeStamp
    temp.extend_from_slice(client_challenge); // ChallengeFromClient
    temp.extend_from_slice(&[0u8; 4]); // Reserved3
    temp.extend_from_slice(target_info); // AvPairs (includes MsvAvEOL terminator)
    temp.extend_from_slice(&[0u8; 4]); // Z(4) trailing pad per MS-NLMP 3.3.2

    // NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge + temp)
    let mut nt_proof_input = Vec::with_capacity(8 + temp.len());
    nt_proof_input.extend_from_slice(server_challenge);
    nt_proof_input.extend_from_slice(&temp);
    let nt_proof_str = hmac_md5(response_key_nt, &nt_proof_input);

    // NtChallengeResponse = NTProofStr + temp
    let mut nt_response = Vec::with_capacity(16 + temp.len());
    nt_response.extend_from_slice(&nt_proof_str);
    nt_response.extend_from_slice(&temp);

    // SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
    let session_base_key = hmac_md5(response_key_nt, &nt_proof_str);

    // ── LMv2 Response ──
    // If MsvAvTimestamp is present, client SHOULD NOT send LmChallengeResponse
    // and SHOULD send Z(24) instead (MS-NLMP 3.1.5.1.2)
    let lm_response = if has_timestamp {
        vec![0u8; 24]
    } else {
        let mut lm_input = Vec::with_capacity(16);
        lm_input.extend_from_slice(server_challenge);
        lm_input.extend_from_slice(client_challenge);
        let lm_proof_str = hmac_md5(response_key_nt, &lm_input);

        let mut lm_resp = Vec::with_capacity(24);
        lm_resp.extend_from_slice(&lm_proof_str);
        lm_resp.extend_from_slice(client_challenge);
        lm_resp
    };

    (nt_response, lm_response, session_base_key)
}

/// Compute MIC (Message Integrity Code) for the three NTLM messages.
///
/// MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE_MESSAGE + CHALLENGE_MESSAGE + AUTHENTICATE_MESSAGE)
///
/// The AUTHENTICATE_MESSAGE MUST have the MIC field (offset 72..88) zeroed.
pub fn compute_mic(
    exported_session_key: &[u8; 16],
    negotiate_bytes: &[u8],
    challenge_bytes: &[u8],
    authenticate_bytes: &[u8],
) -> [u8; 16] {
    let mut data = Vec::with_capacity(
        negotiate_bytes.len() + challenge_bytes.len() + authenticate_bytes.len(),
    );
    data.extend_from_slice(negotiate_bytes);
    data.extend_from_slice(challenge_bytes);
    data.extend_from_slice(authenticate_bytes);
    hmac_md5(exported_session_key, &data)
}

/// Compute EncryptedRandomSessionKey.
///
/// EncryptedRandomSessionKey = RC4K(KeyExchangeKey, ExportedSessionKey)
/// For NTLMv2: KeyExchangeKey = SessionBaseKey
pub fn key_exchange_encrypt(
    session_base_key: &[u8; 16],
    exported_session_key: &[u8; 16],
) -> Vec<u8> {
    let mut rc4 = Rc4::new(session_base_key);
    let mut encrypted = vec![0u8; 16];
    encrypted.copy_from_slice(exported_session_key);
    rc4.process(&mut encrypted);
    encrypted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntowfv2_test_vector() {
        // MS-NLMP 4.2.4.1.1: User="User", Password="Password", Domain="Domain"
        let result = ntowfv2("Password", "User", "Domain");
        assert_eq!(
            result,
            [0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93,
             0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f]
        );
    }

    #[test]
    fn compute_response_basic() {
        let response_key = ntowfv2("Password", "User", "Domain");
        let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let client_challenge = [0xaa; 8];
        let time: u64 = 0;
        let target_info = &[];

        let (nt_response, lm_response, session_base_key) =
            compute_response(&response_key, &server_challenge, &client_challenge, time, target_info, false);

        assert!(nt_response.len() >= 16);
        assert_eq!(lm_response.len(), 24);
        assert_eq!(session_base_key.len(), 16);
    }

    /// MS-NLMP 4.2.4: NTLMv2 NTProofStr, SessionBaseKey, LmProofStr KAT.
    ///
    /// Test vectors from MS-NLMP sections 4.2.4.1 through 4.2.4.2.
    /// TargetInfo = MsvAvNbDomainName("Domain") + MsvAvNbComputerName("Server") + MsvAvEOL.
    /// The temp blob includes a trailing Z(4) after the AV_PAIRS (per 4.2.4.1.3).
    #[test]
    fn compute_response_kat_ms_nlmp_4_2_4() {
        let response_key = ntowfv2("Password", "User", "Domain");
        let server_challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let client_challenge: [u8; 8] = [0xaa; 8];
        let time: u64 = 0;

        // MS-NLMP 4.2.4: TargetInfo (ServerName) from CHALLENGE_MESSAGE
        // MsvAvNbDomainName(0x0002, "Domain") + MsvAvNbComputerName(0x0001, "Server") + MsvAvEOL
        #[rustfmt::skip]
        let target_info: &[u8] = &[
            0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
            0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let (nt_response, lm_response, session_base_key) =
            compute_response(&response_key, &server_challenge, &client_challenge, time, target_info, false);

        // MS-NLMP 4.2.4.2.2: NTProofStr (first 16 bytes of NtChallengeResponse)
        assert_eq!(
            &nt_response[..16],
            &[0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96,
              0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef, 0x6a, 0x1c],
            "NTProofStr does not match MS-NLMP 4.2.4.2.2"
        );

        // MS-NLMP 4.2.4.1.2: SessionBaseKey
        assert_eq!(
            session_base_key,
            [0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82,
             0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9, 0x5c, 0xa3],
            "SessionBaseKey does not match MS-NLMP 4.2.4.1.2"
        );

        // MS-NLMP 4.2.4.2.1: LMv2 Response (no timestamp → LmProofStr + ClientChallenge)
        assert_eq!(lm_response.len(), 24);
        assert_eq!(
            &lm_response[..16],
            &[0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10,
              0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19],
            "LmProofStr does not match MS-NLMP 4.2.4.2.1"
        );
        assert_eq!(&lm_response[16..], &[0xaa; 8]);
    }

    #[test]
    fn lm_response_zeroed_when_timestamp_present() {
        let response_key = ntowfv2("Password", "User", "Domain");
        let server_challenge = [0x01; 8];
        let client_challenge = [0xBB; 8];

        let (_, lm_response, _) =
            compute_response(&response_key, &server_challenge, &client_challenge, 0, &[], true);

        assert_eq!(lm_response, vec![0u8; 24]);
    }

    #[test]
    fn modify_target_info_adds_required_pairs() {
        let pairs = vec![
            AvPair::new(AvId::MsvAvNbDomainName, to_utf16le("DOMAIN")),
            AvPair::new(AvId::MsvAvTimestamp, vec![0u8; 8]),
        ];
        let original = AvPair::encode_list(&pairs);
        let modified = modify_target_info(&original);
        let result = AvPair::parse_list(&modified).unwrap();

        // Should have: NbDomainName, Timestamp, Flags(0x02), ChannelBindings, TargetName
        assert!(result.iter().any(|p| p.id == AvId::MsvAvFlags as u16));
        assert!(result.iter().any(|p| p.id == AvId::MsvAvChannelBindings as u16));
        assert!(result.iter().any(|p| p.id == AvId::MsvAvTargetName as u16));

        // MsvAvFlags should have bit 0x02 set
        let flags_pair = result.iter().find(|p| p.id == AvId::MsvAvFlags as u16).unwrap();
        let flags = u32::from_le_bytes(flags_pair.value[..4].try_into().unwrap());
        assert_eq!(flags & 0x02, 0x02);
    }

    #[test]
    fn key_exchange_roundtrip() {
        let session_base_key = [0x01u8; 16];
        let exported_key = [0x02u8; 16];

        let encrypted = key_exchange_encrypt(&session_base_key, &exported_key);
        let mut rc4 = Rc4::new(&session_base_key);
        let mut decrypted = encrypted.clone();
        rc4.process(&mut decrypted);
        assert_eq!(&decrypted, &exported_key);
    }
}
