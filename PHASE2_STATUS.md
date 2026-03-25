# Phase 2 구현 현황

> 마지막 업데이트: 2026-03-25

## 크레이트 구조

```
crates/
  justrdp-core/       ✅ MD4 추가됨 (NTLM용)
  justrdp-pdu/        ✅ ntlm 모듈 추가됨
  justrdp-bulk/       (Phase 1, 변경 없음)
  justrdp-connector/  ✅ Connection FSM + CredSSP 모듈
  justrdp-tls/        ✅ 새 크레이트
tests/
  integration/        ✅ rdp-connect-test 바이너리
```

## 테스트 현황

- **Unit tests**: 246개 전부 pass
- **Integration test**: TCP → X.224 → TLS → NTLM Negotiate/Challenge 까지 성공, **Authenticate에서 실패**

---

## 5.1 `justrdp-connector` — Connection State Machine

| 항목 | 상태 | 파일 |
|------|------|------|
| `ClientConnector` + `Sequence` trait | ✅ 완료 | `connector.rs`, `sequence.rs` |
| `ClientConnectorState` (24 states) | ✅ 완료 | `state.rs` |
| `Config` + `ConfigBuilder` | ⚠️ 기본만 | `config.rs` — `color_depth`, `auto_reconnect_cookie`, `bitmap_codecs`, `compression` 필드 빠짐 |
| `ConnectionResult` | ✅ 완료 | `result.rs` |
| Channel Join 반복 | ✅ 완료 | `connector.rs` (join_index loop) |
| License Exchange | ⚠️ 단축경로만 | `connector.rs` — `StatusValidClient`만 처리, 전체 라이센스 교환 미구현 |
| Capabilities Exchange | ✅ 완료 | `connector.rs` — DemandActive/ConfirmActive |
| Connection Finalization | ✅ 완료 | `connector.rs` — Sync/Cooperate/RequestControl/FontList + 서버 응답 |
| Encode helpers | ✅ 완료 | `encode_helpers.rs` — TPKT+X224+MCS+ShareControl+ShareData 래핑 |

## 5.2.1 CredSSP / NLA

| 항목 | 상태 | 파일 | 비고 |
|------|------|------|------|
| `CredsspSequence` 상태 머신 | ✅ 구조 완료 | `credssp/mod.rs` | 5단계: SendNego → WaitChallenge → WaitPubKeyAuth → SendCredentials → Done |
| `TsRequest` ASN.1 DER | ✅ 완료 | `credssp/ts_request.rs` | v2-6, roundtrip 테스트 통과 |
| SPNEGO 래퍼 | ✅ 완료 | `credssp/spnego.rs` | NegTokenInit(Negotiate), NegTokenResp(Authenticate), unwrap_challenge |
| `pubKeyAuth` v2-4 | ✅ 코드 있음 | `credssp/mod.rs` | raw public key 암호화 — **서버 검증 실패** |
| `pubKeyAuth` v5+ | ✅ 코드 있음 | `credssp/mod.rs` | SHA256(magic+nonce+pubkey) — **미검증** |
| `authInfo` 자격증명 전송 | ✅ 코드 있음 | `credssp/mod.rs` | TSCredentials/TSPasswordCreds 구조 — CredSSP 통과 못해서 미검증 |
| `EarlyUserAuthResult` (HYBRID_EX) | ❌ 미구현 | | |
| `clientNonce` anti-replay (v5+) | ✅ 필드 있음 | | v5+일 때만 TsRequest에 포함 |
| CredSSP 버전 전환 | ✅ | `ts_request.rs` | 현재 v2로 설정 (디버깅용), v6으로 올려야 함 |

## 5.2.2 NTLM Authentication

| 항목 | 상태 | 파일 | 비고 |
|------|------|------|------|
| `NegotiateMessage` | ✅ 완료 | `ntlm/messages.rs` | Encode 구현, 기본 플래그 |
| `ChallengeMessage` | ✅ 완료 | `ntlm/messages.rs` | decode_from_bytes, flags/challenge/target_info 파싱 |
| `AuthenticateMessage` | ✅ 완료 | `ntlm/messages.rs` | to_bytes(), MIC 오프셋 72, Version 오프셋 64 |
| NTOWFv2 해시 | ✅ 검증됨 | `ntlm/compute.rs` | MS-NLMP 4.2.4.1.1 테스트 벡터 통과 |
| NTProofStr 생성 | ✅ 완료 | `ntlm/compute.rs` | compute_response() |
| 세션 키 파생 | ✅ 완료 | `ntlm/compute.rs` | SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr) |
| key_exchange_encrypt | ✅ 완료 | `ntlm/compute.rs` | RC4(SessionBaseKey, ExportedSessionKey) |
| MIC 계산 | ✅ 완료 | `ntlm/compute.rs` | HMAC_MD5(ExportedSessionKey, Negotiate+Challenge+Authenticate) |
| target_info 수정 | ✅ 완료 | `ntlm/compute.rs` | MsvAvFlags(0x02), MsvAvChannelBindings(Z16), MsvAvTargetName("") 추가 |
| Signing key 파생 | ✅ 완료 | `ntlm/signing.rs` | MD5(SessionKey + magic) |
| Sealing key 파생 | ✅ 완료 | `ntlm/signing.rs` | MD5(SessionKey + magic) |
| NTLM Sign (MAC) | ✅ 완료 | `ntlm/signing.rs` | HMAC-MD5 + RC4 checksum |
| NTLM Seal (encrypt) | ✅ 완료 | `ntlm/signing.rs`, `credssp/mod.rs` | encrypt data → RC4 checksum (persistent RC4 state) |
| AvPair 파싱/인코딩 | ✅ 완료 | `ntlm/messages.rs` | parse_list/encode_list, MsvAvEOL 포함 |

## 5.2.3 ~ 5.2.7

| 항목 | 상태 |
|------|------|
| 5.2.3 Kerberos | ❌ 미구현 |
| 5.2.4 Standard RDP Security | ❌ 미구현 |
| 5.2.5 Remote Credential Guard | ❌ 미구현 |
| 5.2.6 Restricted Admin Mode | ❌ 미구현 |
| 5.2.7 Azure AD (RDSTLS/AAD) | ❌ 미구현 |

## 5.3 `justrdp-tls`

| 항목 | 상태 | 파일 | 비고 |
|------|------|------|------|
| `TlsUpgrader` trait | ✅ 완료 | `lib.rs` | Read+Write+'static |
| rustls 백엔드 | ✅ 동작 확인 | `rustls_backend.rs` | 실서버 핸드셰이크 성공 |
| native-tls 백엔드 | ✅ 코드 있음 | `native_tls_backend.rs` | 실서버 미검증 |
| 서버 공개키 추출 | ✅ 동작 확인 | `lib.rs` | X.509 DER → SPKI 추출 (294 bytes) |
| 자체서명 인증서 | ✅ 동작 확인 | `danger.rs` | DangerousNoVerify |
| TLS 1.2/1.3 | ✅ | | rustls가 자동 처리 |

---

## 🔴 블로킹 이슈: NTLM Authenticate 실패

### 증상
- NTLM Negotiate → Challenge 교환 성공
- Authenticate + pubKeyAuth 전송 후 서버가 **TLS AlertReceived(InternalError)** 반환
- 서버가 TsRequest errorCode를 보내지 않고 TLS 연결 자체를 끊음

### 이미 시도한 수정 (전부 효과 없음)
1. target_info에 MsvAvFlags=0x02, MsvAvChannelBindings=Z(16), MsvAvTargetName="" 추가
2. MsvAvTimestamp 있을 때 LM response = Z(24)
3. SEAL 순서: encrypt data → encrypt checksum (IronRDP 동일)
4. RC4 sealing state를 persistent로 (메시지마다 재초기화 X)
5. CredSSP v2로 다운그레이드 (raw pubkey, nonce 없음)
6. temp 구조에서 trailing Z(4) 제거 (IronRDP 동일)
7. 빈 domain으로 NTOWFv2 호출

### 디버깅 필요 사항

**1. Wireshark 캡처 비교 (최우선)**
- mstsc.exe로 동일 서버(192.168.136.136)에 rdptest/qweQWEqwe! 로 연결
- Wireshark에서 TLS 내부 CredSSP 메시지 캡처 (TLS key log 필요)
- 우리 바이너리의 NTLM Authenticate 메시지와 바이트 단위 비교
- 특히: NegotiateFlags, temp 구조, AvPairs, NTProofStr 값 비교

**2. NTLM Authenticate 메시지 구조 검증**
- Authenticate의 NegotiateFlags가 올바른 값인지 (client AND server flags)
- Version 필드가 올바른지 (NTLMSSP_NEGOTIATE_VERSION 플래그에 따라)
- 페이로드 offset들이 정확히 88부터 시작하는지
- LM response가 정말 Z(24)인지

**3. SPNEGO 래핑 검증**
- NegTokenResp 구조가 RFC 4178과 정확히 일치하는지
- OID가 맞는지 (1.3.6.1.4.1.311.2.2.10)
- negState 필드 필요 여부

**4. pubKeyAuth 암호화 검증**
- NTLM seal 출력 형식: signature(16) + encrypted_data
- v2에서 서버 공개키 전체(SPKI)를 암호화하는 게 맞는지, 아니면 SubjectPublicKey(BIT STRING 내부)만인지
  - MS-CSSP: "ASN.1-encoded SubjectPublicKey sub-field of SubjectPublicKeyInfo" (v2-4)
  - 현재 구현: SPKI 전체를 암호화 → **SubjectPublicKey만 추출해서 암호화해야 할 수 있음**

**5. HMAC 버퍼 사이즈 제한**
- `justrdp-core/src/crypto.rs`의 HMAC 구현에 `combined` 버퍼가 1024 바이트 고정
- NTLM Authenticate + Challenge + Negotiate concatenation이 1024 넘으면 MIC 계산 오류
- MIC 계산 시 3개 메시지 합치면 ~700+ bytes → 확인 필요

### 의심 가는 근본 원인 (우선순위순)

1. **pubKeyAuth에 SPKI 전체 대신 SubjectPublicKey만 써야 함** — MS-CSSP가 명시적으로 "SubjectPublicKey sub-field"라고 함
2. **HMAC 1024 byte 버퍼 오버플로우** — MIC 계산 시 silent truncation 가능성
3. **SPNEGO NegTokenResp 구조 미세 차이** — negState, supportedMech 필드 누락

---

## 다음 단계

### 즉시 해야 할 것
1. `pubKeyAuth`에서 SPKI가 아닌 SubjectPublicKey(내부 BIT STRING)만 추출해서 암호화하도록 수정
2. HMAC 버퍼 사이즈 제한 제거 (dynamic allocation으로 교체)
3. Wireshark로 mstsc.exe와 바이트 비교

### CredSSP 통과 후
4. MCS Basic Settings Exchange → Channel Join → Licensing → Capabilities → Finalization → Connected 검증
5. CredSSP v6으로 업그레이드

### 선택적 (후순위)
6. 5.2.3 Kerberos
7. 5.2.4 Standard RDP Security
8. 5.2.5~5.2.7 기타 인증
9. Config 필드 완성 (color_depth, bitmap_codecs 등)
10. 전체 라이센스 교환 (Valid Client 외)

---

## 테스트 환경

- **서버**: 192.168.136.136:3389 (Windows RDP)
- **계정**: rdptest / qweQWEqwe!
- **실행**: `cargo run -p justrdp-integration-tests --bin rdp-connect-test -- 192.168.136.136 3389 rdptest 'qweQWEqwe!'`
  - bash에서 `!` 이스케이프 문제 → 코드에서 `\!` → `!` 변환 처리됨
