# JustRDP Development Guide

## Project Overview

Pure Rust RDP library. `no_std` core, zero C dependencies. Uses `Encode`/`Decode` traits with `ReadCursor`/`WriteCursor` for all PDU serialization.

## Crate Structure

- `justrdp-core` — Encode/Decode traits, cursors, crypto primitives (RC4, AES, DES, RSA, SHA, MD5, HMAC)
- `justrdp-pdu` — All protocol data units (X.224, MCS, GCC, RDP capabilities, fast-path, drawing orders)
- `justrdp-connector` — Connection state machine, CredSSP/NLA, Kerberos, RDSTLS
- `justrdp-tls` — TLS transport abstraction (rustls/native-tls backends)
- `justrdp-bulk` — Compression (MPPC, NCRUSH, XCRUSH)

## Implementation Flow (MUST FOLLOW)

새로운 프로토콜 섹션을 구현할 때 반드시 이 순서를 따릅니다:

### Step 1: Spec Analysis (구현 전)
```
@spec-checker [roadmap 섹션 이름]
```
- 스펙을 분석하고 와이어 포맷, 상수값, 암호 스텝 등의 체크리스트 생성
- 이 체크리스트를 구현 시 참조

### Step 2: Implementation (구현)
- spec-checker 체크리스트를 보며 코드 작성
- 모든 상수값은 스펙에서 직접 복사
- 경계값 테스트 반드시 포함 (0, max, form 전환 경계)

### Step 3: Verification (검증 — 커밋 전)
```
@impl-verifier [변경된 파일 경로들]
```
- 코드를 스펙과 1:1 대조
- FAIL 항목이 있으면 수정 후 재검증
- 모든 항목 PASS 확인 후 커밋

### Step 4: Test Gap Analysis (선택적)
```
@test-gap-finder [모듈 경로]
```
- Critical 갭이 있으면 테스트 추가

## Code Conventions

### PDU 구현 패턴
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyPdu {
    pub field1: u16,
    pub field2: Vec<u8>,
}

impl Encode for MyPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> { ... }
    fn name(&self) -> &'static str { "MyPdu" }
    fn size(&self) -> usize { ... }  // MUST match encode() output exactly
}

impl<'de> Decode<'de> for MyPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> { ... }
}
```

### 규칙
- `size()`와 `encode()`의 출력 바이트 수는 반드시 일치해야 함
- 모든 상수는 스펙 섹션 번호를 주석에 기재
- `#![forbid(unsafe_code)]` 모든 파일 상단
- `#![no_std]` + `extern crate alloc` (core/pdu crates)
- 테스트에서 roundtrip (encode → decode → assert_eq) 필수
- 경계값 테스트 필수 (short/long form, 0, max)

### Crypto 규칙
- 순수 Rust 구현 (외부 crypto crate 없음)
- NIST/RFC 테스트 벡터가 있으면 반드시 포함
- 키 파생 스텝은 스펙 순서 그대로 구현 (최적화보다 명확성)

### Connector 규칙
- 상태 머신은 `ClientConnectorState` enum으로 관리
- `is_send_state()`에 새 send 상태 추가 잊지 말 것
- `next_pdu_hint()`에 새 wait 상태의 PDU hint 추가
- Standard RDP Security: `decrypt_server_data()` / `encrypt_and_send_mcs()` 사용
- Config에 새 필드 추가 시 builder 메서드도 추가

## Roadmap

`roadmap.md` 참조. `[x]` = 구현 완료, `[ ]` = 미구현.

## Test

```bash
cargo test                          # 전체
cargo test -p justrdp-core          # core만
cargo test -p justrdp-pdu -- mcs    # MCS 모듈만
```

## Agent skills

### Issue tracker

GitHub Issues at `kihyun1998/justrdp` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical names used as-is (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

**Language policy**: `CONTEXT.md` and every file under `docs/adr/` MUST be written
in English. This is the only project artifact with that constraint — `roadmap.md`,
this `CLAUDE.md`, code comments, and commit messages may stay in Korean. Rationale:
domain docs are the cross-readable reference (open-source contributors, future
tooling, indexing) and need to stay accessible without translation.
