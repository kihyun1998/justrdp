# justrdp

바닥부터 짜는 **순수 Rust RDP 클라이언트 라이브러리**. `ironrdp` 을 대체하되, RDP 고유 프로토콜 층(X.224·MCS·GCC·capability·session loop·virtual channel·codec·surface)을 *전부 자체 소유*하고, 보안 크리티컬·비-RDP 크레이트(`rustls`=TLS, `sspi`=NLA)만 위임한다. 코어는 **sans-IO 상태머신** — connect 시퀀스와 session loop 이 순수 상태변환(bytes in → actions/bytes out)이고, ~30줄 tokio I/O 어댑터가 그걸 현실로 만든다.

- **상세 계약(구현 시 참조)**: `CONTEXT.md`(ubiquitous language·경계) + `docs/adr/`(결정 근거) + `docs/plan.md`(빌드플랜 §2–§23).
- **첫 동기**: ironrdp-connector 0.9.0 이 `SUPPORT_DYN_VC_GFX_PROTOCOL`(0x0100) 를 빠뜨려 EGFX 를 못 켜는 단일-플래그 감춤 — 호스트가 *모든* RDP 피처 플래그를 쥐게 하려는 재작성. 자세히는 `CONTEXT.md` §Project intent.

## 작업 규율 — `theflow`

Substantive 변경이면 **`theflow` 스킬**로 짠다 — 착수 시 `/theflow`. 이 repo 전용 바인딩
(크레이트 맵·스펙 라우팅·경계 규칙·oracle/VM 증명·게이트)은 **`docs/agents/theflow.md`**,
규칙에 이빨을 주는 실증(ADR·이슈 앵커)은 **`docs/agents/lessons.md`** 에 산다. 착수 전에
둘 다 읽는다. (justerm 과 같은 규율의 형제 — flow·mindset 은 이제 theflow 가 담는다.)

## 경계 invariant (이게 정체성)

justrdp 가 **하는 것**: 와이어 파싱 → connect 상태머신 구동 → session loop 이 graphics/input PDU 를 dispatch → *FrameUpdate*(rect + RGBA8888 픽셀)·입력 응답·채널 데이터를 호스트에 노출.

justrdp 가 **하지 않는 것** (의존성으로 끌어들이지도 말 것):
- **I/O 없음** — 소켓/런타임 안 읽음. 호스트 어댑터가 bytes 를 코어에 feed 한다.
- **런타임 embed 없음** — 코어는 tokio/async 를 모른다. 어댑터만 안다.
- **정책 무지** — TLS 신뢰(ADR-0005)·자격증명 출처·frame sink 동작은 *호스트가 주입*. 코어는 policy-agnostic.

→ 결과: 소켓도 런타임도 없이 **독립·결정론적 테스트 가능** (오라클 왕복 + 실 VM).

**메커니즘은 core, 정책은 어댑터 (라우팅 규칙, ADR-0001).** 와이어 파싱·상태전이·코덱은 pure state machine core; TLS 신뢰·자격증명·frame sink 는 어댑터(`justrdp-tokio`)가 주입. sspi·rustls 는 보안 크리티컬·비-RDP 라 어댑터에 산다 — 코어는 TSRequest 를 영영 안 본다.

## 크레이트 구조 (ADR-0001)

가상 워크스페이스(edition 2024). 멤버 4 + 워크스페이스 밖 `fuzz`:
`justrdp-pdu`(무의존 PDU) · `justrdp`(sans-IO 코어) · `justrdp-codecs`(코덱, ironrdp-graphics 오라클) · `justrdp-tokio`(~30줄 I/O 어댑터 — tokio/sspi/rustls 는 여기만) · `fuzz`(워크스페이스 밖, nightly). 상세 표·`--workspace` 사각지대는 `docs/agents/theflow.md`.

**위임 의존(ADR-0002, 전부 leaf·보안 크리티컬·비-RDP)**: `rustls`(`ring` provider)·`rustls-platform-verifier`(#36)·`sspi`·`x509-cert`. **sspi fork patch(임시)**: `[patch.crates-io]` 로 `kihyun1998/sspi-rs` 를 탐 — Devolutions/sspi-rs#689 가 crates.io 에 풀리면 제거+범프(ADR-0004, #61; 메모리 `sspi_rs_contribution_setup`).

## 핵심 규칙

- **주석**: 영어. **CONTEXT.md·docs/adr/·docs/agents/**: 영어(LLM 토큰 효율). 그 외 사람이 읽는 문서·CLAUDE.md: 한국어.
- **네이밍**: Rust 관용(snake_case 함수/모듈, CamelCase 타입).
- **커밋 메시지**: `feat(<scope>): … (#issue)`. **`Co-Authored-By`·AI attribution 금지**(메모리 `feedback_no_ai_attribution_external`).
- **이슈 생성**: 항상 triage + type 라벨(메모리 `feedback_label_issues_on_creation`).
- **phase 경계에서 "멈출까요?" 묻지 않기** — 합의된 다단계 계획이면 그냥 이어간다(메모리 `feedback_no_stop_prompts`).

## Agent skills

### Issue tracker
Issues and PRDs are tracked as GitHub issues on `kihyun1998/justrdp`, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels
Five canonical triage roles mapped 1:1 to default label strings (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs
Single-context: one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### CI gates
세 게이트: `test.yml`(build/test/clippy) + `fuzz.yml`(nightly cargo-fuzz) + `supply-chain.yml`(just-shield, ADR-0006). 상세는 메모리 `justrdp_ci_policy` + `docs/agents/theflow.md` Step 7.
