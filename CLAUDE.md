# justrdp

바닥부터 짜는 **순수 Rust RDP 클라이언트 라이브러리**. `ironrdp` 을 대체하되, RDP 고유 프로토콜 층(X.224·MCS·GCC·capability·session loop·virtual channel·codec·surface)을 *전부 자체 소유*하고, 보안 크리티컬·비-RDP 크레이트(`rustls`=TLS, `sspi`=NLA)만 위임한다. 코어는 **sans-IO 상태머신** — connect 시퀀스와 session loop 이 순수 상태변환(bytes in → actions/bytes out)이고, tokio I/O 어댑터가 그걸 현실로 만든다. 어댑터의 *구동 루프* 자체는 `Action` 에 대한 match 수십 줄이지만, 크레이트 전체는 그것만이 아니다 — TLS 핸드셰이크·CredSSP 토큰 루프·스테이지별 타임아웃·세션 러너가 같이 산다(코드 ~1,000줄). 코어에 두지 *않기로* 한 것들이 거기 모여 있는 것이다.

- **상세 계약(구현 시 참조)**: `CONTEXT.md`(ubiquitous language·경계) + `docs/adr/`(결정 근거) + `docs/plan.md`(빌드플랜 §2–§23).
- **첫 동기**: ironrdp-connector 0.9.0 이 `SUPPORT_DYN_VC_GFX_PROTOCOL`(0x0100) 를 빠뜨려 EGFX 를 못 켜는 단일-플래그 감춤 — 호스트가 *모든* RDP 피처 플래그를 쥐게 하려는 재작성. 자세히는 `CONTEXT.md` §Project intent.

## 작업 규율 — `thegraph`

Substantive 변경이면 **`thegraph` 스킬**로 짠다 — 착수 시 `/thegraph`. 고정된 step 목록이
아니라 **노드 카탈로그 + 네 invariant**이고, 이 repo 의 실제 그래프(어느 노드가 몇 개
있는지, 각 가드와 decider, 무엇이 에이전트·스크립트로 추출됐는지)는 **계약 문서
`docs/agents/thegraph.md`** 에 컴파일돼 있다 — 착수 전에 그것을 연다.

두 표는 **`docs/agents/theflow.md` 가 계속 소유**한다: layer 별 **tie-breaker**(무엇이
논쟁을 이기는가)와 **deliberate divergence 23행**(어느 논쟁이 이미 끝났는가). 이슈가
랜딩할 때마다 수정되는 표라 사본을 두지 않는다 — 그 파일이 은퇴하면 표를 *옮긴다*, 지우지
않는다. 규칙에 이빨을 주는 실증(ADR·이슈 앵커)은 **`docs/agents/lessons.md`**.

(`theflow` 는 여전히 유효한 형제 규율이고 `/theflow` 로 부를 수 있다. 기본은 `thegraph`.)

## 착수 전 배선도 — `docs/map/`

**무엇을 건드리면 무엇이 같이 움직이는지**(영토별 `## Blast radius`)와 **영토를 넘어 성립하는
사실**(`invariant/`)의 지도. 허브는 **[`docs/map/README.md`](docs/map/README.md)**. 설계를
확정하기 *전에* 연다 — `map` 노드는 `boundary` 보다 **앞**에 있고, `verify` 의
corpus ① 과 `sweep` 이 다시 읽는다. ADR 은 *결정이 다퉈진 날*로, plan.md 는 *빌드 순서*로 색인돼 있어 이 질문에 답하지 못한다.

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
`justrdp-pdu`(무의존 PDU) · `justrdp`(sans-IO 코어) · `justrdp-codecs`(코덱 — 전부 자체 소유, ironrdp-graphics 는 **dev 오라클로만**; #189 이후 런타임 그래프에 ironrdp 없음) · `justrdp-tokio`(~30줄 I/O 어댑터 — tokio/sspi/rustls 는 여기만) · `fuzz`(워크스페이스 밖, nightly). 상세 표·`--workspace` 사각지대는 `docs/agents/theflow.md`.

**위임 의존(ADR-0002, 전부 leaf·보안 크리티컬·비-RDP)**: `rustls`(`ring` provider)·`rustls-platform-verifier`(#36)·`sspi`·`x509-cert`. **sspi 포크 브리지는 끝났다(2026-08-10)**: `[patch.crates-io]` 제거, `sspi = "=0.21.3"` 정확 핀(ADR-0004 Decision 이 요구하는 형태). Devolutions/sspi-rs#689 가 0.21.1 로 출시되며 탈출 조건이 충족됐고, 루프백 full-CredSSP 테스트가 퍼블리시 크레이트에서 통과한다. **실 VM 스위트도 통과한다** — VM 이 재구축되며 자격증명이 살아났고, 전체 스위트가 병렬 15/15(2026-08-19, #198). 이 문장은 한동안 `STATUS_LOGON_FAILURE` 로 막혀 있다고 적혀 있었다(클라이언트 회귀 아님은 A/B 로 확인됐었다). ADR-0004 Amendment(2026-08-10) + [`docs/map/territory/nla-credssp.md`](docs/map/territory/nla-credssp.md).

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
네 게이트: `test.yml`(build/test/clippy + map) + `fuzz.yml`(nightly cargo-fuzz) + `supply-chain.yml`(just-shield, ADR-0006) + `overflow-32bit.yml`(i686 — x64 게이트가 **구조적으로** 못 잡는 dimension-overflow 클래스, path-filtered). 상세는 **`docs/agents/thegraph.md` § `gate`**(8게이트·9커맨드·사각지대) + 메모리
`justrdp_ci_policy`. 실행 가능한 사본은 **`scripts/thegraph/gates.py`** 하나다 — 각
게이트를 파이프 없이 bare 로 돌린다.

**컴파일러는 핀돼 있다(ADR-0013, #235)** — `rust-toolchain.toml` 이 정확 버전을 고정하고 `rust-toolchain` Dependabot ecosystem 이 올린다. 그래서 로컬 게이트가 CI 를 미러한다; 그 전엔 3개월 차이가 나서 CI 를 빨갛게 만든 lint 가 로컬에선 **아예 발화하지 못했다**. nightly 는 `+nightly` 가 핀을 이기므로 fuzz 레인은 무영향.
