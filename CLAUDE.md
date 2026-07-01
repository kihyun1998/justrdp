# justrdp

바닥부터 짜는 **순수 Rust RDP 클라이언트 라이브러리**. `ironrdp` 을 대체하되, RDP 고유 프로토콜 층(X.224·MCS·GCC·capability·session loop·virtual channel·codec·surface)을 *전부 자체 소유*하고, 보안 크리티컬·비-RDP 크레이트(`rustls`=TLS, `sspi`=NLA)만 위임한다. 코어는 **sans-IO 상태머신** — connect 시퀀스와 session loop 이 순수 상태변환(bytes in → actions/bytes out)이고, ~30줄 tokio I/O 어댑터가 그걸 현실로 만든다.

- **상세 계약(구현 시 참조)**: `CONTEXT.md`(ubiquitous language·경계) + `docs/adr/`(결정 근거) + `docs/plan.md`(빌드플랜 §2–§23). 이 repo 안에서 전부 참조 가능.
- **첫 동기**: ironrdp-connector 0.9.0 이 `SUPPORT_DYN_VC_GFX_PROTOCOL`(0x0100) 를 빠뜨려 EGFX 를 못 켜는 단일-플래그 감춤 — 호스트가 *모든* RDP 피처 플래그를 쥐게 하려는 재작성. 자세히는 `CONTEXT.md` §Project intent.

## 경계 invariant (이게 정체성)

justrdp 가 **하는 것**: 와이어 파싱 → connect 상태머신 구동 → session loop 이 graphics/input PDU 를 dispatch → *FrameUpdate*(rect + RGBA8888 픽셀)·입력 응답·채널 데이터를 호스트에 노출.

justrdp 가 **하지 않는 것** (의존성으로 끌어들이지도 말 것):
- **I/O 없음** — 소켓/런타임 안 읽음. 호스트 어댑터가 bytes 를 코어에 feed 한다.
- **런타임 embed 없음** — 코어는 tokio/async 를 모른다. 어댑터만 안다.
- **정책 무지** — TLS 신뢰(ADR-0005)·자격증명 출처·frame sink 동작은 *호스트가 주입*. 코어는 policy-agnostic.

→ 결과: 소켓도 런타임도 없이 **독립·결정론적 테스트 가능** (오라클 왕복 + 실 VM).

**core 냐 어댑터냐 (라우팅 규칙, ADR-0001)**: 기능의 *메커니즘*(와이어 파싱·상태전이·코덱)은 pure state machine **core**; *정책*(TLS 신뢰·자격증명·frame sink)은 **어댑터**가 주입. sspi(NLA CredSSP 토큰 루프)·rustls 는 보안 크리티컬·비-RDP 라 *어댑터*(`justrdp-tokio`)에 산다 — 코어는 TSRequest 를 영영 안 본다.

## 크레이트 구조 (ADR-0001 + plan.md 결정 6)

가상 워크스페이스(루트에 `[package]` 없음, edition 2024). 멤버 4 + 워크스페이스 밖 `fuzz`:

- **`justrdp-pdu`** — *무의존* PDU encode/decode. 외부 크레이트 0.
- **`justrdp`** — sans-IO 코어(connect/session 상태머신) + 리크 없는 leaf 의존(`rustls`·`x509-cert`).
- **`justrdp-codecs`** — 코덱. `ironrdp-graphics` 를 *dev-dependency 오라클*로 두고 phased-c2 로 자체 소유해 나간다(ADR-0003).
- **`justrdp-tokio`** — ~30줄 I/O 어댑터. `tokio`·`sspi`·`tokio-rustls` 는 여기만.
- **`fuzz/`** — 워크스페이스 밖(자체 `[workspace]`). 커버리지 유도 cargo-fuzz, nightly CI 전용(#99).

## 기술 스택

- Rust edition 2024. 위임 의존(ADR-0002, 전부 leaf·보안 크리티컬·비-RDP): `rustls`(TLS, `ring` provider — Windows NASM 회피)·`rustls-platform-verifier`(OS 신뢰 저장소, #36)·`sspi`(CredSSP/SPNEGO/NTLM/Kerberos)·`x509-cert`(SPKI 추출).
- **sspi fork patch (임시)**: `[patch.crates-io]` 로 `kihyun1998/sspi-rs` 를 탐. Devolutions/sspi-rs#689(loopback CredSSP 수정) 가 crates.io 에 풀리면 *제거*하고 sspi 범프(ADR-0004, issue #61). 상세는 메모리 `sspi_rs_contribution_setup`.

## 개발 명령어

```bash
cargo test --workspace          # 멤버 전부 게이트 (--workspace 필수: 루트가 가상 매니페스트)
cargo clippy --workspace --all-targets
cargo fmt --all --check
cargo check --manifest-path fuzz/Cargo.toml   # 워크스페이스 밖 사각지대 — 공개표면 변경 후 별도 검증
```

**`--workspace` 밖 사각**: `fuzz` 는 의도적으로 워크스페이스 밖이라 `--workspace` 게이트가 *빌드조차 안 한다* — 공개 API 를 바꾸면 별도 `cargo check --manifest-path fuzz/Cargo.toml` 로 검증한다.

## 핵심 규칙

- **주석**: 영어. **CONTEXT.md / docs/adr/**: 영어(LLM 토큰 효율). 그 외 사람이 읽는 문서·CLAUDE.md: 한국어.
- **네이밍**: Rust 관용(snake_case 함수/모듈, CamelCase 타입).
- **커밋 메시지**: 관련 GitHub 이슈 번호 참조(`feat(<scope>): … (#issue)`). **`Co-Authored-By`·AI attribution 금지**(메모리 `feedback_no_ai_attribution_external`).
- **이슈 생성**: 항상 triage + type 라벨을 붙인다(`docs/agents/triage-labels.md`, 메모리 `feedback_label_issues_on_creation`).
- **phase 경계에서 "멈출까요?" 묻지 않기** — 합의된 다단계 계획이면 그냥 이어간다(메모리 `feedback_no_stop_prompts`).

## 사고방식

아키텍처/설계 결정은 **스펙 도출 + 명명된 참조(FreeRDP·IronRDP·실 VM) 교차검증**을 함께 한다. RDP 는 터미널과 달리 *규범 스펙*(`[MS-RDPBCGR]` 등)이 존재 — 여기가 "1원리" 출처다. 단 **스펙 ≠ 상호운용**: 스펙대로 짜도 실 서버와 byte-identical 이 아닐 수 있다 → 도출은 스펙, 증명은 오라클/VM.

**결정 유형으로 라우팅한다.** 순수 기술 메커니즘(와이어 포맷·PDU 레이아웃·플래그·좌표계 — 스펙+실소스로 *도출 가능*한 것)은 사용자에게 grilling 하지 말고 **직접 결정 → 실소스/오라클 대조 검증 → 결과만 제시**(yes/no 승인). 답이 스펙에 있는 걸 묻는 건 일 떠넘기기다. grilling/질문은 **제품·정체성·우선순위**(스코프·MVP 경계·네이밍)에만 쓴다.

**참조는 실소스 대조 — 기억/요약 아님.** FreeRDP(C)·IronRDP(Rust) 는 `gh api repos/<owner>/<repo>/contents/<path> --jq .content | base64 -d > /tmp/x` 로 *통째* 받아 `grep -n`/`sed -n` 으로 실 줄을 읽는다(**WebFetch 금지** — 요약 모델이 큰 파일의 핸들러 본문을 잘라먹는다). **복사 아닌 도출**: ironrdp 코드를 베끼지 않고 스펙에서 재도출하고, 구조 유사성이 아니라 differential test 로 correctness 를 증명한다(ADR-0003). CVE 지식(rle/planar/clearcodec/nsc OOB)은 메모리 `rdp_decoder_robustness_refs`.

**완성 기준 — "대충 금지".** 슬라이스 "완료" 는 ① 골격(계약·경계)이 처음부터 옳고 ② 로직 100% 테스트 ③ 갭이 *추적된 0*(deferral 은 전부 이슈로 surfacing — *침묵하는* 갭 0) ④ 동작 증명이 *가짜 아닌 real*(코덱=`ironrdp-graphics` 오라클 byte-identical 왕복, connect/session=실 VM 왕복) 로 설 때만이다. 데모/fake 통과 ≠ 증명.

**Adversarial 검증은 subagent 로 (자기 enumeration 을 불신).** 디코더/파서처럼 *숨은상태 enumeration 이 불완전할 수 있는* 변경이면, 반응적 spike 로 엣지를 하나씩 찌르지 말고 **독립 completeness 비평가를 *서로 다른 렌즈*로 병렬** 돌린다: ① 우리 형제 디코더(rle/planar/nsc) 간 OOB·경계 처리 diff ② FreeRDP/IronRDP 실소스 CVE 지점 대조. 우리 **proptest no-panic(#98) + cargo-fuzz(#99)** 가 이 축의 자동화다.

## 작업 flow (sans-IO core·codecs 공통 — "그 flow")

substantive 변경이면 이 6단계로 짠다. 단계를 *생략*하려면 (건너뛰는 게 아니라) *왜 이 변경엔 N/A 인지 명시*한다 — 조용한 스킵 금지.

1. **스펙·참조 실측 대조 먼저 (3층 라우팅, 추측 금지).**
   - **와이어/PDU/코덱** → 먼저 **규범 스펙**(`[MS-RDPBCGR]`·`[MS-RDPRFX]`·`[MS-RDPEGDI]` 등)에서 절 번호로 레이아웃·플래그·상태전이를 박고, **로직은 스펙에서 도출**(복사 금지, ADR-0003).
   - **숨은 상태·서버 관용성·엣지** → **FreeRDP**(C, CVE 지식원) + **IronRDP**(Rust) 실소스를 `gh api … | base64 -d` 로 통째 받아 grep/sed(WebFetch 금지). 스펙이 *안 적는* tolerance(서버가 위반하는 caps — #101)는 여기서 나온다.
   - **개념 ≠ 메커니즘**: 기능이 IronRDP 에 없어도(우리가 새로 오너십 갖는 코덱) 그 구성요소(비트 리더·타일 경계·색공간)는 FreeRDP/스펙에 있다 → 둘 다 본다.
2. **경계를 코드로 가른다 (sans-IO core vs 어댑터, ADR-0001).** 메커니즘은 pure state machine core(`bytes in → (Action, bytes) out`); 정책(TLS 신뢰=ADR-0005·자격증명·frame sink)은 어댑터가 주입. 코어는 소켓·런타임 0 의존.
3. **순수 로직을 `/tdd` 로 (RED→GREEN, 한 번에 하나).** sans-IO 라 I/O 없이 결정론적 테스트 — sans-IO 의 배당금. 부수효과(소켓·클럭·frame sink)는 주입 seam 으로.
4. **동작 증명 — 가짜 아닌 real 왕복 (DoD ④).**
   - **코덱** → **differential oracle**: 같은 비트스트림을 우리 디코더 *와* `ironrdp-graphics` 에 먹여 `Vec<u8>` byte-identical 단언(ADR-0003/0007). 100% 통과해야 dependency drop.
   - **connect/session 로직** → 실 RDP **VM**(`192.168.136.136`, 메모리 `test_environment`) 왕복. 데모/fake 통과 ≠ 증명.
5. **Adversarial completeness 패스 (subagent 2렌즈) — 성질로 판단.** *enumeration 리스크*가 있는 변경(엣지/상태 다수·untrusted 파싱)이면 필수: ① 형제 디코더 diff ② FreeRDP/IronRDP CVE 지점 대조 → 갭 surfacing 또는 *수렴 증명*. 닫힌 표면(순수 기계적)이면 생략하되 *그 판단을 명시 기록*.
6. **게이트 & PR/머지.** `cargo test --workspace` + `cargo clippy --workspace --all-targets` + `cargo fmt --all --check` + `cargo check --manifest-path fuzz/Cargo.toml`(워크스페이스 밖) + **just-shield supply-chain**(ADR-0006) → 브랜치 `feat(<scope>): … (#issue)`(Co-Authored-By 금지) → squash PR `Closes #issue` → `test`/`fuzz`/`supply-chain` CI 그린 확인.

## Agent skills

### Issue tracker

Issues and PRDs are tracked as GitHub issues on `kihyun1998/justrdp`, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles mapped 1:1 to default label strings (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### CI gates

세 게이트: `test.yml`(build/test/clippy) + `fuzz.yml`(nightly 커버리지 유도 cargo-fuzz) + `supply-chain.yml`(just-shield, SHA-핀 액션 스캐너 — ADR-0006). 상세는 메모리 `justrdp_ci_policy`.
