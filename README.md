<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="logo/readme/justrdp-readme-dark.png">
    <img alt="justrdp" src="logo/readme/justrdp-readme-light.png" width="600">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/kihyun1998/justrdp/actions/workflows/test.yml"><img alt="test" src="https://github.com/kihyun1998/justrdp/actions/workflows/test.yml/badge.svg"></a>
  <img alt="license" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue">
</p>

**justrdp**는 처음부터 새로 작성한 **순수 Rust RDP 클라이언트 라이브러리**입니다.
X.224, MCS, GCC, capability, 세션 루프, 가상 채널, 코덱, 서피스까지 RDP 고유 계층은 모두
직접 구현하고, RDP가 아닌 보안 핵심 작업(TLS는 `rustls`, NLA는 `sspi`)만 위임합니다.

코어는 **sans-IO 상태 머신**입니다. 연결 시퀀스와 세션 루프는 순수한 전이(바이트 입력 →
액션/바이트 출력)이며, 소켓·런타임·TLS 신뢰·자격 증명 같은 정책은 호스트 쪽 어댑터
(`justrdp-tokio`)가 담당합니다.

## 크레이트

| 크레이트 | 역할 |
|---|---|
| `justrdp-pdu` | RDP 와이어 포맷 PDU 인코딩/디코딩. 외부 의존성 없음 |
| `justrdp` | sans-IO 코어: 연결·세션 상태 머신과 호스트용 출력 타입 |
| `justrdp-codecs` | 모든 그래픽 코덱 (직접 구현) |
| `justrdp-tokio` | Tokio I/O 어댑터: 소켓, TLS 핸드셰이크, CredSSP, 단계별 타임아웃 |

## 문서

- [`CONTEXT.md`](CONTEXT.md) — 용어와 경계
- [`docs/adr/`](docs/adr/) — 설계 결정 기록
- [`docs/plan.md`](docs/plan.md) — 빌드 계획
- [`docs/map/`](docs/map/README.md) — 영역별 영향 범위 지도

## 라이선스

MIT 또는 Apache-2.0 중 선택.
