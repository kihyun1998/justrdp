# `justrdp-blocking` 구현 체크리스트

**목표**: 로드맵 §5.5 `justrdp-blocking`을 **§9.2 Auto-Reconnect까지 실제로 동작**하는 상태로 만든다.

**현재 상태** (scaffold 커밋 기준):
- API 표면 정의 완료 (`RdpClient`, `RdpEvent`, `ConnectError`, `RuntimeError`, `ReconnectPolicy`)
- `drive_until_tls_upgrade()` 만 실제 동작 — TCP 열고 `ClientConnector` 스텝 루프를 `EnhancedSecurityUpgrade` 상태까지 구동
- 그 이후는 전부 `Err(Unimplemented)` stub
- 유닛 테스트 6개 통과 (reconnect backoff, transport framer)

**원칙**:
- 각 단계는 **독립된 커밋**. 이전 단계가 동작해야 다음 단계가 의미 있음
- 커밋 전 `cargo test -p justrdp-blocking && cargo build --workspace` 필수
- 실서버 검증은 `192.168.136.136` Windows RDS (test_environment 메모리 참조)

---

## M1 — TLS 업그레이드 + CertVerifier 훅

**로드맵 근거**: §5.4 `ServerCertVerifier` trait, §5.5 "연결 수립 펌프"

### `justrdp-tls` 변경

- [ ] `ServerCertVerifier` trait 신설 (`src/verifier.rs`)
  ```rust
  pub trait ServerCertVerifier: Send + Sync {
      fn verify(&self, cert_der: &[u8], server_name: &str) -> CertDecision;
  }
  pub enum CertDecision { Accept, Reject, AcceptOnce }
  ```
- [ ] 기본 구현체
  - [ ] `AcceptAll` (현재 rustls `danger.rs`가 하는 것; 경고 로그)
  - [ ] `Pinned { spki_sha256: [u8; 32] }` (지문 고정)
  - [ ] (선택) `SystemRoots` — webpki-roots로 검증
- [ ] `RustlsUpgrader`가 `ServerCertVerifier`를 주입받도록 생성자 변경
  - 현재 `danger::NoCertificateVerification`을 그대로 쓰고 있을 가능성 높음 — 어댑터로 감싸기
- [ ] 단위 테스트: mock verifier가 Reject 반환 → 업그레이드 실패
- [ ] `native-tls` 백엔드는 feature flag 뒤에서 trait 지원 (최소한 컴파일만)

### `justrdp-blocking` 변경

- [ ] `client.rs`: `Transport` enum 도입
  ```rust
  enum Transport {
      Tcp(TcpStream),
      Tls(Box<dyn ReadWrite + Send>),
  }
  impl Read for Transport { /* dispatch */ }
  impl Write for Transport { /* dispatch */ }
  ```
  - `ReadWrite`는 `justrdp_tls::ReadWrite` 재사용
- [ ] `RdpClient::connect()` 시그니처에 `upgrader: impl TlsUpgrader` 추가 (또는 feature 기본값)
- [ ] `drive_until_tls_upgrade()` → `drive_connection()`으로 확장:
  1. `EnhancedSecurityUpgrade` 감지 → `Transport::Tcp`에서 TcpStream 꺼냄
  2. `upgrader.upgrade(tcp, server_name)` 호출
  3. `server_public_key`는 다음 단계(CredSSP)에서 connector에 주입
  4. `Transport::Tls(Box::new(upgraded.stream))`로 교체
  5. 루프 재개
- [ ] `ConnectError::Tls` variant는 이미 있음 — 매핑 확인
- [ ] 통합 테스트: loopback에서 self-signed 서버 생성 → 업그레이드 성공/Reject 시나리오

**검증**: `cargo test -p justrdp-blocking tls_upgrade` + 실서버 `192.168.136.136`에서 TLS 단계까지 도달 확인 (`EarlyUserAuth` 직전까지).

---

## M2 — CredSSP 토큰 pump-through

**로드맵 근거**: §5.2 Authentication (완료된 PDU 레이어), §5.5 런타임

커넥터의 CredSSP 시퀀스는 이미 구현되어 있음. blocking은 그저 I/O를 밀어주기만 하면 됨.

- [ ] `drive_connection()` 루프가 `CredsspNegoTokens`/`CredsspPubKeyAuth`/`CredsspCredentials` 상태에서 올바르게 동작하는지 확인
  - TPKT 프레이밍이 아닌 경우가 있는지 확인 (CredSSP는 TLS record 위에 ASN.1 SEQUENCE)
  - `connector.next_pdu_hint()`가 적절한 hint 반환하는지 확인 — 없으면 `CredsspTsRequestHint` 같은 것을 커넥터 쪽에 추가해야 함 (또는 blocking이 임시로 boundary 감지)
- [ ] `CredsspEarlyUserAuth` 상태: TLS 위에서 **정확히 4바이트** 수신 후 커넥터에 전달
  - 이건 일반 `read_pdu`로 안 됨 — 별도 분기 필요
  - HYBRID_EX 선택 시에만
- [ ] `TlsUpgradeResult::server_public_key`를 `CredsspSequence::new()`에 어떻게 전달하는지 확인
  - 현재 커넥터가 이 값을 어디에서 받는지 `connector.rs` 검토
  - blocking에서 `connector`에 setter가 있다면 호출, 없으면 커넥터 API 보강 필요

**검증**: NTLM 흐름으로 `192.168.136.136`에서 `CredsspCredentials` 완료 도달.

---

## M3 — 연결 완료까지 전체 펌프

**로드맵 근거**: §5.5 "연결 수립 펌프" 완성

- [ ] BasicSettingsExchange → ChannelConnection → (옵션: SecurityCommencement) → SecureSettingsExchange → Licensing → CapabilitiesExchange → ConnectionFinalization 모든 상태 통과
- [ ] `ConnectionResult`를 `self.result`에 저장
- [ ] `ActiveStage::new(SessionConfig { io_channel_id, user_channel_id, share_id, channel_ids })` 생성
  - `ConnectionResult` → `SessionConfig` 변환 헬퍼 (connector 또는 blocking 둘 중 한 곳)
- [ ] `RdpClient::connect()`가 `Ok(Self { transport, session: Some(...), ... })` 반환
- [ ] `disconnect()`가 MCS DisconnectProviderUltimatum 전송 후 소켓 닫도록 수정

**검증**: `RdpClient::connect()`가 실서버에서 `Ok` 반환. 이 시점부터 `next_event()` 테스트 가능.

---

## M4 — ActiveStage 펌프 + RdpEvent 매핑

**로드맵 근거**: §5.5 "ActiveStage 펌프"

- [ ] `next_event()` 구현
  - 내부 상태: `pending_events: VecDeque<RdpEvent>` — 한 프레임에서 여러 이벤트 나오면 큐잉
  - 큐가 비어있으면: `read_pdu(transport, TpktHint 또는 FastPathHint, scratch)` → `session.process(&frame)` → 결과를 큐에 push
  - 큐에서 pop해서 반환
- [ ] Fast-path vs slow-path 프레이밍 구분
  - 첫 바이트 `0x03` = TPKT, 아니면 fast-path
  - `TpktHint`는 이미 있음, fast-path hint는 `justrdp-pdu`에 있는지 확인 — 없으면 inline 2바이트 read
- [ ] `ActiveStageOutput` → `RdpEvent` 변환
  - [ ] `ResponseFrame(bytes)` → 즉시 `transport.write_all()` (이벤트 방출 안 함)
  - [ ] `GraphicsUpdate { update_code, data }` → `RdpEvent::GraphicsUpdate`
  - [ ] `PointerDefault` / `PointerHidden` / `PointerPosition` / `PointerBitmap` 1:1 매핑
  - [ ] `SaveSessionInfo { data }` → `RdpEvent::SaveSessionInfo(data)` + ARC cookie는 `self.last_arc_cookie`에 저장 (M7에서 사용)
  - [ ] `ServerMonitorLayout { monitors }` → `RdpEvent::ServerMonitorLayout`
  - [ ] `ChannelData { channel_id, data }` → 일단 `RdpEvent::ChannelData`로 패스스루 (SVC/DVC 라우팅은 M5)
  - [ ] `Terminate(reason)` → `RdpEvent::Disconnected(reason)` + 내부 상태를 Disconnected로
  - [ ] `DeactivateAll` / `ServerReactivation` → 일단 unimplemented!()로 두거나 Disconnected로 (MVP에서는 스킵)
- [ ] `next_event()`가 `Ok(None)` 반환하는 조건 정의 — disconnect 후 이벤트 소진
- [ ] 에러 전파: `SessionError` → `RuntimeError::Session`

### 누락된 PDU 이벤트 (감사 보고서 #17-19)

- [ ] `SuppressOutputPdu` — 현재 `ActiveStageOutput`에 없음. `justrdp-session` 쪽에 variant 추가 필요
- [ ] `SetKeyboardIndicatorsPdu` / `SetKeyboardImeStatusPdu` — 동일
- [ ] `PlaySoundPdu` (type 34) — 동일
  - 이 4개는 blocking만으로는 못 함. `justrdp-session`에 먼저 `ActiveStageOutput` 변형 추가 → blocking에서 `RdpEvent` 매핑
  - MVP에서는 생략하고 별도 커밋으로 미룰 수 있음

**검증**: 실서버 연결 후 마우스 커서 이동 이벤트 수신 + `GraphicsUpdate` 바이트 수 로깅.

---

## M5 — 입력 송신 헬퍼

**로드맵 근거**: §5.5 "입력 송신"

- [ ] `send_keyboard(scancode, pressed)` 구현
  - `justrdp_input::InputDatabase`를 `RdpClient` 필드로 보유
  - scancode → `FastPathInputEvent` 변환
  - `session.encode_input_events(&[event])` → `transport.write_all()`
- [ ] `send_unicode(ch, pressed)` 추가
- [ ] `send_mouse(x, y, buttons: MouseButtons)` 구현 (현재 시그니처에 buttons 없음 — 수정)
- [ ] `send_mouse_wheel(delta)` 추가 (선택)
- [ ] `InputDatabase` 상태 추적 (modifier keys, sync 이벤트) — `justrdp-input` API 활용

**검증**: 실서버에서 notepad 열고 키보드 입력 반영 확인.

---

## M6 — (선택) SVC/DVC 라우팅

MVP에서는 생략 가능. 필요해질 때 추가.

- [ ] `RdpClient::register_svc(name: &str, processor: Box<dyn SvcProcessor>)`
- [ ] `RdpClient::register_dvc(...)`
- [ ] `ChannelData` 이벤트를 processor로 라우팅 (이벤트는 raw 패스스루 유지)
- [ ] processor 출력 PDU를 `transport.write_all()`로 전송

---

## M7 — Auto-Reconnect 런타임 (§9.2 완성)

**로드맵 근거**: §9.2 런타임 레이어

이게 최종 목표. 여기까지 와야 사용자가 "됐다"를 느낄 수 있음.

- [ ] `ReconnectPolicy`를 `RdpClient`에 통합 (이미 필드 있음)
- [ ] `last_arc_cookie: Option<ArcCookie>` 필드 추가, `SaveSessionInfo` 이벤트에서 `SaveSessionInfoData::arc_random()` 호출해 저장
- [ ] `last_server_addr: SocketAddr` 보관 (connect 시점에 기록)
- [ ] `last_config: Config` 보관 (재사용용, Clone 필요)
- [ ] TCP 끊김 감지
  - `read`가 `Ok(0)` 반환 또는 `WouldBlock` 외 io::Error → 끊김
  - 끊김 시 `Err(RuntimeError::Disconnected)` 대신 재연결 시도 경로로 분기
- [ ] 재연결 루프
  ```rust
  for attempt in 1..=policy.max_attempts {
      std::thread::sleep(policy.delay_for_attempt(attempt));
      emit(RdpEvent::Reconnecting { attempt });
      let new_config = self.last_config.clone()
          .with_auto_reconnect_cookie(self.last_arc_cookie.clone());
      match Self::connect_inner(self.last_server_addr, new_config, ...) {
          Ok(new_client) => {
              *self = new_client;
              emit(RdpEvent::Reconnected);
              return Ok(());
          }
          Err(e) if is_retryable(&e) => continue,
          Err(e) => return Err(e.into()),
      }
  }
  ```
- [ ] `DisconnectReason::is_retryable()` — §21.6 체크리스트, `justrdp-pdu`에 추가 필요
- [ ] 재연결 중 `next_event()`는 `Reconnecting` / `Reconnected` 이벤트 방출 후 투명하게 다음 이벤트로 진행
- [ ] 리다이렉션 루프 방지 (§9.3과 공통) — `reconnect_depth` 카운터
- [ ] **통합 테스트** (가장 중요):
  - [ ] 실서버 연결 → `server_arc_cookie` 확인 / `SaveSessionInfo` 대기
  - [ ] 소켓을 고의로 `shutdown()` → `next_event()`가 `Reconnecting` → `Reconnected` 순서로 이벤트 방출
  - [ ] 3초 이내 복구 (Phase 5 Exit Criteria)

**검증**: §9.2가 진짜로 "돌아간다"고 말할 수 있는 지점. roadmap.md에서 `[ ]` → `[x]` 전환.

---

## 마일스톤 간 의존 관계

```
M1 (TLS + CertVerifier)
 └─► M2 (CredSSP pump-through)
      └─► M3 (전체 연결 펌프 → Connected)
           └─► M4 (ActiveStage 펌프 + RdpEvent)
                ├─► M5 (입력 헬퍼)
                ├─► M6 (SVC/DVC — 선택)
                └─► M7 (Auto-Reconnect — 최종 검증)
```

## 커밋 단위 권장

- M1: 2 커밋 (justrdp-tls trait 추가, blocking TLS 통합)
- M2: 1 커밋
- M3: 1~2 커밋 (연결 완료 + SessionConfig 변환)
- M4: 2~3 커밋 (기본 이벤트, 누락 PDU 4종 추가)
- M5: 1 커밋
- M6: 0~1 커밋 (MVP 생략 가능)
- M7: 2 커밋 (런타임 + 통합 테스트)

**총 9~12 커밋** 예상. 각 커밋 후 `cargo test && cargo build --workspace` 필수.

---

## 커밋 후 진행할 것

- [ ] 로드맵 §9.2 체크박스 업데이트 (`[x]` 변경)
- [ ] 로드맵 §5.5 체크박스 진척 반영
- [ ] `test-gap-finder` 에이전트로 커버리지 점검
- [ ] §9.3 Session Redirection (Task #4) 착수 — M7 완료 후에는 이 경로가 훨씬 짧음 (대부분의 재연결 인프라 재사용)
