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

## M1 — TLS 업그레이드 + CertVerifier 훅 ✅

**로드맵 근거**: §5.4 `ServerCertVerifier` trait, §5.5 "연결 수립 펌프"

### `justrdp-tls` 변경

- [x] `ServerCertVerifier` trait 신설 (`src/verifier.rs`)
- [x] `CertDecision { Accept, Reject, AcceptOnce }`
- [x] `AcceptAll` (mstsc 스타일, 기본값)
- [x] `PinnedSpki { expected_sha256: [u8; 32] }` + `from_cert_der()` + constant-time 비교 + redacted Debug
- [x] `RustlsUpgrader::with_verifier(Arc<dyn ServerCertVerifier>)` 생성자
- [x] `VerifierBridge` — rustls `ServerCertVerifier` ↔ 우리 trait 어댑터 (Debug 수동 구현, 내부에 redacted)
- [x] 기존 `RustlsUpgrader::new()` / `with_verification()` 동작 보존 (webpki-roots 경로 유지)
- [x] 단위 테스트 9개: AcceptAll, PinnedSpki accept/reject/unparseable, constant_time_eq, Debug redaction, VerifierBridge accept/reject forwarding
- [x] `native-tls` 백엔드 trait 지원 (post-handshake verification 모델: handshake 후 cert 추출 → verifier 호출 → Reject 시 stream 드롭)
  - `TrustMode::OsTrustStore`(`with_verification()`) vs `TrustMode::UserVerifier(Arc<dyn>)`(`with_verifier()`/`new()`) 분기
  - rustls 대비 한 RTT 늦게 reject되지만, RDP는 CredSSP 전이라 자격증명 노출 0

### `justrdp-blocking` 변경

- [x] `client.rs`에 `Transport` enum (`Tcp` / `Tls(Box<dyn ReadWrite>)` / `Swapping`)
- [x] `Read` + `Write` impl이 variant에 dispatch, `Swapping`은 `NotConnected` 에러
- [x] `RdpClient::connect(server, server_name, config)` (AcceptAll 기본값)
- [x] `RdpClient::connect_with_verifier(..., Arc<dyn ServerCertVerifier>)`
- [x] `RdpClient::connect_with_upgrader<U: TlsUpgrader>(...)` (커스텀 백엔드/테스트용)
- [x] `drive_until_state_change()` — 일반화된 커넥터 펌프, stop predicate 받음
- [x] TLS 업그레이드 실제 수행: `EnhancedSecurityUpgrade` 감지 → `mem::replace`로 TCP 추출 → `upgrader.upgrade()` → `Transport::Tls`로 swap → `server_public_key` 보관
- [x] `server_public_key: Option<Vec<u8>>` 필드 (M2에서 CredSSP가 사용)
- [x] `Transport::Swapping` 경로 단위 테스트
- [x] 실서버 검증 (`192.168.136.136`): TCP→X.224→TLS→SPKI 추출 성공 — `examples/connect_test.rs`로 확인

**현재 동작**: `connect()`가 TCP → X.224 → TLS 업그레이드까지 수행 후 `ConnectError::Unimplemented("post-TLS CredSSP + connection finalization (M2+)")` 반환. `server_public_key`도 정상 추출됨.

**검증**: `cargo test -p justrdp-tls` (21 pass) + `cargo test -p justrdp-blocking` (7 pass) + `cargo build --workspace` clean.

---

## M2 — CredSSP 토큰 pump-through ✅

**로드맵 근거**: §5.2 Authentication (완료된 PDU 레이어), §5.5 런타임

**발견**: 커넥터의 `Credssp*` 상태들은 모두 `is_send_state() == true`이며 `step(&[])` 호출 시 단순 no-op 전환만 수행. 실제 CredSSP 토큰 교환은 `CredsspSequence` (별도 객체)가 담당하고, 호출자가 TLS 스트림 위에서 I/O를 직접 구동해야 함. blocking은 이 외부 시퀀스를 래핑.

- [x] `src/credssp.rs` 신규 모듈: `run_credssp_sequence(connector, transport, server_public_key)`
- [x] `CredsspRandom` 생성 (OS 랜덤 `getrandom`)
- [x] `ClientConnector::config()` 접근자 추가 (connector에 작은 API 보강) — 자격증명/도메인/auth_mode 읽기용
- [x] `connector.credssp_credential_type()` 활용 (Password / RestrictedAdmin / RemoteGuard 분기)
- [x] HYBRID_EX 감지: `connector.selected_protocol().contains(SecurityProtocol::HYBRID_EX)`
- [x] `read_asn1_sequence()` 프레이머 (`transport.rs`) — DER 길이 인코딩 short/long form 모두 지원, 16 MiB 상한
  - [x] short form (0x30 0xLL ...): 7개 테스트 케이스
  - [x] long form 1바이트 (0x30 0x81 0xLL): 테스트
  - [x] long form 2바이트 (0x30 0x82 0xHH 0xLL): 테스트 (1024 바이트)
  - [x] non-SEQUENCE 거부, oversized, mid-frame EOF, 5-byte length indicator 거부
- [x] `WaitEarlyUserAuth` 분기: 첫 바이트 peek → `0x30`이면 TsRequest fallback, 아니면 4바이트 raw status code
- [x] CredSSP 시퀀스 완료 후 커넥터를 `CredsspNegoTokens → CredsspPubKeyAuth → CredsspCredentials → CredsspEarlyUserAuth → BasicSettingsExchangeSendInitial` 순서로 no-op step
- [x] `client.rs::connect_with_upgrader()` 업데이트: TLS 업그레이드 후 EnhancedSecurityUpgrade 한 스텝 전진 → CredSSP 분기 → 연결 종료 상태 도달
- [x] `ConnectError::Unimplemented` 메시지를 "post-CredSSP connection finalization pump (M3+)"로 업데이트
- [x] 실서버 검증: `examples/connect_test.rs` 실행 → CredSSP/NLA "complete" 통과 확인. 기존 connector finalization 버그(`step_finalization_wait_pdu` PDU 순서 문제)에 의해 finalization 끝까지는 못 가지만 M2 범위는 검증됨

**현재 동작**: TCP → X.224 → TLS 업그레이드 → SPKI 추출 → CredSSP 전체 시퀀스 (Negotiate → Challenge → Authenticate+pubKeyAuth → Credentials → HYBRID_EX EarlyUserAuth) → BasicSettingsExchangeSendInitial 도달 후 `Unimplemented("post-CredSSP connection finalization pump (M3+)")` 반환.

**검증**: `cargo test -p justrdp-blocking` 14 pass (기존 7 + ASN.1 7개), `cargo build --workspace` clean.

---

## M3 — 연결 완료까지 전체 펌프 ✅

**로드맵 근거**: §5.5 "연결 수립 펌프" 완성

- [x] BasicSettingsExchange → ChannelConnection → SecurityCommencement → SecureSettingsExchange → ConnectTimeAutoDetection → Licensing → MultitransportBootstrapping → CapabilitiesExchange → ConnectionFinalization 전체 통과
  - 기존 `drive_until_state_change(predicate)` 재사용: predicate는 `ClientConnectorState::is_connected()` 한 줄로 끝
  - 커넥터가 이 구간 전체를 내부에서 처리하므로 blocking은 TPKT 바이트 펌프만
- [x] `connector.result()`에서 `ConnectionResult` 추출
- [x] `ConnectionResult` → `SessionConfig { io_channel_id, user_channel_id, share_id, channel_ids }` 변환 (inline)
- [x] `ActiveStage::new(session_config)` 생성
- [x] `RdpClient::connect*()` 전체 시그니처 `Ok(Self { ... })` 반환
  - `transport: Some(transport)`, `session: Some(active_stage)`, `reconnect_policy: disabled()`, `scratch: Vec::new()`, `server_public_key` 보관
- [x] `server_public_key`를 clone해서 CredSSP에 전달, 원본은 RdpClient에 보관 (M7 auto-reconnect 재사용 대비)
- [ ] ~~`disconnect()`가 MCS DisconnectProviderUltimatum 전송~~ → M4 이후로 연기 (`ActiveStage::encode_disconnect()` API는 이미 있음, 지금은 transport drop만 수행)

**현재 동작**: TCP → X.224 → TLS 업그레이드 → CredSSP → BasicSettings → ChannelConnection → Capabilities → Finalization → `Connected` → `RdpClient { session: Some(ActiveStage) }` 반환. **`connect()`가 처음으로 `Ok`를 반환함.**

**검증**: 
- `cargo test -p justrdp-blocking` 14 pass, 워크스페이스 clean
- 실서버 `192.168.136.136` 통합 테스트는 M4 이후 `next_event()`로 프레임 수신 확인 가능한 시점에 수행 (지금도 `connect()`는 성공해야 하지만 검증 수단이 없음)

---

## M4 — ActiveStage 펌프 + RdpEvent 매핑 ✅

**로드맵 근거**: §5.5 "ActiveStage 펌프"

### M4a (commit 03ed1da)

- [x] `next_event()` 구현 + `pending_events: VecDeque<RdpEvent>` 큐
- [x] `read_one_frame()` — 한 프레임 읽고 `session.process()` 호출, ResponseFrame은 즉시 write, 나머지는 큐로
- [x] Fast-path/slow-path 자동 분기 — `TpktHint`가 첫 바이트(`0x03` 또는 fast-path action) 보고 dispatch
- [x] 보로우 체커: `transport`/`session` field borrow를 작은 블록 안에 가두고, 이벤트는 local Vec → 블록 종료 후 `self.pending_events`로 flush
- [x] `ResponseFrame(bytes)` → 즉시 transport.write_all (이벤트 방출 X)
- [x] `GraphicsUpdate` / `PointerDefault` / `PointerHidden` / `PointerPosition` / `PointerBitmap` 1:1 매핑
- [x] `SaveSessionInfo { data }` → `RdpEvent::SaveSessionInfo(data)` (ARC cookie 추출은 M7)
- [x] `ServerMonitorLayout` 1:1 매핑
- [x] `ChannelData` 패스스루 (SVC/DVC 라우팅은 M6)
- [x] `Terminate(reason)` → `RdpEvent::Disconnected(reason)` + `disconnected = true`
- [x] `DeactivateAll`/`ServerReactivation` → MVP는 `Disconnected(ShutdownDenied)`로 surface (실제 reactivation은 추후 마일스톤)
- [x] `next_event()`가 disconnect 후 큐 소진 시 `Ok(None)` 반환
- [x] `connect_error_to_runtime()` 헬퍼: `read_pdu`의 `ConnectError` → `RuntimeError`

### M4b (이번 커밋) — 누락된 4종 PDU 추가

- [x] `justrdp-pdu`: `PlaySoundPdu` 신규 (MS-RDPBCGR 2.2.9.1.1.5.1, duration_ms + frequency_hz LE u32 × 2)
  - [x] roundtrip + 0값 + 와이어 바이트 검증 테스트 2개
- [x] `justrdp-session::ActiveStageOutput`에 4 variant 추가:
  - `KeyboardIndicators { led_flags }`
  - `KeyboardImeStatus { ime_state, ime_conv_mode }`
  - `PlaySound { duration_ms, frequency_hz }`
  - `SuppressOutput { allow_display_updates, rect: Option<(u16,u16,u16,u16)> }`
- [x] `dispatch_pdu_type2`에 4 dispatcher arm 추가 (`SetKeyboardIndicators`/`SetKeyboardImeStatus`/`PlaySound`/`SuppressOutput`)
- [x] 5개 단위 테스트 추가 (KeyboardIndicators, KeyboardImeStatus, PlaySound, SuppressOutput resume + pause)
- [x] `justrdp-blocking`: 4 variant → `RdpEvent` 매핑
  - led_flags 비트 분해 (Scroll/Num/Caps/Kana → bool 4개)
  - SuppressOutput rect는 현재 드롭, allow만 surface

**현재 동작**: `connect()` Ok → `next_event()` 루프로 GraphicsUpdate, Pointer*, KeyboardIndicators, ImeStatus, PlaySound, SuppressOutput, ChannelData, SaveSessionInfo, ServerMonitorLayout, Disconnected 모두 surface 가능. 실서버 검증 가능 시점.

**검증**: `cargo test -p justrdp-pdu -p justrdp-session -p justrdp-blocking` — pdu 신규 2 + session 53 (기존 48 + 신규 5) + blocking 14, 워크스페이스 clean.

---

## M5 — 입력 송신 헬퍼 ✅

**로드맵 근거**: §5.5 "입력 송신"

- [x] `send_keyboard(scancode, pressed)` — `FastPathScancodeEvent` (KBDFLAGS_RELEASE/EXTENDED)
- [x] `send_unicode(ch, pressed)` — BMP code point만 지원, 서로게이트 페어 (U+10000+)는 `Unimplemented`
- [x] `send_mouse_move(x, y)` — `FastPathMouseEvent` with PTRFLAGS_MOVE
- [x] `send_mouse_button(button, pressed, x, y)` — Left/Right/Middle만 (X1/X2는 `MouseX` event 필요, `Unimplemented`)
- [x] 모든 헬퍼는 `session.encode_input_events()` → `transport.write_all()` + `flush()` 패턴
- [x] `Session`/`Transport` 어느 쪽이라도 `None`이면 `RuntimeError::Disconnected` 즉시 반환
- [x] Pure 이벤트 빌더 함수 4개 추출 (`build_scancode_event`, `build_unicode_event`, `build_mouse_move_event`, `build_mouse_button_event`) — 라이브 세션 없이 단위 테스트 가능
- [x] 11개 단위 테스트 추가:
  - scancode press/release/extended (3)
  - unicode BMP / release / supplementary plane rejection (3)
  - mouse move (1)
  - mouse button left press / right release / middle press / X1/X2 None (4)
- [ ] ~~`send_mouse_wheel(delta)`~~ → 후속 작업 (PTRFLAGS_WHEEL/HWHEEL/WHEEL_NEGATIVE 인코딩 필요)
- [ ] ~~`InputDatabase` 내장~~ → MVP에서는 사용자가 직접 관리. 추후 옵션 feature로 추가 검토
- [ ] ~~키보드 sync (LockKeys 동기화)~~ → 후속, `FastPathSyncEvent` 사용 예정
- [x] 실서버 검증: `examples/connect_test.rs` 작성, M1-M3 (TCP/TLS/CredSSP)는 정상 동작. M4 이후(`next_event` 루프, `send_*`)는 connector finalization 버그로 도달 못 함 — 별도 이슈

**현재 동작**: `RdpClient` 사용자가 키 입력 / 유니코드 / 마우스 이동 / 마우스 클릭을 송신할 수 있음. 4가지 fast-path 이벤트 모두 와이어 포맷 정확.

**검증**: `cargo test -p justrdp-blocking` 25 pass (14 기존 + 11 신규), 워크스페이스 clean.

---

## M6 — SVC/DVC 라우팅 ✅

**핵심 발견**: `justrdp-svc::StaticChannelSet`이 이미 모든 dispatch 로직을 갖추고 있음 (insert / assign_ids / start_all / process_incoming). DVC는 별도 작업 불필요 — `DrdynvcClient` 자체가 `SvcProcessor` 구현이라 사용자가 그걸 박싱해서 SVC로 등록하면 자동으로 DVC가 동작함.

- [x] `justrdp-svc` 의존성 추가
- [x] `RdpClient`에 `svc_set: SvcChannelSet` + `user_channel_id: u16` 필드
- [x] **`ConnectError::ChannelSetup(String)` 신규 variant** — 채널 등록 / start_all 실패 보고용
- [x] `connect_with_upgrader` 시그니처에 `processors: Vec<Box<dyn SvcProcessor>>` 추가
  - 기존 `connect`, `connect_with_verifier`는 `Vec::new()` forward
- [x] **신규 `connect_with_processors(server, name, config, processors)`** convenience 메서드
- [x] 연결 직후 시퀀스:
  1. `svc_set.insert(processor)` 모두 등록 (실패 시 ChannelSetup 에러)
  2. `svc_set.assign_ids(&result.channel_ids)` — 서버가 할당한 MCS ID와 매칭
  3. `svc_set.start_all(user_channel_id)` — 각 processor의 초기 메시지 (CLIPRDR Capability Request, RDPDR Server Announce Reply 등) 수집
  4. 반환된 frame들 (이미 MCS+TPKT 래핑됨) 즉시 transport.write_all
- [x] `read_one_frame`의 `ChannelData { channel_id, data }` 분기:
  - `svc_set.get_by_channel_id(channel_id).is_some()` → 등록된 processor 있음 → `process_incoming`로 dispatch, 응답 frame들 전송, **`RdpEvent::ChannelData` emission 안 함**
  - 없으면 → 기존대로 raw passthrough 이벤트
- [x] 보로우 체커 우회: `svc_responses: Vec<Vec<u8>>` local accumulator → 내부 borrow block 종료 후 transport 재취득해서 flush
- [x] DVC 지원: 사용자가 `DrdynvcClient::new()` → `register(dvc_processor)` → `Box::new(drdynvc)` → `connect_with_processors(...)` 패턴으로 자동 동작
- [x] 단위 테스트 2개 추가:
  - `RecordingProcessor` (echo SVC) → `SvcChannelSet`이 dispatch 하고 응답 frame 1개 반환 검증
  - `get_by_channel_id` 미등록 ID → None (raw passthrough 경로 보장)

**현재 동작**: clipboard, drive redirection, audio, RemoteApp 등 모든 SVC/DVC 채널을 사용자가 등록하고 사용 가능. M4의 raw `ChannelData` 패스스루는 처리되지 않은 채널에만 적용.

**검증**: `cargo test -p justrdp-blocking` 27 pass (M5 25 + 신규 2), 워크스페이스 clean.

---

## M7 — Auto-Reconnect 런타임 (§9.2 완성) ✅

**로드맵 근거**: §9.2 런타임 레이어

이게 최종 목표. 여기까지 와야 사용자가 "됐다"를 느낄 수 있음.

- [x] `ReconnectPolicy` 통합 (RdpClient 필드)
- [x] `last_arc_cookie: Option<ArcCookie>` — `SaveSessionInfo` 이벤트마다 `SaveSessionInfoData::arc_random()` 호출해 갱신 (M4 dispatcher 안에서 captured_arc_cookie local로 받아 borrow block 종료 후 self에 flush)
- [x] `last_server_addr: SocketAddr` — connect 시 `to_socket_addrs().next()`로 즉시 해석 (DNS는 첫 reconnect 시점에 캐싱됨)
- [x] `last_server_name: String` — TLS SNI 호스트네임 보관
- [x] `last_config: Config` — 원본을 clone()해서 보관 (Config는 이미 Clone)
- [x] **`connect_inner` 패턴 대신 `do_one_reconnect`** — `Self::connect()` 재호출 + 새 인스턴스의 session-tier 필드(transport/session/svc_set/user_channel_id/server_public_key)를 self로 move. last_* 필드와 reconnect_policy/pending_events는 유지
- [x] TCP 끊김 감지: `read_pdu`에서 `ConnectError::UnexpectedEof`/`Tcp(io)` → `RuntimeError::Disconnected`/`Io` → `next_event()`가 `try_reconnect()`로 분기
- [x] 재연결 루프 (`try_reconnect`):
  - `can_reconnect()` 사전 검사 (3가지 전제)
  - `for attempt in 1..=max_attempts`:
    - `sleep(policy.delay_for_attempt(attempt))` (지수 백오프)
    - `pending_events.push_back(Reconnecting { attempt })`
    - `do_one_reconnect()` 호출
    - 성공 시 `Reconnected` push 후 return
  - 모두 실패 시 `Disconnected(ServerDisconnect(DomainDisconnected))` push + `mark_disconnected()`
- [x] **재연결 전제 (`can_reconnect()`)**:
  1. `reconnect_policy.max_attempts > 0`
  2. `last_arc_cookie.is_some()` (서버가 ARC cookie 없이는 logon 세션 부활 불가)
  3. `svc_set.is_empty()` — SVC processors는 stateful이라 reconnect 시 부활 불가, MVP에서 mutex
- [x] `next_event()` 통합: `read_one_frame` 에러를 ` Disconnected/Io` 패턴 매치로 잡아 `try_reconnect()` 호출 → 다시 루프로 돌아가 큐 드레인
- [x] `do_one_reconnect`이 `ConfigBuilder` 안 거치고 `config.auto_reconnect_cookie = self.last_arc_cookie.clone()` 직접 주입 (Config는 public field)
- [x] **6개 단위 테스트**:
  - `can_reconnect_requires_enabled_policy` (disabled → false)
  - `can_reconnect_requires_arc_cookie` (cookie None → false)
  - `can_reconnect_blocked_by_processors` (processor 있음 → false)
  - `can_reconnect_allowed_with_policy_and_cookie` (모든 전제 만족 → true)
  - `try_reconnect_disabled_policy_emits_disconnect_and_marks_terminal` (disabled → Disconnected만 emit, Reconnecting noise 없음)
  - `try_reconnect_with_processors_short_circuits_to_disconnect` (processor → 즉시 Disconnected)
- [x] `synthetic_client()` 헬퍼: 라이브 네트워크 없이 RdpClient 필드를 직접 구성해 predicate 테스트 가능
- [ ] ~~`DisconnectReason::is_retryable()`~~ — 후속 작업. 현재는 모든 IO/Disconnected 에러를 재시도
- [x] 리다이렉션 루프 방지 (depth counter) — §9.3 작업에서 `MAX_REDIRECTS = 5` 구현 (commit `eff6416`)
- [x] 실서버 통합 테스트 — `192.168.136.136`에서 `connect_test.rs --reconnect` 실행 결과:
  - 초기 연결 73ms 만에 `Connected` 도달
  - 10개 이벤트 후 `test_drop_transport()` → 다음 read에서 `Disconnected` → `try_reconnect()` 진입
  - `Reconnecting { attempt: 1 }` 이벤트 emit → 새 TCP/TLS/CredSSP/finalization 자동 수행 → `Reconnected` 이벤트 emit
  - 재연결 후 정상 event loop 재개 (PointerBitmap × N + 25 KiB GraphicsUpdate, 총 569 KiB)
  - 단발 disconnect → 재연결 → 정상 동작 시퀀스 완전 검증

**현재 동작**: `RdpClient::set_reconnect_policy(ReconnectPolicy::aggressive())` 호출하면 다음 disconnect부터 자동 재연결 시도. 로드맵 §9.2의 모든 PDU 레이어 + 런타임 항목 체크 완료.

**검증**: `cargo test -p justrdp-blocking` 33 pass (M6 27 + 신규 6), 워크스페이스 clean. roadmap.md §9.2 런타임 항목 5개 모두 `[x]` 마킹됨.

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

- [x] 로드맵 §9.2 체크박스 업데이트 — M7 commit `0ba4c3b`에서 PDU 레이어 4 + 런타임 5 = 9개 항목 모두 `[x]` 마킹
- [x] 로드맵 §5.5 체크박스 진척 반영 — commit `1f4ba6f`에서 §5.5 본문을 M1-M7 진척과 동기화 (4 connect API + 17 RdpEvent variant 등 실제 시그니처로 갱신)
- [x] `test-gap-finder` 에이전트로 커버리지 점검 → critical 3개 + important 5개 갭 식별, 8개 신규 테스트 추가 (33 → 41 pass)
  - transport: fast-path 분기 + ASN.1 3·4바이트 long-form + indefinite-length 거부
  - client: `mark_disconnected` 부작용 / `next_event` post-disconnect 단락 + 큐 드레인 / `connect_error_to_runtime` 매핑 / `Transport::Swapping` ErrorKind 구체 검증
  - 미수행: `WaitEarlyUserAuth` raw 4-byte 분기 (CredsspSequence mocking 필요, 별도 작업)
- [x] §9.3 Session Redirection (Task #4) — 3-phase로 완료
  - Phase 1 (`a6724ed`): `ServerRedirectionPdu` 디코더 + 11개 unit test
  - Phase 2 (`fbd9004`): connector 통합 (`ConnectionResult.server_redirection` + finalization wait 함수의 `ShareControlPduType::ServerRedirect` 분기)
  - Phase 3 (`eff6416`): blocking 자동 리다이렉트 루프 (max 5 depth) + UTF-16LE 타겟 파싱 + `RdpEvent::Redirected` 방출 + 7개 unit test

## 잔여 follow-up

- [x] §9.3 connector integration test — wire-format injection으로 redirect path end-to-end 검증 (connector test 2개 추가, total 113)
  - `finalization_wait_pdu_handles_server_redirect`: WaitSynchronize 상태에서 LB cookie 포함 ServerRedirect frame 주입 → state == Connected, server_redirection.session_id/load_balance_info 검증
  - `finalization_wait_font_map_handles_server_redirect`: WaitFontMap 상태에서 LB_TARGET_NET_ADDRESS 포함 frame 주입 → 동일 검증
- [ ] §9.3 RC4 비밀번호 cookie 복호화 (RDSTLS auth)
- [ ] §9.3 진짜 mock broker (TcpListener + 가짜 RDP handshake) — 너무 무거움 (500+ 줄), 후속 작업
- [ ] `DisconnectReason::is_retryable()` 정밀 매핑 (§21.6)
- [ ] `send_mouse_wheel(delta)`
- [ ] `send_synchronize(LockKeys)` for FastPathSyncEvent
- [ ] `disconnect()`가 MCS Disconnect Provider Ultimatum 전송 (현재 단순 drop)
- [ ] `InputDatabase` 내장 (선택, feature flag)
