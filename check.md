총 190개 미체크 항목. 카테고리별로 정리:                                                                                
                                                      
  ---                                                                                                                     
  M-Client 남은 작업                                                                                                      
                                                                                                                          
  🔴 핵심 path — 반드시 끝나야 M-Client 완성                                                                              
                                                                  
  §5.6 Async I/O Runtime (~30 항목, 8-9주):
  - §5.6.1 Phase 1 — WebTransport family promote (7 항목, 1주, 코드 이동만)
  - §5.6.2 Phase 2 — WebClient feature parity (9 항목, 2주, ~1500 LoC:
  InputDB/Reconnect/Redirect/RDSTLS/AAD/SVC/tracing/native-tls)
  - §5.6.3 Phase 3 — Gateway async 포팅 (7 항목, 3주, 최대 위험: HTTP/RPCH/WebSocket 3변형 + NLA nesting)
  - §5.6.4 Phase 4 — AsyncRdpClient v2 (5 항목, 3일)
  - §5.6.6 Phase 6 — Tests + 임베더 가이드 (6 항목, 1주)

  §11.5a Tauri Reference Binary (~9 메인 항목 + 4 sub, 데스크톱 MVP):
  - crates/justrdp-tauri/ 신설
  - bridge 레이어 (tauri::command 5종)
  - frame push 레이어 (tauri::Window::emit)
  - session pump task (§5.6 의존)
  - frontend (TS + canvas)
  - 클립보드/오디오 native 통합
  - 신뢰 모델 + packaging (MSI/DMG/AppImage)
  - smoke test (Windows Server 2019 NLA)

  🟡 Secondary track (stretch)

  §11.5b Native winit/wgpu client (8 항목):
  - CLI (clap), .rdp 파일 지원, wgpu 렌더링, winit, 클립보드/파일/오디오 native, 멀티모니터, 게이트웨이, 세션 녹화

  §11.3 web client 잔여 (1):
  - S6c JS 바인딩 + mic capture demo

  🟢 출시 전 (production gate, Phase 6 동반)

  - §14 Testing — cargo fuzz 인프라 (30+ 항목, fuzz_target 작성/CI 통합/OSS-Fuzz 등록)
  - §17 Security — TLS 최소 버전 강제, RC4 기본 비활성화, NLA/CredSSP 기본 강제, 인증서 검증, MITM 방지, 외부 보안 감사
  (10+ 항목)
  - §20 DoD — Phase별 완료 기준 (xrdp/Windows E2E, 코덱 throughput, ActiveStage 레이턴시, Tauri smoke 등 ~15 항목)

  ⚪ M-Client 외 (deferred / 별도 결정)

  - §9.6 Smartcard PKINIT (4): PaaCookie::from_smartcard_provider, wire format research, mock test, live integration
  - §11.4 FFI (4): Diplomat C FFI, PyO3 Python, opaque handle, 비동기 콜백
  - §10.1 게이트웨이 잔여 follow-up (6): 채널 리사이클 테스트, 실서버 integration, 다중 게이트웨이 장애 조치 등
  - §10.2 RDPEUDP/MT UDP transport (3)

  ---
  M-Server 남은 작업

  🔴 핵심

  §11.6 RD Gateway Server (6 항목):
  - HTTP/HTTPS 게이트웨이
  - WebSocket 전송
  - 인증 (NTLM/Kerberos/Bearer)
  - 리소스 인가
  - 백엔드 RDP 서버 프록시
  - 세션 모니터링

  §11.7 RDP Proxy (4 항목):
  - 투명 프록시 (세션 녹화/감사)
  - 프로토콜 변환
  - 로드 밸런싱
  - 연결 풀링

  Appendix G.1 — License Server (MS-RDPELE Full Licensing) (~30 항목, 가장 큰 단일 작업):
  - ClientNewLicenseRequest 인코더 + sub-fields (RSA PKCS#1, ClientRandom, EncryptedPreMasterSecret 등)
  - ClientPlatformChallengeResponse 인코더 (MAC salt 키 파생, RC4 세션 키, EncryptedHWID)
  - ClientLicenseInfo 인코더
  - §20 DoD — Phase별 완료 기준 (xrdp/Windows E2E, 코덱 throughput, ActiveStage 레이턴시, Tauri smoke 등 ~15 항목)

  ⚪ M-Client 외 (deferred / 별도 결정)

  - §9.6 Smartcard PKINIT (4): PaaCookie::from_smartcard_provider, wire format research, mock test, live integration
  - §11.4 FFI (4): Diplomat C FFI, PyO3 Python, opaque handle, 비동기 콜백
  - §10.1 게이트웨이 잔여 follow-up (6): 채널 리사이클 테스트, 실서버 integration, 다중 게이트웨이 장애 조치 등
  - §10.2 RDPEUDP/MT UDP transport (3)

  ---
  M-Server 남은 작업

  🔴 핵심

  §11.6 RD Gateway Server (6 항목):
  - HTTP/HTTPS 게이트웨이
  - WebSocket 전송
  - 인증 (NTLM/Kerberos/Bearer)
  - 리소스 인가
  - 백엔드 RDP 서버 프록시
  - 세션 모니터링

  §11.7 RDP Proxy (4 항목):
  - 투명 프록시 (세션 녹화/감사)
  - 프로토콜 변환
  - 로드 밸런싱
  - 연결 풀링

  Appendix G.1 — License Server (MS-RDPELE Full Licensing) (~30 항목, 가장 큰 단일 작업):
  - ClientNewLicenseRequest 인코더 + sub-fields (RSA PKCS#1, ClientRandom, EncryptedPreMasterSecret 등)
  - ClientPlatformChallengeResponse 인코더 (MAC salt 키 파생, RC4 세션 키, EncryptedHWID)
  - ClientLicenseInfo 인코더
  - PlatformChallenge / NewLicense / UpgradeLicense PDU
  - step_licensing_exchange() FSM 재작성
  - LicenseStore trait + NoopLicenseStore + FileLicenseStore
  - 풀 교환 wire 트레이스 + RSA/RC4/MAC 테스트 벡터 + e2e 테스트

  🟡 §11.1/§11.2 (이미 골격 있음, 마무리 필요)

  대부분 [x] 체크되어 있음. 남은 건 §11.2e (Session Redirection 서버 emit), §11.2f (ARC 서버 emit) 등 sub-section 일부.

  ---
  핵심 비대칭

  - M-Client: §5.6 async unification (8-9주) + §11.5a Tauri (~2-3주) + §14 fuzz infra + 보안 감사 → 대략 3-4개월 풀타임
  (M-Client 완성 timeline)
  - M-Server: License server (~30 항목) + Gateway server + Proxy + §11.2 잔여 → 대략 2-3개월 풀타임 (M-Client 안정 후
  시작)

  핵심 관찰

  1. §4 Foundation, §6 Codecs, §7 Session Core는 거의 다 완료 — 미체크가 거의 없음. Layer 0 sans-IO core는 안정 단계.
  2. §5 Connection도 거의 완료 — §5.6 async runtime이 유일한 큰 미완 항목.
  3. M-Client의 단일 최대 블로커는 §5.6 — Tauri/web/native 3개 트랙이 모두 의존. 이게 끝나야 §11.5a Tauri MVP 진짜 가능.
  4. §5.6 Phase 3 (게이트웨이 포팅) 이 단일 최대 위험. RPCH/HTTP/2 양방향 + NTLM async 협상이 까다로움. 실제 RD Gateway
  환경 테스트 필요.
  5. §11.4 FFI는 M-Client/M-Server 둘 다 사용하지만 둘 다 production critical은 아님 — 사용자 요청 시 우선순위 ↑.
  6. fuzz infra (§14)와 보안 감사 (§17)는 stable release 전 production gate — 기능 완성과 별개로 마무리 작업.

✻ Cogitated for 1m 17s