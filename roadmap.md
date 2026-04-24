# JustRDP Roadmap

> A pure Rust, production-grade RDP (Remote Desktop Protocol) library.
> Zero C dependencies. `no_std` core. Client & Server. WASM-ready.

---

## Table of Contents

1. [Vision & Design Principles](#1-vision--design-principles)
2. [Architecture Overview](#2-architecture-overview)
3. [Crate Structure](#3-crate-structure)
4. [Phase 1 -- Foundation (Core Protocol)](#4-phase-1----foundation-core-protocol)
5. [Phase 2 -- Connection & Authentication](#5-phase-2----connection--authentication)
6. [Phase 3 -- Standalone Codecs & Primitives](#6-phase-3----standalone-codecs--primitives)
7. [Phase 4 -- Session Core & Channel Frameworks](#7-phase-4----session-core--channel-frameworks)
8. [Phase 5 -- Channel Implementations](#8-phase-5----channel-implementations)
9. [Phase 6 -- Advanced Features & Integration](#9-phase-6----advanced-features--integration)
10. [Phase 7 -- Transport Extensions](#10-phase-7----transport-extensions)
11. [Phase 8 -- Server-Side & Ecosystem](#11-phase-8----server-side--ecosystem)
12. [Protocol Specifications Reference](#12-protocol-specifications-reference)
13. [Public API Design](#13-public-api-design)
14. [Testing Strategy](#14-testing-strategy)
15. [Performance Targets](#15-performance-targets)
16. [Dependency Policy](#16-dependency-policy)
17. [Security Audit Plan](#17-security-audit-plan)
18. [Compatibility Matrix](#18-compatibility-matrix)
19. [Crate Dependency Graph](#19-crate-dependency-graph)
20. [Definition of Done (per Phase)](#20-definition-of-done-per-phase)

Appendices:
- [Appendix B: Error & Disconnect Code Reference](#appendix-b-error--disconnect-code-reference)
- [Appendix C: Glossary](#appendix-c-glossary)
- [Appendix D: Microsoft Documentation URLs](#appendix-d-microsoft-documentation-urls)
- [Appendix E: Milestone Summary](#appendix-e-milestone-summary)
- [Appendix F: Competitive Comparison](#appendix-f-competitive-comparison)
- [Appendix G: Deferred / Backlog](#appendix-g-deferred--backlog)

---

## 1. Vision & Design Principles

### Vision

JustRDP는 Rust 생태계에서 RDP 프로토콜의 **표준 구현체**가 되는 것을 목표로 한다. 어떤 Rust 개발자든 RDP 클라이언트, 서버, 프록시, 게이트웨이를 만들 때 JustRDP를 가져다 쓰면 된다.

### Design Principles

| Principle                 | Description                                                                        |
| ------------------------- | ---------------------------------------------------------------------------------- |
| **Zero C deps**           | 순수 Rust. `libc`, `openssl`, `freerdp` 등 C 라이브러리 의존 없음.                 |
| **`no_std` core**         | 핵심 PDU/코덱/상태머신은 `no_std` + `alloc`으로 동작. embedded/WASM 지원.          |
| **No I/O in core**        | 코어 크레이트는 네트워크/파일 I/O를 직접 수행하지 않음. I/O는 `justrdp-blocking`(또는 미래 `-async`)이 전담. |
| **State machine pattern** | 모든 프로토콜 시퀀스는 명시적 상태 머신. `step(input, output) -> Result<Written>`. |
| **Object-safe traits**    | `Encode`, `Decode`, `SvcProcessor`, `DvcProcessor` 등 핵심 trait는 object-safe.    |
| **Backend injection**     | 플랫폼 종속 기능(클립보드, 파일시스템, 오디오)은 trait로 추상화, 구현 주입.        |
| **Strict tiering**        | Core tier는 proc-macro 금지, 최소 의존, 빠른 컴파일.                               |
| **Incremental adoption**  | feature flag 기반. 필요한 기능만 골라 쓸 수 있음.                                  |

---

## 2. Architecture Overview

```
                           ┌─────────────────────────────┐
                           │        justrdp (meta)        │
                           │   feature-gated re-exports   │
                           └──────────┬──────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
    ┌─────────▼─────────┐  ┌─────────▼─────────┐  ┌─────────▼─────────┐
    │   justrdp-core     │  │  justrdp-connector │  │  justrdp-session  │
    │  Encode/Decode     │  │  Connection FSM    │  │  Active session   │
    │  Cursor, Error     │  │  NLA/CredSSP       │  │  FastPath proc    │
    └─────────┬──────────┘  └─────────┬──────────┘  └─────────┬─────────┘
              │                       │                       │
    ┌─────────▼──────────┐            │              ┌────────▼──────────┐
    │    justrdp-pdu     │◄───────────┘              │  justrdp-graphics │
    │  All PDU types     │                           │  RFX, RLE, ZGFX   │
    │  X.224/MCS/GCC     │                           │  Color conversion │
    │  Capabilities      │                           │  DWT, RLGR        │
    └────────────────────┘                           └───────────────────┘
              │
    ┌─────────▼──────────┐   ┌───────────────────┐   ┌──────────────────┐
    │    justrdp-svc     │   │   justrdp-dvc     │   │  justrdp-bulk    │
    │  Static Virtual Ch │   │  Dynamic Virtual Ch│   │  MPPC/NCRUSH     │
    │  Chunk/Dechunk     │   │  DRDYNVC host     │   │  XCRUSH/ZGFX     │
    └────────────────────┘   └───────────────────┘   └──────────────────┘
              │                       │
    ┌─────────▼───────────────────────▼──────────────────────────────────┐
    │                     Channel Implementations                       │
    │  justrdp-cliprdr  justrdp-rdpdr  justrdp-rdpsnd  justrdp-egfx    │
    │  justrdp-rdpeai   justrdp-displaycontrol  justrdp-rail           │
    └────────────────────────────────────────────────────────────────────┘
              │
    ┌─────────▼──────────────────────────────────────────────────────────┐
    │                       I/O Adapters                                │
    │  justrdp-async (trait)   justrdp-tokio   justrdp-blocking        │
    │  justrdp-tls             justrdp-futures                         │
    └────────────────────────────────────────────────────────────────────┘
              │
    ┌─────────▼──────────────────────────────────────────────────────────┐
    │                     Applications & Bindings                       │
    │  justrdp-client (binary)   justrdp-server   justrdp-web (WASM)   │
    │  justrdp-ffi (C/Python)    justrdp-gateway                       │
    └────────────────────────────────────────────────────────────────────┘
```

### Protocol Layer Stack

```
Application Layer
  ├── Graphics: Bitmap Updates, Drawing Orders, RDPEGFX Pipeline
  ├── Input: Keyboard (scancode/unicode), Mouse, Touch, Pen
  ├── Channels: CLIPRDR, RDPDR, RDPSND, RAIL, EGFX, DisplayControl...
  └── Session Management: Deactivation-Reactivation, Auto-Reconnect

Transport Layer
  ├── Fast-Path (optimized, header-compressed)
  ├── Slow-Path (standard X.224 + MCS framing)
  ├── Virtual Channel chunking (SVC: 1600-byte chunks, DVC: variable)
  └── Bulk Compression (MPPC 8K/64K, NCRUSH, XCRUSH)

Security Layer
  ├── TLS 1.2/1.3 (rustls backend)
  ├── CredSSP / NLA (NTLM + Kerberos via SPNEGO)
  ├── Standard RDP Security (RC4, legacy)
  └── AAD / OAuth2 (Azure AD Join)

Connection Layer
  ├── X.224 (ISO 8073 Class 0) -- Connection Request/Confirm
  ├── MCS (T.125 / ITU-T) -- Domain, channels, data routing
  ├── GCC (T.124) -- Conference creation, settings exchange
  └── TPKT (RFC 1006) -- TCP framing (4-byte header)

Network Layer
  ├── TCP (primary)
  ├── UDP (MS-RDPEUDP, reliable + lossy modes)
  ├── WebSocket (browser, gateway)
  └── RD Gateway (MS-TSGU, HTTP/RPC tunnel)
```

---

## 3. Crate Structure

### Core Tier (`no_std`, no I/O, no proc-macros)

| Crate                    | Description                        | Key Types                                                                                                  |
| ------------------------ | ---------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `justrdp-core`           | 인코딩/디코딩 기초                 | `Encode`, `Decode`, `ReadCursor`, `WriteCursor`, `WriteBuf`                                                |
| `justrdp-pdu`            | 모든 PDU 정의                      | `NegotiationRequest`, `McsConnectInitial`, `ClientInfo`, `CapabilitySet`, `FastPathUpdate`, `ShareDataPdu` |
| `justrdp-graphics`       | 이미지 처리, 코덱                  | `RfxDecoder`, `RleDecoder`, `ZgfxDecompressor`, `DwtTransform`, `RlgrDecoder`, `ColorConverter`            |
| `justrdp-bulk`           | 벌크 압축/해제                     | `Mppc8k`, `Mppc64k`, `Ncrush`, `Xcrush`, `BulkCompressor`, `BulkDecompressor`                              |
| `justrdp-svc`            | Static Virtual Channel 프레임워크  | `SvcProcessor`, `StaticChannelSet`, `ChannelPduHeader`, `SvcMessage`                                       |
| `justrdp-dvc`            | Dynamic Virtual Channel 프레임워크 | `DvcProcessor`, `DrdynvcClient`, `DrdynvcServer`, `DynamicChannelId`                                       |
| `justrdp-connector`      | 연결 상태 머신 (클라이언트)        | `ClientConnector`, `ClientConnectorState`, `Sequence`, `Config`, `CredsspSequence`                         |
| `justrdp-acceptor`       | 연결 상태 머신 (서버, Phase 8)     | `ServerAcceptor`, `ServerAcceptorState`, `AcceptorConfig`                                                  |
| `justrdp-session`        | 활성 세션 처리                     | `ActiveStage`, `ActiveStageOutput`, `FastPathProcessor`, `X224Processor`                                   |
| `justrdp-input`          | 입력 이벤트 관리                   | `InputDatabase`, `Operation`, `Scancode`, `FastPathInputEvent`                                             |
| `justrdp-cliprdr`        | 클립보드 채널                      | `Cliprdr<Role>`, `CliprdrBackend`, `FormatList`, `FormatDataRequest`                                       |
| `justrdp-rdpdr`          | 디바이스 리다이렉션                | `RdpdrClient`, `RdpdrBackend`, `DeviceIoRequest`, `DeviceIoResponse`, `IrpRequest`, `DeviceAnnounce`       |
| `justrdp-rdpsnd`         | 오디오 출력                        | `RdpsndClient`, `RdpsndServer`, `AudioFormat`, `WaveData`                                                  |
| `justrdp-rdpeai`         | 오디오 입력                        | `AudioInputClient`, `AudioInputServer`                                                                     |
| `justrdp-egfx`           | 그래픽스 파이프라인                | `GfxClient`, `GfxServer`, `GfxHandler`, `Surface`, `FrameAck`                                              |
| `justrdp-displaycontrol` | 디스플레이 제어                    | `DisplayControlClient`, `MonitorLayout`                                                                    |
| `justrdp-rail`           | RemoteApp                          | `RailClient`, `RailServer`, `ExecRequest`, `WindowOrder`                                                   |

### Extra Tier (I/O, 플랫폼 종속)

| Crate                    | Description                                                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| `justrdp-blocking`       | **동기 I/O 런타임**: `std::net` 기반 TCP/TLS 펌프, `RdpClient` high-level API, 자동 재연결, 세션 리다이렉트, 프레임 루프 |
| `justrdp-async`          | (미래) async I/O trait 추상화: `FramedRead`, `FramedWrite`, `Framed` — blocking API가 안정된 후 미러                     |
| `justrdp-tls`            | TLS 업그레이드 (rustls 기본, native-tls 옵션) + `ServerCertVerifier` trait                                               |
| `justrdp-cliprdr-native` | OS 네이티브 클립보드 백엔드 (Windows/Linux/macOS)                                                                        |
| `justrdp-rdpdr-native`   | 네이티브 파일시스템 백엔드                                                                                               |
| `justrdp-rdpsnd-native`  | 네이티브 오디오 출력 백엔드                                                                                              |
| `justrdp-rdpeai-native`  | 네이티브 오디오 입력 백엔드                                                                                              |

### Application Tier

| Crate             | Description                                                |
| ----------------- | ---------------------------------------------------------- |
| `justrdp`         | 메타 크레이트, feature flag로 모든 하위 크레이트 re-export |
| `justrdp-client`  | 완전한 RDP 클라이언트 바이너리                             |
| `justrdp-server`  | 확장 가능한 RDP 서버 스켈레톤                              |
| `justrdp-web`     | WASM 바인딩 (브라우저 RDP 클라이언트)                      |
| `justrdp-ffi`     | C/Python FFI 바인딩                                        |
| `justrdp-gateway` | RD Gateway (MS-TSGU) 구현                                  |

### Internal (비공개)

| Crate               | Description                    |
| ------------------- | ------------------------------ |
| `justrdp-testsuite` | 통합 테스트, PDU 스냅샷 테스트 |
| `justrdp-fuzzing`   | 퍼징 타겟                      |
| `justrdp-bench`     | 벤치마크                       |
| `xtask`             | 빌드 자동화                    |

---

## 4. Phase 1 -- Foundation (Core Protocol)

> **목표**: 바이트 스트림을 RDP PDU로 인코딩/디코딩하고, 기본 연결 시퀀스를 수행할 수 있는 기반 확보.

### 4.1 `justrdp-core` -- Encoding Foundation

```rust
// 핵심 trait 정의

/// PDU를 바이트로 인코딩
pub trait Encode {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()>;
    fn name(&self) -> &'static str;
    fn size(&self) -> usize;
}

/// 바이트에서 PDU를 디코딩 (zero-copy, lifetime-bound)
pub trait Decode<'de>: Sized {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self>;
}

/// 바이트에서 PDU를 디코딩 (owned, no lifetime)
pub trait DecodeOwned: Sized {
    fn decode_owned(src: &mut ReadCursor<'_>) -> DecodeResult<Self>;
}

/// PDU 경계 감지 (framing layer에서 사용)
pub trait PduHint: Send + Sync {
    fn find_size(&self, bytes: &[u8]) -> Option<(bool, usize)>;
}
```

**구현 항목:**

- [x] `ReadCursor<'a>` -- zero-copy 바이트 읽기 커서
- [x] `WriteCursor<'a>` -- 바이트 쓰기 커서
- [x] `WriteBuf` -- 동적 크기 쓰기 버퍼
- [x] `Encode` trait
- [x] `Encode` / `Decode` derive 매크로 (`justrdp-derive` 크레이트, `#[pdu(...)]` 속성)
- [x] `Decode<'de>` trait + `DecodeOwned` trait
- [x] `EncodeError`, `DecodeError` 타입
- [x] `IntoOwned` trait (borrowed → owned 변환)
- [x] `AsAny` trait (다운캐스팅 지원)
- [x] 편의 함수: `encode_vec()`, `decode()`, `encode_buf()`

### 4.2 `justrdp-pdu` -- Protocol Data Units

#### 4.2.1 Transport Layer PDUs

**TPKT (RFC 1006):**

- [x] `TpktHeader` -- 4바이트 TCP 프레이밍 (version=3, reserved=0, length)
- [x] `TpktHeader::find_size()` -- PduHint 구현

**X.224 / TPDU (ISO 8073):**

- [x] `ConnectionRequest` -- CR TPDU (cookie, routing token, nego flags)
- [x] `ConnectionConfirm` -- CC TPDU (selected protocol, flags)
- [x] `DataTransfer` -- DT TPDU (data wrapping)
- [x] `DisconnectRequest` -- DR TPDU

**Negotiation:**

- [x] `NegotiationRequest` -- 요청 프로토콜 (RDP/TLS/CredSSP/RDSTLS/AAD)
- [x] `NegotiationResponse` -- 선택된 프로토콜, 서버 플래그
- [x] `NegotiationFailure` -- 실패 코드 (SSL_REQUIRED, HYBRID_REQUIRED 등)
- [x] `SecurityProtocol` flags 열거형

**Pre-Connection Blob (PCB):**

- [x] `PreConnectionBlob` -- 로드밸런서/연결 브로커용 사전 연결 데이터
- [x] PCB v1: Correlation ID
- [x] PCB v2: Correlation ID + Target name
- [x] Connection Request 이전에 전송, 로드밸런서가 올바른 세션 호스트로 라우팅하기 위해 사용

#### 4.2.2 MCS Layer (T.125)

**BER/PER 인코딩:**

- [x] BER encoder/decoder (MCS Connect Initial/Response용)
- [x] PER encoder/decoder (MCS Domain PDU용)
- [x] ASN.1 기본 타입: INTEGER, OCTET STRING, OBJECT IDENTIFIER, SEQUENCE, CHOICE, ENUMERATED

**MCS PDUs:**

- [x] `McsConnectInitial` -- 도메인 파라미터 + GCC payload
- [x] `McsConnectResponse` -- 결과 + GCC payload
- [x] `McsErectDomainRequest`
- [x] `McsAttachUserRequest` / `McsAttachUserConfirm`
- [x] `McsChannelJoinRequest` / `McsChannelJoinConfirm`
- [x] `McsSendDataRequest` / `McsSendDataIndication`
- [x] `McsDisconnectProviderUltimatum`
- [x] `DomainParameters` (max channels, max users, max tokens, etc.)

#### 4.2.3 GCC Layer (T.124)

**Conference Create:**

- [x] `ConferenceCreateRequest` -- PER-encoded, wraps client data blocks
- [x] `ConferenceCreateResponse` -- PER-encoded, wraps server data blocks

**Client Data Blocks:**

- [x] `ClientCoreData` -- RDP 버전, 해상도, 색상 깊이, 키보드 타입/레이아웃, 클라이언트 이름, 성능 플래그, 연결 타입, 서버 선택 프로토콜
- [x] `ClientSecurityData` -- 암호화 방법, 암호화 레벨
- [x] `ClientNetworkData` -- 요청 채널 목록 (이름 + 옵션)
- [x] `ClientClusterData` -- 세션 리다이렉션, 클러스터 플래그
- [x] `ClientMonitorData` -- 모니터 정의 (좌표, primary 플래그)
- [x] `ClientMonitorExtendedData` -- 물리 크기, 방향, 스케일링
- [x] `ClientMessageChannelData` -- 메시지 채널 지원
- [x] `ClientMultitransportChannelData` -- UDP 멀티트랜스포트 플래그

**Server Data Blocks:**

- [x] `ServerCoreData` -- RDP 버전, 요청 프로토콜, earlyCapabilityFlags
- [x] `ServerSecurityData` -- 암호화 방법, 서버 인증서/공개키
- [x] `ServerNetworkData` -- 할당된 채널 ID 목록
- [x] `ServerMessageChannelData`
- [x] `ServerMultitransportChannelData`

#### 4.2.4 RDP Core PDUs

**Client Info:**

- [x] `ClientInfoPdu` -- 사용자 이름, 비밀번호, 도메인, 셸, 작업 디렉터리
- [x] `ExtendedClientInfo` -- 자동 재연결 쿠키, 성능 플래그, 타임존, 클라이언트 주소, 압축 타입

**Licensing (MS-RDPELE):**

- [x] `LicenseRequest` _(LicenseGenericPdu로 처리)_
- [x] `PlatformChallenge` / `PlatformChallengeResponse` _(LicenseGenericPdu로 처리)_
- [x] `NewLicense` / `UpgradeLicense` _(LicenseGenericPdu로 처리)_
- [x] `LicenseInfo` _(LicenseGenericPdu로 처리)_
- [x] `LicenseErrorMessage` (STATUS_VALID_CLIENT 포함)

**Capability Sets (30종):**

- [x] `GeneralCapability` -- OS 타입, 프로토콜 버전, 압축 타입, extraFlags
- [x] `BitmapCapability` -- 해상도, 색상 깊이, bitmap 압축 지원
- [x] `OrderCapability` -- 지원 drawing order 배열 (32바이트), 협상 플래그
- [x] `BitmapCacheCapability` (Rev1) -- 3개 캐시
- [x] `BitmapCacheRev2Capability` -- 5개 캐시, persistent caching
- [x] `ControlCapability`
- [x] `ActivationCapability`
- [x] `PointerCapability` -- 포인터 캐시 크기, 컬러/라지 포인터 지원
- [x] `ShareCapability`
- [x] `ColorCacheCapability`
- [x] `SoundCapability` -- 비프 지원
- [x] `InputCapability` -- scancode/unicode/fastpath/mouse 플래그
- [x] `FontCapability`
- [x] `BrushCapability`
- [x] `GlyphCacheCapability` -- 10개 글리프 캐시 크기
- [x] `OffscreenCacheCapability`
- [x] `BitmapCacheHostSupportCapability`
- [x] `VirtualChannelCapability` -- 압축, 청크 크기
- [x] `DrawNineGridCacheCapability`
- [x] `DrawGdiPlusCapability`
- [x] `RailCapability` -- RemoteApp 플래그
- [x] `WindowCapability` -- RAIL 윈도우 관리
- [x] `DesktopCompositionCapability`
- [x] `MultifragmentUpdateCapability` -- 최대 요청 크기
- [x] `LargePointerCapability` -- 96x96 / 384x384
- [x] `SurfaceCommandsCapability` -- SetSurfaceBits, FrameMarker
- [x] `BitmapCodecsCapability` -- NSCodec, RemoteFX, JPEG 코덱 협상
- [x] `FrameAcknowledgeCapability`

**Connection Finalization PDUs:**

- [x] `SynchronizePdu`
- [x] `ControlPdu` (Cooperate / RequestControl / GrantedControl)
- [x] `PersistentKeyListPdu`
  - [x] Key1 / Key2 쌍 (64비트 식별자)으로 캐시 엔트리 참조
  - [x] 5개 캐시에 대한 엔트리 수 (numEntriesCache0~4)
  - [x] 총 엔트리 수 (totalEntriesCache0~4)
  - [x] PERSIST_FIRST_PDU / PERSIST_LAST_PDU 플래그 (대량 키 목록 분할 전송)
  - [x] 서버 응답: 캐시된 비트맵 재전송 생략으로 재연결 속도 향상
- [x] `FontListPdu` / `FontMapPdu`

**Deactivation-Reactivation Sequence:**

- [x] `DeactivateAllPdu` -- 서버가 세션 비활성화 (해상도 변경, 재협상 등)
- [x] Demand Active → Confirm Active 재협상 _(DemandActivePdu / ConfirmActivePdu 구현)_
- [x] Connection Finalization 재수행 _(DeactivateAllPdu → CapabilitiesWaitDemandActive 재진입)_
- [x] 채널 상태 유지 (채널 재생성 불필요) _(채널 ID 보존)_

**Share Data PDUs (활성 세션):**

- [x] `ShareDataHeader` -- pduType2, compressedType, compressedLength
- [x] `UpdatePdu` -- Orders / Bitmap / Palette / Synchronize _(SlowPathUpdatePdu, type + raw body)_
- [x] `PointerUpdatePdu` -- System / Color / New / Cached / Large _(SlowPathPointerUpdatePdu, type + raw body)_
- [x] `InputEventPdu` -- 입력 이벤트 배열
- [x] `SuppressOutputPdu`
- [x] `RefreshRectPdu`
- [x] `ShutdownRequestPdu` / `ShutdownDeniedPdu`
- [x] `SaveSessionInfoPdu` -- Logon / AutoReconnect
- [x] `SetErrorInfoPdu` -- ~100 disconnect reason 코드 (Appendix B 참조)
  - [x] `ErrorInfoCode` enum (`justrdp-pdu::rdp::error_info`) — 42개
        top-level variant (Protocol-Independent 20 + Licensing 11 +
        Connection Broker 11) + `RdpProtocol(u32)` 랩핑 + `Unknown(u32)`
  - [x] `ErrorInfoCode::description()` — 모든 variant용 static 영문
        메시지
  - [x] `ErrorInfoCode::category()` → `ErrorInfoCategory` (5-way)
  - [x] `ErrorInfoCode::severity()` → `ErrorInfoSeverity`
        (Info/Warning/Error/Fatal, `Ord` 구현)
  - [x] `ErrorInfoCode::is_retryable()` + `SetErrorInfoPdu::code()`
  - [x] **latent bug 수정**: 기존 `is_error_info_retryable(u32)`가
        존재하지 않는 범위(`0x100C..=0x1015` 등)를 licensing으로
        체크해서 실제 라이선스 코드(`0x100..=0x10A`)를 모두 retryable로
        잘못 분류하던 문제 — 이제 enum에 위임
  - [x] 서버 모드 emission API: `SetErrorInfoPdu::new(ErrorInfoCode)`
        + `From<ErrorInfoCode>`. 서버 상태머신(§11.1/11.2)이 착수되면
        이 생성자를 그대로 사용해 Share Data Header 에 감싸 전송
- [x] `SetKeyboardIndicatorsPdu`
- [x] `SetKeyboardImeStatusPdu`
- [x] `MonitorLayoutPdu`

**Auto-Detect PDUs (Network Characteristics Detection):**

- [x] `AutoDetectRequest` / `AutoDetectResponse` _(AutoDetectPdu로 통합 처리)_
- [x] RTT Measure Request/Response (requestType 0x0001/0x1001)
- [x] Bandwidth Measure Start (requestType 0x0014)
- [x] Bandwidth Measure Payload (requestType 0x0002)
- [x] Bandwidth Measure Stop (requestType 0x002B/0x0429)
- [x] Bandwidth Measure Results (responseType 0x003B/0x0003)
- [x] Network Characteristics Result (requestType 0x0840/0x0880/0x08C0)
  - [x] baseRTT, bandwidth, averageRTT
- [x] Connect-Time vs. Continuous Auto-Detect 구분

**Multitransport PDUs:**

- [x] `InitiateMultitransportRequest` / `MultitransportResponse`

#### 4.2.5 Fast-Path PDUs

**Fast-Path Output (서버 → 클라이언트):**

- [x] `FastPathOutputHeader` -- action, numEvents, length, encryption
- [x] `FastPathBitmapUpdate` -- 비트맵 데이터 배열 _(FastPathOutputUpdate로 통합)_
- [x] `FastPathPaletteUpdate` _(FastPathOutputUpdate로 통합)_
- [x] `FastPathSurfaceCommands` -- SetSurfaceBits / StreamSurfaceBits / FrameMarker _(FastPathOutputUpdate로 통합)_
- [x] `FastPathPointerUpdate` -- Position / System / Color / New / Cached / Large _(FastPathOutputUpdate로 통합)_
- [x] `FastPathOrdersUpdate` -- Drawing order 배열 _(FastPathOutputUpdate로 통합)_

**Fast-Path Input (클라이언트 → 서버):**

- [x] `FastPathInputHeader`
- [x] `FastPathKeyboardEvent` (scancode)
- [x] `FastPathUnicodeKeyboardEvent`
- [x] `FastPathMouseEvent`
- [x] `FastPathExtendedMouseEvent`
- [x] `FastPathRelativeMouseEvent`
- [x] `FastPathSyncEvent`
- [x] `FastPathQoeTimestampEvent`

#### 4.2.6 Drawing Orders (MS-RDPEGDI)

**Primary Drawing Orders (22종):**

- [x] `DstBlt`, `PatBlt`, `ScrBlt`, `OpaqueRect` _(PrimaryOrder + PrimaryOrderType enum, raw body)_
- [x] `MultiDstBlt`, `MultiPatBlt`, `MultiScrBlt`, `MultiOpaqueRect` _(PrimaryOrder)_
- [x] `DrawNineGrid`, `MultiDrawNineGrid` _(PrimaryOrder)_
- [x] `LineTo`, `Polyline`, `PolygonSc`, `PolygonCb` _(PrimaryOrder)_
- [x] `MemBlt`, `Mem3Blt` _(PrimaryOrder)_
- [x] `SaveBitmap` _(PrimaryOrder)_
- [x] `GlyphIndex`, `FastIndex`, `FastGlyph` _(PrimaryOrder)_
- [x] `EllipseSc`, `EllipseCb` _(PrimaryOrder)_
- [x] `OrderInfo` -- 바운딩 rect, 필드 존재 플래그 _(BoundsRect + field_flags, body는 raw bytes)_

**Secondary Drawing Orders (Cache):**

- [x] `CacheBitmapV1` / `CacheBitmapV2` / `CacheBitmapV3` _(SecondaryOrder + SecondaryOrderType)_
- [x] `CacheColorTable` _(SecondaryOrder)_
- [x] `CacheGlyph` / `CacheGlyphV2` _(SecondaryOrder)_
- [x] `CacheBrush` _(SecondaryOrder)_

**Alternate Secondary Orders:**

- [x] `CreateOffscreenBitmap` / `DeleteOffscreenBitmap` _(AlternateSecondaryOrder)_
- [x] `SwitchSurface` _(AlternateSecondaryOrder)_
- [x] `FrameMarker` (begin/end) _(AlternateSecondaryOrder)_
- [x] `StreamBitmapFirst` / `StreamBitmapNext` _(AlternateSecondaryOrder)_

#### 4.2.7 Cryptographic Primitives

- [x] RC4 encrypt/decrypt (Standard RDP Security)
- [x] RSA public key operations (서버 인증서 검증, 키 교환, RDP raw encrypt)
- [x] MD4 (NTLM NT hash)
- [x] MD5, SHA-1, SHA-256, HMAC (세션 키 파생)
- [x] FIPS 140-1 triple-DES + CBC mode
- [x] AES-128/256 ECB, CBC, CTS (Kerberos)

---

## 5. Phase 2 -- Connection & Authentication

> **목표**: Windows RDP 서버에 실제로 연결하여 세션을 수립할 수 있는 상태.

### 5.1 `justrdp-connector` -- Connection State Machine

```rust
/// 연결 상태 열거형 -- 전체 연결 시퀀스를 인코딩
pub enum ClientConnectorState {
    // Phase 1: Connection Initiation
    ConnectionInitiationSendRequest,
    ConnectionInitiationWaitConfirm,

    // Phase 2: Security Upgrade
    EnhancedSecurityUpgrade,     // TLS 핸드셰이크 (호출자가 수행)

    // Phase 3: NLA / CredSSP
    CredsspNegoTokens,
    CredsspPubKeyAuth,
    CredsspCredentials,
    CredsspEarlyUserAuth,        // HYBRID_EX: EarlyUserAuthResult 수신

    // Phase 4: Basic Settings Exchange
    BasicSettingsExchangeSendInitial,   // MCS Connect Initial + GCC
    BasicSettingsExchangeWaitResponse,  // MCS Connect Response + GCC

    // Phase 5: Channel Connection
    ChannelConnectionSendErectDomainRequest,
    ChannelConnectionSendAttachUserRequest,
    ChannelConnectionWaitAttachUserConfirm,
    ChannelConnectionChannelJoin,       // 각 채널에 대해 Join 반복

    // Phase 6: Security Commencement (Standard RDP Security만 해당)
    SecurityCommencement,

    // Phase 7: Secure Settings Exchange
    SecureSettingsExchange,             // Client Info PDU 전송

    // Phase 8: Connect-Time Auto-Detection
    ConnectTimeAutoDetection,

    // Phase 9: Licensing
    LicensingExchange,

    // Phase 10: Multitransport Bootstrapping
    MultitransportBootstrapping,

    // Phase 11: Capabilities Exchange
    CapabilitiesExchangeWaitDemandActive,
    CapabilitiesExchangeSendConfirmActive,

    // Phase 12: Connection Finalization
    ConnectionFinalizationSendSynchronize,
    ConnectionFinalizationSendCooperate,
    ConnectionFinalizationSendRequestControl,
    ConnectionFinalizationSendPersistentKeyList,
    ConnectionFinalizationSendFontList,
    ConnectionFinalizationWaitSynchronize,
    ConnectionFinalizationWaitCooperate,
    ConnectionFinalizationWaitGrantedControl,
    ConnectionFinalizationWaitFontMap,

    // Terminal
    Connected { result: ConnectionResult },
}
```

**구현 항목:**

- [x] `ClientConnector` struct -- `Sequence` trait 구현
- [x] `Sequence` trait -- `next_pdu_hint()`, `state()`, `step()`
- [x] `Config` struct:
  ```rust
  pub struct Config {
      pub credentials: Credentials,
      pub domain: Option<String>,
      pub desktop_size: DesktopSize,
      pub color_depth: ColorDepth,
      pub keyboard_type: KeyboardType,
      pub keyboard_subtype: u32,
      pub keyboard_layout: u32,
      pub client_name: String,
      pub client_build: u32,
      pub security_protocol: SecurityProtocol,
      pub performance_flags: PerformanceFlags,
      pub auto_reconnect_cookie: Option<Vec<u8>>,
      pub bitmap_codecs: BitmapCodecConfig,
      pub compression: CompressionConfig,
      pub static_channels: StaticChannelSet,
  }
  ```
- [x] `ConnectionResult` -- 연결 결과 (채널 ID 매핑, 서버 capabilities, 세션 정보)
- [x] `ChannelConnectionSequence` -- 채널 Join 반복 상태 머신
- [x] `LicenseExchangeSequence` -- **단축 경로만**: `STATUS_VALID_CLIENT`
      수신 시 통과, `LicenseRequest`/`PlatformChallenge` 수신 시
      `ERR_NO_LICENSE_SERVER` 로 거절. MS-RDPELE §2.2.2.3 이후의 풀
      RSA/RC4 교환은 Appendix G.1 (deferred) 참조
- [x] `ConnectionActivationSequence` -- Demand Active / Confirm Active 교환

### 5.2 Authentication

#### 5.2.1 CredSSP / NLA (Network Level Authentication)

- [x] `CredsspSequence` -- CredSSP 상태 머신
- [x] `TsRequest` PDU 인코딩/디코딩 (version 2-6)
- [x] SPNEGO 협상 래퍼
- [x] 서버 공개키 바인딩 (`pubKeyAuth`)
- [x] 자격 증명 전송 (`authInfo`)
- [x] `EarlyUserAuthResult` (HYBRID_EX)
- [x] `clientNonce` anti-replay (v5+)

#### 5.2.2 NTLM Authentication

- [x] `NtlmNegotiateMessage` -- 플래그, 도메인 힌트
- [x] `NtlmChallengeMessage` -- 서버 챌린지, 타겟 정보, 플래그
- [x] `NtlmAuthenticateMessage` -- NTProofStr, 세션 키, MIC
- [x] NTLMv2 해시 계산 (NTOWFv2)
- [x] NTProofStr 생성
- [x] 세션 키 파생
- [x] MIC (Message Integrity Code) 계산 -- SPNEGO mechListMIC 누락이 원인. MsvAvFlags MIC_PROVIDED 재활성화 + mechListMIC 추가로 수정
- [x] NTLM 서명/봉인 (signing/sealing)
- [x] 빈 도메인 시 서버 `NbDomainName` 자동 사용 (로컬 계정 지원)

#### 5.2.3 Kerberos Authentication

- [x] AS-REQ / AS-REP (TGT 획득)
- [x] TGS-REQ / TGS-REP (서비스 티켓: `TERMSRV/<hostname>`)
- [x] AP-REQ / AP-REP (서비스 인증)
- [x] KDC Proxy URL 지원
- [x] 키탭 / 패스워드 기반 인증
- [x] PKINIT (스마트카드/인증서 기반)

#### 5.2.4 Standard RDP Security (Legacy)

- [x] RSA 키 교환 (서버 공개키로 클라이언트 랜덤 암호화)
- [x] 세션 키 파생 (client random + server random → RC4 키)
- [x] RC4 암호화/복호화
- [x] 서버 프로프라이어터리 인증서 파싱
- [x] FIPS 140-1 모드 (3DES + SHA-1)

#### 5.2.5 Remote Credential Guard

- [x] 자격증명 위임 없이 Kerberos 기반 SSO
- [x] CredSSP에서 자격증명을 서버로 전송하지 않음 (MITM 방지)
- [x] 클라이언트가 Kerberos 서비스 티켓만 전달
- [x] `PROTOCOL_RDSTLS` negotiation flag
- [x] Remote Credential Guard 활성화 시 `TSSmartCardCreds` 대신 `RemoteGuardPackageCred` 전송
- [x] Compound Identity 지원 (디바이스 클레임 포함)

#### 5.2.6 Restricted Admin Mode

- [x] 서버에 자격증명을 저장하지 않는 관리자 모드
- [x] Pass-the-Hash 위험 감소 (관리자 자격증명이 원격 세션에 캐시되지 않음)
- [x] CredSSP에서 빈 자격증명 전송
- [x] `RESTRICTED_ADMIN_MODE_REQUIRED` 플래그
- [x] 네트워크 리소스 접근 시 서버의 머신 계정 사용
- [x] 관리자 그룹 멤버십 필수

#### 5.2.7 Azure AD Authentication (RDSTLS/AAD)

- [x] OAuth2 device code flow (caller 책임, connector는 토큰 수신만)
- [x] Azure AD 토큰 획득 (caller 책임, AadConfig으로 전달)
- [x] RDSAAD 프로토콜 핸드셰이크 (ServerNonce → AuthRequest/JWS → AuthResult)
- [x] Azure AD Join 시나리오 (Hybrid Azure AD Join 포함) -- PROTOCOL_RDSAAD 지원

> **참고**: ARM (Azure Resource Manager) 엔드포인트 해석은 justrdp의 범위 밖입니다.
> AVD/Windows 365 사용 시 caller가 직접 ARM API를 호출하여 hostname/device ID를 알아낸 뒤
> `AadConfig.resource_uri`에 전달해야 합니다. 일반 Windows Server 연결에는 불필요합니다.

### 5.3 실서버 연결 시퀀스 검증

> 실서버: Windows Server 2019 build 17763 (192.168.136.136), 계정: rdptest
> xfreerdp(WSL)로 동일 서버 접속 성공 확인 완료.
>
> **참고**: 아래 단계의 connector 코드는 대부분 구현되어 있었으나 실서버와의 호환성 버그가 있었음.
> 단위 테스트만으로는 발견 불가능한 와이어 레벨 인코딩 오류들이 주원인.
> `rdp-debugger` 에이전트와 xfreerdp 바이트 비교로 디버깅.

**CredSSP/NLA (완료 2026-03-30):**

- [x] SubjectPublicKey BIT STRING unused bits 0x00 제거
- [x] MsvAvFlags MIC_PROVIDED + NTLM MIC + SPNEGO mechListMIC 구현 (CVE-2019-1040 필수)
- [x] 서버 응답 mechListMIC 검증 + recv RC4 save/restore
- [x] CredSSP v6 접속 성공

**BasicSettingsExchange (완료 2026-03-30):**

- [x] GCC ConferenceCreateRequest PER 프리앰블 8바이트 수정
- [x] CS_CORE: V10_12 버전, RDP 10.0+ 필드 5개, supportedColorDepths 0x000F, cluster VERSION5
- [x] GCC ConferenceCreateResponse PER 파싱 수정 (choice byte, tag, ServerNetworkData)

**Channel Connection (완료 2026-03-30):**

- [x] ErectDomain + AttachUser + ChannelJoin(x2) 성공
- [x] `is_send_state()` 분류 오류 수정 — ChannelJoin의 send/wait 교대 동작 복구

**SecureSettingsExchange ~ Licensing (완료 2026-03-30):**

- [x] Client Info PDU 전송 (273 bytes) — 서버 수락
- [x] Licensing 교환 성공 (34 bytes 양방향)

**Capabilities Exchange (완료 2026-03-30):**

- [x] Server Demand Active 수신 (472 bytes)
- [x] Client Confirm Active 전송 (425 bytes)

**Connection Finalization (완료 2026-03-30):**

- [x] Synchronize, Cooperate, RequestControl, FontList 전송
- [x] Server Synchronize + Cooperate + GrantedControl + FontMap 수신 → `Connected` 도달
- [x] ConfirmActive originatorId 수정 (user channel → 0x03EA server channel)
- [x] Order capability: orderSupport[32] 채움 + desktopSaveSize + textFlags (ERRINFO_BADCAPABILITIES 해결)
- [x] **RDP 연결 수립 완료** — Windows Server 2019에서 Connected 상태 확인

**잔여 기술 부채:**

- [x] GCC ConferenceCreateResponse roundtrip 테스트 — UD prefix 3바이트로 수정, `#[ignore]` 제거
- [x] integration test 디버그 hex dump 코드 정리
- [x] PRNG `simple_random_seed()` → OS 랜덤(`getrandom`) 교체

### 5.4 `justrdp-tls` -- TLS Transport

- [x] `TlsUpgrader` trait
- [x] `rustls` 백엔드 (기본)
- [x] `native-tls` 백엔드 (feature flag)
- [x] 서버 공개키 추출 (`extract_server_public_key()`)
- [x] 자체 서명 인증서 처리 (RDP 서버 일반적)
- [x] TLS 1.2 / 1.3 지원
- [x] **`ServerCertVerifier` trait** — `verify(&self, cert_der, server_name) -> CertDecision { Accept, Reject, AcceptOnce }`
  - [x] `AcceptAll` (mstsc.exe 기본), `PinnedSpki` (SHA-256 SPKI 핀닝, constant-time 비교)
  - [x] rustls `VerifierBridge` 래핑 (`with_verifier(Arc<dyn ServerCertVerifier>)`)
  - [x] native-tls post-handshake verification path (M1 follow-up)

### 5.5 `justrdp-blocking` -- Synchronous I/O Runtime

> **requires**: 5.1 Connector, 5.4 TLS, 7.1 Session
> **목표**: sans-I/O 코어 위에 `std::net` 기반 펌프 + 재연결 정책 + high-level API를 얹어, 라이브러리 사용자가 TCP/TLS/상태 머신 펌프 코드를 직접 작성하지 않아도 되도록 함
> **검증**: 실서버 integration test (xrdp Docker + Windows RDS), 재연결/리다이렉션 E2E

**배경:**

정책상 `justrdp-*` 코어 크레이트는 I/O를 수행하지 않음 (no_std + 상태 머신 패턴). 그 결과 실제 동작하는 클라이언트를 만들려면 사용자가 매번 ~200줄의 펌프 루프 코드를 작성해야 했고, "Auto-Reconnect", "Session Redirection" 같은 기능은 PDU만 파싱하고 실제 재연결은 앱 책임으로 미뤄져 있었음. `justrdp-blocking`은 이 공백을 메우는 **유일한 I/O 수행 크레이트**로, 모든 네트워크 책임을 중앙집중화.

**Crate 범위:**

- 의존성: `justrdp-connector`, `justrdp-session`, `justrdp-tls`, `justrdp-input`, `std::net::TcpStream`
- 선택 의존성: `justrdp-svc`/`justrdp-dvc`/`justrdp-cliprdr`/`justrdp-rdpdr`/`justrdp-rdpsnd`/`justrdp-egfx` (feature flags)
- I/O 모델: 동기 블로킹 (`TcpStream::read`/`write`), 옵션 타임아웃

**High-Level API (M1~M7 기준 실제 시그니처):**

```rust
pub struct RdpClient { /* ... */ }

impl RdpClient {
    // Connect — 4가지 진입점, 각각 다른 trade-off
    pub fn connect<A: ToSocketAddrs>(server: A, server_name: &str, config: Config) -> Result<Self, ConnectError>;
    pub fn connect_with_verifier<A>(server: A, server_name: &str, config: Config, verifier: Arc<dyn ServerCertVerifier>) -> Result<Self, ConnectError>;
    pub fn connect_with_processors<A>(server: A, server_name: &str, config: Config, processors: Vec<Box<dyn SvcProcessor>>) -> Result<Self, ConnectError>;
    pub fn connect_with_upgrader<A, U: TlsUpgrader>(server: A, server_name: &str, config: Config, upgrader: U, processors: Vec<Box<dyn SvcProcessor>>) -> Result<Self, ConnectError>;

    // Active session loop
    pub fn next_event(&mut self) -> Result<Option<RdpEvent>, RuntimeError>;
    pub fn set_reconnect_policy(&mut self, policy: ReconnectPolicy);

    // Input
    pub fn send_keyboard(&mut self, scancode: Scancode, pressed: bool) -> Result<(), RuntimeError>;
    pub fn send_unicode(&mut self, ch: char, pressed: bool) -> Result<(), RuntimeError>;
    pub fn send_mouse_move(&mut self, x: u16, y: u16) -> Result<(), RuntimeError>;
    pub fn send_mouse_button(&mut self, button: MouseButton, pressed: bool, x: u16, y: u16) -> Result<(), RuntimeError>;

    pub fn disconnect(self) -> Result<(), RuntimeError>;
}

pub enum RdpEvent {
    // Graphics + pointer
    GraphicsUpdate { update_code: FastPathUpdateType, data: Vec<u8> },
    PointerDefault, PointerHidden,
    PointerPosition { x: u16, y: u16 },
    PointerBitmap { pointer_type: u16, data: Vec<u8> },
    // Keyboard / IME / sound (M4b)
    KeyboardIndicators { scroll: bool, num: bool, caps: bool, kana: bool },
    ImeStatus { state: u32, convert: u32 },
    PlaySound { frequency: u32, duration_ms: u32 },
    SuppressOutput { allow: bool },
    // Session info / monitor / channel passthrough
    SaveSessionInfo(SaveSessionInfoData),
    ServerMonitorLayout { monitors: Vec<MonitorLayoutEntry> },
    ChannelData { channel_id: u16, data: Vec<u8> },
    // Lifecycle (M7 + future 9.3)
    Reconnecting { attempt: u32 },
    Reconnected,
    Redirected { target: String },           // 9.3 미구현
    Disconnected(GracefulDisconnectReason),
}
```

> **차이 노트**: `send_mouse(x, y, buttons)` 단일 함수 대신 `send_mouse_move` + `send_mouse_button` 분리. `resize()`는 미구현 (DisplayControl/MonitorLayout DVC 확장 필요). `Reconnecting`은 attempt 카운터만 포함 (reason은 별도 Disconnected 이벤트로).

**구현 항목:**

> 진척 요약: M1~M7 마일스톤 모두 완료 (`crates/justrdp-blocking/CHECKLIST.md` 참조). 33개 단위 테스트 통과. 실서버 통합 테스트만 잔여.

- [x] **연결 수립 펌프** (M1~M3, 커밋 `5fd0864` / `cc331ed` / `8846565`)
  - [x] `TcpStream::connect` (eager `to_socket_addrs` 해석으로 reconnect 시 DNS 스킵)
  - [x] `ClientConnector::step()` 루프 구동 (`drive_until_state_change` 헬퍼)
  - [x] `EnhancedSecurityUpgrade` → `Transport::Swapping` → TLS 업그레이드 → `Transport::Tls`
  - [x] `EarlyUserAuthResult` 4바이트/TsRequest fallback 분기 (HYBRID_EX)
  - [x] `ServerCertVerifier` 콜백 주입 (rustls + native-tls 양쪽)
  - [x] TCP / TLS 핸드셰이크 타임아웃 — `Config::connect_timeout`
        (기본 30s). `TcpStream::connect_timeout` + `set_read_timeout` +
        `set_write_timeout` 를 raw TcpStream에 설정하고, 세션 펌프
        진입 직전에 `try_clone()` 핸들로 `None` 해제 (세션 reads는
        무한 대기 유지)
- [x] **ActiveStage 펌프** (M4, 커밋 `03ed1da` + `a829d72`)
  - [x] Fast-path/slow-path 자동 분기 (`TpktHint`가 첫 바이트 보고 dispatch)
  - [x] `BulkDecompressor` 상태 세션 수명 동안 유지 (`ActiveStage` 내부에 슬로우/패스트패스 별도 컨텍스트)
  - [x] `ActiveStageOutput::ResponseFrame` → 즉시 소켓 write
  - [x] `GraphicsUpdate` / `Pointer*` / `SaveSessionInfo` / `ServerMonitorLayout` / `ChannelData` → `RdpEvent` 매핑
  - [x] `SuppressOutputPdu` 디코드 → `RdpEvent::SuppressOutput { allow }`
  - [x] `SetKeyboardIndicatorsPdu` → `RdpEvent::KeyboardIndicators { scroll, num, caps, kana }` (OS LED는 앱 책임)
  - [x] `SetKeyboardImeStatusPdu` → `RdpEvent::ImeStatus`
  - [x] `PlaySoundPdu` (type 34) → `RdpEvent::PlaySound { frequency, duration_ms }` (justrdp-pdu에 PDU 신규 추가)
- [x] **입력 송신** (M5, 커밋 `78f3bf6`)
  - [x] `send_keyboard(scancode, pressed)` — `FastPathScancodeEvent` (KBDFLAGS_RELEASE/EXTENDED)
  - [x] `send_unicode(ch, pressed)` — BMP 한정, 서로게이트 페어는 `Unimplemented`
  - [x] `send_mouse_move(x, y)` — `PTRFLAGS_MOVE`
  - [x] `send_mouse_button(button, pressed, x, y)` — Left/Right/Middle (`PTRFLAGS_BUTTON1/2/3 + DOWN`)
  - [x] `send_mouse_wheel(delta, horizontal, x, y)` — PTRFLAGS_WHEEL / PTRFLAGS_HWHEEL / PTRFLAGS_WHEEL_NEGATIVE, 매그니튜드 0..=255 클램프
  - [x] `send_synchronize(LockKeys)` — `FastPathSyncEvent` 연결 완료
  - [x] `InputDatabase` 상태 관리 내부화 — 고수준 상태추적 API 완료 (`key_press/release`, `button_press/release`, `move_mouse`, `synchronize`, `release_all_input`)
- [x] **채널 이벤트 배선** (M6, 커밋 `0067c17`)
  - [x] `RdpClient::connect_with_processors(server, name, config, processors)` — SVC processor 등록
  - [x] `read_one_frame`의 `ChannelData` 분기: 등록된 processor 있으면 dispatch + 응답 frame write, 없으면 raw passthrough
  - [x] DVC 지원: `DrdynvcClient`가 `SvcProcessor` 구현이라 박싱해서 SVC로 등록하면 자동 동작
  - [x] Clipboard/Drive/Audio processor → 사용자가 직접 인스턴스화 후 등록 (라이브러리는 dispatch만 담당)
- [x] **Auto-Reconnect 실제 재연결** (M7, 커밋 `0ba4c3b`, **§9.2 완성**)
  - [x] TCP disconnect 감지 (`read_pdu` 에러 → `RuntimeError::Disconnected`/`Io` → `try_reconnect`)
  - [x] `ReconnectPolicy` (`max_attempts` + `initial_delay` + `max_delay` + 지수 `backoff`)
  - [x] `last_arc_cookie` 자동 캡처 (`SaveSessionInfoData::arc_random()`) + `Config::auto_reconnect_cookie` 재사용
  - [x] `RdpEvent::Reconnecting { attempt }` / `Reconnected` 방출
  - [x] `can_reconnect()` 사전 검사 (정책 활성 + cookie 있음 + SVC 비어 있음)
  - [x] `is_error_info_retryable(code) -> bool` — user intent / policy / transient / license / broker 5-way 분류. blocking의 `next_event` Terminate 분기에서 `try_reconnect` 게이트로 연결
- [x] **Session Redirection 자동 리다이렉트** (§9.3 3-phase 완료)
  - [x] Redirection PDU 수신 시 현재 소켓 종료 (finalization wait에서 ShareControlPduType::ServerRedirect 감지)
  - [x] Target 주소 파싱 (UTF-16LE → SocketAddr, LB_TARGET_NET_ADDRESS / LB_TARGET_NET_ADDRESSES fallback)
  - [x] Routing Token/Cookie를 새 `Config.routing_token`에 주입 (X.224 routingToken field)
  - [x] `RdpEvent::Redirected { target }` 방출 (handshake 루프 탈출 후 one-shot event)
  - [x] 리다이렉션 루프 방지 (MAX_REDIRECTS = 5)
- [x] **에러 처리** (M1~M6 누적)
  - [x] `ConnectError` enum (`Tcp` / `Tls` / `Connector` / `UnexpectedEof` / `FrameTooLarge` / `ChannelSetup` / `Unimplemented`)
  - [x] `RuntimeError` enum (`Io` / `Session` / `FrameTooLarge` / `Disconnected` / `Unimplemented`)
  - [x] `is_error_info_retryable(code)` 분류 (user intent / policy / transient / license / broker 5-way)
- [x] **Integration tests**
  - [x] xrdp Docker 컨테이너 E2E (`tests/xrdp/Dockerfile` +
        `.github/workflows/e2e-xrdp.yml`) — manual/weekly workflow가
        Ubuntu 22.04 + xrdp + xorgxrdp + xfce4 컨테이너를 빌드/기동하고
        `connect_test` 예제로 `testuser:testpass@localhost:3389` 에
        연결, 종료 코드로 회귀 판정. 알려진 finalization 버그(Windows RDS
        WaitSynchronize 드랍)는 xrdp 대상에서 재현 여부가 아직 미확인
        이라 현재는 on-demand/주간 스케줄
  - [x] Windows RDS E2E (manual, `192.168.136.136`) — connect_test 예제로 양방향 활성 세션 검증 (GraphicsUpdate + PointerBitmap + 입력 송신)
  - [x] Auto-reconnect: `test_drop_transport()` → `Reconnecting` → `Reconnected` → 정상 재개 (420ms)
  - [x] Session redirection: connector-level wire-format injection test 2개 (WaitSynchronize + WaitFontMap 양쪽에서 LB cookie / TARGET_NET_ADDRESS 검증)

#### 5.5.1 Non-blocking follow-ups

> M1~M7은 완료된 상태이며 `Connected` / active session 목표를 달성.
> 아래 항목들은 M1~M7의 blocker가 아니고 생태계 편의성 개선용.

- [x] **`.rdp` 파일 로딩** (`justrdp-rdpfile` 통합)
  - [x] `ConfigBuilder::apply_rdp_file(&RdpFile)` — no_std 매핑
        (domain, desktop size, color depth, compression, CredSSP bit,
        PerformanceFlags 7개)
  - [x] `justrdp_connector::rdpfile::server_address(&RdpFile)` —
        IPv4/IPv6(bracketed)/hostname + `server port` fallback → default 3389
  - [x] `justrdp_blocking::rdpfile::rdp_file_config(path, user, pass)` —
        one-shot path→`RdpFileConfig { address, hostname, port, config }`
  - [x] 21 unit test (16 connector + 5 blocking)
- [x] **관찰성**
  - [x] `tracing` crate 지원 (`justrdp-blocking` feature `tracing`,
        기본 off — 의존 없는 빌드 보장)
  - [x] 연결 단계별 이벤트: `rdp.connect.{start, tcp, phase=x224_nego,
        phase=tls_upgrade, phase=credssp, phase=basic_settings_to_finalization,
        phase=connected, redirect, handshake complete}`
  - [x] 재연결 이벤트: `rdp.reconnect.{begin, attempt, ok, skipped,
        exhausted}`
  - [x] 내부 `src/telemetry.rs` shim — feature off 시 매크로가
        no-op으로 확장되어 런타임 오버헤드 0
> License persistence는 Appendix G.1 (MS-RDPELE Full Licensing)에서
> 풀 교환과 함께 처리된다. 단독 구현이 불가능하므로 follow-up
> 체크박스가 아니라 deferred 항목으로 취급한다.

---

## 6. Phase 3 -- Standalone Codecs & Primitives

> **목표**: Connected 상태 없이 단독 구현+테스트 가능한 코덱, 압축, 입력 처리, 파서.
> 모두 `no_std` + unit test로 검증. 서버 연결 불필요.

### Prerequisites (Phase 1/2에서 이관)

- [x] Primary order 필드별 파싱 + delta encoding (DstBlt, PatBlt, ScrBlt, OpaqueRect, MemBlt, LineTo)
- [x] 그래픽 캐시 무효화 여부 판단 (`deactivation_count` 시그널 + `PrimaryOrderHistory::reset()`)
- [x] `AutoDetectSequence` 상태 머신 (wait state로 변경, 서버 PDU를 licensing에 전달)

### 6.1 `justrdp-bulk` -- Bulk Compression

> **requires**: 없음 (순수 알고리즘, `no_std`)
> **검증**: RFC/스펙 테스트 벡터 + roundtrip

- [x] `Mppc8kDecompressor` -- MPPC 8K 슬라이딩 윈도우 (RDP 4.0)
- [x] `Mppc64kDecompressor` -- MPPC 64K 슬라이딩 윈도우 (RDP 5.0)
- [x] `NcrushDecompressor` -- NCRUSH (RDP 6.0, Huffman 기반)
- [x] `XcrushDecompressor` -- XCRUSH (RDP 6.1, LZNT1 + match finder)
- [x] `ZgfxDecompressor` / `ZgfxCompressor` -- RDP8 벌크 압축 (RDPEGFX용)
- [x] `BulkCompressor` -- 통합 압축기 (자동 알고리즘 선택)
- [x] 모든 구현 zero unsafe, `no_std`

### 6.2 `justrdp-graphics` -- Legacy Bitmap Codecs

> **requires**: 없음 (순수 디코더, `no_std`)
> **검증**: 알려진 비트맵 → 디코딩 → 픽셀 비교

#### 6.2.1 Interleaved RLE (RDP 4.0/5.0)

- [x] `RleDecoder` -- Run-Length Encoding 디코딩
- [x] 8bpp, 15bpp, 16bpp, 24bpp 지원
- [x] 포어그라운드/백그라운드 런, 컬러 런, FGBG 이미지, 세트 런, 디더링 런

#### 6.2.2 Planar Codec

- [x] `PlanarDecoder` -- RLE 기반 평면 비트맵 디코딩
- [x] Alpha / Red / Green / Blue 평면 분리
- [x] 평면 내 RLE 디코딩

#### 6.2.3 RDP 6.0 Bitmap Compression

- [x] `Rdp6Decoder` / `Rdp6Encoder` -- 비트맵 스트림 디코딩/인코딩

### 6.3 `justrdp-graphics` -- RemoteFX (RFX) Codec

> **requires**: 없음 (순수 수학/코덱, `no_std`)
> **검증**: 알려진 타일 데이터 → 파이프라인 → 픽셀 비교

전체 파이프라인:

```
RFX 비트스트림
  → RLGR 디코딩 (Run-Length Golomb-Rice)
  → 서브밴드 재구성 (HL, LH, HH 계수 재배치)
  → 역양자화 (quantization table 적용)
  → 역 DWT (Discrete Wavelet Transform, 2D)
  → YCbCr → RGB 색상 변환
  → RGBA 프레임 버퍼 출력
```

- [x] `RlgrDecoder` / `RlgrEncoder` -- RLGR1, RLGR3 모드
- [x] `SubbandReconstructor` -- 계수 재배치
- [x] `Dequantizer` -- 양자화 테이블 적용
- [x] `DwtTransform` -- 2D DWT (forward/inverse)
- [x] `ColorConverter` -- YCbCr ↔ RGBA
- [x] `RfxDecoder` -- 전체 파이프라인 조합
- [x] `RfxEncoder` -- 서버/프록시용 인코딩 파이프라인
- [x] RFX 타일 (64x64) 관리

### 6.4 `justrdp-graphics` -- NSCodec

> **requires**: 없음 (순수 디코더, `no_std`)

- [x] `NsCodecDecoder` -- NSCodec 디코딩
- [x] 채널 분리 (ARGB 채널별 독립 처리)
- [x] NSCodec RLE 디코딩
- [x] ChromaSubsampling 처리

### 6.5 `justrdp-graphics` -- ClearCodec

> **requires**: 없음 (순수 디코더, `no_std`)

- [x] `ClearCodecDecoder` -- ClearCodec 디코딩
- [x] Residual Layer (잔차 레이어)
- [x] Band Layer (밴드 레이어)
- [x] Subcodec Layer (서브코덱 레이어)
- [x] Glyph 캐싱

### 6.6 Image Processing Utilities

> **requires**: 없음 (`no_std`)

- [x] 사각형 처리 (교집합, 합집합, 분할)
- [x] 이미지 diff (변경 영역 감지, 서버용)
- [x] 색상 공간 변환 (RGB ↔ BGR, RGBA ↔ BGRA 등)
- [x] 스케일링/리사이징

### 6.7 Pointer/Cursor Processing

> **requires**: 없음 (순수 디코더, `no_std`)

- [x] `PointerDecoder` -- 포인터 비트맵 디코딩
- [x] 1bpp, 24bpp, 32bpp 포인터
- [x] XOR/AND 마스크 처리
- [x] Large pointer (384x384) 지원
- [x] 포인터 캐시 관리

### 6.8 `justrdp-input` -- Input Event Management

> **requires**: 없음 (순수 상태 머신, `no_std`)
> **검증**: unit test로 상태 diff 검증

- [x] `InputDatabase` -- 키보드 + 마우스 상태 추적
- [x] 키보드: 512-bit 비트필드 (모든 스캔코드 상태)
- [x] 마우스: 5 버튼 + 위치 + 휠 상태
- [x] 상태 diff 기반 이벤트 생성 (중복 이벤트 방지)
- [x] `Operation` enum:
  ```rust
  pub enum Operation {
      KeyPressed(Scancode),
      KeyReleased(Scancode),
      UnicodeKeyPressed(u16),
      UnicodeKeyReleased(u16),
      MouseButtonPressed(MouseButton),
      MouseButtonReleased(MouseButton),
      MouseMove(u16, u16),
      WheelRotations(i16),
      HorizontalWheelRotations(i16),
  }
  ```
- [x] `Scancode` 타입 (extended flag 포함)
- [x] `synchronize_event()` -- 잠금 키 동기화

### 6.9 `.rdp` File Support

> **requires**: 없음 (순수 파서, `no_std` 호환)

- [x] `.rdp` 파일 포맷 파서/라이터
- [x] 모든 표준 설정 키 지원
- [x] `no_std` 호환

### 6.10 `justrdp-audio` -- Audio Codecs

> **requires**: 없음 (순수 코덱, `no_std`)
> **검증**: 알려진 오디오 데이터 → 디코딩 → PCM 샘플 비교

```rust
pub trait AudioDecoder: Send {
    fn decode(&mut self, input: &[u8], output: &mut [i16]) -> AudioResult<usize>;
    fn sample_rate(&self) -> u32;
    fn channels(&self) -> u16;
}
```

- [x] PCM -- passthrough (포맷 변환: u8/i16/i24/f32 → i16)
- [x] MS-ADPCM -- `ADPCMACOEF` 테이블 기반 블록 디코딩 (RFC 2361)
- [x] IMA-ADPCM -- `wSamplesPerBlock` 기반 블록 디코딩 (RFC 2361)
- [x] AAC -- HEAACWAVEINFO 파싱, ADTS 프레임 길이 추출
- [x] Opus -- OpusHead 파싱 (RFC 7845)
- [x] `AudioDecoder` trait -- 통합 디코더 인터페이스 (`justrdp-audio`)
- [x] 포맷별 디코더 팩토리 (`make_decoder(AudioFormat) → Box<dyn AudioDecoder>`, `justrdp-rdpsnd`)

---

## 7. Phase 4 -- Session Core & Channel Frameworks

> **목표**: Active Session 수신 루프와 SVC/DVC 프레임워크 구축.
> 이 Phase가 완료되어야 서버에서 오는 PDU를 받아 채널로 디스패치할 수 있음.

### 7.1 `justrdp-session` -- Active Session Processing

> **requires**: Phase 2 (Connected 상태), Phase 3 bulk compression
> **검증**: integration test로 실서버에서 Fast-Path/Slow-Path 프레임 수신 확인

- [x] `ActiveStage` -- 활성 세션 프로세서
- [x] Fast-Path 입력 프레임 생성
- [x] Fast-Path 출력 프레임 파싱 + 벌크 해제
- [x] X.224/Slow-Path 프레임 파싱
- [x] 프레임 단편화/재조립 (`CompleteData`)
- [x] 출력 디스패치:
  ```rust
  pub enum ActiveStageOutput {
      ResponseFrame(Vec<u8>),
      GraphicsUpdate { update_code: FastPathUpdateType, data: Vec<u8> },
      PointerDefault,
      PointerHidden,
      PointerPosition { x: u16, y: u16 },
      PointerBitmap { pointer_type: u8, data: Vec<u8> },
      Terminate(GracefulDisconnectReason),
      DeactivateAll(DeactivationReactivation),
      SaveSessionInfo { info_type: u32, data: Vec<u8> },
      ChannelData { channel_id: u16, data: Vec<u8> },
  }
  ```
- [x] 세션 Deactivation-Reactivation 처리
- [x] Graceful shutdown 시퀀스

### 7.2 `justrdp-svc` -- Static Virtual Channel Framework

> **requires**: 7.1 (세션에서 MCS 채널 데이터를 수신해야 함)
> **검증**: PDU roundtrip + chunking/dechunking unit test, integration test로 채널 데이터 수신 확인

```rust
/// Static Virtual Channel 프로세서
pub trait SvcProcessor: AsAny + Debug + Send {
    fn channel_name(&self) -> ChannelName;
    fn start(&mut self) -> PduResult<Vec<SvcMessage>>;
    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>>;
    fn compression_condition(&self) -> CompressionCondition { CompressionCondition::WhenRdpDataIsCompressed }
}
```

**구현 항목:**

- [x] `SvcProcessor` trait
- [x] `SvcClientProcessor` / `SvcServerProcessor` marker traits
- [x] `StaticChannelSet` -- TypeId 기반 채널 집합
- [x] `ChannelPduHeader` -- 플래그(FIRST/LAST/SHOW_PROTOCOL/SUSPEND/RESUME), 총 길이
- [x] 자동 chunking (기본 1600바이트) / dechunking
- [x] MCS `SendDataRequest` / `SendDataIndication` 래핑
- [x] 채널 ID ↔ 채널 이름 매핑

### 7.3 `justrdp-dvc` -- Dynamic Virtual Channel Framework

> **requires**: 7.2 (DVC는 DRDYNVC SVC 위에서 동작)
> **검증**: PDU roundtrip + DataFirst/Data 재조립 unit test

```rust
/// Dynamic Virtual Channel 프로세서
pub trait DvcProcessor: AsAny + Send {
    fn channel_name(&self) -> &str;
    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>>;
    fn process(&mut self, channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>>;
    fn close(&mut self, channel_id: u32);
}
```

**구현 항목:**

- [x] `DvcProcessor` trait
- [x] `DrdynvcClient` -- 클라이언트 측 DVC 호스트
- [x] Capability negotiation (v1/v2/v3)
- [x] Channel Create/Close 시퀀스
- [x] DataFirst/Data 재조립 (`CompleteData`)
- [x] 우선순위 지원 (v2: high/medium/low/lowest)

---

## 8. Phase 5 -- Channel Implementations

> **목표**: 클립보드, 파일 공유, 오디오, 디스플레이 제어, EGFX 등 채널별 구현.
> Phase 4의 SVC/DVC 프레임워크 위에 각 채널 프로세서를 구현.

### 8.1 `justrdp-cliprdr` -- Clipboard Channel (MS-RDPECLIP)

> **requires**: 7.2 SVC 프레임워크
> **검증**: PDU roundtrip + integration test (실서버 클립보드 교환)

**SVC 이름**: `CLIPRDR`

```rust
pub trait CliprdrBackend: Send {
    fn on_format_list(&mut self, formats: &[ClipboardFormat]) -> ClipboardResult<FormatListResponse>;
    fn on_format_data_request(&mut self, format_id: u32) -> ClipboardResult<FormatDataResponse>;
    fn on_format_data_response(&mut self, data: &[u8], is_success: bool);
    fn on_file_contents_request(&mut self, request: &FileContentsRequest) -> ClipboardResult<FileContentsResponse>;
    fn on_file_contents_response(&mut self, response: &FileContentsResponse);
    fn on_lock(&mut self, lock_id: u32);
    fn on_unlock(&mut self, lock_id: u32);
}
```

**구현 항목:**

- [x] `Cliprdr<R: Role>` -- Generic 클립보드 프로세서 (Client/Server)
- [x] 초기화 시퀀스 (Capabilities → Monitor Ready → Format List)
- [x] Format List PDU (포맷 ID + 이름)
- [x] Format Data Request/Response PDU
- [x] File Contents Request/Response PDU (FILECONTENTS_SIZE / FILECONTENTS_RANGE)
- [x] Temporary Directory PDU
- [x] Lock/Unlock Clipboard Data PDU
- [x] Long format names 지원
- [x] 표준 포맷: CF_TEXT, CF_UNICODETEXT, CF_DIB, CF_HDROP

### 8.2 `justrdp-rdpsnd` -- Audio Output (MS-RDPEA)

> **requires**: 7.2 SVC 프레임워크 (SVC 모드), 7.3 DVC 프레임워크 (DVC 모드)
> **검증**: PDU roundtrip + integration test (실서버 오디오 수신)

**SVC 이름**: `RDPSND` / **DVC 이름**: `AUDIO_PLAYBACK_DVC`, `AUDIO_PLAYBACK_LOSSY_DVC`

**구현 항목:**

- [x] 초기화 시퀀스 (Formats → Quality Mode → Training)
- [x] 오디오 포맷 협상
- [x] Wave/Wave2 PDU 수신 및 디코딩
- [x] WaveConfirm PDU 전송 (타임스탬프 동기화)
- [x] 볼륨/피치 제어
- [x] DVC 전송 모드:
  - [x] `RdpsndDvcClient` -- `DvcProcessor` 구현 (`AUDIO_PLAYBACK_DVC`)
  - [x] Lossy DVC 채널 (`AUDIO_PLAYBACK_LOSSY_DVC`) 지원
  - [x] SVC/DVC 공통 로직 추출 (PDU 처리, 상태 머신 공유)
- [x] 코덱 → `justrdp-audio` crate (Phase 3 코덱 패턴, `justrdp-bulk`/`justrdp-graphics` 동일 구조)

### 8.3 `justrdp-rdpdr` -- Device Redirection (MS-RDPEFS)

> **requires**: 7.2 SVC 프레임워크
> **검증**: PDU roundtrip + integration test (실서버 드라이브 리다이렉션)

**SVC 이름**: `RDPDR`

```rust
pub trait RdpdrBackend: Send {
    fn device_list(&self) -> Vec<DeviceAnnounce>;
    fn create(&mut self, device_id: u32, path: &str, desired_access: u32, create_disposition: u32) -> IoResult<FileHandle>;
    fn read(&mut self, handle: FileHandle, offset: u64, length: u32) -> IoResult<Vec<u8>>;
    fn write(&mut self, handle: FileHandle, offset: u64, data: &[u8]) -> IoResult<u32>;
    fn close(&mut self, handle: FileHandle) -> IoResult<()>;
    fn query_information(&mut self, handle: FileHandle, info_class: u32) -> IoResult<FileInformation>;
    fn query_directory(&mut self, handle: FileHandle, pattern: &str) -> IoResult<Vec<DirectoryEntry>>;
    fn query_volume_information(&mut self, device_id: u32, info_class: u32) -> IoResult<VolumeInformation>;
    fn device_control(&mut self, handle: FileHandle, ioctl_code: u32, input: &[u8]) -> IoResult<Vec<u8>>;
    fn lock(&mut self, handle: FileHandle, offset: u64, length: u64, exclusive: bool) -> IoResult<()>;
    fn unlock(&mut self, handle: FileHandle, offset: u64, length: u64) -> IoResult<()>;
}
```

**구현 항목:**

- [x] 초기화 시퀀스 (Announce → Name → Capability → Device List)
- [x] 디바이스 타입: Filesystem, Serial, Parallel, Printer, Smartcard
- [x] IRP (I/O Request Packet) 처리:
  - [x] IRP_MJ_CREATE / CLOSE / READ / WRITE
  - [x] IRP_MJ_DEVICE_CONTROL (IOCTL)
  - [x] IRP_MJ_QUERY_INFORMATION / SET_INFORMATION
  - [x] IRP_MJ_QUERY_VOLUME_INFORMATION / SET_VOLUME_INFORMATION
  - [x] IRP_MJ_DIRECTORY_CONTROL (Query / Notify)
  - [x] IRP_MJ_LOCK_CONTROL
- [x] 드라이브 리다이렉션 (`DeviceAnnounce::filesystem()`, `build_device_list_announce()`)
- [x] 스마트카드 리다이렉션 (MS-RDPESC)
  - [x] NDR/RPCE 인코딩 (`scard::ndr`)
  - [x] SCard IOCTL 상수 (`scard::constants`, 48 IOCTL codes)
  - [x] `ScardBackend` trait (`scard::backend`, 17 SCard API methods)
- [x] 프린터 리다이렉션 (MS-RDPEPC)
  - [x] `PrinterDeviceData` (DR_PRN_DEVICE_ANNOUNCE DeviceData)
  - [x] `PrinterUsingXpsPdu` (DR_PRN_USING_XPS)
  - [x] `PrinterCacheDataPdu` (DR_PRN_CACHE_DATA)

### 8.4 `justrdp-displaycontrol` -- Display Control (MS-RDPEDISP)

> **requires**: 7.3 DVC 프레임워크
> **검증**: PDU roundtrip + integration test (동적 리사이즈)

**DVC 이름**: `Microsoft::Windows::RDS::DisplayControl`

**구현 항목:**

- [x] Capabilities PDU 수신 (최대 모니터 수, 최대 해상도)
- [x] Monitor Layout PDU 전송:
  ```rust
  pub struct MonitorLayoutEntry {
      pub flags: MonitorFlags,   // PRIMARY
      pub left: i32,
      pub top: i32,
      pub width: u32,
      pub height: u32,
      pub physical_width: u32,   // mm
      pub physical_height: u32,  // mm
      pub orientation: Orientation, // 0, 90, 180, 270
      pub desktop_scale_factor: u32,
      pub device_scale_factor: u32,
  }
  ```
- [x] 동적 리사이즈
- [x] 멀티모니터 레이아웃 변경

### 8.5 `justrdp-rdpeai` -- Audio Input (MS-RDPEAI)

> **requires**: 7.3 DVC 프레임워크
> **검증**: PDU roundtrip

**DVC 이름**: `AUDIO_INPUT`

**구현 항목:**

- [x] 버전 교환
- [x] 오디오 포맷 협상
- [x] Open/Close 시퀀스
- [x] 오디오 캡처 데이터 전송
- [x] 포맷 변경

### 8.6 `justrdp-egfx` -- Graphics Pipeline Extension (RDPEGFX)

> **requires**: 7.3 DVC 프레임워크 + Phase 3 코덱들 (RFX, ClearCodec, Planar, ZGFX)
> **검증**: PDU roundtrip + integration test (실서버에서 GFX 프레임 수신 → 디코딩)

**DVC 이름**: `Microsoft::Windows::RDS::Graphics`

```rust
pub trait GfxHandler: Send {
    fn on_create_surface(&mut self, surface_id: u16, width: u16, height: u16, pixel_format: PixelFormat);
    fn on_delete_surface(&mut self, surface_id: u16);
    fn on_map_surface(&mut self, surface_id: u16, output_origin_x: u32, output_origin_y: u32);
    fn on_bitmap_update(&mut self, surface_id: u16, codec_id: CodecId, data: &[u8], dest_rect: Rectangle);
    fn on_solid_fill(&mut self, surface_id: u16, fill_color: u32, rects: &[Rectangle]);
    fn on_surface_to_surface(&mut self, src: u16, dst: u16, src_rect: Rectangle, dest_points: &[Point]);
    fn on_cache_to_surface(&mut self, cache_slot: u16, surface_id: u16, dest_points: &[Point]);
    fn on_surface_to_cache(&mut self, surface_id: u16, cache_slot: u16, src_rect: Rectangle);
    fn on_evict_cache(&mut self, cache_slot: u16);
    fn on_reset_graphics(&mut self, width: u32, height: u32, monitors: &[MonitorDef]);
    fn on_start_frame(&mut self, frame_id: u32, timestamp: u32);
    fn on_end_frame(&mut self, frame_id: u32) -> FrameAck;
}
```

**구현 항목:**

- [x] Capability negotiation (v8.0 ~ v10.7)
- [x] `WireToSurface1` PDU -- 코덱 기반 비트맵 전송
- [x] `WireToSurface2` PDU -- 컨텍스트 기반 비트맵 전송
- [x] `DeleteEncodingContext` PDU
- [x] `SolidFill` PDU
- [x] `SurfaceToSurface` PDU
- [x] `SurfaceToCache` / `CacheToSurface` / `EvictCacheEntry` PDU
- [x] `CacheImportOffer` / `CacheImportReply` PDU
- [x] `CreateSurface` / `DeleteSurface` PDU
- [x] `ResetGraphics` PDU
- [x] `MapSurfaceToOutput` / `MapSurfaceToScaledOutput` PDU
- [x] `MapSurfaceToWindow` / `MapSurfaceToScaledWindow` PDU (RAIL)
- [x] `StartFrame` / `EndFrame` PDU
- [x] `FrameAcknowledge` PDU
- [x] 코덱 디스패치 (Uncompressed, ClearCodec, Planar, RFX, H.264, Alpha)
- [x] ZGFX 압축/해제 통합
- [x] DVC 압축 지원 (DYNVC_DATA_FIRST_COMPRESSED, DYNVC_DATA_COMPRESSED) -- ZGFX-Lite 8KB 윈도우
- [x] Progressive RFX (단계적 품질 향상, MS-RDPEGFX)

### 8.7 `justrdp-rail` -- RemoteApp (MS-RDPERP)

> **requires**: 7.2 SVC 프레임워크, 8.6 EGFX (`MapSurfaceToWindow` 연동)
> **검증**: PDU roundtrip

**SVC 이름**: `RAIL`

**구현 항목:**

- [x] RAIL Handshake
- [x] Client Status PDU
- [x] Exec Request/Result PDU (원격 앱 실행)
- [x] System Parameters PDU (양방향)
- [x] Window Activate/Deactivate PDU
- [x] System Menu / System Command PDU
- [x] Notification Icon Event PDU
- [x] Get AppId Request/Response PDU
- [x] Language Bar Info PDU
- [x] Window Cloak PDU
- [x] Snap Arrange PDU
- [x] Z-Order Sync PDU
- [x] Window Information Orders (Alternate Secondary):
  - [x] New/Existing Window Order
  - [x] Delete Window Order
  - [x] Notification Icon Order
- [x] EGFX 연동: `MapSurfaceToWindow` / `MapSurfaceToScaledWindow`

### 8.8 H.264/AVC Codec

> **requires**: 없음 (순수 디코더), 하지만 8.6 EGFX 연동 시 실질적 테스트 가능
> **검증**: 알려진 NAL 유닛 디코딩, EGFX WireToSurface로 end-to-end 확인

- [x] AVC420 디코딩 (YUV 4:2:0)
- [x] AVC444 디코딩 (YUV 4:4:4, 두 AVC420 결합)
- [x] AVC444v2 디코딩
- [x] 순수 Rust H.264 디코더 통합 또는 trait 추상화
- [x] 하드웨어 가속 백엔드 trait

### 8.9 Native Platform Backends

> **requires**: 각 채널 구현 (8.1~8.5)
> **검증**: 각 플랫폼에서 실서버 연결 후 기능 확인

- [x] `justrdp-cliprdr-native`:
  - [x] Windows: Win32 Clipboard API 통합
  - [x] Linux: X11 Selection / Wayland data-device
  - [x] macOS: NSPasteboard
  - **Known limitations:**
    - ~~텍스트만 지원; 이미지 미구현~~ → 완료 (CF_DIB 이미지 지원, macOS TIFF→BMP 변환, X11/Wayland BMP, Windows CF_DIB 직접 처리)
    - 파일 전송(CFSTR_FILEDESCRIPTOR/FILECONTENTS) 미구현
    - ~~macOS `unsafe` 블록 세분화 필요~~ → 완료 (objc2 safe API 확인, unsafe 제거)
    - ~~`ClipboardError::Other(&'static str)` → `String` 변경~~ → 완료 (에러 context 보존 가능)
- [x] `justrdp-rdpdr-native`:
  - [x] 네이티브 파일시스템 백엔드
  - **Known limitations:**
    - ~~`notify_change_directory` 미구현~~ → 완료 (macOS kqueue / Linux inotify / Windows FindFirstChangeNotification)
    - ~~`lock_control` 미구현~~ → 완료 (Unix fcntl + Windows LockFileEx/UnlockFileEx)
    - ~~symlink 검증 미구현~~ → 완료 (canonicalize + starts_with 가드, 부모 디렉토리 검증 포함)
    - ~~rename TOCTOU race~~ → 완료 (Linux renameat2 RENAME_NOREPLACE / macOS renameatx_np RENAME_EXCL / Windows MoveFileExW)
    - ~~`set_information(FILE_BASIC_INFORMATION)` 타임스탬프 반영 미구현~~ → 완료 (Unix utimensat / Windows SetFileTime)
    - ~~volume info `bytes_per_sector`/`sectors_per_cluster` 하드코딩~~ → 완료 (Windows GetDiskFreeSpaceW, Unix statvfs)
- [x] `justrdp-rdpsnd-native`:
  - [x] Windows: waveOut API
  - [x] Linux: PulseAudio / PipeWire
  - [x] macOS: CoreAudio (AudioQueue)
  - **Known limitations:**
    - ~~macOS: AudioQueue buffer leak~~ → 완료 (buffer pool 패턴 + output callback 도입)
    - ~~macOS: byte_size u32 truncation~~ → 완료 (u32::try_from + 청크 분할)
    - ~~Windows: waveOut ManuallyDrop 미적용~~ → 완료 (ManuallyDrop 적용)
    - ~~Windows: WasapiOutput 이름 불일치~~ → 완료 (WaveOutOutput으로 리네임)
    - ~~PulseAudio: per-stream 볼륨 미지원~~ → 완료 (introspect API로 sink input 볼륨 제어)
- [x] `justrdp-rdpeai-native`:
  - [x] Windows: waveIn 캡처
  - [x] Linux: PulseAudio / PipeWire 캡처
  - [x] macOS: CoreAudio (AudioQueue Input) 캡처
  - **Known limitations:**
    - ~~macOS: Arc raw pointer leak in close()~~ → 완료 (shared_raw 필드 + close() 회수)
    - ~~macOS: AudioQueueAllocateBuffer/EnqueueBuffer 반환값 미검사~~ → 완료
    - ~~macOS: read() condvar 타임아웃 없음~~ → 완료 (READ_TIMEOUT 5초)
    - ~~macOS: ring buffer 크기 제한 없음~~ → 완료 (RING_BUFFER_MAX_PACKETS 제한)
    - ~~`packet_byte_size()` overflow 미방어~~ → 완료 (checked_mul + validate())
    - ~~플랫폼 테스트 부재~~ → 완료 (coreaudio: 포맷 거부, open/close, ring buffer 검증 등 7개 테스트 추가)

---

## 9. Phase 6 -- Advanced Features & Integration

> **목표**: 프로덕션 수준의 완성도. 엔터프라이즈 환경에서 요구하는 기능.
> Phase 4/5의 세션+채널 인프라 위에 구축.

### 9.1 Multi-Monitor Support

> **requires**: 8.6 EGFX (`ResetGraphics`), 8.4 DisplayControl
> **검증**: integration test (다중 모니터 레이아웃 전송 → 서버 응답)

**PDU (완료):**

- [x] `ClientMonitorData` (GCC CS_MONITOR 0xC005) -- 최대 16개 `MonitorDef` (justrdp-pdu)
- [x] `ClientMonitorExtendedData` (GCC CS_MONITOR_EX 0xC008) -- `MonitorAttributeDef` (justrdp-pdu)
- [x] `MonitorLayoutPdu` 수신 구조체 (MS-RDPBCGR 2.2.12.1, justrdp-pdu)
- [x] EGFX `ResetGraphicsPdu` + `GfxMonitorDef` (justrdp-egfx)
- [x] `DisplayControlClient` + `MonitorLayoutPdu` 전송 (justrdp-displaycontrol)

**Connector 통합:**

- [x] `Config`에 `monitors: Vec<MonitorConfig>` 추가 (좌표, DPI, 물리크기, primary, orientation)
- [x] `ConfigBuilder::monitor()` / `monitors()` 빌더 메서드
- [x] GCC Basic Settings에 `ClientMonitorData` + `ClientMonitorExtendedData` 전송
- [x] `ClientCoreData`에 `SUPPORT_MONITOR_LAYOUT_PDU` 플래그 설정
- [x] 단일 모니터일 때 Monitor Data 블록 생략 (기존 동작 유지)

**세션 중 모니터 변경:**

- [x] Finalization 단계에서 `MonitorLayoutPdu` 수신 → 콜백/이벤트 전달
- [x] EGFX `ResetGraphics` 모니터 매핑 (서버 재구성 시)
- [x] `DisplayControlClient`로 런타임 모니터 레이아웃 변경 전송

**좌표 & 스케일링:**

- [x] 가상 데스크톱 좌표 처리 (음수 좌표, bounding rect 계산)
- [x] DPI 스케일링 조율 (GCC Extended Data ↔ DisplayControl 간 일관성)

**테스트 보강:**

- [x] Session 통합 테스트: TPKT→X.224→MCS→ShareData 와이어 프레임으로 `ServerMonitorLayout` 출력 검증
- [x] Connector 통합 테스트: Finalization 중 MonitorLayoutPdu 주입 → `ConnectionResult.server_monitor_layout` 검증

### 9.2 Auto-Reconnect

> **requires**: 7.1 세션 (Save Session Info PDU 수신), Phase 2 커넥터, **5.5 `justrdp-blocking`** (실제 재연결)
> **검증**: `justrdp-blocking` integration test (연결 끊기 → 자동 재연결 3초 이내)

**PDU / 상태 머신 레이어 (완료):**

- [x] Auto-Reconnect Cookie 저장/복원 (Save Session Info PDU)
- [x] ARC (Auto-Reconnect Cookie) 랜덤 생성
- [x] ClientAutoReconnectPacket 전송 (Client Info PDU 내)
- [x] `ArcCookie` API + `SaveSessionInfoData::arc_random()` + `ConnectionResult.server_arc_cookie` + `ConfigBuilder::auto_reconnect_cookie()` + HMAC-MD5 SecurityVerifier 자동 계산

**런타임 레이어 (`justrdp-blocking` §5.5에서 구현):**

- [x] TCP 끊김 감지 (read EOF / Io 에러)
- [x] `ReconnectPolicy` (최대 시도, 초기 지연, 최대 지연, 지수 백오프)
- [x] 새 소켓 + TLS 재업그레이드 + ARC cookie 기반 재인증 (`do_one_reconnect`)
- [x] `RdpEvent::Reconnecting { attempt }` / `Reconnected` 방출
- [x] `next_event()` 자동 reconnect 진입 (Disconnected/Io → try_reconnect)
- [x] 재연결 전제 조건 (`can_reconnect()`): policy.max_attempts > 0 AND last_arc_cookie.is_some() AND svc_set.is_empty()
- [x] SVC processor와 reconnect 상호 배제 (MVP: stateful processors는 자동 재연결 시 부활 불가)
- [x] `is_error_info_retryable(code)` → 재연결 가능 여부 판단 (Appendix B 에러 코드 분류 기반): user intent / policy denial → 비재시도; transient (timeout, OOM, protocol error) → 재시도; licensing / broker → 비재시도

### 9.3 Session Redirection ✅

> **requires**: 7.1 세션 (Redirection PDU 수신), Phase 2 커넥터, **5.5 `justrdp-blocking`** (실제 리다이렉트)
> **검증**: `justrdp-blocking` integration test (mock broker 기반 로드밸런서 시나리오)

**PDU 레이어 (`justrdp-pdu`):** — `crates/justrdp-pdu/src/rdp/redirection.rs`

- [x] `ServerRedirectionPdu` 파싱 (MS-RDPBCGR 2.2.13.1) — 전체 12바이트 헤더 + 11개 optional field, 16개 LB_* flag 상수, `TargetNetAddress` / `TargetNetAddresses` substructs
- [x] Enhanced Security 변형 (MS-RDPBCGR 2.2.13.3.1) — Connector가 `ShareControlHeader.pdu_type == ServerRedirect` 분기에서 2바이트 pad 후 본문 파싱
- [x] `RedirFlags` 16개 비트 모두 정의 (TargetNetAddress, LoadBalanceInfo, Username, Domain, Password, DontStoreUsername, SmartcardLogon, NoRedirect, TargetFQDN, TargetNetBiosName, TargetNetAddresses, ClientTsvUrl, ServerTsvCapable, PasswordIsPkEncrypted, RedirectionGuid, TargetCertificate)
- [x] Routing Token / LB Info 바이트 배열 추출 (raw `Vec<u8>` — 바이트 그대로 보존, 호출자가 해석)
- [x] **의도적 미구현**: 비밀번호 cookie RC4/서버 공개키 복호화 —
      클라이언트는 `LB_PASSWORD_IS_PK_ENCRYPTED` blob 을 복호화하지
      않고 `Config.redirection_password_blob` 에 raw bytes 로 보존,
      RDSTLS 재인증 시 그대로 forward (§5.2.6). 실제 복호화는 target
      RD Session Host 가 담당하므로 클라이언트 측 암호화 처리 경로는
      설계상 존재하지 않는다. 투명 전달 구현은 바로 아래 "PK-encrypted
      password cookie 투명 전달" 항목 참조.
- [x] 11개 단위 테스트 (header roundtrip, magic 거부, 절단/오버런 거부, 단일/복수 field, TargetNetAddresses 구조, 64KB sanity cap, padding 소비)

**Connector 레이어 (`justrdp-connector`):**

- [x] `ConnectionResult.server_redirection: Option<ServerRedirectionPdu>` 필드 노출
- [x] `Config.routing_token: Option<Vec<u8>>` + `ConfigBuilder::routing_token(Vec<u8>)` 메서드
- [x] Routing Token을 X.224 Connection Request `routingToken` field에 주입 (mstshash cookie보다 우선)
- [x] `step_finalization_wait_pdu` / `step_finalization_wait_font_map` 양쪽에서 `ShareControlPduType::ServerRedirect` 감지 + 2바이트 pad 소비 + 본문 파싱 + `transition_to_connected()` 호출

**런타임 레이어 (`justrdp-blocking` §5.5):**

- [x] `connect_with_upgrader`가 핸드셰이크 루프 (max 5 depth) — 각 iteration마다 새 TCP/TLS/CredSSP/finalization 수행
- [x] `result.server_redirection.is_some()` 감지 시: 현재 transport drop → routing token + 새 target으로 다음 iteration
- [x] Target 주소 파싱 (`parse_redirect_target`): `LB_TARGET_NET_ADDRESS` 우선, fallback `LB_TARGET_NET_ADDRESSES[0]`, UTF-16LE → `String` → `SocketAddr` (default port 재사용)
- [x] 새 `Config` 빌드: 이전 config clone + routing_token = LB info + cookie/auto_reconnect_cookie 클리어 (콜리전 방지)
- [x] `RdpEvent::Redirected { target }` 방출 (성공 핸드셰이크 후 한 번)
- [x] 리다이렉션 루프 방지 — `MAX_REDIRECTS = 5`, 초과 시 `ConnectError::Tcp(Other)` 반환
- [x] 7개 단위 테스트 (utf16 디코딩, IPv4 default port, 명시 port, target_net_address path, target_net_addresses fallback, 빈 PDU None 반환, 절단 거부)
- [x] 실서버 통합 테스트 — `crates/justrdp-blocking/tests/mock_redirect.rs`
      5개 테스트 (direct target, broker→target redirect, max depth,
      no target address, PK-encrypted password). `TcpListener` 2개로
      broker + target 시뮬레이션, `NoopTlsUpgrader` 로 TLS 스킵.
      세부 Phase 1~4는 아래 §9.3.5 참조

**`justrdp-blocking` 잔여 후속 작업 (CHECKLIST.md에서 이관):**

- [x] `send_synchronize(LockKeys)` — `FastPathSyncEvent` 연결 완료
- [x] `InputDatabase` 상태 관리 내부화 — 고수준 상태추적 API 완료
- [x] PK-encrypted password cookie 투명 전달 — `password_cookie()` 생성자 + Config 필드 + Connector 분기 + Blocking 감지 완료 (클라이언트는 복호화 안함, 투명 전달)
#### 9.3.5 Mock Broker 통합 테스트

> **목적**: Session Redirection E2E 검증 — `TcpListener` 2개 (broker + target)로 redirect path 전체 경로를 실 TCP 위에서 테스트
> **파일**: `crates/justrdp-blocking/tests/mock_redirect.rs`
> **실행**: `cargo test -p justrdp-blocking --test mock_redirect`

**설계 결정:**
- X.224 Confirm에서 `SSL`만 negotiate → `EnhancedSecurityUpgrade` 후 곧바로 GCC로 진입 (CredSSP 전체 스킵)
- `NoopTlsUpgrader` 구현 — TLS 핸드셰이크 없이 raw TCP passthrough, dummy `server_public_key` 반환
- `connect_with_upgrader()`에 주입하여 실 TLS 없이 테스트

**Phase 1 — MockRdpServer 골격:**
- [x] `NoopUpgrader` 구현 (`TlsUpgrader` trait, `PassthroughStream` 래퍼로 TLS 건너뜀)
- [x] `MockMode` enum — `Broker { target_addr, lb_info }` / `Target`
- [x] `run_mock_handshake()` — accept 후 12단계 핸드셰이크 + 모드별 finalization
- [x] `start_mock_server()` — `TcpListener` bind + thread spawn

**Phase 2 — 핸드셰이크 응답 시퀀스:**
- [x] Read X.224 CR → Write X.224 CC (`ConnectionConfirm`, `SSL` only, TPKT 직접 래핑)
- [x] [NoopUpgrader passthrough]
- [x] Read MCS Connect Initial → Write MCS Connect Response (GCC Core/Security/Network, 블록 헤더 자동 포함)
- [x] Read Erect Domain Request (consume)
- [x] Read Attach User Request → Write `AttachUserConfirm` (initiator=1007)
- [x] Read Channel Join Request ×2 → Write `ChannelJoinConfirm` ×2
- [x] Read Client Info PDU → Write `LicenseErrorMessage::valid_client()` (SEC_LICENSE_PKT 플래그)
- [x] Write `DemandActivePdu` (GeneralCapability only)
- [x] Read Confirm Active (consume)
- [x] Read Synchronize + Control Cooperate + Control Request + Font List (consume 4개)
- [x] **Broker 모드**: Write `ServerRedirectionPdu` (LB_LOAD_BALANCE_INFO + LB_TARGET_NET_ADDRESS)
- [x] **Target 모드**: Write Synchronize + Cooperate + Granted Control + Font Map → Connected

**Phase 3 — Redirect E2E 테스트:**
- [x] `test_direct_connect_to_target` — target mock 직접 연결 성공 (redirect 없이)
- [x] `test_redirect_broker_to_target` — broker→target redirect 성공, `RdpEvent::Redirected` 수신, target IP 확인

**Phase 4 — Edge case 테스트:**
- [x] `test_max_redirect_depth_exceeded` — 7개 broker 체인, 6번째 redirect에서 `too many redirects` 에러 확인
- [x] `test_redirect_no_target_address` — LB_TARGET_NET_ADDRESS 없이 redirect → 원래 주소 fallback → TCP 에러 (broker gone)
- [x] `test_redirect_with_pk_encrypted_password` — broker가 PK-encrypted blob 전송 → target X.224 CR에서 `SecurityProtocol::RDSTLS` 확인

**재사용 코드:**
- `TpktHeader::for_payload()`, `DataTransfer`, `SendDataIndication` — 프레임 조립
- `ConnectionConfirm`, `ConnectResponse`, `AttachUserConfirm`, `ChannelJoinConfirm` — Encode impls
- `DemandActivePdu`, `SynchronizePdu`, `ControlPdu`, `FontListPdu` — finalization PDUs
- `encode_vec()` — 범용 PDU 직렬화
- `connector.rs:2794` `build_server_data_frame()` 패턴 참조

### 9.4 Touch Input (MS-RDPEI)

> **requires**: 7.3 DVC 프레임워크 ✅
> **검증**: PDU roundtrip + mock DVC 통합 테스트

**DVC 이름**: `Microsoft::Windows::RDS::Input`

**구현 단계** (CLAUDE.md Implementation Flow 준수):

- [x] **Step 1 — Spec Analysis**: `@spec-checker 9.4 Touch Input (MS-RDPEI)` → `specs/ms-rdpei-checklist.md`
  - MS-RDPEI §2.2 PDU 포맷 전수조사 (RDPINPUT_HEADER, eventId/pduLength)
  - 버전/capability 교환: `EVENTID_SC_READY` (0x01), `EVENTID_CS_READY` (0x02)
  - 터치 이벤트: `EVENTID_TOUCH` (0x03), `EVENTID_SUSPEND_TOUCH` (0x04), `EVENTID_RESUME_TOUCH` (0x05), `EVENTID_DISMISS_HOVERING_CONTACT` (0x06)
  - 프로토콜 버전 상수: `RDPINPUT_PROTOCOL_V1` / `V10` / `V101` / `V200` / `V300`
  - TWO_BYTE_UNSIGNED_INTEGER / FOUR_BYTE_UNSIGNED_INTEGER / EIGHT_BYTE_UNSIGNED_INTEGER 가변 인코딩 규칙
  - RDPINPUT_CONTACT_DATA 필드 (contactId, fieldsPresent, x/y, contactFlags, contactRectLeft/Top/Right/Bottom, orientation, pressure)
  - contactFlags 비트: `DOWN` / `UPDATE` / `UP` / `INRANGE` / `INCONTACT` / `CANCELED`
  - 최대 제약: 256 contacts, 256 frames per PDU

- [x] **Step 2 — PDU 구현** (`crates/justrdp-rdpei/src/pdu.rs`, 39 tests ✅)
  - [x] `RdpeiHeader { event_id: u16, pdu_length: u32 }` + Encode/Decode
  - [x] 가변 길이 정수 헬퍼 (2/4/8-byte unsigned + 2/4-byte signed, all spec examples verified)
  - [x] `ScReadyPdu { protocol_version: u32, supported_features: Option<u32> }` (pdu_length로 V300 features 판별)
  - [x] `CsReadyPdu { flags: u32, protocol_version: u32, max_touch_contacts: u16 }` (fixed 16 bytes)
  - [x] `TouchContact { contact_id, x, y, contact_flags, contact_rect, orientation, pressure }` + 8개 유효 `contactFlags` 조합 validation
  - [x] `TouchFrame { frame_offset, contacts }`
  - [x] `TouchEventPdu { encode_time, frames }`
  - [x] `SuspendInputPdu` / `ResumeInputPdu` (header-only)
  - [x] `DismissHoveringContactPdu { contact_id }`
  - [x] roundtrip + 경계 테스트 (0 frames, 가변 정수 form 전환, orientation/pressure bounds, invalid flag 거부)

- [x] **Step 3 — DVC Processor** (`crates/justrdp-rdpei/src/client.rs`, 20 tests ✅)
  - [x] `RdpeiDvcClient` — `DvcProcessor` 구현 (`DisplayControlClient` 패턴)
  - [x] 채널명 상수: `Microsoft::Windows::RDS::Input`
  - [x] 상태 머신: `WaitScReady` → `Ready` (SC_READY 수신 시 CS_READY 즉시 반환)
  - [x] 공개 API: `send_touch_event(encode_time, frames)`, `dismiss_hovering_contact(id)`, `take_pending_messages()`
  - [x] 프로토콜 버전 협상 (min(server, client_max_version), 기본 client_max = V200)
  - [x] V100 협상 시 `DISABLE_TIMESTAMP_INJECTION` flag 자동 제거 (스펙 SHOULD NOT)
  - [x] Suspend/Resume: `SUSPEND_INPUT` 수신 시 `send_touch_event` 차단 (ADM `InputTransmissionSuspended`)
  - [x] 재연결 시나리오: 두 번째 SC_READY 수신 시 CS_READY 재송신 + suspend flag 리셋
  - [x] 클라 발신 event ID (CS_READY/TOUCH/DISMISS_HOVERING)가 inbound로 도착 시 무시 (§3.1.5.1)
  - [x] `Connector`/세션 레이어 등록 경로 — `crates/justrdp-rdpei/tests/drdynvc_integration.rs`
        3개 통합 테스트로 `DrdynvcClient → RdpeiDvcClient` 라우팅 검증
        (caps → create → SC_READY → CS_READY 왕복, 잘못된 채널 이름
        거절, `Box<dyn SvcProcessor>` vtable 경유)

- [x] **Step 4 — 검증** (77 tests ✅, clean workspace build)
  - [x] `@impl-verifier` 로 스펙 1:1 대조 → 3개 실질 이슈 수정 (TouchFrame::size 절단, ContactRect 미재노출, 무의미한 assertion)
  - [x] `@test-gap-finder` Critical 갭 보강 — partial fields_present 조합 6개, FOUR_BYTE_UNSIGNED boundary wire bytes, x/y 다른 form 크기 16개 조합, ScReadyPdu pduLength-gated features (V200/V300 edge), CsReady/Suspend/Resume 잘못된 length 거부
  - [x] DvcProcessor 트레이트 객체 경유 full-flow 테스트 (vtable dispatch 검증)

**참고 구현 패턴**:
- `justrdp-rdpsnd` (DVC 모드): `RdpsndDvcClient`, 상태 머신, 버전 교환
- `justrdp-displaycontrol`: DVC 채널명 상수, PDU 헤더 공유 패턴

### 9.5 Pen/Stylus Input (MS-RDPEPS)

> **requires**: 9.4 Touch Input (MS-RDPEI V200+) ✅
> **검증**: PDU roundtrip + mock DVC integration

**정정**: MS-RDPEPS 라는 별도 스펙/채널은 존재하지 않습니다. Pen 입력은
MS-RDPEI V200+ 에서 **동일 채널 `Microsoft::Windows::RDS::Input`** 에
`EVENTID_PEN = 0x0008` 이벤트로 추가됩니다. `justrdp-rdpei` 크레이트를
**확장**하는 작업이며, 별도 크레이트가 아닙니다.

**기존 재사용**: `RdpeiHeader`, 가변 정수 코덱(2/4/8-byte), `ScReadyPdu`/
`CsReadyPdu` 협상, `RdpeiDvcClient` 상태 머신, DoS cap 패턴.

**구현 단계** (3단계, §9.4 패턴 축약):

- [x] **Step 1 — Spec Analysis (mini)**: `@spec-checker` MS-RDPEI
  §2.2.3.7+ 의 pen 확장 부분만 분석하여 기존 체크리스트
  (`specs/ms-rdpei-checklist.md` §11–21) 에 append ✅
  - `EVENTID_PEN = 0x0008` PDU 래퍼 구조
  - `RDPINPUT_PEN_CONTACT` 필드 (penContactId, fieldsPresent, x, y, penFlags, 선택: pressure, rotation, tiltX, tiltY)
  - `PEN_FLAGS_*` 비트 및 유효 조합
  - `PEN_FIELDS_PRESENT_*` 비트
  - V200 vs V300 feature 분기 (multipen injection)
  - 최대 펜 contact 수 / 최대 프레임 수 (스펙 vs 정책)

- [x] **Step 2 — Implementation** (`crates/justrdp-rdpei/src/pdu.rs` + `client.rs`, 108 tests ✅)
  - [x] `PenContact { device_id, x, y, contact_flags, pen_flags, pressure, rotation, tilt_x, tilt_y }` + Encode/Decode + `VALID_CONTACT_FLAG_COMBINATIONS` 재사용 (touch와 공유, spec §3.1.1.1)
  - [x] `PenFrame { frame_offset, contacts: Vec<PenContact> }` — 중복 선택 (touch와 semantic/타입 차이로 제네릭화보다 가독성 우선)
  - [x] `PenEventPdu { encode_time, frames }` — `EVENTID_PEN = 0x0008`
  - [x] 가변 정수 재사용 (2/4/8-byte unsigned + 2/4-byte signed 코덱 공유), DoS cap: `MAX_FRAMES_PER_EVENT` 공유 + `MAX_PEN_CONTACTS_PER_FRAME = 4` 별도 (multipen "up to four" 제약)
  - [x] `RdpeiDvcClient::send_pen_event(encode_time, frames)` API
  - [x] 버전 게이트: `pen_input_allowed = negotiated >= V200` 체크
  - [x] V300 multipen 활성 = 3-way AND (negotiated ≥ V300 + 서버 `SC_READY_MULTIPEN_INJECTION_SUPPORTED` + 클라 `CS_READY_FLAGS_ENABLE_MULTIPEN_INJECTION`), 미충족 시 outgoing flag 자동 제거

- [x] **Step 3 — Verification** (120 tests ✅, clean workspace)
  - [x] `@impl-verifier` — 33/35 PASS (2 테스트 커버리지 갭만, 구현은 스펙 정확)
  - [x] `@test-gap-finder` — Critical 4 + Medium 3 갭 식별 및 전부 보강
  - [x] 추가된 테스트: x/y 가변 form 교차, rotation 127/128 form 경계, tilt ±63/±64 form 경계, partial fieldsPresent 조합 (4종), decode-side out-of-range 거부 (invalid flags, pressure, rotation, tilt), pen_event_pdu zero frames + full-optional pdu_length, close()가 pen 상태 리셋 확인, 재연결 시 pen 상태 재협상, send_pen_event 큐 cap

### 9.6 Smartcard Authentication (PKINIT — local card source)

> **requires**: §5.2.3 PKINIT (✅ ASN.1 + KerberosSequence 완성),
> RFC 4556 (PKINIT for Kerberos)
> **검증**: Mock provider 기반 PKINIT AS-REQ 생성 unit test +
> `pcsc` crate 컴파일 통과 (실 하드웨어 검증은 추후)

**정정 사항**:
- 기존 `[ ] 인증서 기반 Kerberos (PKINIT)` 항목은 §5.2.3 line 600 과
  **완전 중복**. ASN.1, AS-REQ/AS-REP 처리, DH 합의는 모두 구현됨
  (`crates/justrdp-pdu/src/kerberos/pkinit.rs` 295줄 +
  `crates/justrdp-connector/src/credssp/kerberos.rs::new_pkinit`).
- 8.3 RDPDR `ScardBackend` (✅ 구현됨)는 **서버로 카드를 redirect**
  하는 용도 (server-side). §9.6 는 **클라이언트가 자기 카드로 PKINIT**
  하는 용도 (client-side). 두 코드 경로는 분리되며, 공통점은 미래에
  PC/SC native binding 을 공유할 수 있다는 정도임.
- 따라서 §9.6 의 실제 간극은: `PkinitConfig` 가 현재 raw DER cert + raw
  `RsaPrivateKey` 만 받음 → **카드/HSM 소스 추상화 trait + 어댑터**
  필요.

**범위 (재정의)**:

`SmartcardProvider` trait 으로 cert 추출/PIN/서명 작업을 추상화하고,
`PkinitConfig` 가 옵션으로 provider 를 받도록 확장. Phase 1 은
하드웨어 없이 완결, Phase 2 는 `pcsc` crate 어댑터를 작성하되 컴파일
+ 단위 테스트만 통과 (실 하드웨어 검증 TODO).

**Phase 1 — 추상화 + Mock + PKINIT 통합 (하드웨어 불필요)**

- [x] **Step 0** — 로드맵 정정 ✅
- [x] **Step 1** — `@spec-checker` mini: trait shape locked
      (`specs/pkinit-smartcard-notes.md`) ✅
- [x] **Step 2** — `crates/justrdp-pkinit-card/` 신규 크레이트
      (8 mock tests ✅)
  - [x] `SmartcardProvider` trait — `get_certificate`,
        `get_intermediate_chain`, `verify_pin`, `sign_digest`
        (reader enumeration은 concrete provider 생성자 책임)
  - [x] `SmartcardError` enum (PinIncorrect/Blocked/CardRemoved/...)
  - [x] `MockSmartcardProvider` — 임베디드 minimal X.509 + 512-bit
        RSA test key (외부 fixture 파일 없음, in-code 생성)
- [x] **Step 3** — `PkinitConfig` 확장 (5 connector tests ✅)
  - [x] `from_provider(provider, dh_bytes)` 빌더
  - [x] `build_as_req_pkinit` 가 provider 있으면 host SHA-256 +
        `provider.sign_digest()` + `[end_entity, ...intermediates]`
        chain 사용
  - [x] `smartcard_provider: None` 시 기존 raw key 경로 유지
        (backward compat)
  - [x] `justrdp-core::rsa::rsa_sign_sha256_digest` helper 추가
        (hash 단계 분리)
- [x] **Step 4** — Phase 1 검증 (commit `<next>`)
  - [x] Mock provider 기반 AS-REQ 생성 unit test —
        `pkinit_smartcard_as_req_structure_matches_rfc4556`
        (`credssp/kerberos.rs`). AS-REQ APPLICATION tag, PA-PK-AS-REQ
        type 16, PA-PAC-REQUEST type 128, CMS signed-data OID,
        id-pkinit-authData OID, dhpublicnumber OID, cname / realm /
        ctime 문자열을 전부 바이트 단위 검증
  - [x] `@impl-verifier` 로 RFC 4556 1:1 대조 — 4개 스펙 편차 발견,
        전부 수정:
        - **Finding A (fixed, `796967a`)**: `AuthPack.clientDHNonce`
          태그 `[2]` → `[3]` (RFC 4556 §3.2.1 의 `supportedCMSTypes`
          가 `[2]` 를 차지)
        - **Finding B (fixed, `<next>`)**: `PaPkAsReq::encode` 가
          `signedAuthPack` 을 EXPLICIT `[0]` OCTET STRING 으로
          인코딩하던 것 (`A0 <len> 04 <inner> <data>`) 을 IMPLICIT
          (`80 <len> <data>`) 로 수정 (ITU-T X.690 §8.14.3)
        - **Finding C (fixed, `<next>`)**: `cms::build_signer_info`
          에 `signedAttributes` 경로 추가. `build_signed_attrs_inner`
          /`_for_signing`/`_for_signer_info` 3-단 헬퍼로 RFC 5652
          §5.4 "separate encoding for signature computation" 규칙
          구현. `id-contentType` + `id-messageDigest` 두 attribute
          포함. `build_as_req_pkinit` 의 서명 파이프라인도 재구성 —
          이제 `auth_pack_der` 대신 `SET` 재태깅된 signedAttrs 를
          서명
        - **Finding D (fixed, `<next>`)**: `build_dh_spki` 의
          `DomainParameters` SEQUENCE 에 `q` 추가. `OakleyGroup14::order()`
          헬퍼 신설 (`justrdp-core::dh`) 로 `q = (p-1)/2` 계산

**Phase 2 — Native PC/SC backend (실 하드웨어 검증 TODO)**

- [x] **Step 5** — `pkinit-card` `pcsc` feature gate (29 tests ✅)
  - [x] `pcsc` crate optional 의존 (Windows WinSCard / Linux pcsc-lite
        / macOS CryptoTokenKit 자동 dispatch)
  - [x] `PcscSmartcardProvider` impl `SmartcardProvider` — `open()`
        은 PC/SC 컨텍스트 → 리더 enumerate → SELECT PIV AID → 인증서
        캐싱
  - [x] APDU 시퀀스: SELECT (00 A4 04 00 + AID) → VERIFY (00 20 00 80
        + 8-byte 0xFF padded PIN) → GENERAL AUTHENTICATE
        (00 87 07 9A + 7C-wrapped padded message, 확장 Lc/Le)
  - [x] 카드 프로파일: PIV (NIST SP 800-73-4) 전용, key 9A
        (Authentication), object 5F C1 05 (Auth cert)
  - [x] PKCS#1 v1.5 padding 호스트 측 (`pkcs1_v15_pad_sha256_digest`),
        카드는 raw RSA만 수행
  - [x] BER-TLV helper (push/parse, short/long form 4 sizes), PIV
        envelope (53/70/71/FE) parser, GENERAL AUTH 응답 (7C/82) parser
  - [x] PIV VERIFY SW classification (63 CX → tries 카운트, 69 83 →
        blocked)
  - [x] **명시적 UNTESTED 마킹**: 모듈 doc comment 최상단 + 각 live
        method doc — pure APDU helpers는 21 unit tests로 검증, 실
        `Context::establish` / `Card::transmit` 경로는 하드웨어 검증
        TODO

- [x] **Step 6** — 최종 검증 (3 agents 병렬)
  - [x] `@impl-verifier` — 42/44 PASS, 2 minor (PIV chaining 61 XX
        TODO + decode test gap)
  - [x] `@code-reviewer` — 9 issues, 핵심만 수정 (에러 정보 보존,
        magic numbers, 0x63C0 promotion, 데드코드 마킹)
  - [x] `@security-scanner` — 0 Critical, 4 Warning + 6 Info,
        실질 항목 전부 수정 (BER 파서 bounds, PIN APDU zeroize,
        Mock Drop, constant-time PIN 비교, 빈 cert 거부, 스테일
        보안 주석 정정, version 주석 정정)
  - [x] 워크스페이스 clean 빌드 + 전체 테스트 통과
        (rsa 9 / pkinit-card 30 / connector pkinit 6)

**Phase 3 — Smart card PAA cookie for RD Gateway (§10.1 follow-up)**

Uses the `SmartcardProvider` trait built in Phase 1 to construct
a PAA cookie for Windows RD Gateways configured with smart-card
authentication RAP (Resource Authorization Policy). MS-TSGU
§2.2.10.1 `CookieAuthData` accepts either an NTLM/CredSSP blob
(already implemented in §10.1 C11) or a smart-card-derived
credential blob verified against the user's X.509 cert.

- [ ] `PaaCookie::from_smartcard_provider(provider, gateway_spn)`
      constructor in `justrdp-gateway::rpch::paa`
- [ ] Wire format research: confirm whether the smart-card PAA
      cookie is (a) a CMS `SignedData` blob signed with the card's
      key, (b) a CredSSP `TSRequest` with a PKINIT-derived
      credential, or (c) a Kerberos AP-REQ wrapped as `auth_info`.
      MS-TSGU §2.2.10 does not specify — needs wire capture from
      a real smart-card PAA deployment or further spec-checker
      investigation.
- [ ] Unit test against mock `SmartcardProvider` (no hardware)
- [ ] Integration test deferred — requires a live Windows RD
      Gateway configured with smart-card RAP, plus a physical
      card or PC/SC virtual card adapter.

### 9.7 USB Redirection (MS-RDPEUSB)

> **requires**: 7.3 DVC 프레임워크 (RDPDR 불필요 — URBDRC DVC 직접 사용)
> **검증**: capability exchange + ADD_DEVICE + URB_COMPLETION roundtrip (mock)

**DVC 이름**: `URBDRC` (Control), per-device sub-channel name = interface ID

**구현 범위 결정 (하드웨어 없음, 전구현)**:
- 커넥션/열거 레이어는 완전 구현 + mock 테스트
- 실제 호스트 USB 스택 연동 제외 (`UrbHandler` trait만 노출 → 상위 레이어 선택)

**Steps**:
- [x] **Step 0**: 로드맵 정정 (이 블록)
- [x] **Step 1**: `@spec-checker MS-RDPEUSB` → `specs/ms-rdpeusb-checklist.md` (683 lines)
- [x] **Step 2**: `justrdp-rdpeusb` 크레이트 — PDU 레이어 (`pdu.rs` + `ts_urb.rs`)
  - [x] Shared header (30-bit InterfaceID + 2-bit Mask 패킹, 8B response / 12B request)
  - [x] RIM_EXCHANGE_CAPABILITY_REQUEST/RESPONSE
  - [x] CHANNEL_CREATED
  - [x] ADD_VIRTUAL_CHANNEL, ADD_DEVICE (+ USB_DEVICE_CAPABILITIES 28B)
  - [x] INTERNAL_IO_CONTROL, IO_CONTROL
  - [x] QUERY_DEVICE_TEXT / QUERY_DEVICE_TEXT_RSP
  - [x] REGISTER_REQUEST_CALLBACK
  - [x] TRANSFER_IN_REQUEST / TRANSFER_OUT_REQUEST
  - [x] URB_COMPLETION / URB_COMPLETION_NO_DATA / IOCONTROL_COMPLETION
  - [x] CANCEL_REQUEST
  - [x] RETRACT_DEVICE
  - [x] TS_URB 15 variants (SelectConfiguration, SelectInterface, PipeRequest, BulkOrInterrupt, IsochTransfer, ControlTransfer/Ex, Feature/Descriptor/Status/Vendor/GetConfig/GetInterface/OsFeatureDescriptor)
  - [x] DoS 캡 (transferBufferLength=16MiB, IoCtl=64KiB, isoch packets=1024, pipes=64, 문자열 캡 등)
- [x] **Step 3**: DVC client state machine (`UrbdrcClient`) + `UrbHandler` trait
  - [x] Control channel: WaitCapabilityRequest → WaitServerChannelCreated → Ready
  - [x] 디바이스 dispatch + `UsbDevice → RequestCompletion` 매핑
  - [x] `UrbHandler` trait (호스트 USB 스택 추상화) + `MockUrbHandler`
  - [x] Out-of-sequence / replay 방어 (state guard, dispatch guard)
- [x] **Step 4**: `@impl-verifier` — 141 PASS / 2 FAIL → fixed
  - [x] IOCONTROL_COMPLETION ERROR_INSUFFICIENT_BUFFER 경로 (§2.2.7.1 OutputBufferSize == request.OutputBufferSize)
  - [x] `handle_query_device_text` 파라미터 이름 수정 (`request_id` → `message_id`)
- [x] **Step 5**: code-reviewer + security-scanner
  - [x] HIGH-1 (sec): `TsUsbdInterfaceInformation::decode` checked_mul + try_from
  - [x] HIGH-2 (sec): local cap guard before `vec![0; output_max]`
  - [x] MEDIUM-2 (sec): dispatch guard for device msgs pre-Ready
  - [x] MEDIUM-3 (sec): Utf16String/Multisz wire_cch/bytes saturating
  - [x] handle_capability / handle_channel_created replay 방어 state guard
  - [x] `urb_result.len() as u16` 오버플로 체크 (2 곳)
  - [x] Dead code 정리 (`saw_nul`, `let _ = (header, expected_fid)`, `let _ = information`)
  - [x] `#[must_use]` 추가
- [x] **Step 6+7**: replay/pre-Ready 테스트 3개 추가 + 커밋
  - [x] 42 tests (41 unit + 1 integration) / 0 failures
  - [x] 워크스페이스 clean build

### 9.8 Video Optimized Remoting (MS-RDPEVOR) ✅

> **requires**: 7.3 DVC ✅, 8.8 H.264 ✅ (trait), 9.11 MS-RDPEGT ✅
> **검증**: Control/Data 2채널 핸드셰이크 + H.264 frame delivery integration test (mock decoder)
> **크레이트**: `justrdp-rdpevor` ✅ (47 tests: 46 unit + 1 integration)

**DVC 이름**:
- `Microsoft::Windows::RDS::Video::Control::v08.01`
- `Microsoft::Windows::RDS::Video::Data::v08.01`

- [x] Step 0: Spec analysis → `specs/ms-rdpevor-checklist.md`
- [x] Step 1: Crate skeleton (`justrdp-rdpevor`, no_std, forbid unsafe)
- [x] Step 2: TSMM PDUs — Header, PresentationRequest (Start/Stop), PresentationResponse, ClientNotification (NetworkError + FrameRateOverride), VideoData, MFVideoFormat_H264 GUID wire bytes
- [x] Step 3: `VideoDecoder` trait + `MockVideoDecoder`
- [x] Step 4: `RdpevorControlClient` (duplicate Start ignored, unknown subtype ignored, Stop shuts down decoder, optional `GeometryLookup`) + `RdpevorDataClient` (BTreeMap reassembly, OOO fragments, duplicate-fragment rejection, register/unregister_presentation for spec §3.2.5.1 discard rule)
- [x] Step 5: Geometry integration via `GeometryLookup` from `justrdp-rdpegt`
- [x] Step 6: Integration test (tests/flow.rs) — Start → OOO 2-fragment VIDEO_DATA → Stop with shared DecoderHandle
- [x] Step 7: impl-verifier + code-reviewer + security-scanner; applied fixes: checked `try_from` on length casts, exact-match FrameRateOverride flags, duplicate fragment rejection, hard channel_id check, single shutdown() on close, inactive-presentation silent drop

### 9.9 Camera Redirection (MS-RDPECAM)

> **requires**: 7.3 DVC 프레임워크
> **검증**: 카메라 디바이스 열거 integration test
> **크레이트**: `justrdp-rdpecam`

**DVC 이름**: `RDCamera_Device_Enumerator` (고정) + per-device 동적 채널

- [x] Step 0: Spec Analysis → `specs/ms-rdpecam-checklist.md`
- [x] Step 1: Crate Skeleton (no_std, forbid unsafe, module stubs: constants/pdu/{header,enumeration,device,stream,capture,property}/camera/enumerator/device)
- [x] Step 2: PDUs — `SharedMsgHeader` helpers + 24 messages (Success/Error response, SelectVersion req/resp, Device Added/Removed, Activate/Deactivate, StreamList req/resp, MediaTypeList req/resp, CurrentMediaType req/resp, StartStreams, StopStreams, Sample req/resp, SampleError, PropertyList req/resp, PropertyValue req/resp, SetPropertyValue), `ErrorCode`/`MediaFormat`/`PropertySet`/`PropertyMode` forward-compat enums, spec §4.x test vectors (§4.1.1/§4.1.2 SelectVersion, §4.2.1 Mock Camera, §4.4.4 StreamList, §4.4.6 MediaTypeList, §4.5.1 StartStreams, §4.6.2 PropertyList, §4.6.4 PropertyValue), 75 roundtrip + 경계값 + cap 테스트 (spec §4.21 PROPERTY_DESCRIPTION 크기 체크리스트 오타 수정: 18→19바이트)
- [x] Step 3: `CameraDevice` host trait (+`CamError` → `ErrorCode` 매핑, `MockCameraDevice` test double), `RdpecamEnumeratorClient` (builder w/ `max_version`, strict state machine `Uninitialised→AwaitingVersion→Ready→Closed`, `announce_device`/`remove_device` API, host-orchestrated per-device 등록 모델), `RdpecamDeviceClient` (strict 3-state FSM `Initialised→Activated{streaming}`, 11개 메시지 dispatch, v2-only 게이팅, `SampleRequest`→`SampleErrorResponse` 에러 경로, graceful deactivate-during-streaming)
- [x] Step 4: Integration test (tests/flow.rs) — enumerator↔device 프로세서 side-by-side end-to-end: v2 negotiation → announce → activate → stream list → media type list → current → start → sample (queue drain + empty→SampleErrorResponse) → property list/get/set/get → stop → deactivate → close → remove → close. Plus announce/remove idempotency, v1 negotiation gating property API, host-level ItemNotFound propagation (4 tests)
- [x] Step 5: impl-verifier (83/86 PASS) + code-reviewer + security-scanner; applied fixes: trailing-bytes → `ErrorResponse(InvalidMessage)` instead of channel tear-down, `start()` re-create calls `stop_streams()` before `deactivate()` for contract-compliant host teardown, `pixel_aspect_ratio_denominator == 0` rejected symmetrically with `frame_rate_denominator`, no-op `DvcError::Encode` identity re-wrap dropped, `encode_to_vec` upgraded from `debug_assert` to `assert` for release-build coverage, `SampleRequest` early-exit `SampleErrorResponse(OutOfMemory)` for oversize host returns, UTF-16 cap exact-boundary + odd-byte orphan tests, `start()` re-create teardown-order regression test, C→S rejection broadened to 0x01/0x02/0x12/0x13

### 9.10 Video Redirection (MS-RDPEV) ✅

> **requires**: 7.3 DVC ✅
> **검증**: PDU roundtrip + 통합 테스트 + 2-pass 검증
> **크레이트**: `justrdp-rdpev` ✅

**DVC 이름**: `TSMF` (TS Multimedia Framework)

- [x] Step 0: Spec Analysis → `specs/ms-rdpev-checklist.md`
- [x] Step 1: Crate Skeleton (no_std, forbid unsafe)
- [x] Step 2A-2H: PDU 레이어 — 24 wire types, 9 modules, 112 unit tests
  - 2A: SHARED_MSG_HEADER (12B 요청 / 8B 응답, InterfaceId+Mask+MessageId+FunctionId)
  - 2B: TSMM_CAPABILITIES + ExchangeCapabilities Req/Rsp
  - 2C: Presentation lifecycle (SetChannelParams, OnNewPresentation, SetTopology Req/Rsp, ShutdownPresentation Req/Rsp) + Guid
  - 2D: TS_AM_MEDIA_TYPE + CheckFormatSupport Req/Rsp (numMediaType invariant)
  - 2E: AddStream + RemoveStream
  - 2F: TS_MM_DATA_SAMPLE + OnSample + PlaybackAck (Client Notifications interface)
  - 2G: NotifyPreroll + OnFlush + OnEndOfStream + OnPlayback{Started,Paused,Stopped,Restarted,RateChanged}
  - 2H: SetVideoWindow + UpdateGeometryInfo + SetSourceVideoRect + OnStreamVolume + OnChannelVolume + SetAllocator + ClientEventNotification
- [x] Step 3: `RdpevClient` DvcProcessor + `TsmfMediaSink` host trait + presentation/stream FSM + 22 PDU 핸들러 + ON_SAMPLE→PlaybackAck 1:1 핫패스
- [x] Step 4: 통합 테스트 (`tests/flow.rs`) — 8 시나리오 (full lifecycle, multi-presentation, pipelined CHECK_FORMAT, etc.)
- [x] Step 5: 2-pass 검증 (impl-verifier + code-reviewer + security-scanner)
  - 1차: P0 (ON_SAMPLE Ready guard) + 4 P1 (HRESULT pairing, stream_id, NotifyPreroll routing, f32 validation) + 3 P2 fix
  - 2차: W1 (Ready→Setup demotion 방지) + W2 (OnPlaybackRateChanged NaN/Inf reject) + 테스트 cleanup
  - 최종: 169 tests passing (161 unit + 8 integration), 0 P0/P1 outstanding

### 9.11 Geometry Tracking (MS-RDPEGT) ✅

> **requires**: 7.3 DVC ✅
> **검증**: PDU roundtrip + RDPEVOR 연동용 host trait
> **크레이트**: `justrdp-rdpegt` ✅
> **참고**: 스펙은 MS-RDPEGT (Geometry Tracking), RDPGFX와 별개

**DVC 이름**: `Microsoft::Windows::RDS::Geometry::v08.01`

- [x] Step 0: Spec Analysis → `specs/ms-rdpegt-checklist.md`
- [x] Step 1: Crate Skeleton (no_std, forbid unsafe)
- [x] Step 2: PDUs — `MappedGeometryPacket` (Update/Clear), `IRect`, `RGNDATAHEADER`, `cbGeometryData == 72 + cbGeometryBuffer` (no trailing Reserved byte), §4.1 120B vector roundtrip
- [x] Step 3: `RdpegtClient` DVC processor, `GeometryEntry` map, `GeometryLookup` trait for RDPEVOR
- [x] Step 4: impl-verifier 0 FAIL (after fixes), code-reviewer + security-scanner clean (23/23 tests, DoS caps, MAX_ACTIVE_MAPPINGS boundary test, trailing-byte rejection, pre-start guard)

### 9.12 Desktop Composition (MS-RDPEDC) ✅

> **requires**: CAPSETTYPE_COMPDESK (`justrdp-pdu` 기존 구현), MS-RDPEGDI Alternate Secondary Order transport
> **검증**: PDU roundtrip + 스펙 §4 hex test vectors
> **Note**: Roadmap alias "MS-RDPECR2" was a typo; the actual spec is [MS-RDPEDC]
>   Desktop Composition Virtual Channel Extension v8.0. MS-RDPCR2 (Composited
>   Remoting V2, 136-message DWM scene-graph protocol) is tracked separately below.

- Step 0: spec-checker → `specs/ms-rdpedc-checklist.md` (7 PDUs, trivial sizing)
- Step 1: crate + constants + 7 PDU Encode/Decode + 25 unit tests (spec §4.2.1, §4.3.2 hex vectors pass)
- Step 2: `RdpedcClient` processor + FSM + surface tables + `CompDeskCallback` + 22 tests
- Step 3: impl-verifier → 2 HIGH + 1 MEDIUM + 3 LOW fixed (duplicate CompositionOn, unknown-op skip, COMPDESK_SUPPORTED const, regression tests)
- [x] 7개 PDU 전부 구현 (TOGGLE / LSURFACE / SURFOBJ / REDIRSURF_ASSOC / COMPREF_PENDING / SWITCH_SURFOBJ / FLUSH_COMPOSEONCE)
- [x] `TS_ALTSEC_COMPDESK_FIRST = 0x0C` Alternate Secondary Order header (0x32 byte)
- [x] Composition mode FSM (COMPOSITION_OFF ↔ COMPOSITION_ON, DWM desk enter/leave sub-modes)
- [x] 논리 서피스 테이블 + 리다이렉션 서피스 테이블 (BTreeMap, no_std)
- [x] CAPSETTYPE_COMPDESK capability set과 연동 (`justrdp-pdu/src/rdp/capabilities.rs` + `COMPDESK_SUPPORTED/NOT_SUPPORTED` const)
- [x] 스펙 §4.2.1, §4.3.2 hex test vectors 정확 매칭
- [x] Forward-compat: unknown operation byte skip via `size` field
- [x] DoS caps: MAX_LOGICAL_SURFACES=4096, MAX_REDIR_SURFACES=4096
- [x] 50/50 tests passing

### 9.13 Multiparty Virtual Channel (MS-RDPEMC) ✅

> **requires**: `justrdp-svc` (static SVC "encomsp"), 7.1 세션
> **검증**: 50/50 tests (25 PDU + 25 FSM), impl-verifier 14/14 PASS
> **참고**: MS-RDPEMC는 DRDYNVC가 아닌 static virtual channel "encomsp"를
> 사용합니다 (MS-RDPBCGR §3.1.5.2).

**Step 9.13a — PDU 레이어 (`justrdp-rdpemc` crate):** ✅

- [x] 13개 PDU struct Encode/Decode (MS-RDPEMC §2.2)
- [x] ORDER_HDR + UNICODE_STRING 공통 타입 (cchString ≤ 1024)
- [x] `decode_all()` 연속 PDU 루프 파서 + 미지 타입 forward-compat skip
- [x] 11개 파생 테스트 벡터 + per-PDU 라운드트립

**Step 9.13b — FSM + SvcProcessor:** ✅

- [x] 다자 RDP 세션 (여러 클라이언트가 하나의 세션 공유)
- [x] Shadow 세션 (관리자가 사용자 세션 모니터링/제어)
- [x] View-only / Interactive 모드 (MAY_VIEW/MAY_INTERACT 플래그)
- [x] 제어 권한 요청/승인 시퀀스 (`build_control_request` + response)
- [x] `EncomspClient<C>` `SvcProcessor` 구현 + `EncomspCallback` trait
- [x] app/window/participant 상태 테이블 + DoS caps (512/1024/512)
- [x] app 삭제 cascade → window, filter state change 전체 플러시

### 9.14 Plug and Play Device Redirection (MS-RDPEPNP)

> **requires**: 7.3 DVC 프레임워크 ✅
> **검증**: PDU roundtrip + FSM + 멀티 에이전트 검증
> **참고**: MS-RDPEPNP는 두 개의 독립 DVC 서브프로토콜로 구성:
> `"PNPDR"` (제어/상태) + `"FileRedirectorChannel"` (per-file I/O).
> 9.14a = PNPDR만, 9.14b = FileRedirectorChannel.

**9.14a — PNPDR 제어 채널 ✅ (crate: justrdp-rdpepnp)**
- [x] `PNP_INFO_HEADER` (8B, Size/PacketId u32 LE, Size inclusive)
- [x] Server/Client Version Message (shared `VersionMsg`, PacketId=0x65, 20B)
- [x] Authenticated Client Message (PacketId=0x67, 8B header only)
- [x] Client Device Addition Message (PacketId=0x66) + `PNP_DEVICE_DESCRIPTION`
      (optional ContainerId/DeviceCaps 조합 4가지 모두 지원)
- [x] Client Device Removal Message (PacketId=0x68, spec §4 wire trace #2 일치)
- [x] `PnpInfoClient` DvcProcessor + 3-state FSM (WaitServerVersion → WaitAuthenticated → Active)
- [x] 디바이스 테이블 + DoS caps (MAX_DEVICES=256, HW/Compat=1024B, Desc=512B, Iface=256B)
- [x] 인바운드 디코드 경로에도 per-field cap 강제 (allocation DoS 방어)
- [x] Balanced-callback invariant (replace-in-place 예외 제외)
- [x] Unknown PacketId forward-compat (silent drop)

**9.14b — FileRedirectorChannel I/O 서브프로토콜 ✅ (crate: justrdp-rdpepnp)**
- [x] `SERVER_IO_HEADER` (8B, u24 RequestId) / `CLIENT_IO_HEADER` (4B)
- [x] ServerCapabilitiesRequest / ClientCapabilitiesReply (§2.2.2.2)
- [x] CreateFile / Read / Write / IoControl Request+Reply (§2.2.2.3.1–8)
- [x] SpecificIoCancelRequest (§2.2.2.3.9, no reply)
- [x] ClientDeviceCustomEvent (§2.2.2.3.10, gated on negotiated v0x0006)
- [x] Per-channel FSM (WaitCapabilities → WaitCreateFile → Active → Closed)
      with outstanding request table (MAX=256, duplicate-id → close)
- [x] Multi-instance DvcProcessor keyed by channel_id
- [x] Per-field DoS caps (64 KiB) mirroring PNPDR convention
- [x] IoCallback trait for host-side I/O service + reply truncation to cb_out

## 10. Phase 7 -- Transport Extensions

> **목표**: WAN 환경에서의 성능 최적화, 방화벽/프록시 통과.
> Phase 4 세션과 병렬 진행 가능 (독립 네트워크 레이어).

### 10.1 RD Gateway (MS-TSGU)

> **requires**: Phase 2 (NTLM/Kerberos 인증), justrdp-tls
> **검증**: 게이트웨이 경유 실서버 연결 integration test
> **참고**: 세션 내용과 무관한 터널 레이어이므로 Phase 4/5와 병렬 진행 가능

**HTTP Transport (신규, 권장):**

- [x] Handshake Request/Response
- [x] Tunnel Create/Response
- [x] Tunnel Auth/Response
- [x] Channel Create/Response
- [x] Data PDU 전송/수신
- [x] Keepalive
- [x] Close Channel
- [x] HTTP/1.1 RDG_IN_DATA/RDG_OUT_DATA 프레이밍 + chunked + 100-byte preamble
- [x] NTLMv2 HTTP 401 재시도 루프 (justrdp-gateway::auth)
- [x] `GatewayConnection<R, W>` std Read/Write adapter
- [x] Mock gateway end-to-end integration test (401 retry + handshake + data)
- [x] `justrdp-blocking::connect_via_gateway_with_upgrader` — 실소켓/TLS를 붙인 high-level API

**RPC-over-HTTP (레거시):** ✅ 전체 구현 완료 (C1-C6)

> **적용 범위**: Windows Server 2008 R2 / 2012 게이트웨이 (HTTP/WebSocket Transport 미지원 환경)
> **의존성 스택**: NDR20 → DCE/RPC → RPC-over-HTTP v2 → TsProxy IDL → PAA → blocking wire-up
> **신규 crate**: `justrdp-rpch` (NDR + DCE/RPC + RPC-over-HTTP v2, 재사용 가능한 범용 레이어)
> **gateway 확장**: `justrdp-gateway::rpch` 모듈 (TsProxy-specific)

*1. NDR 2.0 Marshaling (C706 Ch.14, MS-RPCE §2.2.5)* — `justrdp-rpch::ndr`

- [x] Data Representation format label (integer=little-endian, char=ASCII, float=IEEE)
- [x] Primitive types (`u8/u16/u32/i32/u64` + enum16) with alignment rules (i8/i16/f32/f64/bool not required by TsProxy — descoped)
- [x] Top-level pointer policy: embedded-reference vs full pointer semantics
- [x] Pointer kinds: `unique` (nullable) + `ref` (non-null). `ptr` (full/aliasing) intentionally descoped — TsProxy never uses full pointers.
- [x] Conformant array (max_count prefix + elements)
- [x] Varying array (offset + actual_count + elements)
- [x] Conformant+Varying array (max_count + offset + actual_count)
- [x] Conformant string (`wchar_t*`, NUL-terminated, UTF-16LE) + ASCII variant
- [x] Structure (alignment relative to absolute stream offset)
- [x] Union (encapsulated — discriminant + arm, via `TsgPacket` enum)
- [ ] Pipe primitive (partial stream, fragmented) — intentionally descoped (not needed by TsProxy)
- [x] NDR marshaller/unmarshaller (`NdrEncoder` / `NdrDecoder`)
- [x] 테스트: 30 unit tests covering UUID bytes, alignment boundaries, pointer semantics, string roundtrip / boundary rejection, primitives from odd offsets

*2. DCE/RPC PDU Codec (MS-RPCE §2.2.2)* — `justrdp-rpch::pdu`

- [x] 공통 헤더 (`rpc_vers=5`, `rpc_vers_minor=0`, `PTYPE`, `pfc_flags`, `drep`, `frag_length`, `auth_length`, `call_id`)
- [x] `BIND` (0x0B) — context element 리스트, 추상/전송 구문 UUID+버전, security trailer
- [x] `BIND_ACK` (0x0C) — 서버 assoc group ID, 결과 리스트, 보조 주소
- [x] `BIND_NAK` (0x0D) — 거절 이유
- [x] `ALTER_CONTEXT` (0x0E) / `ALTER_CONTEXT_RESP` (0x0F) — shared wire layout with BIND/BIND_ACK
- [x] `AUTH3` (0x10) — NTLM 3-step 완료
- [x] `REQUEST` (0x00) — opnum + stub data (+ object UUID if flag)
- [x] `RESPONSE` (0x02) — stub data + alloc hint
- [x] `FAULT` (0x03) — status code (nca_s_*)
- [x] `SHUTDOWN` (0x11), `CO_CANCEL` (0x12), `ORPHANED` (0x13) — PTYPE constants defined (bodies are empty)
- [x] `RTS` (0x14) — RPC-over-HTTP 플로우 제어 (MS-RPCH §2.2.3.5)
  - [x] RTS 커맨드: `ReceiveWindowSize`, `FlowControlAck`, `ConnectionTimeout`, `Cookie`, `ChannelLifetime`, `ClientKeepalive`, `Version`, `Empty`, `Padding`, `NegativeANCE`, `ANCE`, `ClientAddress`, `AssociationGroupId`, `Destination`, `PingTrafficSentNotify` (15/15)
  - [x] RTS 플로우: `conn_a1` / `conn_b1` / `recycle_conn_b3` 빌더 (CONN/A2/B2/C1은 서버사이드 — 구현 불필요). B3 흡수는 핸드셰이크 상태머신에서 처리.
- [x] Security trailer (auth_type, auth_level, auth_pad_length, auth_context_id, auth_value)
- [x] Fragmented request/response 재조립 (`PFC_FIRST_FRAG`/`PFC_LAST_FRAG`) — `ReassemblyBuffer` (§10.1 C7)
- [x] 테스트: ~100 unit tests covering 각 PDU roundtrip, 필드 경계, FlowControlAck 정확한 바이트 매치, fragment 재조립 경계 케이스

*3. RPC-over-HTTP v2 Tunnel (MS-RPCH §3.2)* — `justrdp-rpch::{http, tunnel, blocking}`

- [x] HTTP 메서드 `RPC_IN_DATA` / `RPC_OUT_DATA` (커스텀 verb)
- [x] IN 채널 HTTP 요청: `Content-Length: 1073741824` (가짜 large body)
- [x] OUT 채널 HTTP 요청: `Content-Length: 76` (CONN/A1 RTS 길이)
- [x] 채널별 NTLM 401 재시도 루프 (`justrdp-blocking::gateway::authenticate_rpch_channel`)
- [x] Virtual connection cookie (GUID), IN/OUT channel cookies (GUID), association group ID (GUID) — 모두 `make_rpch_tunnel_config`에서 UUIDv4로 생성
- [x] **OUT 채널 핸드셰이크**: 클라 CONN/A1 → 서버 CONN/A3
- [x] **IN 채널 핸드셰이크**: 클라 CONN/B1 (B3는 서버사이드 흡수)
- [x] **Proxy 핸드셰이크**: 서버 CONN/C2 수신
- [x] Flow control: `FlowControlAck` RTS 송수신 (50% 창 소진 시 auto emit)
- [x] KeepAlive Ping 타이머 — `spawn_keepalive_thread` (§10.1 C9). `justrdp-blocking::establish_gateway_tunnel_rpch`에서 자동으로 띄움. Drop 시 클린업.
- [x] IN channel recycling 프리미티브 — `set_recycle_threshold` + `needs_recycle` + `recycle_in_channel` (§10.1 C10). 자동 dial-new-IN 와이어업은 `TlsUpgrader: Clone` 리팩터 필요.
- [x] `RpchTunnel<I: Read+Write, O: Read+Write>` struct — IN/OUT 듀얼 소켓 래퍼
- [x] std Read/Write adapter: `RpchGatewayChannel` (IN 채널로 SendToServer, OUT 채널에서 SetupReceivePipe 스트림)

*4. TsProxy IDL (MS-TSGU §3.1.4)* — `justrdp-gateway::rpch`

- [x] 인터페이스 UUID: `44e265dd-7daf-42cd-8560-3cdb6e7a2729`, version 1.3
- [x] 전송 구문: NDR 2.0 `8a885d04-1ceb-11c9-9fe8-08002b104860` v2.0
- [x] 구조체 NDR 마셜러:
  - [x] `TSG_PACKET_HEADER` (ComponentId + PacketId)
  - [x] `TSG_PACKET` (union: VersionCaps / QuarRequest / Response / QuarEncResponse / CapsResponse / Auth / MsgRequest / MessagePacket / Reauth — 9/9 arms)
  - [x] `TSG_PACKET_VERSION_CAPS`
  - [x] `TSG_PACKET_CAPABILITIES_RESPONSE`
  - [x] `TSG_CAPABILITIES_1` (NAP 계열 5개 bit flag)
  - [x] `TSG_PACKET_AUTH` (VersionCaps + PAA cookie)
  - [x] `TSG_PACKET_MSG_REQUEST/RESPONSE` — 3-arm async union (Consent / Service / Reauth) §10.1 C8
  - [x] `TSG_PACKET_REAUTH` — 64-bit tunnel context + nested VersionCaps/Auth union §10.1 C8
  - [x] `TSG_PACKET_QUARANTINE_ENC_RESPONSE`
  - [x] `TSENDPOINTINFO` (resource name array + alternate names + port+protocol bit-packed)
- [x] 메서드 (opnums는 MS-TSGU Appendix A 기준, 0/5는 NotUsedOnWire):
  - [x] `TsProxyCreateTunnel` (opnum 1)
  - [x] `TsProxyAuthorizeTunnel` (opnum 2)
  - [x] `TsProxyMakeTunnelCall` (opnum 3) — long-poll async message + `TSG_TUNNEL_CALL_ASYNC_MSG_REQUEST`/`CANCEL` procIds §10.1 C8
  - [x] `TsProxyCreateChannel` (opnum 4)
  - [x] `TsProxyCloseChannel` (opnum 6)
  - [x] `TsProxyCloseTunnel` (opnum 7)
  - [x] `TsProxySetupReceivePipe` (opnum 8) — NDR 우회 20-byte context handle
  - [x] `TsProxySendToServer` (opnum 9) — NDR 우회 Generic Send Data Message Packet (big-endian length 필드)
- [x] `TsProxyClient` — state machine (Start→Connected→Authorized→ChannelCreated→PipeCreated→Closing→End) + `build_make_tunnel_call_async_msg_request`
- [x] 에러 처리: `E_PROXY_*` HRESULT + `HRESULT_CODE` DWORD 경로 + Win32 codes + `name_of()` 헬퍼

*5. PAA Cookie 인증 (MS-TSGU §2.2.10)* — `justrdp-gateway::rpch::paa`

- [x] `CookieAuthData` 구조체 (`PaaCookie` — opaque bytes wrapper)
- [x] CredSSP-formatted PAA cookie 생성 — `PaaCookie::from_ntlm_authenticate_as_credssp(bytes)` wraps NTLM AUTHENTICATE in a TSRequest DER per MS-CSSP §2.2.1. 인라인 minimal encoder가 `justrdp-connector::credssp::TsRequest::encode()`와 바이트 일치 (§10.1 C11).
- [x] `from_ntlm_authenticate(bytes)` — 2008 R2 RAP-NTLM 경로용 bare pass-through
- [x] `from_credssp_ts_request(der)` — 호출자가 풀 CredSSP 드라이브한 결과 주입용 pass-through
- [x] `TsProxyCreateTunnel`에서 cookie 전달 (TSG_PACKET_AUTH arm). 참고: 원래 roadmap에 "AuthorizeTunnel"이라 적혀있었지만 실제 스펙은 CreateTunnel에 PAA cookie가 들어감.
- Smart card-based PAA cookie는 §9.6 Phase 3에서 다룸 (PKINIT/SmartcardProvider 인프라 위에 얹음)

*6. blocking Wire-up* — `justrdp-blocking::gateway`

- [x] `RpchGatewayConfig` (gateway addr + creds + target host/port + connection timeouts + optional PAA)
- [x] `connect_via_gateway_rpch_with_upgrader<U: TlsUpgrader>()`
  - [x] IN/OUT TCP 2개 소켓 오픈 + TLS 업그레이드 각각
  - [x] 채널별 NTLM 401 재시도
  - [x] CONN/A/B/C 핸드셰이크 완료 대기 (`RpchTunnel::connect`)
  - [x] DCE/RPC Bind (TsProxy interface, anonymous). RPC-level NTLM SSPI는 현재 미구현 — 터널 레벨 인증은 PAA cookie가 담당.
  - [x] `TsProxyCreateTunnel` → `TsProxyAuthorizeTunnel` → `TsProxyCreateChannel` (MakeTunnelCall 스킵)
  - [x] `TsProxySetupReceivePipe` + `TsProxySendToServer`를 std Read/Write로 래핑 (`RpchGatewayChannel`)
  - [x] `Transport::Boxed`로 RDP 핸드셰이크 단계에 주입 (기존 `run_handshake_over_tunnel` 재사용)

*7. 통합 테스트*

- [x] Mock RPC-over-HTTP 게이트웨이 (IN/OUT 듀얼 소켓 에뮬레이션) — `tests/mock_rpch_gateway.rs`
- [x] CONN/A/B/C 핸드셰이크 roundtrip
- [x] Bind + TsProxyCreateTunnel + AuthorizeTunnel + CreateChannel 풀 플로우
- [x] SendToServer/SetupReceivePipe 데이터 에코 테스트 (클라 write "HELLO" → 서버 수신, 서버 push "SERVER01" → 클라 read)
- [ ] 채널 리사이클 테스트 (ChannelLifetime 만료) — 채널 리사이클 자체가 미구현이므로 테스트도 skip
- [ ] 실서버 integration test (Windows Server 2008 R2 게이트웨이) — 테스트 환경 준비되면 수행

**WebSocket Transport:**

- [x] WebSocket 업그레이드 (RFC 6455 §4.1 + Sec-WebSocket-Accept 검증)
- [x] 바이너리 프레임 전송 (masking, 7/16/64 length variants, 비최소 인코딩 거부)
- [x] Ping/Pong 자동 응답, Close 핸드쉐이크, 단편화/재조립
- [x] `WsGatewayConnection<S>` std Read/Write adapter
- [x] 게이트웨이 인증 (justrdp-gateway::auth NTLM 재사용 — `SSPI_NTLM` scheme)
- [x] `justrdp-blocking::connect_via_gateway_ws_with_upgrader` — 실소켓/TLS + 401 retry + 101 Accept 검증

**공통:**

- [ ] NTLM/Kerberos 게이트웨이 인증
- [ ] 리소스 인가 정책
- [ ] UDP side channel
- [ ] 다중 게이트웨이 장애 조치

### 10.2 UDP Transport (MS-RDPEUDP)

> **requires**: Phase 2 (Connected), justrdp-tls (DTLS)
> **검증**: UDP 핸드셰이크 integration test

**PDU layer (v1 — `justrdp-rdpeudp` crate):**

- [x] `RdpUdpFecHeader` (§2.2.2.1) + 모든 `RDPUDP_FLAG_*` 상수
- [x] `SynDataPayload` (§2.2.2.5) + MTU [1132, 1232] 범위 검증
- [x] `AckVectorHeader` (§2.2.2.7) + DWORD 정렬 패딩 + `AckVectorElement` 2-bit state / 6-bit run length 인코딩
- [x] `AckOfAcksHeader` (§2.2.2.6)
- [x] `SourcePayloadHeader` (§2.2.2.4)
- [x] `FecPayloadHeader` (§2.2.2.2)
- [x] `CorrelationIdPayload` (§2.2.2.8) + byte-value 제약 (no 0x00/0xF4 first, no 0x0D)
- [x] `SynDataExPayload` (§2.2.2.9) + version 1/2/3 + 선택적 `cookieHash`
- [x] `PayloadPrefix` (§2.2.2.3)
- [x] SYN 제로 패딩 헬퍼 (§3.1.5.1.1 step 6)
- [x] 스펙 §2.2 FEC Packet 예제 디코드 테스트

**PDU layer (v2 — MS-RDPEUDP2 §2.2, version 3 이상 활성화):**

- [x] `RdpEudp2Header` — 12-bit flags + 4-bit LogWindowSize 패킹, 상호 배타 flag 검증 (ACK ⊥ ACKVEC, at least one flag)
- [x] `AckPayload` (§2.2.1.2.1) — 24-bit receivedTS + packed numDelayedAcks/delayAckTimeScale + delayAckTimeAdditions
- [x] `OverheadSizePayload` (§2.2.1.2.2)
- [x] `DelayAckInfoPayload` (§2.2.1.2.3)
- [x] `AckOfAcksPayload` (§2.2.1.2.4)
- [x] `DataHeaderPayload` (§2.2.1.2.5)
- [x] `DataBodyPayload` (§2.2.1.2.7) — implicit length consuming UDP datagram tail
- [x] `AckVecPayload` (§2.2.1.2.6) — 선택적 24-bit timestamp + `CodedAckVecElement` (State Map + Run-Length 인코딩 모드)
- [x] `RdpEudp2Packet` top-level composite — canonical 페이로드 순서 (§2.2.1) 강제

**State machine / transport:**

- [x] Sans-io `RdpeudpSession` 3-way 핸드셰이크 (SYN → SYN+ACK → ACK), MTU/version/lossy 협상, client+server
- [x] `RdpeudpSession` 데이터 경로 — 시퀀스 넘버 추적, Source Packet 빌드, ACK vector 수집/RLE 생성, AckOfAcks 처리, wrapping SN 비교
- [x] `RdpeudpSocket` — std UdpSocket 바인딩, SYN 재전송 (exp backoff), blocking send_data/recv_data, loopback echo 테스트
- [x] Reliable 모드:
  - [x] 시퀀스 번호 관리 (wrapping u32, 중복 감지, 순서 비교)
  - [x] 재전송 타이머 (RTO) — RFC 6298 SRTT/RTTVAR + 지수 백오프 + 200ms/60s floor/cap
  - [x] 혼잡 제어 (congestion window) — slow-start / congestion avoidance / loss halving (Reno)
  - [x] FEC (Forward Error Correction) — XOR encode/decode, 단일 손실 복구, 가변 길이 지원
  - [x] 순서 보장 — reorder buffer, out-of-order → in-order flush
  - [x] TLS over UDP (DTLS) — DTLS 1.0/1.2 레코드 레이어, TLS 1.2 PRF, AES-128-CBC-SHA256 record protection (encrypt/decrypt/MAC), key derivation (master_secret + key_block), verify_data 생성
  - [x] DTLS 핸드셰이크 상태 머신 — ClientHello (cookie 재전송), HelloVerifyRequest, ServerHello (cipher 검증), Certificate (DER→SPKI→RSA PubKey 추출), ClientKeyExchange (PKCS#1v1.5 RSA), ChangeCipherSpec + epoch 전환, Finished (verify_data 생성/검증)
- [x] Lossy 모드:
  - [x] FEC only (재전송 없음) — FEC recovery 동작 확인
  - [x] DTLS record protection — Reliable 모드와 동일한 dtls.rs 모듈 공유
- [x] ACK/NACK 처리 — ACK vector gap 감지, acknowledge_up_to 송신 버퍼 정리, detect_loss_from_ack_vector
- [x] MTU 협상 — 4-value min, 경계값 (1132/1232) 테스트
- [x] 프로토콜 버전 1/2/3 지원 — SYNEX 협상, v3 cookieHash, min 선택, 미사용 시 None

### 10.3 Multitransport (MS-RDPEMT)

> **requires**: 10.2 UDP Transport, 7.3 DVC 프레임워크 (Soft-Sync)
> **검증**: UDP 사이드 채널로 DVC 라우팅 integration test

**구현 항목:**

- [x] `InitiateMultitransportRequest` 수신 (메인 TCP 연결 통해, MCS message channel)
  - connector `step_multitransport_bootstrapping` 실 구현 — message channel 미연결 시 즉시 통과, io 채널의 PDU(예: DemandActive)면 다음 phase 위임, message 채널의 multitransport request면 응답 송신
  - 현재는 `E_ABORT` 응답 (Soft-Sync 미지원 — MS-RDPBCGR §1.3.1.1 / §2.2.15.2가 명시적으로 허용)
- [ ] UDP 연결 수립 (justrdp-blocking 통합)
- [ ] TLS/DTLS 핸드셰이크 (UDP 위)
  - [x] DTLS 1.0/1.2 client handshake state machine (HVR cookie, ServerHello, Cert/SPKI capture, CKE/CCS/Finished, server CCS+Finished verify)
  - [x] `DtlsSession` wrapper — auto-driven flight + post-handshake app-data encrypt/decrypt with replay rejection (MS-RDPEMT §5.1 SPKI pinning helper)
  - [x] End-to-end loopback test against in-test minimal DTLS server (RSA-512 key, full HVR-cookie path)
  - [ ] TLS over reliable-UDP variant (UDPFECR transport)
- [x] `RDP_TUNNEL_HEADER` / `RDP_TUNNEL_SUBHEADER` PDU (§2.2.1)
- [x] `TunnelCreateRequest` PDU (requestId + securityCookie) (§2.2.2.1)
- [x] `TunnelCreateResponse` PDU (HRESULT) (§2.2.2.2)
- [x] `TunnelData` PDU (HigherLayerData) (§2.2.2.3)
- [x] `DYNVC_SOFT_SYNC_REQUEST` / `_RESPONSE` PDU encode/decode (MS-RDPEDYC §2.2.5)
- [x] DRDYNVC manager Soft-Sync 라우팅 테이블 (`channel_to_tunnel`, `available_tunnels`, `outbound_tunnels`)
  - `notify_tunnels_ready()` API — caller가 UDP 셋업 완료 시점을 신호
  - `inbound_tunnel_for(channel_id)` / `outbound_tunnel_for(channel_id)` 조회 API
  - `SoftSyncRequest` arm — 중복 channel_id MUST NOT 검증, 가용 터널 교집합 계산, 조건부 Response 송신, 두 번째 Request도 누적
- [x] Inbound 터널 데이터 주입 (`process_tunnel_data`) — 응답을 `outbound_tunnel_for` 기반으로 라우트
- [x] Outbound 라우팅 자동화 (`route_outbound` → `DvcOutput::Svc`/`Tunnel`) + `send_on_channel` Soft-Sync guard
- [x] Fake-tunnel 통합 테스트 (handshake 활성화 → tunnel 데이터 inject → 에코 응답이 같은 터널로 라우트)

---

## 11. Phase 8 -- Server-Side & Ecosystem

> **목표**: 서버 구현 + Rust 외부 생태계 바인딩.
> Phase 3~6의 클라이언트 구현이 대부분 완료된 후 진행.

### 11.1 `justrdp-acceptor` -- Server Connection Acceptance

> **requires**: Phase 2 (커넥터의 미러), Phase 3 코덱들 (서버 인코딩)

```rust
pub struct ServerAcceptor {
    state: ServerAcceptorState,
    config: ServerConfig,
}

pub enum ServerAcceptorState {
    WaitConnectionRequest,
    SendConnectionConfirm,
    TlsAccept,
    CredsspAccept,
    WaitMcsConnectInitial,
    SendMcsConnectResponse,
    ChannelConnection,
    WaitClientInfo,
    SendLicense,
    SendDemandActive,
    WaitConfirmActive,
    ConnectionFinalization,
    Accepted,
}
```

**구현 항목:**

- [x] `ServerAcceptor` -- `Sequence` trait 구현
- [x] `AcceptorConfig` -- 서버 설정 (지원 프로토콜/채널/멀티트랜스포트 플래그 등; 인증서/코덱은 caller 책임)
- [x] 클라이언트 Negotiate 수신 및 프로토콜 선택 (MS-RDPBCGR §2.2.1.1)
- [x] TLS 서버 핸드셰이크 (외부 위임 훅: `TlsAccept` 상태)
- [x] CredSSP 서버 측 (외부 위임 훅: `CredsspAccept` 상태 -- 실제 SPNEGO/NTLM은 caller가 수행)
- [x] 서버 측 Capability Set 생성 (General/Bitmap/Order/Pointer/Input/VirtualChannel/Share + LargePointer/MultifragmentUpdate/SurfaceCommands)
- [x] 채널 ID 할당 (IO=0x03EB, 정적 VC 순차, 메시지 채널, 유저 채널 floor 0x03EF)
- [x] `DrdynvcServer` -- 서버 측 DVC 호스트 (capability negotiation + create/close + data I/O + 모노토닉성 강제)

### 11.2 `justrdp-server` -- Extensible Server Skeleton

> 원래 한 덩어리로 계획돼 있던 `justrdp-server` 를 서브 섹션으로 분리.
> **11.2a** 최소 동작 서버 (bitmap + input + disconnect) ✅,
> **11.2b** GFX 인코딩 파이프라인 (RFX / EGFX / ZGFX) ✅,
> **11.2c** 서버 방향 채널 핸들러 (cliprdr ✅ / rdpsnd ✅ /
> rdpdr 선택), **11.2d** 풀 핸드셰이크 + 활성 세션 통합 테스트 ✅,
> **11.2e** Session Redirection 서버 emit, **11.2f**
> Auto-Reconnect Cookie 서버 emit. 11.2a 완료 시점부터 각 서브
> 섹션은 수요에 따라 독립적으로 진행 가능.

```rust
pub trait RdpServerDisplayHandler: Send {
    fn get_display_update(&mut self) -> Option<DisplayUpdate>;
    fn get_display_size(&self) -> (u16, u16);
}

pub trait RdpServerInputHandler: Send {
    fn on_keyboard_event(&mut self, flags: u16, scancode: u16);
    fn on_unicode_event(&mut self, flags: u16, unicode: u16);
    fn on_mouse_event(&mut self, flags: u16, x: u16, y: u16);
    fn on_extended_mouse_event(&mut self, flags: u16, x: u16, y: u16);
}

pub trait RdpServerClipboardHandler: Send { /* ... */ }
pub trait RdpServerSoundHandler: Send { /* ... */ }
```

#### 11.2a -- Core Server Skeleton (v1)

> **requires**: 11.1 Acceptor, 8.6 EGFX(프로토콜만, 인코딩 루프 제외)

목표: acceptor를 감싸서 **정상 세션이 굴러가는 최소 구성**. 디스플레이는
uncompressed bitmap fast-path, 입력/종료/SVC opaque forward까지. RFX/EGFX
인코딩 파이프라인과 채널별 핸들러는 11.2b/c에서 분리 진행.

- [x] `justrdp-server` crate + `RdpServerConfig` + error 타입
- [x] Connection driver -- `ServerAcceptor` 펌프 → `Accepted` 진입
- [x] `RdpServerDisplayHandler` / `RdpServerInputHandler` trait +
      `DisplayUpdate` enum (Bitmap / Pointer / Palette / Reset)
- [x] `ServerActiveStage` -- **서버 방향** fast-path input 디코드,
      slow-path control PDU 처리 (ShutdownRequest / SuppressOutput /
      RefreshRect / PersistentKeyList 후속 / ClientControl(ACTIVELY))
- [x] Fast-path `FASTPATH_UPDATETYPE_BITMAP` 인코더 (uncompressed RGB)
- [x] Fast-path pointer update 인코더 (Position / Default / Hidden /
      New / Cached / Color)
- [x] Input dispatch -- Scancode / Unicode / Mouse / MouseX / Sync /
      QoE 이벤트 → trait 호출
- [x] SVC data opaque forward hook (채널 크레이트 장착 포인트)
- [x] 종료 경로 -- `SetErrorInfoPdu` 송출 + MCS
      `DisconnectProviderUltimatum` + `ServerTerminate` output
- [-] `justrdp-blocking` 클라와 loopback 통합 테스트 -- **deferred to §11.2d**
      (wire-level smoke test in `active::tests::session_smoke_test_dispatches_in_order`
       covers ServerActiveStage in isolation; combined integration test
       lands in §11.2d after 11.2b/c so the harness can also exercise
       the GFX pipeline and channel handlers in one place rather than
       being rewritten when those interfaces shift)

#### 11.2b -- Server-Side GFX Encoding Pipeline

> **requires**: 11.2a, Phase 3 RFX 인코더, 8.6 EGFX, 4.4 ZGFX
>
> §11.2a 보다 범위가 커서 5개의 sub-section 으로 다시 분할. b-1 부터
> 직선적으로 의존 (b-2 가 b-1 의 fast-path SurfaceCommands 인코더 위에
> RFX 페이로드를 얹고, b-3 이 b-2 의 RFX 프레임을 EGFX `WireToSurface1`
> 바디로 사용). b-5 (Deactivation-Reactivation) 만 b-1 에만 의존하므로
> 독립 진행 가능.
> mstsc 실서버 인터롭 스모크 테스트는 §11.2d 로 이관 (b 단독으로는
> client/server 양측이 한 프로세스에서 돌아가는 환경이 없음).

##### 11.2b-1 -- SurfaceCommand PDU & Fast-Path Frame

> **requires**: 11.2a

`FASTPATH_UPDATETYPE_SURFCMDS = 0x4` 위에 얹히는 Surface Command 송신
경로. 코덱 페이로드는 b-2/b-3 에서 채우되, **컨테이너 PDU 와 fast-path
인코더 + DisplayHandler seam 만 먼저 안착**.

- [x] `SetSurfaceBitsCommand` PDU (MS-RDPBCGR 2.2.9.2.1) -- destLeft/Top/
      Right/Bottom + `TS_BITMAP_DATA_EX` 페이로드 컨테이너
- [x] `StreamSurfaceBitsCommand` PDU (MS-RDPBCGR 2.2.9.2.2)
- [x] `FrameMarkerCommand` PDU (MS-RDPBCGR 2.2.9.2.3) -- Begin/End
      frameId
- [x] Fast-path `SurfaceCommands` 업데이트 인코더 (`encode_fast_path` +
      fragmentation, 15-bit 길이 캡)
- [x] `DisplayUpdate::SurfaceBits(SurfaceBitsUpdate)` +
      `DisplayUpdate::FrameMarker { begin, frame_id }` 추가
- [x] `RdpServerDisplayHandler::get_surface_update()` seam
- [x] PDU roundtrip + fast-path frame 인코더 단위 테스트

##### 11.2b-2 -- RFX Wire-Level Framing & Server Encoder

> **requires**: 11.2b-1, 6.3 RFX 코덱

타일 인코더 (`RfxEncoder`) 위에 **MS-RDPRFX 2.2 메시지 스트림**을 깔고,
서버 측 컨텍스트/채널/sync 핸드셰이크를 관리. RFX 비트스트림을
`TS_BITMAP_DATA_EX.bitmapData` 로 실어 b-1 의 `SetSurfaceBitsCommand`
페이로드로 전달.

- [x] `RfxBlockType` (`WBT_*`) + `RfxHeader` (blockType/blockLen)
- [x] `WBT_SYNC` (0xCCC0) -- magic + version
- [x] `WBT_CODEC_VERSIONS` (0xCCC1)
- [x] `WBT_CHANNELS` (0xCCC2) + `RfxChannel` (id/width/height)
- [x] `WBT_CONTEXT` (0xCCC3) -- ctxId/tileSize/properties (entropy/quant/
      progressive flags)
- [x] `WBT_FRAME_BEGIN` (0xCCC4) / `WBT_FRAME_END` (0xCCC5)
- [x] `WBT_REGION` (0xCCC6) -- regionFlags + rect 배열
- [x] `WBT_TILESET` (0xCCC7) -- quants 테이블 + tile 배열 (tileIdx,
      x/y, YLen/CbLen/CrLen, YData/CbData/CrData)
- [x] `RfxFrameEncoder` -- frame 단위 API (begin → region → tileset →
      end), 서버 sync/codec_versions/channels/context handshake state,
      quant/tile 파티셔닝
- [x] PDU roundtrip + frame 단위 인코드 테스트 (1 tile, 다중 tile,
      다중 region)

##### 11.2b-3 -- EGFX Server Encoding Loop

> **requires**: 11.2b-2, 8.6 EGFX, 11.1 DVC 서버

`GfxClient` 의 미러로 **`GfxServer`** 를 만들어 `DrdynvcServer` 에
register. caps confirm 까지의 핸드셰이크와 `WireToSurface1/2` 송신
루프, `StartFrame/EndFrame ↔ FrameAcknowledge` 왕복 관리.

- [x] `GfxServer` -- `DvcProcessor` 구현 (server 방향)
- [x] Caps negotiation 서버측 -- `CapsAdvertise` 수신 → `CapsConfirm`
      선택 (10.7 우선, fallback)
- [x] 서버 송신 API: `create_surface`, `delete_surface`,
      `map_surface_to_output`, `reset_graphics`, `solid_fill`,
      `surface_to_surface`, `cache_*`, `evict_cache_entry`
- [x] `wire_to_surface_1` (codec 디스패치: codec_id 는 caller 가 지정;
      AVC 비활성 / thinclient 시 거부) + `wire_to_surface_2`
- [x] `start_frame` / `end_frame` 송신 + `FrameAcknowledge` 수신 추적
      (`pending_frames` queue + `QUEUE_DEPTH_UNAVAILABLE` /
      `SUSPEND_FRAME_ACKNOWLEDGEMENT` 인식)
- [x] `RdpServerDisplayHandler::get_egfx_frame()` seam (opaque
      `EgfxFrame { messages: Vec<Vec<u8>> }`; justrdp-server 가
      justrdp-dvc/egfx 에 의존하지 않도록 분리)
- [x] DVC integration test -- §11.2b-3 에서는 `GfxServer ↔ GfxClient`
      직접 loopback (caps + 1 frame echo + AVC 거부); 전체
      DrdynvcServer ↔ DrdynvcClient 까지 포함하는 통합 테스트는
      §11.2d 통합 테스트 단계로 이관

##### 11.2b-4 -- Progressive RFX & ZGFX Compressed DVC Framing

> **requires**: 11.2b-3

송신 루프 위에 얹는 품질/대역 최적화. progressive 는 8.6 의
`CodecQuant` 와 progressive flag 를 `WBT_TILESET` 에 흘려 단계적 품질
향상. ZGFX-Lite 는 DVC 전송 시 `DYNVC_DATA_*COMPRESSED` 로 페이로드
대체.

- [x] Progressive RFX 품질 스케줄링 hook -- `ProgressiveQualityScheduler`
      trait + tile 별 quality level 결정 (현재는 Skip/Full include 게이트;
      multi-pass 단계적 화질은 enum 확장으로 추후)
- [x] DVC 압축 프레이밍 -- `DrdynvcServer::send_data_compressed` /
      `send_data_first_compressed` 가 `DYNVC_DATA_COMPRESSED` /
      `DYNVC_DATA_FIRST_COMPRESSED` PDU emit
- [x] 압축률/사이즈 임계값 기반 fallback --
      `send_data_with_compression_fallback(payload, compressor,
      min_savings_bytes)` -- 압축 후 절약이 임계값 미만이면 raw
      `DYNVC_DATA` 로 fallback (현재 `ZgfxCompressor` 가 pass-through
      라 항상 fallback; LZ77 도입 시 자동으로 동작 활성화)
- [x] 단위 테스트 (스케줄러 skip/full/empty, 압축 PDU roundtrip,
      fallback 결정 매트릭스, 미오픈 채널 거부)

##### 11.2b-5 -- Deactivation-Reactivation Sequence

> **requires**: 11.2b-1 (b-2/b-3 와 무관, 독립 진행 가능)

해상도/모니터 변경 시 서버측 재드라이브. MS-RDPBCGR 1.3.1.3 시퀀스:
서버 → `Deactivate All PDU` → 클라 ack → 서버 재 `Demand Active` →
캡 재협상 → 활성 세션 복귀.

- [x] `DeactivateAllPdu` 송신 (MS-RDPBCGR 2.2.3.1) -- `encode_deactivate_all`
      helper (ShareControl + DeactivateAllPdu body)
- [x] `ServerActiveStage::request_deactivation_reactivation(width, height)`
      API + `DeactivationState { Active, WaitClientDeactivateAck }` 내부
      상태. `confirm_redemand_active_complete(new_share_id)` 가 D/R
      종료를 신호하고 새 share_id 적용
- [-] **재 Demand Active 시 capability set 재생성** -- 부분: 새 size
      는 `pending_display_size` 로 노출하지만 실제 re-DemandActive 흐름
      (acceptor 의 finalization 재실행) 은 application-driven으로 남김.
      현재 아키텍처에서는 active stage 가 acceptor 를 own 하지 않으므로
      caller 가 active stage 폐기 + 새 RdpServer 핸드셰이크로 처리.
      자동화는 §11.2d 통합 테스트에서 도입 예정
- [x] 명시적 API 채택 -- `pending_display_size()` accessor +
      `request_deactivation_reactivation(w, h)` 가 새 size 를 명시적
      으로 받음. `get_display_size()` 자동 감지는 의도적 제외 (애매한
      디바운싱 로직 회피)
- [x] 단위 테스트 (시퀀스 라운드트립, 변경된 해상도 반영, error gating)

#### 11.2c -- Server-Direction Channel Handlers

> **requires**: 11.2a
>
> 채널 간 의존성이 없으므로 채널별 sub-section 으로 분할. 각 sub-section
> 은 "서버 방향 PDU emit/decode + ServerProcessor → Handler trait +
> RdpServer 통합" 구조의 2 commit. cliprdr/rdpsnd 만으로 데모 시나리오
> 충족, rdpdr 은 (선택) 으로 후순위. SVC dispatch 통합은 11.2a 의
> `svc_opaque_forward` hook 위에 채널별 ServerProcessor 를 register
> 하는 식.

##### 11.2c-1 -- cliprdr 서버 방향

> **requires**: 11.2a (SVC opaque forward hook), 8.4 cliprdr PDU

목표: 기존 client-oriented `ClipboardProcessor` 의 미러로
`ClipboardServer` 를 만들어 SVC 채널 위에서 서버 → 클라이언트 클립보드
공유 시퀀스를 구동.

- [x] `ClipboardServer` -- `SvcProcessor` / `SvcServerProcessor` 구현
      (server 방향, 상태 머신 `NotStarted` → `WaitingForInit` →
      `Initialized`)
- [x] Server Monitor Ready PDU emit (MS-RDPECLIP 2.2.2.2)
- [x] Capability exchange -- `Server Clipboard Capabilities PDU` emit,
      `Client Clipboard Capabilities PDU` 수신 (general flags 비트와이즈
      AND 협상; 클라가 Caps 생략 시 `negotiated_flags = 0`)
- [x] `Format List PDU` 수신 + `Format List Response PDU` emit
      (long/short format names 양쪽; handler Err → `CB_RESPONSE_FAIL`
      강등)
- [x] `Format Data Request PDU` emit / `Format Data Response PDU` 수신
      (`build_format_data_request(format_id)` 시 pending 저장, response
      수신 시 correlation 하여 handler 에 format_id 전달)
- [x] `Format Data Request PDU` 수신 / `Format Data Response PDU` emit
      (클라가 서버 클립보드에서 데이터를 가져가는 방향)
- [x] `RdpServerClipboardHandler` trait -- `on_format_list`,
      `on_format_data_request`, `on_format_data_response`,
      `on_file_contents_request/response`, `on_lock/on_unlock`
      (`current_formats()` / `provide_format_data()` 는 명시 API
      (`build_format_list` / `on_format_data_request`) 로 대체)
- [x] `RdpServer` 통합 -- `ServerActiveStage::register_svc_processor`
      로 채널 이름별 라우팅, 미등록 채널은 11.2a `ActiveStageOutput::SvcData`
      로 fall-through
- [x] 단위 테스트 (20건: PDU 라운드트립, 시퀀스 상태 머신, 양방향 데이터
      교환, unknown msgType 드롭, MS-RDPECLIP 4.1.1 test vector +
      8건: dispatch 라우팅 / 프레이밍 / fall-through / error 전파)

##### 11.2c-2 -- rdpsnd 서버 방향

> **requires**: 11.2a, 8.5 rdpsnd PDU

목표: 기존 client-oriented `SoundProcessor` 의 미러로 `SoundServer` 를
만들어 서버 → 클라이언트 오디오 송출 시퀀스를 구동. 데이터 흐름은
주로 서버→클라 (오디오 스트리밍) 이라 emit 측이 무거움.

- [x] `SoundServer` -- `SvcProcessor` / `SvcServerProcessor` 구현
      (상태 머신 `NotStarted` → `WaitClientFormats` → `Streaming`)
- [x] `Server Audio Formats and Version PDU` (MS-RDPEA 2.2.2.1) emit --
      지원 포맷 광고 + 버전 협상 (`ServerAudioFormatsPdu::encode` 추가)
- [x] `Client Audio Formats and Version PDU` 수신 -- 포맷 교집합
      (byte-equal) + flags 비트와이즈 AND + version `min()` 협상
- [x] `Quality Mode PDU` emit (`build_quality_mode`) / 수신
      (`RdpServerSoundHandler::on_quality_mode`)
- [x] `WaveInfo PDU` (MS-RDPEA 2.2.3.3) + `Wave PDU` (2.2.3.4) emit --
      `emit_wave_chunk(format_index, audio, timestamp)` 가
      `[WaveInfoPdu, RawWave]` 페어 반환 (BodySize = 4 + audio.len())
- [x] `Wave2 PDU` (MS-RDPEA 2.2.3.10) emit -- `emit_wave2_chunk`
      (audio timestamp + 단일 PDU)
- [x] `Wave Confirm PDU` 수신 -- pending-confirm 링 (bounded at 256)
      매칭 + u16 wrapping latency 계산
- [x] `Training PDU` emit (`send_training`) / `Training Confirm PDU`
      수신 (rtt 계산 + handler dispatch, pending 없으면 silently drop)
- [x] `RdpServerSoundHandler` trait -- `on_client_formats`,
      `on_quality_mode`, `on_wave_confirm(timestamp, block_no, latency_ms)`,
      `on_training_confirm(timestamp, pack_size, rtt_ms)`, `on_close`
      (`next_audio_chunk()` / `negotiated_format()` 는 명시 API
      `emit_wave_chunk` / `negotiated_formats()` 로 대체)
- [x] `RdpServer` 통합 -- §11.2c-1 의 generic
      `ServerActiveStage::register_svc_processor` 위에 그대로 얹힘
      (cliprdr 와 동일 패턴)
- [x] 단위 테스트 (28건 server: PDU 시퀀스 + 포맷 협상 +
      WaveInfo/Wave 페어 인코드 + latency wraparound +
      blockNo 255→0 wrap + pending cap + Close reset + unknown msgType
      drop; 9건 PDU: ServerAudioFormatsPdu/TrainingPdu encode roundtrip,
      WaveInfoPdu encode, encode_wave_pdu_body)

##### 11.2c-3 -- (선택) rdpdr 서버 방향

> **requires**: 11.2a, 8.7 rdpdr PDU
>
> 데모 시나리오 후순위. IRP 다양성 (file system / printer / smart card /
> serial / parallel) 으로 가장 무거운 서브섹션. cliprdr/rdpsnd 까지만
> 구현하고 멈추는 것도 합리적.

- [ ] `FilesystemServer` -- `SvcProcessor` 구현 (server 방향)
- [ ] `Server Announce Request` (MS-RDPEFS 2.2.2.2) emit
- [ ] `Client Announce Reply` / `Client Name Request` 수신
- [ ] `Server Core Capability Request` emit / `Client Core Capability
      Response` 수신
- [ ] `Server Client ID Confirm` emit
- [ ] `Client Device List Announce Request` 수신 -- 디바이스 목록
      파싱 (DRIVE / PRINT / PORT / SMARTCARD)
- [ ] `Server Device Announce Response` emit
- [ ] `Device I/O Request` emit (CREATE/CLOSE/READ/WRITE/QUERY_INFO/
      SET_INFO/DIRECTORY_CONTROL/LOCK_CONTROL/QUERY_VOLUME_INFO/
      SET_VOLUME_INFO/DEVICE_CONTROL) -- 우선 CREATE/READ/WRITE/CLOSE
      만 1차 범위
- [ ] `Device I/O Completion` 수신 + completion ID 매칭
- [ ] `RdpServerFilesystemHandler` trait -- `on_device_announce`,
      `next_io_request()`, `on_io_completion(completion_id, status,
      data)`
- [ ] `RdpServer` 통합
- [ ] 단위 테스트 (PDU roundtrip, 시퀀스 상태 머신, completion ID 매칭)

#### 11.2d -- Integration Tests

> **requires**: 11.2a, 11.2b, 11.2c
>
> 11.2a/b/c 의 인터페이스가 모두 안정화된 시점에 **한 번에** 통합 테스트
> 인프라를 구축. 11.2a 만 통합 테스트를 작성하면 11.2b 의
> `DisplayHandler::get_surface_update()` / `get_egfx_frame()` 확장과
> 11.2c 의 `*Handler` trait 추가가 들어올 때마다 테스트 재작성이 필요해
> churn 발생.

목표: `ServerAcceptor` ↔ `ClientConnector` 양방향 풀 핸드셰이크 +
active session PDU 교환을 단일 프로세스에서 deterministic 하게 검증.
TLS 단계는 caller-delegated 훅이므로 `NoopTlsUpgrader` 어댑터로 우회
(Standard RDP Security 풀 스택 검증은
[Appendix G.2 (`§11.2a-stdsec`)](#g2-standard-rdp-security-server-side-stack-112a-stdsec)
완료 후 본 섹션에 변형 추가).

- [x] **인프라**: `crates/justrdp-server/tests/handshake_loopback.rs`
      에 `Vec<u8>` 양방향 큐 + `Sequence` 드라이브 루프 (`step_client`
      / `step_acceptor`) 구현. "`NoopTlsUpgrader`" 는 양쪽을
      `SecurityProtocol::RDP` 로 고정시켜 TLS 상태 자체를 도달
      불가능하게 만드는 방식으로 실현 (별도 어댑터 타입 불필요)
- [x] **풀 핸드셰이크 테스트** (11.2a) --
      `protocol_rdp_handshake_reaches_both_terminal_states` --
      X.224 Negotiate → MCS Connect → Channel Join → Client Info →
      License → DemandActive → ConfirmActive → Finalization → 양쪽
      `Accepted` / `Connected` 도달 + io/user channel + share_id 일치
      검증
- [x] **Active session 양방향** (11.2a) --
      `active_session_bitmap_emit_input_dispatch_and_clean_disconnect`
      -- 8x8 32bpp bitmap emit → fast-path 프레임 decode 검증;
      fast-path scancode PDU 클라 → 서버 dispatch 검증; clean
      disconnect (`SetErrorInfoPdu` + `DisconnectProviderUltimatum`)
      2-frame 생성 검증
- [x] **채널 핸들러 검증** (11.2c) --
      `channel_handlers_roundtrip_over_active_stage` -- cliprdr 등록
      init burst (Caps + MonitorReady) + 클라 FormatList → 서버
      `FormatListResponse` 왕복; rdpsnd 등록 init burst
      (ServerAudioFormats) + 클라 ClientAudioFormats → handler
      `on_client_formats` dispatch 검증
- [x] **GFX 파이프라인 검증** (11.2b) --
      `egfx_frame_seam_surfaces_caller_owned_bytes` -- 풀 RFX/EGFX
      왕복은 §11.2b-3 의 `GfxServer↔GfxClient` loopback (commit
      a12f1b2) 에서 이미 검증됨; 여기서는 `get_egfx_frame` seam 의
      바이트 보존성만 smoke test
- [x] **regression suite** -- 위 4 건 모두 `#[test]` 로 CI 에서
      항상 실행됨 (`cargo test --workspace`)

#### 11.2e -- Session Redirection Server Emit

> **requires**: 11.2a, §9.3 Session Redirection (클라이언트 수신
> 경로 ✅), `justrdp-pdu/src/rdp/redirection.rs` (`ServerRedirectionPdu`
> 인코딩 ✅)

목표: 서버가 `ServerRedirectionPdu` 를 emit 해서 클라를 다른 타깃
서버로 유도 (로드밸런싱 / 세션 브로커 시나리오). PDU 레이어는 이미
완성되어 있으므로 `ServerActiveStage` 측 API 만 추가하면 됨.

- [ ] `ServerActiveStage::emit_redirection(target_addr,
      load_balance_info, cookie)` API -- PDU 를 ShareData 로 감싸
      I/O 채널에 송출
- [ ] PK-encrypted password blob / RDSTLS cookie / SmartCard
      redirection 옵션 경로 지원 (이미 `RedirectionPdu` 필드로 존재)
- [ ] Emit 후 상태 처리 -- 서버는 emit 만 하고 클라 연결 종료는
      클라 몫; `ServerActiveStage::has_emitted_redirection()` 조회
      + 이후 송출 차단
- [ ] 단위 테스트 -- wire 바이트 검증 (`mock_redirect.rs` 의
      `build_redirect_frame` 대조), PDU 옵션 분기
- [ ] 통합 테스트 -- `handshake_loopback.rs` 에 시나리오 추가:
      서버 emit → 클라 `ConnectionResult.server_redirection` 파싱

**예상**: 2 commit (API + 테스트 1, 통합 테스트 1).

#### 11.2f -- Auto-Reconnect Cookie Server Emit

> **requires**: 11.2a, §9.2 Auto-Reconnect (클라이언트 수신 경로 ✅),
> `justrdp-pdu/src/rdp/finalization.rs::ArcScPrivate` ✅

목표: 서버가 `SaveSessionInfoPdu` 내 `ArcScPrivate` (32B
arcRandomBits + logonId) 를 emit 해서 클라가 이후 재연결 시 ARC
cookie 로 재인증할 수 있게 함. 클라 측은 §9.2 에서 수신 / 저장 /
재전송 모두 완료. 서버 측은 cookie 생성 + emit + (선택) 재인증
검증 헬퍼만 추가하면 됨.

- [ ] Caller-managed RNG trait 주입 (`fn fill_random(&mut self, buf:
      &mut [u8])`) -- crate 가 RNG 선택을 강제하지 않음
- [ ] `ServerActiveStage::emit_save_session_info_v1(logon_id,
      user_name, domain)` + `..._v2(...)` API (Logon / LogonLong
      variants) + Extended(AutoReconnectCookie) variant
- [ ] `ServerActiveStage::emit_auto_reconnect_cookie(logon_id, rng)`
      편의 API -- 32B cookie 생성 + `ArcScPrivate` 서브구조 + Save
      Session Info PDU 인코드 + 송출 + `(logon_id, cookie)` 반환
- [ ] Cookie retention hook -- 서버 측 세션 저장소 정책은 caller
      몫 (in-memory / Redis / DB). Stage 는 단일 세션의 현재 cookie
      만 기억하고 재전송 시 교체
- [ ] (선택) 재연결 시 `ClientAutoReconnectPacket` 수신 + HMAC-MD5
      (`ClientRandom`, `ArcRandomBits`, `SecurityVerifier`) 검증
      헬퍼 -- 완전한 재인증 경로 (Security Exchange → 세션 키 재개)
      는 §11.2a-stdsec scope; 여기선 검증 헬퍼만
- [ ] 단위 테스트 -- PDU bytes, cookie 32B 보존, logonId 일치
- [ ] 통합 테스트 -- `handshake_loopback.rs` 확장: 서버 emit → 클라
      `ConnectionResult.server_arc_cookie` 에 arrival 확인

**예상**: 1~2 commit (API + 단위/통합 테스트).

### 11.3 `justrdp-web` -- WASM Bindings

> **requires**: Phase 3 코덱 (`no_std`), Phase 4/5 세션+채널

- [ ] `wasm-bindgen` 기반 JavaScript API
- [ ] WebSocket 전송 (브라우저 환경)
- [ ] Canvas/WebGL 렌더링
- [ ] 키보드/마우스 이벤트 캡처
- [ ] 클립보드 API 통합 (Clipboard API)
- [ ] 오디오 재생 (Web Audio API)

### 11.4 `justrdp-ffi` -- C/Python FFI Bindings

> **requires**: Phase 4/5 세션+채널

- [ ] Diplomat 기반 C FFI
- [ ] PyO3 기반 Python 바인딩
- [ ] 타입 안전 opaque handle 패턴
- [ ] 콜백 기반 비동기 인터페이스

### 11.5 `justrdp-client` -- Reference Client Binary

> **requires**: Phase 3~6 (전체 클라이언트 파이프라인)

- [ ] CLI 인터페이스 (clap)
- [ ] `.rdp` 파일 지원
- [ ] 렌더링 백엔드:
  - [ ] softbuffer (소프트웨어 렌더링)
  - [ ] wgpu (GPU 가속)
  - [ ] glutin + OpenGL
- [ ] 윈도우 시스템 통합 (winit)
- [ ] 클립보드/파일/오디오 네이티브 통합
- [ ] 멀티모니터 지원
- [ ] 게이트웨이 연결 지원
- [ ] 세션 녹화/재생 (디버깅용)

### 11.6 `justrdp-gateway` -- RD Gateway Server

> **requires**: 10.1 RD Gateway 프로토콜, 11.1 Server Acceptor

- [ ] HTTP/HTTPS 기반 게이트웨이
- [ ] WebSocket 전송 지원
- [ ] 인증 (NTLM/Kerberos/Bearer 토큰)
- [ ] 리소스 인가
- [ ] 백엔드 RDP 서버 프록시
- [ ] 세션 모니터링

### 11.7 `justrdp-proxy` -- RDP Proxy

> **requires**: 11.1 Server Acceptor, Phase 2 Connector

- [ ] 투명 프록시 (세션 녹화, 감사)
- [ ] 프로토콜 변환
- [ ] 로드 밸런싱
- [ ] 연결 풀링

---

## 12. Protocol Specifications Reference

### Required Specifications (구현 시 참조)

| Spec ID     | Name                                     | Phase | Priority     |
| ----------- | ---------------------------------------- | ----- | ------------ |
| MS-RDPBCGR  | Basic Connectivity and Graphics Remoting | 1-2   | **Critical** |
| MS-RDPEGDI  | Graphics Device Interface Acceleration   | 1     | **Critical** |
| MS-CSSP     | Credential Security Support Provider     | 2     | **Critical** |
| MS-NLMP     | NT LAN Manager Protocol                  | 2     | **Critical** |
| MS-SPNG     | SPNEGO Extension                         | 2     | **Critical** |
| MS-RDPELE   | Licensing Extension                      | 2     | High         |
| MS-RDPRFX   | RemoteFX Codec Extension                 | 3     | **Critical** |
| MS-RDPNSC   | NSCodec Extension                        | 3     | High         |
| MS-RDPEDYC  | Dynamic Virtual Channel Extension        | 4     | **Critical** |
| MS-RDPEGFX  | Graphics Pipeline Extension              | 5     | **Critical** |
| MS-RDPECLIP | Clipboard Virtual Channel Extension      | 5     | **Critical** |
| MS-RDPEFS   | File System Virtual Channel Extension    | 5     | High         |
| MS-RDPEA    | Audio Output Virtual Channel Extension   | 5     | High         |
| MS-RDPEDISP | Display Update Virtual Channel Extension | 5     | High         |
| MS-RDPESC   | Smart Card Virtual Channel Extension     | 5     | Medium       |
| MS-RDPEAI   | Audio Input Virtual Channel Extension    | 5     | Medium       |
| MS-RDPERP   | Remote Programs (RAIL)                   | 5     | Medium       |
| MS-RDPESP   | Serial/Parallel Port Virtual Channel     | 5     | Low          |
| MS-KILE     | Kerberos Protocol Extensions             | 6     | High         |
| MS-RDPEI    | Input Virtual Channel Extension (Touch)  | 6     | Medium       |
| MS-RDPEPS   | Pen Remoting                             | 6     | Low          |
| MS-RDPEVOR  | Video Optimized Remoting                 | 6     | Medium       |
| MS-RDPEUSB  | USB Devices Virtual Channel Extension    | 6     | Low          |
| MS-RDPECAM  | Camera Device Redirection                | 6     | Low          |
| MS-RDPEPC   | Printer Cache Extension                  | 6     | Low          |
| MS-RDPEPNP  | Plug and Play Device Redirection         | 6     | Low          |
| MS-RDPCR2   | Composited Remoting V2 (DWM scene graph) | —     | Deferred     |
| MS-RDPEV    | Video Redirection Virtual Channel (TSMF) | 6     | Low          |
| MS-RDPEMC   | Multiparty Virtual Channel Extension     | 6     | Low          |
| MS-RDPEDC   | Desktop Composition Virtual Channel      | 6     | Low          |
| MS-TSGU     | Terminal Services Gateway                | 7     | High         |
| MS-RDPEUDP  | UDP Transport Extension                  | 7     | Medium       |
| MS-RDPEMT   | Multitransport Extension                 | 7     | Medium       |

### Additional Standards

| Standard          | Purpose                                |
| ----------------- | -------------------------------------- |
| RFC 1006          | TPKT -- TCP 위 ISO transport           |
| ITU-T T.125       | MCS (Multipoint Communication Service) |
| ITU-T T.124       | GCC (Generic Conference Control)       |
| ISO 8073          | X.224 (Transport Protocol Class 0)     |
| ITU-T X.680-X.690 | ASN.1 BER/PER 인코딩                   |
| RFC 5246/8446     | TLS 1.2 / 1.3                          |
| RFC 6347          | DTLS 1.2                               |
| RFC 4120          | Kerberos v5                            |

---

## 13. Public API Design

### 13.1 Client-Side Quick Start API (`justrdp-blocking`)

`justrdp-blocking` 크레이트가 제공하는 권장 API. 대부분의 사용자는 이 레이어만 알면 충분.

```rust
use justrdp_blocking::{RdpClient, RdpEvent, ReconnectPolicy};
use justrdp_connector::{Config, Credentials};

fn main() -> anyhow::Result<()> {
    let config = Config::builder()
        .server("192.168.1.100:3389")
        .credentials(Credentials::password("user", "pass", Some("DOMAIN")))
        .desktop_size(1920, 1080)
        .color_depth(ColorDepth::Bpp32)
        .enable_clipboard(true)
        .enable_drive_redirect("/home/user/share")
        .enable_audio(true)
        .reconnect_policy(ReconnectPolicy::default()) // 9.2
        .follow_redirects(true)                       // 9.3
        .license_store(FileLicenseStore::default())   // Appendix G.1 deferred
        .build()?;

    let mut client = RdpClient::connect(config)?;

    while let Some(event) = client.next_event()? {
        match event {
            RdpEvent::GraphicsUpdate { region, bitmap } => render(region, bitmap),
            RdpEvent::PointerUpdate(p) => update_cursor(p),
            RdpEvent::KeyboardIndicators { caps, num, .. } => update_leds(caps, num),
            RdpEvent::PlaySound { frequency, duration_ms } => beep(frequency, duration_ms),
            RdpEvent::Reconnecting { attempt, .. } => log::info!("reconnecting #{attempt}"),
            RdpEvent::Redirected { target } => log::info!("redirected to {target}"),
            RdpEvent::Disconnected(reason) => { log::info!("bye: {reason:?}"); break; }
            _ => {}
        }

        client.send_keyboard(Scancode::A, true)?;
        client.send_mouse(500, 300, MouseButtons::empty())?;
    }

    Ok(())
}
```

### 13.2 Low-Level State Machine API (`justrdp-connector` 직접)

> **주의**: 이 레이어는 커스텀 트랜스포트(WASM, 테스트 mock, UDP over FIDO 등)가 필요한 경우에만 사용하세요. 일반 TCP 클라이언트는 §13.1 `justrdp-blocking`을 쓰면 됩니다.

```rust
use justrdp_connector::{ClientConnector, Config, Sequence};
use justrdp_pdu::nego::SecurityProtocol;

// 1. 커넥터 생성
let config = Config { /* ... */ };
let mut connector = ClientConnector::new(config);

// 2. TCP 연결
let stream = TcpStream::connect("server:3389").await?;

// 3. 상태 머신 구동
let mut buf = WriteBuf::new();
loop {
    let hint = connector.next_pdu_hint();
    let input = read_pdu(&stream, hint).await?;
    let written = connector.step(&input, &mut buf)?;

    if written.size() > 0 {
        stream.write_all(&buf[..written.size()]).await?;
    }

    match connector.state() {
        ClientConnectorState::EnhancedSecurityUpgrade => {
            // TLS 업그레이드는 호출자가 수행
            let tls_stream = justrdp_tls::upgrade(stream, server_name).await?;
            stream = tls_stream;
        }
        ClientConnectorState::Connected { result } => {
            // 연결 완료
            break;
        }
        _ => continue,
    }
}

// 4. 활성 세션
let mut session = ActiveStage::new(result);
loop {
    let frame = read_frame(&stream).await?;
    let outputs = session.process(&frame)?;
    for output in outputs {
        match output {
            ActiveStageOutput::ResponseFrame(data) => {
                stream.write_all(&data).await?;
            }
            ActiveStageOutput::GraphicsUpdate { region, data } => {
                update_framebuffer(region, data);
            }
            // ...
        }
    }
}
```

### 13.3 Server-Side API

```rust
use justrdp_server::{RdpServer, ServerConfig, DisplayHandler, InputHandler};

struct MyDisplay { /* framebuffer */ }
impl DisplayHandler for MyDisplay {
    fn get_display_update(&mut self) -> Option<DisplayUpdate> { /* ... */ }
    fn get_display_size(&self) -> (u16, u16) { (1920, 1080) }
}

struct MyInput;
impl InputHandler for MyInput {
    fn on_keyboard_event(&mut self, flags: u16, scancode: u16) { /* ... */ }
    fn on_mouse_event(&mut self, flags: u16, x: u16, y: u16) { /* ... */ }
}

let config = ServerConfig::builder()
    .certificate(cert)
    .private_key(key)
    .security(SecurityMode::Nla)
    .build()?;

let server = RdpServer::new(config, MyDisplay::new(), MyInput);
server.listen("0.0.0.0:3389").await?;
```

---

## 14. Testing Strategy

### 14.1 Unit Tests

- **PDU roundtrip**: 모든 PDU 타입에 대해 `encode → decode → assert_eq`
- **Snapshot tests**: `expect-test` 크레이트로 PDU 바이트 스냅샷 검증
- **Property tests**: `proptest`로 임의 입력에 대한 인코딩/디코딩 일관성 검증
- **Codec tests**: 참조 입출력 데이터로 코덱 정확성 검증

### 14.2 Integration Tests

모든 실서버 통합 테스트는 `justrdp-blocking::RdpClient`를 사용 (펌프 루프를 테스트마다 재작성하지 않음).

- **실제 서버 연결**: Windows RDP 서버에 대한 연결/인증/그래픽 수신 통합 테스트
- **xrdp 연결**: 오픈소스 xrdp 서버 대응 테스트
- **xfreerdp 호환성**: FreeRDP 클라이언트와의 상호 운용성 테스트 (서버 모드)
- **게이트웨이 통과**: RD Gateway를 통한 연결 테스트
- **자동 재연결**: `RdpClient` 연결 후 TCP 강제 종료 → 3초 이내 `Reconnected` 이벤트
- **세션 리다이렉션**: mock broker로 redirection PDU 주입 → 새 target 접속 확인
- **라이선스 영구화**: 첫 연결에서 발급 → 두 번째 연결에서 licensing 스킵 검증

### 14.3 Fuzzing

> **status**: 인프라 미구축. DoD Phase 1/2/3의 "cargo fuzz 최소 N시간
> 무크래시" 항목들이 이 플랜에 의존한다. 현재는 `justrdp-fuzzing`
> crate가 §3 Crate Structure 표에만 존재하고 실제 디렉터리/Cargo.toml
> 은 없는 상태 — 본 섹션이 그 공백을 채우는 작업 플랜이다.

#### 14.3.1 인프라 부트스트랩

- [ ] `crates/justrdp-fuzzing/` 디렉터리 + `Cargo.toml` 생성
  - [ ] `[package] publish = false`, 워크스페이스 등록
  - [ ] `libfuzzer-sys` dep, `[[bin]]` 섹션들로 타겟 나열
  - [ ] `cargo fuzz` (`cargo-fuzz` 도구)와 호환되는 레이아웃
- [ ] `fuzz/` 디렉터리와 `fuzz.toml` (타겟 목록, corpus 경로, 디폴트 플래그)
- [ ] 모든 타겟 공통 유틸: `init_from_slice`, 최대 입력 크기 상한,
      `#![no_main]` 보일러플레이트 공통화
- [ ] 로컬 실행 스크립트 `scripts/fuzz.sh` — nightly 툴체인 탐지,
      타겟 이름 → `cargo +nightly fuzz run <target>` 매핑
- [ ] README: `rustup toolchain install nightly`,
      `cargo install cargo-fuzz`, 로컬 run/corpus-minimize 예시

#### 14.3.2 타겟 목록 (우선순위)

> 우선순위 기준: (1) 외부 바이트가 직접 들어오는 표면 (2) 디코더
> 복잡도 (3) 과거 보안 이슈 빈도. 상단일수록 먼저 시작한다.

**Tier 1 — PDU 디코더 (Phase 1 DoD 대상)**

- [ ] `fuzz_tpkt_header` — TPKT 4B 헤더 + X.224
- [ ] `fuzz_mcs_connect_initial` — GCC user data 블록 포함
- [ ] `fuzz_mcs_channel_join` / `mcs_send_data`
- [ ] `fuzz_capability_sets` — 30종 capability set dispatch
- [ ] `fuzz_fastpath_input` / `fuzz_fastpath_output` — 빠른 경로 이벤트
- [ ] `fuzz_share_data_pdu` — Control / Synchronize / FontList / PersistentKey
- [ ] `fuzz_client_info_pdu` — Info packet + Extended info + ARC 쿠키
- [ ] `fuzz_license_preamble` — licensing PDU family

**Tier 2 — 커넥터/시퀀스 (Phase 2 DoD 대상)**

- [ ] `fuzz_credssp_ts_request` — BER/DER 파서 표면
- [ ] `fuzz_ntlm_message` — Negotiate / Challenge / Authenticate + AV pairs
- [ ] `fuzz_x224_negotiation` — CR/CC + RDP_NEG_REQ/RSP
- [ ] `fuzz_server_redirection_pdu` — UTF-16LE 주소, LB cookie,
      PK-encrypted password blob (§9.3 관련)

**Tier 3 — 코덱 (Phase 3 DoD 대상)**

- [ ] `fuzz_rfx_decoder` — 전체 RFX 프레임 (header → tile → RLGR)
- [ ] `fuzz_rle_decoder` — Interleaved RLE bitmap
- [ ] `fuzz_nscodec_decoder`
- [ ] `fuzz_clearcodec_decoder`
- [ ] `fuzz_zgfx_decompressor` — RDP8 bulk 압축 해제
- [ ] `fuzz_mppc_decompressor` — MS-RDPBCGR bulk
- [ ] `fuzz_ncrush_decompressor` / `fuzz_xcrush_decompressor`

**Tier 4 — 가상 채널 / 확장**

- [ ] `fuzz_dvc_pdu` — DRDYNVC create/close/data 프레임
- [ ] `fuzz_rdpegfx_pdu` — GFX pipeline PDU
- [ ] `fuzz_cliprdr_pdu` — 클립보드 포맷 데이터
- [ ] `fuzz_rdpdr_iorequest` — 파일 시스템 IRP

#### 14.3.3 Corpus 전략

- [ ] 각 타겟별 `corpus/<target>/` 디렉터리, 초기 시드로 단위 테스트의
      encode() 출력 바이트 사용 (기존 roundtrip 벡터 재활용)
- [ ] Wire trace 샘플이 존재하는 PDU(§4 Wire Traces, RDPEPNP, RDPEMC 등)는
      스펙 예시 바이트를 corpus에 추가
- [ ] `cargo fuzz tmin` 으로 크래시 재현 corpus 축소 워크플로 문서화
- [ ] `.gitignore`에 `fuzz/corpus/` 제외, `fuzz/seeds/`만 커밋 (대용량
      회피 + 시드 재현성 동시 확보)

#### 14.3.4 CI 통합

- [ ] `.github/workflows/fuzz-smoke.yml` — 모든 타겟 60초 스모크
      (매 PR, 크래시만 체크)
- [ ] `.github/workflows/fuzz-nightly.yml` — 핵심 타겟 1시간 (매일 cron)
- [ ] OSS-Fuzz 등록 검토 (장기) — 24/7 퍼징 서비스 무료 제공, 보안
      프로젝트 요건 충족 여부 확인 필요
- [ ] 크래시 발견 시 failing input 을 테스트 케이스로 승격하는 워크플로
      (regression test 로 보존)

#### 14.3.5 Exit criteria (DoD에서 참조)

- **Phase 1 DoD**: Tier 1 전 타겟 최소 1시간 무크래시
- **Phase 2 DoD**: Tier 1 + Tier 2 최소 4시간 무크래시
- **Phase 3 DoD**: Tier 1 + Tier 3 최소 8시간 무크래시

**공통 목표**: 패닉, 메모리 무한 증가, 무한 루프, 정수 오버플로우,
 unchecked slice indexing 없음.

### 14.4 Benchmarks

- **코덱 벤치마크**: RFX/ZGFX/RLE 디코딩 throughput (`criterion`)
- **PDU 벤치마크**: 인코딩/디코딩 처리량
- **E2E 벤치마크**: 연결 수립 시간, 프레임 처리 레이턴시

### 14.5 CI/CD

- **다중 플랫폼**: Windows, Linux, macOS
- **다중 타겟**: x86_64, aarch64, wasm32
- **MSRV (Minimum Supported Rust Version)**: 명시 및 CI 검증
- **`no_std` 검증**: Core tier 크레이트의 `no_std` 빌드 확인
- **Clippy + rustfmt**: 코드 품질 게이트
- **MIRI**: unsafe 블록 정의된 행동 검증 (unsafe 없는 것이 목표이지만 안전장치)

---

## 15. Performance Targets

| Metric                 | Target                           | Status          | Note                                                                                         |
| ---------------------- | -------------------------------- | --------------- | -------------------------------------------------------------------------------------------- |
| 연결 수립 시간         | < 1s (LAN)                       | 미측정          | NLA 포함. `criterion` 벤치 하네스 + 실서버 필요. xrdp CI 첫 런에서 `connect_test` 총 시간 수집 예정 |
| 프레임 디코딩 레이턴시 | < 5ms (1080p)                    | 미측정          | RFX/EGFX                                                                                     |
| ZGFX 해제 throughput   | > 500 MB/s                       | 미측정          | 싱글 코어                                                                                    |
| RFX 디코딩 throughput  | > 200 Mpixels/s                  | 미측정          | SIMD 최적화                                                                                  |
| 메모리 사용량          | < 50 MB (idle session)           | 미측정          | 코덱 버퍼 포함                                                                               |
| 바이너리 크기          | < 5 MB (stripped, full features) | 미측정          |                                                                                              |
| Zero-copy parsing      | 가능한 모든 곳                   | 진행 중         | `Decode<'de>` lifetime-bound                                                                 |

### 최적화 전략

- **SIMD**: 색상 변환, DWT에 `std::simd` (nightly) 또는 수동 `cfg(target_arch)` 최적화
- **Zero-copy**: `ReadCursor` 기반 파싱, 불필요한 `Vec` 할당 회피
- **Arena allocation**: 프레임 단위 할당기로 GC 부담 최소화
- **병렬 디코딩**: 타일/영역 단위 `rayon` 병렬 처리 (옵션)
- **메모리 풀**: PDU 버퍼 재사용

---

## 16. Dependency Policy

### Core Tier (no_std)

| Allowed            | Examples                |
| ------------------ | ----------------------- |
| `alloc` crate      | `Vec`, `String`, `Box`  |
| Zero-dep 유틸리티  | `bitflags`, `byteorder` |
| Pure Rust 알고리즘 | 자체 구현 선호          |

| Forbidden    | Reason                 |
| ------------ | ---------------------- |
| `std`        | `no_std` 호환성        |
| Proc-macros  | 컴파일 속도            |
| I/O 크레이트 | 코어에서 I/O 분리 원칙 |
| C 바인딩     | 순수 Rust 원칙         |

### Extra Tier

| Allowed              | Examples                               |
| -------------------- | -------------------------------------- |
| `tokio`, `futures`   | Async runtime                          |
| `rustls`             | TLS                                    |
| `ring` / `aws-lc-rs` | 암호화 (CredSSP/NTLM/Kerberos 구현 시) |
| `winit`, `wgpu`      | 클라이언트 앱                          |

| Forbidden | Reason                                   |
| --------- | ---------------------------------------- |
| `openssl` | C 의존성                                 |
| `freerdp` | C 의존성, 이 프로젝트의 존재 이유와 충돌 |

### 의존성 기준

1. **순수 Rust** 우선. C 바인딩은 최후의 수단.
2. **H.264**: 순수 Rust H.264 디코더가 성숙하지 않은 경우, trait 추상화 뒤에 숨기고 `openh264` (C) 또는 `ffmpeg` (C)를 optional feature로 제공 가능. 장기적으로 순수 Rust H.264 디코더 개발 또는 채택.
3. **최소 의존**: 각 크레이트는 실제 필요한 의존성만 포함.
4. **MSRV**: stable Rust, 최신 stable - 2 버전까지 지원 목표.

---

## 17. Security Audit Plan

> RDP는 인터넷에 노출되는 공격 표면이 넓은 프로토콜. 보안은 사후 검토가 아니라 설계 단계부터 반영.

### 17.1 Threat Model

| Threat                           | Attack Surface                 | Mitigation                                                              |
| -------------------------------- | ------------------------------ | ----------------------------------------------------------------------- |
| **Malicious Server**             | PDU 파싱, 코덱 디코딩          | 모든 Decode에 길이 검증, 퍼징, `#[deny(unsafe_code)]`                   |
| **MITM**                         | TLS, CredSSP                   | TLS 인증서 검증, CredSSP pubKeyAuth 바인딩                              |
| **Credential Theft**             | NTLM relay, 메모리 내 비밀번호 | `Zeroize` trait로 메모리 내 자격증명 소거, Remote Credential Guard 지원 |
| **Buffer Overflow**              | PDU 인코딩/디코딩              | Rust 메모리 안전성, 경계 검사, 정수 오버플로 검사                       |
| **DoS**                          | 압축 폭탄, 무한 루프 PDU       | 최대 크기 제한, 재귀 깊이 제한, 타임아웃                                |
| **Malicious Client** (서버 모드) | 인증 우회, 악의적 입력         | NLA 필수, 입력 검증, rate limiting                                      |
| **DVC Injection**                | 악의적 DVC 채널 이름           | 채널 이름 화이트리스트, 길이 제한                                       |

### 17.2 Security Requirements

**코드 수준:**

- [x] `#![forbid(unsafe_code)]` -- Core tier 전체 (core/pdu/connector 등 각 파일 상단 확인)
- [x] `zeroize` -- RSA 개인 키(`justrdp-core::rsa`), CredSSP 자격/세션 키/nonce,
      Kerberos 키, PKINIT smartcard provider, DH/bignum 등에 적용
- [ ] 정수 오버플로 -- `checked_add()`, `checked_mul()` 사용 (PDU 길이 계산) — 부분 적용, 전체 감사 필요
- [x] 최대 PDU 크기 -- TPKT/Fast-Path 레벨에서 거부
- [x] 최대 채널 수 -- SVC 31개, DVC 구현별 configurable cap (예: `MAX_CHANNELS`)
- [ ] 압축 폭탄 방지 -- 해제 출력 최대 크기 제한 (compression ratio limit)
- [ ] 타임아웃 -- 모든 상태 머신에 전환 타임아웃 (configurable)

**프로토콜 수준:**

- [ ] TLS 최소 버전 강제 (TLS 1.2+, configurable)
- [ ] Standard RDP Security 기본 비활성화 (RC4는 안전하지 않음).
      **레거시 RC4 서버 E2E 검증은 의도적으로 수행하지 않는다** —
      2026년 기준 RC4-only RDP 서버는 거의 남아 있지 않고, JustRDP
      정책상 이 경로는 opt-in 레거시 호환성으로만 유지된다.
- [ ] NLA/CredSSP 기본 강제
- [ ] 자체 서명 인증서 경고 (기본 거부, configurable 허용)
- [ ] CredSSP 공개키 바인딩 필수 (MITM 방지)

**감사 계획:**

- [ ] Phase 2 완료 후: CredSSP/NTLM/TLS 보안 전문가 리뷰
- [ ] Phase 3 완료 후: 코덱 디코더 퍼징 결과 리뷰, 메모리 안전성 검증
- [ ] Phase 4 완료 후: 채널 구현 보안 리뷰 (RDPDR 파일 접근 권한, CLIPRDR 데이터 유출)
- [ ] 첫 번째 stable 릴리스 전: 외부 보안 감사 (독립 보안 업체)
- [ ] CVE 대응 프로세스 수립 (보안 취약점 신고 → 패치 → 공개)

### 17.3 Known RDP CVE Patterns (학습용)

| CVE Pattern                   | Description                                         | JustRDP 방어                  |
| ----------------------------- | --------------------------------------------------- | ----------------------------- |
| CVE-2019-0708 (BlueKeep)      | Use-after-free in channel handling                  | Rust 소유권 모델              |
| CVE-2019-1181/1182 (DejaBlue) | Integer overflow in decompression                   | `checked_*()` 연산            |
| CVE-2023-24905                | RDP client remote code execution via crafted server | PDU 길이 검증, 코덱 입력 검증 |
| CVE-2023-35332                | RDP Security downgrade (TLS 1.0 fallback)           | 최소 TLS 1.2 강제             |

---

## 18. Compatibility Matrix

### 18.1 Server Compatibility

| Server                 | Version        | Target | Priority     | E2E validation                              | Notes                               |
| ---------------------- | -------------- | ------ | ------------ | ------------------------------------------- | ----------------------------------- |
| Windows Server 2012 R2 | RDP 8.1        | Full   | Medium       | ☐                                           | 레거시, RDPEGFX v8.0/8.1            |
| Windows Server 2016    | RDP 10.0       | Full   | High         | ☐                                           | RDPEGFX v10.0, H.264                |
| Windows Server 2019    | RDP 10.5       | Full   | **Critical** | ✅ manual `192.168.136.136` (`connect_test`) | 가장 널리 사용, RDPEGFX v10.5       |
| Windows Server 2022    | RDP 10.7       | Full   | **Critical** | ☐                                           | 최신 LTS, RDPEGFX v10.7             |
| Windows Server 2025    | RDP 10.7+      | Full   | High         | ☐                                           | 최신, AAD 통합                      |
| Windows 10 (Pro/Ent)   | RDP 10.x       | Full   | **Critical** | ☐ (물리 머신 필요)                          | 가장 흔한 타겟                      |
| Windows 11 (Pro/Ent)   | RDP 10.x       | Full   | **Critical** | ☐ (물리 머신 필요)                          | 최신 데스크톱                       |
| xrdp                   | 0.9.x / 0.10.x | Full   | High         | ⏳ CI 첫 런 대기 (§5.5 workflow)             | Linux RDP 서버, 오픈소스 생태계     |
| FreeRDP Server         | 3.x            | Basic  | Medium       | ☐                                           | 테스트/개발용                       |
| Azure Virtual Desktop  | Latest         | Full   | High         | ☐                                           | 클라우드 시나리오, AAD/Gateway 필수 |
| Windows 365            | Latest         | Full   | High         | ☐                                           | 클라우드 PC                         |

### 18.2 Client Compatibility (서버 모드 시)

| Client                                 | Version  | Target | Notes                               |
| -------------------------------------- | -------- | ------ | ----------------------------------- |
| mstsc.exe (Windows)                    | Built-in | Full   | 표준 레퍼런스 클라이언트            |
| Microsoft Remote Desktop (macOS)       | Latest   | Full   | Mac 사용자                          |
| Microsoft Remote Desktop (iOS/Android) | Latest   | Full   | 모바일                              |
| FreeRDP (xfreerdp)                     | 3.x      | Full   | 오픈소스 레퍼런스                   |
| Remmina                                | 1.4.x    | Full   | Linux GUI 클라이언트 (FreeRDP 기반) |
| Web 클라이언트 (HTML5)                 | -        | Full   | 브라우저 기반, WebSocket 필수       |

### 18.3 Feature Support by RDP Version

| Feature                  | RDP 5.0 | RDP 6.0 | RDP 7.0 | RDP 8.0 | RDP 8.1 | RDP 10.0+    |
| ------------------------ | ------- | ------- | ------- | ------- | ------- | ------------ |
| Standard RDP Security    | Yes     | Yes     | Yes     | Yes     | Yes     | Yes          |
| TLS                      | -       | Yes     | Yes     | Yes     | Yes     | Yes          |
| NLA (CredSSP)            | -       | Yes     | Yes     | Yes     | Yes     | Yes          |
| Bitmap Compression (RLE) | Yes     | Yes     | Yes     | Yes     | Yes     | Yes          |
| RDP6 Bitmap Compression  | -       | Yes     | Yes     | Yes     | Yes     | Yes          |
| RemoteFX (RFX)           | -       | -       | Yes     | Yes     | Yes     | Yes          |
| NSCodec                  | -       | -       | -       | Yes     | Yes     | Yes          |
| RDPEGFX Pipeline         | -       | -       | -       | Yes     | Yes     | Yes          |
| H.264/AVC420             | -       | -       | -       | -       | Yes     | Yes          |
| H.264/AVC444             | -       | -       | -       | -       | -       | Yes          |
| Progressive RFX          | -       | -       | -       | -       | -       | Yes          |
| UDP Transport            | -       | -       | -       | Yes     | Yes     | Yes          |
| Auto-Detect              | -       | -       | -       | Yes     | Yes     | Yes          |
| RAIL (RemoteApp)         | -       | Yes     | Yes     | Yes     | Yes     | Yes          |
| Clipboard (file copy)    | -       | Yes     | Yes     | Yes     | Yes     | Yes          |
| Drive Redirection        | Yes     | Yes     | Yes     | Yes     | Yes     | Yes          |
| Audio Output             | Yes     | Yes     | Yes     | Yes     | Yes     | Yes          |
| Audio Input              | -       | -       | Yes     | Yes     | Yes     | Yes          |
| Multi-Monitor            | -       | -       | Yes     | Yes     | Yes     | Yes          |
| Display Resize (DISP)    | -       | -       | -       | Yes     | Yes     | Yes          |
| AAD Authentication       | -       | -       | -       | -       | -       | Yes (Win11+) |
| Bulk Compression MPPC    | Yes     | Yes     | Yes     | Yes     | Yes     | Yes          |
| Bulk Compression NCRUSH  | -       | Yes     | Yes     | Yes     | Yes     | Yes          |
| Bulk Compression XCRUSH  | -       | Yes     | Yes     | Yes     | Yes     | Yes          |
| ZGFX Compression         | -       | -       | -       | Yes     | Yes     | Yes          |

### 18.4 Platform Support Matrix

| Platform         | Client  | Server | WASM | Native Clipboard    | Native Audio        | Native FS  |
| ---------------- | ------- | ------ | ---- | ------------------- | ------------------- | ---------- |
| Windows x86_64   | Yes     | Yes    | N/A  | Win32 Clipboard API | WASAPI              | NTFS/Win32 |
| Windows aarch64  | Yes     | Yes    | N/A  | Win32 Clipboard API | WASAPI              | NTFS/Win32 |
| Linux x86_64     | Yes     | Yes    | N/A  | X11/Wayland         | PulseAudio/PipeWire | POSIX      |
| Linux aarch64    | Yes     | Yes    | N/A  | X11/Wayland         | PulseAudio/PipeWire | POSIX      |
| macOS x86_64     | Yes     | Yes    | N/A  | NSPasteboard        | CoreAudio           | POSIX      |
| macOS aarch64    | Yes     | Yes    | N/A  | NSPasteboard        | CoreAudio           | POSIX      |
| wasm32 (browser) | Yes     | No     | Yes  | Clipboard API       | Web Audio           | N/A        |
| FreeBSD x86_64   | Yes     | Yes    | N/A  | X11                 | OSS/sndio           | POSIX      |
| Android aarch64  | Planned | No     | N/A  | Android Clipboard   | AudioTrack          | SAF        |
| iOS aarch64      | Planned | No     | N/A  | UIPasteboard        | AVAudioEngine       | N/A        |

---

## 19. Crate Dependency Graph

```
justrdp-core (foundation, no deps)
  │
  ├──▸ justrdp-pdu (depends on: core)
  │     │
  │     ├──▸ justrdp-connector (depends on: core, pdu)
  │     │     │
  │     │     └──▸ justrdp-async (depends on: core, pdu, connector)
  │     │           ├──▸ justrdp-tokio (depends on: async + tokio)
  │     │           ├──▸ justrdp-futures (depends on: async + futures)
  │     │           └──▸ justrdp-blocking (depends on: core, pdu, connector)
  │     │
  │     ├──▸ justrdp-svc (depends on: core, pdu)
  │     │     │
  │     │     ├──▸ justrdp-dvc (depends on: core, pdu, svc)
  │     │     │     │
  │     │     │     ├──▸ justrdp-egfx (depends on: core, pdu, dvc)
  │     │     │     ├──▸ justrdp-displaycontrol (depends on: core, pdu, dvc)
  │     │     │     ├──▸ justrdp-rdpeai (depends on: core, pdu, dvc)
  │     │     │     └──▸ justrdp-echo (depends on: core, pdu, dvc)
  │     │     │
  │     │     ├──▸ justrdp-cliprdr (depends on: core, pdu, svc)
  │     │     │     └──▸ justrdp-cliprdr-native (depends on: cliprdr + platform APIs)
  │     │     │
  │     │     ├──▸ justrdp-rdpdr (depends on: core, pdu, svc)
  │     │     │     └──▸ justrdp-rdpdr-native (depends on: rdpdr + platform APIs)
  │     │     │
  │     │     ├──▸ justrdp-rdpsnd (depends on: core, pdu, svc)
  │     │     │     └──▸ justrdp-rdpsnd-native (depends on: rdpsnd + platform APIs)
  │     │     │
  │     │     └──▸ justrdp-rail (depends on: core, pdu, svc)
  │     │
  │     └──▸ justrdp-session (depends on: core, pdu, svc, dvc, graphics)
  │
  ├──▸ justrdp-graphics (depends on: core)
  │
  ├──▸ justrdp-bulk (depends on: core)
  │
  ├──▸ justrdp-input (depends on: core, pdu)
  │
  └──▸ justrdp-tls (depends on: rustls or native-tls)

justrdp-acceptor (depends on: core, pdu, connector-patterns)
  └──▸ justrdp-server (depends on: acceptor, session, svc, dvc, graphics)

justrdp (meta-crate, re-exports everything via feature flags)

justrdp-client (binary, depends on: justrdp + tokio + winit + wgpu)
justrdp-web (wasm, depends on: justrdp + wasm-bindgen)
justrdp-ffi (cdylib, depends on: justrdp)
justrdp-gateway (binary, depends on: justrdp + hyper/axum)
justrdp-proxy (binary, depends on: justrdp + tokio)
```

### Build Order (Critical Path)

```
Level 0: justrdp-core
Level 1: justrdp-pdu, justrdp-graphics, justrdp-bulk  (parallel)
Level 2: justrdp-svc, justrdp-input, justrdp-connector  (parallel)
Level 3: justrdp-dvc, justrdp-cliprdr, justrdp-rdpdr, justrdp-rdpsnd, justrdp-rail  (parallel)
Level 4: justrdp-egfx, justrdp-displaycontrol, justrdp-rdpeai, justrdp-echo  (parallel)
Level 5: justrdp-session, justrdp-tls  (parallel)
Level 6: justrdp-blocking  (wraps connector + session + tls with std::net)
Level 7: justrdp-acceptor, justrdp (meta)  (parallel)
Level 8: justrdp-server, justrdp-client, justrdp-web, justrdp-ffi  (parallel)
```

---

## 20. Definition of Done (per Phase)

### Phase 1 -- Foundation

- [x] `justrdp-core`: `Encode`/`Decode` trait 구현 및 100% 단위 테스트
- [x] `justrdp-pdu`: 모든 TPKT/X.224/MCS/GCC PDU roundtrip 테스트 통과
- [x] `justrdp-pdu`: 30종 Capability Set 인코딩/디코딩 통과
- [x] `justrdp-pdu`: Fast-Path 입출력 PDU roundtrip 테스트 통과
- [ ] `cargo fuzz` 최소 1시간 무크래시 (PDU 디코더 대상) — §14.3 인프라 미구축
- [x] `#![no_std]` 빌드 성공 (core, pdu)
- [ ] CI: Linux/Windows/macOS, x86_64/aarch64 빌드 통과
- [x] 문서: 모든 public API에 `///` doc comment

### Phase 2 -- Connection

**Phase 2 acceptance criteria — all actionable items complete.** Server
compatibility is tracked in §18.1, performance targets in §15,
security requirements and the external CredSSP review in §17.2,
and fuzzing exit criteria in §14.3.5. Nothing here should duplicate
those pointers.

- [x] CredSSP/NLA 핸드셰이크 성공 (Windows Server, NTLM v6)
- [x] NTLM MIC 버그 수정 후 MIC 활성화 상태로 접속 성공 (§5.2.2, CVE-2019-1040)
- [x] BasicSettingsExchange → Connection Finalization 전체 시퀀스 → `Connected` 도달
- [x] 실서버 manual E2E: Windows Server 2019 at `192.168.136.136`
      — 양방향 활성 세션 (§5.5 `connect_test` 예제)
- [x] 자동화된 연결 통합 테스트 (`justrdp-blocking` + xrdp Docker 컨테이너)
      — `.github/workflows/e2e-xrdp.yml` 수동/주간 트리거. 첫 런
      결과가 §18.1 compatibility matrix 의 "xrdp" 행을 채운다.
- [x] `justrdp-blocking::RdpClient` API 안정화 (§5.5 참조, M1~M7 완료)
- [x] `ServerCertVerifier` trait 구현 및 기본 구현체 제공 (§5.4)
- [x] 연결 타임아웃 `Config::connect_timeout` (기본 30s, non-zero 강제)
- [x] 관찰성: `tracing` feature 로 연결 단계별 이벤트 (§5.5.1)
- [x] `.rdp` 파일 로딩: `Config::from_rdp_file` glue (§5.5.1)
- [x] `ErrorInfoCode` enum + retryable 분류 수정 (§4.2.4)

> Windows 10/11 manual validation, Standard RDP Security (RC4) 레거시
> 호환성, 연결 시간 < 2s 측정, CredSSP 외부 보안 리뷰, `cargo fuzz`
> 4시간 무크래시 — 이 5개는 외부 환경/벤치 하네스/감사 일정/fuzz
> 인프라에 의존하므로 Phase 2 체크박스가 아니라 해당 섹션이
> 책임진다. §18.1 / §15 / §17.2 / §14.3.5 참조.

### Phase 3 -- Standalone Codecs & Primitives

- [x] RLE / Planar / NSCodec / ClearCodec / RFX 디코더 정확성 검증 (참조 이미지 비교)
- [x] ZGFX 압축/해제 정확성
- [ ] ZGFX 압축/해제 throughput > 300 MB/s (벤치 미측정)
- [x] 포인터/커서 렌더링 정확성
- [ ] `cargo fuzz` 최소 8시간 무크래시 (코덱 디코더 대상) — §14.3 인프라 미구축
- [ ] 코덱 벤치마크 기준선 설정 (`criterion`)
- [x] `justrdp-input` 입력 이벤트 관리 (scancode/unicode/mouse/sync)
- [x] `.rdp` 파일 파서 (`justrdp-rdpfile`)

### Phase 4 -- Session Core & Channel Frameworks

- [x] `ActiveStage` 프레임 처리 (GraphicsUpdate + Pointer + ChannelData 라우팅)
- [x] Fast-path/slow-path 자동 분기 (`TpktHint`)
- [x] EGFX 파이프라인 (v8.0 ~ v10.x) 동작 확인 (Windows RDS manual)
- [x] SVC 프레임워크 (`SvcProcessor`, `StaticChannelSet`)
- [x] DVC 프레임워크 (`DvcProcessor`, `DrdynvcClient`)
- [ ] `ActiveStage` 프레임 처리 레이턴시 < 10ms (1080p) — 벤치 미측정

### Phase 5 -- Channel Implementations

- [x] 클립보드(CLIPRDR): PDU 레이어 + 네이티브 백엔드 (Windows/Linux/macOS)
- [x] 드라이브(RDPDR): FileSystem 리다이렉션
- [x] 오디오 출력(RDPSND): PCM + 네이티브 백엔드
- [x] 오디오 입력(RDPEAI): 네이티브 마이크 백엔드
- [x] 디스플레이 제어(RDPEDISP): 해상도 자동 조정
- [x] RemoteApp(RAIL): 단일 앱 실행 + 윈도우 관리
- [x] EGFX(RDPEGFX): 서버 GFX 수신 파이프라인
- [x] 모든 채널의 초기화/종료 시퀀스 정상 동작
- [ ] Windows ↔ 클라이언트 E2E: 클립보드 텍스트/이미지/파일 양방향 복사 (manual만 검증)
- [ ] 채널 보안 리뷰 완료 (RDPDR 파일 접근 범위, CLIPRDR 데이터 유출 방지)

### Phase 6 -- Advanced Features & Integration

- [x] 멀티모니터: 2개 이상 모니터에서 올바른 좌표/렌더링
- [x] 자동 재연결: 네트워크 끊김 후 세션 복구 (§9.2, `test_drop_transport` 420ms 검증)
- [x] 세션 리다이렉션: LB cookie/TARGET_NET_ADDRESS 파싱 + 자동 재연결 (§9.3)
- [x] Touch/Pen/USB/Smartcard/Camera/Video/Geometry/DesktopComposition/Multiparty/PnP 확장 채널 (§9.4~§9.14)
- [ ] 각 추가 기능의 실서버 E2E (Windows RDS 양방향 검증은 §9.4, §9.8, §9.14 일부만 manual 완료)

### Phase 7 -- Transport Extensions

- [ ] UDP reliable: TCP 대비 레이턴시 개선 측정 가능
- [ ] UDP lossy: 오디오/비디오 스트림 정상 전송
- [ ] RD Gateway: HTTP/WebSocket 전송을 통한 연결 성공
- [ ] Multitransport: TCP+UDP 동시 전송, DVC 라우팅 정상

### Phase 8 -- Server-Side & Ecosystem

- [ ] mstsc.exe (Windows 내장 클라이언트)에서 JustRDP 서버 연결 성공
- [ ] FreeRDP(xfreerdp)에서 JustRDP 서버 연결 성공
- [ ] 서버 → 클라이언트 그래픽 전송 (RFX 인코딩)
- [ ] 클라이언트 → 서버 입력 수신 및 처리
- [ ] 멀티세션 동시 접속
- [ ] WASM 빌드 및 브라우저에서 RDP 연결 성공
- [ ] C FFI: 외부 C 프로그램에서 JustRDP 호출 성공
- [ ] Python 바인딩: `pip install justrdp` 후 스크립팅 사용 가능
- [ ] 레퍼런스 클라이언트: GUI RDP 클라이언트 기본 기능 동작

---

## Appendix B: Error & Disconnect Code Reference

> `SetErrorInfoPdu`로 전송되는 disconnect reason 코드. MS-RDPBCGR §2.2.5.1.1
> 기준으로 전사. 구현은 `justrdp-pdu::rdp::error_info::ErrorInfoCode` 및
> §4.2.4 RDP Core PDUs 참조.

### B.1 Protocol-Independent Codes (`ErrorInfoCategory::ProtocolIndependent`)

| Code       | Name                                          | Description                     |
| ---------- | --------------------------------------------- | ------------------------------- |
| 0x00000000 | ERRINFO_NONE                                  | 에러 없음 (무시)                |
| 0x00000001 | ERRINFO_RPC_INITIATED_DISCONNECT              | 다른 세션의 관리자가 끊음       |
| 0x00000002 | ERRINFO_RPC_INITIATED_LOGOFF                  | 강제 로그오프                   |
| 0x00000003 | ERRINFO_IDLE_TIMEOUT                          | 유휴 타임아웃                   |
| 0x00000004 | ERRINFO_LOGON_TIMEOUT                         | 로그온 세션 타임아웃            |
| 0x00000005 | ERRINFO_DISCONNECTED_BY_OTHERCONNECTION       | 다른 연결에 의해 밀려남         |
| 0x00000006 | ERRINFO_OUT_OF_MEMORY                         | 서버 메모리 부족                |
| 0x00000007 | ERRINFO_SERVER_DENIED_CONNECTION              | 서버가 연결 거부                |
| 0x00000009 | ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES        | 접근 권한 부족                  |
| 0x0000000A | ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED     | 저장된 자격증명 거부, 재입력    |
| 0x0000000B | ERRINFO_RPC_INITIATED_DISCONNECT_BYUSER       | 해당 세션의 관리자가 끊음       |
| 0x0000000C | ERRINFO_LOGOFF_BY_USER                        | 사용자 로그오프                 |
| 0x0000000F | ERRINFO_CLOSE_STACK_ON_DRIVER_NOT_READY       | 디스플레이 드라이버 미준비      |
| 0x00000010 | ERRINFO_SERVER_DWM_CRASH                      | 원격 DWM 프로세스 비정상 종료   |
| 0x00000011 | ERRINFO_CLOSE_STACK_ON_DRIVER_FAILURE         | 드라이버 초기화 실패            |
| 0x00000012 | ERRINFO_CLOSE_STACK_ON_DRIVER_IFACE_FAILURE   | 드라이버 인터페이스 실패        |
| 0x00000017 | ERRINFO_SERVER_WINLOGON_CRASH                 | 원격 Winlogon 비정상 종료       |
| 0x00000018 | ERRINFO_SERVER_CSRSS_CRASH                    | 원격 CSRSS 비정상 종료          |
| 0x00000019 | ERRINFO_SERVER_SHUTDOWN                       | 서버 셧다운 중                  |
| 0x0000001A | ERRINFO_SERVER_REBOOT                         | 서버 재부팅 중                  |

### B.2 Licensing Codes (`ErrorInfoCategory::Licensing`)

| Code       | Name                                        | Description                       |
| ---------- | ------------------------------------------- | --------------------------------- |
| 0x00000100 | ERRINFO_LICENSE_INTERNAL                    | 라이선스 컴포넌트 내부 오류       |
| 0x00000101 | ERRINFO_LICENSE_NO_LICENSE_SERVER           | 라이선스 서버 없음                |
| 0x00000102 | ERRINFO_LICENSE_NO_LICENSE                  | CAL 없음                          |
| 0x00000103 | ERRINFO_LICENSE_BAD_CLIENT_MSG              | 잘못된 클라이언트 라이선스 메시지 |
| 0x00000104 | ERRINFO_LICENSE_HWID_DOESNT_MATCH_LICENSE   | 저장 라이선스 변조 (HWID 불일치)  |
| 0x00000105 | ERRINFO_LICENSE_BAD_CLIENT_LICENSE          | 저장 라이선스 포맷 오류           |
| 0x00000106 | ERRINFO_LICENSE_CANT_FINISH_PROTOCOL        | 라이선스 프로토콜 중단            |
| 0x00000107 | ERRINFO_LICENSE_CLIENT_ENDED_PROTOCOL       | 클라이언트가 프로토콜 조기 종료   |
| 0x00000108 | ERRINFO_LICENSE_BAD_CLIENT_ENCRYPTION       | 라이선스 메시지 암호화 오류       |
| 0x00000109 | ERRINFO_LICENSE_CANT_UPGRADE_LICENSE        | 라이선스 업그레이드 불가          |
| 0x0000010A | ERRINFO_LICENSE_NO_REMOTE_CONNECTIONS       | 원격 연결 허용 안됨               |

### B.3 Connection Broker Codes (`ErrorInfoCategory::ConnectionBroker`)

| Code       | Name                                          | Description               |
| ---------- | --------------------------------------------- | ------------------------- |
| 0x00000400 | ERRINFO_CB_DESTINATION_NOT_FOUND              | 대상 endpoint 없음        |
| 0x00000402 | ERRINFO_CB_LOADING_DESTINATION                | 대상이 브로커에서 분리 중 |
| 0x00000404 | ERRINFO_CB_REDIRECTING_TO_DESTINATION         | 리다이렉트 중 오류        |
| 0x00000405 | ERRINFO_CB_SESSION_ONLINE_VM_WAKE             | 대상 VM 깨우기 실패       |
| 0x00000406 | ERRINFO_CB_SESSION_ONLINE_VM_BOOT             | 대상 VM 부팅 실패         |
| 0x00000407 | ERRINFO_CB_SESSION_ONLINE_VM_NO_DNS           | 대상 VM IP 미확인         |
| 0x00000408 | ERRINFO_CB_DESTINATION_POOL_NOT_FREE          | 풀에 가용 endpoint 없음   |
| 0x00000409 | ERRINFO_CB_CONNECTION_CANCELLED               | 연결 처리 취소            |
| 0x00000410 | ERRINFO_CB_CONNECTION_ERROR_INVALID_SETTINGS  | routingToken 검증 실패    |
| 0x00000411 | ERRINFO_CB_SESSION_ONLINE_VM_BOOT_TIMEOUT     | 대상 VM 부팅 타임아웃     |
| 0x00000412 | ERRINFO_CB_SESSION_ONLINE_VM_SESSMON_FAILED   | VM 세션 모니터링 실패     |

### B.4 RDP Internal Protocol Errors (`ErrorInfoCategory::RdpProtocol`)

> 0x000010C9..=0x00001195 범위의 ~80개 내부 프로토콜 오류 (UnknownPduType,
> SequenceError, Capability/Bitmap/Mouse/Input 파싱 실패, Security header
> 부족, Decrypt 실패 등). 진단용으로만 의미가 있어 열거하지 않고
> `ErrorInfoCode::RdpProtocol(u32)` 한 variant로 랩핑한다. 전체 목록은
> MS-RDPBCGR §2.2.5.1.1 참조.

### B.5 Security Negotiation Failure Codes

| Code   | Name                        | Description            |
| ------ | --------------------------- | ---------------------- |
| 0x0001 | SSL_REQUIRED_BY_SERVER      | 서버가 TLS 필수        |
| 0x0002 | SSL_NOT_ALLOWED_BY_SERVER   | 서버가 TLS 불허        |
| 0x0003 | SSL_CERT_NOT_ON_SERVER      | 서버 인증서 없음       |
| 0x0004 | INCONSISTENT_FLAGS          | 비일관적 플래그        |
| 0x0005 | HYBRID_REQUIRED_BY_SERVER   | 서버가 NLA 필수        |
| 0x0006 | SSL_WITH_USER_AUTH_REQUIRED | TLS + 사용자 인증 필수 |

---

## Appendix C: Glossary

| Term          | Definition                                                                    |
| ------------- | ----------------------------------------------------------------------------- |
| **TPKT**      | Transport Protocol (RFC 1006), 4바이트 헤더로 TCP 위에 ISO transport 프레이밍 |
| **X.224**     | ISO 8073 Transport Protocol Class 0, 연결 요청/확인/데이터 전송               |
| **MCS**       | Multipoint Communication Service (T.125), 채널 기반 데이터 라우팅             |
| **GCC**       | Generic Conference Control (T.124), 회의 생성 시 설정 교환                    |
| **PDU**       | Protocol Data Unit, 프로토콜 메시지의 기본 단위                               |
| **SVC**       | Static Virtual Channel, 연결 시 생성되는 고정 채널 (최대 31개)                |
| **DVC**       | Dynamic Virtual Channel, 세션 중 동적으로 생성/삭제되는 채널                  |
| **NLA**       | Network Level Authentication, 연결 전 사용자 인증 (CredSSP 기반)              |
| **CredSSP**   | Credential Security Support Provider, TLS + SPNEGO + 자격증명 위임            |
| **SPNEGO**    | Simple and Protected GSSAPI Negotiation, NTLM/Kerberos 자동 선택              |
| **Fast-Path** | 헤더 압축된 빠른 데이터 경로 (Slow-Path X.224+MCS 우회)                       |
| **RFX**       | RemoteFX, DWT 기반 손실 이미지 코덱 (64x64 타일)                              |
| **EGFX**      | Enhanced Graphics Pipeline (MS-RDPEGFX), 모던 그래픽 채널                     |
| **ZGFX**      | RDP8 Bulk Compression, EGFX 데이터용 압축                                     |
| **RDPDR**     | Remote Desktop Protocol Device Redirection                                    |
| **CLIPRDR**   | Clipboard Redirection                                                         |
| **RDPSND**    | Remote Desktop Protocol Sound                                                 |
| **RAIL**      | Remote Applications Integrated Locally (RemoteApp)                            |
| **DRDYNVC**   | Dynamic Virtual Channel multiplexer (SVC 위에서 DVC를 호스트)                 |
| **IRP**       | I/O Request Packet, RDPDR에서 파일 작업 요청 단위                             |
| **PCB**       | Pre-Connection Blob, 로드밸런서용 사전 연결 데이터                            |
| **ARC**       | Auto-Reconnect Cookie, 재연결 시 세션 식별                                    |

---

## Appendix D: Microsoft Documentation URLs

| Spec                | URL                                                                 |
| ------------------- | ------------------------------------------------------------------- |
| MS-RDPBCGR          | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr`  |
| MS-RDPEGFX          | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx`  |
| MS-RDPEFS           | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs`   |
| MS-RDPECLIP         | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeclip` |
| MS-RDPEA            | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpea`    |
| MS-RDPEAI           | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeai`   |
| MS-RDPEDISP         | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedisp` |
| MS-RDPEDYC          | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc`  |
| MS-RDPERP           | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdperp`   |
| MS-RDPEUDP          | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp`  |
| MS-RDPEMT           | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpemt`   |
| MS-TSGU             | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu`     |
| MS-CSSP             | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp`     |
| MS-NLMP             | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp`     |
| MS-RDPELE           | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele`   |
| MS-RDPEGDI          | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegdi`  |
| MS-RDPRFX           | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdprfx`   |
| MS-RDPEI            | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpei`    |
| MS-RDPEUSB          | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeusb`  |
| MS-RDSOD (Overview) | `learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdsod`    |

---

## Appendix E: Milestone Summary

```
Phase 1 ▸ Foundation         justrdp-core, justrdp-pdu, justrdp-bulk
                             TPKT, X.224, MCS, GCC, PCB, Capabilities, Fast-Path, Drawing Orders
Phase 2 ▸ Connection         justrdp-connector, justrdp-tls, justrdp-blocking
                             CredSSP, NTLM, Kerberos, SPNEGO, Standard RDP Security
                             Remote Credential Guard, Restricted Admin, Azure AD
                             Synchronous runtime (TCP/TLS pump, RdpClient API)
Phase 3 ▸ Standalone Codecs  justrdp-graphics, justrdp-bulk, justrdp-input, justrdp-rdpfile
                             RLE, Planar, RFX, NSCodec, ClearCodec, H.264, ZGFX
                             Input events, .rdp file parsing
Phase 4 ▸ Session Core       justrdp-session, justrdp-svc, justrdp-dvc, justrdp-egfx
                             ActiveStage, fast/slow-path dispatch, SVC/DVC frameworks
Phase 5 ▸ Channels           cliprdr, rdpdr, rdpsnd, rdpeai, displaycontrol, rail, egfx
                             Native backends (Windows/Linux/macOS)
Phase 6 ▸ Advanced           Multi-monitor, auto-reconnect, session redirection
                             USB, touch, pen, camera, smartcard
                             Video (RDPEVOR/RDPEV), geometry, desktop composition
                             Multiparty, PnP device redirection
                             (MS-RDPELE full exchange + license persistence: Appendix G.1 deferred)
Phase 7 ▸ Transport          justrdp-rdpeudp, justrdp-rdpemt, justrdp-gateway (MS-TSGU)
                             UDP reliable/lossy, DTLS, multitransport, WebSocket
Phase 8 ▸ Server+Ecosystem   justrdp-acceptor, justrdp-server
                             Server-side GFX encoding, multi-session, shadow
                             justrdp-web (WASM), justrdp-ffi (C/Python)
                             justrdp-client (GUI), justrdp-gateway, justrdp-proxy
```

## Appendix F: Competitive Comparison

| Feature                 | JustRDP (Goal)   | IronRDP         | FreeRDP         |
| ----------------------- | ---------------- | --------------- | --------------- |
| Language                | Rust             | Rust            | C               |
| `no_std` core           | Yes              | Yes             | N/A             |
| WASM support            | Yes              | Yes             | No              |
| Server support          | Yes              | Community       | No              |
| Gateway support         | Yes              | Devolutions ext | Yes             |
| H.264                   | Pure Rust (goal) | External        | FFmpeg/OpenH264 |
| NTLM/Kerberos           | Pure Rust        | `sspi` crate    | Built-in C      |
| USB redirection         | Yes              | Yes             | Yes             |
| Audio I/O               | Yes              | Yes             | Yes             |
| RemoteApp (RAIL)        | Yes              | No              | Yes             |
| UDP transport           | Yes              | No              | Yes             |
| Touch/Pen               | Yes              | No              | Yes             |
| Camera                  | Yes              | No              | Yes             |
| Clipboard (file)        | Yes              | Yes             | Yes             |
| Drive redirection       | Yes              | Yes             | Yes             |
| Remote Credential Guard | Yes              | No              | Yes             |
| Restricted Admin        | Yes              | No              | Yes             |
| Desktop Composition     | Yes              | No              | Yes             |
| Shadow Session          | Yes              | No              | Yes             |
| License                 | MIT/Apache-2.0   | MIT/Apache-2.0  | Apache-2.0      |

---

## Appendix G: Deferred / Backlog

> Work items that are **deliberately not scheduled** against any
> active phase because (a) they depend on a prerequisite that is
> itself deferred, (b) the real-world demand does not justify the
> cost, or (c) the right time to pick them up is contingent on an
> external decision (licensing model, server-side rollout, etc.).
>
> Items here are tracked so future-us knows why the gap exists,
> not as a backlog that will be worked through in order. Moving an
> item out of this appendix requires an explicit decision to
> adopt it into a phase — it is not automatic.

### G.1 MS-RDPELE Full Licensing & Persistence

> **Why deferred**: modern NLA/TLS deployments have the server
> skip licensing with a single `STATUS_VALID_CLIENT` error, so
> JustRDP's existing §5.1 `LicenseExchangeSequence` shortcut is
> sufficient for the common case. The full MS-RDPELE §2.2.2.3+
> exchange only matters for per-device CAL + legacy license-server
> topologies, which are a small and shrinking minority of the
> deployments we target.
>
> **Why it cannot be split**: persistence (load/save a license
> blob) and the full exchange are useless without each other —
> without the full exchange there is no blob to save, and without
> persistence the full exchange re-runs every connect. Any future
> work must land both axes together or neither.
>
> **Origin**: previously §5.6 inside Phase 2 (and before that,
> §9.15 inside Phase 6). Moved here in commit `<next>` because
> leaving it inside an active phase gave the wrong impression
> that the unchecked boxes were still on the critical path.
> Cross-references in §5.1, §5.5, and §13.1 all point here.

**축 1 — MS-RDPELE 전체 교환 구현 (`justrdp-pdu` + `justrdp-connector`):**

- [ ] `ClientNewLicenseRequest` (§2.2.2.2) 인코더
  - [ ] `PreferredKeyExchangeAlg` (`KEY_EXCHANGE_ALG_RSA = 0x00000001`)
  - [ ] `PlatformId`
  - [ ] `ClientRandom` (32 bytes)
  - [ ] `EncryptedPreMasterSecret` (RSA PKCS#1 v1.5, `justrdp-core::rsa`)
  - [ ] `ClientUserName` / `ClientMachineName` BLOBs
- [ ] `ClientPlatformChallengeResponse` (§2.2.2.5) 인코더
  - [ ] MAC salt 키 파생 (§5.1.3)
  - [ ] RC4 세션 키 파생
  - [ ] `EncryptedPlatformChallengeResponse` + `EncryptedHWID` + MAC
- [ ] `ClientLicenseInfo` (§2.2.2.3) 인코더 — 저장된 라이선스 재제시 경로
- [ ] `PlatformChallenge` (§2.2.2.4) / `NewLicense` (§2.2.2.6) /
      `UpgradeLicense` (§2.2.2.7) 구조체 디코더 (현재는 `LicenseGenericPdu`
      블롭으로만 파싱)
- [ ] `step_licensing_exchange()` FSM 재작성
  - [ ] 현재의 "거절" 경로를 feature-flag 뒤로 이동
  - [ ] `LicenseRequest → ClientNewLicenseRequest/ClientLicenseInfo →
        PlatformChallenge → ClientPlatformChallengeResponse →
        NewLicense/UpgradeLicense` 풀 라운드트립
  - [ ] `ClientHardwareId` 20바이트 산정 (Config 빌더로 고정 or
        hostname+salt 해시 기본값)

**축 2 — 영속화 레이어:**

- [ ] `LicenseStore` trait (`justrdp-connector`)
  ```rust
  pub trait LicenseStore: Send + Sync {
      fn load(&self, server_hostname: &str, hwid: &[u8; 20]) -> Option<Vec<u8>>;
      fn save(&self, server_hostname: &str, hwid: &[u8; 20], license_blob: &[u8]);
  }
  ```
- [ ] `NoopLicenseStore` 기본값
- [ ] `ConfigBuilder::license_store()` / `server_hostname()` 빌더 메서드
- [ ] 축 1의 FSM에서 진입 시 `store.load()` → `ClientLicenseInfo` 경로,
      `NewLicense`/`UpgradeLicense` 수신 시 `store.save()`
- [ ] `FileLicenseStore` (`justrdp-blocking` §5.5) — `~/.justrdp/licenses/{server_hash}_{hwid_hex}.bin`
  - [ ] `server_hostname` 의 path traversal 방지를 위한 해시/인코딩
  - [ ] 디렉터리 권한 (Unix 0700 / Windows ACL)
  - [ ] 손상 파일 감지 + 재발급 폴백

**검증:**

- [ ] 풀 교환 wire 트레이스 (MS-RDPELE §4) 바이트 단위 일치
- [ ] RSA/RC4/MAC 테스트 벡터
- [ ] 라이선스 발급 → 저장 → 재연결 시 로드 → `STATUS_VALID_CLIENT` 수신
      end-to-end 통합 테스트

---

### G.2 Standard RDP Security Server-Side Stack (`§11.2a-stdsec`)

> **Why deferred**: §11.2a 는 의도적으로 `ServerAcceptor` 의 `SC_SECURITY`
> 블록을 항상 `encryption_method=0/level=0` (no encryption) 으로 emit
> 하도록 stub 처리했음. 모든 모던 RDP 배포는 TLS/CredSSP 를 사용하므로
> Standard RDP Security (PROTOCOL_RDP, RC4 + MAC) 는 legacy interop 외에는
> 가치가 적음. `justrdp-pdu/src/rdp/standard_security.rs` 의 클라이언트
> 측 RC4/MAC 코드는 이미 완성됐고 테스트 벡터도 있음 -- 빠진 건 acceptor
> 측의 RSA 인증서 발급 + `SecurityExchange PDU` 디코드 + 송수신 path 의
> wrap/unwrap 통합뿐.
>
> **Why it cannot be split**: RSA 인증서 → 클라이언트 랜덤 → 세션 키
> 파생 → MAC/RC4 wrap 4단계가 한 핸드셰이크 안에서 모두 살아있어야
> 검증 가능. 어느 한 단계만 떼서 commit 하면 회귀 잡을 길이 없음.
>
> **언제 진가가 살아나는가**: §11.2d 통합 테스트가 "TCP loopback +
> Standard RDP Security 풀 핸드셰이크" 변형을 추가할 수 있게 됨 (현재
> §11.2d 는 `NoopTlsUpgrader` 어댑터로 TLS 만 우회한 형태). 또한 `xrdp`
> 같은 PROTOCOL_RDP-only 클라이언트와의 인터롭이 가능해짐.

**작업 항목 (3 commit 추정):**

- [ ] **S1 -- RSA 인증서 발급**: `ServerAcceptor` 에 `RdpSecurityContext`
      필드 추가. `justrdp-pdu` 의 `ServerRsaPublicKey` / `ProprietaryCertificate`
      구조를 사용해서 connection 별 RSA 키쌍 + 자체 서명 인증서 생성.
      `MCS Connect Response` 의 `SC_SECURITY` 에 `serverRandom` (32B) +
      `serverCertificate` 첨부.
- [ ] **S2 -- SecurityExchange PDU 서버 디코드**: 클라이언트가 보내는
      `Security Exchange PDU` (TPKT 위에서) 를 받아 `EncryptedClientRandom`
      을 RSA 복호화 → `clientRandom` 회수. `derive_session_keys` 호출로
      master / session / sign / encrypt / decrypt 키 파생. `RdpSecurityContext`
      에 키 저장.
- [ ] **S3 -- ActiveStage 송수신 wrap/unwrap**: `ServerActiveStage` 가 모든
      slow-path 송신을 `encrypt_packet()` + MAC 으로 감싸도록, 모든
      slow-path 수신을 `decrypt_packet()` + MAC 검증으로 풀도록 통합.
      Fast-path 도 `FASTPATH_*_ENCRYPTED` 플래그 설정 시 동일 처리.
      Key update (4096B 마다) 트리거.

**검증:**

- [ ] 클라이언트가 보낸 `EncryptedClientRandom` 을 서버가 풀어 동일한
      `clientRandom` 추출 (round-trip wire 트레이스).
- [ ] 양쪽 파생 세션 키가 byte-identical.
- [ ] `ConfirmActive` PDU 가 서버 `decrypt_packet()` 통과.
- [ ] §11.2d 에 "TCP loopback + Standard RDP Security" 변형 통합 테스트
      추가 → 풀 wire-level 검증.
