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
21. [Error & Disconnect Code Reference](#21-error--disconnect-code-reference)

---

## 1. Vision & Design Principles

### Vision

JustRDP는 Rust 생태계에서 RDP 프로토콜의 **표준 구현체**가 되는 것을 목표로 한다. 어떤 Rust 개발자든 RDP 클라이언트, 서버, 프록시, 게이트웨이를 만들 때 JustRDP를 가져다 쓰면 된다.

### Design Principles

| Principle                 | Description                                                                        |
| ------------------------- | ---------------------------------------------------------------------------------- |
| **Zero C deps**           | 순수 Rust. `libc`, `openssl`, `freerdp` 등 C 라이브러리 의존 없음.                 |
| **`no_std` core**         | 핵심 PDU/코덱/상태머신은 `no_std` + `alloc`으로 동작. embedded/WASM 지원.          |
| **No I/O in core**        | 코어 크레이트는 네트워크/파일 I/O를 직접 수행하지 않음. 호출자가 I/O를 drive.      |
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
| `justrdp-connector`      | 연결 상태 머신                     | `ClientConnector`, `ClientConnectorState`, `Sequence`, `Config`, `CredsspSequence`                         |
| `justrdp-session`        | 활성 세션 처리                     | `ActiveStage`, `ActiveStageOutput`, `FastPathProcessor`, `X224Processor`                                   |
| `justrdp-input`          | 입력 이벤트 관리                   | `InputDatabase`, `Operation`, `Scancode`, `FastPathInputEvent`                                             |
| `justrdp-cliprdr`        | 클립보드 채널                      | `Cliprdr<Role>`, `CliprdrBackend`, `FormatList`, `FormatDataRequest`                                       |
| `justrdp-rdpdr`          | 디바이스 리다이렉션                | `Rdpdr`, `RdpdrBackend`, `DeviceIoRequest`, `DeviceIoResponse`                                             |
| `justrdp-rdpsnd`         | 오디오 출력                        | `RdpsndClient`, `RdpsndServer`, `AudioFormat`, `WaveData`                                                  |
| `justrdp-rdpeai`         | 오디오 입력                        | `AudioInputClient`, `AudioInputServer`                                                                     |
| `justrdp-egfx`           | 그래픽스 파이프라인                | `GfxClient`, `GfxServer`, `GfxHandler`, `Surface`, `FrameAck`                                              |
| `justrdp-displaycontrol` | 디스플레이 제어                    | `DisplayControlClient`, `MonitorLayout`                                                                    |
| `justrdp-rail`           | RemoteApp                          | `RailClient`, `RailServer`, `ExecRequest`, `WindowOrder`                                                   |

### Extra Tier (I/O, 플랫폼 종속)

| Crate                    | Description                                                   |
| ------------------------ | ------------------------------------------------------------- |
| `justrdp-async`          | Async I/O trait 추상화: `FramedRead`, `FramedWrite`, `Framed` |
| `justrdp-tokio`          | tokio `AsyncRead`/`AsyncWrite` 구현                           |
| `justrdp-futures`        | futures crate 기반 구현                                       |
| `justrdp-blocking`       | 동기 I/O 래퍼                                                 |
| `justrdp-tls`            | TLS 업그레이드 (rustls 기본, native-tls 옵션)                 |
| `justrdp-cliprdr-native` | OS 네이티브 클립보드 백엔드 (Windows/Linux/macOS)             |
| `justrdp-rdpdr-native`   | 네이티브 파일시스템 백엔드                                    |
| `justrdp-rdpsnd-native`  | 네이티브 오디오 출력 백엔드                                   |
| `justrdp-rdpeai-native`  | 네이티브 오디오 입력 백엔드                                   |

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
- [x] `SetErrorInfoPdu` -- 300+ disconnect reason 코드
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
- [x] `LicenseExchangeSequence` -- 라이센스 교환 (Valid Client 단축 경로 포함)
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
- [ ] DVC 전송 모드:
  - [ ] `RdpsndDvcClient` -- `DvcProcessor` 구현 (`AUDIO_PLAYBACK_DVC`)
  - [ ] Lossy DVC 채널 (`AUDIO_PLAYBACK_LOSSY_DVC`) 지원
  - [ ] SVC/DVC 공통 로직 추출 (PDU 처리, 상태 머신 공유)
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

- [ ] 초기화 시퀀스 (Announce → Name → Capability → Device List)
- [ ] 디바이스 타입: Filesystem, Serial, Parallel, Printer, Smartcard
- [ ] IRP (I/O Request Packet) 처리:
  - [ ] IRP_MJ_CREATE / CLOSE / READ / WRITE
  - [ ] IRP_MJ_DEVICE_CONTROL (IOCTL)
  - [ ] IRP_MJ_QUERY_INFORMATION / SET_INFORMATION
  - [ ] IRP_MJ_QUERY_VOLUME_INFORMATION / SET_VOLUME_INFORMATION
  - [ ] IRP_MJ_DIRECTORY_CONTROL (Query / Notify)
  - [ ] IRP_MJ_LOCK_CONTROL
- [ ] 드라이브 리다이렉션 (`with_drives()`, `add_drive()`)
- [ ] 스마트카드 리다이렉션 (`with_smartcard()`, MS-RDPESC)
  - [ ] NDR/RPCE 인코딩
  - [ ] SCard API 래핑
- [ ] 프린터 리다이렉션 (MS-RDPEPC)

### 8.4 `justrdp-displaycontrol` -- Display Control (MS-RDPEDISP)

> **requires**: 7.3 DVC 프레임워크
> **검증**: PDU roundtrip + integration test (동적 리사이즈)

**DVC 이름**: `Microsoft::Windows::RDS::DisplayControl`

**구현 항목:**

- [ ] Capabilities PDU 수신 (최대 모니터 수, 최대 해상도)
- [ ] Monitor Layout PDU 전송:
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
- [ ] 동적 리사이즈
- [ ] 멀티모니터 레이아웃 변경

### 8.5 `justrdp-rdpeai` -- Audio Input (MS-RDPEAI)

> **requires**: 7.3 DVC 프레임워크
> **검증**: PDU roundtrip

**DVC 이름**: `AUDIO_INPUT`

**구현 항목:**

- [ ] 버전 교환
- [ ] 오디오 포맷 협상
- [ ] Open/Close 시퀀스
- [ ] 오디오 캡처 데이터 전송
- [ ] 포맷 변경

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

- [ ] Capability negotiation (v8.0 ~ v10.7)
- [ ] `WireToSurface1` PDU -- 코덱 기반 비트맵 전송
- [ ] `WireToSurface2` PDU -- 컨텍스트 기반 비트맵 전송
- [ ] `DeleteEncodingContext` PDU
- [ ] `SolidFill` PDU
- [ ] `SurfaceToSurface` PDU
- [ ] `SurfaceToCache` / `CacheToSurface` / `EvictCacheEntry` PDU
- [ ] `CacheImportOffer` / `CacheImportReply` PDU
- [ ] `CreateSurface` / `DeleteSurface` PDU
- [ ] `ResetGraphics` PDU
- [ ] `MapSurfaceToOutput` / `MapSurfaceToScaledOutput` PDU
- [ ] `MapSurfaceToWindow` / `MapSurfaceToScaledWindow` PDU (RAIL)
- [ ] `StartFrame` / `EndFrame` PDU
- [ ] `FrameAcknowledge` PDU
- [ ] 코덱 디스패치 (Uncompressed, ClearCodec, Planar, RFX, H.264, Alpha)
- [ ] ZGFX 압축/해제 통합
- [ ] DVC 압축 지원 (DYNVC_DATA_FIRST_COMPRESSED, DYNVC_DATA_COMPRESSED) -- ZGFX-Lite 8KB 윈도우
- [ ] Progressive RFX (단계적 품질 향상, MS-RDPEGFX)

### 8.7 `justrdp-rail` -- RemoteApp (MS-RDPERP)

> **requires**: 7.2 SVC 프레임워크, 8.6 EGFX (`MapSurfaceToWindow` 연동)
> **검증**: PDU roundtrip

**SVC 이름**: `RAIL`

**구현 항목:**

- [ ] RAIL Handshake
- [ ] Client Status PDU
- [ ] Exec Request/Result PDU (원격 앱 실행)
- [ ] System Parameters PDU (양방향)
- [ ] Window Activate/Deactivate PDU
- [ ] System Menu / System Command PDU
- [ ] Notification Icon Event PDU
- [ ] Get AppId Request/Response PDU
- [ ] Language Bar Info PDU
- [ ] Window Cloak PDU
- [ ] Snap Arrange PDU
- [ ] Z-Order Sync PDU
- [ ] Window Information Orders (Alternate Secondary):
  - [ ] New/Existing Window Order
  - [ ] Delete Window Order
  - [ ] Notification Icon Order
- [ ] EGFX 연동: `MapSurfaceToWindow` / `MapSurfaceToScaledWindow`

### 8.8 H.264/AVC Codec

> **requires**: 없음 (순수 디코더), 하지만 8.6 EGFX 연동 시 실질적 테스트 가능
> **검증**: 알려진 NAL 유닛 디코딩, EGFX WireToSurface로 end-to-end 확인

- [ ] AVC420 디코딩 (YUV 4:2:0)
- [ ] AVC444 디코딩 (YUV 4:4:4, 두 AVC420 결합)
- [ ] AVC444v2 디코딩
- [ ] 순수 Rust H.264 디코더 통합 또는 trait 추상화
- [ ] 하드웨어 가속 백엔드 trait

### 8.9 Native Platform Backends

> **requires**: 각 채널 구현 (8.1~8.5)
> **검증**: 각 플랫폼에서 실서버 연결 후 기능 확인

- [ ] `justrdp-cliprdr-native`:
  - [ ] Windows: Win32 Clipboard API 통합
  - [ ] Linux: X11 Selection / Wayland data-device
  - [ ] macOS: NSPasteboard
- [ ] `justrdp-rdpdr-native`:
  - [ ] 네이티브 파일시스템 백엔드
- [ ] `justrdp-rdpsnd-native`:
  - [ ] Windows: WASAPI
  - [ ] Linux: PulseAudio / PipeWire
  - [ ] macOS: CoreAudio
- [ ] `justrdp-rdpeai-native`:
  - [ ] Windows: WASAPI 캡처
  - [ ] Linux: PulseAudio / PipeWire 캡처
  - [ ] macOS: CoreAudio 캡처

---

## 9. Phase 6 -- Advanced Features & Integration

> **목표**: 프로덕션 수준의 완성도. 엔터프라이즈 환경에서 요구하는 기능.
> Phase 4/5의 세션+채널 인프라 위에 구축.

### 9.1 Multi-Monitor Support

> **requires**: 8.6 EGFX (`ResetGraphics`), 8.4 DisplayControl
> **검증**: integration test (다중 모니터 레이아웃 전송 → 서버 응답)

- [ ] Client Monitor Data (GCC) -- 최대 16개 모니터 정의
- [ ] Client Monitor Extended Data -- 물리 크기, DPI, 방향
- [ ] Monitor Layout PDU 수신 (서버 → 클라이언트)
- [ ] EGFX `ResetGraphics` 모니터 매핑
- [ ] 가상 데스크톱 좌표 처리 (음수 좌표 포함)
- [ ] DPI 스케일링

### 9.2 Auto-Reconnect

> **requires**: 7.1 세션 (Save Session Info PDU 수신), Phase 2 커넥터
> **검증**: integration test (연결 끊기 → 자동 재연결)

- [ ] Auto-Reconnect Cookie 저장/복원 (Save Session Info PDU)
- [ ] ARC (Auto-Reconnect Cookie) 랜덤 생성
- [ ] ClientAutoReconnectPacket 전송 (Client Info PDU 내)
- [ ] 네트워크 끊김 감지 및 자동 재연결 시퀀스

### 9.3 Session Redirection

> **requires**: 7.1 세션 (Redirection PDU 수신), Phase 2 커넥터
> **검증**: integration test (로드밸런서 환경)

- [ ] Server Redirection PDU 파싱
- [ ] 리다이렉션 주소/로드밸런싱 정보 추출
- [ ] Routing Token / Cookie 전달
- [ ] 새 연결로의 자동 리다이렉트

### 9.4 Touch Input (MS-RDPEI)

> **requires**: 7.3 DVC 프레임워크
> **검증**: PDU roundtrip

**DVC 이름**: `Microsoft::Windows::RDS::Input`

- [ ] 터치 프레임 PDU
- [ ] 멀티터치 포인트 (최대 256개)
- [ ] 터치 접촉 영역, 방향
- [ ] 터치 이벤트 (down, move, up, cancel)

### 9.5 Pen/Stylus Input (MS-RDPEPS)

> **requires**: 7.3 DVC 프레임워크
> **검증**: PDU roundtrip

**DVC 이름**: `Microsoft::Windows::RDS::Pen`

- [ ] 펜 프레임 PDU
- [ ] 압력, 기울기, 회전 데이터
- [ ] 펜 타입 (펜, 지우개)

### 9.6 Smartcard Authentication (PKINIT)

> **requires**: Phase 2 Kerberos, 8.3 RDPDR 스마트카드 리다이렉션
> **검증**: 스마트카드 로그인 integration test

- [ ] PKCS#11 인터페이스
- [ ] 인증서 기반 Kerberos (PKINIT)
- [ ] 스마트카드 리더 열거
- [ ] PIN 입력 인터페이스

### 9.7 USB Redirection (MS-RDPEUSB)

> **requires**: 7.3 DVC 프레임워크, 8.3 RDPDR
> **검증**: USB 디바이스 열거 integration test

- [ ] USB 디바이스 열거
- [ ] URB (USB Request Block) 포워딩
- [ ] 디바이스 핫플러그 알림
- [ ] USB over RDPDR 전송

### 9.8 Video Optimized Remoting (MS-RDPEVOR)

> **requires**: 7.3 DVC, 8.8 H.264, 9.11 Geometry Tracking
> **검증**: 비디오 스트림 수신 integration test

**DVC 이름**: `Microsoft::Windows::RDS::Video::Control`, `Microsoft::Windows::RDS::Video::Data`

- [ ] 비디오 스트림 생성/삭제
- [ ] 지오메트리 업데이트
- [ ] H.264 비디오 데이터 전송
- [ ] 프레젠테이션 요청/응답

### 9.9 Camera Redirection (MS-RDPECAM)

> **requires**: 7.3 DVC 프레임워크
> **검증**: 카메라 디바이스 열거 integration test

- [ ] 카메라 디바이스 열거
- [ ] 미디어 타입 협상
- [ ] 프레임 스트리밍

### 9.10 Video Redirection (MS-RDPEV)

> **requires**: 7.3 DVC 프레임워크
> **검증**: PDU roundtrip

**DVC 이름**: `TSMF` (TS Multimedia Framework)

- [ ] TSMF Interface: Exchange Capabilities
- [ ] 미디어 타입 협상 (오디오/비디오 코덱)
- [ ] 서버 측 미디어 플레이어 → 클라이언트 측 로컬 재생
- [ ] Play/Pause/Stop/Seek 제어
- [ ] 스트림 타이밍 동기화 (presentation timestamp)
- [ ] 레거시 비디오 리다이렉션 (RDPEVOR 이전 방식)

### 9.11 Geometry Tracking (RDPGFX)

> **requires**: 7.3 DVC 프레임워크, 8.6 EGFX
> **검증**: PDU roundtrip

**DVC 이름**: `Microsoft::Windows::RDS::Geometry::v08.01`

- [ ] 지오메트리 업데이트 PDU
- [ ] 렌더링 영역 추적 (비디오 오버레이 위치)
- [ ] RDPEVOR과 연동하여 비디오 위치 동기화

### 9.12 Desktop Composition (MS-RDPECR2)

> **requires**: 7.3 DVC 프레임워크
> **검증**: PDU roundtrip

- [ ] Composited Remoting V2 프로토콜
- [ ] 데스크톱 컴포지션 리다이렉션 (DWM 통합)
- [ ] CAPSETTYPE_COMPDESK capability set과 연동
- [ ] 서버측 DWM 컴포지션 활성화/비활성화 제어

### 9.13 Multiparty Virtual Channel (MS-RDPEMC)

> **requires**: 7.3 DVC 프레임워크, 7.1 세션
> **검증**: Shadow 세션 integration test

- [ ] 다자 RDP 세션 (여러 클라이언트가 하나의 세션 공유)
- [ ] Shadow 세션 (관리자가 사용자 세션 모니터링/제어)
- [ ] View-only / Interactive 모드
- [ ] 제어 권한 요청/승인 시퀀스

### 9.14 Plug and Play Device Redirection (MS-RDPEPNP)

> **requires**: 7.3 DVC 프레임워크
> **검증**: PDU roundtrip

- [ ] PnP 디바이스 열거 (클라이언트 → 서버)
- [ ] 디바이스 추가/제거 알림
- [ ] 디바이스 드라이버 매칭 (서버 측)
- [ ] 디바이스 인스턴스 리다이렉션

---

## 10. Phase 7 -- Transport Extensions

> **목표**: WAN 환경에서의 성능 최적화, 방화벽/프록시 통과.
> Phase 4 세션과 병렬 진행 가능 (독립 네트워크 레이어).

### 10.1 RD Gateway (MS-TSGU)

> **requires**: Phase 2 (NTLM/Kerberos 인증), justrdp-tls
> **검증**: 게이트웨이 경유 실서버 연결 integration test
> **참고**: 세션 내용과 무관한 터널 레이어이므로 Phase 4/5와 병렬 진행 가능

**HTTP Transport (신규, 권장):**

- [ ] Handshake Request/Response
- [ ] Tunnel Create/Response
- [ ] Tunnel Auth/Response
- [ ] Channel Create/Response
- [ ] Data PDU 전송/수신
- [ ] Keepalive
- [ ] Close Channel

**RPC-over-HTTP (레거시):**

- [ ] DCE/RPC 바인딩
- [ ] TsProxy 인터페이스:
  - [ ] `TsProxyCreateTunnel`
  - [ ] `TsProxyAuthorizeTunnel`
  - [ ] `TsProxyMakeTunnelCall`
  - [ ] `TsProxyCreateChannel`
  - [ ] `TsProxySendToServer`
  - [ ] `TsProxySetupReceivePipe`
  - [ ] `TsProxyCloseChannel`
  - [ ] `TsProxyCloseTunnel`
- [ ] PAA Cookie 인증

**WebSocket Transport:**

- [ ] WebSocket 업그레이드
- [ ] 바이너리 프레임 전송
- [ ] 게이트웨이 인증

**공통:**

- [ ] NTLM/Kerberos 게이트웨이 인증
- [ ] 리소스 인가 정책
- [ ] UDP side channel
- [ ] 다중 게이트웨이 장애 조치

### 10.2 UDP Transport (MS-RDPEUDP)

> **requires**: Phase 2 (Connected), justrdp-tls (DTLS)
> **검증**: UDP 핸드셰이크 integration test

**구현 항목:**

- [ ] 3-way 핸드셰이크 (SYN → SYN+ACK → ACK)
- [ ] `RdpeudpSocket` -- UDP 소켓 추상화
- [ ] Reliable 모드:
  - [ ] 시퀀스 번호 관리
  - [ ] 재전송 타이머 (RTO)
  - [ ] 혼잡 제어 (congestion window)
  - [ ] FEC (Forward Error Correction)
  - [ ] 순서 보장
  - [ ] TLS over UDP
- [ ] Lossy 모드:
  - [ ] FEC only (재전송 없음)
  - [ ] DTLS
- [ ] ACK/NACK 처리
- [ ] MTU 협상
- [ ] 프로토콜 버전 1/2/3 지원

### 10.3 Multitransport (MS-RDPEMT)

> **requires**: 10.2 UDP Transport, 7.3 DVC 프레임워크 (Soft-Sync)
> **검증**: UDP 사이드 채널로 DVC 라우팅 integration test

**구현 항목:**

- [ ] `InitiateMultitransportRequest` 수신 (메인 TCP 연결 통해)
- [ ] UDP 연결 수립
- [ ] TLS/DTLS 핸드셰이크 (UDP 위)
- [ ] `TunnelCreateRequest` PDU (requestId + securityCookie)
- [ ] `TunnelCreateResponse` PDU
- [ ] DVC를 UDP 트랜스포트로 라우팅
- [ ] 트랜스포트 간 DVC Soft-Sync 마이그레이션 (DYNVC_SOFT_SYNC_REQUEST/RESPONSE)

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

- [ ] `ServerAcceptor` -- `Sequence` trait 구현
- [ ] `ServerConfig` -- 서버 설정 (인증서, 암호화, 지원 채널, 코덱 등)
- [ ] 클라이언트 Negotiate 수신 및 프로토콜 선택
- [ ] TLS 서버 핸드셰이크
- [ ] CredSSP 서버 측 (자격증명 수신)
- [ ] 서버 측 Capability Set 생성
- [ ] 채널 ID 할당
- [ ] `DrdynvcServer` -- 서버 측 DVC 호스트 (Phase 4에서 이동)

### 11.2 `justrdp-server` -- Extensible Server Skeleton

> **requires**: 11.1 Acceptor, Phase 3 코덱 (RFX 인코딩), 8.6 EGFX

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

**구현 항목:**

- [ ] `RdpServer` -- 메인 서버 struct
- [ ] Display handler 통합 (RFX 인코딩, EGFX 전송)
- [ ] Input handler 통합
- [ ] Clipboard handler 통합
- [ ] Sound handler 통합
- [ ] 멀티세션 지원
- [ ] 세션 관리 (disconnect, reconnect)
- [ ] 서버 사이드 GFX 인코딩 파이프라인

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
| MS-RDPECR2  | Composited Remoting V2                   | 6     | Low          |
| MS-RDPEV    | Video Redirection Virtual Channel (TSMF) | 6     | Low          |
| MS-RDPEMC   | Multiparty Virtual Channel Extension     | 6     | Low          |
| MS-RDPEECO  | Extensible Output Channel Extension      | 6     | Low          |
| MS-RDPEXPS  | Extended Presentation Session            | 6     | Low          |
| MS-RDPEDC   | Desktop Composition Virtual Channel      | 6     | Low          |
| MS-RDPEAR   | Audio Redirection (newer)                | 6     | Low          |
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

### 13.1 Client-Side Quick Start API

```rust
use justrdp::client::{RdpClient, Config, Credentials};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::builder()
        .server("192.168.1.100:3389")
        .credentials(Credentials::password("user", "pass", Some("DOMAIN")))
        .desktop_size(1920, 1080)
        .color_depth(ColorDepth::Bpp32)
        .enable_clipboard(true)
        .enable_drive_redirect("/home/user/share")
        .enable_audio(true)
        .build()?;

    let mut client = RdpClient::connect(config).await?;

    loop {
        match client.next_event().await? {
            RdpEvent::GraphicsUpdate { region, bitmap } => {
                render_to_screen(region, bitmap);
            }
            RdpEvent::PointerUpdate(pointer) => {
                update_cursor(pointer);
            }
            RdpEvent::Clipboard(ClipboardEvent::FormatList(formats)) => {
                handle_clipboard(formats);
            }
            RdpEvent::Disconnected(reason) => {
                println!("Disconnected: {:?}", reason);
                break;
            }
            _ => {}
        }

        // 입력 전송
        client.send_key(Scancode::A, true).await?;
        client.send_mouse_move(500, 300).await?;
    }

    Ok(())
}
```

### 13.2 Low-Level State Machine API

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

- **실제 서버 연결**: Windows RDP 서버에 대한 연결/인증/그래픽 수신 통합 테스트
- **xrdp 연결**: 오픈소스 xrdp 서버 대응 테스트
- **xfreerdp 호환성**: FreeRDP 클라이언트와의 상호 운용성 테스트 (서버 모드)
- **게이트웨이 통과**: RD Gateway를 통한 연결 테스트

### 14.3 Fuzzing

- **PDU 퍼징**: `cargo-fuzz` + `libfuzzer`로 모든 `Decode` 구현 퍼징
- **코덱 퍼징**: RFX, RLE, ZGFX, NSCodec 디코더 퍼징
- **상태 머신 퍼징**: 임의 바이트 시퀀스로 커넥터/세션 상태 머신 퍼징
- **목표**: 패닉, OOM, 무한 루프 없음

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

| Metric                 | Target                           | Note                         |
| ---------------------- | -------------------------------- | ---------------------------- |
| 연결 수립 시간         | < 1s (LAN)                       | NLA 포함                     |
| 프레임 디코딩 레이턴시 | < 5ms (1080p)                    | RFX/EGFX                     |
| ZGFX 해제 throughput   | > 500 MB/s                       | 싱글 코어                    |
| RFX 디코딩 throughput  | > 200 Mpixels/s                  | SIMD 최적화                  |
| 메모리 사용량          | < 50 MB (idle session)           | 코덱 버퍼 포함               |
| 바이너리 크기          | < 5 MB (stripped, full features) |                              |
| Zero-copy parsing      | 가능한 모든 곳                   | `Decode<'de>` lifetime-bound |

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

- [ ] `#![forbid(unsafe_code)]` -- Core tier 전체 (예외 시 `// SAFETY:` 주석 필수)
- [ ] `zeroize` -- 자격증명, 세션 키, 비밀번호 메모리 즉시 소거
- [ ] 정수 오버플로 -- `checked_add()`, `checked_mul()` 사용 (PDU 길이 계산)
- [ ] 최대 PDU 크기 -- 상수로 정의, 초과 시 즉시 거부 (예: `MAX_PDU_SIZE = 16 MB`)
- [ ] 최대 채널 수 -- SVC 31개, DVC 무한이지만 configurable limit 설정
- [ ] 압축 폭탄 방지 -- 해제 출력 최대 크기 제한 (compression ratio limit)
- [ ] 타임아웃 -- 모든 상태 머신에 전환 타임아웃 (configurable)

**프로토콜 수준:**

- [ ] TLS 최소 버전 강제 (TLS 1.2+, configurable)
- [ ] Standard RDP Security 기본 비활성화 (RC4는 안전하지 않음)
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

| Server                 | Version        | Target | Priority     | Notes                               |
| ---------------------- | -------------- | ------ | ------------ | ----------------------------------- |
| Windows Server 2012 R2 | RDP 8.1        | Full   | Medium       | 레거시, RDPEGFX v8.0/8.1            |
| Windows Server 2016    | RDP 10.0       | Full   | High         | RDPEGFX v10.0, H.264                |
| Windows Server 2019    | RDP 10.5       | Full   | **Critical** | 가장 널리 사용, RDPEGFX v10.5       |
| Windows Server 2022    | RDP 10.7       | Full   | **Critical** | 최신 LTS, RDPEGFX v10.7             |
| Windows Server 2025    | RDP 10.7+      | Full   | High         | 최신, AAD 통합                      |
| Windows 10 (Pro/Ent)   | RDP 10.x       | Full   | **Critical** | 가장 흔한 타겟                      |
| Windows 11 (Pro/Ent)   | RDP 10.x       | Full   | **Critical** | 최신 데스크톱                       |
| xrdp                   | 0.9.x / 0.10.x | Full   | High         | Linux RDP 서버, 오픈소스 생태계     |
| FreeRDP Server         | 3.x            | Basic  | Medium       | 테스트/개발용                       |
| Azure Virtual Desktop  | Latest         | Full   | High         | 클라우드 시나리오, AAD/Gateway 필수 |
| Windows 365            | Latest         | Full   | High         | 클라우드 PC                         |

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
Level 5: justrdp-session, justrdp-async, justrdp-tls  (parallel)
Level 6: justrdp-tokio, justrdp-futures, justrdp-blocking  (parallel)
Level 7: justrdp-acceptor, justrdp (meta)  (parallel)
Level 8: justrdp-server, justrdp-client, justrdp-web, justrdp-ffi  (parallel)
```

---

## 20. Definition of Done (per Phase)

### Phase 1 -- Foundation

- [x] `justrdp-core`: `Encode`/`Decode` trait 구현 및 100% 단위 테스트
- [ ] `justrdp-pdu`: 모든 TPKT/X.224/MCS/GCC PDU roundtrip 테스트 통과
- [ ] `justrdp-pdu`: 30종 Capability Set 인코딩/디코딩 통과
- [ ] `justrdp-pdu`: Fast-Path 입출력 PDU roundtrip 테스트 통과
- [ ] `cargo fuzz` 최소 1시간 무크래시 (PDU 디코더 대상)
- [ ] `#![no_std]` 빌드 성공 (core, pdu)
- [ ] CI: Linux/Windows/macOS, x86_64/aarch64 빌드 통과
- [ ] 문서: 모든 public API에 `///` doc comment

### Phase 2 -- Connection

- [x] CredSSP/NLA 핸드셰이크 성공 (Windows Server, NTLM v6)
- [ ] NTLM MIC 버그 수정 후 MIC 활성화 상태로 접속 성공
- [ ] BasicSettingsExchange → Connection Finalization 전체 시퀀스 → `Connected` 도달
- [ ] Windows Server 2019/2022에 NLA(CredSSP+NTLM) 연결 성공
- [ ] Windows 10/11에 NLA 연결 성공
- [ ] xrdp에 TLS 연결 성공
- [ ] Standard RDP Security (RC4) 연결 성공 (레거시 서버 테스트)
- [ ] 연결 시간 < 2초 (LAN, NLA 포함)
- [ ] CredSSP 구현 보안 리뷰 완료
- [ ] `cargo fuzz` 최소 4시간 무크래시 (커넥터 상태 머신 대상)
- [ ] 자동화된 연결 통합 테스트 (CI에서 xrdp Docker 컨테이너 사용)

### Phase 3 -- Graphics

- [ ] Windows Server에서 그래픽 수신 및 RGBA 프레임 버퍼 생성 성공
- [ ] RLE, Planar, RFX 코덱 디코딩 정확성 검증 (참조 이미지 비교)
- [ ] EGFX 파이프라인 (v8.0 ~ v10.x) 동작 확인
- [ ] ZGFX 압축/해제 throughput > 300 MB/s
- [ ] `ActiveStage` 프레임 처리 레이턴시 < 10ms (1080p)
- [ ] 포인터/커서 렌더링 정확성
- [ ] `cargo fuzz` 최소 8시간 무크래시 (코덱 디코더 대상)
- [ ] 코덱 벤치마크 기준선 설정 (`criterion`)

### Phase 4 -- Channels

- [ ] 클립보드: 텍스트/이미지/파일 양방향 복사 동작 확인 (Windows ↔ 클라이언트)
- [ ] 드라이브: 로컬 디렉터리를 원격 세션에서 탐색/읽기/쓰기 가능
- [ ] 오디오 출력: 원격 세션 오디오가 로컬에서 재생됨 (PCM 기본)
- [ ] 오디오 입력: 로컬 마이크가 원격 세션에서 인식됨
- [ ] 디스플레이 리사이즈: 클라이언트 창 크기 변경 시 원격 해상도 자동 조정
- [ ] RemoteApp: 단일 앱 실행 및 윈도우 관리 동작 확인
- [ ] 모든 채널의 초기화/종료 시퀀스 정상 동작
- [ ] 채널 보안 리뷰 완료 (RDPDR 파일 접근 범위, CLIPRDR 데이터 유출 방지)

### Phase 5 -- Advanced

- [ ] 멀티모니터: 2개 이상 모니터에서 올바른 좌표/렌더링
- [ ] 자동 재연결: 네트워크 끊김 후 3초 이내 세션 복구
- [ ] 세션 리다이렉션: 로드밸런서 환경에서 올바른 리다이렉트
- [ ] 각 추가 기능(USB, touch, pen)의 기본 동작 확인

### Phase 6 -- Transport

- [ ] UDP reliable: TCP 대비 레이턴시 개선 측정 가능
- [ ] UDP lossy: 오디오/비디오 스트림 정상 전송
- [ ] RD Gateway: HTTP/WebSocket 전송을 통한 연결 성공
- [ ] Multitransport: TCP+UDP 동시 전송, DVC 라우팅 정상

### Phase 7 -- Server

- [ ] mstsc.exe (Windows 내장 클라이언트)에서 JustRDP 서버 연결 성공
- [ ] FreeRDP(xfreerdp)에서 JustRDP 서버 연결 성공
- [ ] 서버 → 클라이언트 그래픽 전송 (RFX 인코딩)
- [ ] 클라이언트 → 서버 입력 수신 및 처리
- [ ] 멀티세션 동시 접속

### Phase 8 -- Ecosystem

- [ ] WASM 빌드 및 브라우저에서 RDP 연결 성공
- [ ] C FFI: 외부 C 프로그램에서 JustRDP 호출 성공
- [ ] Python 바인딩: `pip install justrdp` 후 스크립팅 사용 가능
- [ ] 레퍼런스 클라이언트: GUI RDP 클라이언트 기본 기능 동작

---

## 21. Error & Disconnect Code Reference

> `SetErrorInfoPdu`로 전송되는 disconnect reason 코드. 디버깅과 사용자 메시지에 필수.

### 21.1 Protocol-Independent Codes

| Code   | Name                                      | Description           |
| ------ | ----------------------------------------- | --------------------- |
| 0x0000 | ERRINFO_RPC_INITIATED_DISCONNECT          | 관리자가 세션 종료    |
| 0x0001 | ERRINFO_RPC_INITIATED_LOGOFF              | 관리자가 로그오프     |
| 0x0002 | ERRINFO_IDLE_TIMEOUT                      | 유휴 타임아웃         |
| 0x0003 | ERRINFO_LOGON_TIMEOUT                     | 로그온 타임아웃       |
| 0x0004 | ERRINFO_DISCONNECTED_BY_OTHER_CONNECTION  | 다른 연결에 의해 끊김 |
| 0x0005 | ERRINFO_OUT_OF_MEMORY                     | 서버 메모리 부족      |
| 0x0006 | ERRINFO_SERVER_DENIED_CONNECTION          | 서버가 연결 거부      |
| 0x0007 | ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES    | 권한 부족             |
| 0x0009 | ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED | 새 자격증명 필요      |
| 0x000A | ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER  | 사용자 요청 종료      |
| 0x000B | ERRINFO_LOGOFF_BY_USER                    | 사용자 로그오프       |

### 21.2 Protocol Error Codes

| Code   | Name                                        | Description              |
| ------ | ------------------------------------------- | ------------------------ |
| 0x0100 | ERRINFO_CLOSE_STACK_ON_DRIVER_NOT_READY     | 드라이버 미준비          |
| 0x0104 | ERRINFO_SERVER_DWM_CRASH                    | 서버 DWM 충돌            |
| 0x010C | ERRINFO_CLOSE_STACK_ON_DRIVER_FAILURE       | 드라이버 실패            |
| 0x010D | ERRINFO_CLOSE_STACK_ON_DRIVER_IFACE_FAILURE | 드라이버 인터페이스 실패 |
| 0x1000 | ERRINFO_ENCRYPTION_FAILURE                  | 암호화 실패              |
| 0x1001 | ERRINFO_DECRYPTION_FAILURE                  | 복호화 실패              |
| 0x1002 | ERRINFO_ENCRYPT_UPDATE_FAILURE              | 암호화 업데이트 실패     |
| 0x1003 | ERRINFO_DECRYPT_UPDATE_FAILURE              | 복호화 업데이트 실패     |
| 0x1005 | ERRINFO_ENCRYPT_NO_ENCRYPT_KEY              | 암호화 키 없음           |
| 0x1006 | ERRINFO_DECRYPT_NO_DECRYPT_KEY              | 복호화 키 없음           |
| 0x1007 | ERRINFO_ENCRYPT_NEW_KEYS_FAILED             | 새 키 생성 실패          |
| 0x1008 | ERRINFO_DECRYPT_NEW_KEYS_FAILED             | 새 키 생성 실패          |

### 21.3 Licensing Error Codes

| Code   | Name                                  | Description                 |
| ------ | ------------------------------------- | --------------------------- |
| 0x100C | ERRINFO_LICENSE_NO_LICENSE_SERVER     | 라이센스 서버 없음          |
| 0x100D | ERRINFO_LICENSE_NO_LICENSE            | 라이센스 없음               |
| 0x100E | ERRINFO_LICENSE_BAD_CLIENT_MSG        | 잘못된 클라이언트 메시지    |
| 0x100F | ERRINFO_LICENSE_HWID_DOESNT_MATCH     | 하드웨어 ID 불일치          |
| 0x1010 | ERRINFO_LICENSE_BAD_CLIENT_LICENSE    | 잘못된 클라이언트 라이센스  |
| 0x1011 | ERRINFO_LICENSE_CANT_FINISH_PROTOCOL  | 라이센스 프로토콜 완료 불가 |
| 0x1012 | ERRINFO_LICENSE_CLIENT_ENDED_PROTOCOL | 클라이언트가 프로토콜 종료  |
| 0x1013 | ERRINFO_LICENSE_BAD_CLIENT_ENCRYPTION | 잘못된 암호화               |
| 0x1014 | ERRINFO_LICENSE_CANT_UPGRADE_LICENSE  | 라이센스 업그레이드 불가    |
| 0x1015 | ERRINFO_LICENSE_NO_REMOTE_CONNECTIONS | 원격 연결 라이센스 없음     |

### 21.4 Connection Broker / Redirection Codes

| Code   | Name                                         | Description                |
| ------ | -------------------------------------------- | -------------------------- |
| 0x0400 | ERRINFO_CB_DESTINATION_NOT_FOUND             | 대상 서버 없음             |
| 0x0401 | ERRINFO_CB_LOADING_DESTINATION               | 대상 서버 로딩 중          |
| 0x0402 | ERRINFO_CB_REDIRECTING_TO_DESTINATION        | 대상으로 리다이렉트 중     |
| 0x0404 | ERRINFO_CB_CONNECTION_CANCELLED              | 연결 취소됨                |
| 0x0405 | ERRINFO_CB_CONNECTION_ERROR_INVALID_SETTINGS | 잘못된 설정                |
| 0x0406 | ERRINFO_CB_SESSION_ONLINE_VM_WAKE            | VM 깨우기 중               |
| 0x0407 | ERRINFO_CB_SESSION_ONLINE_VM_BOOT            | VM 부팅 중                 |
| 0x0408 | ERRINFO_CB_SESSION_ONLINE_VM_NO_DNS          | VM DNS 없음                |
| 0x0409 | ERRINFO_CB_DESTINATION_POOL_NOT_FREE         | 풀에 사용 가능한 대상 없음 |
| 0x040A | ERRINFO_CB_CONNECTION_CANCELLED_ADMIN        | 관리자가 연결 취소         |
| 0x040B | ERRINFO_CB_HELPER_FAILED                     | 헬퍼 실패                  |
| 0x040C | ERRINFO_CB_DESTINATION_NOT_IN_POOL           | 대상이 풀에 없음           |

### 21.5 Security Negotiation Failure Codes

| Code   | Name                        | Description            |
| ------ | --------------------------- | ---------------------- |
| 0x0001 | SSL_REQUIRED_BY_SERVER      | 서버가 TLS 필수        |
| 0x0002 | SSL_NOT_ALLOWED_BY_SERVER   | 서버가 TLS 불허        |
| 0x0003 | SSL_CERT_NOT_ON_SERVER      | 서버 인증서 없음       |
| 0x0004 | INCONSISTENT_FLAGS          | 비일관적 플래그        |
| 0x0005 | HYBRID_REQUIRED_BY_SERVER   | 서버가 NLA 필수        |
| 0x0006 | SSL_WITH_USER_AUTH_REQUIRED | TLS + 사용자 인증 필수 |

### 21.6 구현 항목

- [ ] `DisconnectReason` enum -- 모든 에러 코드 매핑
- [ ] 에러 코드 → 사용자 친화적 메시지 변환 함수
- [ ] 에러 코드 → 재연결 가능 여부 판단 함수
- [ ] 에러 코드 → 로그 심각도(severity) 매핑
- [ ] 서버 모드: 적절한 에러 코드 전송 (연결 거부, 라이센스 문제 등)

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
Phase 2 ▸ Connection         justrdp-connector, justrdp-tls
                             CredSSP, NTLM, Kerberos, SPNEGO, Standard RDP Security
                             Remote Credential Guard, Restricted Admin, Azure AD
Phase 3 ▸ Graphics           justrdp-graphics, justrdp-egfx, justrdp-session, justrdp-input
                             RLE, Planar, RFX, NSCodec, ClearCodec, H.264, ZGFX
Phase 4 ▸ Channels           justrdp-svc, justrdp-dvc
                             cliprdr, rdpdr, rdpsnd, rdpeai, displaycontrol, rail
Phase 5 ▸ Advanced           Multi-monitor, auto-reconnect, session redirection
                             USB, touch, pen, camera, video (RDPEVOR/RDPEV)
                             Desktop composition, multiparty, PnP, geometry
Phase 6 ▸ Transport          justrdp-rdpeudp, justrdp-rdpemt, justrdp-gateway (MS-TSGU)
                             UDP reliable/lossy, DTLS, multitransport, WebSocket
Phase 7 ▸ Server             justrdp-acceptor, justrdp-server
                             Server-side GFX encoding, multi-session, shadow
Phase 8 ▸ Ecosystem          justrdp-web (WASM), justrdp-ffi (C/Python)
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
