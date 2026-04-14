# MS-RDPEV Implementation Checklist
## Remote Desktop Protocol: Video Redirection Virtual Channel Extension
## Target crate: justrdp-rdpev (§9.10)
## Spec version: 18.0 (2024-04-23)
## DVC Channel name: `TSMF`

---

### Design Question Answers

**Q1: Is sample data realistically larger than RDPECAM's 4 MiB cap?**
Yes. TSMF carries full audio/video streams at real-time bitrates from a server-side media player. A single 1080p H.264 I-frame can exceed 1 MiB; high-bitrate video (20+ Mbps) at 30 fps produces samples of ~80 KiB on average but bursts at I-frames can reach several MiB. WMA/AAC audio is much smaller (< 64 KiB per sample). Recommended cap: **16 MiB** (`MAX_SAMPLE_BYTES = 16_777_216`). The `cbData` field in `TS_MM_DATA_SAMPLE` is u32, so the absolute ceiling is 4 GiB; the 16 MiB cap protects against malformed messages.

**Q2: Are there client→server requests that expect a matching server→client reply (requiring a correlation table)?**
Yes — three message pairs require request/response correlation via `(InterfaceId, MessageId)` echo:
1. `EXCHANGE_CAPABILITIES_REQ` (S→C) → `EXCHANGE_CAPABILITIES_RSP` (C→S): MessageId echoed in response header.
2. `CHECK_FORMAT_SUPPORT_REQ` (S→C) → `CHECK_FORMAT_SUPPORT_RSP` (C→S): MessageId echoed in response header.
3. `SET_TOPOLOGY_REQ` (S→C) → `SET_TOPOLOGY_RSP` (C→S): MessageId echoed in response header.
All three use `Mask=STREAM_ID_STUB` in the response. The client must store the pending MessageId for each outstanding request and match the response. The server may pipeline multiple `CHECK_FORMAT_SUPPORT_REQ` messages (different MessageIds), so a `HashMap<u32, PendingRequest>` keyed on MessageId is required.
Fire-and-forget (no response expected): all other server→client messages (`SET_CHANNEL_PARAMS`, `ON_NEW_PRESENTATION`, `ADD_STREAM`, `ON_SAMPLE`, `NOTIFY_PREROLL`, `ON_PLAYBACK_STARTED`, `ON_PLAYBACK_PAUSED`, `ON_PLAYBACK_STOPPED`, `ON_PLAYBACK_RESTARTED`, `ON_PLAYBACK_RATE_CHANGED`, `ON_FLUSH`, `ON_STREAM_VOLUME`, `ON_CHANNEL_VOLUME`, `ON_END_OF_STREAM`, `SET_ALLOCATOR`, `UPDATE_GEOMETRY_INFO`, `REMOVE_STREAM`, `SET_SOURCE_VIDEO_RECT`, `SHUTDOWN_PRESENTATION_REQ`, `SET_VIDEO_WINDOW`).
Client→server fire-and-forget: `PLAYBACK_ACK`, `CLIENT_EVENT_NOTIFICATION`, `SHUTDOWN_PRESENTATION_RSP`.

**Q3: Which functions can be "decoder + UnsupportedFunction" stubs vs mandatory for a working client?**

| Message | Mandatory? | Stub safe? |
|---------|-----------|------------|
| `EXCHANGE_CAPABILITIES_REQ/RSP` | YES — must respond or server drops channel | No |
| `SET_CHANNEL_PARAMS` | YES — parse PresentationId/StreamId to track state | Partial (parse, no action) |
| `ON_NEW_PRESENTATION` | YES — create presentation context | Partial (parse + create context) |
| `CHECK_FORMAT_SUPPORT_REQ/RSP` | YES — server uses response to decide ADD_STREAM | No (must answer honestly) |
| `ADD_STREAM` | YES — must parse TS_AM_MEDIA_TYPE to open decoder | No |
| `SET_TOPOLOGY_REQ/RSP` | YES — must respond TopologyReady=1 | No (must send response) |
| `ON_SAMPLE` + `PLAYBACK_ACK` | YES — core data path; must send ACK per sample | No |
| `NOTIFY_PREROLL` | RECOMMENDED — buffering hint; can ignore body | Stub OK |
| `ON_PLAYBACK_STARTED/PAUSED/STOPPED/RESTARTED` | RECOMMENDED — playback state control | Stub OK (parse only) |
| `ON_PLAYBACK_RATE_CHANGED` | Optional | Stub OK |
| `ON_FLUSH` | RECOMMENDED — decoder flush required for seek | Stub dangerous if skipped |
| `ON_END_OF_STREAM` | RECOMMENDED — EOS signal | Stub OK |
| `SET_ALLOCATOR` | Optional (MAY per spec) | Stub OK (ignore body) |
| `ON_STREAM_VOLUME` / `ON_CHANNEL_VOLUME` | Optional | Stub OK |
| `SET_VIDEO_WINDOW` | Optional (server-side HWND) | Stub OK |
| `UPDATE_GEOMETRY_INFO` | Optional | Stub OK |
| `SET_SOURCE_VIDEO_RECT` | Optional | Stub OK |
| `REMOVE_STREAM` | RECOMMENDED | Partial stub OK (remove stream context) |
| `SHUTDOWN_PRESENTATION_REQ/RSP` | YES — must send RSP Result=S_OK | No |
| `CLIENT_EVENT_NOTIFICATION` | Optional (client-side events) | N/A (C→S only) |
| `RIMCALL_RELEASE` / `RIMCALL_QUERYINTERFACE` | Required (interface manipulation) | Partial |

---

### 0. Crate / Module Layout

- [ ] `crates/justrdp-rdpev/Cargo.toml` — `no_std`, `forbid(unsafe_code)`, deps: `justrdp-core`, `justrdp-dvc`
- [ ] `crates/justrdp-rdpev/src/lib.rs` — `#![forbid(unsafe_code)]`, `#![no_std]`, `extern crate alloc`
- [ ] `src/pdu/header.rs` — `SharedMsgHeader` (InterfaceId+Mask+MessageId+FunctionId), `Mask` enum, `FunctionId` enum
- [ ] `src/pdu/capabilities.rs` — `ExchangeCapabilitiesReq`, `ExchangeCapabilitiesRsp`, `TsmmCapabilities`
- [ ] `src/pdu/presentation.rs` — `SetChannelParams`, `NewPresentation`, `ShutdownPresentationReq`, `ShutdownPresentationRsp`
- [ ] `src/pdu/format.rs` — `CheckFormatSupportReq`, `CheckFormatSupportRsp`, `TsAmMediaType`
- [ ] `src/pdu/stream.rs` — `AddStream`, `SetTopologyReq`, `SetTopologyRsp`, `RemoveStream`
- [ ] `src/pdu/sample.rs` — `OnSample`, `PlaybackAck`, `TsMmDataSample`
- [ ] `src/pdu/control.rs` — `NotifyPreroll`, `OnPlaybackStarted/Paused/Stopped/Restarted/RateChanged`, `OnFlush`, `OnEndOfStream`
- [ ] `src/pdu/volume.rs` — `OnStreamVolume`, `OnChannelVolume`
- [ ] `src/pdu/geometry.rs` — `SetVideoWindow`, `UpdateGeometryInfo`, `GeometryInfo`, `SetSourceVideoRect`
- [ ] `src/pdu/allocator.rs` — `SetAllocator`
- [ ] `src/pdu/client.rs` — `ClientEventNotification`
- [ ] `src/constants.rs` — all FunctionId, Mask, CapabilityType, platform cookies, event IDs, window flags
- [ ] `src/processor.rs` — `RdpevClient` implementing `DvcProcessor` trait
- [ ] `src/presentation.rs` — `PresentationContext` and `StreamContext` state
- [ ] `src/media.rs` — `TsmfMediaSink` trait (platform injection)
- [ ] `tests/integration.rs` — roundtrip + full protocol flow with mock sink

---

### 1. DVC Channel Structure (MS-RDPEV §1.3)

- [ ] Single DVC channel name: `TSMF` (exact, null-terminated ANSI) — MS-RDPEV §2.1
- [ ] Channel opened via MS-RDPEDYC §2.2.2.1
- [ ] The single `TSMF` channel multiplexes ALL presentations and ALL streams via PresentationId (GUID) + StreamId (u32) embedded in each message
- [ ] StreamId 0x00000000 is reserved for non-streaming messages (SET_CHANNEL_PARAMS, EXCHANGE_CAPABILITIES); MUST NOT carry ON_SAMPLE or NOTIFY_PREROLL — MS-RDPEV §2.2.5.1
- [ ] Multiple presentations can be active simultaneously (different PresentationId GUIDs)
- [ ] Multiple streams per presentation (different StreamId values within same PresentationId)

---

### 2. SHARED_MSG_HEADER (MS-RDPEV §2.2.1) — 12 bytes fixed

All multi-byte integers are **little-endian**.

| Offset | Size | Type | Field | Notes |
|-------:|-----:|------|-------|-------|
| 0 | 4 | u32 LE | `InterfaceId` | Contains both `InterfaceValue` (lower 30 bits) and `Mask` (upper 2 bits) packed together |
| 4 | 4 | u32 LE | `MessageId` | Correlation ID for req/rsp pairs; echoed in response |
| 8 | 4 | u32 LE | `FunctionId` | Present in all non-response packets; absent (no field) in response packets |

**InterfaceId field decomposition (MS-RDPEV §2.2.1):**

| Bits | Field | Notes |
|------|-------|-------|
| [29:0] (30 bits) | `InterfaceValue` | Interface identifier. 0x00000000 = main/default interface |
| [31:30] (2 bits) | `Mask` | Packed into upper 2 bits of the u32 |

- [ ] `InterfaceValue` bits [29:0]: default value 0x00000000 for the main TSMF interface
- [ ] Non-zero InterfaceValues obtained from QI_RSP or other responses; valid until IFACE_RELEASE
- [ ] `Mask` bits [31:30] packed into the same u32 as InterfaceValue: `STREAM_ID_STUB=0x80000000`, `STREAM_ID_PROXY=0x40000000`, `STREAM_ID_NONE=0x00000000`
- [ ] Response packets: `Mask=STREAM_ID_STUB (0x80000000)`, no FunctionId field — header is 8 bytes (InterfaceId + MessageId only)
- [ ] Request packets: `Mask=STREAM_ID_PROXY (0x40000000)`, FunctionId present — header is 12 bytes
- [ ] Interface manipulation (QI, IFACE_RELEASE): `Mask=STREAM_ID_NONE (0x00000000)` — MS-RDPEV §2.2.3
- [ ] AMBIGUITY: The spec says FunctionId is "absent in response packets" but the wire format shows the response header still occupies 8 bytes (InterfaceId=4 + MessageId=4). FunctionId field is literally not present in response PDUs. Implement response decoding as: if Mask==STREAM_ID_STUB, header size = 8 bytes (no FunctionId); else header size = 12 bytes.

**Key dispatch logic:**
- Parse 4-byte InterfaceId field → extract Mask from bits [31:30] and InterfaceValue from bits [29:0]
- If Mask == STREAM_ID_STUB: this is a response; correlate on (InterfaceValue, MessageId)
- If Mask == STREAM_ID_PROXY: this is a request; dispatch on FunctionId
- If Mask == STREAM_ID_NONE: interface manipulation message; dispatch differently

---

### 3. FunctionId Constants — Server Data Interface (InterfaceValue=0x0) (MS-RDPEV §2.2.1)

All on InterfaceId InterfaceValue=0x00000000, Mask=STREAM_ID_PROXY (0x40000000):

| Name | Value | Direction | Fire-and-forget? |
|------|------:|-----------|-----------------|
| `EXCHANGE_CAPABILITIES_REQ` | 0x00000100 | S→C | No (expects RSP) |
| `SET_CHANNEL_PARAMS` | 0x00000101 | S→C | Yes |
| `ADD_STREAM` | 0x00000102 | S→C | Yes |
| `ON_SAMPLE` | 0x00000103 | S→C | Yes (client sends PLAYBACK_ACK separately) |
| `SET_VIDEO_WINDOW` | 0x00000104 | S→C | Yes |
| `ON_NEW_PRESENTATION` | 0x00000105 | S→C | Yes |
| `SHUTDOWN_PRESENTATION_REQ` | 0x00000106 | S→C | No (expects RSP) |
| `SET_TOPOLOGY_REQ` | 0x00000107 | S→C | No (expects RSP) |
| `CHECK_FORMAT_SUPPORT_REQ` | 0x00000108 | S→C | No (expects RSP) |
| `ON_PLAYBACK_STARTED` | 0x00000109 | S→C | Yes |
| `ON_PLAYBACK_PAUSED` | 0x0000010a | S→C | Yes |
| `ON_PLAYBACK_STOPPED` | 0x0000010b | S→C | Yes |
| `ON_PLAYBACK_RESTARTED` | 0x0000010c | S→C | Yes |
| `ON_PLAYBACK_RATE_CHANGED` | 0x0000010d | S→C | Yes |
| `ON_FLUSH` | 0x0000010e | S→C | Yes |
| `ON_STREAM_VOLUME` | 0x0000010f | S→C | Yes |
| `ON_CHANNEL_VOLUME` | 0x00000110 | S→C | Yes |
| `ON_END_OF_STREAM` | 0x00000111 | S→C | Yes |
| `SET_ALLOCATOR` | 0x00000112 | S→C | Yes (MAY be sent) |
| `NOTIFY_PREROLL` | 0x00000113 | S→C | Yes |
| `UPDATE_GEOMETRY_INFO` | 0x00000114 | S→C | Yes |
| `REMOVE_STREAM` | 0x00000115 | S→C | Yes |
| `SET_SOURCE_VIDEO_RECT` | 0x00000116 | S→C | Yes |

### 3b. FunctionId Constants — Client Notifications Interface (InterfaceValue=0x1) (MS-RDPEV §2.2.1)

| Name | Value | Direction | Notes |
|------|------:|-----------|-------|
| `PLAYBACK_ACK` | 0x00000100 | C→S | InterfaceId bit [0] = 1, i.e., InterfaceValue=0x00000001 combined with Mask=STREAM_ID_PROXY (0x40000001) |
| `CLIENT_EVENT_NOTIFICATION` | 0x00000101 | C→S | Same InterfaceValue=0x00000001 |

### 3c. FunctionId Constants — Capabilities Negotiator (InterfaceValue=0x0) (MS-RDPEV §2.2.1)

| Name | Value | Direction |
|------|------:|-----------|
| `RIM_EXCHANGE_CAPABILITY_REQUEST` | 0x00000100 | S→C (alias name for EXCHANGE_CAPABILITIES_REQ) |

### 3d. Common Interface Manipulation FunctionIds (MS-RDPEV §2.2.1)

| Name | Value | Direction | Notes |
|------|------:|-----------|-------|
| `RIMCALL_RELEASE` | 0x00000001 | Bidirectional | Release interface ID |
| `RIMCALL_QUERYINTERFACE` | 0x00000002 | Bidirectional | Query for new interface; response is QI_RSP |

---

### 4. PDU Wire Formats

All PDU sizes below are **excluding** the SHARED_MSG_HEADER. Header is always 12 bytes for requests (Mask=PROXY), 8 bytes for responses (Mask=STUB, no FunctionId).

#### 4.1 EXCHANGE_CAPABILITIES_REQ (§2.2.4.1) — variable — S→C

Payload after 12-byte header:

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `numHostCapabilities` |
| 4 | variable | `TSMM_CAPABILITIES[]` | Array of capability structures |

- [ ] `InterfaceValue=0`, `Mask=STREAM_ID_PROXY`, `FunctionId=0x00000100`
- [ ] `numHostCapabilities`: count of TSMM_CAPABILITIES structures following

#### 4.2 EXCHANGE_CAPABILITIES_RSP (§2.2.4.2) — variable — C→S

Payload after 8-byte response header:

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `numClientCapabilities` |
| 4 | variable | `TSMM_CAPABILITIES[]` | Array of client capabilities |
| 4+N | 4 | u32 LE | `Result` (HRESULT, S_OK=0x00000000) |

- [ ] `InterfaceValue=0`, `Mask=STREAM_ID_STUB`, same `MessageId` as REQ
- [ ] `Result` MUST be S_OK (0x00000000)
- [ ] Client MUST send its own capability set in `numClientCapabilities`

#### 4.3 TSMM_CAPABILITIES structure (§2.2.4.3) — variable

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `CapabilityType` |
| 4 | 4 | u32 LE | `cbCapabilityLength` |
| 8 | variable | u8[] | `pCapabilityData` |

- [ ] `cbCapabilityLength` = number of bytes in `pCapabilityData`
- [ ] When `CapabilityType=0x00000001` (version): `pCapabilityData` = u32 LE, value MUST be 0x00000002 (version 2)
- [ ] When `CapabilityType=0x00000002` (platform): `pCapabilityData` = u32 LE bitfield from MMREDIR_CAPABILITY_PLATFORM
- [ ] When `CapabilityType=0x00000003` (audio support): `pCapabilityData` = u32 LE from MMREDIR_CAPABILITY_AUDIOSUPPORT
- [ ] When `CapabilityType=0x00000004` (network latency): `pCapabilityData` = u32 LE, one-way latency in milliseconds

#### 4.4 SET_CHANNEL_PARAMS (§2.2.5.1) — 20 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID (128-bit LE) | `PresentationId` |
| 16 | 4 | u32 LE | `StreamId` |

- [ ] `FunctionId=0x00000101`
- [ ] `StreamId=0x00000000` for the control channel; MUST NOT be used for `ON_SAMPLE`
- [ ] MUST be the first message sent per channel setup after EXCHANGE_CAPABILITIES exchange
- [ ] Associate `(PresentationId, StreamId)` with this DVC channel for all subsequent messages

#### 4.5 ON_NEW_PRESENTATION (§2.2.5.2.1) — 20 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `PlatformCookie` |

- [ ] `FunctionId=0x00000105`
- [ ] `PlatformCookie` ∈ {TSMM_PLATFORM_COOKIE_UNDEFINED=0, TSMM_PLATFORM_COOKIE_MF=1, TSMM_PLATFORM_COOKIE_DSHOW=2}; unknown values ignored

#### 4.6 CHECK_FORMAT_SUPPORT_REQ (§2.2.5.2.2) — variable payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `PlatformCookie` |
| 4 | 4 | u32 LE | `NoRolloverFlags` |
| 8 | 4 | u32 LE | `numMediaType` (byte count of following field) |
| 12 | variable | TS_AM_MEDIA_TYPE (as bytes) | `pMediaType` |

- [ ] `FunctionId=0x00000108`
- [ ] `NoRolloverFlags`: 0x00000000=try alternatives if preferred platform fails; 0x00000001=no rollover
- [ ] `numMediaType` is the **byte count** of the serialized `TS_AM_MEDIA_TYPE`, NOT an element count
- [ ] Multiple CHECK_FORMAT_SUPPORT_REQ may be in-flight with different MessageIds; use correlation table

#### 4.7 CHECK_FORMAT_SUPPORT_RSP (§2.2.5.2.3) — 12 bytes payload — C→S

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `FormatSupported` (0=no, 1=yes) |
| 4 | 4 | u32 LE | `PlatformCookie` |
| 8 | 4 | u32 LE | `Result` (HRESULT) |

- [ ] `Mask=STREAM_ID_STUB`, echoed `MessageId` from REQ
- [ ] `PlatformCookie` MUST be set only when `FormatSupported=1`; MUST be TSMM_PLATFORM_COOKIE_MF(1) or TSMM_PLATFORM_COOKIE_DSHOW(2)
- [ ] If format unsupported: `FormatSupported=0`, `PlatformCookie` undefined, `Result=S_OK`

#### 4.8 ADD_STREAM (§2.2.5.2.4) — variable payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `StreamId` |
| 20 | 4 | u32 LE | `numMediaType` (byte count) |
| 24 | variable | TS_AM_MEDIA_TYPE (as bytes) | `pMediaType` |

- [ ] `FunctionId=0x00000102`
- [ ] `numMediaType` is byte count of the serialized `TS_AM_MEDIA_TYPE`
- [ ] Client MUST store `(PresentationId, StreamId) → TS_AM_MEDIA_TYPE` mapping

#### 4.9 SET_TOPOLOGY_REQ (§2.2.5.2.5) — 16 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |

- [ ] `FunctionId=0x00000107`
- [ ] Indicates presentation setup is complete; client MUST respond immediately with SET_TOPOLOGY_RSP
- [ ] Client MUST NOT send any other message between REQ and RSP — MS-RDPEV §3.2.5.2.5

#### 4.10 SET_TOPOLOGY_RSP (§2.2.5.2.6) — 8 bytes payload — C→S

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `TopologyReady` (0=not ready, 1=ready) |
| 4 | 4 | u32 LE | `Result` (HRESULT) |

- [ ] `Mask=STREAM_ID_STUB`, echoed `MessageId` from REQ
- [ ] `TopologyReady=1` if all streams decoded and ready; `TopologyReady=0` if setup failed
- [ ] `Result=S_OK (0x00000000)` on success

#### 4.11 REMOVE_STREAM (§2.2.5.2.7) — 20 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `StreamId` |

- [ ] `FunctionId=0x00000115`
- [ ] Client MUST free all resources for this (PresentationId, StreamId) pair

#### 4.12 SHUTDOWN_PRESENTATION_REQ (§2.2.5.2.8) — 16 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |

- [ ] `FunctionId=0x00000106`
- [ ] Client MUST respond with SHUTDOWN_PRESENTATION_RSP

#### 4.13 SHUTDOWN_PRESENTATION_RSP (§2.2.5.2.9) — 4 bytes payload — C→S

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `Result` (HRESULT, S_OK=0x00000000) |

- [ ] `Mask=STREAM_ID_STUB`, echoed `MessageId` from REQ

#### 4.14 SET_VIDEO_WINDOW (§2.2.5.2.10) — 32 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 8 | u64 LE | `VideoWindowId` (server-side HWND) |
| 24 | 8 | u64 LE | `HwndParent` (parent HWND on server) |

- [ ] `FunctionId=0x00000104`
- [ ] Both window handle values are server-side; client uses them for identification only (display on client side has no corresponding HWND)

#### 4.15 UPDATE_GEOMETRY_INFO (§2.2.5.2.11) — variable payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `numGeometryInfo` (byte count of pGeoInfo) |
| 20 | variable | GEOMETRY_INFO (as bytes) | `pGeoInfo` |
| 20+N | 4 | u32 LE | `cbVisibleRect` (byte count of pVisibleRect) |
| 24+N | variable | TS_RECT[] (as bytes) | `pVisibleRect` |

- [ ] `FunctionId=0x00000114`
- [ ] `numGeometryInfo` is byte count, not element count; determines GEOMETRY_INFO size (44 or 48 bytes depending on optional Padding)
- [ ] `cbVisibleRect` is byte count; must be multiple of 16 (each TS_RECT is 16 bytes)
- [ ] TS_RECT count = `cbVisibleRect / 16`; reject if not multiple of 16

#### 4.16 SET_SOURCE_VIDEO_RECT (§2.2.5.2.12) — 32 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | f32 LE | `Left` (normalized [0.0, 1.0]) |
| 20 | 4 | f32 LE | `Top` (normalized [0.0, 1.0]) |
| 24 | 4 | f32 LE | `Right` (normalized [0.0, 1.0]) |
| 28 | 4 | f32 LE | `Bottom` (normalized [0.0, 1.0]) |

- [ ] `FunctionId=0x00000116` — NOTE: spec says "REMOVE_STREAM (0x00000116)" in §2.2.5.2.12 but this is a documentation error; the function name is SET_SOURCE_VIDEO_RECT and value is 0x00000116, while REMOVE_STREAM is 0x00000115

#### 4.17 SET_ALLOCATOR (§2.2.5.3.1) — 36 bytes payload — S→C (MAY)

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `StreamId` |
| 20 | 4 | u32 LE | `cBuffers` |
| 24 | 4 | u32 LE | `cbBuffer` (bytes per buffer, excluding prefix) |
| 28 | 4 | u32 LE | `cbAlign` (alignment in bytes) |
| 32 | 4 | u32 LE | `cbPrefix` (prefix bytes before each buffer) |

- [ ] `FunctionId=0x00000112`
- [ ] MAY be omitted by server; client implementation SHOULD allocate from this hint but MUST NOT require it

#### 4.18 NOTIFY_PREROLL (§2.2.5.3.2) — 20 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `StreamId` |

- [ ] `FunctionId=0x00000113`
- [ ] Indicates preloading phase; client should buffer samples before rendering

#### 4.19 ON_SAMPLE (§2.2.5.3.3) — variable payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `StreamId` |
| 20 | 4 | u32 LE | `numSample` (byte count of TS_MM_DATA_SAMPLE) |
| 24 | variable | TS_MM_DATA_SAMPLE (as bytes) | `pSample` |

- [ ] `FunctionId=0x00000103`
- [ ] `numSample` is the byte count of the serialized `TS_MM_DATA_SAMPLE`; MUST equal `36 + cbData` (matches the 36-byte fixed header in §5.2)

#### 4.20 ON_FLUSH (§2.2.5.3.4) — 20 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `StreamId` |

- [ ] `FunctionId=0x0000010e`
- [ ] Client MUST flush the decoder state for this stream (seek/discontinuity)

#### 4.21 ON_END_OF_STREAM (§2.2.5.3.5) — 20 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `StreamId` |

- [ ] `FunctionId=0x00000111`

#### 4.22 PLAYBACK_ACK (§2.2.6.1) — 20 bytes payload — C→S

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `StreamId` |
| 4 | 8 | u64 LE | `DataDuration` (ThrottleDuration from acknowledged sample) |
| 12 | 8 | u64 LE | `cbData` (cbData from acknowledged TS_MM_DATA_SAMPLE) |

- [ ] `InterfaceValue=0x00000001`, `Mask=STREAM_ID_PROXY (0x40000001)`, `FunctionId=0x00000100`
- [ ] MUST be sent for every ON_SAMPLE received (1:1 mapping)
- [ ] `DataDuration` MUST equal `ThrottleDuration` from the corresponding `TS_MM_DATA_SAMPLE`
- [ ] `cbData` MUST equal the `cbData` field of the corresponding `TS_MM_DATA_SAMPLE`
- [ ] Note: no PresentationId in PLAYBACK_ACK; StreamId alone identifies the stream

#### 4.23 CLIENT_EVENT_NOTIFICATION (§2.2.6.2) — variable payload — C→S

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `StreamId` |
| 4 | 4 | u32 LE | `EventId` |
| 8 | 4 | u32 LE | `cbData` (byte count of pBlob) |
| 12 | variable | u8[] | `pBlob` |

- [ ] `InterfaceValue=0x00000001`, `Mask=STREAM_ID_PROXY (0x40000001)`, `FunctionId=0x00000101`

#### 4.24 ON_PLAYBACK_STARTED (§2.2.5.4.1) — 28 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 8 | u64 LE | `PlaybackStartOffset` (100-ns units) |
| 24 | 4 | u32 LE | `IsSeek` (0=normal start, 1=seek) |

- [ ] `FunctionId=0x00000109`

#### 4.25 ON_PLAYBACK_PAUSED (§2.2.5.4.2) — 16 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |

- [ ] `FunctionId=0x0000010a`

#### 4.26 ON_PLAYBACK_STOPPED (§2.2.5.4.3) — 16 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |

- [ ] `FunctionId=0x0000010b`

#### 4.27 ON_PLAYBACK_RESTARTED (§2.2.5.4.4) — 16 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |

- [ ] `FunctionId=0x0000010c`

#### 4.28 ON_PLAYBACK_RATE_CHANGED (§2.2.5.4.5) — 20 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | f32 LE | `NewRate` (playback rate, 1.0 = normal) |

- [ ] `FunctionId=0x0000010d`
- [ ] `NewRate` is an f32 (IEEE 754 single-precision), not u32

#### 4.29 ON_STREAM_VOLUME (§2.2.5.5.1) — 24 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `NewVolume` |
| 20 | 4 | u32 LE | `bMuted` (0=not muted, 1=muted) |

- [ ] `FunctionId=0x0000010f`

#### 4.30 ON_CHANNEL_VOLUME (§2.2.5.5.2) — 24 bytes payload — S→C

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `PresentationId` |
| 16 | 4 | u32 LE | `ChannelVolume` |
| 20 | 4 | u32 LE | `ChangedChannel` (channel identifier) |

- [ ] `FunctionId=0x00000110`

---

### 5. Sub-structures

#### 5.1 TS_AM_MEDIA_TYPE (§2.2.7) — variable

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 16 | GUID | `MajorType` |
| 16 | 16 | GUID | `SubType` |
| 32 | 4 | u32 LE | `bFixedSizeSamples` (0 or 1) |
| 36 | 4 | u32 LE | `bTemporalCompression` (0 or 1) |
| 40 | 4 | u32 LE | `SampleSize` |
| 44 | 16 | GUID | `FormatType` |
| 60 | 4 | u32 LE | `cbFormat` (byte count of pbFormat) |
| 64 | variable | u8[] | `pbFormat` |

- [ ] Fixed header: 64 bytes; total = 64 + `cbFormat`
- [ ] `MajorType`, `SubType`, `FormatType` are GUID values passed transparently from server media pipeline
- [ ] `pbFormat` is a format-specific blob (e.g., WAVEFORMATEX for audio)
- [ ] GUID encoding: MS-DTYP §2.3.4.2 (mixed-endian: first 4 bytes LE, next 2 LE, next 2 LE, last 8 bytes big-endian)

#### 5.2 TS_MM_DATA_SAMPLE (§2.2.8) — variable

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 8 | i64 LE | `SampleStartTime` (signed, 100-ns units) |
| 8 | 8 | i64 LE | `SampleEndTime` (signed, 100-ns units) |
| 16 | 8 | u64 LE | `ThrottleDuration` (server-unit throttle hint) |
| 24 | 4 | u32 LE | `SampleFlags` (reserved, MUST be ignored) |
| 28 | 4 | u32 LE | `SampleExtensions` (bitmask) |
| 32 | 4 | u32 LE | `cbData` (byte count of pData) |
| 36 | variable | u8[] | `pData` (encoded media data) |

- [ ] Fixed header: 36 bytes; total = 36 + `cbData`
- [ ] `SampleStartTime` / `SampleEndTime` are **signed** 64-bit integers
- [ ] `ThrottleDuration` is **unsigned** 64-bit integer; units are server-defined
- [ ] When `SampleExtensions` bit 7 (`TSMM_SAMPLE_EXT_HAS_NO_TIMESTAMPS`) = 1, timestamps are invalid
- [ ] `SampleFlags` MUST be ignored on receipt (reserved field)

#### 5.3 GEOMETRY_INFO (§2.2.11) — 44 or 48 bytes

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 8 | u64 LE | `VideoWindowId` (server HWND) |
| 8 | 4 | u32 LE | `VideoWindowState` (TS_WNDFLAG bitmask) |
| 12 | 4 | u32 LE | `Width` (pixels) |
| 16 | 4 | u32 LE | `Height` (pixels) |
| 20 | 4 | u32 LE | `Left` (screen coordinates) |
| 24 | 4 | u32 LE | `Top` (screen coordinates) |
| 28 | 8 | u64 LE | `Reserved` (MUST be ignored) |
| 36 | 4 | u32 LE | `ClientLeft` |
| 40 | 4 | u32 LE | `ClientTop` |
| 44 | 4 | u32 LE | `Padding` (OPTIONAL; present iff `numGeometryInfo=48`) |

- [ ] Presence of `Padding` field detected by `numGeometryInfo` value in UPDATE_GEOMETRY_INFO
- [ ] If `numGeometryInfo=44`: no Padding field; if `numGeometryInfo=48`: Padding present, MUST be ignored

#### 5.4 TS_RECT (§2.2.12) — 16 bytes fixed

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 4 | u32 LE | `Top` |
| 4 | 4 | u32 LE | `Left` |
| 8 | 4 | u32 LE | `Bottom` |
| 12 | 4 | u32 LE | `Right` |

- [ ] Coordinates in client screen space
- [ ] Note field order: Top, Left, Bottom, Right (not the typical Left, Top, Right, Bottom)

---

### 6. Constants

#### 6.1 Mask Values (MS-RDPEV §2.2.1) — packed into upper 2 bits of InterfaceId u32

| Name | Value (u32) | Description |
|------|-------------|-------------|
| `STREAM_ID_STUB` | 0x80000000 | Response message (no FunctionId) |
| `STREAM_ID_PROXY` | 0x40000000 | Request message (FunctionId present) |
| `STREAM_ID_NONE` | 0x00000000 | Interface manipulation only |

#### 6.2 CapabilityType Values (MS-RDPEV §2.2.4.3)

| Name | Value | pCapabilityData type |
|------|------:|---------------------|
| `TSMM_CAPABILITY_TYPE_VERSION` | 0x00000001 | u32 LE; MUST be 0x00000002 |
| `TSMM_CAPABILITY_TYPE_PLATFORM` | 0x00000002 | u32 LE; union of MMREDIR_CAPABILITY_PLATFORM |
| `TSMM_CAPABILITY_TYPE_AUDIOSUPPORT` | 0x00000003 | u32 LE; MMREDIR_CAPABILITY_AUDIOSUPPORT |
| `TSMM_CAPABILITY_TYPE_LATENCY` | 0x00000004 | u32 LE; one-way latency in milliseconds |

#### 6.3 MMREDIR_CAPABILITY_PLATFORM flags (MS-RDPEV §2.2.10)

| Name | Value |
|------|------:|
| `MMREDIR_CAPABILITY_PLATFORM_MF` | 0x00000001 |
| `MMREDIR_CAPABILITY_PLATFORM_DSHOW` | 0x00000002 |
| `MMREDIR_CAPABILITY_PLATFORM_OTHER` | 0x00000004 |

#### 6.4 MMREDIR_CAPABILITY_AUDIOSUPPORT constants (MS-RDPEV §2.2.15)

| Name | Value |
|------|------:|
| `MMREDIR_CAPABILITY_AUDIO_SUPPORTED` | 0x00000001 |
| `MMREDIR_CAPABILITY_AUDIO_NO_DEVICE` | 0x00000002 |

#### 6.5 TSMM_PLATFORM_COOKIE values (MS-RDPEV §2.2.9)

| Name | Value |
|------|------:|
| `TSMM_PLATFORM_COOKIE_UNDEFINED` | 0x00000000 |
| `TSMM_PLATFORM_COOKIE_MF` | 0x00000001 |
| `TSMM_PLATFORM_COOKIE_DSHOW` | 0x00000002 |

#### 6.6 SampleExtensions flags (MS-RDPEV §2.2.8) — bits in u32

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `TSMM_SAMPLE_EXT_CLEANPOINT` | Video key frame; decoding SHOULD begin from this sample |
| 1 | `TSMM_SAMPLE_EXT_DISCONTINUITY` | First sample after a gap |
| 2 | `TSMM_SAMPLE_EXT_INTERLACED` | Interlaced frame |
| 3 | `TSMM_SAMPLE_EXT_BOTTOMFIELDFIRST` | Bottom field displayed first |
| 4 | `TSMM_SAMPLE_EXT_REPEATFIELDFIRST` | Repeat first field |
| 5 | `TSMM_SAMPLE_EXT_SINGLEFIELD` | Sample contains one field only |
| 6 | `TSMM_SAMPLE_EXT_DERIVEDFROMTOPFIELD` | Lower field interpolated from upper |
| 7 | `TSMM_SAMPLE_EXT_HAS_NO_TIMESTAMPS` | No valid timestamps in SampleStartTime/SampleEndTime |
| 8 | `TSMM_SAMPLE_EXT_RELATIVE_TIMESTAMPS` | Timestamps relative to presentation start |
| 9 | `TSMM_SAMPLE_EXT_ABSOLUTE_TIMESTAMPS` | Timestamps are absolute reference clock values |

#### 6.7 TS_WNDFLAG flags (MS-RDPEV §2.2.13) — u32 bitmask

| Name | Value |
|------|------:|
| `TS_WNDFLAG_NEW` | 0x00000001 |
| `TS_WNDFLAG_DELETED` | 0x00000002 |
| `TS_WNDFLAG_VISRGN` | 0x00001000 |

---

### 7. Protocol Sequences / State Machine

#### 7.1 Connection Initialization Sequence (MS-RDPEV §1.3.1)

```
DVC channel opened
  --[S: SET_CHANNEL_PARAMS (StreamId=0)]--> client creates PresentationContext(StreamId=0)
  --[S: EXCHANGE_CAPABILITIES_REQ]--> client parses server capabilities
  --[C: EXCHANGE_CAPABILITIES_RSP]--> server receives client capabilities
  --> INITIALIZED state (per channel)
```

- [ ] SET_CHANNEL_PARAMS MUST come before EXCHANGE_CAPABILITIES_REQ
- [ ] MessageId in EXCHANGE_CAPABILITIES_REQ MUST be echoed in the RSP
- [ ] After capabilities exchange, server knows which platform the client supports

#### 7.2 Presentation Setup Sequence (MS-RDPEV §1.3.2)

```
INITIALIZED
  --[S: ON_NEW_PRESENTATION(PresentationId)]--> create PresentationContext
  --[S: CHECK_FORMAT_SUPPORT_REQ x N]--> per stream format
  --[C: CHECK_FORMAT_SUPPORT_RSP x N]--> client answers each
  --[S: ADD_STREAM(PresentationId, StreamId, MediaType) x N]--> create StreamContext
  --[S: SET_TOPOLOGY_REQ(PresentationId)]--> finalize topology
  --[C: SET_TOPOLOGY_RSP(TopologyReady=1, Result=S_OK)]--> ready
  --> PRESENTATION_READY state
```

- [ ] Multiple CHECK_FORMAT_SUPPORT_REQ may be in-flight; each has unique MessageId
- [ ] All ADD_STREAM messages arrive before SET_TOPOLOGY_REQ
- [ ] Client MUST NOT send any other message between SET_TOPOLOGY_REQ and SET_TOPOLOGY_RSP

#### 7.3 Data Streaming Sequence (MS-RDPEV §1.3.3)

```
PRESENTATION_READY
  --[S: SET_ALLOCATOR(optional)]--> client may adjust buffer pools
  --[S: NOTIFY_PREROLL(StreamId)]--> begin buffering
  --[S: ON_PLAYBACK_STARTED]--> start rendering
  --[S: ON_SAMPLE(StreamId, TS_MM_DATA_SAMPLE) x N]--> media data
  --[C: PLAYBACK_ACK(StreamId, DataDuration, cbData) x N]--> per-sample ACK
  --[S: ON_FLUSH(StreamId)] (on seek) --> client flushes decoder
  --[S: ON_PLAYBACK_PAUSED]--> pause
  --[S: ON_PLAYBACK_RESTARTED]--> resume
  --[S: ON_END_OF_STREAM(StreamId)]--> stream complete
  --[S: ON_PLAYBACK_STOPPED]--> stop
  --> STREAMING state (while samples flowing)
```

- [ ] PLAYBACK_ACK is 1:1 with ON_SAMPLE — one ACK per sample received
- [ ] ON_FLUSH requires decoder pipeline flush (important for seek correctness)
- [ ] CLEANPOINT bit in SampleExtensions identifies keyframes; decoder SHOULD seek to next keyframe after discontinuity

#### 7.4 Presentation Teardown Sequence (MS-RDPEV §1.3.4)

```
STREAMING or PRESENTATION_READY
  --[S: REMOVE_STREAM(PresentationId, StreamId) x N]--> free stream resources
  --[S: SHUTDOWN_PRESENTATION_REQ(PresentationId)]--> shutdown
  --[C: SHUTDOWN_PRESENTATION_RSP(Result=S_OK)]--> confirm
  --> IDLE (presentation removed)
```

- [ ] MessageId in SHUTDOWN_PRESENTATION_REQ echoed in RSP
- [ ] Client MUST free all stream resources associated with PresentationId

#### 7.5 Volume Handling Sequence (MS-RDPEV §1.3.5)

```
Any state (interleaved):
  --[S: ON_STREAM_VOLUME(PresentationId, NewVolume, bMuted)]--> set master volume
  --[S: ON_CHANNEL_VOLUME(PresentationId, ChannelVolume, ChangedChannel)]--> set channel volume
```

- [ ] Volume messages may arrive at any time; no response required

#### 7.6 Geometry Update Sequence (MS-RDPEV §1.3.6)

```
Any state (interleaved):
  --[S: SET_VIDEO_WINDOW]--> server window handle info
  --[S: UPDATE_GEOMETRY_INFO]--> window position/visibility update
  --[S: SET_SOURCE_VIDEO_RECT]--> source crop rectangle
```

---

### 8. Implementation Sub-Steps

#### Step 2A: Crate Skeleton + SHARED_MSG_HEADER

- [ ] Create `crates/justrdp-rdpev/Cargo.toml` (`no_std`, `forbid(unsafe_code)`)
- [ ] `src/lib.rs` with `#![forbid(unsafe_code)]`, `#![no_std]`, `extern crate alloc`
- [ ] Implement `SharedMsgHeader` struct with InterfaceId (u32, packing InterfaceValue+Mask), MessageId (u32), optional FunctionId (u32)
- [ ] `Mask` enum: `STREAM_ID_STUB=0x80000000`, `STREAM_ID_PROXY=0x40000000`, `STREAM_ID_NONE=0x00000000`
- [ ] `Mask` extraction: `(interface_id_raw >> 30) & 0x3` → map to enum
- [ ] `InterfaceValue` extraction: `interface_id_raw & 0x3FFF_FFFF`
- [ ] `Encode`/`Decode` for `SharedMsgHeader` (12 bytes for requests, 8 bytes for responses)
- [ ] All FunctionId constants in `src/constants.rs`
- [ ] Roundtrip test: SET_CHANNEL_PARAMS example from spec §4 (wire vector)

#### Step 2B: Capability PDUs + `TsmmCapabilities`

- [ ] `TsmmCapabilities` struct with `CapabilityType` (u32) + `pCapabilityData` (`Vec<u8>`)
- [ ] `ExchangeCapabilitiesReq` struct: `Vec<TsmmCapabilities>`
- [ ] `ExchangeCapabilitiesRsp` struct: `Vec<TsmmCapabilities>` + `Result` (u32)
- [ ] Encode/Decode both; RSP has no FunctionId field
- [ ] Test: roundtrip exchange capabilities from spec §4 examples
- [ ] Cap: `MAX_CAPABILITIES = 16` (spec defines only 4 types; 16 is generous)

#### Step 2C: Presentation Lifecycle PDUs

- [ ] `SetChannelParams` (PresentationId GUID + StreamId u32)
- [ ] `NewPresentation` (PresentationId + PlatformCookie)
- [ ] `ShutdownPresentationReq` (PresentationId)
- [ ] `ShutdownPresentationRsp` (Result u32)
- [ ] `SetTopologyReq` (PresentationId)
- [ ] `SetTopologyRsp` (TopologyReady u32 + Result u32)
- [ ] GUID Encode/Decode: MS-DTYP §2.3.4.2 mixed-endian (first 8 bytes little-endian in 3 fields, last 8 bytes big-endian)
- [ ] Test: roundtrip Presentation Initialization examples from spec §4

#### Step 2D: Format Negotiation PDUs + TS_AM_MEDIA_TYPE

- [ ] `TsAmMediaType` struct: MajorType (GUID) + SubType (GUID) + bFixedSizeSamples (u32) + bTemporalCompression (u32) + SampleSize (u32) + FormatType (GUID) + `pbFormat` (`Vec<u8>`)
- [ ] Size: 64 bytes fixed + `pbFormat.len()` bytes
- [ ] `CheckFormatSupportReq` struct: PlatformCookie (u32) + NoRolloverFlags (u32) + `pMediaType` (`TsAmMediaType` serialized as bytes with `numMediaType` length prefix)
- [ ] `CheckFormatSupportRsp` struct: FormatSupported (u32) + PlatformCookie (u32) + Result (u32)
- [ ] Cap: `MAX_FORMAT_BYTES = 65536` (format blobs are not unbounded but no spec limit given; 64 KiB is safe)
- [ ] Test: roundtrip CHECK_FORMAT_SUPPORT_REQ/RSP wire vectors from spec §4

#### Step 2E: Stream Management PDUs

- [ ] `AddStream` struct: PresentationId + StreamId + `pMediaType` (TsAmMediaType)
- [ ] `RemoveStream` struct: PresentationId + StreamId
- [ ] Test: ADD_STREAM wire vector from spec §4

#### Step 2F: Sample PDUs + TS_MM_DATA_SAMPLE

- [ ] `TsMmDataSample` struct: SampleStartTime (i64) + SampleEndTime (i64) + ThrottleDuration (u64) + SampleFlags (u32) + SampleExtensions (u32) + `pData` (`Vec<u8>` via cbData)
- [ ] Size: 36 bytes fixed + `pData.len()` bytes
- [ ] `OnSample` struct: PresentationId + StreamId + pSample (TsMmDataSample)
- [ ] `PlaybackAck` struct: StreamId (u32) + DataDuration (u64) + cbData (u64)
- [ ] Note: PlaybackAck header InterfaceValue=0x00000001 (not 0x00000000)
- [ ] Cap: `MAX_SAMPLE_BYTES = 16_777_216` (16 MiB)
- [ ] Test: ON_SAMPLE wire vector from spec §4 (2090-byte example)

#### Step 2G: Playback Control PDUs

- [ ] `NotifyPreroll` (PresentationId + StreamId)
- [ ] `OnPlaybackStarted` (PresentationId + PlaybackStartOffset u64 + IsSeek u32)
- [ ] `OnPlaybackPaused` (PresentationId)
- [ ] `OnPlaybackStopped` (PresentationId)
- [ ] `OnPlaybackRestarted` (PresentationId)
- [ ] `OnPlaybackRateChanged` (PresentationId + NewRate **f32**)
- [ ] `OnFlush` (PresentationId + StreamId)
- [ ] `OnEndOfStream` (PresentationId + StreamId)
- [ ] All as no-payload-response fire-and-forget server→client
- [ ] Test: NOTIFY_PREROLL and ON_FLUSH wire vectors from spec §4

#### Step 2H: Volume + Geometry PDUs

- [ ] `OnStreamVolume` (PresentationId + NewVolume u32 + bMuted u32)
- [ ] `OnChannelVolume` (PresentationId + ChannelVolume u32 + ChangedChannel u32)
- [ ] `SetVideoWindow` (PresentationId + VideoWindowId u64 + HwndParent u64)
- [ ] `GeometryInfo` struct (VideoWindowId u64 + VideoWindowState u32 + Width u32 + Height u32 + Left u32 + Top u32 + Reserved u64 + ClientLeft u32 + ClientTop u32 + optional Padding u32)
- [ ] `TsRect` struct (Top u32 + Left u32 + Bottom u32 + Right u32) — note field order
- [ ] `UpdateGeometryInfo` (PresentationId + numGeometryInfo u32 + GeometryInfo + cbVisibleRect u32 + TsRect[])
- [ ] `SetSourceVideoRect` (PresentationId + Left f32 + Top f32 + Right f32 + Bottom f32)
- [ ] `SetAllocator` (PresentationId + StreamId + cBuffers u32 + cbBuffer u32 + cbAlign u32 + cbPrefix u32)
- [ ] `ClientEventNotification` (StreamId u32 + EventId u32 + pBlob Vec<u8>)
- [ ] Test: SET_ALLOCATOR wire vector from spec §4

#### Step 2I: RdpevClient DvcProcessor + State Machine

- [ ] `PresentationState` enum: `Uninitialized`, `Initialized`, `Setup`, `Streaming`, `Terminated`
- [ ] `StreamContext` struct: `stream_id`, `media_type`, `state`
- [ ] `PresentationContext` struct: `presentation_id` GUID, `streams: HashMap<u32, StreamContext>`, `state`
- [ ] `RdpevClient` struct: `presentations: HashMap<[u8;16], PresentationContext>`, `pending_requests: HashMap<u32, PendingRequest>`, `channel_state`, `media_sink: Box<dyn TsmfMediaSink>`
- [ ] `TsmfMediaSink` trait (platform injection, object-safe):
  ```
  fn check_format_support(media_type: &TsAmMediaType, platform_cookie: u32, no_rollover: bool) -> (bool, u32)
  fn add_stream(presentation_id: &[u8;16], stream_id: u32, media_type: &TsAmMediaType)
  fn on_sample(presentation_id: &[u8;16], stream_id: u32, sample: &TsMmDataSample)
  fn on_flush(presentation_id: &[u8;16], stream_id: u32)
  fn on_playback_started(presentation_id: &[u8;16], offset: u64, is_seek: bool)
  fn on_playback_paused(presentation_id: &[u8;16])
  fn on_playback_stopped(presentation_id: &[u8;16])
  fn on_end_of_stream(presentation_id: &[u8;16], stream_id: u32)
  fn set_volume(presentation_id: &[u8;16], volume: u32, muted: bool)
  fn update_geometry(presentation_id: &[u8;16], geo: &GeometryInfo, visible_rects: &[TsRect])
  fn shutdown_presentation(presentation_id: &[u8;16])
  ```
- [ ] `impl DvcProcessor for RdpevClient` with message dispatch
- [ ] `is_send_state()` equivalent if needed by DVC framework
- [ ] Provide `NoopTsmfMediaSink` stub for tests

#### Step 2J: Integration Tests

- [ ] Test: full capability exchange roundtrip (server sends REQ, client responds RSP)
- [ ] Test: format check pipeline (multiple in-flight CHECK_FORMAT_SUPPORT_REQ with different MessageIds)
- [ ] Test: presentation lifecycle (ON_NEW_PRESENTATION → ADD_STREAM → SET_TOPOLOGY_REQ/RSP → ON_SAMPLE+PLAYBACK_ACK loop → REMOVE_STREAM → SHUTDOWN_PRESENTATION_REQ/RSP)
- [ ] Test: seek sequence (ON_FLUSH followed by ON_SAMPLE with CLEANPOINT)
- [ ] Test: malformed message rejection (cbData exceeds MAX_SAMPLE_BYTES, cbFormat exceeds MAX_FORMAT_BYTES, numGeometryInfo not 44 or 48)

---

### 9. Validation Rules

- [ ] `InterfaceValue` != 0x00000000 and not from prior QI_RSP → reject message (unknown interface)
- [ ] `FunctionId` not in defined set for InterfaceValue → ignore (UnsupportedFunction stub)
- [ ] Response (Mask=STREAM_ID_STUB) with unknown MessageId → discard (no matching pending request)
- [ ] `cbData` in TS_MM_DATA_SAMPLE > `MAX_SAMPLE_BYTES (16 MiB)` → close DVC
- [ ] `cbFormat` in TS_AM_MEDIA_TYPE > `MAX_FORMAT_BYTES (65536)` → close DVC
- [ ] `numSample` in ON_SAMPLE != 36 + cbData → close DVC (structure size mismatch)
- [ ] `numMediaType` in ADD_STREAM/CHECK_FORMAT_SUPPORT_REQ != 64 + cbFormat → close DVC
- [ ] `numGeometryInfo` in UPDATE_GEOMETRY_INFO not in {44, 48} → close DVC
- [ ] `cbVisibleRect` not a multiple of 16 → close DVC
- [ ] SET_TOPOLOGY_RSP not sent immediately after SET_TOPOLOGY_REQ → server behavior undefined
- [ ] PLAYBACK_ACK not sent for each ON_SAMPLE → server throttling stalls

---

### 10. DoS Safety Caps

| Constant | Value | Rationale |
|----------|------:|-----------|
| `MAX_SAMPLE_BYTES` | 16_777_216 (16 MiB) | Full 1080p H.264 I-frame headroom; cbData is u32 (4 GiB max) |
| `MAX_FORMAT_BYTES` | 65_536 (64 KiB) | Format blobs (WAVEFORMATEX, VIDEOINFOHEADER) are typically < 1 KiB |
| `MAX_CAPABILITIES` | 16 | Only 4 types defined; 16 is safe |
| `MAX_STREAMS_PER_PRESENTATION` | 64 | Typical A/V presentations have 2–4 streams |
| `MAX_PRESENTATIONS` | 16 | Concurrent presentations from multiple server apps |
| `MAX_VISIBLE_RECTS` | 256 | Each TS_RECT is 16 bytes; 256 × 16 = 4096 bytes |
| `MAX_PENDING_REQUESTS` | 32 | Outstanding CHECK_FORMAT_SUPPORT_REQ correlation table |
| `MAX_EVENT_BLOB_BYTES` | 4_096 | CLIENT_EVENT_NOTIFICATION pBlob |

---

### 11. Test Vectors from Spec §4

All from MS-RDPEV version 18.0 spec §4 Examples section.

#### 11.1 SET_CHANNEL_PARAMS (§4 — Channel Setup Sequence)
```
00 00 00 40  -> InterfaceId = 0x00000000 | STREAM_ID_PROXY (0x40000000)
00 00 00 00  -> MessageId = 0x00000000
01 01 00 00  -> FunctionId = SET_CHANNEL_PARAMS (0x00000101)
4a 2a fd 28  -> PresentationId GUID = {28fd2a4a-efc7-44a0-bbca-f31789969fd2}
c7 ef a0 44
bb ca f3 17
89 96 9f d2
00 00 00 00  -> StreamId = 0x00000000
```
Total wire: 32 bytes (12 header + 16 GUID + 4 StreamId)

#### 11.2 EXCHANGE_CAPABILITIES_REQ (§4 — Channel Setup Sequence)
```
00 00 00 40  -> InterfaceId = 0x00000000 | STREAM_ID_PROXY
00 00 00 00  -> MessageId = 0x00000000
00 01 00 00  -> FunctionId = EXCHANGE_CAPABILITIES_REQ (0x00000100)
02 00 00 00  -> numHostCapabilities = 2
01 00 00 00  -> CapabilityType = TSMM_CAPABILITY_TYPE_VERSION (0x01)
04 00 00 00  -> cbCapabilityLength = 4
02 00 00 00  -> pCapabilityData = version 2
02 00 00 00  -> CapabilityType = TSMM_CAPABILITY_TYPE_PLATFORM (0x02)
04 00 00 00  -> cbCapabilityLength = 4
01 00 00 00  -> pCapabilityData = MMREDIR_CAPABILITY_PLATFORM_MF (0x01)
```
Total wire: 40 bytes

#### 11.3 EXCHANGE_CAPABILITIES_RSP (§4 — Channel Setup Sequence)
```
00 00 00 80  -> InterfaceId = 0x00000000 | STREAM_ID_STUB (0x80000000)
00 00 00 00  -> MessageId = 0x00000000 (echoed from REQ)
02 00 00 00  -> numClientCapabilities = 2
01 00 00 00  -> CapabilityType = VERSION
04 00 00 00  -> cbCapabilityLength = 4
02 00 00 00  -> version = 2
02 00 00 00  -> CapabilityType = PLATFORM
04 00 00 00  -> cbCapabilityLength = 4
03 00 00 00  -> MF|DShow (0x01|0x02 = 0x03)
00 00 00 00  -> Result = S_OK
```
Total wire: 40 bytes (8 response header + 32 payload)

#### 11.4 ON_NEW_PRESENTATION (§4 — Presentation Init Sequence)
```
00 00 00 40  -> InterfaceId = 0x00000000 | STREAM_ID_PROXY
00 00 00 00  -> MessageId = 0x00000000
05 01 00 00  -> FunctionId = ON_NEW_PRESENTATION (0x00000105)
9f 04 86 e0  -> PresentationId = {e086049f-d926-45ae-8c0f-3e056af3f7d4}
26 d9 ae 45
8c 0f 3e 05
6a f3 f7 d4
02 00 00 00  -> PlatformCookie = TSMM_PLATFORM_COOKIE_DSHOW (0x02)
```
Total wire: 32 bytes

#### 11.5 SET_TOPOLOGY_RSP (§4 — Presentation Init Sequence)
```
00 00 00 80  -> InterfaceId = 0x00000000 | STREAM_ID_STUB
00 00 00 00  -> MessageId = 0x00000000
01 00 00 00  -> TopologyReady = 1
00 00 00 00  -> Result = S_OK
```
Total wire: 16 bytes

#### 11.6 CHECK_FORMAT_SUPPORT_RSP (§4 — Presentation Init Sequence)
```
00 00 00 80  -> InterfaceId = 0x00000000 | STREAM_ID_STUB
00 00 00 00  -> MessageId = 0x00000000
01 00 00 00  -> FormatSupported = 1
01 00 00 00  -> PlatformCookie = TSMM_PLATFORM_COOKIE_MF (0x01)
00 00 00 00  -> Result = S_OK
```
Total wire: 20 bytes

#### 11.7 ON_SAMPLE partial (§4 — Data Streaming Sequence)
```
00 00 00 40  -> InterfaceId = STREAM_ID_PROXY
00 00 00 00  -> MessageId
03 01 00 00  -> ON_SAMPLE (0x00000103)
79 40 84 8b  -> PresentationId = {8b844079-b70e-450f-8793-3d7ffa31d053}
0e b7 0f 45
87 93 3d 7f
fa 31 d0 53
01 00 00 00  -> StreamId = 1
06 08 00 00  -> numSample = 0x0806 = 2054 bytes
37 00 00 00  -> SampleStartTime = 0x37 (low 32 bits)
00 00 00 00  -> SampleStartTime high
38 00 00 00  -> SampleEndTime = 0x38 (low 32 bits)
00 00 00 00
15 16 05 00  -> ThrottleDuration = 0x51615 (low)
00 00 00 00
00 00 00 00  -> SampleFlags = 0 (reserved)
03 00 00 00  -> SampleExtensions = CLEANPOINT|DISCONTINUITY (0x03)
e2 07 00 00  -> cbData = 0x07e2 = 2018 bytes
[2018 bytes of encoded media data follow]
```

#### 11.8 SET_ALLOCATOR (§4 — Data Streaming Sequence)
```
00 00 00 40  -> STREAM_ID_PROXY
00 00 00 00  -> MessageId
12 01 00 00  -> SET_ALLOCATOR (0x00000112)
79 40 84 8b  -> PresentationId = {8b844079-b70e-450f-8793-3d7ffa31d053}
0e b7 0f 45
87 93 3d 7f
fa 31 d0 53
01 00 00 00  -> StreamId = 1
64 00 00 00  -> cBuffers = 100
05 00 01 00  -> cbBuffer = 0x10005 = 65541 bytes
01 00 00 00  -> cbAlign = 1
00 00 00 00  -> cbPrefix = 0
```
Total wire: 48 bytes

---

### 12. Boundary / Edge Cases

- [ ] `cbData = 0` in TS_MM_DATA_SAMPLE: zero-length sample is valid (EOS signal or filler); pData field is absent
- [ ] `cbFormat = 0` in TS_AM_MEDIA_TYPE: valid (format has no extra blob); pbFormat field is absent
- [ ] `numHostCapabilities = 0` / `numClientCapabilities = 0`: valid (empty array)
- [ ] `numGeometryInfo = 0`: invalid; must be 44 or 48
- [ ] `cbVisibleRect = 0`: valid (no visible region = window hidden)
- [ ] `StreamId = 0x00000000` in ON_SAMPLE: invalid per spec §2.2.5.1; reject
- [ ] `EXCHANGE_CAPABILITIES_REQ` with unknown CapabilityType (not 1–4): parse as raw bytes, store, forward to sink for possible future use; do not reject
- [ ] `SampleExtensions` bits 10–31 set: reserved; MUST be ignored on receipt
- [ ] GUID fields: all 16 bytes must be parsed correctly using MS-DTYP mixed-endian encoding
- [ ] `TopologyReady = 0` in SET_TOPOLOGY_RSP: presentation setup failed; server closes associated streams
- [ ] MessageId wrap-around: valid, u32 wraps from 0xFFFFFFFF to 0x00000000; pending request table must handle correctly

---

### 13. Spec Ambiguities / Flags

1. **AMBIGUITY: FunctionId in response headers.** The spec §2.2.1 states "FunctionId MUST be present in all packets except response packets." However, the annotated wire examples show responses ending at MessageId+4 bytes (i.e., 8 bytes total for header). Implement: response headers are 8 bytes (InterfaceId + MessageId only); FunctionId is absent.

2. **AMBIGUITY: SET_SOURCE_VIDEO_RECT FunctionId documentation error.** The spec §2.2.5.2.12 says `FunctionId MUST be set to REMOVE_STREAM (0x00000116)` but REMOVE_STREAM is §2.2.5.2.7 with value 0x00000115. The correct value for SET_SOURCE_VIDEO_RECT is 0x00000116. Implement as 0x00000116.

3. **AMBIGUITY: PLAYBACK_ACK InterfaceId.** The spec §2.2.6.1 says InterfaceId MUST be set to 0x00000001 — but this is the full InterfaceId field value, meaning InterfaceValue=0x00000001 and Mask bits should be STREAM_ID_PROXY (0x40000000). The actual wire value is `0x00000001 | 0x40000000 = 0x40000001`. Confirmed by spec behavior: the Client Notifications Interface uses InterfaceValue=1.

4. **AMBIGUITY: GEOMETRY_INFO optional Padding field.** The spec says the `Padding` field "MUST be detected by checking numGeometryInfo." The spec uses "optional" but does not say what to do when present; it says MUST be ignored. Accept both 44-byte and 48-byte forms.

5. **AMBIGUITY: Multiple concurrent presentations.** The spec does not explicitly state the maximum number of concurrent presentations. Multiple ON_NEW_PRESENTATION messages with different GUIDs are implied by the TSMF design. Implement as `HashMap<[u8;16], PresentationContext>` with `MAX_PRESENTATIONS` cap.

6. **AMBIGUITY: ThrottleDuration units.** The spec §2.2.8 says "The server is free to use any units." The PLAYBACK_ACK must echo the exact value from the sample. Client implementation should treat it as opaque and echo verbatim; no unit interpretation needed.

7. **AMBIGUITY: RIMCALL_RELEASE and RIMCALL_QUERYINTERFACE.** These interface manipulation messages are defined at §2.2.3 but the primary TSMF use case only uses InterfaceValue=0. The QI mechanism is referenced from MS-RDPEXPS. For a minimal client implementation, receiving a QI_REQ for an unsupported interface should be answered with a QI_RSP indicating failure. RIMCALL_RELEASE can be ignored (client does not hold references).

8. **AMBIGUITY: `NoRolloverFlags` value 0x00000001 meaning.** The spec says "SHOULD NOT use alternative platforms" — this is a SHOULD, not MUST. A strict client implementation that only supports one platform should set `FormatSupported=0` regardless of this flag when the format is not supported on the preferred platform. Set FormatSupported=0 + PlatformCookie=undefined when not supported.

---

### 14. Differences vs. RDPEVOR (§9.8) and RDPECAM (§9.9)

| Aspect | MS-RDPEV (TSMF) | MS-RDPEVOR | MS-RDPECAM |
|--------|-----------------|------------|------------|
| Channel model | Single DVC `TSMF` with multiplexed presentations/streams | 2 DVCs (Control + Data) | Enumeration DVC + per-device DVCs |
| Header | 12 bytes request / 8 bytes response; InterfaceId+Mask+MessageId+FunctionId | 8 bytes (cbSize+PacketType) | 2 bytes (Version+MessageId) |
| Dispatch model | 3-level: InterfaceValue + Mask + FunctionId | Simple PacketType enum | Simple MessageId enum |
| Data direction | S→C (server pushes media to client) | S→C (server pushes H.264 frames) | Pull model (S→C request, C→S data) |
| Streaming model | Server pushes + client throttle ACK | Server pushes | Server requests one frame at a time |
| Versioning | Capability negotiation (version 2) | Not negotiated | Explicit v1/v2 negotiation |
| Media format | Generic (TS_AM_MEDIA_TYPE based on DirectShow AM_MEDIA_TYPE) | H.264 only | Fixed enum (H264/MJPG/YUY2 etc.) |
| Correlation table needed | Yes (3 request/response pairs) | No | No |
| Sample data max | 16 MiB recommended cap (cbData is u32) | ~8 MiB typical H.264 frame | 4 MiB (compressed frame) |
| Geometry info | Built-in (UPDATE_GEOMETRY_INFO) | Separate RDPEGT channel | None |
| Audio support | Yes (audio streams via ADD_STREAM) | No | No |
| Deprecated? | Yes (replaced by RDPEVOR for video, RDPSND for audio) | Partially (still used) | No (newer spec) |

---

### 15. no_std Constraints

- [ ] All GUIDs stored as `[u8; 16]` (raw bytes in MS-DTYP wire order)
- [ ] `TS_AM_MEDIA_TYPE.pbFormat`: `Vec<u8>` — alloc required
- [ ] `TS_MM_DATA_SAMPLE.pData`: `Vec<u8>` — alloc required
- [ ] `ExchangeCapabilitiesReq.capabilities`: `Vec<TsmmCapabilities>` — alloc required
- [ ] `presentations: HashMap<[u8; 16], PresentationContext>` — alloc required (via `extern crate alloc`)
- [ ] `pending_requests: HashMap<u32, PendingRequest>` — alloc required
- [ ] `TsmfMediaSink` trait: object-safe, uses `&self` / `&mut self` only
- [ ] No `std::time` usage; all timestamps are u64/i64 values from wire
- [ ] No `std::io`; all I/O via `ReadCursor<'_>` / `WriteCursor<'_>`
