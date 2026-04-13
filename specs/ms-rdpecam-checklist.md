# MS-RDPECAM Implementation Checklist
## Remote Desktop Protocol: Video Capture Virtual Channel Extension
## Target crate: justrdp-rdpecam (§9.9)
## Spec version: 5.0 (2024-04-23)

---

### 0. Crate / Module Layout

- [ ] `crates/justrdp-rdpecam/Cargo.toml` — `no_std`, `forbid(unsafe_code)`, deps: `justrdp-core`, `justrdp-dvc`
- [ ] `crates/justrdp-rdpecam/src/lib.rs` — `#![forbid(unsafe_code)]`, `#![no_std]`, `extern crate alloc`
- [ ] `src/pdu/header.rs` — `SharedMsgHeader`, `MessageId` enum
- [ ] `src/pdu/enumeration.rs` — `SelectVersionRequest/Response`, `DeviceAdded/RemovedNotification`
- [ ] `src/pdu/device.rs` — `SuccessResponse`, `ErrorResponse`, `Activate/DeactivateDeviceRequest`
- [ ] `src/pdu/stream.rs` — stream list, media type list, current media type PDUs + sub-structs
- [ ] `src/pdu/capture.rs` — `StartStreamsRequest`, `StopStreamsRequest`, `Sample*`
- [ ] `src/pdu/property.rs` — `PropertyList*`, `PropertyValue*`, `SetPropertyValueRequest`
- [ ] `src/constants.rs` — all enums and flags
- [ ] `src/camera.rs` — `CameraDevice` trait + `MockCameraDevice`
- [ ] `src/enumerator.rs` — `RdpecamEnumeratorClient` DVC processor
- [ ] `src/device.rs` — `RdpecamDeviceClient` DVC processor
- [ ] `tests/integration.rs` — full protocol flow with mocks

---

### 1. DVC Channel Structure (MS-RDPECAM §2.1)

- [ ] Device enumeration channel name (exact, null-terminated ANSI): `"RDCamera_Device_Enumerator"`
- [ ] Per-device channel name: null-terminated ANSI, ≤ 256 characters total (including null); name announced in `DeviceAddedNotification.VirtualChannelName`
- [ ] Both opened via MS-RDPEDYC §2.2.2.1
- [ ] Enumeration channel carries: SelectVersion* + DeviceAdded/RemovedNotification
- [ ] Per-device channel carries: all device control + streaming messages
- [ ] Client creates per-device DVC; `VirtualChannelName` is the name to use
- [ ] Client closes per-device DVC after sending `DeviceRemovedNotification`

---

### 2. SHARED_MSG_HEADER (MS-RDPECAM §2.2.1) — 2 bytes

All multi-byte integers in the entire protocol are **little-endian**.

| Offset | Size | Type | Field | Constraints |
|-------:|-----:|------|-------|-------------|
| 0 | 1 | u8 | `Version` | MUST be 1 or 2 |
| 1 | 1 | u8 | `MessageId` | See message table |

- [ ] `Version` MUST be 1 or 2; any other value → ErrorResponse(InvalidMessage) on device channel; close DVC on enumeration channel
- [ ] All responses after version negotiation MUST use `Version = negotiated_version`
- [ ] `SelectVersionRequest.Version` = client maximum supported version (1 or 2)
- [ ] `SelectVersionResponse.Version` = min(client_max, server_max)
- [ ] v2-only messages (0x14–0x18) MUST NOT be sent when `negotiated_version = 1`

---

### 3. MessageId Constants (MS-RDPECAM §2.2.1) — 24 total

| Name | Value | Direction | Channel | Version |
|------|------:|-----------|---------|---------|
| `SuccessResponse` | 0x01 | C→S | Device | v1+ |
| `ErrorResponse` | 0x02 | C→S | Device | v1+ |
| `SelectVersionRequest` | 0x03 | C→S | Enumeration | v1+ |
| `SelectVersionResponse` | 0x04 | S→C | Enumeration | v1+ |
| `DeviceAddedNotification` | 0x05 | C→S | Enumeration | v1+ |
| `DeviceRemovedNotification` | 0x06 | C→S | Enumeration | v1+ |
| `ActivateDeviceRequest` | 0x07 | S→C | Device | v1+ |
| `DeactivateDeviceRequest` | 0x08 | S→C | Device | v1+ |
| `StreamListRequest` | 0x09 | S→C | Device | v1+ |
| `StreamListResponse` | 0x0A | C→S | Device | v1+ |
| `MediaTypeListRequest` | 0x0B | S→C | Device | v1+ |
| `MediaTypeListResponse` | 0x0C | C→S | Device | v1+ |
| `CurrentMediaTypeRequest` | 0x0D | S→C | Device | v1+ |
| `CurrentMediaTypeResponse` | 0x0E | C→S | Device | v1+ |
| `StartStreamsRequest` | 0x0F | S→C | Device | v1+ |
| `StopStreamsRequest` | 0x10 | S→C | Device | v1+ |
| `SampleRequest` | 0x11 | S→C | Device | v1+ |
| `SampleResponse` | 0x12 | C→S | Device | v1+ |
| `SampleErrorResponse` | 0x13 | C→S | Device | v1+ |
| `PropertyListRequest` | 0x14 | S→C | Device | v2 only |
| `PropertyListResponse` | 0x15 | C→S | Device | v2 only |
| `PropertyValueRequest` | 0x16 | S→C | Device | v2 only |
| `PropertyValueResponse` | 0x17 | C→S | Device | v2 only |
| `SetPropertyValueRequest` | 0x18 | S→C | Device | v2 only |

---

### 4. PDU Wire Formats

#### 4.1 SelectVersionRequest (§2.2.2.1) — 2 bytes fixed — C→S, Enumeration

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 1 | Version | client_max (1 or 2) |
| 1 | 1 | MessageId | 0x03 |

- [ ] MUST be the first message sent on the enumeration channel

#### 4.2 SelectVersionResponse (§2.2.2.2) — 2 bytes fixed — S→C, Enumeration

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 1 | Version | min(client_max, server_max) |
| 1 | 1 | MessageId | 0x04 |

- [ ] Server MUST NOT exceed the version the client offered
- [ ] MUST be sent in response to SelectVersionRequest before any other message

#### 4.3 DeviceAddedNotification (§2.2.2.3) — variable — C→S, Enumeration

| Offset | Size | Field | Encoding |
|-------:|-----:|-------|---------|
| 0 | 1 | Version | negotiated_version |
| 1 | 1 | MessageId | 0x05 |
| 2 | variable | DeviceName | null-terminated UTF-16 LE (null = 0x00 0x00) |
| 2+len(DeviceName) | variable | VirtualChannelName | null-terminated ANSI (null = 0x00) |

- [ ] `DeviceName` encoding: each character is 2 bytes (little-endian UTF-16); terminated by `00 00`
- [ ] `VirtualChannelName` encoding: each character is 1 byte (ANSI); terminated by `00`; max 256 bytes including null
- [ ] No length prefix on either string; parse by scanning for null terminator
- [ ] `VirtualChannelName` is the exact name to use when opening the per-device DVC

#### 4.4 DeviceRemovedNotification (§2.2.2.4) — variable — C→S, Enumeration

| Offset | Size | Field | Encoding |
|-------:|-----:|-------|---------|
| 0 | 1 | Version | negotiated_version |
| 1 | 1 | MessageId | 0x06 |
| 2 | variable | VirtualChannelName | null-terminated ANSI |

- [ ] Client MUST close the corresponding per-device DVC after sending this notification

#### 4.5 SuccessResponse (§2.2.3.1) — 2 bytes fixed — C→S, Device

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | Version |
| 1 | 1 | MessageId = 0x01 |

- [ ] Sent in response to: ActivateDeviceRequest (0x07), DeactivateDeviceRequest (0x08), StartStreamsRequest (0x0F), StopStreamsRequest (0x10), SetPropertyValueRequest (0x18)

#### 4.6 ErrorResponse (§2.2.3.2) — 6 bytes fixed — C→S, Device

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Version |
| 1 | 1 | u8 | MessageId = 0x02 |
| 2 | 4 | u32 LE | ErrorCode |

- [ ] ErrorCode values: see §5.9

#### 4.7 ActivateDeviceRequest (§2.2.3.3) — 2 bytes fixed — S→C, Device

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | Version |
| 1 | 1 | MessageId = 0x07 |

- [ ] Response: SuccessResponse or ErrorResponse

#### 4.8 DeactivateDeviceRequest (§2.2.3.4) — 2 bytes fixed — S→C, Device

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | Version |
| 1 | 1 | MessageId = 0x08 |

- [ ] Client MUST free device resources after sending SuccessResponse
- [ ] Response: SuccessResponse or ErrorResponse

#### 4.9 StreamListRequest (§2.2.3.5) — 2 bytes fixed — S→C, Device

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | Version |
| 1 | 1 | MessageId = 0x09 |

#### 4.10 StreamListResponse (§2.2.3.6) — variable — C→S, Device

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 2 | Header (Version + 0x0A) |
| 2 | N×5 | StreamDescriptions (array, no count prefix) |

**STREAM_DESCRIPTION (§2.2.3.6.1) — 5 bytes each:**

| Offset | Size | Type | Field | Values |
|-------:|-----:|------|-------|--------|
| 0 | 2 | u16 LE | FrameSourceTypes | flags: Color=0x0001, Infrared=0x0002, Custom=0x0008 |
| 2 | 1 | u8 | StreamCategory | Capture=0x01 |
| 3 | 1 | u8 | Selected | 0=not selected, 1=selected |
| 4 | 1 | u8 | CanBeShared | 0=exclusive, 1=shareable |

- [ ] Total size = 2 + (N × 5) bytes; (msg_len - 2) MUST be divisible by 5
- [ ] Stream index = 0-based position in the array; used by all subsequent per-stream messages
- [ ] 0 streams is valid (msg_len = 2)

#### 4.11 MediaTypeListRequest (§2.2.3.7) — 3 bytes fixed — S→C, Device

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Version |
| 1 | 1 | u8 | MessageId = 0x0B |
| 2 | 1 | u8 | StreamIndex |

#### 4.12 MediaTypeListResponse (§2.2.3.8) — variable — C→S, Device

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 2 | Header (Version + 0x0C) |
| 2 | N×26 | MediaTypeDescriptions (array, no count prefix) |

**MEDIA_TYPE_DESCRIPTION (§2.2.3.8.1) — 26 bytes each:**

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Format |
| 1 | 4 | u32 LE | Width (pixels) |
| 5 | 4 | u32 LE | Height (pixels) |
| 9 | 4 | u32 LE | FrameRateNumerator |
| 13 | 4 | u32 LE | FrameRateDenominator |
| 17 | 4 | u32 LE | PixelAspectRatioNumerator |
| 21 | 4 | u32 LE | PixelAspectRatioDenominator |
| 25 | 1 | u8 | Flags |

- [ ] Total size = 2 + (N × 26) bytes; (msg_len - 2) MUST be divisible by 26
- [ ] `Flags`: DecodingRequired=0x01, BottomUpImage=0x02

#### 4.13 CurrentMediaTypeRequest (§2.2.3.9) — 3 bytes fixed — S→C, Device

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Version |
| 1 | 1 | u8 | MessageId = 0x0D |
| 2 | 1 | u8 | StreamIndex |

#### 4.14 CurrentMediaTypeResponse (§2.2.3.10) — 28 bytes fixed — C→S, Device

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 2 | Header (Version + 0x0E) |
| 2 | 26 | MediaTypeDescription (MEDIA_TYPE_DESCRIPTION) |

#### 4.15 StartStreamsRequest (§2.2.3.11) — variable — S→C, Device

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 2 | Header (Version + 0x0F) |
| 2 | N×27 | StartStreamsInfo (array, no count prefix) |

**START_STREAM_INFO (§2.2.3.11.1) — 27 bytes each:**

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | StreamIndex |
| 1 | 26 | MEDIA_TYPE_DESCRIPTION | MediaTypeDescription |

- [ ] Total size = 2 + (N × 27) bytes; (msg_len - 2) MUST be divisible by 27
- [ ] `StreamIndex` MUST match a valid index from StreamListResponse; else ErrorResponse(InvalidStreamNumber)
- [ ] `MediaTypeDescription` specifies the format the stream MUST produce

#### 4.16 StopStreamsRequest (§2.2.3.12) — 2 bytes fixed — S→C, Device

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | Version |
| 1 | 1 | MessageId = 0x10 |

- [ ] Stops ALL streams on this device channel simultaneously

#### 4.17 SampleRequest (§2.2.3.13) — 3 bytes fixed — S→C, Device

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Version |
| 1 | 1 | u8 | MessageId = 0x11 |
| 2 | 1 | u8 | StreamIndex |

- [ ] 1:1 mapping: one SampleRequest → exactly one SampleResponse or SampleErrorResponse

#### 4.18 SampleResponse (§2.2.3.14) — variable — C→S, Device

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Version |
| 1 | 1 | u8 | MessageId = 0x12 |
| 2 | 1 | u8 | StreamIndex |
| 3 | msg_len-3 | u8[] | Sample data |

- [ ] Minimum: 3 bytes (zero-length sample is allowed)
- [ ] Sample length = (DVC payload length - 3); no explicit length field in wire format
- [ ] Sample format per the `Format` field selected in StartStreamsRequest

#### 4.19 SampleErrorResponse (§2.2.3.15) — 7 bytes fixed — C→S, Device

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Version |
| 1 | 1 | u8 | MessageId = 0x13 |
| 2 | 1 | u8 | StreamIndex |
| 3 | 4 | u32 LE | ErrorCode |

#### 4.20 PropertyListRequest (§2.2.3.16) — 2 bytes fixed — S→C, Device, v2 only

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | Version = 2 |
| 1 | 1 | MessageId = 0x14 |

#### 4.21 PropertyListResponse (§2.2.3.17) — variable — C→S, Device, v2 only

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 2 | Header (Version=2 + 0x15) |
| 2 | N×19 | PropertyDescriptions (array, no count prefix) |

**PROPERTY_DESCRIPTION (§2.2.3.17.1) — 19 bytes each:**

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | PropertySet |
| 1 | 1 | u8 | PropertyId |
| 2 | 1 | u8 | Capabilities |
| 3 | 4 | i32 LE | MinValue |
| 7 | 4 | i32 LE | MaxValue |
| 11 | 4 | i32 LE | Step |
| 15 | 4 | i32 LE | DefaultValue |

- [ ] Total size = 2 + (N × 19) bytes; (msg_len - 2) MUST be divisible by 19
- [ ] All value fields (MinValue, MaxValue, Step, DefaultValue) are **signed** 32-bit LE

#### 4.22 PropertyValueRequest (§2.2.3.18) — 4 bytes fixed — S→C, Device, v2 only

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Version = 2 |
| 1 | 1 | u8 | MessageId = 0x16 |
| 2 | 1 | u8 | PropertySet |
| 3 | 1 | u8 | PropertyId |

#### 4.23 PropertyValueResponse (§2.2.3.19) — 7 bytes fixed — C→S, Device, v2 only

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 2 | Header (Version=2 + 0x17) |
| 2 | 5 | PropertyValue (PROPERTY_VALUE) |

**PROPERTY_VALUE (§2.2.3.19.1) — 5 bytes:**

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Mode |
| 1 | 4 | i32 LE | Value |

#### 4.24 SetPropertyValueRequest (§2.2.3.20) — 9 bytes fixed — S→C, Device, v2 only

| Offset | Size | Type | Field |
|-------:|-----:|------|-------|
| 0 | 1 | u8 | Version = 2 |
| 1 | 1 | u8 | MessageId = 0x18 |
| 2 | 1 | u8 | PropertySet |
| 3 | 1 | u8 | PropertyId |
| 4 | 5 | PROPERTY_VALUE | PropertyValue |

- [ ] If `PropertyValue.Mode = Auto (0x02)`, `PropertyValue.Value` MUST be ignored
- [ ] Response: SuccessResponse or ErrorResponse

---

### 5. Enumerations and Constants

#### 5.1 CamMediaFormat (§2.2.3.8.1)

| Name | Value |
|------|------:|
| `H264` | 0x01 |
| `MJPG` | 0x02 |
| `YUY2` | 0x03 |
| `NV12` | 0x04 |
| `I420` | 0x05 |
| `RGB24` | 0x06 |
| `RGB32` | 0x07 |

#### 5.2 FrameSourceTypes flags (§2.2.3.6.1) — u16 LE bitmask

| Name | Value |
|------|------:|
| `Color` | 0x0001 |
| `Infrared` | 0x0002 |
| `Custom` | 0x0008 |

#### 5.3 StreamCategory (§2.2.3.6.1)

| Name | Value |
|------|------:|
| `Capture` | 0x01 |

#### 5.4 MediaTypeFlags (§2.2.3.8.1) — u8 bitmask

| Name | Value |
|------|------:|
| `DecodingRequired` | 0x01 |
| `BottomUpImage` | 0x02 |

#### 5.5 PropertySet (§2.2.3.17.1)

| Name | Value |
|------|------:|
| `CameraControl` | 0x01 |
| `VideoProcAmp` | 0x02 |

#### 5.6 CameraControlPropertyId (§2.2.3.17.1)

| Name | Value |
|------|------:|
| `Exposure` | 0x01 |
| `Focus` | 0x02 |
| `Pan` | 0x03 |
| `Roll` | 0x04 |
| `Tilt` | 0x05 |
| `Zoom` | 0x06 |

#### 5.7 VideoProcAmpPropertyId (§2.2.3.17.1)

| Name | Value | Constraint |
|------|------:|-----------|
| `BacklightCompensation` | 0x01 | Value MUST be 0 or 1 |
| `Brightness` | 0x02 | |
| `Contrast` | 0x03 | |
| `Hue` | 0x04 | |
| `WhiteBalance` | 0x05 | |

#### 5.8 PropertyMode (§2.2.3.19.1)

| Name | Value |
|------|------:|
| `Manual` | 0x01 |
| `Auto` | 0x02 |

#### 5.9 PropertyCapabilities (§2.2.3.17.1) — u8 bitmask

| Name | Value |
|------|------:|
| `Manual` | 0x01 |
| `Auto` | 0x02 |

#### 5.10 ErrorCode (§2.2.3.2) — u32 LE

| Name | Value | Notes |
|------|------:|-------|
| `UnexpectedError` | 0x00000001 | |
| `InvalidMessage` | 0x00000002 | |
| `NotInitialized` | 0x00000003 | |
| `InvalidRequest` | 0x00000004 | |
| `InvalidStreamNumber` | 0x00000005 | |
| `InvalidMediaType` | 0x00000006 | |
| `OutOfMemory` | 0x00000007 | |
| `ItemNotFound` | 0x00000008 | v2 only |
| `SetNotFound` | 0x00000009 | v2 only |
| `OperationNotSupported` | 0x0000000A | v2 only |

#### 5.11 Protocol Versions

| Value | Meaning |
|------:|---------|
| 1 | Messages 0x01–0x13 only |
| 2 | Adds messages 0x14–0x18 (Property API) |

---

### 6. Variable-Length / Dynamic Size Parsing

- [ ] `DeviceName`: UTF-16 LE null-terminated; scan for `00 00` two-byte terminator; odd-length remaining bytes → malformed
- [ ] `VirtualChannelName`: ANSI null-terminated; scan for `00` single-byte terminator; max 256 bytes including null
- [ ] `StreamDescriptions[]`: count = (payload_len - 2) / 5; reject if (payload_len - 2) % 5 != 0
- [ ] `MediaTypeDescriptions[]`: count = (payload_len - 2) / 26; reject if (payload_len - 2) % 26 != 0
- [ ] `StartStreamsInfo[]`: count = (payload_len - 2) / 27; reject if (payload_len - 2) % 27 != 0
- [ ] `PropertyDescriptions[]`: count = (payload_len - 2) / 19; reject if (payload_len - 2) % 19 != 0
- [ ] `SampleResponse.Sample`: length = payload_len - 3; no structure constraint
- [ ] Edge: 0-element arrays are valid for all list responses
- [ ] No maximum element count defined in spec; use implementation-defined caps (§10)

---

### 7. State Machine / Protocol Sequences

#### 7.1 Enumeration Channel (§1.3.1, §1.3.2, §1.3.3)

```
UNINITIALIZED
  --[C: SelectVersionRequest]--> WAIT_VERSION_RESPONSE
  --[S: SelectVersionResponse]--> VERSIONED
  --[C: DeviceAddedNotification (per device)]--> DEVICE_ENUMERATED
  --[C: DeviceRemovedNotification (per device)]--> (device removed)
```

- [ ] SelectVersionRequest MUST be the first message; SelectVersionResponse MUST be the second
- [ ] DeviceAdded/Removed can arrive at any time after VERSIONED (hotplug support)
- [ ] All messages MUST use `Version = negotiated_version` after SelectVersionResponse

#### 7.2 Per-Device Channel — Device Initialization Sequence (§1.3.4)

```
IDLE
  --[S: ActivateDeviceRequest]--> [C: Success/Error]
  --ACTIVE (on success)
  --[S: StreamListRequest]--> [C: StreamListResponse]
  --[S: MediaTypeListRequest(stream_i)]--> [C: MediaTypeListResponse] (per stream)
  --[S: CurrentMediaTypeRequest(stream_i)]--> [C: CurrentMediaTypeResponse] (per stream)
  --[S: DeactivateDeviceRequest]--> [C: Success/Error]
  --IDLE
```

#### 7.3 Per-Device Channel — Video Capture Sequence (§1.3.5)

```
ACTIVE
  --[S: StartStreamsRequest]--> [C: Success/Error]
  --STREAMING (on success)
  --[S: SampleRequest(stream_i)]--> [C: SampleResponse or SampleErrorResponse] (repeat)
  --[S: StopStreamsRequest]--> [C: Success/Error]
  --ACTIVE
  --[S: DeactivateDeviceRequest]--> [C: Success/Error]
  --IDLE
```

- [ ] ActivateDeviceRequest can be omitted before StartStreamsRequest if already active
- [ ] SampleRequest/Response pairs are 1:1 per stream; server drives the rate
- [ ] StopStreamsRequest stops ALL streams simultaneously

#### 7.4 Per-Device Channel — Device Control Sequence (§1.3.6, §1.3.7) — v2 only

```
ACTIVE or STREAMING
  --[S: PropertyListRequest]--> [C: PropertyListResponse]
  --[S: PropertyValueRequest(set, id)]--> [C: PropertyValueResponse or ErrorResponse]
  --[S: SetPropertyValueRequest(set, id, value)]--> [C: Success/Error]
```

- [ ] Property requests interleave with streaming (channel is full-duplex)
- [ ] SetPropertyValueRequest with Mode=Auto: Value field ignored

---

### 8. Validation Rules

- [ ] `Version` not in {1, 2} → ErrorResponse(InvalidMessage) on device channel; close DVC on enumeration channel
- [ ] `MessageId` not in 0x01–0x18 → ErrorResponse(InvalidMessage)
- [ ] v2 MessageId (0x14–0x18) received with negotiated_version=1 → ErrorResponse(InvalidMessage)
- [ ] SelectVersionRequest not first message on enumeration channel → close DVC
- [ ] Payload length mismatch for fixed-size messages → ErrorResponse(InvalidMessage)
- [ ] (payload_len - 2) % 5 != 0 in StreamListResponse → ErrorResponse(InvalidMessage)
- [ ] (payload_len - 2) % 26 != 0 in MediaTypeListResponse → ErrorResponse(InvalidMessage)
- [ ] (payload_len - 2) % 27 != 0 in StartStreamsRequest → ErrorResponse(InvalidMessage)
- [ ] (payload_len - 2) % 19 != 0 in PropertyListResponse → ErrorResponse(InvalidMessage)
- [ ] `Format` not in 0x01–0x07 → ErrorResponse(InvalidMediaType)
- [ ] `FrameRateDenominator = 0` in MEDIA_TYPE_DESCRIPTION → ErrorResponse(InvalidMediaType)
- [ ] `StreamIndex` references non-existent stream → ErrorResponse(InvalidStreamNumber)
- [ ] `PropertySet` not in {0x01, 0x02} → ErrorResponse(SetNotFound)
- [ ] `PropertyId` invalid for given PropertySet → ErrorResponse(ItemNotFound)
- [ ] `BacklightCompensation` Value not in {0, 1} → ErrorResponse(InvalidRequest)
- [ ] `PropertyCapabilities` = 0 (neither Manual nor Auto) → ErrorResponse(UnexpectedError)
- [ ] SampleResponse received without outstanding SampleRequest → silently discard (spec is silent)
- [ ] DeviceName null terminator missing before end of payload → close DVC / ErrorResponse

---

### 9. Test Vectors (MS-RDPECAM §4.x)

#### 9.1 SelectVersionRequest (§4.1.1) — 2 bytes
```
02 03
```
- `Version=2, MessageId=SelectVersionRequest(3)`

#### 9.2 SelectVersionResponse (§4.1.2) — 2 bytes
```
02 04
```
- `Version=2, MessageId=SelectVersionResponse(4)`

#### 9.3 DeviceAddedNotification (§4.2.1) — 49 bytes
```
02 05
4d 00 6f 00 63 00 6b 00 20 00 43 00 61 00 6d 00
65 00 72 00 61 00 20 00 31 00 00 00
52 44 43 61 6d 65 72 61 5f 44 65 76 69 63 65 5f 30 00
```
- `DeviceName = "Mock Camera 1"` (UTF-16 LE, 14 chars × 2 + 2 null = 30 bytes)
- `VirtualChannelName = "RDCamera_Device_0"` (ANSI, 17 chars + 1 null = 18 bytes)

#### 9.4 StreamListResponse (§4.4.4) — 12 bytes
```
02 0a 01 00 01 01 01 01 00 01 00 01
```
- 2 streams: both Color/Capture/CanBeShared; stream[0] Selected=1, stream[1] Selected=0

#### 9.5 MediaTypeListResponse (§4.4.6) — 106 bytes
```
02 0c
01 80 02 00 00 e0 01 00 00 1e 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01
01 20 03 00 00 58 02 00 00 1e 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01
01 00 05 00 00 d0 02 00 00 1e 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01
01 80 07 00 00 38 04 00 00 1e 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01
```
- 4 entries: H264 at 640×480, 800×600, 1280×720, 1920×1080; all 30fps, PAR 1:1, Flags=DecodingRequired(0x01)

#### 9.6 StartStreamsRequest (§4.5.1) — 29 bytes
```
02 0f 00 01 80 07 00 00 38 04 00 00 1e 00 00 00
01 00 00 00 01 00 00 00 01 00 00 00 01
```
- `StreamIndex=0, Format=H264, Width=1920, Height=1080, FRNum=30, FRDen=1, PARNum=1, PARDen=1, Flags=0x01`

#### 9.7 PropertyListResponse (§4.6.2) — 38 bytes
```
02 15
01 02 03 00 00 00 00 fa 00 00 00 05 00 00 00 00 00 00 00
02 02 01 00 00 00 00 ff 00 00 00 01 00 00 00 80 00 00 00
```
- `[0]: CameraControl(1), Focus(2), Manual+Auto(3), Min=0, Max=250, Step=5, Default=0`
- `[1]: VideoProcAmp(2), Brightness(2), Manual(1), Min=0, Max=255, Step=1, Default=128`

#### 9.8 PropertyValueResponse (§4.6.4) — 7 bytes
```
02 17 01 64 00 00 00
```
- `Version=2, MessageId=PropertyValueResponse(23), Mode=Manual(1), Value=100`

---

### 10. Implementation-Defined Safety Caps

| Constant | Value | Rationale |
|----------|------:|-----------|
| `MAX_VIRTUAL_CHANNEL_NAME` | 256 | Spec §2.1 hard limit |
| `MAX_DEVICE_NAME_UTF16` | 256 | Conservative display name cap |
| `MAX_STREAMS` | 32 | Typical cameras have 1–4 streams |
| `MAX_MEDIA_TYPES_PER_STREAM` | 512 | Prevents OOM on malicious client |
| `MAX_PROPERTIES` | 64 | Both PropertySet totals = 11 defined |
| `MAX_SAMPLE_BYTES` | 4_194_304 | 4 MiB (1920×1080 uncompressed RGB32 = 8 MiB; use 4 MiB for compressed) |
| `MAX_OUTSTANDING_SAMPLE_REQUESTS` | 8 | Per stream |

---

### 11. Differences vs. RDPEVOR (§9.8) / RDPEGT (§9.11)

| Aspect | RDPEVOR | RDPECAM |
|--------|---------|---------|
| Header size | 8 bytes (u32 cbSize + u32 PacketType) | 2 bytes (u8 Version + u8 MessageId) |
| Channel model | 2 fixed channels | 1 enumeration + N per-device DVCs |
| Data direction | Primarily S→C | Bidirectional; client produces sample data |
| Streaming model | Server pushes samples | Pull model: server issues SampleRequest per frame |
| Versioning | Not negotiated | Explicit v1/v2 negotiation at protocol start |
| Variable arrays | Length-prefixed (cbExtra) | No prefix; count derived from payload length |
| String types | None | UTF-16 LE (DeviceName) + ANSI (channel name) |
| Property API | None | v2: CameraControl + VideoProcAmp (11 properties) |
| Geometry binding | GeometryMappingId ties to RDPEGT | No geometry dependency |

---

### 12. no_std Constraints and Host Trait Design

- [ ] `DeviceName` storage: `Vec<u16>` (raw UTF-16 code units); avoid `String` conversion to stay `no_std`-friendly
- [ ] `VirtualChannelName` storage: `Vec<u8>` (raw ANSI bytes with null) or `String` (strip null after parsing)
- [ ] `Sample` data: `Vec<u8>`; up to `MAX_SAMPLE_BYTES`
- [ ] All list arrays (stream, media type, property): `Vec<T>` — `alloc` crate sufficient
- [ ] Define `CameraDevice` trait (platform implementation lives outside this crate):

```rust
// crates/justrdp-rdpecam/src/camera.rs
pub trait CameraDevice {
    fn activate(&mut self) -> Result<(), CamError>;
    fn deactivate(&mut self) -> Result<(), CamError>;
    fn stream_list(&self) -> &[StreamDescription];
    fn media_type_list(&self, stream_index: u8) -> Result<&[MediaTypeDescription], CamError>;
    fn current_media_type(&self, stream_index: u8) -> Result<MediaTypeDescription, CamError>;
    fn start_streams(&mut self, infos: &[StartStreamInfo]) -> Result<(), CamError>;
    fn stop_streams(&mut self) -> Result<(), CamError>;
    fn capture_sample(&mut self, stream_index: u8) -> Result<alloc::vec::Vec<u8>, CamError>;
    // v2 only:
    fn property_list(&self) -> &[PropertyDescription];
    fn property_value(&self, set: PropertySet, id: u8) -> Result<PropertyValue, CamError>;
    fn set_property_value(&mut self, set: PropertySet, id: u8, value: PropertyValue) -> Result<(), CamError>;
}
```

- [ ] Provide `MockCameraDevice` in `src/camera.rs` for use in tests

---

### 13. Spec Ambiguities / Flags

1. **`PROPERTY_DESCRIPTION.DefaultValue` description (§2.2.3.17.1):** The text says "step value that SHOULD be used to create values within the range" — this is a documentation error. The annotated example shows DefaultValue=128 for Brightness, consistent with it being the default property value. Implement as default value.

2. **List count encoding:** No count prefix on any array field. Count is derived from (payload_len - header_size) / element_size. The spec does not specify behavior for non-integer counts; treat as `ErrorResponse(InvalidMessage)`.

3. **`FrameRateDenominator = 0`:** The spec does not explicitly prohibit this. Division by zero would result during frame rate computation. Treat as `ErrorResponse(InvalidMediaType)`.

4. **Zero-element list responses:** Spec does not address 0 streams, 0 media types, or 0 properties. These are logically valid empty arrays; server behavior afterward is unspecified.

5. **`StreamCategory` unknown value:** Only `Capture = 0x01` is defined. The spec does not state whether unknown values are an error. Treat as implementation-defined; do not reject.

6. **Unsolicited SampleResponse:** The spec defines SampleResponse as a reply to SampleRequest, but does not explicitly state what the server does with an unsolicited one. Discard silently.

7. **v2 error codes (ItemNotFound=0x08, SetNotFound=0x09, OperationNotSupported=0x0A) on v1:** The spec says these are "generated only by version 2." A v1 server receiving one of these from a client should treat it as `ErrorResponse(UnexpectedError)`.

8. **`VirtualChannelName` character set:** Described as ANSI. The exact code page is not specified. ASCII subset is safe; non-ASCII ANSI is implementation-defined.

---

Relevant existing spec files for reference:
- `D:\github\justrdp\specs\ms-rdpevor-checklist.md`
- `D:\github\justrdp\specs\ms-rdpegt-checklist.md`

---

**핵심 요약 (300단어 이내)**

체크리스트 파일은 위 내용 그대로이며, 파일 쓰기 도구가 없어 사용자가 직접 `D:\github\justrdp\specs\ms-rdpecam-checklist.md`에 저장해야 합니다.

**총 메시지 수: 24개** (MessageId 0x01–0x18). v1: 19개, v2 추가: 5개.

**특이사항 5가지:**

1. **2채널 모델**: RDPEVOR/RDPEGT와 달리 채널 수가 가변적입니다. 단일 enumeration 채널(`RDCamera_Device_Enumerator`) 위에 카메라 수만큼 per-device DVC가 동적으로 추가됩니다. DVC 이름은 `DeviceAddedNotification.VirtualChannelName`으로 통보됩니다.

2. **배열 길이 추론 방식**: StreamListResponse, MediaTypeListResponse, StartStreamsRequest, PropertyListResponse 모두 배열 원소 수를 나타내는 별도 count 필드가 없습니다. `(payload_len - 2) / element_size`로 추론하고, 나머지가 0이 아니면 InvalidMessage입니다.

3. **두 가지 문자열 인코딩 혼용**: `DeviceName`은 UTF-16 LE null-terminated, `VirtualChannelName`은 ANSI null-terminated입니다. no_std 환경에서는 `Vec<u16>`과 `Vec<u8>`을 각각 사용하고, 변환은 최대한 지연합니다.

4. **Pull 스트리밍 모델**: RDPEVOR처럼 서버가 샘플을 push하지 않습니다. 서버가 `SampleRequest`를 보낼 때마다 클라이언트가 `SampleResponse`를 1:1로 돌려줍니다. 서버가 프레임 레이트를 제어합니다.

5. **`DefaultValue` 명세 오류**: §2.2.3.17.1의 `DefaultValue` 필드 설명이 "step value that SHOULD be used to create values"로 잘못 기재되어 있습니다. annotated example(§4.6.2)의 Brightness DefaultValue=128을 보면 실제 기본값임이 명확합니다. 기본 속성값으로 구현해야 합니다.

Sources:
- [MS-RDPECAM Transport §2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpecam/340f6508-5834-4cbf-a7fa-933cb91e319c)
- [MS-RDPECAM SHARED_MSG_HEADER §2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpecam/6c9dd9fc-0a9a-45c4-84b0-72cd3986dd39)
- [MS-RDPECAM MEDIA_TYPE_DESCRIPTION §2.2.3.8.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpecam/55082483-46ea-4290-8e8f-e56647c09b97)
- [MS-RDPECAM PROPERTY_DESCRIPTION §2.2.3.17.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpecam/d27db22b-5fc3-44e0-ab3b-aace52801724)
- [MS-RDPECAM Error Response §2.2.3.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpecam/92eed5a8-62fb-404b-a85b-b0973e531828)
- [MS-RDPECAM Protocol Overview (TOC)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpecam/toc.json)
- [MS-RDPECAM Spec v5.0 landing page](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpecam/92af6790-b79c-4813-9c07-7c545bed0242)
