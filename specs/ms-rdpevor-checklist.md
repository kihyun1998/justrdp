# MS-RDPEVOR Implementation Checklist
# Remote Desktop Protocol: Video Optimized Remoting Virtual Channel Extension
# Target crate: justrdp-rdpevor (§9.8)

---

## 1. DVC Channel Names

- [ ] Control channel: `Microsoft::Windows::RDS::Video::Control::v08.01` (MS-RDPEVOR §2.1)
- [ ] Data channel: `Microsoft::Windows::RDS::Video::Data::v08.01` (§2.1)
- [ ] Both opened via MS-RDPEDYC §2.2.2.1

Note: the full `::v08.01` suffix is part of the wire name; roadmap dropped it.

---

## 2. TSMM_VIDEO_PACKET_HEADER (§2.2.1.1) — 8 bytes

| Offset | Size | Type   | Field      |
|-------:|-----:|--------|------------|
| 0      | 4    | u32 LE | cbSize     |
| 4      | 4    | u32 LE | PacketType |

- `cbSize` = total length including header.
- `PacketType` ∈ {1,2,3,4}; anything else → close DVC.

---

## 3. PacketType Enum (§2.2.1.1)

- `TSMM_PACKET_TYPE_PRESENTATION_REQUEST  = 1`
- `TSMM_PACKET_TYPE_PRESENTATION_RESPONSE = 2`
- `TSMM_PACKET_TYPE_CLIENT_NOTIFICATION   = 3`
- `TSMM_PACKET_TYPE_VIDEO_DATA            = 4`

---

## 4. PDU Wire Formats

### 4.1 TSMM_PRESENTATION_REQUEST (§2.2.1.2) — server→client, Control

| Offset | Size | Type   | Field |
|-------:|-----:|--------|-------|
| 0      | 8    | header | cbSize + PacketType=1 |
| 8      | 1    | u8     | PresentationId |
| 9      | 1    | u8     | Version (0x01 for RDP8; diagnostic) |
| 10     | 1    | u8     | Command (1=Start, 2=Stop) |
| 11     | 1    | u8     | FrameRate (reserved; ignored) |
| 12     | 2    | u16 LE | AverageBitrateKbps (reserved) |
| 14     | 2    | u16 LE | Reserved |
| 16     | 4    | u32 LE | SourceWidth |
| 20     | 4    | u32 LE | SourceHeight |
| 24     | 4    | u32 LE | ScaledWidth (≤1920) |
| 28     | 4    | u32 LE | ScaledHeight (≤1080) |
| 32     | 8    | u64 LE | hnsTimestampOffset |
| 40     | 8    | u64 LE | GeometryMappingId (binds to MS-RDPEGT) |
| 48     | 16   | GUID   | VideoSubtypeId (mixed endian) |
| 64     | 4    | u32 LE | cbExtra |
| 68     | var  | u8[]   | pExtraData (H.264 SPS+PPS) |

- Total size = 68 + cbExtra.
- Stop: fields after Command zero-filled, total 68 bytes (cbExtra=0).
- GUID wire layout: Data1 u32 LE, Data2 u16 LE, Data3 u16 LE, Data4 8-byte big-endian array.
- Only defined VideoSubtypeId: `MFVideoFormat_H264 = {34363248-0000-0010-8000-00AA00389B71}`, wire bytes `48 32 36 34 00 00 10 00 80 00 00 AA 00 38 9B 71`.

### 4.2 TSMM_PRESENTATION_RESPONSE (§2.2.1.3) — client→server, Control — 12 bytes fixed

| Offset | Size | Field |
|-------:|-----:|-------|
| 0      | 8    | header (cbSize=12, PacketType=2) |
| 8      | 1    | PresentationId |
| 9      | 1    | ResponseFlags (=0) |
| 10     | 2    | ResultFlags (=0) |

### 4.3 TSMM_CLIENT_NOTIFICATION (§2.2.1.4) — client→server, Control

| Offset | Size | Field |
|-------:|-----:|-------|
| 0      | 8    | header (PacketType=3) |
| 8      | 1    | PresentationId |
| 9      | 1    | NotificationType (1=NetworkError, 2=FrameRateOverride) |
| 10     | 2    | Reserved |
| 12     | 4    | cbData |
| 16     | var  | pData |

- NetworkError: cbData=0, cbSize=16.
- FrameRateOverride: cbData=16, cbSize=32; pData = FRAMERATE_OVERRIDE.

### 4.4 TSMM_CLIENT_NOTIFICATION_FRAMERATE_OVERRIDE (§2.2.1.5) — 16 bytes fixed

| Offset | Size | Field |
|-------:|-----:|-------|
| 0      | 4    | Flags (1=Unrestricted, 2=Override; mutually exclusive) |
| 4      | 4    | DesiredFrameRate (1–30 when Flags=2) |
| 8      | 4    | Reserved1 |
| 12     | 4    | Reserved2 |

### 4.5 TSMM_VIDEO_DATA (§2.2.1.6) — server→client, Data

| Offset | Size | Type   | Field |
|-------:|-----:|--------|-------|
| 0      | 8    | header | cbSize + PacketType=4 |
| 8      | 1    | u8     | PresentationId |
| 9      | 1    | u8     | Version |
| 10     | 1    | u8     | Flags (0x01=HAS_TIMESTAMPS, 0x02=KEYFRAME, 0x04=NEW_FRAMERATE) |
| 11     | 1    | u8     | Reserved |
| 12     | 8    | u64 LE | hnsTimestamp |
| 20     | 8    | u64 LE | hnsDuration |
| 28     | 2    | u16 LE | CurrentPacketIndex (1-based) |
| 30     | 2    | u16 LE | PacketsInSample (≥1) |
| 32     | 4    | u32 LE | SampleNumber (1-based) |
| 36     | 4    | u32 LE | cbSample |
| 40     | var  | u8[]   | pSample (H.264 NAL data) |

- Total size = 40 + cbSample.

---

## 5. Constants

- Commands: `START=1`, `STOP=2`.
- VIDEO_DATA flags: `HAS_TIMESTAMPS=0x01`, `KEYFRAME=0x02`, `NEW_FRAMERATE=0x04`.
- FrameRate flags: `UNRESTRICTED=1`, `OVERRIDE=2`.
- NotificationType: `NETWORK_ERROR=1`, `FRAMERATE_OVERRIDE=2`.
- Version RDP8: `0x01`.
- `MFVideoFormat_H264` GUID (above).

---

## 6. Validation Rules (§3.1.5.1)

Common:
- `cbSize` must match actual buffer length → else close DVC.
- `PacketType` ∈ {1..4} → else close DVC.
- Malformed = close DVC; valid-but-unexpected = ignore packet.

PRESENTATION_REQUEST:
- Minimum 68 bytes (Stop) or 68+cbExtra (Start).
- Command ∈ {1,2}.
- ScaledWidth ≤ 1920, ScaledHeight ≤ 1080.
- cbExtra consistent with cbSize.
- VideoSubtypeId must be H264 (else client doesn't respond).

PRESENTATION_RESPONSE:
- cbSize == 12, ResponseFlags==0, ResultFlags==0.

CLIENT_NOTIFICATION:
- cbSize == 16 + cbData.
- NotificationType ∈ {1,2}.
- Type 1 → cbData == 0; type 2 → cbData == 16.

FRAMERATE_OVERRIDE:
- Flags mutually exclusive; at least one of {1,2} set.
- When Flags==2: DesiredFrameRate ∈ [1,30].

VIDEO_DATA:
- cbSize == 40 + cbSample.
- 1 ≤ CurrentPacketIndex ≤ PacketsInSample; PacketsInSample ≥ 1.
- SampleNumber ≥ 1.

---

## 7. State Machine (§3.2.5.1)

Per presentation:

```
UNINITIALIZED --Start-->  STREAMING --Stop--> UNINITIALIZED
```

- Start in STREAMING → ignore (no action, no error).
- Stop in UNINITIALIZED → ignore.
- VIDEO_DATA for unknown PresentationId → discard.
- PRESENTATION_RESPONSE must be sent before server streams VIDEO_DATA.

Direction table:

| PDU | Direction | Channel |
|-----|-----------|---------|
| PRESENTATION_REQUEST | S→C | Control |
| PRESENTATION_RESPONSE | C→S | Control |
| CLIENT_NOTIFICATION | C→S | Control |
| VIDEO_DATA | S→C | Data |

---

## 8. Sample Reassembly (§2.2.1.6)

- Fragments share `SampleNumber`, ordered 1..PacketsInSample.
- Must handle OOO arrivals on unreliable Data transport.
- Missing fragment → drop sample, optionally send NetworkError for I-Frame.
- Recommend `BTreeMap<(SampleNumber, index), Vec<u8>>` per-presentation buffer.

---

## 9. DoS Caps (implementation-defined)

- `MAX_CONCURRENT_PRESENTATIONS = 16`
- `MAX_CBSAMPLE = 1_048_576` (1 MiB per fragment)
- `MAX_CBEXTRA = 65_536`
- `MAX_PACKETS_IN_SAMPLE = 1024`
- `MAX_PENDING_REASSEMBLY_SAMPLES = 32`
- `MAX_SCALED_WIDTH = 1920`, `MAX_SCALED_HEIGHT = 1080`
- `MAX_DESIRED_FRAMERATE = 30`

---

## 10. Error Handling

- Malformed (length/type mismatch, truncated) → close DVC.
- Valid but unexpected (duplicate Start, out-of-sequence) → ignore.
- Unknown VideoSubtypeId → don't respond; don't close.
- Unknown PresentationId in VIDEO_DATA → discard silently.

---

## 11. Integration with MS-RDPEGT

- `TSMM_PRESENTATION_REQUEST.GeometryMappingId` (u64 LE, offset 40) = MS-RDPEGT `MAPPED_GEOMETRY_PACKET.MappingId`.
- Use `justrdp_rdpegt::GeometryLookup::lookup(mapping_id)` to resolve rectangle.
- Geometry may arrive before, after, or never; do not block presentation start on lookup.

---

## 12. VideoDecoder Abstraction

```rust
pub trait VideoDecoder {
    fn initialize(&mut self, width: u32, height: u32, extra_data: &[u8])
        -> Result<(), VideoDecodeError>;
    fn decode_sample(&mut self, sample: &[u8], timestamp_hns: Option<u64>, keyframe: bool)
        -> Result<(), VideoDecodeError>;
    fn shutdown(&mut self);
}
```

- Crate provides trait + plumbing only; no H.264 in-tree.
- `pExtraData` = concatenated SPS + PPS NAL units.
- Provide `MockVideoDecoder` counting frames for tests.

---

## 13. Spec Test Vectors (§4.1–4.4)

### 4.1 Start (105 bytes)
```
69000000 01000000 0301011D C0120000 E0010000 F4000000
E0010000 F4000000 A47A3B82 0F000000 22020400 BA7A0080
48323634 00001000 800000AA 00389B71 25000000
+ 37 bytes H.264 SPS/PPS
```

- PresentationId=3, Version=1, Command=1(Start), Src/Scaled=480×244
- hnsTimestampOffset=0x0F3B7AA4, GeometryMappingId=0x80007ABA00040222 (matches RDPEGT §4.1)
- VideoSubtypeId=MFVideoFormat_H264, cbExtra=37

### 4.2 Response (12 bytes)
```
0C000000 02000000 03000000
```

### 4.3 VIDEO_DATA (819 bytes, first 40)
```
33030000 04000000 03010300 C7C60600 00000000 00000000
00000000 01000100 01000000 0B030000
```

- PresentationId=3, Version=1, Flags=0x03 (HAS_TIMESTAMPS|KEYFRAME)
- hnsTimestamp=0x06C6C7, CurrentPacketIndex=1, PacketsInSample=1
- SampleNumber=1, cbSample=779

### 4.4 Stop (68 bytes)
```
44000000 01000000 03010200 ... (all zeros)
```

- cbSize=68, PresentationId=3, Command=2(Stop)

---

## 14. Spec Ambiguities

1. Channel name suffix `::v08.01` — use spec version.
2. Unknown VideoSubtypeId → don't respond (no explicit rule).
3. DesiredFrameRate out of range → implementation-defined clamp/reject.
4. Geometry timing is not gated; presentations proceed without geometry.
5. Data channel may be unreliable; no reassembly timeout defined.
6. Version field is diagnostic; don't reject on mismatch.

---

## 15. Crate Structure

- `Cargo.toml`: no_std, forbid unsafe, deps: justrdp-core, justrdp-dvc, justrdp-rdpegt
- `src/lib.rs`: re-exports
- `src/pdu.rs`: all TSMM PDUs, Encode/Decode
- `src/decoder.rs`: `VideoDecoder` trait, `MockVideoDecoder`
- `src/control.rs`: `RdpevorControlClient` DvcProcessor
- `src/data.rs`: `RdpevorDataClient` DvcProcessor + reassembly
- `src/client.rs`: `RdpevorClient` coordinating both, holding GeometryLookup + VideoDecoder
- `tests/integration.rs`: full Start → VIDEO_DATA → Stop flow with mocks
