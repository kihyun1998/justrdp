# Logon & Save Session Info

## What it is

The one PDU that says **who logged on** — `PDUTYPE2_SAVE_SESSION_INFO` (0x26),
`[MS-RDPBCGR]` 2.2.10.1. It carries the account and domain the logon used, the server's
session ID, a logon error or warning, and the auto-reconnect cookie that would let this
client resume that session. Four `infoType` variants share one Share Data body, and a
server picks one per PDU.

It is **received on two legs and never sent**. justrdp is a client, so this area has a
decoder and no encoder; the cookie the client eventually *sends* is a different structure
(`ARC_CS_PRIVATE_PACKET`) derived from this one, and that belongs to #306.

## Governing decisions

**None.** No ADR is about logon notifications.

Adjacent but not governing: [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md)
supplies the receive-path posture that settles what an undefined `infoType` does, and
[ADR-0001](../../adr/0001-sans-io-state-machine-core.md) is why storing any of it is the
host's rather than the core's. Neither is about this PDU.

## Design model

- **Two legs, one decoder, and the host reads whichever arrived.** The PDU may precede the
  Font Map (connect leg, accumulated into `ActivationResult::save_session_info`) or follow
  it (session leg, surfaced as `SessionOutput::SaveSessionInfo`). The connect machine's
  `Action`s are instructions to the *adapter* and the host sees none of them, so a new
  `Action` would have had nowhere to go; the handover struct already crosses that seam.
- **A `Vec`, not an `Option`.** Nothing bounds how many arrive: 3.2.5.10.1 phrases the
  logon notification and the auto-reconnect cookie as separate cases, and FreeRDP fills
  `logon_info` and `logon_info_ex` from separate PDUs into separate settings. One
  overwriting the other would relocate the defect this area was built to close.
- **The cookie is credential material and never reaches a log.** `arcRandomBits` keys the
  HMAC that proves, on reconnect, that this client last held the session (5.5, which has
  the client store it *"never allowing programmatic access to it"*).
  `ServerAutoReconnect` hand-writes `Debug` to redact it, because it travels inside a
  `SessionOutput` that derives `Debug`; `log_save_session_info` has no field for it.
- **Three declared lengths are read and deliberately decide nothing** — Logon Info V2's
  `Size`, Logon Info Extended's `Length`, and each `TS_LOGON_INFO_FIELD`'s `cbFieldData`.
  Each is recorded in its decoder's doc rather than enforced, which is way #2 of
  [a decoded field with no reader](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)'s
  three exits. `cbFieldData` keeps one check — that it does not exceed what is left —
  because a length past the buffer is malformed whatever it frames.
- **An undefined `infoType` is carried, not rejected.** `SaveSessionInfo::Unknown` is not a
  wire value. The references split (FreeRDP warns and succeeds, IronRDP errors) and neither
  can tell the host it happened; failing a session over a future RDP version's fifth type
  would be worse than any client in the field.
- **Everything past the decode is the host's.** 3.2.5.10.1 says only that the client SHOULD
  save the cookie and MAY act on the rest — where it is stored, whether a logon error is
  shown, and whether a reconnect is attempted are all policy (CLAUDE.md).
- **A logon error is a notification, not a disconnect.** It may precede one; the attribution
  for a close that follows is still Set Error Info.
- **`errorNotificationType` is typed, `errorNotificationData` is not**, and the split is the
  measurement. The type has eight catalogued values, so it gets the enum-with-`Other(u32)`
  shape [`errinfo::ErrorInfo`](../../../crates/justrdp-pdu/src/errinfo.rs) already uses for
  this repo's other server status code. The data field's *meaning* is discriminated by the
  type rather than by its own value — `LogonErrorNotification::data_is_session_id` is that
  rule — so typing it by value is wrong, which is exactly what IronRDP does.

## Code

- `justrdp-pdu/src/session_info.rs` — `SaveSessionInfo`, `LogonInfo`, `LogonInfoExtended`,
  `ServerAutoReconnect`, `LogonErrorsInfo`, `LogonErrorsInfo::description`,
  `LogonErrorNotification`, `LogonErrorNotification::data_is_session_id`,
  `INFOTYPE_LOGON`, `INFOTYPE_LOGON_LONG`, `INFOTYPE_LOGON_PLAINNOTIFY`,
  `INFOTYPE_LOGON_EXTENDED_INFO`, `LOGON_EX_AUTORECONNECTCOOKIE`, `LOGON_EX_LOGONERRORS`
- `justrdp-pdu/src/share.rs` — `PDU_TYPE2_SAVE_SESSION_INFO`
- `justrdp-pdu/src/cursor.rs` — `utf16_string`
- `justrdp/src/session.rs` — `SessionOutput::SaveSessionInfo`, `log_save_session_info`
- `justrdp/src/connect.rs` — `ActivationResult`
- `justrdp-tokio/src/lib.rs` — `SessionEvent`
- `justrdp-pdu/tests/real_server_session.rs` — `decode_all`
- `justrdp-pdu/tests/fixtures/session/` — the capture and its README

## Reference behaviour

Opened by **#304**, and this territory was born with it —
`crates/justrdp-pdu/tests/fixtures/session/save-session-info.bin`, two whole TPKT frames carved
from a 27 260-byte session read on 2026-09-21. Its README carries the decode; the assertions are
in `justrdp-pdu/tests/real_server_session.rs`, and the live half is
`justrdp-tokio`'s `save_session_info_reaches_the_host_against_real_vm`.

**Always the session leg, never the connect leg. One or two PDUs, and which is not established.**
Five logons: four sent `LogonLong` + `Extended`, one sent `LogonLong` alone — the run that
lacked `Extended` was the first after the VM's account was reset, but no condition has been
pinned. The first three runs all sent two, which is how a transient nearly became a contract
here: the real-VM test asserted `>= 2` and was flaky by construction until the fourth run
refuted it.

**That variance is what makes `ActivationResult::save_session_info` a `Vec`**, and more strongly
than the original argument did: one logon has been observed to produce both one notification and
two, so no fixed-arity carrier is right.

Only `LogonLong` names the account, and exactly one of it arrives per logon.

| Order | `infoType` | Content |
|---|---|---|
| 1 | `INFOTYPE_LOGON_EXTENDED_INFO` | `FieldsPresent = 0x2` (errors only, **no cookie**), type `0xFFFFFFFE`, data = the session ID |
| 2 | `INFOTYPE_LOGON_LONG` | `Version = 1`, `Size = 18`, `Domain = "WIN-R21QJTDL2C2"`, `UserName = "rdptest"` |

Three places this server disagrees with a reading somebody holds, each now a test:

- **`Size = 18`, where 2.2.10.1.1.2 defines it as 576** (the structure excluding the two variable
  strings). FreeRDP records Windows Server 2019 doing this and accepts both; **IronRDP accepts
  only 18** and so would reject a server that obeyed the spec. WS2022 behaves like WS2019.
- **`Length = 18`** — the fields without the 570-byte pad. 2.2.10.1.1.4 calls it *"the total size
  in bytes of this structure, including the variable LogonFields field"*, and this structure ends
  with that pad. A decoder framing from `Length` under the spec's own sentence mis-parses this
  conforming server.
- **`errorNotificationData` is a session ID, not an error code.** It was 2, 3 and 6 on logons
  whose `SessionId` was 2, 3 and 6 — it tracks the session. IronRDP maps `0..=3` to
  `LogonErrorNotificationDataErrorCode`, so it reads all three as `FailedOther` / `Warning`.

One further fact taken from FreeRDP rather than observed here: **Windows 11 appends undocumented
trailing padding** after Logon Info V2's strings, and FreeRDP seeks past it. That is why full
consumption is not an invariant of this PDU and why the decoder does not assert it — the corpus
test does, because *this* server consumes exactly.

**Bounded: one WS2022 box, one advertised configuration, one account.** It proves what this
server sends, never what servers send.

## Cross-cutting invariants

- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — every byte
  here came from the network, and the three pads (576, 570, 558) are the longest reads in the
  area and the easiest to truncate into.
- [A decoded field with no reader is an unstated decision](../invariant/a-decoded-field-with-no-reader-is-an-unstated-decision.md)
  — `Size`, `Length` and `cbFieldData` are three instances taken the *recorded* way out in the
  same change, and `ServerAutoReconnect::version` is a fourth whose reader arrives with #306.
- [Capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
  — this VM sends two of the five `infoType` arms and never a cookie, so three arms and the
  whole `ARC_SC` branch are unobserved rather than absent.

## Blast radius

- [Session loop & PDU dispatch](session-loop-dispatch.md) — owns the session leg's arm and
  the output set this adds a sixth member to.
- [Capability exchange & activation](capability-exchange-activation.md) — owns the connect
  leg's arm and `ActivationResult`, the struct that carries the connect-leg copy across.
- [Adapter drive loop](adapter-drive-loop.md) — `SessionEvent` is where a host actually
  receives this, and one of the two session entry points has no event sink at all.
- [PDU constants & flag tables](pdu-constants.md) — `PDU_TYPE2_SAVE_SESSION_INFO` had been a
  constant nothing read.
- [Verification harness](verification-harness.md) — the capture hook that would produce this
  area's first fixture runs on the connect leg only.

## Known holes / open

- **The capture hook still stops at session-active.** `capture_connect_chunk` runs only in the
  adapter's connect read loop, so this area's fixture had to be teed by hand during #304 rather
  than produced by the mechanism the repo has for exactly this. Every future session-leg PDU
  slice meets the same wall.
- **Three of the five decoder arms have no server here — and one of them is unreachable by
  our own configuration, not by the server's choice.** 2.2.10.1.1 ties `INFOTYPE_LOGON_LONG` to
  the `LONG_CREDENTIALS_SUPPORTED` flag, and `capability.rs`'s `GeneralCapabilitySet` sets it,
  so **Logon Info V1 cannot arrive while this client advertises what it advertises**. That is
  [capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md)
  at its sharpest: the V1 arm is not waiting on a different server, it is waiting on a different
  capability set. **Plain Notify** and an undefined `infoType` are genuinely unobserved. All
  three rest on hand-built bodies and the two references.
- **No auto-reconnect cookie on this VM.** `FieldsPresent` has been `LOGON_EX_LOGONERRORS` alone
  on every observed logon, so the `ARC_SC_PRIVATE_PACKET` branch has no real bytes —
  [capture coverage follows what we advertise](../invariant/capture-coverage-follows-what-we-advertise.md).
  #306's *"capture the cookie, reconnect with it, assert the session resumed"* acceptance has
  **no proof path on this VM as configured**, which that slice needs to know before it starts.
- **The cookie is decoded and nothing replays it** (#306). `ClientInfo::reconnect_cookie` is
  still `None` on every connection, so no session is ever resumed — this area supplies the
  input that slice needs and takes none of its decisions.
- **Set Keyboard Indicators (0x29) is still in the catch-all** (#305) — the other half of
  epic #25 and the last `pduType2` this area's neighbours drop in silence.
- **`LogonErrorsInfo::notification_data` is polymorphic and typed as `u32`.** For the
  reconnect-offering notification types it is a session ID, not an error code; the decoder
  carries the raw value and `description()` does not distinguish them.
