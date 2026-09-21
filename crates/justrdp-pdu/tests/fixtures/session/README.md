# `session/` — server bytes captured after session-active

Server-to-client only, so no credential crosses into these files: the Client Info PDU carrying
the password travels the other way and never reaches a capture. Captured from the real VM
(`docs/agents/thegraph.md`'s third source; memory `test_environment`), one WS2022 box on one
advertised configuration — **they prove what this server sends, never what servers send.**

The sibling `connect/` holds bytes from before the Font Map, recorded by `justrdp_tokio`'s
`JUSTRDP_CONNECT_CAPTURE_FILE` hook. This directory exists because **that hook stopped at
`Action::SessionActive`**, so nothing in the repo could record a session-leg PDU: these bytes
were teed by a throwaway drive loop written by hand during #304 and carved down to the frames
that matter.

**#308 closed that, and the capture was reproduced through it.** `JUSTRDP_SESSION_CAPTURE_FILE`
now records every session read, and a run through it yielded the same two frames at the same
sizes — plus a third the hand-tee never saw, because the capture is per **process** and the
harness reconnects to sign out. Use the env var for the next one; this file stays as it was
carved.

## `save-session-info.bin`

Two complete TPKT frames, 625 + 661 = 1286 bytes, carved out of a 27 260-byte session read
(31 TPKT + 20 fast-path frames) — everything else was graphics. Captured 2026-09-21 for
**#304**, in arrival order:

| # | `infoType` | What it carries |
|---|---|---|
| 1 | `INFOTYPE_LOGON_EXTENDED_INFO` (3) | `FieldsPresent = 0x00000002` — logon errors only, **no auto-reconnect cookie**. `errorNotificationType = 0xFFFFFFFE` (session continue), `errorNotificationData = 3` |
| 2 | `INFOTYPE_LOGON_LONG` (1) | `Version = 1`, `Size = 18`, `SessionId = 3`, `Domain = "WIN-R21QJTDL2C2"`, `UserName = "rdptest"` |

### What it pins that an argument could not

- **One logon can produce two PDUs.** `ActivationResult::save_session_info` is a `Vec` and not
  an `Option` on exactly this evidence: an `Option` drops one of these two.
  **It can also produce one** — a later logon sent the `LogonLong` alone, with no `Extended`.
  Whatever decides that is not established, so the count is a range and not a fact; the capture
  here is the two-PDU case.
- **The session leg carries them and the connect leg carries none.** Five logons, no exception.
- **`Size` is 18, where 2.2.10.1.1.2 defines it as 576** (the structure excluding the two
  variable strings). FreeRDP notes Windows Server 2019 does this; WS2022 does it too. IronRDP
  accepts *only* 18 and would reject a server that obeyed the spec. justrdp reads and ignores it.
- **`Length` is 18 — the fields without the 570-byte pad.** 2.2.10.1.1.4 calls it *"the total
  size in bytes of this structure, including the variable LogonFields field"*, which reads as
  including the pad. This server disagrees with that reading, so a decoder that framed from
  `Length` would mis-parse a conforming server. justrdp does not frame from it.
- **`errorNotificationData` is a session ID here, not an error code.** It was `2` on a capture
  whose `SessionId` was `2` and `3` on this one — it tracks the session. IronRDP maps `0..=3` to
  a `LogonErrorNotificationDataErrorCode`, so it reads this value as `FailedOther` / `Warning`.
  justrdp carries the raw `u32`.

### What it cannot see

**No auto-reconnect cookie.** This server sent `LOGON_EX_LOGONERRORS` alone across every
observed logon, so the `ARC_SC_PRIVATE_PACKET` path has **no fixture and no server here** —
`docs/map/invariant/capture-coverage-follows-what-we-advertise.md` applies, and #306's
"capture the cookie, reconnect with it" acceptance has no proof path on this VM as configured.
The cookie branch is covered by hand-built bodies in `justrdp-pdu/src/session_info.rs` only.

Nor does it exercise Logon Info **V1**, Plain Notify, or an undefined `infoType` — and the
first of those is worth separating from the other two. 2.2.10.1.1 says `INFOTYPE_LOGON_LONG`
*"SHOULD be used if the LONG_CREDENTIALS_SUPPORTED (0x00000004) flag is set in the General
Capability Set"*, and this client sets it (`capability.rs`, `GeneralCapabilitySet::extra_flags`).
So **V1 is unreachable while we advertise what we advertise** — no server change would produce
it here. Plain Notify and an undefined type are unobserved in the ordinary way. All three rest
on the unit tests and the two references.
