# Tauri reference client — smoke test procedure

End-to-end verification of `justrdp-tauri` against a real RDP
server. Slice G of PRD #1 — the final acceptance step before the
§11.5a roadmap milestone can be ticked off.

This procedure is HITL by design. The 8 user-facing checks below
involve human judgement (audio quality, cursor smoothness, paste
correctness) that no headless harness can substitute for.

## Prerequisites

- A built production binary from `pnpm tauri build` (Slice F).
  See `docs/agents/tauri-packaging.md` for the build steps.
- A real RDP server reachable from the host running the binary.
  The reference target is **Windows Server 2019, NLA / NTLMv2,
  port 3389**. Default test environment: `192.168.136.136`.
  Credentials live outside the repo — keep them in your
  password manager or a `.env.local` you do not commit.
- Audio output device active on the host (speakers / headphones)
  for check #8.

## Procedure (8 user-facing checks + 3 timing checks)

Capture each step's outcome (screenshot or short note) and paste
the bundle as a comment on issue #7 when finished.

### 1. Connect succeeds
- Launch the installed binary
- Fill the connect form: host `192.168.136.136`, port `3389`,
  user / pass / domain
- Click **connect**
- **First time only**: a `window.confirm` dialog shows the SPKI
  hex fingerprint. Click **OK** to trust → store persists →
  reconnects automatically
- **Pass**: status bar shows `connected`; session id appears

### 2. Desktop renders
- Within ~1–2 seconds of connect, the canvas paints the remote
  desktop (login screen or shell)
- **Pass**: pixels visible; no all-black canvas

### 3. Keyboard text input
- Click the canvas to focus it
- Open Notepad on the remote (Win key → "notepad" → Enter — but
  this depends on check #5; instead use Run dialog: Win+R, type
  `notepad`, Enter)
- Type "hello world from JustRDP"
- **Pass**: text appears in Notepad letter-for-letter

### 4. Mouse Start menu click
- Move the mouse to the bottom-left Start button on the remote
- Left-click
- **Pass**: Start menu opens

### 5. Modifier shortcut (Win+E)
- Press and release Win+E (Meta+E)
- **Pass**: File Explorer opens on the remote
- **Bonus check**: Alt+Tab between windows works

### 6. Clipboard host → remote
- On the host OS, copy a unique string (e.g. "host-clip-test-42")
  to the system clipboard
- Click the canvas, focus the remote Notepad, press Ctrl+V
- **Pass**: the unique string appears in remote Notepad

### 7. Clipboard remote → host
- In the remote Notepad, select a unique string (e.g.
  "remote-clip-test-99"), press Ctrl+C
- Switch to a host-side editor (Notepad, VS Code, etc.) and
  press Ctrl+V
- **Pass**: the unique string appears in the host editor

### 8. Audio playback
- Trigger an audible event on the remote — easiest:
  open a remote PowerShell window and run
  `[console]::beep(440, 500)`
- **Pass**: a 440 Hz beep plays through the host's speakers
- Alternative: log out and back in to hear the Windows logon
  chime

### 9. 5-minute idle hold
- Leave the session connected and idle for 5 minutes (no
  input, no clicks)
- **Pass**: at the 5-minute mark, the session is still connected;
  no `Disconnected` event; canvas remains responsive when you
  return

### 10. Disconnect button latency
- Click the **disconnect** button
- **Pass**: status flips to `disconnecting…` and then a
  terminal state within **1 second**

### 11. Server-initiated disconnect propagation
- Reconnect, then on the remote run `logoff` (or close the RDP
  session from Server Manager)
- **Pass**: the host UI shows the disconnect within **1 second**
  of the server tearing down

## Recording the result

Post a single comment on issue #7 with:

- Date / build commit hash / OS
- Pass / fail per checkmark above
- Screenshot for any visual checks worth showing
- Short text log of any failure (error message, observed
  behaviour, expected behaviour)

If any check fails, spawn a separate issue per failure and link
it back to #7 in the result comment. Do not bundle multiple
unrelated failures into one issue.

## Close conditions

- All 11 checks pass → close issue #7, then close #2/#3/#4/#5/#6
  in batch (each with a one-line "verified by smoke #7")
- Then close PRD #1 with a note about §11.5a roadmap completion
  and the M-Server unblock (per ADR-0005)

## Troubleshooting

### TLS handshake fails before the trust prompt fires
- Check the server's TLS configuration. Some legacy RDP servers
  require TLS 1.2; `justrdp-tokio`'s rustls is built with `tls12`
  but the server may insist on a specific cipher
- Try `pnpm tauri dev -- -- --features dev-no-verify` to bypass
  the verifier and isolate the issue to TLS vs trust-store

### Canvas stays black after connect
- Hit **disconnect** and reconnect — early frames may be
  dropped during handshake
- Verify the remote desktop is actually painting (move the
  mouse on a console or Hyper-V VMConnect)

### Audio silent on Windows
- Confirm the remote's RDP audio policy is "Play on this
  computer" (Group Policy: Computer Configuration → Admin
  Templates → Windows Components → Remote Desktop Services →
  Remote Desktop Session Host → Device and Resource Redirection)
- Check the host's default audio device has output (system
  tray volume mixer)

### Clipboard one-direction only
- Verify the remote's clipboard redirection policy is enabled
  for both directions
- Check that the host clipboard isn't locked by another app
  (e.g. some password managers grab and hold it)
