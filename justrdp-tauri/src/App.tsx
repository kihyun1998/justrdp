import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import "./App.css";

// Backend-shaped event payload. Mirror of `FrontendEvent` in
// src-tauri/src/lib.rs — keep in sync.
type RdpEvent =
  | { kind: "frame"; count: number }
  | { kind: "pointer_position"; x: number; y: number }
  | { kind: "disconnected"; reason: string }
  | { kind: "error"; message: string };

interface ConnectForm {
  host: string;
  port: number;
  user: string;
  pass: string;
  domain: string;
}

const DEFAULT_FORM: ConnectForm = {
  host: "192.168.136.136",
  port: 3389,
  user: "",
  pass: "",
  domain: "",
};

function App() {
  const [form, setForm] = useState<ConnectForm>(DEFAULT_FORM);
  const [sessionId, setSessionId] = useState<number | null>(null);
  const [status, setStatus] = useState<string>("disconnected");
  const [frameCount, setFrameCount] = useState<number>(0);
  const [pointerPos, setPointerPos] = useState<[number, number] | null>(null);
  const [busy, setBusy] = useState<boolean>(false);

  // Listen for backend events. Empty deps → mount once. The cleanup
  // returned from useEffect calls `unlisten()` so React StrictMode's
  // dev double-invoke doesn't leave a stale listener around.
  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    listen<RdpEvent>("rdp:event", (event) => {
      const payload = event.payload;
      switch (payload.kind) {
        case "frame":
          setFrameCount(payload.count);
          break;
        case "pointer_position":
          setPointerPos([payload.x, payload.y]);
          break;
        case "disconnected":
          setStatus(`disconnected: ${payload.reason}`);
          setSessionId(null);
          break;
        case "error":
          setStatus(`error: ${payload.message}`);
          setSessionId(null);
          break;
      }
    }).then((u) => {
      unlisten = u;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  async function onConnect(e: React.FormEvent) {
    e.preventDefault();
    if (busy || sessionId !== null) return;
    setBusy(true);
    setStatus("connecting…");
    setFrameCount(0);
    setPointerPos(null);
    try {
      const id = await invoke<number>("rdp_connect", {
        host: form.host,
        port: form.port,
        user: form.user,
        pass: form.pass,
        domain: form.domain.trim() === "" ? null : form.domain,
      });
      setSessionId(id);
      setStatus("connected");
    } catch (err) {
      setStatus(`connect failed: ${err}`);
    } finally {
      setBusy(false);
    }
  }

  async function onDisconnect() {
    if (sessionId === null || busy) return;
    setBusy(true);
    setStatus("disconnecting…");
    try {
      await invoke("rdp_disconnect", { id: sessionId });
      setStatus("disconnected");
    } catch (err) {
      setStatus(`disconnect failed: ${err}`);
    } finally {
      setSessionId(null);
      setBusy(false);
    }
  }

  // Slice A demo: send a hardcoded key (the letter 'a'). 8-bit
  // scancode for 'A' on AT/PS-2 is 0x1E, no extended bit. Slice B
  // (or a dedicated keymap track) wires up KeyboardEvent → scancode.
  async function sendDemoKey() {
    if (sessionId === null) return;
    try {
      await invoke("rdp_send_input", {
        id: sessionId,
        event: { kind: "key", code: 0x1e, extended: false, pressed: true },
      });
      await invoke("rdp_send_input", {
        id: sessionId,
        event: { kind: "key", code: 0x1e, extended: false, pressed: false },
      });
    } catch (err) {
      setStatus(`send_input failed: ${err}`);
    }
  }

  return (
    <main className="container">
      <h1>JustRDP — Tauri MVP (Slice A)</h1>
      <p className="subtitle">
        connect / input / disconnect cycle. Frame decoding (BitmapRenderer)
        arrives in Slice B.
      </p>

      {sessionId === null ? (
        <ConnectForm
          form={form}
          setForm={setForm}
          onConnect={onConnect}
          busy={busy}
        />
      ) : (
        <SessionPanel
          sessionId={sessionId}
          frameCount={frameCount}
          pointerPos={pointerPos}
          onDisconnect={onDisconnect}
          onSendDemoKey={sendDemoKey}
          busy={busy}
        />
      )}

      <p className="status">status: {status}</p>
    </main>
  );
}

interface ConnectFormProps {
  form: ConnectForm;
  setForm: React.Dispatch<React.SetStateAction<ConnectForm>>;
  onConnect: (e: React.FormEvent) => void;
  busy: boolean;
}

function ConnectForm({ form, setForm, onConnect, busy }: ConnectFormProps) {
  return (
    <form onSubmit={onConnect} className="connect-form">
      <label>
        host
        <input
          value={form.host}
          onChange={(e) => setForm({ ...form, host: e.target.value })}
          required
        />
      </label>
      <label>
        port
        <input
          type="number"
          value={form.port}
          onChange={(e) =>
            setForm({ ...form, port: parseInt(e.target.value, 10) || 3389 })
          }
          required
        />
      </label>
      <label>
        user
        <input
          value={form.user}
          onChange={(e) => setForm({ ...form, user: e.target.value })}
          autoComplete="username"
          required
        />
      </label>
      <label>
        password
        <input
          type="password"
          value={form.pass}
          onChange={(e) => setForm({ ...form, pass: e.target.value })}
          autoComplete="current-password"
          required
        />
      </label>
      <label>
        domain (optional)
        <input
          value={form.domain}
          onChange={(e) => setForm({ ...form, domain: e.target.value })}
        />
      </label>
      <button type="submit" disabled={busy}>
        {busy ? "connecting…" : "connect"}
      </button>
    </form>
  );
}

interface SessionPanelProps {
  sessionId: number;
  frameCount: number;
  pointerPos: [number, number] | null;
  onDisconnect: () => void;
  onSendDemoKey: () => void;
  busy: boolean;
}

function SessionPanel({
  sessionId,
  frameCount,
  pointerPos,
  onDisconnect,
  onSendDemoKey,
  busy,
}: SessionPanelProps) {
  return (
    <div className="session-panel">
      <p>
        session id: <code>{sessionId}</code>
      </p>
      <p>
        frame events: <code>{frameCount}</code>
      </p>
      <p>
        pointer:{" "}
        <code>
          {pointerPos ? `${pointerPos[0]}, ${pointerPos[1]}` : "(none)"}
        </code>
      </p>
      <RdpCanvasPlaceholder />
      <div className="row">
        <button onClick={onSendDemoKey} disabled={busy}>
          send demo key (a)
        </button>
        <button onClick={onDisconnect} disabled={busy}>
          {busy ? "disconnecting…" : "disconnect"}
        </button>
      </div>
    </div>
  );
}

/// Placeholder canvas. Slice A doesn't decode frames, so the canvas
/// stays empty — but we already mount it with the same ref-only,
/// memoized pattern that Slice B will use to blit RGBA. Mounting it
/// now means Slice B is purely additive (paint into the existing
/// canvas) instead of re-architecting the render path.
function RdpCanvasPlaceholder() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  return (
    <canvas
      ref={canvasRef}
      width={1024}
      height={768}
      className="rdp-canvas"
      tabIndex={0}
    />
  );
}

export default App;
