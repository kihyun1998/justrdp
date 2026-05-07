import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { RdpCanvas } from "./RdpCanvas";
import "./App.css";

// Backend-shaped event payload. Mirror of `FrontendEvent` in
// src-tauri/src/lib.rs — keep in sync.
interface BlitPayload {
  x: number;
  y: number;
  w: number;
  h: number;
  /// Top-down RGBA8, base64-encoded. Length is `w * h * 4` bytes
  /// pre-base64.
  rgba_b64: string;
}

interface PointerSpritePayload {
  width: number;
  height: number;
  hotspot_x: number;
  hotspot_y: number;
  /// Top-down RGBA8, base64-encoded. Length is `width * height * 4`
  /// bytes pre-base64.
  rgba_b64: string;
}

type RdpEvent =
  | { kind: "frame"; blits: BlitPayload[] }
  | { kind: "pointer_position"; x: number; y: number }
  | { kind: "pointer_hidden" }
  | { kind: "pointer_default" }
  | ({ kind: "pointer_sprite" } & PointerSpritePayload)
  | { kind: "disconnected"; reason: string }
  | { kind: "error"; message: string };

const CANVAS_WIDTH = 1024;
const CANVAS_HEIGHT = 768;

/// Decode a base64 RGBA payload into Uint8ClampedArray and blit it.
/// `atob` is sync and runs on the main thread — fine for damaged
/// rectangles in the typical few-KB to few-hundred-KB range. If the
/// server pushes full-screen 32bpp at high frame rates we'd want a
/// binary IPC channel (Tauri `Channel` API) instead, but that's a
/// later optimisation.
function drawBlit(ctx: CanvasRenderingContext2D, blit: BlitPayload) {
  const bin = atob(blit.rgba_b64);
  const len = bin.length;
  const bytes = new Uint8ClampedArray(len);
  for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
  const imageData = new ImageData(bytes, blit.w, blit.h);
  ctx.putImageData(imageData, blit.x, blit.y);
}

/// Convert a server-decoded cursor sprite into a CSS cursor value
/// (`url(<data:image/png;base64,...>) <hsX> <hsY>, default`).
/// Off-screen canvas keeps the main RDP framebuffer untouched.
function spriteToCursorCss(sprite: PointerSpritePayload): string {
  const off = document.createElement("canvas");
  off.width = sprite.width;
  off.height = sprite.height;
  const ctx = off.getContext("2d");
  if (!ctx) return "default";
  const bin = atob(sprite.rgba_b64);
  const bytes = new Uint8ClampedArray(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  ctx.putImageData(new ImageData(bytes, sprite.width, sprite.height), 0, 0);
  const dataUri = off.toDataURL("image/png");
  return `url(${dataUri}) ${sprite.hotspot_x} ${sprite.hotspot_y}, default`;
}

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
  // Canvas ref is owned by the parent so the listen callback can
  // blit into it without re-renders. Lifted out of `RdpCanvas`
  // because event handlers must not depend on child component state.
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Listen for backend events. Empty deps → mount once. The cleanup
  // returned from useEffect calls `unlisten()` so React StrictMode's
  // dev double-invoke doesn't leave a stale listener around.
  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    listen<RdpEvent>("rdp:event", (event) => {
      const payload = event.payload;
      switch (payload.kind) {
        case "frame": {
          const ctx = canvasRef.current?.getContext("2d");
          if (ctx) {
            for (const blit of payload.blits) {
              drawBlit(ctx, blit);
            }
          }
          // Counter is per-update (one IPC event per server-pushed
          // GraphicsUpdate, regardless of how many rects it carried).
          setFrameCount((n) => n + 1);
          break;
        }
        case "pointer_position":
          setPointerPos([payload.x, payload.y]);
          break;
        case "pointer_hidden":
          // Originally `cursor: none` per Slice α — but Windows
          // sends Hidden during normal session bring-up before any
          // sprite arrives, and Slice β only decodes Color pointer
          // (0x09); New/Large/Cached are silent-dropped today, so
          // the host cursor would stay invisible until Slice γ / δ
          // wires the rest. Fall back to OS default until then —
          // proper hide (password field) lands once all sprite
          // types decode.
          if (canvasRef.current) {
            canvasRef.current.style.cursor = "default";
          }
          break;
        case "pointer_default":
          if (canvasRef.current) {
            canvasRef.current.style.cursor = "default";
          }
          break;
        case "pointer_sprite":
          // Slice β: server pushed a decoded color sprite. Convert
          // RGBA → PNG data URI → CSS cursor URL (with hotspot).
          if (canvasRef.current) {
            canvasRef.current.style.cursor = spriteToCursorCss(payload);
          }
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

  async function tryConnect(): Promise<number> {
    return invoke<number>("rdp_connect", {
      host: form.host,
      port: form.port,
      user: form.user,
      pass: form.pass,
      domain: form.domain.trim() === "" ? null : form.domain,
    });
  }

  async function onConnect(e: React.FormEvent) {
    e.preventDefault();
    if (busy || sessionId !== null) return;
    setBusy(true);
    setStatus("connecting…");
    setFrameCount(0);
    setPointerPos(null);
    try {
      // First attempt — succeeds when the server's SPKI is already
      // in the trust store (returning user) or when the build was
      // compiled with `dev-no-verify`.
      const id = await tryConnect();
      setSessionId(id);
      setStatus("connected");
    } catch (err) {
      // First attempt failed. The most likely cause in production
      // builds is an unknown / mismatched SPKI — surface the
      // fingerprint to the user and offer to trust it. If fetching
      // the fingerprint also fails, give up and report the original
      // connect error.
      try {
        setStatus("fetching server certificate…");
        const spki: string = await invoke("rdp_fetch_cert_spki", {
          host: form.host,
          port: form.port,
        });
        const accepted = window.confirm(
          `Server ${form.host}:${form.port}\n\n` +
            `SPKI fingerprint (SHA-256):\n${spki}\n\n` +
            `Trust this server and connect? Click OK only if you ` +
            `recognise this fingerprint.`,
        );
        if (!accepted) {
          setStatus("connection refused (untrusted certificate)");
          return;
        }
        await invoke("rdp_trust_spki", { host: form.host, spkiHex: spki });
        setStatus("trust persisted, reconnecting…");
        const id = await tryConnect();
        setSessionId(id);
        setStatus("connected");
      } catch (retryErr) {
        setStatus(`connect failed: ${err} (retry: ${retryErr})`);
      }
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

  return (
    <main className="container">
      <h1>JustRDP — Tauri MVP (Slice C)</h1>
      <p className="subtitle">
        connect / input / disconnect cycle + bitmap rendering +
        full keyboard / mouse / wheel interactivity. Click the canvas
        to focus it, then type or click as if it were the remote
        desktop.
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
          busy={busy}
          canvasRef={canvasRef}
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
  busy: boolean;
  canvasRef: React.RefObject<HTMLCanvasElement | null>;
}

function SessionPanel({
  sessionId,
  frameCount,
  pointerPos,
  onDisconnect,
  busy,
  canvasRef,
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
      <RdpCanvas
        sessionId={sessionId}
        canvasRef={canvasRef}
        width={CANVAS_WIDTH}
        height={CANVAS_HEIGHT}
      />
      <div className="row">
        <button onClick={onDisconnect} disabled={busy}>
          {busy ? "disconnecting…" : "disconnect"}
        </button>
      </div>
    </div>
  );
}

export default App;
