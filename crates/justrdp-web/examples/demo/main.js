// Demo bootstrap — drives the JsClient handle from a browser <canvas>.
//
// This file is hand-written JS (not generated). It expects the wasm
// bundle at ./pkg/justrdp_web.js produced by:
//   wasm-pack build --target web --out-dir examples/demo/pkg
//
// All interesting logic lives in the Rust side; this file only shuffles
// DOM events into JsClient method calls and renders log lines.

import init, { JsClient } from './pkg/justrdp_web.js';
import { lookup as lookupScancode } from './keymap.js';

const $ = (id) => document.getElementById(id);
const log = (msg, cls) => {
  const div = document.createElement('div');
  if (cls) div.className = cls;
  div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  $('log').prepend(div);
};

let client = null;

async function connect() {
  $('connectBtn').disabled = true;
  $('status').textContent = 'connecting…';
  try {
    client = new JsClient();
    client.attachCanvas($('screen'));
    client.setExternalTls($('extTls').checked);
    const summary = await client.connect(
      $('url').value,
      $('user').value,
      $('pw').value,
      $('domain').value || null,
    );
    log(`connected: ${JSON.stringify(summary)}`, 'ok');
    if (client.hasClipboard) {
      log('cliprdr negotiated — clipboard sync active', 'ok');
    } else {
      log('cliprdr not negotiated — clipboard sync disabled');
    }
    $('status').textContent = 'connected';
    $('disconnectBtn').disabled = false;
    attachInputListeners();
    attachClipboardListeners();
    pollLoop();
  } catch (e) {
    log(`connect failed: ${e?.message ?? e}`, 'err');
    $('status').textContent = 'idle';
    $('connectBtn').disabled = false;
    client = null;
  }
}

async function pollLoop() {
  while (client && client.connected) {
    try {
      const blits = await client.pollEvents();
      if (blits > 0) {
        // Throttle log spam — only print once per 60-frame burst.
        if (Math.random() < 0.02) log(`drew ${blits} rect(s)`);
      }
      // pollEvents drained any incoming clipboard PDU into the
      // ClipboardChannel cache; check for new remote text and push
      // it into the browser's clipboard.
      await syncClipboardFromRdp();
    } catch (e) {
      log(`poll error: ${e?.message ?? e}`, 'err');
      break;
    }
  }
  // Ran out of work or hit an error — clean up UI state.
  $('disconnectBtn').disabled = true;
  $('connectBtn').disabled = false;
  $('status').textContent = 'idle';
  detachInputListeners();
  detachClipboardListeners();
  client = null;
}

async function disconnect() {
  if (!client) return;
  $('disconnectBtn').disabled = true;
  try {
    await client.disconnect();
    log('disconnected', 'ok');
  } catch (e) {
    log(`disconnect: ${e?.message ?? e}`, 'err');
  }
}

// ── Input forwarding ────────────────────────────────────────────────

const canvas = $('screen');

// Translate a MouseEvent's offset (relative to the canvas's CSS box)
// into desktop pixels by undoing any CSS scaling. The canvas's
// internal resolution is set by JsClient.attachCanvas via
// FrameSink::resize on the first frame.
function canvasToDesktop(evt) {
  const rect = canvas.getBoundingClientRect();
  const sx = canvas.width / rect.width;
  const sy = canvas.height / rect.height;
  const x = Math.max(0, Math.min(canvas.width - 1, Math.round((evt.clientX - rect.left) * sx)));
  const y = Math.max(0, Math.min(canvas.height - 1, Math.round((evt.clientY - rect.top) * sy)));
  return { x, y };
}

async function onMouseMove(e) {
  if (!client?.connected) return;
  const { x, y } = canvasToDesktop(e);
  try { await client.sendMouseMove(x, y); } catch (err) { /* swallow per-event */ }
}

async function onMouseButton(e, pressed) {
  if (!client?.connected) return;
  const { x, y } = canvasToDesktop(e);
  // MouseEvent.button: 0=left, 1=middle, 2=right.
  // JsClient.sendMouseButton: 0=left, 1=right, 2=middle.
  // Translate so JS embedders don't have to remember the difference.
  const jsButton = e.button === 1 ? 2 : (e.button === 2 ? 1 : 0);
  try { await client.sendMouseButton(x, y, jsButton, pressed); } catch (err) {}
  // Stop the browser's default context menu / text selection while
  // the canvas is the input target.
  e.preventDefault();
}

async function onWheel(e) {
  if (!client?.connected) return;
  const { x, y } = canvasToDesktop(e);
  // Browser deltaY is positive for "wheel down". RDP convention is
  // positive for "wheel up", so we invert. Magnitudes vary by
  // browser; clamp to a single-notch ±120 step for a consistent feel.
  const direction = -Math.sign(e.deltaY) || 0;
  if (direction !== 0) {
    try { await client.sendMouseWheel(x, y, 120 * direction, false); } catch (err) {}
    e.preventDefault();
  }
}

async function onKey(e, pressed) {
  if (!client?.connected) return;
  const mapping = lookupScancode(e.code);
  if (!mapping) return;
  const [scancode, extended] = mapping;
  try {
    if (pressed) await client.sendKeyDown(scancode, extended);
    else await client.sendKeyUp(scancode, extended);
  } catch (err) {}
  e.preventDefault();
}

const onMouseDown = (e) => onMouseButton(e, true);
const onMouseUp = (e) => onMouseButton(e, false);
const onContextMenu = (e) => e.preventDefault();
const onKeyDown = (e) => onKey(e, true);
const onKeyUp = (e) => onKey(e, false);

function attachInputListeners() {
  canvas.tabIndex = 0; // make the canvas focusable for key events
  canvas.focus();
  canvas.addEventListener('mousemove', onMouseMove);
  canvas.addEventListener('mousedown', onMouseDown);
  canvas.addEventListener('mouseup', onMouseUp);
  canvas.addEventListener('wheel', onWheel, { passive: false });
  canvas.addEventListener('contextmenu', onContextMenu);
  canvas.addEventListener('keydown', onKeyDown);
  canvas.addEventListener('keyup', onKeyUp);
}

function detachInputListeners() {
  canvas.removeEventListener('mousemove', onMouseMove);
  canvas.removeEventListener('mousedown', onMouseDown);
  canvas.removeEventListener('mouseup', onMouseUp);
  canvas.removeEventListener('wheel', onWheel);
  canvas.removeEventListener('contextmenu', onContextMenu);
  canvas.removeEventListener('keydown', onKeyDown);
  canvas.removeEventListener('keyup', onKeyUp);
}

// ── Clipboard sync ──────────────────────────────────────────────────

/// When the RDP server pushes new clipboard text, mirror it into the
/// browser via navigator.clipboard.writeText. Skipped silently if
/// the browser denies the permission (the user can copy manually).
async function syncClipboardFromRdp() {
  if (!client?.hasClipboard) return;
  const text = client.pollRemoteClipboardText();
  if (typeof text !== 'string') return;
  try {
    await navigator.clipboard.writeText(text);
    log(`rdp → browser: ${text.length} chars`);
  } catch (e) {
    /* permission denied / not focused — silent */
  }
}

/// When the user copies in the browser (Ctrl+C or paste-ready content
/// on the canvas focus), push the text into the RDP clipboard.
async function syncClipboardToRdp() {
  if (!client?.hasClipboard) return;
  let text;
  try {
    text = await navigator.clipboard.readText();
  } catch (e) {
    return; // permission denied
  }
  if (!text) return;
  try {
    await client.setLocalClipboardText(text);
    log(`browser → rdp: ${text.length} chars`);
  } catch (e) {
    log(`clipboard push failed: ${e?.message ?? e}`, 'err');
  }
}

const onCanvasFocus = () => {
  // Best effort: when the canvas takes focus, push the browser
  // clipboard to RDP so the user can paste right away.
  syncClipboardToRdp();
};

const onCopyShortcut = (e) => {
  // Detect Ctrl/Cmd+C inside the canvas — push browser clipboard.
  if (!(e.ctrlKey || e.metaKey)) return;
  if (e.code !== 'KeyC') return;
  // Defer one tick so the browser populates the clipboard first.
  setTimeout(() => { syncClipboardToRdp().catch(() => {}); }, 50);
};

function attachClipboardListeners() {
  canvas.addEventListener('focus', onCanvasFocus);
  canvas.addEventListener('keydown', onCopyShortcut);
}

function detachClipboardListeners() {
  canvas.removeEventListener('focus', onCanvasFocus);
  canvas.removeEventListener('keydown', onCopyShortcut);
}

(async function bootstrap() {
  try {
    await init();
    log('wasm loaded', 'ok');
  } catch (e) {
    log(`wasm load failed: ${e?.message ?? e}`, 'err');
    return;
  }
  $('connectBtn').addEventListener('click', connect);
  $('disconnectBtn').addEventListener('click', disconnect);
})();
