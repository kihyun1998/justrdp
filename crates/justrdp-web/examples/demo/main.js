// Demo bootstrap — drives the JsClient handle from a browser <canvas>.
//
// This file is hand-written JS (not generated). It expects the wasm
// bundle at ./pkg/justrdp_web.js produced by:
//   wasm-pack build --target web --out-dir examples/demo/pkg
//
// All interesting logic lives in the Rust side; this file only shuffles
// DOM events into JsClient method calls and renders log lines.

import init, { JsClient } from './pkg/justrdp_web.js';

const $ = (id) => document.getElementById(id);
const log = (msg, cls) => {
  const div = document.createElement('div');
  if (cls) div.className = cls;
  div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  $('log').prepend(div);
};

let client = null;
let pollHandle = null;

async function connect() {
  $('connectBtn').disabled = true;
  $('status').textContent = 'connecting…';
  try {
    client = new JsClient();
    client.attachCanvas($('screen'));
    const summary = await client.connect(
      $('url').value,
      $('user').value,
      $('pw').value,
      $('domain').value || null,
    );
    log(`connected: ${JSON.stringify(summary)}`, 'ok');
    $('status').textContent = 'connected';
    $('disconnectBtn').disabled = false;
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
    } catch (e) {
      log(`poll error: ${e?.message ?? e}`, 'err');
      break;
    }
  }
  // Ran out of work or hit an error — clean up UI state.
  $('disconnectBtn').disabled = true;
  $('connectBtn').disabled = false;
  $('status').textContent = 'idle';
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
