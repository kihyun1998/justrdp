import { useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { info } from "@tauri-apps/plugin-log";
import { keyEventToScancode } from "./keymap";

interface RdpCanvasProps {
  sessionId: number;
  /** Canvas ref owned by the parent so the rendering listener
   *  (`listen("rdp:event")`) and the input listener (this component)
   *  share the same DOM node — putImageData and event handlers
   *  both target this surface. */
  canvasRef: React.RefObject<HTMLCanvasElement | null>;
  width: number;
  height: number;
}

/**
 * Interactive RDP surface. Owns the canvas + a sibling hidden `<input>`
 * for IME composition input.
 *
 * **Why the hidden input** — `<canvas>` is not an IME composition target
 * per HTML spec, so OS-level IMEs (Korean / Japanese / Chinese / AltGr)
 * swallow keydown without firing `compositionstart`. Apache Guacamole
 * uses the same pattern. Pointer-down focuses the hidden input; ASCII
 * keydowns dispatch via the existing scancode path; on `compositionend`
 * the final text is decomposed into Unicode codepoints and dispatched
 * through `InputEvent::Unicode`.
 *
 * Held-key tracking: every key currently in `keydown` state is kept
 * in a Set so a `blur` event can synthesise `keyup`s for all of them
 * — without that, a Shift held while the user Alt-Tabs away would
 * stay logically pressed on the remote and break the next session.
 */
export function RdpCanvas({ sessionId, canvasRef, width, height }: RdpCanvasProps) {
  const imeInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const imeInput = imeInputRef.current;
    if (!canvas || !imeInput) return;

    const heldKeys = new Set<string>();
    let mouseX = 0;
    let mouseY = 0;

    const sendInput = (event: object) => {
      invoke("rdp_send_input", { id: sessionId, event }).catch((err) =>
        console.error("rdp_send_input failed:", err),
      );
    };

    const clampX = (clientX: number) => {
      const rect = canvas.getBoundingClientRect();
      return Math.max(0, Math.min(width - 1, Math.round(clientX - rect.left)));
    };
    const clampY = (clientY: number) => {
      const rect = canvas.getBoundingClientRect();
      return Math.max(0, Math.min(height - 1, Math.round(clientY - rect.top)));
    };

    const onKeyDown = (e: KeyboardEvent) => {
      // [DIAG-key]
      const sc = keyEventToScancode(e.code);
      info(
        `[DIAG-key] keydown code=${e.code} key=${e.key} isComposing=${e.isComposing} repeat=${e.repeat} sc=${sc ? "0x" + sc.code.toString(16) + (sc.extended ? "+ext" : "") : "null"}`,
      ).catch(() => {});
      // Suppress browser auto-repeat — the remote OS handles repeat.
      if (e.repeat) {
        e.preventDefault();
        return;
      }
      // During IME composition, swallow scancode dispatch — the
      // resulting text arrives via `compositionend` as Unicode chars.
      // Chromium also surfaces in-composition keydowns with `keyCode==229`
      // or `code=="Process"`; either marker means defer to composition.
      if (e.isComposing || e.keyCode === 229 || e.code === "Process") {
        return;
      }
      if (sc) {
        e.preventDefault();
        heldKeys.add(e.code);
        sendInput({ kind: "key", code: sc.code, extended: sc.extended, pressed: true });
      }
    };

    const onKeyUp = (e: KeyboardEvent) => {
      const sc = keyEventToScancode(e.code);
      info(
        `[DIAG-key] keyup code=${e.code} key=${e.key} sc=${sc ? "0x" + sc.code.toString(16) : "null"}`,
      ).catch(() => {});
      if (sc) {
        e.preventDefault();
        heldKeys.delete(e.code);
        sendInput({ kind: "key", code: sc.code, extended: sc.extended, pressed: false });
      }
    };

    const onCompositionStart = (e: CompositionEvent) => {
      info(`[DIAG-key] compositionstart data=${JSON.stringify(e.data)}`).catch(() => {});
    };
    const onCompositionUpdate = (e: CompositionEvent) => {
      info(`[DIAG-key] compositionupdate data=${JSON.stringify(e.data)}`).catch(() => {});
    };
    const onCompositionEnd = (e: CompositionEvent) => {
      const text = e.data || "";
      info(
        `[DIAG-key] compositionend data=${JSON.stringify(text)} chars=${[...text].length}`,
      ).catch(() => {});
      // Iterate Unicode code points (handles surrogate-pair emoji etc.;
      // Rust side will reject supplementary plane with NonBmpUnicode but
      // the iteration itself is correct).
      for (const ch of text) {
        const cp = ch.codePointAt(0);
        if (cp === undefined) continue;
        sendInput({ kind: "unicode", codepoint: cp, pressed: true });
        sendInput({ kind: "unicode", codepoint: cp, pressed: false });
      }
      // Clear so subsequent compositions start from empty value.
      imeInput.value = "";
    };
    const onFocus = () => {
      info(`[DIAG-key] ime focus`).catch(() => {});
    };
    const onBlurDiag = () => {
      info(`[DIAG-key] ime blur`).catch(() => {});
    };

    // Hidden input would otherwise intercept native clipboard / undo
    // operations and ingest into `input.value` — that ingestion ALSO
    // overwrites the host OS clipboard (with the empty input value),
    // breaking CLIPRDR host↔server sync. Keystrokes (Ctrl+C/V/X/Z) still
    // dispatch to the server through the existing scancode path; the
    // server uses its own clipboard which CLIPRDR keeps in sync with
    // host. Suppress the native input behavior so CLIPRDR is the only
    // clipboard pathway.
    const onClipboardEvent = (e: Event) => {
      e.preventDefault();
      info(`[DIAG-key] suppressed ${e.type}`).catch(() => {});
    };

    // Pointer events instead of mouse events so we can call
    // setPointerCapture on pointerdown — that's what keeps the
    // pointermove + pointerup events flowing to this canvas even
    // when the cursor leaves the canvas's bounding box.
    const onPointerMove = (e: PointerEvent) => {
      mouseX = clampX(e.clientX);
      mouseY = clampY(e.clientY);
      sendInput({ kind: "mouse_move", x: mouseX, y: mouseY });
    };

    const onPointerDown = (e: PointerEvent) => {
      // Focus the hidden IME input (NOT the canvas) so IME context is
      // valid + keydown / composition events flow to our handlers.
      imeInput.focus();
      try {
        canvas.setPointerCapture(e.pointerId);
      } catch {
        // Older browsers / unusual pointer types — fall back to
        // un-captured behaviour rather than refusing the click.
      }
      mouseX = clampX(e.clientX);
      mouseY = clampY(e.clientY);
      sendInput({ kind: "mouse_button", button: e.button, pressed: true, x: mouseX, y: mouseY });
      e.preventDefault();
    };

    const onPointerUp = (e: PointerEvent) => {
      mouseX = clampX(e.clientX);
      mouseY = clampY(e.clientY);
      sendInput({ kind: "mouse_button", button: e.button, pressed: false, x: mouseX, y: mouseY });
      if (canvas.hasPointerCapture(e.pointerId)) {
        canvas.releasePointerCapture(e.pointerId);
      }
      e.preventDefault();
    };

    const onPointerCancel = (e: PointerEvent) => {
      sendInput({
        kind: "mouse_button",
        button: e.button,
        pressed: false,
        x: mouseX,
        y: mouseY,
      });
    };

    const onWheel = (e: WheelEvent) => {
      const horizontal = Math.abs(e.deltaX) > Math.abs(e.deltaY);
      const raw = horizontal ? e.deltaX : e.deltaY;
      const delta = Math.max(-32768, Math.min(32767, -Math.round(raw)));
      sendInput({ kind: "wheel", delta, horizontal, x: mouseX, y: mouseY });
      e.preventDefault();
    };

    const onBlur = () => {
      // Release every held physical key so a held Shift / Ctrl during
      // an Alt-Tab away does not stay logically pressed on the remote.
      const held = Array.from(heldKeys);
      heldKeys.clear();
      for (const code of held) {
        const sc = keyEventToScancode(code);
        if (sc) {
          sendInput({ kind: "key", code: sc.code, extended: sc.extended, pressed: false });
        }
      }
    };

    const onContextMenu = (e: MouseEvent) => {
      // Let right-click reach the remote instead of opening the
      // browser context menu.
      e.preventDefault();
    };

    // Keyboard + composition listeners attach to the hidden IME input.
    imeInput.addEventListener("keydown", onKeyDown);
    imeInput.addEventListener("keyup", onKeyUp);
    imeInput.addEventListener("compositionstart", onCompositionStart);
    imeInput.addEventListener("compositionupdate", onCompositionUpdate);
    imeInput.addEventListener("compositionend", onCompositionEnd);
    imeInput.addEventListener("focus", onFocus);
    imeInput.addEventListener("blur", onBlurDiag);
    imeInput.addEventListener("blur", onBlur);
    imeInput.addEventListener("cut", onClipboardEvent);
    imeInput.addEventListener("copy", onClipboardEvent);
    imeInput.addEventListener("paste", onClipboardEvent);

    // Pointer / wheel / contextmenu stay on the canvas (the visible
    // surface) — pointer events are not focus-dependent.
    canvas.addEventListener("pointermove", onPointerMove);
    canvas.addEventListener("pointerdown", onPointerDown);
    canvas.addEventListener("pointerup", onPointerUp);
    canvas.addEventListener("pointercancel", onPointerCancel);
    canvas.addEventListener("wheel", onWheel, { passive: false });
    canvas.addEventListener("contextmenu", onContextMenu);

    return () => {
      imeInput.removeEventListener("keydown", onKeyDown);
      imeInput.removeEventListener("keyup", onKeyUp);
      imeInput.removeEventListener("compositionstart", onCompositionStart);
      imeInput.removeEventListener("compositionupdate", onCompositionUpdate);
      imeInput.removeEventListener("compositionend", onCompositionEnd);
      imeInput.removeEventListener("focus", onFocus);
      imeInput.removeEventListener("blur", onBlurDiag);
      imeInput.removeEventListener("blur", onBlur);
      imeInput.removeEventListener("cut", onClipboardEvent);
      imeInput.removeEventListener("copy", onClipboardEvent);
      imeInput.removeEventListener("paste", onClipboardEvent);
      canvas.removeEventListener("pointermove", onPointerMove);
      canvas.removeEventListener("pointerdown", onPointerDown);
      canvas.removeEventListener("pointerup", onPointerUp);
      canvas.removeEventListener("pointercancel", onPointerCancel);
      canvas.removeEventListener("wheel", onWheel);
      canvas.removeEventListener("contextmenu", onContextMenu);
    };
  }, [sessionId, canvasRef, width, height]);

  return (
    <div className="rdp-canvas-wrapper" style={{ position: "relative", width, height }}>
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        className="rdp-canvas"
      />
      <input
        ref={imeInputRef}
        className="rdp-ime-input"
        type="text"
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
        // `pointerEvents: none` lets clicks fall through to the canvas
        // beneath; canvas's pointerdown handler explicitly focuses this
        // input. `opacity: 0` + tiny size + transparent caret hide it.
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          width: 1,
          height: 1,
          opacity: 0,
          border: 0,
          outline: "none",
          caretColor: "transparent",
          pointerEvents: "none",
        }}
      />
    </div>
  );
}
